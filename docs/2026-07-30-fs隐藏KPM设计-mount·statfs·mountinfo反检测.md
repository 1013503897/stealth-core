# 无痕栈升级 —— 内核态 fs 隐藏（mount / statfs / mountinfo 反检测）设计

> 状态：**设计（未动手）**。2026-07-30。触发：Duck Detector（`com.eltavine.duckdetector`）在两台 Pixel6 上把 **Mount / hidden-overlayfs** 判为 Danger。目标：在**内核态**、**零注入 footprint** 地消掉这条，不走 userspace hook（那会反喂 maps/memory 检测面）。
>
> 归属：作为新 verbs **合并进 `kpm/shpte.c`**（复用其 sysinfo bridge + seq_file 隐藏技法 + resolve_syms + 部署链），不新起独立 KPM（避免多 KPM 共嵌 boot 的坑，见 memory `apatch-kpm-load-via-manager-app`）。

## 1. 检测机制拆解（Duck Detector 的 Mount 卡命中了什么）

设备上 APatch/Magisk 用 **overlayfs** 把模块叠加到 `/system`（本机有 `meta-overlayfs` 模块），再用 DenyList 把 overlay 挂载项从 app 命名空间的挂载表里**卸掉/隐藏**。残留的不一致被检测器抓到：

| 信号 | app 侧读法 | 内核读路径 |
|---|---|---|
| **A. "statfs 报 /proc/self/exe 是 overlayfs，但挂载表无对应 system overlay"** | `statfs("/proc/self/exe")` → `f_type == 0x794c7630`(OVL) | `sys_statfs*` → **`vfs_statfs`** → `sb->s_op->statfs` 填 `kstatfs.f_type = sb->s_magic` |
| **B. "/system resolved to overlayfs"** | `statfs("/system")`/statvfs 读 f_type | 同上 `vfs_statfs` |
| **C. "/proc/self/mountinfo 1 hit"（root-field / 传播 / mount-id 一致性）** | 解析 `/proc/self/mountinfo` 找可疑 root 字段（bind mount root≠"/")、propagation、magisk 路径 | **`show_mountinfo`**(seq_file per-mount show，fs/proc_namespace.c) |
| **D. "statx Mount-ID / mount-root 交叉校验"** | `statx(...,STATX_MNT_ID)` 取 exe 所在 mount 的 id，回查 mountinfo 是否存在 | `sys_statx` → `vfs_statx`/`vfs_getattr` 填 `kstat.mnt_id = real_mount(path.mnt)->mnt_id` |
| E. "Overlayfs support / 可疑 tmpfs sizing" | 读 `/proc/filesystems` 有无 overlay、tmpfs 大小 | `filesystems_proc_show` / tmpfs statfs |

**核心不一致 = A/D**：路径解析仍走 overlay（statfs 看到 OVL、statx 拿到 overlay 的 mnt_id），但挂载表里 overlay 被藏了 → 三个视图对不上。**正确修法（策略 A：装作从没 overlay 过）**——让 statfs/statx 也报**底层 fs**（erofs），与"已被藏的挂载表"一致；而不是把 overlay 加回挂载表（stock /system 无 overlay，加回去本身就可疑）。

## 2. 设计总览

- 合并进 `shpte.c`，新增一组 **`fshide*`** verbs 走 sysinfo bridge（`BRIDGE_NR=179` / `BRIDGE_MAGIC="SHPTBRDG"` / 分发器 `shpte_run`）。
- 三个 after-hook（全部复用现有 `hook_wrap2/4` + seq_file 技法）：
  - **P1** `vfs_statfs` → 把 gated 进程看到的 `f_type: OVL→erofs`。
  - **P2** `show_mountinfo`(+`show_vfsmnt` 供 `/proc/mounts`) → 对 gated 进程 **SKIP** 掉 overlay/magisk 挂载行（复用 `hidemaps` 的 rewind-count+SEQ_SKIP）。
  - **P3** `vfs_statx`/`vfs_getattr` → 把 exe 的 overlay `mnt_id` 重映射到底层 `/system` mount 的 id（最难，见 §7）。
- **默认关**（arm 前一字不跑）→ boot 路径零改动、重刷零 bootloop 风险，同 ghost Rev1 原则。

## 3. 门控模型（关键：reader-gate，非 owner-gate）

maps-hide 是 **owner-mm 门控**（藏某 VMA，不管谁读）。fs 隐藏不一样，必须 **reader 门控 = 只对"要骗的进程"骗**，否则 root 自己的 `mount`/`df`/`stat -f` 全花、系统守护进程也被污染。

- 维护一个 **hide-set**（定长数组，`MAX_FSHIDE≈64`），键 = **tgid**（首选）或 **uid**。
- 热路径门 = `fs_caller_gated()`：取 `__task_pid_nr_ns(get_current(), PIDTYPE_PID/…)`（shpte 已用此法拿 tgid）比对 hide-set；命中才改，否则**立即原样返回**（一次数组扫描，非 gated 进程零开销）。
- **谁来填 hide-set**：Vector 注入进目标 app 时，从进程内经 bridge 调 `fshide add`（把自己的 tgid/uid 登记）——复用"agent 从目标内部驱动 KPM"的既有模型，真实目标（GCash/Paytm）**自治覆盖**，无需超密钥。fork 子进程：若键 uid 则天然覆盖；若键 tgid，复用 Rev2 的 `wake_up_new_task` 钩子把子 tgid 也登记（可选）。
- **对 Duck Detector 本身**：Vector 默认 gate-out 它（不注入）→ 它不会自登记。验证时用测试 harness（跑在检测器 uid 下的探针，或临时把检测器 tgid 用 `fshide add` 手工登记）。这点是**测试细节**，非生产依赖：生产只需真实目标过。

## 4. Phase 1 —— `vfs_statfs` f_type 伪装（最高价值、最低风险）

签名 `int vfs_statfs(const struct path *path, struct kstatfs *buf)`（arg0=path, arg1=buf）。`kstatfs.f_type @ +0`。

```c
static uint32_t g_fs_spoof_magic = 0xE0F5E1E2; /* EROFS；可 bridge 配置 */
static void after_statfs(hook_fargs2_t *fargs, void *udata) {
    if (!g_fshide_on) return;
    if (!fs_caller_gated()) return;                 /* reader-gate */
    long *ft = (long *)fargs->arg1;                 /* &kstatfs.f_type */
    if (!ft) return;
    if ((uint32_t)*ft == 0x794c7630)                /* OVERLAYFS_SUPER_MAGIC */
        *ft = (long)g_fs_spoof_magic;               /* -> erofs，挡 A/B */
}
```
- `before_statfs` 空即可（无需存 count，这是改结构体不是改 seq）。用 `hook_wrap2(vfs_statfs, before_statfs, after_statfs, 0)`。
- 只动 `f_type`，`f_blocks/f_bavail` 等不碰 → 应用查剩余空间不受影响，功能副作用极小。
- 伪装目标 magic **配置化**（默认 erofs）：Pixel6 A13+ /system 多为 erofs（0xE0F5E1E2）；上线前用一台 stock 等价机 `stat -f /system` 核实，或做 `fshide magic <hex>`。
- **这一条单独就能把检测器最主打的 "hidden overlayfs" statfs 半边消掉** → A/B 平掉。

## 5. Phase 2 —— `show_mountinfo` 行过滤（对齐挂载表）

复用 `hidemaps` 的 seq_file 骨架（`SEQ_COUNT_OFF=+24 / SEQ_PAD_OFF=+32 / buf@+0`，两内核已校准）：

```c
static void before_mountinfo(hook_fargs2_t *fargs, void *udata){
    if(!g_mountinfo_on) return;
    fargs->local.data0 = *(volatile uint64_t*)((char*)fargs->arg0 + SEQ_COUNT_OFF); /* 存起点 */
}
static void after_mountinfo(hook_fargs2_t *fargs, void *udata){
    if(!g_mountinfo_on || !fs_caller_gated()) return;
    void *m = (void*)fargs->arg0;
    char *buf = *(char**)((char*)m + 0);
    uint64_t s = fargs->local.data0, e = *(volatile uint64_t*)((char*)m + SEQ_COUNT_OFF);
    if (line_contains(buf, s, e, "overlay") || line_contains(buf, s, e, "/data/adb") ||
        line_contains(buf, s, e, "magisk")  || line_contains(buf, s, e, "KSU") /* … */) {
        *(volatile uint64_t*)((char*)m + SEQ_COUNT_OFF) = s;   /* rewind：整行丢弃 */
        *(volatile uint64_t*)((char*)m + SEQ_PAD_OFF) = 0;
        fargs->ret = SEQ_SKIP;
    }
}
```
- `show_mountinfo` 是 per-mount 调用一次（v=`struct mount*`），一次一行 → 逐行判、逐行 SKIP，与 maps-hide 完全同构。
- 同法可选钩 `show_vfsmnt`(`/proc/mounts`)、`show_vfsstat`(`/proc/*/mountstats`)。
- DenyList 通常已卸了大部分；这是**兜底 + 补 DenyList 漏网**（propagation/mount-id 字段一致性）。C 项平掉。

## 6. 新增 bridge verbs（在 `shpte_run` 加 `starts(a,"…")` 分支）

| verb | 作用 |
|---|---|
| `fshide on` / `off` | 总开关（默认 off） |
| `fshide add <tgid|uid>` / `del <…>` | 维护 hide-set（Vector 注入时自登记） |
| `fshide magic <hex>` | 配置伪装目标 fs magic（默认 erofs） |
| `fshide statfs on|off` / `mountinfo on|off` / `statx on|off` | 分 phase 开关，便于灰度 |
| `fshide dump` | 打印 hide-set、各 hook 状态、命中计数（telemetry） |

`ensure_*_hooked()/maybe_unhook_*()` 按 hide-set 非空 ref-count 安装/卸载三个 hook（同 `ensure_maps_hooked` 模式）。

## 7. Phase 3 —— statx mnt_id 重映射（残留、最难，可暂缓）

`vfs_statx`→`kstat.mnt_id = real_mount(path.mnt)->mnt_id`。exe 在 overlay 上 → mnt_id=overlay 的 id，而 overlay 已被 P2 藏出 mountinfo → D 项交叉校验仍不一致。

- 修法：arm 时走命名空间 mount 链，求出**底层 `/system`(erofs) mount 的 id**（可见、未被 DenyList 卸的那个），建 `overlay_mnt_id → real_mnt_id` 映射；`after_statx` 命中 overlay id 时改写为 real id。
- 难点：mount/mnt_namespace 结构偏移随版本变（5.10 vs 6.1），`real_mount`/`mnt_id` 需按偏移校准（可仿 `vma_owned_by` 的自标定思路：扫已知值定偏移）。
- 判断：**P1+P2 已能把检测器 Mount danger 从 2 signals 打到 0/1**；D 项是"更狠的交叉校验"，多数真实 RASP 不做 → **P3 列为可选、按实测决定是否投入**。

## 8. 安全性论证（对照 stealth-poc 硬教训）

- **无 D-state 风险**（本升级线最关键优势）：statfs/mountinfo/statx hook 全部跑在**调用者自己的 syscall 上下文**（可睡眠的进程上下文），**不是** fault handler、**不是** supercall、**不涉及 perf/阻塞 API** → 无需 task_work defer、无 shpte/shhwbp 那种 D-state→物理重启的坑。比 ghost/fork 线**更安全**。
- hook **安装/卸载**在 arm-time 的 bridge/ctl0 上下文（同 `ensure_maps_hooked` 装 `show_map`）→ 有先例、安全。
- `-O0` 强制（build.ps1 已锁；O2→loader panic 重启）、`-mbranch-protection=bti`。
- **默认 off** → 新代码 arm 前不跑，boot 路径零改动 → 重刷零 bootloop 风险。
- **版本无关性**：`vfs_statfs` 签名 / `kstatfs.f_type@0` / `show_mountinfo` 两内核(5.10/6.1)均稳定；seq_file 偏移已在现有代码校准。仅 P3 的 mount 偏移需按版本自标定。
- 功能副作用：只改 `f_type` 与藏 magisk 挂载行，不改容量/不改真实 IO；reader-gate 到 app，root 工具与系统守护不受影响。

## 9. 部署与测试

- **部署**：合并进 shpte.c → `powershell kpm/build.ps1 -Src shpte.c` → 用 APatch app 重嵌 boot → 刷两台 → 重启（同 shpte 任何改动的既有周期，见 memory `apatch-kpm-load-via-manager-app`）。**代码改**才需重刷；**配置/arm** 是 runtime（bridge，无超密钥）。
- **测试 harness**（仿 `tools/s0probe.c`/`pgtool.c`）：一个 `fsprobe` 用户态工具，`statfs("/proc/self/exe")`/`statfs("/system")`/读 `/proc/self/mountinfo`/`statx(...MNT_ID)`，打印所见；`fshide add <自身tgid>` 前后各跑一次做 A/B。
- **端到端**：把 `fsprobe`（或临时登记的 Duck Detector）gate 进 → 重扫 → Mount signals 应从 2→0/1；再看真实目标 GCash/Paytm 是否仍稳。
- 连跑 3 次验证 hook 安装/卸载无泄漏（同 ghost/fork 验证法）。

## 10. 开放问题 / 决策点

1. **键 tgid 还是 uid**？tgid 更精确、拿法现成（`__task_pid_nr_ns`）；uid 天然覆盖 fork/isolated 但要标定 cred 偏移。**倾向 tgid + 可选 uid**。
2. **伪装 magic 来源**：配置化默认 erofs vs arm 时从 overlay 底层 sb 自动求（ovl_fs 结构不稳）→ **倾向配置化**。
3. **P3 做不做**：先只上 P1+P2，实测检测器与真实目标够不够，再定 P3。
4. **落地范围**：先 P1（单 hook，最小）灰度，再 P2。

## 11. 里程碑（建议）

- **M1 = P1**：`vfs_statfs` + `fshide on/add/magic/dump` + `fsprobe` 双端验证。最小、最安全，先证价值。
- **M2 = P2**：`show_mountinfo` 行过滤，Mount danger 打到 0/1。
- **M3 = P3（可选）**：statx mnt_id 重映射。
- 相关：[[shpte-ghost-main-path-rev1]]、[[vector-kpm-gcash-setup]]、[[apatch-kpm-load-via-manager-app]]、[[pixel6-pif-trickystore-keybox]]。

## 12. M1 落地状态（2026-07-30，已双端验证，KPM v0.6.5）

**✅ 完成并验证**。代码在 `kpm/shpte.c`（新 verbs `fshide on|off|add|del|magic|dump`）、harness `tools/fsprobe.c`。

### ⚠️ 重大实现修正：hook syscall，不是 hook `vfs_statfs`
第一版（0.6.4）hook 导出符号 `vfs_statfs` → **不生效**（`spoofed=0`）。根因 = **内联**：`vfs_statfs` 是**直接调用**，GKI 内核把它内联进了 `user_statfs`（syscall 路径），`EXPORT_SYMBOL` 只留一份给外部模块的离线副本，syscall 根本不走它。**对比 maps-hide 的 `show_map` 能中，是因为它经 `seq_operations->show` 函数指针**间接调用**、无法内联。**
- **通用教训**：KPM inline-hook 一个**导出但被同 TU 内联调用**的内核函数，对该函数的 syscall 触发路径**无效**。要么 hook **syscall 入口**（`fp_hook_syscalln`），要么 hook 一个**间接调用点**（函数指针 / `s_op`/`seq_ops` 之类）。→ 这条影响 **P3**：`vfs_statx` 同为直接调用，届时也应 hook `statx` syscall(291) 而非 `vfs_statx`。
- **修法（0.6.5）**：`fp_hook_syscalln(43=statfs / 44=fstatfs, 2, 0, after_sys_statfs, 0)`（arm64 asm-generic 只有这俩，都以 `struct statfs*` 为 arg1、f_type 是头 8 字节）。after 里 `access_process_vm` 读用户 buf 的 f_type，若 == overlayfs(0x794c7630) 且 caller gated，`compat_copy_to_user` 写回 erofs(0xe0f5e1e2)。全在调用者 syscall-exit 上下文、无 D-state。vfs_statfs hook 保留做诊断（`vfs_calls` 计数），确认对本进程 statfs 从不触发。
- **待清理**：vfs_statfs 诊断 hook 已完成使命（证实内联），M2 重刷时随手移除（当前无害、仅冗余）。

### 验证（fsprobe 双端）
- **1C091**（/system=overlayfs）：gated `statfs(/system)` **overlayfs → erofs**，`spoofed=1 sys_calls=2 sys_hooked=1` → **PASS**。before(未gate)=overlayfs / after(gate)=erofs 同进程对比证明 **reader-gate**。
- **19301**（/system=**ext4**，overlay 在别处、mountinfo 有 3 行 overlay）：syscall hook 正常触发但**不改 ext4**（只改 overlayfs）→ 正确 no-op。P1 靶机是 1C091；19301 的 overlay 属 **P2**（mountinfo）范畴。
- 两台重启后健康、无 bootloop、bridge 存活。默认 off、boot 路径零改动的原则兑现。
- 部署：经 APatch app 重嵌 boot 刷两台（同 shpte 任何改动）。**注意内联坑上设备才暴露 → 每次 hook 新内核函数先在设备确认触发计数**。

## 13. M2 落地状态（2026-07-30，已双端验证，KPM v0.6.6）

**✅ 完成并验证**。hook `show_mountinfo`(+`show_vfsmnt`)，对 gated reader **SKIP** 含 `/data/adb`/`overlay`/`magisk`/`KSU`/`worker` 的挂载行（复用 maps-hide 的 `before` 存 count → `after` rewind+`SEQ_SKIP`）。新增子开关 `fshide statfs on|off` / `mountinfo on|off`。**顺手移除了已证实内联的 vfs_statfs 诊断 hook**（P1 现纯靠 statfs/fstatfs syscall hook）。

- **印证设计预判**：`show_mountinfo` 走 `seq_operations->show` 函数指针**间接调用**、**不内联** → hook **一次即中**（与 P1 的 vfs_statfs 内联失败形成对照，坐实"hook 间接调用/syscall、别 hook 被内联的直接调用"这条规则）。
- **验证（fsprobe P1+P2 双判据）**：
  - **19301**（root 见 3 行 overlay 挂载、/system=ext4）：**P2 PASS**——artifact 行 **3→0**、`hidden=3`；P1 n/a。
  - **1C091**（/system=overlayfs、root 的 ns 无 overlay 行）：**P1 PASS**——overlayfs→erofs；P2 n/a（该 reader 无 artifact 行）。
  - reader-gate 生效（before=3 / after=0 gated）；两台重启后健康、无 bootloop、bridge 存活。
- **注意**：root(su) 常在 global/mount-master ns（1C091 上 root 见 0 行），真实 app(untrusted_app) 在自己 ns 里才看得到 DenyList 漏网的 overlay 行；kernel hook 按 current tgid 过滤、与 ns 无关 → 对真实 gated app 一样生效。
- **待办（端到端）**：把 Duck Detector 的 tgid 动态 `fshide add` 进去重扫，看 Mount danger 真掉到 0（tgid 每次启动变，需小工具动态登记）。
- **剩 M3（可选）**：`statx` syscall(291) mnt_id 重映射（`vfs_statx` 同为直接调用、勿 hook 符号）。
