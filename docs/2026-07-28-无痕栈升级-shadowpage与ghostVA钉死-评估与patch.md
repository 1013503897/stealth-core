# 无痕栈升级：评估 + 可落地 patch（2026-07-28 自主推进交接）

> 本文档是一次**用户离场期间**的自主推进交接。**核心边界：我没有改动 `kpm/shpte.c`（你的工作区里它有未提交改动，我不叠加/不污染），没有编译覆盖被 git 跟踪的 `shpte.kpm/.o`，没有把改过的 kpm 上任何测试机重启验证（无人看管时 bootloop 无法及时救）。** 下面是设计 + 可直接 apply 的 patch 片段，等你回来 review、落地、上设备。

---

## 0. TL;DR

| 项 | 状态 |
|---|---|
| 两台 Pixel6 开机自动加载 + auto-bridge 无痕栈 | ✅ **已验证生效**（`/data/adb/kpms/shpte.kpm` + `auto-bridge armed=1`，免 superkey 全自动） |
| Obsidian 作品集沉淀（评估 + 竞品对照） | ✅ 已写 `技术/内核无痕Hook栈的残余暴露面是clone可读-Shadow-Page读写分离补齐.md` + 更新能力地图 |
| FEAT_EPAN 探测 | ⚠️ 架构强判断**不支持**（Pixel6=ARMv8.2 < ARMv8.7），dmesg 实证待设备回 adb |
| 升级 A：`get_unmapped_area` 钉死 ghost VA | 📄 **patch 已写好（本文档 §5）**，未 apply/未编译/未上设备 |
| 升级 B：Shadow Page 读写分离（软件 DABT） | 📄 **设计 + 骨架已写好（本文档 §6）**，需上设备分阶段迭代 |
| 设备物理状态 | ⚠️ **两台 Pixel6 重启后从 adb 掉线，冒出一台 Pixel5**——判断=USB 物理插拔，非 bootloop（见 §2），回来请目视确认 |

---

## 1. 本次自主推进已完成的事

1. **开机自动加载彻底解决"无 superkey"**：`/data/adb/kpms/` 是 KernelPatch 内核级加载目录（boot 时 kpimg 在 `pre-kernel-init` 加载，不经用户态 supercall → 天然免明文 superkey）。两台 Pixel6 均已放入 `shpte.kpm` 并重启验证：dmesg `name: shpte` → `pre-kernel-init` → **`auto-bridge armed=1`** → `load_module: succeed` → `rc:0`，无 bootloop。`shpte_init`（`shpte.c:3015-3028`）自身 init 里 auto-arm sysinfo bridge，开机后 Vector 直接经 bridge 驱动 KPM，免 superkey、免手动 probe/bridge。
2. **作品集沉淀**：见上表。
3. **升级评估**（对照看雪 GhostHook / SharkFall / thread-292066）+ 本文档的 patch/设计。

---

## 2. 设备物理状态 ⚠️（回来先看这条）

重启主力 `19301FDF6001QK` 时，我**已成功读到它重启后的 dmesg**（`auto-bridge armed=1` → `load succeed`），证明**它起来了之后**才从 adb 掉线；`1C091FDF6008DN` 更早已验证起来。之后 `adb devices` 里两台 Pixel6（oriole）都消失，反而出现一台 **Pixel5（redfin, `11071FDD4003BF`）**。

**判断：这是物理 USB 插拔**（你吃饭时动了线 / 换插了设备），**不是 bootloop**——我全程没改它们的内核代码，放的是已在两台验证过的同一个 `shpte.kpm`（md5 `6b5a3de6…`）。**回来请目视确认两台 Pixel6 能正常开机、`adb devices` 能重新看到**。如需，重连后 `dmesg | grep -iE 'shpte|auto-bridge'` 复验自动加载。

---

## 3. FEAT_EPAN 探测结论

- **架构判断**：Pixel6 = Google Tensor（Cortex-X1 + A76 + A55），均为 **ARMv8.2-A**。FEAT_EPAN 是 **ARMv8.7** 特性 → **硬件不支持**。
- **实证方式（待设备回 adb）**：`dmesg | grep -iE 'detected:.*Privileged Access Never'`（内核运行时 cap 检测日志），或写 EL0 `mrs x0, ID_AA64MMFR1_EL1` 读 PAN 字段（[23:20]，==3 才是 EPAN）。
- **对设计的影响（关键）**：Shadow Page **不能靠 EPAN 硬件 execute-only**，必须走**软件 DABT 双页方案**——而这正好复用现有 `do_page_fault` + ESR gate（`shpte.c:793-806` 已按 `ESR.EC` 区分 IABT/DABT）。所以 EPAN 不支持**不阻塞** Shadow Page，只是决定走软件路径（见 §6）。

---

## 4. 架构现状回顾（读码，详版见 Obsidian 笔记）

| 机制 | 现状（file:line） |
|---|---|
| 主 hook 路径 | UXN region clone：`.text` 零改（过 CRC），`before_pf`（`785`）+ ESR gate（`805-806`：`EC==0x20` IABT + 权限故障=UXN 执行陷阱）路由到 clone |
| clone 放哪 | **普通匿名 RX mmap**（`lib/kpmhook.c:9,314`）→ **可读** |
| clone 隐藏 | 仅 `maps hide`（hook `show_map`）抹 `/proc/*/maps` **列表** |
| ghost（VMA-less） | `ghost_inject`（`1513-1548`）等已实现，**未接主路径** |
| Shadow / EPAN | **完全没有**（grep 零匹配） |

**残余暴露面 = clone 是可读内存**：`maps hide` 只抹列表、不拦直读。检测方遍历/扫描地址空间读内容比对，仍能看到 clone。这是 §6 Shadow Page 要补的点。

---

## 5. 升级 A：`get_unmapped_area` 钉死 ghost VA

**定位（诚实）**：这是**半个升级**——它保护的是 ghost memory（防内核分配器/`mmap` 复用已注入的 ghost VA），而 ghost 当前**没接主路径**。所以对当前主路径（普通 mmap clone）**无即时收益**，是"启用 ghost 路径 / Shadow Page 用到 ghost 页时"的必要前置。**建议随 §6 一起启用，不单独上。**

### patch 片段（基于真实符号，未 apply）

**(1) 全局状态**（`g_ghost_va` 附近，`shpte.c:236-239` 区）：
```c
static void *g_addr_gua = 0;          /* get_unmapped_area */
static volatile uint64_t g_gua_blocked = 0;
static int g_gua_hooked = 0;
```

**(2) `resolve_syms()` 加一行**（`shpte.c:1236` 前）：
```c
    if (!g_addr_gua) g_addr_gua = (void *)kallsyms_lookup_name("get_unmapped_area");
```

**(3) after 回调**（放 `before_pf` 之后）。get_unmapped_area 签名 `unsigned long get_unmapped_area(struct file*, unsigned long addr, unsigned long len, unsigned long pgoff, unsigned long flags)`：
```c
/* fail-closed: if the allocator picked a VA that would overlap our injected ghost
 * page (for g_ghost_pid), rewrite the return to -ENOMEM so the caller retries elsewhere.
 * Fast-gate on g_ghost_kaddr first: do_page_fault-class hot path, keep it cheap. */
static void after_gua(hook_fargs5_t *fargs, void *udata)
{
    (void)udata;
    if (!g_ghost_kaddr || !g_ghost_va) return;                 /* no ghost active */
    if (fn_task_pid_nr_ns &&
        fn_task_pid_nr_ns((void *)get_current(), PIDTYPE_TGID, 0) != g_ghost_pid) return;
    uint64_t ret = fargs->ret;
    if (ret >= (uint64_t)-4095) return;                        /* already an errno */
    uint64_t len = (fargs->arg2 + 0xfffUL) & ~0xfffUL;
    uint64_t glo = g_ghost_va, ghi = g_ghost_va + 0x1000;
    if (ret < ghi && (ret + len) > glo) {                      /* overlaps ghost page */
        fargs->ret = (uint64_t)(-12);                          /* -ENOMEM */
        g_gua_blocked++;
    }
}
```

**(4) 装/卸**（新命令 `guaprotect` 或并进 `do_ghostredirect`/`ghost_inject` 成功后自动装）：
```c
    if (!g_gua_hooked && g_addr_gua &&
        hook_wrap5(g_addr_gua, 0, (void *)after_gua, 0) == HOOK_NO_ERR)
        g_gua_hooked = 1;
    /* teardown 时: if (g_gua_hooked) { unhook_wrap(g_addr_gua); g_gua_hooked = 0; } */
```

**(5) dispatch**（`shpte_run`，`shpte.c:3104` 起的 `else if` 链里加）：
```c
    } else if (starts(a, "guaprotect")) {
        resolve_syms();
        /* 装/卸 after_gua，回报 g_gua_hooked / g_gua_blocked */
    }
```

### ⚠️ 落地前必确认
- **hook 框架的 wrap arity**：现有只见 `hook_wrap2/3/4`。get_unmapped_area 有 5 参 → 需确认 KernelPatch inline-hook 是否提供 `hook_wrap5`/`hook_fargs5_t`；若最高到 4，用能覆盖 5 参的通用 hook 或只读 `fargs->ret`+`arg2` 的等价接口。
- get_unmapped_area 是**热路径**：gate 顺序必须 `g_ghost_kaddr` 先、`tgid` 后（已按此写）。
- 某些内核走 `mm->get_unmapped_area` 函数指针而非全局符号；若 kallsyms 拿到的全局不被实际调用，改 hook `arch_get_unmapped_area` / `arch_get_unmapped_area_topdown`。

---

## 6. 升级 B：Shadow Page 读写分离（软件 DABT）— 战略升级

**这是补当前架构唯一实质弱点（clone 可读）的正解。** 无 EPAN，走软件双页方案，复用现有 do_page_fault/ESR gate/ghost_inject/单步 基础设施。

### 原理
同一目标代码页：**执行时**取真码（现有 UXN redirect → clone）、**被读时**返回 shadow（原始 `.text` 内容）。软件实现 = 让目标页**读和执行都触 fault**，在 `before_pf` 按 `ESR.EC` 分流：
- **IABT（`EC==0x20`）= 执行** → 现有逻辑：路由 PC 到 clone。
- **DABT（`EC==0x24`）= 读** → 新逻辑：临时把该页 PTE 切到 **shadow 物理页**（存整页原始 `.text`，可读），单步过这条读指令，再切回陷阱态。检测方读到的是干净原始 `.text`。

### 关键：目标页要从"UXN"升级为"读也陷"
UXN 只挡执行。要让**读**也陷，目标页 PTE 需清 `PTE_VALID`（invalid）或清 AF：任何访问都 translation/access fault，`before_pf` 按 EC 区分 IABT/DABT。注意此时 IABT 是 **translation fault**（FSC `0x04..0x07`）不是现有 gate 的 permission fault（`0x0c`）——需新增/调整 gate 分支。**先例已在**：SSOL 路径注释（`shpte.c:802-803`）明说它"also dispatches on translation faults at its unmapped bk_va"，机制打通过。

### 骨架（`before_pf` 内，pghook 路径 §853-889 的 `if (!is_xtrap)` 分支 §871 处扩展）
```c
    /* 现状: if (!is_xtrap) { g_pf_passthru++; break; }  —— data abort 一律放行 */
    if (!is_xtrap) {
        uint64_t ec = (esr >> 26) & 0x3f;
        if (ec == 0x24 && s->shadow_pte && s->live_ptep) {     /* DABT = 读我们的 hook 代码页 */
            /* 切到 shadow(原始可读) -> 让这条读拿到干净 .text */
            *(volatile uint64_t *)s->live_ptep = s->shadow_pte;
            flush_tlb_all();
            /* 单步这条读指令；step-complete 回调里把 PTE 切回陷阱态 + flush,
             * 使后续 执行 仍 IABT->clone、读 仍 DABT->shadow。复用 fn_user_enable_single_step
             * + register_user_step_hook（SSOL 已用同一套）。多线程同页并发读要防竞态。*/
            shadow_arm_singlestep(s, regs);
            fargs->skip_origin = 1; fargs->ret = 0;
            return;
        }
        g_pf_passthru++; break;
    }
```

### shadow 页分配（复用 `ghost_inject` 模式，§1513-1548）
arm 一个 region 时，额外 vmalloc 一页作 shadow，从目标进程 `access_process_vm` 抓**该页原始 `.text` 字节**（趁其尚未被读检测；或从 clone 反推 + 已知 hook 点还原），`vmalloc_to_pfn` → 组 PTE 值（可读、UXN 或普通 RO）存 `s->shadow_pte`；`s->live_ptep` 缓存目标 live PTE 指针（arm 时经 `apply_to_existing_page_range`/`pte_cb` 拿到，像现有 `g_ptep`）。

### 难点清单（诚实，需上设备逐条验证）
1. **单步 + PTE 切换原子性**：多线程同页并发读，切 PTE 期间要防另一线程执行落进 shadow。参考 `g_ssol_guard`（`shpte.c:939-951`）的 live-vs-snapshot 校验与 enforce 重快照。
2. **shadow 内容 = 整页原始 `.text`**：DABT 的 `far` 可能落页内任意偏移，shadow 必须整页镜像原始。
3. **性能**：每次读 fault + 单步 = 高开销；RASP 若周期性全内存扫描，可能显著拖慢目标。上设备量测，必要时只对被读命中的页惰性开 shadow。
4. **gate 从 permission-fault 改 translation-fault 语义**：目标页设 invalid 后，IABT 也变 translation fault，现有 `is_xtrap`（判 `0x0c`）要相应扩展；勿破坏现有 UXN-permission 路径（可用 per-slot 标志区分"UXN 模式"vs"shadow 模式"）。
5. **TLB/icache 一致性**：切页后 `flush_tlb_all` 已有；shadow→exec 边界注意 `sync_icache`。
6. **do_page_fault D-state 铁律**：新分支里**只做 PTE 写 + flush + 单步武装**，绝不在 fault/supercall 上下文调 perf/blocking（`stealth-poc/CLAUDE.md` 硬教训）。

### 分阶段验证计划（照 P2.1→P4.2 的稳扎稳打法）
1. **S0 只读探针**：写个用户态程序，读一个被 Vector hook 的进程的 clone 地址区间并与原 `.text` 比对，**量化 clone 可读暴露面**（把评估从"读码结论"升级成"实测暴露"）。
2. **S1 单页 shadow**：拿一个隔离测试目标（非 GCash），单页设 invalid + IABT→clone / DABT→shadow 单步，验证"执行正确 + 读返回原始"。
3. **S2 并发**：多线程读同页，验证原子性 + guard。
4. **S3 接主路径**：pghook region 级 shadow，接 kpmhook/Vector，量测性能，再上硬目标。

---

## 7. 为什么没 apply / 没编译 / 没上设备（决策记录）

- **没 apply 到 `kpm/shpte.c`**：`git status` 显示它有你**未提交的改动**（`M kpm/shpte.c`）。我叠加实验代码会和你的 work 混在一起、难区分；且 `shpte.kpm/.o` 被 git 跟踪，编译会污染。你不在无法确认 → 不动。
- **没本地编译**：编译需在仓库目录（依赖 `vendor/KernelPatch` 相对 include），会落进上面的污染；且**内核模块正确性本来就必须上设备验证**，本地编译只证语法。NDK clang 17.0.2 已确认就位，编译能力没问题。
- **没上设备**：改过的 kpm 只能靠 `/data/adb/kpms/` 重启或 APatch app 加载，**改错直接 bootloop**。无人看管的测试机上做这个不负责任。

---

## 8. 你回来的 step-by-step

1. **目视确认两台 Pixel6**能开机、`adb devices` 可见（§2）；重连后 `dmesg | grep -iE 'shpte|auto-bridge'` 复验自动加载。
2. **review** 本文档 §5/§6 的 patch/设计。
3. **升级 A（小、可选）**：把 §5 patch apply 到你的工作区 → `powershell kpm/build.ps1 -Src shpte.c` → 单台设备 `/data/adb/kpms` 或 APatch app 加载验证。先确认 `hook_wrap5` 是否存在。
4. **升级 B（战略）**：按 §6 分阶段验证计划，从 **S0 只读探针**起步（零风险、且能把"clone 可读"从推断变实测），再逐级 S1→S3。
5. 需要我继续写具体某阶段代码 / 陪你上设备迭代，随时叫我。

---

*附：本次相关 auto-memory 已更新 `apatch-kpm-load-via-manager-app`（含 kpms 自动加载 + auto-bridge 免 superkey）；作品集笔记见 Obsidian `技术/内核无痕Hook栈的残余暴露面是clone可读-Shadow-Page读写分离补齐`。*
