# stealth-poc

Android（ARM64）上**内核级无痕 Hook** 的 clean-room PoC，基于 **APatch / KernelPatch（KPM）**。

> English version: [`README.md`](./README.md)。深入的工程约定与硬核教训见 [`CLAUDE.md`](./CLAUDE.md)。

## 这是什么

一句话：**在不改动目标任何一个字节内存的前提下，拦截并接管它的执行**。

- 不 patch 目标 `.text`（过得了 CRC / 自校验）；
- 不注入 SO、不建匿名可执行映射（过得了 `/proc/*/maps` 扫描）；
- 重编译后的克隆代码跑在 **连 `/proc/*/maps` 和 `mincore` 都看不见** 的内存里。

它是 Vector（`../Vector`，JingMatrix 的 Zygisk ART-hook 框架）**KPM 无痕后端的内核源头**——Vector 通过 vendored 的 `lib/kpmhook` + `lib/dbi` 经无 superkey 的 sysinfo bridge 驱动本仓的 KPM。本仓保持独立 git（remote `github.com/1013503897/stealth-poc`）。

参考（仅概念）：看雪文章《Android 内核无痕 Hook 理解和感悟》与公开的 `xiaojianbang-stealth-hook`。**未拷贝任何第三方代码**——全部对着 KernelPatch kpm SDK API 和稳定的 Linux/ARM ABI 自研实现。

## 无痕的三重保证

| 反检测面 | 常规 hook 的破绽 | 本方案 |
|---|---|---|
| **CRC / 自校验** | inline patch 改了 `.text` 字节 | `.text` 一字不改，靠 PTE 的 UXN 位或硬件断点触发陷阱 |
| **`/proc/*/maps` 扫描** | 注入 SO / 匿名 RX 段留下映射行 | 克隆跑在 **VMA-less ghost 内存**（无 VMA，maps/mincore 均不可见）；另有 maps-hide 兜底 |
| **ptrace / 反调试** | 附加调试器改 TracerPid | 无需 ptrace；并提供 `hidetracer` 把 `/proc/*/status` 的 TracerPid 伪造为 0 |

## 三层架构

Hook 逻辑横跨内核态与用户态，靠一条字符串命令控制通道桥接：

1. **KPM 模块**（`kpm/*.c`）——被 KernelPatch **加载进内核** 的内核侧代码。freestanding ELF `ET_REL`（无 libc / 无 stdlib），加载期由 KernelPatch 解重定位；通过 `kallsyms_lookup_name` 在运行时解析内核函数（不与内核链接）。生命周期钩子用 SDK 的 section-attribute 宏导出（`KPM_INIT`/`KPM_CTL0`/`KPM_EXIT`）。
2. **`shctl`**（`cli/shctl.c`）——用户态 ARM64 CLI，通过 **supercall**（`syscall(45, superkey, vcmd, ...)`）驱动已加载的 KPM。`control <name> <args>` 把字符串路由到 KPM 的 `KPM_CTL0` handler，并打印回拷的应答。
3. **测试目标**（`tools/*.c`）——一批自包含的靶子进程，各自验证一个阶段能力（打印 pid + 目标函数地址，循环调用以便断点/陷阱命中）。

### `KPM_CTL0` 命令桥
KPM 只有一个 `KPM_CTL0` 入口，内部用手写的 freestanding 字符串解析（内核态无 libc）分发一套文本协议。新能力以**新命令动词**的形式加入，而非新增 supercall。`shpte` 当前支持的动词：

```
probe        解析内核符号
pte          读+解码某进程的叶子 PTE（只读）
arm/disarm   给目标代码页置/清 PTE_UXN，挂 do_page_fault（自愈式）
redirect     UXN 陷阱 + 把 PC 重定向到用户态克隆页
redirectmap  经 offset_map 路由（DBI 克隆指令位移后仍正确落点）
pagehook     整页 UXN hook（页内多函数共享，单次）
pghook/pgunhook/pgdisarm/pghookg/pggc   多页 region 克隆 + 每页多 override 表（RV-2）
hookto/hwhookto/hwunhook   inline_hooker 原语（UXN / 硬件断点 + ghost backup）
ghosttest/ghostredirect/ghostfree       VMA-less ghost 内存
ssolhook/ssolunhook/ssolguard/ssolgc/ssoldisarm/ssolstat/ssoltest/ssolpoison   SSOL（单步出线）Java 无痕 hook
hidemaps/unhidemaps/hidergn   从 /proc/*/maps 抹掉克隆的 VMA
hidetracer/unhidetracer       伪造 TracerPid=0（反调试）
fshide       fs 反检测（statfs f_type 伪装 + mountinfo 行过滤）
bridge/unbridge  开/关无 superkey 的 sysinfo 桥
selfstep/dump    自测/诊断
```

## 阶段进度

| 阶段 | 内容 | 状态 |
|---|---|---|
| **P0** | KPM 工具链 + syscall-hook 冒烟测试（`shpoc`） | ✅ 设备实测 |
| **P1 / P1.5** | ARM64 硬件断点 hook + 寄存器捕获；单断点 **entry↔return 状态机**（消除重触发 livelock，捕获入参+返回值，目标透明运行） | ✅ |
| **P1.6 / P1.6b** | 多线程跟随——每线程断点表；跟随 hook 后新建线程（`wake_up_new_task`）+ 线程退出 GC（`do_exit`），线程 churn 下表保持有界 | ✅ |
| **P2.0 / P2.1** | 页表遍历读+解码任意进程叶子 PTE；目标代码页翻 UXN + `do_page_fault` 拦截 + **自愈式**恢复 | ✅ |
| **P2.2** | **单函数无痕重定向**：保持 UXN，把 faulting PC 改到函数的逐字**克隆**（`.text` 不动，函数处无新可执行 VMA） | ✅ |
| **P3.1–P3.4** | 用户态 **DBI 重编译器**：`ADR/ADRP/B/BL` 转绝对、条件+内部分支（`B.cond/CBZ/TBZ`）clone-relative 重编码、`LDR`-literal 重指向——带循环/分支/字面量池的函数都能从克隆正确运行；`offset_map` 跨进程路由 | ✅ |
| **P3.5** | `BLRAAZ`/`BRAAZ` PAC-call 降级（需 pauth 构建的目标；stock NDK 不产出） | ⬜ todo |
| **P4.1** | `/proc/*/maps` 隐藏：hook `show_map`，从 seq_file 输出里抹掉克隆行（CRC + maps 扫描一起过） | ✅ |
| **P4.2** | **VMA-less ghost 内存**：`vmalloc`+`vmalloc_to_pfn`+`apply_to_page_range` 给克隆注入一个**无 VMA** 的 PTE——maps/mincore 均不可见，且直接从 ghost 页执行 DBI 克隆（`sync_icache`）；无需 maps-hide 兜底 | ✅ |
| **P5** | 产品化原语：可复用 `lib/dbi`、HWBP/UXN `inline_hooker`（`hwhookto`/`hookto` + ghost backup）、无 superkey syscall bridge、TracerPid 伪造 | ✅ |
| **L1a–L1e** | LSPlant `inline_hooker` 载体：`pghook` 扩到每页多 override（barrier-safe sentinel 表）× 多页；`lib/kpmhook` 把 LSPlant `InitInfo` 回调映射到桥；**RV-2 干净边界多页 region 克隆**（页跨越函数整体在克隆里、正常 `RET`）；把 `MAX_RGN` 提到 64 后，LSPosed 管理器 **6 个** libart inline hook 全部走 region 克隆（零 Dobby 回退），**真机应用内实测无痕 hook 真实 libart**、`.text` 不动 | ✅ 真机实测 |
| **SSOL** | **单步出线（single-step out of line）Java 无痕 hook**：把原始代码留在原地、逐指令 XOL 执行——PC 始终在原始地址，ART 的 PC→method 映射/栈回溯/GC/deopt 全部照常工作，解决稠密框架 JIT 上 region 克隆的「代码/数据交织」「克隆返回地址」两大结构性脆弱点。相当于「用 UXN 陷阱触发的 uprobes」。KPM 侧核心 + 多目标 region + 抗漂移 guard + 死进程 GC 已实现，hookdemo 五个面全 CLEAN | ✅ 真机实测（KPM 侧） |
| **fs-hide** | 内核态文件系统反检测：`vfs_statfs` 把 gated 进程看到的 overlay `f_type` 伪装成底层 fs、`show_mountinfo` SKIP 掉 overlay/magisk 挂载行（reader-gate，只骗要骗的进程）。触发场景：Duck Detector 把 Mount/hidden-overlayfs 判 Danger | ✅ M1+M2 |

## 目录结构

```
kpm/        KPM 内核模块 + 构建脚本
  shpoc.c       P0 syscall-hook 冒烟
  shhwbp.c      P1.5/P1.6 HWBP hook：每线程断点表 + 状态机
  shpte.c       P2/P3/P4/P5/L1/SSOL/fs-hide 主模块（~4100 行，命令集见上）
  shmin.c       最小 ctl0 隔离测试
  build.ps1     用 NDK clang 编 .kpm（build.ps1 -Src shhwbp.c）
  *.py          elf_syms / scope_db / btf_off / oat_census 等符号解析脚本
  libart*.so    census / 离线分析用的 ART 样本

cli/        shctl.c + build_shctl.ps1   KPM 控制 CLI（supercall：load/unload/list/info/control）

lib/        可复用用户态库（Vector 链接的就是这里）
  dbi.c/.h      libdbi：可复用的 AArch64 位置无关函数重编译器
  kpmhook.c/.h  LSPlant InitInfo inline_hooker/unhooker → KPM 多页 pghook 表（经 syscall bridge）
  ssol.c/.h     SSOL 用户态胶水
  *_test.c      host/device 可跑的单元测试

tools/      测试靶子 + 端到端 harness（各 .c 与 shctl 同法编译）
  hbtarget/mttarget          单线程 / 多线程 HWBP 靶
  dbitarget..dbitarget4      P2.2→P3.4 逐级 DBI 靶（逐字→ADR/ADRP/B/BL→分支→LDR-literal）
  ghosttool/ghostexec        P4.2 ghost 内存靶（注入读 / 从 ghost 页执行）
  hooktool/hwhooktool        inline_hooker 靶（UXN 隔离 / HWBP 非隔离）
  pagetool/pgtool/rgntool    整页 / 多页 / region 克隆靶
  kpmhooktool                L1a：模拟 LSPlant 调用模式的进程内 agent
  ssoltarget                 SSOL 靶
  libartcensus               L1c：ELF 页跨越普查（零风险，量化是否需要多页克隆）
  s0probe/fsprobe            残余暴露 / fs 反检测 探针
  bridgetool/tracertest      桥 / TracerPid 探针
  run_*.sh                   各阶段设备侧 harness

docs/       设计文档（SSOL、L2 Java 无痕、fs 隐藏、ghost VA 钉死、脱壳器等）
vendor/     KernelPatch（SDK 头 + 文档；tag 0.13.1）
```

## 关键机制（无痕怎么实现的）

- **UXN「高压网」**：给目标代码页的 PTE 置 `PTE_UXN`，EL0 执行即触发 `do_page_fault`。fault handler **硬门控**（armed + 精确目标页 + faulting `tgid` 匹配），PTE 指针在 arm 期缓存，热路径不做页表遍历。
- **DBI 重编译器**（在用户态靶/`lib/dbi`，不在 KPM——内核只路由入口 fault）：把 PC 相关指令（`ADR/ADRP/B/BL/B.cond/CBZ/TBZ/LDR-literal`）重编码成位置无关，产出 `offset_map`（原指令 idx → 克隆指令 idx）供内核路由。
- **RV-2 干净边界多页 region 克隆**：L1c 普查发现真实 libart **46.5% 的代码字节** 落在跨页函数里，单页克隆会截断函数。解决：一个 `pghook` 槽陷阱一段**连续页 region**，其 `R_hi` 落在函数间空隙——每个函数整体在克隆里、正常 `RET`，无需 trampoline。
- **VMA-less ghost 内存**：`vmalloc` 一页 → `vmalloc_to_pfn` 拿 PFN（**不用** `virt_to_phys`，其 `linear_voffset` 未导出给 KPM）→ 从模板可执行页拷属性 → `apply_to_page_range` 在一个无 VMA 的 VA 注入 PTE → `sync_icache` 后把 UXN 重定向指到这里。ghost 主路径（Rev1 ①）已让 `pghook` 的宿主克隆本身也搬进 ghost 内存。
- **SSOL 单步出线**：稠密框架 JIT 上，region 克隆有两个结构性坑（① 代码/数据交织，字面量池被当指令执行 → SIGILL；② 克隆返回地址上栈，ART unwinder/GC 认不出 → SIGSEGV）。SSOL 把原码留在原地，只逐指令 XOL、对 PC 相关指令做 simulate、mid-step fault 修正——PC 之间永远在原始地址，ART 全套机制照常。触发用已有的 UXN 执行 fault（不写 BRK，故无痕）。
- **fork 安全**（Rev2 ②）：给 fork 出的子进程**解陷阱**，子进程在自己 `.text` 上的执行 fault 不再误命中。

### 最重要的不变量：deferred-work 安全模型

perf/断点内核 API（`register/unregister/modify_user_hw_breakpoint`）和其它阻塞调用，**绝不能在 supercall/`KPM_CTL0` 上下文或断点异常 handler 里跑**——那会让线程卡在不可中断 D-state **同时持有 KernelPatch 锁**，之后每一次 supercall（含 APatch `su`）都挂，只能**物理重启**。全仓强制的模式：

- 断点/fault handler 只**快照寄存器**，然后 `task_work_add(target_task, ..., TWA_RESUME)` 入队；
- 真正的 perf 调用推迟到**目标任务自己的上下文**（可睡眠、返回用户态前）执行。

任何新碰 perf/调度/可能阻塞内核 API 的代码，必须遵守同样的 defer-to-`task_work` 纪律。

## 构建

Windows + NDK clang（无需 WSL/gcc）。构建脚本是 PowerShell。NDK 在脚本里**硬编码为 `26.1.10909125`（clang 17）**，机器不同就改脚本里的 `$ndk`。

```powershell
# KPM 内核模块（传任意 kpm/*.c，产出同名 .kpm + .o）
powershell kpm/build.ps1 -Src shpte.c        # -> kpm/shpte.kpm（默认 Src 是 shpoc.c）

# shctl 用户态 CLI -> cli/shctl（aarch64-linux-android33）
powershell cli/build_shctl.ps1
```

**KPM 构建 flag 是 load-bearing 的，未在真机重测前不要改**：

- **只能 `-O0`**。clang `-O2` 对 KP 模块加载器会 miscompile → 运行期 SP/PC 对齐 panic + 设备重启。（上游 demo 用 gcc `-O2`，不迁移到 clang。）
- **`-mbranch-protection=bti`**——断点 handler 被内核 perf 间接调用，需要 BTI landing pad。
- `--target=aarch64-none-elf -nostdinc -ffreestanding -mgeneral-regs-only`，再做可重定位链接（`-r -nostdlib`）；`-I` 集镜像上游 kpm Makefile。

`tools/*.c` 靶子没有构建脚本，与 `shctl` 同法编译（`--target=aarch64-linux-android33`）。

## 快速自检（纯用户态，无需内核加载 / superkey）

两个核心算法有**纯用户态单元测试**——不 load KPM、不碰内核、不需要 superkey，任意 arm64 Android 设备（含云手机）都能跑，是验证工具链 + 重编译器/模拟器是否正确的最快 smoke test：

```powershell
# 1) libdbi —— AArch64 位置无关重编译器（重编译一个函数、原件 vs 克隆逐一比对）
powershell lib/build_dbi_test.ps1
# 2) libssol —— SSOL 指令模拟器（golden 向量 + 在真芯片上交叉校验 simulate 结果）
powershell lib/build_ssol_test.ps1
```

```bash
adb push lib/dbi_test lib/ssol_test /data/local/tmp/
adb shell chmod 755 /data/local/tmp/dbi_test /data/local/tmp/ssol_test
adb shell /data/local/tmp/dbi_test     # 期望: libdbi: ALL TESTS PASSED
adb shell /data/local/tmp/ssol_test    # 期望: [native cross-check enabled] / ssol: ALL TESTS PASSED
```

> 最近一次在 Pixel 6（`1C091FDF6008DN`）实测：两者 exit 0、`ALL TESTS PASSED`。

## 部署与运行（真机）

需要**物理 ARM64 设备** + APatch/KernelPatch。云手机跑不了（无自定义内核 / KPM）。已实测：Pixel 6（oriole），Android 16，kernel `6.1.145-android14` GKI，KernelPatch kpimg `d01`（= 0.13.1）。

> ⚠️ 本机 Pixel 6 的 **superkey 已于 2026-07-24 移除/迁移**，`shctl` 认证方式已变——用前先与用户确认。`shpte` 现支持 init 时自动开桥，用户态 agent 经 sysinfo bridge 无 superkey 驱动。
>
> ⚠️ 无开机自动加载（`/data/adb/kpms` 空），每次开机手动从 `/data/local/tmp/shpte.kpm` 加载。开发期把设备 supercall 都包在 `timeout N` 里，且 **`unload` 前务必先 `unhook`/`disarm`**（需要目标存活）。`shctl`/靶子重启后仍在，改完 `.kpm` 要重推。

```powershell
adb push kpm/shpte.kpm /data/local/tmp/ ; adb push cli/shctl /data/local/tmp/
adb shell su -c 'chmod 755 /data/local/tmp/shctl'

# KEY = APatch superkey（若已迁移，见上）
adb shell su -c '/data/local/tmp/shctl KEY load /data/local/tmp/shpte.kpm'
adb shell su -c '/data/local/tmp/shctl KEY control shpte probe'    # 解析内核符号
adb shell su -c '/data/local/tmp/shctl KEY control shpte bridge'   # 开无 superkey 桥
adb shell su -c '/data/local/tmp/shctl KEY control shpte dump'     # 诊断
```

内核侧 `logki`/`logke` 输出进内核日志（`adb shell su -c 'dmesg'`），不到 `shctl` stdout——`shctl` 只打印 `KPM_CTL0` 应答缓冲。各阶段端到端 harness 见 `tools/run_*.sh`（它们用 `shctl KEY control` 驱动，需 superkey）。

### 经桥端到端（无 superkey，已实测）

一旦 `shpte` 已加载且桥已开（init 自动开，或 `control shpte bridge`），**任意进程都能不用 superkey 驱动整个 KPM**——`bridgetool` 就是这么做的：`syscall(179 /*sysinfo*/, "SHPTBRDG", cmd, len, out, outlen)`，真 `sysinfo(&info)` 调用（arg0≠magic）原样放行。`tools/run_*.sh` 里凡是 `shctl KEY control shpte "<cmd>"` 都可等价替换成 `bridgetool "<cmd>"`。

```bash
# 先探测：KPM 是否已加载 + 桥是否已开（纯 syscall，未加载则空返回，安全）
adb push tools/bridgetool /data/local/tmp/ ; adb shell chmod 755 /data/local/tmp/bridgetool
adb shell /data/local/tmp/bridgetool probe   # 已开则回全部已解析内核符号；rc=0
adb shell /data/local/tmp/bridgetool dump    # 看当前 armed slot / npg / redirects / maps_hidden

# 旗舰 RV-2 端到端：rgntool 经桥「自 hook」一个跨页函数（不需 shctl/superkey）
adb push tools/rgntool /data/local/tmp/ ; adb shell chmod 755 /data/local/tmp/rgntool
adb shell /data/local/tmp/rgntool            # 自 hook -> 验证 -> 自 unhook（自清理）
```

`rgntool` 期望：`[R span] n=k -> backup=1100+k`（跨页函数**整体**从 region 克隆跑通）、页邻居 `nbfn(n)=n*2` 正常、`unhook: 1`。同理 `kpmhooktool`（L1a 每页多 override，仿 LSPlant 调用模式）也经 `lib/kpmhook` 自 hook。

> 实测（Pixel 6 `1C091FDF6008DN`，superkey 已移除）：`shpte` 已在内核运行、桥已开；`bridgetool probe` 回全部符号；`rgntool` 全项 OK、自清理干净。`dump` 还显示该机正跑着生产级会话——7 个 region（含 63 页的）挂在一个真实进程上、`.text` 不动、`maps_hidden=388`（即 L1d/L1e 真机应用内无痕 hook）。⚠️ 若 `dump` 显示已有存量 slot，说明设备在生产使用中——自 hook 类测试（rgntool/kpmhooktool）用自己的 slot 且自清理是安全的，但别对存量 slot 跑 `pgdisarm`/`unbridge`/`unload`。

## 版本耦合（必须与设备一致）

两个独立的版本 pin 必须与设备匹配，否则 load/supercall 会**静默失败**：

- `vendor/KernelPatch` checkout 在 tag **0.13.1**；它提供的 kpm SDK 头必须匹配设备上的 kpimg 版本（实测 kpimg `d01` = 0.13.1）。
- `cli/shctl.c` 里的 `KP_VER_CODE`（`(0<<16)|(13<<8)|1`）把 KernelPatch 版本编进每次 supercall 的 `vcmd`；升级 KernelPatch 就同步 bump。

## 硬核教训（别再用血踩一遍）

1. **clang `-O2` 对 KP 加载器 miscompile** → 运行期 SP/PC 对齐 panic + 重启。KPM 必须 `-O0`（`build.ps1` 已锁），外加 `-mbranch-protection=bti`。
2. **绝不在 supercall/control 上下文或断点异常 handler 里调阻塞/perf 内核 API**。对远端 task 调 `register/unregister/modify_user_hw_breakpoint` 会卡 D-state + 持 KernelPatch 锁 → 后续 supercall 全挂 → 只能物理重启。修法：一切 perf 调用经 `task_work_add` 推迟到目标任务自己的上下文。
3. arm64 只有在 perf event 用**默认** overflow handler 时才会对执行断点自动单步；用了自定义 handler（为捕获寄存器）就不会 → 裸执行断点无限重触发。解法：**entry↔return 状态机**（入口把断点移到 LR，返回时移回入口）。
4. `pgrep -f <path>` 会匹配到它自己的命令行——用 `ps -A` / `pgrep -x <comm>` 计数。

## 产品化：LSPlant / Vector（及未来的 Frida-Gum 无痕后端）

目标成品是一个改造版 **Vector**（`../Vector`），其 hook 后端换成本仓 KPM。要点（另见 memory `lsplant-vector-integration`）：

- Vector 的 `inline_hooker(target, hooker) → backup` **精确对应** `hwhookto`（HWBP，因真实 libart 函数共享页）+ ghost backup；`inline_unhooker` → `hwunhook` + `ghostfree`。
- **Layer 1**（LSPlant init 时的 native libart hook）：把 Vector 的 `inline_hooker`/`unhooker` 换成经 syscall bridge 调 KPM。载体是扩到每页多 override、跨多页的 **UXN `pghook`**（RV-2 region 克隆）。L1a–L1e 已完成并**真机应用内实测**：LSPosed 管理器 6 个 libart inline hook 全走 region 克隆、零 Dobby 回退、`.text` 不动。
- **Layer 2**（Java 方法）：**SSOL** 是稠密框架 JIT 的正确+可扩展路径（region 克隆保留给 L1 native 与简单 app 的 Java hook）。
- **Frida-Gum**（可选、更大）：用 `hwhookto` 重做 Gum 的 `Interceptor`、用 ghost 内存重做 Stalker 代码缓存；同一 KPM、不同前端。

**剩余 / 未来**：P3.5（`BLRAAZ`/`BRAAZ` PAC 降级）；更多隐藏 hook（进程 `/proc` readdir、端口 `/proc/net/tcp`、线程 `/proc/pid/task`）；ghost VA 钉死防分配器复用、slot 表 RCU 等加固。
