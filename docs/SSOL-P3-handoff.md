# SSOL P3 续作 handoff（冷启动用）

**目的**：把 SSOL（single-step out-of-line traceless hook）从「KPM 侧全部完成+验证」推进到
「接进 Vector 的 LSPlant hook 流 → 在 katana 上 5 面全 CLEAN」。这份文档让新 session 不读全history
也能接着干。背景与北极星见 `docs/SSOL-design.md` 和记忆 `kpm-ultimate-goal`。

---

## 1. 现状一句话

**KPM 侧（`kpm/shpte.c`）的 SSOL hook 机制已 100% 完成并真机验证**：UXN 陷页 → 逐指令 simulate
（PC 相关）/ XOL+硬件单步（PC 无关）跑**原始代码原地址** → 入口覆盖（hook 触发）→ bk_va 一次性旁路
（call-original）。克隆路线在复杂 app 上崩的两个结构性原因（代码/数据交织、克隆返回地址污染 ART 栈）
机制层面全部解决。**剩下的是把它接进 Vector**（跨仓库 + gradle 构建），然后真机验。

> **【2026-06-15 进度】§5.1 多目标 SSOL 区域 = DONE + 真机验证**（stealth-poc `46a34bf`，本地 main 未推）。
> 一个 `ssol_rgn` 现在带 `MAX_SSOL_OV=16` 组 `{ov_off,ov_replace,ov_bk}`（仿 pghook `ov_off[]`），
> 一页可挂多个 qc；`ssolhook` 新签名 `<pid> <region_base> <npages> <xol_va> <entry> <replace> <backup>`
> 走 find-or-append；新增 `ssolunhook`（逐 ov 退役、最后一个 ov 走整区 disarm）。一次性旁路改按
> **entry VA** keying。自测 hook_me+hook_me2 同页两 ov 全 PASS、call-original 各自正确、设备存活。
> **§5.2 bk_va 由调用方传唯一未映射 VA**（KPM 不自分配）。**现从 §5.3 Vector 接线开始。**

设备：Pixel 6 `1C091FDF6008DN`，APatch+KernelPatch，superkey `Lanhuachun2`，shctl 在
`/data/local/tmp/shctl`，shpte.kpm 开机自动加载（bootstrap `load;probe;bridge`）。

---

## 2. 铁律 / 踩过的坑（务必遵守，否则会把设备搞死机要物理重启）

- **绝不 live-unload shpte**（`shctl unload`）。KP 在 `rcu_read_lock` 内跑模块 exit **和** control0
  （`vendor/KernelPatch/kernel/patch/module/module.c` L461、L534），我们的 teardown 若 `synchronize_rcu`
  会自死锁挂内核。开发期**一律重启重载**（reboot 不调 exit）。已在代码里去掉 unregister（commit `076e9eb`）。
- **所有 supercall 包 `timeout`**（`timeout 10 shctl ...`）。曾因热卸载挂死、需物理断电重启。
- KPM 改了就得 **reboot 才能生效**；ssoltarget/驱动脚本改了**不用 reboot**（直接 push 重跑）。
- 构建 KPM：`pwsh kpm/build.ps1 -Src shpte.c`（freestanding/-O0，NDK 26.1）。日志会打印「compiling
  shpoc.c」是 build.ps1 的固定文案 bug，实际产出 `shpte.kpm`，无视即可。`shpte.kpm/.o` 被 gitignore，只跟踪源码。
- 推 + 重启 + 跑自测的固定流程见 `tools/run_ssoltest.sh`（驱动脚本，CRLF 要先 `sed -i 's/\r$//'`）。

---

## 3. KPM 侧已实现的 SSOL 契约（`kpm/shpte.c`，全部已 push origin/main）

桥命令（`shctl Lanhuachun2 control shpte <cmd>`）：
- `selfstep` / `ssolstat` — 单步原语自测 + 计数查看。
- `ssoltest <pid> <func_va> <npages> <xol_va>` — 纯透传 SSOL 区域（无入口覆盖），自测用。
- `ssolhook <pid> <func_va> <npages> <xol_va> <replace_va> <backup_va>` — **带入口覆盖 + call-original**。
- `ssoldisarm` — 拆所有 SSOL 区域，恢复 UXN，释放快照/scratch。

核心数据结构 `struct ssol_rgn`（单目标/区域）：
```
active,pid,mm,page,npages,
entry,        // 被 hook 方法入口 VA（0=纯透传）
replace,      // 入口重定向目标 = trampoline
bk_va,        // call-original 的 backup VA（未映射）；命中即武装一次性旁路+重定向到 entry
insns,        // vmalloc 的指令快照 npages*1024（指令+字面量池，避免 fault 路径 PAN 不安全读用户内存）
xol_kaddr,xol_va,  // XOL scratch 页（内核别名写、用户 VA 执行单步）
ptep[],pte_orig[], n_sim,n_xol,n_hook,n_orig
```
`before_pf`（do_page_fault before 回调）SSOL 分支逻辑：
1. **bk_va 派发**（在区域页匹配循环之前，单独扫一遍）：`far==s->bk_va && tgid==s->pid` →
   `byp_arm(tid,i)` + `regs->pc = s->entry`（x30 不动）。
2. **区域页匹配**：`far` 落在 `[page,page+npages)` 且 tgid 匹配：
   - `far==entry`：`byp_take(tid,i)` 成功 → call-original，落到 SSOL 跑 body；否则 `replace` 非空 →
     `regs->pc=replace`（hook 触发）。
   - 取快照指令 `insns[(far-page)/4]` → `ssol_simulate`：SIMULATED 则保持 UXN 返回（下条再缺页）；
     XOL 则拷到本线程 scratch 槽 + `user_enable_single_step`。
3. 单步异常由注册的 `ssol_step_fn`（`register_user_step_hook`）消费：把 pc 修回 `orig+4`、关单步、放 ctx。

单步原语 = uprobes 流（内核导出 `register_user_step_hook`/`user_enable_single_step` 等，kallsyms 可解析）。
`ssol_simulate` 是 `lib/ssol.c`（P0 离线验证过）移植进来的；BR/BLR/RET 套 `STRIP_PAC`；LDR-literal 从快照读。

一次性旁路表：`g_byp_tid[]/g_byp_rgn[]` + `byp_arm/byp_take`（按 tid，bk 命中武装、entry 命中消费，两次连续 fault）。

自测程序 `tools/ssoltarget.c`（NDK arm64，每个被测函数 `aligned(4096)` 独占页；注意 `aligned` 的**数据**
数组不分隔 .text，要用 `aligned` 的**dummy 函数** `_pgsep` 才能让 main 不与 tramp 共页）：
- `ssol_add/ssol_mix/ssol_indirect` 透传 SSOL；`hook_me`+`tramp` 验入口覆盖+call-original（tramp 调
  `backup=0x5590000000` 这个未映射 bk_va）。最近一次：全 PASS，`hook_me(3,4)=1007 tramp_ran=1
  n_hook=1 n_orig=1`，设备存活。

---

## 4. LSPlant 契约（Explore agent 读 `Vector/external/lsplant/lsplant.cc` + `Vector/.../module.cpp` 得到）

- Vector `module.cpp` 的 `init_info_.traceless_inline_hooker = [](target, replace){ kpm_inline_hooker(target,replace) }`，
  gated by `persist.kpmhook.l2=1`，且 `QcIsTraceable(target)` 通过才走（否则 in-place）。
- `target = qc`（Java 方法的 quick-compiled code 地址），`replace = entrypoint`（LSPlant 用
  `GenerateTrampolineFor(hook)` 生成的**固定 20 字节** ARM64 桩：`ldr x0,#12; ldr x16,[x0]; br x16`，
  跳到 hooker ArtMethod 的入口；桩大小 `kTrampolineSize` 已知）。
- **`backup`（`kpm_inline_hooker` 的返回值）被设到一个单独的 backup-ArtMethod 的 entry，由 ART 的方法
  调用机制调用** —— 不是被 trampoline 直接调。**所以真实调用和 call-original 都经 ART invoke 桩到达 qc
  入口,LR 都在 ART 桩里 → 无法用 LR 区分 → 必须用 bk_va 一次性旁路（已实现）。**
- 当前 `kpm_inline_hooker`（`Vector/native/src/kpm/kpmhook.c`）走的是 **DBI 克隆 + `pghook`**：
  `backup = clone + offmap[roff/4]*4`，命令 `pghook <pid> <base> <clone> <map> <ninsn> <roff> <hooker>`。
  这就是要被 SSOL 替换的地方。`InitInfo` 字段、`HookInline`(L1 Dobby)、`force_compile`、`on_method_hooked`
  等见 module.cpp:484-535、kpmhook.c:364-434。

---

## 5. 下一步要做的（P3 Vector 接线，按顺序）

**5.1 KPM：`ssol_rgn` 扩成「一页多目标」 ✅ DONE（`46a34bf`）**。已实现:`ssol_rgn` 带
`MAX_SSOL_OV=16` 组 `volatile {ov_off[], ov_replace[], ov_bk[]}`（OV_NONE 哨兵 = inert，仿 pghook）；
`ssol_set_ov` key-last 发布、`OV_NONE` key-first 退役。`before_pf`:bk_va 派发扫所有区域所有 ov 找
`far==ov_bk[k]`；entry 判定在本区域 ov 里找 `roff==ov_off[k]`。一次性旁路 re-key 成 **(tid, entry VA)**
（`g_byp_entry[]`）。`do_ssolarm` 改 find-or-append（命中 (pid,page) 现有区域就追加 ov，否则新建）。
`MAX_SSOL_RGN` 8→16。`ssolstat` 打印每条 ov。**做成「一页一区域多 ov」，和 pghook 同构（不是一 qc 一区域）。**
*注:`ssolhook` 现在 base 与 entry 分开传，于是一个多页区域可把落在不同页的 entry 归到同一区域。*

**5.2 KPM：bk_va 分配 ✅（定为调用方传入）**。每个 hook 一个唯一未映射 VA，由 **Vector 侧传入**
（KPM 不自分配，`do_ssolarm` 直接存 `ov_bk`）。Vector 用固定高基址 + hook 序号,如 `0x5500000000 + idx*0x1000`,
保证目标进程里未映射(高地址通常空)。自测里 hook_me/hook_me2 用 `0x5590000000`/`0x5591000000`。
另已加 `ssolunhook <pid> <region_base> <entry>`(仿 pgunhook:逐 ov 退役,最后一个 ov 整区 disarm)供 `kpm_inline_unhooker`。

**5.3 Vector：重写 `kpm_inline_hooker`(`Vector/native/src/kpm/kpmhook.c`)**:
- 不再 `make_rgn`/建 DBI 克隆/发 `pghook`;改为算出 `qc` 所在页范围 → 发 `ssolhook <pid> <qc> <npages>
  <xol_va> <replace=hooker> <bk_va>`。
- `xol_va`:每进程一个 scratch 页基址(高未映射 VA);`bk_va`:每 hook 唯一(见 5.2)。
- **返回 `bk_va` 作为 backup**(LSPlant 会把它设成 backup-ArtMethod 的 entry)。
- `kpm_inline_unhooker`:发新的「移除某 ov」命令(需在 KPM 加,或先整页 disarm)。
- LSPlant 的 trampoline/backup-ArtMethod 那侧**大概率不用改**(backup 只是个 ART 会跳过去的 VA)。
- `QcIsTraceable`(module.cpp):SSOL 不像克隆那样要求 body 不跨页/无数据交织 —— 可放宽,但先保持原判定跑通再说。

**5.4 构建 + 真机**:Vector 编 zip(JBR21 gradle,见记忆 `build-requires-jbr21`;改 native/src/kpm 要
`rm -rf zygisk/build/Debug` 强制重编,否则 globbed 源不重编)→ apd 装 → reboot。优先用 **`/kpm-probe` skill**
(一条龙 build→push→reboot→gate→launch→poll→VERDICT)。先在 **hookdemo**(简单 app,GREEN 基线)验
hook 工作 + 5 面;再上 **katana**(克隆的失败案例)验复杂 app。

**5.5 收尾**:S2 —— 把 xol scratch 页 + 任何 anon-exec 的 SSOL 残留从 /proc/self/{maps,smaps} 隐藏
(复用 KPM 现有 maps-hide `hidergn`/`g_hide`)。probe 期望 **S1/S2/S3/S4/S5 全 CLEAN on katana** = 终极目标在复杂 app 达成。

---

## 6. 提交链(全部 push 到 stealth-poc origin/main = `1013503897/stealth-poc`,**勿推 JingMatrix**)

P0 `8c0f7a0`(lib/ssol.c 离线核+单测)→ P1a `af0bf7d`(移植进 KPM)→ P1b-1 `221c9d9`(单步原语)→
P1b-2/c `2202a97`(完整 XOL 回路)→ `076e9eb`(teardown 自死锁修复)→ `4ea6042`(间接调用去风险)→
`e2bdd0b`(入口覆盖+LR,后被取代)→ `da0048f`(**bk_va call-original,当前 HEAD**)。
全程真机验证。lib/ssol.* 与 tools/ssoltarget.* 也在内。

---

## 7. 快速复跑当前 KPM 自测(确认地基没坏)

```
pwsh kpm/build.ps1 -Src shpte.c
pwsh tools/build_ssoltarget.ps1
adb -s 1C091FDF6008DN push kpm/shpte.kpm /data/local/tmp/shpte.kpm
adb -s 1C091FDF6008DN push tools/ssoltarget /data/local/tmp/ssoltarget
adb -s 1C091FDF6008DN push tools/run_ssoltest.sh /data/local/tmp/run_ssoltest.sh
adb -s 1C091FDF6008DN shell "chmod 755 /data/local/tmp/ssoltarget /data/local/tmp/run_ssoltest.sh; su -c \"sed -i 's/\r\$//' /data/local/tmp/run_ssoltest.sh\""
adb -s 1C091FDF6008DN reboot      # KPM 变了必须重启;等 boot_completed + bootstrap bridge
adb -s 1C091FDF6008DN shell su -c 'sh /data/local/tmp/run_ssoltest.sh'
# 期望:5 行全 PASS(含 hook_me=1007 + hook_me2=2012),same_page=1,ssol[3] nov=2 n_hook=2 n_orig=2,
#      ssolunhook ov1→"region still armed" / ov0→"disarmed region",末尾 nssol=0,设备存活
```
