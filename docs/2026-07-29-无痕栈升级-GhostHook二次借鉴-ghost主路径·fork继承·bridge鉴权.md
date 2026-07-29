# 无痕栈升级评估（二）：GhostHook 二次借鉴点 —— ghost 主路径 · fork 继承 · bridge 鉴权

> 来源文章：看雪 GhostHook / SharkFall，`https://bbs.kanxue.com/thread-292066.htm`
> 本文是第二轮借鉴评估，**承接但不重复** `docs/2026-07-28-无痕栈升级-shadowpage与ghostVA钉死-评估与patch.md`：
> 那份覆盖了 **§5 `get_unmapped_area` 钉死 ghost VA** 与 **§6 Shadow Page 读写分离（软件 DABT）**；
> 本文收录**那两条之外**、上一轮没提取的可借鉴点，并给出对我们 `shpte` 栈的落地设计。
>
> **实证锚点**：`tools/s0probe`（2026-07-29 两台 Pixel6 实测）已量化出栈的唯一实质弱点——
> 主路径 clone 是**匿名 RX mmap**（`lib/kpmhook.c:314`），maps-hide 修好后（commit `ef1080f`）它**从 `/proc/*/maps` 隐藏，但仍可直读 + 可执行 + pagemap PRESENT**。本文 Tier-1 就是关这个面的更划算路线。

---

## 落地状态

- **① ghost 主路径 —— 已实现 + 双端设备验证通过（2026-07-29，KPM v0.6.2）**。`kpm/shpte.c` 加 `ghost_inject_region`/`ghost_region_free` + 新 verb `pghookg`（多页/多槽，与 legacy 单槽 `g_ghost_*` 分离）；`before_pf` 路由 `s->ghost?ghost_va:clone`；`lib/kpmhook` 加 `kpm_hook_set_ghost()` 开关（默认 off，老 `pghook` 路径字节等价、ghost 注入失败自动回退，clone 建成 RW buffer 不再 mprotect RX）。`tools/s0probe`（ghost=ON）在 **19301(5.10) + 1C091(6.1)** 各连跑 3 次全绿：clone 的 ghost_va **maps NONE + mincore ENOMEM + pagemap present=0**（枚举全盲），直读/执行仍成立（诚实边界）；`pgunhook`→`ghost_region_free` 拆卸无泄漏（`npg` 不累加）。**关键正确性**：DBI clone 位置无关（`make_rgn` 在 mmap 拿到 clone 地址前就 recompile → clone 字节不依赖运行地址），搬进 ghost 必然正确。
- ② fork 继承 / ③ bridge 鉴权 —— **未开工**（下一版）。

## 0. TL;DR — 借鉴点与优先级

| # | 借鉴点 | 对我们的价值 | 复用已有？ | 工作量 | 优先级 |
|---|---|---|---|---|---|
| ① | **主 clone 挪进 ghost memory**（VMA-less）替代匿名 mmap | 关闭 S0 枚举暴露面（maps/mincore 查不到） | ✅ `ghost_inject`/`ghostredirect` 原语已验证 | 中 | **P0** |
| ② | **fork/Zygote 继承**：手动重克隆 ghost PTE | ①的**强制**搭档，否则子进程 hook 静默消失 | 半（`wake_up_new_task` hook 基建在） | 中 | **P0（随①）** |
| ③ | **bridge 调用方鉴权**（uid/签名，不止 magic） | 防 RASP 探到 bridge 反向操纵/探测 KPM | 改 `before_bridge` 一处 | 小 | **P1** |
| ④ | 单步 `MDSCR_EL1.SS` per-CPU，迁核丢步 → 钉核 | de-risk §6 shadow page 的单步 | — | 小（随§6） | P2（随§6） |
| ⑤ | 多页 shadow/ghost 校验 PFN 唯一 | 防 `vmap` 多页同 PFN 串数据 | — | 小 | P2 |
| ⑥ | HWBP 直接写调试寄存器 + 伪造 ptrace 假账本 | 替掉可枚举的 perf_event 路径 | 重写 `shhwbp` | 大、风险高 | P3 |
| ⑦ | ArtMethod 的 Shadow **Data** Page（按读取者身份） | 藏 lsplant 的 `entry_point` 篡改 | — | 大 | P3 |

**推荐落地顺序**：**①+② 一起上**（性价比最高、复用 P4.2 已验证原语、直接消掉 S0 面）→ **③**（顺手硬化）→ §6 shadow page 留给"能直读已知 VA / 扫 ArtMethod"的硬核对手，届时 **④⑤** 是必备细节；**⑥⑦** 是另一层、成本高，最后考虑。

---

## Tier 1 — 高价值，且大多复用已有原语

### ① 主 clone 挪进 ghost memory（VMA-less），替代匿名 mmap

**文章原理**：GhostHook 的真正核心不是 shadow page，而是**"幽灵内存"作为一切 hook 载体**（daemon SO、跳板池、DEX 全放 VMA-less 内存）。利用的是 **MMU 页表 与 OS 的 VMA 管理层之间的信息差**：
- CPU 的 MMU 按页表查询合法 → 用户态能正常执行/访问；
- OS 遍历 `mm_struct` 的 VMA 链表却查不到 → `/proc/*/maps` 扫描、`mincore()` 盲探（只对 VMA 内地址有意义）**完全失效**。

**我们现状**：
- 主路径 clone = 用户态 `mmap(PROT_READ|WRITE, MAP_ANONYMOUS)` → `mprotect(R|X)`（`lib/kpmhook.c:314-319`），**在 VMA 里、可读**。maps-hide（`show_map` hook）只抹**列表**，S0 已实测 clone 仍可直读。
- **但我们已经有 ghost 原语且设备验证过**（P4.2）：`ghost_inject`（`kpm/shpte.c:1541`）= `vmalloc` 一页 → `access_process_vm` 拷字节 → `sync_icache` → `vmalloc_to_pfn` 组 PTE → `apply_to_page_range` 注入到**无 VMA 的 VA**；`do_ghostredirect`（`kpm/shpte.c:1445`）在此之上把 UXN redirect 的 PC 路由进 ghost 页，让 DBI clone **从 OS 看不见的内存里执行**。

**落地设计**：给 `do_pghook`（`kpm/shpte.c:2085`）增加 **"ghost 模式"**——
1. clone 不再由用户态 `lib/kpmhook.c` mmap，而是 **KPM 侧 `vmalloc` region-clone 字节**（DBI 结果仍由用户态算好、经 `access_process_vm` 读进内核，或直接把用户态 clone 拷进新 ghost 页）。
2. 用 `ghost_inject` 把它注入目标进程一个**无 VMA 的高 VA**（`g_ghost_va` 那套），`before_pf` 的 UXN redirect 改路由到 ghost VA（复用 `do_ghostredirect` 的 PC 改写逻辑）。
3. `lib/kpmhook.c` 的匿名 mmap clone 撤掉；`backup` 指针改为指向 ghost VA 内偏移。
4. `get_unmapped_area` 钉死（上一轮 §5）在此**真正生效**——保护这个 ghost VA 不被分配器复用。

**诚实的边界（决定它与 §6 的分工）**：
- ghost 挡的是**枚举**：maps / mincore / VMA 遍历都找不到这个 VA。绝大多数 RASP 就是"从 maps 拿区间→读内容比对"，这一步直接瞎掉。
- ghost **挡不住"已知 VA 直读"**（页表里在、可读）。唯一泄露向量 = **指向 ghost 区的代码指针出现在可读处**（lsplant 存下来的 `backup`、栈上返回地址、GOT 里的跳板指针等）。要连这个都堵，才需要 §6 shadow page（读→原始）。
- 结论：**先 ghost（便宜、已验证、挡住 S0 那类枚举），§6 shadow 作为对付"能直读已知 VA"的高级手段再上。** 二者互补，不是二选一。

**风险 / 工作量**：中。原语已设备验证，但把主路径从"用户态 mmap clone"改成"KPM ghost 注入"要动 `lib/kpmhook.c` 与 `do_pghook` 的接口、以及 offmap 传递路径；且**必须同时做 ②**否则 fork 后失效。

---

### ② fork / Zygote 继承 —— ①的**强制**搭档（不做 = 看着装上了、子进程里没了）

**文章的坑**：**`copy_page_range` 只遍历 VMA**，因此 **VMA-less 的 ghost PTE（以及 shadow PTE）在 fork 时被静默丢弃**。文章列了 fork 继承的四类对象：
- 幽灵内存 → `copy_page_range` 跳过，**需手动克隆**；
- 硬件断点寄存器 → per-CPU，fork 不复制，需重配；
- Shadow Page 映射 → fork 路径手动克隆；
- 线程 `clone()` → 共享 `mm`，无需克隆。

**为什么对我们致命**：Android app **全是 Zygote fork 出来的**。一旦 ① 把 clone 放进 ghost，**任何 forked 子进程里 UXN redirect 指向的 ghost 页 PTE 就没了** → 缺页 → 要么走原始 `.text`（hook 失效、静默），要么崩。**且不报错**，最难查。

**落地设计**：hook fork 路径，在子进程 `mm` 上把父进程已注册的 ghost PTE 逐个重注入——
- 挂点：`copy_process` 之后 / `wake_up_new_task`（我们 **`shhwbp.c` 已经 hook 了 `wake_up_new_task` 追新线程**，基建现成，P1.6b）；或更早的 `copy_page_range`/`dup_mmap` 后。
- 逻辑：新 `task->mm != parent->mm`（真 fork 而非线程 clone）时，遍历该 `pid` 名下所有 active ghost region（`g_pg[]` + ghost 元数据），对子 `mm` 用 `apply_to_page_range` 重注入同一份 ghost PFN 的 PTE（页物理内容可共享或按需 CoW 复制）。
- 复用：`ghost_inject` 的注入路径本身就能对指定 `mm` 打 PTE，改造成"对子 mm 重放父 mm 的 ghost 集合"。

**风险**：中。fork 路径是热路径且在原子/加锁上下文——**严守 D-state 铁律**（只做 PTE 写 + flush，绝不 perf/blocking），重克隆的重活尽量 defer 到子进程自身 `task_work` 上下文（和 shhwbp 一样的 defer 纪律）。

---

### ③ bridge 调用方鉴权 —— 我们现在是裸奔

**文章做法**：KPM 启动生成 32 字节随机 session key；**内核态校验调用者 APK 签名摘要**（编译期内置 Manager 证书），命中缓存 uid 走 fast-path；非 Manager 走一次性限时配对码 fallback。

**我们现状（弱点）**：sysinfo bridge（`before_bridge`，`kpm/shpte.c:3065`）**只有一个 `BRIDGE_MAGIC`（`0x5348505442524447`="SHPTBRDG"）常量门**——任何进程 `syscall(179, MAGIC, cmd,…)` 就能驱动 `shpte_run`（`kpm/shpte.c:3124`）跑**全部 verb**（pghook/hidemaps/ghost*/dump…）。magic 就明文写在 `lib/kpmhook.c:29` 和二进制里，**RASP 提取到就能反过来 dump/操纵我们的 KPM**（甚至 `pgdisarm` 把我们的 hook 拆了，或 `dump` 出所有 clone 地址）。

**落地设计**：`before_bridge` 里在 magic 之上加**调用方身份门**——
- 取 `current` 的 uid（`from_kuid` / 直接读 cred）与 cmdline，比对**编译期白名单**（授权的注入宿主：phoenixvec/Vector 所在进程的 uid 或包名）；
- 进一步可校验调用方 APK 签名摘要（成本高，可选）；
- 非白名单：**当真 `sysinfo` 放行**（`arg0 != magic` 的既有 passthrough 分支），绝不回错、不暴露 bridge 存在。
- 命中的 uid 缓存走 fast-path（避免每次 syscall 都算签名）。

**风险 / 工作量**：小。就改 `before_bridge` 一处 + 一张编译期白名单。**收益实在**：把 bridge 从"知道 magic 就能用"收紧到"授权进程才能用"。

---

## Tier 2 — 做 §6 shadow page 时的 de-risk 细节（§6 难点清单里没写）

### ④ 单步 `MDSCR_EL1.SS` 是 per-CPU，目标线程迁核就丢步

**文章的坑**：§6 软件 DABT 要"切 shadow → 单步过这条读指令 → 切回陷阱态"。单步标志 **`MDSCR_EL1.SS` 是 per-CPU 寄存器**，目标线程一被调度到别的 CPU，SS 就丢，单步失效。
**修法**：单步期间 `set_cpus_allowed_ptr` 把目标线程**钉在单个 CPU**，结束恢复亲和性。
**对我们**：直接适用 §6。⚠️ **与 D-state 铁律调和**——`set_cpus_allowed_ptr` 别在 `do_page_fault` 上下文调（可能睡眠/取调度锁），放到 sleepable 的 `register_user_step_hook` 回调上下文里做。

### ⑤ 多页 shadow/ghost 校验每页 PFN 唯一

**文章的坑**：`vmap` 分多页时可能几页**指向同一 PFN** → shadow/ghost 映射串数据。
**对我们**：`ghost_inject` 目前**单页**（`vmalloc` 一页）。一旦扩成多页 region ghost/shadow（① 的 region 级 ghost、或 §6 的整页 shadow 镜像），每页 `vmalloc_to_pfn`（`kpm/shpte.c:1565` 那套）后要**断言 PFN 互异**，否则复用同物理页会把不同页内容串在一起。

---

## Tier 3 — 更进阶 / 属于 ART hook 层，成本高、优先级低

### ⑥ HWBP 走直接操作调试寄存器 + 伪造 ptrace 假账本（替掉 perf_event）

**文章做法**：直接写 ARM64 调试寄存器（`DBGBVR/DBGBCR`）**绕过 perf_event 子系统**；并**拦截 ptrace 对调试寄存器的读写、回一份"假账本"**（真寄存器不受干扰），使 RASP 的"满载占坑 4 个 HWBP 槽 + 越界报错 + 读写一致性"测试全过。绑 TID 不绑 TGID，只给主线程下断、子线程无感。
**我们现状**：`shhwbp.c` 用的是 **perf API**（`register_user_hw_breakpoint`/`modify_user_hw_breakpoint`，`shhwbp.c:154-156`）——**可被枚举**：RASP 数 perf event、或"占满 4 槽"测试就撞上我们注册的 bp。
**对我们**：是 `hwhookto`（Vector/LSPlant 对付页共享 libart 函数走的路）的实质隐蔽性升级，但**复杂、风险高**（per-CPU 调试寄存器状态 + ptrace 拦截 + D-state）。我们主力是 UXN/KPM 无痕，HWBP 是备选 → **优先级低于 ①②③**。

### ⑦ ArtMethod 的 Shadow **Data** Page（按读取者身份区分）

**文章做法**：§6 是**代码页**读写分离；ArtMethod 是**数据**篡改（lsplant 改 `entry_point`），扫描器读 ArtMethod 就发现。文章的 shadow **data** page：**按发起读取的代码 PC 判断身份**——ART 运行时看篡改值（才能派发到 hook）、非信任扫描器看原始值；非信任**写**后做**差分同步**，保证 hook 字段不被覆盖。
**对我们**：是对付"ArtMethod 指针扫描"的正解，但要在 fault handler 里**分类 faulting PC（信任 vs 非信任）**，比 §6 的"所有读都看原始"复杂得多（§6 对代码页可以，因为 ART 不读自己 `.text`；但 ArtMethod 数据 ART 自己要读到篡改值）。属另一层、成本高 → 最后考虑。

---

## 附：与检测手段的对照（文章表 + 我们的落点）

| 检测手段 | 文章对抗 | 我们对应 / 落点 |
|---|---|---|
| maps 扫描 | 幽灵内存（VMA-less PTE） | **①** ghost 主路径（现状只有 maps-hide 抹列表，仍可直读） |
| `mincore` 盲探 | 同上（只对 VMA 有效） | **①** ghost 后天然免疫 |
| 已知 VA 直读 clone | shadow page（读→原始） | **§6**（上一轮）；① 挡不住这个 |
| fork 后 hook 丢失 | 手动克隆 ghost/shadow PTE | **②**（`copy_page_range` 只遍历 VMA） |
| bridge 被第三方驱动 | 调用方签名鉴权 | **③**（现状只有 magic 门） |
| `perf_event` 枚举 HWBP | 直接写调试寄存器 | **⑥**（现状 perf API 可枚举） |
| ptrace 读调试寄存器 | 假账本 | **⑥** |
| ArtMethod 指针扫描 | shadow data page | **⑦** |

---

## 下一步 backlog（建议）

1. **P0：① ghost 主路径 + ② fork 继承（打包做）** —— 复用 P4.2 `ghost_inject`/`ghostredirect` 原语，消掉 S0 实测的枚举暴露面；② 是硬前置，不做则子进程失效。上设备用 `tools/s0probe` 复验（clone 应从 maps **且** VMA 遍历都查不到），并新增 fork 场景验证（子进程里 hook 仍在）。
2. **P1：③ bridge 鉴权** —— 改 `before_bridge` 加 uid/白名单门，小改动、硬收益。
3. **P2：§6 shadow page**（上一轮 §6）+ 本文 **④⑤** 细节 —— 对付"能直读已知 VA / 扫 ArtMethod"的硬核对手时再上。
4. **P3：⑥ HWBP 直接寄存器 / ⑦ ArtMethod shadow data** —— 另一层、成本高，最后。

> 交叉引用：`docs/2026-07-28-无痕栈升级-shadowpage与ghostVA钉死-评估与patch.md`（§5 get_unmapped_area / §6 shadow page）；S0 探针 `tools/s0probe.c`（commit `09c7111`）；maps-hide 跨内核修复 `commit ef1080f`；ghost 原语 `kpm/shpte.c:ghost_inject@1541 / do_ghostredirect@1445`。
