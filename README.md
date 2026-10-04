# KSSMA Merger · 离线化合并器

把《扩散性百万亚瑟王》（KSSMA）2013 年国服安卓客户端**变成离线可玩**的 PC 端工具。

> **本项目不包含游戏本体。** 你需要自备：
> 1. 原版客户端 APK（`com.square_enix.million_cn`）
> 2. 对应的资源包 zip（140330 包）
>
> 合并器把本地服务器与全部修正装配进你自己的客户端副本，产出一个可离线游玩的 APK。

---

## 这个工具做什么

客户端原本要连官方服务器。官方服务器早已关闭，所以原版客户端现在**打不开**。

合并器做的事：**让客户端连你自己手机里的本地服务器**，把原本由官方下发的内容
（卡牌数据、扭蛋、战斗结算、剧情、社交……）全部改为本地生成。

结果：**断网也能完整游玩**，包含探索、扭蛋、合成进化、妖精战、区域守护者、
骑士对战（人机）、排行榜、玩家情报、新手教程等。


##资源指引

如果你没有资源，你可以考虑通过从 [Internet Archive 的 gacha-archive](https://archive.org/details/gacha-archive) 下载以下两个文件。
	```
com.square_enix.million_cn-1.0.0.100.0712.M330.apk
com.square_enix.million_cn-140330.zip
两者SHA-256:
4F6A854C49D1AF59BB5500828D2BDDA0767F4D6A9FCFA8D4D6E46EA9257C58A7  com.square_enix.million_cn-1.0.0.100.0712.M330.apk
D311C8FC3152BE328FA36638F2075F01B95A8AAB2DEA47F918DB3101F18D69F5  com.square_enix.million_cn-140330.zip

```

---

## 你需要什么

| 项 | 要求 |
| --- | --- |
| 系统 | Windows 10 / 11（x64） |
| 软件 | **什么都不用装**（不需要 Java、Android SDK、Python） |
| 磁盘 | 约 **1.5 GB** 空闲（输入 773 MB + 输出约 900 MB） |
| 输入 | 原版 APK + 资源包 zip |
| 输出 | 一个约 900 MB 的 APK |

> **运行时间**约 **20–60 秒**（大头是磁盘 IO）——因为资源全部以**未压缩**方式存储，
> 合并过程是"复制流"而不是"重新压缩"。
>
> **安装提示**：输出 APK 有 900 MB，请用 USB 传输，别用浏览器下载再传
> （部分浏览器/网盘对大文件不友好）。设备上至少留 2 GB 空间。

---

## 怎么用

### 图形界面（推荐）

```
1. 下载并解压 KSSMA-Merger 文件夹
2. 双击文件夹里的 KSSMA-Merger.exe
   （首次启动会自动填好 Downloads 里的原版 APK / 资源包，如果有的话）
3. 确认三个路径：原版 APK、资源包 zip、输出目录
4. 可选：勾选「使用高清 OP 动画」（+100 MB，逐帧超分）
5. 点「开始合并」，等 20–60 秒
6. 完成后点「打开输出目录」，用 adb 安装产物：
       adb install -r KSSMA-Offline-<时间戳>.apk
7.如果你用的是mumu模拟器，请在mumu模拟器中，**新建设备**，安卓版本选择**安卓12**，启动后，把apk拖进模拟器安装即可。
```

> **exe 必须在它的文件夹里运行**，不能单独拷出去——依赖与 105 MB 修正数据都在
> 同目录的 `_internal\` 下。分发时请把**整个文件夹**打包。
>
> 想确认环境是否正常，可以跑一次自检：
> ```
> KSSMA-Merger.exe --selftest
> ```
> 结果会打印到控制台并写入 `selftest-report.txt`。

### 命令行

```
KSSMA-Merger.exe --apk <原版.apk> --res <资源包.zip> --out <输出目录>
                 [--artifacts <目录>]   # 指定修正数据目录（默认包内 artifacts）
                 [--hi-op]              # 使用高清 OP 动画
                 [--no-sign]            # [开发用] 不签名
                 [--report <路径>]      # 自查报告输出路径
                 [--quiet]              # 只输出错误
                 [--selftest]           # 自检（+ --apk/--res/--out 可跑真实合并）
```

> 源码方式运行：`python src/main.py --apk … --res … --out …`
> （命令行**不签 v2/v3**，原因见技术档案 §9b.3；v1 对目标环境已足够）

---

## 从源码运行 / 自行打包

```bash
# 需要 Python 3.9+
pip install cryptography asn1crypto        # 签名用
python src/gui.py                          # 跑图形界面
python src/main.py --help                  # 跑命令行

# 打包成 exe（需要 pyinstaller）
pip install pyinstaller
pwsh -NoProfile -File packaging/Build-Exe.ps1
# 产物：dist/KSSMA-Merger/KSSMA-Merger.exe
```

> 打包用 **onedir**（不是 onefile）。曾试过 onefile，实测直接失败：
> `[PYI-…:ERROR] Could not create temporary directory!` ——
> onefile 每次启动都要把 ~120 MB 自解压到 `%TEMP%`，体积这么大时既慢又容易失败，
> 而 105 MB 的修正数据会被反复解压。onedir 启动是即时的。

---

## 修正数据（`artifacts/`）是什么、放哪里

### 它是什么

`artifacts/` 是**预编译好的修正数据**（约 105 MB），合并时被塞进你的 APK：

| 内容 | 作用 |
| --- | --- |
| `classes2.dex` | 本地服务器（Java 编译成 dex）+ 启动注入 |
| `classes-dex/classes.dex` | 修好的客户端启动类（全局偏移修正 + 新增字符串） |
| `kssma-data/` | 卡牌 / 扭蛋 / 探索 / 商店等配置 + 登录应答模板 |
| `kssma-data/op.mp4` | 高清 OP 动画（**可选**，101 MB，只有勾选「使用高清 OP」时才用） |
| `database/` | 6 张二进制主数据表（卡牌、Boss、道具…） |
| `seeds/` | 48 个补种资源（缺了会导致 native 崩溃） |
| `patches/` | `.so` 与 `AndroidManifest.xml` 的**字节补丁**（在你的文件上原地打） |
| `manifest/` | 改好的 `AndroidManifest.xml` |

> 仓库里**不含** `artifacts/`（105 MB 二进制且含游戏数据）。
> 请从 **GitHub Release** 下载；exe 发行包已经把它打包在里面了。

### 用户需要放到哪里

**正常情况什么都不用做。** 下载 exe 发行包后，`artifacts/` 已经在这里：

```
KSSMA-Merger/                  ← 解压出来的文件夹
├─ KSSMA-Merger.exe
└─ _internal/
   └─ artifacts/               ← 就在这里，程序会自动找到
```

程序按下面的顺序找 `artifacts/`，**找到第一个就用**：

| 顺序 | 位置 | 什么时候用得上 |
| --- | --- | --- |
| 1 | 环境变量 `KSSMA_ARTIFACTS` 指向的目录 | 想显式指定 |
| 2 | **exe 同级**的 `KSSMA-Merger/artifacts/` | 想**覆盖**内置那份（例如自己重编过服务器） |
| 3 | `KSSMA-Merger/_internal/artifacts/` | 发行包自带，**默认走这条** |
| 4 | 源码树的 `merger/artifacts/` | 从源码运行 |

所以：

- **只想用** → 下载 exe 包，解压，双击，结束。
- **想替换内置的** → 把新的 `artifacts/` 放到 **exe 同级**（第 2 条优先于内置）。
- **不确定用的是哪个** → 跑自检，它会**打印实际路径**：

```
KSSMA-Merger.exe --selftest
```

```
  app_dir       : …\KSSMA-Merger
  bundle_dir    : …\KSSMA-Merger\_internal
  artifacts     : …\KSSMA-Merger\_internal\artifacts（存在）
                   71 个文件
  结果：✅ 环境就绪
```

若显示"**不存在**"，它会打印**期望路径**，照那个位置放即可。

---

## 常见问题

**Q：合并后的 APK 能分发吗？**
**不能。** 它内含游戏原始素材，属于二次分发。请只在自己设备上使用。

**Q：为什么输出有 900 MB？**
原版客户端 + 完整资源包（含全部卡图、立绘、场景、音效、OP）就是这个体量。

**Q：装不上 / 提示签名冲突？**
先卸载设备上已有的同名应用。合并器使用自签名证书，与官方（或其它修改版）签名不同。

**Q：用的是什么签名方案（v1 / v2 / v3）？**
合并器签 **v1（JAR signing）**。这对目标环境**足够**——原版客户端未声明
`targetSdkVersion`，因此 Android 11+ 的"必须 v2+"强制检查不适用，
Android 12（含 MuMu 12）可正常安装。
（本项目自己的完整构建走 `apksigner`，产物是 v1+v2+v3；合并器这条 Python 路径
目前只做 v1，原因与技术细节见技术档案 §9b.3。）

**Q：提示「你提供的 APK 版本不受支持」？**
本项目只支持特定版本的原版客户端。请确认你的是 2013 年国服
`com.square_enix.million_cn` 的对应版本，且**未被其它工具修改过**。

**Q：提示「资源包不完整」？**
请使用配套的 140330 资源包（约 478 MB，约 6900 个文件）。

**Q：提示「输出目录不可用 / 写入被拒绝」怎么办？**
这是**安全软件按位置拦截**，不是权限设置问题——已实测确认。

本程序要创建一个 **900 MB 的 `.apk`**。安全软件会限制它**只能在程序自己那一带的
目录树里写文件**，**即使别的目录权限完全正常**。

实测规律（Windows 11 + Defender 实时保护开启、受控文件夹访问关闭）：

| 输出位置 | 结果 |
| --- | --- |
| 程序文件夹内（默认的 `output/`） | ✅ 正常（5 秒写完 799.8 MB） |
| 程序文件夹内的子目录 | ✅ 正常 |
| **程序文件夹的上级目录** | ✅ 正常 |
| 完全无关的目录 / 其它盘（如 `D:\Engine`） | ❌ `Permission denied` |

关键点：**同一个目录用 Python 写 900 MB 是成功的**，所以排除权限、磁盘、路径
问题——被拦的是**本程序**，且限制范围是"程序所在位置那一带的目录树"。

**结论很简单**：

> **把整个 `KSSMA-Merger` 文件夹放到你想输出 APK 的地方，再运行它。**
> 默认输出目录（程序文件夹下的 `output/`）就一定能写。

**如果你想换个位置输出**：不要改输出目录，而是**把整个程序文件夹搬过去**
（用户实测：复制到新位置后，就能在新位置正常输出）。

如果你已经遇到该错误，程序会：

1. 明确告诉你"目录本身通常正常，被拦的是本程序"
2. **主动问你「要不要切到实测可写的目录？」** —— 选「是」就自动填好，
   再点一次「开始合并」，不用自己去别处找目录
3. 若你坚持用原目录，则需把本程序加入杀毒软件白名单，
   或临时关闭「勒索软件防护 / 受控文件夹访问」

**Q：命令行模式（`--apk/--res/--out`）没有输出？**
GUI 版 exe 是**窗口程序**（`console=False`），标准输出不会出现在你的终端里。
要在终端里看输出，请用源码方式运行：

```
python src/main.py --apk <apk> --res <zip> --out <dir>
```

（`KSSMA-Merger.exe --selftest` 例外：它会把结果写入 `selftest-report.txt`。）

**Q：杀毒软件报警？**
打包成 exe 的程序常被误报。你可以直接从源码运行（见下），或自行核对 SHA256。

**Q：能装在 Android 模拟器上吗？**
可以（需要支持 ARM 翻译的模拟器）。也支持真机。

**Q：OP 动画为什么要单独选？**
高清 OP 是逐帧超分处理的，体积约 100 MB。不选则使用原版 OP。

**Q：会联网吗？**
合并过程**完全离线**。只有首次运行需要下载修正数据（也可手动放置）。

---

## 自行核对

每次发布都会在 Release 说明里附上产出 APK 的 SHA256 与「条目级校验清单」。
合并器也会输出一份 `merge-report.json`，列出所有条目的哈希，便于你自查。

---

## 许可证

代码：**MIT**（见 [LICENSE](../LICENSE)）

**声明**：
- 本项目**不含游戏本体**，不分发任何 Square Enix 素材
- 本项目**不破解付费内容**，不做任何绕过官方验证的行为；它把客户端指向一个
  **完全本地**的服务器实现，用于在官方服务终止后继续单机游玩
- 请**不要分发**合并后的 APK
- 请勿用于商业用途
- 本项目与 Square Enix / 盛大游戏**无任何关联**
- 收到版权方通知将立即下架

---

## 文档

| 文档 | 内容 |
| --- | --- |
| [docs/方案.md](docs/方案.md) | 设计与决策记录（含所有技术权衡） |
| [docs/技术说明.md](docs/技术说明.md) | 合并器具体做了什么 |
| [docs/技术档案.md](docs/技术档案.md) | 完整的逆向与实现技术档案 |
| [docs/校验与一致性.md](docs/校验与一致性.md) | 修正数据的哈希清单与一致性验证方法 |
