# KSSMA Merger · 发布说明（可直接贴到 GitHub Release）

## 下载哪个？

| 文件 | 大小 | 给谁用 |
| --- | --- | --- |
| `KSSMA-Merger-<日期>-win64.zip` | 120 MB | **绝大多数人**。GUI 合并器，解压即用 |
| `artifacts-<日期>.zip` | 104 MB | 从源码运行、或想自定义修正数据的人 |
| `SHA256SUMS.txt` | — | 校验用 |

> **只想用**：下载第一个。修正数据已经打包在里面，不需要第二个。

---

## 本版修复（2026-10-04 · M23）**建议务必更新**

旧版合并器会**漏发** `assets/save/appdata/save_appdata`：客户端启动时读不到有效的
appdata，就会删掉 `save/database/master_card` 并**不再重新下载** → 引擎卡表为空 →
进入**图鉴**时 `_CardCollection::setupCardTable → createFaceCard → _Card::getCountryId()`
对 NULL 取成员 → 必崩（`SIGSEGV fault addr 0x8`）。

- 受影响：**仅合并器产出的包**（旧版 `KSSMA-Merger-*-win64.zip` / 旧 exe）；
  走主构建流程（Android SDK + `apksigner`）出的包不受影响。
- 修复：合并器不再跳过 `appdata/`；资源包缺该文件或它全零时**直接拒绝打包**。
- 自查：合并产物里应存在 `assets/save/appdata/save_appdata`（2849 字节 / **118 个非零字节**）。
  直接对产物 SHA256 更省事 —— 用同一原版 APK + 140330 资源包 + 勾选高清 OP，
  正确产物是 `70bcd135f28aefbe52aa1fd138f87b967121388b52e8a6452b2c38135d9a3347`（945,274,027 B）。

---

## 怎么用

1. **解压** `KSSMA-Merger-<日期>-win64.zip` → 得到 `KSSMA-Merger\` 文件夹
2. **双击** `KSSMA-Merger.exe`
3. 选好「原版 APK」和「资源包 zip」；输出目录**保持默认**（程序文件夹下的 `output\`）
4. 可选：勾选「使用高清 OP 动画」（+100 MB）
5. 点「开始合并」，约 20–60 秒
6. 完成后用 adb 安装产物：
   ```
   adb install -r output\KSSMA-Offline-<时间戳>.apk
   ```

> **注意**：exe **必须在它的文件夹里运行**，不能单独拷出去——依赖与修正数据都在
> 同目录的 `_internal\` 下。**想换输出位置？整个文件夹搬过去**，别只改输出目录。

**自检**（可选，确认环境就绪）：

```
KSSMA-Merger.exe --selftest
```

打印实际解析到的路径与依赖状态，并写入 `selftest-report.txt`。

---

## 已知限制（重要）

**输出目录必须在程序文件夹那一带。** 部分安全软件会限制本程序只能在自己所在
位置的目录树内写文件（本程序要生成约 900 MB 的 APK），写到别处会报
`Permission denied`，**即使那些目录权限完全正常**。

- ✅ 程序文件夹内 / 其子目录 / 其上级目录
- ❌ 其它盘或无关目录（如 `D:\Engine`）

想换位置 → **把整个程序文件夹搬过去再运行**。程序也会在开始合并前预检，
并在报错时主动提议切到可用目录。

---

## 系统要求

| 项 | 要求 |
| --- | --- |
| 系统 | Windows 10 / 11 (x64) |
| 依赖 | **无需安装任何东西**（不含 Java / Android SDK / Python） |
| 磁盘 | 约 1.5 GB 空闲（输入 773 MB + 输出约 900 MB） |
| 你需要自备 | 原版客户端 APK（`com.square_enix.million_cn`）+ 140330 资源包 zip |

> **本发布不包含游戏本体。** 请自备原版客户端与资源包。
> 合并产物含游戏原始素材，**仅供个人在自己设备上使用，请勿分发**。

---

## 校验

```
6EF971CAF36E85830FA7CD575F5EAB50F852D45B3990AF0CB60404D643623255  KSSMA-Merger-20261004b-win64.zip
8EF55FA3D27324F4FB512D9DF24C64F2475B45A45FC612DE4DB3BC10A89CE04B  artifacts-20261004.zip
```

PowerShell 校验：

```powershell
Get-FileHash .\KSSMA-Merger-20261004b-win64.zip -Algorithm SHA256
```

---

## 常见问题

**Q：提示「输出目录不可用 / 写入被拒绝」？**
见上面「已知限制」。把整个程序文件夹搬到你想输出的位置，或恢复默认输出目录。

**Q：杀毒软件报警？**
未签名的 PyInstaller 打包程序常被误报。可从源码运行，或自行校验 SHA256。

**Q：命令行模式没有输出？**
GUI 版 exe 是窗口程序，标准输出不出现在终端里。要在终端看输出请用源码运行：
`python src/main.py --apk <apk> --res <zip> --out <dir>`

**Q：为什么输出 APK 有 900 MB？**
原版客户端 + 完整资源包（全部卡图、立绘、场景、音效、OP）就是这体量。

---

## 源码与文档

仓库：https://github.com/CHshuihe/KSSMA-merger

技术档案在 `docs/技术档案.md`（含协议契约、逆向结论、踩坑记录）。
