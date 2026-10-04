# 构建 KSSMA Merger 图形界面 exe（PowerShell）
#
# 用法（在 merger/ 目录下）：
#     pwsh -NoProfile -File packaging\Build-Exe.ps1
#
# 产物：
#     dist/KSSMA-Merger/KSSMA-Merger.exe      （onedir，分发时整个文件夹一起给）
#
# 为什么是 onedir 而不是 onefile：
#     曾用 onefile，实测直接失败：
#         [PYI-…:ERROR] Could not create temporary directory!
#     onefile 每次启动都要把 ~120 MB 自解压到 %TEMP%；体积这么大时既慢又容易失败，
#     而 105 MB 的 artifacts 会被反复解压。onedir 启动即时，对 100 MB 级资源更合适。
#
# 构建后建议跑一次自检：
#     dist\KSSMA-Merger\KSSMA-Merger.exe --selftest
[CmdletBinding()]
param(
    [switch]$SkipExe,                     # 只做清理与准备
    [switch]$RunSelfTest                  # 构建完自动跑自检
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)   # merger/
Set-Location $root

Write-Host '=== KSSMA Merger GUI 打包 ===' -ForegroundColor Cyan

# 1) 前置检查
if (-not (Test-Path 'artifacts')) { throw "找不到 artifacts 目录：$root\artifacts" }
$artMb = [math]::Round(((Get-ChildItem 'artifacts' -Recurse -File |
        Measure-Object -Property Length -Sum).Sum / 1MB), 1)
Write-Host "  artifacts: $artMb MB"

try {
    $ver = (python -c "import PyInstaller;print(PyInstaller.__version__)").Trim()
    Write-Host "  PyInstaller: $ver"
} catch {
    throw '  PyInstaller 未安装。请先：pip install pyinstaller'
}

# 2) 语法自检（避免打包到一半才发现语法错）
foreach ($f in @('src\gui.py', 'src\main.py')) {
    python -c "import ast,io,sys;ast.parse(io.open(r'$f',encoding='utf-8').read())"
    if ($LASTEXITCODE -ne 0) { throw "语法检查失败：$f" }
}
Write-Host '  语法检查通过'

if ($SkipExe) { Write-Host '（-SkipExe）跳过打包'; exit 0 }

# 3) 清理旧产物
#    先结束正在运行的旧 exe —— 否则 _internal 里的 dll 被占用，Remove-Item 会报
#    "Access to the path '…\LIBBZ2.dll' is denied"（踩过）
$running = Get-Process -Name 'KSSMA-Merger*' -ErrorAction SilentlyContinue
if ($running) {
    Write-Host "  结束正在运行的旧进程：$($running.Id -join ', ')"
    $running | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 3
}
foreach ($p in @('build\KSSMA-Merger', 'dist\KSSMA-Merger')) {
    if (Test-Path $p) {
        try {
            Remove-Item $p -Recurse -Force -ErrorAction Stop
        } catch {
            throw "无法清理 $p：$($_.Exception.Message)`n请先关闭正在运行的本程序后重试。"
        }
    }
}

# 4) 打包
Write-Host '  打包中（首次约 1–3 分钟）...'
python -m PyInstaller --clean --noconfirm 'packaging\KSSMA-Merger.spec'
if ($LASTEXITCODE -ne 0) { throw 'PyInstaller 失败' }

# 5) 结果
$exe = 'dist\KSSMA-Merger\KSSMA-Merger.exe'
if (-not (Test-Path $exe)) { throw "未生成 $exe" }
$exeMb = [math]::Round((Get-Item $exe).Length / 1MB, 2)
$dirMb = [math]::Round(((Get-ChildItem 'dist\KSSMA-Merger' -Recurse -File |
        Measure-Object -Property Length -Sum).Sum / 1MB), 1)
$sha = (Get-FileHash $exe -Algorithm SHA256).Hash

Write-Host ''
Write-Host '✅ 打包完成' -ForegroundColor Green
Write-Host "   exe        : $exe  ($exeMb MB)"
Write-Host "   整个文件夹 : dist\KSSMA-Merger\  ($dirMb MB)"
Write-Host "   SHA256     : $sha"
Write-Host ''
Write-Host '分发方式：把 dist\KSSMA-Merger\ 整个文件夹打包给用户。'
Write-Host '（exe 必须在文件夹内运行，不能单独拷出来。）'
Write-Host ''

if ($RunSelfTest) {
    Write-Host '=== 跑自检 ===' -ForegroundColor Cyan
    & ".\$exe" --selftest
    $rep = 'dist\KSSMA-Merger\selftest-report.txt'
    if (Test-Path $rep) { Get-Content $rep | ForEach-Object { "  $_" } }
}
