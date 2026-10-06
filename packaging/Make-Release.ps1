# 打包发布产物（PowerShell）
#
# 用法（在 merger/ 下）：
#     pwsh -NoProfile -File packaging/Make-Release.ps1
#
# 产出（都在 merger/release/ 下）：
#     KSSMA-Merger-<版本>-win64.zip      GUI 合并器（解压即用）
#     artifacts-<日期>.zip               修正数据（105 MB，源码/自定义用）
#     SHA256SUMS.txt                      两个包的校验值
#
# 约定
#   * exe 包：zip 内根目录就是 KSSMA-Merger\（解压后直接进该文件夹双击 exe），
#     不额外套一层，避免用户解压出"文件夹套文件夹"
#   * artifacts 包：zip 内根目录是 artifacts\，解压后得到 artifacts 文件夹
#
# 为什么用 .NET ZipFile 而不是 Compress-Archive：
#     能指定压缩级别（Optimal），且对 105 MB 的二进制更省内存与时间。
[CmdletBinding()]
param(
    [string]$Version = "",
    [ValidateSet('Optimal', 'Fastest', 'NoCompression')]
    [string]$Level = 'Optimal'
)

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.IO.Compression.FileSystem

# 用 $PSScriptRoot 定位 merger/（不要用 $MyInvocation.MyCommand.Path：
# 在 `pwsh -File` / `-Command "& '…'"` 等宿主里它可能是空串，$root 会退化成 ''
# → Set-Location 不动，release/ 被解析到错误的目录，报 "Could not find a part of the path"）。
$root = Split-Path -Parent $PSScriptRoot   # packaging/ → merger/
Set-Location $root
Write-Host "  工作目录：$root" -ForegroundColor DarkGray
# .NET 的 ZipFile 用**进程 CWD** 解析相对路径，而 Set-Location **不会**同步它 ——
# 从 merger/ 之外调用本脚本时，'release\…' 会被解析到错误的目录
# （踩过：`Could not find a part of the path '…\kssma_apk\release\…'`）。显式同步。
[System.IO.Directory]::SetCurrentDirectory((Get-Location).Path)

$distDir = 'dist\KSSMA-Merger'
$artDir  = 'artifacts'
$relDir  = 'release'

# 版本号：优先参数，否则取当天日期
if (-not $Version) { $Version = Get-Date -Format 'yyyyMMdd' }

Write-Host '=== 打包发布产物 ===' -ForegroundColor Cyan

# ── 前置检查 ──
if (-not (Test-Path "$distDir\KSSMA-Merger.exe")) {
    throw "找不到 $distDir\KSSMA-Merger.exe。请先运行 packaging\Build-Exe.ps1"
}
if (-not (Test-Path $artDir)) { throw "找不到 $artDir 目录" }

# 发行包里**不能**有开发痕迹。
# ★ 只从 zip 里**排除**，绝不删磁盘上的原文件（旧版这里直接 Remove-Item，踩过：
#   dist\KSSMA-Merger\keystore\signing.p12 是"与已安装包同源"的签名密钥，
#   删掉后玩家无法覆盖安装，还会污染"这次发布的包是谁签的"这条线索；
#   output\ 里是上一版产物留存。排除同样能保证 zip 干净。）
$excludeTop = @('keystore', 'output', 'selftest-report.txt')

New-Item -ItemType Directory -Force -Path $relDir | Out-Null

function New-ZipFromDir {
    param(
        [string]$SourceDir,       # 磁盘上的源目录
        [string]$BaseInZip,       # 在 zip 内的根名称（如 'KSSMA-Merger' / 'artifacts'）
        [string]$ZipPath,
        [string[]]$ExcludeTop = @()   # 按**顶层条目名**排除（目录或文件）
    )
    if (Test-Path $ZipPath) { Remove-Item $ZipPath -Force }
    $level = [System.IO.Compression.CompressionLevel]::$Level
    $srcFull = (Resolve-Path $SourceDir).Path.TrimEnd('\')
    $zip = [System.IO.Compression.ZipFile]::Open($ZipPath, 'Create')
    try {
        $count = 0
        $skipped = 0
        Get-ChildItem -Path $srcFull -Recurse -File | ForEach-Object {
            $rel = $_.FullName.Substring($srcFull.Length).TrimStart('\')
            if ($ExcludeTop -contains $rel.Split('\')[0]) { $skipped++; return }
            $entry = "$BaseInZip/" + ($rel -replace '\\', '/')
            [void][System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile(
                $zip, $_.FullName, $entry, $level)
            $count++
        }
        Write-Host ("    {0} ：{1} 个文件（排除 {2}）" -f (Split-Path $ZipPath -Leaf), $count, $skipped)
    } finally {
        $zip.Dispose()
    }
}

# ── 1) 合并器 ──
$zipMerger = Join-Path $relDir "KSSMA-Merger-$Version-win64.zip"
Write-Host '  [1/2] 合并器…'
New-ZipFromDir -SourceDir $distDir -BaseInZip 'KSSMA-Merger' -ZipPath $zipMerger -ExcludeTop $excludeTop

# ── 2) 修正数据 ──
$zipArt = Join-Path $relDir "artifacts-$Version.zip"
Write-Host '  [2/2] 修正数据…'
New-ZipFromDir -SourceDir $artDir -BaseInZip 'artifacts' -ZipPath $zipArt

# ── 3) 校验值 ──
$sums = Join-Path $relDir 'SHA256SUMS.txt'
$lines = @()
foreach ($f in @($zipMerger, $zipArt)) {
    $h = (Get-FileHash $f -Algorithm SHA256).Hash
    $lines += "$h  $(Split-Path $f -Leaf)"
}
Set-Content -Path $sums -Value $lines -Encoding ASCII
Write-Host '  已写 SHA256SUMS.txt'

# ── 汇总 ──
Write-Host ''
Write-Host '✅ 打包完成' -ForegroundColor Green
Get-ChildItem $relDir -File | Sort-Object Name | ForEach-Object {
    Write-Host ("   {0,-40} {1,8:N1} MB" -f $_.Name, ($_.Length / 1MB))
}
Write-Host ''
Write-Host '发布到 GitHub Release 时：'
Write-Host '  · 上传上面两个 zip 与 SHA256SUMS.txt'
Write-Host '  · 说明里写明：合并器解压即用；artifacts 是给源码/自定义用的'
Write-Host ''
