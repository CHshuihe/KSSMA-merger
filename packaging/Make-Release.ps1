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

$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)   # merger/
Set-Location $root

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

# 发行包里**不能**有开发痕迹
foreach ($bad in @("$distDir\keystore", "$distDir\output", "$distDir\selftest-report.txt")) {
    if (Test-Path $bad) {
        Remove-Item $bad -Recurse -Force
        Write-Host "  已清理发行包内的 $($bad.Replace("$distDir\", ''))"
    }
}

New-Item -ItemType Directory -Force -Path $relDir | Out-Null

function New-ZipFromDir {
    param(
        [string]$SourceDir,       # 磁盘上的源目录
        [string]$BaseInZip,       # 在 zip 内的根名称（如 'KSSMA-Merger' / 'artifacts'）
        [string]$ZipPath
    )
    if (Test-Path $ZipPath) { Remove-Item $ZipPath -Force }
    $level = [System.IO.Compression.CompressionLevel]::$Level
    $srcFull = (Resolve-Path $SourceDir).Path.TrimEnd('\')
    $zip = [System.IO.Compression.ZipFile]::Open($ZipPath, 'Create')
    try {
        $count = 0
        Get-ChildItem -Path $srcFull -Recurse -File | ForEach-Object {
            $rel = $_.FullName.Substring($srcFull.Length).TrimStart('\')
            $entry = "$BaseInZip/" + ($rel -replace '\\', '/')
            [void][System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile(
                $zip, $_.FullName, $entry, $level)
            $count++
        }
        Write-Host ("    {0} ：{1} 个文件" -f (Split-Path $ZipPath -Leaf), $count)
    } finally {
        $zip.Dispose()
    }
}

# ── 1) 合并器 ──
$zipMerger = Join-Path $relDir "KSSMA-Merger-$Version-win64.zip"
Write-Host '  [1/2] 合并器…'
New-ZipFromDir -SourceDir $distDir -BaseInZip 'KSSMA-Merger' -ZipPath $zipMerger

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
