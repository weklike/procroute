# SPDX-License-Identifier: GPL-3.0-or-later
<#
.SYNOPSIS
    ProcRoute Windows 开发机一次性环境配置（宿主机用，不加载驱动、不注册服务）。

.DESCRIPTION
    安装编译 Rust + Tauri + React 所需工具，并做长路径、执行策略等系统设置。
    驱动、服务、TUN 相关的运行与测试一律放在虚拟机中（CONSTRAINTS C-TEST-04、AGENTS 第 8 节）。

    用法（管理员 PowerShell）：
        Set-ExecutionPolicy -Scope Process Bypass -Force
        .\scripts\setup-windows-dev.ps1                 # 只装开发工具
        .\scripts\setup-windows-dev.ps1 -EnableHyperV   # 同时启用 Hyper-V（需 Pro/Enterprise/Education 版）

    脚本可重复运行；已安装的工具 winget 会跳过。装完后请重开终端，必要时重启。
#>
#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [switch]$EnableHyperV
)

$ErrorActionPreference = 'Stop'

function Write-Step([string]$msg) { Write-Host "`n==> $msg" -ForegroundColor Cyan }

function Install-WingetPackage([string]$id, [string]$extraArgs = '') {
    Write-Host "  - $id"
    $wingetArgs = @('install', '-e', '--id', $id, '--accept-package-agreements', '--accept-source-agreements', '--disable-interactivity')
    if ($extraArgs) { $wingetArgs += @('--override', $extraArgs) }
    & winget @wingetArgs
    # winget 对「已安装」返回非 0，这里只提示不中断
    if ($LASTEXITCODE -ne 0) { Write-Host "    winget 返回 $LASTEXITCODE（若为已安装可忽略）" -ForegroundColor Yellow }
}

# ---------------------------------------------------------------------------
Write-Step '检查系统版本'
$os = Get-CimInstance Win32_OperatingSystem
Write-Host "  $($os.Caption)  build $($os.BuildNumber)"
if ([int]$os.BuildNumber -lt 22621) {
    Write-Host '  建议开发机使用 Windows 11（22H2 及以上）；Windows 10 只作为测试虚拟机。' -ForegroundColor Yellow
}
if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
    throw '未找到 winget。请先从 Microsoft Store 安装/更新「应用安装程序（App Installer）」。'
}

# ---------------------------------------------------------------------------
Write-Step '安装基础工具'
Install-WingetPackage 'Git.Git'
Install-WingetPackage 'Microsoft.PowerShell'
Install-WingetPackage 'Schniz.fnm'            # Node 版本管理，按仓库 .nvmrc 切换

Write-Step '安装 Visual Studio Build Tools（C++ 桌面工作负载 + Windows 11 SDK）'
# Windows 11 SDK 同时提供 signtool，发布阶段签名会用到
Install-WingetPackage 'Microsoft.VisualStudio.BuildTools' `
    '--passive --wait --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended --add Microsoft.VisualStudio.Component.Windows11SDK.26100'

Write-Step '安装 Rust（rustup，MSVC 工具链）'
Install-WingetPackage 'Rustlang.Rustup'

# 让本会话能找到刚装好的 cargo / rustup / fnm
$env:Path = [Environment]::GetEnvironmentVariable('Path', 'Machine') + ';' +
            [Environment]::GetEnvironmentVariable('Path', 'User') + ';' +
            "$env:USERPROFILE\.cargo\bin"

if (Get-Command rustup -ErrorAction SilentlyContinue) {
    rustup default stable-msvc
    rustup component add rustfmt clippy
} else {
    Write-Host '  rustup 尚不可用，请重开终端后执行：rustup default stable-msvc; rustup component add rustfmt clippy' -ForegroundColor Yellow
}

# ---------------------------------------------------------------------------
Write-Step '系统设置'

# 1) 长路径：node_modules 与 Rust target 目录层级很深
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem' `
    -Name 'LongPathsEnabled' -Value 1 -PropertyType DWORD -Force | Out-Null
Write-Host '  已开启 Win32 长路径'

if (Get-Command git -ErrorAction SilentlyContinue) {
    git config --global core.longpaths true
    git config --global core.autocrlf false   # 换行统一由仓库的 .gitattributes 管理
    Write-Host '  已设置 git core.longpaths=true、core.autocrlf=false'
}

# 2) 当前用户允许运行本地脚本（xtask 之外的辅助脚本）
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned -Force
Write-Host '  已设置当前用户执行策略为 RemoteSigned'

# ---------------------------------------------------------------------------
if ($EnableHyperV) {
    Write-Step '启用 Hyper-V（e2e 测试虚拟机用）'
    $edition = (Get-WindowsEdition -Online).Edition
    if ($edition -match 'Core|Home') {
        Write-Host "  当前版本 $edition 不支持 Hyper-V。可改用 VMware Workstation Pro 或升级到 Pro 版。" -ForegroundColor Yellow
    } else {
        Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -All -NoRestart | Out-Null
        Write-Host '  Hyper-V 已启用，重启后生效。'
    }
}

# ---------------------------------------------------------------------------
Write-Step '完成'
Write-Host @'
请重开终端（必要时重启），然后在仓库根目录执行：

    # 首次使用 fnm：把下面这行加进 $PROFILE，让 fnm 在新终端里生效
    #   fnm env --use-on-cd --shell powershell | Out-String | Invoke-Expression
    fnm install; fnm use                     # 按 .nvmrc 安装并切换 Node
    npm install -g pnpm                      # pnpm 版本由 package.json 的 packageManager 字段约束
    cargo install --locked cargo-nextest cargo-deny cargo-llvm-cov tauri-driver
    pnpm -C app install

自检：
    rustc -vV        # host 应为 x86_64-pc-windows-msvc
    cargo nextest run -p procroute-proto -p procroute-config -p procroute-rules
    pnpm -C app typecheck
'@
