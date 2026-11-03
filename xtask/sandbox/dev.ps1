# SPDX-License-Identifier: GPL-3.0-or-later
# `cargo xtask sandbox-dev` 的沙盒端脚本，作为登录命令运行：安装到 Program Files，在可见的控制台窗口里
# 以控制台模式启动服务，控制管道出现后启动界面，把结果写进可写的映射目录。沙盒保持打开，供手动联调。
#
# 注意：Windows PowerShell 5.1 按系统 ANSI 代码页读取没有 BOM 的脚本，字符串字面量只用 ASCII。

$ErrorActionPreference = 'Stop'
$inDir = 'C:\procroute-in'
$outDir = 'C:\procroute-out'
$install = 'C:\Program Files\ProcRoute'
# 与 platform-win 的 CONTROL_PIPE_NAME 一致
$pipe = '\\.\pipe\ProcRoute.Control'
# WebView2 运行时的系统级安装登记在 EdgeUpdate 下
$webview2Key = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}'
# 开发机上的运行时（版本目录）映射到这里，与 sandbox_dev.rs 一致
$hostWebView2 = 'C:\procroute-webview2'
$localWebView2 = 'C:\webview2'

function Test-Pipe {
    try { return [IO.Directory]::GetFiles('\\.\pipe\') -contains $pipe } catch { return $false }
}

function Get-WebView2Version {
    $wv = Get-ItemProperty -Path $webview2Key -Name pv -ErrorAction SilentlyContinue
    if ($wv -and $wv.pv -and $wv.pv -ne '0.0.0.0') { return $wv.pv }
    return $null
}

$status = [ordered]@{ admin = $false; webview2 = $null; service = $false; ui = $false; error = $null }
try {
    $principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    $status.admin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    Copy-Item -Path (Join-Path $inDir 'install') -Destination $install -Recurse -Force

    Start-Process -FilePath powershell.exe -ArgumentList @('-NoExit', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', (Join-Path $inDir 'svc-console.ps1'))
    $deadline = (Get-Date).AddSeconds(30)
    while (-not (Test-Pipe) -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 500 }
    $status.service = Test-Pipe
    if (-not $status.service) { throw 'the control pipe did not appear within 30 s; the service did not start (see svc.log)' }

    # Windows Sandbox 的系统镜像不带 WebView2 运行时：把开发机映射进来的那份当作固定版本运行时使用。
    # 按微软对固定版本运行时的说明复制到本地盘，并给 AppContainer 读与执行权限，否则渲染进程起不来。
    $status.webview2 = Get-WebView2Version
    if (-not $status.webview2) {
        $exe = Join-Path $hostWebView2 'msedgewebview2.exe'
        if (-not (Test-Path $exe)) { throw 'no WebView2 runtime in the sandbox and none mapped from the host' }
        Copy-Item -Path $hostWebView2 -Destination $localWebView2 -Recurse -Force
        icacls $localWebView2 /grant '*S-1-15-2-1:(OI)(CI)(RX)' /grant '*S-1-15-2-2:(OI)(CI)(RX)' /Q | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "icacls failed on $localWebView2 (exit code $LASTEXITCODE)" }
        # 本进程启动的界面与之后从桌面快捷方式启动的界面都用它
        $env:WEBVIEW2_BROWSER_EXECUTABLE_FOLDER = $localWebView2
        [Environment]::SetEnvironmentVariable('WEBVIEW2_BROWSER_EXECUTABLE_FOLDER', $localWebView2, 'Machine')
        $status.webview2 = 'fixed ' + (Get-Item $exe).VersionInfo.ProductVersion
    }

    # 桌面快捷方式：界面被退出后可以从这里再打开
    $shortcut = (New-Object -ComObject WScript.Shell).CreateShortcut((Join-Path ([Environment]::GetFolderPath('Desktop')) 'ProcRoute.lnk'))
    $shortcut.TargetPath = Join-Path $install 'procroute-ui.exe'
    $shortcut.Save()

    # 调试构建的界面是控制台程序：输出留在 ui.log，启动失败时能看到原因
    $ui = Start-Process -FilePath (Join-Path $install 'procroute-ui.exe') -PassThru `
        -RedirectStandardOutput (Join-Path $outDir 'ui.out.log') -RedirectStandardError (Join-Path $outDir 'ui.log')
    Start-Sleep -Seconds 8
    $status.ui = -not $ui.HasExited
    if (-not $status.ui) { throw "the UI exited right after starting (exit code $($ui.ExitCode), see ui.log)" }
} catch {
    $status.error = "$_"
} finally {
    $status | ConvertTo-Json | Set-Content -Path (Join-Path $outDir 'status.json') -Encoding utf8
    Set-Content -Path (Join-Path $outDir 'ready') -Value 'ready'
}
