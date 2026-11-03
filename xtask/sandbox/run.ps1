# SPDX-License-Identifier: GPL-3.0-or-later
# 在 Windows Sandbox 里运行的测试脚本，由 `cargo xtask sandbox-test` 放进只读映射目录并作为登录命令执行。
#
# 先把只读输入复制到沙盒本地磁盘（驱动不从共享文件夹加载），逐个运行 manifest.json 里的测试程序，
# 输出与结果写进可写的映射目录，最后写 done 标记并关闭沙盒（沙盒关闭即丢弃全部状态）。

$ErrorActionPreference = 'Stop'
$inDir = 'C:\procroute-in'
$outDir = 'C:\procroute-out'
$work = 'C:\procroute'

$summary = [ordered]@{ admin = $false; results = @(); error = $null }
try {
    Copy-Item -Path $inDir -Destination $work -Recurse -Force
    $principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    $summary.admin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    $env:PROCROUTE_WINDIVERT_DIR = Join-Path $work 'windivert'
    # 端到端测试的安装目录（服务、sing-box、WinDivert）与可写的输出目录
    $install = Join-Path $work 'install'
    if (Test-Path $install) { $env:PROCROUTE_INSTALL_DIR = $install }
    $env:PROCROUTE_OUT_DIR = $outDir
    $env:RUST_BACKTRACE = '1'

    $manifest = Get-Content (Join-Path $work 'manifest.json') -Raw | ConvertFrom-Json
    foreach ($t in $manifest.tests) {
        $exe = Join-Path $work $t.file
        $log = Join-Path $outDir "$($t.name).log"
        $testArgs = (@('--test-threads=1') + @($t.args)) -join ' '
        $start = Get-Date
        # 经 cmd 重定向：保留原始字节，也避免 Windows PowerShell 把原生程序的 stderr 当成错误记录
        cmd.exe /c "`"$exe`" $testArgs > `"$log`" 2>&1"
        $code = $LASTEXITCODE
        $summary.results += [ordered]@{
            name = $t.name
            exit_code = $code
            seconds = [math]::Round(((Get-Date) - $start).TotalSeconds, 1)
        }
    }
} catch {
    $summary.error = "$_"
} finally {
    $summary | ConvertTo-Json -Depth 4 | Set-Content -Path (Join-Path $outDir 'summary.json') -Encoding utf8
    Set-Content -Path (Join-Path $outDir 'done') -Value 'done'
    if (-not (Test-Path (Join-Path $inDir 'keep-open'))) {
        shutdown.exe /s /t 0
    }
}
