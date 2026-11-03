# SPDX-License-Identifier: GPL-3.0-or-later
# 注意：Windows PowerShell 5.1 按系统 ANSI 代码页读取没有 BOM 的脚本，字符串字面量只用 ASCII。
# 在可见的控制台窗口里以控制台模式运行服务（`cargo xtask sandbox-dev`），日志同时追加到映射出来的
# svc.log，开发机上也能看到。Ctrl+C 停止服务。

$host.UI.RawUI.WindowTitle = 'procroute-svc --console (Ctrl+C to stop)'
# 日志进文件，不要终端颜色码
$env:NO_COLOR = '1'
$log = 'C:\procroute-out\svc.log'
# 服务日志写在 stderr；经 2>&1 合并后每行是一条 ErrorRecord，按文本输出
& 'C:\Program Files\ProcRoute\procroute-svc.exe' --console 2>&1 | ForEach-Object {
    $line = "$_"
    Write-Host $line
    Add-Content -Path $log -Value $line -Encoding UTF8
}
$exit = "procroute-svc exited (exit code $LASTEXITCODE)"
Write-Host $exit
Add-Content -Path $log -Value $exit -Encoding UTF8
