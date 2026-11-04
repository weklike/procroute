# SPDX-License-Identifier: GPL-3.0-or-later
# `cargo xtask sandbox-install`, run inside Windows Sandbox as the logon command: installs the bundled
# installer silently (over a previous version when one is given), checks the service and the signed UI
# on a machine that trusts no ProcRoute certificate, checks that a forged UI is rejected, uninstalls,
# and checks nothing is left behind (T-110, ADR 0002). Results go to C:\procroute-out\install.json,
# then the sandbox shuts down.
# Strings stay ASCII: Windows PowerShell 5.1 reads scripts without a BOM in the ANSI code page.

$ErrorActionPreference = 'Stop'
$inDir = 'C:\procroute-in'
$outDir = 'C:\procroute-out'
$install = 'C:\Program Files\ProcRoute'
$pipe = '\\.\pipe\ProcRoute.Control'
$svcLog = 'C:\ProgramData\ProcRoute\logs\svc.log'
$serviceKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\ProcRoute'
$webview2Key = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}'
$hostWebView2 = 'C:\procroute-webview2'
$localWebView2 = 'C:\webview2'

$result = [ordered]@{ admin = $false; steps = @(); error = $null }
function Step([string]$name, $ok, $detail) {
    $script:result.steps += [ordered]@{ name = $name; ok = [bool]$ok; detail = "$detail" }
}
function Test-Pipe {
    try { return [IO.Directory]::GetFiles('\\.\pipe\') -contains $pipe } catch { return $false }
}
function Wait-Until([scriptblock]$cond, [int]$seconds) {
    $deadline = (Get-Date).AddSeconds($seconds)
    while (-not (& $cond) -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 500 }
    return (& $cond)
}

try {
    $principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    $result.admin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    # The sandbox image has no WebView2 runtime and no internet: use the host's runtime as a fixed-version
    # runtime and register its version so the installer does not try to download the bootstrapper
    if (Test-Path (Join-Path $hostWebView2 'msedgewebview2.exe')) {
        Copy-Item -Path $hostWebView2 -Destination $localWebView2 -Recurse -Force
        icacls $localWebView2 /grant '*S-1-15-2-1:(OI)(CI)(RX)' /grant '*S-1-15-2-2:(OI)(CI)(RX)' /Q | Out-Null
        $version = (Get-Item (Join-Path $localWebView2 'msedgewebview2.exe')).VersionInfo.ProductVersion
        New-Item -Path $webview2Key -Force | Out-Null
        Set-ItemProperty -Path $webview2Key -Name pv -Value $version
        $env:WEBVIEW2_BROWSER_EXECUTABLE_FOLDER = $localWebView2
        [Environment]::SetEnvironmentVariable('WEBVIEW2_BROWSER_EXECUTABLE_FOLDER', $localWebView2, 'Machine')
    }

    # 0. A previous version with its UI running, when testing an upgrade: every release has its own
    # certificate, so the service and the UI must change certificate together
    $previous = Get-ChildItem (Join-Path $inDir 'upgrade-from') -Filter '*-setup.exe' -ErrorAction SilentlyContinue | Select-Object -First 1
    $previousCert = $null
    if ($previous) {
        $p = Start-Process -FilePath $previous.FullName -ArgumentList '/S' -Wait -PassThru
        Step "previous version $($previous.Name) installs" ($p.ExitCode -eq 0) $p.ExitCode
        Step 'previous version service runs' (Wait-Until { (Get-Service ProcRoute -ErrorAction SilentlyContinue).Status -eq 'Running' } 30) ''
        $previousCert = (Get-AuthenticodeSignature (Join-Path $install 'procroute-svc.exe')).SignerCertificate.Thumbprint
        Start-Process -FilePath (Join-Path $install 'procroute-ui.exe') | Out-Null
        Start-Sleep -Seconds 5
    }

    # 1. Silent install
    $setup = Get-ChildItem $inDir -Filter '*-setup.exe' | Select-Object -First 1
    $p = Start-Process -FilePath $setup.FullName -ArgumentList '/S' -Wait -PassThru
    Step 'installer exits with 0' ($p.ExitCode -eq 0) $p.ExitCode
    foreach ($f in 'procroute-ui.exe', 'procroute-svc.exe', 'sing-box.exe', 'WinDivert.dll', 'WinDivert64.sys', 'licenses\NOTICE') {
        Step "installed $f" (Test-Path (Join-Path $install $f)) ''
    }
    # Intact (no HashMismatch), and all with one certificate. UnknownError is what PowerShell reports for
    # a good signature whose root is not trusted, which is the expected state of the one-off certificate.
    $signer = (Get-AuthenticodeSignature (Join-Path $install 'procroute-svc.exe')).SignerCertificate
    foreach ($f in 'procroute-ui.exe', 'procroute-svc.exe', 'uninstall.exe') {
        $sig = Get-AuthenticodeSignature (Join-Path $install $f)
        $good = (@('Valid', 'UnknownError') -contains $sig.Status) -and ($sig.SignerCertificate.Thumbprint -eq $signer.Thumbprint)
        Step "$f is intact and signed with the service's certificate" $good "$($sig.Status) $($sig.SignerCertificate.Subject)"
    }
    Step 'no root trust is needed: the certificate is not in the machine root store' (-not (Test-Path "Cert:\LocalMachine\Root\$($signer.Thumbprint)")) $signer.Thumbprint
    if ($previous) {
        Step 'the upgrade replaced the signing certificate' ($previousCert -ne $signer.Thumbprint) "$previousCert -> $($signer.Thumbprint)"
    }

    # 2. The service is registered, automatic, running, and listening
    $running = Wait-Until { (Get-Service ProcRoute -ErrorAction SilentlyContinue).Status -eq 'Running' } 30
    $svc = Get-CimInstance Win32_Service -Filter "Name='ProcRoute'"
    Step 'service running' $running "$($svc.State) $($svc.StartMode) $($svc.StartName)"
    Step 'service starts automatically as LocalSystem' (($svc.StartMode -eq 'Auto') -and ($svc.StartName -eq 'LocalSystem')) "$($svc.StartMode) $($svc.StartName)"
    Step 'control pipe listening' (Wait-Until { Test-Pipe } 15) ''

    # 3. The signed UI is accepted (client check, C-SEC-02): restart the service with debug logs first
    New-ItemProperty -Path $serviceKey -Name Environment -PropertyType MultiString -Value @('PROCROUTE_LOG=debug') -Force | Out-Null
    # The log survives an upgrade: only what this version wrote counts
    $logStart = if (Test-Path $svcLog) { (Get-Content $svcLog -Raw).Length } else { 0 }
    Restart-Service ProcRoute
    Wait-Until { Test-Pipe } 15 | Out-Null
    $ui = Start-Process -FilePath (Join-Path $install 'procroute-ui.exe') -PassThru
    $accepted = Wait-Until { (Test-Path $svcLog) -and ((Get-Content $svcLog -Raw) -match "pid=$($ui.Id) .*pipe client connected|pipe client connected.*pid=$($ui.Id)") } 30
    $log = if (Test-Path $svcLog) { Get-Content $svcLog -Raw } else { '' }
    Step 'the signed UI is accepted by the service' $accepted "ui pid $($ui.Id)"
    Step 'no pipe client was rejected' (-not ($log.Substring([Math]::Min($logStart, $log.Length)) -match 'pipe client rejected')) ''
    Step 'the UI is still running' (-not $ui.HasExited) ''
    Copy-Item $svcLog (Join-Path $outDir 'svc-installed.log') -ErrorAction SilentlyContinue

    # 4. A UI inside the install directory, signed with another certificate with the same subject, is rejected
    Stop-Process -Id $ui.Id -Force -ErrorAction SilentlyContinue
    $forgedPath = Join-Path $install 'procroute-ui-forged.exe'
    Copy-Item (Join-Path $install 'procroute-ui.exe') $forgedPath
    $forgedCert = New-SelfSignedCertificate -Type CodeSigningCert -Subject $signer.Subject -CertStoreLocation Cert:\CurrentUser\My
    Set-AuthenticodeSignature -FilePath $forgedPath -Certificate $forgedCert -HashAlgorithm SHA256 | Out-Null
    $forged = Start-Process -FilePath $forgedPath -PassThru
    $rejected = Wait-Until { (Get-Content $svcLog -Raw) -match "pipe client rejected.*pid=$($forged.Id) .*different certificate" } 30
    Step 'a UI signed with another certificate with the same subject is rejected' $rejected "forged pid $($forged.Id)"
    Copy-Item $svcLog (Join-Path $outDir 'svc-forged.log') -ErrorAction SilentlyContinue
    Stop-Process -Id $forged.Id -Force -ErrorAction SilentlyContinue
    Wait-Until { -not (Get-Process -Id $forged.Id -ErrorAction SilentlyContinue) } 10 | Out-Null
    Remove-Item $forgedPath -Force

    # 5. Silent uninstall
    Start-Process -FilePath (Join-Path $install 'uninstall.exe') -ArgumentList '/S' -Wait
    $gone = Wait-Until { -not (Get-Service ProcRoute -ErrorAction SilentlyContinue) -and -not (Test-Path (Join-Path $install 'procroute-svc.exe')) } 60
    Step 'uninstall removes the service and the program files' $gone ''
    Step 'no ProcRoute or sing-box process is left' (-not (Get-Process procroute-svc, procroute-ui, sing-box -ErrorAction SilentlyContinue)) ''
    $windivert = Get-CimInstance Win32_SystemDriver -Filter "Name='WinDivert'"
    Step 'the WinDivert driver is not left running' (-not $windivert -or $windivert.State -ne 'Running') "$($windivert.State) $($windivert.StartMode)"
    $rules = Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -like '*ProcRoute*' -or $_.DisplayName -like '*sing-box*' }
    Step 'no firewall rule is left' (-not $rules) ($rules | ForEach-Object { $_.DisplayName })
    $run = Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name ProcRoute -ErrorAction SilentlyContinue
    Step 'no autostart entry is left' (-not $run) ''
} catch {
    $result.error = "$_"
} finally {
    $result | ConvertTo-Json -Depth 4 | Set-Content -Path (Join-Path $outDir 'install.json') -Encoding utf8
    Set-Content -Path (Join-Path $outDir 'done') -Value 'done'
    if (-not (Test-Path (Join-Path $inDir 'keep-open'))) {
        shutdown.exe /s /t 0
    }
}
