# SPDX-License-Identifier: GPL-3.0-or-later
# Signs one file with the local code-signing certificate (T-110). Used by `cargo xtask bundle` for the
# service binary and, through Tauri's signCommand, for every binary the bundler packs: the UI, the NSIS
# plugins, the uninstaller and the installer. This script is the whole signing policy:
# - the hash-locked third-party binaries (sing-box, WinDivert) are never signed: a signature would change
#   their SHA-256 and the service would refuse them (C-DEP-04, C-DRV-01);
# - everything else is signed with the certificate chosen by thumbprint (PROCROUTE_SIGN_THUMBPRINT).
# Strings stay ASCII: Windows PowerShell 5.1 reads scripts without a BOM in the ANSI code page.
param([Parameter(Mandatory = $true)][string]$Path)

$ErrorActionPreference = 'Stop'
$locked = @('sing-box.exe', 'WinDivert.dll', 'WinDivert64.sys')
if ($locked -contains [IO.Path]::GetFileName($Path)) {
    Write-Output "skipped $Path (hash-locked third-party binary)"
    exit 0
}
$thumb = $env:PROCROUTE_SIGN_THUMBPRINT
if (-not $thumb) { throw 'PROCROUTE_SIGN_THUMBPRINT is not set (run through cargo xtask bundle)' }
$cert = Get-Item "Cert:\CurrentUser\My\$thumb"
$result = Set-AuthenticodeSignature -FilePath $Path -Certificate $cert -HashAlgorithm SHA256
# A self-signed root is not trusted on the build machine until the user trusts it, so the status may be
# UnknownError; the file is signed all the same. Anything else, or a different signer, is a failure.
$signed = $result.SignerCertificate -and $result.SignerCertificate.Thumbprint -eq $thumb
if (-not $signed -or ($result.Status -ne 'Valid' -and $result.Status -ne 'UnknownError')) {
    throw "signing $Path failed: $($result.Status) $($result.StatusMessage)"
}
Write-Output "signed $Path"
