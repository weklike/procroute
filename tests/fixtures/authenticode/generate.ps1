# SPDX-License-Identifier: GPL-3.0-or-later
# Regenerates the Authenticode test fixtures (ADR 0002). Needs PowerShell 7 on Windows; run it only when
# the fixtures need changing, the results are committed. The certificates exist only while this script
# runs, are removed with their private keys, and are never trusted anywhere:
#   a1.dll, a2.dll   different files signed with certificate A
#   b.dll            signed with certificate B, which has the same subject as A
#   a1-tampered.dll  a1.dll with one byte changed after signing
$ErrorActionPreference = 'Stop'
$subject = 'CN=ProcRoute Test Fixture'

function New-FixtureCertificate {
    New-SelfSignedCertificate -Type CodeSigningCert -Subject $subject -CertStoreLocation Cert:\CurrentUser\My `
        -KeyExportPolicy NonExportable -KeyAlgorithm RSA -KeyLength 2048 -HashAlgorithm SHA256 `
        -NotAfter (Get-Date).AddYears(100)
}

function New-SignedFixture([string]$name, $cert) {
    $path = Join-Path $PSScriptRoot "$name.dll"
    Remove-Item $path -ErrorAction SilentlyContinue
    Add-Type -TypeDefinition "public static class Fixture_$name { public const int Id = 1; }" `
        -OutputAssembly $path -OutputType Library
    $signed = Set-AuthenticodeSignature -FilePath $path -Certificate $cert -HashAlgorithm SHA256
    if ($signed.SignerCertificate.Thumbprint -ne $cert.Thumbprint) { throw "signing $path failed: $($signed.StatusMessage)" }
    return $path
}

$a = New-FixtureCertificate
$b = New-FixtureCertificate
try {
    $a1 = New-SignedFixture 'a1' $a
    New-SignedFixture 'a2' $a | Out-Null
    New-SignedFixture 'b' $b | Out-Null

    # One byte inside the hashed part of the PE: the first byte of the first section's raw data.
    $bytes = [IO.File]::ReadAllBytes($a1)
    $pe = [BitConverter]::ToInt32($bytes, 0x3C)
    $optionalHeaderSize = [BitConverter]::ToUInt16($bytes, $pe + 20)
    $firstSection = $pe + 24 + $optionalHeaderSize
    $rawData = [BitConverter]::ToInt32($bytes, $firstSection + 20)
    $bytes[$rawData] = $bytes[$rawData] -bxor 0xFF
    [IO.File]::WriteAllBytes((Join-Path $PSScriptRoot 'a1-tampered.dll'), $bytes)
} finally {
    Remove-Item -Path "Cert:\CurrentUser\My\$($a.Thumbprint)" -DeleteKey
    Remove-Item -Path "Cert:\CurrentUser\My\$($b.Thumbprint)" -DeleteKey
}
