# build-env.ps1 -- shared build-environment resolver for the IJW payload scripts.
#
# Dot-sourced by compile_x64.ps1 / compile_x86.ps1. Exposes Initialize-BuildEnv,
# which locates the C++/CLI toolchain, Windows SDK, UCRT and NETFXSDK, sets the
# INCLUDE / LIB environment for the requested architecture, and returns the
# cl.exe / link.exe / csc.exe paths plus the .NET Framework runtime directory.
#
# The MSVC toolchain lives under either a custom C:\BuildTools root or a standard
# Visual Studio 2022 install. The Windows SDK is found in either the standard
# "Windows Kits\10" layout or a NuGet-packaged layout
# (Microsoft.Windows.SDK.CPP[.<arch>]). Missing components are installed: the
# compiler via the VS Build Tools bootstrapper (or winget when present), and a
# missing SDK via the NuGet packages when the compiler itself is already present.

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
# Ensure TLS 1.2 for the bootstrapper / NuGet downloads on older Windows images.
try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 } catch {}

# NuGet SDK version used when provisioning a missing Windows SDK. Bump to match
# the toolchain in use; any already-installed SDK is detected and preferred over
# this regardless of version.
$script:SdkNuGetVersion = "10.0.20348.19"

# VS Build Tools components required for /clr IJW builds: the VC toolset, C++/CLI
# support, a Windows SDK, and the .NET Framework 4.8 SDK (for mscoree.lib).
$script:VsComponents = @(
    "Microsoft.VisualStudio.Workload.VCTools"
    "Microsoft.VisualStudio.Component.VC.CLI.Support"
    "Microsoft.VisualStudio.Component.Windows11SDK.22621"
    "Microsoft.VisualStudio.Component.NetFX.4.8.SDK"
)

function Get-HostBinDir {
    # Host toolset directory name for the running machine (WS2022 targets are x64).
    if ([Environment]::Is64BitOperatingSystem) { return "Hostx64" }
    return "Hostx86"
}

function Test-IsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    return ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Find-Msvc {
    # Locate a VC\Tools\MSVC\<ver> directory. Custom C:\BuildTools first, then the
    # standard VS 2022 editions. Returns Base (...\VC\Tools\MSVC), Version, and the
    # VS install Root (used as the bootstrapper --installPath for in-place repair).
    $bases = @("C:\BuildTools\VC\Tools\MSVC")
    foreach ($pf in @(${env:ProgramFiles}, ${env:ProgramFiles(x86)})) {
        if (-not $pf) { continue }
        foreach ($ed in @("BuildTools", "Community", "Professional", "Enterprise")) {
            $bases += (Join-Path $pf "Microsoft Visual Studio\2022\$ed\VC\Tools\MSVC")
        }
    }
    foreach ($base in $bases) {
        if (-not (Test-Path $base)) { continue }
        $ver = (Get-ChildItem $base -Directory -ErrorAction SilentlyContinue |
                Sort-Object Name -Descending | Select-Object -First 1).Name
        if ($ver) {
            return [pscustomobject]@{
                Base    = $base
                Version = $ver
                Root    = (Split-Path (Split-Path (Split-Path $base)))
            }
        }
    }
    return $null
}

function Find-WindowsSdkKits {
    # Standard "Windows Kits\10" SDK for the given arch, if present and complete.
    param([string]$Arch)
    $root = "C:\Program Files (x86)\Windows Kits\10"
    if (-not (Test-Path "$root\Include")) { return $null }
    $vers = Get-ChildItem "$root\Include" -Directory -ErrorAction SilentlyContinue |
            Where-Object { Test-Path (Join-Path $_.FullName "um\windows.h") } |
            Sort-Object Name -Descending
    foreach ($v in $vers) {
        $ver = $v.Name
        if (Test-Path "$root\Lib\$ver\um\$Arch\kernel32.lib") {
            return [pscustomobject]@{
                Include = @("$root\Include\$ver\um", "$root\Include\$ver\shared", "$root\Include\$ver\ucrt")
                Lib     = @("$root\Lib\$ver\um\$Arch", "$root\Lib\$ver\ucrt\$Arch")
                Version = $ver
            }
        }
    }
    return $null
}

function Find-WindowsSdkNuGet {
    # NuGet-packaged Windows SDK for the given arch. Searches a script-local sdk\
    # dir, C:\TelerikLab\sdk, and the per-user NuGet cache. Headers come from the
    # arch-neutral Microsoft.Windows.SDK.CPP package; libs from the .<arch> one.
    param([string]$Arch, [string]$ScriptDir)
    $roots = @()
    if ($ScriptDir) { $roots += (Join-Path $ScriptDir "sdk") }
    $roots += "C:\TelerikLab\sdk"
    if ($env:USERPROFILE) { $roots += (Join-Path $env:USERPROFILE ".nuget\packages") }

    # SDK.CPP package folders (the full NuGet cache is huge, so filter first).
    $pkgDirs = @()
    foreach ($r in $roots) {
        if (-not (Test-Path $r)) { continue }
        $pkgDirs += Get-ChildItem $r -Directory -ErrorAction SilentlyContinue |
                    Where-Object { $_.Name -match "(?i)Windows\.SDK\.CPP" } |
                    Select-Object -ExpandProperty FullName
    }
    if (-not $pkgDirs) { return $null }

    # The package payload rooted at "c" sits either directly under the package
    # folder (...\Pkg\c, TelerikLab layout) or under a version folder
    # (...\pkg\<ver>\c, per-user NuGet cache). Probe both by wildcard rather than
    # recursing the thousands of files each package contains.
    $cRoots = @()
    foreach ($d in $pkgDirs) {
        $c1 = Join-Path $d "c"
        if (Test-Path $c1) { $cRoots += $c1 }
        Get-ChildItem -Path $d -Directory -ErrorAction SilentlyContinue | ForEach-Object {
            $c2 = Join-Path $_.FullName "c"
            if (Test-Path $c2) { $cRoots += $c2 }
        }
    }

    $incHdr = $null
    foreach ($c in $cRoots) {
        $v = Get-ChildItem -Path (Join-Path $c "Include") -Directory -ErrorAction SilentlyContinue |
             Where-Object { Test-Path (Join-Path $_.FullName "um\winsdkver.h") } |
             Sort-Object Name -Descending | Select-Object -First 1
        if ($v) { $incHdr = $v.FullName ; break }  # ...\c\Include\<ver>
    }
    if (-not $incHdr) { return $null }

    $libC = $null
    foreach ($c in $cRoots) {
        if (Test-Path (Join-Path $c "um\$Arch\kernel32.lib")) { $libC = $c ; break }  # ...\c
    }
    if (-not $libC) { return $null }

    return [pscustomobject]@{
        Include = @("$incHdr\um", "$incHdr\shared", "$incHdr\ucrt")
        Lib     = @("$libC\um\$Arch", "$libC\ucrt\$Arch")
        Version = (Split-Path $incHdr -Leaf)
    }
}

function Find-NetFxSdk {
    # NETFXSDK (provides mscoree.lib / mscoree.h for the /clr link) for the arch.
    param([string]$Arch)
    $root = "C:\Program Files (x86)\Windows Kits\NETFXSDK"
    if (-not (Test-Path $root)) { return $null }
    $vers = Get-ChildItem $root -Directory -ErrorAction SilentlyContinue | Sort-Object Name -Descending
    foreach ($v in $vers) {
        $lib = Join-Path $v.FullName "Lib\um\$Arch"
        $inc = Join-Path $v.FullName "Include\um"
        if (Test-Path (Join-Path $lib "mscoree.lib")) {
            return [pscustomobject]@{ Include = $inc; Lib = $lib; Version = $v.Name }
        }
    }
    return $null
}

function Install-VsBuildTools {
    # Install or repair VS Build Tools with the required components. The
    # bootstrapper is primary: it runs unattended on Server and, given
    # --installPath of an existing instance (e.g. C:\BuildTools), modifies it in
    # place to add missing components. winget is used only when present and no
    # existing install needs modifying.
    param([string]$InstallPath)

    if (-not (Test-IsAdmin)) {
        throw ("Installing/repairing VS Build Tools requires an elevated (Administrator) session. " +
               "Re-run this script from an elevated PowerShell, or pre-install the 'Desktop development with C++' " +
               "workload plus the 'MSVC C++/CLI support' and '.NET Framework 4.8 SDK' components.")
    }

    $addArgs = @()
    foreach ($c in $script:VsComponents) { $addArgs += @("--add", $c) }

    $useWinget = $false
    if (-not $InstallPath) {
        $useWinget = [bool](Get-Command winget -ErrorAction SilentlyContinue)
    }

    if ($useWinget) {
        Write-Host "[*] Installing VS Build Tools via winget ..."
        $override = ("--quiet --wait --norestart " + ($addArgs -join " "))
        & winget install --id Microsoft.VisualStudio.2022.BuildTools --silent `
            --accept-package-agreements --accept-source-agreements --override $override
        if ($LASTEXITCODE -ne 0) { throw "winget install of VS Build Tools failed (exit $LASTEXITCODE)" }
        return
    }

    $bootstrapper = Join-Path $env:TEMP "vs_BuildTools.exe"
    Write-Host "[*] Downloading VS Build Tools bootstrapper ..."
    Invoke-WebRequest -Uri "https://aka.ms/vs/17/release/vs_BuildTools.exe" -OutFile $bootstrapper -UseBasicParsing

    $bargs = @()
    if ($InstallPath) {
        Write-Host "[*] Modifying existing Build Tools at $InstallPath to add missing components ..."
        $bargs += @("modify", "--installPath", $InstallPath)
    } else {
        Write-Host "[*] Installing Build Tools to C:\BuildTools ..."
        $bargs += @("--installPath", "C:\BuildTools")
    }
    $bargs += $addArgs
    $bargs += @("--quiet", "--wait", "--norestart")

    $p = Start-Process -FilePath $bootstrapper -ArgumentList $bargs -Wait -PassThru -NoNewWindow
    # 0 = success, 3010 = success/reboot required.
    if ($p.ExitCode -ne 0 -and $p.ExitCode -ne 3010) {
        throw "VS Build Tools bootstrapper failed (exit $($p.ExitCode))"
    }
}

function Install-WindowsSdkNuGet {
    # Provision the Windows SDK headers + arch libs from NuGet into a script-local
    # sdk\ dir. Lightweight alternative to a full SDK install when the compiler is
    # already present but its SDK libs/headers for this arch are missing.
    # Uses ZipFile::ExtractToDirectory (Expand-Archive is far too slow for the
    # thousands of small files in the SDK packages) and skips packages already
    # extracted so re-runs are cheap.
    param([string]$Arch, [string]$ScriptDir, [string]$Version)
    Add-Type -AssemblyName System.IO.Compression.FileSystem | Out-Null
    $dest = Join-Path $ScriptDir "sdk"
    if (-not (Test-Path $dest)) { New-Item -ItemType Directory -Path $dest | Out-Null }
    foreach ($pkg in @("Microsoft.Windows.SDK.CPP", "Microsoft.Windows.SDK.CPP.$Arch")) {
        $outdir = Join-Path $dest "$pkg.$Version"
        if (Test-Path (Join-Path $outdir "c")) {
            Write-Host "[*] NuGet SDK package $pkg $Version already present, skipping."
            continue
        }
        $url   = "https://www.nuget.org/api/v2/package/$pkg/$Version"
        $nupkg = Join-Path $env:TEMP "$pkg.$Version.nupkg.zip"
        Write-Host "[*] Fetching NuGet SDK package $pkg $Version ..."
        Invoke-WebRequest -Uri $url -OutFile $nupkg -UseBasicParsing
        if (Test-Path $outdir) { Remove-Item $outdir -Recurse -Force }
        Write-Host "[*] Extracting $pkg ..."
        [System.IO.Compression.ZipFile]::ExtractToDirectory($nupkg, $outdir)
        Remove-Item $nupkg -Force -ErrorAction SilentlyContinue
    }
}

function Initialize-BuildEnv {
    # Resolve (installing if needed) the full build environment for $Arch
    # ("x64"/"x86"), set INCLUDE/LIB, and return the tool paths.
    param(
        [Parameter(Mandatory)][ValidateSet("x64", "x86")][string]$Arch,
        [Parameter(Mandatory)][string]$ScriptDir
    )

    # --- Compiler -----------------------------------------------------------
    $msvc = Find-Msvc
    if (-not $msvc) {
        Write-Host "[!] MSVC toolchain not found -- installing VS Build Tools ..."
        Install-VsBuildTools
        $msvc = Find-Msvc
        if (-not $msvc) { throw "MSVC toolchain still not found after install" }
    }
    Write-Host "[*] MSVC version: $($msvc.Version)  ($($msvc.Base))"

    $hostBin = Get-HostBinDir
    $bin     = Join-Path $msvc.Base "$($msvc.Version)\bin\$hostBin\$Arch"
    $clExe   = Join-Path $bin "cl.exe"
    $linkExe = Join-Path $bin "link.exe"
    foreach ($t in @($clExe, $linkExe)) {
        if (-not (Test-Path $t)) { throw "Tool not found: $t (is the $Arch toolset installed?)" }
    }

    # --- Windows SDK --------------------------------------------------------
    $sdk = Find-WindowsSdkKits -Arch $Arch
    if (-not $sdk) { $sdk = Find-WindowsSdkNuGet -Arch $Arch -ScriptDir $ScriptDir }
    if (-not $sdk) {
        Write-Host "[!] Windows SDK for $Arch not found -- provisioning from NuGet ..."
        Install-WindowsSdkNuGet -Arch $Arch -ScriptDir $ScriptDir -Version $script:SdkNuGetVersion
        $sdk = Find-WindowsSdkNuGet -Arch $Arch -ScriptDir $ScriptDir
        if (-not $sdk) { throw "Windows SDK for $Arch still not found after NuGet provisioning" }
    }
    Write-Host "[*] Windows SDK: $($sdk.Version)  ($($sdk.Lib[0]))"

    # --- NETFXSDK (mscoree.lib) --------------------------------------------
    $netfx = Find-NetFxSdk -Arch $Arch
    if (-not $netfx) {
        Write-Host "[!] NETFXSDK (mscoree.lib) for $Arch not found -- repairing Build Tools to add the .NET 4.8 SDK ..."
        Install-VsBuildTools -InstallPath $msvc.Root
        $netfx = Find-NetFxSdk -Arch $Arch
        if (-not $netfx) {
            throw "NETFXSDK (mscoree.lib) for $Arch not found. Add the 'MSVC C++/CLI support' + '.NET Framework 4.8 SDK' components to the Build Tools install."
        }
    }
    Write-Host "[*] NETFXSDK: $($netfx.Version)"

    # --- .NET Framework runtime (System.Web.dll, csc.exe) -------------------
    $dotnetFx = [System.Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory().TrimEnd("\")
    if (-not (Test-Path "$dotnetFx\System.Web.dll")) {
        throw "System.Web.dll not found in runtime directory '$dotnetFx'"
    }
    Write-Host "[*] .NET runtime directory: $dotnetFx"

    # --- Environment --------------------------------------------------------
    $env:INCLUDE = (@("$($msvc.Base)\$($msvc.Version)\include") + $sdk.Include + @($netfx.Include)) -join ";"
    $env:LIB     = (@("$($msvc.Base)\$($msvc.Version)\lib\$Arch") + $sdk.Lib + @($netfx.Lib)) -join ";"

    return [pscustomobject]@{
        Cl       = $clExe
        Link     = $linkExe
        Csc      = Join-Path $dotnetFx "csc.exe"
        DotnetFx = $dotnetFx
    }
}
