#Requires -Version 7.4
<#
.SYNOPSIS
Build paired unsigned Windows inputs, optionally with a real runtime.
.DESCRIPTION
Run in a non-elevated x64 MSVC Developer PowerShell with Rust 1.88.0,
repository-pinned Bun, Python 3 and cached Cargo/workspace dependencies.
Use an LF checkout: a runtime candidate must match the exact current source bytes.
-Runtime is an existing amd64 runtime directory with SHA256SUMS and all sidecars.
Without -Runtime, output is build inputs only, with no bundle.json, ISO or install flow.
-ToolsBundle supplies the controller build's server.mjs for source pairing with -Runtime.
No tools are installed and no VM, HCS service or image build is started.
#>
[CmdletBinding()]
param(
    [string]$Version = $env:OBLIVION_DESKTOP_VERSION,
    [string]$Channel = $env:OBLIVION_BUNDLE_CHANNEL,
    [string]$Runtime = $env:OBLIVION_DESKTOP_RUNTIME,
    [string]$Output = $env:OBLIVION_DESKTOP_OUTPUT,
    [string]$Python = 'python',
    [ValidateNotNullOrEmpty()][string]$ToolsBundle
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$PSNativeCommandArgumentPassing = 'Standard'
$PSNativeCommandUseErrorActionPreference = $false
if ($ToolsBundle -and -not $Runtime) { throw 'Use -ToolsBundle only with -Runtime.' }
if (-not $IsWindows -or [Runtime.InteropServices.RuntimeInformation]::OSArchitecture -ne 'X64' -or
    [Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture -ne 'X64') {
    throw 'Build on native Windows x64 using PowerShell 7.4 or later.'
}
$Identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if ([Security.Principal.WindowsPrincipal]::new($Identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Use a non-elevated MSVC Developer PowerShell; generated files must be owned by the actual user.'
}
$Repository = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$Builder = Join-Path $PSScriptRoot 'bundle-native.py'
$Platform = 'windows-x86_64'
$Target = 'x86_64-pc-windows-msvc'
function Invoke-Native {
    param([string]$Executable, [string[]]$Arguments, [switch]$Capture)
    if ($Capture) { $Result = & $Executable @Arguments }
    else { & $Executable @Arguments }
    if ($LASTEXITCODE -ne 0) { throw "Native build command failed: $Executable (exit $LASTEXITCODE)." }
    if ($Capture) { return $Result }
}
function New-PrivateDirectory {
    param([string]$Path)
    if (Test-Path -LiteralPath $Path) { throw 'A private build directory already exists; refusing to adopt it.' }
    $Security = [Security.AccessControl.DirectorySecurity]::new()
    $Security.SetOwner($Identity.User)
    $Security.SetAccessRuleProtection($true, $false)
    $Inherit = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit
    foreach ($Sid in @($Identity.User, [Security.Principal.SecurityIdentifier]::new('S-1-5-18'))) {
        $Security.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($Sid,
            [Security.AccessControl.FileSystemRights]::FullControl, $Inherit,
            [Security.AccessControl.PropagationFlags]::None, [Security.AccessControl.AccessControlType]::Allow))
    }
    [void][IO.FileSystemAclExtensions]::CreateDirectory($Security, $Path)
}
function Get-EntryAttributes {
    param([string]$Path)
    try { return [IO.File]::GetAttributes($Path) }
    catch [IO.FileNotFoundException], [IO.DirectoryNotFoundException] { return $null }
}
function Install-ToolsBundle {
    param([string]$Path)
    $SourceFile = [IO.Path]::GetFullPath($Path, $Repository)
    $Directory = Join-Path $Repository 'packages/oblivion-tools/dist'
    $Destination = [IO.Path]::GetFullPath((Join-Path $Directory 'server.mjs'))
    $DirectoryFlag = [IO.FileAttributes]::Directory
    $ReparseFlag = [IO.FileAttributes]::ReparsePoint
    $FileMask = $DirectoryFlag -bor $ReparseFlag
    $Attributes = Get-EntryAttributes $SourceFile
    if ($null -eq $Attributes -or ($Attributes -band $FileMask) -or $SourceFile -ieq $Destination) {
        throw '-ToolsBundle must name a separate regular file.'
    }
    foreach ($Component in @($Repository, (Join-Path $Repository 'packages'), (Join-Path $Repository 'packages/oblivion-tools'), $Directory)) {
        $Attributes = Get-EntryAttributes $Component
        if ($null -eq $Attributes -and $Component -eq $Directory) {
            [void][IO.Directory]::CreateDirectory($Directory)
            continue
        }
        if ($null -eq $Attributes -or ($Attributes -band $FileMask) -ne $DirectoryFlag) {
            throw 'The tools output path must contain only ordinary directories.'
        }
    }
    $Attributes = Get-EntryAttributes $Destination
    if ($null -ne $Attributes -and ($Attributes -band $FileMask)) {
        throw 'The tools output must be a regular file.'
    }
    $Temporary = Join-Path $Directory ('.server-' + [guid]::NewGuid().ToString('N') + '.mjs')
    try {
        [IO.File]::Copy($SourceFile, $Temporary, $false)
        [IO.File]::Move($Temporary, $Destination, $true)
    } finally {
        [IO.File]::Delete($Temporary)
    }
}
foreach ($Tool in @($Python, 'cargo', 'rustc', 'bun')) {
    if (-not (Get-Command $Tool -CommandType Application -ErrorAction SilentlyContinue)) { throw "Required tool is missing: $Tool." }
}
Invoke-Native -Executable $Python -Arguments @('-B', (Join-Path $PSScriptRoot 'bundle-version.py'), 'validate', '--channel', $Channel, '--product-version', $Version)
$Rust = (Invoke-Native -Executable 'rustc' -Arguments @('--version') -Capture) -join "`n"
if ($Rust -notmatch '^rustc 1\.88\.0 ') { throw 'Select the pinned Rust 1.88.0 MSVC toolchain before building.' }
$Cargo = (Invoke-Native -Executable 'cargo' -Arguments @('--version') -Capture) -join ''
$RustDetails = (Invoke-Native -Executable 'rustc' -Arguments @('-vV') -Capture) -join "`n"
if ($RustDetails -notmatch 'host: x86_64-pc-windows-msvc') { throw 'Use the native x86_64-pc-windows-msvc Rust toolchain.' }
$Bun = (Invoke-Native -Executable 'bun' -Arguments @('--version') -Capture) -join ''
$Package = Get-Content -LiteralPath (Join-Path $Repository 'package.json') -Raw | ConvertFrom-Json
if ("bun@$Bun" -ne $Package.packageManager) { throw "Use $($Package.packageManager), pinned by package.json." }
$PythonVersion = (Invoke-Native -Executable $Python -Arguments @('-c', 'import sys; assert sys.version_info.major == 3; print(sys.version.split()[0])') -Capture) -join ''
if (-not $env:VCToolsInstallDir -or -not $env:LIB) { throw 'Open an x64 MSVC Developer PowerShell with the Windows SDK environment.' }
$Linker = Join-Path $env:VCToolsInstallDir 'bin/Hostx64/x64/link.exe'
if (-not (Test-Path -LiteralPath $Linker -PathType Leaf)) { throw 'The x64 MSVC linker is unavailable.' }
if (-not $Output) {
    $Kind = if ($Runtime) { 'oblivion-desktop-windows-x86_64' } else { 'oblivion-windows-build-inputs' }
    $Output = Join-Path $Repository "artifacts/$Kind/$Version"
}
$Output = [IO.Path]::GetFullPath($Output, $Repository)
if ($Output -notmatch '^[A-Za-z]:\\') { throw 'Output must be on a local Windows drive.' }
if (Test-Path -LiteralPath $Output) { throw 'Output already exists; refusing to overwrite it.' }
if ($Runtime) {
    $Runtime = [IO.Path]::GetFullPath($Runtime, $Repository)
    if (-not (Test-Path -LiteralPath $Runtime -PathType Container)) { throw 'Runtime must be an existing matching amd64 candidate directory.' }
    if (-not (Get-Command 'bsdtar' -CommandType Application -ErrorAction SilentlyContinue) -and
        -not (Get-Command 'tar' -CommandType Application -ErrorAction SilentlyContinue)) { throw 'Install libarchive/bsdtar to extract a real runtime candidate.' }
}
$Parent = [IO.Path]::GetDirectoryName($Output)
[void][IO.Directory]::CreateDirectory($Parent)
$Work = Join-Path $Parent ('.windows-build-' + [guid]::NewGuid().ToString('N'))
New-PrivateDirectory $Work
$Variables = @('OBLIVION_BUNDLE_CHANNEL', 'OBLIVION_DESKTOP_VERSION', 'OBLIVION_DESKTOP_SOURCE_SHA256', 'OBLIVION_DESKTOP_PLATFORM', 'CARGO_TARGET_DIR', 'CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_LINKER')
$Saved = @{}
foreach ($Name in $Variables) { $Saved[$Name] = [Environment]::GetEnvironmentVariable($Name, 'Process') }
Push-Location -LiteralPath $Repository
try {
    if ($ToolsBundle) { Install-ToolsBundle $ToolsBundle }
    else { Invoke-Native -Executable 'bun' -Arguments @('run', '--cwd', 'packages/oblivion-tools', 'build') }
    $Inventory = Join-Path $Work 'host-sources.sha256'
    $Source = (Invoke-Native -Executable $Python -Arguments @('-B', $Builder, 'sources', '--output', $Inventory) -Capture) -join ''
    if ($Source -notmatch '^[0-9a-f]{64}$') { throw 'The canonical source inventory returned an invalid identity.' }
    $Prepared = Join-Path $Work 'bundle'
    if ($Runtime) {
        $Paired = (Invoke-Native -Executable $Python -Arguments @('-B', $Builder, 'prepare', '--runtime', $Runtime, '--platform', $Platform, '--output', $Prepared) -Capture) -join ''
        if ($Paired -ne $Source) { throw 'The runtime candidate does not match the current native source inventory.' }
    }
    $env:OBLIVION_DESKTOP_VERSION = $Version
    $env:OBLIVION_BUNDLE_CHANNEL = $Channel
    $env:OBLIVION_DESKTOP_SOURCE_SHA256 = $Source
    $env:OBLIVION_DESKTOP_PLATFORM = $Platform
    $env:CARGO_TARGET_DIR = Join-Path $Work 'cargo-target'
    $env:CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_LINKER = $Linker
    Invoke-Native -Executable 'cargo' -Arguments @('build', '--manifest-path', 'packages/oblivion-cli/Cargo.toml', '--locked', '--offline', '--release', '--target', $Target, '--features', 'windows-launcher', '--bin', 'oblivion')
    Invoke-Native -Executable 'cargo' -Arguments @('build', '--manifest-path', 'packages/oblivion-native-windows/Cargo.toml', '--locked', '--offline', '--release', '--target', $Target, '--bin', 'oblivion-vm')
    $Manager = Join-Path $Work 'manager/oblivion-manager.exe'
    Invoke-Native -Executable 'bun' -Arguments @('run', '--cwd', 'packages/oblivion-manager', 'script/build.ts', '--target=bun-windows-x64', "--output=$Manager")
    $After = (Invoke-Native -Executable $Python -Arguments @('-B', $Builder, 'sources', '--output', (Join-Path $Work 'sources-after.sha256')) -Capture) -join ''
    if ($After -ne $Source) { throw 'Runtime sources changed during the build; rebuild from one unchanged source tree.' }
    $Cli = Join-Path $env:CARGO_TARGET_DIR "$Target/release/oblivion.exe"
    $Helper = Join-Path $env:CARGO_TARGET_DIR "$Target/release/oblivion-vm.exe"
    $Assets = Join-Path $Work 'manager/assets'
    $Metadata = [ordered]@{ format = 'oblivion-windows-native-build'; version = 2; channel = $Channel;
        product_version = $Version; platform = $Platform; source_sha256 = $Source; runtime_included = [bool]$Runtime;
        toolchain = @{ rustc = $RustDetails; cargo = $Cargo; bun = $Bun; python = $PythonVersion;
            msvc_toolset = $env:VCToolsVersion; windows_sdk = $env:WindowsSDKVersion;
            linker = [Diagnostics.FileVersionInfo]::GetVersionInfo($Linker).ProductVersion } }
    $BuildEvidence = ($Metadata | ConvertTo-Json -Depth 4) + "`n"
    if ($Runtime) {
        [IO.File]::WriteAllText((Join-Path $Prepared 'evidence/windows-native-build.json'), $BuildEvidence, [Text.UTF8Encoding]::new($false))
        Invoke-Native -Executable $Python -Arguments @('-B', $Builder, 'assemble', '--prepared', $Prepared, '--platform', $Platform,
            '--channel', $Channel, '--product-version', $Version, '--cli', $Cli, '--helper', $Helper, '--manager', $Manager,
            '--manager-assets', $Assets, '--output', $Output)
    } else {
        $Inputs = Join-Path $Work 'build-inputs'
        New-PrivateDirectory $Inputs
        [void][IO.Directory]::CreateDirectory((Join-Path $Inputs 'bin'))
        [void][IO.Directory]::CreateDirectory((Join-Path $Inputs 'lib'))
        [void][IO.Directory]::CreateDirectory((Join-Path $Inputs 'evidence'))
        foreach ($Binary in @($Cli, $Helper, $Manager)) { [IO.File]::Copy($Binary, (Join-Path $Inputs "bin/$([IO.Path]::GetFileName($Binary))"), $false) }
        [IO.Directory]::Move($Assets, (Join-Path $Inputs 'lib/manager'))
        [IO.File]::Copy($Inventory, (Join-Path $Inputs 'evidence/host-sources.sha256'), $false)
        [IO.File]::WriteAllText((Join-Path $Inputs 'evidence/build.json'), $BuildEvidence, [Text.UTF8Encoding]::new($false))
        [IO.File]::WriteAllText((Join-Path $Inputs 'README.md'), @"
# Windows build inputs

This is not an installable Oblivion desktop bundle. It contains no runtime ISO,
VHDX, bundle.json or installation approval. Supply a matching real runtime candidate
to build-native-windows.ps1 -Runtime to assemble a complete unsigned bundle.

Channel: $Channel
Product version: $Version
Source SHA256: $Source
Toolchain versions are recorded in evidence/build.json. Binary reproducibility across
different Windows SDK/linker versions has not been qualified.
"@, [Text.UTF8Encoding]::new($false))
        $Sums = foreach ($File in Get-ChildItem -LiteralPath $Inputs -Recurse -File | Sort-Object FullName) {
            $Relative = [IO.Path]::GetRelativePath($Inputs, $File.FullName).Replace('\', '/')
            (Get-FileHash -LiteralPath $File.FullName -Algorithm SHA256).Hash.ToLowerInvariant() + '  ' + $Relative
        }
        [IO.File]::WriteAllText((Join-Path $Inputs 'SHA256SUMS'), ($Sums -join "`n") + "`n", [Text.UTF8Encoding]::new($false))
        [IO.Directory]::Move($Inputs, $Output)
    }
    Write-Host "Unsigned $Channel output: $Output"
    Write-Host 'No installer, hypervisor, VM or ISO build was run.'
} finally {
    foreach ($Name in $Variables) { [Environment]::SetEnvironmentVariable($Name, $Saved[$Name], 'Process') }
    Pop-Location
    Remove-Item -LiteralPath $Work -Recurse -Force -ErrorAction Continue
    $Identity.Dispose()
}
