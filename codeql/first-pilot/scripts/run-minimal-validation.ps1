param(
    [string]$PackageRoot = (Join-Path $PSScriptRoot '..'),
    [string]$CodeQL = '',
    [string]$AdditionalPacks = '',
    [string]$StagingRoot = '',
    [string]$Clang = '',
    [switch]$Force,
    [switch]$SkipBuild,
    [switch]$SkipAnalyze,
    [switch]$SkipClangCheck
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

try {
    $PackageRoot = (Resolve-Path -LiteralPath $PackageRoot).Path

    $compileArgs = @{ PackageRoot = $PackageRoot }
    if ($CodeQL) { $compileArgs.CodeQL = $CodeQL }
    if ($AdditionalPacks) { $compileArgs.AdditionalPacks = $AdditionalPacks }
    & (Join-Path $PSScriptRoot 'compile-queries.ps1') @compileArgs

    if (-not $SkipBuild) {
        $buildArgs = @{
            PackageRoot = $PackageRoot
            Force = $Force
            SkipClangCheck = $SkipClangCheck
        }
        if ($CodeQL) { $buildArgs.CodeQL = $CodeQL }
        if ($StagingRoot) { $buildArgs.StagingRoot = $StagingRoot }
        if ($Clang) { $buildArgs.Clang = $Clang }
        & (Join-Path $PSScriptRoot 'build-minimal-databases.ps1') @buildArgs
    }

    if (-not $SkipAnalyze) {
        $analyzeArgs = @{
            PackageRoot = $PackageRoot
            Force = $Force
        }
        if ($CodeQL) { $analyzeArgs.CodeQL = $CodeQL }
        if ($AdditionalPacks) { $analyzeArgs.AdditionalPacks = $AdditionalPacks }
        & (Join-Path $PSScriptRoot 'run-smoke-analyze.ps1') @analyzeArgs
    }
}
catch {
    Write-Error $_
    exit 1
}
