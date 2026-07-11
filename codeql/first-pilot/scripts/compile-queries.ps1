param(
    [string]$PackageRoot = (Join-Path $PSScriptRoot '..'),
    [string]$CodeQL = '',
    [string]$AdditionalPacks = '',
    [string]$LogPath = ''
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

function Resolve-RequiredPath {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Name
    )
    if (-not (Test-Path -LiteralPath $Path)) {
        throw "$Name not found: $Path"
    }
    return (Resolve-Path -LiteralPath $Path).Path
}

function Resolve-CodeQLPath {
    param([string]$RequestedPath)

    $candidates = New-Object System.Collections.Generic.List[string]
    if ($RequestedPath) { $candidates.Add($RequestedPath) }
    if ($env:CODEQL_EXE) { $candidates.Add($env:CODEQL_EXE) }
    if ($env:CODEQL_HOME) {
        $candidates.Add((Join-Path $env:CODEQL_HOME 'codeql.exe'))
        $candidates.Add((Join-Path $env:CODEQL_HOME 'codeql'))
    }
    foreach ($name in @('codeql.exe', 'codeql')) {
        $cmd = Get-Command $name -ErrorAction SilentlyContinue
        if ($cmd -and $cmd.Source) { $candidates.Add($cmd.Source) }
    }

    foreach ($candidate in $candidates) {
        if ($candidate -and (Test-Path -LiteralPath $candidate)) {
            return (Resolve-Path -LiteralPath $candidate).Path
        }
    }

    throw 'CodeQL not found. Pass -CodeQL, set CODEQL_EXE or CODEQL_HOME, or add codeql to PATH.'
}

function Resolve-OptionalAdditionalPacks {
    param(
        [string]$RequestedPath,
        [string]$ResolvedPackageRoot
    )

    $candidate = ''
    if ($RequestedPath) {
        $candidate = $RequestedPath
    }
    elseif ($env:CODEQL_ADDITIONAL_PACKS) {
        $candidate = $env:CODEQL_ADDITIONAL_PACKS
    }
    else {
        $nearby = Join-Path $ResolvedPackageRoot '..\codeql\codeql-stdlib'
        if (Test-Path -LiteralPath $nearby) {
            $candidate = $nearby
        }
    }

    if (-not $candidate) { return '' }
    $pathSeparator = [string][System.IO.Path]::PathSeparator
    if ($candidate.Contains($pathSeparator)) { return $candidate }
    return (Resolve-RequiredPath $candidate 'AdditionalPacks')
}

function Add-LogLine {
    param(
        [string]$Path,
        [string]$Line
    )
    Write-Output $Line
    Add-Content -LiteralPath $Path -Value $Line -Encoding UTF8
}

try {
    $PackageRoot = Resolve-RequiredPath $PackageRoot 'PackageRoot'
    $CodeQL = Resolve-CodeQLPath $CodeQL
    $AdditionalPacks = Resolve-OptionalAdditionalPacks $AdditionalPacks $PackageRoot
    if (-not $LogPath) {
        $LogPath = Join-Path $PackageRoot 'validation\compile-latest.log'
    }

    $logDir = Split-Path -Parent $LogPath
    New-Item -ItemType Directory -Path $logDir -Force | Out-Null

    if (-not $env:CODEQL_ALLOW_INSTALLATION_ANYWHERE) {
        $env:CODEQL_ALLOW_INSTALLATION_ANYWHERE = 'true'
    }

    $commandArgs = @('query', 'compile', '--check-only')
    if ($AdditionalPacks) {
        $commandArgs += @('--additional-packs', $AdditionalPacks)
    }
    $commandArgs += @('--', $PackageRoot)

    @(
        '=== compile queries ===',
        "package=$PackageRoot",
        "codeql=$CodeQL",
        "additional_packs=$AdditionalPacks",
        "command=$CodeQL $($commandArgs -join ' ')"
    ) | Set-Content -LiteralPath $LogPath -Encoding UTF8

    $savedErrorActionPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    $output = & $CodeQL @commandArgs 2>&1
    $exitCode = $LASTEXITCODE
    $ErrorActionPreference = $savedErrorActionPreference
    $output | ForEach-Object { Add-LogLine -Path $LogPath -Line $_.ToString() }

    if ($exitCode -ne 0) {
        Add-LogLine -Path $LogPath -Line "STATUS=FAIL exit_code=$exitCode"
        exit $exitCode
    }

    Add-LogLine -Path $LogPath -Line 'STATUS=OK'
}
catch {
    Write-Error $_
    exit 1
}
