param(
    [string]$PackageRoot = (Join-Path $PSScriptRoot '..'),
    [string]$CodeQL = '',
    [string]$AdditionalPacks = '',
    [string]$SummaryPath = '',
    [switch]$Force
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

function Get-SarifResultCount {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        return $null
    }
    $sarif = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json
    $count = 0
    foreach ($run in @($sarif.runs)) {
        if ($null -ne $run.results) {
            $count += @($run.results).Count
        }
    }
    return $count
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
    if (-not $SummaryPath) {
        $SummaryPath = Join-Path $PackageRoot 'minimal-validation-databases\results\smoke-summary.latest.csv'
    }

    if (-not $env:CODEQL_ALLOW_INSTALLATION_ANYWHERE) {
        $env:CODEQL_ALLOW_INSTALLATION_ANYWHERE = 'true'
    }

    $validationRoot = Join-Path $PackageRoot 'minimal-validation-databases'
    $dbRoot = Resolve-RequiredPath (Join-Path $validationRoot 'db') 'DatabaseRoot'
    $logRoot = Join-Path $validationRoot 'logs'
    $resultRoot = Join-Path $validationRoot 'results'
    New-Item -ItemType Directory -Path $logRoot, $resultRoot -Force | Out-Null

    $arrayQuery = Resolve-RequiredPath (Join-Path $PackageRoot 'queries\missing-array-bounds-check-on-network-controlled-index.ql') 'ArrayQuery'
    $lengthQuery = Resolve-RequiredPath (Join-Path $PackageRoot 'queries\missing-minimum-length-check-on-network-protocol-packet.ql') 'LengthQuery'

    $jobs = @(
        [pscustomobject]@{ Cve = 'CVE-2018-17161'; Query = $arrayQuery; QueryName = 'array-index-upper-bound' },
        [pscustomobject]@{ Cve = 'CVE-2019-5604'; Query = $arrayQuery; QueryName = 'array-index-upper-bound' },
        [pscustomobject]@{ Cve = 'CVE-2021-29631'; Query = $arrayQuery; QueryName = 'array-index-upper-bound' },
        [pscustomobject]@{ Cve = 'CVE-2020-7461'; Query = $lengthQuery; QueryName = 'packet-minimum-length' },
        [pscustomobject]@{ Cve = 'CVE-2021-29629'; Query = $lengthQuery; QueryName = 'packet-minimum-length' }
    )

    $summary = New-Object System.Collections.Generic.List[object]

    foreach ($job in $jobs) {
        foreach ($variant in @('vulnerable', 'fixed')) {
            $name = "$($job.Cve)-$variant"
            $db = Join-Path $dbRoot $name
            $output = Join-Path $resultRoot "$name.sarif"
            $logPath = Join-Path $logRoot "analyze-$name.log"
            $status = 'OK'

            if (-not (Test-Path -LiteralPath $db)) {
                throw "Database not found for $name`: $db"
            }

            if ((Test-Path -LiteralPath $output) -and -not $Force) {
                $status = 'SKIPPED'
                @(
                    "=== $name ===",
                    "db=$db",
                    "query=$($job.Query)",
                    "output=$output",
                    'STATUS=SKIPPED existing_result use -Force to rerun'
                ) | Set-Content -LiteralPath $logPath -Encoding UTF8
                Write-Host "SKIP $name (existing SARIF)"
            }
            else {
                $commandArgs = @(
                    'database', 'analyze',
                    $db,
                    $job.Query,
                    '--format=sarif-latest',
                    "--output=$output"
                )
                if ($Force) {
                    $commandArgs += '--rerun'
                }
                if ($AdditionalPacks) {
                    $commandArgs += @('--additional-packs', $AdditionalPacks)
                }

                @(
                    "=== $name ===",
                    "db=$db",
                    "query=$($job.Query)",
                    "output=$output",
                    "codeql=$CodeQL",
                    "additional_packs=$AdditionalPacks",
                    "command=$CodeQL $($commandArgs -join ' ')"
                ) | Set-Content -LiteralPath $logPath -Encoding UTF8

                $savedErrorActionPreference = $ErrorActionPreference
                $ErrorActionPreference = 'Continue'
                $runOutput = & $CodeQL @commandArgs 2>&1
                $exitCode = $LASTEXITCODE
                $ErrorActionPreference = $savedErrorActionPreference
                $runOutput | ForEach-Object { Add-LogLine -Path $logPath -Line $_.ToString() }

                if ($exitCode -ne 0) {
                    Add-LogLine -Path $logPath -Line "STATUS=FAIL exit_code=$exitCode"
                    exit $exitCode
                }

                Add-LogLine -Path $logPath -Line 'STATUS=OK'
                Write-Host "OK $name"
            }

            $summary.Add([pscustomobject]@{
                CVE = $job.Cve
                Variant = $variant
                Query = $job.QueryName
                Results = Get-SarifResultCount -Path $output
                Status = $status
                Sarif = $output
            })
        }
    }

    $sortedSummary = $summary | Sort-Object CVE, Variant
    $sortedSummary | Format-Table -AutoSize
    $sortedSummary | Export-Csv -LiteralPath $SummaryPath -NoTypeInformation -Encoding UTF8
    Write-Host "Summary written to $SummaryPath"
}
catch {
    Write-Error $_
    exit 1
}
