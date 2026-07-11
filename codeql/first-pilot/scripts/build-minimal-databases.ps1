param(
    [string]$PackageRoot = (Join-Path $PSScriptRoot '..'),
    [string]$CodeQL = '',
    [string]$StagingRoot = '',
    [string]$Clang = '',
    [switch]$Force,
    [switch]$SkipClangCheck
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

function Resolve-OptionalClangPath {
    param([string]$RequestedPath)

    $candidates = New-Object System.Collections.Generic.List[string]
    if ($RequestedPath) { $candidates.Add($RequestedPath) }
    if ($env:CLANG_EXE) { $candidates.Add($env:CLANG_EXE) }
    foreach ($name in @('clang.exe', 'clang')) {
        $cmd = Get-Command $name -ErrorAction SilentlyContinue
        if ($cmd -and $cmd.Source) { $candidates.Add($cmd.Source) }
    }
    foreach ($candidate in $candidates) {
        if ($candidate -and (Test-Path -LiteralPath $candidate)) {
            return (Resolve-Path -LiteralPath $candidate).Path
        }
    }

    return ''
}

function Assert-UnderRoot {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Root
    )
    $fullPath = [System.IO.Path]::GetFullPath($Path)
    $fullRoot = [System.IO.Path]::GetFullPath($Root)
    if (-not $fullRoot.EndsWith([System.IO.Path]::DirectorySeparatorChar)) {
        $fullRoot += [System.IO.Path]::DirectorySeparatorChar
    }
    if (-not $fullPath.StartsWith($fullRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to modify path outside root. path=$fullPath root=$fullRoot"
    }
}

function Remove-TreeIfExists {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Root
    )
    if (Test-Path -LiteralPath $Path) {
        Assert-UnderRoot -Path $Path -Root $Root
        Remove-Item -LiteralPath $Path -Recurse -Force
    }
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
    if (-not $StagingRoot) {
        $StagingRoot = Join-Path ([System.IO.Path]::GetTempPath()) 'freevrg-codeql-work\first-ql-validation-package\minimal-validation-databases'
    }
    $StagingRoot = [System.IO.Path]::GetFullPath($StagingRoot)
    $Clang = Resolve-OptionalClangPath $Clang

    if (-not $env:CODEQL_ALLOW_INSTALLATION_ANYWHERE) {
        $env:CODEQL_ALLOW_INSTALLATION_ANYWHERE = 'true'
    }

    if ($StagingRoot -match '[^\x00-\x7F]') {
        Write-Warning "StagingRoot contains non-ASCII characters. If CodeQL database create fails, rerun with -StagingRoot C:\freevrg-codeql-work."
    }

    $validationRoot = Join-Path $PackageRoot 'minimal-validation-databases'
    $sourceRoot = Resolve-RequiredPath (Join-Path $validationRoot 'source') 'SourceRoot'
    $dbRoot = Join-Path $validationRoot 'db'
    $logRoot = Join-Path $validationRoot 'logs'
    $stagingSourceRoot = Join-Path $StagingRoot 'source'
    $stagingDbRoot = Join-Path $StagingRoot 'db'
    $clangCheckRoot = Join-Path $StagingRoot 'clang-check'

    New-Item -ItemType Directory -Path $dbRoot, $logRoot, $stagingSourceRoot, $stagingDbRoot -Force | Out-Null

    $jobs = Get-ChildItem -LiteralPath $sourceRoot -Directory | Sort-Object Name
    if (-not $jobs) {
        throw "No source harness directories found under $sourceRoot"
    }

    foreach ($job in $jobs) {
        $name = $job.Name
        $targetDb = Join-Path $dbRoot $name
        $stagingSource = Join-Path $stagingSourceRoot $name
        $stagingDb = Join-Path $stagingDbRoot $name
        $logPath = Join-Path $logRoot "create-$name.log"

        if ((Test-Path -LiteralPath $targetDb) -and -not $Force) {
            @(
                "=== $name ===",
                "database=$targetDb",
                'STATUS=SKIPPED existing_database use -Force to rebuild'
            ) | Set-Content -LiteralPath $logPath -Encoding UTF8
            Write-Host "SKIP $name (existing database)"
            continue
        }

        Remove-TreeIfExists -Path $stagingSource -Root $StagingRoot
        Remove-TreeIfExists -Path $stagingDb -Root $StagingRoot
        if ($Force) {
            Remove-TreeIfExists -Path $targetDb -Root $dbRoot
        }

        Copy-Item -LiteralPath $job.FullName -Destination $stagingSource -Recurse -Force

        if (-not $SkipClangCheck) {
            if ($Clang) {
                New-Item -ItemType Directory -Path $clangCheckRoot -Force | Out-Null
                $harness = Join-Path $stagingSource 'harness.c'
                $objectPath = Join-Path $clangCheckRoot "$name.obj"
                $savedErrorActionPreference = $ErrorActionPreference
                $ErrorActionPreference = 'Continue'
                $clangOutput = & $Clang '-std=c11' '-c' $harness '-o' $objectPath 2>&1
                $clangExitCode = $LASTEXITCODE
                $ErrorActionPreference = $savedErrorActionPreference
                if ($clangExitCode -ne 0) {
                    $clangOutput | ForEach-Object { $_.ToString() } | Set-Content -LiteralPath $logPath -Encoding UTF8
                    'STATUS=FAIL clang_check' | Add-Content -LiteralPath $logPath -Encoding UTF8
                    throw "clang check failed for $name"
                }
            }
            else {
                Write-Warning 'Clang not found. Skipping clang compile check; CodeQL extraction will still run.'
            }
        }

        $commandArgs = @(
            'database', 'create', $stagingDb,
            '--language=cpp',
            '--source-root', $stagingSource,
            '--build-mode=none'
        )

        @(
            "=== $name ===",
            "source=$stagingSource",
            "db=$stagingDb",
            'build_mode=none',
            "codeql=$CodeQL",
            "command=$CodeQL $($commandArgs -join ' ')"
        ) | Set-Content -LiteralPath $logPath -Encoding UTF8

        $savedErrorActionPreference = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        $output = & $CodeQL @commandArgs 2>&1
        $exitCode = $LASTEXITCODE
        $ErrorActionPreference = $savedErrorActionPreference
        $output | ForEach-Object { Add-LogLine -Path $logPath -Line $_.ToString() }

        if ($exitCode -ne 0) {
            Add-LogLine -Path $logPath -Line "STATUS=FAIL exit_code=$exitCode"
            exit $exitCode
        }

        Copy-Item -LiteralPath $stagingDb -Destination $dbRoot -Recurse -Force
        Add-LogLine -Path $logPath -Line 'STATUS=OK'
        Write-Host "OK $name"
    }
}
catch {
    Write-Error $_
    exit 1
}
