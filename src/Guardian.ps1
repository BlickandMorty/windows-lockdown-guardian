[CmdletBinding()]
param(
    [ValidateSet('Once', 'Loop')][string]$Mode = 'Once',
    [string]$Root,
    [int]$LoopSeconds = 30
)

$ErrorActionPreference = 'Stop'
$Root = if ($Root) { [IO.Path]::GetFullPath($Root) } else { [IO.Path]::GetFullPath($PSScriptRoot) }
. (Join-Path $Root 'Common.ps1')

function Write-GuardianLog {
    param([string]$Message, [string]$Level = 'INFO')
    $logRoot = Join-Path $Root 'Logs'
    New-Item -ItemType Directory -Path $logRoot -Force | Out-Null
    Add-Content -LiteralPath (Join-Path $logRoot 'guardian.log') -Value (
        '[{0}] [{1}] {2}' -f (Get-Date).ToString('o'), $Level, $Message
    )
}

function Get-ValidatedManifest {
    $manifestPath = Join-Path $Root 'manifest.json'
    $hmacPath = Join-Path $Root 'manifest.hmac'
    $secretPath = Join-Path $Root 'manifest.secret.protected'
    foreach ($path in @($manifestPath, $hmacPath, $secretPath)) {
        if (-not (Test-Path -LiteralPath $path)) { throw "Integrity artifact missing: $path" }
    }
    $manifestText = Get-Content -LiteralPath $manifestPath -Raw
    $expected = (Get-Content -LiteralPath $hmacPath -Raw).Trim().ToLowerInvariant()
    $secret = Unprotect-MachineSecret -ProtectedSecret ([IO.File]::ReadAllBytes($secretPath))
    try { $actual = Get-HmacHex -Key $secret -Text $manifestText }
    finally { [Array]::Clear($secret, 0, $secret.Length) }
    if ($actual -ne $expected) { throw 'Integrity manifest authentication failed.' }
    $manifestText | ConvertFrom-Json
}

function Repair-InstalledArtifacts {
    $manifest = Get-ValidatedManifest
    foreach ($entry in @($manifest.entries)) {
        $target = Join-Path $Root ([string]$entry.target)
        $baseline = Join-Path $Root ([string]$entry.baseline)
        if (-not (Test-Path -LiteralPath $baseline)) { throw "Baseline missing: $baseline" }
        if ((Get-FileSha256 $baseline) -ne [string]$entry.sha256) {
            throw "Baseline hash mismatch: $baseline"
        }
        $needsRepair = -not (Test-Path -LiteralPath $target)
        if (-not $needsRepair) { $needsRepair = (Get-FileSha256 $target) -ne [string]$entry.sha256 }
        if ($needsRepair) {
            Copy-Item -LiteralPath $baseline -Destination $target -Force
            Write-GuardianLog "Repaired installed artifact: $($entry.target)" 'WARN'
        }
    }
}

function Set-HostsPolicy {
    param([Parameter(Mandatory)][string[]]$Domains)

    $path = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
    $begin = '# BEGIN COMMUNITY LOCKDOWN GUARDIAN'
    $end = '# END COMMUNITY LOCKDOWN GUARDIAN'
    $content = Get-Content -LiteralPath $path -Raw
    $pattern = '(?ms)^' + [regex]::Escape($begin) + '.*?^' + [regex]::Escape($end) + '\s*'
    $content = [regex]::Replace($content, $pattern, '').TrimEnd()
    $block = @($begin)
    foreach ($domain in $Domains) {
        $block += "0.0.0.0 $domain"
        $block += "0.0.0.0 www.$domain"
    }
    $block += $end
    Write-AtomicUtf8 -Path $path -Content ($content + "`r`n`r`n" + ($block -join "`r`n") + "`r`n")
}

function Set-BrowserPolicy {
    param([Parameter(Mandatory)]$Config, [Parameter(Mandatory)][string[]]$Domains)

    $patterns = Get-BrowserUrlPatterns -Domains $Domains
    $targets = @()
    if ($Config.browserPolicy.chrome) { $targets += 'HKLM:\SOFTWARE\Policies\Google\Chrome\URLBlocklist' }
    if ($Config.browserPolicy.edge) { $targets += 'HKLM:\SOFTWARE\Policies\Microsoft\Edge\URLBlocklist' }
    foreach ($path in $targets) {
        New-Item -Path $path -Force | Out-Null
        Get-ItemProperty -Path $path | ForEach-Object {
            $_.PSObject.Properties | Where-Object { $_.Name -match '^7\d{3}$' } | ForEach-Object {
                Remove-ItemProperty -Path $path -Name $_.Name -ErrorAction SilentlyContinue
            }
        }
        for ($index = 0; $index -lt $patterns.Count; $index++) {
            New-ItemProperty -Path $path -Name (7000 + $index) -Value $patterns[$index] -PropertyType String -Force | Out-Null
        }
    }
}

function Set-ExecutablePolicy {
    param([string[]]$ExecutableNames)

    $policy = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
    $list = Join-Path $policy 'DisallowRun'
    New-Item -Path $list -Force | Out-Null
    New-ItemProperty -Path $policy -Name DisallowRun -Value 1 -PropertyType DWord -Force | Out-Null
    Get-ItemProperty -Path $list | ForEach-Object {
        $_.PSObject.Properties | Where-Object { $_.Name -match '^7\d{3}$' } | ForEach-Object {
            Remove-ItemProperty -Path $list -Name $_.Name -ErrorAction SilentlyContinue
        }
    }
    $names = @($ExecutableNames | ForEach-Object { [IO.Path]::GetFileName(([string]$_).Trim()) } | Where-Object { $_ } | Sort-Object -Unique)
    for ($index = 0; $index -lt $names.Count; $index++) {
        New-ItemProperty -Path $list -Name (7000 + $index) -Value $names[$index] -PropertyType String -Force | Out-Null
    }
}

function Invoke-GuardianPass {
    Assert-Administrator
    Repair-InstalledArtifacts
    $config = Read-LockdownConfig -Path (Join-Path $Root 'policy.json')
    Assert-PolicyConsistency -Config $config
    $domains = Get-PolicyDomains -Config $config
    Set-HostsPolicy -Domains $domains
    Set-BrowserPolicy -Config $config -Domains $domains
    Set-ExecutablePolicy -ExecutableNames @($config.blockedExecutables)
    Clear-DnsClientCache -ErrorAction SilentlyContinue
    Write-GuardianLog "Policy applied: $($domains.Count) domains, $(@($config.blockedExecutables).Count) executable names."
}

do {
    try { Invoke-GuardianPass }
    catch {
        Write-GuardianLog $_.Exception.Message 'ERROR'
        if ($Mode -eq 'Once') { throw }
    }
    if ($Mode -eq 'Loop') { Start-Sleep -Seconds ([Math]::Max(10, $LoopSeconds)) }
} while ($Mode -eq 'Loop')

