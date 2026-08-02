[CmdletBinding()]
param(
    [string]$Root = 'C:\ProgramData\CommunityLockdownGuardian',
    [string]$OutputPath
)

$ErrorActionPreference = 'Stop'
$Root = [IO.Path]::GetFullPath([Environment]::ExpandEnvironmentVariables($Root))
. (Join-Path $Root 'Common.ps1')

$config = Read-LockdownConfig -Path (Join-Path $Root 'policy.json')
Assert-PolicyConsistency -Config $config
$domains = Get-PolicyDomains -Config $config
$results = [Collections.Generic.List[object]]::new()

function Add-Check {
    param([string]$Name, [bool]$Passed, [string]$Detail)
    $results.Add([pscustomobject]@{ name = $Name; passed = $Passed; detail = $Detail })
}

$manifestText = Get-Content -LiteralPath (Join-Path $Root 'manifest.json') -Raw
$expectedHmac = (Get-Content -LiteralPath (Join-Path $Root 'manifest.hmac') -Raw).Trim().ToLowerInvariant()
$secret = Unprotect-MachineSecret -ProtectedSecret ([IO.File]::ReadAllBytes((Join-Path $Root 'manifest.secret.protected')))
try { $actualHmac = Get-HmacHex -Key $secret -Text $manifestText }
finally { [Array]::Clear($secret, 0, $secret.Length) }
Add-Check 'Authenticated manifest' ($expectedHmac -eq $actualHmac) 'HMAC-SHA256 over manifest.json'

$manifest = $manifestText | ConvertFrom-Json
foreach ($entry in @($manifest.entries)) {
    $target = Join-Path $Root ([string]$entry.target)
    $baseline = Join-Path $Root ([string]$entry.baseline)
    $ok = (Test-Path -LiteralPath $target) -and (Test-Path -LiteralPath $baseline)
    if ($ok) {
        $ok = (Get-FileSha256 $target) -eq [string]$entry.sha256 -and
              (Get-FileSha256 $baseline) -eq [string]$entry.sha256
    }
    Add-Check "Integrity: $($entry.target)" $ok 'Target and canonical baseline must match the authenticated hash.'
}

$hostsPath = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
$hosts = Get-Content -LiteralPath $hostsPath -Raw
foreach ($domain in $domains) {
    $present = $hosts -match ('(?m)^0\.0\.0\.0\s+' + [regex]::Escape($domain) + '$')
    Add-Check "Hosts: $domain" $present 'Expected exact local block entry.'
}

$patterns = Get-BrowserUrlPatterns -Domains $domains
foreach ($browser in @(
    [pscustomobject]@{ name = 'Chrome'; enabled = [bool]$config.browserPolicy.chrome; path = 'HKLM:\SOFTWARE\Policies\Google\Chrome\URLBlocklist' },
    [pscustomobject]@{ name = 'Edge'; enabled = [bool]$config.browserPolicy.edge; path = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge\URLBlocklist' }
)) {
    if (-not $browser.enabled) { continue }
    $values = if (Test-Path $browser.path) {
        @((Get-ItemProperty $browser.path).PSObject.Properties | Where-Object Name -match '^7\d{3}$' | ForEach-Object { [string]$_.Value })
    } else { @() }
    Add-Check "$($browser.name) managed blocklist" (@($patterns | Where-Object { $_ -notin $values }).Count -eq 0) "$($values.Count) managed entries found."
    Add-Check "$($browser.name) Qobuz invariant" (@($values | Where-Object { $_ -match '(?i)qobuz' }).Count -eq 0) 'Qobuz must not be blocked.'
}

$taskPrefix = [string]$config.installation.taskPrefix
foreach ($taskName in @("$taskPrefix Startup", "$taskPrefix Recurring")) {
    $task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    Add-Check "Scheduled task: $taskName" ($null -ne $task -and $task.State -ne 'Disabled') ($(if ($task) { [string]$task.State } else { 'Missing' }))
}

$report = [ordered]@{
    generatedAt = (Get-Date).ToString('o')
    root = $Root
    passed = @($results | Where-Object passed).Count
    failed = @($results | Where-Object { -not $_.passed }).Count
    checks = @($results)
}
if (-not $OutputPath) {
    $reportRoot = Join-Path $env:TEMP 'CommunityLockdownGuardian-Reports'
    New-Item -ItemType Directory -Path $reportRoot -Force | Out-Null
    $OutputPath = Join-Path $reportRoot ("verification-{0}.json" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
}
Write-JsonReport -Path $OutputPath -Value $report
$report | ConvertTo-Json -Depth 8
if ($report.failed -gt 0) { exit 2 }
