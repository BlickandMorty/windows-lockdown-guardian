[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$ConfigPath,
    [Parameter(Mandatory)][string]$OutputPath
)

. (Join-Path $PSScriptRoot 'Common.ps1')
$config = Read-LockdownConfig -Path $ConfigPath
Assert-PolicyConsistency -Config $config
$domains = Get-PolicyDomains -Config $config
$header = @(
    '# Generated denylist',
    "# Generated: $((Get-Date).ToString('o'))",
    '# This file contains domains only. It never contains a DNS API key or profile ID.',
    ''
)
Write-AtomicUtf8 -Path $OutputPath -Content (($header + $domains) -join "`n")
Write-Host "Exported $($domains.Count) domains to $OutputPath"

