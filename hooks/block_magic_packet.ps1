# Log-only hook. It does not change a firewall.
# The monitor passes one MAC or one private IPv4 address.
param(
    [Parameter(Mandatory = $true)]
    [string]$Target
)

$mac = '^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$'
$ipv4 = '^(?:\d{1,3}\.){3}\d{1,3}$'
if ($Target -notmatch $mac -and $Target -notmatch $ipv4) {
    [Console]::Error.WriteLine("Refusing a target that is not a MAC or an IPv4 address.")
    exit 2
}

Write-Output "[hook] Magic-packet block requested for $Target"
Write-Output "[hook] No firewall change was made. Adapt this script to your own router before it can do anything else."
exit 0
