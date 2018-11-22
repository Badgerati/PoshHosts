<#
    .SYNOPSIS
        The hosts commands allows you to control the hosts file

    .DESCRIPTION
        The hosts commands allows you to control the hosts file, by adding/removing entries; as well enabling/disabling them.

        Hosts also supports profiles, so you can have a developer hosts file in your repo and import/merge it for developers.

        You can also test the entries by pinging them, either using the normal ping or by passing specific ports.

    .EXAMPLE
        hosts add 127.0.0.3 dev.test.local

    .EXAMPLE
        hosts export ./local.hosts

    .EXAMPLE
        hosts test *.local 80, 443
#>
function Hosts
{
    param (
        [Parameter(Position=0, Mandatory=$true)]
        [ValidateSet('add', 'backup', 'clear', 'diff', 'disable', 'enable', 'export',
            'import', 'list', 'merge', 'path', 'remove', 'restore', 'set', 'test')]
        [Alias('a')]
        [string]
        $Action, 

        [Parameter(Position=1)]
        [Alias('v1')]
        [string[]]
        $Value1, 

        [Parameter(Position=2)]
        [Alias('v2')]
        [string[]]
        $Value2,

        [Parameter()]
        [Alias('p')]
        [string]
        $HostsPath,

        [Parameter()]
        [Alias('e')]
        [string]
        $Environment
    )

    if (@('diff', 'list', 'path', 'test') -inotcontains $Action) {
        Test-AdminUser
    }

    try {
        $Script:HostsFilePath = $HostsPath
        Invoke-HostsAction -Action $Action -Value1 $Value1 -Value2 $Value2 -Environment $Environment
    }
    finally {
        $Script:HostsFilePath = [string]::Empty
    }
}

# load other functions
$root = Split-Path -Parent -Path $MyInvocation.MyCommand.Path
Get-ChildItem "$($root)\Tools.ps1" | Resolve-Path | ForEach-Object { . $_ }

# Export the Hosts function only
Export-ModuleMember -Function Hosts