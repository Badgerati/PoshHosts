function Invoke-HostsAction
{
    param (
        [Parameter()]
        [string]
        $Action, 

        [Parameter()]
        [string[]]
        $Value1, 

        [Parameter()]
        [string[]]
        $Value2,

        [Parameter()]
        [string]
        $Environment
    )

    switch ($Action.ToLowerInvariant())
    {
        'add' {
            Add-HostsFileEntries -IP (@($Value1) | Select-Object -First 1) -Hostnames $Value2 -Environment $Environment
        }

        'backup' {
            New-HostsFileBackup -Path (@($Value1) | Select-Object -First 1) -Write
        }

        'clear' {
            Clear-HostsFile
        }

        'disable' {
            Disable-HostsFileEntries -Values $Value1 -Environment $Environment
        }

        'diff' {
            Compare-HostsFiles -Path (@($Value1) | Select-Object -First 1)
        }

        'enable' {
            Enable-HostsFileEntries -Values $Value1 -Environment $Environment
        }

        'export' {
            Export-HostsFile -Path (@($Value1) | Select-Object -First 1) -Values $Value2 -Environment $Environment
        }

        'import' {
            Import-HostsFile -Path (@($Value1) | Select-Object -First 1) -Values $Value2 -Environment $Environment
        }

        'list' {
            Get-HostsFile -Values $Value1 -Environment $Environment -State All
        }

        'merge' {
            Merge-HostsFiles -Paths $Value1
        }

        'path' {
            Write-Host "=> $(Get-HostsFilePath)"
        }

        'remove' {
            Remove-HostsFileEntries -Values $Value1 -Environment $Environment
        }

        'restore' {
            Restore-HostsFile -Path (@($Value1) | Select-Object -First 1)
        }

        'set' {
            Set-HostsFileEntries -IP (@($Value1) | Select-Object -First 1) -Hostnames $Value2 -Environment $Environemnt
        }

        'test' {
            Test-HostsFileEntries -Values $Value1 -Ports $Value2 -Environment $Environment
        }
    }
}


function Compare-HostsFiles
{
    param (
        [Parameter(Mandatory=$true)]
        [string]
        $Path
    )

    # ensure the path exists
    if (!(Test-Path $Path)) {
        throw "=> File not found: $($Path)"
    }

    # get the hosts file
    $mainInfo = @{}
    @(Get-HostsFileEntriesByState -HostsMap (@(ConvertFrom-HostsFile)) -State Enabled) | ForEach-Object {
        if (!$mainInfo.ContainsKey($_.IP)) {
            $mainInfo[$_.IP] = @()
        }

        $mainInfo[$_.IP] += $_.Hosts
    }

    # get the other hosts file
    $otherInfo = @{}
    @(Get-HostsFileEntriesByState -HostsMap (@(ConvertFrom-HostsFile -Path $Path)) -State Enabled) | ForEach-Object {
        if (!$otherInfo.ContainsKey($_.IP)) {
            $otherInfo[$_.IP] = @()
        }

        $otherInfo[$_.IP] += $_.Hosts
    }

    # what would be added?
    $otherInfo.Keys | ForEach-Object {
        $_key = $_
        $_hosts = @()

        if ($mainInfo.ContainsKey($_key)) {
            $otherInfo[$_key] | ForEach-Object {
                if ($mainInfo[$_key] -inotcontains $_) {
                    $_hosts += $_
                }
            }
        }
        else {
            $_hosts = @($otherInfo[$_key])
        }

        if (($_hosts | Measure-Object).Count -gt 0) {
            Write-Host "+ [$($_key) - $($_hosts -join ' ')]" -ForegroundColor Green
        }
    }

    # what would be removed?
    $mainInfo.Keys | ForEach-Object {
        $_key = $_
        $_hosts = @()

        if ($otherInfo.ContainsKey($_key)) {
            $mainInfo[$_key] | ForEach-Object {
                if ($otherInfo[$_key] -inotcontains $_) {
                    $_hosts += $_
                }
            }
        }
        else {
            $_hosts = @($mainInfo[$_key])
        }

        if (($_hosts | Measure-Object).Count -gt 0) {
            Write-Host "- [$($_key) - $($_hosts -join ' ')]" -ForegroundColor Red
        }
    }
}

function Remove-HostsFileEntries
{
    param (
        [Parameter()]
        [string[]]
        $Values,

        [Parameter()]
        [string]
        $Environment
    )

    $info = @(ConvertFrom-HostsFile)

    @(Set-DefaultValueAll -Values $Values) | ForEach-Object {
        $_value = $_
        $_entries = @(Get-HostsFileEntries -HostsMap $info -IP $_value -Environment $Environment -Hostname $_value -State All -Like)

        if (($_entries | Measure-Object).Count -eq 0) {
            Write-Host "=> Already removed: [$($_value)] {$(Resolve-HostsEnvironment -Environment $Environment)}" -ForegroundColor Cyan
        }
        else {
            $_entries | ForEach-Object {
                $_entry = $_
                @(Get-HostsFileEntryHosts -Entry $_entry -Value $_value) | ForEach-Object {
                    $info = Remove-HostsFileEntry -HostsMap $info -IP $_entry.IP -Hostname $_ -Environment $Environment
                }
            }
        }
    }

    # write back to hosts file
    Out-HostsFile -HostsMap $info
}

function Enable-HostsFileEntries
{
    param (
        [Parameter()]
        [string[]]
        $Values,

        [Parameter()]
        [string]
        $Environment
    )

    $info = @(ConvertFrom-HostsFile)

    @(Set-DefaultValueAll -Values $Values) | ForEach-Object {
        $_value = $_
        $_entries = @(Get-HostsFileEntries -HostsMap $info -IP $_value -Hostname $_value -Environment $Environment -State Disabled -Like)

        if (($_entries | Measure-Object).Count -eq 0) {
            Write-Host "=> Already enabled: [$($_value)] {$(Resolve-HostsEnvironment -Environment $Environment)}" -ForegroundColor Cyan
        }
        else {
            $_entries | ForEach-Object {
                $_entry = $_
                @(Get-HostsFileEntryHosts -Entry $_entry -Value $_value) | ForEach-Object {
                    $info = Add-HostsFileEntry -HostsMap $info -IP $_entry.IP -Hostname $_ -Environment $Environment
                }
            }
        }
    }

    # write back to hosts file
    Out-HostsFile -HostsMap $info
}

function Disable-HostsFileEntries
{
    param (
        [Parameter()]
        [string[]]
        $Values,

        [Parameter()]
        [string]
        $Environment
    )

    $info = @(ConvertFrom-HostsFile)

    @(Set-DefaultValueAll -Values $Values) | ForEach-Object {
        $_value = $_
        $_entries = @(Get-HostsFileEntries -HostsMap $info -IP $_value -Hostname $_value -Environment $Environment -State Enabled -Like)

        if (($_entries | Measure-Object).Count -eq 0) {
            Write-Host "=> Already disabled: [$($_value)] {$(Resolve-HostsEnvironment -Environment $Environment)}" -ForegroundColor Cyan
        }
        else {
            $_entries | ForEach-Object {
                $_entry = $_
                @(Get-HostsFileEntryHosts -Entry $_entry -Value $_value) | ForEach-Object {
                    $info = Disable-HostsFileEntry -HostsMap $info -IP $_entry.IP -Hostname $_ -Environment $Environment
                }
            }
        }
    }

    # write back to hosts file
    Out-HostsFile -HostsMap $info
}

function Test-HostsFileEntries
{
    param (
        [Parameter()]
        [string[]]
        $Values,

        [Parameter()]
        [string[]]
        $Ports,

        [Parameter()]
        [string]
        $Environment
    )

    # do we have any ports?
    $hasPorts = (($Ports | Measure-Object).Count -gt 0)

    # grab all enabled entries in the hosts file for the value passed
    @(Get-HostsFile -Values $Values -Environment $Environment -State Enabled) | ForEach-Object {
        $_ip = $_.IP
        $_name = ($_.Hosts | Select-Object -First 1)

        # either ping the host, or test a specific port
        if (!$hasPorts) {
            Test-HostsFileEntry -IP $_ip -Hostname $_name
        }
        else {
            $Ports | ForEach-Object {
                Test-HostsFileEntry -IP $_ip -Hostname $_name -Port $_
            }
        }
    }
}

function Add-HostsFileEntries
{
    param (
        [Parameter(Mandatory=$true)]
        [string]
        $IP,

        [Parameter(Mandatory=$true)]
        [string[]]
        $Hostnames,

        [Parameter()]
        [string]
        $Environment
    )

    # get the hosts file
    $info = @(ConvertFrom-HostsFile)

    # loop through each hostname and add it
    $Hostnames | ForEach-Object {
        $info = Add-HostsFileEntry -HostsMap $info -IP $IP -Hostname $_ -Environment $Environment
    }

    # write back to hosts file
    Out-HostsFile -HostsMap $info
}

function Set-HostsFileEntries
{
    param (
        [Parameter(Mandatory=$true)]
        [string]
        $IP,

        [Parameter(Mandatory=$true)]
        [string[]]
        $Hostnames,

        [Parameter()]
        [string]
        $Environment
    )

    # get the hosts file
    $info = @(ConvertFrom-HostsFile)

    # reset hosts for all the entries for the IP
    $entries = @(Get-HostsFileEntry -HostsMap $info -Value $IP -Type IP -Environment $Environment -State Enabled)
    if (($entries | Measure-Object).Count -eq 0) {
        $info += (Get-HostsFileEntryObject -IP $IP -Hostnames @() -Environment $Environment -Enabled $true)
    }
    else {
        $entries | ForEach-Object {
            $_.Hosts = @()
            $_.Environment = (Resolve-HostsEnvironment -Environment $Environment -Current $_.Environment)
        }
    }

    # loop through each hostname and add it
    $Hostnames | ForEach-Object {
        $info = Add-HostsFileEntry -HostsMap $info -IP $IP -Hostname $_ -Environment $Environment
    }

    # write back to hosts file
    Out-HostsFile -HostsMap $info
}

function Clear-HostsFile
{
    # empty the hosts file
    Out-HostsFile -Content ([string]::Empty) -Message 'Hosts file cleared'
}

function Restore-HostsFile
{
    param (
        [Parameter()]
        [string]
        $Path
    )

    try {
        $details = Get-HostsFileBackupDetails -BackupPath $Path

        if (!(Test-Path $details.Backup.Path)) {
            throw "=> No $($details.Backup.Name) file found"
        }

        Copy-Item -Path $details.Backup.Path -Destination $details.Hosts.Path -Force | Out-Null
        Write-Host "=> Restored hosts file from $($details.Backup.Name)" -ForegroundColor Green
    }
    catch {
        Write-Host "=> Failed to restore hosts files from $($details.Backup.Name)" -ForegroundColor Red
    }
}

function Merge-HostsFiles
{
    param (
        [Parameter(Mandatory=$true)]
        [string[]]
        $Paths
    )

    # ensure the paths exist
    $Paths | ForEach-Object {
        if (!(Test-Path $_)) {
            throw "=> File not found: $($_)"
        }
    }

    # get the hosts file
    $info = @(ConvertFrom-HostsFile)

    # loop through each merge path, parsing and importing them
    $Paths | ForEach-Object {
        $_path = $_

        # loop through each entry in the file
        @(ConvertFrom-HostsFile -Path $_path) | ForEach-Object {
            $_entry = $_

            # and now loop through each host, removing any occurrences from base file
            $_entry.Hosts | ForEach-Object {
                $_host = $_

                # if the host exists in the base file against a different IP, then remove it
                Get-HostsFileEntry -HostsMap $info -Value $_host -Type Hostname -State Enabled | ForEach-Object {
                    if ($_.IP -ine $_entry.IP) {
                        $_.Hosts = @($_.Hosts | Where-Object { $_ -ine $_host })
                    }
                }

                # call either add or disable on IP+host
                if ($_entry.Enabled) {
                    $info = Add-HostsFileEntry -HostsMap $info -IP $_entry.IP -Hostname $_host -Environment $_entry.Environment
                }
                else {
                    $info = Disable-HostsFileEntry -HostsMap $info -IP $_entry.IP -Hostname $_host -Environment $_entry.Environment
                }
            }
        }
    }

    # write back to hosts file
    Out-HostsFile -HostsMap $info
}

function Import-HostsFile
{
    param (
        [Parameter(Mandatory=$true)]
        [string]
        $Path,

        [Parameter()]
        [string[]]
        $Values,

        [Parameter()]
        [string]
        $Environment
    )

    # ensure the path exists
    if (!(Test-Path $Path)) {
        throw "=> File not found: $($Path)"
    }

    # store the main hosts file path
    $_HostsPathTmp = $Script:HostsFilePath

    # get the relevant entries
    $Script:HostsFilePath = $Path
    $info = Get-HostsFile -Values $Values -Environment $Environment -State All

    # write back to main hosts file
    $Script:HostsFilePath = $_HostsPathTmp
    Out-HostsFile -HostsMap $info -Message "Hosts file imported from: $($Path)"
}

function Export-HostsFile
{
    param (
        [Parameter(Mandatory=$true)]
        [string]
        $Path,

        [Parameter()]
        [string[]]
        $Values,

        [Parameter()]
        [string]
        $Environment
    )

    # get the relevant entries
    $info = Get-HostsFile -Values $Values -Environment $Environment -State All

    # write to export location
    $Script:HostsFilePath = $Path
    Out-HostsFile -HostsMap $info -Message "Hosts file exported to: $($Path)"
}

function Get-HostsFile
{
    param (
        [Parameter()]
        [string[]]
        $Values,

        [Parameter()]
        [string]
        $Environment,

        [Parameter()]
        [ValidateSet('All', 'Disabled', 'Enabled')]
        [string]
        $State
    )

    $info = @(ConvertFrom-HostsFile)
    $results = @()

    # filter by environment
    $info = @(Get-HostsFileEntriesByEnvironment -HostsMap $info -Environment $Environment)

    # filter by values
    if (($Values | Measure-Object).Count -eq 0) {
        $results = $info
    }
    else {
        $Values | ForEach-Object {
            @(Get-HostsFileEntries -HostsMap $info -IP $_ -Hostname $_ -State $State -Like) | ForEach-Object {
                $_tmp = $_
                if (($results | Where-Object { $_.Hash -eq $_tmp.Hash } | Measure-Object).Count -eq 0) {
                    $results += $_tmp
                }
            }
        }
    }

    return ($results | Select-Object IP, Hosts, Environment, Enabled)
}


function New-HostsFileBackup
{
    param (
        [Parameter()]
        [string]
        $Path,

        [switch]
        $Write
    )

    $details = Get-HostsFileBackupDetails -BackupPath $Path

    # if a backup exists, back that up temporarily
    if (Test-Path $details.Backup.Path) {
        Copy-Item -Path $details.Backup.Path -Destination $details.Backup.Temp -Force | Out-Null
    }

    # backup the hosts file
    if (Test-Path $details.Hosts.Path) {
        Copy-Item -Path $details.Hosts.Path -Destination $details.Backup.Path -Force | Out-Null
    }

    # remove tmp backup
    if (Test-Path $details.Backup.Temp) {
        Remove-Item -Path $details.Backup.Temp -Force | Out-Null
    }

    if ($Write) {
        Write-Host "=> Hosts file backed up to $($details.Backup.Name)" -ForegroundColor Green
    }
}

function Get-HostsFileBackupDetails
{
    param (
        [Parameter()]
        [string]
        $BackupPath
    )

    $path = Get-HostsFilePath

    if ([string]::IsNullOrWhiteSpace($BackupPath)) {
        $basepath = Split-Path -Parent -Path $path
        if ([string]::IsNullOrWhiteSpace($basepath)) {
            $basepath = '.'
        }

        $backup = Join-Path $basepath "$(Split-Path -Leaf -Path $path).bak"
    }
    else {
        $backup = $BackupPath
    }

    return @{
        'Hosts' = @{
            'Path' = $path;
            'Name' = (Split-Path -Leaf -Path $path);
        };
        'Backup' = @{
            'Path' = $backup;
            'Name' = (Split-Path -Leaf -Path $backup);
            'Temp' = "$($backup).tmp";
        };
    }
}

function Set-DefaultValueAll
{
    param (
        [Parameter()]
        [string[]]
        $Values
    )

    if (($Values | Measure-Object).Count -eq 0) {
        return @('*')
    }

    return @($Values)
}

function Test-AdminUser
{
    # check the current platform, if it's unix then return true
    if (Test-IsUnix) {
        return
    }

    try {
        $principal = New-Object System.Security.Principal.WindowsPrincipal([System.Security.Principal.WindowsIdentity]::GetCurrent())

        if ($null -eq $principal) {
            $admin = $false
        }
        else {
            $admin = $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
        }
    }
    catch [exception] {
        Write-Host 'Error checking user administrator priviledges' -ForegroundColor Red
        Write-Host $_.Exception.Message -ForegroundColor Red
        $admin = $false
    }

    if (!$admin) {
        throw 'Must be running with administrator priviledges to use the hosts command'
    }
}

function Get-PSVersionTable
{
    return $PSVersionTable
}

function Test-IsUnix
{
    return (Get-PSVersionTable).Platform -ieq 'unix'
}

function Get-HostsFilePath
{
    # custom path
    if (![string]::IsNullOrWhiteSpace($Script:HostsFilePath)) {
        return $Script:HostsFilePath
    }

    # unix
    if (Test-IsUnix) {
        return '/etc/hosts'
    }

    # windows is default
    return "$($env:windir)\System32\drivers\etc\hosts"
}

function Get-HostsIPRegex
{
    return "(?<ip>(\[[a-z0-9\:]+\]|((\d+\.){3}\d+)|\:\:\d+))"
}

function Get-HostsNameRegex
{
    return "(?<hosts>((([a-z0-9]|[a-z0-9][a-z0-9\-]*[a-z0-9])\.)*([a-z0-9]|[a-z0-9][a-z0-9\-]*[a-z0-9])\s*)+)"
}

function ConvertFrom-HostsFile
{
    param (
        [Parameter()]
        [string]
        $Path
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        $Path = Get-HostsFilePath
    }

    $map = @()
    $currentEnv = [string]::Empty

    # if the path doesn't exist, just return
    if (!(Test-Path $Path)) {
        return $map
    }

    # parse the file
    (Get-Content $Path) | ForEach-Object {
        # check if it's an environment start tag
        if ($_ -imatch "^\s*\#\s*\<--\s*(?<name>[a-z0-9\-]+)\s*$") {
            $currentEnv = $Matches['name']
        }

        # check if it's an environment end tag
        elseif ($_ -imatch "^\s*\#\s*--\>\s*$") {
            $currentEnv = [string]::Empty
        }

        # check if it's a host entry
        elseif ($_ -imatch "^\s*(?<enabled>[\#]{0,1})\s*$(Get-HostsIPRegex)\s+$(Get-HostsNameRegex)\s*$") {
            $map += (Get-HostsFileEntryObject `
                -IP ($Matches['ip'].Trim()) `
                -Hostnames @($Matches['hosts'].Trim() -isplit '\s+') `
                -Environment $currentEnv `
                -Enabled ([string]::IsNullOrWhiteSpace($Matches['enabled'])))
        }
    }

    $map = Update-HostsFileObject -HostsMap $map
    return $map
}

function Get-HostsFileEntryObject
{
    param (
        [Parameter(Mandatory=$true)]
        [string]
        $IP,

        [Parameter()]
        [string[]]
        $Hostnames,

        [Parameter()]
        [string]
        $Environment,

        [Parameter()]
        [bool]
        $Enabled
    )

    return (New-Object -TypeName psobject |
        Add-Member -MemberType NoteProperty -Name IP -Value $IP -PassThru |
        Add-Member -MemberType NoteProperty -Name Hosts $Hostnames -PassThru |
        Add-Member -MemberType NoteProperty -Name Environment -Value (Resolve-HostsEnvironment -Environment $Environment) -PassThru |
        Add-Member -MemberType NoteProperty -Name Enabled -Value $Enabled -PassThru |
        Add-Member -MemberType NoteProperty -Name Hash -Value ([string]::Empty) -PassThru)
}

function Resolve-HostsEnvironment
{
    param (
        [Parameter()]
        [string]
        $Environment,

        [Parameter()]
        [string]
        $Current
    )

    # default empty env to None
    if ([string]::IsNullOrWhiteSpace($Environment)) {
        $Environment = 'None'
    }

    # if no current env passed, just return the env
    if ([string]::IsNullOrWhiteSpace($Current)) {
        return $Environment
    }

    # if current env is not None, return current if env is also None
    if ($Current -ine 'None' -and $Environment -ieq 'None') {
        return $Current
    }

    return $Environment
}

function Update-HostsFileObject
{
    param (
        [Parameter()]
        $HostsMap
    )

    $crypto = [System.Security.Cryptography.SHA256]::Create()

    $HostsMap | ForEach-Object {
        $str = "$($_.IP)|$($_.Hosts -join '|')|$($_.Environment)"
        $_.Hash = [System.Convert]::ToBase64String($crypto.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($str)))
    }

    return $HostsMap
}

function ConvertTo-HostsFile
{
    param (
        [Parameter()]
        $HostsMap
    )

    $str = [string]::Empty
    $nl = [Environment]::NewLine

    # if there are no entries, then it's empty
    if (($HostsMap | Measure-Object).Count -eq 0) {
        return $str
    }

    # get each of the environments
    $HostsMap | Select-Object -ExpandProperty Environment | Group-Object | ForEach-Object {
        $_env = $_.Name
        $str += "#<-- $($_env)$($nl)"

        # loop through each one, forming each entry line
        $HostsMap | Where-Object { $_.Environment -ieq $_env } | ForEach-Object {
            if ($null -ne $_ -and ![string]::IsNullOrWhiteSpace($_.IP) -and ($_.Hosts | Measure-Object).Count -gt 0) {
                if (!$_.Enabled) {
                    $str += '# '
                }

                $str += "$($_.IP)`t$($_.Hosts -join ' ')$($nl)"
            }
        }

        $str += "#-->$($nl)$($nl)"
    }

    return $str
}

function Get-HostsFileEntriesByEnvironment
{
    param (
        [Parameter()]
        [object[]]
        $HostsMap,

        [Parameter()]
        [string]
        $Environment
    )

    if ([string]::IsNullOrWhiteSpace($Environment)) {
        return $HostsMap
    }

    return @($HostsMap | Where-Object { $_.Environment -ieq $Environment })
}

function Get-HostsFileEntry
{
    param (
        [Parameter()]
        [object[]]
        $HostsMap,

        [Parameter()]
        [string]
        $Value,

        [Parameter()]
        [ValidateSet('IP', 'Hostname')]
        [string]
        $Type,

        [Parameter()]
        [ValidateSet('All', 'Disabled', 'Enabled')]
        [string]
        $State,

        [Parameter()]
        [string]
        $Environment
    )

    $HostsMap = @(Get-HostsFileEntriesByEnvironment -HostsMap $HostsMap -Environment $Environment)

    switch ($Type.ToLowerInvariant())
    {
        'IP' {
            $HostsMap = @($HostsMap | Where-Object { $_.IP -ieq $Value })
        }

        'Hostname' {
            $HostsMap = @($HostsMap | Where-Object { $_.Hosts -icontains $Value })
        }
    }

    return @(Get-HostsFileEntriesByState -HostsMap $HostsMap -State $State)
}

function Get-HostsFileEntryHosts
{
    param (
        [Parameter()]
        [object]
        $Entry,

        [Parameter()]
        [string]
        $Value
    )

    if ($Entry.IP -ilike $Value) {
        return @($Entry.Hosts)
    }

    $hosts = @()

    $Entry.Hosts | Where-Object {
        if ($_ -ilike $Value) {
            $hosts += $_
        }
    }

    return @($hosts)
}

function Get-HostsFileEntriesByState
{
    param (
        [Parameter()]
        [object[]]
        $HostsMap,

        [Parameter()]
        [ValidateSet('All', 'Disabled', 'Enabled')]
        [string]
        $State
    )

    switch ($State.ToLowerInvariant())
    {
        'disabled' {
            $HostsMap = @($HostsMap | Where-Object { !$_.Enabled })
        }

        'enabled' {
            $HostsMap = @($HostsMap | Where-Object { $_.Enabled })
        }
    }

    return @($HostsMap)
}

function Test-HostnameAgainstDifferentIP
{
    param (
        [Parameter()]
        [object[]]
        $HostsMap,

        [Parameter(Mandatory=$true)]
        [string]
        $IP,

        [Parameter(Mandatory=$true)]
        [string]
        $Hostname,

        [switch]
        $Throw
    )

    $h = (Get-HostsFileEntry -HostsMap $HostsMap -Value $Hostname -Type Hostname -State Enabled | Select-Object -First 1)
    $bound = ($null -ne $h -and $h.IP -ine $IP)

    if ($Throw -and $bound) {
        throw "=> The hostname [$($Hostname)] is bound against a different IP address: [$($h.IP)]"
    }

    return $bound
}

function Get-IPHostString
{
    param (
        [Parameter(Mandatory=$true)]
        [string]
        $IP,

        [Parameter(Mandatory=$true)]
        [string]
        $Hostname,

        [Parameter()]
        [string]
        $Environment
    )

    return "[$($IP) - $($Hostname)] {$(Resolve-HostsEnvironment -Environment $Environment)}"
}

function Remove-HostsFileEntry
{
    param (
        [Parameter()]
        [object[]]
        $HostsMap,

        [Parameter(Mandatory=$true)]
        [string]
        $IP,

        [Parameter(Mandatory=$true)]
        [string]
        $Hostname,

        [Parameter()]
        [string]
        $Environment
    )

    # get entries
    $entries = @(Get-HostsFileEntries -HostsMap $HostsMap -IP $IP -Hostname $Hostname -State All)

    # skip if already removed
    if (($entries | Measure-Object).Count -eq 0) {
        Write-Host "=> Already removed $(Get-IPHostString $IP $Hostname $Environment)" -ForegroundColor Cyan
        return $HostsMap
    }

    # remove hostname from that entries
    $entries | ForEach-Object {
        $_.Hosts = @($_.Hosts | Where-Object { $_ -ine $Hostname })
        $_.Environment = (Resolve-HostsEnvironment -Environment $Environment -Current $_.Environment)
    }

    Write-Host "=> Removing $(Get-IPHostString $IP $Hostname $entries[0].Environment)"
    return $HostsMap
}

function Disable-HostsFileEntry
{
    param (
        [Parameter()]
        [object[]]
        $HostsMap,

        [Parameter(Mandatory=$true)]
        [string]
        $IP,

        [Parameter(Mandatory=$true)]
        [string]
        $Hostname,

        [Parameter()]
        [string]
        $Environment
    )

    # see if there's an enabled entry, and remove hostname from that entry
    Get-HostsFileEntries -HostsMap $HostsMap -IP $IP -Hostname $Hostname -State Enabled | ForEach-Object {
        $_.Hosts = @($_.Hosts | Where-Object { $_ -ine $Hostname })
    }

    # skip if already disabled
    $entries = @(Get-HostsFileEntries -HostsMap $HostsMap -IP $IP -Hostname $Hostname -State Disabled)
    if (($entries | Measure-Object).Count -gt 0) {
        Write-Host "=> Already disabled $(Get-IPHostString $IP $Hostname $Environment)" -ForegroundColor Cyan

        $entries | ForEach-Object {
            $_.Environment = (Resolve-HostsEnvironment -Environment $Environment -Current $_.Environment)
        }

        return $HostsMap
    }

    # disable IP+Hostname
    $entry = (Get-HostsFileEntry -HostsMap $HostsMap -Value $IP -Type IP -State Disabled | Select-Object -First 1)
    if ($null -eq $entry) {
        $entry = (Get-HostsFileEntryObject -IP $IP -Hostnames @($Hostname) -Environment $Environment -Enabled $false)
        $HostsMap += $entry
    }
    else {
        $entry.Hosts = @($entry.Hosts) + $Hostname
        $entry.Environment = (Resolve-HostsEnvironment -Environment $Environment -Current $entry.Environment)
    }

    Write-Host "=> Disabling $(Get-IPHostString $IP $Hostname $entry.Environment)"
    return $HostsMap
}

function Add-HostsFileEntry
{
    param (
        [Parameter()]
        [object[]]
        $HostsMap,

        [Parameter(Mandatory=$true)]
        [string]
        $IP,

        [Parameter(Mandatory=$true)]
        [string]
        $Hostname,

        [Parameter()]
        [string]
        $Environment
    )

    # is the host being added, or enabled from previously being diabled?
    $enabling = $false

    # fail if the hostname or IP address are invalid
    if ($IP -inotmatch "^$(Get-HostsIPRegex)$") {
        throw "=> The IP address [$($IP)] is invalid"
    }

    if ($Hostname -inotmatch "^$(Get-HostsNameRegex)$") {
        throw "=> The hostname [$($Hostname)] is invalid"
    }

    # fail if the hostname is found against a different IP
    Test-HostnameAgainstDifferentIP -HostsMap $HostsMap -IP $IP -Hostname $Hostname -Throw | Out-Null

    # see if there's a disabled entry, and remove hostname from that entry
    Get-HostsFileEntries -HostsMap $HostsMap -IP $IP -Hostname $Hostname -State Disabled | ForEach-Object {
        $enabling = $true
        $_.Hosts = @($_.Hosts | Where-Object { $_ -ine $Hostname })
    }

    # skip if already added/enabled
    $entries = @(Get-HostsFileEntries -HostsMap $HostsMap -IP $IP -Hostname $Hostname -State Enabled)
    if (($entries | Measure-Object).Count -gt 0) {
        Write-Host "=> Already $(if ($enabling) { 'enabled' } else { 'added' }) [$($IP) - $($Hostname)]" -ForegroundColor Cyan

        $entries | ForEach-Object {
            $_.Environment = (Resolve-HostsEnvironment -Environment $Environment -Current $_.Environment)
        }

        return $HostsMap
    }

    # add IP+Hostname
    $entry = (Get-HostsFileEntry -HostsMap $HostsMap -Value $IP -Type IP -State Enabled | Select-Object -First 1)
    if ($null -eq $entry) {
        $entry = (Get-HostsFileEntryObject -IP $IP -Hostnames @($Hostname) -Environment $Environment -Enabled $true)
        $HostsMap += $entry
    }
    else {
        $entry.Hosts = @($entry.Hosts) + $Hostname
        $entry.Environment = (Resolve-HostsEnvironment -Environment $Environment -Current $entry.Environment)
    }

    Write-Host "=> $(if ($enabling) { 'Enabling' } else { 'Adding' }) $(Get-IPHostString $IP $Hostname $entry.Environment)"
    return $HostsMap
}

function Get-HostsFileEntries
{
    param (
        [Parameter()]
        [object[]]
        $HostsMap,

        [Parameter()]
        [string]
        $IP,

        [Parameter()]
        [string]
        $Hostname,

        [Parameter()]
        [string]
        $Environment,

        [Parameter()]
        [ValidateSet('All', 'Disabled', 'Enabled')]
        [string]
        $State,

        [switch]
        $Like
    )

    $HostsMap = @(Get-HostsFileEntriesByEnvironment -HostsMap $HostsMap -Environment $Environment)

    $HostsMap = @($HostsMap | Where-Object {
        if ($Like) {
            $_.IP -ilike $IP -or ($_.Hosts | Where-Object { $_ -ilike $Hostname } | Measure-Object).Count -ne 0 
        }
        else {
            $_.IP -ilike $IP -and ($_.Hosts | Where-Object { $_ -ilike $Hostname } | Measure-Object).Count -ne 0 
        }
    })

    return @(Get-HostsFileEntriesByState -HostsMap $HostsMap -State $State)
}

function Out-HostsFile
{
    param (
        [Parameter()]
        [object[]]
        $HostsMap,

        [Parameter()]
        [string]
        $Content,

        [Parameter()]
        [string]
        $Path,

        [Parameter()]
        [string]
        $Message
    )

    # create backup of current
    New-HostsFileBackup

    # set an appropriate output message
    if ([string]::IsNullOrWhiteSpace($Message)) {
        $Message = 'Hosts file updated'
    }

    # write out to hosts file
    try {
        $hosts_path = Get-HostsFilePath
        New-HostsFilePath -Path (Split-Path -Parent -Path $hosts_path)

        if ([string]::IsNullOrWhiteSpace($Path)) {
            if (($HostsMap | Measure-Object).Count -gt 0) {
                $Content = ConvertTo-HostsFile -HostsMap $HostsMap
            }

            $Content | Out-File -FilePath $hosts_path -Encoding utf8 -Force -ErrorAction Stop | Out-Null
        }
        else {
            Copy-Item -Path $Path -Destination $hosts_path -Force -ErrorAction Stop | Out-Null
        }

        Write-Host "=> $($Message)" -ForegroundColor Green
    }
    catch {
        Restore-HostsFile
        throw $_.Exception
    }
}

function New-HostsFilePath
{
    param (
        [Parameter()]
        [string]
        $Path
    )

    if (!(Test-Path $Path)) {
        New-Item -Path $Path -ItemType Directory -Force | Out-Null
    }
}

function Test-HostsFileEntry
{
    param (
        [Parameter()]
        [string]
        $IP,

        [Parameter()]
        [string]
        $Hostname,

        [Parameter()]
        [string]
        $Port
    )

    # either ping the host, or test a specific port
    if ([string]::IsNullOrWhiteSpace($Port)) {
        Write-Host "=> Testing $($Hostname)>" -NoNewline
        $result = Test-NetConnection -ComputerName $IP -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
    }
    else {
        Write-Host "=> Testing $($Hostname):$($Port)>" -NoNewline
        $result = Test-NetConnection -ComputerName $IP -Port $Port -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
    }

    # was the test successful or a failure?
    if ($null -eq $result -or (!$result.PingSucceeded -and !$result.TcpTestSucceeded)) {
        Write-Host "`tFailed" -ForegroundColor Red
    }
    else {
        Write-Host "`tSuccess" -ForegroundColor Green
    }
}