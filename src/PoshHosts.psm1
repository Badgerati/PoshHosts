function Hosts
{
    param (
        [Parameter(Mandatory=$true)]
        [ValidateSet('add', 'backup', 'clear', 'disable', 'enable', 'export', 'import',
            'list', 'merge', 'path', 'remove', 'restore', 'set', 'test')]
        [string]
        $Action, 

        [Parameter()]
        [string[]]
        $Value1, 

        [Parameter()]
        [string[]]
        $Value2
    )

    if (@('list', 'path') -inotcontains $Action) {
        Test-AdminUser
    }

    switch ($Action.ToLowerInvariant())
    {
        'add' {
            Add-HostsFileEntries -IP (@($Value1) | Select-Object -First 1) -Hostnames $Value2
        }

        'backup' {
            New-HostsFileBackup -Path (@($Value1) | Select-Object -First 1) -Write
        }

        'clear' {
            Clear-HostsFile
        }

        'disable' {
            throw 'Not yet supported'
            #Disable-HostFileEntries -Values $Value1
        }

        'enable' {
            throw 'Not yet supported'
            #Enable-HostFileEntries -Values $Value1
        }

        'export' {
            Export-HostsFile -Path (@($Value1) | Select-Object -First 1)
        }

        'import' {
            Import-HostsFile -Path (@($Value1) | Select-Object -First 1)
        }

        'list' {
            Get-HostsFile -Values $Value1 -State All
        }

        'merge' {
            throw 'Not yet supported'
            #Merge-HostsFile -Path $Value1
        }

        'path' {
            Write-Host "=> $(Get-HostsFilePath)"
        }

        'remove' {
            throw 'Not yet supported'
            #Remove-HostsFileEntries -Values $Value1
        }

        'restore' {
            Restore-HostsFile -Path (@($Value1) | Select-Object -First 1)
        }

        'set' {
            Set-HostsFileEntries -IP (@($Value1) | Select-Object -First 1) -Hostnames $Value2
        }

        'test' {
            Test-HostsFileEntries -Values $Value1 -Port (@($Value2) | Select-Object -First 1)
        }
    }
}


function Test-HostsFileEntries
{
    param (
        [Parameter()]
        [string[]]
        $Values,

        [Parameter()]
        [string]
        $Port
    )

    @(Get-HostsFile -Values $Values -State Enabled) | ForEach-Object {
        $name = ($_.Hosts | Select-Object -First 1)

        if ([string]::IsNullOrWhiteSpace($Port)) {
            Write-Host "=> Testing $($name)>" -NoNewline
            $result = Test-NetConnection -ComputerName $_.IP -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
        }
        else {
            Write-Host "=> Testing $($name):$($Port)>" -NoNewline
            $result = Test-NetConnection -ComputerName $_.IP -Port $Port -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
        }

        if ($null -eq $result -or (!$result.PingSucceeded -and !$result.TcpTestSucceeded)) {
            Write-Host "`tFailed" -ForegroundColor Red
        }
        else {
            Write-Host "`tSuccess" -ForegroundColor Green
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
        $Hostnames
    )

    # get the hosts file
    $path = Get-HostsFilePath
    $info = ConvertFrom-HostsFile -Path $path

    # fail if a hostname is found against a different IP
    $Hostnames | ForEach-Object {
        $h = Get-HostsFileEntry -HostsMap $info -Value $_ -Type Hostname -State Enabled
        if ($null -ne $h -and $h.IP -ine $IP) {
            throw "=> The hostname [$($_)] is bound against a different IP address: [$($h.IP)]"
        }
    }

    # loop through each of the host names supplied
    foreach ($name in $Hostnames)
    {
        # see if there's a disabled entry, and remove hostname from that entry
        Get-HostsFileEntries -HostsMap $info -IP $IP -Hostname $name -State Disabled | ForEach-Object {
            $_.Hosts = @($_.Hosts | Where-Object { $_ -ine $name })
        }

        # skip if already added
        if ((Get-HostsFileEntries -HostsMap $info -IP $IP -Hostname $name -State Enabled | Measure-Object).Count -gt 0) {
            Write-Host "=> Already added [$($IP) - $($name)]" -ForegroundColor Cyan
            continue
        }

        # add IP+Hostname
        $entry = (Get-HostsFileEntry -HostsMap $info -Value $IP -Type IP -State Enabled | Select-Object -First 1)
        if (($entry | Measure-Object).Count -eq 0) {
            $info += (Get-HostsFileEntryObject -IP $IP -Hostnames @($name) -Enabled $true)
        }
        else {
            $entry.Hosts += $name
        }

        Write-Host "=> Adding [$($IP) - $($name)]"
    }

    # create backup of current
    New-HostsFileBackup

    # write out to hosts file
    try {
        ConvertTo-HostsFile -HostsMap $info | Out-File -FilePath $path -Encoding utf8 -Force -ErrorAction Stop | Out-Null
        Write-Host "=> Hosts file updated" -ForegroundColor Green
    }
    catch {
        Restore-HostsFile
        throw $_.Exception
    }
}

function Set-HostsFileEntries
{
    param (
        [Parameter(Mandatory=$true)]
        [string]
        $IP,

        [Parameter(Mandatory=$true)]
        [string[]]
        $Hostnames
    )

    # get the hosts file
    $path = Get-HostsFilePath
    $info = ConvertFrom-HostsFile -Path $path

    # fail if a hostname is found against a different IP
    $Hostnames | ForEach-Object {
        $h = Get-HostsFileEntry -HostsMap $info -Value $_ -Type Hostname -State Enabled
        if ($null -ne $h -and $h.IP -ine $IP) {
            throw "=> The hostname [$($_)] is bound against a different IP address: [$($h.IP)]"
        }
    }

    # reset hosts for all the entries for the IP
    $entries = @(Get-HostsFileEntry -HostsMap $info -Value $IP -Type IP -State Enabled)
    if (($entries | Measure-Object).Count -eq 0) {
        $info += (Get-HostsFileEntryObject -IP $IP -Hostnames @() -Enabled $true)
    }
    else {
        $entries | ForEach-Object {
            $_.Hosts = @()
        }
    }

    # loop through each of the host names supplied
    foreach ($name in $Hostnames)
    {
        # see if there's a disabled entry, and remove hostname from that entry
        Get-HostsFileEntries -HostsMap $info -IP $IP -Hostname $name -State Disabled | ForEach-Object {
            $_.Hosts = @($_.Hosts | Where-Object { $_ -ine $name })
        }

        # skip if already added
        if ((Get-HostsFileEntries -HostsMap $info -IP $IP -Hostname $name -State Enabled | Measure-Object).Count -gt 0) {
            Write-Host "=> Already added [$($IP) - $($name)]" -ForegroundColor Cyan
            continue
        }

        # add IP+Hostname
        $entry = (Get-HostsFileEntry -HostsMap $info -Value $IP -Type IP -State Enabled | Select-Object -First 1)
        $entry.Hosts += $name

        Write-Host "=> Setting [$($IP) - $($name)]"
    }

    # create backup of current
    New-HostsFileBackup

    # write out to hosts file
    try {
        ConvertTo-HostsFile -HostsMap $info | Out-File -FilePath $path -Encoding utf8 -Force -ErrorAction Stop | Out-Null
        Write-Host "=> Hosts file updated" -ForegroundColor Green
    }
    catch {
        Restore-HostsFile
        throw $_.Exception
    }
}

function Clear-HostsFile
{
    # create backup of current
    $path = Get-HostsFilePath
    New-HostsFileBackup

    # clear the hosts file
    try {
        ([string]::Empty) | Out-File -FilePath $path -Encoding utf8 -Force -ErrorAction Stop | Out-Null
        Write-Host "=> Hosts file cleared" -ForegroundColor Green
    }
    catch {
        Restore-HostsFile
        throw $_.Exception
    }
}

function Restore-HostsFile
{
    param (
        [Parameter()]
        [string]
        $Path
    )

    $details = Get-HostsFileBackupDetails -BackupPath $Path

    if (!(Test-Path $details.Backup.Path)) {
        throw "=> No $($details.Backup.Name) file found"
    }

    Copy-Item -Path $details.Backup.Path -Destination $details.Hosts.Path -Force | Out-Null
    Write-Host "=> Restored hosts file from $($details.Backup.Name)" -ForegroundColor Green
}

function Import-HostsFile
{
    param (
        [Parameter(Mandatory=$true)]
        [string]
        $Path
    )

    if (!(Test-Path $Path)) {
        throw "=> File not found: $($Path)"
    }

    # create backup of current
    New-HostsFileBackup

    # import file to hosts file
    try {
        Copy-Item -Path $Path -Destination (Get-HostsFilePath) -Force -ErrorAction Stop | Out-Null
        Write-Host "=> Hosts file imported from: $($Path)" -ForegroundColor Green
    }
    catch {
        Restore-HostsFile
        throw $_.Exception
    }
}

function Export-HostsFile
{
    param (
        [Parameter(Mandatory=$true)]
        [string]
        $Path
    )

    Copy-Item -Path (Get-HostsFilePath) -Destination $Path -Force -ErrorAction Stop | Out-Null
    Write-Host "=> Hosts file exported to: $($Path)" -ForegroundColor Green
}

function Get-HostsFile
{
    param (
        [Parameter()]
        [string[]]
        $Values,

        [Parameter()]
        [ValidateSet('All', 'Disabled', 'Enabled')]
        [string]
        $State
    )

    $info = ConvertFrom-HostsFile
    $results = @()

    $Values | ForEach-Object {
        @(Get-HostsFileEntries -HostsMap $info -IP $_ -Hostname $_ -State $State -Like) | ForEach-Object {
            $_tmp = $_
            if (($results | Where-Object { $_.Hash -eq $_tmp.Hash } | Measure-Object).Count -eq 0) {
                $results += $_tmp
            }
        }
    }

    return ($results | Select-Object IP, Hosts, Enabled)
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
    Copy-Item -Path $details.Hosts.Path -Destination $details.Backup.Path -Force | Out-Null

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
        $backup = Join-Path $basepath 'hosts.bak'
    }
    else {
        $backup = Resolve-Path -Path $BackupPath
    }

    return @{
        'Hosts' = @{
            'Path' = $path;
        };
        'Backup' = @{
            'Path' = $backup;
            'Name' = (Split-Path -Leaf -Path $backup);
            'Temp' = "$($backup).tmp";
        };
    }
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
    # unix
    if (Test-IsUnix) {
        return '/etc/hosts'
    }

    # TODO: check here for MacOS?

    # windows is default
    return "$($env:windir)\System32\drivers\etc\hosts"
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

    $h = Get-Content $Path
    $map = @()

    $h | ForEach-Object {
        if ($_ -imatch "^\s*(?<enabled>[\#]{0,1})\s*(?<ip>(\[[a-z0-9\:]+\]|((\d+\.){3}\d+)|\:\:\d+))\s+(?<hosts>((([a-z0-9]|[a-z0-9][a-z0-9\-]*[a-z0-9])\.)*([a-z0-9]|[a-z0-9][a-z0-9\-]*[a-z0-9])\s*)+)\s*$") {
            $map += (Get-HostsFileEntryObject `
                -IP ($Matches['ip']) `
                -Hostnames @($Matches['hosts'] -isplit '\s+') `
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

        [Parameter(Mandatory=$true)]
        [string[]]
        $Hostnames,

        [Parameter(Mandatory=$true)]
        [bool]
        $Enabled
    )

    return (New-Object -TypeName psobject |
        Add-Member -MemberType NoteProperty -Name IP -Value $IP -PassThru |
        Add-Member -MemberType NoteProperty -Name Hosts $Hostnames -PassThru |
        Add-Member -MemberType NoteProperty -Name Enabled -Value $Enabled -PassThru |
        Add-Member -MemberType NoteProperty -Name Hash -Value ([string]::Empty) -PassThru)
}

function Update-HostsFileObject
{
    param (
        [Parameter(Mandatory=$true)]
        $HostsMap
    )

    $crypto = [System.Security.Cryptography.SHA256]::Create()

    $HostsMap | ForEach-Object {
        $str = "$($_.IP)|$($_.Hosts -join '|')"
        $_.Hash = [System.Convert]::ToBase64String($crypto.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($str)))
    }

    return $HostsMap
}

function ConvertTo-HostsFile
{
    param (
        [Parameter(Mandatory=$true)]
        $HostsMap
    )

    $str = [string]::Empty

    foreach ($entry in $HostsMap)
    {
        if ($null -eq $entry -or [string]::IsNullOrWhiteSpace($entry.IP) -or ($entry.Hosts | Measure-Object).Count -eq 0) {
            continue
        }

        if (!$entry.Enabled) {
            $str += '# '
        }

        $str += "$($entry.IP)`t$($entry.Hosts -join ' ')$([environment]::NewLine)"
    }

    return $str
}

function Get-HostsFileEntry
{
    param (
        [Parameter(Mandatory=$true)]
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
        $State
    )

    switch ($Type.ToLowerInvariant())
    {
        'IP' {
            $HostsMap = @($HostsMap | Where-Object { $_.IP -ieq $Value })
        }

        'Hostname' {
            $HostsMap = @($HostsMap | Where-Object { $_.Hosts -icontains $Value })
        }
    }

    return (Get-HostsFileEntriesByState -HostsMap $HostsMap -State $State)
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

    return $HostsMap
}

function Get-HostsFileEntries
{
    param (
        [Parameter(Mandatory=$true)]
        [object[]]
        $HostsMap,

        [Parameter()]
        [string]
        $IP,

        [Parameter()]
        [string]
        $Hostname,

        [Parameter()]
        [ValidateSet('All', 'Disabled', 'Enabled')]
        [string]
        $State,

        [switch]
        $Like
    )

    $HostsMap = @($HostsMap | Where-Object {
        if ($Like) {
            $_.IP -ilike $IP -or ($_.Hosts | Where-Object { $_ -ilike $Hostname } | Measure-Object).Count -ne 0 
        }
        else {
            $_.IP -ilike $IP -and ($_.Hosts | Where-Object { $_ -ilike $Hostname } | Measure-Object).Count -ne 0 
        }
    })

    return (Get-HostsFileEntriesByState -HostsMap $HostsMap -State $State)
}

# TODO: Export the Hosts function only