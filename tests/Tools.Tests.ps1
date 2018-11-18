$path = $MyInvocation.MyCommand.Path
$src = (Split-Path -Parent -Path $path) -ireplace '[\\/]tests', '/src'
Get-ChildItem "$($src)/*.ps1" | Resolve-Path | ForEach-Object { . $_ }

Describe 'Get-PSVersionTable' {
    It 'Returns valid hashtable' {
        $table = Get-PSVersionTable
        $table | Should Not Be $null
        $table | Should BeOfType System.Collections.Hashtable
    }
}

Describe 'Test-IsUnix' {
    It 'Returns false for non-unix' {
        Mock Get-PSVersionTable { return @{ 'Platform' = 'Windows' } }
        Test-IsUnix | Should Be $false
        Assert-MockCalled Get-PSVersionTable -Times 1
    }

    It 'Returns true for unix' {
        Mock Get-PSVersionTable { return @{ 'Platform' = 'Unix' } }
        Test-IsUnix | Should Be $true
        Assert-MockCalled Get-PSVersionTable -Times 1
    }
}