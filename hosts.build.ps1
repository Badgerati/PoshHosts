<#
# Dependencies
#>

# Synopsis: Install dependencies for running tests
task TestDeps {
    if (((Get-Module -ListAvailable Pester) | Where-Object { $_.Version -ieq '4.4.2' }) -eq $null) {
        Write-Host 'Installing Pester'
        Install-Module -Name Pester -Scope CurrentUser -RequiredVersion '4.4.2' -Force -SkipPublisherCheck
    }
}


<#
# Testing
#>

# Synopsis: Run the tests
task Test TestDeps, {
    $p = (Get-Command Invoke-Pester)
    if ($null -eq $p -or $p.Version -ine '4.4.2') {
        Import-Module Pester -Force -RequiredVersion '4.4.2'
    }

    $Script:TestResultFile = "$($pwd)/TestResults.xml"
    $Script:TestStatus = Invoke-Pester './tests' -OutputFormat NUnitXml -OutputFile $TestResultFile -PassThru
}, PushAppVeyorTests, CheckFailedTests

# Synopsis: Check if any of the tests failed
task CheckFailedTests {
    if ($TestStatus.FailedCount -gt 0) {
        throw "$($TestStatus.FailedCount) tests failed"
    }
}

# Synopsis: If AppVeyor, push result artifacts
task PushAppVeyorTests -If (![string]::IsNullOrWhiteSpace($env:APPVEYOR_JOB_ID)) {
    $url = "https://ci.appveyor.com/api/testresults/nunit/$($env:APPVEYOR_JOB_ID)"
    (New-Object 'System.Net.WebClient').UploadFile($url, $TestResultFile)
    Push-AppveyorArtifact $TestResultFile
}