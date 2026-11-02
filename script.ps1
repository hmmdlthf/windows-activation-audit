# ================================================
# WINDOWS ACTIVATION AUDIT v2
# Read-only licensing and activation investigation
# ================================================

$ErrorActionPreference = "SilentlyContinue"

$Results = [System.Collections.Generic.List[object]]::new()

function Add-Result {
    param($Category, $Finding, $Status, $Details)

    $Results.Add([PSCustomObject]@{
        Category = $Category
        Finding  = $Finding
        Status   = $Status
        Details  = $Details
    })
}

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "       WINDOWS ACTIVATION AUDIT" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

# 1. Windows information
$OS = Get-CimInstance Win32_OperatingSystem

Write-Host "`n[1] WINDOWS INFORMATION" -ForegroundColor Yellow

Write-Host "Edition: $($OS.Caption)"
Write-Host "Version: $($OS.Version)"
Write-Host "Computer: $env:COMPUTERNAME"

# 2. Licensing information
Write-Host "`n[2] LICENSING INFORMATION" -ForegroundColor Yellow

$Licenses = Get-CimInstance SoftwareLicensingProduct |
    Where-Object {
        $_.PartialProductKey -and
        $_.Name -like "*Windows*"
    }

foreach ($License in $Licenses) {

    $Channel = $License.Description

    Write-Host "`nProduct: $($License.Name)"
    Write-Host "Status: $($License.LicenseStatus)"
    Write-Host "Channel: $Channel"
    Write-Host "Partial Key: $($License.PartialProductKey)"

    if ($Channel -match "VOLUME_KMSCLIENT") {
        Add-Result "Licensing" "KMS Client Channel" "WARNING" $Channel
    }
    elseif ($Channel -match "VOLUME_MAK") {
        Add-Result "Licensing" "MAK Volume Channel" "INFO" $Channel
    }
    elseif ($Channel -match "RETAIL") {
        Add-Result "Licensing" "Retail Channel" "INFO" $Channel
    }
    elseif ($Channel -match "OEM") {
        Add-Result "Licensing" "OEM Channel" "INFO" $Channel
    }
}

# 3. Activation expiration
Write-Host "`n[3] ACTIVATION EXPIRATION" -ForegroundColor Yellow

$Expiration = cscript.exe //Nologo "$env:windir\system32\slmgr.vbs" /xpr 2>&1

$Expiration | ForEach-Object { Write-Host $_ }

# 4. KMS configuration
Write-Host "`n[4] KMS CONFIGURATION" -ForegroundColor Yellow

$KMS = Get-CimInstance SoftwareLicensingService

Write-Host "Configured KMS Host: $($KMS.KeyManagementServiceMachine)"
Write-Host "KMS Port: $($KMS.KeyManagementServicePort)"

if ($KMS.KeyManagementServiceMachine) {
    Add-Result "KMS" "KMS Server Configured" "WARNING" `
        $KMS.KeyManagementServiceMachine
}

# 5. Activation-related scheduled tasks
Write-Host "`n[5] SCHEDULED TASK INDICATORS" -ForegroundColor Yellow

$Tasks = Get-ScheduledTask

$SuspiciousTasks = $Tasks | Where-Object {
    $_.TaskName -match "AutoKMS|KMSAuto|HWID|MAS_AIO|Activation" -or
    $_.TaskPath -match "AutoKMS|KMSAuto|HWID|MAS_AIO"
}

if ($SuspiciousTasks) {
    foreach ($Task in $SuspiciousTasks) {
        Write-Host "Potential indicator: $($Task.TaskPath)$($Task.TaskName)" -ForegroundColor Red

        Add-Result "Scheduled Tasks" $Task.TaskName "REVIEW" $Task.TaskPath
    }
}
else {
    Write-Host "No matching task names found."
}

# 6. Known activation tool file indicators
Write-Host "`n[6] ACTIVATION TOOL FILE INDICATORS" -ForegroundColor Yellow

$SearchLocations = @(
    "$env:ProgramData",
    "$env:windir\Setup\Scripts",
    "$env:TEMP"
)

$Patterns = @(
    "*MAS*",
    "*HWID*",
    "*AutoKMS*",
    "*KMSAuto*",
    "*KMSPico*"
)

foreach ($Location in $SearchLocations) {

    foreach ($Pattern in $Patterns) {

        $Found = Get-ChildItem -Path $Location `
            -Filter $Pattern -Recurse -File -Force |
            Select-Object -First 10

        foreach ($File in $Found) {

            Write-Host "Review: $($File.FullName)" -ForegroundColor Yellow

            Add-Result "Files" $File.Name "REVIEW" $File.FullName
        }
    }
}

# 7. Licensing event log availability
Write-Host "`n[7] LICENSING EVENT HISTORY" -ForegroundColor Yellow

$Events = Get-WinEvent -FilterHashtable @{
    LogName = "Application"
    ProviderName = "Microsoft-Windows-Security-SPP"
} -MaxEvents 100

Write-Host "Available licensing events: $($Events.Count)"

if ($Events.Count -gt 0) {
    Add-Result "Event Logs" "Licensing History Available" "INFO" `
        "$($Events.Count) recent events examined"
}

# 8. Report
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "             AUDIT RESULTS" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

if ($Results.Count -eq 0) {
    Write-Host "No matching suspicious indicators found." -ForegroundColor Green
}
else {
    $Results | Format-Table -AutoSize -Wrap
}

# Save report
$ReportPath = "$env:USERPROFILE\Desktop\Windows-Activation-Audit.csv"

$Results | Export-Csv -Path $ReportPath -NoTypeInformation

Write-Host "`nReport saved to: $ReportPath" -ForegroundColor Green

Write-Host "`nAUDIT COMPLETED" -ForegroundColor Cyan
