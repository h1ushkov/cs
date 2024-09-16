# Function to check and start the service if it's not running
function Ensure-ServiceRunning {
    param (
        [string]$serviceName
    )
    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if ($service.Status -ne 'Running') {
        Set-Service -Name $serviceName -StartupType Manual
        Start-Service -Name $serviceName
        Write-Host "Service $serviceName started." -ForegroundColor Green
    } else {
        Write-Host "Service $serviceName is already running." -ForegroundColor Yellow
    }
}

# Ensure necessary services are running
Ensure-ServiceRunning -serviceName "VSS"

# Enable System Protection for the C: drive, if available (not on Home editions)
if (Get-Command Enable-ComputerRestore -ErrorAction SilentlyContinue) {
    Enable-ComputerRestore -Drive "C:\"
    Checkpoint-Computer -Description "Before Security Changes" -RestorePointType MODIFY_SETTINGS
    Write-Host "System restore point created."
} else {
    Write-Host "System Restore is not available on this version of Windows." -ForegroundColor Yellow
}

# Check for administrator rights
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "This script requires administrator privileges." -ForegroundColor Red
    exit
}

# Create an administrative account
$adminUsername = "AdminUAC"
$adminPassword = ConvertTo-SecureString "rGotOroA" -AsPlainText -Force
if (-not (Get-LocalUser -Name $adminUsername -ErrorAction SilentlyContinue)) {
    New-LocalUser -Name $adminUsername -Password $adminPassword -Description "Admin Account" -PasswordNeverExpires | Out-Null
    Add-LocalGroupMember -Group "Administrators" -Member $adminUsername | Out-Null
    Write-Host "Administrative account $adminUsername created successfully."
} else {
    Write-Host "Administrative account $adminUsername already exists."
}

# Remove all other users from the 'Administrators' group, except 'AdminUAC' and disabled users
$adminGroup = Get-LocalGroupMember -Group "Administrators" | Where-Object {
    $_.Name -ne $adminUsername -and $_.Name -ne "Administrator"
}

foreach ($user in $adminGroup) {
    $username = $user.Name.Split('\')[-1]
    $localUser = Get-LocalUser -Name $username -ErrorAction SilentlyContinue

    if ($localUser -and $localUser.Enabled -eq $true -and $localUser.Name -ne $adminUsername) {
        Remove-LocalGroupMember -Group "Administrators" -Member $username -ErrorAction SilentlyContinue
        Add-LocalGroupMember -Group "Users" -Member $username -ErrorAction SilentlyContinue
        Write-Host "User $($username) has been moved from 'Administrators' to 'Users'."
    }
}
Write-Host "All active users, except $adminUsername and 'Administrator', have been moved to the 'Users' group."

# Set UAC to require administrator password input
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorUser /t REG_DWORD /d 3 /f

Write-Host "UAC configured to require administrator password on elevation."

# Disable guest account
net user guest /active:no
Write-Host "Guest account successfully disabled."

# Clear PowerShell command history
Clear-History
Write-Host "PowerShell command history cleared successfully."

Write-Host "Setup completed successfully!"
