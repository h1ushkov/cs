# Check for administrator rights
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "This script requires administrator privileges." -ForegroundColor Red
    exit
}

# Remove the user AdminUAC
$adminUsername = "AdminUAC"
if (Get-LocalUser -Name $adminUsername -ErrorAction SilentlyContinue) {
    Remove-LocalUser -Name $adminUsername
    Write-Host "Account $adminUsername successfully removed."
} else {
    Write-Host "Account $adminUsername does not exist."
}

# Move active users from the 'Users' group to 'Administrators'
$users = Get-LocalUser | Where-Object { $_.Enabled -eq $true -and $_.Name -ne $adminUsername -and $_.Name -ne "Administrator" }
foreach ($user in $users) {
    $inUsersGroup = Get-LocalGroupMember -Group "Users" -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq $user.Name }
    $inAdminGroup = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq $user.Name }

    if ($inUsersGroup) {
        try {
            Remove-LocalGroupMember -Group "Users" -Member $user.Name -ErrorAction Stop
            Write-Host "User $($user.Name) removed from 'Users' group."
        } catch {
            Write-Host "Error removing user $($user.Name) from 'Users' group: $_" -ForegroundColor Red
        }
    }

    if (-not $inAdminGroup) {
        try {
            Add-LocalGroupMember -Group "Administrators" -Member $user.Name -ErrorAction Stop
            Write-Host "User $($user.Name) added to 'Administrators' group."
        } catch {
            Write-Host "Error adding user $($user.Name) to 'Administrators' group: $_" -ForegroundColor Red
        }
    } else {
        Write-Host "User $($user.Name) is already in the 'Administrators' group."
    }
}

Write-Host "User relocation operation completed."

# Restore default UAC settings
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 5 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorUser /t REG_DWORD /d 3 /f

Write-Host "UAC configured to default settings."

# Disable guest account
net user guest /active:no
Write-Host "Guest account has been successfully disabled."

# Clear PowerShell command history
Clear-History
Write-Host "PowerShell command history cleared successfully."

Write-Host "Revert completed successfully!"
