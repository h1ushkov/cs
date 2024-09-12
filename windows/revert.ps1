# Check for administrator rights
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "This script requires administrator privileges." -ForegroundColor Red
    exit
}

# Видалення облікового запису AdminUAC
$adminUsername = "AdminUAC"
if (Get-LocalUser -Name $adminUsername -ErrorAction SilentlyContinue) {
    Remove-LocalUser -Name $adminUsername
    Write-Host "Обліковий запис $adminUsername видалено успішно."
} else {
    Write-Host "Обліковий запис $adminUsername не існує."
}

# Повернення користувачів до групи 'Administrators', якщо вони були понижені
$users = Get-LocalUser | Where-Object { $_.Enabled -eq $true -and $_.Name -ne $adminUsername -and $_.Name -ne "Administrator" }
foreach ($user in $users) {
    if (Get-LocalGroupMember -Group "Users" | Where-Object { $_.Name -eq $user.Name }) {
        Remove-LocalGroupMember -Group "Users" -Member $user.Name -ErrorAction SilentlyContinue
        Add-LocalGroupMember -Group "Administrators" -Member $user.Name -ErrorAction SilentlyContinue
        Write-Host "Користувача $($user.Name) було переведено з групи 'Users' до групи 'Administrators'."
    }
}
Write-Host "Усі користувачі були повернуті до групи 'Administrators'."

# Відновлення стандартних налаштувань UAC
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 5 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorUser /t REG_DWORD /d 3 /f

Write-Host "UAC налаштовано до стандартних значень."

# Вимкнення гостевого облікового запису, якщо було змінено
net user guest /active:no
Write-Host "Гостевий обліковий запис залишено вимкненим."

# Очищення історії команд PowerShell
Clear-History
Write-Host "Історію команд PowerShell очищено успішно."

Write-Host "Revert завершено успішно!"
