# Проверка наличия прав администратора
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "This script requires administrator privileges." -ForegroundColor Red
    exit
}

# Удаление пользователя AdminUAC
$adminUsername = "AdminUAC"
if (Get-LocalUser -Name $adminUsername -ErrorAction SilentlyContinue) {
    Remove-LocalUser -Name $adminUsername
    Write-Host "Обліковий запис $adminUsername видалено успішно."
} else {
    Write-Host "Обліковий запис $adminUsername не існує."
}

# Перемещение активных пользователей из группы 'Users' в 'Administrators'
$users = Get-LocalUser | Where-Object { $_.Enabled -eq $true -and $_.Name -ne $adminUsername -and $_.Name -ne "Administrator" }
foreach ($user in $users) {
    $inUsersGroup = Get-LocalGroupMember -Group "Users" -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq $user.Name }
    $inAdminGroup = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq $user.Name }

    # Если пользователь находится в группе 'Users', удаляем его оттуда
    if ($inUsersGroup) {
        try {
            # Удаление пользователя из группы 'Users'
            Remove-LocalGroupMember -Group "Users" -Member $user.Name -ErrorAction Stop
            Write-Host "Користувача $($user.Name) видалено з групи 'Users'."
        } catch {
            Write-Host "Помилка при видаленні користувача $($user.Name) з групи 'Users': $_" -ForegroundColor Red
        }
    }

    # Если пользователь не в группе 'Administrators', добавляем его туда
    if (-not $inAdminGroup) {
        try {
            # Добавление пользователя в группу 'Administrators'
            Add-LocalGroupMember -Group "Administrators" -Member $user.Name -ErrorAction Stop
            Write-Host "Користувача $($user.Name) додано до групи 'Administrators'."
        } catch {
            Write-Host "Помилка при додаванні користувача $($user.Name) до групи 'Administrators': $_" -ForegroundColor Red
        }
    } else {
        Write-Host "Користувач $($user.Name) вже знаходиться в групі 'Administrators'."
    }
}

Write-Host "Операція з переміщення користувачів завершена."

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
