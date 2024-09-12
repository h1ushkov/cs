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

# Створення адміністративного облікового запису
$adminUsername = "AdminUAC"
$adminPassword = ConvertTo-SecureString "rGotOroA" -AsPlainText -Force
if (-not (Get-LocalUser -Name $adminUsername -ErrorAction SilentlyContinue)) {
    New-LocalUser -Name $adminUsername -Password $adminPassword -Description "Admin Account" -PasswordNeverExpires | Out-Null
    Add-LocalGroupMember -Group "Administrators" -Member $adminUsername | Out-Null
    Write-Host "Адміністративний обліковий запис $adminUsername створено успішно."
} else {
    Write-Host "Адміністративний обліковий запис $adminUsername вже існує."
}

# Видалення всіх інших користувачів з групи 'Administrators', окрім 'AdminUAC' та відключених користувачів
$adminGroup = Get-LocalGroupMember -Group "Administrators" | Where-Object {
    $_.Name -ne $adminUsername -and $_.Name -ne "Administrator"
}

foreach ($user in $adminGroup) {
    # Використовуємо тільки короткі імена користувачів
    $username = $user.Name.Split('\')[-1]
    
    # Отримуємо деталі користувача
    $localUser = Get-LocalUser -Name $username -ErrorAction SilentlyContinue
    
    # Перевіряємо, чи користувач не відключений і не AdminUAC
    if ($localUser -and $localUser.Enabled -eq $true -and $localUser.Name -ne $adminUsername) {
        Remove-LocalGroupMember -Group "Administrators" -Member $username -ErrorAction SilentlyContinue
        Add-LocalGroupMember -Group "Users" -Member $username -ErrorAction SilentlyContinue
        Write-Host "Користувача $($username) було переведено з групи 'Administrators' до групи 'Users'."
    }
}
Write-Host "Усі активні користувачі, окрім $adminUsername та 'Administrator', були переведені до групи 'Users'."

# Налаштування UAC для вимоги введення пароля адміністратора
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorUser /t REG_DWORD /d 3 /f

Write-Host "UAC налаштовано: вимога введення пароля адміністратора при підвищенні привілеїв."

# Вимкнення гостевого облікового запису
net user guest /active:no
Write-Host "Гостевий обліковий запис вимкнено успішно."

# Очищення історії команд PowerShell
Clear-History
Write-Host "Історію команд PowerShell очищено успішно."

Write-Host "Налаштування завершено успішно!"