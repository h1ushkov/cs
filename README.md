# cs
Bunch of cybersecurity scrips and other stuff

Set-ExecutionPolicy Bypass -Scope Process

$scriptUrl = "https://raw.githubusercontent.com/h1ushkov/cs/main/windows/setup.ps1"

# Завантажуємо скрипт
Invoke-WebRequest -Uri $scriptUrl -OutFile "$env:TEMP\setup.ps1"

# Виконуємо завантажений скрипт
& "$env:TEMP\setup.ps1"


Set-ExecutionPolicy Bypass -Scope Process

$scriptUrl = "https://raw.githubusercontent.com/h1ushkov/cs/main/windows/revert.ps1"

# Завантажуємо скрипт
Invoke-WebRequest -Uri $scriptUrl -OutFile "$env:TEMP\revert.ps1"

# Виконуємо завантажений скрипт
& "$env:TEMP\revert.ps1"
