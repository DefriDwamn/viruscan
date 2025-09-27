@echo off
chcp 65001 >nul

if "%1"=="" goto usage
if "%2"=="" goto usage

set "DIR=%~1"
set "COUNT=%~2"
set "OUTPUT=hashes.csv"

if exist "%OUTPUT%" del "%OUTPUT%"
powershell -Command "$files = Get-ChildItem -Path '%DIR%' -File -Recurse -ErrorAction SilentlyContinue | Get-Random -Count %COUNT%; $threats = 'Trojan','Virus','Malware','Worm','Spyware'; foreach ($file in $files) { try { $hash = (Get-FileHash -Path $file.FullName -Algorithm MD5 -ErrorAction Stop).Hash; $threat = $threats | Get-Random; \"$hash;$threat\" | Out-File -FilePath '%OUTPUT%' -Append -Encoding UTF8 } catch { } }; Write-Host 'Обработано файлов: ' $files.Count"
goto :eof

:usage
echo Использование: %~nx0 ^<директория^> ^<количество^>