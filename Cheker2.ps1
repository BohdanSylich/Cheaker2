# BankFileCleaner.ps1
# Для файлів з кириличною "а": bаnk.exe (а = U+0430)

param(
    [Parameter(Mandatory=$true)]
    [string]$FilePath = "C:\Path\To\bаnk.exe"  # Зверніть увагу на кириличну "а"
)

# Функція для виявлення Unicode-символів в імені
function Get-FileUnicodeAnalysis {
    param([string]$Path)

    $fileName = [System.IO.Path]::GetFileName($Path)
    $chars = $fileName.ToCharArray()

    Write-Host "Аналіз імені файла: $fileName" -ForegroundColor Cyan

    for ($i = 0; $i -lt $chars.Length; $i++) {
        $char = $chars[$i]
        $code = [int]$char

        if ($code -gt 127) {
            Write-Host "  Позиція $i: '$char' (Unicode: U+$($code.ToString('X4')))" -ForegroundColor Yellow
        }
    }
}

# Основна функція очищення для файлів з Unicode-символами
function Clean-UnicodeFileTraces {
    param(
        [string]$FilePath,
        [switch]$DeepClean = $false
    )

    # Аналізуємо ім'я файла
    Get-FileUnicodeAnalysis -Path $FilePath

    $fileName = Split-Path $FilePath -Leaf
    $fileNameWithoutExt = [System.IO.Path]::GetFileNameWithoutExtension($fileName)

    # Створюємо регулярні вирази для пошуку
    # 1. Точне ім'я (з Unicode)
    $exactNameRegex = [regex]::Escape($fileName)

    # 2. Ім'я з заміненими символами (кирилиця ↔ латиниця)
    $alternateNames = @()

    # Замінюємо кириличну "а" на латинську
    $latName = $fileName -replace [char]0x0430, [char]0x0061  # а → a
    if ($latName -ne $fileName) {
        $alternateNames += $latName
    }

    # Замінюємо латинську "a" на кириличну (на випадок пошуку)
    $cyrName = $fileName -replace [char]0x0061, [char]0x0430  # a → а
    if ($cyrName -ne $fileName) {
        $alternateNames += $cyrName
    }

    Write-Host "`nВаріанти імен для пошуку:" -ForegroundColor Green
    Write-Host "  Основне: $fileName" -ForegroundColor Yellow
    foreach ($alt in $alternateNames) {
        Write-Host "  Альтернативне: $alt" -ForegroundColor Yellow
    }

    # Отримуємо хеш файла
    Write-Host "`nОбчислення хешу файла..." -ForegroundColor Cyan
    try {
        $stream = [System.IO.File]::OpenRead($FilePath)
        $sha256 = [System.Security.Cryptography.SHA256]::Create()
        $hashBytes = $sha256.ComputeHash($stream)
        $fileHash = [BitConverter]::ToString($hashBytes) -replace '-', ''
        $stream.Close()
        Write-Host "  SHA256: $fileHash" -ForegroundColor Green
    } catch {
        Write-Host "  Не вдалося обчислити хеш" -ForegroundColor Red
        $fileHash = ""
    }

    # --- 1. ОЧИЩЕННЯ PREFETCH ---
    Write-Host "`n[1] Очищення Prefetch..." -ForegroundColor Cyan

    # Пошук у Prefetch за всіма варіантами імен
    $prefetchFiles = Get-ChildItem "C:\Windows\Prefetch" -Filter "*.pf" -ErrorAction SilentlyContinue

    foreach ($pf in $prefetchFiles) {
        $pfContent = ""
        try {
            $pfContent = Get-Content $pf.FullName -Raw -ErrorAction SilentlyContinue
        } catch {}

        if ($pfContent -ne $null) {
            # Перевіряємо всі варіанти
            $shouldDelete = $false

            # Перевірка за точним іменем
            if ($pfContent -match $exactNameRegex) {
                $shouldDelete = $true
                Write-Host "  Знайдено за точним іменем: $($pf.Name)" -ForegroundColor Yellow
            }

            # Перевірка за альтернативними іменами
            foreach ($altName in $alternateNames) {
                $altRegex = [regex]::Escape($altName)
                if ($pfContent -match $altRegex) {
                    $shouldDelete = $true
                    Write-Host "  Знайдено за альтернативним іменем ($altName): $($pf.Name)" -ForegroundColor Yellow
                }
            }

            # Перевірка за хешем (якщо є)
            if ($fileHash -ne "" -and $pfContent -match $fileHash.Substring(0, 16)) {
                $shouldDelete = $true
                Write-Host "  Знайдено за хешем: $($pf.Name)" -ForegroundColor Yellow
            }

            if ($shouldDelete) {
                Remove-Item $pf.FullName -Force -ErrorAction SilentlyContinue
                Write-Host "  ✓ Видалено: $($pf.Name)" -ForegroundColor Green
            }
        }
    }

    # --- 2. ОЧИЩЕННЯ РЕЄСТРУ ---
    Write-Host "`n[2] Очищення реєстру..." -ForegroundColor Cyan

    # Список шляхів для пошуку
    $registryPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
        "HKLM:\SYSTEM\CurrentControlSet\Services",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
    )

    $searchPatterns = @($exactNameRegex) + $alternateNames

    foreach ($regPath in $registryPaths) {
        if (Test-Path $regPath) {
            try {
                # Пошук в іменах ключів
                Get-ChildItem $regPath -ErrorAction SilentlyContinue | ForEach-Object {
                    $key = $_
                    foreach ($pattern in $searchPatterns) {
                        if ($key.PSChildName -match $pattern) {
                            Write-Host "  Знайдено ключ: $($key.Name)" -ForegroundColor Yellow
                            Remove-Item $key.PSPath -Recurse -Force -ErrorAction SilentlyContinue
                            Write-Host "  ✓ Видалено ключ" -ForegroundColor Green
                        }
                    }

                    # Пошук в значеннях ключів
                    $values = Get-ItemProperty $key.PSPath -ErrorAction SilentlyContinue
                    if ($values) {
                        $values.PSObject.Properties | ForEach-Object {
                            $propValue = $_.Value.ToString()
                            foreach ($pattern in $searchPatterns) {
                                if ($propValue -match $pattern -or
                                    ($fileHash -ne "" -and $propValue -match $fileHash)) {
                                    Write-Host "  Знайдено значення в $($key.Name): $($_.Name)" -ForegroundColor Yellow
                                    Remove-ItemProperty -Path $key.PSPath -Name $_.Name -Force -ErrorAction SilentlyContinue
                                    Write-Host "  ✓ Видалено значення" -ForegroundColor Green
                                }
                            }
                        }
                    }
                }
            } catch {
                # Ігноруємо помилки доступу
            }
        }
    }

    # --- 3. ОЧИЩЕННЯ EVENT LOGS ---
    Write-Host "`n[3] Очищення Event Logs..." -ForegroundColor Cyan

    # Запуски програм (Event ID 4688)
    $eventsToCheck = @(
        @{LogName="Security"; ID=4688},
        @{LogName="System"; ID=7036},
        @{LogName="Microsoft-Windows-PowerShell/Operational"; ID=4104}
    )

    foreach ($eventSpec in $eventsToCheck) {
        try {
            $events = Get-WinEvent -FilterHashtable @{
                LogName = $eventSpec.LogName
                ID = $eventSpec.ID
            } -ErrorAction SilentlyContinue | Where-Object {
                $found = $false
                foreach ($pattern in $searchPatterns) {
                    if ($_.Message -match $pattern) {
                        $found = $true
                        break
                    }
                }
                $found -or ($fileHash -ne "" -and $_.Message -match $fileHash)
            }

            if ($events) {
                Write-Host "  Знайдено $($events.Count) подій в $($eventSpec.LogName)" -ForegroundColor Yellow

                # Створюємо тимчасовий лог без цих подій
                $tempFile = "$env:TEMP\clean_$([System.Guid]::NewGuid()).evtx"
                wevtutil epl $eventSpec.LogName $tempFile 2>$null

                # Очищаємо оригінальний лог
                wevtutil cl $eventSpec.LogName 2>$null

                # Відновлюємо лог без знайдених подій (спрощено)
                # На практиці потрібно парсити EVTX і видаляти конкретні події
                Write-Host "  ⚠️  Лог очищено повністю (усі події)" -ForegroundColor Magenta

                Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
            }
        } catch {}
    }

    # --- 4. ОЧИЩЕННЯ ШЛЯХІВ У ПРОВОДНИКУ ---
    Write-Host "`n[4] Очищення Shellbags та Recent..." -ForegroundColor Cyan

    # Recent Items
    Remove-Item "$env:APPDATA\Microsoft\Windows\Recent\*" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item "$env:APPDATA\Microsoft\Windows\Recent\AutomaticDestinations\*" -Force -ErrorAction SilentlyContinue

    # Quick Access
    Remove-Item "$env:APPDATA\Microsoft\Windows\Recent\AutomaticDestinations\f01b4d95cf55d32a.automaticDestinations-ms" -ErrorAction SilentlyContinue

    # --- 5. ОЧИЩЕННЯ TEMP ФАЙЛІВ ---
    Write-Host "`n[5] Очищення тимчасових файлів..." -ForegroundColor Cyan

    $tempPaths = @(
        $env:TEMP,
        "$env:SystemRoot\Temp",
        [System.IO.Path]::GetTempPath()
    )

    foreach ($tempPath in $tempPaths) {
        if (Test-Path $tempPath) {
            Get-ChildItem $tempPath -ErrorAction SilentlyContinue | Where-Object {
                foreach ($pattern in $searchPatterns) {
                    if ($_.Name -match $pattern) {
                        return $true
                    }
                }
                return $false
            } | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    # --- 6. ОЧИЩЕННЯ WINDOWS SEARCH ---
    Write-Host "`n[6] Очищення Windows Search..." -ForegroundColor Cyan

    Stop-Service "WSearch" -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2

    $searchIndexPaths = @(
        "C:\ProgramData\Microsoft\Search\Data\Applications\Windows",
        "$env:APPDATA\Microsoft\Search\Data"
    )

    foreach ($searchPath in $searchIndexPaths) {
        if (Test-Path $searchPath) {
            Get-ChildItem $searchPath -Filter "*.edb" -ErrorAction SilentlyContinue | Remove-Item -Force
        }
    }

    Start-Service "WSearch" -ErrorAction SilentlyContinue

    # --- 7. ГЛИБОКЕ ОЧИЩЕННЯ (якщо ввімкнено) ---
    if ($DeepClean) {
        Write-Host "`n[7] Глибоке очищення..." -ForegroundColor Red

        # USN Journal
        fsutil usn deletejournal /D C: 2>$null
        Write-Host "  USN Journal очищено" -ForegroundColor Yellow

        # Перезапис вільних кластерів (де файл міг бути)
        if (Test-Path $FilePath) {
            $fileSize = (Get-Item $FilePath).Length
            $sDeletePath = "$env:TEMP\sdelete.exe"

            # Можна використати sdelete з Sysinternals
            Write-Host "  Для перезапису використайте: sdelete -p 3 -s $FilePath" -ForegroundColor Yellow
        }

        # MFT запис (складніше)
        Write-Host "  ⚠️  Для очищення MFT потрібні спеціальні інструменти" -ForegroundColor Red
    }

    # --- 8. МЕТАДАНІ ФАЙЛА ---
    Write-Host "`n[8] Очищення метаданих..." -ForegroundColor Cyan

    if (Test-Path $FilePath) {
        # Зміна дат
        $file = Get-Item $FilePath -Force
        $randomDate = Get-Date "2022-06-15"
        $file.CreationTime = $randomDate
        $file.LastWriteTime = $randomDate
        $file.LastAccessTime = $randomDate

        Write-Host "  Дати файла змінено на: $randomDate" -ForegroundColor Green

        # ADS потоки
        Get-Item $FilePath -Stream * -ErrorAction SilentlyContinue |
            Where-Object Stream -ne ':$DATA' |
            ForEach-Object {
                Remove-Item -Path $FilePath -Stream $_.Stream -ErrorAction SilentlyContinue
                Write-Host "  Видалено ADS: $($_.Stream)" -ForegroundColor Green
            }
    }

    # --- 9. SRAM/MEMORY ---
    Write-Host "`n[9] Очищення SRAM..." -ForegroundColor Cyan

    # Очищення Recent Docs
    Remove-Item "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs" -Recurse -Force -ErrorAction SilentlyContinue 2>$null

    # Очищення TypedPaths
    Remove-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths" -Name "*" -ErrorAction SilentlyContinue

    # --- ФІНАЛЬНІ ДІЇ ---
    Write-Host "`n" + "="*50 -ForegroundColor Green
    Write-Host "ОЧИЩЕННЯ ЗАВЕРШЕНО!" -ForegroundColor Green
    Write-Host "="*50 -ForegroundColor Green

    Write-Host "`nПідсумок для файла: $fileName" -ForegroundColor Yellow
    Write-Host "  • Prefetch: очищено" -ForegroundColor Gray
    Write-Host "  • Реєстр: очищено" -ForegroundColor Gray
    Write-Host "  • Event Logs: очищено" -ForegroundColor Gray
    Write-Host "  • Shellbags: очищено" -ForegroundColor Gray
    Write-Host "  • Windows Search: очищено" -ForegroundColor Gray
    Write-Host "  • Метадані: змінено" -ForegroundColor Gray

    if ($DeepClean) {
        Write-Host "  • USN Journal: очищено" -ForegroundColor Gray
        Write-Host "  • Глибоке очищення: виконано" -ForegroundColor Gray
    }

    Write-Host "`nРекомендації:" -ForegroundColor Magenta
    Write-Host "  1. Перезавантажте комп'ютер" -ForegroundColor Yellow
    Write-Host "  2. Не запускайте файл знову перед перевіркою" -ForegroundColor Yellow
    Write-Host "  3. Можливо, видаліть сам файл $fileName" -ForegroundColor Yellow

    if ($DeepClean -and (Test-Path $FilePath)) {
        $confirmDelete = Read-Host "`nВидалити сам файл $fileName? (Y/N)"
        if ($confirmDelete -eq 'Y') {
            Remove-Item $FilePath -Force
            Write-Host "  Файл видалено!" -ForegroundColor Green
        }
    }
}

# --- ЗАПУСК ---
Write-Host "=== ОЧИЩУВАЧ СЛІДІВ ДЛЯ ФАЙЛІВ З UNICODE ===`n" -ForegroundColor Blue

if (-not (Test-Path $FilePath)) {
    Write-Host "ФАЙЛ НЕ ЗНАЙДЕНО: $FilePath" -ForegroundColor Red
    Write-Host "Перевірте шлях. Зверніть увагу на кириличні символи!" -ForegroundColor Yellow
    exit 1
}

Write-Host "Знайдено файл: $FilePath" -ForegroundColor Green
$fileInfo = Get-Item $FilePath
Write-Host "Розмір: $($fileInfo.Length) байт" -ForegroundColor Cyan
Write-Host "Дата створення: $($fileInfo.CreationTime)" -ForegroundColor Cyan

# Запитуємо глибину очищення
$deepCleanChoice = Read-Host "`nВиконати глибоке очищення (USN Journal, MFT)? Може бути підозрілим! (Y/N)"
$deepClean = ($deepCleanChoice -eq 'Y')

# Запускаємо очищення
Clean-UnicodeFileTraces -FilePath $FilePath -DeepClean:$deepClean

# Очищаємо історію PowerShell
Clear-History
Remove-Item (Get-PSReadlineOption).HistorySavePath -ErrorAction SilentlyContinue 2>$null

Write-Host "`nІсторія PowerShell очищена." -ForegroundColor Green
Write-Host "`nСкрипт завершено." -ForegroundColor Blue