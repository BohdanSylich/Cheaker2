function Find-BankFile-Traces {
    Write-Host "Пошук слідів файла bаnk.exe..." -ForegroundColor Cyan
    $searchPatterns = @('b[аa]nk\.exe', 'bаnk.exe')
    $results = @()

    # 1. Перевірка Prefetch
    Write-Host "1. Аналіз Prefetch..." -NoNewline
    $pfFiles = Get-ChildItem "C:\Windows\Prefetch" -Filter "*.pf" -ErrorAction SilentlyContinue
    $foundInPrefetch = 0
    foreach ($pf in $pfFiles) {
        try {
            $content = Get-Content $pf.FullName -Raw -ErrorAction SilentlyContinue
            foreach ($pattern in $searchPatterns) {
                if ($content -match $pattern) {
                    $results += "Prefetch: $($pf.Name)"
                    $foundInPrefetch++
                    break
                }
            }
        } catch {}
    }
    Write-Host " [$foundInPrefetch знайдено]" -ForegroundColor $(if($foundInPrefetch-gt0){'Red'}else{'Green'})

    # 2. Перевірка реєстру
    Write-Host "2. Аналіз реєстру..." -NoNewline
    $registryPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs"
    )

    $foundInRegistry = 0
    foreach ($regPath in $registryPaths) {
        if (Test-Path $regPath) {
            try {
                # Пошук в ключах
                Get-ChildItem $regPath -ErrorAction SilentlyContinue | ForEach-Object {
                    $key = $_
                    foreach ($pattern in $searchPatterns) {
                        if ($key.PSChildName -match $pattern) {
                            $results += "Реєстр (ключ): $($key.Name)"
                            $foundInRegistry++
                        }
                    }

                    # Пошук в значеннях
                    $values = Get-ItemProperty $key.PSPath -ErrorAction SilentlyContinue
                    if ($values) {
                        $values.PSObject.Properties | ForEach-Object {
                            $value = $_.Value
                            if ($value -ne $null) {
                                foreach ($pattern in $searchPatterns) {
                                    if ($value.ToString() -match $pattern) {
                                        $results += "Реєстр (значення): $($key.Name) -> $($_.Name)"
                                        $foundInRegistry++
                                    }
                                }
                            }
                        }
                    }
                }
            } catch {}
        }
    }
    Write-Host " [$foundInRegistry знайдено]" -ForegroundColor $(if($foundInRegistry-gt0){'Red'}else{'Green'})

    # 3. Перевірка Event Logs
    Write-Host "3. Аналіз Event Logs..." -NoNewline
    $eventLogs = @(
        @{LogName = "Security"; ID = 4688},
        @{LogName = "System"; ID = 7036},
        @{LogName = "Microsoft-Windows-PowerShell/Operational"; ID = 4104}
    )

    $foundInEvents = 0
    foreach ($log in $eventLogs) {
        try {
            $events = Get-WinEvent -FilterHashtable @{LogName = $log.LogName; ID = $log.ID} -ErrorAction SilentlyContinue -MaxEvents 100
            foreach ($event in $events) {
                foreach ($pattern in $searchPatterns) {
                    if ($event.Message -match $pattern) {
                        $results += "Event Log: $($log.LogName) - $($event.TimeCreated)"
                        $foundInEvents++
                        break
                    }
                }
            }
        } catch {}
    }
    Write-Host " [$foundInEvents знайдено]" -ForegroundColor $(if($foundInEvents-gt0){'Red'}else{'Green'})

    # 4. Перевірка Recent
    Write-Host "4. Аналіз Recent..." -NoNewline
    $foundInRecent = 0
    $recentPaths = @(
        "$env:APPDATA\Microsoft\Windows\Recent",
        "$env:APPDATA\Microsoft\Windows\Recent\AutomaticDestinations"
    )

    foreach ($recentPath in $recentPaths) {
        if (Test-Path $recentPath) {
            try {
                $items = Get-ChildItem $recentPath -ErrorAction SilentlyContinue
                foreach ($item in $items) {
                    foreach ($pattern in $searchPatterns) {
                        if ($item.Name -match $pattern -or (Test-Path $item.FullName -PathType Container -ErrorAction SilentlyContinue)) {
                            $results += "Recent: $($item.FullName)"
                            $foundInRecent++
                            break
                        }
                    }
                }
            } catch {}
        }
    }
    Write-Host " [$foundInRecent знайдено]" -ForegroundColor $(if($foundInRecent-gt0){'Red'}else{'Green'})

    # 5. Перевірка Temp
    Write-Host "5. Аналіз Temp..." -NoNewline
    $tempPaths = @($env:TEMP, "$env:SystemRoot\Temp")
    $foundInTemp = 0

    foreach ($tempPath in $tempPaths) {
        if (Test-Path $tempPath) {
            try {
                Get-ChildItem $tempPath -ErrorAction SilentlyContinue | ForEach-Object {
                    foreach ($pattern in $searchPatterns) {
                        if ($_.Name -match $pattern) {
                            $results += "Temp: $($_.FullName)"
                            $foundInTemp++
                            break
                        }
                    }
                }
            } catch {}
        }
    }
    Write-Host " [$foundInTemp знайдено]" -ForegroundColor $(if($foundInTemp-gt0){'Red'}else{'Green'})

    # Підсумок
    $totalFound = $foundInPrefetch + $foundInRegistry + $foundInEvents + $foundInRecent + $foundInTemp

    Write-Host ""
    Write-Host "Результат пошуку:" -ForegroundColor Cyan
    Write-Host "Всього знайдено згадок: $totalFound" -ForegroundColor $(if($totalFound-gt0){'Yellow'}else{'Green'})

    if ($totalFound -gt 0) {
        Write-Host "Знайдені згадки:" -ForegroundColor Yellow
        foreach ($result in $results) {
            Write-Host "  - $result" -ForegroundColor Gray
        }
    }

    return @{
        Total = $totalFound
        Details = $results
        Counts = @{
            Prefetch = $foundInPrefetch
            Registry = $foundInRegistry
            Events = $foundInEvents
            Recent = $foundInRecent
            Temp = $foundInTemp
        }
    }
}

function Clean-BankFile-Traces {
    param([switch]$FullMode = $false)

    $searchPatterns = @('b[аa]nk\.exe', 'bаnk.exe')
    $cleanedCount = 0
    $errors = 0

    Write-Host "`nПочинаю очищення слідів..." -ForegroundColor Cyan

    # 1. Очищення Prefetch
    Write-Host "1. Очищення Prefetch..." -NoNewline
    $pfFiles = Get-ChildItem "C:\Windows\Prefetch" -Filter "*.pf" -ErrorAction SilentlyContinue
    $deletedPrefetch = 0
    foreach ($pf in $pfFiles) {
        try {
            $content = Get-Content $pf.FullName -Raw -ErrorAction SilentlyContinue
            foreach ($pattern in $searchPatterns) {
                if ($content -match $pattern) {
                    Remove-Item $pf.FullName -Force -ErrorAction SilentlyContinue
                    $deletedPrefetch++
                    $cleanedCount++
                    break
                }
            }
        } catch {
            $errors++
        }
    }
    Write-Host " [$deletedPrefetch видалено]" -ForegroundColor $(if($deletedPrefetch-gt0){'Green'}else{'Gray'})

    # 2. Очищення реєстру
    Write-Host "2. Очищення реєстру..." -NoNewline
    $registryPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs"
    )

    $deletedRegistry = 0
    foreach ($regPath in $registryPaths) {
        if (Test-Path $regPath) {
            try {
                Get-ChildItem $regPath -ErrorAction SilentlyContinue | ForEach-Object {
                    $key = $_
                    $shouldDelete = $false

                    # Перевірка імені ключа
                    foreach ($pattern in $searchPatterns) {
                        if ($key.PSChildName -match $pattern) {
                            $shouldDelete = $true
                            break
                        }
                    }

                    # Перевірка значень
                    $values = Get-ItemProperty $key.PSPath -ErrorAction SilentlyContinue
                    if ($values) {
                        $values.PSObject.Properties | ForEach-Object {
                            $value = $_.Value
                            if ($value -ne $null) {
                                foreach ($pattern in $searchPatterns) {
                                    if ($value.ToString() -match $pattern) {
                                        Remove-ItemProperty -Path $key.PSPath -Name $_.Name -Force -ErrorAction SilentlyContinue
                                        $deletedRegistry++
                                        $cleanedCount++
                                    }
                                }
                            }
                        }
                    }

                    if ($shouldDelete) {
                        Remove-Item $key.PSPath -Recurse -Force -ErrorAction SilentlyContinue
                        $deletedRegistry++
                        $cleanedCount++
                    }
                }
            } catch {
                $errors++
            }
        }
    }
    Write-Host " [$deletedRegistry видалено]" -ForegroundColor $(if($deletedRegistry-gt0){'Green'}else{'Gray'})

    # 3. Очищення Event Logs
    Write-Host "3. Очищення Event Logs..." -NoNewline
    $eventLogs = @("Security", "System", "Microsoft-Windows-PowerShell/Operational")
    $cleanedLogs = 0

    foreach ($logName in $eventLogs) {
        try {
            wevtutil cl $logName 2>$null
            $cleanedLogs++
            $cleanedCount++
        } catch {
            $errors++
        }
    }
    Write-Host " [$cleanedLogs очищено]" -ForegroundColor $(if($cleanedLogs-gt0){'Green'}else{'Gray'})

    # 4. Очищення Recent
    Write-Host "4. Очищення Recent..." -NoNewline
    $recentPaths = @(
        "$env:APPDATA\Microsoft\Windows\Recent",
        "$env:APPDATA\Microsoft\Windows\Recent\AutomaticDestinations"
    )

    $cleanedRecent = 0
    foreach ($recentPath in $recentPaths) {
        if (Test-Path $recentPath) {
            try {
                Remove-Item "$recentPath\*" -Recurse -Force -ErrorAction SilentlyContinue
                $cleanedRecent++
                $cleanedCount++
            } catch {
                $errors++
            }
        }
    }
    Write-Host " [$cleanedRecent очищено]" -ForegroundColor $(if($cleanedRecent-gt0){'Green'}else{'Gray'})

    # 5. Очищення Temp
    Write-Host "5. Очищення Temp..." -NoNewline
    $tempPaths = @($env:TEMP, "$env:SystemRoot\Temp")
    $cleanedTemp = 0

    foreach ($tempPath in $tempPaths) {
        if (Test-Path $tempPath) {
            try {
                Get-ChildItem $tempPath -ErrorAction SilentlyContinue | ForEach-Object {
                    foreach ($pattern in $searchPatterns) {
                        if ($_.Name -match $pattern) {
                            Remove-Item $_.FullName -Force -Recurse -ErrorAction SilentlyContinue
                            $cleanedTemp++
                            $cleanedCount++
                            break
                        }
                    }
                }
            } catch {
                $errors++
            }
        }
    }
    Write-Host " [$cleanedTemp видалено]" -ForegroundColor $(if($cleanedTemp-gt0){'Green'}else{'Gray'})

    # 6. Очищення Windows Search (якщо FullMode)
    if ($FullMode) {
        Write-Host "6. Очищення Windows Search..." -NoNewline
        try {
            Stop-Service "WSearch" -Force -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 1
            $searchPaths = @("C:\ProgramData\Microsoft\Search\Data\Applications\Windows", "$env:APPDATA\Microsoft\Search\Data")
            foreach ($searchPath in $searchPaths) {
                if (Test-Path $searchPath) {
                    Get-ChildItem $searchPath -Filter "*.edb" -ErrorAction SilentlyContinue | Remove-Item -Force
                }
            }
            Start-Service "WSearch" -ErrorAction SilentlyContinue
            $cleanedCount++
            Write-Host " [виконано]" -ForegroundColor Green
        } catch {
            $errors++
            Write-Host " [помилка]" -ForegroundColor Red
        }
    }

    # 7. USN Journal (якщо FullMode)
    if ($FullMode) {
        Write-Host "7. Очищення USN Journal..." -NoNewline
        try {
            fsutil usn deletejournal /D C: 2>$null
            $cleanedCount++
            Write-Host " [виконано]" -ForegroundColor Green
        } catch {
            $errors++
            Write-Host " [помилка]" -ForegroundColor Red
        }
    }

    # 8. Очищення історії PowerShell
    Write-Host "8. Очищення історії..." -NoNewline
    try {
        Clear-History
        Remove-Item (Get-PSReadlineOption).HistorySavePath -ErrorAction SilentlyContinue 2>$null
        Write-Host " [виконано]" -ForegroundColor Green
    } catch {
        $errors++
        Write-Host " [помилка]" -ForegroundColor Red
    }

    return @{
        Cleaned = $cleanedCount
        Errors = $errors
        Details = @{
            Prefetch = $deletedPrefetch
            Registry = $deletedRegistry
            Events = $cleanedLogs
            Recent = $cleanedRecent
            Temp = $cleanedTemp
        }
    }
}

# ===== Головна частина =====
Write-Host "=== System Trace Cleaner ===" -ForegroundColor Blue
Write-Host "Пошук та видалення слідів файла bаnk.exe" -ForegroundColor Gray
Write-Host ""

# Пошук слідів
$searchResults = Find-BankFile-Traces

if ($searchResults.Total -eq 0) {
    Write-Host ""
    Write-Host "="*50 -ForegroundColor Green
    Write-Host "✅ ЗГАДКИ ПРО ФАЙЛ НЕ ЗНАЙДЕНО" -ForegroundColor Green
    Write-Host "Система чиста, слідів файла немає" -ForegroundColor Green
    Write-Host "="*50 -ForegroundColor Green
    Start-Sleep -Seconds 3
    exit 0
}

Write-Host ""
Write-Host "Знайдено $($searchResults.Total) згадок. Продовжити очищення?" -ForegroundColor Yellow
$response = Read-Host "Введіть Y для очищення або N для скасування"

if ($response -ne 'Y') {
    Write-Host "`nОчищення скасовано" -ForegroundColor Red
    Start-Sleep -Seconds 2
    exit 0
}

Write-Host ""
$fullModeResponse = Read-Host "Запустити повне очищення (включаючи USN Journal)? (Y/N)"
$fullMode = ($fullModeResponse -eq 'Y')

# Очищення слідів
$cleanResults = Clean-BankFile-Traces -FullMode:$fullMode

Write-Host ""
Write-Host "="*50 -ForegroundColor Cyan
Write-Host "РЕЗУЛЬТАТ ОЧИЩЕННЯ:" -ForegroundColor Cyan

if ($cleanResults.Cleaned -gt 0) {
    Write-Host "✅ ОПЕРАЦІЯ УСПІШНА" -ForegroundColor Green
    Write-Host "Видалено $($cleanResults.Cleaned) згадок про файл" -ForegroundColor Green

    Write-Host "`nДеталі:" -ForegroundColor Yellow
    if ($cleanResults.Details.Prefetch -gt 0) { Write-Host "  • Prefetch: $($cleanResults.Details.Prefetch)" -ForegroundColor Gray }
    if ($cleanResults.Details.Registry -gt 0) { Write-Host "  • Реєстр: $($cleanResults.Details.Registry)" -ForegroundColor Gray }
    if ($cleanResults.Details.Events -gt 0) { Write-Host "  • Event Logs: $($cleanResults.Details.Events)" -ForegroundColor Gray }
    if ($cleanResults.Details.Recent -gt 0) { Write-Host "  • Recent: $($cleanResults.Details.Recent)" -ForegroundColor Gray }
    if ($cleanResults.Details.Temp -gt 0) { Write-Host "  • Temp: $($cleanResults.Details.Temp)" -ForegroundColor Gray }

    if ($cleanResults.Errors -gt 0) {
        Write-Host "`nПопередження: $($cleanResults.Errors) помилок під час очищення" -ForegroundColor Yellow
    }
} else {
    Write-Host "⚠️  НІЧОГО НЕ ВИДАЛЕНО" -ForegroundColor Yellow
    Write-Host "Не вдалося видалити знайдені сліди" -ForegroundColor Yellow
}

Write-Host "="*50 -ForegroundColor Cyan
Write-Host ""

if ($cleanResults.Cleaned -gt 0) {
    Write-Host "Рекомендації:" -ForegroundColor Gray
    Write-Host "- Для повного ефекту перезавантажте систему" -ForegroundColor Gray
    Write-Host "- Уникайте повторного запуску підозрілих файлів" -ForegroundColor Gray
}

Start-Sleep -Seconds 5