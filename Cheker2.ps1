function Find-BankFile-Traces {
    Write-Host "Пошук слідів файла bаnk.exe..." -ForegroundColor Cyan
    
    $searchPatterns = @(
        'b[аa]nk\.exe',
        'bаnk\.exe',
        'bank\.exe',
        'b[^a-zA-Z0-9\s\.]nk\.exe',
        'b.*nk\.exe',
        'b¦-nk\.exe',
        'b[^\x00-\x7F]nk\.exe',
        'b.*\.exe.*nk'
        'D:\\projects\\c#\\laba1',
        'D:\\projects\\c#\\la.*nk'
    )
    
    $results = @()
    
    # 1. Пошук у Results.txt та інших звітах
    Write-Host "1. Аналіз звітів..." -NoNewline
    $reportFiles = @(
        "C:\Temp\Results.txt",
        "C:\Temp\Dump\Paths.txt",
        "C:\Temp\Dump\Deletedfile.txt",
        "C:\Temp\Dump\Unsigned.txt"
    )
    
    $foundInReports = 0
    foreach ($reportFile in $reportFiles) {
        if (Test-Path $reportFile) {
            try {
                $lines = Get-Content $reportFile -ErrorAction SilentlyContinue
                if ($lines) {
                    for ($i = 0; $i -lt $lines.Count; $i++) {
                        foreach ($pattern in $searchPatterns) {
                            if ($lines[$i] -match $pattern) {
                                $results += "Звіт ($([System.IO.Path]::GetFileName($reportFile))): Рядок $($i+1): $($lines[$i])"
                                $foundInReports++
                                break
                            }
                        }
                    }
                }
            } catch {}
        }
    }
    Write-Host " [$foundInReports знайдено]" -ForegroundColor $(if($foundInReports-gt0){'Red'}else{'Green'})
    
    # 2. Пошук у Journal файлах
    Write-Host "2. Аналіз Journal..." -NoNewline
    $journalFiles = Get-ChildItem "C:\Temp\Dump\Journal" -Filter "*.txt" -ErrorAction SilentlyContinue
    $foundInJournal = 0
    
    foreach ($journalFile in $journalFiles) {
        try {
            $lines = Get-Content $journalFile.FullName -ErrorAction SilentlyContinue
            if ($lines) {
                for ($i = 0; $i -lt $lines.Count; $i++) {
                    foreach ($pattern in $searchPatterns) {
                        if ($lines[$i] -match $pattern) {
                            $results += "Journal ($($journalFile.Name)): Рядок $($i+1): $($lines[$i])"
                            $foundInJournal++
                            break
                        }
                    }
                }
            }
        } catch {}
    }
    Write-Host " [$foundInJournal знайдено]" -ForegroundColor $(if($foundInJournal-gt0){'Red'}else{'Green'})
    
    # 3. Пошук у Deletedfile.txt (окремо, бо це ключовий файл)
    Write-Host "3. Перевірка Deletedfile.txt..." -NoNewline
    $deletedFilePath = "C:\Temp\Dump\Deletedfile.txt"
    $foundInDeleted = 0
    
    if (Test-Path $deletedFilePath) {
        try {
            $lines = Get-Content $deletedFilePath -ErrorAction SilentlyContinue
            if ($lines) {
                for ($i = 0; $i -lt $lines.Count; $i++) {
                    if ($lines[$i] -match 'D:\\projects\\c#\\la') {
                        $results += "Deletedfile.txt: Рядок $($i+1): $($lines[$i])"
                        $foundInDeleted++
                    }
                }
            }
        } catch {}
    }
    Write-Host " [$foundInDeleted знайдено]" -ForegroundColor $(if($foundInDeleted-gt0){'Red'}else{'Green'})
    
    $totalFound = $foundInReports + $foundInJournal + $foundInDeleted
    
    Write-Host ""
    Write-Host "="*50 -ForegroundColor Cyan
    Write-Host "РЕЗУЛЬТАТ ПОШУКУ:" -ForegroundColor Cyan
    Write-Host "Всього знайдено згадок: $totalFound" -ForegroundColor $(if($totalFound-gt0){'Yellow'}else{'Green'})
    
    if ($totalFound -gt 0) {
        Write-Host "`nЗнайдені згадки:" -ForegroundColor Yellow
        foreach ($result in $results | Select-Object -First 10) {
            Write-Host "  • $result" -ForegroundColor Gray
        }
        if ($results.Count -gt 10) {
            Write-Host "  • ... та ще $($results.Count - 10) інших" -ForegroundColor Gray
        }
    }
    
    return @{
        Total = $totalFound
        Details = $results
        Counts = @{
            Reports = $foundInReports
            Journal = $foundInJournal
            DeletedFile = $foundInDeleted
        }
    }
}

function Clean-BankFile-Traces {
    Write-Host "`nПочинаю очищення слідів..." -ForegroundColor Cyan
    $cleanedCount = 0
    $errors = 0
    
    # Патерни для пошуку
    $patternsToRemove = @(
        'D:\\projects\\c#\\laba1',
        'D:\\projects\\c#\\la.*nk',
        'b[аa]nk\.exe',
        'b.*nk\.exe',
        'File Deleted.*laba1',
        'File Deleted.*bank'
    )
    
    # 1. Очищення Deletedfile.txt (головна проблема)
    Write-Host "1. Очищення Deletedfile.txt..." -NoNewline
    $deletedFilePath = "C:\Temp\Dump\Deletedfile.txt"
    $deletedLines = 0
    
    if (Test-Path $deletedFilePath) {
        try {
            $lines = Get-Content $deletedFilePath -ErrorAction SilentlyContinue
            if ($lines) {
                # Фільтруємо рядки, що НЕ містять згадок про наш файл
                $newLines = @()
                foreach ($line in $lines) {
                    $shouldKeep = $true
                    foreach ($pattern in $patternsToRemove) {
                        if ($line -match $pattern) {
                            $shouldKeep = $false
                            $deletedLines++
                            break
                        }
                    }
                    if ($shouldKeep) {
                        $newLines += $line
                    }
                }
                
                # Зберігаємо новий вміст
                if ($deletedLines -gt 0) {
                    Set-Content -Path $deletedFilePath -Value $newLines -Force -ErrorAction SilentlyContinue
                    $cleanedCount += $deletedLines
                    Write-Host " [$deletedLines рядків видалено]" -ForegroundColor Green
                } else {
                    Write-Host " [немає згадок]" -ForegroundColor Gray
                }
            } else {
                Write-Host " [файл порожній]" -ForegroundColor Gray
            }
        } catch {
            $errors++
            Write-Host " [помилка]" -ForegroundColor Red
        }
    } else {
        Write-Host " [файл не існує]" -ForegroundColor Gray
    }
    
    # 2. Очищення Results.txt
    Write-Host "2. Очищення Results.txt..." -NoNewline
    $resultsPath = "C:\Temp\Results.txt"
    $resultsLines = 0
    
    if (Test-Path $resultsPath) {
        try {
            $lines = Get-Content $resultsPath -ErrorAction SilentlyContinue
            if ($lines) {
                $newLines = @()
                foreach ($line in $lines) {
                    $shouldKeep = $true
                    foreach ($pattern in $patternsToRemove) {
                        if ($line -match $pattern) {
                            $shouldKeep = $false
                            $resultsLines++
                            break
                        }
                    }
                    if ($shouldKeep) {
                        $newLines += $line
                    }
                }
                
                if ($resultsLines -gt 0) {
                    Set-Content -Path $resultsPath -Value $newLines -Force -ErrorAction SilentlyContinue
                    $cleanedCount += $resultsLines
                    Write-Host " [$resultsLines рядків видалено]" -ForegroundColor Green
                } else {
                    Write-Host " [немає згадок]" -ForegroundColor Gray
                }
            }
        } catch {
            $errors++
            Write-Host " [помилка]" -ForegroundColor Red
        }
    } else {
        Write-Host " [файл не існує]" -ForegroundColor Gray
    }
    
    # 3. Очищення Paths.txt
    Write-Host "3. Очищення Paths.txt..." -NoNewline
    $pathsPath = "C:\Temp\Dump\Paths.txt"
    $pathsLines = 0
    
    if (Test-Path $pathsPath) {
        try {
            $lines = Get-Content $pathsPath -ErrorAction SilentlyContinue
            if ($lines) {
                $newLines = @()
                foreach ($line in $lines) {
                    $shouldKeep = $true
                    foreach ($pattern in $patternsToRemove) {
                        if ($line -match $pattern) {
                            $shouldKeep = $false
                            $pathsLines++
                            break
                        }
                    }
                    if ($shouldKeep) {
                        $newLines += $line
                    }
                }
                
                if ($pathsLines -gt 0) {
                    Set-Content -Path $pathsPath -Value $newLines -Force -ErrorAction SilentlyContinue
                    $cleanedCount += $pathsLines
                    Write-Host " [$pathsLines рядків видалено]" -ForegroundColor Green
                } else {
                    Write-Host " [немає згадок]" -ForegroundColor Gray
                }
            }
        } catch {
            $errors++
            Write-Host " [помилка]" -ForegroundColor Red
        }
    } else {
        Write-Host " [файл не існує]" -ForegroundColor Gray
    }
    
    # 4. Очищення Journal файлів
    Write-Host "4. Очищення Journal файлів..." -NoNewline
    $journalFiles = Get-ChildItem "C:\Temp\Dump\Journal" -Filter "*.txt" -ErrorAction SilentlyContinue
    $journalLines = 0
    
    foreach ($journalFile in $journalFiles) {
        try {
            $lines = Get-Content $journalFile.FullName -ErrorAction SilentlyContinue
            if ($lines) {
                $newLines = @()
                foreach ($line in $lines) {
                    $shouldKeep = $true
                    foreach ($pattern in $patternsToRemove) {
                        if ($line -match $pattern) {
                            $shouldKeep = $false
                            $journalLines++
                            break
                        }
                    }
                    if ($shouldKeep) {
                        $newLines += $line
                    }
                }
                
                if ($newLines.Count -ne $lines.Count) {
                    Set-Content -Path $journalFile.FullName -Value $newLines -Force -ErrorAction SilentlyContinue
                }
            }
        } catch {
            $errors++
        }
    }
    
    if ($journalLines -gt 0) {
        $cleanedCount += $journalLines
        Write-Host " [$journalLines рядків]" -ForegroundColor Green
    } else {
        Write-Host " [немає згадок]" -ForegroundColor Gray
    }
    
    # 5. Видалення порожніх файлів
    Write-Host "5. Видалення порожніх файлів..." -NoNewline
    $emptyFilesDeleted = 0
    $filesToCheck = @($deletedFilePath, $resultsPath, $pathsPath)
    
    foreach ($file in $filesToCheck) {
        if (Test-Path $file) {
            try {
                $content = Get-Content $file -Raw -ErrorAction SilentlyContinue
                if ([string]::IsNullOrWhiteSpace($content)) {
                    Remove-Item $file -Force -ErrorAction SilentlyContinue
                    $emptyFilesDeleted++
                }
            } catch {}
        }
    }
    
    Write-Host " [$emptyFilesDeleted файлів]" -ForegroundColor $(if($emptyFilesDeleted-gt0){'Green'}else{'Gray'})
    
    # 6. Очищення USN Journal
    Write-Host "6. Очищення USN Journal..." -NoNewline
    try {
        fsutil usn deletejournal /D C: 2>$null
        $cleanedCount++
        Write-Host " [виконано]" -ForegroundColor Green
    } catch {
        $errors++
        Write-Host " [помилка]" -ForegroundColor Red
    }
    
    # 7. Очищення Prefetch
    Write-Host "7. Очищення Prefetch..." -NoNewline
    $pfFiles = Get-ChildItem "C:\Windows\Prefetch" -Filter "*.pf" -ErrorAction SilentlyContinue
    $deletedPrefetch = 0
    
    foreach ($pf in $pfFiles) {
        try {
            $content = Get-Content $pf.FullName -Raw -ErrorAction SilentlyContinue
            if ($content) {
                foreach ($pattern in $patternsToRemove) {
                    if ($content -match $pattern) {
                        Remove-Item $pf.FullName -Force -ErrorAction SilentlyContinue
                        $deletedPrefetch++
                        break
                    }
                }
            }
        } catch {
            $errors++
        }
    }
    
    if ($deletedPrefetch -gt 0) {
        $cleanedCount += $deletedPrefetch
        Write-Host " [$deletedPrefetch файлів]" -ForegroundColor Green
    } else {
        Write-Host " [немає згадок]" -ForegroundColor Gray
    }
    
    # 8. Очищення реєстру
    Write-Host "8. Очищення реєстру..." -NoNewline
    $registryPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"
    )
    
    $cleanedRegistry = 0
    foreach ($regPath in $registryPaths) {
        if (Test-Path $regPath) {
            try {
                Get-ChildItem $regPath -ErrorAction SilentlyContinue | ForEach-Object {
                    $key = $_
                    
                    # Перевірка імені ключа
                    foreach ($pattern in $patternsToRemove) {
                        if ($key.PSChildName -match $pattern) {
                            Remove-Item $key.PSPath -Recurse -Force -ErrorAction SilentlyContinue
                            $cleanedRegistry++
                            break
                        }
                    }
                    
                    # Перевірка значень
                    $values = Get-ItemProperty $key.PSPath -ErrorAction SilentlyContinue
                    if ($values) {
                        $values.PSObject.Properties | ForEach-Object {
                            $value = $_.Value
                            if ($value -ne $null) {
                                foreach ($pattern in $patternsToRemove) {
                                    if ($value.ToString() -match $pattern) {
                                        Remove-ItemProperty -Path $key.PSPath -Name $_.Name -Force -ErrorAction SilentlyContinue
                                        $cleanedRegistry++
                                    }
                                }
                            }
                        }
                    }
                }
            } catch {
                $errors++
            }
        }
    }
    
    Write-Host " [$cleanedRegistry записів]" -ForegroundColor $(if($cleanedRegistry-gt0){'Green'}else{'Gray'})
    
    # 9. Очищення кешу
    Write-Host "9. Очищення кешу..." -NoNewline
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
        LinesRemoved = $deletedLines + $resultsLines + $pathsLines + $journalLines
    }
}

# ===== Головна частина =====
Write-Host "=== Trace Cleaner ===" -ForegroundColor Blue
Write-Host "Пошук та видалення слідів файла" -ForegroundColor Gray
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

# Очищення
Write-Host ""
$cleanResults = Clean-BankFile-Traces

Write-Host ""
Write-Host "="*50 -ForegroundColor Cyan
Write-Host "РЕЗУЛЬТАТ ОЧИЩЕННЯ:" -ForegroundColor Cyan

if ($cleanResults.Cleaned -gt 0) {
    Write-Host "✅ ОПЕРАЦІЯ УСПІШНА" -ForegroundColor Green
    Write-Host "Видалено $($cleanResults.Cleaned) слідів файла" -ForegroundColor Green
    Write-Host "Видалено $($cleanResults.LinesRemoved) рядків зі згадками" -ForegroundColor Green
    
    # Перевірка після очищення
    Write-Host "`nОстаточна перевірка..." -ForegroundColor Cyan
    $finalCheck = Find-BankFile-Traces
    
    if ($finalCheck.Total -eq 0) {
        Write-Host "✅ Всі згадки успішно видалені" -ForegroundColor Green
    } else {
        Write-Host "⚠️  Залишилося $($finalCheck.Total) згадок" -ForegroundColor Yellow
    }
} else {
    Write-Host "⚠️  НІЧОГО НЕ ВИДАЛЕНО" -ForegroundColor Yellow
    Write-Host "Не вдалося видалити знайдені сліди" -ForegroundColor Yellow
}

if ($cleanResults.Errors -gt 0) {
    Write-Host "`nПопередження: $($cleanResults.Errors) помилок під час очищення" -ForegroundColor Yellow
}

Write-Host "="*50 -ForegroundColor Cyan
Write-Host ""

if ($cleanResults.Cleaned -gt 0) {
    Write-Host "Рекомендації:" -ForegroundColor Gray
    Write-Host "- Рядки 'File Deleted: D:\projects\c#\la...' були повністю видалені" -ForegroundColor Gray
    Write-Host "- USN Journal очищений" -ForegroundColor Gray
    Write-Host "- Prefetch файли очищені" -ForegroundColor Gray
}

Start-Sleep -Seconds 5