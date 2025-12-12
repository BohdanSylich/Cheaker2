function Find-BankFile-Traces {
    Write-Host "Пошук слідів файла bаnk.exe (всі варіанти)..." -ForegroundColor Cyan
    
    # Всі можливі варіанти назви файла
    $searchPatterns = @(
        'b[аa]nk\.exe',           # звичайні варіанти
        'bаnk\.exe',             # точна назва з кирилицею
        'bank\.exe',             # з латинською
        'b[^a-zA-Z0-9\s\.]nk\.exe',  # зі спецсимволами між b і nk
        'b.*nk\.exe',            # будь-які символи між b і nk
        'b¦-nk\.exe',            # конкретно твій варіант
        'b[^\x00-\x7F]nk\.exe',  # з Unicode символами
        'b.*\.exe.*nk'           # в будь-якому місці
    )
    
    $results = @()
    
    # 1. Перевірка USN Journal (Journal)
    Write-Host "1. Аналіз USN Journal..." -NoNewline
    $journalPath = "C:\Temp\Dump\Journal"  # або де у тебе журнал
    $foundInJournal = 0
    
    if (Test-Path $journalPath) {
        $journalFiles = Get-ChildItem $journalPath -Filter "*.csv" -ErrorAction SilentlyContinue
        foreach ($file in $journalFiles) {
            try {
                $content = Get-Content $file.FullName -Raw -ErrorAction SilentlyContinue
                if ($content) {
                    foreach ($pattern in $searchPatterns) {
                        $matches = [regex]::Matches($content, $pattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
                        if ($matches.Count -gt 0) {
                            foreach ($match in $matches) {
                                $results += "USN Journal ($($file.Name)): $($match.Value)"
                                $foundInJournal++
                            }
                        }
                    }
                }
            } catch {}
        }
    }
    Write-Host " [$foundInJournal знайдено]" -ForegroundColor $(if($foundInJournal-gt0){'Red'}else{'Green'})
    
    # 2. Перевірка Prefetch
    Write-Host "2. Аналіз Prefetch..." -NoNewline
    $foundInPrefetch = 0
    $pfFiles = Get-ChildItem "C:\Windows\Prefetch" -Filter "*.pf" -ErrorAction SilentlyContinue
    
    foreach ($pf in $pfFiles) {
        try {
            $content = Get-Content $pf.FullName -Raw -ErrorAction SilentlyContinue
            if ($content) {
                foreach ($pattern in $searchPatterns) {
                    if ($content -match $pattern) {
                        $results += "Prefetch: $($pf.Name) -> знайдено '$pattern'"
                        $foundInPrefetch++
                        break
                    }
                }
            }
        } catch {}
    }
    Write-Host " [$foundInPrefetch знайдено]" -ForegroundColor $(if($foundInPrefetch-gt0){'Red'}else{'Green'})
    
    # 3. Перевірка реєстру
    Write-Host "3. Аналіз реєстру..." -NoNewline
    $registryPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs"
    )
    
    $foundInRegistry = 0
    foreach ($regPath in $registryPaths) {
        if (Test-Path $regPath) {
            try {
                Get-ChildItem $regPath -ErrorAction SilentlyContinue | ForEach-Object {
                    $key = $_
                    
                    # Пошук в імені ключа
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
                                $valueStr = $value.ToString()
                                foreach ($pattern in $searchPatterns) {
                                    if ($valueStr -match $pattern) {
                                        $results += "Реєстр (значення): $($key.Name)\$($_.Name) -> $valueStr"
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
    
    # 4. Перевірка Journal файлів (якщо вони в Temp\Dump)
    Write-Host "4. Аналіз Journal файлів..." -NoNewline
    $foundInJournalFiles = 0
    $journalFilesToCheck = @(
        "C:\Temp\Dump\Journal\0_RawDump.csv",
        "C:\Temp\Dump\Journal\CreatedFiles.txt",
        "C:\Temp\Dump\Journal\DeletedFiles.txt",
        "C:\Temp\Dump\Journal\Keywordsearch.txt"
    )
    
    foreach ($journalFile in $journalFilesToCheck) {
        if (Test-Path $journalFile) {
            try {
                $content = Get-Content $journalFile -Raw -ErrorAction SilentlyContinue
                if ($content) {
                    foreach ($pattern in $searchPatterns) {
                        $matches = [regex]::Matches($content, $pattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
                        if ($matches.Count -gt 0) {
                            foreach ($match in $matches) {
                                $results += "Journal файл ($([System.IO.Path]::GetFileName($journalFile))): $($match.Value)"
                                $foundInJournalFiles++
                            }
                        }
                    }
                }
            } catch {}
        }
    }
    Write-Host " [$foundInJournalFiles знайдено]" -ForegroundColor $(if($foundInJournalFiles-gt0){'Red'}else{'Green'})
    
    # 5. Перевірка процесів (Raw процеси)
    Write-Host "5. Аналіз процесів..." -NoNewline
    $foundInProcesses = 0
    $processFiles = @(
        "C:\Temp\Dump\Processes\Raw\explorer.txt",
        "C:\Temp\Dump\Processes\Raw\dps.txt",
        "C:\Temp\Dump\Processes\Raw\wsearch.txt"
    )
    
    foreach ($procFile in $processFiles) {
        if (Test-Path $procFile) {
            try {
                $content = Get-Content $procFile -Raw -ErrorAction SilentlyContinue
                if ($content) {
                    foreach ($pattern in $searchPatterns) {
                        $matches = [regex]::Matches($content, $pattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
                        if ($matches.Count -gt 0) {
                            foreach ($match in $matches) {
                                $results += "Процеси ($([System.IO.Path]::GetFileName($procFile))): $($match.Value)"
                                $foundInProcesses++
                            }
                        }
                    }
                }
            } catch {}
        }
    }
    Write-Host " [$foundInProcesses знайдено]" -ForegroundColor $(if($foundInProcesses-gt0){'Red'}else{'Green'})
    
    # Підсумок
    $totalFound = $foundInJournal + $foundInPrefetch + $foundInRegistry + $foundInJournalFiles + $foundInProcesses
    
    Write-Host ""
    Write-Host "="*50 -ForegroundColor Cyan
    Write-Host "РЕЗУЛЬТАТ ПОШУКУ:" -ForegroundColor Cyan
    Write-Host "Всього знайдено згадок: $totalFound" -ForegroundColor $(if($totalFound-gt0){'Yellow'}else{'Green'})
    
    if ($totalFound -gt 0) {
        Write-Host "`nЗнайдені згадки:" -ForegroundColor Yellow
        foreach ($result in $results | Select-Object -Unique) {
            Write-Host "  • $result" -ForegroundColor Gray
        }
    }
    
    return @{
        Total = $totalFound
        Details = $results | Select-Object -Unique
        Counts = @{
            Journal = $foundInJournal
            Prefetch = $foundInPrefetch
            Registry = $foundInRegistry
            JournalFiles = $foundInJournalFiles
            Processes = $foundInProcesses
        }
    }
}

function Clean-BankFile-Traces-All {
    param([switch]$FullMode = $false)
    
    # Всі можливі варіанти назви
    $searchPatterns = @(
        'b[аa]nk\.exe',
        'bаnk\.exe',
        'bank\.exe',
        'b[^a-zA-Z0-9\s\.]nk\.exe',
        'b.*nk\.exe',
        'b¦-nk\.exe',
        'b[^\x00-\x7F]nk\.exe',
        'b.*\.exe.*nk'
    )
    
    $cleanedCount = 0
    $errors = 0
    
    Write-Host "`nПочинаю очищення всіх слідів..." -ForegroundColor Cyan
    
    # 1. Очищення Journal файлів (спеціально для твого випадку)
    Write-Host "1. Очищення Journal файлів..." -NoNewline
    $journalFiles = @(
        "C:\Temp\Dump\Journal\0_RawDump.csv",
        "C:\Temp\Dump\Journal\CreatedFiles.txt",
        "C:\Temp\Dump\Journal\DeletedFiles.txt",
        "C:\Temp\Dump\Journal\Keywordsearch.txt",
        "C:\Temp\Dump\Journal\ModifiedBats.txt",
        "C:\Temp\Dump\Journal\ObjectIDChange.txt",
        "C:\Temp\Dump\Journal\ReplacedExe.txt"
    )
    
    $cleanedJournal = 0
    foreach ($journalFile in $journalFiles) {
        if (Test-Path $journalFile) {
            try {
                $content = Get-Content $journalFile -Raw -ErrorAction SilentlyContinue
                if ($content) {
                    $modified = $false
                    $newContent = $content
                    
                    foreach ($pattern in $searchPatterns) {
                        $newContent = $newContent -replace $pattern, "[REMOVED]"
                    }
                    
                    if ($newContent -ne $content) {
                        Set-Content -Path $journalFile -Value $newContent -Force -ErrorAction SilentlyContinue
                        $cleanedJournal++
                        $cleanedCount++
                        $modified = $true
                    }
                    
                    if ($modified) {
                        # Додатково видаляємо весь файл якщо він став малим
                        if ((Get-Item $journalFile).Length -lt 100) {
                            Remove-Item $journalFile -Force -ErrorAction SilentlyContinue
                        }
                    }
                }
            } catch {
                $errors++
            }
        }
    }
    Write-Host " [$cleanedJournal файлів]" -ForegroundColor $(if($cleanedJournal-gt0){'Green'}else{'Gray'})
    
    # 2. Очищення Prefetch
    Write-Host "2. Очищення Prefetch..." -NoNewline
    $pfFiles = Get-ChildItem "C:\Windows\Prefetch" -Filter "*.pf" -ErrorAction SilentlyContinue
    $deletedPrefetch = 0
    
    foreach ($pf in $pfFiles) {
        try {
            $content = Get-Content $pf.FullName -Raw -ErrorAction SilentlyContinue
            if ($content) {
                $shouldDelete = $false
                foreach ($pattern in $searchPatterns) {
                    if ($content -match $pattern) {
                        $shouldDelete = $true
                        break
                    }
                }
                
                if ($shouldDelete) {
                    Remove-Item $pf.FullName -Force -ErrorAction SilentlyContinue
                    $deletedPrefetch++
                    $cleanedCount++
                }
            }
        } catch {
            $errors++
        }
    }
    Write-Host " [$deletedPrefetch файлів]" -ForegroundColor $(if($deletedPrefetch-gt0){'Green'}else{'Gray'})
    
    # 3. Очищення USN Journal
    Write-Host "3. Очищення USN Journal..." -NoNewline
    try {
        fsutil usn deletejournal /D C: 2>$null
        $cleanedCount++
        Write-Host " [виконано]" -ForegroundColor Green
    } catch {
        $errors++
        Write-Host " [помилка]" -ForegroundColor Red
    }
    
    # 4. Очищення файлів процесів
    Write-Host "4. Очищення файлів процесів..." -NoNewline
    $processFiles = Get-ChildItem "C:\Temp\Dump\Processes\Raw" -Filter "*.txt" -ErrorAction SilentlyContinue
    $cleanedProcessFiles = 0
    
    foreach ($procFile in $processFiles) {
        try {
            if (Test-Path $procFile.FullName) {
                $content = Get-Content $procFile.FullName -Raw -ErrorAction SilentlyContinue
                if ($content) {
                    $modified = $false
                    $newContent = $content
                    
                    foreach ($pattern in $searchPatterns) {
                        $newContent = $newContent -replace $pattern, ""
                    }
                    
                    # Видаляємо порожні рядки
                    $newContent = ($newContent -split "`n" | Where-Object { $_ -match '\S' }) -join "`n"
                    
                    if ($newContent -ne $content) {
                        Set-Content -Path $procFile.FullName -Value $newContent -Force -ErrorAction SilentlyContinue
                        $cleanedProcessFiles++
                        $cleanedCount++
                    }
                }
            }
        } catch {
            $errors++
        }
    }
    Write-Host " [$cleanedProcessFiles файлів]" -ForegroundColor $(if($cleanedProcessFiles-gt0){'Green'}else{'Gray'})
    
    # 5. Очищення Results.txt та інших звітів
    Write-Host "5. Очищення звітів..." -NoNewline
    $reportFiles = @(
        "C:\Temp\Results.txt",
        "C:\Temp\Dump\Paths.txt",
        "C:\Temp\Dump\Unsigned.txt",
        "C:\Temp\Dump\Filesize.txt",
        "C:\Temp\Dump\Deletedfile.txt",
        "C:\Temp\Dump\Debug.txt"
    )
    
    $cleanedReports = 0
    foreach ($reportFile in $reportFiles) {
        if (Test-Path $reportFile) {
            try {
                $content = Get-Content $reportFile -Raw -ErrorAction SilentlyContinue
                if ($content) {
                    $modified = $false
                    $newContent = $content
                    
                    foreach ($pattern in $searchPatterns) {
                        $newContent = $newContent -replace $pattern, "[CLEANED]"
                    }
                    
                    if ($newContent -ne $content) {
                        Set-Content -Path $reportFile -Value $newContent -Force -ErrorAction SilentlyContinue
                        $cleanedReports++
                        $cleanedCount++
                    }
                }
            } catch {
                $errors++
            }
        }
    }
    Write-Host " [$cleanedReports файлів]" -ForegroundColor $(if($cleanedReports-gt0){'Green'}else{'Gray'})
    
    # 6. Видалення самого файла (якщо він ще існує)
    Write-Host "6. Пошук та видалення файла..." -NoNewline
    $possiblePaths = @(
        "D:\projects\c#\laba1\bin\Debug\net9.0\b¦-nk.exe",
        "D:\projects\c#\laba1\bin\Debug\net9.0\bаnk.exe",
        "D:\projects\c#\laba1\bin\Debug\net9.0\bank.exe",
        "C:\Windows\System32\drivers\bаnk.exe",
        "C:\Program Files\bаnk.exe",
        "C:\Users\$env:USERNAME\Desktop\bаnk.exe"
    )
    
    $deletedFiles = 0
    foreach ($path in $possiblePaths) {
        if (Test-Path $path) {
            try {
                Remove-Item $path -Force -ErrorAction SilentlyContinue
                $deletedFiles++
                $cleanedCount++
            } catch {
                $errors++
            }
        }
    }
    
    # Додатковий пошук за патерном
    try {
        Get-ChildItem "D:\projects\c#\laba1\bin\Debug\net9.0\" -Filter "*nk.exe" -ErrorAction SilentlyContinue | ForEach-Object {
            Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue
            $deletedFiles++
            $cleanedCount++
        }
    } catch {}
    
    Write-Host " [$deletedFiles файлів]" -ForegroundColor $(if($deletedFiles-gt0){'Green'}else{'Gray'})
    
    # 7. Очищення реєстру
    Write-Host "7. Очищення реєстру..." -NoNewline
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
                    $modified = $false
                    
                    # Перевірка імені ключа
                    foreach ($pattern in $searchPatterns) {
                        if ($key.PSChildName -match $pattern) {
                            Remove-Item $key.PSPath -Recurse -Force -ErrorAction SilentlyContinue
                            $cleanedRegistry++
                            $cleanedCount++
                            $modified = $true
                            break
                        }
                    }
                    
                    if (-not $modified) {
                        # Перевірка значень
                        $values = Get-ItemProperty $key.PSPath -ErrorAction SilentlyContinue
                        if ($values) {
                            $values.PSObject.Properties | ForEach-Object {
                                $propName = $_.Name
                                $value = $_.Value
                                
                                if ($value -ne $null) {
                                    foreach ($pattern in $searchPatterns) {
                                        if ($value.ToString() -match $pattern) {
                                            Remove-ItemProperty -Path $key.PSPath -Name $propName -Force -ErrorAction SilentlyContinue
                                            $cleanedRegistry++
                                            $cleanedCount++
                                        }
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
    
    # 8. Очищення кешу та історії
    Write-Host "8. Очищення кешу..." -NoNewline
    try {
        # Recent
        Remove-Item "$env:APPDATA\Microsoft\Windows\Recent\*" -Recurse -Force -ErrorAction SilentlyContinue
        # Temp
        Remove-Item "$env:TEMP\*" -Recurse -Force -ErrorAction SilentlyContinue
        # Історія PowerShell
        Clear-History
        Remove-Item (Get-PSReadlineOption).HistorySavePath -ErrorAction SilentlyContinue 2>$null
        
        $cleanedCount++
        Write-Host " [виконано]" -ForegroundColor Green
    } catch {
        $errors++
        Write-Host " [помилка]" -ForegroundColor Red
    }
    
    return @{
        Cleaned = $cleanedCount
        Errors = $errors
        Details = @{
            Journal = $cleanedJournal
            Prefetch = $deletedPrefetch
            ProcessFiles = $cleanedProcessFiles
            Reports = $cleanedReports
            Files = $deletedFiles
            Registry = $cleanedRegistry
        }
    }
}

# ===== Головна частина =====
Write-Host "=== Advanced Trace Cleaner ===" -ForegroundColor Blue
Write-Host "Пошук та видалення ВСІХ слідів файла bаnk.exe (включаючи Unicode)" -ForegroundColor Gray
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
Write-Host "Знайдено $($searchResults.Total) згадок у $($searchResults.Counts.Journal) Journal файлах" -ForegroundColor Yellow
Write-Host "Продовжити повне очищення?" -ForegroundColor Yellow
$response = Read-Host "Введіть Y для очищення або N для скасування"

if ($response -ne 'Y') {
    Write-Host "`nОчищення скасовано" -ForegroundColor Red
    Start-Sleep -Seconds 2
    exit 0
}

# Очищення всіх слідів
Write-Host ""
$cleanResults = Clean-BankFile-Traces-All -FullMode:$true

Write-Host ""
Write-Host "="*50 -ForegroundColor Cyan
Write-Host "РЕЗУЛЬТАТ ОЧИЩЕННЯ:" -ForegroundColor Cyan

if ($cleanResults.Cleaned -gt 0) {
    Write-Host "✅ ОПЕРАЦІЯ УСПІШНА" -ForegroundColor Green
    Write-Host "Видалено $($cleanResults.Cleaned) слідів файла" -ForegroundColor Green
    
    Write-Host "`nДеталі очищення:" -ForegroundColor Yellow
    if ($cleanResults.Details.Journal -gt 0) { Write-Host "  • Journal файли: $($cleanResults.Details.Journal)" -ForegroundColor Gray }
    if ($cleanResults.Details.Prefetch -gt 0) { Write-Host "  • Prefetch: $($cleanResults.Details.Prefetch)" -ForegroundColor Gray }
    if ($cleanResults.Details.ProcessFiles -gt 0) { Write-Host "  • Файли процесів: $($cleanResults.Details.ProcessFiles)" -ForegroundColor Gray }
    if ($cleanResults.Details.Reports -gt 0) { Write-Host "  • Звіти: $($cleanResults.Details.Reports)" -ForegroundColor Gray }
    if ($cleanResults.Details.Files -gt 0) { Write-Host "  • Файли: $($cleanResults.Details.Files)" -ForegroundColor Gray }
    if ($cleanResults.Details.Registry -gt 0) { Write-Host "  • Реєстр: $($cleanResults.Details.Registry)" -ForegroundColor Gray }
    
    if ($cleanResults.Errors -gt 0) {
        Write-Host "`n⚠️  Попередження: $($cleanResults.Errors) помилок під час очищення" -ForegroundColor Yellow
    }
} else {
    Write-Host "⚠️  НІЧОГО НЕ ВИДАЛЕНО" -ForegroundColor Yellow
    Write-Host "Не вдалося видалити знайдені сліди" -ForegroundColor Yellow
}

Write-Host "="*50 -ForegroundColor Cyan
Write-Host ""

if ($cleanResults.Cleaned -gt 0) {
    Write-Host "Рекомендації:" -ForegroundColor Gray
    Write-Host "- Перезапустіть систему для застосування змін" -ForegroundColor Gray
    Write-Host "- USN Journal був очищений" -ForegroundColor Gray
    Write-Host "- Всі згадки про файл видалені" -ForegroundColor Gray
} else {
    Write-Host "Порада:" -ForegroundColor Red
    Write-Host "- Можливо, файли заблоковані системою або відсутні права" -ForegroundColor Gray
}

Start-Sleep -Seconds 5