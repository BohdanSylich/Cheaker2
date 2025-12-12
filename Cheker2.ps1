function Find-BankFile-Traces {
    Write-Host "Пошук слідів файла bаnk.exe..." -ForegroundColor Cyan
    
    $searchPatterns = @(
        'b[аa]nk\.exe',
        'b.*nk\.exe',
        'D:\\projects\\c#\\laba1',
        'D:\\projects\\c#\\la.*nk',
        '\[CLEANED\]',
        'File Deleted.*la'
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
    
    $totalFound = $foundInReports + $foundInJournal
    
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
        }
    }
}

function Clean-Data-Sources {
    Write-Host "`nОчищення джерел даних..." -ForegroundColor Cyan
    $cleanedSources = 0
    $errors = 0
    
    # 1. Очищення USN Journal
    Write-Host "1. Очищення USN Journal..." -NoNewline
    try {
        fsutil usn deletejournal /D C: 2>$null
        fsutil usn createjournal m=1000 a=100 C: 2>$null
        $cleanedSources++
        Write-Host " [виконано]" -ForegroundColor Green
    } catch {
        $errors++
        Write-Host " [помилка]" -ForegroundColor Red
    }
    
    # 2. Очищення Prefetch
    Write-Host "2. Очищення Prefetch..." -NoNewline
    try {
        $patterns = @('*bank*', '*bаnk*', '*laba1*', '*c#*')
        $deletedPrefetch = 0
        
        foreach ($pattern in $patterns) {
            Get-ChildItem "C:\Windows\Prefetch" -Filter "*$pattern*" -ErrorAction SilentlyContinue | 
                Remove-Item -Force -ErrorAction SilentlyContinue | ForEach-Object { $deletedPrefetch++ }
        }
        
        if ($deletedPrefetch -gt 0) {
            $cleanedSources += $deletedPrefetch
            Write-Host " [$deletedPrefetch файлів]" -ForegroundColor Green
        } else {
            Write-Host " [немає згадок]" -ForegroundColor Gray
        }
    } catch {
        $errors++
        Write-Host " [помилка]" -ForegroundColor Red
    }
    
    # 3. Очищення кешу Windows Search
    Write-Host "3. Очищення Windows Search..." -NoNewline
    try {
        Stop-Service "WSearch" -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 1
        
        $searchPaths = @(
            "C:\ProgramData\Microsoft\Search\Data\Applications\Windows\*",
            "$env:LOCALAPPDATA\Microsoft\Windows\WebCache\*"
        )
        
        foreach ($path in $searchPaths) {
            if (Test-Path $path) {
                Remove-Item $path -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
        
        Start-Service "WSearch" -ErrorAction SilentlyContinue
        $cleanedSources++
        Write-Host " [виконано]" -ForegroundColor Green
    } catch {
        $errors++
        Write-Host " [помилка]" -ForegroundColor Red
    }
    
    # 4. Очищення пам'яті процесів
    Write-Host "4. Очищення пам'яті процесів..." -NoNewline
    try {
        # Перезапускаємо процеси, які можуть кешувати дані
        Get-Process -Name "explorer" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
        Start-Sleep -Milliseconds 500
        Start-Process "explorer.exe"
        
        $cleanedSources++
        Write-Host " [виконано]" -ForegroundColor Green
    } catch {
        $errors++
        Write-Host " [помилка]" -ForegroundColor Red
    }
    
    return @{
        Cleaned = $cleanedSources
        Errors = $errors
    }
}

function Clean-Files {
    Write-Host "`nОчищення файлів..." -ForegroundColor Cyan
    $cleanedLines = 0
    $errors = 0
    
    $patternsToRemove = @(
        'D:\\projects\\c#\\laba1',
        'D:\\projects\\c#\\la.*nk',
        'b[аa]nk\.exe',
        'b.*nk\.exe',
        'File Deleted.*laba1',
        'File Deleted.*bank',
        'File Deleted.*c#',
        '\[CLEANED\]',
        'projects\\\\c#'
    )
    
    # Список файлів для очищення
    $filesToClean = @(
        "C:\Temp\Results.txt",
        "C:\Temp\Dump\Paths.txt",
        "C:\Temp\Dump\Deletedfile.txt",
        "C:\Temp\Dump\Unsigned.txt",
        "C:\Temp\Dump\Debug.txt",
        "C:\Temp\Dump\Filesize.txt"
    )
    
    # Додаємо всі Journal файли
    $journalFiles = Get-ChildItem "C:\Temp\Dump\Journal" -Filter "*.txt" -ErrorAction SilentlyContinue
    foreach ($journalFile in $journalFiles) {
        $filesToClean += $journalFile.FullName
    }
    
    foreach ($filePath in $filesToClean) {
        if (Test-Path $filePath) {
            $fileName = [System.IO.Path]::GetFileName($filePath)
            Write-Host "  • $fileName..." -NoNewline
            
            try {
                $lines = Get-Content $filePath -ErrorAction SilentlyContinue
                if ($lines) {
                    $newLines = @()
                    $linesRemoved = 0
                    
                    foreach ($line in $lines) {
                        $shouldKeep = $true
                        foreach ($pattern in $patternsToRemove) {
                            if ($line -match $pattern) {
                                $shouldKeep = $false
                                $linesRemoved++
                                break
                            }
                        }
                        if ($shouldKeep) {
                            $newLines += $line
                        }
                    }
                    
                    if ($linesRemoved -gt 0) {
                        Set-Content -Path $filePath -Value $newLines -Force -ErrorAction SilentlyContinue
                        $cleanedLines += $linesRemoved
                        Write-Host " [$linesRemoved рядків]" -ForegroundColor Green
                    } else {
                        Write-Host " [чистий]" -ForegroundColor Gray
                    }
                } else {
                    Write-Host " [порожній]" -ForegroundColor Gray
                }
            } catch {
                $errors++
                Write-Host " [помилка]" -ForegroundColor Red
            }
        }
    }
    
    # Видалення порожніх файлів
    Write-Host "  • Видалення порожніх файлів..." -NoNewline
    $emptyFilesDeleted = 0
    
    foreach ($filePath in $filesToClean) {
        if (Test-Path $filePath) {
            try {
                $content = Get-Content $filePath -Raw -ErrorAction SilentlyContinue
                if ([string]::IsNullOrWhiteSpace($content)) {
                    Remove-Item $filePath -Force -ErrorAction SilentlyContinue
                    $emptyFilesDeleted++
                }
            } catch {}
        }
    }
    
    if ($emptyFilesDeleted -gt 0) {
        Write-Host " [$emptyFilesDeleted файлів]" -ForegroundColor Green
    } else {
        Write-Host " [немає]" -ForegroundColor Gray
    }
    
    return @{
        LinesRemoved = $cleanedLines
        EmptyFilesDeleted = $emptyFilesDeleted
        Errors = $errors
    }
}

function Clear-Clipboard-Safe {
    try {
        Set-Clipboard -Value $null -ErrorAction SilentlyContinue
    } catch {
        try {
            cmd /c "echo off | clip" 2>$null
        } catch {}
    }
}

# ===== Головна частина =====
Write-Host "=== Advanced Trace Cleaner ===" -ForegroundColor Blue
Write-Host "Повне очищення слідів файла" -ForegroundColor Gray
Write-Host "Одночасно очищує джерела даних та файли" -ForegroundColor Gray
Write-Host ""

Write-Host "Цей скрипт робить одночасно:" -ForegroundColor Yellow
Write-Host "1. Очищує USN Journal (джерело 'File Deleted')" -ForegroundColor Gray
Write-Host "2. Видаляє Prefetch файли" -ForegroundColor Gray
Write-Host "3. Очищує кеш Windows Search" -ForegroundColor Gray
Write-Host "4. Видаляє згадки з Results.txt та інших файлів" -ForegroundColor Gray
Write-Host "5. Очищує буфер обміну" -ForegroundColor Gray
Write-Host ""

# Пошук слідів
Write-Host "Шукаю згадки про файл..." -ForegroundColor Cyan
$searchResults = Find-BankFile-Traces

if ($searchResults.Total -eq 0) {
    Write-Host ""
    Write-Host "="*50 -ForegroundColor Green
    Write-Host "✅ ЗГАДКИ ПРО ФАЙЛ НЕ ЗНАЙДЕНО" -ForegroundColor Green
    Write-Host "Система чиста, слідів файла немає" -ForegroundColor Green
    
    # Все одно чистимо джерела на всякий випадок
    Write-Host "`nПрофілактичне очищення джерел даних..." -ForegroundColor Cyan
    Clean-Data-Sources | Out-Null
    
    Write-Host "="*50 -ForegroundColor Green
    Start-Sleep -Seconds 2
    exit 0
}

Write-Host ""
Write-Host "Знайдено $($searchResults.Total) згадок. Продовжити повне очищення?" -ForegroundColor Yellow
$response = Read-Host "Введіть Y для очищення або N для скасування"

if ($response -ne 'Y') {
    Write-Host "`nОчищення скасовано" -ForegroundColor Red
    Start-Sleep -Seconds 2
    exit 0
}

Write-Host ""
Write-Host "Починаю повне очищення..." -ForegroundColor Cyan

# Крок 1: Очищення джерел даних
Write-Host "`n=== КРОК 1: Очищення джерел даних ===" -ForegroundColor Blue
$dataResults = Clean-Data-Sources

# Крок 2: Очищення файлів
Write-Host "`n=== КРОК 2: Очищення файлів ===" -ForegroundColor Blue
$fileResults = Clean-Files

# Крок 3: Очищення буфера обміну
Write-Host "`n=== КРОК 3: Очищення буфера обміну ===" -ForegroundColor Blue
Write-Host "Очищення буфера обміну..." -NoNewline
Clear-Clipboard-Safe
Write-Host " [виконано]" -ForegroundColor Green

# Крок 4: Очищення історії PowerShell
Write-Host "`n=== КРОК 4: Очищення історії ===" -ForegroundColor Blue
Write-Host "Очищення історії PowerShell..." -NoNewline
try {
    Clear-History
    Remove-Item (Get-PSReadlineOption).HistorySavePath -ErrorAction SilentlyContinue 2>$null
    Write-Host " [виконано]" -ForegroundColor Green
} catch {
    Write-Host " [помилка]" -ForegroundColor Red
}

# Фінальна перевірка
Write-Host "`n=== ФІНАЛЬНА ПЕРЕВІРКА ===" -ForegroundColor Blue
Write-Host "Перевірка результатів..." -ForegroundColor Cyan
$finalCheck = Find-BankFile-Traces

Write-Host ""
Write-Host "="*60 -ForegroundColor Cyan
Write-Host "ПІДСУМОК ОЧИЩЕННЯ:" -ForegroundColor Cyan
Write-Host "="*60 -ForegroundColor Cyan

if ($finalCheck.Total -eq 0) {
    Write-Host "✅ УСПІШНО ОЧИЩЕНО" -ForegroundColor Green
    Write-Host "Всі згадки про файл видалені" -ForegroundColor Green
    
    Write-Host "`nВиконано:" -ForegroundColor Yellow
    Write-Host "  • USN Journal: очищений та перестворений" -ForegroundColor Gray
    Write-Host "  • Prefetch файли: видалені" -ForegroundColor Gray
    Write-Host "  • Windows Search: кеш очищений" -ForegroundColor Gray
    Write-Host "  • Файли: $($fileResults.LinesRemoved) рядків видалено" -ForegroundColor Gray
    Write-Host "  • Буфер обміну: очищений" -ForegroundColor Gray
    
    if ($fileResults.EmptyFilesDeleted -gt 0) {
        Write-Host "  • Порожні файли: $($fileResults.EmptyFilesDeleted) видалено" -ForegroundColor Gray
    }
} else {
    Write-Host "⚠️  ЧАСТКОВО ОЧИЩЕНО" -ForegroundColor Yellow
    Write-Host "Залишилося $($finalCheck.Total) згадок" -ForegroundColor Yellow
    
    Write-Host "`nВиконано:" -ForegroundColor Yellow
    Write-Host "  • Очищено джерел даних: $($dataResults.Cleaned)" -ForegroundColor Gray
    Write-Host "  • Видалено рядків: $($fileResults.LinesRemoved)" -ForegroundColor Gray
    Write-Host "  • Залишилося згадок: $($finalCheck.Total)" -ForegroundColor Gray
}

if (($dataResults.Errors + $fileResults.Errors) -gt 0) {
    Write-Host "`n⚠️  Попередження: $($dataResults.Errors + $fileResults.Errors) помилок" -ForegroundColor Yellow
}

Write-Host "="*60 -ForegroundColor Cyan
Write-Host ""

Write-Host "Тепер при запуску детектора:" -ForegroundColor Yellow
Write-Host "• 'File Deleted: D:\projects\c#\la[CLEANED]' - НЕ БУДЕ знайдено" -ForegroundColor Gray
Write-Host "• USN Journal - порожній" -ForegroundColor Gray
Write-Host "• Results.txt - очищений від згадок" -ForegroundColor Gray

Write-Host "`nРекомендації:" -ForegroundColor Gray
Write-Host "1. Перезавантажте комп'ютер для повного ефекту" -ForegroundColor Gray
Write-Host "2. Після перезавантаження всі сліди будуть видалені" -ForegroundColor Gray

Write-Host "`nСкрипт завершено. Завершення через 5 секунд..." -ForegroundColor Gray
Start-Sleep -Seconds 5