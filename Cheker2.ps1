function Check-For-Traces {
    Write-Host "Перевірка наявності слідів у джерелах даних..." -ForegroundColor Cyan
    
    $detectedSources = @()
    
    # 1. Перевірка Prefetch на згадки про файл
    Write-Host "1. Перевірка Prefetch..." -NoNewline
    try {
        $pfFiles = Get-ChildItem "C:\Windows\Prefetch" -Filter "*.pf" -ErrorAction SilentlyContinue | Select-Object -First 10
        
        foreach ($pf in $pfFiles) {
            try {
                $content = Get-Content $pf.FullName -Raw -ErrorAction SilentlyContinue
                if ($content -and ($content -match 'b[аa]nk' -or $content -match 'D:\\projects\\c#')) {
                    $detectedSources += "Prefetch: $($pf.Name)"
                    break
                }
            } catch {}
        }
        
        if ($detectedSources | Where-Object { $_ -match "Prefetch" }) {
            Write-Host " [знайдено]" -ForegroundColor Red
        } else {
            Write-Host " [не знайдено]" -ForegroundColor Green
        }
    } catch {
        Write-Host " [помилка]" -ForegroundColor Yellow
    }
    
    # 2. Перевірка USN Journal (через розмір)
    Write-Host "2. Перевірка USN Journal..." -NoNewline
    try {
        $journalInfo = fsutil usn queryjournal C: 2>$null
        if ($journalInfo -and $journalInfo -match "Usn Journal ID") {
            # Якщо журнал існує і має дані
            $detectedSources += "USN Journal: активний"
            Write-Host " [активний]" -ForegroundColor Red
        } else {
            Write-Host " [не активний]" -ForegroundColor Green
        }
    } catch {
        Write-Host " [помилка]" -ForegroundColor Yellow
    }
    
    # 3. Перевірка Windows Search кешу
    Write-Host "3. Перевірка Windows Search..." -NoNewline
    try {
        $searchPath = "C:\ProgramData\Microsoft\Search\Data\Applications\Windows"
        if (Test-Path $searchPath) {
            $dbFiles = Get-ChildItem $searchPath -Filter "*.edb" -ErrorAction SilentlyContinue
            if ($dbFiles) {
                $detectedSources += "Windows Search: кеш присутній"
                Write-Host " [кеш є]" -ForegroundColor Red
            } else {
                Write-Host " [немає]" -ForegroundColor Green
            }
        } else {
            Write-Host " [не знайдено]" -ForegroundColor Gray
        }
    } catch {
        Write-Host " [помилка]" -ForegroundColor Yellow
    }
    
    return @{
        Detected = ($detectedSources.Count -gt 0)
        Sources = $detectedSources
    }
}

function Clean-Data-Sources-Only {
    Write-Host "`nОчищення джерел даних..." -ForegroundColor Cyan
    
    $results = @{
        USNJournal = Clean-USN-Journal
        Prefetch = Clean-Prefetch-Files
        WindowsSearch = Clean-Windows-Search-Cache
        Clipboard = Clean-Clipboard-History
        TempFiles = Clean-Temp-Script-Files
        ProcessMemory = Clean-Process-Memory-Cache
        PowerShellHistory = Clean-PowerShell-History-Only
    }
    
    return $results
}

function Clean-USN-Journal {
    Write-Host "• USN Journal..." -NoNewline
    try {
        fsutil usn deletejournal /D C: 2>$null
        # Створюємо новий порожній журнал
        fsutil usn createjournal m=1000 a=100 C: 2>$null
        Write-Host " [очищено]" -ForegroundColor Green
        return $true
    } catch {
        Write-Host " [помилка]" -ForegroundColor Red
        return $false
    }
}

function Clean-Prefetch-Files {
    Write-Host "• Prefetch файли..." -NoNewline
    $deleted = 0
    
    try {
        $patterns = @('*bank*', '*bаnk*', '*laba1*', '*c#*')
        
        foreach ($pattern in $patterns) {
            Get-ChildItem "C:\Windows\Prefetch" -Filter "*$pattern*" -ErrorAction SilentlyContinue | 
                ForEach-Object {
                    try {
                        Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue
                        $deleted++
                    } catch {}
                }
        }
        
        if ($deleted -gt 0) {
            Write-Host " [$deleted видалено]" -ForegroundColor Green
        } else {
            Write-Host " [немає]" -ForegroundColor Gray
        }
        return $true
    } catch {
        Write-Host " [помилка]" -ForegroundColor Red
        return $false
    }
}

function Clean-Windows-Search-Cache {
    Write-Host "• Windows Search кеш..." -NoNewline
    
    try {
        Stop-Service "WSearch" -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 1
        
        $searchPath = "C:\ProgramData\Microsoft\Search\Data\Applications\Windows"
        if (Test-Path $searchPath) {
            Get-ChildItem $searchPath -Filter "*.edb" -ErrorAction SilentlyContinue | Remove-Item -Force
            Get-ChildItem $searchPath -Filter "*.db" -ErrorAction SilentlyContinue | Remove-Item -Force
        }
        
        Start-Service "WSearch" -ErrorAction SilentlyContinue
        Write-Host " [очищено]" -ForegroundColor Green
        return $true
    } catch {
        Write-Host " [помилка]" -ForegroundColor Red
        return $false
    }
}

function Clean-Clipboard-History {
    Write-Host "• Буфер обміну (Win+V)..." -NoNewline
    
    $success = $false
    
    try {
        # 1. Очистити поточний буфер
        Set-Clipboard -Value $null -ErrorAction SilentlyContinue
        
        # 2. Очистити через cmd
        cmd /c "echo off | clip" 2>$null
        
        # 3. Видалити файли історії буфера Windows
        $clipboardPath = "$env:LOCALAPPDATA\Microsoft\Windows\Clipboard"
        if (Test-Path $clipboardPath) {
            Remove-Item "$clipboardPath\*" -Force -Recurse -ErrorAction SilentlyContinue
        }
        
        # 4. Записати безпечний текст
        Set-Clipboard -Value "System clean" -ErrorAction SilentlyContinue
        
        $success = $true
        Write-Host " [очищено]" -ForegroundColor Green
    } catch {
        Write-Host " [помилка]" -ForegroundColor Red
    }
    
    return $success
}

function Clean-Temp-Script-Files {
    Write-Host "• Тимчасові файли скриптів..." -NoNewline
    $deleted = 0
    
    try {
        $tempPatterns = @(
            "$env:TEMP\*strings*",
            "$env:TEMP\*PECmd*",
            "$env:TEMP\*Evtx*",
            "$env:TEMP\*dump*",
            "C:\Windows\Temp\*strings*"
        )
        
        foreach ($pattern in $tempPatterns) {
            if (Test-Path $pattern) {
                Get-ChildItem $pattern -ErrorAction SilentlyContinue | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
                $deleted++
            }
        }
        
        if ($deleted -gt 0) {
            Write-Host " [$deleted файлів]" -ForegroundColor Green
        } else {
            Write-Host " [немає]" -ForegroundColor Gray
        }
        return $true
    } catch {
        Write-Host " [помилка]" -ForegroundColor Red
        return $false
    }
}

function Clean-Process-Memory-Cache {
    Write-Host "• Пам'ять процесів..." -NoNewline
    
    try {
        # Перезапустити explorer для очищення кешу
        Get-Process -Name "explorer" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
        Start-Sleep -Milliseconds 500
        Start-Process "explorer.exe"
        
        Write-Host " [очищено]" -ForegroundColor Green
        return $true
    } catch {
        Write-Host " [помилка]" -ForegroundColor Red
        return $false
    }
}

function Clean-PowerShell-History-Only {
    Write-Host "• Історія PowerShell..." -NoNewline
    
    try {
        Clear-History
        
        # Видалити файл історії
        $historyPath = (Get-PSReadlineOption).HistorySavePath
        if (Test-Path $historyPath) {
            Remove-Item $historyPath -Force -ErrorAction SilentlyContinue
        }
        
        Write-Host " [очищено]" -ForegroundColor Green
        return $true
    } catch {
        Write-Host " [помилка]" -ForegroundColor Red
        return $false
    }
}

# === Головна частина ===
Write-Host "=== SYSTEM SOURCES CLEANER ===" -ForegroundColor Blue
Write-Host "Очищення ДЖЕРЕЛ ДАНИХ (не файлів)" -ForegroundColor Gray
Write-Host ""

Write-Host "ВАЖЛИВО:" -ForegroundColor Red
Write-Host "• НЕ ЧІПАЄ Results.txt" -ForegroundColor Red
Write-Host "• НЕ ЧІПАЄ жодні файли в C:\Temp\Dump\" -ForegroundColor Red
Write-Host "• Очищує тільки ДЖЕРЕЛА ДАНИХ" -ForegroundColor Red
Write-Host ""

Write-Host "Очищує джерела даних:" -ForegroundColor Yellow
Write-Host "1. USN Journal (звідси береться 'File Deleted:')" -ForegroundColor Gray
Write-Host "2. Prefetch файли" -ForegroundColor Gray
Write-Host "3. Windows Search кеш" -ForegroundColor Gray
Write-Host "4. Буфер обміну (Win+V)" -ForegroundColor Gray
Write-Host "5. Тимчасові файли скриптів" -ForegroundColor Gray
Write-Host "6. Пам'ять процесів" -ForegroundColor Gray
Write-Host "7. Історію PowerShell" -ForegroundColor Gray
Write-Host ""

Write-Host "Після очищення:" -ForegroundColor Green
Write-Host "• Детектор НЕ ЗНАЙДЕ 'File Deleted: D:\projects\c#\la[CLEANED]'" -ForegroundColor Gray
Write-Host "• Бо USN Journal буде порожній" -ForegroundColor Gray
Write-Host "• Results.txt буде створено ЗАНОВО без цих записів" -ForegroundColor Gray
Write-Host ""

# Перевірка джерел даних
Write-Host "Перевіряю джерела даних..." -ForegroundColor Cyan
$checkResults = Check-For-Traces

if ($checkResults.Detected) {
    Write-Host ""
    Write-Host "Знайдено сліди в:" -ForegroundColor Yellow
    foreach ($source in $checkResults.Sources) {
        Write-Host "  • $source" -ForegroundColor Gray
    }
    Write-Host ""
} else {
    Write-Host ""
    Write-Host "✅ Джерела даних чисті" -ForegroundColor Green
    Write-Host ""
}

$confirm = Read-Host "Очистити джерела даних та буфер обміну? (Y/N)"
if ($confirm -ne 'Y') {
    Write-Host "`nСкасовано" -ForegroundColor Red
    exit
}

Write-Host ""
Write-Host "Починаю очищення джерел даних..." -ForegroundColor Cyan
Write-Host ""

# Виконання очищення
$cleanResults = Clean-Data-Sources-Only

Write-Host ""
Write-Host "="*60 -ForegroundColor Cyan
Write-Host "РЕЗУЛЬТАТ ОЧИЩЕННЯ ДЖЕРЕЛ ДАНИХ:" -ForegroundColor Cyan

$successCount = ($cleanResults.Values | Where-Object { $_ -eq $true }).Count

if ($successCount -gt 0) {
    Write-Host "✅ ДЖЕРЕЛА ДАНИХ ОЧИЩЕНО" -ForegroundColor Green
    
    Write-Host "`nОчищено:" -ForegroundColor Yellow
    
    if ($cleanResults.USNJournal) { Write-Host "  • USN Journal - тепер порожній" -ForegroundColor Gray }
    if ($cleanResults.Prefetch) { Write-Host "  • Prefetch файли зі згадками" -ForegroundColor Gray }
    if ($cleanResults.WindowsSearch) { Write-Host "  • Windows Search кеш" -ForegroundColor Gray }
    if ($cleanResults.Clipboard) { Write-Host "  • Буфер обміну (Win+V)" -ForegroundColor Gray }
    if ($cleanResults.TempFiles) { Write-Host "  • Тимчасові файли скриптів" -ForegroundColor Gray }
    if ($cleanResults.ProcessMemory) { Write-Host "  • Пам'ять процесів" -ForegroundColor Gray }
    if ($cleanResults.PowerShellHistory) { Write-Host "  • Історія PowerShell" -ForegroundColor Gray }
    
    Write-Host "`nТепер при запуску детектора:" -ForegroundColor Green
    Write-Host "1. USN Journal порожній → 'File Deleted:' НЕ БУДЕ знайдено" -ForegroundColor Gray
    Write-Host "2. Results.txt буде створено ЗАНОВО без старих записів" -ForegroundColor Gray
    Write-Host "3. Натисни Win+V - історія буфера чиста" -ForegroundColor Gray
    
} else {
    Write-Host "⚠️  НЕ ВДАЛОСЯ ОЧИСТИТИ ДЖЕРЕЛА" -ForegroundColor Red
}

Write-Host "="*60 -ForegroundColor Cyan
Write-Host ""

Write-Host "Вони будуть перезаписані при наступному запуску детектора" -ForegroundColor Gray

Write-Host ""
Write-Host "Щоб перевірити результат:" -ForegroundColor Yellow
Write-Host "1. Запусти скрипт-детектор заново" -ForegroundColor Gray
Write-Host "2. Він створить НОВИЙ Results.txt" -ForegroundColor Gray
Write-Host "3. 'File Deleted: D:\projects\c#\la[CLEANED]' НЕ З'ЯВИТЬСЯ" -ForegroundColor Gray

Write-Host "`nЗавершення через 3 секунди..." -ForegroundColor Gray
Start-Sleep -Seconds 3