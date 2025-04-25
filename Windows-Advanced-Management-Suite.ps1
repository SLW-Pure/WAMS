# Windows Advanced Management Suite (WAMS)
# Author: [Sizin Adınız]
# Version: 1.0.0
# PowerShell tabanlı gelişmiş Windows yönetim aracı

# Modül yükleme kontrol fonksiyonu
function Test-ModuleInstalled {
    param (
        [string]$ModuleName
    )
    
    if (Get-Module -ListAvailable -Name $ModuleName) {
        return $true
    }
    return $false
}

# Gerekli modülleri kontrol et ve yükle
function Initialize-RequiredModules {
    $requiredModules = @("PSWindowsUpdate", "BurntToast", "ImportExcel")
    
    foreach ($module in $requiredModules) {
        if (-not (Test-ModuleInstalled -ModuleName $module)) {
            try {
                Write-Host "Modül yükleniyor: $module..." -ForegroundColor Yellow
                Install-Module -Name $module -Force -Scope CurrentUser
                Write-Host "$module başarıyla yüklendi." -ForegroundColor Green
            }
            catch {
                Write-Host "HATA: $module yüklenemedi. $($_.Exception.Message)" -ForegroundColor Red
            }
        }
    }
}

# Logo ve Başlık Görüntüleme
function Show-WamsSplashScreen {
    Clear-Host
    $logo = @"
 __          __  _____    __  __   _____ 
 \ \        / / |  __ \  |  \/  | / ____|
  \ \  /\  / /  | |__) | | \  / || (___  
   \ \/  \/ /   |  _  /  | |\/| | \___ \ 
    \  /\  /    | | \ \  | |  | | ____) |
     \/  \/     |_|  \_\ |_|  |_||_____/ 
                                         
 Windows Advanced Management Suite v1.0.0
"@

    Write-Host $logo -ForegroundColor Cyan
    Write-Host "Gelişmiş Windows Yönetim Aracı" -ForegroundColor White
    Write-Host "-------------------------------------" -ForegroundColor DarkGray
}

# Admin haklarını kontrol etme
function Test-AdminRights {
    $currentUser = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentUser.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Elevate to admin if needed
function Request-AdminRights {
    if (-not (Test-AdminRights)) {
        Write-Host "Bu işlem için yönetici hakları gerekiyor. Yeniden başlatılıyor..." -ForegroundColor Yellow
        Start-Sleep -Seconds 2
        
        # Script'i yönetici olarak yeniden başlat
        $scriptPath = $MyInvocation.MyCommand.Path
        Start-Process powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`"" -Verb RunAs
        
        exit
    }
}

# Sistem Bilgisi Fonksiyonları
function Get-SystemOverview {
    Write-Host "`n[Sistem Genel Bakış]`n" -ForegroundColor Cyan
    
    # İşletim Sistemi Bilgisi
    $os = Get-CimInstance -ClassName Win32_OperatingSystem
    $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem
    
    Write-Host "Bilgisayar Adı: " -ForegroundColor White -NoNewline
    Write-Host $env:COMPUTERNAME -ForegroundColor Green
    
    Write-Host "Kullanıcı: " -ForegroundColor White -NoNewline
    Write-Host $env:USERNAME -ForegroundColor Green
    
    Write-Host "İşletim Sistemi: " -ForegroundColor White -NoNewline
    Write-Host "$($os.Caption) $($os.Version)" -ForegroundColor Green
    
    Write-Host "Üretici: " -ForegroundColor White -NoNewline
    Write-Host "$($computerSystem.Manufacturer)" -ForegroundColor Green
    
    Write-Host "Model: " -ForegroundColor White -NoNewline
    Write-Host "$($computerSystem.Model)" -ForegroundColor Green
    
    # BIOS ve Seri Numarası
    $bios = Get-CimInstance -ClassName Win32_BIOS
    Write-Host "BIOS Sürümü: " -ForegroundColor White -NoNewline
    Write-Host "$($bios.Manufacturer) $($bios.SMBIOSBIOSVersion)" -ForegroundColor Green
    
    Write-Host "Seri Numarası: " -ForegroundColor White -NoNewline
    Write-Host "$($bios.SerialNumber)" -ForegroundColor Green
    
    # Donanım Bilgisi
    $processor = Get-CimInstance -ClassName Win32_Processor
    $memory = Get-CimInstance -ClassName Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum
    
    Write-Host "İşlemci: " -ForegroundColor White -NoNewline
    Write-Host "$($processor.Name)" -ForegroundColor Green
    
    Write-Host "Bellek: " -ForegroundColor White -NoNewline
    Write-Host "$([math]::Round($memory.Sum / 1GB, 2)) GB" -ForegroundColor Green
    
    # Disk Bilgisi
    $disks = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DriveType=3"
    Write-Host "Diskler:" -ForegroundColor White
    
    foreach ($disk in $disks) {
        $freeSpacePercent = [math]::Round(($disk.FreeSpace / $disk.Size) * 100, 2)
        $freeSpaceColor = if ($freeSpacePercent -lt 20) { "Red" } elseif ($freeSpacePercent -lt 40) { "Yellow" } else { "Green" }
        
        Write-Host "  $($disk.DeviceID) - $([math]::Round($disk.Size / 1GB, 2)) GB (Boş: " -NoNewline
        Write-Host "$([math]::Round($disk.FreeSpace / 1GB, 2)) GB</div>
        </div>
        <div>
            <strong>$usedPercent% kullanımda</strong>
        </div>
    </div>
    
    <div class="disk-bar">
        <div class="disk-bar-inner $diskClass" style="width: $usedPercent%;"></div>
        <div class="disk-bar-inner disk-free" style="width: $freePercent%;"></div>
    </div>
"@
            }
            
            # En Büyük Klasörler
            $htmlContent += @"
    <h2>En Büyük Klasörler</h2>
"@

            foreach ($disk in $disks) {
                try {
                    $diskRoot = "$($disk.DeviceID)\"
                    
                    $htmlContent += @"
    <h3>$($disk.DeviceID) - $($disk.VolumeName)</h3>
"@

                    # En büyük 10 klasörü al
                    $topFolders = Get-ChildItem -Path $diskRoot -Directory -ErrorAction SilentlyContinue | 
                                 ForEach-Object {
                                     $folderSize = 0
                                     Get-ChildItem -Path $_.FullName -Recurse -ErrorAction SilentlyContinue | 
                                     ForEach-Object { $folderSize += $_.Length }
                                     
                                     [PSCustomObject]@{
                                         FolderName = $_.FullName
                                         Size = $folderSize
                                     }
                                 } | Sort-Object -Property Size -Descending | Select-Object -First 10
                    
                    if ($topFolders) {
                        $maxSize = ($topFolders | Measure-Object -Property Size -Maximum).Maximum
                        
                        $htmlContent += @"
    <table>
        <tr><th>Klasör</th><th>Boyut</th><th>Oran</th></tr>
"@

                        foreach ($folder in $topFolders) {
                            $sizeInGB = [math]::Round($folder.Size / 1GB, 2)
                            $sizePercent = [math]::Round(($folder.Size / $maxSize) * 100, 2)
                            
                            $htmlContent += @"
        <tr>
            <td>$($folder.FolderName)</td>
            <td>$sizeInGB GB</td>
            <td>
                <div class="folder-bar">
                    <div class="folder-bar-inner" style="width: $sizePercent%;"></div>
                </div>
            </td>
        </tr>
"@
                        }
                        
                        $htmlContent += @"
    </table>
"@
                    }
                    else {
                        $htmlContent += @"
    <p>Klasör bilgisi alınamadı.</p>
"@
                    }
                }
                catch {
                    $htmlContent += @"
    <p>Hata: $($_.Exception.Message)</p>
"@
                }
            }
            
            # Dosya Türleri
            $htmlContent += @"
    <h2>En Çok Yer Kaplayan Dosya Türleri</h2>
"@

            foreach ($disk in $disks) {
                try {
                    $diskRoot = "$($disk.DeviceID)\"
                    
                    $htmlContent += @"
    <h3>$($disk.DeviceID) - $($disk.VolumeName)</h3>
"@

                    # Yaygın dosya türlerini al
                    $fileTypes = @{
                        ".zip" = 0
                        ".rar" = 0
                        ".7z" = 0
                        ".mp4" = 0
                        ".mov" = 0
                        ".avi" = 0
                        ".mkv" = 0
                        ".mp3" = 0
                        ".flac" = 0
                        ".wav" = 0
                        ".jpg" = 0
                        ".jpeg" = 0
                        ".png" = 0
                        ".gif" = 0
                        ".pdf" = 0
                        ".doc" = 0
                        ".docx" = 0
                        ".xls" = 0
                        ".xlsx" = 0
                        ".ppt" = 0
                        ".pptx" = 0
                        ".exe" = 0
                        ".dll" = 0
                        ".iso" = 0
                        ".img" = 0
                    }
                    
                    # Örnekleme yaparak dosya türlerini topla
                    $sampleFolders = Get-ChildItem -Path $diskRoot -Directory -ErrorAction SilentlyContinue | 
                                    Select-Object -First 5
                    
                    foreach ($folder in $sampleFolders) {
                        Get-ChildItem -Path $folder.FullName -File -Recurse -ErrorAction SilentlyContinue | 
                        ForEach-Object {
                            $ext = [System.IO.Path]::GetExtension($_.Name).ToLower()
                            if ($fileTypes.ContainsKey($ext)) {
                                $fileTypes[$ext] += $_.Length
                            }
                        }
                    }
                    
                    # Sıralama ve filtreleme
                    $topFileTypes = $fileTypes.GetEnumerator() | 
                                   Where-Object { $_.Value -gt 0 } |
                                   Sort-Object -Property Value -Descending | 
                                   Select-Object -First 10
                    
                    if ($topFileTypes) {
                        $maxSize = ($topFileTypes | Measure-Object -Property Value -Maximum).Maximum
                        
                        $htmlContent += @"
    <table>
        <tr><th>Dosya Türü</th><th>Toplam Boyut</th><th>Oran</th></tr>
"@

                        foreach ($type in $topFileTypes) {
                            $sizeInGB = [math]::Round($type.Value / 1GB, 2)
                            $sizePercent = [math]::Round(($type.Value / $maxSize) * 100, 2)
                            
                            $htmlContent += @"
        <tr>
            <td>$($type.Key)</td>
            <td>$sizeInGB GB</td>
            <td>
                <div class="folder-bar">
                    <div class="folder-bar-inner" style="width: $sizePercent%;"></div>
                </div>
            </td>
        </tr>
"@
                        }
                        
                        $htmlContent += @"
    </table>
"@
                    }
                    else {
                        $htmlContent += @"
    <p>Dosya türü bilgisi alınamadı.</p>
"@
                    }
                }
                catch {
                    $htmlContent += @"
    <p>Hata: $($_.Exception.Message)</p>
"@
                }
            }
            
            # HTML Sonu
            $htmlContent += @"
</body>
</html>
"@
            
            # Dosyaya yaz
            $htmlContent | Out-File -FilePath $reportFile -Encoding utf8
            
            Write-Host "Rapor oluşturuldu: $reportFile" -ForegroundColor Green
            Invoke-Item $reportFile
            
            Pause
            Show-ReportingMenu
        }
        "6" {
            Write-Host "`nPerformans Raporu Oluşturuluyor..." -ForegroundColor Yellow
            
            $reportFile = "$env:USERPROFILE\Desktop\PerformansRaporu_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
            
            # Performans verilerini topla
            Write-Host "Performans verileri toplanıyor (30 saniye)..." -ForegroundColor Yellow
            
            # CPU, Bellek, Disk ve Ağ performans verilerini topla
            $cpuValues = @()
            $memoryValues = @()
            $diskValues = @()
            $networkValues = @()
            
            for ($i = 0; $i -lt 10; $i++) {
                # CPU
                $cpuLoad = (Get-CimInstance -ClassName Win32_Processor | 
                          Measure-Object -Property LoadPercentage -Average).Average
                $cpuValues += $cpuLoad
                
                # Bellek
                $os = Get-CimInstance -ClassName Win32_OperatingSystem
                $totalMemory = $os.TotalVisibleMemorySize
                $freeMemory = $os.FreePhysicalMemory
                $usedMemory = $totalMemory - $freeMemory
                $memoryPercentage = [math]::Round(($usedMemory / $totalMemory) * 100, 2)
                $memoryValues += $memoryPercentage
                
                # Disk
                $diskPerf = Get-CimInstance -ClassName Win32_PerfFormattedData_PerfDisk_PhysicalDisk -Filter "Name='_Total'" |
                          Select-Object -Property PercentDiskTime, AvgDiskQueueLength
                $diskValues += $diskPerf.PercentDiskTime
                
                # Ağ
                $networkPerf = Get-CimInstance -ClassName Win32_PerfFormattedData_Tcpip_NetworkInterface |
                             Measure-Object -Property BytesTotalPersec -Sum | 
                             Select-Object -ExpandProperty Sum
                $networkValues += [math]::Round($networkPerf / 1MB, 2)
                
                Start-Sleep -Seconds 3
            }
            
            # En çok kaynak kullanan süreçler
            $topCpuProcesses = Get-Process | Sort-Object -Property CPU -Descending | Select-Object -First 5
            $topMemoryProcesses = Get-Process | Sort-Object -Property WorkingSet -Descending | Select-Object -First 5
            
            # HTML Başlangıcı
            $htmlContent = @"
<!DOCTYPE html>
<html>
<head>
    <title>Performans Raporu</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1 { color: #0066cc; }
        h2 { color: #0099cc; margin-top: 30px; border-bottom: 1px solid #ddd; padding-bottom: 5px; }
        table { border-collapse: collapse; width: 100%; margin: 20px 0; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        tr:nth-child(even) { background-color: #f9f9f9; }
        .chart-container { height: 200px; margin: 20px 0; }
        .chart-bar { display: inline-block; width: 8%; margin-right: 1%; background-color: #428bca; position: relative; }
        .chart-value { position: absolute; top: -25px; width: 100%; text-align: center; font-size: 12px; }
        .chart-label { position: absolute; bottom: -25px; width: 100%; text-align: center; font-size: 12px; }
        .good { background-color: #5cb85c; }
        .warning { background-color: #f0ad4e; }
        .danger { background-color: #d9534f; }
        .summary { padding: 15px; margin-top: 20px; border-radius: 5px; }
        .summary.good { background-color: #dff0d8; border: 1px solid #d6e9c6; }
        .summary.warning { background-color: #fcf8e3; border: 1px solid #faebcc; }
        .summary.danger { background-color: #f2dede; border: 1px solid #ebccd1; }
    </style>
</head>
<body>
    <h1>Performans Raporu</h1>
    <p>Oluşturma Tarihi: $(Get-Date)</p>
    <p>Bilgisayar Adı: $env:COMPUTERNAME</p>
"@
            
            # CPU Kullanımı
            $avgCpu = ($cpuValues | Measure-Object -Average).Average
            $cpuSummaryClass = if ($avgCpu -lt 60) { "good" } elseif ($avgCpu -lt 85) { "warning" } else { "danger" }
            
            $htmlContent += @"
    <h2>CPU Kullanımı</h2>
    
    <div class="summary $cpuSummaryClass">
        <strong>Özet:</strong> Ortalama CPU kullanımı: $([math]::Round($avgCpu, 2))%
        ${if ($avgCpu -lt 60) {
            "CPU kullanımı normal aralıkta."
        } elseif ($avgCpu -lt 85) {
            "CPU kullanımı yüksek seviyede, bazı uygulamaları kapatmak performansı artırabilir."
        } else {
            "CPU kullanımı çok yüksek! Sistem yanıt vermekte zorlanabilir."
        }}
    </div>
    
    <div class="chart-container" style="height: 250px;">
"@

            for ($i = 0; $i -lt $cpuValues.Count; $i++) {
                $height = [math]::Max(($cpuValues[$i] * 2), 1)
                $barClass = if ($cpuValues[$i] -lt 60) { "good" } elseif ($cpuValues[$i] -lt 85) { "warning" } else { "danger" }
                
                $htmlContent += @"
        <div class="chart-bar $barClass" style="height: ${height}px; bottom: 0;">
            <div class="chart-value">$([math]::Round($cpuValues[$i], 1))%</div>
            <div class="chart-label">$($i + 1)</div>
        </div>
"@
            }
            
            $htmlContent += @"
    </div>
    
    <h3>En Çok CPU Kullanan Süreçler</h3>
    <table>
        <tr><th>Süreç Adı</th><th>CPU Kullanımı</th><th>Bellek Kullanımı (MB)</th><th>ID</th></tr>
"@

            foreach ($process in $topCpuProcesses) {
                $memorySizeMB = [math]::Round($process.WorkingSet / 1MB, 2)
                $cpuUsage = [math]::Round($process.CPU, 2)
                
                $htmlContent += @"
        <tr>
            <td>$($process.ProcessName)</td>
            <td>$cpuUsage</td>
            <td>$memorySizeMB</td>
            <td>$($process.Id)</td>
        </tr>
"@
            }
            
            $htmlContent += @"
    </table>
"@
            
            # Bellek Kullanımı
            $avgMemory = ($memoryValues | Measure-Object -Average).Average
            $memorySummaryClass = if ($avgMemory -lt 70) { "good" } elseif ($avgMemory -lt 90) { "warning" } else { "danger" }
            
            $htmlContent += @"
    <h2>Bellek Kullanımı</h2>
    
    <div class="summary $memorySummaryClass">
        <strong>Özet:</strong> Ortalama bellek kullanımı: $([math]::Round($avgMemory, 2))%
        ${if ($avgMemory -lt 70) {
            "Bellek kullanımı normal aralıkta."
        } elseif ($avgMemory -lt 90) {
            "Bellek kullanımı yüksek seviyede, bazı uygulamaları kapatmak performansı artırabilir."
        } else {
            "Bellek kullanımı çok yüksek! Sistem yanıt vermekte zorlanabilir. RAM yükseltmesi düşünülebilir."
        }}
    </div>
    
    <div class="chart-container" style="height: 250px;">
"@

            for ($i = 0; $i -lt $memoryValues.Count; $i++) {
                $height = [math]::Max(($memoryValues[$i] * 2), 1)
                $barClass = if ($memoryValues[$i] -lt 70) { "good" } elseif ($memoryValues[$i] -lt 90) { "warning" } else { "danger" }
                
                $htmlContent += @"
        <div class="chart-bar $barClass" style="height: ${height}px; bottom: 0;">
            <div class="chart-value">$([math]::Round($memoryValues[$i], 1))%</div>
            <div class="chart-label">$($i + 1)</div>
        </div>
"@
            }
            
            $htmlContent += @"
    </div>
    
    <h3>En Çok Bellek Kullanan Süreçler</h3>
    <table>
        <tr><th>Süreç Adı</th><th>Bellek Kullanımı (MB)</th><th>CPU Kullanımı</th><th>ID</th></tr>
"@

            foreach ($process in $topMemoryProcesses) {
                $memorySizeMB = [math]::Round($process.WorkingSet / 1MB, 2)
                $cpuUsage = [math]::Round($process.CPU, 2)
                
                $htmlContent += @"
        <tr>
            <td>$($process.ProcessName)</td>
            <td>$memorySizeMB</td>
            <td>$cpuUsage</td>
            <td>$($process.Id)</td>
        </tr>
"@
            }
            
            $htmlContent += @"
    </table>
"@
            
            # Disk Kullanımı
            $avgDisk = ($diskValues | Measure-Object -Average).Average
            $diskSummaryClass = if ($avgDisk -lt 60) { "good" } elseif ($avgDisk -lt 85) { "warning" } else { "danger" }
            
            $htmlContent += @"
    <h2>Disk Aktivitesi</h2>
    
    <div class="summary $diskSummaryClass">
        <strong>Özet:</strong> Ortalama disk kullanımı: $([math]::Round($avgDisk, 2))%
        ${if ($avgDisk -lt 60) {
            "Disk aktivitesi normal aralıkta."
        } elseif ($avgDisk -lt 85) {
            "Disk aktivitesi yüksek. SSD yükseltmesi performansı artırabilir."
        } else {
            "Disk aktivitesi çok yüksek! Sistem yanıt vermekte zorlanabilir. SSD yükseltmesi önerilir."
        }}
    </div>
    
    <div class="chart-container" style="height: 250px;">
"@

            for ($i = 0; $i -lt $diskValues.Count; $i++) {
                $height = [math]::Max(($diskValues[$i] * 2), 1)
                $barClass = if ($diskValues[$i] -lt 60) { "good" } elseif ($diskValues[$i] -lt 85) { "warning" } else { "danger" }
                
                $htmlContent += @"
        <div class="chart-bar $barClass" style="height: ${height}px; bottom: 0;">
            <div class="chart-value">$([math]::Round($diskValues[$i], 1))%</div>
            <div class="chart-label">$($i + 1)</div>
        </div>
"@
            }
            
            $htmlContent += @"
    </div>
"@
            
            # Ağ Kullanımı
            $avgNetwork = ($networkValues | Measure-Object -Average).Average
            
            $htmlContent += @"
    <h2>Ağ Aktivitesi</h2>
    
    <div class="summary good">
        <strong>Özet:</strong> Ortalama ağ kullanımı: $([math]::Round($avgNetwork, 2)) MB/s
    </div>
    
    <div class="chart-container" style="height: 250px;">
"@

            $maxNetworkValue = ($networkValues | Measure-Object -Maximum).Maximum
            $scaleFactor = if ($maxNetworkValue -gt 0) { 200 / $maxNetworkValue } else { 1 }
            
            for ($i = 0; $i -lt $networkValues.Count; $i++) {
                $height = [math]::Max(($networkValues[$i] * $scaleFactor), 1)
                
                $htmlContent += @"
        <div class="chart-bar good" style="height: ${height}px; bottom: 0;">
            <div class="chart-value">$([math]::Round($networkValues[$i], 1)) MB/s</div>
            <div class="chart-label">$($i + 1)</div>
        </div>
"@
            }
            
            $htmlContent += @"
    </div>
    
    <h2>Genel Performans Özeti</h2>
"@

            # Genel performans özeti
            $overallClass = "good"
            $recommendation = "Sistem genel olarak iyi durumda ve normal performans gösteriyor."
            
            if ($avgCpu -gt 80 -or $avgMemory -gt 85 -or $avgDisk -gt 80) {
                $overallClass = "danger"
                $recommendation = "Sistem performans sorunları yaşıyor ve optimizasyon gerekiyor."
            }
            elseif ($avgCpu -gt 60 -or $avgMemory -gt 70 -or $avgDisk -gt 60) {
                $overallClass = "warning"
                $recommendation = "Sistem yüksek yük altında, bazı optimizasyonlar gerekebilir."
            }
            
            $htmlContent += @"
    <div class="summary $overallClass">
        <strong>Genel Durum:</strong> $recommendation
        
        <ul>
"@

            if ($avgCpu -gt 80) {
                $htmlContent += @"
            <li>CPU kullanımı kritik seviyede. Arkaplandaki gereksiz uygulamaları kapatmayı deneyin.</li>
"@
            }
            elseif ($avgCpu -gt 60) {
                $htmlContent += @"
            <li>CPU kullanımı yüksek. Aktif süreçleri kontrol edin.</li>
"@
            }
            
            if ($avgMemory -gt 85) {
                $htmlContent += @"
            <li>Bellek kullanımı kritik seviyede. RAM yükseltmesi düşünebilirsiniz.</li>
"@
            }
            elseif ($avgMemory -gt 70) {
                $htmlContent += @"
            <li>Bellek kullanımı yüksek. Bellek optimizasyonu faydalı olabilir.</li>
"@
            }
            
            if ($avgDisk -gt 80) {
                $htmlContent += @"
            <li>Disk aktivitesi kritik seviyede. SSD yükseltmesi önerilir.</li>
"@
            }
            elseif ($avgDisk -gt 60) {
                $htmlContent += @"
            <li>Disk aktivitesi yüksek. Disk temizliği yapılması faydalı olabilir.</li>
"@
            }
            
            $htmlContent += @"
        </ul>
    </div>
"@
            
            # HTML Sonu
            $htmlContent += @"
</body>
</html>
"@
            
            # Dosyaya yaz
            $htmlContent | Out-File -FilePath $reportFile -Encoding utf8
            
            Write-Host "Rapor oluşturuldu: $reportFile" -ForegroundColor Green
            Invoke-Item $reportFile
            
            Pause
            Show-ReportingMenu
        }
        "7" {
            Write-Host "`nGüncelleştirme Geçmişi Raporu Oluşturuluyor..." -ForegroundColor Yellow
            
            $reportFile = "$env:USERPROFILE\Desktop\GüncelleştirmeGeçmişi_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
            
            # Güncelleştirme geçmişini al
            try {
                if (Test-ModuleInstalled -ModuleName "PSWindowsUpdate") {
                    $updates = Get-WUHistory | 
                              Select-Object @{Name="Başlık";Expression={$_.Title}}, 
                                          @{Name="KB_Numarası";Expression={$_.KB}}, 
                                          @{Name="KategoriID";Expression={$_.CategoryIDs}}, 
                                          @{Name="Kategoriler";Expression={$_.Categories}}, 
                                          @{Name="Tarih";Expression={$_.Date}}
                    
                    $updates | Export-Csv -Path $reportFile -NoTypeInformation -Encoding UTF8
                    
                    Write-Host "Rapor oluşturuldu: $reportFile" -ForegroundColor Green
                    Invoke-Item (Split-Path $reportFile -Parent)
                }
                else {
                    Write-Host "PSWindowsUpdate modülü yüklü değil. Yüklemek için ana menüden modül kurulumunu çalıştırın." -ForegroundColor Yellow
                }
            }
            catch {
                Write-Host "Güncelleştirme geçmişi alınamadı: $($_.Exception.Message)" -ForegroundColor Red
            }
            
            Pause
            Show-ReportingMenu
        }
        "8" {
            Write-Host "`nOlay Günlüğü Raporu Oluşturuluyor..." -ForegroundColor Yellow
            
            $reportFile = "$env:USERPROFILE\Desktop\OlayGünlüğüRaporu_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
            
            # Olay günlüğünden hatalar ve uyarıları al
            $startDate = (Get-Date).AddDays(-7)
            
            $systemErrors = Get-EventLog -LogName System -EntryType Error -After $startDate -ErrorAction SilentlyContinue
            $systemWarnings = Get-EventLog -LogName System -EntryType Warning -After $startDate -ErrorAction SilentlyContinue
            $applicationErrors = Get-EventLog -LogName Application -EntryType Error -After $startDate -ErrorAction SilentlyContinue
            $applicationWarnings = Get-EventLog -LogName Application -EntryType Warning -After $startDate -ErrorAction SilentlyContinue
            
            # HTML Başlangıcı
            $htmlContent = @"
<!DOCTYPE html>
<html>
<head>
    <title>Olay Günlüğü Raporu</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1 { color: #0066cc; }
        h2 { color: #0099cc; margin-top: 30px; border-bottom: 1px solid #ddd; padding-bottom: 5px; }
        h3 { color: #5cb85c; margin-top: 20px; }
        table { border-collapse: collapse; width: 100%; margin: 20px 0; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        tr:nth-child(even) { background-color: #f9f9f9; }
        .error { color: #d9534f; }
        .warning { color: #f0ad4e; }
        .summary { padding: 15px; margin-top: 20px; border-radius: 5px; }
        .summary.good { background-color: #dff0d8; border: 1px solid #d6e9c6; }
        .summary.warning { background-color: #fcf8e3; border: 1px solid #faebcc; }
        .summary.danger { background-color: #f2dede; border: 1px solid #ebccd1; }
        .message { max-width: 500px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
        .expand-btn { cursor: pointer; color: blue; text-decoration: underline; }
    </style>
    <script>
        function toggleMessage(id) {
            var element = document.getElementById(id);
            if (element.style.whiteSpace === 'normal') {
                element.style.whiteSpace = 'nowrap';
                element.style.maxWidth = '500px';
                document.getElementById(id + '-btn').innerText = 'Genişlet';
            } else {
                element.style.whiteSpace = 'normal';
                element.style.maxWidth = 'none';
                document.getElementById(id + '-btn').innerText = 'Daralt';
            }
        }
    </script>
</head>
<body>
    <h1>Olay Günlüğü Raporu</h1>
    <p>Oluşturma Tarihi: $(Get-Date)</p>
    <p>Bilgisayar Adı: $env:COMPUTERNAME</p>
    <p>Rapor Periyodu: Son 7 gün ($(Get-Date $startDate -Format 'dd.MM.yyyy') - $(Get-Date -Format 'dd.MM.yyyy'))</p>
"@
            
            # Özet Bilgisi
            $totalSystemErrors = if ($systemErrors) { $systemErrors.Count } else { 0 }
            $totalSystemWarnings = if ($systemWarnings) { $systemWarnings.Count } else { 0 }
            $totalApplicationErrors = if ($applicationErrors) { $applicationErrors.Count } else { 0 }
            $totalApplicationWarnings = if ($applicationWarnings) { $applicationWarnings.Count } else { 0 }
            
            $totalErrors = $totalSystemErrors + $totalApplicationErrors
            $totalWarnings = $totalSystemWarnings + $totalApplicationWarnings
            $summaryClass = if ($totalErrors -eq 0 -and $totalWarnings -lt 10) { "good" } elseif ($totalErrors -lt 5 -and $totalWarnings -lt 20) { "warning" } else { "danger" }
            
            $htmlContent += @"
    <h2>Özet</h2>
    
    <div class="summary $summaryClass">
        <p><strong>Toplam Hata:</strong> $totalErrors</p>
        <p><strong>Toplam Uyarı:</strong> $totalWarnings</p>
        
        <p><strong>Sistem Günlüğü:</strong> $totalSystemErrors hata, $totalSystemWarnings uyarı</p>
        <p><strong>Uygulama Günlüğü:</strong> $totalApplicationErrors hata, $totalApplicationWarnings uyarı</p>
    </div>
"@
            
            # Sistem Hataları
            $htmlContent += @"
    <h2>Sistem Günlüğü</h2>
    <h3 class="error">Hatalar ($totalSystemErrors)</h3>
"@

            if ($systemErrors -and $systemErrors.Count -gt 0) {
                $htmlContent += @"
    <table>
        <tr><th>Tarih</th><th>Kaynak</th><th>Olay ID</th><th>Mesaj</th></tr>
"@

                $counter = 0
                foreach ($error in $systemErrors) {
                    $counter++
                    $messageId = "syserr-$counter"
                    $htmlContent += @"
        <tr>
            <td>$($error.TimeGenerated)</td>
            <td>$($error.Source)</td>
            <td>$($error.EventID)</td>
            <td>
                <div id="$messageId" class="message">$($error.Message -replace '<', '&lt;' -replace '>', '&gt;')</div>
                <span id="$messageId-btn" class="expand-btn" onclick="toggleMessage('$messageId')">Genişlet</span>
            </td>
        </tr>
"@
                }
                
                $htmlContent += @"
    </table>
"@
            }
            else {
                $htmlContent += @"
    <p>Son 7 günde sistem hatası bulunmamaktadır.</p>
"@
            }
            
            # Sistem Uyarıları
            $htmlContent += @"
    <h3 class="warning">Uyarılar ($totalSystemWarnings)</h3>
"@

            if ($systemWarnings -and $systemWarnings.Count -gt 0) {
                $htmlContent += @"
    <table>
        <tr><th>Tarih</th><th>Kaynak</th><th>Olay ID</th><th>Mesaj</th></tr>
"@

                $counter = 0
                foreach ($warning in $systemWarnings) {
                    $counter++
                    $messageId = "syswarn-$counter"
                    $htmlContent += @"
        <tr>
            <td>$($warning.TimeGenerated)</td>
            <td>$($warning.Source)</td>
            <td>$($warning.EventID)</td>
            <td>
                <div id="$messageId" class="message">$($warning.Message -replace '<', '&lt;' -replace '>', '&gt;')</div>
                <span id="$messageId-btn" class="expand-btn" onclick="toggleMessage('$messageId')">Genişlet</span>
            </td>
        </tr>
"@
                }
                
                $htmlContent += @"
    </table>
"@
            }
            else {
                $htmlContent += @"
    <p>Son 7 günde sistem uyarısı bulunmamaktadır.</p>
"@
            }
            
            # Uygulama Hataları
            $htmlContent += @"
    <h2>Uygulama Günlüğü</h2>
    <h3 class="error">Hatalar ($totalApplicationErrors)</h3>
"@

            if ($applicationErrors -and $applicationErrors.Count -gt 0) {
                $htmlContent += @"
    <table>
        <tr><th>Tarih</th><th>Kaynak</th><th>Olay ID</th><th>Mesaj</th></tr>
"@

                $counter = 0
                foreach ($error in $applicationErrors) {
                    $counter++
                    $messageId = "apperr-$counter"
                    $htmlContent += @"
        <tr>
            <td>$($error.TimeGenerated)</td>
            <td>$($error.Source)</td>
            <td>$($error.EventID)</td>
            <td>
                <div id="$messageId" class="message">$($error.Message -replace '<', '&lt;' -replace '>', '&gt;')</div>
                <span id="$messageId-btn" class="expand-btn" onclick="toggleMessage('$messageId')">Genişlet</span>
            </td>
        </tr>
"@
                }
                
                $htmlContent += @"
    </table>
"@
            }
            else {
                $htmlContent += @"
    <p>Son 7 günde uygulama hatası bulunmamaktadır.</p>
"@
            }
            
            # Uygulama Uyarıları
            $htmlContent += @"
    <h3 class="warning">Uyarılar ($totalApplicationWarnings)</h3>
"@

            if ($applicationWarnings -and $applicationWarnings.Count -gt 0) {
                $htmlContent += @"
    <table>
        <tr><th>Tarih</th><th>Kaynak</th><th>Olay ID</th><th>Mesaj</th></tr>
"@

                $counter = 0
                foreach ($warning in $applicationWarnings) {
                    $counter++
                    $messageId = "appwarn-$counter"
                    $htmlContent += @"
        <tr>
            <td>$($warning.TimeGenerated)</td>
            <td>$($warning.Source)</td>
            <td>$($warning.EventID)</td>
            <td>
                <div id="$messageId" class="message">$($warning.Message -replace '<', '&lt;' -replace '>', '&gt;')</div>
                <span id="$messageId-btn" class="expand-btn" onclick="toggleMessage('$messageId')">Genişlet</span>
            </td>
        </tr>
"@
                }
                
                $htmlContent += @"
    </table>
"@
            }
            else {
                $htmlContent += @"
    <p>Son 7 günde uygulama uyarısı bulunmamaktadır.</p>
"@
            }
            
            # HTML Sonu
            $htmlContent += @"
</body>
</html>
"@
            
            # Dosyaya yaz
            $htmlContent | Out-File -FilePath $reportFile -Encoding utf8
            
            Write-Host "Rapor oluşturuldu: $reportFile" -ForegroundColor Green
            Invoke-Item $reportFile
            
            Pause
            Show-ReportingMenu
        }
        "9" {
            Write-Host "`nTam Sistem Bilgisi Raporu Oluşturuluyor..." -ForegroundColor Yellow
            
            $reportFile = "$env:USERPROFILE\Desktop\SistemBilgisiRaporu_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
            
            # msinfo32 çalıştır ve sistem bilgisi raporunu XML formatında al
            $xmlTempFile = "$env:TEMP\SystemInfo_$(Get-Date -Format 'yyyyMMdd_HHmmss').xml"
            
            try {
                Start-Process -FilePath "msinfo32.exe" -ArgumentList "/report `"$xmlTempFile`"" -Wait
                Write-Host "Sistem bilgisi raporu oluşturuldu, HTML formatına dönüştürülüyor..." -ForegroundColor Yellow
                
                # XML'i oku ve içeriğini HTML'e dönüştür
                [xml]$systemInfoXml = Get-Content -Path $xmlTempFile -ErrorAction Stop
                
                # HTML Başlangıcı
                $htmlContent = @"
<!DOCTYPE html>
<html>
<head>
    <title>Tam Sistem Bilgisi Raporu</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1 { color: #0066cc; }
        h2 { color: #0099cc; margin-top: 30px; border-bottom: 1px solid #ddd; padding-bottom: 5px; }
        h3 { color: #5cb85c; margin-top: 20px; }
        table { border-collapse: collapse; width: 100%; margin: 20px 0; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        tr:nth-child(even) { background-color: #f9f9f9; }
        .section { margin-bottom: 40px; }
        .category { margin-top: 30px; }
    </style>
</head>
<body>
    <h1>Tam Sistem Bilgisi Raporu</h1>
    <p>Oluşturma Tarihi: $(Get-Date)</p>
    <p>Bilgisayar Adı: $env:COMPUTERNAME</p>
"@
                
                # XML'den sistem bilgisi bölümlerini al
                $categories = $systemInfoXml.MSINFORMATION.CATEGORY
                
                foreach ($category in $categories) {
                    $htmlContent += @"
    <div class="section">
        <h2>$($category.NAME)</h2>
"@
                    
                    foreach ($subcategory in $category.CATEGORY) {
                        $htmlContent += @"
        <div class="category">
            <h3>$($subcategory.NAME)</h3>
            <table>
                <tr><th>Öğe</th><th>Değer</th></tr>
"@
                        
                        foreach ($data in $subcategory.DATA) {
                            $htmlContent += @"
                <tr>
                    <td>$($data.NAME)</td>
                    <td>$($data.DATA)</td>
                </tr>
"@
                        }
                        
                        $htmlContent += @"
            </table>
        </div>
"@
                    }
                    
                    $htmlContent += @"
    </div>
"@
                }
                
                # HTML Sonu
                $htmlContent += @"
</body>
</html>
"@
                
                # Geçici XML dosyasını temizle
                Remove-Item -Path $xmlTempFile -Force
                
                # HTML dosyasını oluştur
                $htmlContent | Out-File -FilePath $reportFile -Encoding utf8
                
                Write-Host "Rapor oluşturuldu: $reportFile" -ForegroundColor Green
                Invoke-Item $reportFile
            }
            catch {
                Write-Host "Sistem bilgisi raporu oluşturulurken hata oluştu: $($_.Exception.Message)" -ForegroundColor Red
                
                if (Test-Path $xmlTempFile) {
                    Remove-Item -Path $xmlTempFile -Force
                }
            }
            
            Pause
            Show-ReportingMenu
        }
        "10" {
            Show-MainMenu
        }
        default {
            Write-Host "Geçersiz seçim. Lütfen tekrar deneyin." -ForegroundColor Red
            Start-Sleep -Seconds 2
            Show-ReportingMenu
        }
    }
}

# Ana Menü
function Show-MainMenu {
    Clear-Host
    Show-WamsSplashScreen
    
    Write-Host "`n[Ana Menü]`n" -ForegroundColor Cyan
    Write-Host "1. Sistem Bilgisi Görüntüle"
    Write-Host "2. Güncelleştirme Yönetimi"
    Write-Host "3. Ağ Yönetimi"
    Write-Host "4. Bakım ve Onarım"
    Write-Host "5. Performans ve Optimizasyon"
    Write-Host "6. Güvenlik ve Gizlilik"
    Write-Host "7. Donanım ve Yazıcı Yönetimi"
    Write-Host "8. Sistem Raporlama"
    Write-Host "9. Gerekli Modülleri Kur"
    Write-Host "10. Bilgisayarı Kapat veya Yeniden Başlat"
    Write-Host "11. Çıkış"
    
    $choice = Read-Host "`nSeçiminiz"
    
    switch ($choice) {
        "1" {
            Get-SystemOverview
            Pause
            Show-MainMenu
        }
        "2" { Show-UpdatesMenu }
        "3" { Show-NetworkMenu }
        "4" { Show-MaintenanceMenu }
        "5" { Show-PerformanceMenu }
        "6" { Show-SecurityMenu }
        "7" { Show-HardwareMenu }
        "8" { Show-ReportingMenu }
        "9" {
            Write-Host "`nGerekli modüller yükleniyor..." -ForegroundColor Yellow
            Initialize-RequiredModules
            Pause
            Show-MainMenu
        }
        "10" {
            Clear-Host
            Show-WamsSplashScreen
            
            Write-Host "`n[Bilgisayarı Kapat veya Yeniden Başlat]`n" -ForegroundColor Cyan
            Write-Host "1. Bilgisayarı Kapat"
            Write-Host "2. Bilgisayarı Yeniden Başlat"
            Write-Host "3. Oturumu Kapat"
            Write-Host "4. Ana Menüye Dön"
            
            $shutdownChoice = Read-Host "`nSeçiminiz"
            
            switch ($shutdownChoice) {
                "1" {
                    $confirm = Read-Host "Bilgisayarı kapatmak istediğinize emin misiniz? (E/H)"
                    if ($confirm -eq "E" -or $confirm -eq "e") {
                        Write-Host "Bilgisayar kapatılıyor..." -ForegroundColor Yellow
                        Stop-Computer -Force
                    }
                    else {
                        Show-MainMenu
                    }
                }
                "2" {
                    $confirm = Read-Host "Bilgisayarı yeniden başlatmak istediğinize emin misiniz? (E/H)"
                    if ($confirm -eq "E" -or $confirm -eq "e") {
                        Write-Host "Bilgisayar yeniden başlatılıyor..." -ForegroundColor Yellow
                        Restart-Computer -Force
                    }
                    else {
                        Show-MainMenu
                    }
                }
                "3" {
                    $confirm = Read-Host "Oturumu kapatmak istediğinize emin misiniz? (E/H)"
                    if ($confirm -eq "E" -or $confirm -eq "e") {
                        Write-Host "Oturum kapatılıyor..." -ForegroundColor Yellow
                        shutdown.exe /l
                    }
                    else {
                        Show-MainMenu
                    }
                }
                "4" { Show-MainMenu }
                default {
                    Write-Host "Geçersiz seçim. Ana menüye dönülüyor..." -ForegroundColor Red
                    Start-Sleep -Seconds 2
                    Show-MainMenu
                }
            }
        }
        "11" {
            Clear-Host
            Write-Host "Windows Advanced Management Suite'ten çıkılıyor..." -ForegroundColor Yellow
            Start-Sleep -Seconds 1
            exit
        }
        default {
            Write-Host "Geçersiz seçim. Lütfen tekrar deneyin." -ForegroundColor Red
            Start-Sleep -Seconds 2
            Show-MainMenu
        }
    }
}

# Ana program
# Yönetici haklarını kontrol et
if (-not (Test-AdminRights)) {
    Write-Host "Bazı özellikler için yönetici hakları gerekiyor. Yönetici olarak çalıştırmak ister misiniz? (E/H)" -ForegroundColor Yellow
    $adminChoice = Read-Host 
    
    if ($adminChoice -eq "E" -or $adminChoice -eq "e") {
        Request-AdminRights
    }
    else {
        Write-Host "Program sınırlı yetkilerle devam edecek. Bazı özellikler çalışmayabilir." -ForegroundColor Yellow
        Start-Sleep -Seconds 2
    }
}

# Programı başlat
Show-MainMenu GB - %$freeSpacePercent" -ForegroundColor $freeSpaceColor -NoNewline
        Write-Host ")"
    }
    
    # Ağ Bilgisi
    $network = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
    Write-Host "Ağ Adaptörleri:" -ForegroundColor White
    
    foreach ($adapter in $network) {
        $config = Get-NetIPConfiguration -InterfaceIndex $adapter.ifIndex
        Write-Host "  $($adapter.Name) - $($adapter.LinkSpeed)" -ForegroundColor White
        
        if ($config.IPv4Address) {
            Write-Host "    IPv4: " -NoNewline
            Write-Host "$($config.IPv4Address.IPAddress)" -ForegroundColor Green
        }
    }
}

# Güncelleştirme Yönetim Fonksiyonları
function Show-UpdatesMenu {
    if (-not (Test-ModuleInstalled -ModuleName "PSWindowsUpdate")) {
        Write-Host "PSWindowsUpdate modülü yüklü değil. Yüklemek için ana menüden modül kurulumunu çalıştırın." -ForegroundColor Yellow
        return
    }
    
    Clear-Host
    Show-WamsSplashScreen
    
    Write-Host "`n[Güncelleştirme Yönetimi]`n" -ForegroundColor Cyan
    Write-Host "1. Mevcut Güncelleştirmeleri Listele"
    Write-Host "2. Tüm Güncelleştirmeleri Yükle"
    Write-Host "3. Belirli Bir Güncelleştirmeyi Yükle"
    Write-Host "4. Windows Store Uygulamalarını Güncelle"
    Write-Host "5. Yüklü Güncelleştirme Geçmişini Göster"
    Write-Host "6. Ana Menüye Dön"
    
    $choice = Read-Host "`nSeçiminiz"
    
    switch ($choice) {
        "1" {
            Write-Host "`nMevcut güncelleştirmeler kontrol ediliyor..." -ForegroundColor Yellow
            Get-WindowsUpdate
            Pause
            Show-UpdatesMenu
        }
        "2" {
            Write-Host "`nTüm güncelleştirmeler yükleniyor..." -ForegroundColor Yellow
            Install-WindowsUpdate -AcceptAll -AutoReboot
            Pause
            Show-UpdatesMenu
        }
        "3" {
            $updates = Get-WindowsUpdate
            Write-Host "`nMevcut güncelleştirmeler:" -ForegroundColor Yellow
            $i = 1
            foreach ($update in $updates) {
                Write-Host "$i. $($update.Title)"
                $i++
            }
            
            $updateChoice = Read-Host "`nYüklemek istediğiniz güncelleştirmenin numarasını girin"
            if ($updateChoice -match '^\d+$' -and [int]$updateChoice -ge 1 -and [int]$updateChoice -le $updates.Count) {
                $selectedUpdate = $updates[[int]$updateChoice - 1]
                Install-WindowsUpdate -KBArticleID $selectedUpdate.KBArticleID -AcceptAll
            }
            else {
                Write-Host "Geçersiz seçim." -ForegroundColor Red
            }
            
            Pause
            Show-UpdatesMenu
        }
        "4" {
            Write-Host "`nWindows Store uygulamaları güncelleniyor..." -ForegroundColor Yellow
            Start-Process "ms-windows-store://updates"
            Pause
            Show-UpdatesMenu
        }
        "5" {
            Write-Host "`nYüklü güncelleştirme geçmişi:" -ForegroundColor Yellow
            Get-WUHistory
            Pause
            Show-UpdatesMenu
        }
        "6" {
            Show-MainMenu
        }
        default {
            Write-Host "Geçersiz seçim. Lütfen tekrar deneyin." -ForegroundColor Red
            Start-Sleep -Seconds 2
            Show-UpdatesMenu
        }
    }
}

# Ağ Yönetimi Fonksiyonları
function Show-NetworkMenu {
    Clear-Host
    Show-WamsSplashScreen
    
    Write-Host "`n[Ağ Yönetimi]`n" -ForegroundColor Cyan
    Write-Host "1. IP Yapılandırmasını Görüntüle"
    Write-Host "2. Tüm Ağ Adaptörlerini Görüntüle"
    Write-Host "3. DNS Önbelleğini Temizle"
    Write-Host "4. IP Yapılandırmasını Yenile (Renew)"
    Write-Host "5. IP Yapılandırmasını Serbest Bırak (Release)"
    Write-Host "6. Ping Testi Yap"
    Write-Host "7. Traceroute Testi Yap"
    Write-Host "8. Wi-Fi Profil Bilgilerini Göster"
    Write-Host "9. Ağ İstatistiklerini Göster"
    Write-Host "10. Açık Portları Tarama (NetStat)"
    Write-Host "11. Ana Menüye Dön"
    
    $choice = Read-Host "`nSeçiminiz"
    
    switch ($choice) {
        "1" {
            Write-Host "`nIP Yapılandırması:" -ForegroundColor Yellow
            Get-NetIPConfiguration | Format-Table -AutoSize
            Pause
            Show-NetworkMenu
        }
        "2" {
            Write-Host "`nTüm Ağ Adaptörleri:" -ForegroundColor Yellow
            Get-NetAdapter | Format-Table -AutoSize
            Pause
            Show-NetworkMenu
        }
        "3" {
            Write-Host "`nDNS Önbelleği Temizleniyor..." -ForegroundColor Yellow
            Clear-DnsClientCache
            Write-Host "DNS Önbelleği Temizlendi." -ForegroundColor Green
            Pause
            Show-NetworkMenu
        }
        "4" {
            if (Test-AdminRights) {
                Write-Host "`nIP Yapılandırması Yenileniyor..." -ForegroundColor Yellow
                $adapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
                foreach ($adapter in $adapters) {
                    Try {
                        $null = Remove-NetIPAddress -InterfaceIndex $adapter.ifIndex -Confirm:$false -ErrorAction Stop
                        $null = Remove-NetRoute -InterfaceIndex $adapter.ifIndex -Confirm:$false -ErrorAction Stop
                        $null = Clear-DnsClientCache -ErrorAction Stop
                        Start-Sleep -Seconds 1
                        $null = Enable-NetAdapter -InterfaceIndex $adapter.ifIndex -Confirm:$false -ErrorAction Stop
                        Write-Host "Adaptör $($adapter.Name) için IP yapılandırması yenilendi." -ForegroundColor Green
                    }
                    Catch {
                        Write-Host "Hata: $($_.Exception.Message)" -ForegroundColor Red
                    }
                }
            }
            else {
                Write-Host "Bu işlem için yönetici hakları gerekiyor." -ForegroundColor Red
            }
            Pause
            Show-NetworkMenu
        }
        "5" {
            if (Test-AdminRights) {
                Write-Host "`nIP Yapılandırması Serbest Bırakılıyor..." -ForegroundColor Yellow
                $adapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
                foreach ($adapter in $adapters) {
                    Try {
                        $null = Remove-NetIPAddress -InterfaceIndex $adapter.ifIndex -Confirm:$false -ErrorAction Stop
                        $null = Remove-NetRoute -InterfaceIndex $adapter.ifIndex -Confirm:$false -ErrorAction Stop
                        Write-Host "Adaptör $($adapter.Name) için IP yapılandırması serbest bırakıldı." -ForegroundColor Green
                    }
                    Catch {
                        Write-Host "Hata: $($_.Exception.Message)" -ForegroundColor Red
                    }
                }
            }
            else {
                Write-Host "Bu işlem için yönetici hakları gerekiyor." -ForegroundColor Red
            }
            Pause
            Show-NetworkMenu
        }
        "6" {
            $target = Read-Host "`nPinglemek istediğiniz IP adresi veya alan adını girin"
            Write-Host "`nPing testi yapılıyor: $target" -ForegroundColor Yellow
            Test-Connection -ComputerName $target -Count 4
            Pause
            Show-NetworkMenu
        }
        "7" {
            $target = Read-Host "`nTraceroute testi yapmak istediğiniz IP adresi veya alan adını girin"
            Write-Host "`nTraceroute testi yapılıyor: $target" -ForegroundColor Yellow
            Test-NetConnection -TraceRoute -ComputerName $target
            Pause
            Show-NetworkMenu
        }
        "8" {
            Write-Host "`nWi-Fi Profil Bilgileri:" -ForegroundColor Yellow
            if (Test-AdminRights) {
                $profiles = netsh wlan show profiles | Select-String -Pattern "All User Profile" | ForEach-Object { ($_ -split ":")[-1].Trim() }
                foreach ($profile in $profiles) {
                    Write-Host "`nProfil: $profile" -ForegroundColor Green
                    netsh wlan show profile name="$profile" key=clear | Select-String -Pattern "Key Content"
                }
            }
            else {
                Write-Host "Şifre bilgilerini görmek için yönetici hakları gerekiyor." -ForegroundColor Red
                $profiles = netsh wlan show profiles | Select-String -Pattern "All User Profile" | ForEach-Object { ($_ -split ":")[-1].Trim() }
                foreach ($profile in $profiles) {
                    Write-Host "Profil: $profile" -ForegroundColor Green
                }
            }
            Pause
            Show-NetworkMenu
        }
        "9" {
            Write-Host "`nAğ İstatistikleri:" -ForegroundColor Yellow
            Get-NetAdapterStatistics | Format-Table -AutoSize
            Pause
            Show-NetworkMenu
        }
        "10" {
            Write-Host "`nAçık Portlar ve Bağlantılar:" -ForegroundColor Yellow
            Get-NetTCPConnection | Where-Object { $_.State -eq "Established" } | 
            Format-Table -Property LocalAddress, LocalPort, RemoteAddress, RemotePort, State -AutoSize
            Pause
            Show-NetworkMenu
        }
        "11" {
            Show-MainMenu
        }
        default {
            Write-Host "Geçersiz seçim. Lütfen tekrar deneyin." -ForegroundColor Red
            Start-Sleep -Seconds 2
            Show-NetworkMenu
        }
    }
}

# Bakım ve Onarım Fonksiyonları
function Show-MaintenanceMenu {
    Clear-Host
    Show-WamsSplashScreen
    
    Write-Host "`n[Bakım ve Onarım]`n" -ForegroundColor Cyan
    Write-Host "1. Sistem Dosyalarını Tara ve Onar (SFC)"
    Write-Host "2. Disk Kontrolü ve Onarımı (CHKDSK)"
    Write-Host "3. Windows Image (DISM) ile Onarım"
    Write-Host "4. Disk Temizliği (Cleanmgr)"
    Write-Host "5. Temporary Dosyaları Temizle"
    Write-Host "6. Windows Önbelleğini Temizle"
    Write-Host "7. Güvenli Mod Seçenekleri"
    Write-Host "8. Otomatik Başlangıç Öğelerini Yönet"
    Write-Host "9. Ana Menüye Dön"
    
    $choice = Read-Host "`nSeçiminiz"
    
    switch ($choice) {
        "1" {
            if (Test-AdminRights) {
                Write-Host "`nSistem dosyaları taranıyor ve onarılıyor..." -ForegroundColor Yellow
                Start-Process -FilePath "sfc.exe" -ArgumentList "/scannow" -Wait
                Write-Host "SFC taraması tamamlandı." -ForegroundColor Green
            }
            else {
                Write-Host "Bu işlem için yönetici hakları gerekiyor." -ForegroundColor Red
            }
            Pause
            Show-MaintenanceMenu
        }
        "2" {
            if (Test-AdminRights) {
                $drives = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DriveType=3" | 
                          Select-Object -ExpandProperty DeviceID
                
                Write-Host "`nMevcut sürücüler:" -ForegroundColor Yellow
                $i = 1
                foreach ($drive in $drives) {
                    Write-Host "$i. $drive"
                    $i++
                }
                
                $driveChoice = Read-Host "`nKontrol etmek istediğiniz sürücünün numarasını girin"
                
                if ($driveChoice -match '^\d+$' -and [int]$driveChoice -ge 1 -and [int]$driveChoice -le $drives.Count) {
                    $selectedDrive = $drives[[int]$driveChoice - 1]
                    
                    $options = Read-Host "Disk kontrol seçenekleri (Örn: /f /r - Tam tarama ve onarım için)"
                    
                    Write-Host "`n$selectedDrive sürücüsü için disk kontrolü başlatılıyor..." -ForegroundColor Yellow
                    if ($options) {
                        Start-Process -FilePath "chkdsk.exe" -ArgumentList "$selectedDrive $options" -Wait
                    }
                    else {
                        Start-Process -FilePath "chkdsk.exe" -ArgumentList "$selectedDrive" -Wait
                    }
                    
                    Write-Host "Disk kontrolü tamamlandı." -ForegroundColor Green
                }
                else {
                    Write-Host "Geçersiz sürücü seçimi." -ForegroundColor Red
                }
            }
            else {
                Write-Host "Bu işlem için yönetici hakları gerekiyor." -ForegroundColor Red
            }
            Pause
            Show-MaintenanceMenu
        }
        "3" {
            if (Test-AdminRights) {
                Write-Host "`nDISM ile Windows Image taraması ve onarımı yapılıyor..." -ForegroundColor Yellow
                
                Write-Host "1. Kontrol ET (CheckHealth)"
                Write-Host "2. Tara (ScanHealth)"
                Write-Host "3. Onar (RestoreHealth)"
                
                $dismChoice = Read-Host "`nSeçiminiz"
                
                switch ($dismChoice) {
                    "1" {
                        Write-Host "`nWindows Image sağlık kontrolü yapılıyor..." -ForegroundColor Yellow
                        Start-Process -FilePath "DISM.exe" -ArgumentList "/Online /Cleanup-Image /CheckHealth" -Wait
                    }
                    "2" {
                        Write-Host "`nWindows Image taraması yapılıyor..." -ForegroundColor Yellow
                        Start-Process -FilePath "DISM.exe" -ArgumentList "/Online /Cleanup-Image /ScanHealth" -Wait
                    }
                    "3" {
                        Write-Host "`nWindows Image onarımı yapılıyor..." -ForegroundColor Yellow
                        Start-Process -FilePath "DISM.exe" -ArgumentList "/Online /Cleanup-Image /RestoreHealth" -Wait
                    }
                    default {
                        Write-Host "Geçersiz seçim." -ForegroundColor Red
                    }
                }
                
                Write-Host "DISM işlemi tamamlandı." -ForegroundColor Green
            }
            else {
                Write-Host "Bu işlem için yönetici hakları gerekiyor." -ForegroundColor Red
            }
            Pause
            Show-MaintenanceMenu
        }
        "4" {
            Write-Host "`nDisk Temizliği başlatılıyor..." -ForegroundColor Yellow
            Start-Process -FilePath "cleanmgr.exe" -ArgumentList "/sagerun:1" -Wait
            Write-Host "Disk Temizliği tamamlandı." -ForegroundColor Green
            Pause
            Show-MaintenanceMenu
        }
        "5" {
            Write-Host "`nTemporary dosyalar temizleniyor..." -ForegroundColor Yellow
            
            # Temp klasörlerini temizle
            $tempFolders = @(
                "$env:TEMP",
                "C:\Windows\Temp"
            )
            
            foreach ($folder in $tempFolders) {
                if (Test-Path $folder) {
                    Write-Host "Temizleniyor: $folder" -ForegroundColor Yellow
                    try {
                        Remove-Item -Path "$folder\*" -Recurse -Force -ErrorAction SilentlyContinue
                        Write-Host "$folder temizlendi." -ForegroundColor Green
                    }
                    catch {
                        Write-Host "Bazı dosyalar temizlenemedi: $($_.Exception.Message)" -ForegroundColor Red
                    }
                }
            }
            
            Write-Host "Temporary dosya temizliği tamamlandı." -ForegroundColor Green
            Pause
            Show-MaintenanceMenu
        }
        "6" {
            if (Test-AdminRights) {
                Write-Host "`nWindows önbelleği temizleniyor..." -ForegroundColor Yellow
                
                # Windows Update Önbelleği
                Write-Host "Windows Update önbelleği temizleniyor..." -ForegroundColor Yellow
                Stop-Service -Name wuauserv -Force
                Remove-Item -Path "C:\Windows\SoftwareDistribution\*" -Recurse -Force -ErrorAction SilentlyContinue
                Start-Service -Name wuauserv
                
                # Font Önbelleği
                Write-Host "Font önbelleği temizleniyor..." -ForegroundColor Yellow
                Remove-Item -Path "C:\Windows\ServiceProfiles\LocalService\AppData\Local\FontCache\*" -Recurse -Force -ErrorAction SilentlyContinue
                
                # DNS Önbelleği
                Write-Host "DNS önbelleği temizleniyor..." -ForegroundColor Yellow
                Clear-DnsClientCache
                
                # Thumbnail Önbelleği
                Write-Host "Thumbnail önbelleği temizleniyor..." -ForegroundColor Yellow
                Remove-Item -Path "$env:LOCALAPPDATA\Microsoft\Windows\Explorer\thumbcache_*.db" -Force -ErrorAction SilentlyContinue
                
                Write-Host "Windows önbellek temizliği tamamlandı." -ForegroundColor Green
            }
            else {
                Write-Host "Bu işlem için yönetici hakları gerekiyor." -ForegroundColor Red
            }
            Pause
            Show-MaintenanceMenu
        }
        "7" {
            if (Test-AdminRights) {
                Write-Host "`n[Güvenli Mod Seçenekleri]" -ForegroundColor Yellow
                Write-Host "1. Normal Başlangıca Ayarla"
                Write-Host "2. Minimal Güvenli Modda Başlat"
                Write-Host "3. Ağ Bağlantılı Güvenli Modda Başlat"
                Write-Host "4. Komut İstemi ile Güvenli Modda Başlat"
                
                $safeChoice = Read-Host "`nSeçiminiz"
                
                switch ($safeChoice) {
                    "1" {
                        Write-Host "`nNormal başlangıca ayarlanıyor..." -ForegroundColor Yellow
                        bcdedit /deletevalue {default} safeboot
                        Write-Host "Normal başlangıca ayarlandı. Sistemi yeniden başlatın." -ForegroundColor Green
                    }
                    "2" {
                        Write-Host "`nMinimal güvenli mod ayarlanıyor..." -ForegroundColor Yellow
                        bcdedit /set {default} safeboot minimal
                        Write-Host "Minimal güvenli mod ayarlandı. Sistemi yeniden başlatın." -ForegroundColor Green
                    }
                    "3" {
                        Write-Host "`nAğ bağlantılı güvenli mod ayarlanıyor..." -ForegroundColor Yellow
                        bcdedit /set {default} safeboot network
                        Write-Host "Ağ bağlantılı güvenli mod ayarlandı. Sistemi yeniden başlatın." -ForegroundColor Green
                    }
                    "4" {
                        Write-Host "`nKomut istemi ile güvenli mod ayarlanıyor..." -ForegroundColor Yellow
                        bcdedit /set {default} safeboot minimal
                        bcdedit /set {default} safebootalternateshell yes
                        Write-Host "Komut istemi ile güvenli mod ayarlandı. Sistemi yeniden başlatın." -ForegroundColor Green
                    }
                    default {
                        Write-Host "Geçersiz seçim." -ForegroundColor Red
                    }
                }
                
                $restart = Read-Host "`nSistemi şimdi yeniden başlatmak istiyor musunuz? (E/H)"
                if ($restart -eq "E" -or $restart -eq "e") {
                    Restart-Computer -Force
                }
            }
            else {
                Write-Host "Bu işlem için yönetici hakları gerekiyor." -ForegroundColor Red
            }
            Pause
            Show-MaintenanceMenu
        }
        "8" {
            Write-Host "`nOtomatik başlangıç öğeleri:" -ForegroundColor Yellow
            
            $startupItems = Get-CimInstance -ClassName Win32_StartupCommand | 
                            Select-Object Name, Command, Location, User
            
            $i = 1
            foreach ($item in $startupItems) {
                Write-Host "$i. $($item.Name)" -ForegroundColor White
                Write-Host "   Komut: $($item.Command)" -ForegroundColor Gray
                Write-Host "   Konum: $($item.Location)" -ForegroundColor Gray
                Write-Host "   Kullanıcı: $($item.User)" -ForegroundColor Gray
                Write-Host ""
                $i++
            }
            
            Write-Host "Not: Başlangıç öğelerini devre dışı bırakmak için Görev Yöneticisi > Başlangıç sekmesini kullanın."
            Pause
            Show-MaintenanceMenu
        }
        "9" {
            Show-MainMenu
        }
        default {
            Write-Host "Geçersiz seçim. Lütfen tekrar deneyin." -ForegroundColor Red
            Start-Sleep -Seconds 2
            Show-MaintenanceMenu
        }
    }
}

# Performans ve Optimizasyon Fonksiyonları
function Show-PerformanceMenu {
    Clear-Host
    Show-WamsSplashScreen
    
    Write-Host "`n[Performans ve Optimizasyon]`n" -ForegroundColor Cyan
    Write-Host "1. CPU ve Bellek Kullanımını Göster"
    Write-Host "2. Çalışan Süreçleri Göster"
    Write-Host "3. Disk Performansını Analiz Et"
    Write-Host "4. Bellek Tanılama"
    Write-Host "5. Performans Seçeneklerini Aç"
    Write-Host "6. Güç Planını Optimizasyon Et"
    Write-Host "7. Windows Animasyonlarını Devre Dışı Bırak"
    Write-Host "8. Arka Plan Uygulamalarını Yönet"
    Write-Host "9. Ana Menüye Dön"
    
    $choice = Read-Host "`nSeçiminiz"
    
    switch ($choice) {
        "1" {
            Write-Host "`nCPU ve Bellek Kullanımı:" -ForegroundColor Yellow
            
            # CPU Kullanımı
            $cpuLoad = (Get-CimInstance -ClassName Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average
            Write-Host "CPU Kullanımı: " -NoNewline
            if ($cpuLoad -ge 80) {
                Write-Host "$cpuLoad%" -ForegroundColor Red
            }
            elseif ($cpuLoad -ge 60) {
                Write-Host "$cpuLoad%" -ForegroundColor Yellow
            }
            else {
                Write-Host "$cpuLoad%" -ForegroundColor Green
            }
            
            # Bellek Kullanımı
            $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem
            $totalMemory = [math]::Round($osInfo.TotalVisibleMemorySize / 1MB, 2)
            $freeMemory = [math]::Round($osInfo.FreePhysicalMemory / 1MB, 2)
            $usedMemory = $totalMemory - $freeMemory
            $memoryPercentage = [math]::Round(($usedMemory / $totalMemory) * 100, 2)
            
            Write-Host "Toplam Bellek: $totalMemory GB" -ForegroundColor White
            Write-Host "Kullanılan Bellek: $usedMemory GB" -ForegroundColor White
            Write-Host "Boş Bellek: $freeMemory GB" -ForegroundColor White
            Write-Host "Bellek Kullanım Oranı: " -NoNewline
            
            if ($memoryPercentage -ge 80) {
                Write-Host "$memoryPercentage%" -ForegroundColor Red
            }
            elseif ($memoryPercentage -ge 60) {
                Write-Host "$memoryPercentage%" -ForegroundColor Yellow
            }
            else {
                Write-Host "$memoryPercentage%" -ForegroundColor Green
            }
            
            # En çok kaynak kullanan 5 süreç
            Write-Host "`nEn çok CPU kullanan süreçler:" -ForegroundColor Yellow
            Get-Process | Sort-Object -Property CPU -Descending | Select-Object -First 5 -Property ProcessName, CPU, WorkingSet | Format-Table -AutoSize
            
            Write-Host "En çok bellek kullanan süreçler:" -ForegroundColor Yellow
            Get-Process | Sort-Object -Property WorkingSet -Descending | Select-Object -First 5 -Property ProcessName, WorkingSet, CPU | Format-Table -AutoSize
            
            Pause
            Show-PerformanceMenu
        }
        "2" {
            Write-Host "`nÇalışan Süreçler:" -ForegroundColor Yellow
            
            $sortBy = Read-Host "Nasıl sıralamak istiyorsunuz? (CPU, Memory, Name)"
            
            switch ($sortBy.ToLower()) {
                "cpu" {
                    Get-Process | Sort-Object -Property CPU -Descending | Select-Object -First 20 -Property ProcessName, CPU, WorkingSet, Id | Format-Table -AutoSize
                }
                "memory" {
                    Get-Process | Sort-Object -Property WorkingSet -Descending | Select-Object -First 20 -Property ProcessName, WorkingSet, CPU, Id | Format-Table -AutoSize
                }
                "name" {
                    Get-Process | Sort-Object -Property ProcessName | Select-Object -First 20 -Property ProcessName, CPU, WorkingSet, Id | Format-Table -AutoSize
                }
                default {
                    Get-Process | Sort-Object -Property CPU -Descending | Select-Object -First 20 -Property ProcessName, CPU, WorkingSet, Id | Format-Table -AutoSize
                }
            }
            
            $endProcess = Read-Host "`nBir süreci sonlandırmak istiyor musunuz? Süreci ID'si ile belirtin veya iptal için 'H' girin"
            
            if ($endProcess -ne "H" -and $endProcess -ne "h" -and $endProcess -match '^\d+$') {
                try {
                    Stop-Process -Id $endProcess -Force
                    Write-Host "Süreç $endProcess sonlandırıldı." -ForegroundColor Green
                }
                catch {
                    Write-Host "Süreç sonlandırılamadı: $($_.Exception.Message)" -ForegroundColor Red
                }
            }
            
            Pause
            Show-PerformanceMenu
        }
        "3" {
            Write-Host "`nDisk Performansı Analizi:" -ForegroundColor Yellow
            
            # Diskleri listele
            $disks = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DriveType=3"
            $i = 1
            foreach ($disk in $disks) {
                Write-Host "$i. $($disk.DeviceID) - $($disk.VolumeName)"
                $i++
            }
            
            $diskChoice = Read-Host "`nAnaliz etmek istediğiniz diskin numarasını girin"
            
            if ($diskChoice -match '^\d+$' -and [int]$diskChoice -ge 1 -and [int]$diskChoice -le $disks.Count) {
                $selectedDisk = $disks[[int]$diskChoice - 1]
                
                Write-Host "`n$($selectedDisk.DeviceID) diskinin performans analizi yapılıyor..." -ForegroundColor Yellow
                
                # Disk performans ölçümleri
                $measure = Measure-Command {
                    # 10 MB test dosyası oluştur
                    $testFile = "$($selectedDisk.DeviceID)\temp_test_file.dat"
                    $buffer = New-Object byte[] (10MB)
                    [System.IO.File]::WriteAllBytes($testFile, $buffer)
                    
                    # Dosyayı oku
                    $null = [System.IO.File]::ReadAllBytes($testFile)
                    
                    # Dosyayı sil
                    Remove-Item -Path $testFile -Force
                }
                
                $writeSpeed = 10 / $measure.TotalSeconds
                $readSpeed = 10 / ($measure.TotalSeconds / 2)
                
                Write-Host "Yazma Hızı: $([math]::Round($writeSpeed, 2)) MB/s" -ForegroundColor Green
                Write-Host "Okuma Hızı: $([math]::Round($readSpeed, 2)) MB/s" -ForegroundColor Green
            }
            else {
                Write-Host "Geçersiz disk seçimi." -ForegroundColor Red
            }
            
            Pause
            Show-PerformanceMenu
        }
        "4" {
            if (Test-AdminRights) {
                Write-Host "`nBellek Tanılama Başlatılıyor..." -ForegroundColor Yellow
                Start-Process -FilePath "mdsched.exe"
                Write-Host "Bellek Tanılama başlatıldı. Bu araç bir sonraki yeniden başlatmada çalışacaktır." -ForegroundColor Green
            }
            else {
                Write-Host "Bu işlem için yönetici hakları gerekiyor." -ForegroundColor Red
            }
            Pause
            Show-PerformanceMenu
        }
        "5" {
            Write-Host "`nPerformans Seçenekleri Açılıyor..." -ForegroundColor Yellow
            Start-Process -FilePath "SystemPropertiesPerformance.exe"
            Pause
            Show-PerformanceMenu
        }
        "6" {
            if (Test-AdminRights) {
                Write-Host "`n[Güç Planı Optimizasyonu]" -ForegroundColor Yellow
                Write-Host "1. Yüksek Performans"
                Write-Host "2. Dengeli"
                Write-Host "3. Güç Tasarrufu"
                Write-Host "4. Ana Güç Planı Menüsünü Aç"
                
                $powerChoice = Read-Host "`nSeçiminiz"
                
                switch ($powerChoice) {
                    "1" {
                        Write-Host "Yüksek Performans güç planı ayarlanıyor..." -ForegroundColor Yellow
                        powercfg /setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c
                        Write-Host "Yüksek Performans güç planı ayarlandı." -ForegroundColor Green
                    }
                    "2" {
                        Write-Host "Dengeli güç planı ayarlanıyor..." -ForegroundColor Yellow
                        powercfg /setactive 381b4222-f694-41f0-9685-ff5bb260df2e
                        Write-Host "Dengeli güç planı ayarlandı." -ForegroundColor Green
                    }
                    "3" {
                        Write-Host "Güç Tasarrufu planı ayarlanıyor..." -ForegroundColor Yellow
                        powercfg /setactive a1841308-3541-4fab-bc81-f71556f20b4a
                        Write-Host "Güç Tasarrufu planı ayarlandı." -ForegroundColor Green
                    }
                    "4" {
                        Start-Process -FilePath "control.exe" -ArgumentList "powercfg.cpl"
                    }
                    default {
                        Write-Host "Geçersiz seçim." -ForegroundColor Red
                    }
                }
            }
            else {
                Write-Host "Bu işlem için yönetici hakları gerekiyor." -ForegroundColor Red
            }
            Pause
            Show-PerformanceMenu
        }
        "7" {
            if (Test-AdminRights) {
                Write-Host "`nWindows animasyonları yapılandırılıyor..." -ForegroundColor Yellow
                
                Write-Host "1. Tüm Animasyonları Devre Dışı Bırak"
                Write-Host "2. Tüm Animasyonları Etkinleştir"
                
                $animChoice = Read-Host "`nSeçiminiz"
                
                switch ($animChoice) {
                    "1" {
                        Write-Host "Tüm animasyonlar devre dışı bırakılıyor..." -ForegroundColor Yellow
                        Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "UserPreferencesMask" -Value ([byte[]](0x90, 0x12, 0x03, 0x80, 0x10, 0x00, 0x00, 0x00))
                        
                        # Performans ayarlarını güncelle
                        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -Name "VisualFXSetting" -Value 2
                        
                        # Animasyon efektlerini devre dışı bırak
                        Set-ItemProperty -Path "HKCU:\Control Panel\Desktop\WindowMetrics" -Name "MinAnimate" -Value 0
                        
                        Write-Host "Tüm animasyonlar devre dışı bırakıldı. Değişikliklerin etkili olması için oturumu kapatıp açın." -ForegroundColor Green
                    }
                    "2" {
                        Write-Host "Tüm animasyonlar etkinleştiriliyor..." -ForegroundColor Yellow
                        Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "UserPreferencesMask" -Value ([byte[]](0x9E, 0x3E, 0x07, 0x80, 0x12, 0x00, 0x00, 0x00))
                        
                        # Performans ayarlarını güncelle
                        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -Name "VisualFXSetting" -Value 1
                        
                        # Animasyon efektlerini etkinleştir
                        Set-ItemProperty -Path "HKCU:\Control Panel\Desktop\WindowMetrics" -Name "MinAnimate" -Value 1
                        
                        Write-Host "Tüm animasyonlar etkinleştirildi. Değişikliklerin etkili olması için oturumu kapatıp açın." -ForegroundColor Green
                    }
                    default {
                        Write-Host "Geçersiz seçim." -ForegroundColor Red
                    }
                }
            }
            else {
                Write-Host "Bu işlem için yönetici hakları gerekiyor." -ForegroundColor Red
            }
            Pause
            Show-PerformanceMenu
        }
        "8" {
            Write-Host "`nArka Plan Uygulamaları Yönetimi Açılıyor..." -ForegroundColor Yellow
            Start-Process -FilePath "ms-settings:privacy-backgroundapps"
            Pause
            Show-PerformanceMenu
        }
        "9" {
            Show-MainMenu
        }
        default {
            Write-Host "Geçersiz seçim. Lütfen tekrar deneyin." -ForegroundColor Red
            Start-Sleep -Seconds 2
            Show-PerformanceMenu
        }
    }
}

# Güvenlik ve Gizlilik Fonksiyonları
function Show-SecurityMenu {
    Clear-Host
    Show-WamsSplashScreen
    
    Write-Host "`n[Güvenlik ve Gizlilik]`n" -ForegroundColor Cyan
    Write-Host "1. Windows Güvenlik Durumunu Göster"
    Write-Host "2. Güvenlik Duvarı Durumunu Göster"
    Write-Host "3. Güvenlik Duvarını Aç/Kapat"
    Write-Host "4. Windows Defender Taraması Başlat"
    Write-Host "5. Uygulama İzinlerini Yönet"
    Write-Host "6. BitLocker Durumunu Göster"
    Write-Host "7. Windows Gizlilik Ayarlarını Yönet"
    Write-Host "8. Kullanıcı Hesap Kontrol Ayarları (UAC)"
    Write-Host "9. Ana Menüye Dön"
    
    $choice = Read-Host "`nSeçiminiz"
    
    switch ($choice) {
        "1" {
            Write-Host "`nWindows Güvenlik Durumu:" -ForegroundColor Yellow
            
            # Windows Defender Durumu
            try {
                $defenderStatus = Get-MpComputerStatus
                
                Write-Host "Antivirüs Etkin: " -NoNewline
                if ($defenderStatus.AntivirusEnabled) {
                    Write-Host "Evet" -ForegroundColor Green
                }
                else {
                    Write-Host "Hayır" -ForegroundColor Red
                }
                
                Write-Host "Gerçek Zamanlı Koruma: " -NoNewline
                if ($defenderStatus.RealTimeProtectionEnabled) {
                    Write-Host "Etkin" -ForegroundColor Green
                }
                else {
                    Write-Host "Devre Dışı" -ForegroundColor Red
                }
                
                Write-Host "Son Tam Tarama: " -NoNewline
                if ($defenderStatus.FullScanEndTime) {
                    Write-Host "$($defenderStatus.FullScanEndTime)" -ForegroundColor Green
                }
                else {
                    Write-Host "Tam tarama yapılmamış" -ForegroundColor Yellow
                }
                
                Write-Host "İmza Sürümü: $($defenderStatus.AntivirusSignatureVersion)" -ForegroundColor White
                Write-Host "Son İmza Güncellemesi: $($defenderStatus.AntivirusSignatureLastUpdated)" -ForegroundColor White
            }
            catch {
                Write-Host "Windows Defender durumu alınamadı: $($_.Exception.Message)" -ForegroundColor Red
            }
            
            # Güvenlik Duvarı Durumu
            try {
                $firewallProfiles = Get-NetFirewallProfile
                
                Write-Host "`nGüvenlik Duvarı Durumu:" -ForegroundColor Yellow
                foreach ($profile in $firewallProfiles) {
                    Write-Host "$($profile.Name) Profili: " -NoNewline
                    if ($profile.Enabled) {
                        Write-Host "Etkin" -ForegroundColor Green
                    }
                    else {
                        Write-Host "Devre Dışı" -ForegroundColor Red
                    }
                }
            }
            catch {
                Write-Host "Güvenlik duvarı durumu alınamadı: $($_.Exception.Message)" -ForegroundColor Red
            }
            
            # Windows Update Durumu
            try {
                if (Test-ModuleInstalled -ModuleName "PSWindowsUpdate") {
                    $updates = Get-WindowsUpdate
                    
                    Write-Host "`nWindows Update Durumu:" -ForegroundColor Yellow
                    Write-Host "Bekleyen Güncelleştirme Sayısı: $($updates.Count)" -ForegroundColor White
                }
                else {
                    Write-Host "`nWindows Update Durumu:" -ForegroundColor Yellow
                    Write-Host "Güncelleştirme durumu için PSWindowsUpdate modülünü yükleyin." -ForegroundColor Yellow
                }
            }
            catch {
                Write-Host "Windows Update durumu alınamadı: $($_.Exception.Message)" -ForegroundColor Red
            }
            
            Pause
            Show-SecurityMenu
        }
        "2" {
            Write-Host "`nGüvenlik Duvarı Durumu:" -ForegroundColor Yellow
            
            try {
                $firewallProfiles = Get-NetFirewallProfile
                
                foreach ($profile in $firewallProfiles) {
                    Write-Host "`n$($profile.Name) Profili:" -ForegroundColor White
                    Write-Host "Durum: " -NoNewline
                    if ($profile.Enabled) {
                        Write-Host "Etkin" -ForegroundColor Green
                    }
                    else {
                        Write-Host "Devre Dışı" -ForegroundColor Red
                    }
                    
                    Write-Host "Gelen Bağlantılar: $($profile.DefaultInboundAction)" -ForegroundColor White
                    Write-Host "Giden Bağlantılar: $($profile.DefaultOutboundAction)" -ForegroundColor White
                }
                
                # Güvenlik Duvarı Kuralları
                $rulesToShow = Read-Host "`nGüvenlik duvarı kurallarını görmek istiyor musunuz? (E/H)"
                
                if ($rulesToShow -eq "E" -or $rulesToShow -eq "e") {
                    $filter = Read-Host "Filtrelemek için program adı girin (tüm kuralları görmek için boş bırakın)"
                    
                    Write-Host "`nGüvenlik Duvarı Kuralları:" -ForegroundColor Yellow
                    
                    if ([string]::IsNullOrEmpty($filter)) {
                        $rules = Get-NetFirewallRule -Enabled True | Select-Object -First 20
                    }
                    else {
                        $rules = Get-NetFirewallRule -Enabled True | Where-Object { $_.DisplayName -like "*$filter*" }
                    }
                    
                    foreach ($rule in $rules) {
                        Write-Host "$($rule.DisplayName)" -ForegroundColor White
                        Write-Host "  Yön: $($rule.Direction)" -ForegroundColor Gray
                        Write-Host "  Etkin: $($rule.Enabled)" -ForegroundColor Gray
                        Write-Host "  Eylem: $($rule.Action)" -ForegroundColor Gray
                        Write-Host ""
                    }
                }
            }
            catch {
                Write-Host "Güvenlik duvarı durumu alınamadı: $($_.Exception.Message)" -ForegroundColor Red
            }
            
            Pause
            Show-SecurityMenu
        }
        "3" {
            if (Test-AdminRights) {
                Write-Host "`n[Güvenlik Duvarı Kontrolleri]" -ForegroundColor Yellow
                
                # Mevcut durum
                $firewallProfiles = Get-NetFirewallProfile
                
                Write-Host "Mevcut Durum:" -ForegroundColor White
                foreach ($profile in $firewallProfiles) {
                    Write-Host "$($profile.Name): " -NoNewline
                    if ($profile.Enabled) {
                        Write-Host "Etkin" -ForegroundColor Green
                    }
                    else {
                        Write-Host "Devre Dışı" -ForegroundColor Red
                    }
                }
                
                Write-Host "`n1. Tüm Profilleri Etkinleştir" -ForegroundColor White
                Write-Host "2. Tüm Profilleri Devre Dışı Bırak" -ForegroundColor White
                Write-Host "3. Belirli Bir Profili Yapılandır" -ForegroundColor White
                
                $firewallChoice = Read-Host "`nSeçiminiz"
                
                switch ($firewallChoice) {
                    "1" {
                        Write-Host "Tüm güvenlik duvarı profilleri etkinleştiriliyor..." -ForegroundColor Yellow
                        Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
                        Write-Host "Tüm güvenlik duvarı profilleri etkinleştirildi." -ForegroundColor Green
                    }
                    "2" {
                        Write-Host "DİKKAT: Güvenlik duvarını devre dışı bırakmak sisteminizi risk altında bırakabilir!" -ForegroundColor Red
                        $confirm = Read-Host "Güvenlik duvarını devre dışı bırakmak istediğinize emin misiniz? (E/H)"
                        
                        if ($confirm -eq "E" -or $confirm -eq "e") {
                            Write-Host "Tüm güvenlik duvarı profilleri devre dışı bırakılıyor..." -ForegroundColor Yellow
                            Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False
                            Write-Host "Tüm güvenlik duvarı profilleri devre dışı bırakıldı." -ForegroundColor Red
                        }
                    }
                    "3" {
                        Write-Host "`nHangi profili yapılandırmak istiyorsunuz?" -ForegroundColor Yellow
                        Write-Host "1. Domain" -ForegroundColor White
                        Write-Host "2. Private" -ForegroundColor White
                        Write-Host "3. Public" -ForegroundColor White
                        
                        $profileChoice = Read-Host "`nSeçiminiz"
                        $selectedProfile = ""
                        
                        switch ($profileChoice) {
                            "1" { $selectedProfile = "Domain" }
                            "2" { $selectedProfile = "Private" }
                            "3" { $selectedProfile = "Public" }
                            default { 
                                Write-Host "Geçersiz profil seçimi." -ForegroundColor Red 
                                $selectedProfile = ""
                            }
                        }
                        
                        if ($selectedProfile -ne "") {
                            Write-Host "`n$selectedProfile profilini yapılandırıyorsunuz." -ForegroundColor Yellow
                            Write-Host "1. Etkinleştir" -ForegroundColor White
                            Write-Host "2. Devre Dışı Bırak" -ForegroundColor White
                            
                            $statusChoice = Read-Host "`nSeçiminiz"
                            
                            if ($statusChoice -eq "1") {
                                Set-NetFirewallProfile -Profile $selectedProfile -Enabled True
                                Write-Host "$selectedProfile profili etkinleştirildi." -ForegroundColor Green
                            }
                            elseif ($statusChoice -eq "2") {
                                Write-Host "DİKKAT: Güvenlik duvarını devre dışı bırakmak sisteminizi risk altında bırakabilir!" -ForegroundColor Red
                                $confirm = Read-Host "Güvenlik duvarını devre dışı bırakmak istediğinize emin misiniz? (E/H)"
                                
                                if ($confirm -eq "E" -or $confirm -eq "e") {
                                    Set-NetFirewallProfile -Profile $selectedProfile -Enabled False
                                    Write-Host "$selectedProfile profili devre dışı bırakıldı." -ForegroundColor Red
                                }
                            }
                            else {
                                Write-Host "Geçersiz seçim." -ForegroundColor Red
                            }
                        }
                    }
                    default {
                        Write-Host "Geçersiz seçim." -ForegroundColor Red
                    }
                }
            }
            else {
                Write-Host "Bu işlem için yönetici hakları gerekiyor." -ForegroundColor Red
            }
            Pause
            Show-SecurityMenu
        }
        "4" {
            if (Test-AdminRights) {
                Write-Host "`n[Windows Defender Taraması]" -ForegroundColor Yellow
                Write-Host "1. Hızlı Tarama" -ForegroundColor White
                Write-Host "2. Tam Tarama" -ForegroundColor White
                Write-Host "3. Özel Tarama" -ForegroundColor White
                
                $scanChoice = Read-Host "`nSeçiminiz"
                
                switch ($scanChoice) {
                    "1" {
                        Write-Host "Hızlı tarama başlatılıyor..." -ForegroundColor Yellow
                        Start-MpScan -ScanType QuickScan
                        Write-Host "Hızlı tarama başlatıldı." -ForegroundColor Green
                    }
                    "2" {
                        Write-Host "Tam tarama başlatılıyor..." -ForegroundColor Yellow
                        Write-Host "Not: Bu işlem uzun sürebilir." -ForegroundColor Yellow
                        Start-MpScan -ScanType FullScan
                        Write-Host "Tam tarama başlatıldı." -ForegroundColor Green
                    }
                    "3" {
                        $scanPath = Read-Host "Taranacak yolu girin (Örn: C:\Users\Username\Downloads)"
                        
                        if (Test-Path $scanPath) {
                            Write-Host "Özel tarama başlatılıyor: $scanPath" -ForegroundColor Yellow
                            Start-MpScan -ScanType CustomScan -ScanPath $scanPath
                            Write-Host "Özel tarama başlatıldı." -ForegroundColor Green
                        }
                        else {
                            Write-Host "Geçersiz yol: $scanPath" -ForegroundColor Red
                        }
                    }
                    default {
                        Write-Host "Geçersiz seçim." -ForegroundColor Red
                    }
                }
            }
            else {
                Write-Host "Bu işlem için yönetici hakları gerekiyor." -ForegroundColor Red
            }
            Pause
            Show-SecurityMenu
        }
        "5" {
            Write-Host "`nUygulama İzinleri Yönetimi:" -ForegroundColor Yellow
            Write-Host "1. Kamera İzinlerini Yönet" -ForegroundColor White
            Write-Host "2. Mikrofon İzinlerini Yönet" -ForegroundColor White
            Write-Host "3. Konum İzinlerini Yönet" -ForegroundColor White
            Write-Host "4. Bildirim İzinlerini Yönet" -ForegroundColor White
            Write-Host "5. Tam Gizlilik Ayarlarını Aç" -ForegroundColor White
            
            $permChoice = Read-Host "`nSeçiminiz"
            
            switch ($permChoice) {
                "1" { Start-Process -FilePath "ms-settings:privacy-webcam" }
                "2" { Start-Process -FilePath "ms-settings:privacy-microphone" }
                "3" { Start-Process -FilePath "ms-settings:privacy-location" }
                "4" { Start-Process -FilePath "ms-settings:privacy-notifications" }
                "5" { Start-Process -FilePath "ms-settings:privacy" }
                default { Write-Host "Geçersiz seçim." -ForegroundColor Red }
            }
            
            Pause
            Show-SecurityMenu
        }
        "6" {
            Write-Host "`nBitLocker Durumu:" -ForegroundColor Yellow
            
            try {
                $bitlockerVolumes = Get-BitLockerVolume
                
                if ($bitlockerVolumes) {
                    foreach ($volume in $bitlockerVolumes) {
                        Write-Host "`nSürücü: $($volume.MountPoint)" -ForegroundColor White
                        Write-Host "Koruma Durumu: " -NoNewline
                        
                        switch ($volume.ProtectionStatus) {
                            "On" { Write-Host "Etkin" -ForegroundColor Green }
                            "Off" { Write-Host "Devre Dışı" -ForegroundColor Red }
                            default { Write-Host "$($volume.ProtectionStatus)" -ForegroundColor Yellow }
                        }
                        
                        Write-Host "Şifreleme Yöntemi: $($volume.EncryptionMethod)" -ForegroundColor White
                        Write-Host "Şifreleme Yüzdesi: $($volume.VolumeStatus)" -ForegroundColor White
                    }
                }
                else {
                    Write-Host "BitLocker hiçbir sürücüde yapılandırılmamış." -ForegroundColor Yellow
                }
            }
            catch {
                Write-Host "BitLocker durumu alınamadı: $($_.Exception.Message)" -ForegroundColor Red
            }
            
            $configureBitlocker = Read-Host "`nBitLocker yapılandırma aracını açmak istiyor musunuz? (E/H)"
            
            if ($configureBitlocker -eq "E" -or $configureBitlocker -eq "e") {
                Start-Process -FilePath "control.exe" -ArgumentList "/name Microsoft.BitLockerDriveEncryption"
            }
            
            Pause
            Show-SecurityMenu
        }
        "7" {
            Write-Host "`nWindows Gizlilik Ayarları:" -ForegroundColor Yellow
            Write-Host "1. Genel Gizlilik Ayarları" -ForegroundColor White
            Write-Host "2. Telemetri Ayarları" -ForegroundColor White
            Write-Host "3. Deneyim ve Tanılama Ayarları" -ForegroundColor White
            Write-Host "4. Reklam Kimliği Ayarları" -ForegroundColor White
            
            $privacyChoice = Read-Host "`nSeçiminiz"
            
            switch ($privacyChoice) {
                "1" { Start-Process -FilePath "ms-settings:privacy" }
                "2" { Start-Process -FilePath "ms-settings:privacy-feedback" }
                "3" { Start-Process -FilePath "ms-settings:privacy-diagnosticdata" }
                "4" { Start-Process -FilePath "ms-settings:privacy-general" }
                default { Write-Host "Geçersiz seçim." -ForegroundColor Red }
            }
            
            Pause
            Show-SecurityMenu
        }
        "8" {
            Write-Host "`nKullanıcı Hesap Kontrol Ayarları (UAC):" -ForegroundColor Yellow
            
            Start-Process -FilePath "UserAccountControlSettings.exe"
            
            Pause
            Show-SecurityMenu
        }
        "9" {
            Show-MainMenu
        }
        default {
            Write-Host "Geçersiz seçim. Lütfen tekrar deneyin." -ForegroundColor Red
            Start-Sleep -Seconds 2
            Show-SecurityMenu
        }
    }
}

# Donanım ve Yazıcı Yönetimi Fonksiyonları
function Show-HardwareMenu {
    Clear-Host
    Show-WamsSplashScreen
    
    Write-Host "`n[Donanım ve Yazıcı Yönetimi]`n" -ForegroundColor Cyan
    Write-Host "1. Donanım Aygıtları Listesi"
    Write-Host "2. Sürücü Durumunu Görüntüle"
    Write-Host "3. Sürücüleri Güncelle"
    Write-Host "4. Yazıcı Durumunu Görüntüle"
    Write-Host "5. Yazıcı Kuyruğunu Temizle"
    Write-Host "6. Yeni Yazıcı Ekle"
    Write-Host "7. Yazıcı Sorun Giderici Çalıştır"
    Write-Host "8. Donanım Sorun Gidericileri"
    Write-Host "9. Aygıt Yöneticisini Aç"
    Write-Host "10. Ana Menüye Dön"
    
    $choice = Read-Host "`nSeçiminiz"
    
    switch ($choice) {
        "1" {
            Write-Host "`nDonanım Aygıtları:" -ForegroundColor Yellow
            
            $deviceClass = Read-Host "Filtre seçin (Disk, Klavye, Fare, Ağ, USB, Hepsi)"
            
            switch ($deviceClass.ToLower()) {
                "disk" {
                    Get-CimInstance -ClassName Win32_DiskDrive | 
                    Format-Table -Property Model, Size, MediaType, InterfaceType -AutoSize
                }
                "klavye" {
                    Get-CimInstance -ClassName Win32_Keyboard | 
                    Format-Table -Property Description, NumberOfFunctionKeys -AutoSize
                }
                "fare" {
                    Get-CimInstance -ClassName Win32_PointingDevice | 
                    Format-Table -Property Manufacturer, Name, NumberOfButtons -AutoSize
                }
                "ağ" {
                    Get-CimInstance -ClassName Win32_NetworkAdapter | Where-Object { $_.PhysicalAdapter -eq $true } | 
                    Format-Table -Property Name, AdapterType, Speed, MACAddress -AutoSize
                }
                "usb" {
                    Get-CimInstance -ClassName Win32_USBController | 
                    Format-Table -Property Name, Manufacturer -AutoSize
                    
                    Write-Host "`nBağlı USB Aygıtları:" -ForegroundColor Yellow
                    Get-CimInstance -ClassName Win32_USBControllerDevice | 
                    ForEach-Object { [wmi]($_.Dependent) } | 
                    Format-Table -Property Name, Manufacturer, Status -AutoSize
                }
                default {
                    Write-Host "Tüm Aygıtlar:" -ForegroundColor Yellow
                    Get-CimInstance -ClassName Win32_PnPEntity | 
                    Format-Table -Property Name, Manufacturer, Status -AutoSize
                }
            }
            
            Pause
            Show-HardwareMenu
        }
        "2" {
            Write-Host "`nSürücü Durumu:" -ForegroundColor Yellow
            
            $problemDevices = Get-CimInstance -ClassName Win32_PnPEntity | Where-Object { $_.ConfigManagerErrorCode -ne 0 }
            
            if ($problemDevices) {
                Write-Host "Sorunlu Aygıtlar:" -ForegroundColor Red
                $problemDevices | Format-Table -Property Name, Manufacturer, ConfigManagerErrorCode -AutoSize
            }
            else {
                Write-Host "Tüm sürücüler düzgün çalışıyor." -ForegroundColor Green
            }
            
            $showAllDrivers = Read-Host "`nTüm sürücü bilgilerini görmek istiyor musunuz? (E/H)"
            
            if ($showAllDrivers -eq "E" -or $showAllDrivers -eq "e") {
                Write-Host "`nYüklü Sürücüler:" -ForegroundColor Yellow
                Get-CimInstance -ClassName Win32_PnPSignedDriver | 
                Select-Object -Property DeviceName, Manufacturer, DriverVersion | 
                Format-Table -AutoSize
            }
            
            Pause
            Show-HardwareMenu
        }
        "3" {
            if (Test-AdminRights) {
                Write-Host "`nSürücü Güncelleme:" -ForegroundColor Yellow
                
                Write-Host "1. Windows Update ile Sürücüleri Güncelle" -ForegroundColor White
                Write-Host "2. Belirli Bir Aygıtı Güncelle" -ForegroundColor White
                Write-Host "3. Sürücü Ayarlarını Aç" -ForegroundColor White
                
                $driverChoice = Read-Host "`nSeçiminiz"
                
                switch ($driverChoice) {
                    "1" {
                        Write-Host "Windows Update ile sürücüler kontrol ediliyor..." -ForegroundColor Yellow
                        if (Test-ModuleInstalled -ModuleName "PSWindowsUpdate") {
                            Get-WindowsUpdate -UpdateType Driver
                            $installDrivers = Read-Host "`nMevcut sürücü güncellemelerini yüklemek istiyor musunuz? (E/H)"
                            
                            if ($installDrivers -eq "E" -or $installDrivers -eq "e") {
                                Install-WindowsUpdate -UpdateType Driver -AcceptAll
                            }
                        }
                        else {
                            Write-Host "PSWindowsUpdate modülü yüklü değil. Sürücü güncellemeleri için Windows Update'i kullanabilirsiniz." -ForegroundColor Yellow
                            Start-Process -FilePath "control.exe" -ArgumentList "/name Microsoft.WindowsUpdate"
                        }
                    }
                    "2" {
                        Write-Host "Aygıt Yöneticisi açılıyor..." -ForegroundColor Yellow
                        Start-Process -FilePath "devmgmt.msc"
                    }
                    "3" {
                        Write-Host "Sürücü Ayarları açılıyor..." -ForegroundColor Yellow
                        Start-Process -FilePath "ms-settings:windowsupdate-options"
                    }
                    default {
                        Write-Host "Geçersiz seçim." -ForegroundColor Red
                    }
                }
            }
            else {
                Write-Host "Bu işlem için yönetici hakları gerekiyor." -ForegroundColor Red
            }
            Pause
            Show-HardwareMenu
        }
        "4" {
            Write-Host "`nYazıcı Durumu:" -ForegroundColor Yellow
            
            $printers = Get-CimInstance -ClassName Win32_Printer
            
            if ($printers) {
                foreach ($printer in $printers) {
                    Write-Host "`nYazıcı: $($printer.Name)" -ForegroundColor White
                    Write-Host "Durum: " -NoNewline
                    
                    switch ($printer.PrinterStatus) {
                        1 { Write-Host "Diğer" -ForegroundColor Gray }
                        2 { Write-Host "Bilinmiyor" -ForegroundColor Gray }
                        3 { Write-Host "Hazır" -ForegroundColor Green }
                        4 { Write-Host "Yazdırılıyor" -ForegroundColor Cyan }
                        5 { Write-Host "Isınıyor" -ForegroundColor Yellow }
                        6 { Write-Host "Durduruldu" -ForegroundColor Red }
                        7 { Write-Host "Çevrimdışı" -ForegroundColor Red }
                        default { Write-Host $printer.PrinterStatus -ForegroundColor Gray }
                    }
                    
                    Write-Host "Varsayılan: $($printer.Default)" -ForegroundColor White
                    Write-Host "Paylaşılan: $($printer.Shared)" -ForegroundColor White
                    
                    if ($printer.Shared) {
                        Write-Host "Paylaşım Adı: $($printer.ShareName)" -ForegroundColor White
                    }
                }
            }
            else {
                Write-Host "Sisteme kayıtlı yazıcı bulunamadı." -ForegroundColor Yellow
            }
            
            $jobChoice = Read-Host "`nYazdırma işlerini görüntülemek istiyor musunuz? (E/H)"
            
            if ($jobChoice -eq "E" -or $jobChoice -eq "e") {
                Write-Host "`nYazdırma İşleri:" -ForegroundColor Yellow
                
                $printJobs = Get-CimInstance -ClassName Win32_PrintJob
                
                if ($printJobs) {
                    foreach ($job in $printJobs) {
                        Write-Host "İş: $($job.Document)" -ForegroundColor White
                        Write-Host "Durum: $($job.Status)" -ForegroundColor White
                        Write-Host "Öncelik: $($job.Priority)" -ForegroundColor White
                        Write-Host "Sayfa Sayısı: $($job.TotalPages)" -ForegroundColor White
                        Write-Host ""
                    }
                }
                else {
                    Write-Host "Aktif yazdırma işi bulunamadı." -ForegroundColor Yellow
                }
            }
            
            Pause
            Show-HardwareMenu
        }
        "5" {
            if (Test-AdminRights) {
                Write-Host "`nYazıcı Kuyruğu Temizleniyor..." -ForegroundColor Yellow
                
                # Yazıcı hizmetini durdur
                try {
                    Stop-Service -Name "Spooler" -Force
                    Write-Host "Yazdırma hizmeti durduruldu." -ForegroundColor Green
                }
                catch {
                    Write-Host "Yazdırma hizmeti durdurulamadı: $($_.Exception.Message)" -ForegroundColor Red
                    Pause
                    Show-HardwareMenu
                    return
                }
                
                # Kuyruk temizle
                try {
                    Remove-Item -Path "$env:SystemRoot\System32\spool\PRINTERS\*" -Force -Recurse -ErrorAction SilentlyContinue
                    Write-Host "Yazıcı kuyruğu temizlendi." -ForegroundColor Green
                }
                catch {
                    Write-Host "Yazıcı kuyruğu temizlenirken hata oluştu: $($_.Exception.Message)" -ForegroundColor Red
                }
                
                # Yazıcı hizmetini başlat
                try {
                    Start-Service -Name "Spooler"
                    Write-Host "Yazdırma hizmeti yeniden başlatıldı." -ForegroundColor Green
                }
                catch {
                    Write-Host "Yazdırma hizmeti başlatılamadı: $($_.Exception.Message)" -ForegroundColor Red
                }
            }
            else {
                Write-Host "Bu işlem için yönetici hakları gerekiyor." -ForegroundColor Red
            }
            Pause
            Show-HardwareMenu
        }
        "6" {
            Write-Host "`nYeni Yazıcı Ekleme:" -ForegroundColor Yellow
            
            Write-Host "Yazıcı ekleme sihirbazı açılıyor..." -ForegroundColor White
            Start-Process -FilePath "control.exe" -ArgumentList "/name Microsoft.DevicesAndPrinters"
            
            Pause
            Show-HardwareMenu
        }
        "7" {
            Write-Host "`nYazıcı Sorun Giderici Başlatılıyor..." -ForegroundColor Yellow
            
            Start-Process -FilePath "msdt.exe" -ArgumentList "/id PrinterDiagnostic"
            
            Pause
            Show-HardwareMenu
        }
        "8" {
            Write-Host "`nDonanım Sorun Gidericileri:" -ForegroundColor Yellow
            Write-Host "1. Ağ Adaptörü Sorun Giderici" -ForegroundColor White
            Write-Host "2. Donanım ve Aygıtlar Sorun Giderici" -ForegroundColor White
            Write-Host "3. Ses Sorun Giderici" -ForegroundColor White
            Write-Host "4. Güç Sorun Giderici" -ForegroundColor White
            
            $troubleshootChoice = Read-Host "`nSeçiminiz"
            
            switch ($troubleshootChoice) {
                "1" { Start-Process -FilePath "msdt.exe" -ArgumentList "/id NetworkDiagnosticsNetworkAdapter" }
                "2" { Start-Process -FilePath "msdt.exe" -ArgumentList "/id DeviceDiagnostic" }
                "3" { Start-Process -FilePath "msdt.exe" -ArgumentList "/id AudioPlaybackDiagnostic" }
                "4" { Start-Process -FilePath "msdt.exe" -ArgumentList "/id PowerDiagnostic" }
                default { Write-Host "Geçersiz seçim." -ForegroundColor Red }
            }
            
            Pause
            Show-HardwareMenu
        }
        "9" {
            Write-Host "`nAygıt Yöneticisi Açılıyor..." -ForegroundColor Yellow
            Start-Process -FilePath "devmgmt.msc"
            
            Pause
            Show-HardwareMenu
        }
        "10" {
            Show-MainMenu
        }
        default {
            Write-Host "Geçersiz seçim. Lütfen tekrar deneyin." -ForegroundColor Red
            Start-Sleep -Seconds 2
            Show-HardwareMenu
        }
    }
}

# Raporlama Fonksiyonları
function Show-ReportingMenu {
    Clear-Host
    Show-WamsSplashScreen
    
    Write-Host "`n[Sistem Raporlama]`n" -ForegroundColor Cyan
    Write-Host "1. Temel Sistem Raporu"
    Write-Host "2. Donanım Detaylı Raporu"
    Write-Host "3. Yazılım Envanteri Raporu"
    Write-Host "4. Güvenlik Durum Raporu"
    Write-Host "5. Disk Kullanım Raporu"
    Write-Host "6. Performans Raporu"
    Write-Host "7. Güncelleştirme Geçmişi Raporu"
    Write-Host "8. Olay Günlüğü Raporu"
    Write-Host "9. Tam Sistem Bilgisi Raporu"
    Write-Host "10. Ana Menüye Dön"
    
    $choice = Read-Host "`nSeçiminiz"
    
    switch ($choice) {
        "1" {
            Write-Host "`nTemel Sistem Raporu Oluşturuluyor..." -ForegroundColor Yellow
            
            $reportFile = "$env:USERPROFILE\Desktop\SistemRaporu_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
            
            Write-Output "===== WINDOWS ADVANCED MANAGEMENT SUITE =====" | Out-File -FilePath $reportFile
            Write-Output "Temel Sistem Raporu" | Out-File -FilePath $reportFile -Append
            Write-Output "Oluşturma Tarihi: $(Get-Date)" | Out-File -FilePath $reportFile -Append
            Write-Output "========================================" | Out-File -FilePath $reportFile -Append
            
            # İşletim Sistemi Bilgisi
            $os = Get-CimInstance -ClassName Win32_OperatingSystem
            Write-Output "`n----- İŞLETİM SİSTEMİ BİLGİSİ -----" | Out-File -FilePath $reportFile -Append
            Write-Output "Bilgisayar Adı: $env:COMPUTERNAME" | Out-File -FilePath $reportFile -Append
            Write-Output "İşletim Sistemi: $($os.Caption) $($os.Version)" | Out-File -FilePath $reportFile -Append
            Write-Output "Yapı: $($os.BuildNumber)" | Out-File -FilePath $reportFile -Append
            Write-Output "Mimari: $($os.OSArchitecture)" | Out-File -FilePath $reportFile -Append
            Write-Output "Seri Numarası: $($os.SerialNumber)" | Out-File -FilePath $reportFile -Append
            Write-Output "Son Başlatma: $($os.LastBootUpTime)" | Out-File -FilePath $reportFile -Append
            
            # Donanım Bilgisi
            $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem
            Write-Output "`n----- DONANIM BİLGİSİ -----" | Out-File -FilePath $reportFile -Append
            Write-Output "Üretici: $($computerSystem.Manufacturer)" | Out-File -FilePath $reportFile -Append
            Write-Output "Model: $($computerSystem.Model)" | Out-File -FilePath $reportFile -Append
            
            # İşlemci Bilgisi
            $processor = Get-CimInstance -ClassName Win32_Processor
            Write-Output "`n----- İŞLEMCİ BİLGİSİ -----" | Out-File -FilePath $reportFile -Append
            Write-Output "İşlemci: $($processor.Name)" | Out-File -FilePath $reportFile -Append
            Write-Output "Çekirdek Sayısı: $($processor.NumberOfCores)" | Out-File -FilePath $reportFile -Append
            Write-Output "Mantıksal İşlemci Sayısı: $($processor.NumberOfLogicalProcessors)" | Out-File -FilePath $reportFile -Append
            Write-Output "Maksimum Saat Hızı: $($processor.MaxClockSpeed) MHz" | Out-File -FilePath $reportFile -Append
            
            # Bellek Bilgisi
            $memory = Get-CimInstance -ClassName Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum
            Write-Output "`n----- BELLEK BİLGİSİ -----" | Out-File -FilePath $reportFile -Append
            Write-Output "Toplam RAM: $([math]::Round($memory.Sum / 1GB, 2)) GB" | Out-File -FilePath $reportFile -Append
            
            # Disk Bilgisi
            $disks = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DriveType=3"
            Write-Output "`n----- DİSK BİLGİSİ -----" | Out-File -FilePath $reportFile -Append
            
            foreach ($disk in $disks) {
                $freeSpacePercent = [math]::Round(($disk.FreeSpace / $disk.Size) * 100, 2)
                Write-Output "Sürücü: $($disk.DeviceID)" | Out-File -FilePath $reportFile -Append
                Write-Output "  Toplam Alan: $([math]::Round($disk.Size / 1GB, 2)) GB" | Out-File -FilePath $reportFile -Append
                Write-Output "  Boş Alan: $([math]::Round($disk.FreeSpace / 1GB, 2)) GB (%$freeSpacePercent)" | Out-File -FilePath $reportFile -Append
            }
            
            # Ağ Bilgisi
            $networkAdapters = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled -eq $true }
            Write-Output "`n----- AĞ BİLGİSİ -----" | Out-File -FilePath $reportFile -Append
            
            foreach ($adapter in $networkAdapters) {
                Write-Output "Adaptör: $($adapter.Description)" | Out-File -FilePath $reportFile -Append
                Write-Output "  MAC Adresi: $($adapter.MACAddress)" | Out-File -FilePath $reportFile -Append
                Write-Output "  IP Adresi: $($adapter.IPAddress -join ', ')" | Out-File -FilePath $reportFile -Append
                Write-Output "  Alt Ağ Maskesi: $($adapter.IPSubnet -join ', ')" | Out-File -FilePath $reportFile -Append
                Write-Output "  Varsayılan Ağ Geçidi: $($adapter.DefaultIPGateway -join ', ')" | Out-File -FilePath $reportFile -Append
                Write-Output "  DNS Sunucuları: $($adapter.DNSServerSearchOrder -join ', ')" | Out-File -FilePath $reportFile -Append
            }
            
            Write-Host "Rapor oluşturuldu: $reportFile" -ForegroundColor Green
            Invoke-Item (Split-Path $reportFile -Parent)
            
            Pause
            Show-ReportingMenu
        }
        "2" {
            Write-Host "`nDonanım Detaylı Raporu Oluşturuluyor..." -ForegroundColor Yellow
            
            $reportFile = "$env:USERPROFILE\Desktop\DonanımRaporu_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
            
            # HTML Başlangıcı
            $htmlContent = @"
<!DOCTYPE html>
<html>
<head>
    <title>Donanım Detaylı Raporu</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1 { color: #0066cc; }
        h2 { color: #0099cc; margin-top: 30px; border-bottom: 1px solid #ddd; padding-bottom: 5px; }
        table { border-collapse: collapse; width: 100%; margin: 20px 0; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        tr:nth-child(even) { background-color: #f9f9f9; }
    </style>
</head>
<body>
    <h1>Donanım Detaylı Raporu</h1>
    <p>Oluşturma Tarihi: $(Get-Date)</p>
    <p>Bilgisayar Adı: $env:COMPUTERNAME</p>
"@
            
            # Sistem Bilgisi
            $system = Get-CimInstance -ClassName Win32_ComputerSystem
            $bios = Get-CimInstance -ClassName Win32_BIOS
            $os = Get-CimInstance -ClassName Win32_OperatingSystem
            
            $htmlContent += @"
    <h2>Sistem Bilgisi</h2>
    <table>
        <tr><th>Özellik</th><th>Değer</th></tr>
        <tr><td>Üretici</td><td>$($system.Manufacturer)</td></tr>
        <tr><td>Model</td><td>$($system.Model)</td></tr>
        <tr><td>Seri Numarası</td><td>$($bios.SerialNumber)</td></tr>
        <tr><td>BIOS Versiyonu</td><td>$($bios.SMBIOSBIOSVersion)</td></tr>
        <tr><td>İşletim Sistemi</td><td>$($os.Caption) $($os.Version)</td></tr>
        <tr><td>Mimari</td><td>$($os.OSArchitecture)</td></tr>
        <tr><td>Kurulum Tarihi</td><td>$($os.InstallDate)</td></tr>
    </table>
"@
            
            # İşlemci Bilgisi
            $processors = Get-CimInstance -ClassName Win32_Processor
            
            $htmlContent += @"
    <h2>İşlemci Bilgisi</h2>
    <table>
        <tr><th>Özellik</th><th>Değer</th></tr>
"@

            foreach ($processor in $processors) {
                $htmlContent += @"
        <tr><td>İşlemci Adı</td><td>$($processor.Name)</td></tr>
        <tr><td>Üretici</td><td>$($processor.Manufacturer)</td></tr>
        <tr><td>Maksimum Hız</td><td>$($processor.MaxClockSpeed) MHz</td></tr>
        <tr><td>Çekirdek Sayısı</td><td>$($processor.NumberOfCores)</td></tr>
        <tr><td>Mantıksal İşlemci Sayısı</td><td>$($processor.NumberOfLogicalProcessors)</td></tr>
        <tr><td>L2 Önbellek</td><td>$($processor.L2CacheSize) KB</td></tr>
        <tr><td>L3 Önbellek</td><td>$($processor.L3CacheSize) KB</td></tr>
        <tr><td>Soket</td><td>$($processor.SocketDesignation)</td></tr>
"@
            }
            
            $htmlContent += @"
    </table>
"@
            
            # Bellek Bilgisi
            $memory = Get-CimInstance -ClassName Win32_PhysicalMemory
            
            $htmlContent += @"
    <h2>Bellek Bilgisi</h2>
    <table>
        <tr><th>Yuva</th><th>Kapasite</th><th>Hız</th><th>Üretici</th><th>Seri No</th></tr>
"@

            $totalMemory = 0
            foreach ($memModule in $memory) {
                $capacity = [math]::Round($memModule.Capacity / 1GB, 2)
                $totalMemory += $capacity
                $htmlContent += @"
        <tr>
            <td>$($memModule.DeviceLocator)</td>
            <td>$capacity GB</td>
            <td>$($memModule.Speed) MHz</td>
            <td>$($memModule.Manufacturer)</td>
            <td>$($memModule.SerialNumber)</td>
        </tr>
"@
            }
            
            $htmlContent += @"
    </table>
    <p>Toplam Bellek: $totalMemory GB</p>
"@
            
            # Depolama Bilgisi
            $diskDrives = Get-CimInstance -ClassName Win32_DiskDrive
            
            $htmlContent += @"
    <h2>Fiziksel Disk Bilgisi</h2>
    <table>
        <tr><th>Model</th><th>Arayüz</th><th>Boyut</th><th>Sektör Boyutu</th><th>Durum</th></tr>
"@

            foreach ($disk in $diskDrives) {
                $size = [math]::Round($disk.Size / 1GB, 2)
                $htmlContent += @"
        <tr>
            <td>$($disk.Model)</td>
            <td>$($disk.InterfaceType)</td>
            <td>$size GB</td>
            <td>$($disk.BytesPerSector) bytes</td>
            <td>$($disk.Status)</td>
        </tr>
"@
            }
            
            $htmlContent += @"
    </table>
"@
            
            # Mantıksal Disk Bilgisi
            $logicalDisks = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DriveType=3"
            
            $htmlContent += @"
    <h2>Mantıksal Disk Bilgisi</h2>
    <table>
        <tr><th>Sürücü</th><th>Ad</th><th>Dosya Sistemi</th><th>Toplam Alan</th><th>Boş Alan</th><th>Boş Yüzde</th></tr>
"@

            foreach ($logicalDisk in $logicalDisks) {
                $totalSize = [math]::Round($logicalDisk.Size / 1GB, 2)
                $freeSpace = [math]::Round($logicalDisk.FreeSpace / 1GB, 2)
                $freePercent = [math]::Round(($logicalDisk.FreeSpace / $logicalDisk.Size) * 100, 2)
                
                $htmlContent += @"
        <tr>
            <td>$($logicalDisk.DeviceID)</td>
            <td>$($logicalDisk.VolumeName)</td>
            <td>$($logicalDisk.FileSystem)</td>
            <td>$totalSize GB</td>
            <td>$freeSpace GB</td>
            <td>%$freePercent</td>
        </tr>
"@
            }
            
            $htmlContent += @"
    </table>
"@
            
            # Grafik Kartı Bilgisi
            $videoControllers = Get-CimInstance -ClassName Win32_VideoController
            
            $htmlContent += @"
    <h2>Grafik Kartı Bilgisi</h2>
    <table>
        <tr><th>Ad</th><th>Üretici</th><th>Sürücü Sürümü</th><th>Bellek</th><th>Çözünürlük</th></tr>
"@

            foreach ($videoController in $videoControllers) {
                $vramSize = [math]::Round($videoController.AdapterRAM / 1MB, 2)
                $resolution = "$($videoController.CurrentHorizontalResolution) x $($videoController.CurrentVerticalResolution)"
                
                $htmlContent += @"
        <tr>
            <td>$($videoController.Name)</td>
            <td>$($videoController.VideoProcessor)</td>
            <td>$($videoController.DriverVersion)</td>
            <td>$vramSize MB</td>
            <td>$resolution</td>
        </tr>
"@
            }
            
            $htmlContent += @"
    </table>
"@
            
            # Ağ Adaptörleri
            $networkAdapters = Get-CimInstance -ClassName Win32_NetworkAdapter | Where-Object { $_.PhysicalAdapter -eq $true }
            
            $htmlContent += @"
    <h2>Ağ Adaptörleri</h2>
    <table>
        <tr><th>Ad</th><th>Üretici</th><th>MAC Adresi</th><th>Bağlantı Hızı</th><th>Adaptör Tipi</th></tr>
"@

            foreach ($adapter in $networkAdapters) {
                $htmlContent += @"
        <tr>
            <td>$($adapter.Name)</td>
            <td>$($adapter.Manufacturer)</td>
            <td>$($adapter.MACAddress)</td>
            <td>$($adapter.Speed)</td>
            <td>$($adapter.AdapterType)</td>
        </tr>
"@
            }
            
            $htmlContent += @"
    </table>
"@
            
            # Ses Aygıtları
            $soundDevices = Get-CimInstance -ClassName Win32_SoundDevice
            
            $htmlContent += @"
    <h2>Ses Aygıtları</h2>
    <table>
        <tr><th>Ad</th><th>Üretici</th><th>Durum</th></tr>
"@

            foreach ($device in $soundDevices) {
                $htmlContent += @"
        <tr>
            <td>$($device.Name)</td>
            <td>$($device.Manufacturer)</td>
            <td>$($device.Status)</td>
        </tr>
"@
            }
            
            $htmlContent += @"
    </table>
"@
            
            # HTML Sonu
            $htmlContent += @"
</body>
</html>
"@
            
            # Dosyaya yaz
            $htmlContent | Out-File -FilePath $reportFile -Encoding utf8
            
            Write-Host "Rapor oluşturuldu: $reportFile" -ForegroundColor Green
            Invoke-Item $reportFile
            
            Pause
            Show-ReportingMenu
        }
        "3" {
            Write-Host "`nYazılım Envanteri Raporu Oluşturuluyor..." -ForegroundColor Yellow
            
            $reportFile = "$env:USERPROFILE\Desktop\YazılımEnvanteri_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
            
            # Kurulu Programları Al
            Write-Host "Kurulu programlar listeleniyor..." -ForegroundColor Yellow
            
            $installedSoftware = @()
            
            # 64-bit programlar
            $installedSoftware += Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | 
                                Where-Object { $_.DisplayName -ne $null } | 
                                Select-Object DisplayName, DisplayVersion, Publisher, InstallDate
            
            # 32-bit programlar (64-bit sistemde)
            if (Test-Path HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*) {
                $installedSoftware += Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | 
                                    Where-Object { $_.DisplayName -ne $null } | 
                                    Select-Object DisplayName, DisplayVersion, Publisher, InstallDate
            }
            
            # Kullanıcı tarafından kurulmuş programlar
            $installedSoftware += Get-ItemProperty HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | 
                                Where-Object { $_.DisplayName -ne $null } | 
                                Select-Object DisplayName, DisplayVersion, Publisher, InstallDate
            
            # Duplikasyonları temizle ve sırala
            $installedSoftware = $installedSoftware | 
                                Sort-Object DisplayName -Unique | 
                                Select-Object @{Name="ProgramAdı";Expression={$_.DisplayName}}, 
                                            @{Name="Sürüm";Expression={$_.DisplayVersion}}, 
                                            @{Name="Yayımcı";Expression={$_.Publisher}}, 
                                            @{Name="KurulumTarihi";Expression={$_.InstallDate}}
            
            # Windows Store Uygulamaları
            try {
                Write-Host "Windows Store uygulamaları listeleniyor..." -ForegroundColor Yellow
                $storeApps = Get-AppxPackage | 
                            Select-Object @{Name="ProgramAdı";Expression={$_.Name}}, 
                                        @{Name="Sürüm";Expression={$_.Version}}, 
                                        @{Name="Yayımcı";Expression={$_.Publisher}}, 
                                        @{Name="KurulumTarihi";Expression={$_.InstallDate}}
                
                $installedSoftware += $storeApps
            }
            catch {
                Write-Host "Windows Store uygulamaları listelenirken hata oluştu: $($_.Exception.Message)" -ForegroundColor Red
            }
            
            # CSV dosyasına aktar
            $installedSoftware | Export-Csv -Path $reportFile -NoTypeInformation -Encoding UTF8
            
            Write-Host "Rapor oluşturuldu: $reportFile" -ForegroundColor Green
            Invoke-Item (Split-Path $reportFile -Parent)
            
            Pause
            Show-ReportingMenu
        }
        "4" {
            Write-Host "`nGüvenlik Durum Raporu Oluşturuluyor..." -ForegroundColor Yellow
            
            $reportFile = "$env:USERPROFILE\Desktop\GüvenlikDurumRaporu_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
            
            # HTML Başlangıcı
            $htmlContent = @"
<!DOCTYPE html>
<html>
<head>
    <title>Güvenlik Durum Raporu</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1 { color: #0066cc; }
        h2 { color: #0099cc; margin-top: 30px; border-bottom: 1px solid #ddd; padding-bottom: 5px; }
        .section { margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }
        .good { background-color: #dff0d8; border-color: #d6e9c6; }
        .warning { background-color: #fcf8e3; border-color: #faebcc; }
        .danger { background-color: #f2dede; border-color: #ebccd1; }
        .status-icon { font-weight: bold; margin-right: 5px; }
        .good .status-icon { color: green; }
        .warning .status-icon { color: orange; }
        .danger .status-icon { color: red; }
        table { border-collapse: collapse; width: 100%; margin: 20px 0; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        tr:nth-child(even) { background-color: #f9f9f9; }
    </style>
</head>
<body>
    <h1>Güvenlik Durum Raporu</h1>
    <p>Oluşturma Tarihi: $(Get-Date)</p>
    <p>Bilgisayar Adı: $env:COMPUTERNAME</p>
"@
            
            # Windows Defender Durumu
            try {
                $defenderStatus = Get-MpComputerStatus
                
                $defenderClass = if ($defenderStatus.AntivirusEnabled -and $defenderStatus.RealTimeProtectionEnabled) {
                    "good"
                } elseif ($defenderStatus.AntivirusEnabled -and -not $defenderStatus.RealTimeProtectionEnabled) {
                    "warning"
                } else {
                    "danger"
                }
                
                $signatureAge = (Get-Date) - $defenderStatus.AntivirusSignatureLastUpdated
                $signatureClass = if ($signatureAge.Days -lt 3) {
                    "good"
                } elseif ($signatureAge.Days -lt 7) {
                    "warning"
                } else {
                    "danger"
                }
                
                $htmlContent += @"
    <h2>Windows Defender Durumu</h2>
    <div class="section $defenderClass">
        <span class="status-icon">${if ($defenderClass -eq "good") { "✓" } elseif ($defenderClass -eq "warning") { "!" } else { "✗" }}</span>
        <strong>Genel Durum:</strong> ${if ($defenderClass -eq "good") { "Korumalı" } elseif ($defenderClass -eq "warning") { "Kısmen Korumalı" } else { "Korumasız" }}
    </div>
    
    <table>
        <tr><th>Özellik</th><th>Değer</th><th>Durum</th></tr>
        <tr>
            <td>Antivirüs Etkin</td>
            <td>$($defenderStatus.AntivirusEnabled)</td>
            <td>${if ($defenderStatus.AntivirusEnabled) { "✓" } else { "✗" }}</td>
        </tr>
        <tr>
            <td>Gerçek Zamanlı Koruma</td>
            <td>$($defenderStatus.RealTimeProtectionEnabled)</td>
            <td>${if ($defenderStatus.RealTimeProtectionEnabled) { "✓" } else { "✗" }}</td>
        </tr>
        <tr>
            <td>İmza Sürümü</td>
            <td>$($defenderStatus.AntivirusSignatureVersion)</td>
            <td></td>
        </tr>
        <tr>
            <td>Son İmza Güncellemesi</td>
            <td>$($defenderStatus.AntivirusSignatureLastUpdated)</td>
            <td class="$signatureClass">${if ($signatureClass -eq "good") { "✓" } elseif ($signatureClass -eq "warning") { "!" } else { "✗" }}</td>
        </tr>
        <tr>
            <td>Son Tam Tarama</td>
            <td>${if ($defenderStatus.FullScanEndTime) { $defenderStatus.FullScanEndTime } else { "Tam tarama yapılmamış" }}</td>
            <td></td>
        </tr>
        <tr>
            <td>Son Hızlı Tarama</td>
            <td>${if ($defenderStatus.QuickScanEndTime) { $defenderStatus.QuickScanEndTime } else { "Hızlı tarama yapılmamış" }}</td>
            <td></td>
        </tr>
    </table>
"@
            }
            catch {
                $htmlContent += @"
    <h2>Windows Defender Durumu</h2>
    <div class="section danger">
        <span class="status-icon">✗</span>
        <strong>Hata:</strong> Windows Defender durumu alınamadı: $($_.Exception.Message)
    </div>
"@
            }
            
            # Güvenlik Duvarı Durumu
            try {
                $firewallProfiles = Get-NetFirewallProfile
                $domainActive = ($firewallProfiles | Where-Object { $_.Name -eq "Domain" }).Enabled
                $privateActive = ($firewallProfiles | Where-Object { $_.Name -eq "Private" }).Enabled
                $publicActive = ($firewallProfiles | Where-Object { $_.Name -eq "Public" }).Enabled
                
                $firewallClass = if ($domainActive -and $privateActive -and $publicActive) {
                    "good"
                } elseif ($domainActive -or $privateActive -or $publicActive) {
                    "warning"
                } else {
                    "danger"
                }
                
                $htmlContent += @"
    <h2>Güvenlik Duvarı Durumu</h2>
    <div class="section $firewallClass">
        <span class="status-icon">${if ($firewallClass -eq "good") { "✓" } elseif ($firewallClass -eq "warning") { "!" } else { "✗" }}</span>
        <strong>Genel Durum:</strong> ${if ($firewallClass -eq "good") { "Korumalı" } elseif ($firewallClass -eq "warning") { "Kısmen Korumalı" } else { "Korumasız" }}
    </div>
    
    <table>
        <tr><th>Profil</th><th>Durum</th><th>Gelen Bağlantılar</th><th>Giden Bağlantılar</th></tr>
"@

                foreach ($profile in $firewallProfiles) {
                    $statusClass = if ($profile.Enabled) { "good" } else { "danger" }
                    $htmlContent += @"
        <tr>
            <td>$($profile.Name)</td>
            <td class="$statusClass">${if ($profile.Enabled) { "Etkin ✓" } else { "Devre Dışı ✗" }}</td>
            <td>$($profile.DefaultInboundAction)</td>
            <td>$($profile.DefaultOutboundAction)</td>
        </tr>
"@
                }
                
                $htmlContent += @"
    </table>
"@
            }
            catch {
                $htmlContent += @"
    <h2>Güvenlik Duvarı Durumu</h2>
    <div class="section danger">
        <span class="status-icon">✗</span>
        <strong>Hata:</strong> Güvenlik duvarı durumu alınamadı: $($_.Exception.Message)
    </div>
"@
            }
            
            # Windows Update Durumu
            try {
                if (Test-ModuleInstalled -ModuleName "PSWindowsUpdate") {
                    $updates = Get-WindowsUpdate
                    
                    $updateClass = if ($updates.Count -eq 0) {
                        "good"
                    } elseif ($updates.Count -lt 5) {
                        "warning"
                    } else {
                        "danger"
                    }
                    
                    $htmlContent += @"
    <h2>Windows Update Durumu</h2>
    <div class="section $updateClass">
        <span class="status-icon">${if ($updateClass -eq "good") { "✓" } elseif ($updateClass -eq "warning") { "!" } else { "✗" }}</span>
        <strong>Genel Durum:</strong> ${if ($updateClass -eq "good") { "Güncel" } elseif ($updateClass -eq "warning") { "Birkaç güncelleştirme gerekiyor" } else { "Çok sayıda güncelleştirme gerekiyor" }}
    </div>
    
    <p>Bekleyen güncelleştirme sayısı: $($updates.Count)</p>
"@

                    if ($updates.Count -gt 0) {
                        $htmlContent += @"
    <table>
        <tr><th>Güncelleştirme</th><th>KB Numarası</th><th>Tür</th></tr>
"@

                        foreach ($update in $updates) {
                            $htmlContent += @"
        <tr>
            <td>$($update.Title)</td>
            <td>$($update.KBArticleID)</td>
            <td>$($update.UpdateType)</td>
        </tr>
"@
                        }
                        
                        $htmlContent += @"
    </table>
"@
                    }
                }
                else {
                    $htmlContent += @"
    <h2>Windows Update Durumu</h2>
    <div class="section warning">
        <span class="status-icon">!</span>
        <strong>Bilgi:</strong> Güncelleştirme durumu için PSWindowsUpdate modülü yüklü değil.
    </div>
"@
                }
            }
            catch {
                $htmlContent += @"
    <h2>Windows Update Durumu</h2>
    <div class="section danger">
        <span class="status-icon">✗</span>
        <strong>Hata:</strong> Windows Update durumu alınamadı: $($_.Exception.Message)
    </div>
"@
            }
            
            # UAC Durumu
            try {
                $uacStatus = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA"
                $uacClass = if ($uacStatus.EnableLUA -eq 1) {
                    "good"
                } else {
                    "danger"
                }
                
                $htmlContent += @"
    <h2>Kullanıcı Hesap Kontrolü (UAC) Durumu</h2>
    <div class="section $uacClass">
        <span class="status-icon">${if ($uacClass -eq "good") { "✓" } else { "✗" }}</span>
        <strong>Durum:</strong> ${if ($uacClass -eq "good") { "Etkin" } else { "Devre Dışı" }}
    </div>
"@
            }
            catch {
                $htmlContent += @"
    <h2>Kullanıcı Hesap Kontrolü (UAC) Durumu</h2>
    <div class="section danger">
        <span class="status-icon">✗</span>
        <strong>Hata:</strong> UAC durumu alınamadı: $($_.Exception.Message)
    </div>
"@
            }
            
            # BitLocker Durumu
            try {
                $bitlockerVolumes = Get-BitLockerVolume
                
                if ($bitlockerVolumes) {
                    $systemDrive = $bitlockerVolumes | Where-Object { $_.MountPoint -eq $env:SystemDrive }
                    
                    if ($systemDrive) {
                        $bitlockerClass = if ($systemDrive.ProtectionStatus -eq "On") {
                            "good"
                        } else {
                            "danger"
                        }
                        
                        $htmlContent += @"
    <h2>BitLocker Durumu</h2>
    <div class="section $bitlockerClass">
        <span class="status-icon">${if ($bitlockerClass -eq "good") { "✓" } else { "✗" }}</span>
        <strong>Sistem Sürücüsü ($env:SystemDrive) Durumu:</strong> ${if ($bitlockerClass -eq "good") { "Şifreli" } else { "Şifrelenmemiş" }}
    </div>
    
    <table>
        <tr><th>Sürücü</th><th>Koruma Durumu</th><th>Şifreleme Yöntemi</th><th>Şifreleme Yüzdesi</th></tr>
"@

                        foreach ($volume in $bitlockerVolumes) {
                            $protectionClass = if ($volume.ProtectionStatus -eq "On") { "good" } else { "danger" }
                            $htmlContent += @"
        <tr>
            <td>$($volume.MountPoint)</td>
            <td class="$protectionClass">${if ($volume.ProtectionStatus -eq "On") { "Etkin ✓" } else { "Devre Dışı ✗" }}</td>
            <td>$($volume.EncryptionMethod)</td>
            <td>$($volume.VolumeStatus)</td>
        </tr>
"@
                        }
                        
                        $htmlContent += @"
    </table>
"@
                    }
                    else {
                        $htmlContent += @"
    <h2>BitLocker Durumu</h2>
    <div class="section warning">
        <span class="status-icon">!</span>
        <strong>Uyarı:</strong> Sistem sürücüsü ($env:SystemDrive) için BitLocker bilgisi bulunamadı.
    </div>
"@
                    }
                }
                else {
                    $htmlContent += @"
    <h2>BitLocker Durumu</h2>
    <div class="section warning">
        <span class="status-icon">!</span>
        <strong>Uyarı:</strong> BitLocker hiçbir sürücüde yapılandırılmamış.
    </div>
"@
                }
            }
            catch {
                $htmlContent += @"
    <h2>BitLocker Durumu</h2>
    <div class="section warning">
        <span class="status-icon">!</span>
        <strong>Bilgi:</strong> BitLocker durumu alınamadı: $($_.Exception.Message)
    </div>
"@
            }
            
            # Güvenlik Önerileri
            $htmlContent += @"
    <h2>Güvenlik Önerileri</h2>
    <ul>
"@

            # Defender önerileri
            if (-not $defenderStatus.AntivirusEnabled) {
                $htmlContent += @"
        <li class="danger">Windows Defender etkinleştirilmeli.</li>
"@
            }
            
            if (-not $defenderStatus.RealTimeProtectionEnabled) {
                $htmlContent += @"
        <li class="danger">Windows Defender gerçek zamanlı koruma etkinleştirilmeli.</li>
"@
            }
            
            if ($signatureAge.Days -gt 7) {
                $htmlContent += @"
        <li class="danger">Windows Defender imzaları güncelleştirilmeli. Son güncelleme $($signatureAge.Days) gün önce.</li>
"@
            }
            
            # Güvenlik duvarı önerileri
            if (-not $domainActive -or -not $privateActive -or -not $publicActive) {
                $htmlContent += @"
        <li class="danger">Tüm güvenlik duvarı profilleri etkinleştirilmeli.</li>
"@
            }
            
            # Windows Update önerileri
            if ($updates -and $updates.Count -gt 0) {
                $htmlContent += @"
        <li class="warning">$($updates.Count) bekleyen Windows güncelleştirmesi yüklenmeli.</li>
"@
            }
            
            # UAC önerileri
            if ($uacStatus -and $uacStatus.EnableLUA -ne 1) {
                $htmlContent += @"
        <li class="danger">Kullanıcı Hesap Kontrolü (UAC) etkinleştirilmeli.</li>
"@
            }
            
            # BitLocker önerileri
            if ($systemDrive -and $systemDrive.ProtectionStatus -ne "On") {
                $htmlContent += @"
        <li class="warning">Sistem sürücüsü BitLocker ile şifrelenmeli.</li>
"@
            }
            
            $htmlContent += @"
    </ul>
"@
            
            # HTML Sonu
            $htmlContent += @"
</body>
</html>
"@
            
            # Dosyaya yaz
            $htmlContent | Out-File -FilePath $reportFile -Encoding utf8
            
            Write-Host "Rapor oluşturuldu: $reportFile" -ForegroundColor Green
            Invoke-Item $reportFile
            
            Pause
            Show-ReportingMenu
        }
        "5" {
            Write-Host "`nDisk Kullanım Raporu Oluşturuluyor..." -ForegroundColor Yellow
            
            $reportFile = "$env:USERPROFILE\Desktop\DiskKullanımRaporu_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
            
            # HTML Başlangıcı
            $htmlContent = @"
<!DOCTYPE html>
<html>
<head>
    <title>Disk Kullanım Raporu</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1 { color: #0066cc; }
        h2 { color: #0099cc; margin-top: 30px; border-bottom: 1px solid #ddd; padding-bottom: 5px; }
        .disk-bar { height: 30px; margin: 10px 0; background-color: #e9e9e9; border-radius: 5px; overflow: hidden; }
        .disk-bar-inner { height: 100%; float: left; transition: width 0.5s; }
        .disk-used { background-color: #428bca; }
        .disk-free { background-color: #5cb85c; }
        .disk-warning { background-color: #f0ad4e; }
        .disk-danger { background-color: #d9534f; }
        .disk-info { display: flex; justify-content: space-between; margin-bottom: 15px; }
        table { border-collapse: collapse; width: 100%; margin: 20px 0; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        tr:nth-child(even) { background-color: #f9f9f9; }
        .folder-bar { height: 20px; margin: 5px 0; background-color: #e9e9e9; border-radius: 3px; overflow: hidden; }
        .folder-bar-inner { height: 100%; background-color: #428bca; float: left; transition: width 0.5s; }
    </style>
</head>
<body>
    <h1>Disk Kullanım Raporu</h1>
    <p>Oluşturma Tarihi: $(Get-Date)</p>
    <p>Bilgisayar Adı: $env:COMPUTERNAME</p>
"@
            
            # Diskler Bölümü
            $htmlContent += @"
    <h2>Disk Kullanımı</h2>
"@

            $disks = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DriveType=3"
            
            foreach ($disk in $disks) {
                $used = $disk.Size - $disk.FreeSpace
                $usedPercent = [math]::Round(($used / $disk.Size) * 100, 2)
                $freePercent = [math]::Round(($disk.FreeSpace / $disk.Size) * 100, 2)
                
                $diskClass = "disk-used"
                if ($usedPercent -ge 90) {
                    $diskClass = "disk-danger"
                } elseif ($usedPercent -ge 75) {
                    $diskClass = "disk-warning"
                }
                
                $htmlContent += @"
    <div class="disk-info">
        <div>
            <strong>Disk $($disk.DeviceID) - $($disk.VolumeName)</strong>
            <div>Toplam: $([math]::Round($disk.Size / 1GB, 2)) GB | Kullanılan: $([math]::Round($used / 1GB, 2)) GB | Boş: $([math]::Round($disk.FreeSpace / 1GB, 2))
