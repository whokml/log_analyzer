# 🛡️ Log Analyzer — Linux/Windows Güvenlik Log Analiz Aracı

Brute-force saldırıları, yetki yükseltme girişimleri ve şüpheli saatlerdeki
oturumları `auth.log`, Windows Event Log ve Sysmon çıktılarından tespit eden
Python tabanlı CLI aracı.

---

## Özellikler

| Kategori | Tespit Edilen |
|---|---|
| **Brute-Force** | SSH başarısız denemeler, geçersiz kullanıcılar, MaxAuthTries aşımı, Windows EventID 4625 |
| **Yetki Yükseltme** | sudo success/fail, su oturumu, Windows EventID 4672/4648/4697/4720/4728/4732/7045 |
| **Şüpheli Saat** | Gece (00-06), mesai dışı, hafta sonu oturumları |
| **Şüpheli Süreç** | Mimikatz, Meterpreter, PowerShell encoded, PsExec, WMIC, bypass teknikleri (Sysmon/4688) |

Çıktı formatları: **Terminal tablosu** (renkli), **JSON**, **HTML** (koyu tema, arama kutusu).

---

## Kurulum

```bash
# Python 3.8+ gereklidir
pip install rich          # Opsiyonel: zengin terminal tablosu için
```

Harici bağımlılık olmadan da çalışır.

---

## Kullanım

### Temel

```bash
# Linux auth.log — terminal tablosu
python log_analyzer.py sample_logs/auth.log

# Windows Sysmon JSON — HTML rapor
python log_analyzer.py logs/sysmon.json --type windows-json --format html --output rapor.html

# Windows Event Log XML — JSON rapor
python log_analyzer.py logs/security.xml --type windows-xml --format json --output rapor.json

# Windows Get-WinEvent CSV
python log_analyzer.py logs/events.csv --type windows-csv --format table
```

### Zaman Filtresi

```bash
python log_analyzer.py auth.log \
  --start "2026-11-01 00:00" \
  --end   "2026-11-01 23:59" \
  --format html --output gunluk_rapor.html
```

### Brute-Force Eşiği Ayarlama

```bash
# 60 saniyede 3 deneme → uyarı
python log_analyzer.py auth.log --brute-threshold 3 --brute-window 60
```

### Mesai Saati Ayarlama

```bash
# 09:00-17:00 mesai, hafta sonu kontrolü kapalı
python log_analyzer.py auth.log \
  --business-start 9 --business-end 17 \
  --no-weekend-check
```

### Yalnızca Belirli Windows EventID'leri

```bash
python log_analyzer.py security.xml \
  --type windows-xml \
  --event-ids 4625 4624 4672
```

---

## Tüm Parametreler

```
kullanım: log_analyzer [SEÇENEKLER] <LOG_DOSYASI>

Argümanlar:
  logfile               Analiz edilecek log dosyası

Seçenekler:
  --type                auto | linux | windows-xml | windows-csv | windows-json
  --format, -f          table | json | html                  (varsayılan: table)
  --output, -o          Çıktı dosyası yolu
  --start               Başlangıç zamanı  'YYYY-MM-DD HH:MM'
  --end                 Bitiş zamanı      'YYYY-MM-DD HH:MM'
  --year                Linux syslog yılı (varsayılan: geçerli yıl)
  --brute-threshold N   Brute-force eşiği (varsayılan: 5)
  --brute-window SANİYE Kayan pencere boyutu (varsayılan: 300)
  --business-start SAAT Mesai başlangıcı   (varsayılan: 8)
  --business-end SAAT   Mesai bitişi       (varsayılan: 18)
  --no-weekend-check    Hafta sonu kontrolünü devre dışı bırak
  --event-ids ID [ID…]  Windows EventID filtresi
  --verbose, -v         Ayrıştırılan tüm olayları listele
```

---

## Desteklenen Log Formatları

### Linux (`--type linux`)
- `/var/log/auth.log` (Debian/Ubuntu)
- `/var/log/secure` (RHEL/CentOS)
- Standart syslog formatı: `MMM DD HH:MM:SS host service[pid]: mesaj`

### Windows XML (`--type windows-xml`)
PowerShell ile dışa aktarma:
```powershell
Get-WinEvent -LogName Security -MaxEvents 10000 |
  ConvertTo-Xml -As String |
  Set-Content security_events.xml
```

### Windows CSV (`--type windows-csv`)
```powershell
Get-WinEvent -LogName Security |
  Select-Object TimeCreated, Id, LevelDisplayName, Message, MachineName, UserId |
  Export-Csv events.csv -NoTypeInformation -Encoding UTF8
```

### Sysmon / WEF JSON (`--type windows-json`)
Elastic/Splunk/NXLog JSON çıktısı veya NDJSON formatı.

---

## Proje Yapısı

```
log_analyzer/
├── log_analyzer.py          # Ana CLI arayüzü
├── analyzers.py             # Anomali tespit motorları
├── parsers/
│   ├── linux_parser.py      # auth.log / syslog ayrıştırıcı
│   └── windows_parser.py    # Windows XML / CSV / JSON ayrıştırıcı
├── reporters/
│   ├── json_reporter.py     # JSON çıktı
│   ├── table_reporter.py    # Terminal tablosu (rich opsiyonel)
│   └── html_reporter.py     # Tek dosya HTML raporu
├── sample_logs/
│   ├── auth.log             # Örnek Linux log
│   └── windows_events.json  # Örnek Windows/Sysmon JSON
└── requirements.txt
```

---

## Tespit Mantığı

### Brute-Force
- Kayan pencere algoritması (varsayılan: 300 saniye)
- Eşik: 5 başarısız deneme (ayarlanabilir)
- Şiddet: `low` (<20) → `medium` (<50) → `high` (<100) → `critical` (≥100)

### Yetki Yükseltme
- Linux: `sudo`, `su` olayları + şüpheli komut regex eşleşmesi
- Windows: EventID 4672, 4648, 4697, 4720, 4728, 4732, 7045
- Şüpheli araçlar: Mimikatz, UAC bypass teknikleri, servis kurulumu vb.

### Şüpheli Zaman
- Gece saati: 00:00-06:00 (ayarlanabilir)
- Mesai dışı: 08:00-18:00 dışı (ayarlanabilir)
- Hafta sonu: Cumartesi-Pazar (opsiyonel)

### Şüpheli Süreç (Sysmon/Windows)
- 40+ araç ve teknik: Mimikatz, PowerShell encoded, LOLBAS vb.
- EventID 4688 (process creation) ve Sysmon EventID 1
