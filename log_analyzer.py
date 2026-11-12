#!/usr/bin/env python3
"""
Log Analyzer — Ana CLI arayüzü
================================
Kullanım:
  python log_analyzer.py [SEÇENEKLER] <LOG_DOSYASI>

Örnekler:
  # Linux auth.log — terminal tablosu
  python log_analyzer.py sample_logs/auth.log

  # Linux auth.log — belirli zaman aralığı + JSON rapor
  python log_analyzer.py sample_logs/auth.log \\
    --start "2026-11-01 00:00" --end "2026-11-01 23:59" \\
    --format json --output rapor.json

  # Windows JSON (Sysmon/WEF) — HTML rapor
  python log_analyzer.py sample_logs/windows_events.json \\
    --type windows-json --format html --output rapor.html

  # Brute-force eşiğini 3 olarak ayarla, 60 saniyelik pencere
  python log_analyzer.py sample_logs/auth.log \\
    --brute-threshold 3 --brute-window 60 --format table
"""

import argparse
import sys
import os
from datetime import datetime
from typing import Optional, List

# --- Proje kökünü sys.path'e ekle (doğrudan çalıştırma için) ---
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from parsers.linux_parser import parse_auth_log
from parsers.windows_parser import parse_evtx_xml, parse_winevent_csv, parse_sysmon_json
from analyzers import LogAnalyzer
from reporters import json_reporter, table_reporter, html_reporter


# ---------------------------------------------------------------------------
# Argüman ayrıştırıcı
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="log_analyzer",
        description="Linux/Windows log analiz ve anomali tespit aracı",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    p.add_argument(
        "logfile",
        help="Analiz edilecek log dosyası (.log, .xml, .csv, .json)",
    )

    p.add_argument(
        "--type",
        choices=["auto", "linux", "windows-xml", "windows-csv", "windows-json"],
        default="auto",
        help=(
            "Log dosyası türü. 'auto' uzantıya ve içeriğe göre otomatik algılar. "
            "(varsayılan: auto)"
        ),
    )

    p.add_argument(
        "--format", "-f",
        choices=["table", "json", "html"],
        default="table",
        help="Çıktı formatı (varsayılan: table)",
    )

    p.add_argument(
        "--output", "-o",
        default=None,
        metavar="DOSYA",
        help="Çıktının yazılacağı dosya yolu (belirtilmezse yalnızca terminale yazdırılır)",
    )

    p.add_argument(
        "--start",
        default=None,
        metavar="'YYYY-MM-DD HH:MM'",
        help="Başlangıç zamanı filtresi (örn. '2026-11-01 00:00')",
    )

    p.add_argument(
        "--end",
        default=None,
        metavar="'YYYY-MM-DD HH:MM'",
        help="Bitiş zamanı filtresi (örn. '2026-11-01 23:59')",
    )

    p.add_argument(
        "--year",
        type=int,
        default=None,
        help="Linux syslog yılı (varsayılan: geçerli yıl). Syslog formatı yıl içermez.",
    )

    p.add_argument(
        "--brute-threshold",
        type=int,
        default=5,
        metavar="N",
        help="Brute-force uyarısı için minimum başarısız deneme sayısı (varsayılan: 5)",
    )

    p.add_argument(
        "--brute-window",
        type=int,
        default=300,
        metavar="SANİYE",
        help="Brute-force kayan pencere boyutu saniye cinsinden (varsayılan: 300)",
    )

    p.add_argument(
        "--business-start",
        type=int,
        default=8,
        metavar="SAAT",
        help="Mesai başlangıç saati 0-23 (varsayılan: 8)",
    )

    p.add_argument(
        "--business-end",
        type=int,
        default=18,
        metavar="SAAT",
        help="Mesai bitiş saati 0-23 (varsayılan: 18)",
    )

    p.add_argument(
        "--no-weekend-check",
        action="store_true",
        help="Hafta sonu kontrolünü devre dışı bırak",
    )

    p.add_argument(
        "--event-ids",
        nargs="+",
        type=int,
        default=None,
        metavar="ID",
        help="Yalnızca belirtilen Windows EventID'leri analiz et (örn. --event-ids 4625 4624)",
    )

    p.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Ayrıştırılan tüm olayları da listele",
    )

    return p


# ---------------------------------------------------------------------------
# Otomatik log türü algılama
# ---------------------------------------------------------------------------

def _detect_type(filepath: str) -> str:
    ext = os.path.splitext(filepath)[1].lower()
    if ext in (".log", ".txt", ""):
        return "linux"
    if ext == ".xml":
        return "windows-xml"
    if ext == ".csv":
        return "windows-csv"
    if ext == ".json":
        # İçerik kontrolü
        try:
            with open(filepath, "r", encoding="utf-8", errors="replace") as fh:
                peek = fh.read(512)
            if any(k in peek for k in ("EventID", "event_id", "Image", "CommandLine")):
                return "windows-json"
        except Exception:
            pass
        return "windows-json"
    if ext == ".evtx":
        raise ValueError(
            "Ham .evtx dosyaları doğrudan okunamaz.\n"
            "Lütfen önce PowerShell ile XML'e dönüştürün:\n"
            "  Get-WinEvent -Path log.evtx | ConvertTo-Xml -As String | "
            "  Set-Content log.xml"
        )
    # Varsayılan: linux syslog
    return "linux"


# ---------------------------------------------------------------------------
# Zaman ayrıştırıcı
# ---------------------------------------------------------------------------

def _parse_dt(s: Optional[str]) -> Optional[datetime]:
    if not s:
        return None
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d"):
        try:
            return datetime.strptime(s, fmt)
        except ValueError:
            continue
    raise ValueError(
        f"Geçersiz zaman formatı: '{s}'\n"
        "Kabul edilen formatlar: 'YYYY-MM-DD HH:MM:SS', 'YYYY-MM-DD HH:MM', 'YYYY-MM-DD'"
    )


# ---------------------------------------------------------------------------
# Ana fonksiyon
# ---------------------------------------------------------------------------

def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    # Zaman filtrelerini çözümle
    try:
        start_time = _parse_dt(args.start)
        end_time = _parse_dt(args.end)
    except ValueError as exc:
        print(f"[HATA] {exc}", file=sys.stderr)
        return 1

    # Dosya türünü belirle
    log_type = args.type
    if log_type == "auto":
        try:
            log_type = _detect_type(args.logfile)
        except ValueError as exc:
            print(f"[HATA] {exc}", file=sys.stderr)
            return 1

    print(f"[*] Log dosyası : {args.logfile}")
    print(f"[*] Log türü    : {log_type}")
    if start_time:
        print(f"[*] Başlangıç   : {start_time}")
    if end_time:
        print(f"[*] Bitiş       : {end_time}")
    print(f"[*] Çıktı formatı: {args.format}")
    print()

    # --- Ayrıştırma ---
    events = []
    try:
        if log_type == "linux":
            events = parse_auth_log(
                args.logfile,
                start_time=start_time,
                end_time=end_time,
                year=args.year,
            )
        elif log_type == "windows-xml":
            events = parse_evtx_xml(
                args.logfile,
                start_time=start_time,
                end_time=end_time,
                event_id_filter=args.event_ids,
            )
        elif log_type == "windows-csv":
            events = parse_winevent_csv(
                args.logfile,
                start_time=start_time,
                end_time=end_time,
            )
        elif log_type == "windows-json":
            events = parse_sysmon_json(
                args.logfile,
                start_time=start_time,
                end_time=end_time,
            )
    except (FileNotFoundError, PermissionError, ValueError) as exc:
        print(f"[HATA] {exc}", file=sys.stderr)
        return 1

    print(f"[✓] {len(events)} olay ayrıştırıldı.")

    if args.verbose:
        print("\n--- Ayrıştırılan Olaylar ---")
        for ev in events[:50]:
            print(f"  [{ev.get('timestamp', '')}] {ev.get('event_type', ''):<30} user={ev.get('user', ''):<15} ip={ev.get('ip', '')}")
        if len(events) > 50:
            print(f"  ... (+{len(events) - 50} daha)")
        print()

    # --- Analiz ---
    analyzer = LogAnalyzer(
        brute_threshold=args.brute_threshold,
        brute_window=args.brute_window,
        business_hours=(args.business_start, args.business_end),
        check_weekends=not args.no_weekend_check,
    )

    result = analyzer.analyze(events)
    summary = result["summary"]

    print(f"[✓] Analiz tamamlandı.")
    print(f"    Toplam anomali    : {summary['total_anomalies']}")
    print(f"    Brute-force       : {summary['brute_force_count']}")
    print(f"    Yetki yükseltme   : {summary['privilege_escalation_count']}")
    print(f"    Şüpheli oturum    : {summary['suspicious_time_logon_count']}")
    print(f"    Şüpheli süreç     : {summary['suspicious_process_count']}")
    sev = summary.get("severity_breakdown", {})
    if sev:
        sev_str = " | ".join(f"{k.upper()}: {v}" for k, v in sev.items())
        print(f"    Şiddet dağılımı   : {sev_str}")
    print()

    # --- Raporlama ---
    source_name = os.path.basename(args.logfile)

    if args.format == "json":
        output = json_reporter.generate(result, output_path=args.output)
        if not args.output:
            print(output)

    elif args.format == "table":
        table_reporter.generate(result, output_path=args.output)

    elif args.format == "html":
        output = html_reporter.generate(result, output_path=args.output, source_file=source_name)
        if not args.output:
            # HTML'i terminale basmak mantıklı değil — dosya adı bildir
            print("[!] HTML çıktısı için --output ile bir dosya yolu belirtin.")
            print("    Örnek: --output rapor.html")

    return 0


if __name__ == "__main__":
    sys.exit(main())
