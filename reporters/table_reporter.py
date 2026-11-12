"""
Terminal tablosu (renkli ASCII) rapor üretici.
Harici bağımlılık gerektirmez; opsiyonel olarak 'rich' kütüphanesi kullanılır.
"""

from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

# 'rich' varsa zengin tablo, yoksa düz ASCII
try:
    from rich.console import Console
    from rich.table import Table
    from rich import box
    from rich.text import Text
    from rich.panel import Panel
    HAS_RICH = True
except ImportError:
    HAS_RICH = False


# ---------------------------------------------------------------------------
# ANSI renk yardımcıları (rich yoksa kullanılır)
# ---------------------------------------------------------------------------

RESET = "\033[0m"
BOLD  = "\033[1m"
RED   = "\033[91m"
YEL   = "\033[93m"
CYA   = "\033[96m"
GRN   = "\033[92m"
MAG   = "\033[95m"
DIM   = "\033[2m"


def _sev_color(sev: str) -> str:
    return {
        "critical": RED + BOLD,
        "high":     RED,
        "medium":   YEL,
        "low":      GRN,
    }.get(sev.lower(), RESET)


def _trunc(s: str, n: int = 60) -> str:
    return s if len(s) <= n else s[: n - 3] + "..."


# ---------------------------------------------------------------------------
# Rich rapor
# ---------------------------------------------------------------------------

def _rich_report(result: Dict[str, Any]) -> None:
    console = Console()
    summary = result.get("summary", {})

    # --- Özet paneli ---
    total = summary.get("total_events", 0)
    anomalies = summary.get("total_anomalies", 0)
    sev = summary.get("severity_breakdown", {})
    sev_str = "  ".join(
        f"[bold red]{k.upper()}[/]: {v}" for k, v in sev.items()
    )
    panel_text = (
        f"[bold]Toplam Olay:[/] {total}    "
        f"[bold yellow]Anomali:[/] {anomalies}\n"
        f"{sev_str}\n"
        f"[dim]Analiz zamanı: {summary.get('analysis_time', '')}[/dim]"
    )
    console.print(Panel(panel_text, title="[bold cyan]LOG ANALİZ ÖZET[/]", expand=False))

    # --- Brute-Force tablosu ---
    if result.get("brute_force"):
        t = Table(title="🔴 Brute-Force Saldırıları", box=box.ROUNDED, show_lines=True)
        t.add_column("IP Adresi", style="bold red", no_wrap=True)
        t.add_column("Deneme", justify="right")
        t.add_column("Şiddet")
        t.add_column("Kullanıcılar")
        t.add_column("Pencere Başlangıcı")
        t.add_column("Pencere Bitişi")
        for ev in result["brute_force"]:
            sev_val = ev.get("severity", "")
            color = {"critical": "bold red", "high": "red", "medium": "yellow", "low": "green"}.get(sev_val, "white")
            t.add_row(
                ev.get("ip", ""),
                str(ev.get("attempt_count", "")),
                Text(sev_val.upper(), style=color),
                ", ".join(ev.get("unique_users_tried", [])),
                ev.get("window_start", ""),
                ev.get("window_end", ""),
            )
        console.print(t)

    # --- Yetki Yükseltme tablosu ---
    if result.get("privilege_escalation"):
        t = Table(title="🟠 Yetki Yükseltme", box=box.ROUNDED, show_lines=True)
        t.add_column("Zaman", no_wrap=True)
        t.add_column("Kullanıcı")
        t.add_column("Şiddet")
        t.add_column("Olay Türü")
        t.add_column("Açıklama", max_width=55)
        for ev in result["privilege_escalation"]:
            sev_val = ev.get("severity", "")
            color = {"critical": "bold red", "high": "red", "medium": "yellow", "low": "green"}.get(sev_val, "white")
            t.add_row(
                ev.get("timestamp", "")[:19],
                ev.get("user", ""),
                Text(sev_val.upper(), style=color),
                ev.get("event_type", ""),
                _trunc(ev.get("description", "")),
            )
        console.print(t)

    # --- Şüpheli Zaman tablosu ---
    if result.get("suspicious_time_logons"):
        t = Table(title="🟡 Şüpheli Saatlerdeki Oturumlar", box=box.ROUNDED, show_lines=True)
        t.add_column("Zaman", no_wrap=True)
        t.add_column("Kullanıcı")
        t.add_column("IP / Bilgisayar")
        t.add_column("Saat")
        t.add_column("Gün")
        t.add_column("Neden")
        for ev in result["suspicious_time_logons"]:
            t.add_row(
                ev.get("timestamp", "")[:19],
                ev.get("user", ""),
                ev.get("ip", ""),
                str(ev.get("hour", "")),
                ev.get("weekday", ""),
                ev.get("reason", ""),
            )
        console.print(t)

    # --- Şüpheli İşlem tablosu ---
    if result.get("suspicious_processes"):
        t = Table(title="🔵 Şüpheli Süreçler", box=box.ROUNDED, show_lines=True)
        t.add_column("Zaman", no_wrap=True)
        t.add_column("Kullanıcı")
        t.add_column("İşlem")
        t.add_column("Komut", max_width=50)
        for ev in result["suspicious_processes"]:
            t.add_row(
                ev.get("timestamp", "")[:19],
                ev.get("user", ""),
                ev.get("process", ""),
                _trunc(ev.get("command_line", "")),
            )
        console.print(t)

    if not any([
        result.get("brute_force"),
        result.get("privilege_escalation"),
        result.get("suspicious_time_logons"),
        result.get("suspicious_processes"),
    ]):
        console.print("[bold green]✓ Herhangi bir anomali tespit edilmedi.[/]")


# ---------------------------------------------------------------------------
# Düz ASCII rapor
# ---------------------------------------------------------------------------

def _ascii_report(result: Dict[str, Any]) -> None:
    summary = result.get("summary", {})
    sep = "=" * 72

    print(f"\n{sep}")
    print(f"  LOG ANALİZ RAPORU")
    print(sep)
    print(f"  Toplam Olay  : {summary.get('total_events', 0)}")
    print(f"  Toplam Anomali: {summary.get('total_anomalies', 0)}")
    sev = summary.get("severity_breakdown", {})
    for k, v in sev.items():
        print(f"  {k.upper():10}: {v}")
    print(f"  Analiz Zamanı: {summary.get('analysis_time', '')}")
    print(sep)

    def _section(title: str, items: List[Dict[str, Any]], columns: List[str]) -> None:
        if not items:
            return
        print(f"\n--- {title} ({len(items)} kayıt) ---")
        col_widths = {c: max(len(c), *(len(str(i.get(c, ""))[:30]) for i in items)) for c in columns}
        header = "  ".join(c.ljust(col_widths[c]) for c in columns)
        print(header)
        print("-" * len(header))
        for item in items:
            row = "  ".join(str(item.get(c, ""))[:col_widths[c]].ljust(col_widths[c]) for c in columns)
            print(row)

    _section(
        "Brute-Force Saldırıları",
        result.get("brute_force", []),
        ["ip", "attempt_count", "severity", "window_start", "window_end"],
    )
    _section(
        "Yetki Yükseltme",
        result.get("privilege_escalation", []),
        ["timestamp", "user", "severity", "event_type"],
    )
    _section(
        "Şüpheli Saatlerdeki Oturumlar",
        result.get("suspicious_time_logons", []),
        ["timestamp", "user", "ip", "hour", "weekday", "reason"],
    )
    _section(
        "Şüpheli Süreçler",
        result.get("suspicious_processes", []),
        ["timestamp", "user", "process"],
    )
    print(f"\n{sep}\n")


# ---------------------------------------------------------------------------
# Genel arayüz
# ---------------------------------------------------------------------------

def generate(result: Dict[str, Any], output_path: Optional[str] = None) -> None:
    """
    Sonucu terminal tablosu olarak yazdırır.
    output_path belirtilirse düz metin olarak da kaydeder.
    """
    if HAS_RICH:
        _rich_report(result)
    else:
        _ascii_report(result)

    if output_path:
        # Dosyaya düz metin olarak yaz
        import io, sys
        old_stdout = sys.stdout
        sys.stdout = buffer = io.StringIO()
        _ascii_report(result)
        sys.stdout = old_stdout
        text = buffer.getvalue()
        with open(output_path, "w", encoding="utf-8") as fh:
            fh.write(text)
        print(f"[✓] Metin raporu yazıldı: {output_path}")
