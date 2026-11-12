"""HTML rapor üretici — tek dosya, harici bağımlılık yok."""

from __future__ import annotations

import html
from datetime import datetime
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Renk / rozet yardımcıları
# ---------------------------------------------------------------------------

SEVERITY_BADGE = {
    "critical": '<span class="badge badge-critical">KRİTİK</span>',
    "high":     '<span class="badge badge-high">YÜKSEK</span>',
    "medium":   '<span class="badge badge-medium">ORTA</span>',
    "low":      '<span class="badge badge-low">DÜŞÜK</span>',
}


def _badge(sev: str) -> str:
    return SEVERITY_BADGE.get(sev.lower(), f'<span class="badge badge-low">{html.escape(sev)}</span>')


def _e(val: Any) -> str:
    """HTML kaçış + str dönüşümü."""
    return html.escape(str(val))


# ---------------------------------------------------------------------------
# Tablo oluşturucular
# ---------------------------------------------------------------------------

def _table(headers: List[str], rows: List[List[str]], table_id: str = "") -> str:
    id_attr = f' id="{table_id}"' if table_id else ""
    th = "".join(f"<th>{_e(h)}</th>" for h in headers)
    trs = ""
    for row in rows:
        tds = "".join(f"<td>{cell}</td>" for cell in row)
        trs += f"<tr>{tds}</tr>\n"
    return f"""
<div class="table-wrapper">
<table{id_attr}>
  <thead><tr>{th}</tr></thead>
  <tbody>{trs}</tbody>
</table>
</div>"""


def _brute_table(items: List[Dict[str, Any]]) -> str:
    if not items:
        return "<p class='empty'>Brute-force saldırısı tespit edilmedi.</p>"
    rows = [
        [
            _e(i.get("ip", "")),
            f"<strong>{_e(i.get('attempt_count', ''))}</strong>",
            _badge(i.get("severity", "")),
            _e(", ".join(i.get("unique_users_tried", []))),
            _e(i.get("window_start", "")[:19]),
            _e(i.get("window_end", "")[:19]),
            _e(i.get("description", "")),
        ]
        for i in items
    ]
    return _table(
        ["IP Adresi", "Deneme", "Şiddet", "Denenen Kullanıcılar", "Pencere Başlangıcı", "Pencere Bitişi", "Açıklama"],
        rows,
        "tbl-brute",
    )


def _privesc_table(items: List[Dict[str, Any]]) -> str:
    if not items:
        return "<p class='empty'>Yetki yükseltme girişimi tespit edilmedi.</p>"
    rows = [
        [
            _e(i.get("timestamp", "")[:19]),
            _e(i.get("user", "")),
            _badge(i.get("severity", "")),
            _e(i.get("event_type", "")),
            f"<code>{_e(i.get('command', i.get('command_line', '')))}</code>" if i.get("command") or i.get("command_line") else "",
            _e(i.get("description", "")),
        ]
        for i in items
    ]
    return _table(
        ["Zaman", "Kullanıcı", "Şiddet", "Olay Türü", "Komut", "Açıklama"],
        rows,
        "tbl-privesc",
    )


def _susptime_table(items: List[Dict[str, Any]]) -> str:
    if not items:
        return "<p class='empty'>Şüpheli saatte oturum tespit edilmedi.</p>"
    rows = [
        [
            _e(i.get("timestamp", "")[:19]),
            _e(i.get("user", "")),
            _e(i.get("ip", "")),
            _e(str(i.get("hour", ""))),
            _e(i.get("weekday", "")),
            _e(i.get("reason", "")),
        ]
        for i in items
    ]
    return _table(
        ["Zaman", "Kullanıcı", "IP / Bilgisayar", "Saat", "Gün", "Neden"],
        rows,
        "tbl-susptime",
    )


def _suspproc_table(items: List[Dict[str, Any]]) -> str:
    if not items:
        return "<p class='empty'>Şüpheli süreç tespit edilmedi.</p>"
    rows = [
        [
            _e(i.get("timestamp", "")[:19]),
            _e(i.get("user", "")),
            _e(i.get("computer", "")),
            _e(i.get("process", "")),
            f"<code>{_e(i.get('command_line', ''))}</code>",
        ]
        for i in items
    ]
    return _table(
        ["Zaman", "Kullanıcı", "Bilgisayar", "İşlem", "Komut Satırı"],
        rows,
        "tbl-suspproc",
    )


# ---------------------------------------------------------------------------
# CSS + JS
# ---------------------------------------------------------------------------

STYLE = """
:root {
  --bg: #0f1117;
  --surface: #1a1d2e;
  --surface2: #242740;
  --border: #2e3250;
  --text: #e2e8f0;
  --text-dim: #94a3b8;
  --red: #f87171;
  --orange: #fb923c;
  --yellow: #fbbf24;
  --green: #34d399;
  --blue: #60a5fa;
  --purple: #a78bfa;
  --cyan: #22d3ee;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: 'Segoe UI', system-ui, sans-serif; background: var(--bg);
       color: var(--text); padding: 24px; }
h1 { font-size: 1.8rem; color: var(--cyan); margin-bottom: 4px; }
.subtitle { color: var(--text-dim); margin-bottom: 24px; font-size: .9rem; }
/* Summary cards */
.cards { display: flex; flex-wrap: wrap; gap: 16px; margin-bottom: 32px; }
.card { background: var(--surface); border: 1px solid var(--border);
        border-radius: 10px; padding: 18px 24px; min-width: 160px; flex: 1; }
.card .label { font-size: .78rem; color: var(--text-dim); text-transform: uppercase;
               letter-spacing: .06em; }
.card .value { font-size: 2rem; font-weight: 700; margin-top: 4px; }
.card.critical .value { color: var(--red); }
.card.high     .value { color: var(--orange); }
.card.medium   .value { color: var(--yellow); }
.card.safe     .value { color: var(--green); }
.card.info     .value { color: var(--blue); }
/* Sections */
.section { margin-bottom: 32px; }
.section-header { display: flex; align-items: center; gap: 10px; margin-bottom: 12px;
                  border-bottom: 1px solid var(--border); padding-bottom: 8px; }
.section-header h2 { font-size: 1.1rem; }
.count-badge { background: var(--surface2); border-radius: 20px; padding: 2px 10px;
               font-size: .78rem; color: var(--text-dim); }
/* Table */
.table-wrapper { overflow-x: auto; }
table { width: 100%; border-collapse: collapse; font-size: .85rem; }
thead { background: var(--surface2); }
th, td { padding: 10px 14px; text-align: left; border-bottom: 1px solid var(--border); }
th { font-size: .78rem; text-transform: uppercase; letter-spacing: .05em;
     color: var(--text-dim); white-space: nowrap; }
tr:hover td { background: var(--surface2); }
code { background: #0d1117; padding: 2px 6px; border-radius: 4px;
       font-family: 'Cascadia Code', monospace; font-size: .82rem;
       color: var(--cyan); word-break: break-all; }
/* Badges */
.badge { display: inline-block; padding: 2px 8px; border-radius: 4px;
         font-size: .72rem; font-weight: 700; letter-spacing: .05em; }
.badge-critical { background: rgba(248,113,113,.2); color: var(--red); border: 1px solid var(--red); }
.badge-high     { background: rgba(251,146,60,.15); color: var(--orange); border: 1px solid var(--orange); }
.badge-medium   { background: rgba(251,191,36,.12); color: var(--yellow); border: 1px solid var(--yellow); }
.badge-low      { background: rgba(52,211,153,.12); color: var(--green); border: 1px solid var(--green); }
.empty { color: var(--green); padding: 12px 0; font-style: italic; }
/* Collapsible */
details summary { cursor: pointer; list-style: none; }
details summary::-webkit-details-marker { display: none; }
/* Search box */
.search-box { width: 100%; max-width: 400px; padding: 8px 14px;
              background: var(--surface2); border: 1px solid var(--border);
              border-radius: 8px; color: var(--text); font-size: .9rem;
              margin-bottom: 16px; }
.search-box:focus { outline: none; border-color: var(--cyan); }
/* Nav */
nav { display: flex; gap: 12px; margin-bottom: 28px; flex-wrap: wrap; }
nav a { color: var(--blue); text-decoration: none; font-size: .85rem;
        background: var(--surface); padding: 6px 14px; border-radius: 6px;
        border: 1px solid var(--border); }
nav a:hover { border-color: var(--blue); }
/* Footer */
footer { margin-top: 48px; color: var(--text-dim); font-size: .78rem;
         border-top: 1px solid var(--border); padding-top: 16px; }
"""

SCRIPT = """
function filterTable(inputId, tableId) {
  const input = document.getElementById(inputId);
  const table = document.getElementById(tableId);
  if (!table) return;
  input.addEventListener('keyup', () => {
    const q = input.value.toLowerCase();
    const rows = table.querySelectorAll('tbody tr');
    rows.forEach(r => {
      r.style.display = r.textContent.toLowerCase().includes(q) ? '' : 'none';
    });
  });
}
filterTable('search-brute',    'tbl-brute');
filterTable('search-privesc',  'tbl-privesc');
filterTable('search-susptime', 'tbl-susptime');
filterTable('search-suspproc', 'tbl-suspproc');

// Smooth scroll for nav links
document.querySelectorAll('nav a').forEach(a => {
  a.addEventListener('click', e => {
    e.preventDefault();
    const target = document.querySelector(a.getAttribute('href'));
    if (target) target.scrollIntoView({ behavior: 'smooth' });
  });
});
"""


# ---------------------------------------------------------------------------
# Ana şablon
# ---------------------------------------------------------------------------

def generate(
    result: Dict[str, Any],
    output_path: Optional[str] = None,
    source_file: str = "",
) -> str:
    """
    Analiz sonucunu tek dosya HTML belgesi olarak üretir.

    Parameters
    ----------
    result      : LogAnalyzer.analyze() çıktısı.
    output_path : Dosyaya yazılacaksa yol.
    source_file : Raporlanan log dosyasının adı (başlık için).
    """
    summary = result.get("summary", {})
    sev = summary.get("severity_breakdown", {})
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Özet kartları
    cards_html = f"""
<div class="cards">
  <div class="card info">
    <div class="label">Toplam Olay</div>
    <div class="value">{summary.get('total_events', 0)}</div>
  </div>
  <div class="card {'critical' if summary.get('total_anomalies', 0) > 0 else 'safe'}">
    <div class="label">Toplam Anomali</div>
    <div class="value">{summary.get('total_anomalies', 0)}</div>
  </div>
  <div class="card {'critical' if sev.get('critical', 0) > 0 else 'safe'}">
    <div class="label">Kritik</div>
    <div class="value">{sev.get('critical', 0)}</div>
  </div>
  <div class="card {'high' if sev.get('high', 0) > 0 else 'safe'}">
    <div class="label">Yüksek</div>
    <div class="value">{sev.get('high', 0)}</div>
  </div>
  <div class="card {'medium' if sev.get('medium', 0) > 0 else 'safe'}">
    <div class="label">Orta</div>
    <div class="value">{sev.get('medium', 0)}</div>
  </div>
  <div class="card safe">
    <div class="label">Düşük</div>
    <div class="value">{sev.get('low', 0)}</div>
  </div>
</div>"""

    bf_count = summary.get("brute_force_count", 0)
    pe_count = summary.get("privilege_escalation_count", 0)
    st_count = summary.get("suspicious_time_logon_count", 0)
    sp_count = summary.get("suspicious_process_count", 0)

    source_label = f" — {_e(source_file)}" if source_file else ""

    doc = f"""<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Log Analiz Raporu{source_label}</title>
<style>{STYLE}</style>
</head>
<body>
<h1>🛡️ Log Analiz Raporu{source_label}</h1>
<p class="subtitle">Oluşturulma zamanı: {now} &nbsp;|&nbsp; Analiz zamanı: {_e(summary.get('analysis_time', ''))}</p>

<nav>
  <a href="#sec-brute">🔴 Brute-Force ({bf_count})</a>
  <a href="#sec-privesc">🟠 Yetki Yükseltme ({pe_count})</a>
  <a href="#sec-susptime">🟡 Şüpheli Oturum ({st_count})</a>
  <a href="#sec-suspproc">🔵 Şüpheli Süreç ({sp_count})</a>
</nav>

{cards_html}

<!-- BRUTE FORCE -->
<div class="section" id="sec-brute">
  <div class="section-header">
    <h2>🔴 Brute-Force Saldırıları</h2>
    <span class="count-badge">{bf_count} kayıt</span>
  </div>
  <input class="search-box" id="search-brute" placeholder="Filtrele…">
  {_brute_table(result.get('brute_force', []))}
</div>

<!-- PRİVESC -->
<div class="section" id="sec-privesc">
  <div class="section-header">
    <h2>🟠 Yetki Yükseltme Girişimleri</h2>
    <span class="count-badge">{pe_count} kayıt</span>
  </div>
  <input class="search-box" id="search-privesc" placeholder="Filtrele…">
  {_privesc_table(result.get('privilege_escalation', []))}
</div>

<!-- SUSPICIOUS TIME -->
<div class="section" id="sec-susptime">
  <div class="section-header">
    <h2>🟡 Şüpheli Saatlerdeki Oturumlar</h2>
    <span class="count-badge">{st_count} kayıt</span>
  </div>
  <input class="search-box" id="search-susptime" placeholder="Filtrele…">
  {_susptime_table(result.get('suspicious_time_logons', []))}
</div>

<!-- SUSPICIOUS PROCESS -->
<div class="section" id="sec-suspproc">
  <div class="section-header">
    <h2>🔵 Şüpheli Süreçler (Sysmon/Windows)</h2>
    <span class="count-badge">{sp_count} kayıt</span>
  </div>
  <input class="search-box" id="search-suspproc" placeholder="Filtrele…">
  {_suspproc_table(result.get('suspicious_processes', []))}
</div>

<footer>
  Log Analyzer — Otomatik güvenlik raporu. Bu rapor doğrulama gerektiren bulgular içerebilir.
</footer>

<script>{SCRIPT}</script>
</body>
</html>"""

    if output_path:
        with open(output_path, "w", encoding="utf-8") as fh:
            fh.write(doc)
        print(f"[✓] HTML raporu yazıldı: {output_path}")

    return doc
