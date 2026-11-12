"""
Anomali tespit motorları.
Ayrıştırılmış ham olayları alır, istatistik hesaplar ve anomali listesi üretir.
"""

from __future__ import annotations

import re
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Yardımcı fonksiyonlar
# ---------------------------------------------------------------------------

def _ts(event: Dict[str, Any]) -> Optional[datetime]:
    """Olay sözlüğünden datetime nesnesi üretir."""
    raw = event.get("timestamp", "")
    if not raw:
        return None
    try:
        return datetime.fromisoformat(raw)
    except ValueError:
        return None


def _hour(event: Dict[str, Any]) -> Optional[int]:
    dt = _ts(event)
    return dt.hour if dt else None


# ---------------------------------------------------------------------------
# Brute-Force Tespit
# ---------------------------------------------------------------------------

class BruteForceDetector:
    """
    Belirli bir zaman penceresi içinde aynı IP'den gelen başarısız
    giriş denemelerini sayar ve eşiği aşanları raporlar.
    """

    # Linux auth.log olay türleri
    LINUX_FAIL_TYPES = {"ssh_failed_password", "ssh_invalid_user", "ssh_maxauth"}
    # Windows EventID 4625 (başarısız oturum açma)
    WINDOWS_FAIL_TYPES = {"logon_failure"}

    def __init__(
        self,
        threshold: int = 5,
        window_seconds: int = 300,
    ) -> None:
        self.threshold = threshold
        self.window_seconds = window_seconds

    def analyze(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Brute-force saldırılarını tespit eder.

        Returns
        -------
        Her şüpheli IP/kullanıcı çifti için bir dict içeren liste.
        """
        fail_types = self.LINUX_FAIL_TYPES | self.WINDOWS_FAIL_TYPES

        # ip → [(timestamp, user), ...]
        attempts: Dict[str, List[Tuple[datetime, str]]] = defaultdict(list)

        for ev in events:
            if ev.get("event_type") not in fail_types:
                continue
            dt = _ts(ev)
            if dt is None:
                continue
            ip = ev.get("ip", "unknown")
            user = ev.get("user", "unknown")
            attempts[ip].append((dt, user))

        findings: List[Dict[str, Any]] = []

        for ip, records in attempts.items():
            records.sort(key=lambda x: x[0])
            # Kayan pencere
            window: List[Tuple[datetime, str]] = []
            for record in records:
                window.append(record)
                # Pencerenin dışına çıkan eski kayıtları temizle
                cutoff = record[0].timestamp() - self.window_seconds
                window = [r for r in window if r[0].timestamp() >= cutoff]

                if len(window) >= self.threshold:
                    users_in_window = list({r[1] for r in window})
                    findings.append({
                        "anomaly_type": "brute_force",
                        "severity": _brute_severity(len(window)),
                        "ip": ip,
                        "attempt_count": len(window),
                        "unique_users_tried": users_in_window,
                        "window_start": window[0][0].isoformat(),
                        "window_end": window[-1][0].isoformat(),
                        "description": (
                            f"{ip} adresinden {self.window_seconds}s içinde "
                            f"{len(window)} başarısız giriş denemesi tespit edildi."
                        ),
                    })
                    # Aynı pencereyi tekrar raporlamamak için listeyi sıfırla
                    window = []

        # IP başına en fazla sayıya göre sırala
        findings.sort(key=lambda x: x["attempt_count"], reverse=True)
        # Tekrarlayan IP girişlerini deduplicate et (en yüksek sayıyı tut)
        seen_ips: set = set()
        unique_findings = []
        for f in findings:
            if f["ip"] not in seen_ips:
                seen_ips.add(f["ip"])
                unique_findings.append(f)
        return unique_findings


def _brute_severity(count: int) -> str:
    if count >= 100:
        return "critical"
    if count >= 50:
        return "high"
    if count >= 20:
        return "medium"
    return "low"


# ---------------------------------------------------------------------------
# Yetki Yükseltme Tespit
# ---------------------------------------------------------------------------

PRIV_ESC_COMMANDS = re.compile(
    r"(sudo\s+-s|sudo\s+su|sudo\s+bash|sudo\s+sh|"
    r"chmod\s+[47][0-7][0-7]|chown\s+root|"
    r"visudo|usermod\s+-[aG].*sudo|"
    r"passwd\s+root|pkexec|setuid|"
    r"mimikatz|sekurlsa|lsadump|"
    r"getsystem|bypassuac|eventvwr|"
    r"fodhelper|cmstp|sdclt|"
    r"reg\s+add.*\\sam|reg\s+add.*\\security|"
    r"net\s+localgroup.*admin)",
    re.IGNORECASE,
)

PRIV_ESC_LINUX_TYPES = {"sudo_success", "sudo_failed", "su_session"}
PRIV_ESC_WIN_TYPES = {"special_privileges", "logon_success", "explicit_credentials"}
PRIV_ESC_WIN_IDS = {4672, 4648, 4697, 4720, 4728, 4732, 4756, 7045}


class PrivilegeEscalationDetector:
    """Yetki yükseltme girişimlerini ve başarılı yetki kazanımlarını tespit eder."""

    def analyze(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []

        for ev in events:
            etype = ev.get("event_type", "")
            eid = ev.get("event_id", 0)
            cmd = ev.get("command", ev.get("command_line", ""))
            user = ev.get("user", "")
            ts = ev.get("timestamp", "")

            # Linux sudo/su olayları
            if etype in PRIV_ESC_LINUX_TYPES:
                severity = "medium"
                desc = f"{user} kullanıcısı tarafından {etype} olayı."
                if etype == "sudo_failed":
                    severity = "high"
                    desc = f"{user} kullanıcısının sudo yetkisi başarısız oldu — olası brute-force."
                if cmd and PRIV_ESC_COMMANDS.search(cmd):
                    severity = "critical"
                    desc = f"Şüpheli komut ile yetki yükseltme: `{cmd}`"
                findings.append({
                    "anomaly_type": "privilege_escalation",
                    "severity": severity,
                    "timestamp": ts,
                    "user": user,
                    "command": cmd,
                    "event_type": etype,
                    "description": desc,
                })

            # Windows yetki yükseltme
            elif eid in PRIV_ESC_WIN_IDS or etype in PRIV_ESC_WIN_TYPES:
                cmd_line = ev.get("command_line", "")
                suspicious = ev.get("suspicious", False) or bool(
                    PRIV_ESC_COMMANDS.search(cmd_line)
                )
                severity = "critical" if suspicious else "medium"
                desc = (
                    f"Windows EventID {eid}: {user} için {etype}. "
                    + (f"Şüpheli komut: `{cmd_line}`" if suspicious else "")
                )
                findings.append({
                    "anomaly_type": "privilege_escalation",
                    "severity": severity,
                    "timestamp": ts,
                    "user": user,
                    "computer": ev.get("computer", ""),
                    "event_id": eid,
                    "event_type": etype,
                    "command_line": cmd_line,
                    "description": desc,
                })

        return findings


# ---------------------------------------------------------------------------
# Şüpheli Saat Tespit
# ---------------------------------------------------------------------------

class SuspiciousTimeDetector:
    """
    Mesai saatleri dışındaki (gece/hafta sonu) oturum açma olaylarını tespit eder.
    """

    LOGON_SUCCESS_TYPES = {"ssh_success", "logon_success", "pam_session"}
    LOGON_SUCCESS_IDS = {4624}

    def __init__(
        self,
        business_hours: Tuple[int, int] = (8, 18),   # 08:00-18:00
        suspicious_hours: Tuple[int, int] = (0, 6),   # 00:00-06:00
        check_weekends: bool = True,
    ) -> None:
        self.business_start, self.business_end = business_hours
        self.susp_start, self.susp_end = suspicious_hours
        self.check_weekends = check_weekends

    def _is_suspicious_time(self, dt: datetime) -> Tuple[bool, str]:
        hour = dt.hour
        weekday = dt.weekday()  # 0=Pazartesi, 6=Pazar

        is_weekend = self.check_weekends and weekday >= 5
        is_night = self.susp_start <= hour < self.susp_end
        is_outside_business = not (self.business_start <= hour < self.business_end)

        if is_night and is_weekend:
            return True, "hafta sonu gece saati"
        if is_night:
            return True, "gece saati (00:00-06:00)"
        if is_weekend and is_outside_business:
            return True, "hafta sonu mesai dışı"
        if is_outside_business:
            return True, "mesai saati dışı"
        return False, ""

    def analyze(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []

        for ev in events:
            etype = ev.get("event_type", "")
            eid = ev.get("event_id", 0)
            action = ev.get("action", "")

            is_logon = (
                etype in self.LOGON_SUCCESS_TYPES
                or eid in self.LOGON_SUCCESS_IDS
                or (etype == "pam_session" and action == "opened")
            )
            if not is_logon:
                continue

            dt = _ts(ev)
            if dt is None:
                continue

            flagged, reason = self._is_suspicious_time(dt)
            if not flagged:
                continue

            user = ev.get("user", "")
            ip = ev.get("ip", ev.get("computer", ""))
            findings.append({
                "anomaly_type": "suspicious_time_logon",
                "severity": "medium",
                "timestamp": ev.get("timestamp", ""),
                "user": user,
                "ip": ip,
                "hour": dt.hour,
                "weekday": dt.strftime("%A"),
                "reason": reason,
                "description": (
                    f"{user} kullanıcısı {reason} ({dt.strftime('%Y-%m-%d %H:%M:%S')}) "
                    f"saatinde {ip} adresinden oturum açtı."
                ),
            })

        return findings


# ---------------------------------------------------------------------------
# Şüpheli İşlem / Komut Tespit (Windows Sysmon)
# ---------------------------------------------------------------------------

class SuspiciousProcessDetector:
    """Sysmon process creation olaylarında şüpheli araç ve komutları tespit eder."""

    PROC_TYPES = {
        "sysmon_process_create", "process_creation",
        "event_4688", "event_1",
    }
    PROC_IDS = {4688, 1}

    def analyze(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []

        for ev in events:
            if ev.get("event_type") not in self.PROC_TYPES and ev.get("event_id") not in self.PROC_IDS:
                if not ev.get("suspicious"):
                    continue

            if not ev.get("suspicious", False):
                cmd = ev.get("command_line", ev.get("command", ""))
                proc = ev.get("process", "")
                if not (
                    PRIV_ESC_COMMANDS.search(cmd or "")
                    or PRIV_ESC_COMMANDS.search(proc or "")
                ):
                    continue

            findings.append({
                "anomaly_type": "suspicious_process",
                "severity": "high",
                "timestamp": ev.get("timestamp", ""),
                "user": ev.get("user", ""),
                "computer": ev.get("computer", ""),
                "process": ev.get("process", ""),
                "command_line": ev.get("command_line", ev.get("command", "")),
                "description": (
                    f"Şüpheli işlem tespit edildi: "
                    f"`{ev.get('process', '')}` — {ev.get('command_line', ev.get('command', ''))}"
                ),
            })

        return findings


# ---------------------------------------------------------------------------
# Ana analiz orkestratörü
# ---------------------------------------------------------------------------

class LogAnalyzer:
    """Tüm dedektörleri bir arada çalıştırır ve birleşik sonuç üretir."""

    def __init__(
        self,
        brute_threshold: int = 5,
        brute_window: int = 300,
        business_hours: Tuple[int, int] = (8, 18),
        suspicious_hours: Tuple[int, int] = (0, 6),
        check_weekends: bool = True,
    ) -> None:
        self.brute = BruteForceDetector(brute_threshold, brute_window)
        self.privesc = PrivilegeEscalationDetector()
        self.susptime = SuspiciousTimeDetector(
            business_hours, suspicious_hours, check_weekends
        )
        self.suspproc = SuspiciousProcessDetector()

    def analyze(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Tüm anomali detektörlerini çalıştırır.

        Returns
        -------
        {
          "summary": {...},
          "brute_force": [...],
          "privilege_escalation": [...],
          "suspicious_time_logons": [...],
          "suspicious_processes": [...],
          "all_anomalies": [...]   # birleşik, zamana göre sıralı
        }
        """
        brute = self.brute.analyze(events)
        privesc = self.privesc.analyze(events)
        susptime = self.susptime.analyze(events)
        suspproc = self.suspproc.analyze(events)

        all_anomalies = brute + privesc + susptime + suspproc
        # Zaman damgasına göre sırala
        all_anomalies.sort(key=lambda x: x.get("timestamp", ""))

        severity_counts: Dict[str, int] = defaultdict(int)
        for a in all_anomalies:
            severity_counts[a.get("severity", "unknown")] += 1

        summary = {
            "total_events": len(events),
            "total_anomalies": len(all_anomalies),
            "brute_force_count": len(brute),
            "privilege_escalation_count": len(privesc),
            "suspicious_time_logon_count": len(susptime),
            "suspicious_process_count": len(suspproc),
            "severity_breakdown": dict(severity_counts),
            "analysis_time": datetime.now(timezone.utc).isoformat(),
        }

        return {
            "summary": summary,
            "brute_force": brute,
            "privilege_escalation": privesc,
            "suspicious_time_logons": susptime,
            "suspicious_processes": suspproc,
            "all_anomalies": all_anomalies,
        }
