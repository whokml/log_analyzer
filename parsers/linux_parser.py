"""
Linux auth.log / syslog parser
Desteklenen dosyalar: /var/log/auth.log, /var/log/secure
"""

import re
from datetime import datetime
from typing import List, Dict, Any, Optional


# --- Regex kalıpları ---
PATTERNS = {
    # SSH başarısız giriş: şifre yanlış
    "ssh_failed_password": re.compile(
        r"(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+sshd\[\d+\]:\s+"
        r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.a-fA-F:]+) port \d+"
    ),
    # SSH geçersiz kullanıcı
    "ssh_invalid_user": re.compile(
        r"(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+sshd\[\d+\]:\s+"
        r"Invalid user (?P<user>\S+) from (?P<ip>[\d.a-fA-F:]+)"
    ),
    # SSH başarılı giriş
    "ssh_success": re.compile(
        r"(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+sshd\[\d+\]:\s+"
        r"Accepted (?:password|publickey|keyboard-interactive) for (?P<user>\S+) from (?P<ip>[\d.a-fA-F:]+)"
    ),
    # SSH maksimum deneme aşımı (MaxAuthTries)
    "ssh_maxauth": re.compile(
        r"(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+sshd\[\d+\]:\s+"
        r"error: maximum authentication attempts exceeded for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.a-fA-F:]+)"
    ),
    # sudo: yetki yükseltme — başarılı
    "sudo_success": re.compile(
        r"(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+sudo(?:\[\d+\])?:\s+"
        r"(?P<user>\S+)\s*:.*COMMAND=(?P<command>.+)"
    ),
    # sudo: yetki yükseltme — başarısız
    "sudo_failed": re.compile(
        r"(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+sudo(?:\[\d+\])?:\s+"
        r"(?P<user>\S+)\s*:.*authentication failure"
    ),
    # su: kullanıcı değiştirme
    "su_session": re.compile(
        r"(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+su(?:\[\d+\])?:\s+"
        r"(?:Successful|FAILED) su for (?P<user>\S+) by (?P<by_user>\S+)"
    ),
    # PAM oturum açma/kapama
    "pam_session": re.compile(
        r"(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+\S+\s+"
        r"pam_unix\(\S+\): session (?P<action>opened|closed) for user (?P<user>\S+)"
    ),
    # Bağlantı kesilmesi (brute-force sonrası disconnect)
    "ssh_disconnect": re.compile(
        r"(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+sshd\[\d+\]:\s+"
        r"Disconnected from (?:invalid user )?(?P<user>\S+)? ?(?P<ip>[\d.a-fA-F:]+) port \d+"
    ),
}

MONTH_MAP = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4,
    "May": 5, "Jun": 6, "Jul": 7, "Aug": 8,
    "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}


def _parse_timestamp(month: str, day: str, time_str: str, year: Optional[int] = None) -> Optional[datetime]:
    """Syslog formatı zaman damgasını datetime nesnesine çevirir."""
    if year is None:
        year = datetime.now().year
    try:
        m = MONTH_MAP.get(month, 0)
        if m == 0:
            return None
        h, mi, s = map(int, time_str.split(":"))
        return datetime(year, m, int(day), h, mi, s)
    except (ValueError, TypeError):
        return None


def parse_auth_log(
    filepath: str,
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    year: Optional[int] = None,
) -> List[Dict[str, Any]]:
    """
    auth.log dosyasını ayrıştırır ve olayların listesini döndürür.

    Parameters
    ----------
    filepath   : Log dosyasının yolu.
    start_time : Filtrelenecek başlangıç zamanı (dahil).
    end_time   : Filtrelenecek bitiş zamanı (dahil).
    year       : Log yılı (varsayılan: geçerli yıl).

    Returns
    -------
    Her satır için bir dict içeren liste.
    """
    events: List[Dict[str, Any]] = []

    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as fh:
            for lineno, line in enumerate(fh, 1):
                line = line.rstrip()
                for event_type, pattern in PATTERNS.items():
                    m = pattern.search(line)
                    if not m:
                        continue
                    gd = m.groupdict()
                    ts = _parse_timestamp(
                        gd.get("month", ""), gd.get("day", ""), gd.get("time", ""), year
                    )
                    if ts is None:
                        continue
                    if start_time and ts < start_time:
                        continue
                    if end_time and ts > end_time:
                        continue

                    event: Dict[str, Any] = {
                        "lineno": lineno,
                        "event_type": event_type,
                        "timestamp": ts.isoformat(),
                        "host": gd.get("host", ""),
                        "user": gd.get("user", ""),
                        "ip": gd.get("ip", ""),
                        "raw": line,
                    }
                    # Ek alanlar
                    if "command" in gd:
                        event["command"] = gd["command"].strip()
                    if "action" in gd:
                        event["action"] = gd["action"]
                    if "by_user" in gd:
                        event["by_user"] = gd["by_user"]

                    events.append(event)
                    break  # Bir satır yalnızca bir kalıba uyar

    except FileNotFoundError:
        raise FileNotFoundError(f"Log dosyası bulunamadı: {filepath}")
    except PermissionError:
        raise PermissionError(f"Log dosyasına erişim izni yok: {filepath}")

    return events
