"""
Windows Event Log / Sysmon parser
Desteklenen kaynaklar:
  - XML formatında dışa aktarılmış .evtx dosyaları (python-evtx kütüphanesi)
  - Sysmon CSV / JSON çıktıları
  - Düz metin Windows Security log çıktısı (Get-WinEvent | Export-Csv)
"""

import re
import csv
import json
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import List, Dict, Any, Optional


# Windows Güvenlik Olay ID'leri
EVENT_IDS = {
    4624: "logon_success",           # Başarılı oturum açma
    4625: "logon_failure",           # Başarısız oturum açma
    4648: "explicit_credentials",    # Açık kimlik bilgileriyle oturum açma girişimi
    4672: "special_privileges",      # Özel ayrıcalıklar atandı (yetki yükseltme)
    4688: "process_creation",        # Yeni işlem oluşturuldu (Sysmon / audit)
    4697: "service_install",         # Servis kurulumu
    4720: "account_created",         # Kullanıcı hesabı oluşturuldu
    4728: "group_member_added",      # Güvenlik grubuna üye eklendi
    4732: "local_group_member",      # Yerel gruba üye eklendi
    4756: "universal_group_member",  # Evrensel gruba üye eklendi
    4768: "kerberos_tgt",            # Kerberos TGT isteği
    4769: "kerberos_service",        # Kerberos servis bileti isteği
    4776: "ntlm_auth",               # NTLM kimlik doğrulama
    4798: "user_enum",               # Kullanıcı yerel grup üyeliği numaralandırma
    4799: "group_enum",              # Yerel güvenlik grubu numaralandırma
    7045: "new_service",             # SCM: Yeni servis kuruldu
    # Sysmon Olay ID'leri
    1:   "sysmon_process_create",
    3:   "sysmon_network_connect",
    7:   "sysmon_image_load",
    8:   "sysmon_create_remote_thread",
    11:  "sysmon_file_create",
    12:  "sysmon_registry_event",
    13:  "sysmon_registry_value_set",
    22:  "sysmon_dns_query",
}

# Oturum açma türleri (LogonType)
LOGON_TYPES = {
    "2": "Interactive",
    "3": "Network",
    "4": "Batch",
    "5": "Service",
    "7": "Unlock",
    "8": "NetworkCleartext",
    "9": "NewCredentials",
    "10": "RemoteInteractive (RDP)",
    "11": "CachedInteractive",
}

# Şüpheli komutlar / araçlar (process creation olaylarında)
SUSPICIOUS_COMMANDS = re.compile(
    r"(mimikatz|meterpreter|powersploit|cobalt|empire|bloodhound|sharphound|"
    r"psexec|wmic|net\.exe|net1\.exe|nltest|certutil|bitsadmin|"
    r"regsvr32|mshta|cscript|wscript|rundll32|installutil|"
    r"base64|encodedcommand|-enc\b|bypass|downloadstring|iex\s*\(|"
    r"invoke-expression|invoke-mimikatz|add-member|reflection\.assembly)",
    re.IGNORECASE,
)

NS = "http://schemas.microsoft.com/win/2004/08/events/event"


# ---------------------------------------------------------------------------
# XML (dışa aktarılmış .evtx → XML) ayrıştırıcı
# ---------------------------------------------------------------------------

def _parse_xml_event(elem: ET.Element) -> Optional[Dict[str, Any]]:
    """Tek bir <Event> XML öğesini dict'e dönüştürür."""
    try:
        system = elem.find(f"{{{NS}}}System")
        if system is None:
            return None

        event_id_el = system.find(f"{{{NS}}}EventID")
        event_id = int(event_id_el.text) if event_id_el is not None and event_id_el.text else 0

        time_created = system.find(f"{{{NS}}}TimeCreated")
        ts_str = time_created.get("SystemTime", "") if time_created is not None else ""
        try:
            ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00")) if ts_str else None
        except ValueError:
            ts = None

        computer_el = system.find(f"{{{NS}}}Computer")
        computer = computer_el.text if computer_el is not None else ""

        channel_el = system.find(f"{{{NS}}}Channel")
        channel = channel_el.text if channel_el is not None else ""

        # EventData alanlarını topla
        event_data: Dict[str, str] = {}
        event_data_el = elem.find(f"{{{NS}}}EventData")
        if event_data_el is not None:
            for data in event_data_el.findall(f"{{{NS}}}Data"):
                name = data.get("Name", "")
                value = data.text or ""
                if name:
                    event_data[name] = value

        event_type = EVENT_IDS.get(event_id, f"event_{event_id}")

        result: Dict[str, Any] = {
            "event_type": event_type,
            "event_id": event_id,
            "timestamp": ts.isoformat() if ts else "",
            "computer": computer,
            "channel": channel,
            "user": event_data.get("TargetUserName", event_data.get("SubjectUserName", "")),
            "domain": event_data.get("TargetDomainName", event_data.get("SubjectDomainName", "")),
            "ip": event_data.get("IpAddress", event_data.get("WorkstationName", "")),
            "logon_type": LOGON_TYPES.get(event_data.get("LogonType", ""), event_data.get("LogonType", "")),
            "process": event_data.get("NewProcessName", event_data.get("Image", "")),
            "command_line": event_data.get("CommandLine", ""),
            "raw_data": event_data,
        }

        # Şüpheli komut işareti
        combined = f"{result['process']} {result['command_line']}"
        result["suspicious"] = bool(SUSPICIOUS_COMMANDS.search(combined))

        return result
    except Exception:
        return None


def parse_evtx_xml(
    filepath: str,
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    event_id_filter: Optional[List[int]] = None,
) -> List[Dict[str, Any]]:
    """
    XML formatında dışa aktarılmış Windows Event Log dosyasını ayrıştırır.
    (Get-WinEvent ... | Export-Clixml veya wevtutil ile üretilen XML)

    Parameters
    ----------
    filepath        : XML dosyasının yolu.
    start_time      : Filtrelenecek başlangıç zamanı.
    end_time        : Filtrelenecek bitiş zamanı.
    event_id_filter : Yalnızca bu EventID'leri dahil et (None → hepsi).
    """
    events: List[Dict[str, Any]] = []

    try:
        tree = ET.parse(filepath)
        root = tree.getroot()
    except ET.ParseError as exc:
        raise ValueError(f"XML ayrıştırma hatası: {exc}")
    except FileNotFoundError:
        raise FileNotFoundError(f"Dosya bulunamadı: {filepath}")

    # Kök hem doğrudan <Event> listesi hem de bir <Events> wrapper olabilir
    event_elements = (
        root.findall(f"{{{NS}}}Event")
        or root.findall("Event")
        or list(root)
    )

    for elem in event_elements:
        ev = _parse_xml_event(elem)
        if ev is None:
            continue
        if event_id_filter and ev["event_id"] not in event_id_filter:
            continue
        if ev["timestamp"]:
            try:
                ts = datetime.fromisoformat(ev["timestamp"])
                if start_time and ts < start_time:
                    continue
                if end_time and ts > end_time:
                    continue
            except ValueError:
                pass
        events.append(ev)

    return events


# ---------------------------------------------------------------------------
# CSV (Get-WinEvent | Select-Object | Export-Csv) ayrıştırıcı
# ---------------------------------------------------------------------------

def parse_winevent_csv(
    filepath: str,
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
) -> List[Dict[str, Any]]:
    """
    PowerShell Get-WinEvent çıktısının CSV formatını ayrıştırır.
    Beklenen sütunlar: TimeCreated, Id, LevelDisplayName, Message, MachineName, UserId
    """
    events: List[Dict[str, Any]] = []

    try:
        with open(filepath, newline="", encoding="utf-8-sig", errors="replace") as fh:
            reader = csv.DictReader(fh)
            for row in reader:
                raw_ts = row.get("TimeCreated", "")
                try:
                    ts = datetime.fromisoformat(raw_ts)
                except ValueError:
                    ts = None

                if ts:
                    if start_time and ts < start_time:
                        continue
                    if end_time and ts > end_time:
                        continue

                try:
                    event_id = int(row.get("Id", 0))
                except ValueError:
                    event_id = 0

                message = row.get("Message", "")
                event_type = EVENT_IDS.get(event_id, f"event_{event_id}")

                ev: Dict[str, Any] = {
                    "event_type": event_type,
                    "event_id": event_id,
                    "timestamp": ts.isoformat() if ts else raw_ts,
                    "computer": row.get("MachineName", ""),
                    "user": row.get("UserId", ""),
                    "ip": "",
                    "message": message,
                    "suspicious": bool(SUSPICIOUS_COMMANDS.search(message)),
                }
                events.append(ev)
    except FileNotFoundError:
        raise FileNotFoundError(f"Dosya bulunamadı: {filepath}")

    return events


# ---------------------------------------------------------------------------
# JSON (Sysmon / Windows Event Forwarder çıktısı) ayrıştırıcı
# ---------------------------------------------------------------------------

def parse_sysmon_json(
    filepath: str,
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
) -> List[Dict[str, Any]]:
    """
    Sysmon veya WEF JSON çıktısını ayrıştırır.
    Her satır bağımsız bir JSON nesnesi (NDJSON) veya tek bir JSON dizisi olabilir.
    """
    events: List[Dict[str, Any]] = []

    def _process_record(record: Dict[str, Any]) -> None:
        ts_raw = (
            record.get("@timestamp")
            or record.get("TimeCreated")
            or record.get("timestamp", "")
        )
        try:
            ts = datetime.fromisoformat(str(ts_raw).replace("Z", "+00:00"))
        except (ValueError, TypeError):
            ts = None

        if ts:
            if start_time and ts < start_time:
                return
            if end_time and ts > end_time:
                return

        try:
            event_id = int(record.get("EventID", record.get("event_id", 0)))
        except (ValueError, TypeError):
            event_id = 0

        image = record.get("Image", record.get("process", ""))
        cmd = record.get("CommandLine", record.get("command_line", ""))
        combined = f"{image} {cmd}"

        ev: Dict[str, Any] = {
            "event_type": EVENT_IDS.get(event_id, f"event_{event_id}"),
            "event_id": event_id,
            "timestamp": ts.isoformat() if ts else str(ts_raw),
            "computer": record.get("Computer", record.get("hostname", "")),
            "user": record.get("User", record.get("user", "")),
            "ip": record.get("DestinationIp", record.get("SourceIp", record.get("ip", ""))),
            "process": image,
            "command_line": cmd,
            "suspicious": bool(SUSPICIOUS_COMMANDS.search(combined)),
            "raw_data": record,
        }
        events.append(ev)

    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as fh:
            first_char = fh.read(1)
            fh.seek(0)
            if first_char == "[":
                # JSON dizisi
                data = json.load(fh)
                for record in data:
                    _process_record(record)
            else:
                # NDJSON (her satır ayrı JSON)
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        record = json.loads(line)
                        _process_record(record)
                    except json.JSONDecodeError:
                        continue
    except FileNotFoundError:
        raise FileNotFoundError(f"Dosya bulunamadı: {filepath}")

    return events
