import os
import sys
import subprocess
import time
import json
import hashlib
import ctypes
from datetime import datetime
from pathlib import Path

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QTabWidget, QTableWidget, QTableWidgetItem, QTextEdit, QPushButton,
    QLabel, QFrame, QFileDialog, QMessageBox, QHeaderView,
    QScrollArea, QGroupBox, QSplashScreen, QAbstractItemView, QStatusBar
)
from PyQt6.QtCore import (
    Qt, QTimer, QThread, pyqtSignal, QObject, QPropertyAnimation,
    QEasingCurve, pyqtProperty, QRect
)
from PyQt6.QtGui import (
    QFont, QColor, QPainter, QBrush, QLinearGradient, QPen,
    QPixmap, QRadialGradient
)

HIGH_RISK_EXT = {
    '.exe', '.dll', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.jar',
    '.msi', '.scr', '.pif', '.com', '.reg', '.hta', '.wsf', '.lnk',
    '.sys', '.drv'
}
SENSITIVE_EXT = {
    '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
    '.kdbx', '.key', '.pem', '.pfx', '.p12', '.cert', '.crt',
    '.sql', '.db', '.sqlite', '.mdb', '.accdb', '.bak',
    '.zip', '.rar', '.7z', '.tar', '.gz', '.env', '.config'
}
SYSTEM_DIRS = [
    Path.home() / "Desktop",
    Path.home() / "Downloads",
    Path.home() / "Documents",
    Path.home() / "Pictures",
]

DARK = {
    "bg": "#0a0a0f", "surface": "#111118", "surface2": "#18181f",
    "surface3": "#1e1e28", "border": "#2a2a3a",
    "accent": "#c0392b", "accent_dim": "#7a1515", "accent_bright": "#e74c3c",
    "text": "#e8e8f0", "text_dim": "#8888aa", "text_muted": "#3a3a5a",
    "green": "#27ae60", "yellow": "#f39c12", "red": "#e74c3c", "blue": "#2980b9",
    "log_bg": "#06060c", "log_text": "#bb8888",
    "success": "#2ecc71", "warning": "#f1c40f", "error": "#e74c3c", "info": "#3498db",
}
LIGHT = {
    "bg": "#f2f2f7", "surface": "#ffffff", "surface2": "#f0f0f6",
    "surface3": "#e6e6ef", "border": "#d0d0e0",
    "accent": "#c0392b", "accent_dim": "#8b1a1a", "accent_bright": "#e74c3c",
    "text": "#1a1a2e", "text_dim": "#555577", "text_muted": "#9999bb",
    "green": "#1e8449", "yellow": "#b7770d", "red": "#c0392b", "blue": "#1a5276",
    "log_bg": "#140808", "log_text": "#ffaaaa",
    "success": "#27ae60", "warning": "#e67e22", "error": "#c0392b", "info": "#2471a3",
}


def _ps(script: str) -> str:
    try:
        flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
        r = subprocess.run(
            ["powershell", "-NonInteractive", "-NoProfile",
             "-ExecutionPolicy", "Bypass", "-Command", script],
            capture_output=True, text=True, timeout=15, creationflags=flags
        )
        return r.stdout.strip()
    except Exception:
        return ""


def query_all_usb_devices() -> list:
    """
    Uses Win32_USBControllerDevice to walk every USB device connected to the
    system. This catches ALL modes: storage, MTP, PTP, MIDI, tethering, HID,
    audio, no-data-transfer (charging only), etc.
    """
    script = r"""
$seen = @{}
$results = @()
try {
    Get-WmiObject Win32_USBControllerDevice -ErrorAction Stop | ForEach-Object {
        try {
            $dep = [wmi]$_.Dependent
            $id = $dep.DeviceID
            if (-not $seen.ContainsKey($id) -and $dep.Name -ne $null) {
                $seen[$id] = $true

                $vidStr = "N/A"
                $pidStr = "N/A"
                if ($id -match "VID_([0-9A-Fa-f]{4})") { $vidStr = $matches[1].ToUpper() }
                if ($id -match "PID_([0-9A-Fa-f]{4})") { $pidStr = $matches[1].ToUpper() }

                $mfr = if ($dep.Manufacturer) { $dep.Manufacturer } else { "Unknown" }
                $desc = if ($dep.Description) { $dep.Description } else { $dep.Name }
                $cls  = if ($dep.PNPClass)     { $dep.PNPClass }     else { "USB" }
                $stat = if ($dep.Status)       { $dep.Status }       else { "Unknown" }

                $svcMode = "Unknown"
                if ($id -like "USB\VID*") {
                    if ($cls -eq "WPD")                     { $svcMode = "MTP / PTP" }
                    elseif ($cls -eq "DiskDrive" -or $cls -eq "USBSTOR") { $svcMode = "Mass Storage" }
                    elseif ($cls -eq "Ports" -or $desc -like "*COM*") { $svcMode = "USB Tethering / COM" }
                    elseif ($cls -eq "HIDClass" -or $cls -eq "HID") { $svcMode = "HID (Input Device)" }
                    elseif ($cls -eq "AudioEndpoint" -or $cls -eq "Media") { $svcMode = "Audio / MIDI" }
                    elseif ($cls -eq "Net" -or $desc -like "*RNDIS*" -or $desc -like "*tether*") { $svcMode = "USB Tethering (RNDIS)" }
                    elseif ($cls -eq "USB" -and $dep.Service -eq $null) { $svcMode = "No Data Transfer (Power)" }
                    else { $svcMode = $cls }
                }

                $results += [PSCustomObject]@{
                    Name         = $dep.Name
                    DeviceID     = $id
                    VID          = $vidStr
                    PID          = $pidStr
                    Manufacturer = $mfr
                    Description  = $desc
                    Class        = $cls
                    Status       = $stat
                    Mode         = $svcMode
                }
            }
        } catch {}
    }
} catch {}
if ($results.Count -gt 0) {
    $results | ConvertTo-Json -Compress -Depth 3
}
"""
    raw = _ps(script)
    if not raw:
        return []
    try:
        data = json.loads(raw)
        if isinstance(data, dict):
            data = [data]
        out = []
        for d in data:
            name = (d.get("Name") or "").strip()
            did  = (d.get("DeviceID") or "").strip()
            if not name or not did:
                continue
            if name.lower() in ("root hub", "root hub 20", "root hub 30",
                                  "usb root hub", "usb root hub (usb 3.0)",
                                  "generic usb hub", "usb composite device"):
                continue
            out.append({
                "name":         name,
                "device_id":    did,
                "vid":          d.get("VID", "N/A"),
                "pid":          d.get("PID", "N/A"),
                "manufacturer": (d.get("Manufacturer") or "Unknown").strip(),
                "description":  (d.get("Description") or name).strip(),
                "pnp_class":    (d.get("Class") or "USB").strip(),
                "status":       (d.get("Status") or "Unknown").strip(),
                "mode":         (d.get("Mode") or "Unknown").strip(),
            })
        return out
    except Exception:
        return []


def get_drive_for_device(vid: str, pid: str) -> str:
    if vid == "N/A":
        return ""
    script = f"""
$result = ""
Get-WmiObject Win32_DiskDrive | Where-Object {{
    $_.PNPDeviceID -like "*VID_{vid}*" -or $_.PNPDeviceID -like "*VID_{vid.lower()}*"
}} | ForEach-Object {{
    $disk = $_
    Get-WmiObject -Query "ASSOCIATORS OF {{Win32_DiskDrive.DeviceID='$($disk.DeviceID)'}} WHERE AssocClass=Win32_DiskDriveToDiskPartition" |
    ForEach-Object {{
        Get-WmiObject -Query "ASSOCIATORS OF {{Win32_DiskPartition.DeviceID='$($_.DeviceID)'}} WHERE AssocClass=Win32_LogicalDiskToPartition" |
        ForEach-Object {{ $result = $_.DeviceID }}
    }}
}}
$result
"""
    return _ps(script).strip()


def get_disk_size(drive: str) -> str:
    if not drive:
        return ""
    script = (
        f"(Get-WmiObject Win32_LogicalDisk | "
        f"Where-Object {{$_.DeviceID -eq '{drive}'}}).Size"
    )
    raw = _ps(script).strip()
    try:
        return fmt_size(int(raw))
    except Exception:
        return ""


def fmt_size(n) -> str:
    try:
        n = int(n)
        for u in ["B", "KB", "MB", "GB", "TB"]:
            if n < 1024:
                return f"{n:.1f} {u}"
            n /= 1024
    except Exception:
        pass
    return ""


def file_risk(path: str) -> str:
    ext = Path(path).suffix.lower()
    if ext in HIGH_RISK_EXT:
        return "HIGH RISK"
    if ext in SENSITIVE_EXT:
        return "SENSITIVE"
    return "NORMAL"


def fast_hash(path: str) -> str:
    try:
        h = hashlib.md5()
        with open(path, "rb") as f:
            h.update(f.read(65536))
        return h.hexdigest()
    except Exception:
        return ""


def snap_dir(base: str) -> dict:
    result = {}
    try:
        for root, _, files in os.walk(base):
            for fname in files:
                p = os.path.join(root, fname)
                try:
                    s = os.stat(p)
                    result[p] = {
                        "size":  s.st_size,
                        "mtime": s.st_mtime,
                        "hash":  fast_hash(p) if s.st_size < 64 * 1024 * 1024 else None,
                    }
                except Exception:
                    pass
    except Exception:
        pass
    return result


def snap_system() -> dict:
    snap = {}
    for d in SYSTEM_DIRS:
        if d.exists():
            snap.update(snap_dir(str(d)))
    return snap


class ToggleSwitch(QWidget):
    toggled = pyqtSignal(bool)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedSize(52, 26)
        self._checked = False
        self._x = 3
        self._anim = QPropertyAnimation(self, b"handle_x", self)
        self._anim.setDuration(180)
        self._anim.setEasingCurve(QEasingCurve.Type.InOutCubic)

    def get_x(self): return self._x
    def set_x(self, v):
        self._x = v
        self.update()
    handle_x = pyqtProperty(int, get_x, set_x)

    def isChecked(self): return self._checked

    def set_checked(self, v: bool):
        self._checked = v
        self._x = 28 if v else 3
        self.update()

    def mousePressEvent(self, e):
        self._checked = not self._checked
        self._anim.setStartValue(self._x)
        self._anim.setEndValue(28 if self._checked else 3)
        self._anim.start()
        self.toggled.emit(self._checked)

    def paintEvent(self, e):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        p.setBrush(QBrush(QColor("#c0392b") if self._checked else QColor("#333355")))
        p.setPen(Qt.PenStyle.NoPen)
        p.drawRoundedRect(0, 3, 52, 20, 10, 10)
        p.setBrush(QBrush(QColor("#ffffff")))
        p.drawEllipse(self._x, 1, 24, 24)
        p.end()


class SplashScreen(QSplashScreen):
    def __init__(self):
        pm = QPixmap(660, 370)
        pm.fill(QColor("#0a0a0f"))
        super().__init__(pm, Qt.WindowType.WindowStaysOnTopHint)
        self._pct = 0
        self._stage = "Initializing..."

    def set_progress(self, pct: int, stage: str):
        self._pct = pct
        self._stage = stage
        self.repaint()
        QApplication.processEvents()

    def drawContents(self, p: QPainter):
        w, h = self.width(), self.height()
        bg = QLinearGradient(0, 0, w, h)
        bg.setColorAt(0.0, QColor("#0a0a0f"))
        bg.setColorAt(1.0, QColor("#190404"))
        p.fillRect(0, 0, w, h, bg)

        p.setPen(QPen(QColor("#1c1c26"), 1))
        for i in range(0, w, 42):
            p.drawLine(i, 0, i, h)
        for i in range(0, h, 42):
            p.drawLine(0, i, w, i)

        glow = QRadialGradient(w / 2, h / 2, 260)
        glow.setColorAt(0.0, QColor(192, 57, 43, 35))
        glow.setColorAt(1.0, QColor(0, 0, 0, 0))
        p.fillRect(0, 0, w, h, glow)

        p.setPen(QPen(QColor("#c0392b"), 2))
        p.drawRect(1, 1, w - 2, h - 2)
        p.setPen(QPen(QColor("#4d0f0f"), 1))
        p.drawRect(6, 6, w - 12, h - 12)

        p.setFont(QFont("Consolas", 8))
        p.setPen(QColor("#8b1a1a"))
        p.drawText(22, 30, "ADVANCED ENDPOINT MONITORING FRAMEWORK  |  v3.0")

        p.setFont(QFont("Segoe UI", 30, QFont.Weight.Thin))
        p.setPen(QColor("#e8e8f0"))
        p.drawText(QRect(0, 75, w, 55), Qt.AlignmentFlag.AlignHCenter, "Advanced")
        p.setFont(QFont("Segoe UI", 30, QFont.Weight.Bold))
        p.setPen(QColor("#c0392b"))
        p.drawText(QRect(0, 125, w, 55), Qt.AlignmentFlag.AlignHCenter, "Endpoint Monitor")

        p.setFont(QFont("Consolas", 8))
        p.setPen(QColor("#444466"))
        p.drawText(QRect(0, 192, w, 22), Qt.AlignmentFlag.AlignHCenter,
                   "ALL USB MODES  |  MTP / PTP / STORAGE / TETHERING / MIDI / HID / AUDIO")

        bx, by, bw, bh = 60, 270, w - 120, 5
        p.setBrush(QBrush(QColor("#1e1e28")))
        p.setPen(Qt.PenStyle.NoPen)
        p.drawRoundedRect(bx, by, bw, bh, 2, 2)
        fill = int(bw * self._pct / 100)
        if fill > 0:
            g2 = QLinearGradient(bx, 0, bx + bw, 0)
            g2.setColorAt(0.0, QColor("#8b1a1a"))
            g2.setColorAt(1.0, QColor("#e74c3c"))
            p.setBrush(QBrush(g2))
            p.drawRoundedRect(bx, by, fill, bh, 2, 2)

        p.setFont(QFont("Consolas", 9))
        p.setPen(QColor("#666688"))
        p.drawText(QRect(bx, by + 14, bw - 40, 20), Qt.AlignmentFlag.AlignLeft, self._stage)
        p.setPen(QColor("#c0392b"))
        p.drawText(QRect(bx, by + 14, bw, 20), Qt.AlignmentFlag.AlignRight, f"{self._pct}%")

        p.setFont(QFont("Consolas", 7))
        p.setPen(QColor("#2a2a3a"))
        p.drawText(QRect(0, h - 22, w, 18), Qt.AlignmentFlag.AlignHCenter,
                   "Win32_USBControllerDevice backend  |  Detects all connection modes")


class DeviceWorker(QObject):
    """
    Single unified worker that detects ALL USB-connected devices regardless
    of mode using Win32_USBControllerDevice. This is the only reliable way
    to detect devices in No-Data-Transfer, PTP, MTP, MIDI, Tethering, etc.
    """
    device_connected    = pyqtSignal(dict)
    device_disconnected = pyqtSignal(dict)
    log_event           = pyqtSignal(str, str)
    finished            = pyqtSignal()

    def __init__(self):
        super().__init__()
        self._run   = True
        self._prev: dict = {}

    def stop(self): self._run = False

    def run(self):
        while self._run:
            try:
                devices = query_all_usb_devices()
                current = {d["device_id"]: d for d in devices}

                for did, info in current.items():
                    if did not in self._prev:
                        drive = get_drive_for_device(info["vid"], info["pid"])
                        info["drive"]    = drive
                        info["capacity"] = get_disk_size(drive) if drive else ""
                        self.device_connected.emit(info)
                        self.log_event.emit(
                            f"Connected: [{info['mode']}]  {info['name']}  "
                            f"VID:{info['vid']} PID:{info['pid']}  "
                            f"Mfr:{info['manufacturer']}  "
                            f"Drive:{drive or 'N/A'}  ID:{did[:48]}",
                            "info"
                        )

                for did, info in list(self._prev.items()):
                    if did not in current:
                        self.device_disconnected.emit(info)
                        self.log_event.emit(
                            f"Disconnected: {info['name']}  [{info['mode']}]",
                            "warning"
                        )

                self._prev = current

            except Exception as ex:
                self.log_event.emit(f"Device scan error: {ex}", "error")

            time.sleep(2)
        self.finished.emit()


class FileWorker(QObject):
    file_event   = pyqtSignal(str, str, str, str, str)
    log_event    = pyqtSignal(str, str)
    stats_update = pyqtSignal(int, int, int)
    finished     = pyqtSignal()

    def __init__(self):
        super().__init__()
        self._run      = True
        self._drives: set = set()
        self._usb_snaps: dict = {}
        self._sys_snap: dict = snap_system()
        self._total = 0
        self._high  = 0
        self._sens  = 0

    def stop(self): self._run = False

    def add_drive(self, d: str):
        self._drives.add(d)
        self._usb_snaps[d] = snap_dir(d)

    def remove_drive(self, d: str):
        self._drives.discard(d)
        self._usb_snaps.pop(d, None)

    def run(self):
        while self._run:
            new_sys = snap_system()
            for drive in list(self._drives):
                if not os.path.exists(drive):
                    continue
                new_usb = snap_dir(drive)
                old_usb = self._usb_snaps.get(drive, {})
                self._diff_usb(old_usb, new_usb, drive)
                self._diff_to_sys(self._sys_snap, new_sys, old_usb, drive)
                self._usb_snaps[drive] = new_usb
            self._sys_snap = new_sys
            self.stats_update.emit(self._total, self._high, self._sens)
            time.sleep(3)
        self.finished.emit()

    def _emit(self, event: str, fname: str, location: str, size: str):
        risk = file_risk(fname)
        self._total += 1
        if risk == "HIGH RISK":   self._high += 1
        elif risk == "SENSITIVE": self._sens += 1
        self.file_event.emit(event, Path(fname).name, location, size, risk)
        lvl = "error" if risk == "HIGH RISK" else "warning" if risk == "SENSITIVE" else "info"
        self.log_event.emit(
            f"DLP: {event}  |  {risk}  |  {Path(fname).name} ({size})  [{location}]", lvl
        )

    def _diff_usb(self, old: dict, new: dict, drive: str):
        ok, nk = set(old), set(new)
        renamed = set()
        for r in ok - nk:
            for a in nk - ok:
                if (old[r]["size"] == new[a]["size"] and
                        old[r]["hash"] and new[a]["hash"] and
                        old[r]["hash"] == new[a]["hash"]):
                    self._emit("RENAMED", f"{Path(r).name}->{Path(a).name}",
                               drive, fmt_size(new[a]["size"]))
                    renamed.add(r)
                    renamed.add(a)
                    break
        for f in ok & nk:
            if old[f]["mtime"] != new[f]["mtime"]:
                self._emit("MODIFIED", f, drive, fmt_size(new[f]["size"]))
        for a in (nk - ok) - renamed:
            self._emit("SYS -> USB", a, drive, fmt_size(new[a]["size"]))
        for r in (ok - nk) - renamed:
            self._emit("DELETED", r, drive, fmt_size(old[r]["size"]))

    def _diff_to_sys(self, old_sys: dict, new_sys: dict, usb: dict, drive: str):
        for f in set(new_sys) - set(old_sys):
            m = new_sys[f]
            for um in usb.values():
                if (um["size"] == m["size"] and um["hash"] and m["hash"]
                        and um["hash"] == m["hash"]):
                    self._emit("USB -> SYS", f, drive, fmt_size(m["size"]))
                    break


class StatCard(QFrame):
    def __init__(self, label: str, value_color: str = "#e8e8f0"):
        super().__init__()
        self.setObjectName("card")
        self._vc = value_color
        lay = QVBoxLayout(self)
        lay.setContentsMargins(16, 10, 16, 10)
        lay.setSpacing(2)
        self._val = QLabel("0")
        self._val.setFont(QFont("Segoe UI", 24, QFont.Weight.Bold))
        self._val.setStyleSheet(f"color:{value_color};")
        self._lbl = QLabel(label.upper())
        self._lbl.setFont(QFont("Segoe UI", 8, QFont.Weight.Bold))
        self._lbl.setObjectName("card_lbl")
        lay.addWidget(self._val)
        lay.addWidget(self._lbl)

    def set_value(self, v): self._val.setText(str(v))
    def set_color(self, c: str):
        self._vc = c
        self._val.setStyleSheet(f"color:{c};")


def build_qss(t: dict) -> str:
    return f"""
* {{ font-family:"Segoe UI","Arial",sans-serif; font-size:11px; outline:none; }}
QMainWindow, QWidget {{ background:{t['bg']}; color:{t['text']}; border:none; }}
QFrame#topbar {{
    background:{t['surface']}; border-bottom:2px solid {t['accent']};
    min-height:56px; max-height:56px;
}}
QLabel#app_title  {{ color:{t['text']}; font-size:15px; font-weight:700; letter-spacing:1px; }}
QLabel#app_sub    {{ color:{t['text_dim']}; font-size:9px; letter-spacing:2px; }}
QLabel#badge      {{
    background:{t['accent']}; color:#fff; font-size:8px;
    font-weight:700; padding:2px 8px; border-radius:3px; letter-spacing:2px;
}}
QFrame#statbar    {{
    background:{t['surface']}; border-bottom:1px solid {t['border']};
    min-height:74px; max-height:74px;
}}
QFrame#card       {{
    background:{t['surface2']}; border:1px solid {t['border']};
    border-top:2px solid {t['accent']}; border-radius:4px; min-width:148px;
}}
QLabel#card_lbl   {{ color:{t['text_muted']}; font-size:8px; font-weight:700; letter-spacing:2px; }}
QTabWidget::pane  {{ background:{t['bg']}; border:none; border-top:1px solid {t['border']}; }}
QTabBar           {{ background:{t['surface']}; }}
QTabBar::tab      {{
    background:{t['surface']}; color:{t['text_dim']};
    padding:10px 22px; font-size:10px; font-weight:600; letter-spacing:1px;
    border:none; border-bottom:2px solid transparent; margin-right:1px; min-width:100px;
}}
QTabBar::tab:selected     {{ color:{t['accent_bright']}; border-bottom:2px solid {t['accent']}; background:{t['surface2']}; }}
QTabBar::tab:hover:!selected {{ color:{t['text']}; background:{t['surface2']}; }}
QTableWidget {{
    background:{t['surface']}; color:{t['text']}; gridline-color:{t['border']};
    border:none; selection-background-color:{t['accent_dim']};
    selection-color:#fff; alternate-background-color:{t['surface2']};
}}
QTableWidget::item          {{ padding:5px 10px; border:none; }}
QTableWidget::item:hover    {{ background:{t['surface3']}; }}
QHeaderView::section        {{
    background:{t['surface3']}; color:{t['text_dim']};
    font-size:9px; font-weight:700; letter-spacing:2px;
    padding:8px 10px; border:none;
    border-right:1px solid {t['border']}; border-bottom:1px solid {t['accent']};
}}
QPushButton#btn_primary     {{
    background:{t['accent']}; color:#fff; border:none; border-radius:3px;
    font-size:10px; font-weight:700; letter-spacing:1px; padding:7px 18px; min-width:90px;
}}
QPushButton#btn_primary:hover   {{ background:{t['accent_bright']}; }}
QPushButton#btn_primary:pressed {{ background:{t['accent_dim']}; }}
QPushButton#btn_secondary   {{
    background:transparent; color:{t['text_dim']}; border:1px solid {t['border']};
    border-radius:3px; font-size:10px; font-weight:600; letter-spacing:1px; padding:6px 14px;
}}
QPushButton#btn_secondary:hover {{ background:{t['surface3']}; color:{t['text']}; border-color:{t['accent']}; }}
QPushButton#btn_pause       {{
    background:{t['surface3']}; color:{t['accent_bright']};
    border:1px solid {t['accent']}; border-radius:3px;
    font-size:10px; font-weight:700; letter-spacing:2px; padding:6px 16px; min-width:80px;
}}
QPushButton#btn_pause:hover {{ background:{t['accent_dim']}; color:#fff; }}
QTextEdit#logbox            {{
    background:{t['log_bg']}; color:{t['log_text']}; border:none;
    border-top:1px solid {t['border']};
    font-family:"Consolas","Courier New",monospace; font-size:10px; padding:8px;
}}
QFrame#toolbar              {{
    background:{t['surface2']}; border-bottom:1px solid {t['border']};
    min-height:40px; max-height:40px;
}}
QLabel#dir_label            {{ color:{t['text_muted']}; font-family:Consolas; font-size:9px; padding-left:6px; }}
QLabel#info_label           {{
    color:{t['text_muted']}; font-size:9px;
    background:{t['surface3']}; padding:5px 14px; border-bottom:1px solid {t['border']};
}}
QScrollBar:vertical         {{ background:{t['surface']}; width:7px; border-radius:3px; }}
QScrollBar::handle:vertical {{ background:{t['border']}; border-radius:3px; min-height:20px; }}
QScrollBar::handle:vertical:hover {{ background:{t['accent']}; }}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height:0; }}
QScrollBar:horizontal       {{ height:7px; background:{t['surface']}; border-radius:3px; }}
QScrollBar::handle:horizontal {{ background:{t['border']}; border-radius:3px; }}
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{ width:0; }}
QStatusBar                  {{
    background:{t['surface']}; color:{t['text_muted']};
    border-top:1px solid {t['border']}; font-family:Consolas; font-size:9px; padding:0 12px;
}}
QGroupBox#help_box          {{
    color:{t['accent_bright']}; border:1px solid {t['border']}; border-radius:4px;
    margin-top:16px; padding-top:6px; background:{t['surface2']};
    font-size:10px; font-weight:700; letter-spacing:1px;
}}
QGroupBox#help_box::title   {{
    subcontrol-origin:margin; left:12px; padding:0 6px;
    background:{t['surface2']};
}}
QLabel#help_body            {{ color:{t['text_dim']}; font-size:10px; line-height:1.7; padding:4px; }}
QScrollArea                 {{ background:transparent; border:none; }}
QLabel#s_active             {{ color:{t['green']};  font-family:Consolas; font-size:9px; }}
QLabel#s_paused             {{ color:{t['yellow']}; font-family:Consolas; font-size:9px; }}
"""


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self._dark   = True
        self._active = True
        self._rdir   = None
        self._n_dev  = 0
        self._n_ev   = 0
        self._n_high = 0
        self._n_sens = 0
        self._session: list = []

        self.setWindowTitle("Advanced Endpoint Monitor")
        self.setMinimumSize(1400, 800)
        self._build_ui()
        self._apply_theme()
        self._start_workers()
        self._clock_timer = QTimer(self)
        self._clock_timer.timeout.connect(self._tick)
        self._clock_timer.start(1000)

    def _t(self): return DARK if self._dark else LIGHT

    def _build_ui(self):
        root = QWidget()
        self.setCentralWidget(root)
        vl = QVBoxLayout(root)
        vl.setContentsMargins(0, 0, 0, 0)
        vl.setSpacing(0)
        vl.addWidget(self._mk_topbar())
        vl.addWidget(self._mk_statbar())
        self._tabs = QTabWidget()
        self._tabs.setDocumentMode(True)
        vl.addWidget(self._tabs)
        self._tabs.addTab(self._mk_device_tab(), "ALL DEVICES")
        self._tabs.addTab(self._mk_file_tab(),   "FILE ACTIVITY")
        self._tabs.addTab(self._mk_log_tab(),    "AUDIT LOG")
        self._tabs.addTab(self._mk_help_tab(),   "HELP")

        sb = QStatusBar()
        self.setStatusBar(sb)
        self._status_lbl = QLabel("[ MONITORING ACTIVE ]")
        self._status_lbl.setObjectName("s_active")
        self._clock_lbl = QLabel()
        self._clock_lbl.setObjectName("s_active")
        sb.addWidget(self._status_lbl)
        sb.addPermanentWidget(self._clock_lbl)

    def _mk_topbar(self) -> QFrame:
        bar = QFrame()
        bar.setObjectName("topbar")
        lay = QHBoxLayout(bar)
        lay.setContentsMargins(20, 0, 16, 0)
        lay.setSpacing(10)

        stripe = QFrame()
        stripe.setFixedSize(3, 36)
        stripe.setStyleSheet("background:#c0392b; border-radius:1px;")
        lay.addWidget(stripe)
        lay.addSpacing(4)

        tb = QVBoxLayout()
        tb.setSpacing(1)
        t1 = QLabel("Advanced Endpoint Monitor")
        t1.setObjectName("app_title")
        t2 = QLabel("ALL USB MODES  |  DLP  |  FORENSICS  |  AUDIT")
        t2.setObjectName("app_sub")
        tb.addWidget(t1)
        tb.addWidget(t2)
        lay.addLayout(tb)

        badge = QLabel("LIVE")
        badge.setObjectName("badge")
        lay.addWidget(badge)
        lay.addStretch()

        self._pause_btn = QPushButton("PAUSE")
        self._pause_btn.setObjectName("btn_pause")
        self._pause_btn.setFixedSize(86, 30)
        self._pause_btn.clicked.connect(self._toggle_active)
        lay.addWidget(self._pause_btn)
        lay.addSpacing(14)

        tw = QFrame()
        tl = QHBoxLayout(tw)
        tl.setContentsMargins(0, 0, 0, 0)
        tl.setSpacing(6)
        ll = QLabel("LIGHT")
        ll.setStyleSheet("color:#555577; font-size:8px; font-weight:700; letter-spacing:1px;")
        self._toggle = ToggleSwitch()
        self._toggle.set_checked(True)
        self._toggle.toggled.connect(self._on_toggle)
        lr = QLabel("DARK")
        lr.setStyleSheet("color:#c0392b; font-size:8px; font-weight:700; letter-spacing:1px;")
        tl.addWidget(ll)
        tl.addWidget(self._toggle)
        tl.addWidget(lr)
        lay.addWidget(tw)
        return bar

    def _mk_statbar(self) -> QFrame:
        bar = QFrame()
        bar.setObjectName("statbar")
        lay = QHBoxLayout(bar)
        lay.setContentsMargins(14, 8, 14, 8)
        lay.setSpacing(10)
        self._c_dev  = StatCard("Devices Seen",    "#e8e8f0")
        self._c_ev   = StatCard("File Events",     "#e8e8f0")
        self._c_high = StatCard("High Risk",       "#e74c3c")
        self._c_sens = StatCard("Sensitive Files", "#f1c40f")
        for c in [self._c_dev, self._c_ev, self._c_high, self._c_sens]:
            lay.addWidget(c)
        return bar

    def _mk_toolbar(self, *btns) -> QFrame:
        bar = QFrame()
        bar.setObjectName("toolbar")
        lay = QHBoxLayout(bar)
        lay.setContentsMargins(10, 0, 10, 0)
        lay.setSpacing(6)
        for b in btns:
            lay.addWidget(b)
        lay.addStretch()
        return bar

    def _mk_table(self, headers: list) -> QTableWidget:
        t = QTableWidget()
        t.setColumnCount(len(headers))
        t.setHorizontalHeaderLabels(headers)
        t.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        t.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        t.setAlternatingRowColors(True)
        t.setSortingEnabled(True)
        t.verticalHeader().setVisible(False)
        t.setShowGrid(True)
        t.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        t.horizontalHeader().setStretchLastSection(True)
        return t

    def _mk_device_tab(self) -> QWidget:
        w = QWidget()
        vl = QVBoxLayout(w)
        vl.setContentsMargins(0, 0, 0, 0)
        vl.setSpacing(0)

        info = QLabel(
            "  Detects ALL USB connection modes via Win32_USBControllerDevice: "
            "No Data Transfer, MTP, PTP, Mass Storage, USB Tethering, MIDI, HID, Audio, and more."
        )
        info.setObjectName("info_label")
        info.setWordWrap(True)

        clr = QPushButton("CLEAR")
        clr.setObjectName("btn_secondary")
        clr.clicked.connect(lambda: self._dev_tbl.setRowCount(0))

        vl.addWidget(info)
        vl.addWidget(self._mk_toolbar(clr))

        self._dev_tbl = self._mk_table([
            "DEVICE NAME", "MANUFACTURER", "VID", "PID",
            "CONNECTION MODE", "PNP CLASS", "DRIVE", "CAPACITY", "STATUS", "TIMESTAMP"
        ])
        for i, w_ in enumerate([230, 160, 55, 55, 170, 100, 60, 80, 90, 155]):
            self._dev_tbl.setColumnWidth(i, w_)
        vl.addWidget(self._dev_tbl)
        return w

    def _mk_file_tab(self) -> QWidget:
        w = QWidget()
        vl = QVBoxLayout(w)
        vl.setContentsMargins(0, 0, 0, 0)
        vl.setSpacing(0)
        clr = QPushButton("CLEAR")
        clr.setObjectName("btn_secondary")
        clr.clicked.connect(lambda: self._file_tbl.setRowCount(0))
        vl.addWidget(self._mk_toolbar(clr))
        self._file_tbl = self._mk_table(
            ["EVENT", "FILE NAME", "SOURCE / DEST", "SIZE", "RISK LEVEL", "TIMESTAMP"]
        )
        for i, w_ in enumerate([130, 260, 160, 80, 115, 155]):
            self._file_tbl.setColumnWidth(i, w_)
        vl.addWidget(self._file_tbl)
        return w

    def _mk_log_tab(self) -> QWidget:
        w = QWidget()
        vl = QVBoxLayout(w)
        vl.setContentsMargins(0, 0, 0, 0)
        vl.setSpacing(0)

        b_sdir = QPushButton("SET DIRECTORY")
        b_sdir.setObjectName("btn_secondary")
        b_sdir.clicked.connect(self._set_rdir)
        b_gen = QPushButton("GENERATE REPORT")
        b_gen.setObjectName("btn_primary")
        b_gen.clicked.connect(self._gen_report)
        b_exp = QPushButton("EXPORT JSON")
        b_exp.setObjectName("btn_secondary")
        b_exp.clicked.connect(self._export_json)
        b_clr = QPushButton("CLEAR")
        b_clr.setObjectName("btn_secondary")
        b_clr.clicked.connect(lambda: self._logbox.clear())

        self._dir_lbl = QLabel("No directory set")
        self._dir_lbl.setObjectName("dir_label")

        tb = self._mk_toolbar(b_sdir, b_gen, b_exp, b_clr)
        tb.layout().addWidget(self._dir_lbl)
        vl.addWidget(tb)

        self._logbox = QTextEdit()
        self._logbox.setObjectName("logbox")
        self._logbox.setReadOnly(True)
        vl.addWidget(self._logbox)
        return w

    def _mk_help_tab(self) -> QWidget:
        outer = QWidget()
        vl = QVBoxLayout(outer)
        vl.setContentsMargins(0, 0, 0, 0)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        inner = QWidget()
        il = QVBoxLayout(inner)
        il.setContentsMargins(24, 16, 24, 24)
        il.setSpacing(14)

        sections = [
            ("HOW DEVICE DETECTION WORKS",
             "This tool uses Win32_USBControllerDevice — the most comprehensive USB enumeration "
             "API available in Windows WMI.\n\n"
             "It walks every device attached to every USB controller on your system. This means "
             "it detects devices in ANY mode:\n\n"
             "  No Data Transfer (charging only)\n"
             "  MTP  — Media Transfer Protocol (Android file transfer)\n"
             "  PTP  — Picture Transfer Protocol (camera / iOS)\n"
             "  Mass Storage — appears as a drive letter\n"
             "  USB Tethering (RNDIS) — network over USB\n"
             "  MIDI — musical device\n"
             "  HID  — keyboard, mouse, gamepad\n"
             "  Audio — headsets, speakers\n\n"
             "Root hubs and generic USB hubs are automatically filtered out."),
            ("CONNECTION MODE DETECTION",
             "The Mode column is determined by the PnP class of the device:\n\n"
             "  WPD class           -> MTP / PTP\n"
             "  DiskDrive/USBSTOR  -> Mass Storage\n"
             "  Ports / COM desc   -> USB Tethering / COM\n"
             "  Net / RNDIS desc   -> USB Tethering (RNDIS)\n"
             "  HIDClass           -> HID (Input Device)\n"
             "  AudioEndpoint      -> Audio / MIDI\n"
             "  USB (no service)   -> No Data Transfer (Power Only)"),
            ("FILE ACTIVITY / DLP ENGINE",
             "MD5 hash fingerprinting of Desktop, Downloads, Documents, Pictures.\n\n"
             "  SYS -> USB   File copied from system to USB drive\n"
             "  USB -> SYS   File written from USB to system\n"
             "  MODIFIED     File changed on USB drive\n"
             "  RENAMED      Detected by hash comparison\n"
             "  DELETED      File removed from USB\n\n"
             "Risk levels:\n"
             "  HIGH RISK  — .exe .dll .bat .ps1 .vbs .jar .msi .scr\n"
             "  SENSITIVE  — .pdf .docx .sql .db .zip .pfx .pem .kdbx\n"
             "  NORMAL     — All other types"),
            ("REQUIREMENTS",
             "Run as Administrator for full WMI access.\n"
             "Requires PowerShell 5.1+ (Windows 10 / 11 built-in).\n"
             "Keep the application running during your monitoring window.\n"
             "Generate a report before closing to retain session data."),
        ]
        for title, body in sections:
            box = QGroupBox(title)
            box.setObjectName("help_box")
            bl = QVBoxLayout(box)
            lbl = QLabel(body)
            lbl.setObjectName("help_body")
            lbl.setWordWrap(True)
            lbl.setTextFormat(Qt.TextFormat.PlainText)
            bl.addWidget(lbl)
            il.addWidget(box)
        il.addStretch()
        scroll.setWidget(inner)
        vl.addWidget(scroll)
        return outer

    def _start_workers(self):
        self._dev_thread = QThread()
        self._dev_worker = DeviceWorker()
        self._dev_worker.moveToThread(self._dev_thread)
        self._dev_thread.started.connect(self._dev_worker.run)
        self._dev_worker.device_connected.connect(self._on_device_connected)
        self._dev_worker.device_disconnected.connect(self._on_device_disconnected)
        self._dev_worker.log_event.connect(self._log)
        self._dev_thread.start()

        self._file_thread = QThread()
        self._file_worker = FileWorker()
        self._file_worker.moveToThread(self._file_thread)
        self._file_thread.started.connect(self._file_worker.run)
        self._file_worker.file_event.connect(self._on_file)
        self._file_worker.log_event.connect(self._log)
        self._file_worker.stats_update.connect(self._on_stats)
        self._file_thread.start()

    def _find_row_by_device_id(self, device_id: str) -> int:
        for row in range(self._dev_tbl.rowCount()):
            item = self._dev_tbl.item(row, 0)
            if item and item.data(Qt.ItemDataRole.UserRole) == device_id:
                return row
        return -1

    def _on_device_connected(self, info: dict):
        if not self._active:
            return
        self._n_dev += 1
        self._c_dev.set_value(self._n_dev)

        row = self._dev_tbl.rowCount()
        self._dev_tbl.insertRow(row)
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        t  = self._t()

        mode = info.get("mode", "Unknown")
        mode_colors = {
            "MTP / PTP":             t["yellow"],
            "Mass Storage":          t["green"],
            "USB Tethering (RNDIS)": t["blue"],
            "USB Tethering / COM":   t["blue"],
            "No Data Transfer (Power)": t["text_muted"],
            "HID (Input Device)":    t["text_dim"],
            "Audio / MIDI":          t["text_dim"],
        }
        row_color = mode_colors.get(mode, t["text"])

        vals = [
            info.get("name", ""),
            info.get("manufacturer", ""),
            info.get("vid", ""),
            info.get("pid", ""),
            mode,
            info.get("pnp_class", ""),
            info.get("drive", "") or "",
            info.get("capacity", "") or "",
            "CONNECTED",
            ts,
        ]
        for col, val in enumerate(vals):
            item = QTableWidgetItem(str(val))
            item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            item.setForeground(QColor(row_color))
            if col == 0:
                item.setData(Qt.ItemDataRole.UserRole, info.get("device_id", ""))
            self._dev_tbl.setItem(row, col, item)

        drive = info.get("drive", "")
        if drive:
            self._file_worker.add_drive(drive)

        self._session.append({
            "type": "device_connected", "timestamp": ts,
            **{k: info.get(k, "") for k in
               ["name","manufacturer","vid","pid","mode","pnp_class","drive","capacity","device_id"]}
        })

    def _on_device_disconnected(self, info: dict):
        if not self._active:
            return
        did = info.get("device_id", "")
        row = self._find_row_by_device_id(did)
        ts  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        t   = self._t()

        if row >= 0:
            status_item = self._dev_tbl.item(row, 8)
            if status_item:
                status_item.setText("DISCONNECTED")
                status_item.setForeground(QColor(t["text_muted"]))
            ts_item = self._dev_tbl.item(row, 9)
            if ts_item:
                ts_item.setText(ts)
        else:
            r = self._dev_tbl.rowCount()
            self._dev_tbl.insertRow(r)
            vals = [info.get("name",""),"","","","","","","","DISCONNECTED",ts]
            for col, val in enumerate(vals):
                item = QTableWidgetItem(str(val))
                item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                item.setForeground(QColor(t["text_muted"]))
                if col == 0:
                    item.setData(Qt.ItemDataRole.UserRole, did)
                self._dev_tbl.setItem(r, col, item)

        drive = info.get("drive", "")
        if drive:
            self._file_worker.remove_drive(drive)

        self._session.append({
            "type": "device_disconnected", "timestamp": ts,
            "name": info.get("name",""), "device_id": did
        })

    def _on_file(self, event: str, fname: str, location: str, size: str, risk: str):
        if not self._active:
            return
        self._n_ev += 1
        if risk == "HIGH RISK":
            self._n_high += 1
            self._c_high.set_value(self._n_high)
        elif risk == "SENSITIVE":
            self._n_sens += 1
            self._c_sens.set_value(self._n_sens)
        self._c_ev.set_value(self._n_ev)

        row = self._file_tbl.rowCount()
        self._file_tbl.insertRow(row)
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        t  = self._t()
        risk_fg = {"HIGH RISK": t["error"], "SENSITIVE": t["warning"]}.get(risk, t["text_dim"])

        for col, val in enumerate([event, fname, location, size, risk, ts]):
            item = QTableWidgetItem(str(val))
            item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            if col == 4:
                item.setForeground(QColor(risk_fg))
            self._file_tbl.setItem(row, col, item)
        self._file_tbl.scrollToBottom()

        self._session.append({
            "type": "file_event", "event": event, "file": fname,
            "location": location, "size": size, "risk": risk, "timestamp": ts
        })

    def _on_stats(self, total: int, high: int, sens: int):
        self._c_ev.set_value(total)
        self._c_high.set_value(high)
        self._c_sens.set_value(sens)

    def _log(self, msg: str, level: str = "info"):
        t  = self._t()
        ts = datetime.now().strftime("%H:%M:%S")
        clr = {"error":t["error"],"warning":t["warning"],
               "info":t["info"],"success":t["success"]}.get(level, t["log_text"])
        pfx = {"error":"ERROR  ","warning":"WARN   ",
               "info":"INFO   ","success":"OK     "}.get(level, "LOG    ")
        self._logbox.append(
            f'<span style="color:#333355">[{ts}]</span> '
            f'<span style="color:{clr}">{pfx}</span> '
            f'<span style="color:{t["log_text"]}">{msg}</span>'
        )

    def _tick(self):
        self._clock_lbl.setText(datetime.now().strftime("  %a %d %b %Y   %H:%M:%S  "))

    def _toggle_active(self):
        self._active = not self._active
        self._pause_btn.setText("RESUME" if not self._active else "PAUSE")
        self._status_lbl.setObjectName("s_paused" if not self._active else "s_active")
        self._status_lbl.setText(
            "[ PAUSED ]" if not self._active else "[ MONITORING ACTIVE ]"
        )
        self._log(
            "Monitoring PAUSED" if not self._active else "Monitoring RESUMED",
            "warning" if not self._active else "success"
        )
        self._apply_theme()

    def _on_toggle(self, checked: bool):
        self._dark = checked
        self._apply_theme()

    def _apply_theme(self):
        t = self._t()
        self.setStyleSheet(build_qss(t))
        self._c_dev._lbl.setStyleSheet(
            f"color:{t['text_muted']}; font-size:8px; font-weight:700; letter-spacing:2px;")
        self._c_ev._lbl.setStyleSheet(
            f"color:{t['text_muted']}; font-size:8px; font-weight:700; letter-spacing:2px;")
        self._c_high._lbl.setStyleSheet(
            f"color:{t['text_muted']}; font-size:8px; font-weight:700; letter-spacing:2px;")
        self._c_sens._lbl.setStyleSheet(
            f"color:{t['text_muted']}; font-size:8px; font-weight:700; letter-spacing:2px;")
        self._c_dev.set_color(t["text"])
        self._c_ev.set_color(t["text"])
        self._c_high.set_color(t["error"])
        self._c_sens.set_color(t["yellow"])

    def _set_rdir(self):
        d = QFileDialog.getExistingDirectory(self, "Select Report Directory")
        if d:
            self._rdir = d
            self._dir_lbl.setText(f"  {d}")
            self._log(f"Report directory: {d}", "info")

    def _gen_report(self):
        if not self._rdir:
            self._set_rdir()
        if not self._rdir:
            return
        ts   = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        path = os.path.join(self._rdir, f"Endpoint_Audit_{ts}.txt")
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write("=" * 80 + "\n")
                f.write(f"  ENDPOINT AUDIT REPORT  |  {datetime.now()}\n")
                f.write("=" * 80 + "\n\n")

                f.write("SECTION 1 — ALL USB DEVICES\n" + "-" * 80 + "\n")
                f.write(f"{'DEVICE':<28} {'MFR':<18} {'VID':<6} {'PID':<6} "
                        f"{'MODE':<22} {'DRIVE':<7} {'STATUS':<14} TIMESTAMP\n")
                for row in range(self._dev_tbl.rowCount()):
                    v = [self._dev_tbl.item(row, c).text()
                         if self._dev_tbl.item(row, c) else "" for c in range(10)]
                    f.write(f"{v[0]:<28} {v[1]:<18} {v[2]:<6} {v[3]:<6} "
                            f"{v[4]:<22} {v[6]:<7} {v[8]:<14} {v[9]}\n")

                f.write("\nSECTION 2 — FILE ACTIVITY / DLP\n" + "-" * 80 + "\n")
                f.write(f"{'EVENT':<16} {'RISK':<12} {'SIZE':<10} "
                        f"{'LOCATION':<14} {'TIMESTAMP':<22} FILE\n")
                for row in range(self._file_tbl.rowCount()):
                    v = [self._file_tbl.item(row, c).text()
                         if self._file_tbl.item(row, c) else "" for c in range(6)]
                    f.write(f"{v[0]:<16} {v[4]:<12} {v[3]:<10} "
                            f"{v[2]:<14} {v[5]:<22} {v[1]}\n")

                f.write("\nSECTION 3 — RAW EVENT LOG\n" + "-" * 80 + "\n")
                f.write(self._logbox.toPlainText())

            QMessageBox.information(self, "Report Saved", f"Saved:\n{path}")
            self._log(f"Audit report: {path}", "success")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed:\n{e}")

    def _export_json(self):
        if not self._rdir:
            self._set_rdir()
        if not self._rdir:
            return
        ts   = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        path = os.path.join(self._rdir, f"Endpoint_Data_{ts}.json")
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump({
                    "meta": {"generated": datetime.now().isoformat(),
                             "tool": "Advanced Endpoint Monitor", "version": "3.0"},
                    "events": self._session
                }, f, indent=2)
            QMessageBox.information(self, "Exported", f"JSON:\n{path}")
            self._log(f"JSON exported: {path}", "success")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Export failed:\n{e}")

    def closeEvent(self, e):
        self._dev_worker.stop()
        self._file_worker.stop()
        self._dev_thread.quit()
        self._file_thread.quit()
        self._dev_thread.wait(2000)
        self._file_thread.wait(2000)
        e.accept()


def run_splash() -> SplashScreen:
    splash = SplashScreen()
    splash.show()
    QApplication.processEvents()
    steps = [
        (8,  "Loading configuration..."),
        (20, "Initializing PowerShell bridge..."),
        (35, "Connecting to Win32_USBControllerDevice..."),
        (50, "Loading DLP engine..."),
        (62, "Setting up file snapshot system..."),
        (75, "Starting device monitoring thread..."),
        (87, "Building interface..."),
        (95, "Applying theme..."),
        (100,"Ready."),
    ]
    for pct, label in steps:
        splash.set_progress(pct, label)
        time.sleep(0.22)
    return splash


if __name__ == "__main__":
    if os.name == "nt":
        try:
            if not ctypes.windll.shell32.IsUserAnAdmin():
                ctypes.windll.shell32.ShellExecuteW(
                    None, "runas", sys.executable,
                    " ".join(f'"{a}"' for a in sys.argv), None, 1
                )
                sys.exit(0)
        except Exception:
            pass

    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    app.setApplicationName("Advanced Endpoint Monitor")

    splash = run_splash()
    window = MainWindow()
    window.show()
    splash.finish(window)

    sys.exit(app.exec())
