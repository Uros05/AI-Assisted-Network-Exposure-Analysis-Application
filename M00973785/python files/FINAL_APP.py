import sys
import os
import shutil
import subprocess
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Dict, Any, Tuple

from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt6.QtGui import QFont, QPainter, QColor, QPen
from PyQt6.QtWidgets import (
    QApplication,
    QButtonGroup,
    QComboBox,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QPushButton,
    QRadioButton,
    QScrollArea,
    QSizePolicy,
    QStackedWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
    QMessageBox,
)

from network_utils import detect_active_subnet
from parser import parse_nmap_xml


@dataclass
class Exposure:
    host: str
    port: str
    service: str
    risk: str
    description: str


def get_base_dir() -> str:
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.abspath(".")


def get_ai_runner_path() -> str:
    base_dir = get_base_dir()

    if getattr(sys, "frozen", False):
        return os.path.join(base_dir, "FINAL_AI.exe")

    return os.path.join(base_dir, "FINAL_AI.py")




def classify_risk(port: int, service: Optional[str]) -> str:
    svc = (service or "").lower().strip()

    if port == 23:
        return "Critical"
    if port in (445, 3389, 5900, 27017):
        return "High"
    if port in (22, 21, 25, 110, 143, 3306, 5432):
        return "Medium"
    if port in (80, 443):
        return "Low"

    if "rdp" in svc or "ms-wbt-server" in svc:
        return "High"
    if "ssh" in svc or "ftp" in svc:
        return "Medium"
    if "http" in svc:
        return "Low"

    return "Low"


def exposure_description(port: int, service: Optional[str]) -> str:
    svc = service or "unknown service"
    if port == 23:
        return "Telnet is an unencrypted remote login service. If not required, disable it."
    if port == 445:
        return "SMB file sharing can be sensitive on home or small networks. Confirm it is needed and properly restricted."
    if port == 3389:
        return "Remote Desktop exposure can increase risk if weak credentials or broad access exists. Restrict access if possible."
    if port == 22:
        return "SSH is a remote administration service. Use strong credentials and limit who can access it."
    if port in (80, 443):
        return "A web service is running. Confirm it is expected and keep it updated."
    return f"An exposed service was detected ({svc}). Confirm it is expected and restrict access if not."


def safe_port_value(port_raw: Any) -> int:
    try:
        return int(port_raw)
    except (TypeError, ValueError):
        return 0


def build_host_label(host_data: Dict[str, Any]) -> str:
    ip = host_data.get("ip") or "unknown"
    hostname = host_data.get("hostname") or ""
    vendor = host_data.get("vendor") or ""

    if hostname:
        return f"{hostname} ({ip})"
    if vendor:
        return f"{vendor} ({ip})"
    return ip


def get_host_vendor(host_data: Dict[str, Any]) -> str:
    vendor = (host_data.get("vendor") or "").strip()
    return vendor if vendor else "Unknown"


def get_host_open_ports(host_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    return host_data.get("open_ports") or []


def get_highest_risk_for_host(host_data: Dict[str, Any]) -> str:
    open_ports = get_host_open_ports(host_data)
    if not open_ports:
        return "Low"

    risks = []
    for port_data in open_ports:
        port = safe_port_value(port_data.get("port"))
        service = port_data.get("service") or "unknown"
        risks.append(classify_risk(port, service))

    if "Critical" in risks:
        return "Critical"
    if "High" in risks:
        return "High"
    if "Medium" in risks:
        return "Medium"
    return "Low"


def risk_priority(risk: str) -> int:
    order = {
        "Critical": 0,
        "High": 1,
        "Medium": 2,
        "Low": 3,
    }
    return order.get(risk, 99)


def sort_hosts_by_risk(hosts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return sorted(
        hosts,
        key=lambda host: (
            risk_priority(get_highest_risk_for_host(host)),
            build_host_label(host).lower()
        )
    )


def build_exposures(hosts: List[Dict[str, Any]]) -> List[Exposure]:
    exposures: List[Exposure] = []

    for host_data in hosts:
        display_host = build_host_label(host_data)

        for port_data in get_host_open_ports(host_data):
            port = safe_port_value(port_data.get("port"))
            service = port_data.get("service") or "unknown"
            risk = classify_risk(port, service)
            description = exposure_description(port, service)

            exposures.append(
                Exposure(
                    host=display_host,
                    port=str(port),
                    service=str(service),
                    risk=risk,
                    description=description
                )
            )

    risk_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    exposures.sort(
        key=lambda e: (
            risk_order.get(e.risk, 99),
            e.host,
            int(e.port) if e.port.isdigit() else 99999
        )
    )
    return exposures


def build_device_choices(hosts: List[Dict[str, Any]]) -> List[Tuple[str, str]]:
    choices: List[Tuple[str, str]] = []

    for host_data in hosts:
        ip = host_data.get("ip") or ""
        if not ip:
            continue

        label = build_host_label(host_data)
        choices.append((ip, label))

    choices.sort(key=lambda item: item[1].lower())
    return choices


def find_latest_scan_file(scan_dir: str = "scans") -> Optional[Path]:
    scans_path = Path(scan_dir)
    if not scans_path.exists():
        return None

    xml_files = list(scans_path.glob("scan_*.xml"))
    if not xml_files:
        return None

    xml_files.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    return xml_files[0]


def host_list_summary(hosts: List[Dict[str, Any]]) -> str:
    if not hosts:
        return "No previous scan data found."

    total_hosts = len(hosts)
    open_hosts = sum(1 for h in hosts if get_host_open_ports(h))
    return f"{total_hosts} device(s) in last scan • {open_hosts} with open ports"


def run_ai_for_selected_host(xml_path: str, selected_ip: str) -> str:

    try:
        ai_runner = get_ai_runner_path()

        if getattr(sys, "frozen", False):
            cmd = [ai_runner, xml_path, selected_ip, "explain"]
        else:
            cmd = [sys.executable, ai_runner, xml_path, selected_ip, "explain"]

        env_vars = os.environ.copy()
        env_vars["PYTHONIOENCODING"] = "utf-8"

        print("USING NEW FINAL BUILD", flush=True)

        creation_flags = 0
        if os.name == "nt":
            creation_flags = subprocess.CREATE_NO_WINDOW

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=120,
            env=env_vars,
            creationflags=creation_flags
        )

        if result.returncode != 0:
            error_text = result.stderr.strip() or result.stdout.strip() or "Unknown AI error"
            return f"AI analysis could not be generated.\n\nReason: {error_text}"

        return result.stdout.strip() or "No AI explanation was generated."

    except Exception as e:
        return f"AI error: {e}"


class ScanWorker(QThread):
    finished_ok = pyqtSignal(list, list, str)
    finished_err = pyqtSignal(str)

    def __init__(self, target: str, output_dir: str = "scans"):
        super().__init__()
        self.target = target
        self.output_dir = output_dir
        self._cancel = False
        self._proc: Optional[subprocess.Popen] = None

    def cancel(self):
        self._cancel = True
        if self._proc and self._proc.poll() is None:
            try:
                self._proc.terminate()
            except Exception:
                pass

    def run(self):
        try:
            nmap_path = shutil.which("nmap")
            if not nmap_path:
                raise RuntimeError("Nmap not found in PATH. Install Nmap or add it to PATH.")

            out_path = Path(self.output_dir)
            out_path.mkdir(parents=True, exist_ok=True)

            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            xml_file = out_path / f"scan_{timestamp}.xml"

            cmd = [
                nmap_path,
                "-sS",
                "-sV",
                "-oX",
                str(xml_file),
                self.target
            ]

            creation_flags = 0
            if os.name == "nt":
                creation_flags = subprocess.CREATE_NO_WINDOW

            

            self._proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                universal_newlines=True,
                creationflags=creation_flags
            )

            if self._proc.stdout:
                for _line in self._proc.stdout:
                    if self._cancel:
                        return

            ret = self._proc.wait()

            if self._cancel:
                return

            if ret != 0:
                hint = (
                    "Nmap returned a non-zero exit code.\n\n"
                    "Common causes on Windows:\n"
                    "1) Running SYN scan (-sS) without Administrator privileges.\n"
                    "2) Firewall or antivirus interfering.\n"
                    "3) Nmap not installed correctly.\n\n"
                    "Try running the app as Administrator or changing scan type later."
                )
                raise RuntimeError(hint)

            hosts = parse_nmap_xml(str(xml_file))
            exposures = build_exposures(hosts)

            self.finished_ok.emit(hosts, exposures, str(xml_file))

        except Exception as e:
            self.finished_err.emit(str(e))


class AIWorker(QThread):
    finished_ok = pyqtSignal(str)
    finished_err = pyqtSignal(str)

    def __init__(self, xml_path: str, selected_ip: str):
        super().__init__()
        self.xml_path = xml_path
        self.selected_ip = selected_ip

    def run(self):
        try:
            ai_text = run_ai_for_selected_host(self.xml_path, self.selected_ip)
            self.finished_ok.emit(ai_text)
        except Exception as e:
            self.finished_err.emit(str(e))


class ChatWorker(QThread):
    finished_ok = pyqtSignal(str)
    finished_err = pyqtSignal(str)

    def __init__(self, xml_path: str, selected_ip: str, question: str, last_port: Optional[int] = None):
        super().__init__()
        self.xml_path = xml_path
        self.selected_ip = selected_ip
        self.question = question
        self.last_port = last_port

    def run(self):
        try:
            ai_runner = get_ai_runner_path()

            if getattr(sys, "frozen", False):
                cmd = [ai_runner, self.xml_path, self.selected_ip, "chat", self.question]
            else:
                cmd = [sys.executable, ai_runner, self.xml_path, self.selected_ip, "chat", self.question]

            if self.last_port is not None:
                cmd.append(str(self.last_port))

            env_vars = os.environ.copy()
            env_vars["PYTHONIOENCODING"] = "utf-8"

            print("USING NEW FINAL BUILD", flush=True)


            creation_flags = 0
            if os.name == "nt":
                creation_flags = subprocess.CREATE_NO_WINDOW

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=120,
                env=env_vars,
                creationflags=creation_flags
            )

            if result.returncode != 0:
                error_text = result.stderr.strip() or result.stdout.strip() or "Unknown AI error"
                self.finished_err.emit(error_text)
                return

            self.finished_ok.emit(result.stdout.strip() or "No reply was generated.")

        except Exception as e:
            self.finished_err.emit(str(e))


class Header(QWidget):
    def __init__(self):
        super().__init__()
        self.setStyleSheet("background: #f8fafc;")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 24, 0, 18)
        layout.setSpacing(8)

        icon = QLabel("🛡️")
        icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        icon.setFixedSize(64, 64)
        icon.setStyleSheet(
            "background: #dbeafe;"
            "border-radius: 32px;"
            "color: #2563eb;"
            "font-size: 28px;"
        )

        title = QLabel("AI-Assisted Network Exposure Analyser")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setFont(QFont("Segoe UI", 20, QFont.Weight.Bold))
        title.setStyleSheet("color: #0f172a;")

        subtitle = QLabel("Exposure scanning and AI explanation for non-technical users")
        subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        subtitle.setFont(QFont("Segoe UI", 11))
        subtitle.setStyleSheet("color: #64748b;")

        layout.addWidget(icon, alignment=Qt.AlignmentFlag.AlignHCenter)
        layout.addWidget(title)
        layout.addWidget(subtitle)


class DashboardPage(QWidget):
    scan_clicked = pyqtSignal()
    view_last_scan_clicked = pyqtSignal()

    def __init__(self):
        super().__init__()
        self._devices: List[Tuple[str, str]] = []

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(18)

        title = QLabel("Dashboard")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        title.setStyleSheet("color: #1f2937;")
        outer.addWidget(title)

        subtitle = QLabel(
            "Welcome to the AI-Assisted Network Exposure Analyser.\n\n"
            "This application helps you scan your network to identify potentially risky exposed services.\n\n"
            "On the left, choose whether to scan the full network or a single device. "
            "Single-device scanning becomes available after a full scan.\n\n"
            "On the right, you can view a summary of your most recent scan."
        )
        subtitle.setWordWrap(True)
        subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        subtitle.setFont(QFont("Segoe UI", 10))
        subtitle.setStyleSheet("color: #64748b;")
        outer.addWidget(subtitle)

        grid = QGridLayout()
        grid.setHorizontalSpacing(24)
        grid.setVerticalSpacing(0)

        left_panel = QFrame()
        left_panel.setStyleSheet(
            "background: white; border: 1px solid #e2e8f0; border-radius: 18px;"
        )
        left_layout = QVBoxLayout(left_panel)
        left_layout.setContentsMargins(18, 18, 18, 18)
        left_layout.setSpacing(12)

        left_title = QLabel("Scan Options")
        left_title.setFont(QFont("Segoe UI", 11, QFont.Weight.Bold))
        left_title.setStyleSheet("color: #0f172a;")
        left_layout.addWidget(left_title)

        self.network_radio = QRadioButton("Scan whole network")
        self.network_radio.setChecked(True)
        self.network_radio.setFont(QFont("Segoe UI", 10))

        self.single_radio = QRadioButton("Scan one device")
        self.single_radio.setFont(QFont("Segoe UI", 10))

        self.mode_group = QButtonGroup(self)
        self.mode_group.addButton(self.network_radio)
        self.mode_group.addButton(self.single_radio)

        left_layout.addWidget(self.network_radio)
        left_layout.addWidget(self.single_radio)

        dropdown_label = QLabel("Choose a device")
        dropdown_label.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
        dropdown_label.setStyleSheet("color: #475569;")
        left_layout.addWidget(dropdown_label)

        self.device_combo = QComboBox()
        self.device_combo.setEnabled(False)
        self.device_combo.setMinimumWidth(280)
        self.device_combo.setStyleSheet(
            "QComboBox {"
            "  background: white;"
            "  border: 1px solid #cbd5e1;"
            "  border-radius: 10px;"
            "  padding: 8px 10px;"
            "  color: #0f172a;"
            "  selection-background-color: #dbeafe;"
            "  selection-color: #0f172a;"
            "}"
            "QComboBox:disabled {"
            "  color: #94a3b8;"
            "  background: #f8fafc;"
            "}"
            "QComboBox QAbstractItemView {"
            "  background: white;"
            "  color: #0f172a;"
            "  border: 1px solid #cbd5e1;"
            "  selection-background-color: #dbeafe;"
            "  selection-color: #0f172a;"
            "  outline: 0;"
            "}"
        )
        left_layout.addWidget(self.device_combo)

        self.device_hint = QLabel("Run a full network scan first to populate this list.")
        self.device_hint.setWordWrap(True)
        self.device_hint.setStyleSheet("color: #64748b; font-size: 11px;")
        left_layout.addWidget(self.device_hint)
        left_layout.addStretch(1)

        center_panel = QFrame()
        center_panel.setStyleSheet("background: transparent;")
        center_layout = QVBoxLayout(center_panel)
        center_layout.setContentsMargins(0, 0, 0, 0)
        center_layout.setSpacing(18)
        center_layout.addStretch(1)

        self.scan_btn = QPushButton("SCAN NETWORK")
        self.scan_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.scan_btn.setFixedSize(360, 140)
        self.scan_btn.setFont(QFont("Segoe UI", 16, QFont.Weight.Bold))
        self.scan_btn.setStyleSheet(
            "QPushButton {"
            "  background: #2563eb;"
            "  color: white;"
            "  border: none;"
            "  border-radius: 18px;"
            "}"
            "QPushButton:hover {"
            "  background: #1d4ed8;"
            "}"
            "QPushButton:pressed {"
            "  background: #1e40af;"
            "}"
        )
        self.scan_btn.clicked.connect(self.scan_clicked.emit)

        ring = QFrame()
        ring.setFixedSize(390, 170)
        ring.setStyleSheet(
            "border: 4px solid rgba(37, 99, 235, 90);"
            "border-radius: 22px;"
            "background: transparent;"
        )
        ring_layout = QHBoxLayout(ring)
        ring_layout.setContentsMargins(10, 10, 10, 10)
        ring_layout.addWidget(self.scan_btn, alignment=Qt.AlignmentFlag.AlignCenter)

        center_layout.addWidget(ring, alignment=Qt.AlignmentFlag.AlignHCenter)
        center_layout.addStretch(1)

        right_panel = QFrame()
        right_panel.setStyleSheet(
            "background: white; border: 1px solid #e2e8f0; border-radius: 18px;"
        )
        right_layout = QVBoxLayout(right_panel)
        right_layout.setContentsMargins(18, 18, 18, 18)
        right_layout.setSpacing(12)

        right_title = QLabel("Last Scan")
        right_title.setFont(QFont("Segoe UI", 11, QFont.Weight.Bold))
        right_title.setStyleSheet("color: #0f172a;")
        right_layout.addWidget(right_title)

        self.last_scan_summary = QLabel("No previous scan data found.")
        self.last_scan_summary.setWordWrap(True)
        self.last_scan_summary.setStyleSheet("color: #64748b;")
        right_layout.addWidget(self.last_scan_summary)

        self.view_last_btn = QPushButton("View Last Scan")
        self.view_last_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.view_last_btn.setFixedHeight(38)
        self.view_last_btn.setStyleSheet(
            "QPushButton {"
            "  background: white;"
            "  color: #0f172a;"
            "  border: 1px solid #cbd5e1;"
            "  border-radius: 10px;"
            "  padding: 8px 12px;"
            "}"
            "QPushButton:hover {"
            "  background: #f8fafc;"
            "}"
            "QPushButton:disabled {"
            "  color: #94a3b8;"
            "  border-color: #e2e8f0;"
            "}"
        )
        self.view_last_btn.clicked.connect(self.view_last_scan_clicked.emit)
        right_layout.addWidget(self.view_last_btn)
        right_layout.addStretch(1)

        grid.addWidget(left_panel, 0, 0)
        grid.addWidget(center_panel, 0, 1)
        grid.addWidget(right_panel, 0, 2)

        grid.setColumnStretch(0, 1)
        grid.setColumnStretch(1, 1)
        grid.setColumnStretch(2, 1)

        outer.addLayout(grid)

        self.single_radio.toggled.connect(self._update_device_dropdown_state)
        self.network_radio.toggled.connect(self._update_device_dropdown_state)
        self.single_radio.toggled.connect(self._update_mode_styles)
        self.network_radio.toggled.connect(self._update_mode_styles)
        self.single_radio.toggled.connect(self._update_scan_button_text)
        self.network_radio.toggled.connect(self._update_scan_button_text)

        self._update_device_dropdown_state()
        self._update_mode_styles()
        self._update_scan_button_text()

    def _update_mode_styles(self):
        selected_style = (
            "QRadioButton {"
            "  color: #0f172a;"
            "  spacing: 10px;"
            "  padding: 8px 10px;"
            "  border-radius: 10px;"
            "  background: #dbeafe;"
            "  border: 1px solid #93c5fd;"
            "}"
            "QRadioButton::indicator { width: 16px; height: 16px; }"
            "QRadioButton::indicator:unchecked {"
            "  border: 2px solid #94a3b8;"
            "  border-radius: 8px;"
            "  background: white;"
            "}"
            "QRadioButton::indicator:checked {"
            "  border: 2px solid #2563eb;"
            "  border-radius: 8px;"
            "  background: #2563eb;"
            "}"
        )

        normal_style = (
            "QRadioButton {"
            "  color: #0f172a;"
            "  spacing: 10px;"
            "  padding: 8px 10px;"
            "  border-radius: 10px;"
            "  background: white;"
            "  border: 1px solid transparent;"
            "}"
            "QRadioButton::indicator { width: 16px; height: 16px; }"
            "QRadioButton::indicator:unchecked {"
            "  border: 2px solid #94a3b8;"
            "  border-radius: 8px;"
            "  background: white;"
            "}"
            "QRadioButton::indicator:checked {"
            "  border: 2px solid #2563eb;"
            "  border-radius: 8px;"
            "  background: #2563eb;"
            "}"
        )

        self.network_radio.setStyleSheet(selected_style if self.network_radio.isChecked() else normal_style)
        self.single_radio.setStyleSheet(selected_style if self.single_radio.isChecked() else normal_style)

    def _update_scan_button_text(self):
        if self.single_radio.isChecked():
            self.scan_btn.setText("SCAN DEVICE")
        else:
            self.scan_btn.setText("SCAN NETWORK")

    def _update_device_dropdown_state(self):
        enable_dropdown = self.single_radio.isChecked() and bool(self._devices)
        self.device_combo.setEnabled(enable_dropdown)

    def set_devices(self, devices: List[Tuple[str, str]]):
        self._devices = devices[:]
        self.device_combo.clear()

        if not devices:
            self.device_combo.setEnabled(False)
            self.device_hint.setText("Run a full network scan first to populate this list.")
        else:
            for ip, label in devices:
                self.device_combo.addItem(label, ip)
            self.device_hint.setText("Choose a previously discovered device to run a focused scan.")

        self._update_device_dropdown_state()

    def get_selected_mode(self) -> str:
        return "single" if self.single_radio.isChecked() else "network"

    def get_selected_target(self) -> Optional[str]:
        if self.get_selected_mode() != "single":
            return None
        if self.device_combo.count() == 0:
            return None
        return self.device_combo.currentData()

    def set_last_scan_available(self, is_available: bool, summary_text: str):
        self.last_scan_summary.setText(summary_text)
        self.view_last_btn.setEnabled(is_available)


class SpinnerWidget(QWidget):
    def __init__(self, diameter: int = 92):
        super().__init__()
        self._angle = 0
        self.setFixedSize(diameter, diameter)

        self._timer = QTimer(self)
        self._timer.timeout.connect(self._advance)
        self._timer.setInterval(40)

    def start(self):
        self._timer.start()

    def stop(self):
        self._timer.stop()

    def _advance(self):
        self._angle = (self._angle + 18) % 360
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        center = self.rect().center()
        radius = min(self.width(), self.height()) / 2 - 8

        for i in range(12):
            painter.save()
            painter.translate(center)
            painter.rotate(self._angle - i * 30)

            alpha = max(40, 255 - i * 18)
            pen = QPen(QColor(37, 99, 235, alpha))
            pen.setWidth(5)
            pen.setCapStyle(Qt.PenCapStyle.RoundCap)
            painter.setPen(pen)

            painter.drawLine(0, int(-radius * 0.65), 0, int(-radius))
            painter.restore()

        painter.end()


class ScanProgressPage(QWidget):
    cancel_clicked = pyqtSignal()

    def __init__(self):
        super().__init__()
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(20)

        outer.addStretch(1)

        self.spinner = SpinnerWidget(96)
        outer.addWidget(self.spinner, alignment=Qt.AlignmentFlag.AlignHCenter)

        self.title = QLabel("Scanning in Progress")
        self.title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.title.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        self.title.setStyleSheet("color: #1f2937;")
        outer.addWidget(self.title)

        self.subtitle = QLabel("Scanning the network, this could take a few minutes.")
        self.subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.subtitle.setWordWrap(True)
        self.subtitle.setFont(QFont("Segoe UI", 10))
        self.subtitle.setStyleSheet("color: #64748b;")
        outer.addWidget(self.subtitle)

        cancel = QPushButton("Cancel")
        cancel.setCursor(Qt.CursorShape.PointingHandCursor)
        cancel.setFixedHeight(38)
        cancel.setFixedWidth(120)
        cancel.setStyleSheet(
            "QPushButton {"
            "  background: white;"
            "  color: #0f172a;"
            "  border: 1px solid #e2e8f0;"
            "  border-radius: 10px;"
            "  padding: 6px 14px;"
            "}"
            "QPushButton:hover {"
            "  background: #f1f5f9;"
            "}"
        )
        cancel.clicked.connect(self.cancel_clicked.emit)
        outer.addWidget(cancel, alignment=Qt.AlignmentFlag.AlignHCenter)

        outer.addStretch(1)

    def start(self, scan_mode: str):
        if scan_mode == "single":
            self.subtitle.setText("Scanning the selected device, this could take a few minutes.")
        else:
            self.subtitle.setText("Scanning the network, this could take a few minutes.")
        self.spinner.start()

    def stop(self):
        self.spinner.stop()


class SeverityBadge(QLabel):
    def __init__(self, risk: str):
        super().__init__(risk.upper())
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setFont(QFont("Segoe UI", 8, QFont.Weight.Bold))
        self.setFixedHeight(22)
        self.setContentsMargins(10, 0, 10, 0)

        if risk in ("High", "Critical"):
            self.setStyleSheet(
                "background: #fee2e2; color: #b91c1c; border: 1px solid #fecaca; border-radius: 999px;"
            )
        elif risk == "Medium":
            self.setStyleSheet(
                "background: #fef3c7; color: #b45309; border: 1px solid #fde68a; border-radius: 999px;"
            )
        else:
            self.setStyleSheet(
                "background: #dbeafe; color: #1d4ed8; border: 1px solid #bfdbfe; border-radius: 999px;"
            )


class DeviceCard(QFrame):
    clicked = pyqtSignal(dict)

    def __init__(self, host_data: Dict[str, Any]):
        super().__init__()
        self.host_data = host_data
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setStyleSheet(
            "QFrame {"
            "  background: white;"
            "  border: 1px solid #e2e8f0;"
            "  border-radius: 14px;"
            "}"
            "QFrame:hover {"
            "  border: 1px solid #93c5fd;"
            "  background: #f8fbff;"
            "}"
        )

        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 14, 16, 14)
        layout.setSpacing(8)

        top = QHBoxLayout()
        top.setSpacing(10)

        title = QLabel(build_host_label(host_data))
        title.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
        title.setStyleSheet("color: #0f172a;")

        badge = SeverityBadge(get_highest_risk_for_host(host_data))

        top.addWidget(title)
        top.addStretch(1)
        top.addWidget(badge)
        layout.addLayout(top)

        ip = host_data.get("ip") or "unknown"
        vendor = get_host_vendor(host_data)
        open_ports = get_host_open_ports(host_data)
        port_count = len(open_ports)

        if port_count == 0:
            ports_summary = "No open ports detected"
        else:
            port_numbers = ", ".join(str(p.get("port", "?")) for p in open_ports[:5])
            if port_count > 5:
                port_numbers += ", ..."
            ports_summary = f"Open ports: {port_numbers}"

        details = QLabel(
            f"IP: {ip}\n"
            f"Vendor: {vendor}\n"
            f"{ports_summary}"
        )
        details.setWordWrap(True)
        details.setStyleSheet("color: #475569; line-height: 1.4;")
        layout.addWidget(details)

    def mousePressEvent(self, event):
        self.clicked.emit(self.host_data)
        super().mousePressEvent(event)


class ResultsPage(QWidget):
    new_scan_clicked = pyqtSignal()
    explain_device_clicked = pyqtSignal(dict)
    chat_question_submitted = pyqtSignal(dict, str, object)

    def __init__(self):
        super().__init__()
        self.current_host: Optional[Dict[str, Any]] = None
        self.current_hosts: List[Dict[str, Any]] = []
        self.last_port: Optional[int] = None

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(14)

        topbar = QHBoxLayout()

        title = QLabel("Scan Complete")
        title.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        title.setStyleSheet("color: #1f2937;")

        btn = QPushButton("New Scan")
        btn.setCursor(Qt.CursorShape.PointingHandCursor)
        btn.setFixedHeight(36)
        btn.setStyleSheet(
            "QPushButton {"
            "  background: white;"
            "  color: #0f172a;"
            "  border: 1px solid #e2e8f0;"
            "  border-radius: 10px;"
            "  padding: 6px 14px;"
            "}"
            "QPushButton:hover {"
            "  background: #f1f5f9;"
            "}"
        )
        btn.clicked.connect(self.new_scan_clicked.emit)

        topbar.addWidget(title)
        topbar.addStretch(1)
        topbar.addWidget(btn)
        outer.addLayout(topbar)

        grid = QGridLayout()
        grid.setHorizontalSpacing(18)
        grid.setVerticalSpacing(18)

        left = QWidget()
        left_layout = QVBoxLayout(left)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(10)

        # Header row (title + risk label)
        header_row = QHBoxLayout()

        left_header = QLabel("Discovered Devices")
        left_header.setFont(QFont("Segoe UI", 11, QFont.Weight.Bold))
        left_header.setStyleSheet("color: #334155;")

        risk_label = QLabel("RISK")
        risk_label.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
        risk_label.setStyleSheet("color: #64748b; padding-right: 6px;")

        header_row.addWidget(left_header)
        header_row.addStretch(1)
        header_row.addWidget(risk_label)

        left_layout.addLayout(header_row)

        self.device_scroll = QScrollArea()
        self.device_scroll.setWidgetResizable(True)
        self.device_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.device_scroll.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self.device_scroll.setStyleSheet(
            "QScrollArea { border: none; background: transparent; }"
            "QScrollBar:vertical {"
            "  background: #f8fafc;"
            "  width: 10px;"
            "  margin: 0px;"
            "  border-radius: 5px;"
            "}"
            "QScrollBar::handle:vertical {"
            "  background: #cbd5e1;"
            "  min-height: 24px;"
            "  border-radius: 5px;"
            "}"
            "QScrollBar::handle:vertical:hover {"
            "  background: #94a3b8;"
            "}"
            "QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {"
            "  height: 0px;"
            "}"
        )
        self.device_scroll.setMinimumHeight(420)

        self.device_container = QWidget()
        self.device_vbox = QVBoxLayout(self.device_container)
        self.device_vbox.setContentsMargins(0, 0, 0, 0)
        self.device_vbox.setSpacing(10)
        self.device_vbox.addStretch(1)

        self.device_scroll.setWidget(self.device_container)
        left_layout.addWidget(self.device_scroll, 1)

        right = QWidget()
        right_layout = QVBoxLayout(right)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(12)

        self.device_title = QLabel("Select a device")
        self.device_title.setFont(QFont("Segoe UI", 12, QFont.Weight.Bold))
        self.device_title.setStyleSheet("color: #1f2937;")
        right_layout.addWidget(self.device_title)

        self.device_info = QLabel("Choose a device from the list to request an explanation.")
        self.device_info.setWordWrap(True)
        self.device_info.setStyleSheet("color: #64748b;")
        right_layout.addWidget(self.device_info)

        self.explain_btn = QPushButton("Explain This Device")
        self.explain_btn.setEnabled(False)
        self.explain_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.explain_btn.setFixedHeight(40)
        self.explain_btn.setStyleSheet(
            "QPushButton {"
            "  background: #2563eb;"
            "  color: white;"
            "  border: none;"
            "  border-radius: 10px;"
            "  padding: 8px 14px;"
            "}"
            "QPushButton:hover {"
            "  background: #1d4ed8;"
            "}"
            "QPushButton:disabled {"
            "  background: #cbd5e1;"
            "  color: #f8fafc;"
            "}"
        )
        self.explain_btn.clicked.connect(self._emit_explain_current_host)
        right_layout.addWidget(self.explain_btn)

        convo_header = QLabel("Security Analysis and Follow-up")
        convo_header.setFont(QFont("Segoe UI", 11, QFont.Weight.Bold))
        convo_header.setStyleSheet("color: #334155;")
        right_layout.addWidget(convo_header)

        self.conversation_box = QTextEdit()
        self.conversation_box.setReadOnly(True)
        self.conversation_box.setAcceptRichText(False)
        self.conversation_box.setLineWrapMode(QTextEdit.LineWrapMode.WidgetWidth)
        self.conversation_box.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self.conversation_box.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.conversation_box.setStyleSheet(
            "QTextEdit {"
            "  background: white;"
            "  border: 1px solid #e0e7ff;"
            "  border-radius: 14px;"
            "  color: #334155;"
            "  font-size: 12px;"
            "  padding: 10px;"
            "}"
            "QScrollBar:vertical {"
            "  background: #f8fafc;"
            "  width: 10px;"
            "  margin: 0px;"
            "  border-radius: 5px;"
            "}"
            "QScrollBar::handle:vertical {"
            "  background: #cbd5e1;"
            "  min-height: 24px;"
            "  border-radius: 5px;"
            "}"
            "QScrollBar::handle:vertical:hover {"
            "  background: #94a3b8;"
            "}"
            "QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {"
            "  height: 0px;"
            "}"
        )
        self.conversation_box.setFixedHeight(250)
        self.conversation_box.setPlainText("No device explanation generated yet.")
        right_layout.addWidget(self.conversation_box)

        chat_hint = QLabel("Need more detail? Ask a question about this device or its ports below.")
        chat_hint.setWordWrap(True)
        chat_hint.setStyleSheet("color: #64748b; font-size: 11px;")
        right_layout.addWidget(chat_hint)

        chat_row = QHBoxLayout()

        self.chat_input = QLineEdit()
        self.chat_input.setPlaceholderText("Ask about this device or its ports")
        self.chat_input.setStyleSheet(
            "QLineEdit {"
            "  background: white;"
            "  border: 1px solid #cbd5e1;"
            "  border-radius: 10px;"
            "  padding: 10px 12px;"
            "  color: #0f172a;"
            "}"
        )
        chat_row.addWidget(self.chat_input)

        self.send_chat_btn = QPushButton("Send")
        self.send_chat_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.send_chat_btn.setFixedHeight(40)
        self.send_chat_btn.setStyleSheet(
            "QPushButton {"
            "  background: #2563eb;"
            "  color: white;"
            "  border: none;"
            "  border-radius: 10px;"
            "  padding: 8px 14px;"
            "}"
            "QPushButton:hover {"
            "  background: #1d4ed8;"
            "}"
            "QPushButton:disabled {"
            "  background: #cbd5e1;"
            "  color: #f8fafc;"
            "}"
        )
        chat_row.addWidget(self.send_chat_btn)

        right_layout.addLayout(chat_row)
        right_layout.addStretch(1)

        self.send_chat_btn.clicked.connect(self._send_chat_question)
        self.chat_input.returnPressed.connect(self._send_chat_question)

        grid.addWidget(left, 0, 0)
        grid.addWidget(right, 0, 1)
        grid.setColumnStretch(0, 1)
        grid.setColumnStretch(1, 2)

        outer.addLayout(grid)

    def set_hosts(self, hosts: List[Dict[str, Any]]):
        sorted_hosts = sort_hosts_by_risk(hosts)
        self.current_hosts = sorted_hosts
        self.current_host = None

        while self.device_vbox.count():
            item = self.device_vbox.takeAt(0)
            w = item.widget()
            if w:
                w.deleteLater()

        if not sorted_hosts:
            empty = QLabel("No devices were found.")
            empty.setStyleSheet("color: #64748b;")
            self.device_vbox.addWidget(empty)
            self.device_vbox.addStretch(1)
        else:
            for host_data in sorted_hosts:
                card = DeviceCard(host_data)
                card.clicked.connect(self.select_host)
                self.device_vbox.addWidget(card)
            self.device_vbox.addStretch(1)

        self.clear_device_details()
        self.device_scroll.verticalScrollBar().setValue(0)

    def clear_device_details(self):
        self.current_host = None
        self.last_port = None
        self.device_title.setText("Select a device")
        self.device_info.setText("Choose a device from the list to request an explanation.")
        self.explain_btn.setEnabled(False)
        self.conversation_box.setPlainText("No device explanation generated yet.")
        self.conversation_box.verticalScrollBar().setValue(0)
        self.set_chat_enabled(False)

    def select_host(self, host_data: Dict[str, Any]):
        self.current_host = host_data
        self.last_port = None
        self.device_title.setText(build_host_label(host_data))

        open_ports = get_host_open_ports(host_data)
        if open_ports:
            port_summary = ", ".join(str(p.get("port", "?")) for p in open_ports)
        else:
            port_summary = "None"

        self.device_info.setText(f"Open ports: {port_summary}")

        self.explain_btn.setEnabled(True)
        self.conversation_box.setPlainText("Select “Explain This Device” for a quick summary, or ask a question below.")
        self.conversation_box.verticalScrollBar().setValue(0)
        self.set_chat_enabled(True)

    def _emit_explain_current_host(self):
        if self.current_host:
            self.explain_device_clicked.emit(self.current_host)

    def _send_chat_question(self):
        if not self.current_host:
            return

        question = self.chat_input.text().strip()

        if not question or all(ch in ".!?,-_ " for ch in question):
            self.append_conversation(
                "AI",
                "I didn’t quite understand that. Try asking about a specific port or service on this device."
            )
            self.chat_input.clear()
            return

        extracted_port = self._extract_port_from_question(question)
        if extracted_port is not None:
            self.last_port = extracted_port

        self.append_conversation("You", question)
        self.chat_input.clear()
        self.chat_question_submitted.emit(self.current_host, question, self.last_port)

    def set_initial_explanation(self, text: str):
        self.conversation_box.setPlainText(text or "No AI explanation was generated.")
        self.conversation_box.verticalScrollBar().setValue(0)

    def append_conversation(self, sender: str, message: str):
        current = self.conversation_box.toPlainText().strip()
        new_block = f"{sender}:\n{message}"

        if current and current != "No device explanation generated yet.":
            self.conversation_box.append("")
            self.conversation_box.append(new_block)
        else:
            self.conversation_box.setPlainText(new_block)

        self.conversation_box.verticalScrollBar().setValue(
            self.conversation_box.verticalScrollBar().maximum()
        )

    def set_chat_enabled(self, enabled: bool):
        self.chat_input.setEnabled(enabled)
        self.send_chat_btn.setEnabled(enabled)

    def set_explain_button_enabled(self, enabled: bool):
        self.explain_btn.setEnabled(enabled)


    def _extract_port_from_question(self, question: str) -> Optional[int]:
        import re

        match = re.search(r"\bport\s+(\d{1,5})\b", question.lower())
        if match:
            try:
                return int(match.group(1))
            except ValueError:
                return None

        return None


class ExposureApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("AI-Assisted Network Exposure Analyser")
        self.resize(1220, 760)

        self.worker: Optional[ScanWorker] = None
        self.ai_worker: Optional[AIWorker] = None
        self.chat_worker: Optional[ChatWorker] = None
        self.last_hosts: List[Dict[str, Any]] = []
        self.last_exposures: List[Exposure] = []
        self.last_ai_text: str = ""
        self.last_xml_path: Optional[str] = None

        root = QWidget()
        root.setStyleSheet("background: #f8fafc;")
        self.setCentralWidget(root)

        main = QVBoxLayout(root)
        main.setContentsMargins(0, 0, 0, 0)
        main.setSpacing(0)

        main.addWidget(Header())
        main.addWidget(self._divider())

        body = QWidget()
        body_layout = QVBoxLayout(body)
        body_layout.setContentsMargins(24, 24, 24, 24)

        self.stack = QStackedWidget()
        self.stack.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)

        self.page_dashboard = DashboardPage()
        self.page_scan = ScanProgressPage()
        self.page_results = ResultsPage()

        self.stack.addWidget(self.page_dashboard)
        self.stack.addWidget(self.page_scan)
        self.stack.addWidget(self.page_results)

        body_layout.addWidget(self.stack)
        main.addWidget(body)

        self.page_dashboard.scan_clicked.connect(self.start_scan)
        self.page_dashboard.view_last_scan_clicked.connect(self.view_last_scan)
        self.page_scan.cancel_clicked.connect(self.cancel_scan)
        self.page_results.new_scan_clicked.connect(self.go_dashboard)
        self.page_results.explain_device_clicked.connect(self.explain_selected_device)
        self.page_results.chat_question_submitted.connect(self.handle_chat_question)

        self._load_last_scan_from_disk()
        self.go_dashboard()

    def _divider(self):
        line = QFrame()
        line.setFixedHeight(1)
        line.setStyleSheet("background: #e2e8f0;")
        return line

    def _load_last_scan_from_disk(self):
        latest = find_latest_scan_file("scans")
        if not latest:
            self.page_dashboard.set_devices([])
            self.page_dashboard.set_last_scan_available(False, "No previous scan data found.")
            return

        try:
            hosts = parse_nmap_xml(str(latest))
            exposures = build_exposures(hosts)

            self.last_hosts = hosts
            self.last_exposures = exposures
            self.last_ai_text = ""
            self.last_xml_path = str(latest)

            devices = build_device_choices(hosts)
            self.page_dashboard.set_devices(devices)
            self.page_dashboard.set_last_scan_available(True, host_list_summary(hosts))

        except Exception:
            self.page_dashboard.set_devices([])
            self.page_dashboard.set_last_scan_available(False, "Previous scan data could not be loaded.")

    def go_dashboard(self):
        if self.worker and self.worker.isRunning():
            self.worker.cancel()
        if self.ai_worker and self.ai_worker.isRunning():
            self.ai_worker.quit()
            self.ai_worker.wait()
        if self.chat_worker and self.chat_worker.isRunning():
            self.chat_worker.quit()
            self.chat_worker.wait()

        self.page_scan.stop()
        self.stack.setCurrentWidget(self.page_dashboard)

    def _resolve_scan_target(self) -> Tuple[str, str]:
        mode = self.page_dashboard.get_selected_mode()

        info = detect_active_subnet()
        if not info:
            raise RuntimeError("Could not determine the active network or subnet.")

        if mode == "single":
            selected_target = self.page_dashboard.get_selected_target()
            if not selected_target:
                raise RuntimeError("No device is available for single-device scanning yet. Run a full network scan first.")
            return mode, selected_target

        target = info.get("network")
        if not target:
            raise RuntimeError("Detected subnet had no CIDR network value.")
        return mode, target

    def start_scan(self):
        try:
            scan_mode, target = self._resolve_scan_target()
        except Exception as e:
            QMessageBox.critical(self, "Scan setup failed", str(e))
            return

        self.page_scan.start(scan_mode)
        self.stack.setCurrentWidget(self.page_scan)

        self.worker = ScanWorker(target=target, output_dir="scans")
        self.worker.finished_ok.connect(self.on_scan_finished_ok)
        self.worker.finished_err.connect(self.on_scan_finished_err)
        self.worker.start()

    def cancel_scan(self):
        if self.worker and self.worker.isRunning():
            self.worker.cancel()
        self.go_dashboard()

    def on_scan_finished_ok(self, hosts: list, exposures: list, xml_path: str):
        self.page_scan.stop()

        self.last_hosts = hosts
        self.last_exposures = exposures
        self.last_xml_path = xml_path
        self.last_ai_text = ""

        devices = build_device_choices(hosts)
        self.page_dashboard.set_devices(devices)
        self.page_dashboard.set_last_scan_available(True, host_list_summary(hosts))

        self.page_results.set_hosts(hosts)
        self.stack.setCurrentWidget(self.page_results)

    def on_scan_finished_err(self, err: str):
        self.page_scan.stop()
        QMessageBox.critical(self, "Scan failed", err)
        self.go_dashboard()

    def view_last_scan(self):
        if not self.last_hosts:
            QMessageBox.information(self, "Last Scan", "No previous scan results are available.")
            return

        self.page_results.set_hosts(self.last_hosts)
        self.stack.setCurrentWidget(self.page_results)

    def explain_selected_device(self, host_data: Dict[str, Any]):
        selected_ip = host_data.get("ip") or ""

        if not selected_ip:
            self.page_results.set_initial_explanation(
                "AI analysis could not be generated because the selected device has no valid IP address."
            )
            return

        if not self.last_xml_path:
            self.page_results.set_initial_explanation(
                "AI analysis could not be generated because no scan file is available."
            )
            return

        if self.ai_worker and self.ai_worker.isRunning():
            self.page_results.set_initial_explanation(
                "An explanation is already being generated.\n\nShould take a few moments."
            )
            return

        self.page_results.set_explain_button_enabled(False)
        self.page_results.set_initial_explanation(
            "Generating explanation for the selected device.\n\nShould take a few moments."
        )

        self.ai_worker = AIWorker(self.last_xml_path, selected_ip)
        self.ai_worker.finished_ok.connect(self.on_ai_finished_ok)
        self.ai_worker.finished_err.connect(self.on_ai_finished_err)
        self.ai_worker.start()

    def on_ai_finished_ok(self, ai_text: str):
        self.last_ai_text = ai_text
        self.page_results.set_initial_explanation(ai_text)
        self.page_results.set_explain_button_enabled(True)

    def on_ai_finished_err(self, err: str):
        self.page_results.set_initial_explanation(
            f"AI analysis could not be generated.\n\nReason: {err}"
        )
        self.page_results.set_explain_button_enabled(True)

    def handle_chat_question(self, host_data: Dict[str, Any], question: str, last_port: Optional[int]):
        selected_ip = host_data.get("ip") or ""

        if not selected_ip:
            self.page_results.append_conversation(
                "AI",
                "I could not answer that because the selected device has no valid IP address."
            )
            return

        if not self.last_xml_path:
            self.page_results.append_conversation(
                "AI",
                "I could not answer that because no scan file is available."
            )
            return

        if self.chat_worker and self.chat_worker.isRunning():
            self.page_results.append_conversation(
                "AI",
                "Please wait for the current reply to finish."
            )
            return

        self.page_results.set_chat_enabled(False)
        self.page_results.append_conversation("AI", "Thinking...")

        self.chat_worker = ChatWorker(self.last_xml_path, selected_ip, question, last_port)
        self.chat_worker.finished_ok.connect(self.on_chat_finished_ok)
        self.chat_worker.finished_err.connect(self.on_chat_finished_err)
        self.chat_worker.start()
        

    def on_chat_finished_ok(self, reply: str):
        history = self.page_results.conversation_box.toPlainText()
        if history.endswith("AI:\nThinking..."):
            history = history[:-len("AI:\nThinking...")].rstrip()
            self.page_results.conversation_box.setPlainText(history)

        self.page_results.append_conversation("AI", reply)
        self.page_results.set_chat_enabled(True)

    def on_chat_finished_err(self, err: str):
        history = self.page_results.conversation_box.toPlainText()
        if history.endswith("AI:\nThinking..."):
            history = history[:-len("AI:\nThinking...")].rstrip()
            self.page_results.conversation_box.setPlainText(history)

        self.page_results.append_conversation("AI", f"I could not answer that.\n\nReason: {err}")
        self.page_results.set_chat_enabled(True)


def main():
    app = QApplication(sys.argv)
    window = ExposureApp()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()