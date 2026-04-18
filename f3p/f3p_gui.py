#!/usr/bin/env python3
"""
f3p_gui - PyQt6 frontend for f3p.

Runs the scan on a background thread so the UI stays responsive, provides a
Wireless Debugging pairing helper (which is where most users get stuck), and
renders findings with proper severity color coding.
"""

import json
import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path

try:
    from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer, QSize
    from PyQt6.QtGui import QAction, QFont, QIcon, QPalette, QColor
    from PyQt6.QtWidgets import (
        QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
        QPushButton, QLabel, QLineEdit, QTextEdit, QListWidget, QListWidgetItem,
        QProgressBar, QComboBox, QCheckBox, QFileDialog, QMessageBox,
        QDialog, QDialogButtonBox, QGridLayout, QSplitter, QTabWidget,
        QPlainTextEdit, QGroupBox, QStatusBar, QSizePolicy, QScrollArea,
        QFrame,
    )
except ImportError as e:
    raise ImportError("PyQt6 is required. Install with: sudo dnf install python3-pyqt6") from e

# Import the scanner module - try both layouts:
#   - source tree:  ../f3p/f3p.py (sibling directory)
#   - installed:    ./f3p.py (same LIBDIR)
_here = Path(__file__).parent
for _p in (_here, _here.parent / "f3p"):
    if (_p / "f3p.py").exists():
        sys.path.insert(0, str(_p))
        break
import f3p as ds


# ---------------------------------------------------------------------------
# Severity colours
# Chosen to have reasonable contrast against both light and dark system
# themes. No custom palette or stylesheet is applied - the rest of the UI
# follows whatever theme the user's desktop environment is using.
# ---------------------------------------------------------------------------

SEVERITY_COLORS = {
    "CRITICAL": "#c0392b",   # dark red
    "HIGH":     "#d35400",   # dark orange
    "WARN":     "#b7950b",   # dark yellow
    "INFO":     "#2874a6",   # dark blue
}




# ---------------------------------------------------------------------------
# Scan worker thread
# ---------------------------------------------------------------------------

class ScanWorker(QThread):
    stage_changed = pyqtSignal(str)          # stage name
    apk_progress  = pyqtSignal(int, int, str) # i, total, pkg
    log_message   = pyqtSignal(str)
    scan_finished = pyqtSignal(dict)
    scan_failed   = pyqtSignal(str)

    def __init__(self, serial, outdir, skip_apks, apk_limit):
        super().__init__()
        self.serial = serial
        self.outdir = outdir
        self.skip_apks = skip_apks
        self.apk_limit = apk_limit

    def run(self):
        try:
            adb = ds.ADB(serial=self.serial if self.serial else None)
            devs = adb.devices()
            if not devs:
                self.scan_failed.emit("No ADB devices found.")
                return
            for serial, state in devs:
                if state == "unauthorized":
                    self.scan_failed.emit(
                        f"Device {serial} is UNAUTHORIZED. Accept the RSA "
                        f"prompt on the phone and retry.")
                    return
                if state == "offline":
                    self.scan_failed.emit(f"Device {serial} is OFFLINE.")
                    return
            self.log_message.emit(f"Devices: {devs}")

            def cb(stage, extra):
                if stage == "apks":
                    i, total, pkg = extra
                    self.apk_progress.emit(i, total, pkg)
                else:
                    self.stage_changed.emit(stage)
                    labels = {
                        "getprop":  "Dumping getprop...",
                        "proc":     "Reading /proc/meminfo and /proc/cpuinfo...",
                        "storage":  "Reading storage...",
                        "packages": "Listing packages...",
                        "network":  "Capturing network sockets...",
                        "analyze":  "Analyzing findings...",
                        "report":   "Writing report...",
                    }
                    if stage in labels:
                        self.log_message.emit(labels[stage])

            result = ds.run_scan(adb, self.outdir,
                                  skip_apks=self.skip_apks,
                                  apk_limit=self.apk_limit,
                                  progress_cb=cb)
            self.scan_finished.emit(result)
        except ds.ADBError as e:
            self.scan_failed.emit(str(e))
        except Exception as e:
            self.scan_failed.emit(f"Unexpected error: {e}")


# ---------------------------------------------------------------------------
# Pair dialog for Wireless Debugging
# ---------------------------------------------------------------------------

class PairDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Pair via Wireless Debugging")
        self.setMinimumWidth(520)
        layout = QVBoxLayout(self)

        explain = QLabel(
            "<b>On the phone:</b><br>"
            "1. Enable Developer Options (tap Build number 7x)<br>"
            "2. Settings → Developer options → Wireless debugging → ON<br>"
            "3. Tap <b>Pair device with pairing code</b><br>"
            "4. Note the IP, pairing port, and 6-digit code<br><br>"
            "<b>Then enter those below:</b>"
        )
        explain.setWordWrap(True)
        layout.addWidget(explain)

        grid = QGridLayout()
        grid.addWidget(QLabel("Phone IP:"), 0, 0)
        self.ip_edit = QLineEdit("192.168.1.")
        grid.addWidget(self.ip_edit, 0, 1)
        grid.addWidget(QLabel("Pairing port:"), 1, 0)
        self.pair_port_edit = QLineEdit()
        self.pair_port_edit.setPlaceholderText("e.g. 38677 (from pairing dialog)")
        grid.addWidget(self.pair_port_edit, 1, 1)
        grid.addWidget(QLabel("Pairing code:"), 2, 0)
        self.code_edit = QLineEdit()
        self.code_edit.setPlaceholderText("6 digits")
        grid.addWidget(self.code_edit, 2, 1)
        grid.addWidget(QLabel("Connect port:"), 3, 0)
        self.connect_port_edit = QLineEdit()
        self.connect_port_edit.setPlaceholderText(
            "from main Wireless Debugging screen (NOT the pairing port)")
        grid.addWidget(self.connect_port_edit, 3, 1)
        layout.addLayout(grid)

        self.output = QPlainTextEdit()
        self.output.setReadOnly(True)
        self.output.setMaximumHeight(120)
        self.output.setPlaceholderText("Output will appear here...")
        layout.addWidget(self.output)

        btns = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Close)
        self.pair_btn = btns.addButton("Pair", QDialogButtonBox.ButtonRole.ActionRole)
        self.connect_btn = btns.addButton("Connect", QDialogButtonBox.ButtonRole.ActionRole)
        self.pair_btn.setObjectName("primary")
        self.pair_btn.clicked.connect(self._do_pair)
        self.connect_btn.clicked.connect(self._do_connect)
        btns.rejected.connect(self.reject)
        layout.addWidget(btns)

    def _run(self, args):
        self.output.appendPlainText(f"$ {' '.join(args)}")
        try:
            r = subprocess.run(args, capture_output=True, text=True, timeout=30)
            if r.stdout:
                self.output.appendPlainText(r.stdout.strip())
            if r.stderr:
                self.output.appendPlainText(r.stderr.strip())
            return r.returncode == 0
        except subprocess.TimeoutExpired:
            self.output.appendPlainText("(timeout)")
            return False
        except FileNotFoundError:
            self.output.appendPlainText("adb not found in PATH")
            return False

    def _do_pair(self):
        ip = self.ip_edit.text().strip()
        port = self.pair_port_edit.text().strip()
        code = self.code_edit.text().strip()
        if not ip or not port or not code:
            self.output.appendPlainText("Fill in IP, pairing port, and code first.")
            return
        # adb pair is interactive - pipe code via stdin
        self.output.appendPlainText(f"$ adb pair {ip}:{port}")
        try:
            r = subprocess.run(["adb", "pair", f"{ip}:{port}"],
                               input=code + "\n",
                               capture_output=True, text=True, timeout=30)
            if r.stdout:
                self.output.appendPlainText(r.stdout.strip())
            if r.stderr:
                self.output.appendPlainText(r.stderr.strip())
        except Exception as e:
            self.output.appendPlainText(f"Error: {e}")

    def _do_connect(self):
        ip = self.ip_edit.text().strip()
        port = self.connect_port_edit.text().strip()
        if not ip or not port:
            self.output.appendPlainText("Fill in IP and connect port first.")
            return
        self._run(["adb", "connect", f"{ip}:{port}"])


# ---------------------------------------------------------------------------
# Main window
# ---------------------------------------------------------------------------

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("f3p")
        self.resize(1100, 780)
        self.worker = None

        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(16, 12, 16, 12)
        root.setSpacing(10)

        # ---------- Header ----------
        title_row = QHBoxLayout()
        title = QLabel("f3p")
        title.setObjectName("title")
        title_row.addWidget(title)
        subtitle = QLabel(f"v{ds.__version__} — Fight Phone Fraud")
        subtitle.setObjectName("subtitle")
        title_row.addWidget(subtitle)
        title_row.addStretch()
        self.load_btn = QPushButton("Load scan…")
        self.load_btn.setToolTip(
            "Open a previous report.json and populate the tabs from it. "
            "Useful for reviewing past scans or reports shared by others.")
        self.load_btn.clicked.connect(self.load_scan)
        title_row.addWidget(self.load_btn)
        self.doctor_btn = QPushButton("Check environment")
        self.doctor_btn.clicked.connect(self.run_doctor)
        title_row.addWidget(self.doctor_btn)
        root.addLayout(title_row)

        # ---------- Device selector row ----------
        dev_group = QGroupBox("Device")
        dev_lay = QHBoxLayout(dev_group)
        dev_lay.addWidget(QLabel("Serial:"))
        self.device_combo = QComboBox()
        self.device_combo.setMinimumWidth(340)
        dev_lay.addWidget(self.device_combo)
        refresh_btn = QPushButton("Refresh")
        refresh_btn.clicked.connect(self.refresh_devices)
        dev_lay.addWidget(refresh_btn)
        pair_btn = QPushButton("Pair wireless…")
        pair_btn.clicked.connect(self.open_pair_dialog)
        dev_lay.addWidget(pair_btn)
        dev_lay.addStretch()
        root.addWidget(dev_group)

        # ---------- Scan options row ----------
        opt_group = QGroupBox("Scan options")
        opt_lay = QHBoxLayout(opt_group)
        self.skip_apks = QCheckBox("Skip APK pull (faster)")
        self.skip_apks.setToolTip(
            "Skip downloading system APKs. Findings still work - you just lose "
            "the offline APK files for VirusTotal/MobSF later.")
        opt_lay.addWidget(self.skip_apks)
        opt_lay.addWidget(QLabel("Output:"))
        self.outdir_edit = QLineEdit(
            f"./scan-{datetime.now():%Y%m%d-%H%M%S}")
        opt_lay.addWidget(self.outdir_edit, 1)
        browse_btn = QPushButton("Browse…")
        browse_btn.clicked.connect(self.browse_outdir)
        opt_lay.addWidget(browse_btn)
        self.scan_btn = QPushButton("Scan")
        self.scan_btn.setObjectName("primary")
        self.scan_btn.clicked.connect(self.start_scan)
        opt_lay.addWidget(self.scan_btn)
        root.addWidget(opt_group)

        # ---------- Progress ----------
        prog_group = QGroupBox("Progress")
        prog_lay = QVBoxLayout(prog_group)
        self.progress_label = QLabel("Idle.")
        prog_lay.addWidget(self.progress_label)
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        prog_lay.addWidget(self.progress_bar)
        root.addWidget(prog_group)

        # ---------- Results tabs ----------
        self.verdict_label = QLabel("No scan run yet.")
        self.verdict_label.setObjectName("verdict_ok")
        self.verdict_label.setWordWrap(True)
        root.addWidget(self.verdict_label)

        self.tabs = QTabWidget()
        # Findings
        self.findings_list = QListWidget()
        self.findings_list.setWordWrap(True)
        self.tabs.addTab(self.findings_list, "Findings")
        # Props
        # Properties tab - spec card at top, full raw getprop below
        props_tab = QWidget()
        props_layout = QVBoxLayout(props_tab)
        props_layout.setContentsMargins(4, 4, 4, 4)

        # Top: a scrollable grid of spec group boxes
        self.spec_scroll = QScrollArea()
        self.spec_scroll.setWidgetResizable(True)
        self.spec_scroll.setFrameShape(QFrame.Shape.NoFrame)
        self.spec_container = QWidget()
        self.spec_grid = QGridLayout(self.spec_container)
        self.spec_grid.setContentsMargins(0, 0, 0, 0)
        self.spec_grid.setSpacing(6)
        placeholder = QLabel("Run a scan to see device specs here.")
        placeholder.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.spec_grid.addWidget(placeholder, 0, 0)
        self.spec_scroll.setWidget(self.spec_container)
        props_layout.addWidget(self.spec_scroll, stretch=3)

        # Bottom: full raw properties dump in a collapsible-ish text area
        raw_label = QLabel("All properties (raw getprop):")
        props_layout.addWidget(raw_label)
        self.props_view = QPlainTextEdit()
        self.props_view.setReadOnly(True)
        self.props_view.setFont(QFont("monospace"))
        props_layout.addWidget(self.props_view, stretch=2)

        self.tabs.addTab(props_tab, "Properties")
        # Packages
        self.packages_view = QPlainTextEdit()
        self.packages_view.setReadOnly(True)
        self.packages_view.setFont(QFont("monospace"))
        self.tabs.addTab(self.packages_view, "Packages")
        # Log
        self.log_view = QPlainTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setFont(QFont("monospace"))
        self.tabs.addTab(self.log_view, "Log")
        root.addWidget(self.tabs, 1)

        # ---------- Status bar ----------
        self.status = QStatusBar()
        self.setStatusBar(self.status)
        self.status.showMessage("Ready. Click 'Refresh' to detect devices.")

        # Initial refresh
        QTimer.singleShot(150, self.refresh_devices)

    # --- Helpers ---

    def log(self, msg):
        ts = datetime.now().strftime("%H:%M:%S")
        self.log_view.appendPlainText(f"[{ts}] {msg}")

    def refresh_devices(self):
        self.device_combo.clear()
        try:
            adb = ds.ADB()
            devs = adb.devices()
        except ds.ADBError as e:
            self.status.showMessage(str(e))
            self.log(f"ERROR: {e}")
            return
        if not devs:
            self.device_combo.addItem("(no devices)")
            self.device_combo.setEnabled(False)
            self.scan_btn.setEnabled(False)
            self.status.showMessage(
                "No devices. Plug in via USB, or use 'Pair wireless…'.")
            self.log("No ADB devices found.")
            return
        self.device_combo.setEnabled(True)
        for serial, state in devs:
            marker = "" if state == "device" else f" [{state}]"
            self.device_combo.addItem(f"{serial}{marker}", userData=serial)
        self.scan_btn.setEnabled(True)
        self.status.showMessage(f"{len(devs)} device(s) detected.")
        self.log(f"Found devices: {devs}")

    def browse_outdir(self):
        d = QFileDialog.getExistingDirectory(
            self, "Choose output directory", str(Path.home()))
        if d:
            self.outdir_edit.setText(d)

    def open_pair_dialog(self):
        dlg = PairDialog(self)
        dlg.exec()
        self.refresh_devices()

    def run_doctor(self):
        self.log("Running doctor checks...")
        try:
            adb_path = __import__("shutil").which("adb")
            if adb_path:
                r = subprocess.run(["adb", "--version"],
                                   capture_output=True, text=True)
                self.log(f"adb: {adb_path} ({r.stdout.splitlines()[0]})")
            else:
                self.log("FAIL: adb not found. Install android-tools.")
                QMessageBox.critical(self, "adb missing",
                    "adb is not installed.\n\n"
                    "Fedora/RHEL:  sudo dnf install android-tools\n"
                    "Debian/Ubuntu: sudo apt install android-tools-adb")
                return
            try:
                import PyQt6
                self.log(f"PyQt6: {PyQt6.QtCore.PYQT_VERSION_STR}")
            except ImportError:
                pass
            self.log("Environment OK.")
            self.tabs.setCurrentWidget(self.log_view)
        except Exception as e:
            self.log(f"ERROR: {e}")

    def load_scan(self):
        """Open a previous report.json and populate the tabs from it."""
        path, _ = QFileDialog.getOpenFileName(
            self, "Open f3p report", "",
            "f3p report (report.json);;JSON (*.json);;All files (*)")
        if not path:
            return
        try:
            with open(path) as fh:
                data = json.load(fh)
        except (OSError, json.JSONDecodeError) as e:
            QMessageBox.critical(self, "Cannot load report",
                f"Failed to read {path}:\n{e}")
            return

        # Sanity-check it looks like one of our reports
        if not isinstance(data, dict) or "props" not in data or "findings" not in data:
            QMessageBox.warning(self, "Not an f3p report",
                f"{path} doesn't look like an f3p report.json\n"
                f"(missing 'props' and/or 'findings' keys)")
            return

        tool_ver = data.get("tool_version", "unknown")
        scan_ts = data.get("scan_timestamp", "?")
        self.log(f"Loaded report: {path}")
        self.log(f"  tool version: {tool_ver}, scan time: {scan_ts}")

        # Rebuild a result dict in the shape on_scan_done expects
        findings_raw = data.get("findings", [])
        findings = []
        for f in findings_raw:
            if isinstance(f, dict):
                findings.append((f.get("severity", "INFO"),
                                 f.get("message", "")))
            elif isinstance(f, (list, tuple)) and len(f) >= 2:
                findings.append((f[0], f[1]))
        pkg_sys = [(p["pkg"], p["path"])
                   for p in data.get("packages_system", [])
                   if isinstance(p, dict)]
        pkg_usr = [(p["pkg"], p["path"])
                   for p in data.get("packages_user", [])
                   if isinstance(p, dict)]

        # Prefer the loaded findings as-is. If a report predates a detection
        # rule, re-running analyze() against stored props/packages can surface
        # new findings - offer that as a toggle via the log.
        report_dir = str(Path(path).parent)
        result = {
            "props":           data.get("props", {}),
            "findings":        findings,
            "packages_system": pkg_sys,
            "packages_user":   pkg_usr,
            "apk_hashes":      data.get("apk_hashes", []),
            "outdir":          report_dir,
            "meminfo":         data.get("meminfo", {}),
            "storage":         data.get("storage", ""),
            "report_md":       str(Path(report_dir) / "report.md"),
            "report_json":     path,
            "net_cmd":         data.get("network_cmd", ""),
            "net_out":         data.get("network_out", ""),
        }
        self.on_scan_done(result)
        # Reset progress area which on_scan_done left at 100%
        self.progress_label.setText(f"Loaded from {path}")
        self.tabs.setCurrentIndex(0)  # Show findings first

    # --- Scan orchestration ---

    def start_scan(self):
        serial = self.device_combo.currentData()
        if not serial:
            QMessageBox.warning(self, "No device", "Select a device first.")
            return
        outdir = self.outdir_edit.text().strip()
        if not outdir:
            QMessageBox.warning(self, "Output", "Set an output directory.")
            return

        self.scan_btn.setEnabled(False)
        self.findings_list.clear()
        self.props_view.clear()
        self.packages_view.clear()
        self.progress_bar.setValue(0)
        self.progress_bar.setRange(0, 0)  # indeterminate until APK phase
        self.progress_label.setText("Starting scan…")
        self.verdict_label.setText("<i>Scanning…</i>")
        self.tabs.setCurrentWidget(self.log_view)

        self.log(f"Starting scan of {serial} -> {outdir}")
        self.worker = ScanWorker(serial, outdir,
                                  self.skip_apks.isChecked(), 0)
        self.worker.stage_changed.connect(self.on_stage)
        self.worker.apk_progress.connect(self.on_apk_progress)
        self.worker.log_message.connect(self.log)
        self.worker.scan_finished.connect(self.on_scan_done)
        self.worker.scan_failed.connect(self.on_scan_fail)
        self.worker.start()

    def on_stage(self, stage):
        labels = {
            "getprop":  "Dumping system properties…",
            "proc":     "Reading /proc/meminfo and /proc/cpuinfo…",
            "storage":  "Reading storage…",
            "packages": "Listing packages…",
            "network":  "Capturing network sockets…",
            "analyze":  "Analyzing findings…",
            "report":   "Writing report…",
        }
        self.progress_label.setText(labels.get(stage, stage))

    def on_apk_progress(self, i, total, pkg):
        if self.progress_bar.maximum() != total:
            self.progress_bar.setRange(0, total)
        self.progress_bar.setValue(i)
        self.progress_label.setText(f"Pulling APK {i}/{total}: {pkg}")

    def _populate_spec_card(self, specs):
        """Render the structured spec dict as a grid of GroupBoxes."""
        # Clear existing widgets - setParent(None) to detach synchronously
        # (deleteLater alone is async and the new widgets can end up stacked)
        while self.spec_grid.count():
            item = self.spec_grid.takeAt(0)
            w = item.widget()
            if w is not None:
                w.setParent(None)
                w.deleteLater()
        # Reset row/column stretches from previous populate
        for i in range(self.spec_grid.rowCount()):
            self.spec_grid.setRowStretch(i, 0)
        for i in range(self.spec_grid.columnCount()):
            self.spec_grid.setColumnStretch(i, 0)

        # Section label -> (human title, emoji-free icon prefix optional)
        sections = [
            ("identity",     "Identity"),
            ("soc_cpu",      "SoC / CPU"),
            ("memory",       "Memory && Storage"),
            ("display_gpu",  "Display / GPU"),
            ("radio",        "Radio (Cellular / Wi-Fi / BT)"),
            ("os",           "OS && Firmware"),
            ("security",     "Security"),
        ]

        # Lay out in 2 columns
        col_count = 2
        for i, (key, title) in enumerate(sections):
            rows = specs.get(key, [])
            if not rows:
                continue
            gb = QGroupBox(title)
            gb_lay = QGridLayout(gb)
            gb_lay.setContentsMargins(8, 12, 8, 8)
            gb_lay.setHorizontalSpacing(10)
            gb_lay.setVerticalSpacing(4)
            gb_lay.setColumnStretch(0, 0)
            gb_lay.setColumnStretch(1, 1)
            for r, (label, value) in enumerate(rows):
                lbl = QLabel(label + ":")
                lbl_font = lbl.font()
                lbl.setFont(lbl_font)
                pal = lbl.palette()
                # Label is slightly muted vs value - uses disabled-text role
                # which respects the system theme (light or dark)
                lbl.setForegroundRole(QPalette.ColorRole.PlaceholderText)
                val = QLabel(str(value) if value else "—")
                val.setTextInteractionFlags(
                    Qt.TextInteractionFlag.TextSelectableByMouse)
                val.setWordWrap(True)
                vf = val.font()
                if label in ("Model", "SoC (detected)", "RAM (actual)",
                             "Storage /data", "Resolution", "Android release",
                             "Fingerprint"):
                    vf.setBold(True)
                val.setFont(vf)
                gb_lay.addWidget(lbl, r, 0, Qt.AlignmentFlag.AlignTop)
                gb_lay.addWidget(val, r, 1)
            row = i // col_count
            col = i % col_count
            self.spec_grid.addWidget(gb, row, col)

        # Set column stretches so both columns grow equally
        self.spec_grid.setColumnStretch(0, 1)
        self.spec_grid.setColumnStretch(1, 1)
        # Push content to the top
        self.spec_grid.setRowStretch(
            (len(sections) + col_count - 1) // col_count, 1)

    def on_scan_done(self, result):
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(100)
        self.progress_label.setText("Scan complete.")
        self.log(f"Report: {result['report_md']}")
        self.log(f"JSON:   {result['report_json']}")

        # Findings
        findings = result['findings']
        findings_sorted = sorted(findings,
                                  key=lambda f: ds.SEV_ORDER.get(f[0], 9))
        self.findings_list.clear()
        for sev, msg in findings_sorted:
            item = QListWidgetItem(f"[{sev}]  {msg}")
            fg = QColor(SEVERITY_COLORS.get(sev, ""))
            if fg.isValid():
                item.setForeground(fg)
            if sev in ("CRITICAL", "HIGH"):
                font = item.font()
                font.setBold(True)
                item.setFont(font)
            self.findings_list.addItem(item)

        # Verdict
        verdict, tier, crit, high, warn = ds.verdict_from_findings(findings)
        props = result['props']
        device_line = (f"{props.get('ro.product.manufacturer','?')} "
                       f"{props.get('ro.product.model','?')}")
        tier_color = {
            "critical": SEVERITY_COLORS["CRITICAL"],
            "high":     SEVERITY_COLORS["HIGH"],
            "warn":     SEVERITY_COLORS["WARN"],
            "ok":       "#27ae60",
        }.get(tier, "")
        self.verdict_label.setText(
            f"<div style='font-size:14pt; font-weight:bold; color:{tier_color}'>"
            f"{verdict}</div>"
            f"<div>Device: {device_line} &mdash; "
            f"{crit} CRITICAL &middot; {high} HIGH &middot; {warn} WARN</div>")

        # Props tab - populate the spec card, then dump raw getprop below
        specs = ds.extract_specs(props, result.get('meminfo', {}),
                                 result.get('storage', ''))
        self._populate_spec_card(specs)

        lines = []
        for k in sorted(props):
            lines.append(f"{k:45s} = {props[k]}")
        self.props_view.setPlainText("\n".join(lines))

        # Packages tab
        pkg_sys = result['packages_system']
        pkg_usr = result['packages_user']
        lines = [f"# System packages ({len(pkg_sys)})", ""]
        for pkg, path in sorted(pkg_sys):
            lines.append(f"{pkg:55s} {path}")
        lines += ["", f"# User packages ({len(pkg_usr)})", ""]
        for pkg, path in sorted(pkg_usr):
            lines.append(f"{pkg:55s} {path}")
        self.packages_view.setPlainText("\n".join(lines))

        self.tabs.setCurrentWidget(self.findings_list)
        self.status.showMessage(
            f"Scan complete: {crit} critical, {high} high, {warn} warn")
        self.scan_btn.setEnabled(True)
        self.worker = None

    def on_scan_fail(self, msg):
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_label.setText("Scan failed.")
        crit_color = SEVERITY_COLORS["CRITICAL"]
        self.verdict_label.setText(
            f"<div style='color:{crit_color}; font-weight:bold'>"
            f"Scan failed:</div><div>{msg}</div>")
        self.log(f"FAIL: {msg}")
        self.scan_btn.setEnabled(True)
        self.worker = None


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def run_gui():
    app = QApplication(sys.argv)
    w = MainWindow()
    w.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    run_gui()
