import sys
import os
import socket
import signal
import subprocess
import psutil
from functools import partial
from PySide6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLineEdit, QPushButton,
    QTableWidget, QTableWidgetItem, QMessageBox, QLabel, QHeaderView, QSizePolicy,
    QAbstractItemView
)
from PySide6.QtCore import Qt, QTimer, Slot

APP_REFRESH_INTERVAL_MS = 5000  # auto-refresh interval (ms). Set 0 to disable.

def format_local_addr(addr):
    if not addr:
        return ""
    return f"{addr.ip}:{addr.port}"

def safe_proc_name(pid):
    try:
        p = psutil.Process(pid)
        return p.name()
    except Exception:
        return "<unknown>"

class PortInspector(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Port Inspector")
        self.resize(900, 600)
        self.setup_ui()
        self.refresh()  # initial populate

        if APP_REFRESH_INTERVAL_MS > 0:
            self._timer = QTimer(self)
            self._timer.timeout.connect(self.refresh)
            self._timer.start(APP_REFRESH_INTERVAL_MS)

    def setup_ui(self):
        v = QVBoxLayout(self)

        # Header
        header = QHBoxLayout()
        title = QLabel("🔌 Port Inspector — see ports, processes and free them")
        title.setStyleSheet("font-size:18px; font-weight:600;")
        title.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        header.addWidget(title)

        refresh_btn = QPushButton("Refresh")
        refresh_btn.clicked.connect(self.refresh)
        header.addWidget(refresh_btn)

        v.addLayout(header)

        # Search bar
        search_layout = QHBoxLayout()
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search by port, process name or PID")
        self.search_input.textChanged.connect(self.apply_filter)
        search_layout.addWidget(self.search_input)

        clear_btn = QPushButton("Clear")
        clear_btn.clicked.connect(lambda: self.search_input.setText(""))
        search_layout.addWidget(clear_btn)

        v.addLayout(search_layout)

        # Table
        self.table = QTableWidget(0, 7)
        self.table.setHorizontalHeaderLabels(["Proto", "Local", "Remote", "Status", "PID", "Process", ""])
        header_view = self.table.horizontalHeader()
        header_view.setSectionResizeMode(1, QHeaderView.Stretch)
        header_view.setSectionResizeMode(5, QHeaderView.Stretch)
        header_view.setSectionResizeMode(6, QHeaderView.ResizeToContents)
        header_view.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header_view.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        header_view.setSectionResizeMode(3, QHeaderView.ResizeToContents)
        header_view.setSectionResizeMode(4, QHeaderView.ResizeToContents)
        self.table.verticalHeader().setVisible(False)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        self.table.setStyleSheet("""
            QTableWidget {
                font-size: 13px;
            }
            QHeaderView::section {
                background: qlineargradient(x1:0,y1:0,x2:1,y2:0, stop:0 #f5f7fb, stop:1 #e9eef8);
                padding: 6px;
                border: 1px solid #dfe7f5;
                font-weight: 600;
            }
            QPushButton {
                padding: 4px 8px;
                border-radius: 6px;
            }
        """)
        v.addWidget(self.table)

        # Footer
        footer = QHBoxLayout()
        self.status_label = QLabel("")
        footer.addWidget(self.status_label)
        footer.addStretch()
        v.addLayout(footer)

    @Slot()
    def refresh(self):
        """
        Gather active network connections using psutil and display them.
        """
        try:
            conns = psutil.net_connections(kind='inet')  # inet covers tcp/udp
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to enumerate connections:\n{e}")
            return

        rows = []
        for c in conns:
            pid = c.pid if c.pid is not None else -1
            proto = "TCP" if c.type == socket.SOCK_STREAM else "UDP" if c.type == socket.SOCK_DGRAM else str(c.type)
            laddr = format_local_addr(c.laddr) if c.laddr else ""
            raddr = format_local_addr(c.raddr) if c.raddr else ""
            status = c.status if hasattr(c, "status") else ""
            pname = safe_proc_name(pid) if pid > 0 else ""
            rows.append((proto, laddr, raddr, status, pid, pname))

        def sort_key(r):
            try:
                port = int(r[1].rsplit(":", 1)[1]) if ":" in r[1] else 0
            except Exception:
                port = 0
            return (port, r[0], r[5] or "")
        rows.sort(key=sort_key)

        self._all_rows = rows
        self.populate_table(rows)
        self.apply_filter()
        self.status_label.setText(f"{len(rows)} socket(s) found")

    def populate_table(self, rows):
        self.table.setRowCount(0)
        for row_data in rows:
            row = self.table.rowCount()
            self.table.insertRow(row)
            proto_item = QTableWidgetItem(row_data[0])
            proto_item.setTextAlignment(Qt.AlignCenter)
            self.table.setItem(row, 0, proto_item)
            self.table.setItem(row, 1, QTableWidgetItem(row_data[1]))
            self.table.setItem(row, 2, QTableWidgetItem(row_data[2]))
            self.table.setItem(row, 3, QTableWidgetItem(row_data[3]))
            pid_text = str(row_data[4]) if row_data[4] > 0 else ""
            self.table.setItem(row, 4, QTableWidgetItem(pid_text))
            proc_item = QTableWidgetItem(row_data[5] or "")
            self.table.setItem(row, 5, proc_item)

            btn = QPushButton("Kill")
            btn.setToolTip("Kill the process that owns this socket")
            btn.clicked.connect(partial(self.on_kill_clicked, row_data[4], row_data[5], row_data[1]))
            self.table.setCellWidget(row, 6, btn)

    def apply_filter(self):
        q = self.search_input.text().strip().lower()
        if not hasattr(self, "_all_rows"):
            return
        if q == "":
            self.populate_table(self._all_rows)
            return

        filtered = []
        for r in self._all_rows:
            proto, laddr, raddr, status, pid, pname = r
            if q.isdigit():
                if q in laddr or q in raddr or q == str(pid):
                    filtered.append(r)
                    continue
            if (q in (pname or "").lower() or
                q in (proto or "").lower() or
                q in (laddr or "").lower() or
                q in (raddr or "").lower() or
                q in (status or "").lower()):
                filtered.append(r)
        self.populate_table(filtered)

    def on_kill_clicked(self, pid, pname, local_addr):
        if not pid or pid <= 0:
            QMessageBox.information(self, "No PID", "This socket is not associated with a visible PID.")
            return

        reply = QMessageBox.question(
            self, "Confirm Kill",
            f"Really kill process {pname or ''} (PID {pid})?\nThis will free {local_addr} if it owns it.",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No
        )
        if reply != QMessageBox.Yes:
            return

        success, msg = self.try_kill_pid(pid)
        if success:
            QMessageBox.information(self, "Killed", f"Successfully signaled PID {pid}.")
            self.refresh()
        else:
            QMessageBox.critical(self, "Failed", f"Failed to kill PID {pid}:\n{msg}")

    def try_kill_pid(self, pid):
        try:
            proc = psutil.Process(pid)
            proc.terminate()
            try:
                proc.wait(timeout=3)
                return True, "terminated"
            except psutil.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=3)
                return True, "killed"
        except (psutil.NoSuchProcess, ProcessLookupError):
            return False, "process not found"
        except Exception as e:
            if sys.platform.startswith("win"):
                try:
                    subprocess.check_call(["taskkill", "/PID", str(pid), "/F"])
                    return True, "taskkill"
                except Exception as e2:
                    return False, f"{e}; taskkill failed: {e2}"
            else:
                try:
                    os.kill(pid, signal.SIGTERM)
                except PermissionError as pe:
                    return False, f"permission denied: {pe}"
                except Exception as e3:
                    return False, str(e3)
                return True, "SIGTERM sent"

if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyleSheet("""
        QWidget { background: #f7f9fc; color: #1e2b3b; }
        QPushButton { background: qlineargradient(x1:0,y1:0,x2:0,y2:1, stop:0 #6fb1ff, stop:1 #4a90e2); color: white; border: none; padding:6px; border-radius:8px; }
        QPushButton:hover { background: qlineargradient(x1:0,y1:0,x2:0,y2:1, stop:0 #7ec4ff, stop:1 #5aa1ef); }
        QLineEdit { padding:8px; border-radius:8px; border:1px solid #d6e3f8; }
    """)
    w = PortInspector()
    w.show()
    sys.exit(app.exec())
