import sys
import os
import time
from PyQt6.QtWidgets import (
    QApplication,
    QMainWindow,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QStackedWidget,
    QFrame,
    QFileDialog,
    QProgressBar,
    QMessageBox,
    QListWidget,
    QComboBox,
    QCheckBox,
    QInputDialog,
    QGraphicsOpacityEffect,
    QSpinBox,
    QSpinBox,
    QFormLayout,
    QDialog,
    QSpinBox,
    QFormLayout,
    QDialog,
    QTabWidget,
    QTextEdit,
    QSpinBox,
    QFormLayout,
    QDialog,
    QTabWidget,
    QTextEdit,
    QGroupBox,
    QRadioButton,
    QButtonGroup,
    QGridLayout,
)
import io
import qrcode
import psutil  # Ensure psutil is available for direct check if needed, though tools has it.
from core.steganography import StegoEngine
import qrcode
from core.steganography import StegoEngine
from core.network import GhostLink
from core.tools import SecurityTools
from PyQt6.QtCore import (
    Qt,
    QThread,
    pyqtSignal,
    QPropertyAnimation,
    QEasingCurve,
    QSize,
    QParallelAnimationGroup,
    QTimer,
)
from PyQt6.QtGui import QColor, QIcon
import qtawesome as qta

from core.auth import AuthManager
from core.vault_manager import VaultManager
from core.crypto_engine import CryptoEngine
from core.shredder import Shredder
from core.tools import SecurityTools
from core.audit import AuditLog
from core.network import GhostLink
from core.session import SecureSession


from core.session import SecureSession


ACCENT_COLOR = "#00e676"
BG_COLOR = "#09090b"
CARD_COLOR = "#18181b"
TEXT_COLOR = "#ffffff"


class SystemMonitorWidget(QFrame):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("Card")
        self.setStyleSheet(
            f"QFrame#Card {{ background-color: {CARD_COLOR}; border-radius: 16px; border: 1px solid #27272a; }}"
        )
        self.setFixedSize(300, 160)

        layout = QVBoxLayout(self)

        l_title = QLabel("System Vitality")
        l_title.setStyleSheet("font-weight: bold; color: gray;")
        layout.addWidget(l_title)

        # CPU
        self.cpu_bar = QProgressBar()
        self.cpu_bar.setStyleSheet(
            f"QProgressBar {{ border: 0px; background: #27272a; height: 8px; border-radius: 4px; }} QProgressBar::chunk {{ background: {ACCENT_COLOR}; border-radius: 4px; }}"
        )
        self.cpu_bar.setTextVisible(False)
        self.cpu_bar.setRange(0, 100)

        self.lbl_cpu = QLabel("CPU: 0%")
        self.lbl_cpu.setStyleSheet("font-size: 12px; font-weight: bold;")

        layout.addWidget(self.lbl_cpu)
        layout.addWidget(self.cpu_bar)

        # RAM
        self.ram_bar = QProgressBar()
        self.ram_bar.setStyleSheet(
            "QProgressBar { border: 0px; background: #27272a; height: 8px; border-radius: 4px; } QProgressBar::chunk { background: #7f5af0; border-radius: 4px; }"
        )
        self.ram_bar.setTextVisible(False)
        self.ram_bar.setRange(0, 100)

        self.lbl_ram = QLabel("RAM: 0%")
        self.lbl_ram.setStyleSheet("font-size: 12px; font-weight: bold;")

        layout.addWidget(self.lbl_ram)
        layout.addWidget(self.ram_bar)

        self.timer = QTimer(self)
        self.timer.timeout.connect(self.update_stats)
        self.timer.start(2000)
        self.update_stats()

    def update_stats(self):
        try:
            c = psutil.cpu_percent()
            r = psutil.virtual_memory().percent
            self.cpu_bar.setValue(int(c))
            self.lbl_cpu.setText(f"CPU: {c}%")
            self.ram_bar.setValue(int(r))
            self.lbl_ram.setText(f"RAM: {r}%")
        except:
            pass


STYLESHEET = f"""
QMainWindow {{ background-color: {BG_COLOR}; }}
QWidget {{ color: {TEXT_COLOR}; font-family: 'Segoe UI', sans-serif; font-size: 14px; }}

/* Inputs */
QLineEdit, QComboBox, QSpinBox {{
    background-color: #1f1f22; border: 1px solid #27272a; border-radius: 8px; padding: 10px; color: white;
}}
QLineEdit:focus, QComboBox:focus {{ border: 1px solid {ACCENT_COLOR}; }}

/* Cards */
QFrame#Card {{
    background-color: {CARD_COLOR}; border-radius: 16px; border: 1px solid #27272a;
}}

/* Sidebar */
QFrame#Sidebar {{ background-color: #141417; border-right: 1px solid #27272a; }}

/* Buttons */
QPushButton {{
    background-color: #27272a; border-radius: 8px; padding: 12px; color: #a1a1aa; font-weight: 600; text-align: left;
}}
QPushButton:hover {{ background-color: #3f3f46; color: white; }}

QPushButton#Primary {{
    background-color: {ACCENT_COLOR}; color: black; text-align: center;
}}
QPushButton#Primary:hover {{ background-color: #00c853; }}

QPushButton#Danger {{
    background-color: #ff3d3d; color: white; text-align: center;
}}
"""


class FadeStack(QStackedWidget):
    """Custom Stacked Widget with Fade Animation"""

    def __init__(self):
        super().__init__()
        self.fade_anim = None

    def on_fade_finished(self):
        self.currentWidget().setGraphicsEffect(None)
        # The previous widget is now hidden by stacking order or can be explicitly hidden if needed,
        # but standard QStackedWidget only shows one.
        # Actually QStackedWidget shows only current. Custom logic here relied on show().
        # Let's ensure we use standard behavior.
        self.setCurrentIndex(self.next_idx)
        self.widget(self.next_idx).setGraphicsEffect(None)

    def fade_to_index(self, index):
        if index == self.currentIndex():
            return

        self.next_idx = index
        current_widget = self.currentWidget()
        next_widget = self.widget(index)

        if not current_widget or not next_widget:
            self.setCurrentIndex(index)
            return

        self.eff1 = QGraphicsOpacityEffect(self)
        self.eff2 = QGraphicsOpacityEffect(self)
        current_widget.setGraphicsEffect(self.eff1)
        next_widget.setGraphicsEffect(self.eff2)

        next_widget.show()
        next_widget.raise_()

        self.anim_group = QParallelAnimationGroup()

        anim1 = QPropertyAnimation(self.eff1, b"opacity")
        anim1.setDuration(300)
        anim1.setStartValue(1)
        anim1.setEndValue(0)

        anim2 = QPropertyAnimation(self.eff2, b"opacity")
        anim2.setDuration(300)
        anim2.setStartValue(0)
        anim2.setEndValue(1)

        self.anim_group.addAnimation(anim1)
        self.anim_group.addAnimation(anim2)
        self.anim_group.finished.connect(self.on_fade_finished)
        self.anim_group.start()


class StartStegoDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Omega Steganography Tool")
        self.setFixedSize(600, 500)
        self.setStyleSheet(STYLESHEET + "QDialog { background-color: #09090b; }")

        layout = QVBoxLayout(self)

        self.tabs = QTabWidget()
        self.tabs.setStyleSheet(
            "QTabWidget::pane { border: 0; } QTabBar::tab { background: #27272a; color: gray; padding: 10px; } QTabBar::tab:selected { background: #00e676; color: black; }"
        )

        self.tab_enc = self.init_enc_tab()
        self.tab_dec = self.init_dec_tab()

        self.tabs.addTab(self.tab_enc, "Hide Data")
        self.tabs.addTab(self.tab_dec, "Extract Data")

        layout.addWidget(self.tabs)

    def init_enc_tab(self):
        w = QWidget()
        l = QVBoxLayout(w)

        # Cover Image
        self.lbl_cover = QLabel("No Cover Image Selected")
        self.lbl_cover.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.lbl_cover.setStyleSheet(
            "border: 2px dashed #3f3f46; padding: 20px; color: gray;"
        )
        l.addWidget(self.lbl_cover)

        b_sel = QPushButton("Select Cover Image (PNG)")
        b_sel.clicked.connect(self.sel_cover)
        l.addWidget(b_sel)

        self.lbl_cap = QLabel("Capacity: 0 bytes")
        self.lbl_cap.setStyleSheet("color: #00e676; font-weight: bold;")
        l.addWidget(self.lbl_cap)
        l.addSpacing(10)

        # Payload
        self.in_payload = QLineEdit(placeholderText="Path to secret file...")
        self.in_payload.setReadOnly(True)
        l.addWidget(self.in_payload)

        b_pay = QPushButton("Select Secret File")
        b_pay.clicked.connect(self.sel_payload)
        l.addWidget(b_pay)

        l.addStretch()

        b_run = QPushButton("ENCODE & SAVE", objectName="Primary")
        b_run.clicked.connect(self.run_encode)
        l.addWidget(b_run)

        self.cover_path = None
        self.payload_path = None

        return w

    def init_dec_tab(self):
        w = QWidget()
        l = QVBoxLayout(w)

        self.lbl_stego = QLabel("No Stego Image Selected")
        self.lbl_stego.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.lbl_stego.setStyleSheet(
            "border: 2px dashed #3f3f46; padding: 20px; color: gray;"
        )
        l.addWidget(self.lbl_stego)

        b_sel = QPushButton("Select Stego Image")
        b_sel.clicked.connect(self.sel_stego)
        l.addWidget(b_sel)

        l.addStretch()

        b_run = QPushButton("EXTRACT DATA", objectName="Primary")
        b_run.clicked.connect(self.run_decode)
        l.addWidget(b_run)

        self.stego_path = None
        return w

    def sel_cover(self):
        f, _ = QFileDialog.getOpenFileName(
            self, "Select Cover", "", "Images (*.png *.jpg *.jpeg)"
        )
        if f:
            self.cover_path = f
            self.lbl_cover.setText(os.path.basename(f))
            cap = StegoEngine.get_capacity(f)
            self.lbl_cap.setText(f"Capacity: {cap} bytes")

    def sel_payload(self):
        f, _ = QFileDialog.getOpenFileName(self, "Select Secret File")
        if f:
            self.payload_path = f
            self.in_payload.setText(f)

    def run_encode(self):
        if not self.cover_path or not self.payload_path:
            QMessageBox.warning(
                self, "Error", "Select both cover image and secret file."
            )
            return

        out, _ = QFileDialog.getSaveFileName(
            self, "Save Stego Image", "", "PNG Image (*.png)"
        )
        if not out:
            return

        try:
            StegoEngine.encode(self.cover_path, self.payload_path, out)
            QMessageBox.information(self, "Success", f"Data hidden in {out}")
            self.close()
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

    def sel_stego(self):
        f, _ = QFileDialog.getOpenFileName(
            self, "Select Stego Image", "", "PNG Image (*.png)"
        )
        if f:
            self.stego_path = f
            self.lbl_stego.setText(os.path.basename(f))

    def run_decode(self):
        if not self.stego_path:
            QMessageBox.warning(self, "Error", "Select stego image.")
            return

        out, _ = QFileDialog.getSaveFileName(
            self, "Extract Secret To...", "", "All Files (*.*)"
        )
        if not out:
            return

        try:
            size_out = StegoEngine.decode(self.stego_path, out)
            QMessageBox.information(
                self, "Success", f"Extracted {size_out} bytes to {out}"
            )
            self.close()
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))


class GhostLinkDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("GhostLink Secure Tunnel (SFTP)")
        self.setFixedSize(500, 600)
        self.setStyleSheet(STYLESHEET + "QDialog { background-color: #09090b; }")

        self.link = GhostLink()

        layout = QVBoxLayout(self)
        layout.setSpacing(15)

        # Connection Details
        gb_conn = QGroupBox("Connection")
        gb_conn.setStyleSheet(
            "QGroupBox { border: 1px solid #3f3f46; margin-top: 10px; padding-top: 10px; font-weight: bold; color: white; }"
        )
        l_conn = QFormLayout(gb_conn)

        self.in_host = QLineEdit()
        self.in_port = QSpinBox()
        self.in_port.setRange(1, 65535)
        self.in_port.setValue(22)
        self.in_user = QLineEdit()
        self.in_pass = QLineEdit()
        self.in_pass.setEchoMode(QLineEdit.EchoMode.Password)

        l_conn.addRow("Host:", self.in_host)
        l_conn.addRow("Port:", self.in_port)
        l_conn.addRow("Username:", self.in_user)
        l_conn.addRow("Password:", self.in_pass)

        layout.addWidget(gb_conn)

        # Proxy (Optional)
        gb_proxy = QGroupBox("SOCKS5 Proxy (Optional)")
        gb_proxy.setStyleSheet(
            "QGroupBox { border: 1px solid #3f3f46; margin-top: 10px; padding-top: 10px; font-weight: bold; color: gray; }"
        )
        l_proxy = QHBoxLayout(gb_proxy)
        self.in_prox_host = QLineEdit(placeholderText="127.0.0.1")
        self.in_prox_port = QLineEdit(placeholderText="9050")
        l_proxy.addWidget(QLabel("Host:"))
        l_proxy.addWidget(self.in_prox_host)
        l_proxy.addWidget(QLabel("Port:"))
        l_proxy.addWidget(self.in_prox_port)

        layout.addWidget(gb_proxy)

        # Actions
        btn_conn = QPushButton("TEST CONNECTION", objectName="Primary")
        btn_conn.clicked.connect(self.do_connect)
        layout.addWidget(btn_conn)

        self.lbl_status = QLabel("Status: Disconnected")
        self.lbl_status.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.lbl_status)

        layout.addSpacing(20)
        layout.addWidget(
            QLabel("File Operations", styleSheet="font-weight: bold; color: #00e676;")
        )

        btn_upload = QPushButton(" Upload File to Remote Home")
        btn_upload.clicked.connect(self.do_upload)
        layout.addWidget(btn_upload)

        layout.addStretch()

    def do_connect(self):
        h = self.in_host.text()
        p = self.in_port.value()
        u = self.in_user.text()
        pwd = self.in_pass.text()

        ph = self.in_prox_host.text()
        pp = self.in_prox_port.text()

        if not h or not u:
            QMessageBox.warning(self, "Error", "Host and User required")
            return

        self.lbl_status.setText("Status: Connecting...")
        self.lbl_status.repaint()

        # Run in thread strictly speaking, but for simplicity/demo direct call
        ok, msg = self.link.connect(h, p, u, pwd, proxy_host=ph, proxy_port=pp)
        if ok:
            self.lbl_status.setText(f"Status: {msg}")
            self.lbl_status.setStyleSheet("color: #00e676")
        else:
            self.lbl_status.setText("Status: Failed")
            self.lbl_status.setStyleSheet("color: #ff3d3d")
            QMessageBox.critical(self, "Connection Error", msg)

    def do_upload(self):
        if not self.link.sftp:
            QMessageBox.warning(self, "Error", "Establish connection first.")
            return

        f, _ = QFileDialog.getOpenFileName(self, "Select File to Upload")
        if not f:
            return

        rem = os.path.basename(f)
        ok, msg = self.link.upload(f, rem)
        if ok:
            QMessageBox.information(self, "Success", f"Uploaded to {rem}")
        else:
            QMessageBox.warning(self, "Error", msg)

    def closeEvent(self, event):
        self.link.close()
        event.accept()


class PassGenDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Titanium Password Generator")
        self.setFixedSize(400, 350)
        self.setStyleSheet(STYLESHEET + "QDialog { background-color: #09090b; }")

        layout = QVBoxLayout(self)
        layout.setSpacing(20)

        layout.addWidget(
            QLabel("Generate High-Entropy Credentials", styleSheet="color: gray;")
        )

        # Length
        h_len = QHBoxLayout()
        self.spin_len = QSpinBox()
        self.spin_len.setRange(8, 128)
        self.spin_len.setValue(32)
        h_len.addWidget(QLabel("Length:"))
        h_len.addWidget(self.spin_len)
        layout.addLayout(h_len)

        # Result
        self.out_pass = QLineEdit()
        self.out_pass.setReadOnly(True)
        self.out_pass.setStyleSheet(
            "font-family: Consolas; font-size: 16px; color: #00e676; padding: 15px;"
        )
        layout.addWidget(self.out_pass)

        # Actions
        btn_gen = QPushButton(" GENERATE", objectName="Primary")
        btn_gen.setIcon(qta.icon("fa5s.sync", color="black"))
        btn_gen.clicked.connect(self.generate)
        layout.addWidget(btn_gen)

        btn_copy = QPushButton(" Copy to Clipboard")
        btn_copy.clicked.connect(self.copy_to_clip)
        layout.addWidget(btn_copy)

        layout.addStretch()
        self.generate()  # Init with one

    def generate(self):
        l = self.spin_len.value()
        # Using core.tools
        pwd = SecurityTools.generate_password(l)
        self.out_pass.setText(pwd)

    def copy_to_clip(self):
        QApplication.clipboard().setText(self.out_pass.text())
        QMessageBox.information(self, "Copied", "Password copied to clipboard.")


class InitVaultDialog(QDialog):
    def __init__(self, parent=None, vault_mgr=None):
        super().__init__(parent)
        self.vault_mgr = vault_mgr
        self.setWindowTitle("Create Secure Environment")
        self.setFixedSize(500, 550)
        self.setStyleSheet(STYLESHEET + "QDialog { background-color: #09090b; }")

        self.stack = QStackedWidget()
        self.layout = QVBoxLayout(self)
        self.layout.addWidget(self.stack)

        self.init_step_1()
        self.init_step_2()

    def init_step_1(self):
        w = QWidget()
        l = QVBoxLayout(w)
        l.setSpacing(15)

        l.addWidget(
            QLabel(
                "Environment Setup",
                styleSheet="font-size: 20px; font-weight: bold; color: white;",
            )
        )

        self.in_name = QLineEdit(placeholderText="Vault Name (e.g., Personal)")
        self.in_user = QLineEdit(placeholderText="Username")
        self.in_pass = QLineEdit(placeholderText="Master Password")
        self.in_pass.setEchoMode(QLineEdit.EchoMode.Password)
        self.in_duress = QLineEdit(placeholderText="Duress Password (Panic)")
        self.in_duress.setEchoMode(QLineEdit.EchoMode.Password)

        l.addWidget(QLabel("Configuration:"))
        l.addWidget(self.in_name)
        l.addWidget(self.in_user)
        l.addWidget(self.in_pass)
        l.addWidget(self.in_duress)

        l.addStretch()

        btn_next = QPushButton("CREATE ENVIRONMENT", objectName="Primary")
        btn_next.clicked.connect(self.action_create)
        l.addWidget(btn_next)

        self.stack.addWidget(w)

    def init_step_2(self):
        self.p2 = QWidget()
        l = QVBoxLayout(self.p2)
        l.setSpacing(15)

        l.addWidget(
            QLabel(
                "Two-Factor Authentication",
                styleSheet="font-size: 20px; font-weight: bold; color: #00e676;",
            )
        )
        l.addWidget(
            QLabel(
                "Scan this QR Code with your Authenticator App, or enter the secret manually.",
                styleSheet="color: gray;",
            )
        )

        # Tabs for QR / Text
        tabs = QTabWidget()
        tabs.setStyleSheet(
            "QTabWidget::pane { border: 0; } QTabBar::tab { background: #27272a; color: gray; padding: 10px; width: 100px; } QTabBar::tab:selected { background: #3f3f46; color: white; border-bottom: 2px solid #00e676; }"
        )

        # TAB 1: QR
        t1 = QWidget()
        l1 = QVBoxLayout(t1)
        self.qr_lbl = QLabel()
        self.qr_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.qr_lbl.setStyleSheet(
            "background: white; border-radius: 10px; padding: 10px;"
        )
        l1.addWidget(self.qr_lbl)
        tabs.addTab(t1, "QR Code")

        # TAB 2: TEXT
        t2 = QWidget()
        l2 = QVBoxLayout(t2)
        self.txt_secret = QLineEdit()
        self.txt_secret.setReadOnly(True)
        self.txt_secret.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.txt_secret.setStyleSheet(
            "font-size: 24px; letter-spacing: 5px; font-family: Consolas; color: #00e676;"
        )
        l2.addWidget(QLabel("Secret Key (Base32):"))
        l2.addWidget(self.txt_secret)
        tabs.addTab(t2, "Text Code")

        l.addWidget(tabs)
        l.addStretch()

        btn_done = QPushButton("I HAVE SAVED IT", objectName="Primary")
        btn_done.clicked.connect(self.accept)
        l.addWidget(btn_done)

        self.stack.addWidget(self.p2)

    def action_create(self):
        name = self.in_name.text()
        user = self.in_user.text()
        pwd = self.in_pass.text()
        duress = self.in_duress.text()

        if not all([name, user, pwd, duress]):
            QMessageBox.warning(self, "Error", "All fields are required")
            return

        res, data = self.vault_mgr.create_vault(name, user, pwd, duress)
        if not res:
            QMessageBox.critical(self, "Error", data)
            return

        # Success, show step 2
        secret = data
        self.txt_secret.setText(secret)

        # Generate QR
        import pyotp

        totp = pyotp.TOTP(secret)
        uri = totp.provisioning_uri(name=user, issuer_name="NDSFC Vault")

        img = qrcode.make(uri)
        # Convert PIL to Pixmap
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        qimg = QIcon(
            qta.icon("fa5s.lock").pixmap(200, 200)
        )  # Placeholder if fails? No, use QPixmap

        # Properly load from buffer
        from PyQt6.QtGui import QPixmap

        qp = QPixmap()
        qp.loadFromData(buf.getvalue())
        self.qr_lbl.setPixmap(qp.scaled(200, 200, Qt.AspectRatioMode.KeepAspectRatio))

        self.stack.setCurrentIndex(1)


class InitVaultDialog_OLD(QDialog):
    # Removing old manual dialog logic
    pass


class TaskWorker(QThread):
    finished = pyqtSignal(object)

    def __init__(self, func, *args, **kwargs):
        super().__init__()
        self.func, self.args, self.kwargs = func, args, kwargs

    def run(self):
        try:
            res = self.func(*self.args, **self.kwargs)
            self.finished.emit((True, res))
        except Exception as e:
            self.finished.emit((False, str(e)))


class NDSFC_Pro(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("NDSFC | GitHub : MintyExtremum & Vyxara-Arch")
        self.resize(1150, 750)
        self.setStyleSheet(STYLESHEET)

        self.vault_mgr = VaultManager()
        self.auth = AuthManager()
        self.session = SecureSession()

        self.main_stack = FadeStack()
        self.setCentralWidget(self.main_stack)

        self.init_login_ui()
        self.init_dashboard_ui()

        if not self.vault_mgr.list_vaults():
            self.show_create_vault_dialog()

    def show_create_vault_dialog(self):
        d = InitVaultDialog(self, self.vault_mgr)
        if d.exec():
            self.refresh_vaults()

    def init_login_ui(self):
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        card = QFrame(objectName="Card")
        card.setFixedSize(450, 550)
        cl = QVBoxLayout(card)
        cl.setContentsMargins(40, 40, 40, 40)
        cl.setSpacing(20)

        icon_lbl = QLabel()
        icon_lbl.setPixmap(
            qta.icon("fa5s.fingerprint", color=ACCENT_COLOR).pixmap(64, 64)
        )
        icon_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)

        lbl_title = QLabel(
            "SECURE ENVIRONMENT",
            styleSheet=f"font-size: 22px; font-weight: bold; color: {ACCENT_COLOR};",
        )
        lbl_title.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.cb_vaults = QComboBox()
        self.refresh_vaults()

        self.in_pass = QLineEdit(placeholderText="Master Key")
        self.in_pass.setEchoMode(QLineEdit.EchoMode.Password)

        self.in_2fa = QLineEdit(placeholderText="Authenticator Code")
        self.in_2fa.setAlignment(Qt.AlignmentFlag.AlignCenter)

        btn_login = QPushButton("AUTHENTICATE", objectName="Primary")
        btn_login.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_login.clicked.connect(self.do_login)

        btn_new = QPushButton("Create New Environment")
        btn_new.setStyleSheet(
            "background: transparent; color: gray; text-align: center;"
        )
        btn_new.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_new.clicked.connect(self.show_create_vault_dialog)

        cl.addWidget(icon_lbl)
        cl.addWidget(lbl_title)
        cl.addSpacing(10)
        cl.addWidget(QLabel("Select Environment:"))
        cl.addWidget(self.cb_vaults)
        cl.addWidget(self.in_pass)
        cl.addWidget(self.in_2fa)
        cl.addStretch()
        cl.addWidget(btn_login)
        cl.addWidget(btn_new)

        layout.addWidget(card)
        self.main_stack.addWidget(w)

    def refresh_vaults(self):
        self.cb_vaults.clear()
        self.cb_vaults.addItems(self.vault_mgr.list_vaults())

    def init_dashboard_ui(self):
        w = QWidget()
        row = QHBoxLayout(w)
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(0)

        sidebar = QFrame(objectName="Sidebar")
        sidebar.setFixedWidth(280)
        sb_l = QVBoxLayout(sidebar)
        sb_l.setContentsMargins(20, 40, 20, 20)

        sb_l.addWidget(
            QLabel(
                "NDSFC PRO",
                styleSheet=f"font-size: 26px; font-weight: bold; color: {ACCENT_COLOR};",
            )
        )
        sb_l.addSpacing(40)

        self.dash_stack = FadeStack()

        btns = [
            ("Dashboard", "fa5s.chart-pie", 0),
            ("Cryptographer", "fa5s.lock", 1),
            ("Omega Tools", "fa5s.magic", 2),
            ("Settings", "fa5s.cog", 3),
        ]

        self.nav_buttons = []
        for name, icon, idx in btns:
            b = QPushButton(f"  {name}")
            b.setIcon(qta.icon(icon, color="#a1a1aa"))
            b.clicked.connect(lambda ch, i=idx: self.switch_tab(i))
            self.nav_buttons.append(b)
            sb_l.addWidget(b)

        sb_l.addStretch()
        b_out = QPushButton(" LOCK SESSION", objectName="Danger")
        b_out.clicked.connect(self.do_logout)
        sb_l.addWidget(b_out)

        self.dash_stack.addWidget(self.tab_home())
        self.dash_stack.addWidget(self.tab_crypto())
        self.dash_stack.addWidget(self.tab_omega())
        self.dash_stack.addWidget(self.tab_settings())

        row.addWidget(sidebar)
        row.addWidget(self.dash_stack)
        self.main_stack.addWidget(w)

    def switch_tab(self, idx):
        self.dash_stack.fade_to_index(idx)

    def tab_home(self):
        p = QWidget()
        l = QVBoxLayout(p)
        l.setContentsMargins(30, 30, 30, 30)

        # Header
        header = QHBoxLayout()
        lbl_welcome = QLabel("Mission Control")
        lbl_welcome.setStyleSheet("font-size: 28px; font-weight: bold; color: white;")
        header.addWidget(lbl_welcome)
        header.addStretch()
        l.addLayout(header)
        l.addSpacing(20)

        # Grid
        grid = QGridLayout()
        grid.setSpacing(20)

        # 1. System Monitor (Row 0, Col 0)
        sys_mon = SystemMonitorWidget()
        grid.addWidget(sys_mon, 0, 0)

        # 2. Vault Status (Row 0, Col 1)
        v_card = QFrame(objectName="Card")
        v_card.setStyleSheet(
            f"QFrame#Card {{ background-color: {CARD_COLOR}; border-radius: 16px; border: 1px solid #27272a; }}"
        )
        v_card.setFixedSize(300, 160)
        vl = QVBoxLayout(v_card)
        vl.addWidget(
            QLabel("Active Environment", styleSheet="font-weight: bold; color: gray;")
        )
        self.lbl_vault_name = QLabel(self.session.current_vault or "LOCKED")
        self.lbl_vault_name.setStyleSheet(
            f"font-size: 24px; font-weight: bold; color: {ACCENT_COLOR};"
        )
        vl.addWidget(self.lbl_vault_name)
        vl.addStretch()
        b_lock = QPushButton("LOCK NOW")
        b_lock.setStyleSheet("background: #27272a; color: white; border: 0px;")
        b_lock.clicked.connect(self.do_logout)
        vl.addWidget(b_lock)
        grid.addWidget(v_card, 0, 1)

        # 3. Quick Actions (Row 0, Col 2)
        q_card = QFrame(objectName="Card")
        q_card.setStyleSheet(
            f"QFrame#Card {{ background-color: {CARD_COLOR}; border-radius: 16px; border: 1px solid #27272a; }}"
        )
        q_card.setFixedSize(300, 160)
        ql = QVBoxLayout(q_card)
        ql.addWidget(
            QLabel("Quick Actions", styleSheet="font-weight: bold; color: gray;")
        )

        bq1 = QPushButton("  Encrypt File")
        bq1.setIcon(qta.icon("fa5s.lock", color="white"))
        bq1.clicked.connect(lambda: self.switch_tab(1))  # Crypto tab
        ql.addWidget(bq1)

        bq2 = QPushButton("  Secure Tunnel")
        bq2.setIcon(qta.icon("fa5s.network-wired", color="white"))
        bq2.clicked.connect(self.open_ghostlink)
        ql.addWidget(bq2)

        grid.addWidget(q_card, 0, 2)

        # Row 1: Audit Log / Recent Activity
        audit_frame = QFrame(objectName="Card")
        audit_frame.setStyleSheet(
            f"QFrame#Card {{ background-color: {CARD_COLOR}; border-radius: 16px; border: 1px solid #27272a; }}"
        )
        al = QVBoxLayout(audit_frame)
        al.addWidget(
            QLabel("Security Audit Log", styleSheet="font-weight: bold; color: gray;")
        )

        self.list_audit = QListWidget()
        self.list_audit.setStyleSheet(
            "background: transparent; border: 0px; font-family: Consolas;"
        )
        # Dummy data
        self.list_audit.addItem("[SYSTEM] Session Initialized")
        self.list_audit.addItem("[AUDIT] Integrity Check Passed")

        al.addWidget(self.list_audit)

        grid.addWidget(audit_frame, 1, 0, 1, 3)  # Span 3 cols

        l.addLayout(grid)
        l.addStretch()

        return p
        l.addWidget(
            QLabel("Recent Activity", styleSheet="font-size: 18px; color: gray;")
        )
        self.log_list = QListWidget()
        self.log_list.setStyleSheet(
            "border: none; background: transparent; font-family: Consolas;"
        )
        l.addWidget(self.log_list)

        return p

    def tab_crypto(self):
        p = QWidget()
        l = QVBoxLayout(p)
        l.setContentsMargins(50, 50, 50, 50)
        l.addWidget(
            QLabel(
                "Multi-Layer Encryption",
                styleSheet="font-size: 28px; font-weight: bold;",
            )
        )

        conf = QHBoxLayout()
        self.chk_shred = QCheckBox("Secure Shred (3-pass)")
        self.chk_shred.setChecked(True)
        self.chk_pqc = QCheckBox("Quantum-Resistant Layer")

        conf.addWidget(self.chk_shred)
        conf.addWidget(self.chk_pqc)
        conf.addStretch()
        l.addLayout(conf)

        self.file_list = QListWidget()
        self.file_list.setAcceptDrops(True)
        self.file_list.dragEnterEvent = lambda e: e.accept()
        self.file_list.dragMoveEvent = lambda e: e.accept()
        self.file_list.dropEvent = self.on_drop
        self.file_list.setToolTip("Drag files here")
        self.file_list.setStyleSheet("border: 2px dashed #3f3f46; background: #141417;")
        l.addWidget(self.file_list)

        acts = QHBoxLayout()
        b_add = QPushButton(" Add Files")
        b_add.clicked.connect(self.add_files)
        b_enc = QPushButton(" ENCRYPT ALL", objectName="Danger")
        b_enc.clicked.connect(self.run_encrypt)
        b_dec = QPushButton(" DECRYPT ALL", objectName="Primary")
        b_dec.clicked.connect(self.run_decrypt)

        acts.addWidget(b_add)
        acts.addStretch()
        acts.addWidget(b_enc)
        acts.addWidget(b_dec)
        l.addLayout(acts)

        return p

    def tab_settings(self):
        p = QWidget()
        l = QVBoxLayout(p)
        l.setContentsMargins(50, 50, 50, 50)
        l.addWidget(
            QLabel(
                "Environment Settings", styleSheet="font-size: 28px; font-weight: bold;"
            )
        )

        form_frame = QFrame(objectName="Card")
        fl = QFormLayout(form_frame)
        fl.setSpacing(20)
        fl.setContentsMargins(30, 30, 30, 30)

        self.set_algo = QComboBox()
        self.set_algo.addItems(["ChaCha20-Poly1305 (Fast)", "AES-256-GCM (Standard)"])

        self.set_shred = QSpinBox()
        self.set_shred.setRange(1, 35)
        self.set_shred.setValue(3)
        self.set_shred.setSuffix(" Passes")

        self.set_theme = QComboBox()
        self.set_theme.addItems(["Cyber Green", "Red Alert", "Deep Purple"])

        btn_save = QPushButton("Save Configuration", objectName="Primary")
        btn_save.clicked.connect(self.save_settings)

        fl.addRow("Default Encryption:", self.set_algo)
        fl.addRow("Shredder Intensity:", self.set_shred)
        fl.addRow("UI Accent Color:", self.set_theme)
        fl.addRow("", btn_save)

        l.addWidget(form_frame)
        l.addStretch()
        return p

    def tab_omega(self):
        p = QWidget()
        l = QVBoxLayout(p)
        l.setContentsMargins(50, 50, 50, 50)
        l.addWidget(
            QLabel("Omega Utilities", styleSheet="font-size: 28px; font-weight: bold;")
        )

        grid = QHBoxLayout()

        c1 = QFrame(objectName="Card")
        l1 = QVBoxLayout(c1)
        l1.addWidget(
            QLabel("Steganography", styleSheet="font-weight:bold; font-size:16px")
        )
        l1.addWidget(QLabel("Hide encrypted archives inside PNG."))
        b1 = QPushButton("Launch Tool")
        b1.clicked.connect(self.open_stego_tool)
        l1.addWidget(b1)

        c2 = QFrame(objectName="Card")
        l2 = QVBoxLayout(c2)
        l2.addWidget(
            QLabel("Ghost Link (SFTP)", styleSheet="font-weight:bold; font-size:16px")
        )
        l2.addWidget(QLabel("Secure Tunnel file transfer."))
        b2 = QPushButton("Connect...")
        b2.clicked.connect(self.open_ghostlink)
        l2.addWidget(b2)

        c3 = QFrame(objectName="Card")
        l3 = QVBoxLayout(c3)
        l3.addWidget(QLabel("PassGen", styleSheet="font-weight:bold; font-size:16px"))
        l3.addWidget(QLabel("Military-grade key gen."))
        b3 = QPushButton("Open Generator")
        b3.clicked.connect(self.open_passgen)
        l3.addWidget(b3)

        grid.addWidget(c1)
        grid.addWidget(c2)
        grid.addWidget(c3)
        l.addLayout(grid)
        l.addStretch()
        return p

    def on_drop(self, e):
        for u in e.mimeData().urls():
            self.file_list.addItem(u.toLocalFile())

    def add_files(self):
        fs, _ = QFileDialog.getOpenFileNames(self, "Select Files")
        for f in fs:
            self.file_list.addItem(f)

    def do_login(self):
        vault_name = self.cb_vaults.currentText()
        pwd = self.in_pass.text()
        code = self.in_2fa.text()

        path = self.vault_mgr.get_vault_path(vault_name)
        self.auth.set_active_vault(path)

        res, msg = self.auth.login(pwd, code)
        if res:
            self.session.start_session(b"TEMP", vault_name)
            self.load_user_settings()
            self.main_stack.fade_to_index(1)
            AuditLog.log("LOGIN", f"Accessed {vault_name}")
            self.update_log()
        else:
            QMessageBox.warning(self, "Error", msg)

    def do_logout(self):
        self.session.destroy_session()
        self.in_pass.clear()
        self.in_2fa.clear()
        self.main_stack.fade_to_index(0)

    def run_encrypt(self):
        files = [self.file_list.item(i).text() for i in range(self.file_list.count())]
        if not files:
            return

        mode = "pqc" if self.chk_pqc.isChecked() else "standard"
        pwd = self.in_pass.text()  # Using login pass for demo

        self.worker = TaskWorker(self._encrypt_task, files, pwd, mode)
        self.worker.finished.connect(self.on_task_done)
        self.worker.start()

    def _encrypt_task(self, files, pwd, mode):
        for f in files:
            CryptoEngine.encrypt_advanced(f, pwd, mode)
            if self.chk_shred.isChecked():
                Shredder.wipe_file(f)
        return "Encryption Complete"

    def run_decrypt(self):
        files = [self.file_list.item(i).text() for i in range(self.file_list.count())]
        pwd = self.in_pass.text()
        self.worker = TaskWorker(self._decrypt_task, files, pwd)
        self.worker.finished.connect(self.on_task_done)
        self.worker.start()

    def _decrypt_task(self, files, pwd):
        for f in files:
            CryptoEngine.decrypt_advanced(f, pwd)
        return "Decryption Complete"

    def on_task_done(self, res):
        ok, msg = res
        if ok:
            QMessageBox.information(self, "Success", msg)
            self.file_list.clear()
            self.update_log()
        else:
            QMessageBox.critical(self, "Error", msg)

    def update_log(self):
        self.list_audit.clear()
        for l in AuditLog.get_logs()[-10:]:
            self.list_audit.addItem(l)

    def apply_theme(self, theme_name):

        colors = {
            "Cyber Green": "#00e676",
            "Red Alert": "#ff3d3d",
            "Deep Purple": "#7f5af0",
            "Ocean Blue": "#00b4d8",
        }
        accent = colors.get(theme_name, "#00e676")

        NEW_STYLESHEET = STYLESHEET.replace(ACCENT_COLOR, accent)

        if theme_name == "Red Alert":
            NEW_STYLESHEET += (
                "\nQPushButton#Primary { background-color: #ff3d3d; color: white; }"
            )

        self.setStyleSheet(NEW_STYLESHEET)

        self.set_theme.setStyleSheet(f"border: 1px solid {accent};")

    def save_settings(self):
        algo = self.set_algo.currentText()
        shred = self.set_shred.value()
        theme = self.set_theme.currentText()

        pwd = self.in_pass.text()
        if not pwd:
            QMessageBox.warning(
                self, "Error", "Password required to update settings (Session Expired?)"
            )
            return

        self.auth.update_setting("algo", algo, pwd)
        self.auth.update_setting("shred", shred, pwd)
        self.auth.update_setting("theme", theme, pwd)

        self.apply_theme(theme)

        QMessageBox.information(
            self, "Saved", f"Configuration updated.\nTheme set to {theme}"
        )

    def load_user_settings(self):
        s = self.auth.settings
        if "shred" in s:
            self.set_shred.setValue(s["shred"])

    def open_stego_tool(self):
        dlg = StartStegoDialog(self)
        dlg.exec()

    def open_ghostlink(self):
        dlg = GhostLinkDialog(self)
        dlg.exec()

    def open_passgen(self):
        dlg = PassGenDialog(self)
        dlg.exec()


def main():
    app = QApplication(sys.argv)
    w = NDSFC_Pro()
    # Apply global font to QDialogs too
    app.setStyleSheet(STYLESHEET)
    w.show()
    sys.exit(app.exec())
