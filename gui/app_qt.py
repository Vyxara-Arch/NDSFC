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
    QFormLayout,
)
from PyQt6.QtCore import (
    Qt,
    QThread,
    pyqtSignal,
    QPropertyAnimation,
    QEasingCurve,
    QSize,
    QParallelAnimationGroup,
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

# --- DESIGN SYSTEM ---
ACCENT_COLOR = "#00e676"  # Default Green
BG_COLOR = "#09090b"
CARD_COLOR = "#18181b"
TEXT_COLOR = "#ffffff"

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


# --- ANIMATION HELPER ---
class FadeStack(QStackedWidget):
    """Custom Stacked Widget with Fade Animation"""

    def __init__(self):
        super().__init__()
        self.fade_anim = None

    def fade_to_index(self, index):
        if index == self.currentIndex():
            return

        current_widget = self.currentWidget()
        next_widget = self.widget(index)

        # Setup effects
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
        self.anim_group.finished.connect(lambda: self.setCurrentIndex(index))
        self.anim_group.start()


# --- WORKER THREAD ---
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


# --- MAIN WINDOW ---
class NDSFC_Pro(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("NDSFC | GitHub : MintyExtremum & Vyxara-Arch")
        self.resize(1150, 750)
        self.setStyleSheet(STYLESHEET)

        self.vault_mgr = VaultManager()
        self.auth = AuthManager()
        self.session = SecureSession()

        # Main Stack
        self.main_stack = FadeStack()
        self.setCentralWidget(self.main_stack)

        self.init_login_ui()
        self.init_dashboard_ui()

        # Check vaults
        if not self.vault_mgr.list_vaults():
            self.show_create_vault_dialog()

    def show_create_vault_dialog(self):
        # A simple dialog to init the first vault
        d = QWidget()
        d.setWindowTitle("Create Environment")
        # In real app use QDialog, simplified here
        name, ok = QInputDialog.getText(self, "Init", "Environment Name:")
        if ok and name:
            u, ok2 = QInputDialog.getText(self, "Init", "Username:")
            p, ok3 = QInputDialog.getText(self, "Init", "Password:")
            if ok2 and ok3:
                res, sec = self.vault_mgr.create_vault(name, u, p, "panic")
                QMessageBox.information(self, "Vault Created", f"Secret: {sec}")
                self.refresh_vaults()

    # --- LOGIN SCREEN ---
    def init_login_ui(self):
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        card = QFrame(objectName="Card")
        card.setFixedSize(450, 550)
        cl = QVBoxLayout(card)
        cl.setContentsMargins(40, 40, 40, 40)
        cl.setSpacing(20)

        # Logo Icon
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

    # --- DASHBOARD SCREEN ---
    def init_dashboard_ui(self):
        w = QWidget()
        row = QHBoxLayout(w)
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(0)

        # Sidebar
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

        # Nav Buttons
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

        # Tabs
        self.dash_stack.addWidget(self.tab_home())
        self.dash_stack.addWidget(self.tab_crypto())
        self.dash_stack.addWidget(self.tab_omega())
        self.dash_stack.addWidget(self.tab_settings())

        row.addWidget(sidebar)
        row.addWidget(self.dash_stack)
        self.main_stack.addWidget(w)

    def switch_tab(self, idx):
        self.dash_stack.fade_to_index(idx)
        # Highlight logic could go here

    # --- TABS IMPLEMENTATION ---
    def tab_home(self):
        p = QWidget()
        l = QVBoxLayout(p)
        l.setContentsMargins(50, 50, 50, 50)

        l.addWidget(
            QLabel("System Overview", styleSheet="font-size: 28px; font-weight: bold;")
        )
        l.addSpacing(20)

        cards = QHBoxLayout()
        cards.addWidget(
            self.mk_stat_card(
                "Active Environment",
                lambda: self.session.current_vault or "N/A",
                ACCENT_COLOR,
            )
        )
        cards.addWidget(self.mk_stat_card("RAM Volatility", "Secure", "#7f5af0"))
        cards.addWidget(self.mk_stat_card("CPU Encryption", "HW Accel", "#2cb67d"))
        l.addLayout(cards)

        l.addSpacing(40)
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

        # Config Area
        conf = QHBoxLayout()
        self.chk_shred = QCheckBox("Secure Shred (3-pass)")
        self.chk_shred.setChecked(True)
        self.chk_pqc = QCheckBox("Quantum-Resistant Layer")

        conf.addWidget(self.chk_shred)
        conf.addWidget(self.chk_pqc)
        conf.addStretch()
        l.addLayout(conf)

        # Drag Drop
        self.file_list = QListWidget()
        self.file_list.setAcceptDrops(True)
        self.file_list.dragEnterEvent = lambda e: e.accept()
        self.file_list.dragMoveEvent = lambda e: e.accept()
        self.file_list.dropEvent = self.on_drop
        self.file_list.setToolTip("Drag files here")
        self.file_list.setStyleSheet("border: 2px dashed #3f3f46; background: #141417;")
        l.addWidget(self.file_list)

        # Actions
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
        # Card 1
        c1 = QFrame(objectName="Card")
        l1 = QVBoxLayout(c1)
        l1.addWidget(
            QLabel("Steganography", styleSheet="font-weight:bold; font-size:16px")
        )
        l1.addWidget(QLabel("Hide encrypted archives inside PNG."))
        b1 = QPushButton("Launch Tool")
        b1.clicked.connect(
            lambda: QMessageBox.information(self, "Info", "Select Cover Image...")
        )
        l1.addWidget(b1)

        # Card 2
        c2 = QFrame(objectName="Card")
        l2 = QVBoxLayout(c2)
        l2.addWidget(
            QLabel("Ghost Link (SFTP)", styleSheet="font-weight:bold; font-size:16px")
        )
        l2.addWidget(QLabel("Secure Tunnel file transfer."))
        b2 = QPushButton("Connect...")
        l2.addWidget(b2)

        grid.addWidget(c1)
        grid.addWidget(c2)
        l.addLayout(grid)
        l.addStretch()
        return p

    # --- HELPERS ---
    def mk_stat_card(self, t, v_func, color):
        f = QFrame(objectName="Card")
        l = QVBoxLayout(f)
        val = v_func() if callable(v_func) else v_func
        l.addWidget(QLabel(t, styleSheet="color: gray"))
        l.addWidget(
            QLabel(
                val, styleSheet=f"font-size: 22px; font-weight: bold; color: {color}"
            )
        )
        return f

    def on_drop(self, e):
        for u in e.mimeData().urls():
            self.file_list.addItem(u.toLocalFile())

    def add_files(self):
        fs, _ = QFileDialog.getOpenFileNames(self, "Select Files")
        for f in fs:
            self.file_list.addItem(f)

    # --- ACTIONS ---
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
        self.log_list.clear()
        for l in AuditLog.get_logs()[-10:]:
            self.log_list.addItem(l)

    def apply_theme(self, theme_name):
        # Палитра
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

        self.auth.update_setting("algo", algo)
        self.auth.update_setting("shred", shred)
        self.auth.update_setting("theme", theme)

        self.apply_theme(theme)

        QMessageBox.information(
            self, "Saved", f"Configuration updated.\nTheme set to {theme}"
        )

    def load_user_settings(self):
        s = self.auth.settings
        if "shred" in s:
            self.set_shred.setValue(s["shred"])


def main():
    app = QApplication(sys.argv)
    w = NDSFC_Pro()
    w.show()
    sys.exit(app.exec())
