import sys
import os
import time
import qtawesome as qta

from PyQt6.QtWidgets import (
    QApplication,
    QMainWindow,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QFrame,
    QFileDialog,
    QMessageBox,
    QListWidget,
    QComboBox,
    QCheckBox,
    QInputDialog,
    QSpinBox,
    QFormLayout,
    QGridLayout,
    QTableWidget,
    QTableWidgetItem,
    QAbstractItemView,
)
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QIcon

from gui import styles
from gui.widgets import SystemMonitorWidget, FadeStack
from gui.dialogs import (
    StartStegoDialog,
    GhostLinkDialog,
    PassGenDialog,
    NotesDialog,
    InitVaultDialog,
    ThemeCreatorDialog,
    FolderWatcherDialog,
    RecoveryDialog,
)
from gui.workers import TaskWorker

from core.auth import AuthManager
from core.vault_manager import VaultManager
from core.crypto_engine import CryptoEngine
from core.shredder import Shredder
from core.audit import AuditLog
from core.session import SecureSession
from core.backup_manager import BackupManager
from core.folder_watcher import FolderWatcher
from core.theme_manager import ThemeManager
from core.indexer import IndexManager
from core.tools import SecurityTools

class NDSFC_Pro(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("NDSFC | GitHub : MintyExtremum & Vyxara-Arch")
        self.resize(1150, 750)
        self.setMinimumSize(980, 640)

        self.vault_mgr = VaultManager()
        self.auth = AuthManager()
        self.session = SecureSession()
        self._session_password = None
        self.watcher = None
        self.theme_manager = ThemeManager()
        self.indexer = None
        self.current_theme_mode = "light"
        self.current_theme_name = "Noxium Teal"
        self.auto_lock_timer = QTimer(self)
        self.auto_lock_timer.setSingleShot(True)
        self.auto_lock_timer.timeout.connect(self.do_logout)
        app = QApplication.instance()
        if app:
            app.installEventFilter(self)

        palette = self.theme_manager.get_palette(
            self.current_theme_mode, self.current_theme_name
        )
        styles.apply_palette(palette)
        self.setStyleSheet(styles.build_stylesheet())

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
        w.setObjectName("LoginPage")

        layout = QVBoxLayout(w)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        card = QFrame(objectName="Panel")
        card.setMinimumSize(420, 520)
        card.setMaximumWidth(560)

        cl = QVBoxLayout(card)
        cl.setContentsMargins(40, 50, 40, 50)
        cl.setSpacing(20)

        # Icon / Logo
        icon_lbl = QLabel()
        icon_lbl.setPixmap(
            qta.icon("fa5s.shield-alt", color=styles.ACCENT_COLOR).pixmap(64, 64)
        )
        icon_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        cl.addWidget(icon_lbl)

        title = QLabel("NOXIUM VAULT")
        title.setStyleSheet(
            "font-size: 20px; font-weight: 700; letter-spacing: 2px;"
        )
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        cl.addWidget(title)

        cl.addSpacing(20)

        # Inputs
        self.cb_vaults = QComboBox()
        self.cb_vaults.setMinimumHeight(45)
        self.refresh_vaults()

        self.in_pass = QLineEdit(placeholderText="Access Key")
        self.in_pass.setEchoMode(QLineEdit.EchoMode.Password)

        self.in_2fa = QLineEdit(placeholderText="2FA Token")
        self.in_2fa.setAlignment(Qt.AlignmentFlag.AlignCenter)

        cl.addWidget(self.cb_vaults)
        cl.addWidget(self.in_pass)
        cl.addWidget(self.in_2fa)

        cl.addSpacing(10)

        # Login Button
        btn_login = QPushButton("SIGN IN", objectName="Primary")
        btn_login.setMinimumHeight(50)
        btn_login.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_login.clicked.connect(self.do_login)
        cl.addWidget(btn_login)

        cl.addStretch()

        # Footer Actions
        row = QHBoxLayout()
        btn_new = QPushButton(" Create New", objectName="LinkButton")
        btn_new.setIcon(qta.icon("fa5s.plus", color=styles.TEXT_MUTED))
        btn_new.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_new.clicked.connect(self.show_create_vault_dialog)

        btn_imp = QPushButton(" Import", objectName="LinkButton")
        btn_imp.setIcon(qta.icon("fa5s.file-import", color=styles.TEXT_MUTED))
        btn_imp.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_imp.clicked.connect(self.do_vault_import)

        row.addWidget(btn_new)
        row.addStretch()
        row.addWidget(btn_imp)
        cl.addLayout(row)

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
        row.setStretch(0, 0)
        row.setStretch(1, 1)

        sidebar = QFrame(objectName="Sidebar")
        sidebar.setMinimumWidth(240)
        sidebar.setMaximumWidth(320)
        sb_l = QVBoxLayout(sidebar)
        sb_l.setContentsMargins(20, 40, 20, 20)

        title = QLabel("NOXIUM CONTROL")
        title.setProperty("tone", "accent")
        title.setStyleSheet(
            "font-size: 16px; font-weight: 700; letter-spacing: 3px;"
        )
        sb_l.addWidget(title)
        sb_l.addSpacing(40)

        self.dash_stack = FadeStack()

        btns = [
            ("OPERATIONS", "fa5s.chart-pie", 0),
            ("CRYPTOGRAPHY", "fa5s.lock", 1),
            ("OMEGA TOOLS", "fa5s.magic", 2),
            ("ENVIRONMENT", "fa5s.cog", 3),
        ]

        self.nav_buttons = []
        for name, icon, idx in btns:
            b = QPushButton(f"  {name}")
            b.setIcon(qta.icon(icon, color=styles.TEXT_MUTED))
            b.setCursor(Qt.CursorShape.PointingHandCursor)
            b.setProperty("nav", True)
            b.setProperty("active", False)
            b.clicked.connect(lambda ch, i=idx: self.switch_tab(i))
            self.nav_buttons.append((b, icon))
            sb_l.addWidget(b)

        sb_l.addStretch()
        b_out = QPushButton(" DISCONNECT", objectName="Danger")
        b_out.setIcon(qta.icon("fa5s.power-off", color=styles.TEXT_MUTED))
        b_out.clicked.connect(self.do_logout)
        sb_l.addWidget(b_out)

        self.dash_stack.addWidget(self.tab_home())
        self.dash_stack.addWidget(self.tab_crypto())
        self.dash_stack.addWidget(self.tab_omega())
        self.dash_stack.addWidget(self.tab_settings())

        row.addWidget(sidebar)
        row.addWidget(self.dash_stack)
        self.main_stack.addWidget(w)
        self.set_nav_active(0)

    def switch_tab(self, idx):
        self.dash_stack.fade_to_index(idx)
        self.set_nav_active(idx)

    def set_nav_active(self, idx):
        for i, (btn, icon) in enumerate(self.nav_buttons):
            active = i == idx
            btn.setProperty("active", active)
            color = styles.ACCENT_COLOR if active else styles.TEXT_MUTED
            btn.setIcon(qta.icon(icon, color=color))
            btn.style().unpolish(btn)
            btn.style().polish(btn)

    def tab_home(self):
        p = QWidget()
        l = QVBoxLayout(p)
        l.setContentsMargins(30, 30, 30, 30)

        # Header
        header = QHBoxLayout()
        lbl_welcome = QLabel("Mission Control")
        lbl_welcome.setStyleSheet("font-size: 28px; font-weight: bold;")
        header.addWidget(lbl_welcome)
        header.addStretch()

        # Search Bar
        self.txt_search = QLineEdit()
        self.txt_search.setPlaceholderText("Search Encrypted Index...")
        self.txt_search.setMinimumWidth(240)
        self.txt_search.setMaximumWidth(420)
        self.txt_search.setObjectName("SearchField")
        self.txt_search.textChanged.connect(self.do_search)
        header.addWidget(self.txt_search)

        l.addLayout(header)
        l.addSpacing(20)

        # Content Stack
        self.dash_content = FadeStack()

        # PAGE 0: Widgets
        page_widgets = QWidget()
        l_widgets = QVBoxLayout(page_widgets)
        l_widgets.setContentsMargins(0, 0, 0, 0)

        grid = QGridLayout()
        grid.setSpacing(20)
        grid.setColumnStretch(0, 1)
        grid.setColumnStretch(1, 1)
        grid.setColumnStretch(2, 1)

        # 1. System Monitor (Row 0, Col 0)
        sys_mon = SystemMonitorWidget()
        grid.addWidget(sys_mon, 0, 0)

        # 2. Vault Status (Row 0, Col 1)
        v_card = QFrame(objectName="Card")
        v_card.setMinimumHeight(160)
        vl = QVBoxLayout(v_card)
        lbl_active = QLabel("Active Environment")
        lbl_active.setProperty("tone", "muted")
        lbl_active.setStyleSheet("font-weight: bold;")
        vl.addWidget(lbl_active)
        self.lbl_vault_name = QLabel(self.session.current_vault or "LOCKED")
        self.lbl_vault_name.setProperty("tone", "accent")
        self.lbl_vault_name.setStyleSheet("font-size: 24px; font-weight: bold;")
        vl.addWidget(self.lbl_vault_name)
        vl.addStretch()
        b_lock = QPushButton("LOCK NOW")
        b_lock.setObjectName("Secondary")
        b_lock.clicked.connect(self.do_logout)
        vl.addWidget(b_lock)
        grid.addWidget(v_card, 0, 1)

        # 3. Quick Actions (Row 0, Col 2)
        q_card = QFrame(objectName="Card")
        q_card.setMinimumHeight(160)
        ql = QVBoxLayout(q_card)
        lbl_quick = QLabel("Quick Actions")
        lbl_quick.setProperty("tone", "muted")
        lbl_quick.setStyleSheet("font-weight: bold;")
        ql.addWidget(lbl_quick)

        bq1 = QPushButton("  Encrypt File")
        bq1.setIcon(qta.icon("fa5s.lock", color=styles.ACCENT_COLOR))
        bq1.clicked.connect(lambda: self.switch_tab(1))  # Crypto tab
        ql.addWidget(bq1)

        bq2 = QPushButton("  Secure Tunnel")
        bq2.setIcon(qta.icon("fa5s.network-wired", color=styles.ACCENT_COLOR))
        bq2.clicked.connect(self.open_ghostlink)
        ql.addWidget(bq2)

        bq3 = QPushButton("  Rebuild Index")
        bq3.setIcon(qta.icon("fa5s.search-plus", color=styles.ACCENT_COLOR))
        bq3.clicked.connect(self.rebuild_index)
        ql.addWidget(bq3)

        grid.addWidget(q_card, 0, 2)

        # Row 1: Audit Log
        audit_frame = QFrame(objectName="Card")
        al = QVBoxLayout(audit_frame)
        lbl_audit = QLabel("Security Audit Log")
        lbl_audit.setProperty("tone", "muted")
        lbl_audit.setStyleSheet("font-weight: bold;")
        al.addWidget(lbl_audit)

        self.list_audit = QListWidget()
        self.list_audit.setStyleSheet(
            "background: transparent; border: 0px; font-family: Consolas;"
        )
        # Dummy data
        self.list_audit.addItem("[SYSTEM] Session Initialized")
        self.list_audit.addItem("[AUDIT] Integrity Check Passed")

        al.addWidget(self.list_audit)
        grid.addWidget(audit_frame, 1, 0, 1, 3)

        l_widgets.addLayout(grid)
        l_widgets.addStretch()
        self.dash_content.addWidget(page_widgets)

        # PAGE 1: Search Results
        page_results = QWidget()
        l_results = QVBoxLayout(page_results)

        lbl_res = QLabel("Search Results")
        lbl_res.setProperty("tone", "accent")
        lbl_res.setStyleSheet("font-size: 18px; font-weight: bold;")
        l_results.addWidget(lbl_res)

        self.table_results = QTableWidget()
        self.table_results.setObjectName("ResultsTable")
        self.table_results.setColumnCount(5)
        self.table_results.setHorizontalHeaderLabels(
            ["Filename", "Size", "Date", "Original Path", "Algo"]
        )
        self.table_results.horizontalHeader().setStretchLastSection(True)
        self.table_results.setAlternatingRowColors(True)
        self.table_results.setSelectionBehavior(
            QAbstractItemView.SelectionBehavior.SelectRows
        )
        self.table_results.setEditTriggers(
            QAbstractItemView.EditTrigger.NoEditTriggers
        )
        self.table_results.verticalHeader().setVisible(False)
        l_results.addWidget(self.table_results)

        self.dash_content.addWidget(page_results)

        l.addWidget(self.dash_content)
        return p

    def do_search(self, text):
        if not text:
            self.dash_content.fade_to_index(0)
            return

        self.dash_content.fade_to_index(1)
        if self.indexer:
            res = self.indexer.search(text)
            self.table_results.setRowCount(0)
            for row, item in enumerate(res):
                self.table_results.insertRow(row)
                self.table_results.setItem(row, 0, QTableWidgetItem(item["filename"]))
                self.table_results.setItem(row, 1, QTableWidgetItem(str(item["size"])))
                self.table_results.setItem(row, 2, QTableWidgetItem(item["c_time"]))
                self.table_results.setItem(
                    row, 3, QTableWidgetItem(item.get("path", "Unknown"))
                )
                self.table_results.setItem(
                    row, 4, QTableWidgetItem(item.get("algo", "Unknown"))
                )

    def rebuild_index(self):
        d = QFileDialog.getExistingDirectory(self, "Select Directory to Index")
        if d and self.indexer:
            self.worker = TaskWorker(self.indexer.scan_directory, d)
            self.worker.finished.connect(
                lambda: QMessageBox.information(
                    self, "Index", "Indexing Operation Complete"
                )
            )
            self.worker.start()

    def tab_crypto(self):
        p = QWidget()
        l = QVBoxLayout(p)
        l.setContentsMargins(30, 30, 30, 30)

        # Header
        header = QHBoxLayout()
        lbl_title = QLabel("Cryptographer")
        lbl_title.setStyleSheet("font-size: 28px; font-weight: bold;")
        header.addWidget(lbl_title)
        header.addStretch()
        l.addLayout(header)
        l.addSpacing(20)

        # Grid Layout for Controls and File List
        grid = QGridLayout()
        grid.setSpacing(20)
        grid.setColumnStretch(0, 1)
        grid.setColumnStretch(1, 2)

        # Left Panel: Configuration
        config_card = QFrame(objectName="Card")
        config_card.setMinimumWidth(300)
        config_card.setMaximumWidth(380)
        cl = QVBoxLayout(config_card)
        cl.setSpacing(15)

        lbl_settings = QLabel("Encryption Settings")
        lbl_settings.setProperty("tone", "muted")
        lbl_settings.setStyleSheet("font-weight: bold; font-size: 16px;")
        cl.addWidget(lbl_settings)

        # Mode Selector
        lbl_mode = QLabel("Mode:")
        lbl_mode.setProperty("tone", "muted")
        cl.addWidget(lbl_mode)
        self.crypto_mode = QComboBox()
        self.crypto_mode.addItems(
            [
                "ChaCha20-Poly1305 (Fast)",
                "AES-256-GCM (Balanced)",
                "LetNoxEnc-256 (Experimental)",
                "LetNoxEnc-512 (Experimental)",
            ]
        )
        if CryptoEngine.pqc_available():
            self.crypto_mode.addItem("PQC Hybrid (Kyber)")
        cl.addWidget(self.crypto_mode)

        # Options
        cl.addSpacing(10)
        lbl_options = QLabel("Options:")
        lbl_options.setProperty("tone", "muted")
        cl.addWidget(lbl_options)
        self.chk_shred = QCheckBox("Secure Shred Original")
        self.chk_shred.setChecked(True)
        cl.addWidget(self.chk_shred)

        self.chk_compress = QCheckBox("Compress Before Encrypt")
        cl.addWidget(self.chk_compress)

        cl.addStretch()

        # File Stats
        lbl_stats = QLabel("Statistics:")
        lbl_stats.setProperty("tone", "muted")
        lbl_stats.setStyleSheet("font-weight: bold;")
        cl.addWidget(lbl_stats)
        self.lbl_file_count = QLabel("Files: 0")
        self.lbl_file_count.setProperty("tone", "accent")
        self.lbl_file_count.setProperty("mono", True)
        self.lbl_file_count.setStyleSheet("font-weight: 600;")
        cl.addWidget(self.lbl_file_count)

        self.lbl_total_size = QLabel("Total: 0 KB")
        self.lbl_total_size.setProperty("tone", "accent-secondary")
        self.lbl_total_size.setProperty("mono", True)
        self.lbl_total_size.setStyleSheet("font-weight: 600;")
        cl.addWidget(self.lbl_total_size)

        grid.addWidget(config_card, 0, 0, 2, 1)

        # Right Panel: File List
        file_card = QFrame(objectName="Card")
        fcl = QVBoxLayout(file_card)

        lbl_queue = QLabel("File Queue")
        lbl_queue.setProperty("tone", "muted")
        lbl_queue.setStyleSheet("font-weight: bold; font-size: 16px;")
        fcl.addWidget(lbl_queue)

        self.file_table = QTableWidget()
        self.file_table.setObjectName("DropTable")
        self.file_table.setColumnCount(3)
        self.file_table.setHorizontalHeaderLabels(["Filename", "Size", "Path"])
        self.file_table.horizontalHeader().setStretchLastSection(True)
        self.file_table.setSelectionBehavior(
            QAbstractItemView.SelectionBehavior.SelectRows
        )
        self.file_table.setAlternatingRowColors(True)
        self.file_table.setEditTriggers(
            QAbstractItemView.EditTrigger.NoEditTriggers
        )
        self.file_table.verticalHeader().setVisible(False)
        self.file_table.setAcceptDrops(True)
        self.file_table.dragEnterEvent = lambda e: e.accept()
        self.file_table.dragMoveEvent = lambda e: e.accept()
        # self.file_table.dropEvent = self.on_drop # Connected logic should handle this
        self.file_table.dropEvent = self.on_drop
        self.file_table.setToolTip("Drag & drop files here")
        self.file_table.itemSelectionChanged.connect(self.update_file_stats)
        fcl.addWidget(self.file_table)

        # File Actions
        file_acts = QHBoxLayout()
        b_add = QPushButton(" Add Files")
        b_add.setIcon(qta.icon("fa5s.plus", color=styles.TEXT_COLOR))
        b_add.clicked.connect(self.add_files)

        b_remove = QPushButton(" Remove")
        b_remove.setIcon(qta.icon("fa5s.trash", color=styles.TEXT_COLOR))
        b_remove.clicked.connect(self.remove_selected_files)

        b_clear = QPushButton(" Clear All")
        b_clear.clicked.connect(lambda: self.file_table.setRowCount(0))

        file_acts.addWidget(b_add)
        file_acts.addWidget(b_remove)
        file_acts.addStretch()
        file_acts.addWidget(b_clear)
        fcl.addLayout(file_acts)

        grid.addWidget(file_card, 0, 1, 2, 1)

        l.addLayout(grid)
        l.addSpacing(20)

        # Action Buttons
        action_row = QHBoxLayout()

        b_enc = QPushButton(" ENCRYPT ALL", objectName="Primary")
        b_enc.setIcon(qta.icon("fa5s.lock", color="white"))
        b_enc.setMinimumHeight(50)
        b_enc.clicked.connect(self.run_encrypt)

        b_dec = QPushButton(" DECRYPT ALL", objectName="Secondary")
        b_dec.setIcon(qta.icon("fa5s.unlock", color=styles.TEXT_COLOR))
        b_dec.setMinimumHeight(50)
        b_dec.clicked.connect(self.run_decrypt)

        action_row.addWidget(b_enc)
        action_row.addWidget(b_dec)
        l.addLayout(action_row)

        l.addStretch()
        return p

    def tab_settings(self):
        p = QWidget()
        l = QVBoxLayout(p)
        l.setContentsMargins(30, 30, 30, 30)
        l.setSpacing(20)

        title = QLabel(
            "Environment Settings", styleSheet="font-size: 28px; font-weight: bold;"
        )
        subtitle = QLabel("Manage encryption, PQC, appearance, and recovery tools.")
        subtitle.setProperty("tone", "muted")
        l.addWidget(title)
        l.addWidget(subtitle)

        grid = QGridLayout()
        grid.setSpacing(20)
        grid.setColumnStretch(0, 1)
        grid.setColumnStretch(1, 1)

        def make_card(header, helper):
            card = QFrame(objectName="Card")
            card_l = QVBoxLayout(card)
            card_l.setContentsMargins(24, 24, 24, 24)
            card_l.setSpacing(12)
            h = QLabel(header)
            h.setStyleSheet("font-size: 16px; font-weight: 700;")
            card_l.addWidget(h)
            if helper:
                sub = QLabel(helper)
                sub.setProperty("tone", "muted")
                card_l.addWidget(sub)
            form = QFormLayout()
            form.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.AllNonFixedFieldsGrow)
            form.setRowWrapPolicy(QFormLayout.RowWrapPolicy.WrapLongRows)
            form.setLabelAlignment(
                Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter
            )
            form.setHorizontalSpacing(16)
            form.setVerticalSpacing(12)
            card_l.addLayout(form)
            return card, form

        self.set_algo = QComboBox()
        self.set_algo.addItems(
            [
                "ChaCha20-Poly1305 (Fast)",
                "AES-256-GCM (Balanced)",
                "LetNoxEnc-256 (Experimental)",
                "LetNoxEnc-512 (Experimental)",
            ]
        )
        if CryptoEngine.pqc_available():
            self.set_algo.addItem("PQC Hybrid (Kyber)")

        self.chk_default_compress = QCheckBox("Compress before encrypt")

        self.set_theme_mode = QComboBox()
        self.set_theme_mode.addItems(["Light", "Dark"])

        self.set_theme = QComboBox()
        self.set_theme.addItems(self.theme_manager.get_all_theme_names())

        self.chk_pqc_enable = QCheckBox("Enable PQC Hybrid")
        self.chk_pqc_enable.toggled.connect(self.update_pqc_controls)
        self.set_pqc_kem = QComboBox()
        kem_names = CryptoEngine.pqc_kem_names()
        if not kem_names:
            kem_names = ["kyber512"]
        self.set_pqc_kem.addItems(kem_names)
        self.lbl_pqc_status = QLabel("")
        self.lbl_pqc_status.setProperty("tone", "muted")

        if not CryptoEngine.pqc_available():
            self.chk_pqc_enable.setEnabled(False)
            self.set_pqc_kem.setEnabled(False)
            self.chk_pqc_enable.setToolTip("PQC library not available on this system.")

        self.set_shred = QSpinBox()
        self.set_shred.setRange(1, 35)
        self.set_shred.setValue(3)
        self.set_shred.setSuffix(" Passes")

        self.set_auto_lock = QSpinBox()
        self.set_auto_lock.setRange(0, 120)
        self.set_auto_lock.setValue(10)
        self.set_auto_lock.setSuffix(" min")

        self.chk_device_lock = QCheckBox("Bind encrypted files to this device")
        self.chk_device_lock.setToolTip(
            "When enabled, encrypted files can only be opened on this machine."
        )
        self.chk_device_lock.toggled.connect(self.on_device_lock_toggled)

        btn_create = QPushButton("Design Custom Theme")
        btn_create.clicked.connect(self.open_theme_creator)

        btn_export = QPushButton("Backup Vault (.vib)")
        btn_export.clicked.connect(self.do_vault_export)

        btn_recovery = QPushButton("Generate Recovery Shares")
        btn_recovery.clicked.connect(self.open_recovery_shares)

        btn_save = QPushButton("Save Configuration", objectName="Primary")
        btn_save.setMinimumHeight(44)
        btn_save.clicked.connect(self.save_settings)

        enc_card, enc_form = make_card(
            "Encryption", "Default algorithm and PQC settings."
        )
        enc_form.addRow("Default Encryption:", self.set_algo)
        enc_form.addRow("Compression:", self.chk_default_compress)
        enc_form.addRow("PQC Hybrid:", self.chk_pqc_enable)
        enc_form.addRow("PQC KEM:", self.set_pqc_kem)
        enc_form.addRow("PQC Status:", self.lbl_pqc_status)

        ui_card, ui_form = make_card("Appearance", "Theme mode and UI accents.")
        ui_form.addRow("Theme Mode:", self.set_theme_mode)
        ui_form.addRow("UI Accent:", self.set_theme)
        ui_form.addRow("Custom Theme:", btn_create)

        sec_card, sec_form = make_card("Security", "Auto-lock, shredding, recovery.")
        sec_form.addRow("Shredder Intensity:", self.set_shred)
        sec_form.addRow("Auto-Lock:", self.set_auto_lock)
        sec_form.addRow("Device Lock:", self.chk_device_lock)
        sec_form.addRow("Recovery Kit:", btn_recovery)

        vault_card, vault_form = make_card("Backups", "Export your vault safely.")
        vault_form.addRow("Vault Backup:", btn_export)

        grid.addWidget(enc_card, 0, 0)
        grid.addWidget(ui_card, 0, 1)
        grid.addWidget(sec_card, 1, 0)
        grid.addWidget(vault_card, 1, 1)

        l.addLayout(grid)
        l.addStretch()
        l.addWidget(btn_save)
        self.update_pqc_controls()
        return p

    def update_pqc_controls(self):
        if not hasattr(self, "chk_pqc_enable"):
            return
        enabled = self.chk_pqc_enable.isChecked()
        available, status = CryptoEngine.pqc_status()
        self.set_pqc_kem.setEnabled(available and enabled)
        if available:
            self.lbl_pqc_status.setText("Available")
            self.lbl_pqc_status.setToolTip("")
        else:
            self.lbl_pqc_status.setText("Unavailable: install pqcrypto")
            self.lbl_pqc_status.setToolTip(status)

    def on_device_lock_toggled(self, checked):
        if not checked:
            return
        if getattr(self, "_device_lock_prompting", False):
            return
        self._device_lock_prompting = True
        try:
            msg = QMessageBox(self)
            msg.setIcon(QMessageBox.Icon.Warning)
            msg.setWindowTitle("Device Lock Disclaimer")
            msg.setText("Device Lock привязывает зашифрованные файлы к этому устройству.")
            msg.setInformativeText(
                "Основные условия:\n"
                "• Файлы, зашифрованные с Device Lock, не откроются на другой машине.\n"
                "• Переустановка ОС или смена железа может привести к полной потере доступа.\n"
                "• Отключение опции не снимает блокировку с уже зашифрованных файлов.\n"
                "• Рекомендуется хранить резервные копии без Device Lock.\n"
                "• Функция экспериментальная, вы используете её на свой риск."
            )
            accept_btn = msg.addButton(
                "Я принимаю условия, продолжить", QMessageBox.ButtonRole.AcceptRole
            )
            msg.addButton("Отмена", QMessageBox.ButtonRole.RejectRole)
            msg.exec()
            if msg.clickedButton() != accept_btn:
                self.chk_device_lock.blockSignals(True)
                self.chk_device_lock.setChecked(False)
                self.chk_device_lock.blockSignals(False)
        finally:
            self._device_lock_prompting = False

    def tab_omega(self):
        p = QWidget()
        l = QVBoxLayout(p)
        l.setContentsMargins(50, 50, 50, 50)
        l.addWidget(
            QLabel("Omega Utilities", styleSheet="font-size: 28px; font-weight: bold;")
        )

        grid = QGridLayout()
        grid.setSpacing(20)
        grid.setColumnStretch(0, 1)
        grid.setColumnStretch(1, 1)
        grid.setColumnStretch(2, 1)

        # Card 1: Stego
        c1 = QFrame(objectName="Card")
        l1 = QVBoxLayout(c1)
        l1.addWidget(
            QLabel("Steganography", styleSheet="font-weight:bold; font-size:16px")
        )
        l1.addWidget(QLabel("Hide encrypted archives inside PNG."))
        b1 = QPushButton("Launch Tool")
        b1.clicked.connect(self.open_stego_tool)
        l1.addWidget(b1)

        # Card 2: Ghost
        c2 = QFrame(objectName="Card")
        l2 = QVBoxLayout(c2)
        l2.addWidget(
            QLabel("Ghost Link (SFTP)", styleSheet="font-weight:bold; font-size:16px")
        )
        l2.addWidget(QLabel("Secure Tunnel file transfer."))
        b2 = QPushButton("Connect...")
        b2.clicked.connect(self.open_ghostlink)
        l2.addWidget(b2)

        # Card 3: PassGen
        c3 = QFrame(objectName="Card")
        l3 = QVBoxLayout(c3)
        l3.addWidget(QLabel("PassGen", styleSheet="font-weight:bold; font-size:16px"))
        l3.addWidget(QLabel("Military-grade key gen."))
        b3 = QPushButton("Open Generator")
        b3.clicked.connect(self.open_passgen)
        l3.addWidget(b3)

        # Card 4: Notes
        c4 = QFrame(objectName="Card")
        l4 = QVBoxLayout(c4)
        l4.addWidget(
            QLabel("Secure Journal", styleSheet="font-weight:bold; font-size:16px")
        )
        l4.addWidget(QLabel("Encrypted personal notes."))
        b4 = QPushButton("Open Journal")
        b4.clicked.connect(self.open_notes)
        l4.addWidget(b4)

        # Card 5: Watcher
        c5 = QFrame(objectName="Card")
        l5 = QVBoxLayout(c5)
        l5.addWidget(
            QLabel("Folder Watcher", styleSheet="font-weight:bold; font-size:16px")
        )
        l5.addWidget(QLabel("Auto-encrypt dropped files."))
        b5 = QPushButton("Manage Service")
        b5.clicked.connect(self.open_folder_watcher)
        l5.addWidget(b5)

        grid.addWidget(c1, 0, 0)
        grid.addWidget(c2, 0, 1)
        grid.addWidget(c3, 0, 2)
        grid.addWidget(c4, 1, 0)
        grid.addWidget(c5, 1, 1)

        l.addLayout(grid)
        l.addStretch()
        return p

    def on_drop(self, e):
        files = []
        for u in e.mimeData().urls():
            path = u.toLocalFile()
            if os.path.exists(path) and os.path.isfile(path):
                files.append(path)
        if files:
            self._add_files_to_table(files)

    def add_files(self):
        fs, _ = QFileDialog.getOpenFileNames(self, "Select Files")
        self._add_files_to_table(fs)

    def _add_files_to_table(self, files):
        for f in files:
            if not os.path.exists(f):
                continue
            row = self.file_table.rowCount()
            self.file_table.insertRow(row)
            name = os.path.basename(f)
            size = os.path.getsize(f)
            self.file_table.setItem(row, 0, QTableWidgetItem(name))
            self.file_table.setItem(row, 1, QTableWidgetItem(f"{size/1024:.2f} KB"))
            self.file_table.setItem(row, 2, QTableWidgetItem(f))
        self.update_file_stats()

    def remove_selected_files(self):
        rows = sorted(
            set(index.row() for index in self.file_table.selectedIndexes()),
            reverse=True,
        )
        for r in rows:
            self.file_table.removeRow(r)
        self.update_file_stats()

    def update_file_stats(self):
        count = self.file_table.rowCount()
        total_size = 0
        for i in range(count):
            path = self.file_table.item(i, 2).text()
            if os.path.exists(path):
                total_size += os.path.getsize(path)

        self.lbl_file_count.setText(f"Files: {count}")

        if total_size < 1024:
            size_str = f"{total_size} B"
        elif total_size < 1024 * 1024:
            size_str = f"{total_size / 1024:.2f} KB"
        elif total_size < 1024 * 1024 * 1024:
            size_str = f"{total_size / (1024 * 1024):.2f} MB"
        else:
            size_str = f"{total_size / (1024 * 1024 * 1024):.2f} GB"

        self.lbl_total_size.setText(f"Total: {size_str}")

    def do_login(self):
        vault_name = self.cb_vaults.currentText()
        pwd = self.in_pass.text()
        code = self.in_2fa.text()

        if not vault_name:
            QMessageBox.warning(self, "Error", "Select a vault first.")
            return
        if not pwd or not code:
            QMessageBox.warning(self, "Error", "Password and 2FA code required.")
            return

        path = self.vault_mgr.get_vault_path(vault_name)
        self.auth.set_active_vault(path)

        res, msg = self.auth.login(pwd, code)
        if res:
            self._session_password = pwd
            algo = self.auth.settings.get("file_algo", "chacha20-poly1305")
            compress = self.auth.settings.get("file_compress", False)
            pqc_enabled = self.auth.settings.get("pqc_enabled", False)
            pqc_kem = self.auth.settings.get("pqc_kem", "kyber512")
            device_lock = self.auth.settings.get("device_lock_enabled", False)
            pqc_pub = None
            if pqc_enabled:
                if not self.auth.ensure_pqc_keys(pwd, kem_name=pqc_kem):
                    QMessageBox.warning(self, "Warning", "PQC keys unavailable. Falling back.")
                    pqc_enabled = False
                pqc_pub = self.auth.get_pqc_public_key()
            self.watcher = FolderWatcher(
                CryptoEngine,
                pwd,
                mode=algo,
                compress=compress,
                pqc_public_key=pqc_pub,
                pqc_kem=pqc_kem,
                device_lock=device_lock,
            )
            self.indexer = IndexManager(
                vault_name, password=pwd, vault_key=self.auth.vault_key
            )
            self.session.start_session(self.auth.vault_key or b"TEMP", vault_name)
            if hasattr(self, "lbl_vault_name"):
                self.lbl_vault_name.setText(vault_name)
            self.load_user_settings()
            self.reset_inactivity_timer()
            self.main_stack.fade_to_index(1)
            AuditLog.log("LOGIN", f"Accessed {vault_name}")
            self.update_log()
            self.in_pass.clear()
            self.in_2fa.clear()
        else:
            QMessageBox.warning(self, "Error", msg)

    def do_logout(self):
        if self.watcher:
            self.watcher.stop()
            self.watcher = None
        self.indexer = None
        self.session.destroy_session()
        self._session_password = None
        self.auto_lock_timer.stop()
        self.in_pass.clear()
        self.in_2fa.clear()
        self.main_stack.fade_to_index(0)

    def reset_inactivity_timer(self):
        if not self.session.is_active:
            self.auto_lock_timer.stop()
            return
        minutes = self.auth.settings.get("auto_lock_minutes", 10)
        if minutes <= 0:
            self.auto_lock_timer.stop()
            return
        self.auto_lock_timer.start(int(minutes) * 60 * 1000)

    def eventFilter(self, obj, event):
        if self.session.is_active:
            if event.type() in (
                event.Type.MouseMove,
                event.Type.MouseButtonPress,
                event.Type.KeyPress,
            ):
                self.reset_inactivity_timer()
        return super().eventFilter(obj, event)

    def _get_session_password(self, require_active=True):
        if require_active and not self.session.is_active:
            QMessageBox.warning(self, "Error", "No active session.")
            return None
        if self._session_password:
            return self._session_password

        pwd, ok = QInputDialog.getText(
            self,
            "Unlock Vault",
            "Enter vault password to continue:",
            QLineEdit.EchoMode.Password,
        )
        if not ok or not pwd:
            return None
        self._session_password = pwd
        return pwd

    def run_encrypt(self):
        count = self.file_table.rowCount()
        files = [self.file_table.item(i, 2).text() for i in range(count)]
        if not files:
            QMessageBox.warning(self, "No Files", "Please add files to encrypt.")
            return

        algo_map = {
            "ChaCha20-Poly1305 (Fast)": "chacha20-poly1305",
            "AES-256-GCM (Balanced)": "aes-256-gcm",
            "PQC Hybrid (Kyber)": "pqc-hybrid",
            "LetNoxEnc-256 (Experimental)": "letnox-256",
            "LetNoxEnc-512 (Experimental)": "letnox-512",
        }
        algo = algo_map.get(self.crypto_mode.currentText(), "chacha20-poly1305")
        pwd = self._get_session_password()
        if not pwd:
            return

        compress = self.chk_compress.isChecked()
        device_lock = self.auth.settings.get("device_lock_enabled", False)
        pqc_pub = None
        pqc_kem = "kyber512"
        if algo == "pqc-hybrid":
            if not self.auth.settings.get("pqc_enabled", False):
                QMessageBox.warning(self, "Error", "PQC Hybrid is disabled in settings.")
                return
            pqc_kem = self.auth.settings.get("pqc_kem", "kyber512")
            if not self.auth.ensure_pqc_keys(pwd, kem_name=pqc_kem):
                QMessageBox.warning(self, "Error", "PQC keys unavailable.")
                return
            pqc_pub = self.auth.get_pqc_public_key()
            if not pqc_pub:
                QMessageBox.warning(self, "Error", "PQC public key missing.")
                return

        self.worker = TaskWorker(
            self._encrypt_task,
            files,
            pwd,
            algo,
            compress,
            pqc_pub,
            pqc_kem,
            device_lock,
        )
        self.worker.finished.connect(self.on_task_done)
        self.worker.start()

    def _encrypt_task(self, files, pwd, algo, compress, pqc_pub, pqc_kem, device_lock):
        errors = []
        for f in files:
            ok, out_path = CryptoEngine.encrypt_file(
                f,
                pwd,
                algo,
                pqc_public_key=pqc_pub,
                pqc_kem=pqc_kem,
                compress=compress,
                device_lock=device_lock,
            )
            if ok:
                if self.indexer:
                    self.indexer.add_file(out_path, algo)
            else:
                errors.append(out_path)

            if self.chk_shred.isChecked():
                Shredder.wipe_file(f)
        if errors:
            raise RuntimeError(f"Encryption failed: {errors[0]}")
        return "Encryption Complete"

    def run_decrypt(self):
        count = self.file_table.rowCount()
        files = [self.file_table.item(i, 2).text() for i in range(count)]
        if not files:
            QMessageBox.warning(self, "No Files", "Please add files to decrypt.")
            return
        pwd = self._get_session_password()
        if not pwd:
            return
        legacy_files = [f for f in files if CryptoEngine.classify_file(f) == "legacy"]
        unknown_files = [f for f in files if CryptoEngine.classify_file(f) == "unknown"]
        if unknown_files:
            QMessageBox.warning(
                self,
                "Unsupported Files",
                "Some files are not recognized as Noxium archives.",
            )
            return
        allow_legacy = False
        if legacy_files:
            warn = QMessageBox.warning(
                self,
                "Legacy Decryption",
                "Legacy formats are obsolete and may be unsafe (no integrity).\n"
                "Decrypt only if you trust the source and intend to migrate.\n\n"
                "Proceed with legacy decryption?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            )
            if warn != QMessageBox.StandardButton.Yes:
                return
            allow_legacy = True
        pqc_priv = self.auth.get_pqc_private_key()
        self.worker = TaskWorker(self._decrypt_task, files, pwd, pqc_priv, allow_legacy)
        self.worker.finished.connect(self.on_task_done)
        self.worker.start()

    def _decrypt_task(self, files, pwd, pqc_priv, allow_legacy):
        errors = []
        for f in files:
            ok, msg = CryptoEngine.decrypt_file(
                f, pwd, pqc_private_key=pqc_priv, allow_legacy=allow_legacy
            )
            if not ok:
                errors.append(msg)
        if errors:
            raise RuntimeError(f"Decryption failed: {errors[0]}")
        return "Decryption Complete"

    def on_task_done(self, res):
        ok, msg = res
        if ok:
            QMessageBox.information(self, "Success", msg)
            self.file_table.setRowCount(0)
            self.update_log()
        else:
            QMessageBox.critical(self, "Error", msg)

    def update_log(self):
        self.list_audit.clear()
        for l in AuditLog.get_logs()[-10:]:
            self.list_audit.addItem(l)

    def open_theme_creator(self):
        dlg = ThemeCreatorDialog(self, self.theme_manager)
        if dlg.exec():
            current = self.set_theme.currentText()
            self.set_theme.clear()
            names = self.theme_manager.get_all_theme_names()
            self.set_theme.addItems(names)

            # Try to select the new theme
            new_name = dlg.in_name.text()
            if new_name in names:
                self.set_theme.setCurrentText(new_name)
            else:
                idx = self.set_theme.findText(current)
                if idx >= 0:
                    self.set_theme.setCurrentIndex(idx)

    def apply_theme(self, theme_name=None, mode=None):
        if not mode:
            mode = getattr(self, "current_theme_mode", "light")
        if not theme_name:
            theme_name = getattr(self, "current_theme_name", "Noxium Teal")

        self.current_theme_mode = mode
        self.current_theme_name = theme_name

        palette = self.theme_manager.get_palette(mode, theme_name)
        styles.apply_palette(palette)
        app = QApplication.instance()
        if app:
            app.setStyleSheet(styles.build_stylesheet())
        self.setStyleSheet(styles.build_stylesheet())
        if hasattr(self, "dash_stack"):
            self.set_nav_active(self.dash_stack.currentIndex())

    def save_settings(self):
        algo_text = self.set_algo.currentText()
        algo_map = {
            "ChaCha20-Poly1305 (Fast)": "chacha20-poly1305",
            "AES-256-GCM (Balanced)": "aes-256-gcm",
            "PQC Hybrid (Kyber)": "pqc-hybrid",
            "LetNoxEnc-256 (Experimental)": "letnox-256",
            "LetNoxEnc-512 (Experimental)": "letnox-512",
        }
        algo = algo_map.get(algo_text, "chacha20-poly1305")
        compress = self.chk_default_compress.isChecked()
        shred = self.set_shred.value()
        auto_lock = self.set_auto_lock.value()
        theme_mode = self.set_theme_mode.currentText().lower()
        theme_name = self.set_theme.currentText()
        device_lock = self.chk_device_lock.isChecked()
        pqc_enabled = self.chk_pqc_enable.isChecked()
        pqc_kem = self.set_pqc_kem.currentText()

        pwd = self._get_session_password()
        if not pwd:
            QMessageBox.warning(self, "Error", "Password required to update settings.")
            return

        if pqc_enabled:
            if not CryptoEngine.pqc_available():
                QMessageBox.warning(self, "Error", "PQC library not available.")
                pqc_enabled = False
                self.chk_pqc_enable.setChecked(False)
            elif not self.auth.ensure_pqc_keys(pwd, kem_name=pqc_kem):
                QMessageBox.warning(self, "Error", "PQC keys unavailable.")
                pqc_enabled = False
                self.chk_pqc_enable.setChecked(False)

        self.auth.update_setting("file_algo", algo, pwd)
        self.auth.update_setting("file_compress", compress, pwd)
        self.auth.update_setting("shred", shred, pwd)
        self.auth.update_setting("auto_lock_minutes", auto_lock, pwd)
        self.auth.update_setting("theme_mode", theme_mode, pwd)
        self.auth.update_setting("theme_name", theme_name, pwd)
        self.auth.update_setting("device_lock_enabled", device_lock, pwd)
        self.auth.update_setting("pqc_enabled", pqc_enabled, pwd)
        self.auth.update_setting("pqc_kem", pqc_kem, pwd)

        if self.watcher:
            self.watcher.mode = algo
            self.watcher.compress = compress
            self.watcher.pqc_kem = pqc_kem
            self.watcher.pqc_public_key = self.auth.get_pqc_public_key() if pqc_enabled else None
            self.watcher.device_lock = device_lock

        self.apply_theme(theme_name, theme_mode)
        self.reset_inactivity_timer()

        QMessageBox.information(
            self, "Saved", f"Configuration updated.\nTheme set to {theme_name}"
        )

    def load_user_settings(self):
        s = self.auth.settings
        algo = s.get("file_algo")
        if algo:
            reverse_map = {
                "chacha20-poly1305": "ChaCha20-Poly1305 (Fast)",
                "aes-256-gcm": "AES-256-GCM (Balanced)",
                "pqc-hybrid": "PQC Hybrid (Kyber)",
                "letnox-256": "LetNoxEnc-256 (Experimental)",
                "letnox-512": "LetNoxEnc-512 (Experimental)",
            }
            label = reverse_map.get(algo, "")
            idx = self.set_algo.findText(label)
            if idx >= 0:
                self.set_algo.setCurrentIndex(idx)
            if hasattr(self, "crypto_mode") and label:
                idx = self.crypto_mode.findText(label)
                if idx >= 0:
                    self.crypto_mode.setCurrentIndex(idx)

        if "file_compress" in s:
            self.chk_default_compress.setChecked(bool(s["file_compress"]))
            if hasattr(self, "chk_compress"):
                self.chk_compress.setChecked(bool(s["file_compress"]))

        if "shred" in s:
            self.set_shred.setValue(s["shred"])

        if "auto_lock_minutes" in s:
            self.set_auto_lock.setValue(int(s["auto_lock_minutes"]))

        if "device_lock_enabled" in s:
            self.chk_device_lock.blockSignals(True)
            self.chk_device_lock.setChecked(bool(s["device_lock_enabled"]))
            self.chk_device_lock.blockSignals(False)

        if "theme_mode" in s:
            mode = s["theme_mode"].capitalize()
            idx = self.set_theme_mode.findText(mode)
            if idx >= 0:
                self.set_theme_mode.setCurrentIndex(idx)

        theme = s.get("theme_name") or s.get("theme")
        if theme:
            idx = self.set_theme.findText(theme)
            if idx >= 0:
                self.set_theme.setCurrentIndex(idx)
            self.apply_theme(theme, s.get("theme_mode", "light"))

        if "pqc_enabled" in s:
            self.chk_pqc_enable.setChecked(bool(s["pqc_enabled"]))

        if "pqc_kem" in s:
            idx = self.set_pqc_kem.findText(s["pqc_kem"])
            if idx >= 0:
                self.set_pqc_kem.setCurrentIndex(idx)
        self.update_pqc_controls()
        self.reset_inactivity_timer()

    def open_stego_tool(self):
        dlg = StartStegoDialog(self)
        dlg.exec()

    def open_ghostlink(self):
        dlg = GhostLinkDialog(self)
        dlg.exec()

    def open_passgen(self):
        dlg = PassGenDialog(self)
        dlg.exec()

    def open_notes(self):
        # Pass current vault credentials
        vault_name = self.session.current_vault or self.cb_vaults.currentText()
        if not vault_name:
            QMessageBox.warning(self, "Error", "No active vault.")
            return
        pwd = self._get_session_password()
        if not pwd:
            QMessageBox.warning(self, "Error", "Session locked or password missing.")
            return

        dlg = NotesDialog(self, vault_name, pwd, vault_key=self.auth.vault_key)
        dlg.exec()

    def open_recovery_shares(self):
        if not self.auth.vault_key:
            QMessageBox.warning(self, "Error", "Vault key unavailable.")
            return
        dlg = RecoveryDialog(self, vault_key=self.auth.vault_key)
        dlg.exec()

    def open_folder_watcher(self):
        if not self.watcher:
            QMessageBox.warning(
                self, "Service Error", "Watcher service not initialized."
            )
            return
        dlg = FolderWatcherDialog(self, self.watcher)
        dlg.exec()

    def do_vault_export(self):
        if not self.session.is_active or not self.session.current_vault:
            QMessageBox.warning(self, "Error", "No active session.")
            return

        out_dir = QFileDialog.getExistingDirectory(self, "Select Backup Destination")
        if not out_dir:
            return

        pwd, ok = QInputDialog.getText(
            self,
            "Encrypt Backup",
            "Enter a strong password to encrypt this backup archive:\n(You will need this to restore it)",
            QLineEdit.EchoMode.Password,
        )
        if not ok or not pwd:
            return
        ok, issues = SecurityTools.validate_password(pwd)
        if not ok:
            QMessageBox.warning(
                self,
                "Weak Password",
                "Backup password is too weak:\n- " + "\n- ".join(issues),
            )
            return

        bm = BackupManager()
        res, path = bm.export_vault(self.session.current_vault, out_dir, pwd)

        if res:
            QMessageBox.information(
                self, "Export Successful", f"Vault backup saved to:\n{path}"
            )
        else:
            QMessageBox.critical(self, "Export Failed", path)

    def do_vault_import(self):
        f, _ = QFileDialog.getOpenFileName(
            self, "Select Backup File", "", "Vault Backups (*.vib)"
        )
        if not f:
            return

        pwd, ok = QInputDialog.getText(
            self,
            "Decrypt Backup",
            "Enter the password used to encrypt this backup:",
            QLineEdit.EchoMode.Password,
        )
        if not ok or not pwd:
            return

        bm = BackupManager()
        res, msg = bm.import_vault(f, pwd)

        if res:
            QMessageBox.information(self, "Restore Successful", msg)
            self.refresh_vaults()
        else:
            QMessageBox.critical(self, "Restore Failed", msg)


def main():
    app = QApplication(sys.argv)
    w = NDSFC_Pro()
    # Apply global font to QDialogs too
    app.setStyleSheet(styles.build_stylesheet())
    w.show()
    sys.exit(app.exec())
