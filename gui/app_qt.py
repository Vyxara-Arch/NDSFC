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
    QTabWidget,
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

        subtitle = QLabel("Secure access to your encrypted vaults.")
        subtitle.setProperty("tone", "muted")
        subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        subtitle.setWordWrap(True)
        cl.addWidget(subtitle)

        cl.addSpacing(18)

        # Inputs
        lbl_vault = QLabel("Vault")
        lbl_vault.setProperty("tone", "muted")
        cl.addWidget(lbl_vault)
        self.cb_vaults = QComboBox()
        self.cb_vaults.setMinimumHeight(45)
        self.cb_vaults.setToolTip("Select the vault you want to unlock.")
        self.refresh_vaults()
        cl.addWidget(self.cb_vaults)

        lbl_pass = QLabel("Master Password")
        lbl_pass.setProperty("tone", "muted")
        cl.addWidget(lbl_pass)
        self.in_pass = QLineEdit(placeholderText="Enter your master password")
        self.in_pass.setEchoMode(QLineEdit.EchoMode.Password)
        cl.addWidget(self.in_pass)

        lbl_2fa = QLabel("Two-Factor Code")
        lbl_2fa.setProperty("tone", "muted")
        cl.addWidget(lbl_2fa)
        self.in_2fa = QLineEdit(placeholderText="6-digit code")
        self.in_2fa.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.in_2fa.setToolTip("Enter the 6-digit code from your authenticator app.")
        self.in_2fa.setMaxLength(6)
        cl.addWidget(self.in_2fa)

        helper_2fa = QLabel("Use the 6-digit code from your authenticator app.")
        helper_2fa.setProperty("tone", "muted")
        helper_2fa.setStyleSheet("font-size: 12px;")
        helper_2fa.setWordWrap(True)
        cl.addWidget(helper_2fa)

        cl.addSpacing(10)

        # Login Button
        btn_login = QPushButton("UNLOCK VAULT", objectName="Primary")
        btn_login.setMinimumHeight(50)
        btn_login.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_login.clicked.connect(self.do_login)
        cl.addWidget(btn_login)

        cl.addStretch()

        # Footer Actions
        row = QHBoxLayout()
        btn_new = QPushButton(" Create Vault", objectName="LinkButton")
        btn_new.setIcon(qta.icon("fa5s.plus", color=styles.TEXT_MUTED))
        btn_new.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_new.clicked.connect(self.show_create_vault_dialog)

        btn_imp = QPushButton(" Import Backup", objectName="LinkButton")
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

        title = QLabel("NOXIUM VAULT")
        title.setProperty("tone", "accent")
        title.setStyleSheet(
            "font-size: 16px; font-weight: 700; letter-spacing: 3px;"
        )
        sb_l.addWidget(title)
        subtitle = QLabel("Secure workspace")
        subtitle.setProperty("tone", "muted")
        subtitle.setStyleSheet("font-size: 12px;")
        sb_l.addWidget(subtitle)
        sb_l.addSpacing(32)

        self.dash_stack = FadeStack()

        btns = [
            ("DASHBOARD", "fa5s.home", 0),
            ("ENCRYPTION", "fa5s.lock", 1),
            ("TOOLS", "fa5s.magic", 2),
            ("SETTINGS", "fa5s.cog", 3),
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
        title_col = QVBoxLayout()
        lbl_welcome = QLabel("Dashboard")
        lbl_welcome.setStyleSheet("font-size: 28px; font-weight: bold;")
        title_col.addWidget(lbl_welcome)
        lbl_sub = QLabel("Quick status, shortcuts, and recent activity.")
        lbl_sub.setProperty("tone", "muted")
        lbl_sub.setStyleSheet("font-size: 12px;")
        title_col.addWidget(lbl_sub)
        header.addLayout(title_col)
        header.addStretch()

        # Search Bar
        search_col = QVBoxLayout()
        lbl_search = QLabel("Search")
        lbl_search.setProperty("tone", "muted")
        lbl_search.setStyleSheet("font-size: 12px;")
        search_col.addWidget(lbl_search)
        self.txt_search = QLineEdit()
        self.txt_search.setPlaceholderText("Search by filename or tag...")
        self.txt_search.setMinimumWidth(240)
        self.txt_search.setMaximumWidth(420)
        self.txt_search.setObjectName("SearchField")
        self.txt_search.setClearButtonEnabled(True)
        self.txt_search.setToolTip("Search the encrypted index by filename or tag.")
        self.txt_search.textChanged.connect(self.do_search)
        search_col.addWidget(self.txt_search)
        header.addLayout(search_col)

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
        lbl_active = QLabel("Active Vault")
        lbl_active.setProperty("tone", "muted")
        lbl_active.setStyleSheet("font-weight: bold;")
        vl.addWidget(lbl_active)
        self.lbl_vault_name = QLabel(self.session.current_vault or "LOCKED")
        self.lbl_vault_name.setProperty("tone", "accent")
        self.lbl_vault_name.setStyleSheet("font-size: 24px; font-weight: bold;")
        vl.addWidget(self.lbl_vault_name)
        self.lbl_vault_status = QLabel("Status: Locked")
        self.lbl_vault_status.setProperty("tone", "muted")
        self.lbl_vault_status.setStyleSheet("font-size: 12px;")
        vl.addWidget(self.lbl_vault_status)
        self.lbl_auto_lock = QLabel("Auto-lock: --")
        self.lbl_auto_lock.setProperty("tone", "muted")
        self.lbl_auto_lock.setStyleSheet("font-size: 12px;")
        vl.addWidget(self.lbl_auto_lock)
        vl.addStretch()
        b_lock = QPushButton("LOCK VAULT")
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

        bq1 = QPushButton("  Encrypt Files")
        bq1.setIcon(qta.icon("fa5s.lock", color=styles.ACCENT_COLOR))
        bq1.setToolTip("Go to the encryption workspace.")
        bq1.clicked.connect(lambda: self.switch_tab(1))  # Crypto tab
        ql.addWidget(bq1)

        bq2 = QPushButton("  Open Notes")
        bq2.setIcon(qta.icon("fa5s.sticky-note", color=styles.ACCENT_COLOR))
        bq2.setToolTip("Open your encrypted notes journal.")
        bq2.clicked.connect(self.open_notes)
        ql.addWidget(bq2)

        bq3 = QPushButton("  Secure Tunnel")
        bq3.setIcon(qta.icon("fa5s.network-wired", color=styles.ACCENT_COLOR))
        bq3.setToolTip("Open Ghost Link (SFTP).")
        bq3.clicked.connect(self.open_ghostlink)
        ql.addWidget(bq3)

        bq4 = QPushButton("  Rebuild Index")
        bq4.setIcon(qta.icon("fa5s.search-plus", color=styles.ACCENT_COLOR))
        bq4.setToolTip("Scan a folder to refresh the encrypted index.")
        bq4.clicked.connect(self.rebuild_index)
        ql.addWidget(bq4)

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
        self.update_log()

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
            ["Name", "Size", "Date", "Location", "Algorithm"]
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
        self.update_session_summary()
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
                self.table_results.setItem(
                    row, 1, QTableWidgetItem(self.format_size(item["size"]))
                )
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
        lbl_title = QLabel("Encryption Workspace")
        lbl_title.setStyleSheet("font-size: 28px; font-weight: bold;")
        header.addWidget(lbl_title)
        header.addStretch()
        l.addLayout(header)
        lbl_hint = QLabel("Add files, choose a mode, then encrypt or decrypt.")
        lbl_hint.setProperty("tone", "muted")
        lbl_hint.setStyleSheet("font-size: 12px;")
        l.addWidget(lbl_hint)
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
        self.mode_tabs = QTabWidget()
        self.mode_tabs.setObjectName("ModeTabs")

        modern_tab = QWidget()
        modern_layout = QVBoxLayout(modern_tab)
        modern_layout.setContentsMargins(0, 0, 0, 0)
        modern_layout.setSpacing(8)

        self.crypto_mode_modern = QComboBox()
        self.crypto_mode_modern.addItems(
            [
                "ChaCha20-Poly1305 (Fast)",
                "AES-256-GCM (Balanced)",
                "AES-256-SIV (Misuse-Resistant)",
            ]
        )
        if CryptoEngine.pqc_available():
            self.crypto_mode_modern.addItem("PQC Hybrid (Kyber)")
        self.crypto_mode_modern.setToolTip("Select the encryption algorithm to use.")
        modern_layout.addWidget(self.crypto_mode_modern)

        mode_hint = QLabel("Tip: ChaCha20-Poly1305 is fast and secure for most files.")
        mode_hint.setProperty("tone", "muted")
        mode_hint.setStyleSheet("font-size: 12px;")
        mode_hint.setWordWrap(True)
        modern_layout.addWidget(mode_hint)

        legacy_tab = QWidget()
        legacy_layout = QVBoxLayout(legacy_tab)
        legacy_layout.setContentsMargins(0, 0, 0, 0)
        legacy_layout.setSpacing(8)

        legacy_warn = QLabel(
            "Legacy algorithms are for compatibility only and are not recommended for new data."
        )
        legacy_warn.setProperty("tone", "accent-secondary")
        legacy_warn.setStyleSheet("font-size: 12px;")
        legacy_warn.setWordWrap(True)
        legacy_layout.addWidget(legacy_warn)

        self.crypto_mode_legacy = QComboBox()
        self.crypto_mode_legacy.addItems(
            [
                "LetNoxEnc-256 (Experimental)",
                "LetNoxEnc-512 (Experimental)",
            ]
        )
        self.crypto_mode_legacy.setToolTip("Legacy/experimental algorithms.")
        legacy_layout.addWidget(self.crypto_mode_legacy)

        self.mode_tabs.addTab(modern_tab, "Modern")
        self.mode_tabs.addTab(legacy_tab, "Legacy")
        cl.addWidget(self.mode_tabs)

        # Options
        cl.addSpacing(10)
        lbl_options = QLabel("Options:")
        lbl_options.setProperty("tone", "muted")
        cl.addWidget(lbl_options)
        self.chk_shred = QCheckBox("Secure Shred Original")
        self.chk_shred.setChecked(True)
        self.chk_shred.setToolTip("Overwrite original files after encryption.")
        cl.addWidget(self.chk_shred)

        self.chk_compress = QCheckBox("Compress Before Encrypt")
        self.chk_compress.setToolTip("Reduce size before encryption (may slow large files).")
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
        lbl_queue_hint = QLabel("Drag & drop files here or use Add Files.")
        lbl_queue_hint.setProperty("tone", "muted")
        lbl_queue_hint.setStyleSheet("font-size: 12px;")
        fcl.addWidget(lbl_queue_hint)

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

        b_clear = QPushButton(" Clear List")
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
        b_enc.setToolTip("Encrypt all files in the queue.")
        b_enc.clicked.connect(self.run_encrypt)

        b_dec = QPushButton(" DECRYPT ALL", objectName="Secondary")
        b_dec.setIcon(qta.icon("fa5s.unlock", color=styles.TEXT_COLOR))
        b_dec.setMinimumHeight(50)
        b_dec.setToolTip("Decrypt all files in the queue.")
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

        title = QLabel("Settings", styleSheet="font-size: 28px; font-weight: bold;")
        subtitle = QLabel("Manage encryption, security, backups, and appearance.")
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

        self.set_algo_tabs = QTabWidget()
        self.set_algo_tabs.setObjectName("DefaultAlgoTabs")

        set_modern_tab = QWidget()
        set_modern_layout = QVBoxLayout(set_modern_tab)
        set_modern_layout.setContentsMargins(0, 0, 0, 0)
        set_modern_layout.setSpacing(8)

        self.set_algo_modern = QComboBox()
        self.set_algo_modern.addItems(
            [
                "ChaCha20-Poly1305 (Fast)",
                "AES-256-GCM (Balanced)",
                "AES-256-SIV (Misuse-Resistant)",
            ]
        )
        if CryptoEngine.pqc_available():
            self.set_algo_modern.addItem("PQC Hybrid (Kyber)")
        set_modern_layout.addWidget(self.set_algo_modern)

        set_legacy_tab = QWidget()
        set_legacy_layout = QVBoxLayout(set_legacy_tab)
        set_legacy_layout.setContentsMargins(0, 0, 0, 0)
        set_legacy_layout.setSpacing(8)

        set_legacy_warn = QLabel(
            "Legacy algorithms are for compatibility only and are not recommended for new data."
        )
        set_legacy_warn.setProperty("tone", "accent-secondary")
        set_legacy_warn.setStyleSheet("font-size: 12px;")
        set_legacy_warn.setWordWrap(True)
        set_legacy_layout.addWidget(set_legacy_warn)

        self.set_algo_legacy = QComboBox()
        self.set_algo_legacy.addItems(
            [
                "LetNoxEnc-256 (Experimental)",
                "LetNoxEnc-512 (Experimental)",
            ]
        )
        set_legacy_layout.addWidget(self.set_algo_legacy)

        self.set_algo_tabs.addTab(set_modern_tab, "Modern")
        self.set_algo_tabs.addTab(set_legacy_tab, "Legacy")

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
        self.set_shred.setToolTip("Number of overwrite passes for secure delete.")

        self.set_auto_lock = QSpinBox()
        self.set_auto_lock.setRange(0, 120)
        self.set_auto_lock.setValue(10)
        self.set_auto_lock.setSuffix(" min")
        self.set_auto_lock.setToolTip("Lock the vault after inactivity (0 = Off).")

        self.chk_device_lock = QCheckBox("Bind encrypted files to this device")
        self.chk_device_lock.setToolTip(
            "When enabled, encrypted files can only be opened on this machine."
        )
        self.chk_device_lock.toggled.connect(self.on_device_lock_toggled)

        btn_create = QPushButton("Design Custom Theme")
        btn_create.clicked.connect(self.open_theme_creator)

        btn_export = QPushButton("Backup Vault (.vib)")
        btn_export.setToolTip("Create an encrypted backup file.")
        btn_export.clicked.connect(self.do_vault_export)

        btn_recovery = QPushButton("Generate Recovery Shares")
        btn_recovery.setToolTip("Create Shamir recovery shares for the vault key.")
        btn_recovery.clicked.connect(self.open_recovery_shares)

        btn_save = QPushButton("Save Configuration", objectName="Primary")
        btn_save.setMinimumHeight(44)
        btn_save.clicked.connect(self.save_settings)

        enc_card, enc_form = make_card(
            "Encryption", "Default algorithm and PQC settings."
        )
        enc_form.addRow("Default Encryption:", self.set_algo_tabs)
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
            msg.setText("Device Lock binds encrypted files to this device.")
            msg.setInformativeText(
                "Important:\n"
                "- Files encrypted with Device Lock will not open on other machines.\n"
                "- Reinstalling the OS or changing hardware may permanently lock access.\n"
                "- Turning this off does not unlock files already protected.\n"
                "- Keep backups without Device Lock for recovery.\n"
                "- This feature is experimental; use at your own risk."
            )
            accept_btn = msg.addButton(
                "I understand and want to continue", QMessageBox.ButtonRole.AcceptRole
            )
            msg.addButton("Cancel", QMessageBox.ButtonRole.RejectRole)
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
        l.setContentsMargins(30, 30, 30, 30)
        title = QLabel("Tools & Utilities", styleSheet="font-size: 28px; font-weight: bold;")
        subtitle = QLabel("Extra tools for transport, recovery, notes, and stego.")
        subtitle.setProperty("tone", "muted")
        subtitle.setStyleSheet("font-size: 12px;")
        l.addWidget(title)
        l.addWidget(subtitle)

        grid = QGridLayout()
        grid.setSpacing(20)
        grid.setColumnStretch(0, 1)
        grid.setColumnStretch(1, 1)
        grid.setColumnStretch(2, 1)

        def make_tool_card(title_text, desc, icon_name, button_text, handler):
            card = QFrame(objectName="Card")
            card.setMinimumHeight(180)
            card_l = QVBoxLayout(card)
            card_l.setContentsMargins(20, 20, 20, 20)
            card_l.setSpacing(10)

            header = QHBoxLayout()
            icon = QLabel()
            icon.setPixmap(qta.icon(icon_name, color=styles.ACCENT_COLOR).pixmap(28, 28))
            header.addWidget(icon)
            ttl = QLabel(title_text)
            ttl.setStyleSheet("font-weight: bold; font-size: 16px;")
            header.addWidget(ttl)
            header.addStretch()
            card_l.addLayout(header)

            desc_lbl = QLabel(desc)
            desc_lbl.setProperty("tone", "muted")
            desc_lbl.setStyleSheet("font-size: 12px;")
            desc_lbl.setWordWrap(True)
            card_l.addWidget(desc_lbl)

            card_l.addStretch()
            btn = QPushButton(button_text)
            btn.clicked.connect(handler)
            card_l.addWidget(btn)
            return card

        c1 = make_tool_card(
            "Steganography",
            "Hide or extract files inside PNG images.",
            "fa5s.user-secret",
            "Open Stego Tool",
            self.open_stego_tool,
        )
        c2 = make_tool_card(
            "Ghost Link (SFTP)",
            "Secure file transfer over SSH with optional proxy.",
            "fa5s.network-wired",
            "Connect",
            self.open_ghostlink,
        )
        c3 = make_tool_card(
            "Password Generator",
            "Create high-entropy passwords with auto-clear.",
            "fa5s.key",
            "Generate Password",
            self.open_passgen,
        )
        c4 = make_tool_card(
            "Secure Notes",
            "Create and search encrypted personal notes.",
            "fa5s.sticky-note",
            "Open Notes",
            self.open_notes,
        )
        c5 = make_tool_card(
            "Folder Watcher",
            "Auto-encrypt new files in selected folders.",
            "fa5s.folder-open",
            "Manage Watcher",
            self.open_folder_watcher,
        )

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
            self.file_table.setItem(row, 1, QTableWidgetItem(self.format_size(size)))
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

        self.lbl_total_size.setText(f"Total: {self.format_size(total_size)}")

    @staticmethod
    def format_size(size: int) -> str:
        if size < 1024:
            return f"{size} B"
        if size < 1024 * 1024:
            return f"{size / 1024:.2f} KB"
        if size < 1024 * 1024 * 1024:
            return f"{size / (1024 * 1024):.2f} MB"
        return f"{size / (1024 * 1024 * 1024):.2f} GB"

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
            self.update_session_summary()
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
        self.auth.vault_key = None
        self.auth.vault_content = None
        self.auth.settings = {}
        self.auth.active_vault_path = None
        self.auto_lock_timer.stop()
        self.in_pass.clear()
        self.in_2fa.clear()
        self.update_session_summary()
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
            "AES-256-SIV (Misuse-Resistant)": "aes-256-siv",
            "PQC Hybrid (Kyber)": "pqc-hybrid",
            "LetNoxEnc-256 (Experimental)": "letnox-256",
            "LetNoxEnc-512 (Experimental)": "letnox-512",
        }
        algo = algo_map.get(self.get_crypto_mode_text(), "chacha20-poly1305")
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
        logs = AuditLog.get_logs()[-10:]
        if not logs:
            self.list_audit.addItem("No recent activity yet.")
            return
        for l in logs:
            self.list_audit.addItem(l)

    def get_crypto_mode_text(self) -> str:
        if hasattr(self, "mode_tabs") and self.mode_tabs.currentIndex() == 1:
            return self.crypto_mode_legacy.currentText()
        return self.crypto_mode_modern.currentText()

    def get_default_algo_text(self) -> str:
        if hasattr(self, "set_algo_tabs") and self.set_algo_tabs.currentIndex() == 1:
            return self.set_algo_legacy.currentText()
        return self.set_algo_modern.currentText()

    def update_session_summary(self):
        if not hasattr(self, "lbl_vault_name"):
            return
        if self.session.is_active:
            name = self.session.current_vault or "Active"
            status = "Status: Unlocked"
            auto_lock = self.auth.settings.get("auto_lock_minutes", 10)
            if auto_lock <= 0:
                auto_text = "Auto-lock: Off"
            else:
                auto_text = f"Auto-lock: {auto_lock} min"
            tone = "accent"
        else:
            name = "LOCKED"
            status = "Status: Locked"
            auto_text = "Auto-lock: --"
            tone = "muted"

        self.lbl_vault_name.setText(name)
        self.lbl_vault_status.setText(status)
        self.lbl_auto_lock.setText(auto_text)
        self.lbl_vault_status.setProperty("tone", tone)
        self.lbl_vault_status.style().unpolish(self.lbl_vault_status)
        self.lbl_vault_status.style().polish(self.lbl_vault_status)

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
        algo_text = self.get_default_algo_text()
        algo_map = {
            "ChaCha20-Poly1305 (Fast)": "chacha20-poly1305",
            "AES-256-GCM (Balanced)": "aes-256-gcm",
            "AES-256-SIV (Misuse-Resistant)": "aes-256-siv",
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
        self.update_session_summary()

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
                "aes-256-siv": "AES-256-SIV (Misuse-Resistant)",
                "pqc-hybrid": "PQC Hybrid (Kyber)",
                "letnox-256": "LetNoxEnc-256 (Experimental)",
                "letnox-512": "LetNoxEnc-512 (Experimental)",
            }
            label = reverse_map.get(algo, "")
            if label:
                legacy_labels = {
                    "LetNoxEnc-256 (Experimental)",
                    "LetNoxEnc-512 (Experimental)",
                }
                if hasattr(self, "set_algo_tabs"):
                    if label in legacy_labels:
                        self.set_algo_tabs.setCurrentIndex(1)
                        idx = self.set_algo_legacy.findText(label)
                        if idx >= 0:
                            self.set_algo_legacy.setCurrentIndex(idx)
                    else:
                        self.set_algo_tabs.setCurrentIndex(0)
                        idx = self.set_algo_modern.findText(label)
                        if idx >= 0:
                            self.set_algo_modern.setCurrentIndex(idx)
                if hasattr(self, "mode_tabs"):
                    if label in legacy_labels:
                        self.mode_tabs.setCurrentIndex(1)
                        idx = self.crypto_mode_legacy.findText(label)
                        if idx >= 0:
                            self.crypto_mode_legacy.setCurrentIndex(idx)
                    else:
                        self.mode_tabs.setCurrentIndex(0)
                        idx = self.crypto_mode_modern.findText(label)
                        if idx >= 0:
                            self.crypto_mode_modern.setCurrentIndex(idx)

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
