import io
import os
import time
import qrcode
import qtawesome as qta

from PyQt6.QtWidgets import (
    QApplication,
    QDialog,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QStackedWidget,
    QFileDialog,
    QMessageBox,
    QListWidget,
    QListWidgetItem,
    QTabWidget,
    QTextEdit,
    QGroupBox,
    QFormLayout,
    QSpinBox,
    QFrame,
    QColorDialog,
)
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QColor, QIcon, QPixmap

from gui import styles
from core.steganography import StegoEngine
from core.network import GhostLink
from core.tools import SecurityTools
from core.notes_manager import NotesManager
from core.shamir import ShamirVault

class StartStegoDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Omega Steganography Tool")
        self.resize(680, 520)
        self.setMinimumSize(600, 480)
        self.setStyleSheet(styles.build_stylesheet() + f"QDialog {{ background-color: {styles.DIALOG_BG}; }}")

        layout = QVBoxLayout(self)

        self.tabs = QTabWidget()
        self.tabs.setStyleSheet(
            f"QTabWidget::pane {{ border: 0; }} "
            f"QTabBar::tab {{ background: rgba(15, 23, 42, 0.04); color: {styles.TEXT_MUTED}; padding: 10px; border-radius: 8px; }} "
            f"QTabBar::tab:selected {{ background: {styles.CARD_COLOR}; color: {styles.ACCENT_COLOR}; border-bottom: 2px solid {styles.ACCENT_COLOR}; }}"
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
            f"border: 2px dashed rgba(15, 23, 42, 0.2); padding: 20px; color: {styles.TEXT_MUTED};"
        )
        l.addWidget(self.lbl_cover)

        b_sel = QPushButton("Select Cover Image (PNG)")
        b_sel.clicked.connect(self.sel_cover)
        l.addWidget(b_sel)

        self.lbl_cap = QLabel("Capacity: 0 bytes")
        self.lbl_cap.setStyleSheet(f"color: {styles.ACCENT_COLOR}; font-weight: bold;")
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
            f"border: 2px dashed rgba(15, 23, 42, 0.2); padding: 20px; color: {styles.TEXT_MUTED};"
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
        self.resize(560, 640)
        self.setMinimumSize(480, 560)
        self.setStyleSheet(styles.build_stylesheet() + f"QDialog {{ background-color: {styles.DIALOG_BG}; }}")

        self.link = GhostLink()

        layout = QVBoxLayout(self)
        layout.setSpacing(15)

        # Connection Details
        gb_conn = QGroupBox("Connection")
        gb_conn.setStyleSheet(
            f"QGroupBox {{ border: 1px solid {styles.GLASS_BORDER}; margin-top: 10px; padding-top: 10px; font-weight: bold; color: {styles.TEXT_COLOR}; }}"
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
            f"QGroupBox {{ border: 1px solid {styles.GLASS_BORDER}; margin-top: 10px; padding-top: 10px; font-weight: bold; color: {styles.TEXT_MUTED}; }}"
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
            QLabel(
                "File Operations",
                styleSheet=f"font-weight: bold; color: {styles.ACCENT_COLOR};",
            )
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
            self.lbl_status.setStyleSheet(f"color: {styles.ACCENT_COLOR}")
        else:
            self.lbl_status.setText("Status: Failed")
            self.lbl_status.setStyleSheet("color: #ef4444")
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
        self.resize(460, 380)
        self.setMinimumSize(380, 320)
        self.setStyleSheet(styles.build_stylesheet() + f"QDialog {{ background-color: {styles.DIALOG_BG}; }}")

        layout = QVBoxLayout(self)
        layout.setSpacing(20)

        layout.addWidget(
            QLabel(
                "Generate High-Entropy Credentials",
                styleSheet=f"color: {styles.TEXT_MUTED};",
            )
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
            f"font-family: Consolas; font-size: 16px; color: {styles.ACCENT_COLOR}; padding: 15px;"
        )
        layout.addWidget(self.out_pass)

        # Actions
        btn_gen = QPushButton(" GENERATE", objectName="Primary")
        btn_gen.setIcon(qta.icon("fa5s.sync", color="white"))
        btn_gen.clicked.connect(self.generate)
        layout.addWidget(btn_gen)

        btn_copy = QPushButton(" Copy to Clipboard")
        btn_copy.clicked.connect(self.copy_to_clip)
        layout.addWidget(btn_copy)

        layout.addStretch()
        self.generate()  # Init with one
        self.clipboard_timer = QTimer(self)
        self.clipboard_timer.setSingleShot(True)
        self.clipboard_timer.timeout.connect(self._clear_clipboard)

    def generate(self):
        l = self.spin_len.value()
        # Using core.tools
        pwd = SecurityTools.generate_password(l)
        self.out_pass.setText(pwd)

    def copy_to_clip(self):
        QApplication.clipboard().setText(self.out_pass.text())
        QMessageBox.information(self, "Copied", "Password copied to clipboard.")
        self.clipboard_timer.start(15000)

    def _clear_clipboard(self):
        QApplication.clipboard().clear()


class NotesDialog(QDialog):
    def __init__(self, parent=None, vault_name=None, password=None, vault_key=None):
        super().__init__(parent)
        self.setWindowTitle("Encrypted Notes Journal")
        self.resize(900, 600)
        self.setMinimumSize(760, 520)
        self.setStyleSheet(styles.build_stylesheet() + f"QDialog {{ background-color: {styles.DIALOG_BG}; }}")

        self.vault_name = vault_name
        self.password = password
        self.vault_key = vault_key
        self.manager = NotesManager(vault_name, vault_key=vault_key)
        self.current_note_id = None

        main_layout = QHBoxLayout(self)

        # Left Panel: Note List & Search
        left_panel = QFrame(objectName="Card")
        left_layout = QVBoxLayout(left_panel)
        left_layout.setContentsMargins(15, 15, 15, 15)

        left_layout.addWidget(
            QLabel(
                "Your Notes",
                styleSheet=f"font-size: 18px; font-weight: bold; color: {styles.ACCENT_COLOR};",
            )
        )

        self.search_bar = QLineEdit()
        self.search_bar.setPlaceholderText("Search notes...")
        self.search_bar.textChanged.connect(self.do_search)
        left_layout.addWidget(self.search_bar)

        self.note_list = QListWidget()
        self.note_list.itemClicked.connect(self.load_note)
        self.note_list.setStyleSheet("border: none; background: transparent;")
        left_layout.addWidget(self.note_list)

        btn_new = QPushButton(" + New Note", objectName="Primary")
        btn_new.clicked.connect(self.new_note)
        left_layout.addWidget(btn_new)

        main_layout.addWidget(left_panel, 1)

        # Right Panel: Editor
        right_panel = QFrame(objectName="Card")
        right_layout = QVBoxLayout(right_panel)
        right_layout.setContentsMargins(20, 20, 20, 20)

        # Title Row
        title_row = QHBoxLayout()
        self.in_title = QLineEdit()
        self.in_title.setPlaceholderText("Note Title")
        self.in_title.setStyleSheet(
            f"font-size: 16px; font-weight: bold; color: {styles.TEXT_COLOR}; border: none; background: transparent; padding: 0;"
        )
        title_row.addWidget(self.in_title)

        btn_delete = QPushButton("Delete", objectName="Danger")
        btn_delete.setMinimumWidth(80)
        btn_delete.clicked.connect(self.delete_note)
        title_row.addWidget(btn_delete)

        right_layout.addLayout(title_row)

        # Separator
        line = QFrame()
        line.setFrameShape(QFrame.Shape.HLine)
        line.setStyleSheet(f"color: {styles.GLASS_BORDER};")
        right_layout.addWidget(line)

        # Content Editor
        self.editor = QTextEdit()
        self.editor.setPlaceholderText("Write your secure thoughts here...")
        self.editor.setStyleSheet(
            "font-family: Consolas; font-size: 14px; line-height: 1.5; border: none; background: transparent;"
        )
        right_layout.addWidget(self.editor)

        # Status & Save
        action_row = QHBoxLayout()
        self.lbl_status = QLabel("Ready")
        self.lbl_status.setStyleSheet(f"color: {styles.TEXT_MUTED};")
        action_row.addWidget(self.lbl_status)

        action_row.addStretch()

        btn_save = QPushButton(" Save Changes", objectName="Primary")
        btn_save.setIcon(qta.icon("fa5s.save", color="white"))
        btn_save.clicked.connect(self.save_note)
        action_row.addWidget(btn_save)

        right_layout.addLayout(action_row)

        main_layout.addWidget(right_panel, 2)

        self.refresh_list()

    def refresh_list(self):
        self.note_list.clear()
        notes = self.manager.list_notes()

        for n in notes:
            note_content = self.manager.get_note(n["id"], self.password)
            if note_content:
                title = note_content.get("title", "Untitled")

                widget_item = QListWidgetItem(title)
                widget_item.setData(Qt.ItemDataRole.UserRole, n["id"])

                modified = note_content.get("modified", "")
                widget_item.setToolTip(f"Modified: {modified}")

                self.note_list.addItem(widget_item)

    def new_note(self):
        self.current_note_id = None
        self.in_title.clear()
        self.editor.clear()
        self.in_title.setFocus()
        self.lbl_status.setText("New Note")

    def load_note(self, item):
        note_id = item.data(Qt.ItemDataRole.UserRole)
        note = self.manager.get_note(note_id, self.password)

        if note:
            self.current_note_id = note_id
            self.in_title.setText(note.get("title", ""))
            self.editor.setText(note.get("content", ""))

            mod = note.get("modified", "").split("T")[0]
            self.lbl_status.setText(f"Last Modified: {mod}")

    def save_note(self):
        title = self.in_title.text()
        content = self.editor.toPlainText()

        if not title:
            QMessageBox.warning(self, "Error", "Title cannot be empty")
            return

        if self.current_note_id:
            self.manager.update_note(
                self.current_note_id, title, content, self.password
            )
            self.lbl_status.setText("Saved existing note.")
        else:
            self.current_note_id = self.manager.create_note(
                title, content, self.password
            )
            self.lbl_status.setText("Created new note.")

        self.refresh_list()

    def delete_note(self):
        if not self.current_note_id:
            return

        confirm = QMessageBox.question(
            self,
            "Confirm Delete",
            "Are you sure you want to delete this encrypted note? This cannot be undone.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )

        if confirm == QMessageBox.StandardButton.Yes:
            self.manager.delete_note(self.current_note_id)
            self.new_note()
            self.refresh_list()

    def do_search(self, text):
        if not text:
            self.refresh_list()
            return

        results = self.manager.search_notes(text, self.password)
        self.note_list.clear()

        for note in results:
            widget_item = QListWidgetItem(note["title"])
            widget_item.setData(Qt.ItemDataRole.UserRole, note["id"])
            self.note_list.addItem(widget_item)


class InitVaultDialog(QDialog):
    def __init__(self, parent=None, vault_mgr=None):
        super().__init__(parent)
        self.vault_mgr = vault_mgr
        self.setWindowTitle("Create Secure Environment")
        self.resize(560, 600)
        self.setMinimumSize(480, 520)
        self.setStyleSheet(styles.build_stylesheet() + f"QDialog {{ background-color: {styles.DIALOG_BG}; }}")

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
                styleSheet=f"font-size: 20px; font-weight: bold; color: {styles.TEXT_COLOR};",
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
                styleSheet=f"font-size: 20px; font-weight: bold; color: {styles.ACCENT_COLOR};",
            )
        )
        l.addWidget(
            QLabel(
                "Scan this QR Code with your Authenticator App, or enter the secret manually.",
                styleSheet=f"color: {styles.TEXT_MUTED};",
            )
        )

        # Tabs for QR / Text
        tabs = QTabWidget()
        tabs.setStyleSheet(
            f"QTabWidget::pane {{ border: 0; }} "
            f"QTabBar::tab {{ background: rgba(15, 23, 42, 0.04); color: {styles.TEXT_MUTED}; padding: 10px; width: 100px; border-radius: 8px; }} "
            f"QTabBar::tab:selected {{ background: {styles.CARD_COLOR}; color: {styles.ACCENT_COLOR}; border-bottom: 2px solid {styles.ACCENT_COLOR}; }}"
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
            f"font-size: 24px; letter-spacing: 5px; font-family: Consolas; color: {styles.ACCENT_COLOR};"
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
        if pwd == duress:
            QMessageBox.warning(
                self, "Error", "Duress password must be different from the master password."
            )
            return
        ok, issues = SecurityTools.validate_password(pwd)
        if not ok:
            QMessageBox.warning(
                self,
                "Weak Password",
                "Master password is too weak:\n- " + "\n- ".join(issues),
            )
            return
        ok, issues = SecurityTools.validate_password(duress)
        if not ok:
            QMessageBox.warning(
                self,
                "Weak Duress Password",
                "Duress password is too weak:\n- " + "\n- ".join(issues),
            )
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



class ThemeCreatorDialog(QDialog):
    def __init__(self, parent=None, theme_manager=None):
        super().__init__(parent)
        self.tm = theme_manager
        self.setWindowTitle("Design Custom Theme")
        self.resize(520, 420)
        self.setMinimumSize(460, 360)
        self.setStyleSheet(styles.build_stylesheet() + f"QDialog {{ background-color: {styles.DIALOG_BG}; }}")

        layout = QVBoxLayout(self)
        layout.setSpacing(20)

        # Name Input
        self.in_name = QLineEdit()
        self.in_name.setPlaceholderText("Theme Name (e.g. Neon Nights)")
        layout.addWidget(QLabel("Theme Name:"))
        layout.addWidget(self.in_name)

        # Colors
        self.colors = {
            "accent": styles.ACCENT_COLOR,
            "secondary": styles.ACCENT_SECONDARY,
            "tertiary": styles.ACCENT_TERTIARY,
        }

        # Color Pickers
        form = QFormLayout()

        self.btn_accent = QPushButton(self.colors["accent"])
        self.btn_accent.clicked.connect(
            lambda: self.pick_color("accent", self.btn_accent)
        )
        self.style_button(self.btn_accent, self.colors["accent"])

        self.btn_secondary = QPushButton(self.colors["secondary"])
        self.btn_secondary.clicked.connect(
            lambda: self.pick_color("secondary", self.btn_secondary)
        )
        self.style_button(self.btn_secondary, self.colors["secondary"])

        self.btn_tertiary = QPushButton(self.colors["tertiary"])
        self.btn_tertiary.clicked.connect(
            lambda: self.pick_color("tertiary", self.btn_tertiary)
        )
        self.style_button(self.btn_tertiary, self.colors["tertiary"])

        form.addRow("Primary Accent:", self.btn_accent)
        form.addRow("Secondary Accent:", self.btn_secondary)
        form.addRow("Tertiary Accent:", self.btn_tertiary)

        layout.addLayout(form)

        layout.addStretch()

        # Save
        btn_save = QPushButton("Save Theme", objectName="Primary")
        btn_save.clicked.connect(self.save_theme)
        layout.addWidget(btn_save)

    def style_button(self, btn, color):
        btn.setStyleSheet(
            f"background-color: {color}; color: {styles.TEXT_COLOR}; font-weight: bold; border: 2px solid {styles.GLASS_BORDER}; border-radius: 8px;"
        )
        btn.setText(color)

    def pick_color(self, key, btn):
        c = QColorDialog.getColor(QColor(self.colors[key]), self, f"Select {key} Color")
        if c.isValid():
            hex_c = c.name()
            self.colors[key] = hex_c
            self.style_button(btn, hex_c)

    def save_theme(self):
        name = self.in_name.text().strip()
        if not name:
            QMessageBox.warning(self, "Error", "Theme name required")
            return

        if self.tm.save_custom_theme(name, self.colors):
            QMessageBox.information(self, "Success", f"Theme '{name}' saved!")
            self.accept()
        else:
            QMessageBox.critical(self, "Error", "Failed to save theme")


class RecoveryDialog(QDialog):
    def __init__(self, parent=None, vault_key=None):
        super().__init__(parent)
        self.vault_key = vault_key
        self.setWindowTitle("Recovery Shares")
        self.resize(560, 440)
        self.setMinimumSize(480, 380)
        self.setStyleSheet(styles.build_stylesheet() + f"QDialog {{ background-color: {styles.DIALOG_BG}; }}")

        layout = QVBoxLayout(self)
        layout.setSpacing(12)

        layout.addWidget(
            QLabel(
                "Generate Algebraic Recovery Shares",
                styleSheet=f"font-size: 18px; font-weight: bold; color: {styles.ACCENT_COLOR};",
            )
        )
        layout.addWidget(
            QLabel(
                "Store these shares offline. Any threshold number can recover the vault key.",
                styleSheet=f"color: {styles.TEXT_MUTED};",
            )
        )

        form = QFormLayout()
        self.spin_threshold = QSpinBox()
        self.spin_threshold.setRange(2, 8)
        self.spin_threshold.setValue(3)

        self.spin_shares = QSpinBox()
        self.spin_shares.setRange(2, 8)
        self.spin_shares.setValue(5)
        self.spin_shares.valueChanged.connect(self._sync_threshold)

        form.addRow("Threshold (t):", self.spin_threshold)
        form.addRow("Total Shares (n):", self.spin_shares)
        layout.addLayout(form)

        self.out_shares = QTextEdit()
        self.out_shares.setReadOnly(True)
        self.out_shares.setPlaceholderText("Generated shares will appear here...")
        layout.addWidget(self.out_shares)

        btn_row = QHBoxLayout()
        btn_gen = QPushButton("Generate", objectName="Primary")
        btn_gen.clicked.connect(self.generate_shares)
        btn_copy = QPushButton("Copy")
        btn_copy.clicked.connect(self.copy_shares)
        btn_save = QPushButton("Save to File")
        btn_save.clicked.connect(self.save_shares)

        btn_row.addWidget(btn_gen)
        btn_row.addWidget(btn_copy)
        btn_row.addWidget(btn_save)
        layout.addLayout(btn_row)

        self.clipboard_timer = QTimer(self)
        self.clipboard_timer.setSingleShot(True)
        self.clipboard_timer.timeout.connect(self._clear_clipboard)

    def _sync_threshold(self):
        if self.spin_threshold.value() > self.spin_shares.value():
            self.spin_threshold.setValue(self.spin_shares.value())

    def generate_shares(self):
        if not self.vault_key:
            QMessageBox.warning(self, "Error", "Vault key unavailable.")
            return
        n = self.spin_shares.value()
        t = self.spin_threshold.value()
        if t > n:
            t = n
            self.spin_threshold.setValue(n)
        shares = ShamirVault.split_secret(self.vault_key, t, n)
        lines = [f"{idx}:{share}" for idx, share in shares]
        self.out_shares.setPlainText("\n".join(lines))

    def copy_shares(self):
        text = self.out_shares.toPlainText().strip()
        if not text:
            return
        QApplication.clipboard().setText(text)
        QMessageBox.information(self, "Copied", "Shares copied to clipboard.")
        self.clipboard_timer.start(15000)

    def save_shares(self):
        text = self.out_shares.toPlainText().strip()
        if not text:
            return
        path, _ = QFileDialog.getSaveFileName(self, "Save Shares", "", "Text Files (*.txt)")
        if not path:
            return
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)

    def _clear_clipboard(self):
        QApplication.clipboard().clear()


class FolderWatcherDialog(QDialog):
    def __init__(self, parent=None, watcher=None):
        super().__init__(parent)
        self.watcher = watcher
        self.setWindowTitle("Auto-Encrypt Watcher")
        self.resize(640, 420)
        self.setMinimumSize(560, 360)
        self.setStyleSheet(styles.build_stylesheet() + f"QDialog {{ background-color: {styles.DIALOG_BG}; }}")

        layout = QVBoxLayout(self)

        # Status
        self.lbl_status = QLabel("Service Status: STOPPED")
        self.lbl_status.setStyleSheet(
            f"font-size: 16px; font-weight: bold; color: {styles.TEXT_MUTED};"
        )
        layout.addWidget(self.lbl_status)

        # Toggle
        self.btn_toggle = QPushButton("START WATCHER", objectName="Primary")
        self.btn_toggle.clicked.connect(self.toggle_service)
        layout.addWidget(self.btn_toggle)

        layout.addSpacing(20)

        # Folder List
        layout.addWidget(
            QLabel(
                "Monitored Folders:",
                styleSheet=f"color: {styles.ACCENT_COLOR}; font-weight: bold;",
            )
        )
        self.list_folders = QListWidget()
        layout.addWidget(self.list_folders)

        # Controls
        row = QHBoxLayout()
        b_add = QPushButton("Add Folder")
        b_add.clicked.connect(self.add_folder)
        b_rem = QPushButton("Remove Selected")
        b_rem.clicked.connect(self.remove_folder)
        row.addWidget(b_add)
        row.addWidget(b_rem)
        layout.addLayout(row)

        # Log
        layout.addWidget(
            QLabel("Activity Log:", styleSheet=f"color: {styles.TEXT_MUTED};")
        )
        self.log = QTextEdit()
        self.log.setReadOnly(True)
        self.log.setMinimumHeight(100)
        layout.addWidget(self.log)

        self.update_ui()

        # Connect signal
        if self.watcher:
            self.watcher.file_processed.connect(self.on_file_processed)

    def update_ui(self):
        if self.watcher and self.watcher.running:
            self.lbl_status.setText("Service Status: RUNNING")
            self.lbl_status.setStyleSheet(
                f"font-size: 16px; font-weight: bold; color: {styles.ACCENT_COLOR};"
            )
            self.btn_toggle.setText("STOP WATCHER")
            self.btn_toggle.setObjectName("Danger")
        else:
            self.lbl_status.setText("Service Status: STOPPED")
            self.lbl_status.setStyleSheet(
                f"font-size: 16px; font-weight: bold; color: {styles.TEXT_MUTED};"
            )
            self.btn_toggle.setText("START WATCHER")
            self.btn_toggle.setObjectName("Primary")

        # Refresh style logic workaround since Qt doesn't dynamic reload objectName style easily
        # We manually apply specific style or just trust stylesheet reload?
        # A simple trick is unpolish/polish, but let's just set specific style
        if self.btn_toggle.objectName() == "Danger":
            self.btn_toggle.setStyleSheet("background-color: #ef4444; color: white;")
        else:
            self.btn_toggle.setStyleSheet(
                f"background-color: {styles.ACCENT_COLOR}; color: white;"
            )

        self.list_folders.clear()
        if self.watcher:
            for f in self.watcher.get_folders():
                self.list_folders.addItem(f)

    def toggle_service(self):
        if not self.watcher:
            return

        if self.watcher.running:
            self.watcher.stop()
        else:
            if not self.watcher.get_folders():
                QMessageBox.warning(
                    self, "Error", "Add at least one folder monitoring."
                )
                return
            self.watcher.start()
        self.update_ui()

    def add_folder(self):
        d = QFileDialog.getExistingDirectory(self, "Select Folder to Watch")
        if d and self.watcher:
            self.watcher.add_folder(d)
            self.update_ui()

    def remove_folder(self):
        item = self.list_folders.currentItem()
        if item and self.watcher:
            self.watcher.remove_folder(item.text())
            self.update_ui()

    def on_file_processed(self, filename, status):
        self.log.append(f"[{time.strftime('%H:%M:%S')}] {filename}: {status}")


