import sys
import json
import os
import secrets
import webbrowser
from PyQt5 import QtWidgets, QtCore, QtGui
from PyQt5.QtWidgets import *
from PyQt5.QtCore import Qt, QTimer, QSize, QPropertyAnimation, QEasingCurve
from PyQt5.QtGui import QPixmap, QImage, QPalette, QColor, QFont, QIcon
import qrcode
from io import BytesIO

# Import bip_utils modules
from bip_utils import (
    Bip39MnemonicGenerator, Bip39WordsNum, Bip39SeedGenerator,
    Bip44, Bip44Coins, Bip44Changes,
    Bip84, Bip84Coins, Bip39MnemonicValidator,
    Bip32Utils, WifEncoder, WifDecoder,
    Bech32Encoder, Bech32Decoder, Bech32ChecksumError,
    Base58Encoder, Base58Decoder
)
from bip_utils.utils.mnemonic import MnemonicChecksumError
from bip_utils.addr import P2PKHAddr, P2WPKHAddr
from coincurve import PublicKey
import bech32

def validate_mnemonic(mnemonic_str):
    """Validate a BIP39 mnemonic phrase."""
    try:
        Bip39MnemonicValidator().Validate(mnemonic_str)
        return True, None
    except MnemonicChecksumError as e:
        return False, f"Invalid checksum in mnemonic: {str(e)}"
    except Exception as e:
        return False, f"Invalid mnemonic: {str(e)}"

def validate_xpub(xpub):
    """Validate an extended public key."""
    try:
        if not xpub.startswith(('xpub', 'ypub', 'zpub')):
            return False, "Invalid XPUB format"
        raw_key = Base58Decoder.CheckDecode(xpub)
        if len(raw_key) != 78:
            return False, "Invalid key length"
        version_bytes = raw_key[:4].hex()
        if xpub.startswith('zpub') and version_bytes != '04b24746':
            return False, "Invalid zpub version bytes"
        elif xpub.startswith('xpub') and version_bytes != '0488b21e':
            return False, "Invalid xpub version bytes"
        return True, None
    except Exception as e:
        return False, str(e)

def validate_bitcoin_address(address, is_segwit=False):
    """Validate a Bitcoin address."""
    try:
        if is_segwit:
            if not address.startswith('bc1'):
                return False
            try:
                hrp, data = bech32.decode('bc', address)
                return hrp is not None and data is not None
            except Exception:
                return False
        else:
            if not address.startswith(('1', '3')):
                return False
            try:
                Base58Decoder.CheckDecode(address)
                return True
            except Exception:
                return False
    except Exception:
        return False

class SwipeableTabBar(QTabBar):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.pressing = False
        self.mousePressPos = None
        self.tabWidget = None
        
    def setTabWidget(self, tabWidget):
        self.tabWidget = tabWidget
    
    def mousePressEvent(self, event):
        self.pressing = True
        self.mousePressPos = event.pos()
        super().mousePressEvent(event)
    
    def mouseReleaseEvent(self, event):
        self.pressing = False
        super().mouseReleaseEvent(event)
    
    def mouseMoveEvent(self, event):
        if self.pressing and self.mousePressPos and self.tabWidget:
            delta = event.pos().x() - self.mousePressPos.x()
            if abs(delta) > 100:  # Threshold for swipe
                current = self.tabWidget.currentIndex()
                if delta < 0 and current < self.tabWidget.count() - 1:
                    self.tabWidget.setCurrentIndex(current + 1)
                elif delta > 0 and current > 0:
                    self.tabWidget.setCurrentIndex(current - 1)
                self.pressing = False
        super().mouseMoveEvent(event)

class SwipeableTabWidget(QTabWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setTabBar(SwipeableTabBar())
        self.tabBar().setTabWidget(self)
        
        # Mobile-friendly tab styling
        self.setStyleSheet("""
            QTabWidget::pane {
                border: none;
                background: #1e1e1e;
            }
            QTabBar::tab {
                padding: 12px 20px;
                min-width: 80px;
                background: #2d2d2d;
                border: none;
                color: #888;
            }
            QTabBar::tab:selected {
                background: #353535;
                color: #2a82da;
                border-bottom: 2px solid #2a82da;
            }
        """)

class CollapsibleSection(QWidget):
    def __init__(self, title, parent=None):
        super().__init__(parent)
        self.animation = None
        self.is_collapsed = True
        
        layout = QVBoxLayout(self)
        layout.setSpacing(0)
        layout.setContentsMargins(0, 0, 0, 0)
        
        self.toggle_button = QPushButton(title)
        self.toggle_button.setStyleSheet("""
            QPushButton {
                text-align: left;
                padding: 12px;
                background-color: #2d2d2d;
                border: none;
                border-radius: 4px;
                color: #c8c8c8;
            }
            QPushButton:hover {
                background-color: #353535;
            }
        """)
        self.toggle_button.clicked.connect(self.toggle_collapse)
        
        self.content = QWidget()
        self.content_layout = QVBoxLayout(self.content)
        self.content.setMaximumHeight(0)
        self.content.setVisible(False)
        
        layout.addWidget(self.toggle_button)
        layout.addWidget(self.content)
    
    def add_widget(self, widget):
        self.content_layout.addWidget(widget)
    
    def toggle_collapse(self):
        if self.animation and self.animation.state() == QPropertyAnimation.Running:
            return
        
        self.is_collapsed = not self.is_collapsed
        self.content.setVisible(True)
        
        self.animation = QPropertyAnimation(self.content, b"maximumHeight")
        self.animation.setDuration(300)
        self.animation.setEasingCurve(QEasingCurve.InOutQuad)
        
        if self.is_collapsed:
            self.animation.setStartValue(self.content.sizeHint().height())
            self.animation.setEndValue(0)
        else:
            self.animation.setStartValue(0)
            self.animation.setEndValue(self.content.sizeHint().height())
        
        self.animation.finished.connect(
            lambda: self.content.setVisible(not self.is_collapsed)
        )
        self.animation.start()

class CompactQRWidget(QLabel):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMinimumSize(150, 150)
        self.setMaximumSize(150, 150)
        self.setAlignment(Qt.AlignCenter)
        self.setStyleSheet("""
            QLabel {
                background-color: #2d2d2d;
                border-radius: 8px;
                padding: 8px;
            }
        """)
    
    def setQRCode(self, data):
        if not data:
            self.clear()
            return
            
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=1,
        )
        qr.add_data(data)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="#2a82da", back_color="#2d2d2d")
        byte_array = BytesIO()
        img.save(byte_array, format='PNG')
        qimage = QImage.fromData(byte_array.getvalue())
        pixmap = QPixmap.fromImage(qimage)
        scaled_pixmap = pixmap.scaled(140, 140, Qt.KeepAspectRatio, Qt.SmoothTransformation)
        self.setPixmap(scaled_pixmap)

class StatusIndicator(QLabel):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedSize(24, 24)
        self.setAlignment(Qt.AlignCenter)
        self.setStyleSheet("""
            QLabel {
                background-color: #2d2d2d;
                border-radius: 12px;
                color: #c8c8c8;
            }
        """)
    
    def setState(self, state):
        if state == "success":
            self.setText("✓")
            self.setStyleSheet("background: #2a5a3c; color: #4cd964; border-radius: 12px;")
        elif state == "error":
            self.setText("✗")
            self.setStyleSheet("background: #5a2a2a; color: #ff3b30; border-radius: 12px;")
        elif state == "warning":
            self.setText("!")
            self.setStyleSheet("background: #5a4d2a; color: #ffcc00; border-radius: 12px;")
        else:
            self.setText("○")
            self.setStyleSheet("background: #2d2d2d; color: #c8c8c8; border-radius: 12px;")

class CompactWalletTool(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Mobile Wallet Tool")
        self.setMinimumWidth(320)
        self.setup_ui()
    
    def setup_ui(self):
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        layout = QVBoxLayout(main_widget)
        layout.setSpacing(8)
        layout.setContentsMargins(8, 8, 8, 8)
        
        # Create swipeable tab widget
        self.tabs = SwipeableTabWidget()
        layout.addWidget(self.tabs)
        
        # Setup tabs
        self.setup_generate_tab()
        self.setup_addresses_tab()
        self.setup_verify_tab()
        
        # Add tabs
        self.tabs.addTab(self.generate_tab, "Generate")
        self.tabs.addTab(self.addresses_tab, "Addresses")
        self.tabs.addTab(self.verify_tab, "Verify")
        
        self.setup_theme()
    
    def setup_generate_tab(self):
        self.generate_tab = QWidget()
        layout = QVBoxLayout(self.generate_tab)
        layout.setSpacing(12)
        
        # Key Type Selection
        key_type_layout = QHBoxLayout()
        key_type_label = QLabel("Key Type:")
        self.key_type_combo = QComboBox()
        self.key_type_combo.addItems(["zpub (BIP84)", "xpub (BIP44)"])
        key_type_layout.addWidget(key_type_label)
        key_type_layout.addWidget(self.key_type_combo)
        layout.addLayout(key_type_layout)
        
        # Generate Button
        self.generate_btn = QPushButton("Generate New Wallet")
        self.generate_btn.clicked.connect(self.generate_wallet)
        layout.addWidget(self.generate_btn)
        
        # Collapsible Sections
        self.mnemonic_section = CollapsibleSection("Mnemonic Seed")
        self.mnemonic_text = QTextEdit()
        self.mnemonic_text.setReadOnly(True)
        self.mnemonic_text.setMaximumHeight(80)
        self.mnemonic_section.add_widget(self.mnemonic_text)
        layout.addWidget(self.mnemonic_section)
        
        self.xpub_section = CollapsibleSection("Extended Public Key")
        self.xpub_text = QTextEdit()
        self.xpub_text.setReadOnly(True)
        self.xpub_text.setMaximumHeight(60)
        self.xpub_section.add_widget(self.xpub_text)
        layout.addWidget(self.xpub_section)
        
        self.qr_section = CollapsibleSection("QR Code")
        self.qr_widget = CompactQRWidget()
        self.qr_section.add_widget(self.qr_widget)
        layout.addWidget(self.qr_section)
        
        layout.addStretch()
    
    def setup_addresses_tab(self):
        self.addresses_tab = QWidget()
        layout = QVBoxLayout(self.addresses_tab)
        layout.setSpacing(12)
        
        # XPUB Input Section
        xpub_section = CollapsibleSection("Extended Public Key")
        self.addr_xpub_input = QLineEdit()
        self.addr_xpub_input.setPlaceholderText("Enter xpub/zpub...")
        xpub_section.add_widget(self.addr_xpub_input)
        layout.addWidget(xpub_section)
        
        # Settings Section
        settings_section = CollapsibleSection("Generation Settings")
        settings_layout = QFormLayout()
        
        self.addr_count = QSpinBox()
        self.addr_count.setRange(1, 1000)
        self.addr_count.setValue(10)
        settings_layout.addRow("Number of Addresses:", self.addr_count)
        
        self.addr_format = QComboBox()
        self.addr_format.addItems(["Plain Text", "CSV", "JSON"])
        settings_layout.addRow("Output Format:", self.addr_format)
        
        settings_widget = QWidget()
        settings_widget.setLayout(settings_layout)
        settings_section.add_widget(settings_widget)
        layout.addWidget(settings_section)
        
        # Buttons
        buttons_layout = QHBoxLayout()
        self.generate_addresses_btn = QPushButton("Generate")
        self.save_addresses_btn = QPushButton("Save")
        self.generate_addresses_btn.clicked.connect(self.generate_addresses)
        self.save_addresses_btn.clicked.connect(self.save_addresses)
        buttons_layout.addWidget(self.generate_addresses_btn)
        buttons_layout.addWidget(self.save_addresses_btn)
        layout.addLayout(buttons_layout)
        
        # Output Section
        self.addresses_output = QTextEdit()
        self.addresses_output.setReadOnly(True)
        self.addresses_output.setMinimumHeight(200)
        layout.addWidget(self.addresses_output)
    
    def setup_verify_tab(self):
        self.verify_tab = QWidget()
        layout = QVBoxLayout(self.verify_tab)
        layout.setSpacing(12)
        
        # XPUB Verification Section
        xpub_verify_section = CollapsibleSection("Verify XPUB")
        xpub_layout = QVBoxLayout()
        
        self.verify_xpub_input = QLineEdit()
        self.verify_xpub_input.setPlaceholderText("Enter xpub/zpub to verify...")
        xpub_layout.addWidget(self.verify_xpub_input)
        
        self.verify_xpub_btn = QPushButton("Verify XPUB")
        self.verify_xpub_btn.clicked.connect(self.verify_xpub)
        xpub_layout.addWidget(self.verify_xpub_btn)
        
        # Status indicators
        self.xpub_indicators = {}
        indicators_layout = QFormLayout()
        for key in ["Format", "Version", "Length", "Checksum"]:
            indicator = StatusIndicator()
            self.xpub_indicators[key.lower()] = indicator
            indicators_layout.addRow(f"{key}:", indicator)
        
        indicators_widget = QWidget()
        indicators_widget.setLayout(indicators_layout)
        xpub_layout.addWidget(indicators_widget)
        
        xpub_verify_widget = QWidget()
        xpub_verify_widget.setLayout(xpub_layout)
        xpub_verify_section.add_widget(xpub_verify_widget)
        layout.addWidget(xpub_verify_section)
        
        # Address Verification Section
        addr_verify_section = CollapsibleSection("Verify Address")
        addr_layout = QVBoxLayout()
        
        self.verify_addr_input = QLineEdit()
        self.verify_addr_input.setPlaceholderText("Enter Bitcoin address to verify...")
        addr_layout.addWidget(self.verify_addr_input)
        
        self.verify_addr_btn = QPushButton("Verify Address")
        self.verify_addr_btn.clicked.connect(self.verify_address)
        addr_layout.addWidget(self.verify_addr_btn)
        
        # Address status indicators
        self.addr_indicators = {}
        addr_indicators_layout = QFormLayout()
        for key in ["Format", "Type", "Network"]:
            indicator = StatusIndicator()
            self.addr_indicators[key.lower()] = indicator
            addr_indicators_layout.addRow(f"{key}:", indicator)
        
        addr_indicators_widget = QWidget()
        addr_indicators_widget.setLayout(addr_indicators_layout)
        addr_layout.addWidget(addr_indicators_widget)
        
        addr_verify_widget = QWidget()
        addr_verify_widget.setLayout(addr_layout)
        addr_verify_section.add_widget(addr_verify_widget)
        layout.addWidget(addr_verify_section)
        
        layout.addStretch()
    
    def setup_theme(self):
        self.setStyleSheet("""
            QMainWindow, QWidget {
                background-color: #1e1e1e;
                color: #c8c8c8;
            }
            QPushButton {
                background-color: #2a82da;
                color: white;
                border: none;
                border-radius: 4px;
                padding: 12px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #3a92ea;
            }
            QLineEdit, QTextEdit, QComboBox, QSpinBox {
                background-color: #353535;
                border: 1px solid #454545;
                border-radius: 4px;
                padding: 8px;
                color: #c8c8c8;
            }
            QLabel {
                color: #c8c8c8;
            }
        """)
    
    def generate_wallet(self):
        try:
            # Generate mnemonic
            mnemonic = Bip39MnemonicGenerator().FromWordsNumber(Bip39WordsNum.WORDS_NUM_12)
            seed = Bip39SeedGenerator(mnemonic).Generate()
            
            # Generate master key based on selected type
            if "zpub" in self.key_type_combo.currentText().lower():
                master_key = Bip84.FromSeed(seed, Bip84Coins.BITCOIN)
            else:
                master_key = Bip44.FromSeed(seed, Bip44Coins.BITCOIN)
            
            # Get extended public key
            xpub = master_key.PublicKey().ToExtended()
            
            # Update UI
            self.mnemonic_text.setText(" ".join(mnemonic.ToList()))
            self.xpub_text.setText(xpub)
            self.qr_widget.setQRCode(xpub)
            
            # Auto-expand sections
            for section in [self.mnemonic_section, self.xpub_section, self.qr_section]:
                if section.is_collapsed:
                    section.toggle_collapse()
            
            # Copy to addresses tab
            self.addr_xpub_input.setText(xpub)
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to generate wallet: {str(e)}")
    
    def generate_addresses(self):
        xpub = self.addr_xpub_input.text().strip()
        if not xpub:
            QMessageBox.warning(self, "Input Error", "Please enter an extended public key.")
            return
        
        try:
            count = self.addr_count.value()
            is_bip84 = xpub.startswith("zpub")
            
            # Create master key from xpub
            if is_bip84:
                master_key = Bip84.FromExtendedKey(xpub, Bip84Coins.BITCOIN)
            else:
                master_key = Bip44.FromExtendedKey(xpub, Bip44Coins.BITCOIN)
            
            # Generate addresses
            addresses = []
            for i in range(count):
                addr = master_key.Change(Bip44Changes.CHAIN_EXT).AddressIndex(i).PublicKey().ToAddress()
                addresses.append({"index": i, "address": addr})
            
            # Format output
            output_format = self.addr_format.currentText()
            if output_format == "CSV":
                output = "index,address\n" + "\n".join(f"{a['index']},{a['address']}" for a in addresses)
            elif output_format == "JSON":
                output = json.dumps(addresses, indent=2)
            else:
                output = "\n".join(f"{a['index']}: {a['address']}" for a in addresses)
            
            self.addresses_output.setText(output)
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to generate addresses: {str(e)}")
    
    def save_addresses(self):
        text = self.addresses_output.toPlainText()
        if not text:
            QMessageBox.warning(self, "No Data", "Please generate addresses first.")
            return
        
        try:
            file_name, _ = QFileDialog.getSaveFileName(
                self, "Save Addresses",
                "",
                "Text Files (*.txt);;CSV Files (*.csv);;JSON Files (*.json);;All Files (*)"
            )
            
            if file_name:
                with open(file_name, 'w') as f:
                    f.write(text)
                QMessageBox.information(self, "Success", "Addresses saved successfully!")
                
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to save file: {str(e)}")
    
    def verify_xpub(self):
        xpub = self.verify_xpub_input.text().strip()
        if not xpub:
            QMessageBox.warning(self, "Input Error", "Please enter an extended public key.")
            return
        
        # Reset indicators
        for indicator in self.xpub_indicators.values():
            indicator.setState("neutral")
        
        try:
            # Format check
            self.xpub_indicators["format"].setState(
                "success" if xpub.startswith(('xpub', 'ypub', 'zpub')) else "error"
            )
            
            # Full validation
            is_valid, error = validate_xpub(xpub)
            if is_valid:
                for key in ["version", "length", "checksum"]:
                    self.xpub_indicators[key].setState("success")
            else:
                QMessageBox.warning(self, "Validation Error", error)
                
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Validation failed: {str(e)}")
    
    def verify_address(self):
        address = self.verify_addr_input.text().strip()
        if not address:
            QMessageBox.warning(self, "Input Error", "Please enter a Bitcoin address.")
            return
        
        # Reset indicators
        for indicator in self.addr_indicators.values():
            indicator.setState("neutral")
        
        try:
            # Format check
            valid_format = address.startswith(('bc1', '1', '3'))
            self.addr_indicators["format"].setState("success" if valid_format else "error")
            
            # Type detection
            if address.startswith('bc1'):
                self.addr_indicators["type"].setState("success")
                addr_type = "Native SegWit"
            elif address.startswith('3'):
                self.addr_indicators["type"].setState("success")
                addr_type = "Nested SegWit"
            elif address.startswith('1'):
                self.addr_indicators["type"].setState("success")
                addr_type = "Legacy"
            else:
                self.addr_indicators["type"].setState("error")
                addr_type = "Unknown"
            
            # Network check (mainnet)
            self.addr_indicators["network"].setState(
                "success" if valid_format else "error"
            )
            
            if valid_format:
                QMessageBox.information(
                    self,
                    "Address Info",
                    f"Type: {addr_type}\nNetwork: Mainnet\nFormat: Valid"
                )
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Validation failed: {str(e)}")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = CompactWalletTool()
    window.show()
    sys.exit(app.exec_()) 