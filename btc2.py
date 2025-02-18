import sys
import json
import os
import secrets
import webbrowser
from PyQt5 import QtWidgets, QtCore, QtGui
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QLabel, QLineEdit, QSpinBox, QComboBox,
    QPushButton, QTextEdit, QVBoxLayout, QFormLayout, QWidget, QFileDialog, QMessageBox, QHBoxLayout,
    QFrame, QSizePolicy, QTabWidget, QGroupBox, QGridLayout
)
from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtGui import QPixmap, QImage, QPalette, QColor, QFont
import qrcode
from io import BytesIO

# Import bip_utils modules with updated imports
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
        # This will check:
        # 1. All words are in the wordlist
        # 2. Checksum is valid
        # 3. Word count is valid
        Bip39MnemonicValidator().Validate(mnemonic_str)
        return True, None
    except MnemonicChecksumError as e:
        return False, f"Invalid checksum in mnemonic: {str(e)}"
    except Exception as e:
        return False, f"Invalid mnemonic: {str(e)}"

def validate_secp256k1_pubkey(key_bytes):
    """Validate a secp256k1 public key."""
    try:
        # Check key length (33 bytes for compressed, 65 for uncompressed)
        if len(key_bytes) not in (33, 65):
            return False, "Invalid public key length"
            
        # For compressed public keys (what we expect)
        if len(key_bytes) == 33:
            # Check first byte (0x02 or 0x03 for compressed keys)
            if key_bytes[0] not in (0x02, 0x03):
                return False, "Invalid public key format"
                
        # For uncompressed public keys
        elif len(key_bytes) == 65:
            # Check first byte (0x04 for uncompressed keys)
            if key_bytes[0] != 0x04:
                return False, "Invalid public key format"
        
        # Validate the public key using coincurve
        try:
            # This will raise an exception if the key is invalid
            PublicKey(key_bytes)
            return True, None
        except Exception as e:
            return False, f"Public key validation failed: {str(e)}"
            
    except Exception as e:
        return False, f"Error validating public key: {str(e)}"

def validate_xpub(xpub):
    """Validate an extended public key."""
    try:
        # Basic format check
        if not xpub.startswith(('xpub', 'ypub', 'zpub')):
            return False, "Invalid XPUB format"
            
        # Decode and validate
        raw_key = Base58Decoder.CheckDecode(xpub)
        
        # Check length
        if len(raw_key) != 78:
            return False, "Invalid key length"
            
        # Check version bytes
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
            # For BIP84 (native SegWit), addresses start with bc1
            if not address.startswith('bc1'):
                return False
                
            try:
                # Decode bech32
                hrp, data = bech32.decode('bc', address)
                if hrp is None or data is None:
                    return False
                return True
            except Exception:
                return False
        else:
            # For BIP44 (legacy), addresses start with 1 or 3
            if not address.startswith(('1', '3')):
                return False
                
            try:
                # Decode base58
                Base58Decoder.CheckDecode(address)
                return True
            except Exception:
                return False
                
    except Exception:
        return False

def generate_qr_code(data, size=200):
    """Generate a styled QR code with the given data"""
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=1,
    )
    qr.add_data(data)
    qr.make(fit=True)

    # Create QR code image with custom colors
    img = qr.make_image(fill_color="#2a82da", back_color="#2d2d2d")
    
    # Convert to QPixmap
    byte_array = BytesIO()
    img.save(byte_array, format='PNG')
    qimage = QImage.fromData(byte_array.getvalue())
    pixmap = QPixmap.fromImage(qimage)
    
    # Scale to desired size
    pixmap = pixmap.scaled(size, size, Qt.KeepAspectRatio, Qt.SmoothTransformation)
    
    return pixmap

def setup_theme(app):
    """Set up the modern dark theme for the application"""
    # Set up the dark theme palette
    palette = QPalette()
    palette.setColor(QPalette.Window, QColor(30, 30, 30))
    palette.setColor(QPalette.WindowText, QColor(200, 200, 200))
    palette.setColor(QPalette.Base, QColor(45, 45, 45))
    palette.setColor(QPalette.AlternateBase, QColor(35, 35, 35))
    palette.setColor(QPalette.ToolTipBase, QColor(30, 30, 30))
    palette.setColor(QPalette.ToolTipText, QColor(200, 200, 200))
    palette.setColor(QPalette.Text, QColor(200, 200, 200))
    palette.setColor(QPalette.Button, QColor(53, 53, 53))
    palette.setColor(QPalette.ButtonText, QColor(200, 200, 200))
    palette.setColor(QPalette.BrightText, Qt.red)
    palette.setColor(QPalette.Link, QColor(42, 130, 218))
    palette.setColor(QPalette.Highlight, QColor(42, 130, 218))
    palette.setColor(QPalette.HighlightedText, QColor(30, 30, 30))
    palette.setColor(QPalette.Disabled, QPalette.Text, QColor(100, 100, 100))
    palette.setColor(QPalette.Disabled, QPalette.ButtonText, QColor(100, 100, 100))
    app.setPalette(palette)

    # Set up modern stylesheet
    app.setStyleSheet("""
        QMainWindow {
            background-color: #1e1e1e;
        }
        QTabWidget::pane {
            border: none;
            background-color: #1e1e1e;
        }
        QTabBar::tab {
            background-color: #2d2d2d;
            color: #c8c8c8;
            padding: 12px 25px;
            border: none;
            border-top-left-radius: 4px;
            border-top-right-radius: 4px;
            margin-right: 2px;
        }
        QTabBar::tab:selected {
            background-color: #353535;
            color: #ffffff;
        }
        QTabBar::tab:hover:!selected {
            background-color: #404040;
        }
        QGroupBox {
            background-color: #2d2d2d;
            border: none;
            border-radius: 8px;
            margin-top: 15px;
            padding: 15px;
        }
        QGroupBox::title {
            color: #c8c8c8;
            subcontrol-origin: margin;
            left: 15px;
            padding: 0 5px;
        }
        QPushButton {
            background-color: #2a82da;
            color: white;
            border: none;
            border-radius: 4px;
            padding: 8px 15px;
            min-width: 80px;
            outline: none;
        }
        QPushButton:hover {
            background-color: #3a92ea;
        }
        QPushButton:pressed {
            background-color: #1a72ca;
        }
        QPushButton:disabled {
            background-color: #555555;
            color: #888888;
        }
        QLineEdit, QTextEdit, QSpinBox, QComboBox {
            background-color: #353535;
            border: 1px solid #454545;
            border-radius: 4px;
            padding: 8px;
            color: #c8c8c8;
            selection-background-color: #2a82da;
        }
        QLineEdit:focus, QTextEdit:focus, QSpinBox:focus, QComboBox:focus {
            border: 1px solid #2a82da;
        }
        QSpinBox::up-button, QSpinBox::down-button {
            border: none;
            background-color: #454545;
            border-radius: 2px;
        }
        QSpinBox::up-button:hover, QSpinBox::down-button:hover {
            background-color: #555555;
        }
        QComboBox::drop-down {
            border: none;
            width: 20px;
        }
        QComboBox::down-arrow {
            image: url(down_arrow.png);
            width: 12px;
            height: 12px;
        }
        QScrollBar:vertical {
            border: none;
            background-color: #2d2d2d;
            width: 10px;
            margin: 0;
        }
        QScrollBar::handle:vertical {
            background-color: #454545;
            min-height: 20px;
            border-radius: 5px;
        }
        QScrollBar::handle:vertical:hover {
            background-color: #555555;
        }
        QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
            height: 0;
            background: none;
        }
        QLabel {
            color: #c8c8c8;
        }
        QTextEdit {
            background-color: #2d2d2d;
        }
        #separator {
            background-color: #454545;
        }
    """)

class LoadingOverlay(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAttribute(Qt.WA_TransparentForMouseEvents)
        self.setAttribute(Qt.WA_TranslucentBackground)
        
        # Animation timer
        self.angle = 0
        self.timer = QTimer()
        self.timer.timeout.connect(self.rotate)
        self.timer.start(30)  # 30ms interval for smooth animation
        
        # Hide initially
        self.hide()
    
    def paintEvent(self, event):
        if not self.isVisible():
            return
            
        painter = QtGui.QPainter(self)
        painter.setRenderHint(QtGui.QPainter.Antialiasing)
        
        # Create loading circle
        center = self.rect().center()
        painter.translate(center)
        painter.rotate(self.angle)
        
        # Draw loading circle segments
        painter.setPen(Qt.NoPen)
        for i in range(8):
            painter.rotate(45)
            alpha = 255 - (i * 32)
            if alpha < 0:
                alpha = 0
            painter.setBrush(QColor(42, 130, 218, alpha))
            painter.drawRoundedRect(-4, -20, 8, 12, 4, 4)
    
    def rotate(self):
        self.angle = (self.angle + 10) % 360
        self.update()
    
    def showEvent(self, event):
        self.timer.start()
    
    def hideEvent(self, event):
        self.timer.stop()

class QRCodeWidget(QLabel):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedSize(200, 200)
        self.setAlignment(Qt.AlignCenter)
        self.setStyleSheet("""
            QLabel {
                background-color: #2d2d2d;
                border-radius: 10px;
                padding: 10px;
            }
        """)
        
        # Add shadow effect
        shadow = QtWidgets.QGraphicsDropShadowEffect()
        shadow.setBlurRadius(10)
        shadow.setColor(QColor(0, 0, 0, 80))
        shadow.setOffset(0, 2)
        self.setGraphicsEffect(shadow)
        
        # Create loading overlay
        self.loading = LoadingOverlay(self)
        self.loading.resize(self.size())
        self.loading.hide()
    
    def showLoading(self):
        self.loading.show()
    
    def hideLoading(self):
        self.loading.hide()
    
    def setQRCode(self, data):
        self.showLoading()
        # Use QTimer to allow the loading animation to show
        QTimer.singleShot(100, lambda: self._setQRCode(data))
    
    def _setQRCode(self, data):
        if data:
            pixmap = generate_qr_code(data)
            self.setPixmap(pixmap)
        else:
            self.clear()
        self.hideLoading()

class StyledLineEdit(QLineEdit):
    def __init__(self, parent=None, placeholder=""):
        super().__init__(parent)
        self.setPlaceholderText(placeholder)
        self.setMinimumHeight(40)
        self.setStyleSheet("""
            QLineEdit {
                background-color: #353535;
                border: 2px solid #454545;
                border-radius: 6px;
                padding: 8px 12px;
                color: #c8c8c8;
                font-size: 13px;
            }
            QLineEdit:focus {
                border: 2px solid #2a82da;
                background-color: #404040;
            }
            QLineEdit:hover:!focus {
                background-color: #404040;
            }
        """)

class StyledTextEdit(QTextEdit):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setStyleSheet("""
            QTextEdit {
                background-color: #353535;
                border: 2px solid #454545;
                border-radius: 6px;
                padding: 8px 12px;
                color: #c8c8c8;
                font-size: 13px;
            }
            QTextEdit:focus {
                border: 2px solid #2a82da;
                background-color: #404040;
            }
            QTextEdit:hover:!focus {
                background-color: #404040;
            }
        """)

class StyledButton(QPushButton):
    def __init__(self, text, parent=None, primary=True):
        super().__init__(text, parent)
        self.setMinimumHeight(40)
        self.setCursor(Qt.PointingHandCursor)
        
        if primary:
            self.setStyleSheet("""
                QPushButton {
                    background-color: #2a82da;
                    color: white;
                    border: none;
                    border-radius: 6px;
                    padding: 8px 20px;
                    font-size: 13px;
                    font-weight: bold;
                }
                QPushButton:hover {
                    background-color: #3a92ea;
                }
                QPushButton:pressed {
                    background-color: #1a72ca;
                }
                QPushButton:disabled {
                    background-color: #555555;
                    color: #888888;
                }
            """)
        else:
            self.setStyleSheet("""
                QPushButton {
                    background-color: #454545;
                    color: #c8c8c8;
                    border: none;
                    border-radius: 6px;
                    padding: 8px 20px;
                    font-size: 13px;
                }
                QPushButton:hover {
                    background-color: #505050;
                }
                QPushButton:pressed {
                    background-color: #353535;
                }
                QPushButton:disabled {
                    background-color: #353535;
                    color: #888888;
                }
            """)

class StyledComboBox(QComboBox):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMinimumHeight(40)
        self.setCursor(Qt.PointingHandCursor)
        self.setStyleSheet("""
            QComboBox {
                background-color: #353535;
                border: 2px solid #454545;
                border-radius: 6px;
                padding: 8px 12px;
                color: #c8c8c8;
                font-size: 13px;
            }
            QComboBox:hover {
                background-color: #404040;
            }
            QComboBox:focus {
                border: 2px solid #2a82da;
            }
            QComboBox::drop-down {
                border: none;
                width: 30px;
            }
            QComboBox::down-arrow {
                image: url(down_arrow.png);
                width: 12px;
                height: 12px;
            }
            QComboBox QAbstractItemView {
                background-color: #353535;
                border: 1px solid #454545;
                selection-background-color: #2a82da;
                selection-color: white;
            }
        """)

class StyledSpinBox(QSpinBox):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMinimumHeight(40)
        self.setStyleSheet("""
            QSpinBox {
                background-color: #353535;
                border: 2px solid #454545;
                border-radius: 6px;
                padding: 8px 12px;
                color: #c8c8c8;
                font-size: 13px;
            }
            QSpinBox:hover {
                background-color: #404040;
            }
            QSpinBox:focus {
                border: 2px solid #2a82da;
            }
            QSpinBox::up-button, QSpinBox::down-button {
                width: 25px;
                border: none;
                background-color: #454545;
                border-radius: 3px;
            }
            QSpinBox::up-button:hover, QSpinBox::down-button:hover {
                background-color: #505050;
            }
            QSpinBox::up-button:pressed, QSpinBox::down-button:pressed {
                background-color: #353535;
            }
        """)

class StatusIndicator(QLabel):
    def __init__(self, text="", tooltip="", parent=None):
        super().__init__(text, parent)
        self.setFixedSize(24, 24)
        self.setAlignment(Qt.AlignCenter)
        self.setToolTip(tooltip)
        self.setStyleSheet("""
            QLabel {
                background-color: #353535;
                border-radius: 12px;
                color: #c8c8c8;
                font-size: 14px;
            }
        """)
        self.setState("neutral")
    
    def setState(self, state):
        """Set the state of the indicator: success, error, warning, or neutral"""
        if state == "success":
            self.setText("✓")
            self.setStyleSheet("""
                QLabel {
                    background-color: #2a5a3c;
                    border-radius: 12px;
                    color: #4cd964;
                    font-size: 14px;
                }
            """)
        elif state == "error":
            self.setText("✗")
            self.setStyleSheet("""
                QLabel {
                    background-color: #5a2a2a;
                    border-radius: 12px;
                    color: #ff3b30;
                    font-size: 14px;
                }
            """)
        elif state == "warning":
            self.setText("!")
            self.setStyleSheet("""
                QLabel {
                    background-color: #5a4d2a;
                    border-radius: 12px;
                    color: #ffcc00;
                    font-size: 14px;
                }
            """)
        else:  # neutral
            self.setText("⚪")
            self.setStyleSheet("""
                QLabel {
                    background-color: #353535;
                    border-radius: 12px;
                    color: #c8c8c8;
                    font-size: 14px;
                }
            """)

class StatusRow(QWidget):
    def __init__(self, label_text, tooltip="", parent=None):
        super().__init__(parent)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(10)
        
        self.label = QLabel(label_text)
        self.label.setToolTip(tooltip)
        self.indicator = StatusIndicator(tooltip=tooltip)
        
        layout.addWidget(self.label)
        layout.addStretch()
        layout.addWidget(self.indicator)
    
    def setState(self, state):
        self.indicator.setState(state)

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Bitcoin Wallet Tool: Generate and Verify XPUB/Addresses")
        self.setGeometry(100, 100, 1200, 800)  # Made window slightly wider
        
        # Set window flags for modern look
        self.setWindowFlags(Qt.Window | Qt.FramelessWindowHint)
        self.setAttribute(Qt.WA_TranslucentBackground)
        
        # Create main widget with rounded corners
        self.main_widget = QWidget()
        self.main_widget.setObjectName("mainWidget")
        self.main_widget.setStyleSheet("""
            QWidget#mainWidget {
                background-color: #1e1e1e;
                border-radius: 10px;
            }
        """)
        
        # Create title bar
        self.title_bar = QWidget()
        self.title_bar.setFixedHeight(40)
        self.title_bar.setStyleSheet("""
            QWidget {
                background-color: #2d2d2d;
                border-top-left-radius: 10px;
                border-top-right-radius: 10px;
            }
        """)
        
        # Title bar layout
        title_layout = QHBoxLayout(self.title_bar)
        title_layout.setContentsMargins(10, 0, 10, 0)
        
        # Window title
        title_label = QLabel("Bitcoin Wallet Tool")
        title_label.setStyleSheet("color: #c8c8c8; font-size: 14px;")
        
        # Window controls
        btn_size = 12
        btn_style = """
            QPushButton {
                border: none;
                border-radius: 6px;
                padding: 4px;
            }
            QPushButton:hover {
                background-color: #404040;
            }
        """
        
        self.minimize_btn = QPushButton("−")
        self.minimize_btn.setFixedSize(btn_size, btn_size)
        self.minimize_btn.setStyleSheet(btn_style)
        self.minimize_btn.clicked.connect(self.showMinimized)
        
        self.maximize_btn = QPushButton("□")
        self.maximize_btn.setFixedSize(btn_size, btn_size)
        self.maximize_btn.setStyleSheet(btn_style)
        self.maximize_btn.clicked.connect(self.toggle_maximize)
        
        self.close_btn = QPushButton("×")
        self.close_btn.setFixedSize(btn_size, btn_size)
        self.close_btn.setStyleSheet(btn_style + "QPushButton:hover { background-color: #e81123; color: white; }")
        self.close_btn.clicked.connect(self.close)
        
        title_layout.addWidget(title_label)
        title_layout.addStretch()
        title_layout.addWidget(self.minimize_btn)
        title_layout.addWidget(self.maximize_btn)
        title_layout.addWidget(self.close_btn)
        
        # Main layout
        main_layout = QVBoxLayout(self.main_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.addWidget(self.title_bar)
        
        # Create content widget
        content_widget = QWidget()
        content_layout = QVBoxLayout(content_widget)
        content_layout.setContentsMargins(20, 20, 20, 20)
        
        self.initUI()  # Initialize the rest of the UI
        content_layout.addWidget(self.tabs)
        
        main_layout.addWidget(content_widget)
        self.setCentralWidget(self.main_widget)
        
        # Enable window dragging
        self.title_bar.mousePressEvent = self.mousePressEvent
        self.title_bar.mouseMoveEvent = self.mouseMoveEvent
        
        # Shadow effect
        shadow = QtWidgets.QGraphicsDropShadowEffect()
        shadow.setBlurRadius(20)
        shadow.setColor(QColor(0, 0, 0, 100))
        shadow.setOffset(0, 0)
        self.main_widget.setGraphicsEffect(shadow)

        # Create loading overlay for the main window
        self.loading = LoadingOverlay(self)
        self.loading.resize(self.size())
        self.loading.hide()

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton:
            self.drag_pos = event.globalPos() - self.frameGeometry().topLeft()
            event.accept()

    def mouseMoveEvent(self, event):
        if event.buttons() == Qt.LeftButton:
            self.move(event.globalPos() - self.drag_pos)
            event.accept()

    def toggle_maximize(self):
        if self.isMaximized():
            self.showNormal()
        else:
            self.showMaximized()

    def initUI(self):
        # Create a QTabWidget for functionalities
        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)

        # Create tabs
        self.tab_generate = QWidget()
        self.tab_addresses = QWidget()
        self.tab_verification = QWidget()  # New verification tab

        # Setup each tab
        self.setup_generation_tab()
        self.setup_addresses_tab()
        self.setup_verification_tab()  # New setup method

        # Add tabs to widget
        self.tabs.addTab(self.tab_generate, "Generate Wallet")
        self.tabs.addTab(self.tab_addresses, "Generate Addresses")
        self.tabs.addTab(self.tab_verification, "Verify Keys")

    def setup_generation_tab(self):
        """Setup the wallet generation tab."""
        layout = QVBoxLayout()
        
        # Add the generation section
        generation_section = self.create_generation_section()
        layout.addWidget(generation_section)
        
        self.tab_generate.setLayout(layout)

    def setup_addresses_tab(self):
        """Setup the address generation tab."""
        layout = QVBoxLayout()
        
        # Add the input section
        input_section = self.create_input_section()
        layout.addWidget(input_section)
        
        # Add separator
        layout.addWidget(self.create_separator())
        
        # Add the output section
        output_section = self.create_output_section()
        layout.addWidget(output_section)
        
        self.tab_addresses.setLayout(layout)

    def setup_verification_tab(self):
        """Setup the verification tab with visual indicators for xpub and address verification."""
        layout = QVBoxLayout()
        layout.setSpacing(20)
        
        # XPUB Verification Section
        xpub_group = QGroupBox("XPUB Verification")
        xpub_layout = QVBoxLayout()
        xpub_layout.setSpacing(15)
        
        # XPUB Input and QR Code
        xpub_top_layout = QHBoxLayout()
        xpub_top_layout.setSpacing(20)
        
        # Input section
        xpub_input_section = QVBoxLayout()
        xpub_input_section.setSpacing(15)
        
        xpub_input_layout = QHBoxLayout()
        xpub_input_layout.setSpacing(10)
        self.verify_xpub_input = StyledLineEdit(
            placeholder="Enter XPUB to verify..."
        )
        
        # Button container for better alignment
        xpub_button_container = QWidget()
        xpub_button_layout = QHBoxLayout(xpub_button_container)
        xpub_button_layout.setSpacing(5)
        xpub_button_layout.setContentsMargins(0, 0, 0, 0)
        
        self.copy_xpub_button = StyledButton("📋", primary=False)
        self.copy_xpub_button.setFixedWidth(40)
        self.copy_xpub_button.clicked.connect(
            lambda: self.copy_to_clipboard(self.verify_xpub_input.text())
        )
        self.copy_xpub_button.setToolTip("Copy XPUB to clipboard")
        
        self.verify_xpub_button = StyledButton("Verify XPUB", primary=True)
        self.verify_xpub_button.clicked.connect(self.verify_xpub)
        self.verify_xpub_button.setToolTip("Verify the format and validity of the XPUB")
        
        xpub_button_layout.addWidget(self.copy_xpub_button)
        xpub_button_layout.addWidget(self.verify_xpub_button)
        
        xpub_input_layout.addWidget(self.verify_xpub_input)
        xpub_input_layout.addWidget(xpub_button_container)
        
        xpub_input_section.addLayout(xpub_input_layout)
        
        # XPUB Status Indicators
        self.xpub_status_rows = {}
        xpub_status_widget = QWidget()
        xpub_status_layout = QVBoxLayout(xpub_status_widget)
        xpub_status_layout.setSpacing(8)
        
        status_items = [
            ("format", "Format Valid", "Checks if the XPUB starts with xpub, ypub, or zpub"),
            ("version", "Version Bytes", "Validates the version bytes for the specific XPUB type"),
            ("length", "Key Length", "Verifies the XPUB has the correct length (78 bytes)"),
            ("checksum", "Checksum Valid", "Validates the Base58Check encoding checksum"),
            ("network", "Network Type", "Identifies if the XPUB is for Mainnet or Testnet")
        ]
        
        for key, label, tooltip in status_items:
            status_row = StatusRow(label, tooltip)
            self.xpub_status_rows[key] = status_row
            xpub_status_layout.addWidget(status_row)
        
        xpub_input_section.addWidget(xpub_status_widget)
        xpub_top_layout.addLayout(xpub_input_section)
        
        # QR Code section
        self.xpub_qr_label = QRCodeWidget()
        self.xpub_qr_label.setToolTip("QR code representation of the XPUB")
        xpub_top_layout.addWidget(self.xpub_qr_label)
        
        # XPUB Details
        self.xpub_details = StyledTextEdit()
        self.xpub_details.setReadOnly(True)
        self.xpub_details.setMaximumHeight(100)
        self.xpub_details.setToolTip("Detailed information about the XPUB")
        
        xpub_layout.addLayout(xpub_top_layout)
        xpub_layout.addWidget(QLabel("XPUB Details:"))
        xpub_layout.addWidget(self.xpub_details)
        xpub_group.setLayout(xpub_layout)
        
        # Address Verification Section
        addr_group = QGroupBox("Address Verification")
        addr_layout = QVBoxLayout()
        addr_layout.setSpacing(15)
        
        # Address Input and QR Code
        addr_top_layout = QHBoxLayout()
        addr_top_layout.setSpacing(20)
        
        # Input section
        addr_input_section = QVBoxLayout()
        addr_input_section.setSpacing(15)
        
        addr_input_layout = QHBoxLayout()
        addr_input_layout.setSpacing(10)
        self.verify_addr_input = StyledLineEdit(
            placeholder="Enter Bitcoin address to verify..."
        )
        
        # Button container
        addr_button_container = QWidget()
        addr_button_layout = QHBoxLayout(addr_button_container)
        addr_button_layout.setSpacing(5)
        addr_button_layout.setContentsMargins(0, 0, 0, 0)
        
        self.copy_addr_button = StyledButton("📋", primary=False)
        self.copy_addr_button.setFixedWidth(40)
        self.copy_addr_button.clicked.connect(
            lambda: self.copy_to_clipboard(self.verify_addr_input.text())
        )
        self.copy_addr_button.setToolTip("Copy address to clipboard")
        
        self.explorer_button = StyledButton("🔍", primary=False)
        self.explorer_button.setFixedWidth(40)
        self.explorer_button.clicked.connect(self.open_in_explorer)
        self.explorer_button.setToolTip("View address on blockchain explorer")
        
        self.verify_addr_button = StyledButton("Verify Address", primary=True)
        self.verify_addr_button.clicked.connect(self.verify_address)
        self.verify_addr_button.setToolTip("Verify the format and validity of the Bitcoin address")
        
        addr_button_layout.addWidget(self.copy_addr_button)
        addr_button_layout.addWidget(self.explorer_button)
        addr_button_layout.addWidget(self.verify_addr_button)
        
        addr_input_layout.addWidget(self.verify_addr_input)
        addr_input_layout.addWidget(addr_button_container)
        
        addr_input_section.addLayout(addr_input_layout)
        
        # Address Status Indicators
        self.addr_status_rows = {}
        addr_status_widget = QWidget()
        addr_status_layout = QVBoxLayout(addr_status_widget)
        addr_status_layout.setSpacing(8)
        
        addr_status_items = [
            ("format", "Address Format", "Checks if the address format is valid (starts with bc1, 1, or 3)"),
            ("type", "Address Type", "Identifies the address type (Legacy, SegWit, or Native SegWit)"),
            ("checksum", "Checksum Valid", "Validates the address checksum"),
            ("network", "Network Type", "Identifies if the address is for Mainnet or Testnet")
        ]
        
        for key, label, tooltip in addr_status_items:
            status_row = StatusRow(label, tooltip)
            self.addr_status_rows[key] = status_row
            addr_status_layout.addWidget(status_row)
        
        addr_input_section.addWidget(addr_status_widget)
        addr_top_layout.addLayout(addr_input_section)
        
        # QR Code section
        self.addr_qr_label = QRCodeWidget()
        self.addr_qr_label.setToolTip("QR code representation of the Bitcoin address")
        addr_top_layout.addWidget(self.addr_qr_label)
        
        # Address Details
        self.addr_details = StyledTextEdit()
        self.addr_details.setReadOnly(True)
        self.addr_details.setMaximumHeight(100)
        self.addr_details.setToolTip("Detailed information about the Bitcoin address")
        
        addr_layout.addLayout(addr_top_layout)
        addr_layout.addWidget(QLabel("Address Details:"))
        addr_layout.addWidget(self.addr_details)
        addr_group.setLayout(addr_layout)
        
        # Add both sections to main layout
        layout.addWidget(xpub_group)
        layout.addWidget(addr_group)
        layout.addStretch()
        
        self.tab_verification.setLayout(layout)

    def copy_to_clipboard(self, text):
        """Copy text to clipboard with visual feedback."""
        if text.strip():
            clipboard = QApplication.clipboard()
            clipboard.setText(text)
            
            # Show temporary success message
            msg = QMessageBox(self)
            msg.setIcon(QMessageBox.Information)
            msg.setText("Copied to clipboard!")
            msg.setWindowTitle("Success")
            msg.setStandardButtons(QMessageBox.NoButton)
            msg.show()
            
            # Auto-close after 1 second
            QTimer.singleShot(1000, msg.close)

    def open_in_explorer(self):
        """Open the Bitcoin address in a blockchain explorer."""
        address = self.verify_addr_input.text().strip()
        if address:
            # Use Blockstream explorer for both mainnet and testnet
            if address.startswith(('bc1', '1', '3')):
                url = f"https://blockstream.info/address/{address}"
            else:
                url = f"https://blockstream.info/testnet/address/{address}"
            webbrowser.open(url)
        else:
            QMessageBox.warning(self, "Error", "Please enter a Bitcoin address first.")

    def show_loading_indicator(self, widget):
        """Show a loading indicator on a widget."""
        widget.setEnabled(False)
        widget.setText("Verifying...")

    def hide_loading_indicator(self, widget, original_text):
        """Hide the loading indicator and restore original text."""
        widget.setEnabled(True)
        widget.setText(original_text)

    def verify_xpub(self):
        """Verify an XPUB and update visual indicators."""
        self.loading.show()
        
        xpub = self.verify_xpub_input.text().strip()
        
        # Clear QR code
        self.xpub_qr_label.clear()
        
        try:
            # Reset indicators
            for row in self.xpub_status_rows.values():
                row.setState("neutral")
            
            if not xpub:
                raise ValueError("Please enter an XPUB to verify")
            
            # Format check
            if xpub.startswith(('xpub', 'ypub', 'zpub')):
                self.xpub_status_rows["format"].setState("success")
                
                # Network/Version check
                if xpub.startswith('zpub'):
                    self.xpub_status_rows["version"].setState("success")
                    self.xpub_status_rows["network"].setState("success")
                elif xpub.startswith('xpub'):
                    self.xpub_status_rows["version"].setState("success")
                    self.xpub_status_rows["network"].setState("success")
            else:
                self.xpub_status_rows["format"].setState("error")
                raise ValueError("Invalid XPUB format")
            
            # Validate using bip_utils
            is_valid, error = validate_xpub(xpub)
            if is_valid:
                self.xpub_status_rows["checksum"].setState("success")
                self.xpub_status_rows["length"].setState("success")
                
                # Generate and display QR code
                self.xpub_qr_label.setQRCode(xpub)
                
                # Show detailed breakdown
                self.xpub_details.setPlainText(
                    f"XPUB Type: {'Native SegWit (BIP84)' if xpub.startswith('zpub') else 'Legacy (BIP44)'}\n"
                    f"Network: Mainnet\n"
                    f"Purpose: {'84h' if xpub.startswith('zpub') else '44h'}\n"
                    f"Coin Type: 0h (Bitcoin)\n"
                    f"Account: 0h"
                )
            else:
                raise ValueError(f"XPUB validation failed: {error}")
                
        except Exception as e:
            self.xpub_details.setPlainText(f"Error: {str(e)}")
            # Mark remaining indicators as failed
            for key, row in self.xpub_status_rows.items():
                if row.indicator.text() == "⚪":
                    row.setState("error")
        
        finally:
            self.loading.hide()

    def verify_address(self):
        """Verify a Bitcoin address and update visual indicators."""
        self.loading.show()
        
        address = self.verify_addr_input.text().strip()
        
        # Clear QR code
        self.addr_qr_label.clear()
        
        try:
            # Reset indicators
            for row in self.addr_status_rows.values():
                row.setState("neutral")
            
            if not address:
                raise ValueError("Please enter an address to verify")
            
            # Basic format check
            if address.startswith(('bc1', '1', '3')):
                self.addr_status_rows["format"].setState("success")
                
                # Determine address type
                if address.startswith('bc1'):
                    addr_type = "Native SegWit (P2WPKH)"
                    self.addr_status_rows["type"].setState("success")
                elif address.startswith('3'):
                    addr_type = "Nested SegWit (P2SH)"
                    self.addr_status_rows["type"].setState("success")
                else:
                    addr_type = "Legacy (P2PKH)"
                    self.addr_status_rows["type"].setState("success")
                
                # Network check (mainnet)
                self.addr_status_rows["network"].setState("success")
                
                # Validate checksum and format
                is_valid = validate_bitcoin_address(address, address.startswith('bc1'))
                if is_valid:
                    self.addr_status_rows["checksum"].setState("success")
                    
                    # Generate and display QR code
                    self.addr_qr_label.setQRCode(address)
                    
                    # Show detailed info
                    self.addr_details.setPlainText(
                        f"Address Type: {addr_type}\n"
                        f"Network: Mainnet\n"
                        f"Length: {len(address)} characters"
                    )
                else:
                    raise ValueError("Invalid address checksum")
            else:
                self.addr_status_rows["format"].setState("error")
                raise ValueError("Invalid address format")
                
        except Exception as e:
            self.addr_details.setPlainText(f"Error: {str(e)}")
            # Mark remaining indicators as failed
            for key, row in self.addr_status_rows.items():
                if row.indicator.text() == "⚪":
                    row.setState("error")
        
        finally:
            self.loading.hide()

    def create_separator(self):
        separator = QFrame()
        separator.setObjectName("separator")
        separator.setFrameShape(QFrame.HLine)
        separator.setFixedHeight(1)
        return separator

    def create_input_section(self):
        section = QWidget()
        layout = QVBoxLayout(section)
        layout.setSpacing(15)

        # Extended public key input
        self.xpub_label = QLabel("Extended Public Key (xpub / zpub):")
        self.xpub_input = StyledLineEdit(
            placeholder="Enter or generate an XPUB (xpub...) or ZPUB (zpub...)"
        )

        layout.addWidget(self.xpub_label)
        layout.addWidget(self.xpub_input)
        return section

    def create_generation_section(self):
        section = QWidget()
        layout = QVBoxLayout(section)
        layout.setSpacing(20)

        # Key type selection and generation
        key_type_layout = QHBoxLayout()
        key_type_layout.setSpacing(15)
        
        self.xpub_type_label = QLabel("Extended Key Type:")
        self.xpub_type_combo = StyledComboBox()
        self.xpub_type_combo.addItems(["zpub (BIP84)", "xpub (BIP44)"])
        
        self.gen_key_button = StyledButton(
            "Generate New Wallet (Mnemonic & xPub / zPub)",
            primary=True
        )
        self.gen_key_button.clicked.connect(self.generate_new_wallet)
        
        key_type_layout.addWidget(self.xpub_type_label)
        key_type_layout.addWidget(self.xpub_type_combo)
        key_type_layout.addWidget(self.gen_key_button)
        layout.addLayout(key_type_layout)

        # Mnemonic display
        self.mnemonic_label = QLabel("Mnemonic (seed words):")
        self.mnemonic_output = StyledTextEdit()
        self.mnemonic_output.setReadOnly(True)
        self.mnemonic_output.setMaximumHeight(100)
        layout.addWidget(self.mnemonic_label)
        layout.addWidget(self.mnemonic_output)

        # Generated xpub display
        self.generated_xpub_label = QLabel("Generated Extended Public Key:")
        self.generated_xpub_output = StyledLineEdit()
        self.generated_xpub_output.setReadOnly(True)
        layout.addWidget(self.generated_xpub_label)
        layout.addWidget(self.generated_xpub_output)

        return section

    def create_output_section(self):
        section = QWidget()
        layout = QVBoxLayout(section)
        layout.setSpacing(20)

        # Settings row
        settings_layout = QHBoxLayout()
        settings_layout.setSpacing(15)
        
        # Count input
        count_widget = QWidget()
        count_layout = QVBoxLayout(count_widget)
        count_layout.setSpacing(8)
        self.count_label = QLabel("Number of Addresses:")
        self.count_input = StyledSpinBox()
        self.count_input.setRange(1, 1000000)
        self.count_input.setValue(10)
        count_layout.addWidget(self.count_label)
        count_layout.addWidget(self.count_input)
        
        # Format selection
        format_widget = QWidget()
        format_layout = QVBoxLayout(format_widget)
        format_layout.setSpacing(8)
        self.format_label = QLabel("Output Format:")
        self.format_combo = StyledComboBox()
        self.format_combo.addItems(["CSV", "JSON", "Plain Text"])
        format_layout.addWidget(self.format_label)
        format_layout.addWidget(self.format_combo)

        settings_layout.addWidget(count_widget)
        settings_layout.addWidget(format_widget)
        layout.addLayout(settings_layout)

        # Action buttons
        button_layout = QHBoxLayout()
        button_layout.setSpacing(15)
        self.generate_button = StyledButton("Generate Addresses", primary=True)
        self.save_button = StyledButton("Save to File", primary=False)
        self.generate_button.clicked.connect(self.generate_addresses)
        self.save_button.clicked.connect(self.save_to_file)
        button_layout.addWidget(self.generate_button)
        button_layout.addWidget(self.save_button)
        layout.addLayout(button_layout)

        # Output area
        self.output_area = StyledTextEdit()
        self.output_area.setReadOnly(True)
        self.output_area.setMinimumHeight(200)
        layout.addWidget(self.output_area)

        return section

    def generate_new_wallet(self):
        """
        1. Generate a new random mnemonic.
        2. Derive a seed from that mnemonic.
        3. Depending on user's choice, derive an xpub (BIP44) or zpub (BIP84).
        4. Display the mnemonic and extended public key in the UI.
        """
        # 1. Generate a random 12-word mnemonic
        mnemonic = Bip39MnemonicGenerator().FromWordsNumber(Bip39WordsNum.WORDS_NUM_12)
        mnemonic_str = str(mnemonic)  # Updated to use str() instead of ToStr()
        
        # Validate the generated mnemonic
        is_valid, error = validate_mnemonic(mnemonic_str)
        if not is_valid:
            QMessageBox.critical(self, "Validation Error", error)
            return

        # 2. Generate the seed (no passphrase in this example)
        seed_bytes = Bip39SeedGenerator(mnemonic).Generate()

        # 3. Derive xpub or zpub
        selected_type = self.xpub_type_combo.currentText()
        if "xpub" in selected_type.lower():
            # Use BIP44 for standard xpub
            bip_obj = Bip44.FromSeed(seed_bytes, Bip44Coins.BITCOIN)
            # Get the account extended key (m/44'/0'/0')
            acct_obj = bip_obj.Purpose().Coin().Account(0)
            # Get the extended public key at account level
            xpub = acct_obj.PublicKey().ToExtended()
        else:
            # Use BIP84 for zpub (native SegWit)
            bip_obj = Bip84.FromSeed(seed_bytes, Bip84Coins.BITCOIN)
            # Get the account extended key (m/84'/0'/0')
            acct_obj = bip_obj.Purpose().Coin().Account(0)
            # Get the extended public key at account level
            xpub = acct_obj.PublicKey().ToExtended()

        # Validate the generated xpub/zpub
        is_valid, error = validate_xpub(xpub)
        if not is_valid:
            QMessageBox.critical(self, "Validation Error", error)
            return

        # 4. Display them
        self.mnemonic_output.setPlainText(mnemonic_str)
        self.generated_xpub_output.setText(xpub)
        # Also auto-fill the main xpub input for address generation
        self.xpub_input.setText(xpub)

    def generate_addresses(self):
        """
        Takes the user-supplied or newly-generated xpub/zpub, validates it,
        then generates the requested number of addresses.
        """
        xpub = self.xpub_input.text().strip()
        count = self.count_input.value()
        output_format = self.format_combo.currentText()

        if not xpub:
            QMessageBox.warning(self, "Input Error", "Please enter or generate a valid xPub/zPub.")
            return

        # Validate the input xpub/zpub
        is_valid, error = validate_xpub(xpub)
        if not is_valid:
            QMessageBox.critical(self, "Validation Error", error)
            return

        # Validate count
        if count <= 0 or count > 1000000:
            QMessageBox.warning(self, "Input Error", "Please enter a valid number of addresses (1-1,000,000).")
            return

        addresses = []
        try:
            # Determine if we're using BIP84 (zpub) or BIP44 (xpub)
            is_bip84 = xpub.startswith("zpub")
            
            try:
                if xpub.startswith("xpub"):
                    # BIP44 - Legacy addresses
                    account_ctx = Bip44.FromExtendedKey(xpub, Bip44Coins.BITCOIN)
                elif xpub.startswith("zpub"):
                    # BIP84 - Native SegWit addresses
                    account_ctx = Bip84.FromExtendedKey(xpub, Bip84Coins.BITCOIN)
                else:
                    raise ValueError("Unsupported extended key format. Must start with xpub or zpub.")
            except Exception as e:
                QMessageBox.critical(self, "Key Error", f"Error parsing extended key:\n{str(e)}")
                return

            # Get the external chain (receiving addresses)
            try:
                change_ctx = account_ctx.Change(Bip44Changes.CHAIN_EXT)
            except Exception as e:
                QMessageBox.critical(self, "Derivation Error", f"Error deriving change addresses:\n{str(e)}")
                return

            for i in range(count):
                try:
                    # Get the address at current index
                    addr_ctx = change_ctx.AddressIndex(i)
                    address = addr_ctx.PublicKey().ToAddress()
                    
                    # Validate the generated address
                    if not validate_bitcoin_address(address, is_bip84):
                        QMessageBox.critical(self, "Validation Error", 
                            f"Generated invalid address at index {i}:\n{address}")
                        return
                    
                    addresses.append({"index": i, "address": address})
                except Exception as e:
                    QMessageBox.critical(self, "Generation Error", 
                        f"Error generating address at index {i}:\n{str(e)}")
                    return

        except Exception as e:
            QMessageBox.critical(self, "Generation Error", f"Error generating addresses:\n{str(e)}")
            return

        # Format output based on user choice
        try:
            if output_format == "CSV":
                lines = ["index,address"]
                for entry in addresses:
                    lines.append(f"{entry['index']},{entry['address']}")
                output_text = "\n".join(lines)
            elif output_format == "JSON":
                output_text = json.dumps(addresses, indent=2)
            else:  # Plain Text
                lines = [f"{entry['index']}: {entry['address']}" for entry in addresses]
                output_text = "\n".join(lines)

            self.output_area.setPlainText(output_text)
        except Exception as e:
            QMessageBox.critical(self, "Output Error", f"Error formatting output:\n{str(e)}")

    def save_to_file(self):
        """
        Saves the content of output_area to a file.
        """
        text = self.output_area.toPlainText()
        if not text:
            QMessageBox.warning(self, "No Data", "There is no data to save. Please generate addresses first.")
            return

        options = QFileDialog.Options()
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Save Output",
            "",
            "All Files (*);;Text Files (*.txt)",
            options=options
        )
        if file_path:
            try:
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(text)
                QMessageBox.information(self, "File Saved", f"Output successfully saved to:\n{file_path}")
            except Exception as e:
                QMessageBox.critical(self, "Save Error", f"Error saving file:\n{str(e)}")

    def resizeEvent(self, event):
        super().resizeEvent(event)
        if hasattr(self, 'loading'):
            self.loading.resize(self.size())

if __name__ == "__main__":
    app = QApplication(sys.argv)
    setup_theme(app)  # Apply the modern theme
    
    # Set modern font
    font = app.font()
    font.setFamily("Segoe UI")  # Modern system font
    app.setFont(font)
    
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())
