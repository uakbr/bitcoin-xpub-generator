import sys
import json
import os
import secrets
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

class CollapsibleSection(QWidget):
    def __init__(self, title, parent=None):
        super().__init__(parent)
        self.animation = None
        self.is_collapsed = True
        
        layout = QVBoxLayout(self)
        layout.setSpacing(0)
        layout.setContentsMargins(0, 0, 0, 0)
        
        # Header button
        self.toggle_button = QPushButton(title)
        self.toggle_button.setStyleSheet("""
            QPushButton {
                text-align: left;
                padding: 12px;
                background-color: #2d2d2d;
                border: none;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #353535;
            }
        """)
        self.toggle_button.clicked.connect(self.toggle_collapse)
        
        # Content
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
        self.setStyleSheet("background-color: #2d2d2d; border-radius: 8px;")
    
    def setQRCode(self, data):
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

class CompactWalletTool(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Mobile Wallet Tool")
        self.setMinimumWidth(320)  # Minimum width for mobile
        self.setup_ui()
    
    def setup_ui(self):
        # Main widget and layout
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        layout = QVBoxLayout(main_widget)
        layout.setSpacing(8)
        layout.setContentsMargins(8, 8, 8, 8)
        
        # Key Type Selection
        key_type_layout = QHBoxLayout()
        key_type_label = QLabel("Key Type:")
        self.key_type_combo = QComboBox()
        self.key_type_combo.addItem("zpub (BIP84)")
        self.key_type_combo.setStyleSheet("""
            QComboBox {
                padding: 8px;
                background-color: #353535;
                border: 1px solid #454545;
                border-radius: 4px;
                color: #c8c8c8;
            }
        """)
        key_type_layout.addWidget(key_type_label)
        key_type_layout.addWidget(self.key_type_combo)
        layout.addLayout(key_type_layout)
        
        # Generate Button
        self.generate_btn = QPushButton("Generate New Wallet")
        self.generate_btn.setStyleSheet("""
            QPushButton {
                padding: 12px;
                background-color: #2a82da;
                color: white;
                border: none;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #3a92ea;
            }
        """)
        self.generate_btn.clicked.connect(self.generate_wallet)
        layout.addWidget(self.generate_btn)
        
        # Collapsible Sections
        # Mnemonic Section
        self.mnemonic_section = CollapsibleSection("Mnemonic Seed")
        self.mnemonic_text = QTextEdit()
        self.mnemonic_text.setReadOnly(True)
        self.mnemonic_text.setMaximumHeight(80)
        self.mnemonic_text.setStyleSheet("""
            QTextEdit {
                background-color: #353535;
                border: 1px solid #454545;
                border-radius: 4px;
                color: #c8c8c8;
                padding: 8px;
            }
        """)
        self.mnemonic_section.add_widget(self.mnemonic_text)
        layout.addWidget(self.mnemonic_section)
        
        # Extended Public Key Section
        self.xpub_section = CollapsibleSection("Extended Public Key")
        self.xpub_text = QTextEdit()
        self.xpub_text.setReadOnly(True)
        self.xpub_text.setMaximumHeight(60)
        self.xpub_text.setStyleSheet("""
            QTextEdit {
                background-color: #353535;
                border: 1px solid #454545;
                border-radius: 4px;
                color: #c8c8c8;
                padding: 8px;
            }
        """)
        self.xpub_section.add_widget(self.xpub_text)
        layout.addWidget(self.xpub_section)
        
        # QR Code Section
        self.qr_section = CollapsibleSection("QR Code")
        self.qr_widget = CompactQRWidget()
        self.qr_section.add_widget(self.qr_widget)
        layout.addWidget(self.qr_section)
        
        # Add stretching space at the bottom
        layout.addStretch()
        
        # Apply dark theme
        self.setup_theme()
    
    def setup_theme(self):
        self.setStyleSheet("""
            QMainWindow {
                background-color: #1e1e1e;
            }
            QLabel {
                color: #c8c8c8;
            }
            QWidget {
                color: #c8c8c8;
            }
        """)
    
    def generate_wallet(self):
        # Generate mnemonic
        mnemonic = Bip39MnemonicGenerator().FromWordsNumber(Bip39WordsNum.WORDS_NUM_12)
        seed = Bip39SeedGenerator(mnemonic).Generate()
        
        # Generate BIP84 master key (for native SegWit)
        bip84_ctx = Bip84.FromSeed(seed, Bip84Coins.BITCOIN)
        
        # Get extended public key (zpub)
        zpub = bip84_ctx.PublicKey().ToExtended()
        
        # Update UI
        self.mnemonic_text.setText(" ".join(mnemonic.ToList()))
        self.xpub_text.setText(zpub)
        self.qr_widget.setQRCode(zpub)
        
        # Expand sections
        if self.mnemonic_section.is_collapsed:
            self.mnemonic_section.toggle_collapse()
        if self.xpub_section.is_collapsed:
            self.xpub_section.toggle_collapse()
        if self.qr_section.is_collapsed:
            self.qr_section.toggle_collapse()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = CompactWalletTool()
    window.show()
    sys.exit(app.exec_()) 