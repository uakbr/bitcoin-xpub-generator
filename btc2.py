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
from PyQt5.QtGui import QPixmap, QImage
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
    """Generate a QR code for the given data."""
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(data)
    qr.make(fit=True)
    
    # Create PIL image
    img = qr.make_image(fill_color="black", back_color="white")
    
    # Convert PIL image to bytes
    img_byte_array = BytesIO()
    img.save(img_byte_array, format='PNG')
    img_byte_array = img_byte_array.getvalue()
    
    # Convert to QImage
    qimage = QImage()
    qimage.loadFromData(img_byte_array)
    
    # Convert to QPixmap and resize
    pixmap = QPixmap.fromImage(qimage)
    pixmap = pixmap.scaled(size, size, Qt.KeepAspectRatio, Qt.SmoothTransformation)
    
    return pixmap

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Bitcoin Wallet Tool: Generate and Verify XPUB/Addresses")
        self.setGeometry(100, 100, 1000, 800)
        self.initUI()

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
        
        # XPUB Verification Section
        xpub_group = QGroupBox("XPUB Verification")
        xpub_layout = QVBoxLayout()
        
        # XPUB Input and QR Code
        xpub_top_layout = QHBoxLayout()
        
        # Input section
        xpub_input_section = QVBoxLayout()
        xpub_input_layout = QHBoxLayout()
        self.verify_xpub_input = QLineEdit()
        self.verify_xpub_input.setPlaceholderText("Enter XPUB to verify...")
        self.verify_xpub_button = QPushButton("Verify XPUB")
        self.verify_xpub_button.clicked.connect(self.verify_xpub)
        self.verify_xpub_button.setToolTip("Verify the format and validity of the XPUB")
        
        # Copy XPUB button
        self.copy_xpub_button = QPushButton("📋")
        self.copy_xpub_button.setFixedWidth(30)
        self.copy_xpub_button.clicked.connect(lambda: self.copy_to_clipboard(self.verify_xpub_input.text()))
        self.copy_xpub_button.setToolTip("Copy XPUB to clipboard")
        
        xpub_input_layout.addWidget(self.verify_xpub_input)
        xpub_input_layout.addWidget(self.copy_xpub_button)
        xpub_input_layout.addWidget(self.verify_xpub_button)
        
        # XPUB Status Indicators with tooltips
        self.xpub_status_layout = QGridLayout()
        self.xpub_indicators = {}
        
        indicators = [
            ("format", "Format Valid", "Checks if the XPUB starts with xpub, ypub, or zpub"),
            ("version", "Version Bytes", "Validates the version bytes for the specific XPUB type"),
            ("length", "Key Length", "Verifies the XPUB has the correct length (78 bytes)"),
            ("checksum", "Checksum Valid", "Validates the Base58Check encoding checksum"),
            ("network", "Network Type", "Identifies if the XPUB is for Mainnet or Testnet")
        ]
        
        for row, (key, label, tooltip) in enumerate(indicators):
            status_label = QLabel(label)
            status_label.setToolTip(tooltip)
            status_indicator = QLabel("⚪")
            status_indicator.setToolTip(tooltip)
            self.xpub_indicators[key] = status_indicator
            self.xpub_status_layout.addWidget(status_label, row, 0)
            self.xpub_status_layout.addWidget(status_indicator, row, 1)
        
        xpub_input_section.addLayout(xpub_input_layout)
        xpub_input_section.addLayout(self.xpub_status_layout)
        xpub_top_layout.addLayout(xpub_input_section)
        
        # QR Code section
        self.xpub_qr_label = QLabel()
        self.xpub_qr_label.setFixedSize(200, 200)
        self.xpub_qr_label.setAlignment(Qt.AlignCenter)
        self.xpub_qr_label.setToolTip("QR code representation of the XPUB")
        xpub_top_layout.addWidget(self.xpub_qr_label)
        
        # XPUB Details
        self.xpub_details = QTextEdit()
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
        
        # Address Input and QR Code
        addr_top_layout = QHBoxLayout()
        
        # Input section
        addr_input_section = QVBoxLayout()
        addr_input_layout = QHBoxLayout()
        self.verify_addr_input = QLineEdit()
        self.verify_addr_input.setPlaceholderText("Enter Bitcoin address to verify...")
        self.verify_addr_button = QPushButton("Verify Address")
        self.verify_addr_button.clicked.connect(self.verify_address)
        self.verify_addr_button.setToolTip("Verify the format and validity of the Bitcoin address")
        
        # Copy address button
        self.copy_addr_button = QPushButton("📋")
        self.copy_addr_button.setFixedWidth(30)
        self.copy_addr_button.clicked.connect(lambda: self.copy_to_clipboard(self.verify_addr_input.text()))
        self.copy_addr_button.setToolTip("Copy address to clipboard")
        
        # Blockchain explorer button
        self.explorer_button = QPushButton("🔍")
        self.explorer_button.setFixedWidth(30)
        self.explorer_button.clicked.connect(self.open_in_explorer)
        self.explorer_button.setToolTip("View address on blockchain explorer")
        
        addr_input_layout.addWidget(self.verify_addr_input)
        addr_input_layout.addWidget(self.copy_addr_button)
        addr_input_layout.addWidget(self.explorer_button)
        addr_input_layout.addWidget(self.verify_addr_button)
        
        # Address Status Indicators with tooltips
        self.addr_status_layout = QGridLayout()
        self.addr_indicators = {}
        
        addr_indicators = [
            ("format", "Address Format", "Checks if the address format is valid (starts with bc1, 1, or 3)"),
            ("type", "Address Type", "Identifies the address type (Legacy, SegWit, or Native SegWit)"),
            ("checksum", "Checksum Valid", "Validates the address checksum"),
            ("network", "Network Type", "Identifies if the address is for Mainnet or Testnet")
        ]
        
        for row, (key, label, tooltip) in enumerate(addr_indicators):
            status_label = QLabel(label)
            status_label.setToolTip(tooltip)
            status_indicator = QLabel("⚪")
            status_indicator.setToolTip(tooltip)
            self.addr_indicators[key] = status_indicator
            self.addr_status_layout.addWidget(status_label, row, 0)
            self.addr_status_layout.addWidget(status_indicator, row, 1)
        
        addr_input_section.addLayout(addr_input_layout)
        addr_input_section.addLayout(self.addr_status_layout)
        addr_top_layout.addLayout(addr_input_section)
        
        # QR Code section
        self.addr_qr_label = QLabel()
        self.addr_qr_label.setFixedSize(200, 200)
        self.addr_qr_label.setAlignment(Qt.AlignCenter)
        self.addr_qr_label.setToolTip("QR code representation of the Bitcoin address")
        addr_top_layout.addWidget(self.addr_qr_label)
        
        # Address Details
        self.addr_details = QTextEdit()
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
        # Show loading indicator
        self.show_loading_indicator(self.verify_xpub_button)
        
        xpub = self.verify_xpub_input.text().strip()
        
        # Clear QR code
        self.xpub_qr_label.clear()
        
        try:
            # Reset indicators
            for indicator in self.xpub_indicators.values():
                indicator.setText("⚪")
                indicator.setStyleSheet("color: gray;")
            
            if not xpub:
                raise ValueError("Please enter an XPUB to verify")
            
            # Format check
            if xpub.startswith(('xpub', 'ypub', 'zpub')):
                self.xpub_indicators["format"].setText("✓")
                self.xpub_indicators["format"].setStyleSheet("color: green;")
                
                # Network/Version check
                if xpub.startswith('zpub'):
                    self.xpub_indicators["version"].setText("✓")
                    self.xpub_indicators["version"].setStyleSheet("color: green;")
                    self.xpub_indicators["network"].setText("Mainnet (Native SegWit)")
                    self.xpub_indicators["network"].setStyleSheet("color: green;")
                elif xpub.startswith('xpub'):
                    self.xpub_indicators["version"].setText("✓")
                    self.xpub_indicators["version"].setStyleSheet("color: green;")
                    self.xpub_indicators["network"].setText("Mainnet (Legacy)")
                    self.xpub_indicators["network"].setStyleSheet("color: green;")
            else:
                self.xpub_indicators["format"].setText("✗")
                self.xpub_indicators["format"].setStyleSheet("color: red;")
                raise ValueError("Invalid XPUB format")
            
            # Validate using bip_utils
            is_valid, error = validate_xpub(xpub)
            if is_valid:
                self.xpub_indicators["checksum"].setText("✓")
                self.xpub_indicators["checksum"].setStyleSheet("color: green;")
                self.xpub_indicators["length"].setText("✓")
                self.xpub_indicators["length"].setStyleSheet("color: green;")
                
                # Generate and display QR code
                qr_pixmap = generate_qr_code(xpub)
                self.xpub_qr_label.setPixmap(qr_pixmap)
                
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
            for key, indicator in self.xpub_indicators.items():
                if indicator.text() == "⚪":
                    indicator.setText("✗")
                    indicator.setStyleSheet("color: red;")
        
        finally:
            # Hide loading indicator
            self.hide_loading_indicator(self.verify_xpub_button, "Verify XPUB")

    def verify_address(self):
        """Verify a Bitcoin address and update visual indicators."""
        # Show loading indicator
        self.show_loading_indicator(self.verify_addr_button)
        
        address = self.verify_addr_input.text().strip()
        
        # Clear QR code
        self.addr_qr_label.clear()
        
        try:
            # Reset indicators
            for indicator in self.addr_indicators.values():
                indicator.setText("⚪")
                indicator.setStyleSheet("color: gray;")
            
            if not address:
                raise ValueError("Please enter an address to verify")
            
            # Basic format check
            if address.startswith(('bc1', '1', '3')):
                self.addr_indicators["format"].setText("✓")
                self.addr_indicators["format"].setStyleSheet("color: green;")
                
                # Determine address type
                if address.startswith('bc1'):
                    addr_type = "Native SegWit (P2WPKH)"
                    self.addr_indicators["type"].setText("Native SegWit")
                elif address.startswith('3'):
                    addr_type = "Nested SegWit (P2SH)"
                    self.addr_indicators["type"].setText("Nested SegWit")
                else:
                    addr_type = "Legacy (P2PKH)"
                    self.addr_indicators["type"].setText("Legacy")
                self.addr_indicators["type"].setStyleSheet("color: green;")
                
                # Network check (mainnet)
                self.addr_indicators["network"].setText("Mainnet")
                self.addr_indicators["network"].setStyleSheet("color: green;")
                
                # Validate checksum and format
                is_valid = validate_bitcoin_address(address, address.startswith('bc1'))
                if is_valid:
                    self.addr_indicators["checksum"].setText("✓")
                    self.addr_indicators["checksum"].setStyleSheet("color: green;")
                    
                    # Generate and display QR code
                    qr_pixmap = generate_qr_code(address)
                    self.addr_qr_label.setPixmap(qr_pixmap)
                    
                    # Show detailed info
                    self.addr_details.setPlainText(
                        f"Address Type: {addr_type}\n"
                        f"Network: Mainnet\n"
                        f"Length: {len(address)} characters"
                    )
                else:
                    raise ValueError("Invalid address checksum")
            else:
                self.addr_indicators["format"].setText("✗")
                self.addr_indicators["format"].setStyleSheet("color: red;")
                raise ValueError("Invalid address format")
                
        except Exception as e:
            self.addr_details.setPlainText(f"Error: {str(e)}")
            # Mark remaining indicators as failed
            for key, indicator in self.addr_indicators.items():
                if indicator.text() == "⚪":
                    indicator.setText("✗")
                    indicator.setStyleSheet("color: red;")
        
        finally:
            # Hide loading indicator
            self.hide_loading_indicator(self.verify_addr_button, "Verify Address")

    def create_separator(self):
        separator = QFrame()
        separator.setObjectName("separator")
        separator.setFrameShape(QFrame.HLine)
        separator.setFixedHeight(1)
        return separator

    def create_input_section(self):
        section = QWidget()
        layout = QVBoxLayout(section)
        layout.setSpacing(10)

        # Extended public key input
        self.xpub_label = QLabel("Extended Public Key (xpub / zpub):")
        self.xpub_input = QLineEdit()
        self.xpub_input.setPlaceholderText("Enter or generate an XPUB (xpub...) or ZPUB (zpub...)")
        self.xpub_input.setMinimumHeight(35)

        layout.addWidget(self.xpub_label)
        layout.addWidget(self.xpub_input)
        return section

    def create_generation_section(self):
        section = QWidget()
        layout = QVBoxLayout(section)
        layout.setSpacing(15)

        # Key type selection and generation
        key_type_layout = QHBoxLayout()
        self.xpub_type_label = QLabel("Extended Key Type:")
        self.xpub_type_combo = QComboBox()
        self.xpub_type_combo.addItems(["zpub (BIP84)", "xpub (BIP44)"])
        self.xpub_type_combo.setMinimumHeight(35)
        self.gen_key_button = QPushButton("Generate New Wallet (Mnemonic & xPub / zPub)")
        self.gen_key_button.setMinimumHeight(35)
        self.gen_key_button.clicked.connect(self.generate_new_wallet)
        
        key_type_layout.addWidget(self.xpub_type_label)
        key_type_layout.addWidget(self.xpub_type_combo)
        key_type_layout.addWidget(self.gen_key_button)
        layout.addLayout(key_type_layout)

        # Mnemonic display
        self.mnemonic_label = QLabel("Mnemonic (seed words):")
        self.mnemonic_output = QTextEdit()
        self.mnemonic_output.setReadOnly(True)
        self.mnemonic_output.setStyleSheet("font-family: 'Courier New', monospace; font-size: 14pt;")
        self.mnemonic_output.setMaximumHeight(100)
        layout.addWidget(self.mnemonic_label)
        layout.addWidget(self.mnemonic_output)

        # Generated xpub display
        self.generated_xpub_label = QLabel("Generated Extended Public Key:")
        self.generated_xpub_output = QLineEdit()
        self.generated_xpub_output.setReadOnly(True)
        self.generated_xpub_output.setMinimumHeight(35)
        layout.addWidget(self.generated_xpub_label)
        layout.addWidget(self.generated_xpub_output)

        return section

    def create_output_section(self):
        section = QWidget()
        layout = QVBoxLayout(section)
        layout.setSpacing(15)

        # Settings row
        settings_layout = QHBoxLayout()
        
        # Count input
        count_widget = QWidget()
        count_layout = QVBoxLayout(count_widget)
        self.count_label = QLabel("Number of Addresses:")
        self.count_input = QSpinBox()
        self.count_input.setRange(1, 1000000)
        self.count_input.setValue(10)
        self.count_input.setMinimumHeight(35)
        count_layout.addWidget(self.count_label)
        count_layout.addWidget(self.count_input)
        
        # Format selection
        format_widget = QWidget()
        format_layout = QVBoxLayout(format_widget)
        self.format_label = QLabel("Output Format:")
        self.format_combo = QComboBox()
        self.format_combo.addItems(["CSV", "JSON", "Plain Text"])
        self.format_combo.setMinimumHeight(35)
        format_layout.addWidget(self.format_label)
        format_layout.addWidget(self.format_combo)

        settings_layout.addWidget(count_widget)
        settings_layout.addWidget(format_widget)
        layout.addLayout(settings_layout)

        # Action buttons
        button_layout = QHBoxLayout()
        self.generate_button = QPushButton("Generate Addresses")
        self.save_button = QPushButton("Save to File")
        self.generate_button.setMinimumHeight(35)
        self.save_button.setMinimumHeight(35)
        self.generate_button.clicked.connect(self.generate_addresses)
        self.save_button.clicked.connect(self.save_to_file)
        button_layout.addWidget(self.generate_button)
        button_layout.addWidget(self.save_button)
        layout.addLayout(button_layout)

        # Output area
        self.output_area = QTextEdit()
        self.output_area.setReadOnly(True)
        self.output_area.setStyleSheet("font-family: 'Courier New', monospace; font-size: 12pt;")
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


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())
