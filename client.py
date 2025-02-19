import sys
import json
import socket
import threading
from tkinter.ttk import Label
import hashlib
import requests
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QStackedWidget,
    QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton,
    QTextEdit, QMessageBox, QFormLayout, QListWidget, QListWidgetItem, QDialog, QRadioButton, QCheckBox, QStyle,
    QComboBox
)
from PyQt6.QtCore import pyqtSignal, QObject, Qt
from PyQt6.QtGui import QFont
from urllib3 import request

API_URL = "http://127.0.0.1:5000/get_available_specs"
FILTER_URL = "http://127.0.0.1:5000/get_laptops"


# -----------------------
# Client Communication Class
# -----------------------
class Client(QObject):
    response_received = pyqtSignal(dict)

    def __init__(self, host='127.0.0.1', port=5554):
        super().__init__()
        self.host = host
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((host, port))
        threading.Thread(target=self.listen_for_messages, daemon=True).start()

    def listen_for_messages(self):
        while True:
            try:
                data = self.sock.recv(4096)
                if not data:
                    break
                response = json.loads(data.decode('utf-8'))
                self.response_received.emit(response)
            except Exception as e:
                print("Error receiving data:", e)
                break

    def send_request(self, request):
        try:
            request_json = json.dumps(request)
            self.sock.send(request_json.encode('utf-8'))
        except Exception as e:
            print("Error sending request:", e)


# -----------------------
# Login Page
# -----------------------
class LoginPage(QWidget):
    login_signal = pyqtSignal(str, str)
    register_signal = pyqtSignal(str, str)

    def __init__(self):
        super().__init__()
        layout = QVBoxLayout()
        header = QLabel("Welcome to Marketplace")
        header.setAlignment(Qt.AlignmentFlag.AlignCenter)
        header.setFont(QFont("Segoe UI", 24, QFont.Weight.Bold))
        layout.addWidget(header)

        form_layout = QFormLayout()
        self.username_edit = QLineEdit()
        self.username_edit.setPlaceholderText("Enter your username")
        self.password_edit = QLineEdit()
        self.password_edit.setPlaceholderText("Enter your password")
        self.password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        form_layout.addRow("Username:", self.username_edit)
        form_layout.addRow("Password:", self.password_edit)
        layout.addLayout(form_layout)

        btn_layout = QHBoxLayout()
        self.login_btn = QPushButton("Login")
        self.register_btn = QPushButton("Register")
        btn_layout.addWidget(self.login_btn)
        btn_layout.addWidget(self.register_btn)
        layout.addLayout(btn_layout)

        self.setLayout(layout)

        self.login_btn.clicked.connect(self.on_login)
        self.register_btn.clicked.connect(self.on_register)

    def on_login(self):
        username = self.username_edit.text().strip()
        password = self.password_edit.text().strip()
        if username and password:
            self.login_signal.emit(username, self.hash_text(password))
        else:
            QMessageBox.warning(self, "Error", "Please enter username and password.")

    def on_register(self):
        username = self.username_edit.text().strip()
        password = self.password_edit.text().strip()
        if username and password:
            self.register_signal.emit(username, self.hash_text(password))
        else:
            QMessageBox.warning(self, "Error", "Please enter username and password.")

    def hash_text(self,text):
        # Create a SHA-256 hash object
        hash_object = hashlib.sha256()
        # Convert the password to bytes and hash it
        hash_object.update(text.encode())
        # Get the hex digest of the hash
        output = hash_object.hexdigest()
        return output

# -----------------------
# Marketplace Page
# -----------------------
class MarketplacePage(QWidget):
    upload_signal = pyqtSignal(str, str, float)
    list_signal = pyqtSignal()
    goto_chat_signal = pyqtSignal()
    listing_clicked = pyqtSignal(dict)

    def __init__(self, client, current_user):
        super().__init__()
        self.client = client
        self.current_user = current_user

        layout = QVBoxLayout()
        form_layout = QFormLayout()
        self.title_edit = QLineEdit()
        self.title_edit.setPlaceholderText("Product title")
        self.desc_edit = QLineEdit()
        self.desc_edit.setPlaceholderText("Product description")
        self.price_edit = QLineEdit()
        self.price_edit.setPlaceholderText("Product price")
        form_layout.addRow("Title:", self.title_edit)
        form_layout.addRow("Description:", self.desc_edit)
        form_layout.addRow("Price:", self.price_edit)
        layout.addLayout(form_layout)
        specs_layout = QHBoxLayout()
        self.custombuilt_btn = QPushButton("add custom specs")
        self.prebuilt_btn = QPushButton("select pre-built spec")
        specs_layout.addWidget(self.custombuilt_btn)
        specs_layout.addWidget(self.prebuilt_btn)
        layout.addLayout(specs_layout)
        self.prebuilt_btn.clicked.connect(self.select_prebuilt_specs)
        self.custombuilt_btn.clicked.connect(self.select_custom_specs)
        self.list_btn = QPushButton("Refresh Listings")
        layout.addWidget(self.list_btn)
        self.list_btn.clicked.connect(lambda: self.list_signal.emit())
        self.products_list = QListWidget()
        self.products_list.setWordWrap(True)
        layout.addWidget(self.products_list)
        self.products_list.itemDoubleClicked.connect(self.on_item_double_clicked)
        self.goto_chat_btn = QPushButton("Go to Chat")
        layout.addWidget(self.goto_chat_btn)
        self.goto_chat_btn.clicked.connect(lambda: self.goto_chat_signal.emit())
        self.setLayout(layout)

    def select_prebuilt_specs(self):
        select_prebuilt_specs_dlg = Prebuilt(self.client, self.current_user, self.title_edit.text().strip(),
                                             self.desc_edit.text().strip(), float(self.price_edit.text().strip() if self.price_edit.text().strip() != '' else 0))
        select_prebuilt_specs_dlg.exec()

    def select_custom_specs(self):
        select_custom_specs_dlg = CustomSpecs(self.client, self.current_user, self.title_edit.text().strip(),
                                              self.desc_edit.text().strip(), float(self.price_edit.text().strip() if self.price_edit.text().strip() != '' else 0))
        select_custom_specs_dlg.exec()

    # def on_upload(self):
    #     title = self.title_edit.text().strip()
    #     desc = self.desc_edit.text().strip()
    #     price_text = self.price_edit.text().strip()
    #     if title and price_text:
    #         try:
    #             price = float(price_text)
    #         except ValueError:
    #             QMessageBox.warning(self, "Error", "Price must be a number.")
    #             return
    #         self.upload_signal.emit(title, desc, price)
    #     else:
    #         QMessageBox.warning(self, "Error", "Please fill in title and price.")

    def update_products(self, products):
        self.products_list.clear()
        for prod in products:
            display_text = (
                f"Title: {prod['title']}\n"
                f"Price: ${prod['price']}\n"
                f"CPU: {prod.get('cpu', 'N/A')}\n"
                f"RAM: {prod.get('ram', 'N/A')} GB\n"
                f"GPU: {prod.get('gpu', 'N/A')}"
            )
            item = QListWidgetItem(display_text)
            item.setData(Qt.ItemDataRole.UserRole, prod)
            self.products_list.addItem(item)

        self.products_list.itemDoubleClicked.connect(self.show_product_details)

    def show_product_details(self, item):
        prod = item.data(Qt.ItemDataRole.UserRole)
        details_text = (
            f"Title: {prod['title']}\n"
            f"Description: {prod.get('description', 'N/A')}\n"
            f"Price: ${prod['price']}\n"
            f"Seller: {prod['seller']}\n"
            f"Brand: {prod.get('brand', 'N/A')}\n"
            f"CPU: {prod.get('cpu', 'N/A')}\n"
            f"RAM: {prod.get('ram', 'N/A')} GB\n"
            f"Storage: {prod.get('storage', 'N/A')} GB\n"
            f"GPU: {prod.get('gpu', 'N/A')}\n"
            f"Monitor Size: {prod.get('monitor_size', 'N/A')} inches\n"
            f"Refresh Rate: {prod.get('refresh_rate', 'N/A')} Hz\n"
            f"Resolution: {prod.get('resolution', 'N/A')}"
        )
        QMessageBox.information(self, "Product Details", details_text)

    def on_item_double_clicked(self, item):
        product = item.data(Qt.ItemDataRole.UserRole)
        self.listing_clicked.emit(product)


# -----------------------
# Chat Page
# -----------------------
class ChatPage(QWidget):
    send_chat_signal = pyqtSignal(str, str)
    back_signal = pyqtSignal()

    def __init__(self):
        super().__init__()
        layout = QVBoxLayout()
        header = QLabel("Chat")
        header.setFont(QFont("Segoe UI", 20, QFont.Weight.Bold))
        header.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(header)

        self.chat_display = QTextEdit()
        self.chat_display.setReadOnly(True)
        layout.addWidget(self.chat_display)
        form_layout = QFormLayout()
        self.recipient_edit = QLineEdit()
        self.recipient_edit.setPlaceholderText("Recipient username")
        self.message_edit = QLineEdit()
        self.message_edit.setPlaceholderText("Type your message here")
        form_layout.addRow("Recipient:", self.recipient_edit)
        form_layout.addRow("Message:", self.message_edit)
        layout.addLayout(form_layout)
        btn_layout = QHBoxLayout()
        self.send_btn = QPushButton("Send")
        self.back_btn = QPushButton("Back to Marketplace")
        btn_layout.addWidget(self.send_btn)
        btn_layout.addWidget(self.back_btn)
        layout.addLayout(btn_layout)
        self.send_btn.clicked.connect(self.on_send)
        self.back_btn.clicked.connect(lambda: self.back_signal.emit())
        self.setLayout(layout)

    def on_send(self):
        recipient = self.recipient_edit.text().strip()
        message = self.message_edit.text().strip()
        if recipient and message:
            self.send_chat_signal.emit(recipient, message)
            self.chat_display.append(f"You -> {recipient}: {message}")
            self.message_edit.clear()
        else:
            QMessageBox.warning(self, "Error", "Please enter both recipient and message.")

    def display_chat_message(self, sender, message):
        self.chat_display.append(f"{sender}: {message}")


# -----------------------
# Main Window
# -----------------------
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Marketplace")
        self.client = Client()
        self.current_user = None

        # Apply a dark theme style sheet
        self.setStyleSheet("""
            QWidget {
                font-family: 'Segoe UI';
                font-size: 14pt;
                background-color: #121212;
                color: #dcdcdc;
            }
            QMainWindow {
                background-color: #121212;
            }
            QPushButton {
                background-color: #1f1f1f;
                color: #dcdcdc;
                border: 1px solid #333;
                padding: 8px;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #333333;
            }
            QLineEdit, QTextEdit, QListWidget {
                background-color: #1f1f1f;
                color: #dcdcdc;
                border: 1px solid #333;
                border-radius: 4px;
                padding: 4px;
            }
            QLabel {
                color: #dcdcdc;
            }
        """)

        self.stacked_widget = QStackedWidget()
        self.setCentralWidget(self.stacked_widget)

        self.login_page = LoginPage()
        self.market_page = MarketplacePage(self.client,self.current_user)
        self.chat_page = ChatPage()

        self.stacked_widget.addWidget(self.login_page)
        self.stacked_widget.addWidget(self.market_page)
        self.stacked_widget.addWidget(self.chat_page)

        self.login_page.login_signal.connect(self.handle_login)
        self.login_page.register_signal.connect(self.handle_register)
        self.market_page.upload_signal.connect(self.handle_upload)
        self.market_page.list_signal.connect(self.handle_list)
        self.market_page.goto_chat_signal.connect(self.show_chat_page)
        self.market_page.listing_clicked.connect(self.on_listing_clicked)
        self.chat_page.send_chat_signal.connect(self.handle_send_chat)
        self.chat_page.back_signal.connect(self.show_market_page)

        self.client.response_received.connect(self.process_response)

    def handle_login(self, username, password):
        req = {"action": "login", "username": username, "password": password}
        self.client.send_request(req)
        self.current_user = username
        self.market_page.current_user = username

    def handle_register(self, username, password):
        req = {"action": "register", "username": username, "password": password}
        self.client.send_request(req)

    def handle_upload(self, title, desc, price, brand, cpu, ram, storage, gpu, monitor_size, refresh_rate, resolution):
        req = {
            "action": "upload_product",
            "title": title,
            "description": desc,
            "price": price,
            "seller": self.current_user,
            "brand": brand,
            "cpu": cpu,
            "ram": ram,
            "storage": storage,
            "gpu": gpu,
            "monitor_size": monitor_size,
            "refresh_rate": refresh_rate,
            "resolution": resolution
        }
        self.client.send_request(req)

    def handle_list(self):
        req = {"action": "list_products"}
        self.client.send_request(req)

    def handle_send_chat(self, recipient, message):
        req = {"action": "chat", "sender": self.current_user, "receiver": recipient, "message": message}
        self.client.send_request(req)

    def process_response(self, response):
        status = response.get("status")
        message = response.get("message", "")
        if response.get("action") == "chat_message":
            sender = response.get("sender", "Unknown")
            msg = response.get("message", "")
            self.chat_page.display_chat_message(sender, msg)
        else:
            if status == "ok":
                if message == "Login successful":
                    #QMessageBox.information(self, "Info", message)
                    self.stacked_widget.setCurrentWidget(self.market_page)
                elif "products" in response:
                    products = response["products"]
                    self.market_page.update_products(products)
                else:
                    QMessageBox.information(self, "Info", message)
            else:
                QMessageBox.warning(self, "Error", message)

    def on_listing_clicked(self, product):
        if self.current_user == product["seller"]:
            msg_box = QMessageBox(self)
            msg_box.setWindowTitle("Listing Options")
            msg_box.setText(f"What would you like to do with listing '{product['title']}'?")
            remove_button = msg_box.addButton("Remove Listing", QMessageBox.ButtonRole.ActionRole)
            chat_button = msg_box.addButton("Open Chat", QMessageBox.ButtonRole.ActionRole)
            cancel_button = msg_box.addButton("Cancel", QMessageBox.ButtonRole.RejectRole)
            msg_box.exec()
            clicked = msg_box.clickedButton()
            if clicked == remove_button:
                req = {"action": "remove_product", "product_id": product["id"], "seller": self.current_user}
                self.client.send_request(req)
            elif clicked == chat_button:
                self.chat_page.recipient_edit.setText(product["seller"])
                self.stacked_widget.setCurrentWidget(self.chat_page)
        else:
            self.chat_page.recipient_edit.setText(product["seller"])
            self.stacked_widget.setCurrentWidget(self.chat_page)

    def show_chat_page(self):
        self.stacked_widget.setCurrentWidget(self.chat_page)

    def show_market_page(self):
        self.stacked_widget.setCurrentWidget(self.market_page)


class Prebuilt(QDialog):
    def __init__(self, client, current_user, product_title="New computer", product_description="", product_price=0.0):
        super().__init__()
        self.setWindowTitle("select prebuilt specs")
        self.client = client
        self.current_user = current_user
        self.product_title = product_title
        self.product_description = product_description
        self.product_price = product_price
        # Apply a dark theme style sheet
        self.setStyleSheet("""
            QWidget {
                font-family: 'Segoe UI';
                font-size: 14pt;
                background-color: #121212;
                color: #dcdcdc;
            }
            QMainWindow {
                background-color: #121212;
            }
            QPushButton {
                background-color: #1f1f1f;
                color: #dcdcdc;
                border: 1px solid #333;
                padding: 8px;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #333333;
            }
            QLineEdit, QTextEdit, QListWidget {
                background-color: #1f1f1f;
                color: #dcdcdc;
                border: 1px solid #333;
                border-radius: 4px;
                padding: 4px;
            }
            QLabel {
                color: #dcdcdc;
            }
        """)

        self.layout = QVBoxLayout()
        self.specs = self.fetch_specs()

        self.brand_label = QLabel("Brand:")
        self.brand_combo = QComboBox()
        self.brand_combo.addItem("None")

        self.cpu_label = QLabel("CPU:")
        self.cpu_combo = QComboBox()
        self.cpu_combo.addItem("None")

        self.ram_label = QLabel("RAM:")
        self.ram_combo = QComboBox()
        self.ram_combo.addItem("None")

        self.storage_label = QLabel("Storage:")
        self.storage_combo = QComboBox()
        self.storage_combo.addItem("None")

        self.gpu_label = QLabel("GPU:")
        self.gpu_combo = QComboBox()
        self.gpu_combo.addItem("None")

        self.monitor_size_label = QLabel("Monitor Size:")
        self.monitor_size_combo = QComboBox()
        self.monitor_size_combo.addItem("None")

        self.refresh_rate_label = QLabel("Refresh Rate:")
        self.refresh_rate_combo = QComboBox()
        self.refresh_rate_combo.addItem("None")

        self.resolution_label = QLabel("Resolution:")
        self.resolution_combo = QComboBox()
        self.resolution_combo.addItem("None")

        self.populate_comboboxes()

        self.upload_button = QPushButton("Upload Product")
        self.upload_button.clicked.connect(self.upload_product)

        self.brand_combo.currentIndexChanged.connect(self.update_filters)
        self.resolution_combo.currentIndexChanged.connect(self.update_filters)
        self.cpu_combo.currentIndexChanged.connect(self.update_filters)
        self.ram_combo.currentIndexChanged.connect(self.update_filters)
        self.storage_combo.currentIndexChanged.connect(self.update_filters)
        self.gpu_combo.currentIndexChanged.connect(self.update_filters)
        self.monitor_size_combo.currentIndexChanged.connect(self.update_filters)
        self.refresh_rate_combo.currentIndexChanged.connect(self.update_filters)

        self.layout.addWidget(self.brand_label)
        self.layout.addWidget(self.brand_combo)
        self.layout.addWidget(self.cpu_label)
        self.layout.addWidget(self.cpu_combo)
        self.layout.addWidget(self.ram_label)
        self.layout.addWidget(self.ram_combo)
        self.layout.addWidget(self.storage_label)
        self.layout.addWidget(self.storage_combo)
        self.layout.addWidget(self.gpu_label)
        self.layout.addWidget(self.gpu_combo)
        self.layout.addWidget(self.monitor_size_label)
        self.layout.addWidget(self.monitor_size_combo)
        self.layout.addWidget(self.refresh_rate_label)
        self.layout.addWidget(self.refresh_rate_combo)
        self.layout.addWidget(self.resolution_label)
        self.layout.addWidget(self.resolution_combo)
        self.layout.addWidget(self.upload_button)

        self.setLayout(self.layout)

    def fetch_specs(self, filters=None):
        try:
            url = API_URL if not filters else FILTER_URL
            response = requests.get(url) if not filters else requests.post(url, json=filters)
            if response.status_code == 200:
                data = response.json()
                return data if isinstance(data, dict) else {}
            else:
                return {}
        except requests.exceptions.RequestException as e:
            print(f"Error fetching specs: {e}")
            return {}

    def populate_comboboxes(self):
        if not isinstance(self.specs, dict):
            return
        print(self.specs.get("brands"))
        self.brand_combo.addItems(self.specs.get("brands", []))
        self.cpu_combo.addItems(self.specs.get("cpus", []))
        self.ram_combo.addItems(map(str, self.specs.get("rams", [])))
        self.storage_combo.addItems(map(str, self.specs.get("storages", [])))
        self.gpu_combo.addItems(self.specs.get("gpus", []))
        self.monitor_size_combo.addItems(map(str, self.specs.get("monitor_sizes", [])))
        self.refresh_rate_combo.addItems(map(str, self.specs.get("refresh_rates", [])))
        self.resolution_combo.addItems(self.specs.get("resolutions", []))

    def update_filters(self):
        filters = {
            "brand": self.brand_combo.currentText() if self.brand_combo.currentText() != "None" else None,
            "cpu": self.cpu_combo.currentText() if self.cpu_combo.currentText() != "None" else None,
            "ram": int(self.ram_combo.currentText()) if self.ram_combo.currentText() not in ["None", ""] else None,
            "storage": int(self.storage_combo.currentText()) if self.storage_combo.currentText() not in ["None",
                                                                                                         ""] else None,
            "gpu": self.gpu_combo.currentText() if self.gpu_combo.currentText() != "None" else None,
            "monitor_size": float(
                self.monitor_size_combo.currentText()) if self.monitor_size_combo.currentText() not in ["None",
                                                                                                        ""] else None,
            "refresh_rate": int(self.refresh_rate_combo.currentText()) if self.refresh_rate_combo.currentText() not in [
                "None", ""] else None,
            "resolution": self.resolution_combo.currentText() if self.resolution_combo.currentText() != "None" else None
        }
        filters = {k: v for k, v in filters.items() if v is not None}  # Remove empty filters

        updated_specs = self.fetch_specs(filters)

        if not isinstance(updated_specs, dict):
            print("Error: Expected a dictionary but got:", type(updated_specs))
            return

            # Block signals to prevent infinite update loop
        self.brand_combo.blockSignals(True)
        self.cpu_combo.blockSignals(True)
        self.ram_combo.blockSignals(True)
        self.storage_combo.blockSignals(True)
        self.gpu_combo.blockSignals(True)
        self.monitor_size_combo.blockSignals(True)
        self.refresh_rate_combo.blockSignals(True)
        self.resolution_combo.blockSignals(True)

        self.brand_combo.clear()
        self.brand_combo.addItem("None")
        self.brand_combo.addItems(map(str, updated_specs.get("brands", [])))

        self.cpu_combo.clear()
        self.cpu_combo.addItem("None")
        self.cpu_combo.addItems(map(str, updated_specs.get("cpus", [])))

        self.ram_combo.clear()
        self.ram_combo.addItem("None")
        self.ram_combo.addItems(map(str, updated_specs.get("rams", [])))

        self.storage_combo.clear()
        self.storage_combo.addItem("None")
        self.storage_combo.addItems(map(str, updated_specs.get("storages", [])))

        self.gpu_combo.clear()
        self.gpu_combo.addItem("None")
        self.gpu_combo.addItems(updated_specs.get("gpus", []))

        self.monitor_size_combo.clear()
        self.monitor_size_combo.addItem("None")
        self.monitor_size_combo.addItems(map(str, updated_specs.get("monitor_sizes", [])))

        self.refresh_rate_combo.clear()
        self.refresh_rate_combo.addItem("None")
        self.refresh_rate_combo.addItems(map(str, updated_specs.get("refresh_rates", [])))

        self.resolution_combo.clear()
        self.resolution_combo.addItem("None")
        self.resolution_combo.addItems(updated_specs.get("resolutions", []))

        for k, v in filters.items():
            getattr(self, f"{k}_combo").setCurrentText(str(v))

        # Re-enable signals after updates
        self.brand_combo.blockSignals(False)
        self.cpu_combo.blockSignals(False)
        self.ram_combo.blockSignals(False)
        self.storage_combo.blockSignals(False)
        self.gpu_combo.blockSignals(False)
        self.monitor_size_combo.blockSignals(False)
        self.refresh_rate_combo.blockSignals(False)
        self.resolution_combo.blockSignals(False)

    def upload_product(self):
        req = {
            "action": "upload_product",
            "title": self.product_title,
            "description": self.product_description,
            "price": self.product_price,
            "seller": self.current_user,
            "brand": self.brand_combo.currentText(),
            "cpu": self.cpu_combo.currentText(),
            "ram": self.ram_combo.currentText(),
            "storage": self.storage_combo.currentText(),
            "gpu": self.gpu_combo.currentText(),
            "monitor_size": self.monitor_size_combo.currentText(),
            "refresh_rate": self.refresh_rate_combo.currentText(),
            "resolution": self.resolution_combo.currentText()
        }
        self.client.send_request(req)


class CustomSpecs(QDialog):
    def __init__(self, client, current_user, product_title="New computer", product_description="", product_price=0.0):
        super().__init__()
        self.setWindowTitle("select custom specs")
        self.client = client
        print(current_user)
        self.current_user = current_user
        self.product_title = product_title
        self.product_description = product_description
        self.product_price = product_price

        # Apply a dark theme style sheet
        self.setStyleSheet("""
            QWidget {
                font-family: 'Segoe UI';
                font-size: 14pt;
                background-color: #121212;
                color: #dcdcdc;
            }
            QMainWindow {
                background-color: #121212;
            }
            QPushButton {
                background-color: #1f1f1f;
                color: #dcdcdc;
                border: 1px solid #333;
                padding: 8px;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #333333;
            }
            QLineEdit, QTextEdit, QListWidget {
                background-color: #1f1f1f;
                color: #dcdcdc;
                border: 1px solid #333;
                border-radius: 4px;
                padding: 4px;
            }
            QLabel {
                color: #dcdcdc;
            }
        """)

        self.layout = QVBoxLayout()
        self.specs = self.fetch_specs()

        self.brand_label = QLabel("Brand:")
        self.brand_combo = QComboBox()
        self.brand_combo.addItem("None")

        self.cpu_label = QLabel("CPU:")
        self.cpu_combo = QComboBox()
        self.cpu_combo.addItem("None")

        self.ram_label = QLabel("RAM:")
        self.ram_combo = QComboBox()
        self.ram_combo.addItem("None")

        self.storage_label = QLabel("Storage:")
        self.storage_combo = QComboBox()
        self.storage_combo.addItem("None")

        self.gpu_label = QLabel("GPU:")
        self.gpu_combo = QComboBox()
        self.gpu_combo.addItem("None")

        self.monitor_size_label = QLabel("Monitor Size:")
        self.monitor_size_combo = QComboBox()
        self.monitor_size_combo.addItem("None")

        self.refresh_rate_label = QLabel("Refresh Rate:")
        self.refresh_rate_combo = QComboBox()
        self.refresh_rate_combo.addItem("None")

        self.resolution_label = QLabel("Resolution:")
        self.resolution_combo = QComboBox()
        self.resolution_combo.addItem("None")

        self.populate_comboboxes()

        self.upload_button = QPushButton("Upload Product")
        self.upload_button.clicked.connect(self.upload_product)

        self.layout.addWidget(self.brand_label)
        self.layout.addWidget(self.brand_combo)
        self.layout.addWidget(self.cpu_label)
        self.layout.addWidget(self.cpu_combo)
        self.layout.addWidget(self.ram_label)
        self.layout.addWidget(self.ram_combo)
        self.layout.addWidget(self.storage_label)
        self.layout.addWidget(self.storage_combo)
        self.layout.addWidget(self.gpu_label)
        self.layout.addWidget(self.gpu_combo)
        self.layout.addWidget(self.monitor_size_label)
        self.layout.addWidget(self.monitor_size_combo)
        self.layout.addWidget(self.refresh_rate_label)
        self.layout.addWidget(self.refresh_rate_combo)
        self.layout.addWidget(self.resolution_label)
        self.layout.addWidget(self.resolution_combo)
        self.layout.addWidget(self.upload_button)

        self.setLayout(self.layout)

    def fetch_specs(self, filters=None):
        try:
            url = API_URL if not filters else FILTER_URL
            response = requests.get(url) if not filters else requests.post(url, json=filters)
            if response.status_code == 200:
                data = response.json()
                return data if isinstance(data, dict) else {}
            else:
                return {}
        except requests.exceptions.RequestException as e:
            print(f"Error fetching specs: {e}")
            return {}

    def populate_comboboxes(self):
        if not isinstance(self.specs, dict):
            return
        self.brand_combo.addItems(self.specs.get("brands", []))
        self.cpu_combo.addItems(self.specs.get("cpus", []))
        self.ram_combo.addItems(map(str, self.specs.get("rams", [])))
        self.storage_combo.addItems(map(str, self.specs.get("storages", [])))
        self.gpu_combo.addItems(self.specs.get("gpus", []))
        self.monitor_size_combo.addItems(map(str, self.specs.get("monitor_sizes", [])))
        self.refresh_rate_combo.addItems(map(str, self.specs.get("refresh_rates", [])))
        self.resolution_combo.addItems(self.specs.get("resolutions", []))

    def upload_product(self):
        req = {
            "action": "upload_product",
            "title": self.product_title,
            "description": self.product_description,
            "price": self.product_price,
            "seller": self.current_user,
            "brand": self.brand_combo.currentText(),
            "cpu": self.cpu_combo.currentText(),
            "ram": self.ram_combo.currentText(),
            "storage": self.storage_combo.currentText(),
            "gpu": self.gpu_combo.currentText(),
            "monitor_size": self.monitor_size_combo.currentText(),
            "refresh_rate": self.refresh_rate_combo.currentText(),
            "resolution": self.resolution_combo.currentText()
        }
        self.client.send_request(req)


def main():
    app = QApplication(sys.argv)
    window = MainWindow()
    window.resize(800, 600)
    window.show()
    sys.exit(app.exec())


if __name__ == '__main__':
    main()
