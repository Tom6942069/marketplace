import sys
import json
import socket
import threading
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QStackedWidget,
    QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton,
    QTextEdit, QMessageBox, QFormLayout, QListWidget, QListWidgetItem
)
from PyQt6.QtCore import pyqtSignal, QObject, Qt
from PyQt6.QtGui import QFont

# -----------------------
# Client Communication Class
# -----------------------
class Client(QObject):
    response_received = pyqtSignal(dict)

    def __init__(self, host='127.0.0.1', port=5555):
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
            self.login_signal.emit(username, password)
        else:
            QMessageBox.warning(self, "Error", "Please enter username and password.")

    def on_register(self):
        username = self.username_edit.text().strip()
        password = self.password_edit.text().strip()
        if username and password:
            self.register_signal.emit(username, password)
        else:
            QMessageBox.warning(self, "Error", "Please enter username and password.")

# -----------------------
# Marketplace Page
# -----------------------
class MarketplacePage(QWidget):
    upload_signal = pyqtSignal(str, str, float)
    list_signal = pyqtSignal()
    goto_chat_signal = pyqtSignal()
    listing_clicked = pyqtSignal(dict)

    def __init__(self):
        super().__init__()
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
        self.upload_btn = QPushButton("Upload Product")
        layout.addWidget(self.upload_btn)
        self.upload_btn.clicked.connect(self.on_upload)
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

    def on_upload(self):
        title = self.title_edit.text().strip()
        desc = self.desc_edit.text().strip()
        price_text = self.price_edit.text().strip()
        if title and price_text:
            try:
                price = float(price_text)
            except ValueError:
                QMessageBox.warning(self, "Error", "Price must be a number.")
                return
            self.upload_signal.emit(title, desc, price)
        else:
            QMessageBox.warning(self, "Error", "Please fill in title and price.")

    def update_products(self, products):
        self.products_list.clear()
        for prod in products:
            display_text = (
                f"ID: {prod['id']}\n"
                f"Title: {prod['title']}\n"
                f"Description: {prod['description']}\n"
                f"Price: {prod['price']}\n"
                f"Seller: {prod['seller']}"
            )
            item = QListWidgetItem(display_text)
            item.setData(Qt.ItemDataRole.UserRole, prod)
            self.products_list.addItem(item)

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
        self.market_page = MarketplacePage()
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

    def handle_register(self, username, password):
        req = {"action": "register", "username": username, "password": password}
        self.client.send_request(req)

    def handle_upload(self, title, desc, price):
        req = {
            "action": "upload_product",
            "title": title,
            "description": desc,
            "price": price,
            "seller": self.current_user
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
                    QMessageBox.information(self, "Info", message)
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

def main():
    app = QApplication(sys.argv)
    window = MainWindow()
    window.resize(800, 600)
    window.show()
    sys.exit(app.exec())

if __name__ == '__main__':
    main()
