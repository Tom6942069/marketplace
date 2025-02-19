import socket
import threading
import sqlite3
import json

# Global dictionary to map logged-in usernames to their client sockets
client_sockets = {}

# -----------------------
# Database Initialization
# -----------------------
def init_db():
    # The file 'marketplace.db' is created in the same directory.
    # Listings saved here will persist even if the server is restarted.
    conn = sqlite3.connect('marketplace.db')
    cursor = conn.cursor()
    cursor.execute('''
          CREATE TABLE IF NOT EXISTS Users (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              username TEXT UNIQUE NOT NULL,
              password TEXT NOT NULL
          )
    ''')
    cursor.execute('''
            CREATE TABLE IF NOT EXISTS Products (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                description TEXT,
                price REAL NOT NULL,
                seller_username TEXT NOT NULL,
                brand TEXT,
                cpu TEXT,
                ram INTEGER,
                storage INTEGER,
                gpu TEXT,
                monitor_size REAL,
                refresh_rate INTEGER,
                resolution TEXT
            )
        ''')
    cursor.execute('''
          CREATE TABLE IF NOT EXISTS Chats (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              sender TEXT,
              receiver TEXT,
              message TEXT,
              timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
          )
    ''')
    conn.commit()
    conn.close()

# -----------------------
# Request Handlers
# -----------------------
def register_user(username, password):
    try:
        conn = sqlite3.connect('marketplace.db')
        cursor = conn.cursor()
        cursor.execute("INSERT INTO Users (username, password) VALUES (?, ?)", (username, password))
        conn.commit()
        conn.close()
        return {"status": "ok", "message": "Registration successful"}
    except sqlite3.IntegrityError:
        return {"status": "error", "message": "Username already exists"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def login_user(username, password):
    try:
        conn = sqlite3.connect('marketplace.db')
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM Users WHERE username=? AND password=?", (username, password))
        user = cursor.fetchone()
        conn.close()
        if user:
            return {"status": "ok", "message": "Login successful"}
        else:
            return {"status": "error", "message": "Invalid credentials"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def upload_product(title, description, price, seller, brand, cpu, ram, storage, gpu, monitor_size, refresh_rate, resolution):
    try:
        conn = sqlite3.connect('marketplace.db')
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO Products (title, description, price, seller_username, brand, cpu, ram, storage, gpu, monitor_size, refresh_rate, resolution) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (title, description, price, seller, brand, cpu, ram, storage, gpu, monitor_size, refresh_rate, resolution))
        conn.commit()
        conn.close()
        return {"status": "ok", "message": "Product uploaded"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def list_products():
    try:
        conn = sqlite3.connect('marketplace.db')
        cursor = conn.cursor()
        cursor.execute('''
            SELECT id, title, description, price, seller_username, brand, cpu, ram, storage, gpu, monitor_size, refresh_rate, resolution 
            FROM Products
        ''')
        products = cursor.fetchall()
        conn.close()

        product_list = []
        for prod in products:
            product_list.append({
                "id": prod[0],
                "title": prod[1],
                "description": prod[2],
                "price": prod[3],
                "seller": prod[4],
                "brand": prod[5],
                "cpu": prod[6],
                "ram": prod[7],
                "storage": prod[8],
                "gpu": prod[9],
                "monitor_size": prod[10],
                "refresh_rate": prod[11],
                "resolution": prod[12]
            })
        return {"status": "ok", "products": product_list}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def remove_product(product_id, seller):
    try:
        conn = sqlite3.connect('marketplace.db')
        cursor = conn.cursor()
        cursor.execute("SELECT seller_username FROM Products WHERE id=?", (product_id,))
        row = cursor.fetchone()
        if not row:
            conn.close()
            return {"status": "error", "message": "Product not found"}
        if row[0] != seller:
            conn.close()
            return {"status": "error", "message": "You are not allowed to remove this product"}
        cursor.execute("DELETE FROM Products WHERE id=?", (product_id,))
        conn.commit()
        conn.close()
        return {"status": "ok", "message": "Product removed"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def save_chat(sender, receiver, message):
    try:
        conn = sqlite3.connect('marketplace.db')
        cursor = conn.cursor()
        cursor.execute("INSERT INTO Chats (sender, receiver, message) VALUES (?, ?, ?)",
                       (sender, receiver, message))
        conn.commit()
        conn.close()
        return {"status": "ok", "message": "Chat saved"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def process_request(request):
    action = request.get("action")
    if action == "register":
        username = request.get("username")
        password = request.get("password")
        return register_user(username, password)
    elif action == "login":
        username = request.get("username")
        password = request.get("password")
        return login_user(username, password)
    elif action == "upload_product":
        title = request.get("title")
        description = request.get("description")
        price = request.get("price")
        seller = request.get("seller")
        brand = request.get("brand")
        cpu = request.get("cpu")
        ram = request.get("ram")
        storage = request.get("storage")
        gpu = request.get("gpu")
        monitor_size = request.get("monitor_size")
        refresh_rate = request.get("refresh_rate")
        resolution = request.get("resolution")
        return upload_product(title, description, price, seller, brand, cpu, ram, storage, gpu, monitor_size,
                              refresh_rate, resolution)
    elif action == "list_products":
        return list_products()
    elif action == "remove_product":
        product_id = request.get("product_id")
        seller = request.get("seller")
        return remove_product(product_id, seller)
    elif action == "chat":
        sender = request.get("sender")
        receiver = request.get("receiver")
        message = request.get("message")
        response = save_chat(sender, receiver, message)
        # Forward chat message if recipient is online
        if receiver in client_sockets:
            try:
                forward_message = json.dumps({
                    "action": "chat_message",
                    "sender": sender,
                    "message": message
                }).encode('utf-8')
                client_sockets[receiver].send(forward_message)
            except Exception as e:
                print("Error forwarding chat to", receiver, ":", e)
        return response
    else:
        return {"status": "error", "message": "Unknown action"}

# -----------------------
# Client Connection Handler
# -----------------------
def handle_client(client_socket, addr):
    print("New connection from", addr)
    logged_in_username = None
    while True:
        try:
            data = client_socket.recv(4096)
            if not data:
                break
            request = json.loads(data.decode('utf-8'))
            print("Received request:", request)
            response = process_request(request)
            if request.get("action") == "login" and response.get("status") == "ok":
                logged_in_username = request.get("username")
                client_sockets[logged_in_username] = client_socket
            client_socket.send(json.dumps(response).encode('utf-8'))
        except Exception as e:
            print("Error handling client", addr, ":", e)
            break
    if logged_in_username and logged_in_username in client_sockets:
        del client_sockets[logged_in_username]
    client_socket.close()
    print("Connection closed", addr)

def custom_script():
    try:
        conn = sqlite3.connect('marketplace.db')
        cursor = conn.cursor()
        cursor.execute("DROP TABLE Products;")

        conn.commit()
        conn.close()
        return {"status": "ok", "message": "Product removed"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

# -----------------------
# Server Main Loop
# -----------------------
def start_server(host='127.0.0.1', port=5554):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((host, port))
    server.listen(5)
    print(f"Server listening on {host}:{port}")
    while True:
        client_socket, addr = server.accept()
        threading.Thread(target=handle_client, args=(client_socket, addr), daemon=True).start()

if __name__ == '__main__':
    init_db()
    start_server()

