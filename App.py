# app.py (Flask Backend
from flask import Flask, request, jsonify, render_template
from flask_compress import Compress
import cProfile, pstats, io
from flask import Flask, request, jsonify, render_template
import sqlite3
import os
import base64
from flask import Flask, request, jsonify, render_template
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import bcrypt
from flask_cors import CORS # For development, allows frontend to call backend on different ports

# --- Configuration ---
DATABASE_FILE = "password_manager.db"
SALT_FILE = "kdf_salt.bin"
MASTER_PASSWORD_HASH_FILE = "master_password_hash.bin"

app = Flask(__name__)
CORS(app) # Enable CORS for all routes (important for development with separate frontend)

# --- Global Variables for Encryption ---
# In a web app, Fernet instance should ideally be created per request
# or cached securely, but for simplicity here, we'll derive it on demand
# based on the verified master password.
# IMPORTANT: In a multi-user environment, you'd need per-user key management!
_cached_fernet_instance = None # To cache the Fernet instance after master password verification

# --- Database Operations ---
def connect_db():
    conn = sqlite3.connect(DATABASE_FILE)
    conn.row_factory = sqlite3.Row # Allows accessing columns by name
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS passwords (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            service TEXT NOT NULL UNIQUE, -- Added UNIQUE constraint
            encrypted_password TEXT NOT NULL
        )
    ''')
    conn.commit()
    return conn

# --- Key Management & Master Password ---

def generate_kdf_salt():
    salt = os.urandom(16)
    with open(SALT_FILE, "wb") as f:
        f.write(salt)
    return salt

def load_kdf_salt():
    if not os.path.exists(SALT_FILE):
        return generate_kdf_salt()
    with open(SALT_FILE, "rb") as f:
        return f.read()

def derive_key(master_password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
    return key

def set_master_password_hash(password):
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    with open(MASTER_PASSWORD_HASH_FILE, "wb") as f:
        f.write(hashed_password)
    return True

def verify_master_password_hash(password):
    if not os.path.exists(MASTER_PASSWORD_HASH_FILE):
        return False
    with open(MASTER_PASSWORD_HASH_FILE, "rb") as f:
        stored_hash = f.read()
    try:
        return bcrypt.checkpw(password.encode('utf-8'), stored_hash)
    except Exception as e:
        print(f"Error during master password verification: {e}")
        return False

# --- Encryption/Decryption Helper (using cached Fernet) ---
def get_fernet_instance(master_password):
    global _cached_fernet_instance
    if _cached_fernet_instance is None:
        try:
            salt = load_kdf_salt()
            key = derive_key(master_password, salt)
            _cached_fernet_instance = Fernet(key)
        except Exception as e:
            print(f"Error deriving Fernet key: {e}")
            return None
    return _cached_fernet_instance

def encrypt_data_with_fernet(data, fernet_instance):
    if not fernet_instance:
        return None
    try:
        return fernet_instance.encrypt(data.encode()).decode()
    except Exception as e:
        print(f"Encryption error: {e}")
        return None

def decrypt_data_with_fernet(encrypted_data, fernet_instance):
    if not fernet_instance:
        return None
    try:
        return fernet_instance.decrypt(encrypted_data.encode()).decode()
    except Exception as e:
        print(f"Decryption error: {e}")
        return None

# --- Flask Routes (API Endpoints) ---

@app.route('/')
def index():
    # Renders the main HTML page. This is where your frontend lives.
    return render_template('index.html')

@app.route('/api/master-password-status', methods=['GET'])
def get_master_password_status():
    if os.path.exists(MASTER_PASSWORD_HASH_FILE):
        return jsonify({"status": "set"})
    return jsonify({"status": "not_set"})

@app.route('/api/set-master-password', methods=['POST'])
def api_set_master_password():
    data = request.get_json()
    master_pw = data.get('master_password')

    if not master_pw:
        return jsonify({"success": False, "message": "Master password cannot be empty."}), 400
    if os.path.exists(MASTER_PASSWORD_HASH_FILE):
        return jsonify({"success": False, "message": "Master password already set."}), 400

    if set_master_password_hash(master_pw):
        return jsonify({"success": True, "message": "Master password set successfully!"})
    else:
        return jsonify({"success": False, "message": "Failed to set master password."}), 500

@app.route('/api/verify-master-password', methods=['POST'])
def api_verify_master_password():
    global _cached_fernet_instance
    data = request.get_json()
    master_pw = data.get('master_password')

    if not master_pw:
        return jsonify({"success": False, "message": "Please provide master password."}), 400

    if verify_master_password_hash(master_pw):
        # On successful verification, store the Fernet instance globally
        _cached_fernet_instance = get_fernet_instance(master_pw)
        if _cached_fernet_instance:
            return jsonify({"success": True, "message": "Master password verified."})
        else:
            return jsonify({"success": False, "message": "Failed to derive encryption key."}), 500
    else:
        # Clear the cached Fernet instance if verification fails
        _cached_fernet_instance = None
        return jsonify({"success": False, "message": "Incorrect master password."}), 401

@app.route('/api/passwords', methods=['GET'])
def get_passwords():
    if not _cached_fernet_instance:
        return jsonify({"success": False, "message": "Authentication required."}), 401

    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id, service FROM passwords ORDER BY service")
    passwords = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return jsonify({"success": True, "passwords": passwords})

@app.route('/api/passwords', methods=['POST'])
def add_or_update_password():
    if not _cached_fernet_instance:
        return jsonify({"success": False, "message": "Authentication required."}), 401

    data = request.get_json()
    service = data.get('service')
    password = data.get('password')

    if not service or not password:
        return jsonify({"success": False, "message": "Service name and password cannot be empty."}), 400

    encrypted_pw = encrypt_data_with_fernet(password, _cached_fernet_instance)
    if not encrypted_pw:
        return jsonify({"success": False, "message": "Encryption failed."}), 500

    conn = connect_db()
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO passwords (service, encrypted_password) VALUES (?, ?)", (service, encrypted_pw))
        conn.commit()
        return jsonify({"success": True, "message": f"Password for '{service}' added successfully."}), 201
    except sqlite3.IntegrityError: # Handles UNIQUE constraint violation
        # If service already exists, update it
        cursor.execute("UPDATE passwords SET encrypted_password=? WHERE service=?", (encrypted_pw, service))
        conn.commit()
        return jsonify({"success": True, "message": f"Password for '{service}' updated successfully."}), 200
    except Exception as e:
        conn.rollback()
        return jsonify({"success": False, "message": f"Database error: {e}"}), 500
    finally:
        conn.close()

@app.route('/api/passwords/<int:password_id>', methods=['DELETE'])
def delete_password(password_id):
    if not _cached_fernet_instance:
        return jsonify({"success": False, "message": "Authentication required."}), 401

    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM passwords WHERE id=?", (password_id,))
    conn.commit()
    if cursor.rowcount > 0:
        return jsonify({"success": True, "message": "Password deleted successfully."})
    else:
        return jsonify({"success": False, "message": "Password not found."}), 404
    conn.close()

@app.route('/api/passwords/decrypt/<int:password_id>', methods=['GET'])
def api_decrypt_password(password_id):
    if not _cached_fernet_instance:
        return jsonify({"success": False, "message": "Authentication required."}), 401

    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute("SELECT encrypted_password FROM passwords WHERE id=?", (password_id,))
    row = cursor.fetchone()
    conn.close()

    if row:
        encrypted_pw = row['encrypted_password']
        decrypted_pw = decrypt_data_with_fernet(encrypted_pw, _cached_fernet_instance)
        if decrypted_pw is not None:
            return jsonify({"success": True, "decrypted_password": decrypted_pw})
        else:
            return jsonify({"success": False, "message": "Failed to decrypt password."}), 500
    else:
        return jsonify({"success": False, "message": "Password not found."}), 404

if __name__ == '__main__':
    # Initialize DB and Salt if they don't exist
    connect_db()
    load_kdf_salt() # Ensure salt exists
    app.run(debug=True, port=5000) # Run on port 5000 in debug mode

app = Flask(__name__)
CORS(app)
compress = Compress(app)
