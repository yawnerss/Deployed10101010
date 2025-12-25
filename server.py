from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import os
from datetime import datetime
import json
import requests

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'your-secret-key-change-this')
CORS(app)

# Telegram Bot Configuration
TELEGRAM_BOT_TOKEN = "7895976352:AAHhQgEgWdTGibFuR6D_jWy2pPwpbiy2rT8"
TELEGRAM_CHAT_ID = os.environ.get('TELEGRAM_CHAT_ID', '7383039587')  # You need to set this

def send_telegram_message(message):
    """Send message to Telegram bot"""
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {
        'chat_id': TELEGRAM_CHAT_ID,
        'text': message,
        'parse_mode': 'HTML'
    }
    try:
        response = requests.post(url, json=payload)
        return response.json()
    except Exception as e:
        print(f"Error sending Telegram message: {e}")
        return None

def format_receipt_message(receipt_data, user_email):
    """Format receipt data for Telegram message"""
    message = "🧾 <b>NEW RECEIPT</b>\n\n"
    message += f"👤 <b>User:</b> {user_email}\n"
    message += f"📅 <b>Date:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
    message += "<b>📦 Items:</b>\n"
    
    for item in receipt_data['items']:
        message += f"  • {item['name']} - ${item['price']:.2f}\n"
    
    message += f"\n💰 <b>Total:</b> ${receipt_data['total']:.2f}"
    return message

# Database setup - PostgreSQL for production, SQLite for local
DATABASE_URL = os.environ.get('DATABASE_URL')
if DATABASE_URL:
    # Fix for Render's postgres:// URL (needs postgresql://)
    if DATABASE_URL.startswith('postgres://'):
        DATABASE_URL = DATABASE_URL.replace('postgres://', 'postgresql://', 1)
    
    import psycopg2
    from psycopg2.extras import RealDictCursor
    
    def get_db():
        return psycopg2.connect(DATABASE_URL)
    
    def init_db():
        conn = get_db()
        c = conn.cursor()
        
        # Users table
        c.execute('''CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            is_admin INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )''')
        
        # Products table
        c.execute('''CREATE TABLE IF NOT EXISTS products (
            id SERIAL PRIMARY KEY,
            name TEXT NOT NULL,
            price REAL NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )''')
        
        # Admin credentials table
        c.execute('''CREATE TABLE IF NOT EXISTS admin_credentials (
            id SERIAL PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )''')
        
        # Create default admin if not exists
        c.execute("SELECT * FROM users WHERE email = 'admin@store.com'")
        if not c.fetchone():
            admin_password = generate_password_hash('admin123')
            c.execute("INSERT INTO users (email, password, is_admin) VALUES (%s, %s, 1)",
                      ('admin@store.com', admin_password))
        
        # Create admin credentials if not exists
        c.execute("SELECT * FROM admin_credentials WHERE username = 'descalzojhon'")
        if not c.fetchone():
            admin_cred_password = generate_password_hash('jhonwilson')
            c.execute("INSERT INTO admin_credentials (username, password) VALUES (%s, %s)",
                      ('descalzojhon', admin_cred_password))
        
        # Add sample products if empty
        c.execute("SELECT COUNT(*) FROM products")
        if c.fetchone()[0] == 0:
            sample_products = [
                ('Apple', 1.50),
                ('Bread', 2.00),
                ('Milk', 3.50),
                ('Eggs', 4.00),
                ('Cheese', 5.50)
            ]
            c.executemany("INSERT INTO products (name, price) VALUES (%s, %s)", sample_products)
        
        conn.commit()
        conn.close()
else:
    # SQLite for local development
    import sqlite3
    
    def get_db():
        return sqlite3.connect('store.db')
    
    def init_db():
        conn = get_db()
        c = conn.cursor()
        
        # Users table
        c.execute('''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            is_admin INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )''')
        
        # Products table
        c.execute('''CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            price REAL NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )''')
        
        # Admin credentials table
        c.execute('''CREATE TABLE IF NOT EXISTS admin_credentials (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )''')
        
        # Create default admin if not exists
        c.execute("SELECT * FROM users WHERE email = 'admin@store.com'")
        if not c.fetchone():
            admin_password = generate_password_hash('admin123')
            c.execute("INSERT INTO users (email, password, is_admin) VALUES (?, ?, 1)",
                      ('admin@store.com', admin_password))
        
        # Create admin credentials if not exists
        c.execute("SELECT * FROM admin_credentials WHERE username = 'descalzojhon'")
        if not c.fetchone():
            admin_cred_password = generate_password_hash('jhonwilson')
            c.execute("INSERT INTO admin_credentials (username, password) VALUES (?, ?)",
                      ('descalzojhon', admin_cred_password))
        
        # Add sample products if empty
        c.execute("SELECT COUNT(*) FROM products")
        if c.fetchone()[0] == 0:
            sample_products = [
                ('Apple', 1.50),
                ('Bread', 2.00),
                ('Milk', 3.50),
                ('Eggs', 4.00),
                ('Cheese', 5.50)
            ]
            c.executemany("INSERT INTO products (name, price) VALUES (?, ?)", sample_products)
        
        conn.commit()
        conn.close()

# Helper function for query parameter binding
def get_param_placeholder():
    return '%s' if DATABASE_URL else '?'

# Routes
@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('index.html')

@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/signup')
def signup():
    return render_template('signup.html')

@app.route('/admin')
def admin():
    if 'admin_authenticated' not in session:
        return render_template('admin_login.html')
    return render_template('admin.html')

# API Routes
@app.route('/api/register', methods=['POST'])
def register():
    data = request.json
    email = data.get('email')
    password = data.get('password')
    
    if not email or not password:
        return jsonify({'error': 'Email and password required'}), 400
    
    conn = get_db()
    c = conn.cursor()
    param = get_param_placeholder()
    
    try:
        hashed_password = generate_password_hash(password)
        c.execute(f"INSERT INTO users (email, password) VALUES ({param}, {param})", (email, hashed_password))
        conn.commit()
        return jsonify({'message': 'User registered successfully'}), 201
    except Exception as e:
        return jsonify({'error': 'Email already exists'}), 400
    finally:
        conn.close()

@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.json
    email = data.get('email')
    password = data.get('password')
    param = get_param_placeholder()
    
    conn = get_db()
    c = conn.cursor()
    c.execute(f"SELECT id, password, is_admin FROM users WHERE email = {param}", (email,))
    user = c.fetchone()
    conn.close()
    
    if user and check_password_hash(user[1], password):
        session['user_id'] = user[0]
        session['email'] = email
        session['is_admin'] = user[2]
        return jsonify({
            'message': 'Login successful',
            'is_admin': user[2]
        }), 200
    
    return jsonify({'error': 'Invalid credentials'}), 401

@app.route('/api/admin/login', methods=['POST'])
def admin_login():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    param = get_param_placeholder()
    
    conn = get_db()
    c = conn.cursor()
    c.execute(f"SELECT username, password FROM admin_credentials WHERE username = {param}", (username,))
    admin = c.fetchone()
    conn.close()
    
    if admin and check_password_hash(admin[1], password):
        session['admin_authenticated'] = True
        session['admin_username'] = username
        return jsonify({'message': 'Admin login successful'}), 200
    
    return jsonify({'error': 'Invalid admin credentials'}), 401

@app.route('/api/admin/check-auth', methods=['GET'])
def check_admin_auth():
    if 'admin_authenticated' in session:
        return jsonify({
            'authenticated': True,
            'username': session.get('admin_username')
        })
    return jsonify({'authenticated': False})

@app.route('/api/admin/change-password', methods=['POST'])
def change_admin_password():
    if 'admin_authenticated' not in session:
        return jsonify({'error': 'Unauthorized'}), 403
    
    data = request.json
    current_password = data.get('current_password')
    new_password = data.get('new_password')
    param = get_param_placeholder()
    
    if not current_password or not new_password:
        return jsonify({'error': 'Both passwords required'}), 400
    
    conn = get_db()
    c = conn.cursor()
    
    # Verify current password
    username = session.get('admin_username')
    c.execute(f"SELECT password FROM admin_credentials WHERE username = {param}", (username,))
    admin = c.fetchone()
    
    if not admin or not check_password_hash(admin[0], current_password):
        conn.close()
        return jsonify({'error': 'Current password is incorrect'}), 401
    
    # Update password
    new_hashed = generate_password_hash(new_password)
    c.execute(f"UPDATE admin_credentials SET password = {param}, updated_at = CURRENT_TIMESTAMP WHERE username = {param}",
              (new_hashed, username))
    
    conn.commit()
    conn.close()
    
    return jsonify({'message': 'Password updated successfully'}), 200

@app.route('/api/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'message': 'Logged out successfully'}), 200

@app.route('/api/products', methods=['GET'])
def get_products():
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT id, name, price FROM products ORDER BY name")
    products = [{'id': row[0], 'name': row[1], 'price': row[2]} for row in c.fetchall()]
    conn.close()
    return jsonify(products)

@app.route('/api/products', methods=['POST'])
def add_product():
    if 'admin_authenticated' not in session:
        return jsonify({'error': 'Unauthorized'}), 403
    
    data = request.json
    name = data.get('name')
    price = data.get('price')
    
    if not name or price is None:
        return jsonify({'error': 'Name and price required'}), 400
    
    conn = get_db()
    c = conn.cursor()
    param = get_param_placeholder()
    
    if DATABASE_URL:
        c.execute(f"INSERT INTO products (name, price) VALUES ({param}, {param}) RETURNING id", (name, float(price)))
        product_id = c.fetchone()[0]
    else:
        c.execute(f"INSERT INTO products (name, price) VALUES ({param}, {param})", (name, float(price)))
        product_id = c.lastrowid
    
    conn.commit()
    conn.close()
    
    return jsonify({'id': product_id, 'name': name, 'price': float(price)}), 201

@app.route('/api/products/<int:product_id>', methods=['DELETE'])
def delete_product(product_id):
    if 'admin_authenticated' not in session:
        return jsonify({'error': 'Unauthorized'}), 403
    
    conn = get_db()
    c = conn.cursor()
    param = get_param_placeholder()
    c.execute(f"DELETE FROM products WHERE id = {param}", (product_id,))
    conn.commit()
    conn.close()
    
    return jsonify({'message': 'Product deleted'}), 200

@app.route('/api/receipts', methods=['POST'])
def create_receipt():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.json
    items = data.get('items', [])
    total = data.get('total', 0)
    
    # Format and send receipt to Telegram
    receipt_data = {
        'items': items,
        'total': total
    }
    
    user_email = session.get('email', 'Unknown')
    message = format_receipt_message(receipt_data, user_email)
    
    telegram_response = send_telegram_message(message)
    
    if telegram_response and telegram_response.get('ok'):
        return jsonify({
            'message': 'Receipt sent to Telegram successfully',
            'telegram_message_id': telegram_response.get('result', {}).get('message_id')
        }), 201
    else:
        return jsonify({'error': 'Failed to send receipt to Telegram'}), 500

@app.route('/api/check-auth', methods=['GET'])
def check_auth():
    if 'user_id' in session:
        return jsonify({
            'authenticated': True,
            'email': session.get('email'),
            'is_admin': session.get('is_admin', False)
        })
    return jsonify({'authenticated': False})

if __name__ == '__main__':
    init_db()
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
