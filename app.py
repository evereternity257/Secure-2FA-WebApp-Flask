from flask import Flask, render_template, request, redirect, url_for, session, flash
import bcrypt
import secrets
import hmac
import hashlib
import base64
import time
import struct
import qrcode
import os
import smtplib
import threading
import json
import requests
from email.mime.text import MIMEText
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from datetime import datetime
from dotenv import load_dotenv

# ==========================================
# KHỞI TẠO HỆ THỐNG VÀ BIẾN MÔI TRƯỜNG
# ==========================================
load_dotenv()
app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", secrets.token_hex(16))
SENDER_EMAIL = os.getenv("EMAIL_USER")
APP_PASSWORD = os.getenv("EMAIL_PASS")

# ==========================================
# CƠ SỞ DỮ LIỆU NOSQL (JSON PERSISTENCE)
# ==========================================
DB_FILE = "database.json"

db_users = {}
db_messages = []
db_otp_cache = {} # Riêng OTP Cache chỉ cần lưu trên RAM vì nó hết hạn sau 3 phút

def load_db():
    """Tải dữ liệu từ ổ cứng lên RAM khi khởi động Server"""
    global db_users, db_messages
    try:
        if os.path.exists(DB_FILE):
            with open(DB_FILE, "r") as f:
                data = json.load(f)
                db_users = data.get("users", {})
                db_messages = data.get("messages", [])
    except Exception as e:
        print(f"[CẢNH BÁO] Lỗi đọc Database: {e}")

def save_db():
    """Ghi đè dữ liệu từ RAM xuống ổ cứng mỗi khi có thay đổi"""
    try:
        with open(DB_FILE, "w") as f:
            json.dump({"users": db_users, "messages": db_messages}, f, indent=4)
    except Exception as e:
        print(f"[CẢNH BÁO] Lỗi ghi Database: {e}")

# Kích hoạt tải dữ liệu ngay khi chạy app
load_db()

# ==========================================
# TÌNH BÁO BẢO MẬT (CYBER THREAT INTELLIGENCE)
# ==========================================
def check_pwned_password(password: str) -> int:
    """Kiểm tra mật khẩu có bị lộ trên toàn cầu hay chưa qua API 'Have I Been Pwned'"""
    # Băm mật khẩu bằng SHA-1 (Tiêu chuẩn của API này)
    sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix, suffix = sha1_hash[:5], sha1_hash[5:]
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    try:
        res = requests.get(url, timeout=3)
        if res.status_code != 200: return 0
        # Tìm xem hậu tố SHA-1 có nằm trong danh sách bị lộ không
        hashes = (line.split(':') for line in res.text.splitlines())
        for h, count in hashes:
            if h == suffix: return int(count) # Trả về số lần bị hack
        return 0
    except:
        return 0 # Nếu rớt mạng, bỏ qua bước kiểm tra

# ==========================================
# MODULE GIÁM SÁT (AUDIT LOGS)
# ==========================================
def log_audit(username: str, action: str, status: str):
    if username not in db_users: return
    os_name = request.user_agent.platform.capitalize() if request.user_agent.platform else "Unknown OS"
    browser = request.user_agent.browser.capitalize() if request.user_agent.browser else "Unknown Browser"
    log_entry = {
        "time": datetime.now().strftime("%d/%m/%Y %H:%M:%S"),
        "ip": request.remote_addr,
        "device": f"{os_name} - {browser}",
        "action": action,
        "status": status 
    }
    db_users[username].setdefault("audit_logs", []).insert(0, log_entry)
    db_users[username]["audit_logs"] = db_users[username]["audit_logs"][:15]
    save_db() # Ghi log vào file

# ==========================================
# MODULE MẬT MÃ: AES & RSA
# ==========================================
AES_KEY = Fernet.generate_key()
cipher_suite = Fernet(AES_KEY)

def encrypt_data(data: str) -> str: return cipher_suite.encrypt(data.encode()).decode()
def decrypt_data(encrypted_data: str) -> str: return cipher_suite.decrypt(encrypted_data.encode()).decode()

def generate_rsa_keypair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem_private = private_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption())
    pem_public = private_key.public_key().public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
    return pem_private.decode('utf-8'), pem_public.decode('utf-8')

def rsa_encrypt(public_key_pem: str, plaintext: str) -> str:
    public_key = serialization.load_pem_public_key(public_key_pem.encode('utf-8'))
    ciphertext = public_key.encrypt(plaintext.encode('utf-8'), padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    return base64.b64encode(ciphertext).decode('utf-8')

def rsa_decrypt(private_key_pem: str, b64_ciphertext: str) -> str:
    private_key = serialization.load_pem_private_key(private_key_pem.encode('utf-8'), password=None)
    try:
        return private_key.decrypt(base64.b64decode(b64_ciphertext), padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)).decode('utf-8')
    except: return "[LỖI GIẢI MÃ]"

# ==========================================
# MODULE MẬT MÃ: BCRYPT, TOTP, CSPRNG & EMAIL
# ==========================================
def _send_email_task(to_email: str, otp: str):
    try:
        msg = MIMEText(f"Mã xác thực 2FA của bạn là: {otp}\nMã này sẽ hết hạn sau 3 phút.")
        msg['Subject'] = 'Mã OTP - Đồ án Mật mã'
        msg['From'] = SENDER_EMAIL
        msg['To'] = to_email
        with smtplib.SMTP('smtp.gmail.com', 587) as server:
            server.ehlo()
            server.starttls() 
            if SENDER_EMAIL and APP_PASSWORD:
                server.login(SENDER_EMAIL, APP_PASSWORD)
                server.send_message(msg)
    except Exception as e: print(f"[ERROR] Lỗi gửi mail: {e}")

def send_real_email(to_email: str, otp: str):
    threading.Thread(target=_send_email_task, args=(to_email, otp)).start()

def generate_recovery_codes():
    cleartext_codes = [secrets.token_hex(4).upper() for _ in range(5)]
    hashed_codes = [bcrypt.hashpw(code.encode(), bcrypt.gensalt()).decode('utf-8') for code in cleartext_codes]
    return cleartext_codes, hashed_codes

def hash_password(password: str) -> str: 
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(12)).decode('utf-8')
    
def verify_password(password: str, hashed_pw_str: str) -> bool: 
    return bcrypt.checkpw(password.encode('utf-8'), hashed_pw_str.encode('utf-8'))

def generate_email_otp(username: str, email: str) -> str:
    otp = ''.join(str(secrets.randbelow(10)) for _ in range(6))
    db_otp_cache[username] = {"otp": otp, "expires_at": time.time() + 180}
    send_real_email(email, otp)
    return otp

def get_totp_token(secret: str) -> str:
    key = base64.b32decode(secret, True)
    msg = struct.pack(">Q", int(time.time()) // 30)
    hmac_hash = hmac.new(key, msg, hashlib.sha1).digest()
    offset = hmac_hash[19] & 15
    return f"{(struct.unpack('>I', hmac_hash[offset:offset+4])[0] & 0x7fffffff) % 1000000:06d}"

# ==========================================
# WEB ROUTES & SECURITY HEADERS
# ==========================================
@app.after_request
def add_security_headers(response):
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['X-Content-Type-Options'] = 'nosniff' 
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'     
    response.headers['X-XSS-Protection'] = '1; mode=block' 
    return response

@app.route('/')
def home(): return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if username in db_users:
            flash("Tài khoản đã tồn tại!", "danger")
            return redirect(url_for('register'))

        # KIỂM TRA MẬT KHẨU RÒ RỈ (HAVE I BEEN PWNED)
        pwned_count = check_pwned_password(password)
        if pwned_count > 0:
            flash(f"CẢNH BÁO: Mật khẩu này đã bị rò rỉ {pwned_count:,} lần trên toàn cầu! Vui lòng chọn mật khẩu khác để đảm bảo an toàn.", "danger")
            return redirect(url_for('register'))

        clear_codes, hash_codes = generate_recovery_codes()
        rsa_priv, rsa_pub = generate_rsa_keypair()
        method_2fa = request.form.get('method_2fa', 'email')

        db_users[username] = {
            "email": request.form['email'],
            "password_hash": hash_password(password),
            "method_2fa": method_2fa,
            "totp_secret": base64.b32encode(secrets.token_bytes(10)).decode('utf-8') if method_2fa == 'totp' else None,
            "recovery_codes": hash_codes,
            "failed_attempts": 0, 
            "lockout_until": 0,
            "secret_note": encrypt_data("Két sắt trống."),
            "rsa_public": rsa_pub, 
            "rsa_private": encrypt_data(rsa_priv),
            "audit_logs": [], 
            "last_ip": None
        }
        
        save_db() # LƯU DATABASE
        log_audit(username, "Đăng ký tài khoản", "SUCCESS")

        qr_url = None
        if method_2fa == 'totp':
            os.makedirs('static/qrcodes', exist_ok=True)
            qr_url = f"/static/qrcodes/{username}.png"
            qrcode.make(f"otpauth://totp/DoAnMatMa:{username}?secret={db_users[username]['totp_secret']}&issuer=DoAnMatMa").save(f".{qr_url}")

        return render_template('register_success.html', qr_url=qr_url, recovery_codes=clear_codes)
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user_record = db_users.get(username)

        if user_record and verify_password(password, user_record["password_hash"]):
            session['temp_user'] = username
            log_audit(username, "Xác thực Mật khẩu (B1)", "SUCCESS")
            if user_record['method_2fa'] == 'email':
                generate_email_otp(username, user_record['email'])
            return redirect(url_for('verify_2fa'))
        else:
            if user_record: log_audit(username, "Xác thực Mật khẩu (B1)", "FAILED")
            flash("Sai tài khoản hoặc mật khẩu!", "danger")
    return render_template('login.html')

@app.route('/verify-2fa', methods=['GET', 'POST'])
def verify_2fa():
    if 'temp_user' not in session: return redirect(url_for('login'))
    username = session['temp_user']
    user = db_users[username]

    if time.time() < user["lockout_until"]:
        flash(f"Tài khoản bị khóa! Thử lại sau {int(user['lockout_until'] - time.time())} giây.", "danger")
        return render_template('verify_2fa.html', method=user['method_2fa'])

    if request.method == 'POST':
        user_code = request.form['otp_code'].strip().upper()
        is_valid = False

        if len(user_code) == 8:
            for i, hashed_code_str in enumerate(user["recovery_codes"]):
                if bcrypt.checkpw(user_code.encode(), hashed_code_str.encode('utf-8')):
                    is_valid = True
                    user["recovery_codes"].pop(i)
                    flash("Đăng nhập bằng Mã dự phòng thành công!", "success")
                    log_audit(username, "Dùng Mã Dự Phòng", "SUCCESS")
                    break
        elif len(user_code) == 6:
            if user['method_2fa'] == 'email' and username in db_otp_cache and time.time() < db_otp_cache[username]["expires_at"]:
                is_valid = secrets.compare_digest(db_otp_cache[username]["otp"], user_code)
            elif user['method_2fa'] == 'totp':
                is_valid = secrets.compare_digest(user_code, get_totp_token(user['totp_secret']))

        if is_valid:
            user["failed_attempts"] = 0 
            session['logged_in_user'] = username
            session.pop('temp_user', None)
            
            log_audit(username, "Xác thực 2FA (B2)", "SUCCESS")
            
            current_ip = request.remote_addr
            if user["last_ip"] and user["last_ip"] != current_ip:
                flash(f"CẢNH BÁO: Phát hiện đăng nhập từ IP lạ ({current_ip}). IP cũ: {user['last_ip']}", "warning")
                log_audit(username, "Cảnh báo IP Lạ", "WARNING")
            user["last_ip"] = current_ip
            save_db() # LƯU DATABASE

            return redirect(url_for('dashboard'))
        else:
            user["failed_attempts"] += 1
            log_audit(username, "Xác thực 2FA (B2)", "FAILED")
            if user["failed_attempts"] >= 3:
                user["lockout_until"] = time.time() + 60 
                log_audit(username, "Khóa tài khoản (Brute-Force)", "WARNING")
                flash("Bạn đã nhập sai 3 lần. Tài khoản bị khóa 60 giây!", "danger")
            else:
                flash(f"Mã không hợp lệ! Bạn còn {3 - user['failed_attempts']} lần thử.", "warning")
            save_db() # LƯU DATABASE

    return render_template('verify_2fa.html', method=user['method_2fa'])

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'logged_in_user' not in session: return redirect(url_for('login'))
    username = session['logged_in_user']
    user = db_users[username]
    
    if request.method == 'POST' and 'secret_note' in request.form:
        user['secret_note'] = encrypt_data(request.form['secret_note'])
        save_db() # LƯU DATABASE
        log_audit(username, "Cập nhật Két sắt AES", "SUCCESS")
        flash("Đã mã hóa AES và lưu bí mật thành công!", "success")
        
    if request.method == 'POST' and 'receiver' in request.form:
        receiver = request.form['receiver']
        msg_content = request.form['message']
        if receiver in db_users:
            encrypted_msg = rsa_encrypt(db_users[receiver]['rsa_public'], msg_content)
            db_messages.append({
                "from": username, 
                "to": receiver, 
                "ciphertext": encrypted_msg, 
                "time": time.strftime("%H:%M:%S")
            })
            save_db() # LƯU DATABASE
            log_audit(username, f"Gửi tin RSA cho {receiver}", "SUCCESS")
            flash(f"Đã mã hóa RSA và gửi tin tới {receiver}!", "success")
        else: 
            flash("Người nhận không tồn tại!", "danger")

    my_inbox = []
    my_private_key = decrypt_data(user['rsa_private']) 
    for msg in db_messages:
        if msg['to'] == username:
            my_inbox.append({
                "from": msg['from'], "time": msg['time'], 
                "ciphertext": msg['ciphertext'], "plaintext": rsa_decrypt(my_private_key, msg['ciphertext'])
            })

    return render_template(
        'dashboard.html', username=username, decrypted_note=decrypt_data(user['secret_note']), 
        encrypted_note=user['secret_note'], other_users=[u for u in db_users.keys() if u != username], 
        inbox=my_inbox, audit_logs=user['audit_logs']
    )

@app.route('/logout')
def logout():
    if 'logged_in_user' in session:
        log_audit(session['logged_in_user'], "Đăng xuất hệ thống", "SUCCESS")
    session.clear()
    flash("Đã đăng xuất an toàn (Hoặc do bạn treo máy quá lâu).", "info")
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True, port=5001, ssl_context='adhoc')