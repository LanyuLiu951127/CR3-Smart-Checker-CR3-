import os

# 取得目前腳本所在的目錄 (CR3_Smart_Checker)
BASE_DIR = os.getcwd()
SERVER_DIR = os.path.join(BASE_DIR, "server")
TEMPLATE_DIR = os.path.join(SERVER_DIR, "templates")
STATIC_DIR = os.path.join(SERVER_DIR, "static")

print(f"🔧 正在修復伺服器路徑...")
print(f"📂 根目錄: {BASE_DIR}")
print(f"📂 模板目錄: {TEMPLATE_DIR}")

# 確保目錄存在
os.makedirs(TEMPLATE_DIR, exist_ok=True)
os.makedirs(os.path.join(STATIC_DIR, "avatars"), exist_ok=True)
os.makedirs(os.path.join(STATIC_DIR, "uploads"), exist_ok=True)

# 定義檔案寫入函數
def write_file(path, content):
    with open(path, "w", encoding="utf-8") as f:
        f.write(content.strip())
    print(f"✅ 已重建: {path}")

# ==========================================
# 1. 修復 server/app.py (使用絕對路徑鎖定)
# ==========================================
app_code = """
import os
import random
import string
import hashlib
import smtplib
import uuid
import time
import threading
from datetime import datetime, date
from email.mime.text import MIMEText
from email.header import Header

from flask import Flask, render_template, request, redirect, url_for, flash, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash

# --- 核心修復：強制使用絕對路徑 ---
# 取得 app.py 所在的資料夾路徑 (server 資料夾)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
# 明確指定 templates 和 static 的完整路徑
TEMPLATE_DIR = os.path.join(BASE_DIR, 'templates')
STATIC_DIR = os.path.join(BASE_DIR, 'static')

app = Flask(__name__, template_folder=TEMPLATE_DIR, static_folder=STATIC_DIR)

app.config['SECRET_KEY'] = 'your_secret_key'
# 資料庫也使用絕對路徑
DB_PATH = os.path.join(BASE_DIR, 'instance', 'cms.db')
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{DB_PATH}'

GMAIL_USER = 'kimminnie20081127@gmail.com'
GMAIL_APP_PASS = 'eztu zvkj tmqd ciml' 

app.config['UPLOAD_FOLDER'] = os.path.join(STATIC_DIR, 'avatars')
app.config['TEMP_FOLDER'] = os.path.join(STATIC_DIR, 'uploads')

# 確保 instance 資料夾存在
os.makedirs(os.path.join(BASE_DIR, 'instance'), exist_ok=True)

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# 自動清理執行緒
def cleanup_temp_folder():
    while True:
        time.sleep(900)
        try:
            now = time.time()
            if os.path.exists(app.config['TEMP_FOLDER']):
                for f in os.listdir(app.config['TEMP_FOLDER']):
                    f_path = os.path.join(app.config['TEMP_FOLDER'], f)
                    if os.path.isfile(f_path) and now - os.path.getmtime(f_path) > 900:
                        os.remove(f_path)
        except:
            pass

threading.Thread(target=cleanup_temp_folder, daemon=True).start()

def send_email_via_gmail(to_email, subject, body_text):
    try:
        msg = MIMEText(body_text, 'plain', 'utf-8')
        msg['Subject'] = Header(subject, 'utf-8')
        msg['From'] = GMAIL_USER
        msg['To'] = to_email
        server = smtplib.SMTP_SSL('smtp.gmail.com', 465)
        server.login(GMAIL_USER, GMAIL_APP_PASS)
        server.send_message(msg)
        server.quit()
        return True
    except:
        return False

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    name = db.Column(db.String(150), nullable=False)
    country = db.Column(db.String(50), default='台灣')
    language = db.Column(db.String(20), default='zh-TW')
    avatar = db.Column(db.String(150), default='default.png')
    role = db.Column(db.String(20), default='user')
    download_count = db.Column(db.Integer, default=0)
    verification_code = db.Column(db.String(6), nullable=True)
    verification_attempts = db.Column(db.Integer, default=0)
    verification_attempts_total = db.Column(db.Integer, default=0)
    last_request_time = db.Column(db.DateTime, nullable=True)
    is_restricted = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.now)
    last_upload_reset = db.Column(db.DateTime, nullable=True)
    upload_count_window = db.Column(db.Integer, default=0)

class Feedback(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    email = db.Column(db.String(150))
    subject = db.Column(db.String(50))
    message = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.now)

class Announcement(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100))
    content = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.now)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def calculate_md5(file_path):
    hash_md5 = hashlib.md5()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(email=request.form.get('email')).first()
        if not user:
            flash('此帳號不存在，請先註冊。', 'danger')
        elif not check_password_hash(user.password, request.form.get('password')):
            flash('密碼錯誤，請重試。', 'danger')
        else:
            login_user(user)
            if user.is_restricted:
                flash('⚠️ 您的帳號已被列為觀察名單。', 'warning')
            return redirect(url_for('profile'))
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        if User.query.filter_by(email=request.form.get('email')).first():
            flash('Email 已存在', 'warning')
        else:
            role = 'super_admin' if request.form.get('email') == '111534105@stu.ukn.edu.tw' else 'user'
            db.session.add(User(email=request.form.get('email'), name=request.form.get('name'), password=generate_password_hash(request.form.get('password')), role=role))
            db.session.commit()
            flash('註冊成功！', 'success')
            return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    step = 1; email = ''
    if request.method == 'POST':
        step_val = request.form.get('step')
        if step_val == '1':
            user = User.query.filter_by(email=request.form.get('email')).first()
            if user:
                now = datetime.now()
                if user.is_restricted and user.last_request_time and (now - user.last_request_time).total_seconds() < 300:
                    flash('⚠️ 帳號異常，請等待 5 分鐘後再試。', 'danger')
                    return render_template('forgot_password.html', step=1, email=email)
                
                if user.last_request_time and (now - user.last_request_time).total_seconds() < 60:
                    user.verification_attempts += 1
                else:
                    user.verification_attempts = 1
                
                user.last_request_time = now
                user.verification_attempts_total += 1
                
                if user.verification_attempts > 3:
                    user.is_restricted = True
                    db.session.commit()
                    flash('⚠️ 警告：請求過於頻繁，已限制 5 分鐘。', 'danger')
                    return render_template('forgot_password.html', step=1, email=email)

                code = ''.join(random.choices(string.digits, k=6))
                user.verification_code = code
                db.session.commit()
                send_email_via_gmail(user.email, "【CR3 系統】重置密碼驗證碼", f"您的驗證碼：{code}")
                flash('驗證碼已寄出', 'info')
                step = 2
                email = user.email
            else:
                flash('找不到此 Email', 'danger')
        elif step_val == '2':
            user = User.query.filter_by(email=request.form.get('email')).first()
            if user and user.verification_code == request.form.get('code'):
                user.password = generate_password_hash(request.form.get('new_password'))
                user.verification_code = None
                db.session.commit()
                flash('密碼重置成功', 'success')
                return redirect(url_for('login'))
            else:
                flash('驗證碼錯誤', 'danger')
                step = 2
                email = request.form.get('email')
    return render_template('forgot_password.html', step=step, email=email)

@app.route('/download_app')
@login_required
def download_app():
    current_user.download_count += 1
    db.session.commit()
    flash(f"開始下載 cr3_check.exe (目前下載次數: {current_user.download_count})", 'success')
    return redirect(url_for('index'))

@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html')

@app.route('/update_profile', methods=['POST'])
@login_required
def update_profile():
    current_user.name = request.form.get('name')
    current_user.country = request.form.get('country')
    current_user.language = request.form.get('language')
    db.session.commit()
    return redirect(url_for('profile'))

@app.route('/upload_avatar', methods=['POST'])
@login_required
def upload_avatar():
    file = request.files.get('avatar')
    if file:
        filename = f"user_{current_user.id}_{int(datetime.now().timestamp())}.png"
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        current_user.avatar = filename
        db.session.commit()
    return redirect(url_for('profile'))

@app.route('/change_password', methods=['POST'])
@login_required
def change_password():
    if check_password_hash(current_user.password, request.form.get('current_password')):
        if check_password_hash(current_user.password, request.form.get('new_password')):
            flash('新密碼不能與目前密碼相同！', 'warning')
            return redirect(url_for('profile'))
        current_user.password = generate_password_hash(request.form.get('new_password'))
        db.session.commit()
        logout_user()
        flash('密碼已變更，請重新登入', 'success')
        return redirect(url_for('login'))
    flash('目前密碼輸入錯誤', 'danger')
    return redirect(url_for('profile'))

@app.route('/change_email', methods=['POST'])
@login_required
def change_email():
    if check_password_hash(current_user.password, request.form.get('password_verify')):
        if User.query.filter_by(email=request.form.get('new_email')).first():
            flash('該信箱已被使用', 'warning')
        else:
            current_user.email = request.form.get('new_email')
            db.session.commit()
            flash('信箱變更成功', 'success')
    else:
        flash('密碼錯誤', 'danger')
    return redirect(url_for('profile'))

@app.route('/admin')
@login_required
def admin_dashboard():
    if current_user.role not in ['admin', 'super_admin']:
        return redirect(url_for('index'))
    return render_template('admin.html', 
                           users=User.query.all(), 
                           feedbacks=Feedback.query.order_by(Feedback.created_at.desc()).all(), 
                           announcements=Announcement.query.order_by(Announcement.created_at.desc()).all(), 
                           total_downloads=sum(u.download_count for u in User.query.all()), 
                           flagged_count=sum(1 for u in User.query.all() if u.is_restricted))

@app.route('/admin/create_admin', methods=['POST'])
@login_required
def create_admin():
    if current_user.role != 'super_admin':
        return redirect(url_for('admin_dashboard'))
    if User.query.filter_by(email=request.form.get('email')).first():
        flash('Email 已存在', 'warning')
    else:
        db.session.add(User(email=request.form.get('email'), name=request.form.get('name'), password=generate_password_hash(request.form.get('password')), role='admin'))
        db.session.commit()
        flash('已新增管理員', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/add_announcement', methods=['POST'])
@login_required
def add_announcement():
    if current_user.role not in ['admin', 'super_admin']:
        return redirect(url_for('index'))
    db.session.add(Announcement(title=request.form.get('title'), content=request.form.get('content')))
    db.session.commit()
    flash('公告已發布', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/edit_announcement/<int:ann_id>', methods=['POST'])
@login_required
def edit_announcement(ann_id):
    if current_user.role != 'super_admin':
        return redirect(url_for('admin_dashboard'))
    ann = Announcement.query.get(ann_id)
    ann.title = request.form.get('title')
    ann.content = request.form.get('content')
    db.session.commit()
    flash('公告已更新', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/delete_announcement/<int:ann_id>')
@login_required
def delete_announcement(ann_id):
    if current_user.role != 'super_admin':
        return redirect(url_for('admin_dashboard'))
    db.session.delete(Announcement.query.get(ann_id))
    db.session.commit()
    flash('公告已刪除', 'warning')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/delete_user/<int:user_id>')
@login_required
def delete_user(user_id):
    if current_user.role != 'super_admin':
        return redirect(url_for('admin_dashboard'))
    if user_id == current_user.id:
        flash('不能刪除自己', 'danger')
        return redirect(url_for('admin_dashboard'))
    db.session.delete(User.query.get(user_id))
    db.session.commit()
    flash('使用者已刪除', 'warning')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/flag_user/<int:user_id>')
@login_required
def flag_user(user_id):
    if current_user.role != 'super_admin':
        return redirect(url_for('index'))
    user = User.query.get(user_id)
    user.is_restricted = True
    db.session.commit()
    flash('已管制帳號', 'warning')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/unflag_user/<int:user_id>')
@login_required
def unflag_user(user_id):
    if current_user.role != 'super_admin':
        return redirect(url_for('index'))
    user = User.query.get(user_id)
    user.is_restricted = False
    db.session.commit()
    flash('已解除管制', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/edit_user/<int:user_id>', methods=['POST'])
@login_required
def admin_edit_user(user_id):
    if current_user.role != 'super_admin':
        return redirect(url_for('index'))
    user = User.query.get(user_id)
    user.email = request.form.get('email')
    if request.form.get('password'):
        user.password = generate_password_hash(request.form.get('password'))
    db.session.commit()
    flash('資料已更新', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/submit_feedback', methods=['POST'])
def submit_feedback():
    db.session.add(Feedback(name=request.form.get('name'), email=request.form.get('email'), subject=request.form.get('subject'), message=request.form.get('message')))
    db.session.commit()
    send_email_via_gmail("111534105@stu.ukn.edu.tw", f"【意見回饋】{request.form.get('subject')}", f"寄件者: {request.form.get('name')} <{request.form.get('email')}>\\n\\n內容:\\n{request.form.get('message')}")
    flash('意見已發送！', 'success')
    return redirect(url_for('about'))

@app.route('/online_check', methods=['GET', 'POST'])
@login_required
def online_check():
    duplicates = {}
    scan_complete = False
    now = datetime.now()
    if current_user.last_upload_reset is None or (now - current_user.last_upload_reset).total_seconds() > 300:
        current_user.upload_count_window = 0
        current_user.last_upload_reset = now
        db.session.commit()
    
    if request.method == 'POST':
        files = request.files.getlist('files')
        if len(files) > 20:
            flash('單次上傳不可超過 20 張！', 'danger')
            return redirect(url_for('online_check'))
        if current_user.upload_count_window + len(files) > 20:
            flash(f'上傳頻率過高！每 5 分鐘限傳 20 張，目前剩餘 {20 - current_user.upload_count_window} 張。', 'danger')
            return redirect(url_for('online_check'))
        
        hashes = {}
        processed_count = 0
        for file in files:
            if file.filename == '': continue
            unique_name = str(uuid.uuid4()) + os.path.splitext(file.filename)[1]
            filepath = os.path.join(app.config['TEMP_FOLDER'], unique_name)
            file.save(filepath)
            file_hash = calculate_md5(filepath)
            file_obj = {'storage': unique_name, 'display': file.filename}
            if file_hash in hashes: hashes[file_hash].append(file_obj)
            else: hashes[file_hash] = [file_obj]
            processed_count += 1
        
        current_user.upload_count_window += processed_count
        db.session.commit()
        duplicates = {k: v for k, v in hashes.items() if len(v) > 1}
        scan_complete = True
    return render_template('online_check.html', duplicates=duplicates, scan_complete=scan_complete)

@app.route('/about')
def about():
    return render_template('about.html', announcements=Announcement.query.order_by(Announcement.created_at.desc()).all())

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, port=5000)
"""
write_file(os.path.join(SERVER_DIR, "app.py"), app_code)

# ==========================================
# 2. 寫入所有 Templates (確保檔案存在)
# ==========================================

# Base.html
base_html = """<!DOCTYPE html>
<html lang="zh-TW" data-bs-theme="light">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CR3 系統</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <style>
        body { background-color: #f3f6f9; font-family: 'Segoe UI', Roboto, sans-serif; transition: background-color 0.3s, color 0.3s; }
        .navbar { background-color: #ffffff !important; box-shadow: 0 4px 12px rgba(0,0,0,0.05); padding: 12px 0; }
        .navbar-brand { font-weight: 800; color: #4e73df !important; font-size: 1.4rem; }
        .main-container { max-width: 1140px; margin: 0 auto; padding: 40px 20px; }
        .card-custom { border: none; border-radius: 16px; box-shadow: 0 8px 24px rgba(0,0,0,0.06); background: #fff; overflow: hidden; margin-bottom: 30px; }
        
        [data-bs-theme="dark"] body { background-color: #121212; color: #e0e0e0; }
        [data-bs-theme="dark"] .navbar { background-color: #1e1e1e !important; border-bottom: 1px solid #333; }
        [data-bs-theme="dark"] .card-custom { background-color: #1e1e1e; color: #fff; border: 1px solid #333; }
        [data-bs-theme="dark"] .form-control { background-color: #2b2b2b; border-color: #444; color: #fff; }
        [data-bs-theme="dark"] .offcanvas { background-color: #1e1e1e; color: #fff; }
        [data-bs-theme="dark"] .btn-close { filter: invert(1); }
        [data-bs-theme="dark"] .list-group-item { background-color: #1e1e1e; color: #fff; border-color: #333; }
        [data-bs-theme="dark"] .modal-content { background-color: #1e1e1e; color: #fff; border: 1px solid #444; }

        .profile-header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); height: 180px; position: relative; }
        .profile-avatar-container { position: absolute; left: 50%; transform: translate(-50%, 50%); bottom: 0; width: 140px; height: 140px; }
        .profile-avatar { width: 100%; height: 100%; border-radius: 50%; border: 5px solid #fff; object-fit: cover; background-color: #fff; }
        .avatar-edit-btn { position: absolute; bottom: 0px; right: 0px; background: #fff; border-radius: 50%; width: 40px; height: 40px; display: flex; align-items: center; justify-content: center; box-shadow: 0 4px 8px rgba(0,0,0,0.3); cursor: pointer; color: #555; z-index: 20; transition: transform 0.2s; border: 2px solid #f0f2f5; }
        .avatar-edit-btn:hover { transform: scale(1.1); background-color: #f8f9fa; }

        .no-drag { user-select: none; }
        .offcanvas-header { background-color: #f8f9fa; border-bottom: 1px solid #dee2e6; }
        [data-bs-theme="dark"] .offcanvas-header { background-color: #2c2c2c; border-color: #444; }
        .cr3-logo-circle { width: 80px; height: 80px; background: linear-gradient(135deg, #4e73df, #224abe); color: white; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-weight: 900; font-size: 1.5rem; letter-spacing: 1px; margin: 0 auto 20px; box-shadow: 0 5px 15px rgba(78, 115, 223, 0.3); }
        .announcement-item { border-left: 4px solid #4e73df; background-color: rgba(78, 115, 223, 0.05); transition: transform 0.2s; }
        .announcement-item:hover { transform: translateX(5px); }
        .password-toggle-btn { cursor: pointer; border-left: none; z-index: 10; }
        .password-toggle-btn:hover { background-color: transparent; color: #4e73df; }
        .scrollable-box { max-height: 400px; overflow-y: auto; padding-right: 5px; }
        .scrollable-box::-webkit-scrollbar { width: 6px; }
        .scrollable-box::-webkit-scrollbar-track { background: #f1f1f1; border-radius: 10px; }
        .scrollable-box::-webkit-scrollbar-thumb { background: #ccc; border-radius: 10px; }
        
        .upload-area { border: 2px dashed #4e73df; background-color: rgba(78, 115, 223, 0.05); transition: all 0.3s; cursor: pointer; }
        .upload-area:hover { background-color: rgba(78, 115, 223, 0.1); transform: scale(1.01); }
        .filename-text { white-space: normal !important; word-break: break-all; font-size: 0.85rem; line-height: 1.4; }
        .preview-card img { cursor: zoom-in; transition: opacity 0.2s; }
        .preview-card img:hover { opacity: 0.9; }
        .zoom-container { overflow: hidden; cursor: crosshair; position: relative; background-color: #000; }
        .zoom-container img { transition: transform 0.1s ease-out; transform-origin: center center; width: 100%; display: block; }
        
        .presentation-container { position: relative; width: 100%; padding-bottom: 56.25%; height: 0; overflow: hidden; border-radius: 16px; box-shadow: 0 10px 30px rgba(0,0,0,0.1); background: #000; margin-bottom: 20px; }
        .presentation-container iframe { position: absolute; top: 0; left: 0; width: 100%; height: 100%; border: 0; }
    </style>
    <script>
        function restrictInput(input) { input.value = input.value.replace(/[^a-zA-Z0-9@._-]/g, ''); }
        function togglePassword(inputId, iconId) {
            const input = document.getElementById(inputId); const icon = document.getElementById(iconId);
            if (input.type === "password") { input.type = "text"; icon.classList.remove("fa-eye"); icon.classList.add("fa-eye-slash"); } 
            else { input.type = "password"; icon.classList.remove("fa-eye-slash"); icon.classList.add("fa-eye"); }
        }
    </script>
</head>
<body>
<nav class="navbar navbar-expand-lg sticky-top">
  <div class="container">
    <a class="navbar-brand" href="{{ url_for('index') }}"><i class="fas fa-images me-2"></i>CR3 系統</a>
    <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav"><span class="navbar-toggler-icon"></span></button>
    <div class="collapse navbar-collapse" id="navbarNav">
      <ul class="navbar-nav ms-auto align-items-center">
        {% if current_user.is_authenticated %}
            {% if current_user.role in ['admin', 'super_admin'] %}
                <li class="nav-item"><button class="btn btn-warning btn-sm fw-bold me-3 rounded-pill px-3 shadow-sm" type="button" data-bs-toggle="offcanvas" data-bs-target="#adminOffcanvas"><i class="fas fa-tools me-1"></i>管理選單</button></li>
            {% endif %}
            <li class="nav-item me-3"><a class="nav-link fw-bold" href="{{ url_for('profile') }}"><img src="{{ url_for('static', filename='avatars/' + current_user.avatar) }}" class="rounded-circle me-1" width="32" height="32" style="object-fit: cover;">{{ current_user.name }}</a></li>
            <li class="nav-item"><a class="nav-link" href="{{ url_for('logout') }}">登出</a></li>
        {% else %}
            <li class="nav-item"><a class="nav-link" href="{{ url_for('login') }}">登入</a></li>
        {% endif %}
        <li class="nav-item"><a class="nav-link" href="{{ url_for('about') }}">關於</a></li>
        <li class="nav-item"><a class="btn btn-outline-primary btn-sm ms-2 rounded-pill px-4" href="{{ url_for('online_check') }}">線上檢查</a></li>
        {% if current_user.is_authenticated %}
            <li class="nav-item ms-2"><a class="btn btn-primary btn-sm rounded-pill px-3" href="{{ url_for('download_app') }}"><i class="fas fa-download me-1"></i>EXE</a></li>
        {% endif %}
        <li class="nav-item ms-3"><button class="btn btn-light rounded-circle shadow-sm border" id="themeToggle" style="width: 40px; height: 40px;"><i class="fas fa-sun text-warning"></i></button></li>
      </ul>
    </div>
  </div>
</nav>

<div class="offcanvas offcanvas-end" tabindex="-1" id="adminOffcanvas">
  <div class="offcanvas-header"><h5 class="offcanvas-title fw-bold"><i class="fas fa-user-shield me-2"></i>管理員中心</h5><button type="button" class="btn-close text-reset" data-bs-dismiss="offcanvas"></button></div>
  <div class="offcanvas-body">
    <div class="list-group list-group-flush">
        <a href="{{ url_for('admin_dashboard') }}" class="list-group-item list-group-item-action border-0 py-3"><i class="fas fa-tachometer-alt me-3 text-primary"></i>儀表板總覽</a>
        <a href="{{ url_for('admin_dashboard') }}#announcements" class="list-group-item list-group-item-action border-0 py-3"><i class="fas fa-bullhorn me-3 text-danger"></i>系統公告管理</a>
        <a href="{{ url_for('admin_dashboard') }}#users" class="list-group-item list-group-item-action border-0 py-3"><i class="fas fa-users me-3 text-success"></i>會員管理</a>
        <a href="{{ url_for('admin_dashboard') }}#feedback" class="list-group-item list-group-item-action border-0 py-3"><i class="fas fa-envelope me-3 text-info"></i>意見信箱</a>
        {% if current_user.role == 'super_admin' %}<a href="{{ url_for('admin_dashboard') }}#admins" class="list-group-item list-group-item-action border-0 py-3"><i class="fas fa-key me-3 text-warning"></i>新增管理員</a>{% endif %}
    </div>
    <div class="mt-5 text-center text-muted small border-top pt-3">CR3 System v30.0</div>
  </div>
</div>

<div class="container py-5">
    {% with messages = get_flashed_messages(with_categories=true) %}
      {% if messages %}
        <div class="row justify-content-center mb-4"><div class="col-md-8">
            {% for category, message in messages %}<div class="alert alert-{{ category }} alert-dismissible fade show shadow-sm" role="alert">{{ message }}<button type="button" class="btn-close" data-bs-dismiss="alert"></button></div>{% endfor %}
        </div></div>
      {% endif %}
    {% endwith %}
    {% block content %}{% endblock %}
</div>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
<script>
    const toggleBtn = document.getElementById('themeToggle'); const htmlEl = document.documentElement; const icon = toggleBtn.querySelector('i');
    const savedTheme = localStorage.getItem('theme') || 'light'; htmlEl.setAttribute('data-bs-theme', savedTheme); updateIcon(savedTheme);
    toggleBtn.addEventListener('click', () => { const newTheme = htmlEl.getAttribute('data-bs-theme') === 'light' ? 'dark' : 'light'; htmlEl.setAttribute('data-bs-theme', newTheme); localStorage.setItem('theme', newTheme); updateIcon(newTheme); });
    function updateIcon(theme) { if (theme === 'dark') { icon.className = 'fas fa-moon text-white'; toggleBtn.className = 'btn btn-dark border-secondary'; } else { icon.className = 'fas fa-sun text-warning'; toggleBtn.className = 'btn btn-light border'; } }
</script>
</body>
</html>
"""
write_file(os.path.join(TEMPLATE_DIR, "base.html"), base_html)

# Index.html
index_html = """{% extends "base.html" %}
{% block content %}
<div class="text-center py-5">
    <h1 class="display-4 fw-bold mb-3">CR3 相同照片檢查系統</h1>
    <p class="lead text-muted mb-5">專為攝影師設計的邊緣運算解決方案。<br>快速篩選大量 RAW 檔，節省您的時間與硬碟空間。</p>
    
    <div class="row justify-content-center mb-5">
        <div class="col-md-8">
            <div class="card card-custom p-5 text-center">
                <div class="d-flex flex-column align-items-center justify-content-center">
                    <div class="mb-3 text-primary"><i class="fas fa-download fa-4x"></i></div>
                    <h3 class="fw-bold mb-2">下載 Desktop App (.exe)</h3>
                    <p class="mb-4 text-muted">v1.0.2 | Windows 10/11 | 專為 CR3 優化</p>
                    {% if current_user.is_authenticated %}
                        <a href="{{ url_for('download_app') }}" class="btn btn-primary rounded-pill px-5 btn-lg">立即下載</a>
                    {% else %}
                        <a href="{{ url_for('login') }}" class="btn btn-secondary rounded-pill px-5 btn-lg">登入後下載</a>
                    {% endif %}
                </div>
            </div>
        </div>
    </div>

    <div class="row justify-content-center">
        <div class="col-md-10">
            <h3 class="fw-bold mb-4 text-start"><i class="fas fa-presentation me-2"></i>系統功能介紹 (簡報)</h3>
            <div class="presentation-container">
                <iframe loading="lazy" style="position: absolute; width: 100%; height: 100%; top: 0; left: 0; border: none; padding: 0;margin: 0;"
                    src="https://www.canva.com/design/DAG95dzxg_Y/tO4aTyMdoTYQGrVpDq81DA/view?embed" allowfullscreen="allowfullscreen" allow="fullscreen">
                </iframe>
            </div>
            <p class="text-muted mt-3 small">
                <a href="https://www.canva.com/design/DAG95dzxg_Y/tO4aTyMdoTYQGrVpDq81DA/view?utm_content=DAG95dzxg_Y&amp;utm_campaign=designshare&amp;utm_medium=embeds&amp;utm_source=link" target="_blank" rel="noopener">CR3 Smart Checker Presentation</a> by 111534105 田心于
            </p>
        </div>
    </div>
</div>
{% endblock %}
"""
write_file(os.path.join(TEMPLATE_DIR, "index.html"), index_html)

# Login.html
login_html = """{% extends "base.html" %}{% block content %}<div class="row justify-content-center align-items-center" style="min-height: 70vh;"><div class="col-md-5"><div class="card card-custom p-5"><h2 class="text-center fw-bold mb-4">使用者登入</h2><form method="POST"><div class="mb-3"><label class="form-label fw-bold">Email</label><input type="email" class="form-control" name="email" required oninput="restrictInput(this)"></div><div class="mb-4"><label class="form-label fw-bold">密碼</label><div class="input-group"><input type="password" class="form-control" name="password" id="loginPass" required oninput="restrictInput(this)"><span class="input-group-text bg-white password-toggle-btn" onclick="togglePassword('loginPass', 'eyeLoginPass')"><i class="fas fa-eye" id="eyeLoginPass"></i></span></div></div><button type="submit" class="btn btn-primary w-100 btn-lg">登入</button></form><div class="text-center mt-3"><a href="{{ url_for('forgot_password') }}" class="text-danger me-3">忘記密碼?</a><a href="{{ url_for('register') }}">註冊帳號</a></div></div></div></div>{% endblock %}"""
write_file(os.path.join(TEMPLATE_DIR, "login.html"), login_html)

# Register.html
register_html = """{% extends "base.html" %}{% block content %}<div class="row justify-content-center align-items-center" style="min-height: 70vh;"><div class="col-md-5"><div class="card card-custom p-5"><h2 class="text-center fw-bold mb-4">使用者註冊</h2><form method="POST"><div class="mb-3"><label class="form-label fw-bold">暱稱 (可輸入中文)</label><input type="text" class="form-control" name="name" required></div><div class="mb-3"><label class="form-label fw-bold">Email</label><input type="email" class="form-control" name="email" required oninput="restrictInput(this)"></div><div class="mb-4"><label class="form-label fw-bold">密碼 (僅限英數)</label><div class="input-group"><input type="password" class="form-control" name="password" id="regPass" required oninput="restrictInput(this)"><span class="input-group-text bg-white password-toggle-btn" onclick="togglePassword('regPass', 'eyeRegPass')"><i class="fas fa-eye" id="eyeRegPass"></i></span></div></div><button type="submit" class="btn btn-primary w-100 btn-lg">註冊</button></form><div class="text-center mt-3"><a href="{{ url_for('login') }}">返回登入</a></div></div></div></div>{% endblock %}"""
write_file(os.path.join(TEMPLATE_DIR, "register.html"), register_html)

# Forgot Password.html
forgot_html = """{% extends "base.html" %}{% block content %}<div class="row justify-content-center pt-5"><div class="col-md-5"><div class="card card-custom p-5"><h3 class="fw-bold text-center mb-4">忘記密碼</h3>{% if step == 1 %}<form method="POST"><input type="hidden" name="step" value="1"><div class="mb-3"><label class="form-label">請輸入您的註冊 Email</label><input type="email" class="form-control" name="email" required oninput="restrictInput(this)"></div><button type="submit" class="btn btn-primary w-100 rounded-pill">發送驗證碼</button></form>{% elif step == 2 %}<form method="POST"><input type="hidden" name="step" value="2"><input type="hidden" name="email" value="{{ email }}"><div class="alert alert-info">驗證碼已寄送到 {{ email }}</div><div class="mb-3"><label class="form-label">6位數驗證碼</label><input type="text" class="form-control text-center" name="code" placeholder="000000" maxlength="6" style="letter-spacing: 5px; font-size: 1.5rem;" required oninput="this.value = this.value.replace(/[^0-9]/g, '')"></div><div class="mb-3"><label class="form-label">設定新密碼</label><div class="input-group"><input type="password" class="form-control" name="new_password" id="newPass" required oninput="restrictInput(this)"><span class="input-group-text bg-white password-toggle-btn" onclick="togglePassword('newPass', 'eyeNewPass')"><i class="fas fa-eye" id="eyeNewPass"></i></span></div><div class="form-text">僅允許英文與數字</div></div><button type="submit" class="btn btn-success w-100 rounded-pill">重置密碼</button></form>{% endif %}<div class="text-center mt-3"><a href="{{ url_for('login') }}">返回登入</a></div></div></div></div>{% endblock %}"""
write_file(os.path.join(TEMPLATE_DIR, "forgot_password.html"), forgot_html)

# About.html
about_html = """{% extends "base.html" %}{% block content %}<div class="row justify-content-center"><div class="col-md-6 mb-4"><div class="card card-custom p-5 h-100"><div class="text-center mb-4"><div class="cr3-logo-circle mb-3">CR3</div><h3 class="fw-bold">關於 CR3 系統</h3><p class="text-muted mt-2">製作人：111534105 田心于</p></div><hr class="my-4"><h5 class="fw-bold mb-3"><i class="fas fa-bullhorn text-danger me-2"></i>系統更新通知</h5><div class="announcement-list scrollable-box">{% if announcements %}{% for item in announcements %}<div class="announcement-item p-3 mb-3 rounded"><div class="d-flex justify-content-between align-items-center mb-1"><span class="badge bg-primary rounded-pill">#{{ item.id }}</span><small class="text-muted">{{ item.created_at.strftime('%Y-%m-%d') }}</small></div><h6 class="fw-bold mb-1">{{ item.title }}</h6><p class="mb-0 small text-muted">{{ item.content }}</p></div>{% endfor %}{% else %}<p class="text-muted text-center py-3">目前沒有系統公告。</p>{% endif %}</div></div></div><div class="col-md-6 mb-4"><div class="card card-custom h-100"><div class="card-body p-5"><h3 class="fw-bold mb-4 text-center">意見信箱</h3><form method="POST" action="{{ url_for('submit_feedback') }}"><div class="row"><div class="col-md-6 mb-3"><label class="form-label fw-bold small">您的姓名</label><input type="text" class="form-control" name="name" value="{{ current_user.name if current_user.is_authenticated else '' }}" required></div><div class="col-md-6 mb-3"><label class="form-label fw-bold small">您的 Email</label><input type="email" class="form-control" name="email" value="{{ current_user.email if current_user.is_authenticated else '' }}" required oninput="restrictInput(this)"></div></div><div class="mb-3"><label class="form-label fw-bold small">主旨 (限 50 字)</label><input type="text" class="form-control" name="subject" maxlength="50" required></div><div class="mb-4"><label class="form-label fw-bold small">內容 (限 500 字)</label><textarea class="form-control" name="message" rows="6" maxlength="500" required></textarea></div><div class="d-grid"><button type="submit" class="btn btn-primary btn-lg rounded-pill shadow-sm">確認送出</button></div></form></div></div></div></div>{% endblock %}"""
write_file(os.path.join(TEMPLATE_DIR, "about.html"), about_html)

# Profile.html
profile_html = """{% extends "base.html" %}{% block content %}<div class="row justify-content-center"><div class="col-md-9 col-lg-8"><div class="card card-custom mb-5"><div class="profile-header"><div class="profile-avatar-container"><img src="{{ url_for('static', filename='avatars/' + current_user.avatar) }}" class="profile-avatar shadow" onerror="this.src='https://ui-avatars.com/api/?name={{ current_user.name }}&background=random&size=150'"><label for="avatarUpload" class="avatar-edit-btn" title="更換頭像"> <i class="fas fa-camera"></i> </label> <form id="avatarForm" action="{{ url_for('upload_avatar') }}" method="POST" enctype="multipart/form-data" style="display: none;"> <input type="file" id="avatarUpload" name="avatar" accept="image/*" onchange="document.getElementById('avatarForm').submit();"> </form> </div> </div> <div class="card-body pt-5 px-5 pb-5"> <div class="text-center mt-5 mb-5"> <h2 class="fw-bold">{{ current_user.name }}</h2> {% if current_user.role in ['admin', 'super_admin'] %} <span class="badge bg-warning text-dark mb-2">ADMIN 管理員</span> {% endif %} <p class="text-muted">{{ current_user.email }}</p> </div> <hr class="my-5"> <h4 class="fw-bold mb-4"><i class="fas fa-user-edit me-2 text-primary"></i>基本資料</h4> <form method="POST" action="{{ url_for('update_profile') }}"> <div class="row g-4"> <div class="col-md-6"> <label class="form-label fw-bold text-muted">暱稱</label> <input type="text" class="form-control" name="name" value="{{ current_user.name }}"> </div> <div class="col-md-6"> <label class="form-label fw-bold text-muted">國家 / 地區 (15大國)</label> <select class="form-select" name="country"> <option value="台灣" {% if current_user.country == '台灣' %}selected{% endif %}>🇹🇼 台灣 (Taiwan)</option> <option value="美國" {% if current_user.country == '美國' %}selected{% endif %}>🇺🇸 美國 (USA)</option> <option value="中國" {% if current_user.country == '中國' %}selected{% endif %}>🇨🇳 中國 (China)</option> <option value="日本" {% if current_user.country == '日本' %}selected{% endif %}>🇯🇵 日本 (Japan)</option> <option value="德國" {% if current_user.country == '德國' %}selected{% endif %}>🇩🇪 德國 (Germany)</option> <option value="印度" {% if current_user.country == '印度' %}selected{% endif %}>🇮🇳 印度 (India)</option> <option value="英國" {% if current_user.country == '英國' %}selected{% endif %}>🇬🇧 英國 (UK)</option> <option value="法國" {% if current_user.country == '法國' %}selected{% endif %}>🇫🇷 法國 (France)</option> <option value="義大利" {% if current_user.country == '義大利' %}selected{% endif %}>🇮🇹 義大利 (Italy)</option> <option value="巴西" {% if current_user.country == '巴西' %}selected{% endif %}>🇧🇷 巴西 (Brazil)</option> <option value="加拿大" {% if current_user.country == '加拿大' %}selected{% endif %}>🇨🇦 加拿大 (Canada)</option> <option value="韓國" {% if current_user.country == '韓國' %}selected{% endif %}>🇰🇷 韓國 (Korea)</option> <option value="俄羅斯" {% if current_user.country == '俄羅斯' %}selected{% endif %}>🇷🇺 俄羅斯 (Russia)</option> <option value="澳洲" {% if current_user.country == '澳洲' %}selected{% endif %}>🇦🇺 澳洲 (Australia)</option> <option value="西班牙" {% if current_user.country == '西班牙' %}selected{% endif %}>🇪🇸 西班牙 (Spain)</option> <option value="印尼" {% if current_user.country == '印尼' %}selected{% endif %}>🇮🇩 印尼 (Indonesia)</option> <option value="其他" {% if current_user.country == '其他' %}selected{% endif %}>🏳️ 其他 (Other)</option> </select> </div> <div class="col-md-6"> <label class="form-label fw-bold text-muted">偏好語言</label> <select class="form-select" name="language"> <option value="zh-TW" {% if current_user.language == 'zh-TW' %}selected{% endif %}>繁體中文</option> <option value="en-US" {% if current_user.language == 'en-US' %}selected{% endif %}>English</option> </select> </div> <div class="col-md-6"> <label class="form-label fw-bold text-muted">註冊日期</label> <input type="text" class="form-control" value="{{ current_user.created_at.strftime('%Y/%m/%d') }}" disabled> </div> </div> <div class="text-end mt-4"> <button type="submit" class="btn btn-primary px-5 rounded-pill shadow-sm">儲存變更</button> </div> </form> <hr class="my-5"> <h4 class="fw-bold mb-4"><i class="fas fa-shield-alt me-2 text-danger"></i>帳號安全</h4> <div class="accordion" id="securityAccordion"> <div class="accordion-item border rounded mb-3 overflow-hidden"> <h2 class="accordion-header"> <button class="accordion-button collapsed bg-light" type="button" data-bs-toggle="collapse" data-bs-target="#collapsePass"> <span class="fw-bold"><i class="fas fa-key me-2"></i>變更密碼</span> </button> </h2> <div id="collapsePass" class="accordion-collapse collapse" data-bs-parent="#securityAccordion"> <div class="accordion-body"> <form method="POST" action="{{ url_for('change_password') }}"> <div class="mb-3"><div class="input-group"><input type="password" class="form-control" name="current_password" id="curPass" placeholder="目前密碼" required oninput="restrictInput(this)"><span class="input-group-text bg-white password-toggle-btn" onclick="togglePassword('curPass', 'eyeCurPass')"><i class="fas fa-eye" id="eyeCurPass"></i></span></div></div> <div class="mb-3"><div class="input-group"><input type="password" class="form-control" name="new_password" id="newProfPass" placeholder="新密碼 (限英數)" required oninput="restrictInput(this)"><span class="input-group-text bg-white password-toggle-btn" onclick="togglePassword('newProfPass', 'eyeNewProfPass')"><i class="fas fa-eye" id="eyeNewProfPass"></i></span></div></div> <button type="submit" class="btn btn-danger w-100">確認變更</button> </form> </div> </div> </div> <div class="accordion-item border rounded overflow-hidden"> <h2 class="accordion-header"> <button class="accordion-button collapsed bg-light" type="button" data-bs-toggle="collapse" data-bs-target="#collapseEmail"> <span class="fw-bold"><i class="fas fa-envelope me-2"></i>變更信箱</span> </button> </h2> <div id="collapseEmail" class="accordion-collapse collapse" data-bs-parent="#securityAccordion"> <div class="accordion-body"> <form method="POST" action="{{ url_for('change_email') }}"> <div class="mb-3"><input type="email" class="form-control" name="new_email" placeholder="新電子信箱 (限英數)" required oninput="restrictInput(this)"></div> <div class="mb-3"><input type="password" class="form-control" name="password_verify" placeholder="輸入密碼驗證 (限英數)" required oninput="restrictInput(this)"></div> <button type="submit" class="btn btn-warning w-100">變更信箱</button> </form> </div> </div> </div> </div> </div> </div> </div> </div> {% endblock %}"""
write_file(os.path.join(TEMPLATE_DIR, "profile.html"), profile_html)

# Admin.html
admin_html = """{% extends "base.html" %}{% block content %}<div class="container"><div class="d-flex justify-content-between align-items-center mb-4"><h2 class="fw-bold"><i class="fas fa-crown me-2 text-warning"></i>後台管理中心</h2><span class="badge bg-secondary">{{ current_user.role|upper }}</span></div><div class="row mb-5"><div class="col-md-4"><div class="card card-custom p-4 text-center border-start border-5 border-primary"><h5 class="text-primary fw-bold text-uppercase mb-2">總會員數</h5><h1 class="display-4 fw-bold mb-0">{{ users|length }}</h1></div></div><div class="col-md-4"><div class="card card-custom p-4 text-center border-start border-5 border-success"><h5 class="text-success fw-bold text-uppercase mb-2">軟體下載次數</h5><h1 class="display-4 fw-bold mb-0">{{ total_downloads }}</h1></div></div><div class="col-md-4"><div class="card card-custom p-4 text-center border-start border-5 border-danger"><h5 class="text-danger fw-bold text-uppercase mb-2">異常警告帳號</h5><h1 class="display-4 fw-bold mb-0">{{ flagged_count }}</h1></div></div></div><div id="announcements" class="card card-custom p-4 mb-5 border-danger" style="border-left: 5px solid #dc3545;"><h4 class="fw-bold mb-3">系統公告管理</h4><form action="{{ url_for('add_announcement') }}" method="POST" class="mb-4"><div class="row g-2 align-items-center"><div class="col-md-3"><input type="text" class="form-control" name="title" placeholder="公告標題" required></div><div class="col-md-7"><input type="text" class="form-control" name="content" placeholder="公告內容..." required></div><div class="col-md-2"><button type="submit" class="btn btn-danger w-100"><i class="fas fa-plus me-1"></i>發布</button></div></div></form><div class="table-responsive"><table class="table table-sm table-hover align-middle"><thead><tr><th>ID</th><th>日期</th><th>標題</th><th>內容摘要</th><th>操作</th></tr></thead><tbody>{% for ann in announcements %}<tr><td>{{ ann.id }}</td><td>{{ ann.created_at.strftime('%Y-%m-%d') }}</td><td>{{ ann.title }}</td><td class="text-truncate" style="max-width: 300px;">{{ ann.content }}</td><td>{% if current_user.role == 'super_admin' %}<button class="btn btn-sm btn-outline-primary me-1" data-bs-toggle="modal" data-bs-target="#editAnn{{ ann.id }}">修改</button><a href="{{ url_for('delete_announcement', ann_id=ann.id) }}" class="btn btn-sm btn-outline-danger" onclick="return confirm('確定刪除？')">刪除</a>{% else %}<span class="text-muted small">無權限</span>{% endif %}</td></tr><div class="modal fade" id="editAnn{{ ann.id }}"><div class="modal-dialog"><div class="modal-content"><form action="{{ url_for('edit_announcement', ann_id=ann.id) }}" method="POST"><div class="modal-header"><h5 class="modal-title">修改公告</h5><button type="button" class="btn-close" data-bs-dismiss="modal"></button></div><div class="modal-body"><div class="mb-3"><label>標題</label><input type="text" class="form-control" name="title" value="{{ ann.title }}" required></div><div class="mb-3"><label>內容</label><textarea class="form-control" name="content" rows="3" required>{{ ann.content }}</textarea></div></div><div class="modal-footer"><button type="submit" class="btn btn-primary">儲存</button></div></form></div></div></div>{% endfor %}</tbody></table></div></div><div id="users" class="card card-custom p-4 mb-5"><h4 class="fw-bold mb-4 border-bottom pb-2">會員列表管理</h4><div class="table-responsive"><table class="table table-hover align-middle"><thead class="table-light"><tr><th>狀態</th><th>ID</th><th>使用者</th><th>權限</th><th>下載數</th><th>驗證次數</th><th>操作</th></tr></thead><tbody>{% for user in users %}<tr class="{{ 'table-danger' if user.is_restricted else '' }}"><td>{{ '<i class="fas fa-exclamation-triangle text-danger"></i>'|safe if user.is_restricted else '<i class="fas fa-check-circle text-success"></i>'|safe }}</td><td>{{ user.id }}</td><td><div class="d-flex align-items-center"><img src="{{ url_for('static', filename='avatars/' + user.avatar) }}" width="35" height="35" class="rounded-circle me-3"><div>{{ user.name }}<br><small class="text-muted">{{ user.email }}</small></div></div></td><td><span class="badge bg-secondary">{{ user.role }}</span></td><td>{{ user.download_count }}</td><td>{{ user.verification_attempts_total }}</td><td>{% if current_user.role == 'super_admin' %}<div class="btn-group"><button class="btn btn-sm btn-outline-primary" data-bs-toggle="modal" data-bs-target="#editUser{{ user.id }}">修改</button>{% if user.is_restricted %}<a href="{{ url_for('unflag_user', user_id=user.id) }}" class="btn btn-sm btn-success">解除</a>{% else %}<a href="{{ url_for('flag_user', user_id=user.id) }}" class="btn btn-sm btn-outline-warning">管制</a>{% endif %}<a href="{{ url_for('delete_user', user_id=user.id) }}" class="btn btn-sm btn-outline-danger" onclick="return confirm('確定刪除此使用者？')"><i class="fas fa-trash"></i></a></div>{% else %}<span class="text-muted small">僅檢視</span>{% endif %}</td></tr>{% if current_user.role == 'super_admin' %}<div class="modal fade" id="editUser{{ user.id }}"><div class="modal-dialog"><div class="modal-content"><form action="{{ url_for('admin_edit_user', user_id=user.id) }}" method="POST"><div class="modal-header"><h5 class="modal-title">修改: {{ user.name }}</h5></div><div class="modal-body"><div class="mb-3"><label>Email</label><input type="email" class="form-control" name="email" value="{{ user.email }}"></div><div class="mb-3"><label>重置密碼</label><input type="password" class="form-control" name="password" placeholder="留空則不修改"></div></div><div class="modal-footer"><button type="submit" class="btn btn-primary">儲存</button></div></form></div></div></div>{% endif %}{% endfor %}</tbody></table></div></div><div id="feedback" class="card card-custom p-4 mb-5"><h4 class="fw-bold mb-4 border-bottom pb-2">意見信箱</h4><div class="table-responsive"><table class="table table-hover"><thead class="table-light"><tr><th>日期</th><th>姓名</th><th>主旨</th><th>內容</th></tr></thead><tbody>{% for fb in feedbacks %}<tr><td style="white-space:nowrap">{{ fb.created_at.strftime('%Y-%m-%d') }}</td><td>{{ fb.name }}</td><td>{{ fb.subject }}</td><td>{{ fb.message }}</td></tr>{% endfor %}</tbody></table></div></div>{% if current_user.role == 'super_admin' %}<div id="admins" class="card card-custom p-4 mb-5 border-warning" style="border-left: 5px solid #ffc107;"><h4 class="fw-bold mb-3">新增其他管理員</h4><form action="{{ url_for('create_admin') }}" method="POST" class="row g-3"><div class="col-md-4"><input type="email" class="form-control" name="email" placeholder="Email (防呆)" required oninput="restrictInput(this)"></div><div class="col-md-4"><input type="password" class="form-control" name="password" placeholder="Password (防呆)" required oninput="restrictInput(this)"></div><div class="col-md-3"><input type="text" class="form-control" name="name" placeholder="Name" required></div><div class="col-md-1"><button type="submit" class="btn btn-warning w-100">新增</button></div></form></div>{% endif %}</div>{% endblock %}"""
write_file(os.path.join(TEMPLATE_DIR, "admin.html"), admin_html)

# Online_Check.html
online_check_html = """{% extends "base.html" %}{% block content %}<div class="row justify-content-center mt-4"><div class="col-md-10"><div class="card card-custom mb-4"><div class="card-body pt-3"><h5 class="fw-bold mb-3"><i class="fas fa-book-open me-2 text-primary"></i>使用教學</h5><ol class="mb-0 text-muted" style="line-height: 1.8;"><li>點擊下方區塊選擇照片，或直接<strong>拖曳照片</strong>至框框內 (JPG/PNG)。</li><li>系統會自動計算雜湊值比對重複內容。</li><li>檢查結果會顯示上傳的<strong>原始檔案名稱</strong>。</li><li>點擊結果圖片可開啟<strong>放大鏡檢視</strong>。</li><li>每個帳號每 5 分鐘最多上傳 20 張照片做判斷。</li><li class="text-danger">本系統不永久儲存照片！每 15 分鐘系統會自動清除暫存檔，以節省伺服器空間。</li></ol></div></div><div class="card card-custom p-5 border-dashed border-2 text-center upload-area" onclick="document.getElementById('fileInput').click();" ondragover="event.preventDefault(); this.style.backgroundColor='rgba(78,115,223,0.2)';" ondragleave="this.style.backgroundColor='rgba(78,115,223,0.05)';" ondrop="event.preventDefault(); this.style.backgroundColor='rgba(78,115,223,0.05)'; document.getElementById('fileInput').files = event.dataTransfer.files; document.getElementById('uploadForm').submit();"><div class="card-body"><form id="uploadForm" method="POST" enctype="multipart/form-data"><div class="mb-4"><i class="fas fa-cloud-upload-alt fa-3x text-primary"></i></div><h4 class="mb-2">拖曳或點擊上傳照片</h4><p class="text-muted small">支援 JPG / PNG，單次限 20 張</p><input type="file" id="fileInput" class="d-none" name="files" multiple accept=".png, .jpg, .jpeg" onchange="document.getElementById('uploadForm').submit();"><button type="button" class="btn btn-primary btn-lg px-5 rounded-pill shadow" onclick="document.getElementById('fileInput').click();">選擇檔案</button></form></div></div>{% if duplicates %}<h3 class="fw-bold text-danger mb-4"><i class="fas fa-exclamation-circle me-2"></i>發現重複群組</h3>{% for hash_val, file_list in duplicates.items() %}<div class="duplicate-group border border-danger p-3 rounded mb-3 bg-white"><h5 class="fw-bold mb-3 text-danger">重複群組 #{{ loop.index }}</h5><div class="row g-3">{% for file_obj in file_list %}<div class="col-md-3 col-6"><div class="card border shadow-sm preview-card"><img src="{{ url_for('static', filename='uploads/' + file_obj.storage) }}" class="card-img-top" style="height: 150px; object-fit: cover;" onclick="showImage(this.src, '{{ file_obj.display }}')"><div class="card-footer bg-white p-2"><small class="d-block filename-text" title="{{ file_obj.display }}">{{ file_obj.display }}</small></div></div></div>{% endfor %}</div></div>{% endfor %}{% endif %}</div></div>{% if scan_complete %}<div class="modal fade" id="scanResultModal" tabindex="-1"><div class="modal-dialog modal-dialog-centered"><div class="modal-content"><div class="modal-header {{ 'bg-danger text-white' if duplicates else 'bg-success text-white' }}"><h5 class="modal-title fw-bold">{% if duplicates %}<i class="fas fa-exclamation-triangle me-2"></i>掃描完成！發現重複{% else %}<i class="fas fa-check-circle me-2"></i>掃描完成！無重複{% endif %}</h5><button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button></div><div class="modal-body text-center py-4">{% if duplicates %}<h4 class="text-danger fw-bold">共發現 {{ duplicates|length }} 組重複照片</h4><p class="text-muted">請往下滑動查看詳細比對結果。</p>{% else %}<h4 class="text-success fw-bold">恭喜！</h4><p class="text-muted">您上傳的照片中沒有發現任何重複內容。</p>{% endif %}</div><div class="modal-footer"><button type="button" class="btn btn-secondary" data-bs-dismiss="modal">關閉</button></div></div></div></div><script>document.addEventListener("DOMContentLoaded", function(){var myModal = new bootstrap.Modal(document.getElementById('scanResultModal'));myModal.show();});</script>{% endif %}<div class="modal fade" id="imageZoomModal" tabindex="-1"><div class="modal-dialog modal-dialog-centered modal-lg"><div class="modal-content bg-dark"><div class="modal-header border-0"><h6 class="modal-title text-white" id="zoomModalTitle"></h6><button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button></div><div class="modal-body text-center p-0"><div class="zoom-container" id="zoomContainer" onmousemove="zoom(event)" onmouseleave="resetZoom()"><img id="zoomedImage" src=""></div></div></div></div></div><script>function showImage(src, filename) {document.getElementById('zoomedImage').src = src;document.getElementById('zoomModalTitle').innerText = filename;var zoomModal = new bootstrap.Modal(document.getElementById('imageZoomModal'));zoomModal.show();} function zoom(e) {var zoomer = e.currentTarget; var img = zoomer.querySelector('img'); var offsetX = e.offsetX; var offsetY = e.offsetY; var x = offsetX / zoomer.offsetWidth * 100; var y = offsetY / zoomer.offsetHeight * 100; img.style.transformOrigin = x + '% ' + y + '%'; img.style.transform = 'scale(2.5)';} function resetZoom() {var img = document.getElementById('zoomedImage'); img.style.transform = 'scale(1)';}</script>{% endblock %}"""
write_file(os.path.join(TEMPLATE_DIR, "online_check.html"), online_check_html)

print("\n🎉 修復完成！請執行: python run_server.py")