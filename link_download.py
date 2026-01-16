import os
import shutil

# 取得根目錄
BASE_DIR = os.getcwd()
DIST_DIR = os.path.join(BASE_DIR, "dist")
STATIC_DIR = os.path.join(BASE_DIR, "server", "static")
APP_PY_PATH = os.path.join(BASE_DIR, "server", "app.py")

print("🚀 開始串接 EXE 下載功能...")

# 1. 搬運 EXE 檔案
exe_name = "CR3_Check_Tool.exe"
src_exe = os.path.join(DIST_DIR, exe_name)
dst_exe = os.path.join(STATIC_DIR, exe_name)

if os.path.exists(src_exe):
    print(f"📦 發現 EXE 檔：{src_exe}")
    # 確保 static 資料夾存在
    os.makedirs(STATIC_DIR, exist_ok=True)
    # 複製檔案
    shutil.copy(src_exe, dst_exe)
    print(f"✅ 已將 EXE 部署至網站目錄：{dst_exe}")
else:
    print("❌ 警告：在 dist 資料夾找不到 .exe 檔！")
    print("   -> 請確認你有執行過 'python build_exe.py'")
    # 這裡不終止，繼續更新代碼，以免你之後補上檔案還要再跑一次

# 2. 更新 server/app.py 的下載邏輯
# 我們直接整份覆蓋 app.py，確保邏輯最正確，並加入 send_file 功能
new_app_code = """
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

# 取得路徑
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEMPLATE_DIR = os.path.join(BASE_DIR, 'templates')
STATIC_DIR = os.path.join(BASE_DIR, 'static')

app = Flask(__name__, template_folder=TEMPLATE_DIR, static_folder=STATIC_DIR)

app.config['SECRET_KEY'] = 'your_secret_key'
DB_PATH = os.path.join(BASE_DIR, 'instance', 'cms.db')
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{DB_PATH}'

GMAIL_USER = 'kimminnie20081127@gmail.com'
GMAIL_APP_PASS = 'eztu zvkj tmqd ciml' 

app.config['UPLOAD_FOLDER'] = os.path.join(STATIC_DIR, 'avatars')
app.config['TEMP_FOLDER'] = os.path.join(STATIC_DIR, 'uploads')

os.makedirs(os.path.join(BASE_DIR, 'instance'), exist_ok=True)

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# 自動清理
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
        except: pass
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
    except: return False

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
def load_user(user_id): return User.query.get(int(user_id))

def calculate_md5(file_path):
    hash_md5 = hashlib.md5()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""): hash_md5.update(chunk)
    return hash_md5.hexdigest()

@app.route('/')
def index(): return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(email=request.form.get('email')).first()
        if not user: flash('此帳號不存在，請先註冊。', 'danger')
        elif not check_password_hash(user.password, request.form.get('password')): flash('密碼錯誤，請重試。', 'danger')
        else:
            login_user(user)
            if user.is_restricted: flash('⚠️ 您的帳號已被列為觀察名單。', 'warning')
            return redirect(url_for('profile'))
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        if User.query.filter_by(email=request.form.get('email')).first(): flash('Email 已存在', 'warning')
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
                    flash('⚠️ 帳號異常，請等待 5 分鐘後再試。', 'danger'); return render_template('forgot_password.html', step=1, email=email)
                if user.last_request_time and (now - user.last_request_time).total_seconds() < 60: user.verification_attempts += 1
                else: user.verification_attempts = 1
                user.last_request_time = now; user.verification_attempts_total += 1
                if user.verification_attempts > 3:
                    user.is_restricted = True; db.session.commit(); flash('⚠️ 警告：請求過於頻繁，已限制 5 分鐘。', 'danger'); return render_template('forgot_password.html', step=1, email=email)
                code = ''.join(random.choices(string.digits, k=6)); user.verification_code = code; db.session.commit()
                send_email_via_gmail(user.email, "【CR3 系統】重置密碼驗證碼", f"您的驗證碼：{code}")
                flash('驗證碼已寄出', 'info'); step = 2; email = user.email
            else: flash('找不到此 Email', 'danger')
        elif step_val == '2':
            user = User.query.filter_by(email=request.form.get('email')).first()
            if user and user.verification_code == request.form.get('code'):
                user.password = generate_password_hash(request.form.get('new_password')); user.verification_code = None; db.session.commit()
                flash('密碼重置成功', 'success'); return redirect(url_for('login'))
            else: flash('驗證碼錯誤', 'danger'); step = 2; email = request.form.get('email')
    return render_template('forgot_password.html', step=step, email=email)

# --- 核心修改：真的下載 EXE ---
@app.route('/download_app')
@login_required
def download_app():
    # 檔案路徑
    exe_path = os.path.join(STATIC_DIR, 'CR3_Check_Tool.exe')
    
    if os.path.exists(exe_path):
        current_user.download_count += 1
        db.session.commit()
        # 這裡會觸發瀏覽器下載
        return send_file(exe_path, as_attachment=True, download_name='CR3_Check_Tool.exe')
    else:
        # 如果檔案還沒搬過去
        flash('⚠️ 系統維護中：暫時無法下載安裝檔 (File Not Found)', 'danger')
        return redirect(url_for('index'))

@app.route('/profile')
@login_required
def profile(): return render_template('profile.html')

@app.route('/update_profile', methods=['POST'])
@login_required
def update_profile():
    current_user.name = request.form.get('name'); current_user.country = request.form.get('country'); current_user.language = request.form.get('language')
    db.session.commit(); return redirect(url_for('profile'))

@app.route('/upload_avatar', methods=['POST'])
@login_required
def upload_avatar():
    file = request.files.get('avatar')
    if file:
        filename = f"user_{current_user.id}_{int(datetime.now().timestamp())}.png"
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        current_user.avatar = filename; db.session.commit()
    return redirect(url_for('profile'))

@app.route('/change_password', methods=['POST'])
@login_required
def change_password():
    if check_password_hash(current_user.password, request.form.get('current_password')):
        if check_password_hash(current_user.password, request.form.get('new_password')):
            flash('新密碼不能與目前密碼相同！', 'warning'); return redirect(url_for('profile'))
        current_user.password = generate_password_hash(request.form.get('new_password'))
        db.session.commit(); logout_user(); flash('密碼已變更，請重新登入', 'success'); return redirect(url_for('login'))
    flash('目前密碼輸入錯誤', 'danger'); return redirect(url_for('profile'))

@app.route('/change_email', methods=['POST'])
@login_required
def change_email():
    if check_password_hash(current_user.password, request.form.get('password_verify')):
        if User.query.filter_by(email=request.form.get('new_email')).first(): flash('該信箱已被使用', 'warning')
        else: current_user.email = request.form.get('new_email'); db.session.commit(); flash('信箱變更成功', 'success')
    else: flash('密碼錯誤', 'danger')
    return redirect(url_for('profile'))

@app.route('/admin')
@login_required
def admin_dashboard():
    if current_user.role not in ['admin', 'super_admin']: return redirect(url_for('index'))
    return render_template('admin.html', users=User.query.all(), feedbacks=Feedback.query.order_by(Feedback.created_at.desc()).all(), announcements=Announcement.query.order_by(Announcement.created_at.desc()).all(), total_downloads=sum(u.download_count for u in User.query.all()), flagged_count=sum(1 for u in User.query.all() if u.is_restricted))

@app.route('/admin/create_admin', methods=['POST'])
@login_required
def create_admin():
    if current_user.role != 'super_admin': return redirect(url_for('admin_dashboard'))
    if User.query.filter_by(email=request.form.get('email')).first(): flash('Email 已存在', 'warning')
    else: db.session.add(User(email=request.form.get('email'), name=request.form.get('name'), password=generate_password_hash(request.form.get('password')), role='admin')); db.session.commit(); flash('已新增管理員', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/add_announcement', methods=['POST'])
@login_required
def add_announcement():
    if current_user.role not in ['admin', 'super_admin']: return redirect(url_for('index'))
    db.session.add(Announcement(title=request.form.get('title'), content=request.form.get('content'))); db.session.commit(); flash('公告已發布', 'success'); return redirect(url_for('admin_dashboard'))

@app.route('/admin/edit_announcement/<int:ann_id>', methods=['POST'])
@login_required
def edit_announcement(ann_id):
    if current_user.role != 'super_admin': return redirect(url_for('admin_dashboard'))
    ann = Announcement.query.get(ann_id); ann.title = request.form.get('title'); ann.content = request.form.get('content'); db.session.commit(); flash('公告已更新', 'success'); return redirect(url_for('admin_dashboard'))

@app.route('/admin/delete_announcement/<int:ann_id>')
@login_required
def delete_announcement(ann_id):
    if current_user.role != 'super_admin': return redirect(url_for('admin_dashboard'))
    db.session.delete(Announcement.query.get(ann_id)); db.session.commit(); flash('公告已刪除', 'warning'); return redirect(url_for('admin_dashboard'))

@app.route('/admin/delete_user/<int:user_id>')
@login_required
def delete_user(user_id):
    if current_user.role != 'super_admin': return redirect(url_for('admin_dashboard'))
    if user_id == current_user.id: flash('不能刪除自己', 'danger'); return redirect(url_for('admin_dashboard'))
    db.session.delete(User.query.get(user_id)); db.session.commit(); flash('使用者已刪除', 'warning'); return redirect(url_for('admin_dashboard'))

@app.route('/admin/flag_user/<int:user_id>')
@login_required
def flag_user(user_id):
    if current_user.role != 'super_admin': return redirect(url_for('index'))
    user = User.query.get(user_id); user.is_restricted = True; db.session.commit(); flash('已管制帳號', 'warning'); return redirect(url_for('admin_dashboard'))

@app.route('/admin/unflag_user/<int:user_id>')
@login_required
def unflag_user(user_id):
    if current_user.role != 'super_admin': return redirect(url_for('index'))
    user = User.query.get(user_id); user.is_restricted = False; db.session.commit(); flash('已解除管制', 'success'); return redirect(url_for('admin_dashboard'))

@app.route('/admin/edit_user/<int:user_id>', methods=['POST'])
@login_required
def admin_edit_user(user_id):
    if current_user.role != 'super_admin': return redirect(url_for('index'))
    user = User.query.get(user_id); user.email = request.form.get('email')
    if request.form.get('password'): user.password = generate_password_hash(request.form.get('password'))
    db.session.commit(); flash('資料已更新', 'success'); return redirect(url_for('admin_dashboard'))

@app.route('/submit_feedback', methods=['POST'])
def submit_feedback():
    db.session.add(Feedback(name=request.form.get('name'), email=request.form.get('email'), subject=request.form.get('subject'), message=request.form.get('message'))); db.session.commit()
    send_email_via_gmail("111534105@stu.ukn.edu.tw", f"【意見回饋】{request.form.get('subject')}", f"寄件者: {request.form.get('name')} <{request.form.get('email')}>\\n\\n內容:\\n{request.form.get('message')}")
    flash('意見已發送！', 'success'); return redirect(url_for('about'))

@app.route('/online_check', methods=['GET', 'POST'])
@login_required
def online_check():
    duplicates = {}; scan_complete = False; now = datetime.now()
    if current_user.last_upload_reset is None or (now - current_user.last_upload_reset).total_seconds() > 300:
        current_user.upload_count_window = 0; current_user.last_upload_reset = now; db.session.commit()
    if request.method == 'POST':
        files = request.files.getlist('files')
        if len(files) > 20: flash('單次上傳不可超過 20 張！', 'danger'); return redirect(url_for('online_check'))
        if current_user.upload_count_window + len(files) > 20: flash(f'上傳頻率過高！每 5 分鐘限傳 20 張，目前剩餘 {20 - current_user.upload_count_window} 張。', 'danger'); return redirect(url_for('online_check'))
        hashes = {}; processed_count = 0
        for file in files:
            if file.filename == '': continue
            unique_name = str(uuid.uuid4()) + os.path.splitext(file.filename)[1]; filepath = os.path.join(app.config['TEMP_FOLDER'], unique_name); file.save(filepath); file_hash = calculate_md5(filepath); file_obj = {'storage': unique_name, 'display': file.filename}
            if file_hash in hashes: hashes[file_hash].append(file_obj)
            else: hashes[file_hash] = [file_obj]
            processed_count += 1
        current_user.upload_count_window += processed_count; db.session.commit()
        duplicates = {k: v for k, v in hashes.items() if len(v) > 1}; scan_complete = True
    return render_template('online_check.html', duplicates=duplicates, scan_complete=scan_complete)

@app.route('/about')
def about():
    return render_template('about.html', announcements=Announcement.query.order_by(Announcement.created_at.desc()).all())

@app.route('/logout')
@login_required
def logout(): logout_user(); return redirect(url_for('login'))

if __name__ == '__main__':
    with app.app_context(): db.create_all()
    app.run(debug=True, port=5000)
"""

with open(APP_PY_PATH, "w", encoding="utf-8") as f:
    f.write(new_app_code.strip())

print(f"✅ 已更新 app.py 路由邏輯：{APP_PY_PATH}")
print("------------------------------------------------")
print("🎉 部署完成！請執行: python run_server.py")
print("------------------------------------------------")