import PyInstaller.__main__
import os
import shutil

print("🚀 開始打包 CR3 Desktop App...")

# 清理舊檔
if os.path.exists("dist"): shutil.rmtree("dist")
if os.path.exists("build"): shutil.rmtree("build")

PyInstaller.__main__.run([
    'client_app.py',
    '--name=CR3_Check_Tool',
    '--onefile',
    '--windowed', # 隱藏黑色終端機視窗
    '--clean'
])

print("✅ 打包完成！請到 dist 資料夾查看 CR3_Check_Tool.exe")