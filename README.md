# 專案名稱：CR3 Smart Checker (CR3 智慧相片快篩系統)

簡報：
https://www.canva.com/design/DAG95dzxg_Y/SoLf43PXz1fdmaQHo4ye-Q/edit?utm_content=DAG95dzxg_Y&utm_campaign=designshare&utm_medium=link2&utm_source=sharebutton


1. 專案簡介 (Project Overview) 這是一個專為攝影師設計的 雙平台 (Web + Desktop) 相片篩選解決方案。旨在解決 RAW 檔 (CR3) 體積龐大、難以快速比對重複內容的痛點。系統採用「邊緣運算」概念，讓使用者選擇最適合的操作模式：輕量級的網頁版或高效能的桌面版。

2. 核心功能 (Key Features)

Web 雲端平台 (Flask)：

會員生態系：完整的註冊、登入、忘記密碼 (SMTP 驗證碼)、個人資料管理。

權限分級：超級管理員可管理公告、封鎖異常帳號、查看數據儀表板。

資安防護：防暴力破解 (Rate Limiting)、密碼雜湊加密、輸入防呆機制。

互動體驗：首頁整合 Canva 簡報展示、RWD 響應式設計、黑夜模式。

桌面端軟體 (Desktop App)：

極速運算：使用 Python Tkinter 開發，直接讀取本地硬碟，無需上傳 30MB+ 的大檔。

隱私優先：照片不離開使用者電腦，適合注重版權的商業攝影。

一鍵打包：提供 PyInstaller 腳本，可編譯為獨立 .exe 執行檔。

3. 技術棧 (Tech Stack)

Backend: Python, Flask, SQLAlchemy (SQLite)

Frontend: HTML5, CSS3 (Bootstrap 5), JavaScript

Desktop: Python Tkinter, PyInstaller

Security: Werkzeug Security, MD5 Hashing

