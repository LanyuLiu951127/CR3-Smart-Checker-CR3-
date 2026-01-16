import tkinter as tk
from tkinter import filedialog, ttk, messagebox
import hashlib
import os
import threading

class CR3CheckerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("CR3 相同照片檢查器 (本地版) v1.0")
        self.root.geometry("650x500")
        self.root.configure(bg="#f3f6f9")
        
        # 標題
        tk.Label(root, text="CR3 RAW檔 快速篩選工具", font=("Microsoft JhengHei", 18, "bold"), bg="#f3f6f9", fg="#4e73df").pack(pady=20)
        
        # 說明
        info_frame = tk.Frame(root, bg="#f3f6f9")
        info_frame.pack(pady=5)
        tk.Label(info_frame, text="✅ 專為 .CR3, .JPG, .PNG 設計", font=("Microsoft JhengHei", 10), bg="#f3f6f9").pack()
        tk.Label(info_frame, text="✅ 本地運算，無需上傳，速度快且安全", font=("Microsoft JhengHei", 10), bg="#f3f6f9").pack()
        
        # 按鈕
        self.btn_select = tk.Button(root, text="選擇資料夾開始掃描", font=("Microsoft JhengHei", 12), bg="#4e73df", fg="white", 
                                    relief="flat", padx=20, pady=10, command=self.start_scan_thread)
        self.btn_select.pack(pady=20)
        
        # 進度條
        self.progress_var = tk.DoubleVar()
        self.progress = ttk.Progressbar(root, orient="horizontal", length=550, mode="determinate", variable=self.progress_var)
        self.progress.pack(pady=10)
        
        # 結果文字框
        self.result_text = tk.Text(root, height=12, width=75, font=("Consolas", 9))
        self.result_text.pack(pady=10)
        self.result_text.insert(tk.END, "準備就緒。請點擊上方按鈕選擇包含照片的資料夾...\n")
        
    def calculate_md5(self, file_path):
        # 對於大型 CR3，我們讀取頭尾與中間部分來加速比對 (快速雜湊)
        # 為了準確性，這裡示範完整讀取，若要加速可改寫
        hash_md5 = hashlib.md5()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()

    def start_scan_thread(self):
        folder_selected = filedialog.askdirectory()
        if not folder_selected: return
        
        self.btn_select.config(state=tk.DISABLED, text="掃描中...")
        self.result_text.delete(1.0, tk.END)
        self.result_text.insert(tk.END, f"正在掃描資料夾: {folder_selected}\n")
        self.result_text.insert(tk.END, "分析中...這可能需要一點時間 (取決於檔案數量)\n")
        
        # 開啟執行緒避免介面卡死
        threading.Thread(target=self.scan_folder, args=(folder_selected,)).start()

    def scan_folder(self, folder):
        try:
            files = [f for f in os.listdir(folder) if f.lower().endswith(('.cr3', '.jpg', '.png', '.jpeg'))]
            total = len(files)
            
            if total == 0:
                self.update_ui_result("該資料夾沒有支援的圖片檔案。\n", 0)
                return

            hashes = {}
            duplicates = {}
            
            for i, filename in enumerate(files):
                filepath = os.path.join(folder, filename)
                file_hash = self.calculate_md5(filepath)
                
                if file_hash in hashes:
                    if file_hash not in duplicates:
                        duplicates[file_hash] = [hashes[file_hash]]
                    duplicates[file_hash].append(filename)
                else:
                    hashes[file_hash] = filename
                
                # 更新進度
                progress_val = (i + 1) / total * 100
                self.progress_var.set(progress_val)
                self.root.update_idletasks()
                
            # 整理結果文字
            result_msg = "-"*60 + "\n"
            if duplicates:
                result_msg += f"⚠️ 掃描完成！發現 {len(duplicates)} 組完全重複的照片：\n\n"
                for h, flist in duplicates.items():
                    result_msg += f"群組: {', '.join(flist)}\n"
            else:
                result_msg += "✅ 恭喜！沒有發現任何重複照片。\n"
            
            self.update_ui_result(result_msg, 100)
            
        except Exception as e:
            self.update_ui_result(f"發生錯誤: {str(e)}\n", 0)

    def update_ui_result(self, msg, progress):
        self.result_text.insert(tk.END, msg)
        self.result_text.see(tk.END)
        self.progress_var.set(progress)
        self.btn_select.config(state=tk.NORMAL, text="選擇資料夾開始掃描")

if __name__ == "__main__":
    root = tk.Tk()
    app = CR3CheckerApp(root)
    root.mainloop()