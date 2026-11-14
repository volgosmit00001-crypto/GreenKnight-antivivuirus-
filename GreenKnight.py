import os
import zipfile
import hashlib
import threading
import tkinter as tk
from tkinter import ttk, messagebox

MALWARE_HASHES = {
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f": "EICAR-Test-Signature",
}
EICAR_SIG = b"EICAR-STANDARD-" + b"ANTIVIRUS-TEST-FILE!"

if os.path.exists("/storage/emulated/0"):
    SCAN_DIRS = [
        os.getcwd(),
        "/storage/emulated/0/Download",
        "/storage/emulated/0/Documents",
        "/storage/emulated/0/Telegram/Telegram Documents",
    ]
    QUARANTINE_DIR = "/storage/emulated/0/AV_Quarantine"
    RESTORE_DIR = "/storage/emulated/0/Download"
else:
    HOME = os.path.expanduser("~")
    SCAN_DIRS = [
        os.getcwd(),
        os.path.join(HOME, "Downloads"),
        os.path.join(HOME, "Documents"),
        os.path.join(HOME, "Desktop"),
    ]
    QUARANTINE_DIR = os.path.join(HOME, "AV_Quarantine")
    RESTORE_DIR = os.path.join(HOME, "Downloads")

TARGET_EXTENSIONS = (".apk", ".zip", ".exe", ".bat", ".sh", ".py", ".txt")
XOR_KEY = 0x5A


class GreenKnightGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("GreenKnight 2026")
        self.root.configure(bg="#121212")
        if not os.path.exists("/storage/emulated/0"):
            self.root.geometry("480x580")

        self.is_scanning = False
        self.found_threats = []
        self.checked_count = 0

        tk.Label(root, text="GREENKNIGHT 2026", font=("Arial", 16, "bold"), bg="#121212", fg="#00E676").pack(pady=(12, 0))
        tk.Label(root, text="Offline Security Engine • by @kospersky8", font=("Arial", 9), bg="#121212", fg="#888888").pack(pady=(0, 8))

        sf = tk.Frame(root, bg="#1E1E1E", bd=2, relief="groove")
        sf.pack(fill="x", padx=15, pady=8)
        self.status_label = tk.Label(sf, text="Готов к проверке", font=("Arial", 13, "bold"), bg="#1E1E1E", fg="#FFFFFF", pady=15)
        self.status_label.pack()

        self.percent_label = tk.Label(root, text="Проверено файлов: 0 (0%)", font=("Arial", 11), bg="#121212", fg="#AAAAAA")
        self.percent_label.pack()
        self.progress = ttk.Progressbar(root, orient="horizontal", mode="determinate")
        self.progress.pack(fill="x", padx=20, pady=(2, 12))

        self.btn_scan = tk.Button(root, text="СКАНИРОВАТЬ УСТРОЙСТВО", font=("Arial", 11, "bold"), bg="#00C853", fg="#000000", height=2, command=self.start_scan)
        self.btn_scan.pack(fill="x", padx=20, pady=5)

        self.btn_quar = tk.Button(root, text="ОТКРЫТЬ КАРАНТИН", font=("Arial", 11, "bold"), bg="#2979FF", fg="#FFFFFF", height=2, command=self.open_quarantine)
        self.btn_quar.pack(fill="x", padx=20, pady=5)

        self.log_box = tk.Listbox(root, font=("Arial", 10), bg="#1E1E1E", fg="#FF5252", height=8)
        self.log_box.pack(fill="both", expand=True, padx=15, pady=10)

        af = tk.Frame(root, bg="#121212")
        af.pack(fill="x", padx=15, pady=(0, 15))
        tk.Button(af, text="Удалить", font=("Arial", 11, "bold"), bg="#D50000", fg="#FFFFFF", command=self.del_threat).pack(side="left", expand=True, fill="x", padx=(0, 5))
        tk.Button(af, text="В карантин", font=("Arial", 11, "bold"), bg="#FF9100", fg="#000000", command=self.quar_threat).pack(side="right", expand=True, fill="x", padx=(5, 0))

    def get_sha256(self, path):
        h = hashlib.sha256()
        try:
            with open(path, "rb") as f:
                while chunk := f.read(65536):
                    h.update(chunk)
            return h.hexdigest()
        except Exception:
            return None

    def inspect_file(self, path, name):
        f_hash = self.get_sha256(path)
        if f_hash in MALWARE_HASHES:
            return MALWARE_HASHES[f_hash]
        try:
            if name.endswith((".txt", ".py", ".sh", ".bat")):
                with open(path, "rb") as f:
                    if EICAR_SIG in f.read(4096):
                        return "EICAR-Test-Signature"
            if name.endswith(".apk"):
                with zipfile.ZipFile(path, "r") as z:
                    for item in z.namelist():
                        if item.startswith("assets/") and item.endswith(".dex"):
                            return f"Скрытый код ({item})"
            elif name.endswith(".zip"):
                with zipfile.ZipFile(path, "r") as z:
                    for info in z.infolist():
                        if not info.is_dir() and info.filename.lower().endswith((".exe", ".bat", ".cmd", ".scr")):
                            return f"Опасный файл: {info.filename}"
        except Exception:
            pass
        return None

    def start_scan(self):
        if self.is_scanning:
            return
        self.is_scanning = True
        self.checked_count = 0
        self.btn_scan.config(state="disabled", text="ИДЁТ ПРОВЕРКА...")
        self.log_box.delete(0, tk.END)
        self.found_threats.clear()
        self.status_label.config(text="Проверяю файлы...", fg="#FFD600")
        threading.Thread(target=self.run_scan, daemon=True).start()

    def run_scan(self):
        files, seen = [], set()
        for folder in SCAN_DIRS:
            if os.path.exists(folder):
                for r, _, fs in os.walk(folder):
                    if QUARANTINE_DIR in r:
                        continue
                    for f in fs:
                        if f.lower().endswith(TARGET_EXTENSIONS):
                            p = os.path.abspath(os.path.join(r, f))
                            if p not in seen:
                                seen.add(p)
                                try:
                                    if os.path.getsize(p) <= 100 * 1024 * 1024:
                                        files.append(p)
                                except Exception:
                                    pass
        total = len(files)
        self.checked_count = total
        for i, p in enumerate(files, 1):
            self.root.after(0, self.upd_prog, int((i / total) * 100), i, total)
            name = os.path.basename(p)
            risk = self.inspect_file(p, name.lower())
            if risk:
                self.found_threats.append((p, name, risk))
        self.root.after(0, self.finish_scan)

    def upd_prog(self, val, cur, total):
        self.progress["value"] = val
        self.percent_label.config(text=f"Проверено: {cur}/{total} ({val}%)")

    def finish_scan(self):
        self.is_scanning = False
        self.btn_scan.config(state="normal", text="СКАНИРОВАТЬ УСТРОЙСТВО")
        self.progress["value"] = 100
        self.percent_label.config(text=f"Проверено файлов: {self.checked_count} (100%)")
        if not self.found_threats:
            self.status_label.config(text="Угрозы: 0\nВы в безопасности!", fg="#00E676")
        else:
            self.status_label.config(text=f"Угроза: {len(self.found_threats)}\nНайдены угрозы!", fg="#FF5252")
            for i, (_, name, reason) in enumerate(self.found_threats, 1):
                self.log_box.insert(tk.END, f"Угроза:{i} это {name} ({reason})")

    def toggle_xor(self, src, dest):
        with open(src, "rb") as f:
            data = bytearray(f.read())
        for i in range(len(data)):
            data[i] ^= XOR_KEY
        with open(dest, "wb") as f:
            f.write(data)
        os.remove(src)

    def del_threat(self):
        for idx in self.log_box.curselection():
            p, _, _ = self.found_threats.pop(idx)
            os.remove(p)
            self.log_box.delete(idx)
            break
        if not self.found_threats:
            self.status_label.config(text="Угрозы: 0\nВы в безопасности!", fg="#00E676")

    def quar_threat(self):
        for idx in self.log_box.curselection():
            p, name, _ = self.found_threats.pop(idx)
            os.makedirs(QUARANTINE_DIR, exist_ok=True)
            self.toggle_xor(p, os.path.join(QUARANTINE_DIR, name + ".locked"))
            self.log_box.delete(idx)
            break
        if not self.found_threats:
            self.status_label.config(text="Угрозы: 0\nВы в безопасности!", fg="#00E676")

    def open_quarantine(self):
        qw = tk.Toplevel(self.root)
        qw.title("Карантин GreenKnight")
        qw.configure(bg="#121212")
        tk.Label(qw, text="КАРАНТИН", font=("Arial", 13, "bold"), bg="#121212", fg="#2979FF").pack(pady=10)
        ql = tk.Listbox(qw, font=("Arial", 11), bg="#1E1E1E", fg="#FFFFFF", height=10)
        ql.pack(fill="both", expand=True, padx=15, pady=5)

        os.makedirs(QUARANTINE_DIR, exist_ok=True)
        locked = [f for f in os.listdir(QUARANTINE_DIR) if f.endswith(".locked")]
        for f in locked:
            ql.insert(tk.END, f[:-7])

        def restore():
            for idx in ql.curselection():
                lname = locked.pop(idx)
                self.toggle_xor(os.path.join(QUARANTINE_DIR, lname), os.path.join(RESTORE_DIR, lname[:-7]))
                ql.delete(idx)
                messagebox.showinfo("Готово", "Файл восстановлен!")
                break

        def wipe():
            for idx in ql.curselection():
                os.remove(os.path.join(QUARANTINE_DIR, locked.pop(idx)))
                ql.delete(idx)
                messagebox.showinfo("Готово", "Файл удалён навсегда!")
                break

        bf = tk.Frame(qw, bg="#121212")
        bf.pack(fill="x", padx=15, pady=15)
        tk.Button(bf, text="Восстановить", font=("Arial", 11, "bold"), bg="#00C853", fg="#000000", command=restore).pack(side="left", expand=True, fill="x", padx=(0, 5))
        tk.Button(bf, text="Удалить", font=("Arial", 11, "bold"), bg="#D50000", fg="#FFFFFF", command=wipe).pack(side="right", expand=True, fill="x", padx=(5, 0))


root = tk.Tk()
app = GreenKnightGUI(root)
root.mainloop()
