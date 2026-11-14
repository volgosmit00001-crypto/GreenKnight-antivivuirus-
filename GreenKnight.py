import os
import zipfile
import hashlib
import threading
from kivy.app import App
from kivy.clock import Clock
from kivy.core.window import Window
from kivy.utils import get_color_from_hex
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.label import Label
from kivy.uix.button import Button
from kivy.uix.progressbar import ProgressBar
from kivy.uix.scrollview import ScrollView
from kivy.uix.popup import Popup

MALWARE_HASHES = {
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f": "EICAR-Test-Signature",
}
EICAR_SIG = b"EICAR-STANDARD-" + b"ANTIVIRUS-TEST-FILE!"
IS_ANDROID = os.path.exists("/storage/emulated/0")

if IS_ANDROID:
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
    Window.size = (480, 640)

TARGET_EXTENSIONS = (".apk", ".zip", ".exe", ".bat", ".sh", ".py", ".txt")
XOR_KEY = 0x5A
Window.clearcolor = get_color_from_hex("#121212")


class GreenKnightApp(App):
    def build(self):
        self.title = "GreenKnight 2026"
        self.is_scanning = False
        self.found_threats = []
        self.selected_index = None
        self.checked_count = 0

        root = BoxLayout(orientation="vertical", padding=15, spacing=8)
        root.add_widget(Label(text="GREENKNIGHT 2026", font_size="22sp", bold=True, color=get_color_from_hex("#00E676"), size_hint_y=None, height=36))
        root.add_widget(Label(text="Offline Security Engine by kospersky8", font_size="12sp", color=get_color_from_hex("#888888"), size_hint_y=None, height=22))

        self.status_label = Label(text="Готов к проверке", font_size="18sp", bold=True, halign="center", color=get_color_from_hex("#FFFFFF"), size_hint_y=None, height=64)
        root.add_widget(self.status_label)

        self.percent_label = Label(text="Проверено файлов: 0 (0%)", font_size="14sp", color=get_color_from_hex("#AAAAAA"), size_hint_y=None, height=26)
        root.add_widget(self.percent_label)

        self.progress = ProgressBar(max=100, value=0, size_hint_y=None, height=18)
        root.add_widget(self.progress)

        self.btn_scan = Button(text="СКАНИРОВАТЬ УСТРОЙСТВО", font_size="15sp", bold=True, background_normal="", background_color=get_color_from_hex("#00C853"), color=get_color_from_hex("#000000"), size_hint_y=None, height=48)
        self.btn_scan.bind(on_release=self.start_scan)
        root.add_widget(self.btn_scan)

        self.btn_quar = Button(text="ОТКРЫТЬ КАРАНТИН", font_size="15sp", bold=True, background_normal="", background_color=get_color_from_hex("#2979FF"), color=get_color_from_hex("#FFFFFF"), size_hint_y=None, height=48)
        self.btn_quar.bind(on_release=self.open_quarantine)
        root.add_widget(self.btn_quar)

        scroll = ScrollView()
        self.threat_list_layout = BoxLayout(orientation="vertical", spacing=5, size_hint_y=None)
        self.threat_list_layout.bind(minimum_height=self.threat_list_layout.setter("height"))
        scroll.add_widget(self.threat_list_layout)
        root.add_widget(scroll)

        action_bar = BoxLayout(orientation="horizontal", spacing=10, size_hint_y=None, height=46)
        btn_del = Button(text="Удалить", font_size="15sp", bold=True, background_normal="", background_color=get_color_from_hex("#D50000"), color=get_color_from_hex("#FFFFFF"))
        btn_del.bind(on_release=self.del_threat)

        btn_quar_item = Button(text="В карантин", font_size="15sp", bold=True, background_normal="", background_color=get_color_from_hex("#FF9100"), color=get_color_from_hex("#000000"))
        btn_quar_item.bind(on_release=self.quar_threat)

        action_bar.add_widget(btn_del)
        action_bar.add_widget(btn_quar_item)
        root.add_widget(action_bar)

        if IS_ANDROID:
            Clock.schedule_once(self.request_android_perms, 0.5)
        return root

    def request_android_perms(self, dt):
        try:
            from android.permissions import request_permissions, Permission
            request_permissions([Permission.READ_EXTERNAL_STORAGE, Permission.WRITE_EXTERNAL_STORAGE])
        except Exception:
            pass

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
    def start_scan(self, instance):
        if self.is_scanning:
            return
        self.is_scanning = True
        self.checked_count = 0
        self.selected_index = None
        self.btn_scan.disabled = True
        self.btn_scan.text = "ИДЁТ ПРОВЕРКА..."
        self.threat_list_layout.clear_widgets()
        self.found_threats.clear()
        self.status_label.text = "Проверяю файлы..."
        self.status_label.color = get_color_from_hex("#FFD600")
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
            val = int((i / total) * 100) if total else 100
            Clock.schedule_once(lambda dt, v=val, c=i, t=total: self.upd_prog(v, c, t))
            name = os.path.basename(p)
            risk = self.inspect_file(p, name.lower())
            if risk:
                self.found_threats.append((p, name, risk))
        Clock.schedule_once(lambda dt: self.finish_scan())

    def upd_prog(self, val, cur, total):
        self.progress.value = val
        self.percent_label.text = f"Проверено: {cur}/{total} ({val}%)"

    def refresh_threat_buttons(self):
        self.threat_list_layout.clear_widgets()
        for i, (_, name, reason) in enumerate(self.found_threats):
            is_sel = (i == self.selected_index)
            btn = Button(text=f"Угроза {i + 1}: {name} ({reason})", font_size="13sp", halign="left", size_hint_y=None, height=44, background_normal="", background_color=get_color_from_hex("#421818" if is_sel else "#1E1E1E"), color=get_color_from_hex("#FF5252"))
            btn.bind(on_release=lambda inst, idx=i: self.select_threat(idx))
            self.threat_list_layout.add_widget(btn)

    def select_threat(self, idx):
        self.selected_index = idx
        self.refresh_threat_buttons()

    def finish_scan(self):
        self.is_scanning = False
        self.btn_scan.disabled = False
        self.btn_scan.text = "СКАНИРОВАТЬ УСТРОЙСТВО"
        self.progress.value = 100
        self.percent_label.text = f"Проверено файлов: {self.checked_count} (100%)"
        if not self.found_threats:
            self.status_label.text = "Угрозы: 0\nВы в безопасности!"
            self.status_label.color = get_color_from_hex("#00E676")
        else:
            self.status_label.text = f"Угроз: {len(self.found_threats)}\nНажмите на угрозу и выберите действие"
            self.status_label.color = get_color_from_hex("#FF5252")
            self.selected_index = 0
            self.refresh_threat_buttons()

    def toggle_xor(self, src, dest):
        with open(src, "rb") as f:
            data = bytearray(f.read())
        for i in range(len(data)):
            data[i] ^= XOR_KEY
        with open(dest, "wb") as f:
            f.write(data)
        os.remove(src)

    def del_threat(self, instance):
        if self.selected_index is None or not self.found_threats:
            return
        p, _, _ = self.found_threats.pop(self.selected_index)
        if os.path.exists(p):
            os.remove(p)
        self.selected_index = 0 if self.found_threats else None
        self.refresh_threat_buttons()
        if not self.found_threats:
            self.status_label.text = "Угрозы: 0\nВы в безопасности!"
            self.status_label.color = get_color_from_hex("#00E676")

    def quar_threat(self, instance):
        if self.selected_index is None or not self.found_threats:
            return
        p, name, _ = self.found_threats.pop(self.selected_index)
        os.makedirs(QUARANTINE_DIR, exist_ok=True)
        if os.path.exists(p):
            self.toggle_xor(p, os.path.join(QUARANTINE_DIR, name + ".locked"))
        self.selected_index = 0 if self.found_threats else None
        self.refresh_threat_buttons()
        if not self.found_threats:
            self.status_label.text = "Угрозы: 0\nВы в безопасности!"
            self.status_label.color = get_color_from_hex("#00E676")

    def open_quarantine(self, instance):
        os.makedirs(QUARANTINE_DIR, exist_ok=True)
        locked = [f for f in os.listdir(QUARANTINE_DIR) if f.endswith(".locked")]

        content = BoxLayout(orientation="vertical", padding=10, spacing=8)
        q_scroll = ScrollView()
        q_list = BoxLayout(orientation="vertical", spacing=5, size_hint_y=None)
        q_list.bind(minimum_height=q_list.setter("height"))
        q_scroll.add_widget(q_list)
        content.add_widget(q_scroll)

        state = {"sel": 0 if locked else None}

        def render_q():
            q_list.clear_widgets()
            if not locked:
                q_list.add_widget(Label(text="Карантин пуст", size_hint_y=None, height=40))
                return
            for i, fname in enumerate(locked):
                btn = Button(text=fname[:-7], size_hint_y=None, height=42, background_normal="", background_color=get_color_from_hex("#1B3B6F" if i == state["sel"] else "#222222"))
                btn.bind(on_release=lambda inst, idx=i: (state.update({"sel": idx}), render_q()))
                q_list.add_widget(btn)

        render_q()

        btns = BoxLayout(orientation="horizontal", spacing=8, size_hint_y=None, height=44)
        b_res = Button(text="Восстановить", background_normal="", background_color=get_color_from_hex("#00C853"), color=get_color_from_hex("#000000"), bold=True)
        b_del = Button(text="Удалить", background_normal="", background_color=get_color_from_hex("#D50000"), bold=True)
        b_close = Button(text="Закрыть", background_normal="", background_color=get_color_from_hex("#444444"))

        def do_restore(inst):
            if state["sel"] is None or not locked:
                return
            lname = locked.pop(state["sel"])
            os.makedirs(RESTORE_DIR, exist_ok=True)
            self.toggle_xor(os.path.join(QUARANTINE_DIR, lname), os.path.join(RESTORE_DIR, lname[:-7]))
            state["sel"] = 0 if locked else None
            render_q()

        def do_wipe(inst):
            if state["sel"] is None or not locked:
                return
            lname = locked.pop(state["sel"])
            os.remove(os.path.join(QUARANTINE_DIR, lname))
            state["sel"] = 0 if locked else None
            render_q()

        b_res.bind(on_release=do_restore)
        b_del.bind(on_release=do_wipe)
        btns.add_widget(b_res)
        btns.add_widget(b_del)
        btns.add_widget(b_close)
        content.add_widget(btns)

        popup = Popup(title="КАРАНТИН GREENKNIGHT", content=content, size_hint=(0.92, 0.8))
        b_close.bind(on_release=popup.dismiss)
        popup.open()


if __name__ == "__main__":
    GreenKnightApp().run()
