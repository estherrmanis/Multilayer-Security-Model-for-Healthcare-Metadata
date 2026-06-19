import base64
import json
import shutil
import tkinter as tk
import time
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from aes_lsb import process_secure_embedding
from evaluation import evaluate_images
from svm_security import SVMAnomalyDetector

ACCENT_BLUE = "#0D52DB"
NAVBAR_BG = "#D9D9D9"

try:
    from PIL import Image, ImageTk
except ImportError:
    Image = None
    ImageTk = None


class SecurityMedicalApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("Sistem Keamanan Rekam Medis")
        self.geometry("1366x820")
        self.minsize(1220, 760)

        self.detector = SVMAnomalyDetector("dataset_svm.csv")
        self.valid_username = "admin"
        self.valid_password = "simbakucingaku"
        self.max_attempts = 3
        self.remaining_attempts = self.max_attempts
        self.system_locked = False

        self.medical_file_paths: list[Path] = []
        self.cover_image_path: Path | None = None
        self.stego_output_path: Path | None = None
        self.encryption_info = {}
        self.eval_metrics = {}
        self.current_preview = None

        self.container = ttk.Frame(self)
        self.container.pack(fill="both", expand=True)

        self.frames = {}
        for frame_cls in (LoginPage, InputPage, ResultPage, DeteksiAnomaliPage):
            frame = frame_cls(parent=self.container, controller=self)
            self.frames[frame_cls.__name__] = frame
            frame.grid(row=0, column=0, sticky="nsew")

        self.container.grid_rowconfigure(0, weight=1)
        self.container.grid_columnconfigure(0, weight=1)
        self.show_frame("LoginPage")

    def close_app(self) -> None:
        self.destroy()

    def show_frame(self, name: str) -> None:
        frame = self.frames[name]
        frame.tkraise()
        if hasattr(frame, "refresh"):
            frame.refresh()

    def lock_system(self) -> None:
        self.system_locked = True
        login_page: LoginPage = self.frames["LoginPage"]
        login_page.disable_inputs()
        messagebox.showerror(
            "Sistem Terkunci",
            "Sistem dikunci karena terdeteksi percobaan serangan berulang. "
            "Input login dinonaktifkan.",
        )

    def handle_login(self, username: str, password: str) -> None:
        if self.system_locked:
            messagebox.showerror("Terkunci", "Sistem sudah terkunci.")
            return

        login_page: LoginPage = self.frames["LoginPage"]

        # Kredensial resmi selalu diperlakukan sebagai akses aman.
        if username == self.valid_username and password == self.valid_password:
            self.remaining_attempts = self.max_attempts
            login_page.set_attempt_text(self.remaining_attempts)
            self.show_frame("InputPage")
            return

        prediction = self.detector.predict_login(username, password)

        if prediction.is_anomaly:
            self.remaining_attempts -= 1
            messagebox.showwarning(
                "Anomali Terdeteksi",
                f"Terdeteksi serangan: {prediction.detected_attack}\n"
                f"Confidence: {prediction.confidence:.2f}\n",
            )
            login_page.set_attempt_text(self.remaining_attempts)
            if self.remaining_attempts <= 0:
                self.lock_system()
            return

        self.remaining_attempts -= 1
        login_page.set_attempt_text(self.remaining_attempts)
        if self.remaining_attempts <= 0:
            self.lock_system()
        else:
            messagebox.showerror(
                "Login Gagal",
                f"Username/password salah. Sisa kesempatan: {self.remaining_attempts}",
            )

    def process_aes_lsb(self, passphrase: str = "secretkey") -> None:
        if not self.medical_file_paths or not self.cover_image_path:
            raise ValueError("File medis dan cover image harus dipilih terlebih dahulu.")

        payload_files = []
        total_original_bytes = 0
        for medical_file in self.medical_file_paths:
            medical_bytes = medical_file.read_bytes()
            total_original_bytes += len(medical_bytes)
            payload_files.append(
                {
                    "filename": medical_file.name,
                    "content_b64": base64.b64encode(medical_bytes).decode("utf-8"),
                }
            )
        payload = {"files": payload_files}
        message = json.dumps(payload)
        output_name = f"cipher_{self.cover_image_path.stem}.png"

        started = time.perf_counter()
        self.encryption_info = process_secure_embedding(
            message=message,
            image_path=str(self.cover_image_path),
            passphrase=passphrase,
            output_path=output_name,
        )
        elapsed = time.perf_counter() - started
        cipher_b64 = self.encryption_info.get("ciphertext_b64", "")
        encrypted_size = 0
        if cipher_b64:
            try:
                encrypted_size = len(base64.b64decode(cipher_b64))
            except Exception:
                encrypted_size = 0
        self.encryption_info["original_size_bytes"] = total_original_bytes
        self.encryption_info["encrypted_size_bytes"] = encrypted_size
        self.encryption_info["process_time_sec"] = elapsed
        self.stego_output_path = Path(self.encryption_info["stego_path"])
        self.eval_metrics = evaluate_images(
            str(self.cover_image_path), str(self.stego_output_path)
        )
        self.show_frame("ResultPage")


class LoginPage(tk.Frame):
    def __init__(self, parent, controller: SecurityMedicalApp):
        super().__init__(parent, bg="#FFFFFF")
        self.controller = controller
        self.login_icon = None
        self.user_field_icon = None
        self.password_field_icon = None

        center = tk.Frame(self, bg="#FFFFFF")
        center.place(relx=0.5, rely=0.5, anchor="center")

        self.login_icon_label = tk.Label(center, bg="#FFFFFF")
        self.login_icon_label.pack(pady=(0, 14))
        self._load_login_icon()

        title = tk.Label(
            center,
            text="SISTEM KEAMANAN\nREKAM MEDIS",
            font=("Segoe UI", 22, "bold"),
            anchor="center",
            justify="center",
            bg="#FFFFFF",
        )
        title.pack(pady=(0, 16))

        box = tk.Frame(center, bg="#FFFFFF", padx=4, pady=4)
        box.pack()

        self.username_var = tk.StringVar()
        self.password_var = tk.StringVar()

        username_row = tk.Frame(
            box,
            bg="#FFFFFF",
            bd=1,
            relief="solid",
            highlightthickness=1,
            highlightbackground="#D0D5DD",
            highlightcolor=ACCENT_BLUE,
        )
        username_row.grid(row=0, column=0, pady=6, sticky="ew")
        password_row = tk.Frame(
            box,
            bg="#FFFFFF",
            bd=1,
            relief="solid",
            highlightthickness=1,
            highlightbackground="#D0D5DD",
            highlightcolor=ACCENT_BLUE,
        )
        password_row.grid(row=1, column=0, pady=6, sticky="ew")
        box.grid_columnconfigure(0, weight=1)

        self.user_icon_label = tk.Label(username_row, bg="#FFFFFF")
        self.user_icon_label.pack(side="left", padx=(10, 8))
        self.password_icon_label = tk.Label(password_row, bg="#FFFFFF")
        self.password_icon_label.pack(side="left", padx=(10, 8))
        self._load_field_icons()

        self.username_entry = tk.Entry(
            username_row,
            width=35,
            textvariable=self.username_var,
            relief="flat",
            bd=0,
            font=("Segoe UI", 10),
        )
        self.password_entry = tk.Entry(
            password_row,
            width=35,
            textvariable=self.password_var,
            show="*",
            relief="flat",
            bd=0,
            font=("Segoe UI", 10),
        )
        self.username_entry.pack(side="left", fill="x", expand=True, padx=(0, 10), ipady=8)
        self.password_entry.pack(side="left", fill="x", expand=True, padx=(0, 10), ipady=8)

        self.login_btn = tk.Button(
            box,
            text="LOGIN",
            width=32,
            command=self.on_login,
            bg=ACCENT_BLUE,
            fg="#FFFFFF",
            activebackground="#0A43B6",
            activeforeground="#FFFFFF",
            relief="flat",
            bd=0,
            font=("Segoe UI", 10, "bold"),
            cursor="hand2",
        )
        self.login_btn.grid(row=2, column=0, pady=(12, 8), ipady=6, sticky="ew")

    def _load_login_icon(self) -> None:
        icon_path = Path("kunci.jpeg")
        if not icon_path.exists():
            self.login_icon_label.configure(text="Ikon kunci tidak ditemukan (kunci.jpeg)")
            return
        if Image is None or ImageTk is None:
            self.login_icon_label.configure(text="Pillow belum terpasang, ikon tidak dapat ditampilkan.")
            return
        try:
            icon_img = Image.open(icon_path).convert("RGB")
            icon_img.thumbnail((96, 96))
            self.login_icon = ImageTk.PhotoImage(icon_img)
            self.login_icon_label.configure(image=self.login_icon, text="")
        except Exception:
            self.login_icon_label.configure(text="Gagal memuat ikon kunci.")

    def _load_field_icons(self) -> None:
        user_icon = self._load_png_icon(Path("user.jpeg"), (28, 28))
        lock_icon = self._load_png_icon(Path("padlock.jpeg"), (28, 28))

        if user_icon is not None:
            self.user_field_icon = user_icon
            self.user_icon_label.configure(image=self.user_field_icon, text="")
        else:
            self.user_icon_label.configure(text="U", fg="#64748B")

        if lock_icon is not None:
            self.password_field_icon = lock_icon
            self.password_icon_label.configure(image=self.password_field_icon, text="")
        else:
            self.password_icon_label.configure(text="L", fg="#64748B")

    def _load_png_icon(self, icon_path: Path, size: tuple[int, int]):
        if not icon_path.exists() or Image is None or ImageTk is None:
            return None
        try:
            icon_img = Image.open(icon_path).convert("RGBA")
            icon_img.thumbnail(size)
            return ImageTk.PhotoImage(icon_img)
        except Exception:
            return None

    def on_login(self) -> None:
        self.controller.handle_login(self.username_var.get().strip(), self.password_var.get().strip())

    def set_attempt_text(self, remaining: int) -> None:
        _ = remaining

    def disable_inputs(self) -> None:
        self.username_entry.configure(state="disabled")
        self.password_entry.configure(state="disabled")
        self.login_btn.configure(state="disabled")


class InputPage(ttk.Frame):
    def __init__(self, parent, controller: SecurityMedicalApp):
        super().__init__(parent)
        self.controller = controller
        self.menu_icon_refs = {}
        self.box_icon_refs = {}
        self.icon_refs = {}

        root = tk.Frame(self, bg="#EEF5FF")
        root.pack(fill="both", expand=True, padx=14, pady=14)

        sidebar = tk.Frame(root, bg="#DCEBFF", width=200, bd=0)
        sidebar.pack(side="left", fill="y")
        sidebar.pack_propagate(False)

        tk.Label(
            sidebar,
            text="Menu",
            font=("Segoe UI", 16, "bold"),
            bg="#DCEBFF",
            fg="#173A68",
        ).pack(anchor="center", padx=14, pady=(18, 12))
        self._create_menu_item(
            sidebar, "Input Data", "google-docs.png", active=True, command=None
        )
        self._create_menu_item(
            sidebar, "Hasil", "photo.png", active=False, command=lambda: controller.show_frame("ResultPage")
        )
        self._create_menu_item(
            sidebar, "Deteksi Anomali", "focus.png", active=False, command=lambda: controller.show_frame("DeteksiAnomaliPage")
        )
        self._create_menu_item(sidebar, "Logout", "logout.png", active=False, command=controller.close_app)

        content = tk.Frame(root, bg="#EEF5FF")
        content.pack(side="left", fill="both", expand=True, padx=(14, 0))

        tk.Label(
            content,
            text="Input Data & Gambar",
            font=("Segoe UI", 34, "bold"),
            bg="#EEF5FF",
            fg="#114B9B",
        ).pack(anchor="w", pady=(0, 12))

        info_shadow = tk.Frame(content, bg="#D9E7FB")
        info_shadow.pack(fill="x", pady=(0, 14))
        info_box = tk.Frame(info_shadow, bg="#FFFFFF", highlightbackground="#D8E3F2", highlightthickness=1, bd=0)
        info_box.pack(fill="x", padx=(0, 2), pady=(0, 2), ipady=10)
        info_top = tk.Frame(info_box, bg="#FFFFFF")
        info_top.pack(fill="x", padx=16, pady=(10, 4))
        info_icon = self._load_icon_asset(["verified.png"], (30, 30))
        if info_icon is not None:
            self.icon_refs["verified"] = info_icon
            tk.Label(info_top, image=info_icon, bg="#FFFFFF").pack(side="left")
        else:
            tk.Label(info_top, text="i", bg="#EAF2FF", fg="#114B9B", font=("Segoe UI", 12, "bold"), width=2).pack(side="left")
        tk.Label(info_top, text="information box", bg="#FFFFFF", fg="#114B9B", font=("Segoe UI", 22, "bold")).pack(
            side="left", padx=16
        )
        tk.Label(
            info_box,
            text=(
                "Halaman input data digunakan untuk mengunggah file rekam medis dan memilih cover image "
                "sebelum dilakukan proses keamanan AES-LSB serta analisis deteksi anomali berbasis SVM."
            ),
            bg="#FFFFFF",
            fg="#334155",
            font=("Segoe UI", 10),
            justify="left",
            wraplength=980,
        ).pack(anchor="w", padx=16, pady=(0, 8))

        boxes = tk.Frame(content, bg="#EEF5FF")
        boxes.pack(fill="x")
        boxes.grid_columnconfigure(0, weight=1)
        boxes.grid_columnconfigure(1, weight=1)

        box1 = self._create_card(boxes, "Upload File Rekam Medis", "document.png")
        box1.grid(row=0, column=0, sticky="nsew", padx=(0, 10))
        self._create_upload_zone(
            box1,
            "document.png",
            "Drop file di sini",
            "Pilih File",
            self.pick_medical_file,
        )
        self.medical_var = tk.StringVar(value="Belum ada file dipilih")
        tk.Label(box1, textvariable=self.medical_var, bg="#FFFFFF", justify="left", wraplength=370, fg="#334155").pack(
            anchor="w", pady=(0, 8), padx=14
        )
        tk.Label(box1, text="Format yang didukung: TXT, PDF, DCM/DICOM", bg="#FFFFFF", fg="#475467").pack(anchor="w", padx=14)
        tk.Label(box1, text="Maks. File: 500 MB", bg="#FFFFFF", fg="#475467").pack(anchor="w", pady=(0, 12), padx=14)


        box2 = self._create_card(boxes, "Pilih Gambar", "image.png")
        box2.grid(row=0, column=1, sticky="nsew", padx=(10, 0))
        self._create_upload_zone(
            box2,
            "image.png",
            "Drop gambar di sini",
            "Pilih Gambar",
            self.pick_cover_image,
        )
        self.cover_var = tk.StringVar(value="Belum ada gambar dipilih")
        tk.Label(box2, textvariable=self.cover_var, bg="#FFFFFF", justify="left", wraplength=370, fg="#334155").pack(
            anchor="w", pady=(0, 8), padx=14
        )
        tk.Label(box2, text="Format yang didukung: JPG, PNG, BMP", bg="#FFFFFF", fg="#475467").pack(anchor="w", padx=14)
        tk.Label(box2, text="Maks. File: 100 MB", bg="#FFFFFF", fg="#475467").pack(anchor="w", pady=(0, 12), padx=14)

        # Catatan: ukuran cover image dibatasi 100 MB (sesuai requirement).

        tk.Button(

            content,
            text="Proses AES-LSB",
            command=self.run_process,
            bg="#2E7CF6",
            fg="#FFFFFF",
            activebackground="#1F67D9",
            activeforeground="#FFFFFF",
            relief="flat",
            bd=0,
            font=("Segoe UI", 11, "bold"),
            cursor="hand2",
            padx=30,
            pady=12,
        ).pack(anchor="e", side="bottom", pady=16)

    def _create_card(self, parent: tk.Widget, title: str, icon_name: str) -> tk.Frame:
        card = tk.Frame(parent, bg="#FFFFFF", highlightbackground="#D9E3F0", highlightthickness=1, bd=0)
        title_row = tk.Frame(card, bg="#FFFFFF")
        title_row.pack(fill="x", padx=14, pady=(12, 8))
        icon = self._load_icon_asset([icon_name], (18, 18))
        if icon is not None:
            self.box_icon_refs[f"{title}_{icon_name}"] = icon
            tk.Label(title_row, image=icon, bg="#FFFFFF").pack(side="left")
        tk.Label(
            title_row,
            text=title,
            bg="#FFFFFF",
            fg="#1D4ED8",
            font=("Segoe UI", 12, "bold"),
        ).pack(side="left", padx=(7, 0))
        return card

    def _create_menu_item(self, parent: tk.Frame, label: str, icon_name: str, active: bool, command) -> None:
        bg_color = "#4A90FF" if active else "#DCEBFF"
        fg_color = "#FFFFFF" if active else "#173A68"
        item = tk.Frame(parent, bg=bg_color, padx=12, pady=11)
        item.pack(fill="x", padx=10, pady=5)

        icon = self._load_icon_asset([icon_name], (16, 16))
        if icon is not None:
            self.menu_icon_refs[label] = icon
            tk.Label(item, image=icon, bg=bg_color).pack(side="left")

        tk.Label(item, text=label, bg=bg_color, fg=fg_color, font=("Segoe UI", 10, "bold")).pack(
            side="left", padx=(8, 0)
        )
        if command is not None:
            item.bind("<Button-1>", lambda _evt, fn=command: fn())
            for child in item.winfo_children():
                child.bind("<Button-1>", lambda _evt, fn=command: fn())

    def _create_upload_zone(
        self, parent: tk.Widget, icon_name: str, text: str, button_text: str, button_command
    ) -> None:
        zone = tk.Canvas(
            parent,
            width=400,
            height=190,
            bg="#FFFFFF",
            highlightthickness=0,
            bd=0,
        )
        zone.pack(anchor="w", pady=(0, 8), padx=14)
        zone.create_rectangle(8, 8, 392, 182, outline="#98A2B3", width=2, dash=(6, 4))
        icon = self._load_icon_asset([icon_name], (42, 42))
        if icon is not None:
            self.box_icon_refs[f"{parent}_{icon_name}"] = icon
            zone.create_image(200, 58, image=icon)
        else:
            zone.create_text(200, 58, text="ICON", fill="#667085", font=("Segoe UI", 9, "bold"))
        zone.create_text(200, 94, text=text, fill="#344054", font=("Segoe UI", 10))
        select_button = tk.Button(
            zone,
            text=button_text,
            command=button_command,
            bg="#EAF2FF",
            relief="flat",
            bd=0,
            cursor="hand2",
            padx=22,
            pady=6,
            font=("Segoe UI", 9, "bold"),
        )
        zone.create_window(200, 136, window=select_button)

    def _load_icon_asset(self, filenames: list[str], size: tuple[int, int]):
        if Image is None or ImageTk is None:
            return None
        for filename in filenames:
            path = Path(filename)
            if not path.exists():
                continue
            try:
                icon_img = Image.open(path).convert("RGBA")
                icon_img.thumbnail(size)
                return ImageTk.PhotoImage(icon_img)
            except Exception:
                continue
        return None

    def pick_medical_file(self) -> None:
        paths = filedialog.askopenfilenames(
            title="Pilih file rekam medis",
            filetypes=[("Medical files", "*.txt *.pdf *.dcm *.dicom"), ("All files", "*.*")],
        )
        if not paths:
            return

        selected_files = [Path(path) for path in paths]
        allowed_ext = {".txt", ".pdf", ".dcm", ".dicom"}
        invalid = [path.name for path in selected_files if path.suffix.lower() not in allowed_ext]
        if invalid:
            messagebox.showerror("Format Tidak Didukung", f"Format file tidak valid:\n{', '.join(invalid)}")
            return

        total_size = sum(path.stat().st_size for path in selected_files)
        limit_bytes = 500 * 1024 * 1024
        if total_size > limit_bytes:
            messagebox.showerror(
                "Ukuran File Melebihi Batas",
                "Total ukuran file medis tidak boleh melebihi 500 MB.",
            )
            return


        self.controller.medical_file_paths = selected_files
        names_preview = ", ".join(path.name for path in selected_files[:2])
        if len(selected_files) > 2:
            names_preview += f", +{len(selected_files) - 2} file lainnya"
        self.medical_var.set(f"{len(selected_files)} file dipilih: {names_preview}")

    def pick_cover_image(self) -> None:
        path = filedialog.askopenfilename(
            title="Pilih cover image",
            filetypes=[("Image files", "*.png *.jpg *.jpeg *.bmp"), ("All files", "*.*")],
        )
        if not path:
            return
        cover_path = Path(path)
        if cover_path.stat().st_size > 100 * 1024 * 1024:
            messagebox.showerror(
                "Ukuran File Melebihi Batas",
                "Ukuran gambar cover tidak boleh melebihi 100 MB.",
            )
            return

        self.controller.cover_image_path = cover_path
        self.cover_var.set(cover_path.name)

    def run_process(self) -> None:
        try:
            self.controller.process_aes_lsb()
        except Exception as exc:
            messagebox.showerror("Proses Gagal", str(exc))


class ResultPage(ttk.Frame):
    def __init__(self, parent, controller: SecurityMedicalApp):
        super().__init__(parent)
        self.controller = controller
        self.menu_icon_refs = {}
        self.icon_refs = {}
        self.current_preview = None

        root = tk.Frame(self, bg="#EEF5FF")
        root.pack(fill="both", expand=True, padx=14, pady=14)

        sidebar = tk.Frame(root, bg="#DCEBFF", width=200)
        sidebar.pack(side="left", fill="y")
        sidebar.pack_propagate(False)
        tk.Label(
            sidebar,
            text="Menu",
            bg="#DCEBFF",
            fg="#173A68",
            font=("Segoe UI", 16, "bold"),
        ).pack(anchor="center", pady=(18, 12), padx=10)
        self._create_menu_item(sidebar, "Input Data", "google-docs.png", active=False, command=lambda: controller.show_frame("InputPage"))
        self._create_menu_item(sidebar, "Hasil", "photo.png", active=True, command=None)
        self._create_menu_item(sidebar, "Deteksi Anomali", "focus.png", active=False, command=lambda: controller.show_frame("DeteksiAnomaliPage"))
        self._create_menu_item(sidebar, "Logout", "logout.png", active=False, command=controller.close_app)

        content_wrap = tk.Frame(root, bg="#EEF5FF")
        content_wrap.pack(side="left", fill="both", expand=True, padx=(14, 0))
        self.content_canvas = tk.Canvas(content_wrap, bg="#EEF5FF", highlightthickness=0)
        self.content_scrollbar = ttk.Scrollbar(content_wrap, orient="vertical", command=self.content_canvas.yview)
        self.content_canvas.configure(yscrollcommand=self.content_scrollbar.set)
        self.content_scrollbar.pack(side="right", fill="y")
        self.content_canvas.pack(side="left", fill="both", expand=True)

        self.content = tk.Frame(self.content_canvas, bg="#EEF5FF")
        self.content_window_id = self.content_canvas.create_window((0, 0), window=self.content, anchor="nw")
        self.content.bind("<Configure>", self._on_content_configure)
        self.content_canvas.bind("<Configure>", self._on_canvas_configure)

        tk.Label(self.content, text="Hasil Proses AES-LSB", font=("Segoe UI", 34, "bold"), bg="#EEF5FF", fg="#114B9B").pack(
            anchor="w", pady=(0, 12)
        )

        info_shadow = tk.Frame(self.content, bg="#D9E7FB")
        info_shadow.pack(fill="x", pady=(0, 14))
        info_box = tk.Frame(info_shadow, bg="#FFFFFF", highlightbackground="#D8E3F2", highlightthickness=1, bd=0)
        info_box.pack(fill="x", padx=(0, 2), pady=(0, 2), ipady=10)
        info_top = tk.Frame(info_box, bg="#FFFFFF")
        info_top.pack(fill="x", padx=16, pady=(10, 4))
        info_icon = self._load_icon_asset(["verified.png"], (30, 30))
        if info_icon is not None:
            self.icon_refs["verified"] = info_icon
            tk.Label(info_top, image=info_icon, bg="#FFFFFF").pack(side="left")
        else:
            tk.Label(info_top, text="i", bg="#EAF2FF", fg="#114B9B", font=("Segoe UI", 12, "bold"), width=2).pack(side="left")
        tk.Label(info_top, text="information box", bg="#FFFFFF", fg="#114B9B", font=("Segoe UI", 22, "bold")).pack(
            side="left", padx=16
        )
        info_text = (
            "Halaman hasil menampilkan output steganografi, metadata file, informasi enkripsi AES, "
            "serta evaluasi kualitas citra (PSNR, MSE, SSIM, NCC) dengan tampilan modern untuk mendukung "
            "monitoring keamanan data rekam medis."
        )
        tk.Label(info_box, text=info_text, bg="#FFFFFF", fg="#334155", wraplength=980, justify="left", font=("Segoe UI", 10)).pack(
            anchor="w", padx=16, pady=(0, 8)
        )

        preview_card = self._create_card(self.content, "Gambar Hasil Steganografi", "image.png")
        top = tk.Frame(preview_card, bg="#FFFFFF")
        top.pack(fill="x", padx=14, pady=(0, 10))
        self.img_label = tk.Label(top, text="Belum ada hasil gambar.", bg="#FFFFFF", width=32, height=10)
        self.img_label.pack(side="left")
        self.file_meta_var = tk.StringVar(value="Nama file: -\nUkuran: -\nDimensi: -\nFormat: -")
        tk.Label(top, textvariable=self.file_meta_var, bg="#FFFFFF", fg="#334155", justify="left", font=("Segoe UI", 10)).pack(
            side="left", padx=16, anchor="n"
        )

        btns = tk.Frame(preview_card, bg="#FFFFFF")
        btns.pack(anchor="w", padx=14, pady=(0, 12))
        tk.Button(
            btns, text="Download Gambar", command=self.download_image, bg="#2E7CF6", fg="#FFFFFF",
            activebackground="#1F67D9", activeforeground="#FFFFFF", relief="flat", bd=0, cursor="hand2",
            font=("Segoe UI", 10, "bold"), padx=16, pady=8
        ).pack(side="left")
        tk.Button(
            btns, text="Preview", command=self.open_preview_window, bg="#EAF2FF", fg="#114B9B",
            activebackground="#D8E8FF", relief="flat", bd=0, cursor="hand2",
            font=("Segoe UI", 10, "bold"), padx=16, pady=8
        ).pack(side="left", padx=(10, 0))

        enc_card = self._create_card(self.content, "Informasi Enkripsi (AES)", "padlock.jpeg")
        self.enc_info_var = tk.StringVar(value="-")
        tk.Label(enc_card, textvariable=self.enc_info_var, bg="#FFFFFF", fg="#334155", justify="left", font=("Consolas", 10)).pack(
            anchor="w", padx=14, pady=(0, 12)
        )

        eval_card = self._create_card(self.content, "Evaluasi AES-LSB", "signal-status.png")
        self.eval_table = ttk.Treeview(eval_card, columns=("metric", "value", "desc"), show="headings", height=4)
        self.eval_table.heading("metric", text="Parameter Metrik")
        self.eval_table.heading("value", text="Nilai")
        self.eval_table.heading("desc", text="Keterangan")
        self.eval_table.column("metric", width=220, anchor="w")
        self.eval_table.column("value", width=220, anchor="center")
        self.eval_table.column("desc", width=260, anchor="center")
        self.eval_table.pack(fill="x", padx=14, pady=(0, 12))

        tk.Button(
            self.content,
            text="Kembali ke Input",
            command=lambda: self.controller.show_frame("InputPage"),
            bg="#2E7CF6",
            fg="#FFFFFF",
            activebackground="#1F67D9",
            activeforeground="#FFFFFF",
            relief="flat",
            bd=0,
            font=("Segoe UI", 10, "bold"),
            cursor="hand2",
            padx=16,
            pady=10,
        ).pack(anchor="e", side="bottom", pady=(8, 0))

    def _create_menu_item(self, parent: tk.Frame, label: str, icon_name: str, active: bool, command) -> None:
        bg_color = "#4A90FF" if active else "#DCEBFF"
        item = tk.Frame(parent, bg=bg_color, padx=12, pady=11)
        item.pack(fill="x", padx=10, pady=5)

        icon = self._load_icon_asset([icon_name], (16, 16))
        if icon is not None:
            self.menu_icon_refs[label] = icon
            tk.Label(item, image=icon, bg=bg_color).pack(side="left")

        text_color = "#FFFFFF" if active else "#173A68"
        tk.Label(item, text=label, bg=bg_color, fg=text_color, font=("Segoe UI", 10, "bold")).pack(
            side="left", padx=(8, 0)
        )
        if command is not None:
            item.bind("<Button-1>", lambda _evt, fn=command: fn())
            for child in item.winfo_children():
                child.bind("<Button-1>", lambda _evt, fn=command: fn())

    def _on_content_configure(self, _event) -> None:
        self.content_canvas.configure(scrollregion=self.content_canvas.bbox("all"))

    def _on_canvas_configure(self, event) -> None:
        self.content_canvas.itemconfigure(self.content_window_id, width=event.width)

    def _load_icon_asset(self, filenames: list[str], size: tuple[int, int]):
        if Image is None or ImageTk is None:
            return None
        for filename in filenames:
            path = Path(filename)
            if not path.exists():
                continue
            try:
                icon_img = Image.open(path).convert("RGBA")
                icon_img.thumbnail(size)
                return ImageTk.PhotoImage(icon_img)
            except Exception:
                continue
        return None

    def _create_card(self, parent: tk.Widget, title: str, icon_name: str) -> tk.Frame:
        shadow = tk.Frame(parent, bg="#DCE8F8")
        shadow.pack(fill="x", pady=(0, 12))
        card = tk.Frame(shadow, bg="#FFFFFF", highlightbackground="#D9E3F0", highlightthickness=1, bd=0)
        card.pack(fill="x", padx=(0, 2), pady=(0, 2))
        title_row = tk.Frame(card, bg="#FFFFFF")
        title_row.pack(fill="x", padx=14, pady=(12, 8))
        icon = self._load_icon_asset([icon_name], (18, 18))
        if icon is not None:
            self.icon_refs[f"{title}_{icon_name}"] = icon
            tk.Label(title_row, image=icon, bg="#FFFFFF").pack(side="left")
        tk.Label(title_row, text=title, bg="#FFFFFF", fg="#1D4ED8", font=("Segoe UI", 12, "bold")).pack(side="left", padx=(7, 0))
        return card

    def refresh(self) -> None:
        stego_path = self.controller.stego_output_path
        if not stego_path:
            self.img_label.configure(text="Belum ada hasil gambar.", image="")
            return
        try:
            self._set_preview_image(stego_path)
        except Exception:
            self.img_label.configure(text=f"Hasil tersimpan: {stego_path}", image="")

        file_size_kb = stego_path.stat().st_size / 1024
        img_format = stego_path.suffix.replace(".", "").upper() or "-"
        dimensions = "-"
        if Image is not None:
            try:
                with Image.open(stego_path) as img:
                    dimensions = f"{img.width} x {img.height}"
                    if img.format:
                        img_format = img.format.upper()
            except Exception:
                pass
        self.file_meta_var.set(
            f"Nama file: {stego_path.name}\nUkuran: {file_size_kb:.2f} KB\nDimensi: {dimensions}\nFormat: {img_format}"
        )

        enc = self.controller.encryption_info
        rows = [
            ("Algoritma", enc.get("algorithm", "AES-128")),
            ("Key (Hex)", enc.get("key_hex", "-")),
            ("IV (Hex)", enc.get("iv_hex", "-")),
            ("Ukuran data asli", self._format_bytes(enc.get("original_size_bytes", 0))),
            ("Ukuran data enkripsi", self._format_bytes(enc.get("encrypted_size_bytes", 0))),
            ("Waktu proses", f"{enc.get('process_time_sec', 0.0):.3f} detik"),
        ]
        self.enc_info_var.set("\n".join(f"{k:<21}: {v}" for k, v in rows))
        self._refresh_eval_table(self.controller.eval_metrics)

    def _set_preview_image(self, image_path: Path) -> None:
        if Image is None or ImageTk is None:
            return
        with Image.open(image_path) as img:
            preview = img.convert("RGB")
            preview.thumbnail((260, 260))
            self.current_preview = ImageTk.PhotoImage(preview)
            self.img_label.configure(image=self.current_preview, text="")

    def _refresh_eval_table(self, metrics: dict) -> None:
        for row_id in self.eval_table.get_children():
            self.eval_table.delete(row_id)
        psnr = float(metrics.get("PSNR", 0))
        mse = float(metrics.get("MSE", 0))
        ssim = float(metrics.get("SSIM", 0))
        ncc = float(metrics.get("NCC", 0))

        self.eval_table.insert("", "end", values=("PSNR", f"{psnr:.2f} dB", self._psnr_desc(psnr)))
        self.eval_table.insert("", "end", values=("MSE", f"{mse:.6f}", self._mse_desc(mse)))
        self.eval_table.insert("", "end", values=("SSIM", f"{ssim:.6f}", self._ssim_desc(ssim)))
        self.eval_table.insert("", "end", values=("NCC", f"{ncc:.6f}", self._ncc_desc(ncc)))

    def _psnr_desc(self, value: float) -> str:
        return "Sangat Baik" if value >= 40 else "Baik" if value >= 30 else "Buruk"

    def _mse_desc(self, value: float) -> str:
        return "Sangat Baik" if value <= 0.005 else "Baik" if value <= 0.02 else "Buruk"

    def _ssim_desc(self, value: float) -> str:
        return "Sangat Baik" if value >= 0.95 else "Baik" if value >= 0.85 else "Buruk"

    def _ncc_desc(self, value: float) -> str:
        return "Sangat Baik" if value >= 0.99 else "Baik" if value >= 0.95 else "Buruk"

    def _format_bytes(self, size_bytes: int) -> str:
        if size_bytes < 1024:
            return f"{size_bytes} B"
        if size_bytes < 1024 * 1024:
            return f"{size_bytes / 1024:.2f} KB"
        return f"{size_bytes / (1024 * 1024):.2f} MB"

    def open_preview_window(self) -> None:
        stego_path = self.controller.stego_output_path
        if not stego_path:
            messagebox.showwarning("Belum Ada Hasil", "Belum ada gambar hasil untuk dipreview.")
            return
        if Image is None or ImageTk is None:
            messagebox.showinfo("Preview", f"Preview penuh tersedia di:\n{stego_path}")
            return
        with Image.open(stego_path) as img:
            preview = img.convert("RGB")
            preview.thumbnail((600, 600))
            popup = tk.Toplevel(self)
            popup.title("Preview Gambar Hasil")
            popup.configure(bg="#FFFFFF")
            popup_img = ImageTk.PhotoImage(preview)
            label = tk.Label(popup, image=popup_img, bg="#FFFFFF")
            label.image = popup_img
            label.pack(padx=12, pady=12)

    def download_image(self) -> None:
        if not self.controller.stego_output_path:
            messagebox.showwarning("Belum Ada Hasil", "Jalankan proses AES-LSB terlebih dahulu.")
            return
        destination = filedialog.asksaveasfilename(
            title="Simpan stego image",
            defaultextension=".png",
            filetypes=[("PNG Image", "*.png"), ("All files", "*.*")],
        )
        if destination:
            shutil.copy(self.controller.stego_output_path, destination)
            messagebox.showinfo("Berhasil", f"Gambar berhasil disimpan ke:\n{destination}")


class DeteksiAnomaliPage(ttk.Frame):
    def __init__(self, parent, controller: SecurityMedicalApp):
        super().__init__(parent)
        self.controller = controller
        self.menu_icon_refs = {}
        self.icon_refs = {}

        root = tk.Frame(self, bg="#EEF5FF")
        root.pack(fill="both", expand=True, padx=14, pady=14)

        sidebar = tk.Frame(root, bg="#DCEBFF", width=200)
        sidebar.pack(side="left", fill="y")
        sidebar.pack_propagate(False)
        tk.Label(sidebar, text="Menu", bg="#DCEBFF", fg="#173A68", font=("Segoe UI", 16, "bold")).pack(anchor="center", pady=(18, 12))
        self._create_menu_item(sidebar, "Input Data", "google-docs.png", active=False, command=lambda: controller.show_frame("InputPage"))
        self._create_menu_item(sidebar, "Hasil", "photo.png", active=False, command=lambda: controller.show_frame("ResultPage"))
        self._create_menu_item(sidebar, "Deteksi Anomali", "focus.png", active=True, command=None)
        self._create_menu_item(sidebar, "Logout", "logout.png", active=False, command=controller.close_app)

        content_wrap = tk.Frame(root, bg="#EEF5FF")
        content_wrap.pack(side="left", fill="both", expand=True, padx=(14, 0))
        canvas = tk.Canvas(content_wrap, bg="#EEF5FF", highlightthickness=0)
        scrollbar = ttk.Scrollbar(content_wrap, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)
        content = tk.Frame(canvas, bg="#EEF5FF")
        window_id = canvas.create_window((0, 0), window=content, anchor="nw")
        content.bind("<Configure>", lambda _e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.bind("<Configure>", lambda e: canvas.itemconfigure(window_id, width=e.width))

        tk.Label(content, text="Deteksi Anomali", font=("Segoe UI", 34, "bold"), bg="#EEF5FF", fg="#114B9B").pack(anchor="w", pady=(0, 12))
        info_shadow = tk.Frame(content, bg="#D9E7FB")
        info_shadow.pack(fill="x", pady=(0, 14))
        info_box = tk.Frame(info_shadow, bg="#FFFFFF", highlightbackground="#D8E3F2", highlightthickness=1, bd=0)
        info_box.pack(fill="x", padx=(0, 2), pady=(0, 2), ipady=10)
        top = tk.Frame(info_box, bg="#FFFFFF")
        top.pack(fill="x", padx=16, pady=(10, 4))
        icon = self._load_icon_asset(["verified.png"], (30, 30))
        if icon is not None:
            self.icon_refs["verified"] = icon
            tk.Label(top, image=icon, bg="#FFFFFF").pack(side="left")
        tk.Label(top, text="information box", bg="#FFFFFF", fg="#114B9B", font=("Segoe UI", 22, "bold")).pack(side="left", padx=16)
        tk.Label(
            info_box,
            text="Halaman deteksi anomali ini digunakan untuk menampilkan hasil klasifikasi aktivitas sistem menggunakan algoritma Support Vector Machine (SVM).",
            bg="#FFFFFF",
            fg="#334155",
            wraplength=980,
            justify="left",
            font=("Segoe UI", 10),
        ).pack(anchor="w", padx=16, pady=(0, 8))

        columns = tk.Frame(content, bg="#EEF5FF")
        columns.pack(fill="x", pady=(0, 14))
        columns.grid_columnconfigure(0, weight=1, uniform="dash")
        columns.grid_columnconfigure(1, weight=1, uniform="dash")
        columns.grid_columnconfigure(2, weight=1, uniform="dash")
        left_col = tk.Frame(columns, bg="#EEF5FF")
        left_col.grid(row=0, column=0, sticky="nsew", padx=(0, 10))
        mid_col = tk.Frame(columns, bg="#EEF5FF")
        mid_col.grid(row=0, column=1, sticky="nsew", padx=5)
        right_col = tk.Frame(columns, bg="#EEF5FF")
        right_col.grid(row=0, column=2, sticky="nsew", padx=(10, 0))
        self._build_detection_card(left_col)
        self._build_model_info_card(mid_col)
        self._build_metrics_card(mid_col)
        self._build_history_chart_card(right_col)
        self._build_table_history_card(content)

    def _create_menu_item(self, parent: tk.Frame, label: str, icon_name: str, active: bool, command) -> None:
        bg_color = "#4A90FF" if active else "#DCEBFF"
        item = tk.Frame(parent, bg=bg_color, padx=12, pady=11)
        item.pack(fill="x", padx=10, pady=5)
        icon = self._load_icon_asset([icon_name], (16, 16))
        if icon is not None:
            self.menu_icon_refs[label] = icon
            tk.Label(item, image=icon, bg=bg_color).pack(side="left")
        text_color = "#FFFFFF" if active else "#173A68"
        tk.Label(item, text=label, bg=bg_color, fg=text_color, font=("Segoe UI", 10, "bold")).pack(side="left", padx=(8, 0))
        if command is not None:
            item.bind("<Button-1>", lambda _evt, fn=command: fn())
            for child in item.winfo_children():
                child.bind("<Button-1>", lambda _evt, fn=command: fn())

    def _load_icon_asset(self, filenames: list[str], size: tuple[int, int]):
        if Image is None or ImageTk is None:
            return None
        for filename in filenames:
            path = Path(filename)
            if not path.exists():
                continue
            try:
                icon_img = Image.open(path).convert("RGBA")
                icon_img.thumbnail(size)
                return ImageTk.PhotoImage(icon_img)
            except Exception:
                continue
        return None

    def _create_card(self, parent: tk.Widget, title: str, icon_name: str) -> tk.Frame:
        shadow = tk.Frame(parent, bg="#DCE8F8")
        shadow.pack(fill="x", pady=(0, 12))
        card = tk.Frame(shadow, bg="#FFFFFF", highlightbackground="#D9E3F0", highlightthickness=1, bd=0)
        card.pack(fill="x", padx=(0, 2), pady=(0, 2))
        title_row = tk.Frame(card, bg="#FFFFFF")
        title_row.pack(fill="x", padx=14, pady=(12, 8))
        icon = self._load_icon_asset([icon_name], (18, 18))
        if icon is not None:
            self.icon_refs[f"{title}_{icon_name}"] = icon
            tk.Label(title_row, image=icon, bg="#FFFFFF").pack(side="left")
        tk.Label(title_row, text=title, bg="#FFFFFF", fg="#1D4ED8", font=("Segoe UI", 12, "bold")).pack(side="left", padx=(7, 0))
        return card

    def _build_detection_card(self, parent: tk.Widget) -> None:
        card = self._create_card(parent, "Hasil Deteksi Anomali", "focus.png")
        gauge = tk.Canvas(card, width=302, height=176, bg="#FFFFFF", highlightthickness=0)
        gauge.pack(padx=10, pady=(0, 8))
        gauge.create_arc((50, 30, 252, 232), start=0, extent=180, style="arc", outline="#D6E4FF", width=18)
        gauge.create_arc((50, 30, 252, 232), start=18, extent=136, style="arc", outline="#4A90FF", width=18)
        warning_icon = self._load_icon_asset(["warning segitiga.png"], (26, 26))
        if warning_icon is not None:
            self.icon_refs["warning"] = warning_icon
            gauge.create_image(151, 82, image=warning_icon)
        gauge.create_text(151, 112, text="ANOMALI\nTERDETEKSI", fill="#1D4ED8", font=("Segoe UI", 12, "bold"), justify="center")
        details = [
            ("Status", "ANOMALI"),
            ("Tingkat Kepercayaan", "96.42%"),
            ("Kelas Prediksi", "Anomali"),
            ("Waktu Proses", "2.13 detik"),
            ("Waktu Deteksi", "10 Mei 2026 15:24:31"),
        ]
        detail_wrap = tk.Frame(card, bg="#F8FBFF")
        detail_wrap.pack(fill="x", padx=14, pady=(0, 12))
        for idx, (label, value) in enumerate(details):
            row = tk.Frame(detail_wrap, bg="#F8FBFF")
            row.pack(fill="x", pady=2)
            tk.Label(row, text=label, bg="#F8FBFF", fg="#334155", font=("Segoe UI", 9)).pack(side="left")
            tk.Label(row, text=value, bg="#F8FBFF", fg="#0F4AA3", font=("Segoe UI", 9, "bold")).pack(side="right")
            if idx < len(details) - 1:
                tk.Frame(detail_wrap, bg="#E2E8F0", height=1).pack(fill="x", pady=1)

    def _build_model_info_card(self, parent: tk.Widget) -> None:
        card = self._create_card(parent, "Informasi Model SVM", "magnifying-glass.png")
        body = tk.Frame(card, bg="#FFFFFF")
        body.pack(fill="x", padx=14, pady=(0, 12))
        for label, value in [
            ("Tipe Model", "SVM Klasifikasi"),
            ("Kernel", "RBF (Radial Basis Function)"),
            ("Akurasi Model", "93.87%"),
            ("Versi Model", "SVM_Model"),
        ]:
            row = tk.Frame(body, bg="#FFFFFF")
            row.pack(fill="x", pady=3)
            tk.Label(row, text=label, bg="#FFFFFF", fg="#475467", font=("Segoe UI", 9)).pack(side="left")
            tk.Label(row, text=value, bg="#FFFFFF", fg="#0F4AA3", font=("Segoe UI", 9, "bold")).pack(side="right")

    def _build_metrics_card(self, parent: tk.Widget) -> None:
        card = self._create_card(parent, "Metrik Performa Deteksi", "signal-status.png")
        body = tk.Frame(card, bg="#FFFFFF")
        body.pack(fill="x", padx=14, pady=(0, 12))
        metrics = [
            ("Akurasi", 93.87, "#1D4ED8"),
            ("Presisi", 94.21, "#2E8B57"),
            ("Recall", 93.12, "#FD6A00"),
            ("F1-Score", 93.66, "#592693"),
        ]
        for label, value, color in metrics:
            row = tk.Frame(body, bg="#FFFFFF")
            row.pack(fill="x", pady=(2, 8))
            tk.Label(row, text=label, bg="#FFFFFF", fg="#334155", font=("Segoe UI", 9, "bold")).pack(side="left")
            tk.Label(row, text=f"{value:.2f}%", bg="#FFFFFF", fg="#334155", font=("Segoe UI", 9)).pack(side="right")
            bar = tk.Canvas(body, height=11, bg="#FFFFFF", highlightthickness=0)
            bar.pack(fill="x")
            bar_width = 290
            bar.create_rectangle(0, 0, bar_width, 11, fill="#E5E7EB", width=0)
            bar.create_rectangle(0, 0, int(bar_width * (value / 100.0)), 11, fill=color, width=0)

    def _build_history_chart_card(self, parent: tk.Widget) -> None:
        card = self._create_card(parent, "Grafik History", "bar-chart.png")
        chart = tk.Canvas(card, width=318, height=250, bg="#FFFFFF", highlightthickness=0)
        chart.pack(fill="x", padx=14, pady=(0, 6))
        chart.create_line(44, 200, 296, 200, fill="#94A3B8", width=2)
        chart.create_line(44, 36, 44, 200, fill="#94A3B8", width=2)
        chart.create_text(24, 44, text="30", fill="#64748B", font=("Segoe UI", 8))
        chart.create_text(24, 92, text="20", fill="#64748B", font=("Segoe UI", 8))
        chart.create_text(24, 142, text="10", fill="#64748B", font=("Segoe UI", 8))
        bars = [("sql injection", 156), ("xss", 98), ("bruteforce", 132)]
        x = 72
        for label, height in bars:
            chart.create_rectangle(x, 200 - height, x + 40, 200, fill="#60A5FA", width=0)
            chart.create_text(x + 20, 218, text=label, fill="#334155", font=("Segoe UI", 8))
            x += 78
        tk.Label(card, text="serangan dilakukan dalam 24 jam terakhir", bg="#FFFFFF", fg="#6B7280", font=("Segoe UI", 9)).pack(
            anchor="w", padx=14, pady=(0, 12)
        )

    def _build_table_history_card(self, parent: tk.Widget) -> None:
        card = self._create_card(parent, "table history", "file.png")
        table = ttk.Treeview(card, columns=("jenis", "bentuk", "kesempatan", "waktu"), show="headings", height=5)
        table.heading("jenis", text="Jenis Serangan")
        table.heading("bentuk", text="Bentuk Serangan")
        table.heading("kesempatan", text="Kesempatan (1-3)")
        table.heading("waktu", text="Waktu")
        table.column("jenis", width=130, anchor="w")
        table.column("bentuk", width=290, anchor="w")
        table.column("kesempatan", width=130, anchor="center")
        table.column("waktu", width=200, anchor="center")
        table.pack(fill="x", padx=14, pady=(0, 14))
        rows = [
            ("SQL Injection", "Input ' OR '1'='1 pada form login", "3", "10-05-2026 14:55:12"),
            ("XSS", "Script <script>alert(1)</script> pada parameter URL", "2", "10-05-2026 15:02:41"),
            ("Bruteforce", "Percobaan login berulang pada akun admin", "1", "10-05-2026 15:10:03"),
        ]
        for row in rows:
            table.insert("", "end", values=row)


if __name__ == "__main__":
    app = SecurityMedicalApp()
    app.mainloop()