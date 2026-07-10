import os
import threading
import queue
import time
import concurrent.futures
import tkinter as tk
import json
import subprocess
from tkinter import filedialog, messagebox, ttk, scrolledtext
from pathlib import Path
import shutil

from AnalysisEngine import AnalysisEngine


class VulnerabilityScannerUI:
    def __init__(self, root_window: tk.Tk):
        self.root_window = root_window
        self.root_window.title("TinkerMole")
        self.root_window.geometry("1100x900")
        self.root_window.minsize(1050, 750)

        # Tema Renk Paleti - "The Wind Rises" İlhamlı
        self.theme_colors = {
            "background": "#E8F0F2",
            "card_bg": "#FFFFFF",
            "primary_text": "#2C3E50",
            "secondary_text": "#7F8C8D",
            "button_primary": "#5C9EAD",
            "button_primary_hover": "#4A8291",
            "button_danger": "#D96C6C",
            "button_success": "#7BAE7F",
            "button_intellij": "#A2708A",
            "border_color": "#D1DDE3",
            "terminal_bg": "#1E272E",
            "terminal_fg": "#E0E6ED"
        }

        self.total_applications_processed: int = 0
        self.selected_target_files: list = []
        self.completed_project_directories: list = []

        self.system_log_queue = queue.Queue()
        self.execution_stop_event = threading.Event()
        self.statistics_lock = threading.Lock()

        self.base_directory = Path(__file__).resolve().parent
        self.activity_log_path = self.base_directory / "scanner_activity.log"
        self.system_configuration_path = self.base_directory / "scanner_config.json"

        self.system_dependencies = self._verify_and_load_dependencies()

        self._apply_visual_theme()
        self._construct_user_interface()

        self.root_window.after(100, self._process_incoming_logs)
        self._run_initial_system_diagnostics()

    def _verify_and_load_dependencies(self) -> dict:
        """Sistemdeki bağımlılıkları kontrol eder (Örn: dex2jar)."""
        is_windows = os.name == 'nt'
        command_extension = '.bat' if is_windows else '.sh'
        local_dex2jar_path = self.base_directory / 'dex-tools' / f'd2j-dex2jar{command_extension}'

        def resolve_absolute_path(local_path: Path, executable_name: str) -> str:
            if local_path.exists(): return str(local_path.resolve())
            system_path = shutil.which(executable_name) or shutil.which(executable_name + '.bat')
            return str(Path(system_path).resolve()) if system_path else ""

        return {'dex2jar': resolve_absolute_path(local_dex2jar_path, 'd2j-dex2jar')}

    def _update_config_file(self, key: str, value: str):
        """Konfigürasyon dosyasını (diğer ayarları bozmadan) günceller."""
        config_data = {}
        if self.system_configuration_path.exists():
            try:
                with open(self.system_configuration_path, 'r', encoding='utf-8') as config_file:
                    config_data = json.load(config_file)
            except Exception:
                pass

        config_data[key] = value
        try:
            with open(self.system_configuration_path, 'w', encoding='utf-8') as config_file:
                json.dump(config_data, config_file, indent=4)
        except Exception:
            pass

    def _get_or_prompt_ghidra_path(self) -> str:
        """Ghidra yolunu konfigürasyondan alır, yoksa kullanıcıya sorar."""
        ghidra_headless_path = None
        if self.system_configuration_path.exists():
            try:
                with open(self.system_configuration_path, 'r', encoding='utf-8') as config_file:
                    ghidra_headless_path = json.load(config_file).get('ghidra_path')
            except Exception:
                pass

        if not ghidra_headless_path or not Path(ghidra_headless_path).exists():
            messagebox.showinfo(
                "Ghidra Configuration Required",
                "Otomatik Ghidra analizi seçtiniz ancak sistem Ghidra kurulumunuzu bulamadı.\n\n"
                "Lütfen açılan pencerede 'analyzeHeadless.bat' (veya .sh) dosyasını seçin.\n"
                "(Genellikle Ghidra/support/ klasörü içindedir)\n\n"
                "Bu işlem sadece bir kere sorulacaktır."
            )

            ghidra_headless_path = filedialog.askopenfilename(
                title="Locate analyzeHeadless",
                filetypes=[("Executable/Script Files", "*.bat *.sh *")]
            )

            if ghidra_headless_path:
                self._update_config_file('ghidra_path', ghidra_headless_path)
            else:
                return ""

        return ghidra_headless_path

    def _apply_visual_theme(self):
        """Arayüz stillerini uygular."""
        style_manager = ttk.Style(self.root_window)
        if 'clam' in style_manager.theme_names():
            style_manager.theme_use('clam')

        self.root_window.configure(bg=self.theme_colors["background"])

        style_manager.configure('.', font=('Segoe UI', 10), background=self.theme_colors["background"],
                                foreground=self.theme_colors["primary_text"])
        style_manager.configure('Card.TFrame', background=self.theme_colors["card_bg"])
        style_manager.configure('Header.TLabel', font=('Segoe UI', 12, 'bold'), background=self.theme_colors["card_bg"],
                                foreground=self.theme_colors["primary_text"])
        style_manager.configure('Sub.TLabel', font=('Segoe UI', 10), background=self.theme_colors["card_bg"],
                                foreground=self.theme_colors["secondary_text"])
        style_manager.configure('TCheckbutton', background=self.theme_colors["card_bg"], font=('Segoe UI', 10))
        style_manager.map('TCheckbutton', background=[('active', self.theme_colors["card_bg"])])

        style_manager.configure('TButton', font=('Segoe UI', 10, 'bold'), padding=10, relief='flat')

        style_manager.configure('Browse.TButton', background="#E4E6EB", foreground=self.theme_colors["primary_text"])
        style_manager.map('Browse.TButton', background=[('active', '#D8DADF')])

        style_manager.configure('Start.TButton', background=self.theme_colors["button_primary"], foreground="white")
        style_manager.map('Start.TButton',
                          background=[('active', self.theme_colors["button_primary_hover"]), ('disabled', '#B0C4DE')])

        style_manager.configure('Cancel.TButton', background=self.theme_colors["button_danger"], foreground="white")
        style_manager.map('Cancel.TButton', background=[('active', '#C95A5A'), ('disabled', '#F3B3BC')])

        style_manager.configure('Folder.TButton', background=self.theme_colors["button_success"], foreground="white")
        style_manager.map('Folder.TButton', background=[('active', '#66966A'), ('disabled', '#A3D9B0')])

        style_manager.configure('IntelliJ.TButton', background=self.theme_colors["button_intellij"], foreground="white")
        style_manager.map('IntelliJ.TButton', background=[('active', '#8C5D76'), ('disabled', '#E3A1C3')])

        style_manager.configure('Horizontal.TProgressbar', background=self.theme_colors["button_primary"],
                                troughcolor='#E4E6EB', borderwidth=0)

    def _build_interface_card(self, parent_widget, title_text, description_text=""):
        container_frame = tk.Frame(parent_widget, bg=self.theme_colors["border_color"], padx=1, pady=1)
        card_frame = ttk.Frame(container_frame, style='Card.TFrame')
        card_frame.pack(fill="both", expand=True)

        header_area = ttk.Frame(card_frame, style='Card.TFrame')
        header_area.pack(fill="x", padx=25, pady=(25, 10))

        ttk.Label(header_area, text=title_text, style='Header.TLabel').pack(anchor="w")
        if description_text:
            ttk.Label(header_area, text=description_text, style='Sub.TLabel').pack(anchor="w", pady=(5, 0))

        content_area = ttk.Frame(card_frame, style='Card.TFrame')
        content_area.pack(fill="both", expand=True, padx=25, pady=(0, 25))

        return container_frame, content_area

    def _construct_user_interface(self):
        """Kullanıcı arayüzü elemanlarını oluşturur."""
        self.root_window.columnconfigure(0, weight=1)
        self.root_window.rowconfigure(0, weight=1)

        main_canvas_area = tk.Canvas(self.root_window, bg=self.theme_colors["background"], highlightthickness=0)
        main_canvas_area.pack(fill="both", expand=True, padx=35, pady=35)

        file_card_container, file_card_content = self._build_interface_card(
            main_canvas_area,
            "1. Target Application Files",
            "Select Android application packages to analyze."
        )
        file_card_container.pack(fill="x", pady=(0, 25))

        file_card_content.columnconfigure(0, weight=1)
        self.selected_files_display_entry = ttk.Entry(file_card_content, state="readonly", font=('Segoe UI', 11))
        self.selected_files_display_entry.grid(row=0, column=0, sticky="ew", padx=(0, 15), ipady=6)
        self.browse_files_button = ttk.Button(file_card_content, text="Browse Files", command=self._event_browse_files,
                                              style='Browse.TButton')
        self.browse_files_button.grid(row=0, column=1)

        settings_card_container, settings_card_content = self._build_interface_card(
            main_canvas_area,
            "2. Analysis Modules",
            "Select which actions to perform on the targets."
        )
        settings_card_container.pack(fill="x", pady=(0, 25))

        self.enable_backup_option = tk.BooleanVar(value=True)
        self.enable_decompilation_option = tk.BooleanVar(value=True)
        self.enable_vulnerability_scan_option = tk.BooleanVar(value=True)
        self.enable_auto_ghidra_option = tk.BooleanVar(value=True)

        user_selectable_options = [
            ("Secure Original Packages (Move to Backups)", self.enable_backup_option),
            ("Decompile DEX to JAR & Generate IntelliJ IDE Project", self.enable_decompilation_option),
            ("Extract Vulnerabilities, API Keys & Dump Binary Strings", self.enable_vulnerability_scan_option),
            ("If Flutter detected, automatically analyze and open in Ghidra (Otomatik Ghidra)",
             self.enable_auto_ghidra_option)
        ]

        for index, (description, boolean_variable) in enumerate(user_selectable_options):
            ttk.Checkbutton(settings_card_content, text=description, variable=boolean_variable).pack(anchor="w", pady=6)

        action_card_container, action_card_content = self._build_interface_card(main_canvas_area,
                                                                                "3. Execution & Results")
        action_card_container.pack(fill="x", pady=(0, 25))

        button_grid_frame = ttk.Frame(action_card_content, style='Card.TFrame')
        button_grid_frame.pack(fill="x")

        button_grid_frame.columnconfigure((0, 1, 2, 3), weight=1)

        self.start_analysis_button = ttk.Button(button_grid_frame, text="▶ START ANALYSIS", state="disabled",
                                                command=self._event_start_analysis, style='Start.TButton')
        self.start_analysis_button.grid(row=0, column=0, padx=5, sticky="ew")

        self.cancel_analysis_button = ttk.Button(button_grid_frame, text="■ CANCEL", state="disabled",
                                                 command=self._event_cancel_analysis, style='Cancel.TButton')
        self.cancel_analysis_button.grid(row=0, column=1, padx=5, sticky="ew")

        self.open_in_intellij_button = ttk.Button(button_grid_frame, text="❖ Open in IntelliJ", state="disabled",
                                                  command=self._event_open_intellij, style='IntelliJ.TButton')
        self.open_in_intellij_button.grid(row=0, column=2, padx=5, sticky="ew")

        self.open_output_folder_button = ttk.Button(button_grid_frame, text="📁 Open Outputs", state="disabled",
                                                    command=self._event_open_output_folder, style='Folder.TButton')
        self.open_output_folder_button.grid(row=0, column=3, padx=5, sticky="ew")

        self.activity_progress_bar = ttk.Progressbar(action_card_content, orient="horizontal", mode="indeterminate")
        self.activity_progress_bar.pack(fill="x", pady=(25, 10))

        self.status_display_label_var = tk.StringVar(value="System ready. Awaiting file selection...")
        self.status_display_label = ttk.Label(action_card_content, textvariable=self.status_display_label_var,
                                              font=('Segoe UI', 10, 'italic'), style='Sub.TLabel')
        self.status_display_label.pack(anchor="w")

        console_container = tk.Frame(main_canvas_area, bg=self.theme_colors["border_color"], padx=1, pady=1)
        console_container.pack(fill="both", expand=True)

        console_header = tk.Frame(console_container, bg="#192026", height=32)
        console_header.pack(fill="x")
        console_header.pack_propagate(False)
        tk.Label(console_header, text=">_ System Terminal", bg="#192026", fg="#A3B8CC",
                 font=('Consolas', 10, 'bold')).pack(side="left", padx=15)

        self.terminal_text_area = scrolledtext.ScrolledText(
            console_container, wrap="word", font=('Consolas', 10),
            bg=self.theme_colors["terminal_bg"], fg=self.theme_colors["terminal_fg"],
            insertbackground=self.theme_colors["terminal_fg"], relief='flat',
            padx=15, pady=15, borderwidth=0
        )
        self.terminal_text_area.pack(fill="both", expand=True)
        self.terminal_text_area.config(state="disabled")

    def _run_initial_system_diagnostics(self):
        self._write_system_log("--- System Diagnostics ---", internal=True)
        for tool_name, tool_path in self.system_dependencies.items():
            if tool_path:
                self._write_system_log(f"[OK] {tool_name.upper()} verified at: {tool_path}", internal=True)
            else:
                self._write_system_log(f"[WARN] {tool_name.upper()} is missing. Decompilation will fail.",
                                       is_error=True, internal=True)
        self._write_system_log("--- Ready ---", internal=True)

    def _write_system_log(self, message: str, is_error: bool = False, internal: bool = False):
        self.system_log_queue.put((message, is_error, internal))
        try:
            current_timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
            with open(self.activity_log_path, "a", encoding="utf-8") as log_file:
                log_file.write(f"[{current_timestamp}] {'[ERROR]' if is_error else '[INFO]'} {message}\n")
        except Exception as e:
            pass

    def _process_incoming_logs(self):
        try:
            processed_count = 0
            self.terminal_text_area.config(state="normal")
            while processed_count < 50:
                try:
                    message, is_error, internal = self.system_log_queue.get_nowait()
                except queue.Empty:
                    break

                timestamp_string = time.strftime('%H:%M:%S')
                self.terminal_text_area.insert(tk.END, f"[{timestamp_string}] {message}\n")
                if not internal:
                    self.status_display_label_var.set(message)
                    self.status_display_label.config(
                        foreground=self.theme_colors["button_danger"] if is_error else self.theme_colors[
                            "primary_text"])
                processed_count += 1

            if processed_count > 0: self.terminal_text_area.see(tk.END)
            self.terminal_text_area.config(state="disabled")
        finally:
            self.root_window.after(50, self._process_incoming_logs)

    def _event_browse_files(self):
        selected_file_paths = filedialog.askopenfilenames(
            title="Select Target Applications",
            filetypes=[("Android Packages", "*.apk *.xapk *.apkm"), ("All Files", "*.*")]
        )
        if selected_file_paths:
            self.selected_target_files = [Path(f) for f in selected_file_paths]
            self.selected_files_display_entry.config(state="normal")
            self.selected_files_display_entry.delete(0, tk.END)
            self.selected_files_display_entry.insert(0, f"{len(self.selected_target_files)} file(s) selected.")
            self.selected_files_display_entry.config(state="readonly")

            self.start_analysis_button.config(state="normal")
            self.status_display_label_var.set(f"Ready to process {len(self.selected_target_files)} file(s).")
            self.status_display_label.config(foreground=self.theme_colors["button_primary"])

            self.terminal_text_area.config(state="normal")
            self.terminal_text_area.delete('1.0', tk.END)
            self.terminal_text_area.config(state="disabled")

            self._run_initial_system_diagnostics()

    def _event_start_analysis(self):
        if self.enable_auto_ghidra_option.get():
            ghidra_path = self._get_or_prompt_ghidra_path()
            if not ghidra_path:
                self._write_system_log("Ghidra yolu belirtilmediği için analiz başlatılamadı.", is_error=True)
                return
            self.system_dependencies['ghidra_headless'] = ghidra_path

        self.start_analysis_button.config(state="disabled", text="PROCESSING...")
        self.cancel_analysis_button.config(state="normal")
        self.browse_files_button.config(state="disabled")
        self.open_in_intellij_button.config(state="disabled")
        self.open_output_folder_button.config(state="disabled")
        self.status_display_label.config(foreground=self.theme_colors["button_primary"])

        self.current_run_configuration = {
            'enable_backup': self.enable_backup_option.get(),
            'enable_decompilation': self.enable_decompilation_option.get(),
            'enable_vulnerability_scan': self.enable_vulnerability_scan_option.get(),
            'enable_auto_ghidra': self.enable_auto_ghidra_option.get()
        }

        self.activity_progress_bar.start(10)
        self.execution_stop_event.clear()
        self.total_applications_processed = 0
        self.completed_project_directories.clear()

        self._write_system_log("Engine initialized. Starting analysis threads...", internal=False)
        threading.Thread(target=self._run_analysis_threads, daemon=True).start()

    def _event_cancel_analysis(self):
        self._write_system_log("Cancellation requested. Sending halt signal to background workers...", is_error=True)
        self.execution_stop_event.set()
        self.cancel_analysis_button.config(state="disabled")

    def _run_analysis_threads(self):
        processing_start_time = time.time()
        try:
            analyzer_engine = AnalysisEngine(self.system_log_queue, self.execution_stop_event, self.system_dependencies)

            with concurrent.futures.ThreadPoolExecutor(max_workers=3) as thread_executor:
                file_futures = {
                    thread_executor.submit(analyzer_engine.process_application, file_path,
                                           self.current_run_configuration): file_path
                    for file_path in self.selected_target_files
                }

                for future_result in concurrent.futures.as_completed(file_futures):
                    result_directory = future_result.result()
                    if result_directory:
                        with self.statistics_lock:
                            self.completed_project_directories.append(result_directory)
                            self.total_applications_processed += 1

            total_execution_duration = time.time() - processing_start_time

            if self.execution_stop_event.is_set():
                message = "Process aborted by user."
                self._write_system_log(message, is_error=True)
                self.root_window.after(0, self._show_completion_message, message, True)
            else:
                self._handle_post_analysis_ghidra()

                message = f"Analysis completed successfully! Processed {self.total_applications_processed} file(s) in {total_execution_duration:.2f}s."
                self._write_system_log(message)
                self.root_window.after(0, self._show_completion_message, message, False)

        except Exception as critical_error:
            self._write_system_log(f"Critical System Error: {critical_error}", is_error=True)
            self.root_window.after(0, self._restore_user_interface_state)

    def _handle_post_analysis_ghidra(self):
        """Analiz bittikten sonra Flutter tespit edilirse Ghidra'yı otomatik çalıştırır."""
        if not self.current_run_configuration.get('enable_auto_ghidra'):
            return
        if not self.completed_project_directories:
            return

        target_project_directory = self.completed_project_directories[0].parent
        app_name = target_project_directory.name
        ghidra_workspace_dir = target_project_directory / "Ghidra_Workspace"

        if ghidra_workspace_dir.exists() and (ghidra_workspace_dir / "patched_libflutter.so").exists():
            self._write_system_log("Flutter projesi tespit edildi! Ghidra arka plan analizi başlatılıyor...",
                                   internal=False)

            engine = AnalysisEngine(self.system_log_queue, self.execution_stop_event, self.system_dependencies)
            success = engine.run_ghidra_analysis(ghidra_workspace_dir, app_name)

            if success:
                self.root_window.after(0, self._launch_ghidra_gui_automatically, ghidra_workspace_dir, app_name)
            else:
                self._write_system_log("Otomatik Ghidra analizi başarısız oldu.", is_error=True)
        else:
            self._write_system_log("Flutter altyapısı bulunamadığı için Ghidra otomasyonu atlandı.", internal=True)

    def _launch_ghidra_gui_automatically(self, workspace_dir: Path, app_name: str):
        """Ghidra arayüzünü (GUI) soru sormadan otomatik olarak başlatır."""
        headless_path_str = self.system_dependencies.get('ghidra_headless', '')
        if not headless_path_str:
            return

        headless_path = Path(headless_path_str)
        exe_name = "ghidraRun.bat" if os.name == 'nt' else "ghidraRun"
        ghidra_run_path = headless_path.parent.parent / exe_name

        if ghidra_run_path.exists():
            self._write_system_log("[Ghidra] Analiz tamamlandı. Ghidra arayüzü (GUI) otomatik olarak başlatılıyor...",
                                   internal=False)
            try:
                subprocess.Popen([str(ghidra_run_path)], cwd=str(ghidra_run_path.parent))

                self.root_window.attributes('-topmost', True)
                messagebox.showinfo(
                    "Ghidra Başlatılıyor",
                    f"Ghidra analizi tamamlandı ve arayüz başlatılıyor!\n\nProgram açıldığında 'File -> Open Project' menüsünden şu dizini seçin:\n\n{workspace_dir}"
                )
                self.root_window.attributes('-topmost', False)

            except Exception as e:
                self._write_system_log(f"Ghidra arayüzü başlatılırken hata oluştu: {e}", is_error=True)
        else:
            self.root_window.attributes('-topmost', True)
            messagebox.showwarning(
                "Dosya Bulunamadı",
                f"Arayüz başlatıcı bulunamadı:\n{ghidra_run_path}\n\nLütfen Ghidra'yı manuel olarak açın."
            )
            self.root_window.attributes('-topmost', False)

    def _show_completion_message(self, message: str, is_aborted: bool = False):
        self._restore_user_interface_state()
        if is_aborted:
            messagebox.showwarning("Aborted", message)
        else:
            messagebox.showinfo("Success", f"{message}\n\nYou can now inspect the results.")

    def _restore_user_interface_state(self):
        self.activity_progress_bar.stop()
        self.selected_target_files = []
        self.selected_files_display_entry.config(state="normal")
        self.selected_files_display_entry.delete(0, tk.END)
        self.selected_files_display_entry.config(state="readonly")

        self.start_analysis_button.config(state="disabled", text="▶ START ANALYSIS")
        self.cancel_analysis_button.config(state="disabled")
        self.browse_files_button.config(state="normal")

        if self.completed_project_directories:
            self.open_output_folder_button.config(state="normal")
            self.open_in_intellij_button.config(state="normal")

        self.status_display_label.config(foreground=self.theme_colors["primary_text"])
        self.status_display_label_var.set("Awaiting new file selection...")

    def _event_open_output_folder(self):
        if not self.completed_project_directories: return
        target_directory_to_open = self.completed_project_directories[0].parent

        try:
            if os.name == 'nt':
                os.startfile(target_directory_to_open)
            elif os.name == 'posix':
                subprocess.call(['open', target_directory_to_open])
            else:
                subprocess.call(['xdg-open', target_directory_to_open])
            self._write_system_log(f"Opened outputs directory: {target_directory_to_open}")
        except Exception as error:
            self._write_system_log(f"Could not open directory: {error}", is_error=True)
            messagebox.showerror("System Error", f"Failed to open folder:\n{error}")

    def _event_open_intellij(self):
        if not self.completed_project_directories: return

        target_project_directory = str(self.completed_project_directories[0])
        intellij_executable_path = None

        if self.system_configuration_path.exists():
            try:
                with open(self.system_configuration_path, 'r', encoding='utf-8') as config_file:
                    intellij_executable_path = json.load(config_file).get('ij_path')
            except Exception:
                pass

        if not intellij_executable_path or not Path(intellij_executable_path).exists():
            if os.name == 'nt':
                messagebox.showinfo(
                    "IntelliJ Configuration Required",
                    "The system cannot locate your IntelliJ IDEA installation.\n\n"
                    "Please select your 'idea64.exe' file in the next window.\n"
                    "(Usually located in C:\\Program Files\\JetBrains\\...)\n"
                    "This is a one-time setup."
                )

                intellij_executable_path = filedialog.askopenfilename(
                    title="Locate idea64.exe",
                    filetypes=[("Executable Files", "*.exe")]
                )

                if intellij_executable_path:
                    self._update_config_file('ij_path', intellij_executable_path)
                else:
                    self._write_system_log("IntelliJ path configuration was cancelled.", is_error=True)
                    return
            else:
                intellij_executable_path = "idea"

        try:
            self._write_system_log(f"[IntelliJ] Launching IDE for: {Path(target_project_directory).name}...",
                                   internal=True)
            subprocess.Popen([intellij_executable_path, target_project_directory])
        except Exception as error:
            self._write_system_log(f"Failed to launch IntelliJ: {error}", is_error=True)
            messagebox.showerror("Execution Error",
                                 f"Failed to launch IntelliJ. Did you select the correct executable?\n\nDetails: {error}")


if __name__ == "__main__":
    main_app_window = tk.Tk()
    application_gui = VulnerabilityScannerUI(main_app_window)
    main_app_window.mainloop()