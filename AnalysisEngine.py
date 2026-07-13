import os
import shutil
import zipfile
import subprocess
import json
import re
import sys
import time
import queue
import threading
import functools
from pathlib import Path
from typing import Optional

from rules import VULNERABILITY_RULES
from md_creator import MarkdownReportGenerator
from vscode_settings_helper import create_vscode_settings


class AnalysisEngine:
    def __init__(self, log_queue, stop_event, dependencies):
        self.log_queue = log_queue
        self.stop_event = stop_event
        self.dependencies = dependencies
        self.vulnerability_rules = VULNERABILITY_RULES

        self.base_dir = Path(__file__).resolve().parent

        self.ignored_files_path = self.base_dir / "ignored_files.txt"
        self.ignored_strings_path = self.base_dir / "ignored_strings.txt"

        self.ignored_files = self._load_filter_list(
            self.ignored_files_path,
            ['public-suffix-list.txt', 'license', 'license.txt', 'notice', 'notice.txt',
             'readme.md', 'readme.txt', 'changelog.md', 'changelog', 'robots.txt'],
            as_set=True
        )

        self.ignored_strings = self._load_filter_list(
            self.ignored_strings_path,
            ['apache.org/licenses', 'w3.org', 'schemas.android.com', 'ns.adobe.com',
             'play.google.com', 'apple.com', 'github.com', 'example.com', 'xmlns.jcp.org']
        )

    def _load_filter_list(self, file_path: Path, default_items: list, as_set: bool = False):
        if file_path.exists():
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    lines = [line.strip().lower() for line in f.readlines() if
                             line.strip() and not line.startswith('#')]
                return set(lines) if as_set else lines
            except Exception as e:
                self._send_log(f"[Sistem] {file_path.name} okunamadı: {e}", is_error=True, internal=True)
                return set(default_items) if as_set else default_items
        else:
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write("# Yoksayılacak öğeleri ekleyin (her satıra bir tane). # ile başlayan satırlar yorumdur.\n")
                    for item in default_items:
                        f.write(f"{item}\n")
            except Exception as e:
                self._send_log(f"[Sistem] Varsayılan {file_path.name} oluşturulamadı: {e}", is_error=True,
                               internal=True)
            return set(default_items) if as_set else default_items

    def _send_log(self, message: str, is_error: bool = False, internal: bool = False):
        self.log_queue.put((message, is_error, internal))

    @staticmethod
    def setup_project_directories(base_directory: Path, application_name: str) -> dict:
        app_base_directory = base_directory / application_name

        directories = {
            "app_base": app_base_directory,
            "extracted_files": app_base_directory / "Extracted_Files",
            "original_backups": app_base_directory / "Original_Backups",
            "analysis_reports": app_base_directory / "Analysis_Reports",
            "decompiled_jars": app_base_directory / "Decompiled_JARs",
            "intellij_project": app_base_directory / "IntelliJ_Project",
            "flutter_files": app_base_directory / "Flutter_Files",
            "native_libraries": app_base_directory / "Native_Libraries",
            "js_framework_files": app_base_directory / "JS_Framework_Files",
            "ghidra_workspace": app_base_directory / "Ghidra_Workspace",
            "blutter_output": app_base_directory / "Blutter_Output"
        }

        for key, directory_path in directories.items():
            if key != "app_base":
                directory_path.mkdir(parents=True, exist_ok=True)

        return directories

    @functools.lru_cache(maxsize=1)
    def _get_vsdev_env(self) -> dict:

        if os.name != 'nt':
            return dict(os.environ)

        vcvarsall_candidates = [
            r"C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat",
            r"C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvarsall.bat",
            r"C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvarsall.bat",
            r"C:\Program Files\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvarsall.bat",
            r"C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvarsall.bat",
            r"C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\VC\Auxiliary\Build\vcvarsall.bat",
        ]

        custom_vcvarsall = self.dependencies.get('vcvarsall_path')
        if custom_vcvarsall:
            vcvarsall_candidates.insert(0, custom_vcvarsall)

        vcvarsall = next((p for p in vcvarsall_candidates if Path(p).exists()), None)

        if not vcvarsall:
            self._send_log(
                "[Blutter] vcvarsall.bat bulunamadı, mevcut process ortamıyla devam ediliyor "
                "(ilk derleme cmake/link hatası verirse bu muhtemel sebep).",
                internal=True)
            return dict(os.environ)

        try:
            command = f'"{vcvarsall}" x64 && set'
            result = subprocess.run(
                command, shell=True, capture_output=True, text=True,
                encoding='utf-8', errors='replace', timeout=60
            )
            env = dict(os.environ)
            for line in result.stdout.splitlines():
                if '=' in line:
                    key, _, value = line.partition('=')
                    if key:
                        env[key] = value
            self._send_log(f"[Blutter] VS derleyici ortamı yüklendi ({Path(vcvarsall).parent.parent.parent.name}).",
                           internal=True)
            return env
        except Exception as e:
            self._send_log(f"[Blutter] vcvarsall.bat çalıştırılamadı: {e}. Mevcut ortamla devam ediliyor.",
                           internal=True)
            return dict(os.environ)

    def _execute_terminal_command(self, command_arguments: list, log_prefix: str = "",
                                  timeout_seconds: int = 300, custom_cwd: Optional[Path] = None,
                                  input_data: Optional[str] = None, env: Optional[dict] = None) -> tuple:

        process = None
        try:
            creation_flags = subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0

            tool_path = Path(command_arguments[0])
            working_directory = custom_cwd if custom_cwd else (
                tool_path.parent if tool_path.resolve().exists() else None)

            process = subprocess.Popen(
                args=command_arguments, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                creationflags=creation_flags, cwd=working_directory, text=True, encoding='utf-8', errors='replace',
                bufsize=1, env=env
            )

            if input_data:
                try:
                    process.stdin.write(input_data + "\n")
                    process.stdin.flush()
                except Exception as e:
                    self._send_log(f"{log_prefix} Input yazma hatası: {e}", internal=True)

            if process.stdin:
                process.stdin.close()

            line_queue: "queue.Queue" = queue.Queue()

            def _reader():
                try:
                    for raw_line in iter(process.stdout.readline, ''):
                        line_queue.put(raw_line)
                except Exception:
                    pass
                finally:
                    line_queue.put(None)

            reader_thread = threading.Thread(target=_reader, daemon=True)
            reader_thread.start()

            deadline = time.monotonic() + timeout_seconds
            last_error_message = ""
            fallback_last_line = ""

            while True:
                if self.stop_event.is_set():
                    process.terminate()
                    return False, "Süreç kullanıcı tarafından iptal edildi."

                if time.monotonic() > deadline:
                    process.kill()
                    return False, f"Süreç {timeout_seconds} saniye içinde tamamlanamadı (zaman aşımı / hang)."

                try:
                    line = line_queue.get(timeout=1)
                except queue.Empty:
                    continue

                if line is None:
                    break

                line = line.strip()
                if not line:
                    continue

                if "ignored invalid inner class name" in line.lower():
                    continue

                fallback_last_line = line
                lowered = line.lower()
                if any(keyword in lowered for keyword in ("error", "failed", "fatal", "exception")):
                    last_error_message = line

                display_message = line
                if "I: " in line:
                    display_message = line.split("I: ")[-1]
                elif "INFO " in line:
                    display_message = line.split("INFO ")[-1].strip('- ')
                elif "W: " in line:
                    display_message = "WARNING: " + line.split("W: ")[-1]
                elif "WARN: " in line:
                    display_message = "WARNING: " + line.split("WARN: ")[-1]

                if len(display_message) > 100:
                    display_message = display_message[:97] + "..."

                if log_prefix:
                    self._send_log(f"{log_prefix} {display_message}", internal=False)
                else:
                    self._send_log(display_message, internal=True)

            reader_thread.join(timeout=5)

            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                return False, "Süreç kapanmadı, zorla sonlandırıldı."

            if process.returncode == 0:
                return True, ""

            return False, last_error_message or fallback_last_line or "Bilinmeyen hata (çıkış kodu != 0)."

        except Exception as error:
            return False, str(error)

    def _unpack_archive_securely(self, archive_path: Path, destination_directory: Path) -> bool:
        self._send_log(f"[Extractor] Güvenli çıkarma başlatıldı -> {archive_path.name}")
        try:
            with zipfile.ZipFile(archive_path, 'r') as zip_reference:
                for member in zip_reference.infolist():
                    if self.stop_event.is_set(): return False
                    if member.filename.startswith('/') or '..' in member.filename: continue

                    safe_filename = member.filename
                    if os.name == 'nt':
                        safe_parts = [re.sub(r'[<>:"|?*]', '_', p) for p in safe_filename.split('/')]
                        safe_filename = '/'.join(safe_parts)

                    target_path = destination_directory / safe_filename
                    target_path_resolved = target_path.resolve()

                    if not target_path_resolved.is_relative_to(destination_directory.resolve()):
                        self._send_log(f"[Security] Kötü niyetli dosya yolu (Zip Slip) engellendi: {safe_filename}",
                                       is_error=True)
                        continue

                    target_path_string = str(target_path_resolved)

                    if os.name == 'nt' and len(target_path_string) > 250 and not target_path_string.startswith(
                            '\\\\?\\'):
                        target_path_string = '\\\\?\\' + target_path_string
                        target_path_resolved = Path(target_path_string)

                    if member.is_dir():
                        target_path_resolved.mkdir(parents=True, exist_ok=True)
                    else:
                        target_path_resolved.parent.mkdir(parents=True, exist_ok=True)
                        try:
                            with zip_reference.open(member) as source_file, open(target_path_string,
                                                                                 "wb") as target_file:
                                shutil.copyfileobj(source_file, target_file)
                        except Exception as e:
                            self._send_log(f"[Extractor] {safe_filename} yazılamadı: {e}", internal=True)
            return True
        except zipfile.BadZipFile:
            self._send_log(f"[Error] Bozuk arşiv formatı {archive_path.name}", is_error=True)
            return False
        except Exception as error:
            self._send_log(f"[Error] Arşiv çıkarma hatası {archive_path.name}: {error}", is_error=True)
            return False

    def _extract_readable_strings_from_binary(self, binary_file_path: Path, output_text_path: Path):
        try:
            with open(binary_file_path, 'rb') as binary_file:
                binary_content = binary_file.read()

            string_pattern = re.compile(b'[ -~]{4,}')

            matches_found = False
            with open(output_text_path, 'w', encoding='utf-8') as output_file:
                for match in string_pattern.finditer(binary_content):
                    output_file.write(match.group().decode('ascii') + '\n')
                    matches_found = True

            if not matches_found and output_text_path.exists():
                output_text_path.unlink()

        except MemoryError:
            self._send_log(f"[Bellek Hatası] {binary_file_path.name} belleğe sığmayacak kadar büyük.", is_error=True)
        except Exception as e:
            self._send_log(f"[Binary Analiz Hatası] {binary_file_path.name} analiz edilemedi: {e}", internal=True)

    def _isolate_and_analyze_flutter_engine(self, extracted_directory: Path, flutter_target_directory: Path) -> bool:
        is_flutter_detected = False

        for root, dirs, _ in os.walk(extracted_directory):
            if "flutter_assets" in dirs:
                is_flutter_detected = True
                flutter_assets_source = Path(root) / "flutter_assets"
                destination = flutter_target_directory / "flutter_assets"
                if not destination.exists():
                    shutil.copytree(str(flutter_assets_source), str(destination))
                break

        for root, _, files in os.walk(extracted_directory):
            for file_name in files:
                if file_name in ["libapp.so", "libflutter.so"]:
                    is_flutter_detected = True
                    source_file_path = Path(root) / file_name
                    architecture_name = source_file_path.parent.name

                    destination_folder = flutter_target_directory / "lib" / architecture_name
                    destination_folder.mkdir(parents=True, exist_ok=True)

                    target_shared_object = destination_folder / file_name
                    shutil.copy2(str(source_file_path), str(target_shared_object))

                    target_strings_file = destination_folder / f"{file_name}_strings.txt"
                    self._extract_readable_strings_from_binary(target_shared_object, target_strings_file)

        return is_flutter_detected

    def _apply_reflutter(self, target_apk_path: Path, flutter_target_directory: Path) -> Optional[Path]:
        self._send_log(f"[Reflutter] Otomasyon başlatılıyor -> {target_apk_path.name}")

        working_dir = target_apk_path.parent
        reflutter_cmd = self.dependencies.get('reflutter', 'reflutter')
        command_arguments = [str(reflutter_cmd), target_apk_path.name]

        target_ip = "127.0.0.1"

        is_success, error_message = self._execute_terminal_command(
            command_arguments,
            log_prefix="[Reflutter]",
            timeout_seconds=600,
            custom_cwd=working_dir,
            input_data=target_ip
        )

        expected_output_path = working_dir / "release.RE.zip"

        if expected_output_path.exists():
            reflutter_dest_dir = flutter_target_directory / "Refluttered_APK"
            reflutter_dest_dir.mkdir(parents=True, exist_ok=True)

            final_dest = reflutter_dest_dir / f"{target_apk_path.stem}_refluttered.apk"
            shutil.move(str(expected_output_path), str(final_dest))

            self._send_log(f"[Reflutter] Başarılı! Dosya hazır: {final_dest.name}", internal=False)
            return final_dest
        else:
            self._send_log(
                f"[Reflutter Hata] İşlem başarısız oldu veya 'release.RE.zip' bulunamadı. Detay: {error_message}",
                is_error=True)
            return None

    def _isolate_and_analyze_js_frameworks(self, extracted_directory: Path, js_target_directory: Path) -> str:
        framework_detected = ""

        for root, dirs, files in os.walk(extracted_directory):
            if "index.android.bundle" in files:
                framework_detected = "React Native"
                source_bundle = Path(root) / "index.android.bundle"
                destination = js_target_directory / "React_Native_Bundle"
                destination.mkdir(parents=True, exist_ok=True)
                try:
                    shutil.copy2(str(source_bundle), str(destination / "index.android.bundle"))
                except Exception as e:
                    self._send_log(f"[JS Analiz] {source_bundle.name} kopyalanamadı: {e}", internal=True)
                break

        if not framework_detected:
            for root, dirs, _ in os.walk(extracted_directory):
                if "www" in dirs:
                    www_path = Path(root) / "www"
                    index_file = www_path / "index.html"
                    if index_file.exists():
                        framework_detected = "Cordova / Ionic"
                        destination = js_target_directory / "Web_Assets"
                        try:
                            shutil.copytree(str(www_path), str(destination), dirs_exist_ok=True)
                        except Exception as e:
                            self._send_log(f"[JS Analiz] Web klasörü kopyalanamadı: {e}", internal=True)
                        break

        return framework_detected

    def _isolate_and_analyze_native_libraries(self, extracted_directory: Path, native_target_directory: Path) -> int:
        libraries_processed_count = 0

        for root, _, files in os.walk(extracted_directory):
            for file_name in files:
                if file_name.endswith(".so") and file_name not in ["libapp.so", "libflutter.so"]:
                    source_file_path = Path(root) / file_name
                    architecture_name = source_file_path.parent.name

                    destination_folder = native_target_directory / architecture_name
                    destination_folder.mkdir(parents=True, exist_ok=True)

                    target_shared_object = destination_folder / file_name
                    shutil.copy2(str(source_file_path), str(target_shared_object))

                    target_strings_file = destination_folder / f"{file_name}_strings.txt"
                    self._extract_readable_strings_from_binary(target_shared_object, target_strings_file)
                    libraries_processed_count += 1

        return libraries_processed_count

    @staticmethod
    def _generate_intellij_project_structure(project_directory: Path, project_name: str):
        idea_settings_directory = project_directory / '.idea'
        idea_settings_directory.mkdir(exist_ok=True)

        iml_file_content = f"""<?xml version="1.0" encoding="UTF-8"?>
<module type="JAVA_MODULE" version="4">
  <component name="NewModuleRootManager" inherit-compiler-output="true">
    <exclude-output />
    <content url="file://$MODULE_DIR$">
      <sourceFolder url="file://$MODULE_DIR$" isTestSource="false" />
    </content>
    <orderEntry type="inheritedJdk" />
    <orderEntry type="sourceFolder" forTests="false" />
  </component>
</module>"""

        modules_xml_content = f"""<?xml version="1.0" encoding="UTF-8"?>
<project version="4">
  <component name="ProjectModuleManager">
    <modules>
      <module fileurl="file://$PROJECT_DIR$/{project_name}.iml" filepath="$PROJECT_DIR$/{project_name}.iml" />
    </modules>
  </component>
</project>"""

        with open(project_directory / f"{project_name}.iml", 'w', encoding='utf-8') as iml_file:
            iml_file.write(iml_file_content)
        with open(idea_settings_directory / "modules.xml", 'w', encoding='utf-8') as modules_file:
            modules_file.write(modules_xml_content)

    def _scan_and_decompile_dex(self, extracted_directory: Path, jar_output_directory: Path,
                                intellij_project_directory: Path, application_name: str):
        class_to_dex_mapping = {}
        mapping_json_file = intellij_project_directory / "class_mapping.json"

        self._generate_intellij_project_structure(intellij_project_directory, application_name)

        for root_path, _, files in os.walk(extracted_directory):
            if self.stop_event.is_set(): break
            for file_name in files:
                if self.stop_event.is_set(): break
                if file_name.lower().endswith('.dex'):
                    dex_file_path = Path(root_path) / file_name

                    try:
                        relative_path = dex_file_path.relative_to(extracted_directory)
                    except ValueError:
                        relative_path = Path(dex_file_path.name)

                    target_jar_folder = jar_output_directory / relative_path.parent
                    target_jar_folder.mkdir(parents=True, exist_ok=True)
                    jar_file_path = target_jar_folder / f"{dex_file_path.stem}.jar"

                    self._send_log(f"[Converter] İşleniyor -> {dex_file_path.name}")
                    command_arguments = [str(self.dependencies['dex2jar']), str(dex_file_path), "-o",
                                         str(jar_file_path), "--force"]
                    is_success, error_message = self._execute_terminal_command(command_arguments,
                                                                               log_prefix="[Dex2Jar]")

                    if not is_success:
                        self._send_log(f"[Decompilation Hatası] {error_message}", is_error=True)
                    else:
                        self._send_log(f"[IntelliJ] JAR sınıfları çıkarılıyor: {dex_file_path.name}...", internal=True)
                        try:
                            with zipfile.ZipFile(jar_file_path, 'r') as jar_archive:
                                for member in jar_archive.namelist():
                                    if member.endswith('.class'):
                                        class_to_dex_mapping[member] = {
                                            "source_dex": str(relative_path),
                                            "source_jar": str(jar_file_path.name)
                                        }
                                jar_archive.extractall(intellij_project_directory)
                        except zipfile.BadZipFile:
                            self._send_log(f"[IntelliJ Hatası] {jar_file_path.name} bozuk bir zip arşivi.",
                                           is_error=True)
                        except Exception as extraction_error:
                            self._send_log(f"[IntelliJ Hatası] {jar_file_path.name} açılamadı: {extraction_error}",
                                           is_error=True)

        if class_to_dex_mapping:
            try:
                with open(mapping_json_file, 'w', encoding='utf-8') as mapping_file:
                    json.dump(class_to_dex_mapping, mapping_file, indent=4)
            except Exception as e:
                self._send_log(f"[Mapping Hatası] class_mapping.json oluşturulamadı: {e}", internal=True)

    def _scan_for_vulnerabilities_and_secrets(self, directories_to_scan: list, report_output_directory: Path,
                                              application_name: str) -> tuple:
        master_report_path = report_output_directory / f"{application_name}_Master_Report.json"
        categorized_base_dir = report_output_directory / "Categorized_Findings"

        scan_results = {category: [] for category in self.vulnerability_rules.keys()}
        already_seen_items = set()

        for source_directory in directories_to_scan:
            if not source_directory.exists(): continue
            for root_path, _, files in os.walk(source_directory):
                if self.stop_event.is_set(): break
                for file_name in files:
                    if self.stop_event.is_set(): break

                    safe_file_name_lower = file_name.lower()
                    safe_file_name_casefold = file_name.casefold()

                    is_blacklisted = False
                    for ignored_file in self.ignored_files:
                        if ignored_file in safe_file_name_lower or ignored_file in safe_file_name_casefold or file_name.upper() == ignored_file.upper():
                            is_blacklisted = True
                            break

                    if is_blacklisted:
                        continue

                    allowed_extensions = ('.xml', '.java', '.smali', '.json', '.txt', '.html', '.js', '.class',
                                          '.bundle', '.properties', '.yaml', '.yml', '.env', '.ini')

                    if safe_file_name_casefold.endswith(allowed_extensions) or safe_file_name_lower.endswith(
                            allowed_extensions):
                        file_path = Path(root_path) / file_name
                        try:
                            file_size_bytes = file_path.stat().st_size
                            is_high_value_dart_dump = file_name.lower() in ("pp.txt", "objs.txt")
                            size_limit_bytes = (60 if is_high_value_dart_dump else 15) * 1024 * 1024

                            if file_size_bytes > size_limit_bytes: continue

                            with open(file_path, 'r', encoding='utf-8', errors='ignore') as current_file:
                                file_content = current_file.read()

                                for category_name, rule in self.vulnerability_rules.items():
                                    patterns_to_check = rule if isinstance(rule, list) else [rule]

                                    for pattern in patterns_to_check:
                                        matches = pattern.findall(file_content)
                                        for match in matches:
                                            extracted_value = match if isinstance(match, str) else match[0]

                                            if "Network" in category_name:
                                                is_noise = False
                                                for noise in self.ignored_strings:
                                                    if noise in extracted_value.lower() or noise in extracted_value.casefold():
                                                        is_noise = True
                                                        break
                                                if is_noise:
                                                    continue

                                            unique_identifier = f"{category_name}_{extracted_value}_{file_path}"

                                            if unique_identifier not in already_seen_items:
                                                already_seen_items.add(unique_identifier)
                                                try:
                                                    relative_file_path = str(
                                                        file_path.relative_to(source_directory.parent))
                                                except ValueError:
                                                    relative_file_path = str(file_path)

                                                scan_results[category_name].append({
                                                    "found_value": extracted_value,
                                                    "file_location": relative_file_path
                                                })
                        except Exception as read_error:
                            self._send_log(f"[Tarama Hatası] {file_name} okunamadı: {read_error}", internal=True)

        cleaned_results = {key: value for key, value in scan_results.items() if value}

        if cleaned_results:
            try:
                with open(master_report_path, 'w', encoding='utf-8') as final_report:
                    json.dump(cleaned_results, final_report, indent=4)
            except Exception as e:
                self._send_log(f"[Rapor Hatası] Ana rapor kaydedilemedi: {e}", is_error=True)

            folder_mapping = {
                "Cloud": "Cloud_Services",
                "AI": "AI_Providers",
                "Payment": "Payment_Systems",
                "Database": "Databases",
                "Comm": "Communications",
                "DevOps": "DevOps_Tools",
                "Auth": "Security_and_Auth",
                "Crypto": "Security_and_Auth",
                "Generic": "Security_and_Auth",
                "Network": "Network_Endpoints",
                "Business": "Business_Logic",
                "Hardcoded": "Hardcoded_Vulnerabilities"
            }

            for category, items in cleaned_results.items():
                folder_prefix = category.split('_')[0] if '_' in category else "Other"
                folder_name = folder_mapping.get(folder_prefix, "Misc_Findings")

                specific_folder = categorized_base_dir / folder_name
                specific_folder.mkdir(parents=True, exist_ok=True)

                category_file_path = specific_folder / f"{category}.json"
                try:
                    with open(category_file_path, 'w', encoding='utf-8') as cat_file:
                        json.dump({
                            "category": category,
                            "total_found": len(items),
                            "findings": items
                        }, cat_file, indent=4)
                except Exception as e:
                    self._send_log(f"[Rapor Hatası] Kategori raporu oluşturulamadı ({category}): {e}", internal=True)

            return True, master_report_path.name

        return False, ""

    def _detect_available_architecture(self, dirs: dict) -> Optional[str]:
        architecture_priority = ["arm64-v8a", "armeabi-v7a", "x86_64", "x86"]
        flutter_lib_dir = dirs["flutter_files"] / "lib"

        for arch in architecture_priority:
            if (flutter_lib_dir / arch / "libapp.so").exists():
                return arch

        if flutter_lib_dir.exists():
            for arch_dir in flutter_lib_dir.iterdir():
                if arch_dir.is_dir() and (arch_dir / "libapp.so").exists():
                    return arch_dir.name

        return None

    def _prepare_ghidra_workspace(self, dirs: dict, target_arch: Optional[str]):
        self._send_log("[Ghidra] Tüm kütüphaneler (.so) çalışma alanına toplanıyor...", internal=True)
        ghidra_dir = dirs["ghidra_workspace"]

        if target_arch is None:
            self._send_log(
                "[Ghidra Uyarı] Desteklenen bir mimari (.so) bulunamadığından hazırlık atlandı.",
                is_error=True)
            return

        flutter_lib_dir = dirs["flutter_files"] / "lib"
        reflutter_libs_dir = dirs["flutter_files"] / "Refluttered_Libs" / "lib"

        original_libapp = flutter_lib_dir / target_arch / "libapp.so"
        patched_libflutter = reflutter_libs_dir / target_arch / "libflutter.so"

        if original_libapp.exists():
            shutil.copy2(str(original_libapp), str(ghidra_dir / "libapp.so"))
        else:
            self._send_log(f"[Ghidra Uyarı] {target_arch} için orijinal libapp.so bulunamadı.", is_error=True)

        if patched_libflutter.exists():
            shutil.copy2(str(patched_libflutter), str(ghidra_dir / "patched_libflutter.so"))
        else:
            self._send_log(
                "[Ghidra] Patch'lenmiş libflutter.so bulunamadı, sadece libapp.so ile devam ediliyor.",
                internal=True)

        native_arch_dir = dirs["native_libraries"] / target_arch
        if native_arch_dir.exists():
            for so_file in native_arch_dir.glob("*.so"):
                shutil.copy2(str(so_file), str(ghidra_dir / so_file.name))

        toplam_kutuphane = len(list(ghidra_dir.glob('*.so')))
        self._send_log(
            f"[Ghidra] Hazır! Toplam {toplam_kutuphane} adet kütüphane Ghidra Workspace'e kopyalandı (mimari: {target_arch}).",
            internal=False)


    def _resolve_blutter_python(self, blutter_script: Path) -> str:

        custom_python = self.dependencies.get('blutter_python')
        if custom_python and Path(custom_python).exists():
            return custom_python

        exe_name = "python.exe" if os.name == 'nt' else "python3"
        bin_dir = "Scripts" if os.name == 'nt' else "bin"

        venv_candidates = [
            blutter_script.parent / "venv" / bin_dir / exe_name,
            blutter_script.parent / ".venv" / bin_dir / exe_name,
        ]
        for candidate in venv_candidates:
            if candidate.exists():
                return str(candidate)

        return sys.executable

    def _ensure_blutter_python_dependencies(self, python_executable: str, blutter_script: Path) -> bool:

        try:
            check_result = subprocess.run(
                [python_executable, "-c", "import requests"],
                capture_output=True, text=True, timeout=30
            )
            if check_result.returncode == 0:
                return True
        except Exception as e:
            self._send_log(f"[Blutter] Python bağımlılık kontrolü yapılamadı: {e}", internal=True)

        self._send_log(
            f"[Blutter] '{Path(python_executable).name}' içinde 'requests' modülü bulunamadı, "
            "otomatik kurulum deneniyor...", internal=False)

        requirements_file = blutter_script.parent / "requirements.txt"
        if requirements_file.exists():
            install_command = [python_executable, "-m", "pip", "install", "-r", str(requirements_file)]
        else:
            install_command = [python_executable, "-m", "pip", "install", "requests"]

        is_success, error_message = self._execute_terminal_command(
            install_command,
            log_prefix="[Blutter Pip]",
            timeout_seconds=180,
            custom_cwd=blutter_script.parent
        )

        if not is_success:
            self._send_log(f"[Blutter] Gerekli paketler kurulamadı: {error_message}", is_error=True)
            return False

        self._send_log("[Blutter] Gerekli Python paketleri kuruldu.", internal=False)
        return True

    def _resolve_blutter_fix_script(self, blutter_script: Path) -> Optional[Path]:

        custom_path = self.dependencies.get('blutter_fix_script')
        if custom_path and Path(custom_path).exists():
            return Path(custom_path)

        default_path = blutter_script.parent / "fix_blutter_windows.ps1"
        if default_path.exists():
            return default_path

        return None

    def _run_blutter_fix_script(self, blutter_script: Path) -> bool:

        if os.name != 'nt':
            return False

        fix_script = self._resolve_blutter_fix_script(blutter_script)
        if not fix_script:
            self._send_log(
                "[Blutter Onarım] fix_blutter_windows.ps1 bulunamadı, otomatik onarım atlandı.",
                internal=True)
            return False

        self._send_log(
            "[Blutter Onarım] İlk deneme başarısız oldu, bilinen Windows sorunları için "
            "otomatik onarım script'i çalıştırılıyor...",
            internal=False)

        command_arguments = [
            "powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass",
            "-File", str(fix_script), "-RepoRoot", str(blutter_script.parent)
        ]

        is_success, error_message = self._execute_terminal_command(
            command_arguments,
            log_prefix="[Blutter Onarım]",
            timeout_seconds=180,
            custom_cwd=blutter_script.parent
        )

        if not is_success:
            self._send_log(f"[Blutter Onarım] Script çalıştırılamadı: {error_message}", is_error=True)
            return False


        build_dir = blutter_script.parent / "build"
        if build_dir.exists():
            try:
                shutil.rmtree(build_dir, ignore_errors=True)
                self._send_log("[Blutter Onarım] Eski build klasörü temizlendi.", internal=True)
            except Exception as e:
                self._send_log(f"[Blutter Onarım] Build klasörü temizlenemedi: {e}", internal=True)

        self._send_log("[Blutter Onarım] Onarım tamamlandı, analiz tekrar deneniyor...", internal=False)
        return True


    def _log_blutter_extraction_summary(self, output_dir: Path):
        """
        Blutter çıktısını (asm/, pp.txt, objs.txt, blutter_frida.js) özetler
        ve kaç dosya / ne kadar veri çıkarıldığını kullanıcıya bildirir.

        - asm/*.txt : sembollerle (fonksiyon/sınıf isimleriyle) etiketlenmiş,
          okunabilir hale getirilmiş Dart assembly dökümü.
        - pp.txt    : Object Pool dökümü (tüm sabit string'ler - API key,
          endpoint, secret ihtimali en yüksek dosya).
        - objs.txt  : Nested object pool dökümü.
        - blutter_frida.js : hazır Frida hook script'i.
        """
        asm_dir = output_dir / "asm"
        asm_file_count = len(list(asm_dir.rglob("*.txt"))) if asm_dir.exists() else 0

        pp_file = output_dir / "pp.txt"
        pp_size_kb = pp_file.stat().st_size / 1024 if pp_file.exists() else 0

        objs_file = output_dir / "objs.txt"
        objs_size_kb = objs_file.stat().st_size / 1024 if objs_file.exists() else 0

        frida_ready = (output_dir / "blutter_frida.js").exists()

        self._send_log(
            f"[Blutter] Çıkarım özeti -> {asm_file_count} sembollü assembly dosyası (asm/), "
            f"pp.txt {pp_size_kb:.0f} KB (Dart string/object pool), "
            f"objs.txt {objs_size_kb:.0f} KB, "
            f"{'Frida script hazır' if frida_ready else 'Frida script bulunamadı'}.",
            internal=False)

    def _run_blutter_analysis(self, dirs: dict, target_arch: str, _is_retry: bool = False) -> bool:
        blutter_script_path = self.dependencies.get('blutter_script')
        if not blutter_script_path or not Path(blutter_script_path).exists():
            self._send_log(
                "[Blutter Hatası] 'blutter_script' yolu bulunamadı veya geçersiz. Lütfen ayarlardan kontrol edin.",
                is_error=True)
            return False

        blutter_script = Path(blutter_script_path)

        input_lib_dir = dirs["flutter_files"] / "lib" / target_arch
        original_libapp = input_lib_dir / "libapp.so"
        original_libflutter = input_lib_dir / "libflutter.so"

        if not original_libapp.exists() or not original_libflutter.exists():
            self._send_log(
                f"[Blutter Uyarı] {target_arch} için orijinal libapp.so/libflutter.so çifti bulunamadığından atlandı.",
                is_error=True)
            return False

        output_dir = dirs["blutter_output"] / target_arch
        output_dir.mkdir(parents=True, exist_ok=True)

        blutter_python = self._resolve_blutter_python(blutter_script)

        if not _is_retry:
            self._ensure_blutter_python_dependencies(blutter_python, blutter_script)

        self._send_log(
            "[Blutter] Dart snapshot analizi başlatılıyor (ilk çalıştırmada Dart SDK derlemesi uzun sürebilir)...",
            internal=False)

        command_arguments = [blutter_python, str(blutter_script), str(input_lib_dir), str(output_dir)]

        subprocess_env = self._get_vsdev_env() if os.name == 'nt' else None

        is_success, error_message = self._execute_terminal_command(
            command_arguments,
            log_prefix="[Blutter]",
            timeout_seconds=3600,
            custom_cwd=blutter_script.parent,
            env=subprocess_env
        )

        if is_success:
            self._send_log(f"[Blutter] Analiz tamamlandı! Çıktı: {output_dir}", internal=False)
            self._log_blutter_extraction_summary(output_dir)
            create_vscode_settings(output_dir)
            self._send_log(f"[Blutter] VS Code ayar dosyası oluşturuldu, '{output_dir}' klasörünü doğrudan açabilirsiniz.", internal=True)
            return True

        self._send_log(f"[Blutter Hatası] Analiz başarısız oldu: {error_message}", is_error=True)

        if not _is_retry and "ModuleNotFoundError" in error_message:
            self._send_log(
                "[Blutter] Eksik Python modülü tespit edildi, bağımlılıklar kuruluyor ve tekrar deneniyor...",
                internal=False)
            if self._ensure_blutter_python_dependencies(blutter_python, blutter_script):
                return self._run_blutter_analysis(dirs, target_arch, _is_retry=True)

        if not _is_retry and os.name == 'nt' and not self.stop_event.is_set():
            if self._run_blutter_fix_script(blutter_script):
                return self._run_blutter_analysis(dirs, target_arch, _is_retry=True)

        return False

    def run_ghidra_analysis(self, ghidra_workspace_dir: Path, project_name: str) -> bool:
        ghidra_headless_path = self.dependencies.get('ghidra_headless')

        if not ghidra_headless_path or not Path(ghidra_headless_path).exists():
            self._send_log(
                "[Ghidra Hatası] 'ghidra_headless' yolu bulunamadı veya geçersiz. Lütfen ayarlardan kontrol edin.",
                is_error=True)
            return False

        self._send_log("[Ghidra] Headless analiz başlatılıyor (Tüm kütüphaneler dahil ediliyor)...", internal=False)

        command_arguments = [
            str(ghidra_headless_path),
            str(ghidra_workspace_dir),
            project_name,
            "-overwrite"
        ]

        imported_files_count = 0
        for so_file in ghidra_workspace_dir.glob("*.so"):
            command_arguments.extend(["-import", str(so_file)])
            imported_files_count += 1

        if imported_files_count == 0:
            self._send_log("[Ghidra Uyarı] Çalışma alanında import edilecek .so dosyası bulunamadı.", is_error=True)
            return False

        is_success, error_message = self._execute_terminal_command(
            command_arguments,
            log_prefix="[Ghidra Headless]",
            timeout_seconds=1200
        )

        if is_success:
            self._send_log(
                f"[Ghidra] Analiz tamamlandı! Toplam {imported_files_count} kütüphane '{project_name}' projesine eklendi.",
                internal=False)
            return True
        else:
            self._send_log(f"[Ghidra Hatası] Analiz başarısız oldu: {error_message}", is_error=True)
            return False

    def process_application(self, target_apk_file: Path, user_options: dict) -> Optional[Path]:
        if self.stop_event.is_set(): return None

        file_extension = target_apk_file.suffix.lower()
        if file_extension not in ['.apk', '.xapk', '.apkm', '.zip']:
            self._send_log(f"[Uyarı] Desteklenmeyen format atlandı: {target_apk_file.name}", is_error=True)
            return None

        base_working_directory = target_apk_file.parent
        app_name = target_apk_file.stem

        dirs = self.setup_project_directories(base_working_directory, app_name)

        try:
            if file_extension in ['.xapk', '.apkm', '.zip']:
                if not self._unpack_archive_securely(target_apk_file, dirs["extracted_files"]): return None
                sub_apks = list(dirs["extracted_files"].rglob("*.apk"))
                if sub_apks:
                    self._send_log(f"[Extractor] {len(sub_apks)} iç içe APK bulundu.")
                    for sub_apk in sub_apks:
                        sub_apk_target_dir = sub_apk.parent / sub_apk.stem
                        self._unpack_archive_securely(sub_apk, sub_apk_target_dir)
            elif file_extension == '.apk':
                self._unpack_archive_securely(target_apk_file, dirs["extracted_files"])

            is_flutter_app = self._isolate_and_analyze_flutter_engine(dirs["extracted_files"], dirs["flutter_files"])
            if is_flutter_app:
                self._send_log("[Info] Flutter framework tespit edildi!", internal=False)

                apk_to_reflutter = None

                if file_extension == '.apk':
                    apk_to_reflutter = target_apk_file
                else:
                    architecture_glob_patterns = {
                        "arm64-v8a": "*arm64*v8a*.apk",
                        "armeabi-v7a": "*armeabi*v7a*.apk",
                        "x86_64": "*x86*64*.apk",
                        "x86": "*x86*.apk",
                    }

                    apk_to_reflutter = None
                    for arch_name, glob_pattern in architecture_glob_patterns.items():
                        matching_apks = list(dirs["extracted_files"].rglob(glob_pattern))
                        if matching_apks:
                            apk_to_reflutter = matching_apks[0]
                            self._send_log(f"[Reflutter] Split APK bulundu ({arch_name}): {apk_to_reflutter.name}",
                                           internal=True)
                            break

                    if not apk_to_reflutter:
                        base_apks = list(dirs["extracted_files"].rglob("base.apk"))
                        if base_apks:
                            apk_to_reflutter = base_apks[0]

                if apk_to_reflutter:
                    refluttered_apk_path = self._apply_reflutter(apk_to_reflutter, dirs["flutter_files"])

                    if refluttered_apk_path:
                        self._send_log("[Reflutter] Yeniden derlenmiş APK analiz için çıkartılıyor...", internal=True)
                        reflutter_extract_dir = dirs["flutter_files"] / "Refluttered_Extracted"
                        self._unpack_archive_securely(refluttered_apk_path, reflutter_extract_dir)

                        reflutter_libs_dir = dirs["flutter_files"] / "Refluttered_Libs"
                        self._isolate_and_analyze_flutter_engine(reflutter_extract_dir, reflutter_libs_dir)

                        self._send_log("[Reflutter] Yeni derlemedeki kütüphane metinleri analize dahil edildi.",
                                       internal=False)
                else:
                    self._send_log("[Reflutter] Uygun bir APK veya Split APK (arm64_v8a) bulunamadığı için atlandı.",
                                   is_error=True)

            detected_js_framework = self._isolate_and_analyze_js_frameworks(dirs["extracted_files"],
                                                                            dirs["js_framework_files"])
            if detected_js_framework:
                self._send_log(f"[Info] {detected_js_framework} framework tespit edildi!", internal=False)

            native_lib_count = self._isolate_and_analyze_native_libraries(dirs["extracted_files"],
                                                                          dirs["native_libraries"])
            if native_lib_count > 0:
                self._send_log(f"[Isolator] {native_lib_count} native library (.so) dosyası çıkartıldı.", internal=True)

            blutter_output_ready_dir = None

            if is_flutter_app:
                detected_arch = self._detect_available_architecture(dirs)

                if user_options.get('enable_blutter') and self.dependencies.get('blutter_script'):
                    if detected_arch == "arm64-v8a":
                        blutter_success = self._run_blutter_analysis(dirs, detected_arch)
                        if blutter_success:
                            blutter_output_ready_dir = dirs["blutter_output"] / detected_arch
                    elif detected_arch:
                        self._send_log(
                            f"[Blutter] Şu an yalnızca arm64-v8a destekleniyor, tespit edilen mimari ({detected_arch}) atlandı.",
                            is_error=True)
                    else:
                        self._send_log("[Blutter] Desteklenen bir mimari bulunamadığından atlandı.", is_error=True)

                self._prepare_ghidra_workspace(dirs, detected_arch)

            if user_options.get('enable_decompilation') and self.dependencies.get('dex2jar'):
                self._scan_and_decompile_dex(dirs["extracted_files"], dirs["decompiled_jars"], dirs["intellij_project"],
                                             app_name)

            if user_options.get('enable_vulnerability_scan'):
                self._send_log("[Scanner] Zafiyetler, API anahtarları ve cloud sırları taranıyor...")

                directories_to_scan = [dirs["extracted_files"], dirs["intellij_project"], dirs["native_libraries"]]

                if is_flutter_app: directories_to_scan.append(dirs["flutter_files"])
                if detected_js_framework: directories_to_scan.append(dirs["js_framework_files"])


                if blutter_output_ready_dir and blutter_output_ready_dir.exists():
                    directories_to_scan.append(blutter_output_ready_dir)
                    self._send_log(
                        "[Scanner] Blutter'ın çıkardığı Dart assembly/object pool dosyaları "
                        "(asm/, pp.txt, objs.txt) taramaya dahil edildi.",
                        internal=True)

                vulnerability_found, report_name = self._scan_for_vulnerabilities_and_secrets(directories_to_scan,
                                                                                              dirs["analysis_reports"],
                                                                                              app_name)
                framework_str = ""
                if is_flutter_app:
                    framework_str = "Flutter"
                elif detected_js_framework:
                    framework_str = detected_js_framework

                json_path = dirs["analysis_reports"] / report_name if vulnerability_found else None

                md_generator = MarkdownReportGenerator(
                    report_directory=dirs["analysis_reports"],
                    application_name=app_name,
                    framework_detected=framework_str,
                    json_report_path=json_path
                )
                md_generator.generate_report()

                self._send_log(f"[Analysis] Bulgular kategorize edildi ve MD Raporu oluşturuldu.", internal=True)

            if user_options.get('enable_backup'):
                backup_file_path = dirs["original_backups"] / target_apk_file.name
                shutil.move(str(target_apk_file), str(backup_file_path))
                self._send_log("[Backup] Orijinal paket yedeğe alındı.", internal=True)

            return dirs["intellij_project"]

        except Exception as unhandled_error:
            self._send_log(f"İşlem Başarısız ({target_apk_file.name}): {unhandled_error}", is_error=True)
            return None