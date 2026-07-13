"""
Blutter/Ghidra cikti klasorlerini VS Code'da gercek bir Dart projesi sanip
kirmizi hata cizgileriyle doldurmasini ve yavaslamasini onlemek icin
.vscode/settings.json otomatik olusturan yardimci script.

NEDEN GEREKLI:
Blutter'in urettigi asm/*.txt dosyalari gecerli Dart kodu degildir
("class :: {}" gibi bloklar). VS Code'daki Dart eklentisi bunlari analiz
etmeye calisip her dosyada hata verir ve klasoru acmak/gezmek yavaslar.
Bu script, o klasorler icin Dart analizini kapatan bir ayar dosyasi yazar.

KULLANIM 1 - Bagimsiz / komut satirindan (elindeki mevcut cikti icin):
    python vscode_settings_helper.py "D:\\...\\Blutter-using-fresh\\out_dir"

    Verilen kok klasor altinda "asm" adinda tum klasorleri bulur, hem o
    klasorlere hem de kok klasore .vscode/settings.json yazar.

KULLANIM 2 - Koda entegre / arka plan otomasyonu icin:
    from vscode_settings_helper import create_vscode_settings
    create_vscode_settings(output_dir)   # output_dir = blutter'in cikti kok klasoru

    Bunu analysis_engine.py icindeki _run_blutter_analysis basarili
    oldugunda cagirmak icin INTEGRATION.md dosyasina bak.
"""

import json
import sys
from pathlib import Path

SETTINGS_CONTENT = {
    "dart.analysisExcludedFolders": ["."],
    "dart.previewFlutterUiGuides": False,
    "dart.enableSdkFormatter": False,
    "editor.formatOnSave": False,
    "files.watcherExclude": {
        "**/asm/**": True
    }
}


def create_vscode_settings(target_dir: Path) -> Path:
    """target_dir altina .vscode/settings.json yazar.
    Dosya zaten varsa mevcut ayarlarla birlestirir (ustune yazmaz, ekler)."""
    target_dir = Path(target_dir)
    vscode_dir = target_dir / ".vscode"
    vscode_dir.mkdir(parents=True, exist_ok=True)
    settings_path = vscode_dir / "settings.json"

    merged = dict(SETTINGS_CONTENT)
    if settings_path.exists():
        try:
            existing = json.loads(settings_path.read_text(encoding="utf-8"))
            existing.update(merged)
            merged = existing
        except Exception:
            pass  # bozuk/okunamayan dosyaysa uzerine temiz yaz

    settings_path.write_text(json.dumps(merged, indent=4, ensure_ascii=False), encoding="utf-8")
    return settings_path


def create_settings_recursively(root_dir: Path) -> list:
    """root_dir'in kendisine ve altindaki tum 'asm' klasorlerine ayar dosyasi yazar."""
    root_dir = Path(root_dir)
    written = [create_vscode_settings(root_dir)]

    for asm_dir in root_dir.rglob("asm"):
        if asm_dir.is_dir():
            written.append(create_vscode_settings(asm_dir))

    return written


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Kullanim: python vscode_settings_helper.py <klasor_yolu>")
        print("Ornek   : python vscode_settings_helper.py \"D:\\yazilim\\my_codes\\python\\Blutter-using-fresh\\out_dir\"")
        sys.exit(1)

    root = Path(sys.argv[1])
    if not root.exists():
        print(f"Klasor bulunamadi: {root}")
        sys.exit(1)

    results = create_settings_recursively(root)
    print(f"{len(results)} adet .vscode/settings.json olusturuldu/guncellendi:")
    for r in results:
        print(f"  - {r}")