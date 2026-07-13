"""
Blutter ciktisini (asm/*.txt + pp.txt) tarayip tek bir JSON indeksine cevirir.
Bu JSON dosyasi blutter_viewer.html icine yuklenip arama/gezinme icin kullanilir.

Bu ARKA PLAN adimidir (bir kere calistirilir, sonuc dosyaya yazilir).
Gorsel gezinme/arama ise blutter_viewer.html'de, yani ON YUZDE olur.

KULLANIM:
    python blutter_indexer.py "D:\\...\\Blutter_Output\\arm64-v8a" -o blutter_index.json

NOT (onemli):
    pp.txt <-> asm eslestirmesi sezgiseldir; Blutter'in pp.txt formatinin
    "0xNNNN: deger" seklinde satir satir oldugunu varsayar. Viewer'da
    "pp referans sayisi" cok ama esleseme/tooltip cikmiyorsa, bana bir
    pp.txt ornegi gonder, regex'i gercek formata gore ayarlarim.
"""

import argparse
import json
import re
import sys
from pathlib import Path

CLASS_MARKER_RE = re.compile(
    r"^// class id: (\d+), size: (0x[0-9a-fA-F]+)(?:, field offset: (0x[0-9a-fA-F]+))?\s*$"
)
LIB_URL_RE = re.compile(r"^// lib: (.*?), url: (.*)$")
CLASS_DECL_RE = re.compile(
    r"^\s*(abstract\s+)?class\s+([\w$]+)(?:<[^>]*>)?"
    r"(?:\s+extends\s+([\w$.<>]+))?"
    r"(?:\s+implements\s+([\w$.<>,\s]+?))?\s*\{?\s*$"
)
METHOD_ADDR_RE = re.compile(r"^\s*// \*\* addr: (0x[0-9a-fA-F]+), size: (-?0x[0-9a-fA-F]+|-1)\s*$")
PP_REF_RE = re.compile(r"pp\+(0x[0-9a-fA-F]+)")
PP_LINE_RE = re.compile(r"^\s*(0x[0-9a-fA-F]+)[:\s]+(.*)$")

FRAMEWORK_PREFIXES = ("package:", "dart:")


def parse_pp_txt(pp_path: Path) -> dict:
    entries = {}
    if not pp_path.exists():
        return entries
    with open(pp_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            m = PP_LINE_RE.match(line)
            if m:
                offset = m.group(1).lower()
                norm = hex(int(offset, 16))  # baki bastaki sifirlari temizler
                entries[norm] = m.group(2).strip()
    return entries


def parse_asm_file(path: Path, rel_path: str) -> dict:
    text = path.read_text(encoding="utf-8", errors="ignore")
    lines = text.split("\n")

    file_url = ""
    if lines and lines[0].startswith("// lib:"):
        m = LIB_URL_RE.match(lines[0])
        if m:
            file_url = m.group(2).strip()

    is_framework = file_url.startswith(FRAMEWORK_PREFIXES)

    class_start_indices = [i for i, l in enumerate(lines) if CLASS_MARKER_RE.match(l)]
    class_start_indices.append(len(lines))

    classes = []
    for idx in range(len(class_start_indices) - 1):
        start = class_start_indices[idx]
        end = class_start_indices[idx + 1]
        block_lines = lines[start:end]

        marker_match = CLASS_MARKER_RE.match(block_lines[0])
        class_id, size, field_offset = marker_match.groups()

        class_name, extends, implements = None, None, None
        for bl in block_lines[1:6]:
            m = CLASS_DECL_RE.match(bl)
            if m:
                class_name = m.group(2)
                extends = m.group(3)
                implements = m.group(4)
                break

        if not class_name:
            continue

        method_marker_positions = [
            i for i, l in enumerate(block_lines) if METHOD_ADDR_RE.match(l.strip())
        ]
        methods = []
        for m_idx, pos in enumerate(method_marker_positions):
            addr_match = METHOD_ADDR_RE.match(block_lines[pos].strip())
            addr, msize = addr_match.groups()

            sig_line = ""
            for back in range(pos - 1, max(pos - 6, -1), -1):
                candidate = block_lines[back].strip()
                if candidate and not candidate.startswith("//"):
                    sig_line = candidate
                    break

            body_end = (
                method_marker_positions[m_idx + 1]
                if m_idx + 1 < len(method_marker_positions)
                else len(block_lines)
            )
            body_lines = block_lines[pos:body_end]
            body_text = "\n".join(body_lines)

            refs = sorted(set(hex(int(h, 16)) for h in PP_REF_RE.findall(body_text)))

            methods.append({
                "signature": sig_line,
                "addr": addr,
                "size": msize,
                "refs": refs,
                "body": body_text
            })

        classes.append({
            "class_id": class_id,
            "size": size,
            "field_offset": field_offset,
            "name": class_name,
            "extends": extends,
            "implements": implements,
            "methods": methods
        })

    return {
        "path": rel_path,
        "url": file_url,
        "is_framework": is_framework,
        "classes": classes
    }


def build_index(blutter_output_dir: Path) -> dict:
    asm_dir = blutter_output_dir / "asm"
    pp_path = blutter_output_dir / "pp.txt"

    if not asm_dir.exists():
        print(f"UYARI: {asm_dir} bulunamadi.")

    pp_entries = parse_pp_txt(pp_path)

    files = []
    asm_files = list(asm_dir.rglob("*.txt")) if asm_dir.exists() else []
    total = len(asm_files)
    for i, asm_file in enumerate(asm_files, 1):
        rel = str(asm_file.relative_to(asm_dir))
        try:
            files.append(parse_asm_file(asm_file, rel))
        except Exception as e:
            print(f"  [atlandi] {rel}: {e}")
        if i % 200 == 0 or i == total:
            print(f"  islendi: {i}/{total}")

    return {
        "source_dir": str(blutter_output_dir),
        "pp_entry_count": len(pp_entries),
        "pp_entries": pp_entries,
        "file_count": len(files),
        "files": files
    }


def main():
    parser = argparse.ArgumentParser(
        description="Blutter ciktisini arama/gezinme icin JSON indeksine cevirir."
    )
    parser.add_argument(
        "blutter_output_dir",
        help="asm/ ve pp.txt iceren klasor (orn: Blutter_Output/arm64-v8a)"
    )
    parser.add_argument("-o", "--output", default="blutter_index.json", help="cikti JSON dosyasi")
    args = parser.parse_args()

    src = Path(args.blutter_output_dir)
    if not src.exists():
        print(f"Klasor bulunamadi: {src}")
        sys.exit(1)

    print(f"Indeksleniyor: {src}")
    index = build_index(src)

    out_path = Path(args.output)
    out_path.write_text(json.dumps(index, ensure_ascii=False), encoding="utf-8")

    print(f"\nTamamlandi -> {out_path}")
    print(f"  Dosya sayisi : {index['file_count']}")
    print(f"  pp.txt kaydi : {index['pp_entry_count']}")
    print(f"\nSimdi blutter_viewer.html dosyasini tarayicida ac ve '{out_path.name}' dosyasini sec.")


if __name__ == "__main__":
    main()