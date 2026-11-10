"""Private ZIP preservation, bounded extraction and inert SkyHome manifest.

No archived code is executed. Requires Python 3 and Node with bundled Acorn.
The original ZIPs, raw files and decoded JS string fragments remain private.
"""

import argparse
import hashlib
import json
import re
import shutil
import stat
import subprocess
import uuid
import zipfile
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path, PurePosixPath
from urllib.parse import unquote, urlsplit

from skyhome_static import StaticRecovery

MAX_FILES = 4096
MAX_FILE = 32 << 20
MAX_TOTAL = 128 << 20
DEVICE = re.compile(r"^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])$", re.I)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def write_json(path, value):
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, ensure_ascii=True, indent=2)
        stream.write("\n")


def unsafe_name(name):
    if not name or name.startswith("/") or "\\" in name:
        return True
    for part in name.rstrip("/").split("/"):
        if (part in ("", ".", "..") or part.rstrip(" .") != part
                or any(ord(c) < 32 or c in ':<>"|?*' for c in part)
                or DEVICE.fullmatch(part.split(".")[0])):
            return True
    return False


def inventory(path):
    if path.stat().st_size > MAX_TOTAL:
        raise ValueError("archive exceeds compressed size limit")
    data = path.read_bytes()
    if len(data) > MAX_TOTAL:
        raise ValueError("archive exceeds compressed size limit")
    rows, seen, total = [], set(), 0
    with zipfile.ZipFile(path) as archive:
        entries = archive.infolist()
        if len(entries) > MAX_FILES:
            raise ValueError("too many ZIP entries")
        for entry in entries:
            total += entry.file_size
            mode = entry.external_attr >> 16
            if (entry.file_size > MAX_FILE or total > MAX_TOTAL
                    or entry.file_size > max(1, entry.compress_size) * 1000
                    or entry.flag_bits & 1):
                raise ValueError("ZIP size/ratio/encryption policy failed")
            key = entry.filename.rstrip("/").casefold()
            if key in seen:
                raise ValueError("case-insensitive ZIP path collision")
            seen.add(key)
            reason = None
            if unsafe_name(entry.filename):
                reason = "unsafe path or Windows alternate stream"
            elif stat.S_ISLNK(mode) or (stat.S_IFMT(mode) not in (0, stat.S_IFREG, stat.S_IFDIR)):
                reason = "link or special file"
            rows.append({"name": entry.filename, "size": entry.file_size,
                         "compressed_size": entry.compress_size, "crc32": f"{entry.CRC:08x}",
                         "external_attributes": entry.external_attr, "skip": reason})
    return {"original_path": str(path), "sha256": digest(data),
            "compressed_bytes": len(data), "expanded_bytes": total, "entries": rows}


def preserve_extract(source, root, report):
    originals = root / "originals"
    originals.mkdir(exist_ok=True)
    copy = originals / source.name
    with source.open("rb") as src, copy.open("xb") as dst:
        shutil.copyfileobj(src, dst)
    if digest(copy.read_bytes()) != report["sha256"]:
        raise ValueError("archive changed while preserving")
    target = root / "extracted" / source.stem
    target.mkdir(parents=True, exist_ok=False)
    with zipfile.ZipFile(copy) as archive:
        for entry, row in zip(archive.infolist(), report["entries"]):
            if row["skip"]:
                continue
            out = target.joinpath(*PurePosixPath(entry.filename).parts)
            if not out.resolve().is_relative_to(target.resolve()):
                raise ValueError("ZIP escapes extraction root")
            if entry.is_dir():
                out.mkdir(parents=True, exist_ok=True)
                continue
            out.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(entry) as src, out.open("xb") as dst:
                data = src.read(MAX_FILE + 1)
                if len(data) != entry.file_size or len(data) > MAX_FILE:
                    raise ValueError("ZIP expansion size mismatch")
                dst.write(data)
                row["sha256"] = digest(data)
    return target


class Fragment(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.hidden = []
        self.text = []
        self.references = []
        self.ids = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag in ("script", "style", "iframe", "object"):
            self.hidden.append(tag)
        if attrs.get("id"):
            self.ids.append(attrs["id"])
        for key in ("src", "href", "action"):
            if attrs.get(key):
                self.references.append(attrs[key])

    def handle_endtag(self, tag):
        if self.hidden and tag == self.hidden[-1]:
            self.hidden.pop()

    def handle_data(self, data):
        if not self.hidden:
            text = " ".join(data.split())
            # Template expressions are not evaluated or represented as live data.
            if (len(text) > 2 and re.search(r"[A-Za-z]{3}", text)
                    and not re.search(r"<%|%>|[{};=]|function\(|display:|^div$", text)):
                self.text.append(text[:2048])


def inspect(root, report_root, literal_tool):
    sources, fragments, labels = [], [], {}
    recovered = report_root / "reconstructed" / "js-string-fragments"
    recovered.mkdir(parents=True)
    for path in sorted(root.rglob("*")):
        if not path.is_file() or "__MACOSX" in path.parts or path.name.startswith("._"):
            continue
        if path.suffix.lower() not in (".html", ".js", ".css", ".json", ".txt", ".md"):
            continue
        text = path.read_text(encoding="utf-8-sig", errors="replace")
        page_labels = []
        row = {"path": str(path.relative_to(root)), "sha256": digest(path.read_bytes()),
               "license_markers": sorted(set(re.findall(r"(?i)MIT|GPL|copyright|all rights reserved|license", text))),
               "remote_hosts": sorted(set(re.findall(r"https?://([a-zA-Z0-9.-]+)", text))),
               "bridge_markers": sorted(set(re.findall(r"external\.[A-Za-z_][A-Za-z0-9_]*|SkypeKit|skypeToken|skypetoken|msBeacon|SH\.API|SH\.Tracking", text)))}
        parser = Fragment()
        if path.suffix.lower() == ".html":
            parser.feed(text)
            row["references"] = parser.references
            row["dom_ids"] = parser.ids
            row["missing_local_references"] = []
            for ref in parser.references:
                url = urlsplit(ref)
                if not url.scheme and not url.netloc and url.path and not url.path.startswith("/"):
                    if not (path.parent / unquote(url.path)).is_file():
                        row["missing_local_references"].append(ref)
            # Ignore Wayback toolbar text when an untouched page is also present.
            if path.name != "Skype Home.html":
                page_labels.extend(parser.text)
        elif path.suffix.lower() == ".js":
            result = subprocess.run(["node", "--expose-internals", str(literal_tool), str(path)],
                                    capture_output=True, text=True, encoding="utf-8", check=True)
            decoded = json.loads(result.stdout)
            row["literal_parser"] = decoded["parser"]
            row["literal_tokenizer_error"] = decoded["error"]
            for literal in decoded["literals"]:
                value = literal.pop("value")
                filename = digest(value.encode("utf-8")) + ".txt"
                out = recovered / filename
                if not out.exists():
                    with out.open("x", encoding="utf-8") as stream:
                        stream.write(value)
                fragments.append({"source": row["path"], "utf16_start": literal["start"],
                                  "utf16_end": literal["end"], "file": str(out.relative_to(report_root)),
                                  "kind": "decoded JS string; not standalone original source"})
                if re.match(r"\s*<(?:div|span|p|a|ul|li|h[1-6]|img|table|section)\b", value, re.I):
                    fragment = Fragment()
                    fragment.feed(value)
                    page_labels.extend(fragment.text)
        if page_labels:
            labels[row["path"]] = list(dict.fromkeys(page_labels))
        sources.append(row)
    write_json(report_root / "source-inspection.json", sources)
    write_json(report_root / "reconstructed" / "provenance.json", fragments)
    return labels


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--home", type=Path, required=True)
    parser.add_argument("--incall", type=Path, required=True)
    parser.add_argument("--ads", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    args = parser.parse_args()
    inputs = [args.home, args.incall, args.ads]
    # Inventory ALL archives before creating any extraction target.
    reports = [inventory(path) for path in inputs]
    run = "recovery-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ-") + uuid.uuid4().hex[:8]
    home = args.output_root / "SkyHome" / run
    widget = args.output_root / "Sky-InnCallAdWidget" / run
    home.mkdir(parents=True, exist_ok=False)
    widget.mkdir(parents=True, exist_ok=False)
    roots = [home, widget, widget]
    for path, root, report in zip(inputs, roots, reports):
        write_json(root / (path.stem + "-inventory-before-extract.json"), report)
    extracted = [preserve_extract(path, root, report) for path, root, report in zip(inputs, roots, reports)]
    for path, root, report in zip(inputs, roots, reports):
        write_json(root / (path.stem + "-extraction-manifest.json"), report)
    # Exactly one nested level, with its own pre-extraction inventory and caps.
    nested_rows = []
    for index, raw in enumerate(extracted):
        for number, nested in enumerate(p for p in sorted(raw.rglob("*.zip")) if "__MACOSX" not in p.parts and not p.name.startswith("._")):
            if number >= 8:
                raise ValueError("nested ZIP count limit")
            report = inventory(nested)
            nested_root = roots[index] / "nested" / (str(number) + "-" + report["sha256"][:12])
            nested_root.mkdir(parents=True, exist_ok=False)
            write_json(nested_root / "inventory-before-extract.json", report)
            preserve_extract(nested, nested_root, report)
            write_json(nested_root / "extraction-manifest.json", report)
            inspect(nested_root / "extracted", nested_root, Path(__file__).with_name("skyhome_literals.cjs"))
            nested_rows.append({"source": str(nested), "root": str(nested_root), "sha256": report["sha256"]})
    labels_home = inspect(extracted[0], home, Path(__file__).with_name("skyhome_literals.cjs"))
    labels_widget = inspect(extracted[1], widget, Path(__file__).with_name("skyhome_literals.cjs"))
    serve = home / "serve"
    (serve / "assets").mkdir(parents=True)
    assets = []
    images = {}
    groups = {}
    for group, raw in [("home", extracted[0]), ("widget", extracted[1]), ("incall", extracted[2])]:
        groups[group] = []
        for path in sorted(raw.rglob("*")):
            if not path.is_file() or "__MACOSX" in path.parts or path.name.startswith("._"):
                continue
            if path.suffix.lower() not in (".png", ".gif", ".jpg", ".jpeg"):
                continue
            data = path.read_bytes()
            name = digest(data) + path.suffix.lower()
            out = serve / "assets" / name
            if not out.exists():
                with out.open("xb") as stream:
                    stream.write(data)
                assets.append({"id": "image-" + digest(data)[:16], "file": "assets/" + name, "sha256": digest(data)})
            groups[group].append("image-" + digest(data)[:16])
            images[path.resolve()] = "image-" + digest(data)[:16]
    def selected(labels, needle, suffix):
        return list(dict.fromkeys(text for source, values in labels.items()
                                 if needle in source and source.endswith(suffix)
                                 for text in values))[:48]

    pages, static_reports = [], []
    variants = [("home", "Skype Home", extracted[0] / "skypehome" / "Skype Home Present", "index-634a660f68768ef95f569e89afd9ed82.min.css"),
                ("classic", "Skype Home 5.9-6.21", extracted[0] / "skypehome" / "Skype Home 5.9-6.21", "index-d39b690859dfa6a91b7938ef29422d82.min.css"),
                ("original", "Skype Home Original", extracted[0] / "skypehome" / "Skype Home original", "i/production/combined.css"),
                ("incall", "In-Call Ad Widget", extracted[1], "index-0dc0ccc8a4d895da2b058c43ff94b6b4.min.css")]
    for page_id, title, folder, css_name in variants:
        recovery = StaticRecovery(images)
        nodes = recovery.html(folder / "index.html")
        style = recovery.css(folder / css_name) + "\n" + "\n".join(recovery.inline_rules)
        style_file = "styles/" + page_id + ".css"
        (serve / "styles").mkdir(exist_ok=True)
        with (serve / style_file).open("x", encoding="utf-8", newline="\n") as stream:
            stream.write(style)
        assets.append({"id": "style-" + page_id, "kind": "css", "file": style_file, "sha256": digest(style.encode("utf-8"))})
        pages.append({"id": page_id, "title": title, "text": [], "nodes": nodes,
                      "style": "style-" + page_id, "images": groups["incall"] if page_id == "incall" else []})
        static_reports.append({"page": page_id, "html_source": str(folder / "index.html"),
                               "css_source": str(folder / css_name), "missing_images": recovery.missing,
                               "removed_css": recovery.dropped, "inert_ad_gallery_fallback": page_id == "incall"})
    write_json(home / "static-reconstruction.json", static_reports)
    write_json(serve / "manifest.json", {"version": 1, "pages": pages, "assets": assets})
    summary = {"home": str(home), "widget": str(widget), "serve_dir": str(serve),
               "analysis": "ordinary static source inspection; no recovered code executed",
               "copyright": "No archive-wide redistribution permission established. Keep all recovered material private.",
               "limits": {"files": MAX_FILES, "file_bytes": MAX_FILE, "total_bytes": MAX_TOTAL},
               "archives": [{"path": r["original_path"], "sha256": r["sha256"],
                             "entries": len(r["entries"]), "skipped": [e["name"] for e in r["entries"] if e["skip"]]} for r in reports],
               "nested_archives": nested_rows,
               "authored_vs_recovered": "serve/manifest.json contains recovered structural DOM, local asset references and sanitized recovered CSS. Raw extracted/ is unchanged. reconstructed/ contains decoded JS strings with source offsets, not original source modules. Navigation, safety overrides and server are authored; incall GIF gallery is an explicit inert fallback.",
               "limitations": ["No dynamic template expressions evaluated", "No Skype host bridge or contact/feed/account endpoints implemented", "No remote assets fetched", "No original JS or unsanitized HTML/CSS served", "GIF previews are first-frame PNGs", "@-rules including fonts/media queries removed; IE hacks/expressions/remote image declarations removed", "Classic/original remain mostly empty source DOM shells without their JS and host data", "Fragment boundaries do not reconstruct source modules or original filenames"]}
    write_json(home / "recovery-summary.json", summary)
    print(json.dumps(summary, ensure_ascii=True, indent=2))


if __name__ == "__main__":
    main()
