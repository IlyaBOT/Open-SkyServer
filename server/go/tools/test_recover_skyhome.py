import json
import stat
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

import recover_skyhome as recovery
from skyhome_static import StaticRecovery


class RecoveryTests(unittest.TestCase):
    def test_unsafe_paths(self):
        for name in ("../escape", "/absolute", "C:/drive", "a\\b", "x:y", "CON.txt", "a/../b", "a//b", "a/b.", "x\x00y"):
            with self.subTest(name=name):
                self.assertTrue(recovery.unsafe_name(name))
        self.assertFalse(recovery.unsafe_name("images/a.png"))

    def test_inventory_preservation_and_skip(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            archive = root / "input.zip"
            with zipfile.ZipFile(archive, "w") as stream:
                stream.writestr("normal/index.html", "<p>original</p>")
                stream.writestr("../escape", "unsafe")
                stream.writestr("Thumbs.db:encryptable", "unsafe")
                link = zipfile.ZipInfo("link")
                link.external_attr = (stat.S_IFLNK | 0o777) << 16
                stream.writestr(link, "../outside")
            before = archive.read_bytes()
            report = recovery.inventory(archive)
            self.assertEqual(len(list(root.iterdir())), 1)
            self.assertEqual(sum(bool(row["skip"]) for row in report["entries"]), 3)
            output = root / "private"
            output.mkdir()
            extracted = recovery.preserve_extract(archive, output, report)
            self.assertEqual((extracted / "normal/index.html").read_text(), "<p>original</p>")
            self.assertEqual((output / "originals/input.zip").read_bytes(), before)
            self.assertEqual(archive.read_bytes(), before)
            self.assertFalse((root / "escape").exists())
            with self.assertRaises(FileExistsError):
                recovery.preserve_extract(archive, output, report)

    def test_collision_and_size_limit(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "input.zip"
            with zipfile.ZipFile(path, "w") as stream:
                stream.writestr("A.txt", "a")
                stream.writestr("a.txt", "b")
            with self.assertRaises(ValueError):
                recovery.inventory(path)
            with zipfile.ZipFile(path, "w") as stream:
                stream.writestr("large", "abcdef")
            with patch.object(recovery, "MAX_FILE", 3):
                with self.assertRaises(ValueError):
                    recovery.inventory(path)

    def test_static_html_and_css(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            image = root / "local.png"
            source = root / "index.html"
            source.write_text('<body><div id="feed" class="clearfix" style="color:red"><a href="https://tracker/" onclick="steal()">News</a><textarea>Update</textarea><script>secret()</script><iframe src="https://tracker/"></iframe><form><input name="password"></form><img src="local.png"></div>', encoding="utf-8")
            recovery = StaticRecovery({image.resolve(): "image-local"})
            nodes = recovery.html(source)
            encoded = json.dumps(nodes)
            for bad in ("tracker", "onclick", "secret", "password", "script", "iframe", "form"):
                self.assertNotIn(bad, encoded)
            self.assertIn('"id": "feed"', encoded)
            self.assertIn('"tag": "a"', encoded)
            self.assertIn('"image": "image-local"', encoded)
            css = root / "style.css"
            css.write_text('@import "https://tracker/x";#feed{color:red;background:url(local.png);behavior:url(x.htc);width:expression(steal());background-image:image-set("https://tracker/y");filter:progid:DXImageTransform.Microsoft.AlphaImageLoader(src="https://tracker/x")}div{background:url(https://missing/no.png)}', encoding="utf-8")
            clean = recovery.css(css)
            self.assertIn('#feed{', clean)
            self.assertIn('color:red', clean)
            self.assertIn('url("/skyhome/assets/image-local")', clean)
            for bad in ("@", "tracker", "expression", "behavior", "image-set", "progid", "missing"):
                self.assertNotIn(bad, clean)
            self.assertTrue(recovery.missing)
            self.assertTrue(recovery.dropped)


if __name__ == "__main__":
    unittest.main()
