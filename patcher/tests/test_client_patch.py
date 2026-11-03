"""No private keys, emulation, Skype execution, or third-party packages needed."""
import base64
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location("ClientPatch", Path(__file__).resolve().parents[1] / "tools" / "ClientPatch.py")
patch = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(patch)


class ClientPatchTests(unittest.TestCase):
    def setUp(self):
        self.image = bytes(range(256)) * 16
        modified = bytearray(self.image)
        modified[0:2] = b"XY"
        modified[500:503] = b"abc"
        modified[-1] = 7
        self.patched = bytes(modified) + b"appended\x00\xff"
        self.build = {"original_sha256": patch.ORIGINAL_SHA256, "static_image_sha256": patch.sha256(self.image),
                      "patched_sha256": patch.sha256(self.patched), "server_ip": "192.168.52.34",
                      "source_path": "C:/PRIVATE/operator.exe", "private_key": "DO NOT COPY", "unverified": ["private"]}
        self.constants = mock.patch.multiple(patch, IMAGE_SIZE=len(self.image), IMAGE_SHA256=patch.sha256(self.image))
        self.constants.start()
        self.addCleanup(self.constants.stop)
        self.recipe = patch.create_recipe(self.image, self.patched, self.build)

    def test_exact_output_and_minimal_public_allowlist(self):
        self.assertEqual(patch.apply_recipe(self.image, self.recipe), self.patched)
        self.assertEqual([(s["offset"], len(base64.b64decode(s["data"]))) for s in self.recipe["spans"]],
                         [(0, 2), (500, 3), (len(self.image) - 1, 1)])
        encoded = json.dumps(self.recipe)
        for secret in ("PRIVATE", "source_path", "private_key", "DO NOT COPY", "unverified"):
            self.assertNotIn(secret, encoded)
        metadata = patch.public_metadata(self.recipe, patch.sha256(encoded.encode()))
        self.assertEqual(metadata["client_version"], "4.2.0.187")
        self.assertEqual(metadata["server_ip"], self.build["server_ip"])

    def test_wrong_input_including_packed_exe_rejected(self):
        for data in (b"MZ packed", self.image[:-1], bytes(len(self.image)), self.patched):
            with self.subTest(size=len(data)), self.assertRaisesRegex(ValueError, "UNPACKED"):
                patch.apply_recipe(data, self.recipe)

    def test_tampered_span_append_and_hashes(self):
        for mutate in (lambda r: r["spans"][0].update(data="WVk="),
                       lambda r: r["spans"][0].update(source_sha256="0" * 64),
                       lambda r: r.update(append=base64.b64encode(b"tampered!!").decode()),
                       lambda r: r["output"].update(sha256="0" * 64)):
            recipe = copy.deepcopy(self.recipe)
            mutate(recipe)
            with self.assertRaises(ValueError):
                patch.apply_recipe(self.image, recipe)

    def test_malformed_fields_ranges_types_and_payloads(self):
        mutations = [lambda r: r.update(unexpected="private"), lambda r: r.pop("server_ip"),
                     lambda r: r.update(schema_version=True), lambda r: r.update(schema_version=2),
                     lambda r: r.update(client_version="../../bad"), lambda r: r.update(server_ip="224.0.0.1"),
                     lambda r: r.update(server_ip="0.0.0.0"), lambda r: r.update(server_ip="255.255.255.255"),
                     lambda r: r.update(server_ip=["127.0.0.1"]), lambda r: r.update(server_port="12350"),
                     lambda r: r.update(original_sha256="0" * 64), lambda r: r["source"].update(sha256="0" * 64),
                     lambda r: r["source"].update(size=True), lambda r: r["output"].update(size=1 << 64),
                     lambda r: r["output"].update(size=len(self.image)), lambda r: r["output"].update(sha256="A" * 64),
                     lambda r: r["spans"][0].update(offset=-1), lambda r: r["spans"][0].update(offset=1.5),
                     lambda r: r["spans"][0].update(offset=True), lambda r: r["spans"][0].update(offset=len(self.image)),
                     lambda r: r["spans"][0].update(offset=len(self.image) - 1),
                     lambda r: r["spans"][1].update(offset=1), lambda r: r["spans"].reverse(),
                     lambda r: r["spans"][0].update(data=""), lambda r: r["spans"][0].update(data="%%%"),
                     lambda r: r["spans"][0].update(data="WFk=\n"), lambda r: r["spans"][0].update(data="WFk=="),
                     lambda r: r["spans"][0].update(data=8), lambda r: r["spans"][0].update(extra=1),
                     lambda r: r.update(spans={}), lambda r: r.update(append=None)]
        for i, mutate in enumerate(mutations):
            recipe = copy.deepcopy(self.recipe)
            mutate(recipe)
            with self.subTest(case=i), self.assertRaises(ValueError):
                patch.validate_recipe(recipe)
        for value in (None, [], 1, "recipe"):
            with self.assertRaises(ValueError):
                patch.validate_recipe(value)

    def test_refuses_unchanged_bytes_even_with_correct_output_hash(self):
        recipe = copy.deepcopy(self.recipe)
        recipe["spans"][0]["data"] = base64.b64encode(self.image[:2]).decode()
        with self.assertRaisesRegex(ValueError, "unchanged"):
            patch.apply_recipe(self.image, recipe)

    def test_limits_payload_span_count_and_files_before_read(self):
        with mock.patch.object(patch, "MAX_PATCH_BYTES", 8), self.assertRaises(ValueError):
            patch.validate_recipe(self.recipe)
        with mock.patch.object(patch, "MAX_SPANS", 1), self.assertRaises(ValueError):
            patch.validate_recipe(self.recipe)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "huge"
            path.write_bytes(b"x" * 100)
            with self.assertRaisesRegex(ValueError, "size limit"):
                patch.read_bounded(path, 10)
            with mock.patch.object(patch, "MAX_RECIPE_SIZE", 10), self.assertRaises(ValueError):
                patch.load_recipe(path)

    def test_duplicate_json_nonfinite_encoding_and_nesting(self):
        for data in (b'{"a":1,"a":2}', b'{"nested":{"a":1,"a":2}}', b'{"a":NaN}',
                     b"\xff", b"[" * 2000 + b"]" * 2000):
            with self.subTest(data=data[:20]), self.assertRaises(ValueError):
                patch._json(data)

    def test_build_fingerprints_version_and_wrong_canonical_source(self):
        for key in ("original_sha256", "static_image_sha256", "patched_sha256", "server_ip", "client_version"):
            build = dict(self.build, **{key: "wrong"})
            with self.subTest(key=key), self.assertRaises(ValueError):
                patch.create_recipe(self.image, self.patched, build)
        with self.assertRaises(ValueError):
            patch.create_recipe(self.patched, self.patched, self.build)

    def test_cli_both_create_forms_and_apply_never_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            image, exe, build = root / "image.bin", root / "Skype.exe", root / "build.json"
            image.write_bytes(self.image)
            exe.write_bytes(self.patched)
            build.write_text(json.dumps(self.build), encoding="utf-8")
            for i, arguments in enumerate((["--build-dir", str(root)],
                                           ["--patched", str(exe), "--build-json", str(build)])):
                recipe, output = root / f"recipe{i}.json", root / f"output{i}.exe"
                patch.main(["create", "--image", str(image), *arguments, "--output", str(recipe)])
                patch.main(["apply", "--image", str(image), "--patch", str(recipe), "--output", str(output)])
                self.assertEqual(output.read_bytes(), self.patched)
                with self.assertRaises(FileExistsError):
                    patch.main(["apply", "--image", str(image), "--patch", str(recipe), "--output", str(output)])
            self.assertEqual(image.read_bytes(), self.image)
            self.assertEqual(exe.read_bytes(), self.patched)

    def test_apply_failure_leaves_no_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "image").write_bytes(self.image)
            recipe = copy.deepcopy(self.recipe)
            recipe["output"]["sha256"] = "0" * 64
            (root / "recipe").write_text(json.dumps(recipe), encoding="ascii")
            with self.assertRaises(ValueError):
                patch.main(["apply", "--image", str(root / "image"), "--patch", str(root / "recipe"),
                            "--output", str(root / "output")])
            self.assertFalse((root / "output").exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
