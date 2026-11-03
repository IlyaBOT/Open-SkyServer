"""Public, stdlib-only delta recipes for the canonical UNPACKED Skype image.

Operator: create --image canonical.image.bin --build-dir developer-build
                 --output dist/community.patch.json
Client:   apply --image canonical.image.bin --patch dist/community.patch.json
                --output NEW/Skype.exe

Recipes contain only changed bytes and a bounded appended tail, never the packed
EXE or build manifest. Hashes detect corruption, not an untrusted recipe author;
obtain recipes from a trusted operator. No keys or profiles are read by this tool.
"""
import argparse
import base64
import binascii
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import sys

ORIGINAL_SHA256 = "a2e175ce7c9888c125e2b3d4c2343229832ba0d0cd8a8a1ce120ce92624e856c"
IMAGE_SHA256 = "53ecb3032e76afe1db0a01eeb81e81f81c84e72d7cfae79dad3f197ca171d1ac"
IMAGE_SIZE = 0x1848000
CLIENT_VERSION = "4.2.0.187"
MAX_FILE_SIZE = 64 * 1024 * 1024
MAX_PATCH_BYTES = 1024 * 1024
MAX_RECIPE_SIZE = 8 * 1024 * 1024
MAX_BUILD_JSON_SIZE = 1024 * 1024
MAX_SPANS = 32768
FORMAT = "opensky-client-patch"


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def read_bounded(path, limit):
    with Path(path).open("rb") as stream:
        if stream.seek(0, 2) > limit:
            raise ValueError(f"File exceeds size limit ({limit} bytes)")
        stream.seek(0)
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise ValueError("File grew beyond size limit")
    return data


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON field: " + key)
        result[key] = value
    return result


def _json(data):
    try:
        value = json.loads(data.decode("utf-8"), object_pairs_hook=_unique_object,
                           parse_constant=lambda value: _reject("Non-finite JSON value"))
    except (UnicodeError, RecursionError) as error:
        raise ValueError("Invalid JSON encoding or nesting") from error
    if type(value) is not dict:
        raise ValueError("Expected a JSON object")
    return value


def _reject(message):
    raise ValueError(message)


def _fields(value, names, label):
    if type(value) is not dict or set(value) != set(names):
        raise ValueError("Invalid " + label + " fields")


def _integer(value, low, high, label):
    if type(value) is not int or not low <= value <= high:
        raise ValueError("Invalid " + label)
    return value


def _hash(value):
    if type(value) is not str or not re.fullmatch("[0-9a-f]{64}", value):
        raise ValueError("Invalid SHA256")
    return value


def _server(value):
    if type(value) is not str:
        raise ValueError("Invalid server_ip")
    try:
        ip = ipaddress.IPv4Address(value)
    except ipaddress.AddressValueError as error:
        raise ValueError("Invalid server_ip") from error
    if str(ip) != value or ip.is_multicast or ip.is_unspecified or int(ip) == 0xFFFFFFFF:
        raise ValueError("Expected a unicast server IPv4")
    return value


def _decode(value):
    if type(value) is not str or len(value) > 4 * ((MAX_PATCH_BYTES + 2) // 3):
        raise ValueError("Invalid or oversized base64 payload")
    try:
        data = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as error:
        raise ValueError("Invalid base64 payload") from error
    if base64.b64encode(data).decode("ascii") != value:
        raise ValueError("Noncanonical base64 payload")
    return data


def validate_recipe(recipe):
    _fields(recipe, ("format", "schema_version", "client_version", "original_sha256",
                     "source", "output", "server_ip", "server_port", "spans", "append"), "recipe")
    if recipe["format"] != FORMAT or type(recipe["format"]) is not str:
        raise ValueError("Unsupported recipe format")
    _integer(recipe["schema_version"], 1, 1, "schema version")
    if recipe["client_version"] != CLIENT_VERSION:
        raise ValueError("Unsupported client_version")
    if _hash(recipe["original_sha256"]) != ORIGINAL_SHA256:
        raise ValueError("Unsupported packed original SHA256")
    for name in ("source", "output"):
        _fields(recipe[name], ("size", "sha256"), name)
        _hash(recipe[name]["sha256"])
    source = recipe["source"]
    if source["sha256"] != IMAGE_SHA256:
        raise ValueError("Recipe source must be the canonical UNPACKED image")
    _integer(source["size"], IMAGE_SIZE, IMAGE_SIZE, "canonical image size")
    _integer(recipe["output"]["size"], IMAGE_SIZE, min(MAX_FILE_SIZE, IMAGE_SIZE + MAX_PATCH_BYTES), "output size")
    _server(recipe["server_ip"])
    _integer(recipe["server_port"], 12350, 12350, "server port")
    spans = recipe["spans"]
    if type(spans) is not list or len(spans) > MAX_SPANS:
        raise ValueError("Invalid or excessive spans")
    end, total = 0, 0
    for row in spans:
        _fields(row, ("offset", "source_sha256", "data"), "span")
        at = _integer(row["offset"], 0, IMAGE_SIZE - 1, "span offset")
        _hash(row["source_sha256"])
        data = _decode(row["data"])
        if not data or at < end or at + len(data) > IMAGE_SIZE:
            raise ValueError("Empty, overlapping, unordered, or out-of-range span")
        end = at + len(data)
        total += len(data)
        if total > MAX_PATCH_BYTES:
            raise ValueError("Changed payload exceeds limit")
    tail = _decode(recipe["append"])
    if total + len(tail) > MAX_PATCH_BYTES:
        raise ValueError("Total patch payload exceeds limit")
    if recipe["output"]["size"] != IMAGE_SIZE + len(tail):
        raise ValueError("Output size disagrees with appended bytes")
    return recipe


def load_recipe(path):
    return validate_recipe(_json(read_bounded(path, MAX_RECIPE_SIZE)))


def public_metadata(recipe, recipe_sha256):
    validate_recipe(recipe)
    return {"format": 1, "client_version": recipe["client_version"],
            "original_sha256": recipe["original_sha256"],
            "static_image_sha256": recipe["source"]["sha256"],
            "patched_sha256": recipe["output"]["sha256"],
            "patched_size": recipe["output"]["size"],
            "server_ip": recipe["server_ip"], "server_port": recipe["server_port"],
            "recipe_sha256": _hash(recipe_sha256)}


def _canonical(image):
    if len(image) != IMAGE_SIZE or sha256(image) != IMAGE_SHA256:
        raise ValueError("Wrong input: expected canonical UNPACKED image SHA256")


def apply_recipe(image, recipe):
    validate_recipe(recipe)
    _canonical(image)
    output = bytearray(image)
    for row in recipe["spans"]:
        at, data = row["offset"], _decode(row["data"])
        old = image[at:at + len(data)]
        if sha256(old) != row["source_sha256"]:
            raise ValueError("Span source SHA256 mismatch")
        if any(a == b for a, b in zip(old, data)):
            raise ValueError("Span contains unchanged bytes")
        output[at:at + len(data)] = data
    output.extend(_decode(recipe["append"]))
    if len(output) != recipe["output"]["size"] or sha256(output) != recipe["output"]["sha256"]:
        raise ValueError("Output SHA256 mismatch")
    return bytes(output)


def create_recipe(image, patched, build):
    _canonical(image)
    if not IMAGE_SIZE <= len(patched) <= min(MAX_FILE_SIZE, IMAGE_SIZE + MAX_PATCH_BYTES):
        raise ValueError("Invalid patched file size")
    if type(build) is not dict:
        raise ValueError("Invalid build manifest")
    for key, expected in (("original_sha256", ORIGINAL_SHA256),
                          ("static_image_sha256", IMAGE_SHA256), ("patched_sha256", sha256(patched))):
        if _hash(build.get(key)) != expected:
            raise ValueError("Build manifest fingerprint mismatch: " + key)
    if build.get("client_version", CLIENT_VERSION) != CLIENT_VERSION:
        raise ValueError("Unsupported build client_version")
    server_ip = _server(build.get("server_ip"))
    spans, start, changed = [], None, 0
    # Deliberately do not merge across unchanged bytes: no unmodified code ships.
    for at in range(len(image) + 1):
        different = at < len(image) and image[at] != patched[at]
        if different:
            changed += 1
            if changed + len(patched) - len(image) > MAX_PATCH_BYTES:
                raise ValueError("Total patch payload exceeds limit")
            if start is None:
                start = at
        elif start is not None:
            spans.append({"offset": start, "source_sha256": sha256(image[start:at]),
                          "data": base64.b64encode(patched[start:at]).decode("ascii")})
            if len(spans) > MAX_SPANS:
                raise ValueError("Excessive spans")
            start = None
    recipe = {"format": FORMAT, "schema_version": 1, "client_version": CLIENT_VERSION,
              "original_sha256": ORIGINAL_SHA256, "source": {"size": len(image), "sha256": sha256(image)},
              "output": {"size": len(patched), "sha256": sha256(patched)},
              "server_ip": server_ip, "server_port": 12350, "spans": spans,
              "append": base64.b64encode(patched[len(image):]).decode("ascii")}
    validate_recipe(recipe)
    if apply_recipe(image, recipe) != patched:
        raise ValueError("Internal delta reconstruction failed")
    return recipe


def write_new(path, data):
    # Exclusive creation also refuses existing symlinks and source==output.
    with Path(path).open("xb") as stream:
        stream.write(data)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    create = commands.add_parser("create", help="operator: generate public delta from a verified build")
    create.add_argument("--image", type=Path, required=True)
    create.add_argument("--build-dir", type=Path)
    create.add_argument("--patched", type=Path)
    create.add_argument("--build-json", type=Path)
    create.add_argument("--output", type=Path, required=True)
    apply = commands.add_parser("apply", help="reconstruct a verified patched EXE; never launch it")
    apply.add_argument("--image", type=Path, required=True)
    apply.add_argument("--patch", type=Path, required=True)
    apply.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    if args.command == "create":
        if args.build_dir:
            if args.patched or args.build_json:
                parser.error("Use --build-dir OR --patched with --build-json")
            args.patched, args.build_json = args.build_dir / "Skype.exe", args.build_dir / "build.json"
        elif not args.patched or not args.build_json:
            parser.error("create requires --build-dir OR both --patched and --build-json")
        build = _json(read_bounded(args.build_json, MAX_BUILD_JSON_SIZE))
        recipe = create_recipe(read_bounded(args.image, MAX_FILE_SIZE),
                               read_bounded(args.patched, MAX_FILE_SIZE), build)
        data = (json.dumps(recipe, ensure_ascii=True, separators=(",", ":")) + "\n").encode("ascii")
        if len(data) > MAX_RECIPE_SIZE:
            raise ValueError("Recipe exceeds JSON size limit")
        write_new(args.output, data)
    else:
        recipe = load_recipe(args.patch)
        data = apply_recipe(read_bounded(args.image, MAX_FILE_SIZE), recipe)
        write_new(args.output, data)
    print(json.dumps({"sha256": sha256(data), "size": len(data), "status": "created; not launched"}))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError) as error:
        print("ClientPatch: " + str(error), file=sys.stderr)
        sys.exit(1)
