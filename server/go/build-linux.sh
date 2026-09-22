#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
OUT="$ROOT/server/go/bin"
SRC="$ROOT/skypeopensource2/skyauth4_dll/skyauth4_dll/skype"
mkdir -p "$OUT"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

cp "$SRC/skype_basics.h" "$TMP/"
sed -E 's/__asm[[:space:]]+int[[:space:]]+3/abort()/g' "$SRC/pack-4142.c" > "$TMP/pack-4142.c"
sed -E 's/__asm[[:space:]]+int[[:space:]]+3/abort()/g' "$SRC/unpack-4142.c" > "$TMP/unpack-4142.c"

if ! printf 'int main(void){return 0;}\n' | gcc -m32 -x c - -o "$TMP/probe" >/dev/null 2>&1; then
  echo "32-bit GCC runtime is required for the isolated 0x42 worker." >&2
  echo "Debian/Ubuntu: sudo apt install gcc-multilib libc6-dev-i386" >&2
  exit 1
fi

gcc -m32 -O2 -fno-strict-aliasing -Wno-pointer-to-int-cast -Wno-int-to-pointer-cast   -I"$TMP" "$ROOT/server/native/skype_blob_worker_linux.c" -o "$OUT/skype_blob_worker"

cd "$ROOT/server/go"
CGO_ENABLED=1 go build -trimpath -ldflags="-s -w" -o "$OUT/openskyserver" ./cmd/openskyserver
echo "Built:"
file "$OUT/openskyserver" "$OUT/skype_blob_worker"
