#!/bin/sh
# Rebuild the WebAssembly core used by the local DB web UI.
#
# Requires Emscripten (emcc/em++) on PATH.  SQLite is compiled directly from
# the official amalgamation instead of going through Emscripten's port
# manager: that avoids the port download/cache lock, which fails on systems
# with a frozen cache ("Attempt to lock the cache but FROZEN_CACHE is set").
set -eu
cd "$(dirname "$0")"

SQLITE_VERSION=3540000
SQLITE_YEAR=2026
SQLITE_SHA512="49fabc986547b7f83b238e1fe9705a9cefc403bdecba3e82ce879d204919f3f7ca91b5a91f1880c62105ccffa362eb84265b0efc618facd90429fdb0aa38260b"

SQLITE_DIR="$PWD/.sqlite"
SQLITE_C="$SQLITE_DIR/sqlite3.c"
SQLITE_H="$SQLITE_DIR/sqlite3.h"
STAMP="$SQLITE_DIR/.version"

if [ ! -f "$SQLITE_C" ] || [ ! -f "$SQLITE_H" ] || \
   [ "$(cat "$STAMP" 2>/dev/null || true)" != "$SQLITE_VERSION" ]; then
    echo "downloading SQLite $SQLITE_VERSION amalgamation..."
    mkdir -p "$SQLITE_DIR"
    rm -f "$SQLITE_DIR/sqlite3.c" "$SQLITE_DIR/sqlite3.h" "$SQLITE_DIR/sqlite3.o"
    python3 - "$SQLITE_DIR" "$SQLITE_VERSION" "$SQLITE_YEAR" "$SQLITE_SHA512" <<'PY'
import hashlib
import io
import os
import sys
import urllib.request
import zipfile

out_dir, version, year, expected = sys.argv[1:5]
url = f"https://www.sqlite.org/{year}/sqlite-amalgamation-{version}.zip"
data = urllib.request.urlopen(url, timeout=120).read()
if hashlib.sha512(data).hexdigest() != expected:
    raise SystemExit("SQLite zip checksum mismatch")
with zipfile.ZipFile(io.BytesIO(data)) as archive:
    found = 0
    for name in archive.namelist():
        base = os.path.basename(name)
        if base in ("sqlite3.c", "sqlite3.h"):
            with open(os.path.join(out_dir, base), "wb") as out:
                out.write(archive.read(name))
            found += 1
    if found != 2:
        raise SystemExit("SQLite zip did not contain sqlite3.c/sqlite3.h")
PY
    printf '%s' "$SQLITE_VERSION" > "$STAMP"
fi

mkdir -p static

# SQLite is C, not C++; compile it with emcc before linking the C++ core.
emcc "$SQLITE_C" -c -o "$SQLITE_DIR/sqlite3.o" \
    -I"$SQLITE_DIR" \
    -O3 \
    -DSTDC_HEADERS=1 \
    -DHAVE_SYS_TYPES_H=1 \
    -DHAVE_SYS_STAT_H=1 \
    -DHAVE_STDLIB_H=1 \
    -DHAVE_STRING_H=1 \
    -DHAVE_MEMORY_H=1 \
    -DHAVE_STRINGS_H=1 \
    -DHAVE_INTTYPES_H=1 \
    -DHAVE_STDINT_H=1 \
    -DHAVE_UNISTD_H=1 \
    -DHAVE_FDATASYNC=1 \
    -DHAVE_USLEEP=1 \
    -DHAVE_LOCALTIME_R=1 \
    -DHAVE_GMTIME_R=1 \
    -DHAVE_DECL_STRERROR_R=1 \
    -DHAVE_STRERROR_R=1 \
    -DHAVE_POSIX_FALLOCATE=1 \
    -DSQLITE_OMIT_LOAD_EXTENSION=1 \
    -DSQLITE_OMIT_POPEN=1 \
    -DSQLITE_THREADSAFE=0

em++ core.cpp "$SQLITE_DIR/sqlite3.o" \
    -I"$SQLITE_DIR" \
    -O3 \
    -std=c++17 \
    -sMODULARIZE=1 \
    -sEXPORT_NAME=createCore \
    -sENVIRONMENT=web,node \
    -sALLOW_MEMORY_GROWTH=1 \
    -sINITIAL_MEMORY=64MB \
    -sFORCE_FILESYSTEM=1 \
    -sEXPORTED_FUNCTIONS='["_mc_open","_mc_close","_mc_apply","_mc_sort","_mc_count","_mc_total","_mc_load_ms","_mc_error","_mc_cell","_mc_detail","_mc_ip","_mc_sqlite_version","_malloc","_free"]' \
    -sEXPORTED_RUNTIME_METHODS='["ccall","cwrap","FS","UTF8ToString"]' \
    -o static/core.js

echo "built static/core.js and static/core.wasm (SQLite $SQLITE_VERSION)"
