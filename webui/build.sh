#!/bin/sh
# Rebuild the WebAssembly core used by the local DB web UI.
# Requires Emscripten (emcc) on PATH.
set -eu
cd "$(dirname "$0")"

mkdir -p static

em++ core.cpp \
    -O3 \
    -std=c++17 \
    -sUSE_SQLITE3=1 \
    -sMODULARIZE=1 \
    -sEXPORT_NAME=createCore \
    -sENVIRONMENT=web,node \
    -sALLOW_MEMORY_GROWTH=1 \
    -sINITIAL_MEMORY=64MB \
    -sFORCE_FILESYSTEM=1 \
    -sEXPORTED_FUNCTIONS='["_mc_open","_mc_close","_mc_apply","_mc_sort","_mc_count","_mc_total","_mc_load_ms","_mc_error","_mc_cell","_mc_detail","_mc_ip","_mc_sqlite_version","_malloc","_free"]' \
    -sEXPORTED_RUNTIME_METHODS='["ccall","cwrap","FS","UTF8ToString"]' \
    -o static/core.js

echo "built static/core.js and static/core.wasm"
