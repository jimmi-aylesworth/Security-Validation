#!/usr/bin/env bash
#
# rust_utf16.sh
#
# Encode or decode Rust UTF-16 u16 arrays commonly used for Windows API
# strings (CreateMutexW, CreateFileW, RegOpenKeyExW, etc.).
#
# Examples
# --------
#
# Encode a string:
#
#   ./rust_utf16.sh -e "Global\\MyPrograms_Mutex_1252"
#
# Decode a Rust array:
#
#   ./rust_utf16.sh -d '[
#       0x0047,0x006C,0x006F,0x0062,
#       0x0061,0x006C,0x005C,0x0000
#   ]'
#
# Decode a file:
#
#   cat mutex.txt | ./rust_utf16.sh --decode
#
# Encode without a NULL terminator:
#
#   ./rust_utf16.sh -e --no-null "Hello"
#

set -euo pipefail

NULL_TERMINATE=1

usage() {
cat <<EOF
Usage:
  $(basename "$0") [OPTIONS] <data>

Modes (choose one):
  -e, --encode      Encode UTF-8 text into a Rust UTF-16 array
  -d, --decode      Decode a Rust UTF-16 array into UTF-8 text

Options:
  --no-null         Do not append a UTF-16 NULL terminator when encoding
  -h, --help        Show this help

Input
-----

Encode expects a normal UTF-8 string.

Decode accepts any of the following:

  [0x0048, 0x0065, 0x006C, 0x006C, 0x006F, 0x0000]

or

  0x0048,0x0065,0x006C

or

  0048 0065 006C

The decoder ignores:

  - brackets
  - commas
  - whitespace
  - semicolons
  - "const ..." Rust declarations

The first 0x0000 encountered terminates decoding.

Examples
--------

Encode:

  $(basename "$0") -e "Hello"

Decode:

  $(basename "$0") -d '[0x0048,0x0065,0x006C,0x006C,0x006F,0x0000]'

Pipe input:

  cat array.txt | $(basename "$0") -d

EOF
}

MODE=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        -e|--encode)
            MODE="encode"
            shift
            ;;
        -d|--decode)
            MODE="decode"
            shift
            ;;
        --no-null)
            NULL_TERMINATE=0
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            break
            ;;
    esac
done

[[ -z "$MODE" ]] && {
    echo "Error: specify either --encode or --decode." >&2
    usage
    exit 1
}

# Remaining argument, or stdin if none.
if [[ $# -gt 0 ]]; then
    INPUT="$*"
else
    INPUT="$(cat)"
fi

if [[ "$MODE" == "encode" ]]; then

python3 - "$INPUT" "$NULL_TERMINATE" <<'PY'
import sys

text = sys.argv[1]
nullterm = sys.argv[2] == "1"

utf16 = text.encode("utf-16le")

values = []

for i in range(0, len(utf16), 2):
    code = utf16[i] | (utf16[i+1] << 8)
    values.append(f"0x{code:04X}")

if nullterm:
    values.append("0x0000")

print("[")
for i,v in enumerate(values):
    comma = "," if i != len(values)-1 else ""
    print(f"    {v}{comma}")
print("]")
PY

else

python3 - "$INPUT" <<'PY'
import re
import sys

text = sys.argv[1]

#
# Extract every hexadecimal value.
#
# This works for:
#
#   0x0048
#   0048
#
tokens = re.findall(r'(?:0x)?([0-9A-Fa-f]{4})', text)

if not tokens:
    sys.exit("No UTF-16 values found.")

buf = bytearray()

for tok in tokens:
    value = int(tok,16)

    #
    # Windows UTF-16 strings are conventionally
    # NULL terminated.
    #
    if value == 0:
        break

    buf.extend(value.to_bytes(2,"little"))

print(buf.decode("utf-16le"))
PY

fi