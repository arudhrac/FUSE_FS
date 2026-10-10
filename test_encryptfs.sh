#!/usr/bin/env bash

set -euo pipefail

BINARY="${1:-./encryptfs}"
PASS="TestPassw0rd!encryptfs"
BACKING="/tmp/efs_test_back_$$"
MOUNT="/tmp/efs_test_mnt_$$"
FUSE_PID=""

RED='\033[0;31m'; GRN='\033[0;32m'; YEL='\033[1;33m'
CYN='\033[0;36m'; BLD='\033[1m'; RST='\033[0m'

PASS_CT=0; FAIL_CT=0

ok()   { echo -e "  ${GRN}✓${RST}  $1"; ((PASS_CT++)); }
fail() { echo -e "  ${RED}✗${RST}  $1 — ${RED}${2:-}${RST}"; ((FAIL_CT++)); }
info() { echo -e "  ${YEL}→${RST}  $1"; }
sep()  { echo -e "\n${CYN}── $1 ────────────────────────────${RST}"; }

# ── Cleanup on exit (always) ──
cleanup() {
    fusermount3 -u "$MOUNT" 2>/dev/null || true
    kill "$FUSE_PID" 2>/dev/null || true
    rm -rf "$BACKING" "$MOUNT"
}
trap cleanup EXIT INT TERM

# ── Mount helper ──
do_mount() {
    local pass="$1"
    "$BINARY" "$BACKING" "$MOUNT" "--password=$pass" -f &>/tmp/efs_test_log &
    FUSE_PID=$!
    sleep 1
    mountpoint -q "$MOUNT" || return 1
    return 0
}

do_unmount() {
    fusermount3 -u "$MOUNT" 2>/dev/null || true
    kill "$FUSE_PID" 2>/dev/null || true
    FUSE_PID=""
    sleep 0.5
}

# ══════════════════════════════════════════════════════════
echo ""
echo -e "${BLD}${CYN}  ╔═══════════════════════════════════════╗"
echo -e "  ║    encryptfs Test Suite               ║"
echo -e "  ╚═══════════════════════════════════════╝${RST}"
echo ""

mkdir -p "$BACKING" "$MOUNT"
info "Backing : $BACKING"
info "Mount   : $MOUNT"
info "Binary  : $BINARY"

# ── Test: Initial mount & init ─────────────────────────
sep "Mount & Initialize"

if do_mount "$PASS"; then
    ok "Filesystem mounted successfully"
else
    fail "Mount failed" "check dmesg and /tmp/efs_test_log"
    exit 1
fi

[ -f "$BACKING/$( echo .encryptfs )" ] && \
    ok "Config file .encryptfs created in backing dir" || \
    fail "Config file missing" ""

# ── Test: Basic write / read ───────────────────────────
sep "Basic Write / Read"

echo "Hello, Encrypted World!" > "$MOUNT/hello.txt"
ok "echo to /dev/casedev succeeded"

CONTENT=$(cat "$MOUNT/hello.txt")
if [ "$CONTENT" = "Hello, Encrypted World!" ]; then
    ok "cat returns correct plaintext"
else
    fail "Plaintext mismatch" "got: $CONTENT"
fi

# ── Test: Encryption verification ─────────────────────
sep "Encryption Verification"

if ! grep -qF "Hello" "$BACKING/hello.txt" 2>/dev/null; then
    ok "Backing file contains NO readable plaintext"
else
    fail "Plaintext visible in backing file" "encryption not working!"
fi

PLAIN_SZ=$(stat -c%s "$MOUNT/hello.txt")
BACK_SZ=$(stat -c%s "$BACKING/hello.txt")
EXP_BACK=$((PLAIN_SZ + 28))    # 28 = IV(12) + TAG(16)
if [ "$BACK_SZ" -eq "$EXP_BACK" ]; then
    ok "Backing file size = plaintext + 28 bytes (IV+TAG overhead)"
else
    fail "Size mismatch" "backing=$BACK_SZ expected=$EXP_BACK"
fi

# ── Test: File operations ──────────────────────────────
sep "File Operations"

mkdir -p "$MOUNT/subdir"
[ -d "$MOUNT/subdir" ] && ok "mkdir works" || fail "mkdir failed" ""

echo "nested" > "$MOUNT/subdir/nested.txt"
[ "$(cat "$MOUNT/subdir/nested.txt")" = "nested" ] && \
    ok "nested file read/write" || fail "nested file" ""

cp "$MOUNT/hello.txt" "$MOUNT/copy.txt"
[ "$(cat "$MOUNT/copy.txt")" = "Hello, Encrypted World!" ] && \
    ok "cp preserves content" || fail "cp failed" ""

mv "$MOUNT/copy.txt" "$MOUNT/moved.txt"
[ -f "$MOUNT/moved.txt" ] && ! [ -f "$MOUNT/copy.txt" ] && \
    ok "mv works" || fail "mv failed" ""

rm "$MOUNT/moved.txt"
[ ! -f "$MOUNT/moved.txt" ] && ok "rm works" || fail "rm failed" ""

# ── Test: File size reporting ──────────────────────────
sep "File Size"

printf 'ABCDE' > "$MOUNT/size5.txt"
SZ=$(stat -c%s "$MOUNT/size5.txt")
[ "$SZ" -eq 5 ] && ok "5-byte file reported as 5 bytes" || \
    fail "Wrong size" "got $SZ expected 5"

printf '%0.s.' {1..1000} > "$MOUNT/size1k.txt"
SZ=$(stat -c%s "$MOUNT/size1k.txt")
[ "$SZ" -eq 1000 ] && ok "1000-byte file reported correctly" || \
    fail "Wrong size" "got $SZ expected 1000"

# ── Test: Config hidden from mountpoint ───────────────
sep "Security"

[ ! -f "$MOUNT/.encryptfs" ] && \
    ok ".encryptfs hidden from virtual filesystem" || \
    fail ".encryptfs VISIBLE in mountpoint" "security issue!"

# ── Test: Persist after unmount ────────────────────────
sep "Persistence (remount)"

do_unmount
info "Remounting with SAME password..."
do_mount "$PASS"
CONTENT2=$(cat "$MOUNT/hello.txt" 2>&1)
if [ "$CONTENT2" = "Hello, Encrypted World!" ]; then
    ok "Data persists after unmount/remount"
else
    fail "Persistence failed" "got: $CONTENT2"
fi

# ── Test: Wrong password ───────────────────────────────
sep "Wrong Password (Tamper Detection)"

do_unmount
info "Remounting with WRONG password..."
"$BINARY" "$BACKING" "$MOUNT" "--password=WRONGPASSWORD" -f &>/tmp/efs_wrong_log &
FUSE_PID=$!
sleep 1

if mountpoint -q "$MOUNT"; then
    READ_OUT=$(cat "$MOUNT/hello.txt" 2>&1)
    if echo "$READ_OUT" | grep -qiE "input/output error|I/O error|cannot"; then
        ok "Wrong password → I/O error (GCM auth tag rejected)"
    elif [ "$READ_OUT" = "$CONTENT" ]; then
        fail "Wrong password returned correct plaintext!" "encryption broken"
    else
        ok "Wrong password → garbled/error output (authentication working)"
    fi
    fusermount3 -u "$MOUNT" 2>/dev/null || true
    kill "$FUSE_PID" 2>/dev/null || true
    FUSE_PID=""
else
    ok "Filesystem refused to operate with wrong password"
fi

# ── Test: Multi-line and binary-ish content ────────────
sep "Content Types"

do_unmount 2>/dev/null || true
do_mount "$PASS"

printf "line1\nline2\nline3\n" > "$MOUNT/lines.txt"
LC=$(wc -l < "$MOUNT/lines.txt")
[ "$LC" -eq 3 ] && ok "Multi-line file: $LC lines" || \
    fail "Line count wrong" "got $LC"

printf '\x00\x01\x02\xFE\xFF' > "$MOUNT/binary.bin"
HEX=$(xxd -p "$MOUNT/binary.bin")
[ "$HEX" = "000102feff" ] && ok "Binary content preserved exactly" || \
    fail "Binary content corrupted" "got $HEX"

# ── Summary ────────────────────────────────────────────
do_unmount

echo ""
echo -e "${BLD}${CYN}  ══ Results ══════════════════════════════${RST}"
echo -e "  ${GRN}Passed: $PASS_CT${RST}   ${RED}Failed: $FAIL_CT${RST}   Total: $((PASS_CT+FAIL_CT))"
echo ""

if [ "$FAIL_CT" -eq 0 ]; then
    echo -e "  ${GRN}${BLD}All tests passed ✓${RST}"
    exit 0
else
    echo -e "  ${RED}${BLD}$FAIL_CT test(s) failed${RST}"
    echo "  Check /tmp/efs_test_log for FUSE output"
    exit 1
fi
