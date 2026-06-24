#!/usr/bin/env bash
#
# Intel Processor Trace gdbstub test suite
#
# Tests the QEMU gdbstub Intel PT remote protocol by running a
# kvm-unit-test binary (sieve.flat) under QEMU and driving the
# gdbstub via raw RSP packets.  Requires Intel PT hardware.
#
# Usage:
#   QEMU=/path/to/qemu-system-x86_64 ./scripts/pt-gdbstub-test.sh
#
# Exit codes (kvm-unit-tests convention):
#   0  = all tests passed
#   1  = some tests failed
#   77 = skipped (no PT hardware)
#

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
KUT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

: "${QEMU:=qemu-system-x86_64}"
: "${TEST_BINARY:=$KUT_DIR/x86/sieve.flat}"
: "${ACCEL:=kvm}"

PASSED=0
FAILED=0

SELF="pt-gdbstub"

pass() { echo "PASS: $SELF $1"; PASSED=$((PASSED + 1)); }
fail() { echo "FAIL: $SELF $1"; FAILED=$((FAILED + 1)); }
skip() { echo "SKIP: $SELF $1"; }

find_port() {
    python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(('', 0))
print(s.getsockname()[1])
s.close()
"
}

do_pt_test() {
    local cpu_model="$1"
    local extra_desc="$2"
    local gdb_port
    gdb_port=$(find_port)
    local qemu_out=$(mktemp /tmp/pt-qemu-XXXX.out)
    local pt_raw=$(mktemp /tmp/pt-raw-XXXX.txt)
    local py_out=$(mktemp /tmp/pt-py-XXXX.out)

    $QEMU \
        --no-reboot -nodefaults \
        -global kvm-pit.lost_tick_policy=discard \
        -device pc-testdev \
        -device isa-debug-exit,iobase=0xf4,iosize=0x4 \
        -display none -serial stdio \
        -machine accel=$ACCEL -cpu "$cpu_model" -smp 1 \
        -kernel "$TEST_BINARY" \
        -gdb tcp::"$gdb_port" -S \
        > "$qemu_out" 2>&1 &
    local qemu_pid=$!
    sleep 2

    python3 -c "
import socket, time, sys

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(10)
try:
    s.connect(('127.0.0.1', $gdb_port))
except Exception as e:
    print('FAIL: connect error: %s' % e)
    sys.exit(1)

def rsp(cmd):
    csum = sum(ord(c) for c in cmd) % 256
    s.send(('\$' + cmd + '#%02x' % csum).encode())
    while True:
        b = s.recv(1)
        if b == b'+' or b == b'\x03': continue
        if b == b'\$': break
    resp = b''
    while True:
        ch = s.recv(1)
        if ch == b'#': break
        resp += ch
    s.send(b'+')
    return resp.decode()

ok = True

# T1: Qbtrace:pt
r = rsp('Qbtrace:pt')
if r == 'OK':
    print('PASS: $SELF T1: Qbtrace:pt')
else:
    print('FAIL: $SELF T1: Qbtrace:pt -> ' + r)
    ok = False

# T2: qXfer:btrace-conf:read
r = rsp('qXfer:btrace-conf:read::0,1000')
if '<pt>' in r and '<size>' in r:
    print('PASS: $SELF T2: btrace-conf xml')
else:
    print('FAIL: $SELF T2: btrace-conf -> ' + repr(r[:100]))
    ok = False

# T3: Single-step to generate trace
for i in range(5):
    r = rsp('s')
    if not r.startswith('T'):
        print('FAIL: $SELF T3: step %d -> %s' % (i, r[:30]))
        ok = False

if ok:
    print('PASS: $SELF T3: stepped 5 instructions')

# T4: Read PT trace data
r = rsp('qXfer:btrace:read:all:0,8000')
if r[0] in ('l','m'):
    xml = r[1:]
    if '<raw>' in xml and '</raw>' in xml:
        raw = xml[xml.index('<raw>')+5:xml.index('</raw>')].strip()
        raw_len = len(raw)
        if raw_len > 0:
            print('PASS: $SELF T4: PT data = %d chars' % raw_len)
            with open('$pt_raw', 'w') as f:
                f.write(raw)
        else:
            print('FAIL: $SELF T4: empty raw data')
            ok = False
    else:
        print('FAIL: $SELF T4: no raw element')
        ok = False
else:
    print('FAIL: $SELF T4: btrace:all -> ' + r[:80])
    ok = False

# T5: Qbtrace:off
r = rsp('Qbtrace:off')
if r == 'OK':
    print('PASS: $SELF T5: Qbtrace:off')
else:
    print('FAIL: $SELF T5: Qbtrace:off -> ' + r)
    ok = False

if ok:
    print('ALL_PASS')
else:
    print('SOME_FAIL')

s.close()
" 2>&1 | tee "$py_out"

    kill "$qemu_pid" 2>/dev/null || true
    wait "$qemu_pid" 2>/dev/null || true

    if grep -q "ALL_PASS" "$py_out"; then
        local raw_len=0
        [ -f "$pt_raw" ] && raw_len=$(wc -c < "$pt_raw")
        pass "$extra_desc: PT capture OK ($raw_len bytes)"
    else
        local fails=$(grep "^FAIL: $SELF" "$py_out" | head -3 | tr '\n' '; ')
        fail "$extra_desc: $fails"
    fi

    rm -f "$qemu_out" "$pt_raw" "$py_out"
}

#
# Pre-flight checks
#
"$QEMU" --version > /dev/null 2>&1 || {
    echo "FAIL: $SELF QEMU not found: $QEMU"
    exit 1
}

if [ ! -f "$TEST_BINARY" ]; then
    echo "FAIL: $SELF test binary not found: $TEST_BINARY"
    echo "  Run 'make' in kvm-unit-tests first."
    exit 1
fi

if [ ! -f /sys/bus/event_source/devices/intel_pt/type ]; then
    skip "No Intel PT hardware on this host"
    exit 77
fi

#
# Tests
#
do_pt_test "qemu64" "PT capture (guest PT hidden)"
do_pt_test "host"   "PT capture (guest PT visible)"

#
# Summary
#
if [ $FAILED -eq 0 ]; then
    # kvm-unit-tests SUMMARY: line format
    echo "SUMMARY: $SELF: $PASSED tests"
else
    echo "SUMMARY: $SELF: $PASSED tests, $FAILED failures"
fi

exit $(( FAILED > 0 ? 1 : 0 ))
