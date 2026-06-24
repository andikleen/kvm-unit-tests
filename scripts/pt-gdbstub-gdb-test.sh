#!/usr/bin/env bash
#
# Intel Processor Trace gdbstub test — GDB-based version
#
# Tests PT recording by sending RSP packets through GDB's own
# RemoteTargetConnection.send_packet() API instead of raw sockets.
# The test includes a disconnect/reconnect sequence via GDB's own
# CLI (disconnect + target remote) to verify cleanup state.
#
# Requires Intel PT hardware and a QEMU with PT gdbstub support.
#
# Usage:
#   QEMU=/path/to/qemu-system-x86_64 ./scripts/pt-gdbstub-gdb-test.sh
#
# Exit codes:
#   0  = all tests passed
#   1  = some tests failed
#   77 = skipped (no PT hardware)
#

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
KUT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

: "${QEMU:=qemu-system-x86_64}"
: "${GDB:=gdb}"
: "${TEST_BINARY:=$KUT_DIR/x86/sieve.flat}"
: "${ACCEL:=kvm}"

PASSED=0
FAILED=0
SELF="pt-gdbstub-gdb"

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

do_test() {
    local cpu_model="$1"
    local extra_desc="$2"
    local gdb_port
    gdb_port=$(find_port)
    local qemu_out=$(mktemp /tmp/pt-qemu-XXXX.out)
    local gdb_out=$(mktemp /tmp/pt-gdb-XXXX.out)

    # Use -S to suspend QEMU at the reset vector so the CPU state is
    # deterministic when GDB connects.  Raw RSP 's' packets (via
    # send_packet) work from any PC.
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

    $GDB -batch -nx -q \
        -ex "set pagination off" \
        -ex "set confirm off" \
        -ex "target remote :$gdb_port" \
        -x "$SCRIPT_DIR/pt-gdbstub-gdb.py" \
        > "$gdb_out" 2>&1 || true

    kill "$qemu_pid" 2>/dev/null || true
    wait "$qemu_pid" 2>/dev/null || true

    if grep -q "ALL_PASS" "$gdb_out"; then
        pass "$extra_desc"
    else
        local fails=$(grep "^FAIL:" "$gdb_out" | head -5 | tr '\n' '; ')
        fail "$extra_desc: $fails"
    fi

    cat "$gdb_out"
    rm -f "$qemu_out" "$gdb_out"
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
# Tests — run two CPU model variants:
#   host    : guest PT CPUID visible  (e.g. -cpu host)
#   qemu64  : guest PT CPUID hidden   (default x86_64 CPU model)
#
do_test "host"   "PT capture via GDB (guest PT visible)"
do_test "qemu64" "PT capture via GDB (guest PT hidden)"

#
# Summary
#
if [ $FAILED -eq 0 ]; then
    echo "SUMMARY: $SELF: $PASSED tests"
else
    echo "SUMMARY: $SELF: $PASSED tests, $FAILED failures"
fi

exit $(( FAILED > 0 ? 1 : 0 ))
