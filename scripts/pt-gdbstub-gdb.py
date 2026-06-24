#
# Intel Processor Trace (PT) gdbstub test — GDB Python API version
#
# Tests PT recording by sending RSP packets through GDB's own
# RemoteTargetConnection.send_packet(), not via raw sockets.
# Designed for kvm-unit-tests sieve.flat under QEMU with gdbstub.
#

import gdb
import sys

PASSED = 0
FAILED = 0

def report(cond, msg):
    global PASSED, FAILED
    if cond:
        print("PASS: pt-gdbstub-gdb %s" % msg)
        PASSED += 1
    else:
        print("FAIL: pt-gdbstub-gdb %s" % msg)
        FAILED += 1

def rsp(cmd):
    conn = gdb.selected_inferior().connection
    return conn.send_packet(cmd.encode()).decode()

def qxfer_read(annex, max_size=16000):
    """Read a qXfer object, handling chunked transfers."""
    all_data = bytearray()
    offset = 0
    while True:
        raw = rsp("qXfer:btrace:read:%s:%d,%d" % (annex, offset, max_size))
        if not raw:
            break
        prefix = raw[0]
        body = raw[1:]
        all_data.extend(body.encode() if isinstance(body, str) else body)
        if prefix == 'l':
            break
        if prefix != 'm':
            break
        offset += max_size
    return all_data.decode()

try:
    print("  connected, pc = 0x%x" % int(gdb.selected_frame().pc()))

    # T1: Qbtrace:pt — start PT recording
    r = rsp("Qbtrace:pt")
    report(r == "OK", "T1: Qbtrace:pt -> %s" % r)
    if r != "OK":
        sys.exit(1)

    # T2: Single-step 10 times to generate trace
    for i in range(10):
        stop = rsp("s")
        if not stop.startswith("T"):
            report(False, "T2: step %d bad stop reply: %s" % (i, stop[:30]))
            sys.exit(1)
    report(True, "T2: stepped 10 instructions")

    # T3: Read PT trace data (full chunked read)
    xml = qxfer_read("all")
    if "<raw>" in xml and "</raw>" in xml:
        raw = xml[xml.index("<raw>")+5:xml.index("</raw>")].strip()
        raw_bytes = len([b for b in raw.split() if b])
        report(raw_bytes > 0, "T3: btrace:all raw = %d hex bytes" % raw_bytes)
    else:
        report(False, "T3: no <raw> element in btrace XML")

    # T4: Qbtrace:off — stop recording (but keep buffers)
    r = rsp("Qbtrace:off")
    report(r == "OK", "T4: Qbtrace:off -> %s" % r)

    # T5: Read trace AFTER stop (buffers survive, not freed)
    xml2 = qxfer_read("all")
    if "<raw>" in xml2 and "</raw>" in xml2:
        report(True, "T5: post-stop buffer accessible (valid XML)")
    else:
        report(False, "T5: post-stop buffer not accessible")

    # T6: Verify CPU info in the XML
    if "<cpu vendor=" in xml:
        report(True, "T6: CPU info present in btrace XML")
    else:
        report(False, "T6: no CPU info")

    # T7: Re-enable Qbtrace:pt (disable → re-enable cycle)
    r = rsp("Qbtrace:pt")
    report(r == "OK", "T7: Qbtrace:pt (re-enable) -> %s" % r)
    if r != "OK":
        sys.exit(1)

    # T8: Step and read trace after re-enable
    for i in range(5):
        stop = rsp("s")
        if not stop.startswith("T"):
            report(False, "T8: step %d after re-enable bad reply: %s" % (i, stop[:30]))
            sys.exit(1)
    xml3 = qxfer_read("all")
    if "<raw>" in xml3 and "</raw>" in xml3:
        raw3 = xml3[xml3.index("<raw>")+5:xml3.index("</raw>")].strip()
        raw3_bytes = len([b for b in raw3.split() if b])
        report(raw3_bytes > 0, "T8: re-enabled trace raw = %d hex bytes" % raw3_bytes)
    else:
        report(False, "T8: re-enabled trace no <raw> element")
        sys.exit(1)

    # T9: Re-enabled trace has different content from first session
    # (new AUX buffer was allocated; trace data captures different
    # instruction flow at a different PC)
    old_raw = xml[xml.index("<raw>")+5:xml.index("</raw>")].strip()
    report(old_raw != raw3, "T9: re-enabled trace differs from first session")

    # T10: Final Qbtrace:off
    r = rsp("Qbtrace:off")
    report(r == "OK", "T10: Qbtrace:off (final) -> %s" % r)

    print("")
    if FAILED == 0:
        print("ALL_PASS: pt-gdbstub-gdb: %d tests" % PASSED)
    else:
        print("SOME_FAIL: pt-gdbstub-gdb: %d pass, %d fail" % (PASSED, FAILED))

except gdb.error as e:
    report(False, "unexpected error: %s" % str(e))
    sys.exit(1)
