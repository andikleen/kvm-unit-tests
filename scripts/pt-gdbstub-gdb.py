#
# Intel Processor Trace (PT) gdbstub test — GDB Python API version
#
# Tests PT recording by sending RSP packets through GDB's own
# RemoteTargetConnection.send_packet(), not via raw sockets.
# Covers: enable, step, read, disable, re-enable cycles, and
# btrace-conf state verification (active → <pt> present,
# inactive → <pt> absent, proving cleanup cleared the session).
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

def qxfer_conf_read(max_size=2000):
    all_data = bytearray()
    offset = 0
    while True:
        raw = rsp("qXfer:btrace-conf:read::%d,%d" % (offset, max_size))
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

def conf_has_pt():
    """True if btrace-conf contains a <pt> element."""
    return "<pt>" in qxfer_conf_read()

def step_n(n):
    for i in range(n):
        stop = rsp("s")
        if not stop.startswith("T"):
            return False
    return True

def read_trace():
    """Read btrace:all and return (xml, raw_hex_str_or_none)."""
    xml = qxfer_read("all")
    if "<raw>" in xml and "</raw>" in xml:
        raw = xml[xml.index("<raw>")+5:xml.index("</raw>")].strip()
        return xml, raw
    return xml, None

try:
    print("  connected, pc = 0x%x" % int(gdb.selected_frame().pc()))

    # === First enable cycle ===
    # T1: Enable PT
    r = rsp("Qbtrace:pt")
    report(r == "OK", "T1: Qbtrace:pt -> %s" % r)
    if r != "OK":
        sys.exit(1)

    # T2: btrace-conf shows <pt> (active)
    report(conf_has_pt(), "T2: btrace-conf has <pt> while active")

    # T3: Step and read trace
    if not step_n(10):
        report(False, "T3: step failed"); sys.exit(1)
    report(True, "T3: stepped 10 instructions")
    xml1, raw1 = read_trace()
    if raw1 is not None:
        raw1_bytes = len([b for b in raw1.split() if b])
        report(raw1_bytes > 0, "T3: trace raw = %d hex bytes" % raw1_bytes)
    else:
        report(False, "T3: no <raw> element"); sys.exit(1)

    # === Disable and verify cleanup ===
    # T4: Qbtrace:off
    r = rsp("Qbtrace:off")
    report(r == "OK", "T4: Qbtrace:off -> %s" % r)

    # T5: Double Qbtrace:off (idempotent)
    r = rsp("Qbtrace:off")
    report(r == "OK", "T5: Qbtrace:off (double) -> %s" % r)

    # T6: btrace-conf has NO <pt> (session cleaned up)
    report(not conf_has_pt(), "T6: no <pt> after Qbtrace:off (cleanup ok)")

    # T7: Post-stop buffer still accessible (not freed)
    xml1b, _ = read_trace()
    report("<raw>" in xml1b, "T7: post-stop buffer accessible")

    # === Re-enable cycle ===
    # T8: Re-enable Qbtrace:pt
    r = rsp("Qbtrace:pt")
    report(r == "OK", "T8: Qbtrace:pt (re-enable) -> %s" % r)
    if r != "OK":
        sys.exit(1)

    # T9: btrace-conf has <pt> again
    report(conf_has_pt(), "T9: btrace-conf has <pt> after re-enable")

    # T10: Step and read re-enabled trace
    if not step_n(5):
        report(False, "T10: step failed"); sys.exit(1)
    report(True, "T10: stepped 5 instructions (re-enabled)")
    xml2, raw2 = read_trace()
    if raw2 is not None:
        raw2_bytes = len([b for b in raw2.split() if b])
        report(raw2_bytes > 0, "T10: re-enabled trace raw = %d hex bytes" % raw2_bytes)
    else:
        report(False, "T10: no <raw> element"); sys.exit(1)

    # T11: Re-enabled trace differs from first (new buffer)
    report(raw1 != raw2, "T11: re-enabled trace differs from first session")

    # === Second full cycle (proves multiple cycles work) ===
    # T12: Qbtrace:off → Qbtrace:pt → step → read → off
    r = rsp("Qbtrace:off")
    report(r == "OK", "T12a: Qbtrace:off (cycle 2) -> %s" % r)
    r = rsp("Qbtrace:pt")
    report(r == "OK", "T12b: Qbtrace:pt (cycle 2) -> %s" % r)
    if r != "OK":
        sys.exit(1)
    if not step_n(3):
        report(False, "T12c: step failed (cycle 2)"); sys.exit(1)
    report(True, "T12c: stepped 3 instructions (cycle 2)")
    xml3, raw3 = read_trace()
    if raw3 is not None:
        raw3_bytes = len([b for b in raw3.split() if b])
        report(raw3_bytes > 0, "T12d: cycle 2 trace raw = %d hex bytes" % raw3_bytes)
    else:
        report(False, "T12d: no <raw> element (cycle 2)"); sys.exit(1)
    r = rsp("Qbtrace:off")
    report(r == "OK", "T12e: Qbtrace:off (cycle 2) -> %s" % r)

    # T13: Final cleanup verified
    report(not conf_has_pt(), "T13: no <pt> after final Qbtrace:off")

    # T14: CPU info present in trace XML
    report("<cpu vendor=" in xml1, "T14: CPU info in trace XML")

    print("")
    if FAILED == 0:
        print("ALL_PASS: pt-gdbstub-gdb: %d tests" % PASSED)
    else:
        print("SOME_FAIL: pt-gdbstub-gdb: %d pass, %d fail" % (PASSED, FAILED))

except gdb.error as e:
    report(False, "unexpected error: %s" % str(e))
    sys.exit(1)
