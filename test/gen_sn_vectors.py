#!/usr/bin/env python3
"""
Emit test/sn_vectors.h from shieldnet-protocol/vectors/shieldnet-v1-vectors.json
and shieldnet-msglayer-vectors.json (message layer Appendix A).

The host C suites have no JSON parser, and the two implementations are
separate git repos, so the vectors cross the boundary as a generated C header of
hex byte arrays, checked in. Regenerating must produce the byte-identical committed
header. Never hand-edit the header.

Run:  python3 test/gen_sn_vectors.py "$SPEC/vectors" > test/sn_vectors.h
(the argument is the spec repository's vectors directory)
"""
import json, sys, os

if len(sys.argv) != 2:
    sys.exit("usage: gen_sn_vectors.py <vectors-dir>")
vdir = sys.argv[1]
j = json.load(open(os.path.join(vdir, "shieldnet-v1-vectors.json")))

def carr(name, hexstr):
    b = bytes.fromhex(hexstr)
    body = ", ".join("0x%02x" % x for x in b)
    return "static const unsigned char %s[%d] = { %s };" % (name, len(b), body)

out = []
out.append("/* Copyright (c) 2025-2026 BlackShield LDA")
out.append(" * SPDX-License-Identifier: Apache-2.0 */")
out.append("/* Generated from shieldnet-protocol/vectors/shieldnet-{v1,msglayer}-vectors.json")
out.append(" * by test/gen_sn_vectors.py. Do not hand-edit. */")
out.append("#ifndef SN_VECTORS_H")
out.append("#define SN_VECTORS_H")
out.append("")
for k, v in j["inputs"].items():
    if isinstance(v, str):
        out.append(carr("sn_in_" + k, v))
out.append("static const unsigned long long sn_in_seq_full = %dULL;" % j["inputs"]["seq_full"])
out.append("static const unsigned long sn_in_kcp_conv = %dUL;" % j["inputs"]["kcp_conv"])
out.append("")
for k, v in j["schedule"].items():
    out.append(carr("sn_want_" + k, v))
out.append("")
for k, v in j["messages"].items():
    out.append(carr("sn_msg_" + k, v))
out.append("")
out.append("struct sn_recon_case { unsigned int seq_wire; unsigned long long hwm; long long candidate; };")
cases = ", ".join("{ 0x%xu, %dULL, %dLL }" % (c["seq_wire"], c["hwm"], c["candidate"]) for c in j["reconstruct"])
out.append("static const struct sn_recon_case sn_recon[%d] = { %s };" % (len(j["reconstruct"]), cases))
out.append("")

# §4.3 / §8.2 tables. Emitted as plain arrays so the header stays dependency-free;
# the C test assembles sn_prefix values from them.
def bytes_rows(name, rows):
    out.append("static const unsigned char %s[%d][16] = {" % (name, len(rows)))
    for r in rows:
        out.append("  { " + ", ".join("0x%02x" % x for x in bytes.fromhex(r)) + " },")
    out.append("};")

def int_row(name, vals, ctype="int"):
    out.append("static const %s %s[%d] = { %s };" % (ctype, name, len(vals), ", ".join(str(v) for v in vals)))

loc = j["source_local"]
bytes_rows("sn_src_local_a16", [p["addr"] for p in loc])
int_row("sn_src_local_is_v4", [1 if p["is_v4"] else 0 for p in loc])
int_row("sn_src_local_bits", [p["bits"] for p in loc])
out.append("#define SN_SRC_LOCAL_N %d" % len(loc))

cs = j["source_cases"]
bytes_rows("sn_src_case_a16", [c["addr"] for c in cs])
int_row("sn_src_case_is_v4", [1 if c["is_v4"] else 0 for c in cs])
int_row("sn_src_case_rejected", [1 if c["rejected"] else 0 for c in cs])
out.append("static const char *const sn_src_case_name[%d] = {" % len(cs))
for c in cs:
    out.append('  "%s",' % c["name"].replace('"', '\\"'))
out.append("};")
out.append("#define SN_SRC_CASE_N %d" % len(cs))

out.append(carr("sn_canon_v4", j["canonical_source"]["v4"]))
out.append(carr("sn_canon_v6", j["canonical_source"]["v6"]))

# §3/§5 wire table. Datagrams vary in length, so they are emitted as one flat
# blob with offsets rather than a ragged 2-D array.
wcs = j["wire_cases"]
blob, offs, lens = bytearray(), [], []
for c in wcs:
    b = bytes.fromhex(c["datagram"])
    offs.append(len(blob)); lens.append(len(b)); blob += b
out.append(carr("sn_wire_blob", blob.hex()))
int_row("sn_wire_off", offs, "unsigned")
int_row("sn_wire_len", lens, "unsigned")
int_row("sn_wire_role", [c["role"] for c in wcs])
int_row("sn_wire_cls", [c["cls"] for c in wcs])
int_row("sn_wire_decodes", [1 if c["decodes"] else 0 for c in wcs])
out.append("static const char *const sn_wire_name[%d] = {" % len(wcs))
for c in wcs:
    out.append('  "%s",' % c["name"].replace('"', '\\"'))
out.append("};")
out.append("#define SN_WIRE_CASE_N %d" % len(wcs))

rp = j["replay_script"]
out.append("static const unsigned long long sn_replay_seq[%d] = { %s };"
           % (len(rp), ", ".join("%dULL" % o["seq"] for o in rp)))
int_row("sn_replay_accept", [1 if o["accept"] else 0 for o in rp])
out.append("#define SN_REPLAY_N %d" % len(rp))

# reconstruct plus the window test (in_range); integers as in sn_recon.
rr = j["reconstruct_range"]
out.append("struct sn_recon_range_case { unsigned int seq_wire; unsigned long long hwm; long long candidate; int in_range; };")
cases = ", ".join("{ 0x%xu, %dULL, %dLL, %d }" % (c["seq_wire"], c["hwm"], c["candidate"], 1 if c["in_range"] else 0) for c in rr)
out.append("static const struct sn_recon_range_case sn_recon_range[%d] = { %s };" % (len(rr), cases))
out.append("#define SN_RECON_RANGE_N %d" % len(rr))

# Datagram lengths the envelope size check accepts or drops.
es = j["envelope_size"]
out.append("static const unsigned sn_envelope_size_wire_mtu = %du;" % es["wire_mtu"])
int_row("sn_envelope_size_len", [c["len"] for c in es["cases"]], "unsigned")
int_row("sn_envelope_size_accept", [1 if c["accept"] else 0 for c in es["cases"]])
out.append("#define SN_ENVELOPE_SIZE_N %d" % len(es["cases"]))
out.append("")

# Message layer Appendix A. Plaintexts and frames vary in length (and the
# `padded` plaintext is empty), so each goes in one blob with offsets.
ml = json.load(open(os.path.join(vdir, "shieldnet-msglayer-vectors.json")))
mcs = ml["cases"]
out.append(carr("sn_ml_key", ml["key"]))
out.append("static const char *const sn_ml_name[%d] = {" % len(mcs))
for c in mcs:
    out.append('  "%s",' % c["name"].replace('"', '\\"'))
out.append("};")
out.append("static const unsigned long sn_ml_type[%d] = { %s };"
           % (len(mcs), ", ".join("0x%xUL" % int(c["message_type"], 16) for c in mcs)))
out.append("static const unsigned long long sn_ml_num[%d] = { %s };"
           % (len(mcs), ", ".join("0x%xULL" % int(c["message_num"], 16) for c in mcs)))
for field in ("plaintext", "frame"):
    blob, offs, lens = bytearray(), [], []
    for c in mcs:
        b = bytes.fromhex(c[field])
        offs.append(len(blob)); lens.append(len(b)); blob += b
    out.append(carr("sn_ml_%s_blob" % field, blob.hex()))
    int_row("sn_ml_%s_off" % field, offs, "unsigned")
    int_row("sn_ml_%s_len" % field, lens, "unsigned")
out.append("#define SN_ML_CASE_N %d" % len(mcs))
out.append("")
out.append("#endif")
sys.stdout.write("\n".join(out) + "\n")
