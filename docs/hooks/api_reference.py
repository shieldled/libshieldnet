# Copyright (c) 2025-2026 BlackShield LDA
# SPDX-License-Identifier: Apache-2.0
"""MkDocs hook: generate the API reference from the public headers, and point
the examples page's file links at the sources shown on that page.

Every header in include/shieldnet/ and port/ becomes one page under api/, built
at documentation-build time, so the reference cannot drift from the code. A page
shows the header's overview, a summary table, and every declaration verbatim
with the comment above it, in file order. api/index.md lists the headers by
area and every symbol A-Z.

The parser is deliberately simple: it relies on the headers' own layout (a
comment directly above a declaration documents it; a comment followed by a blank
line is prose; a one-line "--- title ---" comment starts a section).
"""
import html
import re
from pathlib import Path

from mkdocs.plugins import event_priority
from mkdocs.structure.files import File

REPO_URL = "https://github.com/shieldled/libshieldnet/blob/main/"

# Areas, in the order the reference presents them. A header not listed here
# still gets a page, under "Other".
AREAS = [
    ("Client", "Admit to a device and talk to it: the client role.",
     ["sn_client.h", "sn_client_session.h", "sn_client_wire.h"]),
    ("Device", "Admit clients, run the session and serve commands: the device role.",
     ["sn_device.h", "sn_agent.h", "sn_agent_dispatch.h"]),
    ("Port seams", "What a platform implements: transport, device callbacks, OS services, logging.",
     ["shieldnet_device.h", "shieldnet_io.h", "shieldnet_os.h", "shieldnet_log.h"]),
    ("Keys and crypto", "Key derivation, MACs and the message-layer AEAD.",
     ["sn_kdf.h", "crypto.h"]),
    ("Message layer", "Sealing and opening application messages, both roles.",
     ["sn_app_frame.h", "protocol.h", "frame.h", "decompress.h"]),
    ("Transport", "Wire messages, envelope, demultiplexing, replay window, source checks.",
     ["sn_wire.h", "sn_demux.h", "sn_replay.h", "sn_source.h"]),
    ("Commands", "Command kinds, parsers, encoders and response decoders.",
     ["command.h", "command_parse.h", "command_encode.h", "response_decode.h"]),
    ("Frame timing", "When to present, hold or discard a pixel frame.",
     ["sn_pts.h"]),
    ("Policies", "Small pure rules the command core and devices share.",
     ["payload_encode_policy.h", "pixel_frame_policy.h", "command_response_policy.h",
      "mode_decode_policy.h", "mode_ownership_policy.h", "kcp_server_policy.h"]),
]

SECTION_RE = re.compile(r"^[-─=—\s]{2,}(.+?)[-─=—\s]*$")
IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def _strip_comment(block):
    """Comment source -> text lines without the comment markers."""
    text = block.strip()
    if text.startswith("//"):
        return [re.sub(r"^\s*//+ ?", "", l) for l in text.splitlines()]
    text = text[2:-2] if text.endswith("*/") else text[2:]
    lines = text.splitlines()
    out = []
    for l in lines:
        l = re.sub(r"^\s*\* ?", "", l) if re.match(r"^\s*\*", l) else l.strip() if not out else l
        out.append(l.rstrip())
    while out and not out[0].strip():
        out.pop(0)
    while out and not out[-1].strip():
        out.pop()
    return out


def _code_only(src):
    """Source with comments and string literals removed, for brace counting."""
    src = re.sub(r"/\*.*?\*/", " ", src, flags=re.S)
    src = re.sub(r"//[^\n]*", " ", src)
    src = re.sub(r'"(\\.|[^"\\])*"', '""', src)
    src = re.sub(r"'(\\.|[^'\\])*'", "''", src)
    return src


def _name_and_kind(code):
    c = " ".join(_code_only(code).split())
    if c.startswith("#define"):
        m = re.match(r"#define\s+([A-Za-z_]\w*)", c)
        return (m.group(1) if m else "?"), "macro"
    if re.match(r"(static_assert|_Static_assert|[A-Z_]*STATIC_ASSERT)\s*\(", c):
        return None, "assert"  # a build-time check: shown, but declares nothing
    if c.startswith("typedef"):
        if "}" in c:  # a struct, enum or union: the name follows the body
            ids = IDENT_RE.findall(c.rsplit("}", 1)[-1].split("[")[0])
            return (ids[-1] if ids else "?"), "type"
        m = re.search(r"\(\s*\*\s*([A-Za-z_]\w*)\s*\)", c)
        if m:
            return m.group(1), "type"
        ids = IDENT_RE.findall(c.split("[")[0])
        return (ids[-1] if ids else "?"), "type"
    m = re.match(r"(struct|enum|union)\s+([A-Za-z_]\w*)\s*[{;]", c)
    if m:
        return m.group(2), "type"
    m = re.match(r"[^(]*\(\s*\*\s*([A-Za-z_]\w*)\s*\)\s*\(", c)
    if m:  # a function-pointer variable
        return m.group(1), "variable"
    head = c.split("{", 1)[0]
    if "(" in head:
        m = re.search(r"([A-Za-z_]\w*)\s*\($", head.split("(", 1)[0] + "(")
        return (m.group(1) if m else "?"), "function"
    ids = IDENT_RE.findall(c.split("=")[0].split("[")[0])
    return (ids[-1] if ids else "?"), "variable"


def _only_conditionals(lines):
    """True if every line is a preprocessor conditional (#if.../#else/#endif)."""
    return all(re.match(r"\s*#\s*(if|ifdef|ifndef|elif|else|endif)\b", l) for l in lines)


def parse_header(text):
    """-> (overview lines, items). Item: ("prose", lines) | ("section", title)
    | ("decl", name, kind, comment_src, code_src, more_names)
    | ("code", comment_src, code_src): a static assertion, shown without a name."""
    lines = text.splitlines()
    i, n = 0, len(lines)
    items, pending = [], None
    overview, seen_code = None, False
    guard = None
    last_end = -2

    def flush_pending():
        nonlocal pending, overview
        if pending is None:
            return
        body = _strip_comment(pending)
        if any("SPDX-License-Identifier" in l for l in body):
            pass
        elif overview is None and not seen_code and not items:
            overview = body
        elif len(body) == 1 and SECTION_RE.match(body[0]):
            items.append(("section", SECTION_RE.match(body[0]).group(1).strip()))
        elif body:
            items.append(("prose", body))
        pending = None

    while i < n:
        line = lines[i]
        s = line.strip()
        if not s:
            flush_pending()
            i += 1
            continue
        if s.startswith("/*") or s.startswith("//"):
            if pending is not None:
                flush_pending()
            start = i
            if s.startswith("/*"):
                while "*/" not in lines[i]:
                    i += 1
            else:
                while i + 1 < n and lines[i + 1].strip().startswith("//"):
                    i += 1
            pending = "\n".join(lines[start:i + 1])
            i += 1
            continue
        if s.startswith("#"):
            m = re.match(r"#\s*(\w+)\s*(\w*)", s)
            d, arg = (m.group(1), m.group(2)) if m else ("", "")
            if d == "ifndef" and guard is None and not seen_code:
                guard = arg
            if d == "define" and arg and arg != guard:
                start = i
                while lines[i].rstrip().endswith("\\") and i + 1 < n:
                    i += 1
                code = "\n".join(lines[start:i + 1])
                name, kind = _name_and_kind(code)
                prev = items[-1] if items else None
                if pending is None and prev and prev[0] == "decl" and prev[2] == "macro" \
                        and _only_conditionals(lines[last_end + 1:start]):
                    # A run of #defines under one comment (conditionals between
                    # them allowed): one block, one comment. A name defined
                    # again (#ifdef/#else) is listed once.
                    more = prev[5] if name == prev[1] or name in prev[5] else prev[5] + (name,)
                    items[-1] = prev[:4] + (prev[4] + "\n" + code, more)
                else:
                    items.append(("decl", name, kind, pending, code, ()))
                pending, seen_code, last_end = None, True, i
            i += 1
            continue
        if re.match(r'extern\s+"C"\s*\{', s) or s == "}":
            i += 1
            continue
        start, depth, saw_brace = i, 0, False
        while i < n:
            code = _code_only(lines[i])
            depth += code.count("{") - code.count("}")
            saw_brace = saw_brace or "{" in code
            tail = code.strip()
            if depth <= 0 and (tail.endswith(";") or (saw_brace and tail.endswith("}"))):
                break
            i += 1
        code = "\n".join(lines[start:i + 1])
        name, kind = _name_and_kind(code)
        prev = items[-1] if items else None
        if kind == "assert" and pending is None and prev and prev[0] == "code" \
                and _only_conditionals(lines[last_end + 1:start]):
            items[-1] = ("code", prev[1], prev[2] + "\n" + code)
        elif kind == "assert":
            items.append(("code", pending, code))
        else:
            items.append(("decl", name, kind, pending, code, ()))
        pending, seen_code, last_end = None, True, i
        i += 1
    flush_pending()
    return overview or [], items


def _esc(t):
    t = html.escape(t, quote=False)
    return re.sub(r"(?<!\*)\*(?!\*)", r"\\*", t)


def _md_text(lines):
    """Comment prose -> Markdown, paragraph by paragraph. A paragraph holding a
    diagram or an indented block stays verbatim in a text block; list items
    (lines starting with "-" or "1.") keep their continuation lines."""
    paras, cur = [], []
    for l in lines + [""]:
        if l.strip():
            cur.append(l)
        elif cur:
            paras.append(cur)
            cur = []
    out = []
    for p in paras:
        base = min(len(l) - len(l.lstrip()) for l in p)
        if any(len(l) - len(l.lstrip()) - base >= 4 for l in p) or \
                any(re.search(r"[─│┌└├┼▶►]|->|<-", l) and len(l) - len(l.lstrip()) >= 2 for l in p) or \
                sum(bool(re.search(r"\S {2,}\S", l.strip())) for l in p) >= 2:  # a table
            out.append("```text\n" + "\n".join(l[base:] for l in p) + "\n```")
            continue
        items = []
        for l in p:
            t = l.strip()
            if re.match(r"^(-|\*|\d+[.)])\s", t) or not items:
                items.append(t)
            else:
                items[-1] += " " + t
        if len(items) > 1 or re.match(r"^(-|\*|\d+[.)])\s", items[0]):
            out.append("\n".join(_esc(i) if not i.startswith("* ") else "- " + _esc(i[2:]) for i in items))
        else:
            out.append(_esc(items[0]))
    return "\n\n".join(out)


def _summary(comment_src, plain=False):
    if not comment_src:
        return ""
    text = " ".join(l.strip() for l in _strip_comment(comment_src) if l.strip())
    m = re.match(r"(.+?\.)(\s|$)", text)
    s = m.group(1) if m else text
    if len(s) > 180:
        s = s[:180].rsplit(" ", 1)[0] + " …"
    return s if plain else _esc(s).replace("|", r"\|")


def render_page(rel, overview, items):
    fname = Path(rel).name
    md = [f"# `{fname}`", ""]
    inc = rel.split("/", 1)[1] if rel.startswith("include/") else Path(rel).name
    md += [f"`#include \"{inc}\"` · [source]({REPO_URL}{rel})", ""]
    if overview:
        md += [_md_text(overview), ""]
    used = {}

    def anchor(name):
        a = re.sub(r"[^a-z0-9_]+", "-", name.lower())
        used[a] = used.get(a, 0) + 1
        return a if used[a] == 1 else f"{a}-{used[a]}"

    # (name, kind, anchor, summary, item) for every declared name, in file order
    syms = []
    for it in items:
        if it[0] == "decl":
            summ = _summary(it[3])
            for nm in (it[1],) + it[5]:
                syms.append((nm, it[2], anchor(nm), summ, it))
    # A name declared twice (a forward declaration, then the definition) is
    # summarised and indexed once, at its definition.
    def forward(it):
        return re.match(r"\s*(struct|enum|union)\s+\w+\s*;", _code_only(it[4])) is not None
    primary = {}
    for s in syms:
        if s[0] not in primary or (forward(primary[s[0]][4]) and not forward(s[4])):
            primary[s[0]] = s
    if syms:
        md += ["## Summary", "", "| Name | Kind | Description |", "| --- | --- | --- |"]
        for nm, kind, a, summ, _ in primary.values():
            md.append(f"| [`{nm}`](#{a}) | {kind} | {summ} |")
        md.append("")
    md += ["## Reference", ""]
    for it in items:
        if it[0] == "section":
            md += [f"### {html.escape(it[1], quote=False)}", ""]
        elif it[0] == "prose":
            md += [_md_text(it[1]), ""]
        elif it[0] == "code":
            body = (it[1] + "\n" if it[1] else "") + it[2]
            md += ["```c", body, "```", ""]
        else:
            mine = [x for x in syms if x[4] is it]
            title = ", ".join(f"`{x[0]}`" for x in mine)
            md += [f"#### {title} {{#{mine[0][2]}}}", ""]
            md += [f'<a id="{x[2]}"></a>' for x in mine[1:]]
            body = (it[3] + "\n" if it[3] else "") + it[4]
            md += ["```c", body, "```", ""]
    return "\n".join(md), [(x[0], x[1], x[2], x[3]) for x in primary.values()]


def _headers(root):
    return sorted(list((root / "include" / "shieldnet").glob("*.h")) + list((root / "port").glob("*.h")))


def build(root):
    """-> {docs path: markdown}, nav entries, [(header page, plain summary)]."""
    pages, symbols, area_of = {}, [], {}
    summaries, plain = {}, {}
    for h in _headers(root):
        rel = h.relative_to(root).as_posix()
        overview, items = parse_header(h.read_text(encoding="utf-8"))
        md, syms = render_page(rel, overview, items)
        page = f"api/{h.stem}.md"
        pages[page] = md
        summaries[h.name] = (page, _summary("/* " + " ".join(overview) + " */") if overview else "")
        plain[page] = _summary("/* " + " ".join(overview) + " */", plain=True) if overview else ""
        symbols += [(s[0], s[1], page, s[2], s[3], h.name) for s in syms]
    areas = [(a, d, [f for f in fs if f in summaries]) for a, d, fs in AREAS]
    listed = {f for _, _, fs in areas for f in fs}
    other = sorted(f for f in summaries if f not in listed)
    if other:
        areas.append(("Other", "Headers not yet sorted into an area.", other))

    idx = ["# API reference", "",
           "Generated from the public headers, `include/shieldnet/*.h` and `port/*.h`, each "
           "time the documentation is built. Each page shows a header's overview, a summary, "
           "and every declaration exactly as the header has it, with its comment. The "
           "[README](../index.md) explains how the pieces fit together; the "
           "[examples](../examples/README.md) show them in use.", ""]
    for a, d, fs in areas:
        if not fs:
            continue
        idx += [f"## {a}", "", d, "", "| Header | What it is |", "| --- | --- |"]
        for f in fs:
            page, summ = summaries[f]
            idx.append(f"| [`{f}`]({Path(page).name}) | {summ} |")
        idx.append("")
    idx += ["## All symbols", "", "| Symbol | Kind | Header | Description |", "| --- | --- | --- | --- |"]
    seen = set()
    for name, kind, page, anchor, summ, hname in sorted(symbols, key=lambda s: (s[0].lower(), s[5])):
        if (name, hname) in seen:
            continue
        seen.add((name, hname))
        idx.append(f"| [`{name}`]({Path(page).name}#{anchor}) | {kind} | `{hname}` | {summ} |")
    pages["api/index.md"] = "\n".join(idx) + "\n"

    nav = ["api/index.md"]
    for a, _, fs in areas:
        if fs:
            nav.append({a: [summaries[f][0] for f in fs]})
    descs = [(summaries[f][0], plain[summaries[f][0]]) for _, _, fs in areas for f in fs]
    return pages, nav, descs


_PAGES = {}


def on_config(config):
    root = Path(config["config_file_path"]).parent
    pages, nav, descs = build(root)
    _PAGES.clear()
    _PAGES.update(pages)
    for i, entry in enumerate(config["nav"] or []):
        if isinstance(entry, dict) and "API reference" in entry:
            config["nav"][i] = {"API reference": nav}
    # llms.txt: list each header page with its summary. A glob entry would
    # give them none, and would also drop api/index.md's description.
    llmstxt = config["plugins"].get("llmstxt")
    if llmstxt is not None:
        for inputs in llmstxt.config.sections.values():
            if "api/*.md" in inputs:
                at = inputs.index("api/*.md")
                inputs[at:at + 1] = [{page: desc} for page, desc in descs]
    return config


# Before every plugin, so llmstxt sees the generated pages.
@event_priority(100)
def on_files(files, config):
    for path, content in _PAGES.items():
        files.append(File.generated(config, path, content=content))
    return files


# The examples page shows examples/README.md followed by every example source
# (docs/examples/README.md). The README links to the sources by file name, which
# works on GitHub; on the site those links go to the source sections instead.
EXAMPLE_SOURCES = {
    "led_device.c": "led_device-c",
    "led_client.c": "led_client-c",
    "example_util.h": "example_util-h",
    "CMakeLists.txt": "cmakelists-txt",
    "led_loopback.sh": "led_loopback-sh",
}


def on_page_markdown(markdown, page, config, files):
    if page.file.src_uri != "examples/README.md":
        return markdown
    for name, anchor in EXAMPLE_SOURCES.items():
        markdown = markdown.replace(f"]({name})", f"](#{anchor})")
    return markdown
