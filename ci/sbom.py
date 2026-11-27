#!/usr/bin/env python3
# Copyright (c) 2025-2026 BlackShield LDA
# SPDX-License-Identifier: Apache-2.0
"""Writes libshieldnet's software bill of materials as CycloneDX 1.6 JSON.

The third-party code is vendored (vendor/) or built by ci/install-deps.sh, so no
package manifest lists it and SBOM scanners cannot find it. This script reads
each component's version from the files that pin it, so the SBOM cannot drift
from the tree:

  LZ4        vendor/lz4.h        LZ4_VERSION_MAJOR / _MINOR / _RELEASE
  KCP        vendor/ikcp.h       "Upstream baseline: skywind3000/kcp X.Y.Z (tag commit H"
  libsodium  ci/install-deps.sh  SODIUM_VERSION / SODIUM_SHA256

Usage, from the repository root:  python3 ci/sbom.py > sbom.cdx.json
The output depends only on the commit (no wall-clock time), so it is
reproducible. CI scans it for known vulnerabilities with Grype.
"""
import json
import os
import re
import subprocess
import sys
import uuid

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def read(rel):
    with open(os.path.join(ROOT, rel), encoding="utf-8") as f:
        return f.read()


def need(pattern, text, what):
    m = re.search(pattern, text, re.M)
    if not m:
        sys.exit(f"sbom.py: cannot find {what}")
    return m


def git(*args):
    try:
        return subprocess.run(["git", "-C", ROOT, *args], check=True,
                              capture_output=True, text=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return ""


def lz4():
    h = read("vendor/lz4.h")
    v = ".".join(need(rf"^#define LZ4_VERSION_{k}\s+(\d+)", h, f"LZ4_VERSION_{k}").group(1)
                 for k in ("MAJOR", "MINOR", "RELEASE"))
    return {
        "type": "library", "bom-ref": "lz4", "name": "lz4", "version": v,
        "supplier": {"name": "Yann Collet", "url": ["https://github.com/lz4/lz4"]},
        "licenses": [{"license": {"id": "BSD-2-Clause"}}],
        "purl": f"pkg:github/lz4/lz4@v{v}",
        "cpe": f"cpe:2.3:a:lz4_project:lz4:{v}:*:*:*:*:*:*:*",
        "description": "LZ4 block compression (vendor/lz4.c, vendor/lz4.h), unmodified",
        "externalReferences": [{"type": "vcs", "url": "https://github.com/lz4/lz4"}],
    }


def kcp():
    m = need(r"Upstream baseline: skywind3000/kcp (\d+\.\d+\.\d+) \(tag commit ([0-9a-f]+)",
             read("vendor/ikcp.h"), "the KCP baseline in vendor/ikcp.h")
    v, commit = m.group(1), m.group(2)
    return {
        "type": "library", "bom-ref": "kcp", "name": "kcp", "version": v,
        "supplier": {"name": "Lin Wei (skywind3000)", "url": ["https://github.com/skywind3000/kcp"]},
        "licenses": [{"license": {"id": "MIT"}}],
        "purl": f"pkg:github/skywind3000/kcp@{v}",
        "description": "KCP reliable transport (vendor/ikcp.c, vendor/ikcp.h)",
        "externalReferences": [{"type": "vcs", "url": "https://github.com/skywind3000/kcp"}],
        "pedigree": {
            "ancestors": [{"type": "library", "name": "kcp", "version": v,
                           "purl": f"pkg:github/skywind3000/kcp@{v}",
                           "description": f"upstream tag commit {commit}"}],
            "notes": "Modified by BlackShield LDA; every change is listed in the header of vendor/ikcp.h.",
        },
    }


def libsodium():
    s = read("ci/install-deps.sh")
    v = need(r"^SODIUM_VERSION=(\S+)", s, "SODIUM_VERSION in ci/install-deps.sh").group(1)
    sha = need(r"^SODIUM_SHA256=([0-9a-f]{64})", s, "SODIUM_SHA256 in ci/install-deps.sh").group(1)
    return {
        "type": "library", "bom-ref": "libsodium", "name": "libsodium", "version": v,
        "scope": "required",
        "supplier": {"name": "Frank Denis", "url": ["https://libsodium.org"]},
        "licenses": [{"license": {"id": "ISC"}}],
        "purl": f"pkg:generic/libsodium@{v}?download_url=https://download.libsodium.org/libsodium/releases/libsodium-{v}.tar.gz",
        "cpe": f"cpe:2.3:a:libsodium_project:libsodium:{v}:*:*:*:*:*:*:*",
        "hashes": [{"alg": "SHA-256", "content": sha}],
        "description": "External dependency, linked; not redistributed here. The version is the one "
                       "CI builds (ci/install-deps.sh); the library needs 1.0.19 or newer.",
    }


def main():
    commit = git("rev-parse", "HEAD") or "unknown"
    version = git("describe", "--tags", "--always", "--dirty") or commit
    when = git("show", "-s", "--format=%cI", "HEAD") or "1970-01-01T00:00:00Z"
    comps = [lz4(), kcp(), libsodium()]
    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": "urn:uuid:" + str(uuid.uuid5(uuid.NAMESPACE_URL,
                                                    f"https://github.com/shieldled/libshieldnet@{commit}")),
        "version": 1,
        "metadata": {
            "timestamp": when,
            "tools": {"components": [{"type": "application", "name": "ci/sbom.py"}]},
            "component": {
                "type": "library", "bom-ref": "libshieldnet", "name": "libshieldnet",
                "version": version,
                "supplier": {"name": "BlackShield LDA"},
                "licenses": [{"license": {"id": "Apache-2.0"}}],
                "purl": f"pkg:github/shieldled/libshieldnet@{commit}",
                "externalReferences": [{"type": "vcs", "url": "https://github.com/shieldled/libshieldnet"}],
            },
        },
        "components": comps,
        "dependencies": [
            {"ref": "libshieldnet", "dependsOn": [c["bom-ref"] for c in comps]},
        ] + [{"ref": c["bom-ref"], "dependsOn": []} for c in comps],
    }
    json.dump(bom, sys.stdout, indent=2)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
