#!/usr/bin/env python3
"""Generate expected JA4+ fingerprint outputs from Python library for cross-validation."""
import json
import sys
import importlib.util

from scapy.all import rdpcap


def _load_module(name, path):
    """Load a Python module directly from file path, bypassing package __init__."""
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    # Inject the base module dependency before exec
    base_spec = importlib.util.spec_from_file_location(
        "ja4plus.fingerprinters.base",
        path.replace(name.split(".")[-1] + ".py", "base.py"),
    )
    base_mod = importlib.util.module_from_spec(base_spec)
    base_spec.loader.exec_module(base_mod)
    sys.modules["ja4plus.fingerprinters.base"] = base_mod
    spec.loader.exec_module(mod)
    return mod


def _find_ja4plus_root():
    """Find the ja4plus Python library relative to this script."""
    import os
    script_dir = os.path.dirname(os.path.abspath(__file__))
    # Try ../ja4plus/ (sibling repo) then ../../ja4plus/
    for rel in ["../../ja4plus", "../../../ja4plus"]:
        candidate = os.path.normpath(os.path.join(script_dir, rel, "ja4plus", "fingerprinters"))
        if os.path.isdir(candidate):
            return candidate
    return None


# Try direct import first, fall back to file-based loading
try:
    from ja4plus.fingerprinters.ja4t import generate_ja4t
    from ja4plus.fingerprinters.ja4ts import generate_ja4ts
except (ImportError, SyntaxError):
    _fp_dir = _find_ja4plus_root()
    if _fp_dir is None:
        print("Error: cannot find ja4plus Python library", file=sys.stderr)
        sys.exit(1)
    import os
    _ja4t_mod = _load_module("ja4t", os.path.join(_fp_dir, "ja4t.py"))
    _ja4ts_mod = _load_module("ja4ts", os.path.join(_fp_dir, "ja4ts.py"))
    generate_ja4t = _ja4t_mod.generate_ja4t
    generate_ja4ts = _ja4ts_mod.generate_ja4ts

def main():
    if len(sys.argv) < 2:
        print("Usage: gen_expected.py <pcap_file>", file=sys.stderr)
        sys.exit(1)

    pcap_path = sys.argv[1]
    packets = rdpcap(pcap_path)
    results = []

    for i, pkt in enumerate(packets):
        ja4t = generate_ja4t(pkt)
        if ja4t:
            results.append({"packet_index": i, "type": "ja4t", "fingerprint": ja4t})
        ja4ts = generate_ja4ts(pkt)
        if ja4ts:
            results.append({"packet_index": i, "type": "ja4ts", "fingerprint": ja4ts})

    json.dump(results, sys.stdout, indent=2)
    print()

if __name__ == "__main__":
    main()
