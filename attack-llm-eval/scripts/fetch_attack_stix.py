#!/usr/bin/env python3
"""Download the MITRE ATT&CK Enterprise STIX bundle.

Pulls enterprise-attack.json from the official mitre-attack/attack-stix-data
repo. Pin a release tag for reproducibility (recommended for a study).

    python scripts/fetch_attack_stix.py --out data/enterprise-attack.json
    python scripts/fetch_attack_stix.py --version 15.1 --out data/enterprise-attack.json
"""
import argparse
import os
import sys
import urllib.request

BASE = ("https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
        "master/enterprise-attack/enterprise-attack.json")
VERSIONED = ("https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
             "master/enterprise-attack/enterprise-attack-{v}.json")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="data/enterprise-attack.json")
    ap.add_argument("--version", default=None,
                    help="pin an ATT&CK version, e.g. 15.1 (recommended)")
    args = ap.parse_args()

    url = VERSIONED.format(v=args.version) if args.version else BASE
    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    print(f"[+] downloading {url}", file=sys.stderr)
    try:
        urllib.request.urlretrieve(url, args.out)
    except Exception as exc:  # noqa: BLE001
        print(f"[!] download failed: {exc}", file=sys.stderr)
        return 1
    size = os.path.getsize(args.out)
    print(f"[+] saved {args.out} ({size/1_000_000:.1f} MB)", file=sys.stderr)
    if size < 1_000_000:
        print("[!] file looks too small; check the version/URL", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
