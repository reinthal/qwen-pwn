#!/usr/bin/env python3
"""Delegate the honeypot domains from Njalla DNS to our own BIND (ns1/ns2 glue).

Runs with the project's uv venv (needs the `njalla` package / requests):

    cd ~/qwen-pwn
    .venv/bin/python server/honeypot/njalla_delegate.py            # dry run (read-only)
    .venv/bin/python server/honeypot/njalla_delegate.py --apply    # make the changes
    .venv/bin/python server/honeypot/njalla_delegate.py --revert --apply  # back to Njalla NS

The API key comes from $NJALLA_API_KEY, else NJALLA_API_KEY= in the repo .env,
else an interactive getpass prompt. Dry run without a key just prints the plan.

Before --apply, the script checks that 80.78.18.246 answers authoritatively
(aa flag) for each zone's SOA, so we never delegate to a dead server.
Use --force to skip that check.
"""

from __future__ import annotations

import argparse
import getpass
import os
import subprocess
import sys
from pathlib import Path

DOMAINS = ["r0ck3t.net", "r0ck3y.net", "r0ckey.com", "r0ckey.net"]
IPV4 = "80.78.18.246"
IPV6 = "2a0a:3840:8078:18:0:504e:12f6:1337"
# name -> (address4, address6)
GLUE = {"ns1": (IPV4, None), "ns2": (IPV4, IPV6)}
REPO_ENV = Path(__file__).resolve().parents[2] / ".env"


def load_key(interactive: bool) -> str | None:
    key = os.environ.get("NJALLA_API_KEY", "").strip()
    if key and key != "configme":
        return key
    if REPO_ENV.exists():
        for line in REPO_ENV.read_text().splitlines():
            if line.strip().startswith("NJALLA_API_KEY="):
                val = line.split("=", 1)[1].strip().strip('"').strip("'")
                if val and val != "configme":
                    return val
    if interactive and sys.stdin.isatty():
        return getpass.getpass("Njalla API key: ").strip() or None
    return None


def norm_ip6(a: str | None) -> str | None:
    if not a:
        return None
    import ipaddress
    return str(ipaddress.ip_address(a))


def authoritative_ok(domain: str) -> tuple[bool, str]:
    try:
        out = subprocess.run(
            ["dig", "+norec", "+time=3", "+tries=2", "SOA", domain, f"@{IPV4}"],
            capture_output=True, text=True, timeout=20).stdout
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, f"dig failed: {exc}"
    ok = "status: NOERROR" in out and " aa" in out.split("flags:", 1)[-1].split(";", 1)[0]
    return ok, "authoritative NOERROR" if ok else "NOT authoritative / no answer"


def glue_entries(result) -> dict[str, dict]:
    items = result.get("glue", result) if isinstance(result, dict) else result
    out = {}
    for g in items or []:
        if isinstance(g, dict) and g.get("name"):
            name = g["name"].split(".")[0].lower()
            out[name] = g
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--apply", action="store_true", help="actually perform the API calls")
    ap.add_argument("--revert", action="store_true", help="switch back to Njalla's nameservers (glue kept)")
    ap.add_argument("--force", action="store_true", help="skip the authoritative-server pre-flight")
    ap.add_argument("--domains", nargs="*", default=DOMAINS)
    args = ap.parse_args()

    key = load_key(interactive=True)
    client = None
    if key:
        from Njalla import Client  # imported lazily so --help works without the venv
        client = Client(key)
    elif args.apply:
        print("ERROR: --apply needs NJALLA_API_KEY", file=sys.stderr)
        return 2
    else:
        print("(no API key: printing the plan only, current state not checked)\n")

    if args.apply and not args.revert and not args.force:
        bad = []
        for d in args.domains:
            ok, msg = authoritative_ok(d)
            print(f"pre-flight {d} @ {IPV4}: {msg}")
            if not ok:
                bad.append(d)
        if bad:
            print(f"\nRefusing to delegate {bad}: our BIND is not serving them. "
                  "Run `sudo ./deploy.sh server` first (or --force).", file=sys.stderr)
            return 3
        print()

    mode = "APPLY" if args.apply else "DRY-RUN"
    for d in args.domains:
        print(f"=== {d} [{mode}]")
        want_ns = [] if args.revert else [f"ns1.{d}", f"ns2.{d}"]

        if not args.revert:
            existing = glue_entries(client.Domain.list_glue(d)) if client else {}
            for name, (a4, a6) in GLUE.items():
                cur = existing.get(name)
                if cur and cur.get("address4") == a4 and norm_ip6(cur.get("address6")) == norm_ip6(a6):
                    print(f"  glue {name}.{d}: already {a4} {a6 or ''}")
                    continue
                call = "edit_glue" if cur else "add_glue"
                print(f"  {call}({d!r}, {name!r}, address4={a4!r}, address6={a6!r})"
                      + (f"   [was {cur}]" if cur else ""))
                if args.apply:
                    getattr(client.Domain, call)(d, name, address4=a4, address6=a6)

        cur_ns = None
        if client:
            info = client.Domain.get_domain(d)
            cur_ns = sorted(n.rstrip(".").lower() for n in (info.get("nameservers") or []))
        if cur_ns is not None and cur_ns == sorted(want_ns):
            print(f"  nameservers already {want_ns or 'Njalla default'}")
        else:
            print(f"  edit_domain({d!r}, nameservers={want_ns!r})"
                  + (f"   [currently {cur_ns or 'Njalla default'}]" if cur_ns is not None else ""))
            if args.apply:
                client.Domain.edit_domain(d, nameservers=want_ns)
        print()

    if not args.apply:
        print("Dry run only. Re-run with --apply to make these changes.")
        return 0
    print("Done. Registry changes can take minutes (sometimes hours) to propagate.")
    print("Check the parent zone directly:")
    for d in args.domains:
        tld = d.rsplit(".", 1)[1]
        print(f"  dig +norec +noall +authority +additional NS {d} @a.gtld-servers.net   # .{tld}")
    print("Then: sudo ./deploy.sh certs")
    return 0


if __name__ == "__main__":
    sys.exit(main())
