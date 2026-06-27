#!/usr/bin/env python3
"""
Fetch ATT&CK enterprise data and produce a compact groups+techniques JSON.
Run once locally (or in CI) to regenerate data/attack_data.json.

Usage:
    pip install requests --break-system-packages
    python scripts/fetch_data.py
"""

import json
import sys
import requests
from collections import defaultdict

STIX_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
OUT_PATH = "data/attack_data.json"

def fetch_bundle():
    print("Downloading ATT&CK enterprise bundle (~80 MB)…", flush=True)
    r = requests.get(STIX_URL, stream=True, timeout=120)
    r.raise_for_status()
    total = int(r.headers.get("content-length", 0))
    buf = []
    downloaded = 0
    for chunk in r.iter_content(chunk_size=1 << 20):
        buf.append(chunk)
        downloaded += len(chunk)
        if total:
            pct = downloaded * 100 // total
            print(f"\r  {pct}%", end="", flush=True)
    print()
    return json.loads(b"".join(buf))

def process(bundle):
    objects = bundle["objects"]

    # Index by id
    by_id = {o["id"]: o for o in objects}

    # --- Techniques (attack-pattern, enterprise only, no deprecated/revoked) ---
    techniques = {}
    for o in objects:
        if o.get("type") != "attack-pattern":
            continue
        if o.get("x_mitre_deprecated") or o.get("revoked"):
            continue
        # extract ATT&CK ID from external_references
        att_id = None
        for ref in o.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                att_id = ref["external_id"]
                break
        if not att_id:
            continue
        techniques[o["id"]] = {
            "id": att_id,
            "name": o["name"],
            "url": f"https://attack.mitre.org/techniques/{att_id.replace('.', '/')}",
            "tactics": [p["phase_name"] for p in o.get("kill_chain_phases", [])],
        }

    # --- Groups (intrusion-set) ---
    groups = {}
    for o in objects:
        if o.get("type") != "intrusion-set":
            continue
        if o.get("x_mitre_deprecated") or o.get("revoked"):
            continue
        att_id = None
        for ref in o.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                att_id = ref["external_id"]
                break
        if not att_id:
            continue
        groups[o["id"]] = {
            "id": att_id,
            "stix_id": o["id"],
            "name": o["name"],
            "aliases": o.get("aliases", [o["name"]]),
            "description": o.get("description", "")[:300],
            "url": f"https://attack.mitre.org/groups/{att_id}",
            "techniques": [],
        }

    # --- Relationships: group uses technique ---
    group_techs = defaultdict(set)
    for o in objects:
        if o.get("type") != "relationship":
            continue
        if o.get("relationship_type") != "uses":
            continue
        src = o.get("source_ref", "")
        tgt = o.get("target_ref", "")
        if src in groups and tgt in techniques:
            group_techs[src].add(tgt)

    # Attach techniques to groups
    for stix_id, tech_stix_ids in group_techs.items():
        groups[stix_id]["techniques"] = sorted(
            [techniques[t]["id"] for t in tech_stix_ids if t in techniques]
        )

    # Build final output keyed by ATT&CK group ID
    out_groups = {}
    for stix_id, g in groups.items():
        if not g["techniques"]:
            continue
        out_groups[g["id"]] = {
            "name": g["name"],
            "aliases": g["aliases"],
            "description": g["description"],
            "url": g["url"],
            "techniques": g["techniques"],
        }

    out_techniques = {v["id"]: v for v in techniques.values()}

    return {"groups": out_groups, "techniques": out_techniques}

def main():
    bundle = fetch_bundle()
    print("Processing…")
    data = process(bundle)
    with open(OUT_PATH, "w") as f:
        json.dump(data, f, separators=(",", ":"))
    groups_n = len(data["groups"])
    techs_n  = len(data["techniques"])
    size_kb  = len(json.dumps(data)) // 1024
    print(f"Done. {groups_n} groups, {techs_n} techniques → {OUT_PATH} ({size_kb} KB)")

if __name__ == "__main__":
    main()
