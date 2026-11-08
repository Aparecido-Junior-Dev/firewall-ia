#!/usr/bin/env python3
"""
coletar_feeds.py — Arquiva snapshots diários dos feeds de reputação

Uso:
    python scripts/coletar_feeds.py [--output data/feeds/]

Arquiva um snapshot de cada feed por dia para medir:
- Contribuição exclusiva: quantos fluxos só um feed bloquearia
- Latência: quantos dias um feed bloqueia antes do outro
"""

import os
import sys
import hashlib
from datetime import datetime
from pathlib import Path
import urllib.request
import ssl

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

FEEDS = {
    "abuseipdb_s100_180d": "https://raw.githubusercontent.com/borestad/blocklist-abuseipdb/refs/heads/main/abuseipdb-s100-180d.ipv4",
    "spamhaus_drop": "https://www.spamhaus.org/drop/drop.txt",
    "spamhaus_edrop": "https://www.spamhaus.org/drop/edrop.txt",
    "dshield_block": "https://www.dshield.org/block.txt",
    "et_drop": "https://rules.emergingthreats.net/blockrules/emerging-drop.rules",
}

def coletar(output_dir="data/feeds"):
    hoje = datetime.now().strftime("%Y-%m-%d")
    base = Path(output_dir) / hoje
    base.mkdir(parents=True, exist_ok=True)

    manifest = []
    for nome, url in FEEDS.items():
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "firewall-ia/1.0"})
            with urllib.request.urlopen(req, context=ctx, timeout=30) as resp:
                conteudo = resp.read()
                arq = base / f"{nome}.txt"
                arq.write_bytes(conteudo)
                sha256 = hashlib.sha256(conteudo).hexdigest()
                linhas = conteudo.decode("utf-8", errors="ignore").strip().split("\n")
                ips = sum(1 for l in linhas if l.strip() and not l.startswith("#"))
                manifest.append({
                    "feed": nome,
                    "url": url,
                    "arquivo": str(arq),
                    "sha256": sha256,
                    "linhas": len(linhas),
                    "ips": ips,
                    "data": hoje,
                })
                print(f"  {nome}: {ips} IPs")
        except Exception as e:
            print(f"  {nome}: ERRO — {e}")
            manifest.append({"feed": nome, "url": url, "erro": str(e), "data": hoje})

    # Salvar manifest
    import json
    man_arq = base / "manifest.json"
    with open(man_arq, "w") as f:
        json.dump(manifest, f, indent=2, ensure_ascii=False)
    print(f"\nSnapshots de {hoje} salvos em {base}")
    return manifest

if __name__ == "__main__":
    output = "data/feeds"
    if "--output" in sys.argv:
        output = sys.argv[sys.argv.index("--output") + 1]
    print(f"Coletando feeds para {output}/...")
    coletar(output)
