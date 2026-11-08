#!/usr/bin/env python3
"""
avaliar_familias.py — Fase 3: avalia famílias de regras e compara com CrowdSec

1. Família IP individual: bloquear IPs que geraram alerta no período A
2. Família comportamento: bloquear por porta + taxa no período A
3. Comparar com CrowdSec: IPs na tabela crowdsec_blocklists

Métricas para cada família:
- Cobertura incremental: fluxos que passaram no B que a regra bloquearia
- Bloqueio colateral: fluxos sem alerta que a regra também bloquearia
"""

import json
import re
import csv
from pathlib import Path
from collections import defaultdict, Counter
from datetime import datetime

DATA_DIR = Path("data/raw")
EXPORTS = Path("exports")
EXPORTS.mkdir(exist_ok=True)

PERIODO_A = {"inicio": "2026-09-28", "fim": "2026-09-30"}
PERIODO_B = {"inicio": "2026-10-01", "fim": "2026-10-02"}

# Portas de serviços comuns que são alvo de varredura
PORTAS_COMPORTAMENTO = [22, 3389, 5060, 2323, 3306, 5900, 8443, 3000, 161, 8081]

def carregar_filterlog(arquivo):
    fluxos = []
    with open(arquivo, "r") as f:
        for linha in f:
            match = re.search(r'filterlog \d+ - \[meta sequenceId="\d+"\] (.+)$', linha)
            if not match:
                continue
            dados = match.group(1).strip().split(",")
            if len(dados) < 18:
                continue
            action = dados[6] if len(dados) > 6 else ""
            direcao = dados[7] if len(dados) > 7 else ""
            src_ip = dados[17] if len(dados) > 17 else ""
            dst_ip = dados[18] if len(dados) > 18 else ""
            src_port = dados[19] if len(dados) > 19 else ""
            dst_port = dados[20] if len(dados) > 20 else ""
            fluxos.append({
                "action": action,
                "dir": direcao,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
            })
    return fluxos

def carregar_eve(arquivo):
    alertas = []
    with open(arquivo, "r") as f:
        for linha in f:
            try:
                evt = json.loads(linha)
                if evt.get("event_type") == "alert":
                    alertas.append({
                        "timestamp": evt.get("timestamp", ""),
                        "src_ip": evt.get("src_ip", ""),
                        "dst_ip": evt.get("dest_ip", ""),
                        "src_port": evt.get("src_port", 0),
                        "dest_port": evt.get("dest_port", 0),
                        "sid": evt.get("alert", {}).get("signature_id", 0),
                        "category": evt.get("alert", {}).get("category", ""),
                    })
            except json.JSONDecodeError:
                continue
    return alertas

def classificar_periodo(timestamp, periodo):
    try:
        ts = timestamp[:10]
        return periodo["inicio"] <= ts <= periodo["fim"]
    except:
        return False

def carregar_crowdsec_ips():
    """Lê IPs da tabela crowdsec_blocklists do PF via arquivo de configuração."""
    # Os IPs do CrowdSec podem ser obtidos via API ou SSH
    # Por ora, vamos buscar via SSH do OPNsense
    import subprocess
    try:
        result = subprocess.run(
            ["ssh", "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=10",
             "root@172.16.0.1", "pfctl -t crowdsec_blocklists -T show"],
            capture_output=True, text=True, timeout=15
        )
        ips = set()
        for linha in result.stdout.strip().split("\n"):
            linha = linha.strip()
            if linha and not linha.startswith("-") and "." in linha:
                # Remove a máscara se presente
                ip = linha.split("/")[0]
                ips.add(ip)
        return ips
    except Exception as e:
        print(f"Erro ao carregar CrowdSec: {e}")
        return set()

def carregar_abuseip_ips():
    """Lê IPs da tabela ABUSEIP do PF via SSH."""
    import subprocess
    try:
        result = subprocess.run(
            ["ssh", "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=10",
             "root@172.16.0.1", "pfctl -t ABUSEIP -T show"],
            capture_output=True, text=True, timeout=30
        )
        ips = set()
        for linha in result.stdout.strip().split("\n"):
            linha = linha.strip()
            if linha and not linha.startswith("-") and "." in linha:
                ip = linha.split("/")[0]
                ips.add(ip)
        return ips
    except Exception as e:
        print(f"Erro ao carregar ABUSEIP: {e}")
        return set()

def main():
    print("=== Fase 3: Avaliação de Famílias ===\n")

    # Carregar dados
    eve_files = list(DATA_DIR.glob("suricata/eve*.json")) + list(DATA_DIR.glob("suricata/*.json"))
    alertas_a, alertas_b = [], []
    for arq in eve_files:
        for a in carregar_eve(arq):
            if classificar_periodo(a["timestamp"], PERIODO_A):
                alertas_a.append(a)
            elif classificar_periodo(a["timestamp"], PERIODO_B):
                alertas_b.append(a)

    pf_files = sorted(DATA_DIR.glob("pf/filter_*.log"))
    fluxos_a, fluxos_b = [], []
    for arq in pf_files:
        nome = arq.name
        if "20260928" in nome or "20260929" in nome or "20260930" in nome:
            fluxos_a.extend(carregar_filterlog(arq))
        elif "20261001" in nome or "20261002" in nome:
            fluxos_b.extend(carregar_filterlog(arq))

    # IPs externos que passaram no B (sem alerta)
    ips_passaram_b = set()
    fluxos_passaram_b = []
    for f in fluxos_b:
        if f["action"] == "pass":
            # Só IPs externos (não 192.168.x nem 172.16.x)
            src = f["src_ip"]
            if not src.startswith("192.168.") and not src.startswith("172.16."):
                ips_passaram_b.add(src)
                fluxos_passaram_b.append(f)

    # IPs externos bloqueados no B
    ips_bloqueados_b = set()
    for f in fluxos_b:
        if f["action"] == "block":
            src = f["src_ip"]
            if not src.startswith("192.168.") and not src.startswith("172.16."):
                ips_bloqueados_b.add(src)

    print(f"Período A: {len(alertas_a)} alertas, {len(fluxos_a)} fluxos PF")
    print(f"Período B: {len(alertas_b)} alertas, {len(fluxos_b)} fluxos PF")
    print(f"IPs externos que passaram no B: {len(ips_passaram_b)}")
    print(f"IPs externos bloqueados no B: {len(ips_bloqueados_b)}")
    print()

    # === Família 1: IP individual ===
    ips_alerta_a_externos = set(
        a["src_ip"] for a in alertas_a
        if not a["src_ip"].startswith("192.168.") and not a["src_ip"].startswith("172.16.")
    )
    cob_ip = ips_passaram_b & ips_alerta_a_externos
    # Colateral: IPs que passaram no B sem alerta mas seriam bloqueados
    ips_alerta_b = set(a["src_ip"] for a in alertas_b)
    colateral_ip = len(ips_passaram_b & ips_alerta_a_externos - ips_alerta_b)

    print("=== Família 1: IP individual ===")
    print(f"  Regras candidatas: {len(ips_alerta_a_externos)} IPs")
    print(f"  Cobertura incremental: {len(cob_ip)} fluxos ({len(cob_ip)/max(len(ips_passaram_b),1)*100:.1f}%)")
    print(f"  Bloqueio colateral: {colateral_ip} fluxos")

    # === Família 2: Comportamento (porta + taxa) ===
    # Contar alertas por porta no período A
    porta_alertas_a = Counter(a["dest_port"] for a in alertas_a)
    # Contar alertas por IP por porta no A (para taxa)
    ip_porta_a = defaultdict(lambda: defaultdict(int))
    for a in alertas_a:
        src = a["src_ip"]
        if not src.startswith("192.168.") and not src.startswith("172.16."):
            ip_porta_a[src][a["dest_port"]] += 1

    # Regra de comportamento: se um IP gerou > 5 alertas para uma porta no A
    # então bloquear esse IP + porta no B
    THRESHOLD = 5
    regras_comportamento = set()
    for ip, portas in ip_porta_a.items():
        for porta, count in portas.items():
            if count >= THRESHOLD:
                regras_comportamento.add((ip, porta))

    # Testar no B: quantos fluxos que passaram no B seriam bloqueados
    cob_comportamento = 0
    colateral_comportamento = 0
    for f in fluxos_passaram_b:
        porta = 0
        try:
            porta = int(f.get("dst_port", "0") or "0")
        except:
            pass
        if (f["src_ip"], porta) in regras_comportamento:
            cob_comportamento += 1
        elif f["src_ip"] not in ips_alerta_b:
            # Sem alerta no B — seria colateral
            for (ip_r, porta_r) in regras_comportamento:
                if ip_r == f["src_ip"] and porta_r == porta:
                    colateral_comportamento += 1
                    break

    print(f"\n=== Família 2: Comportamento (porta + taxa > {THRESHOLD}) ===")
    print(f"  Regras candidatas: {len(regras_comportamento)} (IP, porta)")
    print(f"  Cobertura incremental: {cob_comportamento} fluxos ({cob_comportamento/max(len(ips_passaram_b),1)*100:.1f}%)")
    print(f"  Bloqueio colateral: {colateral_comportamento} fluxos")

    # === Família 3: CrowdSec (baseline) ===
    print(f"\n=== Baseline: CrowdSec ===")
    crowdsec_ips = carregar_crowdsec_ips()
    print(f"  IPs na tabela crowdsec_blocklists: {len(crowdsec_ips)}")
    cob_crowdsec = len(ips_passaram_b & crowdsec_ips)
    colateral_crowdsec = len(ips_passaram_b & crowdsec_ips - ips_alerta_b)
    print(f"  Cobertura incremental: {cob_crowdsec} fluxos ({cob_crowdsec/max(len(ips_passaram_b),1)*100:.1f}%)")
    print(f"  Bloqueio colateral: {colateral_crowdsec} fluxos")

    # === Baseline: AbuseIPDB ===
    print(f"\n=== Baseline: AbuseIPDB (ABUSEIP) ===")
    abuseip_ips = carregar_abuseip_ips()
    print(f"  IPs na tabela ABUSEIP: {len(abuseip_ips)}")
    cob_abuseip = len(ips_passaram_b & abuseip_ips)
    colateral_abuseip = len(ips_passaram_b & abuseip_ips - ips_alerta_b)
    print(f"  Cobertura incremental: {cob_abuseip} fluxos ({cob_abuseip/max(len(ips_passaram_b),1)*100:.1f}%)")
    print(f"  Bloqueio colateral: {colateral_abuseip} fluxos")

    # === Resumo comparativo ===
    print(f"\n=== Resumo comparativo ===")
    print(f"{'Família':<25} {'Regras':<10} {'Cobertura':<12} {'Colateral':<12}")
    print(f"{'-'*59}")
    print(f"{'IP individual':<25} {len(ips_alerta_a_externos):<10} {len(cob_ip):<12} {colateral_ip:<12}")
    print(f"{'Comportamento':<25} {len(regras_comportamento):<10} {cob_comportamento:<12} {colateral_comportamento:<12}")
    print(f"{'CrowdSec':<25} {len(crowdsec_ips):<10} {cob_crowdsec:<12} {colateral_crowdsec:<12}")
    print(f"{'AbuseIPDB':<25} {len(abuseip_ips):<10} {cob_abuseip:<12} {colateral_abuseip:<12}")

    # Salvar resultado
    resultado = {
        "periodo_a": PERIODO_A,
        "periodo_b": PERIODO_B,
        "ips_passaram_b": len(ips_passaram_b),
        "ips_bloqueados_b": len(ips_bloqueados_b),
        "familias": {
            "ip_individual": {
                "regras": len(ips_alerta_a_externos),
                "cobertura_incremental": len(cob_ip),
                "bloqueio_colateral": colateral_ip,
            },
            "comportamento": {
                "regras": len(regras_comportamento),
                "cobertura_incremental": cob_comportamento,
                "bloqueio_colateral": colateral_comportamento,
                "threshold": THRESHOLD,
            },
            "crowdsec": {
                "regras": len(crowdsec_ips),
                "cobertura_incremental": cob_crowdsec,
                "bloqueio_colateral": colateral_crowdsec,
            },
            "abuseipdb": {
                "regras": len(abuseip_ips),
                "cobertura_incremental": cob_abuseip,
                "bloqueio_colateral": colateral_abuseip,
            },
        },
    }

    saida = EXPORTS / "avaliacao_familias.json"
    with open(saida, "w") as f:
        json.dump(resultado, f, indent=2, ensure_ascii=False)
    print(f"\nResultado salvo em {saida}")

if __name__ == "__main__":
    main()
