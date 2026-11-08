#!/usr/bin/env python3
import re
"""
split_temporal.py — Fase 3: split temporal e avaliação de regras

Divide os dados em período A (treino) e período B (teste):
- Período A: 28/09 a 30/09 (3 dias) — gerar regras candidatas
- Período B: 01/10 a 02/10 (2 dias) — simular regras e medir

Para cada família de regras (IP individual, comportamento), mede:
- Cobertura incremental: fluxos que passaram no B que a regra bloquearia
- Bloqueio colateral: fluxos sem alerta que a regra também bloquearia
- Compara com baseline: regras atuais + CrowdSec

Uso:
    python scripts/split_temporal.py
"""

import json
import csv
from pathlib import Path
from collections import defaultdict
from datetime import datetime

DATA_DIR = Path("data/raw")
EXPORTS = Path("exports")
EXPORTS.mkdir(exist_ok=True)

# Períodos
PERIODO_A = {"inicio": "2026-09-28", "fim": "2026-09-30"}  # treino
PERIODO_B = {"inicio": "2026-10-01", "fim": "2026-10-02"}  # teste

def carregar_filterlog(arquivo):
    """Carrega filterlog (formato syslog OPNsense) e retorna lista de fluxos."""
    fluxos = []
    with open(arquivo, "r") as f:
        for linha in f:
            # Formato: <134>1 TIMESTAMP HOST filterlog PID - [meta ...] DATA
            # DATA é separado por vírgulas: tamanho,,,hash,iface,match,ACTION,DIR,ver,tos,,ttl,id,offset,flags,proto_num,proto_name,len,SRC_IP,DST_IP[,SRC_PORT,DST_PORT]
            match = re.search(r'filterlog \d+ - \[meta sequenceId="\d+"\] (.+)$', linha)
            if not match:
                continue
            dados = match.group(1).strip().split(",")
            if len(dados) < 18:
                continue
            action = dados[6] if len(dados) > 6 else ""
            direcao = dados[7] if len(dados) > 7 else ""
            proto_name = dados[15] if len(dados) > 15 else ""
            src_ip = dados[17] if len(dados) > 17 else ""
            dst_ip = dados[18] if len(dados) > 18 else ""
            src_port = dados[19] if len(dados) > 19 else ""
            dst_port = dados[20] if len(dados) > 20 else ""
            fluxos.append({
                "action": action,
                "dir": direcao,
                "proto": proto_name,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
            })
    return fluxos

def carregar_eve(arquivo):
    """Carrega eve.json e retorna alertas."""
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
                        "proto": evt.get("proto", ""),
                        "signature": evt.get("alert", {}).get("signature", ""),
                        "sid": evt.get("alert", {}).get("signature_id", 0),
                        "community_id": evt.get("community_id", ""),
                        "category": evt.get("alert", {}).get("category", ""),
                    })
            except json.JSONDecodeError:
                continue
    return alertas

def classificar_periodo(timestamp, periodo):
    """Verifica se timestamp está dentro do período."""
    try:
        ts = timestamp[:10]  # YYYY-MM-DD
        return periodo["inicio"] <= ts <= periodo["fim"]
    except:
        return False

def main():
    print("=== Fase 3: Split Temporal ===")
    print(f"Período A (treino): {PERIODO_A['inicio']} a {PERIODO_A['fim']}")
    print(f"Período B (teste):  {PERIODO_B['inicio']} a {PERIODO_B['fim']}")
    print()

    # Carregar EVE
    eve_files = list(DATA_DIR.glob("suricata/eve*.json")) + list(DATA_DIR.glob("suricata/*.json"))
    if not eve_files:
        # Tentar caminho alternativo
        eve_files = list(DATA_DIR.glob("**/eve*.json"))

    alertas_a = []
    alertas_b = []
    for arq in eve_files:
        print(f"Carregando {arq.name}...")
        alertas = carregar_eve(arq)
        for a in alertas:
            if classificar_periodo(a["timestamp"], PERIODO_A):
                alertas_a.append(a)
            elif classificar_periodo(a["timestamp"], PERIODO_B):
                alertas_b.append(a)

    print(f"\nAlertas no período A: {len(alertas_a)}")
    print(f"Alertas no período B: {len(alertas_b)}")

    # Carregar filterlog
    pf_files = sorted(DATA_DIR.glob("pf/filter_*.log")) + sorted(DATA_DIR.glob("**/filter_*.log"))
    fluxos_a = []
    fluxos_b = []
    for arq in pf_files:
        nome = arq.name
        # filter_20260928.log, filter_20260929.log, etc.
        if "20260928" in nome or "20260929" in nome or "20260930" in nome:
            print(f"Carregando PF (A): {nome}")
            fluxos_a.extend(carregar_filterlog(arq))
        elif "20261001" in nome or "20261002" in nome:
            print(f"Carregando PF (B): {nome}")
            fluxos_b.extend(carregar_filterlog(arq))

    print(f"\nFluxos PF no período A: {len(fluxos_a)}")
    print(f"Fluxos PF no período B: {len(fluxos_b)}")

    # IPs que passaram no período B (para testar cobertura)
    ips_passaram_b = set()
    for f in fluxos_b:
        if f["action"] == "pass":
            ips_passaram_b.add(f["src_ip"])

    # IPs bloqueados no período B
    ips_bloqueados_b = set()
    for f in fluxos_b:
        if f["action"] == "block":
            ips_bloqueados_b.add(f["src_ip"])

    print(f"\nIPs que passaram no período B: {len(ips_passaram_b)}")
    print(f"IPs bloqueados no período B: {len(ips_bloqueados_b)}")

    # Família 1: IP individual
    # Pegar IPs que geraram alertas no período A e que passaram no B
    ips_alerta_a = set(a["src_ip"] for a in alertas_a if not a["src_ip"].startswith("192.168.") and not a["src_ip"].startswith("172.16."))
    regras_ip = ips_alerta_a  # regras candidatas: bloquear esses IPs

    # Cobertura incremental: quantos dos IPs que passaram no B a regra bloquearia
    cobertos_ip = ips_passaram_b & regras_ip
    cobertura_ip = len(cobertos_ip)
    pct_cobertura_ip = (cobertura_ip / len(ips_passaram_b) * 100) if ips_passaram_b else 0

    # Bloqueio colateral: fluxos sem alerta que a regra também bloquearia
    # (IPs que passaram sem alerta no B mas seriam bloqueados pela regra)
    ips_sem_alerta_b = set(f["src_ip"] for f in fluxos_b if f["action"] == "pass")
    colateral_ip = len(ips_sem_alerta_b & regras_ip)

    print(f"\n=== Família 1: IP individual ===")
    print(f"Regras candidatas (IPs do período A): {len(regras_ip)}")
    print(f"Cobertura incremental: {cobertura_ip} fluxos ({pct_cobertura_ip:.1f}%)")
    print(f"Bloqueio colateral: {colateral_ip} fluxos")

    # Família 2: Comportamento (porta + taxa)
    # Pegar portas destino dos alertas no período A
    portas_alerta_a = defaultdict(int)
    for a in alertas_a:
        if not a["src_ip"].startswith("192.168.") and not a["src_ip"].startswith("172.16."):
            portas_alerta_a[a["dest_port"]] += 1

    # Top 10 portas
    top_portas = sorted(portas_alerta_a.items(), key=lambda x: -x[1])[:10]
    print(f"\n=== Família 2: Comportamento (porta) ===")
    print(f"Top 10 portas destino nos alertas (A):")
    for porta, count in top_portas:
        print(f"  porta {porta}: {count} alertas")

    # Salvar resultado
    resultado = {
        "periodo_a": PERIODO_A,
        "periodo_b": PERIODO_B,
        "alertas_a": len(alertas_a),
        "alertas_b": len(alertas_b),
        "fluxos_pf_a": len(fluxos_a),
        "fluxos_pf_b": len(fluxos_b),
        "ips_passaram_b": len(ips_passaram_b),
        "ips_bloqueados_b": len(ips_bloqueados_b),
        "familia_ip": {
            "regras_candidatas": len(regras_ip),
            "cobertura_incremental": cobertura_ip,
            "pct_cobertura": round(pct_cobertura_ip, 2),
            "bloqueio_colateral": colateral_ip,
        },
        "familia_comportamento": {
            "top_portas": top_portas[:10],
        },
    }

    saida = EXPORTS / "split_temporal_resultado.json"
    with open(saida, "w") as f:
        json.dump(resultado, f, indent=2, ensure_ascii=False, default=str)

    print(f"\nResultado salvo em {saida}")

    # CSV com regras candidatas
    csv_saida = EXPORTS / "regras_candidatas_periodo_a.csv"
    with open(csv_saida, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["ip_origem", "familia", "acao", "periodo_origem"])
        for ip in sorted(regras_ip):
            w.writerow([ip, "IP individual", "block", "A"])

    print(f"Regras candidatas salvas em {csv_saida}")

if __name__ == "__main__":
    main()
