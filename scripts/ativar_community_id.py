#!/usr/bin/env python3
"""
ativar_community_id.py — Ativa community_id e log em pass no OPNsense via API REST

O que faz:
  1. Verifica se community_id já está ativo no Suricata
  2. Se não, ativa via API (IDS Settings)
  3. Reinicia o Suricata para aplicar
  4. Verifica quantas regras pass estão sem log e ativa log nelas
  5. Aplica as mudanças no PF

Por que é necessário (conforme feedback do prof. Diego):
  - community_id permite junção exata entre evento Suricata e registro PF
  - sem ele, a correlação depende de janela temporal (±5s) e pode ter falsos positivos
  - log em pass já está ativo nos dados históricos, mas confirmar para coletas futuras

ATENÇÃO: este script modifica a configuração do Suricata e do PF.
  - O Suricata será reiniciado (breve interrupção da detecção)
  - Regras pass passarão a gerar mais logs (aumento de volume no filterlog)
  - Execute em horário de baixo tráfego

Uso:
  python3 ativar_community_id.py [--dry-run] [--so-community-id] [--so-log-pass]

Versão: 1.0.0
Data:   2026-10-21
"""

import argparse
import base64
import json
import ssl
import sys
import urllib.request
import urllib.error
from pathlib import Path

CONFIG_FILE = Path(__file__).resolve().parent.parent / "firewall-ia" / "config" / "opnsense_api.conf"


def carregar_config():
    cfg = {}
    with CONFIG_FILE.open(encoding="utf-8") as f:
        for linha in f:
            linha = linha.strip()
            if not linha or linha.startswith("#") or "=" not in linha:
                continue
            k, _, v = linha.partition("=")
            cfg[k.strip()] = v.strip()
    return cfg


def api_call(cfg, metodo, endpoint, corpo=None):
    host   = cfg["OPNSENSE_HOST"]
    key    = cfg["OPNSENSE_API_KEY"]
    secret = cfg["OPNSENSE_API_SECRET"]
    auth   = base64.b64encode(f"{key}:{secret}".encode()).decode()
    ctx    = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode    = ssl.CERT_NONE
    url    = f"https://{host}/{endpoint.lstrip('/')}"
    data   = json.dumps(corpo or {}).encode()
    req    = urllib.request.Request(
        url, data=data, method=metodo,
        headers={"Authorization": f"Basic {auth}",
                 "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=15) as r:
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"HTTP {e.code}: {e.read().decode()[:200]}")
    except Exception as e:
        raise RuntimeError(f"Erro: {e}")


def verificar_community_id(cfg):
    """Verifica se community_id está ativo nas configurações do Suricata."""
    try:
        resp = api_call(cfg, "GET", "api/ids/settings/getSettings")
        cid = resp.get("ids", {}).get("community-id", "0")
        print(f"  community_id atual: {cid}")
        return cid == "1"
    except RuntimeError as e:
        print(f"  Erro ao consultar configurações IDS: {e}")
        return None


def ativar_community_id(cfg, dry_run=False):
    """Ativa community_id no Suricata."""
    print("\n[1] Community ID no Suricata")
    ativo = verificar_community_id(cfg)

    if ativo is None:
        print("  Não foi possível verificar. Verifique o OPNsense manualmente:")
        print("  Services → Intrusion Detection → Advanced Settings → community-id: yes")
        return False

    if ativo:
        print("  ✅ community_id já está ativo.")
        return True

    print("  ❌ community_id NÃO está ativo.")
    if dry_run:
        print("  [DRY-RUN] Seria ativado via API.")
        return False

    try:
        resp = api_call(cfg, "POST", "api/ids/settings/setSettings",
                        {"ids": {"community-id": "1"}})
        if resp.get("result") == "saved":
            print("  Configuração salva. Reiniciando Suricata...")
            resp2 = api_call(cfg, "POST", "api/ids/service/restart", {})
            print(f"  Restart: {resp2}")
            print("  ✅ community_id ativado. Novos logs terão o campo.")
            print("  ⚠  Logs históricos NÃO terão community_id retroativamente.")
            return True
        else:
            print(f"  Resposta inesperada: {resp}")
            return False
    except RuntimeError as e:
        print(f"  Erro: {e}")
        print("  Tente manualmente: Services → Intrusion Detection → Advanced Settings")
        return False


def verificar_log_pass(cfg):
    """Conta regras pass com e sem log."""
    try:
        resp = api_call(cfg, "POST", "api/firewall/filter/searchRule",
                        {"current": 1, "rowCount": 9999, "searchPhrase": ""})
        rows = resp.get("rows", [])
        pass_sem_log = [r for r in rows if r.get("action") == "pass" and not r.get("log")]
        pass_com_log = [r for r in rows if r.get("action") == "pass" and r.get("log")]
        print(f"  Regras pass COM log: {len(pass_com_log)}")
        print(f"  Regras pass SEM log: {len(pass_sem_log)}")
        return pass_sem_log
    except RuntimeError as e:
        print(f"  Erro: {e}")
        return []


def ativar_log_pass(cfg, dry_run=False):
    """Ativa log nas regras pass que ainda não têm."""
    print("\n[2] Log nas regras pass")

    # Nota: nos dados históricos coletados, o log em pass JÁ está ativo
    # (66.958 registros pass/dia no filterlog). Esta função é para
    # confirmar e garantir para coletas futuras.

    print("  NOTA: dados históricos já contêm 66.958 registros pass/dia.")
    print("  Isso confirma que o log em pass já está ativo no OPNsense.")
    print("  Esta verificação é para garantir coletas futuras.")

    regras_sem_log = verificar_log_pass(cfg)

    if not regras_sem_log:
        print("  ✅ Todas as regras pass já têm log ativo.")
        return True

    if dry_run:
        print(f"  [DRY-RUN] {len(regras_sem_log)} regras seriam atualizadas.")
        for r in regras_sem_log[:5]:
            print(f"    UUID: {r.get('uuid','?')[:8]}... desc: {r.get('description','')[:50]}")
        return False

    atualizadas = 0
    for regra in regras_sem_log:
        uuid = regra.get("uuid")
        if not uuid:
            continue
        try:
            resp = api_call(cfg, "POST", f"api/firewall/filter/setRule/{uuid}",
                            {"rule": {"log": "1"}})
            if resp.get("result") == "saved":
                atualizadas += 1
        except RuntimeError:
            pass

    if atualizadas:
        print(f"  Ativando log em {atualizadas} regras. Aplicando...")
        api_call(cfg, "POST", "api/firewall/filter/apply", {})
        print(f"  ✅ {atualizadas} regras atualizadas e apply executado.")

    return True


def main():
    parser = argparse.ArgumentParser(
        description="Ativa community_id no Suricata e log em pass no PF"
    )
    parser.add_argument("--dry-run", action="store_true",
                        help="Mostra o que faria sem alterar nada")
    parser.add_argument("--so-community-id", action="store_true",
                        help="Executa apenas a ativação do community_id")
    parser.add_argument("--so-log-pass", action="store_true",
                        help="Executa apenas a verificação do log em pass")
    args = parser.parse_args()

    print(f"ativar_community_id.py v1.0.0")
    print(f"Modo: {'DRY-RUN' if args.dry_run else 'APLICAR'}\n")

    if not CONFIG_FILE.exists():
        print(f"ERRO: config não encontrada em {CONFIG_FILE}")
        sys.exit(1)

    cfg = carregar_config()

    if not args.so_log_pass:
        ativar_community_id(cfg, dry_run=args.dry_run)

    if not args.so_community_id:
        ativar_log_pass(cfg, dry_run=args.dry_run)

    print("\n=== PRÓXIMOS PASSOS ===")
    print("1. Coletar novos logs por 1-2 semanas com community_id ativo")
    print("2. Implementar cálculo de community_id para o filterlog:")
    print("   community_id = hash(proto + src_ip + src_port + dst_ip + dst_port)")
    print("   Biblioteca: pip install communityid")
    print("3. Substituir correlação por tupla+janela por junção exata por community_id")
    print("4. Classificar cada alerta: bloqueado | passou | sem_registro")


if __name__ == "__main__":
    main()
