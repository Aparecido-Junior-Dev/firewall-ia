#!/usr/bin/env python3
"""
propor_regra.py — Fase A: Proposição de regras via API REST do OPNsense

Lê o CSV produzido pelo correlacionador (correlacao_sid2044008.csv),
agrupa os alertas por IP de origem, verifica se já existe regra equivalente,
propõe um bloqueio por IP de origem via API REST e gera relatório auditável.

Fluxo:
  1. Ler CSV de correlação
  2. Selecionar candidatos (status=candidato, pf_acao=block, sem regra prévia)
  3. Para cada IP único: verificar duplicata na API
  4. Criar regra com descrição "IA-aparecido: <justificativa>"
  5. Aplicar (apply) somente se --aplicar for passado
  6. Gravar relatório JSON + MD

Uso:
  python3 propor_regra.py [--csv ARQUIVO] [--aplicar] [--dry-run] [--remover-uuid UUID]

Flags:
  --csv       Caminho do CSV de correlação (padrão: reports/correlacao_sid2044008/correlacao_sid2044008.csv)
  --aplicar   Envia as regras para o OPNsense E chama /apply (sem esta flag é dry-run automático)
  --dry-run   Explícito: apenas mostra o que seria feito sem enviar nada
  --remover-uuid UUID   Remove uma regra específica pelo UUID (para testes/rollback)

Requisitos:
  - Python >= 3.10, apenas biblioteca padrão
  - /home/aparecido/firewall-ia/config/opnsense_api.conf com OPNSENSE_HOST, OPNSENSE_API_KEY, OPNSENSE_API_SECRET

Versão: 1.0.0
Data:   2026-10-18
"""

import argparse
import csv
import ipaddress
import json
import os
import sys
import urllib.request
import urllib.error
import ssl
import base64
from datetime import datetime, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# Constantes
# ---------------------------------------------------------------------------

VERSION      = "1.0.0"
PREFIXO_DESC = "IA-aparecido"          # prefixo obrigatório em todas as regras
INTERFACE    = "wan"                    # WAN = onde o tráfego inbound chega
DIRECAO      = "in"
PROTOCOLO    = "udp"
IPPROTO      = "inet"
PORTA_DEST   = "9034"                  # porta-alvo do CVE-2021-35394
SID          = 2044008
ASSINATURA   = "ET EXPLOIT Realtek SDK Command Execution/Backdoor Access Inbound"
CVE          = "CVE-2021-35394"

BASE_DIR     = Path(__file__).resolve().parent
# Se o script está em scripts/, sobe um nível para a raiz do projeto
PROJECT_DIR  = BASE_DIR.parent if BASE_DIR.name == "scripts" else BASE_DIR
CONFIG_FILE  = PROJECT_DIR / "config" / "opnsense_api.conf"
CSV_PADRAO   = PROJECT_DIR / "reports" / "correlacao_sid2044008" / "correlacao_sid2044008.csv"
REPORT_DIR   = PROJECT_DIR / "reports" / "propostas_regras"

# ---------------------------------------------------------------------------
# Carregamento de configuração
# ---------------------------------------------------------------------------

def carregar_config(caminho: Path) -> dict:
    """Lê arquivo .conf no formato KEY=VALUE, ignora comentários e linhas vazias."""
    if not caminho.exists():
        raise FileNotFoundError(f"Arquivo de configuração não encontrado: {caminho}")
    cfg = {}
    with caminho.open(encoding="utf-8") as f:
        for linha in f:
            linha = linha.strip()
            if not linha or linha.startswith("#"):
                continue
            if "=" not in linha:
                continue
            chave, _, valor = linha.partition("=")
            cfg[chave.strip()] = valor.strip()
    for campo in ("OPNSENSE_HOST", "OPNSENSE_API_KEY", "OPNSENSE_API_SECRET"):
        if campo not in cfg:
            raise ValueError(f"Campo obrigatório ausente no config: {campo}")
    return cfg


# ---------------------------------------------------------------------------
# Cliente HTTP minimalista para a API REST do OPNsense
# ---------------------------------------------------------------------------

class OPNsenseAPI:
    """
    Cliente para a API REST do OPNsense usando apenas urllib.
    Autenticação: HTTP Basic (key:secret).
    TLS: verificação desativada para certificado autoassinado residencial.
    """

    def __init__(self, host: str, key: str, secret: str, verify_tls: bool = False):
        self.base    = f"https://{host}"
        self._auth   = base64.b64encode(f"{key}:{secret}".encode()).decode()
        self._ctx    = ssl.create_default_context() if verify_tls else self._ctx_inseguro()

    @staticmethod
    def _ctx_inseguro() -> ssl.SSLContext:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        return ctx

    def _request(self, metodo: str, endpoint: str, corpo: dict | None = None) -> dict:
        url  = f"{self.base}/{endpoint.lstrip('/')}"
        data = json.dumps(corpo).encode() if corpo is not None else b"{}"
        req  = urllib.request.Request(
            url, data=data, method=metodo,
            headers={
                "Authorization": f"Basic {self._auth}",
                "Content-Type":  "application/json",
                "Accept":        "application/json",
            },
        )
        try:
            with urllib.request.urlopen(req, context=self._ctx, timeout=15) as resp:
                return json.loads(resp.read().decode())
        except urllib.error.HTTPError as exc:
            corpo_erro = exc.read().decode(errors="replace")
            raise RuntimeError(f"HTTP {exc.code} em {url}: {corpo_erro}") from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(f"Erro de rede em {url}: {exc.reason}") from exc

    def get(self, endpoint: str) -> dict:
        return self._request("GET", endpoint)

    def post(self, endpoint: str, corpo: dict | None = None) -> dict:
        return self._request("POST", endpoint, corpo)

    # --- Métodos de alto nível ---

    def buscar_regras(self, frase: str = "") -> list[dict]:
        """Retorna todas as regras que contenham 'frase' na descrição."""
        resp = self.post(
            "api/firewall/filter/searchRule",
            {"current": 1, "rowCount": 9999, "searchPhrase": frase},
        )
        return resp.get("rows", [])

    def criar_regra(self, payload: dict) -> dict:
        """Cria regra e retorna {'result': 'saved', 'uuid': '...'}."""
        return self.post("api/firewall/filter/addRule", {"rule": payload})

    def remover_regra(self, uuid: str) -> dict:
        return self.post(f"api/firewall/filter/delRule/{uuid}", {})

    def aplicar(self) -> dict:
        """Envia as regras pendentes ao PF (/apply)."""
        return self.post("api/firewall/filter/apply", {})


# ---------------------------------------------------------------------------
# Lógica de correlação / seleção de candidatos
# ---------------------------------------------------------------------------

def ler_csv(caminho: Path) -> list[dict]:
    """Lê o CSV de correlação e retorna lista de dicionários."""
    if not caminho.exists():
        raise FileNotFoundError(f"CSV de correlação não encontrado: {caminho}")
    with caminho.open(encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def selecionar_candidatos(linhas: list[dict]) -> list[dict]:
    """
    Retorna apenas alertas com status=candidato E pf_acao=block.
    Esses são os eventos onde a correlação identificou bloqueio pelo PF.
    Alertas sem_candidato são excluídos: não há evidência de bloqueio,
    e propor regra com base apenas no alerta Suricata seria prematuro.
    """
    return [
        r for r in linhas
        if r.get("status") == "candidato" and r.get("pf_acao") == "block"
    ]


def agrupar_por_ip(candidatos: list[dict]) -> dict[str, list[dict]]:
    """Agrupa alertas pelo IP de origem para evitar regras redundantes."""
    grupos: dict[str, list[dict]] = {}
    for row in candidatos:
        ip = row["src_ip"]
        grupos.setdefault(ip, []).append(row)
    return grupos


def validar_ip(ip_str: str) -> bool:
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Montagem do payload de regra
# ---------------------------------------------------------------------------

def montar_payload(ip_origem: str, alertas: list[dict]) -> dict:
    """
    Monta o payload para POST /api/firewall/filter/addRule.
    A descrição segue o padrão obrigatório "IA-aparecido: <justificativa>".
    """
    ids      = ",".join(str(a["alerta_id"]) for a in alertas)
    primeira = alertas[0]["eve_timestamp"]
    descricao = (
        f"{PREFIXO_DESC}: block {ip_origem} udp/{PORTA_DEST} "
        f"SID={SID} {CVE} alertas=[{ids}] gerado={datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%MZ')}"
    )
    # Truncar para o limite do campo (255 caracteres conforme Filter.xml)
    if len(descricao) > 255:
        descricao = descricao[:252] + "..."

    return {
        "enabled":          "1",
        "action":           "block",
        "quick":            "1",          # first-match (comportamento padrão do PF)
        "interface":        INTERFACE,
        "direction":        DIRECAO,
        "ipprotocol":       IPPROTO,
        "protocol":         PROTOCOLO,
        "source_net":       ip_origem,
        "source_not":       "0",
        "destination_net":  "any",
        "destination_not":  "0",
        "destination_port": PORTA_DEST,
        "log":              "1",          # registrar nos logs do firewall
        "description":      descricao,
    }


# ---------------------------------------------------------------------------
# Verificação de duplicata
# ---------------------------------------------------------------------------

def ja_existe(api: OPNsenseAPI, ip_origem: str) -> tuple[bool, str | None]:
    """
    Verifica se já existe regra IA-aparecido para este IP de origem.
    Retorna (existe, uuid_existente).
    """
    regras = api.buscar_regras(PREFIXO_DESC)
    for regra in regras:
        desc = regra.get("description", "")
        if PREFIXO_DESC in desc and ip_origem in desc:
            return True, regra.get("uuid")
    return False, None


# ---------------------------------------------------------------------------
# Execução principal
# ---------------------------------------------------------------------------

def executar(csv_path: Path, aplicar: bool, dry_run: bool) -> int:
    """Fluxo principal. Retorna código de saída (0=ok, 1=erro)."""

    ts_execucao = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    print(f"[{ts_execucao}] propor_regra.py v{VERSION}")
    print(f"Modo: {'DRY-RUN (nenhuma alteração será feita)' if dry_run or not aplicar else 'APLICAR — regras serão enviadas ao OPNsense'}")
    print()

    # 1. Configuração
    cfg = carregar_config(CONFIG_FILE)
    api = OPNsenseAPI(
        host       = cfg["OPNSENSE_HOST"],
        key        = cfg["OPNSENSE_API_KEY"],
        secret     = cfg["OPNSENSE_API_SECRET"],
        verify_tls = cfg.get("OPNSENSE_VERIFY_TLS", "false").lower() == "true",
    )

    # 2. Ler CSV
    linhas      = ler_csv(csv_path)
    candidatos  = selecionar_candidatos(linhas)
    grupos      = agrupar_por_ip(candidatos)

    print(f"CSV lido: {len(linhas)} linhas totais")
    print(f"Candidatos (status=candidato, pf_acao=block): {len(candidatos)}")
    print(f"IPs únicos de origem: {len(grupos)}")
    print()

    # 3. Processar cada IP
    resultados  = []
    erros       = []
    duplicatas  = []
    propostas   = []

    for ip, alertas in sorted(grupos.items()):
        if not validar_ip(ip):
            erros.append({"ip": ip, "motivo": "IP inválido"})
            print(f"  [ERRO] IP inválido ignorado: {ip}")
            continue

        existe, uuid_existente = (False, None) if dry_run else ja_existe(api, ip)

        if existe:
            duplicatas.append({"ip": ip, "uuid_existente": uuid_existente})
            print(f"  [DUPLICATA] {ip} já tem regra {uuid_existente[:8]}... — ignorado")
            continue

        payload    = montar_payload(ip, alertas)
        n_alertas  = len(alertas)
        delta_vals = [float(a["delta_pf_menos_eve_s"]) for a in alertas if a.get("delta_pf_menos_eve_s")]

        proposta = {
            "ip_origem":    ip,
            "n_alertas":    n_alertas,
            "alerta_ids":   [a["alerta_id"] for a in alertas],
            "timestamps":   [a["eve_timestamp"] for a in alertas],
            "delta_s":      delta_vals,
            "payload":      payload,
            "uuid":         None,
            "status":       "dry-run",
            "aplicada":     False,
        }

        print(f"  [PROPOSTA] {ip} — {n_alertas} alerta(s) — porta dest {PORTA_DEST}/udp")
        print(f"             Descrição: {payload['description']}")

        if not dry_run and aplicar:
            try:
                resp = api.criar_regra(payload)
                if resp.get("result") == "saved":
                    proposta["uuid"]   = resp["uuid"]
                    proposta["status"] = "criada"
                    print(f"             UUID: {resp['uuid']}")
                else:
                    proposta["status"] = f"falha: {resp}"
                    erros.append({"ip": ip, "motivo": str(resp)})
                    print(f"             [FALHA] resposta inesperada: {resp}")
            except RuntimeError as exc:
                proposta["status"] = f"erro: {exc}"
                erros.append({"ip": ip, "motivo": str(exc)})
                print(f"             [ERRO] {exc}")

        propostas.append(proposta)
        resultados.append(proposta)

    # 4. Apply
    status_apply = "não executado (dry-run)"
    if not dry_run and aplicar:
        regras_criadas = [p for p in propostas if p["status"] == "criada"]
        if regras_criadas:
            print()
            print(f"Chamando /apply para {len(regras_criadas)} regra(s) novas...")
            try:
                resp_apply = api.aplicar()
                status_apply = resp_apply.get("status", str(resp_apply)).strip()
                print(f"Apply: {status_apply}")
                for p in regras_criadas:
                    p["aplicada"] = True
            except RuntimeError as exc:
                status_apply = f"ERRO: {exc}"
                print(f"[ERRO no apply] {exc}")
        else:
            status_apply = "nenhuma regra nova para aplicar"
            print(f"\n{status_apply}")

    # 5. Relatório
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    ts_arquivo = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

    relatorio = {
        "versao_script":   VERSION,
        "timestamp":       ts_execucao,
        "modo":            "dry-run" if (dry_run or not aplicar) else "aplicar",
        "csv_entrada":     str(csv_path),
        "sid":             SID,
        "cve":             CVE,
        "assinatura":      ASSINATURA,
        "total_linhas_csv": len(linhas),
        "candidatos":      len(candidatos),
        "ips_unicos":      len(grupos),
        "propostas":       len(propostas),
        "duplicatas":      len(duplicatas),
        "erros":           len(erros),
        "status_apply":    status_apply,
        "detalhes_propostas": resultados,
        "detalhes_duplicatas": duplicatas,
        "detalhes_erros":  erros,
        "limitacoes": [
            "Correlação temporal não prova identidade de pacote.",
            "sem_candidato excluídos: ausência de registro PF não confirma tráfego permitido.",
            "Regra bloqueia IP de origem inteiro; pode afetar tráfego legítimo futuro do mesmo IP.",
            "Destino 192.168.15.200 pode não pertencer à LAN atual; NAT e topologia não verificados.",
            "Ambiente residencial real: rollback manual disponível via --remover-uuid UUID.",
        ],
    }

    json_path = REPORT_DIR / f"propostas_{ts_arquivo}.json"
    md_path   = REPORT_DIR / f"propostas_{ts_arquivo}.md"

    json_path.write_text(
        json.dumps(relatorio, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    # Markdown para apresentação
    criadas   = [p for p in resultados if p["status"] == "criada"]
    dry_list  = [p for p in resultados if p["status"] == "dry-run"]

    md_linhas = [
        f"# Relatório de Propostas de Regras — {ts_execucao}",
        "",
        f"**Script:** propor_regra.py v{VERSION}  ",
        f"**Modo:** {relatorio['modo']}  ",
        f"**CSV de entrada:** `{csv_path.name}`  ",
        f"**SID:** {SID} — {ASSINATURA}  ",
        f"**CVE:** {CVE}  ",
        "",
        "## Resumo",
        "",
        f"| Item | Valor |",
        f"|------|-------|",
        f"| Linhas no CSV | {len(linhas)} |",
        f"| Candidatos selecionados | {len(candidatos)} |",
        f"| IPs únicos | {len(grupos)} |",
        f"| Propostas geradas | {len(propostas)} |",
        f"| Regras criadas no OPNsense | {len(criadas)} |",
        f"| Duplicatas ignoradas | {len(duplicatas)} |",
        f"| Erros | {len(erros)} |",
        f"| Status do apply | `{status_apply}` |",
        "",
    ]

    if propostas:
        md_linhas += ["## Propostas", ""]
        for p in propostas:
            emoji = "✅" if p["status"] == "criada" else ("🔍" if p["status"] == "dry-run" else "❌")
            md_linhas.append(f"### {emoji} {p['ip_origem']}")
            md_linhas.append("")
            md_linhas.append(f"- **Alertas Suricata:** {p['n_alertas']} (IDs: {', '.join(str(i) for i in p['alerta_ids'])})")
            md_linhas.append(f"- **Ação proposta:** block {p['ip_origem']} → {INTERFACE}/in udp/{PORTA_DEST}")
            md_linhas.append(f"- **Descrição da regra:** `{p['payload']['description']}`")
            if p["uuid"]:
                md_linhas.append(f"- **UUID OPNsense:** `{p['uuid']}`")
                md_linhas.append(f"  - Rollback: `python3 propor_regra.py --remover-uuid {p['uuid']}`")
            md_linhas.append(f"- **Status:** {p['status']}")
            if p["delta_s"]:
                deltas = ", ".join(f"{d:.3f}s" for d in p["delta_s"])
                md_linhas.append(f"- **Δt Suricata→PF:** {deltas}")
            md_linhas.append("")

    if duplicatas:
        md_linhas += ["## Duplicatas ignoradas", ""]
        for d in duplicatas:
            md_linhas.append(f"- `{d['ip']}` — UUID existente: `{d['uuid_existente']}`")
        md_linhas.append("")

    if erros:
        md_linhas += ["## Erros", ""]
        for e in erros:
            md_linhas.append(f"- `{e['ip']}`: {e['motivo']}")
        md_linhas.append("")

    md_linhas += [
        "## Limitações e ressalvas",
        "",
        *[f"- {l}" for l in relatorio["limitacoes"]],
        "",
        "## Critérios de seleção",
        "",
        "Apenas alertas com `status=candidato` **e** `pf_acao=block` foram considerados.",
        "Alertas `sem_candidato` foram excluídos: a ausência de registro PF não permite",
        "concluir que o tráfego foi permitido, e propor bloqueio sem evidência seria especulativo.",
        "",
        f"*Gerado por propor_regra.py v{VERSION}*",
    ]

    md_path.write_text("\n".join(md_linhas) + "\n", encoding="utf-8")

    print()
    print(f"Relatório JSON: {json_path}")
    print(f"Relatório MD:   {md_path}")
    print()
    print("=== RESUMO FINAL ===")
    print(f"  Candidatos:     {len(candidatos)}")
    print(f"  Propostas:      {len(propostas)}")
    print(f"  Criadas:        {len(criadas)}")
    print(f"  Duplicatas:     {len(duplicatas)}")
    print(f"  Erros:          {len(erros)}")
    print(f"  Apply:          {status_apply}")

    return 0 if not erros else 1


# ---------------------------------------------------------------------------
# Rollback: remover regra por UUID
# ---------------------------------------------------------------------------

def remover_por_uuid(uuid: str) -> int:
    cfg = carregar_config(CONFIG_FILE)
    api = OPNsenseAPI(
        host       = cfg["OPNSENSE_HOST"],
        key        = cfg["OPNSENSE_API_KEY"],
        secret     = cfg["OPNSENSE_API_SECRET"],
        verify_tls = cfg.get("OPNSENSE_VERIFY_TLS", "false").lower() == "true",
    )
    print(f"Removendo regra {uuid}...")
    resp = api.remover_regra(uuid)
    print(f"Resposta: {resp}")
    if resp.get("result") == "deleted":
        resp_apply = api.aplicar()
        print(f"Apply: {resp_apply.get('status', resp_apply).strip()}")
        print("Regra removida e apply executado.")
        return 0
    print("AVISO: regra pode não ter sido encontrada.")
    return 1


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Propõe regras de firewall no OPNsense a partir do CSV de correlação Suricata×PF.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--csv", type=Path, default=CSV_PADRAO,
        help=f"CSV de correlação (padrão: {CSV_PADRAO})",
    )
    parser.add_argument(
        "--aplicar", action="store_true",
        help="Envia as regras ao OPNsense e executa /apply. Sem esta flag: apenas dry-run.",
    )
    parser.add_argument(
        "--dry-run", dest="dry_run", action="store_true",
        help="Explícito: apenas mostra o que seria feito (padrão quando --aplicar não é passado).",
    )
    parser.add_argument(
        "--remover-uuid", metavar="UUID",
        help="Remove uma regra específica pelo UUID (rollback).",
    )
    args = parser.parse_args()

    if args.remover_uuid:
        return remover_por_uuid(args.remover_uuid)

    return executar(
        csv_path = args.csv,
        aplicar  = args.aplicar,
        dry_run  = args.dry_run,
    )


if __name__ == "__main__":
    sys.exit(main())
