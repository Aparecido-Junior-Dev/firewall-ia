#!/usr/bin/env python3
"""
correlacionar_v2.py — Correlacionador Suricata × PF com Community ID

Evolução do correlacionar_sid.py (v1) implementando a recomendação do
prof. Diego: substituir a correlação por tupla+janela temporal por junção
exata via Community ID (RFC draft-ietf-dots-signal-channel).

Diferenças em relação à v1:
  - Calcula community_id para cada evento PF a partir dos campos da tupla
  - Usa community_id como chave primária de junção (junção exata)
  - Mantém janela temporal apenas como critério secundário de desambiguação
  - Classifica cada alerta em: BLOQUEADO | PASSOU | SEM_REGISTRO
  - Processa TODOS os alertas do arquivo EVE, não apenas um SID específico
  - Separa trilhas: interna, reputação, comportamento

Requisitos:
  pip install communityid
  (além disso, apenas biblioteca padrão Python 3.10+)

Uso:
  python3 correlacionar_v2.py [--sid SID] [--janela S] [--dry-run]
  python3 correlacionar_v2.py --todos-sid --trilhas

Versão: 2.0.0
Data:   2026-10-21
"""

import argparse
import csv
import ipaddress
import json
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

try:
    import communityid
    COMMUNITYID_OK = True
except ImportError:
    COMMUNITYID_OK = False
    print("AVISO: biblioteca 'communityid' não instalada. "
          "Usando fallback de tupla+janela. "
          "Instale com: pip install communityid", file=sys.stderr)

BASE_DIR    = Path(__file__).resolve().parent
PROJECT_DIR = BASE_DIR.parent if BASE_DIR.name == "scripts" else BASE_DIR
EVE_PATH    = PROJECT_DIR / "data/raw/suricata/eve_20260927_20261004.json"
PF_PATHS    = [PROJECT_DIR / f"data/raw/pf/filter_{d}.log"
               for d in ("20260928","20260929","20260930","20261001","20261002")]
REPORT_DIR  = PROJECT_DIR / "reports" / "correlacao_v2"

NOTICE = (
    "Community ID calculado a partir da tupla (proto, src_ip, src_port, dst_ip, dst_port). "
    "Junção exata substitui a janela temporal da v1. "
    "BLOQUEADO = alerta tem par PF com action=block. "
    "PASSOU = alerta tem par PF com action=pass. "
    "SEM_REGISTRO = nenhum par PF encontrado (possível lacuna de log, NAT ou cobertura)."
)

# IPs privados conhecidos a tratar separadamente
REDES_PRIVADAS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]

# Assinaturas de reputação pura (não comportamento)
CATS_REPUTACAO = {
    "Misc Activity",          # ET CINS, ET DROP
    "Potentially Bad Traffic",
    "Not Suspicious Traffic",
    "Unknown Traffic",
    "Potential Corporate Privacy Violation",
}


# ---------------------------------------------------------------------------
# Community ID
# ---------------------------------------------------------------------------

def calc_community_id(proto: str, src_ip: str, src_port: int,
                       dst_ip: str, dst_port: int) -> str | None:
    """Calcula community_id para uma tupla de fluxo."""
    if not COMMUNITYID_OK:
        return None
    try:
        cid = communityid.CommunityID()
        p = proto.upper()
        if p == "TCP":
            tpl = communityid.FlowTuple.make_tcp(src_ip, dst_ip, src_port, dst_port)
        elif p == "UDP":
            tpl = communityid.FlowTuple.make_udp(src_ip, dst_ip, src_port, dst_port)
        elif p == "ICMP":
            tpl = communityid.FlowTuple.make_icmp(src_ip, dst_ip, 0, 0)
        else:
            return None
        return cid.calc(tpl)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Classificação de trilha
# ---------------------------------------------------------------------------

def classificar_trilha(src_ip: str, categoria: str) -> str:
    """Classifica o alerta em: interna | reputacao | comportamento."""
    try:
        ip = ipaddress.ip_address(src_ip)
        for rede in REDES_PRIVADAS:
            if ip in rede:
                return "interna"
    except ValueError:
        pass
    if categoria in CATS_REPUTACAO:
        return "reputacao"
    return "comportamento"


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

HEADER_PF = __import__("re").compile(
    r'^<\d+>\d+\s+(\S+)\s+\S+\s+filterlog\s+\S+\s+\S+\s+'
    r'(?:-|(?:\[(?:[^\\\]]|\\.)*\])+)\s+(.*)$'
)


def ts_utc(value: str) -> datetime:
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        raise ValueError("timestamp sem timezone")
    return dt.astimezone(timezone.utc)


def parse_pf_linha(line: str) -> dict | None:
    """Parseia linha filterlog e retorna dict com community_id calculado."""
    if "filterlog" not in line:
        return None
    m = HEADER_PF.match(line.rstrip())
    if not m:
        return None
    ts_str, payload = m.groups()
    try:
        dt = ts_utc(ts_str)
        fields = list(csv.reader([payload]))[0]
        if len(fields) < 9:
            return None

        ipver = fields[8]
        if ipver == "4":
            proto_id, proto_txt, start = 15, 16, 18
        elif ipver == "6":
            proto_id, proto_txt, start = 13, 12, 15
        else:
            return None

        if len(fields) <= max(proto_txt, proto_id):
            return None
        if fields[proto_id] != "17" and fields[proto_id] != "6":
            return None   # só UDP(17) e TCP(6) por ora
        if len(fields) < start + 4:
            return None

        proto = "UDP" if fields[proto_id] == "17" else "TCP"
        src_ip  = str(ipaddress.ip_address(fields[start]))
        dst_ip  = str(ipaddress.ip_address(fields[start + 1]))
        src_port = int(fields[start + 2])
        dst_port = int(fields[start + 3])

        cid = calc_community_id(proto, src_ip, src_port, dst_ip, dst_port)

        return {
            "time":         dt,
            "timestamp":    ts_str,
            "community_id": cid,
            "src_ip":       src_ip,
            "dst_ip":       dst_ip,
            "src_port":     src_port,
            "dst_port":     dst_port,
            "proto":        proto,
            "iface":        fields[4],
            "action":       fields[6],   # pass | block | rdr
            "direction":    fields[7],
            "rule":         fields[0],
            "tracker":      fields[3],
        }
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Indexação do PF
# ---------------------------------------------------------------------------

def indexar_pf(pf_paths: list[Path], verbose: bool = True) -> dict:
    """
    Lê todos os arquivos PF e constrói índice:
      community_id → lista de eventos PF
    Para eventos sem community_id (fallback), usa tupla como chave.
    """
    indice: dict[str, list[dict]] = defaultdict(list)
    contadores = Counter()

    for path in pf_paths:
        if not path.exists():
            print(f"  AVISO: arquivo PF não encontrado: {path}", file=sys.stderr)
            continue
        with path.open(encoding="utf-8") as f:
            for n, line in enumerate(f, 1):
                contadores["linhas"] += 1
                try:
                    ev = parse_pf_linha(line)
                    if ev is None:
                        continue
                    contadores["eventos_udp_tcp"] += 1
                    chave = ev["community_id"] or f"{ev['proto']}|{ev['src_ip']}|{ev['src_port']}|{ev['dst_ip']}|{ev['dst_port']}"
                    ev["arquivo"] = str(path)
                    ev["linha"]   = n
                    indice[chave].append(ev)
                    contadores[f"action_{ev['action']}"] += 1
                except Exception:
                    contadores["erros"] += 1

    if verbose:
        print(f"  PF indexado: {contadores['linhas']:,} linhas, "
              f"{contadores['eventos_udp_tcp']:,} eventos UDP/TCP")
        print(f"  pass: {contadores['action_pass']:,}  "
              f"block: {contadores['action_block']:,}  "
              f"rdr: {contadores['action_rdr']:,}")
        print(f"  Chaves únicas no índice: {len(indice):,}")

    return dict(indice), contadores


# ---------------------------------------------------------------------------
# Correlação principal
# ---------------------------------------------------------------------------

def correlacionar(eve_path: Path, pf_index: dict, pf_counts: Counter,
                  sid: int | None = None, janela_s: float = 30.0,
                  todos_sid: bool = False) -> tuple[list, dict]:
    """
    Para cada alerta EVE:
      1. Calcula community_id
      2. Busca no índice PF por community_id exato
      3. Se encontrar, classifica como BLOQUEADO ou PASSOU
      4. Se não encontrar, classifica como SEM_REGISTRO
      5. Determina trilha: interna | reputacao | comportamento
    """
    alertas = []
    contadores = Counter()

    with eve_path.open(encoding="utf-8") as f:
        for n, line in enumerate(f, 1):
            if not line.strip():
                continue
            contadores["eve_linhas"] += 1
            try:
                ev = json.loads(line)
                if ev.get("event_type") != "alert":
                    continue
                contadores["alertas"] += 1

                alert_data = ev.get("alert", {})
                ev_sid = alert_data.get("signature_id")

                # Filtro por SID se especificado
                if sid is not None and ev_sid != sid:
                    continue

                contadores["alertas_selecionados"] += 1

                proto    = ev.get("proto", "").upper()
                src_ip   = ev.get("src_ip", "")
                dst_ip   = ev.get("dest_ip", "")
                src_port = int(ev.get("src_port", 0))
                dst_port = int(ev.get("dest_port", 0))

                # Community ID do alerta
                cid = ev.get("community_id") or calc_community_id(
                    proto, src_ip, src_port, dst_ip, dst_port
                )

                # Trilha
                categoria = alert_data.get("category", "")
                trilha    = classificar_trilha(src_ip, categoria)

                # Busca no índice PF
                chave_cid   = cid
                chave_tupla = f"{proto}|{src_ip}|{src_port}|{dst_ip}|{dst_port}"

                candidatos_pf = []
                if chave_cid and chave_cid in pf_index:
                    candidatos_pf = pf_index[chave_cid]
                elif chave_tupla in pf_index:
                    candidatos_pf = pf_index[chave_tupla]

                # Classificação
                if not candidatos_pf:
                    desfecho = "SEM_REGISTRO"
                    contadores["SEM_REGISTRO"] += 1
                else:
                    acoes = {p["action"] for p in candidatos_pf}
                    if "block" in acoes and "pass" not in acoes:
                        desfecho = "BLOQUEADO"
                        contadores["BLOQUEADO"] += 1
                    elif "pass" in acoes and "block" not in acoes:
                        desfecho = "PASSOU"
                        contadores["PASSOU"] += 1
                    else:
                        desfecho = "AMBOS"   # pass e block — incomum
                        contadores["AMBOS"] += 1

                contadores[f"trilha_{trilha}"] += 1

                alertas.append({
                    "eve_linha":       n,
                    "eve_timestamp":   ev.get("timestamp"),
                    "eve_utc":         ts_utc(ev.get("timestamp")).isoformat(),
                    "sid":             ev_sid,
                    "assinatura":      alert_data.get("signature", ""),
                    "categoria":       categoria,
                    "severidade":      alert_data.get("severity"),
                    "src_ip":          src_ip,
                    "dst_ip":          dst_ip,
                    "src_port":        src_port,
                    "dst_port":        dst_port,
                    "proto":           proto,
                    "iface":           ev.get("in_iface", ""),
                    "community_id":    cid,
                    "cid_fonte":       "eve" if ev.get("community_id") else "calculado",
                    "trilha":          trilha,
                    "desfecho":        desfecho,
                    "n_candidatos_pf": len(candidatos_pf),
                    "acoes_pf":        sorted({p["action"] for p in candidatos_pf}),
                    "pf_timestamps":   [p["timestamp"] for p in candidatos_pf[:3]],
                    "pf_ifaces":       sorted({p["iface"] for p in candidatos_pf}),
                    "pf_arquivos":     sorted({p["arquivo"].split("/")[-1]
                                               for p in candidatos_pf}),
                })

            except Exception as exc:
                contadores["erros_eve"] += 1
                print(f"  ERRO linha {n}: {exc}", file=sys.stderr)

    return alertas, dict(contadores), dict(pf_counts)


# ---------------------------------------------------------------------------
# Salvamento
# ---------------------------------------------------------------------------

CAMPOS_CSV = [
    "eve_linha", "eve_timestamp", "eve_utc", "sid", "assinatura",
    "categoria", "severidade", "src_ip", "dst_ip", "src_port", "dst_port",
    "proto", "iface", "community_id", "cid_fonte", "trilha", "desfecho",
    "n_candidatos_pf", "acoes_pf", "pf_timestamps", "pf_ifaces", "pf_arquivos",
]


def salvar(alertas: list, contadores_eve: dict, contadores_pf: dict,
           sid: int | None, janela_s: float, out_dir: Path):
    out_dir.mkdir(parents=True, exist_ok=True)

    # CSV
    csv_path = out_dir / "correlacao_v2.csv"
    with csv_path.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=CAMPOS_CSV, extrasaction="ignore")
        w.writeheader()
        for a in alertas:
            row = dict(a)
            row["acoes_pf"]     = "|".join(row["acoes_pf"])
            row["pf_timestamps"] = "|".join(row["pf_timestamps"])
            row["pf_ifaces"]    = "|".join(row["pf_ifaces"])
            row["pf_arquivos"]  = "|".join(row["pf_arquivos"])
            w.writerow(row)

    # Resumo por desfecho
    por_desfecho = Counter(a["desfecho"] for a in alertas)
    por_trilha   = Counter(a["trilha"]   for a in alertas)
    por_desfecho_trilha = Counter((a["desfecho"], a["trilha"]) for a in alertas)

    # Top SIDs por desfecho
    top_passou = Counter(a["sid"] for a in alertas if a["desfecho"] == "PASSOU")
    top_passou_sigs = {sid: next((a["assinatura"] for a in alertas
                                  if a["sid"] == sid), "?")
                       for sid, _ in top_passou.most_common(10)}

    resumo = {
        "versao":             "2.0.0",
        "timestamp":          datetime.now(timezone.utc).isoformat(),
        "eve_path":           str(EVE_PATH),
        "pf_paths":           [str(p) for p in PF_PATHS if p.exists()],
        "sid_filtro":         sid,
        "janela_s_secundaria": janela_s,
        "communityid_ativo":  COMMUNITYID_OK,
        "eve_linhas":         contadores_eve.get("eve_linhas", 0),
        "alertas_total":      contadores_eve.get("alertas", 0),
        "alertas_selecionados": contadores_eve.get("alertas_selecionados", 0),
        "pf_linhas":          contadores_pf.get("linhas", 0),
        "pf_eventos_udp_tcp": contadores_pf.get("eventos_udp_tcp", 0),
        "pf_chaves_unicas":   contadores_pf.get("chaves", 0),
        "por_desfecho":       dict(por_desfecho),
        "por_trilha":         dict(por_trilha),
        "por_desfecho_trilha": {f"{d}|{t}": c
                                for (d, t), c in por_desfecho_trilha.most_common()},
        "top10_passou_sids":  {str(k): {"count": v, "sig": top_passou_sigs[k]}
                               for k, v in top_passou.most_common(10)},
        "observacao":         NOTICE,
    }

    json_path = out_dir / "resumo_v2.json"
    json_path.write_text(json.dumps(resumo, ensure_ascii=False, indent=2) + "\n",
                         encoding="utf-8")

    # Markdown
    md = [
        "# Correlação v2 — Community ID",
        "",
        f"**Versão:** 2.0.0  ",
        f"**Data:** {resumo['timestamp'][:10]}  ",
        f"**Community ID ativo:** {'✅ sim' if COMMUNITYID_OK else '❌ não (fallback tupla)'}  ",
        f"**Alertas analisados:** {resumo['alertas_selecionados']:,}  ",
        "",
        "## Desfecho por trilha",
        "",
        "| Desfecho | Interna | Reputação | Comportamento | Total |",
        "|---|---:|---:|---:|---:|",
    ]
    for desfecho in ("BLOQUEADO", "PASSOU", "SEM_REGISTRO", "AMBOS"):
        row = [desfecho]
        for trilha in ("interna", "reputacao", "comportamento"):
            row.append(str(por_desfecho_trilha.get((desfecho, trilha), 0)))
        row.append(str(por_desfecho.get(desfecho, 0)))
        md.append("| " + " | ".join(row) + " |")

    md += [
        "",
        "## Top 10 SIDs com tráfego que PASSOU",
        "",
        "| SID | Alertas | Assinatura |",
        "|---|---:|---|",
    ]
    for sid_k, v in top_passou.most_common(10):
        md.append(f"| {sid_k} | {v} | {top_passou_sigs[sid_k][:60]} |")

    md += [
        "",
        "## Observação metodológica",
        "",
        NOTICE,
        "",
        f"*Gerado por correlacionar_v2.py v2.0.0*",
    ]
    (out_dir / "resumo_v2.md").write_text("\n".join(md) + "\n", encoding="utf-8")

    return csv_path, json_path


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Correlacionador Suricata × PF com Community ID (v2)"
    )
    parser.add_argument("--sid",    type=int, default=None,
                        help="Filtrar por SID específico (padrão: todos)")
    parser.add_argument("--janela", type=float, default=30.0,
                        help="Janela temporal secundária em segundos (padrão: 30)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Apenas mostra estatísticas sem salvar")
    args = parser.parse_args()

    print(f"correlacionar_v2.py v2.0.0")
    print(f"Community ID: {'ativo' if COMMUNITYID_OK else 'INATIVO (fallback tupla)'}")
    print(f"SID filtro: {args.sid or 'todos'}")
    print()

    # Verificar arquivos
    for p in [EVE_PATH, *PF_PATHS]:
        if not p.exists():
            print(f"AVISO: arquivo não encontrado: {p}", file=sys.stderr)

    # Indexar PF
    print("Indexando logs PF...")
    pf_index, pf_counts = indexar_pf(
        [p for p in PF_PATHS if p.exists()], verbose=True
    )
    pf_counts["chaves"] = len(pf_index)
    print()

    # Correlacionar
    print("Correlacionando alertas EVE...")
    alertas, eve_counts, _ = correlacionar(
        EVE_PATH, pf_index, pf_counts,
        sid=args.sid, janela_s=args.janela
    )
    print(f"  Alertas selecionados: {eve_counts.get('alertas_selecionados',0):,}")
    print()

    # Resumo
    por_desfecho = Counter(a["desfecho"] for a in alertas)
    por_trilha   = Counter(a["trilha"]   for a in alertas)

    print("=== DESFECHO ===")
    for d in ("BLOQUEADO", "PASSOU", "SEM_REGISTRO", "AMBOS"):
        print(f"  {d:15s}: {por_desfecho.get(d, 0):6,}")
    print()
    print("=== TRILHA ===")
    for t in ("interna", "reputacao", "comportamento"):
        print(f"  {t:15s}: {por_trilha.get(t, 0):6,}")

    if args.dry_run:
        print("\n[DRY-RUN] Nenhum arquivo salvo.")
        return

    # Salvar
    print("\nSalvando relatórios...")
    csv_p, json_p = salvar(alertas, eve_counts, pf_counts,
                           args.sid, args.janela, REPORT_DIR)
    print(f"  CSV:  {csv_p}")
    print(f"  JSON: {json_p}")
    print(f"  MD:   {REPORT_DIR / 'resumo_v2.md'}")


if __name__ == "__main__":
    main()
