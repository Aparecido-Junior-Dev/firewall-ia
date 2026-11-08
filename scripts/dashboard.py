#!/usr/bin/env python3
"""
dashboard.py — Dashboard web em tempo real do projeto Firewall IA

Exibe ao vivo:
  - Status das regras IA-aparecido no OPNsense (via API REST)
  - Regras ativas no PF (pfctl -sr via SSH)
  - Resumo da correlação Suricata × PF
  - Últimas propostas geradas
  - Log de eventos do dashboard

Acesso: http://172.16.0.125:8080
Atualização automática via SSE (Server-Sent Events) a cada 15 segundos.

Uso:
  .venv/bin/python scripts/dashboard.py [--port 8080] [--intervalo 15]

Versão: 1.0.0
Data:   2026-10-18
"""

import argparse
import base64
import csv
import json
import os
import queue
import ssl
import subprocess
import sys
import threading
import time
import urllib.request
import urllib.error
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, Response, render_template_string, jsonify

# ---------------------------------------------------------------------------
# Caminhos
# ---------------------------------------------------------------------------

BASE_DIR    = Path(__file__).resolve().parent
PROJECT_DIR = BASE_DIR.parent if BASE_DIR.name == "scripts" else BASE_DIR
CONFIG_FILE = PROJECT_DIR / "config" / "opnsense_api.conf"
CSV_CORR    = PROJECT_DIR / "reports" / "correlacao_sid2044008" / "correlacao_sid2044008.csv"
RESUMO_JSON = PROJECT_DIR / "reports" / "correlacao_sid2044008" / "resumo.json"
PROPOSTAS   = PROJECT_DIR / "reports" / "propostas_regras"
RESUMO_V2   = PROJECT_DIR / "reports" / "correlacao_v2" / "resumo_v2.json"
VERSION     = "2.0.0"

# ---------------------------------------------------------------------------
# Config OPNsense
# ---------------------------------------------------------------------------

def carregar_config():
    cfg = {}
    if not CONFIG_FILE.exists():
        return cfg
    with CONFIG_FILE.open(encoding="utf-8") as f:
        for linha in f:
            linha = linha.strip()
            if not linha or linha.startswith("#") or "=" not in linha:
                continue
            k, _, v = linha.partition("=")
            cfg[k.strip()] = v.strip()
    return cfg


def opnsense_get(endpoint: str, cfg: dict) -> dict | None:
    host   = cfg.get("OPNSENSE_HOST", "172.16.0.1")
    key    = cfg.get("OPNSENSE_API_KEY", "")
    secret = cfg.get("OPNSENSE_API_SECRET", "")
    auth   = base64.b64encode(f"{key}:{secret}".encode()).decode()
    ctx    = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode    = ssl.CERT_NONE
    url = f"https://{host}/{endpoint.lstrip('/')}"
    try:
        req = urllib.request.Request(
            url, data=b"{}",
            method="POST",
            headers={"Authorization": f"Basic {auth}",
                     "Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, context=ctx, timeout=8) as r:
            return json.loads(r.read().decode())
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Coleta de dados
# ---------------------------------------------------------------------------

def coletar_regras_ia(cfg: dict) -> list[dict]:
    """Busca regras IA-aparecido na API do OPNsense."""
    resp = opnsense_get(
        "api/firewall/filter/searchRule",
        cfg,
    )
    # POST com body correto
    host   = cfg.get("OPNSENSE_HOST", "172.16.0.1")
    key    = cfg.get("OPNSENSE_API_KEY", "")
    secret = cfg.get("OPNSENSE_API_SECRET", "")
    auth   = base64.b64encode(f"{key}:{secret}".encode()).decode()
    ctx    = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode    = ssl.CERT_NONE
    url  = f"https://{host}/api/firewall/filter/searchRule"
    body = json.dumps({"current": 1, "rowCount": 9999,
                       "searchPhrase": "IA-aparecido"}).encode()
    try:
        req = urllib.request.Request(
            url, data=body, method="POST",
            headers={"Authorization": f"Basic {auth}",
                     "Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, context=ctx, timeout=8) as r:
            dados = json.loads(r.read().decode())
            return dados.get("rows", [])
    except Exception as exc:
        return [{"erro": str(exc)}]


def coletar_pf_regras_ia() -> list[str]:
    """Lê regras PF ativas via SSH (pfctl -sr | grep 9034)."""
    try:
        result = subprocess.run(
            ["ssh", "-i", str(Path.home() / ".ssh/id_ed25519"),
             "-o", "StrictHostKeyChecking=no",
             "-o", "ConnectTimeout=5",
             "root@172.16.0.1",
             "pfctl -sr | grep IA-aparecido || pfctl -sr | grep 9034"],
            capture_output=True, text=True, timeout=10,
        )
        linhas = [l.strip() for l in result.stdout.splitlines() if l.strip()]
        return linhas if linhas else ["(nenhuma regra 9034 ativa no PF)"]
    except Exception as exc:
        return [f"Erro SSH: {exc}"]


def coletar_resumo_correlacao() -> dict:
    """Lê o resumo.json da correlação."""
    if not RESUMO_JSON.exists():
        return {"erro": "resumo.json não encontrado"}
    try:
        return json.loads(RESUMO_JSON.read_text(encoding="utf-8"))
    except Exception as exc:
        return {"erro": str(exc)}


def coletar_csv_correlacao() -> list[dict]:
    """Lê o CSV de correlação."""
    if not CSV_CORR.exists():
        return []
    try:
        with CSV_CORR.open(encoding="utf-8", newline="") as f:
            return list(csv.DictReader(f))
    except Exception:
        return []


def coletar_resumo_v2() -> dict:
    """Lê o resumo da correlação v2 (community_id)."""
    if not RESUMO_V2.exists():
        return {}
    try:
        return json.loads(RESUMO_V2.read_text(encoding="utf-8"))
    except Exception:
        return {}
def coletar_ultima_proposta() -> dict:
    """Lê o JSON da última proposta gerada."""
    if not PROPOSTAS.exists():
        return {}
    arquivos = sorted(PROPOSTAS.glob("propostas_*.json"))
    if not arquivos:
        return {}
    try:
        return json.loads(arquivos[-1].read_text(encoding="utf-8"))
    except Exception:
        return {}


def coletar_todos_dados() -> dict:
    """Agrega todos os dados em um único dicionário."""
    cfg         = carregar_config()
    ts          = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    regras_api  = coletar_regras_ia(cfg)
    pf_linhas   = coletar_pf_regras_ia()
    resumo      = coletar_resumo_correlacao()
    resumo_v2   = coletar_resumo_v2()
    correlacao  = coletar_csv_correlacao()
    proposta    = coletar_ultima_proposta()

    # Status geral
    n_regras_ia = len([r for r in regras_api if "erro" not in r])
    n_pf_ativas = len([l for l in pf_linhas if "block" in l])

    status_geral = "OK"
    if not cfg:
        status_geral = "ERRO: config não encontrada"
    elif not regras_api or "erro" in (regras_api[0] if regras_api else {}):
        status_geral = "ERRO: API OPNsense inacessível"

    return {
        "timestamp":        ts,
        "status_geral":     status_geral,
        "regras_api":       regras_api,
        "n_regras_ia":      n_regras_ia,
        "pf_linhas":        pf_linhas,
        "n_pf_ativas":      n_pf_ativas,
        "resumo":           resumo,
        "correlacao":       correlacao,
        "proposta":         proposta,
        "resumo_v2":        resumo_v2,
        "opnsense_host":    cfg.get("OPNSENSE_HOST", "?"),
        "versao":           VERSION,
    }


# ---------------------------------------------------------------------------
# Cache com atualização em background
# ---------------------------------------------------------------------------

_cache: dict = {}
_cache_lock  = threading.Lock()
_sse_clients: list[queue.Queue] = []
_sse_lock    = threading.Lock()


def atualizar_cache(intervalo: int):
    """Thread que atualiza o cache e notifica clientes SSE."""
    global _cache
    while True:
        try:
            dados = coletar_todos_dados()
            with _cache_lock:
                _cache = dados
            # Notificar todos os clientes SSE
            payload = json.dumps(dados, ensure_ascii=False)
            mortos  = []
            with _sse_lock:
                for q in _sse_clients:
                    try:
                        q.put_nowait(payload)
                    except queue.Full:
                        mortos.append(q)
                for q in mortos:
                    _sse_clients.remove(q)
        except Exception:
            pass
        time.sleep(intervalo)


# ---------------------------------------------------------------------------
# HTML do dashboard
# ---------------------------------------------------------------------------

HTML = """<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Firewall IA — Dashboard</title>
<style>
  :root {
    --bg:       #0f1117;
    --card:     #1a1d27;
    --border:   #2a2d3e;
    --accent:   #4f8ef7;
    --green:    #2ecc71;
    --yellow:   #f1c40f;
    --red:      #e74c3c;
    --text:     #e0e4f0;
    --muted:    #7a7f99;
    --mono:     'Courier New', monospace;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: var(--bg); color: var(--text); font-family: 'Segoe UI', system-ui, sans-serif; font-size: 14px; }
  header { background: var(--card); border-bottom: 1px solid var(--border); padding: 14px 24px; display: flex; align-items: center; justify-content: space-between; }
  header h1 { font-size: 18px; font-weight: 600; letter-spacing: .5px; }
  header h1 span { color: var(--accent); }
  #status-badge { padding: 4px 12px; border-radius: 20px; font-size: 12px; font-weight: 600; }
  .ok    { background: #1a3a2a; color: var(--green); border: 1px solid var(--green); }
  .erro  { background: #3a1a1a; color: var(--red);   border: 1px solid var(--red); }
  #ts { font-size: 11px; color: var(--muted); margin-left: 12px; }
  main { display: grid; grid-template-columns: repeat(auto-fit, minmax(340px, 1fr)); gap: 16px; padding: 20px 24px; }
  .card { background: var(--card); border: 1px solid var(--border); border-radius: 10px; padding: 16px; }
  .card h2 { font-size: 13px; text-transform: uppercase; letter-spacing: 1px; color: var(--muted); margin-bottom: 12px; display: flex; align-items: center; gap: 8px; }
  .card h2 .dot { width: 8px; height: 8px; border-radius: 50%; display: inline-block; }
  .dot-green  { background: var(--green); box-shadow: 0 0 6px var(--green); }
  .dot-blue   { background: var(--accent); box-shadow: 0 0 6px var(--accent); }
  .dot-yellow { background: var(--yellow); box-shadow: 0 0 6px var(--yellow); }
  .dot-red    { background: var(--red); box-shadow: 0 0 6px var(--red); }
  .stat-row { display: flex; justify-content: space-between; align-items: center; padding: 6px 0; border-bottom: 1px solid var(--border); }
  .stat-row:last-child { border-bottom: none; }
  .stat-label { color: var(--muted); font-size: 12px; }
  .stat-val { font-weight: 600; font-size: 16px; }
  .val-green  { color: var(--green); }
  .val-yellow { color: var(--yellow); }
  .val-red    { color: var(--red); }
  .val-blue   { color: var(--accent); }
  table { width: 100%; border-collapse: collapse; font-size: 12px; }
  th { color: var(--muted); text-align: left; padding: 4px 8px; border-bottom: 1px solid var(--border); font-weight: 500; }
  td { padding: 5px 8px; border-bottom: 1px solid #1e2130; vertical-align: top; }
  tr:last-child td { border-bottom: none; }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 10px; font-size: 11px; font-weight: 600; }
  .badge-green  { background: #1a3a2a; color: var(--green); }
  .badge-red    { background: #3a1a1a; color: var(--red); }
  .badge-yellow { background: #3a3010; color: var(--yellow); }
  .badge-blue   { background: #1a2a4a; color: var(--accent); }
  .mono { font-family: var(--mono); font-size: 11px; word-break: break-all; color: #b0b8d8; }
  .pf-line { font-family: var(--mono); font-size: 11px; color: #b0b8d8; padding: 4px 0; border-bottom: 1px solid #1e2130; word-break: break-all; }
  .pf-line:last-child { border-bottom: none; }
  #pulse { width: 10px; height: 10px; border-radius: 50%; background: var(--green); display: inline-block; margin-right: 8px; animation: pulse 2s infinite; }
  @keyframes pulse { 0%,100%{opacity:1;transform:scale(1)} 50%{opacity:.4;transform:scale(.8)} }
  .full-width { grid-column: 1 / -1; }
  .uuid { font-family: var(--mono); font-size: 10px; color: var(--muted); }
  footer { text-align: center; padding: 16px; color: var(--muted); font-size: 11px; border-top: 1px solid var(--border); margin-top: 8px; }
</style>
</head>
<body>
<header>
  <h1>🔥 Firewall <span>IA</span> — Dashboard</h1>
  <div style="display:flex;align-items:center">
    <span id="pulse"></span>
    <span id="status-badge" class="ok">OK</span>
    <span id="ts">carregando...</span>
  </div>
</header>

<main id="main">
  <!-- Cards injetados via JS -->
  <div class="card full-width" style="text-align:center;padding:40px;color:var(--muted)">
    Conectando ao servidor... aguarde.
  </div>
</main>

<footer>
  Firewall IA Dashboard v{{ versao }} &nbsp;·&nbsp; OPNsense {{ host }} &nbsp;·&nbsp;
  Atualização automática a cada <strong>{{ intervalo }}s</strong> via SSE
</footer>

<script>
const intervalo = {{ intervalo }};

function badge(txt, cor) {
  return `<span class="badge badge-${cor}">${txt}</span>`;
}

function render(d) {
  // Header
  const ok = d.status_geral === 'OK';
  document.getElementById('status-badge').textContent = d.status_geral;
  document.getElementById('status-badge').className   = ok ? 'ok' : 'erro';
  document.getElementById('ts').textContent = '  ' + d.timestamp;

  // Cards
  let html = '';

  // ── Card 1: Contadores gerais ──────────────────────────────────────────
  const r = d.resumo || {};
  html += `<div class="card">
  <h2><span class="dot dot-blue"></span>Correlação Suricata × PF</h2>
  <div class="stat-row"><span class="stat-label">Arquivo EVE analisado</span><span class="stat-val val-blue">${r.alertas || 0} alertas SID ${r.sid || '?'}</span></div>
  <div class="stat-row"><span class="stat-label">Janela de correlação</span><span class="stat-val">±${r.janela_segundos || 5} s</span></div>
  <div class="stat-row"><span class="stat-label">Com candidato PF</span><span class="stat-val val-green">${r.com_candidato || 0}</span></div>
  <div class="stat-row"><span class="stat-label">Sem candidato PF</span><span class="stat-val val-yellow">${r.sem_candidato || 0}</span></div>
  <div class="stat-row"><span class="stat-label">Ação PF correlacionada</span><span class="stat-val val-green">${JSON.stringify(r.acoes_pf_por_par || {})}</span></div>
  <div class="stat-row"><span class="stat-label">Linhas PF processadas</span><span class="stat-val">${(r.pf_linhas||0).toLocaleString('pt-BR')}</span></div>
  </div>`;

  // ── Card 2: Regras IA-aparecido no OPNsense ───────────────────────────
  const regras = (d.regras_api || []).filter(r => !r.erro);
  const errApi = (d.regras_api || []).find(r => r.erro);
  html += `<div class="card">
  <h2><span class="dot dot-green"></span>Regras IA-aparecido — OPNsense API</h2>`;
  if (errApi) {
    html += `<div style="color:var(--red);font-size:12px">${errApi.erro}</div>`;
  } else if (regras.length === 0) {
    html += `<div style="color:var(--muted);font-size:12px">Nenhuma regra encontrada.</div>`;
  } else {
    html += `<div style="margin-bottom:8px">${badge(regras.length + ' regras ativas', 'green')}</div>`;
    html += `<table><thead><tr><th>IP Origem</th><th>Porta</th><th>Ação</th><th>UUID</th></tr></thead><tbody>`;
    for (const rg of regras) {
      const desc  = rg.description || '';
      const ipParts = desc.split('block ');
    const ipMatch = ipParts.length > 1 ? [null, ipParts[1].split(' ')[0]] : null;
      const ip    = ipMatch ? ipMatch[1] : (rg.source_net || '?');
      const porta = rg.destination_port || '?';
      const acao  = rg.action || '?';
      const uuid  = (rg.uuid || '').substring(0,8) + '...';
      const cor   = acao === 'block' ? 'red' : 'green';
      html += `<tr>
        <td class="mono">${ip}</td>
        <td>${porta}/udp</td>
        <td>${badge(acao, cor)}</td>
        <td class="uuid">${uuid}</td>
      </tr>`;
    }
    html += `</tbody></table>`;
  }
  html += `</div>`;

  // ── Card 3: PF ativo (pfctl) ──────────────────────────────────────────
  html += `<div class="card">
  <h2><span class="dot dot-red"></span>PF Ativo — pfctl -sr (porta 9034)</h2>`;
  html += `<div style="margin-bottom:8px">${badge(d.n_pf_ativas + ' regras no PF', d.n_pf_ativas > 0 ? 'green' : 'yellow')}</div>`;
  for (const l of (d.pf_linhas || [])) {
    const cor = l.includes('block') ? '#ffb3b3' : l.startsWith('Erro') ? '#f1c40f' : '#b0b8d8';
    html += `<div class="pf-line" style="color:${cor}">${escHtml(l)}</div>`;
  }
  html += `</div>`;

  // ── Card 4: Detalhes da última proposta ───────────────────────────────
  const p = d.proposta || {};
  html += `<div class="card">
  <h2><span class="dot dot-yellow"></span>Última Proposta de Regras</h2>`;
  if (!p.timestamp) {
    html += `<div style="color:var(--muted);font-size:12px">Nenhuma proposta encontrada.</div>`;
  } else {
    html += `<div class="stat-row"><span class="stat-label">Timestamp</span><span class="mono">${p.timestamp}</span></div>`;
    html += `<div class="stat-row"><span class="stat-label">Modo</span><span>${badge(p.modo||'?','blue')}</span></div>`;
    html += `<div class="stat-row"><span class="stat-label">Propostas</span><span class="stat-val val-blue">${p.propostas||0}</span></div>`;
    html += `<div class="stat-row"><span class="stat-label">Criadas</span><span class="stat-val val-green">${(p.detalhes_propostas||[]).filter(x=>x.status==='criada').length}</span></div>`;
    html += `<div class="stat-row"><span class="stat-label">Duplicatas ignoradas</span><span class="stat-val val-yellow">${p.duplicatas||0}</span></div>`;
    html += `<div class="stat-row"><span class="stat-label">Apply status</span><span>${badge(p.status_apply||'?', p.status_apply==='OK'?'green':'red')}</span></div>`;
    html += `<div class="stat-row"><span class="stat-label">Script versão</span><span class="mono">${p.versao_script||'?'}</span></div>`;
  }
  html += `</div>`;


  // --- Card v2: Funil por desfecho (community_id) ---
  const rv2 = d.resumo_v2 || {};
  if (rv2.por_desfecho) {
    const pd = rv2.por_desfecho;
    const dtrilha = rv2.por_desfecho_trilha || {};
    const cid_ok = rv2.communityid_ativo;
    html += '<div class="card full-width">';
    html += '<h2><span class="dot dot-green"></span>Correlação v2 &mdash; Community ID &mdash; todos os alertas</h2>';
    html += '<div style="margin-bottom:8px">' + badge(cid_ok ? "community_id ATIVO" : "fallback tupla", cid_ok ? "green" : "yellow") + '&nbsp;' + badge((rv2.alertas_selecionados||0).toLocaleString("pt-BR") + " alertas", "blue") + '</div>';
    html += '<div style="overflow-x:auto"><table><thead><tr><th>Desfecho</th><th>Interna</th><th>Reputação</th><th>Comportamento</th><th>Total</th></tr></thead><tbody>';
    const desfechos2 = [["BLOQUEADO","red"],["PASSOU","green"],["SEM_REGISTRO","yellow"],["AMBOS","blue"]];
    for (const [d2,cor] of desfechos2) {
      const i_ = (dtrilha[d2+"|interna"]||0).toLocaleString("pt-BR");
      const r_ = (dtrilha[d2+"|reputacao"]||0).toLocaleString("pt-BR");
      const c_ = (dtrilha[d2+"|comportamento"]||0).toLocaleString("pt-BR");
      const t_ = (pd[d2]||0).toLocaleString("pt-BR");
      html += '<tr><td>' + badge(d2,cor) + '</td><td class="mono">' + i_ + '</td><td class="mono">' + r_ + '</td><td class="mono">' + c_ + '</td><td class="mono" style="font-weight:600">' + t_ + '</td></tr>';
    }
    html += '</tbody></table></div></div>';
  }

  // ── Card 5 (full): Tabela de correlação ───────────────────────────────
  const corr = d.correlacao || [];
  html += `<div class="card full-width">
  <h2><span class="dot dot-blue"></span>Tabela de Correlação — ${corr.length} eventos SID ${r.sid||'?'}</h2>
  <div style="overflow-x:auto">
  <table><thead><tr>
    <th>#</th><th>IP Origem</th><th>Timestamp Suricata</th>
    <th>Status</th><th>Δt (s)</th><th>Ação PF</th><th>Interface</th><th>Arquivo PF</th>
  </tr></thead><tbody>`;
  for (const c of corr) {
    const stCor = c.status === 'candidato' ? 'green' : 'yellow';
    const pfCor = c.pf_acao === 'block' ? 'red' : c.pf_acao ? 'green' : '';
    const dt    = c.delta_pf_menos_eve_s ? parseFloat(c.delta_pf_menos_eve_s).toFixed(3)+'s' : '—';
    const arq   = c.pf_arquivo ? c.pf_arquivo.split('/').pop() : '—';
    html += `<tr>
      <td>${c.alerta_id}</td>
      <td class="mono">${c.src_ip}</td>
      <td class="mono">${c.eve_timestamp}</td>
      <td>${badge(c.status, stCor)}</td>
      <td class="mono">${dt}</td>
      <td>${c.pf_acao ? badge(c.pf_acao, pfCor) : '—'}</td>
      <td class="mono">${c.pf_interface||'—'}</td>
      <td class="mono">${arq}</td>
    </tr>`;
  }
  html += `</tbody></table></div></div>`;

  document.getElementById('main').innerHTML = html;
}

function escHtml(s) {
  return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

// SSE — atualizações em tempo real
const evtSource = new EventSource('/stream');
evtSource.onmessage = e => {
  try { render(JSON.parse(e.data)); } catch(err) { console.error(err); }
};
evtSource.onerror = () => {
  document.getElementById('pulse').style.background = 'var(--red)';
};

// Carga inicial via REST para não esperar o primeiro ciclo do SSE
fetch('/dados').then(r=>r.json()).then(render).catch(console.error);
</script>
</body>
</html>
"""

# ---------------------------------------------------------------------------
# Flask app
# ---------------------------------------------------------------------------

app = Flask(__name__)
_intervalo_global = 15


@app.route("/")
def index():
    cfg = carregar_config()
    return render_template_string(
        HTML,
        versao=VERSION,
        host=cfg.get("OPNSENSE_HOST", "?"),
        intervalo=_intervalo_global,
    )


@app.route("/dados")
def dados():
    with _cache_lock:
        return jsonify(_cache if _cache else coletar_todos_dados())


@app.route("/stream")
def stream():
    """Server-Sent Events — envia dados ao cliente a cada atualização."""
    q: queue.Queue = queue.Queue(maxsize=5)
    with _sse_lock:
        _sse_clients.append(q)

    def gerar():
        try:
            # Envia snapshot imediato
            with _cache_lock:
                snap = _cache if _cache else coletar_todos_dados()
            yield f"data: {json.dumps(snap, ensure_ascii=False)}\n\n"
            while True:
                try:
                    payload = q.get(timeout=30)
                    yield f"data: {payload}\n\n"
                except queue.Empty:
                    yield ": keepalive\n\n"
        except GeneratorExit:
            pass
        finally:
            with _sse_lock:
                if q in _sse_clients:
                    _sse_clients.remove(q)

    return Response(
        gerar(),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.route("/api/status")
def api_status():
    """Endpoint JSON puro para automação/monitoramento externo."""
    with _cache_lock:
        dados_atual = _cache if _cache else coletar_todos_dados()
    return jsonify({
        "timestamp":    dados_atual.get("timestamp"),
        "status_geral": dados_atual.get("status_geral"),
        "n_regras_ia":  dados_atual.get("n_regras_ia"),
        "n_pf_ativas":  dados_atual.get("n_pf_ativas"),
        "versao":       VERSION,
    })


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    global _intervalo_global
    parser = argparse.ArgumentParser(
        description="Dashboard web em tempo real — Firewall IA",
    )
    parser.add_argument("--port",      type=int, default=8080, help="Porta HTTP (padrão: 8080)")
    parser.add_argument("--intervalo", type=int, default=15,   help="Segundos entre atualizações (padrão: 15)")
    parser.add_argument("--host",      default="0.0.0.0",      help="Bind address (padrão: 0.0.0.0)")
    args = parser.parse_args()

    _intervalo_global = args.intervalo

    # Carga inicial síncrona antes de subir o servidor
    print(f"[{datetime.now(timezone.utc).strftime('%H:%M:%S')}] Coletando dados iniciais...")
    with _cache_lock:
        _cache.update(coletar_todos_dados())
    print(f"[{datetime.now(timezone.utc).strftime('%H:%M:%S')}] Dados prontos.")

    # Thread de atualização contínua
    t = threading.Thread(
        target=atualizar_cache, args=(args.intervalo,), daemon=True
    )
    t.start()

    print(f"[{datetime.now(timezone.utc).strftime('%H:%M:%S')}] Dashboard disponível em http://172.16.0.125:{args.port}")
    print(f"[{datetime.now(timezone.utc).strftime('%H:%M:%S')}] Atualização automática a cada {args.intervalo}s")
    print("  Ctrl+C para parar.\n")

    app.run(host=args.host, port=args.port, debug=False, threaded=True)


if __name__ == "__main__":
    main()
