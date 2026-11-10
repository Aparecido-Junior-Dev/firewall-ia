#!/usr/bin/env python3
"""
dashboard_v2.py — Dashboard com mapa de ataques em tempo real
Acesso: http://172.16.0.125:8080
Versão: 2.0.0
"""
import argparse, base64, csv, json, os, queue, ssl, subprocess
import sys, threading, time, urllib.request, urllib.error
from datetime import datetime, timezone
from pathlib import Path
from flask import Flask, Response, render_template_string, jsonify

BASE_DIR    = Path(__file__).resolve().parent if '__file__' in dir() else Path.cwd()
PROJECT_DIR = BASE_DIR.parent if BASE_DIR.name == "scripts" else BASE_DIR
CONFIG_FILE = PROJECT_DIR / "config" / "opnsense_api.conf"
RESUMO_V2   = PROJECT_DIR / "reports" / "correlacao_v2" / "resumo_v2.json"
PROPOSTAS   = PROJECT_DIR / "reports" / "propostas_regras"
EVE_FILE    = PROJECT_DIR / "data" / "raw" / "suricata" / "eve_20260927_20261004.json"
VERSION     = "2.0.0"

# ── Geolocalização dos blocos de IP mais comuns nos alertas reais ──────────
GEO_DB = {
    "85.217":  {"lat": 46.2,  "lon":  2.2,  "pais": "França",       "flag": "🇫🇷"},
    "85.185":  {"lat": 46.2,  "lon":  2.2,  "pais": "França",       "flag": "🇫🇷"},
    "195.184": {"lat": 46.8,  "lon":  8.2,  "pais": "Suíça",        "flag": "🇨🇭"},
    "147.185": {"lat": 37.1,  "lon": -95.7, "pais": "EUA",          "flag": "🇺🇸"},
    "66.132":  {"lat": 37.1,  "lon": -95.7, "pais": "EUA",          "flag": "🇺🇸"},
    "69.5":    {"lat": 37.1,  "lon": -95.7, "pais": "EUA",          "flag": "🇺🇸"},
    "35.203":  {"lat": 37.1,  "lon": -95.7, "pais": "EUA (GCP)",    "flag": "🇺🇸"},
    "162.216": {"lat": 37.1,  "lon": -95.7, "pais": "EUA",          "flag": "🇺🇸"},
    "64.62":   {"lat": 37.1,  "lon": -95.7, "pais": "EUA",          "flag": "🇺🇸"},
    "152.32":  {"lat": 22.3,  "lon": 114.2, "pais": "Hong Kong",    "flag": "🇭🇰"},
    "165.154": {"lat": 22.3,  "lon": 114.2, "pais": "Hong Kong",    "flag": "🇭🇰"},
    "91.231":  {"lat": 52.1,  "lon":  5.3,  "pais": "Holanda",      "flag": "🇳🇱"},
    "91.196":  {"lat": 48.4,  "lon": 31.2,  "pais": "Ucrânia",      "flag": "🇺🇦"},
    "91.230":  {"lat": 48.4,  "lon": 31.2,  "pais": "Ucrânia",      "flag": "🇺🇦"},
    "94.154":  {"lat": 42.7,  "lon": 25.5,  "pais": "Bulgária",     "flag": "🇧🇬"},
    "193.163": {"lat":  1.3,  "lon":103.8,  "pais": "Singapura",    "flag": "🇸🇬"},
    "193.176": {"lat": 55.7,  "lon": 37.6,  "pais": "Rússia",       "flag": "🇷🇺"},
    "193.124": {"lat": 55.7,  "lon": 37.6,  "pais": "Rússia",       "flag": "🇷🇺"},
    "185.242": {"lat": 51.2,  "lon": 10.5,  "pais": "Alemanha",     "flag": "🇩🇪"},
    "213.209": {"lat": 51.2,  "lon": 10.5,  "pais": "Alemanha",     "flag": "🇩🇪"},
    "216.25":  {"lat": 37.1,  "lon": -95.7, "pais": "EUA",          "flag": "🇺🇸"},
    "81.19":   {"lat": 50.5,  "lon": 30.5,  "pais": "Ucrânia",      "flag": "🇺🇦"},
    "194.88":  {"lat": 55.4,  "lon": -3.4,  "pais": "Reino Unido",  "flag": "🇬🇧"},
    "167.94":  {"lat": 37.1,  "lon": -95.7, "pais": "EUA",          "flag": "🇺🇸"},
    "65.49":   {"lat": 37.1,  "lon": -95.7, "pais": "EUA",          "flag": "🇺🇸"},
    "45.135":  {"lat": 42.7,  "lon": 25.5,  "pais": "Bulgária",     "flag": "🇧🇬"},
    "45.142":  {"lat": 55.7,  "lon": 37.6,  "pais": "Rússia",       "flag": "🇷🇺"},
    "45.148":  {"lat": 55.7,  "lon": 37.6,  "pais": "Rússia",       "flag": "🇷🇺"},
    "199.45":  {"lat": 37.1,  "lon": -95.7, "pais": "EUA",          "flag": "🇺🇸"},
    "204.76":  {"lat": 37.1,  "lon": -95.7, "pais": "EUA",          "flag": "🇺🇸"},
    "89.21":   {"lat": 59.9,  "lon": 30.3,  "pais": "Rússia",       "flag": "🇷🇺"},
    "118.31":  {"lat": 35.9,  "lon":104.2,  "pais": "China",        "flag": "🇨🇳"},
    "121.171": {"lat": 35.9,  "lon":127.8,  "pais": "Coreia do Sul","flag": "🇰🇷"},
    "165.245": {"lat": 37.1,  "lon": -95.7, "pais": "EUA",          "flag": "🇺🇸"},
    "74.81":   {"lat": 37.1,  "lon": -95.7, "pais": "EUA",          "flag": "🇺🇸"},
}

def geo_ip(ip: str) -> dict:
    """Retorna geolocalização de um IP pelo prefixo /16."""
    partes = ip.split(".")
    if len(partes) >= 2:
        chave = f"{partes[0]}.{partes[1]}"
        if chave in GEO_DB:
            return GEO_DB[chave]
    return {"lat": 0, "lon": 0, "pais": "Desconhecido", "flag": "🌐"}

# ── Config OPNsense ─────────────────────────────────────────────────────────
def carregar_config():
    cfg = {}
    if not CONFIG_FILE.exists():
        return cfg
    with CONFIG_FILE.open() as f:
        for linha in f:
            linha = linha.strip()
            if not linha or linha.startswith("#") or "=" not in linha:
                continue
            k, _, v = linha.partition("=")
            cfg[k.strip()] = v.strip()
    return cfg

def opnsense_post(url_path, body, cfg):
    host   = cfg.get("OPNSENSE_HOST", "172.16.0.1")
    key    = cfg.get("OPNSENSE_API_KEY", "")
    secret = cfg.get("OPNSENSE_API_SECRET", "")
    auth   = base64.b64encode(f"{key}:{secret}".encode()).decode()
    ctx    = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode    = ssl.CERT_NONE
    url = f"https://{host}/{url_path.lstrip('/')}"
    try:
        req = urllib.request.Request(
            url, data=json.dumps(body).encode(), method="POST",
            headers={"Authorization": f"Basic {auth}", "Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, context=ctx, timeout=8) as r:
            return json.loads(r.read().decode())
    except Exception as exc:
        return {"erro": str(exc)}

def coletar_regras_ia(cfg):
    resp = opnsense_post(
        "api/firewall/filter/searchRule",
        {"current": 1, "rowCount": 9999, "searchPhrase": "IA-aparecido"},
        cfg
    )
    return resp.get("rows", []) if isinstance(resp, dict) else []

def coletar_pf_via_ssh():
    try:
        result = subprocess.run(
            ["ssh", "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=5",
             "root@172.16.0.1", "pfctl -sr | grep 9034"],
            capture_output=True, text=True, timeout=10,
        )
        return [l.strip() for l in result.stdout.splitlines() if l.strip()] or ["(nenhuma regra 9034)"]
    except Exception as exc:
        return [f"Erro SSH: {exc}"]

def coletar_resumo_v2():
    if not RESUMO_V2.exists():
        return {}
    try:
        return json.loads(RESUMO_V2.read_text())
    except:
        return {}

def coletar_ultima_proposta():
    if not PROPOSTAS.exists():
        return {}
    arquivos = sorted(PROPOSTAS.glob("propostas_*.json"))
    if not arquivos:
        return {}
    try:
        return json.loads(arquivos[-1].read_text())
    except:
        return {}

# ── Alertas do EVE para o mapa ──────────────────────────────────────────────
_alertas_mapa = []   # lista global de alertas geolocalizados
_alertas_lock = threading.Lock()

def carregar_alertas_eve():
    """Carrega alertas externos do eve.json e geoocaliza."""
    if not EVE_FILE.exists():
        return []
    alertas = []
    from collections import Counter
    contagem = Counter()
    sigs = {}
    desfechos = {}

    # Carregar desfechos do resumo v2
    rv2 = coletar_resumo_v2()
    for trilha_desfecho, count in rv2.get("por_desfecho_trilha", {}).items():
        pass  # usado só para contexto

    with EVE_FILE.open() as f:
        for linha in f:
            try:
                e = json.loads(linha)
                if e.get("event_type") != "alert":
                    continue
                src = e.get("src_ip", "")
                if src.startswith(("192.168.", "172.16.", "10.")):
                    continue
                sig = e.get("alert", {}).get("signature", "")
                contagem[src] += 1
                if src not in sigs:
                    sigs[src] = sig
            except:
                continue

    # Montar lista geolocalizaada
    for ip, count in contagem.most_common(50):
        geo = geo_ip(ip)
        if geo["lat"] == 0:
            continue
        sig = sigs.get(ip, "")
        # Classificar nível
        if count > 500:
            nivel = "high"
        elif count > 100:
            nivel = "medium"
        else:
            nivel = "low"
        alertas.append({
            "ip":    ip,
            "count": count,
            "pais":  geo["pais"],
            "flag":  geo["flag"],
            "lat":   geo["lat"],
            "lon":   geo["lon"],
            "sig":   sig[:60],
            "nivel": nivel,
        })

    return sorted(alertas, key=lambda x: -x["count"])

def coletar_todos_dados():
    cfg        = carregar_config()
    ts         = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    regras_ia  = coletar_regras_ia(cfg)
    pf_linhas  = coletar_pf_via_ssh()
    resumo_v2  = coletar_resumo_v2()
    proposta   = coletar_ultima_proposta()
    with _alertas_lock:
        alertas_mapa = _alertas_mapa.copy()

    n_regras = len([r for r in regras_ia if "erro" not in r])
    status   = "OK" if cfg else "ERRO: config não encontrada"

    return {
        "timestamp":    ts,
        "status":       status,
        "regras_ia":    regras_ia,
        "n_regras":     n_regras,
        "pf_linhas":    pf_linhas,
        "resumo_v2":    resumo_v2,
        "proposta":     proposta,
        "alertas_mapa": alertas_mapa,
        "versao":       VERSION,
        "host":         cfg.get("OPNSENSE_HOST", "?"),
    }

# ── Cache e SSE ──────────────────────────────────────────────────────────────
_cache      = {}
_cache_lock = threading.Lock()
_sse_q      = []
_sse_lock   = threading.Lock()

def atualizar_cache(intervalo):
    global _cache
    while True:
        try:
            dados = coletar_todos_dados()
            with _cache_lock:
                _cache = dados
            payload = json.dumps(dados, ensure_ascii=False, default=str)
            mortos  = []
            with _sse_lock:
                for q in _sse_q:
                    try:    q.put_nowait(payload)
                    except: mortos.append(q)
                for q in mortos:
                    _sse_q.remove(q)
        except:
            pass
        time.sleep(intervalo)

# ── HTML ─────────────────────────────────────────────────────────────────────
HTML = r"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Firewall IA — Dashboard</title>
<script src="https://cdn.jsdelivr.net/npm/d3@7.9.0/dist/d3.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/topojson-client@3.1.0/dist/topojson-client.min.js"></script>
<style>
:root{--bg:#07101c;--card:#111f33;--card2:#162640;--line:#1e3050;
  --azul:#4f91ff;--verde:#22d67a;--amar:#f5c518;--verm:#f04d4d;
  --cinza:#8ba3c0;--branco:#e8f0fe;}
*{margin:0;padding:0;box-sizing:border-box}
body{background:var(--bg);color:var(--cinza);font-family:'Segoe UI',system-ui,sans-serif;font-size:13px}

/* NAV */
nav{position:sticky;top:0;z-index:100;background:rgba(7,16,28,.97);
  border-bottom:2px solid var(--azul);padding:.6rem 1.5rem;
  display:flex;align-items:center;justify-content:space-between;backdrop-filter:blur(8px)}
.nav-brand{font-weight:800;font-size:1rem;color:var(--azul)}
.nav-brand span{color:var(--branco)}
#status-pill{padding:.25rem .9rem;border-radius:20px;font-size:.78rem;font-weight:700}
.pill-ok  {background:rgba(34,214,122,.15);color:var(--verde);border:1px solid var(--verde)}
.pill-err {background:rgba(240,77,77,.15); color:var(--verm); border:1px solid var(--verm)}
#ts{font-size:.75rem;color:var(--cinza);margin-left:.7rem}
#pulse{width:9px;height:9px;border-radius:50%;background:var(--verde);
  display:inline-block;margin-right:.5rem;animation:pulse 2s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.3}}

/* GRID */
.grid{display:grid;gap:1rem;padding:1rem 1.5rem;
  grid-template-columns:repeat(auto-fit,minmax(320px,1fr))}
.full{grid-column:1/-1}

/* CARDS */
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:1rem}
.card h2{font-size:.72rem;font-weight:700;text-transform:uppercase;letter-spacing:.1em;
  color:var(--cinza);margin-bottom:.8rem;display:flex;align-items:center;gap:.5rem}
.dot{width:8px;height:8px;border-radius:50%;flex-shrink:0}
.dot-g{background:var(--verde);box-shadow:0 0 6px var(--verde)}
.dot-b{background:var(--azul); box-shadow:0 0 6px var(--azul)}
.dot-a{background:var(--amar); box-shadow:0 0 6px var(--amar)}
.dot-r{background:var(--verm); box-shadow:0 0 6px var(--verm)}

/* STAT ROWS */
.srow{display:flex;justify-content:space-between;align-items:center;
  padding:.45rem 0;border-bottom:1px solid var(--line)}
.srow:last-child{border-bottom:none}
.sl{color:var(--cinza);font-size:.82rem}
.sv{font-weight:700;font-size:.95rem}
.g{color:var(--verde)}.b{color:var(--azul)}.a{color:var(--amar)}.r{color:var(--verm)}

/* TABELA */
table{width:100%;border-collapse:collapse;font-size:.8rem}
th{color:var(--cinza);text-align:left;padding:.35rem .6rem;border-bottom:1px solid var(--line);font-weight:600}
td{padding:.4rem .6rem;border-bottom:1px solid rgba(30,48,80,.5);vertical-align:middle}
tr:hover td{background:var(--card2)}
.mono{font-family:monospace;font-size:.78rem;color:var(--branco)}
.badge{display:inline-block;padding:.15rem .6rem;border-radius:12px;font-size:.72rem;font-weight:700}
.bg{background:rgba(34,214,122,.15);color:var(--verde)}
.bb{background:rgba(79,145,255,.15);color:var(--azul)}
.ba{background:rgba(245,197,24,.15);color:var(--amar)}
.br{background:rgba(240,77,77,.15);color:var(--verm)}
.pf-line{font-family:monospace;font-size:.78rem;color:var(--branco);
  padding:.35rem 0;border-bottom:1px solid var(--line)}
.pf-line:last-child{border-bottom:none}

/* MAPA */
#map-wrap{position:relative;border-radius:12px;overflow:hidden;
  background:#030b17;border:1px solid var(--line)}
#map-svg{display:block;width:100%}
#map-canvas{position:absolute;top:0;left:0;width:100%;pointer-events:none}
#map-tip{position:absolute;display:none;pointer-events:none;
  background:rgba(3,11,23,.96);border:1px solid var(--azul);
  border-radius:8px;padding:.45rem .9rem;font-size:.78rem;
  color:var(--branco);white-space:nowrap;z-index:10}
.map-counter{position:absolute;bottom:10px;right:12px;
  background:rgba(3,11,23,.85);border:1px solid var(--line);
  border-radius:8px;padding:.35rem .8rem;font-size:.72rem;pointer-events:none}
.map-legend{display:flex;gap:1rem;flex-wrap:wrap;margin-bottom:.6rem;font-size:.78rem;align-items:center}
.leg{display:flex;align-items:center;gap:.35rem}
.leg-dot{width:9px;height:9px;border-radius:50%}

/* FUNIL */
.funil{display:flex;flex-direction:column;gap:.4rem}
.fbloco{border-radius:8px;padding:.6rem 1rem;display:flex;
  justify-content:space-between;align-items:center}
.fn{font-weight:800;font-size:1.1rem}
.fd{font-size:.8rem;opacity:.8}

/* FOOTER */
footer{text-align:center;padding:1rem;color:var(--cinza);font-size:.75rem;
  border-top:1px solid var(--line);margin-top:.5rem}
</style>
</head>
<body>

<nav>
  <div class="nav-brand">🛡️ Firewall <span>IA</span> — Dashboard</div>
  <div style="display:flex;align-items:center">
    <span id="pulse"></span>
    <span id="status-pill" class="pill-ok">OK</span>
    <span id="ts">carregando...</span>
  </div>
</nav>

<div class="grid">

  <!-- ══ MAPA ══ -->
  <div class="card full">
    <h2><span class="dot dot-r"></span>Mapa de ataques detectados — dados reais do período 27/09–04/10/2026</h2>
    <div class="map-legend">
      <div class="leg"><div class="leg-dot" style="background:#f04d4d"></div>&gt;500 alertas</div>
      <div class="leg"><div class="leg-dot" style="background:#f5c518"></div>100–500</div>
      <div class="leg"><div class="leg-dot" style="background:#4f91ff"></div>&lt;100</div>
      <div class="leg" style="margin-left:auto"><div class="leg-dot" style="background:#22d67a"></div>Brasil (alvo)</div>
    </div>
    <div id="map-wrap">
      <svg id="map-svg"></svg>
      <canvas id="map-canvas"></canvas>
      <div id="map-tip"></div>
      <div class="map-counter">
        <span style="color:var(--cinza)">IPs únicos: </span>
        <span id="mc-ips" style="color:var(--azul);font-weight:800">—</span>
        &nbsp;
        <span style="color:var(--cinza)">Países: </span>
        <span id="mc-paises" style="color:var(--verde);font-weight:800">—</span>
        &nbsp;&nbsp;
        <span id="mc-ts" style="color:var(--cinza)">—</span>
      </div>
    </div>
    <!-- Tabela de top atacantes -->
    <div style="margin-top:.8rem;overflow-x:auto">
      <table id="tbl-atacantes">
        <thead><tr>
          <th>#</th><th>País</th><th>IP</th><th>Alertas</th><th>Assinatura</th>
        </tr></thead>
        <tbody id="tbody-atacantes"></tbody>
      </table>
    </div>
  </div>

  <!-- ══ FUNIL ══ -->
  <div class="card">
    <h2><span class="dot dot-b"></span>Funil por desfecho — Community ID</h2>
    <div class="funil" id="funil-container">
      <div class="fbloco" style="background:rgba(79,145,255,.1);border:1px solid rgba(79,145,255,.3)">
        <span class="fd">Total alertas</span><span class="fn b" id="f-total">—</span>
      </div>
      <div class="fbloco" style="background:rgba(34,214,122,.08);border:1px solid rgba(34,214,122,.25)">
        <span class="fd">SEM_REGISTRO (default deny)</span><span class="fn g" id="f-semreg">—</span>
      </div>
      <div class="fbloco" style="background:rgba(34,214,122,.06);border:1px solid rgba(34,214,122,.2)">
        <span class="fd">BLOQUEADOS (log explícito)</span><span class="fn g" id="f-bloq">—</span>
      </div>
      <div class="fbloco" style="background:rgba(245,197,24,.08);border:1px solid rgba(245,197,24,.25)">
        <span class="fd">PASSARAM (legítimo)</span><span class="fn a" id="f-passou">—</span>
      </div>
    </div>
    <div style="margin-top:.8rem">
      <div class="srow"><span class="sl">Community ID ativo</span><span id="cid-status" class="sv">—</span></div>
      <div class="srow"><span class="sl">Linhas PF processadas</span><span id="pf-linhas" class="sv b">—</span></div>
      <div class="srow"><span class="sl">IPs externos únicos</span><span id="ips-ext" class="sv b">—</span></div>
    </div>
  </div>

  <!-- ══ REGRAS IA ══ -->
  <div class="card">
    <h2><span class="dot dot-g"></span>Regras IA-aparecido ativas no OPNsense</h2>
    <div id="regras-container">
      <div style="color:var(--cinza)">Carregando...</div>
    </div>
  </div>

  <!-- ══ PF AO VIVO ══ -->
  <div class="card">
    <h2><span class="dot dot-r"></span>PF — porta 9034 (Realtek CVE-2021-35394)</h2>
    <div id="pf-container">
      <div style="color:var(--cinza)">Carregando...</div>
    </div>
  </div>

  <!-- ══ ÚLTIMA PROPOSTA ══ -->
  <div class="card">
    <h2><span class="dot dot-a"></span>Última proposta de regras</h2>
    <div id="proposta-container">
      <div style="color:var(--cinza)">Carregando...</div>
    </div>
  </div>

</div>

<footer>
  Firewall IA Dashboard v2.0.0 &nbsp;·&nbsp; OPNsense 172.16.0.1 &nbsp;·&nbsp;
  Atualização automática via SSE a cada 15s &nbsp;·&nbsp;
  <a href="https://github.com/Aparecido-Junior-Dev/firewall-ia" 
     target="_blank" style="color:var(--azul)">GitHub</a>
</footer>

<script>
// ════════════════════════════════════════════════════════════
// MAPA — D3 Natural Earth + Canvas animado
// ════════════════════════════════════════════════════════════
var mapSvg    = document.getElementById('map-svg');
var mapCanvas = document.getElementById('map-canvas');
var mapTip    = document.getElementById('map-tip');
var mapWrap   = document.getElementById('map-wrap');
var ctxMap    = mapCanvas.getContext('2d');

var W, H, projFn;
var nodes       = [];      // nós calculados
var brasilPt    = null;
var pktList     = [];
var phases      = {};
var agendados   = {};      // IPs já com setTimeout rodando
var mapReady    = false;
var alertasPend = null;    // alertas aguardando mapa terminar de carregar

var BRA = [-51.9, -14.2];

function lcNivel(nivel) {
  if (nivel === 'high')   return {r:240, g:77,  b:77 };
  if (nivel === 'medium') return {r:245, g:197, b:24 };
  return                         {r:79,  g:145, b:255};
}
function rgba(c, a) { return 'rgba('+c.r+','+c.g+','+c.b+','+a+')'; }

// ── Dimensionar e criar projeção ──────────────────────────────────────────
function setMapSize() {
  W = mapWrap.clientWidth || 900;
  H = Math.round(W * 0.5);
  mapCanvas.width  = W;  mapCanvas.height  = H;
  mapSvg.setAttribute('width',  W);
  mapSvg.setAttribute('height', H);
  mapSvg.style.height    = H + 'px';
  mapCanvas.style.height = H + 'px';
  mapWrap.style.height   = H + 'px';
  projFn = d3.geoNaturalEarth1().scale(W / 6.4).translate([W / 2, H / 2]);
}

function screenPt(lon, lat) {
  var p = projFn([lon, lat]);
  return { x: p[0], y: p[1] };
}

// ── Construir lista de nós a partir dos alertas ───────────────────────────
function buildNodes(alertas) {
  // Manter agendamentos existentes para IPs que voltaram
  var novosIps = {};
  alertas.forEach(function(a) { novosIps[a.ip] = true; });

  nodes = alertas.map(function(a) {
    var pt = screenPt(a.lon, a.lat);
    if (!phases[a.ip]) phases[a.ip] = Math.random() * Math.PI * 2;
    return { ip:a.ip, pais:a.pais, flag:a.flag, count:a.count,
             sig:a.sig, nivel:a.nivel, col:lcNivel(a.nivel), x:pt.x, y:pt.y };
  });
  brasilPt = screenPt(BRA[0], BRA[1]);

  // Agendar apenas IPs novos
  nodes.forEach(function(n) {
    if (!agendados[n.ip]) {
      agendados[n.ip] = true;
      schedNode(n);
    }
  });
}

// ── Desenhar SVG base (países) ────────────────────────────────────────────
function drawSVG(world) {
  var countries = topojson.feature(world, world.objects.countries);
  var borders   = topojson.mesh(world, world.objects.countries,
                                function(a,b){ return a !== b; });
  var pathGen   = d3.geoPath().projection(projFn);
  var svgSel    = d3.select('#map-svg');
  svgSel.selectAll('*').remove();

  // Fundo oceano
  svgSel.append('rect').attr('width', W).attr('height', H).attr('fill', '#030b17');

  // Grade
  var graticule = d3.geoGraticule()();
  svgSel.append('path').datum(graticule).attr('d', pathGen)
    .attr('fill','none')
    .attr('stroke','rgba(79,145,255,0.05)')
    .attr('stroke-width', 0.4);

  // Países
  svgSel.append('g').selectAll('path')
    .data(countries.features).enter().append('path')
    .attr('d', pathGen)
    .attr('fill', '#132240')
    .attr('stroke', '#243d5c')
    .attr('stroke-width', 0.5);

  // Bordas
  svgSel.append('path').datum(borders).attr('d', pathGen)
    .attr('fill','none').attr('stroke','#1e3a5a').attr('stroke-width', 0.4);

  // Equador
  svgSel.append('path')
    .datum({type:'LineString', coordinates:[[-180,0],[180,0]]})
    .attr('d', pathGen).attr('fill','none')
    .attr('stroke','rgba(79,145,255,0.18)').attr('stroke-width', 0.8)
    .attr('stroke-dasharray','6,8');

  mapReady = true;

  // Se havia alertas esperando o mapa, construir agora
  if (alertasPend) {
    buildNodes(alertasPend);
    alertasPend = null;
  }
}

// ── Partículas ────────────────────────────────────────────────────────────
function easeIO(t) { return t < 0.5 ? 2*t*t : -1+(4-2*t)*t; }
function bez(t, p0, p1, p2) { return (1-t)*(1-t)*p0 + 2*(1-t)*t*p1 + t*t*p2; }

function launchPkt(n) {
  if (!brasilPt) return;
  var cx = (n.x + brasilPt.x) / 2 + (Math.random() - 0.5) * 50;
  var cy = Math.min(n.y, brasilPt.y) - Math.abs(n.x - brasilPt.x) * 0.15
           - 12 + (Math.random() - 0.5) * 20;
  pktList.push({
    sx:n.x, sy:n.y, dx:brasilPt.x, dy:brasilPt.y,
    cx:cx, cy:cy, col:n.col,
    start:performance.now(), dur:1400 + Math.random()*900, trail:[]
  });
}

function schedNode(n) {
  // Busca o nó atualizado a cada disparo (pode ter sido recalculado)
  function fire() {
    var atual = null;
    for (var i = 0; i < nodes.length; i++) {
      if (nodes[i].ip === n.ip) { atual = nodes[i]; break; }
    }
    if (!atual) { agendados[n.ip] = false; return; } // IP sumiu
    launchPkt(atual);
    var delay = atual.nivel === 'high'   ? 200 + Math.random()*200
              : atual.nivel === 'medium' ? 400 + Math.random()*300
              :                            650 + Math.random()*400;
    setTimeout(fire, delay);
  }
  setTimeout(fire, Math.random() * 1200);
}

// ── Render Canvas ─────────────────────────────────────────────────────────
function drawArcs() {
  if (!brasilPt) return;
  nodes.forEach(function(n) {
    var cx = (n.x + brasilPt.x) / 2;
    var cy = Math.min(n.y, brasilPt.y) - Math.abs(n.x - brasilPt.x) * 0.14 - 12;
    var a  = n.nivel==='high' ? 0.08 : n.nivel==='medium' ? 0.05 : 0.03;
    ctxMap.beginPath();
    ctxMap.moveTo(n.x, n.y);
    ctxMap.quadraticCurveTo(cx, cy, brasilPt.x, brasilPt.y);
    ctxMap.strokeStyle = rgba(n.col, a);
    ctxMap.lineWidth   = n.nivel==='high' ? 0.9 : 0.55;
    ctxMap.stroke();
  });
}

function drawPkts(now) {
  for (var i = pktList.length - 1; i >= 0; i--) {
    var p = pktList[i];
    var t = Math.min((now - p.start) / p.dur, 1);
    if (t >= 1) { pktList.splice(i, 1); continue; }
    var et = easeIO(t);
    var px = bez(et, p.sx, p.cx, p.dx);
    var py = bez(et, p.sy, p.cy, p.dy);
    p.trail.push({x:px, y:py});
    if (p.trail.length > 14) p.trail.shift();
    // Rastro
    for (var j = 1; j < p.trail.length; j++) {
      var a = (j / p.trail.length) * (1 - t) * 0.5;
      ctxMap.beginPath();
      ctxMap.moveTo(p.trail[j-1].x, p.trail[j-1].y);
      ctxMap.lineTo(p.trail[j].x,   p.trail[j].y);
      ctxMap.strokeStyle = rgba(p.col, a);
      ctxMap.lineWidth   = 1.5;
      ctxMap.stroke();
    }
    // Ponto
    var fa = t < 0.88 ? 1 : 1 - (t - 0.88) / 0.12;
    ctxMap.globalAlpha  = fa;
    ctxMap.shadowColor  = rgba(p.col, 1);
    ctxMap.shadowBlur   = 8;
    ctxMap.beginPath();
    ctxMap.arc(px, py, 2.5, 0, Math.PI * 2);
    ctxMap.fillStyle = rgba(p.col, 1);
    ctxMap.fill();
    ctxMap.shadowBlur   = 0;
    ctxMap.globalAlpha  = 1;
  }
}

function drawNodes(now) {
  if (!brasilPt) return;
  var fs = Math.max(9, W * 0.011);
  nodes.forEach(function(n) {
    var ph = phases[n.ip] || 0;
    var p  = (Math.sin(now / 850 + ph) * 0.5 + 0.5);
    var br = n.nivel==='high' ? 5.5 : n.nivel==='medium' ? 4 : 3;
    // Anel externo
    ctxMap.beginPath(); ctxMap.arc(n.x, n.y, br+4+p*8, 0, Math.PI*2);
    ctxMap.fillStyle = rgba(n.col, 0.04 + p*0.08); ctxMap.fill();
    // Anel médio
    ctxMap.beginPath(); ctxMap.arc(n.x, n.y, br+2, 0, Math.PI*2);
    ctxMap.fillStyle = rgba(n.col, 0.15); ctxMap.fill();
    // Núcleo
    ctxMap.shadowColor = rgba(n.col, 0.9); ctxMap.shadowBlur = 12;
    ctxMap.beginPath(); ctxMap.arc(n.x, n.y, br, 0, Math.PI*2);
    ctxMap.fillStyle = rgba(n.col, 1); ctxMap.fill();
    ctxMap.shadowBlur = 0;
    // Label países de alta intensidade
    if (n.nivel === 'high' && W > 500) {
      ctxMap.fillStyle = rgba(n.col, 0.9);
      ctxMap.font      = 'bold ' + fs + 'px sans-serif';
      ctxMap.textAlign = 'center';
      ctxMap.fillText(n.pais, n.x, n.y - br - 5);
    }
  });
  // Brasil
  var gb = {r:34, g:214, b:122};
  var pb = (Math.sin(now / 600) * 0.5 + 0.5);
  ctxMap.beginPath(); ctxMap.arc(brasilPt.x, brasilPt.y, 15+pb*12, 0, Math.PI*2);
  ctxMap.fillStyle = rgba(gb, 0.05+pb*0.07); ctxMap.fill();
  ctxMap.shadowColor = 'rgba(34,214,122,.9)'; ctxMap.shadowBlur = 16;
  ctxMap.beginPath(); ctxMap.arc(brasilPt.x, brasilPt.y, 6, 0, Math.PI*2);
  ctxMap.fillStyle = '#22d67a'; ctxMap.fill();
  ctxMap.shadowBlur = 0;
  ctxMap.fillStyle = '#22d67a';
  ctxMap.font      = 'bold ' + Math.max(11, W*0.013) + 'px sans-serif';
  ctxMap.textAlign = 'center';
  ctxMap.fillText('BRASIL', brasilPt.x, brasilPt.y - 18);
}

// ── Loop principal ────────────────────────────────────────────────────────
function mapLoop(now) {
  ctxMap.clearRect(0, 0, W, H);
  if (mapReady) {
    drawArcs();
    drawPkts(now);
    drawNodes(now);
  }
  requestAnimationFrame(mapLoop);
}

// ── Tooltip ───────────────────────────────────────────────────────────────
mapWrap.addEventListener('mousemove', function(e) {
  var rect  = mapCanvas.getBoundingClientRect();
  var scale = W / rect.width;
  var mx    = (e.clientX - rect.left) * scale;
  var my    = (e.clientY - rect.top)  * scale;
  var found = null;
  for (var i = 0; i < nodes.length; i++) {
    var dx = mx - nodes[i].x, dy = my - nodes[i].y;
    if (Math.sqrt(dx*dx + dy*dy) < 18) { found = nodes[i]; break; }
  }
  if (found) {
    mapTip.innerHTML = found.flag + ' <strong>' + found.pais + '</strong>'
      + ' (' + found.ip + ')<br>'
      + found.count.toLocaleString('pt-BR') + ' alertas &nbsp;·&nbsp; ' + found.sig;
    mapTip.style.display = 'block';
    var wr = mapWrap.getBoundingClientRect();
    mapTip.style.left = (e.clientX - wr.left + 14) + 'px';
    mapTip.style.top  = (e.clientY - wr.top  - 10) + 'px';
  } else {
    mapTip.style.display = 'none';
  }
});
mapWrap.addEventListener('mouseleave', function() { mapTip.style.display = 'none'; });

// ── Inicialização ─────────────────────────────────────────────────────────
function initMapa() {
  setMapSize();
  d3.json('https://cdn.jsdelivr.net/npm/world-atlas@2.0.2/countries-110m.json')
    .then(function(world) {
      drawSVG(world);       // seta mapReady=true e constrói nodes se alertasPend != null
    })
    .catch(function(e) { console.error('Mapa não carregou:', e); });
}

// Iniciar loop e carregar mapa
requestAnimationFrame(mapLoop);
initMapa();

// Resize responsivo
var rt;
window.addEventListener('resize', function() {
  clearTimeout(rt);
  rt = setTimeout(function() {
    setMapSize();
    // Redesenhar SVG com nova projeção
    d3.json('https://cdn.jsdelivr.net/npm/world-atlas@2.0.2/countries-110m.json')
      .then(function(world) { drawSVG(world); if (nodes.length) buildNodes(nodes); });
  }, 300);
});

// ════════════════════════════════════════════════════════════
// RENDER — atualiza todos os cards com os dados do SSE
// ════════════════════════════════════════════════════════════
function esc(s){ return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
function badge(t,c){ return '<span class="badge b'+c+'">'+esc(t)+'</span>'; }

function renderDados(d) {
  // Nav
  var ok = d.status === 'OK';
  document.getElementById('status-pill').textContent = d.status;
  document.getElementById('status-pill').className   = ok ? 'pill-ok' : 'pill-err';
  document.getElementById('ts').textContent = '  ' + d.timestamp;

  // Funil
  var rv2 = d.resumo_v2 || {};
  var pd  = rv2.por_desfecho || {};
  document.getElementById('f-total').textContent   = (rv2.alertas_total||0).toLocaleString('pt-BR');
  document.getElementById('f-semreg').textContent  = (pd.SEM_REGISTRO||0).toLocaleString('pt-BR');
  document.getElementById('f-bloq').textContent    = (pd.BLOQUEADO||0).toLocaleString('pt-BR');
  document.getElementById('f-passou').textContent  = (pd.PASSOU||0).toLocaleString('pt-BR');
  document.getElementById('cid-status').innerHTML  = rv2.communityid_ativo
    ? '<span class="g">✅ Ativo</span>' : '<span class="a">⚠️ Fallback</span>';
  document.getElementById('pf-linhas').textContent = (rv2.pf_linhas||0).toLocaleString('pt-BR');
  document.getElementById('ips-ext').textContent   = (d.alertas_mapa||[]).length + ' blocos';

  // Mapa — atualizar nós se mapa já estiver pronto
  var alertas = d.alertas_mapa || [];
  if (alertas.length > 0) {
    if (mapReady) {
      buildNodes(alertas);
    } else {
      // Mapa ainda carregando — guardar para quando estiver pronto
      alertasPend = alertas;
    }
    // Contadores e tabela (independente do mapa estar pronto)
    var paises = new Set(alertas.map(function(a){return a.pais;}));
    document.getElementById('mc-ips').textContent    = alertas.length;
    document.getElementById('mc-paises').textContent = paises.size;
    document.getElementById('mc-ts').textContent     = d.timestamp;
    var tbody = document.getElementById('tbody-atacantes');
    tbody.innerHTML = '';
    alertas.slice(0,10).forEach(function(a,i){
      var cor = a.nivel==='high'?'r':a.nivel==='medium'?'a':'b';
      tbody.innerHTML += '<tr>'
        +'<td>'+(i+1)+'</td>'
        +'<td>'+a.flag+' '+esc(a.pais)+'</td>'
        +'<td class="mono">'+esc(a.ip)+'</td>'
        +'<td>'+badge(a.count.toLocaleString('pt-BR'), cor)+'</td>'
        +'<td style="color:var(--cinza)">'+esc(a.sig)+'</td>'
        +'</tr>';
    });
  } // fim if alertas.length > 0
  }

  // Regras IA
  var regras = (d.regras_ia||[]).filter(function(r){return !r.erro;});
  var errApi = (d.regras_ia||[]).find(function(r){return r.erro;});
  var hRegras = '';
  if(errApi){
    hRegras = '<div style="color:var(--verm);font-size:.8rem">'+esc(errApi.erro)+'</div>';
  } else if(regras.length === 0){
    hRegras = '<div style="color:var(--cinza)">Nenhuma regra encontrada</div>';
  } else {
    hRegras += '<div style="margin-bottom:.6rem">'+badge(regras.length+' regras ativas','g')+'</div>';
    hRegras += '<table><thead><tr><th>IP</th><th>Porta</th><th>Ação</th><th>UUID</th></tr></thead><tbody>';
    regras.forEach(function(rg){
      var desc  = rg.description||'';
      var ip    = (desc.split('block ')[1]||'').split(' ')[0]||rg.source_net||'?';
      var porta = rg.destination_port||'?';
      var acao  = rg.action||'?';
      var uuid  = (rg.uuid||'').substring(0,8)+'…';
      hRegras += '<tr><td class="mono">'+esc(ip)+'</td><td>'+esc(porta)+'/udp</td>'
        +'<td>'+badge(acao,acao==='block'?'r':'g')+'</td>'
        +'<td class="mono" style="font-size:.72rem">'+esc(uuid)+'</td></tr>';
    });
    hRegras += '</tbody></table>';
  }
  document.getElementById('regras-container').innerHTML = hRegras;

  // PF ao vivo
  var hPf = '';
  (d.pf_linhas||[]).forEach(function(l){
    var cor = l.includes('block')?'#ffb3b3':l.startsWith('Erro')?'var(--amar)':'var(--branco)';
    hPf += '<div class="pf-line" style="color:'+cor+'">'+esc(l)+'</div>';
  });
  document.getElementById('pf-container').innerHTML = hPf || '<div style="color:var(--cinza)">Sem dados</div>';

  // Última proposta
  var p = d.proposta||{};
  var hP = '';
  if(!p.timestamp){
    hP = '<div style="color:var(--cinza)">Nenhuma proposta</div>';
  } else {
    hP += '<div class="srow"><span class="sl">Timestamp</span><span class="mono">'+esc(p.timestamp)+'</span></div>';
    hP += '<div class="srow"><span class="sl">Modo</span>'+badge(p.modo||'?','b')+'</div>';
    hP += '<div class="srow"><span class="sl">Propostas geradas</span><span class="sv b">'+esc(p.propostas||0)+'</span></div>';
    var criadas = ((p.detalhes_propostas||[]).filter(function(x){return x.status==='criada';}).length);
    hP += '<div class="srow"><span class="sl">Criadas no OPNsense</span><span class="sv g">'+criadas+'</span></div>';
    hP += '<div class="srow"><span class="sl">Duplicatas ignoradas</span><span class="sv a">'+esc(p.duplicatas||0)+'</span></div>';
  }
  document.getElementById('proposta-container').innerHTML = hP;
}

// ════════════════════════════════════════════════════════════
// SSE — receber atualizações em tempo real
// ════════════════════════════════════════════════════════════
var evtSource = new EventSource('/stream');
evtSource.onmessage = function(e){
  try { renderDados(JSON.parse(e.data)); } catch(err){ console.error(err); }
};
evtSource.onerror = function(){
  document.getElementById('pulse').style.background='var(--verm)';
};

// Carga inicial imediata
fetch('/dados').then(function(r){return r.json();}).then(renderDados).catch(console.error);
</script>
</body>
</html>"""

# ── Flask ───────────────────────────────────────────────────────────────────
app = Flask(__name__)
_intervalo_global = 15

@app.route("/")
def index():
    return render_template_string(HTML)

@app.route("/dados")
def dados():
    with _cache_lock:
        return jsonify(_cache if _cache else coletar_todos_dados())

@app.route("/stream")
def stream():
    q = queue.Queue(maxsize=5)
    with _sse_lock:
        _sse_q.append(q)
    def gerar():
        try:
            with _cache_lock:
                snap = _cache if _cache else coletar_todos_dados()
            yield f"data: {json.dumps(snap, ensure_ascii=False, default=str)}\n\n"
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
                if q in _sse_q:
                    _sse_q.remove(q)
    return Response(gerar(), mimetype="text/event-stream",
                    headers={"Cache-Control":"no-cache","X-Accel-Buffering":"no"})

@app.route("/api/alertas-mapa")
def api_alertas():
    """Endpoint dedicado para os dados do mapa."""
    with _cache_lock:
        dados = _cache if _cache else coletar_todos_dados()
    return jsonify(dados.get("alertas_mapa", []))

def main():
    global _intervalo_global
    parser = argparse.ArgumentParser()
    parser.add_argument("--port",      type=int, default=8080)
    parser.add_argument("--intervalo", type=int, default=15)
    parser.add_argument("--host",      default="0.0.0.0")
    args = parser.parse_args()
    _intervalo_global = args.intervalo

    print(f"[INIT] Carregando alertas do EVE para o mapa...")
    with _alertas_lock:
        _alertas_mapa.extend(carregar_alertas_eve())
    print(f"[INIT] {len(_alertas_mapa)} blocos de IPs geolocalizados")

    print(f"[INIT] Coletando dados iniciais do OPNsense...")
    with _cache_lock:
        _cache.update(coletar_todos_dados())
    print(f"[INIT] Pronto.")

    t = threading.Thread(target=atualizar_cache, args=(args.intervalo,), daemon=True)
    t.start()

    print(f"[OK] Dashboard disponível em http://172.16.0.125:{args.port}")
    print(f"[OK] Mapa com {len(_alertas_mapa)} origens de ataque reais")
    app.run(host=args.host, port=args.port, debug=False, threaded=True)

if __name__ == "__main__":
    main()
