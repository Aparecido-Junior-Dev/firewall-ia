"""
test_correlacionador.py — Testes unitários do correlacionador Suricata × PF

Cobre:
  - timestamp(): parsing, timezone, microssegundos, valores inválidos
  - key(): tupla orientada, validação de IP e porta
  - parse_pf(): IPv4/UDP válido, IPv6/UDP, proto não-UDP, cabeçalho malformado,
                campos incompletos, linha sem filterlog
  - analyze(): 8 alertas de referência, janela inclusiva, múltiplos candidatos,
               sem candidato, contagem incorreta, arquivo ausente, SID errado
  - save(): estrutura do CSV, campos obrigatórios, resumo JSON, resumo TXT
  - Autoteste interno: self_test() deve passar sem exceção

Todos os testes usam apenas dados sintéticos — nunca tocam em data/raw/.

Versão: 1.0.0
Data:   2026-10-18
"""

import csv
import json
import sys
import tempfile
import textwrap
from datetime import datetime, timezone, timedelta
from pathlib import Path

import pytest

# Adiciona scripts/ ao path para importar sem instalar
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from correlacionar_sid import (
    NOTICE,
    analyze,
    key,
    parse_pf,
    save,
    timestamp,
    self_test,
)

# ---------------------------------------------------------------------------
# Helpers de fábrica
# ---------------------------------------------------------------------------

DEST_IP   = "192.168.15.200"
DEST_PORT = 9034
SID       = 2044008

# 8 eventos reais do estudo de caso Realtek (anonimizados pela porta de origem)
EVENTOS_REFERENCIA = [
    ("2026-09-28T22:49:06.102969-0300", "124.235.163.60",  52908),
    ("2026-09-29T08:51:18.955499-0300", "165.245.187.19",  51901),
    ("2026-09-29T09:35:42.560733-0300", "74.117.6.146",    46406),
    ("2026-09-29T13:06:51.825239-0300", "74.81.97.18",     49095),
    ("2026-09-29T15:56:54.860858-0300", "96.228.60.184",   55050),
    ("2026-09-29T20:07:55.061520-0300", "121.171.129.37",  55630),
    ("2026-09-30T23:58:30.909022-0300", "118.31.169.106",  40123),
    ("2026-10-02T21:53:20.300253-0300", "94.154.43.117",   34514),
]


def _eve_line(ts: str, src: str, sport: int, sid: int = SID) -> str:
    """Gera uma linha EVE JSON de alerta."""
    return json.dumps({
        "event_type":  "alert",
        "timestamp":   ts,
        "src_ip":      src,
        "src_port":    sport,
        "dest_ip":     DEST_IP,
        "dest_port":   DEST_PORT,
        "proto":       "UDP",
        "in_iface":    "igb0",
        "alert": {
            "signature_id": sid,
            "action":       "allowed",
            "signature":    "ET EXPLOIT Realtek SDK",
            "category":     "Misc Attack",
            "severity":     1,
        },
    }) + "\n"


def _pf_line(
    ts: str,
    src: str,
    sport: int,
    action: str = "block",
    dst: str = DEST_IP,
    dport: int = DEST_PORT,
    iface: str = "igb0",
    proto_num: str = "17",
    proto_txt: str = "udp",
    ip_ver: str = "4",
) -> str:
    """
    Gera uma linha filterlog RFC 5424 IPv4/UDP sintética.
    Índices baseados nos observados nos logs reais (IPv4 UDP):
      f[0]=rule f[3]=tracker f[4]=iface f[6]=action f[7]=dir
      f[8]=ipver f[15]=proto_id f[16]=proto_txt
      f[18]=src f[19]=dst f[20]=sport f[21]=dport
    """
    fields = [
        "5",          # 0  rule
        "0",          # 1
        "0",          # 2
        "uuid-test",  # 3  tracker
        iface,        # 4  interface
        "match",      # 5
        action,       # 6  action
        "in",         # 7  direction
        ip_ver,       # 8  ip version
        "0x0",        # 9
        "",           # 10
        "64",         # 11
        "1",          # 12
        "0",          # 13
        "none",       # 14
        proto_num,    # 15 protocol id (17=UDP)
        proto_txt,    # 16 protocol text
        "28",         # 17 length
        src,          # 18 src ip
        dst,          # 19 dst ip
        str(sport),   # 20 src port
        str(dport),   # 21 dst port
        "8",          # 22 length
    ]
    payload = ",".join(fields)
    return f'<134>1 {ts} host filterlog 50144 - [meta sequenceId="1"] {payload}\n'


def _pf_line_v6(ts: str, src: str, sport: int, dst: str, dport: int) -> str:
    """
    Gera linha filterlog IPv6/UDP sintética no formato exato aceito pelo parse_pf.
    Baseado no self_test() interno do correlacionador.
    Campos IPv6:  f[8]=ipver f[12]=proto_id f[13]=proto_txt
                  f[15]=src  f[16]=dst  f[17]=sport  f[18]=dport
    """
    fields = [
        "1",           # 0  rule
        "0",           # 1
        "0",           # 2
        "uuid",        # 3  tracker
        "igb0",        # 4  interface
        "match",       # 5
        "pass",        # 6  action
        "in",          # 7  direction
        "6",           # 8  ip version
        "0x0",         # 9
        "0x0",         # 10 flow label
        "64",          # 11 hop limit
        "UDP",         # 12 proto_txt  ← proto_text=12 para IPv6
        "17",          # 13 proto_id   ← proto_id=13 para IPv6
        "48",          # 14 length
        src,           # 15 src ip
        dst,           # 16 dst ip
        str(sport),    # 17 src port
        str(dport),    # 18 dst port
        "8",           # 19
    ]
    payload = ",".join(fields)
    return f'<134>1 {ts} host filterlog 50144 - [meta sequenceId="1"] {payload}\n'


def _write_eve(path: Path, eventos=EVENTOS_REFERENCIA, extra_lines: list[str] | None = None):
    """Escreve arquivo EVE com os eventos fornecidos."""
    linhas = [_eve_line(ts, src, sport) for ts, src, sport in eventos]
    if extra_lines:
        linhas.extend(extra_lines)
    path.write_text("".join(linhas), encoding="utf-8")


def _write_pf(path: Path, linhas: list[str]):
    path.write_text("".join(linhas), encoding="utf-8")


# ---------------------------------------------------------------------------
# timestamp()
# ---------------------------------------------------------------------------

class TestTimestamp:
    def test_com_offset_negativo(self):
        dt = timestamp("2026-09-29T08:51:18.955499-0300")
        assert dt.tzinfo == timezone.utc
        assert dt == datetime(2026, 9, 29, 11, 51, 18, 955499, tzinfo=timezone.utc)

    def test_com_offset_zero(self):
        dt = timestamp("2026-09-29T00:00:00+00:00")
        assert dt == datetime(2026, 9, 29, 0, 0, 0, tzinfo=timezone.utc)

    def test_com_Z(self):
        dt = timestamp("2026-09-29T12:00:00Z")
        assert dt.tzinfo == timezone.utc

    def test_microsegundos_preservados(self):
        dt = timestamp("2026-09-28T22:49:06.102969-0300")
        assert dt.microsecond == 102969

    def test_sem_timezone_levanta_valueerror(self):
        with pytest.raises(ValueError, match="timezone"):
            timestamp("2026-09-28T22:49:06.102969")

    def test_string_invalida_levanta_valueerror(self):
        with pytest.raises(ValueError):
            timestamp("não-é-data")

    def test_offset_positivo(self):
        dt = timestamp("2026-09-29T08:00:00+0300")
        assert dt == datetime(2026, 9, 29, 5, 0, 0, tzinfo=timezone.utc)


# ---------------------------------------------------------------------------
# key()
# ---------------------------------------------------------------------------

class TestKey:
    def test_tupla_orientada_ipv4(self):
        k = key("1.2.3.4", "5.6.7.8", "1234", "9034")
        assert k == ("1.2.3.4", "5.6.7.8", 1234, 9034)

    def test_ipv6(self):
        k = key("2001:db8::1", "2001:db8::2", "123", "9034")
        assert k == ("2001:db8::1", "2001:db8::2", 123, 9034)

    def test_ip_invalido(self):
        with pytest.raises(ValueError):
            key("999.999.999.999", "1.2.3.4", "80", "9034")

    def test_porta_acima_65535(self):
        with pytest.raises(ValueError, match="porta"):
            key("1.2.3.4", "5.6.7.8", "80", "99999")

    def test_porta_negativa(self):
        with pytest.raises(ValueError, match="porta"):
            key("1.2.3.4", "5.6.7.8", "-1", "9034")

    def test_porta_zero_e_65535_validas(self):
        k = key("1.2.3.4", "5.6.7.8", "0", "65535")
        assert k == ("1.2.3.4", "5.6.7.8", 0, 65535)


# ---------------------------------------------------------------------------
# parse_pf()
# ---------------------------------------------------------------------------

class TestParsePF:
    TS = "2026-09-29T08:51:19-03:00"

    def test_ipv4_udp_valido(self):
        linha = _pf_line(self.TS, "165.245.187.19", 51901)
        pf = parse_pf(linha)
        assert pf is not None
        assert pf["key"] == ("165.245.187.19", DEST_IP, 51901, DEST_PORT)
        assert pf["action"]    == "block"
        assert pf["direction"] == "in"
        assert pf["iface"]     == "igb0"
        assert pf["time"].tzinfo == timezone.utc

    def test_timestamp_convertido_para_utc(self):
        linha = _pf_line(self.TS, "1.2.3.4", 9999)
        pf = parse_pf(linha)
        # -03:00 → +3h em UTC
        assert pf["time"].hour == (datetime.fromisoformat(self.TS).hour + 3) % 24

    def test_proto_tcp_retorna_none(self):
        # proto_id=6 (TCP), não UDP → deve retornar None
        linha = _pf_line(self.TS, "1.2.3.4", 80, proto_num="6", proto_txt="tcp")
        assert parse_pf(linha) is None

    def test_proto_icmp_retorna_none(self):
        linha = _pf_line(self.TS, "1.2.3.4", 0, proto_num="1", proto_txt="icmp")
        assert parse_pf(linha) is None

    def test_linha_sem_filterlog_retorna_none(self):
        assert parse_pf("Oct 18 10:00:00 host syslogd: mensagem qualquer\n") is None

    def test_cabecalho_malformado_levanta_valueerror(self):
        # Linha tem 'filterlog' mas o header não casa com o regex RFC5424
        with pytest.raises(ValueError, match="RFC5424"):
            parse_pf("<134>1 filterlog INCOMPLETO SEM ESTRUTURA\n")

    def test_payload_incompleto_levanta_valueerror(self):
        with pytest.raises(ValueError):
            parse_pf('<134>1 2026-09-29T00:00:00Z host filterlog 1 - - a,b,c\n')

    def test_versao_ip_invalida_levanta_valueerror(self):
        # ip_ver=5 não é suportado
        linha = _pf_line(self.TS, "1.2.3.4", 80, ip_ver="5")
        with pytest.raises(ValueError, match="versão IP"):
            parse_pf(linha)

    def test_acao_pass(self):
        linha = _pf_line(self.TS, "1.2.3.4", 80, action="pass")
        pf = parse_pf(linha)
        assert pf["action"] == "pass"

    def test_ipv6_udp(self):
        ts  = "2026-09-29T00:00:00Z"
        pf  = parse_pf(_pf_line_v6(ts, "2001:db8::1", 123, "2001:db8::2", 9034))
        assert pf is not None
        assert pf["key"] == ("2001:db8::1", "2001:db8::2", 123, 9034)


# ---------------------------------------------------------------------------
# analyze()
# ---------------------------------------------------------------------------

class TestAnalyze:
    def test_8_alertas_de_referencia_sem_pf(self, tmp_path):
        """Os 8 eventos reais devem ser encontrados; sem arquivo PF, sem candidatos."""
        eve = tmp_path / "eve.json"
        _write_eve(eve)
        pf  = tmp_path / "pf.log"
        _write_pf(pf, [])
        alerts, summary = analyze(eve, [pf], expected=8)
        assert summary["alertas"]       == 8
        assert summary["com_candidato"] == 0
        assert summary["sem_candidato"] == 8
        assert len(alerts)              == 8

    def test_candidato_dentro_da_janela(self, tmp_path):
        """Registro PF a +0.044s deve ser correlacionado."""
        eve = tmp_path / "eve.json"
        _write_eve(eve, [EVENTOS_REFERENCIA[1]])  # 165.245.187.19, 08:51:18
        ts_pf = (timestamp(EVENTOS_REFERENCIA[1][0]) + timedelta(seconds=0, microseconds=44501)).isoformat()
        pf = tmp_path / "pf.log"
        _write_pf(pf, [_pf_line(ts_pf, "165.245.187.19", 51901)])
        alerts, summary = analyze(eve, [pf], expected=1)
        assert summary["com_candidato"] == 1
        assert abs(alerts[0]["candidates"][0]["delta"] - 0.044501) < 0.001

    def test_candidato_no_limite_exato_da_janela(self, tmp_path):
        """Delta exatamente = 5s deve ser incluído (limite inclusivo)."""
        eve = tmp_path / "eve.json"
        ts_eve = EVENTOS_REFERENCIA[0][0]
        src    = EVENTOS_REFERENCIA[0][1]
        sport  = EVENTOS_REFERENCIA[0][2]
        _write_eve(eve, [(ts_eve, src, sport)])
        ts_pf = (timestamp(ts_eve) + timedelta(seconds=5)).isoformat()
        pf = tmp_path / "pf.log"
        _write_pf(pf, [_pf_line(ts_pf, src, sport)])
        alerts, summary = analyze(eve, [pf], expected=1)
        assert summary["com_candidato"] == 1
        assert alerts[0]["candidates"][0]["delta"] == pytest.approx(5.0, abs=0.001)

    def test_fora_da_janela_nao_correlaciona(self, tmp_path):
        """Delta > 5s não deve ser candidato."""
        eve = tmp_path / "eve.json"
        ts_eve = EVENTOS_REFERENCIA[0][0]
        src    = EVENTOS_REFERENCIA[0][1]
        sport  = EVENTOS_REFERENCIA[0][2]
        _write_eve(eve, [(ts_eve, src, sport)])
        ts_pf = (timestamp(ts_eve) + timedelta(seconds=5, microseconds=1)).isoformat()
        pf = tmp_path / "pf.log"
        _write_pf(pf, [_pf_line(ts_pf, src, sport)])
        alerts, summary = analyze(eve, [pf], expected=1)
        assert summary["com_candidato"] == 0

    def test_multiplos_candidatos_para_mesmo_alerta(self, tmp_path):
        """Dois registros PF dentro da janela → multiplos_candidatos = 1."""
        eve = tmp_path / "eve.json"
        ts_eve = EVENTOS_REFERENCIA[0][0]
        src, sport = EVENTOS_REFERENCIA[0][1], EVENTOS_REFERENCIA[0][2]
        _write_eve(eve, [(ts_eve, src, sport)])
        ts1 = (timestamp(ts_eve) + timedelta(seconds=1)).isoformat()
        ts2 = (timestamp(ts_eve) + timedelta(seconds=2)).isoformat()
        pf = tmp_path / "pf.log"
        _write_pf(pf, [_pf_line(ts1, src, sport), _pf_line(ts2, src, sport)])
        alerts, summary = analyze(eve, [pf], expected=1)
        assert summary["multiplos_candidatos"] == 1
        assert summary["pares_candidatos"]     == 2

    def test_tupla_diferente_nao_correlaciona(self, tmp_path):
        """Porta de origem diferente → não deve correlacionar."""
        eve = tmp_path / "eve.json"
        ts_eve, src, sport = EVENTOS_REFERENCIA[0]
        _write_eve(eve, [(ts_eve, src, sport)])
        pf = tmp_path / "pf.log"
        _write_pf(pf, [_pf_line(timestamp(ts_eve).isoformat(), src, sport + 1)])
        alerts, summary = analyze(eve, [pf], expected=1)
        assert summary["com_candidato"] == 0

    def test_destino_diferente_nao_correlaciona(self, tmp_path):
        ts_eve, src, sport = EVENTOS_REFERENCIA[0]
        eve = tmp_path / "eve.json"
        _write_eve(eve, [(ts_eve, src, sport)])
        pf = tmp_path / "pf.log"
        _write_pf(pf, [_pf_line(timestamp(ts_eve).isoformat(), src, sport, dst="192.168.15.201")])
        alerts, summary = analyze(eve, [pf], expected=1)
        assert summary["com_candidato"] == 0

    def test_contagem_errada_levanta_valueerror(self, tmp_path):
        """expected=9 com 8 alertas → ValueError."""
        eve = tmp_path / "eve.json"
        _write_eve(eve)
        pf = tmp_path / "pf.log"
        _write_pf(pf, [])
        with pytest.raises(ValueError, match="esperados"):
            analyze(eve, [pf], expected=9)

    def test_arquivo_eve_ausente(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            analyze(tmp_path / "nao_existe.json", [], expected=0)

    def test_arquivo_pf_ausente(self, tmp_path):
        eve = tmp_path / "eve.json"
        _write_eve(eve)
        with pytest.raises((FileNotFoundError, OSError)):
            analyze(eve, [tmp_path / "nao_existe.log"], expected=8)

    def test_sid_diferente_ignorado(self, tmp_path):
        """Evento com SID diferente não deve ser coletado."""
        eve = tmp_path / "eve.json"
        eve.write_text(
            _eve_line("2026-09-29T00:00:00Z", "1.2.3.4", 1234, sid=9999999),
            encoding="utf-8",
        )
        pf = tmp_path / "pf.log"
        _write_pf(pf, [])
        alerts, summary = analyze(eve, [pf], sid=SID, expected=0)
        assert summary["alertas"] == 0

    def test_multiplos_arquivos_pf(self, tmp_path):
        """Candidatos espalhados por dois arquivos PF distintos."""
        eve = tmp_path / "eve.json"
        _write_eve(eve, EVENTOS_REFERENCIA[:2])
        ts0 = (timestamp(EVENTOS_REFERENCIA[0][0]) + timedelta(seconds=1)).isoformat()
        ts1 = (timestamp(EVENTOS_REFERENCIA[1][0]) + timedelta(seconds=1)).isoformat()
        pf0 = tmp_path / "pf0.log"
        pf1 = tmp_path / "pf1.log"
        _write_pf(pf0, [_pf_line(ts0, EVENTOS_REFERENCIA[0][1], EVENTOS_REFERENCIA[0][2])])
        _write_pf(pf1, [_pf_line(ts1, EVENTOS_REFERENCIA[1][1], EVENTOS_REFERENCIA[1][2])])
        alerts, summary = analyze(eve, [pf0, pf1], expected=2)
        assert summary["com_candidato"] == 2

    def test_linhas_eve_nao_alerta_ignoradas(self, tmp_path):
        """Linhas EVE de outros tipos não devem entrar como alertas."""
        eve = tmp_path / "eve.json"
        outras = [
            json.dumps({"event_type": "flow", "timestamp": "2026-09-29T00:00:00Z"}) + "\n",
            json.dumps({"event_type": "dns",  "timestamp": "2026-09-29T00:00:01Z"}) + "\n",
            json.dumps({"event_type": "anomaly", "timestamp": "2026-09-29T00:00:02Z"}) + "\n",
            "\n",  # linha em branco
        ]
        _write_eve(eve, EVENTOS_REFERENCIA, extra_lines=outras)
        pf = tmp_path / "pf.log"
        _write_pf(pf, [])
        alerts, summary = analyze(eve, [pf], expected=8)
        assert summary["alertas"] == 8

    def test_acoes_pf_contabilizadas_por_par(self, tmp_path):
        """Duas regras block e uma pass → acoes_pf_por_par correto."""
        eve = tmp_path / "eve.json"
        _write_eve(eve, EVENTOS_REFERENCIA[:2])
        ts0 = timestamp(EVENTOS_REFERENCIA[0][0]).isoformat()
        ts1 = timestamp(EVENTOS_REFERENCIA[1][0]).isoformat()
        pf = tmp_path / "pf.log"
        _write_pf(pf, [
            _pf_line(ts0, EVENTOS_REFERENCIA[0][1], EVENTOS_REFERENCIA[0][2], action="block"),
            _pf_line(ts1, EVENTOS_REFERENCIA[1][1], EVENTOS_REFERENCIA[1][2], action="pass"),
        ])
        _, summary = analyze(eve, [pf], expected=2)
        assert summary["acoes_pf_por_par"] == {"block": 1, "pass": 1}

    def test_janela_personalizada(self, tmp_path):
        """Janela de 1s: delta=2s não correlaciona; delta=0.5s correlaciona."""
        eve = tmp_path / "eve.json"
        ts_eve, src, sport = EVENTOS_REFERENCIA[0]
        _write_eve(eve, [(ts_eve, src, sport)])
        pf = tmp_path / "pf.log"
        ts_dentro = (timestamp(ts_eve) + timedelta(milliseconds=500)).isoformat()
        ts_fora   = (timestamp(ts_eve) + timedelta(seconds=2)).isoformat()
        _write_pf(pf, [
            _pf_line(ts_dentro, src, sport),
            _pf_line(ts_fora,   src, sport),
        ])
        alerts, summary = analyze(eve, [pf], window=1, expected=1)
        assert summary["com_candidato"] == 1
        assert summary["pares_candidatos"] == 1


# ---------------------------------------------------------------------------
# save()
# ---------------------------------------------------------------------------

class TestSave:
    def _setup(self, tmp_path):
        eve = tmp_path / "eve.json"
        _write_eve(eve, EVENTOS_REFERENCIA[:3])
        ts0 = (timestamp(EVENTOS_REFERENCIA[1][0]) + timedelta(seconds=1)).isoformat()
        pf  = tmp_path / "pf.log"
        _write_pf(pf, [_pf_line(ts0, EVENTOS_REFERENCIA[1][1], EVENTOS_REFERENCIA[1][2])])
        alerts, summary = analyze(eve, [pf], expected=3)
        out = tmp_path / "out"
        save(alerts, summary, out)
        return out, alerts, summary

    def test_csv_criado(self, tmp_path):
        out, _, _ = self._setup(tmp_path)
        assert (out / "correlacao_sid2044008.csv").exists()

    def test_resumo_json_criado(self, tmp_path):
        out, _, _ = self._setup(tmp_path)
        assert (out / "resumo.json").exists()

    def test_resumo_txt_criado(self, tmp_path):
        out, _, _ = self._setup(tmp_path)
        assert (out / "resumo.txt").exists()

    def test_csv_campos_obrigatorios(self, tmp_path):
        out, _, _ = self._setup(tmp_path)
        with (out / "correlacao_sid2044008.csv").open(encoding="utf-8", newline="") as f:
            rows = list(csv.DictReader(f))
        campos = set(rows[0].keys())
        for campo in ("alerta_id", "status", "src_ip", "dest_ip", "src_port",
                      "dest_port", "proto", "eve_timestamp", "pf_acao"):
            assert campo in campos, f"Campo obrigatório ausente: {campo}"

    def test_csv_tem_candidato_e_sem_candidato(self, tmp_path):
        out, _, _ = self._setup(tmp_path)
        with (out / "correlacao_sid2044008.csv").open(encoding="utf-8", newline="") as f:
            rows = list(csv.DictReader(f))
        status_vals = {r["status"] for r in rows}
        assert "candidato"      in status_vals
        assert "sem_candidato"  in status_vals

    def test_csv_n_linhas(self, tmp_path):
        """3 alertas, 1 com candidato → 3 linhas no CSV."""
        out, _, _ = self._setup(tmp_path)
        with (out / "correlacao_sid2044008.csv").open(encoding="utf-8", newline="") as f:
            rows = list(csv.DictReader(f))
        assert len(rows) == 3

    def test_resumo_json_bate_com_summary(self, tmp_path):
        out, _, summary = self._setup(tmp_path)
        gravado = json.loads((out / "resumo.json").read_text(encoding="utf-8"))
        assert gravado["alertas"]       == summary["alertas"]
        assert gravado["com_candidato"] == summary["com_candidato"]
        assert gravado["sid"]           == SID

    def test_resumo_json_contem_observacao(self, tmp_path):
        out, _, _ = self._setup(tmp_path)
        gravado = json.loads((out / "resumo.json").read_text(encoding="utf-8"))
        assert "observacao" in gravado
        assert "candidato" in gravado["observacao"].lower()

    def test_resumo_txt_contem_sid(self, tmp_path):
        out, _, _ = self._setup(tmp_path)
        txt = (out / "resumo.txt").read_text(encoding="utf-8")
        assert str(SID) in txt

    def test_csv_proto_sempre_UDP(self, tmp_path):
        out, _, _ = self._setup(tmp_path)
        with (out / "correlacao_sid2044008.csv").open(encoding="utf-8", newline="") as f:
            rows = list(csv.DictReader(f))
        assert all(r["proto"] == "UDP" for r in rows)

    def test_idempotencia_save(self, tmp_path):
        """Chamar save() duas vezes não deve duplicar linhas."""
        eve = tmp_path / "eve.json"
        _write_eve(eve, EVENTOS_REFERENCIA[:1])
        pf  = tmp_path / "pf.log"
        _write_pf(pf, [])
        alerts, summary = analyze(eve, [pf], expected=1)
        out = tmp_path / "out"
        save(alerts, summary, out)
        save(alerts, summary, out)  # segunda chamada
        with (out / "correlacao_sid2044008.csv").open(encoding="utf-8", newline="") as f:
            rows = list(csv.DictReader(f))
        assert len(rows) == 1


# ---------------------------------------------------------------------------
# Autoteste interno
# ---------------------------------------------------------------------------

class TestSelfTest:
    def test_self_test_passa_sem_excecao(self):
        """O self_test() embutido no correlacionador deve executar sem erros."""
        self_test()  # levanta AssertionError ou ValueError se falhar
