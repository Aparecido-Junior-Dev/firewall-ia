"""
test_correlacionar_v2.py — Testes unitários do correlacionador v2

Cobre:
  - calc_community_id(): IPv4 TCP/UDP, simetria, proto inválido
  - classificar_trilha(): interna, reputação, comportamento
  - parse_pf_linha(): IPv4 UDP/TCP, community_id calculado, proto ignorado
  - correlacionar(): BLOQUEADO, PASSOU, SEM_REGISTRO, AMBOS
  - separação de trilhas: interna ≠ comportamento
  - salvar(): arquivos gerados, campos obrigatórios no CSV

Versão: 1.0.0
Data:   2026-11-02
"""

import csv
import json
import sys
import tempfile
from datetime import datetime, timezone, timedelta
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from correlacionar_v2 import (
    calc_community_id,
    classificar_trilha,
    parse_pf_linha,
    correlacionar,
    indexar_pf,
    salvar,
    COMMUNITYID_OK,
    CATS_REPUTACAO,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

TS_BASE  = "2026-09-29T10:00:00-03:00"
TS_BASE2 = "2026-09-29T10:00:01-03:00"  # 1s depois


def _pf_line(ts: str, src: str, sport: int, dst: str, dport: int,
             action: str = "block", proto_id: str = "17",
             iface: str = "igb0") -> str:
    """Gera linha filterlog IPv4 UDP ou TCP sintética."""
    proto_txt = "udp" if proto_id == "17" else "tcp"
    fields = [
        "5", "0", "0", "uuid-test", iface,
        "match", action, "in", "4",
        "0x0", "", "64", "1", "0", "none",
        proto_id, proto_txt, "28",
        src, dst, str(sport), str(dport), "8",
    ]
    payload = ",".join(fields)
    return f'<134>1 {ts} host filterlog 50144 - [meta sequenceId="1"] {payload}\n'


def _eve_line(ts: str, src: str, sport: int, dst: str = "192.168.15.200",
              dport: int = 9034, proto: str = "UDP", sid: int = 2044008,
              cat: str = "Misc Attack", src_internal: bool = False) -> str:
    return json.dumps({
        "event_type": "alert",
        "timestamp":  ts,
        "src_ip":     src,
        "src_port":   sport,
        "dest_ip":    dst,
        "dest_port":  dport,
        "proto":      proto,
        "in_iface":   "igb0",
        "alert": {
            "signature_id": sid,
            "action":       "allowed",
            "signature":    "ET TEST",
            "category":     cat,
            "severity":     2,
        },
    }) + "\n"


def _write_eve(path: Path, linhas: list[str]):
    path.write_text("".join(linhas), encoding="utf-8")


def _write_pf(path: Path, linhas: list[str]):
    path.write_text("".join(linhas), encoding="utf-8")


# ---------------------------------------------------------------------------
# calc_community_id
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not COMMUNITYID_OK, reason="communityid não instalado")
class TestCommunityID:
    def test_udp_retorna_string(self):
        cid = calc_community_id("UDP", "1.2.3.4", 1234, "5.6.7.8", 9034)
        assert isinstance(cid, str)
        assert cid.startswith("1:")

    def test_tcp_retorna_string(self):
        cid = calc_community_id("TCP", "1.2.3.4", 80, "5.6.7.8", 443)
        assert isinstance(cid, str)
        assert cid.startswith("1:")

    def test_simetria_udp(self):
        """Community ID deve ser o mesmo nos dois sentidos do fluxo."""
        a = calc_community_id("UDP", "1.2.3.4", 1234, "5.6.7.8", 9034)
        b = calc_community_id("UDP", "5.6.7.8", 9034, "1.2.3.4", 1234)
        assert a == b

    def test_simetria_tcp(self):
        a = calc_community_id("TCP", "10.0.0.1", 55000, "8.8.8.8", 443)
        b = calc_community_id("TCP", "8.8.8.8", 443, "10.0.0.1", 55000)
        assert a == b

    def test_diferente_para_portas_distintas(self):
        a = calc_community_id("UDP", "1.2.3.4", 1111, "5.6.7.8", 9034)
        b = calc_community_id("UDP", "1.2.3.4", 2222, "5.6.7.8", 9034)
        assert a != b

    def test_proto_invalido_retorna_none(self):
        cid = calc_community_id("IGMP", "1.2.3.4", 0, "5.6.7.8", 0)
        assert cid is None

    def test_realtek_conhecido(self):
        """Alerta 2 do estudo de caso: 165.245.187.19:51901 → 192.168.15.200:9034"""
        cid = calc_community_id("UDP", "165.245.187.19", 51901,
                                 "192.168.15.200", 9034)
        assert cid == "1:gNg4PTjKqHUqYFNspAqRjXH+4r0="


# ---------------------------------------------------------------------------
# classificar_trilha
# ---------------------------------------------------------------------------

class TestClassificarTrilha:
    def test_ip_privado_192(self):
        assert classificar_trilha("192.168.1.1", "Misc Attack") == "interna"

    def test_ip_privado_10(self):
        assert classificar_trilha("10.0.0.5", "Misc Attack") == "interna"

    def test_ip_privado_172(self):
        assert classificar_trilha("172.16.0.100", "Misc Attack") == "interna"

    def test_ip_publico_reputacao(self):
        for cat in CATS_REPUTACAO:
            assert classificar_trilha("1.2.3.4", cat) == "reputacao"

    def test_ip_publico_comportamento(self):
        assert classificar_trilha("8.8.8.8", "Misc Attack") == "comportamento"

    def test_ip_publico_exploit(self):
        assert classificar_trilha("94.154.43.117",
                                   "Attempted Administrator Privilege Gain") == "comportamento"

    def test_ip_invalido_comportamento(self):
        # IP inválido não é privado → comportamento
        assert classificar_trilha("invalid", "Misc Attack") == "comportamento"


# ---------------------------------------------------------------------------
# parse_pf_linha
# ---------------------------------------------------------------------------

class TestParsePFLinha:
    TS = "2026-09-29T10:00:00-03:00"

    def test_udp_retorna_dict(self):
        linha = _pf_line(self.TS, "1.2.3.4", 1234, "5.6.7.8", 9034)
        pf = parse_pf_linha(linha)
        assert pf is not None
        assert pf["src_ip"]   == "1.2.3.4"
        assert pf["dst_ip"]   == "5.6.7.8"
        assert pf["src_port"] == 1234
        assert pf["dst_port"] == 9034
        assert pf["proto"]    == "UDP"
        assert pf["action"]   == "block"

    def test_tcp_retorna_dict(self):
        linha = _pf_line(self.TS, "1.2.3.4", 80, "5.6.7.8", 443,
                         proto_id="6", action="pass")
        pf = parse_pf_linha(linha)
        assert pf is not None
        assert pf["proto"]  == "TCP"
        assert pf["action"] == "pass"

    def test_community_id_calculado(self):
        if not COMMUNITYID_OK:
            pytest.skip("communityid não instalado")
        linha = _pf_line(self.TS, "165.245.187.19", 51901,
                         "192.168.15.200", 9034)
        pf = parse_pf_linha(linha)
        assert pf["community_id"] == "1:gNg4PTjKqHUqYFNspAqRjXH+4r0="

    def test_sem_filterlog_retorna_none(self):
        assert parse_pf_linha("linha qualquer sem a palavra\n") is None

    def test_icmp_retorna_none(self):
        """ICMP (proto_id=1) não é UDP nem TCP → None."""
        fields = ["5","0","0","uuid","igb0","match","block","in","4",
                  "0x0","","64","1","0","none","1","icmp","28",
                  "1.2.3.4","5.6.7.8","0","0","8"]
        payload = ",".join(fields)
        linha = f'<134>1 {self.TS} host filterlog 1 - - {payload}\n'
        assert parse_pf_linha(linha) is None

    def test_timestamp_convertido_utc(self):
        linha = _pf_line("2026-09-29T10:00:00-03:00", "1.2.3.4", 80,
                         "5.6.7.8", 443, proto_id="6")
        pf = parse_pf_linha(linha)
        assert pf["time"].tzinfo == timezone.utc
        assert pf["time"].hour == 13   # -03:00 → UTC = +3h


# ---------------------------------------------------------------------------
# indexar_pf
# ---------------------------------------------------------------------------

class TestIndexarPF:
    def test_indexa_eventos(self, tmp_path):
        pf = tmp_path / "pf.log"
        _write_pf(pf, [
            _pf_line(TS_BASE,  "1.2.3.4", 1111, "5.6.7.8", 9034, "block"),
            _pf_line(TS_BASE2, "1.2.3.4", 2222, "5.6.7.8", 9034, "pass"),
        ])
        idx, cnt = indexar_pf([pf], verbose=False)
        assert cnt["eventos_udp_tcp"] == 2
        assert cnt["action_block"] == 1
        assert cnt["action_pass"]  == 1

    def test_arquivo_inexistente_ignorado(self, tmp_path):
        idx, cnt = indexar_pf([tmp_path / "nao_existe.log"], verbose=False)
        assert len(idx) == 0


# ---------------------------------------------------------------------------
# correlacionar
# ---------------------------------------------------------------------------

class TestCorrelacionar:
    def _setup(self, tmp_path, pf_linhas=None, eve_linhas=None):
        eve = tmp_path / "eve.json"
        pf  = tmp_path / "pf.log"
        _write_eve(eve, eve_linhas or [])
        _write_pf(pf, pf_linhas or [])
        idx, cnt_pf = indexar_pf([pf], verbose=False)
        return eve, idx, cnt_pf

    def test_bloqueado(self, tmp_path):
        """Alerta com par PF block → BLOQUEADO."""
        eve, idx, cnt_pf = self._setup(tmp_path,
            pf_linhas=[_pf_line(TS_BASE, "1.2.3.4", 1234, "5.6.7.8", 9034, "block")],
            eve_linhas=[_eve_line(TS_BASE, "1.2.3.4", 1234, "5.6.7.8", 9034)],
        )
        alertas, cnt, _ = correlacionar(eve, idx, cnt_pf)
        assert len(alertas) == 1
        assert alertas[0]["desfecho"] == "BLOQUEADO"

    def test_passou(self, tmp_path):
        """Alerta com par PF pass → PASSOU."""
        eve, idx, cnt_pf = self._setup(tmp_path,
            pf_linhas=[_pf_line(TS_BASE, "1.2.3.4", 1234, "5.6.7.8", 9034, "pass")],
            eve_linhas=[_eve_line(TS_BASE, "1.2.3.4", 1234, "5.6.7.8", 9034)],
        )
        alertas, cnt, _ = correlacionar(eve, idx, cnt_pf)
        assert alertas[0]["desfecho"] == "PASSOU"

    def test_sem_registro(self, tmp_path):
        """Alerta sem par PF → SEM_REGISTRO."""
        eve, idx, cnt_pf = self._setup(tmp_path,
            pf_linhas=[],
            eve_linhas=[_eve_line(TS_BASE, "9.9.9.9", 5555, "5.6.7.8", 9034)],
        )
        alertas, cnt, _ = correlacionar(eve, idx, cnt_pf)
        assert alertas[0]["desfecho"] == "SEM_REGISTRO"

    def test_ambos(self, tmp_path):
        """Mesmo community_id com pass e block → AMBOS."""
        eve, idx, cnt_pf = self._setup(tmp_path,
            pf_linhas=[
                _pf_line(TS_BASE,  "1.2.3.4", 1234, "5.6.7.8", 9034, "block"),
                _pf_line(TS_BASE2, "1.2.3.4", 1234, "5.6.7.8", 9034, "pass"),
            ],
            eve_linhas=[_eve_line(TS_BASE, "1.2.3.4", 1234, "5.6.7.8", 9034)],
        )
        alertas, cnt, _ = correlacionar(eve, idx, cnt_pf)
        assert alertas[0]["desfecho"] == "AMBOS"

    def test_trilha_interna(self, tmp_path):
        """IP privado → trilha interna."""
        eve, idx, cnt_pf = self._setup(tmp_path,
            pf_linhas=[],
            eve_linhas=[_eve_line(TS_BASE, "192.168.15.200", 1234)],
        )
        alertas, _, _ = correlacionar(eve, idx, cnt_pf)
        assert alertas[0]["trilha"] == "interna"

    def test_trilha_reputacao(self, tmp_path):
        eve, idx, cnt_pf = self._setup(tmp_path,
            pf_linhas=[],
            eve_linhas=[_eve_line(TS_BASE, "8.8.8.8", 1234,
                                  cat="Misc Activity")],
        )
        alertas, _, _ = correlacionar(eve, idx, cnt_pf)
        assert alertas[0]["trilha"] == "reputacao"

    def test_trilha_comportamento(self, tmp_path):
        eve, idx, cnt_pf = self._setup(tmp_path,
            pf_linhas=[],
            eve_linhas=[_eve_line(TS_BASE, "8.8.8.8", 1234,
                                  cat="Misc Attack")],
        )
        alertas, _, _ = correlacionar(eve, idx, cnt_pf)
        assert alertas[0]["trilha"] == "comportamento"

    def test_filtro_sid(self, tmp_path):
        """Com sid=999 deve ignorar alertas de outros SIDs."""
        eve, idx, cnt_pf = self._setup(tmp_path,
            pf_linhas=[],
            eve_linhas=[
                _eve_line(TS_BASE,  "1.1.1.1", 1111, sid=2044008),
                _eve_line(TS_BASE2, "2.2.2.2", 2222, sid=9999999),
            ],
        )
        alertas, cnt, _ = correlacionar(eve, idx, cnt_pf, sid=9999999)
        assert len(alertas) == 1
        assert alertas[0]["src_ip"] == "2.2.2.2"

    def test_sem_filtro_processa_tudo(self, tmp_path):
        eve, idx, cnt_pf = self._setup(tmp_path,
            pf_linhas=[],
            eve_linhas=[
                _eve_line(TS_BASE,  "1.1.1.1", 1111, sid=111),
                _eve_line(TS_BASE2, "2.2.2.2", 2222, sid=222),
            ],
        )
        alertas, _, _ = correlacionar(eve, idx, cnt_pf, sid=None)
        assert len(alertas) == 2

    def test_community_id_calculado_presente(self, tmp_path):
        if not COMMUNITYID_OK:
            pytest.skip("communityid não instalado")
        eve, idx, cnt_pf = self._setup(tmp_path,
            pf_linhas=[],
            eve_linhas=[_eve_line(TS_BASE, "165.245.187.19", 51901,
                                  "192.168.15.200", 9034)],
        )
        alertas, _, _ = correlacionar(eve, idx, cnt_pf)
        assert alertas[0]["community_id"] == "1:gNg4PTjKqHUqYFNspAqRjXH+4r0="
        assert alertas[0]["cid_fonte"] == "calculado"

    def test_linha_eve_nao_alerta_ignorada(self, tmp_path):
        eve, idx, cnt_pf = self._setup(tmp_path,
            pf_linhas=[],
            eve_linhas=[
                json.dumps({"event_type": "flow", "timestamp": TS_BASE}) + "\n",
                json.dumps({"event_type": "dns",  "timestamp": TS_BASE}) + "\n",
                _eve_line(TS_BASE, "1.1.1.1", 1111),
            ],
        )
        alertas, _, _ = correlacionar(eve, idx, cnt_pf)
        assert len(alertas) == 1

    def test_multiplos_candidatos_pf_block(self, tmp_path):
        """Dois registros PF block para o mesmo fluxo → BLOQUEADO, n_candidatos=2."""
        eve, idx, cnt_pf = self._setup(tmp_path,
            pf_linhas=[
                _pf_line(TS_BASE,  "1.2.3.4", 1234, "5.6.7.8", 9034, "block"),
                _pf_line(TS_BASE2, "1.2.3.4", 1234, "5.6.7.8", 9034, "block"),
            ],
            eve_linhas=[_eve_line(TS_BASE, "1.2.3.4", 1234, "5.6.7.8", 9034)],
        )
        alertas, _, _ = correlacionar(eve, idx, cnt_pf)
        assert alertas[0]["desfecho"]        == "BLOQUEADO"
        assert alertas[0]["n_candidatos_pf"] == 2


# ---------------------------------------------------------------------------
# salvar
# ---------------------------------------------------------------------------

class TestSalvar:
    def _rodar(self, tmp_path):
        """EVE e PF usam o mesmo dst/dport para que o community_id coincida."""
        eve = tmp_path / "eve.json"
        pf  = tmp_path / "pf.log"
        DST = "192.168.15.200"
        DP  = 9034
        _write_pf(pf, [
            _pf_line(TS_BASE, "1.1.1.1", 1111, DST, DP, "block"),
            _pf_line(TS_BASE, "2.2.2.2", 2222, DST, DP, "pass"),
        ])
        _write_eve(eve, [
            _eve_line(TS_BASE, "1.1.1.1", 1111, DST, DP),
            _eve_line(TS_BASE, "2.2.2.2", 2222, DST, DP),
            _eve_line(TS_BASE, "3.3.3.3", 3333, DST, DP),  # sem par
        ])
        idx, cnt_pf = indexar_pf([pf], verbose=False)
        alertas, cnt_eve, _ = correlacionar(eve, idx, cnt_pf)
        out = tmp_path / "out"
        salvar(alertas, cnt_eve, cnt_pf, sid=None, janela_s=30, out_dir=out)
        return out, alertas

    def test_csv_criado(self, tmp_path):
        out, _ = self._rodar(tmp_path)
        assert (out / "correlacao_v2.csv").exists()

    def test_json_criado(self, tmp_path):
        out, _ = self._rodar(tmp_path)
        assert (out / "resumo_v2.json").exists()

    def test_md_criado(self, tmp_path):
        out, _ = self._rodar(tmp_path)
        assert (out / "resumo_v2.md").exists()

    def test_csv_campos_obrigatorios(self, tmp_path):
        out, _ = self._rodar(tmp_path)
        with (out / "correlacao_v2.csv").open(newline="") as f:
            campos = set(csv.DictReader(f).fieldnames)
        for c in ("sid","src_ip","desfecho","trilha","community_id","cid_fonte"):
            assert c in campos

    def test_csv_tres_linhas(self, tmp_path):
        out, _ = self._rodar(tmp_path)
        with (out / "correlacao_v2.csv").open(newline="") as f:
            linhas = list(csv.DictReader(f))
        assert len(linhas) == 3

    def test_json_por_desfecho(self, tmp_path):
        out, _ = self._rodar(tmp_path)
        d = json.loads((out / "resumo_v2.json").read_text())
        assert d["por_desfecho"]["BLOQUEADO"] == 1
        assert d["por_desfecho"]["PASSOU"]    == 1
        assert d["por_desfecho"]["SEM_REGISTRO"] == 1

    def test_json_community_id_ativo(self, tmp_path):
        out, _ = self._rodar(tmp_path)
        d = json.loads((out / "resumo_v2.json").read_text())
        assert d["communityid_ativo"] == COMMUNITYID_OK

    def test_md_contem_desfecho(self, tmp_path):
        out, _ = self._rodar(tmp_path)
        md = (out / "resumo_v2.md").read_text()
        assert "BLOQUEADO" in md
        assert "PASSOU"    in md
        assert "SEM_REGISTRO" in md
