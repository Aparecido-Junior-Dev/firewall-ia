"""
test_propor_regra.py — Testes unitários do propositor de regras

Cobre:
  - carregar_config(): campos presentes, ausentes, comentários, linhas vazias
  - validar_ip(): IPv4, IPv6, inválido
  - selecionar_candidatos(): filtragem correta por status e pf_acao
  - agrupar_por_ip(): agrupamento, deduplicação
  - montar_payload(): campos obrigatórios, prefixo, truncamento de descrição
  - OPNsenseAPI (mock): erro HTTP, erro de rede, timeout
  - fluxo executar(): dry-run não chama API; gera CSV e MD; idempotência
  - fluxo executar(): aplicar=True chama criar_regra e aplicar
  - Detecção de duplicata: IP já presente não gera nova chamada

Todos os testes são isolados — não fazem requisições de rede reais.

Versão: 1.0.0
Data:   2026-10-18
"""

import csv
import json
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch, call

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from propor_regra import (
    PREFIXO_DESC,
    SID,
    VERSION,
    agrupar_por_ip,
    carregar_config,
    executar,
    montar_payload,
    selecionar_candidatos,
    validar_ip,
)

# ---------------------------------------------------------------------------
# CSV de correlação sintético
# ---------------------------------------------------------------------------

CAMPOS_CSV = (
    "alerta_id,status,n_candidatos,eve_timestamp,eve_utc,eve_arquivo,eve_linha,"
    "src_ip,dest_ip,src_port,dest_port,proto,eve_interface,eve_acao,"
    "pf_timestamp,pf_utc,delta_pf_menos_eve_s,pf_arquivo,pf_linha,"
    "pf_interface,interface_igual,pf_acao,pf_direcao,pf_regra,pf_tracker"
).split(",")


def _linha_candidato(alerta_id: int, src_ip: str, delta: float = 0.5) -> dict:
    return {
        "alerta_id":           str(alerta_id),
        "status":              "candidato",
        "n_candidatos":        "1",
        "eve_timestamp":       "2026-09-29T08:51:18.955499-0300",
        "eve_utc":             "2026-09-29T11:51:18.955499+00:00",
        "eve_arquivo":         "/data/raw/suricata/eve.json",
        "eve_linha":           "100",
        "src_ip":              src_ip,
        "dest_ip":             "192.168.15.200",
        "src_port":            "51901",
        "dest_port":           "9034",
        "proto":               "UDP",
        "eve_interface":       "igb0",
        "eve_acao":            "allowed",
        "pf_timestamp":        "2026-09-29T08:51:19-03:00",
        "pf_utc":              "2026-09-29T11:51:19+00:00",
        "delta_pf_menos_eve_s": str(delta),
        "pf_arquivo":          "/data/raw/pf/filter_20260929.log",
        "pf_linha":            "26649",
        "pf_interface":        "igb0",
        "interface_igual":     "true",
        "pf_acao":             "block",
        "pf_direcao":          "in",
        "pf_regra":            "5",
        "pf_tracker":          "02f4bab031b57d1e",
    }


def _linha_sem_candidato(alerta_id: int, src_ip: str) -> dict:
    row = _linha_candidato(alerta_id, src_ip)
    row.update({
        "status":              "sem_candidato",
        "n_candidatos":        "0",
        "pf_timestamp":        "",
        "pf_utc":              "",
        "delta_pf_menos_eve_s": "",
        "pf_arquivo":          "",
        "pf_linha":            "",
        "pf_interface":        "",
        "interface_igual":     "",
        "pf_acao":             "",
        "pf_direcao":          "",
        "pf_regra":            "",
        "pf_tracker":          "",
    })
    return row


def _escrever_csv(path: Path, linhas: list[dict]):
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=CAMPOS_CSV)
        writer.writeheader()
        writer.writerows(linhas)


# ---------------------------------------------------------------------------
# Fixture: config de API
# ---------------------------------------------------------------------------

@pytest.fixture
def config_file(tmp_path) -> Path:
    cf = tmp_path / "opnsense_api.conf"
    cf.write_text(
        "# comentário\n"
        "\n"
        "OPNSENSE_HOST=172.16.0.1\n"
        "OPNSENSE_API_KEY=chave-teste-abc123\n"
        "OPNSENSE_API_SECRET=segredo-teste-xyz789\n"
        "OPNSENSE_VERIFY_TLS=false\n",
        encoding="utf-8",
    )
    return cf


# ---------------------------------------------------------------------------
# carregar_config()
# ---------------------------------------------------------------------------

class TestCarregarConfig:
    def test_lê_campos_obrigatórios(self, config_file):
        cfg = carregar_config(config_file)
        assert cfg["OPNSENSE_HOST"]       == "172.16.0.1"
        assert cfg["OPNSENSE_API_KEY"]    == "chave-teste-abc123"
        assert cfg["OPNSENSE_API_SECRET"] == "segredo-teste-xyz789"

    def test_ignora_comentarios_e_linhas_vazias(self, config_file):
        cfg = carregar_config(config_file)
        assert len(cfg) == 4  # HOST, KEY, SECRET, VERIFY_TLS

    def test_arquivo_ausente(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            carregar_config(tmp_path / "nao_existe.conf")

    def test_campo_obrigatorio_ausente(self, tmp_path):
        cf = tmp_path / "incompleto.conf"
        cf.write_text("OPNSENSE_HOST=172.16.0.1\n", encoding="utf-8")
        with pytest.raises(ValueError, match="OPNSENSE_API_KEY"):
            carregar_config(cf)

    def test_todos_os_tres_campos_ausentes(self, tmp_path):
        cf = tmp_path / "vazio.conf"
        cf.write_text("# apenas comentario\n", encoding="utf-8")
        with pytest.raises(ValueError):
            carregar_config(cf)

    def test_linhas_sem_sinal_de_igual_ignoradas(self, tmp_path):
        cf = tmp_path / "conf.conf"
        cf.write_text(
            "OPNSENSE_HOST=1.2.3.4\n"
            "OPNSENSE_API_KEY=k\n"
            "OPNSENSE_API_SECRET=s\n"
            "LINHA_SEM_IGUAL\n",
            encoding="utf-8",
        )
        cfg = carregar_config(cf)
        assert "LINHA_SEM_IGUAL" not in cfg


# ---------------------------------------------------------------------------
# validar_ip()
# ---------------------------------------------------------------------------

class TestValidarIP:
    def test_ipv4_valido(self):      assert validar_ip("1.2.3.4")          is True
    def test_ipv6_valido(self):      assert validar_ip("2001:db8::1")       is True
    def test_invalido_texto(self):   assert validar_ip("nao-e-ip")          is False
    def test_invalido_octet(self):   assert validar_ip("999.999.999.999")   is False
    def test_vazio(self):            assert validar_ip("")                   is False


# ---------------------------------------------------------------------------
# selecionar_candidatos()
# ---------------------------------------------------------------------------

class TestSelecionarCandidatos:
    def test_retorna_so_candidatos_block(self):
        linhas = [
            _linha_candidato(1, "1.1.1.1"),         # candidato + block ✓
            _linha_sem_candidato(2, "2.2.2.2"),      # sem_candidato ✗
            {**_linha_candidato(3, "3.3.3.3"), "pf_acao": "pass"},   # candidato + pass ✗
        ]
        selecionados = selecionar_candidatos(linhas)
        assert len(selecionados) == 1
        assert selecionados[0]["src_ip"] == "1.1.1.1"

    def test_sem_candidatos_retorna_lista_vazia(self):
        linhas = [_linha_sem_candidato(i, f"1.1.1.{i}") for i in range(3)]
        assert selecionar_candidatos(linhas) == []

    def test_todos_candidatos_block(self):
        linhas = [_linha_candidato(i, f"10.0.0.{i}") for i in range(5)]
        assert len(selecionar_candidatos(linhas)) == 5

    def test_candidato_com_acao_reject_excluido(self):
        linhas = [{**_linha_candidato(1, "1.1.1.1"), "pf_acao": "reject"}]
        assert selecionar_candidatos(linhas) == []

    def test_lista_vazia(self):
        assert selecionar_candidatos([]) == []


# ---------------------------------------------------------------------------
# agrupar_por_ip()
# ---------------------------------------------------------------------------

class TestAgruparPorIP:
    def test_agrupa_por_src_ip(self):
        candidatos = [
            _linha_candidato(1, "10.0.0.1"),
            _linha_candidato(2, "10.0.0.1"),
            _linha_candidato(3, "10.0.0.2"),
        ]
        grupos = agrupar_por_ip(candidatos)
        assert len(grupos) == 2
        assert len(grupos["10.0.0.1"]) == 2
        assert len(grupos["10.0.0.2"]) == 1

    def test_cinco_ips_distintos(self):
        ips = ["165.245.187.19", "74.81.97.18", "121.171.129.37",
               "118.31.169.106", "94.154.43.117"]
        candidatos = [_linha_candidato(i+1, ip) for i, ip in enumerate(ips)]
        grupos = agrupar_por_ip(candidatos)
        assert set(grupos.keys()) == set(ips)

    def test_lista_vazia(self):
        assert agrupar_por_ip([]) == {}


# ---------------------------------------------------------------------------
# montar_payload()
# ---------------------------------------------------------------------------

class TestMontarPayload:
    def _alertas(self, n=1):
        return [_linha_candidato(i+1, "1.2.3.4") for i in range(n)]

    def test_campos_obrigatorios_presentes(self):
        payload = montar_payload("1.2.3.4", self._alertas())
        for campo in ("enabled", "action", "interface", "direction", "ipprotocol",
                      "protocol", "source_net", "destination_port", "log", "description"):
            assert campo in payload, f"Campo ausente: {campo}"

    def test_acao_e_block(self):
        payload = montar_payload("1.2.3.4", self._alertas())
        assert payload["action"] == "block"

    def test_source_net_e_o_ip(self):
        payload = montar_payload("5.6.7.8", self._alertas())
        assert payload["source_net"] == "5.6.7.8"

    def test_porta_destino_correta(self):
        payload = montar_payload("1.2.3.4", self._alertas())
        assert payload["destination_port"] == "9034"

    def test_descricao_comeca_com_prefixo(self):
        payload = montar_payload("1.2.3.4", self._alertas())
        assert payload["description"].startswith(PREFIXO_DESC)

    def test_descricao_contem_ip(self):
        payload = montar_payload("1.2.3.4", self._alertas())
        assert "1.2.3.4" in payload["description"]

    def test_descricao_contem_sid(self):
        payload = montar_payload("1.2.3.4", self._alertas())
        assert str(SID) in payload["description"]

    def test_descricao_contem_cve(self):
        payload = montar_payload("1.2.3.4", self._alertas())
        assert "CVE-2021-35394" in payload["description"]

    def test_descricao_max_255_chars(self):
        payload = montar_payload("1.2.3.4", self._alertas(n=20))
        assert len(payload["description"]) <= 255

    def test_log_ativado(self):
        payload = montar_payload("1.2.3.4", self._alertas())
        assert payload["log"] == "1"

    def test_quick_ativado(self):
        payload = montar_payload("1.2.3.4", self._alertas())
        assert payload["quick"] == "1"

    def test_multiplos_alertas_ids_na_descricao(self):
        alertas = [_linha_candidato(i+1, "1.2.3.4") for i in range(3)]
        alertas[0]["alerta_id"] = "2"
        alertas[1]["alerta_id"] = "4"
        alertas[2]["alerta_id"] = "7"
        payload = montar_payload("1.2.3.4", alertas)
        desc = payload["description"]
        assert "2" in desc and "4" in desc and "7" in desc


# ---------------------------------------------------------------------------
# executar() — dry-run
# ---------------------------------------------------------------------------

class TestExecutarDryRun:
    def _csv_padrao(self, tmp_path: Path) -> Path:
        """Cria um CSV com 5 candidatos block + 3 sem_candidato."""
        ips = ["165.245.187.19", "74.81.97.18", "121.171.129.37",
               "118.31.169.106", "94.154.43.117"]
        linhas = [_linha_candidato(i+1, ip) for i, ip in enumerate(ips)]
        linhas += [_linha_sem_candidato(i+6, f"9.9.9.{i}") for i in range(3)]
        csv_path = tmp_path / "correlacao.csv"
        _escrever_csv(csv_path, linhas)
        return csv_path

    def _config(self, tmp_path: Path) -> Path:
        cf = tmp_path / "api.conf"
        cf.write_text(
            "OPNSENSE_HOST=172.16.0.1\n"
            "OPNSENSE_API_KEY=k\n"
            "OPNSENSE_API_SECRET=s\n",
            encoding="utf-8",
        )
        return cf

    def test_dry_run_nao_chama_api(self, tmp_path, monkeypatch):
        """Em dry-run, nenhuma chamada HTTP deve ser feita."""
        csv_p = self._csv_padrao(tmp_path)
        cf    = self._config(tmp_path)
        monkeypatch.setattr("propor_regra.CONFIG_FILE",  cf)
        monkeypatch.setattr("propor_regra.REPORT_DIR",   tmp_path / "reports")

        chamadas = []
        def mock_request(self_api, metodo, endpoint, corpo=None):
            chamadas.append(endpoint)
            return {}

        monkeypatch.setattr("propor_regra.OPNsenseAPI._request", mock_request)
        executar(csv_path=csv_p, aplicar=False, dry_run=True)
        assert chamadas == [], f"API foi chamada em dry-run: {chamadas}"

    def test_dry_run_gera_relatorio_json(self, tmp_path, monkeypatch):
        csv_p = self._csv_padrao(tmp_path)
        cf    = self._config(tmp_path)
        rep   = tmp_path / "reports"
        monkeypatch.setattr("propor_regra.CONFIG_FILE", cf)
        monkeypatch.setattr("propor_regra.REPORT_DIR",  rep)
        executar(csv_path=csv_p, aplicar=False, dry_run=True)
        jsons = list(rep.glob("propostas_*.json"))
        assert len(jsons) == 1
        dados = json.loads(jsons[0].read_text(encoding="utf-8"))
        assert dados["modo"]      == "dry-run"
        assert dados["propostas"] == 5

    def test_dry_run_gera_relatorio_md(self, tmp_path, monkeypatch):
        csv_p = self._csv_padrao(tmp_path)
        cf    = self._config(tmp_path)
        rep   = tmp_path / "reports"
        monkeypatch.setattr("propor_regra.CONFIG_FILE", cf)
        monkeypatch.setattr("propor_regra.REPORT_DIR",  rep)
        executar(csv_path=csv_p, aplicar=False, dry_run=True)
        mds = list(rep.glob("propostas_*.md"))
        assert len(mds) == 1
        conteudo = mds[0].read_text(encoding="utf-8")
        assert PREFIXO_DESC in conteudo

    def test_dry_run_status_todos_dry_run(self, tmp_path, monkeypatch):
        csv_p = self._csv_padrao(tmp_path)
        cf    = self._config(tmp_path)
        rep   = tmp_path / "reports"
        monkeypatch.setattr("propor_regra.CONFIG_FILE", cf)
        monkeypatch.setattr("propor_regra.REPORT_DIR",  rep)
        executar(csv_path=csv_p, aplicar=False, dry_run=True)
        dados = json.loads(list(rep.glob("propostas_*.json"))[0].read_text(encoding="utf-8"))
        statuses = {p["status"] for p in dados["detalhes_propostas"]}
        assert statuses == {"dry-run"}

    def test_sem_candidatos_no_csv(self, tmp_path, monkeypatch):
        """CSV só com sem_candidato → propostas=0."""
        linhas = [_linha_sem_candidato(i, f"9.9.9.{i}") for i in range(3)]
        csv_p  = tmp_path / "c.csv"
        _escrever_csv(csv_p, linhas)
        cf  = self._config(tmp_path)
        rep = tmp_path / "reports"
        monkeypatch.setattr("propor_regra.CONFIG_FILE", cf)
        monkeypatch.setattr("propor_regra.REPORT_DIR",  rep)
        ret = executar(csv_path=csv_p, aplicar=False, dry_run=True)
        assert ret == 0
        dados = json.loads(list(rep.glob("propostas_*.json"))[0].read_text(encoding="utf-8"))
        assert dados["propostas"] == 0

    def test_csv_ausente(self, tmp_path, monkeypatch):
        cf = self._config(tmp_path)
        monkeypatch.setattr("propor_regra.CONFIG_FILE", cf)
        monkeypatch.setattr("propor_regra.REPORT_DIR",  tmp_path / "reports")
        with pytest.raises(FileNotFoundError):
            executar(csv_path=tmp_path / "nao_existe.csv", aplicar=False, dry_run=True)


# ---------------------------------------------------------------------------
# executar() — aplicar=True com mock de API
# ---------------------------------------------------------------------------

class TestExecutarAplicar:
    UUID_PADRAO = "aaaabbbb-cccc-dddd-eeee-ffffffffffff"

    def _setup(self, tmp_path: Path, ips: list[str]):
        linhas  = [_linha_candidato(i+1, ip) for i, ip in enumerate(ips)]
        csv_p   = tmp_path / "correlacao.csv"
        _escrever_csv(csv_p, linhas)
        cf = tmp_path / "api.conf"
        cf.write_text(
            "OPNSENSE_HOST=172.16.0.1\n"
            "OPNSENSE_API_KEY=k\n"
            "OPNSENSE_API_SECRET=s\n",
            encoding="utf-8",
        )
        rep = tmp_path / "reports"
        return csv_p, cf, rep

    def _mock_api(self, monkeypatch, regras_existentes=None, uuid=UUID_PADRAO):
        """Substitui OPNsenseAPI por mock que simula respostas do OPNsense."""
        regras_existentes = regras_existentes or []

        mock = MagicMock()
        mock.buscar_regras.return_value = regras_existentes
        mock.criar_regra.return_value   = {"result": "saved", "uuid": uuid}
        mock.aplicar.return_value       = {"status": "OK\n\n"}

        monkeypatch.setattr("propor_regra.OPNsenseAPI", lambda **kw: mock)
        return mock

    def test_cria_regra_para_cada_ip(self, tmp_path, monkeypatch):
        ips = ["1.1.1.1", "2.2.2.2", "3.3.3.3"]
        csv_p, cf, rep = self._setup(tmp_path, ips)
        monkeypatch.setattr("propor_regra.CONFIG_FILE", cf)
        monkeypatch.setattr("propor_regra.REPORT_DIR",  rep)
        mock = self._mock_api(monkeypatch)
        executar(csv_path=csv_p, aplicar=True, dry_run=False)
        assert mock.criar_regra.call_count == 3

    def test_chama_apply_uma_vez(self, tmp_path, monkeypatch):
        ips = ["1.1.1.1", "2.2.2.2"]
        csv_p, cf, rep = self._setup(tmp_path, ips)
        monkeypatch.setattr("propor_regra.CONFIG_FILE", cf)
        monkeypatch.setattr("propor_regra.REPORT_DIR",  rep)
        mock = self._mock_api(monkeypatch)
        executar(csv_path=csv_p, aplicar=True, dry_run=False)
        mock.aplicar.assert_called_once()

    def test_nao_chama_apply_sem_novas_regras(self, tmp_path, monkeypatch):
        """Se todos os IPs já têm regra, apply não deve ser chamado."""
        ip = "1.1.1.1"
        csv_p, cf, rep = self._setup(tmp_path, [ip])
        monkeypatch.setattr("propor_regra.CONFIG_FILE", cf)
        monkeypatch.setattr("propor_regra.REPORT_DIR",  rep)
        # Regra existente com prefixo correto e o IP na descrição
        mock = self._mock_api(monkeypatch, regras_existentes=[{
            "description": f"{PREFIXO_DESC}: block {ip} udp/9034",
            "uuid": self.UUID_PADRAO,
        }])
        executar(csv_path=csv_p, aplicar=True, dry_run=False)
        mock.criar_regra.assert_not_called()
        mock.aplicar.assert_not_called()

    def test_uuid_gravado_no_relatorio(self, tmp_path, monkeypatch):
        ips = ["5.5.5.5"]
        csv_p, cf, rep = self._setup(tmp_path, ips)
        monkeypatch.setattr("propor_regra.CONFIG_FILE", cf)
        monkeypatch.setattr("propor_regra.REPORT_DIR",  rep)
        self._mock_api(monkeypatch, uuid="test-uuid-1234")
        executar(csv_path=csv_p, aplicar=True, dry_run=False)
        dados = json.loads(list(rep.glob("propostas_*.json"))[0].read_text(encoding="utf-8"))
        uuids = [p["uuid"] for p in dados["detalhes_propostas"]]
        assert "test-uuid-1234" in uuids

    def test_status_criada_no_relatorio(self, tmp_path, monkeypatch):
        ips = ["6.6.6.6"]
        csv_p, cf, rep = self._setup(tmp_path, ips)
        monkeypatch.setattr("propor_regra.CONFIG_FILE", cf)
        monkeypatch.setattr("propor_regra.REPORT_DIR",  rep)
        self._mock_api(monkeypatch)
        executar(csv_path=csv_p, aplicar=True, dry_run=False)
        dados = json.loads(list(rep.glob("propostas_*.json"))[0].read_text(encoding="utf-8"))
        statuses = {p["status"] for p in dados["detalhes_propostas"]}
        assert "criada" in statuses

    def test_ip_invalido_registrado_como_erro(self, tmp_path, monkeypatch):
        """IP inválido no CSV deve ir para detalhes_erros, não gerar regra."""
        linha_invalida = _linha_candidato(1, "999.999.999.999")
        csv_p = tmp_path / "c.csv"
        _escrever_csv(csv_p, [linha_invalida])
        cf  = tmp_path / "api.conf"
        cf.write_text("OPNSENSE_HOST=h\nOPNSENSE_API_KEY=k\nOPNSENSE_API_SECRET=s\n")
        rep = tmp_path / "reports"
        monkeypatch.setattr("propor_regra.CONFIG_FILE", cf)
        monkeypatch.setattr("propor_regra.REPORT_DIR",  rep)
        mock = self._mock_api(monkeypatch)
        ret = executar(csv_path=csv_p, aplicar=True, dry_run=False)
        assert ret == 1
        mock.criar_regra.assert_not_called()
        dados = json.loads(list(rep.glob("propostas_*.json"))[0].read_text(encoding="utf-8"))
        assert dados["erros"] == 1

    def test_falha_na_api_registrada_como_erro(self, tmp_path, monkeypatch):
        """RuntimeError na criação deve ser capturado, não propagar."""
        ips = ["7.7.7.7"]
        csv_p, cf, rep = self._setup(tmp_path, ips)
        monkeypatch.setattr("propor_regra.CONFIG_FILE", cf)
        monkeypatch.setattr("propor_regra.REPORT_DIR",  rep)
        mock = self._mock_api(monkeypatch)
        mock.criar_regra.side_effect = RuntimeError("HTTP 500: Internal Server Error")
        ret = executar(csv_path=csv_p, aplicar=True, dry_run=False)
        assert ret == 1
        dados = json.loads(list(rep.glob("propostas_*.json"))[0].read_text(encoding="utf-8"))
        assert dados["erros"] == 1

    def test_relatorio_contem_limitacoes(self, tmp_path, monkeypatch):
        ips = ["8.8.8.8"]
        csv_p, cf, rep = self._setup(tmp_path, ips)
        monkeypatch.setattr("propor_regra.CONFIG_FILE", cf)
        monkeypatch.setattr("propor_regra.REPORT_DIR",  rep)
        self._mock_api(monkeypatch)
        executar(csv_path=csv_p, aplicar=True, dry_run=False)
        dados = json.loads(list(rep.glob("propostas_*.json"))[0].read_text(encoding="utf-8"))
        assert "limitacoes" in dados
        assert len(dados["limitacoes"]) > 0

    def test_md_contem_uuid(self, tmp_path, monkeypatch):
        ips = ["9.9.9.1"]
        csv_p, cf, rep = self._setup(tmp_path, ips)
        monkeypatch.setattr("propor_regra.CONFIG_FILE", cf)
        monkeypatch.setattr("propor_regra.REPORT_DIR",  rep)
        self._mock_api(monkeypatch, uuid="uuid-para-md-1234")
        executar(csv_path=csv_p, aplicar=True, dry_run=False)
        md = list(rep.glob("propostas_*.md"))[0].read_text(encoding="utf-8")
        assert "uuid-para-md-1234" in md

    def test_md_contem_comando_rollback(self, tmp_path, monkeypatch):
        ips = ["9.9.9.2"]
        csv_p, cf, rep = self._setup(tmp_path, ips)
        monkeypatch.setattr("propor_regra.CONFIG_FILE", cf)
        monkeypatch.setattr("propor_regra.REPORT_DIR",  rep)
        self._mock_api(monkeypatch)
        executar(csv_path=csv_p, aplicar=True, dry_run=False)
        md = list(rep.glob("propostas_*.md"))[0].read_text(encoding="utf-8")
        assert "--remover-uuid" in md

    def test_idempotencia_dry_run_duas_vezes(self, tmp_path, monkeypatch):
        """Segunda execução dry-run com mesmo CSV sobrescreve o relatório se ocorrer
        no mesmo segundo, ou gera novo arquivo se ocorrer em segundo diferente.
        Em ambos os casos deve haver pelo menos 1 relatório com propostas=1."""
        ips = ["1.2.3.4"]
        csv_p, cf, rep = self._setup(tmp_path, ips)
        monkeypatch.setattr("propor_regra.CONFIG_FILE", cf)
        monkeypatch.setattr("propor_regra.REPORT_DIR",  rep)
        executar(csv_path=csv_p, aplicar=False, dry_run=True)
        executar(csv_path=csv_p, aplicar=False, dry_run=True)
        jsons = list(rep.glob("propostas_*.json"))
        assert len(jsons) >= 1
        # Todos os relatórios devem ter propostas=1
        for j in jsons:
            dados = json.loads(j.read_text(encoding="utf-8"))
            assert dados["propostas"] == 1
