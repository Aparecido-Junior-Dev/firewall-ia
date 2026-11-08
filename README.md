# Firewall IA

> Pipeline que correlaciona alertas do Suricata com o filterlog do OPNsense/PF,
> classifica cada alerta por desfecho e propõe regras de bloqueio via API REST.

![Python](https://img.shields.io/badge/Python-3.11+-blue)
![Tests](https://img.shields.io/badge/tests-140%20passing-brightgreen)
![License](https://img.shields.io/badge/license-MIT-green)
![Status](https://img.shields.io/badge/status-Fase%202%20conclu%C3%ADda-yellow)

---

## Resultados

| M\u00e9trica | Valor |
|---|---|
| Alertas analisados | 48.915 |
| BLOQUEADOS (Suricata + PF) | 165 |
| PASSARAM (tr\u00e1fego leg\u00edtimo) | 6.012 |
| SEM REGISTRO (default deny) | 42.639 |
| Regras IA-aparecido ativas | 5 |
| Community ID ativo desde | 02/11/2026 |
| Testes automatizados | 140 |

### Hip\u00f3teses

| Hip\u00f3tese | Descri\u00e7\u00e3o | Status |
|---|---|---|
| H1 | Maioria dos alertas j\u00e1 \u00e9 bloqueada pelo PF | \u2705 Confirmada |
| H2 | Diverg\u00eancia entre feeds explica os que passam | \u26a0\ufe0f Parcial |
| H3 | Regras de comportamento generalizam melhor que IP | \u23f3 N\u00e3o testada |
| H4 | Regras do pipeline batem o CrowdSec | \u23f3 N\u00e3o testada |
| H5 | LLM prop\u00f5e regras compar\u00e1veis \u00e0s heur\u00edsticas | \u23f3 N\u00e3o testada |

---

## Arquitetura

```
                    Internet
                        |
                   igb0 (WAN)
                   /         \
            c\u00f3pia          original
              |              |
        Suricata IDS    PF Packet Filter
        (wire/pcap)     (pass / block)
              |              |
          eve.json      filterlog
              |              |
              +------+=------+
                     |
            correlacionar_v2.py
            (Community ID junta os dois)
                     |
            +--------+--------+
            |                 |
     propor_regra.py    dashboard.py
     (POST addRule)       (:8080 ao vivo)
            |
     OPNsense / PF
     (5 regras ativas)
```

---

## Pr\u00e9-requisitos

- Python 3.11+
- OPNsense com API REST habilitada
- Suricata em modo IDS (wire/pcap) com community-id ativo
- Log em pass habilitado no PF

## Instala\u00e7\u00e3o

```bash
git clone https://github.com/Aparecido-Junior-Dev/firewall-ia.git
cd firewall-ia
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Uso

```bash
# 1. Correlacionar alertas Suricata x PF (gera CSV com desfecho)
python scripts/correlacionar_v2.py

# 2. Propor regras (envia via API REST do OPNsense)
python scripts/propor_regra.py

# 3. Dashboard ao vivo (http://localhost:8080)
python scripts/dashboard.py

# 4. Ativar Community ID no Suricata
python scripts/ativar_community_id.py

# 5. Investigar alertas sem candidato
python scripts/investigar_sem_candidato.py
```

## Testes

```bash
pytest tests/ -v
```

---

## Estrutura

```
firewall-ia/
\u251c\u2500\u2500 README.md              # Este arquivo
\u251c\u2500\u2500 DATASET.md            # Ficha completa do dataset
\u251c\u2500\u2500 requirements.txt      # Depend\u00eancias Python
\u251c\u2500\u2500 LICENSE               # Licen\u00e7a MIT
\u251c\u2500\u2500 .gitignore            # Ignora credenciais, dados brutos, venv
\u251c\u2500\u2500 scripts/              # Scripts execut\u00e1veis
\u2502   \u251c\u2500\u2500 correlacionar_v2.py    # Correla\u00e7\u00e3o EVE x filterlog (Community ID)
\u2502   \u251c\u2500\u2500 propor_regra.py        # Prop\u00f5e regras via API REST
\u2502   \u251c\u2500\u2500 dashboard.py           # Dashboard web Flask (:8080)
\u2502   \u251c\u2500\u2500 ativar_community_id.py  # Ativa community-id no Suricata
\u2502   \u251c\u2500\u2500 investigar_sem_candidato.py  # Analisa alertas sem par no PF
\u2502   \u251c\u2500\u2500 analisar_alertas_blacklist.py  # Cruza alertas com blacklist
\u2502   \u2514\u2500\u2500 iniciar_dashboard.sh   # Script de inicializa\u00e7\u00e3o
\u251c\u2500\u2500 src/                 # C\u00f3digo-fonte reutiliz\u00e1vel
\u251c\u2500\u2500 tests/               # 140 testes (pytest)
\u2502   \u251c\u2500\u2500 test_correlacionador.py
\u2502   \u251c\u2500\u2500 test_correlacionar_v2.py
\u2502   \u2514\u2500\u2500 test_propor_regra.py
\u251c\u2500\u2500 config/              # Configura\u00e7\u00e3o (gitignored: credenciais API)
\u251c\u2500\u2500 data/raw/            # Dados brutos (gitignored: IPs reais / LGPD)
\u251c\u2500\u2500 exports/             # CSVs e an\u00e1lises exportadas
\u2514\u2500\u2500 reports/             # Relat\u00f3rios e evid\u00eancias de execu\u00e7\u00e3o
```

---

## Crit\u00e9rio de sele\u00e7\u00e3o de candidatos

1. **Community ID igual** nos dois arquivos (eve.json e filterlog) \u2014 mesmo fluxo
2. **PF registrou bloqueio** (pf_acao = block) para esse fluxo
3. **Verifica\u00e7\u00e3o de duplicata**: consulta API do OPNsense por regras com prefixo `IA-aparecido`
   - Se existe \u2192 ignora (j\u00e1 bloqueado)
   - Se n\u00e3o existe \u2192 cria regra nova

## Onde entra a IA

- **Hoje**: m\u00e9todo totalmente determin\u00edstico (crit\u00e9rio fixo, audit\u00e1vel)
- **Fase 3**: LLM entra como 4\u00aa fam\u00edlia de regras, comparada com as heur\u00edsticas
- **Seguran\u00e7a**: LLM nunca escreve direto no firewall \u2014 passa pelo simulador primeiro

---

## Dataset

Ver [DATASET.md](DATASET.md) para a ficha completa:
- Modo e interface do Suricata
- Vers\u00e3o das regras
- Per\u00edodo exato dos alertas
- Lacunas de cobertura
- Fontes da blacklist
- Host interno investigado

---

## Autor

**Aparecido de Souza Vieira Junior**
Mestrado 2026 \u2014 UNIPAMPA
Disciplina LIAA \u2014 Prof. Diego Kreutz

## Licen\u00e7a

MIT \u2014 ver [LICENSE](LICENSE)
