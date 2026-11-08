# Firewall IA

> Pipeline que correlaciona alertas do Suricata com o filterlog do OPNsense/PF,
> classifica cada alerta por desfecho e propõe regras de bloqueio via API REST.

![Python](https://img.shields.io/badge/Python-3.11+-blue)
![Tests](https://img.shields.io/badge/tests-140%20passing-brightgreen)
![License](https://img.shields.io/badge/license-MIT-green)
![Status](https://img.shields.io/badge/status-Fase%203%20concluída-yellow)

---

## Resultados

| Métrica | Valor |
|---|---|
| Alertas analisados | 48.915 |
| BLOQUEADOS (Suricata + PF) | 165 |
| PASSARAM (tráfego legítimo) | 6.012 |
| SEM REGISTRO (default deny) | 42.639 |
| Regras IA-aparecido ativas | 5 |
| Community ID ativo desde | 02/11/2026 |
| Testes automatizados | 140 |
| Filterlog analisado | 31 dias (10,6M fluxos) |

### Hipóteses

| Hipótese | Descrição | Status |
|---|---|---|
| H1 | Maioria dos alertas já é bloqueada pelo PF | Confirmada (87,3%) |
| H2 | Divergência entre feeds explica os que passam | Parcial |
| H3 | Regras de comportamento generalizam melhor que IP | Não conclusivo |
| H4 | Regras do pipeline batem o CrowdSec | Respondida (ambos 0%) |
| H5 | LLM propõe regras comparáveis às heurísticas | Sem resíduo para testar |

---

## Arquitetura

```
                    Internet
                        |
                   igb0 (WAN)
                   /         \
            cópia          original
              |              |
        Suricata IDS    PF Packet Filter
        (wire/pcap)     (pass / block)
              |              |
          eve.json      filterlog
              |              |
              +------=-------+
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

## Pré-requisitos

- Python 3.11+
- OPNsense com API REST habilitada
- Suricata em modo IDS (wire/pcap) com community-id ativo
- Log em pass habilitado no PF

## Instalação

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

# 6. Coletar feeds de reputação (snapshot diário)
python scripts/coletar_feeds.py

# 7. Split temporal (Fase 3)
python scripts/split_temporal.py

# 8. Avaliar famílias de regras
python scripts/avaliar_familias.py
```

## Testes

```bash
pytest tests/ -v
```

---

## Estrutura

```
firewall-ia/
├── README.md              # Este arquivo
├── DATASET.md            # Ficha completa do dataset
├── requirements.txt      # Dependências Python
├── LICENSE               # Licença MIT
├── .gitignore            # Ignora credenciais, dados brutos, venv
├── scripts/              # Scripts executáveis
│   ├── correlacionar_v2.py    # Correlação EVE x filterlog (Community ID)
│   ├── propor_regra.py        # Propõe regras via API REST
│   ├── dashboard.py           # Dashboard web Flask (:8080)
│   ├── ativar_community_id.py # Ativa community-id no Suricata
│   ├── investigar_sem_candidato.py  # Analisa alertas sem par no PF
│   ├── analisar_alertas_blacklist.py  # Cruza alertas com blacklist
│   ├── coletar_feeds.py       # Coleta snapshot diário dos feeds
│   ├── split_temporal.py      # Fase 3: split temporal e avaliação
│   ├── avaliar_familias.py    # Avalia famílias vs CrowdSec
│   └── iniciar_dashboard.sh  # Script de inicialização
├── src/                 # Código-fonte reutilizável
├── tests/               # 140 testes (pytest)
│   ├── test_correlacionador.py
│   ├── test_correlacionar_v2.py
│   └── test_propor_regra.py
├── config/              # Configuração (gitignored: credenciais API)
├── data/raw/            # Dados brutos (gitignored: IPs reais / LGPD)
├── exports/             # CSVs e análises exportadas
└── reports/             # Relatórios e evidências de execução
```

---

## Critério de seleção de candidatos

1. **Community ID igual** nos dois arquivos (eve.json e filterlog) - mesmo fluxo
2. **PF registrou bloqueio** (pf_acao = block) para esse fluxo
3. **Verificação de duplicata**: consulta API do OPNsense por regras com prefixo `IA-aparecido`
   - Se existe: ignora (já bloqueado)
   - Se não existe: cria regra nova

## Onde entra a IA

- **Hoje**: método totalmente determinístico (critério fixo, auditável)
- **Fase 3**: LLM entra como 4ª família de regras, comparada com as heurísticas
- **Segurança**: LLM nunca escreve direto no firewall - passa pelo simulador primeiro

---

## Dataset

Ver [DATASET.md](DATASET.md) para a ficha completa:
- Modo e interface do Suricata
- Versão das regras
- Período exato dos alertas
- Lacunas de cobertura
- Fontes da blacklist
- Host interno investigado

---

## Autor

**Aparecido de Souza Vieira Junior**
Mestrado 2026 - UNIPAMPA
Disciplina LIAA - Prof. Diego Kreutz

## Licença

MIT - ver [LICENSE](LICENSE)
