# Firewall IA — Logs para regras OPNsense

Pipeline que correlaciona alertas do Suricata com o filterlog do OPNsense/PF,
classifica cada alerta por desfecho (BLOQUEADO / PASSOU / SEM_REGISTRO) e propõe
regras de bloqueio via API REST do OPNsense.

## Arquitetura

```
Internet → igb0 (WAN)
              ├── cópia → Suricata IDS → eve.json
              └── original → PF → pass/block → filterlog
                                              ↓
                                    correlacionar_v2.py
                                    (Community ID junta os dois)
                                              ↓
                                    propor_regra.py
                                    (POST addRule + apply)
                                              ↓
                                    dashboard.py :8080
```

## Pré-requisitos

- Python 3.11+
- OPNsense com API REST habilitada
- Suricata em modo IDS (wire/pcap) com community-id ativo
- Log em pass habilitado no PF

## Instalação

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Uso

```bash
# 1. Correlacionar alertas (gera CSV com desfecho)
python scripts/correlacionar_v2.py

# 2. Propor regras (envia via API do OPNsense)
python scripts/propor_regra.py

# 3. Dashboard ao vivo
python scripts/dashboard.py
```

## Dataset

Ver `DATASET.md` para a ficha completa do dataset (modo do Suricata, interface,
versão das regras, período, lacunas, fontes da blacklist).

## Testes

```bash
pytest tests/ -v
```

## Estrutura

```
firewall-ia/
├── scripts/          # Scripts executáveis
├── src/              # Código-fonte reutilizável
├── tests/            # Testes (pytest)
├── config/           # Configuração (gitignored: credenciais)
├── data/raw/         # Dados brutos (gitignored: IPs reais)
├── exports/          # CSVs gerados
└── reports/          # Relatórios e evidências
```

## Autor

Aparecido de Souza Vieira Junior — Mestrado 2026 — UNIPAMPA
Prof. Diego Kreutz — Disciplina LIAA
