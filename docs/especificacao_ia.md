# Especificação do Módulo IA — firewall-ia

**Versão:** 1.0.0  
**Data:** 2026-11-08  
**Autor:** Aparecido Junior  
**Projeto:** firewall-ia (Mestrado — Engenharia de Software)

---

## 1. Visão Geral

O módulo IA do projeto firewall-ia propõe, valida e aplica regras de bloqueio no
firewall OPNsense com base na correlação entre alertas do Suricata e eventos do
filterlog do PF. A versão atual (Fase 2) é **determinística**: não usa modelo de
linguagem — a "decisão" é feita por critérios explícitos e auditáveis codificados
em `scripts/propor_regra.py`.

---

## 2. Critérios de Seleção de Candidatos

### 2.1 Fonte de dados

| Fonte | Arquivo | Conteúdo |
|-------|---------|----------|
| Suricata EVE | `data/raw/suricata/eve_*.json` | Alertas IDS com timestamp, IPs, portas, SID |
| PF filterlog | `data/raw/pf/filter_*.log` | Eventos de firewall: action, IP, porta, protocolo |
| CSV correlação | `reports/correlacao_sid2044008/correlacao_sid2044008.csv` | Correlação Suricata × PF por Community ID |

### 2.2 Filtro principal (função `selecionar_candidatos`)

```python
def selecionar_candidatos(linhas: list[dict]) -> list[dict]:
    return [
        r for r in linhas
        if r.get("status") == "candidato" and r.get("pf_acao") == "block"
    ]
```

**Critérios obrigatórios (AND lógico):**

| Campo CSV | Valor exigido | Justificativa |
|-----------|--------------|---------------|
| `status` | `candidato` | Alerta correlacionado com evento PF (Community ID match) |
| `pf_acao` | `block` | O PF já bloqueou — confirma ameaça ativa, não apenas detecção |

**Por que excluir `sem_candidato`?**  
Alertas sem correlação PF podem ser: tráfego que passou antes da regra ser criada,
tráfego encapsulado/NAT, ou lacuna de log. Propor bloqueio sem evidência de evento
real no firewall seria especulativo e geraria mais FP.

### 2.3 Deduplicação por IP de origem (função `agrupar_por_ip`)

```python
def agrupar_por_ip(candidatos: list[dict]) -> dict[str, list[dict]]:
    grupos: dict[str, list[dict]] = {}
    for row in candidatos:
        ip = row["src_ip"]
        grupos.setdefault(ip, []).append(row)
    return grupos
```

Um IP com múltiplos alertas gera **uma única regra**, não N regras. Isso evita
duplicatas e mantém o conjunto de regras mínimo e gerenciável.

### 2.4 Verificação de duplicata (função `ja_existe`)

Antes de criar qualquer regra, o script consulta a API REST do OPNsense:

```python
regras = api.buscar_regras("IA-aparecido")
for regra in regras:
    if "IA-aparecido" in regra["description"] and ip_origem in regra["description"]:
        return True, regra["uuid"]
```

Se o IP já tem regra ativa, o candidato é marcado como `DUPLICATA` e ignorado.

---

## 3. Prompt e Instruções (Fase 2 — Determinístico)

Na Fase 2 atual, **não há modelo de linguagem**. A "IA" é um conjunto de regras
determinísticas explícitas. O raciocínio que um LLM faria na Fase 3 é hoje
substituído pelo seguinte pseudoprompt implícito:

```
DADO:
  - alerta Suricata: SID=2044008, src_ip=<IP>, dst_ip=192.168.15.200, 
    proto=udp, dst_port=9034
  - correlação PF: action=block, Community ID match

PERGUNTA: Devo criar uma regra de bloqueio permanente para este IP?

CRITÉRIO DETERMINÍSTICO:
  SE status=candidato E pf_acao=block E IP não tem regra existente:
    → CRIAR regra: block WAN in src=<IP> proto=udp dst_port=9034
  SENÃO:
    → IGNORAR (sem_candidato ou duplicata)
```

---

## 4. Formato JSON das Regras Propostas

### 4.1 Payload enviado à API OPNsense (`POST /api/firewall/filter/addRule`)

```json
{
  "rule": {
    "enabled":          "1",
    "action":           "block",
    "quick":            "1",
    "interface":        "wan",
    "direction":        "in",
    "ipprotocol":       "inet",
    "protocol":         "udp",
    "source_net":       "<IP_ORIGEM>",
    "source_not":       "0",
    "destination_net":  "any",
    "destination_not":  "0",
    "destination_port": "9034",
    "log":              "1",
    "description":      "IA-aparecido: block <IP> udp/9034 SID=2044008 CVE-2021-35394 alertas=[<IDs>] gerado=<ISO8601>"
  }
}
```

### 4.2 Estrutura do relatório de propostas (`reports/propostas_regras/propostas_*.json`)

```json
{
  "versao_script":    "1.0.0",
  "timestamp":        "2026-10-18T12:56:57Z",
  "modo":             "aplicar | dry-run",
  "csv_entrada":      "<caminho>",
  "sid":              2044008,
  "cve":              "CVE-2021-35394",
  "assinatura":       "ET EXPLOIT Realtek SDK Command Execution/Backdoor Access Inbound",
  "total_linhas_csv": 8,
  "candidatos":       5,
  "ips_unicos":       5,
  "propostas":        0,
  "duplicatas":       5,
  "erros":            0,
  "status_apply":     "nenhuma regra nova para aplicar",
  "detalhes_propostas":  [...],
  "detalhes_duplicatas": [
    {"ip": "118.31.169.106", "uuid_existente": "1aaa6b39-..."},
    {"ip": "121.171.129.37", "uuid_existente": "a8b8d12a-..."},
    {"ip": "165.245.187.19", "uuid_existente": "7a989adc-..."},
    {"ip": "74.81.97.18",    "uuid_existente": "6bc9389e-..."},
    {"ip": "94.154.43.117",  "uuid_existente": "83929162-..."}
  ],
  "detalhes_erros": [],
  "limitacoes":      [...]
}
```

---

## 5. Fluxo de Decisão: Quando Bloquear vs. Ignorar

```
┌─────────────────────────────────────────────────────────┐
│              ENTRADA: CSV de correlação                 │
└───────────────────────┬─────────────────────────────────┘
                        │
                        ▼
              ┌─────────────────┐
              │ status=candidato│ ← NÃO → [IGNORAR: sem_candidato]
              │ E pf_acao=block │
              └────────┬────────┘
                       │ SIM
                       ▼
              ┌─────────────────┐
              │ IP válido?      │ ← NÃO → [ERRO: IP inválido]
              └────────┬────────┘
                       │ SIM
                       ▼
              ┌──────────────────────┐
              │ Já existe regra      │
              │ IA-aparecido p/ IP?  │ ← SIM → [DUPLICATA: ignorar]
              └────────┬─────────────┘
                       │ NÃO
                       ▼
              ┌──────────────────┐
              │ modo dry-run?    │ ← SIM → [PROPOSTA: sem envio]
              └────────┬─────────┘
                       │ NÃO (--aplicar)
                       ▼
              ┌──────────────────────────────┐
              │ POST /api/firewall/filter/   │
              │ addRule  →  UUID retornado   │
              └────────┬─────────────────────┘
                       │
                       ▼
              ┌──────────────────┐
              │ POST /apply      │ → [REGRA ATIVA no PF]
              └──────────────────┘
```

**Critério de bloqueio:** IP externo que gerou alerta Suricata SID confirmado pelo
PF (correlação Community ID). Evidência dupla: detecção IDS + ação firewall.

**Critério de ignorar:**
- `sem_candidato`: alerta sem correspondência PF — possível lacuna de log ou NAT
- `pf_acao=pass`: o PF deixou passar — pode ser falso positivo do Suricata
- Duplicata: regra já existe — idempotência garantida
- IP inválido: proteção contra entradas malformadas

**Rollback:** `python3 propor_regra.py --remover-uuid <UUID>`

---

## 6. Limitações Declaradas

As limitações são registradas em todos os relatórios de proposta:

| # | Limitação | Impacto | Mitigação |
|---|-----------|---------|-----------|
| L1 | Correlação temporal não prova identidade de pacote | Pode correlacionar eventos distintos com timing similar | Community ID melhora precisão; janela 30s limita escopo |
| L2 | `sem_candidato` excluídos: ausência de PF não confirma permissão | Cobertura menor — ameaças sem log PF não são bloqueadas | Revisar config de log do OPNsense |
| L3 | Regra bloqueia IP inteiro; pode afetar tráfego legítimo futuro | FP potencial se IP for compartilhado (CGNAT, CDN) | Verificação geolocalização e ASN na Fase 3 |
| L4 | Destino `192.168.15.200` pode não estar na LAN atual | NAT e topologia não verificados automaticamente | Auditoria manual periódica da topologia |
| L5 | Ambiente residencial real | Escopo limitado; resultados não generalizáveis diretamente | Documentado como ambiente de pesquisa |

---

## 7. Plano para LLM na Fase 3

A Fase 3 substituirá a lógica determinística por um Large Language Model (LLM) com
capacidade de raciocínio contextual. O objetivo é avaliar candidatos que a Fase 2
rejeita por falta de evidência dupla.

### 7.1 Arquitetura prevista

```
┌───────────────────┐     ┌─────────────────┐     ┌───────────────────┐
│  Dados de entrada │────▶│  Contexto LLM   │────▶│  Decisão + JSON   │
│  - alertas EVE    │     │  - resumo stats │     │  - acao: block/ok │
│  - logs PF        │     │  - histórico IP │     │  - confianca: 0-1 │
│  - feeds threat   │     │  - CVE info     │     │  - justificativa  │
│  - geoloc/ASN     │     │  - limitacoes   │     │  - evidencias[]   │
└───────────────────┘     └─────────────────┘     └───────────────────┘
```

### 7.2 Prompt base (rascunho)

```
Você é um analista de segurança de redes. Dado o alerta abaixo, decida se deve
propor bloqueio no firewall.

CONTEXTO DO AMBIENTE:
- Rede residencial: LAN 192.168.15.0/24, DMZ 172.16.0.0/24
- Firewall: OPNsense com PF
- IDS: Suricata com regras ET Open

ALERTA SURICATA:
  SID: {sid}
  Assinatura: {sig}
  CVE: {cve}
  src_ip: {src_ip} (ASN: {asn}, País: {pais}, Reputação AbuseIPDB: {score})
  dst_ip: {dst_ip}
  Protocolo: {proto}/{porta}
  Timestamp: {ts}
  Contexto PF: {contexto_pf}

HISTÓRICO DO IP:
  - Alertas anteriores: {n_alertas}
  - Primeiro visto: {primeiro_visto}

DECIDA:
  1. acao: "block" ou "ignorar"
  2. confianca: 0.0 a 1.0
  3. justificativa: string curta
  4. evidencias: lista de fatos que apoiam a decisão

Responda APENAS em JSON válido seguindo o schema fornecido.
```

### 7.3 Schema de saída do LLM

```json
{
  "acao":         "block | ignorar",
  "confianca":    0.95,
  "justificativa": "IP chinês em ASN suspeito explorando CVE-2021-35394 ativo",
  "evidencias":   [
    "SID 2044008 confirmado pelo PF (block)",
    "AbuseIPDB score 98/100",
    "ASN 4134 China Telecom — alto volume de varredura"
  ],
  "meta": {
    "model":    "gpt-4o-mini | llama3 | ...",
    "latencia": 1.2,
    "tokens":   450
  }
}
```

### 7.4 Limiar de confiança para aplicação automática

| Confiança | Ação |
|-----------|------|
| ≥ 0.90 | Aplicar automaticamente (com log de auditoria) |
| 0.70–0.89 | Dry-run + notificação para revisão humana |
| < 0.70 | Ignorar + registrar para análise posterior |

### 7.5 Casos que o LLM tratará que a Fase 2 não trata

- Alertas `sem_candidato` com alta reputação negativa no AbuseIPDB
- IPs recorrentes em múltiplos SIDs (comportamento multi-vetor)
- Correlação com feeds externos (CrowdSec, Abuse.ch, VT)
- Detecção de padrões de varredura sem evento PF correspondente

---

## 8. Histórico de Versões

| Versão | Data | Mudança |
|--------|------|---------|
| 1.0.0 | 2026-10-18 | Fase 2: lógica determinística, 5 regras Realtek criadas |
| 2.0.0 | Planejado | Fase 3: integração LLM, análise multi-SID |

---

*Documento gerado para o Projeto firewall-ia — Mestrado em Engenharia de Software*
