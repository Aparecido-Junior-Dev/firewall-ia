# Ficha do Dataset

## OPNsense

| Campo | Valor |
|---|---|
| Versão | 26.7.8_2 |
| IP | 172.16.0.1 |
| API REST | Habilitada |
| Plugin CrowdSec | os-crowdsec-1.0.12 (instalado e ativo) |

## Suricata

| Campo | Valor |
|---|---|
| Versão | 8.0.8 RELEASE |
| Modo | IDS (wire/pcap) |
| Interface | igb0 (WAN física) |
| Community ID | Ativo (community-id: true) |
| Conjunto de regras | Emerging Threats (ET) + abuse.ch + outras |
| Arquivos de regras | emerging-*.rules, abuse.ch.*, botcc, ciarmy, compromised, drop, dshield |
| Período dos alertas | 27/09/2026 23:00 → 04/10/2026 18:59 (7+ dias) |
| Total de alertas | 48.915 |
| Formato | eve.json (JSON, um evento por linha) |

## PF Packet Filter

| Campo | Valor |
|---|---|
| Log em pass | Ativo (66.958 registros/dia) |
| Log em block | Ativo (30.153 registros/dia) |
| Período coberto | 28/09 → 02/10/2026 (5 dias) |
| Total de linhas | 473.304 |
| Arquivos | 5 diários (filter_20260928 a filter_20261002) |
| Formato | filterlog (syslog) |

## Aliases e tabelas do PF

| Tabela | Tipo | IPs | Última atualização | Fonte |
|---|---|---|---|---|
| ABUSEIP | URL (IPs) | 414.244 | 20/09/2026 | AbuseIPDB score 100, 180 dias |
| crowdsec_blocklists | CrowdSec | 8.332 | Em tempo real | CrowdSec (ativo) |
| crowdsec6_blocklists | CrowdSec IPv6 | — | Em tempo real | CrowdSec (ativo) |
| bogons | External | 3.026 | — | Redes reservadas |
| sshlockout | Internal | 0 | — | Bloqueio de SSH |
| virusprot | Internal | 0 | — | Proteção contra vírus |

## Lacunas de cobertura

| Data | EVE tem? | PF tem? | Impacto |
|---|---|---|---|
| 27/09 | Sim (23:00-23:59) | Não | Alertas sem par no PF |
| 03/10 | Sim | Não | Alertas sem par no PF |
| 04/10 | Sim | Não | Alertas sem par no PF |
| Total | — | — | ~2,5 dias sem cobertura PF |

## Blacklist — documentação completa

### Fonte 1: AbuseIPDB (alias ABUSEIP)
- URL: https://raw.githubusercontent.com/borestad/blocklist-abuseipdb/refs/heads/main/abuseipdb-s100-180d.ipv4
- Critério: score 100, últimos 180 dias
- IPs: 414.244
- Última atualização: 20/09/2026 20:39
- Tipo: alias URL no PF (atualiza automaticamente)
- Estatísticas do PF: 43.478 matchs, 2.210.688 pacotes bloqueados

### Fonte 2: CrowdSec (tabelas crowdsec_blocklists)
- Plugin: os-crowdsec-1.0.12
- IPs: 8.332 (IPv4)
- Tipo: tabela do PF gerenciada pelo CrowdSec
- Modo: ativo (bloqueando)
- Atualização: em tempo real (feed comunitário)

### Fonte 3: Regras do Suricata (ET + abuse.ch)
- Emerging Threats: drop.rules, dshield.rules, emerging-*.rules
- abuse.ch: feodotracker, sslblacklist, threatfox, urlhaus
- Outras: botcc, ciarmy, compromised
- Aplicação: detecção nativa no Suricata (gera alertas no eve.json)

## Host interno

| Campo | Valor |
|---|---|
| IP | 192.168.15.200 |
| Alertas gerados | 6.495 (82% do resíduo) |
| Top assinatura | ET INFO STUN Binding Request (3.664) |
| Interpretação | Host interno legítimo — Discord, STUN, atualizações |
| Identificação | Pendente — via DHCP e ARP |

## Community ID

| Campo | Valor |
|---|---|
| Especificação | v1 (corelight/community-id-spec) |
| Cálculo | Hash de (protocolo, src_ip, src_port, dst_ip, dst_port) |
| Simétrico | Sim — mesmo hash nos 2 sentidos |
| Ativo desde | 02/11/2026 |
| Confirmado via | SSH (community-id: true no suricata.yaml) |

## VM Debian (processamento)

| Campo | Valor |
|---|---|
| IP | 172.16.0.125 |
| Dashboard | http://172.16.0.125:8080 |
| Python | 3.11+ com venv |
| Testes | 140 testes (pytest) |
