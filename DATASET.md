# Ficha do Dataset

## Suricata

| Campo | Valor |
|---|---|
| Modo | IDS (wire/pcap) |
| Interface | igb0 (WAN física) |
| community-id | Ativo desde 02/11/2026 |
| Conjunto de regras | Emerging Threats (ET) |
| Versão das regras | A confirmar via SSH |
| Período dos alertas | 27/09/2026 23:00 → 04/10/2026 18:59 (7+ dias) |
| Total de alertas | 48.915 |
| Formato | eve.json (JSON, um evento por linha) |

## PF Packet Filter (OPNsense)

| Campo | Valor |
|---|---|
| IP do OPNsense | 172.16.0.1 |
| Log em pass | Ativo (66.958 registros/dia) |
| Log em block | Ativo (30.153 registros/dia) |
| API REST | Disponível |
| Período coberto | 28/09 → 02/10/2026 (5 dias) |
| Total de linhas | 473.304 |
| Arquivos | 5 arquivos diários (filter_20260928 a filter_20261002) |
| Formato | filterlog (syslog) |

## Lacunas identificadas

| Data | EVE tem? | PF tem? | Impacto |
|---|---|---|---|
| 27/09 | Sim (23:00-23:59) | Não | Alertas sem par no PF |
| 03/10 | Sim | Não | Alertas sem par no PF |
| 04/10 | Sim | Não | Alertas sem par no PF |
| Total | — | — | ~2,5 dias sem cobertura PF |

## Blacklist

| Fonte | Tipo | Aplicação | Data de captura |
|---|---|---|---|
| AbuseIPDB | Score de reputação (0-100%) | Consulta manual por IP | A confirmar |
| Spamhaus DROP | Blocos CIDR maliciosos | Verificação offline | A confirmar |
| DShield / ET DROP | Assinatura Suricata (SID 2402000) | Nativo no Suricata | A confirmar |

**Ação pendente:** verificar se há alias no PF com essas listas e documentar
número de entradas via `pfctl -t <alias> -T show | wc -l`.

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

## VM Debian (processamento)

| Campo | Valor |
|---|---|
| IP | 172.16.0.125 |
| Dashboard | http://172.16.0.125:8080 |
| Python | 3.11+ com venv |
| Testes | 140 testes (pytest) |
