# Validação das Regras IA-aparecido — Tráfego Benigno

**Gerado em:** 2026-11-09T11:20:17Z  
**Script:** validar_trafego_benigno.py v1.0.0  

## 1. Fonte dos Dados

| Arquivo | Linhas PF |
|---------|-----------|
| `filter_20260928.log` | — |
| `filter_20260929.log` | — |
| `filter_20260930.log` | — |
| `filter_20261001.log` | — |
| `filter_20261002.log` | — |

- **Total de linhas PF:** 473,304
- **Linhas parseadas:** 473,087
- **Eventos pass:** 336,192
- **Eventos block:** 136,701

## 2. Tráfego Benigno Identificado

**Total de fluxos benignos:** 336,049

| Critério | Fluxos | Descrição |
|----------|--------|-----------|
| origem_interna | 336,005 | src_ip em 192.168.x.x / 172.16.x.x / 10.x.x.x |
| direcao_out | 37 | Tráfego saindo da LAN (gerado internamente) |
| porta_servico_80 | 7 | Destino em porta 80 |

## 3. As 5 Regras IA-aparecido (Realtek CVE-2021-35394)

| IP de Origem | UUID OPNsense |
|--------------|---------------|
| `118.31.169.106` | `1aaa6b39-b4c9-48c1-b3d8-f694e80383bf` |
| `121.171.129.37` | `a8b8d12a-fb19-402b-ae39-a6a4d1d6718d` |
| `165.245.187.19` | `7a989adc-af3c-4834-8b4b-de5a2005bc3e` |
| `74.81.97.18` | `6bc9389e-2430-4966-b97b-686cce67b2b3` |
| `94.154.43.117` | `83929162-005b-4716-8686-83a4c0ba96b0` |

- **SID:** 2044008 — ET EXPLOIT Realtek SDK Command Execution/Backdoor Access Inbound
- **CVE:** CVE-2021-35394
- **Ação:** block WAN in, UDP, porta destino 9034

## 4. Análise de Falsos Positivos

| Métrica | Valor |
|---------|-------|
| Fluxos benignos totais | 336,049 |
| Falsos positivos absolutos | 0 |
| **Taxa de FP** | **0.000000%** |

✅ **Nenhum falso positivo detectado.**

Os 5 IPs Realtek não aparecem como origem de tráfego benigno (action=pass)
em nenhum dos 5 dias de logs analisados. As regras IA-aparecido são seguras
para o tráfego legítimo da rede.

## 5. Cobertura sobre Alertas Realtek

| Métrica | Valor |
|---------|-------|
| Alertas SID 2044008 nos logs | 8 |
| IPs únicos detectados pelo correlacionador | 5 |
| IPs com regra IA ativa | 5 |
| **Cobertura de IPs** | **100.0%** |

> 5 de 5 IPs únicos do CVE-2021-35394 têm regra IA-aparecido ativa no OPNsense

## 6. Conclusão

| Indicador | Resultado |
|-----------|-----------|
| Taxa de Falso Positivo | 0.000000% ✅ |
| Cobertura Realtek | 100% ✅ |
| Regras aprovadas | Sim ✅ |

**Taxa de FP: 0.000000%. As 5 regras IA-aparecido não geram impacto mensurável no tráfego benigno. Cobertura de 100% dos IPs Realtek detectados. Manter regras ativas.**

---
*Gerado por validar_trafego_benigno.py v1.0.0*
