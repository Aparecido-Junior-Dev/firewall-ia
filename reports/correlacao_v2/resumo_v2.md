# Correlação v2 — Community ID

**Versão:** 2.0.0  
**Data:** 2026-11-02  
**Community ID ativo:** ✅ sim  
**Alertas analisados:** 48,915  

## Desfecho por trilha

| Desfecho | Interna | Reputação | Comportamento | Total |
|---|---:|---:|---:|---:|
| BLOQUEADO | 0 | 0 | 165 | 165 |
| PASSOU | 5994 | 2 | 16 | 6012 |
| SEM_REGISTRO | 501 | 0 | 42138 | 42639 |
| AMBOS | 0 | 0 | 99 | 99 |

## Top 10 SIDs com tráfego que PASSOU

| SID | Alertas | Assinatura |
|---|---:|---|
| 2016149 | 3664 | ET INFO Session Traversal Utilities for NAT (STUN Binding Re |
| 2027863 | 1009 | ET INFO Observed DNS Query to .biz TLD |
| 2035465 | 360 | ET INFO Observed Discord Domain in DNS Lookup (discord .com) |
| 2060503 | 286 | ET INFO Discord Chat Service Domain in DNS Lookup (discord . |
| 2013504 | 251 | ET INFO GNU/Linux APT User-Agent Outbound likely related to  |
| 2042930 | 65 | ET DYN_DNS DYNAMIC_DNS Query to a *.cloudns .net Domain |
| 2028774 | 52 | ET JA3 Hash - [Abuse.ch] Possible Adware |
| 2035466 | 51 | ET INFO Observed Discord Domain in DNS Lookup (discordapp .c |
| 2033078 | 36 | ET INFO Session Traversal Utilities for NAT (STUN Binding Re |
| 2050736 | 32 | ET INFO Tencent Cloud Storage Domain in DNS Lookup (myqcloud |

## Observação metodológica

Community ID calculado a partir da tupla (proto, src_ip, src_port, dst_ip, dst_port). Junção exata substitui a janela temporal da v1. BLOQUEADO = alerta tem par PF com action=block. PASSOU = alerta tem par PF com action=pass. SEM_REGISTRO = nenhum par PF encontrado (possível lacuna de log, NAT ou cobertura).

*Gerado por correlacionar_v2.py v2.0.0*
