# Mapa de Cobertura: OPNsense × ModSecurity

**Versão:** 1.0.0  
**Data:** 2026-11-08  
**Autor:** Aparecido Junior  
**Fonte dos dados:** `reports/correlacao_v2/resumo_v2.json` — 48.915 alertas, período 2026-09-28 a 2026-10-02

---

## 1. Visão Geral dos Dados

| Métrica | Valor |
|---------|-------|
| Total de alertas Suricata | 48.915 |
| Período | 28/09/2026 a 02/10/2026 (5 dias) |
| Linhas PF filterlog | 473.304 |
| Alertas com PF block | 165 |
| Alertas com PF pass | 6.012 |
| Alertas sem registro PF | 42.639 |
| Alertas por trilha comportamento | 42.418 |
| Alertas por trilha interna | 6.495 |
| Alertas por trilha reputação | 2 |

---

## 2. Top Assinaturas Observadas

| SID | Categoria ET | Assinatura | Alertas | OPNsense cobre? | ModSecurity necessário? |
|-----|-------------|------------|---------|-----------------|------------------------|
| 2016149 | INFO | Session Traversal Utilities for NAT (STUN Binding Request) | 3.664 | ❌ Parcial | ❌ Não |
| 2027863 | INFO | Observed DNS Query to .biz TLD | 1.009 | ❌ Não | ❌ Não |
| 2035465 | INFO | Observed Discord Domain in DNS Lookup (discord.com) | 360 | ❌ Não | ❌ Não |
| 2060503 | INFO | Discord Chat Service Domain in DNS Lookup (discord.com) | 286 | ❌ Não | ❌ Não |
| 2013504 | INFO | GNU/Linux APT User-Agent Outbound | 251 | ❌ Não | ❌ Não |
| 2042930 | DYN_DNS | Dynamic DNS Query to *.cloudns.net Domain | 65 | ⚠️ Parcial | ❌ Não |
| 2028774 | JA3 | JA3 Hash — Adware (Abuse.ch) | 52 | ⚠️ Parcial | ⚠️ Considerar |
| 2035466 | INFO | Observed Discord Domain in DNS Lookup (discordapp.com) | 51 | ❌ Não | ❌ Não |
| 2033078 | INFO | STUN Binding Request (porta não-padrão alta) | 36 | ❌ Parcial | ❌ Não |
| 2050736 | INFO | Tencent Cloud Storage Domain in DNS (myqcloud.com) | 32 | ❌ Não | ❌ Não |
| 2044008 | EXPLOIT | Realtek SDK Command Execution/Backdoor Access Inbound | 8 | ✅ Sim (regras IA) | ⚠️ Complementar |

---

## 3. Classificação por Categoria ET

### 3.1 ET INFO — Informacional (maioria absoluta)

**Volume:** ~5.800 alertas (≈ 90% do tráfego com registro PF)  
**Descrição:** Atividade observável mas não intrinsecamente maliciosa. DNS para TLDs
incomuns, plataformas de comunicação, serviços de atualização de software.

| Subcategoria | Exemplos | Ação Recomendada |
|-------------|----------|-----------------|
| STUN/ICE | SID 2016149, 2033078 | Monitorar; bloquear se política proíbe P2P |
| DNS Query | SID 2027863 (.biz), 2035465/2060503/2035466 (Discord) | Auditoria de política; não bloquear automaticamente |
| APT/Pacotes | SID 2013504 (apt-get) | Allowlist de hosts de atualização |
| CDN/Cloud | SID 2050736 (Tencent Cloud) | Revisar se há relação com app legítimo |

**OPNsense:** Não bloqueia tráfego INFO por padrão (e não deveria — alto FP).  
**ModSecurity:** Não aplicável — não é tráfego HTTP/HTTPS de entrada para servidores web locais.

---

### 3.2 ET EXPLOIT — Exploração ativa

**Volume:** 8 alertas (SID 2044008 — Realtek CVE-2021-35394)  
**Descrição:** Tentativas reais de explorar vulnerabilidade conhecida no SDK Realtek
(CVE-2021-35394, CVSS 9.8). Backdoor access + command execution via UDP/9034.

| Indicador | Valor |
|-----------|-------|
| SID | 2044008 |
| CVE | CVE-2021-35394 |
| Protocolo | UDP/9034 |
| IPs únicos atacantes | 5 |
| Correlação PF | BLOQUEADO (action=block) |
| Regras IA criadas | 5 (uuid confirmados) |

**OPNsense:** ✅ **Cobre completamente** — 5 regras IA-aparecido ativas bloqueiam os IPs.
PF também bloqueou durante a detecção (confirmado pela correlação v2).

**ModSecurity:** ⚠️ Complementar — o CVE-2021-35394 afeta dispositivos IoT via UDP,
não HTTP. ModSecurity não interceptaria esse vetor. Entretanto, variantes do Realtek
exploit com payload HTTP seriam cobertas por regras OWASP CRS (rule id: 930xxx).

---

### 3.3 ET DYN_DNS — Dynamic DNS

**Volume:** 65 alertas (SID 2042930 — *.cloudns.net)  
**Descrição:** Consultas DNS para domínios DDNS. Podem indicar C2 (command-and-control)
usando infraestrutura dinâmica para evasão de blocklists por IP.

**Risco:** Médio — DDNS é usado legalmente (acesso remoto residencial) e por malware.

**OPNsense:** ⚠️ Parcial — sem regra ativa para DDNS. Seria necessário blocklist de
provedores DDNS suspeitos ou detecção por comportamento (muitas queries DDNS = suspeito).

**ModSecurity:** ❌ Não aplicável para DNS. Mas se o host DDNS servir conteúdo malicioso
via HTTP, o OWASP CRS cobriria a requisição HTTP de entrada.

---

### 3.4 ET JA3 — Fingerprint TLS

**Volume:** 52 alertas (SID 2028774 — Adware Abuse.ch)  
**Descrição:** Hash JA3 do handshake TLS associado a adware catalogado pelo Abuse.ch.
Indica que um host interno estabeleceu conexão TLS com comportamento de adware.

**Risco:** Médio — pode indicar dispositivo comprometido ou software não autorizado.

**OPNsense:** ⚠️ Pode bloquear o IP destino se estiver em blocklist de reputação.
Não inspeciona TLS natively. Para bloquear por JA3 exigiria inspeção SSL/TLS.

**ModSecurity:** ⚠️ ModSecurity em modo proxy SSL pode inspecionar e bloquear por JA3.
Requer configuração de MITM SSL na infraestrutura.

---

## 4. Tabela Consolidada de Cobertura

| Tipo de Ataque/Evento | Volume Observado | OPNsense (PF) | ModSecurity | Cobertura Atual | Lacuna |
|-----------------------|-----------------|---------------|-------------|-----------------|--------|
| Exploração Realtek (CVE-2021-35394) | 8 | ✅ Bloqueia (regras IA) | ⚠️ Complementar | Alta | Nenhuma relevante |
| STUN/NAT Traversal | 3.664 | ❌ Não bloqueia | ❌ N/A | Nenhuma | Política P2P |
| DNS .biz TLD | 1.009 | ❌ Não bloqueia | ❌ N/A | Nenhuma | DNS filtering |
| Discord (DNS lookup) | 697 | ❌ Não bloqueia | ❌ N/A | Nenhuma | Política de uso |
| APT/apt-get outbound | 251 | ❌ Não bloqueia | ❌ N/A | Nenhuma | Allowlisting |
| Dynamic DNS (*.cloudns.net) | 65 | ⚠️ Parcial | ❌ N/A | Baixa | Blocklist DDNS |
| JA3 Adware (Abuse.ch) | 52 | ⚠️ Com blocklist | ⚠️ Com SSL MITM | Baixa | Inspeção TLS |
| Tencent Cloud DNS | 32 | ❌ Não bloqueia | ❌ N/A | Nenhuma | Política cloud |
| **Total monitorado** | **48.915** | **Parcial** | **Marginal** | **Baixa** | **Alta** |

---

## 5. Análise por Trilha de Correlação

| Trilha | Alertas | Desfecho Predominante | Interpretação |
|--------|---------|----------------------|---------------|
| `comportamento` | 42.418 | SEM_REGISTRO (99.3%) | Detecções sem par PF — lacuna de log ou tráfego NAT |
| `interna` | 6.495 | PASSOU (92.3%) | Tráfego interno legítimo detectado pelo Suricata |
| `reputacao` | 2 | PASSOU | Raro — feed de reputação correspondeu com tráfego permitido |

**Observação:** Os 165 alertas com `pf_acao=block` pertencem à trilha `comportamento`,
confirmando que o PF age sobre ameaças de comportamento antes mesmo das regras IA.

---

## 6. Quando ModSecurity Seria Necessário

ModSecurity opera na camada de aplicação (L7) como WAF (Web Application Firewall).
É relevante apenas nos seguintes cenários:

| Cenário | ModSecurity cobre? | OPNsense PF cobre? |
|---------|-------------------|-------------------|
| Injection (SQLi, CMDi) via HTTP | ✅ Sim (OWASP CRS) | ❌ Não |
| XSS em requisições HTTP | ✅ Sim | ❌ Não |
| Path traversal / LFI / RFI | ✅ Sim | ❌ Não |
| Realtek exploit via UDP/9034 | ❌ Não | ✅ Sim |
| Varredura de portas | ❌ Não | ✅ Sim (Snort/IDS) |
| DNS C2 via DDNS | ❌ Não | ⚠️ Parcial |
| C2 HTTP over TLS | ⚠️ Com SSL offload | ⚠️ Com IDS TLS inspect |
| DDoS volumétrico | ❌ Não | ⚠️ Limiter do PF |

**Conclusão:** Para o ambiente atual (residencial, sem servidor web exposto à internet),
ModSecurity não seria o controle prioritário. O foco deve ser:

1. **PF rules** via IA-aparecido para IPs de ameaça ativa (já implementado)
2. **Blocklists DNS** para DDNS suspeito (próxima fase)
3. **Suricata tuning** para reduzir alertas INFO sem impacto operacional

---

## 7. Recomendações Operacionais

### 7.1 Imediatas (já implementadas)
- ✅ 5 regras IA-aparecido bloqueando IPs Realtek CVE-2021-35394
- ✅ Correlação Suricata × PF v2 com Community ID
- ✅ Validação de FP: 0 falsos positivos sobre 336.049 fluxos benignos

### 7.2 Curto prazo (Fase 3)
- 🔲 Integrar LLM para avaliar alertas `sem_candidato` com alta reputação negativa
- 🔲 Adicionar blocklist DNS para provedores DDNS suspeitos (resolver os 65 DYN_DNS)
- 🔲 Configurar feed AbuseIPDB para atualização automática de blocklist
- 🔲 Revisar alertas INFO: suprimir STUN e Discord se política de uso permitir

### 7.3 Médio prazo
- 🔲 Avaliar Suricata JA3 rules para detecção de adware (SID 2028774)
- 🔲 Implementar detecção de comportamento multi-SID (mesmo IP, múltiplos alertas)
- 🔲 Dashboard de cobertura: porcentagem de alertas com ação PF correspondente
- 🔲 Expandir coleta de logs PF para cobrir período completo de 31 dias

### 7.4 Sobre ModSecurity
Recomenda-se instalar ModSecurity no OPNsense **somente se** houver um servidor
web exposto à internet (HTTP/HTTPS inbound). No cenário atual residencial, o
vetor HTTP não é o principal risco — o foco em bloqueio de IP e detecção de
exploits UDP/TCP é mais efetivo.

---

## 8. Glossário de Categorias ET

| Prefixo | Significado |
|---------|------------|
| ET INFO | Informacional — atividade observável, geralmente benigna |
| ET EXPLOIT | Exploração de vulnerabilidade conhecida |
| ET DYN_DNS | Consulta a serviço de DNS dinâmico |
| ET JA3 | Fingerprint de handshake TLS (JA3/JA3S hash) |
| ET POLICY | Violação de política de rede (P2P, Tor, etc.) |
| ET SCAN | Varredura de portas ou serviços |
| ET MALWARE | Comunicação de malware conhecido |
| ET TROJAN | Tráfego de trojans/RATs conhecidos |
| ET CNC | Comunicação com infraestrutura C2 |

---

*Documento gerado para o Projeto firewall-ia — Mestrado em Engenharia de Software*
