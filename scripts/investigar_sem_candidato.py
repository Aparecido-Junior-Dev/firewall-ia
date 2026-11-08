#!/usr/bin/env python3
"""Diagnóstico complementar; não altera a correlação original."""
import csv
import json
from pathlib import Path
import sys
from correlacionar_sid import analyze, parse_pf, NOTICE


def main():
    base = Path.home() / 'firewall-ia'
    eve = base / 'data/raw/suricata/eve_20260927_20261004.json'
    paths = [base/'data/raw/pf'/f'filter_{d}.log' for d in
             ('20260928','20260929','20260930','20261001','20261002')]
    alerts, _ = analyze(eve, paths)
    targets = [(i, a) for i, a in enumerate(alerts, 1) if not a['candidates']]
    nearest = {i: [] for i, _ in targets}
    nearby = {i: [] for i, _ in targets}
    for path in paths:
        with path.open(encoding='utf-8') as stream:
            for n, line in enumerate(stream, 1):
                try:
                    pf = parse_pf(line)
                except (ValueError, IndexError, csv.Error) as exc:
                    raise ValueError(f'{path}:{n}: {exc}') from exc
                if pf is None:
                    continue
                for i, alert in targets:
                    delta = (pf['time'] - alert['time']).total_seconds()
                    row = dict(alerta_id=i, eve_timestamp=alert['timestamp'],
                               src_ip=alert['key'][0], dest_ip=alert['key'][1],
                               eve_src_port=alert['key'][2], eve_dest_port=alert['key'][3],
                               pf_timestamp=pf['timestamp'], delta_s=f'{delta:.6f}',
                               pf_src_port=pf['key'][2], pf_dest_port=pf['key'][3],
                               pf_acao=pf['action'], pf_interface=pf['iface'],
                               pf_direcao=pf['direction'], pf_regra=pf['rule'],
                               pf_tracker=pf['tracker'], pf_arquivo=str(path), pf_linha=n)
                    if pf['key'] == alert['key']:
                        nearest[i].append((abs(delta), row))
                        nearest[i].sort(key=lambda x: (x[0], x[1]['pf_arquivo'], x[1]['pf_linha']))
                        del nearest[i][3:]
                    elif pf['key'][:2] == alert['key'][:2] and abs(delta) <= 5:
                        nearby[i].append(row)
    out = base/'reports/diagnostico_sid2044008'
    out.mkdir(parents=True, exist_ok=True)
    rows = []
    results = []
    for i, alert in targets:
        exact = [dict(tipo='mesma_tupla_mais_proxima', **r) for _, r in nearest[i]]
        different = [dict(tipo='mesmos_ips_portas_diferentes_5s', **r) for r in nearby[i]]
        rows.extend(exact + different)
        results.append(dict(alerta_id=i, timestamp=alert['timestamp'], tupla=list(alert['key']),
                            mesma_tupla_mais_proxima=exact, mesmos_ips_portas_diferentes_5s=different))
        print(f"Alerta {i}: {alert['key'][0]}:{alert['key'][2]} -> {alert['key'][1]}:{alert['key'][3]}")
        if exact:
            for r in exact:
                print(f"  Mesma tupla: delta={r['delta_s']} s; {r['pf_acao']}; {r['pf_arquivo']}:{r['pf_linha']}")
        else:
            print('  Mesma tupla: nenhum registro UDP nos cinco arquivos PF.')
        print(f'  Mesmos IPs, portas diferentes em ±5 s: {len(different)} registros.')
    fields = ('tipo alerta_id eve_timestamp src_ip dest_ip eve_src_port eve_dest_port '
              'pf_timestamp delta_s pf_src_port pf_dest_port pf_acao pf_interface '
              'pf_direcao pf_regra pf_tracker pf_arquivo pf_linha').split()
    with (out/'diagnostico.csv').open('w', encoding='utf-8', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
    (out/'diagnostico.json').write_text(json.dumps(dict(
        observacao=NOTICE, criterio='Até três registros mais próximos de mesma tupla nos cinco arquivos; mesmos IPs orientados com portas diferentes em ±5 s.',
        alertas_investigados=len(targets), resultados=results), ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
    print(f'Diagnóstico salvo em {out}')

if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError) as exc:
        print(f'ERRO: {exc}', file=sys.stderr)
        sys.exit(1)
