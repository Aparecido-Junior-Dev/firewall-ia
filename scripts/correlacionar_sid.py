#!/usr/bin/env python3
"""Correlação observacional EVE/PF; Python 3, apenas biblioteca padrão."""
import argparse
import csv
import ipaddress
import json
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone, timedelta
from pathlib import Path

NOTICE = ('Candidatos têm a mesma tupla UDP orientada e proximidade temporal; '
          'não demonstram identidade de pacote, causalidade ou bloqueio do alerta. '
          'Sem candidato não significa tráfego permitido. NAT, relógios, resolução '
          'do timestamp e cobertura do logging podem limitar a correlação.')
HEADER = re.compile(r'^<\d+>\d+\s+(\S+)\s+\S+\s+filterlog\s+\S+\s+\S+\s+(?:-|(?:\[(?:[^\\\]]|\\.)*\])+)\s+(.*)$')

def timestamp(value):
    dt = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if dt.tzinfo is None or dt.utcoffset() is None:
        raise ValueError('timestamp sem timezone explícito')
    return dt.astimezone(timezone.utc)

def key(src, dst, sport, dport):
    ports = (int(sport), int(dport))
    if not all(0 <= p <= 65535 for p in ports):
        raise ValueError('porta fora de 0..65535')
    return (str(ipaddress.ip_address(src)), str(ipaddress.ip_address(dst)), *ports)

def parse_pf(line):
    if 'filterlog' not in line:
        return None
    match = HEADER.match(line.rstrip())
    if not match:
        raise ValueError('cabeçalho filterlog não é RFC5424 suportado')
    ts, payload = match.groups()
    dt = timestamp(ts)
    f = next(csv.reader([payload]))
    if len(f) < 9:
        raise ValueError('payload PF incompleto')
    if f[8] == '4':
        proto_id, proto_text, start = 15, 16, 18
    elif f[8] == '6':
        proto_id, proto_text, start = 13, 12, 15
    else:
        raise ValueError('versão IP PF inválida')
    if len(f) <= proto_text or len(f) <= proto_id:
        raise ValueError('campos IP incompletos')
    if f[proto_id] != '17':
        return None
    if f[proto_text].lower() != 'udp' or len(f) < start + 5:
        raise ValueError('campos UDP incompletos/inconsistentes')
    return {'time': dt, 'timestamp': ts, 'key': key(*f[start:start+4]),
            'iface': f[4], 'action': f[6], 'direction': f[7],
            'rule': f[0], 'tracker': f[3]}

def analyze(eve, pf_paths, sid=2044008, window=5, expected=8):
    alerts, index, counts = [], defaultdict(list), Counter()
    with eve.open(encoding='utf-8') as stream:
        for n, line in enumerate(stream, 1):
            if not line.strip():
                continue
            counts['eve_linhas'] += 1
            try:
                event = json.loads(line)
                if event.get('event_type') != 'alert' or event.get('alert', {}).get('signature_id') != sid:
                    continue
                if event.get('proto', '').upper() != 'UDP':
                    raise ValueError('alerta SID selecionado não é UDP')
                alert = {'time': timestamp(event['timestamp']), 'timestamp': event['timestamp'],
                         'key': key(event['src_ip'], event['dest_ip'], event['src_port'], event['dest_port']),
                         'iface': event.get('in_iface', ''), 'action': event['alert'].get('action', ''),
                         'file': str(eve), 'line': n, 'candidates': []}
                alerts.append(alert)
                index[alert['key']].append(alert)
            except (ValueError, KeyError, TypeError, AttributeError) as exc:
                raise ValueError(f'{eve}:{n}: {exc}') from exc
    if expected is not None and len(alerts) != expected:
        raise ValueError(f'esperados {expected} alertas SID {sid}; encontrados {len(alerts)}')
    for path in pf_paths:
        with path.open(encoding='utf-8') as stream:
            for n, line in enumerate(stream, 1):
                counts['pf_linhas'] += 1
                try:
                    pf = parse_pf(line)
                except (ValueError, IndexError, csv.Error) as exc:
                    raise ValueError(f'{path}:{n}: {exc}') from exc
                if pf is None:
                    continue
                counts['pf_udp'] += 1
                for alert in index.get(pf['key'], ()):
                    delta = (pf['time'] - alert['time']).total_seconds()
                    if abs(delta) <= window:
                        alert['candidates'].append(dict(pf, file=str(path), line=n, delta=delta))
    alerts.sort(key=lambda a: (a['time'], a['line']))
    summary = dict(counts)
    summary.update(sid=sid, janela_segundos=window, alertas=len(alerts),
                   com_candidato=sum(bool(a['candidates']) for a in alerts),
                   sem_candidato=sum(not a['candidates'] for a in alerts),
                   multiplos_candidatos=sum(len(a['candidates']) > 1 for a in alerts),
                   pares_candidatos=sum(len(a['candidates']) for a in alerts),
                   acoes_pf_por_par=dict(Counter(p['action'] for a in alerts for p in a['candidates'])),
                   arquivos_entrada=[str(eve), *map(str, pf_paths)], observacao=NOTICE)
    return alerts, summary

FIELDS = 'alerta_id,status,n_candidatos,eve_timestamp,eve_utc,eve_arquivo,eve_linha,src_ip,dest_ip,src_port,dest_port,proto,eve_interface,eve_acao,pf_timestamp,pf_utc,delta_pf_menos_eve_s,pf_arquivo,pf_linha,pf_interface,interface_igual,pf_acao,pf_direcao,pf_regra,pf_tracker'.split(',')

def save(alerts, summary, out):
    out.mkdir(parents=True, exist_ok=True)
    with (out / 'correlacao_sid2044008.csv').open('w', encoding='utf-8', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=FIELDS)
        writer.writeheader()
        for i, a in enumerate(alerts, 1):
            candidates = sorted(a['candidates'], key=lambda p: (abs(p['delta']), p['file'], p['line']))
            for p in candidates or [None]:
                row = dict(alerta_id=i, status='candidato' if p else 'sem_candidato',
                           n_candidatos=len(candidates), eve_timestamp=a['timestamp'], eve_utc=a['time'].isoformat(),
                           eve_arquivo=a['file'], eve_linha=a['line'], src_ip=a['key'][0], dest_ip=a['key'][1],
                           src_port=a['key'][2], dest_port=a['key'][3], proto='UDP',
                           eve_interface=a['iface'], eve_acao=a['action'])
                if p:
                    row.update(pf_timestamp=p['timestamp'], pf_utc=p['time'].isoformat(),
                               delta_pf_menos_eve_s=f"{p['delta']:.6f}", pf_arquivo=p['file'], pf_linha=p['line'],
                               pf_interface=p['iface'], interface_igual=str(a['iface'] == p['iface']).lower(),
                               pf_acao=p['action'], pf_direcao=p['direction'], pf_regra=p['rule'], pf_tracker=p['tracker'])
                writer.writerow(row)
    (out / 'resumo.json').write_text(json.dumps(summary, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
    report = (f"SID {summary['sid']}; janela inclusiva ±{summary['janela_segundos']} s; timestamps em UTC\n"
              f"Alertas: {summary['alertas']}; com candidato: {summary['com_candidato']}; "
              f"sem candidato: {summary['sem_candidato']}; múltiplos: {summary['multiplos_candidatos']}\n"
              f"Pares candidatos: {summary['pares_candidatos']}; ações PF por par: {summary['acoes_pf_por_par']}\n{NOTICE}\n")
    (out / 'resumo.txt').write_text(report, encoding='utf-8')
    return report

def self_test():
    import tempfile
    data = [
        ('2026-09-28T22:49:06.102969-0300','124.235.163.60',52908),
        ('2026-09-29T08:51:18.955499-0300','165.245.187.19',51901),
        ('2026-09-29T09:35:42.560733-0300','74.117.6.146',46406),
        ('2026-09-29T13:06:51.825239-0300','74.81.97.18',49095),
        ('2026-09-29T15:56:54.860858-0300','96.228.60.184',55050),
        ('2026-09-29T20:07:55.061520-0300','121.171.129.37',55630),
        ('2026-09-30T23:58:30.909022-0300','118.31.169.106',40123),
        ('2026-10-02T21:53:20.300253-0300','94.154.43.117',34514)]
    def pf(ts, src, port, action='block', dst='192.168.15.200'):
        return f'<134>1 {ts} host filterlog 50144 - [meta sequenceId="1"] 71,,,uuid,igb0,match,{action},in,4,0x0,,64,1,0,none,17,udp,28,{src},{dst},{port},9034,8\n'
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        eve, log = root/'eve.json', root/'pf.log'
        eve.write_text(''.join(json.dumps(dict(event_type='alert', alert=dict(signature_id=2044008, action='allowed'), timestamp=t, src_ip=s, src_port=p, dest_ip='192.168.15.200', dest_port=9034, proto='UDP', in_iface='igb0'))+'\n' for t,s,p in data))
        lines = []
        for t,s,p in data[:7]:
            lines.append(pf((timestamp(t)+timedelta(seconds=5)).isoformat(), s, p))
        t,s,p = data[0]
        lines += [pf((timestamp(t)-timedelta(seconds=5)).isoformat(),s,p,'pass'),
                  pf((timestamp(t)+timedelta(seconds=5, microseconds=1)).isoformat(),s,p),
                  pf(timestamp(t).isoformat(),s,p+1),
                  pf(timestamp(t).isoformat(),s,p,dst='192.168.15.201'),
                  pf(timestamp(t).isoformat(),'192.168.15.200',9034,dst=s)]
        log.write_text(''.join(lines))
        alerts, summary = analyze(eve,[log])
        assert summary['alertas'] == 8 and summary['com_candidato'] == 7
        assert summary['sem_candidato'] == 1 and summary['pares_candidatos'] == 8
        assert summary['multiplos_candidatos'] == 1
        assert {p['delta'] for p in alerts[0]['candidates']} == {-5,5}
        save(alerts, summary, root/'out')
        with (root/'out/correlacao_sid2044008.csv').open() as stream:
            rows = list(csv.DictReader(stream))
        assert len(rows) == 9 and rows[-1]['status'] == 'sem_candidato'
        assert json.loads((root/'out/resumo.json').read_text()) == summary
        for bad in ['2026-09-28T22:49:06', 'inválido']:
            try:
                timestamp(bad)
            except ValueError:
                pass
            else:
                raise AssertionError('timestamp inválido aceito')
        log.write_text('<134>1 inválido host filterlog 1 - - quebrado\n')
        try:
            analyze(eve,[log])
        except ValueError:
            pass
        else:
            raise AssertionError('PF inválido aceito')
        try:
            analyze(eve,[root/'ausente'])
        except FileNotFoundError:
            pass
        else:
            raise AssertionError('arquivo ausente aceito')
        try:
            analyze(eve,[],expected=9)
        except ValueError:
            pass
        else:
            raise AssertionError('contagem inesperada aceita')
        v6 = '<134>1 2026-09-29T00:00:00Z host filterlog 1 - - 1,,,uuid,igb0,match,pass,in,6,0x0,0x0,64,UDP,17,48,2001:db8::1,2001:db8::2,123,9034,8'
        assert parse_pf(v6)['key'] == ('2001:db8::1','2001:db8::2',123,9034)
    print('Autoteste OK: 8 alertas de referência; PF sintético; limites inclusivos, timezone, tupla orientada, múltiplos/ausentes, CSV/resumo e falhas de entrada.')

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base', type=Path, default=Path.home()/'firewall-ia')
    parser.add_argument('--self-test', action='store_true')
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return
    base = args.base.expanduser().resolve()
    eve = base/'data/raw/suricata/eve_20260927_20261004.json'
    paths = [base/'data/raw/pf'/f'filter_{d}.log' for d in ['20260928','20260929','20260930','20261001','20261002']]
    for path in [eve,*paths]:
        if not path.is_file():
            parser.error(f'arquivo ausente: {path}')
    try:
        alerts, summary = analyze(eve,paths)
        out = base/'reports/correlacao_sid2044008'
        print(save(alerts,summary,out), end='')
        print(f'Resultados: {out}')
    except (OSError, ValueError) as exc:
        print(f'ERRO: {exc}', file=sys.stderr)
        sys.exit(1)

if __name__ == '__main__':
    main()
