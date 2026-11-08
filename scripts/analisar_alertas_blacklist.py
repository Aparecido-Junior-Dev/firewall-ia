#!/usr/bin/env python3
"""Extrai origens de todos os alertas EVE e compara com snapshot IPv4."""
import argparse
import csv
import hashlib
import ipaddress
import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
import sys


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024*1024), b''):
            h.update(chunk)
    return h.hexdigest()


def analyze(eve, blacklist):
    blocked = set()
    for n, line in enumerate(blacklist.read_text(encoding='utf-8').splitlines(), 1):
        value = line.split('#', 1)[0].strip()
        if not value:
            continue
        # Alguns snapshots trazem metadados após o primeiro campo IP.
        token = value.split()[0]
        try:
            ip = ipaddress.IPv4Address(token)
        except ValueError as exc:
            raise ValueError(f'{blacklist}:{n}: IPv4 inválido: {token}') from exc
        blocked.add(str(ip))
    if not blocked:
        raise ValueError('blacklist vazia')
    origins = {}
    ranks = {group: {kind: Counter() for kind in ('assinaturas','destinos','horas','categorias')}
             for group in ('todos','na_blacklist','restantes')}
    total_lines = total_alerts = 0
    for n, line in enumerate(eve.open(encoding='utf-8'), 1):
        if not line.strip():
            continue
        total_lines += 1
        try:
            event = json.loads(line)
            if event.get('event_type') != 'alert':
                continue
            alert = event['alert']
            src = str(ipaddress.ip_address(event['src_ip']))
            dst = str(ipaddress.ip_address(event['dest_ip']))
            dt = datetime.fromisoformat(event['timestamp'].replace('Z','+00:00'))
            if dt.tzinfo is None:
                raise ValueError('timestamp sem timezone')
            utc = dt.astimezone(timezone.utc).isoformat()
            sid = int(alert['signature_id'])
            signature = str(alert.get('signature',''))
            category = str(alert.get('category',''))
            proto = str(event.get('proto','')).upper()
            port = str(event.get('dest_port',''))
        except (ValueError, KeyError, TypeError, AttributeError) as exc:
            raise ValueError(f'{eve}:{n}: {exc}') from exc
        total_alerts += 1
        listed = src in blocked
        group = 'na_blacklist' if listed else 'restantes'
        if src not in origins:
            origins[src] = dict(ip=src, versao_ip=ipaddress.ip_address(src).version,
                                na_blacklist=listed, eventos=0, primeiro_utc=utc, ultimo_utc=utc,
                                sids=set(), destinos=set())
        entry = origins[src]
        entry['eventos'] += 1
        entry['primeiro_utc'] = min(entry['primeiro_utc'], utc)
        entry['ultimo_utc'] = max(entry['ultimo_utc'], utc)
        entry['sids'].add(sid)
        entry['destinos'].add(dst)
        for g in ('todos', group):
            ranks[g]['assinaturas'][(sid, signature, category)] += 1
            ranks[g]['destinos'][(dst, proto, port)] += 1
            ranks[g]['horas'][(dt.astimezone(timezone.utc).strftime('%Y-%m-%dT%H:00:00Z'),)] += 1
            ranks[g]['categorias'][(category,)] += 1
    if not total_alerts:
        raise ValueError('nenhum alerta encontrado')
    listed_ips = sum(e['na_blacklist'] for e in origins.values())
    listed_events = sum(e['eventos'] for e in origins.values() if e['na_blacklist'])
    summary = dict(eventos_eve=total_lines, alertas=total_alerts, ips_blacklist_unicos=len(blocked),
                   ips_origem_unicos=len(origins), ips_na_blacklist=listed_ips,
                   ips_restantes=len(origins)-listed_ips, alertas_na_blacklist=listed_events,
                   alertas_restantes=total_alerts-listed_events,
                   ips_origem_ipv6=sum(e['versao_ip']==6 for e in origins.values()),
                   eve_arquivo=str(eve), eve_sha256=digest(eve),
                   blacklist_arquivo=str(blacklist), blacklist_sha256=digest(blacklist),
                   observacao='Filtro por pertinência do IP de origem à cópia da blacklist, sem comprovar malícia ou benignidade. IPv6 não é coberto pela lista IPv4. Assinaturas são alertas, não ataques confirmados. Portas não confirmam o serviço. A lista coletada em outubro não demonstra sua cobertura na data dos eventos.')
    assert summary['ips_origem_unicos'] == summary['ips_na_blacklist']+summary['ips_restantes']
    assert total_alerts == summary['alertas_na_blacklist']+summary['alertas_restantes']
    return origins, ranks, summary


def save(origins, ranks, summary, out):
    out.mkdir(parents=True, exist_ok=True)
    sorted_ips = sorted(origins, key=lambda ip: (ipaddress.ip_address(ip).version, int(ipaddress.ip_address(ip))))
    for name, ips in (
        ('ips_origem_todos.txt',sorted_ips),
        ('ips_na_blacklist.txt',[ip for ip in sorted_ips if origins[ip]['na_blacklist']]),
        ('ips_restantes.txt',[ip for ip in sorted_ips if not origins[ip]['na_blacklist']])):
        (out/name).write_text(''.join(ip+'\n' for ip in ips),encoding='utf-8')
    fields = ['ip','versao_ip','na_blacklist','eventos','primeiro_utc','ultimo_utc','sids','destinos']
    with (out/'origens.csv').open('w',encoding='utf-8',newline='') as stream:
        writer = csv.DictWriter(stream,fieldnames=fields); writer.writeheader()
        for ip in sorted_ips:
            row = dict(origins[ip])
            row['sids'] = ';'.join(map(str,sorted(row['sids'])))
            row['destinos'] = ';'.join(sorted(row['destinos']))
            writer.writerow(row)
    headers = dict(assinaturas=['sid','assinatura','categoria'],destinos=['dest_ip','protocolo','dest_port'],
                   horas=['hora_utc'],categorias=['categoria'])
    for group, kinds in ranks.items():
        for kind, counts in kinds.items():
            with (out/f'{kind}_{group}.csv').open('w',encoding='utf-8',newline='') as stream:
                writer = csv.writer(stream); writer.writerow(headers[kind]+['alertas'])
                for k,v in sorted(counts.items(),key=lambda kv: (-kv[1],kv[0])):
                    writer.writerow([*k,v])
    (out/'resumo.json').write_text(json.dumps(summary,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    report = (f"Alertas: {summary['alertas']}\nIPs origem únicos: {summary['ips_origem_unicos']}\n"
              f"IPs na blacklist: {summary['ips_na_blacklist']}; restantes: {summary['ips_restantes']}\n"
              f"Alertas de IPs na blacklist: {summary['alertas_na_blacklist']}; restantes: {summary['alertas_restantes']}\n"
              f"Origens IPv6 (fora da cobertura da lista): {summary['ips_origem_ipv6']}\n"
              'Top 10 assinaturas — todos os alertas:\n')
    for (sid,signature,category),count in ranks['todos']['assinaturas'].most_common(10):
        report += f'  {sid}: {count} — {signature} — {category}\n'
    report += 'Top 10 assinaturas — após subtração da blacklist:\n'
    for (sid,signature,category),count in ranks['restantes']['assinaturas'].most_common(10):
        report += f'  {sid}: {count} — {signature} — {category}\n'
    report += summary['observacao']+'\n'
    (out/'resumo.txt').write_text(report,encoding='utf-8')
    return report


def self_test():
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        root=Path(tmp); eve=root/'eve'; block=root/'list'
        block.write_text('# snapshot\n192.0.2.1 # metadata\n192.0.2.1\n192.0.2.99\n')
        events=[dict(event_type='alert',timestamp='2026-09-29T00:00:00-0300',src_ip=src,
                     dest_ip='192.168.15.200',dest_port=9034,proto='UDP',
                     alert=dict(signature_id=sid,signature='test',category='test'))
                for src,sid in [('192.0.2.1',1),('192.0.2.1',1),('192.0.2.2',2),('2001:db8::1',3)]]
        eve.write_text('\n'.join(json.dumps(e) for e in events)+'\n'+json.dumps({'event_type':'stats'})+'\n')
        origins,ranks,s=analyze(eve,block)
        assert (s['alertas'],s['ips_origem_unicos'],s['ips_na_blacklist'],s['ips_restantes'])==(4,3,1,2)
        assert (s['alertas_na_blacklist'],s['alertas_restantes'],s['ips_origem_ipv6'])==(2,2,1)
        assert sum(ranks['restantes']['assinaturas'].values())==2
        save(origins,ranks,s,root/'out')
        assert (root/'out/ips_restantes.txt').read_text()=='192.0.2.2\n2001:db8::1\n'
        assert len(list(csv.DictReader((root/'out/origens.csv').open())))==3
        assert json.loads((root/'out/resumo.json').read_text())==s
        for content in ('# empty\n','bad-ip\n'):
            block.write_text(content)
            try: analyze(eve,block)
            except ValueError: pass
            else: raise AssertionError('blacklist inválida aceita')
    print('Autoteste OK: subtração, IPs únicos/eventos, duplicatas, IPv6, rankings, CSV/JSON e lista inválida.')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--blacklist',type=Path)
    parser.add_argument('--base',type=Path,default=Path.home()/'firewall-ia')
    parser.add_argument('--self-test',action='store_true')
    args=parser.parse_args()
    if args.self_test:
        self_test(); return
    if args.blacklist is None: parser.error('--blacklist é obrigatório')
    base=args.base.expanduser().resolve()
    eve=base/'data/raw/suricata/eve_20260927_20261004.json'
    blacklist=args.blacklist.expanduser().resolve()
    try:
        origins,ranks,summary=analyze(eve,blacklist)
        # Pasta única para preservar execuções anteriores.
        import tempfile
        out=Path(tempfile.mkdtemp(prefix='panorama_blacklist_',dir=base/'reports'))
        print(save(origins,ranks,summary,out),end='')
        print(f'Resultados: {out}')
    except (OSError,ValueError) as exc:
        print(f'ERRO: {exc}',file=sys.stderr); sys.exit(1)

if __name__=='__main__': main()
