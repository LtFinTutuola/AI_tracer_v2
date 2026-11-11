"""Render observed application flows as Markdown and streaming JSONL.

Run without arguments to use config.yaml. Catalogs and sources are read-only;
new maps are published only after both output files have been generated.
"""
import argparse
from collections import Counter, OrderedDict
import hashlib
import html
import json
import os
from pathlib import Path
import shutil
import sqlite3
import sys
import tempfile

from application_decoder import ApplicationDecoder
from context_reader import BlockContextReader


def get_latest_log_file(working_dir):
    files = list(Path(working_dir).glob('*.log'))
    return max(files, key=lambda p: (p.stat().st_mtime_ns, p.name)) if files else None


def arguments(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--config', type=Path)
    p.add_argument('--db', type=Path);p.add_argument('--log', type=Path)
    p.add_argument('--build-manifest', type=Path);p.add_argument('--allow-unverified', action='store_true')
    p.add_argument('--output', type=Path)
    p.add_argument('--max-states', type=int, default=100000);p.add_argument('--max-depth', type=int, default=32)
    p.add_argument('--max-alternatives', type=int, default=8);p.add_argument('--max-memory-mb', type=int, default=128)
    p.add_argument('--source-context', type=int, default=2);p.add_argument('--diagram-max-nodes', type=int, default=80)
    a = p.parse_args(argv)
    if min(a.max_states,a.max_depth,a.max_alternatives,a.max_memory_mb,a.diagram_max_nodes)<1 or not 0<=a.source_context<=50:
        p.error('Limits must be positive; --source-context must be 0..50 (0 disables source snippets)')
    config = {}
    config_path = a.config or Path(__file__).with_name('config.yaml')
    if config_path.exists() and (a.config or not (a.db and a.log)):
        import yaml
        config = yaml.safe_load(config_path.read_text(encoding='utf-8-sig')) or {}
        if not isinstance(config,dict): raise ValueError('Configuration must be a mapping')
    elif a.config or not (a.db and a.log):
        raise ValueError('Configuration not found: ' + str(config_path))
    base = Path(__file__).resolve().parents[1] / 'code_analysis' / config.get('working_folder','default')
    a.db = (a.db or base / 'basic_blocks.sqlite').resolve()
    a.log = (a.log or get_latest_log_file(base))
    if a.log is None: raise ValueError('No runtime log found in ' + str(base))
    a.log = a.log.resolve();a.output = (a.output or a.db.parent / 'execution_map.md').resolve()
    if a.output.suffix.lower()!='.md': raise ValueError('--output must have .md extension')
    if not a.db.is_file() or not a.log.is_file(): raise ValueError('Database or log does not exist')
    if a.build_manifest: a.build_manifest = a.build_manifest.resolve()
    else:
        manifests = list(a.db.parent.glob('*.aitracer.json'))
        if len(manifests)>1: raise ValueError('Multiple build manifests found; specify --build-manifest')
        if manifests: a.build_manifest = manifests[0].resolve()
    inputs = {os.path.normcase(str(x)) for x in (a.db,a.log,a.build_manifest) if x}
    if any(os.path.normcase(str(x)) in inputs for x in (a.output,a.output.with_suffix('.jsonl'))):
        raise ValueError('Output must differ from all input files')
    return a


class Catalog:
    def __init__(self, path, context_lines):
        self.connection = sqlite3.connect(path.as_uri()+'?mode=ro',uri=True)
        self.connection.row_factory = sqlite3.Row
        tables = {r[0] for r in self.connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if 'basic_blocks' not in tables: raise ValueError('Missing basic_blocks table')
        self.manifest = dict(self.connection.execute('SELECT key,value FROM analysis_manifest')) if 'analysis_manifest' in tables else {}
        self.application = self.manifest.get('schema_version') in ('6','7') and self.manifest.get('injection_contract')=='application_edits_v1'
        self.static = self.manifest.get('schema_version') == '8' and self.manifest.get('injection_contract') == 'static_probes_v1'
        self.tables, self.context_lines = tables, context_lines
        self.cache, self.source_cache = OrderedDict(), OrderedDict()

    def close(self): self.connection.close()

    def probe(self, probe):
        if probe in self.cache:
            self.cache.move_to_end(probe);return self.cache[probe]
        row = self.connection.execute('SELECT * FROM basic_blocks WHERE id=?',(probe,)).fetchone()
        info = dict(row) if row else {'id':probe,'unknown':True}
        if (self.application or self.static) and row:
            placement = self.connection.execute('SELECT * FROM application_placements WHERE legacy_id=?',(probe,)).fetchone()
            if placement: info['placement'] = dict(placement)
        self.cache[probe] = info
        if len(self.cache)>256: self.cache.popitem(last=False)
        return info

    def snippet(self, info):
        if not self.context_lines or info.get('unknown'): return None
        file = info.get('file_path');line = info.get('injection_line',0)
        if not file or line<1: return None
        expected = info.get('placement',{}).get('source_hash')
        key = file,line,expected
        if key in self.source_cache: return self.source_cache[key]
        result = {'path':file,'line':line,'status':'unavailable'}
        try:
            path = Path(file);before = path.stat()
            digest = hashlib.sha256()
            with path.open(encoding='utf-8-sig',newline='') as f:
                for chunk in iter(lambda:f.read(65536),''): digest.update(chunk.encode('utf-8'))
            if expected and digest.hexdigest()!=expected:
                result.update(status='changed',reason='Source differs from injection catalog; excerpt omitted')
            else:
                lines = []
                with path.open(encoding='utf-8-sig',newline='') as f:
                    for n,text in enumerate(f,1):
                        if n>line+self.context_lines: break
                        if n>=max(1,line-self.context_lines): lines.append({'line':n,'text':text.rstrip('\r\n')[:2000]})
                after = path.stat()
                if (before.st_mtime_ns,before.st_size)!=(after.st_mtime_ns,after.st_size):
                    result.update(status='changed',reason='Source changed during read')
                else: result.update(status='verified' if expected else 'unverified',lines=lines)
        except (OSError,UnicodeError) as e: result['reason']=str(e)
        self.source_cache[key]=result
        if len(self.source_cache)>64: self.source_cache.popitem(last=False)
        return result

    def enrich(self, record):
        for event in record.get('observations',[]):
            info=self.probe(event['probe_id'])
            event['source']={k:info[k] for k in ('file_path','injection_line','method_signature','to_trace') if k in info}
            snippet=self.snippet(info)
            if snippet: event['source_context']=snippet
            for alternative in event.get('alternatives',[]):
                row=self.connection.execute('SELECT * FROM project_variants WHERE id=?',(alternative['variant_id'],)).fetchone()
                if row: alternative['project']={k:row[k] for k in ('name','path') if k in row.keys()}
                if 'application_entries' in self.tables:
                    entry=self.connection.execute('SELECT classification,reasons FROM application_entries WHERE method_id=?',(alternative['method_id'],)).fetchone()
                    if entry: alternative['entry']={'classification':entry['classification'],'reasons':json.loads(entry['reasons'])}
                if 'application_facts' in self.tables and 'application_symbols' in self.tables:
                    targets=self.connection.execute('''SELECT DISTINCT s.description FROM application_facts f
                        JOIN application_symbols s ON s.key=f.symbol_key JOIN application_placements p ON p.legacy_id=?
                        WHERE f.method_id=? AND (f.anchor=p.anchor OR (f.span_start=p.span_start AND f.span_end=p.span_end))
                        ORDER BY s.key LIMIT 33''',(event['probe_id'],alternative['method_id'])).fetchall()
                    alternative['targets']=[json.loads(t[0]) for t in targets[:32]]
                    alternative['targets_truncated']=len(targets)>32
        return record


def legacy_records(catalog, log):
    for n,raw in enumerate(log.open(encoding='utf-8-sig'),1):
        fields=raw.rstrip('\r\n').split('||')
        try:
            if len(fields)!=4 or not fields[0] or not fields[1]: raise ValueError()
            stamp,trace,thread,token=fields;probe=int(token);int(thread)
        except ValueError:
            yield {'kind':'gap','status':'incomplete','line':n,'reason':'malformed_record','binding_status':'unverified'};continue
        info=catalog.probe(probe)
        yield {'kind':'legacy_segment','segment_id':f'event-{n}','status':'incomplete','binding_status':'unverified',
               'trace_id':trace,'thread_id':thread,'first_line':n,'last_line':n,'closed':False,
               'reasons':['legacy_observations_only']+(['unknown_probe'] if info.get('unknown') else []),
               'observations':[{'probe_id':probe,'event_index':0,'line':n,'timestamp':stamp,'mapping_status':'legacy',
                                'alternatives':[],'alternatives_truncated':False}], 'relations':[],'operations':[]}


def cell(value):
    return html.escape(' '.join(str(value).split()),quote=False).replace('|','&#124;').replace('`','&#96;')


def event_label(event):
    alternatives=event.get('alternatives',[])
    if not alternatives: return 'Evento legacy o ID non risolto'
    labels=[]
    for a in alternatives:
        label='; '.join(o['kind']+': '+o['evidence'] for o in a['observations']) or a.get('evidence', 'marker osservato')
        targets=[(t.get('Type') or t.get('type',''))+'.'+(t.get('Member') or t.get('member','')) for t in a.get('targets',[])]
        if targets:label+=' · '+', '.join(targets)
        labels.append(label)
    return ' / '.join(labels)


def diagram(record,limit):
    events=record.get('observations',[]);shown=events[:limit]
    text=['```mermaid','flowchart TD']
    for e in shown:
        label=f"#{e['line']} · ID {e['probe_id']} · {event_label(e)}"
        if len(label)>220: label=label[:217]+'...'
        label=html.escape(' '.join(label.split()),quote=True).replace('`','&#96;')
        text.append(f'  E{e["event_index"]}["{label}"]')
    links=set();shown_ids={e['event_index'] for e in shown}
    for r in record.get('relations',[]):
        if r['from_event'] not in shown_ids or r['to_event'] not in shown_ids: continue
        kind=r['kind'];label=kind+(' · candidato opaco' if r['evidence']=='opaque_candidate' else '')
        link=(r['from_event'],r['to_event'],label,r['evidence'])
        if link in links: continue
        links.add(link);arrow='-.->' if kind=='gap' or r['evidence']!='cfg_witness' else '-->'
        text.append(f'  E{r["from_event"]} {arrow}|"{label}"| E{r["to_event"]}')
    if len(events)>limit: text.append(f'  omitted["{len(events)-limit} eventi omessi dal diagramma; disponibili nel JSONL"]')
    text.append('```')
    return '\n'.join(text)


def render_segment(out,record,limit):
    if record['kind']=='gap':
        out.write(f"\n## Lacuna alla riga {record['line']}\n\n{cell(record['reason'])}\n");return
    out.write(f"\n## {record['segment_id']} · {record['status']}\n\n")
    out.write(f"Thread `{record['thread_id']}` · Correlazione `{record['trace_id']}` · Righe {record['first_line']}–{record['last_line']}\n\n")
    observed=record.get('observations',[])
    if observed:out.write(f"Intervallo dei marker: `{observed[0]['timestamp']}` → `{observed[-1]['timestamp']}`.\n\n")
    if record['kind']=='static_segment':
        out.write('Marker osservati e compatibilità con le firme statiche. Identità delle attivazioni, completamento, numero di iterazioni e profondità ricorsiva non dimostrati.\n\n')
        for loss in record.get('losses', []): out.write('Dettaglio omesso dal profilo: '+cell(loss)+'.\n\n')
    else:
        out.write('Unicità riferita alle osservazioni applicative nel modello. I collegamenti rappresentano compatibilità CFG.\n\n' if record['kind']=='application_segment' else 'Vista degli eventi legacy osservati; ricostruzione applicativa non disponibile.\n\n')
    if record['reasons']: out.write('Lacune: '+', '.join('`'+r+'`' for r in record['reasons'])+'.\n\n')
    operations=record.get('operations',[])
    if operations:
        out.write('Operazioni con marker di ingresso e uscita:\n\n')
        for op in sorted(operations,key=lambda o:(o['enter_event'],o['variant_id'])):
            e=record['observations'][op['enter_event']]
            signature=next((a['signature'] for a in e['alternatives'] if a['method_id']==op['method_id']),str(op['method_id']))
            depth=0;parent=op.get('parent_enter_event');seen=set()
            while parent is not None and parent not in seen:
                seen.add(parent);depth+=1;parent=next((p.get('parent_enter_event') for p in operations if p['enter_event']==parent),None)
            end=str(op['leave_event']+1) if op['leave_event'] is not None else 'uscita non osservata'
            out.write('  '*depth+f"- `{cell(signature)}` · variante {op['variant_id']} · eventi {op['enter_event']+1}→{end} · {op['outcome']}\n")
        out.write('\n')
    if record.get('observations'): out.write(diagram(record,limit)+'\n\n')
    out.write('| Riga log | Timestamp | ID | Osservazione emessa | Metodo / variante | Mapping |\n|---:|---|---:|---|---|---|\n')
    for e in record.get('observations',[]):
        methods='; '.join(a['signature']+' [variante '+str(a['variant_id'])+']' for a in e.get('alternatives',[]))
        methods=methods or e.get('source',{}).get('method_signature','non disponibile')
        label=event_label(e)+(' · ulteriori alternative non esposte' if e.get('alternatives_truncated') else '')
        out.write(f"| {e['line']} | {cell(e['timestamp'])} | {e['probe_id']} | {cell(label)} | {cell(methods)} | {e['mapping_status']} |\n")
    contexts={}
    for e in record.get('observations',[]):
        c=e.get('source_context')
        if c: contexts.setdefault((c['path'],c['line']),c)
    for (file,line),c in contexts.items():
        out.write(f"\n<details>\n<summary>Contesto sorgente: {html.escape(file)}:{line} · {c['status']}</summary>\n\n")
        out.write('Contesto del marker; la visualizzazione non attesta l’esecuzione delle righe adiacenti.\n\n')
        if c.get('lines'):
            out.write('```csharp\n')
            for source in c['lines']: out.write(f"{source['line']:5d} | {source['text'].replace('```','` ` `')}\n")
            out.write('```\n')
        else: out.write(cell(c.get('reason','Sorgente non disponibile'))+'\n')
        out.write('\n</details>\n')


def publish_pair(staged,targets):
    backups={};changed=[]
    try:
        for source,target in zip(staged,targets):
            backup=source.with_name(source.name+'.previous')
            if target.exists(): shutil.copy2(target,backup);backups[target]=backup
            os.replace(source,target);changed.append(target)
    except BaseException:
        for target in reversed(changed):
            if target in backups: os.replace(backups[target],target)
            else: target.unlink(missing_ok=True)
        raise


def generate_map(args):
    catalog=Catalog(args.db,args.source_context);reader=None
    try:
        decoder=None
        if catalog.application or catalog.static:
            reader=BlockContextReader(args.db)
            if catalog.static:
                from static_flow_decoder import StaticFlowDecoder
                decoder=StaticFlowDecoder(reader,args.build_manifest,args.max_states,args.max_depth,args.max_alternatives,args.max_memory_mb,allow_unverified=args.allow_unverified)
            else:
                decoder=ApplicationDecoder(reader,args.build_manifest,args.max_states,args.max_depth,args.max_alternatives,args.max_memory_mb,allow_unverified=args.allow_unverified)
            records=decoder.decode(args.log)
        else:
            if args.build_manifest: raise ValueError('Application build manifest supplied for a legacy catalog')
            records=legacy_records(catalog,args.log)
        binding=decoder.binding_status if decoder else 'unverified'
        metadata={'kind':'map_metadata','format_version':1,'database':str(args.db),'log':str(args.log),
                  'build_manifest':str(args.build_manifest) if args.build_manifest else None,'binding_status':binding,
                  'mode':'static' if catalog.static else 'application' if catalog.application else 'legacy_observations',
                  'schema_version':catalog.manifest.get('schema_version','legacy'),
                  'profile_id':catalog.manifest.get('selection_profile_id'),
                  'policy_fingerprint':catalog.manifest.get('application_policy_fingerprint'),
                  'input_fingerprint':catalog.manifest.get('fingerprint'),
                  'application_summary':json.loads(catalog.manifest.get('application_summary','{}')),
                  'static_flow_summary':json.loads(catalog.manifest.get('static_flow_summary','{}')),
                  'catalog_coverage':catalog.manifest.get('coverage','unknown'),
                  'uniqueness_scope':'declared_marker_language_compatibility' if catalog.static else 'application_observations_in_declared_model'}
        print(json.dumps(metadata))
        args.output.parent.mkdir(parents=True,exist_ok=True)
        stats=Counter();statuses=Counter();decode_summary={}
        with tempfile.TemporaryDirectory(prefix='.execution-map-',dir=args.output.parent) as temp:
            temp=Path(temp);body=temp/'body.md';md=temp/'map.md';structured=temp/'map.jsonl'
            with body.open('w',encoding='utf-8',newline='\n') as out,structured.open('w',encoding='utf-8',newline='\n') as machine:
                machine.write(json.dumps(metadata,ensure_ascii=False)+'\n')
                for record in records:
                    if record['kind']=='summary': decode_summary=record;continue
                    catalog.enrich(record);statuses[record['status']]+=1;stats['segments']+=record['kind']!='gap'
                    stats['gaps']+=record['kind']=='gap'
                    for e in record.get('observations',[]):
                        stats['events']+=1;stats['source_only_events']+=e['mapping_status']=='source_only'
                        c=e.get('source_context',{})
                        stats['source_warnings']+=c.get('status') in ('changed','unavailable','unverified')
                    render_segment(out,record,args.diagram_max_nodes)
                    machine.write(json.dumps(record,ensure_ascii=False)+'\n')
                summary=decode_summary|{'kind':'map_summary','binding_status':binding,'counts':dict(stats),'statuses':dict(statuses)}
                machine.write(json.dumps(summary,ensure_ascii=False)+'\n')
            with md.open('w',encoding='utf-8',newline='\n') as out,body.open(encoding='utf-8') as content:
                out.write('# AI Tracer — Execution map applicativa\n\n')
                out.write(f"Log: `{args.log}`\n\nCatalogo: `{args.db}` · schema {metadata['schema_version']}\n\n")
                out.write(f"**Corrispondenza build–catalogo: {binding}.** Profilo: `{metadata['profile_id']}`.\n\n")
                if binding=='unverified': out.write('Analisi esplorativa: la corrispondenza con la build che ha emesso il log non è verificata.\n\n')
                out.write(f"Eventi: **{stats['events']}** · segmenti: **{stats['segments']}** · osservazioni source-only: **{stats['source_only_events']}**.\n\n")
                out.write('Stati: '+', '.join(f'{k}: {v}' for k,v in sorted(statuses.items()))+'.\n\n')
                out.write(f"Copertura dichiarata dal catalogo: `{metadata['catalog_coverage']}`. Ordine preservato per correlazione e thread; nessun ordine causale globale dedotto.\n\n")
                out.write('Gli ID assenti dal log non provano la mancata esecuzione del codice. Diagrammi e dettagli distinguono marker osservati, corridoi compatibili e lacune.\n\n')
                shutil.copyfileobj(content,out)
            publish_pair((md,structured),(args.output,args.output.with_suffix('.jsonl')))
        code=2 if binding!='verified' or any(k!='unique' for k in statuses) or stats['source_warnings'] else 0
        print(json.dumps({'state':'map_generated','exit_code':code,'markdown':str(args.output),'jsonl':str(args.output.with_suffix('.jsonl')),'summary':summary}))
        return code
    finally:
        if reader: reader.close()
        catalog.close()


def main(argv=None):
    try: return generate_map(arguments(argv))
    except (Exception,KeyboardInterrupt) as e:
        print(json.dumps({'state':'failed','error':str(e),'exception_type':type(e).__name__}),file=sys.stderr)
        return 1


if __name__=='__main__':
    sys.exit(main())
