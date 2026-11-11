"""Bounded schema 6/7 decoding; uniqueness concerns application observations.

Hypotheses retain their own continuations and activation stacks. Layered
predecessors survive convergence and are pruned by subsequent runtime events.
"""
from collections import OrderedDict, defaultdict, deque
from dataclasses import dataclass, field
import json
from pathlib import Path


@dataclass
class Hypothesis:
    state: tuple | None
    frames: tuple
    group: tuple
    parents: dict = field(default_factory=dict)
    reasons: frozenset = frozenset()
    operation: dict | None = None


@dataclass
class Segment:
    number: int
    first_line: int
    events: list = field(default_factory=list)
    layers: list = field(default_factory=list)
    hypotheses: dict = field(default_factory=dict)
    visited: int = 0
    reasons: set = field(default_factory=set)


class ApplicationDecoder:
    def __init__(self, reader, build_manifest=None, max_states=100000, max_depth=32,
                 max_candidates=8, max_memory_mb=128, allow_unverified=False):
        if min(max_states, max_depth, max_candidates, max_memory_mb) < 1:
            raise ValueError('Decoder limits must be positive')
        self.reader, meta = reader, reader.manifest
        if meta.get('schema_version') not in ('6', '7') or meta.get('injection_contract') != 'application_edits_v1':
            raise ValueError('Application schema 6/7 catalog required; regenerate and rebuild')
        if build_manifest:
            manifest = json.loads(Path(build_manifest).read_text(encoding='utf-8-sig'))
            for field_name, meta_name in [('profile_id', 'selection_profile_id'),
                                          ('policy_fingerprint', 'application_policy_fingerprint'),
                                          ('input_fingerprint', 'fingerprint'), ('injection_contract', 'injection_contract')]:
                if not manifest.get(field_name) or manifest[field_name] != meta.get(meta_name):
                    raise ValueError('Build manifest/catalog mismatch: ' + field_name)
            if str(manifest.get('schema_version')) != meta['schema_version']:
                raise ValueError('Build manifest schema/catalog mismatch')
            self.binding_status = 'verified'
        elif allow_unverified:
            self.binding_status = 'unverified'
        else:
            raise ValueError('Build manifest required; use --allow-unverified for explicit exploration')
        self.max_states, self.max_depth = max_states, max_depth
        self.max_candidates, self.memory_limit = max_candidates, max_memory_mb * 1024 * 1024
        self.cache, self.cache_bytes = OrderedDict(), 0
        self.peak_states = self.peak_owned_bytes = 0
        self.events_read = self.segments_emitted = self.next_segment = 0
        self.active_streams = {}
        self.has_summaries = bool(reader.rows("SELECT name FROM sqlite_master WHERE type='table' AND name='application_method_summaries'"))
        self.has_diagnostics = bool(reader.rows("SELECT name FROM sqlite_master WHERE type='table' AND name='analysis_diagnostics'"))

    def method_incomplete(self, method):
        return self.has_diagnostics and bool(self.rows('''SELECT EXISTS(SELECT 1 FROM analysis_diagnostics
            WHERE scope=? OR scope=(SELECT 'document:'||document_id FROM methods WHERE id=?)) AS incomplete WHERE 1=1''',
            ('method:'+str(method),method))[0]['incomplete'])

    def rows(self, sql, parameters=()):
        key = sql, tuple(parameters)
        if key in self.cache:
            self.cache.move_to_end(key)
            return self.cache[key][0]
        result = self.reader.rows(sql + ' LIMIT ' + str(self.max_states + 1), parameters)
        if len(result) > self.max_states: raise OverflowError('adjacency_budget')
        size = 256 + len(json.dumps(result, ensure_ascii=False)) * 3
        if size > self.memory_limit // 3: raise OverflowError('adjacency_memory_budget')
        while self.cache and (len(self.cache) >= 256 or self.cache_bytes + size > self.memory_limit // 3):
            _, (_, previous) = self.cache.popitem(last=False);self.cache_bytes -= previous
        self.cache[key] = result, size;self.cache_bytes += size
        return result

    def event(self, probe):
        rows = self.rows('''SELECT o.*,l.node_id,l.position,l.edge_id,m.signature,f.is_async,b.to_trace
            FROM application_probe_bindings x JOIN application_observations o ON o.id=x.observation_id
            JOIN basic_blocks b ON b.id=x.legacy_id JOIN methods m ON m.id=o.method_id
            JOIN application_method_facts f ON f.method_id=m.id
            LEFT JOIN application_locations l ON l.observation_id=o.id
            WHERE x.legacy_id=? ORDER BY o.variant_id,o.id,l.node_id,l.position''', (probe,))
        groups = {}
        for row in rows:
            key = row['method_id'], row['variant_id']
            g = groups.setdefault(key, {'method_id': key[0], 'variant_id': key[1], 'signature': row['signature'],
                                       'observations': {}, 'locations': set(), 'async': bool(row['is_async']), 'enabled': bool(row['to_trace'])})
            g['observations'][row['id']] = {k: row[k] for k in ('id', 'kind', 'evidence', 'status')} | {
                'mapping_status':row.get('mapping_status','exact_frontier' if row['node_id'] is not None else 'source_only'),
                'mapping_reason':row.get('mapping_reason','Schema 6 location' if row['node_id'] is not None else 'Schema 6 has no demonstrated CFG location')}
            if row['node_id'] is not None: g['locations'].add((row['node_id'], row['position'], row['edge_id']))
        return groups

    def gap(self, node, position):
        rows = self.rows('''SELECT DISTINCT x.legacy_id,p.anchor FROM application_locations l
            JOIN application_probe_bindings x ON x.observation_id=l.observation_id
            JOIN application_placements p ON p.legacy_id=x.legacy_id JOIN basic_blocks b ON b.id=x.legacy_id
            WHERE l.node_id=? AND l.position=? AND l.edge_id IS NULL AND b.to_trace=1 ORDER BY p.anchor,x.legacy_id''', (node, position))
        return [r['legacy_id'] for r in rows]

    def edge_probes(self, edge):
        return [r['legacy_id'] for r in self.rows('''SELECT DISTINCT x.legacy_id FROM application_locations l
            JOIN application_probe_bindings x ON x.observation_id=l.observation_id JOIN basic_blocks b ON b.id=x.legacy_id
            WHERE l.edge_id=? AND b.to_trace=1 ORDER BY x.legacy_id''', (edge,))]

    def spend(self, seg, amount=1):
        seg.visited += amount;self.peak_states = max(self.peak_states, seg.visited)
        if seg.visited > self.max_states: raise OverflowError('state_or_predecessor_budget')
        # Conservative ledger includes temporary closures/predecessors and the
        # materialized corridor evidence, before those buffers reach the caller.
        estimate = self.cache_bytes + sum(s.visited*768+len(s.events)*4096 for s in self.active_streams.values())
        self.peak_owned_bytes = max(self.peak_owned_bytes,estimate)
        if estimate > self.memory_limit: raise OverflowError('global_buffer_budget')

    def seeds(self, group, uncertain=False):
        states = set()
        for node, position, edge in group['locations']:
            if edge is not None:
                points = self.rows('SELECT position FROM flow_points WHERE node_id=? ORDER BY position DESC', (node,))
                position = points[0]['position'] + 1 if points else 0
            states.add((node, position, (), 0, uncertain, False))
        return states

    def reach(self, seg, start, probe):
        queue, seen, previous, found = deque([start]), set(), defaultdict(list), []
        reasons = set()
        while queue:
            state = queue.popleft()
            if state in seen: continue
            seen.add(state);self.spend(seg)
            node, position, stack, phase, uncertain, exceptional = state
            current = self.rows('SELECT * FROM flow_nodes WHERE id=?', (node,))[0]
            if self.method_incomplete(current['method_id']): reasons.add('method_model_incomplete')
            required = self.gap(node, position)
            if phase < len(required):
                if required[phase] == probe:
                    found.append(((node, position, stack, phase + 1, uncertain, exceptional), current['method_id'], state, None))
                continue
            points = self.rows('SELECT * FROM flow_points WHERE node_id=? ORDER BY position', (node,))
            point = next((p for p in points if p['position'] >= position), None)
            moves = []
            if point is not None:
                if point['kind'] == 'incomplete':
                    reasons.add('suspension_or_transfer_not_modeled');continue
                if point['kind'] == 'call':
                    call = self.rows('SELECT * FROM call_sites WHERE point_id=?', (point['id'],))[0]
                    targets = self.rows('SELECT method_id FROM call_targets WHERE site_id=? ORDER BY method_id', (call['id'],))
                    opened = call['resolution'] != 'static' or len(targets) != 1
                    if len(stack) >= self.max_depth and targets: raise OverflowError('call_depth_budget')
                    for target in targets:
                        if self.has_summaries:
                            summary = self.rows('SELECT flags,opaque FROM application_method_summaries WHERE method_id=?',(target['method_id'],))
                            if summary and summary[0]['flags']==0:
                                exits = self.rows("SELECT reachable FROM flow_nodes WHERE method_id=? AND kind='Exit'",(target['method_id'],))
                                if exits and exits[0]['reachable']:
                                    moves.append(((node,call['continuation_position'],stack,0,uncertain or opened or bool(summary[0]['opaque']),exceptional),('summary',call['id'],target['method_id'])))
                                continue
                        entries = self.rows("SELECT id FROM flow_nodes WHERE method_id=? AND kind='Entry'", (target['method_id'],))
                        if entries:
                            frame = (node, call['continuation_position'], call['id'])
                            moves.append(((entries[0]['id'], 0, stack + (frame,), 0, uncertain or opened, exceptional), ('call', call['id'], target['method_id'])))
                    if opened or not targets:
                        moves.append(((node, call['continuation_position'], stack, 0, True, exceptional), ('opaque', call['id'], None)))
                elif point['kind'] == 'exit':
                    if stack and not exceptional:
                        caller, continuation, site = stack[-1]
                        moves.append(((caller, continuation, stack[:-1], 0, uncertain, False), ('return', site, current['method_id'])))
                else:
                    moves.append(((node, point['position'] + 1, stack, 0, uncertain, exceptional), ('local', None, current['method_id'])))
            else:
                for edge in self.rows('SELECT * FROM flow_edges WHERE source_id=? ORDER BY id', (node,)):
                    witnesses = self.edge_probes(edge['id'])
                    if witnesses:
                        if probe in witnesses and len(witnesses) == 1 and edge['target_id'] is not None:
                            end = (edge['target_id'], 0, stack, 0, uncertain or edge['status'] != 'modeled', exceptional)
                            found.append((end, current['method_id'], state, edge['id']))
                        elif len(witnesses) > 1: reasons.add('multiple_edge_witnesses')
                        continue
                    if edge['status'] != 'modeled' or edge['target_id'] is None:
                        reasons.add('transfer_not_modeled');continue
                    moves.append(((edge['target_id'], 0, stack, 0, uncertain, exceptional), ('edge', edge['id'], current['method_id'])))
            for destination, transfer in moves:
                self.spend(seg);previous[destination].append((state, transfer));queue.append(destination)
        result = []
        for end, method, source, edge in found:
            pending, live, transfers, branching = [source], set(), set(), False
            while pending:
                cursor = pending.pop()
                if cursor in live: continue
                self.spend(seg);live.add(cursor);parents = previous.get(cursor, ())
                branching |= len(parents) > 1
                for parent, transfer in parents:
                    self.spend(seg);transfers.add(transfer)
                    if parent in live: branching = True
                    pending.append(parent)
            kinds = sorted({k for k, _, _ in transfers if k in ('call', 'return', 'opaque')} | ({'call','return'} if any(k=='summary' for k,_,_ in transfers) else set()))
            movement='call' if len(end[2])>len(start[2]) else 'return' if len(end[2])<len(start[2]) else 'local'
            corridor = {'kind': movement,
                        'evidence': 'opaque_candidate' if end[4] else 'cfg_witness',
                        'call_sites': sorted({v for k, v, _ in transfers if k in ('call', 'return', 'opaque', 'summary')}),
                        'edge_ids': sorted({v for k, v, _ in transfers if k == 'edge'} | ({edge} if edge else set())),
                        'method_ids': sorted({m for _, _, m in transfers if m is not None} | {method}),
                        'transfers': kinds, 'silent_method_summaries': sorted({m for k,_,m in transfers if k=='summary'}),
                        'technical_ambiguity': branching or any(k=='summary' for k,_,_ in transfers), 'corridor_states': len(live)}
            why = reasons | ({'opaque_call_or_dispatch'} if end[4] else set())
            result.append((end, method, corridor, why))
        return result

    def new_segment(self, line):
        self.next_segment += 1
        return Segment(self.next_segment, line)

    def advance(self, seg, groups, probe, line, stamp, unmapped):
        index = len(seg.events)
        seg.events.append({'probe_id': probe, 'line': line, 'timestamp': stamp, '_groups': groups,
                           'unmapped_variant_candidates': unmapped[:self.max_candidates], 'unmapped_variants_truncated': len(unmapped) > self.max_candidates})
        previous = seg.layers[-1] if seg.layers else [None]
        matches, unknown = [], []
        for parent_id in previous:
            parent = seg.hypotheses[parent_id] if parent_id is not None else None
            for key, g in groups.items():
                kinds = {o['kind'] for o in g['observations'].values()}
                if 'operation_error' in kinds:
                    if parent and parent.frames and parent.frames[-1][:2] == key:
                        matches.append((parent_id, key, None, self.corridor('gap'), {'exceptional_transfer_source_boundary'}))
                    else: unknown.append((parent_id, key))
                    continue
                seeds = [parent.state] if parent and parent.state is not None else self.seeds(g, bool(parent))
                for seed in seeds:
                    for state, method, corridor, why in self.reach(seg, seed, probe):
                        if method == g['method_id']:
                            if parent and parent.state is None: why = why | {'source_observation_without_proven_cfg_chain'};corridor = self.corridor('gap')
                            matches.append((parent_id, key, state, corridor, why))
                if not g['locations']: unknown.append((parent_id, key))
        # Unsupported bindings remain open alternatives; disproven modeled ones
        # are discarded. Recover only when the entire modeled frontier failed.
        recover = unknown if matches else [(p, k) for p in previous for k in groups]
        for parent_id, key in recover:
            recovered = []
            for seed in self.seeds(groups[key], True):
                recovered.extend(r[0] for r in self.reach(seg, seed, probe) if r[1] == groups[key]['method_id'])
            for state in recovered or [None]:
                matches.append((parent_id, key, state, self.corridor('gap'), {'source_observation_without_proven_cfg_chain'}))
        layer, merged = [], {}
        for parent_id, key, state, corridor, extra in matches:
            g = groups[key];parent = seg.hypotheses.get(parent_id)
            frames = parent.frames if parent else ()
            why = set(parent.reasons if parent else ()) | extra
            kinds = {o['kind'] for o in g['observations'].values()}
            if unmapped: why.add('probe_emittable_in_unmapped_variant')
            if g['async']: why.add('async_invocation_correlation_not_proven')
            if any(o['status'] != 'modeled' for o in g['observations'].values()): why.add('opaque_observation')
            if any(o['kind']=='operation_enter' and o['evidence']=='opaque' for o in g['observations'].values()): why.add('policy_opaque_component')
            if not parent and 'operation_enter' not in kinds: why.add('missing_entry_or_cross_thread_continuation')
            if 'operation_error' in kinds:
                if frames and frames[-1][:2] == key: frames = frames[:-1] + (frames[-1][:4] + (True,),)
                else: why.add('exception_scope_not_proven')
            if 'operation_enter' in kinds:
                if any(f[3] for f in frames): why.add('interleaved_async_activation')
                if len(frames) >= self.max_depth: raise OverflowError('operation_depth_budget')
                frames += ((key[0], key[1], index, g['async'], False),)
            operation = None
            if 'operation_leave' in kinds:
                if frames and frames[-1][:2] == key:
                    closed, frames = frames[-1], frames[:-1]
                    operation = {'enter_event': closed[2], 'leave_event': index, 'method_id': key[0], 'variant_id': key[1],
                                 'outcome': 'exceptional' if closed[4] else next(o['evidence'] for o in g['observations'].values() if o['kind']=='operation_leave'),
                                 'parent_enter_event': frames[-1][2] if frames else None}
                else: why.add('unbalanced_operation_leave')
            merge_key = state, frames, key, frozenset(why)
            number = merged.get(merge_key)
            if number is None:
                self.spend(seg);number = len(seg.hypotheses) + 1;merged[merge_key] = number;layer.append(number)
                seg.hypotheses[number] = Hypothesis(state, frames, key, reasons=frozenset(why), operation=operation)
            if parent_id is not None:
                self.spend(seg);seg.hypotheses[number].parents.setdefault(parent_id, []).append(corridor)
        seg.layers.append(layer)

    @staticmethod
    def corridor(kind):
        return {'kind': kind, 'evidence': 'source_only', 'call_sites': [], 'edge_ids': [], 'method_ids': [], 'transfers': [], 'technical_ambiguity': True}

    def result(self, key, seg, line, terminal=False, forced=None):
        live, pending = set(), list(seg.layers[-1] if seg.layers else [])
        while pending:
            number = pending.pop()
            if number in live: continue
            live.add(number);pending.extend(seg.hypotheses[number].parents)
        reasons = set(seg.reasons)
        for n in seg.layers[-1] if seg.layers else (): reasons.update(seg.hypotheses[n].reasons)
        events, relations, operations = [], [], []
        ambiguous = technical = relations_truncated = operations_truncated = False
        displayed=[]
        for index, event in enumerate(seg.events):
            numbers = [n for n in (seg.layers[index] if index < len(seg.layers) else []) if n in live]
            keys = {seg.hypotheses[n].group for n in numbers}
            if not keys: keys = set(event.get('_groups', {}))
            groups = [event['_groups'][k] for k in sorted(keys)]
            displayed.append(set(sorted(keys)[:self.max_candidates]))
            alternatives = []
            for g in groups[:self.max_candidates]:
                obs = list(g['observations'].values())
                alternatives.append({'method_id': g['method_id'], 'variant_id': g['variant_id'], 'signature': g['signature'],
                    'observations': obs, 'observation_ids': [o['id'] for o in obs], 'kind': obs[0]['kind'],
                    'evidence': '; '.join(o['evidence'] for o in obs),
                    'locations': [{'node_id': n, 'position': p, 'edge_id': e} for n, p, e in sorted(g['locations'], key=lambda x:(x[0],x[1],x[2] or -1))]})
            ambiguous |= len(groups) > 1
            technical |= len(groups) > 1
            events.append({k: v for k, v in event.items() if not k.startswith('_')} | {'event_index': index,
                'alternatives': alternatives, 'alternatives_truncated': len(groups)>self.max_candidates,
                'mapping_status': 'exact_frontier' if groups and all(g['locations'] for g in groups) else 'source_only'})
            links = []
            for n in numbers:
                h = seg.hypotheses[n]
                if h.group not in displayed[index]:
                    relations_truncated=True;operations_truncated=True;continue
                if h.operation and h.operation not in operations: operations.append(h.operation)
                for parent_id, corridors in h.parents.items():
                    if parent_id not in live: continue
                    if seg.hypotheses[parent_id].group not in displayed[index-1]:
                        relations_truncated=True;continue
                    for corridor in corridors:
                        entry = dict(corridor, from_event=index-1, to_event=index,
                                     from_interpretation=list(seg.hypotheses[parent_id].group), to_interpretation=list(h.group))
                        if entry not in links: links.append(entry)
                        technical |= corridor.get('technical_ambiguity', False)
            relations.extend(links)
        for n in seg.layers[-1] if seg.layers else ():
            for method,variant,enter,is_async,error in seg.hypotheses[n].frames:
                if (method,variant) not in displayed[enter]:
                    operations_truncated=True;continue
                op={'enter_event':enter,'leave_event':None,'method_id':method,'variant_id':variant,
                    'outcome':'exception_without_leave' if error else 'open','parent_enter_event':None}
                if op not in operations:operations.append(op)
        if not terminal: reasons.add('segment_not_closed')
        # A pair of boundary markers alone does not prove a caller relationship.
        for op in operations:
            inbound = [r for r in relations if r['to_event']==op['enter_event']]
            proven = bool(inbound) and all('call' in r['transfers'] and r['evidence']=='cfg_witness' for r in inbound)
            op['nesting_evidence'] = 'cfg_witness' if proven else 'boundary_markers_only'
            if op['parent_enter_event'] is not None and not proven:
                op['candidate_parent_enter_event'] = op['parent_enter_event'];op['parent_enter_event'] = None
        self.segments_emitted += 1
        return {'kind': 'application_segment', 'segment_id': f'segment-{seg.number}',
            'status': forced or ('incomplete' if reasons else 'ambiguous' if ambiguous else 'unique'),
            'binding_status': self.binding_status, 'uniqueness_scope': 'application_observations_in_declared_model',
            'trace_id': key[0], 'thread_id': key[1], 'first_line': seg.first_line, 'last_line': line, 'closed': terminal,
            'reasons': sorted(reasons), 'observations': events, 'relations': relations, 'operations': operations,
            'relations_truncated':relations_truncated,'operations_truncated':operations_truncated,
            'technical_path': 'candidate_equivalence_class; no enumeration',
            'technical_path_status': 'incomplete' if reasons else 'ambiguous' if technical else 'unique_in_model',
            'visited_states': seg.visited}

    def owned(self, streams):
        size = self.cache_bytes
        for s in streams.values():
            size += 2048 + len(s.events)*2048 + len(s.hypotheses)*2048
            for h in s.hypotheses.values():
                size += len(h.frames)*96
                for corridors in h.parents.values():
                    for c in corridors: size += 512 + 48*sum(len(c.get(k, ())) for k in ('edge_ids','method_ids','call_sites'))
        return size

    def decode(self, log):
        streams = OrderedDict();line_number = 0
        self.active_streams = streams
        with Path(log).open(encoding='utf-8-sig') as source:
            for line_number, raw in enumerate(source, 1):
                fields = raw.rstrip('\r\n').split('||')
                try:
                    if len(fields)!=4 or not fields[0] or not fields[1]: raise ValueError()
                    stamp, trace, thread, token = fields;probe = int(token);int(thread)
                except ValueError:
                    for key, seg in streams.items():
                        seg.reasons.add('malformed_record_gap');yield self.result(key, seg, line_number)
                    streams.clear()
                    yield {'kind':'gap','status':'incomplete','binding_status':self.binding_status,'line':line_number,'reason':'malformed_record'}
                    continue
                self.events_read += 1;key = trace, thread
                if key not in streams: streams[key] = self.new_segment(line_number)
                seg = streams[key];streams.move_to_end(key);before = len(seg.events)
                try:
                    groups = self.event(probe)
                    if not groups or any(not g['enabled'] for g in groups.values()):
                        seg.events.append({'probe_id':probe,'line':line_number,'timestamp':stamp,'_groups':groups})
                        seg.reasons.add('unknown_or_disabled_probe');item = self.result(key,seg,line_number);item['unexpected_probe_id']=probe
                        yield item;streams.pop(key,None);continue
                    unmapped = self.rows('''SELECT DISTINCT v.id,v.name FROM documents d JOIN project_variants v ON v.id=d.variant_id
                        WHERE d.origin='source' AND d.path=(SELECT path FROM application_placements WHERE legacy_id=?) COLLATE NOCASE
                        AND NOT EXISTS(SELECT 1 FROM application_probe_bindings b JOIN application_observations o ON o.id=b.observation_id
                            WHERE b.legacy_id=? AND o.variant_id=d.variant_id) ORDER BY v.id''',(probe,probe))
                    self.advance(seg,groups,probe,line_number,stamp,unmapped)
                    owned = self.owned(streams);self.peak_owned_bytes=max(self.peak_owned_bytes,owned)
                    if owned>self.memory_limit or len(streams)>min(1024,self.max_states): raise OverflowError('global_buffer_budget')
                    last=[seg.hypotheses[n] for n in seg.layers[-1]]
                    if last and all(not h.frames for h in last):
                        leaves=all(any(o['kind']=='operation_leave' for o in g['observations'].values()) for g in groups.values())
                        yield self.result(key,seg,line_number,terminal=leaves);streams.pop(key,None)
                except OverflowError as ex:
                    if len(seg.events)==before: seg.events.append({'probe_id':probe,'line':line_number,'timestamp':stamp,'_groups':{}})
                    seg.reasons.add(str(ex));yield self.result(key,seg,line_number,forced='budget_exceeded');streams.pop(key,None)
                    while streams and self.owned(streams)>self.memory_limit:
                        other_key,other=streams.popitem(last=False);other.reasons.add('global_buffer_budget')
                        yield self.result(other_key,other,line_number,forced='budget_exceeded')
        for key,seg in streams.items():
            seg.reasons.add('log_ended_with_open_operation');yield self.result(key,seg,line_number)
        yield {'kind':'summary','events_read':self.events_read,'segments':self.segments_emitted,'peak_states':self.peak_states,
               'peak_owned_buffer_estimate':self.peak_owned_bytes,'profile_id':self.reader.manifest['selection_profile_id'],
               'binding_status':self.binding_status,'ordering':'file order within correlation/thread; no global causal ordering inferred'}
