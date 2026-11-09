"""Bounded source-model decoding. Correlation IDs are groups, not invocation IDs."""
from collections import OrderedDict, deque
from dataclasses import dataclass, field
import json
from pathlib import Path


@dataclass
class Segment:
    states: set = field(default_factory=set)
    frames: list = field(default_factory=list)
    events: list = field(default_factory=list)
    reasons: set = field(default_factory=set)
    visited: int = 0
    first_line: int = 0


class ApplicationDecoder:
    def __init__(self, reader, build_manifest, max_states=100000, max_depth=32,
                 max_candidates=8, max_memory_mb=128):
        if min(max_states, max_depth, max_candidates, max_memory_mb) < 1:
            raise ValueError('Decoder limits must be positive')
        self.reader = reader
        meta = reader.manifest
        manifest = json.loads(Path(build_manifest).read_text(encoding='utf-8-sig'))
        if meta.get('schema_version') != '6' or meta.get('injection_contract') != 'application_edits_v1':
            raise ValueError('Application schema 6 catalog required; regenerate and rebuild')
        for field_name, meta_name in [('profile_id', 'selection_profile_id'),
                                      ('policy_fingerprint', 'application_policy_fingerprint'),
                                      ('input_fingerprint', 'fingerprint'),
                                      ('injection_contract', 'injection_contract')]:
            if not manifest.get(field_name) or manifest[field_name] != meta.get(meta_name):
                raise ValueError('Build manifest/catalog mismatch: ' + field_name)
        if manifest.get('schema_version') != 6:
            raise ValueError('Build manifest schema 6 required')
        self.max_states, self.max_depth = max_states, max_depth
        self.max_candidates, self.memory_limit = max_candidates, max_memory_mb * 1024 * 1024
        self.cache, self.cache_bytes = OrderedDict(), 0
        self.peak_states = self.peak_owned_bytes = 0
        self.events_read = self.segments_emitted = 0

    def rows(self, sql, parameters=()):
        key = sql, tuple(parameters)
        if key in self.cache:
            self.cache.move_to_end(key)
            return self.cache[key][0]
        result = self.reader.rows(sql + ' LIMIT ' + str(self.max_states + 1), parameters)
        if len(result) > self.max_states:
            raise OverflowError('adjacency_budget')
        size = 256 + len(json.dumps(result, ensure_ascii=False)) * 3
        if size > self.memory_limit // 3:
            raise OverflowError('adjacency_memory_budget')
        while self.cache and (len(self.cache) >= 256 or self.cache_bytes + size > self.memory_limit // 3):
            _, (_, previous) = self.cache.popitem(last=False)
            self.cache_bytes -= previous
        self.cache[key] = result, size
        self.cache_bytes += size
        return result

    def event(self, probe):
        return self.rows('''SELECT o.*,l.node_id,l.position,l.edge_id,m.signature,f.is_async,b.to_trace
            FROM application_probe_bindings x JOIN application_observations o ON o.id=x.observation_id
            JOIN basic_blocks b ON b.id=x.legacy_id JOIN methods m ON m.id=o.method_id
            JOIN application_method_facts f ON f.method_id=m.id
            LEFT JOIN application_locations l ON l.observation_id=o.id
            WHERE x.legacy_id=? ORDER BY o.variant_id,o.id''', (probe,))

    def node(self, node):
        return self.rows('SELECT * FROM flow_nodes WHERE id=?', (node,))[0]

    def gap(self, node, position):
        rows = self.rows('''SELECT DISTINCT x.legacy_id,p.anchor FROM application_locations l
            JOIN application_probe_bindings x ON x.observation_id=l.observation_id
            JOIN application_placements p ON p.legacy_id=x.legacy_id
            JOIN basic_blocks b ON b.id=x.legacy_id
            WHERE l.node_id=? AND l.position=? AND l.edge_id IS NULL AND b.to_trace=1
            ORDER BY p.anchor,x.legacy_id''', (node, position))
        return [r['legacy_id'] for r in rows]

    def edge_probes(self, edge):
        return [r['legacy_id'] for r in self.rows('''SELECT DISTINCT x.legacy_id
            FROM application_locations l JOIN application_probe_bindings x ON x.observation_id=l.observation_id
            JOIN basic_blocks b ON b.id=x.legacy_id WHERE l.edge_id=? AND b.to_trace=1 ORDER BY x.legacy_id''', (edge,))]

    def reach(self, segment, probe):
        queue, seen, found, methods = deque(segment.states), set(), set(), set()
        while queue:
            state = queue.popleft()
            if state in seen:
                continue
            seen.add(state)
            segment.visited += 1
            self.peak_states = max(self.peak_states, len(seen) + len(found))
            if segment.visited > self.max_states:
                raise OverflowError('state_budget')
            node, position, stack, phase, uncertain, exceptional = state
            if not node:
                continue
            current = self.node(node)
            required = self.gap(node, position)
            if phase < len(required):
                if required[phase] == probe:
                    found.add((node, position, stack, phase + 1, uncertain, exceptional))
                    methods.add(current['method_id'])
                continue
            points = self.rows('SELECT * FROM flow_points WHERE node_id=? ORDER BY position', (node,))
            point = next((p for p in points if p['position'] >= position), None)
            if point is not None:
                next_position = point['position'] + 1
                if point['kind'] == 'incomplete':
                    segment.reasons.add('suspension_or_transfer_not_modeled')
                    continue
                if point['kind'] == 'call':
                    calls = self.rows('SELECT * FROM call_sites WHERE point_id=?', (point['id'],))
                    call = calls[0]
                    targets = self.rows('SELECT method_id FROM call_targets WHERE site_id=? ORDER BY method_id', (call['id'],))
                    open_call = call['resolution'] != 'static' or len(targets) != 1
                    if len(stack) >= self.max_depth and targets:
                        raise OverflowError('call_depth_budget')
                    for target in targets:
                        entries = self.rows("SELECT id FROM flow_nodes WHERE method_id=? AND kind='Entry'", (target['method_id'],))
                        if entries:
                            frame = (node, call['continuation_position'])
                            queue.append((entries[0]['id'], 0, stack + (frame,), 0, uncertain or open_call, exceptional))
                    if open_call or not targets:
                        # This is an explicit opaque alternative, never proof that
                        # a virtual/external call really returned normally.
                        queue.append((node, call['continuation_position'], stack, 0, True, exceptional))
                elif point['kind'] == 'exit':
                    if exceptional:
                        continue  # never turn a throw into a normal caller continuation
                    if stack:
                        caller, continuation = stack[-1]
                        queue.append((caller, continuation, stack[:-1], 0, uncertain, False))
                    else:
                        queue.append((0, 0, (), 0, uncertain, False))
                else:
                    queue.append((node, next_position, stack, 0, uncertain, exceptional))
                continue
            for edge in self.rows('SELECT * FROM flow_edges WHERE source_id=? ORDER BY id', (node,)):
                witnesses = self.edge_probes(edge['id'])
                if witnesses:
                    if probe in witnesses and len(witnesses) == 1 and edge['target_id'] is not None:
                        found.add((edge['target_id'], 0, stack, 0, uncertain or edge['status'] != 'modeled', exceptional))
                        methods.add(current['method_id'])
                    elif len(witnesses) > 1:
                        segment.reasons.add('multiple_edge_witnesses')
                    continue
                if edge['status'] != 'modeled' or edge['target_id'] is None:
                    segment.reasons.add('transfer_not_modeled')
                    continue
                queue.append((edge['target_id'], 0, stack, 0, uncertain, exceptional))
        if any(s[4] for s in found):
            segment.reasons.add('opaque_call_or_dispatch')
        return found, methods

    def resume(self, observations, probe, exceptional=False):
        states = set()
        for o in observations:
            if o['node_id'] is None:
                continue
            if o['edge_id'] is not None:
                edge = self.rows('SELECT target_id FROM flow_edges WHERE id=?', (o['edge_id'],))[0]
                if edge['target_id'] is not None:
                    states.add((edge['target_id'], 0, (), 0, True, exceptional))
            else:
                gap = self.gap(o['node_id'], o['position'])
                if probe in gap:
                    states.add((o['node_id'], o['position'], (), gap.index(probe) + 1, True, exceptional))
        return states

    def result(self, key, segment, line, terminal=False, forced=None):
        alternatives = max((len(e['alternatives']) + int(e['alternatives_truncated']) for e in segment.events), default=0)
        status = forced or ('incomplete' if segment.reasons or not terminal else 'ambiguous' if alternatives > 1 else 'unique')
        self.segments_emitted += 1
        return {'kind': 'application_segment', 'status': status, 'trace_id': key[0], 'thread_id': key[1],
                'first_line': segment.first_line, 'last_line': line, 'closed': terminal,
                'reasons': sorted(segment.reasons), 'observations': segment.events,
                'technical_path': 'candidate_equivalence_class; no enumeration',
                'visited_states': segment.visited}

    def decode(self, log):
        streams = OrderedDict()
        line_number = 0
        with Path(log).open(encoding='utf-8-sig') as source:
            for line_number, raw in enumerate(source, 1):
                fields = raw.rstrip('\r\n').split('||')
                try:
                    if len(fields) != 4 or not fields[0] or not fields[1]:
                        raise ValueError()
                    stamp, trace, thread, token = fields
                    probe = int(token)
                    int(thread)
                except ValueError:
                    # An unknown record could belong to any stream. Break every
                    # open chain instead of silently joining across the gap.
                    for key, seg in streams.items():
                        seg.reasons.add('malformed_record_gap')
                        yield self.result(key, seg, line_number)
                    streams.clear()
                    yield {'kind': 'gap', 'status': 'incomplete', 'line': line_number, 'reason': 'malformed_record'}
                    continue
                self.events_read += 1
                key = trace, thread
                seg = streams.setdefault(key, Segment(first_line=line_number))
                streams.move_to_end(key)
                try:
                    obs = self.event(probe)
                    if not obs or any(not o['to_trace'] for o in obs):
                        seg.reasons.add('unknown_or_disabled_probe')
                        item=self.result(key, seg, line_number)
                        item['unexpected_probe_id']=probe
                        yield item
                        streams.pop(key, None)
                        continue
                    kinds = {o['kind'] for o in obs}
                    unmapped=self.rows('''SELECT DISTINCT v.id,v.name FROM documents d JOIN project_variants v ON v.id=d.variant_id
                        WHERE d.origin='source' AND d.path=(SELECT path FROM application_placements WHERE legacy_id=?) COLLATE NOCASE
                        AND NOT EXISTS(SELECT 1 FROM application_probe_bindings b JOIN application_observations o ON o.id=b.observation_id
                            WHERE b.legacy_id=? AND o.variant_id=d.variant_id) ORDER BY v.id''',(probe,probe))
                    if unmapped:
                        seg.reasons.add('probe_emittable_in_unmapped_variant')
                    starts = 'operation_enter' in kinds
                    leaves = 'operation_leave' in kinds
                    errors = 'operation_error' in kinds
                    if starts and seg.frames and any(f['async'] for f in seg.frames):
                        seg.reasons.add('interleaved_async_activation')
                        yield self.result(key, seg, line_number)
                        seg = streams[key] = Segment(first_line=line_number)
                    if not seg.frames:
                        if not starts:
                            seg.reasons.add('missing_entry_or_cross_thread_continuation')
                        seg.states = {(o['node_id'], o['position'], (), 0, False, False)
                                      for o in obs if o['node_id'] is not None and o['edge_id'] is None}
                    if errors:
                        matching = {o['method_id'] for o in obs}
                        if not seg.frames or not matching.intersection(seg.frames[-1]['methods']):
                            seg.reasons.add('exception_scope_not_proven')
                        if seg.frames:
                            seg.frames[-1]['error'] = True
                        seg.reasons.add('exceptional_transfer_source_boundary')
                        seg.states = set()
                        for method in matching:
                            exits = self.rows("SELECT n.id,p.position FROM flow_nodes n JOIN flow_points p ON p.node_id=n.id WHERE n.method_id=? AND p.kind='exit'", (method,))
                            seg.states.update((x['id'], x['position'], (), 0, True, True) for x in exits)
                        reached = matching
                    else:
                        following, reached = self.reach(seg, probe)
                        if following:
                            seg.states = following
                        else:
                            seg.reasons.add('source_observation_without_proven_cfg_chain')
                            seg.states = self.resume(obs, probe)
                    if reached:
                        compatible = [o for o in obs if o['method_id'] in reached]
                        if compatible:
                            obs = compatible
                    if starts:
                        seg.frames.append({'methods': {o['method_id'] for o in obs}, 'async': any(o['is_async'] for o in obs), 'error': False})
                        if len(seg.frames) > self.max_depth:
                            raise OverflowError('operation_depth_budget')
                    if any(o['is_async'] for o in obs):
                        seg.reasons.add('async_invocation_correlation_not_proven')
                    if any(o['status'] != 'modeled' for o in obs):
                        seg.reasons.add('opaque_observation')
                    if any(o['kind']=='operation_enter' and o['evidence']=='opaque' for o in obs):
                        seg.reasons.add('policy_opaque_component')
                    alternatives = [dict(kind=o['kind'], evidence=o['evidence'], method_id=o['method_id'],
                                         variant_id=o['variant_id'], signature=o['signature']) for o in obs]
                    seg.events.append({'probe_id': probe, 'line': line_number, 'timestamp': stamp,
                                       'alternatives': alternatives[:self.max_candidates],
                                       'unmapped_variant_candidates': unmapped[:self.max_candidates],
                                       'alternatives_truncated': len(alternatives) > self.max_candidates})
                    if len(seg.events) > self.max_states:
                        raise OverflowError('observation_buffer_budget')
                    owned = self.cache_bytes + sum(1024 + len(s.events)*1024 + len(s.states)*512 for s in streams.values())
                    self.peak_owned_bytes = max(self.peak_owned_bytes, owned)
                    if owned > self.memory_limit or len(streams) > min(1024, self.max_states):
                        raise OverflowError('global_buffer_budget')
                    if leaves:
                        matching = {o['method_id'] for o in obs}
                        if seg.frames and seg.frames[-1]['methods'].intersection(matching):
                            seg.frames.pop()
                        else:
                            seg.reasons.add('unbalanced_operation_leave')
                        if not seg.frames:
                            yield self.result(key, seg, line_number, terminal=True)
                            streams.pop(key, None)
                    elif not seg.frames:
                        yield self.result(key, seg, line_number)
                        streams.pop(key, None)
                    # Bound all streams, not merely each individual activation.
                except OverflowError as ex:
                    seg.reasons.add(str(ex))
                    yield self.result(key, seg, line_number, forced='budget_exceeded')
                    streams.pop(key, None)
                    while streams and self.cache_bytes + sum(1024 + len(s.events)*1024 + len(s.states)*512 for s in streams.values()) > self.memory_limit:
                        other_key, other = streams.popitem(last=False)
                        other.reasons.add('global_buffer_budget')
                        yield self.result(other_key, other, line_number, forced='budget_exceeded')
        for key, seg in streams.items():
            seg.reasons.add('log_ended_with_open_operation')
            yield self.result(key, seg, line_number)
        yield {'kind': 'summary', 'events_read': self.events_read, 'segments': self.segments_emitted,
               'peak_states': self.peak_states, 'peak_owned_buffer_estimate': self.peak_owned_bytes,
               'profile_id': self.reader.manifest['selection_profile_id'],
               'ordering': 'file order within correlation/thread; no global causal ordering inferred'}
