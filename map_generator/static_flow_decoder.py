"""Offline-only matching of statically qualified, ordered marker languages.

No recursion depth is expanded here: recursive/loop losses are explicit catalog facts.
Marker-language matches never prove method completion, event integrity or activation IDs.
"""
from collections import OrderedDict
import json
from pathlib import Path


class StaticFlowDecoder:
    def __init__(self, reader, build_manifest=None, max_states=100000, max_depth=32,
                 max_candidates=8, max_memory_mb=128, allow_unverified=False):
        if min(max_states, max_candidates, max_memory_mb) < 1:
            raise ValueError('Static decoder limits must be positive')
        self.reader = reader
        meta = reader.manifest
        if meta.get('schema_version') != '8' or meta.get('injection_contract') != 'static_probes_v1':
            raise ValueError('Static schema 8 catalog required')
        if build_manifest:
            manifest = json.loads(Path(build_manifest).read_text(encoding='utf-8-sig'))
            for field, key in [('profile_id', 'selection_profile_id'), ('input_fingerprint', 'fingerprint'),
                               ('policy_fingerprint', 'application_policy_fingerprint'), ('injection_contract', 'injection_contract'),
                               ('schema_version', 'schema_version')]:
                if str(manifest.get(field, '')) != str(meta.get(key, '')) or not str(meta.get(key, '')):
                    raise ValueError('Build manifest/catalog mismatch: ' + field)
            self.binding_status = 'verified'
        elif allow_unverified:
            self.binding_status = 'unverified'
        else:
            raise ValueError('Build manifest required; use --allow-unverified for exploration')
        self.max_states, self.max_candidates = max_states, max_candidates
        self.memory_limit = max_memory_mb * 1024 * 1024
        self.events_read = self.segments = 0
        self.cache = OrderedDict()
        self.local_streams = OrderedDict()

    def event(self, probe, line, stamp):
        if probe not in self.cache:
            rows = self.reader.rows('''SELECT DISTINCT m.id,m.variant_id,m.signature FROM methods m
                WHERE m.id IN (SELECT method_id FROM legacy_block_links WHERE legacy_id=?
                  UNION SELECT o.method_id FROM application_probe_bindings b JOIN application_observations o ON o.id=b.observation_id WHERE b.legacy_id=?)
                ORDER BY m.id LIMIT ?''', (probe, probe, self.max_candidates + 1))
            decision = self.reader.rows('SELECT enabled,reason,evidence FROM static_flow_decisions WHERE probe_id=?', (probe,))
            self.cache[probe] = rows, decision
            if len(self.cache) > 256:
                self.cache.popitem(last=False)
        rows, decision = self.cache[probe]
        alternatives = [dict(method_id=r['id'], variant_id=r['variant_id'], signature=r['signature'],
                             kind='constant_probe', evidence='source marker reached', observations=[], locations=[])
                        for r in rows[:self.max_candidates]]
        return {'probe_id': probe, 'line': line, 'timestamp': stamp, 'alternatives': alternatives,
                'alternatives_truncated': len(rows) > self.max_candidates, 'mapping_status': 'static_source_point',
                'selection_reason': decision[0]['reason'] if decision else 'unknown_probe',
                'enabled': bool(decision and decision[0]['enabled'])}

    def starts(self, probe, local=False):
        rows = self.reader.rows('''SELECT l.method_id,l.word_json,m.status,m.evidence FROM static_flow_languages l
            JOIN static_flow_methods m ON m.method_id=l.method_id WHERE l.first_probe=?
            AND (m.status LIKE 'qualified_intra_method%')=? ORDER BY l.method_id,l.word_json LIMIT ?''',
            (probe, int(local), self.max_states + 1))
        if len(rows) > self.max_states:
            return [], True
        # Bound materialized language text as well as the number of alternatives.
        if sum(len(r['word_json']) * 8 + 512 for r in rows) > self.memory_limit // 2:
            return [], True
        return [(r['method_id'], tuple(json.loads(r['word_json'])), 1, r['status']) for r in rows], False

    def local_result(self, key, lines, candidates, reason=None):
        return {'kind': 'static_local_path', 'trace_id': key[0], 'thread_id': key[1],
                'method_id': key[2], 'marker_lines': lines, 'first_line': lines[0], 'last_line': lines[-1],
                'status': 'incomplete' if reason else 'compatible', 'reason': reason,
                'matching_words': [list(w) for _, w, p, _ in candidates if p == len(w)][:self.max_candidates],
                'scope': 'own_method_projection', 'activation_identity': 'not_proven',
                'call_relations': 'not_inferred', 'binding_status': self.binding_status}

    def local_event(self, key, event):
        # Project by source ownership offline, never pair publishers with callbacks.
        # A repeated entry resets the projection: recursion/reentrancy is not flattened.
        if not event['enabled'] or event['alternatives_truncated']:
            yield from self.flush_local('unknown_or_ambiguous_probe')
            return
        starts, over = self.starts(event['probe_id'], local=True)
        if over:
            yield from self.flush_local('decoder_budget')
            return
        owners = {a['method_id'] for a in event['alternatives']}
        if len(owners) != 1:
            yield from self.flush_local('ambiguous_source_ownership')
            return
        method = next(iter(owners))
        stream_key = (*key, method)
        lines, candidates = self.local_streams.pop(stream_key, ([], []))
        new = [s for s in starts if s[0] == method]
        if new:
            if lines:
                yield self.local_result(stream_key, lines, candidates, 'repeated_entry_or_truncated_activation')
            lines, candidates = [event['line']], new
        elif lines:
            candidates = [(m, w, p + 1, s) for m, w, p, s in candidates if p < len(w) and w[p] == event['probe_id']]
            lines.append(event['line'])
            if not candidates:
                yield self.local_result(stream_key, lines, [], 'local_word_mismatch')
                return
        else:
            return
        complete = [s for s in candidates if s[2] == len(s[1])]
        if complete:
            yield self.local_result(stream_key, lines[:], complete)
        pending = [s for s in candidates if s[2] < len(s[1])]
        if pending:
            self.local_streams[stream_key] = lines, pending
        while self.local_streams and (len(self.local_streams) > 1024 or
                sum(len(ls)*32 + sum(len(w)*16+512 for _, w, _, _ in cs)
                    for ls, cs in self.local_streams.values()) > self.memory_limit // 2 or
                any(len(ls) > self.max_states for ls, _ in self.local_streams.values())):
            k, (ls, cs) = self.local_streams.popitem(last=False)
            yield self.local_result(k, ls, cs, 'decoder_budget')

    def flush_local(self, reason):
        for key, (lines, candidates) in self.local_streams.items():
            yield self.local_result(key, lines, candidates, reason)
        self.local_streams.clear()

    def result(self, key, events, candidates, reason=None):
        self.segments += 1
        complete = {(m, w, status) for m, w, position, status in candidates if position == len(w)}
        pending = any(position < len(w) for _, w, position, _ in candidates)
        status = 'budget_exceeded' if reason == 'decoder_budget' else 'incomplete' if reason or not complete else 'ambiguous'
        # Even one match establishes only compatibility with a normal-flow projection.
        # It does not establish a unique activation or rule out an exceptional suffix.
        return {'kind': 'static_segment', 'segment_id': 'static-' + str(self.segments), 'status': status,
                'binding_status': self.binding_status, 'trace_id': key[0], 'thread_id': key[1],
                'first_line': events[0]['line'], 'last_line': events[-1]['line'], 'closed': False,
                'reasons': [reason] if reason else ['activation_and_unobserved_suffix_not_proven'],
                'observations': [dict(e, event_index=i) for i, e in enumerate(events)], 'relations': [], 'operations': [],
                'matching_methods': sorted({m for m, _, _ in complete})[:self.max_candidates],
                'matching_methods_truncated': len({m for m, _, _ in complete}) > self.max_candidates,
                'longer_candidates_remain': pending, 'uniqueness_scope': 'declared_marker_language_compatibility',
                'technical_path_status': 'omitted_or_ambiguous',
                'iteration_count': None, 'recursion_depth': None,
                'losses': json.loads(self.reader.manifest.get('static_flow_summary', '{}')).get('losses', [])}

    def decode(self, log):
        streams = OrderedDict()
        with Path(log).open(encoding='utf-8-sig') as source:
            for line, raw in enumerate(source, 1):
                try:
                    stamp, trace, thread, token = raw.rstrip('\r\n').split('||')
                    if not stamp or not trace:
                        raise ValueError()
                    probe = int(token);int(thread)
                except ValueError:
                    yield from self.flush_local('malformed_record_gap')
                    for key, (events, candidates) in streams.items():
                        yield self.result(key, events, candidates, 'malformed_record_gap')
                    streams.clear()
                    yield {'kind': 'gap', 'status': 'incomplete', 'binding_status': self.binding_status,
                           'line': line, 'reason': 'malformed_record'}
                    continue
                self.events_read += 1
                key = trace, thread
                event = self.event(probe, line, stamp)
                yield from self.local_event(key, event)
                events, candidates = streams.pop(key, ([], []))
                advanced = [(m, w, position + 1, status) for m, w, position, status in candidates
                            if position < len(w) and w[position] == probe]
                if events and not advanced:
                    yield self.result(key, events, candidates)
                    events, candidates = [], []
                else:
                    candidates = advanced
                over = False
                if not events:
                    candidates, over = self.starts(probe)
                events.append(event)
                if not event['enabled'] or over:
                    yield self.result(key, events, candidates, 'unknown_or_disabled_probe' if not event['enabled'] else 'decoder_budget')
                    continue
                streams[key] = events, candidates
                while streams and (len(streams) > 1024 or sum(len(e)*4096 + sum(len(w)*16+512 for _, w, _, _ in c)
                       for e, c in streams.values()) > self.memory_limit or any(len(e) > self.max_states for e, _ in streams.values())):
                    oldest, (buffer, paths) = streams.popitem(last=False)
                    yield self.result(oldest, buffer, paths, 'decoder_budget')
        for key, (events, candidates) in streams.items():
            yield self.result(key, events, candidates)
        yield from self.flush_local('end_of_log')
        yield {'kind': 'summary', 'events_read': self.events_read, 'segments': self.segments,
               'binding_status': self.binding_status, 'profile_id': self.reader.manifest['selection_profile_id'],
               'ordering': 'file order within correlation/thread; activation identities unavailable'}
