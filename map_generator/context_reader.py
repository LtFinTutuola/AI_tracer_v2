"""Read-only schema 3/4 queries. Expansion is bounded and selection remains visible."""
import argparse
from collections import OrderedDict, deque
import json
from pathlib import Path
import sqlite3


class BlockContextReader:
    def __init__(self, database):
        self.connection = sqlite3.connect(Path(database).resolve().as_uri() + '?mode=ro', uri=True)
        self.connection.row_factory = sqlite3.Row
        self.cache = OrderedDict()
        try:
            self.manifest = dict(self.connection.execute('SELECT key,value FROM analysis_manifest'))
            if self.manifest.get('schema_version') not in ('3', '4') or self.manifest.get('state') != 'validated':
                raise ValueError('Schema 3 or 4 validated catalog required; regenerate the database')
        except Exception:
            self.connection.close()
            raise

    def close(self):
        self.cache.clear()
        self.connection.close()

    def rows(self, sql, parameters=()):
        return [dict(r) for r in self.connection.execute(sql, parameters)]

    def _cached(self, sql, parameters=()):
        key = sql, parameters
        if key in self.cache:
            self.cache.move_to_end(key)
            return self.cache[key]
        result = self.rows(sql, parameters)
        self.cache[key] = result
        if len(self.cache) > 512:
            self.cache.popitem(last=False)
        return result

    def _method_incomplete(self, method_id):
        return bool(self._cached('''SELECT d.id FROM analysis_diagnostics d WHERE d.scope=? OR
                                    d.scope=(SELECT 'document:'||document_id FROM methods WHERE id=?) LIMIT 1''',
                                 ('method:' + str(method_id), method_id)))

    @staticmethod
    def _page(limit, offset):
        if not 1 <= limit <= 1000 or offset < 0:
            raise ValueError('limit must be 1..1000; offset must be nonnegative')

    def get_block_context(self, legacy_id):
        legacy = self.rows('SELECT * FROM basic_blocks WHERE id=?', (legacy_id,))
        if not legacy:
            raise KeyError(legacy_id)
        links = self.rows('''SELECT l.*,p.node_id,p.position FROM legacy_block_links l
                             LEFT JOIN flow_points p ON p.id=l.point_id WHERE l.legacy_id=?''', (legacy_id,))
        methods = []
        for method_id in dict.fromkeys(link['method_id'] for link in links):
            methods += self.rows('SELECT * FROM methods WHERE id=?', (method_id,))
        selected = self.rows('''SELECT v.id,v.stable_key,v.name,v.path FROM legacy_probe_variants s
                                JOIN project_variants v ON v.id=s.variant_id WHERE s.legacy_id=? ORDER BY v.id''', (legacy_id,))
        unselected = self.rows('''SELECT DISTINCT v.id,v.stable_key,v.name,v.path FROM documents d
                                  JOIN project_variants v ON v.id=d.variant_id
                                  WHERE d.origin='source' AND d.path=? COLLATE NOCASE
                                    AND NOT EXISTS(SELECT 1 FROM legacy_probe_variants s WHERE s.legacy_id=? AND s.variant_id=v.id)
                                  ORDER BY v.id''', (legacy[0]['file_path'], legacy_id))
        selection = None
        if self.manifest.get('schema_version') == '4':
            decisions = self.rows('''SELECT d.enabled,d.reason,d.profile_id,p.status,p.options_json,p.metrics_json
                FROM trace_selection_decisions d JOIN trace_selection_profiles p ON p.id=d.profile_id
                WHERE d.legacy_id=?''', (legacy_id,))
            if decisions:
                selection = decisions[0]
                selection['enabled'] = bool(selection['enabled'])
                selection['options'] = json.loads(selection.pop('options_json'))
                selection['metrics'] = json.loads(selection.pop('metrics_json'))
        return {'manifest': self.manifest, 'legacy': legacy[0], 'mapping': links, 'methods': methods,
                'trace_enabled': bool(legacy[0].get('to_trace', 1)), 'trace_selection': selection,
                'selected_by': selected, 'compiled_by_without_selection': unselected,
                'diagnostics': self.rows('SELECT * FROM analysis_diagnostics WHERE scope=?', ('legacy:' + str(legacy_id),))}

    def get_local_flow(self, method_id, limit=1000, offset=0):
        self._page(limit, offset)
        nodes = self.rows('SELECT * FROM flow_nodes WHERE method_id=? ORDER BY ordinal LIMIT ? OFFSET ?',
                          (method_id, limit + 1, offset))
        more = len(nodes) > limit
        nodes = nodes[:limit]
        return {'nodes': nodes, 'edges': [edge for node in nodes for edge in
                self.rows('SELECT * FROM flow_edges WHERE source_id=? ORDER BY id', (node['id'],))],
                'points': [point for node in nodes for point in
                self.rows('SELECT * FROM flow_points WHERE node_id=? ORDER BY position', (node['id'],))],
                'has_more': more}

    def get_callees(self, method_id, limit=1000, offset=0):
        self._page(limit, offset)
        return self.rows('''SELECT s.*,t.method_id AS target_method_id,t.evidence FROM call_sites s
                            LEFT JOIN call_targets t ON t.site_id=s.id WHERE s.method_id=?
                            ORDER BY s.id,t.method_id LIMIT ? OFFSET ?''', (method_id, limit, offset))

    def get_callers(self, method_id, limit=1000, offset=0):
        self._page(limit, offset)
        return self.rows('''SELECT s.*,t.evidence FROM call_targets t JOIN call_sites s ON s.id=t.site_id
                            WHERE t.method_id=? ORDER BY s.id LIMIT ? OFFSET ?''', (method_id, limit, offset))

    def get_reachable_subgraph(self, root_method_id, budget=100000):
        if budget < 1:
            raise ValueError('budget must be positive')
        queue, seen, methods, calls, spent = deque([root_method_id]), set(), [], [], 0
        incomplete = False
        while queue:
            method = queue.popleft()
            if method in seen:
                continue
            if spent >= budget:
                return {'status': 'budget_exceeded', 'methods': methods, 'calls': calls}
            seen.add(method)
            found = self.rows('SELECT * FROM methods WHERE id=?', (method,))
            if not found:
                raise KeyError(method)
            methods += found
            incomplete |= found[0]['status'] != 'analyzed' or self._method_incomplete(method)
            spent += 1
            offset = 0
            while True:
                page = self.get_callees(method, min(1000, max(1, budget-spent)), offset)
                if not page:
                    break
                if spent + len(page) > budget:
                    return {'status': 'budget_exceeded', 'methods': methods, 'calls': calls}
                calls += page
                spent += len(page)
                for call in page:
                    incomplete |= call['resolution'] != 'static' or call['target_method_id'] is None
                    if call['target_method_id'] is not None:
                        queue.append(call['target_method_id'])
                offset += len(page)
                if spent >= budget:
                    return {'status': 'budget_exceeded', 'methods': methods, 'calls': calls}
        return {'status': 'incomplete' if incomplete else 'complete', 'methods': methods, 'calls': calls}

    def explain_context(self, root_method_id, legacy_id, budget=100000, max_depth=32):
        """One candidate prefix to a legacy point, never a runtime proof or all paths."""
        if budget < 1 or max_depth < 1:
            raise ValueError('positive budget/depth required')
        context = self.get_block_context(legacy_id)
        targets = {link['point_id'] for link in context['mapping'] if link['point_id'] is not None}
        if not targets:
            return {'status': 'incomplete', 'witness': None, 'reason': 'unmapped_legacy_point'}
        entries = self._cached("SELECT id FROM flow_nodes WHERE method_id=? AND kind='Entry'", (root_method_id,))
        if not entries:
            if self.rows('SELECT id FROM methods WHERE id=?', (root_method_id,)):
                return {'status': 'incomplete', 'witness': None, 'reason': 'root_body_unavailable'}
            raise KeyError(root_method_id)
        # State includes the actual call-site continuation stack and uncertainty.
        start = (entries[0]['id'], 0, (), self._method_incomplete(root_method_id) or bool(context['diagnostics']))
        queue, previous = deque([start]), {start: None}
        incomplete, depth_limited, unselected_reached, unmapped_reached = start[3], False, False, False
        source_path = context['legacy']['file_path']
        while queue:
            state = queue.popleft()
            node, position, stack, uncertain = state
            # A union probe is inserted into every compilation of its physical
            # file. A variant that did not select it has no defensible CFG point.
            unselected_here = bool(self._cached('''SELECT n.id FROM flow_nodes n
                JOIN methods m ON m.id=n.method_id JOIN documents d ON d.id=m.document_id
                WHERE n.id=? AND d.path=? COLLATE NOCASE AND d.origin='source'
                  AND NOT EXISTS(SELECT 1 FROM legacy_probe_variants v
                    WHERE v.legacy_id=? AND v.variant_id=m.variant_id) LIMIT 1''',
                (node, source_path, legacy_id)))
            unmapped_here = bool(self._cached('''SELECT n.id FROM flow_nodes n
                JOIN methods m ON m.id=n.method_id JOIN documents d ON d.id=m.document_id
                WHERE n.id=? AND d.path=? COLLATE NOCASE AND d.origin='source'
                  AND EXISTS(SELECT 1 FROM legacy_probe_variants v
                    WHERE v.legacy_id=? AND v.variant_id=m.variant_id)
                  AND NOT EXISTS(SELECT 1 FROM legacy_block_links l
                    JOIN methods lm ON lm.id=l.method_id
                    WHERE l.legacy_id=? AND lm.variant_id=m.variant_id AND l.point_id IS NOT NULL)
                LIMIT 1''', (node, source_path, legacy_id, legacy_id)))
            incomplete |= unselected_here or unmapped_here
            unselected_reached |= unselected_here
            unmapped_reached |= unmapped_here
            uncertain |= unselected_here or unmapped_here
            points = self._cached('SELECT * FROM flow_points WHERE node_id=? ORDER BY position', (node,))
            point = next((p for p in points if p['position'] >= position), None)
            transitions = []
            if point is not None:
                if point['id'] in targets:
                    witness, cursor = [], state
                    while previous[cursor] is not None:
                        cursor, event = previous[cursor]
                        witness.append(event)
                    return {'status': 'found', 'evidence': 'candidate', 'model_incomplete': uncertain,
                            'witness': list(reversed(witness)), 'point_id': point['id']}
                next_position = point['position'] + 1
                if point['kind'] == 'incomplete':
                    incomplete = True
                    continue
                if point['kind'] == 'call':
                    call = self._cached('SELECT * FROM call_sites WHERE point_id=?', (point['id'],))[0]
                    known = self._cached('SELECT * FROM call_targets WHERE site_id=? ORDER BY method_id', (call['id'],))
                    open_call = call['resolution'] != 'static' or len(known) != 1
                    for target in known:
                        if len(stack) >= max_depth:
                            depth_limited = True
                            continue
                        entry = self._cached("SELECT id FROM flow_nodes WHERE method_id=? AND kind='Entry'", (target['method_id'],))
                        if not entry:
                            incomplete = True
                            continue
                        frame = (node, call['continuation_position'], call['id'])
                        target_incomplete = self._method_incomplete(target['method_id'])
                        incomplete |= target_incomplete
                        transitions.append(((entry[0]['id'], 0, stack + (frame,), uncertain or open_call or target_incomplete),
                                            {'call': call['id'], 'target': target['method_id'], 'evidence': target['evidence']}))
                    if open_call or not known:
                        incomplete = True
                        transitions.append(((node, call['continuation_position'], stack, True),
                                            {'unknown_return': call['id'], 'resolution': call['resolution']}))
                elif point['kind'] == 'exit':
                    if stack:
                        caller, continuation, site = stack[-1]
                        transitions.append(((caller, continuation, stack[:-1], uncertain), {'return': site}))
                else:
                    transitions.append(((node, next_position, stack, uncertain), {'point': point['id'], 'kind': point['kind']}))
            else:
                for edge in self._cached('SELECT * FROM flow_edges WHERE source_id=? ORDER BY id', (node,)):
                    if edge['status'] != 'modeled':
                        incomplete = True
                        continue
                    if edge['target_id'] is not None:
                        transitions.append(((edge['target_id'], 0, stack, uncertain),
                                            {'edge': edge['id'], 'alternative': edge['alternative'], 'semantics': edge['semantics']}))
            for following, event in transitions:
                if following not in previous:
                    if len(previous) >= budget:
                        return {'status': 'budget_exceeded', 'witness': None}
                    previous[following] = state, event
                    queue.append(following)
        return {'status': 'depth_exceeded' if depth_limited else 'incomplete' if incomplete else 'not_found',
                'witness': None, 'reason': 'probe_not_selected_for_reachable_variant' if incomplete and not depth_limited and
                unselected_reached else 'probe_unmapped_in_reachable_variant' if incomplete and not depth_limited and
                unmapped_reached else None, 'evidence': 'static_model'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('database')
    parser.add_argument('block_id', type=int)
    parser.add_argument('--markdown', action='store_true')
    parser.add_argument('--root', type=int)
    args = parser.parse_args()
    reader = BlockContextReader(args.database)
    try:
        result = reader.get_block_context(args.block_id) if args.root is None else reader.explain_context(args.root, args.block_id)
        value = json.dumps(result, ensure_ascii=False, indent=2)
        print('```json\n' + value + '\n```' if args.markdown else value)
    finally:
        reader.close()


if __name__ == '__main__':
    main()
