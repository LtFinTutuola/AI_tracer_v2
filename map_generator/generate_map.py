import sqlite3
import os
import yaml
import glob
import sys

def get_latest_log_file(working_dir):
    search_pattern = os.path.join(working_dir, '*.log')
    log_files = glob.glob(search_pattern)
    if not log_files:
        return None
    return max(log_files, key=os.path.getmtime)

config_path = os.path.join(os.path.dirname(__file__), 'config.yaml')
with open(config_path, 'r', encoding='utf-8') as f:
    config = yaml.safe_load(f)

working_folder = config.get('working_folder', 'default')
target_solution = config.get('target_solution')

repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
out_dir = os.path.join(repo_root, 'code_analysis', working_folder)

# Find sqlite database in working folder
sqlite_files = glob.glob(os.path.join(out_dir, '*.sqlite'))
DB_PATH = sqlite_files[0] if sqlite_files else os.path.join(out_dir, 'basic_blocks.sqlite')

LOG_PATH = get_latest_log_file(out_dir)
OUTPUT_PATH = os.path.join(out_dir, "execution_map.md")

def load_basic_blocks(db_path):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT id, project_name, file_path, method_signature, scope_start_line, scope_end_line, block_start_line, block_end_line, injection_line, reason FROM basic_blocks")
    blocks = {}
    for row in cursor.fetchall():
        blocks[str(row[0])] = {
            'project_name': row[1],
            'file_path': row[2],
            'method_signature': row[3],
            'scope_start_line': row[4],
            'scope_end_line': row[5],
            'block_start_line': row[6],
            'block_end_line': row[7],
            'injection_line': row[8],
            'reason': row[9]
        }
    conn.close()
    return blocks

def read_file_lines(file_path, file_cache):
    if file_path not in file_cache:
        try:
            with open(file_path, 'r', encoding='utf-8-sig') as f:
                file_cache[file_path] = f.readlines()
        except Exception as e:
            file_cache[file_path] = []
            print(f"Error reading file {file_path}: {e}")
    return file_cache[file_path]

def get_unexecuted_blocks(db_path, file_path, method_signature, executed_block_ids):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, block_start_line, block_end_line 
        FROM basic_blocks 
        WHERE file_path = ? AND method_signature = ?
    """, (file_path, method_signature))
    
    unexecuted = []
    for row in cursor.fetchall():
        block_id = str(row[0])
        if block_id not in executed_block_ids:
            unexecuted.append({
                'id': block_id,
                'block_start_line': row[1],
                'block_end_line': row[2]
            })
    conn.close()
    return unexecuted

def expand_implicit_blocks(db_path, file_path, method_signature, executed_block_ids):
    if not executed_block_ids:
        return executed_block_ids
        
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    placeholders = ','.join('?' * len(executed_block_ids))
    cursor.execute(f"SELECT block_start_line, block_end_line FROM basic_blocks WHERE id IN ({placeholders})", executed_block_ids)
    executed_ranges = cursor.fetchall()
    
    expanded_set = set(executed_block_ids)
    
    cursor.execute("SELECT id, block_start_line, block_end_line FROM basic_blocks WHERE file_path = ? AND method_signature = ?", (file_path, method_signature))
    all_blocks = cursor.fetchall()
    
    for b_id, b_start, b_end in all_blocks:
        b_id_str = str(b_id)
        if b_id_str in expanded_set:
            continue
            
        # Se il blocco padre contiene il blocco eseguito, è implicitamente eseguito
        for ex_start, ex_end in executed_ranges:
            if b_start <= ex_start and b_end >= ex_end:
                expanded_set.add(b_id_str)
                break
                
    conn.close()
    return list(expanded_set)

def format_scope_output(file_path, method_signature, executed_block_ids, blocks, file_cache, db_path):
    expanded_executed_ids = expand_implicit_blocks(db_path, file_path, method_signature, executed_block_ids)
    unexecuted_blocks = get_unexecuted_blocks(db_path, file_path, method_signature, expanded_executed_ids)
    
    first_block_id = executed_block_ids[0]
    scope_start = blocks[first_block_id]['scope_start_line']
    scope_end = blocks[first_block_id]['scope_end_line']
    
    last_block_id = executed_block_ids[-1]
    last_executed_block_end = blocks[last_block_id]['block_end_line']
    
    source_lines = read_file_lines(file_path, file_cache)
    output_lines = []
    
    emptied_lines = set()
    for u_block in unexecuted_blocks:
        b_start = u_block['block_start_line']
        b_end = u_block['block_end_line']
        for i in range(b_start, b_end - 1):
            emptied_lines.add(i + 1)

    truncated = False
    
    for line_num in range(scope_start, scope_end + 1):
        if line_num > last_executed_block_end and line_num < scope_end:
            if not truncated:
                output_lines.append(f" ... | // [Truncated: Code after last executed block]")
                truncated = True
            continue
            
        if line_num in emptied_lines:
            continue
            
        idx = line_num - 1
        if 0 <= idx < len(source_lines):
            marker = ""
            for eb_id in executed_block_ids:
                if blocks[eb_id]['block_start_line'] == line_num or blocks[eb_id]['injection_line'] == line_num:
                    marker = f" // <--- [EXECUTED: Block {eb_id}]"
                    break
            
            output_lines.append(f"{line_num:4d} | {source_lines[idx].rstrip()}{marker}")

    return "\n".join(output_lines) + "\n"

class ScopeNode:
    def __init__(self, file_path, method_signature, timestamp, correlation_id, thread_id):
        self.file_path = file_path
        self.method_signature = method_signature
        self.timestamp = timestamp
        self.correlation_id = correlation_id
        self.thread_id = thread_id
        self.executed_block_ids = []

    def __eq__(self, other):
        if not isinstance(other, ScopeNode):
            return False
        return (self.file_path == other.file_path and 
                self.method_signature == other.method_signature and 
                self.executed_block_ids == other.executed_block_ids)

class LoopNode:
    def __init__(self, sequence, iterations):
        self.sequence = sequence
        self.iterations = iterations

def compress_stream(nodes):
    MAX_PATTERN_LENGTH = 10
    compressed = []
    i = 0
    n = len(nodes)
    while i < n:
        match_found = False
        max_len = min(MAX_PATTERN_LENGTH, (n - i) // 2)
        for L in range(max_len, 0, -1):
            pattern = nodes[i:i+L]
            next_pattern = nodes[i+L:i+2*L]
            if pattern == next_pattern:
                iterations = 2
                k = i + 2*L
                while k + L <= n and nodes[k:k+L] == pattern:
                    iterations += 1
                    k += L
                compressed.append(LoopNode(pattern, iterations))
                i = k
                match_found = True
                break
        
        if not match_found:
            compressed.append(nodes[i])
            i += 1
            
    return compressed

def render_scope(scope, blocks, file_cache, db_path, out, indent=""):
    out.write(f"{indent}---\n\n")
    out.write(f"{indent}### ⏱️ [{scope.timestamp}] CONTEXT SWITCH\n")
    out.write(f"{indent}- **File:** `{scope.file_path}`\n")
    out.write(f"{indent}- **Method:** `{scope.method_signature}`\n")
    out.write(f"{indent}- **Thread ID:** {scope.thread_id} | **Correlation ID:** `{scope.correlation_id}`\n")
    out.write(f"{indent}- **Executed Blocks:** {', '.join(scope.executed_block_ids)}\n\n")
    
    formatted_scope = format_scope_output(scope.file_path, scope.method_signature, scope.executed_block_ids, blocks, file_cache, db_path)
    
    out.write(f"{indent}```csharp\n")
    for line in formatted_scope.splitlines():
        out.write(f"{indent}{line}\n")
    out.write(f"{indent}```\n\n")

def render_node(node, blocks, file_cache, db_path, out, indent=""):
    if isinstance(node, ScopeNode):
        render_scope(node, blocks, file_cache, db_path, out, indent)
    elif isinstance(node, LoopNode):
        out.write(f"\n{indent}> 🔁 **[LOOP DETECTED] Eseguito per {node.iterations} iterazioni**\n")
        out.write(f"{indent}>\n")
        for sub_node in node.sequence:
            render_node(sub_node, blocks, file_cache, db_path, out, indent + "> ")

def generate_map():
    if LOG_PATH is None:
        print(f"Error: No log file found in the working folder: {out_dir}")
        return
        
    blocks = load_basic_blocks(DB_PATH)
    file_cache = {}
    
    with open(LOG_PATH, 'r', encoding='utf-8') as f:
        log_lines = [line.strip() for line in f if line.strip()]
    
    thread_streams = {}
    
    for idx, line in enumerate(log_lines):
        parts = line.split("||")
        if len(parts) < 4:
            continue
        
        timestamp = parts[0]
        correlation_id = parts[1]
        thread_id = parts[2]
        block_id = parts[3]
        
        if block_id not in blocks:
            print(f"[!] Block ID {block_id} not found in database.")
            continue
            
        block = blocks[block_id]
        file_path = block['file_path']
        method_signature = block['method_signature']
        
        if thread_id not in thread_streams:
            thread_streams[thread_id] = []
            
        stream = thread_streams[thread_id]
        
        if stream and isinstance(stream[-1], ScopeNode) and stream[-1].file_path == file_path and stream[-1].method_signature == method_signature:
            stream[-1].executed_block_ids.append(block_id)
        else:
            new_scope = ScopeNode(file_path, method_signature, timestamp, correlation_id, thread_id)
            new_scope.executed_block_ids.append(block_id)
            stream.append(new_scope)

    with open(OUTPUT_PATH, 'w', encoding='utf-8') as out:
        out.write("# AI Tracer - Execution Map\n\n")
        out.write(f"**Generated from:** `{LOG_PATH}`\n\n")
        
        for thread_id, stream in thread_streams.items():
            out.write(f"## Thread ID: {thread_id}\n\n")
            compressed_stream = compress_stream(stream)
            for node in compressed_stream:
                render_node(node, blocks, file_cache, DB_PATH, out)
            out.write("\n---\n\n")

if __name__ == "__main__":
    generate_map()
    print(f"Map generated successfully at {OUTPUT_PATH}")
