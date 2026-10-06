import sqlite3
import os

DB_PATH = r"c:\repo\AI_tracer_v2\code_analysis\basic_blocks_frontend_8.2.sqlite"
LOG_PATH = r"c:\repo\AI_tracer_v2\code_analysis\aitracer_runtime_8.2.log"
OUTPUT_PATH = r"c:\repo\AI_tracer_v2\code_analysis\execution_map_8.2.md"

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

def format_scope_output(file_path, method_signature, executed_block_ids, blocks, file_cache, db_path):
    unexecuted_blocks = get_unexecuted_blocks(db_path, file_path, method_signature, executed_block_ids)
    
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

def generate_map():
    blocks = load_basic_blocks(DB_PATH)
    file_cache = {}
    
    with open(LOG_PATH, 'r', encoding='utf-8') as f:
        log_lines = [line.strip() for line in f if line.strip()]
    
    grouped_scopes = []
    
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
        
        if grouped_scopes and grouped_scopes[-1][0] == file_path and grouped_scopes[-1][1] == method_signature:
            grouped_scopes[-1][5].append(block_id)
        else:
            grouped_scopes.append((file_path, method_signature, timestamp, correlation_id, thread_id, [block_id]))

    with open(OUTPUT_PATH, 'w', encoding='utf-8') as out:
        out.write("# AI Tracer - Execution Map\n\n")
        out.write(f"**Generated from:** `{LOG_PATH}`\n\n")
        
        for group in grouped_scopes:
            file_path, method_signature, timestamp, correlation_id, thread_id, executed_block_ids = group
            
            out.write("---\n\n")
            out.write(f"### ⏱️ [{timestamp}] CONTEXT SWITCH\n")
            out.write(f"- **File:** `{file_path}`\n")
            out.write(f"- **Method:** `{method_signature}`\n")
            out.write(f"- **Thread ID:** {thread_id} | **Correlation ID:** `{correlation_id}`\n")
            out.write(f"- **Executed Blocks:** {', '.join(executed_block_ids)}\n\n")
            
            formatted_scope = format_scope_output(file_path, method_signature, executed_block_ids, blocks, file_cache, DB_PATH)
            
            out.write("```csharp\n")
            out.write(formatted_scope)
            out.write("```\n\n")

if __name__ == "__main__":
    generate_map()
    print(f"Map generated successfully at {OUTPUT_PATH}")
