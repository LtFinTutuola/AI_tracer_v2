import sqlite3
import os

DB_PATH = r"c:\repo\AI_tracer_v2\code_analysis\basic_blocks.sqlite"
LOG_PATH = r"c:\repo\AI_tracer_v2\code_analysis\aitracer_runtime.log"
OUTPUT_PATH = r"c:\repo\AI_tracer_v2\code_analysis\execution_map.txt"

def load_basic_blocks(db_path):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT id, project_name, file_path, method_signature, scope_start_line, scope_end_line, injection_line, reason FROM basic_blocks")
    blocks = {}
    for row in cursor.fetchall():
        blocks[str(row[0])] = {
            'project_name': row[1],
            'file_path': row[2],
            'method_signature': row[3],
            'scope_start_line': row[4],
            'scope_end_line': row[5],
            'injection_line': row[6],
            'reason': row[7]
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

def generate_map():
    blocks = load_basic_blocks(DB_PATH)
    file_cache = {}
    
    with open(LOG_PATH, 'r', encoding='utf-8') as f:
        log_lines = [line.strip() for line in f if line.strip()]
    
    with open(OUTPUT_PATH, 'w', encoding='utf-8') as out:
        out.write("=== EXECUTION MAP ===\n")
        out.write(f"Generated from: {LOG_PATH}\n\n")
        
        last_file = None
        last_method = None
        last_end_line = None
        
        for idx, line in enumerate(log_lines):
            parts = line.split("||")
            if len(parts) < 4:
                continue
            
            timestamp = parts[0]
            correlation_id = parts[1]
            thread_id = parts[2]
            block_id = parts[3]
            
            if block_id not in blocks:
                out.write(f"\n[!] Block ID {block_id} not found in database.\n")
                continue
                
            block = blocks[block_id]
            file_path = block['file_path']
            method_signature = block['method_signature']
            start_line = block['scope_start_line']
            end_line = block['scope_end_line']
            reason = block['reason']
            
            is_jump = False
            jump_desc = ""
            if file_path != last_file or method_signature != last_method:
                is_jump = True
                jump_desc = f"CONTEXT SWITCH to {method_signature}"
            elif last_end_line is not None and start_line != last_end_line + 1:
                is_jump = True
                if start_line > last_end_line:
                    jump_desc = f"FORWARD JUMP (+{start_line - last_end_line} lines) due to {reason}"
                else:
                    jump_desc = f"BACKWARD/BRANCH JUMP ({start_line - last_end_line} lines) due to {reason}"
            
            if is_jump or idx == 0:
                out.write("\n" + "="*80 + "\n")
                out.write(f"[{timestamp}] {jump_desc if is_jump else 'EXECUTION START'}\n")
                out.write(f"File: {file_path}\n")
                out.write(f"Method: {method_signature}\n")
                out.write(f"Thread ID: {thread_id} | Correlation ID: {correlation_id}\n")
                out.write("="*80 + "\n")
            
            source_lines = read_file_lines(file_path, file_cache)
            out.write(f"--- Block ID: {block_id} | Reason: {reason} | Lines: {start_line}-{end_line} ---\n")
            
            for i in range(start_line - 1, end_line):
                if 0 <= i < len(source_lines):
                    out.write(f"{i + 1:4d} | {source_lines[i].rstrip()}\n")
            
            last_file = file_path
            last_method = method_signature
            last_end_line = end_line

if __name__ == "__main__":
    generate_map()
    print(f"Map generated successfully at {OUTPUT_PATH}")
