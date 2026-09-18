import sqlite3
import argparse
import os
import sys
from collections import defaultdict
from datetime import datetime

def read_source_lines(file_path, start_line, end_line, source_root):
    """Legge le righe specifiche da un file sorgente."""
    # Prova a risolvere il percorso del file.
    # Se il file_path salvato in db è assoluto e la macchina è la stessa, funzionerà.
    # Altrimenti cerchiamo di risolverlo tramite source_root.
    
    target_path = file_path
    if not os.path.exists(target_path) and source_root:
        # Tenta un matching parziale (MVP semplice)
        file_name = os.path.basename(file_path)
        for root, _, files in os.walk(source_root):
            if file_name in files:
                candidate = os.path.join(root, file_name)
                # Verifica rudimentale: se la fine del path coincide
                if candidate.replace('\\', '/').endswith(file_path.replace('\\', '/').split('/')[-1]):
                    target_path = candidate
                    break

    if not os.path.exists(target_path):
        return f"// [Errore] File sorgente non trovato: {file_path}"

    try:
        with open(target_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
            
            # Line array è 0-indexed, start_line è 1-indexed
            s_idx = max(0, start_line - 1)
            e_idx = min(len(lines), end_line)
            
            extracted = lines[s_idx:e_idx]
            return "".join(extracted)
    except Exception as e:
        return f"// [Errore] Impossibile leggere {file_path}: {str(e)}"

def main():
    parser = argparse.ArgumentParser(description="AI Tracer - Reconciler")
    parser.add_argument("--log", required=True, help="Percorso del file .log")
    parser.add_argument("--db", required=True, help="Percorso del database basic_blocks.sqlite")
    parser.add_argument("--source-root", required=False, help="Directory radice dei sorgenti (opzionale se percorsi DB sono assoluti e validi)")
    parser.add_argument("--output", required=True, help="Percorso del file Markdown di output")
    
    args = parser.parse_args()

    if not os.path.exists(args.log):
        print(f"Errore: Log file non trovato in {args.log}")
        sys.exit(1)
        
    if not os.path.exists(args.db):
        print(f"Errore: DB file non trovato in {args.db}")
        sys.exit(1)

    print("Analisi file di log...")
    
    # dict: trace_id -> list of (timestamp, thread_id, block_id)
    flows = defaultdict(list)
    
    with open(args.log, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            parts = line.split("||")
            if len(parts) >= 4:
                ts_str, trace_id, thread_id, block_id_str = parts[0], parts[1], parts[2], parts[3]
                try:
                    block_id = int(block_id_str)
                    ts = datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
                    flows[trace_id].append((ts, thread_id, block_id))
                except ValueError:
                    continue

    print(f"Trovati {len(flows)} flussi unici.")
    
    print("Connessione al database SQLite...")
    conn = sqlite3.connect(args.db)
    cursor = conn.cursor()

    # Creazione Markdown
    with open(args.output, 'w', encoding='utf-8') as out_f:
        out_f.write("# AI Tracer - Report Esecuzione\n\n")
        out_f.write(f"Generato il: {datetime.now().isoformat()}\n\n")
        
        for trace_id, entries in flows.items():
            out_f.write(f"## Flusso: `{trace_id}`\n")
            out_f.write(f"Numero di eventi: {len(entries)}\n\n")
            
            # Ordina per timestamp
            entries.sort(key=lambda x: x[0])
            
            for idx, (ts, thread_id, block_id) in enumerate(entries):
                cursor.execute("SELECT file_path, method_signature, scope_start_line, scope_end_line, reason FROM basic_blocks WHERE id = ?", (block_id,))
                row = cursor.fetchone()
                
                if not row:
                    out_f.write(f"### [Step {idx+1}] BlockID: {block_id} (Dati non trovati nel DB)\n")
                    out_f.write(f"**Timestamp**: {ts.isoformat()} | **Thread**: {thread_id}\n\n")
                    continue
                
                file_path, method_signature, scope_start, scope_end, reason = row
                
                out_f.write(f"### [Step {idx+1}] `{method_signature}`\n")
                out_f.write(f"- **Motivazione Block**: {reason}\n")
                out_f.write(f"- **File**: `{os.path.basename(file_path)}` (Linee {scope_start}-{scope_end})\n")
                out_f.write(f"- **Timestamp**: {ts.isoformat()} | **Thread**: {thread_id}\n\n")
                
                code_snippet = read_source_lines(file_path, scope_start, scope_end, args.source_root)
                
                out_f.write("```csharp\n")
                out_f.write(code_snippet.strip() + "\n")
                out_f.write("```\n\n")
            
            out_f.write("---\n\n")

    conn.close()
    print(f"Riconciliazione completata. File generato in {args.output}")

if __name__ == "__main__":
    main()
