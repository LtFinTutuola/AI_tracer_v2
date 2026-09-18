using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Microsoft.Build.Framework;
using Microsoft.Build.Utilities;
using Microsoft.Data.Sqlite;

namespace AITracer.MsBuildTask
{
    public class InjectTracesTask : Task
    {
        [Required]
        public ITaskItem[] Compile { get; set; }

        public string DatabasePath { get; set; }
        
        [Required]
        public string IntermediateOutputPath { get; set; }

        [Output]
        public ITaskItem[] ModifiedCompile { get; set; }

        public override bool Execute()
        {
            if (string.IsNullOrEmpty(DatabasePath) || !File.Exists(DatabasePath))
            {
                Log.LogMessage(MessageImportance.High, $"[AITracer] Database not found at '{DatabasePath}'. Skipping injection.");
                ModifiedCompile = Compile; // Return unmodified
                return true;
            }

            var blocksByFile = new Dictionary<string, List<BlockInfo>>(StringComparer.OrdinalIgnoreCase);

            try
            {
                using (var connection = new SqliteConnection($"Data Source={DatabasePath}"))
                {
                    connection.Open();
                    var cmd = connection.CreateCommand();
                    cmd.CommandText = "SELECT id, file_path, injection_line FROM basic_blocks WHERE to_trace = 1";
                    
                    using (var reader = cmd.ExecuteReader())
                    {
                        while (reader.Read())
                        {
                            var id = reader.GetInt32(0);
                            var filePath = reader.GetString(1);
                            var injectionLine = reader.GetInt32(2);

                            var normPath = Path.GetFullPath(filePath);
                            if (!blocksByFile.TryGetValue(normPath, out var list))
                            {
                                list = new List<BlockInfo>();
                                blocksByFile[normPath] = list;
                            }
                            list.Add(new BlockInfo { Id = id, InjectionLine = injectionLine });
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Log.LogErrorFromException(ex);
                return false;
            }

            var modifiedItems = new List<ITaskItem>();
            string genDir = Path.Combine(IntermediateOutputPath, "AI_Tracer_Gen");
            Directory.CreateDirectory(genDir);

            foreach (var item in Compile)
            {
                var fullPath = Path.GetFullPath(item.ItemSpec);
                if (blocksByFile.TryGetValue(fullPath, out var blocks))
                {
                    try
                    {
                        // Order descending to prevent line shifts
                        var sortedBlocks = blocks.OrderByDescending(b => b.InjectionLine).ToList();
                        var lines = File.ReadAllLines(fullPath).ToList();

                        foreach (var block in sortedBlocks)
                        {
                            // 1-based index to 0-based index. We insert at the line so it shifts the original line down.
                            int insertIdx = block.InjectionLine - 1;
                            
                            // Safety bounds
                            if (insertIdx < 0) insertIdx = 0;
                            if (insertIdx >= lines.Count) insertIdx = lines.Count - 1;

                            // Pragmatic MVP fix: avoid splitting try-catch, if-else etc.
                            string trimmed = lines[insertIdx].Trim();
                            if (trimmed.StartsWith("catch") || trimmed.StartsWith("finally") || trimmed.StartsWith("else") || trimmed.StartsWith("try"))
                            {
                                // Search forward for '{'
                                int scanIdx = insertIdx;
                                while (scanIdx < lines.Count && !lines[scanIdx].Contains("{"))
                                {
                                    scanIdx++;
                                }
                                if (scanIdx < lines.Count)
                                {
                                    insertIdx = scanIdx + 1; // Insert after '{'
                                }
                            }

                            var traceLines = new[]
                            {
                                "#line hidden",
                                $"AITracer.Runtime.TraceContext.Log({block.Id});",
                                "#line default"
                            };

                            lines.InsertRange(insertIdx, traceLines);
                        }

                        // Save to obj/AI_Tracer_Gen/
                        var fileName = Path.GetFileName(fullPath);
                        // Prefix with hash of directory to avoid collisions if files have same name
                        var hash = (fullPath.GetHashCode() & 0x7FFFFFFF).ToString("x");
                        var newPath = Path.Combine(genDir, $"{hash}_{fileName}");
                        
                        File.WriteAllLines(newPath, lines);

                        // Create a new task item pointing to the modified file
                        var newItem = new TaskItem(newPath);
                        item.CopyMetadataTo(newItem);
                        modifiedItems.Add(newItem);
                        
                        Log.LogMessage(MessageImportance.Normal, $"[AITracer] Injected traces in {fileName}");
                    }
                    catch (Exception ex)
                    {
                        Log.LogError($"[AITracer] Error processing {fullPath}: {ex.Message}");
                        modifiedItems.Add(item); // Fallback to original
                    }
                }
                else
                {
                    modifiedItems.Add(item); // Unmodified
                }
            }

            ModifiedCompile = modifiedItems.ToArray();
            return true;
        }

        private class BlockInfo
        {
            public int Id { get; set; }
            public int InjectionLine { get; set; }
        }
    }
}
