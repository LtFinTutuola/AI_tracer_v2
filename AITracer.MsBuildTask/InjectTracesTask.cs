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
                    
                    // Check if optional columns exist for backwards compatibility with older databases
                    bool hasWrapInBlock = false;
                    bool hasStatementEndOffset = false;
                    using (var colCmd = connection.CreateCommand())
                    {
                        colCmd.CommandText = "PRAGMA table_info(basic_blocks)";
                        using (var colReader = colCmd.ExecuteReader())
                        {
                            while (colReader.Read())
                            {
                                var colName = colReader.GetString(1);
                                if (string.Equals(colName, "wrap_in_block", StringComparison.OrdinalIgnoreCase)) hasWrapInBlock = true;
                                if (string.Equals(colName, "statement_end_offset", StringComparison.OrdinalIgnoreCase)) hasStatementEndOffset = true;
                            }
                        }
                    }

                    var query = "SELECT id, file_path, injection_line, injection_offset";
                    if (hasWrapInBlock) query += ", wrap_in_block";
                    else query += ", 0";
                    if (hasStatementEndOffset) query += ", statement_end_offset";
                    else query += ", 0";
                    query += " FROM basic_blocks WHERE to_trace = 1";

                    var cmd = connection.CreateCommand();
                    cmd.CommandText = query;
                    
                    using (var reader = cmd.ExecuteReader())
                    {
                        while (reader.Read())
                        {
                            var id = reader.GetInt32(0);
                            var filePath = reader.GetString(1);
                            var injectionLine = reader.GetInt32(2);
                            var injectionOffset = reader.GetInt32(3);
                            var wrapInBlock = reader.GetInt32(4) == 1;
                            var statementEndOffset = reader.GetInt32(5);

                            var normPath = Path.GetFullPath(filePath);
                            if (!blocksByFile.TryGetValue(normPath, out var list))
                            {
                                list = new List<BlockInfo>();
                                blocksByFile[normPath] = list;
                            }
                            list.Add(new BlockInfo 
                            { 
                                Id = id, 
                                InjectionLine = injectionLine, 
                                InjectionOffset = injectionOffset,
                                WrapInBlock = wrapInBlock,
                                StatementEndOffset = statementEndOffset
                            });
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
                        // Defensive deduplication: ensure only one trace call per injection offset in this file
                        var uniqueBlocks = new Dictionary<int, BlockInfo>();
                        foreach (var b in blocks)
                        {
                            if (!uniqueBlocks.ContainsKey(b.InjectionOffset))
                            {
                                uniqueBlocks[b.InjectionOffset] = b;
                            }
                        }

                        // Collect all textual insertions needed
                        var insertions = new List<TextInsertion>();
                        foreach (var block in uniqueBlocks.Values)
                        {
                            if (block.WrapInBlock && block.StatementEndOffset > block.InjectionOffset)
                            {
                                // Single-statement branch body (e.g. if (...) return true;) needing block wrapping
                                insertions.Add(new TextInsertion
                                {
                                    Offset = block.StatementEndOffset,
                                    Text = "\n}",
                                    IsEndWrapper = true
                                });
                                insertions.Add(new TextInsertion
                                {
                                    Offset = block.InjectionOffset,
                                    Text = $"{{\n#line hidden\nAITracer.Runtime.TraceContext.Log({block.Id});\n#line default\n",
                                    IsEndWrapper = false
                                });
                            }
                            else
                            {
                                insertions.Add(new TextInsertion
                                {
                                    Offset = block.InjectionOffset,
                                    Text = $"\n#line hidden\nAITracer.Runtime.TraceContext.Log({block.Id});\n#line default\n",
                                    IsEndWrapper = false
                                });
                            }
                        }

                        // Order descending by Offset to prevent shifting subsequent offsets
                        var sortedInsertions = insertions
                            .OrderByDescending(i => i.Offset)
                            .ThenBy(i => i.IsEndWrapper ? 0 : 1)
                            .ToList();

                        var text = File.ReadAllText(fullPath);

                        foreach (var ins in sortedInsertions)
                        {
                            if (ins.Offset >= 0 && ins.Offset <= text.Length)
                            {
                                text = text.Insert(ins.Offset, ins.Text);
                            }
                        }

                        // Add <auto-generated> header to bypass StyleCop/SonarQube strict rules on the generated file
                        text = "// <auto-generated/>\n" + text;

                        // Save to obj/AI_Tracer_Gen/
                        var fileName = Path.GetFileNameWithoutExtension(fullPath);
                        // Prefix with hash of directory to avoid collisions if files have same name
                        var hash = (fullPath.GetHashCode() & 0x7FFFFFFF).ToString("x");
                        var newPath = Path.Combine(genDir, $"{hash}_{fileName}.g.cs");
                        
                        File.WriteAllText(newPath, text);

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
            public int InjectionOffset { get; set; }
            public bool WrapInBlock { get; set; }
            public int StatementEndOffset { get; set; }
        }

        private class TextInsertion
        {
            public int Offset { get; set; }
            public string Text { get; set; }
            public bool IsEndWrapper { get; set; }
        }
    }
}
