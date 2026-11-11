using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;
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

        [Output]
        public string ProfileManifest { get; set; }

        public override bool Execute()
        {
            if (string.IsNullOrEmpty(DatabasePath) || !File.Exists(DatabasePath))
            {
                Log.LogMessage(MessageImportance.High, $"[AITracer] Database not found at '{DatabasePath}'. Skipping injection.");
                ModifiedCompile = Compile; // Return unmodified
                return true;
            }

            var blocksByFile = new Dictionary<string, List<BlockInfo>>(StringComparer.OrdinalIgnoreCase);
            var applicationEdits = new Dictionary<string,List<ApplicationEdit>>(StringComparer.OrdinalIgnoreCase);
            var applicationHashes = new Dictionary<string,string>(StringComparer.OrdinalIgnoreCase);
            var placedIds = new HashSet<int>();
            ProfileInfo profile = null;

            try
            {
                using (var connection = new SqliteConnection(new SqliteConnectionStringBuilder {DataSource=DatabasePath,Mode=SqliteOpenMode.ReadOnly}.ToString()))
                {
                    connection.Open();
                    using(var exists=connection.CreateCommand()) {
                        exists.CommandText="SELECT count(*) FROM sqlite_master WHERE name='analysis_manifest'";
                        if(Convert.ToInt32(exists.ExecuteScalar())!=0) {
                            var meta=new Dictionary<string,string>();using(var m=connection.CreateCommand()){m.CommandText="SELECT key,value FROM analysis_manifest";using(var r=m.ExecuteReader())while(r.Read())meta[r.GetString(0)]=r.GetString(1);}
                            if(meta.TryGetValue("injection_contract",out var contract)) {
                                bool blind=contract=="static_probes_v1";
                                if((contract!="application_edits_v1"&&!blind)||meta["state"]!="validated"||
                                    (blind?meta["schema_version"]!="8":meta["schema_version"]!="6"&&meta["schema_version"]!="7"))throw new InvalidOperationException("Unsupported or unvalidated injection contract");
                                using(var validate=connection.CreateCommand()) {
                                    validate.CommandText="SELECT count(*) FROM basic_blocks b JOIN trace_selection_decisions d ON d.legacy_id=b.id WHERE b.to_trace<>d.enabled";
                                    if(Convert.ToInt64(validate.ExecuteScalar())!=0)throw new InvalidOperationException("Application flags do not match the verified profile; reselect before building");
                                    validate.CommandText=blind?"SELECT count(*) FROM basic_blocks b LEFT JOIN static_flow_decisions d ON d.probe_id=b.id WHERE d.probe_id IS NULL OR b.to_trace<>d.enabled":"SELECT count(*) FROM (SELECT p.group_key FROM application_placements p JOIN basic_blocks b ON b.id=p.legacy_id WHERE p.kind IN ('operation_enter','operation_error','operation_leave') GROUP BY p.group_key HAVING sum(b.to_trace) NOT IN (0,count(*)))";
                                    if(Convert.ToInt64(validate.ExecuteScalar())!=0)throw new InvalidOperationException("Partial application boundary group is not a valid profile");
                                }
                                profile=new ProfileInfo {SchemaVersion=int.Parse(meta["schema_version"]),ProfileId=meta["selection_profile_id"],PolicyFingerprint=meta["application_policy_fingerprint"],InputFingerprint=meta["fingerprint"],InjectionContract=contract};
                                using(var p=connection.CreateCommand()) {
                                    p.CommandText="SELECT p.legacy_id,p.path,p.source_hash FROM application_placements p JOIN basic_blocks b ON b.id=p.legacy_id WHERE b.to_trace=1";
                                    using(var r=p.ExecuteReader())while(r.Read()){placedIds.Add(r.GetInt32(0));applicationHashes[r.GetString(1)]=r.GetString(2);}
                                }
                                using(var e=connection.CreateCommand()) {
                                    e.CommandText="SELECT e.path,e.offset,e.remove_length,e.text,e.priority FROM application_edits e JOIN basic_blocks b ON b.id=e.gate_id WHERE b.to_trace=1 ORDER BY e.id";
                                    using(var r=e.ExecuteReader())while(r.Read()) {
                                        string file=r.GetString(0);if(!applicationEdits.TryGetValue(file,out var list))applicationEdits[file]=list=new List<ApplicationEdit>();
                                        var edit=new ApplicationEdit {Offset=r.GetInt32(1),Remove=r.GetInt32(2),Text=r.GetString(3),Priority=r.GetInt32(4)};
                                        if(blind&&!IsBlindEdit(edit))throw new InvalidOperationException("Static profile attempted to inject runtime logic");
                                        list.Add(edit);
                                    }
                                }
                                if(blind)using(var sources=connection.CreateCommand()) {
                                    sources.CommandText="SELECT path,source_hash FROM static_flow_sources";
                                    using(var r=sources.ExecuteReader())while(r.Read())applicationHashes[r.GetString(0)]=r.GetString(1);
                                }
                            }
                        }
                    }
                    
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
                            if(placedIds.Contains(id))continue;
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
            foreach(var file in applicationEdits.Keys)if(!blocksByFile.ContainsKey(file))blocksByFile[file]=new List<BlockInfo>();
            if(profile!=null) {
                ProfileManifest=Path.GetFullPath(Path.Combine(genDir,"aitracer.profile.json"));
                using(var stream=File.Create(ProfileManifest))new DataContractJsonSerializer(typeof(ProfileInfo)).WriteObject(stream,profile);
            }

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
                        if(profile!=null&&profile.InjectionContract=="static_probes_v1"&&!applicationEdits.ContainsKey(fullPath)) {
                            using(var sha=SHA256.Create()) {
                                string sourceHash=BitConverter.ToString(sha.ComputeHash(Encoding.UTF8.GetBytes(text))).Replace("-","").ToLowerInvariant();
                                if(!applicationHashes.TryGetValue(fullPath,out var expected)||sourceHash!=expected)throw new InvalidOperationException("Source changed since static analysis: "+fullPath);
                            }
                        }
                        if(applicationEdits.TryGetValue(fullPath,out var edits)) {
                            using(var sha=SHA256.Create()) {
                                string sourceHash=BitConverter.ToString(sha.ComputeHash(Encoding.UTF8.GetBytes(text))).Replace("-","").ToLowerInvariant();
                                if(!applicationHashes.TryGetValue(fullPath,out var expected)||sourceHash!=expected)throw new InvalidOperationException("Source changed since application analysis: "+fullPath);
                            }
                            var all=edits.Concat(sortedInsertions.Select(i=>new ApplicationEdit {Offset=i.Offset,Text=i.Text,Priority=i.IsEndWrapper?100000:2000000})).OrderByDescending(e=>e.Offset).ThenByDescending(e=>e.Priority);
                            foreach(var e in all) {
                                if(e.Offset<0||e.Remove<0||e.Offset+e.Remove>text.Length)throw new InvalidOperationException("Invalid application source edit");
                                text=text.Remove(e.Offset,e.Remove).Insert(e.Offset,e.Text);
                            }
                        } else foreach (var ins in sortedInsertions)
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
            return !Log.HasLoggedErrors;
        }

        private class ApplicationEdit {public int Offset;public int Remove;public string Text;public int Priority;}
        private static bool IsBlindEdit(ApplicationEdit edit) {
            if(edit.Remove!=0)return false;
            string rest=Regex.Replace(edit.Text,@"(?m)^\s*#line (?:hidden|default)\s*$","");
            rest=Regex.Replace(rest,@"AITracer\.Runtime\.TraceContext\.Log\([1-9][0-9]*\);","");
            return Regex.Replace(rest,@"\belse\b|[{}\s]","").Length==0;
        }

        [DataContract]
        public class ProfileInfo {
            [DataMember(Name="schema_version")]public int SchemaVersion {get;set;}
            [DataMember(Name="profile_id")]public string ProfileId {get;set;}
            [DataMember(Name="policy_fingerprint")]public string PolicyFingerprint {get;set;}
            [DataMember(Name="input_fingerprint")]public string InputFingerprint {get;set;}
            [DataMember(Name="injection_contract")]public string InjectionContract {get;set;}
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
