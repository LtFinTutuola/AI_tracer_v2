using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.Data.Sqlite;

namespace RoslynAnalyzer;

public sealed record InterestEvidence(long Id,string Rule,string Detail);
public sealed class InterestFilterResult
{
    internal InputRegistry Inputs {get;}=new();
    internal long RetainedBytes=>Evidence.Sum(item=>192L+item.Detail.Length*2L)+Reasons.Count*160L+(Enabled.Count+HardProtected.Count+RequiredIds.Count+InterestCandidates.Count)*48L;
    public const string RulesVersion="application_interest_rules_v2";
    public HashSet<long> Enabled {get;}=new();
    public HashSet<long> HardProtected {get;}=new();
    public HashSet<long> RequiredIds {get;}=new();
    public HashSet<long> InterestCandidates {get;}=new();
    public Dictionary<long,string> Reasons {get;}=new();
    public List<InterestEvidence> Evidence {get;}=new();
    public int TargetCount {get;set;}
    public int BaselineCount {get;set;}
    public int RequiredCount {get;set;}
    public int Requirements {get;set;}
    public int UncoveredRequirements {get;set;}
    public int SourceFilesVerified {get;set;}
    public int SourceFilesUnavailable {get;set;}
    public int AuditCompleted {get;set;}
    public int AuditIncomplete {get;set;}
    public int AuditSilentTechnical {get;set;}
    public int AuditApplicationPaths {get;set;}
    public int AuditSilentBeforeRepair {get;set;}
    public int AuditSilentAfterRepair {get;set;}
    public HashSet<long> AuditRestoredIds {get;}=new();
    public object Summary=>new {rules_version=RulesVersion,observation_model="application_checkpoints_heuristic_v1",
        target_count=TargetCount,baseline_eligible=BaselineCount,required_count=RequiredCount,enabled=Enabled.Count,
        enabled_fraction=BaselineCount==0?0:(double)Enabled.Count/BaselineCount,target_met=Enabled.Count<=TargetCount,
        requirements=Requirements,uncovered_requirements=UncoveredRequirements,source_files_verified=SourceFilesVerified,
        source_files_unavailable=SourceFilesUnavailable,
        audit=new {attempts_per_root=16,seed_split=3,completed=AuditCompleted,incomplete=AuditIncomplete,
            paths_with_interest_witnesses=AuditApplicationPaths,quiet_paths_without_recognized_interest=AuditSilentTechnical,
            silent_interest_paths_before_repair=AuditSilentBeforeRepair,silent_interest_paths_after_repair=AuditSilentAfterRepair,
            restored_count=AuditRestoredIds.Count,restored_ids_preview=AuditRestoredIds.OrderBy(id=>id).Take(32)},
        requirements_scope="existing mapped probe regions; not exhaustive semantic effects",
        semantic_path_accuracy="not_established; structural witnesses and syntax/symbol-name rules, not effect verification",
        reasons=Reasons.Values.GroupBy(reason=>reason).ToDictionary(group=>group.Key,group=>group.Count())};
}

/// <summary>Deterministic experimental second pass. No CFG rebuild, no target build,
/// no LLM. The count target never overrides integrity guards or observation requirements.</summary>
public static class ApplicationInterestFilter
{
    private static readonly Regex Technical=new(@"(?:\b(?:get|set)_|\b(?:GetHashCode|Equals|ToString|Convert\w*|Format\w*|Translate\w*|Serialize\w*|Deserialize\w*)\s*\(|(?:Encoding|Translation|Serialization|Resources|Designer)\b)",RegexOptions.IgnoreCase|RegexOptions.CultureInvariant);
    private static readonly Regex Decision=new(@"\b(?:CheckPermission|IsAllowed|CanManage\w*|IsSuccessful|HasError|Succeeded|Authorize\w*|Authenticate\w*)\b",RegexOptions.IgnoreCase|RegexOptions.CultureInvariant);
    private static readonly Regex Effect=new(@"\.(?:Commit|CommitAsync|Rollback|RollbackAsync|SaveChanges|SaveChangesAsync|ExecuteNonQuery|ExecuteNonQueryAsync|Send|SendAsync|Publish|PublishAsync|PrintReceipt\w*|PrintInvoice\w*|PrintFiscal\w*|OpenDrawer|CloseTransaction|OperatorLogout|ProcessPayment\w*|ExecuteFunction)\s*\(",RegexOptions.IgnoreCase|RegexOptions.CultureInvariant);
    private static readonly Regex Error=new(@"\.(?:LogError|MsgError|ReportError|HandleException|Retry\w*|Compensate\w*)\s*\(",RegexOptions.IgnoreCase|RegexOptions.CultureInvariant);
    private static readonly Regex State=new(@"\b(?:Status|State|Phase|AbortMacro|IsClosed|IsOpen|LoggedIn|CurrentTransaction)\b",RegexOptions.IgnoreCase|RegexOptions.CultureInvariant);
    private sealed record Probe(long Id,string Path,int Offset,string Signature,string Reason,long Method,long? Node,long? Point);
    private sealed class Candidate(Probe probe)
    {
        public Probe Probe {get;}=probe;
        public int Score {get;set;}=10;
        public bool Technical {get;set;}
        public HashSet<string> Units {get;}=new(StringComparer.Ordinal);
    }

    internal static InterestFilterResult Select(string path,TraceSelectionOptions options,ISet<long> firstPassDisabled,
        Action check,Action<long> reserve,Action<long> release)
    {
        var result=new InterestFilterResult();long owned=0;
        void Charge(long bytes){reserve(bytes);owned+=bytes;}
        try {
            using var db=new SqliteConnection(new SqliteConnectionStringBuilder {DataSource=path,Mode=SqliteOpenMode.ReadOnly,Pooling=false}.ToString());db.Open();
            using(var setup=db.CreateCommand()){setup.CommandText="PRAGMA cache_size=-1024";setup.ExecuteNonQuery();Charge(1024*1024);}
            void Rows(string sql,Action<SqliteDataReader> read,object? document=null) {
                using var cmd=db.CreateCommand();cmd.CommandText=sql;if(document!=null)cmd.Parameters.AddWithValue("@document",document);
                using var rows=cmd.ExecuteReader();while(rows.Read()){check();read(rows);}
            }
            var candidates=new Dictionary<long,Candidate>();
            void Evidence(long id,string rule,string detail){Charge(192+detail.Length*2L);result.Evidence.Add(new(id,rule,detail));}
            Rows("""
                SELECT b.id,b.file_path,b.injection_offset,b.method_signature,b.reason,l.method_id,p.node_id,l.point_id
                FROM basic_blocks b LEFT JOIN legacy_block_links l ON l.id=(SELECT min(x.id) FROM legacy_block_links x WHERE x.legacy_id=b.id)
                LEFT JOIN flow_points p ON p.id=l.point_id WHERE b.to_trace=1 ORDER BY b.id
                """,row=>{
                    Charge(1024+row.GetString(1).Length*2L+row.GetString(3).Length*2L);
                    var probe=new Probe(row.GetInt64(0),row.GetString(1),row.GetInt32(2),row.GetString(3),row.GetString(4),row.IsDBNull(5)?0:row.GetInt64(5),row.IsDBNull(6)?null:row.GetInt64(6),row.IsDBNull(7)?null:row.GetInt64(7));
                    candidates[probe.Id]=new(probe);
                });
            result.BaselineCount=candidates.Count;result.TargetCount=(int)Math.Ceiling(candidates.Count*options.InterestTargetFraction);
            void Hard(long id,string reason) {
                if(!candidates.ContainsKey(id))return;
                result.HardProtected.Add(id);result.Enabled.Add(id);result.Reasons[id]=reason;
            }
            Rows("SELECT scope FROM analysis_diagnostics WHERE code='SHARED_PROBE_CONFLICT_DISCARDED'",row=>{
                if(long.TryParse(row.GetString(0).Replace("legacy:",""),out long id))Hard(id,"interest_shared_conflict");
            });
            Rows("SELECT DISTINCT legacy_id FROM legacy_block_links WHERE point_id IS NULL",row=>Hard(row.GetInt64(0),"interest_unmapped"));
            Rows("SELECT legacy_id FROM legacy_probe_variants GROUP BY legacy_id HAVING count(*)>1",row=>Hard(row.GetInt64(0),"interest_shared_variants"));
            Rows("""
                SELECT b.id FROM basic_blocks b WHERE EXISTS(SELECT 1 FROM documents d WHERE d.origin='source' AND d.path=b.file_path COLLATE NOCASE
                  AND NOT EXISTS(SELECT 1 FROM legacy_probe_variants v WHERE v.legacy_id=b.id AND v.variant_id=d.variant_id))
                """,row=>Hard(row.GetInt64(0),"interest_variant_without_mapping"));
            foreach(var candidate in candidates.Values)if(candidate.Probe.Method==0)Hard(candidate.Probe.Id,"interest_no_owner");

            // Read only the physical inputs already recorded in the catalog. Changed
            // inputs are a failure; unavailable inputs retain all their probes.
            foreach(var file in candidates.Values.GroupBy(item=>item.Probe.Path,StringComparer.OrdinalIgnoreCase).OrderBy(group=>group.Key,StringComparer.OrdinalIgnoreCase)) {
                check();string text;
                try{text=File.ReadAllText(file.Key);}catch(IOException){result.SourceFilesUnavailable++;foreach(var item in file)Hard(item.Probe.Id,"interest_source_unavailable");continue;}
                result.Inputs.Track(file.Key,text);
                long syntaxBytes=4096+text.Length*24L;reserve(syntaxBytes);
                try {
                    string hash=ContextCatalog.Id(text);bool known=false;
                    Rows("SELECT hash FROM documents WHERE path=@document COLLATE NOCASE AND origin='source'",row=>{
                        known=true;if(row.GetString(0)!=hash)throw new InvalidOperationException("Interest filter source changed since extraction: "+file.Key);
                    },file.Key);
                    if(!known){result.SourceFilesUnavailable++;foreach(var item in file)Hard(item.Probe.Id,"interest_source_unverified");continue;}
                    result.SourceFilesVerified++;
                    // Each linked variant gets its own parse options; trees are released
                    // before the next variant/file rather than retained globally.
                    var documentIds=new Dictionary<long,long>();
                    Rows("SELECT m.id,m.document_id FROM methods m JOIN documents d ON d.id=m.document_id WHERE d.path=@document COLLATE NOCASE",row=>documentIds[row.GetInt64(0)]=row.GetInt64(1),file.Key);
                    foreach(var document in file.GroupBy(item=>documentIds.GetValueOrDefault(item.Probe.Method))) {
                        if(document.Key==0)continue;
                        string parseJson="{}";
                        Rows("SELECT v.options FROM documents d JOIN project_variants v ON v.id=d.variant_id WHERE d.id=@document",row=>parseJson=row.GetString(0),document.Key);
                        using var parseOptions=JsonDocument.Parse(parseJson);
                        var symbols=parseOptions.RootElement.TryGetProperty("Symbols",out var names)&&names.ValueKind==JsonValueKind.Array?names.EnumerateArray().Select(item=>item.GetString()!).ToArray():Array.Empty<string>();
                        var syntax=CSharpSyntaxTree.ParseText(text,new CSharpParseOptions(preprocessorSymbols:symbols),file.Key).GetRoot();
                        var nodeCalls=new Dictionary<long,List<string>>();
                        var methodCalls=new Dictionary<long,List<string>>();
                        Rows("""
                            SELECT p.node_id,s.target_signature,m.id FROM methods m JOIN call_sites s ON s.method_id=m.id
                            JOIN flow_points p ON p.id=s.point_id WHERE m.document_id=@document ORDER BY s.id
                            """,row=>{
                                long node=row.GetInt64(0),method=row.GetInt64(2);string call=row.GetString(1);
                                if(!nodeCalls.TryGetValue(node,out var calls))nodeCalls[node]=calls=new();calls.Add(call);
                                if(!methodCalls.TryGetValue(method,out var targets))methodCalls[method]=targets=new();targets.Add(call);
                            },document.Key);
                        var mechanical=new Dictionary<long,bool>();
                        foreach(var item in document) {
                            check();var probe=item.Probe;
                            if(probe.Offset<0||probe.Offset>=text.Length){Hard(probe.Id,"interest_invalid_offset");continue;}
                            var token=syntax.FindToken(probe.Offset,findInsideTrivia:true);
                            var statement=token.Parent?.AncestorsAndSelf().OfType<StatementSyntax>().FirstOrDefault();
                            if(statement==null||!statement.FullSpan.Contains(probe.Offset)){Hard(probe.Id,"interest_inactive_syntax");continue;}
                            if(!mechanical.TryGetValue(probe.Method,out bool calculationOnly)) {
                                var method=statement.AncestorsAndSelf().OfType<BaseMethodDeclarationSyntax>().FirstOrDefault();
                                calculationOnly=method!=null&&IsCalculationOrRead(method,methodCalls.GetValueOrDefault(probe.Method)??new());
                                mechanical[probe.Method]=calculationOnly;
                            }
                            item.Technical=calculationOnly||Technical.IsMatch(probe.Signature)||Technical.IsMatch(Path.GetFileNameWithoutExtension(file.Key));
                            item.Score=item.Technical?-20:10;
                            var calls=probe.Node.HasValue?nodeCalls.GetValueOrDefault(probe.Node.Value):null;
                            if(calls!=null)foreach(string call in calls) {
                                if(Effect.IsMatch(call)||Error.IsMatch(call)) {
                                    string rule=Error.IsMatch(call)?"error_or_recovery":"external_or_domain_operation";
                                    item.Units.Add(rule+":"+probe.Node+":"+call);item.Score+=150;
                                    Evidence(probe.Id,rule,"CFG region containing call: "+call);
                                }
                            }
                            if(statement is ThrowStatementSyntax||probe.Reason.Contains("Exception Handler")) {
                                item.Units.Add("exception:"+probe.Method+":"+statement.SpanStart);item.Score+=200;
                                Evidence(probe.Id,"exception_path","Source throw/catch witness; not an implicit exception guarantee");
                            }
                            foreach(var guard in statement.AncestorsAndSelf().OfType<IfStatementSyntax>()) {
                                if(!Decision.IsMatch(guard.Condition.ToString()))continue;
                                string arm=guard.Statement.FullSpan.Contains(probe.Offset)?"true_arm":guard.Else?.Statement.FullSpan.Contains(probe.Offset)==true?"false_arm":"condition";
                                item.Units.Add("decision:"+probe.Method+":"+guard.SpanStart+":"+arm);item.Score+=100;
                                Evidence(probe.Id,"application_decision",guard.Condition+" / "+arm);
                            }
                            if(statement is ExpressionStatementSyntax expression&&expression.Expression is AssignmentExpressionSyntax assignment&&State.IsMatch(assignment.Left.ToString())) {
                                item.Units.Add("state:"+probe.Method+":"+statement.SpanStart);item.Score+=120;
                                Evidence(probe.Id,"state_assignment","Source assignment reached: "+assignment.Left);
                            }
                            var section=statement.AncestorsAndSelf().OfType<SwitchSectionSyntax>().FirstOrDefault();
                            if(section!=null&&!item.Technical) {
                                item.Units.Add("dispatch:"+probe.Method+":"+section.SpanStart);item.Score+=60;
                                Evidence(probe.Id,"dispatch_case",string.Join(" ",section.Labels.Select(label=>label.ToString())));
                            }
                            if(probe.Reason.Contains("Proof of Completion"))item.Score+=45;
                            if(probe.Reason.Contains("Early Exit"))item.Score+=15;
                        }
                    }
                } finally {release(syntaxBytes);}
            }

            // A single structural checkpoint per nontechnical method, with specific
            // branch/effect requirements kept separately. Technical helpers may be quiet.
            foreach(var item in candidates.Values)if(!item.Technical&&item.Probe.Method!=0)item.Units.Add("method:"+item.Probe.Method);
            var units=new Dictionary<string,List<long>>(StringComparer.Ordinal);
            foreach(var item in candidates.Values)foreach(string unit in item.Units) {
                Charge(96);if(!units.TryGetValue(unit,out var ids))units[unit]=ids=new();ids.Add(item.Probe.Id);
            }
            result.Requirements=units.Count;
            // The audit preserves paths with explicit application witnesses. A generic
            // method checkpoint is not a claim that every technical invocation matters.
            result.InterestCandidates.UnionWith(candidates.Values.Where(item=>item.Units.Any(unit=>!unit.StartsWith("method:",StringComparison.Ordinal))).Select(item=>item.Probe.Id));
            var uncovered=units.Where(unit=>!unit.Value.Any(result.Enabled.Contains)).Select(unit=>unit.Key).ToHashSet(StringComparer.Ordinal);
            // Deterministic set cover: satisfy observation requirements before cost target.
            var queue=new PriorityQueue<(Candidate Item,int Coverage),(int Coverage,int Score,long Id)>();
            foreach(var item in candidates.Values.Where(item=>!result.Enabled.Contains(item.Probe.Id))) {
                int coverage=item.Units.Count(uncovered.Contains);
                if(coverage>0)queue.Enqueue((item,coverage),(-coverage,-item.Score,item.Probe.Id));
            }
            while(uncovered.Count>0&&queue.TryDequeue(out var entry,out _)) {
                check();var best=entry.Item;int coverage=best.Units.Count(uncovered.Contains);
                if(coverage==0)continue;
                if(coverage!=entry.Coverage){queue.Enqueue((best,coverage),(-coverage,-best.Score,best.Probe.Id));continue;}
                result.Enabled.Add(best.Probe.Id);result.Reasons[best.Probe.Id]="interest_required_witness";
                uncovered.ExceptWith(best.Units);
            }
            result.UncoveredRequirements=uncovered.Count;result.RequiredCount=result.Enabled.Count;
            result.RequiredIds.UnionWith(result.Enabled);
            // Optional details use a reproducible score and prefer the first-pass
            // profile on ties. No required witness is deleted to meet a quota.
            foreach(var item in candidates.Values.Where(item=>!result.Enabled.Contains(item.Probe.Id))
                .OrderByDescending(item=>item.Score).ThenBy(item=>firstPassDisabled.Contains(item.Probe.Id)).ThenBy(item=>item.Probe.Id)) {
                check();if(result.Enabled.Count>=result.TargetCount)break;
                result.Enabled.Add(item.Probe.Id);result.Reasons[item.Probe.Id]="interest_optional_checkpoint";
            }
            foreach(var item in candidates.Values) {
                check();if(!result.Enabled.Contains(item.Probe.Id))result.Reasons[item.Probe.Id]=item.Technical?"interest_technical_detail_suppressed":"interest_internal_detail_suppressed";
            }
            check();result.Inputs.Verify();check();return result;
        } finally {release(owned);}
    }

    internal static bool IsCalculationOrRead(BaseMethodDeclarationSyntax method,IEnumerable<string> calls)
    {
        // Syntactic evidence only, intentionally named as a rule rather than a proof
        // of purity. Unknown calls, ref/out, shared writes and concurrency constructs
        // prevent this rule. Explicit error/decision/effect witnesses still win.
        if(method.ParameterList.Parameters.Any(parameter=>parameter.Modifiers.Any(token=>token.IsKind(SyntaxKind.RefKeyword)||token.IsKind(SyntaxKind.OutKeyword))))return false;
        if(method.DescendantNodes().Any(node=>node is AwaitExpressionSyntax or YieldStatementSyntax or LockStatementSyntax or UnsafeStatementSyntax or AnonymousFunctionExpressionSyntax or LocalFunctionStatementSyntax))return false;
        var locals=method.DescendantNodes().OfType<VariableDeclaratorSyntax>().Select(variable=>variable.Identifier.ValueText)
            .Concat(method.ParameterList.Parameters.Select(parameter=>parameter.Identifier.ValueText)).ToHashSet(StringComparer.Ordinal);
        foreach(var assignment in method.DescendantNodes().OfType<AssignmentExpressionSyntax>())
            if(assignment.Left is not IdentifierNameSyntax id||!locals.Contains(id.Identifier.ValueText))return false;
        foreach(var update in method.DescendantNodes().Where(node=>node.IsKind(SyntaxKind.PreIncrementExpression)||node.IsKind(SyntaxKind.PreDecrementExpression)||node.IsKind(SyntaxKind.PostIncrementExpression)||node.IsKind(SyntaxKind.PostDecrementExpression))) {
            var operand=update is PrefixUnaryExpressionSyntax prefix?prefix.Operand:((PostfixUnaryExpressionSyntax)update).Operand;
            if(operand is not IdentifierNameSyntax id||!locals.Contains(id.Identifier.ValueText))return false;
        }
        return calls.All(call=>call.StartsWith("System.Math.",StringComparison.Ordinal)||call.StartsWith("System.MathF.",StringComparison.Ordinal)||
            call.StartsWith("System.Convert.",StringComparison.Ordinal)||call.StartsWith("string.",StringComparison.Ordinal)||call.StartsWith("System.String.",StringComparison.Ordinal));
    }
}
