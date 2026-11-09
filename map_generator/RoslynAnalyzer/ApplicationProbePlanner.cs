using System.Text.Json;
using System.Security.Cryptography;
using System.Text;
using Microsoft.CodeAnalysis.Text;
using Microsoft.Data.Sqlite;

namespace RoslynAnalyzer;

public sealed record ApplicationObservation(string Id,long Method,long Variant,string Kind,string Evidence,long? Point,string Status);
public sealed record ApplicationBinding(string Observation,long Probe);
public sealed record ApplicationLocation(string Observation,long Node,int Position,long? Edge);
public sealed record ApplicationPlacement(long Probe,string Kind,string Path,int Anchor,int Start,int End,string Hash,string Group);
public sealed record ApplicationEdit(string Path,int Offset,int Remove,string Text,int Priority,long Gate);
public sealed record ApplicationEntry(long Method,string Classification,string Reasons,string Signature="",string Project="",string Path="",long Variant=0);
public sealed record ApplicationSummary(long Method,int Flags,bool Repeated,bool Opaque);
public sealed class ApplicationPlan
{
    public const string Algorithm="application_observations_v1";
    public required string PolicyFingerprint {get;init;}
    public required string PolicyJson {get;init;}
    public InputRegistry Inputs {get;}=new();
    public List<(long Id,BasicBlockRecord Record)> NewProbes {get;}=new();
    public Dictionary<long,ApplicationPlacement> Placements {get;}=new();
    public List<ApplicationEdit> Edits {get;}=new();
    public Dictionary<string,ApplicationObservation> Observations {get;}=new();
    public HashSet<ApplicationBinding> Bindings {get;}=new();
    public Dictionary<string,ApplicationLocation> Locations {get;}=new();
    public List<ApplicationEntry> Entries {get;}=new();
    public List<ApplicationSummary> Summaries {get;}=new();
    public HashSet<long> Enabled {get;}=new();
    public Dictionary<long,string> Reasons {get;}=new();
    public int ExistingProbes {get;set;}
    public int Unresolved {get;set;}
    public int SharedAmbiguities {get;set;}
    public int UnmappedCompilationVariants {get;set;}
    public object Summary=>new {algorithm=Algorithm,policy_fingerprint=PolicyFingerprint,observation_budget=0,
        observation_scope="declared source observations; no value payload or exhaustive reflection/async correlation",
        entries=Entries.Count,entry_classifications=Entries.GroupBy(e=>e.Classification).ToDictionary(g=>g.Key,g=>g.Count()),
        observations=Observations.Count,bindings=Bindings.Count,cfg_locations=Locations.Count,new_probes=NewProbes.Count,enabled=Enabled.Count,
        opaque_observations=Observations.Values.Count(o=>o.Status!="modeled"),unclassified_entries=Unresolved,
        shared_variant_ambiguities=SharedAmbiguities,unmapped_compilation_variants=UnmappedCompilationVariants,coverage_verification="constructive exact-placement witnesses; no sampled accuracy claim",
        repeated_observation_methods=Summaries.Count(s=>s.Repeated&&s.Flags!=0)};
    public void Persist(SqliteConnection db,SqliteTransaction tx,CancellationToken token)
    {
        using var cmd=db.CreateCommand();cmd.Transaction=tx;
        void Run(string sql,params object?[] args) {token.ThrowIfCancellationRequested();cmd.CommandText=sql;cmd.Parameters.Clear();for(int i=0;i<args.Length;i++)cmd.Parameters.AddWithValue("@p"+i,args[i]??DBNull.Value);cmd.ExecuteNonQuery();}
        Run("DELETE FROM application_probe_bindings;DELETE FROM application_locations;DELETE FROM application_observations;DELETE FROM application_edits;DELETE FROM application_entries;DELETE FROM application_method_summaries;");
        foreach(var (id,r) in NewProbes)Run("INSERT INTO basic_blocks(id,project_name,file_path,method_signature,scope_start_line,scope_end_line,block_start_line,block_end_line,injection_line,injection_offset,reason,to_trace,wrap_in_block,statement_end_offset) VALUES(@p0,@p1,@p2,@p3,@p4,@p5,@p6,@p7,@p8,@p9,@p10,1,0,0)",
            id,r.ProjectName,r.FilePath,r.MethodSignature,r.ScopeStartLine,r.ScopeEndLine,r.BlockStartLine,r.BlockEndLine,r.InjectionLine,r.InjectionOffset,r.Reason);
        foreach(var p in Placements.Values.OrderBy(p=>p.Probe))Run("INSERT OR IGNORE INTO application_placements VALUES(@p0,@p1,@p2,@p3,@p4,@p5,@p6,@p7)",p.Probe,p.Kind,p.Path,p.Anchor,p.Start,p.End,p.Hash,p.Group);
        foreach(var o in Observations.Values.OrderBy(o=>o.Id,StringComparer.Ordinal))Run("INSERT INTO application_observations VALUES(@p0,@p1,@p2,@p3,@p4,@p5,@p6)",o.Id,o.Method,o.Variant,o.Kind,o.Evidence,o.Point,o.Status);
        foreach(var l in Locations.Values)Run("INSERT INTO application_locations VALUES(@p0,@p1,@p2,@p3)",l.Observation,l.Node,l.Position,l.Edge);
        foreach(var b in Bindings.OrderBy(b=>b.Observation,StringComparer.Ordinal).ThenBy(b=>b.Probe)) {
            Run("INSERT INTO application_probe_bindings VALUES(@p0,@p1)",b.Observation,b.Probe);
            var o=Observations[b.Observation];
            Run("INSERT OR IGNORE INTO application_probe_contexts VALUES(@p0,@p1)",b.Probe,o.Method);
            // Preserve existing CFG links. New boundary/edge probes have a separate
            // placement contract and are not fabricated as legacy CFG operations.
        }
        foreach(var e in Edits.Distinct().OrderBy(e=>e.Path,StringComparer.OrdinalIgnoreCase).ThenBy(e=>e.Offset).ThenBy(e=>e.Priority))Run("INSERT INTO application_edits(path,offset,remove_length,text,priority,gate_id) VALUES(@p0,@p1,@p2,@p3,@p4,@p5)",e.Path,e.Offset,e.Remove,e.Text,e.Priority,e.Gate);
        foreach(var e in Entries)Run("INSERT INTO application_entries VALUES(@p0,@p1,@p2)",e.Method,e.Classification,e.Reasons);
        foreach(var s in Summaries)Run("INSERT INTO application_method_summaries VALUES(@p0,@p1,@p2,@p3)",s.Method,s.Flags,s.Repeated?1:0,s.Opaque?1:0);
        Run("INSERT OR REPLACE INTO analysis_manifest VALUES('application_policy_fingerprint',@p0)",PolicyFingerprint);
        Run("INSERT OR REPLACE INTO analysis_manifest VALUES('application_policy_json',@p0)",PolicyJson);
        Run("INSERT OR REPLACE INTO analysis_manifest VALUES('application_summary',@p0)",JsonSerializer.Serialize(Summary));
        Run("INSERT OR REPLACE INTO analysis_manifest VALUES('injection_contract','application_edits_v1')");
    }
}

internal sealed record ApplicationMethod(long Id,long Variant,string Signature,string Path,string Hash,string Project,int Start,int Length,
    string Symbol,int BodyStart,int BodyEnd,int ExpressionStart,int ExpressionEnd,string ReturnPrefix,bool Exported,string EntryKind,bool Async,bool Iterator,string ExitSemantics,bool Supported,bool PhysicalSource);

/// <summary>Policy and compact facts become exact source observation obligations.</summary>
public static class ApplicationObservationBuilder
{
    public static TraceSelectionResult Build(string path,TraceSelectionOptions options,CancellationToken token,Action<string,object?>? progress)
    {
        var resources=new SelectionResources(options,token){PhaseFraction=1};
        var policy=ApplicationPolicy.Load(options.ObservationPolicy);string policyText=File.ReadAllText(options.ObservationPolicy);
        if(ContextCatalog.Id(policyText)!=policy.Fingerprint)throw new InvalidOperationException("Observation policy changed while loading");
        var plan=new ApplicationPlan {PolicyFingerprint=policy.Fingerprint,PolicyJson=policyText};plan.Inputs.Track(options.ObservationPolicy,policyText);
        using var db=new SqliteConnection(new SqliteConnectionStringBuilder {DataSource=path,Mode=SqliteOpenMode.ReadOnly,Pooling=false}.ToString());db.Open();
        using(var setup=db.CreateCommand()){setup.CommandText="PRAGMA cache_size=-1024";setup.ExecuteNonQuery();resources.Reserve(1024*1024);}
        using(var schema=db.CreateCommand()){schema.CommandText="SELECT value FROM analysis_manifest WHERE key='schema_version'";if((string?)schema.ExecuteScalar()!="6")throw new InvalidOperationException("Application mode requires schema 6 facts; regenerate the catalog before selection");}
        void Rows(string sql,Action<SqliteDataReader> read,params object[] args) {using var c=db.CreateCommand();c.CommandText=sql;for(int i=0;i<args.Length;i++)c.Parameters.AddWithValue("@p"+i,args[i]);using var r=c.ExecuteReader();while(r.Read()){resources.Check();read(r);}}
        var symbols=new Dictionary<string,ApplicationSymbol>(StringComparer.Ordinal);
        Rows("SELECT key,description FROM application_symbols",r=>{string json=r.GetString(1);resources.Reserve(256+json.Length*3L);symbols[r.GetString(0)]=JsonSerializer.Deserialize<ApplicationSymbol>(json)!;});
        var roleCache=new Dictionary<string,string?>(StringComparer.Ordinal);
        string? Role(string key) {
            if(roleCache.TryGetValue(key,out var role))return role;
            resources.Reserve(96);role=symbols.TryGetValue(key,out var s)?policy.Role(s):null;roleCache[key]=role;return role;
        }
        var methods=new Dictionary<long,ApplicationMethod>();
        Rows("""
          SELECT m.id,m.variant_id,m.signature,d.path,d.hash,v.name,m.start,m.length,f.symbol_key,f.body_start,f.body_end,f.expression_start,f.expression_end,f.return_prefix,f.exported,f.entry_kind,f.is_async,f.is_iterator,f.exit_semantics,f.supported,d.origin
          FROM application_method_facts f JOIN methods m ON m.id=f.method_id JOIN documents d ON d.id=m.document_id JOIN project_variants v ON v.id=m.variant_id
          ORDER BY d.path COLLATE NOCASE,m.start,m.id
          """,r=>{resources.Reserve(1024+r.GetString(3).Length*2L);methods[r.GetInt64(0)]=new(r.GetInt64(0),r.GetInt64(1),r.GetString(2),r.GetString(3),r.GetString(4),r.GetString(5),r.GetInt32(6),r.GetInt32(7),r.GetString(8),r.GetInt32(9),r.GetInt32(10),r.GetInt32(11),r.GetInt32(12),r.GetString(13),r.GetInt32(14)!=0,r.GetString(15),r.GetInt32(16)!=0,r.GetInt32(17)!=0,r.GetString(18),r.GetInt32(19)!=0,r.GetString(20)=="source");});
        var incoming=new HashSet<long>();var calls=new List<(long Caller,long Callee)>();
        Rows("SELECT s.method_id,t.method_id FROM call_sites s JOIN call_targets t ON t.site_id=s.id",r=>{resources.Reserve(32);incoming.Add(r.GetInt64(1));calls.Add((r.GetInt64(0),r.GetInt64(1)));});
        var registrations=new Dictionary<string,HashSet<string>>(StringComparer.Ordinal);
        Rows("SELECT target_key,api_key,kind FROM application_registrations",r=>{
            string target=r.GetString(0),api=r.GetString(1),kind=r.GetString(2);
            if(kind!="event"&&(!symbols.TryGetValue(api,out var s)||!policy.CallbackApis.Any(c=>c.Type==s.Type&&c.Member==s.Member)))return;
            resources.Reserve(128);if(!registrations.TryGetValue(target,out var list))registrations[target]=list=new();list.Add(kind);
        });
        var roles=new Dictionary<long,string?>();var candidates=new Dictionary<long,List<string>>();
        foreach(var m in methods.Values) {
            resources.Check();string? role=Role(m.Symbol);var reasons=new List<string>();var symbol=symbols[m.Symbol];
            if(m.EntryKind!="")reasons.Add(m.EntryKind);
            if(m.Exported&&!incoming.Contains(m.Id))reasons.Add("exported_without_known_caller");
            if(registrations.TryGetValue(m.Symbol,out var regs))reasons.AddRange(regs.OrderBy(x=>x,StringComparer.Ordinal));
            if(role is "operation" or "outcome" or "opaque")reasons.Add("policy_"+role);
            // A registration is inventory evidence, not an observation obligation.
            // Otherwise a timer that only polls/heartbeats would emit two events
            // on every tick. Only the actual application program entry is inferred.
            if(role==null&&reasons.Contains("program")&&policy.ApplicationAssemblies.Contains(symbol.Assembly,StringComparer.Ordinal))role="operation";
            roles[m.Id]=role;
            if(reasons.Count>0)candidates[m.Id]=reasons;
        }
        var instrumentedTargets=methods.Values.Where(m=>roles[m.Id] is "operation" or "outcome" or "opaque"&&m.Supported).Select(m=>m.Symbol).ToHashSet(StringComparer.Ordinal);
        var planner=new ApplicationProbePlanner(db,plan,resources,methods);
        progress?.Invoke("application_observations",new {methods=methods.Count,entry_candidates=candidates.Count,policy=policy.Name});
        foreach(var m in methods.Values) {
            resources.Check();var role=roles[m.Id];bool operation=role is "operation" or "outcome" or "opaque";
            bool expandControl=role is "operation" or "outcome";
            string classification=role=="technical"?"technical":role=="opaque"||operation&&!m.Supported?"opaque":operation?"observed":"unclassified";
            if(candidates.TryGetValue(m.Id,out var reasons)){plan.Entries.Add(new(m.Id,classification,JsonSerializer.Serialize(reasons),m.Signature,m.Project,m.Path,m.Variant));if(classification=="unclassified")plan.Unresolved++;}
            if(operation&&m.Supported)planner.Operation(m,role!,symbols[m.Symbol].Member==".ctor");
            else if(operation||role=="opaque")planner.Opaque(m,"unsupported_or_explicit_opaque_body");
            if(operation&&!m.Supported)continue;
            Rows("SELECT kind,symbol_key,anchor,edit_offset,span_start,span_end,repeated,payload FROM application_facts WHERE method_id=@p0 ORDER BY anchor,kind",r=>{
                string kind=r.GetString(0),key=r.GetString(1);bool repeated=r.GetInt32(6)!=0;using var payload=JsonDocument.Parse(r.GetString(7));var p=payload.RootElement;
                bool decision=p.TryGetProperty("references",out var refs)&&refs.EnumerateArray().Any(s=>Role(s.GetString()!)=="decision");
                string? targetRole=key==""?null:Role(key);
                bool selected=(kind is "arm" or "case" or "unsupported_control")&&(decision||expandControl&&!repeated)||kind=="unsupported_loop_control"&&decision||kind=="assignment"&&targetRole=="state_assignment";
                if(kind=="call"&&targetRole is "operation" or "outcome" or "opaque") {
                    // A source operation is witnessed in its own body, including
                    // repeated invocations. External/uninstrumentable calls need a caller boundary.
                    bool bodyAvailable=instrumentedTargets.Contains(key);
                    selected=!bodyAvailable;
                }
                if(selected) {
                    if(!m.PhysicalSource||!File.Exists(m.Path))planner.Opaque(m,"nonphysical_observation_source");
                    else planner.Fact(m,kind,r.GetInt32(2),r.GetInt32(3),r.GetInt32(4),r.GetInt32(5),p,kind=="assignment"?"state_assignment_completed":kind=="call"?"operation_call":"decision",repeated);
                }
            },m.Id);
        }
        // Source-level openness remains visible independently of probe coverage.
        var opaqueMethods=new HashSet<long>();
        Rows("SELECT DISTINCT method_id FROM call_sites WHERE resolution<>'static'",r=>opaqueMethods.Add(r.GetInt64(0)));
        Rows("SELECT DISTINCT m.id FROM methods m JOIN analysis_diagnostics d ON d.scope='method:'||m.id OR d.scope='document:'||m.document_id",r=>opaqueMethods.Add(r.GetInt64(0)));
        var observedMethods=plan.Bindings.Select(b=>plan.Observations[b.Observation].Method).ToHashSet();
        var flags=methods.Keys.ToDictionary(id=>id,id=>observedMethods.Contains(id)?1:0);
        // Monotone bit propagation, O(V+E) worklist rather than per-root reachability.
        var reverse=calls.GroupBy(c=>c.Callee).ToDictionary(g=>g.Key,g=>g.Select(c=>c.Caller).Distinct().ToArray());
        var queue=new Queue<long>(flags.Where(p=>p.Value!=0).Select(p=>p.Key));
        while(queue.TryDequeue(out long callee)){resources.Check();foreach(long caller in reverse.GetValueOrDefault(callee)??Array.Empty<long>())if(flags.ContainsKey(caller)&&flags[caller]==0){flags[caller]=1;queue.Enqueue(caller);}}
        for(int i=0;i<plan.Entries.Count;i++) {
            var entry=plan.Entries[i];
            if(entry.Classification=="unclassified"&&flags.GetValueOrDefault(entry.Method)!=0) {
                plan.Entries[i]=entry with {Classification="observed",Reasons=JsonSerializer.Serialize((JsonSerializer.Deserialize<string[]>(entry.Reasons)??Array.Empty<string>()).Append("observed_descendant_or_local_fact"))};
                plan.Unresolved--;
            }
        }
        opaqueMethods.UnionWith(methods.Values.Where(m=>!m.Supported||roles[m.Id]=="opaque").Select(m=>m.Id));
        queue=new(opaqueMethods);
        while(queue.TryDequeue(out long callee)){resources.Check();foreach(long caller in reverse.GetValueOrDefault(callee)??Array.Empty<long>())if(opaqueMethods.Add(caller))queue.Enqueue(caller);}
        Rows("SELECT DISTINCT m.method_id FROM application_facts f JOIN application_method_facts m ON m.symbol_key=f.symbol_key WHERE f.kind='call' AND f.repeated=1",r=>planner.Repeated.Add(r.GetInt64(0)));
        var forward=calls.GroupBy(c=>c.Caller).ToDictionary(g=>g.Key,g=>g.Select(c=>c.Callee).Distinct().ToArray());
        queue=new(planner.Repeated);
        while(queue.TryDequeue(out long caller)){resources.Check();foreach(long callee in forward.GetValueOrDefault(caller)??Array.Empty<long>())if(planner.Repeated.Add(callee))queue.Enqueue(callee);}
        foreach(var m in methods.Values)plan.Summaries.Add(new(m.Id,flags[m.Id],planner.Repeated.Contains(m.Id),opaqueMethods.Contains(m.Id)||!m.Supported||roles[m.Id]=="opaque"));
        var boundVariants=plan.Bindings.GroupBy(b=>b.Probe).ToDictionary(g=>g.Key,g=>g.Select(b=>plan.Observations[b.Observation].Variant).ToHashSet());
        foreach(var file in plan.Placements.Values.GroupBy(p=>p.Path,StringComparer.OrdinalIgnoreCase)) {
            var variants=new HashSet<long>();Rows("SELECT DISTINCT variant_id FROM documents WHERE origin='source' AND path=@p0 COLLATE NOCASE",r=>variants.Add(r.GetInt64(0)),file.Key);
            foreach(var placement in file)plan.UnmappedCompilationVariants+=variants.Count(v=>!boundVariants[placement.Probe].Contains(v));
        }
        ApplicationProfileVerifier.Verify(plan,resources.Check);
        plan.Inputs.Verify(token);
        var result=new TraceSelectionResult {Options=options,Application=plan,Status="applied_partial",Partial=plan.Unresolved>0||opaqueMethods.Count>0||plan.SharedAmbiguities>0||plan.UnmappedCompilationVariants>0||roles.Values.Contains("opaque")||plan.Observations.Values.Any(o=>o.Status!="modeled"),
            ProbeCount=plan.ExistingProbes+plan.NewProbes.Count,CorpusFingerprint=ContextCatalog.Id(policy.Fingerprint,string.Join(';',plan.Observations.Keys.OrderBy(k=>k,StringComparer.Ordinal)))};
        if(!result.Partial)result.Status="applied";
        foreach(long id in planner.AllIds)if(!plan.Enabled.Contains(id))result.Disabled.Add(id);
        foreach(long id in plan.Enabled)result.Protected[id]=plan.Reasons[id];
        foreach(var entry in plan.Entries)result.Roots.Add(new(entry.Method){Status=entry.Classification});
        result.PeakBufferBytes=resources.PeakBytes;result.DurationSeconds=resources.Seconds;
        progress?.Invoke("application_verified",plan.Summary);return result;
    }
}

public sealed class ApplicationProbePlanner
{
    private readonly SqliteConnection db;private readonly ApplicationPlan plan;private readonly SelectionResources resources;
    private readonly Dictionary<(string Path,int Offset),long> offsets=new();
    private readonly Dictionary<string,string> canonicalPaths=new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<long,ApplicationPlacement> previous=new();
    private readonly Dictionary<string,(long Enter,long Error,long Leave)> groups=new(StringComparer.Ordinal);
    private string currentPath="",currentText="",currentRawHash="",currentWorkspaceHash="";private SourceText currentSource=SourceText.From("");private long next,sourceBytes;
    private readonly HashSet<long> edited=new();
    public HashSet<long> AllIds {get;}=new();public HashSet<long> Repeated {get;}=new();
    internal ApplicationProbePlanner(SqliteConnection db,ApplicationPlan plan,SelectionResources resources,Dictionary<long,ApplicationMethod> methods) {
        this.db=db;this.plan=plan;this.resources=resources;
        using var c=db.CreateCommand();c.CommandText="SELECT id,file_path,injection_offset FROM basic_blocks ORDER BY id";
        using(var r=c.ExecuteReader())while(r.Read()){resources.Check();resources.Reserve(256+r.GetString(1).Length*2L);long id=r.GetInt64(0);AllIds.Add(id);canonicalPaths.TryAdd(r.GetString(1),r.GetString(1));offsets[(r.GetString(1).ToUpperInvariant(),r.GetInt32(2))]=id;next=Math.Max(next,id);}
        plan.ExistingProbes=AllIds.Count;
        c.CommandText="SELECT * FROM application_placements";using(var r=c.ExecuteReader())while(r.Read()){resources.Reserve(1024+r.GetString(2).Length*2L);previous[r.GetInt64(0)]=new(r.GetInt64(0),r.GetString(1),r.GetString(2),r.GetInt32(3),r.GetInt32(4),r.GetInt32(5),r.GetString(6),r.GetString(7));}
    }
    private void Source(ApplicationMethod m) {
        resources.Check();if(string.Equals(currentPath,m.Path,StringComparison.OrdinalIgnoreCase)) {
            if(currentWorkspaceHash!=m.Hash)throw new InvalidOperationException("Shared application input texts differ: "+m.Path);return;
        }
        if(sourceBytes>0)resources.Release(sourceBytes);
        long length=new FileInfo(m.Path).Length;sourceBytes=8192+length*24L;resources.Reserve(sourceBytes);
        currentText=File.ReadAllText(m.Path);currentWorkspaceHash=ContextCatalog.Id(currentText);if(currentWorkspaceHash!=m.Hash)throw new InvalidOperationException("Application input changed: "+m.Path);
        currentRawHash=Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(currentText))).ToLowerInvariant();
        currentPath=m.Path;canonicalPaths.TryAdd(m.Path,m.Path);currentSource=SourceText.From(currentText);plan.Inputs.Track(m.Path,currentText);
    }
    private long Probe(ApplicationMethod m,string kind,int anchor,int start,int end,string group) {
        Source(m);var k=(m.Path.ToUpperInvariant(),anchor);
        if(!offsets.TryGetValue(k,out long id)) {
            id=++next;offsets[k]=id;AllIds.Add(id);int line=currentSource.Lines.GetLineFromPosition(Math.Clamp(anchor,0,currentSource.Length)).LineNumber+1;
            int first=currentSource.Lines.GetLineFromPosition(m.Start).LineNumber+1,last=currentSource.Lines.GetLineFromPosition(Math.Min(m.Start+m.Length,currentSource.Length)).LineNumber+1;
            plan.NewProbes.Add((id,new BasicBlockRecord {ProjectName=m.Project,FilePath=canonicalPaths[m.Path],MethodSignature=m.Signature,ScopeStartLine=first,ScopeEndLine=last,BlockStartLine=first,BlockEndLine=last,InjectionLine=line,InjectionOffset=anchor,Reason="Application observation: "+kind,ToTrace=true}));
        } else if(!previous.ContainsKey(id)&&!plan.Placements.ContainsKey(id)&&kind is not ("before" or "wrap"))throw new InvalidOperationException("Incompatible application/legacy anchor at "+m.Path+":"+anchor);
        var placement=new ApplicationPlacement(id,kind,canonicalPaths[m.Path],anchor,start,end,currentRawHash,group);
        if(previous.TryGetValue(id,out var old)&&old!=placement||plan.Placements.TryGetValue(id,out var existing)&&existing!=placement)throw new InvalidOperationException("Incompatible application placement at "+m.Path+":"+anchor);
        if(plan.Placements.TryAdd(id,placement))resources.Reserve(1024+m.Path.Length*2L);
        plan.Enabled.Add(id);plan.Reasons[id]="application_observation_witness";return id;
    }
    private string Observation(ApplicationMethod m,string kind,string evidence,long? probe,int anchor,string status="modeled") {
        string id=ContextCatalog.Id(m.Variant,m.Symbol,m.Start,kind,anchor,evidence);
        if(plan.Observations.TryAdd(id,new(id,m.Id,m.Variant,kind,evidence,null,status)))resources.Reserve(512+evidence.Length*2L);
        if(probe.HasValue)plan.Bindings.Add(new(id,probe.Value));
        return id;
    }
    private void Locate(string observation,ApplicationMethod m,string sql,params object[] args) {
        using var cmd=db.CreateCommand();cmd.CommandText=sql;cmd.Parameters.AddWithValue("@method",m.Id);
        for(int i=0;i<args.Length;i++)cmd.Parameters.AddWithValue("@p"+i,args[i]);
        using var r=cmd.ExecuteReader();ApplicationLocation? location=null;int count=0;
        while(r.Read()){resources.Check();count++;location=new(observation,r.GetInt64(0),r.GetInt32(1),r.IsDBNull(2)?null:r.GetInt64(2));if(count>1)break;}
        if(count==1)plan.Locations[observation]=location!;
    }
    private static string Log(long id)=>"\n#line hidden\nAITracer.Runtime.TraceContext.Log("+id+");\n#line default\n";
    internal void Operation(ApplicationMethod m,string role,bool constructor) {
        Source(m);string group=ContextCatalog.Id(m.Path.ToUpperInvariant(),m.BodyStart,m.BodyEnd);
        if(!groups.TryGetValue(group,out var ids)) {
            bool expression=m.ExpressionStart>=0;
            int startAnchor=expression?(currentText.AsSpan(m.BodyStart,Math.Min(2,currentText.Length-m.BodyStart)).SequenceEqual("=>")?m.BodyStart:m.BodyStart-2):m.BodyStart-1;
            long enter=Probe(m,"operation_enter",startAnchor,m.BodyStart,m.BodyEnd,group);
            long leave=Probe(m,"operation_leave",expression?m.ExpressionEnd:m.BodyEnd,m.BodyStart,m.BodyEnd,group);
            long error=Probe(m,"operation_error",expression?startAnchor+1:m.BodyEnd+1,m.BodyStart,m.BodyEnd,group);
            ids=(enter,error,leave);groups[group]=ids;
            string prefix=Log(enter)+"try {\n",suffix="\n} catch {"+Log(error)+"throw; } finally {"+Log(leave)+"}\n";
            if(expression) {
                string expr=currentText[m.ExpressionStart..m.ExpressionEnd];
                plan.Edits.Add(new(m.Path,m.BodyStart,m.BodyEnd-m.BodyStart,"{"+prefix+m.ReturnPrefix+expr+";"+suffix+"}",0,enter));
            } else {
                plan.Edits.Add(new(m.Path,m.BodyStart,0,prefix,0,enter));plan.Edits.Add(new(m.Path,m.BodyEnd,0,suffix,1000000,enter));
            }
        }
        string enterObservation=Observation(m,"operation_enter",role,ids.Enter,m.BodyStart);
        Observation(m,"operation_error","escaping_exception; rethrow preserves stack",ids.Error,m.BodyEnd);
        string leaveObservation=Observation(m,"operation_leave",m.ExitSemantics,ids.Leave,m.BodyEnd);
        if(constructor) {
            // Constructor initializers execute before the source-body wrapper.
            Locate(enterObservation,m,"SELECT p.node_id,p.position,NULL FROM flow_points p JOIN flow_nodes n ON n.id=p.node_id WHERE n.method_id=@method AND n.reachable=1 AND p.kind='source_before' AND p.start>=@p0 AND p.start<@p1 ORDER BY p.start,p.position LIMIT 1",m.BodyStart,m.BodyEnd);
            if(!plan.Locations.ContainsKey(enterObservation))Locate(enterObservation,m,"SELECT n.id,p.position,NULL FROM flow_nodes n JOIN flow_points p ON p.node_id=n.id WHERE n.method_id=@method AND n.reachable=1 AND p.kind='exit'");
        } else Locate(enterObservation,m,"SELECT id,0,NULL FROM flow_nodes WHERE method_id=@method AND kind='Entry'");
        Locate(leaveObservation,m,"SELECT n.id,p.position,NULL FROM flow_nodes n JOIN flow_points p ON p.node_id=n.id WHERE n.method_id=@method AND p.kind='exit'");
    }
    internal void Opaque(ApplicationMethod m,string reason)=>Observation(m,"opaque",reason,null,m.Start,"opaque");
    internal void Fact(ApplicationMethod m,string fact,int anchor,int edit,int start,int end,JsonElement payload,string observation,bool repeated) {
        Source(m);string style=payload.GetProperty("style").GetString()!;
        if(style=="unsupported"||edit<0){Observation(m,"opaque",observation+": unsupported expression placement",null,anchor,"opaque");return;}
        string evidence=payload.TryGetProperty("label",out var label)?label.GetString()!:observation;
        string group=ContextCatalog.Id(m.Path.ToUpperInvariant(),fact,anchor,style);
        long id=Probe(m,style,anchor,start,end,group);
        if(repeated)Repeated.Add(m.Id);
        string text=style switch {"wrap"=>"{"+Log(id),"else"=>" else {"+Log(id)+"}",_=>Log(id)};
        // Same physical observation selected in several variants emits only once.
        if(edited.Add(id)) {
            int depth=payload.TryGetProperty("depth",out var d)?d.GetInt32():0;
            plan.Edits.Add(new(m.Path,edit,0,text,style=="after"?100:style=="else"?100000-depth*100+10:2000000,id));
            if(style=="wrap")plan.Edits.Add(new(m.Path,payload.GetProperty("arm_end").GetInt32(),0,"\n}",100000-depth*100,id));
        }
        string oid=Observation(m,observation,evidence,id,anchor);
        if(fact=="arm") {
            Locate(oid,m,"SELECT p.node_id,2147483647,e.id FROM flow_points p JOIN flow_nodes n ON n.id=p.node_id JOIN flow_edges e ON e.source_id=n.id WHERE n.method_id=@method AND p.kind='control' AND p.start=@p0 AND p.length=@p1 AND e.alternative=@p2",payload.GetProperty("condition_start").GetInt32(),payload.GetProperty("condition_length").GetInt32(),payload.GetProperty("truth").GetBoolean()?"true":"false");
        } else {
            int position=fact=="case"?payload.GetProperty("first_statement").GetInt32():style=="after"?end:start;
            Locate(oid,m,style=="after"?
                "SELECT p.node_id,p.position,NULL FROM flow_points p JOIN flow_nodes n ON n.id=p.node_id WHERE n.method_id=@method AND p.kind='source_after' AND p.start IN (@p0,@p1)":
                "SELECT p.node_id,p.position,NULL FROM flow_points p JOIN flow_nodes n ON n.id=p.node_id WHERE n.method_id=@method AND p.kind='source_before' AND p.start=@p0",position,position-1);
        }
        if(fact=="call") {
            int after=payload.GetProperty("after").GetInt32();
            if(after>=0) {
                int nextAnchor=Math.Max(start,after-1);long completed=Probe(m,"after",nextAnchor,start,end,group+":completed");
                if(edited.Add(completed))plan.Edits.Add(new(m.Path,after,0,Log(completed),100,completed));
                string completedObservation=Observation(m,"call_statement_completed",evidence,completed,nextAnchor,"opaque");
                Locate(completedObservation,m,"SELECT p.node_id,p.position,NULL FROM flow_points p JOIN flow_nodes n ON n.id=p.node_id WHERE n.method_id=@method AND p.kind='source_after' AND p.start IN (@p0,@p1)",end,end-1);
            }
        }
    }
}

public static class ApplicationProfileVerifier
{
    internal static void Verify(ApplicationPlan plan,Action check) {
        if(plan.Observations.Count==0||plan.Enabled.Count==0)throw new InvalidOperationException("Policy selected no instrumentable application observations; profile not published");
        var covered=plan.Bindings.Select(b=>b.Observation).ToHashSet(StringComparer.Ordinal);
        foreach(var o in plan.Observations.Values){check();if(o.Status=="modeled"&&!covered.Contains(o.Id))throw new InvalidOperationException("Uncovered application observation: "+o.Id);}
        foreach(var b in plan.Bindings){check();if(!plan.Enabled.Contains(b.Probe)||!plan.Placements.ContainsKey(b.Probe))throw new InvalidOperationException("Observation has no enabled placement");}
        plan.SharedAmbiguities=plan.Bindings.GroupBy(b=>b.Probe).Count(g=>g.Select(b=>plan.Observations[b.Observation].Variant).Distinct().Skip(1).Any());
        // Do not let a source edit delete another active source observation.
        foreach(var group in plan.Edits.GroupBy(e=>e.Path,StringComparer.OrdinalIgnoreCase)) {
            var replacements=group.Where(e=>e.Remove>0).OrderBy(e=>e.Offset).ToArray();
            for(int i=1;i<replacements.Length;i++)if(replacements[i].Offset<replacements[i-1].Offset+replacements[i-1].Remove)throw new InvalidOperationException("Overlapping application expression rewrites");
            foreach(var replace in replacements)if(group.Any(e=>e!=replace&&e.Offset>replace.Offset&&e.Offset<replace.Offset+replace.Remove))throw new InvalidOperationException("Expression rewrite overlaps an observation");
        }
    }
}
