using System.Text.Json;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Data.Sqlite;

namespace RoslynAnalyzer;

/// <summary>Static normal-flow abstraction. Analysis failures never enable an all-probe fallback.</summary>
public static class StaticFlowSelection
{
    public static int AnalyzeOnly(string[] args,Action<string,object?> progress) {
        if(args.Length<3)throw new ArgumentException("Usage: --analyze-static-catalog <input.sqlite> <report-directory> [selection options]");
        var options=new TraceSelectionOptions {Mode="static",AmbiguityBudget=0};
        for(int i=3;i<args.Length;i+=2){if(i+1>=args.Length)throw new ArgumentException("Missing selection option value");options=TraceSelectionOptions.ParseOption(options,args[i],args[i+1]);}
        if(options.Mode!="static")throw new ArgumentException("Static analysis-only command requires mode=static");
        options.Validate();var result=Build(Path.GetFullPath(args[1]),options,default,progress);
        string output=Path.GetFullPath(args[2]);Directory.CreateDirectory(output);TraceSelectionStore.WriteApplicationReport(output,result);
        Console.WriteLine(JsonSerializer.Serialize(new {state="analyzed",database_modified=false,report=Path.Combine(output,"static-flow-report.json"),selection=result.Static!.Summary}));return 2;
    }
    public static TraceSelectionResult Build(string path,TraceSelectionOptions options,CancellationToken token=default,Action<string,object?>? progress=null)
    {
        var resources=new SelectionResources(options,token){PhaseFraction=1};
        using var db=new SqliteConnection(new SqliteConnectionStringBuilder {DataSource=path,Mode=SqliteOpenMode.ReadOnly,Pooling=false}.ToString());db.Open();
        void Rows(string sql,Action<SqliteDataReader> read,params object[] values){using var c=db.CreateCommand();c.CommandText=sql;for(int i=0;i<values.Length;i++)c.Parameters.AddWithValue("@p"+i,values[i]);using var r=c.ExecuteReader();while(r.Read()){resources.Check();read(r);}}
        string? contract=null;Rows("SELECT value FROM analysis_manifest WHERE key='injection_contract'",r=>contract=r.GetString(0));
        if(contract!=null&&contract!=StaticFlowPlan.Contract)throw new InvalidOperationException("Regenerate the catalog in static mode; application wrappers cannot be requalified as blind probes");
        var policy=options.ObservationPolicy.Length==0?null:ApplicationPolicy.Load(options.ObservationPolicy);
        var placement=new ApplicationPlan {PolicyFingerprint=policy?.Fingerprint??ContextCatalog.Id("static-default"),PolicyJson=policy==null?"{}":File.ReadAllText(options.ObservationPolicy)};
        if(policy!=null)placement.Inputs.Track(options.ObservationPolicy,File.ReadAllText(options.ObservationPolicy));
        var plan=new StaticFlowPlan {RepeatPolicy=options.RepeatPolicy};
        var methods=new Dictionary<long,ApplicationMethod>();
        Rows("""
          SELECT m.id,m.variant_id,m.signature,d.path,d.hash,v.name,m.start,m.length,f.symbol_key,f.body_start,f.body_end,f.expression_start,f.expression_end,f.return_prefix,f.exported,f.entry_kind,f.is_async,f.is_iterator,f.exit_semantics,f.supported,d.origin
          FROM application_method_facts f JOIN methods m ON m.id=f.method_id JOIN documents d ON d.id=m.document_id JOIN project_variants v ON v.id=m.variant_id
          ORDER BY d.path COLLATE NOCASE,m.start,m.id
          """,r=>{resources.Reserve(1200+r.GetString(3).Length*2L);methods[r.GetInt64(0)]=new(r.GetInt64(0),r.GetInt64(1),r.GetString(2),r.GetString(3),r.GetString(4),r.GetString(5),r.GetInt32(6),r.GetInt32(7),r.GetString(8),r.GetInt32(9),r.GetInt32(10),r.GetInt32(11),r.GetInt32(12),r.GetString(13),r.GetInt32(14)!=0,r.GetString(15),r.GetInt32(16)!=0,r.GetInt32(17)!=0,r.GetString(18),r.GetInt32(19)!=0,r.GetString(20)=="source");});
        if(methods.Count==0)throw new InvalidOperationException("Static mode requires schema 7+ method facts; regenerate the catalog");
        var roles=new Dictionary<string,string?>();
        var constructors=new HashSet<string>();
        Rows("SELECT key,description FROM application_symbols",r=>{var symbol=JsonSerializer.Deserialize<ApplicationSymbol>(r.GetString(1))!;roles[r.GetString(0)]=policy?.Role(symbol);if(symbol.Member==".ctor")constructors.Add(symbol.Key);});
        progress?.Invoke("static_local_graphs",new {methods=methods.Count});
        var model=StaticFlowModel.Load(db,methods.Keys,resources);
        foreach(var group in model.CyclicNodes.GroupBy(n=>model.Components[n])) {
            var members=group.OrderBy(n=>n).ToArray();plan.Regions.Add(new("loop:"+group.Key,"loop",model.Nodes[members[0]].Method,members,options.RepeatPolicy,"iteration count, internal order and nonescaping anomalies are omitted unless detail is selected"));
        }
        foreach(var component in model.MethodComponents.Where(c=>model.Recursive.Contains(c[0])))plan.Regions.Add(new("recursion:"+component[0],"recursion",component[0],component,options.RepeatPolicy,"activation depth and internal recursive paths are omitted unless detail is selected"));
        var planner=new ApplicationProbePlanner(db,placement,resources,methods);
        var technical=methods.Values.Where(m=>roles.GetValueOrDefault(m.Symbol)=="technical").Select(m=>m.Id).ToHashSet();
        var hidden=options.RepeatPolicy=="detail"?new HashSet<long>():new HashSet<long>(model.Repeated);
        hidden.UnionWith(technical);
        foreach(var m in methods.Values) {
            resources.Check();
            if(m.Async||m.Iterator||!m.Supported||roles.GetValueOrDefault(m.Symbol)=="opaque")model.Opaque.Add(m.Id);
            if(!m.Supported||!m.PhysicalSource||hidden.Contains(m.Id))continue;
            planner.BlindEntry(m,constructors.Contains(m.Symbol));
            if(options.RepeatPolicy=="boundaries"&&model.MethodNodes[m.Id].Any(model.CyclicNodes.Contains))planner.BlindLoopBoundaries(m);
            // Explicit source call boundaries witness attempts and statement completion.
            // They use existing control flow and do not wrap expressions or exceptions.
            Rows("SELECT id,kind,anchor,edit_offset,span_start,span_end,repeated,payload,symbol_key FROM application_facts WHERE method_id=@p0 AND kind='call' ORDER BY anchor",r=>{
                using var payload=JsonDocument.Parse(r.GetString(7));var p=payload.RootElement;
                if(r.GetInt32(3)<0||p.GetProperty("style").GetString()=="unsupported")return;
                if(options.RepeatPolicy!="detail"&&r.GetInt32(6)!=0)return;
                planner.Fact(m,"call",r.GetInt32(2),r.GetInt32(3),r.GetInt32(4),r.GetInt32(5),p,"call_attempt",r.GetInt32(6)!=0,r.GetInt64(0));
            },m.Id);
            if(policy!=null)Rows("SELECT id,kind,anchor,edit_offset,span_start,span_end,repeated,payload,symbol_key FROM application_facts WHERE method_id=@p0 AND kind IN ('arm','case','assignment') ORDER BY anchor",r=>{
                using var payload=JsonDocument.Parse(r.GetString(7));var p=payload.RootElement;string kind=r.GetString(1);
                bool selected=kind=="assignment"?roles.GetValueOrDefault(r.GetString(8))=="state_assignment":
                    roles.GetValueOrDefault(m.Symbol) is "operation" or "outcome"||p.TryGetProperty("references",out var refs)&&refs.EnumerateArray().Any(s=>roles.GetValueOrDefault(s.GetString()!)=="decision");
                if(!selected||r.GetInt32(3)<0||p.GetProperty("style").GetString()=="unsupported"||options.RepeatPolicy!="detail"&&r.GetInt32(6)!=0)return;
                planner.Fact(m,kind,r.GetInt32(2),r.GetInt32(3),r.GetInt32(4),r.GetInt32(5),p,kind=="assignment"?"state_assignment_completed":"decision",r.GetInt32(6)!=0,r.GetInt64(0));
            },m.Id);
        }
        // Current and newly appended probe IDs form the candidate universe, independent of old flags.
        var all=planner.AllIds;
        foreach(var binding in placement.Bindings) {
            var observation=placement.Observations[binding.Observation];
            if(!model.Owners.TryGetValue(binding.Probe,out var owners))model.Owners[binding.Probe]=owners=new();owners.Add(observation.Method);
        }
        foreach(long probe in placement.Bindings.Select(b=>b.Probe).Distinct())model.Links.Remove(probe);
        var locations=placement.Locations.GroupBy(l=>l.Observation).ToDictionary(g=>g.Key,g=>g.ToArray());
        foreach(var binding in placement.Bindings)foreach(var location in locations.GetValueOrDefault(binding.Observation)??Array.Empty<ApplicationLocation>()) {
            if(!model.Nodes.ContainsKey(location.Node))continue;
            if(!model.Links.TryGetValue(binding.Probe,out var links))model.Links[binding.Probe]=links=new();
            if(location.Edge==null)links.Add((location.Node,location.Position));
            else model.Opaque.Add(placement.Observations[binding.Observation].Method);
        }
        var suppressed=new HashSet<long>();
        foreach(long id in all.OrderBy(x=>x)) {
            var owners=model.Owners.GetValueOrDefault(id)??new();var links=model.Links.GetValueOrDefault(id)??new();
            bool repeat=owners.Any(model.Repeated.Contains)||links.Any(l=>model.CyclicNodes.Contains(l.Node));
            string? reason=owners.Any(technical.Contains)?"suppressed_by_observation_scope":options.RepeatPolicy!="detail"&&repeat?"suppressed_by_repeat_policy":null;
            if(options.RepeatPolicy=="silent"&&owners.Any(m=>model.MethodNodes.GetValueOrDefault(m)?.Any(model.CyclicNodes.Contains)==true))reason="suppressed_by_repeat_policy";
            if(reason!=null){suppressed.Add(id);plan.Decisions[id]=new(id,false,reason,"Global source-point decision; applies to every caller and compilation variant. Internal repetition detail is not reconstructible.");continue;}
            foreach(var link in links)if(model.Nodes.TryGetValue(link.Node,out var node))node.Events.Add(new(link.Position,id));
            string evidence=links.Count==0?"No exact CFG placement; retained without a reconstruction claim":"Candidate exact point in the normal-flow model";
            plan.Decisions[id]=new(id,true,links.Count==0?"unresolved_analysis":"retained_discriminator",evidence);
            if(links.Count==0)model.Opaque.UnionWith(owners);
        }
        foreach(var n in model.Nodes.Values)n.Events=n.Events.Distinct().OrderBy(e=>e.Position).ThenBy(e=>e.Callee==0?0:1).ThenBy(e=>e.Probe).ToList();
        // A physical marker shared across compilation variants must be safe in all owners.
        Rows("""
          SELECT DISTINCT l.method_id FROM legacy_block_links l JOIN basic_blocks b ON b.id=l.legacy_id
          WHERE l.point_id IS NULL OR EXISTS(SELECT 1 FROM documents d WHERE d.origin='source' AND d.path=b.file_path COLLATE NOCASE
            AND NOT EXISTS(SELECT 1 FROM legacy_probe_variants v WHERE v.legacy_id=b.id AND v.variant_id=d.variant_id))
          """,r=>model.Opaque.Add(r.GetInt64(0)));
        progress?.Invoke("static_interprocedural_summaries",new {regions=plan.Regions.Count,repeated_methods=model.Repeated.Count});
        var languages=new Dictionary<long,List<TraceWord>>();var qualified=new HashSet<long>();
        // SCC order is caller-first. Reverse order substitutes already-built callee languages.
        foreach(var component in model.MethodComponents.AsEnumerable().Reverse())foreach(long method in component) {
            resources.Check();
            bool abstracted=hidden.Contains(method);
            bool loop=model.MethodNodes[method].Any(model.CyclicNodes.Contains);
            List<TraceWord>? words;
            if(abstracted&&model.Calls[method].All(hidden.Contains)&&!model.Opaque.Contains(method))words=new(){new(Array.Empty<long>())};
            else if(model.Recursive.Contains(method)||model.Opaque.Contains(method)||model.Calls[method].Any(c=>!languages.ContainsKey(c)||!qualified.Contains(c)&&!hidden.Contains(c)))words=null;
            else words=Enumerate(method,model,languages,options,resources);
            if(words!=null){languages[method]=words;if(!abstracted&&!model.Opaque.Contains(method))qualified.Add(method);}
            string status=abstracted?(words==null?"policy_abstracted_opaque":"policy_abstracted"):words==null?"unresolved_analysis":model.Opaque.Contains(method)?"baseline_ambiguous":loop||model.Calls[method].Any(hidden.Contains)?"qualified_abstraction":"qualified_normal_flow";
            string emission=words==null?"unknown":abstracted&&words.All(w=>w.Events.Length==0)?"silent":options.RepeatPolicy=="detail"&&(loop||model.Repeated.Contains(method))?"potentially_unbounded":"bounded_in_declared_model";
            plan.Methods.Add(new(method,status,model.Repeated.Contains(method),model.Opaque.Contains(method),words?.Count??0,emission,
                abstracted?"Local execution detail and termination are not observed; non-suppressed callee observations remain in the language when known":words==null?"Open call, unsupported transfer, recursive detail or state budget prevents proof":"Finite normal-flow language with balanced call-site substitution; silent SCC internals abstracted; feasibility is conservative"));
            plan.Obligations.Add(new(method,"ordered_normal_paths",status,"Preserve distinct full candidate-marker words within the declared abstraction; identical baseline words are not proven distinct control paths"));
        }
        // Protect unresolved method owners: their behavior cannot justify a deletion.
        var protectedIds=model.Owners.Where(p=>p.Value.Any(m=>!qualified.Contains(m)&&!hidden.Contains(m))).Select(p=>p.Key).ToHashSet();
        foreach(var binding in placement.Bindings)if(placement.Observations[binding.Observation].Kind is "call_attempt" or "call_statement_completed" or "decision" or "state_assignment_completed")protectedIds.Add(binding.Probe);
        foreach(long id in all)if(!model.Links.ContainsKey(id))protectedIds.Add(id);
        var corpus=new Dictionary<TraceWord,long>();
        foreach(long method in qualified)foreach(var word in languages[method]){resources.Check();corpus[word]=1;}
        var fit=TraceSequenceSelector.Select(corpus.Keys.Select(w=>new TraceObservation(w,1,1)),protectedIds,0,1,()=>resources.HasTime,resources.Reserve,resources.Release,token);
        if(fit.TimeLimited)throw new InvalidOperationException("Static proof deadline exceeded; no all-probe fallback is published");
        foreach(long id in fit.Disabled)if(!suppressed.Contains(id))plan.Decisions[id]=new(id,false,"suppressed_proven_redundant","Removing this ID preserves every ordered baseline-marker word in the complete finite declared corpus; baseline observability gaps remain explicit");
        foreach(var p in plan.Decisions.Values)if(p.Enabled&&protectedIds.Contains(p.Probe)) {
            bool unresolved=!model.Links.ContainsKey(p.Probe)||(model.Owners.GetValueOrDefault(p.Probe)??new()).Any(m=>!qualified.Contains(m)&&!hidden.Contains(m));
            plan.Decisions[p.Probe]=p with {Reason=unresolved?"unresolved_analysis":"retained_obligation"};
        }
        foreach(long method in qualified)plan.Witnesses[method]=languages[method].Select(w=>w.Events).ToArray();
        placement.Enabled.Clear();foreach(var d in plan.Decisions.Values){placement.Reasons[d.Probe]=d.Reason;if(d.Enabled)placement.Enabled.Add(d.Probe);}
        foreach(var edit in placement.Edits)if(!StaticFlowPlan.IsBlindEdit(edit))throw new InvalidOperationException("Static instrumentation contains a non-blind source edit");
        var sourcePaths=new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        Rows("SELECT id,file_path FROM basic_blocks",r=>{if(plan.Decisions.TryGetValue(r.GetInt64(0),out var decision)&&decision.Enabled)sourcePaths.Add(r.GetString(1));});
        foreach(var p in placement.Placements.Values)if(placement.Enabled.Contains(p.Probe))sourcePaths.Add(p.Path);
        var hashes=methods.Values.GroupBy(m=>m.Path,StringComparer.OrdinalIgnoreCase).ToDictionary(g=>g.Key,g=>g.Select(m=>m.Hash).Distinct().ToArray(),StringComparer.OrdinalIgnoreCase);
        foreach(string source in sourcePaths) {
            resources.Check();long charge=8192+new FileInfo(source).Length*8;resources.Reserve(charge);
            try {
                string text=File.ReadAllText(source);
                if(hashes.TryGetValue(source,out var expected)&&expected.Any(h=>h!=ContextCatalog.Id(text)))throw new InvalidOperationException("Source changed since static extraction: "+source);
                placement.Inputs.Track(source,text);plan.SourceHashes[source]=Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(text))).ToLowerInvariant();
            } finally {resources.Release(charge);}
        }
        placement.Inputs.Verify(token);
        var result=new TraceSelectionResult {Options=options,Application=placement,Static=plan,Partial=true,Status="applied_partial",ProbeCount=all.Count,
            CorpusFingerprint=ContextCatalog.Id(plan.Summary,string.Join(';',plan.Decisions.Values.OrderBy(d=>d.Probe).Select(d=>$"{d.Probe}:{d.Enabled}:{d.Reason}"))),Fit=fit};
        foreach(var d in plan.Decisions.Values)if(!d.Enabled)result.Disabled.Add(d.Probe);
        foreach(var m in plan.Methods)result.Roots.Add(new(m.Method){Status=m.Status});
        result.PeakBufferBytes=resources.PeakBytes;result.DurationSeconds=resources.Seconds;
        progress?.Invoke("static_verified",plan.Summary);return result;
    }

    private static List<TraceWord>? Enumerate(long method,StaticFlowModel model,Dictionary<long,List<TraceWord>> languages,TraceSelectionOptions options,SelectionResources resources)
    {
        var nodes=model.MethodNodes[method];long entry=nodes.FirstOrDefault(n=>model.Nodes[n].Kind=="Entry");if(entry==0)return null;
        var groups=nodes.GroupBy(n=>model.Components[n]).ToDictionary(g=>g.Key,g=>g.ToArray());
        var outputs=new HashSet<TraceWord>();var pending=new Stack<(long Component,long[] Word)>();pending.Push((model.Components[entry],Array.Empty<long>()));
        int states=0;long bytes=0;
        try {
            while(pending.TryPop(out var state)) {
                resources.Check();if(++states>options.MaxFlowStates)return null;
                var members=groups[state.Component];bool cyclic=members.Any(model.CyclicNodes.Contains);
                if(cyclic&&options.RepeatPolicy=="detail")return null;
                var words=new List<long[]>{state.Word};
                if(!cyclic)foreach(var ev in model.Nodes[members[0]].Events) {
                    var additions=ev.Callee==0?new List<TraceWord>{new(new[]{ev.Probe})}:languages[ev.Callee];
                    if((long)words.Count*additions.Count>options.MaxFlowStates)return null;
                    var expanded=new List<long[]>();foreach(var prefix in words)foreach(var suffix in additions){resources.Check();long size=128L+(prefix.Length+suffix.Events.Length)*8L;resources.Reserve(size);bytes+=size;expanded.Add(prefix.Concat(suffix.Events).ToArray());}
                    words=expanded;
                }
                if(members.Any(n=>model.Nodes[n].Kind=="Exit"))foreach(var word in words)if(!outputs.Add(new(word)))model.Opaque.Add(method);
                var edges=members.SelectMany(n=>model.Nodes[n].Edges).Where(e=>e.Complete&&model.Components[e.Target]!=state.Component).Select(e=>model.Components[e.Target]).Distinct();
                foreach(long next in edges)foreach(var word in words){if(++states>options.MaxFlowStates)return null;pending.Push((next,word));}
            }
            if(outputs.Count==0)return null;
            var result=outputs.OrderBy(w=>string.Join(',',w.Events),StringComparer.Ordinal).ToList();
            resources.Reserve(result.Sum(w=>128L+w.Events.Length*8L));return result;
        } finally {resources.Release(bytes);}
    }
}
