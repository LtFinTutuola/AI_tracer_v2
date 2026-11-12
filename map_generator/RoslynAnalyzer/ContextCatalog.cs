using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.FlowAnalysis;
using Microsoft.CodeAnalysis.Operations;
using Microsoft.Data.Sqlite;

namespace RoslynAnalyzer;

/// <summary>Schema 7: compact local flow and semantic application frontiers.</summary>
public sealed partial class ContextCatalog : IDisposable
{
    public const int SchemaVersion=7;
    private readonly SqliteConnection db;
    private SqliteTransaction? tx;
    private readonly Dictionary<string,SqliteCommand> commands=new();
    private readonly Dictionary<long,string> variantKeys=new();
    private sealed record SharedPoint(long Id,LegacyProjectionRecord Record,LegacyProjectionSnapshot FirstProjection);
    private sealed class SharedFile(string canonicalPath)
    {
        public string CanonicalPath { get; }=canonicalPath;
        public Dictionary<int,SharedPoint> Points { get; }=new();
    }
    private readonly Dictionary<string,SharedFile> shared=new(StringComparer.OrdinalIgnoreCase);
    public IReadOnlyList<TraceableBlock> LastNewProbes { get; private set; }=Array.Empty<TraceableBlock>();
    public int LastNewCount { get; private set; }
    public int LastReusedCount { get; private set; }
    public int LastDiscardedConflictCount { get; private set; }
    public long SharedProbeNew { get; private set; }
    public long SharedProbeReused { get; private set; }
    public long SharedProbeDiscardedConflicts { get; private set; }
    public InputRegistry Inputs { get; }
    public long GraphsCreated { get; private set; }
    public long CfgRequests { get; private set; }
    public long DocumentsAnalyzed { get; private set; }
    public long WriteTicks { get; private set; }
    public int DiagnosticCount { get; private set; }
    public Dictionary<string,double> FinalizationMilliseconds { get; }=new();
    public Dictionary<string,long> Counts { get; }=new();
    private readonly string framework;
    private readonly string configuration;
    public ContextCatalog(string path,string framework,string configuration,InputRegistry? inputs=null)
    {
        this.framework=framework; this.configuration=configuration;Inputs=inputs??new();
        db=new(new SqliteConnectionStringBuilder {DataSource=path,Pooling=false}.ToString()); db.Open();
        Run("PRAGMA foreign_keys=ON; PRAGMA journal_mode=DELETE;");
        Run(SqliteRepository.Schema);
        Run("""
          CREATE TABLE analysis_manifest(key TEXT PRIMARY KEY,value TEXT NOT NULL);
          CREATE TABLE project_variants(id INTEGER PRIMARY KEY,stable_key TEXT UNIQUE,path TEXT,name TEXT,options TEXT);
          CREATE TABLE documents(id INTEGER PRIMARY KEY,variant_id INTEGER REFERENCES project_variants(id),path TEXT,hash TEXT,origin TEXT);
          CREATE INDEX documents_variant ON documents(variant_id);
          CREATE INDEX documents_path ON documents(path);
          CREATE TABLE methods(id INTEGER PRIMARY KEY,stable_key TEXT UNIQUE,symbol_key TEXT,variant_id INTEGER REFERENCES project_variants(id),document_id INTEGER REFERENCES documents(id),parent_id INTEGER REFERENCES methods(id),signature TEXT,start INTEGER,length INTEGER,status TEXT);
          CREATE INDEX methods_symbol ON methods(symbol_key,variant_id);
          CREATE INDEX methods_document ON methods(document_id);
          CREATE INDEX methods_parent ON methods(parent_id);
          CREATE TABLE flow_nodes(id INTEGER PRIMARY KEY,method_id INTEGER REFERENCES methods(id),ordinal INTEGER,kind TEXT,reachable INTEGER,region TEXT,UNIQUE(method_id,ordinal));
          CREATE TABLE flow_points(id INTEGER PRIMARY KEY,node_id INTEGER REFERENCES flow_nodes(id),position INTEGER,kind TEXT,start INTEGER,length INTEGER,UNIQUE(node_id,position));
          CREATE TABLE flow_edges(id INTEGER PRIMARY KEY,source_id INTEGER REFERENCES flow_nodes(id),target_id INTEGER REFERENCES flow_nodes(id),alternative TEXT,semantics TEXT,regions TEXT,status TEXT);
          CREATE INDEX edges_source ON flow_edges(source_id);
          CREATE INDEX edges_target ON flow_edges(target_id);
          CREATE TABLE call_sites(id INTEGER PRIMARY KEY,method_id INTEGER REFERENCES methods(id),point_id INTEGER UNIQUE REFERENCES flow_points(id),target_key TEXT,target_signature TEXT,resolution TEXT,continuation_position INTEGER);
          CREATE INDEX calls_method ON call_sites(method_id);
          CREATE INDEX calls_key ON call_sites(target_key);
          CREATE TABLE call_targets(site_id INTEGER REFERENCES call_sites(id),method_id INTEGER REFERENCES methods(id),evidence TEXT,PRIMARY KEY(site_id,method_id));
          CREATE INDEX targets_method ON call_targets(method_id);
          CREATE TABLE legacy_block_links(id INTEGER PRIMARY KEY,legacy_id INTEGER REFERENCES basic_blocks(id),method_id INTEGER REFERENCES methods(id),point_id INTEGER REFERENCES flow_points(id),mapping_kind TEXT);
          CREATE TABLE legacy_probe_variants(legacy_id INTEGER REFERENCES basic_blocks(id),variant_id INTEGER REFERENCES project_variants(id),PRIMARY KEY(legacy_id,variant_id));
          CREATE INDEX probe_variants_variant ON legacy_probe_variants(variant_id);
          CREATE TABLE shared_projection_stats(document_id INTEGER PRIMARY KEY REFERENCES documents(id),variant_id INTEGER REFERENCES project_variants(id),new_points INTEGER,reused_points INTEGER,discarded_conflicts INTEGER);
          CREATE INDEX links_legacy ON legacy_block_links(legacy_id);
          CREATE INDEX links_method ON legacy_block_links(method_id);
          CREATE INDEX links_point ON legacy_block_links(point_id);
          CREATE TABLE analysis_diagnostics(id INTEGER PRIMARY KEY,scope TEXT,code TEXT,message TEXT);
          CREATE INDEX diagnostics_scope ON analysis_diagnostics(scope);
          """);
        Run(TraceSelectionStore.Schema);
        Run(ApplicationSchema);
        Batch(()=> {Meta("schema_version",SchemaVersion.ToString()); Meta("state","in_progress"); Meta("framework",framework); Meta("configuration",configuration);
            Meta("model","source_explicit_cfg_declared_calls"); Meta("input_scope","known_workspace_inputs; additions not exhaustively detected");});
    }
    private SqliteCommand Command(string sql,object?[] values)
    {
        if(!commands.TryGetValue(sql,out var cmd)) {
            cmd=db.CreateCommand(); cmd.CommandText=sql;
            for(int i=0;i<values.Length;i++) cmd.Parameters.Add(new SqliteParameter("@p"+i,DBNull.Value));
            commands[sql]=cmd;
        }
        cmd.Transaction=tx;
        for(int i=0;i<values.Length;i++) cmd.Parameters[i].Value=values[i]??DBNull.Value;
        return cmd;
    }
    private void Run(string sql,params object?[] values) {
        long start=Stopwatch.GetTimestamp(); Command(sql,values).ExecuteNonQuery(); WriteTicks+=Stopwatch.GetTimestamp()-start;
    }
    private long Insert(string sql,params object?[] values) {
        long start=Stopwatch.GetTimestamp(); var id=Convert.ToInt64(Command(sql,values).ExecuteScalar()); WriteTicks+=Stopwatch.GetTimestamp()-start; return id;
    }
    public void Batch(Action action) {
        if(tx!=null) {action();return;}
        long begin=Stopwatch.GetTimestamp();using var batch=db.BeginTransaction(); tx=batch;WriteTicks+=Stopwatch.GetTimestamp()-begin;
        try {action();long commit=Stopwatch.GetTimestamp();batch.Commit();WriteTicks+=Stopwatch.GetTimestamp()-commit;}
        catch {applicationSymbolCache.Clear();throw;}
        finally {tx=null;}
    }
    public void Meta(string key,string value)=>Run("INSERT INTO analysis_manifest VALUES(@p0,@p1) ON CONFLICT(key) DO UPDATE SET value=excluded.value",key,value);
    public void Diagnostic(string scope,string code,string message) {
        DiagnosticCount++; Run("INSERT INTO analysis_diagnostics(scope,code,message) VALUES(@p0,@p1,@p2)",scope,code,message);
    }
    public static string Id(params object[] parts)=>Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(parts)))).ToLowerInvariant();
    private static string SymbolKey(IMethodSymbol s) {
        s=(s.ReducedFrom??s).OriginalDefinition;
        return s.ContainingAssembly.Identity+":"+(s.GetDocumentationCommentId()??
            s.ToDisplayString(SymbolDisplayFormat.FullyQualifiedFormat)+":"+string.Join(";",s.Locations.Where(l=>l.IsInSource).Select(l=>l.SourceTree?.FilePath+":"+l.SourceSpan.Start)));
    }
    public long AddProject(Project project) {
        long result=0;
        string effectiveFramework=ProjectFramework.Effective(project,framework);
        Batch(()=> {
            var options=JsonSerializer.Serialize(new {RequestedFramework=framework,EffectiveFramework=effectiveFramework,configuration,project.AssemblyName,
                LanguageVersion=(project.ParseOptions as CSharpParseOptions)?.LanguageVersion.ToString(),
                Nullable=(project.CompilationOptions as CSharpCompilationOptions)?.NullableContextOptions.ToString(),
                Optimization=project.CompilationOptions?.OptimizationLevel.ToString(),
                Symbols=(project.ParseOptions as CSharpParseOptions)?.PreprocessorSymbolNames.OrderBy(s=>s),
                References=project.MetadataReferences.Select(r=>r.Display).OrderBy(p=>p),
                ProjectReferences=project.ProjectReferences.Select(r=>project.Solution.GetProject(r.ProjectId)?.FilePath).OrderBy(p=>p)});
            string stableKey=Id(project.FilePath??project.Name,options);
            result=Insert("INSERT INTO project_variants(stable_key,path,name,options) VALUES(@p0,@p1,@p2,@p3) RETURNING id",stableKey,project.FilePath,project.Name,options);
            variantKeys[result]=stableKey;
        });
        Inputs.Track(project.FilePath);
        foreach(var r in project.MetadataReferences) Inputs.Track(r.Display);
        foreach(var r in project.AnalyzerReferences) Inputs.Track(r.FullPath);
        foreach(var d in project.AdditionalDocuments.Concat(project.AnalyzerConfigDocuments)) Inputs.Track(d.FilePath);
        if(project.FilePath!=null)
            for(var dir=Directory.GetParent(project.FilePath);dir!=null;dir=dir.Parent)
                foreach(var name in new[]{"Directory.Build.props","Directory.Build.targets","Directory.Packages.props","global.json","NuGet.Config"}) Inputs.Track(Path.Combine(dir.FullName,name));
        return result;
    }
    private sealed record Body(long Id,SyntaxNode Syntax,ControlFlowGraph? Graph,List<TraceableBlock> Probes,IMethodSymbol? Symbol);
    private sealed record Event(string Kind,int Start,int Length,IMethodSymbol? Target=null,string? Resolution=null,TraceableBlock? Probe=null,string Mapping="exact_point");

    public async Task<IReadOnlyList<TraceableBlock>> AnalyzeDocument(Document document,long variant,bool generated=false,CancellationToken token=default)
    {
        if(tx!=null)throw new InvalidOperationException("Document analysis must own its transaction");
        LastNewProbes=Array.Empty<TraceableBlock>();
        LastNewCount=0;LastReusedCount=0;LastDiscardedConflictCount=0;
        var root=await document.GetSyntaxRootAsync(token); var model=await document.GetSemanticModelAsync(token);
        if(root==null || model==null) {Batch(()=>Diagnostic(document.Name,"NO_MODEL","No syntax/semantic model"));return Array.Empty<TraceableBlock>();}
        string path=document.FilePath==null?document.Name:Path.GetFullPath(document.FilePath);
        if(!generated) Inputs.Track(path,root.ToFullString());
        shared.TryGetValue(path,out var committed);
        string canonicalPath=committed?.CanonicalPath??path;
        var pending=new Dictionary<int,SharedPoint>();
        var newProbes=new List<TraceableBlock>();int newCount=0,reusedCount=0,discardedConflictCount=0;
        var bodies=new List<Body>(); var graphs=new Dictionary<BaseMethodDeclarationSyntax,ControlFlowGraph?>();
        var extractor=new BlockExtractor(); List<TraceableBlock> probes=new();
        Batch(()=> {
            token.ThrowIfCancellationRequested();
            long doc=Insert("INSERT INTO documents(variant_id,path,hash,origin) VALUES(@p0,@p1,@p2,@p3) RETURNING id",variant,path,Id(root.ToFullString()),generated?"generated":"source");
            foreach(var error in model.GetDiagnostics(cancellationToken:token).Where(d=>d.Severity==DiagnosticSeverity.Error)) Diagnostic("document:"+doc,"SEMANTIC_ERROR",error.ToString());
            foreach(var syntax in root.DescendantNodes().Where(n=>n is BaseMethodDeclarationSyntax or AccessorDeclarationSyntax || n is PropertyDeclarationSyntax {ExpressionBody:not null})) {
                token.ThrowIfCancellationRequested();
                IMethodSymbol? symbol=syntax is PropertyDeclarationSyntax p ? (model.GetDeclaredSymbol(p,token) as IPropertySymbol)?.GetMethod : model.GetDeclaredSymbol(syntax,token) as IMethodSymbol;
                ControlFlowGraph? cfg=null; string status="analyzed";
                try {CfgRequests++;cfg=ControlFlowGraph.Create(syntax is PropertyDeclarationSyntax prop ? prop.ExpressionBody! : syntax,model,token);if(cfg==null)status="no_body";else GraphsCreated++;}
                catch(ArgumentException ex) {status="unsupported";Diagnostic(path,"CFG_UNSUPPORTED",ex.Message);}
                if(syntax is BaseMethodDeclarationSyntax m) graphs[m]=cfg;
                AddBody(syntax,symbol,cfg,null,status);
            }
            if(root.DescendantNodes().OfType<GlobalStatementSyntax>().Any()) {
                try {CfgRequests++;var cfg=ControlFlowGraph.Create(root,model,token);if(cfg!=null)GraphsCreated++;AddBody(root,model.Compilation.GetEntryPoint(token),cfg,null,cfg==null?"no_body":"analyzed");}
                catch(ArgumentException ex){Diagnostic(path,"CFG_UNSUPPORTED",ex.Message);}
            }
            if(!generated && Program.ShouldProcess(document)) probes=extractor.ExtractBlocks(model,root,m=>graphs.GetValueOrDefault(m));
            var records=probes.Select(p=>ToRecord(p,document.Project.Name,canonicalPath)).ToArray();
            var projection=LegacyProjectionDiagnostics.Create(document.Project,variant.ToString(),framework,canonicalPath,records);
            var legacyIds=new Dictionary<int,long>();
            var canonicalRecords=new Dictionary<int,LegacyProjectionRecord>();
            foreach(var candidateRecord in projection.Records) {
                if(canonicalRecords.TryGetValue(candidateRecord.InjectionOffset,out var prior)) {
                    var fields=LegacyProjectionDiagnostics.CompareAtOffset(prior,candidateRecord);
                    if(fields.Count>0)throw new LegacyProjectionConflictException(projection,projection,
                        new[]{new LegacyProjectionDifference(candidateRecord.InjectionOffset,"different_record",new[]{prior},new[]{candidateRecord},fields)});
                } else canonicalRecords[candidateRecord.InjectionOffset]=candidateRecord;
            }
            foreach(var pair in probes.Zip(records)) {
                token.ThrowIfCancellationRequested();
                var record=pair.Second;
                var offset=record.InjectionOffset;
                var candidate=canonicalRecords[offset];
                SharedPoint? existing=null;
                if(committed!=null)committed.Points.TryGetValue(offset,out existing);
                if(existing==null)pending.TryGetValue(offset,out existing);
                if(existing!=null) {
                    var fields=LegacyProjectionDiagnostics.CompareAtOffset(existing.Record,candidate);
                    legacyIds[offset]=existing.Id;
                    if(fields.Count>0) {
                        discardedConflictCount++;
                        Diagnostic("legacy:"+existing.Id,"SHARED_PROBE_CONFLICT_DISCARDED",JsonSerializer.Serialize(new {
                            source=canonicalPath,offset,
                            consolidated=new {origin=existing.FirstProjection.Origin,hash=existing.FirstProjection.Hash,record=existing.Record},
                            incoming=new {origin=projection.Origin,hash=projection.Hash,record=candidate},
                            fields
                        }));
                    } else reusedCount++;
                } else {
                    long id=Insert(SqliteRepository.Insert,SqliteRepository.Values(record));
                    pending[offset]=new(id,candidate,projection);legacyIds[offset]=id;newCount++;newProbes.Add(pair.First);
                }
                Run("INSERT OR IGNORE INTO legacy_probe_variants(legacy_id,variant_id) VALUES(@p0,@p1)",legacyIds[offset],variant);
            }
            Run("INSERT INTO shared_projection_stats(document_id,variant_id,new_points,reused_points,discarded_conflicts) VALUES(@p0,@p1,@p2,@p3,@p4)",doc,variant,newCount,reusedCount,discardedConflictCount);
            foreach(var body in bodies) {
                token.ThrowIfCancellationRequested();
                // The legacy selector only visits BaseMethodDeclarationSyntax.
                if(body.Syntax is BaseMethodDeclarationSyntax method) body.Probes.AddRange(probes.Where(p=>p.ScopeStartLine==method.GetLocation().GetLineSpan().StartLinePosition.Line+1 && p.InjectionOffset>=method.SpanStart && p.InjectionOffset<method.Span.End));
                if(body.Graph!=null) SaveGraph(body,legacyIds,token);
                RecordApplicationBody(body,model,generated,token);
            }

            void AddBody(SyntaxNode syntax,IMethodSymbol? symbol,ControlFlowGraph? cfg,long? parent,string status) {
                string key=symbol==null?path+":"+syntax.SpanStart:SymbolKey(symbol);
                long id=Insert("INSERT INTO methods(stable_key,symbol_key,variant_id,document_id,parent_id,signature,start,length,status) VALUES(@p0,@p1,@p2,@p3,@p4,@p5,@p6,@p7,@p8) RETURNING id",Id(variantKeys[variant],path,key,syntax.SpanStart),key,variant,doc,parent,symbol?.ToDisplayString()??"<top-level>",syntax.SpanStart,syntax.Span.Length,status);
                bodies.Add(new(id,syntax,cfg,new(),symbol));
                if(cfg==null)return;
                foreach(var local in cfg.LocalFunctions) {
                    CfgRequests++;var nested=cfg.GetLocalFunctionControlFlowGraph(local,token); GraphsCreated++; AddBody(nested.OriginalOperation.Syntax,local,nested,id,"analyzed");
                }
                foreach(var block in cfg.Blocks) foreach(var op in block.Operations.Concat(block.BranchValue==null?Array.Empty<IOperation>():new[]{block.BranchValue})) Find(op);
                void Find(IOperation op) {
                    if(op is IFlowAnonymousFunctionOperation lambda) {CfgRequests++;var nested=cfg.GetAnonymousFunctionControlFlowGraph(lambda,token);GraphsCreated++;AddBody(nested.OriginalOperation.Syntax,lambda.Symbol,nested,id,"analyzed");return;}
                    foreach(var child in op.ChildOperations) Find(child);
                }
            }
        });
        if(!generated) {
            var state=committed??new SharedFile(canonicalPath);
            foreach(var (offset,point) in pending)state.Points.Add(offset,point);
            if(committed==null)shared[path]=state;
        }
        LastNewProbes=newProbes;
        LastNewCount=newCount;LastReusedCount=reusedCount;LastDiscardedConflictCount=discardedConflictCount;
        SharedProbeNew+=newCount;SharedProbeReused+=reusedCount;SharedProbeDiscardedConflicts+=discardedConflictCount;
        DocumentsAnalyzed++; return probes;
    }
    public static BasicBlockRecord ToRecord(TraceableBlock b,string project,string path)=>new() {
        ProjectName=project,FilePath=path,MethodSignature=b.MethodSignature,ScopeStartLine=b.ScopeStartLine,ScopeEndLine=b.ScopeEndLine,
        BlockStartLine=b.BlockStartLine,BlockEndLine=b.BlockEndLine,InjectionLine=b.StartLine,InjectionOffset=b.InjectionOffset,
        Reason=b.Reason,ToTrace=true,WrapInBlock=b.WrapInBlock,StatementEndOffset=b.StatementEndOffset };

    private void SaveGraph(Body body,Dictionary<int,long> legacyIds,CancellationToken token)
    {
        var cfg=body.Graph!; var nodes=new Dictionary<int,long>();
        // Return expressions are evaluated in the CFG branch value. The source
        // probe precedes that evaluation; map only an exact expression root.
        foreach(var probe in body.Probes.Where(p=>p.CfgOrdinal==null)) {
            var jump=body.Syntax.FindToken(probe.InjectionOffset).Parent?.AncestorsAndSelf().OfType<ReturnStatementSyntax>().FirstOrDefault();
            if(jump?.Expression!=null) {
                var matches=cfg.Blocks.Where(b=>b.BranchValue is not IFlowCaptureReferenceOperation&&b.BranchValue?.Syntax.Span==jump.Expression.Span).ToArray();
                if(matches.Length==1)probe.CfgOrdinal=matches[0].Ordinal;
            }
            var statement=body.Syntax.FindToken(probe.InjectionOffset).Parent?.AncestorsAndSelf().OfType<StatementSyntax>().FirstOrDefault();
            if(probe.CfgOrdinal!=null||statement is not (ReturnStatementSyntax {Expression:null} or ContinueStatementSyntax or BreakStatementSyntax))continue;
            if(statement.Parent is BlockSyntax parent) {
                int index=parent.Statements.IndexOf(statement);
                if(index>0&&parent.Statements[index-1] is ExpressionStatementSyntax or LocalDeclarationStatementSyntax) {
                    var previous=parent.Statements[index-1];
                    var matches=cfg.Blocks.Where(b=>b.BranchValue==null&&b.ConditionalSuccessor?.Destination==null&&b.FallThroughSuccessor?.Destination!=null&&
                        b.Operations.LastOrDefault()?.Syntax.AncestorsAndSelf().Contains(previous)==true).ToArray();
                    if(matches.Length==1)probe.CfgOrdinal=matches[0].Ordinal;
                } else if(parent==((body.Syntax as BaseMethodDeclarationSyntax)?.Body)&&parent.Statements.Count==1&&cfg.Blocks.Length==2&&statement is ReturnStatementSyntax)
                    probe.CfgOrdinal=cfg.Blocks[0].Ordinal;
            }
        }
        var regions=new Stack<ControlFlowRegion>();regions.Push(cfg.Root);
        bool exceptional=false;
        while(regions.TryPop(out var region)) {
            string kind=region.Kind.ToString();
            exceptional|=kind.Contains("Catch") || kind.Contains("Finally") || kind.Contains("Filter");
            foreach(var child in region.NestedRegions)regions.Push(child);
        }
        if(exceptional)Diagnostic("method:"+body.Id,"EXCEPTION_REGIONS_INCOMPLETE","Implicit handler dispatch and structured exceptional execution are not expanded");
        foreach(var b in cfg.Blocks) nodes[b.Ordinal]=Insert("INSERT INTO flow_nodes(method_id,ordinal,kind,reachable,region) VALUES(@p0,@p1,@p2,@p3,@p4) RETURNING id",body.Id,b.Ordinal,b.Kind.ToString(),b.IsReachable?1:0,Region(b.EnclosingRegion));
        var mapped=new HashSet<TraceableBlock>();int extraOrdinal=cfg.Blocks.Length;
        foreach(var b in cfg.Blocks) {
            token.ThrowIfCancellationRequested();
            var events=new List<Event>(); var operations=b.Operations.Concat(b.BranchValue==null?Array.Empty<IOperation>():new[]{b.BranchValue}).ToArray();
            foreach(var op in b.Operations) {
                events.Add(new("source_before",op.Syntax.SpanStart,0));Visit(op);
                events.Add(new("source_after",op.Syntax.Span.End,0));
            }
            if(b.BranchValue!=null) {
                events.Add(new("source_before",b.BranchValue.Syntax.SpanStart,0));Visit(b.BranchValue);
                events.Add(new("control",b.BranchValue.Syntax.SpanStart,b.BranchValue.Syntax.Span.Length));
            }
            foreach(var probe in body.Probes.Where(p=>p.CfgOrdinal==b.Ordinal)) {
                int index=events.FindIndex(e=>e.Start>=probe.InjectionOffset || (e.Start<=probe.InjectionOffset && e.Start+e.Length>probe.InjectionOffset));
                if(index<0) index=events.Count;
                bool exact=operations.Any(op=>op.Syntax.SpanStart==probe.InjectionOffset);
                events.Insert(index,new("legacy",probe.InjectionOffset,0,Probe:probe,Mapping:exact?"exact_point":"shared_statement")); mapped.Add(probe);
            }
            int position=0;
            Point(b.Kind==BasicBlockKind.Entry?"entry":"boundary",body.Syntax.SpanStart,0);
            foreach(var e in events) {
                long point=Point(e.Kind,e.Start,e.Length);
                if(e.Kind=="call") Insert("INSERT INTO call_sites(method_id,point_id,target_key,target_signature,resolution,continuation_position) VALUES(@p0,@p1,@p2,@p3,@p4,@p5) RETURNING id",body.Id,point,e.Target==null?null:SymbolKey(e.Target),e.Target?.ToDisplayString()??"<dynamic>",e.Resolution,position);
                if(e.Probe!=null) Run("INSERT INTO legacy_block_links(legacy_id,method_id,point_id,mapping_kind) VALUES(@p0,@p1,@p2,@p3)",legacyIds[e.Probe.InjectionOffset],body.Id,point,e.Mapping);
            }
            Point(b.Kind==BasicBlockKind.Exit?"exit":"boundary",body.Syntax.Span.End,0);
            Edge(b.FallThroughSuccessor,false); Edge(b.ConditionalSuccessor,true);
            long Point(string kind,int start,int length)=>Insert("INSERT INTO flow_points(node_id,position,kind,start,length) VALUES(@p0,@p1,@p2,@p3,@p4) RETURNING id",nodes[b.Ordinal],position++,kind,start,length);
            void Edge(ControlFlowBranch? branch,bool conditional) {
                if(branch==null)return;
                string alternative=b.ConditionKind==ControlFlowConditionKind.None?"unconditional":conditional==(b.ConditionKind==ControlFlowConditionKind.WhenTrue)?"true":"false";
                bool unsupported=branch.FinallyRegions.Length>0 || branch.Semantics is ControlFlowBranchSemantics.StructuredExceptionHandling or ControlFlowBranchSemantics.Error;
                long? destination=branch.Destination==null?null:nodes[branch.Destination.Ordinal];
                // A pure guard return may be represented by an edge straight to Exit,
                // rather than an operation. Split only when syntax proves the exact arm.
                if(branch.Destination!=null && b.BranchValue!=null && alternative!="unconditional")
                    foreach(var probe in body.Probes.Where(p=>p.CfgOrdinal==null)) {
                        var jump=body.Syntax.FindToken(probe.InjectionOffset).Parent?.AncestorsAndSelf().OfType<StatementSyntax>().FirstOrDefault();
                        var guard=jump?.Ancestors().OfType<IfStatementSyntax>().FirstOrDefault();
                        if(jump is not (ReturnStatementSyntax {Expression:null} or BreakStatementSyntax or ContinueStatementSyntax)||guard==null||guard.Condition.Span!=b.BranchValue.Syntax.Span)continue;
                        if(jump is ReturnStatementSyntax&&branch.Destination.Kind!=BasicBlockKind.Exit)continue;
                        if(jump is ContinueStatementSyntax&&!jump.Ancestors().Any(n=>n is ForStatementSyntax or WhileStatementSyntax or DoStatementSyntax or CommonForEachStatementSyntax))continue;
                        if(jump is BreakStatementSyntax&&!jump.Ancestors().Any(n=>n is ForStatementSyntax or WhileStatementSyntax or DoStatementSyntax or CommonForEachStatementSyntax or SwitchStatementSyntax))continue;
                        StatementSyntax? arm=alternative=="true"?guard.Statement:guard.Else?.Statement;
                        if(arm is BlockSyntax block && block.Statements.Count==1)arm=block.Statements[0];
                        if(arm!=jump)continue;
                        long bridge=Insert("INSERT INTO flow_nodes(method_id,ordinal,kind,reachable,region) VALUES(@p0,@p1,'Block',@p2,@p3) RETURNING id",body.Id,extraOrdinal++,b.IsReachable?1:0,Region(b.EnclosingRegion));
                        long point=Insert("INSERT INTO flow_points(node_id,position,kind,start,length) VALUES(@p0,0,'legacy',@p1,0) RETURNING id",bridge,probe.InjectionOffset);
                        Run("INSERT INTO legacy_block_links(legacy_id,method_id,point_id,mapping_kind) VALUES(@p0,@p1,@p2,'exact_point')",legacyIds[probe.InjectionOffset],body.Id,point);
                        Run("INSERT INTO flow_edges(source_id,target_id,alternative,semantics,regions,status) VALUES(@p0,@p1,'unconditional',@p2,'{}',@p3)",bridge,destination,jump is ReturnStatementSyntax?"Return":jump is ContinueStatementSyntax?"Continue":"Break",unsupported?"incomplete":"modeled");
                        destination=bridge;mapped.Add(probe);
                    }
                Run("INSERT INTO flow_edges(source_id,target_id,alternative,semantics,regions,status) VALUES(@p0,@p1,@p2,@p3,@p4,@p5)",nodes[b.Ordinal],destination,alternative,branch.Semantics.ToString(),JsonSerializer.Serialize(new {Leaving=branch.LeavingRegions.Select(Region),Entering=branch.EnteringRegions.Select(Region),Finally=branch.FinallyRegions.Select(Region)}),unsupported?"incomplete":"modeled");
                if(unsupported) Diagnostic("method:"+body.Id,"TRANSFER_INCOMPLETE","Finally/structured exceptional transfer is not expanded");
            }
            void Call(IOperation op,IMethodSymbol? target,string? resolution=null) {
                if(target==null && resolution==null)return;
                if(target?.MethodKind==MethodKind.DelegateInvoke) resolution="delegate_open";
                resolution??=target!.IsVirtual||target.IsAbstract||target.ContainingType.TypeKind==TypeKind.Interface?"dispatch_open":"static";
                events.Add(new("call",op.Syntax.SpanStart,op.Syntax.Span.Length,target,resolution));
            }
            void Visit(IOperation op) {
                if(op is IFlowAnonymousFunctionOperation or IAnonymousFunctionOperation)return;
                if(op is IObjectCreationOperation creation) {
                    foreach(var argument in creation.Arguments)Visit(argument);
                    Call(op,creation.Constructor);
                    if(creation.Initializer!=null)Visit(creation.Initializer);
                    return;
                }
                if(op is IAwaitOperation || op.Kind is OperationKind.YieldReturn or OperationKind.YieldBreak) {
                    foreach(var child in op.ChildOperations) Visit(child);
                    events.Add(new("incomplete",op.Syntax.SpanStart,op.Syntax.Span.Length));
                    Diagnostic("method:"+body.Id,"SUSPENSION_INCOMPLETE",op.Kind.ToString()); return;
                }
                if(op is ISimpleAssignmentOperation {Target:IPropertyReferenceOperation property} assignment) {
                    foreach(var child in property.ChildOperations) Visit(child); Visit(assignment.Value);Call(op,property.Property.SetMethod);return;
                }
                if(op is ICompoundAssignmentOperation {Target:IPropertyReferenceOperation cp} compound) {
                    foreach(var child in cp.ChildOperations) Visit(child);Call(cp,cp.Property.GetMethod);Visit(compound.Value);Call(op,compound.OperatorMethod);Call(op,cp.Property.SetMethod);return;
                }
                if(op is IIncrementOrDecrementOperation {Target:IPropertyReferenceOperation ip} increment) {
                    foreach(var child in ip.ChildOperations) Visit(child);Call(ip,ip.Property.GetMethod);Call(op,increment.OperatorMethod);Call(op,ip.Property.SetMethod);return;
                }
                foreach(var child in op.ChildOperations) Visit(child);
                switch(op) {
                    case IInvocationOperation invocation: Call(op,invocation.TargetMethod,invocation.IsVirtual?"dispatch_open":null);break;
                    case IPropertyReferenceOperation reference:Call(op,reference.Property.GetMethod);break;
                    case IDynamicInvocationOperation:Call(op,null,"dynamic_open");break;
                    case IBinaryOperation binary:Call(op,binary.OperatorMethod);break;
                    case IUnaryOperation unary:Call(op,unary.OperatorMethod);break;
                    case IConversionOperation conversion:Call(op,conversion.OperatorMethod);break;
                    case ICompoundAssignmentOperation compoundAssignment:Call(op,compoundAssignment.OperatorMethod);break;
                    case IIncrementOrDecrementOperation update:Call(op,update.OperatorMethod);break;
                }
            }
        }
        foreach(var probe in body.Probes.Where(p=>!mapped.Contains(p))) {
            Run("INSERT INTO legacy_block_links(legacy_id,method_id,point_id,mapping_kind) VALUES(@p0,@p1,NULL,'unmapped')",legacyIds[probe.InjectionOffset],body.Id);
            Diagnostic("legacy:"+legacyIds[probe.InjectionOffset],"LEGACY_UNMAPPED","No precise CFG location for syntactic fallback probe");
        }
    }
    private static string Region(ControlFlowRegion r)=>r.Kind+":"+r.FirstBlockOrdinal+":"+r.LastBlockOrdinal;
    public void Complete(CancellationToken token=default,bool verifyInputs=true,Action<string>? progress=null,bool finalize=true) {
        token.ThrowIfCancellationRequested(); if(verifyInputs)Inputs.Verify(token);
        var timer=Stopwatch.StartNew();progress?.Invoke("resolve_calls");
        Batch(()=> {
            // Indexed exact symbol lookup, preferring the caller's variant. Never enumerate overrides.
            Run("""
              INSERT INTO call_targets
              SELECT s.id,m.id,CASE WHEN s.resolution='static' THEN 'declared_target' ELSE 'declared_candidate' END
              FROM call_sites s JOIN methods caller ON caller.id=s.method_id JOIN methods m ON m.symbol_key=s.target_key
              WHERE m.status='analyzed' AND (m.variant_id=caller.variant_id OR NOT EXISTS
                (SELECT 1 FROM methods local WHERE local.symbol_key=s.target_key AND local.variant_id=caller.variant_id AND local.status='analyzed'));
              """);
            Run("UPDATE call_sites SET resolution='external' WHERE resolution='static' AND NOT EXISTS(SELECT 1 FROM call_targets t WHERE t.site_id=call_sites.id)");
            Run("""
              INSERT INTO analysis_diagnostics(scope,code,message)
              SELECT 'call:'||s.id,'CALL_OPEN',s.resolution FROM call_sites s
              WHERE s.resolution<>'static' OR (SELECT count(*) FROM call_targets t WHERE t.site_id=s.id)<>1;
              """);
            FinalizationMilliseconds["resolution_ms"]=timer.Elapsed.TotalMilliseconds;
            timer.Restart();progress?.Invoke("validate_graph");
            using var cmd=db.CreateCommand();cmd.Transaction=tx;cmd.CommandText="PRAGMA foreign_key_check";
            using(var reader=cmd.ExecuteReader()) if(reader.Read())throw new InvalidOperationException("Foreign key validation failed");
            cmd.CommandText="""
              SELECT count(*) FROM flow_edges e JOIN flow_nodes a ON a.id=e.source_id JOIN flow_nodes b ON b.id=e.target_id WHERE a.method_id<>b.method_id
              """;
            if(Convert.ToInt64(cmd.ExecuteScalar())!=0)throw new InvalidOperationException("Cross-method local edge");
            cmd.CommandText="""
              SELECT count(*) FROM (
                SELECT s.id FROM call_sites s JOIN flow_points p ON p.id=s.point_id JOIN flow_nodes n ON n.id=p.node_id
                  WHERE s.method_id<>n.method_id OR p.kind<>'call' OR s.continuation_position<>p.position+1
                UNION ALL
                SELECT l.id FROM legacy_block_links l JOIN flow_points p ON p.id=l.point_id JOIN flow_nodes n ON n.id=p.node_id
                  WHERE l.method_id<>n.method_id OR p.kind<>'legacy'
                UNION ALL
                SELECT l.id FROM legacy_block_links l JOIN methods m ON m.id=l.method_id
                  WHERE NOT EXISTS(SELECT 1 FROM legacy_probe_variants v WHERE v.legacy_id=l.legacy_id AND v.variant_id=m.variant_id)
                UNION ALL
                SELECT m.id FROM methods m WHERE m.status='analyzed' AND
                  ((SELECT count(*) FROM flow_nodes n WHERE n.method_id=m.id AND n.kind='Entry')<>1 OR
                   (SELECT count(*) FROM flow_nodes n WHERE n.method_id=m.id AND n.kind='Exit')<>1)
              )
              """;
            if(Convert.ToInt64(cmd.ExecuteScalar())!=0)throw new InvalidOperationException("Invalid call, probe or method boundary");
            token.ThrowIfCancellationRequested();
            cmd.CommandText="SELECT count(*) FROM analysis_diagnostics";DiagnosticCount=Convert.ToInt32(cmd.ExecuteScalar());
            cmd.CommandText="SELECT count(*) FROM application_fact_locations l JOIN application_facts f ON f.id=l.fact_id JOIN flow_nodes n ON n.id=l.node_id LEFT JOIN flow_edges e ON e.id=l.edge_id WHERE f.method_id<>n.method_id OR (l.edge_id IS NOT NULL AND e.source_id<>l.node_id)";
            if(Convert.ToInt64(cmd.ExecuteScalar())!=0)throw new InvalidOperationException("Invalid application fact frontier");
            foreach(var table in new[]{"project_variants","documents","methods","basic_blocks","flow_nodes","flow_points","flow_edges","call_sites","call_targets","legacy_block_links","legacy_probe_variants","shared_projection_stats","analysis_diagnostics","application_symbols","application_method_facts","application_facts","application_fact_locations","application_fact_mappings","application_registrations"}) {
                cmd.CommandText="SELECT count(*) FROM "+table;Counts[table]=Convert.ToInt64(cmd.ExecuteScalar());
            }
            Meta("input_manifest",Inputs.Manifest());Meta("fingerprint",Id(Inputs.Manifest()));
            Meta("graphs_created",GraphsCreated.ToString());Meta("documents_analyzed",DocumentsAnalyzed.ToString());
            Meta("cfg_requests",CfgRequests.ToString());
            Meta("shared_probe_new",SharedProbeNew.ToString());Meta("shared_probe_reused",SharedProbeReused.ToString());
            Meta("shared_probe_discarded_conflicts",SharedProbeDiscardedConflicts.ToString());
            Meta("shared_probe_policy","union_per_file_offset; first_functional_record_wins; incompatible_incoming_record_discarded_with_diagnostic; selected_variants_recorded; injected_into_all_compilations");
            Meta("counts",JsonSerializer.Serialize(Counts));
            Meta("extraction_coverage",DiagnosticCount==0?"complete_for_model":"partial");
            Meta("coverage",DiagnosticCount==0?"complete_for_model":"partial");Meta("state",finalize?"validated":"graph_validated");
        });
        FinalizationMilliseconds["validation_ms"]=timer.Elapsed.TotalMilliseconds;
    }
    public void Dispose() {foreach(var cmd in commands.Values)cmd.Dispose();db.Dispose();}
}
