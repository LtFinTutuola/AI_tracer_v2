using System.Text.Json;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Operations;

namespace RoslynAnalyzer;

public sealed partial class ContextCatalog
{
    public const string ApplicationSchema="""
      CREATE TABLE application_symbols(key TEXT PRIMARY KEY,description TEXT NOT NULL);
      CREATE TABLE application_method_facts(method_id INTEGER PRIMARY KEY REFERENCES methods(id),symbol_key TEXT REFERENCES application_symbols(key),body_start INTEGER,body_end INTEGER,expression_start INTEGER,expression_end INTEGER,return_prefix TEXT,exported INTEGER,entry_kind TEXT,is_async INTEGER,is_iterator INTEGER,exit_semantics TEXT,supported INTEGER);
      CREATE TABLE application_facts(id INTEGER PRIMARY KEY,stable_key TEXT UNIQUE,method_id INTEGER REFERENCES methods(id),kind TEXT,symbol_key TEXT,anchor INTEGER,edit_offset INTEGER,span_start INTEGER,span_end INTEGER,repeated INTEGER,payload TEXT);
      CREATE INDEX app_facts_method ON application_facts(method_id);
      CREATE TABLE application_fact_mappings(fact_id INTEGER PRIMARY KEY REFERENCES application_facts(id),status TEXT NOT NULL,reason TEXT NOT NULL);
      CREATE TABLE application_fact_locations(id INTEGER PRIMARY KEY,fact_id INTEGER REFERENCES application_facts(id),node_id INTEGER REFERENCES flow_nodes(id),position INTEGER,edge_id INTEGER REFERENCES flow_edges(id),phase TEXT NOT NULL);
      CREATE INDEX app_fact_locations_fact ON application_fact_locations(fact_id);
      CREATE INDEX app_fact_locations_node ON application_fact_locations(node_id,position);
      CREATE TABLE application_registrations(method_id INTEGER REFERENCES methods(id),target_key TEXT,api_key TEXT,kind TEXT,PRIMARY KEY(method_id,target_key,api_key));
      CREATE INDEX app_reg_target ON application_registrations(target_key);
      CREATE TABLE application_entries(method_id INTEGER PRIMARY KEY REFERENCES methods(id),classification TEXT,reasons TEXT);
      CREATE TABLE application_observations(id TEXT PRIMARY KEY,method_id INTEGER REFERENCES methods(id),variant_id INTEGER REFERENCES project_variants(id),kind TEXT,evidence TEXT,point_id INTEGER REFERENCES flow_points(id),status TEXT,mapping_status TEXT NOT NULL,mapping_reason TEXT NOT NULL);
      CREATE INDEX app_obs_method ON application_observations(method_id);
      CREATE TABLE application_locations(id INTEGER PRIMARY KEY,observation_id TEXT REFERENCES application_observations(id),node_id INTEGER REFERENCES flow_nodes(id),position INTEGER,edge_id INTEGER REFERENCES flow_edges(id));
      CREATE UNIQUE INDEX app_locations_unique ON application_locations(observation_id,node_id,position,coalesce(edge_id,-1));
      CREATE INDEX app_locations_observation ON application_locations(observation_id);
      CREATE INDEX app_locations_node ON application_locations(node_id,position);
      CREATE TABLE application_probe_bindings(observation_id TEXT REFERENCES application_observations(id),legacy_id INTEGER REFERENCES basic_blocks(id),PRIMARY KEY(observation_id,legacy_id));
      CREATE INDEX app_bind_probe ON application_probe_bindings(legacy_id);
      CREATE TABLE application_probe_contexts(legacy_id INTEGER REFERENCES basic_blocks(id),method_id INTEGER REFERENCES methods(id),PRIMARY KEY(legacy_id,method_id));
      CREATE TABLE application_placements(legacy_id INTEGER PRIMARY KEY REFERENCES basic_blocks(id),kind TEXT,path TEXT,anchor INTEGER,span_start INTEGER,span_end INTEGER,source_hash TEXT,group_key TEXT);
      CREATE TABLE application_edits(id INTEGER PRIMARY KEY,path TEXT,offset INTEGER,remove_length INTEGER,text TEXT,priority INTEGER,gate_id INTEGER REFERENCES basic_blocks(id));
      CREATE INDEX app_edits_path ON application_edits(path);
      CREATE TABLE application_method_summaries(method_id INTEGER PRIMARY KEY REFERENCES methods(id),flags INTEGER,repeated INTEGER,opaque INTEGER);
      """;
    private readonly HashSet<string> applicationSymbolCache=new(StringComparer.Ordinal);
    private string RecordSymbol(ISymbol symbol)
    {
        string key=ApplicationPolicy.Key(symbol);
        if(applicationSymbolCache.Add(key)) {
            Run("INSERT OR IGNORE INTO application_symbols VALUES(@p0,@p1)",key,JsonSerializer.Serialize(ApplicationPolicy.Describe(symbol)));
            if(applicationSymbolCache.Count>10000)applicationSymbolCache.Clear();
        }
        return key;
    }
    private void RecordApplicationBody(Body body,SemanticModel model,bool generated,CancellationToken token)
    {
        if(body.Symbol==null)return;
        var mapping=new ApplicationFactMapper(db,tx,body.Id,body.Graph,model,token);
        string symbol=RecordSymbol(body.Symbol);
        var nodes=body.Syntax.DescendantNodesAndSelf(n=>n==body.Syntax||n is not (LocalFunctionStatementSyntax or AnonymousFunctionExpressionSyntax)).ToArray();
        BlockSyntax? block=body.Syntax switch {BaseMethodDeclarationSyntax m=>m.Body,AccessorDeclarationSyntax a=>a.Body,LocalFunctionStatementSyntax f=>f.Body,AnonymousFunctionExpressionSyntax a=>a.Body as BlockSyntax,BlockSyntax b=>b,_=>null};
        ArrowExpressionClauseSyntax? arrow=body.Syntax switch {MethodDeclarationSyntax m=>m.ExpressionBody,ConstructorDeclarationSyntax c=>c.ExpressionBody,AccessorDeclarationSyntax a=>a.ExpressionBody,LocalFunctionStatementSyntax f=>f.ExpressionBody,PropertyDeclarationSyntax p=>p.ExpressionBody,_=>null};
        ExpressionSyntax? expression=arrow?.Expression??(body.Syntax is LambdaExpressionSyntax lambda?lambda.Body as ExpressionSyntax:null);
        int arrowStart=arrow?.ArrowToken.SpanStart??(body.Syntax is LambdaExpressionSyntax l?l.ArrowToken.Span.End:-1);
        int arrowEnd=arrow!=null?body.Syntax.Span.End:expression?.Span.End??-1;
        bool iterator=nodes.Any(n=>n is YieldStatementSyntax);
        string type=body.Symbol.ReturnType.OriginalDefinition.ToDisplayString();
        bool asyncVoid=body.Symbol.IsAsync&&(body.Symbol.ReturnsVoid||type is "System.Threading.Tasks.Task" or "System.Threading.Tasks.ValueTask");
        string prefix=body.Symbol.ReturnsVoid||asyncVoid?"":"return ";
        if(body.Symbol.ReturnsByRef||body.Symbol.ReturnsByRefReadonly)prefix="return "; // expression already carries its ref token
        bool supported=!generated&&File.Exists(model.SyntaxTree.FilePath)&&!iterator&&(block!=null||expression!=null)&&body.Syntax is not PropertyDeclarationSyntax&&!body.Symbol.IsAbstract&&body.Graph!=null;
        bool exported=body.Symbol.DeclaredAccessibility is Accessibility.Public or Accessibility.Protected or Accessibility.ProtectedOrInternal;
        bool implements=body.Symbol.ContainingType?.AllInterfaces.Any(i=>i.GetMembers().OfType<IMethodSymbol>().Any(member=>SymbolEqualityComparer.Default.Equals(body.Symbol.ContainingType.FindImplementationForInterfaceMember(member),body.Symbol)))==true;
        string entry=SymbolEqualityComparer.Default.Equals(model.Compilation.GetEntryPoint(token),body.Symbol)?"program":body.Symbol.IsOverride?"override":implements?"contract":"";
        Run("INSERT INTO application_method_facts VALUES(@p0,@p1,@p2,@p3,@p4,@p5,@p6,@p7,@p8,@p9,@p10,@p11,@p12)",body.Id,symbol,
            block?.OpenBraceToken.Span.End??arrowStart,block?.CloseBraceToken.SpanStart??arrowEnd,expression?.SpanStart??-1,expression?.Span.End??-1,prefix,exported?1:0,entry,body.Symbol.IsAsync?1:0,iterator?1:0,
            !body.Symbol.IsAsync&&(type.StartsWith("System.Threading.Tasks.Task",StringComparison.Ordinal)||type.StartsWith("System.Threading.Tasks.ValueTask",StringComparison.Ordinal))?"handle_returned":"body_left",supported?1:0);
        bool Repeated(SyntaxNode n)=>n.Ancestors().TakeWhile(a=>a!=body.Syntax).Any(a=>a is ForStatementSyntax or ForEachStatementSyntax or ForEachVariableStatementSyntax or WhileStatementSyntax or DoStatementSyntax);
        void Fact(string kind,SyntaxNode syntax,int anchor,int edit,ISymbol? target,object payload,int? start=null,int? end=null) {
            token.ThrowIfCancellationRequested();string key=target==null?"":RecordSymbol(target);
            long fact=Insert("INSERT INTO application_facts(stable_key,method_id,kind,symbol_key,anchor,edit_offset,span_start,span_end,repeated,payload) VALUES(@p0,@p1,@p2,@p3,@p4,@p5,@p6,@p7,@p8,@p9) ON CONFLICT(stable_key) DO UPDATE SET payload=excluded.payload RETURNING id",
                Id(body.Id,kind,anchor,key),body.Id,kind,key,anchor,edit,start??syntax.SpanStart,end??syntax.Span.End,Repeated(syntax)?1:0,JsonSerializer.Serialize(payload));
            mapping.Save(fact,kind,syntax,JsonSerializer.SerializeToElement(payload));
        }
        var localInputs=new Dictionary<ISymbol,List<ExpressionSyntax>>(SymbolEqualityComparer.Default);
        void LocalInput(ISymbol? local,ExpressionSyntax value) {if(local is not ILocalSymbol)return;if(!localInputs.TryGetValue(local,out var inputs))localInputs[local]=inputs=new();inputs.Add(value);}
        foreach(var variable in nodes.OfType<VariableDeclaratorSyntax>())if(variable.Initializer!=null)LocalInput(model.GetDeclaredSymbol(variable,token),variable.Initializer.Value);
        foreach(var assignment in nodes.OfType<AssignmentExpressionSyntax>())LocalInput(model.GetSymbolInfo(assignment.Left,token).Symbol,assignment.Right);
        string[] References(SyntaxNode condition) {
            var result=new HashSet<string>(StringComparer.Ordinal);var expanded=new HashSet<ISymbol>(SymbolEqualityComparer.Default);var queue=new Queue<SyntaxNode>();queue.Enqueue(condition);int visited=0;
            while(queue.TryDequeue(out var expression)) {
                token.ThrowIfCancellationRequested();if(++visited>2048){Diagnostic("method:"+body.Id,"APPLICATION_DEPENDENCE_LIMIT","Local definition expansion budget reached");break;}
                foreach(var n in expression.DescendantNodesAndSelf().Where(n=>n is IdentifierNameSyntax or MemberAccessExpressionSyntax or InvocationExpressionSyntax)) {
                    var s=model.GetSymbolInfo(n,token).Symbol;
                    if(s is IMethodSymbol or IPropertySymbol or IFieldSymbol)result.Add(RecordSymbol(s));
                    else if(s is ILocalSymbol&&expanded.Add(s)&&localInputs.TryGetValue(s,out var definitions))foreach(var value in definitions)queue.Enqueue(value);
                }
            }
            return result.OrderBy(k=>k,StringComparer.Ordinal).ToArray();
        }
        foreach(var statement in nodes.OfType<IfStatementSyntax>()) {
            var refs=References(statement.Condition);string condition=statement.Condition.ToString();
            void Arm(StatementSyntax? arm,bool yes) {
                int anchor=arm?.SpanStart??statement.CloseParenToken.SpanStart;
                bool unsafeScope=false;
                if(arm!=null&&arm is not BlockSyntax) {
                    try {
                        var flow=model.AnalyzeDataFlow(arm);
                        unsafeScope=flow?.Succeeded==true&&flow.VariablesDeclared.Any(v=>flow.DataFlowsOut.Contains(v,SymbolEqualityComparer.Default));
                    } catch(ArgumentException) {unsafeScope=true;}
                }
                Fact("arm",statement,anchor,arm is BlockSyntax b?b.OpenBraceToken.Span.End:arm?.SpanStart??statement.Statement.Span.End,null,
                    new {references=refs,label=condition+" / "+(yes?"true":"false"),style=unsafeScope?"unsupported":arm is BlockSyntax?"block":arm==null?"else":"wrap",arm_end=arm?.Span.End??statement.Statement.Span.End,truth=yes,depth=statement.Ancestors().Count(),condition_start=statement.Condition.SpanStart,condition_length=statement.Condition.Span.Length});
            }
            Arm(statement.Statement,true);Arm(statement.Else?.Statement,false);
        }
        foreach(var section in nodes.OfType<SwitchSectionSyntax>()) {
            var parent=(SwitchStatementSyntax)section.Parent!;
            Fact("case",section,section.Labels[0].SpanStart,section.Labels.Last().GetLastToken().Span.End,null,
                new {references=References(parent.Expression),label=string.Join(" ",section.Labels.Select(l=>l.ToString())),style="plain",first_statement=section.Statements.FirstOrDefault()?.SpanStart??-1});
        }
        foreach(var assignment in nodes.OfType<AssignmentExpressionSyntax>()) {
            var target=model.GetSymbolInfo(assignment.Left,token).Symbol;
            if(target is not (IPropertySymbol or IFieldSymbol))continue;
            var statement=assignment.Parent as ExpressionStatementSyntax;
            Fact("assignment",assignment,statement?.SemicolonToken.SpanStart??assignment.SpanStart,statement?.Span.End??-1,target,new {style=statement==null?"unsupported":"after"},statement?.SpanStart,statement?.Span.End);
        }
        foreach(var update in nodes.OfType<ExpressionSyntax>().Where(n=>n.IsKind(SyntaxKind.PreIncrementExpression)||n.IsKind(SyntaxKind.PostIncrementExpression)||n.IsKind(SyntaxKind.PreDecrementExpression)||n.IsKind(SyntaxKind.PostDecrementExpression))) {
            var operand=update is PrefixUnaryExpressionSyntax pre?pre.Operand:((PostfixUnaryExpressionSyntax)update).Operand;
            var target=model.GetSymbolInfo(operand,token).Symbol;if(target is not (IPropertySymbol or IFieldSymbol))continue;
            var statement=update.Parent as ExpressionStatementSyntax;
            Fact("assignment",update,statement?.SemicolonToken.SpanStart??update.SpanStart,statement?.Span.End??-1,target,new {style=statement==null?"unsupported":"after"},statement?.SpanStart,statement?.Span.End);
        }
        foreach(var conditional in nodes.OfType<ConditionalExpressionSyntax>())Fact("unsupported_control",conditional,conditional.SpanStart,-1,null,new {references=References(conditional.Condition),style="unsupported"});
        foreach(var selection in nodes.OfType<SwitchExpressionSyntax>())Fact("unsupported_control",selection,selection.SpanStart,-1,null,new {references=References(selection.GoverningExpression),style="unsupported"});
        foreach(var loop in nodes.Where(n=>n is WhileStatementSyntax or DoStatementSyntax or ForStatementSyntax)) {
            ExpressionSyntax? condition=loop switch {WhileStatementSyntax w=>w.Condition,DoStatementSyntax d=>d.Condition,ForStatementSyntax f=>f.Condition,_=>null};
            if(condition!=null)Fact("unsupported_loop_control",loop,loop.SpanStart,-1,null,new {references=References(condition),style="unsupported"});
        }
        foreach(var invocation in nodes.Where(n=>n is InvocationExpressionSyntax or ObjectCreationExpressionSyntax)) {
            if(model.GetSymbolInfo(invocation,token).Symbol is not IMethodSymbol target)continue;
            var statement=invocation.Parent as ExpressionStatementSyntax;
            Fact("call",invocation,invocation.SpanStart,statement?.SpanStart??-1,target,new {style=statement==null?"unsupported":"before",after=statement?.Span.End??-1},statement?.SpanStart,statement?.Span.End);
        }
        foreach(var n in nodes) {
            if(n is AssignmentExpressionSyntax eventSyntax&&model.GetOperation(eventSyntax,token) is IEventAssignmentOperation ev) {
                if(ev.EventReference is IEventReferenceOperation er)Register(ev.HandlerValue,RecordSymbol(er.Event),"event");
            } else if(n is InvocationExpressionSyntax call&&model.GetOperation(call,token) is IInvocationOperation op) {
                foreach(var argument in op.Arguments)if(argument.Parameter?.Type.TypeKind==TypeKind.Delegate)Register(argument.Value,RecordSymbol(op.TargetMethod),"callback");
            } else if(n is ObjectCreationExpressionSyntax creation&&model.GetOperation(creation,token) is IObjectCreationOperation op2&&op2.Constructor!=null) {
                foreach(var argument in op2.Arguments)if(argument.Parameter?.Type.TypeKind==TypeKind.Delegate)Register(argument.Value,RecordSymbol(op2.Constructor),"callback");
            }
        }
        void Register(IOperation operation,string api,string kind) {
            if(operation is IMethodReferenceOperation reference)Run("INSERT OR IGNORE INTO application_registrations VALUES(@p0,@p1,@p2,@p3)",body.Id,RecordSymbol(reference.Method),api,kind);
            else if(operation is IAnonymousFunctionOperation anonymous)Run("INSERT OR IGNORE INTO application_registrations VALUES(@p0,@p1,@p2,@p3)",body.Id,RecordSymbol(anonymous.Symbol),api,kind);
            else foreach(var child in operation.ChildOperations)Register(child,api,kind);
        }
    }
}
