using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.CodeAnalysis;

namespace RoslynAnalyzer;

public sealed record ApplicationSymbol(string Key,string Assembly,string Namespace,string Type,string Member,string DocumentationId,string Kind,string[] Contracts);
public sealed record ApplicationRule
{
    public string Role {get;init;}="";
    public string? Assembly {get;init;}
    public string? Namespace {get;init;}
    public string? Type {get;init;}
    public string? Member {get;init;}
    public string? DocumentationId {get;init;}
    public string? Contract {get;init;}
    public int Specificity=>DocumentationId!=null||Member!=null?4:Type!=null||Contract!=null?3:Namespace!=null?2:1;
    public bool Matches(ApplicationSymbol s)=>
        (Assembly==null||Assembly==s.Assembly)&&(Namespace==null||s.Namespace==Namespace||s.Namespace.StartsWith(Namespace+".",StringComparison.Ordinal))&&
        (Type==null||Type==s.Type)&&(Member==null||Member==s.Member)&&(DocumentationId==null||DocumentationId==s.DocumentationId)&&
        (Contract==null||s.Contracts.Contains(Contract,StringComparer.Ordinal));
}
public sealed record CallbackContract(string Type,string Member);
public sealed record ApplicationPolicy
{
    [JsonRequired] public int Version {get;init;}=1;
    public string Name {get;init;}="";
    public string[] ApplicationAssemblies {get;init;}=Array.Empty<string>();
    public ApplicationRule[] Rules {get;init;}=Array.Empty<ApplicationRule>();
    public CallbackContract[] CallbackApis {get;init;}=new[]{new CallbackContract("System.Threading.Tasks.Task","Run"),new("System.Threading.Tasks.TaskFactory","StartNew"),new("System.Threading.Thread",".ctor"),new("System.Threading.Timer",".ctor"),new("System.Threading.SynchronizationContext","Post")};
    public string Fingerprint {get;private set;}="";
    public static readonly JsonSerializerOptions Json=new() {PropertyNamingPolicy=JsonNamingPolicy.SnakeCaseLower,PropertyNameCaseInsensitive=false,UnmappedMemberHandling=JsonUnmappedMemberHandling.Disallow};
    public static ApplicationPolicy Load(string path)
    {
        string text=File.ReadAllText(path);
        var p=JsonSerializer.Deserialize<ApplicationPolicy>(text,Json)??throw new ArgumentException("Empty application observation policy");
        if(p.Version!=1||string.IsNullOrWhiteSpace(p.Name)||p.Rules==null||p.ApplicationAssemblies==null||p.CallbackApis==null)throw new ArgumentException("Invalid application policy version/name/arrays");
        if(p.Rules.Any(r=>r==null))throw new ArgumentException("Null application rule");
        string[] roles={"operation","decision","outcome","state_assignment","technical","opaque"};
        foreach(var rule in p.Rules)if(!roles.Contains(rule.Role)||new[]{rule.Assembly,rule.Namespace,rule.Type,rule.Member,rule.DocumentationId,rule.Contract}.All(v=>v==null)||
            new[]{rule.Assembly,rule.Namespace,rule.Type,rule.Member,rule.DocumentationId,rule.Contract}.Any(v=>v!=null&&string.IsNullOrWhiteSpace(v)))throw new ArgumentException("Invalid application policy selector/role");
        if(p.ApplicationAssemblies.Any(string.IsNullOrWhiteSpace)||p.CallbackApis.Any(c=>c==null||string.IsNullOrWhiteSpace(c.Type)||string.IsNullOrWhiteSpace(c.Member)))throw new ArgumentException("Invalid application assemblies/callback API");
        foreach(var group in p.Rules.GroupBy(r=>JsonSerializer.Serialize(r with {Role=""},Json)))
            if(group.Select(r=>r.Role).Distinct().Count()>1)throw new ArgumentException("Contradictory application policy rules");
        p.Fingerprint=ContextCatalog.Id(text);return p;
    }
    public string? Role(ApplicationSymbol symbol)
    {
        var matches=Rules.Where(r=>r.Matches(symbol)).ToArray();if(matches.Length==0)return null;
        int specificity=matches.Max(r=>r.Specificity);var roles=matches.Where(r=>r.Specificity==specificity).Select(r=>r.Role).Distinct().ToArray();
        if(roles.Length!=1)throw new InvalidOperationException("Contradictory application rules for "+symbol.Key);
        return roles[0];
    }
    public static string Key(ISymbol symbol)
    {
        symbol=(symbol is IMethodSymbol m?m.ReducedFrom??m:symbol).OriginalDefinition;
        return symbol.ContainingAssembly?.Identity+":"+(symbol.GetDocumentationCommentId()??symbol.ToDisplayString(SymbolDisplayFormat.FullyQualifiedFormat)+":"+
            string.Join(';',symbol.Locations.Where(l=>l.IsInSource).Select(l=>l.SourceTree?.FilePath+":"+l.SourceSpan.Start)));
    }
    public static ApplicationSymbol Describe(ISymbol symbol)
    {
        symbol=(symbol is IMethodSymbol m?m.ReducedFrom??m:symbol).OriginalDefinition;
        var contracts=new HashSet<string>(StringComparer.Ordinal);
        for(var t=symbol.ContainingType;t!=null;t=t.BaseType)contracts.Add(t.OriginalDefinition.ToDisplayString());
        foreach(var t in symbol.ContainingType?.AllInterfaces??default)contracts.Add(t.OriginalDefinition.ToDisplayString());
        if(symbol is IMethodSymbol method)for(var current=method.OverriddenMethod;current!=null;current=current.OverriddenMethod) {
            contracts.Add(current.ContainingType.OriginalDefinition.ToDisplayString());contracts.Add(current.GetDocumentationCommentId()??"");
        }
        return new(Key(symbol),symbol.ContainingAssembly?.Name??"",symbol.ContainingNamespace?.ToDisplayString()??"",symbol.ContainingType?.OriginalDefinition.ToDisplayString()??"",
            symbol is IMethodSymbol {MethodKind:MethodKind.Constructor}?".ctor":symbol.Name,symbol.GetDocumentationCommentId()??"",symbol.Kind.ToString(),contracts.OrderBy(x=>x,StringComparer.Ordinal).ToArray());
    }
}
