using System.Security.Cryptography;
using System.Text.Json;
namespace RoslynAnalyzer;

/// <summary>Known inputs only; does not claim detection of newly added files.</summary>
public sealed class InputRegistry
{
    private readonly Dictionary<string,string> hashes=new(StringComparer.OrdinalIgnoreCase);
    private static string Hash(string path)=>Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path)));
    public void Track(string? path, string? workspaceText=null)
    {
        if(string.IsNullOrEmpty(path) || !File.Exists(path)) return;
        path=Path.GetFullPath(path);
        if(!hashes.ContainsKey(path)) hashes[path]=Hash(path);
        if(workspaceText!=null && File.ReadAllText(path)!=workspaceText)
            throw new InvalidOperationException("Workspace/disk source mismatch: "+path);
    }
    public void Verify(CancellationToken token=default)
    {
        foreach(var (path,hash) in hashes) {
            token.ThrowIfCancellationRequested();
            if(!File.Exists(path) || Hash(path)!=hash) throw new InvalidOperationException("Input changed during analysis: "+path);
        }
    }
    public string Manifest()=>JsonSerializer.Serialize(hashes.OrderBy(p=>p.Key));
    public static void VerifyManifest(string manifest,CancellationToken token=default,string? excluding=null)
    {
        var entries=JsonSerializer.Deserialize<KeyValuePair<string,string>[]>(manifest)??Array.Empty<KeyValuePair<string,string>>();
        foreach(var entry in entries) {
            token.ThrowIfCancellationRequested();
            if(excluding!=null&&string.Equals(Path.GetFullPath(entry.Key),Path.GetFullPath(excluding),StringComparison.OrdinalIgnoreCase))continue;
            if(!File.Exists(entry.Key)||Hash(entry.Key)!=entry.Value)throw new InvalidOperationException("Known input changed since extraction: "+entry.Key);
        }
    }
    public static string ReplacePolicy(string manifest,string? previous,string policy)
    {
        policy=Path.GetFullPath(policy);if(!string.IsNullOrEmpty(previous))previous=Path.GetFullPath(previous);
        var entries=(JsonSerializer.Deserialize<KeyValuePair<string,string>[]>(manifest)??Array.Empty<KeyValuePair<string,string>>())
            .Where(p=>!string.Equals(p.Key,previous,StringComparison.OrdinalIgnoreCase)&&!string.Equals(p.Key,policy,StringComparison.OrdinalIgnoreCase)).ToList();
        entries.Add(new(Path.GetFullPath(policy),Hash(policy)));
        return JsonSerializer.Serialize(entries.OrderBy(p=>p.Key,StringComparer.OrdinalIgnoreCase));
    }
}
