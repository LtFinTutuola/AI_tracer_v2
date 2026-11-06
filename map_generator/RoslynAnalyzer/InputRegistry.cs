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
}
