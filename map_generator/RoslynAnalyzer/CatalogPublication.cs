using Microsoft.Data.Sqlite;

namespace RoslynAnalyzer;

/// <summary>Publishes only validated catalogs, preserving the previous generation for rollback.</summary>
public static class CatalogPublication
{
    public static void Publish(string staging, string destination)
    {
        using (var db = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource=staging, Mode=SqliteOpenMode.ReadOnly, Pooling=false }.ToString()))
        {
            db.Open();
            using var cmd=db.CreateCommand();
            cmd.CommandText="SELECT value FROM analysis_manifest WHERE key='state'";
            if ((string?)cmd.ExecuteScalar() != "validated") throw new InvalidOperationException("Unvalidated catalog");
            cmd.CommandText="PRAGMA integrity_check";
            if ((string?)cmd.ExecuteScalar() != "ok") throw new InvalidOperationException("Invalid catalog");
        }
        if(File.Exists(destination)) File.Replace(staging,destination,destination+".previous",true);
        else File.Move(staging,destination);
    }
}

public sealed class CatalogStaging : IDisposable
{
    public string Path { get; }
    public CatalogStaging(string directory) => Path=System.IO.Path.Combine(directory,"catalog-"+Guid.NewGuid().ToString("N")+".sqlite");
    public void Dispose()
    {
        // Only files belonging to this unique generation, never a published catalog.
        foreach(var suffix in new[]{"","-journal","-wal","-shm"})
            try { File.Delete(Path+suffix); }
            catch(IOException) { /* A retained staging file is safer than masking the original failure. */ }
    }
}
