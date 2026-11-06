using Microsoft.Data.Sqlite;
namespace RoslynAnalyzer;

/// <summary>Legacy schema contract; ContextCatalog owns the shared writer.</summary>
public sealed class SqliteRepository
{
    private readonly string path;
    public SqliteRepository(string path) => this.path = path;
    public const string Schema = """
        CREATE TABLE IF NOT EXISTS basic_blocks (
          id INTEGER PRIMARY KEY AUTOINCREMENT, project_name TEXT NOT NULL,
          file_path TEXT NOT NULL, method_signature TEXT NOT NULL,
          scope_start_line INTEGER NOT NULL, scope_end_line INTEGER NOT NULL,
          block_start_line INTEGER NOT NULL, block_end_line INTEGER NOT NULL,
          injection_line INTEGER NOT NULL, injection_offset INTEGER NOT NULL DEFAULT 0,
          reason TEXT NOT NULL, to_trace INTEGER NOT NULL DEFAULT 1,
          wrap_in_block INTEGER NOT NULL DEFAULT 0, statement_end_offset INTEGER NOT NULL DEFAULT 0);
        CREATE UNIQUE INDEX IF NOT EXISTS idx_basic_blocks_file_offset ON basic_blocks(file_path,injection_offset);
        """;
    public static object[] Values(BasicBlockRecord b) => new object[] {
        b.ProjectName,b.FilePath,b.MethodSignature,b.ScopeStartLine,b.ScopeEndLine,b.BlockStartLine,
        b.BlockEndLine,b.InjectionLine,b.InjectionOffset,b.Reason,b.ToTrace?1:0,b.WrapInBlock?1:0,b.StatementEndOffset };
    public const string Insert = """
        INSERT INTO basic_blocks(project_name,file_path,method_signature,scope_start_line,scope_end_line,
          block_start_line,block_end_line,injection_line,injection_offset,reason,to_trace,wrap_in_block,statement_end_offset)
        VALUES(@p0,@p1,@p2,@p3,@p4,@p5,@p6,@p7,@p8,@p9,@p10,@p11,@p12) RETURNING id
        """;
    public void InitializeDatabase(bool clearAll=false)
    {
        if(clearAll && File.Exists(path)) File.Delete(path);
        using var db=new SqliteConnection(new SqliteConnectionStringBuilder { DataSource=path,Pooling=false }.ToString());
        db.Open(); using var cmd=db.CreateCommand(); cmd.CommandText=Schema; cmd.ExecuteNonQuery();
    }
    public void SaveBlocksBatch(IEnumerable<BasicBlockRecord> records)
    {
        using var db=new SqliteConnection(new SqliteConnectionStringBuilder { DataSource=path,Pooling=false }.ToString());
        db.Open(); using var tx=db.BeginTransaction(); using var cmd=db.CreateCommand();
        cmd.Transaction=tx; cmd.CommandText=Insert;
        for(int i=0;i<13;i++) cmd.Parameters.Add(new SqliteParameter("@p"+i,DBNull.Value));
        foreach(var b in records) {
            var values=Values(b); for(int i=0;i<values.Length;i++) cmd.Parameters[i].Value=values[i];
            cmd.ExecuteScalar();
        }
        tx.Commit();
    }
}
