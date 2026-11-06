using Microsoft.CodeAnalysis;

if(args.Length==3 && args[0]=="--probe-selection-experiment")
{
    Environment.ExitCode=ProbeSelectionInjectionExperiment.Run(Path.GetFullPath(args[1]),Path.GetFullPath(args[2]));
    return;
}

string directory=Path.Combine(Path.GetTempPath(),"injection-tests-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(directory);
int assertions=0;
try {
    var references=((string)AppContext.GetData("TRUSTED_PLATFORM_ASSEMBLIES")!).Split(Path.PathSeparator).Select(p=>MetadataReference.CreateFromFile(p)).ToArray();
    InjectionTests.Run(directory,references,(valid,message)=> {assertions++;if(!valid)throw new Exception(message);});
    Console.WriteLine($"Injection tests: {assertions} assertions passed");
} finally {Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();Directory.Delete(directory,true);}
