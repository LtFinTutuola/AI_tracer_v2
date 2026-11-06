using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace RoslynAnalyzer;

public sealed class TraceRootCoverage(long method)
{
    public long MethodId {get;}=method;
    public string Status {get;set;}="pending";
    public int[] Attempts {get;}=new int[3];
    public int[] Accepted {get;}=new int[3];
    internal Dictionary<TraceWord,int>[] Samples {get;}=new[]{new Dictionary<TraceWord,int>(),new(),new()};
}
public sealed record TraceValidation(long Executions,long EventsBefore,long EventsAfter,long AmbiguousExecutions,
    int CollidingSignatures,int MaximumCandidates,long SilentExecutions,long EmpiricalMinorityExecutions,double ConditionalEntropyBits)
{
    public double AmbiguityFraction=>Executions==0?0:(double)AmbiguousExecutions/Executions;
    public double EventReductionFraction=>EventsBefore==0?0:1-(double)EventsAfter/EventsBefore;
    public List<TraceCounterexample> Counterexamples {get;init;}=new();
    public List<TracePreview> SilentCounterexamples {get;init;}=new();
}
public sealed record TraceCounterexample(long[] FirstBaseline,long[] SecondBaseline,long[] Reduced,bool Truncated);
public sealed record TracePreview(long[] Events,bool Truncated);
public sealed class TraceSelectionResult
{
    public string Status {get;set;}="not_run";
    public bool Partial {get;set;}
    public string? FallbackReason {get;set;}
    public HashSet<long> Disabled {get;set;}=new();
    public Dictionary<long,string> Protected {get;}=new();
    public List<TraceRootCoverage> Roots {get;}=new();
    public Dictionary<string,long> SampleOutcomes {get;}=new();
    public Dictionary<string,long> OpaqueCalls {get;}=new();
    public TraceOptimization? Fit {get;set;}
    public TraceValidation? Validation {get;set;}
    public TraceValidation? ValidationBeforeRepair {get;set;}
    public HashSet<long> RestoredForActivity {get;}=new();
    public int RootsWithoutEvents {get;set;}
    public long PeakBufferBytes {get;set;}
    public double DurationSeconds {get;set;}
    public string CorpusFingerprint {get;set;}="";
    public int ProbeCount {get;set;}
    public int BaselineDisabledCount {get;set;}
    public TraceSelectionOptions Options {get;set;}=new();
    public long TrainingExecutions {get;set;}
    public long CalibrationExecutions {get;set;}
    public const string Algorithm="ordered_partition_greedy_local_qualification_v3";
    public object Summary=>new {algorithm=Algorithm,status=Status,partial=Partial,
        options=Options,
        qualification_policy="protect_unqualified_method_owners_only",
        incomplete_callers_coverage="partial; qualified callees remain eligible",
        fallback_reason=FallbackReason,probes=ProbeCount,disabled=Disabled.Count,baseline_disabled=BaselineDisabledCount,
        enabled=ProbeCount-BaselineDisabledCount-Disabled.Count,metrics_scope=Status=="fallback"?"discarded_candidate":"applied_profile",
        protected_probes=Protected.Count,protected_reasons=Protected.Values.GroupBy(reason=>reason).ToDictionary(group=>group.Key,group=>group.Count()),
        roots=Roots.Count,roots_without_events=RootsWithoutEvents,root_statuses=Roots.GroupBy(root=>root.Status).ToDictionary(group=>group.Key,group=>group.Count()),
        qualified_roots=Roots.Count(root=>root.Status=="qualified"),fit=Fit==null?null:new {
            TrainingExecutions,CalibrationExecutions,Fit.TrainingAmbiguous,Fit.CalibrationAmbiguous,
            training_ambiguity_fraction=TrainingExecutions==0?0:(double)Fit.TrainingAmbiguous/TrainingExecutions,
            calibration_ambiguity_fraction=CalibrationExecutions==0?0:(double)Fit.CalibrationAmbiguous/CalibrationExecutions,
            Fit.MaximumCandidates,Fit.EventsBefore,Fit.EventsAfter,event_reduction_fraction=Fit.EventsBefore==0?0:1-(double)Fit.EventsAfter/Fit.EventsBefore,Fit.TimeLimited},
        validation=Validation,validation_before_repair=ValidationBeforeRepair,
        validation_role=RestoredForActivity.Count>0?"repair_calibration":"independent_validation",
        activity_repair=new {restored_count=RestoredForActivity.Count,restored_ids=RestoredForActivity.OrderBy(id=>id)},
        sample_outcomes=SampleOutcomes,opaque_calls=OpaqueCalls,
        peak_buffer_bytes=PeakBufferBytes,duration_seconds=DurationSeconds,corpus_fingerprint=CorpusFingerprint};
}

public static class TraceSelectionEngine
{
    private const int MinimumSuccessful=16;
    public static TraceSelectionResult Select(string catalogPath,TraceSelectionOptions options,
        CancellationToken token=default,Action<string,object?>? progress=null)
    {
        options.Validate();var result=new TraceSelectionResult {Options=options};var resources=new SelectionResources(options,token);
        token.ThrowIfCancellationRequested();
        if(!options.Enabled){result.Status="disabled";return result;}
        TraceSelectionModel? model=null;
        try {
            progress?.Invoke("selection_load",options);model=new(catalogPath,resources,options.MaxMemoryMb);model.Load();
            result.ProbeCount=model.Probes.Count;
            result.BaselineDisabledCount=model.Probes.Values.Count(probe=>!probe.Baseline);
            var active=model.ActiveRoots(options.MaxCallDepth);
            result.RootsWithoutEvents=model.Methods.Count-active.Count;
            resources.Reserve(active.Count*1024L);
            foreach(var method in model.Methods.Values.Where(method=>active.Contains(method.Id)).OrderBy(method=>method.Key,StringComparer.Ordinal).ThenBy(method=>method.Id))
                result.Roots.Add(new(method.Id));
            var pool=new Dictionary<TraceWord,TraceWord>();
            var validation=new Dictionary<TraceWord,long>();
            TraceWord Intern(TraceWord word) {
                if(pool.TryGetValue(word,out var old))return old;
                resources.Reserve(192+word.Events.Length*8L);pool[word]=word;return word;
            }
            void Sample(TraceRootCoverage root,int split,int attempt) {
                root.Attempts[split]++;
                var sample=model.Sample(root.MethodId,split,attempt,options);
                result.SampleOutcomes[sample.Status]=result.SampleOutcomes.GetValueOrDefault(sample.Status)+1;
                if(sample.Word==null)return;
                var word=Intern(sample.Word);root.Accepted[split]++;
                void AddValidation(TraceWord value,int count) {
                    if(!validation.ContainsKey(value))resources.Reserve(80);
                    validation[value]=validation.GetValueOrDefault(value)+count;
                }
                if(split==2&&root.Accepted[split]>MinimumSuccessful) {AddValidation(word,1);return;}
                if(!root.Samples[split].ContainsKey(word))resources.Reserve(64);
                root.Samples[split][word]=root.Samples[split].GetValueOrDefault(word)+1;
                if(split==2&&root.Accepted[split]==MinimumSuccessful) {
                    foreach(var (value,count) in root.Samples[split])AddValidation(value,count);
                    resources.Release(root.Samples[split].Count*64L);root.Samples[split]=new();
                }
            }
            int fitAttempts=options.SamplesPerRoot/4;
            progress?.Invoke("selection_sample",new {roots=result.Roots.Count,attempts_per_fit_split=fitAttempts});
            // Fair chunks: visit all roots before adding another 16 attempts.
            bool samplingLimited=false;
            double lastProgress=resources.Seconds;
            try {
                for(int chunk=0;chunk<fitAttempts;chunk+=16)
                    foreach(var root in result.Roots) {
                        resources.Check();
                        if(resources.Seconds-lastProgress>=5) {
                            progress?.Invoke("selection_sample",new {elapsed_seconds=resources.Seconds,
                                roots_started=result.Roots.Count(item=>item.Attempts[0]>0),buffer_bytes=resources.Bytes});lastProgress=resources.Seconds;
                        }
                        for(int attempt=chunk;attempt<Math.Min(chunk+16,fitAttempts);attempt++) {
                            Sample(root,0,attempt);Sample(root,1,attempt);
                        }
                    }
            } catch(SelectionDeadlineException){samplingLimited=true;}
            resources.PhaseFraction=.8;
            foreach(var root in result.Roots)
                root.Status=root.Accepted[0]>=MinimumSuccessful&&root.Accepted[1]>=MinimumSuccessful?"fit_qualified":"unqualified_fit";
            model.ProtectUnqualifiedMethods(result.Roots.Where(root=>root.Status!="fit_qualified").Select(root=>root.MethodId));
            var fitRows=new Dictionary<TraceWord,(long Training,long Calibration)>();
            foreach(var root in result.Roots.Where(root=>root.Status=="fit_qualified"))
                for(int split=0;split<2;split++)foreach(var (word,count) in root.Samples[split]) {
                    resources.Check();var old=fitRows.GetValueOrDefault(word);
                    if(!fitRows.ContainsKey(word))resources.Reserve(96);
                    fitRows[word]=split==0?(old.Training+count,old.Calibration):(old.Training,old.Calibration+count);
                }
            var observed=fitRows.Keys.SelectMany(word=>word.Events).ToHashSet();
            foreach(var root in result.Roots)for(int split=0;split<2;split++) {
                resources.Release(root.Samples[split].Count*64L);root.Samples[split]=new();
            }
            foreach(var word in pool.Keys.Where(word=>!fitRows.ContainsKey(word)).ToArray()) {
                pool.Remove(word);resources.Release(192+word.Events.Length*8L);
            }
            model.ClearCache();
            foreach(var probe in model.Probes.Values)if(!observed.Contains(probe.Id))model.Protected.TryAdd(probe.Id,"unobserved");
            result.TrainingExecutions=fitRows.Values.Sum(row=>row.Training);result.CalibrationExecutions=fitRows.Values.Sum(row=>row.Calibration);
            progress?.Invoke("selection_optimize",new {words=fitRows.Count,protected_probes=model.Protected.Count});
            result.Fit=TraceSequenceSelector.Select(fitRows.Select(row=>new TraceObservation(row.Key,row.Value.Training,row.Value.Calibration)),
                model.Protected.Keys.ToHashSet(),options.AmbiguityBudget,options.MaxCandidates,()=>resources.HasTime,resources.Reserve,resources.Release,token);
            result.Disabled=new(result.Fit.Disabled);
            resources.PhaseFraction=1;
            var qualified=result.Roots.Where(root=>root.Status=="fit_qualified").ToArray();
            int validationAttempts=options.SamplesPerRoot-2*fitAttempts;
            progress?.Invoke("selection_verify",new {roots=qualified.Length,attempts=validationAttempts});
            for(int chunk=0;chunk<validationAttempts;chunk+=16)
                foreach(var root in qualified) {
                    if(resources.Seconds-lastProgress>=5) {
                        progress?.Invoke("selection_verify",new {elapsed_seconds=resources.Seconds,
                            roots_started=qualified.Count(item=>item.Attempts[2]>0),buffer_bytes=resources.Bytes});lastProgress=resources.Seconds;
                    }
                    for(int attempt=chunk;attempt<Math.Min(chunk+16,validationAttempts);attempt++)Sample(root,2,attempt);
                }
            foreach(var root in qualified)root.Status=root.Accepted[2]>=MinimumSuccessful?"qualified":"unqualified_validation";
            model.ProtectUnqualifiedMethods(qualified.Where(root=>root.Status!="qualified").Select(root=>root.MethodId));
            result.Disabled.ExceptWith(model.Protected.Keys);
            foreach(var root in result.Roots) {
                resources.Release(root.Samples[2].Count*64L);root.Samples[2]=new();
            }
            model.ClearCache();
            foreach(var word in pool.Keys)resources.Release(128+(!fitRows.ContainsKey(word)&&!validation.ContainsKey(word)?64+word.Events.Length*8L:0));
            pool.Clear();pool.TrimExcess();
            result.ValidationBeforeRepair=Assess(fitRows.Keys,validation,result.Disabled,resources.Check,resources.Reserve,resources.Release);
            if(result.ValidationBeforeRepair.SilentExecutions>0) {
                progress?.Invoke("selection_repair_activity",new {silent_executions=result.ValidationBeforeRepair.SilentExecutions});
                result.RestoredForActivity.UnionWith(RepairActivity(validation,fitRows.Select(row=>new TraceObservation(row.Key,row.Value.Training,row.Value.Calibration)),
                    result.Disabled,resources.Check,resources.Reserve,resources.Release));
            }
            TraceValidation MeasureFit(bool training) {
                long bytes=fitRows.Count*80L;resources.Reserve(bytes);
                try {
                    var weights=fitRows.ToDictionary(row=>row.Key,row=>training?row.Value.Training:row.Value.Calibration);
                    return Assess(fitRows.Keys,weights,result.Disabled,resources.Check,resources.Reserve,resources.Release);
                } finally {resources.Release(bytes);}
            }
            var finalTrain=MeasureFit(true);var finalCalibration=MeasureFit(false);
            result.Fit=result.Fit with {Disabled=new(result.Disabled),TrainingAmbiguous=finalTrain.AmbiguousExecutions,
                CalibrationAmbiguous=finalCalibration.AmbiguousExecutions,MaximumCandidates=Math.Max(finalTrain.MaximumCandidates,finalCalibration.MaximumCandidates),
                EventsBefore=finalTrain.EventsBefore+finalCalibration.EventsBefore,EventsAfter=finalTrain.EventsAfter+finalCalibration.EventsAfter};
            result.Validation=result.RestoredForActivity.Count==0?result.ValidationBeforeRepair:
                Assess(fitRows.Keys,validation,result.Disabled,resources.Check,resources.Reserve,resources.Release);
            result.CorpusFingerprint=Fingerprint(fitRows,validation,resources.Check);
            foreach(var (id,reason) in model.Protected)result.Protected[id]=reason;
            foreach(var (reason,count) in model.OpaqueCalls)result.OpaqueCalls[reason]=count;
            result.Partial=result.RestoredForActivity.Count>0||samplingLimited||result.Fit.TimeLimited||result.Roots.Any(root=>root.Status!="qualified")||
                result.Validation.AmbiguityFraction>options.AmbiguityBudget||result.Validation.MaximumCandidates>options.MaxCandidates;
            result.Status=result.Partial?"applied_partial":"applied";
            string? rejection=ValidationRejection(result.Validation,result.Roots.Any(root=>root.Status=="qualified"));
            if(rejection!=null)Fallback(rejection);
            return result;
        } catch(SelectionMemoryException){Fallback("memory_limit");return result;}
          catch(SelectionDeadlineException){Fallback("verification_or_setup_timeout");return result;}
        finally {
            if(model!=null) {
                result.ProbeCount=model.Probes.Count;
                foreach(var (id,reason) in model.Protected)result.Protected[id]=reason;
                foreach(var (reason,count) in model.OpaqueCalls)result.OpaqueCalls[reason]=count;
                model.Dispose();
            }
            result.PeakBufferBytes=resources.PeakBytes;result.DurationSeconds=resources.Seconds;
        }
        void Fallback(string reason){result.Disabled=new();result.Status="fallback";result.Partial=true;result.FallbackReason=reason;}
    }

    internal static string? ValidationRejection(TraceValidation validation,bool hasQualifiedRoots)=>
        validation.SilentExecutions>0?"silent_validation_trace":!hasQualifiedRoots?"no_qualified_contexts":null;

    // Greedy weighted hitting set over ALL silent words, never the truncated report examples.
    // Costs come from fit occurrences; the repaired corpus is explicitly calibration data.
    internal static HashSet<long> RepairActivity(IReadOnlyDictionary<TraceWord,long> validation,
        IEnumerable<TraceObservation> fit,ISet<long> disabled,Action? check=null,Action<long>? reserve=null,Action<long>? release=null)
    {
        long owned=0;
        void Charge(long bytes){reserve?.Invoke(bytes);owned+=bytes;}
        try {
            var words=new List<HashSet<long>>();var costs=new Dictionary<long,long>();
            foreach(var (word,count) in validation) {
                check?.Invoke();
                if(count<=0||word.Events.Length==0||!word.Events.All(disabled.Contains))continue;
                Charge(192+word.Events.Length*64L);
                var ids=word.Events.ToHashSet();words.Add(ids);
                foreach(long id in ids)costs.TryAdd(id,0);
            }
            foreach(var row in fit) {
                check?.Invoke();
                foreach(long id in row.Word.Events)if(costs.ContainsKey(id))costs[id]=checked(costs[id]+row.Training+row.Calibration);
            }
            var restored=new HashSet<long>();
            while(words.Count>0) {
                check?.Invoke();
                var coverage=new Dictionary<long,int>();
                foreach(var word in words) {
                    check?.Invoke();foreach(long id in word)coverage[id]=coverage.GetValueOrDefault(id)+1;
                }
                long best=coverage.Keys.OrderBy(id=>(double)costs[id]/coverage[id]).ThenBy(id=>costs[id]).ThenBy(id=>id).First();
                restored.Add(best);words.RemoveAll(word=>word.Contains(best));
            }
            check?.Invoke();disabled.ExceptWith(restored);return restored;
        } finally {release?.Invoke(owned);}
    }

    public static TraceValidation Assess(IEnumerable<TraceWord> reference,IReadOnlyDictionary<TraceWord,long> validation,
        ISet<long> disabled,Action? check=null,Action<long>? reserve=null,Action<long>? release=null)
    {
        var groups=new Dictionary<TraceWord,(int Classes,long Count,long Maximum,double SumCountLogCount,TraceWord First)>();
        var examples=new List<TraceCounterexample>();
        var silentExamples=new List<TracePreview>();
        long owned=0;
        try {
            var known=new HashSet<TraceWord>();
            foreach(var word in reference.Concat(validation.Keys)) {
                check?.Invoke();if(!known.Add(word))continue;
                long bytes=384+word.Events.Length*16L;reserve?.Invoke(bytes);owned+=bytes;
                var projected=new TraceWord(word.Events.Where(id=>!disabled.Contains(id)));
                var old=groups.GetValueOrDefault(projected);long count=validation.GetValueOrDefault(word);
                if(old.Classes==1&&examples.Count<3)examples.Add(new(old.First.Events.Take(64).ToArray(),word.Events.Take(64).ToArray(),projected.Events.Take(64).ToArray(),old.First.Events.Length>64||word.Events.Length>64));
                groups[projected]=(old.Classes+1,old.Count+count,Math.Max(old.Maximum,count),old.SumCountLogCount+(count>0?count*Math.Log2(count):0),old.Classes==0?word:old.First);
            }
            long runs=0,before=0,after=0,silent=0;
            foreach(var (word,count) in validation) {
                check?.Invoke();runs+=count;before+=word.Events.Length*count;
                int remaining=word.Events.Count(id=>!disabled.Contains(id));after+=remaining*count;
                if(word.Events.Length>0&&remaining==0) {
                    silent+=count;
                    if(silentExamples.Count<3)silentExamples.Add(new(word.Events.Take(64).ToArray(),word.Events.Length>64));
                }
            }
            long ambiguous=groups.Values.Where(group=>group.Classes>1).Sum(group=>group.Count);
            long minority=groups.Values.Sum(group=>group.Count-group.Maximum);
            double entropy=groups.Values.Where(group=>group.Count>0).Sum(group=>group.Count*Math.Log2(group.Count)-group.SumCountLogCount);
            return new(runs,before,after,ambiguous,groups.Values.Count(group=>group.Classes>1),
                groups.Count==0?0:groups.Values.Max(group=>group.Classes),silent,minority,runs==0?0:entropy/runs) {Counterexamples=examples,SilentCounterexamples=silentExamples};
        } finally {release?.Invoke(owned);}
    }
    private static string Fingerprint(Dictionary<TraceWord,(long Training,long Calibration)> fit,Dictionary<TraceWord,long> validation,Action check)
    {
        using var hash=IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        Span<byte> buffer=stackalloc byte[8];
        foreach(var word in fit.Keys.Concat(validation.Keys).Distinct().OrderBy(word=>word,WordComparer.Instance)) {
            check();var counts=fit.GetValueOrDefault(word);
            System.Buffers.Binary.BinaryPrimitives.WriteInt64LittleEndian(buffer,word.Events.Length);hash.AppendData(buffer);
            foreach(long id in word.Events){System.Buffers.Binary.BinaryPrimitives.WriteInt64LittleEndian(buffer,id);hash.AppendData(buffer);}
            foreach(long count in new[]{counts.Training,counts.Calibration,validation.GetValueOrDefault(word)}) {
                System.Buffers.Binary.BinaryPrimitives.WriteInt64LittleEndian(buffer,count);hash.AppendData(buffer);
            }
        }
        return Convert.ToHexString(hash.GetHashAndReset()).ToLowerInvariant();
    }
    private sealed class WordComparer:IComparer<TraceWord>
    {
        public static WordComparer Instance {get;}=new();
        public int Compare(TraceWord? a,TraceWord? b) {
            if(a==null||b==null)return a==b?0:a==null?-1:1;
            for(int i=0;i<Math.Min(a.Events.Length,b.Events.Length);i++) {
                int result=a.Events[i].CompareTo(b.Events[i]);if(result!=0)return result;
            }
            return a.Events.Length.CompareTo(b.Events.Length);
        }
    }
}
