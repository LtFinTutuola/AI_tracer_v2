using System;
using System.Collections.Concurrent;
using System.IO;
using System.Threading;

namespace AITracer.Runtime
{
    public static class TraceContext
    {
        private static readonly AsyncLocal<string> _traceId = new AsyncLocal<string>();
        private static readonly ConcurrentQueue<string> _queue = new ConcurrentQueue<string>();
        
        private static string _logFilePath = @"C:\repo\AI_tracer_v2\code_analysis\aitracer_runtime.log";
        private static bool _isRunning = false;
        private static readonly object _lock = new object();

        public static void Configure(string logFilePath)
        {
            _logFilePath = logFilePath;
        }

        public static void Log(int blockId)
        {
            EnsureWriterStarted();

            if (_traceId.Value == null)
            {
                _traceId.Value = Guid.NewGuid().ToString("N");
            }

            int threadId = Thread.CurrentThread.ManagedThreadId;
            string timestamp = DateTime.UtcNow.ToString("O");
            
            // Format: Timestamp || TraceId || ThreadId || BlockId
            string entry = $"{timestamp}||{_traceId.Value}||{threadId}||{blockId}";
            _queue.Enqueue(entry);
        }

        private static void EnsureWriterStarted()
        {
            if (!_isRunning)
            {
                lock (_lock)
                {
                    if (!_isRunning)
                    {
                        _isRunning = true;
                        // Use a background thread so it doesn't prevent application exit
                        var thread = new Thread(WriterLoop)
                        {
                            IsBackground = true,
                            Name = "AITracer Background Writer"
                        };
                        thread.Start();
                    }
                }
            }
        }

        private static void WriterLoop()
        {
            while (true)
            {
                if (_queue.IsEmpty)
                {
                    Thread.Sleep(100);
                    continue;
                }

                int count = 0;
                
                try
                {
                    // Append mode
                    using (var stream = new FileStream(_logFilePath, FileMode.Append, FileAccess.Write, FileShare.ReadWrite))
                    using (var writer = new StreamWriter(stream))
                    {
                        while (_queue.TryDequeue(out var entry))
                        {
                            writer.WriteLine(entry);
                            count++;
                            
                            // Break out to flush periodically if it's a huge batch
                            if (count >= 1000)
                            {
                                break;
                            }
                        }
                    }
                }
                catch
                {
                    // Ignore I/O errors in background thread to avoid crashing the host app
                }

                if (count == 0)
                {
                    // Sleep if queue was empty to prevent tight loop
                    Thread.Sleep(100);
                }
            }
        }
    }
}
