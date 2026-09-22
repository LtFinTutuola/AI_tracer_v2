using System;
using System.Collections.Generic;
using System.IO;
using Microsoft.Data.Sqlite;

namespace RoslynAnalyzer
{
    public class SqliteRepository
    {
        private readonly string _dbPath;
        private readonly string _connectionString;

        public SqliteRepository(string dbPath)
        {
            _dbPath = dbPath;
            _connectionString = $"Data Source={_dbPath}";
        }

        public void InitializeDatabase(bool clearAll = false)
        {
            if (clearAll && File.Exists(_dbPath))
            {
                File.Delete(_dbPath);
            }

            using var connection = new SqliteConnection(_connectionString);
            connection.Open();

            var command = connection.CreateCommand();
            command.CommandText = @"
                CREATE TABLE IF NOT EXISTS basic_blocks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    project_name TEXT NOT NULL,
                    file_path TEXT NOT NULL,
                    method_signature TEXT NOT NULL,
                    scope_start_line INTEGER NOT NULL,
                    scope_end_line INTEGER NOT NULL,
                    injection_line INTEGER NOT NULL,
                    injection_offset INTEGER NOT NULL DEFAULT 0,
                    reason TEXT NOT NULL,
                    to_trace INTEGER NOT NULL DEFAULT 1
                );
            ";
            command.ExecuteNonQuery();
        }

        public void SaveBlocksBatch(IEnumerable<BasicBlockRecord> records)
        {
            using var connection = new SqliteConnection(_connectionString);
            connection.Open();

            using var transaction = connection.BeginTransaction();
            
            var command = connection.CreateCommand();
            command.CommandText = @"
                INSERT INTO basic_blocks 
                (project_name, file_path, method_signature, scope_start_line, scope_end_line, injection_line, injection_offset, reason, to_trace) 
                VALUES 
                (@project_name, @file_path, @method_signature, @scope_start_line, @scope_end_line, @injection_line, @injection_offset, @reason, @to_trace)
            ";

            var projectParam = command.Parameters.Add("@project_name", SqliteType.Text);
            var fileParam = command.Parameters.Add("@file_path", SqliteType.Text);
            var sigParam = command.Parameters.Add("@method_signature", SqliteType.Text);
            var startParam = command.Parameters.Add("@scope_start_line", SqliteType.Integer);
            var endParam = command.Parameters.Add("@scope_end_line", SqliteType.Integer);
            var injParam = command.Parameters.Add("@injection_line", SqliteType.Integer);
            var offsetParam = command.Parameters.Add("@injection_offset", SqliteType.Integer);
            var reasonParam = command.Parameters.Add("@reason", SqliteType.Text);
            var toTraceParam = command.Parameters.Add("@to_trace", SqliteType.Integer);

            foreach (var record in records)
            {
                projectParam.Value = record.ProjectName;
                fileParam.Value = record.FilePath;
                sigParam.Value = record.MethodSignature ?? string.Empty;
                startParam.Value = record.ScopeStartLine;
                endParam.Value = record.ScopeEndLine;
                injParam.Value = record.InjectionLine;
                offsetParam.Value = record.InjectionOffset;
                reasonParam.Value = record.Reason ?? string.Empty;
                toTraceParam.Value = record.ToTrace ? 1 : 0;

                command.ExecuteNonQuery();
            }

            transaction.Commit();
        }
    }
}
