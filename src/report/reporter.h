/**
 * MultiLog-OS: High-Performance Multithreaded Log Analysis & Threat Detection System
 * File: src/report/reporter.h
 */

#ifndef MULTILOG_REPORTER_H
#define MULTILOG_REPORTER_H

#include "../core/types.h"
#include "../io/file_io.h"
#include "../process/supervisor.h"
#include "../memory/arena.h"

/* Terminal formatted console report */
void reporter_print_console_summary(
    const AnalyzerConfig *config,
    const FileMetadata *meta,
    const GlobalStats *stats,
    const ProcessAccounting *proc,
    const MemoryMetrics *mem
);

/* Export structured JSON report (consumed by Dashboard & Evaluators) */
bool reporter_export_json(
    const char *filepath,
    const AnalyzerConfig *config,
    const FileMetadata *meta,
    const GlobalStats *stats,
    const ProcessAccounting *proc,
    const MemoryMetrics *mem
);

/* Export CSV report */
bool reporter_export_csv(
    const char *filepath,
    const GlobalStats *stats
);

/* Export Standalone HTML Report */
bool reporter_export_html(
    const char *filepath,
    const AnalyzerConfig *config,
    const FileMetadata *meta,
    const GlobalStats *stats,
    const ProcessAccounting *proc,
    const MemoryMetrics *mem
);

#endif /* MULTILOG_REPORTER_H */
