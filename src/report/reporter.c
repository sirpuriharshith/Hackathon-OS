/**
 * MultiLog-OS: High-Performance Multithreaded Log Analysis & Threat Detection System
 * File: src/report/reporter.c
 */

#include "reporter.h"

void reporter_print_console_summary(
    const AnalyzerConfig *config,
    const FileMetadata *meta,
    const GlobalStats *stats,
    const ProcessAccounting *proc,
    const MemoryMetrics *mem
) {
    if (!config || !meta || !stats || !proc || !mem) return;

    printf("\n");
    printf("######################################################################\n");
    printf("#      MultiLog-OS: HIGH-PERFORMANCE MULTITHREADED LOG ANALYZER      #\n");
    printf("######################################################################\n\n");

    printf("[1. WORKLOAD & SYSTEM CONFIGURATION]\n");
    printf("  Target Log File       : %s\n", meta->filename);
    printf("  File Size             : %.2f MB (%llu bytes)\n", (double)meta->file_size_bytes / (1024.0 * 1024.0), (unsigned long long)meta->file_size_bytes);
    printf("  Worker Thread Count   : %d Threads\n", config->thread_count);
    printf("  I/O Mechanism (CO-5)  : %s\n", io_mode_to_string(config->io_mode));
    printf("  Virtual Page Size     : %d Bytes\n", VIRTUAL_PAGE_SIZE);

    printf("\n[2. LOG SEVERITY CLASSIFICATION]\n");
    printf("  Total Lines Processed : %llu\n", (unsigned long long)stats->total_lines);
    printf("  Total Volume Analyzed : %.2f MB\n", (double)stats->total_bytes / (1024.0 * 1024.0));
    printf("  [!] Errors / Fatal    : %llu\n", (unsigned long long)(stats->total_error + stats->total_fatal));
    printf("  [*] Warnings          : %llu\n", (unsigned long long)stats->total_warn);
    printf("  [i] Informational     : %llu\n", (unsigned long long)stats->total_info);

    printf("\n[3. SUSPICIOUS SECURITY EVENTS & THREATS (CO-6 Protected)]\n");
    printf("  SQL Injections        : %llu\n", (unsigned long long)stats->total_threats[THREAT_SQL_INJECTION]);
    printf("  Cross-Site Scripting  : %llu\n", (unsigned long long)stats->total_threats[THREAT_XSS]);
    printf("  Directory Traversals  : %llu\n", (unsigned long long)stats->total_threats[THREAT_DIR_TRAVERSAL]);
    printf("  Recon Probes / Scans  : %llu\n", (unsigned long long)stats->total_threats[THREAT_MALICIOUS_PROBE]);
    printf("  Auth / Brute Force    : %llu\n", (unsigned long long)stats->total_threats[THREAT_AUTH_FAILURE]);
    printf("  Privilege Escalations : %llu\n", (unsigned long long)stats->total_threats[THREAT_PRIVILEGE_ESC]);

    printf("\n[4. HTTP STATUS DISTRIBUTION]\n");
    printf("  2xx Success           : %llu\n", (unsigned long long)stats->http_status_dist[2]);
    printf("  3xx Redirection       : %llu\n", (unsigned long long)stats->http_status_dist[3]);
    printf("  4xx Client Error      : %llu\n", (unsigned long long)stats->http_status_dist[4]);
    printf("  5xx Server Error      : %llu\n", (unsigned long long)stats->http_status_dist[5]);

    printf("\n[5. OPERATING SYSTEM & HARDWARE TELEMETRY]\n");
    printf("  Execution Wall-Time   : %.4f seconds\n", proc->elapsed_wall_sec);
    double mb_s = proc->elapsed_wall_sec > 0.0001 ? ((double)stats->total_bytes / (1024.0 * 1024.0)) / proc->elapsed_wall_sec : 0;
    double lps = proc->elapsed_wall_sec > 0.0001 ? (double)stats->total_lines / proc->elapsed_wall_sec : 0;
    printf("  Processing Throughput : %.2f MB/sec (%.0f lines/sec)\n", mb_s, lps);
    printf("  User-Space CPU Time   : %.4f sec (Pure computation)\n", proc->user_cpu_time_sec);
    printf("  Kernel-Space CPU Time : %.4f sec (I/O, Page Faults & Syscalls)\n", proc->kernel_cpu_time_sec);
    printf("  Resident Set Size(RSS): %.2f MB (Physical RAM)\n", (double)mem->resident_set_size_bytes / (1024.0 * 1024.0));
    printf("  Peak Working Set      : %.2f MB\n", (double)mem->peak_working_set_bytes / (1024.0 * 1024.0));
    printf("  Page Fault Count      : %llu (Soft/Hard Demand Paging)\n", (unsigned long long)mem->minor_page_faults);

    if (stats->alert_count > 0) {
        printf("\n[6. DETECTED SECURITY INCIDENTS (Sample preview of %u records)]\n", stats->alert_count > 5 ? 5 : stats->alert_count);
        for (uint32_t i = 0; i < (stats->alert_count > 5 ? 5 : stats->alert_count); ++i) {
            const SecurityAlert *a = &stats->alerts[i];
            printf("  - [#%llu] Threat: %-22s | IP: %-15s | Rule: %s\n",
                (unsigned long long)a->line_number,
                threat_type_to_string(a->threat_type),
                a->ip_address,
                a->rule_matched
            );
        }
    }
    printf("----------------------------------------------------------------------\n\n");
}

bool reporter_export_json(
    const char *filepath,
    const AnalyzerConfig *config,
    const FileMetadata *meta,
    const GlobalStats *stats,
    const ProcessAccounting *proc,
    const MemoryMetrics *mem
) {
    if (!filepath || !config || !meta || !stats || !proc || !mem) return false;

    FILE *fp = fopen(filepath, "w");
    if (!fp) return false;

    double mb_s = proc->elapsed_wall_sec > 0.0001 ? ((double)stats->total_bytes / (1024.0 * 1024.0)) / proc->elapsed_wall_sec : 0;
    double lps = proc->elapsed_wall_sec > 0.0001 ? (double)stats->total_lines / proc->elapsed_wall_sec : 0;

    fprintf(fp, "{\n");
    fprintf(fp, "  \"project\": \"MultiLog-OS\",\n");
    fprintf(fp, "  \"syllabus\": \"Operating Systems (CO-1 to CO-6)\",\n");
    fprintf(fp, "  \"config\": {\n");
    fprintf(fp, "    \"filename\": \"%s\",\n", meta->filename);
    fprintf(fp, "    \"file_size_bytes\": %llu,\n", (unsigned long long)meta->file_size_bytes);
    fprintf(fp, "    \"thread_count\": %d,\n", config->thread_count);
    fprintf(fp, "    \"io_mode\": \"%s\"\n", io_mode_to_string(config->io_mode));
    fprintf(fp, "  },\n");
    fprintf(fp, "  \"summary\": {\n");
    fprintf(fp, "    \"total_lines\": %llu,\n", (unsigned long long)stats->total_lines);
    fprintf(fp, "    \"total_bytes\": %llu,\n", (unsigned long long)stats->total_bytes);
    fprintf(fp, "    \"total_errors\": %llu,\n", (unsigned long long)(stats->total_error + stats->total_fatal));
    fprintf(fp, "    \"total_warnings\": %llu,\n", (unsigned long long)stats->total_warn);
    fprintf(fp, "    \"total_info\": %llu\n", (unsigned long long)stats->total_info);
    fprintf(fp, "  },\n");
    fprintf(fp, "  \"threats\": {\n");
    fprintf(fp, "    \"sql_injection\": %llu,\n", (unsigned long long)stats->total_threats[THREAT_SQL_INJECTION]);
    fprintf(fp, "    \"cross_site_scripting\": %llu,\n", (unsigned long long)stats->total_threats[THREAT_XSS]);
    fprintf(fp, "    \"directory_traversal\": %llu,\n", (unsigned long long)stats->total_threats[THREAT_DIR_TRAVERSAL]);
    fprintf(fp, "    \"recon_probe\": %llu,\n", (unsigned long long)stats->total_threats[THREAT_MALICIOUS_PROBE]);
    fprintf(fp, "    \"auth_failure\": %llu,\n", (unsigned long long)stats->total_threats[THREAT_AUTH_FAILURE]);
    fprintf(fp, "    \"privilege_escalation\": %llu\n", (unsigned long long)stats->total_threats[THREAT_PRIVILEGE_ESC]);
    fprintf(fp, "  },\n");
    fprintf(fp, "  \"http_status\": {\n");
    fprintf(fp, "    \"2xx\": %llu,\n", (unsigned long long)stats->http_status_dist[2]);
    fprintf(fp, "    \"3xx\": %llu,\n", (unsigned long long)stats->http_status_dist[3]);
    fprintf(fp, "    \"4xx\": %llu,\n", (unsigned long long)stats->http_status_dist[4]);
    fprintf(fp, "    \"5xx\": %llu\n", (unsigned long long)stats->http_status_dist[5]);
    fprintf(fp, "  },\n");
    fprintf(fp, "  \"os_telemetry\": {\n");
    fprintf(fp, "    \"elapsed_wall_sec\": %.4f,\n", proc->elapsed_wall_sec);
    fprintf(fp, "    \"user_cpu_time_sec\": %.4f,\n", proc->user_cpu_time_sec);
    fprintf(fp, "    \"kernel_cpu_time_sec\": %.4f,\n", proc->kernel_cpu_time_sec);
    fprintf(fp, "    \"cpu_utilization_pct\": %.2f,\n", proc->cpu_utilization_pct);
    fprintf(fp, "    \"throughput_mb_s\": %.2f,\n", mb_s);
    fprintf(fp, "    \"lines_per_sec\": %.0f,\n", lps);
    fprintf(fp, "    \"resident_set_size_bytes\": %llu,\n", (unsigned long long)mem->resident_set_size_bytes);
    fprintf(fp, "    \"peak_working_set_bytes\": %llu,\n", (unsigned long long)mem->peak_working_set_bytes);
    fprintf(fp, "    \"page_fault_count\": %llu\n", (unsigned long long)mem->minor_page_faults);
    fprintf(fp, "  },\n");
    fprintf(fp, "  \"alerts_sample\": [\n");

    static char escaped_rule[256];
    uint32_t limit = stats->alert_count > 50 ? 50 : stats->alert_count;
    for (uint32_t i = 0; i < limit; ++i) {
        const SecurityAlert *a = &stats->alerts[i];
        
        /* Escape backslashes and quotes for valid JSON */
        size_t o = 0;
        for (const char *p = a->rule_matched; *p && o < sizeof(escaped_rule) - 2; ++p) {
            if (*p == '\\') {
                escaped_rule[o++] = '\\';
                escaped_rule[o++] = '\\';
            } else if (*p == '"') {
                escaped_rule[o++] = '\\';
                escaped_rule[o++] = '"';
            } else {
                escaped_rule[o++] = *p;
            }
        }
        escaped_rule[o] = '\0';

        fprintf(fp, "    {\n");
        fprintf(fp, "      \"line\": %llu,\n", (unsigned long long)a->line_number);
        fprintf(fp, "      \"threat\": \"%s\",\n", threat_type_to_string(a->threat_type));
        fprintf(fp, "      \"ip\": \"%s\",\n", a->ip_address);
        fprintf(fp, "      \"rule\": \"%s\"\n", escaped_rule);
        fprintf(fp, "    }%s\n", (i + 1 < limit) ? "," : "");
    }
    fprintf(fp, "  ]\n");
    fprintf(fp, "}\n");

    fclose(fp);
    return true;
}

bool reporter_export_csv(const char *filepath, const GlobalStats *stats) {
    if (!filepath || !stats) return false;
    FILE *fp = fopen(filepath, "w");
    if (!fp) return false;

    fprintf(fp, "LineNumber,Severity,ThreatType,IPAddress,RuleMatched\n");
    for (uint32_t i = 0; i < stats->alert_count; ++i) {
        const SecurityAlert *a = &stats->alerts[i];
        fprintf(fp, "%llu,%s,%s,%s,\"%s\"\n",
            (unsigned long long)a->line_number,
            severity_to_string(a->severity),
            threat_type_to_string(a->threat_type),
            a->ip_address,
            a->rule_matched
        );
    }
    fclose(fp);
    return true;
}

bool reporter_export_html(
    const char *filepath,
    const AnalyzerConfig *config,
    const FileMetadata *meta,
    const GlobalStats *stats,
    const ProcessAccounting *proc,
    const MemoryMetrics *mem
) {
    if (!filepath || !config || !meta || !stats || !proc || !mem) return false;
    FILE *fp = fopen(filepath, "w");
    if (!fp) return false;

    double mb_s = proc->elapsed_wall_sec > 0.0001 ? ((double)stats->total_bytes / (1024.0 * 1024.0)) / proc->elapsed_wall_sec : 0;
    double lps = proc->elapsed_wall_sec > 0.0001 ? (double)stats->total_lines / proc->elapsed_wall_sec : 0;

    fprintf(fp, "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n");
    fprintf(fp, "<meta charset=\"UTF-8\">\n<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n");
    fprintf(fp, "<title>MultiLog-OS: Analysis Dashboard</title>\n");
    fprintf(fp, "<style>\n");
    fprintf(fp, ":root { --bg: #0f172a; --card: #1e293b; --text: #f8fafc; --accent: #38bdf8; --danger: #ef4444; --warn: #f59e0b; --success: #10b981; }\n");
    fprintf(fp, "body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background: var(--bg); color: var(--text); margin: 0; padding: 24px; }\n");
    fprintf(fp, ".container { max-width: 1200px; margin: 0 auto; }\n");
    fprintf(fp, "header { display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #334155; padding-bottom: 16px; margin-bottom: 24px; }\n");
    fprintf(fp, "h1 { margin: 0; font-size: 26px; color: var(--accent); }\n");
    fprintf(fp, ".badge { background: #0369a1; padding: 4px 12px; border-radius: 9999px; font-size: 13px; font-weight: 600; }\n");
    fprintf(fp, ".grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; margin-bottom: 24px; }\n");
    fprintf(fp, ".card { background: var(--card); border-radius: 10px; padding: 18px; border: 1px solid #334155; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1); }\n");
    fprintf(fp, ".card-title { font-size: 13px; text-transform: uppercase; letter-spacing: 0.05em; color: #94a3b8; margin-bottom: 8px; }\n");
    fprintf(fp, ".card-val { font-size: 28px; font-weight: 700; }\n");
    fprintf(fp, ".card-sub { font-size: 12px; color: #64748b; margin-top: 4px; }\n");
    fprintf(fp, "table { width: 100%%; border-collapse: collapse; margin-top: 12px; }\n");
    fprintf(fp, "th, td { text-align: left; padding: 10px 14px; border-bottom: 1px solid #334155; font-size: 14px; }\n");
    fprintf(fp, "th { background: #0f172a; color: #94a3b8; }\n");
    fprintf(fp, "tr:hover { background: #334155; }\n");
    fprintf(fp, ".tag-danger { color: var(--danger); font-weight: 600; }\n");
    fprintf(fp, ".tag-warn { color: var(--warn); font-weight: 600; }\n");
    fprintf(fp, ".tag-threat { background: rgba(239, 68, 68, 0.2); color: #fca5a5; padding: 3px 8px; border-radius: 4px; font-size: 12px; }\n");
    fprintf(fp, "</style>\n</head>\n<body>\n<div class=\"container\">\n");

    fprintf(fp, "<header><div><h1>MultiLog-OS: Multithreaded Log Analysis</h1><div style=\"color: #94a3b8; font-size: 14px;\">Operating Systems (CO-1 to CO-6) Evaluation Dashboard</div></div><span class=\"badge\">C11 MinGW-W64 / POSIX</span></header>\n");

    fprintf(fp, "<div class=\"grid\">\n");
    fprintf(fp, "<div class=\"card\"><div class=\"card-title\">Total Lines</div><div class=\"card-val\">%llu</div><div class=\"card-sub\">%.2f MB Log Volume</div></div>\n", (unsigned long long)stats->total_lines, (double)meta->file_size_bytes / (1024.0 * 1024.0));
    fprintf(fp, "<div class=\"card\"><div class=\"card-title\">Processing Throughput</div><div class=\"card-val\" style=\"color: var(--accent);\">%.2f <span style=\"font-size:16px\">MB/s</span></div><div class=\"card-sub\">%.0f lines / second</div></div>\n", mb_s, lps);
    fprintf(fp, "<div class=\"card\"><div class=\"card-title\">Execution Wall Time</div><div class=\"card-val\">%.3fs</div><div class=\"card-sub\">%d Worker Threads</div></div>\n", proc->elapsed_wall_sec, config->thread_count);
    fprintf(fp, "<div class=\"card\"><div class=\"card-title\">Errors & Fatal</div><div class=\"card-val tag-danger\">%llu</div><div class=\"card-sub\">HTTP 5xx & Exceptions</div></div>\n", (unsigned long long)(stats->total_error + stats->total_fatal));
    fprintf(fp, "<div class=\"card\"><div class=\"card-title\">Security Threats</div><div class=\"card-val tag-warn\">%llu</div><div class=\"card-sub\">SQLi, XSS, Probes, Auth</div></div>\n", (unsigned long long)(stats->total_threats[THREAT_SQL_INJECTION] + stats->total_threats[THREAT_XSS] + stats->total_threats[THREAT_DIR_TRAVERSAL] + stats->total_threats[THREAT_MALICIOUS_PROBE] + stats->total_threats[THREAT_AUTH_FAILURE] + stats->total_threats[THREAT_PRIVILEGE_ESC]));
    fprintf(fp, "</div>\n");

    fprintf(fp, "<div class=\"card\" style=\"margin-bottom: 24px;\"><div class=\"card-title\">OS Architecture & Syllabus Verification (CO-1 to CO-6)</div>\n");
    fprintf(fp, "<table><thead><tr><th>Course Outcome</th><th>Concept Demonstrated</th><th>Observed Measurement</th></tr></thead><tbody>\n");
    fprintf(fp, "<tr><td><b>CO-1</b>: OS as Service Layer</td><td>User vs Kernel Space Execution</td><td>User CPU: %.4fs | Kernel CPU: %.4fs</td></tr>\n", proc->user_cpu_time_sec, proc->kernel_cpu_time_sec);
    fprintf(fp, "<tr><td><b>CO-2</b>: Process Lifecycle</td><td>State Transitions & Multicore Scaling</td><td>Parallel CPU Utilization: %.1f%%</td></tr>\n", proc->cpu_utilization_pct);
    fprintf(fp, "<tr><td><b>CO-3</b>: IPC & Signals</td><td>Anonymous Pipes & Signal Traps</td><td>Asynchronous SIGINT/SIGBREAK Safe Trap</td></tr>\n");
    fprintf(fp, "<tr><td><b>CO-4</b>: Memory Management</td><td>Virtual Memory, Page Faults, Bump Arena</td><td>RSS: %.2f MB | Page Faults: %llu</td></tr>\n", (double)mem->resident_set_size_bytes / (1024.0 * 1024.0), (unsigned long long)mem->minor_page_faults);
    fprintf(fp, "<tr><td><b>CO-5</b>: File Systems & I/O</td><td>Zero-Copy mmap / Chunk Partitioning</td><td>I/O Mode: %s</td></tr>\n", io_mode_to_string(config->io_mode));
    fprintf(fp, "<tr><td><b>CO-6</b>: Concurrency</td><td>POSIX Threads, Mutexes, Semaphores</td><td>%d Threads with Lock-Protected Aggregation</td></tr>\n", config->thread_count);
    fprintf(fp, "</tbody></table></div>\n");

    if (stats->alert_count > 0) {
        fprintf(fp, "<div class=\"card\"><div class=\"card-title\">Detected Security Incidents (Top %u Records)</div>\n", stats->alert_count > 50 ? 50 : stats->alert_count);
        fprintf(fp, "<table><thead><tr><th>Line #</th><th>Threat Type</th><th>Offending IP</th><th>Matched Rule</th><th>Log Snippet Preview</th></tr></thead><tbody>\n");
        uint32_t limit = stats->alert_count > 50 ? 50 : stats->alert_count;
        for (uint32_t i = 0; i < limit; ++i) {
            const SecurityAlert *a = &stats->alerts[i];
            fprintf(fp, "<tr><td>#%llu</td><td><span class=\"tag-threat\">%s</span></td><td>%s</td><td><code>%s</code></td><td style=\"color:#cbd5e1;font-family:monospace;font-size:12px;\">%s</td></tr>\n",
                (unsigned long long)a->line_number,
                threat_type_to_string(a->threat_type),
                a->ip_address,
                a->rule_matched,
                a->snippet
            );
        }
        fprintf(fp, "</tbody></table></div>\n");
    }

    fprintf(fp, "</div></body></html>\n");
    fclose(fp);
    return true;
}
