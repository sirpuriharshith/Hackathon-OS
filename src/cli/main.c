/**
 * MultiLog-OS: High-Performance Multithreaded Log Analysis & Threat Detection System
 * File: src/cli/main.c
 * 
 * Course Outcome Mapping:
 * - CO-1: The OS as a Service Layer - Shell CLI Interface, Syscalls, User Space
 * - CO-2: Process Lifecycle & Execution Journey
 * - CO-3: Inter-Process Communication & Signals
 * - CO-4: Virtual Memory Management & Page Tables
 * - CO-5: File Systems, File Descriptors, and I/O Engines
 * - CO-6: POSIX Threads Concurrency, Mutexes, and Semaphores
 */

#include "../core/types.h"
#include "../io/file_io.h"
#include "../memory/arena.h"
#include "../concurrency/thread_pool.h"
#include "../ipc/ipc_channel.h"
#include "../process/supervisor.h"
#include "../report/reporter.h"

static void print_banner(void) {
    printf("\n");
    printf("======================================================================\n");
    printf("  __  __       _ _   _ _                 ___  ____  \n");
    printf(" |  \\/  |_   _| | |_(_) |    ___   __ _ / _ \\/ ___| \n");
    printf(" | |\\/| | | | | | __| | |   / _ \\ / _` | | | \\___ \\ \n");
    printf(" | |  | | |_| | | |_| | |__| (_) | (_| | |_| |___) |\n");
    printf(" |_|  |_|\\__,_|_|\\__|_|_____\\___/ \\__, |\\___/|____/ \n");
    printf("                                  |___/             \n");
    printf(" Multithreaded High-Speed Log Analysis & Threat Detection System\n");
    printf(" Operating Systems Project (CO-1 to CO-6 POSIX & C11 Implementation)\n");
    printf("======================================================================\n\n");
}

static void print_usage(const char *prog_name) {
    printf("Usage: %s [OPTIONS]\n\n", prog_name);
    printf("Options:\n");
    printf("  --file <path>        Path to input log file (Required for analysis)\n");
    printf("  --threads <n>        Number of worker threads to spawn [1-64] (Default: 4)\n");
    printf("  --io <mode>          I/O Strategy: 'mmap', 'direct', or 'buffered' (Default: mmap)\n");
    printf("  --benchmark          Run automated multi-thread scaling benchmark (1, 2, 4, 8 threads)\n");
    printf("  --compare-io         Benchmark and compare mmap vs direct syscalls vs buffered stdio\n");
    printf("  --json <path>        Export detailed machine-readable JSON telemetry\n");
    printf("  --html <path>        Generate standalone interactive HTML dashboard\n");
    printf("  --csv <path>         Export security alerts to CSV\n");
    printf("  --memory-layout      Display virtual process address space layout (CO-4)\n");
    printf("  --help               Display this help documentation\n\n");
    printf("Example:\n");
    printf("  %s --file data/server.log --threads 8 --io mmap --html report.html\n\n", prog_name);
}

/* Single Run Execution Core */
static bool run_analysis_pass(
    const AnalyzerConfig *config,
    GlobalStats *stats,
    ProcessAccounting *proc,
    MemoryMetrics *mem
) {
    FileMetadata meta;
    if (!file_inspect_metadata(config->filepath, &meta)) {
        fprintf(stderr, "[Error] Failed to open/stat target file: %s\n", config->filepath);
        return false;
    }

    if (config->io_mode == IO_MODE_MMAP) {
        if (!file_mmap_open(&meta)) {
            fprintf(stderr, "[Warning] mmap failed; falling back to Direct Syscall I/O\n");
            ((AnalyzerConfig*)config)->io_mode = IO_MODE_DIRECT;
        }
    }

    /* Initialize Global Stats */
    memset(stats, 0, sizeof(GlobalStats));
    stats->alert_capacity = MAX_ALERT_RECORDS;
    stats->alerts = (SecurityAlert*)malloc(stats->alert_capacity * sizeof(SecurityAlert));
    pthread_mutex_init(&stats->stats_mutex, NULL);
    pthread_mutex_init(&stats->alert_mutex, NULL);
    pthread_mutex_init(&stats->ip_table_mutex, NULL);

    /* Allocate Chunk Array */
    FileChunk *chunks = (FileChunk*)malloc(config->thread_count * sizeof(FileChunk));
    if (!file_partition_chunks(&meta, config->thread_count, chunks)) {
        fprintf(stderr, "[Error] Failed to partition file chunks\n");
        free(chunks);
        if (config->io_mode == IO_MODE_MMAP) file_mmap_close(&meta);
        return false;
    }

    /* Start Process Supervisor Timing (CO-2) */
    supervisor_start_accounting(proc);

    /* Initialize and Launch POSIX Thread Pool (CO-6) */
    ThreadPool *pool = thread_pool_init(
        config->thread_count,
        chunks,
        &meta,
        config->io_mode,
        config->enable_affinity,
        stats
    );

    if (pool) {
        thread_pool_run_and_wait(pool);
        thread_pool_destroy(pool);
    }

    /* Stop Supervisor Accounting */
    supervisor_stop_accounting(proc, config->thread_count);

    /* Fetch Virtual Memory & Page Fault Telemetry (CO-4) */
    *mem = os_get_memory_metrics();

    /* Clean Up File Resources */
    if (config->io_mode == IO_MODE_MMAP) {
        file_mmap_close(&meta);
    }

    /* Clean up chunk local alerts */
    for (int i = 0; i < config->thread_count; ++i) {
        if (chunks[i].local_alerts) free(chunks[i].local_alerts);
    }
    free(chunks);

    return true;
}

/* Automated Thread Scaling Benchmark (Amdahl's Law) */
static void run_scaling_benchmark(const char *filepath) {
    printf("\n======================================================================\n");
    printf("        MULTITHREADED SCALABILITY BENCHMARK (AMDAHL'S LAW & SPEEDUP)   \n");
    printf("======================================================================\n");
    printf(" Target File: %s\n\n", filepath);
    
    int thread_counts[] = {1, 2, 4, 8, 16};
    int num_tests = sizeof(thread_counts) / sizeof(thread_counts[0]);
    double baseline_time = 0.0;

    printf(" +---------+----------------+---------------+------------+--------------+\n");
    printf(" | Threads | Wall Time (s)  | Speedup       | Efficiency | Throughput   |\n");
    printf(" +---------+----------------+---------------+------------+--------------+\n");

    for (int i = 0; i < num_tests; ++i) {
        int tc = thread_counts[i];
        AnalyzerConfig cfg = {0};
        strncpy(cfg.filepath, filepath, MAX_PATH_LEN - 1);
        cfg.thread_count = tc;
        cfg.io_mode = IO_MODE_MMAP;

        GlobalStats stats;
        ProcessAccounting proc;
        MemoryMetrics mem;

        if (run_analysis_pass(&cfg, &stats, &proc, &mem)) {
            if (i == 0) baseline_time = proc.elapsed_wall_sec;
            double speedup = baseline_time > 0 ? baseline_time / proc.elapsed_wall_sec : 1.0;
            double efficiency = (speedup / tc) * 100.0;
            double mb_s = proc.elapsed_wall_sec > 0 ? ((double)stats.total_bytes / (1024.0 * 1024.0)) / proc.elapsed_wall_sec : 0;

            printf(" | %-7d | %-14.4f | %-13.2fx | %-9.1f%% | %-7.2f MB/s |\n",
                tc, proc.elapsed_wall_sec, speedup, efficiency, mb_s);

            if (stats.alerts) free(stats.alerts);
        }
    }
    printf(" +---------+----------------+---------------+------------+--------------+\n\n");
}

/* I/O Strategy Comparison Benchmark (CO-5) */
static void run_io_comparison_benchmark(const char *filepath) {
    printf("\n======================================================================\n");
    printf("       [CO-5] FILE I/O STRATEGY BENCHMARK: MMAP vs DIRECT vs BUFFERED \n");
    printf("======================================================================\n");
    printf(" Target File: %s | Thread Count: 4\n\n", filepath);

    IOMode modes[] = {IO_MODE_MMAP, IO_MODE_DIRECT, IO_MODE_BUFFERED};
    const char *names[] = {
        "Memory-Mapped I/O (mmap/MapViewOfFile)",
        "Direct Syscall I/O (open/read/lseek)  ",
        "Buffered Stream I/O (fopen/fread)     "
    };

    printf(" +----------------------------------------+---------------+--------------+------------+\n");
    printf(" | I/O Architecture Mechanism             | Wall Time (s) | Kernel CPU   | Throughput |\n");
    printf(" +----------------------------------------+---------------+--------------+------------+\n");

    for (int i = 0; i < 3; ++i) {
        AnalyzerConfig cfg = {0};
        strncpy(cfg.filepath, filepath, MAX_PATH_LEN - 1);
        cfg.thread_count = 4;
        cfg.io_mode = modes[i];

        GlobalStats stats;
        ProcessAccounting proc;
        MemoryMetrics mem;

        if (run_analysis_pass(&cfg, &stats, &proc, &mem)) {
            double mb_s = proc.elapsed_wall_sec > 0 ? ((double)stats.total_bytes / (1024.0 * 1024.0)) / proc.elapsed_wall_sec : 0;
            printf(" | %-38s | %-13.4f | %-12.4fs | %-6.2f MB/s|\n",
                names[i], proc.elapsed_wall_sec, proc.kernel_cpu_time_sec, mb_s);
            if (stats.alerts) free(stats.alerts);
        }
    }
    printf(" +----------------------------------------+---------------+--------------+------------+\n\n");
}

int main(int argc, char *argv[]) {
    ipc_signals_init(); /* Install OS Signal Traps (CO-3) */

    AnalyzerConfig config = {0};
    config.thread_count = 4;
    config.io_mode = IO_MODE_MMAP;
    bool run_benchmark = false;
    bool run_io_compare = false;
    bool show_mem_layout = false;

    if (argc < 2) {
        print_banner();
        print_usage(argv[0]);
        return 0;
    }

    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--file") == 0 && i + 1 < argc) {
            strncpy(config.filepath, argv[++i], MAX_PATH_LEN - 1);
        } else if (strcmp(argv[i], "--threads") == 0 && i + 1 < argc) {
            config.thread_count = atoi(argv[++i]);
            if (config.thread_count <= 0) config.thread_count = 1;
            if (config.thread_count > 64) config.thread_count = 64;
        } else if (strcmp(argv[i], "--io") == 0 && i + 1 < argc) {
            i++;
            if (strcmp(argv[i], "mmap") == 0) config.io_mode = IO_MODE_MMAP;
            else if (strcmp(argv[i], "direct") == 0) config.io_mode = IO_MODE_DIRECT;
            else if (strcmp(argv[i], "buffered") == 0) config.io_mode = IO_MODE_BUFFERED;
            else {
                fprintf(stderr, "Unknown I/O mode: %s (using mmap)\n", argv[i]);
                config.io_mode = IO_MODE_MMAP;
            }
        } else if (strcmp(argv[i], "--benchmark") == 0) {
            run_benchmark = true;
        } else if (strcmp(argv[i], "--compare-io") == 0) {
            run_io_compare = true;
        } else if (strcmp(argv[i], "--json") == 0 && i + 1 < argc) {
            strncpy(config.output_json, argv[++i], MAX_PATH_LEN - 1);
        } else if (strcmp(argv[i], "--html") == 0 && i + 1 < argc) {
            strncpy(config.output_html, argv[++i], MAX_PATH_LEN - 1);
        } else if (strcmp(argv[i], "--csv") == 0 && i + 1 < argc) {
            strncpy(config.output_csv, argv[++i], MAX_PATH_LEN - 1);
        } else if (strcmp(argv[i], "--memory-layout") == 0) {
            show_mem_layout = true;
        } else if (strcmp(argv[i], "--help") == 0) {
            print_banner();
            print_usage(argv[0]);
            return 0;
        }
    }

    print_banner();

    if (show_mem_layout) {
        print_memory_layout_info();
    }

    if (config.filepath[0] == '\0') {
        if (!show_mem_layout) {
            fprintf(stderr, "[Error] No input log file specified. Use --file <path>\n");
            print_usage(argv[0]);
            return 1;
        }
        return 0;
    }

    if (run_benchmark) {
        run_scaling_benchmark(config.filepath);
        return 0;
    }

    if (run_io_compare) {
        run_io_comparison_benchmark(config.filepath);
        return 0;
    }

    /* Standard Analysis Run */
    FileMetadata meta;
    if (!file_inspect_metadata(config.filepath, &meta)) {
        fprintf(stderr, "[Error] Target log file '%s' cannot be accessed.\n", config.filepath);
        return 1;
    }

    GlobalStats stats;
    ProcessAccounting proc;
    MemoryMetrics mem;

    printf("[*] Initializing MultiLog-OS Engine...\n");
    printf("[*] File: %s (%.2f MB)\n", meta.filename, (double)meta.file_size_bytes / (1024.0 * 1024.0));
    printf("[*] Spawning %d POSIX Worker Threads with %s...\n", config.thread_count, io_mode_to_string(config.io_mode));

    if (!run_analysis_pass(&config, &stats, &proc, &mem)) {
        fprintf(stderr, "[Fatal] Analysis pipeline failed.\n");
        return 1;
    }

    /* Print Reports */
    reporter_print_console_summary(&config, &meta, &stats, &proc, &mem);
    supervisor_print_summary(&proc);

    if (config.output_json[0] != '\0') {
        if (reporter_export_json(config.output_json, &config, &meta, &stats, &proc, &mem)) {
            printf("[+] Exported JSON telemetry to: %s\n", config.output_json);
        }
    }

    if (config.output_html[0] != '\0') {
        if (reporter_export_html(config.output_html, &config, &meta, &stats, &proc, &mem)) {
            printf("[+] Generated Interactive HTML Dashboard: %s\n", config.output_html);
        }
    }

    if (config.output_csv[0] != '\0') {
        if (reporter_export_csv(config.output_csv, &stats)) {
            printf("[+] Exported Security Alerts CSV to: %s\n", config.output_csv);
        }
    }

    if (stats.alerts) free(stats.alerts);
    pthread_mutex_destroy(&stats.stats_mutex);
    pthread_mutex_destroy(&stats.alert_mutex);
    pthread_mutex_destroy(&stats.ip_table_mutex);

    return 0;
}
