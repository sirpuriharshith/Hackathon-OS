/**
 * MultiLog-OS: High-Performance Multithreaded Log Analysis & Threat Detection System
 * File: src/core/types.h
 * 
 * Course Outcome Mapping:
 * - CO-1: Systems Programming Fundamentals, Kernel/User Space Abstractions
 * - CO-4: Memory Layout and Page Size Constants
 * - CO-5: File Metadata and I/O Mode Specifications
 * - CO-6: Concurrency Structures and Synchronization Types
 */

#ifndef MULTILOG_TYPES_H
#define MULTILOG_TYPES_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>
#include <pthread.h>

#ifdef _WIN32
    #include <windows.h>
    #include <io.h>
    #include <process.h>
#else
    #include <unistd.h>
    #include <sys/types.h>
    #include <sys/stat.h>
    #include <sys/mman.h>
    #include <fcntl.h>
    #include <semaphore.h>
#endif

#define MAX_PATH_LEN 1024
#define MAX_IP_LEN 64
#define MAX_MSG_PREVIEW 256
#define MAX_ALERT_RECORDS 10000
#define IP_HASH_TABLE_SIZE 1024
#define VIRTUAL_PAGE_SIZE 4096  /* CO-4: Standard Virtual Memory Page Size */

/* I/O Strategies (CO-5: Buffered vs Unbuffered vs Memory-Mapped) */
typedef enum {
    IO_MODE_MMAP = 0,     /* Memory-Mapped I/O: Zero-copy via page cache */
    IO_MODE_DIRECT = 1,   /* Direct/Unbuffered Syscall I/O (read/lseek) */
    IO_MODE_BUFFERED = 2  /* Standard Library Buffered I/O (fread) */
} IOMode;

/* Log Severity Classifications */
typedef enum {
    SEV_DEBUG = 0,
    SEV_INFO,
    SEV_WARN,
    SEV_ERROR,
    SEV_FATAL,
    SEV_UNKNOWN
} SeverityLevel;

/* Suspicious Security Threat Classifications */
typedef enum {
    THREAT_NONE = 0,
    THREAT_BRUTE_FORCE,       /* Multiple failed logins / password spraying */
    THREAT_SQL_INJECTION,      /* SQLi meta-characters: ' OR '1'='1, UNION SELECT, SLEEP() */
    THREAT_XSS,                /* Cross-Site Scripting: <script>, javascript:, onerror= */
    THREAT_DIR_TRAVERSAL,      /* Path traversal: ../, ..\\, /etc/passwd, boot.ini */
    THREAT_MALICIOUS_PROBE,    /* Reconnaissance scanning: /wp-admin, /.env, /.git, /phpmyadmin */
    THREAT_DDOS_BURST,         /* Anomalous high-frequency request flood */
    THREAT_PRIVILEGE_ESC,      /* sudoers abuse, unauthorized root commands */
    THREAT_AUTH_FAILURE,       /* Generic authentication/authorization failures */
    THREAT_COUNT               /* Enum counter */
} ThreatType;

/* Structure for recorded Security Alert / Suspicious Event */
typedef struct {
    uint64_t line_number;
    char timestamp[32];
    char ip_address[MAX_IP_LEN];
    SeverityLevel severity;
    ThreatType threat_type;
    char rule_matched[64];
    char snippet[MAX_MSG_PREVIEW];
} SecurityAlert;

/* IP Address Frequency Tracking Node (Hash Table for Offender Analysis) */
typedef struct IPEntry {
    char ip[MAX_IP_LEN];
    uint32_t request_count;
    uint32_t error_count;
    uint32_t threat_count;
    time_t last_seen;
    struct IPEntry *next;
} IPEntry;

/* Partitioned Chunk Assigned to a Worker Thread (CO-5 & CO-6) */
typedef struct {
    int chunk_id;
    uint64_t start_offset;       /* Byte offset where chunk starts (aligned to line) */
    uint64_t end_offset;         /* Byte offset where chunk ends */
    uint64_t chunk_size;         /* Size in bytes */
    
    /* Per-thread Statistics (Eliminates lock contention on hot path) */
    uint64_t lines_count;
    uint64_t bytes_count;
    uint64_t debug_count;
    uint64_t info_count;
    uint64_t warn_count;
    uint64_t error_count;
    uint64_t fatal_count;
    uint64_t threat_counts[THREAT_COUNT];
    
    /* HTTP Status Code Distribution */
    uint64_t http_2xx;
    uint64_t http_3xx;
    uint64_t http_4xx;
    uint64_t http_5xx;

    /* Per-thread timing */
    double thread_exec_time_sec;
    int worker_cpu_core;         /* Core affinity assigned (CO-2/CO-6) */
    
    /* Thread private alert storage before merging */
    SecurityAlert *local_alerts;
    uint32_t local_alerts_count;
    uint32_t local_alerts_capacity;
} FileChunk;

/* System Configuration */
typedef struct {
    char filepath[MAX_PATH_LEN];
    int thread_count;
    IOMode io_mode;
    bool benchmark_mode;
    bool verbose;
    bool enable_affinity;
    char output_json[MAX_PATH_LEN];
    char output_html[MAX_PATH_LEN];
    char output_csv[MAX_PATH_LEN];
} AnalyzerConfig;

/* Global Aggregated System State (CO-6: Mutex & Shared Memory Protection) */
typedef struct {
    /* Aggregated Totals */
    uint64_t total_lines;
    uint64_t total_bytes;
    uint64_t total_debug;
    uint64_t total_info;
    uint64_t total_warn;
    uint64_t total_error;
    uint64_t total_fatal;
    uint64_t total_threats[THREAT_COUNT];
    uint64_t http_status_dist[6]; /* 0: other, 1: 1xx, 2: 2xx, 3: 3xx, 4: 4xx, 5: 5xx */
    
    /* Global Alert Reservoir */
    SecurityAlert *alerts;
    uint32_t alert_count;
    uint32_t alert_capacity;
    pthread_mutex_t alert_mutex; /* Protects alert reservoir */

    /* IP Offender Hash Table */
    IPEntry *ip_table[IP_HASH_TABLE_SIZE];
    pthread_mutex_t ip_table_mutex; /* Protects hash table updates */

    /* Synchronization Primitives (CO-6) */
    pthread_mutex_t stats_mutex;    /* Protects global statistics consolidation */
    pthread_cond_t work_cond;       /* Coordination for worker tasks */
    bool work_ready;

    /* Execution & Memory Telemetry (CO-1, CO-4) */
    double total_wall_time_sec;
    double user_cpu_time_sec;
    double kernel_cpu_time_sec;
    uint64_t peak_memory_bytes;
    uint64_t page_faults_minor;
    uint64_t page_faults_major;
    double throughput_mb_s;
    double lines_per_second;
} GlobalStats;

/* Helper string conversion utilities */
const char* threat_type_to_string(ThreatType threat);
const char* severity_to_string(SeverityLevel sev);
const char* io_mode_to_string(IOMode mode);

#endif /* MULTILOG_TYPES_H */
