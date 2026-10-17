/**
 * MultiLog-OS: High-Performance Multithreaded Log Analysis & Threat Detection System
 * File: src/concurrency/thread_pool.c
 * 
 * Course Outcome Mapping:
 * - CO-6: POSIX Threads, Race Conditions, Mutual Exclusion, Condition Variables,
 *         Counting Semaphores, User-level Thread Scheduling & CPU Affinity.
 */

#include "thread_pool.h"
#include "../analyzer/analyzer.h"

#ifdef _WIN32
    #include <windows.h>
#else
    #define _GNU_SOURCE
    #include <sched.h>
    #include <pthread.h>
#endif

void thread_set_affinity(int thread_id, int core_id) {
#ifdef _WIN32
    HANDLE hThread = GetCurrentThread();
    DWORD_PTR mask = (DWORD_PTR)1 << (core_id % 64);
    SetThreadAffinityMask(hThread, mask);
#else
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(core_id % sysconf(_SC_NPROCESSORS_ONLN), &cpuset);
    pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);
#endif
}

static double get_time_sec(void) {
#ifdef _WIN32
    LARGE_INTEGER freq, counter;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&counter);
    return (double)counter.QuadPart / (double)freq.QuadPart;
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec * 1e-9;
#endif
}

static void* worker_thread_entry(void *arg) {
    WorkerThreadContext *ctx = (WorkerThreadContext*)arg;
    FileChunk *chunk = ctx->chunk;
    const FileMetadata *meta = ctx->meta;
    GlobalStats *stats = ctx->global_stats;

    if (ctx->enable_affinity) {
        chunk->worker_cpu_core = ctx->worker_id;
        thread_set_affinity(ctx->worker_id, ctx->worker_id);
    }

    double t_start = get_time_sec();

    /* Create Thread-Local Memory Arena (CO-4: Virtual Page Alignment) */
    MemoryArena *arena = arena_create(1024 * 1024); /* 1MB Arena */
    ctx->arena = arena;

    if (chunk->chunk_size > 0) {
        if (ctx->io_mode == IO_MODE_MMAP && meta->mmap_base_addr) {
            /* Zero-Copy mmap directly accessing OS Page Cache (CO-5) */
            const char *chunk_start_ptr = meta->mmap_base_addr + chunk->start_offset;
            analyze_chunk_buffer(chunk_start_ptr, chunk->chunk_size, chunk, arena);
        } else if (ctx->io_mode == IO_MODE_DIRECT) {
            /* Direct/Unbuffered Syscall I/O throttled by Semaphore (CO-6) */
            SYS_SEM_WAIT(ctx->io_semaphore);
            char *read_buf = (char*)malloc((size_t)chunk->chunk_size + 1);
            if (read_buf) {
                size_t bytes = file_read_direct_slice(meta, chunk->start_offset, (size_t)chunk->chunk_size, read_buf);
                SYS_SEM_POST(ctx->io_semaphore);
                read_buf[bytes] = '\0';
                analyze_chunk_buffer(read_buf, bytes, chunk, arena);
                free(read_buf);
            } else {
                SYS_SEM_POST(ctx->io_semaphore);
            }
        } else {
            /* Standard Buffered I/O (CO-5) */
            SYS_SEM_WAIT(ctx->io_semaphore);
            char *read_buf = (char*)malloc((size_t)chunk->chunk_size + 1);
            if (read_buf) {
                size_t bytes = file_read_buffered_slice(meta->filename, chunk->start_offset, (size_t)chunk->chunk_size, read_buf);
                SYS_SEM_POST(ctx->io_semaphore);
                read_buf[bytes] = '\0';
                analyze_chunk_buffer(read_buf, bytes, chunk, arena);
                free(read_buf);
            } else {
                SYS_SEM_POST(ctx->io_semaphore);
            }
        }
    }

    double t_end = get_time_sec();
    chunk->thread_exec_time_sec = t_end - t_start;

    /* CO-6: Mutual Exclusion (Mutex) for Merging Results into Shared Global State */
    pthread_mutex_lock(&stats->stats_mutex);
    stats->total_lines += chunk->lines_count;
    stats->total_bytes += chunk->bytes_count;
    stats->total_debug += chunk->debug_count;
    stats->total_info += chunk->info_count;
    stats->total_warn += chunk->warn_count;
    stats->total_error += chunk->error_count;
    stats->total_fatal += chunk->fatal_count;
    for (int t = 0; t < THREAT_COUNT; ++t) {
        stats->total_threats[t] += chunk->threat_counts[t];
    }
    stats->http_status_dist[2] += chunk->http_2xx;
    stats->http_status_dist[3] += chunk->http_3xx;
    stats->http_status_dist[4] += chunk->http_4xx;
    stats->http_status_dist[5] += chunk->http_5xx;

    /* Merge thread-local alerts into global reservoir safely */
    if (chunk->local_alerts && chunk->local_alerts_count > 0) {
        for (uint32_t a = 0; a < chunk->local_alerts_count; ++a) {
            if (stats->alert_count < stats->alert_capacity) {
                stats->alerts[stats->alert_count++] = chunk->local_alerts[a];
            }
        }
    }
    pthread_mutex_unlock(&stats->stats_mutex);

    arena_destroy(arena);
    ctx->arena = NULL;
    return NULL;
}

ThreadPool* thread_pool_init(
    int thread_count,
    FileChunk *chunks,
    const FileMetadata *meta,
    IOMode io_mode,
    bool enable_affinity,
    GlobalStats *stats
) {
    if (thread_count <= 0 || !chunks || !meta || !stats) return NULL;

    ThreadPool *pool = (ThreadPool*)malloc(sizeof(ThreadPool));
    if (!pool) return NULL;

    pool->thread_count = thread_count;
    pool->chunks = chunks;
    pool->stats = stats;
    pool->completed_workers = 0;

    pthread_mutex_init(&pool->pool_mutex, NULL);
    pthread_cond_init(&pool->pool_cond, NULL);

    /* Initialize Counting Semaphore: Allow up to 8 concurrent disk operations (CO-6) */
    SYS_SEM_INIT(&pool->io_throttle_sem, 8);

    pool->workers = (WorkerThreadContext*)malloc(thread_count * sizeof(WorkerThreadContext));
    for (int i = 0; i < thread_count; ++i) {
        pool->workers[i].worker_id = i;
        pool->workers[i].chunk = &chunks[i];
        pool->workers[i].meta = meta;
        pool->workers[i].io_mode = io_mode;
        pool->workers[i].enable_affinity = enable_affinity;
        pool->workers[i].global_stats = stats;
        pool->workers[i].arena = NULL;
        pool->workers[i].io_semaphore = &pool->io_throttle_sem;
    }

    return pool;
}

void thread_pool_run_and_wait(ThreadPool *pool) {
    if (!pool) return;

    /* Spawn POSIX Worker Threads (CO-6) */
    for (int i = 0; i < pool->thread_count; ++i) {
        int ret = pthread_create(
            &pool->workers[i].thread_handle,
            NULL,
            worker_thread_entry,
            &pool->workers[i]
        );
        if (ret != 0) {
            fprintf(stderr, "[Error] Failed to spawn worker thread %d: %d\n", i, ret);
        }
    }

    /* Wait for all threads to terminate (CO-6: Thread Joining & Synchronization) */
    for (int i = 0; i < pool->thread_count; ++i) {
        pthread_join(pool->workers[i].thread_handle, NULL);
    }
}

void thread_pool_destroy(ThreadPool *pool) {
    if (!pool) return;

    SYS_SEM_DESTROY(&pool->io_throttle_sem);
    pthread_mutex_destroy(&pool->pool_mutex);
    pthread_cond_destroy(&pool->pool_cond);

    if (pool->workers) {
        free(pool->workers);
    }
    free(pool);
}
