/**
 * MultiLog-OS: High-Performance Multithreaded Log Analysis & Threat Detection System
 * File: src/concurrency/thread_pool.h
 * 
 * Course Outcome Mapping:
 * - CO-6: POSIX Threads, Race Conditions, Mutual Exclusion (Mutexes),
 *         Condition Variables, Counting Semaphores, Atomic Operations,
 *         CPU Affinity and User-Level Thread Scheduling.
 */

#ifndef MULTILOG_THREAD_POOL_H
#define MULTILOG_THREAD_POOL_H

#include "../core/types.h"
#include "../io/file_io.h"
#include "../memory/arena.h"

#ifdef _WIN32
    /* Windows Semaphore Handle */
    typedef HANDLE sys_semaphore_t;
    #define SYS_SEM_INIT(sem, val) (*(sem) = CreateSemaphore(NULL, val, 64, NULL))
    #define SYS_SEM_WAIT(sem) (WaitForSingleObject(*(sem), INFINITE))
    #define SYS_SEM_POST(sem) (ReleaseSemaphore(*(sem), 1, NULL))
    #define SYS_SEM_DESTROY(sem) (CloseHandle(*(sem)))
#else
    #include <semaphore.h>
    typedef sem_t sys_semaphore_t;
    #define SYS_SEM_INIT(sem, val) (sem_init(sem, 0, val))
    #define SYS_SEM_WAIT(sem) (sem_wait(sem))
    #define SYS_SEM_POST(sem) (sem_post(sem))
    #define SYS_SEM_DESTROY(sem) (sem_destroy(sem))
#endif

/* Worker Thread Context */
typedef struct {
    int worker_id;
    pthread_t thread_handle;
    FileChunk *chunk;
    const FileMetadata *meta;
    IOMode io_mode;
    bool enable_affinity;
    GlobalStats *global_stats;
    MemoryArena *arena;
    sys_semaphore_t *io_semaphore;
} WorkerThreadContext;

/* Thread Pool Controller */
typedef struct {
    int thread_count;
    WorkerThreadContext *workers;
    FileChunk *chunks;
    GlobalStats *stats;
    sys_semaphore_t io_throttle_sem;
    pthread_mutex_t pool_mutex;
    pthread_cond_t pool_cond;
    int completed_workers;
} ThreadPool;

/* Initialize and execute thread pool across chunks */
ThreadPool* thread_pool_init(
    int thread_count,
    FileChunk *chunks,
    const FileMetadata *meta,
    IOMode io_mode,
    bool enable_affinity,
    GlobalStats *stats
);

/* Run all threads and wait for completion (pthread_join) */
void thread_pool_run_and_wait(ThreadPool *pool);

/* Clean up thread pool resources */
void thread_pool_destroy(ThreadPool *pool);

/* Set thread affinity to specific CPU core (CO-2/CO-6) */
void thread_set_affinity(int thread_id, int core_id);

#endif /* MULTILOG_THREAD_POOL_H */
