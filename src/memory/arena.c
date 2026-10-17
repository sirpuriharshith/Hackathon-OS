/**
 * MultiLog-OS: High-Performance Multithreaded Log Analysis & Threat Detection System
 * File: src/memory/arena.c
 * 
 * Course Outcome Mapping:
 * - CO-4: Memory Management, Virtual Memory, Address Space Layout,
 *         Page Fault Telemetry, and Dynamic Memory Allocation.
 */

#include "arena.h"

#ifdef _WIN32
    #include <psapi.h>
#else
    #include <sys/resource.h>
#endif

/* Global anchor variables to inspect process address space layout (CO-4) */
static int bss_segment_marker;
static const int data_segment_marker = 42;

MemoryArena* arena_create(size_t capacity_bytes) {
    /* Align capacity to OS Virtual Page Boundary (CO-4) */
    size_t page_aligned_capacity = ((capacity_bytes + VIRTUAL_PAGE_SIZE - 1) / VIRTUAL_PAGE_SIZE) * VIRTUAL_PAGE_SIZE;
    
    MemoryArena *arena = (MemoryArena*)malloc(sizeof(MemoryArena));
    if (!arena) return NULL;
    
    arena->buffer = (char*)malloc(page_aligned_capacity);
    if (!arena->buffer) {
        free(arena);
        return NULL;
    }
    
    arena->capacity = page_aligned_capacity;
    arena->offset = 0;
    arena->high_watermark = 0;
    arena->allocation_count = 0;
    return arena;
}

void* arena_alloc(MemoryArena *arena, size_t size_bytes) {
    if (!arena || !arena->buffer) return NULL;
    
    /* 8-byte memory alignment for CPU word boundaries */
    size_t aligned_size = (size_bytes + 7) & ~7;
    
    if (arena->offset + aligned_size > arena->capacity) {
        /* Arena overflow: fallback to standard malloc or reject */
        return NULL;
    }
    
    void *ptr = (void*)(arena->buffer + arena->offset);
    arena->offset += aligned_size;
    if (arena->offset > arena->high_watermark) {
        arena->high_watermark = arena->offset;
    }
    arena->allocation_count++;
    return ptr;
}

void arena_reset(MemoryArena *arena) {
    if (arena) {
        arena->offset = 0;
        /* O(1) instantaneous memory reclamation without heap fragmentation */
    }
}

void arena_destroy(MemoryArena *arena) {
    if (arena) {
        if (arena->buffer) free(arena->buffer);
        free(arena);
    }
}

MemoryMetrics os_get_memory_metrics(void) {
    MemoryMetrics metrics = {0};
    
#ifdef _WIN32
    PROCESS_MEMORY_COUNTERS_EX pmc;
    if (GetProcessMemoryInfo(GetCurrentProcess(), (PROCESS_MEMORY_COUNTERS*)&pmc, sizeof(pmc))) {
        metrics.virtual_memory_bytes = pmc.PrivateUsage;
        metrics.resident_set_size_bytes = pmc.WorkingSetSize;
        metrics.peak_working_set_bytes = pmc.PeakWorkingSetSize;
        metrics.minor_page_faults = pmc.PageFaultCount;
        metrics.major_page_faults = 0; /* Windows lumps soft/hard faults in PageFaultCount */
    }
#else
    struct rusage usage;
    if (getrusage(RUSAGE_SELF, &usage) == 0) {
        metrics.resident_set_size_bytes = usage.ru_maxrss * 1024; /* KB to bytes */
        metrics.peak_working_set_bytes = metrics.resident_set_size_bytes;
        metrics.minor_page_faults = usage.ru_minflt;
        metrics.major_page_faults = usage.ru_majflt;
    }
#endif

    return metrics;
}

void print_memory_layout_info(void) {
    int stack_variable_marker = 100;
    void *heap_pointer = malloc(16);
    
    printf("\n[OS Memory Layout Inspection - CO-4 Virtual Address Space]\n");
    printf("  +-----------------------+-----------------------------+\n");
    printf("  | Memory Segment        | Virtual Address             |\n");
    printf("  +-----------------------+-----------------------------+\n");
    printf("  | Code / Text Segment   | %-27p |\n", (void*)(uintptr_t)&arena_create);
    printf("  | Initialized Data      | %-27p |\n", (void*)&data_segment_marker);
    printf("  | Uninitialized BSS     | %-27p |\n", (void*)&bss_segment_marker);
    printf("  | Heap Segment (Brk)    | %-27p |\n", heap_pointer);
    printf("  | Stack Segment         | %-27p |\n", (void*)&stack_variable_marker);
    printf("  +-----------------------+-----------------------------+\n");
    printf("  [Page Size: %d Bytes | Virtual Address Translation: Active]\n\n", VIRTUAL_PAGE_SIZE);
    
    if (heap_pointer) free(heap_pointer);
}
