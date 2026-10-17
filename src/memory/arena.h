/**
 * MultiLog-OS: High-Performance Multithreaded Log Analysis & Threat Detection System
 * File: src/memory/arena.h
 * 
 * Course Outcome Mapping:
 * - CO-4: Virtual Memory as an Operating System Abstraction, Page Tables, 
 *         Demand Paging, Process Address Space Layout, Dynamic Memory Allocation,
 *         Memory Debugging and Performance Analysis.
 */

#ifndef MULTILOG_ARENA_H
#define MULTILOG_ARENA_H

#include "../core/types.h"

/* Fast Thread-Local Bump Pointer Memory Arena (CO-4: Virtual Memory Page Alignment) */
typedef struct {
    char *buffer;             /* Raw contiguous memory block */
    size_t capacity;          /* Total capacity in bytes (page aligned) */
    size_t offset;            /* Current bump allocation offset */
    size_t high_watermark;    /* Peak bytes allocated */
    uint32_t allocation_count;/* Number of allocations served */
} MemoryArena;

/* Memory Telemetry Snapshot (CO-4: Address Space & Page Fault Metrics) */
typedef struct {
    size_t virtual_memory_bytes;     /* Total virtual address space */
    size_t resident_set_size_bytes;  /* Physical RAM pages currently mapped */
    size_t peak_working_set_bytes;   /* Peak physical memory used */
    uint64_t minor_page_faults;      /* Pages resolved without disk I/O */
    uint64_t major_page_faults;      /* Pages requiring disk I/O */
} MemoryMetrics;

/* Arena lifecycle functions */
MemoryArena* arena_create(size_t capacity_bytes);
void* arena_alloc(MemoryArena *arena, size_t size_bytes);
void arena_reset(MemoryArena *arena);
void arena_destroy(MemoryArena *arena);

/* OS Virtual Memory Inspection Functions (CO-4) */
MemoryMetrics os_get_memory_metrics(void);
void print_memory_layout_info(void);

#endif /* MULTILOG_ARENA_H */
