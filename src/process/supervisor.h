/**
 * MultiLog-OS: High-Performance Multithreaded Log Analysis & Threat Detection System
 * File: src/process/supervisor.h
 * 
 * Course Outcome Mapping:
 * - CO-1: User Space vs Kernel Space CPU Execution Journey
 * - CO-2: Process Lifecycle, State Transitions, CPU Times & Resource Accounting.
 */

#ifndef MULTILOG_SUPERVISOR_H
#define MULTILOG_SUPERVISOR_H

#include "../core/types.h"

/* Process State Machine (CO-2) */
typedef enum {
    PROC_STATE_READY = 0,
    PROC_STATE_RUNNING,
    PROC_STATE_BLOCKED_IO,
    PROC_STATE_TERMINATED
} ProcessState;

/* Process Resource Accounting Snapshot (CO-1 & CO-2) */
typedef struct {
    uint32_t process_id;
    uint32_t parent_process_id;
    ProcessState state;
    double start_wall_time;
    double end_wall_time;
    double elapsed_wall_sec;
    double user_cpu_time_sec;     /* Time spent executing User-Space code */
    double kernel_cpu_time_sec;   /* Time spent servicing Kernel System Calls */
    double cpu_utilization_pct;   /* Multithreaded parallel CPU efficiency */
} ProcessAccounting;

/* Start supervisor monitoring for the current process */
void supervisor_start_accounting(ProcessAccounting *proc);

/* Stop supervisor monitoring and compute final metrics */
void supervisor_stop_accounting(ProcessAccounting *proc, int active_threads);

/* Print detailed Process Accounting and Kernel/User Space breakdown */
void supervisor_print_summary(const ProcessAccounting *proc);

#endif /* MULTILOG_SUPERVISOR_H */
