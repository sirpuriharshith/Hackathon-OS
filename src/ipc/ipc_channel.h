/**
 * MultiLog-OS: High-Performance Multithreaded Log Analysis & Threat Detection System
 * File: src/ipc/ipc_channel.h
 * 
 * Course Outcome Mapping:
 * - CO-3: Inter-Process Communication (IPC), Anonymous Pipes, Named Pipes,
 *         Signals and Asynchronous Notifications, POSIX Signal Handlers.
 */

#ifndef MULTILOG_IPC_CHANNEL_H
#define MULTILOG_IPC_CHANNEL_H

#include "../core/types.h"
#include <signal.h>

/* IPC Message Types (CO-3) */
typedef enum {
    IPC_MSG_HEARTBEAT = 1,
    IPC_MSG_PROGRESS_UPDATE,
    IPC_MSG_SECURITY_ALERT,
    IPC_MSG_WORKER_COMPLETED,
    IPC_MSG_TERMINATE
} IPCMessageType;

/* IPC Telemetry Packet Sent Over Anonymous Pipes (CO-3) */
typedef struct {
    uint32_t magic;           /* 0x4D4C4F53 ("MLOS") */
    IPCMessageType type;
    int worker_id;
    uint64_t processed_lines;
    uint32_t threat_code;
    char summary[128];
} IPCPacket;

/* Anonymous Pipe Channel Abstraction */
typedef struct {
    int read_fd;
    int write_fd;
    bool is_open;
} IPCPipeChannel;

/* Pipe lifecycle functions (CO-3: Anonymous Pipes) */
bool ipc_pipe_create(IPCPipeChannel *chan);
bool ipc_pipe_send(IPCPipeChannel *chan, const IPCPacket *packet);
bool ipc_pipe_receive(IPCPipeChannel *chan, IPCPacket *packet);
void ipc_pipe_close(IPCPipeChannel *chan);

/* Signal Handling Subsystem (CO-3: Asynchronous Notifications) */
extern volatile sig_atomic_t g_shutdown_requested;
extern volatile sig_atomic_t g_dump_metrics_requested;

void ipc_signals_init(void);

#endif /* MULTILOG_IPC_CHANNEL_H */
