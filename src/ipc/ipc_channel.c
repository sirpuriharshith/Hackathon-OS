/**
 * MultiLog-OS: High-Performance Multithreaded Log Analysis & Threat Detection System
 * File: src/ipc/ipc_channel.c
 * 
 * Course Outcome Mapping:
 * - CO-3: Anonymous Pipes, IPC Packet Streaming, Signal Handlers,
 *         Asynchronous Event Notification.
 */

#include "ipc_channel.h"
#include <fcntl.h>

#ifdef _WIN32
    #include <io.h>
#else
    #include <unistd.h>
#endif

volatile sig_atomic_t g_shutdown_requested = 0;
volatile sig_atomic_t g_dump_metrics_requested = 0;

static void signal_handler(int sig) {
    if (sig == SIGINT) {
        g_shutdown_requested = 1;
        /* Re-register signal handler */
        signal(SIGINT, signal_handler);
    }
#ifdef SIGBREAK
    else if (sig == SIGBREAK) {
        g_dump_metrics_requested = 1;
        signal(SIGBREAK, signal_handler);
    }
#endif
}

void ipc_signals_init(void) {
    /* Register OS Signal Handlers (CO-3: POSIX / Asynchronous Notifications) */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
#ifdef SIGBREAK
    signal(SIGBREAK, signal_handler);
#endif
}

bool ipc_pipe_create(IPCPipeChannel *chan) {
    if (!chan) return false;
    int fds[2];

#ifdef _WIN32
    if (_pipe(fds, sizeof(IPCPacket) * 16, _O_BINARY) != 0) {
        perror("[Error] Win32 _pipe creation failed");
        return false;
    }
#else
    if (pipe(fds) != 0) {
        perror("[Error] POSIX pipe syscall failed");
        return false;
    }
#endif

    chan->read_fd = fds[0];
    chan->write_fd = fds[1];
    chan->is_open = true;
    return true;
}

bool ipc_pipe_send(IPCPipeChannel *chan, const IPCPacket *packet) {
    if (!chan || !chan->is_open || !packet) return false;

#ifdef _WIN32
    int written = _write(chan->write_fd, packet, sizeof(IPCPacket));
#else
    ssize_t written = write(chan->write_fd, packet, sizeof(IPCPacket));
#endif

    return written == sizeof(IPCPacket);
}

bool ipc_pipe_receive(IPCPipeChannel *chan, IPCPacket *packet) {
    if (!chan || !chan->is_open || !packet) return false;

#ifdef _WIN32
    int bytes = _read(chan->read_fd, packet, sizeof(IPCPacket));
#else
    ssize_t bytes = read(chan->read_fd, packet, sizeof(IPCPacket));
#endif

    return bytes == sizeof(IPCPacket);
}

void ipc_pipe_close(IPCPipeChannel *chan) {
    if (!chan || !chan->is_open) return;

#ifdef _WIN32
    if (chan->read_fd >= 0) _close(chan->read_fd);
    if (chan->write_fd >= 0) _close(chan->write_fd);
#else
    if (chan->read_fd >= 0) close(chan->read_fd);
    if (chan->write_fd >= 0) close(chan->write_fd);
#endif

    chan->read_fd = -1;
    chan->write_fd = -1;
    chan->is_open = false;
}
