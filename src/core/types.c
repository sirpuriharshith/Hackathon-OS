/**
 * MultiLog-OS: High-Performance Multithreaded Log Analysis & Threat Detection System
 * File: src/core/types.c
 */

#include "types.h"

const char* threat_type_to_string(ThreatType threat) {
    switch (threat) {
        case THREAT_NONE: return "NONE";
        case THREAT_BRUTE_FORCE: return "BRUTE_FORCE_AUTH";
        case THREAT_SQL_INJECTION: return "SQL_INJECTION";
        case THREAT_XSS: return "CROSS_SITE_SCRIPTING";
        case THREAT_DIR_TRAVERSAL: return "DIRECTORY_TRAVERSAL";
        case THREAT_MALICIOUS_PROBE: return "RECON_PROBE";
        case THREAT_DDOS_BURST: return "DDOS_FLOOD_BURST";
        case THREAT_PRIVILEGE_ESC: return "PRIVILEGE_ESCALATION";
        case THREAT_AUTH_FAILURE: return "AUTHENTICATION_FAILURE";
        default: return "UNKNOWN_THREAT";
    }
}

const char* severity_to_string(SeverityLevel sev) {
    switch (sev) {
        case SEV_DEBUG: return "DEBUG";
        case SEV_INFO: return "INFO";
        case SEV_WARN: return "WARN";
        case SEV_ERROR: return "ERROR";
        case SEV_FATAL: return "FATAL";
        default: return "UNKNOWN";
    }
}

const char* io_mode_to_string(IOMode mode) {
    switch (mode) {
        case IO_MODE_MMAP: return "Memory-Mapped I/O (mmap/MapViewOfFile)";
        case IO_MODE_DIRECT: return "Direct Syscall I/O (read/lseek)";
        case IO_MODE_BUFFERED: return "Standard Buffered I/O (fread/fgets)";
        default: return "UNKNOWN";
    }
}
