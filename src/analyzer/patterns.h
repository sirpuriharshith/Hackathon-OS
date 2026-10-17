/**
 * MultiLog-OS: High-Performance Multithreaded Log Analysis & Threat Detection System
 * File: src/analyzer/patterns.h
 * 
 * High-speed string matching patterns and signature definitions
 * for detecting Errors, Warnings, and Suspicious Events.
 */

#ifndef MULTILOG_PATTERNS_H
#define MULTILOG_PATTERNS_H

#include "../core/types.h"

/* Case-insensitive string search in needle */
static inline const char* strcasestr_portable(const char *haystack, const char *needle) {
    if (!haystack || !needle) return NULL;
    if (!*needle) return haystack;
    
    for (; *haystack; haystack++) {
        if (tolower((unsigned char)*haystack) == tolower((unsigned char)*needle)) {
            const char *h = haystack;
            const char *n = needle;
            while (*h && *n && tolower((unsigned char)*h) == tolower((unsigned char)*n)) {
                h++;
                n++;
            }
            if (!*n) return haystack;
        }
    }
    return NULL;
}

/* Suspicious Event Signatures */
static const char* SQL_INJECTION_PATTERNS[] = {
    "union select",
    "union all select",
    "' or '1'='1",
    "' or 1=1",
    "sleep(",
    "benchmark(",
    "drop table",
    "--",
    "information_schema"
};
#define SQL_PATTERNS_COUNT (sizeof(SQL_INJECTION_PATTERNS) / sizeof(SQL_INJECTION_PATTERNS[0]))

static const char* XSS_PATTERNS[] = {
    "<script",
    "javascript:",
    "onerror=",
    "onload=",
    "alert(",
    "<iframe",
    "document.cookie"
};
#define XSS_PATTERNS_COUNT (sizeof(XSS_PATTERNS) / sizeof(XSS_PATTERNS[0]))

static const char* DIR_TRAVERSAL_PATTERNS[] = {
    "../..",
    "..\\..\\",
    "/etc/passwd",
    "/etc/shadow",
    "boot.ini",
    "win.ini",
    "system32"
};
#define TRAVERSAL_PATTERNS_COUNT (sizeof(DIR_TRAVERSAL_PATTERNS) / sizeof(DIR_TRAVERSAL_PATTERNS[0]))

static const char* RECON_PROBE_PATTERNS[] = {
    "/wp-login",
    "/wp-admin",
    "/.env",
    "/.git/config",
    "/phpmyadmin",
    "/actuator",
    "/cgi-bin/",
    "/web-console"
};
#define PROBE_PATTERNS_COUNT (sizeof(RECON_PROBE_PATTERNS) / sizeof(RECON_PROBE_PATTERNS[0]))

static const char* AUTH_FAILURE_PATTERNS[] = {
    "failed password",
    "authentication failure",
    "invalid credentials",
    "pam_unix(sshd:auth): failure",
    "login failed",
    "access denied",
    "unauthorized access"
};
#define AUTH_PATTERNS_COUNT (sizeof(AUTH_FAILURE_PATTERNS) / sizeof(AUTH_FAILURE_PATTERNS[0]))

static const char* PRIVILEGE_ESC_PATTERNS[] = {
    "sudo: auth failure",
    "command=/bin/sh",
    "command=/bin/bash",
    "nopasswd:",
    "privilege escalation",
    "root shell spawned"
};
#define PRIV_PATTERNS_COUNT (sizeof(PRIVILEGE_ESC_PATTERNS) / sizeof(PRIVILEGE_ESC_PATTERNS[0]))

static const char* ERROR_KEYWORDS[] = {
    "[error]",
    "error:",
    "level=error",
    "fatal",
    "critical",
    "panic:",
    "segmentation fault",
    "out of memory",
    "oom-killer",
    "exception in thread",
    "core dumped",
    "connection refused"
};
#define ERROR_KEYWORDS_COUNT (sizeof(ERROR_KEYWORDS) / sizeof(ERROR_KEYWORDS[0]))

static const char* WARN_KEYWORDS[] = {
    "[warn]",
    "[warning]",
    "warn:",
    "warning:",
    "level=warn",
    "deprecated",
    "threshold exceeded",
    "retry attempt",
    "connection reset",
    "high latency",
    "disk usage high"
};
#define WARN_KEYWORDS_COUNT (sizeof(WARN_KEYWORDS) / sizeof(WARN_KEYWORDS[0]))

#endif /* MULTILOG_PATTERNS_H */
