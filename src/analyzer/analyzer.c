/**
 * MultiLog-OS: High-Performance Multithreaded Log Analysis & Threat Detection System
 * File: src/analyzer/analyzer.c
 */

#include "analyzer.h"
#include "patterns.h"
#include <ctype.h>

bool extract_ipv4(const char *line, char *out_ip, size_t max_len) {
    if (!line || !out_ip || max_len < 16) return false;
    
    const char *p = line;
    while (*p) {
        if (isdigit((unsigned char)*p)) {
            int octets = 0;
            const char *start = p;
            while (*p && (isdigit((unsigned char)*p) || *p == '.')) {
                if (*p == '.') octets++;
                p++;
            }
            if (octets == 3) {
                size_t len = p - start;
                if (len < max_len && len >= 7) {
                    strncpy(out_ip, start, len);
                    out_ip[len] = '\0';
                    return true;
                }
            }
        } else {
            p++;
        }
    }
    return false;
}

int extract_http_status(const char *line) {
    if (!line) return 0;
    
    /* Look for " HTTP/1.x" or " HTTP/2" followed by status code */
    const char *http_ver = strstr(line, "HTTP/1.");
    if (!http_ver) http_ver = strstr(line, "HTTP/2");
    
    if (http_ver) {
        const char *quote = strchr(http_ver, '"');
        if (quote) {
            const char *p = quote + 1;
            while (*p == ' ') p++;
            if (isdigit((unsigned char)p[0]) && isdigit((unsigned char)p[1]) && isdigit((unsigned char)p[2])) {
                return (p[0] - '0') * 100 + (p[1] - '0') * 10 + (p[2] - '0');
            }
        }
    }
    return 0;
}

void analyze_single_line(
    const char *line_start,
    size_t line_len,
    uint64_t line_num,
    FileChunk *chunk,
    MemoryArena *arena
) {
    if (!line_start || line_len == 0 || !chunk) return;
    
    chunk->lines_count++;
    chunk->bytes_count += line_len;

    /* Copy line to temporary null-terminated stack buffer for safe scanning */
    char line_buf[512];
    size_t copy_len = line_len < sizeof(line_buf) - 1 ? line_len : sizeof(line_buf) - 1;
    memcpy(line_buf, line_start, copy_len);
    line_buf[copy_len] = '\0';

    char ip[MAX_IP_LEN] = "127.0.0.1";
    extract_ipv4(line_buf, ip, sizeof(ip));
    
    int http_status = extract_http_status(line_buf);
    if (http_status >= 100 && http_status < 600) {
        int cat = http_status / 100;
        if (cat == 2) chunk->http_2xx++;
        else if (cat == 3) chunk->http_3xx++;
        else if (cat == 4) chunk->http_4xx++;
        else if (cat == 5) chunk->http_5xx++;
    }

    ThreatType detected_threat = THREAT_NONE;
    const char *matched_rule = NULL;

    /* 1. Threat Detection: SQL Injection */
    for (size_t i = 0; i < SQL_PATTERNS_COUNT; ++i) {
        if (strcasestr_portable(line_buf, SQL_INJECTION_PATTERNS[i])) {
            detected_threat = THREAT_SQL_INJECTION;
            matched_rule = SQL_INJECTION_PATTERNS[i];
            break;
        }
    }

    /* 2. Threat Detection: XSS */
    if (detected_threat == THREAT_NONE) {
        for (size_t i = 0; i < XSS_PATTERNS_COUNT; ++i) {
            if (strcasestr_portable(line_buf, XSS_PATTERNS[i])) {
                detected_threat = THREAT_XSS;
                matched_rule = XSS_PATTERNS[i];
                break;
            }
        }
    }

    /* 3. Threat Detection: Directory Traversal */
    if (detected_threat == THREAT_NONE) {
        for (size_t i = 0; i < TRAVERSAL_PATTERNS_COUNT; ++i) {
            if (strcasestr_portable(line_buf, DIR_TRAVERSAL_PATTERNS[i])) {
                detected_threat = THREAT_DIR_TRAVERSAL;
                matched_rule = DIR_TRAVERSAL_PATTERNS[i];
                break;
            }
        }
    }

    /* 4. Threat Detection: Malicious Recon Probes */
    if (detected_threat == THREAT_NONE) {
        for (size_t i = 0; i < PROBE_PATTERNS_COUNT; ++i) {
            if (strcasestr_portable(line_buf, RECON_PROBE_PATTERNS[i])) {
                detected_threat = THREAT_MALICIOUS_PROBE;
                matched_rule = RECON_PROBE_PATTERNS[i];
                break;
            }
        }
    }

    /* 5. Threat Detection: Brute Force / Auth Failures */
    if (detected_threat == THREAT_NONE) {
        for (size_t i = 0; i < AUTH_PATTERNS_COUNT; ++i) {
            if (strcasestr_portable(line_buf, AUTH_FAILURE_PATTERNS[i])) {
                detected_threat = THREAT_AUTH_FAILURE;
                matched_rule = AUTH_FAILURE_PATTERNS[i];
                break;
            }
        }
    }

    /* 6. Threat Detection: Privilege Escalation */
    if (detected_threat == THREAT_NONE) {
        for (size_t i = 0; i < PRIV_PATTERNS_COUNT; ++i) {
            if (strcasestr_portable(line_buf, PRIVILEGE_ESC_PATTERNS[i])) {
                detected_threat = THREAT_PRIVILEGE_ESC;
                matched_rule = PRIVILEGE_ESC_PATTERNS[i];
                break;
            }
        }
    }

    /* Record threat statistics */
    if (detected_threat != THREAT_NONE) {
        chunk->threat_counts[detected_threat]++;
        
        /* Store alert in chunk local buffer */
        if (chunk->local_alerts && chunk->local_alerts_count < chunk->local_alerts_capacity) {
            SecurityAlert *alert = &chunk->local_alerts[chunk->local_alerts_count++];
            alert->line_number = line_num;
            alert->severity = SEV_ERROR;
            alert->threat_type = detected_threat;
            strncpy(alert->ip_address, ip, MAX_IP_LEN - 1);
            strncpy(alert->rule_matched, matched_rule ? matched_rule : "Threat Signature", 63);
            strncpy(alert->snippet, line_buf, MAX_MSG_PREVIEW - 1);
            alert->timestamp[0] = '\0';
        }
    }

    /* Error & Warning Classification */
    bool is_error = false;
    bool is_warn = false;

    if (http_status >= 500) {
        is_error = true;
    } else if (http_status >= 400) {
        is_warn = true;
    }

    if (!is_error) {
        for (size_t i = 0; i < ERROR_KEYWORDS_COUNT; ++i) {
            if (strcasestr_portable(line_buf, ERROR_KEYWORDS[i])) {
                is_error = true;
                break;
            }
        }
    }

    if (!is_error && !is_warn) {
        for (size_t i = 0; i < WARN_KEYWORDS_COUNT; ++i) {
            if (strcasestr_portable(line_buf, WARN_KEYWORDS[i])) {
                is_warn = true;
                break;
            }
        }
    }

    if (is_error) {
        chunk->error_count++;
    } else if (is_warn) {
        chunk->warn_count++;
    } else {
        chunk->info_count++;
    }
}

void analyze_chunk_buffer(
    const char *buffer,
    uint64_t buffer_len,
    FileChunk *chunk,
    MemoryArena *arena
) {
    if (!buffer || buffer_len == 0 || !chunk) return;

    const char *p = buffer;
    const char *end = buffer + buffer_len;
    uint64_t line_num = 1;

    while (p < end) {
        const char *line_start = p;
        while (p < end && *p != '\n') {
            p++;
        }
        
        size_t line_len = p - line_start;
        /* Trim trailing \r if present */
        if (line_len > 0 && line_start[line_len - 1] == '\r') {
            line_len--;
        }

        if (line_len > 0) {
            analyze_single_line(line_start, line_len, line_num, chunk, arena);
        }

        if (p < end && *p == '\n') {
            p++; /* Skip newline */
        }
        line_num++;
    }
}
