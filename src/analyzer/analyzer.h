/**
 * MultiLog-OS: High-Performance Multithreaded Log Analysis & Threat Detection System
 * File: src/analyzer/analyzer.h
 */

#ifndef MULTILOG_ANALYZER_H
#define MULTILOG_ANALYZER_H

#include "../core/types.h"
#include "../memory/arena.h"

/* Fast IP Address Extractor */
bool extract_ipv4(const char *line, char *out_ip, size_t max_len);

/* Fast HTTP Status Code Extractor */
int extract_http_status(const char *line);

/* Parse and classify a single line */
void analyze_single_line(
    const char *line_start,
    size_t line_len,
    uint64_t line_num,
    FileChunk *chunk,
    MemoryArena *arena
);

/* Process an entire memory buffer or chunk */
void analyze_chunk_buffer(
    const char *buffer,
    uint64_t buffer_len,
    FileChunk *chunk,
    MemoryArena *arena
);

#endif /* MULTILOG_ANALYZER_H */
