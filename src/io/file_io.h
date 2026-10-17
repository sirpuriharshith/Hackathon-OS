/**
 * MultiLog-OS: High-Performance Multithreaded Log Analysis & Threat Detection System
 * File: src/io/file_io.h
 * 
 * Course Outcome Mapping:
 * - CO-5: File Systems, File Abstractions, File Descriptors, Inodes/Metadata,
 *         Buffered vs Unbuffered I/O, Memory-Mapped File I/O (mmap/MapViewOfFile),
 *         Boundary-Aligned File Chunking.
 */

#ifndef MULTILOG_FILE_IO_H
#define MULTILOG_FILE_IO_H

#include "../core/types.h"

/* Metadata Structure describing the underlying file system inode/object (CO-5) */
typedef struct {
    char filename[MAX_PATH_LEN];
    uint64_t file_size_bytes;
    uint32_t block_size;
    uint64_t inode_number;
    uint32_t permissions;
    time_t last_modified;
    int file_descriptor;
    
    /* Memory mapped pointer (if IO_MODE_MMAP is used) */
    char *mmap_base_addr;
#ifdef _WIN32
    HANDLE win_file_handle;
    HANDLE win_map_handle;
#endif
} FileMetadata;

/* Initialize and inspect file properties using OS system calls (CO-5) */
bool file_inspect_metadata(const char *filepath, FileMetadata *meta);

/* Map file into virtual address space (CO-4 & CO-5: Zero-Copy mmap) */
bool file_mmap_open(FileMetadata *meta);
void file_mmap_close(FileMetadata *meta);

/* Compute thread chunk boundaries aligned cleanly to newline '\n' characters */
bool file_partition_chunks(const FileMetadata *meta, int thread_count, FileChunk *chunks);

/* Read a slice of file using Direct Syscalls (read/lseek) */
size_t file_read_direct_slice(const FileMetadata *meta, uint64_t offset, size_t length, char *dest_buffer);

/* Read a slice of file using Buffered Standard Streams (fread) */
size_t file_read_buffered_slice(const char *filepath, uint64_t offset, size_t length, char *dest_buffer);

#endif /* MULTILOG_FILE_IO_H */
