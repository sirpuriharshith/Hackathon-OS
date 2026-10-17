/**
 * MultiLog-OS: High-Performance Multithreaded Log Analysis & Threat Detection System
 * File: src/io/file_io.c
 * 
 * Course Outcome Mapping:
 * - CO-5: Linux/OS File System Calls, Inodes, Virtual File System,
 *         mmap Zero-Copy, Buffered vs Unbuffered I/O, Chunk Boundary Synchronization.
 */

#include "file_io.h"
#include <sys/stat.h>
#include <fcntl.h>

#ifdef _WIN32
    #include <io.h>
    #include <share.h>
#else
    #include <sys/mman.h>
    #include <unistd.h>
#endif

bool file_inspect_metadata(const char *filepath, FileMetadata *meta) {
    if (!filepath || !meta) return false;
    memset(meta, 0, sizeof(FileMetadata));
    strncpy(meta->filename, filepath, MAX_PATH_LEN - 1);

#ifdef _WIN32
    struct _stat64 st;
    if (_stat64(filepath, &st) != 0) {
        perror("Failed to stat file");
        return false;
    }
    meta->file_size_bytes = (uint64_t)st.st_size;
    meta->block_size = 4096; /* NTFS / standard cluster size */
    meta->inode_number = (uint64_t)st.st_ino;
    meta->permissions = (uint32_t)st.st_mode;
    meta->last_modified = st.st_mtime;
#else
    struct stat st;
    if (stat(filepath, &st) != 0) {
        perror("Failed to stat file (VFS)");
        return false;
    }
    meta->file_size_bytes = (uint64_t)st.st_size;
    meta->block_size = (uint32_t)st.st_blksize;
    meta->inode_number = (uint64_t)st.st_ino;
    meta->permissions = (uint32_t)st.st_mode;
    meta->last_modified = st.st_mtime;
#endif

    return true;
}

bool file_mmap_open(FileMetadata *meta) {
    if (!meta || meta->file_size_bytes == 0) return false;

#ifdef _WIN32
    meta->win_file_handle = CreateFileA(
        meta->filename,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
        NULL
    );

    if (meta->win_file_handle == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "[Error] Failed to open file for mmap (Win32 CreateFile): %lu\n", GetLastError());
        return false;
    }

    meta->win_map_handle = CreateFileMappingA(
        meta->win_file_handle,
        NULL,
        PAGE_READONLY,
        0,
        0,
        NULL
    );

    if (meta->win_map_handle == NULL) {
        fprintf(stderr, "[Error] Failed to create file mapping object: %lu\n", GetLastError());
        CloseHandle(meta->win_file_handle);
        return false;
    }

    meta->mmap_base_addr = (char*)MapViewOfFile(
        meta->win_map_handle,
        FILE_MAP_READ,
        0,
        0,
        0
    );

    if (!meta->mmap_base_addr) {
        fprintf(stderr, "[Error] Failed to map view of file into address space: %lu\n", GetLastError());
        CloseHandle(meta->win_map_handle);
        CloseHandle(meta->win_file_handle);
        return false;
    }
#else
    meta->file_descriptor = open(meta->filename, O_RDONLY);
    if (meta->file_descriptor < 0) {
        perror("[Error] POSIX open syscall failed");
        return false;
    }

    meta->mmap_base_addr = (char*)mmap(
        NULL,
        meta->file_size_bytes,
        PROT_READ,
        MAP_SHARED,
        meta->file_descriptor,
        0
    );

    if (meta->mmap_base_addr == MAP_FAILED) {
        perror("[Error] POSIX mmap syscall failed");
        close(meta->file_descriptor);
        return false;
    }
#endif

    return true;
}

void file_mmap_close(FileMetadata *meta) {
    if (!meta) return;

#ifdef _WIN32
    if (meta->mmap_base_addr) {
        UnmapViewOfFile(meta->mmap_base_addr);
        meta->mmap_base_addr = NULL;
    }
    if (meta->win_map_handle) {
        CloseHandle(meta->win_map_handle);
        meta->win_map_handle = NULL;
    }
    if (meta->win_file_handle != INVALID_HANDLE_VALUE) {
        CloseHandle(meta->win_file_handle);
        meta->win_file_handle = INVALID_HANDLE_VALUE;
    }
#else
    if (meta->mmap_base_addr && meta->mmap_base_addr != MAP_FAILED) {
        munmap(meta->mmap_base_addr, meta->file_size_bytes);
        meta->mmap_base_addr = NULL;
    }
    if (meta->file_descriptor >= 0) {
        close(meta->file_descriptor);
        meta->file_descriptor = -1;
    }
#endif
}

bool file_partition_chunks(const FileMetadata *meta, int thread_count, FileChunk *chunks) {
    if (!meta || !chunks || thread_count <= 0) return false;
    
    uint64_t file_size = meta->file_size_bytes;
    if (file_size == 0) {
        for (int i = 0; i < thread_count; ++i) {
            memset(&chunks[i], 0, sizeof(FileChunk));
            chunks[i].chunk_id = i;
        }
        return true;
    }

    if (thread_count == 1) {
        memset(&chunks[0], 0, sizeof(FileChunk));
        chunks[0].chunk_id = 0;
        chunks[0].start_offset = 0;
        chunks[0].end_offset = file_size;
        chunks[0].chunk_size = file_size;
        return true;
    }

    FILE *fp = fopen(meta->filename, "rb");
    if (!fp) {
        perror("Failed to open file for boundary scanning");
        return false;
    }

    uint64_t nominal_chunk_size = file_size / thread_count;
    uint64_t boundaries[65]; /* Up to 64 threads */
    boundaries[0] = 0;

    for (int i = 1; i < thread_count; ++i) {
        uint64_t nominal_boundary = i * nominal_chunk_size;
        
        if (nominal_boundary >= file_size) {
            boundaries[i] = file_size;
            continue;
        }

        /* Seek to nominal boundary and scan forward for '\n' */
#if defined(_WIN32)
        _fseeki64(fp, nominal_boundary, SEEK_SET);
#else
        fseeko(fp, nominal_boundary, SEEK_SET);
#endif
        uint64_t curr_pos = nominal_boundary;
        int ch;
        bool found_newline = false;
        
        while ((ch = fgetc(fp)) != EOF) {
            curr_pos++;
            if (ch == '\n') {
                found_newline = true;
                break;
            }
        }

        if (found_newline) {
            boundaries[i] = curr_pos; /* Chunk begins after newline character */
        } else {
            boundaries[i] = file_size;
        }
    }
    boundaries[thread_count] = file_size;
    fclose(fp);

    /* Assign offsets to each thread chunk */
    for (int i = 0; i < thread_count; ++i) {
        memset(&chunks[i], 0, sizeof(FileChunk));
        chunks[i].chunk_id = i;
        chunks[i].start_offset = boundaries[i];
        chunks[i].end_offset = boundaries[i + 1];
        if (chunks[i].end_offset >= chunks[i].start_offset) {
            chunks[i].chunk_size = chunks[i].end_offset - chunks[i].start_offset;
        } else {
            chunks[i].chunk_size = 0;
        }
        chunks[i].local_alerts_capacity = 256;
        chunks[i].local_alerts = (SecurityAlert*)malloc(chunks[i].local_alerts_capacity * sizeof(SecurityAlert));
        chunks[i].local_alerts_count = 0;
    }

    return true;
}

size_t file_read_direct_slice(const FileMetadata *meta, uint64_t offset, size_t length, char *dest_buffer) {
    if (!meta || !dest_buffer || length == 0) return 0;

#ifdef _WIN32
    int fd = _open(meta->filename, _O_RDONLY | _O_BINARY);
    if (fd < 0) return 0;
    _lseeki64(fd, offset, SEEK_SET);
    int bytes_read = _read(fd, dest_buffer, (unsigned int)length);
    _close(fd);
    return bytes_read > 0 ? (size_t)bytes_read : 0;
#else
    int fd = open(meta->filename, O_RDONLY);
    if (fd < 0) return 0;
    lseek(fd, offset, SEEK_SET);
    ssize_t bytes_read = read(fd, dest_buffer, length);
    close(fd);
    return bytes_read > 0 ? (size_t)bytes_read : 0;
#endif
}

size_t file_read_buffered_slice(const char *filepath, uint64_t offset, size_t length, char *dest_buffer) {
    if (!filepath || !dest_buffer || length == 0) return 0;

    FILE *fp = fopen(filepath, "rb");
    if (!fp) return 0;

#ifdef _WIN32
    _fseeki64(fp, offset, SEEK_SET);
#else
    fseeko(fp, offset, SEEK_SET);
#endif

    size_t bytes_read = fread(dest_buffer, 1, length, fp);
    fclose(fp);
    return bytes_read;
}
