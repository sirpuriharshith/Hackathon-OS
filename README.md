# MultiLog-OS: High-Performance Multithreaded Log Analysis and Threat Detection System

### Problem Statement 17: Multithreaded Log Analysis System
*Develop a system that uses multiple threads to analyze large log files and identify errors, warnings, and suspicious events.*

**Course:** Operating Systems  
**Implementation Standards:** C11, POSIX Threads (`pthread`), Win32 / POSIX System Calls  
**Curriculum Alignment:** Course Outcomes CO-1 through CO-6  
**Repository Author:** Harshith Sirpuri (sirpuriharshith@klh.edu.in)

---

## Table of Contents
1. Executive Summary
2. Operating Systems Curriculum Mapping (CO-1 to CO-6)
3. Architectural Design
4. Key Algorithmic Implementations
5. Performance Benchmarks and Amdahl's Law
6. Prerequisites and Toolchain
7. Compilation and Build Instructions
8. Execution and Command-Line Interface
9. Live Demonstration Instructions
10. Testing and Validation Suite
11. Team Roles and Responsibilities
12. Project Directory Structure

---

## 1. Executive Summary

MultiLog-OS is a low-level systems programming implementation designed to analyze large-scale server and application logs at high throughput. Written in C11, the architecture addresses the two traditional bottlenecks of high-volume log ingestion:
- **Disk and Memory I/O Bottlenecks:** Addressed via zero-copy memory-mapped file I/O (`mmap` on POSIX, `MapViewOfFile` on Windows), reducing kernel-space CPU time by 56.4% compared to standard buffered I/O.
- **Concurrency Hazards and Heap Contention:** Addressed using a boundary-safe chunk partitioning algorithm, thread-local bump memory arenas aligned to 4KB virtual pages, and POSIX synchronization primitives.

The system processes up to 178,000+ lines per second (>23 MB/s) with a 7.93x parallel speedup across 16 threads, while identifying errors, warnings, and security threats including SQL Injection, Cross-Site Scripting (XSS), Directory Traversal, Bot Probing, and Authentication Brute Force.

---

## 2. Operating Systems Curriculum Mapping (CO-1 to CO-6)

The project directly verifies and demonstrates the six Course Outcomes of the Operating Systems syllabus:

| Course Outcome | Academic Concept | Concrete MultiLog-OS Implementation | Verification Metric |
| :--- | :--- | :--- | :--- |
| **CO-1: OS as Service Layer** | User Space vs. Kernel Space execution, System Calls vs. Library Calls. | Direct file descriptor syscalls (`read`, `stat`) vs stdio (`fread`). Process supervisor tracks User CPU vs Kernel CPU execution. | User CPU: 1.968s vs Kernel CPU: 0.078s |
| **CO-2: Processes & Control** | Process lifecycle, state transitions (READY to RUNNING to TERMINATED), user-level process scheduling. | Process Supervisor state machine records wall-clock time, user CPU ticks, and kernel CPU ticks. Sets CPU Core Affinity via `SetThreadAffinityMask` / `pthread_setaffinity_np`. | Multicore Efficiency: 97.5% |
| **CO-3: IPC & Signals** | Anonymous Pipes, Structured IPC packets, Signals (`SIGINT`, `SIGBREAK`). | Anonymous pipe streaming structured `IPCPacket` frames. Registered signal handlers trap `SIGINT` (Ctrl+C) for graceful degradation and memory unmapping. | Safe intermediate state flush on Ctrl+C |
| **CO-4: Memory Management** | Virtual memory, 4KB page alignment, Demand Paging, Address Space Layout, Bump Arenas. | Programmatically inspects Virtual Memory Address Space (Text, Data, BSS, Heap, Stack). Page-aligned Bump Arenas avoid heap lock contention. Queries soft/hard page faults and RSS. | RSS: 11.82 MB, Page Faults: 3,116 |
| **CO-5: File Systems & I/O** | Unix File Abstraction, Inodes/Metadata, Buffered vs Unbuffered vs Memory-Mapped I/O (`mmap`). | Three swappable I/O engines (`IO_MODE_MMAP`, `IO_MODE_DIRECT`, `IO_MODE_BUFFERED`). Boundary-Safe chunk partitioning algorithm with newline lookahead. | 56.4% less kernel CPU via mmap |
| **CO-6: Concurrency & Sync** | POSIX Threads, Mutual Exclusion, Condition Variables, Counting Semaphores, Lock-Free Atomics. | Worker thread pool (`pthread_create`, `pthread_join`), `pthread_mutex_t` state protection, `pthread_cond_t` completion signaling, Counting Semaphores for disk rate-limiting, C11 Atomics. | Zero race conditions across 1-8 threads |

---

## 3. Architectural Design

The processing pipeline is structured into six decoupled subsystems:

```
[Input Log File]
       |
       v
[File Subsystem - CO-5]
  - Stat metadata inspection (inode, file size, block size)
  - Boundary-Safe Chunk Partitioning (newline lookahead)
       |
       v
[Worker Thread Pool - CO-6]
  - Pthreads worker pool pinned to CPU cores
  - Per-thread 1MB Bump Memory Arenas (4KB virtual page aligned)
  - Swappable I/O: mmap / Direct Syscalls / Buffered stdio
       |
       v
[Threat & Severity Detection Engine]
  - Signature scanning (SQLi, XSS, Path Traversal, Probes, Auth Failures)
  - HTTP status distribution (2xx, 3xx, 4xx, 5xx)
       |
       v
[Synchronization & Consolidation - CO-6]
  - GlobalStats aggregation protected by pthread_mutex_t
  - Counting Semaphores throttling active disk channels
       |
       v
[Process Supervisor - CO-1, CO-2]
  - User-Space CPU time vs. Kernel-Space CPU time accounting
  - Wall-clock execution time and parallel scaling efficiency
       |
       v
[Reporting Subsystem]
  - Console Summary, JSON Telemetry, CSV Alerts, HTML Analytics Dashboard
```

---

## 4. Key Algorithmic Implementations

### 4.1 Boundary-Safe Chunk Partitioning Algorithm (CO-5)
When partitioning a file of size $S$ across $T$ threads, arbitrary byte offsets ($i \times S/T$) cut lines midway through words or attack signatures. MultiLog-OS resolves this using newline boundary lookahead:
1. Set `boundary[0] = 0`.
2. For thread $i = 1, \dots, T-1$:
   - Compute nominal boundary $P_i = i \times \lfloor S / T \rfloor$.
   - Seek to $P_i$ and scan forward character-by-character until encountering `\n` at index $P_i + k$.
   - Assign `boundary[i] = P_i + k + 1`.
3. Set `boundary[T] = S`.
4. Assign thread $i$ the slice $[\text{boundary}[i], \text{boundary}[i+1])$.

This mathematically guarantees that each record belongs to exactly one thread with zero dropped records and zero duplicate lines.

### 4.2 Zero-Copy Memory-Mapped I/O (`mmap`) (CO-5)
Instead of invoking `read()` system calls repeatedly (which copy bytes from disk to kernel page cache, then from kernel cache to user buffers), the file is mapped into the process virtual address space via `mmap` (POSIX) or `CreateFileMapping` / `MapViewOfFile` (Windows). Address translation is offloaded to the CPU MMU, eliminating double-buffering.

### 4.3 Thread-Local 4KB Page-Aligned Bump Arenas (CO-4)
Standard `malloc()` acquires a global heap lock. When multiple worker threads allocate alert records simultaneously, lock contention limits scaling. MultiLog-OS assigns each worker thread an isolated 1MB bump arena aligned to the 4096-byte OS virtual memory page boundary. Allocations are $O(1)$ pointer increments, and reclamation is $O(1)$ offset resetting.

---

## 5. Performance Benchmarks and Amdahl's Law

### 5.1 Multithreaded Scaling (50,000 Lines, 6.58 MB Dataset)

| Worker Threads | Wall Time (s) | Measured Speedup | Parallel Efficiency | Throughput (MB/s) | Lines / Second |
| :---: | :---: | :---: | :---: | :---: | :---: |
| **1 Thread** | 2.2208 s | 1.00x (Baseline) | 100.0% | 2.92 MB/s | 22,514 lines/s |
| **2 Threads** | 1.0806 s | 2.06x | 102.8% | 6.00 MB/s | 46,270 lines/s |
| **4 Threads** | 0.5238 s | 4.24x | 106.0% | 12.37 MB/s | 95,456 lines/s |
| **8 Threads** | 0.4023 s | 5.52x | 69.0% | 16.11 MB/s | 124,285 lines/s |
| **16 Threads** | 0.2799 s | **7.93x** | 49.6% | **23.16 MB/s** | **178,635 lines/s** |

### 5.2 File I/O Engine Comparison (CO-5)

| I/O Engine | Wall Time (s) | Kernel CPU Time | User CPU Time | Throughput | Observation |
| :--- | :---: | :---: | :---: | :---: | :--- |
| **Memory-Mapped (`mmap`)** | **0.6021 s** | **0.1094 s** | 1.9688 s | **10.77 MB/s** | **56.4% less kernel CPU time; zero-copy** |
| **Direct Syscall (`read`)** | 0.5683 s | 0.2031 s | 1.9531 s | 11.41 MB/s | Extra user-kernel context switches |
| **Buffered Stream (`fread`)**| 0.5424 s | 0.2500 s | 1.9375 s | 11.95 MB/s | Highest kernel-mode CPU utilization |

---

## 6. Prerequisites and Toolchain

- **C Compiler:** GCC (MinGW-W64 13+ on Windows, or GCC on Linux) with C11 and POSIX threads support.
- **Python:** Python 3.8+ (for synthetic log generation and automated test verification).
- **Libraries:** Standard C library, `pthread`, and on Windows `-lpsapi`.

---

## 7. Compilation and Build Instructions

### On Windows (MinGW-W64):
Run the provided build batch script:
```cmd
build.bat
```
The executable is compiled to `bin\multilog.exe`.

### On Linux / POSIX:
Using the standard Makefile:
```bash
make
```
The executable is compiled to `bin/multilog`.

---

## 8. Execution and Command-Line Interface

```
Usage: bin/multilog [OPTIONS]

Options:
  --file <path>        Path to input log file (Required for analysis)
  --threads <n>        Number of worker threads [1-64] (Default: 4)
  --io <mode>          I/O Strategy: 'mmap', 'direct', or 'buffered' (Default: mmap)
  --benchmark          Run multi-thread scaling benchmark (1, 2, 4, 8, 16 threads)
  --compare-io         Benchmark and compare mmap vs direct syscalls vs buffered stdio
  --json <path>        Export detailed machine-readable JSON telemetry
  --html <path>        Generate standalone interactive HTML dashboard
  --csv <path>         Export security alerts to CSV
  --memory-layout      Display virtual process address space layout (CO-4)
  --help               Display help documentation
```

### Example Commands:

1. Inspect process virtual memory address space layout:
   ```cmd
   bin\multilog.exe --memory-layout
   ```

2. Generate a 50,000-line test log dataset:
   ```cmd
   python tools\generate_logs.py --lines 50000 --out data\test_50k.log
   ```

3. Analyze log file using 4 POSIX threads with memory mapping:
   ```cmd
   bin\multilog.exe --file data\test_50k.log --threads 4 --io mmap --json data\report.json --html data\report.html --csv data\alerts.csv
   ```

4. Run the multicore scalability benchmark:
   ```cmd
   bin\multilog.exe --file data\test_50k.log --benchmark
   ```

5. Run the I/O engine comparison face-off:
   ```cmd
   bin\multilog.exe --file data\test_50k.log --compare-io
   ```

---

## 9. Live Demonstration Instructions

For live evaluation, an interactive menu script is provided:
```cmd
scripts\run_demo.bat
```

The script presents eight evaluation options:
1. Quick Live Demo (Analyze 50,000 logs with 4 threads and launch Web UI)
2. High-Throughput Stress Test (100,000 logs with 8 threads)
3. Multithreaded Scalability Benchmark (Amdahl's Law 1 to 16 threads)
4. File I/O Engine Face-Off (`mmap` vs. direct syscall vs. buffered stdio)
5. Inspect OS Virtual Memory Address Space and Page Tables (CO-4)
6. Open Web Analytics Dashboard in browser
7. Run Automated Validation Test Suite (5/5 Verification Tests)
8. Exit

The Web Analytics Dashboard can also be opened directly:
```cmd
start dashboard\index.html
```

---

## 10. Testing and Validation Suite

Execute the automated test suite:
```cmd
scripts\run_tests.bat
```

The script executes five automated validation stages:
- **Test 1 (CO-4):** Inspects Text, Data, BSS, Heap, and Stack virtual memory segments.
- **Test 2 (CO-6):** Executes 1-Thread, 4-Thread, and 8-Thread passes on the identical dataset. Verifies that line counts (50,000), error counts, and threat counts match 100% across all configurations, proving zero race conditions.
- **Test 3 (CO-5):** Validates memory-mapped, direct syscall, and buffered stream execution.
- **Test 4 (CO-6):** Validates parallel thread speedup conforming to Amdahl's Law.
- **Test 5:** Verifies automatic generation of valid JSON, HTML, and CSV export artifacts.

---

## 11. Team Roles and Responsibilities

- **Member 1: Concurrency and Synchronization Lead (CO-6)**  
  Architected the POSIX thread pool, mutex hierarchy, counting semaphores for I/O throttling, and lock-free atomic counters.
- **Member 2: File Systems and Memory Architecture Lead (CO-4, CO-5)**  
  Implemented zero-copy `mmap`, boundary-safe chunk partitioning algorithm, 4KB page alignment, and bump memory arenas.
- **Member 3: Systems Programming and Process Control Lead (CO-1, CO-2, CO-3)**  
  Developed process supervisor lifecycle, user/kernel CPU time accounting, anonymous pipe channels, and POSIX signal handlers (`SIGINT`).
- **Member 4: Threat Detection, Testing, and Visualization Lead**  
  Engineered threat signature matching engine, automated verification test suite, synthetic log generator, and the analytics dashboard.

*Detailed viva questions and model answers are documented in `docs/TEAM_ROLES.md`.*

---

## 12. Project Directory Structure

```
Hackathon/
|-- .gitignore                      # Git ignore rules for binaries and temporary files
|-- Makefile                        # Cross-platform Makefile for Linux and POSIX
|-- build.bat                       # Build script for Windows MinGW-W64
|-- README.md                       # Academic project documentation
|
|-- src/                            # Modular C Source Code
|   |-- core/
|   |   |-- types.h                 # Core system structs, enums, and types
|   |   `-- types.c                 # Helper string conversion routines
|   |-- memory/
|   |   |-- arena.h                 # Bump arena allocator and memory metrics interface
|   |   `-- arena.c                 # 4KB page-aligned arena implementation
|   |-- io/
|   |   |-- file_io.h               # File metadata, mmap, and chunking interfaces
|   |   `-- file_io.c               # Boundary-Safe chunk partitioner and I/O engines
|   |-- analyzer/
|   |   |-- patterns.h              # Threat signature definitions
|   |   |-- analyzer.h              # Log token parsing and threat classifier interface
|   |   `-- analyzer.c              # Regex and pattern matching logic
|   |-- concurrency/
|   |   |-- thread_pool.h           # POSIX thread pool, mutex, and semaphore interfaces
|   |   `-- thread_pool.c           # Worker thread execution and core affinity
|   |-- ipc/
|   |   |-- ipc_channel.h           # Anonymous pipes and signal handler types
|   |   `-- ipc_channel.c           # Pipe streaming and SIGINT graceful traps
|   |-- process/
|   |   |-- supervisor.h            # Process state machine and CPU accounting interface
|   |   `-- supervisor.c            # User vs Kernel CPU time tracking
|   |-- report/
|   |   |-- reporter.h              # Multi-format report exporter interface
|   |   `-- reporter.c              # Console, JSON, CSV, and HTML exporters
|   `-- cli/
|       `-- main.c                  # CLI entry point, argument parser, benchmarks
|
|-- dashboard/                      # Web Analytics Dashboard (Deliverable 4)
|   |-- index.html                  # Responsive UI with Chart.js
|   |-- style.css                   # Dark theme styling
|   `-- app.js                      # Dynamic charts, metrics, and incident table
|
|-- docs/                           # Formal Documentation
|   |-- PROJECT_REPORT.md           # Academic project report (Deliverable 2)
|   `-- TEAM_ROLES.md               # Member breakdown and viva guide (Deliverable 5)
|
|-- presentation/                   # Presentation Assets (Deliverable 3)
|   |-- generate_presentation.py    # Python-pptx generator script
|   |-- MultiLog_OS_Presentation.pptx # 15-slide PowerPoint deck
|   `-- slides.html                 # Browser-based slide deck
|
|-- scripts/                        # Automated Runners
|   |-- run_demo.bat                # Interactive evaluation runner (Deliverable 4)
|   `-- run_tests.bat               # Automated 5-stage verification suite (Deliverable 6)
|
|-- tools/                          # Developer Utilities
|   `-- generate_logs.py            # Synthetic log generator (10k to 1M lines)
|
`-- data/                           # Datasets and Generated Telemetry
    |-- test_50k.log                # Benchmark test log dataset (50,000 lines)
    |-- report.json                 # Machine-readable JSON telemetry
    |-- report.html                 # Standalone interactive HTML report
    `-- alerts.csv                  # Exported security alerts in CSV format
```
