# MultiLog-OS: Team Roles, Contributions & Viva Guide
## Deliverable 5: Team Participation & Concept Mastery

This document outlines the specific roles, module ownership, and OS technical concept mastery for each team member to facilitate smooth live demonstration and evaluation.

---

### Team Member 1: Concurrency & Synchronization Lead
- **Domain:** Operating Systems Concurrency (CO-6)
- **Module Ownership:** `src/concurrency/thread_pool.h`, `src/concurrency/thread_pool.c`
- **Core Responsibilities:**
  - Architected the POSIX thread pool model (`pthread_create`, `pthread_join`).
  - Implemented mutual exclusion locks (`pthread_mutex_t`) to eliminate race conditions when worker threads consolidate results into `GlobalStats`.
  - Implemented counting semaphores (`sem_t` / Win32 Semaphores) to throttle concurrent disk I/O operations and avoid storage thrashing.
  - Implemented lock-free C11 atomic counters for high-velocity thread metrics.
  - Benchmarked Amdahl's Law speedup curves across 1, 2, 4, 8, and 16 worker threads.

#### Evaluation Viva Questions & Model Answers:
1. **Q: How does MultiLog-OS prevent race conditions when multiple threads analyze logs simultaneously?**
   *A:* "Each worker thread records counts into its own thread-local `FileChunk` structure without acquiring any locks during log parsing. Only once a chunk is completed does the worker acquire `stats_mutex` for a fraction of a millisecond to merge its totals into `GlobalStats`. This isolates the critical section from the hot path."
2. **Q: What is the purpose of the counting semaphore in your thread pool?**
   *A:* "If 32 threads simultaneously issue heavy unbuffered `read()` syscalls on spinning disks or NVMe drives, disk head contention and queue saturation degrade throughput. The counting semaphore permits up to 8 threads to perform active disk I/O concurrently, while remaining threads process data in CPU memory."
3. **Q: What does your Amdahl's Law benchmark prove?**
   *A:* "Our benchmark demonstrated a 4.24x speedup on 4 threads and 7.93x on 16 threads. According to Amdahl's Law, this proves that over 98% of our code executes in parallel ($P > 0.98$), with less than 2% serialized execution."

---

### Team Member 2: File Systems & Memory Architecture Lead
- **Domain:** Memory Management (CO-4) & File Systems/I/O (CO-5)
- **Module Ownership:** `src/io/file_io.h`, `src/io/file_io.c`, `src/memory/arena.h`, `src/memory/arena.c`
- **Core Responsibilities:**
  - Implemented zero-copy memory-mapped file I/O (`mmap` / `MapViewOfFile`).
  - Designed the **Boundary-Safe Chunk Partitioning** algorithm to prevent record corruption.
  - Developed 4KB page-aligned Bump Arena Allocators to eliminate heap allocator lock contention.
  - Implemented telemetry for Resident Set Size (RSS), Working Set, and Page Faults (minor and major).

#### Evaluation Viva Questions & Model Answers:
1. **Q: How does your Boundary-Safe Chunking algorithm ensure no log line is cut in half?**
   *A:* "A naive division divides file size by thread count ($S / T$). But that byte offset almost always falls in the middle of a word. Our algorithm computes the nominal offset and then scans forward byte-by-byte until it finds the first newline (`\n`). The boundary is set to `newline + 1`. Thread $i-1$ stops at that exact byte and Thread $i$ starts there, guaranteeing zero duplicate lines and zero truncated tokens."
2. **Q: Why does Memory-Mapped I/O (`mmap`) outperform buffered `fread()`?**
   *A:* "Traditional `fread` copies data from the kernel page cache into a C-library stream buffer, and then into user buffers—requiring double memory copying and repeated system call context switches. `mmap` maps disk blocks directly into the process virtual address space. Address translations are handled in hardware by the MMU, resulting in a 56.4% reduction in kernel CPU time."
3. **Q: What is a Bump Allocator and why is it aligned to 4096 bytes?**
   *A:* "Standard `malloc()` uses a global heap lock. In multithreaded systems, thousands of allocations cause lock contention. A bump allocator simply increments a pointer in a contiguous pre-allocated buffer ($O(1)$ allocation). Aligning to 4096 bytes matches the virtual memory page size, ensuring optimal TLB cache utilization and preventing unaligned memory access penalties."

---

### Team Member 3: Systems Programming & Process Control Lead
- **Domain:** OS as Service Layer (CO-1), Process Control (CO-2), IPC & Signals (CO-3)
- **Module Ownership:** `src/process/supervisor.h`, `src/process/supervisor.c`, `src/ipc/ipc_channel.h`, `src/ipc/ipc_channel.c`
- **Core Responsibilities:**
  - Engineered the Process Supervisor and resource accounting state machine.
  - Segregated User-Space CPU execution time from Kernel-Space system call time using `GetProcessTimes` / `getrusage`.
  - Implemented CPU Core Affinity binding (`SetThreadAffinityMask` / `pthread_setaffinity_np`) to demonstrate user-level scheduling.
  - Built anonymous pipe channels for streaming structured `IPCPacket` telemetry.
  - Registered POSIX signal handlers (`SIGINT`, `SIGTERM`, `SIGBREAK`) for safe emergency shutdown.

#### Evaluation Viva Questions & Model Answers:
1. **Q: How does your system differentiate User CPU Time from Kernel CPU Time?**
   *A:* "When our program executes string matching or arithmetic, the processor runs in User Mode (Ring 3). When it invokes `read`, `mmap`, or `stat`, the CPU executes a software interrupt switching into Kernel Mode (Ring 0). Using `GetProcessTimes()` and `getrusage()`, our Process Supervisor accounts for CPU ticks spent in User Space vs Kernel Space separately."
2. **Q: What happens if a user presses Ctrl+C (`SIGINT`) while analyzing a 10GB file?**
   *A:* "Rather than terminating abruptly and corrupting open file handles or leaking mapped memory, our registered `SIGINT` signal handler intercepts the signal, flips a `sig_atomic_t` shutdown flag, safely halts all worker threads, flushes intermediate analytics to disk, unmaps virtual memory, and exits cleanly with exit code 0."
3. **Q: Why is thread CPU affinity beneficial in log analysis?**
   *A:* "Operating system schedulers frequently migrate threads between CPU cores, invalidating CPU L1 and L2 caches. By pinning worker thread $i$ to core $i$ via `SetThreadAffinityMask`, chunk memory buffers remain cached in the same core's local cache, boosting instruction throughput and reducing cache miss latency."

---

### Team Member 4: Threat Detection, Testing & Visualization Lead
- **Domain:** Threat Intelligence Engine, Test Suite, Live Demonstration Web UI
- **Module Ownership:** `src/analyzer/patterns.h`, `src/analyzer/analyzer.c`, `tools/generate_logs.py`, `dashboard/`, `presentation/`
- **Core Responsibilities:**
  - Engineered signature matchers for SQL Injection, XSS, Directory Traversal, Bot Probes, and Brute Force.
  - Authored the automated synthetic log generator supporting realistic multi-format logs.
  - Developed the automated 5-stage verification test suite (`scripts/run_tests.bat`).
  - Created the interactive real-time Web Dashboard with Chart.js analytics.
  - Built the live demonstration runner (`scripts/run_demo.bat`) and PowerPoint deck.

#### Evaluation Viva Questions & Model Answers:
1. **Q: What security threats does the MultiLog-OS analyzer identify?**
   *A:* "We detect 8 distinct security threat categories: SQL Injections (`UNION SELECT`, `' OR '1'='1`), Cross-Site Scripting (`<script>`, DOM onload handlers), Directory Traversal (`../../etc/passwd`, `win.ini`), Reconnaissance Bot Scans (`/wp-admin`, `/.env`, `/.git`), SSH Brute Force attacks, Privilege Escalations (`sudo: auth failure`), and HTTP 5xx / Kernel panic errors."
2. **Q: How did you test and validate that your multithreaded system is free of race conditions?**
   *A:* "In Test 2 of our automated validation suite, we analyze the exact same 50,000-line dataset using 1 thread, 4 threads, and 8 threads. An automated Python verification script verifies that the total line count (50,000), total error count, and total threat count match 100% across all runs. If a single race condition or chunk split occurred, the counts would diverge."
3. **Q: How does the live demonstration dashboard work?**
   *A:* "When the C engine finishes analysis, it exports a structured JSON telemetry file (`data/report.json`). The web dashboard reads this JSON and renders dynamic Chart.js visualizations: threat breakdown doughnuts, Amdahl's Law speedup curves, I/O mechanism comparisons, and an interactive searchable incident table."
