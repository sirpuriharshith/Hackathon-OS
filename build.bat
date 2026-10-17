@echo off
REM ====================================================================
REM MultiLog-OS: Windows Build Script using MinGW-W64 GCC
REM ====================================================================

echo [*] Cleaning previous build artifacts...
if not exist bin mkdir bin
if not exist data mkdir data

echo [*] Compiling MultiLog-OS source files...
gcc -O3 -Wall -Wextra -std=c11 ^
    src/core/types.c ^
    src/memory/arena.c ^
    src/io/file_io.c ^
    src/analyzer/analyzer.c ^
    src/concurrency/thread_pool.c ^
    src/ipc/ipc_channel.c ^
    src/process/supervisor.c ^
    src/report/reporter.c ^
    src/cli/main.c ^
    -o bin/multilog.exe ^
    -lpsapi -lpthread

if %ERRORLEVEL% EQU 0 (
    echo [SUCCESS] MultiLog-OS binary built successfully: bin\multilog.exe
) else (
    echo [ERROR] Build failed! Check compiler error messages above.
    exit /b %ERRORLEVEL%
)
