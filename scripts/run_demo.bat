@echo off
REM ====================================================================
REM MultiLog-OS: Live Evaluation Demonstration Script (Deliverable 4)
REM ====================================================================

title MultiLog-OS Live Evaluation Demo
color 0b

:MENU
cls
echo ======================================================================
echo    MultiLog-OS: MULTITHREADED LOG ANALYSIS - LIVE EVALUATION DEMO     
echo             Operating Systems Project (Syllabus: CO-1 to CO-6)        
echo ======================================================================
echo.
echo Select Demonstration Scenario:
echo   [1] Quick Live Demo (Analyze 50,000 logs with 4 threads + Web UI)
echo   [2] High-Throughput Stress Test (100,000 logs with 8 threads)
echo   [3] Multithreaded Scalability Benchmark (Amdahl's Law 1-16 Threads)
echo   [4] File I/O Engine Face-Off (mmap vs direct syscall vs buffered)
echo   [5] Inspect OS Virtual Memory Address Space & Page Tables (CO-4)
echo   [6] Open Interactive Web Analytics Dashboard in Browser
echo   [7] Run Automated Validation Test Suite (5/5 Verification Tests)
echo   [8] Exit
echo.
set /p choice="Enter option [1-8]: "

if "%choice%"=="1" goto DEMO_QUICK
if "%choice%"=="2" goto DEMO_STRESS
if "%choice%"=="3" goto DEMO_BENCH
if "%choice%"=="4" goto DEMO_IO
if "%choice%"=="5" goto DEMO_MEM
if "%choice%"=="6" goto OPEN_DASH
if "%choice%"=="7" goto RUN_TESTS
if "%choice%"=="8" goto EXIT

echo [!] Invalid selection. Please try again.
pause
goto MENU

:DEMO_QUICK
cls
echo [*] Scenario 1: Quick Live Analysis Demo (50,000 Records, 4 POSIX Threads)
echo.
if not exist data\test_50k.log (
    echo [*] Generating 50,000 sample log records...
    python tools\generate_logs.py --lines 50000 --out data\test_50k.log
)
bin\multilog.exe --file data\test_50k.log --threads 4 --io mmap --json data\report.json --html data\report.html --csv data\alerts.csv
echo.
echo [*] Launching Web Analytics Dashboard in default browser...
start dashboard\index.html
echo.
pause
goto MENU

:DEMO_STRESS
cls
echo [*] Scenario 2: High-Throughput Analysis (100,000 Records, 8 POSIX Threads)
echo.
if not exist data\test_100k.log (
    echo [*] Generating 100,000 synthetic logs...
    python tools\generate_logs.py --lines 100000 --out data\test_100k.log
)
bin\multilog.exe --file data\test_100k.log --threads 8 --io mmap --json data\report.json --html data\report.html
echo.
pause
goto MENU

:DEMO_BENCH
cls
echo [*] Scenario 3: Multithreaded Scalability Benchmark (Amdahl's Law)
echo.
bin\multilog.exe --file data\test_50k.log --benchmark
echo.
pause
goto MENU

:DEMO_IO
cls
echo [*] Scenario 4: File I/O Strategy Benchmark (CO-5)
echo.
bin\multilog.exe --file data\test_50k.log --compare-io
echo.
pause
goto MENU

:DEMO_MEM
cls
echo [*] Scenario 5: OS Virtual Memory Layout & Page Tables (CO-4)
echo.
bin\multilog.exe --memory-layout
echo.
pause
goto MENU

:OPEN_DASH
cls
echo [*] Opening Web Analytics Dashboard...
start dashboard\index.html
goto MENU

:RUN_TESTS
cls
call scripts\run_tests.bat
echo.
pause
goto MENU

:EXIT
echo [*] Exiting MultiLog-OS Demo. Good luck with the Hackathon presentation!
exit /b 0
