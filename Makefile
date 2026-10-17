# MultiLog-OS Makefile
# High-Performance Multithreaded Log Analysis & Threat Detection System

CC ?= gcc
CFLAGS ?= -O3 -Wall -Wextra -std=c11 -pthread
INCLUDES = -Isrc
TARGET = bin/multilog

ifeq ($(OS),Windows_NT)
    LIBS = -lpsapi -lpthread
    TARGET = bin/multilog.exe
    MKDIR = if not exist bin mkdir bin
    RM = del /q /f
else
    LIBS = -lpthread -lrt
    MKDIR = mkdir -p bin
    RM = rm -rf
endif

SRCS = src/core/types.c \
       src/memory/arena.c \
       src/io/file_io.c \
       src/analyzer/analyzer.c \
       src/concurrency/thread_pool.c \
       src/ipc/ipc_channel.c \
       src/process/supervisor.c \
       src/report/reporter.c \
       src/cli/main.c

all: $(TARGET)

$(TARGET): $(SRCS)
	$(MKDIR)
	$(CC) $(CFLAGS) $(INCLUDES) $(SRCS) -o $(TARGET) $(LIBS)

clean:
	$(RM) bin/*

.PHONY: all clean
