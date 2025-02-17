#pragma once
#ifndef BASE_H
#define BASE_H

#include <winsock2.h>
#include <windows.h>
#include <winhttp.h>
#include <ws2tcpip.h>
#include <tlhelp32.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <random>
#include <iphlpapi.h>
#include <winternl.h>


// 类型定义
typedef uintptr_t(*pInit)(uintptr_t);

// 字符转换函数
char* WCHARtoCHAR(const WCHAR* wstr);
WCHAR* CHARtoWCHAR(const char* str);

// 工具函数
void intToString(int value, char* buffer, size_t bufferSize);

// 调试宏
#ifdef DEBUG
#define DEBUG_PRINT(fmt, ...) printf("[DEBUG] " fmt, ##__VA_ARGS__)
#else
#define DEBUG_PRINT(fmt, ...)
#endif

// 安全释放宏
#define SAFE_FREE(p) { if(p) { free(p); (p) = NULL; } }

// 网络相关常量
#define MAX_BUFFER_SIZE 4096
#define DEFAULT_TIMEOUT 5000

// 错误处理
#define CHECK_HANDLE(h, msg) \
    if (!(h)) { \
        fprintf(stderr, "%s (Error: %d)\n", msg, GetLastError()); \
        exit(EXIT_FAILURE); \
    }

#endif // BASE_H