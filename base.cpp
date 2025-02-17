#include "base.h"

char* WCHARtoCHAR(const WCHAR* wstr)
{
    // 初步计算转换后的char字符串所需的最大字节数
// 这里我们假设使用系统的默认代码页进行转换
    int len = WideCharToMultiByte(CP_ACP, 0, wstr, -1, NULL, 0, NULL, NULL);

    // 为转换后的字符串分配内存（包含空字符）
    char* str = (char*)malloc(len * sizeof(char));
    if (str == NULL) {
        // 内存分配失败，返回NULL
        return NULL;
    }

    // 执行实际的转换操作
    WideCharToMultiByte(CP_ACP, 0, wstr, -1, str, len, NULL, NULL);

    // 返回转换后的字符串
    return str;
}

WCHAR* CHARtoWCHAR(const char* str)
{
	return nullptr;
}

void intToString(int value, char* buffer, size_t bufferSize)
{
	snprintf(buffer, bufferSize, "%d", value);
}
