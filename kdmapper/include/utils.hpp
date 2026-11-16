#pragma once

#include <Windows.h>
#include <TlHelp32.h>
#include <stdint.h>
#include <vector>
#include <string>
#include <iostream>
#include <fstream>
#include <sstream>
#include <mutex>

#include "nt.hpp"

// Debug file logging
namespace DebugLog {
	extern std::wofstream g_logFile;
	extern std::mutex g_logMutex;
	void Initialize();
	void Close();
	void Write(const std::wstring& message);
	std::wstring GetLogPath();
}

#if defined(DISABLE_OUTPUT)
	#define Log(content) 
#else
	#define Log(content) do { \
		std::wstringstream _log_ss; \
		_log_ss << content; \
		std::wcout << _log_ss.str(); \
		DebugLog::Write(_log_ss.str()); \
	} while(0)
#endif

namespace utils
{
	std::wstring GetFullTempPath();
	bool ReadFileToMemory(const std::wstring& file_path, std::vector<uint8_t>* out_buffer);
	bool CreateFileFromMemory(const std::wstring& desired_file_path, const char* address, size_t size);
	uint64_t GetKernelModuleAddress(const std::string& module_name);
	BOOLEAN bDataCompare(const BYTE* pData, const BYTE* bMask, const char* szMask);
	uintptr_t FindPattern(uintptr_t dwAddress, uintptr_t dwLen, BYTE* bMask, const char* szMask);
	PVOID FindSection(const char* sectionName, uintptr_t modulePtr, PULONG size);
}