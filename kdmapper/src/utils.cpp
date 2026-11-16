#include "utils.hpp"
#include <sstream>
#include <ctime>
#include <cwchar>

// Debug logging implementation
namespace DebugLog {
	std::wofstream g_logFile;
	std::mutex g_logMutex;

	std::wstring GetLogPath()
	{
		wchar_t exePath[MAX_PATH] = {};
		GetModuleFileNameW(nullptr, exePath, MAX_PATH);
		std::wstring dir = exePath;
		size_t slash = dir.find_last_of(L'\\');
		if (slash != std::wstring::npos)
			dir.resize(slash);
		return dir + L"\\debug.txt";
	}

	void Initialize() {
		std::lock_guard<std::mutex> lock(g_logMutex);

		// Try exe dir first; if it can't be written (e.g. read-only share in the
		// VM), fall back to the %TEMP% folder so we never silently lose the log.
		std::wstring logPath = GetLogPath();
		g_logFile.open(logPath, std::ios::out | std::ios::trunc);
		if (!g_logFile.is_open()) {
			wchar_t tmp[MAX_PATH] = {};
			GetTempPathW(MAX_PATH, tmp);
			logPath = std::wstring(tmp) + L"debug.txt";
			g_logFile.open(logPath, std::ios::out | std::ios::trunc);
		}

		if (g_logFile.is_open()) {
			time_t now = time(nullptr);
			tm timeinfo;
			localtime_s(&timeinfo, &now);
			wchar_t timestamp[100];
			wcsftime(timestamp, sizeof(timestamp) / sizeof(wchar_t), L"%Y-%m-%d %H:%M:%S", &timeinfo);

			g_logFile << L"Mapper Debug Log\n";
			g_logFile << L"Started: " << timestamp << L"\n";
			g_logFile.flush();

			// Surface the log location on the console too, so it's findable.
			std::wcout << L"[+] Debug log: " << logPath << std::endl;
		}
		else {
			std::wcout << L"[-] Warning: could not create debug log file (" << logPath << L")\n";
		}
	}

	void Close() {
		std::lock_guard<std::mutex> lock(g_logMutex);
		if (g_logFile.is_open()) {
			g_logFile << L"Log closed\n";
			g_logFile.close();
		}
	}

	void Write(const std::wstring& message) {
		std::lock_guard<std::mutex> lock(g_logMutex);
		if (g_logFile.is_open()) {
			g_logFile << message;
			g_logFile.flush(); // Flush immediately so we don't lose data on crash
		}
	}
}

std::wstring utils::GetFullTempPath() {
	wchar_t temp_directory[MAX_PATH + 1] = { 0 };
	const uint32_t get_temp_path_ret = GetTempPathW(sizeof(temp_directory) / 2, temp_directory);
	if (!get_temp_path_ret || get_temp_path_ret > MAX_PATH + 1) {
		Log(L"[-] Failed to get temp path" << std::endl);
		return L"";
	}
	if (temp_directory[wcslen(temp_directory) - 1] == L'\\')
		temp_directory[wcslen(temp_directory) - 1] = 0x0;

	return std::wstring(temp_directory);
}

bool utils::ReadFileToMemory(const std::wstring& file_path, std::vector<uint8_t>* out_buffer) {
	std::ifstream file_ifstream(file_path, std::ios::binary);

	if (!file_ifstream) {
		Log(L"[-] Failed to open file: " << file_path << std::endl);
		Log(L"[-] Error: File may not exist or is inaccessible" << std::endl);
		return false;
	}

	out_buffer->assign((std::istreambuf_iterator<char>(file_ifstream)), std::istreambuf_iterator<char>());
	file_ifstream.close();

	if (out_buffer->empty()) {
		Log(L"[-] File was opened but is empty: " << file_path << std::endl);
		return false;
	}

	return true;
}

bool utils::CreateFileFromMemory(const std::wstring& desired_file_path, const char* address, size_t size) {
	std::ofstream file_ofstream(desired_file_path.c_str(), std::ios_base::out | std::ios_base::binary);

	if (!file_ofstream.write(address, size)) {
		file_ofstream.close();
		return false;
	}

	file_ofstream.close();
	return true;
}

uint64_t utils::GetKernelModuleAddress(const std::string& module_name) {
	void* buffer = nullptr;
	DWORD buffer_size = 0;

	NTSTATUS status = NtQuerySystemInformation(static_cast<SYSTEM_INFORMATION_CLASS>(nt::SystemModuleInformation), buffer, buffer_size, &buffer_size);

	while (status == nt::STATUS_INFO_LENGTH_MISMATCH) {
		if (buffer != nullptr)
			VirtualFree(buffer, 0, MEM_RELEASE);

		buffer = VirtualAlloc(nullptr, buffer_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		status = NtQuerySystemInformation(static_cast<SYSTEM_INFORMATION_CLASS>(nt::SystemModuleInformation), buffer, buffer_size, &buffer_size);
	}

	if (!NT_SUCCESS(status)) {
		if (buffer != nullptr)
			VirtualFree(buffer, 0, MEM_RELEASE);
		return 0;
	}

	const auto modules = static_cast<nt::PRTL_PROCESS_MODULES>(buffer);
	if (!modules)
		return 0;

	for (auto i = 0u; i < modules->NumberOfModules; ++i) {
		const std::string current_module_name = std::string(reinterpret_cast<char*>(modules->Modules[i].FullPathName) + modules->Modules[i].OffsetToFileName);

		if (!_stricmp(current_module_name.c_str(), module_name.c_str()))
		{
			const uint64_t result = reinterpret_cast<uint64_t>(modules->Modules[i].ImageBase);

			VirtualFree(buffer, 0, MEM_RELEASE);
			return result;
		}
	}

	VirtualFree(buffer, 0, MEM_RELEASE);
	return 0;
}

BOOLEAN utils::bDataCompare(const BYTE* pData, const BYTE* bMask, const char* szMask) {
	for (; *szMask; ++szMask, ++pData, ++bMask)
		if (*szMask == 'x' && *pData != *bMask)
			return 0;
	return (*szMask) == 0;
}

uintptr_t utils::FindPattern(uintptr_t dwAddress, uintptr_t dwLen, BYTE* bMask, const char* szMask) {
	size_t max_len = dwLen - strlen(szMask);
	for (uintptr_t i = 0; i < max_len; i++)
		if (bDataCompare((BYTE*)(dwAddress + i), bMask, szMask))
			return (uintptr_t)(dwAddress + i);
	return 0;
}

PVOID utils::FindSection(const char* sectionName, uintptr_t modulePtr, PULONG size) {
	size_t namelength = strlen(sectionName);
	PIMAGE_NT_HEADERS headers = (PIMAGE_NT_HEADERS)(modulePtr + ((PIMAGE_DOS_HEADER)modulePtr)->e_lfanew);
	PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(headers);
	for (DWORD i = 0; i < headers->FileHeader.NumberOfSections; ++i) {
		PIMAGE_SECTION_HEADER section = &sections[i];
		if (memcmp(section->Name, sectionName, namelength) == 0 &&
			namelength == strlen((char*)section->Name)) {
			if (!section->VirtualAddress) {
				return 0;
			}
			if (size) {
				*size = section->Misc.VirtualSize;
			}
			return (PVOID)(modulePtr + section->VirtualAddress);
		}
	}
	return 0;
}