#ifndef KDLIBMODE

#include <Windows.h>
#include <string>
#include <vector>
#include <filesystem>
#include <iostream>
#include <thread>
#include <chrono>
#include <ios>
#include <iomanip>
#include <Lmcons.h>
#include <sstream>

#include "kdmapper.hpp"
#include "utils.hpp"
#include <sstream>
//#include "VMProtectSDK.h"

HANDLE cormem_device_handle;

LONG WINAPI SimplestCrashHandler(EXCEPTION_POINTERS* ExceptionInfo)
{
	if (ExceptionInfo && ExceptionInfo->ExceptionRecord)
		Log(L"[!!] Crash at addr 0x" << ExceptionInfo->ExceptionRecord->ExceptionAddress << L" by 0x" << std::hex << ExceptionInfo->ExceptionRecord->ExceptionCode << std::endl);
	else
		Log(L"[!!] Crash" << std::endl);

	if (cormem_device_handle)
		cormem_driver::Unload(cormem_device_handle);

	return EXCEPTION_EXECUTE_HANDLER;
}

int paramExists(const int argc, wchar_t** argv, const wchar_t* param) {
	size_t plen = wcslen(param);
	for (int i = 1; i < argc; i++) {
		if (wcslen(argv[i]) == plen + 1ull && _wcsicmp(&argv[i][1], param) == 0 && argv[i][0] == '/') { // with slash
			return i;
		}
		else if (wcslen(argv[i]) == plen + 2ull && _wcsicmp(&argv[i][2], param) == 0 && argv[i][0] == '-' && argv[i][1] == '-') { // with double dash
			return i;
		}
	}
	return -1;
}

void help() {
	Log(L"\r\n\r\n[!] Incorrect Usage!" << std::endl);
	Log(L"[+] Usage: map-workspace.exe driver.sys" << std::endl);
}

bool callbackExample(ULONG64* param1, ULONG64* param2, ULONG64 allocationPtr, ULONG64 allocationSize) {
	UNREFERENCED_PARAMETER(param1);
	UNREFERENCED_PARAMETER(param2);
	UNREFERENCED_PARAMETER(allocationPtr);
	UNREFERENCED_PARAMETER(allocationSize);
	Log("[+] Callback example called" << std::endl);
	return true;
}

DWORD getParentProcess()
{
	HANDLE hSnapshot;
	PROCESSENTRY32 pe32;
	DWORD ppid = 0, pid = GetCurrentProcessId();

	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	__try {
		if (hSnapshot == INVALID_HANDLE_VALUE) __leave;

		ZeroMemory(&pe32, sizeof(pe32));
		pe32.dwSize = sizeof(pe32);
		if (!Process32First(hSnapshot, &pe32)) __leave;

		do {
			if (pe32.th32ProcessID == pid) {
				ppid = pe32.th32ParentProcessID;
				break;
			}
		} while (Process32Next(hSnapshot, &pe32));

	}
	__finally {
		if (hSnapshot != INVALID_HANDLE_VALUE) CloseHandle(hSnapshot);
	}
	return ppid;
}

//Help people that don't understand how to open a console
void PauseIfParentIsExplorer() {
	DWORD explorerPid = 0;
	GetWindowThreadProcessId(GetShellWindow(), &explorerPid);
	DWORD parentPid = getParentProcess();
	if (parentPid == explorerPid) {
		Log(L"[+] Pausing to allow for debugging" << std::endl);
		Log(L"[+] Press enter to close" << std::endl);
		std::cin.get();
	}
}

void enableANSIColors() {
	HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
	DWORD dwMode = 0;

	if (hOut != INVALID_HANDLE_VALUE && GetConsoleMode(hOut, &dwMode)) {
		SetConsoleMode(hOut, dwMode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
	}
}


static const char* GetExeDisplayName() {
	return "@humbleness mapper";
}

static std::atomic<bool> g_running{ true };
static std::string g_baseTitle;            

void UpdateTitleThread() {
	while (g_running) {
		SYSTEMTIME st;
		GetLocalTime(&st);

		char timestr[16];
		snprintf(timestr, sizeof(timestr), "%02d:%02d:%02d",
			st.wHour, st.wMinute, st.wSecond);

		char title[512];
		snprintf(title, sizeof(title), "%s%s", g_baseTitle.c_str(), timestr);

		SetConsoleTitleA(title);

		std::this_thread::sleep_for(std::chrono::seconds(1));
	}
}

int console_init() {
	enableANSIColors();

	HWND hwnd = GetConsoleWindow();
	ShowWindow(hwnd, SW_SHOW);

	CONSOLE_FONT_INFOEX cfi{};
	cfi.cbSize = sizeof(cfi);
	cfi.nFont = 0;
	cfi.dwFontSize.Y = 12;
	cfi.FontFamily = FF_DONTCARE;
	cfi.FontWeight = FW_NORMAL;
	wcscpy_s(cfi.FaceName, L"Consolas");
	SetCurrentConsoleFontEx(GetStdHandle(STD_OUTPUT_HANDLE), FALSE, &cfi);

	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED | FOREGROUND_GREEN);

	SetWindowLong(hwnd, GWL_EXSTYLE, GetWindowLong(hwnd, GWL_EXSTYLE) | WS_EX_LAYERED);
	//SetLayeredWindowAttributes(hwnd, 0, 200, LWA_ALPHA); 
	//this sets the opacity of the console, 255 is fully opaque, 0 is fully transparent

	char username[UNLEN + 1] = { 0 };
	DWORD usernameLen = UNLEN + 1;
	if (!GetUserNameA(username, &usernameLen)) {
		strcpy_s(username, sizeof(username), "Unknown");
	}

	char base[256];
	snprintf(base, sizeof(base), "%s | %s | ", GetExeDisplayName(), username);
	g_baseTitle = base;

	std::thread(UpdateTitleThread).detach();

	SYSTEMTIME st_init;
	GetLocalTime(&st_init);
	char timestr_init[16];
	snprintf(timestr_init, sizeof(timestr_init), "%02d:%02d:%02d",
		st_init.wHour, st_init.wMinute, st_init.wSecond);
	char title_init[512];
	snprintf(title_init, sizeof(title_init), "%s%s", g_baseTitle.c_str(), timestr_init);
	SetConsoleTitleA(title_init);
}

int wmain(const int argc, wchar_t** argv) {
	DebugLog::Initialize();

	console_init();
//	system("winver");
//	std::cin.get(); // wait for user input before continuing, this allows the user to see the initial console output and set up any necessary hooks before the program continues
	SetUnhandledExceptionFilter(SimplestCrashHandler);

	bool passAllocationPtr = paramExists(argc, argv, L"PassAllocationPtr") > 0;

	int drvIndex = -1;
	for (int i = 1; i < argc; i++) {
		if (std::filesystem::path(argv[i]).extension().string().compare(".sys") == 0) {
			drvIndex = i;
			break;
		}
	}

	if (drvIndex <= 0) {
		help();
		DebugLog::Close();
		std::cin.get();
		return -1;
	}

	const std::wstring driver_path = argv[drvIndex];

	Log(L"[*] Driver path from command line: " << driver_path << std::endl);

	if (!std::filesystem::exists(driver_path)) {
		Log(L"[-] file " << driver_path << L" doesn't exist" << std::endl);
		PauseIfParentIsExplorer();
		DebugLog::Close();
		std::cin.get();
		return -1;
	}

	// Get absolute path for clarity
	std::wstring absolute_path = std::filesystem::absolute(driver_path).wstring();
	Log(L"[*] Absolute path: " << absolute_path << std::endl);

	// Check file size
	try {
		auto file_size = std::filesystem::file_size(driver_path);
		Log(L"[*] File size from filesystem: " << file_size << L" bytes" << std::endl);
	} catch (const std::exception& e) {
		Log(L"[-] Error getting file size: " << e.what() << std::endl);
	}

	cormem_device_handle = cormem_driver::Load();

	if (cormem_device_handle == INVALID_HANDLE_VALUE) {
		PauseIfParentIsExplorer();
		DebugLog::Close();
		std::cin.get();
		return -1;
	}

	std::vector<uint8_t> raw_image = { 0 };
	if (!utils::ReadFileToMemory(driver_path, &raw_image)) {
		Log(L"[-] failed to read image to memory" << std::endl);
		cormem_driver::Unload(cormem_device_handle);
		PauseIfParentIsExplorer();
		DebugLog::Close();
		std::cin.get();
		return -1;
	}

	Log(L"[+] Driver file size: " << raw_image.size() << L" bytes" << std::endl);

	// Check if file was actually read
	if (raw_image.size() < sizeof(IMAGE_DOS_HEADER)) {
		Log(L"[-] Driver file too small (less than DOS header size)" << std::endl);
		cormem_driver::Unload(cormem_device_handle);
		PauseIfParentIsExplorer();
		DebugLog::Close();
		std::cin.get();
		return -1;
	}

	// Display first few bytes for debugging
	Log(L"[+] First 4 bytes: 0x" << std::hex << std::setfill(L'0')
		<< std::setw(2) << (unsigned int)raw_image[0]
		<< std::setw(2) << (unsigned int)raw_image[1]
		<< std::setw(2) << (unsigned int)raw_image[2]
		<< std::setw(2) << (unsigned int)raw_image[3] << std::dec << std::endl);

	// AllocateIndependentPages gives RWX kernel memory (NonPagedPool is NX on Win11 24H2+/25H2
	// and executing a manual-mapped image there causes a bugcheck).
	kdmapper::AllocationMode mode = kdmapper::AllocationMode::AllocateIndependentPages;

	NTSTATUS exitCode = 0;
	// IMPORTANT: never free the mapped driver's memory after DriverEntry returns -
	// the driver keeps running from that pool and freeing it causes a BSOD.
	if (!kdmapper::MapDriver(cormem_device_handle, raw_image.data(), 0, 0, false, true, mode, passAllocationPtr, callbackExample, &exitCode)) {
		Log(L"[-] failed to map " << driver_path << std::endl);
		cormem_driver::Unload(cormem_device_handle);
		PauseIfParentIsExplorer();
		DebugLog::Close();
		std::cin.get();
		return -1;
	}

	if (!cormem_driver::Unload(cormem_device_handle)) {
		Log(L"[-] failed to unload vul drv " << std::endl);
		PauseIfParentIsExplorer();
	}
	Log(L"[+] success" << std::endl);

	// The mapped driver created \Device\WinKnlHook + \??\WinKnlHook in its own
	// DriverEntry (via IoCreateDriver). Verify UM's entry point (\\\\.\\WinKnlHook)
	// is actually reachable now - if not, map WinKnlHook.sys (mapping Cormem.sys
	// only creates \\\\.\\CORMEM, which UM does not talk to).
	{
		// probe a few candidate device paths used by target drivers mapped this way
		HANDLE probe = CreateFileW(L"\\\\.\\WinKnlHook", GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
		if (probe != INVALID_HANDLE_VALUE) {
			Log(L"[+] \\\\.\\WinKnlHook is reachable - UM client can connect." << std::endl);
			CloseHandle(probe);
		}
		else {
			DWORD pmErr = GetLastError();
			Log(L"[-] \\\\.\\WinKnlHook NOT reachable (error " << pmErr << L")" << std::endl);
		}
	}

	DebugLog::Close();
	std::cin.get();
}

#endif