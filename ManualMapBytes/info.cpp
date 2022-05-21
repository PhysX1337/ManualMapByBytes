#include "globals.h"

ManualMapper::ManualMapper() {
	NtOpenProcess = reinterpret_cast<_NtOpenProcess>(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtOpenProcess"));
	NtReadVirtualMemory = reinterpret_cast<_NtReadVirtualMemory>(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtReadVirtualMemory"));
    NtQueryVirtualMemory = reinterpret_cast<_NtQueryVirtualMemory>(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryVirtualMemory"));
	NtWriteVirtualMemory = reinterpret_cast<_NtWriteVirtualMemory>(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtWriteVirtualMemory"));
	NtProtectVirtualMemory = reinterpret_cast<_NtProtectVirtualMemory>(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtProtectVirtualMemory"));
	NtAllocateVirtualMemory = reinterpret_cast<_NtAllocateVirtualMemory>(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtAllocateVirtualMemory"));
	NtCreateThreadEx = reinterpret_cast<_NtCreateThreadEx>(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateThreadEx"));
}

DWORD ManualMapper::get_pid(const char* exename) {
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnap == INVALID_HANDLE_VALUE) {
		meError("Failed opening Snapshot! 0x%x", GetLastError());
	}

	PROCESSENTRY32 pe32{0};
	pe32.dwSize = sizeof(pe32);

	BOOL status = Process32First(hSnap, &pe32);
	while (status) {
		if (!strcmp(pe32.szExeFile, exename)) {
			CloseHandle(hSnap);
			return pe32.th32ProcessID;
		}
		status = Process32Next(hSnap, &pe32);
	}
	CloseHandle(hSnap);
	return 0;
}
uintptr_t ManualMapper::get_base(const char* modname, DWORD pid) {
	uintptr_t base_buffer = 0;
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
	if (hSnap == INVALID_HANDLE_VALUE) {
		meError("Failed opening Snapshot! 0x%x", GetLastError());
	}

	MODULEENTRY32 me32{ 0 };
	me32.dwSize = sizeof(me32);

	BOOL status = Module32First(hSnap, &me32);
	while (status) {
		if (!strcmp(me32.szModule, modname)) {
			base_buffer = (uintptr_t)me32.modBaseAddr;
		}
		this->meModuleCount++;
		status = Module32Next(hSnap, &me32);
	}
	CloseHandle(hSnap);
	return base_buffer;
}
HANDLE ManualMapper::get_handle(DWORD pid) {
	HANDLE to_return = nullptr;
	OBJECT_ATTRIBUTES oa;
	InitializeObjectAttributes(&oa, 0, 0, 0, 0);
	CLIENT_ID cid = { (HANDLE)pid, 0 };
	NtOpenProcess(&to_return, PROCESS_ALL_ACCESS, &oa, &cid);
	return to_return;
}

void ManualMapper::setup(const char* exename, const char* modulename) {
	mePid = this->get_pid(exename);
	if (!mePid)
		meError("Didn't find process!");

	meBase = this->get_base(modulename, mePid);
	if (!meBase)
		meError("Error getting base_address");

	meHandle = this->get_handle(mePid);
	if (meHandle == INVALID_HANDLE_VALUE)
		meError("Error retrieving handle to target process");

	meSuccess("Opened handle 0x%x to %s (0x%x, %i) -> 0x%p", meHandle, exename, mePid ,mePid, meBase);
	meSuccess("Found %i Modules", meModuleCount);
}