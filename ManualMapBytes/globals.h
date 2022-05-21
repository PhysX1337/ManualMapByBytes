#pragma once
#include <Windows.h>
#include <iostream>
#include <winternl.h>
#include <fstream>
#include <TlHelp32.h>
#include "nt.h"

using pLoadLibraryA = HMODULE(WINAPI*)(const char* libraryname);
using pGetProcAddress = uintptr_t(WINAPI*)(HMODULE mod, const char* funtionname);
using pDLLEntry = BOOL(WINAPI*)(void* mod, DWORD reason, LPVOID reserved);

struct InJectionData {
	pLoadLibraryA LoadLibraryA;
	pGetProcAddress GetProcAddress;
	HMODULE DLL;
};
void __stdcall ShellCodeFunction(InJectionData* pData);
class ManualMapper 
{
private:
	int meModuleCount = 0;
	DWORD mePid = 0;
	uintptr_t meBase = 0;
	HANDLE meHandle = nullptr;
	const char* meDllpath = nullptr;
	PVOID meDllCopy = nullptr;
	DWORD meDllsize = 0;
	DWORD meTotalAllocationSize = 0;

	_NtOpenProcess NtOpenProcess;
	_NtReadVirtualMemory NtReadVirtualMemory;
	_NtQueryVirtualMemory  NtQueryVirtualMemory;
	_NtWriteVirtualMemory NtWriteVirtualMemory;
	_NtProtectVirtualMemory NtProtectVirtualMemory;
	_NtAllocateVirtualMemory NtAllocateVirtualMemory;
	_NtCreateThreadEx NtCreateThreadEx;

	DWORD get_pid(const char* exename);
	uintptr_t get_base(const char* modname, DWORD pid);
	HANDLE get_handle(DWORD pid);
	LIST_ENTRY get_module_list();
	uintptr_t allocation_base(LIST_ENTRY list);

public:
	ManualMapper();
	void setup(const char* exename, const char* modulename);
	void load_dll();
	void inject_dll();
};

template <typename ...Args>
void meSuccess(const char* message, Args... arguments) {
	char Buffer[0x512];
	RtlSecureZeroMemory(Buffer, sizeof(Buffer));
	strncpy(Buffer, "[+] ", sizeof(Buffer));
	strncat(Buffer, message, sizeof(Buffer));
	strncat(Buffer, "\n", sizeof(Buffer));
	printf(Buffer, arguments...);
}

template <typename ...Args>
void meError(const char* message, Args... arguments) {
	char Buffer[0x512];
	RtlSecureZeroMemory(Buffer, sizeof(Buffer));
	strncpy(Buffer, "[-] ", sizeof(Buffer));
	strncat(Buffer, message, sizeof(Buffer));
	strncat(Buffer, "\n", sizeof(Buffer));
	printf(Buffer, arguments...);
	system("pause");
	exit(-1);
}