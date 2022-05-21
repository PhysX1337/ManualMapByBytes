#include "globals.h"


void ManualMapper::inject_dll() {
	LIST_ENTRY module_list = this->get_module_list();
	uintptr_t allocation_address = 0;
#ifdef _WIN64
	allocation_address = this->allocation_base(module_list);
#else
	allocation_address = this->allocation_base(module_list);
#endif
	if (!allocation_address)
		meError("Didnt find space to allocate dll");
	PVOID addy = (PVOID)allocation_address;
	SIZE_T size = meTotalAllocationSize;
	NtAllocateVirtualMemory(meHandle, &addy, 0, &size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	InJectionData data;
	data.LoadLibraryA = LoadLibraryA;
	data.GetProcAddress = reinterpret_cast<pGetProcAddress>(GetProcAddress);

	PIMAGE_NT_HEADERS meDllNT = (PIMAGE_NT_HEADERS)((BYTE*)meDllCopy + ((PIMAGE_DOS_HEADER)meDllCopy)->e_lfanew);
	PIMAGE_SECTION_HEADER cSectionHeader = IMAGE_FIRST_SECTION(meDllNT);
	uintptr_t last = 0;
	uintptr_t last_size = 0;
	for (int i = 0; i < meDllNT->FileHeader.NumberOfSections; ++i, ++cSectionHeader) {
		if (cSectionHeader->SizeOfRawData) {
			if (!NtWriteVirtualMemory(meHandle, (char*)allocation_address + cSectionHeader->VirtualAddress, (BYTE*)meDllCopy + cSectionHeader->PointerToRawData, cSectionHeader->SizeOfRawData, 0)) {
				meSuccess("Wrote %i section to %p", i, allocation_address + cSectionHeader->VirtualAddress);
			}
			else
				meError("Failed writing %i section to %p", i, allocation_address + cSectionHeader->VirtualAddress);
			last = allocation_address + cSectionHeader->VirtualAddress;
			last_size = cSectionHeader->SizeOfRawData;
		}
	}

	memcpy(meDllCopy, &data, sizeof(data));
	NtWriteVirtualMemory(meHandle, (PVOID)(allocation_address), (BYTE*)meDllCopy , 0x1000, 0);

	NtWriteVirtualMemory(meHandle, (PVOID)(last + last_size + 0x1000), ShellCodeFunction, 0x1000, 0);
	HANDLE remote_handle;
	OBJECT_ATTRIBUTES oab;
	InitializeObjectAttributes(&oab, 0, 0, 0, 0);
	NtCreateThreadEx(&remote_handle, THREAD_ALL_ACCESS, &oab, meHandle, (LPTHREAD_START_ROUTINE)(last + last_size + 0x1000), (void*)allocation_address, 0, 0, 0, 0, 0);

	if (WaitForSingleObject(remote_handle, INFINITE) == WAIT_FAILED) {
		printf("[+] Waiting for thread...\n");
	}
	if (remote_handle != INVALID_HANDLE_VALUE)
		meSuccess("Created thread!");
	VirtualFreeEx(meHandle, (LPVOID)(last + last_size + 0x1000), 1, MEM_FREE);
	delete[]meDllCopy;
	CloseHandle(meHandle);
}

LIST_ENTRY ManualMapper::get_module_list() {
	PROCESS_BASIC_INFORMATION pI;
	NtQueryInformationProcess(meHandle, ProcessBasicInformation, &pI, sizeof(pI), 0);

	if (!pI.PebBaseAddress)
		meError("Didn't find peb!");
	meSuccess("Peb at: 0x%p", pI.PebBaseAddress);

	PEB peb;
	NtReadVirtualMemory(meHandle, pI.PebBaseAddress, &peb, sizeof(peb), 0);
	RPEB_LDR_DATA ldr;
	NtReadVirtualMemory(meHandle, peb.Ldr, &ldr, sizeof(ldr), 0);
	LIST_ENTRY list = ldr.InLoadOrderModuleList;
	return list;
}

uintptr_t ManualMapper::allocation_base(LIST_ENTRY list) {
	DWORD size_of_dll = meDllsize;
	DWORD additional_buffer = 0x4000;
	DWORD size_of_imports = 0x0;

	PIMAGE_NT_HEADERS meDllNT = (PIMAGE_NT_HEADERS)((BYTE*)meDllCopy + ((PIMAGE_DOS_HEADER)meDllCopy)->e_lfanew);
	PIMAGE_SECTION_HEADER cSectionHeader = IMAGE_FIRST_SECTION(meDllNT);
	for (int i = 0; i < meDllNT->FileHeader.NumberOfSections; ++i, ++cSectionHeader) {
		if (cSectionHeader->SizeOfRawData) {
			size_of_imports += cSectionHeader->SizeOfRawData;
		}
	}

	meTotalAllocationSize = additional_buffer + size_of_imports + meDllsize;
	meSuccess("Need to allocate: %x bytes", meTotalAllocationSize);



	LIST_ENTRY begin = list;
	PLIST_ENTRY current = list.Flink;
	rLDR_DATA_TABLE_ENTRY meModule;
	for (int i = 0; i < meModuleCount - 1; i++) {
		
		NtReadVirtualMemory(meHandle, begin.Flink, &current, sizeof(current), 0);
		NtReadVirtualMemory(meHandle, current, &begin.Flink, sizeof(begin.Flink), 0);
		
		NtReadVirtualMemory(meHandle, current, &meModule, sizeof(meModule), 0);

		IMAGE_DOS_HEADER dos;
		NtReadVirtualMemory(meHandle, meModule.DllBase, &dos, sizeof(dos), 0);
		IMAGE_NT_HEADERS nt;
		NtReadVirtualMemory(meHandle, (LPVOID)((uintptr_t)meModule.DllBase +dos.e_lfanew), &nt, sizeof(nt), 0);

		uintptr_t start = (uintptr_t)meModule.DllBase;
		DWORD size = nt.OptionalHeader.SizeOfImage;
		uintptr_t end = start + size;
		uintptr_t place_to_allocate = end;

		DWORD skippedaddys = 0;
		uintptr_t max = end + 0x100000;
		while (place_to_allocate % 0x10000 != 0 && place_to_allocate < max) {
			place_to_allocate += 0x1000;
			skippedaddys += 0x1000;
		}
		if (place_to_allocate % 0x10000 != 0)
			continue;
			

		MEMORY_BASIC_INFORMATION mbi;
		NtQueryVirtualMemory(meHandle, (PVOID)place_to_allocate, MemoryBasicInformation, &mbi, sizeof(mbi), 0);
		if (mbi.AllocationBase)
			continue;
		NtQueryVirtualMemory(meHandle, (PVOID)(place_to_allocate + meTotalAllocationSize), MemoryBasicInformation, &mbi, sizeof(mbi), 0);
		if (mbi.AllocationBase)
			continue;
		

	
		rLDR_DATA_TABLE_ENTRY LDRFAKE = meModule;
		LDRFAKE.SizeOfImage = meModule.SizeOfImage + skippedaddys + meTotalAllocationSize;
		NtWriteVirtualMemory(meHandle, current, &LDRFAKE, sizeof(LDRFAKE), 0);

		IMAGE_NT_HEADERS NTFAKE = nt;
		NTFAKE.OptionalHeader.SizeOfImage = nt.OptionalHeader.SizeOfImage + skippedaddys + meTotalAllocationSize;
		DWORD old;
		VirtualProtectEx(meHandle, (PVOID)((uintptr_t)meModule.DllBase + dos.e_lfanew), sizeof(IMAGE_NT_HEADERS), PAGE_READWRITE, &old);
		NtWriteVirtualMemory(meHandle, (PVOID)((uintptr_t)meModule.DllBase + dos.e_lfanew), &NTFAKE, sizeof(NTFAKE), 0);
		VirtualProtectEx(meHandle, (PVOID*)((uintptr_t)meModule.DllBase + dos.e_lfanew), sizeof(IMAGE_NT_HEADERS), old,0);

		IMAGE_NT_HEADERS ntafter;
		NtReadVirtualMemory(meHandle, (LPVOID)((uintptr_t)meModule.DllBase + dos.e_lfanew), &ntafter, sizeof(ntafter), 0);
		rLDR_DATA_TABLE_ENTRY meModuleAfter;
		NtReadVirtualMemory(meHandle, current, &meModuleAfter, sizeof(meModuleAfter), 0);

		meSuccess("Size of nt->optheader: %x -> %x", nt.OptionalHeader.SizeOfImage, ntafter.OptionalHeader.SizeOfImage);
		meSuccess("Size of ldr: %x -> %x", meModule.SizeOfImage, meModuleAfter.SizeOfImage);
		meSuccess("Spoofed end to: 0x%p", meModuleAfter.SizeOfImage + (uintptr_t)meModuleAfter.DllBase);
		meSuccess("Increased size of%p now image can be allocated at: 0x%p",meModule.DllBase, place_to_allocate);
		return place_to_allocate;

	}

	return 0;
}

void __stdcall ShellCodeFunction(InJectionData* pData) {
	if (!pData)
		return;

	BYTE* pBase = reinterpret_cast<BYTE*>(pData);
	auto* pOpt = &reinterpret_cast<IMAGE_NT_HEADERS*>(pBase + reinterpret_cast<IMAGE_DOS_HEADER*>(pData)->e_lfanew)->OptionalHeader;

	auto _LoadLibraryA = pData->LoadLibraryA;
	auto _GetProcAddress = pData->GetProcAddress;
	auto _DllMain = reinterpret_cast<pDLLEntry>(pBase + pOpt->AddressOfEntryPoint);

	BYTE* LocationDelta = pBase - pOpt->ImageBase;
	if (LocationDelta)
	{
		if (!pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size)
			return;

		auto* pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
		while (pRelocData->VirtualAddress)
		{
			UINT AmountOfEntries = (pRelocData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
			WORD* pRelativeInfo = reinterpret_cast<WORD*>(pRelocData + 1);

			for (UINT i = 0; i != AmountOfEntries; ++i, ++pRelativeInfo)
			{
				if (RELOC_FLAG(*pRelativeInfo))
				{
					UINT_PTR* pPatch = reinterpret_cast<UINT_PTR*>(pBase + pRelocData->VirtualAddress + ((*pRelativeInfo) & 0xFFF));
					*pPatch += reinterpret_cast<UINT_PTR>(LocationDelta);
				}
			}
			pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<BYTE*>(pRelocData) + pRelocData->SizeOfBlock);
		}
	}

	if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size)
	{
		auto* pImportDescr = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
		while (pImportDescr->Name)
		{
			char* szMod = reinterpret_cast<char*>(pBase + pImportDescr->Name);
			HINSTANCE hDll = _LoadLibraryA(szMod);

			ULONG_PTR* pThunkRef = reinterpret_cast<ULONG_PTR*>(pBase + pImportDescr->OriginalFirstThunk);
			ULONG_PTR* pFuncRef = reinterpret_cast<ULONG_PTR*>(pBase + pImportDescr->FirstThunk);

			if (!pThunkRef)
				pThunkRef = pFuncRef;

			for (; *pThunkRef; ++pThunkRef, ++pFuncRef)
			{
				if (IMAGE_SNAP_BY_ORDINAL(*pThunkRef))
				{
					*pFuncRef = _GetProcAddress(hDll, reinterpret_cast<char*>(*pThunkRef & 0xFFFF));
				}
				else
				{
					auto* pImport = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(pBase + (*pThunkRef));
					*pFuncRef = _GetProcAddress(hDll, pImport->Name);
				}
			}
			++pImportDescr;
		}
	}

	if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size)
	{
		auto* pTLS = reinterpret_cast<IMAGE_TLS_DIRECTORY*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
		auto* pCallback = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(pTLS->AddressOfCallBacks);
		for (; pCallback && *pCallback; ++pCallback)
			(*pCallback)(pBase, DLL_PROCESS_ATTACH, nullptr);
	}

	_DllMain(pBase, DLL_PROCESS_ATTACH, nullptr);

	pData->DLL = reinterpret_cast<HINSTANCE>(pBase);

}