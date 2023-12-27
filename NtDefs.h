/*
	Definitions for undocumented NTDLL structures and functions
*/

#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#define ProcessBasicInformation 0

typedef struct _LSA_UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
	ULONG           Length;
	HANDLE          RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG           Attributes;
	PVOID           SecurityDescriptor;
	PVOID           SecurityQualityOfService;
}  OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef NTSTATUS (WINAPI *t_NtUnmapViewOfSection)(
	HANDLE ProcessHandle,
	PVOID BaseAddress);

typedef NTSTATUS (WINAPI *t_NtCreateSection)(
	PHANDLE SectionHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PLARGE_INTEGER MaximumSize,
	ULONG SectionPageProtection,
	ULONG AllocationAttributes,
	HANDLE FileHandle
	);

typedef NTSTATUS (WINAPI *t_NtMapViewOfSection)(
	HANDLE SectionHandle, 
	HANDLE ProcessHandle,
	PVOID *BaseAddress, 
	ULONG_PTR ZeroBits, 
	SIZE_T CommitSize, 
	PLARGE_INTEGER SectionOffset, 
	PSIZE_T ViewSize, 
	DWORD InheritDisposition, 
	ULONG AllocationType, 
	ULONG Win32Protect);

typedef NTSTATUS (WINAPI *t_NtQueryInformationProcess)(
	HANDLE ProcessHandle,
	DWORD ProcessInformationClass,
	PVOID ProcessInformation,
	ULONG ProcessInformationLength,
	PULONG ReturnLength
	);

typedef NTSTATUS (WINAPI *t_NtClose)(
	HANDLE Handle
	);

typedef NTSTATUS (WINAPI* t_NtSetContextThread)(
	HANDLE ThreadHandle, PCONTEXT Context
	);