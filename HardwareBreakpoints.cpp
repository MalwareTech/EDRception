#include <Windows.h>
#include <stdio.h>
#include "HardwareBreakpoints.h"

// find the address of the syscall and retn instruction within a Nt* function
BOOL FindSyscallInstruction(LPVOID nt_func_addr, LPVOID* syscall_addr, LPVOID* syscall_ret_addr) {
    BYTE* ptr = (BYTE*)nt_func_addr;

    // iterate through the native function stub to find the syscall instruction
    for (int i = 0; i < 1024; i++) {

        // check for syscall opcode (FF 05)
        if (ptr[i] == 0x0F && ptr[i + 1] == 0x05) {
            printf("Found syscall opcode at 0x%llx\n", (DWORD64)&ptr[i]);
            *syscall_addr = (LPVOID)&ptr[i];
            *syscall_ret_addr = (LPVOID)&ptr[i + 2];
            break;
        }
    }

    // make sure we found the syscall instruction
    if (!*syscall_addr) {
        printf("error: syscall instruction not found\n");
        return FALSE;
    }

    // make sure the instruction after syscall is retn
    if (**(BYTE**)syscall_ret_addr != 0xc3) {
        printf("Error: syscall instruction not followed by ret\n");
        return FALSE;
    }

    return TRUE;
}

// set a breakpoint on the syscall and retn instruction of a Nt* function
BOOL SetSyscallBreakpoints(LPVOID nt_func_addr, HANDLE thread_handle) {
    LPVOID syscall_addr, syscall_ret_addr;
    CONTEXT thread_context = { 0 };
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");

    if (!FindSyscallInstruction(nt_func_addr, &syscall_addr, &syscall_ret_addr)) {
        return FALSE;
    }

    thread_context.ContextFlags = CONTEXT_FULL;

    // get the current thread context (note, this must be a suspended thread)
    if (!GetThreadContext(thread_handle, &thread_context)) {
        printf("GetThreadContext() failed, error: %d\n", GetLastError());
        return FALSE;
    }

    dr7_t dr7 = { 0 };

    dr7.dr0_local = 1; // set DR0 as an execute breakpoint
    dr7.dr1_local = 1; // set DR1 as an execute breakpoint

    thread_context.ContextFlags = CONTEXT_ALL;

    thread_context.Dr0 = (DWORD64)syscall_addr;     // set DR0 to break on syscall address
    thread_context.Dr1 = (DWORD64)syscall_ret_addr; // set DR1 to break on syscall ret address
    thread_context.Dr7 = *(DWORD*)&dr7;

    // use SetThreadContext to update the debug registers
    if (!SetThreadContext(thread_handle, &thread_context)) {
        printf("SetThreadContext() failed, error: %d\n", GetLastError());
    }

    printf("Hardware breakpoints set\n");
    return TRUE;
}