BOOL SetSyscallBreakpoints(LPVOID nt_func_addr, HANDLE thread_handle);

typedef struct {
    unsigned int  dr0_local : 1;
    unsigned int  dr0_global : 1;
    unsigned int  dr1_local : 1;
    unsigned int  dr1_global : 1;
    unsigned int  dr2_local : 1;
    unsigned int  dr2_global : 1;
    unsigned int  dr3_local : 1;
    unsigned int  dr3_global : 1;
    unsigned int  local_enabled : 1;
    unsigned int  global_enabled : 1;
    unsigned int  reserved_10 : 1;
    unsigned int  rtm : 1;
    unsigned int  reserved_12 : 1;
    unsigned int  gd : 1;
    unsigned int  reserved_14_15 : 2;
    unsigned int  dr0_break : 2;
    unsigned int  dr0_len : 2;
    unsigned int  dr1_break : 2;
    unsigned int  dr1_len : 2;
    unsigned int  dr2_break : 2;
    unsigned int  dr2_len : 2;
    unsigned int  dr3_break : 2;
    unsigned int  dr3_len : 2;
} dr7_t;