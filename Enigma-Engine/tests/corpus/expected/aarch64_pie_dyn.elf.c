void __cdecl entry()
{
    code *UNRECOVERED_JUMPTABLE;
    UNRECOVERED_JUMPTABLE = (code *)__libc_init();
    if (UNRECOVERED_JUMPTABLE != (code *)0x0) {
                    
                    
        (*UNRECOVERED_JUMPTABLE)();
        return;
    }
    return;
}



void __cdecl ptrace()
{
                    
                    
    (*_ptrace)();
    return;
}



void __cdecl syscall()
{
                    
                    
    (*_syscall)();
    return;
}



void __cdecl getenv()
{
                    
                    
    (*_getenv)();
    return;
}



void __cdecl write()
{
                    
                    
    (*_write)();
    return;
}



int32_t __cdecl scanf(char *param_1,...)
{
    int32_t v_1;
                    
                    
    v_1 = (*_scanf)((int32_t)param_1);
    return v_1;
}



void * __cdecl malloc(uint64_t param_1)
{
    void *v_1;
                    
                    
    v_1 = (void *)(*_malloc)();
    return v_1;
}



void __cdecl free(void *param_1)
{
                    
                    
    (*_free)();
    return;
}



int32_t __cdecl setvbuf(void *param_1, char *param_2, int32_t param_3, uint64_t param_4)
{
    int32_t v_1;
                    
                    
    v_1 = (*_setvbuf)((int32_t)param_1,param_2,param_3);
    return v_1;
}



void __cdecl prctl()
{
                    
                    
    (*_prctl)();
    return;
}

