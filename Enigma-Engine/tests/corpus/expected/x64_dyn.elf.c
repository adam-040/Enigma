

void __fastcall _start(char *param_1, char *param_2, int32_t param_3, uint64_t param_4)
{
    fib();
    prctl();
    syscall();
    ptrace();
    scanf(param_1);
    malloc((uint64_t)param_1);
    free(param_1);
    setvbuf(param_1,param_2,param_3,param_4);
    write();
    getenv();
                    
                    
    (*_prctl)();
    return;
}



void __fastcall fib()
{
                    
                    
    (*_fib)();
    return;
}



void __fastcall prctl()
{
                    
                    
    (*_prctl)();
    return;
}



void __fastcall syscall()
{
                    
                    
    (*_syscall)();
    return;
}



void __fastcall ptrace()
{
                    
                    
    (*_ptrace)();
    return;
}



int32_t __fastcall scanf(char *param_1,...)
{
    int32_t v_1;
                    
                    
    v_1 = (*_scanf)();
    return v_1;
}



void * __fastcall malloc(uint64_t param_1)
{
    void *v_1;
                    
                    
    v_1 = (void *)(*_malloc)();
    return v_1;
}



void __fastcall free(void *param_1)
{
                    
                    
    (*_free)();
    return;
}



int32_t __fastcall
setvbuf(void *param_1, char *param_2, int32_t param_3, uint64_t param_4)
{
    int32_t v_1;
                    
                    
    v_1 = (*_setvbuf)();
    return v_1;
}



void __fastcall write()
{
                    
                    
    (*_write)();
    return;
}



void __fastcall getenv()
{
                    
                    
    (*_getenv)();
    return;
}

int32_t __fastcall fib()
{
    int32_t v_1;
    int32_t v_2;
    int32_t unaff_EDI;
    v_2 = 0;
    for (; 1 < unaff_EDI; unaff_EDI += -2) {
        v_1 = fib();
        v_2 += v_1;
    }
    return unaff_EDI + v_2;
}

