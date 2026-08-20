

void __stdcall _start()
{
    void *v_1;
    char *v_2;
    void *out_r0;
    uint32_t out_r1;
    char *out_r1_00;
    int32_t out_r2;
    uint32_t unaff_r4;
    uint32_t unaff_lr;
    v_1 = (void *)fib(10);
    prctl();
    syscall(v_1);
    v_2 = (char *)ptrace(v_1);
    scanf(v_2);
    malloc(out_r1 << 0x20 | v_1);
    free(v_1);
    setvbuf(out_r0,out_r1_00,out_r2,unaff_lr << 0x20 | unaff_r4);
    write();
    getenv();
                    
                    
    (*_prctl)(*_g_data + (int32_t)v_1);
    return;
}



void __stdcall fib()
{
                    
                    
    (*_fib)();
    return;
}



void __stdcall prctl()
{
                    
                    
    (*_prctl)();
    return;
}



void __stdcall syscall()
{
                    
                    
    (*_syscall)();
    return;
}



void __stdcall ptrace()
{
                    
                    
    (*_ptrace)();
    return;
}



int32_t __stdcall scanf(char *param_1,...)
{
    int32_t v_1;
                    
                    
    v_1 = (*_scanf)(param_1);
    return v_1;
}



void * __stdcall malloc(uint64_t param_1)
{
    void *v_1;
                    
                    
    v_1 = (void *)(*_malloc)((int32_t)param_1,(int32_t)(param_1 >> 0x20));
    return v_1;
}



void __stdcall free(void *param_1)
{
                    
                    
    (*_free)(param_1);
    return;
}



int32_t __stdcall
setvbuf(void *param_1, char *param_2, int32_t param_3, uint64_t param_4)
{
    int32_t v_1;
                    
                    
    v_1 = (*_setvbuf)(param_1);
    return v_1;
}



void __stdcall write()
{
                    
                    
    (*_write)();
    return;
}



void __stdcall getenv()
{
                    
                    
    (*_getenv)();
    return;
}

int32_t __stdcall fib(int32_t param_1)
{
    int32_t v_1;
    int32_t v_2;
    v_2 = 0;
    for (; 1 < param_1; param_1 += -2) {
        v_1 = fib(param_1 + -1);
        v_2 += v_1;
    }
    return param_1 + v_2;
}

