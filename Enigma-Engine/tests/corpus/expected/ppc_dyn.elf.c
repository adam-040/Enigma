

void __stdcall _start()
{
    int32_t v_1;
    v_1 = 00000000.plt_pic32.fib(10);
    00000000.plt_pic32.prctl();
    00000000.plt_pic32.syscall(v_1);
    00000000.plt_pic32.ptrace(v_1);
    00000000.plt_pic32.scanf();
    00000000.plt_pic32.malloc(v_1);
    00000000.plt_pic32.free(v_1);
    00000000.plt_pic32.setvbuf();
    00000000.plt_pic32.write();
    00000000.plt_pic32.getenv();
    00000000.plt_pic32.prctl(*_g_data + v_1);
    return;
}

void __stdcall 00000000.plt_pic32.fib()
{
    int32_t unaff_r30;
                    
                    
    (**(code **)(unaff_r30 + 0x10010))();
    return;
}

void __stdcall 00000000.plt_pic32.prctl()
{
    int32_t unaff_r30;
                    
                    
    (**(code **)(unaff_r30 + 0x10014))();
    return;
}

void __stdcall 00000000.plt_pic32.syscall()
{
    int32_t unaff_r30;
                    
                    
    (**(code **)(unaff_r30 + 0x10018))();
    return;
}

void __stdcall 00000000.plt_pic32.ptrace()
{
    int32_t unaff_r30;
                    
                    
    (**(code **)(unaff_r30 + 0x1001c))();
    return;
}

void __stdcall 00000000.plt_pic32.scanf()
{
    int32_t unaff_r30;
                    
                    
    (**(code **)(unaff_r30 + 0x10020))();
    return;
}

void __stdcall 00000000.plt_pic32.malloc()
{
    int32_t unaff_r30;
                    
                    
    (**(code **)(unaff_r30 + 0x10024))();
    return;
}

void __stdcall 00000000.plt_pic32.free()
{
    int32_t unaff_r30;
                    
                    
    (**(code **)(unaff_r30 + 0x10028))();
    return;
}

void __stdcall 00000000.plt_pic32.setvbuf()
{
    int32_t unaff_r30;
                    
                    
    (**(code **)(unaff_r30 + 0x1002c))();
    return;
}

void __stdcall 00000000.plt_pic32.write()
{
    int32_t unaff_r30;
                    
                    
    (**(code **)(unaff_r30 + 0x10030))();
    return;
}

void __stdcall 00000000.plt_pic32.getenv()
{
    int32_t unaff_r30;
                    
                    
    (**(code **)(unaff_r30 + 0x10034))();
    return;
}

int32_t __stdcall fib(int32_t param_1)
{
    int32_t v_1;
    int32_t v_2;
    int32_t v_3;
    v_1 = param_1;
    if (0 < param_1) {
        v_1 = 1;
    }
    v_1 = ((param_1 - v_1) + 1U >> 1) + 1;
    v_3 = 0;
    while (v_1 += -1, v_1 != 0) {
        v_2 = 00000000.plt_pic32.fib(param_1 + -1);
        param_1 += -2;
        v_3 += v_2;
    }
    return param_1 + v_3;
}

