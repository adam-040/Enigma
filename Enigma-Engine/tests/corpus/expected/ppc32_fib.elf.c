void __stdcall _start()
{
    int32_t v_1;
    int32_t v_2;
    v_1 = sum();
    v_2 = fib(10);
    *ptr_0x10020190 = v_1 + v_2 + 9;
    do {
                    
    } while( true );
}

uint32_t __stdcall sum()
{
    return 0x6f;
}

int32_t __stdcall fib(uint32_t param_1)
{
    int32_t v_1;
    int32_t v_2;
    int32_t v_3;
    v_2 = (param_1 >> 1) + 1;
    v_3 = 0;
    while (v_2 += -1, v_2 != 0) {
        v_1 = fib(param_1 - 1);
        param_1 -= 2;
        v_3 += v_1;
    }
    return param_1 + v_3;
}

