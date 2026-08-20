void __stdcall _start()
{
    sum();
    fib(10);
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
    v_2 = 0;
    for (; 1 < param_1; param_1 -= 2) {
        v_1 = fib(param_1 - 1);
        v_2 += v_1;
    }
    return param_1 + v_2;
}

