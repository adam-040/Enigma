uint64_t __cdecl _start()
{
    int64_t *v_1;
    uint64_t v_2;
    int64_t v_3;
    int64_t v_4;
    ptr_0x220230 = fib(10);
    v_4 = 0;
    v_3 = 0;
    do {
        v_1 = (int64_t *)(v_4 + 0x2201f0);
        v_4 += 8;
        v_3 = *v_1 + v_3;
    } while (v_4 != 0x40);
    v_2 = v_3 + ptr_0x220230;
    if (v_2 < 0x3e9) {
        v_2 = 1000;
    }
    return v_2;
}

int64_t __cdecl fib(uint64_t param_1)
{
    int64_t v_1;
    int64_t v_2;
    v_2 = 0;
    for (; 1 < param_1; param_1 -= 2) {
        v_1 = fib(param_1 - 1);
        v_2 += v_1;
    }
    return param_1 + v_2;
}

