void __stdcall _start()
{
    int32_t v_1;
    int32_t arg_t9;
    v_1 = (**(code **)(arg_t9 + 0x100ec))(10);
    (**(code **)(arg_t9 + 0x100f0))(v_1);
    (**(code **)(arg_t9 + 0x100f4))(v_1);
    (**(code **)(arg_t9 + 0x100f8))(v_1);
    (**(code **)(arg_t9 + 0x100fc))();
    (**(code **)(arg_t9 + 0x10100))(v_1);
    (**(code **)(arg_t9 + 0x10104))(v_1);
    (**(code **)(arg_t9 + 0x10108))();
    (**(code **)(arg_t9 + 0x1010c))();
    (**(code **)(arg_t9 + 0x10110))();
    (**(code **)(arg_t9 + 0x100f0))(**(int32_t **)(arg_t9 + 0x10114) + v_1);
    return;
}

int32_t __stdcall fib(int32_t param_1)
{
    int32_t v_1;
    int32_t v_2;
    int32_t arg_t9;
    v_2 = 0;
    for (; 1 < param_1; param_1 += -2) {
        v_1 = (**(code **)(arg_t9 + 0x10158))(param_1 + -1);
        v_2 += v_1;
    }
    return param_1 + v_2;
}

