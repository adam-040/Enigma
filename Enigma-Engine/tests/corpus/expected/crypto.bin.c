uint64_t __stdcall entry()
{
    uint8_t arg_xmm0 [16];
    uint8_t v_1 [16];
    uint8_t arg_xmm1 [16];
    uint8_t arg_xmm2 [16];
    uint8_t arg_xmm3 [16];
    uint8_t arg_xmm4 [16];
    v_1 = aesenc(arg_xmm0,arg_xmm1);
    v_1 = aesenclast(v_1,arg_xmm2);
    v_1 = aesdec(v_1,arg_xmm3);
    v_1 = aesdeclast(v_1,arg_xmm4);
    return v_1._0_8_;
}

