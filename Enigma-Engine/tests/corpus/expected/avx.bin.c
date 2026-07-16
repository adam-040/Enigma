uint64_t __stdcall entry(uint64_t param_1, uint64_t param_2)
{
    uint8_t v_1 [16];
    uint32_t arg_xmm1_dc;
    uint32_t arg_xmm1_dd;
    uint8_t arg_xmm3 [16];
    uint32_t local_0x28;
    v_1._8_4_ = arg_xmm1_dc;
    v_1._0_8_ = param_2;
    v_1._12_4_ = arg_xmm1_dd;
    vsubps_avx(v_1,arg_xmm3);
    return local_0x28 << 0x20 | local_0x28;
}

