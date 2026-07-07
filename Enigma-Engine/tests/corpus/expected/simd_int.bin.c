uint2 __stdcall entry(uint64_t param_1,uint64_t param_2)
{
    int4 v_1;
    int4 v_3;
    int4 arg_xmm0_dc;
    int4 v_4;
    int4 arg_xmm0_dd;
    int4 v_5;
    uint8_t v_2 [16];
    uint4 v_6;
    int4 arg_xmm1_dc;
    int4 arg_xmm1_dd;
    char arg_xmm2_ba;
    char arg_xmm2_bb;
    char arg_xmm2_bc;
    char arg_xmm2_bd;
    char arg_xmm2_be;
    char arg_xmm2_bf;
    char arg_xmm2_bg;
    char arg_xmm2_bh;
    char arg_xmm2_bi;
    char arg_xmm2_bj;
    char arg_xmm2_bk;
    char arg_xmm2_bl;
    char arg_xmm2_bm;
    char arg_xmm2_bn;
    char arg_xmm2_bo;
    char arg_xmm2_bp;
    uint8_t arg_xmm3 [16];
    uint8_t arg_xmm4 [16];
    
    v_1 = (int4)param_1 + (int4)param_2;
    v_3 = (int4)((uint8)param_1 >> 0x20) + (int4)((uint8)param_2 >> 0x20);
    v_4 = arg_xmm0_dc + arg_xmm1_dc;
    v_5 = arg_xmm0_dd + arg_xmm1_dd;
    v_2[0] = (char)v_1 - arg_xmm2_ba;
    v_2[1] = (char)((uint4)v_1 >> 8) - arg_xmm2_bb;
    v_2[2] = (char)((uint4)v_1 >> 0x10) - arg_xmm2_bc;
    v_2[3] = (char)((uint4)v_1 >> 0x18) - arg_xmm2_bd;
    v_2[4] = (char)v_3 - arg_xmm2_be;
    v_2[5] = (char)((uint4)v_3 >> 8) - arg_xmm2_bf;
    v_2[6] = (char)((uint4)v_3 >> 0x10) - arg_xmm2_bg;
    v_2[7] = (char)((uint4)v_3 >> 0x18) - arg_xmm2_bh;
    v_2[8] = (char)v_4 - arg_xmm2_bi;
    v_2[9] = (char)((uint4)v_4 >> 8) - arg_xmm2_bj;
    v_2[10] = (char)((uint4)v_4 >> 0x10) - arg_xmm2_bk;
    v_2[0xb] = (char)((uint4)v_4 >> 0x18) - arg_xmm2_bl;
    v_2[0xc] = (char)v_5 - arg_xmm2_bm;
    v_2[0xd] = (char)((uint4)v_5 >> 8) - arg_xmm2_bn;
    v_2[0xe] = (char)((uint4)v_5 >> 0x10) - arg_xmm2_bo;
    v_2[0xf] = (char)((uint4)v_5 >> 0x18) - arg_xmm2_bp;
    v_2 = v_2 & arg_xmm3 | arg_xmm4;
    v_6 = v_2._12_4_;
    return (uint2)(SUB161(v_2 >> 7,0) & 1) | (uint2)(SUB161(v_2 >> 0xf,0) & 1) << 1 |
               (uint2)(SUB161(v_2 >> 0x17,0) & 1) << 2 |
               (uint2)(SUB161(v_2 >> 0x1f,0) & 1) << 3 |
               (uint2)(SUB161(v_2 >> 0x27,0) & 1) << 4 |
               (uint2)(SUB161(v_2 >> 0x2f,0) & 1) << 5 |
               (uint2)(SUB161(v_2 >> 0x37,0) & 1) << 6 |
               (uint2)(SUB161(v_2 >> 0x3f,0) & 1) << 7 |
               (uint2)(SUB161(v_2 >> 0x47,0) & 1) << 8 |
               (uint2)(SUB161(v_2 >> 0x4f,0) & 1) << 9 |
               (uint2)(SUB161(v_2 >> 0x57,0) & 1) << 10 |
               (uint2)(SUB161(v_2 >> 0x5f,0) & 1) << 0xb |
               (uint2)((uint1)(v_6 >> 7) & 1) << 0xc |
               (uint2)((uint1)(v_6 >> 0xf) & 1) << 0xd |
               (uint2)((uint1)(v_6 >> 0x17) & 1) << 0xe |
               (uint2)(uint1)(v_2[0xf] >> 7) << 0xf;
}

