


uint64_t __fastcall entry()
{
    void *v_1;
    char *v_2;
    uint32_t v_3;
    int64_t v_4;
    int32_t v_5;
    int64_t v_6;
    uint64_t *v_7;
    uint64_t v_8;
    void *v_9;
    uint32_t *v_10;
    uint64_t *v_11;
    uint64_t v_12;
    uint64_t *v_13;
    uint64_t out_rax;
    uint64_t unaff_RBX;
    uint8_t *v_14;
    uint64_t unaff_RBP;
    uint64_t v_15;
    int64_t unaff_RSI;
    code *unaff_RDI;
    uint64_t unaff_R12;
    uint64_t unaff_R13;
    uint64_t unaff_R14;
    uint64_t unaff_R15;
    int64_t unaff_GS_OFFSET;
    bool v_16;
    ptr_0x1401cd840 = 0;
    v_14 = (uint8_t *)ptr_0x20;
    do {
        *(uint64_t *)(v_14 + -8) = unaff_R15;
        *(uint64_t *)(v_14 + -0x10) = unaff_R14;
        *(uint64_t *)(v_14 + -0x18) = unaff_R13;
        *(uint64_t *)(v_14 + -0x20) = unaff_R12;
        *(uint64_t *)(v_14 + -0x28) = unaff_RBP;
        *(code **)(v_14 + -0x30) = unaff_RDI;
        *(int64_t *)(v_14 + -0x38) = unaff_RSI;
        *(uint64_t *)(v_14 + -0x40) = unaff_RBX;
        unaff_RSI = *(int64_t *)(*(int64_t *)(unaff_GS_OFFSET + 0x30) + 8);
        unaff_RBX = 0x1401cd7f0;
        unaff_RDI = Sleep;
        while( true ) {
            v_6 = 0;
            LOCK();
            v_16 = ptr_0x1401cd7f0 == 0;
            v_4 = unaff_RSI;
            if (!v_16) {
                v_6 = ptr_0x1401cd7f0;
                v_4 = ptr_0x1401cd7f0;
            }
            ptr_0x1401cd7f0 = v_4;
            UNLOCK();
            if (v_16) {
                unaff_R14 = 0;
                goto code_0x14000108c;
            }
            if (unaff_RSI == v_6) break;
            *(uint64_t *)(v_14 + -0xa0) = 0x140001080;
            Sleep(1000);
        }
        unaff_R14 = 1;
code_0x14000108c:
        unaff_R12 = 0x1401cd7f8;
        if (ptr_0x1401cd7f8 != 1) goto code_0x14000109e;
        *(uint64_t *)(v_14 + -0xa0) = 0x140001434;
        _amsg_exit(0x1f);
        ptr_0x1401cd840 = 1;
        v_14 = v_14 + -0x98;
    } while( true );
    
code_0x140001419:
    *(uint64_t *)(v_14 + -0xa0) = 0x140001423;
    _amsg_exit(10);
    v_8 = out_rax;
    goto code_0x140001423;
    
code_0x14000109e:
    if (ptr_0x1401cd7f8 == 0) {
        ptr_0x1401cd7f8 = 1;
        *(uint64_t *)(v_14 + -0xa0) = 0x140001172;
        v_9 = (void *)func_0x1400f3200(2);
        *(uint64_t *)(v_14 + -0xa0) = 0x140001185;
        setvbuf(v_9,(char *)0x0,4,0);
        *(uint64_t *)(v_14 + -0xa0) = 0x140001191;
        v_5 = atexit(func_0x140001030);
        if (v_5 != 0) {
                    
            *(uint64_t *)(v_14 + -0xa0) = 0x140001419;
            abort();
        }
        *(uint64_t *)(v_14 + -0xa0) = 0x1400011a0;
        func_0x1400f2510();
        *(uint64_t *)(v_14 + -0xa0) = 0x1400011ac;
        func_0x1400f30c0(func_0x140001000);
        *(uint64_t *)(v_14 + -0xa0) = 0x1400011b1;
        func_0x1400f2c20();
        ptr_0x1401cd828 = 1;
        ptr_0x1401cd824 = 1;
        ptr_0x1401cd820 = 1;
        ptr_0x1401c9008 = 0;
        if (ptr_0x1401cd840 != 0) goto code_0x140001378;
        *(uint64_t *)(v_14 + -0xa0) = 0x140001253;
        __set_app_type(1);
        do {
            *(uint64_t *)(v_14 + -0xa0) = 0x140001258;
            v_10 = (uint32_t *)func_0x1400f3080();
            *v_10 = ptr_0x1401cd870;
            *(uint64_t *)(v_14 + -0xa0) = 0x140001268;
            v_10 = (uint32_t *)func_0x1400f3090();
            *v_10 = ptr_0x1401cd830;
            *(uint64_t *)(v_14 + -0xa0) = 0x140001278;
            v_5 = func_0x1400f2180();
            if (-1 < v_5) {
                if (ptr_0x14016e0a0 == 1) {
                    *(uint64_t *)(v_14 + -0xa0) = 0x1400013f0;
                    func_0x1400f28f0(func_0x1400f2240);
                }
                if (ptr_0x14016e080 == -1) {
                    *(uint64_t *)(v_14 + -0xa0) = 0x1400013df;
                    func_0x1400f30d0(0xffffffff);
                }
                *(uint64_t *)(v_14 + -0xa0) = 0x1400012b3;
                v_5 = func_0x1400f3040(0x1401a45c8,0x1401a45d0);
                if (v_5 != 0) goto code_0x140001419;
                *(uint32_t *)(v_14 + -0x4c) = ptr_0x1401cd810;
                *(uint8_t **)(v_14 + -0x78) = v_14 + -0x4c;
                *(uint64_t *)(v_14 + -0xa0) = 0x1400012f6;
                v_5 = __getmainargs(0x1401c9020,0x1401c9018,0x1401c9010,ptr_0x1401cd800);
                v_3 = ptr_0x1401c9020;
                if (-1 < v_5) {
                    v_8 = (uint64_t)ptr_0x1401c9020;
                    *(uint64_t *)(v_14 + -0xa0) = 0x14000130f;
                    v_11 = malloc((int64_t)(int32_t)(ptr_0x1401c9020 + 1) << 3);
                    v_7 = ptr_0x1401c9018;
                    if (v_11 != (uint64_t *)0x0) {
                        v_13 = v_11;
                        if ((int32_t)v_3 < 1) {
code_0x140001395:
                            *v_13 = 0;
                            *(uint64_t *)(v_14 + -0xa0) = 0x1400013b0;
                            ptr_0x1401c9018 = v_11;
                            SetUnhandledExceptionFilter(func_0x140001010);
                            *(uint64_t *)(v_14 + -0xa0) = 0x1400013c3;
                            _initterm((void *)0x1401a45b8,(void *)0x1401a45c0);
                            *(uint64_t *)(v_14 + -0xa0) = 0x1400013c8;
                            main();
                            ptr_0x1401cd7f8 = 2;
                            goto code_0x1400010b5;
                        }
                        v_15 = 1;
                        while( true ) {
                            v_2 = (char *)v_7[v_15 - 1];
                            *(uint64_t *)(v_14 + -0xa0) = 0x140001353;
                            v_12 = strlen(v_2);
                            *(uint64_t *)(v_14 + -0xa0) = 0x14000135f;
                            v_9 = malloc(v_12 + 1);
                            v_11[v_15 - 1] = v_9;
                            if (v_9 == (void *)0x0) break;
                            v_1 = (void *)v_7[v_15 - 1];
                            *(uint64_t *)(v_14 + -0xa0) = 0x140001340;
                            memcpy(v_9,v_1,v_12 + 1);
                            if (v_8 == v_15) {
                                v_13 = v_11 + v_8;
                                goto code_0x140001395;
                            }
                            v_15 += 1;
                        }
                    }
                }
            }
            *(uint64_t *)(v_14 + -0xa0) = 0x140001373;
            _amsg_exit(8);
code_0x140001378:
            *(uint64_t *)(v_14 + -0xa0) = 0x140001382;
            __set_app_type(2);
        } while( true );
    }
    ptr_0x1401c9004 = 1;
code_0x1400010b5:
    if ((int32_t)unaff_R14 == 0) {
        LOCK();
        ptr_0x1401cd7f0 = 0;
        UNLOCK();
    }
    *(uint64_t *)(v_14 + -0xa0) = 0x1400010d9;
    func_0x1400f21b0(0,2,0);
    *(uint64_t *)(v_14 + -0xa0) = 0x1400010de;
    v_7 = (uint64_t *)func_0x1400f30a0();
    v_3 = ptr_0x1401c9020;
    *v_7 = ptr_0x1401c9010;
    *(uint64_t *)(v_14 + -0xa0) = 0x1400010fa;
    v_8 = func_0x14012e6d0(v_3,ptr_0x1401c9018);
    if (ptr_0x1401c9008 != 0) {
        if (ptr_0x1401c9004 == 0) {
            *(int32_t *)(v_14 + -0x5c) = (int32_t)v_8;
            *(uint64_t *)(v_14 + -0xa0) = 0x140001141;
            _cexit();
            v_8 = (uint64_t)*(uint32_t *)(v_14 + -0x5c);
        }
        return v_8;
    }
code_0x140001423:
                    
    *(uint64_t *)(v_14 + -0xa0) = 0x14000142a;
    exit((int32_t)v_8);
}

int64_t __fastcall func_0x1400f3200(uint64_t param_1)
{
    int64_t v_1;
    v_1 = __iob_func();
    return v_1 + (param_1 & 0xffffffff) * 0x30;
}

int32_t __fastcall
setvbuf(void *param_1, char *param_2, int32_t param_3, uint64_t param_4)
{
    int32_t v_1;
    v_1 = setvbuf(param_1,param_2,param_3,param_4);
    return v_1;
}

int32_t __fastcall atexit(void *param_1)
{
    int32_t v_1;
    v_1 = atexit(param_1);
    return v_1;
}

void __fastcall abort()
{
    abort();
    return;
}

