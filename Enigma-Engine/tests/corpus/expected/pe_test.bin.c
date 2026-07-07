void __fastcall entry()
{
    ptr_0x1402385a0 = 0;
    func_0x140001010();
    return;
}




uint8 __fastcall func_0x140001010()
{
    int8 v_1;
    int4 v_2;
    int4 v_3;
    uint64_t *v_4;
    uint8 v_5;
    uint32_t *v_6;
    uint64_t *v_7;
    void *v_8;
    uint8 out_rax;
    uint64_t *v_9;
    uint8 out_rax_00;
    int8 v_10;
    int8 v_11;
    int8 unaff_GS_OFFSET;
    bool v_12;
    uint32_t local_0x4c [3];
    
    v_11 = *(int8 *)(*(int8 *)(unaff_GS_OFFSET + 0x30) + 8);
    while( true ) {
        v_10 = 0;
        LOCK();
        v_12 = ptr_0x140238550 == 0;
        v_1 = v_11;
        if (!v_12) {
            v_10 = ptr_0x140238550;
            v_1 = ptr_0x140238550;
        }
        ptr_0x140238550 = v_1;
        UNLOCK();
        if (v_12) {
            v_12 = false;
            goto code_0x14000105c;
        }
        if (v_11 == v_10) break;
        Sleep(1000);
    }
    v_12 = true;
code_0x14000105c:
    if (ptr_0x140238558 == 1) {
        _amsg_exit(0x1f);
        v_5 = out_rax_00;
        goto code_0x1400013d2;
    }
    if (ptr_0x140238558 == 0) {
        ptr_0x140238558 = 1;
        func_0x1400b8cd0();
        ptr_0x1402385e0 = SetUnhandledExceptionFilter(func_0x1400b90b0);
        func_0x1400b99f0();
        func_0x1400b9520();
        ptr_0x140238588 = 1;
        ptr_0x140238584 = 1;
        ptr_0x140238580 = 1;
        ptr_0x140234008 = 0;
        if (ptr_0x1402385a0 == 0) {
            __set_app_type(1);
        }
        else {
            __set_app_type(2);
        }
        v_6 = (uint32_t *)func_0x1400b99b0();
        *v_6 = ptr_0x1402385d0;
        v_6 = (uint32_t *)func_0x1400b99c0();
        *v_6 = ptr_0x140238590;
        v_2 = func_0x1400b8940();
        if (-1 < v_2) {
            if (ptr_0x140194090 == 1) {
                func_0x1400b90a0(func_0x1400b8a00);
            }
            if (ptr_0x140194070 == -1) {
                func_0x1400b9a00(0xffffffff);
            }
            v_2 = func_0x1400b9970(0x1401d5d28,0x1401d5d30);
            if (v_2 != 0) {
                return 0xff;
            }
            local_0x4c[0] = ptr_0x140238570;
            v_3 = main(0x140234020,0x140234018,0x140234010,ptr_0x140238560,local_0x4c);
            v_2 = ptr_0x140234020;
            if (-1 < v_3) {
                v_11 = (int8)ptr_0x140234020;
                v_7 = malloc((int8)(ptr_0x140234020 + 1) << 3);
                v_4 = ptr_0x140234018;
                if (v_7 != (uint64_t *)0x0) {
                    v_9 = v_7;
                    if (v_2 < 1) {
code_0x14000134c:
                        *v_9 = 0;
                        ptr_0x140234018 = v_7;
                        _initterm((void *)0x1401d5d18,(void *)0x1401d5d20);
                        func_0x1400b8920();
                        ptr_0x140238558 = 2;
                        goto code_0x140001084;
                    }
                    v_10 = 1;
                    while( true ) {
                        v_5 = strlen((char *)v_4[v_10 + -1]);
                        v_8 = malloc(v_5 + 1);
                        v_7[v_10 + -1] = v_8;
                        if (v_8 == (void *)0x0) break;
                        memcpy(v_8,(void *)v_4[v_10 + -1],v_5 + 1);
                        if (v_11 == v_10) {
                            v_9 = v_7 + v_11;
                            goto code_0x14000134c;
                        }
                        v_10 += 1;
                    }
                }
            }
        }
        _amsg_exit(8);
        v_5 = out_rax;
    }
    else {
        ptr_0x140234004 = 1;
code_0x140001084:
        if (!v_12) {
            LOCK();
            ptr_0x140238550 = 0;
            UNLOCK();
        }
        func_0x1400b8970(0,2,0);
        v_4 = (uint64_t *)func_0x1400b99d0();
        v_2 = ptr_0x140234020;
        *v_4 = ptr_0x140234010;
        v_5 = func_0x1400015aa(v_2,ptr_0x140234018);
        if (ptr_0x140234008 == 0) {
code_0x1400013d2:
                    
            exit((int4)v_5);
        }
        if (ptr_0x140234004 != 0) {
            return v_5;
        }
    }
    _cexit();
    return v_5 & 0xffffffff;
}



void __fastcall Sleep(int4 param_1)
{
    char v_1;
    int4 arg_eax;
    uint8_t v_3;
    uint32_t arg_0x4;
    char arg_dh;
    char unaff_BL;
    uint8_t unaff_RBX;
    char *unaff_RDI;
    uint32_t v_2;
    
    v_1 = (char)arg_eax;
    *(char *)CONCAT44(arg_0x4,arg_eax) = *(char *)CONCAT44(arg_0x4,arg_eax) + v_1;
    *(int4 *)CONCAT44(arg_0x4,arg_eax) = *(int4 *)CONCAT44(arg_0x4,arg_eax) + arg_eax;
    *(char *)CONCAT44(arg_0x4,arg_eax) = *(char *)CONCAT44(arg_0x4,arg_eax) + v_1;
    v_3 = (uint8_t)((uint4)arg_eax >> 8);
    v_1 -= *(char *)CONCAT44(arg_0x4,arg_eax);
    v_2 = CONCAT31(v_3,v_1);
    *(char *)CONCAT44(arg_0x4,v_2) = *(char *)CONCAT44(arg_0x4,v_2) + v_1;
    *(char *)CONCAT44(arg_0x4,v_2) = *(char *)CONCAT44(arg_0x4,v_2) + v_1;
    *(char *)CONCAT44(arg_0x4,v_2) = *(char *)CONCAT44(arg_0x4,v_2) + v_1;
    *(uint8_t *)(CONCAT71(unaff_RBX,unaff_BL) + 0x14012) = 0;
    *unaff_RDI = *unaff_RDI + unaff_BL;
    *(char *)CONCAT44(arg_0x4,v_2) = *(char *)CONCAT44(arg_0x4,v_2) + v_1;
    *(char *)CONCAT44(arg_0x4,v_2) = *(char *)CONCAT44(arg_0x4,v_2) + v_1;
    *(char *)CONCAT44(arg_0x4,v_2) = *(char *)CONCAT44(arg_0x4,v_2) + v_1;
    v_1 += arg_dh >> 0x10;
    v_2 = CONCAT31(v_3,v_1);
    *(char *)CONCAT44(arg_0x4,v_2) = *(char *)CONCAT44(arg_0x4,v_2) + v_1;
                    
    halt_baddata_0x2399f8();
}









void __fastcall
func_0x1400b8cd0(uint64_t param_1,uint64_t param_2,uint64_t param_3,
                uint64_t param_4)
{
    uint64_t v_1;
    uint4 v_2;
    int4 v_3;
    LPVOID v_4;
    int8 v_5;
    uint8 v_6;
    int8 v_7;
    int4 *v_8;
    uint32_t v_9;
    uint4 v_10;
    uint4 *v_12;
    int4 v_13;
    int8 *v_14;
    uint4 *v_15;
    uint64_t local_0xe8 [5];
    uint32_t local_0xc0 [2];
    uint8 local_0xb8 [10];
    int8 local_0x68 [2];
    uint8_t local_0x58 [8];
    int8 local_0x50 [2];
    uint8 v_11;
    
    if (ptr_0x1402385b0 == 0) {
        ptr_0x1402385b0 = 1;
        local_0xb8[5] = 0x1400b8d0f;
        func_0x1400b96d0();
        local_0xb8[5] = 0x1400b8d26;
        v_5 = func_0x1400b9930();
        v_5 = -v_5;
        ptr_0x1402385b4 = 0;
        ptr_0x1402385b8 = local_0x58 + v_5;
        v_12 = (uint4 *)0x1401d524c;
        do {
            while( true ) {
                v_2 = v_12[2];
                v_14 = (int8 *)((uint8)*v_12 + 0x140000000);
                v_10 = v_2 & 0xff;
                v_11 = (uint8)v_10;
                v_7 = *v_14;
                v_15 = (uint4 *)((uint8)v_12[1] + 0x140000000);
                if (v_10 != 0x20) break;
                v_6 = (uint8)*v_15;
                if ((int4)*v_15 < 0) {
                    v_6 |= 0xffffffff00000000;
                }
                v_7 = (v_6 - (int8)v_14) + v_7;
                local_0x50[0] = v_7;
                if (((v_2 & 0xc0) == 0) && ((0xffffffff < v_7 || (v_7 < -0x80000000))))
                goto code_0x1400b903f;
                *(uint64_t *)((int8)local_0xb8 + v_5 + 0x28) = 0x1400b8fab;
                func_0x1400b8b60(v_15);
                *(uint64_t *)((int8)local_0xb8 + v_5 + 0x28) = 0x1400b8fbc;
                memcpy(v_15,local_0x50,4);
code_0x1400b8e07:
                v_12 = v_12 + 3;
                if ((uint4 *)0x1401d5abb < v_12) goto code_0x1400b8e90;
            }
            if (v_10 < 0x21) {
                if (v_10 == 8) {
                    v_6 = (uint8)*(uint1 *)v_15;
                    if ((char)*(uint1 *)v_15 < '\0') {
                        v_6 |= 0xffffffffffffff00;
                    }
                    v_7 = (v_6 - (int8)v_14) + v_7;
                    local_0x50[0] = v_7;
                    if (((v_2 & 0xc0) == 0) && ((0xff < v_7 || (v_7 < -0x80))))
                    goto code_0x1400b903f;
                    *(uint64_t *)((int8)local_0xb8 + v_5 + 0x28) = 0x1400b9001;
                    func_0x1400b8b60(v_15);
                    *(uint64_t *)((int8)local_0xb8 + v_5 + 0x28) = 0x1400b9012;
                    memcpy(v_15,local_0x50,1);
                }
                else {
                    if (v_10 != 0x10) goto code_0x1400b902b;
                    v_6 = (uint8)*(uint2 *)v_15;
                    if ((int2)*(uint2 *)v_15 < 0) {
                        v_6 |= 0xffffffffffff0000;
                    }
                    v_7 = (v_6 - (int8)v_14) + v_7;
                    local_0x50[0] = v_7;
                    if (((v_2 & 0xc0) == 0) && ((0xffff < v_7 || (v_7 < -0x8000))))
                    goto code_0x1400b903f;
                    *(uint64_t *)((int8)local_0xb8 + v_5 + 0x28) = 0x1400b8df6;
                    func_0x1400b8b60(v_15);
                    *(uint64_t *)((int8)local_0xb8 + v_5 + 0x28) = 0x1400b8e07;
                    memcpy(v_15,local_0x50,2);
                }
                goto code_0x1400b8e07;
            }
            if (v_10 != 0x40) {
code_0x1400b902b:
                local_0x50[0] = 0;
                *(uint64_t *)((int8)local_0xb8 + v_5 + 0x28) = 0x1400b903f;
                v_7 = func_0x1400b8b00(0x1401a7ed8);
code_0x1400b903f:
                *(int8 *)((int8)local_0x68 + v_5) = v_7;
                *(uint64_t *)((int8)local_0xb8 + v_5 + 0x28) = 0x1400b9053;
                func_0x1400b8b00(0x1401a7f08);
                v_9 = 0x401a7ea0;
                *(uint64_t *)((int8)local_0xb8 + v_5 + 0x28) = 0x1400b905f;
                func_0x1400b8b00();
                if (ptr_0x1402385c0 != (code *)0x0) {
                    v_1 = *(uint64_t *)((int8)local_0x68 + v_5 + 8);
                    *(uint32_t *)((int8)local_0xc0 + v_5) = v_9;
                    *(uint8 *)((int8)local_0xb8 + v_5) = v_11;
                    *(uint64_t *)((int8)local_0xb8 + v_5 + 8) = param_3;
                    *(uint64_t *)((int8)local_0xb8 + v_5 + 0x10) = param_4;
                    *(uint64_t *)((int8)local_0xb8 + v_5 + 0x18) = v_1;
                    *(uint64_t *)((int8)local_0xe8 + v_5) = 0x1400b9098;
                    (*ptr_0x1402385c0)((int8)local_0xc0 + v_5);
                }
                return;
            }
            v_7 = (*(int8 *)v_15 - (int8)v_14) + v_7;
            local_0x50[0] = v_7;
            if (((v_2 & 0xc0) == 0) && (-1 < v_7)) goto code_0x1400b903f;
            v_12 = v_12 + 3;
            *(uint64_t *)((int8)local_0xb8 + v_5 + 0x28) = 0x1400b8e6f;
            func_0x1400b8b60(v_15);
            *(uint64_t *)((int8)local_0xb8 + v_5 + 0x28) = 0x1400b8e80;
            memcpy(v_15,local_0x50,8);
        } while (v_12 < (uint4 *)0x1401d5abc);
code_0x1400b8e90:
        if (0 < ptr_0x1402385b4) {
            v_7 = 0;
            v_13 = 0;
            do {
                v_8 = (int4 *)(ptr_0x1402385b8 + v_7);
                v_3 = *v_8;
                if (v_3 != 0) {
                    v_11 = *(uint8 *)(v_8 + 4);
                    v_4 = *(LPVOID *)(v_8 + 2);
                    *(uint64_t *)((int8)local_0xb8 + v_5 + 0x28) = 0x1400b8ecf;
                    VirtualProtect(v_4,v_11,v_3,(uint4 *)local_0x50);
                }
                v_13 += 1;
                v_7 += 0x28;
            } while (v_13 < ptr_0x1402385b4);
        }
    }
    return;
}



void * __fastcall SetUnhandledExceptionFilter(void *param_1)
{
    uint1 *v_1;
    char arg_al;
    uint8_t arg_rax;
    
    v_1 = (uint1 *)(CONCAT71(arg_rax,arg_al) + 0x14012);
    *v_1 = *v_1 ^ (uint1)((uint8)param_1 >> 8);
    *(char *)CONCAT71(arg_rax,arg_al) = *(char *)CONCAT71(arg_rax,arg_al) + arg_al;
                    
    halt_baddata_0x2399b8();
}

