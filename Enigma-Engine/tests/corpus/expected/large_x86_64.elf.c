void __fastcall entry()
{
    uint64_t v_1;
    uint32_t v_2;
    uint8_t *v_3;
    code *unaff_RBX;
    uint64_t *v_4;
    int64_t v_5;
    int32_t v_6;
    code *v_7;
    int64_t unaff_R12;
    uint8_t *unaff_R13;
    int64_t unaff_retaddr;
    uint8_t local_0x8_00 [32];
    uint64_t local_0x8;
    v_5 = 0;
    local_0x8 = 0x4038c7;
    v_3 = local_0x8_00;
    v_4 = &local_0x8;
    v_7 = (code *)0x4042ea;
    do {
        *(uint8_t **)((int64_t)v_4 + -8) = unaff_R13;
        v_6 = (int32_t)unaff_retaddr;
        *(int64_t *)((int64_t)v_4 + -0x10) = v_5;
        *(uint8_t **)((int64_t)v_4 + -0x20) = v_3;
        *(uint64_t *)((int64_t)v_4 + -0x30) = 0x4bee02;
        sub_0x4bec23();
        unaff_retaddr = *(int64_t *)((int64_t)v_4 + -0x20);
        v_1 = *(uint64_t *)((int64_t)v_4 + -0x10);
        *(uint64_t *)((int64_t)v_4 + -8) = *(uint64_t *)((int64_t)v_4 + -8);
        *(int64_t *)((int64_t)v_4 + -0x10) = unaff_R12;
        *(uint64_t *)((int64_t)v_4 + -0x18) = v_1;
        *(code **)((int64_t)v_4 + -0x20) = unaff_RBX;
        *(uint64_t *)((int64_t)v_4 + -0x28) = 0x4bedb2;
        v_5 = (int64_t)v_6;
        unaff_R13 = (uint8_t *)(unaff_retaddr + 8 + v_5 * 8);
        *(uint64_t *)((int64_t)v_4 + -0x30) = 0x4bedcf;
        func_0x4bed94();
        *(uint64_t *)((int64_t)v_4 + -0x30) = 0x4bedd9;
        v_3 = unaff_R13;
        v_2 = (*v_7)();
        *(uint64_t *)((int64_t)v_4 + -0x30) = 0x4bede0;
        func_0x400130();
        unaff_RBX = v_7;
        v_4 = (uint64_t *)((int64_t)v_4 + -0x28);
        v_7 = (code *)(uint64_t)v_2;
        unaff_R12 = unaff_retaddr;
    } while( true );
}




void __fastcall sub_0x4bec23()
{
    int64_t v_1;
    char v_2;
    uint64_t v_3;
    uint64_t *v_4;
    int64_t v_5;
    char *unaff_RSI;
    int64_t unaff_RDI;
    uint32_t *v_6;
    uint32_t local_0x150;
    uint8_t local_0x14a [18];
    uint64_t local_0x138 [6];
    uint64_t local_0x108;
    int64_t local_0xe0;
    int64_t local_0xd8;
    int64_t local_0xd0;
    int64_t local_0xc8;
    uint64_t local_0xb8;
    int64_t local_0x80;
    char *local_0x40;
    int64_t local_0x38;
    v_4 = local_0x138;
    for (v_5 = 0x4c; v_5 != 0; v_5 += -1) {
        *(uint32_t *)v_4 = 0;
        v_4 = (uint64_t *)((int64_t)v_4 + 4);
    }
    v_5 = 0;
    do {
        v_1 = v_5 * 8;
        v_5 += 1;
    } while (*(int64_t *)(unaff_RDI + v_1) != 0);
    ptr_0x713788 = (uint64_t *)(unaff_RDI + v_5 * 8);
    for (v_4 = ptr_0x713788; v_3 = *v_4, v_3 != 0; v_4 = v_4 + 2) {
        if (v_3 < 0x26) {
            local_0x138[v_3] = v_4[1];
        }
    }
    ptr_0x7137e8 = local_0xb8;
    if (local_0x38 != 0) {
        ptr_0x713fa0 = local_0x38;
    }
    ptr_0x7137b0 = local_0x108;
    ptr_0x713640 = unaff_RSI;
    ptr_0x713648 = unaff_RSI;
    if ((unaff_RSI == (char *)0x0) && 
           (unaff_RSI = local_0x40, ptr_0x713640 = local_0x40, ptr_0x713648 = local_0x40,
           local_0x40 == (char *)0x0)) {
        unaff_RSI = "";
        ptr_0x713640 = unaff_RSI;
        ptr_0x713648 = unaff_RSI;
    }
    while( true ) {
        v_2 = *unaff_RSI;
        unaff_RSI = unaff_RSI + 1;
        if (v_2 == '\0') break;
        if (v_2 == '/') {
            ptr_0x713648 = unaff_RSI;
        }
    }
    ptr_0x713620 = unaff_RDI;
    func_0x4d62b5();
    func_0x4bec22();
    if (((local_0xe0 != local_0xd8) || (local_0xd0 != local_0xc8)) || (local_0x80 != 0)) {
        v_6 = &local_0x150;
        for (v_5 = 6; v_5 != 0; v_5 += -1) {
            *v_6 = 0;
            v_6 = v_6 + 1;
        }
        local_0x14a[2] = 1;
        local_0x14a[3] = 0;
        local_0x14a[4] = 0;
        local_0x14a[5] = 0;
        local_0x14a[10] = 2;
        local_0x14a[0xb] = 0;
        local_0x14a[0xc] = 0;
        local_0x14a[0xd] = 0;
        syscall();
        v_5 = 0;
        do {
            if ((local_0x14a[v_5 * 8] & 0x20) != 0) {
                syscall();
            }
            v_5 += 1;
        } while (v_5 != 3);
        ptr_0x713782 = 1;
    }
    return;
}

void __fastcall func_0x4bed94()
{
    uint64_t *v_1;
    func_0x400120();
    for (v_1 = (uint64_t *)0x711fe0; v_1 < (uint64_t *)0x711fe0; v_1 = v_1 + 1) {
        (*(code *)*v_1)();
    }
    return;
}




void __fastcall func_0x400130()
{
    func_0x4bf206();
    sub_0x4bf207();
    func_0x4d9612();
    func_0x4d6437();
    return;
}

void __fastcall func_0x4bf206()
{
    return;
}

uint64_t __fastcall sub_0x4bf207()
{
    uint64_t *v_1;
    v_1 = (uint64_t *)0x711fe0;
    while ((uint64_t *)0x711fe0 < v_1) {
        v_1 = v_1 + -1;
        (*(code *)*v_1)();
    }
    func_0x4001d0();
    return 0;
}

void __fastcall func_0x4d9612(uint64_t param_1)
{
    int64_t *v_1;
    int64_t v_2;
    v_1 = (int64_t *)func_0x4cfc86();
    for (v_2 = *v_1; v_2 != 0; v_2 = *(int64_t *)(v_2 + 0x70)) {
        func_0x4d95c4();
    }
    func_0x4d95c4();
    func_0x4d95c4();
    v_2 = ptr_0x7122f8;
    if (ptr_0x7122f8 == 0) {
        return;
    }
    if (-1 < *(int32_t *)(ptr_0x7122f8 + 0x8c)) {
        func_0x4ce882();
    }
    if (*(int64_t *)(v_2 + 0x28) != *(int64_t *)(v_2 + 0x38)) {
        (**(code **)(v_2 + 0x48))(param_1,0);
    }
    if (*(int64_t *)(v_2 + 8) != *(int64_t *)(v_2 + 0x10)) {
                    
                    
        (**(code **)(v_2 + 0x50))(param_1,1);
        return;
    }
    return;
}

void __fastcall func_0x4d6437()
{
    syscall();
    do {
        syscall();
    } while( true );
}

uint64_t __fastcall func_0x4cfc86()
{
    func_0x4d357d();
    return 0x713698;
}

void __fastcall func_0x4d95c4(uint64_t param_1)
{
    int64_t unaff_RDI;
    if (unaff_RDI == 0) {
        return;
    }
    if (-1 < *(int32_t *)(unaff_RDI + 0x8c)) {
        func_0x4ce882();
    }
    if (*(int64_t *)(unaff_RDI + 0x28) != *(int64_t *)(unaff_RDI + 0x38)) {
        (**(code **)(unaff_RDI + 0x48))(param_1,0);
    }
    if (*(int64_t *)(unaff_RDI + 8) != *(int64_t *)(unaff_RDI + 0x10)) {
                    
                    
        (**(code **)(unaff_RDI + 0x50))(param_1,1);
        return;
    }
    return;
}



uint64_t __fastcall func_0x4ce882()
{
    uint32_t *v_1;
    uint32_t v_2;
    uint32_t v_3;
    uint32_t v_4;
    int64_t unaff_RDI;
    uint64_t v_5;
    int64_t *arg_fs_offset;
    v_2 = *(uint32_t *)(*arg_fs_offset + 0x30);
    if ((*(uint32_t *)(unaff_RDI + 0x8c) & 0xbfffffff) == v_2) {
        v_5 = 0;
    }
    else {
        v_1 = (uint32_t *)(unaff_RDI + 0x8c);
        LOCK();
        v_3 = *(uint32_t *)(unaff_RDI + 0x8c);
        if (v_3 == 0) {
            *(uint32_t *)(unaff_RDI + 0x8c) = v_2;
            v_3 = 0;
        }
        UNLOCK();
        if (v_3 != 0) {
code_0x4ce8d1:
            LOCK();
            v_3 = *v_1;
            if (v_3 == 0) {
                *v_1 = v_2 | 0x40000000;
                v_3 = 0;
            }
            UNLOCK();
            if (v_3 == 0) {
                return 1;
            }
            if ((v_3 >> 0x1e & 1) == 0) goto code_0x4ce919;
            goto code_0x4ce8f9;
        }
        v_5 = 1;
    }
    return v_5;
    
code_0x4ce919:
    LOCK();
    v_4 = *v_1;
    if (v_3 == v_4) {
        *v_1 = v_3 | 0x40000000;
        v_4 = v_3;
    }
    UNLOCK();
    if (v_4 == v_3) {
code_0x4ce8f9:
        syscall();
    }
    goto code_0x4ce8d1;
}



void __fastcall func_0x4d357d()
{
    char v_1;
    int32_t v_2;
    int32_t v_3;
    int32_t v_4;
    int32_t *unaff_RDI;
    v_1 = ptr_0x713783;
    if (ptr_0x713783 != '\0') {
        LOCK();
        v_3 = *unaff_RDI;
        if (v_3 == 0) {
            *unaff_RDI = -0x7fffffff;
            v_3 = 0;
        }
        UNLOCK();
        if (v_1 < '\0') {
            ptr_0x713783 = '\0';
        }
        if (v_3 != 0) {
            v_4 = 10;
            while( true ) {
                if (v_3 < 0) {
                    v_3 += 0x7fffffff;
                }
                LOCK();
                v_2 = *unaff_RDI;
                if (v_3 == v_2) {
                    *unaff_RDI = v_3 + -0x7fffffff;
                    v_2 = v_3;
                }
                UNLOCK();
                if (v_3 == v_2) break;
                v_4 += -1;
                v_3 = v_2;
                if (v_4 == 0) {
                    LOCK();
                    v_3 = *unaff_RDI;
                    *unaff_RDI = *unaff_RDI + 1;
                    UNLOCK();
                    v_3 += 1;
                    do {
                        v_4 = v_3;
                        if (v_3 < 0) {
                            syscall();
                            v_4 = v_3 + 0x7fffffff;
                        }
                        LOCK();
                        v_3 = *unaff_RDI;
                        if (v_4 == v_3) {
                            *unaff_RDI = v_4 + -0x80000000;
                            v_3 = v_4;
                        }
                        UNLOCK();
                    } while (v_4 != v_3);
                    return;
                }
            }
        }
    }
    return;
}





void __fastcall func_0x4001d0()
{
    if (ptr_0x712360 != '\0') {
        return;
    }
    func_0x400160();
    ptr_0x712360 = 1;
    return;
}




void __fastcall func_0x400160()
{
    return;
}

uint64_t __fastcall func_0x400120()
{
    uint64_t arg_rax;
    func_0x400260();
    func_0x403870();
    return arg_rax;
}





void __fastcall func_0x400260()
{
    return;
}

void __fastcall func_0x403870()
{
    code *v_1;
    int64_t v_2;
    if (ptr_0x711fe0 != (code *)0xffffffffffffffff) {
        v_2 = 0x711fe0;
        v_1 = ptr_0x711fe0;
        do {
            (*v_1)();
            v_1 = *(code **)(v_2 + -8);
            v_2 += -8;
        } while (v_1 != (code *)0xffffffffffffffff);
        return;
    }
    return;
}



void __fastcall func_0x4d62b5()
{
    bool v_1;
    int32_t v_2;
    int32_t *v_3;
    int64_t v_4;
    int32_t *v_5;
    int32_t *v_6;
    uint64_t v_7;
    uint64_t v_8;
    int64_t unaff_RDI;
    int64_t v_9;
    v_8 = (uint64_t)ptr_0x712344;
    v_1 = false;
    v_4 = 0;
    v_3 = *(int32_t **)(unaff_RDI + 0x18);
    v_5 = (int32_t *)0x0;
    for (v_9 = *(int64_t *)(unaff_RDI + 0x28); v_9 != 0; v_9 += -1) {
        v_2 = *v_3;
        v_6 = v_5;
        if (v_2 == 6) {
            v_4 = (int64_t)*(int32_t **)(unaff_RDI + 0x18) - *(int64_t *)(v_3 + 4);
        }
        else if ((((v_2 != 2) && (v_6 = v_3, v_2 != 7)) && (v_6 = v_5, v_2 == 0x6474e551))
                    && ((v_7 = *(uint64_t *)(v_3 + 10), (v_8 & 0xffffffff) < v_7 && 
                            (v_1 = true, v_8 = v_7, 0x800000 < v_7)))) {
            v_8 = 0x800000;
        }
        v_3 = (int32_t *)((int64_t)v_3 + *(int64_t *)(unaff_RDI + 0x20));
        v_5 = v_6;
    }
    if (v_1) {
        ptr_0x712344 = (uint32_t)v_8;
    }
    if (v_5 != (int32_t *)0x0) {
        ptr_0x713150 = *(uint64_t *)(v_5 + 8);
        ptr_0x713148 = v_4 + *(int64_t *)(v_5 + 4);
        ptr_0x713790 = 0x713140;
        ptr_0x713158 = *(int64_t *)(v_5 + 10);
        ptr_0x7137a8 = 1;
        ptr_0x713160 = *(uint64_t *)(v_5 + 0xc);
    }
    ptr_0x713168 = (-(ptr_0x713148 + ptr_0x713158) & ptr_0x713160 - 1) + ptr_0x713158;
    if (ptr_0x713160 < 8) {
        ptr_0x713160 = 8;
    }
    ptr_0x7137a0 = ptr_0x713160;
    ptr_0x713798 = ptr_0x713168 + 0xdf + ptr_0x713160 & 0xfffffffffffffff8;
    v_7 = ptr_0x713160;
    if (0x150 < ptr_0x713798) {
        v_8 = 0xffffffffffffffff;
        v_7 = 3;
        ptr_0x713158 = 0x4d641d;
        syscall();
    }
    v_9 = ptr_0x713158;
    ptr_0x713158 = ptr_0x713168;
    func_0x4d623c(v_9,v_7,v_8,0);
    v_2 = func_0x4d61d6();
    if (v_2 < 0) {
        do {
                    
        } while( true );
    }
    return;
}

void __fastcall func_0x4bec22()
{
    return;
}

uint64_t __fastcall func_0x4d623c()
{
    uint64_t *v_1;
    int64_t *unaff_RDI;
    uint64_t v_2;
    int64_t *v_3;
    v_2 = -ptr_0x7137a0 & (int64_t)unaff_RDI + ptr_0x713798 + -200;
    v_3 = unaff_RDI;
    for (v_1 = ptr_0x713790; v_3 = v_3 + 1, v_1 != (uint64_t *)0x0;
        v_1 = (uint64_t *)*v_1) {
        *v_3 = v_2 - v_1[5];
        func_0x4d321f();
    }
    *unaff_RDI = ptr_0x7137a8;
    *(int64_t **)(v_2 + 8) = unaff_RDI;
    return v_2;
}

uint64_t __fastcall func_0x4d61d6()
{
    int32_t v_1;
    uint64_t v_2;
    int64_t unaff_RDI;
    *(int64_t *)unaff_RDI = unaff_RDI;
    v_1 = func_0x4d8758();
    v_2 = 0xffffffff;
    if (-1 < v_1) {
        if (v_1 == 0) {
            ptr_0x713780 = 1;
        }
        *(uint32_t *)(unaff_RDI + 0x38) = 1;
        syscall();
        *(uint32_t *)(unaff_RDI + 0x30) = 0xda;
        *(int64_t *)(unaff_RDI + 0x88) = unaff_RDI + 0x88;
        v_2 = ptr_0x713fa0;
        *(uint64_t *)(unaff_RDI + 0xa8) = 0x7137b8;
        *(int64_t *)(unaff_RDI + 0x10) = unaff_RDI;
        *(int64_t *)(unaff_RDI + 0x18) = unaff_RDI;
        *(uint64_t *)(unaff_RDI + 0x20) = v_2;
        v_2 = 0;
    }
    return v_2;
}

uint64_t __fastcall func_0x4d8758()
{
    syscall();
    return 0x9e;
}

void __fastcall func_0x4d321f(uint64_t param_1, uint64_t param_2)
{
    uint64_t v_1;
    uint32_t v_2;
    uint64_t *unaff_RSI;
    uint64_t *unaff_RDI;
    if (7 < param_2) {
        for (; ((uint64_t)unaff_RDI & 7) != 0;
            unaff_RDI = (uint64_t *)((int64_t)unaff_RDI + 1)) {
            *(uint8_t *)unaff_RDI = *(uint8_t *)unaff_RSI;
            param_2 -= 1;
            unaff_RSI = (uint64_t *)((int64_t)unaff_RSI + 1);
        }
    }
    for (v_1 = param_2 >> 3; v_1 != 0; v_1 -= 1) {
        *unaff_RDI = *unaff_RSI;
        unaff_RSI = unaff_RSI + 1;
        unaff_RDI = unaff_RDI + 1;
    }
    v_2 = (uint32_t)param_2 & 7;
    if ((param_2 & 7) != 0) {
        do {
            *(uint8_t *)unaff_RDI = *(uint8_t *)unaff_RSI;
            v_2 -= 1;
            unaff_RSI = (uint64_t *)((int64_t)unaff_RSI + 1);
            unaff_RDI = (uint64_t *)((int64_t)unaff_RDI + 1);
        } while (v_2 != 0);
    }
    return;
}

uint64_t __fastcall func_0x400290()
{
    int32_t *v_1;
    uint64_t unaff_RDI;
    if (unaff_RDI < 0xfffffffffffff001) {
        return unaff_RDI;
    }
    v_1 = (int32_t *)func_0x4bf1be();
    *v_1 = -(int32_t)unaff_RDI;
    return 0xffffffffffffffff;
}

uint64_t __fastcall func_0x4002a0()
{
    int32_t *v_1;
    int32_t unaff_EDI;
    v_1 = (int32_t *)func_0x4bf1be();
    *v_1 = -unaff_EDI;
    return 0xffffffffffffffff;
}

uint64_t * __fastcall func_0x4002d0()
{
    int64_t v_1;
    uint8_t v_2 [16];
    uint8_t v_3 [16];
    int32_t v_4;
    uint64_t *v_5;
    int64_t v_6;
    uint32_t *v_7;
    uint32_t v_8;
    uint64_t v_9;
    uint64_t unaff_RSI;
    uint64_t unaff_RDI;
    uint64_t *v_10;
    uint64_t v_11;
    if ((unaff_RSI == 0) || 
           (v_2._8_8_ = 0, v_2._0_8_ = unaff_RDI, v_3._8_8_ = 0, v_3._0_8_ = unaff_RSI,
           SUB168(v_2 * v_3,8) == 0)) {
        v_11 = unaff_RDI * unaff_RSI;
        v_5 = (uint64_t *)func_0x4c0959();
        if ((v_5 != (uint64_t *)0x0) && 
               ((ptr_0x713fc4 != 0 || (v_4 = func_0x4c0b57(), v_4 == 0)))) {
            if (0xfff < v_11) {
code_0x400340:
                v_6 = func_0x4d3276();
                v_11 = v_6 - (int64_t)v_5;
                if (0xfff < v_11) {
                    v_1 = v_6 + -0x1000;
                    do {
                        if (*(int64_t *)(v_6 + -8) != 0 || *(int64_t *)(v_6 + -0x10) != 0)
                        break;
                        v_6 += -0x10;
                    } while (v_1 != v_6);
                    goto code_0x400340;
                }
            }
            v_8 = (uint32_t)v_11;
            if (0x7e < v_11) {
                *(uint64_t *)((int64_t)v_5 + (v_11 - 8)) = 0;
                v_10 = v_5;
                if (((uint64_t)v_5 & 0xf) != 0) {
                    v_9 = (uint64_t)(-(int32_t)v_5 & 0xf);
                    *v_5 = 0;
                    v_5[1] = 0;
                    v_11 -= v_9;
                    v_10 = (uint64_t *)((int64_t)v_5 + v_9);
                }
                for (v_11 >>= 3; v_11 != 0; v_11 -= 1) {
                    *v_10 = 0;
                    v_10 = v_10 + 1;
                }
                return v_5;
            }
            if (v_8 != 0) {
                *(uint8_t *)v_5 = 0;
                *(uint8_t *)((int64_t)v_5 + (v_11 - 1)) = 0;
                if (2 < v_8) {
                    *(uint16_t *)((int64_t)v_5 + 1) = 0;
                    *(uint16_t *)((int64_t)v_5 + (v_11 - 3)) = 0;
                    if (6 < v_8) {
                        *(uint32_t *)((int64_t)v_5 + 3) = 0;
                        *(uint32_t *)((int64_t)v_5 + (v_11 - 7)) = 0;
                        if (0xe < v_8) {
                            *(uint64_t *)((int64_t)v_5 + 7) = 0;
                            *(uint64_t *)((int64_t)v_5 + (v_11 - 0xf)) = 0;
                            if (0x1e < v_8) {
                                *(uint64_t *)((int64_t)v_5 + 0xf) = 0;
                                *(uint64_t *)((int64_t)v_5 + 0x17) = 0;
                                *(uint64_t *)((int64_t)v_5 + (v_11 - 0x1f)) = 0;
                                *(uint64_t *)((int64_t)v_5 + (v_11 - 0x17)) = 0;
                                if (0x3e < v_8) {
                                    *(uint64_t *)((int64_t)v_5 + 0x1f) = 0;
                                    *(uint64_t *)((int64_t)v_5 + 0x27) = 0;
                                    *(uint64_t *)((int64_t)v_5 + 0x2f) = 0;
                                    *(uint64_t *)((int64_t)v_5 + 0x37) = 0;
                                    *(uint64_t *)((int64_t)v_5 + (v_11 - 0x3f)) = 0;
                                    *(uint64_t *)((int64_t)v_5 + (v_11 - 0x37)) = 0;
                                    *(uint64_t *)((int64_t)v_5 + (v_11 - 0x2f)) = 0;
                                    *(uint64_t *)((int64_t)v_5 + (v_11 - 0x27)) = 0;
                                }
                            }
                        }
                    }
                }
            }
            return v_5;
        }
    }
    else {
        v_7 = (uint32_t *)func_0x4bf1be();
        v_5 = (uint64_t *)0x0;
        *v_7 = 0xc;
    }
    return v_5;
}

uint64_t * __fastcall func_0x4003c0(uint64_t param_1, uint64_t param_2)
{
    uint64_t v_1;
    uint8_t unaff_SIL;
    uint32_t v_2;
    uint64_t *unaff_RDI;
    uint64_t *v_3;
    v_2 = (uint32_t)unaff_SIL;
    for (; ((uint64_t)unaff_RDI & 7) != 0;
        unaff_RDI = (uint64_t *)((int64_t)unaff_RDI + 1)) {
        if (param_2 == 0) {
            return (uint64_t *)0x0;
        }
        if ((uint8_t)*unaff_RDI == v_2) goto code_0x400453;
        param_2 -= 1;
    }
    if (param_2 != 0) {
        if (((uint8_t)*unaff_RDI != v_2) && (7 < param_2)) {
            do {
                v_1 = *unaff_RDI ^ (int64_t)(int32_t)v_2 * 0x101010101010101;
                if ((~v_1 & v_1 + 0xfefefefefefefeff & 0x8080808080808080) != 0)
                goto code_0x400453;
                param_2 -= 8;
                unaff_RDI = unaff_RDI + 1;
            } while (7 < param_2);
            if (param_2 == 0) {
                return (uint64_t *)0x0;
            }
        }
code_0x400453:
        v_3 = (uint64_t *)((int64_t)unaff_RDI + param_2);
        do {
            if ((uint8_t)*unaff_RDI == v_2) {
                return unaff_RDI;
            }
            unaff_RDI = (uint64_t *)((int64_t)unaff_RDI + 1);
        } while (unaff_RDI != v_3);
    }
    return (uint64_t *)0x0;
}

int32_t __fastcall func_0x400490(uint64_t param_1, int64_t param_2)
{
    int64_t v_1;
    int64_t unaff_RSI;
    int64_t unaff_RDI;
    v_1 = 0;
    if (param_2 == 0) {
        return 0;
    }
    do {
        if (*(uint8_t *)(unaff_RDI + v_1) != *(uint8_t *)(unaff_RSI + v_1)) {
            return (uint32_t)*(uint8_t *)(unaff_RDI + v_1) -
                       (uint32_t)*(uint8_t *)(unaff_RSI + v_1);
        }
        v_1 += 1;
    } while (v_1 != param_2);
    return 0;
}

uint64_t __fastcall func_0x4004c0()
{
    return 0;
}

char * __fastcall func_0x4004d0(uint64_t param_1, int64_t param_2)
{
    char *v_1;
    char *v_2;
    char unaff_SIL;
    int64_t unaff_RDI;
    v_1 = (char *)(unaff_RDI + -1 + param_2);
    do {
        v_2 = v_1;
        if (v_2 == (char *)(unaff_RDI + -1)) {
            return (char *)0x0;
        }
        v_1 = v_2 + -1;
    } while (*v_2 != unaff_SIL);
    return v_2;
}

void __fastcall func_0x400500()
{
    char v_1;
    uint64_t v_2;
    uint64_t v_3;
    uint64_t *unaff_RSI;
    uint64_t *unaff_RDI;
    if ((((uint32_t)unaff_RDI ^ (uint32_t)unaff_RSI) & 7) == 0) {
        for (; ((uint64_t)unaff_RSI & 7) != 0;
            unaff_RSI = (uint64_t *)((int64_t)unaff_RSI + 1)) {
            v_2 = *unaff_RSI;
            *(char *)unaff_RDI = (char)v_2;
            if ((char)v_2 == '\0') {
                return;
            }
            unaff_RDI = (uint64_t *)((int64_t)unaff_RDI + 1);
        }
        v_2 = *unaff_RSI;
        v_3 = v_2 + 0xfefefefefefefeff & ~v_2;
        while ((v_3 & 0x8080808080808080) == 0) {
            unaff_RSI = unaff_RSI + 1;
            *unaff_RDI = v_2;
            unaff_RDI = unaff_RDI + 1;
            v_2 = *unaff_RSI;
            v_3 = v_2 + 0xfefefefefefefeff & ~v_2;
        }
    }
    v_2 = *unaff_RSI;
    *(char *)unaff_RDI = (char)v_2;
    if ((char)v_2 != '\0') {
        do {
            v_1 = *(char *)((int64_t)unaff_RSI + 1);
            unaff_RSI = (uint64_t *)((int64_t)unaff_RSI + 1);
            unaff_RDI = (uint64_t *)((int64_t)unaff_RDI + 1);
            *(char *)unaff_RDI = v_1;
        } while (v_1 != '\0');
        return;
    }
    return;
}

uint64_t * __fastcall func_0x4005b0(uint64_t param_1, uint64_t param_2)
{
    uint64_t v_1;
    uint64_t *unaff_RSI;
    uint64_t *unaff_RDI;
    if ((((uint64_t)unaff_RDI ^ (uint64_t)unaff_RSI) & 7) == 0) {
        for (; ((uint64_t)unaff_RSI & 7) != 0;
            unaff_RSI = (uint64_t *)((int64_t)unaff_RSI + 1)) {
            if ((param_2 == 0) || 
                   (v_1 = *unaff_RSI, *(char *)unaff_RDI = (char)v_1, (char)v_1 == '\0'))
            goto code_0x4005e9;
            param_2 -= 1;
            unaff_RDI = (uint64_t *)((int64_t)unaff_RDI + 1);
        }
        if ((param_2 == 0) || ((char)*unaff_RSI == '\0')) goto code_0x4005e9;
        if (7 < param_2) {
            do {
                v_1 = *unaff_RSI;
                if ((v_1 + 0xfefefefefefefeff & ~v_1 & 0x8080808080808080) != 0)
                goto code_0x4005de;
                param_2 -= 8;
                *unaff_RDI = v_1;
                unaff_RSI = unaff_RSI + 1;
                unaff_RDI = unaff_RDI + 1;
            } while (7 < param_2);
            goto code_0x4005bf;
        }
    }
    else {
code_0x4005bf:
        if (param_2 == 0) goto code_0x4005e9;
    }
code_0x4005de:
    do {
        v_1 = *unaff_RSI;
        *(char *)unaff_RDI = (char)v_1;
        if ((char)v_1 == '\0') break;
        unaff_RSI = (uint64_t *)((int64_t)unaff_RSI + 1);
        unaff_RDI = (uint64_t *)((int64_t)unaff_RDI + 1);
        param_2 -= 1;
    } while (param_2 != 0);
code_0x4005e9:
    func_0x4d3276();
    return unaff_RDI;
}

int32_t __fastcall func_0x400690()
{
    char v_1;
    int32_t v_2;
    int32_t v_3;
    char *unaff_RSI;
    char *unaff_RDI;
    v_1 = *unaff_RDI;
    for (; (v_1 != '\0' && (*unaff_RSI != '\0')); unaff_RSI = unaff_RSI + 1) {
        if (*unaff_RSI != v_1) {
            v_2 = func_0x4d60cc();
            v_3 = func_0x4d60cc();
            if (v_2 != v_3) break;
        }
        v_1 = unaff_RDI[1];
        unaff_RDI = unaff_RDI + 1;
    }
    v_2 = func_0x4d60cc();
    v_3 = func_0x4d60cc();
    return v_2 - v_3;
}

char * __fastcall func_0x400700(uint64_t param_1)
{
    char v_1;
    int32_t v_2;
    uint64_t v_3;
    char *unaff_RDI;
    v_3 = func_0x4009f0();
    v_1 = *unaff_RDI;
    while( true ) {
        if (v_1 == '\0') {
            return (char *)0x0;
        }
        v_2 = func_0x400a70(param_1,v_3);
        if (v_2 == 0) break;
        unaff_RDI = unaff_RDI + 1;
        v_1 = *unaff_RDI;
    }
    return unaff_RDI;
}

void __fastcall func_0x400750()
{
    func_0x4009f0();
    func_0x4008d0();
    return;
}

char * __fastcall func_0x400780()
{
    char *v_1;
    char unaff_SIL;
    v_1 = (char *)func_0x4007a0();
    if (*v_1 != unaff_SIL) {
        v_1 = (char *)0x0;
    }
    return v_1;
}

uint64_t * __fastcall func_0x4007a0()
{
    uint64_t v_1;
    uint8_t v_2;
    int64_t v_3;
    uint64_t v_4;
    uint32_t unaff_ESI;
    uint32_t v_5;
    uint64_t *unaff_RDI;
    v_5 = unaff_ESI & 0xff;
    if (v_5 == 0) {
        v_3 = func_0x4009f0();
        return (uint64_t *)((int64_t)unaff_RDI + v_3);
    }
    while( true ) {
        if (((uint64_t)unaff_RDI & 7) == 0) {
            v_1 = *unaff_RDI;
            v_4 = (int64_t)(int32_t)v_5 * 0x101010101010101 ^ v_1;
            if (((v_1 + 0xfefefefefefefeff & ~v_1 | ~v_4 & v_4 + 0xfefefefefefefeff) &
                    0x8080808080808080) != 0) goto code_0x400870;
            do {
                v_1 = unaff_RDI[1];
                unaff_RDI = unaff_RDI + 1;
                v_4 = v_1 ^ (int64_t)(int32_t)v_5 * 0x101010101010101;
            } while (((v_1 + 0xfefefefefefefeff & ~v_1 | ~v_4 & v_4 + 0xfefefefefefefeff)
                         & 0x8080808080808080) == 0);
            v_2 = (uint8_t)*unaff_RDI;
            while ((v_2 != 0 && (v_2 != v_5))) {
                unaff_RDI = (uint64_t *)((int64_t)unaff_RDI + 1);
code_0x400870:
                v_2 = (uint8_t)*unaff_RDI;
            }
            return unaff_RDI;
        }
        if ((uint8_t)*unaff_RDI == 0) break;
        if ((uint8_t)*unaff_RDI == v_5) {
            return unaff_RDI;
        }
        unaff_RDI = (uint64_t *)((int64_t)unaff_RDI + 1);
    }
    return unaff_RDI;
}

int32_t __fastcall func_0x400890()
{
    uint8_t *v_1;
    int64_t v_2;
    uint32_t v_3;
    uint8_t v_4;
    uint8_t *unaff_RSI;
    uint8_t *unaff_RDI;
    v_4 = *unaff_RDI;
    v_3 = (uint32_t)*unaff_RSI;
    v_2 = 1;
    if (*unaff_RSI == v_4) {
        do {
            if (v_4 == 0) {
                return -v_3;
            }
            v_4 = unaff_RDI[v_2];
            v_1 = unaff_RSI + v_2;
            v_3 = (uint32_t)*v_1;
            v_2 = v_2 + 1;
        } while (v_4 == *v_1);
    }
    return v_4 - v_3;
}

void __fastcall func_0x4008d0()
{
    func_0x400500();
    return;
}

int64_t __fastcall func_0x4008e0(uint64_t param_1)
{
    uint8_t v_1;
    uint8_t v_2;
    int64_t v_3;
    uint8_t *v_4;
    uint8_t v_5;
    uint8_t *unaff_RSI;
    uint8_t *unaff_RDI;
    uint64_t local_0x38 [5];
    if ((*unaff_RSI == 0) || (unaff_RSI[1] == 0)) {
        v_3 = func_0x4007a0();
        v_3 -= (int64_t)unaff_RDI;
    }
    else {
        func_0x4d3276(param_1,0x20);
        v_5 = *unaff_RSI;
        while (v_5 != 0) {
            unaff_RSI = unaff_RSI + 1;
            v_1 = v_5 & 0x3f;
            v_2 = v_5 >> 6;
            v_5 = *unaff_RSI;
            local_0x38[v_2] = local_0x38[v_2] | 1LL << v_1;
        }
        v_5 = *unaff_RDI;
        v_4 = unaff_RDI;
        if (v_5 != 0) {
            do {
                if ((local_0x38[v_5 >> 6] >> (v_5 & 0x3f) & 1) != 0) break;
                v_5 = v_4[1];
                v_4 = v_4 + 1;
            } while (v_5 != 0);
            return (int64_t)v_4 - (int64_t)unaff_RDI;
        }
        v_3 = 0;
    }
    return v_3;
}

uint64_t __fastcall func_0x40098a()
{
    return 0;
}

uint64_t * __fastcall func_0x4009a0()
{
    int64_t v_1;
    uint64_t *v_2;
    uint64_t *v_3;
    uint64_t v_4;
    uint32_t v_5;
    uint64_t v_6;
    uint64_t *unaff_RDI;
    v_1 = func_0x4009f0();
    v_6 = v_1 + 1;
    v_2 = (uint64_t *)func_0x4c0959();
    if (v_2 != (uint64_t *)0x0) {
        v_3 = v_2;
        if (7 < v_6) {
            for (; ((uint64_t)v_2 & 7) != 0; v_2 = (uint64_t *)((int64_t)v_2 + 1)) {
                *(uint8_t *)v_2 = *(uint8_t *)unaff_RDI;
                v_6 -= 1;
                unaff_RDI = (uint64_t *)((int64_t)unaff_RDI + 1);
            }
        }
        for (v_4 = v_6 >> 3; v_4 != 0; v_4 -= 1) {
            *v_2 = *unaff_RDI;
            unaff_RDI = unaff_RDI + 1;
            v_2 = v_2 + 1;
        }
        v_5 = (uint32_t)v_6 & 7;
        if ((v_6 & 7) != 0) {
            do {
                *(uint8_t *)v_2 = *(uint8_t *)unaff_RDI;
                v_5 -= 1;
                unaff_RDI = (uint64_t *)((int64_t)unaff_RDI + 1);
                v_2 = (uint64_t *)((int64_t)v_2 + 1);
            } while (v_5 != 0);
        }
        return v_3;
    }
    return (uint64_t *)0x0;
}

int64_t __fastcall func_0x4009f0()
{
    uint64_t *v_1;
    uint64_t *v_2;
    uint64_t v_3;
    uint8_t unaff_DIL;
    uint64_t unaff_RDI;
    v_2 = (uint64_t *)(unaff_RDI << 8 | unaff_DIL);
    if ((unaff_DIL & 7) != 0) {
        do {
            if ((char)*v_2 == '\0') {
                return (int64_t)v_2 - (unaff_RDI << 8 | unaff_DIL);
            }
            v_2 = (uint64_t *)((int64_t)v_2 + 1);
        } while (((uint64_t)v_2 & 7) != 0);
    }
    v_3 = ~*v_2 & *v_2 + 0xfefefefefefefeff;
    while ((v_3 & 0x8080808080808080) == 0) {
        v_1 = v_2 + 1;
        v_2 = v_2 + 1;
        v_3 = ~*v_1 & *v_1 + 0xfefefefefefefeff;
    }
    for (; (char)*v_2 != '\0'; v_2 = (uint64_t *)((int64_t)v_2 + 1)) {
    }
    return (int64_t)v_2 - (unaff_RDI << 8 | unaff_DIL);
}

int32_t __fastcall func_0x400a70(uint64_t param_1, int64_t param_2)
{
    char v_1;
    int32_t v_2;
    int32_t v_3;
    char *unaff_RSI;
    char v_4;
    char *unaff_RDI;
    char *v_5;
    if (param_2 == 0) {
        return 0;
    }
    v_4 = *unaff_RDI;
    if (v_4 != '\0') {
        v_1 = *unaff_RSI;
        if ((param_2 != 1) && (v_5 = unaff_RSI + param_2 + -1, v_1 != '\0')) {
            do {
                if (v_4 != v_1) {
                    v_2 = func_0x4d60cc();
                    v_3 = func_0x4d60cc();
                    if (v_2 != v_3) break;
                }
                v_4 = unaff_RDI[1];
                unaff_RDI = unaff_RDI + 1;
                unaff_RSI = unaff_RSI + 1;
                if (((v_4 == '\0') || (v_1 = *unaff_RSI, unaff_RSI == v_5)) || 
                       (v_1 == '\0')) break;
            } while( true );
        }
    }
    v_2 = func_0x4d60cc();
    v_3 = func_0x4d60cc();
    return v_2 - v_3;
}

uint64_t __fastcall func_0x400b08()
{
    return 0;
}

int32_t __fastcall func_0x400b20(uint64_t param_1, int64_t param_2)
{
    uint8_t v_1;
    uint8_t v_2;
    uint32_t v_3;
    int32_t v_4;
    int64_t v_5;
    uint8_t *unaff_RSI;
    uint8_t *unaff_RDI;
    uint32_t v_6;
    bool v_7;
    v_4 = 0;
    if (param_2 != 0) {
        v_1 = *unaff_RDI;
        v_2 = *unaff_RSI;
        v_6 = (uint32_t)v_2;
        v_3 = (uint32_t)v_2;
        if (v_1 == 0) {
code_0x400b88:
            v_6 = v_3;
            v_3 = 0;
        }
        else if ((param_2 == 1 || v_2 == 0) || (v_5 = 1, v_1 != v_2)) {
            v_3 = (uint32_t)v_1;
        }
        else {
            do {
                v_1 = unaff_RDI[v_5];
                v_2 = unaff_RSI[v_5];
                v_6 = (uint32_t)v_2;
                v_3 = v_6;
                if (v_1 == 0) goto code_0x400b88;
                v_7 = param_2 + -1 != v_5;
                v_5 += 1;
            } while ((v_2 != 0 && v_1 == v_2) && v_7);
            v_3 = (uint32_t)v_1;
        }
        v_4 = v_3 - v_6;
    }
    return v_4;
}

int32_t __fastcall func_0x400b88(uint64_t param_1, uint64_t param_2, int32_t param_3)
{
    return -param_3;
}

void __fastcall func_0x400ba0()
{
    func_0x4005b0();
    return;
}

int64_t __fastcall func_0x400bb0(uint64_t param_1)
{
    int64_t v_1;
    int64_t v_2;
    v_1 = func_0x400bf0();
    v_2 = func_0x4c0959();
    if (v_2 != 0) {
        func_0x4d321f(param_1,v_1);
        *(uint8_t *)(v_2 + v_1) = 0;
    }
    return v_2;
}

void __fastcall func_0x400bf0()
{
    func_0x4003c0();
    return;
}

