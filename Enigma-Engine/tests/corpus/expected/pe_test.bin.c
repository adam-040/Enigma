void __fastcall entry()
{
  uRam00000001402385a0 = 0;
  func_pdata_0x140001010();
  return;
}




uint8 __fastcall func_pdata_0x140001010()
{
  int8 iVar1;
  int4 iVar2;
  int4 iVar3;
  uint64_t *puVar4;
  uint8 uVar5;
  uint32_t *puVar6;
  uint64_t *puVar7;
  void *pvVar8;
  uint8 extraout_RAX;
  uint64_t *puVar9;
  uint8 extraout_RAX_00;
  int8 iVar10;
  int8 iVar11;
  int8 unaff_GS_OFFSET;
  bool bVar12;
  uint32_t auStack_4c [3];
  
  iVar11 = *(int8 *)(*(int8 *)(unaff_GS_OFFSET + 0x30) + 8);
  while( true ) {
    iVar10 = 0;
    LOCK();
    bVar12 = iRam0000000140238550 == 0;
    iVar1 = iVar11;
    if (!bVar12) {
      iVar10 = iRam0000000140238550;
      iVar1 = iRam0000000140238550;
    }
    iRam0000000140238550 = iVar1;
    UNLOCK();
    if (bVar12) {
      bVar12 = false;
      goto code_r0x00014000105c;
    }
    if (iVar11 == iVar10) break;
    Sleep(1000);
  }
  bVar12 = true;
code_r0x00014000105c:
  if (iRam0000000140238558 == 1) {
    _amsg_exit(0x1f);
    uVar5 = extraout_RAX_00;
    goto code_r0x0001400013d2;
  }
  if (iRam0000000140238558 == 0) {
    iRam0000000140238558 = 1;
    func_pdata_0x1400b8cd0();
    pvRam00000001402385e0 = SetUnhandledExceptionFilter(func_pdata_0x1400b90b0);
    func_pdata_0x1400b99f0();
    func_pdata_0x1400b9520();
    uRam0000000140238588 = 1;
    uRam0000000140238584 = 1;
    uRam0000000140238580 = 1;
    iRam0000000140234008 = 0;
    if (uRam00000001402385a0 == 0) {
      __set_app_type(1);
    }
    else {
      __set_app_type(2);
    }
    puVar6 = (uint32_t *)func_pdata_0x1400b99b0();
    *puVar6 = uRam00000001402385d0;
    puVar6 = (uint32_t *)func_pdata_0x1400b99c0();
    *puVar6 = uRam0000000140238590;
    iVar2 = func_pdata_0x1400b8940();
    if (-1 < iVar2) {
      if (iRam0000000140194090 == 1) {
        func_pdata_0x1400b90a0(func_pdata_0x1400b8a00);
      }
      if (iRam0000000140194070 == -1) {
        func_pdata_0x1400b9a00(0xffffffff);
      }
      iVar2 = func_pdata_0x1400b9970(0x1401d5d68,0x1401d5d70);
      if (iVar2 != 0) {
        return 0xff;
      }
      auStack_4c[0] = uRam0000000140238570;
      iVar3 = __getmainargs(0x140234020,0x140234018,0x140234010,uRam0000000140238560,auStack_4c);
      iVar2 = iRam0000000140234020;
      if (-1 < iVar3) {
        iVar11 = (int8)iRam0000000140234020;
        puVar7 = malloc((int8)(iRam0000000140234020 + 1) << 3);
        puVar4 = puRam0000000140234018;
        if (puVar7 != (uint64_t *)0x0) {
          puVar9 = puVar7;
          if (iVar2 < 1) {
code_r0x00014000134c:
            *puVar9 = 0;
            puRam0000000140234018 = puVar7;
            _initterm((void *)0x1401d5d58,(void *)0x1401d5d60);
            func_pdata_0x1400b8920();
            iRam0000000140238558 = 2;
            goto code_r0x000140001084;
          }
          iVar10 = 1;
          while( true ) {
            uVar5 = strlen((char *)puVar4[iVar10 + -1]);
            pvVar8 = malloc(uVar5 + 1);
            puVar7[iVar10 + -1] = pvVar8;
            if (pvVar8 == (void *)0x0) break;
            memcpy(pvVar8,(void *)puVar4[iVar10 + -1],uVar5 + 1);
            if (iVar11 == iVar10) {
              puVar9 = puVar7 + iVar11;
              goto code_r0x00014000134c;
            }
            iVar10 += 1;
          }
        }
      }
    }
    _amsg_exit(8);
    uVar5 = extraout_RAX;
  }
  else {
    iRam0000000140234004 = 1;
code_r0x000140001084:
    if (!bVar12) {
      LOCK();
      iRam0000000140238550 = 0;
      UNLOCK();
    }
    func_pdata_0x1400b8970(0,2,0);
    puVar4 = (uint64_t *)func_pdata_0x1400b99d0();
    iVar2 = iRam0000000140234020;
    *puVar4 = uRam0000000140234010;
    uVar5 = func_pdata_0x1400015aa(iVar2,puRam0000000140234018);
    if (iRam0000000140234008 == 0) {
code_r0x0001400013d2:
                    
      exit((int4)uVar5);
    }
    if (iRam0000000140234004 != 0) {
      return uVar5;
    }
  }
  _cexit();
  return uVar5 & 0xffffffff;
}



void __fastcall Sleep(int4 param_1)
{
  char *pcVar1;
  uint1 *puVar2;
  code *pcVar3;
  uint1 in_AL;
  uint1 uVar4;
  uint1 uVar5;
  char cVar6;
  char extraout_AL;
  uint1 in_AH;
  uint8_t extraout_AH;
  uint16_t in_register_00000002;
  uint16_t extraout_var;
  uint32_t in_register_00000004;
  uint32_t extraout_var_00;
  uint1 uVar7;
  char *in_RDX;
  char unaff_BL;
  char *unaff_RDI;
  char *unaff_retaddr;
  
  uVar4 = *(uint1 *)CONCAT44(in_register_00000004,
                             CONCAT22(in_register_00000002,CONCAT11(in_AH,in_AL)));
  *(uint1 *)CONCAT44(in_register_00000004,CONCAT22(in_register_00000002,CONCAT11(in_AH,in_AL))) =
       *(char *)CONCAT44(in_register_00000004,CONCAT22(in_register_00000002,CONCAT11(in_AH,in_AL)))
       + in_AL;
  pcVar1 = (char *)(CONCAT44(in_register_00000004,
                             CONCAT22(in_register_00000002,CONCAT11(in_AH,0xfd))) + 1);
  *pcVar1 = *pcVar1 + -3 + CARRY1(uVar4,in_AL);
  *(char *)CONCAT44(in_register_00000004,CONCAT22(in_register_00000002,CONCAT11(in_AH,0xfd))) =
       *(char *)CONCAT44(in_register_00000004,CONCAT22(in_register_00000002,CONCAT11(in_AH,0xfd))) +
       -3;
  cVar6 = (char)((uint4)param_1 >> 8);
  *in_RDX = *in_RDX + cVar6;
  *(char *)CONCAT44(in_register_00000004,CONCAT22(in_register_00000002,CONCAT11(in_AH,0xfd))) =
       *(char *)CONCAT44(in_register_00000004,CONCAT22(in_register_00000002,CONCAT11(in_AH,0xfd))) +
       -3;
  *(char *)CONCAT44(in_register_00000004,CONCAT22(in_register_00000002,CONCAT11(in_AH,0xfd))) =
       *(char *)CONCAT44(in_register_00000004,CONCAT22(in_register_00000002,CONCAT11(in_AH,0xfd))) +
       -3;
  *(char *)CONCAT44(in_register_00000004,CONCAT22(in_register_00000002,CONCAT11(in_AH,0xfd))) =
       *(char *)CONCAT44(in_register_00000004,CONCAT22(in_register_00000002,CONCAT11(in_AH,0xfd))) +
       -3;
  puVar2 = (uint1 *)(CONCAT44(in_register_00000004,
                              CONCAT22(in_register_00000002,CONCAT11(in_AH,0xfd))) + -0x5e);
  uVar4 = *puVar2;
  uVar7 = (uint1)((uint8)in_RDX >> 8);
  *puVar2 = *puVar2 + uVar7;
  uVar4 = *(char *)(CONCAT44(in_register_00000004,
                             CONCAT22(in_register_00000002,CONCAT11(in_AH,0xfd))) + 1) + -3 +
          CARRY1(uVar4,uVar7);
  *(uint1 *)CONCAT44(in_register_00000004,CONCAT22(in_register_00000002,CONCAT11(in_AH,uVar4))) =
       *(char *)CONCAT44(in_register_00000004,CONCAT22(in_register_00000002,CONCAT11(in_AH,uVar4)))
       + uVar4;
  *unaff_RDI = *unaff_RDI + unaff_BL;
  *(uint1 *)CONCAT44(in_register_00000004,CONCAT22(in_register_00000002,CONCAT11(in_AH,uVar4))) =
       *(char *)CONCAT44(in_register_00000004,CONCAT22(in_register_00000002,CONCAT11(in_AH,uVar4)))
       + uVar4;
  *(uint1 *)CONCAT44(in_register_00000004,CONCAT22(in_register_00000002,CONCAT11(in_AH,uVar4))) =
       *(char *)CONCAT44(in_register_00000004,CONCAT22(in_register_00000002,CONCAT11(in_AH,uVar4)))
       + uVar4;
  *(uint1 *)CONCAT44(in_register_00000004,CONCAT22(in_register_00000002,CONCAT11(in_AH,uVar4))) =
       *(char *)CONCAT44(in_register_00000004,CONCAT22(in_register_00000002,CONCAT11(in_AH,uVar4)))
       + uVar4;
  uVar5 = uVar4 + in_AH +
          *(char *)(int8)(CONCAT22(in_register_00000002,CONCAT11(in_AH,uVar4 + in_AH)) + 1) +
          CARRY1(uVar4,in_AH);
  *(uint1 *)CONCAT44(in_register_00000004,CONCAT22(in_register_00000002,CONCAT11(in_AH,uVar5))) =
       *(char *)CONCAT44(in_register_00000004,CONCAT22(in_register_00000002,CONCAT11(in_AH,uVar5)))
       + uVar5;
  *unaff_RDI = *unaff_RDI + unaff_BL;
  *(uint1 *)CONCAT44(in_register_00000004,CONCAT22(in_register_00000002,CONCAT11(in_AH,uVar5))) =
       *(char *)CONCAT44(in_register_00000004,CONCAT22(in_register_00000002,CONCAT11(in_AH,uVar5)))
       + uVar5;
  *(uint1 *)CONCAT44(in_register_00000004,CONCAT22(in_register_00000002,CONCAT11(in_AH,uVar5))) =
       *(char *)CONCAT44(in_register_00000004,CONCAT22(in_register_00000002,CONCAT11(in_AH,uVar5)))
       + uVar5;
  *(uint1 *)CONCAT44(in_register_00000004,CONCAT22(in_register_00000002,CONCAT11(in_AH,uVar5))) =
       *(char *)CONCAT44(in_register_00000004,CONCAT22(in_register_00000002,CONCAT11(in_AH,uVar5)))
       + uVar5;
  puVar2 = (uint1 *)(CONCAT44(in_register_00000004,
                              CONCAT22(in_register_00000002,CONCAT11(in_AH,uVar5))) + -6);
  uVar4 = *puVar2;
  *puVar2 = *puVar2 + uVar5;
  pcVar1 = (char *)(CONCAT44(in_register_00000004,
                             CONCAT22(in_register_00000002,CONCAT11(in_AH,uVar5))) + 1);
  *pcVar1 = *pcVar1 + uVar5 + CARRY1(uVar4,uVar5);
  *(uint1 *)CONCAT44(in_register_00000004,CONCAT22(in_register_00000002,CONCAT11(in_AH,uVar5))) =
       *(char *)CONCAT44(in_register_00000004,CONCAT22(in_register_00000002,CONCAT11(in_AH,uVar5)))
       + uVar5;
  *in_RDX = *in_RDX + cVar6;
  *(uint1 *)CONCAT44(in_register_00000004,CONCAT22(in_register_00000002,CONCAT11(in_AH,uVar5))) =
       *(char *)CONCAT44(in_register_00000004,CONCAT22(in_register_00000002,CONCAT11(in_AH,uVar5)))
       + uVar5;
  *(uint1 *)CONCAT44(in_register_00000004,CONCAT22(in_register_00000002,CONCAT11(in_AH,uVar5))) =
       *(char *)CONCAT44(in_register_00000004,CONCAT22(in_register_00000002,CONCAT11(in_AH,uVar5)))
       + uVar5;
  *(uint1 *)CONCAT44(in_register_00000004,CONCAT22(in_register_00000002,CONCAT11(in_AH,uVar5))) =
       *(char *)CONCAT44(in_register_00000004,CONCAT22(in_register_00000002,CONCAT11(in_AH,uVar5)))
       + uVar5;
  pcVar1 = (char *)(CONCAT44(in_register_00000004,
                             CONCAT22(in_register_00000002,CONCAT11(in_AH,uVar5))) + 0x1401272);
  *pcVar1 = *pcVar1 + uVar7;
  *(uint1 *)CONCAT44(in_register_00000004,CONCAT22(in_register_00000002,CONCAT11(in_AH,uVar5))) =
       *(char *)CONCAT44(in_register_00000004,CONCAT22(in_register_00000002,CONCAT11(in_AH,uVar5)))
       + uVar5;
  *unaff_RDI = *unaff_RDI + unaff_BL;
  *(uint1 *)CONCAT44(in_register_00000004,CONCAT22(in_register_00000002,CONCAT11(in_AH,uVar5))) =
       *(char *)CONCAT44(in_register_00000004,CONCAT22(in_register_00000002,CONCAT11(in_AH,uVar5)))
       + uVar5;
  *(uint1 *)CONCAT44(in_register_00000004,CONCAT22(in_register_00000002,CONCAT11(in_AH,uVar5))) =
       *(char *)CONCAT44(in_register_00000004,CONCAT22(in_register_00000002,CONCAT11(in_AH,uVar5)))
       + uVar5;
  *(uint1 *)CONCAT44(in_register_00000004,CONCAT22(in_register_00000002,CONCAT11(in_AH,uVar5))) =
       *(char *)CONCAT44(in_register_00000004,CONCAT22(in_register_00000002,CONCAT11(in_AH,uVar5)))
       + uVar5;
  cVar6 = uVar5 + (uint1)in_RDX;
  cVar6 = cVar6 + *(char *)(CONCAT44(in_register_00000004,
                                     CONCAT22(in_register_00000002,CONCAT11(in_AH,cVar6))) + 1) +
          CARRY1(uVar5,(uint1)in_RDX);
  *(char *)CONCAT44(in_register_00000004,CONCAT22(in_register_00000002,CONCAT11(in_AH,cVar6))) =
       *(char *)CONCAT44(in_register_00000004,CONCAT22(in_register_00000002,CONCAT11(in_AH,cVar6)))
       + cVar6;
  *unaff_RDI = *unaff_RDI + unaff_BL;
  *(char *)CONCAT44(in_register_00000004,CONCAT22(in_register_00000002,CONCAT11(in_AH,cVar6))) =
       *(char *)CONCAT44(in_register_00000004,CONCAT22(in_register_00000002,CONCAT11(in_AH,cVar6)))
       + cVar6;
  *(char *)CONCAT44(in_register_00000004,CONCAT22(in_register_00000002,CONCAT11(in_AH,cVar6))) =
       *(char *)CONCAT44(in_register_00000004,CONCAT22(in_register_00000002,CONCAT11(in_AH,cVar6)))
       + cVar6;
  *(char *)CONCAT44(in_register_00000004,CONCAT22(in_register_00000002,CONCAT11(in_AH,cVar6))) =
       *(char *)CONCAT44(in_register_00000004,CONCAT22(in_register_00000002,CONCAT11(in_AH,cVar6)))
       + cVar6;
  pcVar3 = (code *)swi(0x10);
  (*pcVar3)();
  *(int4 *)CONCAT44(extraout_var_00,CONCAT22(extraout_var,CONCAT11(extraout_AH,extraout_AL))) =
       *(int4 *)CONCAT44(extraout_var_00,CONCAT22(extraout_var,CONCAT11(extraout_AH,extraout_AL))) +
       CONCAT22(extraout_var,CONCAT11(extraout_AH,extraout_AL));
  *(char *)CONCAT44(extraout_var_00,CONCAT22(extraout_var,CONCAT11(extraout_AH,extraout_AL))) =
       *(char *)CONCAT44(extraout_var_00,CONCAT22(extraout_var,CONCAT11(extraout_AH,extraout_AL))) +
       extraout_AL;
  uVar5 = extraout_AL -
          *(char *)CONCAT44(extraout_var_00,CONCAT22(extraout_var,CONCAT11(extraout_AH,extraout_AL))
                           );
  *(uint1 *)CONCAT44(extraout_var_00,CONCAT22(extraout_var,CONCAT11(extraout_AH,uVar5))) =
       *(char *)CONCAT44(extraout_var_00,CONCAT22(extraout_var,CONCAT11(extraout_AH,uVar5))) + uVar5
  ;
  *(uint1 *)CONCAT44(extraout_var_00,CONCAT22(extraout_var,CONCAT11(extraout_AH,uVar5))) =
       *(char *)CONCAT44(extraout_var_00,CONCAT22(extraout_var,CONCAT11(extraout_AH,uVar5))) + uVar5
  ;
  uVar4 = *(uint1 *)CONCAT44(extraout_var_00,CONCAT22(extraout_var,CONCAT11(extraout_AH,uVar5)));
  *(uint1 *)CONCAT44(extraout_var_00,CONCAT22(extraout_var,CONCAT11(extraout_AH,uVar5))) =
       *(char *)CONCAT44(extraout_var_00,CONCAT22(extraout_var,CONCAT11(extraout_AH,uVar5))) + uVar5
  ;
  *unaff_retaddr = *unaff_retaddr + '@' + CARRY1(uVar4,uVar5);
  *(int4 *)CONCAT44(extraout_var_00,CONCAT22(extraout_var,CONCAT11(extraout_AH,uVar5))) =
       *(int4 *)CONCAT44(extraout_var_00,CONCAT22(extraout_var,CONCAT11(extraout_AH,uVar5))) +
       CONCAT22(extraout_var,CONCAT11(extraout_AH,uVar5));
  *(uint1 *)CONCAT44(extraout_var_00,CONCAT22(extraout_var,CONCAT11(extraout_AH,uVar5))) =
       *(char *)CONCAT44(extraout_var_00,CONCAT22(extraout_var,CONCAT11(extraout_AH,uVar5))) + uVar5
  ;
                    
  halt_baddata_0x239a48();
}









void __fastcall
func_pdata_0x1400b8cd0(uint64_t param_1,uint64_t param_2,uint64_t param_3,uint64_t param_4)
{
  uint64_t uVar1;
  uint4 uVar2;
  int4 iVar3;
  LPVOID pvVar4;
  int8 iVar5;
  uint8 uVar6;
  int8 iVar7;
  int4 *piVar8;
  uint32_t uVar9;
  uint4 uVar10;
  uint4 *puVar12;
  int4 iVar13;
  int8 *piVar14;
  uint4 *puVar15;
  uint64_t auStack_e8 [5];
  uint32_t auStack_c0 [2];
  uint8 auStack_b8 [10];
  int8 aiStack_68 [2];
  uint8_t auStack_58 [8];
  int8 aiStack_50 [2];
  uint8 uVar11;
  
  if (iRam00000001402385b0 == 0) {
    iRam00000001402385b0 = 1;
    auStack_b8[5] = 0x1400b8d0f;
    func_pdata_0x1400b96d0();
    auStack_b8[5] = 0x1400b8d26;
    iVar5 = func_call_0x1400b9930();
    iVar5 = -iVar5;
    iRam00000001402385b4 = 0;
    puRam00000001402385b8 = auStack_58 + iVar5;
    puVar12 = (uint4 *)0x1401d528c;
    do {
      while( true ) {
        uVar2 = puVar12[2];
        piVar14 = (int8 *)((uint8)*puVar12 + 0x140000000);
        uVar10 = uVar2 & 0xff;
        uVar11 = (uint8)uVar10;
        iVar7 = *piVar14;
        puVar15 = (uint4 *)((uint8)puVar12[1] + 0x140000000);
        if (uVar10 != 0x20) break;
        uVar6 = (uint8)*puVar15;
        if ((int4)*puVar15 < 0) {
          uVar6 |= 0xffffffff00000000;
        }
        iVar7 = (uVar6 - (int8)piVar14) + iVar7;
        aiStack_50[0] = iVar7;
        if (((uVar2 & 0xc0) == 0) && ((0xffffffff < iVar7 || (iVar7 < -0x80000000))))
        goto code_r0x0001400b903f;
        *(uint64_t *)((int8)auStack_b8 + iVar5 + 0x28) = 0x1400b8fab;
        func_pdata_0x1400b8b60(puVar15);
        *(uint64_t *)((int8)auStack_b8 + iVar5 + 0x28) = 0x1400b8fbc;
        memcpy(puVar15,aiStack_50,4);
code_r0x0001400b8e07:
        puVar12 = puVar12 + 3;
        if ((uint4 *)0x1401d5afb < puVar12) goto code_r0x0001400b8e90;
      }
      if (uVar10 < 0x21) {
        if (uVar10 == 8) {
          uVar6 = (uint8)*(uint1 *)puVar15;
          if ((char)*(uint1 *)puVar15 < '\0') {
            uVar6 |= 0xffffffffffffff00;
          }
          iVar7 = (uVar6 - (int8)piVar14) + iVar7;
          aiStack_50[0] = iVar7;
          if (((uVar2 & 0xc0) == 0) && ((0xff < iVar7 || (iVar7 < -0x80))))
          goto code_r0x0001400b903f;
          *(uint64_t *)((int8)auStack_b8 + iVar5 + 0x28) = 0x1400b9001;
          func_pdata_0x1400b8b60(puVar15);
          *(uint64_t *)((int8)auStack_b8 + iVar5 + 0x28) = 0x1400b9012;
          memcpy(puVar15,aiStack_50,1);
        }
        else {
          if (uVar10 != 0x10) goto code_r0x0001400b902b;
          uVar6 = (uint8)*(uint2 *)puVar15;
          if ((int2)*(uint2 *)puVar15 < 0) {
            uVar6 |= 0xffffffffffff0000;
          }
          iVar7 = (uVar6 - (int8)piVar14) + iVar7;
          aiStack_50[0] = iVar7;
          if (((uVar2 & 0xc0) == 0) && ((0xffff < iVar7 || (iVar7 < -0x8000))))
          goto code_r0x0001400b903f;
          *(uint64_t *)((int8)auStack_b8 + iVar5 + 0x28) = 0x1400b8df6;
          func_pdata_0x1400b8b60(puVar15);
          *(uint64_t *)((int8)auStack_b8 + iVar5 + 0x28) = 0x1400b8e07;
          memcpy(puVar15,aiStack_50,2);
        }
        goto code_r0x0001400b8e07;
      }
      if (uVar10 != 0x40) {
code_r0x0001400b902b:
        aiStack_50[0] = 0;
        *(uint64_t *)((int8)auStack_b8 + iVar5 + 0x28) = 0x1400b903f;
        iVar7 = func_pdata_0x1400b8b00(0x1401a7f18);
code_r0x0001400b903f:
        *(int8 *)((int8)aiStack_68 + iVar5) = iVar7;
        *(uint64_t *)((int8)auStack_b8 + iVar5 + 0x28) = 0x1400b9053;
        func_pdata_0x1400b8b00(0x1401a7f48);
        uVar9 = 0x401a7ee0;
        *(uint64_t *)((int8)auStack_b8 + iVar5 + 0x28) = 0x1400b905f;
        func_pdata_0x1400b8b00();
        if (pcRam00000001402385c0 != (code *)0x0) {
          uVar1 = *(uint64_t *)((int8)aiStack_68 + iVar5 + 8);
          *(uint32_t *)((int8)auStack_c0 + iVar5) = uVar9;
          *(uint8 *)((int8)auStack_b8 + iVar5) = uVar11;
          *(uint64_t *)((int8)auStack_b8 + iVar5 + 8) = param_3;
          *(uint64_t *)((int8)auStack_b8 + iVar5 + 0x10) = param_4;
          *(uint64_t *)((int8)auStack_b8 + iVar5 + 0x18) = uVar1;
          *(uint64_t *)((int8)auStack_e8 + iVar5) = 0x1400b9098;
          (*pcRam00000001402385c0)((int8)auStack_c0 + iVar5);
        }
        return;
      }
      iVar7 = (*(int8 *)puVar15 - (int8)piVar14) + iVar7;
      aiStack_50[0] = iVar7;
      if (((uVar2 & 0xc0) == 0) && (-1 < iVar7)) goto code_r0x0001400b903f;
      puVar12 = puVar12 + 3;
      *(uint64_t *)((int8)auStack_b8 + iVar5 + 0x28) = 0x1400b8e6f;
      func_pdata_0x1400b8b60(puVar15);
      *(uint64_t *)((int8)auStack_b8 + iVar5 + 0x28) = 0x1400b8e80;
      memcpy(puVar15,aiStack_50,8);
    } while (puVar12 < (uint4 *)0x1401d5afc);
code_r0x0001400b8e90:
    if (0 < iRam00000001402385b4) {
      iVar7 = 0;
      iVar13 = 0;
      do {
        piVar8 = (int4 *)(puRam00000001402385b8 + iVar7);
        iVar3 = *piVar8;
        if (iVar3 != 0) {
          uVar11 = *(uint8 *)(piVar8 + 4);
          pvVar4 = *(LPVOID *)(piVar8 + 2);
          *(uint64_t *)((int8)auStack_b8 + iVar5 + 0x28) = 0x1400b8ecf;
          VirtualProtect(pvVar4,uVar11,iVar3,(uint4 *)aiStack_50);
        }
        iVar13 += 1;
        iVar7 += 0x28;
      } while (iVar13 < iRam00000001402385b4);
    }
  }
  return;
}



void * __fastcall SetUnhandledExceptionFilter(void *param_1)
{
  char in_AL;
  uint1 in_AH;
  uint8_t in_register_00000002;
  int8 unaff_RDI;
  
  *(uint1 *)(unaff_RDI + 0x14012) = *(uint1 *)(unaff_RDI + 0x14012) & in_AH;
  *(char *)CONCAT62(in_register_00000002,CONCAT11(in_AH,in_AL)) =
       *(char *)CONCAT62(in_register_00000002,CONCAT11(in_AH,in_AL)) + in_AL;
                    
  halt_baddata_0x2399b8();
}

