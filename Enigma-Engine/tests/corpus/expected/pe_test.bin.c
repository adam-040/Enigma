[INFO] Apply Data Archives: Detected format: PE, pointer size=4
[INFO] Apply Data Archives: Applied 58 Windows data types to program

void __fastcall entry()
{
  xRam00000001402285a0 = 0;
  sub_0x140001010();
  return;
}


uint8 __fastcall sub_0x140001010()
{
  int4 iVar1;
  int4 iVar2;
  uint64_t *pxVar3;
  uint8 uVar4;
  uint32_t *pxVar5;
  uint64_t *pxVar6;
  int8 iVar7;
  int8 iVar8;
  uint64_t *pxVar9;
  int8 iVar10;
  int8 iVar11;
  int8 unaff_GS_OFFSET;
  bool bVar12;
  uint32_t axStack_4c [3];
  
  iVar10 = *(int8 *)(*(int8 *)(unaff_GS_OFFSET + 0x30) + 8);
  while( true ) {
    iVar11 = 0;
    LOCK();
    bVar12 = iRam0000000140228550 == 0;
    iVar7 = iVar10;
    if (!bVar12) {
      iVar11 = iRam0000000140228550;
      iVar7 = iRam0000000140228550;
    }
    iRam0000000140228550 = iVar7;
    UNLOCK();
    if (bVar12) {
      bVar12 = false;
      goto code_r0x00014000105c;
    }
    if (iVar10 == iVar11) break;
    Sleep(1000);
  }
  bVar12 = true;
code_r0x00014000105c:
  if (iRam0000000140228558 == 1) {
    uVar4 = sub_0x1400b5e80(0x1f);
    goto code_r0x0001400013d2;
  }
  if (iRam0000000140228558 == 0) {
    iRam0000000140228558 = 1;
    sub_0x1400b4fe0();
    pvRam00000001402285e0 = SetUnhandledExceptionFilter((void *)0x1400b53c0);
    sub_0x1400b5cf0();
    sub_0x1400b5820();
    uRam0000000140224008 = 0;
    xRam0000000140228588 = 1;
    xRam0000000140228584 = 1;
    xRam0000000140228580 = 1;
    if ((iRam0000000140000000 == 0x5a4d) &&
       (iVar10 = (int8)iRam000000014000003c, *(int4 *)(iVar10 + 0x140000000) == 0x4550)) {
      if (*(int2 *)(iVar10 + 0x140000018) == 0x10b) {
        if (0xe < *(uint4 *)(iVar10 + 0x140000074)) {
          uRam0000000140224008 = (uint4)(*(int4 *)(iVar10 + 0x1400000e8) != 0);
        }
      }
      else if ((*(int2 *)(iVar10 + 0x140000018) == 0x20b) &&
              (0xe < *(uint4 *)(iVar10 + 0x140000084))) {
        uRam0000000140224008 = (uint4)(*(int4 *)(iVar10 + 0x1400000f8) != 0);
      }
    }
    if (xRam00000001402285a0 == 0) {
      sub_0x1400b5e70(1);
    }
    else {
      sub_0x1400b5e70(2);
    }
    pxVar5 = (uint32_t *)sub_0x1400b5cb0();
    *pxVar5 = xRam00000001402285d0;
    pxVar5 = (uint32_t *)sub_0x1400b5cc0();
    *pxVar5 = xRam0000000140228590;
    iVar1 = sub_0x1400b4c50();
    if (-1 < iVar1) {
      if (iRam0000000140187090 == 1) {
        sub_0x1400b53b0(0x1400b4d10);
      }
      if (iRam0000000140187070 == -1) {
        sub_0x1400b5d00(0xffffffff);
      }
      iVar1 = sub_0x1400b5c70(0x1401c8b98,0x1401c8ba0);
      if (iVar1 != 0) {
        return 0xff;
      }
      axStack_4c[0] = xRam0000000140228570;
      iVar2 = sub_0x1400b5e60
                        (0x140224020,0x140224018,0x140224010,xRam0000000140228560,axStack_4c);
      iVar1 = iRam0000000140224020;
      if (-1 < iVar2) {
        iVar10 = (int8)iRam0000000140224020;
        pxVar6 = (uint64_t *)sub_0x1400b5ee8((int8)(iRam0000000140224020 + 1) << 3);
        pxVar3 = pxRam0000000140224018;
        if (pxVar6 != (uint64_t *)0x0) {
          pxVar9 = pxVar6;
          if (iVar1 < 1) {
code_r0x00014000134c:
            *pxVar9 = 0;
            pxRam0000000140224018 = pxVar6;
            sub_0x1400b5e98(0x1401c8b88,0x1401c8b90);
            sub_0x1400b4c30();
            iRam0000000140228558 = 2;
            goto code_r0x000140001084;
          }
          iVar11 = 1;
          while( true ) {
            iVar7 = sub_0x1400b5f20(pxVar3[iVar11 + -1]);
            iVar8 = sub_0x1400b5ee8(iVar7 + 1);
            pxVar6[iVar11 + -1] = iVar8;
            if (iVar8 == 0) break;
            sub_0x1400b5f00(iVar8,pxVar3[iVar11 + -1],iVar7 + 1);
            if (iVar10 == iVar11) {
              pxVar9 = pxVar6 + iVar10;
              goto code_r0x00014000134c;
            }
            iVar11 += 1;
          }
        }
      }
    }
    uVar4 = sub_0x1400b5e80(8);
  }
  else {
    iRam0000000140224004 = 1;
code_r0x000140001084:
    if (!bVar12) {
      LOCK();
      iRam0000000140228550 = 0;
      UNLOCK();
    }
    (*(code *)0x1400b4c80)(0,2,0);
    pxVar3 = (uint64_t *)sub_0x1400b5cd0();
    iVar1 = iRam0000000140224020;
    *pxVar3 = xRam0000000140224010;
    uVar4 = main(iVar1,pxRam0000000140224018);
    if (uRam0000000140224008 == 0) {
code_r0x0001400013d2:
      sub_0x1400b5ec0(uVar4 & 0xffffffff);
      xRam00000001402285a0 = 1;
      uVar4 = sub_0x140001010();
      return uVar4;
    }
    if (iRam0000000140224004 != 0) {
      return uVar4;
    }
  }
  sub_0x1400b5e88();
  return uVar4 & 0xffffffff;
}




void __fastcall Sleep(int4 param_1)
{
                    
  halt_baddata();
}


void __fastcall sub_0x1400b5e80(int4 param_1)
{
  _amsg_exit(param_1);
  return;
}










void __fastcall
sub_0x1400b4fe0(uint64_t param_1,uint64_t param_2,uint64_t param_3,uint64_t param_4)
{
  uint64_t xVar1;
  uint4 uVar2;
  int4 iVar3;
  LPVOID pvVar4;
  int8 iVar5;
  uint8 uVar6;
  int8 iVar7;
  int4 *piVar8;
  uint32_t xVar9;
  uint4 uVar10;
  uint4 *puVar12;
  int4 iVar13;
  int8 *piVar14;
  uint4 *puVar15;
  uint64_t axStack_e8 [5];
  uint32_t axStack_c0 [2];
  uint8 auStack_b8 [10];
  int8 aiStack_68 [2];
  uint8_t axStack_58 [8];
  int8 aiStack_50 [2];
  uint8 uVar11;
  
  if (iRam00000001402285b0 == 0) {
    iRam00000001402285b0 = 1;
    auStack_b8[5] = 0x1400b501f;
    sub_0x1400b59d0();
    auStack_b8[5] = 0x1400b5036;
    iVar5 = sub_0x1400b5c30();
    iVar5 = -iVar5;
    iRam00000001402285b4 = 0;
    pxRam00000001402285b8 = axStack_58 + iVar5;
    puVar12 = (uint4 *)0x1401c80bc;
    do {
      while( true ) {
        uVar2 = puVar12[2];
        piVar14 = (int8 *)((int8)&iRam0000000140000000 + (uint8)*puVar12);
        uVar10 = uVar2 & 0xff;
        uVar11 = (uint8)uVar10;
        iVar7 = *piVar14;
        puVar15 = (uint4 *)((int8)&iRam0000000140000000 + (uint8)puVar12[1]);
        if (uVar10 != 0x20) break;
        uVar6 = (uint8)*puVar15;
        if ((int4)*puVar15 < 0) {
          uVar6 |= 0xffffffff00000000;
        }
        iVar7 = (uVar6 - (int8)piVar14) + iVar7;
        aiStack_50[0] = iVar7;
        if (((uVar2 & 0xc0) == 0) && ((0xffffffff < iVar7 || (iVar7 < -0x80000000))))
        goto code_r0x0001400b534f;
        *(uint64_t *)((int8)auStack_b8 + iVar5 + 0x28) = 0x1400b52bb;
        sub_0x1400b4e70(puVar15);
        *(uint64_t *)((int8)auStack_b8 + iVar5 + 0x28) = 0x1400b52cc;
        sub_0x1400b5f00(puVar15,aiStack_50,4);
code_r0x0001400b5117:
        puVar12 = puVar12 + 3;
        if ((uint4 *)0x1401c892b < puVar12) goto code_r0x0001400b51a0;
      }
      if (uVar10 < 0x21) {
        if (uVar10 == 8) {
          uVar6 = (uint8)(uint1)*puVar15;
          if ((char)(uint1)*puVar15 < '\0') {
            uVar6 |= 0xffffffffffffff00;
          }
          iVar7 = (uVar6 - (int8)piVar14) + iVar7;
          aiStack_50[0] = iVar7;
          if (((uVar2 & 0xc0) == 0) && ((0xff < iVar7 || (iVar7 < -0x80))))
          goto code_r0x0001400b534f;
          *(uint64_t *)((int8)auStack_b8 + iVar5 + 0x28) = 0x1400b5311;
          sub_0x1400b4e70(puVar15);
          *(uint64_t *)((int8)auStack_b8 + iVar5 + 0x28) = 0x1400b5322;
          sub_0x1400b5f00(puVar15,aiStack_50,1);
        }
        else {
          if (uVar10 != 0x10) goto code_r0x0001400b533b;
          uVar6 = (uint8)(uint2)*puVar15;
          if ((int2)(uint2)*puVar15 < 0) {
            uVar6 |= 0xffffffffffff0000;
          }
          iVar7 = (uVar6 - (int8)piVar14) + iVar7;
          aiStack_50[0] = iVar7;
          if (((uVar2 & 0xc0) == 0) && ((0xffff < iVar7 || (iVar7 < -0x8000))))
          goto code_r0x0001400b534f;
          *(uint64_t *)((int8)auStack_b8 + iVar5 + 0x28) = 0x1400b5106;
          sub_0x1400b4e70(puVar15);
          *(uint64_t *)((int8)auStack_b8 + iVar5 + 0x28) = 0x1400b5117;
          sub_0x1400b5f00(puVar15,aiStack_50,2);
        }
        goto code_r0x0001400b5117;
      }
      if (uVar10 != 0x40) {
code_r0x0001400b533b:
        aiStack_50[0] = 0;
        *(uint64_t *)((int8)auStack_b8 + iVar5 + 0x28) = 0x1400b534f;
        iVar7 = sub_0x1400b4e10(0x14019adb8);
code_r0x0001400b534f:
        *(int8 *)((int8)aiStack_68 + iVar5) = iVar7;
        *(uint64_t *)((int8)auStack_b8 + iVar5 + 0x28) = 0x1400b5363;
        sub_0x1400b4e10(0x14019ade8);
        xVar9 = 0x4019ad80;
        *(uint64_t *)((int8)auStack_b8 + iVar5 + 0x28) = 0x1400b536f;
        sub_0x1400b4e10();
        if (pcRam00000001402285c0 != (code *)0x0) {
          xVar1 = *(uint64_t *)((int8)aiStack_68 + iVar5 + 8);
          *(uint32_t *)((int8)axStack_c0 + iVar5) = xVar9;
          *(uint8 *)((int8)auStack_b8 + iVar5) = uVar11;
          *(uint64_t *)((int8)auStack_b8 + iVar5 + 8) = param_3;
          *(uint64_t *)((int8)auStack_b8 + iVar5 + 0x10) = param_4;
          *(uint64_t *)((int8)auStack_b8 + iVar5 + 0x18) = xVar1;
          *(uint64_t *)((int8)axStack_e8 + iVar5) = 0x1400b53a8;
          (*pcRam00000001402285c0)((int8)axStack_c0 + iVar5);
        }
        return;
      }
      iVar7 = (*(int8 *)puVar15 - (int8)piVar14) + iVar7;
      aiStack_50[0] = iVar7;
      if (((uVar2 & 0xc0) == 0) && (-1 < iVar7)) goto code_r0x0001400b534f;
      puVar12 = puVar12 + 3;
      *(uint64_t *)((int8)auStack_b8 + iVar5 + 0x28) = 0x1400b517f;
      sub_0x1400b4e70(puVar15);
      *(uint64_t *)((int8)auStack_b8 + iVar5 + 0x28) = 0x1400b5190;
      sub_0x1400b5f00(puVar15,aiStack_50,8);
    } while (puVar12 < (uint4 *)0x1401c892c);
code_r0x0001400b51a0:
    if (0 < iRam00000001402285b4) {
      iVar7 = 0;
      iVar13 = 0;
      do {
        piVar8 = (int4 *)(pxRam00000001402285b8 + iVar7);
        iVar3 = *piVar8;
        if (iVar3 != 0) {
          uVar11 = *(uint8 *)(piVar8 + 4);
          pvVar4 = *(LPVOID *)(piVar8 + 2);
          *(uint64_t *)((int8)auStack_b8 + iVar5 + 0x28) = 0x1400b51df;
          VirtualProtect(pvVar4,uVar11,iVar3,(uint4 *)aiStack_50);
        }
        iVar13 += 1;
        iVar7 += 0x28;
      } while (iVar13 < iRam00000001402285b4);
    }
  }
  return;
}

