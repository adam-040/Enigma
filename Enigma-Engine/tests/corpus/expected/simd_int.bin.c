
uint2 __stdcall FUN_ENTRY(uint64_t param_1,uint64_t param_2)
{
  int4 iVar1;
  int4 iVar3;
  int4 in_XMM0_Dc;
  int4 iVar4;
  int4 in_XMM0_Dd;
  int4 iVar5;
  uint8_t axVar2 [16];
  uint4 uVar6;
  int4 in_XMM1_Dc;
  int4 in_XMM1_Dd;
  char in_XMM2_Ba;
  char in_XMM2_Bb;
  char in_XMM2_Bc;
  char in_XMM2_Bd;
  char in_XMM2_Be;
  char in_XMM2_Bf;
  char in_XMM2_Bg;
  char in_XMM2_Bh;
  char in_XMM2_Bi;
  char in_XMM2_Bj;
  char in_XMM2_Bk;
  char in_XMM2_Bl;
  char in_XMM2_Bm;
  char in_XMM2_Bn;
  char in_XMM2_Bo;
  char in_XMM2_Bp;
  uint8_t in_XMM3 [16];
  uint8_t in_XMM4 [16];
  
  iVar1 = (int4)param_1 + (int4)param_2;
  iVar3 = (int4)((uint8)param_1 >> 0x20) + (int4)((uint8)param_2 >> 0x20);
  iVar4 = in_XMM0_Dc + in_XMM1_Dc;
  iVar5 = in_XMM0_Dd + in_XMM1_Dd;
  axVar2[0] = (char)iVar1 - in_XMM2_Ba;
  axVar2[1] = (char)((uint4)iVar1 >> 8) - in_XMM2_Bb;
  axVar2[2] = (char)((uint4)iVar1 >> 0x10) - in_XMM2_Bc;
  axVar2[3] = (char)((uint4)iVar1 >> 0x18) - in_XMM2_Bd;
  axVar2[4] = (char)iVar3 - in_XMM2_Be;
  axVar2[5] = (char)((uint4)iVar3 >> 8) - in_XMM2_Bf;
  axVar2[6] = (char)((uint4)iVar3 >> 0x10) - in_XMM2_Bg;
  axVar2[7] = (char)((uint4)iVar3 >> 0x18) - in_XMM2_Bh;
  axVar2[8] = (char)iVar4 - in_XMM2_Bi;
  axVar2[9] = (char)((uint4)iVar4 >> 8) - in_XMM2_Bj;
  axVar2[10] = (char)((uint4)iVar4 >> 0x10) - in_XMM2_Bk;
  axVar2[0xb] = (char)((uint4)iVar4 >> 0x18) - in_XMM2_Bl;
  axVar2[0xc] = (char)iVar5 - in_XMM2_Bm;
  axVar2[0xd] = (char)((uint4)iVar5 >> 8) - in_XMM2_Bn;
  axVar2[0xe] = (char)((uint4)iVar5 >> 0x10) - in_XMM2_Bo;
  axVar2[0xf] = (char)((uint4)iVar5 >> 0x18) - in_XMM2_Bp;
  axVar2 = axVar2 & in_XMM3 | in_XMM4;
  uVar6 = axVar2._12_4_;
  return (uint2)(SUB161(axVar2 >> 7,0) & 1) | (uint2)(SUB161(axVar2 >> 0xf,0) & 1) << 1 |
         (uint2)(SUB161(axVar2 >> 0x17,0) & 1) << 2 | (uint2)(SUB161(axVar2 >> 0x1f,0) & 1) << 3 |
         (uint2)(SUB161(axVar2 >> 0x27,0) & 1) << 4 | (uint2)(SUB161(axVar2 >> 0x2f,0) & 1) << 5 |
         (uint2)(SUB161(axVar2 >> 0x37,0) & 1) << 6 | (uint2)(SUB161(axVar2 >> 0x3f,0) & 1) << 7 |
         (uint2)(SUB161(axVar2 >> 0x47,0) & 1) << 8 | (uint2)(SUB161(axVar2 >> 0x4f,0) & 1) << 9 |
         (uint2)(SUB161(axVar2 >> 0x57,0) & 1) << 10 | (uint2)(SUB161(axVar2 >> 0x5f,0) & 1) << 0xb
         | (uint2)((uint1)(uVar6 >> 7) & 1) << 0xc | (uint2)((uint1)(uVar6 >> 0xf) & 1) << 0xd |
         (uint2)((uint1)(uVar6 >> 0x17) & 1) << 0xe | (uint2)(uint1)(axVar2[0xf] >> 7) << 0xf;
}

