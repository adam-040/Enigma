
uint64_t __stdcall FUN_ENTRY(uint64_t param_1,uint64_t param_2)
{
  uint8_t axVar1 [16];
  uint32_t in_XMM1_Dc;
  uint32_t in_XMM1_Dd;
  uint8_t in_XMM3 [16];
  uint32_t xStack_28;
  
  axVar1._8_4_ = in_XMM1_Dc;
  axVar1._0_8_ = param_2;
  axVar1._12_4_ = in_XMM1_Dd;
  vsubps_avx(axVar1,in_XMM3);
  return CONCAT44(xStack_28,xStack_28);
}

