uint64_t __stdcall FUN_ENTRY(uint64_t param_1,uint64_t param_2)
{
  uint8_t auVar1 [16];
  uint32_t in_XMM1_Dc;
  uint32_t in_XMM1_Dd;
  uint8_t in_XMM3 [16];
  uint32_t uStack_28;
  
  auVar1._8_4_ = in_XMM1_Dc;
  auVar1._0_8_ = param_2;
  auVar1._12_4_ = in_XMM1_Dd;
  vsubps_avx(auVar1,in_XMM3);
  return CONCAT44(uStack_28,uStack_28);
}

