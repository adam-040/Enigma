
uint64_t __stdcall FUN_ENTRY()
{
  uint8_t in_XMM0 [16];
  uint8_t axVar1 [16];
  uint8_t in_XMM1 [16];
  uint8_t in_XMM2 [16];
  uint8_t in_XMM3 [16];
  uint8_t in_XMM4 [16];
  
  axVar1 = aesenc(in_XMM0,in_XMM1);
  axVar1 = aesenclast(axVar1,in_XMM2);
  axVar1 = aesdec(axVar1,in_XMM3);
  axVar1 = aesdeclast(axVar1,in_XMM4);
  return axVar1._0_8_;
}

