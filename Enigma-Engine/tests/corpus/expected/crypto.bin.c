uint64_t __stdcall FUN_ENTRY()
{
  uint8_t in_XMM0 [16];
  uint8_t auVar1 [16];
  uint8_t in_XMM1 [16];
  uint8_t in_XMM2 [16];
  uint8_t in_XMM3 [16];
  uint8_t in_XMM4 [16];
  
  auVar1 = aesenc(in_XMM0,in_XMM1);
  auVar1 = aesenclast(auVar1,in_XMM2);
  auVar1 = aesdec(auVar1,in_XMM3);
  auVar1 = aesdeclast(auVar1,in_XMM4);
  return auVar1._0_8_;
}

