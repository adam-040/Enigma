float8 __stdcall
entry(uint64_t param_1, uint64_t param_2, uint64_t param_3, float8 param_4)
{
    return (float8)SUB84((float8)(((float4)((uint64_t)param_1 >> 0x20) +
                                       (float4)((uint64_t)param_2 >> 0x20)) *
                                   (float4)((uint64_t)param_3 >> 0x20) << 0x20 |
                                      ((float4)param_1 + (float4)param_2) *
                                      (float4)param_3) + param_4,0);
}

