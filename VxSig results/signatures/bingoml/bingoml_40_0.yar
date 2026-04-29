rule bingoml_40_0 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         535657e8
         // 005f4523: push ebx
         // 005f4524: push esi
         // 005f4525: push edi
         // 005f4526: call 0x5ec86c
      [-]85c07414
         // 0041ffd2: test eax, eax
         // 0041ffd4: jz 0x41ffea
      [-]516a0c8d4d
         // 005f4605: push ecx
         // 005f4606: push 0xc
         // 005f4608: lea ecx, ss:[ebp+0xffffffffffffffec]
      [-]516a0150ff
         // 005f460b: push ecx
         // 005f460c: push 0x1
         // 005f460e: push eax
         // 005f460f: call edi
      [-]85c07406
         // 005f4611: test eax, eax
         // 005f4613: jz 0x5f461b

  }
  condition:
    all of them
}
