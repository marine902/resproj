rule bingoml_50_0 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         85c07414
         // 005f45b4: test eax, eax
         // 005f45b6: jz 0x5f45cc
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
      [-]ffd0eb02
         // 004200c9: call eax
         // 004200cb: jmp 0x4200cf

  }
  condition:
    all of them
}
