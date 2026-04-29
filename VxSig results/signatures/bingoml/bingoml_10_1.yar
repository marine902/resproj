rule bingoml_10_1 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         535657e8
         // 00408fa8: push ebx
         // 00408faf: push esi
         // 00408fb0: push edi
         // 00408fc4: call ___crtIsPackagedApp
      [-]8bf885ff
         // 005f4549: mov edi, eax
         // 005f454b: test edi, edi
      [-]85c07414
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

  }
  condition:
    all of them
}
