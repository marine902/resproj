rule ibryte_50_0 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         8bff56b8
         // 0047a146: mov edi, edi
         // 0047a148: push esi
         // 0047a149: mov eax, 0x4ac538
      [-]578bf83bc6730f
         // 0047a153: push edi
         // 0047a154: mov edi, eax
         // 0047a156: cmp eax, esi
         // 0047a158: jnb 0x47a169
      [-]8b0785c07402
         // 0047243a: mov eax, ds:[edi]
         // 0047243c: test eax, eax
         // 0047243e: jz 0x472442
      [-]83c7043bfe72f1
         // 00472442: add edi, 0x4
         // 00472445: cmp edi, esi
         // 00472447: jb 0x47243a
      [-]8bff56b8
         // 0047a16c: mov edi, edi
         // 0047a16e: push esi
         // 0047a16f: mov eax, 0x4ac540
      [-]578bf83bc6730f
         // 0047a179: push edi
         // 0047a17a: mov edi, eax
         // 0047a17c: cmp eax, esi
         // 0047a17e: jnb 0x47a18f
      [-]8b0785c07402
         // 00472460: mov eax, ds:[edi]
         // 00472462: test eax, eax
         // 00472464: jz 0x472468
      [-]83c7043bfe72f1
         // 00472468: add edi, 0x4
         // 0047246b: cmp edi, esi
         // 0047246d: jb 0x472460

  }
  condition:
    all of them
}
