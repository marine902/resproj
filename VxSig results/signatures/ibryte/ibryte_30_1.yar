rule ibryte_30_1 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         8bff56b8
         // 004739c6: mov edi, edi
         // 004739c8: push esi
         // 004739c9: mov eax, 0x4a39d0
      [-]578bf83bc6730f
         // 004739d3: push edi
         // 004739d4: mov edi, eax
         // 004739d6: cmp eax, esi
         // 004739d8: jnb 0x4739e9
      [-]8b0785c07402
         // 004727fb: mov eax, ds:[edi]
         // 004727fd: test eax, eax
         // 004727ff: jz 0x472803
      [-]83c7043bfe72f1
         // 00472803: add edi, 0x4
         // 00472806: cmp edi, esi
         // 00472808: jb 0x4727fb
      [-]8bff56b8
         // 004739ec: mov edi, edi
         // 004739ee: push esi
         // 004739ef: mov eax, 0x4a39d8
      [-]578bf83bc6730f
         // 004739f9: push edi
         // 004739fa: mov edi, eax
         // 004739fc: cmp eax, esi
         // 004739fe: jnb 0x473a0f
      [-]8b0785c07402
         // 00472821: mov eax, ds:[edi]
         // 00472823: test eax, eax
         // 00472825: jz 0x472829
      [-]83c7043bfe72f1
         // 00472829: add edi, 0x4
         // 0047282c: cmp edi, esi
         // 0047282e: jb 0x472821

  }
  condition:
    all of them
}
