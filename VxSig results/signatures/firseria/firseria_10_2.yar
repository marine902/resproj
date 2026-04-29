rule firseria_10_2 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         558bec568bf1c706
         // 0040f988: push ebp
         // 0040f989: mov ebp, esp
         // 0040f98b: push esi
         // 0040f98c: mov esi, ecx
         // 0040f98e: mov ds:[esi], ??_7exception@std@@6B@
      [-]f64508017407
         // 0040f999: test b1 ss:[ebp+0x8], b1 0x1
         // 0040f99d: jz 0x40f9a6
      [-]8bc65e5dc20400
         // 0040c5ce: mov eax, esi
         // 0040c5d0: pop esi
         // 0040c5d1: pop ebp
         // 0040c5d2: retn b2 0x4
      [-]85c07402
         // 00415bd9: test eax, eax
         // 00415bdb: jz 0x415bdf
      [-]83f8ff740c
         // 0041d615: cmp eax, 0xffffffffffffffff
         // 0041d618: jz 0x41d626
      [-]83f8fe7407
         // 0041dbda: cmp eax, 0xfffffffffffffffe
         // 0041dbdd: jz 0x41dbe6

  }
  condition:
    all of them
}
