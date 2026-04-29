rule cosmicduke_20_1 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         64890d????????
         // 0040287f: mov fs:[0x0], ecx
      [-]8bff568bf1807e08007409
         // 00413789: mov edi, edi
         // 0041378b: push esi
         // 0041378c: mov esi, ecx
         // 0041378e: cmp b1 ds:[esi+0x8], b1 0x0
         // 00413792: jz 0x41379d
      [-]ff7604e8
         // 00413794: push ds:[esi+0x4]
         // 00413797: call _free
      [-]83660400c64608005ec3
         // 0041379d: and ds:[esi+0x4], 0x0
         // 004137a1: mov b1 ds:[esi+0x8], b1 0x0
         // 004137a5: pop esi
         // 004137a6: retn 
      [-]6a0aff15
         // 00415211: push 0xa
         // 00415213: call ds:[IsProcessorFeaturePresent]
      [-]0033c0c3
         // 00416df4: xor eax, eax
         // 00416df6: retn 
      [-]8bff56b8
         // 004177bb: mov edi, edi
         // 004177bd: push esi
         // 004177be: mov eax, 0x423b9c
      [-]578bf83bc6730f
         // 004177c8: push edi
         // 004177c9: mov edi, eax
         // 004177cb: cmp eax, esi
         // 004177cd: jnb 0x4177de
      [-]8b0785c07402
         // 004177cf: mov eax, ds:[edi]
         // 004177d1: test eax, eax
         // 004177d3: jz 0x4177d7
      [-]83c7043bfe72f1
         // 004177d7: add edi, 0x4
         // 004177da: cmp edi, esi
         // 004177dc: jb 0x4177cf
      [-]8bff56b8
         // 004177e1: mov edi, edi
         // 004177e3: push esi
         // 004177e4: mov eax, 0x423ba4
      [-]578bf83bc6730f
         // 004177ee: push edi
         // 004177ef: mov edi, eax
         // 004177f1: cmp eax, esi
         // 004177f3: jnb 0x417804
      [-]8b0785c07402
         // 004177f5: mov eax, ds:[edi]
         // 004177f7: test eax, eax
         // 004177f9: jz 0x4177fd
      [-]83c7043bfe72f1
         // 004177fd: add edi, 0x4
         // 00417800: cmp edi, esi
         // 00417802: jb 0x4177f5

  }
  condition:
    all of them
}
