rule pioneer_10_0 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         508b44240483c00450c20800
         // 00409751: push eax
         // 00409752: mov eax, ss:[esp+0x4]
         // 00409756: add eax, 0x4
         // 00409759: push eax
         // 0040975a: retn b2 0x8
      [-]5060e8edffffffc20400
         // 0040975d: push eax
         // 0040975e: pusha 
         // 0040975f: call 0x409751
         // 00409764: retn b2 0x4
      [-]508b44240483c004508b442404c20800
         // 0040977f: push eax
         // 00409780: mov eax, ss:[esp+0x4]
         // 00409784: add eax, 0x4
         // 00409787: push eax
         // 00409788: mov eax, ss:[esp+0x4]
         // 0040978c: retn b2 0x8
      [-]8b4c2408565733ff0fb741140fb7710685f68d4408187623
         // 004097bf: mov ecx, ss:[esp+0x8]
         // 004097c3: push esi
         // 004097c4: push edi
         // 004097c5: xor edi, edi
         // 004097c7: movzx eax, b2 ds:[ecx+0x14]
         // 004097cb: movzx esi, b2 ds:[ecx+0x6]
         // 004097cf: test esi, esi
         // 004097d1: lea eax, ds:[eax+ecx+0x18]
         // 004097d5: jbe 0x4097fa
      [-]8b480885c97503
         // 004097d7: mov ecx, ds:[eax+0x8]
         // 004097da: test ecx, ecx
         // 004097dc: jnz 0x4097e1
      [-]8b500c3954240c7208
         // 004097e1: mov edx, ds:[eax+0xc]
         // 004097e4: cmp ss:[esp+0xc], edx
         // 004097e8: jb 0x4097f2
      [-]03d13954240c720a
         // 004097ea: add edx, ecx
         // 004097ec: cmp ss:[esp+0xc], edx
         // 004097f0: jb 0x4097fc
      [-]4783c0283bfe72dd
         // 004097f2: inc edi
         // 004097f3: add eax, 0x28
         // 004097f6: cmp edi, esi
         // 004097f8: jb 0x4097d7
      [-]e841deffffc3
         // 0040b917: call 0x40975d
         // 0040b91c: retn 

  }
  condition:
    all of them
}
