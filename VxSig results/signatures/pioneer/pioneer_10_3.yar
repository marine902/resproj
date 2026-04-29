rule pioneer_10_3 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         508b44240483c00450c20800
         // 0040865e: push eax
         // 0040865f: mov eax, ss:[esp+0x4]
         // 00408663: add eax, 0x4
         // 00408666: push eax
         // 00408667: retn b2 0x8
      [-]5060e8edffffffc20400
         // 0040866a: push eax
         // 0040866b: pusha 
         // 0040866c: call 0x40865e
         // 00408671: retn b2 0x4
      [-]8b542404807a0301
         // 0040869c: mov edx, ss:[esp+0x4]
         // 004086a0: cmp b1 ds:[edx+0x3], b1 0x1
      [-]8d4204538bc8
         // 004086aa: lea eax, ds:[edx+0x4]
         // 004086ad: push ebx
         // 004086ae: mov ecx, eax
      [-]8a5a0284db
         // 004086b0: mov b1 bl, b1 ds:[edx+0x2]
         // 004086b3: test b1 bl, b1 bl
      [-]8a19f6d384db
         // 004086b9: mov b1 bl, b1 ds:[ecx]
         // 004086bb: not b1 bl
         // 004086bd: test b1 bl, b1 bl
      [-]8b4c2408565733ff0fb741140fb7710685f68d4408187623
         // 004086cc: mov ecx, ss:[esp+0x8]
         // 004086d0: push esi
         // 004086d1: push edi
         // 004086d2: xor edi, edi
         // 004086d4: movzx eax, b2 ds:[ecx+0x14]
         // 004086d8: movzx esi, b2 ds:[ecx+0x6]
         // 004086dc: test esi, esi
         // 004086de: lea eax, ds:[eax+ecx+0x18]
         // 004086e2: jbe 0x408707
      [-]8b480885c97503
         // 004086e4: mov ecx, ds:[eax+0x8]
         // 004086e7: test ecx, ecx
         // 004086e9: jnz 0x4086ee
      [-]8b500c3954240c7208
         // 004086ee: mov edx, ds:[eax+0xc]
         // 004086f1: cmp ss:[esp+0xc], edx
         // 004086f5: jb 0x4086ff
      [-]03d13954240c720a
         // 004086f7: add edx, ecx
         // 004086f9: cmp ss:[esp+0xc], edx
         // 004086fd: jb 0x408709
      [-]4783c0283bfe72dd
         // 004086ff: inc edi
         // 00408700: add eax, 0x28
         // 00408703: cmp edi, esi
         // 00408705: jb 0x4086e4
      [-]deffffc3
         // 0040a82c: retn 

  }
  condition:
    all of them
}
