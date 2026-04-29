rule allaple_10_0 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         c9b104014c24
         // 00401faf: mov b1 cl, b1 0x4
         // 00401fb1: add ss:[esp+0xffffffffffffffbc], ecx
      [-]33c0b004014424
         // 00402347: xor eax, eax
         // 00402349: mov b1 al, b1 0x4
         // 0040234b: add ss:[esp+0xffffffffffffffbc], eax
      [-]c0b004014424
         // 0040245a: mov b1 al, b1 0x4
         // 0040245c: add ss:[esp+0xffffffffffffffbc], eax
      [-]b004014424
         // 004024a9: mov b1 al, b1 0x4
         // 004024ab: add ss:[esp+0xffffffffffffffbc], eax
      [-]33d2b204015424
         // 00402876: xor edx, edx
         // 00402878: mov b1 dl, b1 0x4
         // 0040287a: add ss:[esp+0xffffffffffffffbc], edx
      [-]33dbb304015c24
         // 00402a96: xor ebx, ebx
         // 00402a98: mov b1 bl, b1 0x4
         // 00402a9a: add ss:[esp+0xffffffffffffffbc], ebx
      [-]33c0b004014424
         // 00402d09: xor eax, eax
         // 00402d0b: mov b1 al, b1 0x4
         // 00402d0d: add ss:[esp+0xffffffffffffffbc], eax
      [-]33dbb304015c24
         // 00402e31: xor ebx, ebx
         // 00402e33: mov b1 bl, b1 0x4
         // 00402e35: add ss:[esp+0xffffffffffffffbc], ebx
      [-]33dbb304015c24
         // 00403105: xor ebx, ebx
         // 00403107: mov b1 bl, b1 0x4
         // 00403109: add ss:[esp+0xffffffffffffffbc], ebx
      [-]33dbb304015c24
         // 00403209: xor ebx, ebx
         // 0040320b: mov b1 bl, b1 0x4
         // 0040320d: add ss:[esp+0xffffffffffffffbc], ebx
      [-]33c9b104014c24
         // 004032c2: xor ecx, ecx
         // 004032c4: mov b1 cl, b1 0x4
         // 004032c6: add ss:[esp+0xffffffffffffffbc], ecx
      [-]33dbb304015c24
         // 00403333: xor ebx, ebx
         // 00403335: mov b1 bl, b1 0x4
         // 00403337: add ss:[esp+0xffffffffffffffbc], ebx
      [-]c9b104014c24
         // 004034cb: mov b1 cl, b1 0x4
         // 004034cd: add ss:[esp+0xffffffffffffffbc], ecx
      [-]33c0b004014424
         // 00403572: xor eax, eax
         // 00403574: mov b1 al, b1 0x4
         // 00403576: add ss:[esp+0xffffffffffffffbc], eax
      [-]33c0b004
         // 004035e0: xor eax, eax
         // 004035e2: mov b1 al, b1 0x4
         // 0040361c: mov b1 bl, b1 0x4
      [-]33c0b004
         // 004036c2: xor eax, eax
         // 004036c4: mov b1 al, b1 0x4
      [-]33c0b004
         // 004037ae: xor eax, eax
         // 004037b0: mov b1 al, b1 0x4
      [-]33c0b004014424
         // 004038da: xor eax, eax
         // 004038dc: mov b1 al, b1 0x4
         // 004038de: add ss:[esp+0xffffffffffffffbc], eax
      [-]33c0b004
         // 0040399b: xor eax, eax
         // 0040399d: mov b1 al, b1 0x4
      [-]33c9b104
         // 00403a08: xor ecx, ecx
         // 00403a0a: mov b1 cl, b1 0x4
      [-]33c0b004
         // 00403a23: xor eax, eax
         // 00403a25: mov b1 al, b1 0x4
      [-]8bf4a558
         // 00403b3e: mov esi, esp
         // 00403b40: movsdd 
         // 00403b41: pop eax
      [-]8bf4a55833
         // 00403b74: mov esi, esp
         // 00403b76: movsdd 
         // 00403b77: pop eax
         // 00403b7b: xor eax, eax
      [-]c9b104014c24
         // 00403bb2: mov b1 cl, b1 0x4
         // 00403bb4: add ss:[esp+0xffffffffffffffbc], ecx
      [-]33c0b004
         // 00403bc7: xor eax, eax
         // 00403bc9: mov b1 al, b1 0x4
      [-]c0b004014424
         // 00403bf7: mov b1 al, b1 0x4
         // 00403bf9: add ss:[esp+0xffffffffffffffbc], eax
      [-]c0b004014424
         // 00403c25: mov b1 al, b1 0x4
         // 00403c27: add ss:[esp+0xffffffffffffffbc], eax
      [-]b004014424
         // 00403ce8: mov b1 al, b1 0x4
         // 00403cea: add ss:[esp+0xffffffffffffffbc], eax
         // 00403cf4: mov eax, ss:[esp+0xffffffffffffffbc]
         // 00403d0e: mov ecx, ss:[esp+0xffffffffffffffbc]
      [-]c0b004014424
         // 00403d37: mov b1 al, b1 0x4
         // 00403d39: add ss:[esp+0xffffffffffffffbc], eax
      [-]33c0b004014424
         // 00403e95: xor eax, eax
         // 00403e97: mov b1 al, b1 0x4
         // 00403e99: add ss:[esp+0xffffffffffffffbc], eax
         // 00403eb4: add ss:[esp+0xffffffffffffffbc], ebx
      [-]c0b004014424
         // 00403f02: mov b1 al, b1 0x4
         // 00403f04: add ss:[esp+0xffffffffffffffbc], eax
      [-]33c0b004014424
         // 00403fa8: xor eax, eax
         // 00403faa: mov b1 al, b1 0x4
         // 00403fc4: mov b1 cl, b1 0x4
         // 00403fc6: add ss:[esp+0xffffffffffffffbc], ecx
         // 00403fe8: mov eax, ss:[esp+0xffffffffffffffbc]
         // 00403ffe: add ss:[esp+0xffffffffffffffbc], ecx

  }
  condition:
    all of them
}
