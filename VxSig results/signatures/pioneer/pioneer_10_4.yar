rule pioneer_10_4 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         5060e8edffffffc20400
         // 0041abf5: push eax
         // 0041abf6: pusha 
         // 0041abf7: call 0x41abe9
         // 0041abfc: retn b2 0x4
      [-]8b542404807a03017504
         // 0041ac27: mov edx, ss:[esp+0x4]
         // 0041ac2b: cmp b1 ds:[edx+0x3], b1 0x1
         // 0041ac2f: jnz 0x41ac35
      [-]8d4204c3
         // 0041ac31: lea eax, ds:[edx+0x4]
         // 0041ac34: retn 
      [-]8d4204538bc8
         // 0041ac35: lea eax, ds:[edx+0x4]
         // 0041ac38: push ebx
         // 0041ac39: mov ecx, eax
      [-]8a5a0284db7402
         // 0041ac3b: mov b1 bl, b1 ds:[edx+0x2]
         // 0041ac3e: test b1 bl, b1 bl
         // 0041ac40: jz 0x41ac44
      [-]8a19f6d384db88197403
         // 0041ac44: mov b1 bl, b1 ds:[ecx]
         // 0041ac46: not b1 bl
         // 0041ac48: test b1 bl, b1 bl
         // 0041ac4a: mov b1 ds:[ecx], b1 bl
         // 0041ac4c: jz 0x41ac51
      [-]c64203015bc3
         // 0041ac51: mov b1 ds:[edx+0x3], b1 0x1
         // 0041ac55: pop ebx
         // 0041ac56: retn 
      [-]8b480885c97503
         // 0041ac6f: mov ecx, ds:[eax+0x8]
         // 0041ac72: test ecx, ecx
         // 0041ac74: jnz 0x41ac79
      [-]8b500c3954240c7208
         // 0041ac79: mov edx, ds:[eax+0xc]
         // 0041ac7c: cmp ss:[esp+0xc], edx
         // 0041ac80: jb 0x41ac8a
      [-]03d13954240c720a
         // 0041ac82: add edx, ecx
         // 0041ac84: cmp ss:[esp+0xc], edx
         // 0041ac88: jb 0x41ac94
      [-]4783c0283bfe72dd
         // 0041ac8a: inc edi
         // 0041ac8b: add eax, 0x28
         // 0041ac8e: cmp edi, esi
         // 0041ac90: jb 0x41ac6f
      [-]e841deffffc3
         // 0041cdaf: call 0x41abf5
         // 0041cdb4: retn 

  }
  condition:
    all of them
}
