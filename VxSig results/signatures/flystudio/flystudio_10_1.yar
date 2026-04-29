rule flystudio_10_1 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         85db7503
         // 004010da: test ebx, ebx
         // 004010dc: jnz 0x4010e1
      [-]8bcbf7c1????????740f
         // 004010e1: mov ecx, ebx
         // 004010e3: test ecx, 0x3
         // 004010e9: jz 0x4010fa
      [-]8a014184c0743b
         // 004010eb: mov b1 al, b1 ds:[ecx]
         // 004010ed: inc ecx
         // 004010ee: test b1 al, b1 al
         // 004010f0: jz 0x40112d
      [-]f7c1????????75f1
         // 004010f2: test ecx, 0x3
         // 004010f8: jnz 0x4010eb
      [-]8b01ba????????03d083f0ff33c283c104a9????????74e8
         // 004010fa: mov eax, ds:[ecx]
         // 004010fc: mov edx, 0x7efefeff
         // 00401101: add edx, eax
         // 00401103: xor eax, 0xffffffffffffffff
         // 00401106: xor eax, edx
         // 00401108: add ecx, 0x4
         // 0040110b: test eax, 0xffffffff81010100
         // 00401110: jz 0x4010fa
      [-]8b41fc84c07426
         // 00401112: mov eax, ds:[ecx+0xfffffffffffffffc]
         // 00401115: test b1 al, b1 al
         // 00401117: jz 0x40113f
      [-]84e4741c
         // 00401119: test b1 ah, b1 ah
         // 0040111b: jz 0x401139
      [-]a9????????740f
         // 0040111d: test eax, 0xff0000
         // 00401122: jz 0x401133
      [-]a9????????7402
         // 00401124: test eax, 0xffffffffff000000
         // 00401129: jz 0x40112d
      [-]8d41ff2bc3c3
         // 0040112d: lea eax, ds:[ecx+0xffffffffffffffff]
         // 00401130: sub eax, ebx
         // 00401132: retn 
      [-]8d41fe2bc3c3
         // 00401133: lea eax, ds:[ecx+0xfffffffffffffffe]
         // 00401136: sub eax, ebx
         // 00401138: retn 
      [-]8d41fd2bc3c3
         // 00401139: lea eax, ds:[ecx+0xfffffffffffffffd]
         // 0040113c: sub eax, ebx
         // 0040113e: retn 
      [-]8d41fc2bc3c3
         // 0040113f: lea eax, ds:[ecx+0xfffffffffffffffc]
         // 00401142: sub eax, ebx
         // 00401144: retn 
      [-]558bec8bc140c1e0022be08d3c2451c745fc????????8d7508
         // 00401145: push ebp
         // 00401146: mov ebp, esp
         // 00401148: mov eax, ecx
         // 0040114a: inc eax
         // 0040114b: shl eax, b1 0x2
         // 0040114e: sub esp, eax
         // 00401150: lea edi, ss:[esp]
         // 00401153: push ecx
         // 00401154: mov ss:[ebp+0xfffffffffffffffc], 0x1
         // 0040115b: lea esi, ss:[ebp+0x8]
      [-]8b1e83c60451e8
         // 0040115e: mov ebx, ds:[esi]
         // 00401160: add esi, 0x4
         // 00401163: push ecx
         // 00401164: call 0x4010da
      [-]590145fc890783c7044975e9
         // 00401169: pop ecx
         // 0040116a: add ss:[ebp+0xfffffffffffffffc], eax
         // 0040116d: mov ds:[edi], eax
         // 0040116f: add edi, 0x4
         // 00401172: dec ecx
         // 00401173: jnz 0x40115e
      [-]ff75fce8
         // 00401b3e: push ss:[ebp+0xfffffffffffffffc]
         // 00401b41: call 0x418af2
      [-]0083c4048bf8588d1c24578d5508
         // 00401b46: add esp, 0x4
         // 00401b49: mov edi, eax
         // 00401b4b: pop eax
         // 00401b4c: lea ebx, ss:[esp]
         // 00401b4f: push edi
         // 00401b50: lea edx, ss:[ebp+0x8]
      [-]8b0b83c3048b3283c204f3a44875f1
         // 0040118a: mov ecx, ds:[ebx]
         // 0040118c: add ebx, 0x4
         // 0040118f: mov esi, ds:[edx]
         // 00401191: add edx, 0x4
         // 00401194: rep movsbb 
         // 00401196: dec eax
         // 00401197: jnz 0x40118a
      [-]c60700588be55dc3
         // 00401199: mov b1 ds:[edi], b1 0x0
         // 0040119c: pop eax
         // 0040119d: mov esp, ebp
         // 0040119f: pop ebp
         // 004011a0: retn 
      [-]fcdbe3e8
         // 004127c2: cld 
         // 004127c3: fninit 
         // 004127c5: call 0x4127b5
      [-]b8????????e8
         // 004127cf: mov eax, 0x3
         // 004127d4: call 0x412816
      [-]83c404e8
         // 004127d9: add esp, 0x4
         // 004127e6: call 0x41076c
      [-]578b7c24
         // 004cdf40: push edi
         // 004cdf41: mov edi, ss:[esp+0x8]
      [-]83c9ff33c0f2aef7d1495f8bc1c3
         // 004cdf45: or ecx, 0xffffffffffffffff
         // 004cdf48: xor eax, eax
         // 004cdf4a: repne scasbb 
         // 004cdf4c: not ecx
         // 004cdf4e: dec ecx
         // 004cdf4f: pop edi
         // 004cdf50: mov eax, ecx
         // 004cdf52: retn 
      [-]83ec1c8d442400
         // 004f4160: sub esp, 0x1c
         // 004f4163: lea eax, ss:[esp+0x0]
      [-]6a006a006a006a0050ff
         // 004f416e: push 0x0
         // 004f4170: push 0x0
         // 004f4172: push 0x0
         // 004f4174: push 0x0
         // 004f4176: push eax
         // 004f4177: call esi
      [-]6a006a006a008d
         // 004f4190: push 0x0
         // 004f4192: push 0x0
         // 004f4194: push 0x0
         // 004f4196: lea eax, ss:[esp+0x10]
      [-]83c41cc3
         // 004e3aa4: add esp, 0x1c
         // 004e3aa7: retn 
      [-]8b44240485c07501
         // 004ecd90: mov eax, ss:[esp+0x4]
         // 004ecd94: test eax, eax
         // 004ecd96: jnz 0x4ecd99
      [-]25????????3d????????7506
         // 004ecd99: and eax, 0xffffffffc0000000
         // 004ecd9e: cmp eax, 0xffffffff80000000
         // 004ecda3: jnz 0x4ecdab
      [-]b8????????c3
         // 004ecda5: mov eax, 0x1
         // 004ecdaa: retn 
      [-]33c93d????????0f95c183c1028bc1c3
         // 004ecdab: xor ecx, ecx
         // 004ecdad: cmp eax, 0x40000000
         // 004ecdb2: setnz b1 cl
         // 004ecdb5: add ecx, 0x2
         // 004ecdb8: mov eax, ecx
         // 004ecdba: retn 

  }
  condition:
    all of them
}
