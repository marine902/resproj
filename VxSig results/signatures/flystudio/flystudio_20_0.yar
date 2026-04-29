rule flystudio_20_0 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         558bec8bc140c1e0022be08d3c2451c745fc????????8d7508
         // 0040171f: push ebp
         // 00401720: mov ebp, esp
         // 00401722: mov eax, ecx
         // 00401724: inc eax
         // 00401725: shl eax, b1 0x2
         // 00401728: sub esp, eax
         // 0040172a: lea edi, ss:[esp]
         // 0040172d: push ecx
         // 0040172e: mov ss:[ebp+0xfffffffffffffffc], 0x1
         // 00401735: lea esi, ss:[ebp+0x8]
      [-]8b1e83c60451e8
         // 00401ea3: mov ebx, ds:[esi]
         // 00401ea5: add esi, 0x4
         // 00401ea8: push ecx
         // 00401ea9: call 0x4011b4
      [-]590145fc890783c7044975e9
         // 00401eae: pop ecx
         // 00401eaf: add ss:[ebp+0xfffffffffffffffc], eax
         // 00401eb2: mov ds:[edi], eax
         // 00401eb4: add edi, 0x4
         // 00401eb7: dec ecx
         // 00401eb8: jnz 0x401ea3
      [-]ff75fce8
         // 0040116f: push ss:[ebp+0xfffffffffffffffc]
         // 00401172: call 0x40a41e
      [-]0083c4048bf8588d1c24578d5508
         // 00401177: add esp, 0x4
         // 0040117a: mov edi, eax
         // 0040117c: pop eax
         // 0040117d: lea ebx, ss:[esp]
         // 00401180: push edi
         // 00401181: lea edx, ss:[ebp+0x8]
      [-]8b0b83c3048b3283c204f3a44875f1
         // 00401764: mov ecx, ds:[ebx]
         // 00401766: add ebx, 0x4
         // 00401769: mov esi, ds:[edx]
         // 0040176b: add edx, 0x4
         // 0040176e: rep movsbb 
         // 00401770: dec eax
         // 00401771: jnz 0x401764
      [-]c60700588be55dc3
         // 00401773: mov b1 ds:[edi], b1 0x0
         // 00401776: pop eax
         // 00401777: mov esp, ebp
         // 00401779: pop ebp
         // 0040177a: retn 
      [-]83ec1c8d442400
         // 004e3a60: sub esp, 0x1c
         // 004e3a63: lea eax, ss:[esp+0x0]
      [-]6a006a006a006a0050ff
         // 004e3a6e: push 0x0
         // 004e3a70: push 0x0
         // 004e3a72: push 0x0
         // 004e3a74: push 0x0
         // 004e3a76: push eax
         // 004e3a77: call esi
      [-]6a006a006a008d
         // 004302a0: push 0x0
         // 004302a2: push 0x0
         // 004302a4: push 0x0
         // 004302a6: lea eax, ss:[esp+0x10]
      [-]83c41cc3
         // 0040b8fb: add esp, 0x1c
         // 0040b8fe: retn 
      [-]8b44240485c07501
         // 0040c320: mov eax, ss:[esp+0x4]
         // 0040c324: test eax, eax
         // 0040c326: jnz 0x40c329
      [-]25????????3d????????7506
         // 0040c329: and eax, 0xffffffffc0000000
         // 0040c32e: cmp eax, 0xffffffff80000000
         // 0040c333: jnz 0x40c33b
      [-]b8????????c3
         // 0040c335: mov eax, 0x1
         // 0040c33a: retn 
      [-]33c93d????????0f95c183c1028bc1c3
         // 0040c33b: xor ecx, ecx
         // 0040c33d: cmp eax, 0x40000000
         // 0040c342: setnz b1 cl
         // 0040c345: add ecx, 0x2
         // 0040c348: mov eax, ecx
         // 0040c34a: retn 

  }
  condition:
    all of them
}
