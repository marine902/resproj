rule jqrk_10_4 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         894db4e9
         // 00401106: mov ss:[ebp+0xffffffffffffffb4], ecx
         // 00401109: jmp 0x4012dc
      [-]8b4c24045633f63bce751d
         // 004022a3: mov ecx, ss:[esp+0x4]
         // 004022a7: push esi
         // 004022a8: xor esi, esi
         // 004022aa: cmp ecx, esi
         // 004022ac: jnz 0x4022cb
      [-]1700005656565656c700????????e8
         // 004022b3: push esi
         // 004022b4: push esi
         // 004022b5: push esi
         // 004022b6: push esi
         // 004022b7: push esi
         // 004022b8: mov ds:[eax], 0x16
         // 004022be: call __invalid_parameter
      [-]16000083c4146a16585ec3
         // 004022c3: add esp, 0x14
         // 004022c6: push 0x16
         // 004022c8: pop eax
         // 004022c9: pop esi
         // 004022ca: retn 
      [-]3bc674da
         // 004022d0: cmp eax, esi
         // 004022d2: jz 0x4022ae
      [-]890133c05ec3
         // 004022d4: mov ds:[ecx], eax
         // 004022d6: xor eax, eax
         // 004022d8: pop esi
         // 004022d9: retn 
      [-]8b4424045633f63bc6751d
         // 004022da: mov eax, ss:[esp+0x4]
         // 004022de: push esi
         // 004022df: xor esi, esi
         // 004022e1: cmp eax, esi
         // 004022e3: jnz 0x402302
      [-]1700005656565656c700????????e8
         // 004022ea: push esi
         // 004022eb: push esi
         // 004022ec: push esi
         // 004022ed: push esi
         // 004022ee: push esi
         // 004022ef: mov ds:[eax], 0x16
         // 004022f5: call __invalid_parameter
      [-]16000083c4146a16585ec3
         // 004022fa: add esp, 0x14
         // 004022fd: push 0x16
         // 004022ff: pop eax
         // 00402300: pop esi
         // 00402301: retn 
      [-]890833c05ec3
         // 00402310: mov ds:[eax], ecx
         // 00402312: xor eax, eax
         // 00402314: pop esi
         // 00402315: retn 
      [-]3bc78bf0730f
         // 00402e3e: cmp eax, edi
         // 00402e40: mov esi, eax
         // 00402e42: jnb 0x402e53
      [-]8b0685c07402
         // 00402e44: mov eax, ds:[esi]
         // 00402e46: test eax, eax
         // 00402e48: jz 0x402e4c
      [-]83c6043bf772f1
         // 00402e4c: add esi, 0x4
         // 00402e4f: cmp esi, edi
         // 00402e51: jb 0x402e44
      [-]3bc78bf0730f
         // 00402e62: cmp eax, edi
         // 00402e64: mov esi, eax
         // 00402e66: jnb 0x402e77
      [-]8b0685c07402
         // 00402e68: mov eax, ds:[esi]
         // 00402e6a: test eax, eax
         // 00402e6c: jz 0x402e70
      [-]83c6043bf772f1
         // 00402e70: add esi, 0x4
         // 00402e73: cmp esi, edi
         // 00402e75: jb 0x402e68
      [-]8b442404a3
         // 00403891: mov eax, ss:[esp+0x4]
         // 00403895: mov ds:[0x40e9c8], eax
      [-]f2ffff59c3
         // 00403ce1: pop ecx
         // 00403ce2: retn 
      [-]8b442404a3
         // 00403e93: mov eax, ss:[esp+0x4]
         // 00403e97: mov ds:[0x40e9e4], eax
      [-]8b442404a3
         // 00403e9d: mov eax, ss:[esp+0x4]
         // 00403ea1: mov ds:[0x40e9f0], eax
      [-]8b442404a3
         // 00403ea7: mov eax, ss:[esp+0x4]
         // 00403eab: mov ds:[0x40e9f4], eax
      [-]8b442404a3
         // 00403f86: mov eax, ss:[esp+0x4]
         // 00403f8a: mov ds:[0x40e9f8], eax
      [-]558bec83ec20535657e8
         // 00403fb2: push ebp
         // 00403fb3: mov ebp, esp
         // 00403fb5: sub esp, 0x20
         // 00403fb8: push ebx
         // 00403fb9: push esi
         // 00403fba: push edi
         // 00403fbb: call __encoded_null
      [-]efffff33db391d
         // 00403fc0: xor ebx, ebx
         // 00403fc2: cmp ds:[0x40e9fc], ebx
      [-]8945f0895dfc895df8895df40f85ad000000
         // 00403fc8: mov ss:[ebp+0xfffffffffffffff0], eax
         // 00403fcb: mov ss:[ebp+0xfffffffffffffffc], ebx
         // 00403fce: mov ss:[ebp+0xfffffffffffffff8], ebx
         // 00403fd1: mov ss:[ebp+0xfffffffffffffff4], ebx
         // 00403fd4: jnz 0x404087
      [-]ff151c9040008bf83bfb7507
         // 00403fdf: call ds:[__imp_LoadLibraryA]
         // 00403fe5: mov edi, eax
         // 00403fe7: cmp edi, ebx
         // 00403fe9: jnz 0x403ff2
      [-]33c0e959010000
         // 00403feb: xor eax, eax
         // 00403fed: jmp 0x40414b
      [-]8b351090400068
         // 00403ff2: mov esi, ds:[__imp_GetProcAddress]
         // 00403ff8: push 0x409e1c
      [-]57ffd63bc374e7
         // 00403ffd: push edi
         // 00403ffe: call esi
         // 00404000: cmp eax, ebx
         // 00404002: jz 0x403feb
      [-]eeffffc70424
         // 0040400a: mov ss:[esp], 0x409e0c
      [-]ffd650e8
         // 00404017: call esi
         // 00404019: push eax
         // 0040401a: call __encode_pointer
      [-]eeffffc70424
         // 0040401f: mov ss:[esp], 0x409df8
      [-]ffd650e8
         // 0040402c: call esi
         // 0040402e: push eax
         // 0040402f: call __encode_pointer
      [-]eeffffa3
         // 00404034: mov ds:[0x40ea04], eax
      [-]8d45f850e8
         // 00404039: lea eax, ss:[ebp+0xfffffffffffffff8]
         // 0040403c: push eax
         // 0040403d: call 0x4022a3
      [-]e2ffff85c05959740d
         // 00404042: test eax, eax
         // 00404044: pop ecx
         // 00404045: pop ecx
         // 00404046: jz 0x404055
      [-]5353535353e849f8ffff
         // 00404048: push ebx
         // 00404049: push ebx
         // 0040404a: push ebx
         // 0040404b: push ebx
         // 0040404c: push ebx
         // 0040404d: call __invoke_watson
      [-]837df802752c
         // 00404055: cmp ss:[ebp+0xfffffffffffffff8], 0x2
         // 00404059: jnz 0x404087
      [-]57ffd650e8
         // 00404060: push edi
         // 00404061: call esi
         // 00404063: push eax
         // 00404064: call __encode_pointer
      [-]eeffff3bc359a3
         // 00404069: cmp eax, ebx
         // 0040406b: pop ecx
         // 0040406c: mov ds:[0x40ea0c], eax
      [-]57ffd650e8
         // 00404078: push edi
         // 00404079: call esi
         // 0040407b: push eax
         // 0040407c: call __encode_pointer
      [-]edffff59a3
         // 00404081: pop ecx
         // 00404082: mov ds:[0x40ea08], eax
      [-]8b75f03bc6746d
         // 0040408c: mov esi, ss:[ebp+0xfffffffffffffff0]
         // 0040408f: cmp eax, esi
         // 00404091: jz 0x404100
      [-]eeffff59ffd03bc37425
         // 004040a1: pop ecx
         // 004040a2: call eax
         // 004040a4: cmp eax, ebx
         // 004040a6: jz 0x4040cd
      [-]8d4dec516a0c8d4de0516a0150ff35
         // 004040a8: lea ecx, ss:[ebp+0xffffffffffffffec]
         // 004040ab: push ecx
         // 004040ac: push 0xc
         // 004040ae: lea ecx, ss:[ebp+0xffffffffffffffe0]
         // 004040b1: push ecx
         // 004040b2: push 0x1
         // 004040b4: push eax
         // 004040b5: push ds:[0x40ea0c]
      [-]eeffff59ffd085c07406
         // 004040c0: pop ecx
         // 004040c1: call eax
         // 004040c3: test eax, eax
         // 004040c5: jz 0x4040cd
      [-]f645e8017533
         // 004040c7: test b1 ss:[ebp+0xffffffffffffffe8], b1 0x1
         // 004040cb: jnz 0x404100
      [-]8d45f450e8
         // 004040cd: lea eax, ss:[ebp+0xfffffffffffffff4]
         // 004040d0: push eax
         // 004040d1: call 0x4022da
      [-]e2ffff85c059740d
         // 004040d6: test eax, eax
         // 004040d8: pop ecx
         // 004040d9: jz 0x4040e8
      [-]5353535353e8b6f7ffff
         // 004040db: push ebx
         // 004040dc: push ebx
         // 004040dd: push ebx
         // 004040de: push ebx
         // 004040df: push ebx
         // 004040e0: call __invoke_watson
      [-]837df4047209
         // 004040e8: cmp ss:[ebp+0xfffffffffffffff4], 0x4
         // 004040ec: jb 0x4040f7
      [-]814d10????????eb3a
         // 004040ee: or ss:[ebp+0x10], 0x200000
         // 004040f5: jmp 0x404131
      [-]814d10????????eb31
         // 004040f7: or ss:[ebp+0x10], 0x40000
         // 004040fe: jmp 0x404131
      [-]3bc67428
         // 00404105: cmp eax, esi
         // 00404107: jz 0x404131
      [-]edffff59ffd03bc38945fc7418
         // 0040410f: pop ecx
         // 00404110: call eax
         // 00404112: cmp eax, ebx
         // 00404114: mov ss:[ebp+0xfffffffffffffffc], eax
         // 00404117: jz 0x404131
      [-]3bc6740f
         // 0040411e: cmp eax, esi
         // 00404120: jz 0x404131
      [-]ff75fc50e8
         // 00404122: push ss:[ebp+0xfffffffffffffffc]
         // 00404125: push eax
         // 00404126: call __decode_pointer
      [-]edffff59ffd08945fc
         // 0040412b: pop ecx
         // 0040412c: call eax
         // 0040412e: mov ss:[ebp+0xfffffffffffffffc], eax
      [-]ff7510ff750cff7508ff75fcff35
         // 00404131: push ss:[ebp+0x10]
         // 00404134: push ss:[ebp+0xc]
         // 00404137: push ss:[ebp+0x8]
         // 0040413a: push ss:[ebp+0xfffffffffffffffc]
         // 0040413d: push ds:[0x40e9fc]
      [-]edffff59ffd0
         // 00404148: pop ecx
         // 00404149: call eax
      [-]5f5e5bc9c3
         // 0040414b: pop edi
         // 0040414c: pop esi
         // 0040414d: pop ebx
         // 0040414e: leave 
         // 0040414f: retn 
      [-]e89bffffffa3
         // 0040790c: call __get_sse2_info
         // 00407911: mov ds:[0x40ee4c], eax

  }
  condition:
    all of them
}
