rule jqrk_40_0 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         894db4e9
         // 0040134a: mov ss:[ebp+0xffffffffffffffb4], ecx
         // 0040134d: jmp 0x4016a8
      [-]8b4c24045633f63bce751d
         // 00402381: mov ecx, ss:[esp+0x4]
         // 00402385: push esi
         // 00402386: xor esi, esi
         // 00402388: cmp ecx, esi
         // 0040238a: jnz 0x4023a9
      [-]1700005656565656c700????????e8
         // 00402391: push esi
         // 00402392: push esi
         // 00402393: push esi
         // 00402394: push esi
         // 00402395: push esi
         // 00402396: mov ds:[eax], 0x16
         // 0040239c: call __invalid_parameter
      [-]16000083c4146a16585ec3
         // 004023a1: add esp, 0x14
         // 004023a4: push 0x16
         // 004023a6: pop eax
         // 004023a7: pop esi
         // 004023a8: retn 
      [-]3bc674da
         // 004023ae: cmp eax, esi
         // 004023b0: jz 0x40238c
      [-]890133c05ec3
         // 004023b2: mov ds:[ecx], eax
         // 004023b4: xor eax, eax
         // 004023b6: pop esi
         // 004023b7: retn 
      [-]8b4424045633f63bc6751d
         // 004023b8: mov eax, ss:[esp+0x4]
         // 004023bc: push esi
         // 004023bd: xor esi, esi
         // 004023bf: cmp eax, esi
         // 004023c1: jnz 0x4023e0
      [-]1700005656565656c700????????e8
         // 004023c8: push esi
         // 004023c9: push esi
         // 004023ca: push esi
         // 004023cb: push esi
         // 004023cc: push esi
         // 004023cd: mov ds:[eax], 0x16
         // 004023d3: call __invalid_parameter
      [-]16000083c4146a16585ec3
         // 004023d8: add esp, 0x14
         // 004023db: push 0x16
         // 004023dd: pop eax
         // 004023de: pop esi
         // 004023df: retn 
      [-]890833c05ec3
         // 004023ee: mov ds:[eax], ecx
         // 004023f0: xor eax, eax
         // 004023f2: pop esi
         // 004023f3: retn 
      [-]3bc78bf0730f
         // 00402f1c: cmp eax, edi
         // 00402f1e: mov esi, eax
         // 00402f20: jnb 0x402f31
      [-]8b0685c07402
         // 00402f22: mov eax, ds:[esi]
         // 00402f24: test eax, eax
         // 00402f26: jz 0x402f2a
      [-]83c6043bf772f1
         // 00402f2a: add esi, 0x4
         // 00402f2d: cmp esi, edi
         // 00402f2f: jb 0x402f22
      [-]3bc78bf0730f
         // 00402f40: cmp eax, edi
         // 00402f42: mov esi, eax
         // 00402f44: jnb 0x402f55
      [-]8b0685c07402
         // 00402f46: mov eax, ds:[esi]
         // 00402f48: test eax, eax
         // 00402f4a: jz 0x402f4e
      [-]83c6043bf772f1
         // 00402f4e: add esi, 0x4
         // 00402f51: cmp esi, edi
         // 00402f53: jb 0x402f46
      [-]8b442404a3
         // 00403971: mov eax, ss:[esp+0x4]
         // 00403975: mov ds:[0x40e808], eax
      [-]f2ffff59c3
         // 00403dc1: pop ecx
         // 00403dc2: retn 
      [-]8b442404a3
         // 00403f73: mov eax, ss:[esp+0x4]
         // 00403f77: mov ds:[0x40e824], eax
      [-]8b442404a3
         // 00403f7d: mov eax, ss:[esp+0x4]
         // 00403f81: mov ds:[0x40e830], eax
      [-]8b442404a3
         // 00403f87: mov eax, ss:[esp+0x4]
         // 00403f8b: mov ds:[0x40e834], eax
      [-]8b442404a3
         // 00404066: mov eax, ss:[esp+0x4]
         // 0040406a: mov ds:[0x40e838], eax
      [-]558bec83ec20535657e8
         // 00404092: push ebp
         // 00404093: mov ebp, esp
         // 00404095: sub esp, 0x20
         // 00404098: push ebx
         // 00404099: push esi
         // 0040409a: push edi
         // 0040409b: call __encoded_null
      [-]efffff33db391d
         // 004040a0: xor ebx, ebx
         // 004040a2: cmp ds:[0x40e83c], ebx
      [-]8945f0895dfc895df8895df40f85ad000000
         // 004040a8: mov ss:[ebp+0xfffffffffffffff0], eax
         // 004040ab: mov ss:[ebp+0xfffffffffffffffc], ebx
         // 004040ae: mov ss:[ebp+0xfffffffffffffff8], ebx
         // 004040b1: mov ss:[ebp+0xfffffffffffffff4], ebx
         // 004040b4: jnz 0x404167
      [-]ff151c9040008bf83bfb7507
         // 004040bf: call ds:[__imp_LoadLibraryA]
         // 004040c5: mov edi, eax
         // 004040c7: cmp edi, ebx
         // 004040c9: jnz 0x4040d2
      [-]33c0e959010000
         // 004040cb: xor eax, eax
         // 004040cd: jmp 0x40422b
      [-]8b351090400068
         // 004040d2: mov esi, ds:[__imp_GetProcAddress]
         // 004040d8: push 0x409de4
      [-]57ffd63bc374e7
         // 004040dd: push edi
         // 004040de: call esi
         // 004040e0: cmp eax, ebx
         // 004040e2: jz 0x4040cb
      [-]eeffffc70424
         // 004040ea: mov ss:[esp], 0x409dd4
      [-]ffd650e8
         // 004040f7: call esi
         // 004040f9: push eax
         // 004040fa: call __encode_pointer
      [-]eeffffc70424
         // 004040ff: mov ss:[esp], 0x409dc0
      [-]ffd650e8
         // 0040410c: call esi
         // 0040410e: push eax
         // 0040410f: call __encode_pointer
      [-]eeffffa3
         // 00404114: mov ds:[0x40e844], eax
      [-]8d45f850e8
         // 00404119: lea eax, ss:[ebp+0xfffffffffffffff8]
         // 0040411c: push eax
         // 0040411d: call 0x402381
      [-]e2ffff85c05959740d
         // 00404122: test eax, eax
         // 00404124: pop ecx
         // 00404125: pop ecx
         // 00404126: jz 0x404135
      [-]5353535353e849f8ffff
         // 00404128: push ebx
         // 00404129: push ebx
         // 0040412a: push ebx
         // 0040412b: push ebx
         // 0040412c: push ebx
         // 0040412d: call __invoke_watson
      [-]837df802752c
         // 00404135: cmp ss:[ebp+0xfffffffffffffff8], 0x2
         // 00404139: jnz 0x404167
      [-]57ffd650e8
         // 00404140: push edi
         // 00404141: call esi
         // 00404143: push eax
         // 00404144: call __encode_pointer
      [-]eeffff3bc359a3
         // 00404149: cmp eax, ebx
         // 0040414b: pop ecx
         // 0040414c: mov ds:[0x40e84c], eax
      [-]57ffd650e8
         // 00404158: push edi
         // 00404159: call esi
         // 0040415b: push eax
         // 0040415c: call __encode_pointer
      [-]edffff59a3
         // 00404161: pop ecx
         // 00404162: mov ds:[0x40e848], eax
      [-]8b75f03bc6746d
         // 0040416c: mov esi, ss:[ebp+0xfffffffffffffff0]
         // 0040416f: cmp eax, esi
         // 00404171: jz 0x4041e0
      [-]eeffff59ffd03bc37425
         // 00404181: pop ecx
         // 00404182: call eax
         // 00404184: cmp eax, ebx
         // 00404186: jz 0x4041ad
      [-]8d4dec516a0c8d4de0516a0150ff35
         // 00404188: lea ecx, ss:[ebp+0xffffffffffffffec]
         // 0040418b: push ecx
         // 0040418c: push 0xc
         // 0040418e: lea ecx, ss:[ebp+0xffffffffffffffe0]
         // 00404191: push ecx
         // 00404192: push 0x1
         // 00404194: push eax
         // 00404195: push ds:[0x40e84c]
      [-]eeffff59ffd085c07406
         // 004041a0: pop ecx
         // 004041a1: call eax
         // 004041a3: test eax, eax
         // 004041a5: jz 0x4041ad
      [-]f645e8017533
         // 004041a7: test b1 ss:[ebp+0xffffffffffffffe8], b1 0x1
         // 004041ab: jnz 0x4041e0
      [-]8d45f450e8
         // 004041ad: lea eax, ss:[ebp+0xfffffffffffffff4]
         // 004041b0: push eax
         // 004041b1: call 0x4023b8
      [-]e2ffff85c059740d
         // 004041b6: test eax, eax
         // 004041b8: pop ecx
         // 004041b9: jz 0x4041c8
      [-]5353535353e8b6f7ffff
         // 004041bb: push ebx
         // 004041bc: push ebx
         // 004041bd: push ebx
         // 004041be: push ebx
         // 004041bf: push ebx
         // 004041c0: call __invoke_watson
      [-]837df4047209
         // 004041c8: cmp ss:[ebp+0xfffffffffffffff4], 0x4
         // 004041cc: jb 0x4041d7
      [-]814d10????????eb3a
         // 004041ce: or ss:[ebp+0x10], 0x200000
         // 004041d5: jmp 0x404211
      [-]814d10????????eb31
         // 004041d7: or ss:[ebp+0x10], 0x40000
         // 004041de: jmp 0x404211
      [-]3bc67428
         // 004041e5: cmp eax, esi
         // 004041e7: jz 0x404211
      [-]edffff59ffd03bc38945fc7418
         // 004041ef: pop ecx
         // 004041f0: call eax
         // 004041f2: cmp eax, ebx
         // 004041f4: mov ss:[ebp+0xfffffffffffffffc], eax
         // 004041f7: jz 0x404211
      [-]3bc6740f
         // 004041fe: cmp eax, esi
         // 00404200: jz 0x404211
      [-]ff75fc50e8
         // 00404202: push ss:[ebp+0xfffffffffffffffc]
         // 00404205: push eax
         // 00404206: call __decode_pointer
      [-]edffff59ffd08945fc
         // 0040420b: pop ecx
         // 0040420c: call eax
         // 0040420e: mov ss:[ebp+0xfffffffffffffffc], eax
      [-]ff7510ff750cff7508ff75fcff35
         // 00404211: push ss:[ebp+0x10]
         // 00404214: push ss:[ebp+0xc]
         // 00404217: push ss:[ebp+0x8]
         // 0040421a: push ss:[ebp+0xfffffffffffffffc]
         // 0040421d: push ds:[0x40e83c]
      [-]edffff59ffd0
         // 00404228: pop ecx
         // 00404229: call eax
      [-]5f5e5bc9c3
         // 0040422b: pop edi
         // 0040422c: pop esi
         // 0040422d: pop ebx
         // 0040422e: leave 
         // 0040422f: retn 
      [-]e89bffffffa3
         // 004079ec: call __get_sse2_info
         // 004079f1: mov ds:[0x40ec8c], eax

  }
  condition:
    all of them
}
