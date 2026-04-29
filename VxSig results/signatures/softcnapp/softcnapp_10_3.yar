rule softcnapp_10_3 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         558bec8b5508b9
         // 004cf270: push ebp
         // 004cf271: mov ebp, esp
         // 004cf274: mov edx, ss:[ebp+0x8]
         // 004cf277: mov ecx, 0x6f0728
      [-]5356578b4208bf
         // 004cf27c: push ebx
         // 004cf27d: push esi
         // 004cf27e: push edi
         // 004cf27f: mov eax, ds:[edx+0x8]
         // 004cf282: mov edi, 0x65134c
      [-]0f45c88b420c
         // 004cf28e: cmovnz ecx, eax
         // 004cf291: mov eax, ds:[edx+0xc]
      [-]0f45f88b42
         // 004cf296: cmovnz edi, eax
         // 004cf299: mov eax, ds:[edx+0x14]
      [-]80382ebe
         // 0051a6da: cmp b1 ds:[eax], b1 0x2e
         // 0051a6dd: mov esi, 0x655bb8
      [-]560f44c15068
         // 00431e4b: push esi
         // 00431e4c: cmovz eax, ecx
         // 00431e4f: push eax
         // 00431e50: push 0x5a48bc
      [-]83c42c5f5e5b5dc3
         // 00431e5a: add esp, 0x2c
         // 00431e5d: pop edi
         // 00431e5e: pop esi
         // 00431e5f: pop ebx
         // 00431e62: pop ebp
         // 00431e63: retn 
      [-]558bec8b45088b80
         // 0051afd0: push ebp
         // 0051afd1: mov ebp, esp
         // 0051afd3: mov eax, ss:[ebp+0x8]
         // 0051afd6: mov eax, ds:[eax+0x3bc]
      [-]558bec8b4d085651e8
         // 004325a0: push ebp
         // 004325a1: mov ebp, esp
         // 004325a3: mov ecx, ss:[ebp+0x8]
         // 004325a6: push esi
         // 004325a7: push ecx
         // 004325a8: call 0x4324b0
      [-]83c410c746
         // 004325bb: add esp, 0x10
         // 004325be: mov ds:[esi+0x14], 0x0
      [-]005e5dc3
         // 004325c5: pop esi
         // 004325c6: pop ebp
         // 004325c7: retn 
      [-]558bec568b7508
         // 0053aba0: push ebp
         // 0053aba1: mov ebp, esp
         // 0053aba3: push esi
         // 0053aba4: mov esi, ss:[ebp+0x8]
      [-]558bec568b75088b
         // 005425c0: push ebp
         // 005425c1: mov ebp, esp
         // 005425c3: push esi
         // 005425c4: mov esi, ss:[ebp+0x8]
         // 005425c7: mov eax, ds:[esi+0x1d0]
      [-]83c40ceb0f
         // 005231f4: add esp, 0xc
         // 005231f7: jmp 0x523208
      [-]558bec8b
         // 00523290: push ebp
         // 00523291: mov ebp, esp
         // 00523293: mov ecx, ss:[ebp+0x8]
      [-]558bec83ec086a006a00c745fc????????c745f8????????ff15
         // 00544300: push ebp
         // 00544301: mov ebp, esp
         // 00544303: sub esp, 0x8
         // 00544306: push 0x0
         // 00544308: push 0x0
         // 0054430a: mov ss:[ebp+0xfffffffffffffffc], 0x0
         // 00544311: mov ss:[ebp+0xfffffffffffffff8], 0x4
         // 00544318: call ds:[SleepEx]
      [-]8d45f8508d45fc5068????????68????????ff7508ff15
         // 0054431e: lea eax, ss:[ebp+0xfffffffffffffff8]
         // 00544321: push eax
         // 00544322: lea eax, ss:[ebp+0xfffffffffffffffc]
         // 00544325: push eax
         // 00544326: push 0x1007
         // 0054432b: push 0xffff
         // 00544330: push ss:[ebp+0x8]
         // 00544333: call ds:[getsockopt]
      [-]3d????????7404
         // 004d97bc: cmp eax, 0x2748
         // 004d97c1: jz 0x4d97c7
      [-]558bec51538b5d08b8
         // 00525bf0: push ebp
         // 00525bf1: mov ebp, esp
         // 00525bf3: push ecx
         // 00525bf4: push ebx
         // 00525bf5: mov ebx, ss:[ebp+0x8]
         // 00525bf8: mov eax, 0x657bec
      [-]837d0c03bf
         // 00525c08: cmp ss:[ebp+0xc], 0x3
         // 00525c0c: mov edi, 0x657ba0
      [-]ff3753e8
         // 004e4f71: push ds:[edi]
         // 004e4f73: push ebx
         // 004e4f74: call 0x4c9360
      [-]fe077ce8
         // 004e4f87: jl 0x4e4f71
      [-]005f0f45c65e5b8be55dc3
         // 004e4f90: pop edi
         // 004e4f91: cmovnz eax, esi
         // 004e4f94: pop esi
         // 004e4f95: pop ebx
         // 004e4f96: mov esp, ebp
         // 004e4f98: pop ebp
         // 004e4f99: retn 
      [-]005f0f45c65e5b8be55dc3
         // 004e4fa5: pop edi
         // 004e4fa6: cmovnz eax, esi
         // 004e4fa9: pop esi
         // 004e4faa: pop ebx
         // 004e4fab: mov esp, ebp
         // 004e4fad: pop ebp
         // 004e4fae: retn 
      [-]558bec51538b5d085657
         // 00525c60: push ebp
         // 00525c61: mov ebp, esp
         // 00525c63: push ecx
         // 00525c64: push ebx
         // 00525c65: mov ebx, ss:[ebp+0x8]
         // 00525c68: push esi
         // 00525c69: push edi
      [-]ff3753e8
         // 004e4fc5: push ds:[edi]
         // 004e4fc7: push ebx
         // 004e4fc8: call 0x4c9360
      [-]fe0c7ce8
         // 004e4fdb: jl 0x4e4fc5
      [-]005f0f45c65e5b8be55dc3
         // 004e4fe4: pop edi
         // 004e4fe5: cmovnz eax, esi
         // 004e4fe8: pop esi
         // 004e4fe9: pop ebx
         // 004e4fea: mov esp, ebp
         // 004e4fec: pop ebp
         // 004e4fed: retn 
      [-]005f0f45c65e5b8be55dc3
         // 004e4ff9: pop edi
         // 004e4ffa: cmovnz eax, esi
         // 004e4ffd: pop esi
         // 004e4ffe: pop ebx
         // 004e4fff: mov esp, ebp
         // 004e5001: pop ebp
         // 004e5002: retn 
      [-]558bec538b5d085657be
         // 00525cc0: push ebp
         // 00525cc1: mov ebp, esp
         // 00525cc3: push ebx
         // 00525cc4: mov ebx, ss:[ebp+0x8]
         // 00525cc7: push esi
         // 00525cc8: push edi
         // 00525cc9: mov esi, 0x657c08
      [-]5f5e83c8ff5b5dc3
         // 004e5037: pop edi
         // 004e5038: pop esi
         // 004e5039: or eax, 0xffffffffffffffff
         // 004e503c: pop ebx
         // 004e503d: pop ebp
         // 004e503e: retn 
      [-]8b4608c1e0042b46085f5ec1e0025b5dc3
         // 004e503f: mov eax, ds:[esi+0x8]
         // 004e5042: shl eax, b1 0x4
         // 004e5045: sub eax, ds:[esi+0x8]
         // 004e5048: pop edi
         // 004e5049: pop esi
         // 004e504a: shl eax, b1 0x2
         // 004e504d: pop ebx
         // 004e504e: pop ebp
         // 004e504f: retn 
      [-]558bec568b75088b06
         // 0049bec0: push ebp
         // 0049bec1: mov ebp, esp
         // 0049bec3: push esi
         // 0049bec4: mov esi, ss:[ebp+0x8]
         // 0049bec7: mov eax, ds:[esi]
      [-]ff068b06
         // 0049bee0: inc ds:[esi]
         // 0049bee2: mov eax, ds:[esi]
      [-]558bec6a006a00ff750cff75086a006a00e8
         // 00527a20: push ebp
         // 00527a21: mov ebp, esp
         // 00527a23: push 0x0
         // 00527a25: push 0x0
         // 00527a27: push ss:[ebp+0xc]
         // 00527a2a: push ss:[ebp+0x8]
         // 00527a2d: push 0x0
         // 00527a2f: push 0x0
         // 00527a31: call 0x53fdec
      [-]83f8ff7502
         // 004e5c2d: cmp eax, 0xffffffffffffffff
         // 004e5c30: jnz 0x4e5c34
      [-]558bec56578b7d086affff37ff15
         // 004e5c50: push ebp
         // 004e5c51: mov ebp, esp
         // 004e5c53: push esi
         // 004e5c54: push edi
         // 004e5c55: mov edi, ss:[ebp+0x8]
         // 004e5c58: push 0xffffffffffffffff
         // 004e5c5a: push ds:[edi]
         // 004e5c5c: call ds:[WaitForSingleObject]
      [-]ff37f7d81bf6e8d3ff
         // 004e5c62: push ds:[edi]
         // 004e5c64: neg eax
         // 004e5c66: sbb esi, esi
         // 004e5c68: call 0x4e5c40
      [-]83c404c707????????8d46015f5e5dc3
         // 004e5c6d: add esp, 0x4
         // 004e5c70: mov ds:[edi], 0x0
         // 004e5c76: lea eax, ds:[esi+0x1]
         // 004e5c79: pop edi
         // 004e5c7a: pop esi
         // 004e5c7b: pop ebp
         // 004e5c7c: retn 
      [-]558bec8b
         // 00549670: push ebp
         // 00549671: mov ebp, esp
         // 00549673: mov ecx, ss:[ebp+0xc]
      [-]ff83c40c
         // 004a535e: add esp, 0xc
      [-]0f45c88d
         // 004a5376: cmovnz ecx, eax
         // 004a5379: lea eax, ds:[edx+0x300]
      [-]010083c4
         // 004a538e: add esp, 0x10
      [-]115e5dc3
         // 00554b51: mov ds:[ecx], edx
         // 00554b53: pop esi
         // 00554b54: pop ebp
         // 00554b55: retn 
      [-]558bec568b7508
         // 00533e00: push ebp
         // 00533e01: mov ebp, esp
         // 00533e03: push esi
         // 00533e04: mov esi, ss:[ebp+0x8]
      [-]83c404c746
         // 00533e42: add esp, 0x4
         // 00533e45: mov ds:[esi+0x3c], 0x0
      [-]558bec53
         // 004a8040: push ebp
         // 004a8041: mov ebp, esp
         // 004a8043: push ebx
      [-]8b750857
         // 004a8048: mov esi, ss:[ebp+0x8]
         // 004a804b: push edi
      [-]5e5b5dc3
         // 00533f0e: pop esi
         // 00533f0f: pop ebx
         // 00533f10: pop ebp
         // 00533f11: retn 
      [-]0fb60650e8
         // 004a80dd: movzx eax, b1 ds:[esi]
         // 004a80e0: push eax
         // 004a80e1: call 0x48d310
      [-]0fb6460150e8
         // 004a80ed: movzx eax, b1 ds:[esi+0x1]
         // 004a80f1: push eax
         // 004a80f2: call 0x48d310
      [-]0fb6460250e8
         // 004a80fe: movzx eax, b1 ds:[esi+0x2]
         // 004a8102: push eax
         // 004a8103: call 0x48d310
      [-]807e032075
         // 004ee92f: cmp b1 ds:[esi+0x3], b1 0x20
         // 004ee933: jnz 0x4ee952
      [-]6a0a6a0056e8
         // 00533f98: push 0xa
         // 00533f9a: push 0x0
         // 00533f9c: push esi
         // 00533f9d: call 0x5022fe
      [-]83c4108901
         // 00533fab: add esp, 0x10
         // 00533fae: mov ds:[ecx], eax
      [-]53568b75
         // 004ee9e7: push ebx
         // 004ee9e8: push esi
         // 004ee9e9: mov esi, ss:[ebp+0x8]
      [-]1cdd????????38
         // 004ee9fd: cmp b1 ds:[edi+0x58], b1 bl
      [-]5268????????56e8
         // 004eea0c: push edx
         // 004eea0d: push 0xc8
         // 004eea12: push esi
         // 004eea13: call 0x4f0670
      [-]000083c414
         // 004eea18: add esp, 0x14
      [-]5e5b5dc3
         // 004eea1c: pop esi
         // 004eea1d: pop ebx
         // 004eea1e: pop ebp
         // 004eea1f: retn 
      [-]0fb6c35068
         // 00454710: movzx eax, b1 bl
         // 00454713: push eax
         // 00454714: push 0x5a9e88
      [-]83c40888
         // 005340cf: add esp, 0x8
         // 005340d2: mov b1 ds:[edi+0x60], b1 bl
      [-]558bec8b4508
         // 005340e0: push ebp
         // 005340e1: mov ebp, esp
         // 005340e3: mov eax, ss:[ebp+0x8]
      [-]4d0c0f94c10fbe90
         // 005340e8: cmp ss:[ebp+0xc], ecx
         // 005340eb: setz b1 cl
         // 005340ee: movsx edx, b1 ds:[eax+0x430]
      [-]8d0ccd????????3bd10f95c05dc3
         // 005340f7: lea ecx, ds:[0x41+ecx*0x8]
         // 005340fe: cmp edx, ecx
         // 00534100: setnz b1 al
         // 00534103: pop ebp
         // 00534104: retn 
      [-]558bec81ec????????a1
         // 004eee70: push ebp
         // 004eee71: mov ebp, esp
         // 004eee73: sub esp, 0x104
         // 004eee79: mov eax, ds:[___security_cookie]
      [-]0033c58945fc8b450c8d8d????????568b7510578b7d0868????????5150e8
         // 004eee7e: xor eax, ebp
         // 004eee80: mov ss:[ebp+0xfffffffffffffffc], eax
         // 004eee83: mov eax, ss:[ebp+0xc]
         // 004eee86: lea ecx, ss:[ebp+0xfffffffffffffefc]
         // 004eee8c: push esi
         // 004eee8d: mov esi, ss:[ebp+0x10]
         // 004eee90: push edi
         // 004eee91: mov edi, ss:[ebp+0x8]
         // 004eee94: push 0x100
         // 004eee99: push ecx
         // 004eee9a: push eax
         // 004eee9b: call 0x4d0240
      [-]ffff75148d85????????505668
         // 004eeea0: push ss:[ebp+0x14]
         // 004eeea3: lea eax, ss:[ebp+0xfffffffffffffefc]
         // 004eeea9: push eax
         // 004eeeaa: push esi
         // 004eeeab: push 0x66ecd8
      [-]ff8b4dfc83c42033cd5f5ee8
         // 004eeeb7: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 004eeeba: add esp, 0x20
         // 004eeebd: xor ecx, ebp
         // 004eeebf: pop edi
         // 004eeec0: pop esi
         // 004eeec1: call @__security_check_cookie@4
      [-]8be55dc3
         // 004eeec6: mov esp, ebp
         // 004eeec8: pop ebp
         // 004eeec9: retn 
      [-]106a0c6a01
         // 00534563: push 0xc
         // 00534565: push 0x1
      [-]000083c40c
         // 00534573: add esp, 0xc
      [-]558bec515356
         // 005347a0: push ebp
         // 005347a1: mov ebp, esp
         // 005347a3: push ecx
         // 005347a4: push ebx
         // 005347a5: push esi
      [-]6a006a00
         // 005347aa: push 0x0
         // 005347ac: push 0x0
      [-]6a006a0056e8
         // 005347d1: push 0x0
         // 005347d3: push 0x0
         // 005347d5: push esi
         // 005347d6: call 0x52dcb0
      [-]750c8d45fc
         // 005347f2: lea eax, ss:[ebp+0xfffffffffffffffc]
      [-]5b8be55dc3
         // 004ef192: pop ebx
         // 004ef193: mov esp, ebp
         // 004ef195: pop ebp
         // 004ef196: retn 
      [-]5f5e5b8be55dc3
         // 004ef1a9: pop edi
         // 004ef1aa: pop esi
         // 004ef1ab: pop ebx
         // 004ef1ac: mov esp, ebp
         // 004ef1ae: pop ebp
         // 004ef1af: retn 
      [-]ffff83c404
         // 0053483b: add esp, 0x4
      [-]5e5b8be55dc3
         // 004ef1bc: pop esi
         // 004ef1bd: pop ebx
         // 004ef1be: mov esp, ebp
         // 004ef1c0: pop ebp
         // 004ef1c1: retn 
      [-]558bec8b450c3d????????74
         // 004ef270: push ebp
         // 004ef271: mov ebp, esp
         // 004ef273: mov eax, ss:[ebp+0xc]
         // 004ef276: cmp eax, 0xe6
         // 004ef27b: jz 0x4ef297
      [-]ff83c40c
         // 004347ad: add esp, 0xc
      [-]ff7508e8
         // 004a88b5: push ss:[ebp+0x8]
         // 004a88b8: call 0x4a8cb0
      [-]000083c4045dc3
         // 004a88bd: add esp, 0x4
         // 004a88c0: pop ebp
         // 004a88c1: retn 
      [-]6a1056e8
         // 004ef31e: push 0x10
         // 004ef320: push esi
         // 004ef321: call 0x4ee700
      [-]558bec568b7508
         // 004ef670: push ebp
         // 004ef671: mov ebp, esp
         // 004ef673: push esi
         // 004ef674: mov esi, ss:[ebp+0x8]
      [-]6a0656e8
         // 004ef69c: push 0x6
         // 004ef69e: push esi
         // 004ef69f: call 0x4ee700
      [-]000083c4
         // 004ef6b2: add esp, 0x4
      [-]ff83c408
         // 00455a6d: add esp, 0x8
      [-]4683fe027516
         // 004efd87: inc esi
         // 004efd88: cmp esi, 0x2
         // 004efd8b: jnz 0x4efda3
      [-]ff83c4088d461c5f
         // 005353f3: add esp, 0x8
         // 005353f6: lea eax, ds:[esi+0x1c]
         // 005353f9: pop edi
      [-]000083c4085f
         // 00535405: add esp, 0x8
         // 00535408: pop edi
      [-]558bec568b75088b
         // 00535620: push ebp
         // 00535621: mov ebp, esp
         // 00535623: push esi
         // 00535624: mov esi, ss:[ebp+0x8]
         // 00535627: mov ecx, ds:[esi]
      [-]6a0d56e8
         // 004efdf5: push 0xd
         // 004efdf7: push esi
         // 004efdf8: call 0x4ee700
      [-]6a0d6a0156e8
         // 004efdfd: push 0xd
         // 004efdff: push 0x1
         // 004efe01: push esi
         // 004efe02: call 0x4eff20
      [-]000083c414
         // 004efe07: add esp, 0x14
      [-]6a0056e8
         // 004efe18: push 0x0
         // 004efe1a: push esi
         // 004efe1b: call 0x4f09c0
      [-]000083c408
         // 004efe20: add esp, 0x8
      [-]558bec8b
         // 004a9990: push ebp
         // 004a9991: mov ebp, esp
         // 004a9999: mov ecx, ss:[ebp+0xc]
      [-]ff83c408
         // 004a99dc: add esp, 0x8
      [-]5f5e5b8be55dc3
         // 004a99e4: pop edi
         // 004a99e5: pop esi
         // 004a99e6: pop ebx
         // 004a99e7: mov esp, ebp
         // 004a99e9: pop ebp
         // 004a99ea: retn 
      [-]894f108957148b86
         // 00535774: mov ds:[edi+0x10], ecx
         // 00535777: mov ds:[edi+0x14], edx
         // 0053577a: mov eax, ds:[esi+0x8650]
      [-]23c283f8ff75
         // 004a9a07: and eax, edx
         // 004a9a09: cmp eax, 0xffffffffffffffff
         // 004a9a0c: jnz 0x4a9a1e
      [-]ff83c408
         // 005357a0: add esp, 0x8
      [-]1bd0898e
         // 00556a63: sbb edx, eax
         // 00556a65: mov ds:[esi+0x8650], ecx
      [-]894f101b
         // 00535837: mov ds:[edi+0x10], ecx
         // 0053583a: sbb edx, eax
      [-]8b47100b471475
         // 004f032f: mov eax, ds:[edi+0x10]
         // 004f0332: or eax, ds:[edi+0x14]
         // 004f0335: jnz 0x4f036e
      [-]6aff6aff
         // 004f033e: push 0xffffffffffffffff
         // 004f0340: push 0xffffffffffffffff
      [-]5f5e5b8be55dc3
         // 004f0367: pop edi
         // 004f0368: pop esi
         // 004f0369: pop ebx
         // 004f036a: mov esp, ebp
         // 004f036c: pop ebp
         // 004f036d: retn 
      [-]5f5e5b8be55dc3
         // 004f03b6: pop edi
         // 004f03b7: pop esi
         // 004f03b8: pop ebx
         // 004f03b9: mov esp, ebp
         // 004f03bb: pop ebp
         // 004f03bc: retn 
      [-]5f5e5b8be55dc3
         // 004f03e8: pop edi
         // 004f03e9: pop esi
         // 004f03ea: pop ebx
         // 004f03eb: mov esp, ebp
         // 004f03ed: pop ebp
         // 004f03ee: retn 
      [-]558bec6a0d6a01ff7508e8
         // 004a9b60: push ebp
         // 004a9b61: mov ebp, esp
         // 004a9b63: push 0xd
         // 004a9b65: push 0x1
         // 004a9b67: push ss:[ebp+0x8]
         // 004a9b6a: call 0x4a9670
      [-]83c40c5dc3
         // 004a9b6f: add esp, 0xc
         // 004a9b72: pop ebp
         // 004a9b73: retn 
      [-]6a1756e8
         // 004f0447: push 0x17
         // 004f0449: push esi
         // 004f044a: call 0x4ee700
      [-]558bec8b4d0c56
         // 004f0670: push ebp
         // 004f0671: mov ebp, esp
         // 004f0673: mov ecx, ss:[ebp+0xc]
         // 004f0676: push esi
      [-]83f86472
         // 004f0685: cmp eax, 0x64
         // 004f0688: jb 0x4f069f
      [-]81f9????????740f
         // 004f069f: cmp ecx, 0xc8
         // 004f06a5: jz 0x4f06b6
      [-]ff83c40c
         // 004f06b3: add esp, 0xc
      [-]8b451083f81375
         // 004f06b6: mov eax, ss:[ebp+0x10]
         // 004f06b9: cmp eax, 0x13
         // 004f06bc: jnz 0x4f06cd
      [-]ffff83c4
         // 00535eb4: add esp, 0x4
      [-]83f81475
         // 004f06cd: cmp eax, 0x14
         // 004f06d0: jnz 0x4f06e1
      [-]ffff83c404
         // 00535ec8: add esp, 0x4
      [-]83f81575
         // 004f06e1: cmp eax, 0x15
         // 004f06e4: jnz 0x4f06f5
      [-]ffff83c404
         // 00535edc: add esp, 0x4
      [-]83f816750b
         // 004f06f5: cmp eax, 0x16
         // 004f06f8: jnz 0x4f0705
      [-]558bec83ec
         // 00456400: push ebp
         // 00456401: mov ebp, esp
         // 00456403: sub esp, 0x10
      [-]450c7404
         // 00456430: mov b1 al, b1 ss:[ebp+0xc]
         // 00456433: jz 0x456439
      [-]5f5e5b8be55dc3
         // 004f0793: pop edi
         // 004f0794: pop esi
         // 004f0795: pop ebx
         // 004f0796: mov esp, ebp
         // 004f0798: pop ebp
         // 004f0799: retn 
      [-]ff83c408
         // 00535fc6: add esp, 0x8
      [-]5f5e5b8be55dc3
         // 00535fce: pop edi
         // 00535fcf: pop esi
         // 00535fd0: pop ebx
         // 00535fd1: mov esp, ebp
         // 00535fd3: pop ebp
         // 00535fd4: retn 
      [-]ff6a006a
         // 004f08c1: push 0xffffffffffffffff
         // 004f08c5: push 0x0
         // 004f08c7: push 0xffffffffffffffff
      [-]6aff6aff
         // 004f08c9: push 0xffffffffffffffff
         // 004f08cb: push 0xffffffffffffffff
      [-]5f5e5b8be55dc3
         // 004f08ea: pop edi
         // 004f08eb: pop esi
         // 004f08ec: pop ebx
         // 004f08ed: mov esp, ebp
         // 004f08ef: pop ebp
         // 004f08f0: retn 
      [-]ff83c408
         // 005360f2: add esp, 0x8
      [-]5f5e5b8be55dc3
         // 005360fa: pop edi
         // 005360fb: pop esi
         // 005360fc: pop ebx
         // 005360fd: mov esp, ebp
         // 005360ff: pop ebp
         // 00536100: retn 
      [-]5f5e5b8be55dc3
         // 004f093d: pop edi
         // 004f093e: pop esi
         // 004f093f: pop ebx
         // 004f0940: mov esp, ebp
         // 004f0942: pop ebp
         // 004f0943: retn 
      [-]0f94c38d049d
         // 005573c3: setz b1 bl
         // 005573c6: lea eax, ds:[0x5ae894+ebx*0x4]
      [-]ff83c410
         // 005361a9: add esp, 0x10
      [-]5f5e5b5dc3
         // 004f09bb: pop edi
         // 004f09bc: pop esi
         // 004f09bd: pop ebx
         // 004f09be: pop ebp
         // 004f09bf: retn 
      [-]558bec81ec
         // 004f09c0: push ebp
         // 004f09c1: mov ebp, esp
         // 004f09c3: sub esp, 0x9b4
      [-]0033c58945fc538b
         // 004f09ce: xor eax, ebp
         // 004f09d0: mov ss:[ebp+0xfffffffffffffffc], eax
         // 004f09d3: push ebx
         // 004f09d5: mov esi, ss:[ebp+0x8]
      [-]8a014184c075f9
         // 004f0a50: mov b1 al, b1 ds:[ecx]
         // 004f0a52: inc ecx
         // 004f0a53: test b1 al, b1 al
         // 004f0a55: jnz 0x4f0a50
      [-]2bca83f9010f86
         // 004aa307: sub ecx, edx
         // 004aa309: cmp ecx, 0x1
         // 004aa30c: jbe 0x4aa57f
      [-]8a014184c075f9
         // 004f0a67: mov b1 al, b1 ds:[ecx]
         // 004f0a69: inc ecx
         // 004f0a6a: test b1 al, b1 al
         // 004f0a6c: jnz 0x4f0a67
      [-]2bca83f9
         // 004f0a6e: sub ecx, edx
         // 004f0a70: cmp ecx, 0x16
      [-]8a014184c075f9
         // 004f0a81: mov b1 al, b1 ds:[ecx]
         // 004f0a83: inc ecx
         // 004f0a84: test b1 al, b1 al
         // 004f0a86: jnz 0x4f0a81
      [-]8d41016a0150ff15
         // 0053628a: lea eax, ds:[ecx+0x1]
         // 0053628d: push 0x1
         // 0053628f: push eax
         // 00536290: call ds:[0x678030]
      [-]83c4088985
         // 00536296: add esp, 0x8
         // 00536299: mov ss:[ebp+0xfffffffffffff66c], eax
      [-]5b8b4dfc33cde8
         // 005362aa: pop ebx
         // 005362ab: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 005362ae: xor ecx, ebp
         // 005362b0: call @__security_check_cookie@4
      [-]8be55dc3
         // 005362b5: mov esp, ebp
         // 005362b7: pop ebp
         // 005362b8: retn 
      [-]ff84c075f3
         // 004aa439: test b1 al, b1 al
         // 004aa43b: jnz 0x4aa430
      [-]ff83c408
         // 004f0d14: add esp, 0x8
      [-]3d????????75
         // 004aa77e: cmp eax, 0x2741
         // 004aa783: jnz 0x4aa7f8
      [-]3d????????7405
         // 004f0eaf: cmp eax, 0x2740
         // 004f0eb4: jz 0x4f0ebb
      [-]83f80d75
         // 004aa7ff: cmp eax, 0xd
         // 004aa802: jnz 0x4aa84a
      [-]6a01ffb5
         // 00536750: push 0x1
         // 00536752: push ss:[ebp+0xfffffffffffff674]
      [-]ff83c40c
         // 005367a6: add esp, 0xc
      [-]6683f90275
         // 004f1008: cmp b2 cx, b2 0x2
         // 004f100c: jnz 0x4f103b
      [-]0fb7c08985
         // 00557a38: movzx eax, b2 ax
         // 00557a3b: mov ss:[ebp+0xfffffffffffff654], eax
      [-]000083c4
         // 00557a91: call 0x558780
         // 00557a96: add esp, 0x8
      [-]5f5e5b8b4dfc33cde8
         // 00557a9b: pop edi
         // 00557a9c: pop esi
         // 00557a9d: pop ebx
         // 00557a9e: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 00557aa1: xor ecx, ebp
         // 00557aa3: call @__security_check_cookie@4
      [-]8be55dc3
         // 00557aa8: mov esp, ebp
         // 00557aaa: pop ebp
         // 00557aab: retn 
      [-]84c97411
         // 004aaa22: test b1 cl, b1 cl
         // 004aaa24: jz 0x4aaa37
      [-]80f92e0fb6c10f44
         // 00456d8b: cmp b1 cl, b1 0x2e
         // 00456d8e: movzx eax, b1 cl
         // 00456d91: cmovz eax, esi
      [-]0fb7c80fb6c150c1e9085168
         // 004f10b2: movzx ecx, b2 ax
         // 004f10b5: movzx eax, b1 cl
         // 004f10b8: push eax
         // 004f10b9: shr ecx, b1 0x8
         // 004f10bc: push ecx
         // 004f10bd: push 0x66ef84
      [-]6a1452c60200e8
         // 004f10c2: push 0x14
         // 004f10c4: push edx
         // 004f10c5: mov b1 ds:[edx], b1 0x0
         // 004f10c8: call _snprintf
      [-]5f5e5b8b4dfc33cde8
         // 004eb5b8: pop edi
         // 004eb5b9: pop esi
         // 004eb5ba: pop ebx
         // 004eb5bb: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 004eb5be: xor ecx, ebp
         // 004eb5c0: call @__security_check_cookie@4
      [-]8be55dc3
         // 004eb5c5: mov esp, ebp
         // 004eb5c7: pop ebp
         // 004eb5c8: retn 
      [-]0fb7c0508d
         // 004f113e: movzx eax, b2 ax
         // 004f1141: push eax
         // 004f1142: lea eax, ss:[ebp+0xfffffffffffffefc]
      [-]ffff020f95c0405068
         // 004f1153: setnz b1 al
         // 004f1156: inc eax
         // 004f1157: push eax
         // 004f1158: push 0x66ecf8
      [-]5f5e5b8b4dfc33cde8
         // 00536990: pop edi
         // 00536991: pop esi
         // 00536992: pop ebx
         // 00536993: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 00536996: xor ecx, ebp
         // 00536998: call @__security_check_cookie@4
      [-]8be55dc3
         // 0053699d: mov esp, ebp
         // 0053699f: pop ebp
         // 005369a0: retn 
      [-]5f5e33cd5be8
         // 005369d6: pop edi
         // 005369d7: pop esi
         // 005369d8: xor ecx, ebp
         // 005369da: pop ebx
         // 005369db: call @__security_check_cookie@4
      [-]8be55dc3
         // 005369e0: mov esp, ebp
         // 005369e2: pop ebp
         // 005369e3: retn 
      [-]558bec8b
         // 00557ca0: push ebp
         // 00557ca1: mov ebp, esp
         // 00557ca3: mov edx, ss:[ebp+0xc]
      [-]0c568b7508
         // 00557ca6: push esi
         // 00557ca7: mov esi, ss:[ebp+0x8]
      [-]0f45c85168
         // 00536a81: cmovnz ecx, eax
         // 00536a84: push ecx
         // 00536a85: push 0x6580ec
      [-]6a0456e8
         // 00557ced: push 0x4
         // 00557cef: push esi
         // 00557cf0: call 0x558780
      [-]83f86473
         // 004f12c4: cmp eax, 0x64
         // 004f12c7: jnb 0x4f12d8
      [-]ffff83c404
         // 00557d0f: add esp, 0x4
      [-]6a0556e8
         // 00557d43: push 0x5
         // 00557d45: push esi
         // 00557d46: call 0x558780
      [-]ff83c408
         // 00557d5f: add esp, 0x8
      [-]000083c4
         // 00536b3c: add esp, 0xc
      [-]000083c408
         // 004f1358: mov b1 ds:[eax+0x8658], b1 0x1
         // 004f1364: add esp, 0x8
      [-]558bec568b7508
         // 0043b280: push ebp
         // 0043b281: mov ebp, esp
         // 0043b283: push esi
         // 0043b284: mov esi, ss:[ebp+0x8]
      [-]ff83c414
         // 0043b2a7: add esp, 0x14
      [-]188b4d083bc874
         // 004fa141: mov ecx, ss:[ebp+0x8]
         // 004fa144: cmp ecx, eax
         // 004fa146: jz 0x4fa152
      [-]558bec83ec
         // 0055caf0: push ebp
         // 0055caf1: mov ebp, esp
         // 0055caf3: sub esp, 0x8
      [-]8be55dc3
         // 004fa6ac: mov esp, ebp
         // 004fa6ae: pop ebp
         // 004fa6af: retn 
      [-]5f5e8be55dc3
         // 0053b90c: pop edi
         // 0053b90d: pop esi
         // 0053b90e: mov esp, ebp
         // 0053b910: pop ebp
         // 0053b911: retn 
      [-]558bec568b750c578b7d085657c60700ff15
         // 004fb220: push ebp
         // 004fb221: mov ebp, esp
         // 004fb223: push esi
         // 004fb224: mov esi, ss:[ebp+0xc]
         // 004fb227: push edi
         // 004fb228: mov edi, ss:[ebp+0x8]
         // 004fb22b: push esi
         // 004fb22c: push edi
         // 004fb22d: mov b1 ds:[edi], b1 0x0
         // 004fb230: call ds:[gethostname]
      [-]c64437ff00
         // 004fb236: mov b1 ds:[edi+esi+0xffffffffffffffff], b1 0x0
      [-]6a2e57e8
         // 0053d02f: push 0x2e
         // 0053d031: push edi
         // 0053d032: call 0x4f2a40
      [-]5f5e5dc3
         // 004fb253: pop edi
         // 004fb254: pop esi
         // 004fb255: pop ebp
         // 004fb256: retn 
      [-]6a346a01ff15
         // 00461b70: push 0x34
         // 00461b72: push 0x1
         // 00461b74: call ds:[0x6220b4]
      [-]83c408c3
         // 00461b7a: add esp, 0x8
         // 00461b7d: retn 

  }
  condition:
    all of them
}
