rule softcnapp_20_3 {
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
         // 004c08d0: push ebp
         // 004c08d1: mov ebp, esp
         // 004c08d3: mov ecx, ss:[ebp+0x8]
         // 004c08d6: push esi
         // 004c08d7: push ecx
         // 004c08d8: call 0x4c07e0
      [-]83c410c746
         // 004c08eb: add esp, 0x10
         // 004c08ee: mov ds:[esi+0x14], 0x0
      [-]005e5dc3
         // 004c08f5: pop esi
         // 004c08f6: pop ebp
         // 004c08f7: retn 
      [-]558bec83ec08568b750883be
         // 004cfec0: push ebp
         // 004cfec1: mov ebp, esp
         // 004cfec3: sub esp, 0x8
         // 004cfec6: push esi
         // 004cfec7: mov esi, ss:[ebp+0x8]
         // 004cfeca: cmp ds:[esi+0x290], 0xffffffffffffffff
      [-]6a026a0356e8
         // 00432a2f: push 0x2
         // 00432a31: push 0x3
         // 00432a33: push esi
         // 00432a34: call 0x447f90
      [-]8d45f850e8
         // 004cfeec: lea eax, ss:[ebp+0xfffffffffffffff8]
         // 004cfeef: push eax
         // 004cfef0: call __time64
      [-]75fcff75f8ffb6
         // 004cfef5: push ss:[ebp+0xfffffffffffffffc]
         // 004cfef8: push ss:[ebp+0xfffffffffffffff8]
         // 004cfefb: push ds:[esi+0x290]
      [-]000083c41483
         // 004cff09: add esp, 0x14
         // 004cff0c: cmp ds:[esi+0x48], 0x0
      [-]6a0356e8
         // 00432a62: push 0x3
         // 00432a64: push esi
         // 00432a65: call 0x447fd0
      [-]5e8be55dc3
         // 004cff1d: pop esi
         // 004cff1e: mov esp, ebp
         // 004cff20: pop ebp
         // 004cff21: retn 
      [-]558bec8b4d
         // 004c0e80: push ebp
         // 004c0e81: mov ebp, esp
         // 004c0e83: mov ecx, ss:[ebp+0x8]
      [-]83e80274
         // 004c0e89: sub eax, 0x2
         // 004c0e8c: jz 0x4c0eb0
      [-]ff75108b
         // 00432da2: push ss:[ebp+0x10]
         // 00432da5: mov eax, ds:[ecx+0x18]
      [-]83c4105dc3
         // 00432db6: add esp, 0x10
         // 00432db9: pop ebp
         // 00432dba: retn 
      [-]558bec83ec14a1
         // 00419150: push ebp
         // 00419151: mov ebp, esp
         // 00419153: sub esp, 0x14
         // 00419156: mov eax, ds:[___security_cookie]
      [-]0033c58945fc8b450c8b4d088945ec8b45108945f48b45148945f88d45ec68
         // 0041915b: xor eax, ebp
         // 0041915d: mov ss:[ebp+0xfffffffffffffffc], eax
         // 00419160: mov eax, ss:[ebp+0xc]
         // 00419163: mov ecx, ss:[ebp+0x8]
         // 00419166: mov ss:[ebp+0xffffffffffffffec], eax
         // 00419169: mov eax, ss:[ebp+0x10]
         // 0041916c: mov ss:[ebp+0xfffffffffffffff4], eax
         // 0041916f: mov eax, ss:[ebp+0x14]
         // 00419172: mov ss:[ebp+0xfffffffffffffff8], eax
         // 00419175: lea eax, ss:[ebp+0xffffffffffffffec]
         // 00419178: push 0x4191a0
      [-]8b4dfc83c40c33cde8
         // 00419184: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 00419187: add esp, 0xc
         // 0041918a: xor ecx, ebp
         // 0041918c: call @__security_check_cookie@4
      [-]8be55dc3
         // 00419191: mov esp, ebp
         // 00419193: pop ebp
         // 00419194: retn 
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
         // 004e5c10: push ebp
         // 004e5c11: mov ebp, esp
         // 004e5c13: push 0x0
         // 004e5c15: push 0x0
         // 004e5c17: push ss:[ebp+0xc]
         // 004e5c1a: push ss:[ebp+0x8]
         // 004e5c1d: push 0x0
         // 004e5c1f: push 0x0
         // 004e5c21: call __beginthreadex
      [-]83f8ff7502
         // 004e5c2d: cmp eax, 0xffffffffffffffff
         // 004e5c30: jnz 0x4e5c34
      [-]558bec8b
         // 00549670: push ebp
         // 00549671: mov ebp, esp
         // 00549673: mov ecx, ss:[ebp+0xc]
      [-]ff83c40c
         // 004a535e: add esp, 0xc
      [-]0f45c88d
         // 004e8ce6: cmovnz ecx, eax
         // 004e8ce9: lea eax, ds:[esi+0x3f8]
      [-]010083c4
         // 004e8cfd: add esp, 0xc
      [-]558bec568b7508
         // 00533e00: push ebp
         // 00533e01: mov ebp, esp
         // 00533e03: push esi
         // 00533e04: mov esi, ss:[ebp+0x8]
      [-]83c404c746
         // 00533e42: add esp, 0x4
         // 00533e45: mov ds:[esi+0x3c], 0x0
      [-]0fb60650e8
         // 004a80dd: movzx eax, b1 ds:[esi]
         // 004a80e0: push eax
         // 004a80e1: call 0x48d310
      [-]0fb6460150e8
         // 00523f40: movzx eax, b1 ds:[esi+0x1]
         // 00523f44: push eax
         // 00523f45: call _isdigit
      [-]0fb6460250e8
         // 004a80fe: movzx eax, b1 ds:[esi+0x2]
         // 004a8102: push eax
         // 004a8103: call 0x48d310
      [-]807e032075
         // 004ee92f: cmp b1 ds:[esi+0x3], b1 0x20
         // 004ee933: jnz 0x4ee952
      [-]6a0a6a0056e8
         // 0055e518: push 0xa
         // 0055e51a: push 0x0
         // 0055e51c: push esi
         // 0055e51d: call _strtol
      [-]83c4108901
         // 0055e52b: add esp, 0x10
         // 0055e52e: mov ds:[ecx], eax
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
         // 00433270: push ebp
         // 00433271: mov ebp, esp
         // 00433273: sub esp, 0x104
         // 00433279: mov eax, ds:[___security_cookie]
      [-]0033c58945fc8b450c8d8d????????568b7510578b7d0868????????5150e8
         // 0043327e: xor eax, ebp
         // 00433280: mov ss:[ebp+0xfffffffffffffffc], eax
         // 00433283: mov eax, ss:[ebp+0xc]
         // 00433286: lea ecx, ss:[ebp+0xfffffffffffffefc]
         // 0043328c: push esi
         // 0043328d: mov esi, ss:[ebp+0x10]
         // 00433290: push edi
         // 00433291: mov edi, ss:[ebp+0x8]
         // 00433294: push 0x100
         // 00433299: push ecx
         // 0043329a: push eax
         // 0043329b: call 0x4183f0
      [-]ffff75148d85????????505668
         // 004332a0: push ss:[ebp+0x14]
         // 004332a3: lea eax, ss:[ebp+0xfffffffffffffefc]
         // 004332a9: push eax
         // 004332aa: push esi
         // 004332ab: push 0x45f310
      [-]ff8b4dfc83c42033cd5f5ee8
         // 004332b7: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 004332ba: add esp, 0x20
         // 004332bd: xor ecx, ebp
         // 004332bf: pop edi
         // 004332c0: pop esi
         // 004332c1: call @__security_check_cookie@4
      [-]8be55dc3
         // 004332c6: mov esp, ebp
         // 004332c8: pop ebp
         // 004332c9: retn 
      [-]106a0c6a01
         // 00534563: push 0xc
         // 00534565: push 0x1
      [-]000083c40c
         // 00534573: add esp, 0xc
      [-]558bec515356
         // 00454e10: push ebp
         // 00454e11: mov ebp, esp
         // 00454e13: push ecx
         // 00454e14: push ebx
         // 00454e15: push esi
      [-]6a006a00
         // 00454e1a: push 0x0
         // 00454e1c: push 0x0
      [-]6a006a0056e8
         // 00454e3e: push 0x0
         // 00454e40: push 0x0
         // 00454e42: push esi
         // 00454e43: call 0x446110
      [-]750c8d45fc
         // 00454e5f: lea eax, ss:[ebp+0xfffffffffffffffc]
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
         // 0053490d: add esp, 0xc
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
         // 00534be0: push ebp
         // 00534be1: mov ebp, esp
         // 00534be3: push esi
         // 00534be4: mov esi, ss:[ebp+0x8]
      [-]6a0656e8
         // 004ef69c: push 0x6
         // 004ef69e: push esi
         // 004ef69f: call 0x4ee700
      [-]000083c4
         // 004ef6b2: add esp, 0x4
      [-]ff83c408
         // 00455a6d: add esp, 0x8
      [-]ff83c4088d
         // 005353f3: add esp, 0x8
         // 005353f6: lea eax, ds:[esi+0x1c]
      [-]000083c4085f5e
         // 004efdaa: add esp, 0x8
         // 004efdad: pop edi
         // 004efdae: pop esi
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
         // 00535720: push ebp
         // 00535721: mov ebp, esp
         // 00535729: mov ecx, ss:[ebp+0xc]
      [-]ff83c408
         // 004a99dc: add esp, 0x8
      [-]5f5e5b8be55dc3
         // 004a99e4: pop edi
         // 004a99e5: pop esi
         // 004a99e6: pop ebx
         // 004a99e7: mov esp, ebp
         // 004a99e9: pop ebp
         // 004a99ea: retn 
      [-]23c283f8ff75
         // 004a9a07: and eax, edx
         // 004a9a09: cmp eax, 0xffffffffffffffff
         // 004a9a0c: jnz 0x4a9a1e
      [-]ff83c408
         // 005357a0: add esp, 0x8
      [-]1bd0898e
         // 00556a63: sbb edx, eax
         // 00556a65: mov ds:[esi+0x8650], ecx
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
         // 004e06ec: add esp, 0x4
      [-]83f816750b
         // 004f06f5: cmp eax, 0x16
         // 004f06f8: jnz 0x4f0705
      [-]558bec83ec
         // 00557150: push ebp
         // 00557151: mov ebp, esp
         // 00557153: sub esp, 0x10
      [-]450c7404
         // 0055717d: mov eax, ss:[ebp+0xc]
         // 00557180: jz 0x557186
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
         // 00557307: push 0xffffffffffffffff
         // 00557309: push 0x0
         // 0055730b: push 0x0
      [-]6aff6aff
         // 0055730d: push 0xffffffffffffffff
         // 0055730f: push 0xffffffffffffffff
      [-]5f5e5b8be55dc3
         // 00557330: pop edi
         // 00557331: pop esi
         // 00557332: pop ebx
         // 00557333: mov esp, ebp
         // 00557335: pop ebp
         // 00557336: retn 
      [-]5f5e5b8be55dc3
         // 004f093d: pop edi
         // 004f093e: pop esi
         // 004f093f: pop ebx
         // 004f0940: mov esp, ebp
         // 004f0942: pop ebp
         // 004f0943: retn 
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
         // 0045677a: lea eax, ds:[ecx+0x1]
         // 0045677d: push 0x1
         // 0045677f: push eax
         // 00456780: call ds:[0x6220b4]
      [-]83c4088985
         // 00456786: add esp, 0x8
         // 00456789: mov ss:[ebp+0xfffffffffffff660], eax
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
      [-]6683f90275
         // 004e1115: cmp b2 cx, b2 0x2
         // 004e1119: jnz 0x4e114d
      [-]0fb7c08985
         // 00557a38: movzx eax, b2 ax
         // 00557a3b: mov ss:[ebp+0xfffffffffffff654], eax
      [-]000083c4
         // 00456d52: mov b1 ds:[esi+0x225], b1 0x1
         // 00456d5e: add esp, 0xc
      [-]5f5e5b8b4dfc33cde8
         // 00456d63: pop edi
         // 00456d64: pop esi
         // 00456d65: pop ebx
         // 00456d66: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 00456d69: xor ecx, ebp
         // 00456d6b: call @__security_check_cookie@4
      [-]8be55dc3
         // 00456d70: mov esp, ebp
         // 00456d72: pop ebp
         // 00456d73: retn 
      [-]84c97411
         // 004aaa22: test b1 cl, b1 cl
         // 004aaa24: jz 0x4aaa37
      [-]80f92e0fb6c10f44
         // 00456d8b: cmp b1 cl, b1 0x2e
         // 00456d8e: movzx eax, b1 cl
         // 00456d91: cmovz eax, esi
      [-]0fb7c80fb6c150c1e9085168
         // 00557add: movzx ecx, b2 ax
         // 00557ae0: movzx eax, b1 cl
         // 00557ae3: push eax
         // 00557ae4: shr ecx, b1 0x8
         // 00557ae7: push ecx
         // 00557ae8: push 0x5aed58
      [-]6a1452c60200e8
         // 00557aed: push 0x14
         // 00557aef: push edx
         // 00557af0: mov b1 ds:[edx], b1 0x0
         // 00557af3: call _snprintf
      [-]5f5e5b8b4dfc33cde8
         // 004367a8: pop edi
         // 004367a9: pop esi
         // 004367aa: pop ebx
         // 004367ab: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 004367ae: xor ecx, ebp
         // 004367b0: call @__security_check_cookie@4
      [-]8be55dc3
         // 004367b5: mov esp, ebp
         // 004367b7: pop ebp
         // 004367b8: retn 
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
      [-]558bec568b7508
         // 0045fe50: push ebp
         // 0045fe51: mov ebp, esp
         // 0045fe53: push esi
         // 0045fe54: mov esi, ss:[ebp+0x8]
         // 0045fe57: lea eax, ss:[ebp+0x8]
      [-]ff83c414
         // 0045fe77: add esp, 0x14
      [-]188b4d083bc874
         // 004ee574: mov ecx, ss:[ebp+0x8]
         // 004ee577: cmp ecx, eax
         // 004ee579: jz 0x4ee587
      [-]558bec83ec08
         // 0043d130: push ebp
         // 0043d131: mov ebp, esp
         // 0043d133: sub esp, 0x8
      [-]8be55dc3
         // 0043d15c: mov esp, ebp
         // 0043d15e: pop ebp
         // 0043d15f: retn 
      [-]8be55dc3
         // 004eec4e: mov esp, ebp
         // 004eec50: pop ebp
         // 004eec51: retn 
      [-]558bec568b750c578b7d085657c60700ff15
         // 0053d010: push ebp
         // 0053d011: mov ebp, esp
         // 0053d013: push esi
         // 0053d014: mov esi, ss:[ebp+0xc]
         // 0053d017: push edi
         // 0053d018: mov edi, ss:[ebp+0x8]
         // 0053d01b: push esi
         // 0053d01c: push edi
         // 0053d01d: mov b1 ds:[edi], b1 0x0
         // 0053d020: call ds:[gethostname]
      [-]c64437ff00
         // 0053d026: mov b1 ds:[edi+esi+0xffffffffffffffff], b1 0x0
      [-]6a2e57e8
         // 0053d02f: push 0x2e
         // 0053d031: push edi
         // 0053d032: call 0x4f2a40
      [-]5f5e5dc3
         // 004fb253: pop edi
         // 004fb254: pop esi
         // 004fb255: pop ebp
         // 004fb256: retn 

  }
  condition:
    all of them
}
