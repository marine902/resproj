rule bingoml_10_0 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         8b0b83c30433c085c9740d
         // 00401004: mov ecx, ds:[ebx]
         // 00401006: add ebx, 0x4
         // 00401009: xor eax, eax
         // 0040100b: test ecx, ecx
         // 0040100d: jz 0x40101c
      [-]83c304497405
         // 00401011: add ebx, 0x4
         // 00401014: dec ecx
         // 00401015: jz 0x40101c
      [-]0faf03ebf5
         // 00401017: imul eax, ds:[ebx]
         // 0040101a: jmp 0x401011
      [-]85db7503
         // 0040101d: test ebx, ebx
         // 0040101f: jnz 0x401024
      [-]8b0b83c30485c9740f
         // 00401024: mov ecx, ds:[ebx]
         // 00401026: add ebx, 0x4
         // 00401029: test ecx, ecx
         // 0040102b: jz 0x40103c
      [-]83c304497405
         // 0040102f: add ebx, 0x4
         // 00401032: dec ecx
         // 00401033: jz 0x40103a
      [-]0faf03ebf5
         // 00401035: imul eax, ds:[ebx]
         // 00401038: jmp 0x40102f
      [-]8b5424048b4c240885d2750d
         // 0040103d: mov edx, ss:[esp+0x4]
         // 00401041: mov ecx, ss:[esp+0x8]
         // 00401045: test edx, edx
         // 00401047: jnz 0x401056
      [-]33c085c97406
         // 00401049: xor eax, eax
         // 0040104b: test ecx, ecx
         // 0040104d: jz 0x401055
      [-]8039007401
         // 0040104f: cmp b1 ds:[ecx], b1 0x0
         // 00401052: jz 0x401055
      [-]85c97509
         // 00401056: test ecx, ecx
         // 00401058: jnz 0x401063
      [-]33c0803a007401
         // 0040105a: xor eax, eax
         // 0040105c: cmp b1 ds:[edx], b1 0x0
         // 0040105f: jz 0x401062
      [-]f7c2????????7537
         // 00401063: test edx, 0x3
         // 00401069: jnz 0x4010a2
      [-]8b023a01752b
         // 0040106b: mov eax, ds:[edx]
         // 0040106d: cmp b1 al, b1 ds:[ecx]
         // 0040106f: jnz 0x40109c
      [-]0ac07424
         // 00401071: or b1 al, b1 al
         // 00401073: jz 0x401099
      [-]3a61017522
         // 00401075: cmp b1 ah, b1 ds:[ecx+0x1]
         // 00401078: jnz 0x40109c
      [-]0ae4741b
         // 0040107a: or b1 ah, b1 ah
         // 0040107c: jz 0x401099
      [-]c1e8103a41027516
         // 0040107e: shr eax, b1 0x10
         // 00401081: cmp b1 al, b1 ds:[ecx+0x2]
         // 00401084: jnz 0x40109c
      [-]0ac0740f
         // 00401086: or b1 al, b1 al
         // 00401088: jz 0x401099
      [-]3a6103750d
         // 0040108a: cmp b1 ah, b1 ds:[ecx+0x3]
         // 0040108d: jnz 0x40109c
      [-]83c10483c2040ae475d2
         // 0040108f: add ecx, 0x4
         // 00401092: add edx, 0x4
         // 00401095: or b1 ah, b1 ah
         // 00401097: jnz 0x40106b
      [-]1bc0d1e040c3
         // 0040109c: sbb eax, eax
         // 0040109e: shl eax, b1 0x1
         // 004010a0: inc eax
         // 004010a1: retn 
      [-]f7c2????????7414
         // 004010a2: test edx, 0x1
         // 004010a8: jz 0x4010be
      [-]8a02423a0175eb
         // 004010aa: mov b1 al, b1 ds:[edx]
         // 004010ac: inc edx
         // 004010ad: cmp b1 al, b1 ds:[ecx]
         // 004010af: jnz 0x40109c
      [-]410ac074e3
         // 004010b1: inc ecx
         // 004010b2: or b1 al, b1 al
         // 004010b4: jz 0x401099
      [-]f7c2????????74ad
         // 004010b6: test edx, 0x2
         // 004010bc: jz 0x40106b
      [-]668b0283c2023a0175d4
         // 004010be: mov b2 ax, b2 ds:[edx]
         // 004010c1: add edx, 0x2
         // 004010c4: cmp b1 al, b1 ds:[ecx]
         // 004010c6: jnz 0x40109c
      [-]0ac074cd
         // 004010c8: or b1 al, b1 al
         // 004010ca: jz 0x401099
      [-]3a610175cb
         // 004010cc: cmp b1 ah, b1 ds:[ecx+0x1]
         // 004010cf: jnz 0x40109c
      [-]0ae474c4
         // 004010d1: or b1 ah, b1 ah
         // 004010d3: jz 0x401099
      [-]83c102eb91
         // 004010d5: add ecx, 0x2
         // 004010d8: jmp 0x40106b
      [-]85db7503
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
      [-]8b1e83c60451e871ffffff590145fc890783c7044975e9
         // 0040115e: mov ebx, ds:[esi]
         // 00401160: add esi, 0x4
         // 00401163: push ecx
         // 00401164: call 0x4010da
         // 00401169: pop ecx
         // 0040116a: add ss:[ebp+0xfffffffffffffffc], eax
         // 0040116d: mov ds:[edi], eax
         // 0040116f: add edi, 0x4
         // 00401172: dec ecx
         // 00401173: jnz 0x40115e
      [-]ff75fce8835a0c0083c4048bf8588d1c24578d5508
         // 00401175: push ss:[ebp+0xfffffffffffffffc]
         // 00401178: call 0x4c6c00
         // 0040117d: add esp, 0x4
         // 00401180: mov edi, eax
         // 00401182: pop eax
         // 00401183: lea ebx, ss:[esp]
         // 00401186: push edi
         // 00401187: lea edx, ss:[ebp+0x8]
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
      [-]558bec81ec????????68????????e84c5a0c0083c4048945fc8bf8be????????adabadabc745f8????????c745f4????????c745f0????????c745ec????????68????????6a008d45fc5068????????bb????????e8175a0c0083c4108b5dfce8fefdffff8945e4837de4000f8507000000
         // 004011a1: push ebp
         // 004011a2: mov ebp, esp
         // 004011a4: sub esp, 0x2c
         // 004011aa: push 0x8
         // 004011af: call 0x4c6c00
         // 004011b4: add esp, 0x4
         // 004011b7: mov ss:[ebp+0xfffffffffffffffc], eax
         // 004011ba: mov edi, eax
         // 004011bc: mov esi, 0x560da9
         // 004011c1: lodsdd 
         // 004011c2: stosdd 
         // 004011c3: lodsdd 
         // 004011c4: stosdd 
         // 004011c5: mov ss:[ebp+0xfffffffffffffff8], 0x0
         // 004011cc: mov ss:[ebp+0xfffffffffffffff4], 0x0
         // 004011d3: mov ss:[ebp+0xfffffffffffffff0], 0x0
         // 004011da: mov ss:[ebp+0xffffffffffffffec], 0x0
         // 004011e1: push 0xffffffff80000004
         // 004011e6: push 0x0
         // 004011e8: lea eax, ss:[ebp+0xfffffffffffffffc]
         // 004011eb: push eax
         // 004011ec: push 0x1
         // 004011f1: mov ebx, 0x4c75b0
         // 004011f6: call 0x4c6c12
         // 004011fb: add esp, 0x10
         // 004011fe: mov ebx, ss:[ebp+0xfffffffffffffffc]
         // 00401201: call 0x401004
         // 00401206: mov ss:[ebp+0xffffffffffffffe4], eax
         // 00401209: cmp ss:[ebp+0xffffffffffffffe4], 0x0
         // 0040120d: jnz 0x40121a
      [-]b8????????eb05
         // 00401213: mov eax, 0x1
         // 00401218: jmp 0x40121f
      [-]b8????????
         // 0040121a: mov eax, 0x0
      [-]85c00f840f000000
         // 0040121f: test eax, eax
         // 00401221: jz 0x401236
      [-]e8320500006a00e8fd590c0083c404
         // 00401227: call 0x40175e
         // 0040122c: push 0x0
         // 0040122e: call 0x4c6c30
         // 00401233: add esp, 0x4
      [-]8b5dfce8c6fdffff8945e4837de4020f8552000000
         // 00401236: mov ebx, ss:[ebp+0xfffffffffffffffc]
         // 00401239: call 0x401004
         // 0040123e: mov ss:[ebp+0xffffffffffffffe4], eax
         // 00401241: cmp ss:[ebp+0xffffffffffffffe4], 0x2
         // 00401245: jnz 0x40129d
      [-]8b5dfce8cafdffffb8????????3bc17c17
         // 0040124b: mov ebx, ss:[ebp+0xfffffffffffffffc]
         // 0040124e: call 0x40101d
         // 00401253: mov eax, 0x0
         // 00401258: cmp eax, ecx
         // 0040125a: jl 0x401273
      [-]68????????68????????68????????e896590c0083c40c
         // 0040125c: push 0x121
         // 00401261: push 0x4010001
         // 00401266: push 0x1
         // 0040126b: call 0x4c6c06
         // 00401270: add esp, 0xc
      [-]c1e00203d8895ddc68????????8b5ddcff33e8b3fdffff83c40883f8000f8507000000
         // 00401273: shl eax, b1 0x2
         // 00401276: add ebx, eax
         // 00401278: mov ss:[ebp+0xffffffffffffffdc], ebx
         // 0040127b: push 0x560d6c
         // 00401280: mov ebx, ss:[ebp+0xffffffffffffffdc]
         // 00401283: push ds:[ebx]
         // 00401285: call 0x40103d
         // 0040128a: add esp, 0x8
         // 0040128d: cmp eax, 0x0
         // 00401290: jnz 0x40129d
      [-]b8????????eb05
         // 00401296: mov eax, 0x1
         // 0040129b: jmp 0x4012a2
      [-]b8????????
         // 0040129d: mov eax, 0x0
      [-]85c00f84ec020000
         // 004012a2: test eax, eax
         // 004012a4: jz 0x401596
      [-]68????????bb????????e859590c0083c4048945e868????????bb????????e844590c0083c4048945e4ff75e468????????ff75e8b9????????e85cfeffff83c40c8945e08b5de885db7409
         // 004012aa: push 0x0
         // 004012af: mov ebx, 0x4c72d0
         // 004012b4: call 0x4c6c12
         // 004012b9: add esp, 0x4
         // 004012bc: mov ss:[ebp+0xffffffffffffffe8], eax
         // 004012bf: push 0x0
         // 004012c4: mov ebx, 0x4c72f0
         // 004012c9: call 0x4c6c12
         // 004012ce: add esp, 0x4
         // 004012d1: mov ss:[ebp+0xffffffffffffffe4], eax
         // 004012d4: push ss:[ebp+0xffffffffffffffe4]
         // 004012d7: push 0x560d73
         // 004012dc: push ss:[ebp+0xffffffffffffffe8]
         // 004012df: mov ecx, 0x3
         // 004012e4: call 0x401145
         // 004012e9: add esp, 0xc
         // 004012ec: mov ss:[ebp+0xffffffffffffffe0], eax
         // 004012ef: mov ebx, ss:[ebp+0xffffffffffffffe8]
         // 004012f2: test ebx, ebx
         // 004012f4: jz 0x4012ff
      [-]53e8fe580c0083c404
         // 004012f6: push ebx
         // 004012f7: call 0x4c6bfa
         // 004012fc: add esp, 0x4
      [-]8b5de485db7409
         // 004012ff: mov ebx, ss:[ebp+0xffffffffffffffe4]
         // 00401302: test ebx, ebx
         // 00401304: jz 0x40130f
      [-]53e8ee580c0083c404
         // 00401306: push ebx
         // 00401307: call 0x4c6bfa
         // 0040130c: add esp, 0x4
      [-]68????????6a008b45e085c07505
         // 0040130f: push 0xffffffff80000004
         // 00401314: push 0x0
         // 00401316: mov eax, ss:[ebp+0xffffffffffffffe0]
         // 00401319: test eax, eax
         // 0040131b: jnz 0x401322
      [-]b8????????
         // 0040131d: mov eax, 0x560d75
      [-]5068????????bb????????e8e0580c0083c4108945dc8b5de085db7409
         // 00401322: push eax
         // 00401323: push 0x1
         // 00401328: mov ebx, 0x4c9a80
         // 0040132d: call 0x4c6c12
         // 00401332: add esp, 0x10
         // 00401335: mov ss:[ebp+0xffffffffffffffdc], eax
         // 00401338: mov ebx, ss:[ebp+0xffffffffffffffe0]
         // 0040133b: test ebx, ebx
         // 0040133d: jz 0x401348
      [-]53e8b5580c0083c404
         // 0040133f: push ebx
         // 00401340: call 0x4c6bfa
         // 00401345: add esp, 0x4
      [-]8b45dc508b5df885db7409
         // 00401348: mov eax, ss:[ebp+0xffffffffffffffdc]
         // 0040134b: push eax
         // 0040134c: mov ebx, ss:[ebp+0xfffffffffffffff8]
         // 0040134f: test ebx, ebx
         // 00401351: jz 0x40135c
      [-]53e8a1580c0083c404
         // 00401353: push ebx
         // 00401354: call 0x4c6bfa
         // 00401359: add esp, 0x4
      [-]588945f8b8????????508b5df485db7409
         // 0040135c: pop eax
         // 0040135d: mov ss:[ebp+0xfffffffffffffff8], eax
         // 00401360: mov eax, 0x560d76
         // 00401365: push eax
         // 00401366: mov ebx, ss:[ebp+0xfffffffffffffff4]
         // 00401369: test ebx, ebx
         // 0040136b: jz 0x401376
      [-]53e887580c0083c404
         // 0040136d: push ebx
         // 0040136e: call 0x4c6bfa
         // 00401373: add esp, 0x4
      [-]588945f4c745e8????????6a00ff75e8c745e4????????6a00ff75e48d45f850e8821e00008945e0c745dc????????6a00ff75dc68????????e8f81600008945d868????????ff75d8ff75e068????????b9????????e874fdffff83c4108945d48b5de085db7409
         // 00401376: pop eax
         // 00401377: mov ss:[ebp+0xfffffffffffffff4], eax
         // 0040137a: mov ss:[ebp+0xffffffffffffffe8], 0x0
         // 00401381: push 0x0
         // 00401383: push ss:[ebp+0xffffffffffffffe8]
         // 00401386: mov ss:[ebp+0xffffffffffffffe4], 0x0
         // 0040138d: push 0x0
         // 0040138f: push ss:[ebp+0xffffffffffffffe4]
         // 00401392: lea eax, ss:[ebp+0xfffffffffffffff8]
         // 00401395: push eax
         // 00401396: call 0x40321d
         // 0040139b: mov ss:[ebp+0xffffffffffffffe0], eax
         // 0040139e: mov ss:[ebp+0xffffffffffffffdc], 0x0
         // 004013a5: push 0x0
         // 004013a7: push ss:[ebp+0xffffffffffffffdc]
         // 004013aa: push 0xc
         // 004013af: call 0x402aac
         // 004013b4: mov ss:[ebp+0xffffffffffffffd8], eax
         // 004013b7: push 0x560da5
         // 004013bc: push ss:[ebp+0xffffffffffffffd8]
         // 004013bf: push ss:[ebp+0xffffffffffffffe0]
         // 004013c2: push 0x560da7
         // 004013c7: mov ecx, 0x4
         // 004013cc: call 0x401145
         // 004013d1: add esp, 0x10
         // 004013d4: mov ss:[ebp+0xffffffffffffffd4], eax
         // 004013d7: mov ebx, ss:[ebp+0xffffffffffffffe0]
         // 004013da: test ebx, ebx
         // 004013dc: jz 0x4013e7
      [-]53e816580c0083c404
         // 004013de: push ebx
         // 004013df: call 0x4c6bfa
         // 004013e4: add esp, 0x4
      [-]8b5dd885db7409
         // 004013e7: mov ebx, ss:[ebp+0xffffffffffffffd8]
         // 004013ea: test ebx, ebx
         // 004013ec: jz 0x4013f7
      [-]53e806580c0083c404
         // 004013ee: push ebx
         // 004013ef: call 0x4c6bfa
         // 004013f4: add esp, 0x4
      [-]8b45d4508b5df085db7409
         // 004013f7: mov eax, ss:[ebp+0xffffffffffffffd4]
         // 004013fa: push eax
         // 004013fb: mov ebx, ss:[ebp+0xfffffffffffffff0]
         // 004013fe: test ebx, ebx
         // 00401400: jz 0x40140b
      [-]53e8f2570c0083c404
         // 00401402: push ebx
         // 00401403: call 0x4c6bfa
         // 00401408: add esp, 0x4
      [-]588945f068????????6a008b45f485c07505
         // 0040140b: pop eax
         // 0040140c: mov ss:[ebp+0xfffffffffffffff0], eax
         // 0040140f: push 0xffffffff80000004
         // 00401414: push 0x0
         // 00401416: mov eax, ss:[ebp+0xfffffffffffffff4]
         // 00401419: test eax, eax
         // 0040141b: jnz 0x401422
      [-]b8????????
         // 0040141d: mov eax, 0x560d75
      [-]5068????????bb????????e8e0570c0083c4108945e868????????6a008b45f085c07505
         // 00401422: push eax
         // 00401423: push 0x1
         // 00401428: mov ebx, 0x4c8aa0
         // 0040142d: call 0x4c6c12
         // 00401432: add esp, 0x10
         // 00401435: mov ss:[ebp+0xffffffffffffffe8], eax
         // 00401438: push 0xffffffff80000004
         // 0040143d: push 0x0
         // 0040143f: mov eax, ss:[ebp+0xfffffffffffffff0]
         // 00401442: test eax, eax
         // 00401444: jnz 0x40144b
      [-]b8????????
         // 00401446: mov eax, 0x560d75
      [-]5068????????bb????????e8b7570c0083c4108945e4c745e0????????6a00ff75e0c745dc????????6a00ff75dc6a018d45e4508d45e8508d45f850e8a22700008945d88b5de885db7409
         // 0040144b: push eax
         // 0040144c: push 0x1
         // 00401451: mov ebx, 0x4c8aa0
         // 00401456: call 0x4c6c12
         // 0040145b: add esp, 0x10
         // 0040145e: mov ss:[ebp+0xffffffffffffffe4], eax
         // 00401461: mov ss:[ebp+0xffffffffffffffe0], 0x0
         // 00401468: push 0x0
         // 0040146a: push ss:[ebp+0xffffffffffffffe0]
         // 0040146d: mov ss:[ebp+0xffffffffffffffdc], 0x0
         // 00401474: push 0x0
         // 00401476: push ss:[ebp+0xffffffffffffffdc]
         // 00401479: push 0x1
         // 0040147b: lea eax, ss:[ebp+0xffffffffffffffe4]
         // 0040147e: push eax
         // 0040147f: lea eax, ss:[ebp+0xffffffffffffffe8]
         // 00401482: push eax
         // 00401483: lea eax, ss:[ebp+0xfffffffffffffff8]
         // 00401486: push eax
         // 00401487: call 0x403c2e
         // 0040148c: mov ss:[ebp+0xffffffffffffffd8], eax
         // 0040148f: mov ebx, ss:[ebp+0xffffffffffffffe8]
         // 00401492: test ebx, ebx
         // 00401494: jz 0x40149f
      [-]53e85e570c0083c404
         // 00401496: push ebx
         // 00401497: call 0x4c6bfa
         // 0040149c: add esp, 0x4
      [-]8b5de485db7409
         // 0040149f: mov ebx, ss:[ebp+0xffffffffffffffe4]
         // 004014a2: test ebx, ebx
         // 004014a4: jz 0x4014af
      [-]53e84e570c0083c404
         // 004014a6: push ebx
         // 004014a7: call 0x4c6bfa
         // 004014ac: add esp, 0x4
      [-]8b45d8508b5df885db7409
         // 004014af: mov eax, ss:[ebp+0xffffffffffffffd8]
         // 004014b2: push eax
         // 004014b3: mov ebx, ss:[ebp+0xfffffffffffffff8]
         // 004014b6: test ebx, ebx
         // 004014b8: jz 0x4014c3
      [-]53e83a570c0083c404
         // 004014ba: push ebx
         // 004014bb: call 0x4c6bfa
         // 004014c0: add esp, 0x4
      [-]588945f868????????bb????????e83c570c0083c4048945e88b5dfce839fbffffb8????????3bc17c17
         // 004014c3: pop eax
         // 004014c4: mov ss:[ebp+0xfffffffffffffff8], eax
         // 004014c7: push 0x0
         // 004014cc: mov ebx, 0x4c72d0
         // 004014d1: call 0x4c6c12
         // 004014d6: add esp, 0x4
         // 004014d9: mov ss:[ebp+0xffffffffffffffe8], eax
         // 004014dc: mov ebx, ss:[ebp+0xfffffffffffffffc]
         // 004014df: call 0x40101d
         // 004014e4: mov eax, 0x1
         // 004014e9: cmp eax, ecx
         // 004014eb: jl 0x401504
      [-]68????????68????????68????????e805570c0083c40c
         // 004014ed: push 0x32b
         // 004014f2: push 0x4010001
         // 004014f7: push 0x1
         // 004014fc: call 0x4c6c06
         // 00401501: add esp, 0xc
      [-]c1e00203d8895de48b5de4ff3368????????ff75e8b9????????e822fcffff83c40c8945e08b5de885db7409
         // 00401504: shl eax, b1 0x2
         // 00401507: add ebx, eax
         // 00401509: mov ss:[ebp+0xffffffffffffffe4], ebx
         // 0040150c: mov ebx, ss:[ebp+0xffffffffffffffe4]
         // 0040150f: push ds:[ebx]
         // 00401511: push 0x560d73
         // 00401516: push ss:[ebp+0xffffffffffffffe8]
         // 00401519: mov ecx, 0x3
         // 0040151e: call 0x401145
         // 00401523: add esp, 0xc
         // 00401526: mov ss:[ebp+0xffffffffffffffe0], eax
         // 00401529: mov ebx, ss:[ebp+0xffffffffffffffe8]
         // 0040152c: test ebx, ebx
         // 0040152e: jz 0x401539
      [-]53e8c4560c0083c404
         // 00401530: push ebx
         // 00401531: call 0x4c6bfa
         // 00401536: add esp, 0x4
      [-]68????????6a008b45f885c07505
         // 00401539: push 0xffffffff80000005
         // 0040153e: push 0x0
         // 00401540: mov eax, ss:[ebp+0xfffffffffffffff8]
         // 00401543: test eax, eax
         // 00401545: jnz 0x40154c
      [-]b8????????
         // 00401547: mov eax, 0x560da9
      [-]5068????????6a008b45e085c07505
         // 0040154c: push eax
         // 0040154d: push 0xffffffff80000004
         // 00401552: push 0x0
         // 00401554: mov eax, ss:[ebp+0xffffffffffffffe0]
         // 00401557: test eax, eax
         // 00401559: jnz 0x401560
      [-]b8????????
         // 0040155b: mov eax, 0x560d75
      [-]5068????????bb????????e8a2560c0083c41c8945dc8b5de085db7409
         // 00401560: push eax
         // 00401561: push 0x2
         // 00401566: mov ebx, 0x4c9af0
         // 0040156b: call 0x4c6c12
         // 00401570: add esp, 0x1c
         // 00401573: mov ss:[ebp+0xffffffffffffffdc], eax
         // 00401576: mov ebx, ss:[ebp+0xffffffffffffffe0]
         // 00401579: test ebx, ebx
         // 0040157b: jz 0x401586
      [-]53e877560c0083c404
         // 0040157d: push ebx
         // 0040157e: call 0x4c6bfa
         // 00401583: add esp, 0x4
      [-]8b45dc8945ec6a00e89d560c0083c404
         // 00401586: mov eax, ss:[ebp+0xffffffffffffffdc]
         // 00401589: mov ss:[ebp+0xffffffffffffffec], eax
         // 0040158c: push 0x0
         // 0040158e: call 0x4c6c30
         // 00401593: add esp, 0x4
      [-]c745e8????????6a00ff75e868????????e8001500008945e468????????ff75e4b9????????e884fbffff83c4088945e08b5de485db7409
         // 00401596: mov ss:[ebp+0xffffffffffffffe8], 0x0
         // 0040159d: push 0x0
         // 0040159f: push ss:[ebp+0xffffffffffffffe8]
         // 004015a2: push 0x8
         // 004015a7: call 0x402aac
         // 004015ac: mov ss:[ebp+0xffffffffffffffe4], eax
         // 004015af: push 0x560db1
         // 004015b4: push ss:[ebp+0xffffffffffffffe4]
         // 004015b7: mov ecx, 0x2
         // 004015bc: call 0x401145
         // 004015c1: add esp, 0x8
         // 004015c4: mov ss:[ebp+0xffffffffffffffe0], eax
         // 004015c7: mov ebx, ss:[ebp+0xffffffffffffffe4]
         // 004015ca: test ebx, ebx
         // 004015cc: jz 0x4015d7
      [-]53e826560c0083c404
         // 004015ce: push ebx
         // 004015cf: call 0x4c6bfa
         // 004015d4: add esp, 0x4
      [-]8b45e0508b1d????????85db7409
         // 004015d7: mov eax, ss:[ebp+0xffffffffffffffe0]
         // 004015da: push eax
         // 004015db: mov ebx, ds:[0x5b14f0]
         // 004015e1: test ebx, ebx
         // 004015e3: jz 0x4015ee
      [-]53e80f560c0083c404
         // 004015e5: push ebx
         // 004015e6: call 0x4c6bfa
         // 004015eb: add esp, 0x4
      [-]58a3????????e8ea2f000085c00f8447000000
         // 004015ee: pop eax
         // 004015ef: mov ds:[0x5b14f0], eax
         // 004015f4: call 0x4045e3
         // 004015f9: test eax, eax
         // 004015fb: jz 0x401648
      [-]8965e868????????68????????68????????68????????b8????????e8ea550c003965e87417
         // 00401601: mov ss:[ebp+0xffffffffffffffe8], esp
         // 00401604: push 0x10
         // 00401609: push 0x560db6
         // 0040160e: push 0x560dbb
         // 00401613: push 0x0
         // 00401618: mov eax, 0x0
         // 0040161d: call 0x4c6c0c
         // 00401622: cmp ss:[ebp+0xffffffffffffffe8], esp
         // 00401625: jz 0x40163e
      [-]68????????68????????68????????e8cb550c0083c40c
         // 00401627: push 0x423
         // 0040162c: push 0x4010001
         // 00401631: push 0x6
         // 00401636: call 0x4c6c06
         // 0040163b: add esp, 0xc
      [-]b8????????e99b000000
         // 0040163e: mov eax, 0x0
         // 00401643: jmp 0x4016e3
      [-]e85e3100008945e4837de4000f8547000000
         // 00401648: call 0x4047ab
         // 0040164d: mov ss:[ebp+0xffffffffffffffe4], eax
         // 00401650: cmp ss:[ebp+0xffffffffffffffe4], 0x0
         // 00401654: jnz 0x4016a1
      [-]8965e868????????68????????68????????68????????b8????????e891550c003965e87417
         // 0040165a: mov ss:[ebp+0xffffffffffffffe8], esp
         // 0040165d: push 0x0
         // 00401662: push 0x560db6
         // 00401667: push 0x560dd7
         // 0040166c: push 0x0
         // 00401671: mov eax, 0x0
         // 00401676: call 0x4c6c0c
         // 0040167b: cmp ss:[ebp+0xffffffffffffffe8], esp
         // 0040167e: jz 0x401697
      [-]68????????68????????68????????e872550c0083c40c
         // 00401680: push 0x4ce
         // 00401685: push 0x4010001
         // 0040168a: push 0x6
         // 0040168f: call 0x4c6c06
         // 00401694: add esp, 0xc
      [-]b8????????e942000000
         // 00401697: mov eax, 0x0
         // 0040169c: jmp 0x4016e3
      [-]e83032000068????????6a0068????????6a006a006a0068????????68????????68????????68????????bb????????e83c550c0083c428b8????????e900000000
         // 004016a1: call 0x4048d6
         // 004016a6: push 0xffffffff80000002
         // 004016ab: push 0x0
         // 004016ad: push 0x0
         // 004016b2: push 0x0
         // 004016b4: push 0x0
         // 004016b6: push 0x0
         // 004016b8: push 0x10001
         // 004016bd: push 0x60698e8
         // 004016c2: push 0x520698e7
         // 004016c7: push 0x3
         // 004016cc: mov ebx, 0x4c7220
         // 004016d1: call 0x4c6c12
         // 004016d6: add esp, 0x28
         // 004016d9: mov eax, 0x0
         // 004016de: jmp 0x4016e3
      [-]508b5dfc538b0b83c30485c97411
         // 004016e3: push eax
         // 004016e4: mov ebx, ss:[ebp+0xfffffffffffffffc]
         // 004016e7: push ebx
         // 004016e8: mov ecx, ds:[ebx]
         // 004016ea: add ebx, 0x4
         // 004016ed: test ecx, ecx
         // 004016ef: jz 0x401702
      [-]83c304497405
         // 004016f3: add ebx, 0x4
         // 004016f6: dec ecx
         // 004016f7: jz 0x4016fe
      [-]0faf03ebf5
         // 004016f9: imul eax, ds:[ebx]
         // 004016fc: jmp 0x4016f3
      [-]8bc885c9
         // 004016fe: mov ecx, eax
         // 00401700: test ecx, ecx
      [-]0f8419000000
         // 00401702: jz 0x401721
      [-]518b0385c0740b
         // 00401708: push ecx
         // 00401709: mov eax, ds:[ebx]
         // 0040170b: test eax, eax
         // 0040170d: jz 0x40171a
      [-]5350e8e4540c0083c4045b
         // 0040170f: push ebx
         // 00401710: push eax
         // 00401711: call 0x4c6bfa
         // 00401716: add esp, 0x4
         // 00401719: pop ebx
      [-]83c304594975e7
         // 0040171a: add ebx, 0x4
         // 0040171d: pop ecx
         // 0040171e: dec ecx
         // 0040171f: jnz 0x401708
      [-]e8d4540c0083c4048b5df885db7409
         // 00401721: call 0x4c6bfa
         // 00401726: add esp, 0x4
         // 00401729: mov ebx, ss:[ebp+0xfffffffffffffff8]
         // 0040172c: test ebx, ebx
         // 0040172e: jz 0x401739
      [-]53e8c4540c0083c404
         // 00401730: push ebx
         // 00401731: call 0x4c6bfa
         // 00401736: add esp, 0x4
      [-]8b5df485db7409
         // 00401739: mov ebx, ss:[ebp+0xfffffffffffffff4]
         // 0040173c: test ebx, ebx
         // 0040173e: jz 0x401749
      [-]53e8b4540c0083c404
         // 00401740: push ebx
         // 00401741: call 0x4c6bfa
         // 00401746: add esp, 0x4
      [-]8b5df085db7409
         // 00401749: mov ebx, ss:[ebp+0xfffffffffffffff0]
         // 0040174c: test ebx, ebx
         // 0040174e: jz 0x401759
      [-]53e8a4540c0083c404
         // 00401750: push ebx
         // 00401751: call 0x4c6bfa
         // 00401756: add esp, 0x4
      [-]588be55dc3
         // 00401759: pop eax
         // 0040175a: mov esp, ebp
         // 0040175c: pop ebp
         // 0040175d: retn 
      [-]558bec81ec????????c745fc????????c745f8????????68????????e881540c0083c4048945f48bf8be????????adabadab68????????bb????????e873540c0083c4048945f068????????ff75f0b9????????e88ef9ffff83c4088945ec8b5df085db7409
         // 0040175e: push ebp
         // 0040175f: mov ebp, esp
         // 00401761: sub esp, 0x20
         // 00401767: mov ss:[ebp+0xfffffffffffffffc], 0x0
         // 0040176e: mov ss:[ebp+0xfffffffffffffff8], 0x0
         // 00401775: push 0x8
         // 0040177a: call 0x4c6c00
         // 0040177f: add esp, 0x4
         // 00401782: mov ss:[ebp+0xfffffffffffffff4], eax
         // 00401785: mov edi, eax
         // 00401787: mov esi, 0x560da9
         // 0040178c: lodsdd 
         // 0040178d: stosdd 
         // 0040178e: lodsdd 
         // 0040178f: stosdd 
         // 00401790: push 0x0
         // 00401795: mov ebx, 0x4c72d0
         // 0040179a: call 0x4c6c12
         // 0040179f: add esp, 0x4
         // 004017a2: mov ss:[ebp+0xfffffffffffffff0], eax
         // 004017a5: push 0x560de1
         // 004017aa: push ss:[ebp+0xfffffffffffffff0]
         // 004017ad: mov ecx, 0x2
         // 004017b2: call 0x401145
         // 004017b7: add esp, 0x8
         // 004017ba: mov ss:[ebp+0xffffffffffffffec], eax
         // 004017bd: mov ebx, ss:[ebp+0xfffffffffffffff0]
         // 004017c0: test ebx, ebx
         // 004017c2: jz 0x4017cd
      [-]53e830540c0083c404
         // 004017c4: push ebx
         // 004017c5: call 0x4c6bfa
         // 004017ca: add esp, 0x4
      [-]6a006a006a0068????????6a0068????????68????????6a0068????????68????????6a008b45ec85c07505
         // 004017cd: push 0x0
         // 004017cf: push 0x0
         // 004017d1: push 0x0
         // 004017d3: push 0xffffffff80000004
         // 004017d8: push 0x0
         // 004017da: push 0x560df1
         // 004017df: push 0xffffffff80000004
         // 004017e4: push 0x0
         // 004017e6: push 0x560df5
         // 004017eb: push 0xffffffff80000004
         // 004017f0: push 0x0
         // 004017f2: mov eax, ss:[ebp+0xffffffffffffffec]
         // 004017f5: test eax, eax
         // 004017f7: jnz 0x4017fe
      [-]b8????????
         // 004017f9: mov eax, 0x560d75
      [-]5068????????bb????????e804540c0083c4348945e88b5dec85db7409
         // 004017fe: push eax
         // 004017ff: push 0x4
         // 00401804: mov ebx, 0x4cb290
         // 00401809: call 0x4c6c12
         // 0040180e: add esp, 0x34
         // 00401811: mov ss:[ebp+0xffffffffffffffe8], eax
         // 00401814: mov ebx, ss:[ebp+0xffffffffffffffec]
         // 00401817: test ebx, ebx
         // 00401819: jz 0x401824
      [-]53e8d9530c0083c404
         // 0040181b: push ebx
         // 0040181c: call 0x4c6bfa
         // 00401821: add esp, 0x4
      [-]8b45e8508b5dfc85db7409
         // 00401824: mov eax, ss:[ebp+0xffffffffffffffe8]
         // 00401827: push eax
         // 00401828: mov ebx, ss:[ebp+0xfffffffffffffffc]
         // 0040182b: test ebx, ebx
         // 0040182d: jz 0x401838
      [-]53e8c5530c0083c404
         // 0040182f: push ebx
         // 00401830: call 0x4c6bfa
         // 00401835: add esp, 0x4
      [-]588945fcc745f0????????6a00ff75f08d45fc506a018d45f450e8180400008945f8837df8000f8eac000000
         // 00401838: pop eax
         // 00401839: mov ss:[ebp+0xfffffffffffffffc], eax
         // 0040183c: mov ss:[ebp+0xfffffffffffffff0], 0x0
         // 00401843: push 0x0
         // 00401845: push ss:[ebp+0xfffffffffffffff0]
         // 00401848: lea eax, ss:[ebp+0xfffffffffffffffc]
         // 0040184b: push eax
         // 0040184c: push 0x1
         // 0040184e: lea eax, ss:[ebp+0xfffffffffffffff4]
         // 00401851: push eax
         // 00401852: call 0x401c6f
         // 00401857: mov ss:[ebp+0xfffffffffffffff8], eax
         // 0040185a: cmp ss:[ebp+0xfffffffffffffff8], 0x0
         // 0040185e: jle 0x401910
      [-]68????????bb????????e89f530c0083c4048945f0ff75fc68????????ff75f0b9????????e8b7f8ffff83c40c8945ec8b5df085db7409
         // 00401864: push 0x0
         // 00401869: mov ebx, 0x4c72d0
         // 0040186e: call 0x4c6c12
         // 00401873: add esp, 0x4
         // 00401876: mov ss:[ebp+0xfffffffffffffff0], eax
         // 00401879: push ss:[ebp+0xfffffffffffffffc]
         // 0040187c: push 0x560d73
         // 00401881: push ss:[ebp+0xfffffffffffffff0]
         // 00401884: mov ecx, 0x3
         // 00401889: call 0x401145
         // 0040188e: add esp, 0xc
         // 00401891: mov ss:[ebp+0xffffffffffffffec], eax
         // 00401894: mov ebx, ss:[ebp+0xfffffffffffffff0]
         // 00401897: test ebx, ebx
         // 00401899: jz 0x4018a4
      [-]53e859530c0083c404
         // 0040189b: push ebx
         // 0040189c: call 0x4c6bfa
         // 004018a1: add esp, 0x4
      [-]c745e8????????6a00ff75e8c745e4????????6a008d45e4506a01b8????????8945e08d45e0508d45ec506a0168????????e8630b00008b5dec85db7409
         // 004018a4: mov ss:[ebp+0xffffffffffffffe8], 0x0
         // 004018ab: push 0x0
         // 004018ad: push ss:[ebp+0xffffffffffffffe8]
         // 004018b0: mov ss:[ebp+0xffffffffffffffe4], 0x0
         // 004018b7: push 0x0
         // 004018b9: lea eax, ss:[ebp+0xffffffffffffffe4]
         // 004018bc: push eax
         // 004018bd: push 0x1
         // 004018bf: mov eax, 0x560dfa
         // 004018c4: mov ss:[ebp+0xffffffffffffffe0], eax
         // 004018c7: lea eax, ss:[ebp+0xffffffffffffffe0]
         // 004018ca: push eax
         // 004018cb: lea eax, ss:[ebp+0xffffffffffffffec]
         // 004018ce: push eax
         // 004018cf: push 0x1
         // 004018d1: push 0x1
         // 004018d6: call 0x40243e
         // 004018db: mov ebx, ss:[ebp+0xffffffffffffffec]
         // 004018de: test ebx, ebx
         // 004018e0: jz 0x4018eb
      [-]53e812530c0083c404
         // 004018e2: push ebx
         // 004018e3: call 0x4c6bfa
         // 004018e8: add esp, 0x4
      [-]8b5de085db7409
         // 004018eb: mov ebx, ss:[ebp+0xffffffffffffffe0]
         // 004018ee: test ebx, ebx
         // 004018f0: jz 0x4018fb
      [-]53e802530c0083c404
         // 004018f2: push ebx
         // 004018f3: call 0x4c6bfa
         // 004018f8: add esp, 0x4
      [-]8b5de485db7409
         // 004018fb: mov ebx, ss:[ebp+0xffffffffffffffe4]
         // 004018fe: test ebx, ebx
         // 00401900: jz 0x40190b
      [-]53e8f2520c0083c404
         // 00401902: push ebx
         // 00401903: call 0x4c6bfa
         // 00401908: add esp, 0x4
      [-]e93f030000
         // 0040190b: jmp 0x401c4f
      [-]68????????bb????????e8f3520c0083c4048945f0ff75fc68????????ff75f0b9????????e80bf8ffff83c40c8945ec8b5df085db7409
         // 00401910: push 0x0
         // 00401915: mov ebx, 0x4c72d0
         // 0040191a: call 0x4c6c12
         // 0040191f: add esp, 0x4
         // 00401922: mov ss:[ebp+0xfffffffffffffff0], eax
         // 00401925: push ss:[ebp+0xfffffffffffffffc]
         // 00401928: push 0x560d73
         // 0040192d: push ss:[ebp+0xfffffffffffffff0]
         // 00401930: mov ecx, 0x3
         // 00401935: call 0x401145
         // 0040193a: add esp, 0xc
         // 0040193d: mov ss:[ebp+0xffffffffffffffec], eax
         // 00401940: mov ebx, ss:[ebp+0xfffffffffffffff0]
         // 00401943: test ebx, ebx
         // 00401945: jz 0x401950
      [-]53e8ad520c0083c404
         // 00401947: push ebx
         // 00401948: call 0x4c6bfa
         // 0040194d: add esp, 0x4
      [-]68????????6a008b45ec85c07505
         // 00401950: push 0xffffffff80000004
         // 00401955: push 0x0
         // 00401957: mov eax, ss:[ebp+0xffffffffffffffec]
         // 0040195a: test eax, eax
         // 0040195c: jnz 0x401963
      [-]b8????????
         // 0040195e: mov eax, 0x560d75
      [-]5068????????bb????????e89f520c0083c4108945e88b5dec85db7409
         // 00401963: push eax
         // 00401964: push 0x1
         // 00401969: mov ebx, 0x4c9a40
         // 0040196e: call 0x4c6c12
         // 00401973: add esp, 0x10
         // 00401976: mov ss:[ebp+0xffffffffffffffe8], eax
         // 00401979: mov ebx, ss:[ebp+0xffffffffffffffec]
         // 0040197c: test ebx, ebx
         // 0040197e: jz 0x401989
      [-]53e874520c0083c404
         // 00401980: push ebx
         // 00401981: call 0x4c6bfa
         // 00401986: add esp, 0x4
      [-]837de8010f8576000000
         // 00401989: cmp ss:[ebp+0xffffffffffffffe8], 0x1
         // 0040198d: jnz 0x401a09
      [-]68????????bb????????e870520c0083c4048945f0ff75fc68????????ff75f0b9????????e888f7ffff83c40c8945ec8b5df085db7409
         // 00401993: push 0x0
         // 00401998: mov ebx, 0x4c72d0
         // 0040199d: call 0x4c6c12
         // 004019a2: add esp, 0x4
         // 004019a5: mov ss:[ebp+0xfffffffffffffff0], eax
         // 004019a8: push ss:[ebp+0xfffffffffffffffc]
         // 004019ab: push 0x560d73
         // 004019b0: push ss:[ebp+0xfffffffffffffff0]
         // 004019b3: mov ecx, 0x3
         // 004019b8: call 0x401145
         // 004019bd: add esp, 0xc
         // 004019c0: mov ss:[ebp+0xffffffffffffffec], eax
         // 004019c3: mov ebx, ss:[ebp+0xfffffffffffffff0]
         // 004019c6: test ebx, ebx
         // 004019c8: jz 0x4019d3
      [-]53e82a520c0083c404
         // 004019ca: push ebx
         // 004019cb: call 0x4c6bfa
         // 004019d0: add esp, 0x4
      [-]68????????6a008b45ec85c07505
         // 004019d3: push 0xffffffff80000004
         // 004019d8: push 0x0
         // 004019da: mov eax, ss:[ebp+0xffffffffffffffec]
         // 004019dd: test eax, eax
         // 004019df: jnz 0x4019e6
      [-]b8????????
         // 004019e1: mov eax, 0x560d75
      [-]5068????????bb????????e81c520c0083c4108b5dec85db7409
         // 004019e6: push eax
         // 004019e7: push 0x1
         // 004019ec: mov ebx, 0x4c9a20
         // 004019f1: call 0x4c6c12
         // 004019f6: add esp, 0x10
         // 004019f9: mov ebx, ss:[ebp+0xffffffffffffffec]
         // 004019fc: test ebx, ebx
         // 004019fe: jz 0x401a09
      [-]53e8f4510c0083c404
         // 00401a00: push ebx
         // 00401a01: call 0x4c6bfa
         // 00401a06: add esp, 0x4
      [-]c745f0????????6a00ff75f068????????e88d1000008945ec68????????ff75ecb9????????e811f7ffff83c4088945e88b5dec85db7409
         // 00401a09: mov ss:[ebp+0xfffffffffffffff0], 0x0
         // 00401a10: push 0x0
         // 00401a12: push ss:[ebp+0xfffffffffffffff0]
         // 00401a15: push 0xa
         // 00401a1a: call 0x402aac
         // 00401a1f: mov ss:[ebp+0xffffffffffffffec], eax
         // 00401a22: push 0x560dfc
         // 00401a27: push ss:[ebp+0xffffffffffffffec]
         // 00401a2a: mov ecx, 0x2
         // 00401a2f: call 0x401145
         // 00401a34: add esp, 0x8
         // 00401a37: mov ss:[ebp+0xffffffffffffffe8], eax
         // 00401a3a: mov ebx, ss:[ebp+0xffffffffffffffec]
         // 00401a3d: test ebx, ebx
         // 00401a3f: jz 0x401a4a
      [-]53e8b3510c0083c404
         // 00401a41: push ebx
         // 00401a42: call 0x4c6bfa
         // 00401a47: add esp, 0x4
      [-]8b45e8508b5dfc85db7409
         // 00401a4a: mov eax, ss:[ebp+0xffffffffffffffe8]
         // 00401a4d: push eax
         // 00401a4e: mov ebx, ss:[ebp+0xfffffffffffffffc]
         // 00401a51: test ebx, ebx
         // 00401a53: jz 0x401a5e
      [-]53e89f510c0083c404
         // 00401a55: push ebx
         // 00401a56: call 0x4c6bfa
         // 00401a5b: add esp, 0x4
      [-]588945fc68????????bb????????e8a1510c0083c4048945f068????????bb????????e88c510c0083c4048945ecff75fc68????????ff75ec68????????ff75f0b9????????e89cf6ffff83c4148945e88b5df085db7409
         // 00401a5e: pop eax
         // 00401a5f: mov ss:[ebp+0xfffffffffffffffc], eax
         // 00401a62: push 0x0
         // 00401a67: mov ebx, 0x4c72d0
         // 00401a6c: call 0x4c6c12
         // 00401a71: add esp, 0x4
         // 00401a74: mov ss:[ebp+0xfffffffffffffff0], eax
         // 00401a77: push 0x0
         // 00401a7c: mov ebx, 0x4c72f0
         // 00401a81: call 0x4c6c12
         // 00401a86: add esp, 0x4
         // 00401a89: mov ss:[ebp+0xffffffffffffffec], eax
         // 00401a8c: push ss:[ebp+0xfffffffffffffffc]
         // 00401a8f: push 0x560e01
         // 00401a94: push ss:[ebp+0xffffffffffffffec]
         // 00401a97: push 0x560d73
         // 00401a9c: push ss:[ebp+0xfffffffffffffff0]
         // 00401a9f: mov ecx, 0x5
         // 00401aa4: call 0x401145
         // 00401aa9: add esp, 0x14
         // 00401aac: mov ss:[ebp+0xffffffffffffffe8], eax
         // 00401aaf: mov ebx, ss:[ebp+0xfffffffffffffff0]
         // 00401ab2: test ebx, ebx
         // 00401ab4: jz 0x401abf
      [-]53e83e510c0083c404
         // 00401ab6: push ebx
         // 00401ab7: call 0x4c6bfa
         // 00401abc: add esp, 0x4
      [-]8b5dec85db7409
         // 00401abf: mov ebx, ss:[ebp+0xffffffffffffffec]
         // 00401ac2: test ebx, ebx
         // 00401ac4: jz 0x401acf
      [-]53e82e510c0083c404
         // 00401ac6: push ebx
         // 00401ac7: call 0x4c6bfa
         // 00401acc: add esp, 0x4
      [-]6a006a006a0068????????6a0068????????68????????6a008b45e885c07505
         // 00401acf: push 0x0
         // 00401ad1: push 0x0
         // 00401ad3: push 0x0
         // 00401ad5: push 0xffffffff80000002
         // 00401ada: push 0x0
         // 00401adc: push 0x1
         // 00401ae1: push 0xffffffff80000004
         // 00401ae6: push 0x0
         // 00401ae8: mov eax, ss:[ebp+0xffffffffffffffe8]
         // 00401aeb: test eax, eax
         // 00401aed: jnz 0x401af4
      [-]b8????????
         // 00401aef: mov eax, 0x560d75
      [-]5068????????bb????????e80e510c0083c4288b5de885db7409
         // 00401af4: push eax
         // 00401af5: push 0x3
         // 00401afa: mov ebx, 0x4c70d0
         // 00401aff: call 0x4c6c12
         // 00401b04: add esp, 0x28
         // 00401b07: mov ebx, ss:[ebp+0xffffffffffffffe8]
         // 00401b0a: test ebx, ebx
         // 00401b0c: jz 0x401b17
      [-]53e8e6500c0083c404
         // 00401b0e: push ebx
         // 00401b0f: call 0x4c6bfa
         // 00401b14: add esp, 0x4
      [-]68????????bb????????e8ec500c0083c4048945f068????????ff75f0b9????????e807f6ffff83c4088945ec8b5df085db7409
         // 00401b17: push 0x0
         // 00401b1c: mov ebx, 0x4c72d0
         // 00401b21: call 0x4c6c12
         // 00401b26: add esp, 0x4
         // 00401b29: mov ss:[ebp+0xfffffffffffffff0], eax
         // 00401b2c: push 0x560de1
         // 00401b31: push ss:[ebp+0xfffffffffffffff0]
         // 00401b34: mov ecx, 0x2
         // 00401b39: call 0x401145
         // 00401b3e: add esp, 0x8
         // 00401b41: mov ss:[ebp+0xffffffffffffffec], eax
         // 00401b44: mov ebx, ss:[ebp+0xfffffffffffffff0]
         // 00401b47: test ebx, ebx
         // 00401b49: jz 0x401b54
      [-]53e8a9500c0083c404
         // 00401b4b: push ebx
         // 00401b4c: call 0x4c6bfa
         // 00401b51: add esp, 0x4
      [-]68????????6a008b45fc85c07505
         // 00401b54: push 0xffffffff80000004
         // 00401b59: push 0x0
         // 00401b5b: mov eax, ss:[ebp+0xfffffffffffffffc]
         // 00401b5e: test eax, eax
         // 00401b60: jnz 0x401b67
      [-]b8????????
         // 00401b62: mov eax, 0x560d75
      [-]5068????????6a0068????????68????????6a0068????????68????????6a008b45ec85c07505
         // 00401b67: push eax
         // 00401b68: push 0xffffffff80000004
         // 00401b6d: push 0x0
         // 00401b6f: push 0x560df1
         // 00401b74: push 0xffffffff80000004
         // 00401b79: push 0x0
         // 00401b7b: push 0x560df5
         // 00401b80: push 0xffffffff80000004
         // 00401b85: push 0x0
         // 00401b87: mov eax, ss:[ebp+0xffffffffffffffec]
         // 00401b8a: test eax, eax
         // 00401b8c: jnz 0x401b93
      [-]b8????????
         // 00401b8e: mov eax, 0x560d75
      [-]5068????????bb????????e86f500c0083c4348b5dec85db7409
         // 00401b93: push eax
         // 00401b94: push 0x4
         // 00401b99: mov ebx, 0x4cb390
         // 00401b9e: call 0x4c6c12
         // 00401ba3: add esp, 0x34
         // 00401ba6: mov ebx, ss:[ebp+0xffffffffffffffec]
         // 00401ba9: test ebx, ebx
         // 00401bab: jz 0x401bb6
      [-]53e847500c0083c404
         // 00401bad: push ebx
         // 00401bae: call 0x4c6bfa
         // 00401bb3: add esp, 0x4
      [-]68????????bb????????e84d500c0083c4048945f0ff75fc68????????ff75f0b9????????e865f5ffff83c40c8945ec8b5df085db7409
         // 00401bb6: push 0x0
         // 00401bbb: mov ebx, 0x4c72d0
         // 00401bc0: call 0x4c6c12
         // 00401bc5: add esp, 0x4
         // 00401bc8: mov ss:[ebp+0xfffffffffffffff0], eax
         // 00401bcb: push ss:[ebp+0xfffffffffffffffc]
         // 00401bce: push 0x560d73
         // 00401bd3: push ss:[ebp+0xfffffffffffffff0]
         // 00401bd6: mov ecx, 0x3
         // 00401bdb: call 0x401145
         // 00401be0: add esp, 0xc
         // 00401be3: mov ss:[ebp+0xffffffffffffffec], eax
         // 00401be6: mov ebx, ss:[ebp+0xfffffffffffffff0]
         // 00401be9: test ebx, ebx
         // 00401beb: jz 0x401bf6
      [-]53e807500c0083c404
         // 00401bed: push ebx
         // 00401bee: call 0x4c6bfa
         // 00401bf3: add esp, 0x4
      [-]6a006a006a0068????????6a0068????????68????????6a008b45ec85c07505
         // 00401bf6: push 0x0
         // 00401bf8: push 0x0
         // 00401bfa: push 0x0
         // 00401bfc: push 0xffffffff80000002
         // 00401c01: push 0x0
         // 00401c03: push 0x0
         // 00401c08: push 0xffffffff80000004
         // 00401c0d: push 0x0
         // 00401c0f: mov eax, ss:[ebp+0xffffffffffffffec]
         // 00401c12: test eax, eax
         // 00401c14: jnz 0x401c1b
      [-]b8????????
         // 00401c16: mov eax, 0x560d75
      [-]5068????????bb????????e8e74f0c0083c4288b5dec85db7409
         // 00401c1b: push eax
         // 00401c1c: push 0x3
         // 00401c21: mov ebx, 0x4c70d0
         // 00401c26: call 0x4c6c12
         // 00401c2b: add esp, 0x28
         // 00401c2e: mov ebx, ss:[ebp+0xffffffffffffffec]
         // 00401c31: test ebx, ebx
         // 00401c33: jz 0x401c3e
      [-]53e8bf4f0c0083c404
         // 00401c35: push ebx
         // 00401c36: call 0x4c6bfa
         // 00401c3b: add esp, 0x4
      [-]c745f0????????6a00ff75f0e869110000
         // 00401c3e: mov ss:[ebp+0xfffffffffffffff0], 0x0
         // 00401c45: push 0x0
         // 00401c47: push ss:[ebp+0xfffffffffffffff0]
         // 00401c4a: call 0x402db8
      [-]8b5dfc85db7409
         // 00401c4f: mov ebx, ss:[ebp+0xfffffffffffffffc]
         // 00401c52: test ebx, ebx
         // 00401c54: jz 0x401c5f
      [-]53e89e4f0c0083c404
         // 00401c56: push ebx
         // 00401c57: call 0x4c6bfa
         // 00401c5c: add esp, 0x4
      [-]8b5df453e8924f0c0083c4048be55dc3
         // 00401c5f: mov ebx, ss:[ebp+0xfffffffffffffff4]
         // 00401c62: push ebx
         // 00401c63: call 0x4c6bfa
         // 00401c68: add esp, 0x4
         // 00401c6b: mov esp, ebp
         // 00401c6d: pop ebp
         // 00401c6e: retn 
      [-]558bec81ec????????c745fc????????68????????e8774f0c0083c4048945f88bd88bf833c0b9????????f3ab83c3245368????????e8564f0c0083c4045b89038bf8be????????adabadab33c0b9????????f3abc745f4????????8b5d088b1b53e8244f0c0083c404b8????????8b5d0889038965f068????????68????????b8????????e8124f0c003965f07417
         // 00401c6f: push ebp
         // 00401c70: mov ebp, esp
         // 00401c72: sub esp, 0x20
         // 00401c78: mov ss:[ebp+0xfffffffffffffffc], 0x0
         // 00401c7f: push 0x28
         // 00401c84: call 0x4c6c00
         // 00401c89: add esp, 0x4
         // 00401c8c: mov ss:[ebp+0xfffffffffffffff8], eax
         // 00401c8f: mov ebx, eax
         // 00401c91: mov edi, eax
         // 00401c93: xor eax, eax
         // 00401c95: mov ecx, 0xa
         // 00401c9a: rep stosdd 
         // 00401c9c: add ebx, 0x24
         // 00401c9f: push ebx
         // 00401ca0: push 0x108
         // 00401ca5: call 0x4c6c00
         // 00401caa: add esp, 0x4
         // 00401cad: pop ebx
         // 00401cae: mov ds:[ebx], eax
         // 00401cb0: mov edi, eax
         // 00401cb2: mov esi, 0x560e0a
         // 00401cb7: lodsdd 
         // 00401cb8: stosdd 
         // 00401cb9: lodsdd 
         // 00401cba: stosdd 
         // 00401cbb: xor eax, eax
         // 00401cbd: mov ecx, 0x40
         // 00401cc2: rep stosdd 
         // 00401cc4: mov ss:[ebp+0xfffffffffffffff4], 0x0
         // 00401ccb: mov ebx, ss:[ebp+0x8]
         // 00401cce: mov ebx, ds:[ebx]
         // 00401cd0: push ebx
         // 00401cd1: call 0x4c6bfa
         // 00401cd6: add esp, 0x4
         // 00401cd9: mov eax, 0x560da9
         // 00401cde: mov ebx, ss:[ebp+0x8]
         // 00401ce1: mov ds:[ebx], eax
         // 00401ce3: mov ss:[ebp+0xfffffffffffffff0], esp
         // 00401ce6: push 0x0
         // 00401ceb: push 0xf
         // 00401cf0: mov eax, 0x1
         // 00401cf5: call 0x4c6c0c
         // 00401cfa: cmp ss:[ebp+0xfffffffffffffff0], esp
         // 00401cfd: jz 0x401d16
      [-]68????????68????????68????????e8f34e0c0083c40c
         // 00401cff: push 0x33
         // 00401d04: push 0x408d1ca
         // 00401d09: push 0x6
         // 00401d0e: call 0x4c6c06
         // 00401d13: add esp, 0xc
      [-]8945fc837dfc000f84bc060000
         // 00401d16: mov ss:[ebp+0xfffffffffffffffc], eax
         // 00401d19: cmp ss:[ebp+0xfffffffffffffffc], 0x0
         // 00401d1d: jz 0x4023df
      [-]8b5df8895df08b5df0c703????????8965f08b45f85068????????e8bd4e0c0083c4048bf85b50895de88945ec8b0383c304890783c7048b0383c304890783c7048b0383c304890783c7048b0383c304890783c7048b0383c304890783c7048b0383c304890783c7048b0383c304890783c7048b0383c304890783c7048b0383c304890783c704538b1b81c3????????b9????????8bf3f3a45b83c304ff75fcb8????????e83f4e0c003965f07417
         // 00401d23: mov ebx, ss:[ebp+0xfffffffffffffff8]
         // 00401d26: mov ss:[ebp+0xfffffffffffffff0], ebx
         // 00401d29: mov ebx, ss:[ebp+0xfffffffffffffff0]
         // 00401d2c: mov ds:[ebx], 0x400
         // 00401d32: mov ss:[ebp+0xfffffffffffffff0], esp
         // 00401d35: mov eax, ss:[ebp+0xfffffffffffffff8]
         // 00401d38: push eax
         // 00401d39: push 0x124
         // 00401d3e: call 0x4c6c00
         // 00401d43: add esp, 0x4
         // 00401d46: mov edi, eax
         // 00401d48: pop ebx
         // 00401d49: push eax
         // 00401d4a: mov ss:[ebp+0xffffffffffffffe8], ebx
         // 00401d4d: mov ss:[ebp+0xffffffffffffffec], eax
         // 00401d50: mov eax, ds:[ebx]
         // 00401d52: add ebx, 0x4
         // 00401d55: mov ds:[edi], eax
         // 00401d57: add edi, 0x4
         // 00401d5a: mov eax, ds:[ebx]
         // 00401d5c: add ebx, 0x4
         // 00401d5f: mov ds:[edi], eax
         // 00401d61: add edi, 0x4
         // 00401d64: mov eax, ds:[ebx]
         // 00401d66: add ebx, 0x4
         // 00401d69: mov ds:[edi], eax
         // 00401d6b: add edi, 0x4
         // 00401d6e: mov eax, ds:[ebx]
         // 00401d70: add ebx, 0x4
         // 00401d73: mov ds:[edi], eax
         // 00401d75: add edi, 0x4
         // 00401d78: mov eax, ds:[ebx]
         // 00401d7a: add ebx, 0x4
         // 00401d7d: mov ds:[edi], eax
         // 00401d7f: add edi, 0x4
         // 00401d82: mov eax, ds:[ebx]
         // 00401d84: add ebx, 0x4
         // 00401d87: mov ds:[edi], eax
         // 00401d89: add edi, 0x4
         // 00401d8c: mov eax, ds:[ebx]
         // 00401d8e: add ebx, 0x4
         // 00401d91: mov ds:[edi], eax
         // 00401d93: add edi, 0x4
         // 00401d96: mov eax, ds:[ebx]
         // 00401d98: add ebx, 0x4
         // 00401d9b: mov ds:[edi], eax
         // 00401d9d: add edi, 0x4
         // 00401da0: mov eax, ds:[ebx]
         // 00401da2: add ebx, 0x4
         // 00401da5: mov ds:[edi], eax
         // 00401da7: add edi, 0x4
         // 00401daa: push ebx
         // 00401dab: mov ebx, ds:[ebx]
         // 00401dad: add ebx, 0x8
         // 00401db3: mov ecx, 0x100
         // 00401db8: mov esi, ebx
         // 00401dba: rep movsbb 
         // 00401dbc: pop ebx
         // 00401dbd: add ebx, 0x4
         // 00401dc0: push ss:[ebp+0xfffffffffffffffc]
         // 00401dc3: mov eax, 0x2
         // 00401dc8: call 0x4c6c0c
         // 00401dcd: cmp ss:[ebp+0xfffffffffffffff0], esp
         // 00401dd0: jz 0x401de9
      [-]68????????68????????68????????e8204e0c0083c40c
         // 00401dd2: push 0xd4
         // 00401dd7: push 0x408d1ca
         // 00401ddc: push 0x6
         // 00401de1: call 0x4c6c06
         // 00401de6: add esp, 0xc
      [-]508b5dec538b7de88b0383c304890783c7048b0383c304890783c7048b0383c304890783c7048b0383c304890783c7048b0383c304890783c7048b0383c304890783c7048b0383c304890783c7048b0383c304890783c7048b0383c304890783c70453576a01b8????????e89b4d0c0083c4045f5b53578b3f8b0f83c70485c9740f
         // 00401de9: push eax
         // 00401dea: mov ebx, ss:[ebp+0xffffffffffffffec]
         // 00401ded: push ebx
         // 00401dee: mov edi, ss:[ebp+0xffffffffffffffe8]
         // 00401df1: mov eax, ds:[ebx]
         // 00401df3: add ebx, 0x4
         // 00401df6: mov ds:[edi], eax
         // 00401df8: add edi, 0x4
         // 00401dfb: mov eax, ds:[ebx]
         // 00401dfd: add ebx, 0x4
         // 00401e00: mov ds:[edi], eax
         // 00401e02: add edi, 0x4
         // 00401e05: mov eax, ds:[ebx]
         // 00401e07: add ebx, 0x4
         // 00401e0a: mov ds:[edi], eax
         // 00401e0c: add edi, 0x4
         // 00401e0f: mov eax, ds:[ebx]
         // 00401e11: add ebx, 0x4
         // 00401e14: mov ds:[edi], eax
         // 00401e16: add edi, 0x4
         // 00401e19: mov eax, ds:[ebx]
         // 00401e1b: add ebx, 0x4
         // 00401e1e: mov ds:[edi], eax
         // 00401e20: add edi, 0x4
         // 00401e23: mov eax, ds:[ebx]
         // 00401e25: add ebx, 0x4
         // 00401e28: mov ds:[edi], eax
         // 00401e2a: add edi, 0x4
         // 00401e2d: mov eax, ds:[ebx]
         // 00401e2f: add ebx, 0x4
         // 00401e32: mov ds:[edi], eax
         // 00401e34: add edi, 0x4
         // 00401e37: mov eax, ds:[ebx]
         // 00401e39: add ebx, 0x4
         // 00401e3c: mov ds:[edi], eax
         // 00401e3e: add edi, 0x4
         // 00401e41: mov eax, ds:[ebx]
         // 00401e43: add ebx, 0x4
         // 00401e46: mov ds:[edi], eax
         // 00401e48: add edi, 0x4
         // 00401e4b: push ebx
         // 00401e4c: push edi
         // 00401e4d: push 0x1
         // 00401e4f: mov eax, 0x2
         // 00401e54: call 0x4c6bf4
         // 00401e59: add esp, 0x4
         // 00401e5c: pop edi
         // 00401e5d: pop ebx
         // 00401e5e: push ebx
         // 00401e5f: push edi
         // 00401e60: mov edi, ds:[edi]
         // 00401e62: mov ecx, ds:[edi]
         // 00401e64: add edi, 0x4
         // 00401e67: test ecx, ecx
         // 00401e69: jz 0x401e7a
      [-]83c704497405
         // 00401e6d: add edi, 0x4
         // 00401e70: dec ecx
         // 00401e71: jz 0x401e78
      [-]0faf07ebf5
         // 00401e73: imul eax, ds:[edi]
         // 00401e76: jmp 0x401e6d
      [-]81f9????????7e05
         // 00401e7a: cmp ecx, 0x100
         // 00401e80: jle 0x401e87
      [-]b9????????
         // 00401e82: mov ecx, 0x100
      [-]8bf3f3a45f5b83c70481c3????????e85f4d0c0083c404588945f4837d14000f8463020000
         // 00401e87: mov esi, ebx
         // 00401e89: rep movsbb 
         // 00401e8b: pop edi
         // 00401e8c: pop ebx
         // 00401e8d: add edi, 0x4
         // 00401e90: add ebx, 0x100
         // 00401e96: call 0x4c6bfa
         // 00401e9b: add esp, 0x4
         // 00401e9e: pop eax
         // 00401e9f: mov ss:[ebp+0xfffffffffffffff4], eax
         // 00401ea2: cmp ss:[ebp+0x14], 0x0
         // 00401ea6: jz 0x40210f
      [-]837df4000f8454020000
         // 00401eac: cmp ss:[ebp+0xfffffffffffffff4], 0x0
         // 00401eb0: jz 0x40210a
      [-]8b5df883c324895df068????????6a008b5df0ff3368????????bb????????e8384d0c0083c4108945ec8b5d108b0350ff75ece84ff1ffff83c40883f800b8????????0f94c08945e88b5dec85db7409
         // 00401eb6: mov ebx, ss:[ebp+0xfffffffffffffff8]
         // 00401eb9: add ebx, 0x24
         // 00401ebc: mov ss:[ebp+0xfffffffffffffff0], ebx
         // 00401ebf: push 0xffffffffa0000101
         // 00401ec4: push 0x0
         // 00401ec6: mov ebx, ss:[ebp+0xfffffffffffffff0]
         // 00401ec9: push ds:[ebx]
         // 00401ecb: push 0x1
         // 00401ed0: mov ebx, 0x4c9550
         // 00401ed5: call 0x4c6c12
         // 00401eda: add esp, 0x10
         // 00401edd: mov ss:[ebp+0xffffffffffffffec], eax
         // 00401ee0: mov ebx, ss:[ebp+0x10]
         // 00401ee3: mov eax, ds:[ebx]
         // 00401ee5: push eax
         // 00401ee6: push ss:[ebp+0xffffffffffffffec]
         // 00401ee9: call 0x40103d
         // 00401eee: add esp, 0x8
         // 00401ef1: cmp eax, 0x0
         // 00401ef4: mov eax, 0x0
         // 00401ef9: setz b1 al
         // 00401efc: mov ss:[ebp+0xffffffffffffffe8], eax
         // 00401eff: mov ebx, ss:[ebp+0xffffffffffffffec]
         // 00401f02: test ebx, ebx
         // 00401f04: jz 0x401f0f
      [-]53e8ee4c0c0083c404
         // 00401f06: push ebx
         // 00401f07: call 0x4c6bfa
         // 00401f0c: add esp, 0x4
      [-]837de8000f847c000000
         // 00401f0f: cmp ss:[ebp+0xffffffffffffffe8], 0x0
         // 00401f13: jz 0x401f95
      [-]8b5df883c308895df0ff75086a04b8????????e8c34c0c0083c4088b5df08b038945ec8b5d088b1b895de8e8d4f0ffff894de48b7de8c707????????83c7048bc140890783c7043bfb7404
         // 00401f19: mov ebx, ss:[ebp+0xfffffffffffffff8]
         // 00401f1c: add ebx, 0x8
         // 00401f1f: mov ss:[ebp+0xfffffffffffffff0], ebx
         // 00401f22: push ss:[ebp+0x8]
         // 00401f25: push 0x4
         // 00401f27: mov eax, 0x2
         // 00401f2c: call 0x4c6bf4
         // 00401f31: add esp, 0x8
         // 00401f34: mov ebx, ss:[ebp+0xfffffffffffffff0]
         // 00401f37: mov eax, ds:[ebx]
         // 00401f39: mov ss:[ebp+0xffffffffffffffec], eax
         // 00401f3c: mov ebx, ss:[ebp+0x8]
         // 00401f3f: mov ebx, ds:[ebx]
         // 00401f41: mov ss:[ebp+0xffffffffffffffe8], ebx
         // 00401f44: call 0x40101d
         // 00401f49: mov ss:[ebp+0xffffffffffffffe4], ecx
         // 00401f4c: mov edi, ss:[ebp+0xffffffffffffffe8]
         // 00401f4f: mov ds:[edi], 0x1
         // 00401f55: add edi, 0x4
         // 00401f58: mov eax, ecx
         // 00401f5a: inc eax
         // 00401f5b: mov ds:[edi], eax
         // 00401f5d: add edi, 0x4
         // 00401f60: cmp edi, ebx
         // 00401f62: jz 0x401f68
      [-]8bf3f3a5
         // 00401f64: mov esi, ebx
         // 00401f66: rep movsdd 
      [-]8b45e440c1e00283c00850ff75e8e89d4c0c0083c4088b5d0889038bf883c7088b45e4c1e00203f88b45ec8907
         // 00401f68: mov eax, ss:[ebp+0xffffffffffffffe4]
         // 00401f6b: inc eax
         // 00401f6c: shl eax, b1 0x2
         // 00401f6f: add eax, 0x8
         // 00401f72: push eax
         // 00401f73: push ss:[ebp+0xffffffffffffffe8]
         // 00401f76: call 0x4c6c18
         // 00401f7b: add esp, 0x8
         // 00401f7e: mov ebx, ss:[ebp+0x8]
         // 00401f81: mov ds:[ebx], eax
         // 00401f83: mov edi, eax
         // 00401f85: add edi, 0x8
         // 00401f88: mov eax, ss:[ebp+0xffffffffffffffe4]
         // 00401f8b: shl eax, b1 0x2
         // 00401f8e: add edi, eax
         // 00401f90: mov eax, ss:[ebp+0xffffffffffffffec]
         // 00401f93: mov ds:[edi], eax
      [-]8965f08b45f85068????????e85a4c0c0083c4048bf85b50895de88945ec8b0383c304890783c7048b0383c304890783c7048b0383c304890783c7048b0383c304890783c7048b0383c304890783c7048b0383c304890783c7048b0383c304890783c7048b0383c304890783c7048b0383c304890783c704538b1b81c3????????b9????????8bf3f3a45b83c304ff75fcb8????????e8dc4b0c003965f07417
         // 00401f95: mov ss:[ebp+0xfffffffffffffff0], esp
         // 00401f98: mov eax, ss:[ebp+0xfffffffffffffff8]
         // 00401f9b: push eax
         // 00401f9c: push 0x124
         // 00401fa1: call 0x4c6c00
         // 00401fa6: add esp, 0x4
         // 00401fa9: mov edi, eax
         // 00401fab: pop ebx
         // 00401fac: push eax
         // 00401fad: mov ss:[ebp+0xffffffffffffffe8], ebx
         // 00401fb0: mov ss:[ebp+0xffffffffffffffec], eax
         // 00401fb3: mov eax, ds:[ebx]
         // 00401fb5: add ebx, 0x4
         // 00401fb8: mov ds:[edi], eax
         // 00401fba: add edi, 0x4
         // 00401fbd: mov eax, ds:[ebx]
         // 00401fbf: add ebx, 0x4
         // 00401fc2: mov ds:[edi], eax
         // 00401fc4: add edi, 0x4
         // 00401fc7: mov eax, ds:[ebx]
         // 00401fc9: add ebx, 0x4
         // 00401fcc: mov ds:[edi], eax
         // 00401fce: add edi, 0x4
         // 00401fd1: mov eax, ds:[ebx]
         // 00401fd3: add ebx, 0x4
         // 00401fd6: mov ds:[edi], eax
         // 00401fd8: add edi, 0x4
         // 00401fdb: mov eax, ds:[ebx]
         // 00401fdd: add ebx, 0x4
         // 00401fe0: mov ds:[edi], eax
         // 00401fe2: add edi, 0x4
         // 00401fe5: mov eax, ds:[ebx]
         // 00401fe7: add ebx, 0x4
         // 00401fea: mov ds:[edi], eax
         // 00401fec: add edi, 0x4
         // 00401fef: mov eax, ds:[ebx]
         // 00401ff1: add ebx, 0x4
         // 00401ff4: mov ds:[edi], eax
         // 00401ff6: add edi, 0x4
         // 00401ff9: mov eax, ds:[ebx]
         // 00401ffb: add ebx, 0x4
         // 00401ffe: mov ds:[edi], eax
         // 00402000: add edi, 0x4
         // 00402003: mov eax, ds:[ebx]
         // 00402005: add ebx, 0x4
         // 00402008: mov ds:[edi], eax
         // 0040200a: add edi, 0x4
         // 0040200d: push ebx
         // 0040200e: mov ebx, ds:[ebx]
         // 00402010: add ebx, 0x8
         // 00402016: mov ecx, 0x100
         // 0040201b: mov esi, ebx
         // 0040201d: rep movsbb 
         // 0040201f: pop ebx
         // 00402020: add ebx, 0x4
         // 00402023: push ss:[ebp+0xfffffffffffffffc]
         // 00402026: mov eax, 0x3
         // 0040202b: call 0x4c6c0c
         // 00402030: cmp ss:[ebp+0xfffffffffffffff0], esp
         // 00402033: jz 0x40204c
      [-]68????????68????????68????????e8bd4b0c0083c40c
         // 00402035: push 0x1db
         // 0040203a: push 0x408d1ca
         // 0040203f: push 0x6
         // 00402044: call 0x4c6c06
         // 00402049: add esp, 0xc
      [-]508b5dec538b7de88b0383c304890783c7048b0383c304890783c7048b0383c304890783c7048b0383c304890783c7048b0383c304890783c7048b0383c304890783c7048b0383c304890783c7048b0383c304890783c7048b0383c304890783c70453576a01b8????????e8384b0c0083c4045f5b53578b3f8b0f83c70485c9740f
         // 0040204c: push eax
         // 0040204d: mov ebx, ss:[ebp+0xffffffffffffffec]
         // 00402050: push ebx
         // 00402051: mov edi, ss:[ebp+0xffffffffffffffe8]
         // 00402054: mov eax, ds:[ebx]
         // 00402056: add ebx, 0x4
         // 00402059: mov ds:[edi], eax
         // 0040205b: add edi, 0x4
         // 0040205e: mov eax, ds:[ebx]
         // 00402060: add ebx, 0x4
         // 00402063: mov ds:[edi], eax
         // 00402065: add edi, 0x4
         // 00402068: mov eax, ds:[ebx]
         // 0040206a: add ebx, 0x4
         // 0040206d: mov ds:[edi], eax
         // 0040206f: add edi, 0x4
         // 00402072: mov eax, ds:[ebx]
         // 00402074: add ebx, 0x4
         // 00402077: mov ds:[edi], eax
         // 00402079: add edi, 0x4
         // 0040207c: mov eax, ds:[ebx]
         // 0040207e: add ebx, 0x4
         // 00402081: mov ds:[edi], eax
         // 00402083: add edi, 0x4
         // 00402086: mov eax, ds:[ebx]
         // 00402088: add ebx, 0x4
         // 0040208b: mov ds:[edi], eax
         // 0040208d: add edi, 0x4
         // 00402090: mov eax, ds:[ebx]
         // 00402092: add ebx, 0x4
         // 00402095: mov ds:[edi], eax
         // 00402097: add edi, 0x4
         // 0040209a: mov eax, ds:[ebx]
         // 0040209c: add ebx, 0x4
         // 0040209f: mov ds:[edi], eax
         // 004020a1: add edi, 0x4
         // 004020a4: mov eax, ds:[ebx]
         // 004020a6: add ebx, 0x4
         // 004020a9: mov ds:[edi], eax
         // 004020ab: add edi, 0x4
         // 004020ae: push ebx
         // 004020af: push edi
         // 004020b0: push 0x1
         // 004020b2: mov eax, 0x2
         // 004020b7: call 0x4c6bf4
         // 004020bc: add esp, 0x4
         // 004020bf: pop edi
         // 004020c0: pop ebx
         // 004020c1: push ebx
         // 004020c2: push edi
         // 004020c3: mov edi, ds:[edi]
         // 004020c5: mov ecx, ds:[edi]
         // 004020c7: add edi, 0x4
         // 004020ca: test ecx, ecx
         // 004020cc: jz 0x4020dd
      [-]83c704497405
         // 004020d0: add edi, 0x4
         // 004020d3: dec ecx
         // 004020d4: jz 0x4020db
      [-]0faf07ebf5
         // 004020d6: imul eax, ds:[edi]
         // 004020d9: jmp 0x4020d0
      [-]81f9????????7e05
         // 004020dd: cmp ecx, 0x100
         // 004020e3: jle 0x4020ea
      [-]b9????????
         // 004020e5: mov ecx, 0x100
      [-]8bf3f3a45f5b83c70481c3????????e8fc4a0c0083c404588945f4e9a2fdffff
         // 004020ea: mov esi, ebx
         // 004020ec: rep movsbb 
         // 004020ee: pop edi
         // 004020ef: pop ebx
         // 004020f0: add edi, 0x4
         // 004020f3: add ebx, 0x100
         // 004020f9: call 0x4c6bfa
         // 004020fe: add esp, 0x4
         // 00402101: pop eax
         // 00402102: mov ss:[ebp+0xfffffffffffffff4], eax
         // 00402105: jmp 0x401eac
      [-]e9d0020000
         // 0040210a: jmp 0x4023df
      [-]837df4000f84c6020000
         // 0040210f: cmp ss:[ebp+0xfffffffffffffff4], 0x0
         // 00402113: jz 0x4023df
      [-]8b5df883c324895df068????????6a008b5df0ff3368????????bb????????e8d54a0c0083c4108945ec68????????6a008b45ec85c07505
         // 00402119: mov ebx, ss:[ebp+0xfffffffffffffff8]
         // 0040211c: add ebx, 0x24
         // 0040211f: mov ss:[ebp+0xfffffffffffffff0], ebx
         // 00402122: push 0xffffffffa0000101
         // 00402127: push 0x0
         // 00402129: mov ebx, ss:[ebp+0xfffffffffffffff0]
         // 0040212c: push ds:[ebx]
         // 0040212e: push 0x1
         // 00402133: mov ebx, 0x4c9550
         // 00402138: call 0x4c6c12
         // 0040213d: add esp, 0x10
         // 00402140: mov ss:[ebp+0xffffffffffffffec], eax
         // 00402143: push 0xffffffff80000004
         // 00402148: push 0x0
         // 0040214a: mov eax, ss:[ebp+0xffffffffffffffec]
         // 0040214d: test eax, eax
         // 0040214f: jnz 0x402156
      [-]b8????????
         // 00402151: mov eax, 0x560d75
      [-]5068????????bb????????e8ac4a0c0083c4108945e88b5dec85db7409
         // 00402156: push eax
         // 00402157: push 0x1
         // 0040215c: mov ebx, 0x4c7c60
         // 00402161: call 0x4c6c12
         // 00402166: add esp, 0x10
         // 00402169: mov ss:[ebp+0xffffffffffffffe8], eax
         // 0040216c: mov ebx, ss:[ebp+0xffffffffffffffec]
         // 0040216f: test ebx, ebx
         // 00402171: jz 0x40217c
      [-]53e8814a0c0083c404
         // 00402173: push ebx
         // 00402174: call 0x4c6bfa
         // 00402179: add esp, 0x4
      [-]68????????6a008b5d108b0385c07505
         // 0040217c: push 0xffffffff80000004
         // 00402181: push 0x0
         // 00402183: mov ebx, ss:[ebp+0x10]
         // 00402186: mov eax, ds:[ebx]
         // 00402188: test eax, eax
         // 0040218a: jnz 0x402191
      [-]b8????????
         // 0040218c: mov eax, 0x560d75
      [-]5068????????bb????????e8714a0c0083c4108945e48b45e450ff75e8e88aeeffff83c40883f800b8????????0f94c08945e08b5de885db7409
         // 00402191: push eax
         // 00402192: push 0x1
         // 00402197: mov ebx, 0x4c7c60
         // 0040219c: call 0x4c6c12
         // 004021a1: add esp, 0x10
         // 004021a4: mov ss:[ebp+0xffffffffffffffe4], eax
         // 004021a7: mov eax, ss:[ebp+0xffffffffffffffe4]
         // 004021aa: push eax
         // 004021ab: push ss:[ebp+0xffffffffffffffe8]
         // 004021ae: call 0x40103d
         // 004021b3: add esp, 0x8
         // 004021b6: cmp eax, 0x0
         // 004021b9: mov eax, 0x0
         // 004021be: setz b1 al
         // 004021c1: mov ss:[ebp+0xffffffffffffffe0], eax
         // 004021c4: mov ebx, ss:[ebp+0xffffffffffffffe8]
         // 004021c7: test ebx, ebx
         // 004021c9: jz 0x4021d4
      [-]53e8294a0c0083c404
         // 004021cb: push ebx
         // 004021cc: call 0x4c6bfa
         // 004021d1: add esp, 0x4
      [-]8b5de485db7409
         // 004021d4: mov ebx, ss:[ebp+0xffffffffffffffe4]
         // 004021d7: test ebx, ebx
         // 004021d9: jz 0x4021e4
      [-]53e8194a0c0083c404
         // 004021db: push ebx
         // 004021dc: call 0x4c6bfa
         // 004021e1: add esp, 0x4
      [-]837de0000f847c000000
         // 004021e4: cmp ss:[ebp+0xffffffffffffffe0], 0x0
         // 004021e8: jz 0x40226a
      [-]8b5df883c308895df0ff75086a04b8????????e8ee490c0083c4088b5df08b038945ec8b5d088b1b895de8e8ffedffff894de48b7de8c707????????83c7048bc140890783c7043bfb7404
         // 004021ee: mov ebx, ss:[ebp+0xfffffffffffffff8]
         // 004021f1: add ebx, 0x8
         // 004021f4: mov ss:[ebp+0xfffffffffffffff0], ebx
         // 004021f7: push ss:[ebp+0x8]
         // 004021fa: push 0x4
         // 004021fc: mov eax, 0x2
         // 00402201: call 0x4c6bf4
         // 00402206: add esp, 0x8
         // 00402209: mov ebx, ss:[ebp+0xfffffffffffffff0]
         // 0040220c: mov eax, ds:[ebx]
         // 0040220e: mov ss:[ebp+0xffffffffffffffec], eax
         // 00402211: mov ebx, ss:[ebp+0x8]
         // 00402214: mov ebx, ds:[ebx]
         // 00402216: mov ss:[ebp+0xffffffffffffffe8], ebx
         // 00402219: call 0x40101d
         // 0040221e: mov ss:[ebp+0xffffffffffffffe4], ecx
         // 00402221: mov edi, ss:[ebp+0xffffffffffffffe8]
         // 00402224: mov ds:[edi], 0x1
         // 0040222a: add edi, 0x4
         // 0040222d: mov eax, ecx
         // 0040222f: inc eax
         // 00402230: mov ds:[edi], eax
         // 00402232: add edi, 0x4
         // 00402235: cmp edi, ebx
         // 00402237: jz 0x40223d
      [-]8bf3f3a5
         // 00402239: mov esi, ebx
         // 0040223b: rep movsdd 
      [-]8b45e440c1e00283c00850ff75e8e8c8490c0083c4088b5d0889038bf883c7088b45e4c1e00203f88b45ec8907
         // 0040223d: mov eax, ss:[ebp+0xffffffffffffffe4]
         // 00402240: inc eax
         // 00402241: shl eax, b1 0x2
         // 00402244: add eax, 0x8
         // 00402247: push eax
         // 00402248: push ss:[ebp+0xffffffffffffffe8]
         // 0040224b: call 0x4c6c18
         // 00402250: add esp, 0x8
         // 00402253: mov ebx, ss:[ebp+0x8]
         // 00402256: mov ds:[ebx], eax
         // 00402258: mov edi, eax
         // 0040225a: add edi, 0x8
         // 0040225d: mov eax, ss:[ebp+0xffffffffffffffe4]
         // 00402260: shl eax, b1 0x2
         // 00402263: add edi, eax
         // 00402265: mov eax, ss:[ebp+0xffffffffffffffec]
         // 00402268: mov ds:[edi], eax
      [-]8965f08b45f85068????????e885490c0083c4048bf85b50895de88945ec8b0383c304890783c7048b0383c304890783c7048b0383c304890783c7048b0383c304890783c7048b0383c304890783c7048b0383c304890783c7048b03
         // 0040226a: mov ss:[ebp+0xfffffffffffffff0], esp
         // 0040226d: mov eax, ss:[ebp+0xfffffffffffffff8]
         // 00402270: push eax
         // 00402271: push 0x124
         // 00402276: call 0x4c6c00
         // 0040227b: add esp, 0x4
         // 0040227e: mov edi, eax
         // 00402280: pop ebx
         // 00402281: push eax
         // 00402282: mov ss:[ebp+0xffffffffffffffe8], ebx
         // 00402285: mov ss:[ebp+0xffffffffffffffec], eax
         // 00402288: mov eax, ds:[ebx]
         // 0040228a: add ebx, 0x4
         // 0040228d: mov ds:[edi], eax
         // 0040228f: add edi, 0x4
         // 00402292: mov eax, ds:[ebx]
         // 00402294: add ebx, 0x4
         // 00402297: mov ds:[edi], eax
         // 00402299: add edi, 0x4
         // 0040229c: mov eax, ds:[ebx]
         // 0040229e: add ebx, 0x4
         // 004022a1: mov ds:[edi], eax
         // 004022a3: add edi, 0x4
         // 004022a6: mov eax, ds:[ebx]
         // 004022a8: add ebx, 0x4
         // 004022ab: mov ds:[edi], eax
         // 004022ad: add edi, 0x4
         // 004022b0: mov eax, ds:[ebx]
         // 004022b2: add ebx, 0x4
         // 004022b5: mov ds:[edi], eax
         // 004022b7: add edi, 0x4
         // 004022ba: mov eax, ds:[ebx]
         // 004022bc: add ebx, 0x4
         // 004022bf: mov ds:[edi], eax
         // 004022c1: add edi, 0x4
         // 004022c4: mov eax, ds:[ebx]
         // 004022c6: add ebx, 0x4
         // 004022c9: mov ds:[edi], eax
         // 004022cb: add edi, 0x4
         // 004022ce: mov eax, ds:[ebx]
         // 004022d0: add ebx, 0x4
         // 004022d3: mov ds:[edi], eax
         // 004022d5: add edi, 0x4
         // 004022d8: mov eax, ds:[ebx]
         // 004022da: add ebx, 0x4
         // 004022dd: mov ds:[edi], eax
         // 004022df: add edi, 0x4
         // 004022e2: push ebx
         // 004022e3: mov ebx, ds:[ebx]
         // 004022e5: add ebx, 0x8
         // 004022eb: mov ecx, 0x100
         // 004022f0: mov esi, ebx
         // 004022f2: rep movsbb 
         // 004022f4: pop ebx
         // 004022f5: add ebx, 0x4
         // 004022f8: push ss:[ebp+0xfffffffffffffffc]
         // 004022fb: mov eax, 0x3
         // 00402300: call 0x4c6c0c
         // 00402305: cmp ss:[ebp+0xfffffffffffffff0], esp
         // 00402308: jz 0x402321

  }
  condition:
    all of them
}
