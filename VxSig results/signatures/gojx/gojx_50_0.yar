rule gojx_50_0 {
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
      [-]ff75fce8fc6f0d0083c4048bf8588d1c24578d5508
         // 00401175: push ss:[ebp+0xfffffffffffffffc]
         // 00401178: call 0x4d8179
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
      [-]558bec81ec????????68????????e8c56f0d0083c4048945fc8bf8be????????adabadabc745f8????????c745f4????????c745f0????????c745ec????????c745e8????????68????????6a008d45fc5068????????bb????????e8896f0d0083c4108b5dfce8f7fdffff8945e0837de0000f8507000000
         // 004011a1: push ebp
         // 004011a2: mov ebp, esp
         // 004011a4: sub esp, 0x30
         // 004011aa: push 0x8
         // 004011af: call 0x4d8179
         // 004011b4: add esp, 0x4
         // 004011b7: mov ss:[ebp+0xfffffffffffffffc], eax
         // 004011ba: mov edi, eax
         // 004011bc: mov esi, 0x58d351
         // 004011c1: lodsdd 
         // 004011c2: stosdd 
         // 004011c3: lodsdd 
         // 004011c4: stosdd 
         // 004011c5: mov ss:[ebp+0xfffffffffffffff8], 0x0
         // 004011cc: mov ss:[ebp+0xfffffffffffffff4], 0x0
         // 004011d3: mov ss:[ebp+0xfffffffffffffff0], 0x0
         // 004011da: mov ss:[ebp+0xffffffffffffffec], 0x0
         // 004011e1: mov ss:[ebp+0xffffffffffffffe8], 0x0
         // 004011e8: push 0xffffffff80000004
         // 004011ed: push 0x0
         // 004011ef: lea eax, ss:[ebp+0xfffffffffffffffc]
         // 004011f2: push eax
         // 004011f3: push 0x1
         // 004011f8: mov ebx, 0x4d8b20
         // 004011fd: call 0x4d818b
         // 00401202: add esp, 0x10
         // 00401205: mov ebx, ss:[ebp+0xfffffffffffffffc]
         // 00401208: call 0x401004
         // 0040120d: mov ss:[ebp+0xffffffffffffffe0], eax
         // 00401210: cmp ss:[ebp+0xffffffffffffffe0], 0x0
         // 00401214: jnz 0x401221
      [-]b8????????eb05
         // 0040121a: mov eax, 0x1
         // 0040121f: jmp 0x401226
      [-]b8????????
         // 00401221: mov eax, 0x0
      [-]85c00f840f000000
         // 00401226: test eax, eax
         // 00401228: jz 0x40123d
      [-]e83a0600006a00e86f6f0d0083c404
         // 0040122e: call 0x40186d
         // 00401233: push 0x0
         // 00401235: call 0x4d81a9
         // 0040123a: add esp, 0x4
      [-]8b5dfce8bffdffff8945e0837de0020f8552000000
         // 0040123d: mov ebx, ss:[ebp+0xfffffffffffffffc]
         // 00401240: call 0x401004
         // 00401245: mov ss:[ebp+0xffffffffffffffe0], eax
         // 00401248: cmp ss:[ebp+0xffffffffffffffe0], 0x2
         // 0040124c: jnz 0x4012a4
      [-]8b5dfce8c3fdffffb8????????3bc17c17
         // 00401252: mov ebx, ss:[ebp+0xfffffffffffffffc]
         // 00401255: call 0x40101d
         // 0040125a: mov eax, 0x0
         // 0040125f: cmp eax, ecx
         // 00401261: jl 0x40127a
      [-]68????????68????????68????????e8086f0d0083c40c
         // 00401263: push 0x121
         // 00401268: push 0x4010001
         // 0040126d: push 0x1
         // 00401272: call 0x4d817f
         // 00401277: add esp, 0xc
      [-]c1e00203d8895dd868????????8b5dd8ff33e8acfdffff83c40883f8000f8507000000
         // 0040127a: shl eax, b1 0x2
         // 0040127d: add ebx, eax
         // 0040127f: mov ss:[ebp+0xffffffffffffffd8], ebx
         // 00401282: push 0x58d314
         // 00401287: mov ebx, ss:[ebp+0xffffffffffffffd8]
         // 0040128a: push ds:[ebx]
         // 0040128c: call 0x40103d
         // 00401291: add esp, 0x8
         // 00401294: cmp eax, 0x0
         // 00401297: jnz 0x4012a4
      [-]b8????????eb05
         // 0040129d: mov eax, 0x1
         // 004012a2: jmp 0x4012a9
      [-]b8????????
         // 004012a4: mov eax, 0x0
      [-]85c00f84ec020000
         // 004012a9: test eax, eax
         // 004012ab: jz 0x40159d
      [-]68????????bb????????e8cb6e0d0083c4048945e468????????bb????????e8b66e0d0083c4048945e0ff75e068????????ff75e4b9????????e855feffff83c40c8945dc8b5de485db7409
         // 004012b1: push 0x0
         // 004012b6: mov ebx, 0x4d8840
         // 004012bb: call 0x4d818b
         // 004012c0: add esp, 0x4
         // 004012c3: mov ss:[ebp+0xffffffffffffffe4], eax
         // 004012c6: push 0x0
         // 004012cb: mov ebx, 0x4d8860
         // 004012d0: call 0x4d818b
         // 004012d5: add esp, 0x4
         // 004012d8: mov ss:[ebp+0xffffffffffffffe0], eax
         // 004012db: push ss:[ebp+0xffffffffffffffe0]
         // 004012de: push 0x58d31b
         // 004012e3: push ss:[ebp+0xffffffffffffffe4]
         // 004012e6: mov ecx, 0x3
         // 004012eb: call 0x401145
         // 004012f0: add esp, 0xc
         // 004012f3: mov ss:[ebp+0xffffffffffffffdc], eax
         // 004012f6: mov ebx, ss:[ebp+0xffffffffffffffe4]
         // 004012f9: test ebx, ebx
         // 004012fb: jz 0x401306
      [-]53e8706e0d0083c404
         // 004012fd: push ebx
         // 004012fe: call 0x4d8173
         // 00401303: add esp, 0x4
      [-]8b5de085db7409
         // 00401306: mov ebx, ss:[ebp+0xffffffffffffffe0]
         // 00401309: test ebx, ebx
         // 0040130b: jz 0x401316
      [-]53e8606e0d0083c404
         // 0040130d: push ebx
         // 0040130e: call 0x4d8173
         // 00401313: add esp, 0x4
      [-]68????????6a008b45dc85c07505
         // 00401316: push 0xffffffff80000004
         // 0040131b: push 0x0
         // 0040131d: mov eax, ss:[ebp+0xffffffffffffffdc]
         // 00401320: test eax, eax
         // 00401322: jnz 0x401329
      [-]b8????????
         // 00401324: mov eax, 0x58d31d
      [-]5068????????bb????????e8526e0d0083c4108945d88b5ddc85db7409
         // 00401329: push eax
         // 0040132a: push 0x1
         // 0040132f: mov ebx, 0x4daec0
         // 00401334: call 0x4d818b
         // 00401339: add esp, 0x10
         // 0040133c: mov ss:[ebp+0xffffffffffffffd8], eax
         // 0040133f: mov ebx, ss:[ebp+0xffffffffffffffdc]
         // 00401342: test ebx, ebx
         // 00401344: jz 0x40134f
      [-]53e8276e0d0083c404
         // 00401346: push ebx
         // 00401347: call 0x4d8173
         // 0040134c: add esp, 0x4
      [-]8b45d8508b5df885db7409
         // 0040134f: mov eax, ss:[ebp+0xffffffffffffffd8]
         // 00401352: push eax
         // 00401353: mov ebx, ss:[ebp+0xfffffffffffffff8]
         // 00401356: test ebx, ebx
         // 00401358: jz 0x401363
      [-]53e8136e0d0083c404
         // 0040135a: push ebx
         // 0040135b: call 0x4d8173
         // 00401360: add esp, 0x4
      [-]588945f8b8????????508b5df485db7409
         // 00401363: pop eax
         // 00401364: mov ss:[ebp+0xfffffffffffffff8], eax
         // 00401367: mov eax, 0x58d31e
         // 0040136c: push eax
         // 0040136d: mov ebx, ss:[ebp+0xfffffffffffffff4]
         // 00401370: test ebx, ebx
         // 00401372: jz 0x40137d
      [-]53e8f96d0d0083c404
         // 00401374: push ebx
         // 00401375: call 0x4d8173
         // 0040137a: add esp, 0x4
      [-]588945f4c745e4????????6a00ff75e4c745e0????????6a00ff75e08d45f850e81f2100008945dcc745d8????????6a00ff75d868????????e8001800008945d468????????ff75d4ff75dc68????????b9????????e86dfdffff83c4108945d08b5ddc85db7409
         // 0040137d: pop eax
         // 0040137e: mov ss:[ebp+0xfffffffffffffff4], eax
         // 00401381: mov ss:[ebp+0xffffffffffffffe4], 0x0
         // 00401388: push 0x0
         // 0040138a: push ss:[ebp+0xffffffffffffffe4]
         // 0040138d: mov ss:[ebp+0xffffffffffffffe0], 0x0
         // 00401394: push 0x0
         // 00401396: push ss:[ebp+0xffffffffffffffe0]
         // 00401399: lea eax, ss:[ebp+0xfffffffffffffff8]
         // 0040139c: push eax
         // 0040139d: call 0x4034c1
         // 004013a2: mov ss:[ebp+0xffffffffffffffdc], eax
         // 004013a5: mov ss:[ebp+0xffffffffffffffd8], 0x0
         // 004013ac: push 0x0
         // 004013ae: push ss:[ebp+0xffffffffffffffd8]
         // 004013b1: push 0xc
         // 004013b6: call 0x402bbb
         // 004013bb: mov ss:[ebp+0xffffffffffffffd4], eax
         // 004013be: push 0x58d34d
         // 004013c3: push ss:[ebp+0xffffffffffffffd4]
         // 004013c6: push ss:[ebp+0xffffffffffffffdc]
         // 004013c9: push 0x58d34f
         // 004013ce: mov ecx, 0x4
         // 004013d3: call 0x401145
         // 004013d8: add esp, 0x10
         // 004013db: mov ss:[ebp+0xffffffffffffffd0], eax
         // 004013de: mov ebx, ss:[ebp+0xffffffffffffffdc]
         // 004013e1: test ebx, ebx
         // 004013e3: jz 0x4013ee
      [-]53e8886d0d0083c404
         // 004013e5: push ebx
         // 004013e6: call 0x4d8173
         // 004013eb: add esp, 0x4
      [-]8b5dd485db7409
         // 004013ee: mov ebx, ss:[ebp+0xffffffffffffffd4]
         // 004013f1: test ebx, ebx
         // 004013f3: jz 0x4013fe
      [-]53e8786d0d0083c404
         // 004013f5: push ebx
         // 004013f6: call 0x4d8173
         // 004013fb: add esp, 0x4
      [-]8b45d0508b5df085db7409
         // 004013fe: mov eax, ss:[ebp+0xffffffffffffffd0]
         // 00401401: push eax
         // 00401402: mov ebx, ss:[ebp+0xfffffffffffffff0]
         // 00401405: test ebx, ebx
         // 00401407: jz 0x401412
      [-]53e8646d0d0083c404
         // 00401409: push ebx
         // 0040140a: call 0x4d8173
         // 0040140f: add esp, 0x4
      [-]588945f068????????6a008b45f485c07505
         // 00401412: pop eax
         // 00401413: mov ss:[ebp+0xfffffffffffffff0], eax
         // 00401416: push 0xffffffff80000004
         // 0040141b: push 0x0
         // 0040141d: mov eax, ss:[ebp+0xfffffffffffffff4]
         // 00401420: test eax, eax
         // 00401422: jnz 0x401429
      [-]b8????????
         // 00401424: mov eax, 0x58d31d
      [-]5068????????bb????????e8526d0d0083c4108945e468????????6a008b45f085c07505
         // 00401429: push eax
         // 0040142a: push 0x1
         // 0040142f: mov ebx, 0x4d9ec0
         // 00401434: call 0x4d818b
         // 00401439: add esp, 0x10
         // 0040143c: mov ss:[ebp+0xffffffffffffffe4], eax
         // 0040143f: push 0xffffffff80000004
         // 00401444: push 0x0
         // 00401446: mov eax, ss:[ebp+0xfffffffffffffff0]
         // 00401449: test eax, eax
         // 0040144b: jnz 0x401452
      [-]b8????????
         // 0040144d: mov eax, 0x58d31d
      [-]5068????????bb????????e8296d0d0083c4108945e0c745dc????????6a00ff75dcc745d8????????6a00ff75d86a018d45e0508d45e4508d45f850e83f2a00008945d48b5de485db7409
         // 00401452: push eax
         // 00401453: push 0x1
         // 00401458: mov ebx, 0x4d9ec0
         // 0040145d: call 0x4d818b
         // 00401462: add esp, 0x10
         // 00401465: mov ss:[ebp+0xffffffffffffffe0], eax
         // 00401468: mov ss:[ebp+0xffffffffffffffdc], 0x0
         // 0040146f: push 0x0
         // 00401471: push ss:[ebp+0xffffffffffffffdc]
         // 00401474: mov ss:[ebp+0xffffffffffffffd8], 0x0
         // 0040147b: push 0x0
         // 0040147d: push ss:[ebp+0xffffffffffffffd8]
         // 00401480: push 0x1
         // 00401482: lea eax, ss:[ebp+0xffffffffffffffe0]
         // 00401485: push eax
         // 00401486: lea eax, ss:[ebp+0xffffffffffffffe4]
         // 00401489: push eax
         // 0040148a: lea eax, ss:[ebp+0xfffffffffffffff8]
         // 0040148d: push eax
         // 0040148e: call 0x403ed2
         // 00401493: mov ss:[ebp+0xffffffffffffffd4], eax
         // 00401496: mov ebx, ss:[ebp+0xffffffffffffffe4]
         // 00401499: test ebx, ebx
         // 0040149b: jz 0x4014a6
      [-]53e8d06c0d0083c404
         // 0040149d: push ebx
         // 0040149e: call 0x4d8173
         // 004014a3: add esp, 0x4
      [-]8b5de085db7409
         // 004014a6: mov ebx, ss:[ebp+0xffffffffffffffe0]
         // 004014a9: test ebx, ebx
         // 004014ab: jz 0x4014b6
      [-]53e8c06c0d0083c404
         // 004014ad: push ebx
         // 004014ae: call 0x4d8173
         // 004014b3: add esp, 0x4
      [-]8b45d4508b5df885db7409
         // 004014b6: mov eax, ss:[ebp+0xffffffffffffffd4]
         // 004014b9: push eax
         // 004014ba: mov ebx, ss:[ebp+0xfffffffffffffff8]
         // 004014bd: test ebx, ebx
         // 004014bf: jz 0x4014ca
      [-]53e8ac6c0d0083c404
         // 004014c1: push ebx
         // 004014c2: call 0x4d8173
         // 004014c7: add esp, 0x4
      [-]588945f868????????bb????????e8ae6c0d0083c4048945e48b5dfce832fbffffb8????????3bc17c17
         // 004014ca: pop eax
         // 004014cb: mov ss:[ebp+0xfffffffffffffff8], eax
         // 004014ce: push 0x0
         // 004014d3: mov ebx, 0x4d8840
         // 004014d8: call 0x4d818b
         // 004014dd: add esp, 0x4
         // 004014e0: mov ss:[ebp+0xffffffffffffffe4], eax
         // 004014e3: mov ebx, ss:[ebp+0xfffffffffffffffc]
         // 004014e6: call 0x40101d
         // 004014eb: mov eax, 0x1
         // 004014f0: cmp eax, ecx
         // 004014f2: jl 0x40150b
      [-]68????????68????????68????????e8776c0d0083c40c
         // 004014f4: push 0x32b
         // 004014f9: push 0x4010001
         // 004014fe: push 0x1
         // 00401503: call 0x4d817f
         // 00401508: add esp, 0xc
      [-]c1e00203d8895de08b5de0ff3368????????ff75e4b9????????e81bfcffff83c40c8945dc8b5de485db7409
         // 0040150b: shl eax, b1 0x2
         // 0040150e: add ebx, eax
         // 00401510: mov ss:[ebp+0xffffffffffffffe0], ebx
         // 00401513: mov ebx, ss:[ebp+0xffffffffffffffe0]
         // 00401516: push ds:[ebx]
         // 00401518: push 0x58d31b
         // 0040151d: push ss:[ebp+0xffffffffffffffe4]
         // 00401520: mov ecx, 0x3
         // 00401525: call 0x401145
         // 0040152a: add esp, 0xc
         // 0040152d: mov ss:[ebp+0xffffffffffffffdc], eax
         // 00401530: mov ebx, ss:[ebp+0xffffffffffffffe4]
         // 00401533: test ebx, ebx
         // 00401535: jz 0x401540
      [-]53e8366c0d0083c404
         // 00401537: push ebx
         // 00401538: call 0x4d8173
         // 0040153d: add esp, 0x4
      [-]68????????6a008b45f885c07505
         // 00401540: push 0xffffffff80000005
         // 00401545: push 0x0
         // 00401547: mov eax, ss:[ebp+0xfffffffffffffff8]
         // 0040154a: test eax, eax
         // 0040154c: jnz 0x401553
      [-]b8????????
         // 0040154e: mov eax, 0x58d351
      [-]5068????????6a008b45dc85c07505
         // 00401553: push eax
         // 00401554: push 0xffffffff80000004
         // 00401559: push 0x0
         // 0040155b: mov eax, ss:[ebp+0xffffffffffffffdc]
         // 0040155e: test eax, eax
         // 00401560: jnz 0x401567
      [-]b8????????
         // 00401562: mov eax, 0x58d31d
      [-]5068????????bb????????e8146c0d0083c41c8945d88b5ddc85db7409
         // 00401567: push eax
         // 00401568: push 0x2
         // 0040156d: mov ebx, 0x4daf30
         // 00401572: call 0x4d818b
         // 00401577: add esp, 0x1c
         // 0040157a: mov ss:[ebp+0xffffffffffffffd8], eax
         // 0040157d: mov ebx, ss:[ebp+0xffffffffffffffdc]
         // 00401580: test ebx, ebx
         // 00401582: jz 0x40158d
      [-]53e8e96b0d0083c404
         // 00401584: push ebx
         // 00401585: call 0x4d8173
         // 0040158a: add esp, 0x4
      [-]8b45d88945ec6a00e80f6c0d0083c404
         // 0040158d: mov eax, ss:[ebp+0xffffffffffffffd8]
         // 00401590: mov ss:[ebp+0xffffffffffffffec], eax
         // 00401593: push 0x0
         // 00401595: call 0x4d81a9
         // 0040159a: add esp, 0x4
      [-]c745e4????????6a00ff75e468????????e8081600008945e068????????ff75e0b9????????e87dfbffff83c4088945dc8b5de085db7409
         // 0040159d: mov ss:[ebp+0xffffffffffffffe4], 0x0
         // 004015a4: push 0x0
         // 004015a6: push ss:[ebp+0xffffffffffffffe4]
         // 004015a9: push 0x8
         // 004015ae: call 0x402bbb
         // 004015b3: mov ss:[ebp+0xffffffffffffffe0], eax
         // 004015b6: push 0x58d359
         // 004015bb: push ss:[ebp+0xffffffffffffffe0]
         // 004015be: mov ecx, 0x2
         // 004015c3: call 0x401145
         // 004015c8: add esp, 0x8
         // 004015cb: mov ss:[ebp+0xffffffffffffffdc], eax
         // 004015ce: mov ebx, ss:[ebp+0xffffffffffffffe0]
         // 004015d1: test ebx, ebx
         // 004015d3: jz 0x4015de
      [-]53e8986b0d0083c404
         // 004015d5: push ebx
         // 004015d6: call 0x4d8173
         // 004015db: add esp, 0x4
      [-]8b45dc508b1d????????85db7409
         // 004015de: mov eax, ss:[ebp+0xffffffffffffffdc]
         // 004015e1: push eax
         // 004015e2: mov ebx, ds:[0x5e70a0]
         // 004015e8: test ebx, ebx
         // 004015ea: jz 0x4015f5
      [-]53e8816b0d0083c404
         // 004015ec: push ebx
         // 004015ed: call 0x4d8173
         // 004015f2: add esp, 0x4
      [-]58a3????????e88732000085c00f8447000000
         // 004015f5: pop eax
         // 004015f6: mov ds:[0x5e70a0], eax
         // 004015fb: call 0x404887
         // 00401600: test eax, eax
         // 00401602: jz 0x40164f
      [-]8965e468????????68????????68????????68????????b8????????e85c6b0d003965e47417
         // 00401608: mov ss:[ebp+0xffffffffffffffe4], esp
         // 0040160b: push 0x10
         // 00401610: push 0x58d35e
         // 00401615: push 0x58d363
         // 0040161a: push 0x0
         // 0040161f: mov eax, 0x0
         // 00401624: call 0x4d8185
         // 00401629: cmp ss:[ebp+0xffffffffffffffe4], esp
         // 0040162c: jz 0x401645
      [-]68????????68????????68????????e83d6b0d0083c40c
         // 0040162e: push 0x423
         // 00401633: push 0x4010001
         // 00401638: push 0x6
         // 0040163d: call 0x4d817f
         // 00401642: add esp, 0xc
      [-]b8????????e993010000
         // 00401645: mov eax, 0x0
         // 0040164a: jmp 0x4017e2
      [-]e8fb3300008945e0837de0000f8547000000
         // 0040164f: call 0x404a4f
         // 00401654: mov ss:[ebp+0xffffffffffffffe0], eax
         // 00401657: cmp ss:[ebp+0xffffffffffffffe0], 0x0
         // 0040165b: jnz 0x4016a8
      [-]8965e468????????68????????68????????68????????b8????????e8036b0d003965e47417
         // 00401661: mov ss:[ebp+0xffffffffffffffe4], esp
         // 00401664: push 0x0
         // 00401669: push 0x58d35e
         // 0040166e: push 0x58d37f
         // 00401673: push 0x0
         // 00401678: mov eax, 0x0
         // 0040167d: call 0x4d8185
         // 00401682: cmp ss:[ebp+0xffffffffffffffe4], esp
         // 00401685: jz 0x40169e
      [-]68????????68????????68????????e8e46a0d0083c40c
         // 00401687: push 0x4ce
         // 0040168c: push 0x4010001
         // 00401691: push 0x6
         // 00401696: call 0x4d817f
         // 0040169b: add esp, 0xc
      [-]b8????????e93a010000
         // 0040169e: mov eax, 0x0
         // 004016a3: jmp 0x4017e2
      [-]e8cd34000068????????bb????????e8cf6a0d0083c4048945e468????????ff75e4b9????????e871faffff83c4088945e08b5de485db7409
         // 004016a8: call 0x404b7a
         // 004016ad: push 0x0
         // 004016b2: mov ebx, 0x4d8840
         // 004016b7: call 0x4d818b
         // 004016bc: add esp, 0x4
         // 004016bf: mov ss:[ebp+0xffffffffffffffe4], eax
         // 004016c2: push 0x58d389
         // 004016c7: push ss:[ebp+0xffffffffffffffe4]
         // 004016ca: mov ecx, 0x2
         // 004016cf: call 0x401145
         // 004016d4: add esp, 0x8
         // 004016d7: mov ss:[ebp+0xffffffffffffffe0], eax
         // 004016da: mov ebx, ss:[ebp+0xffffffffffffffe4]
         // 004016dd: test ebx, ebx
         // 004016df: jz 0x4016ea
      [-]53e88c6a0d0083c404
         // 004016e1: push ebx
         // 004016e2: call 0x4d8173
         // 004016e7: add esp, 0x4
      [-]6a006a006a0068????????6a0068????????68????????6a0068????????68????????6a008b45e085c07505
         // 004016ea: push 0x0
         // 004016ec: push 0x0
         // 004016ee: push 0x0
         // 004016f0: push 0xffffffff80000004
         // 004016f5: push 0x0
         // 004016f7: push 0x58d399
         // 004016fc: push 0xffffffff80000004
         // 00401701: push 0x0
         // 00401703: push 0x58d39e
         // 00401708: push 0xffffffff80000004
         // 0040170d: push 0x0
         // 0040170f: mov eax, ss:[ebp+0xffffffffffffffe0]
         // 00401712: test eax, eax
         // 00401714: jnz 0x40171b
      [-]b8????????
         // 00401716: mov eax, 0x58d31d
      [-]5068????????bb????????e8606a0d0083c4348945dc8b5de085db7409
         // 0040171b: push eax
         // 0040171c: push 0x4
         // 00401721: mov ebx, 0x4dc450
         // 00401726: call 0x4d818b
         // 0040172b: add esp, 0x34
         // 0040172e: mov ss:[ebp+0xffffffffffffffdc], eax
         // 00401731: mov ebx, ss:[ebp+0xffffffffffffffe0]
         // 00401734: test ebx, ebx
         // 00401736: jz 0x401741
      [-]53e8356a0d0083c404
         // 00401738: push ebx
         // 00401739: call 0x4d8173
         // 0040173e: add esp, 0x4
      [-]8b45dc508b5de885db7409
         // 00401741: mov eax, ss:[ebp+0xffffffffffffffdc]
         // 00401744: push eax
         // 00401745: mov ebx, ss:[ebp+0xffffffffffffffe8]
         // 00401748: test ebx, ebx
         // 0040174a: jz 0x401755
      [-]53e8216a0d0083c404
         // 0040174c: push ebx
         // 0040174d: call 0x4d8173
         // 00401752: add esp, 0x4
      [-]588945e868????????ff75e8e8d7f8ffff83c40883f8000f8433000000
         // 00401755: pop eax
         // 00401756: mov ss:[ebp+0xffffffffffffffe8], eax
         // 00401759: push 0x58d3a3
         // 0040175e: push ss:[ebp+0xffffffffffffffe8]
         // 00401761: call 0x40103d
         // 00401766: add esp, 0x8
         // 00401769: cmp eax, 0x0
         // 0040176c: jz 0x4017a5
      [-]68????????6a0068????????6a006a006a0068????????68????????68????????68????????bb????????e8e9690d0083c428
         // 00401772: push 0xffffffff80000002
         // 00401777: push 0x0
         // 00401779: push 0x1
         // 0040177e: push 0x0
         // 00401780: push 0x0
         // 00401782: push 0x0
         // 00401784: push 0x10001
         // 00401789: push 0x608af62
         // 0040178e: push 0x5208af63
         // 00401793: push 0x3
         // 00401798: mov ebx, 0x4d8790
         // 0040179d: call 0x4d818b
         // 004017a2: add esp, 0x28
      [-]68????????6a0068????????6a006a006a0068????????68????????68????????68????????bb????????e8b6690d0083c428b8????????e900000000
         // 004017a5: push 0xffffffff80000002
         // 004017aa: push 0x0
         // 004017ac: push 0x0
         // 004017b1: push 0x0
         // 004017b3: push 0x0
         // 004017b5: push 0x0
         // 004017b7: push 0x10001
         // 004017bc: push 0x607d595
         // 004017c1: push 0x5207d594
         // 004017c6: push 0x3
         // 004017cb: mov ebx, 0x4d8790
         // 004017d0: call 0x4d818b
         // 004017d5: add esp, 0x28
         // 004017d8: mov eax, 0x0
         // 004017dd: jmp 0x4017e2
      [-]508b5dfc538b0b83c30485c97411
         // 004017e2: push eax
         // 004017e3: mov ebx, ss:[ebp+0xfffffffffffffffc]
         // 004017e6: push ebx
         // 004017e7: mov ecx, ds:[ebx]
         // 004017e9: add ebx, 0x4
         // 004017ec: test ecx, ecx
         // 004017ee: jz 0x401801
      [-]83c304497405
         // 004017f2: add ebx, 0x4
         // 004017f5: dec ecx
         // 004017f6: jz 0x4017fd
      [-]0faf03ebf5
         // 004017f8: imul eax, ds:[ebx]
         // 004017fb: jmp 0x4017f2
      [-]8bc885c9
         // 004017fd: mov ecx, eax
         // 004017ff: test ecx, ecx
      [-]0f8419000000
         // 00401801: jz 0x401820
      [-]518b0385c0740b
         // 00401807: push ecx
         // 00401808: mov eax, ds:[ebx]
         // 0040180a: test eax, eax
         // 0040180c: jz 0x401819
      [-]5350e85e690d0083c4045b
         // 0040180e: push ebx
         // 0040180f: push eax
         // 00401810: call 0x4d8173
         // 00401815: add esp, 0x4
         // 00401818: pop ebx
      [-]83c304594975e7
         // 00401819: add ebx, 0x4
         // 0040181c: pop ecx
         // 0040181d: dec ecx
         // 0040181e: jnz 0x401807
      [-]e84e690d0083c4048b5df885db7409
         // 00401820: call 0x4d8173
         // 00401825: add esp, 0x4
         // 00401828: mov ebx, ss:[ebp+0xfffffffffffffff8]
         // 0040182b: test ebx, ebx
         // 0040182d: jz 0x401838
      [-]53e83e690d0083c404
         // 0040182f: push ebx
         // 00401830: call 0x4d8173
         // 00401835: add esp, 0x4
      [-]8b5df485db7409
         // 00401838: mov ebx, ss:[ebp+0xfffffffffffffff4]
         // 0040183b: test ebx, ebx
         // 0040183d: jz 0x401848
      [-]53e82e690d0083c404
         // 0040183f: push ebx
         // 00401840: call 0x4d8173
         // 00401845: add esp, 0x4
      [-]8b5df085db7409
         // 00401848: mov ebx, ss:[ebp+0xfffffffffffffff0]
         // 0040184b: test ebx, ebx
         // 0040184d: jz 0x401858
      [-]53e81e690d0083c404
         // 0040184f: push ebx
         // 00401850: call 0x4d8173
         // 00401855: add esp, 0x4
      [-]8b5de885db7409
         // 00401858: mov ebx, ss:[ebp+0xffffffffffffffe8]
         // 0040185b: test ebx, ebx
         // 0040185d: jz 0x401868
      [-]53e80e690d0083c404
         // 0040185f: push ebx
         // 00401860: call 0x4d8173
         // 00401865: add esp, 0x4
      [-]588be55dc3
         // 00401868: pop eax
         // 00401869: mov esp, ebp
         // 0040186b: pop ebp
         // 0040186c: retn 
      [-]558bec81ec????????c745fc????????c745f8????????68????????e8eb680d0083c4048945f48bf8be????????adabadab68????????bb????????e8dd680d0083c4048945f068????????ff75f0b9????????e87ff8ffff83c4088945ec8b5df085db7409
         // 0040186d: push ebp
         // 0040186e: mov ebp, esp
         // 00401870: sub esp, 0x20
         // 00401876: mov ss:[ebp+0xfffffffffffffffc], 0x0
         // 0040187d: mov ss:[ebp+0xfffffffffffffff8], 0x0
         // 00401884: push 0x8
         // 00401889: call 0x4d8179
         // 0040188e: add esp, 0x4
         // 00401891: mov ss:[ebp+0xfffffffffffffff4], eax
         // 00401894: mov edi, eax
         // 00401896: mov esi, 0x58d351
         // 0040189b: lodsdd 
         // 0040189c: stosdd 
         // 0040189d: lodsdd 
         // 0040189e: stosdd 
         // 0040189f: push 0x0
         // 004018a4: mov ebx, 0x4d8840
         // 004018a9: call 0x4d818b
         // 004018ae: add esp, 0x4
         // 004018b1: mov ss:[ebp+0xfffffffffffffff0], eax
         // 004018b4: push 0x58d389
         // 004018b9: push ss:[ebp+0xfffffffffffffff0]
         // 004018bc: mov ecx, 0x2
         // 004018c1: call 0x401145
         // 004018c6: add esp, 0x8
         // 004018c9: mov ss:[ebp+0xffffffffffffffec], eax
         // 004018cc: mov ebx, ss:[ebp+0xfffffffffffffff0]
         // 004018cf: test ebx, ebx
         // 004018d1: jz 0x4018dc
      [-]53e89a680d0083c404
         // 004018d3: push ebx
         // 004018d4: call 0x4d8173
         // 004018d9: add esp, 0x4
      [-]6a006a006a0068????????6a0068????????68????????6a0068????????68????????6a008b45ec85c07505
         // 004018dc: push 0x0
         // 004018de: push 0x0
         // 004018e0: push 0x0
         // 004018e2: push 0xffffffff80000004
         // 004018e7: push 0x0
         // 004018e9: push 0x58d3a5
         // 004018ee: push 0xffffffff80000004
         // 004018f3: push 0x0
         // 004018f5: push 0x58d39e
         // 004018fa: push 0xffffffff80000004
         // 004018ff: push 0x0
         // 00401901: mov eax, ss:[ebp+0xffffffffffffffec]
         // 00401904: test eax, eax
         // 00401906: jnz 0x40190d
      [-]b8????????
         // 00401908: mov eax, 0x58d31d
      [-]5068????????bb????????e86e680d0083c4348945e88b5dec85db7409
         // 0040190d: push eax
         // 0040190e: push 0x4
         // 00401913: mov ebx, 0x4dc450
         // 00401918: call 0x4d818b
         // 0040191d: add esp, 0x34
         // 00401920: mov ss:[ebp+0xffffffffffffffe8], eax
         // 00401923: mov ebx, ss:[ebp+0xffffffffffffffec]
         // 00401926: test ebx, ebx
         // 00401928: jz 0x401933
      [-]53e843680d0083c404
         // 0040192a: push ebx
         // 0040192b: call 0x4d8173
         // 00401930: add esp, 0x4
      [-]8b45e8508b5dfc85db7409
         // 00401933: mov eax, ss:[ebp+0xffffffffffffffe8]
         // 00401936: push eax
         // 00401937: mov ebx, ss:[ebp+0xfffffffffffffffc]
         // 0040193a: test ebx, ebx
         // 0040193c: jz 0x401947
      [-]53e82f680d0083c404
         // 0040193e: push ebx
         // 0040193f: call 0x4d8173
         // 00401944: add esp, 0x4
      [-]588945fcc745f0????????6a00ff75f08d45fc506a018d45f450e8180400008945f8837df8000f8eac000000
         // 00401947: pop eax
         // 00401948: mov ss:[ebp+0xfffffffffffffffc], eax
         // 0040194b: mov ss:[ebp+0xfffffffffffffff0], 0x0
         // 00401952: push 0x0
         // 00401954: push ss:[ebp+0xfffffffffffffff0]
         // 00401957: lea eax, ss:[ebp+0xfffffffffffffffc]
         // 0040195a: push eax
         // 0040195b: push 0x1
         // 0040195d: lea eax, ss:[ebp+0xfffffffffffffff4]
         // 00401960: push eax
         // 00401961: call 0x401d7e
         // 00401966: mov ss:[ebp+0xfffffffffffffff8], eax
         // 00401969: cmp ss:[ebp+0xfffffffffffffff8], 0x0
         // 0040196d: jle 0x401a1f
      [-]68????????bb????????e809680d0083c4048945f0ff75fc68????????ff75f0b9????????e8a8f7ffff83c40c8945ec8b5df085db7409
         // 00401973: push 0x0
         // 00401978: mov ebx, 0x4d8840
         // 0040197d: call 0x4d818b
         // 00401982: add esp, 0x4
         // 00401985: mov ss:[ebp+0xfffffffffffffff0], eax
         // 00401988: push ss:[ebp+0xfffffffffffffffc]
         // 0040198b: push 0x58d31b
         // 00401990: push ss:[ebp+0xfffffffffffffff0]
         // 00401993: mov ecx, 0x3
         // 00401998: call 0x401145
         // 0040199d: add esp, 0xc
         // 004019a0: mov ss:[ebp+0xffffffffffffffec], eax
         // 004019a3: mov ebx, ss:[ebp+0xfffffffffffffff0]
         // 004019a6: test ebx, ebx
         // 004019a8: jz 0x4019b3
      [-]53e8c3670d0083c404
         // 004019aa: push ebx
         // 004019ab: call 0x4d8173
         // 004019b0: add esp, 0x4
      [-]c745e8????????6a00ff75e8c745e4????????6a008d45e4506a01b8????????8945e08d45e0508d45ec506a0168????????e8630b00008b5dec85db7409
         // 004019b3: mov ss:[ebp+0xffffffffffffffe8], 0x0
         // 004019ba: push 0x0
         // 004019bc: push ss:[ebp+0xffffffffffffffe8]
         // 004019bf: mov ss:[ebp+0xffffffffffffffe4], 0x0
         // 004019c6: push 0x0
         // 004019c8: lea eax, ss:[ebp+0xffffffffffffffe4]
         // 004019cb: push eax
         // 004019cc: push 0x1
         // 004019ce: mov eax, 0x58d3a3
         // 004019d3: mov ss:[ebp+0xffffffffffffffe0], eax
         // 004019d6: lea eax, ss:[ebp+0xffffffffffffffe0]
         // 004019d9: push eax
         // 004019da: lea eax, ss:[ebp+0xffffffffffffffec]
         // 004019dd: push eax
         // 004019de: push 0x1
         // 004019e0: push 0x1
         // 004019e5: call 0x40254d
         // 004019ea: mov ebx, ss:[ebp+0xffffffffffffffec]
         // 004019ed: test ebx, ebx
         // 004019ef: jz 0x4019fa
      [-]53e87c670d0083c404
         // 004019f1: push ebx
         // 004019f2: call 0x4d8173
         // 004019f7: add esp, 0x4
      [-]8b5de085db7409
         // 004019fa: mov ebx, ss:[ebp+0xffffffffffffffe0]
         // 004019fd: test ebx, ebx
         // 004019ff: jz 0x401a0a
      [-]53e86c670d0083c404
         // 00401a01: push ebx
         // 00401a02: call 0x4d8173
         // 00401a07: add esp, 0x4
      [-]8b5de485db7409
         // 00401a0a: mov ebx, ss:[ebp+0xffffffffffffffe4]
         // 00401a0d: test ebx, ebx
         // 00401a0f: jz 0x401a1a
      [-]53e85c670d0083c404
         // 00401a11: push ebx
         // 00401a12: call 0x4d8173
         // 00401a17: add esp, 0x4
      [-]e93f030000
         // 00401a1a: jmp 0x401d5e
      [-]68????????bb????????e85d670d0083c4048945f0ff75fc68????????ff75f0b9????????e8fcf6ffff83c40c8945ec8b5df085db7409
         // 00401a1f: push 0x0
         // 00401a24: mov ebx, 0x4d8840
         // 00401a29: call 0x4d818b
         // 00401a2e: add esp, 0x4
         // 00401a31: mov ss:[ebp+0xfffffffffffffff0], eax
         // 00401a34: push ss:[ebp+0xfffffffffffffffc]
         // 00401a37: push 0x58d31b
         // 00401a3c: push ss:[ebp+0xfffffffffffffff0]
         // 00401a3f: mov ecx, 0x3
         // 00401a44: call 0x401145
         // 00401a49: add esp, 0xc
         // 00401a4c: mov ss:[ebp+0xffffffffffffffec], eax
         // 00401a4f: mov ebx, ss:[ebp+0xfffffffffffffff0]
         // 00401a52: test ebx, ebx
         // 00401a54: jz 0x401a5f
      [-]53e817670d0083c404
         // 00401a56: push ebx
         // 00401a57: call 0x4d8173
         // 00401a5c: add esp, 0x4
      [-]68????????6a008b45ec85c07505
         // 00401a5f: push 0xffffffff80000004
         // 00401a64: push 0x0
         // 00401a66: mov eax, ss:[ebp+0xffffffffffffffec]
         // 00401a69: test eax, eax
         // 00401a6b: jnz 0x401a72
      [-]b8????????
         // 00401a6d: mov eax, 0x58d31d
      [-]5068????????bb????????e809670d0083c4108945e88b5dec85db7409
         // 00401a72: push eax
         // 00401a73: push 0x1
         // 00401a78: mov ebx, 0x4dae80
         // 00401a7d: call 0x4d818b
         // 00401a82: add esp, 0x10
         // 00401a85: mov ss:[ebp+0xffffffffffffffe8], eax
         // 00401a88: mov ebx, ss:[ebp+0xffffffffffffffec]
         // 00401a8b: test ebx, ebx
         // 00401a8d: jz 0x401a98
      [-]53e8de660d0083c404
         // 00401a8f: push ebx
         // 00401a90: call 0x4d8173
         // 00401a95: add esp, 0x4
      [-]837de8010f8576000000
         // 00401a98: cmp ss:[ebp+0xffffffffffffffe8], 0x1
         // 00401a9c: jnz 0x401b18
      [-]68????????bb????????e8da660d0083c4048945f0ff75fc68????????ff75f0b9????????e879f6ffff83c40c8945ec8b5df085db7409
         // 00401aa2: push 0x0
         // 00401aa7: mov ebx, 0x4d8840
         // 00401aac: call 0x4d818b
         // 00401ab1: add esp, 0x4
         // 00401ab4: mov ss:[ebp+0xfffffffffffffff0], eax
         // 00401ab7: push ss:[ebp+0xfffffffffffffffc]
         // 00401aba: push 0x58d31b
         // 00401abf: push ss:[ebp+0xfffffffffffffff0]
         // 00401ac2: mov ecx, 0x3
         // 00401ac7: call 0x401145
         // 00401acc: add esp, 0xc
         // 00401acf: mov ss:[ebp+0xffffffffffffffec], eax
         // 00401ad2: mov ebx, ss:[ebp+0xfffffffffffffff0]
         // 00401ad5: test ebx, ebx
         // 00401ad7: jz 0x401ae2
      [-]53e894660d0083c404
         // 00401ad9: push ebx
         // 00401ada: call 0x4d8173
         // 00401adf: add esp, 0x4
      [-]68????????6a008b45ec85c07505
         // 00401ae2: push 0xffffffff80000004
         // 00401ae7: push 0x0
         // 00401ae9: mov eax, ss:[ebp+0xffffffffffffffec]
         // 00401aec: test eax, eax
         // 00401aee: jnz 0x401af5
      [-]b8????????
         // 00401af0: mov eax, 0x58d31d
      [-]5068????????bb????????e886660d0083c4108b5dec85db7409
         // 00401af5: push eax
         // 00401af6: push 0x1
         // 00401afb: mov ebx, 0x4dae60
         // 00401b00: call 0x4d818b
         // 00401b05: add esp, 0x10
         // 00401b08: mov ebx, ss:[ebp+0xffffffffffffffec]
         // 00401b0b: test ebx, ebx
         // 00401b0d: jz 0x401b18
      [-]53e85e660d0083c404
         // 00401b0f: push ebx
         // 00401b10: call 0x4d8173
         // 00401b15: add esp, 0x4
      [-]c745f0????????6a00ff75f068????????e88d1000008945ec68????????ff75ecb9????????e802f6ffff83c4088945e88b5dec85db7409
         // 00401b18: mov ss:[ebp+0xfffffffffffffff0], 0x0
         // 00401b1f: push 0x0
         // 00401b21: push ss:[ebp+0xfffffffffffffff0]
         // 00401b24: push 0xa
         // 00401b29: call 0x402bbb
         // 00401b2e: mov ss:[ebp+0xffffffffffffffec], eax
         // 00401b31: push 0x58d3a9
         // 00401b36: push ss:[ebp+0xffffffffffffffec]
         // 00401b39: mov ecx, 0x2
         // 00401b3e: call 0x401145
         // 00401b43: add esp, 0x8
         // 00401b46: mov ss:[ebp+0xffffffffffffffe8], eax
         // 00401b49: mov ebx, ss:[ebp+0xffffffffffffffec]
         // 00401b4c: test ebx, ebx
         // 00401b4e: jz 0x401b59
      [-]53e81d660d0083c404
         // 00401b50: push ebx
         // 00401b51: call 0x4d8173
         // 00401b56: add esp, 0x4
      [-]8b45e8508b5dfc85db7409
         // 00401b59: mov eax, ss:[ebp+0xffffffffffffffe8]
         // 00401b5c: push eax
         // 00401b5d: mov ebx, ss:[ebp+0xfffffffffffffffc]
         // 00401b60: test ebx, ebx
         // 00401b62: jz 0x401b6d
      [-]53e809660d0083c404
         // 00401b64: push ebx
         // 00401b65: call 0x4d8173
         // 00401b6a: add esp, 0x4
      [-]588945fc68????????bb????????e80b660d0083c4048945f068????????bb????????e8f6650d0083c4048945ecff75fc68????????ff75ec68????????ff75f0b9????????e88df5ffff83c4148945e88b5df085db7409
         // 00401b6d: pop eax
         // 00401b6e: mov ss:[ebp+0xfffffffffffffffc], eax
         // 00401b71: push 0x0
         // 00401b76: mov ebx, 0x4d8840
         // 00401b7b: call 0x4d818b
         // 00401b80: add esp, 0x4
         // 00401b83: mov ss:[ebp+0xfffffffffffffff0], eax
         // 00401b86: push 0x0
         // 00401b8b: mov ebx, 0x4d8860
         // 00401b90: call 0x4d818b
         // 00401b95: add esp, 0x4
         // 00401b98: mov ss:[ebp+0xffffffffffffffec], eax
         // 00401b9b: push ss:[ebp+0xfffffffffffffffc]
         // 00401b9e: push 0x58d3ae
         // 00401ba3: push ss:[ebp+0xffffffffffffffec]
         // 00401ba6: push 0x58d31b
         // 00401bab: push ss:[ebp+0xfffffffffffffff0]
         // 00401bae: mov ecx, 0x5
         // 00401bb3: call 0x401145
         // 00401bb8: add esp, 0x14
         // 00401bbb: mov ss:[ebp+0xffffffffffffffe8], eax
         // 00401bbe: mov ebx, ss:[ebp+0xfffffffffffffff0]
         // 00401bc1: test ebx, ebx
         // 00401bc3: jz 0x401bce
      [-]53e8a8650d0083c404
         // 00401bc5: push ebx
         // 00401bc6: call 0x4d8173
         // 00401bcb: add esp, 0x4
      [-]8b5dec85db7409
         // 00401bce: mov ebx, ss:[ebp+0xffffffffffffffec]
         // 00401bd1: test ebx, ebx
         // 00401bd3: jz 0x401bde
      [-]53e898650d0083c404
         // 00401bd5: push ebx
         // 00401bd6: call 0x4d8173
         // 00401bdb: add esp, 0x4
      [-]6a006a006a0068????????6a0068????????68????????6a008b45e885c07505
         // 00401bde: push 0x0
         // 00401be0: push 0x0
         // 00401be2: push 0x0
         // 00401be4: push 0xffffffff80000002
         // 00401be9: push 0x0
         // 00401beb: push 0x1
         // 00401bf0: push 0xffffffff80000004
         // 00401bf5: push 0x0
         // 00401bf7: mov eax, ss:[ebp+0xffffffffffffffe8]
         // 00401bfa: test eax, eax
         // 00401bfc: jnz 0x401c03
      [-]b8????????
         // 00401bfe: mov eax, 0x58d31d
      [-]5068????????bb????????e878650d0083c4288b5de885db7409
         // 00401c03: push eax
         // 00401c04: push 0x3
         // 00401c09: mov ebx, 0x4d8640
         // 00401c0e: call 0x4d818b
         // 00401c13: add esp, 0x28
         // 00401c16: mov ebx, ss:[ebp+0xffffffffffffffe8]
         // 00401c19: test ebx, ebx
         // 00401c1b: jz 0x401c26
      [-]53e850650d0083c404
         // 00401c1d: push ebx
         // 00401c1e: call 0x4d8173
         // 00401c23: add esp, 0x4
      [-]68????????bb????????e856650d0083c4048945f068????????ff75f0b9????????e8f8f4ffff83c4088945ec8b5df085db7409
         // 00401c26: push 0x0
         // 00401c2b: mov ebx, 0x4d8840
         // 00401c30: call 0x4d818b
         // 00401c35: add esp, 0x4
         // 00401c38: mov ss:[ebp+0xfffffffffffffff0], eax
         // 00401c3b: push 0x58d389
         // 00401c40: push ss:[ebp+0xfffffffffffffff0]
         // 00401c43: mov ecx, 0x2
         // 00401c48: call 0x401145
         // 00401c4d: add esp, 0x8
         // 00401c50: mov ss:[ebp+0xffffffffffffffec], eax
         // 00401c53: mov ebx, ss:[ebp+0xfffffffffffffff0]
         // 00401c56: test ebx, ebx
         // 00401c58: jz 0x401c63
      [-]53e813650d0083c404
         // 00401c5a: push ebx
         // 00401c5b: call 0x4d8173
         // 00401c60: add esp, 0x4
      [-]68????????6a008b45fc85c07505
         // 00401c63: push 0xffffffff80000004
         // 00401c68: push 0x0
         // 00401c6a: mov eax, ss:[ebp+0xfffffffffffffffc]
         // 00401c6d: test eax, eax
         // 00401c6f: jnz 0x401c76
      [-]b8????????
         // 00401c71: mov eax, 0x58d31d
      [-]5068????????6a0068????????68????????6a0068????????68????????6a008b45ec85c07505
         // 00401c76: push eax
         // 00401c77: push 0xffffffff80000004
         // 00401c7c: push 0x0
         // 00401c7e: push 0x58d3a5
         // 00401c83: push 0xffffffff80000004
         // 00401c88: push 0x0
         // 00401c8a: push 0x58d39e
         // 00401c8f: push 0xffffffff80000004
         // 00401c94: push 0x0
         // 00401c96: mov eax, ss:[ebp+0xffffffffffffffec]
         // 00401c99: test eax, eax
         // 00401c9b: jnz 0x401ca2
      [-]b8????????
         // 00401c9d: mov eax, 0x58d31d
      [-]5068????????bb????????e8d9640d0083c4348b5dec85db7409
         // 00401ca2: push eax
         // 00401ca3: push 0x4
         // 00401ca8: mov ebx, 0x4dc550
         // 00401cad: call 0x4d818b
         // 00401cb2: add esp, 0x34
         // 00401cb5: mov ebx, ss:[ebp+0xffffffffffffffec]
         // 00401cb8: test ebx, ebx
         // 00401cba: jz 0x401cc5
      [-]53e8b1640d0083c404
         // 00401cbc: push ebx
         // 00401cbd: call 0x4d8173
         // 00401cc2: add esp, 0x4
      [-]68????????bb????????e8b7640d0083c4048945f0ff75fc68????????ff75f0b9????????e856f4ffff83c40c8945ec8b5df085db7409
         // 00401cc5: push 0x0
         // 00401cca: mov ebx, 0x4d8840
         // 00401ccf: call 0x4d818b
         // 00401cd4: add esp, 0x4
         // 00401cd7: mov ss:[ebp+0xfffffffffffffff0], eax
         // 00401cda: push ss:[ebp+0xfffffffffffffffc]
         // 00401cdd: push 0x58d31b
         // 00401ce2: push ss:[ebp+0xfffffffffffffff0]
         // 00401ce5: mov ecx, 0x3
         // 00401cea: call 0x401145
         // 00401cef: add esp, 0xc
         // 00401cf2: mov ss:[ebp+0xffffffffffffffec], eax
         // 00401cf5: mov ebx, ss:[ebp+0xfffffffffffffff0]
         // 00401cf8: test ebx, ebx
         // 00401cfa: jz 0x401d05
      [-]53e871640d0083c404
         // 00401cfc: push ebx
         // 00401cfd: call 0x4d8173
         // 00401d02: add esp, 0x4
      [-]6a006a006a0068????????6a0068????????68????????6a008b45ec85c07505
         // 00401d05: push 0x0
         // 00401d07: push 0x0
         // 00401d09: push 0x0
         // 00401d0b: push 0xffffffff80000002
         // 00401d10: push 0x0
         // 00401d12: push 0x0
         // 00401d17: push 0xffffffff80000004
         // 00401d1c: push 0x0
         // 00401d1e: mov eax, ss:[ebp+0xffffffffffffffec]
         // 00401d21: test eax, eax
         // 00401d23: jnz 0x401d2a
      [-]b8????????
         // 00401d25: mov eax, 0x58d31d
      [-]5068????????bb????????e851640d0083c4288b5dec85db7409
         // 00401d2a: push eax
         // 00401d2b: push 0x3
         // 00401d30: mov ebx, 0x4d8640
         // 00401d35: call 0x4d818b
         // 00401d3a: add esp, 0x28
         // 00401d3d: mov ebx, ss:[ebp+0xffffffffffffffec]
         // 00401d40: test ebx, ebx
         // 00401d42: jz 0x401d4d
      [-]53e829640d0083c404
         // 00401d44: push ebx
         // 00401d45: call 0x4d8173
         // 00401d4a: add esp, 0x4
      [-]c745f0????????6a00ff75f0e869110000
         // 00401d4d: mov ss:[ebp+0xfffffffffffffff0], 0x0
         // 00401d54: push 0x0
         // 00401d56: push ss:[ebp+0xfffffffffffffff0]
         // 00401d59: call 0x402ec7
      [-]8b5dfc85db7409
         // 00401d5e: mov ebx, ss:[ebp+0xfffffffffffffffc]
         // 00401d61: test ebx, ebx
         // 00401d63: jz 0x401d6e
      [-]53e808640d0083c404
         // 00401d65: push ebx
         // 00401d66: call 0x4d8173
         // 00401d6b: add esp, 0x4
      [-]8b5df453e8fc630d0083c4048be55dc3
         // 00401d6e: mov ebx, ss:[ebp+0xfffffffffffffff4]
         // 00401d71: push ebx
         // 00401d72: call 0x4d8173
         // 00401d77: add esp, 0x4
         // 00401d7a: mov esp, ebp
         // 00401d7c: pop ebp
         // 00401d7d: retn 
      [-]558bec81ec????????c745fc????????68????????e8e1630d0083c4048945f88bd88bf833c0b9????????f3ab83c3245368????????e8c0630d0083c4045b89038bf8be????????adabadab33c0b9????????f3abc745f4????????8b5d088b1b53e88e630d0083c404b8????????8b5d0889038965f068????????68????????b8????????e87c630d003965f07417
         // 00401d7e: push ebp
         // 00401d7f: mov ebp, esp
         // 00401d81: sub esp, 0x20
         // 00401d87: mov ss:[ebp+0xfffffffffffffffc], 0x0
         // 00401d8e: push 0x28
         // 00401d93: call 0x4d8179
         // 00401d98: add esp, 0x4
         // 00401d9b: mov ss:[ebp+0xfffffffffffffff8], eax
         // 00401d9e: mov ebx, eax
         // 00401da0: mov edi, eax
         // 00401da2: xor eax, eax
         // 00401da4: mov ecx, 0xa
         // 00401da9: rep stosdd 
         // 00401dab: add ebx, 0x24
         // 00401dae: push ebx
         // 00401daf: push 0x108
         // 00401db4: call 0x4d8179
         // 00401db9: add esp, 0x4
         // 00401dbc: pop ebx
         // 00401dbd: mov ds:[ebx], eax
         // 00401dbf: mov edi, eax
         // 00401dc1: mov esi, 0x58d3b7
         // 00401dc6: lodsdd 
         // 00401dc7: stosdd 
         // 00401dc8: lodsdd 
         // 00401dc9: stosdd 
         // 00401dca: xor eax, eax
         // 00401dcc: mov ecx, 0x40
         // 00401dd1: rep stosdd 
         // 00401dd3: mov ss:[ebp+0xfffffffffffffff4], 0x0
         // 00401dda: mov ebx, ss:[ebp+0x8]
         // 00401ddd: mov ebx, ds:[ebx]
         // 00401ddf: push ebx
         // 00401de0: call 0x4d8173
         // 00401de5: add esp, 0x4
         // 00401de8: mov eax, 0x58d351
         // 00401ded: mov ebx, ss:[ebp+0x8]
         // 00401df0: mov ds:[ebx], eax
         // 00401df2: mov ss:[ebp+0xfffffffffffffff0], esp
         // 00401df5: push 0x0
         // 00401dfa: push 0xf
         // 00401dff: mov eax, 0x1
         // 00401e04: call 0x4d8185
         // 00401e09: cmp ss:[ebp+0xfffffffffffffff0], esp
         // 00401e0c: jz 0x401e25
      [-]68????????68????????68????????e85d630d0083c40c
         // 00401e0e: push 0x33
         // 00401e13: push 0x409535b
         // 00401e18: push 0x6
         // 00401e1d: call 0x4d817f
         // 00401e22: add esp, 0xc
      [-]8945fc837dfc000f84bc060000
         // 00401e25: mov ss:[ebp+0xfffffffffffffffc], eax
         // 00401e28: cmp ss:[ebp+0xfffffffffffffffc], 0x0
         // 00401e2c: jz 0x4024ee
      [-]8b5df8895df08b5df0c703????????8965f08b45f85068????????e827630d0083c4048bf85b50895de88945ec8b0383c304890783c7048b0383c304890783c7048b0383c304890783c7048b0383c304890783c7048b0383c304890783c7048b0383c304890783c7048b0383c304890783c7048b0383c304890783c7048b0383c304890783c704538b1b81c3????????b9????????8bf3f3a45b83c304ff75fcb8????????e8a9620d003965f07417
         // 00401e32: mov ebx, ss:[ebp+0xfffffffffffffff8]
         // 00401e35: mov ss:[ebp+0xfffffffffffffff0], ebx
         // 00401e38: mov ebx, ss:[ebp+0xfffffffffffffff0]
         // 00401e3b: mov ds:[ebx], 0x400
         // 00401e41: mov ss:[ebp+0xfffffffffffffff0], esp
         // 00401e44: mov eax, ss:[ebp+0xfffffffffffffff8]
         // 00401e47: push eax
         // 00401e48: push 0x124
         // 00401e4d: call 0x4d8179
         // 00401e52: add esp, 0x4
         // 00401e55: mov edi, eax
         // 00401e57: pop ebx
         // 00401e58: push eax
         // 00401e59: mov ss:[ebp+0xffffffffffffffe8], ebx
         // 00401e5c: mov ss:[ebp+0xffffffffffffffec], eax
         // 00401e5f: mov eax, ds:[ebx]
         // 00401e61: add ebx, 0x4
         // 00401e64: mov ds:[edi], eax
         // 00401e66: add edi, 0x4
         // 00401e69: mov eax, ds:[ebx]
         // 00401e6b: add ebx, 0x4
         // 00401e6e: mov ds:[edi], eax
         // 00401e70: add edi, 0x4
         // 00401e73: mov eax, ds:[ebx]
         // 00401e75: add ebx, 0x4
         // 00401e78: mov ds:[edi], eax
         // 00401e7a: add edi, 0x4
         // 00401e7d: mov eax, ds:[ebx]
         // 00401e7f: add ebx, 0x4
         // 00401e82: mov ds:[edi], eax
         // 00401e84: add edi, 0x4
         // 00401e87: mov eax, ds:[ebx]
         // 00401e89: add ebx, 0x4
         // 00401e8c: mov ds:[edi], eax
         // 00401e8e: add edi, 0x4
         // 00401e91: mov eax, ds:[ebx]
         // 00401e93: add ebx, 0x4
         // 00401e96: mov ds:[edi], eax
         // 00401e98: add edi, 0x4
         // 00401e9b: mov eax, ds:[ebx]
         // 00401e9d: add ebx, 0x4
         // 00401ea0: mov ds:[edi], eax
         // 00401ea2: add edi, 0x4
         // 00401ea5: mov eax, ds:[ebx]
         // 00401ea7: add ebx, 0x4
         // 00401eaa: mov ds:[edi], eax
         // 00401eac: add edi, 0x4
         // 00401eaf: mov eax, ds:[ebx]
         // 00401eb1: add ebx, 0x4
         // 00401eb4: mov ds:[edi], eax
         // 00401eb6: add edi, 0x4
         // 00401eb9: push ebx
         // 00401eba: mov ebx, ds:[ebx]
         // 00401ebc: add ebx, 0x8
         // 00401ec2: mov ecx, 0x100
         // 00401ec7: mov esi, ebx
         // 00401ec9: rep movsbb 
         // 00401ecb: pop ebx
         // 00401ecc: add ebx, 0x4
         // 00401ecf: push ss:[ebp+0xfffffffffffffffc]
         // 00401ed2: mov eax, 0x2
         // 00401ed7: call 0x4d8185
         // 00401edc: cmp ss:[ebp+0xfffffffffffffff0], esp
         // 00401edf: jz 0x401ef8
      [-]68????????68????????68????????e88a620d0083c40c
         // 00401ee1: push 0xd4
         // 00401ee6: push 0x409535b
         // 00401eeb: push 0x6
         // 00401ef0: call 0x4d817f
         // 00401ef5: add esp, 0xc
      [-]508b5dec538b7de88b0383c304890783c7048b0383c304890783c7048b0383c304890783c7048b0383c304890783c7048b0383c304890783c7048b0383c304890783c7048b0383c304890783c7048b0383c304890783c7048b0383c304890783c70453576a01b8????????e805620d0083c4045f5b53578b3f8b0f83c70485c9740f
         // 00401ef8: push eax
         // 00401ef9: mov ebx, ss:[ebp+0xffffffffffffffec]
         // 00401efc: push ebx
         // 00401efd: mov edi, ss:[ebp+0xffffffffffffffe8]
         // 00401f00: mov eax, ds:[ebx]
         // 00401f02: add ebx, 0x4
         // 00401f05: mov ds:[edi], eax
         // 00401f07: add edi, 0x4
         // 00401f0a: mov eax, ds:[ebx]
         // 00401f0c: add ebx, 0x4
         // 00401f0f: mov ds:[edi], eax
         // 00401f11: add edi, 0x4
         // 00401f14: mov eax, ds:[ebx]
         // 00401f16: add ebx, 0x4
         // 00401f19: mov ds:[edi], eax
         // 00401f1b: add edi, 0x4
         // 00401f1e: mov eax, ds:[ebx]
         // 00401f20: add ebx, 0x4
         // 00401f23: mov ds:[edi], eax
         // 00401f25: add edi, 0x4
         // 00401f28: mov eax, ds:[ebx]
         // 00401f2a: add ebx, 0x4
         // 00401f2d: mov ds:[edi], eax
         // 00401f2f: add edi, 0x4
         // 00401f32: mov eax, ds:[ebx]
         // 00401f34: add ebx, 0x4
         // 00401f37: mov ds:[edi], eax
         // 00401f39: add edi, 0x4
         // 00401f3c: mov eax, ds:[ebx]
         // 00401f3e: add ebx, 0x4
         // 00401f41: mov ds:[edi], eax
         // 00401f43: add edi, 0x4
         // 00401f46: mov eax, ds:[ebx]
         // 00401f48: add ebx, 0x4
         // 00401f4b: mov ds:[edi], eax
         // 00401f4d: add edi, 0x4
         // 00401f50: mov eax, ds:[ebx]
         // 00401f52: add ebx, 0x4
         // 00401f55: mov ds:[edi], eax
         // 00401f57: add edi, 0x4
         // 00401f5a: push ebx
         // 00401f5b: push edi
         // 00401f5c: push 0x1
         // 00401f5e: mov eax, 0x2
         // 00401f63: call 0x4d816d
         // 00401f68: add esp, 0x4
         // 00401f6b: pop edi
         // 00401f6c: pop ebx
         // 00401f6d: push ebx
         // 00401f6e: push edi
         // 00401f6f: mov edi, ds:[edi]
         // 00401f71: mov ecx, ds:[edi]
         // 00401f73: add edi, 0x4
         // 00401f76: test ecx, ecx
         // 00401f78: jz 0x401f89
      [-]83c704497405
         // 00401f7c: add edi, 0x4
         // 00401f7f: dec ecx
         // 00401f80: jz 0x401f87
      [-]0faf07ebf5
         // 00401f82: imul eax, ds:[edi]
         // 00401f85: jmp 0x401f7c
      [-]81f9????????7e05
         // 00401f89: cmp ecx, 0x100
         // 00401f8f: jle 0x401f96
      [-]b9????????
         // 00401f91: mov ecx, 0x100
      [-]8bf3f3a45f5b83c70481c3????????e8c9610d0083c404588945f4837d14000f8463020000
         // 00401f96: mov esi, ebx
         // 00401f98: rep movsbb 
         // 00401f9a: pop edi
         // 00401f9b: pop ebx
         // 00401f9c: add edi, 0x4
         // 00401f9f: add ebx, 0x100
         // 00401fa5: call 0x4d8173
         // 00401faa: add esp, 0x4
         // 00401fad: pop eax
         // 00401fae: mov ss:[ebp+0xfffffffffffffff4], eax
         // 00401fb1: cmp ss:[ebp+0x14], 0x0
         // 00401fb5: jz 0x40221e
      [-]837df4000f8454020000
         // 00401fbb: cmp ss:[ebp+0xfffffffffffffff4], 0x0
         // 00401fbf: jz 0x402219
      [-]8b5df883c324895df068????????6a008b5df0ff3368????????bb????????e8a2610d0083c4108945ec8b5d108b0350ff75ece840f0ffff83c40883f800b8????????0f94c08945e88b5dec85db7409
         // 00401fc5: mov ebx, ss:[ebp+0xfffffffffffffff8]
         // 00401fc8: add ebx, 0x24
         // 00401fcb: mov ss:[ebp+0xfffffffffffffff0], ebx
         // 00401fce: push 0xffffffffa0000101
         // 00401fd3: push 0x0
         // 00401fd5: mov ebx, ss:[ebp+0xfffffffffffffff0]
         // 00401fd8: push ds:[ebx]
         // 00401fda: push 0x1
         // 00401fdf: mov ebx, 0x4da970
         // 00401fe4: call 0x4d818b
         // 00401fe9: add esp, 0x10
         // 00401fec: mov ss:[ebp+0xffffffffffffffec], eax
         // 00401fef: mov ebx, ss:[ebp+0x10]
         // 00401ff2: mov eax, ds:[ebx]
         // 00401ff4: push eax
         // 00401ff5: push ss:[ebp+0xffffffffffffffec]
         // 00401ff8: call 0x40103d
         // 00401ffd: add esp, 0x8
         // 00402000: cmp eax, 0x0
         // 00402003: mov eax, 0x0
         // 00402008: setz b1 al
         // 0040200b: mov ss:[ebp+0xffffffffffffffe8], eax
         // 0040200e: mov ebx, ss:[ebp+0xffffffffffffffec]
         // 00402011: test ebx, ebx
         // 00402013: jz 0x40201e
      [-]53e858610d0083c404
         // 00402015: push ebx
         // 00402016: call 0x4d8173
         // 0040201b: add esp, 0x4
      [-]837de8000f847c000000
         // 0040201e: cmp ss:[ebp+0xffffffffffffffe8], 0x0
         // 00402022: jz 0x4020a4
      [-]8b5df883c308895df0ff75086a04b8????????e82d610d0083c4088b5df08b038945ec8b5d088b1b895de8e8c5efffff894de48b7de8c707????????83c7048bc140890783c7043bfb7404
         // 00402028: mov ebx, ss:[ebp+0xfffffffffffffff8]
         // 0040202b: add ebx, 0x8
         // 0040202e: mov ss:[ebp+0xfffffffffffffff0], ebx
         // 00402031: push ss:[ebp+0x8]
         // 00402034: push 0x4
         // 00402036: mov eax, 0x2
         // 0040203b: call 0x4d816d
         // 00402040: add esp, 0x8
         // 00402043: mov ebx, ss:[ebp+0xfffffffffffffff0]
         // 00402046: mov eax, ds:[ebx]
         // 00402048: mov ss:[ebp+0xffffffffffffffec], eax
         // 0040204b: mov ebx, ss:[ebp+0x8]
         // 0040204e: mov ebx, ds:[ebx]
         // 00402050: mov ss:[ebp+0xffffffffffffffe8], ebx
         // 00402053: call 0x40101d
         // 00402058: mov ss:[ebp+0xffffffffffffffe4], ecx
         // 0040205b: mov edi, ss:[ebp+0xffffffffffffffe8]
         // 0040205e: mov ds:[edi], 0x1
         // 00402064: add edi, 0x4
         // 00402067: mov eax, ecx
         // 00402069: inc eax
         // 0040206a: mov ds:[edi], eax
         // 0040206c: add edi, 0x4
         // 0040206f: cmp edi, ebx
         // 00402071: jz 0x402077
      [-]8bf3f3a5
         // 00402073: mov esi, ebx
         // 00402075: rep movsdd 
      [-]8b45e440c1e00283c00850ff75e8e807610d0083c4088b5d0889038bf883c7088b45e4c1e00203f88b45ec8907
         // 00402077: mov eax, ss:[ebp+0xffffffffffffffe4]
         // 0040207a: inc eax
         // 0040207b: shl eax, b1 0x2
         // 0040207e: add eax, 0x8
         // 00402081: push eax
         // 00402082: push ss:[ebp+0xffffffffffffffe8]
         // 00402085: call 0x4d8191
         // 0040208a: add esp, 0x8
         // 0040208d: mov ebx, ss:[ebp+0x8]
         // 00402090: mov ds:[ebx], eax
         // 00402092: mov edi, eax
         // 00402094: add edi, 0x8
         // 00402097: mov eax, ss:[ebp+0xffffffffffffffe4]
         // 0040209a: shl eax, b1 0x2
         // 0040209d: add edi, eax
         // 0040209f: mov eax, ss:[ebp+0xffffffffffffffec]
         // 004020a2: mov ds:[edi], eax
      [-]8965f08b45f85068????????e8c4600d0083c4048bf85b50895de88945ec8b0383c304890783c7048b0383c304890783c7048b0383c304890783c7048b0383c304890783c7048b0383c304890783c7048b0383c304890783c7048b0383c304890783c7048b0383c304890783c7048b0383c304890783c704538b1b81c3????????b9????????8bf3f3a45b83c304ff75fcb8????????e846600d003965f07417
         // 004020a4: mov ss:[ebp+0xfffffffffffffff0], esp
         // 004020a7: mov eax, ss:[ebp+0xfffffffffffffff8]
         // 004020aa: push eax
         // 004020ab: push 0x124
         // 004020b0: call 0x4d8179
         // 004020b5: add esp, 0x4
         // 004020b8: mov edi, eax
         // 004020ba: pop ebx
         // 004020bb: push eax
         // 004020bc: mov ss:[ebp+0xffffffffffffffe8], ebx
         // 004020bf: mov ss:[ebp+0xffffffffffffffec], eax
         // 004020c2: mov eax, ds:[ebx]
         // 004020c4: add ebx, 0x4
         // 004020c7: mov ds:[edi], eax
         // 004020c9: add edi, 0x4
         // 004020cc: mov eax, ds:[ebx]
         // 004020ce: add ebx, 0x4
         // 004020d1: mov ds:[edi], eax
         // 004020d3: add edi, 0x4
         // 004020d6: mov eax, ds:[ebx]
         // 004020d8: add ebx, 0x4
         // 004020db: mov ds:[edi], eax
         // 004020dd: add edi, 0x4
         // 004020e0: mov eax, ds:[ebx]
         // 004020e2: add ebx, 0x4
         // 004020e5: mov ds:[edi], eax
         // 004020e7: add edi, 0x4
         // 004020ea: mov eax, ds:[ebx]
         // 004020ec: add ebx, 0x4
         // 004020ef: mov ds:[edi], eax
         // 004020f1: add edi, 0x4
         // 004020f4: mov eax, ds:[ebx]
         // 004020f6: add ebx, 0x4
         // 004020f9: mov ds:[edi], eax
         // 004020fb: add edi, 0x4
         // 004020fe: mov eax, ds:[ebx]
         // 00402100: add ebx, 0x4
         // 00402103: mov ds:[edi], eax
         // 00402105: add edi, 0x4
         // 00402108: mov eax, ds:[ebx]
         // 0040210a: add ebx, 0x4
         // 0040210d: mov ds:[edi], eax
         // 0040210f: add edi, 0x4
         // 00402112: mov eax, ds:[ebx]
         // 00402114: add ebx, 0x4
         // 00402117: mov ds:[edi], eax
         // 00402119: add edi, 0x4
         // 0040211c: push ebx
         // 0040211d: mov ebx, ds:[ebx]
         // 0040211f: add ebx, 0x8
         // 00402125: mov ecx, 0x100
         // 0040212a: mov esi, ebx
         // 0040212c: rep movsbb 
         // 0040212e: pop ebx
         // 0040212f: add ebx, 0x4
         // 00402132: push ss:[ebp+0xfffffffffffffffc]
         // 00402135: mov eax, 0x3
         // 0040213a: call 0x4d8185
         // 0040213f: cmp ss:[ebp+0xfffffffffffffff0], esp
         // 00402142: jz 0x40215b
      [-]68????????68????????68????????e827600d0083c40c
         // 00402144: push 0x1db
         // 00402149: push 0x409535b
         // 0040214e: push 0x6
         // 00402153: call 0x4d817f
         // 00402158: add esp, 0xc
      [-]508b5dec538b7de88b0383c304890783c7048b0383c304890783c7048b0383c304890783c7048b0383c304890783c7048b0383c304890783c7048b0383c304890783c7048b0383c304890783c7048b0383c304890783c7048b0383c304890783c70453576a01b8????????e8a25f0d0083c4045f5b53578b3f8b0f83c70485c9740f
         // 0040215b: push eax
         // 0040215c: mov ebx, ss:[ebp+0xffffffffffffffec]
         // 0040215f: push ebx
         // 00402160: mov edi, ss:[ebp+0xffffffffffffffe8]
         // 00402163: mov eax, ds:[ebx]
         // 00402165: add ebx, 0x4
         // 00402168: mov ds:[edi], eax
         // 0040216a: add edi, 0x4
         // 0040216d: mov eax, ds:[ebx]
         // 0040216f: add ebx, 0x4
         // 00402172: mov ds:[edi], eax
         // 00402174: add edi, 0x4
         // 00402177: mov eax, ds:[ebx]
         // 00402179: add ebx, 0x4
         // 0040217c: mov ds:[edi], eax
         // 0040217e: add edi, 0x4
         // 00402181: mov eax, ds:[ebx]
         // 00402183: add ebx, 0x4
         // 00402186: mov ds:[edi], eax
         // 00402188: add edi, 0x4
         // 0040218b: mov eax, ds:[ebx]
         // 0040218d: add ebx, 0x4
         // 00402190: mov ds:[edi], eax
         // 00402192: add edi, 0x4
         // 00402195: mov eax, ds:[ebx]
         // 00402197: add ebx, 0x4
         // 0040219a: mov ds:[edi], eax
         // 0040219c: add edi, 0x4
         // 0040219f: mov eax, ds:[ebx]
         // 004021a1: add ebx, 0x4
         // 004021a4: mov ds:[edi], eax
         // 004021a6: add edi, 0x4
         // 004021a9: mov eax, ds:[ebx]
         // 004021ab: add ebx, 0x4
         // 004021ae: mov ds:[edi], eax
         // 004021b0: add edi, 0x4
         // 004021b3: mov eax, ds:[ebx]
         // 004021b5: add ebx, 0x4
         // 004021b8: mov ds:[edi], eax
         // 004021ba: add edi, 0x4
         // 004021bd: push ebx
         // 004021be: push edi
         // 004021bf: push 0x1
         // 004021c1: mov eax, 0x2
         // 004021c6: call 0x4d816d
         // 004021cb: add esp, 0x4
         // 004021ce: pop edi
         // 004021cf: pop ebx
         // 004021d0: push ebx
         // 004021d1: push edi
         // 004021d2: mov edi, ds:[edi]
         // 004021d4: mov ecx, ds:[edi]
         // 004021d6: add edi, 0x4
         // 004021d9: test ecx, ecx
         // 004021db: jz 0x4021ec
      [-]83c704497405
         // 004021df: add edi, 0x4
         // 004021e2: dec ecx
         // 004021e3: jz 0x4021ea
      [-]0faf07ebf5
         // 004021e5: imul eax, ds:[edi]
         // 004021e8: jmp 0x4021df
      [-]81f9????????7e05
         // 004021ec: cmp ecx, 0x100
         // 004021f2: jle 0x4021f9
      [-]b9????????
         // 004021f4: mov ecx, 0x100
      [-]8bf3f3a45f5b83c70481c3????????e8665f0d0083c404588945f4e9a2fdffff
         // 004021f9: mov esi, ebx
         // 004021fb: rep movsbb 
         // 004021fd: pop edi
         // 004021fe: pop ebx
         // 004021ff: add edi, 0x4
         // 00402202: add ebx, 0x100
         // 00402208: call 0x4d8173
         // 0040220d: add esp, 0x4
         // 00402210: pop eax
         // 00402211: mov ss:[ebp+0xfffffffffffffff4], eax
         // 00402214: jmp 0x401fbb
      [-]e9d0020000
         // 00402219: jmp 0x4024ee
      [-]837df4000f84c6020000
         // 0040221e: cmp ss:[ebp+0xfffffffffffffff4], 0x0
         // 00402222: jz 0x4024ee
      [-]8b5df883c324895df068????????6a008b5df0ff3368????????bb????????e83f5f0d0083c4108945ec68????????6a008b45ec85c07505
         // 00402228: mov ebx, ss:[ebp+0xfffffffffffffff8]
         // 0040222b: add ebx, 0x24
         // 0040222e: mov ss:[ebp+0xfffffffffffffff0], ebx
         // 00402231: push 0xffffffffa0000101
         // 00402236: push 0x0
         // 00402238: mov ebx, ss:[ebp+0xfffffffffffffff0]
         // 0040223b: push ds:[ebx]
         // 0040223d: push 0x1
         // 00402242: mov ebx, 0x4da970
         // 00402247: call 0x4d818b
         // 0040224c: add esp, 0x10
         // 0040224f: mov ss:[ebp+0xffffffffffffffec], eax
         // 00402252: push 0xffffffff80000004
         // 00402257: push 0x0
         // 00402259: mov eax, ss:[ebp+0xffffffffffffffec]
         // 0040225c: test eax, eax
         // 0040225e: jnz 0x402265
      [-]b8????????
         // 00402260: mov eax, 0x58d31d
      [-]5068????????bb????????e8165f0d0083c4108945e88b5dec85db7409
         // 00402265: push eax
         // 00402266: push 0x1
         // 0040226b: mov ebx, 0x4d91d0
         // 00402270: call 0x4d818b
         // 00402275: add esp, 0x10
         // 00402278: mov ss:[ebp+0xffffffffffffffe8], eax
         // 0040227b: mov ebx, ss:[ebp+0xffffffffffffffec]
         // 0040227e: test ebx, ebx
         // 00402280: jz 0x40228b
      [-]53e8eb5e0d0083c404
         // 00402282: push ebx
         // 00402283: call 0x4d8173
         // 00402288: add esp, 0x4
      [-]68????????6a008b5d108b0385c07505
         // 0040228b: push 0xffffffff80000004
         // 00402290: push 0x0
         // 00402292: mov ebx, ss:[ebp+0x10]
         // 00402295: mov eax, ds:[ebx]
         // 00402297: test eax, eax
         // 00402299: jnz 0x4022a0
      [-]b8????????
         // 0040229b: mov eax, 0x58d31d
      [-]5068????????bb????????e8db5e0d0083c4108945e48b45e450ff75e8e87bedffff
         // 004022a0: push eax
         // 004022a1: push 0x1
         // 004022a6: mov ebx, 0x4d91d0
         // 004022ab: call 0x4d818b
         // 004022b0: add esp, 0x10
         // 004022b3: mov ss:[ebp+0xffffffffffffffe4], eax
         // 004022b6: mov eax, ss:[ebp+0xffffffffffffffe4]
         // 004022b9: push eax
         // 004022ba: push ss:[ebp+0xffffffffffffffe8]
         // 004022bd: call 0x40103d
         // 004022c2: add esp, 0x8
         // 004022c5: cmp eax, 0x0
         // 004022c8: mov eax, 0x0
         // 004022cd: setz b1 al
         // 004022d0: mov ss:[ebp+0xffffffffffffffe0], eax
         // 004022d3: mov ebx, ss:[ebp+0xffffffffffffffe8]
         // 004022d6: test ebx, ebx
         // 004022d8: jz 0x4022e3

  }
  condition:
    all of them
}
