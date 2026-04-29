rule necurs_30_2 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         8b45d0c1c806b9????????81e9????????03c105????????8945fce9a8020000
         // 00401010: mov eax, ss:[ebp+0xffffffffffffffd0]
         // 00401013: ror eax, b1 0x6
         // 00401016: mov ecx, 0x7d0f93d9
         // 0040101b: sub ecx, 0x7d0f63d9
         // 00401021: add eax, ecx
         // 00401023: add eax, 0x19c5c8d1
         // 00401028: mov ss:[ebp+0xfffffffffffffffc], eax
         // 0040102b: jmp 0x4012d8
      [-]8b138b4da0c1c10d03d9e951070000
         // 00401044: mov edx, ds:[ebx]
         // 00401046: mov ecx, ss:[ebp+0xffffffffffffffa0]
         // 00401049: rol ecx, b1 0xd
         // 0040104c: add ebx, ecx
         // 0040104e: jmp 0x4017a4
      [-]8b75b881f6????????ba????????c1c20623f2b8????????c1c809b9????????81c1????????e9f1040000
         // 0040105c: mov esi, ss:[ebp+0xffffffffffffffb8]
         // 0040105f: xor esi, 0xffffffffb3071591
         // 00401065: mov edx, 0x3fffc00
         // 0040106a: rol edx, b1 0x6
         // 0040106d: and esi, edx
         // 0040106f: mov eax, 0xb49a00
         // 00401074: ror eax, b1 0x9
         // 00401077: mov ecx, 0x1246a5d6
         // 0040107c: add ecx, 0xffffffffedba5a29
         // 00401082: jmp 0x401578
      [-]8b0303c7ba????????81ea????????03da35????????8945ac03cd51e867040000565a592bcd8b55ec81c2????????03d13bd10f85b7020000
         // 00401128: mov eax, ds:[ebx]
         // 0040112a: add eax, edi
         // 0040112c: mov edx, 0xffffffffe32f30b9
         // 00401131: sub edx, 0xffffffffe32f30b5
         // 00401137: add ebx, edx
         // 00401139: xor eax, 0x1ef93e92
         // 0040113e: mov ss:[ebp+0xffffffffffffffac], eax
         // 00401141: add ecx, ebp
         // 00401143: push ecx
         // 00401144: call 0x4015b0
         // 00401149: push esi
         // 0040114a: pop edx
         // 0040114b: pop ecx
         // 0040114c: sub ecx, ebp
         // 0040114e: mov edx, ss:[ebp+0xffffffffffffffec]
         // 00401151: add edx, 0xfffffffff9be0d0b
         // 00401157: add edx, ecx
         // 00401159: cmp edx, ecx
         // 0040115b: jnz 0x401418
      [-]2bd1493bca75c0
         // 00401161: sub edx, ecx
         // 00401163: dec ecx
         // 00401164: cmp ecx, edx
         // 00401166: jnz 0x401128
      [-]e9fb020000
         // 00401168: jmp 0x401468
      [-]33d033f6b9????????81f1????????e9c4020000
         // 00401174: xor edx, eax
         // 00401176: xor esi, esi
         // 00401178: mov ecx, 0x72fa1631
         // 0040117d: xor ecx, 0xffffffff8dfa1631
         // 00401183: jmp 0x40144c
      [-]81c2????????8955ec5b5e5fc3
         // 004011bc: add edx, 0x641f2f5
         // 004011c2: mov ss:[ebp+0xffffffffffffffec], edx
         // 004011c5: pop ebx
         // 004011c6: pop esi
         // 004011c7: pop edi
         // 004011c8: retn 
      [-]5753568b7d9081f7????????8b5de081f3????????8b75fc81c6????????4f85ff0f8495000000
         // 004011d4: push edi
         // 004011d5: push ebx
         // 004011d6: push esi
         // 004011d7: mov edi, ss:[ebp+0xffffffffffffff90]
         // 004011da: xor edi, 0xffffffffba72a61d
         // 004011e0: mov ebx, ss:[ebp+0xffffffffffffffe0]
         // 004011e3: xor ebx, 0x3f71e254
         // 004011e9: mov esi, ss:[ebp+0xfffffffffffffffc]
         // 004011ec: add esi, 0xffffffffe63a372f
         // 004011f2: dec edi
         // 004011f3: test edi, edi
         // 004011f5: jz 0x401290
      [-]e9e4040000
         // 004011fb: jmp 0x4016e4
      [-]8b138b4db481e9????????03d9e902050000
         // 00401290: mov edx, ds:[ebx]
         // 00401292: mov ecx, ss:[ebp+0xffffffffffffffb4]
         // 00401295: sub ecx, 0xffffffffabfa527c
         // 0040129b: add ebx, ecx
         // 0040129d: jmp 0x4017a4
      [-]35????????8945ac5b5e5fc3
         // 004012a8: xor eax, 0x1ef93e92
         // 004012ad: mov ss:[ebp+0xffffffffffffffac], eax
         // 004012b0: pop ebx
         // 004012b1: pop esi
         // 004012b2: pop edi
         // 004012b3: retn 
      [-]68????????e8466e0000c3
         // 004012b8: push 0x40d435
         // 004012bd: call LoadLibraryA
         // 004012c2: retn 
      [-]42e9eafeffff
         // 004012cc: inc edx
         // 004012cd: jmp 0x4011bc
      [-]8b5dd8c1cb130fb6034343c1cb0d895dd8b9????????c1c1033bc17223
         // 004012d8: mov ebx, ss:[ebp+0xffffffffffffffd8]
         // 004012db: ror ebx, b1 0x13
         // 004012de: movzx eax, b1 ds:[ebx]
         // 004012e1: inc ebx
         // 004012e2: inc ebx
         // 004012e3: ror ebx, b1 0xd
         // 004012e6: mov ss:[ebp+0xffffffffffffffd8], ebx
         // 004012e9: mov ecx, 0x18
         // 004012ee: rol ecx, b1 0x3
         // 004012f1: cmp eax, ecx
         // 004012f3: jb 0x401318
      [-]2bc103c08b55fc81c2????????03d003d081c2????????8955fc85c075c5
         // 004012f5: sub eax, ecx
         // 004012f7: add eax, eax
         // 004012f9: mov edx, ss:[ebp+0xfffffffffffffffc]
         // 004012fc: add edx, 0xffffffffe63a372f
         // 00401302: add edx, eax
         // 00401304: add edx, eax
         // 00401306: add edx, 0x19c5c8d1
         // 0040130c: mov ss:[ebp+0xfffffffffffffffc], edx
         // 0040130f: test eax, eax
         // 00401311: jnz 0x4012d8
      [-]b9????????894db4ba????????8955a0b9????????81e9????????3bc10f826d030000
         // 00401318: mov ecx, 0xffffffffabfa5280
         // 0040131d: mov ss:[ebp+0xffffffffffffffb4], ecx
         // 00401320: mov edx, 0x200000
         // 00401325: mov ss:[ebp+0xffffffffffffffa0], edx
         // 00401328: mov ecx, 0xffffffffb0d71087
         // 0040132d: sub ecx, 0xffffffffb0d71047
         // 00401333: cmp eax, ecx
         // 00401335: jb 0x4016a8
      [-]2bc13bc10f83af000000
         // 0040133b: sub eax, ecx
         // 0040133d: cmp eax, ecx
         // 0040133f: jnb 0x4013f4
      [-]b9????????894db4e956030000
         // 00401345: mov ecx, 0xffffffffabfa5284
         // 0040134a: mov ss:[ebp+0xffffffffffffffb4], ecx
         // 0040134d: jmp 0x4016a8
      [-]03c7e90effffff
         // 00401393: add eax, edi
         // 00401395: jmp 0x4012a8
      [-]5756538b7dc481c7????????b9????????81f1????????3bf90f82d5020000
         // 004013a4: push edi
         // 004013a5: push esi
         // 004013a6: push ebx
         // 004013a7: mov edi, ss:[ebp+0xffffffffffffffc4]
         // 004013aa: add edi, 0xffffffffd09a7526
         // 004013b0: mov ecx, 0xffffffffc6ac8d94
         // 004013b5: xor ecx, 0xffffffffc6ad8d94
         // 004013bb: cmp edi, ecx
         // 004013bd: jb 0x401698
      [-]b8????????35????????03c78b1003d7bb????????81f3????????03da8b3303f7e9b3000000
         // 004013c3: mov eax, 0x3027e20b
         // 004013c8: xor eax, 0x3027e237
         // 004013cd: add eax, edi
         // 004013cf: mov edx, ds:[eax]
         // 004013d1: add edx, edi
         // 004013d3: mov ebx, 0x4c6e5b90
         // 004013d8: xor ebx, 0x4c6e5be8
         // 004013de: add ebx, edx
         // 004013e0: mov esi, ds:[ebx]
         // 004013e2: add esi, edi
         // 004013e4: jmp 0x40149c
      [-]ba????????d1ca03d68b0aba????????81f2????????03d68b1a03dfe96bfcffff
         // 0040149c: mov edx, 0x30
         // 004014a1: ror edx, b1 0x1
         // 004014a3: add edx, esi
         // 004014a5: mov ecx, ds:[edx]
         // 004014a7: mov edx, 0x3fea570a
         // 004014ac: xor edx, 0x3fea572a
         // 004014b2: add edx, esi
         // 004014b4: mov ebx, ds:[edx]
         // 004014b6: add ebx, edi
         // 004014b8: jmp 0x401128
      [-]558bec81ec????????e82a6c000068????????6a0850e8236c00008bd868????????536a00e8fc6b000053e8fc6b0000e8bffdffffbe????????68????????e8e86b00008bf868????????57e8e16b000085c07445
         // 004014c4: push ebp
         // 004014c5: mov ebp, esp
         // 004014c7: sub esp, 0x3a0
         // 004014cd: call GetProcessHeap
         // 004014d2: push 0x104
         // 004014d7: push 0x8
         // 004014d9: push eax
         // 004014da: call HeapAlloc
         // 004014df: mov ebx, eax
         // 004014e1: push 0x104
         // 004014e6: push ebx
         // 004014e7: push 0x0
         // 004014e9: call GetModuleFileNameA
         // 004014ee: push ebx
         // 004014ef: call GetModuleHandleA
         // 004014f4: call 0x4012b8
         // 004014f9: mov esi, 0x40d40d
         // 004014fe: push 0x40d450
         // 00401503: call GetModuleHandleA
         // 00401508: mov edi, eax
         // 0040150a: push 0x40d45a
         // 0040150f: push edi
         // 00401510: call GetProcAddress
         // 00401515: test eax, eax
         // 00401517: jz 0x40155e
      [-]8bd86a006a00ffd385c07539
         // 00401519: mov ebx, eax
         // 0040151b: push 0x0
         // 0040151d: push 0x0
         // 0040151f: call ebx
         // 00401521: test eax, eax
         // 00401523: jnz 0x40155e
      [-]6a006a00ffd3487530
         // 00401525: push 0x0
         // 00401527: push 0x0
         // 00401529: call ebx
         // 0040152b: dec eax
         // 0040152c: jnz 0x40155e
      [-]68????????57e8bd6b000085c07421
         // 0040152e: push 0x40d43f
         // 00401533: push edi
         // 00401534: call GetProcAddress
         // 00401539: test eax, eax
         // 0040153b: jz 0x40155e
      [-]8bd868????????68????????6a006a0568????????ffd385c07506
         // 0040153d: mov ebx, eax
         // 0040153f: push 0x40d431
         // 00401544: push 0x40d421
         // 00401549: push 0x0
         // 0040154b: push 0x5
         // 0040154d: push 0x40d411
         // 00401552: call ebx
         // 00401554: test eax, eax
         // 00401556: jnz 0x40155e
      [-]81c6????????
         // 00401558: add esi, 0xffffffffffffffe8
      [-]568b0605????????ffd05e83c604ebf0
         // 0040155e: push esi
         // 0040155f: mov eax, ds:[esi]
         // 00401561: add eax, 0x401698
         // 00401566: call eax
         // 00401568: pop esi
         // 00401569: add esi, 0x4
         // 0040156c: jmp 0x40155e
      [-]8b162bf123d14e3bd075f5
         // 00401578: mov edx, ds:[esi]
         // 0040157a: sub esi, ecx
         // 0040157c: and edx, ecx
         // 0040157e: dec esi
         // 0040157f: cmp edx, eax
         // 00401581: jnz 0x401578
      [-]b9????????81f1????????03ce81c1????????894dc4c3
         // 00401594: mov ecx, 0x672438fe
         // 00401599: xor ecx, 0x672538fe
         // 0040159f: add ecx, esi
         // 004015a1: add ecx, 0x2f658ada
         // 004015a7: mov ss:[ebp+0xffffffffffffffc4], ecx
         // 004015aa: retn 
      [-]5756538b5dac81f3????????8b138b85????????2d????????3bd00f85a3fbffff
         // 004015b0: push edi
         // 004015b1: push esi
         // 004015b2: push ebx
         // 004015b3: mov ebx, ss:[ebp+0xffffffffffffffac]
         // 004015b6: xor ebx, 0x1ef93e92
         // 004015bc: mov edx, ds:[ebx]
         // 004015be: mov eax, ss:[ebp+0xffffffffffffff7c]
         // 004015c4: sub eax, 0x3b6c95f6
         // 004015c9: cmp edx, eax
         // 004015cb: jnz 0x401174
      [-]ba????????81c2????????03da8b138b458cc1c0063bd00f8586fbffff
         // 004015d1: mov edx, 0x7ffeddbb
         // 004015d6: add edx, 0xffffffff80012249
         // 004015dc: add ebx, edx
         // 004015de: mov edx, ds:[ebx]
         // 004015e0: mov eax, ss:[ebp+0xffffffffffffff8c]
         // 004015e3: rol eax, b1 0x6
         // 004015e6: cmp edx, eax
         // 004015e8: jnz 0x401174
      [-]ba????????c1c20603da8b138b459835????????3bd00f856afbffff
         // 004015ee: mov edx, 0x10000000
         // 004015f3: rol edx, b1 0x6
         // 004015f6: add ebx, edx
         // 004015f8: mov edx, ds:[ebx]
         // 004015fa: mov eax, ss:[ebp+0xffffffffffffff98]
         // 004015fd: xor eax, 0x1fbca01b
         // 00401602: cmp edx, eax
         // 00401604: jnz 0x401174
      [-]ba????????81f2????????03da8b138b459c35????????3bd00f854bfbffff
         // 0040160a: mov edx, 0x62633fa5
         // 0040160f: xor edx, 0x62633fa1
         // 00401615: add ebx, edx
         // 00401617: mov edx, ds:[ebx]
         // 00401619: mov eax, ss:[ebp+0xffffffffffffff9c]
         // 0040161c: xor eax, 0x7971152f
         // 00401621: cmp edx, eax
         // 00401623: jnz 0x401174
      [-]ba????????81c2????????03da8b138b45dc05????????3bd00f852cfbffff
         // 00401629: mov edx, 0xffffffff9c87fd0f
         // 0040162e: add edx, 0x637802f5
         // 00401634: add ebx, edx
         // 00401636: mov edx, ds:[ebx]
         // 00401638: mov eax, ss:[ebp+0xffffffffffffffdc]
         // 0040163b: add eax, 0xffffffff82b5e19d
         // 00401640: cmp edx, eax
         // 00401642: jnz 0x401174
      [-]e97ffcffff
         // 00401648: jmp 0x4012cc
      [-]8b45c82d????????50c3
         // 00401654: mov eax, ss:[ebp+0xffffffffffffffc8]
         // 00401657: sub eax, 0xffffffffdb835015
         // 0040165c: push eax
         // 0040165d: retn 
      [-]3bd60f8444fcffff
         // 00401680: cmp edx, esi
         // 00401682: jz 0x4012cc
      [-]8bd6e92dfbffff
         // 00401688: mov edx, esi
         // 0040168a: jmp 0x4011bc
      [-]8be55dc21000
         // 00401698: mov esp, ebp
         // 0040169a: pop ebp
         // 0040169b: retn b2 0x10
      [-]35????????894590e81ffbffff535ae91cfcffff
         // 004016a8: xor eax, 0xffffffffba72a61d
         // 004016ad: mov ss:[ebp+0xffffffffffffff90], eax
         // 004016b0: call 0x4011d4
         // 004016b5: push ebx
         // 004016b6: pop edx
         // 004016b7: jmp 0x4012d8
      [-]8b138b4db481c1????????03d98b03c1c00b83e00503d04f8916b9????????81c1????????03f185ff0f8431f9ffff
         // 004016e4: mov edx, ds:[ebx]
         // 004016e6: mov ecx, ss:[ebp+0xffffffffffffffb4]
         // 004016e9: add ecx, 0x5405ad84
         // 004016ef: add ebx, ecx
         // 004016f1: mov eax, ds:[ebx]
         // 004016f3: rol eax, b1 0xb
         // 004016f6: and eax, 0x5
         // 004016f9: add edx, eax
         // 004016fb: dec edi
         // 004016fc: mov ds:[esi], edx
         // 004016fe: mov ecx, 0x40fe0cd7
         // 00401703: add ecx, 0xffffffffbf01f32d
         // 00401709: add esi, ecx
         // 0040170b: test edi, edi
         // 0040170d: jz 0x401044
      [-]8b138b4da0c1c91303d98b03c1c00b83e00503d04f8916b9????????c1c90703f185ff75ac
         // 00401713: mov edx, ds:[ebx]
         // 00401715: mov ecx, ss:[ebp+0xffffffffffffffa0]
         // 00401718: ror ecx, b1 0x13
         // 0040171b: add ebx, ecx
         // 0040171d: mov eax, ds:[ebx]
         // 0040171f: rol eax, b1 0xb
         // 00401722: and eax, 0x5
         // 00401725: add edx, eax
         // 00401727: dec edi
         // 00401728: mov ds:[esi], edx
         // 0040172a: mov ecx, 0x200
         // 0040172f: ror ecx, b1 0x7
         // 00401732: add esi, ecx
         // 00401734: test edi, edi
         // 00401736: jnz 0x4016e4
      [-]e953fbffff
         // 00401738: jmp 0x401290
      [-]b8????????35????????03d08916b9????????c1c90603f1ba????????c1ca0203da81f3????????895de081ee????????8975fc5e5b5fc3
         // 004017a4: mov eax, 0xffffffff9317b0d9
         // 004017a9: xor eax, 0x714dc833
         // 004017ae: add edx, eax
         // 004017b0: mov ds:[esi], edx
         // 004017b2: mov ecx, 0x100
         // 004017b7: ror ecx, b1 0x6
         // 004017ba: add esi, ecx
         // 004017bc: mov edx, 0x4
         // 004017c1: ror edx, b1 0x2
         // 004017c4: add ebx, edx
         // 004017c6: xor ebx, 0x3f71e254
         // 004017cc: mov ss:[ebp+0xffffffffffffffe0], ebx
         // 004017cf: sub esi, 0xffffffffe63a372f
         // 004017d5: mov ss:[ebp+0xfffffffffffffffc], esi
         // 004017d8: pop esi
         // 004017d9: pop ebx
         // 004017da: pop edi
         // 004017db: retn 
      [-]8b4c24045633f63bce751d
         // 00402381: mov ecx, ss:[esp+0x4]
         // 00402385: push esi
         // 00402386: xor esi, esi
         // 00402388: cmp ecx, esi
         // 0040238a: jnz 0x4023a9
      [-]e8451700005656565656c700????????e8d616000083c4146a16585ec3
         // 0040238c: call __errno
         // 00402391: push esi
         // 00402392: push esi
         // 00402393: push esi
         // 00402394: push esi
         // 00402395: push esi
         // 00402396: mov ds:[eax], 0x16
         // 0040239c: call __invalid_parameter
         // 004023a1: add esp, 0x14
         // 004023a4: push 0x16
         // 004023a6: pop eax
         // 004023a7: pop esi
         // 004023a8: retn 
      [-]a1????????3bc674da
         // 004023a9: mov eax, ds:[0x40e130]
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
      [-]e80e1700005656565656c700????????e89f16000083c4146a16585ec3
         // 004023c3: call __errno
         // 004023c8: push esi
         // 004023c9: push esi
         // 004023ca: push esi
         // 004023cb: push esi
         // 004023cc: push esi
         // 004023cd: mov ds:[eax], 0x16
         // 004023d3: call __invalid_parameter
         // 004023d8: add esp, 0x14
         // 004023db: push 0x16
         // 004023dd: pop eax
         // 004023de: pop esi
         // 004023df: retn 
      [-]3935????????74db
         // 004023e0: cmp ds:[0x40e130], esi
         // 004023e6: jz 0x4023c3
      [-]8b0d????????890833c05ec3
         // 004023e8: mov ecx, ds:[0x40e13c]
         // 004023ee: mov ds:[eax], ecx
         // 004023f0: xor eax, eax
         // 004023f2: pop esi
         // 004023f3: retn 
      [-]5657b8????????bf????????3bc78bf0730f
         // 00402f10: push esi
         // 00402f11: push edi
         // 00402f12: mov eax, 0x40a860
         // 00402f17: mov edi, 0x40a860
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
      [-]5657b8????????bf????????3bc78bf0730f
         // 00402f34: push esi
         // 00402f35: push edi
         // 00402f36: mov eax, 0x40a868
         // 00402f3b: mov edi, 0x40a868
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
      [-]8b442404a3????????c3
         // 00403971: mov eax, ss:[esp+0x4]
         // 00403975: mov ds:[0x40e808], eax
         // 0040397a: retn 
      [-]ff35????????e803f2ffff59c3
         // 00403db6: push ds:[0x40e818]
         // 00403dbc: call __decode_pointer
         // 00403dc1: pop ecx
         // 00403dc2: retn 
      [-]8b442404a3????????c3
         // 00403f73: mov eax, ss:[esp+0x4]
         // 00403f77: mov ds:[0x40e824], eax
         // 00403f7c: retn 
      [-]8b442404a3????????c3
         // 00403f7d: mov eax, ss:[esp+0x4]
         // 00403f81: mov ds:[0x40e830], eax
         // 00403f86: retn 
      [-]8b442404a3????????c3
         // 00403f87: mov eax, ss:[esp+0x4]
         // 00403f8b: mov ds:[0x40e834], eax
         // 00403f90: retn 
      [-]8b442404a3????????c3
         // 00404066: mov eax, ss:[esp+0x4]
         // 0040406a: mov ds:[0x40e838], eax
         // 0040406f: retn 
      [-]558bec83ec20535657e81befffff33db391d????????8945f0895dfc895df8895df40f85ad000000
         // 00404092: push ebp
         // 00404093: mov ebp, esp
         // 00404095: sub esp, 0x20
         // 00404098: push ebx
         // 00404099: push esi
         // 0040409a: push edi
         // 0040409b: call __encoded_null
         // 004040a0: xor ebx, ebx
         // 004040a2: cmp ds:[0x40e83c], ebx
         // 004040a8: mov ss:[ebp+0xfffffffffffffff0], eax
         // 004040ab: mov ss:[ebp+0xfffffffffffffffc], ebx
         // 004040ae: mov ss:[ebp+0xfffffffffffffff8], ebx
         // 004040b1: mov ss:[ebp+0xfffffffffffffff4], ebx
         // 004040b4: jnz 0x404167
      [-]68????????ff151c9040008bf83bfb7507
         // 004040ba: push 0x409df0
         // 004040bf: call ds:[__imp_LoadLibraryA]
         // 004040c5: mov edi, eax
         // 004040c7: cmp edi, ebx
         // 004040c9: jnz 0x4040d2
      [-]33c0e959010000
         // 004040cb: xor eax, eax
         // 004040cd: jmp 0x40422b
      [-]8b351090400068????????57ffd63bc374e7
         // 004040d2: mov esi, ds:[__imp_GetProcAddress]
         // 004040d8: push 0x409de4
         // 004040dd: push edi
         // 004040de: call esi
         // 004040e0: cmp eax, ebx
         // 004040e2: jz 0x4040cb
      [-]50e86eeeffffc70424????????57a3????????ffd650e859eeffffc70424????????57a3????????ffd650e844eeffffa3????????8d45f850e85fe2ffff85c05959740d
         // 004040e4: push eax
         // 004040e5: call __encode_pointer
         // 004040ea: mov ss:[esp], 0x409dd4
         // 004040f1: push edi
         // 004040f2: mov ds:[0x40e83c], eax
         // 004040f7: call esi
         // 004040f9: push eax
         // 004040fa: call __encode_pointer
         // 004040ff: mov ss:[esp], 0x409dc0
         // 00404106: push edi
         // 00404107: mov ds:[0x40e840], eax
         // 0040410c: call esi
         // 0040410e: push eax
         // 0040410f: call __encode_pointer
         // 00404114: mov ds:[0x40e844], eax
         // 00404119: lea eax, ss:[ebp+0xfffffffffffffff8]
         // 0040411c: push eax
         // 0040411d: call 0x402381
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
      [-]68????????57ffd650e80feeffff3bc359a3????????7414
         // 0040413b: push 0x409da4
         // 00404140: push edi
         // 00404141: call esi
         // 00404143: push eax
         // 00404144: call __encode_pointer
         // 00404149: cmp eax, ebx
         // 0040414b: pop ecx
         // 0040414c: mov ds:[0x40e84c], eax
         // 00404151: jz 0x404167
      [-]68????????57ffd650e8f7edffff59a3????????
         // 00404153: push 0x409d8c
         // 00404158: push edi
         // 00404159: call esi
         // 0040415b: push eax
         // 0040415c: call __encode_pointer
         // 00404161: pop ecx
         // 00404162: mov ds:[0x40e848], eax
      [-]a1????????8b75f03bc6746d
         // 00404167: mov eax, ds:[0x40e848]
         // 0040416c: mov esi, ss:[ebp+0xfffffffffffffff0]
         // 0040416f: cmp eax, esi
         // 00404171: jz 0x4041e0
      [-]3935????????7465
         // 00404173: cmp ds:[0x40e84c], esi
         // 00404179: jz 0x4041e0
      [-]50e843eeffff59ffd03bc37425
         // 0040417b: push eax
         // 0040417c: call __decode_pointer
         // 00404181: pop ecx
         // 00404182: call eax
         // 00404184: cmp eax, ebx
         // 00404186: jz 0x4041ad
      [-]8d4dec516a0c8d4de0516a0150ff35????????e824eeffff59ffd085c07406
         // 00404188: lea ecx, ss:[ebp+0xffffffffffffffec]
         // 0040418b: push ecx
         // 0040418c: push 0xc
         // 0040418e: lea ecx, ss:[ebp+0xffffffffffffffe0]
         // 00404191: push ecx
         // 00404192: push 0x1
         // 00404194: push eax
         // 00404195: push ds:[0x40e84c]
         // 0040419b: call __decode_pointer
         // 004041a0: pop ecx
         // 004041a1: call eax
         // 004041a3: test eax, eax
         // 004041a5: jz 0x4041ad
      [-]f645e8017533
         // 004041a7: test b1 ss:[ebp+0xffffffffffffffe8], b1 0x1
         // 004041ab: jnz 0x4041e0
      [-]8d45f450e802e2ffff85c059740d
         // 004041ad: lea eax, ss:[ebp+0xfffffffffffffff4]
         // 004041b0: push eax
         // 004041b1: call 0x4023b8
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
      [-]a1????????3bc67428
         // 004041e0: mov eax, ds:[0x40e840]
         // 004041e5: cmp eax, esi
         // 004041e7: jz 0x404211
      [-]50e8d5edffff59ffd03bc38945fc7418
         // 004041e9: push eax
         // 004041ea: call __decode_pointer
         // 004041ef: pop ecx
         // 004041f0: call eax
         // 004041f2: cmp eax, ebx
         // 004041f4: mov ss:[ebp+0xfffffffffffffffc], eax
         // 004041f7: jz 0x404211
      [-]a1????????3bc6740f
         // 004041f9: mov eax, ds:[0x40e844]
         // 004041fe: cmp eax, esi
         // 00404200: jz 0x404211
      [-]ff75fc50e8b9edffff59ffd08945fc
         // 00404202: push ss:[ebp+0xfffffffffffffffc]
         // 00404205: push eax
         // 00404206: call __decode_pointer
         // 0040420b: pop ecx
         // 0040420c: call eax
         // 0040420e: mov ss:[ebp+0xfffffffffffffffc], eax
      [-]ff7510ff750cff7508ff75fcff35????????e89cedffff59ffd0
         // 00404211: push ss:[ebp+0x10]
         // 00404214: push ss:[ebp+0xc]
         // 00404217: push ss:[ebp+0x8]
         // 0040421a: push ss:[ebp+0xfffffffffffffffc]
         // 0040421d: push ds:[0x40e83c]
         // 00404223: call __decode_pointer
         // 00404228: pop ecx
         // 00404229: call eax
      [-]5f5e5bc9c3
         // 0040422b: pop edi
         // 0040422c: pop esi
         // 0040422d: pop ebx
         // 0040422e: leave 
         // 0040422f: retn 
      [-]8325????????00c3
         // 0040605f: and ds:[0x40ec90], 0x0
         // 00406066: retn 
      [-]e89bffffffa3????????33c0c3
         // 004079ec: call __get_sse2_info
         // 004079f1: mov ds:[0x40ec8c], eax
         // 004079f6: xor eax, eax
         // 004079f8: retn 

  }
  condition:
    all of them
}
