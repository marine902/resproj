rule buzus_10_4 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         c701fc914100e955550000
         // 00401000: mov ds:[ecx], ??_7bad_alloc@std@@6B@
         // 00401006: jmp 0x406560
      [-]568bf1c706fc914100e842550000f6442408017409
         // 00401010: push esi
         // 00401011: mov esi, ecx
         // 00401013: mov ds:[esi], ??_7bad_alloc@std@@6B@
         // 00401019: call 0x406560
         // 0040101e: test b1 ss:[esp+0x8], b1 0x1
         // 00401023: jz 0x40102e
      [-]56e8d257000083c404
         // 00401025: push esi
         // 00401026: call j__free
         // 0040102b: add esp, 0x4
      [-]8bc65ec20400
         // 0040102e: mov eax, esi
         // 00401030: pop esi
         // 00401031: retn b2 0x4
      [-]558bec6afe68d8cb410068a0bd400064a1????????5083ec14535657a184e141003145f833c5508d45f064a3????????8965e833c08845e78945fc53bb????????b8????????0f3f070b85db0f9445e75beb38
         // 00401040: push ebp
         // 00401041: mov ebp, esp
         // 00401043: push 0xfffffffffffffffe
         // 00401045: push stru_41CBD8.GSCookieOffset
         // 0040104a: push __except_handler4
         // 0040104f: mov eax, fs:[0x0]
         // 00401055: push eax
         // 00401056: sub esp, 0x14
         // 00401059: push ebx
         // 0040105a: push esi
         // 0040105b: push edi
         // 0040105c: mov eax, ds:[___security_cookie]
         // 00401061: xor ss:[ebp+0xfffffffffffffff8], eax
         // 00401064: xor eax, ebp
         // 00401066: push eax
         // 00401067: lea eax, ss:[ebp+0xfffffffffffffff0]
         // 0040106a: mov fs:[0x0], eax
         // 00401070: mov ss:[ebp+0xffffffffffffffe8], esp
         // 00401073: xor eax, eax
         // 00401075: mov b1 ss:[ebp+0xffffffffffffffe7], b1 al
         // 00401078: mov ss:[ebp+0xfffffffffffffffc], eax
         // 0040107b: push ebx
         // 0040107c: mov ebx, 0x0
         // 00401081: mov eax, 0x1
         // 00401086: vpcext b1 0x7, b1 0xb
         // 0040108a: test ebx, ebx
         // 0040108c: setz b1 ss:[ebp+0xffffffffffffffe7]
         // 00401090: pop ebx
         // 00401091: jmp 0x4010cb
      [-]c745fc????????8a45e78b4df064890d????????595f5e5b8be55dc3
         // 004010cb: mov ss:[ebp+0xfffffffffffffffc], 0xfffffffffffffffe
         // 004010d2: mov b1 al, b1 ss:[ebp+0xffffffffffffffe7]
         // 004010d5: mov ecx, ss:[ebp+0xfffffffffffffff0]
         // 004010d8: mov fs:[0x0], ecx
         // 004010df: pop ecx
         // 004010e0: pop edi
         // 004010e1: pop esi
         // 004010e2: pop ebx
         // 004010e3: mov esp, ebp
         // 004010e5: pop ebp
         // 004010e6: retn 
      [-]558bec6afe68b8cb410068a0bd400064a1????????5083ec0c535657a184e141003145f833c5508d45f064a3????????8965e8c645e701c745fc????????525153b8????????bb????????b9????????ba????????ed81fb????????0f9445e75b595ac745fc????????8a45e78b4df064890d????????595f5e5b8be55dc3
         // 004010f0: push ebp
         // 004010f1: mov ebp, esp
         // 004010f3: push 0xfffffffffffffffe
         // 004010f5: push stru_41CBB8.GSCookieOffset
         // 004010fa: push __except_handler4
         // 004010ff: mov eax, fs:[0x0]
         // 00401105: push eax
         // 00401106: sub esp, 0xc
         // 00401109: push ebx
         // 0040110a: push esi
         // 0040110b: push edi
         // 0040110c: mov eax, ds:[___security_cookie]
         // 00401111: xor ss:[ebp+0xfffffffffffffff8], eax
         // 00401114: xor eax, ebp
         // 00401116: push eax
         // 00401117: lea eax, ss:[ebp+0xfffffffffffffff0]
         // 0040111a: mov fs:[0x0], eax
         // 00401120: mov ss:[ebp+0xffffffffffffffe8], esp
         // 00401123: mov b1 ss:[ebp+0xffffffffffffffe7], b1 0x1
         // 00401127: mov ss:[ebp+0xfffffffffffffffc], 0x0
         // 0040112e: push edx
         // 0040112f: push ecx
         // 00401130: push ebx
         // 00401131: mov eax, 0x564d5868
         // 00401136: mov ebx, 0x0
         // 0040113b: mov ecx, 0xa
         // 00401140: mov edx, 0x5658
         // 00401145: in eax, b2 dx
         // 00401146: cmp ebx, 0x564d5868
         // 0040114c: setz b1 ss:[ebp+0xffffffffffffffe7]
         // 00401150: pop ebx
         // 00401151: pop ecx
         // 00401152: pop edx
         // 00401153: mov ss:[ebp+0xfffffffffffffffc], 0xfffffffffffffffe
         // 0040115a: mov b1 al, b1 ss:[ebp+0xffffffffffffffe7]
         // 0040115d: mov ecx, ss:[ebp+0xfffffffffffffff0]
         // 00401160: mov fs:[0x0], ecx
         // 00401167: pop ecx
         // 00401168: pop edi
         // 00401169: pop esi
         // 0040116a: pop ebx
         // 0040116b: mov esp, ebp
         // 0040116d: pop ebp
         // 0040116e: retn 
      [-]6aff68????????64a1????????50515657a184e1410033c4508d44241064a3????????33c08bf18944240c6a018d7c24248944241ce8260600008b4c2434518d48018bd7e8d7040000837c243810720d
         // 004011a0: push 0xffffffffffffffff
         // 004011a2: push 0x418078
         // 004011a7: mov eax, fs:[0x0]
         // 004011ad: push eax
         // 004011ae: push ecx
         // 004011af: push esi
         // 004011b0: push edi
         // 004011b1: mov eax, ds:[___security_cookie]
         // 004011b6: xor eax, esp
         // 004011b8: push eax
         // 004011b9: lea eax, ss:[esp+0x10]
         // 004011bd: mov fs:[0x0], eax
         // 004011c3: xor eax, eax
         // 004011c5: mov esi, ecx
         // 004011c7: mov ss:[esp+0xc], eax
         // 004011cb: push 0x1
         // 004011cd: lea edi, ss:[esp+0x24]
         // 004011d1: mov ss:[esp+0x1c], eax
         // 004011d5: call 0x401800
         // 004011da: mov ecx, ss:[esp+0x34]
         // 004011de: push ecx
         // 004011df: lea ecx, ds:[eax+0x1]
         // 004011e2: mov edx, edi
         // 004011e4: call 0x4016c0
         // 004011e9: cmp ss:[esp+0x38], 0x10
         // 004011ee: jb 0x4011fd
      [-]8b54242452e80356000083c404
         // 004011f0: mov edx, ss:[esp+0x24]
         // 004011f4: push edx
         // 004011f5: call j__free
         // 004011fa: add esp, 0x4
      [-]8bc68b4c241064890d????????595f5e83c410c3
         // 004011fd: mov eax, esi
         // 004011ff: mov ecx, ss:[esp+0x10]
         // 00401203: mov fs:[0x0], ecx
         // 0040120a: pop ecx
         // 0040120b: pop edi
         // 0040120c: pop esi
         // 0040120d: add esp, 0x10
         // 00401210: retn 
      [-]6aff68????????64a1????????5081ec????????a184e1410033c4898424????????53555657a184e1410033c4508d8424????????64a3????????6a0b33dbbd????????68????????8d4c2460896c2478895c2474885c2464e882060000536a02899c24????????e80b4700008bf068????????8d44247c535089742424899c24????????e8569c000068????????8d8c24????????5351899c24????????e83c9c000083c41883feff7515
         // 00401220: push 0xffffffffffffffff
         // 00401222: push 0x418181
         // 00401227: mov eax, fs:[0x0]
         // 0040122d: push eax
         // 0040122e: sub esp, 0x4bc
         // 00401234: mov eax, ds:[___security_cookie]
         // 00401239: xor eax, esp
         // 0040123b: mov ss:[esp+0x4b8], eax
         // 00401242: push ebx
         // 00401243: push ebp
         // 00401244: push esi
         // 00401245: push edi
         // 00401246: mov eax, ds:[___security_cookie]
         // 0040124b: xor eax, esp
         // 0040124d: push eax
         // 0040124e: lea eax, ss:[esp+0x4d0]
         // 00401255: mov fs:[0x0], eax
         // 0040125b: push 0xb
         // 0040125d: xor ebx, ebx
         // 0040125f: mov ebp, 0xf
         // 00401264: push 0x41b484
         // 00401269: lea ecx, ss:[esp+0x60]
         // 0040126d: mov ss:[esp+0x78], ebp
         // 00401271: mov ss:[esp+0x74], ebx
         // 00401275: mov b1 ss:[esp+0x64], b1 bl
         // 00401279: call 0x401900
         // 0040127e: push ebx
         // 0040127f: push 0x2
         // 00401281: mov ss:[esp+0x4e0], ebx
         // 00401288: call CreateToolhelp32Snapshot
         // 0040128d: mov esi, eax
         // 0040128f: push 0x124
         // 00401294: lea eax, ss:[esp+0x7c]
         // 00401298: push ebx
         // 00401299: push eax
         // 0040129a: mov ss:[esp+0x24], esi
         // 0040129e: mov ss:[esp+0x80], ebx
         // 004012a5: call _memset
         // 004012aa: push 0x220
         // 004012af: lea ecx, ss:[esp+0x1b0]
         // 004012b6: push ebx
         // 004012b7: push ecx
         // 004012b8: mov ss:[esp+0x1b4], ebx
         // 004012bf: call _memset
         // 004012c4: add esp, 0x18
         // 004012c7: cmp esi, 0xffffffffffffffff
         // 004012ca: jnz 0x4012e1
      [-]837c2470100f8236020000
         // 004012cc: cmp ss:[esp+0x70], 0x10
         // 004012d1: jb 0x40150d
      [-]8b54245c52e924020000
         // 004012d7: mov edx, ss:[esp+0x5c]
         // 004012db: push edx
         // 004012dc: jmp 0x401505
      [-]68????????8d8424????????5350c78424????????????????889c24d0030000e8fa9b000083c40c68????????8d8c24????????5153ff151890410050ff153c9041008d8424????????896c2454895c2450885c24408d48018d9b????????
         // 004012e1: push 0x103
         // 004012e6: lea eax, ss:[esp+0x3c9]
         // 004012ed: push ebx
         // 004012ee: push eax
         // 004012ef: mov ss:[esp+0x80], 0x128
         // 004012fa: mov b1 ss:[esp+0x3d0], b1 bl
         // 00401301: call _memset
         // 00401306: add esp, 0xc
         // 00401309: push 0x103
         // 0040130e: lea ecx, ss:[esp+0x3c8]
         // 00401315: push ecx
         // 00401316: push ebx
         // 00401317: call ds:[GetModuleHandleA]
         // 0040131d: push eax
         // 0040131e: call ds:[GetModuleFileNameA]
         // 00401324: lea eax, ss:[esp+0x3c4]
         // 0040132b: mov ss:[esp+0x54], ebp
         // 0040132f: mov ss:[esp+0x50], ebx
         // 00401333: mov b1 ss:[esp+0x40], b1 bl
         // 00401337: lea ecx, ds:[eax+0x1]
         // 0040133a: lea ebx, ds:[ebx+0x0]
      [-]8a1083c0013ad375f7
         // 00401340: mov b1 dl, b1 ds:[eax]
         // 00401342: add eax, 0x1
         // 00401345: cmp b1 dl, b1 bl
         // 00401347: jnz 0x401340
      [-]2bc1508d9424????????528d4c2444e8a305000083ec1c8bcc896424386affc68424f804000001538d44246089691889591450885904e86c0300008d4c243ce813feffff83c41c6aff53508d4c2448c68424e404000002e84b030000bf????????397c2438720d
         // 00401349: sub eax, ecx
         // 0040134b: push eax
         // 0040134c: lea edx, ss:[esp+0x3c8]
         // 00401353: push edx
         // 00401354: lea ecx, ss:[esp+0x44]
         // 00401358: call 0x401900
         // 0040135d: sub esp, 0x1c
         // 00401360: mov ecx, esp
         // 00401362: mov ss:[esp+0x38], esp
         // 00401366: push 0xffffffffffffffff
         // 00401368: mov b1 ss:[esp+0x4f8], b1 0x1
         // 00401370: push ebx
         // 00401371: lea eax, ss:[esp+0x60]
         // 00401375: mov ds:[ecx+0x18], ebp
         // 00401378: mov ds:[ecx+0x14], ebx
         // 0040137b: push eax
         // 0040137c: mov b1 ds:[ecx+0x4], b1 bl
         // 0040137f: call 0x4016f0
         // 00401384: lea ecx, ss:[esp+0x3c]
         // 00401388: call 0x4011a0
         // 0040138d: add esp, 0x1c
         // 00401390: push 0xffffffffffffffff
         // 00401392: push ebx
         // 00401393: push eax
         // 00401394: lea ecx, ss:[esp+0x48]
         // 00401398: mov b1 ss:[esp+0x4e4], b1 0x2
         // 004013a0: call 0x4016f0
         // 004013a5: mov edi, 0x10
         // 004013aa: cmp ss:[esp+0x38], edi
         // 004013ae: jb 0x4013bd
      [-]8b4c242451e84354000083c404
         // 004013b0: mov ecx, ss:[esp+0x24]
         // 004013b4: push ecx
         // 004013b5: call j__free
         // 004013ba: add esp, 0x4
      [-]8d5424745256e8dc45000085c00f840b010000
         // 004013bd: lea edx, ss:[esp+0x74]
         // 004013c1: push edx
         // 004013c2: push esi
         // 004013c3: call Process32First
         // 004013c8: test eax, eax
         // 004013ca: jz 0x4014db
      [-]8d4424745056e8cf45000085c00f84f8000000
         // 004013d0: lea eax, ss:[esp+0x74]
         // 004013d4: push eax
         // 004013d5: push esi
         // 004013d6: call Process32Next
         // 004013db: test eax, eax
         // 004013dd: jz 0x4014db
      [-]397c24548b4c24407304
         // 004013e3: cmp ss:[esp+0x54], edi
         // 004013e7: mov ecx, ss:[esp+0x40]
         // 004013eb: jnb 0x4013f1
      [-]8d4c2440
         // 004013ed: lea ecx, ss:[esp+0x40]
      [-]8d8424????????
         // 004013f1: lea eax, ss:[esp+0x98]
      [-]8a103a11751a
         // 004013f8: mov b1 dl, b1 ds:[eax]
         // 004013fa: cmp b1 dl, b1 ds:[ecx]
         // 004013fc: jnz 0x401418
      [-]3ad37412
         // 004013fe: cmp b1 dl, b1 bl
         // 00401400: jz 0x401414
      [-]8a50013a5101750e
         // 00401402: mov b1 dl, b1 ds:[eax+0x1]
         // 00401405: cmp b1 dl, b1 ds:[ecx+0x1]
         // 00401408: jnz 0x401418
      [-]83c00283c1023ad375e4
         // 0040140a: add eax, 0x2
         // 0040140d: add ecx, 0x2
         // 00401410: cmp b1 dl, b1 bl
         // 00401412: jnz 0x4013f8
      [-]33c0eb05
         // 00401414: xor eax, eax
         // 00401416: jmp 0x40141d
      [-]1bc083d8ff
         // 00401418: sbb eax, eax
         // 0040141a: sbb eax, 0xffffffffffffffff
      [-]3bc30f85a3000000
         // 0040141d: cmp eax, ebx
         // 0040141f: jnz 0x4014c8
      [-]8b4c247c516a08e8674500008bf083feff0f8488000000
         // 00401425: mov ecx, ss:[esp+0x7c]
         // 00401429: push ecx
         // 0040142a: push 0x8
         // 0040142c: call CreateToolhelp32Snapshot
         // 00401431: mov esi, eax
         // 00401433: cmp esi, 0xffffffffffffffff
         // 00401436: jz 0x4014c4
      [-]8d9424????????5256c78424????????????????e84945000085c0746b
         // 0040143c: lea edx, ss:[esp+0x19c]
         // 00401443: push edx
         // 00401444: push esi
         // 00401445: mov ss:[esp+0x1a4], 0x224
         // 00401450: call Module32First
         // 00401455: test eax, eax
         // 00401457: jz 0x4014c4
      [-]8d8424????????5056e84945000085c07459
         // 00401459: lea eax, ss:[esp+0x19c]
         // 00401460: push eax
         // 00401461: push esi
         // 00401462: call Module32Next
         // 00401467: test eax, eax
         // 00401469: jz 0x4014c4
      [-]397c24708b4c245c7304
         // 00401470: cmp ss:[esp+0x70], edi
         // 00401474: mov ecx, ss:[esp+0x5c]
         // 00401478: jnb 0x40147e
      [-]8d4c245c
         // 0040147a: lea ecx, ss:[esp+0x5c]
      [-]8d8424????????
         // 0040147e: lea eax, ss:[esp+0x1bc]
      [-]8a103a11751a
         // 00401485: mov b1 dl, b1 ds:[eax]
         // 00401487: cmp b1 dl, b1 ds:[ecx]
         // 00401489: jnz 0x4014a5
      [-]3ad37412
         // 0040148b: cmp b1 dl, b1 bl
         // 0040148d: jz 0x4014a1
      [-]8a50013a5101750e
         // 0040148f: mov b1 dl, b1 ds:[eax+0x1]
         // 00401492: cmp b1 dl, b1 ds:[ecx+0x1]
         // 00401495: jnz 0x4014a5
      [-]83c00283c1023ad375e4
         // 00401497: add eax, 0x2
         // 0040149a: add ecx, 0x2
         // 0040149d: cmp b1 dl, b1 bl
         // 0040149f: jnz 0x401485
      [-]33c0eb05
         // 004014a1: xor eax, eax
         // 004014a3: jmp 0x4014aa
      [-]1bc083d8ff
         // 004014a5: sbb eax, eax
         // 004014a7: sbb eax, 0xffffffffffffffff
      [-]3bc30f8485000000
         // 004014aa: cmp eax, ebx
         // 004014ac: jz 0x401537
      [-]8d8c24????????5156e8f044000085c075ac
         // 004014b2: lea ecx, ss:[esp+0x19c]
         // 004014b9: push ecx
         // 004014ba: push esi
         // 004014bb: call Module32Next
         // 004014c0: test eax, eax
         // 004014c2: jnz 0x401470
      [-]8b742418
         // 004014c4: mov esi, ss:[esp+0x18]
      [-]8d5424745256e8d744000085c00f8508ffffff
         // 004014c8: lea edx, ss:[esp+0x74]
         // 004014cc: push edx
         // 004014cd: push esi
         // 004014ce: call Process32Next
         // 004014d3: test eax, eax
         // 004014d5: jnz 0x4013e3
      [-]397c2454720d
         // 004014db: cmp ss:[esp+0x54], edi
         // 004014df: jb 0x4014ee
      [-]8b54244052e81253000083c404
         // 004014e1: mov edx, ss:[esp+0x40]
         // 004014e5: push edx
         // 004014e6: call j__free
         // 004014eb: add esp, 0x4
      [-]397c2470896c2454895c2450885c2440720d
         // 004014ee: cmp ss:[esp+0x70], edi
         // 004014f2: mov ss:[esp+0x54], ebp
         // 004014f6: mov ss:[esp+0x50], ebx
         // 004014fa: mov b1 ss:[esp+0x40], b1 bl
         // 004014fe: jb 0x40150d
      [-]8b44245c50
         // 00401500: mov eax, ss:[esp+0x5c]
         // 00401504: push eax
      [-]e8f352000083c404
         // 00401505: call j__free
         // 0040150a: add esp, 0x4
      [-]8b8c24????????64890d????????595f5e5d5b8b8c24????????33cce89551000081c4????????c3
         // 0040150f: mov ecx, ss:[esp+0x4d0]
         // 00401516: mov fs:[0x0], ecx
         // 0040151d: pop ecx
         // 0040151e: pop edi
         // 0040151f: pop esi
         // 00401520: pop ebp
         // 00401521: pop ebx
         // 00401522: mov ecx, ss:[esp+0x4b8]
         // 00401529: xor ecx, esp
         // 0040152b: call @__security_check_cookie@4
         // 00401530: add esp, 0x4c8
         // 00401536: retn 
      [-]397c2454720d
         // 00401537: cmp ss:[esp+0x54], edi
         // 0040153b: jb 0x40154a
      [-]8b44244050e8b652000083c404
         // 0040153d: mov eax, ss:[esp+0x40]
         // 00401541: push eax
         // 00401542: call j__free
         // 00401547: add esp, 0x4
      [-]397c2470896c2454895c2450885c2440720d
         // 0040154a: cmp ss:[esp+0x70], edi
         // 0040154e: mov ss:[esp+0x54], ebp
         // 00401552: mov ss:[esp+0x50], ebx
         // 00401556: mov b1 ss:[esp+0x40], b1 bl
         // 0040155a: jb 0x401569
      [-]8b4c245c51e89752000083c404
         // 0040155c: mov ecx, ss:[esp+0x5c]
         // 00401560: push ecx
         // 00401561: call j__free
         // 00401566: add esp, 0x4
      [-]b001eba2
         // 00401569: mov b1 al, b1 0x1
         // 0040156b: jmp 0x40150f
      [-]81ec????????a184e1410033c4898424????????538d4424045068????????33db5368????????68????????c744241c????????ff150490410085c07553
         // 00401570: sub esp, 0x8c
         // 00401576: mov eax, ds:[___security_cookie]
         // 0040157b: xor eax, esp
         // 0040157d: mov ss:[esp+0x88], eax
         // 00401584: push ebx
         // 00401585: lea eax, ss:[esp+0x4]
         // 00401589: push eax
         // 0040158a: push 0x20019
         // 0040158f: xor ebx, ebx
         // 00401591: push ebx
         // 00401592: push 0x41b4a8
         // 00401597: push 0xffffffff80000002
         // 0040159c: mov ss:[esp+0x1c], 0x7f
         // 004015a4: call ds:[RegOpenKeyExA]
         // 004015aa: test eax, eax
         // 004015ac: jnz 0x401601
      [-]558d4c240c518d5424145250508b44241868????????50ff150090410085c08b2d089041007524
         // 004015ae: push ebp
         // 004015af: lea ecx, ss:[esp+0xc]
         // 004015b3: push ecx
         // 004015b4: lea edx, ss:[esp+0x14]
         // 004015b8: push edx
         // 004015b9: push eax
         // 004015ba: push eax
         // 004015bb: mov eax, ss:[esp+0x18]
         // 004015bf: push 0x41b4d4
         // 004015c4: push eax
         // 004015c5: call ds:[RegQueryValueExA]
         // 004015cb: test eax, eax
         // 004015cd: mov ebp, ds:[RegCloseKey]
         // 004015d3: jnz 0x4015f9
      [-]56578d7c2418be????????b9????????33d2f3a65f5e750c
         // 004015d5: push esi
         // 004015d6: push edi
         // 004015d7: lea edi, ss:[esp+0x18]
         // 004015db: mov esi, 0x41b4e0
         // 004015e0: mov ecx, 0x18
         // 004015e5: xor edx, edx
         // 004015e7: repe cmpsbb 
         // 004015e9: pop edi
         // 004015ea: pop esi
         // 004015eb: jnz 0x4015f9
      [-]8b44240850ffd5bb????????
         // 004015ed: mov eax, ss:[esp+0x8]
         // 004015f1: push eax
         // 004015f2: call ebp
         // 004015f4: mov ebx, 0x1
      [-]8b4c240851ffd55d
         // 004015f9: mov ecx, ss:[esp+0x8]
         // 004015fd: push ecx
         // 004015fe: call ebp
         // 00401600: pop ebp
      [-]8b8c24????????8bc35b33cce8b350000081c4????????c3
         // 00401601: mov ecx, ss:[esp+0x8c]
         // 00401608: mov eax, ebx
         // 0040160a: pop ebx
         // 0040160b: xor ecx, esp
         // 0040160d: call @__security_check_cookie@4
         // 00401612: add esp, 0x8c
         // 00401618: retn 
      [-]8b542404568bf18bc257c74618????????c746????????00c64604008d780190
         // 00401620: mov edx, ss:[esp+0x4]
         // 00401624: push esi
         // 00401625: mov esi, ecx
         // 00401627: mov eax, edx
         // 00401629: push edi
         // 0040162a: mov ds:[esi+0x18], 0xf
         // 00401631: mov ds:[esi+0x14], 0x0
         // 00401638: mov b1 ds:[esi+0x4], b1 0x0
         // 0040163c: lea edi, ds:[eax+0x1]
         // 0040163f: nop 
      [-]8a0883c00184c975f7
         // 00401640: mov b1 cl, b1 ds:[eax]
         // 00401642: add eax, 0x1
         // 00401645: test b1 cl, b1 cl
         // 00401647: jnz 0x401640
      [-]2bc750528bcee8ac0200005f8bc65ec20400
         // 00401649: sub eax, edi
         // 0040164b: push eax
         // 0040164c: push edx
         // 0040164d: mov ecx, esi
         // 0040164f: call 0x401900
         // 00401654: pop edi
         // 00401655: mov eax, esi
         // 00401657: pop esi
         // 00401658: retn b2 0x4
      [-]5633c08bf16aff894614c74618????????508846048b44241050e8710000008bc65ec20400
         // 00401660: push esi
         // 00401661: xor eax, eax
         // 00401663: mov esi, ecx
         // 00401665: push 0xffffffffffffffff
         // 00401667: mov ds:[esi+0x14], eax
         // 0040166a: mov ds:[esi+0x18], 0xf
         // 00401671: push eax
         // 00401672: mov b1 ds:[esi+0x4], b1 al
         // 00401675: mov eax, ss:[esp+0x10]
         // 00401679: push eax
         // 0040167a: call 0x4016f0
         // 0040167f: mov eax, esi
         // 00401681: pop esi
         // 00401682: retn b2 0x4
      [-]568bf1837e1810720c
         // 00401690: push esi
         // 00401691: mov esi, ecx
         // 00401693: cmp ds:[esi+0x18], 0x10
         // 00401697: jb 0x4016a5
      [-]8b460450e85b51000083c404
         // 00401699: mov eax, ds:[esi+0x4]
         // 0040169c: push eax
         // 0040169d: call j__free
         // 004016a2: add esp, 0x4
      [-]33c0c74618????????8946148846045ec3
         // 004016a5: xor eax, eax
         // 004016a7: mov ds:[esi+0x18], 0xf
         // 004016ae: mov ds:[esi+0x14], eax
         // 004016b1: mov b1 ds:[esi+0x4], b1 al
         // 004016b4: pop esi
         // 004016b5: retn 
      [-]5133c0894614c74618????????8904248846048b4424085051528bcee80f0000008bc659c20400
         // 004016c0: push ecx
         // 004016c1: xor eax, eax
         // 004016c3: mov ds:[esi+0x14], eax
         // 004016c6: mov ds:[esi+0x18], 0xf
         // 004016cd: mov ss:[esp], eax
         // 004016d0: mov b1 ds:[esi+0x4], b1 al
         // 004016d3: mov eax, ss:[esp+0x8]
         // 004016d7: push eax
         // 004016d8: push ecx
         // 004016d9: push edx
         // 004016da: mov ecx, esi
         // 004016dc: call 0x4016f0
         // 004016e1: mov eax, esi
         // 004016e3: pop ecx
         // 004016e4: retn b2 0x4
      [-]538b5c2408558b6c2410396b1456578bf17305
         // 004016f0: push ebx
         // 004016f1: mov ebx, ss:[esp+0x8]
         // 004016f5: push ebp
         // 004016f6: mov ebp, ss:[esp+0x10]
         // 004016fa: cmp ds:[ebx+0x14], ebp
         // 004016fd: push esi
         // 004016fe: push edi
         // 004016ff: mov esi, ecx
         // 00401701: jnb 0x401708
      [-]e815440000
         // 00401703: call ?_Xran@_String_base@std@@SAXXZ
      [-]8b7b148b44241c2bfd3bc77302
         // 00401708: mov edi, ds:[ebx+0x14]
         // 0040170b: mov eax, ss:[esp+0x1c]
         // 0040170f: sub edi, ebp
         // 00401711: cmp eax, edi
         // 00401713: jnb 0x401717
      [-]3bf3751f
         // 00401717: cmp esi, ebx
         // 00401719: jnz 0x40173a
      [-]6aff03fd578bcee8a9020000556a008bcee89f0200005f8bc65e5d5bc20c00
         // 0040171b: push 0xffffffffffffffff
         // 0040171d: add edi, ebp
         // 0040171f: push edi
         // 00401720: mov ecx, esi
         // 00401722: call 0x4019d0
         // 00401727: push ebp
         // 00401728: push 0x0
         // 0040172a: mov ecx, esi
         // 0040172c: call 0x4019d0
         // 00401731: pop edi
         // 00401732: mov eax, esi
         // 00401734: pop esi
         // 00401735: pop ebp
         // 00401736: pop ebx
         // 00401737: retn b2 0xc
      [-]83fffe7605
         // 0040173a: cmp edi, 0xfffffffffffffffe
         // 0040173d: jbe 0x401744
      [-]e848430000
         // 0040173f: call ?_Xlen@_String_base@std@@SAXXZ
      [-]8b46183bc7731b
         // 00401744: mov eax, ds:[esi+0x18]
         // 00401747: cmp eax, edi
         // 00401749: jnb 0x401766
      [-]8b461450578bcee80903000085ff
         // 0040174b: mov eax, ds:[esi+0x14]
         // 0040174e: push eax
         // 0040174f: push edi
         // 00401750: mov ecx, esi
         // 00401752: call 0x401a60
         // 00401757: test edi, edi
      [-]837b1810722f
         // 0040175b: cmp ds:[ebx+0x18], 0x10
         // 0040175f: jb 0x401790
      [-]8b5304eb2d
         // 00401761: mov edx, ds:[ebx+0x4]
         // 00401764: jmp 0x401793
      [-]85ff75ef
         // 00401766: test edi, edi
         // 00401768: jnz 0x401759
      [-]83f810897e14720f
         // 0040176a: cmp eax, 0x10
         // 0040176d: mov ds:[esi+0x14], edi
         // 00401770: jb 0x401781
      [-]8b46045fc600008bc65e5d5bc20c00
         // 00401772: mov eax, ds:[esi+0x4]
         // 00401775: pop edi
         // 00401776: mov b1 ds:[eax], b1 0x0
         // 00401779: mov eax, esi
         // 0040177b: pop esi
         // 0040177c: pop ebp
         // 0040177d: pop ebx
         // 0040177e: retn b2 0xc
      [-]8d46045fc600008bc65e5d5bc20c00
         // 00401781: lea eax, ds:[esi+0x4]
         // 00401784: pop edi
         // 00401785: mov b1 ds:[eax], b1 0x0
         // 00401788: mov eax, esi
         // 0040178a: pop esi
         // 0040178b: pop ebp
         // 0040178c: pop ebx
         // 0040178d: retn b2 0xc
      [-]8b4e1883f9108d5e047204
         // 00401793: mov ecx, ds:[esi+0x18]
         // 00401796: cmp ecx, 0x10
         // 00401799: lea ebx, ds:[esi+0x4]
         // 0040179c: jb 0x4017a2
      [-]8b03eb02
         // 0040179e: mov eax, ds:[ebx]
         // 004017a0: jmp 0x4017a4
      [-]5703d5525150e8254f000083c410837e1810897e147202
         // 004017a4: push edi
         // 004017a5: add edx, ebp
         // 004017a7: push edx
         // 004017a8: push ecx
         // 004017a9: push eax
         // 004017aa: call _memcpy_s
         // 004017af: add esp, 0x10
         // 004017b2: cmp ds:[esi+0x18], 0x10
         // 004017b6: mov ds:[esi+0x14], edi
         // 004017b9: jb 0x4017bd
      [-]c6043b00
         // 004017bd: mov b1 ds:[ebx+edi], b1 0x0
      [-]5f8bc65e5d5bc20c00
         // 004017c1: pop edi
         // 004017c2: mov eax, esi
         // 004017c4: pop esi
         // 004017c5: pop ebp
         // 004017c6: pop ebx
         // 004017c7: retn b2 0xc
      [-]568b7424088bc6578d7801eb03
         // 004017d0: push esi
         // 004017d1: mov esi, ss:[esp+0x8]
         // 004017d5: mov eax, esi
         // 004017d7: push edi
         // 004017d8: lea edi, ds:[eax+0x1]
         // 004017db: jmp 0x4017e0
      [-]8a1083c00184d275f7
         // 004017e0: mov b1 dl, b1 ds:[eax]
         // 004017e2: add eax, 0x1
         // 004017e5: test b1 dl, b1 dl
         // 004017e7: jnz 0x4017e0
      [-]2bc75056e80e0100005f5ec20400
         // 004017e9: sub eax, edi
         // 004017eb: push eax
         // 004017ec: push esi
         // 004017ed: call 0x401900
         // 004017f2: pop edi
         // 004017f3: pop esi
         // 004017f4: retn b2 0x4
      [-]53558b6c240c85ed56767f
         // 00401800: push ebx
         // 00401801: push ebp
         // 00401802: mov ebp, ss:[esp+0xc]
         // 00401806: test ebp, ebp
         // 00401808: push esi
         // 00401809: jbe 0x40188a
      [-]8b471485c07678
         // 0040180b: mov eax, ds:[edi+0x14]
         // 0040180e: test eax, eax
         // 00401810: jbe 0x40188a
      [-]83f8ff7605
         // 00401812: cmp eax, 0xffffffffffffffff
         // 00401815: jbe 0x40181c
      [-]83c9ffeb03
         // 00401817: or ecx, 0xffffffffffffffff
         // 0040181a: jmp 0x40181f
      [-]837f18108d5f047204
         // 0040181f: cmp ds:[edi+0x18], 0x10
         // 00401823: lea ebx, ds:[edi+0x4]
         // 00401826: jb 0x40182c
      [-]8b03eb02
         // 00401828: mov eax, ds:[ebx]
         // 0040182a: jmp 0x40182e
      [-]8d34080fbe06555068????????e8104f000083c40c85c07525
         // 0040182e: lea esi, ds:[eax+ecx]
         // 00401831: movsx eax, b1 ds:[esi]
         // 00401834: push ebp
         // 00401835: push eax
         // 00401836: push 0x41b480
         // 0040183b: call _memchr
         // 00401840: add esp, 0xc
         // 00401843: test eax, eax
         // 00401845: jnz 0x40186c
      [-]8bcfe8a20000003bf07438
         // 00401847: mov ecx, edi
         // 00401849: call 0x4018f0
         // 0040184e: cmp esi, eax
         // 00401850: jz 0x40188a
      [-]0fbe4eff83ee01555168????????e8eb4e000083c40c85c074db
         // 00401852: movsx ecx, b1 ds:[esi+0xffffffffffffffff]
         // 00401856: sub esi, 0x1
         // 00401859: push ebp
         // 0040185a: push ecx
         // 0040185b: push 0x41b480
         // 00401860: call _memchr
         // 00401865: add esp, 0xc
         // 00401868: test eax, eax
         // 0040186a: jz 0x401847
      [-]837f1810720c
         // 0040186c: cmp ds:[edi+0x18], 0x10
         // 00401870: jb 0x40187e
      [-]8b0b8bc65e5d2bc15bc20400
         // 00401872: mov ecx, ds:[ebx]
         // 00401874: mov eax, esi
         // 00401876: pop esi
         // 00401877: pop ebp
         // 00401878: sub eax, ecx
         // 0040187a: pop ebx
         // 0040187b: retn b2 0x4
      [-]8bc65e8bcb5d2bc15bc20400
         // 0040187e: mov eax, esi
         // 00401880: pop esi
         // 00401881: mov ecx, ebx
         // 00401883: pop ebp
         // 00401884: sub eax, ecx
         // 00401886: pop ebx
         // 00401887: retn b2 0x4
      [-]5e5d83c8ff5bc20400
         // 0040188a: pop esi
         // 0040188b: pop ebp
         // 0040188c: or eax, 0xffffffffffffffff
         // 0040188f: pop ebx
         // 00401890: retn b2 0x4
      [-]807c24040056578b7c24108bf17427
         // 004018a0: cmp b1 ss:[esp+0x4], b1 0x0
         // 004018a5: push esi
         // 004018a6: push edi
         // 004018a7: mov edi, ss:[esp+0x10]
         // 004018ab: mov esi, ecx
         // 004018ad: jz 0x4018d6
      [-]837e18107221
         // 004018af: cmp ds:[esi+0x18], 0x10
         // 004018b3: jb 0x4018d6
      [-]85ff8d4604538b18760d
         // 004018b5: test edi, edi
         // 004018b7: lea eax, ds:[esi+0x4]
         // 004018ba: push ebx
         // 004018bb: mov ebx, ds:[eax]
         // 004018bd: jbe 0x4018cc
      [-]57536a1050e80b4e000083c410
         // 004018bf: push edi
         // 004018c0: push ebx
         // 004018c1: push 0x10
         // 004018c3: push eax
         // 004018c4: call _memcpy_s
         // 004018c9: add esp, 0x10
      [-]53e82b4f000083c4045b
         // 004018cc: push ebx
         // 004018cd: call j__free
         // 004018d2: add esp, 0x4
         // 004018d5: pop ebx
      [-]897e14c74618????????c6443e04005f5ec20800
         // 004018d6: mov ds:[esi+0x14], edi
         // 004018d9: mov ds:[esi+0x18], 0xf
         // 004018e0: mov b1 ds:[esi+edi+0x4], b1 0x0
         // 004018e5: pop edi
         // 004018e6: pop esi
         // 004018e7: retn b2 0x8
      [-]5355568bf18b4e1883f9108d5e047204
         // 00401900: push ebx
         // 00401901: push ebp
         // 00401902: push esi
         // 00401903: mov esi, ecx
         // 00401905: mov ecx, ds:[esi+0x18]
         // 00401908: cmp ecx, 0x10
         // 0040190b: lea ebx, ds:[esi+0x4]
         // 0040190e: jb 0x401914
      [-]8b03eb02
         // 00401910: mov eax, ds:[ebx]
         // 00401912: jmp 0x401916
      [-]8b6c24103be87231
         // 00401916: mov ebp, ss:[esp+0x10]
         // 0040191a: cmp ebp, eax
         // 0040191c: jb 0x40194f
      [-]83f9107204
         // 0040191e: cmp ecx, 0x10
         // 00401921: jb 0x401927
      [-]8b03eb02
         // 00401923: mov eax, ds:[ebx]
         // 00401925: jmp 0x401929
      [-]8b561403d03bd5761d
         // 00401929: mov edx, ds:[esi+0x14]
         // 0040192c: add edx, eax
         // 0040192e: cmp edx, ebp
         // 00401930: jbe 0x40194f
      [-]83f9107202
         // 00401932: cmp ecx, 0x10
         // 00401935: jb 0x401939
      [-]8b442414502beb55568bcee8a7fdffff5e5d5bc20800
         // 00401939: mov eax, ss:[esp+0x14]
         // 0040193d: push eax
         // 0040193e: sub ebp, ebx
         // 00401940: push ebp
         // 00401941: push esi
         // 00401942: mov ecx, esi
         // 00401944: call 0x4016f0
         // 00401949: pop esi
         // 0040194a: pop ebp
         // 0040194b: pop ebx
         // 0040194c: retn b2 0x8
      [-]578b7c241883fffe7605
         // 0040194f: push edi
         // 00401950: mov edi, ss:[esp+0x18]
         // 00401954: cmp edi, 0xfffffffffffffffe
         // 00401957: jbe 0x40195e
      [-]e82e410000
         // 00401959: call ?_Xlen@_String_base@std@@SAXXZ
      [-]8b46183bc7731c
         // 0040195e: mov eax, ds:[esi+0x18]
         // 00401961: cmp eax, edi
         // 00401963: jnb 0x401981
      [-]8b4e1451578bcee8ef00000085ff
         // 00401965: mov ecx, ds:[esi+0x14]
         // 00401968: push ecx
         // 00401969: push edi
         // 0040196a: mov ecx, esi
         // 0040196c: call 0x401a60
         // 00401971: test edi, edi
      [-]8b4e1883f910721e
         // 00401975: mov ecx, ds:[esi+0x18]
         // 00401978: cmp ecx, 0x10
         // 0040197b: jb 0x40199b
      [-]8b03eb1c
         // 0040197d: mov eax, ds:[ebx]
         // 0040197f: jmp 0x40199d
      [-]85ff75ee
         // 00401981: test edi, edi
         // 00401983: jnz 0x401973
      [-]83f810897e147202
         // 00401985: cmp eax, 0x10
         // 00401988: mov ds:[esi+0x14], edi
         // 0040198b: jb 0x40198f
      [-]5f8bc65e5dc603005bc20800
         // 0040198f: pop edi
         // 00401990: mov eax, esi
         // 00401992: pop esi
         // 00401993: pop ebp
         // 00401994: mov b1 ds:[ebx], b1 0x0
         // 00401997: pop ebx
         // 00401998: retn b2 0x8
      [-]57555150e82e4d000083c410837e1810897e147202
         // 0040199d: push edi
         // 0040199e: push ebp
         // 0040199f: push ecx
         // 004019a0: push eax
         // 004019a1: call _memcpy_s
         // 004019a6: add esp, 0x10
         // 004019a9: cmp ds:[esi+0x18], 0x10
         // 004019ad: mov ds:[esi+0x14], edi
         // 004019b0: jb 0x4019b4
      [-]c6043b00
         // 004019b4: mov b1 ds:[ebx+edi], b1 0x0
      [-]5f8bc65e5d5bc20800
         // 004019b8: pop edi
         // 004019b9: mov eax, esi
         // 004019bb: pop esi
         // 004019bc: pop ebp
         // 004019bd: pop ebx
         // 004019be: retn b2 0x8
      [-]538b5c2408568bf1395e14577305
         // 004019d0: push ebx
         // 004019d1: mov ebx, ss:[esp+0x8]
         // 004019d5: push esi
         // 004019d6: mov esi, ecx
         // 004019d8: cmp ds:[esi+0x14], ebx
         // 004019db: push edi
         // 004019dc: jnb 0x4019e3
      [-]e83a410000
         // 004019de: call ?_Xran@_String_base@std@@SAXXZ
      [-]8b46148b7c24142bc33bc77302
         // 004019e3: mov eax, ds:[esi+0x14]
         // 004019e6: mov edi, ss:[esp+0x14]
         // 004019ea: sub eax, ebx
         // 004019ec: cmp eax, edi
         // 004019ee: jnb 0x4019f2
      [-]85ff7655
         // 004019f2: test edi, edi
         // 004019f4: jbe 0x401a4b
      [-]8b4e1883f910558d6e047209
         // 004019f6: mov ecx, ds:[esi+0x18]
         // 004019f9: cmp ecx, 0x10
         // 004019fc: push ebp
         // 004019fd: lea ebp, ds:[esi+0x4]
         // 00401a00: jb 0x401a0b
      [-]8b550089542414eb04
         // 00401a02: mov edx, ss:[ebp+0x0]
         // 00401a05: mov ss:[esp+0x14], edx
         // 00401a09: jmp 0x401a0f
      [-]896c2414
         // 00401a0b: mov ss:[esp+0x14], ebp
      [-]83f9107205
         // 00401a0f: cmp ecx, 0x10
         // 00401a12: jb 0x401a19
      [-]8b5500eb02
         // 00401a14: mov edx, ss:[ebp+0x0]
         // 00401a17: jmp 0x401a1b
      [-]2bc7508b44241803c303c7502bcb5103d352e8d04d00008b46142bc783c410837e18108946147203
         // 00401a1b: sub eax, edi
         // 00401a1d: push eax
         // 00401a1e: mov eax, ss:[esp+0x18]
         // 00401a22: add eax, ebx
         // 00401a24: add eax, edi
         // 00401a26: push eax
         // 00401a27: sub ecx, ebx
         // 00401a29: push ecx
         // 00401a2a: add edx, ebx
         // 00401a2c: push edx
         // 00401a2d: call _memmove_s
         // 00401a32: mov eax, ds:[esi+0x14]
         // 00401a35: sub eax, edi
         // 00401a37: add esp, 0x10
         // 00401a3a: cmp ds:[esi+0x18], 0x10
         // 00401a3e: mov ds:[esi+0x14], eax
         // 00401a41: jb 0x401a46
      [-]c60428005d
         // 00401a46: mov b1 ds:[eax+ebp], b1 0x0
         // 00401a4a: pop ebp
      [-]5f8bc65e5bc20800
         // 00401a4b: pop edi
         // 00401a4c: mov eax, esi
         // 00401a4e: pop esi
         // 00401a4f: pop ebx
         // 00401a50: retn b2 0x8
      [-]558bec6aff68????????64a1????????5083ec1c535657a184e1410033c5508d45f464a3????????8965f08bf9897dec8b45088bf083ce0f83fefe7604
         // 00401a60: push ebp
         // 00401a61: mov ebp, esp
         // 00401a63: push 0xffffffffffffffff
         // 00401a65: push 0x418050
         // 00401a6a: mov eax, fs:[0x0]
         // 00401a70: push eax
         // 00401a71: sub esp, 0x1c
         // 00401a74: push ebx
         // 00401a75: push esi
         // 00401a76: push edi
         // 00401a77: mov eax, ds:[___security_cookie]
         // 00401a7c: xor eax, ebp
         // 00401a7e: push eax
         // 00401a7f: lea eax, ss:[ebp+0xfffffffffffffff4]
         // 00401a82: mov fs:[0x0], eax
         // 00401a88: mov ss:[ebp+0xfffffffffffffff0], esp
         // 00401a8b: mov edi, ecx
         // 00401a8d: mov ss:[ebp+0xffffffffffffffec], edi
         // 00401a90: mov eax, ss:[ebp+0x8]
         // 00401a93: mov esi, eax
         // 00401a95: or esi, 0xf
         // 00401a98: cmp esi, 0xfffffffffffffffe
         // 00401a9b: jbe 0x401aa1
      [-]8bf0eb22
         // 00401a9d: mov esi, eax
         // 00401a9f: jmp 0x401ac3
      [-]8b5f18b8????????f7e68bcbd1e9d1ea3bd1730e
         // 00401aa1: mov ebx, ds:[edi+0x18]
         // 00401aa4: mov eax, 0xffffffffaaaaaaab
         // 00401aa9: mul esi
         // 00401aab: mov ecx, ebx
         // 00401aad: shr ecx, b1 0x1
         // 00401aaf: shr edx, b1 0x1
         // 00401ab1: cmp edx, ecx
         // 00401ab3: jnb 0x401ac3
      [-]b8????????2bc13bd87703
         // 00401ab5: mov eax, 0xfffffffffffffffe
         // 00401aba: sub eax, ecx
         // 00401abc: cmp ebx, eax
         // 00401abe: ja 0x401ac3
      [-]33db8d4e013bcb895dfc7710
         // 00401ac3: xor ebx, ebx
         // 00401ac5: lea ecx, ds:[esi+0x1]
         // 00401ac8: cmp ecx, ebx
         // 00401aca: mov ss:[ebp+0xfffffffffffffffc], ebx
         // 00401acd: ja 0x401adf
      [-]51e83f4b000083c404894508eb58
         // 00401ad1: push ecx
         // 00401ad2: call ??2@YAPAXI@Z
         // 00401ad7: add esp, 0x4
         // 00401ada: mov ss:[ebp+0x8], eax
         // 00401add: jmp 0x401b37
      [-]8b5d0c85db7620
         // 00401b37: mov ebx, ss:[ebp+0xc]
         // 00401b3a: test ebx, ebx
         // 00401b3c: jbe 0x401b5e
      [-]837f18107205
         // 00401b3e: cmp ds:[edi+0x18], 0x10
         // 00401b42: jb 0x401b49
      [-]8b4704eb03
         // 00401b44: mov eax, ds:[edi+0x4]
         // 00401b47: jmp 0x401b4c
      [-]8b4d0853508d46015051e8794b000083c410
         // 00401b4c: mov ecx, ss:[ebp+0x8]
         // 00401b4f: push ebx
         // 00401b50: push eax
         // 00401b51: lea eax, ds:[esi+0x1]
         // 00401b54: push eax
         // 00401b55: push ecx
         // 00401b56: call _memcpy_s
         // 00401b5b: add esp, 0x10
      [-]837f1810720c
         // 00401b5e: cmp ds:[edi+0x18], 0x10
         // 00401b62: jb 0x401b70
      [-]8b570452e8904c000083c404
         // 00401b64: mov edx, ds:[edi+0x4]
         // 00401b67: push edx
         // 00401b68: call j__free
         // 00401b6d: add esp, 0x4
      [-]83fe108b4d088d4704c600008908897718895f147202
         // 00401b70: cmp esi, 0x10
         // 00401b73: mov ecx, ss:[ebp+0x8]
         // 00401b76: lea eax, ds:[edi+0x4]
         // 00401b79: mov b1 ds:[eax], b1 0x0
         // 00401b7c: mov ds:[eax], ecx
         // 00401b7e: mov ds:[edi+0x18], esi
         // 00401b81: mov ds:[edi+0x14], ebx
         // 00401b84: jb 0x401b88
      [-]c60418008b4df464890d????????595f5e5b8be55dc20800
         // 00401b88: mov b1 ds:[eax+ebx], b1 0x0
         // 00401b8c: mov ecx, ss:[ebp+0xfffffffffffffff4]
         // 00401b8f: mov fs:[0x0], ecx
         // 00401b96: pop ecx
         // 00401b97: pop edi
         // 00401b98: pop esi
         // 00401b99: pop ebx
         // 00401b9a: mov esp, ebp
         // 00401b9c: pop ebp
         // 00401b9d: retn b2 0x8
      [-]8b4c240483ec0c85c97711
         // 00401be0: mov ecx, ss:[esp+0x4]
         // 00401be4: sub esp, 0xc
         // 00401be7: test ecx, ecx
         // 00401be9: ja 0x401bfc
      [-]51e8234a000083c40483c40cc20400
         // 00401bed: push ecx
         // 00401bee: call ??2@YAPAXI@Z
         // 00401bf3: add esp, 0x4
         // 00401bf6: add esp, 0xc
         // 00401bf9: retn b2 0x4
      [-]83c8ff33d2f7f183f80173e5
         // 00401bfc: or eax, 0xffffffffffffffff
         // 00401bff: xor edx, edx
         // 00401c01: div ecx
         // 00401c03: cmp eax, 0x1
         // 00401c06: jnb 0x401bed
      [-]8d442410508d4c2404c74424????????00e8844800006818cb41008d4c240451c7442408fc914100e8f6620000
         // 00401c08: lea eax, ss:[esp+0x10]
         // 00401c0c: push eax
         // 00401c0d: lea ecx, ss:[esp+0x4]
         // 00401c11: mov ss:[esp+0x14], 0x0
         // 00401c19: call ??0exception@std@@QAE@ABQBD@Z
         // 00401c1e: push __TI2?AVbad_alloc@std@@
         // 00401c23: lea ecx, ss:[esp+0x4]
         // 00401c27: push ecx
         // 00401c28: mov ss:[esp+0x8], ??_7bad_alloc@std@@6B@
         // 00401c30: call __CxxThrowException@8
      [-]8b44240456508bf1e8bb480000c706fc9141008bc65ec20400
         // 00401c40: mov eax, ss:[esp+0x4]
         // 00401c44: push esi
         // 00401c45: push eax
         // 00401c46: mov esi, ecx
         // 00401c48: call ??0exception@std@@QAE@ABV01@@Z
         // 00401c4d: mov ds:[esi], ??_7bad_alloc@std@@6B@
         // 00401c53: mov eax, esi
         // 00401c55: pop esi
         // 00401c56: retn b2 0x4
      [-]83f80456577214
         // 00401c60: cmp eax, 0x4
         // 00401c63: push esi
         // 00401c64: push edi
         // 00401c65: jb 0x401c7b
      [-]8b323b317512
         // 00401c67: mov esi, ds:[edx]
         // 00401c69: cmp esi, ds:[ecx]
         // 00401c6b: jnz 0x401c7f
      [-]83e80483c10483c20483f80473ec
         // 00401c6d: sub eax, 0x4
         // 00401c70: add ecx, 0x4
         // 00401c73: add edx, 0x4
         // 00401c76: cmp eax, 0x4
         // 00401c79: jnb 0x401c67
      [-]85c0745e
         // 00401c7b: test eax, eax
         // 00401c7d: jz 0x401cdd
      [-]0fb6320fb6392bf77545
         // 00401c7f: movzx esi, b1 ds:[edx]
         // 00401c82: movzx edi, b1 ds:[ecx]
         // 00401c85: sub esi, edi
         // 00401c87: jnz 0x401cce
      [-]83e80183c10183c20185c07447
         // 00401c89: sub eax, 0x1
         // 00401c8c: add ecx, 0x1
         // 00401c8f: add edx, 0x1
         // 00401c92: test eax, eax
         // 00401c94: jz 0x401cdd
      [-]0fb6320fb6392bf7752e
         // 00401c96: movzx esi, b1 ds:[edx]
         // 00401c99: movzx edi, b1 ds:[ecx]
         // 00401c9c: sub esi, edi
         // 00401c9e: jnz 0x401cce
      [-]83e80183c10183c20185c07430
         // 00401ca0: sub eax, 0x1
         // 00401ca3: add ecx, 0x1
         // 00401ca6: add edx, 0x1
         // 00401ca9: test eax, eax
         // 00401cab: jz 0x401cdd
      [-]0fb6320fb6392bf77517
         // 00401cad: movzx esi, b1 ds:[edx]
         // 00401cb0: movzx edi, b1 ds:[ecx]
         // 00401cb3: sub esi, edi
         // 00401cb5: jnz 0x401cce
      [-]83e80183c10183c20185c07419
         // 00401cb7: sub eax, 0x1
         // 00401cba: add ecx, 0x1
         // 00401cbd: add edx, 0x1
         // 00401cc0: test eax, eax
         // 00401cc2: jz 0x401cdd
      [-]0fb6320fb6012bf0740f
         // 00401cc4: movzx esi, b1 ds:[edx]
         // 00401cc7: movzx eax, b1 ds:[ecx]
         // 00401cca: sub esi, eax
         // 00401ccc: jz 0x401cdd
      [-]85f6b8????????7f08
         // 00401cce: test esi, esi
         // 00401cd0: mov eax, 0x1
         // 00401cd5: jg 0x401cdf
      [-]5f83c8ff5ec3
         // 00401cd7: pop edi
         // 00401cd8: or eax, 0xffffffffffffffff
         // 00401cdb: pop esi
         // 00401cdc: retn 
      [-]6aff68????????64a1????????5056a184e1410033c4508d44240864a3????????8b7424188bcee87547000033c0894424108d4e0cc706????????6aff894114c74118????????508841048b44242450e8abf9ffff8bc68b4c240864890d????????595e83c40cc20800
         // 00401cf0: push 0xffffffffffffffff
         // 00401cf2: push 0x418138
         // 00401cf7: mov eax, fs:[0x0]
         // 00401cfd: push eax
         // 00401cfe: push esi
         // 00401cff: mov eax, ds:[___security_cookie]
         // 00401d04: xor eax, esp
         // 00401d06: push eax
         // 00401d07: lea eax, ss:[esp+0x8]
         // 00401d0b: mov fs:[0x0], eax
         // 00401d11: mov esi, ss:[esp+0x18]
         // 00401d15: mov ecx, esi
         // 00401d17: call 0x406491
         // 00401d1c: xor eax, eax
         // 00401d1e: mov ss:[esp+0x10], eax
         // 00401d22: lea ecx, ds:[esi+0xc]
         // 00401d25: mov ds:[esi], 0x41b804
         // 00401d2b: push 0xffffffffffffffff
         // 00401d2d: mov ds:[ecx+0x14], eax
         // 00401d30: mov ds:[ecx+0x18], 0xf
         // 00401d37: push eax
         // 00401d38: mov b1 ds:[ecx+0x4], b1 al
         // 00401d3b: mov eax, ss:[esp+0x24]
         // 00401d3f: push eax
         // 00401d40: call 0x4016f0
         // 00401d45: mov eax, esi
         // 00401d47: mov ecx, ss:[esp+0x8]
         // 00401d4b: mov fs:[0x0], ecx
         // 00401d52: pop ecx
         // 00401d53: pop esi
         // 00401d54: add esp, 0xc
         // 00401d57: retn b2 0x8
      [-]6aff68????????64a1????????505356a184e1410033c4508d44240c64a3????????8b74241c33db538bcee84b420000895c2414b8????????89461c895e18885e08894638895e34885e24894654895e50885e40894670895e6c885e5c68????????56c644241c04e85840000083c4088bc68b4c240c64890d????????595e5b83c40cc20400
         // 00401d70: push 0xffffffffffffffff
         // 00401d72: push 0x418274
         // 00401d77: mov eax, fs:[0x0]
         // 00401d7d: push eax
         // 00401d7e: push ebx
         // 00401d7f: push esi
         // 00401d80: mov eax, ds:[___security_cookie]
         // 00401d85: xor eax, esp
         // 00401d87: push eax
         // 00401d88: lea eax, ss:[esp+0xc]
         // 00401d8c: mov fs:[0x0], eax
         // 00401d92: mov esi, ss:[esp+0x1c]
         // 00401d96: xor ebx, ebx
         // 00401d98: push ebx
         // 00401d99: mov ecx, esi
         // 00401d9b: call ??0_Lockit@std@@QAE@H@Z
         // 00401da0: mov ss:[esp+0x14], ebx
         // 00401da4: mov eax, 0xf
         // 00401da9: mov ds:[esi+0x1c], eax
         // 00401dac: mov ds:[esi+0x18], ebx
         // 00401daf: mov b1 ds:[esi+0x8], b1 bl
         // 00401db2: mov ds:[esi+0x38], eax
         // 00401db5: mov ds:[esi+0x34], ebx
         // 00401db8: mov b1 ds:[esi+0x24], b1 bl
         // 00401dbb: mov ds:[esi+0x54], eax
         // 00401dbe: mov ds:[esi+0x50], ebx
         // 00401dc1: mov b1 ds:[esi+0x40], b1 bl
         // 00401dc4: mov ds:[esi+0x70], eax
         // 00401dc7: mov ds:[esi+0x6c], ebx
         // 00401dca: mov b1 ds:[esi+0x5c], b1 bl
         // 00401dcd: push 0x41b4f8
         // 00401dd2: push esi
         // 00401dd3: mov b1 ss:[esp+0x1c], b1 0x4
         // 00401dd8: call ?_Locinfo_ctor@_Locinfo@std@@SAXPAV12@PBD@Z
         // 00401ddd: add esp, 0x8
         // 00401de0: mov eax, esi
         // 00401de2: mov ecx, ss:[esp+0xc]
         // 00401de6: mov fs:[0x0], ecx
         // 00401ded: pop ecx
         // 00401dee: pop esi
         // 00401def: pop ebx
         // 00401df0: add esp, 0xc
         // 00401df3: retn b2 0x4
      [-]6aff68????????64a1????????5053555657a184e1410033c4508d44241464a3????????8b74242456c7442420????????e8a03e0000bd????????83c404396e70720c
         // 00401e00: push 0xffffffffffffffff
         // 00401e02: push 0x418034
         // 00401e07: mov eax, fs:[0x0]
         // 00401e0d: push eax
         // 00401e0e: push ebx
         // 00401e0f: push ebp
         // 00401e10: push esi
         // 00401e11: push edi
         // 00401e12: mov eax, ds:[___security_cookie]
         // 00401e17: xor eax, esp
         // 00401e19: push eax
         // 00401e1a: lea eax, ss:[esp+0x14]
         // 00401e1e: mov fs:[0x0], eax
         // 00401e24: mov esi, ss:[esp+0x24]
         // 00401e28: push esi
         // 00401e29: mov ss:[esp+0x20], 0x4
         // 00401e31: call ?_Locinfo_dtor@_Locinfo@std@@SAXPAV12@@Z
         // 00401e36: mov ebp, 0x10
         // 00401e3b: add esp, 0x4
         // 00401e3e: cmp ds:[esi+0x70], ebp
         // 00401e41: jb 0x401e4f
      [-]8b465c50e8b149000083c404
         // 00401e43: mov eax, ds:[esi+0x5c]
         // 00401e46: push eax
         // 00401e47: call j__free
         // 00401e4c: add esp, 0x4
      [-]33dbbf????????897e70895e6c885e5c396e54720c
         // 00401e4f: xor ebx, ebx
         // 00401e51: mov edi, 0xf
         // 00401e56: mov ds:[esi+0x70], edi
         // 00401e59: mov ds:[esi+0x6c], ebx
         // 00401e5c: mov b1 ds:[esi+0x5c], b1 bl
         // 00401e5f: cmp ds:[esi+0x54], ebp
         // 00401e62: jb 0x401e70
      [-]8b464050e89049000083c404
         // 00401e64: mov eax, ds:[esi+0x40]
         // 00401e67: push eax
         // 00401e68: call j__free
         // 00401e6d: add esp, 0x4
      [-]897e54895e50885e40396e38720c
         // 00401e70: mov ds:[esi+0x54], edi
         // 00401e73: mov ds:[esi+0x50], ebx
         // 00401e76: mov b1 ds:[esi+0x40], b1 bl
         // 00401e79: cmp ds:[esi+0x38], ebp
         // 00401e7c: jb 0x401e8a
      [-]8b462450e87649000083c404
         // 00401e7e: mov eax, ds:[esi+0x24]
         // 00401e81: push eax
         // 00401e82: call j__free
         // 00401e87: add esp, 0x4
      [-]897e38895e34885e24396e1c720c
         // 00401e8a: mov ds:[esi+0x38], edi
         // 00401e8d: mov ds:[esi+0x34], ebx
         // 00401e90: mov b1 ds:[esi+0x24], b1 bl
         // 00401e93: cmp ds:[esi+0x1c], ebp
         // 00401e96: jb 0x401ea4
      [-]8b460850e85c49000083c404
         // 00401e98: mov eax, ds:[esi+0x8]
         // 00401e9b: push eax
         // 00401e9c: call j__free
         // 00401ea1: add esp, 0x4
      [-]897e1c895e188bce885e08c744241c????????e8504100008b4c241464890d????????595f5e5d5b83c40cc20400
         // 00401ea4: mov ds:[esi+0x1c], edi
         // 00401ea7: mov ds:[esi+0x18], ebx
         // 00401eaa: mov ecx, esi
         // 00401eac: mov b1 ds:[esi+0x8], b1 bl
         // 00401eaf: mov ss:[esp+0x1c], 0xffffffffffffffff
         // 00401eb7: call ??1_Lockit@std@@QAE@XZ
         // 00401ebc: mov ecx, ss:[esp+0x14]
         // 00401ec0: mov fs:[0x0], ecx
         // 00401ec7: pop ecx
         // 00401ec8: pop edi
         // 00401ec9: pop esi
         // 00401eca: pop ebp
         // 00401ecb: pop ebx
         // 00401ecc: add esp, 0xc
         // 00401ecf: retn b2 0x4
      [-]6aff68????????64a1????????50515657a184e1410033c4508d44241064a3????????8bf18974240c8b7c242057e8f545000033d2895424186aff8d4e0cc706????????8d470c52c74118????????89511450885104e8b5f7ffff8bc68b4c241064890d????????595f5e83c410c20400
         // 00401ee0: push 0xffffffffffffffff
         // 00401ee2: push 0x418108
         // 00401ee7: mov eax, fs:[0x0]
         // 00401eed: push eax
         // 00401eee: push ecx
         // 00401eef: push esi
         // 00401ef0: push edi
         // 00401ef1: mov eax, ds:[___security_cookie]
         // 00401ef6: xor eax, esp
         // 00401ef8: push eax
         // 00401ef9: lea eax, ss:[esp+0x10]
         // 00401efd: mov fs:[0x0], eax
         // 00401f03: mov esi, ecx
         // 00401f05: mov ss:[esp+0xc], esi
         // 00401f09: mov edi, ss:[esp+0x20]
         // 00401f0d: push edi
         // 00401f0e: call ??0exception@std@@QAE@ABV01@@Z
         // 00401f13: xor edx, edx
         // 00401f15: mov ss:[esp+0x18], edx
         // 00401f19: push 0xffffffffffffffff
         // 00401f1b: lea ecx, ds:[esi+0xc]
         // 00401f1e: mov ds:[esi], 0x41b804
         // 00401f24: lea eax, ds:[edi+0xc]
         // 00401f27: push edx
         // 00401f28: mov ds:[ecx+0x18], 0xf
         // 00401f2f: mov ds:[ecx+0x14], edx
         // 00401f32: push eax
         // 00401f33: mov b1 ds:[ecx+0x4], b1 dl
         // 00401f36: call 0x4016f0
         // 00401f3b: mov eax, esi
         // 00401f3d: mov ecx, ss:[esp+0x10]
         // 00401f41: mov fs:[0x0], ecx
         // 00401f48: pop ecx
         // 00401f49: pop edi
         // 00401f4a: pop esi
         // 00401f4b: add esp, 0x10
         // 00401f4e: retn b2 0x4
      [-]51568bf16a008d4c2408e87c4000008b460483f8ff7306
         // 00401f60: push ecx
         // 00401f61: push esi
         // 00401f62: mov esi, ecx
         // 00401f64: push 0x0
         // 00401f66: lea ecx, ss:[esp+0x8]
         // 00401f6a: call ??0_Lockit@std@@QAE@H@Z
         // 00401f6f: mov eax, ds:[esi+0x4]
         // 00401f72: cmp eax, 0xffffffffffffffff
         // 00401f75: jnb 0x401f7d
      [-]83c001894604
         // 00401f77: add eax, 0x1
         // 00401f7a: mov ds:[esi+0x4], eax
      [-]8d4c2404e8864000005e59c3
         // 00401f7d: lea ecx, ss:[esp+0x4]
         // 00401f81: call ??1_Lockit@std@@QAE@XZ
         // 00401f86: pop esi
         // 00401f87: pop ecx
         // 00401f88: retn 
      [-]5156578bf96a008d4c240ce84b4000008b470485c0760b
         // 00401f90: push ecx
         // 00401f91: push esi
         // 00401f92: push edi
         // 00401f93: mov edi, ecx
         // 00401f95: push 0x0
         // 00401f97: lea ecx, ss:[esp+0xc]
         // 00401f9b: call ??0_Lockit@std@@QAE@H@Z
         // 00401fa0: mov eax, ds:[edi+0x4]
         // 00401fa3: test eax, eax
         // 00401fa5: jbe 0x401fb2
      [-]83f8ff7306
         // 00401fa7: cmp eax, 0xffffffffffffffff
         // 00401faa: jnb 0x401fb2
      [-]83c0ff894704
         // 00401fac: add eax, 0xffffffffffffffff
         // 00401faf: mov ds:[edi+0x4], eax
      [-]8b7704f7de1bf6f7d68d4c240823f7e8464000005f8bc65e59c3
         // 00401fb2: mov esi, ds:[edi+0x4]
         // 00401fb5: neg esi
         // 00401fb7: sbb esi, esi
         // 00401fb9: not esi
         // 00401fbb: lea ecx, ss:[esp+0x8]
         // 00401fbf: and esi, edi
         // 00401fc1: call ??1_Lockit@std@@QAE@XZ
         // 00401fc6: pop edi
         // 00401fc7: mov eax, esi
         // 00401fc9: pop esi
         // 00401fca: pop ecx
         // 00401fcb: retn 
      [-]c70154924100c3
         // 00401fd0: mov ds:[ecx], ??_7facet@locale@std@@6B@
         // 00401fd6: retn 
      [-]51578b3985ff7441
         // 00401fe0: push ecx
         // 00401fe1: push edi
         // 00401fe2: mov edi, ds:[ecx]
         // 00401fe4: test edi, edi
         // 00401fe6: jz 0x402029
      [-]6a008d4c2408e8f83f00008b470485c0760b
         // 00401fe8: push 0x0
         // 00401fea: lea ecx, ss:[esp+0x8]
         // 00401fee: call ??0_Lockit@std@@QAE@H@Z
         // 00401ff3: mov eax, ds:[edi+0x4]
         // 00401ff6: test eax, eax
         // 00401ff8: jbe 0x402005
      [-]83f8ff7306
         // 00401ffa: cmp eax, 0xffffffffffffffff
         // 00401ffd: jnb 0x402005
      [-]83c0ff894704
         // 00401fff: add eax, 0xffffffffffffffff
         // 00402002: mov ds:[edi+0x4], eax
      [-]568b7704f7de1bf6f7d68d4c240823f7e8f23f000085f6740a
         // 00402005: push esi
         // 00402006: mov esi, ds:[edi+0x4]
         // 00402009: neg esi
         // 0040200b: sbb esi, esi
         // 0040200d: not esi
         // 0040200f: lea ecx, ss:[esp+0x8]
         // 00402013: and esi, edi
         // 00402015: call ??1_Lockit@std@@QAE@XZ
         // 0040201a: test esi, esi
         // 0040201c: jz 0x402028
      [-]8b068b106a018bceffd2
         // 0040201e: mov eax, ds:[esi]
         // 00402020: mov edx, ds:[eax]
         // 00402022: push 0x1
         // 00402024: mov ecx, esi
         // 00402026: call edx
      [-]c70054924100c3
         // 00402030: mov ds:[eax], ??_7facet@locale@std@@6B@
         // 00402036: retn 
      [-]b8????????c3
         // 00402050: mov eax, 0x1
         // 00402055: retn 
      [-]6aff68????????64a1????????5081ec????????a184e1410033c4898424????????a184e1410033c4508d8424????????64a3????????33c089742408894604898424????????8d44241c50c70610b84100e8b9fcffff8d4c240c51e8994000008b108956088b4804894e0c8b50088956108b400c83c4048d4c241c51894614e81bfdffff8bc68b8c24????????64890d????????598b8c24????????33cce8c145000081c4????????c3
         // 00402060: push 0xffffffffffffffff
         // 00402062: push 0x41834b
         // 00402067: mov eax, fs:[0x0]
         // 0040206d: push eax
         // 0040206e: sub esp, 0x94
         // 00402074: mov eax, ds:[___security_cookie]
         // 00402079: xor eax, esp
         // 0040207b: mov ss:[esp+0x90], eax
         // 00402082: mov eax, ds:[___security_cookie]
         // 00402087: xor eax, esp
         // 00402089: push eax
         // 0040208a: lea eax, ss:[esp+0x98]
         // 00402091: mov fs:[0x0], eax
         // 00402097: xor eax, eax
         // 00402099: mov ss:[esp+0x8], esi
         // 0040209d: mov ds:[esi+0x4], eax
         // 004020a0: mov ss:[esp+0xa0], eax
         // 004020a7: lea eax, ss:[esp+0x1c]
         // 004020ab: push eax
         // 004020ac: mov ds:[esi], ??_7?$ctype@D@std@@6B@
         // 004020b2: call 0x401d70
         // 004020b7: lea ecx, ss:[esp+0xc]
         // 004020bb: push ecx
         // 004020bc: call __Getctype
         // 004020c1: mov edx, ds:[eax]
         // 004020c3: mov ds:[esi+0x8], edx
         // 004020c6: mov ecx, ds:[eax+0x4]
         // 004020c9: mov ds:[esi+0xc], ecx
         // 004020cc: mov edx, ds:[eax+0x8]
         // 004020cf: mov ds:[esi+0x10], edx
         // 004020d2: mov eax, ds:[eax+0xc]
         // 004020d5: add esp, 0x4
         // 004020d8: lea ecx, ss:[esp+0x1c]
         // 004020dc: push ecx
         // 004020dd: mov ds:[esi+0x14], eax
         // 004020e0: call 0x401e00
         // 004020e5: mov eax, esi
         // 004020e7: mov ecx, ss:[esp+0x98]
         // 004020ee: mov fs:[0x0], ecx
         // 004020f5: pop ecx
         // 004020f6: mov ecx, ss:[esp+0x90]
         // 004020fd: xor ecx, esp
         // 004020ff: call @__security_check_cookie@4
         // 00402104: add esp, 0xa0
         // 0040210a: retn 
      [-]6aff68????????64a1????????5083ec0856a184e1410033c4508d44241064a3????????85ff742c
         // 00402110: push 0xffffffffffffffff
         // 00402112: push 0x41838b
         // 00402117: mov eax, fs:[0x0]
         // 0040211d: push eax
         // 0040211e: sub esp, 0x8
         // 00402121: push esi
         // 00402122: mov eax, ds:[___security_cookie]
         // 00402127: xor eax, esp
         // 00402129: push eax
         // 0040212a: lea eax, ss:[esp+0x10]
         // 0040212e: mov fs:[0x0], eax
         // 00402134: test edi, edi
         // 00402136: jz 0x402164
      [-]833f007527
         // 00402138: cmp ds:[edi], 0x0
         // 0040213b: jnz 0x402164
      [-]6a18e8d244000083c4048944240c85c0c74424????????007409
         // 0040213d: push 0x18
         // 0040213f: call ??2@YAPAXI@Z
         // 00402144: add esp, 0x4
         // 00402147: mov ss:[esp+0xc], eax
         // 0040214b: test eax, eax
         // 0040214d: mov ss:[esp+0x18], 0x0
         // 00402155: jz 0x402160
      [-]8bf0e802ffffffeb02
         // 00402157: mov esi, eax
         // 00402159: call 0x402060
         // 0040215e: jmp 0x402162
      [-]b8????????8b4c241064890d????????595e83c414c3
         // 00402164: mov eax, 0x2
         // 00402169: mov ecx, ss:[esp+0x10]
         // 0040216d: mov fs:[0x0], ecx
         // 00402174: pop ecx
         // 00402175: pop esi
         // 00402176: add esp, 0x14
         // 00402179: retn 
      [-]0fb644240483c1085150e8bc3e000083c408c20400
         // 00402180: movzx eax, b1 ss:[esp+0x4]
         // 00402185: add ecx, 0x8
         // 00402188: push ecx
         // 00402189: push eax
         // 0040218a: call __Tolower
         // 0040218f: add esp, 0x8
         // 00402192: retn b2 0x4
      [-]538b5c240c568b74240c3bf3741b
         // 004021a0: push ebx
         // 004021a1: mov ebx, ss:[esp+0xc]
         // 004021a5: push esi
         // 004021a6: mov esi, ss:[esp+0xc]
         // 004021aa: cmp esi, ebx
         // 004021ac: jz 0x4021c9
      [-]578d7908
         // 004021ae: push edi
         // 004021af: lea edi, ds:[ecx+0x8]
      [-]0fb6065750e88f3e0000880683c60183c4083bf375ea
         // 004021b2: movzx eax, b1 ds:[esi]
         // 004021b5: push edi
         // 004021b6: push eax
         // 004021b7: call __Tolower
         // 004021bc: mov b1 ds:[esi], b1 al
         // 004021be: add esi, 0x1
         // 004021c1: add esp, 0x8
         // 004021c4: cmp esi, ebx
         // 004021c6: jnz 0x4021b2
      [-]8bc65e5bc20800
         // 004021c9: mov eax, esi
         // 004021cb: pop esi
         // 004021cc: pop ebx
         // 004021cd: retn b2 0x8
      [-]0fb644240483c1085150e8a03c000083c408c20400
         // 004021d0: movzx eax, b1 ss:[esp+0x4]
         // 004021d5: add ecx, 0x8
         // 004021d8: push ecx
         // 004021d9: push eax
         // 004021da: call __Toupper
         // 004021df: add esp, 0x8
         // 004021e2: retn b2 0x4
      [-]538b5c240c568b74240c3bf3741b
         // 004021f0: push ebx
         // 004021f1: mov ebx, ss:[esp+0xc]
         // 004021f5: push esi
         // 004021f6: mov esi, ss:[esp+0xc]
         // 004021fa: cmp esi, ebx
         // 004021fc: jz 0x402219
      [-]578d7908
         // 004021fe: push edi
         // 004021ff: lea edi, ds:[ecx+0x8]
      [-]0fb6065750e8733c0000880683c60183c4083bf375ea
         // 00402202: movzx eax, b1 ds:[esi]
         // 00402205: push edi
         // 00402206: push eax
         // 00402207: call __Toupper
         // 0040220c: mov b1 ds:[esi], b1 al
         // 0040220e: add esi, 0x1
         // 00402211: add esp, 0x8
         // 00402214: cmp esi, ebx
         // 00402216: jnz 0x402202
      [-]8bc65e5bc20800
         // 00402219: mov eax, esi
         // 0040221b: pop esi
         // 0040221c: pop ebx
         // 0040221d: retn b2 0x8
      [-]8b4424088b542404568b31578bf82bfa578b7c241857508b461c52ffd05f5ec20c00
         // 00402230: mov eax, ss:[esp+0x8]
         // 00402234: mov edx, ss:[esp+0x4]
         // 00402238: push esi
         // 00402239: mov esi, ds:[ecx]
         // 0040223b: push edi
         // 0040223c: mov edi, eax
         // 0040223e: sub edi, edx
         // 00402240: push edi
         // 00402241: mov edi, ss:[esp+0x18]
         // 00402245: push edi
         // 00402246: push eax
         // 00402247: mov eax, ds:[esi+0x1c]
         // 0040224a: push edx
         // 0040224b: call eax
         // 0040224d: pop edi
         // 0040224e: pop esi
         // 0040224f: retn b2 0xc
      [-]538b5c2408558b6c241856578b7c24188bf72bf33bee7305
         // 00402260: push ebx
         // 00402261: mov ebx, ss:[esp+0x8]
         // 00402265: push ebp
         // 00402266: mov ebp, ss:[esp+0x18]
         // 0040226a: push esi
         // 0040226b: push edi
         // 0040226c: mov edi, ss:[esp+0x18]
         // 00402270: mov esi, edi
         // 00402272: sub esi, ebx
         // 00402274: cmp ebp, esi
         // 00402276: jnb 0x40227d
      [-]e8c9500000
         // 00402278: call __invalid_parameter_noinfo
      [-]8b44241c56535550e84a44000083c4108bc75f5e5d5bc21000
         // 0040227d: mov eax, ss:[esp+0x1c]
         // 00402281: push esi
         // 00402282: push ebx
         // 00402283: push ebp
         // 00402284: push eax
         // 00402285: call _memcpy_s
         // 0040228a: add esp, 0x10
         // 0040228d: mov eax, edi
         // 0040228f: pop edi
         // 00402290: pop esi
         // 00402291: pop ebp
         // 00402292: pop ebx
         // 00402293: retn b2 0x10
      [-]8b4424088b542404568b31578bf82bfa578b7c241c578b7c241c57508b462852ffd05f5ec21000
         // 004022b0: mov eax, ss:[esp+0x8]
         // 004022b4: mov edx, ss:[esp+0x4]
         // 004022b8: push esi
         // 004022b9: mov esi, ds:[ecx]
         // 004022bb: push edi
         // 004022bc: mov edi, eax
         // 004022be: sub edi, edx
         // 004022c0: push edi
         // 004022c1: mov edi, ss:[esp+0x1c]
         // 004022c5: push edi
         // 004022c6: mov edi, ss:[esp+0x1c]
         // 004022ca: push edi
         // 004022cb: push eax
         // 004022cc: mov eax, ds:[esi+0x28]
         // 004022cf: push edx
         // 004022d0: call eax
         // 004022d2: pop edi
         // 004022d3: pop esi
         // 004022d4: retn b2 0x10
      [-]538b5c2408558b6c241c56578b7c24188bf72bf33bee7305
         // 004022e0: push ebx
         // 004022e1: mov ebx, ss:[esp+0x8]
         // 004022e5: push ebp
         // 004022e6: mov ebp, ss:[esp+0x1c]
         // 004022ea: push esi
         // 004022eb: push edi
         // 004022ec: mov edi, ss:[esp+0x18]
         // 004022f0: mov esi, edi
         // 004022f2: sub esi, ebx
         // 004022f4: cmp ebp, esi
         // 004022f6: jnb 0x4022fd
      [-]e849500000
         // 004022f8: call __invalid_parameter_noinfo
      [-]8b44242056535550e8ca43000083c4108bc75f5e5d5bc21400
         // 004022fd: mov eax, ss:[esp+0x20]
         // 00402301: push esi
         // 00402302: push ebx
         // 00402303: push ebp
         // 00402304: push eax
         // 00402305: call _memcpy_s
         // 0040230a: add esp, 0x10
         // 0040230d: mov eax, edi
         // 0040230f: pop edi
         // 00402310: pop esi
         // 00402311: pop ebp
         // 00402312: pop ebx
         // 00402313: retn b2 0x14
      [-]568bf18b461485c0c70610b841007e0b
         // 00402320: push esi
         // 00402321: mov esi, ecx
         // 00402323: mov eax, ds:[esi+0x14]
         // 00402326: test eax, eax
         // 00402328: mov ds:[esi], ??_7?$ctype@D@std@@6B@
         // 0040232e: jle 0x40233b
      [-]8b461050e8e6540000eb0b
         // 00402330: mov eax, ds:[esi+0x10]
         // 00402333: push eax
         // 00402334: call _free
         // 00402339: jmp 0x402346
      [-]8b4e1051e801590000
         // 0040233d: mov ecx, ds:[esi+0x10]
         // 00402340: push ecx
         // 00402341: call j_j__free
      [-]f644240801c706549241007409
         // 00402349: test b1 ss:[esp+0x8], b1 0x1
         // 0040234e: mov ds:[esi], ??_7facet@locale@std@@6B@
         // 00402354: jz 0x40235f
      [-]56e8a144000083c404
         // 00402356: push esi
         // 00402357: call j__free
         // 0040235c: add esp, 0x4
      [-]8bc65ec20400
         // 0040235f: mov eax, esi
         // 00402361: pop esi
         // 00402362: retn b2 0x4
      [-]568bf1c706????????837e2410720c
         // 00402370: push esi
         // 00402371: mov esi, ecx
         // 00402373: mov ds:[esi], 0x41b804
         // 00402379: cmp ds:[esi+0x24], 0x10
         // 0040237d: jb 0x40238b
      [-]8b461050e87544000083c404
         // 0040237f: mov eax, ds:[esi+0x10]
         // 00402382: push eax
         // 00402383: call j__free
         // 00402388: add esp, 0x4
      [-]33c0c74624????????8946208846108bce5ee9be410000
         // 0040238b: xor eax, eax
         // 0040238d: mov ds:[esi+0x24], 0xf
         // 00402394: mov ds:[esi+0x20], eax
         // 00402397: mov b1 ds:[esi+0x10], b1 al
         // 0040239a: mov ecx, esi
         // 0040239c: pop esi
         // 0040239d: jmp 0x406560
      [-]6aff68????????64a1????????5081ec????????a184e1410033c4508d8424????????64a3????????8b410c234108a8047456
         // 004023b0: push 0xffffffffffffffff
         // 004023b2: push 0x41831e
         // 004023b7: mov eax, fs:[0x0]
         // 004023bd: push eax
         // 004023be: sub esp, 0x8c
         // 004023c4: mov eax, ds:[___security_cookie]
         // 004023c9: xor eax, esp
         // 004023cb: push eax
         // 004023cc: lea eax, ss:[esp+0x90]
         // 004023d3: mov fs:[0x0], eax
         // 004023d9: mov eax, ds:[ecx+0xc]
         // 004023dc: and eax, ds:[ecx+0x8]
         // 004023df: test b1 al, b1 0x4
         // 004023e1: jz 0x402439
      [-]6a1468????????8d4c2410c7442428????????c74424????????00c644241400e8f8f4ffff8d442408508d4c242851c78424????????????????e8cef8ffff6870cb41008d54242852c744242c40b84100e8f25a0000
         // 004023e3: push 0x14
         // 004023e5: push 0x41b4fc
         // 004023ea: lea ecx, ss:[esp+0x10]
         // 004023ee: mov ss:[esp+0x28], 0xf
         // 004023f6: mov ss:[esp+0x24], 0x0
         // 004023fe: mov b1 ss:[esp+0x14], b1 0x0
         // 00402403: call 0x401900
         // 00402408: lea eax, ss:[esp+0x8]
         // 0040240c: push eax
         // 0040240d: lea ecx, ss:[esp+0x28]
         // 00402411: push ecx
         // 00402412: mov ss:[esp+0xa0], 0x0
         // 0040241d: call 0x401cf0
         // 00402422: push __TI3?AVfailure@ios_base@std@@
         // 00402427: lea edx, ss:[esp+0x28]
         // 0040242b: push edx
         // 0040242c: mov ss:[esp+0x2c], ??_7failure@ios_base@std@@6B@
         // 00402434: call __CxxThrowException@8
      [-]a802743f
         // 00402439: test b1 al, b1 0x2
         // 0040243b: jz 0x40247c
      [-]68????????8d4c240ce8d5f1ffff8d442408508d4c242851c78424????????????????e88bf8ffff6870cb41008d54242852c744242c40b84100e8af5a0000
         // 0040243d: push 0x41b514
         // 00402442: lea ecx, ss:[esp+0xc]
         // 00402446: call 0x401620
         // 0040244b: lea eax, ss:[esp+0x8]
         // 0040244f: push eax
         // 00402450: lea ecx, ss:[esp+0x28]
         // 00402454: push ecx
         // 00402455: mov ss:[esp+0xa0], 0x1
         // 00402460: call 0x401cf0
         // 00402465: push __TI3?AVfailure@ios_base@std@@
         // 0040246a: lea edx, ss:[esp+0x28]
         // 0040246e: push edx
         // 0040246f: mov ss:[esp+0x2c], ??_7failure@ios_base@std@@6B@
         // 00402477: call __CxxThrowException@8
      [-]68????????8d4c2478e896f1ffff8d442474508d4c245051c78424????????????????e84cf8ffff6870cb41008d54245052c744245440b84100e8705a0000
         // 0040247c: push 0x41b52c
         // 00402481: lea ecx, ss:[esp+0x78]
         // 00402485: call 0x401620
         // 0040248a: lea eax, ss:[esp+0x74]
         // 0040248e: push eax
         // 0040248f: lea ecx, ss:[esp+0x50]
         // 00402493: push ecx
         // 00402494: mov ss:[esp+0xa0], 0x2
         // 0040249f: call 0x401cf0
         // 004024a4: push __TI3?AVfailure@ios_base@std@@
         // 004024a9: lea edx, ss:[esp+0x50]
         // 004024ad: push edx
         // 004024ae: mov ss:[esp+0x54], ??_7failure@ios_base@std@@6B@
         // 004024b6: call __CxxThrowException@8
      [-]518b4824568b316a008d4c24088937e8173b00008b460483f8ff7306
         // 004024c0: push ecx
         // 004024c1: mov ecx, ds:[eax+0x24]
         // 004024c4: push esi
         // 004024c5: mov esi, ds:[ecx]
         // 004024c7: push 0x0
         // 004024c9: lea ecx, ss:[esp+0x8]
         // 004024cd: mov ds:[edi], esi
         // 004024cf: call ??0_Lockit@std@@QAE@H@Z
         // 004024d4: mov eax, ds:[esi+0x4]
         // 004024d7: cmp eax, 0xffffffffffffffff
         // 004024da: jnb 0x4024e2
      [-]83c001894604
         // 004024dc: add eax, 0x1
         // 004024df: mov ds:[esi+0x4], eax
      [-]8d4c2404e8213b00008bc75e59c3
         // 004024e2: lea ecx, ss:[esp+0x4]
         // 004024e6: call ??1_Lockit@std@@QAE@XZ
         // 004024eb: mov eax, edi
         // 004024ed: pop esi
         // 004024ee: pop ecx
         // 004024ef: retn 
      [-]83ec08535533ed576a04896e24896e0cc74610????????c74614????????896e18896e1c896e20896e08e8f74000008bf883c4043bfd7439
         // 004024f0: sub esp, 0x8
         // 004024f3: push ebx
         // 004024f4: push ebp
         // 004024f5: xor ebp, ebp
         // 004024f7: push edi
         // 004024f8: push 0x4
         // 004024fa: mov ds:[esi+0x24], ebp
         // 004024fd: mov ds:[esi+0xc], ebp
         // 00402500: mov ds:[esi+0x10], 0x201
         // 00402507: mov ds:[esi+0x14], 0x6
         // 0040250e: mov ds:[esi+0x18], ebp
         // 00402511: mov ds:[esi+0x1c], ebp
         // 00402514: mov ds:[esi+0x20], ebp
         // 00402517: mov ds:[esi+0x8], ebp
         // 0040251a: call ??2@YAPAXI@Z
         // 0040251f: mov edi, eax
         // 00402521: add esp, 0x4
         // 00402524: cmp edi, ebp
         // 00402526: jz 0x402561
      [-]e86e3800008907e89b360000558d4c24148bd8e8ab3a00008b430483f8ff7306
         // 00402528: call ?_Init@locale@std@@CAPAV_Locimp@12@XZ
         // 0040252d: mov ds:[edi], eax
         // 0040252f: call 0x405bcf
         // 00402534: push ebp
         // 00402535: lea ecx, ss:[esp+0x14]
         // 00402539: mov ebx, eax
         // 0040253b: call ??0_Lockit@std@@QAE@H@Z
         // 00402540: mov eax, ds:[ebx+0x4]
         // 00402543: cmp eax, 0xffffffffffffffff
         // 00402546: jnb 0x40254e
      [-]83c001894304
         // 00402548: add eax, 0x1
         // 0040254b: mov ds:[ebx+0x4], eax
      [-]8d4c2410e8b53a0000897e245f5d5b83c408c3
         // 0040254e: lea ecx, ss:[esp+0x10]
         // 00402552: call ??1_Lockit@std@@QAE@XZ
         // 00402557: mov ds:[esi+0x24], edi
         // 0040255a: pop edi
         // 0040255b: pop ebp
         // 0040255c: pop ebx
         // 0040255d: add esp, 0x8
         // 00402560: retn 
      [-]5f896e245d5b83c408c3
         // 00402561: pop edi
         // 00402562: mov ds:[esi+0x24], ebp
         // 00402565: pop ebp
         // 00402566: pop ebx
         // 00402567: add esp, 0x8
         // 0040256a: retn 
      [-]568bf1c706????????837e2410720c
         // 00402570: push esi
         // 00402571: mov esi, ecx
         // 00402573: mov ds:[esi], 0x41b804
         // 00402579: cmp ds:[esi+0x24], 0x10
         // 0040257d: jb 0x40258b
      [-]8b461050e87542000083c404
         // 0040257f: mov eax, ds:[esi+0x10]
         // 00402582: push eax
         // 00402583: call j__free
         // 00402588: add esp, 0x4
      [-]33c0c74624????????8946208bce884610e8bf3f0000f64424080174
         // 0040258b: xor eax, eax
         // 0040258d: mov ds:[esi+0x24], 0xf
         // 00402594: mov ds:[esi+0x20], eax
         // 00402597: mov ecx, esi
         // 00402599: mov b1 ds:[esi+0x10], b1 al
         // 0040259c: call 0x406560
         // 004025a1: test b1 ss:[esp+0x8], b1 0x1
         // 004025a6: jz 0x4025b1

  }
  condition:
    all of them
}
