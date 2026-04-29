rule canbis_10_0 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         5383c4bcbb????????54e889fffffff644242c017405
         // 00401170: push ebx
         // 00401171: add esp, 0xffffffffffffffbc
         // 00401174: mov ebx, 0xa
         // 00401179: push esp
         // 0040117a: call GetStartupInfoA
         // 0040117f: test b1 ss:[esp+0x2c], b1 0x1
         // 00401184: jz 0x40118b
      [-]0fb75c2430
         // 00401186: movzx ebx, b2 ss:[esp+0x30]
      [-]8bc383c4445bc3
         // 0040118b: mov eax, ebx
         // 0040118d: add esp, 0x44
         // 00401190: pop ebx
         // 00401191: retn 
      [-]5356be????????833e00753a
         // 004011d4: push ebx
         // 004011d5: push esi
         // 004011d6: mov esi, 0x40e5d0
         // 004011db: cmp ds:[esi], 0x0
         // 004011de: jnz 0x40121a
      [-]68????????6a00e8a8ffffff8bc885c97505
         // 004011e0: push 0x644
         // 004011e5: push 0x0
         // 004011e7: call LocalAlloc
         // 004011ec: mov ecx, eax
         // 004011ee: test ecx, ecx
         // 004011f0: jnz 0x4011f7
      [-]33c05e5bc3
         // 004011f2: xor eax, eax
         // 004011f4: pop esi
         // 004011f5: pop ebx
         // 004011f6: retn 
      [-]a1????????8901890d????????33d2
         // 004011f7: mov eax, ds:[0x40e5cc]
         // 004011fc: mov ds:[ecx], eax
         // 004011fe: mov ds:[0x40e5cc], ecx
         // 00401204: xor edx, edx
      [-]8bc203c08d44c1048b1e891889064283fa6475ec
         // 00401206: mov eax, edx
         // 00401208: add eax, eax
         // 0040120a: lea eax, ds:[ecx+eax*0x8]
         // 0040120e: mov ebx, ds:[esi]
         // 00401210: mov ds:[eax], ebx
         // 00401212: mov ds:[esi], eax
         // 00401214: inc edx
         // 00401215: cmp edx, 0x64
         // 00401218: jnz 0x401206
      [-]8b068b1089165e5bc3
         // 0040121a: mov eax, ds:[esi]
         // 0040121c: mov edx, ds:[eax]
         // 0040121e: mov ds:[esi], edx
         // 00401220: pop esi
         // 00401221: pop ebx
         // 00401222: retn 
      [-]8900894004c3
         // 00401224: mov ds:[eax], eax
         // 00401226: mov ds:[eax+0x4], eax
         // 00401229: retn 
      [-]53568bf28bd8e89dffffff85c07505
         // 0040122c: push ebx
         // 0040122d: push esi
         // 0040122e: mov esi, edx
         // 00401230: mov ebx, eax
         // 00401232: call 0x4011d4
         // 00401237: test eax, eax
         // 00401239: jnz 0x401240
      [-]33c05e5bc3
         // 0040123b: xor eax, eax
         // 0040123d: pop esi
         // 0040123e: pop ebx
         // 0040123f: retn 
      [-]8b168950088b560489500c8b1389108958048942048903b0015e5bc3
         // 00401240: mov edx, ds:[esi]
         // 00401242: mov ds:[eax+0x8], edx
         // 00401245: mov edx, ds:[esi+0x4]
         // 00401248: mov ds:[eax+0xc], edx
         // 0040124b: mov edx, ds:[ebx]
         // 0040124d: mov ds:[eax], edx
         // 0040124f: mov ds:[eax+0x4], ebx
         // 00401252: mov ds:[edx+0x4], eax
         // 00401255: mov ds:[ebx], eax
         // 00401257: mov b1 al, b1 0x1
         // 00401259: pop esi
         // 0040125a: pop ebx
         // 0040125b: retn 
      [-]8b50048b08890a8951048b15????????8910a3????????c3
         // 0040125c: mov edx, ds:[eax+0x4]
         // 0040125f: mov ecx, ds:[eax]
         // 00401261: mov ds:[edx], ecx
         // 00401263: mov ds:[ecx+0x4], edx
         // 00401266: mov edx, ds:[0x40e5d0]
         // 0040126c: mov ds:[eax], edx
         // 0040126e: mov ds:[0x40e5d0], eax
         // 00401273: retn 
      [-]53565755518bf18914248be88b5d008b04248b1089168b5004895604
         // 00401274: push ebx
         // 00401275: push esi
         // 00401276: push edi
         // 00401277: push ebp
         // 00401278: push ecx
         // 00401279: mov esi, ecx
         // 0040127b: mov ss:[esp], edx
         // 0040127e: mov ebp, eax
         // 00401280: mov ebx, ss:[ebp+0x0]
         // 00401283: mov eax, ss:[esp]
         // 00401286: mov edx, ds:[eax]
         // 00401288: mov ds:[esi], edx
         // 0040128a: mov edx, ds:[eax+0x4]
         // 0040128d: mov ds:[esi+0x4], edx
      [-]8b3b8b068b530803530c3bc27514
         // 00401290: mov edi, ds:[ebx]
         // 00401292: mov eax, ds:[esi]
         // 00401294: mov edx, ds:[ebx+0x8]
         // 00401297: add edx, ds:[ebx+0xc]
         // 0040129a: cmp eax, edx
         // 0040129c: jnz 0x4012b2
      [-]8bc3e8b7ffffff8b430889068b430c014604eb15
         // 0040129e: mov eax, ebx
         // 004012a0: call 0x40125c
         // 004012a5: mov eax, ds:[ebx+0x8]
         // 004012a8: mov ds:[esi], eax
         // 004012aa: mov eax, ds:[ebx+0xc]
         // 004012ad: add ds:[esi+0x4], eax
         // 004012b0: jmp 0x4012c7
      [-]0346043b4308750d
         // 004012b2: add eax, ds:[esi+0x4]
         // 004012b5: cmp eax, ds:[ebx+0x8]
         // 004012b8: jnz 0x4012c7
      [-]8bc3e89bffffff8b430c014604
         // 004012ba: mov eax, ebx
         // 004012bc: call 0x40125c
         // 004012c1: mov eax, ds:[ebx+0xc]
         // 004012c4: add ds:[esi+0x4], eax
      [-]8bdf3beb75c3
         // 004012c7: mov ebx, edi
         // 004012c9: cmp ebp, ebx
         // 004012cb: jnz 0x401290
      [-]8bd68bc5e856ffffff84c07504
         // 004012cd: mov edx, esi
         // 004012cf: mov eax, ebp
         // 004012d1: call 0x40122c
         // 004012d6: test b1 al, b1 al
         // 004012d8: jnz 0x4012de
      [-]33c08906
         // 004012da: xor eax, eax
         // 004012dc: mov ds:[esi], eax
      [-]5a5d5f5e5bc3
         // 004012de: pop edx
         // 004012df: pop ebp
         // 004012e0: pop edi
         // 004012e1: pop esi
         // 004012e2: pop ebx
         // 004012e3: retn 
      [-]5356575583c4f88bd88bfb
         // 004012e4: push ebx
         // 004012e5: push esi
         // 004012e6: push edi
         // 004012e7: push ebp
         // 004012e8: add esp, 0xfffffffffffffff8
         // 004012eb: mov ebx, eax
         // 004012ed: mov edi, ebx
      [-]8b328b43083bf07270
         // 004012ef: mov esi, ds:[edx]
         // 004012f1: mov eax, ds:[ebx+0x8]
         // 004012f4: cmp esi, eax
         // 004012f6: jb 0x401368
      [-]8bce034a048be8036b0c3bcd7762
         // 004012f8: mov ecx, esi
         // 004012fa: add ecx, ds:[edx+0x4]
         // 004012fd: mov ebp, eax
         // 004012ff: add ebp, ds:[ebx+0xc]
         // 00401302: cmp ecx, ebp
         // 00401304: ja 0x401368
      [-]3bf0751b
         // 00401306: cmp esi, eax
         // 00401308: jnz 0x401325
      [-]8b42040143088b420429430c837b0c007548
         // 0040130a: mov eax, ds:[edx+0x4]
         // 0040130d: add ds:[ebx+0x8], eax
         // 00401310: mov eax, ds:[edx+0x4]
         // 00401313: sub ds:[ebx+0xc], eax
         // 00401316: cmp ds:[ebx+0xc], 0x0
         // 0040131a: jnz 0x401364
      [-]8bc3e839ffffffeb3f
         // 0040131c: mov eax, ebx
         // 0040131e: call 0x40125c
         // 00401323: jmp 0x401364
      [-]8bce8b7a0403cf8be8036b0c3bcd7505
         // 00401325: mov ecx, esi
         // 00401327: mov edi, ds:[edx+0x4]
         // 0040132a: add ecx, edi
         // 0040132c: mov ebp, eax
         // 0040132e: add ebp, ds:[ebx+0xc]
         // 00401331: cmp ecx, ebp
         // 00401333: jnz 0x40133a
      [-]297b0ceb2a
         // 00401335: sub ds:[ebx+0xc], edi
         // 00401338: jmp 0x401364
      [-]8b0a034a04890c248b7b08037b0c2bf9897c24042bf089730c8bd48bc3e8d0feffff84c07504
         // 0040133a: mov ecx, ds:[edx]
         // 0040133c: add ecx, ds:[edx+0x4]
         // 0040133f: mov ss:[esp], ecx
         // 00401342: mov edi, ds:[ebx+0x8]
         // 00401345: add edi, ds:[ebx+0xc]
         // 00401348: sub edi, ecx
         // 0040134a: mov ss:[esp+0x4], edi
         // 0040134e: sub esi, eax
         // 00401350: mov ds:[ebx+0xc], esi
         // 00401353: mov edx, esp
         // 00401355: mov eax, ebx
         // 00401357: call 0x40122c
         // 0040135c: test b1 al, b1 al
         // 0040135e: jnz 0x401364
      [-]33c0eb0c
         // 00401360: xor eax, eax
         // 00401362: jmp 0x401370
      [-]b001eb08
         // 00401364: mov b1 al, b1 0x1
         // 00401366: jmp 0x401370
      [-]8b1b3bfb7581
         // 00401368: mov ebx, ds:[ebx]
         // 0040136a: cmp edi, ebx
         // 0040136c: jnz 0x4012ef
      [-]595a5d5f5e5bc3
         // 00401370: pop ecx
         // 00401371: pop edx
         // 00401372: pop ebp
         // 00401373: pop edi
         // 00401374: pop esi
         // 00401375: pop ebx
         // 00401376: retn 
      [-]5356578bda8bf081fe????????7d07
         // 00401378: push ebx
         // 00401379: push esi
         // 0040137a: push edi
         // 0040137b: mov ebx, edx
         // 0040137d: mov esi, eax
         // 0040137f: cmp esi, 0x100000
         // 00401385: jge 0x40138e
      [-]be????????eb0c
         // 00401387: mov esi, 0x100000
         // 0040138c: jmp 0x40139a
      [-]81c6????????81e6????????
         // 0040138e: add esi, 0xffff
         // 00401394: and esi, 0xffffffffffff0000
      [-]8973046a0168????????566a00e8f8fdffff8bf8893b85ff7423
         // 0040139a: mov ds:[ebx+0x4], esi
         // 0040139d: push 0x1
         // 0040139f: push 0x2000
         // 004013a4: push esi
         // 004013a5: push 0x0
         // 004013a7: call VirtualAlloc
         // 004013ac: mov edi, eax
         // 004013ae: mov ds:[ebx], edi
         // 004013b0: test edi, edi
         // 004013b2: jz 0x4013d7
      [-]8bd3b8????????e86cfeffff84c07513
         // 004013b4: mov edx, ebx
         // 004013b6: mov eax, 0x40e5d4
         // 004013bb: call 0x40122c
         // 004013c0: test b1 al, b1 al
         // 004013c2: jnz 0x4013d7
      [-]68????????6a008b0350e8d9fdffff33c08903
         // 004013c4: push 0x8000
         // 004013c9: push 0x0
         // 004013cb: mov eax, ds:[ebx]
         // 004013cd: push eax
         // 004013ce: call VirtualFree
         // 004013d3: xor eax, eax
         // 004013d5: mov ds:[ebx], eax
      [-]5f5e5bc3
         // 004013d7: pop edi
         // 004013d8: pop esi
         // 004013d9: pop ebx
         // 004013da: retn 
      [-]535657558bd98bf28be8c74304????????6a0468????????68????????55e8a5fdffff8bf8893b85ff751f
         // 004013dc: push ebx
         // 004013dd: push esi
         // 004013de: push edi
         // 004013df: push ebp
         // 004013e0: mov ebx, ecx
         // 004013e2: mov esi, edx
         // 004013e4: mov ebp, eax
         // 004013e6: mov ds:[ebx+0x4], 0x100000
         // 004013ed: push 0x4
         // 004013ef: push 0x2000
         // 004013f4: push 0x100000
         // 004013f9: push ebp
         // 004013fa: call VirtualAlloc
         // 004013ff: mov edi, eax
         // 00401401: mov ds:[ebx], edi
         // 00401403: test edi, edi
         // 00401405: jnz 0x401426
      [-]81c6????????81e6????????8973046a0468????????5655e880fdffff8903
         // 00401407: add esi, 0xffff
         // 0040140d: and esi, 0xffffffffffff0000
         // 00401413: mov ds:[ebx+0x4], esi
         // 00401416: push 0x4
         // 00401418: push 0x2000
         // 0040141d: push esi
         // 0040141e: push ebp
         // 0040141f: call VirtualAlloc
         // 00401424: mov ds:[ebx], eax
      [-]833b007423
         // 00401426: cmp ds:[ebx], 0x0
         // 00401429: jz 0x40144e
      [-]8bd3b8????????e8f5fdffff84c07513
         // 0040142b: mov edx, ebx
         // 0040142d: mov eax, 0x40e5d4
         // 00401432: call 0x40122c
         // 00401437: test b1 al, b1 al
         // 00401439: jnz 0x40144e
      [-]68????????6a008b0350e862fdffff33c08903
         // 0040143b: push 0x8000
         // 00401440: push 0x0
         // 00401442: mov eax, ds:[ebx]
         // 00401444: push eax
         // 00401445: call VirtualFree
         // 0040144a: xor eax, eax
         // 0040144c: mov ds:[ebx], eax
      [-]5d5f5e5bc3
         // 0040144e: pop ebp
         // 0040144f: pop edi
         // 00401450: pop esi
         // 00401451: pop ebx
         // 00401452: retn 
      [-]5356575583c4ec894c2404891424c7442408????????33d28954240c8be88b042403c5894424108b1d????????eb57
         // 00401454: push ebx
         // 00401455: push esi
         // 00401456: push edi
         // 00401457: push ebp
         // 00401458: add esp, 0xffffffffffffffec
         // 0040145b: mov ss:[esp+0x4], ecx
         // 0040145f: mov ss:[esp], edx
         // 00401462: mov ss:[esp+0x8], 0xffffffffffffffff
         // 0040146a: xor edx, edx
         // 0040146c: mov ss:[esp+0xc], edx
         // 00401470: mov ebp, eax
         // 00401472: mov eax, ss:[esp]
         // 00401475: add eax, ebp
         // 00401477: mov ss:[esp+0x10], eax
         // 0040147b: mov ebx, ds:[0x40e5d4]
         // 00401481: jmp 0x4014da
      [-]8b3b8b73083bee774c
         // 00401483: mov edi, ds:[ebx]
         // 00401485: mov esi, ds:[ebx+0x8]
         // 00401488: cmp ebp, esi
         // 0040148a: ja 0x4014d8
      [-]8bc603430c3b4424107741
         // 0040148c: mov eax, esi
         // 0040148e: add eax, ds:[ebx+0xc]
         // 00401491: cmp eax, ss:[esp+0x10]
         // 00401495: ja 0x4014d8
      [-]3b7424087304
         // 00401497: cmp esi, ss:[esp+0x8]
         // 0040149b: jnb 0x4014a1
      [-]89742408
         // 0040149d: mov ss:[esp+0x8], esi
      [-]8bc603430c3b44240c760a
         // 004014a1: mov eax, esi
         // 004014a3: add eax, ds:[ebx+0xc]
         // 004014a6: cmp eax, ss:[esp+0xc]
         // 004014aa: jbe 0x4014b6
      [-]8b430803430c8944240c
         // 004014ac: mov eax, ds:[ebx+0x8]
         // 004014af: add eax, ds:[ebx+0xc]
         // 004014b2: mov ss:[esp+0xc], eax
      [-]68????????6a0056e8e9fcffff85c0750a
         // 004014b6: push 0x8000
         // 004014bb: push 0x0
         // 004014bd: push esi
         // 004014be: call VirtualFree
         // 004014c3: test eax, eax
         // 004014c5: jnz 0x4014d1
      [-]c705????????????????
         // 004014c7: mov ds:[0x40e5b0], 0x1
      [-]8bc3e884fdffff
         // 004014d1: mov eax, ebx
         // 004014d3: call 0x40125c
      [-]81fb????????75a1
         // 004014da: cmp ebx, 0x40e5d4
         // 004014e0: jnz 0x401483
      [-]8b44240433d28910837c240c007419
         // 004014e2: mov eax, ss:[esp+0x4]
         // 004014e6: xor edx, edx
         // 004014e8: mov ds:[eax], edx
         // 004014ea: cmp ss:[esp+0xc], 0x0
         // 004014ef: jz 0x40150a
      [-]8b4424048b54240889108b44240c2b4424088b542404894204
         // 004014f1: mov eax, ss:[esp+0x4]
         // 004014f5: mov edx, ss:[esp+0x8]
         // 004014f9: mov ds:[eax], edx
         // 004014fb: mov eax, ss:[esp+0xc]
         // 004014ff: sub eax, ss:[esp+0x8]
         // 00401503: mov edx, ss:[esp+0x4]
         // 00401507: mov ds:[edx+0x4], eax
      [-]83c4145d5f5e5bc3
         // 0040150a: add esp, 0x14
         // 0040150d: pop ebp
         // 0040150e: pop edi
         // 0040150f: pop esi
         // 00401510: pop ebx
         // 00401511: retn 
      [-]5356575583c4f4894c24048914248bd08bea81e5????????03142481c2????????81e2????????895424088b44240489288b4424082bc58b5424048942048b35????????eb3c
         // 00401514: push ebx
         // 00401515: push esi
         // 00401516: push edi
         // 00401517: push ebp
         // 00401518: add esp, 0xfffffffffffffff4
         // 0040151b: mov ss:[esp+0x4], ecx
         // 0040151f: mov ss:[esp], edx
         // 00401522: mov edx, eax
         // 00401524: mov ebp, edx
         // 00401526: and ebp, 0xfffffffffffff000
         // 0040152c: add edx, ss:[esp]
         // 0040152f: add edx, 0xfff
         // 00401535: and edx, 0xfffffffffffff000
         // 0040153b: mov ss:[esp+0x8], edx
         // 0040153f: mov eax, ss:[esp+0x4]
         // 00401543: mov ds:[eax], ebp
         // 00401545: mov eax, ss:[esp+0x8]
         // 00401549: sub eax, ebp
         // 0040154b: mov edx, ss:[esp+0x4]
         // 0040154f: mov ds:[edx+0x4], eax
         // 00401552: mov esi, ds:[0x40e5d4]
         // 00401558: jmp 0x401596
      [-]8b5e088b7e0c03fb3beb7602
         // 0040155a: mov ebx, ds:[esi+0x8]
         // 0040155d: mov edi, ds:[esi+0xc]
         // 00401560: add edi, ebx
         // 00401562: cmp ebp, ebx
         // 00401564: jbe 0x401568
      [-]3b7c24087604
         // 00401568: cmp edi, ss:[esp+0x8]
         // 0040156c: jbe 0x401572
      [-]8b7c2408
         // 0040156e: mov edi, ss:[esp+0x8]
      [-]3bfb761e
         // 00401572: cmp edi, ebx
         // 00401574: jbe 0x401594
      [-]6a0468????????2bfb5753e81efcffff85c0750a
         // 00401576: push 0x4
         // 00401578: push 0x1000
         // 0040157d: sub edi, ebx
         // 0040157f: push edi
         // 00401580: push ebx
         // 00401581: call VirtualAlloc
         // 00401586: test eax, eax
         // 00401588: jnz 0x401594
      [-]8b44240433d28910eb0a
         // 0040158a: mov eax, ss:[esp+0x4]
         // 0040158e: xor edx, edx
         // 00401590: mov ds:[eax], edx
         // 00401592: jmp 0x40159e
      [-]81fe????????75bc
         // 00401596: cmp esi, 0x40e5d4
         // 0040159c: jnz 0x40155a
      [-]83c40c5d5f5e5bc3
         // 0040159e: add esp, 0xc
         // 004015a1: pop ebp
         // 004015a2: pop edi
         // 004015a3: pop esi
         // 004015a4: pop ebx
         // 004015a5: retn 
      [-]53565755518bd88bf381c6????????81e6????????8934248beb03ea81e5????????8b042489018bc52b04248941048b35????????eb38
         // 004015a8: push ebx
         // 004015a9: push esi
         // 004015aa: push edi
         // 004015ab: push ebp
         // 004015ac: push ecx
         // 004015ad: mov ebx, eax
         // 004015af: mov esi, ebx
         // 004015b1: add esi, 0xfff
         // 004015b7: and esi, 0xfffffffffffff000
         // 004015bd: mov ss:[esp], esi
         // 004015c0: mov ebp, ebx
         // 004015c2: add ebp, edx
         // 004015c4: and ebp, 0xfffffffffffff000
         // 004015ca: mov eax, ss:[esp]
         // 004015cd: mov ds:[ecx], eax
         // 004015cf: mov eax, ebp
         // 004015d1: sub eax, ss:[esp]
         // 004015d4: mov ds:[ecx+0x4], eax
         // 004015d7: mov esi, ds:[0x40e5d4]
         // 004015dd: jmp 0x401617
      [-]8b5e088b7e0c03fb3b1c247303
         // 004015df: mov ebx, ds:[esi+0x8]
         // 004015e2: mov edi, ds:[esi+0xc]
         // 004015e5: add edi, ebx
         // 004015e7: cmp ebx, ss:[esp]
         // 004015ea: jnb 0x4015ef
      [-]3bef7302
         // 004015ef: cmp ebp, edi
         // 004015f1: jnb 0x4015f5
      [-]3bfb761c
         // 004015f5: cmp edi, ebx
         // 004015f7: jbe 0x401615
      [-]68????????2bfb5753e8a5fbffff85c0750a
         // 004015f9: push 0x4000
         // 004015fe: sub edi, ebx
         // 00401600: push edi
         // 00401601: push ebx
         // 00401602: call VirtualFree
         // 00401607: test eax, eax
         // 00401609: jnz 0x401615
      [-]c705????????????????
         // 0040160b: mov ds:[0x40e5b0], 0x2
      [-]81fe????????75c0
         // 00401617: cmp esi, 0x40e5d4
         // 0040161d: jnz 0x4015df
      [-]5a5d5f5e5bc3
         // 0040161f: pop edx
         // 00401620: pop ebp
         // 00401621: pop edi
         // 00401622: pop esi
         // 00401623: pop ebx
         // 00401624: retn 
      [-]5356575583c4f88bf28bf8bd????????81c7????????81e7????????
         // 00401628: push ebx
         // 00401629: push esi
         // 0040162a: push edi
         // 0040162b: push ebp
         // 0040162c: add esp, 0xfffffffffffffff8
         // 0040162f: mov esi, edx
         // 00401631: mov edi, eax
         // 00401633: mov ebp, 0x40e5e4
         // 00401638: add edi, 0x3fff
         // 0040163e: and edi, 0xffffffffffffc000
      [-]8b5d00eb33
         // 00401644: mov ebx, ss:[ebp+0x0]
         // 00401647: jmp 0x40167c
      [-]3b7b0c7f2c
         // 00401649: cmp edi, ds:[ebx+0xc]
         // 0040164c: jg 0x40167a
      [-]8bce8bd78b4308e8bafeffff833e007450
         // 0040164e: mov ecx, esi
         // 00401650: mov edx, edi
         // 00401652: mov eax, ds:[ebx+0x8]
         // 00401655: call 0x401514
         // 0040165a: cmp ds:[esi], 0x0
         // 0040165d: jz 0x4016af
      [-]8b46040143088b460429430c837b0c00753e
         // 0040165f: mov eax, ds:[esi+0x4]
         // 00401662: add ds:[ebx+0x8], eax
         // 00401665: mov eax, ds:[esi+0x4]
         // 00401668: sub ds:[ebx+0xc], eax
         // 0040166b: cmp ds:[ebx+0xc], 0x0
         // 0040166f: jnz 0x4016af
      [-]8bc3e8e4fbffffeb35
         // 00401671: mov eax, ebx
         // 00401673: call 0x40125c
         // 00401678: jmp 0x4016af
      [-]3bdd75c9
         // 0040167c: cmp ebx, ebp
         // 0040167e: jnz 0x401649
      [-]8bd68bc7e8effcffff833e007421
         // 00401680: mov edx, esi
         // 00401682: mov eax, edi
         // 00401684: call 0x401378
         // 00401689: cmp ds:[esi], 0x0
         // 0040168c: jz 0x4016af
      [-]8bcc8bd68bc5e8dbfbffff833c240075a5
         // 0040168e: mov ecx, esp
         // 00401690: mov edx, esi
         // 00401692: mov eax, ebp
         // 00401694: call 0x401274
         // 00401699: cmp ss:[esp], 0x0
         // 0040169d: jnz 0x401644
      [-]8bcc8b56048b06e8a9fdffff33c08906
         // 0040169f: mov ecx, esp
         // 004016a1: mov edx, ds:[esi+0x4]
         // 004016a4: mov eax, ds:[esi]
         // 004016a6: call 0x401454
         // 004016ab: xor eax, eax
         // 004016ad: mov ds:[esi], eax
      [-]595a5d5f5e5bc3
         // 004016af: pop ecx
         // 004016b0: pop edx
         // 004016b1: pop ebp
         // 004016b2: pop edi
         // 004016b3: pop esi
         // 004016b4: pop ebx
         // 004016b5: retn 
      [-]5356575583c4ec890c248bfa8bf0bd????????81c7????????81e7????????
         // 004016b8: push ebx
         // 004016b9: push esi
         // 004016ba: push edi
         // 004016bb: push ebp
         // 004016bc: add esp, 0xffffffffffffffec
         // 004016bf: mov ss:[esp], ecx
         // 004016c2: mov edi, edx
         // 004016c4: mov esi, eax
         // 004016c6: mov ebp, 0x40e5e4
         // 004016cb: add edi, 0x3fff
         // 004016d1: and edi, 0xffffffffffffc000
      [-]8b5d00eb02
         // 004016d7: mov ebx, ss:[ebp+0x0]
         // 004016da: jmp 0x4016de
      [-]3bdd7405
         // 004016de: cmp ebx, ebp
         // 004016e0: jz 0x4016e7
      [-]3b730875f5
         // 004016e2: cmp esi, ds:[ebx+0x8]
         // 004016e5: jnz 0x4016dc
      [-]3b73087557
         // 004016e7: cmp esi, ds:[ebx+0x8]
         // 004016ea: jnz 0x401743
      [-]3b7b0c0f8e96000000
         // 004016ec: cmp edi, ds:[ebx+0xc]
         // 004016ef: jle 0x40178b
      [-]8d4c24048bd72b530c8b430803430ce8d3fcffff837c2404007433
         // 004016f5: lea ecx, ss:[esp+0x4]
         // 004016f9: mov edx, edi
         // 004016fb: sub edx, ds:[ebx+0xc]
         // 004016fe: mov eax, ds:[ebx+0x8]
         // 00401701: add eax, ds:[ebx+0xc]
         // 00401704: call 0x4013dc
         // 00401709: cmp ss:[esp+0x4], 0x0
         // 0040170e: jz 0x401743
      [-]8d4c240c8d5424048bc5e855fbffff837c240c0075b1
         // 00401710: lea ecx, ss:[esp+0xc]
         // 00401714: lea edx, ss:[esp+0x4]
         // 00401718: mov eax, ebp
         // 0040171a: call 0x401274
         // 0040171f: cmp ss:[esp+0xc], 0x0
         // 00401724: jnz 0x4016d7
      [-]8d4c240c8b5424088b442404e81dfdffff8b042433d28910e990000000
         // 00401726: lea ecx, ss:[esp+0xc]
         // 0040172a: mov edx, ss:[esp+0x8]
         // 0040172e: mov eax, ss:[esp+0x4]
         // 00401732: call 0x401454
         // 00401737: mov eax, ss:[esp]
         // 0040173a: xor edx, edx
         // 0040173c: mov ds:[eax], edx
         // 0040173e: jmp 0x4017d3
      [-]8d4c24048bd78bc6e88cfcffff837c2404007434
         // 00401743: lea ecx, ss:[esp+0x4]
         // 00401747: mov edx, edi
         // 00401749: mov eax, esi
         // 0040174b: call 0x4013dc
         // 00401750: cmp ss:[esp+0x4], 0x0
         // 00401755: jz 0x40178b
      [-]8d4c240c8d5424048bc5e80efbffff837c240c000f8566ffffff
         // 00401757: lea ecx, ss:[esp+0xc]
         // 0040175b: lea edx, ss:[esp+0x4]
         // 0040175f: mov eax, ebp
         // 00401761: call 0x401274
         // 00401766: cmp ss:[esp+0xc], 0x0
         // 0040176b: jnz 0x4016d7
      [-]8d4c240c8b5424088b442404e8d2fcffff8b042433d28910eb48
         // 00401771: lea ecx, ss:[esp+0xc]
         // 00401775: mov edx, ss:[esp+0x8]
         // 00401779: mov eax, ss:[esp+0x4]
         // 0040177d: call 0x401454
         // 00401782: mov eax, ss:[esp]
         // 00401785: xor edx, edx
         // 00401787: mov ds:[eax], edx
         // 00401789: jmp 0x4017d3
      [-]8b6b083bf5753a
         // 0040178b: mov ebp, ds:[ebx+0x8]
         // 0040178e: cmp esi, ebp
         // 00401790: jnz 0x4017cc
      [-]3b7b0c7f35
         // 00401792: cmp edi, ds:[ebx+0xc]
         // 00401795: jg 0x4017cc
      [-]8b0c248bd78bc5e871fdffff8b04248338007428
         // 00401797: mov ecx, ss:[esp]
         // 0040179a: mov edx, edi
         // 0040179c: mov eax, ebp
         // 0040179e: call 0x401514
         // 004017a3: mov eax, ss:[esp]
         // 004017a6: cmp ds:[eax], 0x0
         // 004017a9: jz 0x4017d3
      [-]8b04248b40040143088b04248b400429430c837b0c007510
         // 004017ab: mov eax, ss:[esp]
         // 004017ae: mov eax, ds:[eax+0x4]
         // 004017b1: add ds:[ebx+0x8], eax
         // 004017b4: mov eax, ss:[esp]
         // 004017b7: mov eax, ds:[eax+0x4]
         // 004017ba: sub ds:[ebx+0xc], eax
         // 004017bd: cmp ds:[ebx+0xc], 0x0
         // 004017c1: jnz 0x4017d3
      [-]8bc3e892faffffeb07
         // 004017c3: mov eax, ebx
         // 004017c5: call 0x40125c
         // 004017ca: jmp 0x4017d3
      [-]8b042433d28910
         // 004017cc: mov eax, ss:[esp]
         // 004017cf: xor edx, edx
         // 004017d1: mov ds:[eax], edx
      [-]83c4145d5f5e5bc3
         // 004017d3: add esp, 0x14
         // 004017d6: pop ebp
         // 004017d7: pop edi
         // 004017d8: pop esi
         // 004017d9: pop ebx
         // 004017da: retn 
      [-]53565783c4ec8bf98914248d98????????81e3????????8b342403f081e6????????3bde735b
         // 004017dc: push ebx
         // 004017dd: push esi
         // 004017de: push edi
         // 004017df: add esp, 0xffffffffffffffec
         // 004017e2: mov edi, ecx
         // 004017e4: mov ss:[esp], edx
         // 004017e7: lea ebx, ds:[eax+0x3fff]
         // 004017ed: and ebx, 0xffffffffffffc000
         // 004017f3: mov esi, ss:[esp]
         // 004017f6: add esi, eax
         // 004017f8: and esi, 0xffffffffffffc000
         // 004017fe: cmp ebx, esi
         // 00401800: jnb 0x40185d
      [-]8bcf8bd62bd38bc3e899fdffff8d4c24048bd7b8????????e855faffff8b5c240485db741f
         // 00401802: mov ecx, edi
         // 00401804: mov edx, esi
         // 00401806: sub edx, ebx
         // 00401808: mov eax, ebx
         // 0040180a: call 0x4015a8
         // 0040180f: lea ecx, ss:[esp+0x4]
         // 00401813: mov edx, edi
         // 00401815: mov eax, 0x40e5e4
         // 0040181a: call 0x401274
         // 0040181f: mov ebx, ss:[esp+0x4]
         // 00401823: test ebx, ebx
         // 00401825: jz 0x401846
      [-]8d4c240c8b5424088bc3e81efcffff8b44240c894424048b44241089442408
         // 00401827: lea ecx, ss:[esp+0xc]
         // 0040182b: mov edx, ss:[esp+0x8]
         // 0040182f: mov eax, ebx
         // 00401831: call 0x401454
         // 00401836: mov eax, ss:[esp+0xc]
         // 0040183a: mov ss:[esp+0x4], eax
         // 0040183e: mov eax, ss:[esp+0x10]
         // 00401842: mov ss:[esp+0x8], eax
      [-]837c2404007414
         // 00401846: cmp ss:[esp+0x4], 0x0
         // 0040184b: jz 0x401861
      [-]8d542404b8????????e889faffffeb04
         // 0040184d: lea edx, ss:[esp+0x4]
         // 00401851: mov eax, 0x40e5e4
         // 00401856: call 0x4012e4
         // 0040185b: jmp 0x401861
      [-]33c08907
         // 0040185d: xor eax, eax
         // 0040185f: mov ds:[edi], eax
      [-]83c4145f5e5bc3
         // 00401861: add esp, 0x14
         // 00401864: pop edi
         // 00401865: pop esi
         // 00401866: pop ebx
         // 00401867: retn 
      [-]558bec33d25568????????64ff3264892268b4e54000e831f9ffff803d35e0400000740a
         // 00401868: push ebp
         // 00401869: mov ebp, esp
         // 0040186b: xor edx, edx
         // 0040186d: push ebp
         // 0040186e: push 0x40191e
         // 00401873: push fs:[edx]
         // 00401876: mov fs:[edx], esp
         // 00401879: push CriticalSection.DebugInfo
         // 0040187e: call InitializeCriticalSection
         // 00401883: cmp b1 ds:[0x40e035], b1 0x0
         // 0040188a: jz 0x401896
      [-]68b4e54000e826f9ffff
         // 0040188c: push CriticalSection.DebugInfo
         // 00401891: call EnterCriticalSection
      [-]b8????????e884f9ffffb8????????e87af9ffffb8????????e870f9ffff68????????6a00e8d4f8ffffa3????????833d????????00742f
         // 00401896: mov eax, 0x40e5d4
         // 0040189b: call 0x401224
         // 004018a0: mov eax, 0x40e5e4
         // 004018a5: call 0x401224
         // 004018aa: mov eax, 0x40e610
         // 004018af: call 0x401224
         // 004018b4: push 0xff8
         // 004018b9: push 0x0
         // 004018bb: call LocalAlloc
         // 004018c0: mov ds:[0x40e60c], eax
         // 004018c5: cmp ds:[0x40e60c], 0x0
         // 004018cc: jz 0x4018fd
      [-]b8????????
         // 004018ce: mov eax, 0x3
      [-]8b15????????33c9894c82f4403d????????75ec
         // 004018d3: mov edx, ds:[0x40e60c]
         // 004018d9: xor ecx, ecx
         // 004018db: mov ds:[edx+eax*0x4], ecx
         // 004018df: inc eax
         // 004018e0: cmp eax, 0x401
         // 004018e5: jnz 0x4018d3
      [-]b8????????8940048900a3????????c605ace5400001
         // 004018e7: mov eax, 0x40e5f4
         // 004018ec: mov ds:[eax+0x4], eax
         // 004018ef: mov ds:[eax], eax
         // 004018f1: mov ds:[0x40e600], eax
         // 004018f6: mov b1 ds:[0x40e5ac], b1 0x1
      [-]33c05a595964891068????????803d35e0400000740a
         // 004018fd: xor eax, eax
         // 004018ff: pop edx
         // 00401900: pop ecx
         // 00401901: pop ecx
         // 00401902: mov fs:[eax], edx
         // 00401905: push 0x401925
         // 0040190a: cmp b1 ds:[0x40e035], b1 0x0
         // 00401911: jz 0x40191d
      [-]68b4e54000e8a7f8ffff
         // 00401913: push CriticalSection.DebugInfo
         // 00401918: call LeaveCriticalSection
      [-]0fb605ace540005dc3
         // 00401925: movzx eax, b1 ds:[0x40e5ac]
         // 0040192c: pop ebp
         // 0040192d: retn 
      [-]558bec53803dace54000000f84cd000000
         // 00401930: push ebp
         // 00401931: mov ebp, esp
         // 00401933: push ebx
         // 00401934: cmp b1 ds:[0x40e5ac], b1 0x0
         // 0040193b: jz 0x401a0e
      [-]33c05568????????64ff30648920803d35e0400000740a
         // 00401941: xor eax, eax
         // 00401943: push ebp
         // 00401944: push 0x401a07
         // 00401949: push fs:[eax]
         // 0040194c: mov fs:[eax], esp
         // 0040194f: cmp b1 ds:[0x40e035], b1 0x0
         // 00401956: jz 0x401962
      [-]68b4e54000e85af8ffff
         // 00401958: push CriticalSection.DebugInfo
         // 0040195d: call EnterCriticalSection
      [-]c605ace5400000a1????????50e828f8ffff33c0a3????????8b1d????????eb12
         // 00401962: mov b1 ds:[0x40e5ac], b1 0x0
         // 00401969: mov eax, ds:[0x40e60c]
         // 0040196e: push eax
         // 0040196f: call LocalFree
         // 00401974: xor eax, eax
         // 00401976: mov ds:[0x40e60c], eax
         // 0040197b: mov ebx, ds:[0x40e5d4]
         // 00401981: jmp 0x401995
      [-]68????????6a008b430850e819f8ffff8b1b
         // 00401983: push 0x8000
         // 00401988: push 0x0
         // 0040198a: mov eax, ds:[ebx+0x8]
         // 0040198d: push eax
         // 0040198e: call VirtualFree
         // 00401993: mov ebx, ds:[ebx]
      [-]81fb????????75e6
         // 00401995: cmp ebx, 0x40e5d4
         // 0040199b: jnz 0x401983
      [-]b8????????e87df8ffffb8????????e873f8ffffb8????????e869f8ffff8b1d????????85db7417
         // 0040199d: mov eax, 0x40e5d4
         // 004019a2: call 0x401224
         // 004019a7: mov eax, 0x40e5e4
         // 004019ac: call 0x401224
         // 004019b1: mov eax, 0x40e610
         // 004019b6: call 0x401224
         // 004019bb: mov ebx, ds:[0x40e5cc]
         // 004019c1: test ebx, ebx
         // 004019c3: jz 0x4019dc
      [-]8b03a3????????53e8caf7ffff8b1d????????85db75e9
         // 004019c5: mov eax, ds:[ebx]
         // 004019c7: mov ds:[0x40e5cc], eax
         // 004019cc: push ebx
         // 004019cd: call LocalFree
         // 004019d2: mov ebx, ds:[0x40e5cc]
         // 004019d8: test ebx, ebx
         // 004019da: jnz 0x4019c5
      [-]33c05a595964891068????????803d35e0400000740a
         // 004019dc: xor eax, eax
         // 004019de: pop edx
         // 004019df: pop ecx
         // 004019e0: pop ecx
         // 004019e1: mov fs:[eax], edx
         // 004019e4: push 0x401a0e
         // 004019e9: cmp b1 ds:[0x40e035], b1 0x0
         // 004019f0: jz 0x4019fc
      [-]68b4e54000e8c8f7ffff
         // 004019f2: push CriticalSection.DebugInfo
         // 004019f7: call LeaveCriticalSection
      [-]68b4e54000e8c6f7ffffc3
         // 004019fc: push CriticalSection.DebugInfo
         // 00401a01: call DeleteCriticalSection
         // 00401a06: retn 
      [-]533b05????????7509
         // 00401a14: push ebx
         // 00401a15: cmp eax, ds:[0x40e600]
         // 00401a1b: jnz 0x401a26
      [-]8b50048915????????
         // 00401a1d: mov edx, ds:[eax+0x4]
         // 00401a20: mov ds:[0x40e600], edx
      [-]8b50048b480881f9????????7f38
         // 00401a26: mov edx, ds:[eax+0x4]
         // 00401a29: mov ecx, ds:[eax+0x8]
         // 00401a2c: cmp ecx, 0x1000
         // 00401a32: jg 0x401a6c
      [-]3bc27517
         // 00401a34: cmp eax, edx
         // 00401a36: jnz 0x401a4f
      [-]85c97903
         // 00401a38: test ecx, ecx
         // 00401a3a: jns 0x401a3f
      [-]c1f902a1????????33d2895488f4eb24
         // 00401a3f: sar ecx, b1 0x2
         // 00401a42: mov eax, ds:[0x40e60c]
         // 00401a47: xor edx, edx
         // 00401a49: mov ds:[eax+ecx*0x4], edx
         // 00401a4d: jmp 0x401a73
      [-]85c97903
         // 00401a4f: test ecx, ecx
         // 00401a51: jns 0x401a56
      [-]c1f9028b1d????????89548bf48b0089028950045bc3
         // 00401a56: sar ecx, b1 0x2
         // 00401a59: mov ebx, ds:[0x40e60c]
         // 00401a5f: mov ds:[ebx+ecx*0x4], edx
         // 00401a63: mov eax, ds:[eax]
         // 00401a65: mov ds:[edx], eax
         // 00401a67: mov ds:[eax+0x4], edx
         // 00401a6a: pop ebx
         // 00401a6b: retn 
      [-]8b008902895004
         // 00401a6c: mov eax, ds:[eax]
         // 00401a6e: mov ds:[edx], eax
         // 00401a70: mov ds:[eax+0x4], edx
      [-]8b15????????eb10
         // 00401a78: mov edx, ds:[0x40e610]
         // 00401a7e: jmp 0x401a90
      [-]8b4a083bc17207
         // 00401a80: mov ecx, ds:[edx+0x8]
         // 00401a83: cmp eax, ecx
         // 00401a85: jb 0x401a8e
      [-]034a0c3bc17216
         // 00401a87: add ecx, ds:[edx+0xc]
         // 00401a8a: cmp eax, ecx
         // 00401a8c: jb 0x401aa4
      [-]81fa????????75e8
         // 00401a90: cmp edx, 0x40e610
         // 00401a96: jnz 0x401a80
      [-]c705????????????????33d2
         // 00401a98: mov ds:[0x40e5b0], 0x3
         // 00401aa2: xor edx, edx
      [-]538bca83e9048d1c0183fa107c0f
         // 00401aa8: push ebx
         // 00401aa9: mov ecx, edx
         // 00401aab: sub ecx, 0x4
         // 00401aae: lea ebx, ds:[ecx+eax]
         // 00401ab1: cmp edx, 0x10
         // 00401ab4: jl 0x401ac5
      [-]c703????????8bd1e8b90100005bc3
         // 00401ab6: mov ds:[ebx], 0xffffffff80000007
         // 00401abc: mov edx, ecx
         // 00401abe: call 0x401c7c
         // 00401ac3: pop ebx
         // 00401ac4: retn 
      [-]83fa047c0c
         // 00401ac5: cmp edx, 0x4
         // 00401ac8: jl 0x401ad6
      [-]8bca81c9????????8908890b
         // 00401aca: mov ecx, edx
         // 00401acc: or ecx, 0xffffffff80000002
         // 00401ad2: mov ds:[eax], ecx
         // 00401ad4: mov ds:[ebx], ecx
      [-]ff05????????8bd083ea048b1281e2????????83ea040115????????e8f3050000c3
         // 00401ad8: inc ds:[0x40e59c]
         // 00401ade: mov edx, eax
         // 00401ae0: sub edx, 0x4
         // 00401ae3: mov edx, ds:[edx]
         // 00401ae5: and edx, 0x7ffffffc
         // 00401aeb: sub edx, 0x4
         // 00401aee: add ds:[0x40e5a0], edx
         // 00401af4: call 0x4020ec
         // 00401af9: retn 
      [-]83fa0c7c0e
         // 00401afc: cmp edx, 0xc
         // 00401aff: jl 0x401b0f
      [-]83ca02891083c004e8caffffffc3
         // 00401b01: or edx, 0x2
         // 00401b04: mov ds:[eax], edx
         // 00401b06: add eax, 0x4
         // 00401b09: call 0x401ad8
         // 00401b0e: retn 
      [-]83fa047c0a
         // 00401b0f: cmp edx, 0x4
         // 00401b12: jl 0x401b1e
      [-]8bca81c9????????8908
         // 00401b14: mov ecx, edx
         // 00401b16: or ecx, 0xffffffff80000002
         // 00401b1c: mov ds:[eax], ecx
      [-]03c28320fec3
         // 00401b1e: add eax, edx
         // 00401b20: and ds:[eax], 0xfffffffffffffffe
         // 00401b23: retn 
      [-]53568bd083ea048b128bca81e1????????81f9????????740a
         // 00401b24: push ebx
         // 00401b25: push esi
         // 00401b26: mov edx, eax
         // 00401b28: sub edx, 0x4
         // 00401b2b: mov edx, ds:[edx]
         // 00401b2d: mov ecx, edx
         // 00401b2f: and ecx, 0xffffffff80000002
         // 00401b35: cmp ecx, 0xffffffff80000002
         // 00401b3b: jz 0x401b47
      [-]c705????????????????
         // 00401b3d: mov ds:[0x40e5b0], 0x4
      [-]8bda81e3????????2bc38bc83311f7c2????????740a
         // 00401b47: mov ebx, edx
         // 00401b49: and ebx, 0x7ffffffc
         // 00401b4f: sub eax, ebx
         // 00401b51: mov ecx, eax
         // 00401b53: xor edx, ds:[ecx]
         // 00401b55: test edx, 0xfffffffffffffffe
         // 00401b5b: jz 0x401b67
      [-]c705????????????????
         // 00401b5d: mov ds:[0x40e5b0], 0x5
      [-]f601017420
         // 00401b67: test b1 ds:[ecx], b1 0x1
         // 00401b6a: jz 0x401b8c
      [-]8bd083ea0c8b72082bc63b7008740a
         // 00401b6c: mov edx, eax
         // 00401b6e: sub edx, 0xc
         // 00401b71: mov esi, ds:[edx+0x8]
         // 00401b74: sub eax, esi
         // 00401b76: cmp esi, ds:[eax+0x8]
         // 00401b79: jz 0x401b85
      [-]c705????????????????
         // 00401b7b: mov ds:[0x40e5b0], 0x6
      [-]e88afeffff03de
         // 00401b85: call 0x401a14
         // 00401b8a: add ebx, esi
      [-]8bc35e5bc3
         // 00401b8c: mov eax, ebx
         // 00401b8e: pop esi
         // 00401b8f: pop ebx
         // 00401b90: retn 
      [-]5356578bd833ff8b03a9????????740b
         // 00401b94: push ebx
         // 00401b95: push esi
         // 00401b96: push edi
         // 00401b97: mov ebx, eax
         // 00401b99: xor edi, edi
         // 00401b9b: mov eax, ds:[ebx]
         // 00401b9d: test eax, 0xffffffff80000000
         // 00401ba2: jz 0x401baf
      [-]25????????03f803d88b03
         // 00401ba4: and eax, 0x7ffffffc
         // 00401ba9: add edi, eax
         // 00401bab: add ebx, eax
         // 00401bad: mov eax, ds:[ebx]
      [-]a8027513
         // 00401baf: test b1 al, b1 0x2
         // 00401bb1: jnz 0x401bc6
      [-]8bf38bc6e858feffff8b460803f803d88323fe
         // 00401bb3: mov esi, ebx
         // 00401bb5: mov eax, esi
         // 00401bb7: call 0x401a14
         // 00401bbc: mov eax, ds:[esi+0x8]
         // 00401bbf: add edi, eax
         // 00401bc1: add ebx, eax
         // 00401bc3: and ds:[ebx], 0xfffffffffffffffe
      [-]8bc75f5e5bc3
         // 00401bc6: mov eax, edi
         // 00401bc8: pop edi
         // 00401bc9: pop esi
         // 00401bca: pop ebx
         // 00401bcb: retn 
      [-]5356575583c4f48bfa8bf0c60424008bc6e896feffff8bd885db0f8482000000
         // 00401bcc: push ebx
         // 00401bcd: push esi
         // 00401bce: push edi
         // 00401bcf: push ebp
         // 00401bd0: add esp, 0xfffffffffffffff4
         // 00401bd3: mov edi, edx
         // 00401bd5: mov esi, eax
         // 00401bd7: mov b1 ss:[esp], b1 0x0
         // 00401bdb: mov eax, esi
         // 00401bdd: call 0x401a78
         // 00401be2: mov ebx, eax
         // 00401be4: test ebx, ebx
         // 00401be6: jz 0x401c6e
      [-]8b6b088bc503430c8bd08d0c372bd183fa0c7f04
         // 00401bec: mov ebp, ds:[ebx+0x8]
         // 00401bef: mov eax, ebp
         // 00401bf1: add eax, ds:[ebx+0xc]
         // 00401bf4: mov edx, eax
         // 00401bf6: lea ecx, ds:[edi+esi]
         // 00401bf9: sub edx, ecx
         // 00401bfb: cmp edx, 0xc
         // 00401bfe: jg 0x401c04
      [-]8bf82bfe
         // 00401c00: mov edi, eax
         // 00401c02: sub edi, esi
      [-]8bc62bc583f80c7d14
         // 00401c04: mov eax, esi
         // 00401c06: sub eax, ebp
         // 00401c08: cmp eax, 0xc
         // 00401c0b: jge 0x401c21
      [-]8d4c24018bd62b530803d78bc5e8bdfbffffeb11
         // 00401c0d: lea ecx, ss:[esp+0x1]
         // 00401c11: mov edx, esi
         // 00401c13: sub edx, ds:[ebx+0x8]
         // 00401c16: add edx, edi
         // 00401c18: mov eax, ebp
         // 00401c1a: call 0x4017dc
         // 00401c1f: jmp 0x401c32
      [-]8d4c24018bd783ea048d4604e8aafbffff
         // 00401c21: lea ecx, ss:[esp+0x1]
         // 00401c25: mov edx, edi
         // 00401c27: sub edx, 0x4
         // 00401c2a: lea eax, ds:[esi+0x4]
         // 00401c2d: call 0x4017dc
      [-]8b6c240185ed7434
         // 00401c32: mov ebp, ss:[esp+0x1]
         // 00401c36: test ebp, ebp
         // 00401c38: jz 0x401c6e
      [-]8bd52bd68bc6e863feffff8bc5034424058b530803530c3bc2730a
         // 00401c3a: mov edx, ebp
         // 00401c3c: sub edx, esi
         // 00401c3e: mov eax, esi
         // 00401c40: call 0x401aa8
         // 00401c45: mov eax, ebp
         // 00401c47: add eax, ss:[esp+0x5]
         // 00401c4b: mov edx, ds:[ebx+0x8]
         // 00401c4e: add edx, ds:[ebx+0xc]
         // 00401c51: cmp eax, edx
         // 00401c53: jnb 0x401c5f
      [-]8d14372bd0e89dfeffff
         // 00401c55: lea edx, ds:[edi+esi]
         // 00401c58: sub edx, eax
         // 00401c5a: call 0x401afc
      [-]8d5424018bc3e87af6ffffc6042401
         // 00401c5f: lea edx, ss:[esp+0x1]
         // 00401c63: mov eax, ebx
         // 00401c65: call 0x4012e4
         // 00401c6a: mov b1 ss:[esp], b1 0x1
      [-]0fb6042483c40c5d5f5e5bc3
         // 00401c6e: movzx eax, b1 ss:[esp]
         // 00401c72: add esp, 0xc
         // 00401c75: pop ebp
         // 00401c76: pop edi
         // 00401c77: pop esi
         // 00401c78: pop ebx
         // 00401c79: retn 
      [-]5356578bf28bf88bdf8973088bc303c683e80c89700881fe????????7f37
         // 00401c7c: push ebx
         // 00401c7d: push esi
         // 00401c7e: push edi
         // 00401c7f: mov esi, edx
         // 00401c81: mov edi, eax
         // 00401c83: mov ebx, edi
         // 00401c85: mov ds:[ebx+0x8], esi
         // 00401c88: mov eax, ebx
         // 00401c8a: add eax, esi
         // 00401c8c: sub eax, 0xc
         // 00401c8f: mov ds:[eax+0x8], esi
         // 00401c92: cmp esi, 0x1000
         // 00401c98: jg 0x401cd1
      [-]8bd685d27903
         // 00401c9a: mov edx, esi
         // 00401c9c: test edx, edx
         // 00401c9e: jns 0x401ca3
      [-]c1fa02a1????????8b4490f485c07510
         // 00401ca3: sar edx, b1 0x2
         // 00401ca6: mov eax, ds:[0x40e60c]
         // 00401cab: mov eax, ds:[eax+edx*0x4]
         // 00401caf: test eax, eax
         // 00401cb1: jnz 0x401cc3
      [-]a1????????895c90f4895b04891beb3a
         // 00401cb3: mov eax, ds:[0x40e60c]
         // 00401cb8: mov ds:[eax+edx*0x4], ebx
         // 00401cbc: mov ds:[ebx+0x4], ebx
         // 00401cbf: mov ds:[ebx], ebx
         // 00401cc1: jmp 0x401cfd
      [-]8b1089430489138918895a04eb2c
         // 00401cc3: mov edx, ds:[eax]
         // 00401cc5: mov ds:[ebx+0x4], eax
         // 00401cc8: mov ds:[ebx], edx
         // 00401cca: mov ds:[eax], ebx
         // 00401ccc: mov ds:[edx+0x4], ebx
         // 00401ccf: jmp 0x401cfd
      [-]81fe????????7c0d
         // 00401cd1: cmp esi, 0x3c00
         // 00401cd7: jl 0x401ce6
      [-]8bd68bc7e8eafeffff84c07517
         // 00401cd9: mov edx, esi
         // 00401cdb: mov eax, edi
         // 00401cdd: call 0x401bcc
         // 00401ce2: test b1 al, b1 al
         // 00401ce4: jnz 0x401cfd
      [-]a1????????891d????????8b1089430489138918895a04
         // 00401ce6: mov eax, ds:[0x40e600]
         // 00401ceb: mov ds:[0x40e600], ebx
         // 00401cf1: mov edx, ds:[eax]
         // 00401cf3: mov ds:[ebx+0x4], eax
         // 00401cf6: mov ds:[ebx], edx
         // 00401cf8: mov ds:[eax], ebx
         // 00401cfa: mov ds:[edx+0x4], ebx
      [-]5f5e5bc3
         // 00401cfd: pop edi
         // 00401cfe: pop esi
         // 00401cff: pop ebx
         // 00401d00: retn 
      [-]833d????????007e40
         // 00401d04: cmp ds:[0x40e604], 0x0
         // 00401d0b: jle 0x401d4d
      [-]833d????????0c7d0c
         // 00401d0d: cmp ds:[0x40e604], 0xc
         // 00401d14: jge 0x401d22
      [-]c705????????????????eb2b
         // 00401d16: mov ds:[0x40e5b0], 0x7
         // 00401d20: jmp 0x401d4d
      [-]a1????????83c8028b15????????8902a1????????83c004e899fdffff33c0a3????????33c0a3????????
         // 00401d22: mov eax, ds:[0x40e604]
         // 00401d27: or eax, 0x2
         // 00401d2a: mov edx, ds:[0x40e608]
         // 00401d30: mov ds:[edx], eax
         // 00401d32: mov eax, ds:[0x40e608]
         // 00401d37: add eax, 0x4
         // 00401d3a: call 0x401ad8
         // 00401d3f: xor eax, eax
         // 00401d41: mov ds:[0x40e608], eax
         // 00401d46: xor eax, eax
         // 00401d48: mov ds:[0x40e604], eax
      [-]53565783c4f08bf08d3c24a5a58bfce8a0ffffff8d4c24088bd7b8????????e800f5ffff8b5c240885db7504
         // 00401d50: push ebx
         // 00401d51: push esi
         // 00401d52: push edi
         // 00401d53: add esp, 0xfffffffffffffff0
         // 00401d56: mov esi, eax
         // 00401d58: lea edi, ss:[esp]
         // 00401d5b: movsdd 
         // 00401d5c: movsdd 
         // 00401d5d: mov edi, esp
         // 00401d5f: call 0x401d04
         // 00401d64: lea ecx, ss:[esp+0x8]
         // 00401d68: mov edx, edi
         // 00401d6a: mov eax, 0x40e610
         // 00401d6f: call 0x401274
         // 00401d74: mov ebx, ss:[esp+0x8]
         // 00401d78: test ebx, ebx
         // 00401d7a: jnz 0x401d80
      [-]33c0eb52
         // 00401d7c: xor eax, eax
         // 00401d7e: jmp 0x401dd2
      [-]8b073bd8730a
         // 00401d80: mov eax, ds:[edi]
         // 00401d82: cmp ebx, eax
         // 00401d84: jnb 0x401d90
      [-]e899fdffff2907014704
         // 00401d86: call 0x401b24
         // 00401d8b: sub ds:[edi], eax
         // 00401d8d: add ds:[edi+0x4], eax
      [-]8b070347048bf30374240c3bc67308
         // 00401d90: mov eax, ds:[edi]
         // 00401d92: add eax, ds:[edi+0x4]
         // 00401d95: mov esi, ebx
         // 00401d97: add esi, ss:[esp+0xc]
         // 00401d9b: cmp eax, esi
         // 00401d9d: jnb 0x401da7
      [-]e8f0fdffff014704
         // 00401d9f: call 0x401b94
         // 00401da4: add ds:[edi+0x4], eax
      [-]8b070347043bf07511
         // 00401da7: mov eax, ds:[edi]
         // 00401da9: add eax, ds:[edi+0x4]
         // 00401dac: cmp esi, eax
         // 00401dae: jnz 0x401dc1
      [-]83e804ba????????e8ebfcffff836f0404
         // 00401db0: sub eax, 0x4
         // 00401db3: mov edx, 0x4
         // 00401db8: call 0x401aa8
         // 00401dbd: sub ds:[edi+0x4], 0x4
      [-]8b07a3????????8b4704a3????????b001
         // 00401dc1: mov eax, ds:[edi]
         // 00401dc3: mov ds:[0x40e608], eax
         // 00401dc8: mov eax, ds:[edi+0x4]
         // 00401dcb: mov ds:[0x40e604], eax
         // 00401dd0: mov b1 al, b1 0x1
      [-]83c4105f5e5bc3
         // 00401dd2: add esp, 0x10
         // 00401dd5: pop edi
         // 00401dd6: pop esi
         // 00401dd7: pop ebx
         // 00401dd8: retn 
      [-]5383c4f88bd88bd48d4304e83cf8ffff833c2400740b
         // 00401ddc: push ebx
         // 00401ddd: add esp, 0xfffffffffffffff8
         // 00401de0: mov ebx, eax
         // 00401de2: mov edx, esp
         // 00401de4: lea eax, ds:[ebx+0x4]
         // 00401de7: call 0x401628
         // 00401dec: cmp ss:[esp], 0x0
         // 00401df0: jz 0x401dfd
      [-]8bc4e857ffffff84c07504
         // 00401df2: mov eax, esp
         // 00401df4: call 0x401d50
         // 00401df9: test b1 al, b1 al
         // 00401dfb: jnz 0x401e01
      [-]33c0eb02
         // 00401dfd: xor eax, eax
         // 00401dff: jmp 0x401e03
      [-]595a5bc3
         // 00401e03: pop ecx
         // 00401e04: pop edx
         // 00401e05: pop ebx
         // 00401e06: retn 
      [-]535683c4f88bf28bd88bcc8d56048bc3e89bf8ffff833c2400740b
         // 00401e08: push ebx
         // 00401e09: push esi
         // 00401e0a: add esp, 0xfffffffffffffff8
         // 00401e0d: mov esi, edx
         // 00401e0f: mov ebx, eax
         // 00401e11: mov ecx, esp
         // 00401e13: lea edx, ds:[esi+0x4]
         // 00401e16: mov eax, ebx
         // 00401e18: call 0x4016b8
         // 00401e1d: cmp ss:[esp], 0x0
         // 00401e21: jz 0x401e2e
      [-]8bc4e826ffffff84c07504
         // 00401e23: mov eax, esp
         // 00401e25: call 0x401d50
         // 00401e2a: test b1 al, b1 al
         // 00401e2c: jnz 0x401e32
      [-]33c0eb02
         // 00401e2e: xor eax, eax
         // 00401e30: jmp 0x401e34
      [-]595a5e5bc3
         // 00401e34: pop ecx
         // 00401e35: pop edx
         // 00401e36: pop esi
         // 00401e37: pop ebx
         // 00401e38: retn 
      [-]33d285c07903
         // 00401e3c: xor edx, edx
         // 00401e3e: test eax, eax
         // 00401e40: jns 0x401e45
      [-]c1f8023d????????7f16
         // 00401e45: sar eax, b1 0x2
         // 00401e48: cmp eax, 0x400
         // 00401e4d: jg 0x401e65
      [-]8b15????????8b5482f485d27508
         // 00401e4f: mov edx, ds:[0x40e60c]
         // 00401e55: mov edx, ds:[edx+eax*0x4]
         // 00401e59: test edx, edx
         // 00401e5b: jnz 0x401e65
      [-]403d????????75ea
         // 00401e5d: inc eax
         // 00401e5e: cmp eax, 0x401
         // 00401e63: jnz 0x401e4f
      [-]535657558bf0bf????????bd????????
         // 00401e68: push ebx
         // 00401e69: push esi
         // 00401e6a: push edi
         // 00401e6b: push ebp
         // 00401e6c: mov esi, eax
         // 00401e6e: mov edi, 0x40e600
         // 00401e73: mov ebp, 0x40e604
      [-]8b1d????????3b73080f8e84000000
         // 00401e78: mov ebx, ds:[0x40e5f8]
         // 00401e7e: cmp esi, ds:[ebx+0x8]
         // 00401e81: jle 0x401f0b
      [-]8b1f8b43083bf07e7b
         // 00401e87: mov ebx, ds:[edi]
         // 00401e89: mov eax, ds:[ebx+0x8]
         // 00401e8c: cmp esi, eax
         // 00401e8e: jle 0x401f0b
      [-]8b5b043b73087ff8
         // 00401e93: mov ebx, ds:[ebx+0x4]
         // 00401e96: cmp esi, ds:[ebx+0x8]
         // 00401e99: jg 0x401e93
      [-]8b178942083b1f7404
         // 00401e9b: mov edx, ds:[edi]
         // 00401e9d: mov ds:[edx+0x8], eax
         // 00401ea0: cmp ebx, ds:[edi]
         // 00401ea2: jz 0x401ea8
      [-]891feb63
         // 00401ea4: mov ds:[edi], ebx
         // 00401ea6: jmp 0x401f0b
      [-]81fe????????7f0d
         // 00401ea8: cmp esi, 0x1000
         // 00401eae: jg 0x401ebd
      [-]8bc6e885ffffff8bd885db754e
         // 00401eb0: mov eax, esi
         // 00401eb2: call 0x401e3c
         // 00401eb7: mov ebx, eax
         // 00401eb9: test ebx, ebx
         // 00401ebb: jnz 0x401f0b
      [-]8bc6e818ffffff84c07507
         // 00401ebd: mov eax, esi
         // 00401ebf: call 0x401ddc
         // 00401ec4: test b1 al, b1 al
         // 00401ec6: jnz 0x401ecf
      [-]33c0e988000000
         // 00401ec8: xor eax, eax
         // 00401eca: jmp 0x401f57
      [-]3b75007fa4
         // 00401ecf: cmp esi, ss:[ebp+0x0]
         // 00401ed2: jg 0x401e78
      [-]297500837d000c7d08
         // 00401ed4: sub ss:[ebp+0x0], esi
         // 00401ed7: cmp ss:[ebp+0x0], 0xc
         // 00401edb: jge 0x401ee5
      [-]03750033c0894500
         // 00401edd: add esi, ss:[ebp+0x0]
         // 00401ee0: xor eax, eax
         // 00401ee2: mov ss:[ebp+0x0], eax
      [-]a1????????0135????????8bd683ca02891083c004ff05????????83ee040135????????eb4c
         // 00401ee5: mov eax, ds:[0x40e608]
         // 00401eea: add ds:[0x40e608], esi
         // 00401ef0: mov edx, esi
         // 00401ef2: or edx, 0x2
         // 00401ef5: mov ds:[eax], edx
         // 00401ef7: add eax, 0x4
         // 00401efa: inc ds:[0x40e59c]
         // 00401f00: sub esi, 0x4
         // 00401f03: add ds:[0x40e5a0], esi
         // 00401f09: jmp 0x401f57
      [-]8bc3e802fbffff8b53088bc22bc683f80c7c0c
         // 00401f0b: mov eax, ebx
         // 00401f0d: call 0x401a14
         // 00401f12: mov edx, ds:[ebx+0x8]
         // 00401f15: mov eax, edx
         // 00401f17: sub eax, esi
         // 00401f19: cmp eax, 0xc
         // 00401f1c: jl 0x401f2a
      [-]8bd303d692e854fdffffeb12
         // 00401f1e: mov edx, ebx
         // 00401f20: add edx, esi
         // 00401f22: xchg eax, edx
         // 00401f23: call 0x401c7c
         // 00401f28: jmp 0x401f3c
      [-]8bf23b1f7505
         // 00401f2a: mov esi, edx
         // 00401f2c: cmp ebx, ds:[edi]
         // 00401f2e: jnz 0x401f35
      [-]8b43048907
         // 00401f30: mov eax, ds:[ebx+0x4]
         // 00401f33: mov ds:[edi], eax
      [-]8bc303c68320fe
         // 00401f35: mov eax, ebx
         // 00401f37: add eax, esi
         // 00401f39: and ds:[eax], 0xfffffffffffffffe
      [-]8bc38bd683ca02891083c004ff05????????83ee040135????????
         // 00401f3c: mov eax, ebx
         // 00401f3e: mov edx, esi
         // 00401f40: or edx, 0x2
         // 00401f43: mov ds:[eax], edx
         // 00401f45: add eax, 0x4
         // 00401f48: inc ds:[0x40e59c]
         // 00401f4e: sub esi, 0x4
         // 00401f51: add ds:[0x40e5a0], esi
      [-]5d5f5e5bc3
         // 00401f57: pop ebp
         // 00401f58: pop edi
         // 00401f59: pop esi
         // 00401f5a: pop ebx
         // 00401f5b: retn 
      [-]558bec83c4f85356578bd8803dace54000007509
         // 00401f5c: push ebp
         // 00401f5d: mov ebp, esp
         // 00401f5f: add esp, 0xfffffffffffffff8
         // 00401f62: push ebx
         // 00401f63: push esi
         // 00401f64: push edi
         // 00401f65: mov ebx, eax
         // 00401f67: cmp b1 ds:[0x40e5ac], b1 0x0
         // 00401f6e: jnz 0x401f79
      [-]e8f3f8ffff84c07408
         // 00401f70: call 0x401868
         // 00401f75: test b1 al, b1 al
         // 00401f77: jz 0x401f81
      [-]81fb????????7e0a
         // 00401f79: cmp ebx, 0x7ffffff8
         // 00401f7f: jle 0x401f8b
      [-]33c08945fce954010000
         // 00401f81: xor eax, eax
         // 00401f83: mov ss:[ebp+0xfffffffffffffffc], eax
         // 00401f86: jmp 0x4020df
      [-]33c95568????????64ff31648921803d35e0400000740a
         // 00401f8b: xor ecx, ecx
         // 00401f8d: push ebp
         // 00401f8e: push 0x4020d8
         // 00401f93: push fs:[ecx]
         // 00401f96: mov fs:[ecx], esp
         // 00401f99: cmp b1 ds:[0x40e035], b1 0x0
         // 00401fa0: jz 0x401fac
      [-]68b4e54000e810f2ffff
         // 00401fa2: push CriticalSection.DebugInfo
         // 00401fa7: call EnterCriticalSection
      [-]83c30783e3fc83fb0c7d05
         // 00401fac: add ebx, 0x7
         // 00401faf: and ebx, 0xfffffffffffffffc
         // 00401fb2: cmp ebx, 0xc
         // 00401fb5: jge 0x401fbc
      [-]bb????????
         // 00401fb7: mov ebx, 0xc
      [-]81fb????????0f8f93000000
         // 00401fbc: cmp ebx, 0x1000
         // 00401fc2: jg 0x40205b
      [-]8bc385c07903
         // 00401fc8: mov eax, ebx
         // 00401fca: test eax, eax
         // 00401fcc: jns 0x401fd1
      [-]c1f8028b15????????8b5482f485d27479
         // 00401fd1: sar eax, b1 0x2
         // 00401fd4: mov edx, ds:[0x40e60c]
         // 00401fda: mov edx, ds:[edx+eax*0x4]
         // 00401fde: test edx, edx
         // 00401fe0: jz 0x40205b
      [-]8bf28bc603c38320fe8b42043bd0751a
         // 00401fe2: mov esi, edx
         // 00401fe4: mov eax, esi
         // 00401fe6: add eax, ebx
         // 00401fe8: and ds:[eax], 0xfffffffffffffffe
         // 00401feb: mov eax, ds:[edx+0x4]
         // 00401fee: cmp edx, eax
         // 00401ff0: jnz 0x40200c
      [-]8bc385c07903
         // 00401ff2: mov eax, ebx
         // 00401ff4: test eax, eax
         // 00401ff6: jns 0x401ffb
      [-]c1f8028b0d????????33ff897c81f4eb26
         // 00401ffb: sar eax, b1 0x2
         // 00401ffe: mov ecx, ds:[0x40e60c]
         // 00402004: xor edi, edi
         // 00402006: mov ds:[ecx+eax*0x4], edi
         // 0040200a: jmp 0x402032
      [-]8bcb85c97903
         // 0040200c: mov ecx, ebx
         // 0040200e: test ecx, ecx
         // 00402010: jns 0x402015
      [-]c1f9028b3d????????89448ff48b0a894df88b4df88941048b4df88908
         // 00402015: sar ecx, b1 0x2
         // 00402018: mov edi, ds:[0x40e60c]
         // 0040201e: mov ds:[edi+ecx*0x4], eax
         // 00402022: mov ecx, ds:[edx]
         // 00402024: mov ss:[ebp+0xfffffffffffffff8], ecx
         // 00402027: mov ecx, ss:[ebp+0xfffffffffffffff8]
         // 0040202a: mov ds:[ecx+0x4], eax
         // 0040202d: mov ecx, ss:[ebp+0xfffffffffffffff8]
         // 00402030: mov ds:[eax], ecx
      [-]8bc68b520883ca02891083c0048945fcff05????????83eb04011d????????e84a1a0000e984000000
         // 00402032: mov eax, esi
         // 00402034: mov edx, ds:[edx+0x8]
         // 00402037: or edx, 0x2
         // 0040203a: mov ds:[eax], edx
         // 0040203c: add eax, 0x4
         // 0040203f: mov ss:[ebp+0xfffffffffffffffc], eax
         // 00402042: inc ds:[0x40e59c]
         // 00402048: sub ebx, 0x4
         // 0040204b: add ds:[0x40e5a0], ebx
         // 00402051: call 0x403aa0
         // 00402056: jmp 0x4020df
      [-]3b1d????????7f4a
         // 0040205b: cmp ebx, ds:[0x40e604]
         // 00402061: jg 0x4020ad
      [-]291d????????833d????????0c7d0d
         // 00402063: sub ds:[0x40e604], ebx
         // 00402069: cmp ds:[0x40e604], 0xc
         // 00402070: jge 0x40207f
      [-]031d????????33c0a3????????
         // 00402072: add ebx, ds:[0x40e604]
         // 00402078: xor eax, eax
         // 0040207a: mov ds:[0x40e604], eax
      [-]a1????????011d????????8bd383ca02891083c0048945fcff05????????83eb04011d????????e8f5190000eb32
         // 0040207f: mov eax, ds:[0x40e608]
         // 00402084: add ds:[0x40e608], ebx
         // 0040208a: mov edx, ebx
         // 0040208c: or edx, 0x2
         // 0040208f: mov ds:[eax], edx
         // 00402091: add eax, 0x4
         // 00402094: mov ss:[ebp+0xfffffffffffffffc], eax
         // 00402097: inc ds:[0x40e59c]
         // 0040209d: sub ebx, 0x4
         // 004020a0: add ds:[0x40e5a0], ebx
         // 004020a6: call 0x403aa0
         // 004020ab: jmp 0x4020df
      [-]8bc3e8b4fdffff8945fc33c05a595964891068????????803d35e0400000740a
         // 004020ad: mov eax, ebx
         // 004020af: call 0x401e68
         // 004020b4: mov ss:[ebp+0xfffffffffffffffc], eax
         // 004020b7: xor eax, eax
         // 004020b9: pop edx
         // 004020ba: pop ecx
         // 004020bb: pop ecx
         // 004020bc: mov fs:[eax], edx
         // 004020bf: push 0x4020df
         // 004020c4: cmp b1 ds:[0x40e035], b1 0x0
         // 004020cb: jz 0x4020d7
      [-]68b4e54000e8edf0ffff
         // 004020cd: push CriticalSection.DebugInfo
         // 004020d2: call LeaveCriticalSection
      [-]8b45fc5f5e5b59595dc3
         // 004020df: mov eax, ss:[ebp+0xfffffffffffffffc]
         // 004020e2: pop edi
         // 004020e3: pop esi
         // 004020e4: pop ebx
         // 004020e5: pop ecx
         // 004020e6: pop ecx
         // 004020e7: pop ebp
         // 004020e8: retn 
      [-]558bec515356578bd833c0a3????????803dace5400000751f
         // 004020ec: push ebp
         // 004020ed: mov ebp, esp
         // 004020ef: push ecx
         // 004020f0: push ebx
         // 004020f1: push esi
         // 004020f2: push edi
         // 004020f3: mov ebx, eax
         // 004020f5: xor eax, eax
         // 004020f7: mov ds:[0x40e5b0], eax
         // 004020fc: cmp b1 ds:[0x40e5ac], b1 0x0
         // 00402103: jnz 0x402124
      [-]e85ef7ffff84c07516
         // 00402105: call 0x401868
         // 0040210a: test b1 al, b1 al
         // 0040210c: jnz 0x402124
      [-]c705????????????????c745fc????????e961010000
         // 0040210e: mov ds:[0x40e5b0], 0x8
         // 00402118: mov ss:[ebp+0xfffffffffffffffc], 0x8
         // 0040211f: jmp 0x402285
      [-]33c95568????????64ff31648921803d35e0400000740a
         // 00402124: xor ecx, ecx
         // 00402126: push ebp
         // 00402127: push 0x40227e
         // 0040212c: push fs:[ecx]
         // 0040212f: mov fs:[ecx], esp
         // 00402132: cmp b1 ds:[0x40e035], b1 0x0
         // 00402139: jz 0x402145
      [-]68b4e54000e877f0ffff
         // 0040213b: push CriticalSection.DebugInfo
         // 00402140: call EnterCriticalSection
      [-]8bf383ee048b1ef6c302750f
         // 00402145: mov esi, ebx
         // 00402147: sub esi, 0x4
         // 0040214a: mov ebx, ds:[esi]
         // 0040214c: test b1 bl, b1 0x2
         // 0040214f: jnz 0x402160
      [-]c705????????????????e9f5000000
         // 00402151: mov ds:[0x40e5b0], 0x9
         // 0040215b: jmp 0x402255
      [-]ff0d????????8bc325????????83e8042905????????f6c3017445
         // 00402160: dec ds:[0x40e59c]
         // 00402166: mov eax, ebx
         // 00402168: and eax, 0x7ffffffc
         // 0040216d: sub eax, 0x4
         // 00402170: sub ds:[0x40e5a0], eax
         // 00402176: test b1 bl, b1 0x1
         // 00402179: jz 0x4021c0
      [-]8bc683e80c8b500883fa0c7c08
         // 0040217b: mov eax, esi
         // 0040217d: sub eax, 0xc
         // 00402180: mov edx, ds:[eax+0x8]
         // 00402183: cmp edx, 0xc
         // 00402186: jl 0x402190
      [-]f7c2????????740f
         // 00402188: test edx, 0xffffffff80000003
         // 0040218e: jz 0x40219f
      [-]c705????????????????e9b6000000
         // 00402190: mov ds:[0x40e5b0], 0xa
         // 0040219a: jmp 0x402255
      [-]8bc62bc23b5008740f
         // 0040219f: mov eax, esi
         // 004021a1: sub eax, edx
         // 004021a3: cmp edx, ds:[eax+0x8]
         // 004021a6: jz 0x4021b7
      [-]c705????????????????e99e000000
         // 004021a8: mov ds:[0x40e5b0], 0xa
         // 004021b2: jmp 0x402255
      [-]03da8bf0e854f8ffff
         // 004021b7: add ebx, edx
         // 004021b9: mov esi, eax
         // 004021bb: call 0x401a14
      [-]81e3????????8bc603c38bf83b3d????????752c
         // 004021c0: and ebx, 0x7ffffffc
         // 004021c6: mov eax, esi
         // 004021c8: add eax, ebx
         // 004021ca: mov edi, eax
         // 004021cc: cmp edi, ds:[0x40e608]
         // 004021d2: jnz 0x402200
      [-]291d????????011d????????813d????????????????7e05
         // 004021d4: sub ds:[0x40e608], ebx
         // 004021da: add ds:[0x40e604], ebx
         // 004021e0: cmp ds:[0x40e604], 0x3c00
         // 004021ea: jle 0x4021f1
      [-]e813fbffff
         // 004021ec: call 0x401d04
      [-]33c08945fce8a5180000e985000000
         // 004021f1: xor eax, eax
         // 004021f3: mov ss:[ebp+0xfffffffffffffffc], eax
         // 004021f6: call 0x403aa0
         // 004021fb: jmp 0x402285
      [-]8b10f6c202741c
         // 00402200: mov edx, ds:[eax]
         // 00402202: test b1 dl, b1 0x2
         // 00402205: jz 0x402223
      [-]81e2????????83fa047d0c
         // 00402207: and edx, 0x7ffffffc
         // 0040220d: cmp edx, 0x4
         // 00402210: jge 0x40221e
      [-]c705????????????????eb37
         // 00402212: mov ds:[0x40e5b0], 0xb
         // 0040221c: jmp 0x402255
      [-]830801eb29
         // 0040221e: or ds:[eax], 0x1
         // 00402221: jmp 0x40224c
      [-]8bc783780400740b
         // 00402223: mov eax, edi
         // 00402225: cmp ds:[eax+0x4], 0x0
         // 00402229: jz 0x402236
      [-]8338007406
         // 0040222b: cmp ds:[eax], 0x0
         // 0040222e: jz 0x402236
      [-]8378080c7d0c
         // 00402230: cmp ds:[eax+0x8], 0xc
         // 00402234: jge 0x402242
      [-]c705????????????????eb13
         // 00402236: mov ds:[0x40e5b0], 0xb
         // 00402240: jmp 0x402255
      [-]8b500803dae8c8f7ffff
         // 00402242: mov edx, ds:[eax+0x8]
         // 00402245: add ebx, edx
         // 00402247: call 0x401a14
      [-]8bd38bc6e827faffff
         // 0040224c: mov edx, ebx
         // 0040224e: mov eax, esi
         // 00402250: call 0x401c7c
      [-]a1????????8945fc33c05a595964891068????????803d35e0400000740a
         // 00402255: mov eax, ds:[0x40e5b0]
         // 0040225a: mov ss:[ebp+0xfffffffffffffffc], eax
         // 0040225d: xor eax, eax
         // 0040225f: pop edx
         // 00402260: pop ecx
         // 00402261: pop ecx
         // 00402262: mov fs:[eax], edx
         // 00402265: push 0x402285
         // 0040226a: cmp b1 ds:[0x40e035], b1 0x0
         // 00402271: jz 0x40227d
      [-]68b4e54000e847efffff
         // 00402273: push CriticalSection.DebugInfo
         // 00402278: call LeaveCriticalSection
      [-]8b45fc5f5e5b595dc3
         // 00402285: mov eax, ss:[ebp+0xfffffffffffffffc]
         // 00402288: pop edi
         // 00402289: pop esi
         // 0040228a: pop ebx
         // 0040228b: pop ecx
         // 0040228c: pop ebp
         // 0040228d: retn 
      [-]5356575583c4f88bf283c60783e6fc83fe0c7d05
         // 00402290: push ebx
         // 00402291: push esi
         // 00402292: push edi
         // 00402293: push ebp
         // 00402294: add esp, 0xfffffffffffffff8
         // 00402297: mov esi, edx
         // 00402299: add esi, 0x7
         // 0040229c: and esi, 0xfffffffffffffffc
         // 0040229f: cmp esi, 0xc
         // 004022a2: jge 0x4022a9
      [-]be????????
         // 004022a4: mov esi, 0xc
      [-]8be883ed048b7d0081e7????????8bc503c78bd83bfe7507
         // 004022a9: mov ebp, eax
         // 004022ab: sub ebp, 0x4
         // 004022ae: mov edi, ss:[ebp+0x0]
         // 004022b1: and edi, 0x7ffffffc
         // 004022b7: mov eax, ebp
         // 004022b9: add eax, edi
         // 004022bb: mov ebx, eax
         // 004022bd: cmp edi, esi
         // 004022bf: jnz 0x4022c8
      [-]b001e99b010000
         // 004022c1: mov b1 al, b1 0x1
         // 004022c3: jmp 0x402463
      [-]3bfe0f8e83000000
         // 004022c8: cmp edi, esi
         // 004022ca: jle 0x402353
      [-]8bd72bd68914243b1d????????7538
         // 004022d0: mov edx, edi
         // 004022d2: sub edx, esi
         // 004022d4: mov ss:[esp], edx
         // 004022d7: cmp ebx, ds:[0x40e608]
         // 004022dd: jnz 0x402317
      [-]8b04242905????????8b04240105????????833d????????0c0f8d4c010000
         // 004022df: mov eax, ss:[esp]
         // 004022e2: sub ds:[0x40e608], eax
         // 004022e8: mov eax, ss:[esp]
         // 004022eb: add ds:[0x40e604], eax
         // 004022f1: cmp ds:[0x40e604], 0xc
         // 004022f8: jge 0x40244a
      [-]8b04240105????????8b04242905????????8bf7e933010000
         // 004022fe: mov eax, ss:[esp]
         // 00402301: add ds:[0x40e608], eax
         // 00402307: mov eax, ss:[esp]
         // 0040230a: sub ds:[0x40e604], eax
         // 00402310: mov esi, edi
         // 00402312: jmp 0x40244a
      [-]8bd8f60302750d
         // 00402317: mov ebx, eax
         // 00402319: test b1 ds:[ebx], b1 0x2
         // 0040231c: jnz 0x40232b
      [-]8bc38b5008011424e8e9f6ffff
         // 0040231e: mov eax, ebx
         // 00402320: mov edx, ds:[eax+0x8]
         // 00402323: add ss:[esp], edx
         // 00402326: call 0x401a14
      [-]833c240c7c1b
         // 0040232b: cmp ss:[esp], 0xc
         // 0040232f: jl 0x40234c
      [-]8bdd03de8b042483c80289038bc383c004e891f7ffffe9fe000000
         // 00402331: mov ebx, ebp
         // 00402333: add ebx, esi
         // 00402335: mov eax, ss:[esp]
         // 00402338: or eax, 0x2
         // 0040233b: mov ds:[ebx], eax
         // 0040233d: mov eax, ebx
         // 0040233f: add eax, 0x4
         // 00402342: call 0x401ad8
         // 00402347: jmp 0x40244a
      [-]8bf7e9f7000000
         // 0040234c: mov esi, edi
         // 0040234e: jmp 0x40244a
      [-]8bc62bc7894424043b1d????????7567
         // 00402353: mov eax, esi
         // 00402355: sub eax, edi
         // 00402357: mov ss:[esp+0x4], eax
         // 0040235b: cmp ebx, ds:[0x40e608]
         // 00402361: jnz 0x4023ca
      [-]a1????????3b4424047c53
         // 00402363: mov eax, ds:[0x40e604]
         // 00402368: cmp eax, ss:[esp+0x4]
         // 0040236c: jl 0x4023c1
      [-]8b4424042905????????8b4424040105????????833d????????0c7d18
         // 0040236e: mov eax, ss:[esp+0x4]
         // 00402372: sub ds:[0x40e604], eax
         // 00402378: mov eax, ss:[esp+0x4]
         // 0040237c: add ds:[0x40e608], eax
         // 00402382: cmp ds:[0x40e604], 0xc
         // 00402389: jge 0x4023a3
      [-]a1????????0105????????0335????????33c0a3????????
         // 0040238b: mov eax, ds:[0x40e604]
         // 00402390: add ds:[0x40e608], eax
         // 00402396: add esi, ds:[0x40e604]
         // 0040239c: xor eax, eax
         // 0040239e: mov ds:[0x40e604], eax
      [-]8bc62bc70105????????8b450025????????0bf0897500b001e9a2000000
         // 004023a3: mov eax, esi
         // 004023a5: sub eax, edi
         // 004023a7: add ds:[0x40e5a0], eax
         // 004023ad: mov eax, ss:[ebp+0x0]
         // 004023b0: and eax, 0xffffffff80000003
         // 004023b5: or esi, eax
         // 004023b7: mov ss:[ebp+0x0], esi
         // 004023ba: mov b1 al, b1 0x1
         // 004023bc: jmp 0x402463
      [-]e83ef9ffff8bdd03df
         // 004023c1: call 0x401d04
         // 004023c6: mov ebx, ebp
         // 004023c8: add ebx, edi
      [-]f60302754d
         // 004023ca: test b1 ds:[ebx], b1 0x2
         // 004023cd: jnz 0x40241c
      [-]8bd38bc28b4808890c248b0c243b4c24047d0e
         // 004023cf: mov edx, ebx
         // 004023d1: mov eax, edx
         // 004023d3: mov ecx, ds:[eax+0x8]
         // 004023d6: mov ss:[esp], ecx
         // 004023d9: mov ecx, ss:[esp]
         // 004023dc: cmp ecx, ss:[esp+0x4]
         // 004023e0: jge 0x4023f0
      [-]0314248bda8b042429442404eb2c
         // 004023e2: add edx, ss:[esp]
         // 004023e5: mov ebx, edx
         // 004023e7: mov eax, ss:[esp]
         // 004023ea: sub ss:[esp+0x4], eax
         // 004023ee: jmp 0x40241c
      [-]e81ff6ffff8b442404290424833c240c7c0e
         // 004023f0: call 0x401a14
         // 004023f5: mov eax, ss:[esp+0x4]
         // 004023f9: sub ss:[esp], eax
         // 004023fc: cmp ss:[esp], 0xc
         // 00402400: jl 0x402410
      [-]8bc503c68b1424e86ef8ffffeb3a
         // 00402402: mov eax, ebp
         // 00402404: add eax, esi
         // 00402406: mov edx, ss:[esp]
         // 00402409: call 0x401c7c
         // 0040240e: jmp 0x40244a
      [-]0334248bdd03de8323feeb2e
         // 00402410: add esi, ss:[esp]
         // 00402413: mov ebx, ebp
         // 00402415: add ebx, esi
         // 00402417: and ds:[ebx], 0xfffffffffffffffe
         // 0040241a: jmp 0x40244a
      [-]8b03a9????????7421
         // 0040241c: mov eax, ds:[ebx]
         // 0040241e: test eax, 0xffffffff80000000
         // 00402423: jz 0x402446
      [-]25????????03c38bd88b5424048bc3e8cff9ffff84c07409
         // 00402425: and eax, 0x7ffffffc
         // 0040242a: add eax, ebx
         // 0040242c: mov ebx, eax
         // 0040242e: mov edx, ss:[esp+0x4]
         // 00402432: mov eax, ebx
         // 00402434: call 0x401e08
         // 00402439: test b1 al, b1 al
         // 0040243b: jz 0x402446
      [-]8bdd03dfe90dffffff
         // 0040243d: mov ebx, ebp
         // 0040243f: add ebx, edi
         // 00402441: jmp 0x402353
      [-]33c0eb19
         // 00402446: xor eax, eax
         // 00402448: jmp 0x402463
      [-]8bc62bc70105????????8b450025????????0bf0897500b001
         // 0040244a: mov eax, esi
         // 0040244c: sub eax, edi
         // 0040244e: add ds:[0x40e5a0], eax
         // 00402454: mov eax, ss:[ebp+0x0]
         // 00402457: and eax, 0xffffffff80000003
         // 0040245c: or esi, eax
         // 0040245e: mov ss:[ebp+0x0], esi
         // 00402461: mov b1 al, b1 0x1
      [-]595a5d5f5e5bc3
         // 00402463: pop ecx
         // 00402464: pop edx
         // 00402465: pop ebp
         // 00402466: pop edi
         // 00402467: pop esi
         // 00402468: pop ebx
         // 00402469: retn 
      [-]558bec515356578bf28bd8803dace54000007513
         // 0040246c: push ebp
         // 0040246d: mov ebp, esp
         // 0040246f: push ecx
         // 00402470: push ebx
         // 00402471: push esi
         // 00402472: push edi
         // 00402473: mov esi, edx
         // 00402475: mov ebx, eax
         // 00402477: cmp b1 ds:[0x40e5ac], b1 0x0
         // 0040247e: jnz 0x402493
      [-]e8e3
         // 00402480: call 0x401868
         // 00402485: test b1 al, b1 al
         // 00402487: jnz 0x402493

  }
  condition:
    all of them
}
