rule lauri_20_0 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         5383c4bcbb????????54e869fffffff644242c017405
         // 004011c0: push ebx
         // 004011c1: add esp, 0xffffffffffffffbc
         // 004011c4: mov ebx, 0xa
         // 004011c9: push esp
         // 004011ca: call GetStartupInfoA
         // 004011cf: test b1 ss:[esp+0x2c], b1 0x1
         // 004011d4: jz 0x4011db
      [-]0fb75c2430
         // 004011d6: movzx ebx, b2 ss:[esp+0x30]
      [-]8bc383c4445bc3
         // 004011db: mov eax, ebx
         // 004011dd: add esp, 0x44
         // 004011e0: pop ebx
         // 004011e1: retn 
      [-]5356be????????833e00753a
         // 00401224: push ebx
         // 00401225: push esi
         // 00401226: mov esi, 0x40d440
         // 0040122b: cmp ds:[esi], 0x0
         // 0040122e: jnz 0x40126a
      [-]68????????6a00e8a8ffffff8bc885c97505
         // 00401230: push 0x644
         // 00401235: push 0x0
         // 00401237: call LocalAlloc
         // 0040123c: mov ecx, eax
         // 0040123e: test ecx, ecx
         // 00401240: jnz 0x401247
      [-]33c05e5bc3
         // 00401242: xor eax, eax
         // 00401244: pop esi
         // 00401245: pop ebx
         // 00401246: retn 
      [-]a1????????8901890d????????33d2
         // 00401247: mov eax, ds:[0x40d43c]
         // 0040124c: mov ds:[ecx], eax
         // 0040124e: mov ds:[0x40d43c], ecx
         // 00401254: xor edx, edx
      [-]8bc203c08d44c1048b1e891889064283fa6475ec
         // 00401256: mov eax, edx
         // 00401258: add eax, eax
         // 0040125a: lea eax, ds:[ecx+eax*0x8]
         // 0040125e: mov ebx, ds:[esi]
         // 00401260: mov ds:[eax], ebx
         // 00401262: mov ds:[esi], eax
         // 00401264: inc edx
         // 00401265: cmp edx, 0x64
         // 00401268: jnz 0x401256
      [-]8b068b1089165e5bc3
         // 0040126a: mov eax, ds:[esi]
         // 0040126c: mov edx, ds:[eax]
         // 0040126e: mov ds:[esi], edx
         // 00401270: pop esi
         // 00401271: pop ebx
         // 00401272: retn 
      [-]8900894004c3
         // 00401274: mov ds:[eax], eax
         // 00401276: mov ds:[eax+0x4], eax
         // 00401279: retn 
      [-]53568bf28bd8e89dffffff85c07505
         // 0040127c: push ebx
         // 0040127d: push esi
         // 0040127e: mov esi, edx
         // 00401280: mov ebx, eax
         // 00401282: call 0x401224
         // 00401287: test eax, eax
         // 00401289: jnz 0x401290
      [-]33c05e5bc3
         // 0040128b: xor eax, eax
         // 0040128d: pop esi
         // 0040128e: pop ebx
         // 0040128f: retn 
      [-]8b168950088b560489500c8b1389108958048942048903b0015e5bc3
         // 00401290: mov edx, ds:[esi]
         // 00401292: mov ds:[eax+0x8], edx
         // 00401295: mov edx, ds:[esi+0x4]
         // 00401298: mov ds:[eax+0xc], edx
         // 0040129b: mov edx, ds:[ebx]
         // 0040129d: mov ds:[eax], edx
         // 0040129f: mov ds:[eax+0x4], ebx
         // 004012a2: mov ds:[edx+0x4], eax
         // 004012a5: mov ds:[ebx], eax
         // 004012a7: mov b1 al, b1 0x1
         // 004012a9: pop esi
         // 004012aa: pop ebx
         // 004012ab: retn 
      [-]8b50048b08890a8951048b15????????8910a3????????c3
         // 004012ac: mov edx, ds:[eax+0x4]
         // 004012af: mov ecx, ds:[eax]
         // 004012b1: mov ds:[edx], ecx
         // 004012b3: mov ds:[ecx+0x4], edx
         // 004012b6: mov edx, ds:[0x40d440]
         // 004012bc: mov ds:[eax], edx
         // 004012be: mov ds:[0x40d440], eax
         // 004012c3: retn 
      [-]53565755518bf18914248be88b5d008b04248b1089168b5004895604
         // 004012c4: push ebx
         // 004012c5: push esi
         // 004012c6: push edi
         // 004012c7: push ebp
         // 004012c8: push ecx
         // 004012c9: mov esi, ecx
         // 004012cb: mov ss:[esp], edx
         // 004012ce: mov ebp, eax
         // 004012d0: mov ebx, ss:[ebp+0x0]
         // 004012d3: mov eax, ss:[esp]
         // 004012d6: mov edx, ds:[eax]
         // 004012d8: mov ds:[esi], edx
         // 004012da: mov edx, ds:[eax+0x4]
         // 004012dd: mov ds:[esi+0x4], edx
      [-]8b3b8b43088bd003530c3b167514
         // 004012e0: mov edi, ds:[ebx]
         // 004012e2: mov eax, ds:[ebx+0x8]
         // 004012e5: mov edx, eax
         // 004012e7: add edx, ds:[ebx+0xc]
         // 004012ea: cmp edx, ds:[esi]
         // 004012ec: jnz 0x401302
      [-]8bc3e8b7ffffff8b430889068b430c014604eb16
         // 004012ee: mov eax, ebx
         // 004012f0: call 0x4012ac
         // 004012f5: mov eax, ds:[ebx+0x8]
         // 004012f8: mov ds:[esi], eax
         // 004012fa: mov eax, ds:[ebx+0xc]
         // 004012fd: add ds:[esi+0x4], eax
         // 00401300: jmp 0x401318
      [-]8b160356043bc2750d
         // 00401302: mov edx, ds:[esi]
         // 00401304: add edx, ds:[esi+0x4]
         // 00401307: cmp eax, edx
         // 00401309: jnz 0x401318
      [-]8bc3e89affffff8b430c014604
         // 0040130b: mov eax, ebx
         // 0040130d: call 0x4012ac
         // 00401312: mov eax, ds:[ebx+0xc]
         // 00401315: add ds:[esi+0x4], eax
      [-]8bdf3beb75c2
         // 00401318: mov ebx, edi
         // 0040131a: cmp ebp, ebx
         // 0040131c: jnz 0x4012e0
      [-]8bd68bc5e855ffffff84c07504
         // 0040131e: mov edx, esi
         // 00401320: mov eax, ebp
         // 00401322: call 0x40127c
         // 00401327: test b1 al, b1 al
         // 00401329: jnz 0x40132f
      [-]33c08906
         // 0040132b: xor eax, eax
         // 0040132d: mov ds:[esi], eax
      [-]5a5d5f5e5bc3
         // 0040132f: pop edx
         // 00401330: pop ebp
         // 00401331: pop edi
         // 00401332: pop esi
         // 00401333: pop ebx
         // 00401334: retn 
      [-]5356575583c4f88bd88bfb
         // 00401338: push ebx
         // 00401339: push esi
         // 0040133a: push edi
         // 0040133b: push ebp
         // 0040133c: add esp, 0xfffffffffffffff8
         // 0040133f: mov ebx, eax
         // 00401341: mov edi, ebx
      [-]8b328b43083bf0726c
         // 00401343: mov esi, ds:[edx]
         // 00401345: mov eax, ds:[ebx+0x8]
         // 00401348: cmp esi, eax
         // 0040134a: jb 0x4013b8
      [-]8bce034a048be8036b0c3bcd775e
         // 0040134c: mov ecx, esi
         // 0040134e: add ecx, ds:[edx+0x4]
         // 00401351: mov ebp, eax
         // 00401353: add ebp, ds:[ebx+0xc]
         // 00401356: cmp ecx, ebp
         // 00401358: ja 0x4013b8
      [-]3bf0751b
         // 0040135a: cmp esi, eax
         // 0040135c: jnz 0x401379
      [-]8b42040143088b420429430c837b0c007544
         // 0040135e: mov eax, ds:[edx+0x4]
         // 00401361: add ds:[ebx+0x8], eax
         // 00401364: mov eax, ds:[edx+0x4]
         // 00401367: sub ds:[ebx+0xc], eax
         // 0040136a: cmp ds:[ebx+0xc], 0x0
         // 0040136e: jnz 0x4013b4
      [-]8bc3e835ffffffeb3b
         // 00401370: mov eax, ebx
         // 00401372: call 0x4012ac
         // 00401377: jmp 0x4013b4
      [-]8b0a8b720403ce8bf8037b0c3bcf7505
         // 00401379: mov ecx, ds:[edx]
         // 0040137b: mov esi, ds:[edx+0x4]
         // 0040137e: add ecx, esi
         // 00401380: mov edi, eax
         // 00401382: add edi, ds:[ebx+0xc]
         // 00401385: cmp ecx, edi
         // 00401387: jnz 0x40138e
      [-]29730ceb26
         // 00401389: sub ds:[ebx+0xc], esi
         // 0040138c: jmp 0x4013b4
      [-]8b0a034a04890c242bf9897c24048b122bd089530c8bd48bc3e8d0feffff84c07504
         // 0040138e: mov ecx, ds:[edx]
         // 00401390: add ecx, ds:[edx+0x4]
         // 00401393: mov ss:[esp], ecx
         // 00401396: sub edi, ecx
         // 00401398: mov ss:[esp+0x4], edi
         // 0040139c: mov edx, ds:[edx]
         // 0040139e: sub edx, eax
         // 004013a0: mov ds:[ebx+0xc], edx
         // 004013a3: mov edx, esp
         // 004013a5: mov eax, ebx
         // 004013a7: call 0x40127c
         // 004013ac: test b1 al, b1 al
         // 004013ae: jnz 0x4013b4
      [-]33c0eb0c
         // 004013b0: xor eax, eax
         // 004013b2: jmp 0x4013c0
      [-]b001eb08
         // 004013b4: mov b1 al, b1 0x1
         // 004013b6: jmp 0x4013c0
      [-]8b1b3bfb7585
         // 004013b8: mov ebx, ds:[ebx]
         // 004013ba: cmp edi, ebx
         // 004013bc: jnz 0x401343
      [-]595a5d5f5e5bc3
         // 004013c0: pop ecx
         // 004013c1: pop edx
         // 004013c2: pop ebp
         // 004013c3: pop edi
         // 004013c4: pop esi
         // 004013c5: pop ebx
         // 004013c6: retn 
      [-]5356578bda8bf081fe????????7d07
         // 004013c8: push ebx
         // 004013c9: push esi
         // 004013ca: push edi
         // 004013cb: mov ebx, edx
         // 004013cd: mov esi, eax
         // 004013cf: cmp esi, 0x100000
         // 004013d5: jge 0x4013de
      [-]be????????eb0c
         // 004013d7: mov esi, 0x100000
         // 004013dc: jmp 0x4013ea
      [-]81c6????????81e6????????
         // 004013de: add esi, 0xffff
         // 004013e4: and esi, 0xffffffffffff0000
      [-]8973046a0168????????566a00e8f8fdffff8bf8893b85ff7423
         // 004013ea: mov ds:[ebx+0x4], esi
         // 004013ed: push 0x1
         // 004013ef: push 0x2000
         // 004013f4: push esi
         // 004013f5: push 0x0
         // 004013f7: call VirtualAlloc
         // 004013fc: mov edi, eax
         // 004013fe: mov ds:[ebx], edi
         // 00401400: test edi, edi
         // 00401402: jz 0x401427
      [-]8bd3b8????????e86cfeffff84c07513
         // 00401404: mov edx, ebx
         // 00401406: mov eax, 0x40d444
         // 0040140b: call 0x40127c
         // 00401410: test b1 al, b1 al
         // 00401412: jnz 0x401427
      [-]68????????6a008b0350e8d9fdffff33c08903
         // 00401414: push 0x8000
         // 00401419: push 0x0
         // 0040141b: mov eax, ds:[ebx]
         // 0040141d: push eax
         // 0040141e: call VirtualFree
         // 00401423: xor eax, eax
         // 00401425: mov ds:[ebx], eax
      [-]5f5e5bc3
         // 00401427: pop edi
         // 00401428: pop esi
         // 00401429: pop ebx
         // 0040142a: retn 
      [-]535657558bd98bf28be8c74304????????6a0468????????68????????55e8a5fdffff8bf8893b85ff751f
         // 0040142c: push ebx
         // 0040142d: push esi
         // 0040142e: push edi
         // 0040142f: push ebp
         // 00401430: mov ebx, ecx
         // 00401432: mov esi, edx
         // 00401434: mov ebp, eax
         // 00401436: mov ds:[ebx+0x4], 0x100000
         // 0040143d: push 0x4
         // 0040143f: push 0x2000
         // 00401444: push 0x100000
         // 00401449: push ebp
         // 0040144a: call VirtualAlloc
         // 0040144f: mov edi, eax
         // 00401451: mov ds:[ebx], edi
         // 00401453: test edi, edi
         // 00401455: jnz 0x401476
      [-]81c6????????81e6????????8973046a0468????????5655e880fdffff8903
         // 00401457: add esi, 0xffff
         // 0040145d: and esi, 0xffffffffffff0000
         // 00401463: mov ds:[ebx+0x4], esi
         // 00401466: push 0x4
         // 00401468: push 0x2000
         // 0040146d: push esi
         // 0040146e: push ebp
         // 0040146f: call VirtualAlloc
         // 00401474: mov ds:[ebx], eax
      [-]833b007423
         // 00401476: cmp ds:[ebx], 0x0
         // 00401479: jz 0x40149e
      [-]8bd3b8????????e8f5fdffff84c07513
         // 0040147b: mov edx, ebx
         // 0040147d: mov eax, 0x40d444
         // 00401482: call 0x40127c
         // 00401487: test b1 al, b1 al
         // 00401489: jnz 0x40149e
      [-]68????????6a008b0350e862fdffff33c08903
         // 0040148b: push 0x8000
         // 00401490: push 0x0
         // 00401492: mov eax, ds:[ebx]
         // 00401494: push eax
         // 00401495: call VirtualFree
         // 0040149a: xor eax, eax
         // 0040149c: mov ds:[ebx], eax
      [-]5d5f5e5bc3
         // 0040149e: pop ebp
         // 0040149f: pop edi
         // 004014a0: pop esi
         // 004014a1: pop ebx
         // 004014a2: retn 
      [-]5356575583c4ec894c2404891424c7442408????????33d28954240c8be88b042403c5894424108b1d????????eb51
         // 004014a4: push ebx
         // 004014a5: push esi
         // 004014a6: push edi
         // 004014a7: push ebp
         // 004014a8: add esp, 0xffffffffffffffec
         // 004014ab: mov ss:[esp+0x4], ecx
         // 004014af: mov ss:[esp], edx
         // 004014b2: mov ss:[esp+0x8], 0xffffffffffffffff
         // 004014ba: xor edx, edx
         // 004014bc: mov ss:[esp+0xc], edx
         // 004014c0: mov ebp, eax
         // 004014c2: mov eax, ss:[esp]
         // 004014c5: add eax, ebp
         // 004014c7: mov ss:[esp+0x10], eax
         // 004014cb: mov ebx, ds:[0x40d444]
         // 004014d1: jmp 0x401524
      [-]8b3b8b73083bee7746
         // 004014d3: mov edi, ds:[ebx]
         // 004014d5: mov esi, ds:[ebx+0x8]
         // 004014d8: cmp ebp, esi
         // 004014da: ja 0x401522
      [-]8bc603430c3b442410773b
         // 004014dc: mov eax, esi
         // 004014de: add eax, ds:[ebx+0xc]
         // 004014e1: cmp eax, ss:[esp+0x10]
         // 004014e5: ja 0x401522
      [-]3b7424087304
         // 004014e7: cmp esi, ss:[esp+0x8]
         // 004014eb: jnb 0x4014f1
      [-]89742408
         // 004014ed: mov ss:[esp+0x8], esi
      [-]8bc603430c3b44240c7604
         // 004014f1: mov eax, esi
         // 004014f3: add eax, ds:[ebx+0xc]
         // 004014f6: cmp eax, ss:[esp+0xc]
         // 004014fa: jbe 0x401500
      [-]8944240c
         // 004014fc: mov ss:[esp+0xc], eax
      [-]68????????6a0056e8effcffff85c0750a
         // 00401500: push 0x8000
         // 00401505: push 0x0
         // 00401507: push esi
         // 00401508: call VirtualFree
         // 0040150d: test eax, eax
         // 0040150f: jnz 0x40151b
      [-]c705????????????????
         // 00401511: mov ds:[0x40d420], 0x1
      [-]8bc3e88afdffff
         // 0040151b: mov eax, ebx
         // 0040151d: call 0x4012ac
      [-]81fb????????75a7
         // 00401524: cmp ebx, 0x40d444
         // 0040152a: jnz 0x4014d3
      [-]8b44240433d28910837c240c007419
         // 0040152c: mov eax, ss:[esp+0x4]
         // 00401530: xor edx, edx
         // 00401532: mov ds:[eax], edx
         // 00401534: cmp ss:[esp+0xc], 0x0
         // 00401539: jz 0x401554
      [-]8b4424048b54240889108b44240c2b4424088b542404894204
         // 0040153b: mov eax, ss:[esp+0x4]
         // 0040153f: mov edx, ss:[esp+0x8]
         // 00401543: mov ds:[eax], edx
         // 00401545: mov eax, ss:[esp+0xc]
         // 00401549: sub eax, ss:[esp+0x8]
         // 0040154d: mov edx, ss:[esp+0x4]
         // 00401551: mov ds:[edx+0x4], eax
      [-]83c4145d5f5e5bc3
         // 00401554: add esp, 0x14
         // 00401557: pop ebp
         // 00401558: pop edi
         // 00401559: pop esi
         // 0040155a: pop ebx
         // 0040155b: retn 
      [-]5356575583c4f4894c24048914248bd08bea81e5????????03142481c2????????81e2????????895424088b44240489288b4424082bc58b5424048942048b35????????eb3c
         // 0040155c: push ebx
         // 0040155d: push esi
         // 0040155e: push edi
         // 0040155f: push ebp
         // 00401560: add esp, 0xfffffffffffffff4
         // 00401563: mov ss:[esp+0x4], ecx
         // 00401567: mov ss:[esp], edx
         // 0040156a: mov edx, eax
         // 0040156c: mov ebp, edx
         // 0040156e: and ebp, 0xfffffffffffff000
         // 00401574: add edx, ss:[esp]
         // 00401577: add edx, 0xfff
         // 0040157d: and edx, 0xfffffffffffff000
         // 00401583: mov ss:[esp+0x8], edx
         // 00401587: mov eax, ss:[esp+0x4]
         // 0040158b: mov ds:[eax], ebp
         // 0040158d: mov eax, ss:[esp+0x8]
         // 00401591: sub eax, ebp
         // 00401593: mov edx, ss:[esp+0x4]
         // 00401597: mov ds:[edx+0x4], eax
         // 0040159a: mov esi, ds:[0x40d444]
         // 004015a0: jmp 0x4015de
      [-]8b5e088b7e0c03fb3beb7602
         // 004015a2: mov ebx, ds:[esi+0x8]
         // 004015a5: mov edi, ds:[esi+0xc]
         // 004015a8: add edi, ebx
         // 004015aa: cmp ebp, ebx
         // 004015ac: jbe 0x4015b0
      [-]3b7c24087604
         // 004015b0: cmp edi, ss:[esp+0x8]
         // 004015b4: jbe 0x4015ba
      [-]8b7c2408
         // 004015b6: mov edi, ss:[esp+0x8]
      [-]3bfb761e
         // 004015ba: cmp edi, ebx
         // 004015bc: jbe 0x4015dc
      [-]6a0468????????2bfb5753e826fcffff85c0750a
         // 004015be: push 0x4
         // 004015c0: push 0x1000
         // 004015c5: sub edi, ebx
         // 004015c7: push edi
         // 004015c8: push ebx
         // 004015c9: call VirtualAlloc
         // 004015ce: test eax, eax
         // 004015d0: jnz 0x4015dc
      [-]8b44240433d28910eb0a
         // 004015d2: mov eax, ss:[esp+0x4]
         // 004015d6: xor edx, edx
         // 004015d8: mov ds:[eax], edx
         // 004015da: jmp 0x4015e6
      [-]81fe????????75bc
         // 004015de: cmp esi, 0x40d444
         // 004015e4: jnz 0x4015a2
      [-]83c40c5d5f5e5bc3
         // 004015e6: add esp, 0xc
         // 004015e9: pop ebp
         // 004015ea: pop edi
         // 004015eb: pop esi
         // 004015ec: pop ebx
         // 004015ed: retn 
      [-]53565755518bd88bf381c6????????81e6????????8934248beb03ea81e5????????8b042489018bc52b04248941048b35????????eb38
         // 004015f0: push ebx
         // 004015f1: push esi
         // 004015f2: push edi
         // 004015f3: push ebp
         // 004015f4: push ecx
         // 004015f5: mov ebx, eax
         // 004015f7: mov esi, ebx
         // 004015f9: add esi, 0xfff
         // 004015ff: and esi, 0xfffffffffffff000
         // 00401605: mov ss:[esp], esi
         // 00401608: mov ebp, ebx
         // 0040160a: add ebp, edx
         // 0040160c: and ebp, 0xfffffffffffff000
         // 00401612: mov eax, ss:[esp]
         // 00401615: mov ds:[ecx], eax
         // 00401617: mov eax, ebp
         // 00401619: sub eax, ss:[esp]
         // 0040161c: mov ds:[ecx+0x4], eax
         // 0040161f: mov esi, ds:[0x40d444]
         // 00401625: jmp 0x40165f
      [-]8b5e088b7e0c03fb3b1c247303
         // 00401627: mov ebx, ds:[esi+0x8]
         // 0040162a: mov edi, ds:[esi+0xc]
         // 0040162d: add edi, ebx
         // 0040162f: cmp ebx, ss:[esp]
         // 00401632: jnb 0x401637
      [-]3bef7302
         // 00401637: cmp ebp, edi
         // 00401639: jnb 0x40163d
      [-]3bfb761c
         // 0040163d: cmp edi, ebx
         // 0040163f: jbe 0x40165d
      [-]68????????2bfb5753e8adfbffff85c0750a
         // 00401641: push 0x4000
         // 00401646: sub edi, ebx
         // 00401648: push edi
         // 00401649: push ebx
         // 0040164a: call VirtualFree
         // 0040164f: test eax, eax
         // 00401651: jnz 0x40165d
      [-]c705????????????????
         // 00401653: mov ds:[0x40d420], 0x2
      [-]81fe????????75c0
         // 0040165f: cmp esi, 0x40d444
         // 00401665: jnz 0x401627
      [-]5a5d5f5e5bc3
         // 00401667: pop edx
         // 00401668: pop ebp
         // 00401669: pop edi
         // 0040166a: pop esi
         // 0040166b: pop ebx
         // 0040166c: retn 
      [-]5356575583c4f88bf28bf8bd????????81c7????????81e7????????
         // 00401670: push ebx
         // 00401671: push esi
         // 00401672: push edi
         // 00401673: push ebp
         // 00401674: add esp, 0xfffffffffffffff8
         // 00401677: mov esi, edx
         // 00401679: mov edi, eax
         // 0040167b: mov ebp, 0x40d454
         // 00401680: add edi, 0x3fff
         // 00401686: and edi, 0xffffffffffffc000
      [-]8b5d00eb33
         // 0040168c: mov ebx, ss:[ebp+0x0]
         // 0040168f: jmp 0x4016c4
      [-]3b7b0c7f2c
         // 00401691: cmp edi, ds:[ebx+0xc]
         // 00401694: jg 0x4016c2
      [-]8bce8bd78b4308e8bafeffff833e007450
         // 00401696: mov ecx, esi
         // 00401698: mov edx, edi
         // 0040169a: mov eax, ds:[ebx+0x8]
         // 0040169d: call 0x40155c
         // 004016a2: cmp ds:[esi], 0x0
         // 004016a5: jz 0x4016f7
      [-]8b46040143088b460429430c837b0c00753e
         // 004016a7: mov eax, ds:[esi+0x4]
         // 004016aa: add ds:[ebx+0x8], eax
         // 004016ad: mov eax, ds:[esi+0x4]
         // 004016b0: sub ds:[ebx+0xc], eax
         // 004016b3: cmp ds:[ebx+0xc], 0x0
         // 004016b7: jnz 0x4016f7
      [-]8bc3e8ecfbffffeb35
         // 004016b9: mov eax, ebx
         // 004016bb: call 0x4012ac
         // 004016c0: jmp 0x4016f7
      [-]3bdd75c9
         // 004016c4: cmp ebx, ebp
         // 004016c6: jnz 0x401691
      [-]8bd68bc7e8f7fcffff833e007421
         // 004016c8: mov edx, esi
         // 004016ca: mov eax, edi
         // 004016cc: call 0x4013c8
         // 004016d1: cmp ds:[esi], 0x0
         // 004016d4: jz 0x4016f7
      [-]8bcc8bd68bc5e8e3fbffff833c240075a5
         // 004016d6: mov ecx, esp
         // 004016d8: mov edx, esi
         // 004016da: mov eax, ebp
         // 004016dc: call 0x4012c4
         // 004016e1: cmp ss:[esp], 0x0
         // 004016e5: jnz 0x40168c
      [-]8bcc8b56048b06e8b1fdffff33c08906
         // 004016e7: mov ecx, esp
         // 004016e9: mov edx, ds:[esi+0x4]
         // 004016ec: mov eax, ds:[esi]
         // 004016ee: call 0x4014a4
         // 004016f3: xor eax, eax
         // 004016f5: mov ds:[esi], eax
      [-]595a5d5f5e5bc3
         // 004016f7: pop ecx
         // 004016f8: pop edx
         // 004016f9: pop ebp
         // 004016fa: pop edi
         // 004016fb: pop esi
         // 004016fc: pop ebx
         // 004016fd: retn 
      [-]5356575583c4ec890c248bfa8bf0bd????????81c7????????81e7????????
         // 00401700: push ebx
         // 00401701: push esi
         // 00401702: push edi
         // 00401703: push ebp
         // 00401704: add esp, 0xffffffffffffffec
         // 00401707: mov ss:[esp], ecx
         // 0040170a: mov edi, edx
         // 0040170c: mov esi, eax
         // 0040170e: mov ebp, 0x40d454
         // 00401713: add edi, 0x3fff
         // 00401719: and edi, 0xffffffffffffc000
      [-]8b5d00eb02
         // 0040171f: mov ebx, ss:[ebp+0x0]
         // 00401722: jmp 0x401726
      [-]3bdd7405
         // 00401726: cmp ebx, ebp
         // 00401728: jz 0x40172f
      [-]3b730875f5
         // 0040172a: cmp esi, ds:[ebx+0x8]
         // 0040172d: jnz 0x401724
      [-]3b73087557
         // 0040172f: cmp esi, ds:[ebx+0x8]
         // 00401732: jnz 0x40178b
      [-]3b7b0c0f8e96000000
         // 00401734: cmp edi, ds:[ebx+0xc]
         // 00401737: jle 0x4017d3
      [-]8d4c24048bd72b530c8b430803430ce8dbfcffff837c2404007433
         // 0040173d: lea ecx, ss:[esp+0x4]
         // 00401741: mov edx, edi
         // 00401743: sub edx, ds:[ebx+0xc]
         // 00401746: mov eax, ds:[ebx+0x8]
         // 00401749: add eax, ds:[ebx+0xc]
         // 0040174c: call 0x40142c
         // 00401751: cmp ss:[esp+0x4], 0x0
         // 00401756: jz 0x40178b
      [-]8d4c240c8d5424048bc5e85dfbffff837c240c0075b1
         // 00401758: lea ecx, ss:[esp+0xc]
         // 0040175c: lea edx, ss:[esp+0x4]
         // 00401760: mov eax, ebp
         // 00401762: call 0x4012c4
         // 00401767: cmp ss:[esp+0xc], 0x0
         // 0040176c: jnz 0x40171f
      [-]8d4c240c8b5424088b442404e825fdffff8b042433d28910e990000000
         // 0040176e: lea ecx, ss:[esp+0xc]
         // 00401772: mov edx, ss:[esp+0x8]
         // 00401776: mov eax, ss:[esp+0x4]
         // 0040177a: call 0x4014a4
         // 0040177f: mov eax, ss:[esp]
         // 00401782: xor edx, edx
         // 00401784: mov ds:[eax], edx
         // 00401786: jmp 0x40181b
      [-]8d4c24048bd78bc6e894fcffff837c2404007434
         // 0040178b: lea ecx, ss:[esp+0x4]
         // 0040178f: mov edx, edi
         // 00401791: mov eax, esi
         // 00401793: call 0x40142c
         // 00401798: cmp ss:[esp+0x4], 0x0
         // 0040179d: jz 0x4017d3
      [-]8d4c240c8d5424048bc5e816fbffff837c240c000f8566ffffff
         // 0040179f: lea ecx, ss:[esp+0xc]
         // 004017a3: lea edx, ss:[esp+0x4]
         // 004017a7: mov eax, ebp
         // 004017a9: call 0x4012c4
         // 004017ae: cmp ss:[esp+0xc], 0x0
         // 004017b3: jnz 0x40171f
      [-]8d4c240c8b5424088b442404e8dafcffff8b042433d28910eb48
         // 004017b9: lea ecx, ss:[esp+0xc]
         // 004017bd: mov edx, ss:[esp+0x8]
         // 004017c1: mov eax, ss:[esp+0x4]
         // 004017c5: call 0x4014a4
         // 004017ca: mov eax, ss:[esp]
         // 004017cd: xor edx, edx
         // 004017cf: mov ds:[eax], edx
         // 004017d1: jmp 0x40181b
      [-]8b6b083bf5753a
         // 004017d3: mov ebp, ds:[ebx+0x8]
         // 004017d6: cmp esi, ebp
         // 004017d8: jnz 0x401814
      [-]3b7b0c7f35
         // 004017da: cmp edi, ds:[ebx+0xc]
         // 004017dd: jg 0x401814
      [-]8b0c248bd78bc5e871fdffff8b04248338007428
         // 004017df: mov ecx, ss:[esp]
         // 004017e2: mov edx, edi
         // 004017e4: mov eax, ebp
         // 004017e6: call 0x40155c
         // 004017eb: mov eax, ss:[esp]
         // 004017ee: cmp ds:[eax], 0x0
         // 004017f1: jz 0x40181b
      [-]8b04248b40040143088b04248b400429430c837b0c007510
         // 004017f3: mov eax, ss:[esp]
         // 004017f6: mov eax, ds:[eax+0x4]
         // 004017f9: add ds:[ebx+0x8], eax
         // 004017fc: mov eax, ss:[esp]
         // 004017ff: mov eax, ds:[eax+0x4]
         // 00401802: sub ds:[ebx+0xc], eax
         // 00401805: cmp ds:[ebx+0xc], 0x0
         // 00401809: jnz 0x40181b
      [-]8bc3e89afaffffeb07
         // 0040180b: mov eax, ebx
         // 0040180d: call 0x4012ac
         // 00401812: jmp 0x40181b
      [-]8b042433d28910
         // 00401814: mov eax, ss:[esp]
         // 00401817: xor edx, edx
         // 00401819: mov ds:[eax], edx
      [-]83c4145d5f5e5bc3
         // 0040181b: add esp, 0x14
         // 0040181e: pop ebp
         // 0040181f: pop edi
         // 00401820: pop esi
         // 00401821: pop ebx
         // 00401822: retn 
      [-]53565783c4ec8bf98914248d98????????81e3????????8b342403f081e6????????3bde735b
         // 00401824: push ebx
         // 00401825: push esi
         // 00401826: push edi
         // 00401827: add esp, 0xffffffffffffffec
         // 0040182a: mov edi, ecx
         // 0040182c: mov ss:[esp], edx
         // 0040182f: lea ebx, ds:[eax+0x3fff]
         // 00401835: and ebx, 0xffffffffffffc000
         // 0040183b: mov esi, ss:[esp]
         // 0040183e: add esi, eax
         // 00401840: and esi, 0xffffffffffffc000
         // 00401846: cmp ebx, esi
         // 00401848: jnb 0x4018a5
      [-]8bcf8bd62bd38bc3e899fdffff8d4c24048bd7b8????????e85dfaffff8b5c240485db741f
         // 0040184a: mov ecx, edi
         // 0040184c: mov edx, esi
         // 0040184e: sub edx, ebx
         // 00401850: mov eax, ebx
         // 00401852: call 0x4015f0
         // 00401857: lea ecx, ss:[esp+0x4]
         // 0040185b: mov edx, edi
         // 0040185d: mov eax, 0x40d454
         // 00401862: call 0x4012c4
         // 00401867: mov ebx, ss:[esp+0x4]
         // 0040186b: test ebx, ebx
         // 0040186d: jz 0x40188e
      [-]8d4c240c8b5424088bc3e826fcffff8b44240c894424048b44241089442408
         // 0040186f: lea ecx, ss:[esp+0xc]
         // 00401873: mov edx, ss:[esp+0x8]
         // 00401877: mov eax, ebx
         // 00401879: call 0x4014a4
         // 0040187e: mov eax, ss:[esp+0xc]
         // 00401882: mov ss:[esp+0x4], eax
         // 00401886: mov eax, ss:[esp+0x10]
         // 0040188a: mov ss:[esp+0x8], eax
      [-]837c2404007414
         // 0040188e: cmp ss:[esp+0x4], 0x0
         // 00401893: jz 0x4018a9
      [-]8d542404b8????????e895faffffeb04
         // 00401895: lea edx, ss:[esp+0x4]
         // 00401899: mov eax, 0x40d454
         // 0040189e: call 0x401338
         // 004018a3: jmp 0x4018a9
      [-]33c08907
         // 004018a5: xor eax, eax
         // 004018a7: mov ds:[edi], eax
      [-]83c4145f5e5bc3
         // 004018a9: add esp, 0x14
         // 004018ac: pop edi
         // 004018ad: pop esi
         // 004018ae: pop ebx
         // 004018af: retn 
      [-]558bec33d25568????????64ff326489226824d44000e839f9ffff803d35d0400000740a
         // 004018b0: push ebp
         // 004018b1: mov ebp, esp
         // 004018b3: xor edx, edx
         // 004018b5: push ebp
         // 004018b6: push 0x401966
         // 004018bb: push fs:[edx]
         // 004018be: mov fs:[edx], esp
         // 004018c1: push CriticalSection.DebugInfo
         // 004018c6: call InitializeCriticalSection
         // 004018cb: cmp b1 ds:[0x40d035], b1 0x0
         // 004018d2: jz 0x4018de
      [-]6824d44000e82ef9ffff
         // 004018d4: push CriticalSection.DebugInfo
         // 004018d9: call EnterCriticalSection
      [-]b8????????e88cf9ffffb8????????e882f9ffffb8????????e878f9ffff68????????6a00e8dcf8ffffa3????????833d????????00742f
         // 004018de: mov eax, 0x40d444
         // 004018e3: call 0x401274
         // 004018e8: mov eax, 0x40d454
         // 004018ed: call 0x401274
         // 004018f2: mov eax, 0x40d480
         // 004018f7: call 0x401274
         // 004018fc: push 0xff8
         // 00401901: push 0x0
         // 00401903: call LocalAlloc
         // 00401908: mov ds:[0x40d47c], eax
         // 0040190d: cmp ds:[0x40d47c], 0x0
         // 00401914: jz 0x401945
      [-]b8????????
         // 00401916: mov eax, 0x3
      [-]8b15????????33c9894c82f4403d????????75ec
         // 0040191b: mov edx, ds:[0x40d47c]
         // 00401921: xor ecx, ecx
         // 00401923: mov ds:[edx+eax*0x4], ecx
         // 00401927: inc eax
         // 00401928: cmp eax, 0x401
         // 0040192d: jnz 0x40191b
      [-]b8????????8940048900a3????????c6051cd4400001
         // 0040192f: mov eax, 0x40d464
         // 00401934: mov ds:[eax+0x4], eax
         // 00401937: mov ds:[eax], eax
         // 00401939: mov ds:[0x40d470], eax
         // 0040193e: mov b1 ds:[0x40d41c], b1 0x1
      [-]33c05a595964891068????????803d35d0400000740a
         // 00401945: xor eax, eax
         // 00401947: pop edx
         // 00401948: pop ecx
         // 00401949: pop ecx
         // 0040194a: mov fs:[eax], edx
         // 0040194d: push 0x40196d
         // 00401952: cmp b1 ds:[0x40d035], b1 0x0
         // 00401959: jz 0x401965
      [-]6824d44000e8aff8ffff
         // 0040195b: push CriticalSection.DebugInfo
         // 00401960: call LeaveCriticalSection
      [-]a01cd440005dc3
         // 0040196d: mov b1 al, b1 ds:[0x40d41c]
         // 00401972: pop ebp
         // 00401973: retn 
      [-]558bec53803d1cd44000000f84cc000000
         // 00401974: push ebp
         // 00401975: mov ebp, esp
         // 00401977: push ebx
         // 00401978: cmp b1 ds:[0x40d41c], b1 0x0
         // 0040197f: jz 0x401a51
      [-]33d25568????????64ff32648922803d35d0400000740a
         // 00401985: xor edx, edx
         // 00401987: push ebp
         // 00401988: push 0x401a4a
         // 0040198d: push fs:[edx]
         // 00401990: mov fs:[edx], esp
         // 00401993: cmp b1 ds:[0x40d035], b1 0x0
         // 0040199a: jz 0x4019a6
      [-]6824d44000e866f8ffff
         // 0040199c: push CriticalSection.DebugInfo
         // 004019a1: call EnterCriticalSection
      [-]c6051cd4400000a1????????50e834f8ffff33c0a3????????8b1d????????eb12
         // 004019a6: mov b1 ds:[0x40d41c], b1 0x0
         // 004019ad: mov eax, ds:[0x40d47c]
         // 004019b2: push eax
         // 004019b3: call LocalFree
         // 004019b8: xor eax, eax
         // 004019ba: mov ds:[0x40d47c], eax
         // 004019bf: mov ebx, ds:[0x40d444]
         // 004019c5: jmp 0x4019d9
      [-]68????????6a008b430850e825f8ffff8b1b
         // 004019c7: push 0x8000
         // 004019cc: push 0x0
         // 004019ce: mov eax, ds:[ebx+0x8]
         // 004019d1: push eax
         // 004019d2: call VirtualFree
         // 004019d7: mov ebx, ds:[ebx]
      [-]81fb????????75e6
         // 004019d9: cmp ebx, 0x40d444
         // 004019df: jnz 0x4019c7
      [-]b8????????e889f8ffffb8????????e87ff8ffffb8????????e875f8ffffa1????????85c07417
         // 004019e1: mov eax, 0x40d444
         // 004019e6: call 0x401274
         // 004019eb: mov eax, 0x40d454
         // 004019f0: call 0x401274
         // 004019f5: mov eax, 0x40d480
         // 004019fa: call 0x401274
         // 004019ff: mov eax, ds:[0x40d43c]
         // 00401a04: test eax, eax
         // 00401a06: jz 0x401a1f
      [-]8b108915????????50e8d6f7ffffa1????????85c075e9
         // 00401a08: mov edx, ds:[eax]
         // 00401a0a: mov ds:[0x40d43c], edx
         // 00401a10: push eax
         // 00401a11: call LocalFree
         // 00401a16: mov eax, ds:[0x40d43c]
         // 00401a1b: test eax, eax
         // 00401a1d: jnz 0x401a08
      [-]33c05a595964891068????????803d35d0400000740a
         // 00401a1f: xor eax, eax
         // 00401a21: pop edx
         // 00401a22: pop ecx
         // 00401a23: pop ecx
         // 00401a24: mov fs:[eax], edx
         // 00401a27: push 0x401a51
         // 00401a2c: cmp b1 ds:[0x40d035], b1 0x0
         // 00401a33: jz 0x401a3f
      [-]6824d44000e8d5f7ffff
         // 00401a35: push CriticalSection.DebugInfo
         // 00401a3a: call LeaveCriticalSection
      [-]6824d44000e8d3f7ffffc3
         // 00401a3f: push CriticalSection.DebugInfo
         // 00401a44: call DeleteCriticalSection
         // 00401a49: retn 
      [-]533b05????????7509
         // 00401a54: push ebx
         // 00401a55: cmp eax, ds:[0x40d470]
         // 00401a5b: jnz 0x401a66
      [-]8b50048915????????
         // 00401a5d: mov edx, ds:[eax+0x4]
         // 00401a60: mov ds:[0x40d470], edx
      [-]8b50048b480881f9????????7f38
         // 00401a66: mov edx, ds:[eax+0x4]
         // 00401a69: mov ecx, ds:[eax+0x8]
         // 00401a6c: cmp ecx, 0x1000
         // 00401a72: jg 0x401aac
      [-]3bc27517
         // 00401a74: cmp eax, edx
         // 00401a76: jnz 0x401a8f
      [-]85c97903
         // 00401a78: test ecx, ecx
         // 00401a7a: jns 0x401a7f
      [-]c1f902a1????????33d2895488f4eb24
         // 00401a7f: sar ecx, b1 0x2
         // 00401a82: mov eax, ds:[0x40d47c]
         // 00401a87: xor edx, edx
         // 00401a89: mov ds:[eax+ecx*0x4], edx
         // 00401a8d: jmp 0x401ab3
      [-]85c97903
         // 00401a8f: test ecx, ecx
         // 00401a91: jns 0x401a96
      [-]c1f9028b1d????????89548bf48b0089028950045bc3
         // 00401a96: sar ecx, b1 0x2
         // 00401a99: mov ebx, ds:[0x40d47c]
         // 00401a9f: mov ds:[ebx+ecx*0x4], edx
         // 00401aa3: mov eax, ds:[eax]
         // 00401aa5: mov ds:[edx], eax
         // 00401aa7: mov ds:[eax+0x4], edx
         // 00401aaa: pop ebx
         // 00401aab: retn 
      [-]8b008902895004
         // 00401aac: mov eax, ds:[eax]
         // 00401aae: mov ds:[edx], eax
         // 00401ab0: mov ds:[eax+0x4], edx
      [-]8b15????????eb10
         // 00401ab8: mov edx, ds:[0x40d480]
         // 00401abe: jmp 0x401ad0
      [-]8b4a083bc17207
         // 00401ac0: mov ecx, ds:[edx+0x8]
         // 00401ac3: cmp eax, ecx
         // 00401ac5: jb 0x401ace
      [-]034a0c3bc17216
         // 00401ac7: add ecx, ds:[edx+0xc]
         // 00401aca: cmp eax, ecx
         // 00401acc: jb 0x401ae4
      [-]81fa????????75e8
         // 00401ad0: cmp edx, 0x40d480
         // 00401ad6: jnz 0x401ac0
      [-]c705????????????????33d2
         // 00401ad8: mov ds:[0x40d420], 0x3
         // 00401ae2: xor edx, edx
      [-]538bca83e9048d1c0183fa107c0f
         // 00401ae8: push ebx
         // 00401ae9: mov ecx, edx
         // 00401aeb: sub ecx, 0x4
         // 00401aee: lea ebx, ds:[ecx+eax]
         // 00401af1: cmp edx, 0x10
         // 00401af4: jl 0x401b05
      [-]c703????????8bd1e8a10100005bc3
         // 00401af6: mov ds:[ebx], 0xffffffff80000007
         // 00401afc: mov edx, ecx
         // 00401afe: call 0x401ca4
         // 00401b03: pop ebx
         // 00401b04: retn 
      [-]83fa047c0c
         // 00401b05: cmp edx, 0x4
         // 00401b08: jl 0x401b16
      [-]8bca81c9????????8908890b
         // 00401b0a: mov ecx, edx
         // 00401b0c: or ecx, 0xffffffff80000002
         // 00401b12: mov ds:[eax], ecx
         // 00401b14: mov ds:[ebx], ecx
      [-]ff05????????8bd083ea048b1281e2????????83ea040115????????e8d3050000c3
         // 00401b18: inc ds:[0x40d410]
         // 00401b1e: mov edx, eax
         // 00401b20: sub edx, 0x4
         // 00401b23: mov edx, ds:[edx]
         // 00401b25: and edx, 0x7ffffffc
         // 00401b2b: sub edx, 0x4
         // 00401b2e: add ds:[0x40d414], edx
         // 00401b34: call 0x40210c
         // 00401b39: retn 
      [-]83fa0c7c0e
         // 00401b3c: cmp edx, 0xc
         // 00401b3f: jl 0x401b4f
      [-]83ca02891083c004e8caffffffc3
         // 00401b41: or edx, 0x2
         // 00401b44: mov ds:[eax], edx
         // 00401b46: add eax, 0x4
         // 00401b49: call 0x401b18
         // 00401b4e: retn 
      [-]83fa047c0a
         // 00401b4f: cmp edx, 0x4
         // 00401b52: jl 0x401b5e
      [-]8bca81c9????????8908
         // 00401b54: mov ecx, edx
         // 00401b56: or ecx, 0xffffffff80000002
         // 00401b5c: mov ds:[eax], ecx
      [-]03c28320fec3
         // 00401b5e: add eax, edx
         // 00401b60: and ds:[eax], 0xfffffffffffffffe
         // 00401b63: retn 
      [-]53568bd083ea048b128bca81e1????????81f9????????740a
         // 00401b64: push ebx
         // 00401b65: push esi
         // 00401b66: mov edx, eax
         // 00401b68: sub edx, 0x4
         // 00401b6b: mov edx, ds:[edx]
         // 00401b6d: mov ecx, edx
         // 00401b6f: and ecx, 0xffffffff80000002
         // 00401b75: cmp ecx, 0xffffffff80000002
         // 00401b7b: jz 0x401b87
      [-]c705????????????????
         // 00401b7d: mov ds:[0x40d420], 0x4
      [-]8bda81e3????????2bc38bc83311f7c2????????740a
         // 00401b87: mov ebx, edx
         // 00401b89: and ebx, 0x7ffffffc
         // 00401b8f: sub eax, ebx
         // 00401b91: mov ecx, eax
         // 00401b93: xor edx, ds:[ecx]
         // 00401b95: test edx, 0xfffffffffffffffe
         // 00401b9b: jz 0x401ba7
      [-]c705????????????????
         // 00401b9d: mov ds:[0x40d420], 0x5
      [-]f601017420
         // 00401ba7: test b1 ds:[ecx], b1 0x1
         // 00401baa: jz 0x401bcc
      [-]8bd083ea0c8b72082bc63b7008740a
         // 00401bac: mov edx, eax
         // 00401bae: sub edx, 0xc
         // 00401bb1: mov esi, ds:[edx+0x8]
         // 00401bb4: sub eax, esi
         // 00401bb6: cmp esi, ds:[eax+0x8]
         // 00401bb9: jz 0x401bc5
      [-]c705????????????????
         // 00401bbb: mov ds:[0x40d420], 0x6
      [-]e88afeffff03de
         // 00401bc5: call 0x401a54
         // 00401bca: add ebx, esi
      [-]8bc35e5bc3
         // 00401bcc: mov eax, ebx
         // 00401bce: pop esi
         // 00401bcf: pop ebx
         // 00401bd0: retn 
      [-]5356578bd833ff8b03a9????????740b
         // 00401bd4: push ebx
         // 00401bd5: push esi
         // 00401bd6: push edi
         // 00401bd7: mov ebx, eax
         // 00401bd9: xor edi, edi
         // 00401bdb: mov eax, ds:[ebx]
         // 00401bdd: test eax, 0xffffffff80000000
         // 00401be2: jz 0x401bef
      [-]25????????03f803d88b03
         // 00401be4: and eax, 0x7ffffffc
         // 00401be9: add edi, eax
         // 00401beb: add ebx, eax
         // 00401bed: mov eax, ds:[ebx]
      [-]a8027513
         // 00401bef: test b1 al, b1 0x2
         // 00401bf1: jnz 0x401c06
      [-]8bf38bc6e858feffff8b460803f803d88323fe
         // 00401bf3: mov esi, ebx
         // 00401bf5: mov eax, esi
         // 00401bf7: call 0x401a54
         // 00401bfc: mov eax, ds:[esi+0x8]
         // 00401bff: add edi, eax
         // 00401c01: add ebx, eax
         // 00401c03: and ds:[ebx], 0xfffffffffffffffe
      [-]8bc75f5e5bc3
         // 00401c06: mov eax, edi
         // 00401c08: pop edi
         // 00401c09: pop esi
         // 00401c0a: pop ebx
         // 00401c0b: retn 
      [-]5356575583c4f88bfa8bf08bc6e89afeffff8bd88b6b088bc503430c8bd08d0c372bd183fa0c7f04
         // 00401c0c: push ebx
         // 00401c0d: push esi
         // 00401c0e: push edi
         // 00401c0f: push ebp
         // 00401c10: add esp, 0xfffffffffffffff8
         // 00401c13: mov edi, edx
         // 00401c15: mov esi, eax
         // 00401c17: mov eax, esi
         // 00401c19: call 0x401ab8
         // 00401c1e: mov ebx, eax
         // 00401c20: mov ebp, ds:[ebx+0x8]
         // 00401c23: mov eax, ebp
         // 00401c25: add eax, ds:[ebx+0xc]
         // 00401c28: mov edx, eax
         // 00401c2a: lea ecx, ds:[edi+esi]
         // 00401c2d: sub edx, ecx
         // 00401c2f: cmp edx, 0xc
         // 00401c32: jg 0x401c38
      [-]8bf82bfe
         // 00401c34: mov edi, eax
         // 00401c36: sub edi, esi
      [-]8bc62bc583f80c7d12
         // 00401c38: mov eax, esi
         // 00401c3a: sub eax, ebp
         // 00401c3c: cmp eax, 0xc
         // 00401c3f: jge 0x401c53
      [-]8bcc8bd62b530803d78bc5e8d3fbffffeb0f
         // 00401c41: mov ecx, esp
         // 00401c43: mov edx, esi
         // 00401c45: sub edx, ds:[ebx+0x8]
         // 00401c48: add edx, edi
         // 00401c4a: mov eax, ebp
         // 00401c4c: call 0x401824
         // 00401c51: jmp 0x401c62
      [-]8bcc8bd783ea048d4604e8c2fbffff
         // 00401c53: mov ecx, esp
         // 00401c55: mov edx, edi
         // 00401c57: sub edx, 0x4
         // 00401c5a: lea eax, ds:[esi+0x4]
         // 00401c5d: call 0x401824
      [-]8b2c2485ed7504
         // 00401c62: mov ebp, ss:[esp]
         // 00401c65: test ebp, ebp
         // 00401c67: jnz 0x401c6d
      [-]33c0eb30
         // 00401c69: xor eax, eax
         // 00401c6b: jmp 0x401c9d
      [-]8bd52bd68bc6e870feffff8bc5034424048b530803530c3bc2730a
         // 00401c6d: mov edx, ebp
         // 00401c6f: sub edx, esi
         // 00401c71: mov eax, esi
         // 00401c73: call 0x401ae8
         // 00401c78: mov eax, ebp
         // 00401c7a: add eax, ss:[esp+0x4]
         // 00401c7e: mov edx, ds:[ebx+0x8]
         // 00401c81: add edx, ds:[ebx+0xc]
         // 00401c84: cmp eax, edx
         // 00401c86: jnb 0x401c92
      [-]8d14372bd0e8aafeffff
         // 00401c88: lea edx, ds:[edi+esi]
         // 00401c8b: sub edx, eax
         // 00401c8d: call 0x401b3c
      [-]8bd48bc3e89df6ffffb001
         // 00401c92: mov edx, esp
         // 00401c94: mov eax, ebx
         // 00401c96: call 0x401338
         // 00401c9b: mov b1 al, b1 0x1
      [-]595a5d5f5e5bc3
         // 00401c9d: pop ecx
         // 00401c9e: pop edx
         // 00401c9f: pop ebp
         // 00401ca0: pop edi
         // 00401ca1: pop esi
         // 00401ca2: pop ebx
         // 00401ca3: retn 
      [-]5356578bf28bf88bdf8973088bc303c683e80c89700881fe????????7f37
         // 00401ca4: push ebx
         // 00401ca5: push esi
         // 00401ca6: push edi
         // 00401ca7: mov esi, edx
         // 00401ca9: mov edi, eax
         // 00401cab: mov ebx, edi
         // 00401cad: mov ds:[ebx+0x8], esi
         // 00401cb0: mov eax, ebx
         // 00401cb2: add eax, esi
         // 00401cb4: sub eax, 0xc
         // 00401cb7: mov ds:[eax+0x8], esi
         // 00401cba: cmp esi, 0x1000
         // 00401cc0: jg 0x401cf9
      [-]8bd685d27903
         // 00401cc2: mov edx, esi
         // 00401cc4: test edx, edx
         // 00401cc6: jns 0x401ccb
      [-]c1fa02a1????????8b4490f485c07510
         // 00401ccb: sar edx, b1 0x2
         // 00401cce: mov eax, ds:[0x40d47c]
         // 00401cd3: mov eax, ds:[eax+edx*0x4]
         // 00401cd7: test eax, eax
         // 00401cd9: jnz 0x401ceb
      [-]a1????????895c90f4895b04891beb3a
         // 00401cdb: mov eax, ds:[0x40d47c]
         // 00401ce0: mov ds:[eax+edx*0x4], ebx
         // 00401ce4: mov ds:[ebx+0x4], ebx
         // 00401ce7: mov ds:[ebx], ebx
         // 00401ce9: jmp 0x401d25
      [-]8b1089430489138918895a04eb2c
         // 00401ceb: mov edx, ds:[eax]
         // 00401ced: mov ds:[ebx+0x4], eax
         // 00401cf0: mov ds:[ebx], edx
         // 00401cf2: mov ds:[eax], ebx
         // 00401cf4: mov ds:[edx+0x4], ebx
         // 00401cf7: jmp 0x401d25
      [-]81fe????????7c0d
         // 00401cf9: cmp esi, 0x3c00
         // 00401cff: jl 0x401d0e
      [-]8bd68bc7e802ffffff84c07517
         // 00401d01: mov edx, esi
         // 00401d03: mov eax, edi
         // 00401d05: call 0x401c0c
         // 00401d0a: test b1 al, b1 al
         // 00401d0c: jnz 0x401d25
      [-]a1????????891d????????8b1089430489138918895a04
         // 00401d0e: mov eax, ds:[0x40d470]
         // 00401d13: mov ds:[0x40d470], ebx
         // 00401d19: mov edx, ds:[eax]
         // 00401d1b: mov ds:[ebx+0x4], eax
         // 00401d1e: mov ds:[ebx], edx
         // 00401d20: mov ds:[eax], ebx
         // 00401d22: mov ds:[edx+0x4], ebx
      [-]5f5e5bc3
         // 00401d25: pop edi
         // 00401d26: pop esi
         // 00401d27: pop ebx
         // 00401d28: retn 
      [-]833d????????007e40
         // 00401d2c: cmp ds:[0x40d474], 0x0
         // 00401d33: jle 0x401d75
      [-]833d????????0c7d0c
         // 00401d35: cmp ds:[0x40d474], 0xc
         // 00401d3c: jge 0x401d4a
      [-]c705????????????????eb2b
         // 00401d3e: mov ds:[0x40d420], 0x7
         // 00401d48: jmp 0x401d75
      [-]a1????????83c8028b15????????8902a1????????83c004e8b1fdffff33c0a3????????33c0a3????????
         // 00401d4a: mov eax, ds:[0x40d474]
         // 00401d4f: or eax, 0x2
         // 00401d52: mov edx, ds:[0x40d478]
         // 00401d58: mov ds:[edx], eax
         // 00401d5a: mov eax, ds:[0x40d478]
         // 00401d5f: add eax, 0x4
         // 00401d62: call 0x401b18
         // 00401d67: xor eax, eax
         // 00401d69: mov ds:[0x40d478], eax
         // 00401d6e: xor eax, eax
         // 00401d70: mov ds:[0x40d474], eax
      [-]53565783c4f08bf08d3c24a5a58bfce8a0ffffff8d4c24088bd7b8????????e828f5ffff8b5c240885db7504
         // 00401d78: push ebx
         // 00401d79: push esi
         // 00401d7a: push edi
         // 00401d7b: add esp, 0xfffffffffffffff0
         // 00401d7e: mov esi, eax
         // 00401d80: lea edi, ss:[esp]
         // 00401d83: movsdd 
         // 00401d84: movsdd 
         // 00401d85: mov edi, esp
         // 00401d87: call 0x401d2c
         // 00401d8c: lea ecx, ss:[esp+0x8]
         // 00401d90: mov edx, edi
         // 00401d92: mov eax, 0x40d480
         // 00401d97: call 0x4012c4
         // 00401d9c: mov ebx, ss:[esp+0x8]
         // 00401da0: test ebx, ebx
         // 00401da2: jnz 0x401da8
      [-]33c0eb52
         // 00401da4: xor eax, eax
         // 00401da6: jmp 0x401dfa
      [-]8b073bd8730a
         // 00401da8: mov eax, ds:[edi]
         // 00401daa: cmp ebx, eax
         // 00401dac: jnb 0x401db8
      [-]e8b1fdffff2907014704
         // 00401dae: call 0x401b64
         // 00401db3: sub ds:[edi], eax
         // 00401db5: add ds:[edi+0x4], eax
      [-]8b070347048bf30374240c3bc67308
         // 00401db8: mov eax, ds:[edi]
         // 00401dba: add eax, ds:[edi+0x4]
         // 00401dbd: mov esi, ebx
         // 00401dbf: add esi, ss:[esp+0xc]
         // 00401dc3: cmp eax, esi
         // 00401dc5: jnb 0x401dcf
      [-]e808feffff014704
         // 00401dc7: call 0x401bd4
         // 00401dcc: add ds:[edi+0x4], eax
      [-]8b070347043bf07511
         // 00401dcf: mov eax, ds:[edi]
         // 00401dd1: add eax, ds:[edi+0x4]
         // 00401dd4: cmp esi, eax
         // 00401dd6: jnz 0x401de9
      [-]83e804ba????????e803fdffff836f0404
         // 00401dd8: sub eax, 0x4
         // 00401ddb: mov edx, 0x4
         // 00401de0: call 0x401ae8
         // 00401de5: sub ds:[edi+0x4], 0x4
      [-]8b07a3????????8b4704a3????????b001
         // 00401de9: mov eax, ds:[edi]
         // 00401deb: mov ds:[0x40d478], eax
         // 00401df0: mov eax, ds:[edi+0x4]
         // 00401df3: mov ds:[0x40d474], eax
         // 00401df8: mov b1 al, b1 0x1
      [-]83c4105f5e5bc3
         // 00401dfa: add esp, 0x10
         // 00401dfd: pop edi
         // 00401dfe: pop esi
         // 00401dff: pop ebx
         // 00401e00: retn 
      [-]5383c4f88bd88bd48d4304e85cf8ffff833c2400740b
         // 00401e04: push ebx
         // 00401e05: add esp, 0xfffffffffffffff8
         // 00401e08: mov ebx, eax
         // 00401e0a: mov edx, esp
         // 00401e0c: lea eax, ds:[ebx+0x4]
         // 00401e0f: call 0x401670
         // 00401e14: cmp ss:[esp], 0x0
         // 00401e18: jz 0x401e25
      [-]8bc4e857ffffff84c07504
         // 00401e1a: mov eax, esp
         // 00401e1c: call 0x401d78
         // 00401e21: test b1 al, b1 al
         // 00401e23: jnz 0x401e29
      [-]33c0eb02
         // 00401e25: xor eax, eax
         // 00401e27: jmp 0x401e2b
      [-]595a5bc3
         // 00401e2b: pop ecx
         // 00401e2c: pop edx
         // 00401e2d: pop ebx
         // 00401e2e: retn 
      [-]535683c4f88bf28bd88bcc8d56048bc3e8bbf8ffff833c2400740b
         // 00401e30: push ebx
         // 00401e31: push esi
         // 00401e32: add esp, 0xfffffffffffffff8
         // 00401e35: mov esi, edx
         // 00401e37: mov ebx, eax
         // 00401e39: mov ecx, esp
         // 00401e3b: lea edx, ds:[esi+0x4]
         // 00401e3e: mov eax, ebx
         // 00401e40: call 0x401700
         // 00401e45: cmp ss:[esp], 0x0
         // 00401e49: jz 0x401e56
      [-]8bc4e826ffffff84c07504
         // 00401e4b: mov eax, esp
         // 00401e4d: call 0x401d78
         // 00401e52: test b1 al, b1 al
         // 00401e54: jnz 0x401e5a
      [-]33c0eb02
         // 00401e56: xor eax, eax
         // 00401e58: jmp 0x401e5c
      [-]595a5e5bc3
         // 00401e5c: pop ecx
         // 00401e5d: pop edx
         // 00401e5e: pop esi
         // 00401e5f: pop ebx
         // 00401e60: retn 
      [-]33d285c07903
         // 00401e64: xor edx, edx
         // 00401e66: test eax, eax
         // 00401e68: jns 0x401e6d
      [-]c1f8023d????????7f16
         // 00401e6d: sar eax, b1 0x2
         // 00401e70: cmp eax, 0x400
         // 00401e75: jg 0x401e8d
      [-]8b15????????8b5482f485d27508
         // 00401e77: mov edx, ds:[0x40d47c]
         // 00401e7d: mov edx, ds:[edx+eax*0x4]
         // 00401e81: test edx, edx
         // 00401e83: jnz 0x401e8d
      [-]403d????????75ea
         // 00401e85: inc eax
         // 00401e86: cmp eax, 0x401
         // 00401e8b: jnz 0x401e77
      [-]535657558bf0bf????????bd????????
         // 00401e90: push ebx
         // 00401e91: push esi
         // 00401e92: push edi
         // 00401e93: push ebp
         // 00401e94: mov esi, eax
         // 00401e96: mov edi, 0x40d470
         // 00401e9b: mov ebp, 0x40d474
      [-]8b1d????????3b73080f8e84000000
         // 00401ea0: mov ebx, ds:[0x40d468]
         // 00401ea6: cmp esi, ds:[ebx+0x8]
         // 00401ea9: jle 0x401f33
      [-]8b1f8b43083bf07e7b
         // 00401eaf: mov ebx, ds:[edi]
         // 00401eb1: mov eax, ds:[ebx+0x8]
         // 00401eb4: cmp esi, eax
         // 00401eb6: jle 0x401f33
      [-]8b5b043b73087ff8
         // 00401ebb: mov ebx, ds:[ebx+0x4]
         // 00401ebe: cmp esi, ds:[ebx+0x8]
         // 00401ec1: jg 0x401ebb
      [-]8b178942083b1f7404
         // 00401ec3: mov edx, ds:[edi]
         // 00401ec5: mov ds:[edx+0x8], eax
         // 00401ec8: cmp ebx, ds:[edi]
         // 00401eca: jz 0x401ed0
      [-]891feb63
         // 00401ecc: mov ds:[edi], ebx
         // 00401ece: jmp 0x401f33
      [-]81fe????????7f0d
         // 00401ed0: cmp esi, 0x1000
         // 00401ed6: jg 0x401ee5
      [-]8bc6e885ffffff8bd885db754e
         // 00401ed8: mov eax, esi
         // 00401eda: call 0x401e64
         // 00401edf: mov ebx, eax
         // 00401ee1: test ebx, ebx
         // 00401ee3: jnz 0x401f33
      [-]8bc6e818ffffff84c07507
         // 00401ee5: mov eax, esi
         // 00401ee7: call 0x401e04
         // 00401eec: test b1 al, b1 al
         // 00401eee: jnz 0x401ef7
      [-]33c0e988000000
         // 00401ef0: xor eax, eax
         // 00401ef2: jmp 0x401f7f
      [-]3b75007fa4
         // 00401ef7: cmp esi, ss:[ebp+0x0]
         // 00401efa: jg 0x401ea0
      [-]297500837d000c7d08
         // 00401efc: sub ss:[ebp+0x0], esi
         // 00401eff: cmp ss:[ebp+0x0], 0xc
         // 00401f03: jge 0x401f0d
      [-]03750033c0894500
         // 00401f05: add esi, ss:[ebp+0x0]
         // 00401f08: xor eax, eax
         // 00401f0a: mov ss:[ebp+0x0], eax
      [-]a1????????0135????????8bd683ca02891083c004ff05????????83ee040135????????eb4c
         // 00401f0d: mov eax, ds:[0x40d478]
         // 00401f12: add ds:[0x40d478], esi
         // 00401f18: mov edx, esi
         // 00401f1a: or edx, 0x2
         // 00401f1d: mov ds:[eax], edx
         // 00401f1f: add eax, 0x4
         // 00401f22: inc ds:[0x40d410]
         // 00401f28: sub esi, 0x4
         // 00401f2b: add ds:[0x40d414], esi
         // 00401f31: jmp 0x401f7f
      [-]8bc3e81afbffff8b53088bc22bc683f80c7c0c
         // 00401f33: mov eax, ebx
         // 00401f35: call 0x401a54
         // 00401f3a: mov edx, ds:[ebx+0x8]
         // 00401f3d: mov eax, edx
         // 00401f3f: sub eax, esi
         // 00401f41: cmp eax, 0xc
         // 00401f44: jl 0x401f52
      [-]8bd303d692e854fdffffeb12
         // 00401f46: mov edx, ebx
         // 00401f48: add edx, esi
         // 00401f4a: xchg eax, edx
         // 00401f4b: call 0x401ca4
         // 00401f50: jmp 0x401f64
      [-]8bf23b1f7505
         // 00401f52: mov esi, edx
         // 00401f54: cmp ebx, ds:[edi]
         // 00401f56: jnz 0x401f5d
      [-]8b43048907
         // 00401f58: mov eax, ds:[ebx+0x4]
         // 00401f5b: mov ds:[edi], eax
      [-]8bc303c68320fe
         // 00401f5d: mov eax, ebx
         // 00401f5f: add eax, esi
         // 00401f61: and ds:[eax], 0xfffffffffffffffe
      [-]8bc38bd683ca02891083c004ff05????????83ee040135????????
         // 00401f64: mov eax, ebx
         // 00401f66: mov edx, esi
         // 00401f68: or edx, 0x2
         // 00401f6b: mov ds:[eax], edx
         // 00401f6d: add eax, 0x4
         // 00401f70: inc ds:[0x40d410]
         // 00401f76: sub esi, 0x4
         // 00401f79: add ds:[0x40d414], esi
      [-]5d5f5e5bc3
         // 00401f7f: pop ebp
         // 00401f80: pop edi
         // 00401f81: pop esi
         // 00401f82: pop ebx
         // 00401f83: retn 
      [-]558bec83c4f85356578bd8803d1cd44000007513
         // 00401f84: push ebp
         // 00401f85: mov ebp, esp
         // 00401f87: add esp, 0xfffffffffffffff8
         // 00401f8a: push ebx
         // 00401f8b: push esi
         // 00401f8c: push edi
         // 00401f8d: mov ebx, eax
         // 00401f8f: cmp b1 ds:[0x40d41c], b1 0x0
         // 00401f96: jnz 0x401fab
      [-]e813f9ffff84c0750a
         // 00401f98: call 0x4018b0
         // 00401f9d: test b1 al, b1 al
         // 00401f9f: jnz 0x401fab
      [-]33c08945fce954010000
         // 00401fa1: xor eax, eax
         // 00401fa3: mov ss:[ebp+0xfffffffffffffffc], eax
         // 00401fa6: jmp 0x4020ff
      [-]33c95568????????64ff31648921803d35d0400000740a
         // 00401fab: xor ecx, ecx
         // 00401fad: push ebp
         // 00401fae: push 0x4020f8
         // 00401fb3: push fs:[ecx]
         // 00401fb6: mov fs:[ecx], esp
         // 00401fb9: cmp b1 ds:[0x40d035], b1 0x0
         // 00401fc0: jz 0x401fcc
      [-]6824d44000e840f2ffff
         // 00401fc2: push CriticalSection.DebugInfo
         // 00401fc7: call EnterCriticalSection
      [-]83c30783e3fc83fb0c7d05
         // 00401fcc: add ebx, 0x7
         // 00401fcf: and ebx, 0xfffffffffffffffc
         // 00401fd2: cmp ebx, 0xc
         // 00401fd5: jge 0x401fdc
      [-]bb????????
         // 00401fd7: mov ebx, 0xc
      [-]81fb????????0f8f93000000
         // 00401fdc: cmp ebx, 0x1000
         // 00401fe2: jg 0x40207b
      [-]8bc385c07903
         // 00401fe8: mov eax, ebx
         // 00401fea: test eax, eax
         // 00401fec: jns 0x401ff1
      [-]c1f8028b15????????8b5482f485d27479
         // 00401ff1: sar eax, b1 0x2
         // 00401ff4: mov edx, ds:[0x40d47c]
         // 00401ffa: mov edx, ds:[edx+eax*0x4]
         // 00401ffe: test edx, edx
         // 00402000: jz 0x40207b
      [-]8bf28bc603c38320fe8b42043bd0751a
         // 00402002: mov esi, edx
         // 00402004: mov eax, esi
         // 00402006: add eax, ebx
         // 00402008: and ds:[eax], 0xfffffffffffffffe
         // 0040200b: mov eax, ds:[edx+0x4]
         // 0040200e: cmp edx, eax
         // 00402010: jnz 0x40202c
      [-]8bc385c07903
         // 00402012: mov eax, ebx
         // 00402014: test eax, eax
         // 00402016: jns 0x40201b
      [-]c1f8028b0d????????33ff897c81f4eb26
         // 0040201b: sar eax, b1 0x2
         // 0040201e: mov ecx, ds:[0x40d47c]
         // 00402024: xor edi, edi
         // 00402026: mov ds:[ecx+eax*0x4], edi
         // 0040202a: jmp 0x402052
      [-]8bcb85c97903
         // 0040202c: mov ecx, ebx
         // 0040202e: test ecx, ecx
         // 00402030: jns 0x402035
      [-]c1f9028b3d????????89448ff48b0a894df88b4df88941048b4df88908
         // 00402035: sar ecx, b1 0x2
         // 00402038: mov edi, ds:[0x40d47c]
         // 0040203e: mov ds:[edi+ecx*0x4], eax
         // 00402042: mov ecx, ds:[edx]
         // 00402044: mov ss:[ebp+0xfffffffffffffff8], ecx
         // 00402047: mov ecx, ss:[ebp+0xfffffffffffffff8]
         // 0040204a: mov ds:[ecx+0x4], eax
         // 0040204d: mov ecx, ss:[ebp+0xfffffffffffffff8]
         // 00402050: mov ds:[eax], ecx
      [-]8bc68b520883ca02891083c0048945fcff05????????83eb04011d????????e86a0c0000e984000000
         // 00402052: mov eax, esi
         // 00402054: mov edx, ds:[edx+0x8]
         // 00402057: or edx, 0x2
         // 0040205a: mov ds:[eax], edx
         // 0040205c: add eax, 0x4
         // 0040205f: mov ss:[ebp+0xfffffffffffffffc], eax
         // 00402062: inc ds:[0x40d410]
         // 00402068: sub ebx, 0x4
         // 0040206b: add ds:[0x40d414], ebx
         // 00402071: call 0x402ce0
         // 00402076: jmp 0x4020ff
      [-]3b1d????????7f4a
         // 0040207b: cmp ebx, ds:[0x40d474]
         // 00402081: jg 0x4020cd
      [-]291d????????833d????????0c7d0d
         // 00402083: sub ds:[0x40d474], ebx
         // 00402089: cmp ds:[0x40d474], 0xc
         // 00402090: jge 0x40209f
      [-]031d????????33c0a3????????
         // 00402092: add ebx, ds:[0x40d474]
         // 00402098: xor eax, eax
         // 0040209a: mov ds:[0x40d474], eax
      [-]a1????????011d????????8bd383ca02891083c0048945fcff05????????83eb04011d????????e8150c0000eb32
         // 0040209f: mov eax, ds:[0x40d478]
         // 004020a4: add ds:[0x40d478], ebx
         // 004020aa: mov edx, ebx
         // 004020ac: or edx, 0x2
         // 004020af: mov ds:[eax], edx
         // 004020b1: add eax, 0x4
         // 004020b4: mov ss:[ebp+0xfffffffffffffffc], eax
         // 004020b7: inc ds:[0x40d410]
         // 004020bd: sub ebx, 0x4
         // 004020c0: add ds:[0x40d414], ebx
         // 004020c6: call 0x402ce0
         // 004020cb: jmp 0x4020ff
      [-]8bc3e8bcfdffff8945fc33c05a595964891068????????803d35d0400000740a
         // 004020cd: mov eax, ebx
         // 004020cf: call 0x401e90
         // 004020d4: mov ss:[ebp+0xfffffffffffffffc], eax
         // 004020d7: xor eax, eax
         // 004020d9: pop edx
         // 004020da: pop ecx
         // 004020db: pop ecx
         // 004020dc: mov fs:[eax], edx
         // 004020df: push 0x4020ff
         // 004020e4: cmp b1 ds:[0x40d035], b1 0x0
         // 004020eb: jz 0x4020f7
      [-]6824d44000e81df1ffff
         // 004020ed: push CriticalSection.DebugInfo
         // 004020f2: call LeaveCriticalSection
      [-]8b45fc5f5e5b59595dc3
         // 004020ff: mov eax, ss:[ebp+0xfffffffffffffffc]
         // 00402102: pop edi
         // 00402103: pop esi
         // 00402104: pop ebx
         // 00402105: pop ecx
         // 00402106: pop ecx
         // 00402107: pop ebp
         // 00402108: retn 
      [-]558bec515356578bd833c0a3????????803d1cd4400000751f
         // 0040210c: push ebp
         // 0040210d: mov ebp, esp
         // 0040210f: push ecx
         // 00402110: push ebx
         // 00402111: push esi
         // 00402112: push edi
         // 00402113: mov ebx, eax
         // 00402115: xor eax, eax
         // 00402117: mov ds:[0x40d420], eax
         // 0040211c: cmp b1 ds:[0x40d41c], b1 0x0
         // 00402123: jnz 0x402144
      [-]e886f7ffff84c07516
         // 00402125: call 0x4018b0
         // 0040212a: test b1 al, b1 al
         // 0040212c: jnz 0x402144
      [-]c705????????????????c745fc????????e961010000
         // 0040212e: mov ds:[0x40d420], 0x8
         // 00402138: mov ss:[ebp+0xfffffffffffffffc], 0x8
         // 0040213f: jmp 0x4022a5
      [-]33c95568????????64ff31648921803d35d0400000740a
         // 00402144: xor ecx, ecx
         // 00402146: push ebp
         // 00402147: push 0x40229e
         // 0040214c: push fs:[ecx]
         // 0040214f: mov fs:[ecx], esp
         // 00402152: cmp b1 ds:[0x40d035], b1 0x0
         // 00402159: jz 0x402165
      [-]6824d44000e8a7f0ffff
         // 0040215b: push CriticalSection.DebugInfo
         // 00402160: call EnterCriticalSection
      [-]8bf383ee048b1ef6c302750f
         // 00402165: mov esi, ebx
         // 00402167: sub esi, 0x4
         // 0040216a: mov ebx, ds:[esi]
         // 0040216c: test b1 bl, b1 0x2
         // 0040216f: jnz 0x402180
      [-]c705????????????????e9f5000000
         // 00402171: mov ds:[0x40d420], 0x9
         // 0040217b: jmp 0x402275
      [-]ff0d????????8bc325????????83e8042905????????f6c3017445
         // 00402180: dec ds:[0x40d410]
         // 00402186: mov eax, ebx
         // 00402188: and eax, 0x7ffffffc
         // 0040218d: sub eax, 0x4
         // 00402190: sub ds:[0x40d414], eax
         // 00402196: test b1 bl, b1 0x1
         // 00402199: jz 0x4021e0
      [-]8bc683e80c8b500883fa0c7c08
         // 0040219b: mov eax, esi
         // 0040219d: sub eax, 0xc
         // 004021a0: mov edx, ds:[eax+0x8]
         // 004021a3: cmp edx, 0xc
         // 004021a6: jl 0x4021b0
      [-]f7c2????????740f
         // 004021a8: test edx, 0xffffffff80000003
         // 004021ae: jz 0x4021bf
      [-]c705????????????????e9b6000000
         // 004021b0: mov ds:[0x40d420], 0xa
         // 004021ba: jmp 0x402275
      [-]8bc62bc23b5008740f
         // 004021bf: mov eax, esi
         // 004021c1: sub eax, edx
         // 004021c3: cmp edx, ds:[eax+0x8]
         // 004021c6: jz 0x4021d7
      [-]c705????????????????e99e000000
         // 004021c8: mov ds:[0x40d420], 0xa
         // 004021d2: jmp 0x402275
      [-]03da8bf0e874f8ffff
         // 004021d7: add ebx, edx
         // 004021d9: mov esi, eax
         // 004021db: call 0x401a54
      [-]81e3????????8bc603c38bf83b3d????????752c
         // 004021e0: and ebx, 0x7ffffffc
         // 004021e6: mov eax, esi
         // 004021e8: add eax, ebx
         // 004021ea: mov edi, eax
         // 004021ec: cmp edi, ds:[0x40d478]
         // 004021f2: jnz 0x402220
      [-]291d????????011d????????813d????????????????7e05
         // 004021f4: sub ds:[0x40d478], ebx
         // 004021fa: add ds:[0x40d474], ebx
         // 00402200: cmp ds:[0x40d474], 0x3c00
         // 0040220a: jle 0x402211
      [-]e81bfbffff
         // 0040220c: call 0x401d2c
      [-]33c08945fce8c50a0000e985000000
         // 00402211: xor eax, eax
         // 00402213: mov ss:[ebp+0xfffffffffffffffc], eax
         // 00402216: call 0x402ce0
         // 0040221b: jmp 0x4022a5
      [-]8b10f6c202741c
         // 00402220: mov edx, ds:[eax]
         // 00402222: test b1 dl, b1 0x2
         // 00402225: jz 0x402243
      [-]81e2????????83fa047d0c
         // 00402227: and edx, 0x7ffffffc
         // 0040222d: cmp edx, 0x4
         // 00402230: jge 0x40223e
      [-]c705????????????????eb37
         // 00402232: mov ds:[0x40d420], 0xb
         // 0040223c: jmp 0x402275
      [-]830801eb29
         // 0040223e: or ds:[eax], 0x1
         // 00402241: jmp 0x40226c
      [-]8bc783780400740b
         // 00402243: mov eax, edi
         // 00402245: cmp ds:[eax+0x4], 0x0
         // 00402249: jz 0x402256
      [-]8338007406
         // 0040224b: cmp ds:[eax], 0x0
         // 0040224e: jz 0x402256
      [-]8378080c7d0c
         // 00402250: cmp ds:[eax+0x8], 0xc
         // 00402254: jge 0x402262
      [-]c705????????????????eb13
         // 00402256: mov ds:[0x40d420], 0xb
         // 00402260: jmp 0x402275
      [-]8b500803dae8e8f7ffff
         // 00402262: mov edx, ds:[eax+0x8]
         // 00402265: add ebx, edx
         // 00402267: call 0x401a54
      [-]8bd38bc6e82ffaffff
         // 0040226c: mov edx, ebx
         // 0040226e: mov eax, esi
         // 00402270: call 0x401ca4
      [-]a1????????8945fc33c05a595964891068????????803d35d0400000740a
         // 00402275: mov eax, ds:[0x40d420]
         // 0040227a: mov ss:[ebp+0xfffffffffffffffc], eax
         // 0040227d: xor eax, eax
         // 0040227f: pop edx
         // 00402280: pop ecx
         // 00402281: pop ecx
         // 00402282: mov fs:[eax], edx
         // 00402285: push 0x4022a5
         // 0040228a: cmp b1 ds:[0x40d035], b1 0x0
         // 00402291: jz 0x40229d
      [-]6824d44000e877efffff
         // 00402293: push CriticalSection.DebugInfo
         // 00402298: call LeaveCriticalSection
      [-]8b45fc5f5e5b595dc3
         // 004022a5: mov eax, ss:[ebp+0xfffffffffffffffc]
         // 004022a8: pop edi
         // 004022a9: pop esi
         // 004022aa: pop ebx
         // 004022ab: pop ecx
         // 004022ac: pop ebp
         // 004022ad: retn 
      [-]5356575583c4f88bf283c60783e6fc83fe0c7d05
         // 004022b0: push ebx
         // 004022b1: push esi
         // 004022b2: push edi
         // 004022b3: push ebp
         // 004022b4: add esp, 0xfffffffffffffff8
         // 004022b7: mov esi, edx
         // 004022b9: add esi, 0x7
         // 004022bc: and esi, 0xfffffffffffffffc
         // 004022bf: cmp esi, 0xc
         // 004022c2: jge 0x4022c9
      [-]be????????
         // 004022c4: mov esi, 0xc
      [-]8be883ed048b7d0081e7????????8bc503c78bd83bfe0f8c83000000
         // 004022c9: mov ebp, eax
         // 004022cb: sub ebp, 0x4
         // 004022ce: mov edi, ss:[ebp+0x0]
         // 004022d1: and edi, 0x7ffffffc
         // 004022d7: mov eax, ebp
         // 004022d9: add eax, edi
         // 004022db: mov ebx, eax
         // 004022dd: cmp edi, esi
         // 004022df: jl 0x402368
      [-]8bd72bd68914243b1d????????7538
         // 004022e5: mov edx, edi
         // 004022e7: sub edx, esi
         // 004022e9: mov ss:[esp], edx
         // 004022ec: cmp ebx, ds:[0x40d478]
         // 004022f2: jnz 0x40232c
      [-]8b04242905????????8b04240105????????833d????????0c0f8d4c010000
         // 004022f4: mov eax, ss:[esp]
         // 004022f7: sub ds:[0x40d478], eax
         // 004022fd: mov eax, ss:[esp]
         // 00402300: add ds:[0x40d474], eax
         // 00402306: cmp ds:[0x40d474], 0xc
         // 0040230d: jge 0x40245f
      [-]8b04240105????????8b04242905????????8bf7e933010000
         // 00402313: mov eax, ss:[esp]
         // 00402316: add ds:[0x40d478], eax
         // 0040231c: mov eax, ss:[esp]
         // 0040231f: sub ds:[0x40d474], eax
         // 00402325: mov esi, edi
         // 00402327: jmp 0x40245f
      [-]8bd8f60302750d
         // 0040232c: mov ebx, eax
         // 0040232e: test b1 ds:[ebx], b1 0x2
         // 00402331: jnz 0x402340
      [-]8bc38b5008011424e814f7ffff
         // 00402333: mov eax, ebx
         // 00402335: mov edx, ds:[eax+0x8]
         // 00402338: add ss:[esp], edx
         // 0040233b: call 0x401a54
      [-]833c240c7c1b
         // 00402340: cmp ss:[esp], 0xc
         // 00402344: jl 0x402361
      [-]8bdd03de8b042483c80289038bc383c004e8bcf7ffffe9fe000000
         // 00402346: mov ebx, ebp
         // 00402348: add ebx, esi
         // 0040234a: mov eax, ss:[esp]
         // 0040234d: or eax, 0x2
         // 00402350: mov ds:[ebx], eax
         // 00402352: mov eax, ebx
         // 00402354: add eax, 0x4
         // 00402357: call 0x401b18
         // 0040235c: jmp 0x40245f
      [-]8bf7e9f7000000
         // 00402361: mov esi, edi
         // 00402363: jmp 0x40245f
      [-]8bc62bc7894424043b1d????????7567
         // 00402368: mov eax, esi
         // 0040236a: sub eax, edi
         // 0040236c: mov ss:[esp+0x4], eax
         // 00402370: cmp ebx, ds:[0x40d478]
         // 00402376: jnz 0x4023df
      [-]a1????????3b4424047c53
         // 00402378: mov eax, ds:[0x40d474]
         // 0040237d: cmp eax, ss:[esp+0x4]
         // 00402381: jl 0x4023d6
      [-]8b4424042905????????8b4424040105????????833d????????0c7d18
         // 00402383: mov eax, ss:[esp+0x4]
         // 00402387: sub ds:[0x40d474], eax
         // 0040238d: mov eax, ss:[esp+0x4]
         // 00402391: add ds:[0x40d478], eax
         // 00402397: cmp ds:[0x40d474], 0xc
         // 0040239e: jge 0x4023b8
      [-]a1????????0105????????0335????????33c0a3????????
         // 004023a0: mov eax, ds:[0x40d474]
         // 004023a5: add ds:[0x40d478], eax
         // 004023ab: add esi, ds:[0x40d474]
         // 004023b1: xor eax, eax
         // 004023b3: mov ds:[0x40d474], eax
      [-]8bc62bc70105????????8b450025????????0bf0897500b001e9a2000000
         // 004023b8: mov eax, esi
         // 004023ba: sub eax, edi
         // 004023bc: add ds:[0x40d414], eax
         // 004023c2: mov eax, ss:[ebp+0x0]
         // 004023c5: and eax, 0xffffffff80000003
         // 004023ca: or esi, eax
         // 004023cc: mov ss:[ebp+0x0], esi
         // 004023cf: mov b1 al, b1 0x1
         // 004023d1: jmp 0x402478
      [-]e851f9ffff8bdd03df
         // 004023d6: call 0x401d2c
         // 004023db: mov ebx, ebp
         // 004023dd: add ebx, edi
      [-]f60302754d
         // 004023df: test b1 ds:[ebx], b1 0x2
         // 004023e2: jnz 0x402431
      [-]8bd38bc28b4808890c248b0c243b4c24047d0e
         // 004023e4: mov edx, ebx
         // 004023e6: mov eax, edx
         // 004023e8: mov ecx, ds:[eax+0x8]
         // 004023eb: mov ss:[esp], ecx
         // 004023ee: mov ecx, ss:[esp]
         // 004023f1: cmp ecx, ss:[esp+0x4]
         // 004023f5: jge 0x402405
      [-]0314248bda8b042429442404eb2c
         // 004023f7: add edx, ss:[esp]
         // 004023fa: mov ebx, edx
         // 004023fc: mov eax, ss:[esp]
         // 004023ff: sub ss:[esp+0x4], eax
         // 00402403: jmp 0x402431
      [-]e84af6ffff8b442404290424833c240c7c0e
         // 00402405: call 0x401a54
         // 0040240a: mov eax, ss:[esp+0x4]
         // 0040240e: sub ss:[esp], eax
         // 00402411: cmp ss:[esp], 0xc
         // 00402415: jl 0x402425
      [-]8bc503c68b1424e881f8ffffeb3a
         // 00402417: mov eax, ebp
         // 00402419: add eax, esi
         // 0040241b: mov edx, ss:[esp]
         // 0040241e: call 0x401ca4
         // 00402423: jmp 0x40245f
      [-]0334248bdd03de8323feeb2e
         // 00402425: add esi, ss:[esp]
         // 00402428: mov ebx, ebp
         // 0040242a: add ebx, esi
         // 0040242c: and ds:[ebx], 0xfffffffffffffffe
         // 0040242f: jmp 0x40245f
      [-]8b03a9????????7421
         // 00402431: mov eax, ds:[ebx]
         // 00402433: test eax, 0xffffffff80000000
         // 00402438: jz 0x40245b
      [-]25????????03c38bd88b5424048bc3e8e2f9ffff84c07409
         // 0040243a: and eax, 0x7ffffffc
         // 0040243f: add eax, ebx
         // 00402441: mov ebx, eax
         // 00402443: mov edx, ss:[esp+0x4]
         // 00402447: mov eax, ebx
         // 00402449: call 0x401e30
         // 0040244e: test b1 al, b1 al
         // 00402450: jz 0x40245b
      [-]8bdd03dfe90dffffff
         // 00402452: mov ebx, ebp
         // 00402454: add ebx, edi
         // 00402456: jmp 0x402368
      [-]33c0eb19
         // 0040245b: xor eax, eax
         // 0040245d: jmp 0x402478
      [-]8bc62bc70105????????8b450025????????0bf0897500b001
         // 0040245f: mov eax, esi
         // 00402461: sub eax, edi
         // 00402463: add ds:[0x40d414], eax
         // 00402469: mov eax, ss:[ebp+0x0]
         // 0040246c: and eax, 0xffffffff80000003
         // 00402471: or esi, eax
         // 00402473: mov ss:[ebp+0x0], esi
         // 00402476: mov b1 al, b1 0x1
      [-]595a5d5f5e5bc3
         // 00402478: pop ecx
         // 00402479: pop edx
         // 0040247a: pop ebp
         // 0040247b: pop edi
         // 0040247c: pop esi
         // 0040247d: pop ebx
         // 0040247e: retn 
      [-]558bec515356578bf28bd8803d1cd44000007513
         // 00402480: push ebp
         // 00402481: mov ebp, esp
         // 00402483: push ecx
         // 00402484: push ebx
         // 00402485: push esi
         // 00402486: push edi
         // 00402487: mov esi, edx
         // 00402489: mov ebx, eax
         // 0040248b: cmp b1 ds:[0x40d41c], b1 0x0
         // 00402492: jnz 0x4024a7
      [-]e817f4ffff84c0750a
         // 00402494: call 0x4018b0
         // 00402499: test b1 al, b1 al
         // 0040249b: jnz 0x4024a7
      [-]33c08945fce991000000
         // 0040249d: xor eax, eax
         // 0040249f: mov ss:[ebp+0xfffffffffffffffc], eax
         // 004024a2: jmp 0x402538
      [-]33d25568????????64ff32648922803d35d0400000740a
         // 004024a7: xor edx, edx
         // 004024a9: push ebp
         // 004024aa: push 0x402531
         // 004024af: push fs:[edx]
         // 004024b2: mov fs:[edx], esp
         // 004024b5: cmp b1 ds:[0x40d035], b1 0x0
         // 004024bc: jz 0x4024c8
      [-]6824d44000e844edffff
         // 004024be: push CriticalSection.DebugInfo
         // 004024c3: call EnterCriticalSection
      [-]8bd6
         // 004024c8: mov edx, esi
         // 004024ca: mov eax, ebx
         // 004024cc: call 0x4022b0
         // 004024d1: test b1 al, b1 al
         // 004024d3: jz 0x4024da

  }
  condition:
    all of them
}
