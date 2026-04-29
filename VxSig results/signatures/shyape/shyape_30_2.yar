rule shyape_30_2 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         81ec????????a1
         // 00401000: sub esp, 0xa0
         // 00401006: mov eax, ds:[___security_cookie]
      [-]68????????8d
         // 00401014: push 0x98
         // 00401019: lea eax, ss:[esp+0x8]
      [-]6a0050e8
         // 0040101d: push 0x0
         // 0040101f: push eax
         // 00401020: call _memset
      [-]000083c40c8d
         // 00401025: add esp, 0xc
         // 00401028: lea ecx, ss:[esp]
      [-]010f95c08d4400048b
         // 0040106b: setnz b1 al
         // 0040106e: lea eax, ds:[eax+eax+0x4]
         // 00401072: mov ecx, ss:[ebp+0xfffffffffffffffc]
      [-]83f80175
         // 0040108c: cmp eax, 0x1
         // 0040108f: jnz 0x4010b7
      [-]010f95c08d4400058b
         // 0040109b: setnz b1 al
         // 0040109e: lea eax, ds:[eax+eax+0x5]
         // 004010a2: mov ecx, ss:[esp+0x9c]
      [-]83f80275
         // 004010b7: cmp eax, 0x2
         // 004010ba: jnz 0x401131
      [-]010f95c083c0088b
         // 004010c6: setnz b1 al
         // 004010c9: add eax, 0x8
         // 004010cc: mov ecx, ss:[esp+0x9c]
      [-]83f80575
         // 004010e1: cmp eax, 0x5
         // 004010e4: jnz 0x401131
      [-]83f80275
         // 004010ea: cmp eax, 0x2
         // 004010ed: jnz 0x401109
      [-]b8????????8b
         // 004010ef: mov eax, 0x3
         // 004010f4: mov ecx, ss:[esp+0x9c]
      [-]83f80175
         // 00401109: cmp eax, 0x1
         // 0040110c: jnz 0x401128
      [-]b8????????8b
         // 0040110e: mov eax, 0x2
         // 00401113: mov ecx, ss:[esp+0x9c]
      [-]85c07505
         // 00401128: test eax, eax
         // 0040112a: jnz 0x401131
      [-]b8????????
         // 0040112c: mov eax, 0x1
      [-]81ec????????a1
         // 00401180: sub esp, 0x810
         // 00401186: mov eax, ds:[___security_cookie]
      [-]5333db68????????8d
         // 00401194: push ebx
         // 00401195: xor ebx, ebx
         // 00401197: push 0x3ff
         // 0040119c: lea eax, ss:[esp+0x415]
      [-]000068????????8d
         // 004011b1: push 0x3ff
         // 004011b6: lea ecx, ss:[esp+0x21]
      [-]000083c41868????????8d
         // 004011d1: add esp, 0x18
         // 004011d4: push 0x400
         // 004011d9: lea edx, ss:[esp+0x14]
      [-]5268????????8d
         // 004011ec: push edx
         // 004011ed: push 0x400
         // 004011f2: lea eax, ss:[esp+0x428]
      [-]f7d81bc023
         // 0040120c: neg eax
         // 0040120e: sbb eax, eax
         // 00401210: and eax, ss:[esp+0x4]
      [-]83ec18a1
         // 00401220: sub esp, 0x18
         // 00401223: mov eax, ds:[___security_cookie]
      [-]0fbec099
         // 00401240: movsx eax, b1 al
         // 00401243: cdq 
      [-]ffffff33c9508d
         // 0040121b: xor ecx, ecx
         // 0040121d: push eax
         // 0040121e: lea eax, ss:[ebp+0xffffffffffffffe8]
      [-]83c40c8b
         // 00401246: add esp, 0xc
         // 00401249: mov ecx, eax
      [-]8bc8c1e902f3a58bc883e103f3a48b
         // 004012bd: mov ecx, eax
         // 004012bf: shr ecx, b1 0x2
         // 004012c2: rep movsdd 
         // 004012c4: mov ecx, eax
         // 004012c6: and ecx, 0x3
         // 004012c9: rep movsbb 
         // 004012cb: mov ecx, ss:[esp+0x1c]
      [-]68????????8d
         // 00401314: push 0x103
         // 00401319: lea eax, ss:[esp+0x5]
      [-]6a0050c6
         // 0040131d: push 0x0
         // 0040131f: push eax
         // 00401320: mov b1 ss:[esp+0xc], b1 0x0
      [-]000083c40c68????????8d
         // 0040132a: add esp, 0xc
         // 0040132d: push 0x104
         // 00401332: lea ecx, ss:[esp+0x4]
      [-]516a00ff15
         // 00401336: push ecx
         // 00401337: push 0x0
         // 00401339: call ds:[0x40f0bc]
      [-]52894804e8
         // 00401395: push edx
         // 00401396: mov ds:[eax+0x4], ecx
         // 00401399: call 0x403b3d
      [-]83c40885
         // 004013a0: add esp, 0x8
         // 004013a3: test esi, esi
      [-]6a026a00
         // 00401357: push 0x2
         // 00401359: push 0x0
      [-]00006a006a00
         // 00401367: push 0x0
         // 00401369: push 0x0
      [-]feffff84c07506
         // 0040141b: test b1 al, b1 al
         // 0040141d: jnz 0x401425
      [-]5f32c05e
         // 00401456: pop edi
         // 00401457: xor b1 al, b1 al
         // 00401459: pop esi
      [-]fdffff69f6????????
         // 00401464: imul esi, 0x1a4
      [-]68????????6a00
         // 004014ee: push 0xfa
         // 004014f3: push 0x0
      [-]000068????????6a0068
         // 004014ff: push 0xfa
         // 00401504: push 0x0
         // 00401506: push 0x413b20
      [-]000068????????6a0068
         // 00401510: push 0xfa
         // 00401515: push 0x0
         // 00401517: push 0x413c20
      [-]00008b0d
         // 00401521: mov ecx, ds:[0x40f278]
      [-]8bc3890d
         // 0040152d: mov eax, ebx
         // 0040152f: mov ds:[0x413a24], ecx
      [-]83c42489
         // 00401535: add esp, 0x24
         // 00401538: mov ds:[0x413a20], ebp
      [-]8bc8c1e902f3a58bc883e1038d4332f3a48bc8
         // 00401508: mov ecx, eax
         // 0040150a: shr ecx, b1 0x2
         // 0040150d: rep movsdd 
         // 0040150f: mov ecx, eax
         // 00401511: and ecx, 0x3
         // 00401514: lea eax, ds:[ebx+0x32]
         // 00401517: rep movsbb 
         // 00401519: mov ecx, eax
      [-]2bc18bf1
         // 0040152c: sub eax, ecx
         // 0040152e: mov esi, ecx
      [-]8bc8c1e902f3a58bc883e103b8
         // 00401539: mov ecx, eax
         // 0040153b: shr ecx, b1 0x2
         // 0040153e: rep movsdd 
         // 00401540: mov ecx, eax
         // 00401542: and ecx, 0x3
         // 00401545: mov eax, 0x414774
      [-]f3a48bc8
         // 0040154a: rep movsbb 
         // 0040154c: mov ecx, eax
      [-]2bc18bf1
         // 0040155c: sub eax, ecx
         // 0040155e: mov esi, ecx
      [-]8bc8c1e902f3a58bc883e103b8
         // 00401569: mov ecx, eax
         // 0040156b: shr ecx, b1 0x2
         // 0040156e: rep movsdd 
         // 00401570: mov ecx, eax
         // 00401572: and ecx, 0x3
         // 00401575: mov eax, 0x414460
      [-]0c8d4364ba
         // 004015ad: lea eax, ds:[ebx+0x64]
         // 004015b0: mov edx, 0x414560
      [-]8a08880c02
         // 004015b7: mov b1 cl, b1 ds:[eax]
         // 004015b9: mov b1 ds:[edx+eax], b1 cl
      [-]2bc18bf1
         // 004015ed: sub eax, ecx
         // 004015ef: mov esi, ecx
      [-]8bc8c1e902f3a58bc883e103b8
         // 0040166f: mov ecx, eax
         // 00401671: shr ecx, b1 0x2
         // 00401674: rep movsdd 
         // 00401676: mov ecx, eax
         // 00401678: and ecx, 0x3
         // 0040167b: mov eax, 0x413b20
      [-]89088b0d
         // 0040169b: mov ds:[eax], ecx
         // 0040169d: mov ecx, ds:[0x40f250]
      [-]8950048b15
         // 004016a3: mov ds:[eax+0x4], edx
         // 004016a6: mov edx, ds:[0x40f254]
      [-]8948088b0d
         // 004016ac: mov ds:[eax+0x8], ecx
         // 004016af: mov ecx, ds:[0x40f258]
      [-]89500c8a15
         // 004016b5: mov ds:[eax+0xc], edx
         // 004016b8: mov b1 dl, b1 ds:[0x40f25c]
      [-]00894810
         // 004016be: mov ds:[eax+0x10], ecx
      [-]885014a1
         // 004016c1: mov b1 ds:[eax+0x14], b1 dl
         // 004016c4: mov eax, ds:[0x40f278]
      [-]2bc18bf1
         // 0040166e: sub eax, ecx
         // 00401670: mov esi, ecx
      [-]8bc8c1e902f3a58bc883e1038d83????????f3a48bc8
         // 0040167b: mov ecx, eax
         // 0040167d: shr ecx, b1 0x2
         // 00401680: rep movsdd 
         // 00401682: mov ecx, eax
         // 00401684: and ecx, 0x3
         // 00401687: lea eax, ds:[ebx+0x96]
         // 0040168d: rep movsbb 
         // 0040168f: mov ecx, eax
      [-]2bc18bf1
         // 0040169d: sub eax, ecx
         // 0040169f: mov esi, ecx
      [-]8bc8c1e902f3a58bc883e103b8
         // 004016aa: mov ecx, eax
         // 004016ac: shr ecx, b1 0x2
         // 004016af: rep movsdd 
         // 004016b1: mov ecx, eax
         // 004016b3: and ecx, 0x3
         // 004016b6: mov eax, 0x414660
      [-]2bc18bf1
         // 00401712: sub eax, ecx
         // 00401714: mov esi, ecx
      [-]8bc8c1e902f3a58bc883e103833d
         // 00401709: mov ecx, eax
         // 0040170b: shr ecx, b1 0x2
         // 0040170e: rep movsdd 
         // 00401710: mov ecx, eax
         // 00401712: and ecx, 0x3
         // 00401715: cmp ds:[0x412738], 0x0
      [-]00f3a475
         // 0040171c: rep movsbb 
         // 0040171e: jnz 0x401745
      [-]6a006a006a006a0068
         // 00401720: push 0x0
         // 00401722: push 0x0
         // 00401724: push 0x0
         // 00401726: push 0x0
         // 00401728: push 0x40ead8
      [-]5b5f32c05e
         // 0040173c: pop ebx
         // 0040173d: pop edi
         // 0040173e: xor b1 al, b1 al
         // 00401740: pop esi
      [-]8d7c000257e8
         // 0040188b: lea edi, ds:[eax+eax+0x2]
         // 0040188f: push edi
         // 00401890: call _malloc
      [-]0000578bf06a0056e8
         // 00401895: push edi
         // 00401896: mov esi, eax
         // 00401898: push 0x0
         // 0040189a: push esi
         // 0040189b: call _memset
      [-]6a006a01ffd7
         // 004018af: push 0x0
         // 004018b1: push 0x1
         // 004018b3: call edi
      [-]000083c4
         // 004018d3: add esp, 0xc
      [-]8d7c000257e8
         // 004018fb: lea edi, ds:[eax+eax+0x2]
         // 004018ff: push edi
         // 00401900: call _malloc
      [-]0000578bf06a0056e8
         // 00401905: push edi
         // 00401906: mov esi, eax
         // 00401908: push 0x0
         // 0040190a: push esi
         // 0040190b: call _memset
      [-]00008b3d
         // 00401910: mov edi, ds:[MultiByteToWideChar]
      [-]83c4106a00566aff
         // 00401916: add esp, 0x10
         // 00401919: push 0x0
         // 0040191b: push esi
         // 0040191c: push 0xffffffffffffffff
      [-]6a0068????????ffd7
         // 0040191f: push 0x0
         // 00401921: push 0xfde9
         // 00401926: call edi
      [-]6a0068????????ffd78b
         // 00401935: push 0x0
         // 00401937: push 0xfde9
         // 0040193c: call edi
         // 0040193e: mov edi, ss:[esp+0x18]
      [-]6a006a006a00
         // 00401948: push 0x0
         // 0040194a: push 0x0
         // 0040194c: push 0x0
      [-]6aff566a006a01ff
         // 0040194f: push 0xffffffffffffffff
         // 00401951: push esi
         // 00401952: push 0x0
         // 00401954: push 0x1
         // 00401956: call ebx
      [-]6a006a0050
         // 00401958: push 0x0
         // 0040195a: push 0x0
         // 0040195c: push eax
      [-]6aff566a006a01ff
         // 0040195e: push 0xffffffffffffffff
         // 00401960: push esi
         // 00401961: push 0x0
         // 00401963: push 0x1
         // 00401965: call ebx
      [-]85c0560f95c3e8
         // 00401967: test eax, eax
         // 00401969: push esi
         // 0040196a: setnz b1 bl
         // 0040196d: call _free
      [-]000083c4045f5e
         // 00401972: add esp, 0x4
         // 00401975: pop edi
         // 00401976: pop esi
      [-]5768????????
         // 004018f9: push edi
         // 004018fa: push 0xfa
      [-]00008bd883c40485db0f8401
         // 0040190a: mov ebx, eax
         // 0040190c: add esp, 0x4
         // 0040190f: test ebx, ebx
         // 00401911: jz 0x401a54
      [-]68????????6a0053e8
         // 004018f2: push 0xfa
         // 004018f7: push 0x0
         // 004018f9: push ebx
         // 004018fa: call _memset
      [-]000083c40cff15
         // 004018ff: add esp, 0xc
         // 00401902: call ds:[GetTickCount]
      [-]83c71857e8
         // 0040191c: add edi, 0x18
         // 0040191f: push edi
         // 00401920: call _malloc
      [-]00008bf083c41885f60f84
         // 00401925: mov esi, eax
         // 00401927: add esp, 0x18
         // 0040192a: test esi, esi
         // 0040192c: jz 0x4019e8
      [-]000083c4
         // 00401a8c: add esp, 0x18
      [-]6a0068????????6a006a0068
         // 004019b2: push 0x0
         // 004019b4: push 0x100
         // 004019b9: push 0x0
         // 004019bb: push 0x0
         // 004019bd: push 0x40eae4
      [-]57566a006a00
         // 004019ff: push edi
         // 00401a00: push esi
         // 00401a01: push 0x0
         // 00401a03: push 0x0
      [-]000083c404eb
         // 00401b1e: add esp, 0x4
         // 00401b21: jmp 0x401b2b
      [-]000083c404
         // 00401a00: add esp, 0x4
      [-]81ec????????a1
         // 00401a73: sub esp, 0x134
         // 00401a79: mov eax, ds:[___security_cookie]
      [-]5668????????8d
         // 00401a83: push esi
         // 00401a84: push 0x12b
         // 00401a89: lea eax, ss:[ebp+0xfffffffffffffed1]
      [-]6a0050c6
         // 00401a8f: push 0x0
         // 00401a91: push eax
         // 00401a92: mov b1 ss:[ebp+0xfffffffffffffed0], b1 0x0
      [-]000083c40cff15
         // 00401a9e: add esp, 0xc
         // 00401aa1: call ds:[GetTickCount]
      [-]83c40c6a0068????????6a006a008d
         // 00401abe: add esp, 0xc
         // 00401ac1: push 0x0
         // 00401ac3: push 0x100
         // 00401ac8: push 0x0
         // 00401aca: push 0x0
         // 00401acc: lea edx, ss:[ebp+0xfffffffffffffed0]
      [-]5250ff15
         // 00401ad2: push edx
         // 00401ad3: push eax
         // 00401ad4: call ds:[InternetOpenUrlA]
      [-]8bf085f674
         // 00401ada: mov esi, eax
         // 00401adc: test esi, esi
         // 00401ade: jz 0x401b30
      [-]85c0560f95c3ff15
         // 00401b2a: test eax, eax
         // 00401b2c: push esi
         // 00401b2d: setnz b1 bl
         // 00401b30: call ds:[InternetCloseHandle]
      [-]84db5b74
         // 00401b36: test b1 bl, b1 bl
         // 00401b38: pop ebx
         // 00401b39: jz 0x401b5a
      [-]b0015e8b
         // 00401c13: mov b1 al, b1 0x1
         // 00401c15: pop esi
         // 00401c16: mov ecx, ss:[esp+0x130]
      [-]68????????8d
         // 00401c6d: push 0x12b
         // 00401c72: lea eax, ss:[esp+0x11]
      [-]000083c40cff15
         // 00401c83: add esp, 0xc
         // 00401c86: call ds:[0x40f0a8]
      [-]83c40c6a0068????????6a006a008d
         // 00401ca1: add esp, 0xc
         // 00401ca4: push 0x0
         // 00401ca6: push 0x100
         // 00401cab: push 0x0
         // 00401cad: push 0x0
         // 00401caf: lea edx, ss:[esp+0x1c]
      [-]000083c40c8d
         // 00401bee: add esp, 0xc
         // 00401bf1: lea edx, ss:[ebp+0xfffffffffffffec8]
      [-]000083c404
         // 00401c34: add esp, 0x4
      [-]81ec????????a1
         // 00401cc0: sub esp, 0x10c
         // 00401cc6: mov eax, ds:[___security_cookie]
      [-]80781000538d581089
         // 00401cdb: cmp b1 ds:[eax+0x10], b1 0x0
         // 00401cdf: push ebx
         // 00401ce0: lea ebx, ds:[eax+0x10]
         // 00401ce3: mov ss:[esp+0x4], ebx
      [-]32c05b8b
         // 00401dc9: xor b1 al, b1 al
         // 00401dcb: pop ebx
         // 00401dcc: mov ecx, ss:[esp+0x108]
      [-]565768????????8d
         // 00401de1: push esi
         // 00401de2: push edi
         // 00401de3: push 0x103
         // 00401de8: lea eax, ss:[esp+0x15]
      [-]6a0050c6
         // 00401dec: push 0x0
         // 00401dee: push eax
         // 00401def: mov b1 ss:[esp+0x1c], b1 0x0
      [-]000083c40c8d
         // 00401df9: add esp, 0xc
         // 00401dfc: lea ecx, ss:[esp+0x10]
      [-]5168????????ff15
         // 00401e00: push ecx
         // 00401e01: push 0x104
         // 00401e06: call ds:[0x40f0a0]
      [-]2bf18d7e063bf77d
         // 00401d28: sub esi, ecx
         // 00401d2a: lea edi, ds:[esi+0x6]
         // 00401d2d: cmp esi, edi
         // 00401d2f: jge 0x401d5f
      [-]ffd333d2b9????????f7f16a0180c26188
         // 00401e32: call ebx
         // 00401e34: xor edx, edx
         // 00401e36: mov ecx, 0x1a
         // 00401e3b: div ecx
         // 00401e3d: push 0x1
         // 00401e3f: add b1 dl, b1 0x61
         // 00401e42: mov b1 ss:[esp+esi+0x18], b1 dl
      [-]0089108848048d
         // 00401e76: mov ds:[eax], edx
         // 00401e78: mov b1 ds:[eax+0x4], b1 cl
         // 00401e7b: lea eax, ss:[esp+0x8]
      [-]8bd38bc82bd1
         // 00401e7f: mov edx, ebx
         // 00401e81: mov ecx, eax
         // 00401e83: sub edx, ecx
      [-]8a08880c02
         // 00401da0: mov b1 cl, b1 ds:[eax]
         // 00401da2: mov b1 ds:[edx+eax], b1 cl
      [-]535756e8
         // 00401db4: push ebx
         // 00401db5: push edi
         // 00401db6: push esi
         // 00401db7: call 0x401cb0
      [-]feffff8d7e10
         // 00401dbc: lea edi, ds:[esi+0x10]
      [-]faffff83c4
         // 00401dc9: add esp, 0x8
      [-]833e01740a
         // 00401dcc: cmp ds:[esi], 0x1
         // 00401dcf: jz 0x401ddb
      [-]83f8ff7523
         // 00401ed6: cmp eax, 0xffffffffffffffff
         // 00401ed9: jnz 0x401efe
      [-]6a0068????????6a016a006a0068????????57ff15
         // 00401ddb: push 0x0
         // 00401ddd: push 0x80
         // 00401de2: push 0x1
         // 00401de4: push 0x0
         // 00401de6: push 0x0
         // 00401de8: push 0x40000000
         // 00401ded: push edi
         // 00401dee: call ds:[CreateFileA]
      [-]8b4e086a006a005150ff15
         // 00401e1b: mov ecx, ds:[esi+0x8]
         // 00401e1e: push 0x0
         // 00401e20: push 0x0
         // 00401e22: push ecx
         // 00401e23: push eax
         // 00401e24: call ds:[SetFilePointer]
      [-]83f8ff74
         // 00401e2a: cmp eax, 0xffffffffffffffff
         // 00401e2d: jz 0x401e5a
      [-]8b460c6a008d
         // 00401f12: mov eax, ds:[esi+0xc]
         // 00401f15: push 0x0
         // 00401f17: lea edx, ss:[esp+0x14]
      [-]508d8e????????5152c7
         // 00401f22: push eax
         // 00401f23: lea ecx, ds:[esi+0x114]
         // 00401f29: push ecx
         // 00401f2a: push edx
         // 00401f2b: mov ss:[esp+0x24], 0x0
      [-]833e037524
         // 00401e76: cmp ds:[esi], 0x3
         // 00401e79: jnz 0x401e9f
      [-]6a0057ff15
         // 00401e79: push 0x0
         // 00401e7b: push edi
         // 00401e7c: call ds:[WinExec]
      [-]2bc28bc885c97e
         // 00401ebc: sub eax, edx
         // 00401ebe: mov ecx, eax
         // 00401ec0: test ecx, ecx
         // 00401ec2: jle 0x401ecf
      [-]803c385c74
         // 00401ec4: cmp b1 ds:[eax+edi], b1 0x5c
         // 00401ec8: jz 0x401ecf
      [-]8a540701881406
         // 00401ee0: mov b1 dl, b1 ds:[edi+eax+0x1]
         // 00401ee4: mov b1 ds:[esi+eax], b1 dl
      [-]576a0068????????6a036a006a01
         // 00401f05: push edi
         // 00401f06: push 0x0
         // 00401f08: push 0x80
         // 00401f0d: push 0x3
         // 00401f0f: push 0x0
         // 00401f11: push 0x1
      [-]68????????
         // 00401f15: push 0xffffffff80000000
      [-]566a006a006a00
         // 00402036: push esi
         // 00402037: push 0x0
         // 00402039: push 0x0
         // 0040203b: push 0x0
      [-]83f8ff0f84
         // 00402044: cmp eax, 0xffffffffffffffff
         // 00402047: jz 0x4021bf
      [-]6a0468????????68????????6a00ff15
         // 00401f48: push 0x4
         // 00401f4a: push 0x1000
         // 00401f4f: push 0x19400
         // 00401f54: push 0x0
         // 00401f56: call ds:[VirtualAlloc]
      [-]8bf085f60f84
         // 00401f5c: mov esi, eax
         // 00401f5e: test esi, esi
         // 00401f60: jz 0x4020bc
      [-]68????????6a0056e8
         // 00402090: push 0x19400
         // 00402095: push 0x0
         // 00402097: push esi
         // 00402098: call _memset
      [-]83c40c6a006a00
         // 004020a1: add esp, 0xc
         // 004020a4: push 0x0
         // 004020a6: push 0x0
      [-]83f8ff0f84
         // 004020b0: cmp eax, 0xffffffffffffffff
         // 004020b3: jz 0x4021c5
      [-]5168????????8d96????????5250c7
         // 004020c3: push ecx
         // 004020c4: push 0x19000
         // 004020c9: lea edx, ds:[esi+0x114]
         // 004020cf: push edx
         // 004020d0: push eax
         // 004020d1: mov ss:[esp+0x24], 0x0
      [-]85c00f84
         // 004020df: test eax, eax
         // 004020e1: jz 0x4021e2
      [-]894e0c89
         // 004020f0: mov ds:[esi+0xc], ecx
         // 004020f3: mov ds:[esi+0x8], edi
      [-]08c706????????89
         // 004020f6: mov ds:[esi], 0x2
         // 004020fc: mov ds:[esi+0x4], ebp
      [-]f7ffff68????????8d
         // 00402104: push 0x103
         // 00402109: lea eax, ss:[esp+0x25]
      [-]000068????????8d
         // 0040211a: push 0x103
         // 0040211f: lea ecx, ss:[esp+0x135]
      [-]feffff68
         // 00402141: push 0x413d34
      [-]b8????????f7
         // 0040214b: mov eax, 0x51eb851f
         // 00402150: mul ebp
      [-]52b8????????f7
         // 00402158: push edx
         // 00402159: mov eax, 0x51eb851f
         // 0040215e: mul edi
      [-]f8ffff83c4
         // 00402196: add esp, 0x10
      [-]68????????ff15
         // 00402199: push 0x1f4
         // 0040219e: call ds:[0x40f0a4]
      [-]85f6740e
         // 004020c3: test esi, esi
         // 004020c5: jz 0x4020d5
      [-]68????????6a0056ff15
         // 004020c7: push 0x8000
         // 004020cc: push 0x0
         // 004020ce: push esi
         // 004020cf: call ds:[VirtualFree]
      [-]ffff83c4
         // 00402112: add esp, 0x4
      [-]000083c40c8d
         // 00402163: add esp, 0xc
         // 00402166: lea ecx, ss:[esp+0x40]
      [-]68????????89
         // 00402175: push 0x400
         // 0040217a: mov ss:[esp+0x84], eax
      [-]83c40c89
         // 004021d1: add esp, 0xc
         // 004021d4: mov ss:[esp+0x90], edx
      [-]8bc8c1e902f3a58bc883e1038d
         // 0040231a: mov ecx, eax
         // 0040231c: shr ecx, b1 0x2
         // 0040231f: rep movsdd 
         // 00402321: mov ecx, eax
         // 00402323: and ecx, 0x3
         // 00402326: lea eax, ss:[esp+0x8b]
      [-]f3a48d5001
         // 0040232d: rep movsbb 
         // 0040232f: lea edx, ds:[eax+0x1]
      [-]2bc20f84
         // 0040233b: sub eax, edx
         // 0040233d: jz 0x402437
      [-]68????????e8
         // 00402363: push 0x100000
         // 00402368: call 0x403e92
      [-]000068????????8b
         // 0040236d: push 0x100000
         // 00402372: mov ebx, eax
      [-]000083c41068????????c7
         // 0040237b: add esp, 0x10
         // 0040237e: push 0xbb8
         // 00402383: mov ss:[esp+0x14], 0x1
      [-]6a006a008d
         // 004023a3: push 0x0
         // 004023a5: push 0x0
         // 004023a7: lea eax, ss:[esp+0x18]
      [-]50be????????2b
         // 004023ab: push eax
         // 004023ac: mov esi, 0x100000
         // 004023b1: sub esi, ebp
      [-]5751ff15
         // 004023b7: push edi
         // 004023b8: push ecx
         // 004023b9: call ds:[0x40f04c]
      [-]52565750ff15
         // 004022ba: push edx
         // 004022bb: push esi
         // 004022bc: push edi
         // 004022bd: push eax
         // 004022be: call ds:[ReadFile]
      [-]85c07506
         // 004022c4: test eax, eax
         // 004022c6: jnz 0x4022ce
      [-]6a01ff15
         // 004023f5: push 0x1
         // 004023f7: call ds:[Sleep]
      [-]f4ffff8b
         // 00402344: mov eax, edi
      [-]83c00a50
         // 0040235b: add eax, 0xa
         // 0040235e: push eax
      [-]f5ffff83c4
         // 0040236a: add esp, 0xc
      [-]0fb6f0eb
         // 0040236d: movzx esi, b1 al
         // 00402370: jmp 0x40237a
      [-]83c40485f6
         // 0040231f: add esp, 0x4
         // 00402322: test esi, esi
      [-]81ec????????a1
         // 00402550: sub esp, 0x388
         // 00402556: mov eax, ds:[___security_cookie]
      [-]68????????8d
         // 00402564: push 0x383
         // 00402569: lea eax, ss:[esp+0x5]
      [-]6a0050c6
         // 0040256d: push 0x0
         // 0040256f: push eax
         // 00402570: mov b1 ss:[esp+0xc], b1 0x0
      [-]000083c40cff15
         // 0040257a: add esp, 0xc
         // 0040257d: call ds:[GetCurrentProcessId]
      [-]83c40c8d
         // 00402597: add esp, 0xc
         // 0040259d: lea ecx, ds:[ecx+0x0]
      [-]2bc268????????8d
         // 00402589: sub eax, edx
         // 0040258b: push 0x104
         // 00402590: lea edx, ss:[esp+eax+0x4]
      [-]526a00ff15
         // 00402594: push edx
         // 00402595: push 0x0
         // 00402597: call ds:[GetModuleFileNameA]
      [-]68????????
         // 004025bd: push 0x258
      [-]33c4898424
         // 00402801: xor eax, esp
         // 00402803: mov ss:[esp+0x250], eax
      [-]68????????8d
         // 0040280d: push 0x103
         // 00402812: lea eax, ss:[esp+0x14d]
      [-]000083c40c68????????8d
         // 00402827: add esp, 0xc
         // 0040282a: push 0x104
         // 0040282f: lea ecx, ss:[esp+0x14c]
      [-]000083c40885c0740d
         // 00402e80: add esp, 0x8
         // 00402e83: test eax, eax
         // 00402e85: jz 0x402e94
      [-]000083c40432c05dc3
         // 00402bbe: add esp, 0x4
         // 00402bc1: xor b1 al, b1 al
         // 00402bc3: pop ebp
         // 00402bc4: retn 
      [-]00008bf083c40885f67505
         // 00402a34: mov esi, eax
         // 00402a36: add esp, 0x8
         // 00402a39: test esi, esi
         // 00402a3b: jnz 0x402a42
      [-]53576a026a0056e8
         // 00402a42: push ebx
         // 00402a43: push edi
         // 00402a44: push 0x2
         // 00402a46: push 0x0
         // 00402a48: push esi
         // 00402a49: call _fseek
      [-]000056e8
         // 00402a4e: push esi
         // 00402a4f: call _ftell
      [-]00006a006a00568bf8e8
         // 00402a54: push 0x0
         // 00402a56: push 0x0
         // 00402a58: push esi
         // 00402a59: mov edi, eax
         // 00402a5b: call _fseek
      [-]000057e8
         // 00402a60: push edi
         // 00402a61: call _malloc
      [-]0000566a018bd85753e8
         // 00402a66: push esi
         // 00402a67: push 0x1
         // 00402a69: mov ebx, eax
         // 00402a6b: push edi
         // 00402a6c: push ebx
         // 00402a6d: call _fread
      [-]000056e8
         // 00402a72: push esi
         // 00402a73: call _fclose
      [-]000083c434ff15
         // 00402a78: add esp, 0x34
         // 00402a7b: call ds:[GetTickCount]
      [-]89443bf8e8
         // 00402a87: mov ds:[ebx+edi+0xfffffffffffffff8], eax
         // 00402a8b: call _fopen
      [-]00008bf0566a015753e8
         // 00402a90: mov esi, eax
         // 00402a92: push esi
         // 00402a93: push 0x1
         // 00402a95: push edi
         // 00402a96: push ebx
         // 00402a97: call _fwrite
      [-]000056e8
         // 00402a9c: push esi
         // 00402a9d: call _fclose
      [-]000083c41c
         // 00402aa2: add esp, 0x1c
      [-]83cfff3b
         // 00402b16: or edi, 0xffffffffffffffff
         // 00402b19: cmp ebx, edi
      [-]5068????????
         // 00402b25: push eax
         // 00402b26: push 0xf01ff
      [-]68????????6a206a028d
         // 00402b4a: push 0x220
         // 00402b4f: push 0x20
         // 00402b51: push 0x2
         // 00402b53: lea edx, ss:[esp+0x4c]
      [-]68????????e8
         // 00403285: push 0x400
         // 0040328a: call _malloc
      [-]000068????????8bf8
         // 0040328f: push 0x400
         // 00403294: mov edi, eax
      [-]83c4108d
         // 004032a1: add esp, 0x10
         // 004032a4: lea eax, ss:[esp+0x20]
      [-]5068????????576a0251ff15
         // 004032a8: push eax
         // 004032a9: push 0x400
         // 004032ae: push edi
         // 004032af: push 0x2
         // 004032b1: push ecx
         // 004032b2: call ds:[GetTokenInformation]
      [-]000083c404
         // 0040301a: add esp, 0x4
      [-]81ec????????a1
         // 00402c40: sub esp, 0x114
         // 00402c46: mov eax, ds:[___security_cookie]
      [-]68????????ff15
         // 00402c54: push 0x100
         // 00402c59: call ds:[GetCurrentProcess]
      [-]6a0fff15
         // 00402c66: push 0xf
         // 00402c68: call ds:[GetCurrentThread]
      [-]6a00506a
         // 00402c7a: push 0x0
         // 00402c7c: push eax
         // 00402c7d: push 0x1
      [-]6a04ff15
         // 00402c7f: push 0x4
         // 00402c81: call ds:[SHChangeNotify]
      [-]83c40c6a006a008d
         // 00402c9d: add esp, 0xc
         // 00402ca0: push 0x0
         // 00402ca2: push 0x0
         // 00402ca4: lea eax, ss:[esp+0x8]
      [-]6a00ff15
         // 00402cb3: push 0x0
         // 00402cb5: call ds:[ShellExecuteA]
      [-]6a00ff15
         // 00402cbb: push 0x0
         // 00402cbd: call ds:[ExitProcess]
      [-]ffffff59c3
         // 004090d8: pop ecx
         // 004090d9: retn 

  }
  condition:
    all of them
}
