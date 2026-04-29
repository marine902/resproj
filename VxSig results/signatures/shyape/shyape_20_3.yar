rule shyape_20_3 {
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
      [-]400085c075
         // 0040103a: test eax, eax
         // 0040103c: jnz 0x401053
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
         // 004010e7: mov eax, 0x2
         // 004010ec: mov ecx, ss:[ebp+0xfffffffffffffffc]
      [-]85c07505
         // 00401128: test eax, eax
         // 0040112a: jnz 0x401131
      [-]b8????????
         // 0040112c: mov eax, 0x1
      [-]81ec????????a1
         // 00401170: sub esp, 0x810
         // 00401176: mov eax, ds:[___security_cookie]
      [-]5333db68????????8d
         // 00401184: push ebx
         // 00401185: xor ebx, ebx
         // 00401187: push 0x3ff
         // 0040118c: lea eax, ss:[esp+0x415]
      [-]000068????????8d
         // 004011a1: push 0x3ff
         // 004011a6: lea ecx, ss:[esp+0x21]
      [-]000083c41868????????8d
         // 004011c1: add esp, 0x18
         // 004011c4: push 0x400
         // 004011c9: lea edx, ss:[esp+0x14]
      [-]5268????????8d
         // 004011dc: push edx
         // 004011dd: push 0x400
         // 004011e2: lea eax, ss:[esp+0x428]
      [-]f7d81bc023
         // 004011fc: neg eax
         // 004011fe: sbb eax, eax
         // 00401200: and eax, ss:[esp+0x4]
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
         // 004012f4: push 0x103
         // 004012f9: lea eax, ss:[esp+0x5]
      [-]6a0050c6
         // 004012fd: push 0x0
         // 004012ff: push eax
         // 00401300: mov b1 ss:[esp+0xc], b1 0x0
      [-]000083c40c68????????8d
         // 0040130a: add esp, 0xc
         // 0040130d: push 0x104
         // 00401312: lea ecx, ss:[esp+0x4]
      [-]516a00ff15
         // 00401316: push ecx
         // 00401317: push 0x0
         // 00401319: call ds:[GetModuleFileNameA]
      [-]400085c075
         // 0040131f: test eax, eax
         // 00401321: jnz 0x40133a
      [-]52894804e8
         // 00401395: push edx
         // 00401396: mov ds:[eax+0x4], ecx
         // 00401399: call _fopen
      [-]83c40885
         // 004013a0: add esp, 0x8
         // 004013a3: test esi, esi
      [-]6a026a00
         // 004013c1: push 0x2
         // 004013c3: push 0x0
      [-]00006a006a00
         // 004013d1: push 0x0
         // 004013d3: push 0x0
      [-]feffff84c07506
         // 0040141b: test b1 al, b1 al
         // 0040141d: jnz 0x401425
      [-]400085c075
         // 0040146b: test eax, eax
         // 0040146d: jnz 0x40147b
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
         // 0040155d: mov ecx, eax
         // 0040155f: shr ecx, b1 0x2
         // 00401562: rep movsdd 
         // 00401564: mov ecx, eax
         // 00401566: and ecx, 0x3
         // 00401569: lea eax, ds:[ebx+0x32]
         // 0040156c: rep movsbb 
         // 0040156e: mov ecx, eax
      [-]2bc18bf1
         // 0040157e: sub eax, ecx
         // 00401580: mov esi, ecx
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
         // 004015b2: sub eax, ecx
         // 004015b4: mov esi, ecx
      [-]8bc8c1e902f3a58bc883e103b8
         // 00401569: mov ecx, eax
         // 0040156b: shr ecx, b1 0x2
         // 0040156e: rep movsdd 
         // 00401570: mov ecx, eax
         // 00401572: and ecx, 0x3
         // 00401575: mov eax, 0x414460
      [-]0c8d4364ba
         // 0040160f: lea eax, ds:[ebx+0x64]
         // 00401612: mov edx, 0x413b20
      [-]8a08880c02
         // 004015b7: mov b1 cl, b1 ds:[eax]
         // 004015b9: mov b1 ds:[edx+eax], b1 cl
      [-]2bc18bf1
         // 0040165e: sub eax, ecx
         // 00401660: mov esi, ecx
      [-]8bc8c1e902f3a58bc883e103b8
         // 004015fa: mov ecx, eax
         // 004015fc: shr ecx, b1 0x2
         // 004015ff: rep movsdd 
         // 00401601: mov ecx, eax
         // 00401603: and ecx, 0x3
         // 00401606: mov eax, 0x414560
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
         // 004016ee: sub eax, ecx
         // 004016f0: mov esi, ecx
      [-]8bc8c1e902f3a58bc883e1038d83????????f3a48bc8
         // 004016ff: mov ecx, eax
         // 00401701: shr ecx, b1 0x2
         // 00401704: rep movsdd 
         // 00401706: mov ecx, eax
         // 00401708: and ecx, 0x3
         // 0040170b: lea eax, ds:[ebx+0x96]
         // 00401711: rep movsbb 
         // 00401713: mov ecx, eax
      [-]2bc18bf1
         // 00401723: sub eax, ecx
         // 00401725: mov esi, ecx
      [-]8bc8c1e902f3a58bc883e103b8
         // 0040173a: mov ecx, eax
         // 0040173c: shr ecx, b1 0x2
         // 0040173f: rep movsdd 
         // 00401741: mov ecx, eax
         // 00401743: and ecx, 0x3
         // 00401746: mov eax, 0x413c20
      [-]2bc18bf1
         // 004017a6: sub eax, ecx
         // 004017a8: mov esi, ecx
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
         // 00401799: lea edi, ds:[eax+eax+0x2]
         // 0040179d: push edi
         // 0040179e: call _malloc
      [-]0000578bf06a0056e8
         // 004017a3: push edi
         // 004017a4: mov esi, eax
         // 004017a6: push 0x0
         // 004017a8: push esi
         // 004017a9: call _memset
      [-]6a006a01ffd7
         // 004017bd: push 0x0
         // 004017bf: push 0x1
         // 004017c1: call edi
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
      [-]400083c4106a00566aff
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
      [-]006a006a006a00
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
         // 004018d5: push edi
         // 004018d6: push 0xfa
      [-]00008bd883c40485db0f8401
         // 004018e5: mov ebx, eax
         // 004018e7: add esp, 0x4
         // 004018ea: test ebx, ebx
         // 004018ec: jz 0x4019f3
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
         // 00401990: add esp, 0xc
      [-]6a0068????????6a006a0068
         // 00401aa9: push 0x0
         // 00401aab: push 0x100
         // 00401ab0: push 0x0
         // 00401ab2: push 0x0
         // 00401ab4: push 0x40f284
      [-]57566a006a00
         // 004019ff: push edi
         // 00401a00: push esi
         // 00401a01: push 0x0
         // 00401a03: push 0x0
      [-]400083f801
         // 00401a0c: cmp eax, 0x1
      [-]000083c404eb
         // 00401a4f: add esp, 0x4
         // 00401a52: jmp 0x401a5c
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
      [-]4000508d
         // 00401aa7: push eax
         // 00401aa8: lea ecx, ss:[ebp+0xfffffffffffffed0]
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
      [-]40008bf085f674
         // 00401ada: mov esi, eax
         // 00401adc: test esi, esi
         // 00401ade: jz 0x401b30
      [-]400085c0560f95c3ff15
         // 00401b05: test eax, eax
         // 00401b07: push esi
         // 00401b08: setnz b1 bl
         // 00401b0b: call ds:[InternetCloseHandle]
      [-]400084db5b74
         // 00401b11: test b1 bl, b1 bl
         // 00401b13: pop ebx
         // 00401b14: jz 0x401b30
      [-]b0015e8b
         // 00401b42: mov b1 al, b1 0x1
         // 00401b44: pop esi
         // 00401b45: mov ecx, ss:[esp+0x130]
      [-]68????????8d
         // 00401b67: push 0x12b
         // 00401b6c: lea ecx, ss:[ebp+0xfffffffffffffed1]
      [-]000083c40cff15
         // 00401b87: add esp, 0xc
         // 00401b8a: call ds:[GetTickCount]
      [-]4000508d
         // 00401b90: push eax
         // 00401b91: lea edx, ss:[ebp+0xfffffffffffffed0]
      [-]83c40c6a0068????????6a006a008d
         // 00401ba8: add esp, 0xc
         // 00401bab: push 0x0
         // 00401bad: push 0x100
         // 00401bb2: push 0x0
         // 00401bb4: push 0x0
         // 00401bb6: lea eax, ss:[ebp+0xfffffffffffffed0]
      [-]000083c40c8d
         // 00401bee: add esp, 0xc
         // 00401bf1: lea edx, ss:[ebp+0xfffffffffffffec8]
      [-]400085c074
         // 00401c0f: test eax, eax
         // 00401c11: jz 0x401c1d
      [-]40008b85
         // 00401c43: mov eax, ss:[esp+0x8]
         // 00401c47: test eax, eax
      [-]000083c404
         // 00401c34: add esp, 0x4
      [-]81ec????????a1
         // 00401cb3: sub esp, 0x10c
         // 00401cb9: mov eax, ds:[___security_cookie]
      [-]80781000538d581089
         // 00401cc6: cmp b1 ds:[eax+0x10], b1 0x0
         // 00401cca: push ebx
         // 00401ccb: lea ebx, ds:[eax+0x10]
         // 00401cce: mov ss:[ebp+0xfffffffffffffef4], ebx
      [-]32c05b8b
         // 00401ce9: xor b1 al, b1 al
         // 00401ceb: pop ebx
         // 00401cec: mov ecx, ss:[esp+0x108]
      [-]565768????????8d
         // 00401d01: push esi
         // 00401d02: push edi
         // 00401d03: push 0x103
         // 00401d08: lea eax, ss:[esp+0x15]
      [-]6a0050c6
         // 00401d0c: push 0x0
         // 00401d0e: push eax
         // 00401d0f: mov b1 ss:[esp+0x1c], b1 0x0
      [-]000083c40c8d
         // 00401d19: add esp, 0xc
         // 00401d1c: lea ecx, ss:[esp+0x10]
      [-]5168????????ff15
         // 00401d20: push ecx
         // 00401d21: push 0x104
         // 00401d26: call ds:[GetTempPathA]
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
         // 00401d8b: mov ds:[eax], edx
         // 00401d8d: mov b1 ds:[eax+0x4], b1 cl
         // 00401d90: lea eax, ss:[esp+0x8]
      [-]8bd38bc82bd1
         // 00401d94: mov edx, ebx
         // 00401d96: mov ecx, eax
         // 00401d98: sub edx, ecx
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
         // 00401df3: cmp eax, 0xffffffffffffffff
         // 00401df6: jnz 0x401e1b
      [-]6a0068????????6a016a006a0068????????57ff15
         // 00401df8: push 0x0
         // 00401dfa: push 0x80
         // 00401dff: push 0x1
         // 00401e01: push 0x0
         // 00401e03: push 0x0
         // 00401e05: push 0x40000000
         // 00401e0a: push edi
         // 00401e0b: call ds:[CreateFileA]
      [-]8b4e086a006a005150ff15
         // 00401e1b: mov ecx, ds:[esi+0x8]
         // 00401e1e: push 0x0
         // 00401e20: push 0x0
         // 00401e22: push ecx
         // 00401e23: push eax
         // 00401e24: call ds:[SetFilePointer]
      [-]400083f8ff74
         // 00401e2a: cmp eax, 0xffffffffffffffff
         // 00401e2d: jz 0x401e5a
      [-]8b460c6a008d
         // 00401e2f: mov eax, ds:[esi+0xc]
         // 00401e32: push 0x0
         // 00401e34: lea edx, ss:[esp+0xc]
      [-]508d8e????????5152c7
         // 00401e3f: push eax
         // 00401e40: lea ecx, ds:[esi+0x114]
         // 00401e46: push ecx
         // 00401e47: push edx
         // 00401e48: mov ss:[esp+0x1c], 0x0
      [-]400085c075
         // 00401e56: test eax, eax
         // 00401e58: jnz 0x401e76
      [-]4000c705
         // 00401e66: mov ds:[0x4139e4], 0xffffffffffffffff
      [-]833e037524
         // 00401f59: cmp ds:[esi], 0x3
         // 00401f5c: jnz 0x401f82
      [-]6a0057ff15
         // 00401e96: push 0x0
         // 00401e98: push edi
         // 00401e99: call ds:[WinExec]
      [-]2bc28bc885c97e
         // 00401fa9: sub eax, edx
         // 00401fab: mov ecx, eax
         // 00401fad: test ecx, ecx
         // 00401faf: jle 0x401fbe
      [-]803c385c74
         // 00401fb1: cmp b1 ds:[eax+edi], b1 0x5c
         // 00401fb5: jz 0x401fbe
      [-]8a540701881406
         // 00401ee0: mov b1 dl, b1 ds:[edi+eax+0x1]
         // 00401ee4: mov b1 ds:[esi+eax], b1 dl
      [-]576a0068????????6a036a006a01
         // 00401ee4: push edi
         // 00401ee5: push 0x0
         // 00401ee7: push 0x80
         // 00401eec: push 0x3
         // 00401eee: push 0x0
         // 00401ef0: push 0x1
      [-]68????????
         // 00401ef4: push 0xffffffff80000000
      [-]566a006a006a00
         // 00401f31: push esi
         // 00401f32: push 0x0
         // 00401f34: push 0x0
         // 00401f36: push 0x0
      [-]400083f8ff0f84
         // 00401f3f: cmp eax, 0xffffffffffffffff
         // 00401f42: jz 0x4020aa
      [-]6a0468????????68????????6a00ff15
         // 00401f64: push 0x4
         // 00401f66: push 0x1000
         // 00401f6b: push 0x19400
         // 00401f70: push 0x0
         // 00401f72: call ds:[VirtualAlloc]
      [-]40008bf085f60f84
         // 00401f78: mov esi, eax
         // 00401f7a: test esi, esi
         // 00401f7c: jz 0x4020b4
      [-]68????????6a0056e8
         // 00401f84: push 0x19400
         // 00401f89: push 0x0
         // 00401f8b: push esi
         // 00401f8c: call _memset
      [-]83c40c6a006a00
         // 00401f95: add esp, 0xc
         // 00401f98: push 0x0
         // 00401f9a: push 0x0
      [-]400083f8ff0f84
         // 00401fa4: cmp eax, 0xffffffffffffffff
         // 00401fa7: jz 0x4020b0
      [-]5168????????8d96????????5250c7
         // 00401fb7: push ecx
         // 00401fb8: push 0x19000
         // 00401fbd: lea edx, ds:[esi+0x114]
         // 00401fc3: push edx
         // 00401fc4: push eax
         // 00401fc5: mov ss:[esp+0x24], 0x0
      [-]400085c00f84
         // 00401fd3: test eax, eax
         // 00401fd5: jz 0x4020cd
      [-]894e0c89
         // 00401fe3: mov ds:[esi+0xc], ecx
         // 00401fe6: mov ds:[esi+0x8], ebp
      [-]08c706????????89
         // 00401fe9: mov ds:[esi], 0x2
         // 00401fef: mov ds:[esi+0x4], ebx
      [-]f7ffff68????????8d
         // 00401ff7: push 0x103
         // 00401ffc: lea edx, ss:[esp+0x21]
      [-]000068????????8d
         // 0040200d: push 0x103
         // 00402012: lea eax, ss:[esp+0x131]
      [-]feffff68
         // 00402033: push 0x414774
      [-]b8????????f7
         // 0040203d: mov eax, 0x51eb851f
         // 00402042: mul ebx
      [-]52b8????????f7
         // 00402048: push edx
         // 00402049: mov eax, 0x51eb851f
         // 0040204e: mul ebp
      [-]f8ffff83c4
         // 00402081: add esp, 0x44
      [-]68????????ff15
         // 00402084: push 0x1f4
         // 00402089: call ds:[Sleep]
      [-]400085f6740e
         // 004020bb: test esi, esi
         // 004020bd: jz 0x4020cd
      [-]68????????6a0056ff15
         // 004020bf: push 0x8000
         // 004020c4: push 0x0
         // 004020c6: push esi
         // 004020c7: call ds:[VirtualFree]
      [-]ffff83c4
         // 00402112: add esp, 0x4
      [-]400085c075
         // 00402147: test eax, eax
         // 00402149: jnz 0x402152
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
         // 004021f9: mov ecx, eax
         // 004021fb: shr ecx, b1 0x2
         // 004021fe: rep movsdd 
         // 00402200: mov ecx, eax
         // 00402202: and ecx, 0x3
         // 00402205: lea eax, ss:[esp+0x93]
      [-]f3a48d5001
         // 0040220c: rep movsbb 
         // 0040220e: lea edx, ds:[eax+0x1]
      [-]2bc20f84
         // 00402218: sub eax, edx
         // 0040221a: jz 0x402313
      [-]400068????????e8
         // 00402363: push 0x100000
         // 00402368: call _malloc
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
         // 004023b9: call ds:[PeekNamedPipe]
      [-]40008b85
         // 004023bf: mov eax, ss:[esp+0x10]
         // 004023c3: test eax, eax
      [-]52565750ff15
         // 004022ba: push edx
         // 004022bb: push esi
         // 004022bc: push edi
         // 004022bd: push eax
         // 004022be: call ds:[ReadFile]
      [-]400085c07506
         // 004022c4: test eax, eax
         // 004022c6: jnz 0x4022ce
      [-]6a01ff15
         // 004022d2: push 0x1
         // 004022d4: call ds:[Sleep]
      [-]f4ffff8b
         // 00402344: mov eax, edi
      [-]83c00a50
         // 004022fc: add eax, 0xa
         // 004022ff: push eax
      [-]f5ffff83c4
         // 0040230b: add esp, 0xc
      [-]0fb6f0eb
         // 0040230e: movzx esi, b1 al
         // 00402311: jmp 0x402319
      [-]83c40485f6
         // 0040244a: add esp, 0x4
         // 0040244e: test esi, esi
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
      [-]4000508d
         // 00402583: push eax
         // 00402584: lea ecx, ss:[esp+0x4]
      [-]83c40c8d
         // 00402597: add esp, 0xc
         // 0040259a: lea edx, ds:[eax+0x1]
      [-]2bc268????????8d
         // 004025bb: sub eax, edx
         // 004025bd: push 0x104
         // 004025c2: lea edx, ss:[ebp+eax+0xfffffffffffffc78]
      [-]526a00ff15
         // 004025c9: push edx
         // 004025ca: push 0x0
         // 004025cc: call ds:[GetModuleFileNameA]
      [-]68????????
         // 004025ec: push 0x258
         // 004025f2: mov ecx, 0x412714
      [-]33c4898424
         // 0040296b: xor eax, esp
         // 0040296d: mov ss:[esp+0x104], eax
      [-]68????????8d
         // 00402974: push 0x103
         // 00402979: lea eax, ss:[esp+0x5]
      [-]000083c40c68????????8d
         // 0040298a: add esp, 0xc
         // 0040298d: push 0x104
         // 00402992: lea ecx, ss:[esp+0x4]
      [-]000083c40885c0740d
         // 00402a10: add esp, 0x8
         // 00402a13: test eax, eax
         // 00402a15: jz 0x402a24
      [-]000083c40432c05dc3
         // 00402bbe: add esp, 0x4
         // 00402bc1: xor b1 al, b1 al
         // 00402bc3: pop ebp
         // 00402bc4: retn 
      [-]00008bf083c40885f67505
         // 00402ea4: mov esi, eax
         // 00402ea6: add esp, 0x8
         // 00402ea9: test esi, esi
         // 00402eab: jnz 0x402eb2
      [-]53576a026a0056e8
         // 00402be2: push ebx
         // 00402be3: push edi
         // 00402be4: push 0x2
         // 00402be6: push 0x0
         // 00402be8: push esi
         // 00402be9: call _fseek
      [-]000056e8
         // 00402bee: push esi
         // 00402bef: call _ftell
      [-]00006a006a00568bf8e8
         // 00402bf4: push 0x0
         // 00402bf6: push 0x0
         // 00402bf8: push esi
         // 00402bf9: mov edi, eax
         // 00402bfb: call _fseek
      [-]000057e8
         // 00402c00: push edi
         // 00402c01: call _malloc
      [-]0000566a018bd85753e8
         // 00402c06: push esi
         // 00402c07: push 0x1
         // 00402c09: mov ebx, eax
         // 00402c0b: push edi
         // 00402c0c: push ebx
         // 00402c0d: call _fread
      [-]000056e8
         // 00402c12: push esi
         // 00402c13: call _fclose
      [-]000083c434ff15
         // 00402c18: add esp, 0x34
         // 00402c1b: call ds:[GetTickCount]
      [-]89443bf8e8
         // 00402c2a: mov ds:[ebx+edi+0xfffffffffffffff8], eax
         // 00402c2e: call _fopen
      [-]00008bf0566a015753e8
         // 00402c33: mov esi, eax
         // 00402c35: push esi
         // 00402c36: push 0x1
         // 00402c38: push edi
         // 00402c39: push ebx
         // 00402c3a: call _fwrite
      [-]000056e8
         // 00402c3f: push esi
         // 00402c40: call _fclose
      [-]000083c41c
         // 00402c45: add esp, 0x1c
      [-]fdffffe8
         // 004031c5: call 0x402900
      [-]85c07402
         // 00409422: test eax, eax
         // 00409424: jz 0x409428
      [-]85c07402
         // 00409446: test eax, eax
         // 00409448: jz 0x40944c

  }
  condition:
    all of them
}
