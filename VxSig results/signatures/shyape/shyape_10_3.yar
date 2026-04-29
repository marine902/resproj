rule shyape_10_3 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         81ec????????a1
         // 00401003: sub esp, 0xa0
         // 00401009: mov eax, ds:[___security_cookie]
      [-]68????????8d
         // 00401013: push 0x98
         // 00401018: lea eax, ss:[ebp+0xffffffffffffff64]
      [-]6a0050e8
         // 0040101e: push 0x0
         // 00401020: push eax
         // 00401021: call _memset
      [-]000083c40c8d
         // 00401026: add esp, 0xc
         // 00401029: lea ecx, ss:[ebp+0xffffffffffffff60]
      [-]400085c075
         // 00401040: test eax, eax
         // 00401042: jnz 0x401052
      [-]010f95c08d4400048b
         // 00401070: setnz b1 al
         // 00401073: lea eax, ds:[eax+eax+0x4]
         // 00401077: mov ecx, ss:[esp+0x9c]
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
         // 00401269: mov ecx, eax
         // 0040126b: shr ecx, b1 0x2
         // 0040126e: rep movsdd 
         // 00401270: mov ecx, eax
         // 00401272: and ecx, 0x3
         // 00401275: rep movsbb 
         // 00401277: mov ecx, ss:[ebp+0xfffffffffffffffc]
      [-]68????????8d
         // 004012a3: push 0x103
         // 004012a8: lea eax, ss:[ebp+0xfffffffffffffef9]
      [-]6a0050c6
         // 004012ae: push 0x0
         // 004012b0: push eax
         // 004012b1: mov b1 ss:[ebp+0xfffffffffffffef8], b1 0x0
      [-]000083c40c68????????8d
         // 004012bd: add esp, 0xc
         // 004012c0: push 0x104
         // 004012c5: lea ecx, ss:[ebp+0xfffffffffffffef8]
      [-]516a00ff15
         // 004012cb: push ecx
         // 004012cc: push 0x0
         // 004012ce: call ds:[GetModuleFileNameA]
      [-]400085c075
         // 004012d4: test eax, eax
         // 004012d6: jnz 0x4012e8
      [-]52894804e8
         // 00401395: push edx
         // 00401396: mov ds:[eax+0x4], ecx
         // 00401399: call _fopen
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
      [-]400085c075
         // 0040146b: test eax, eax
         // 0040146d: jnz 0x40147b
      [-]5f32c05e
         // 004014b7: pop edi
         // 004014b8: xor b1 al, b1 al
         // 004014ba: pop esi
      [-]fdffff69f6????????
         // 00401481: imul esi, 0x1a4
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
      [-]00894810885014a1
         // 004016be: mov ds:[eax+0x10], ecx
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
      [-]894808668b
         // 00401777: mov ds:[eax+0x8], ecx
         // 0040177a: mov b2 cx, b2 ds:[0x40f244]
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
         // 0040180d: pop ebx
         // 0040180e: pop edi
         // 0040180f: xor b1 al, b1 al
         // 00401811: pop esi
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
         // 004017c8: push 0x0
         // 004017ca: push 0x1
         // 004017cc: call edi
      [-]000083c4
         // 00401812: add esp, 0x4
      [-]8d7c000257e8
         // 00401839: lea edi, ds:[eax+eax+0x2]
         // 0040183d: push edi
         // 0040183e: call _malloc
      [-]0000578bf06a0056e8
         // 00401843: push edi
         // 00401844: mov esi, eax
         // 00401846: push 0x0
         // 00401848: push esi
         // 00401849: call _memset
      [-]00008b3d
         // 0040184e: mov edi, ds:[MultiByteToWideChar]
      [-]400083c4106a00566aff
         // 00401854: add esp, 0x10
         // 00401857: push 0x0
         // 00401859: push esi
         // 0040185a: push 0xffffffffffffffff
      [-]6a0068????????ffd7
         // 0040185d: push 0x0
         // 0040185f: push 0xfde9
         // 00401864: call edi
      [-]6a0068????????ffd78b
         // 00401873: push 0x0
         // 00401875: push 0xfde9
         // 0040187a: call edi
         // 0040187c: mov ebx, ss:[esp+0x14]
      [-]006a006a006a00
         // 00401886: push 0x0
         // 00401888: push 0x0
         // 0040188a: push 0x0
      [-]6aff566a006a01ff
         // 0040188d: push 0xffffffffffffffff
         // 0040188f: push esi
         // 00401890: push 0x0
         // 00401892: push 0x1
         // 00401894: call edi
      [-]6a006a0050
         // 00401896: push 0x0
         // 00401898: push 0x0
         // 0040189a: push eax
      [-]6aff566a006a01ff
         // 0040189c: push 0xffffffffffffffff
         // 0040189e: push esi
         // 0040189f: push 0x0
         // 004018a1: push 0x1
         // 004018a3: call edi
      [-]85c0560f95c3e8
         // 004018a5: test eax, eax
         // 004018a7: push esi
         // 004018a8: setnz b1 bl
         // 004018ab: call _free
      [-]000083c4045f5e
         // 004018b0: add esp, 0x4
         // 004018b3: pop edi
         // 004018b4: pop esi
      [-]00008bd883c40485db0f84
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
      [-]897e048b0d
         // 00401957: mov ds:[esi+0x4], edi
         // 0040195a: mov ecx, ds:[0x414764]
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
         // 00401b95: push 0x12b
         // 00401b9a: lea eax, ss:[esp+0xd]
      [-]000083c40cff15
         // 00401bab: add esp, 0xc
         // 00401bae: call ds:[GetTickCount]
      [-]4000508d
         // 00401bb4: push eax
         // 00401bb5: lea ecx, ss:[esp+0xc]
      [-]83c40c6a0068????????6a006a008d
         // 00401bc9: add esp, 0xc
         // 00401bcc: push 0x0
         // 00401bce: push 0x100
         // 00401bd3: push 0x0
         // 00401bd5: push 0x0
         // 00401bd7: lea edx, ss:[esp+0x18]
      [-]000083c40c8d
         // 00401bee: add esp, 0xc
         // 00401bf1: lea edx, ss:[ebp+0xfffffffffffffec8]
      [-]400085c074
         // 00401c0f: test eax, eax
         // 00401c11: jz 0x401c1d
      [-]85c07409
         // 00401c47: test eax, eax
         // 00401c49: jz 0x401c54
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
         // 0040219e: call ds:[Sleep]
      [-]400085f6740e
         // 004020bb: test esi, esi
         // 004020bd: jz 0x4020cd
      [-]68????????6a0056ff15
         // 004020bf: push 0x8000
         // 004020c4: push 0x0
         // 004020c6: push esi
         // 004020c7: call ds:[VirtualFree]
      [-]ffff83c4
         // 00402224: add esp, 0x8
      [-]400085c075
         // 00402259: test eax, eax
         // 0040225b: jnz 0x402276
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
         // 00402240: push 0x100000
         // 00402245: call _malloc
      [-]000068????????8b
         // 0040224a: push 0x100000
         // 0040224f: mov ebx, eax
      [-]000083c41068????????c7
         // 00402258: add esp, 0x10
         // 0040225b: push 0xbb8
         // 00402260: mov ss:[esp+0x18], 0x1
      [-]6a006a008d
         // 00402280: push 0x0
         // 00402282: push 0x0
         // 00402284: lea eax, ss:[esp+0x1c]
      [-]50be????????2b
         // 00402288: push eax
         // 00402289: mov esi, 0x100000
         // 0040228e: sub esi, ebp
      [-]5751ff15
         // 00402294: push edi
         // 00402295: push ecx
         // 00402296: call ds:[PeekNamedPipe]
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
      [-]000083c40485f60f95c0
         // 0040244a: add esp, 0x4
         // 0040244e: test esi, esi
         // 00402452: setnz b1 al
      [-]81ec????????a1
         // 00402563: sub esp, 0x388
         // 00402569: mov eax, ds:[___security_cookie]
      [-]68????????8d
         // 00402573: push 0x383
         // 00402578: lea eax, ss:[ebp+0xfffffffffffffc79]
      [-]6a0050c6
         // 0040257e: push 0x0
         // 00402580: push eax
         // 00402581: mov b1 ss:[ebp+0xfffffffffffffc78], b1 0x0
      [-]000083c40cff15
         // 0040258d: add esp, 0xc
         // 00402590: call ds:[GetCurrentProcessId]
      [-]4000508d
         // 00402596: push eax
         // 00402597: lea ecx, ss:[ebp+0xfffffffffffffc78]
      [-]83c40c8d
         // 004025ae: add esp, 0xc
         // 004025b1: lea edx, ds:[eax+0x1]
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
      [-]000083c40c68????????8d
         // 0040298a: add esp, 0xc
         // 0040298d: push 0x104
         // 00402992: lea ecx, ss:[esp+0x4]
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
         // 00402ea4: mov esi, eax
         // 00402ea6: add esp, 0x8
         // 00402ea9: test esi, esi
         // 00402eab: jnz 0x402eb2
      [-]53576a026a0056e8
         // 00402eb2: push ebx
         // 00402eb3: push edi
         // 00402eb4: push 0x2
         // 00402eb6: push 0x0
         // 00402eb8: push esi
         // 00402eb9: call _fseek
      [-]000056e8
         // 00402ebe: push esi
         // 00402ebf: call _ftell
      [-]00006a006a00568bf8e8
         // 00402ec4: push 0x0
         // 00402ec6: push 0x0
         // 00402ec8: push esi
         // 00402ec9: mov edi, eax
         // 00402ecb: call _fseek
      [-]000057e8
         // 00402ed0: push edi
         // 00402ed1: call _malloc
      [-]0000566a018bd85753e8
         // 00402ed6: push esi
         // 00402ed7: push 0x1
         // 00402ed9: mov ebx, eax
         // 00402edb: push edi
         // 00402edc: push ebx
         // 00402edd: call _fread
      [-]000056e8
         // 00402ee2: push esi
         // 00402ee3: call _fclose
      [-]000083c434ff15
         // 00402ee8: add esp, 0x34
         // 00402eeb: call ds:[GetTickCount]
      [-]89443bf8e8
         // 00402ef7: mov ds:[ebx+edi+0xfffffffffffffff8], eax
         // 00402efb: call _fopen
      [-]00008bf0566a015753e8
         // 00402f00: mov esi, eax
         // 00402f02: push esi
         // 00402f03: push 0x1
         // 00402f05: push edi
         // 00402f06: push ebx
         // 00402f07: call _fwrite
      [-]000056e8
         // 00402f0c: push esi
         // 00402f0d: call _fclose
      [-]000083c41c
         // 00402f12: add esp, 0x1c
      [-]83cfff3b
         // 00403233: or edi, 0xffffffffffffffff
         // 00403236: cmp ebx, edi
      [-]5068????????
         // 00403242: push eax
         // 00403243: push 0xf01ff
      [-]400085c075
         // 0040324f: test eax, eax
         // 00403251: jnz 0x40325c
      [-]400085c075
         // 004032cf: test eax, eax
         // 004032d1: jnz 0x4032e3
      [-]000083c404
         // 0040301a: add esp, 0x4
      [-]81ec????????a1
         // 00403083: sub esp, 0x114
         // 00403089: mov eax, ds:[___security_cookie]
      [-]68????????ff15
         // 00403093: push 0x100
         // 00403098: call ds:[GetCurrentProcess]
      [-]400050ff15
         // 0040309e: push eax
         // 0040309f: call ds:[SetPriorityClass]
      [-]40006a0fff15
         // 004030a5: push 0xf
         // 004030a7: call ds:[GetCurrentThread]
      [-]400050ff15
         // 004030ad: push eax
         // 004030ae: call ds:[SetThreadPriority]
      [-]6a00506a
         // 004030b9: push 0x0
         // 004030bb: push eax
         // 004030bc: push 0x5
      [-]6a04ff15a0
         // 004030be: push 0x4
         // 004030c0: call ds:[SHChangeNotify]
      [-]40008b0d
         // 004030c6: mov ecx, ds:[0x4117a0]
      [-]83c40c6a006a008d
         // 004030de: add esp, 0xc
         // 004030e1: push 0x0
         // 004030e3: push 0x0
         // 004030e5: lea eax, ss:[ebp+0xfffffffffffffeec]
      [-]6a00ff15a8
         // 004030f6: push 0x0
         // 004030f8: call ds:[ShellExecuteA]
      [-]40006a00ff15
         // 004030fe: push 0x0
         // 00403100: call ds:[ExitProcess]

  }
  condition:
    all of them
}
