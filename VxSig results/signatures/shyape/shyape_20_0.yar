rule shyape_20_0 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         81ec????????a1
         // 00401000: sub esp, 0xa0
         // 00401006: mov eax, ds:[0x4129e8]
      [-]68????????8d
         // 00401014: push 0x98
         // 00401019: lea eax, ss:[esp+0x8]
      [-]6a0050e8
         // 0040101d: push 0x0
         // 0040101f: push eax
         // 00401020: call 0x403910
      [-]000083c40c8d
         // 00401025: add esp, 0xc
         // 00401028: lea ecx, ss:[esp]
      [-]010f95c08d4400048b
         // 00401070: setnz b1 al
         // 00401073: lea eax, ds:[eax+eax+0x4]
         // 00401077: mov ecx, ss:[esp+0x9c]
      [-]83f80175
         // 00401080: cmp eax, 0x1
         // 00401083: jnz 0x4010a0
      [-]010f95c08d4400058b
         // 0040109b: setnz b1 al
         // 0040109e: lea eax, ds:[eax+eax+0x5]
         // 004010a2: mov ecx, ss:[esp+0x9c]
      [-]83f80275
         // 004010a0: cmp eax, 0x2
         // 004010a3: jnz 0x401103
      [-]010f95c083c0088b
         // 004010c6: setnz b1 al
         // 004010c9: add eax, 0x8
         // 004010cc: mov ecx, ss:[esp+0x9c]
      [-]83f80575
         // 004010bf: cmp eax, 0x5
         // 004010c2: jnz 0x401103
      [-]83f80275
         // 004010ca: cmp eax, 0x2
         // 004010cd: jnz 0x4010e2
      [-]b8????????8b
         // 004010ef: mov eax, 0x3
         // 004010f4: mov ecx, ss:[esp+0x9c]
      [-]83f80175
         // 004010e2: cmp eax, 0x1
         // 004010e5: jnz 0x4010fa
      [-]b8????????8b
         // 0040110e: mov eax, 0x2
         // 00401113: mov ecx, ss:[esp+0x9c]
      [-]85c07505
         // 004010fa: test eax, eax
         // 004010fc: jnz 0x401103
      [-]b8????????
         // 004010fe: mov eax, 0x1
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
         // 00401230: sub esp, 0x18
         // 00401233: mov eax, ds:[___security_cookie]
      [-]5784c074
         // 0040124a: push edi
         // 0040124d: test b1 al, b1 al
         // 0040124f: jz 0x401275
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
         // 00401476: test b1 al, b1 al
         // 00401478: jnz 0x401480
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
         // 004014ea: mov ecx, eax
         // 004014ec: shr ecx, b1 0x2
         // 004014ef: rep movsdd 
         // 004014f1: mov ecx, eax
         // 004014f3: and ecx, 0x3
         // 004014f6: lea eax, ds:[ebx+0x32]
         // 004014f9: rep movsbb 
         // 004014fb: mov ecx, eax
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
         // 0040160f: lea eax, ds:[ebx+0x64]
         // 00401612: mov edx, 0x413b20
      [-]8a08880c02
         // 004015b7: mov b1 cl, b1 ds:[eax]
         // 004015b9: mov b1 ds:[edx+eax], b1 cl
      [-]2bc18bf1
         // 004015ed: sub eax, ecx
         // 004015ef: mov esi, ecx
      [-]8bc8c1e902f3a58bc883e103b8
         // 004015d9: mov ecx, eax
         // 004015db: shr ecx, b1 0x2
         // 004015de: rep movsdd 
         // 004015e0: mov ecx, eax
         // 004015e2: and ecx, 0x3
         // 004015e5: mov eax, 0x412508
      [-]89088b0d
         // 00401604: mov ds:[eax], ecx
         // 00401606: mov ecx, ds:[0x40eab4]
      [-]8950048b15
         // 0040160c: mov ds:[eax+0x4], edx
         // 0040160f: mov edx, ds:[0x40eab8]
      [-]8948088b0d
         // 00401615: mov ds:[eax+0x8], ecx
         // 00401618: mov ecx, ds:[0x40eabc]
      [-]89500c8a15
         // 0040161e: mov ds:[eax+0xc], edx
         // 00401621: mov b1 dl, b1 ds:[0x40eac0]
      [-]00894810885014a1
         // 00401627: mov ds:[eax+0x10], ecx
         // 00401630: mov b1 ds:[eax+0x14], b1 dl
         // 00401633: mov eax, ds:[0x40ea90]
      [-]2bc18bf1
         // 0040166e: sub eax, ecx
         // 00401670: mov esi, ecx
      [-]8bc8c1e902f3a58bc883e1038d83????????f3a48bc8
         // 00401660: mov ecx, eax
         // 00401662: shr ecx, b1 0x2
         // 00401665: rep movsdd 
         // 00401667: mov ecx, eax
         // 00401669: and ecx, 0x3
         // 0040166c: lea eax, ds:[ebx+0x96]
         // 00401672: rep movsbb 
         // 00401674: mov ecx, eax
      [-]2bc18bf1
         // 0040169d: sub eax, ecx
         // 0040169f: mov esi, ecx
      [-]8bc8c1e902f3a58bc883e103b8
         // 0040168f: mov ecx, eax
         // 00401691: shr ecx, b1 0x2
         // 00401694: rep movsdd 
         // 00401696: mov ecx, eax
         // 00401698: and ecx, 0x3
         // 0040169b: mov eax, 0x412608
      [-]2bc18bf1
         // 00401712: sub eax, ecx
         // 00401714: mov esi, ecx
      [-]8bc8c1e902f3a58bc883e103833d
         // 004017ba: mov ecx, eax
         // 004017bc: shr ecx, b1 0x2
         // 004017bf: rep movsdd 
         // 004017c1: mov ecx, eax
         // 004017c3: and ecx, 0x3
         // 004017c6: cmp ds:[0x413d58], 0x0
      [-]00f3a475
         // 004017cd: rep movsbb 
         // 004017cf: jnz 0x4017ed
      [-]6a006a006a006a0068
         // 00401736: push 0x0
         // 00401738: push 0x0
         // 0040173a: push 0x0
         // 0040173c: push 0x0
         // 0040173e: push 0x4104cc
      [-]000083c404
         // 00401763: add esp, 0x4
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
      [-]83c4106a00566aff
         // 004017b4: add esp, 0x10
         // 004017b7: push 0x0
         // 004017b9: push esi
         // 004017ba: push 0xffffffffffffffff
      [-]6a006a01ffd750566aff
         // 004017bd: push 0x0
         // 004017bf: push 0x1
         // 004017c1: call edi
         // 004017c3: push eax
         // 004017c4: push esi
         // 004017c5: push 0xffffffffffffffff
      [-]6a006a01ffd78b
         // 004017c8: push 0x0
         // 004017ca: push 0x1
         // 004017cc: call edi
         // 004017e7: mov edi, eax
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
      [-]83c4106a00566aff
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
      [-]6a006a006a00
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
      [-]000083c4045f5e5d
         // 004018b0: add esp, 0x4
         // 004018b3: pop edi
         // 004018b4: pop esi
         // 004018b5: pop ebp
      [-]5768????????
         // 004018f9: push edi
         // 004018fa: push 0xfa
      [-]00008bd883c40485db0f84
         // 0040190a: mov ebx, eax
         // 0040190c: add esp, 0x4
         // 0040190f: test ebx, ebx
         // 00401911: jz 0x401a54
      [-]68????????6a0053e8
         // 00401917: push 0xfa
         // 0040191c: push 0x0
         // 0040191e: push ebx
         // 0040191f: call _memset
      [-]000083c40cff15
         // 00401924: add esp, 0xc
         // 00401927: call ds:[GetTickCount]
      [-]83c71857e8
         // 0040193f: add edi, 0x18
         // 00401942: push edi
         // 00401943: call _malloc
      [-]00008bf083c41885f60f84
         // 00401948: mov esi, eax
         // 0040194a: add esp, 0x18
         // 0040194d: test esi, esi
         // 0040194f: jz 0x401a45
      [-]897e048b0d
         // 00401a39: mov ds:[esi+0x4], edi
         // 00401a3c: mov ecx, ds:[0x413d24]
      [-]000083c4
         // 00401a8c: add esp, 0x18
      [-]6a0068????????6a006a0068
         // 004019b2: push 0x0
         // 004019b4: push 0x100
         // 004019b9: push 0x0
         // 004019bb: push 0x0
         // 004019bd: push 0x40eae4
      [-]57566a006a00
         // 004019d6: push edi
         // 004019d7: push esi
         // 004019d8: push 0x0
         // 004019da: push 0x0
      [-]000083c404eb
         // 00401b1e: add esp, 0x4
         // 00401b21: jmp 0x401b2b
      [-]85f67409
         // 004019f6: test esi, esi
         // 004019f8: jz 0x401a03
      [-]000083c404
         // 00401b35: add esp, 0x4
      [-]81ec????????a1
         // 00401b70: sub esp, 0x134
         // 00401b76: mov eax, ds:[0x4129e8]
      [-]5668????????8d
         // 00401b84: push esi
         // 00401b85: push 0x12b
         // 00401b8a: lea eax, ss:[esp+0xd]
      [-]6a0050c6
         // 00401b8e: push 0x0
         // 00401b90: push eax
         // 00401b91: mov b1 ss:[esp+0x14], b1 0x0
      [-]000083c40cff15
         // 00401b9b: add esp, 0xc
         // 00401b9e: call ds:[0x40f0a8]
      [-]83c40c6a0068????????6a006a008d
         // 00401bb9: add esp, 0xc
         // 00401bbc: push 0x0
         // 00401bbe: push 0x100
         // 00401bc3: push 0x0
         // 00401bc5: push 0x0
         // 00401bc7: lea edx, ss:[esp+0x18]
      [-]5250ff15
         // 00401bcb: push edx
         // 00401bcc: push eax
         // 00401bcd: call ds:[0x40f1c0]
      [-]8bf085f674
         // 00401bd3: mov esi, eax
         // 00401bd5: test esi, esi
         // 00401bd7: jz 0x401c2b
      [-]85c0560f95c3ff15
         // 00401b05: test eax, eax
         // 00401b07: push esi
         // 00401b08: setnz b1 bl
         // 00401b0b: call ds:[InternetCloseHandle]
      [-]84db5b74
         // 00401b11: test b1 bl, b1 bl
         // 00401b13: pop ebx
         // 00401b14: jz 0x401b30
      [-]b0015e8b
         // 00401c13: mov b1 al, b1 0x1
         // 00401c15: pop esi
         // 00401c16: mov ecx, ss:[esp+0x130]
      [-]68????????8d
         // 00401c6d: push 0x12b
         // 00401c72: lea eax, ss:[esp+0x11]
      [-]000083c40cff15
         // 00401c83: add esp, 0xc
         // 00401c86: call ds:[GetTickCount]
      [-]83c40c6a0068????????6a006a008d
         // 00401ca1: add esp, 0xc
         // 00401ca4: push 0x0
         // 00401ca6: push 0x100
         // 00401cab: push 0x0
         // 00401cad: push 0x0
         // 00401caf: lea edx, ss:[esp+0x1c]
      [-]000083c40c8d
         // 00401ce2: add esp, 0xc
         // 00401ce5: lea eax, ss:[esp+0x8]
      [-]85c07409
         // 00401c47: test eax, eax
         // 00401c49: jz 0x401c54
      [-]000083c404
         // 00401d1c: add esp, 0x4
      [-]81ec????????a1
         // 00401da0: sub esp, 0x10c
         // 00401da6: mov eax, ds:[0x4129e8]
      [-]80781000538d581089
         // 00401dbb: cmp b1 ds:[eax+0x10], b1 0x0
         // 00401dbf: push ebx
         // 00401dc0: lea ebx, ds:[eax+0x10]
         // 00401dc3: mov ss:[esp+0x4], ebx
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
         // 00401e1c: sub esi, ecx
         // 00401e1e: lea edi, ds:[esi+0x6]
         // 00401e21: cmp esi, edi
         // 00401e23: jge 0x401e54
      [-]ffd333d2b9????????f7f16a0180c26188
         // 00401d50: call ebx
         // 00401d52: xor edx, edx
         // 00401d54: mov ecx, 0x1a
         // 00401d59: div ecx
         // 00401d5b: push 0x1
         // 00401d5d: add b1 dl, b1 0x61
         // 00401d60: mov b1 ss:[esp+esi+0x18], b1 dl
      [-]0089108848048d
         // 00401d7c: mov ds:[eax], edx
         // 00401d7e: mov b1 ds:[eax+0x4], b1 cl
         // 00401d81: lea eax, ss:[ebp+0xfffffffffffffef8]
      [-]8bd38bc82bd1
         // 00401d87: mov edx, ebx
         // 00401d89: mov ecx, eax
         // 00401d8b: sub edx, ecx
      [-]8a08880c02
         // 00401da0: mov b1 cl, b1 ds:[eax]
         // 00401da2: mov b1 ds:[edx+eax], b1 cl
      [-]535756e8
         // 00401dd1: push ebx
         // 00401dd2: push edi
         // 00401dd3: push esi
         // 00401dd4: call 0x401cc0
      [-]feffff8d7e10
         // 00401dd9: lea edi, ds:[esi+0x10]
      [-]faffff83c4
         // 00401de6: add esp, 0x8
      [-]833e01740a
         // 00401de9: cmp ds:[esi], 0x1
         // 00401dec: jz 0x401df8
      [-]83f8ff7523
         // 00401ed6: cmp eax, 0xffffffffffffffff
         // 00401ed9: jnz 0x401efe
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
         // 00401e59: cmp ds:[esi], 0x3
         // 00401e5c: jnz 0x401e82
      [-]6a0057ff15
         // 00401e96: push 0x0
         // 00401e98: push edi
         // 00401e99: call ds:[WinExec]
      [-]2bc28bc885c97e
         // 00401e9f: sub eax, edx
         // 00401ea1: mov ecx, eax
         // 00401ea3: test ecx, ecx
         // 00401ea5: jle 0x401eb2
      [-]803c385c74
         // 00401ea7: cmp b1 ds:[eax+edi], b1 0x5c
         // 00401eab: jz 0x401eb2
      [-]8a540701881406
         // 00401ee0: mov b1 dl, b1 ds:[edi+eax+0x1]
         // 00401ee4: mov b1 ds:[esi+eax], b1 dl
      [-]576a0068????????6a036a006a01
         // 0040200c: push edi
         // 0040200d: push 0x0
         // 0040200f: push 0x80
         // 00402014: push 0x3
         // 00402016: push 0x0
         // 00402018: push 0x1
      [-]68????????
         // 0040201a: push 0xffffffff80000000
      [-]566a006a006a00
         // 00402036: push esi
         // 00402037: push 0x0
         // 00402039: push 0x0
         // 0040203b: push 0x0
      [-]83f8ff0f84
         // 00402044: cmp eax, 0xffffffffffffffff
         // 00402047: jz 0x4021bf
      [-]6a0468????????68????????6a00ff15
         // 00401f64: push 0x4
         // 00401f66: push 0x1000
         // 00401f6b: push 0x19400
         // 00401f70: push 0x0
         // 00401f72: call ds:[VirtualAlloc]
      [-]8bf085f60f84
         // 00401f78: mov esi, eax
         // 00401f7a: test esi, esi
         // 00401f7c: jz 0x4020b4
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
      [-]85f6740e
         // 004020bb: test esi, esi
         // 004020bd: jz 0x4020cd
      [-]68????????6a0056ff15
         // 004020bf: push 0x8000
         // 004020c4: push 0x0
         // 004020c6: push esi
         // 004020c7: call ds:[VirtualFree]
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
         // 00402307: push edx
         // 00402308: push esi
         // 00402309: push edi
         // 0040230a: push eax
         // 0040230b: call ds:[ReadFile]
      [-]85c07506
         // 00402311: test eax, eax
         // 00402313: jnz 0x40231b
      [-]6a01ff15
         // 004023f5: push 0x1
         // 004023f7: call ds:[0x40f0a4]
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
         // 004025a7: sub eax, edx
         // 004025a9: push 0x104
         // 004025ae: lea edx, ss:[esp+eax+0x4]
      [-]526a00ff15
         // 004025b2: push edx
         // 004025b3: push 0x0
         // 004025b5: call ds:[GetModuleFileNameA]
      [-]68????????
         // 004025d4: push 0x258
      [-]33c4898424
         // 00402ac1: xor eax, esp
         // 00402ac3: mov ss:[esp+0x250], eax
      [-]68????????8d
         // 00402acd: push 0x103
         // 00402ad2: lea eax, ss:[esp+0x14d]
      [-]000083c40c68????????8d
         // 00402ae7: add esp, 0xc
         // 00402aea: push 0x104
         // 00402aef: lea ecx, ss:[esp+0x14c]
      [-]000083c40885c0740d
         // 00402a10: add esp, 0x8
         // 00402a13: test eax, eax
         // 00402a15: jz 0x402a24
      [-]000083c40432c05dc3
         // 00402a1d: add esp, 0x4
         // 00402a20: xor b1 al, b1 al
         // 00402a22: pop ebp
         // 00402a23: retn 
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
         // 00402b68: push 0x400
         // 00402b6d: call 0x403e92
      [-]000068????????8bf8
         // 00402b72: push 0x400
         // 00402b77: mov edi, eax
      [-]83c4108d
         // 00402b84: add esp, 0x10
         // 00402b87: lea eax, ss:[esp+0x20]
      [-]5068????????576a0251ff15
         // 00402b8b: push eax
         // 00402b8c: push 0x400
         // 00402b91: push edi
         // 00402b92: push 0x2
         // 00402b94: push ecx
         // 00402b95: call ds:[0x40f018]
      [-]000083c404
         // 00402bee: add esp, 0x4
      [-]81ec????????a1
         // 00403360: sub esp, 0x114
         // 00403366: mov eax, ds:[___security_cookie]
      [-]68????????ff15
         // 00403374: push 0x100
         // 00403379: call ds:[GetCurrentProcess]
      [-]6a0fff15
         // 00403386: push 0xf
         // 00403388: call ds:[GetCurrentThread]
      [-]6a00506a
         // 0040339a: push 0x0
         // 0040339c: push eax
         // 0040339d: push 0x1
      [-]6a04ff15
         // 0040339f: push 0x4
         // 004033a1: call ds:[SHChangeNotify]
      [-]83c40c6a006a008d
         // 004033bd: add esp, 0xc
         // 004033c0: push 0x0
         // 004033c2: push 0x0
         // 004033c4: lea eax, ss:[esp+0x8]
      [-]6a00ff15
         // 004033d3: push 0x0
         // 004033d5: call ds:[ShellExecuteA]
      [-]6a00ff15
         // 004033db: push 0x0
         // 004033dd: call ds:[ExitProcess]

  }
  condition:
    all of them
}
