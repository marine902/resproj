rule shyape_10_4 {
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
         // 00401080: cmp eax, 0x1
         // 00401083: jnz 0x4010a0
      [-]010f95c08d4400058b
         // 0040108b: setnz b1 al
         // 0040108e: lea eax, ds:[eax+eax+0x5]
         // 00401092: mov ecx, ss:[ebp+0xfffffffffffffffc]
      [-]83f80275
         // 004010a0: cmp eax, 0x2
         // 004010a3: jnz 0x401103
      [-]010f95c083c0088b
         // 004010ab: setnz b1 al
         // 004010ae: add eax, 0x8
         // 004010b1: mov ecx, ss:[ebp+0xfffffffffffffffc]
      [-]83f80575
         // 004010bf: cmp eax, 0x5
         // 004010c2: jnz 0x401103
      [-]83f80275
         // 004010ca: cmp eax, 0x2
         // 004010cd: jnz 0x4010e2
      [-]b8????????8b
         // 004010cf: mov eax, 0x3
         // 004010d4: mov ecx, ss:[ebp+0xfffffffffffffffc]
      [-]83f80175
         // 004010e2: cmp eax, 0x1
         // 004010e5: jnz 0x4010fa
      [-]b8????????8b
         // 004010e7: mov eax, 0x2
         // 004010ec: mov ecx, ss:[ebp+0xfffffffffffffffc]
      [-]85c07505
         // 004010fa: test eax, eax
         // 004010fc: jnz 0x401103
      [-]b8????????
         // 004010fe: mov eax, 0x1
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
         // 004011d3: sub esp, 0x18
         // 004011d6: mov eax, ds:[0x410004]
      [-]5784c074
         // 004011e8: push edi
         // 004011e9: test b1 al, b1 al
         // 004011eb: jz 0x40120f
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
         // 00401357: push 0x2
         // 00401359: push 0x0
      [-]00006a006a00
         // 00401367: push 0x0
         // 00401369: push 0x0
      [-]feffff84c07506
         // 00401476: test b1 al, b1 al
         // 00401478: jnz 0x401480
      [-]400085c075
         // 004014ad: test eax, eax
         // 004014af: jnz 0x4014bd
      [-]5f32c05e
         // 00401475: pop edi
         // 00401476: xor b1 al, b1 al
         // 00401478: pop esi
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
         // 0040150c: sub eax, ecx
         // 0040150e: mov esi, ecx
      [-]8bc8c1e902f3a58bc883e103b8
         // 00401519: mov ecx, eax
         // 0040151b: shr ecx, b1 0x2
         // 0040151e: rep movsdd 
         // 00401520: mov ecx, eax
         // 00401522: and ecx, 0x3
         // 00401525: mov eax, 0x412714
      [-]f3a48bc8
         // 0040152a: rep movsbb 
         // 0040152c: mov ecx, eax
      [-]2bc18bf1
         // 0040153c: sub eax, ecx
         // 0040153e: mov esi, ecx
      [-]8bc8c1e902f3a58bc883e103b8
         // 00401549: mov ecx, eax
         // 0040154b: shr ecx, b1 0x2
         // 0040154e: rep movsdd 
         // 00401550: mov ecx, eax
         // 00401552: and ecx, 0x3
         // 00401555: mov eax, 0x412408
      [-]0c8d4364ba
         // 0040160f: lea eax, ds:[ebx+0x64]
         // 00401612: mov edx, 0x413b20
      [-]8a08880c02
         // 00401597: mov b1 cl, b1 ds:[eax]
         // 00401599: mov b1 ds:[edx+eax], b1 cl
      [-]2bc18bf1
         // 004015cc: sub eax, ecx
         // 004015ce: mov esi, ecx
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
      [-]00894810
         // 00401627: mov ds:[eax+0x10], ecx
      [-]885014a1
         // 00401630: mov b1 ds:[eax+0x14], b1 dl
         // 00401633: mov eax, ds:[0x40ea90]
      [-]2bc18bf1
         // 00401653: sub eax, ecx
         // 00401655: mov esi, ecx
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
         // 00401682: sub eax, ecx
         // 00401684: mov esi, ecx
      [-]8bc8c1e902f3a58bc883e103b8
         // 0040168f: mov ecx, eax
         // 00401691: shr ecx, b1 0x2
         // 00401694: rep movsdd 
         // 00401696: mov ecx, eax
         // 00401698: and ecx, 0x3
         // 0040169b: mov eax, 0x412608
      [-]2bc18bf1
         // 004016fc: sub eax, ecx
         // 004016fe: mov esi, ecx
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
         // 0040174f: add esp, 0x4
      [-]8d7c000257e8
         // 00401789: lea edi, ds:[eax+eax+0x2]
         // 0040178d: push edi
         // 0040178e: call _malloc
      [-]0000578bf06a0056e8
         // 00401793: push edi
         // 00401794: mov esi, eax
         // 00401796: push 0x0
         // 00401798: push esi
         // 00401799: call _memset
      [-]6a006a01ffd7
         // 004017be: push 0x0
         // 004017c0: push 0x1
         // 004017c2: call edi
      [-]000083c4
         // 0040180a: add esp, 0x4
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
         // 00401877: push 0x0
         // 00401879: push 0xfde9
         // 0040187e: call edi
         // 00401880: mov ebx, ss:[ebp+0x8]
      [-]006a006a006a00
         // 00401889: push 0x0
         // 0040188b: push 0x0
         // 0040188d: push 0x0
      [-]6aff566a006a01ff
         // 00401890: push 0xffffffffffffffff
         // 00401892: push esi
         // 00401893: push 0x0
         // 00401895: push 0x1
         // 00401897: call edi
      [-]6a006a0050
         // 00401899: push 0x0
         // 0040189b: push 0x0
         // 0040189d: push eax
      [-]6aff566a006a01ff
         // 0040189f: push 0xffffffffffffffff
         // 004018a1: push esi
         // 004018a2: push 0x0
         // 004018a4: push 0x1
         // 004018a6: call edi
      [-]85c0560f95c3e8
         // 004018a8: test eax, eax
         // 004018aa: push esi
         // 004018ab: setnz b1 bl
         // 004018ae: call _free
      [-]000083c4045f5e
         // 004018b3: add esp, 0x4
         // 004018b6: pop edi
         // 004018b7: pop esi
      [-]5768????????89
         // 004018f9: push edi
         // 004018fa: push 0xfa
         // 004018ff: mov ss:[esp+0x14], eax
      [-]00008bd883c40485db0f8401
         // 0040190a: mov ebx, eax
         // 0040190c: add esp, 0x4
         // 0040190f: test ebx, ebx
         // 00401911: jz 0x401a54
      [-]68????????6a0053e8
         // 004019f5: push 0xfa
         // 004019fa: push 0x0
         // 004019fc: push ebx
         // 004019fd: call _memset
      [-]000083c40cff15
         // 00401a02: add esp, 0xc
         // 00401a05: call ds:[GetTickCount]
      [-]83c71857e8
         // 00401a21: add edi, 0x18
         // 00401a24: push edi
         // 00401a25: call _malloc
      [-]00008bf083c41885f60f84
         // 00401a2a: mov esi, eax
         // 00401a2c: add esp, 0x18
         // 00401a2f: test esi, esi
         // 00401a31: jz 0x401b14
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
      [-]400083f801
         // 004019e3: cmp eax, 0x1
      [-]000083c404eb
         // 00401b1e: add esp, 0x4
         // 00401b21: jmp 0x401b2b
      [-]000083c404
         // 00401b35: add esp, 0x4
      [-]81ec????????a1
         // 00401b70: sub esp, 0x134
         // 00401b76: mov eax, ds:[___security_cookie]
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
         // 00401b9e: call ds:[GetTickCount]
      [-]4000508d
         // 00401ba4: push eax
         // 00401ba5: lea ecx, ss:[esp+0xc]
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
         // 00401bcd: call ds:[InternetOpenUrlA]
      [-]40008bf085f674
         // 00401bd3: mov esi, eax
         // 00401bd5: test esi, esi
         // 00401bd7: jz 0x401c2b
      [-]400085c0560f95c3ff15
         // 00401b2a: test eax, eax
         // 00401b2c: push esi
         // 00401b2d: setnz b1 bl
         // 00401b30: call ds:[InternetCloseHandle]
      [-]400084db5b74
         // 00401b36: test b1 bl, b1 bl
         // 00401b38: pop ebx
         // 00401b39: jz 0x401b5a
      [-]b0015e8b
         // 00401b42: mov b1 al, b1 0x1
         // 00401b44: pop esi
         // 00401b45: mov ecx, ss:[esp+0x130]
      [-]68????????8d
         // 00401c6d: push 0x12b
         // 00401c72: lea eax, ss:[esp+0x11]
      [-]000083c40cff15
         // 00401c83: add esp, 0xc
         // 00401c86: call ds:[GetTickCount]
      [-]4000508d
         // 00401c8c: push eax
         // 00401c8d: lea ecx, ss:[esp+0x10]
      [-]83c40c6a0068????????6a006a008d
         // 00401ca1: add esp, 0xc
         // 00401ca4: push 0x0
         // 00401ca6: push 0x100
         // 00401cab: push 0x0
         // 00401cad: push 0x0
         // 00401caf: lea edx, ss:[esp+0x1c]
      [-]000083c40c8d
         // 00401c13: add esp, 0xc
         // 00401c16: lea ecx, ss:[esp+0x8]
      [-]400085c074
         // 00401c30: test eax, eax
         // 00401c32: jz 0x401c3c
      [-]40008b85
         // 00401c43: mov eax, ss:[esp+0x8]
         // 00401c47: test eax, eax
      [-]000083c404
         // 00401d1c: add esp, 0x4
      [-]81ec????????a1
         // 00401cc0: sub esp, 0x10c
         // 00401cc6: mov eax, ds:[___security_cookie]
      [-]80781000538d581089
         // 00401cdb: cmp b1 ds:[eax+0x10], b1 0x0
         // 00401cdf: push ebx
         // 00401ce0: lea ebx, ds:[eax+0x10]
         // 00401ce3: mov ss:[esp+0x4], ebx
      [-]32c05b8b
         // 00401ce9: xor b1 al, b1 al
         // 00401ceb: pop ebx
         // 00401cec: mov ecx, ss:[esp+0x108]
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
         // 00401e06: call ds:[GetTempPathA]
      [-]2bf18d7e063bf77d
         // 00401e1c: sub esi, ecx
         // 00401e1e: lea edi, ds:[esi+0x6]
         // 00401e21: cmp esi, edi
         // 00401e23: jge 0x401e54
      [-]ffd333d2b9????????f7f16a0180c26188
         // 00401d37: call ebx
         // 00401d39: xor edx, edx
         // 00401d3b: mov ecx, 0x1a
         // 00401d40: div ecx
         // 00401d42: push 0x1
         // 00401d44: add b1 dl, b1 0x61
         // 00401d47: mov b1 ss:[ebp+esi+0xfffffffffffffef8], b1 dl
      [-]0089108848048d
         // 00401d7c: mov ds:[eax], edx
         // 00401d7e: mov b1 ds:[eax+0x4], b1 cl
         // 00401d81: lea eax, ss:[ebp+0xfffffffffffffef8]
      [-]8bd38bc82bd1
         // 00401d87: mov edx, ebx
         // 00401d89: mov ecx, eax
         // 00401d8b: sub edx, ecx
      [-]8a08880c02
         // 00401d90: mov b1 cl, b1 ds:[eax]
         // 00401d92: mov b1 ds:[edx+eax], b1 cl
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
         // 00401edb: push 0x0
         // 00401edd: push 0x80
         // 00401ee2: push 0x1
         // 00401ee4: push 0x0
         // 00401ee6: push 0x0
         // 00401ee8: push 0x40000000
         // 00401eed: push edi
         // 00401eee: call ds:[CreateFileA]
      [-]8b4e086a006a005150ff15
         // 00401efe: mov ecx, ds:[esi+0x8]
         // 00401f01: push 0x0
         // 00401f03: push 0x0
         // 00401f05: push ecx
         // 00401f06: push eax
         // 00401f07: call ds:[SetFilePointer]
      [-]400083f8ff74
         // 00401f0d: cmp eax, 0xffffffffffffffff
         // 00401f10: jz 0x401f3d
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
      [-]400085c075
         // 00401f39: test eax, eax
         // 00401f3b: jnz 0x401f59
      [-]4000c705
         // 00401f49: mov ds:[0x4129e4], 0xffffffffffffffff
      [-]833e037524
         // 00401e59: cmp ds:[esi], 0x3
         // 00401e5c: jnz 0x401e82
      [-]6a0057ff15
         // 00401f79: push 0x0
         // 00401f7b: push edi
         // 00401f7c: call ds:[WinExec]
      [-]2bc28bc885c97e
         // 00401e9f: sub eax, edx
         // 00401ea1: mov ecx, eax
         // 00401ea3: test ecx, ecx
         // 00401ea5: jle 0x401eb2
      [-]803c385c74
         // 00401ea7: cmp b1 ds:[eax+edi], b1 0x5c
         // 00401eab: jz 0x401eb2
      [-]8a540701881406
         // 00401ec0: mov b1 dl, b1 ds:[edi+eax+0x1]
         // 00401ec4: mov b1 ds:[esi+eax], b1 dl
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
      [-]400083f8ff0f84
         // 00402044: cmp eax, 0xffffffffffffffff
         // 00402047: jz 0x4021bf
      [-]6a0468????????68????????6a00ff15
         // 00402069: push 0x4
         // 0040206b: push 0x1000
         // 00402070: push 0x19400
         // 00402075: push 0x0
         // 00402077: call ds:[VirtualAlloc]
      [-]40008bf085f60f84
         // 0040207d: mov esi, eax
         // 0040207f: test esi, esi
         // 00402081: jz 0x4021c9
      [-]68????????6a0056e8
         // 00402090: push 0x19400
         // 00402095: push 0x0
         // 00402097: push esi
         // 00402098: call _memset
      [-]83c40c6a006a00
         // 004020a1: add esp, 0xc
         // 004020a4: push 0x0
         // 004020a6: push 0x0
      [-]400083f8ff0f84
         // 004020b0: cmp eax, 0xffffffffffffffff
         // 004020b3: jz 0x4021c5
      [-]5168????????8d96????????5250c7
         // 004020c3: push ecx
         // 004020c4: push 0x19000
         // 004020c9: lea edx, ds:[esi+0x114]
         // 004020cf: push edx
         // 004020d0: push eax
         // 004020d1: mov ss:[esp+0x24], 0x0
      [-]400085c00f84
         // 004020df: test eax, eax
         // 004020e1: jz 0x4021e2
      [-]894e0c89
         // 00401fd7: mov ds:[esi+0xc], ecx
         // 00401fda: mov ds:[esi+0x8], ebx
      [-]08c706????????89
         // 00401fdd: mov ds:[esi], 0x2
         // 00401fe3: mov ds:[esi+0x4], edx
      [-]f7ffff68????????8d
         // 00401feb: push 0x103
         // 00401ff0: lea eax, ss:[ebp+0xfffffffffffffdf5]
      [-]000068????????8d
         // 00402005: push 0x103
         // 0040200a: lea ecx, ss:[ebp+0xfffffffffffffef9]
      [-]feffff68
         // 0040202b: push 0x412714
      [-]b8????????f7
         // 00402037: mov eax, 0x51eb851f
         // 0040203c: mul ss:[ebp+0xfffffffffffffdf0]
      [-]52b8????????f7
         // 00402046: push edx
         // 00402047: mov eax, 0x51eb851f
         // 0040204c: mul ebx
      [-]f8ffff83c4
         // 0040207f: add esp, 0x44
      [-]68????????ff15
         // 00402082: push 0x1f4
         // 00402087: call ds:[Sleep]
      [-]400085f6740e
         // 004021d0: test esi, esi
         // 004021d2: jz 0x4021e2
      [-]68????????6a0056ff15
         // 004020bf: push 0x8000
         // 004020c4: push 0x0
         // 004020c6: push esi
         // 004020c7: call ds:[VirtualFree]
      [-]ffff83c4
         // 00402110: add esp, 0x4
      [-]400085c075
         // 00402153: test eax, eax
         // 00402155: jnz 0x40216a
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
         // 004023dd: push edx
         // 004023de: push esi
         // 004023df: push edi
         // 004023e0: push eax
         // 004023e1: call ds:[ReadFile]
      [-]400085c07506
         // 004023e7: test eax, eax
         // 004023e9: jnz 0x4023f1
      [-]6a01ff15
         // 004023f5: push 0x1
         // 004023f7: call ds:[Sleep]
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
         // 00402383: add esp, 0x4
         // 00402386: test esi, esi
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
         // 0040259d: lea ecx, ds:[ecx+0x0]
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
      [-]83cfff3b
         // 00402b16: or edi, 0xffffffffffffffff
         // 00402b19: cmp ebx, edi
      [-]5068????????
         // 00402b25: push eax
         // 00402b26: push 0xf01ff
      [-]400085c075
         // 00402b32: test eax, eax
         // 00402b34: jnz 0x402b3f
      [-]400085c075
         // 00403000: test eax, eax
         // 00403002: jnz 0x403060
      [-]000083c404
         // 00402bee: add esp, 0x4
      [-]81ec????????a1
         // 00403360: sub esp, 0x114
         // 00403366: mov eax, ds:[___security_cookie]
      [-]68????????ff15
         // 00403374: push 0x100
         // 00403379: call ds:[GetCurrentProcess]
      [-]400050ff15
         // 0040337f: push eax
         // 00403380: call ds:[SetPriorityClass]
      [-]40006a0fff15
         // 00403386: push 0xf
         // 00403388: call ds:[GetCurrentThread]
      [-]400050ff15
         // 0040338e: push eax
         // 0040338f: call ds:[SetThreadPriority]
      [-]6a00506a
         // 0040339a: push 0x0
         // 0040339c: push eax
         // 0040339d: push 0x1
      [-]6a04ff15a0
         // 0040339f: push 0x4
         // 004033a1: call ds:[SHChangeNotify]
      [-]40008b0d
         // 004033a7: mov ecx, ds:[0x413a20]
      [-]83c40c6a006a008d
         // 004033bd: add esp, 0xc
         // 004033c0: push 0x0
         // 004033c2: push 0x0
         // 004033c4: lea eax, ss:[esp+0x8]
      [-]6a00ff15a8
         // 004033d3: push 0x0
         // 004033d5: call ds:[ShellExecuteA]
      [-]40006a00ff15
         // 004033db: push 0x0
         // 004033dd: call ds:[ExitProcess]

  }
  condition:
    all of them
}
