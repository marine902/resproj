rule scar_10_1 {
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
         // 004011d3: sub esp, 0x18
         // 004011d6: mov eax, ds:[0x410004]
      [-]0fbec099
         // 004011f0: movsx eax, b1 al
         // 004011f3: cdq 
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
         // 004013c1: push 0x2
         // 004013c3: push 0x0
      [-]00006a006a00
         // 004013d1: push 0x0
         // 004013d3: push 0x0
      [-]feffff84c07506
         // 00401438: test b1 al, b1 al
         // 0040143a: jnz 0x401442
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
         // 0040149f: push 0xfa
         // 004014a4: push 0x0
      [-]000068????????6a0068
         // 004014b0: push 0xfa
         // 004014b5: push 0x0
         // 004014b7: push 0x414560
      [-]000068????????6a0068
         // 004014c1: push 0xfa
         // 004014c6: push 0x0
         // 004014c8: push 0x414660
      [-]00008b0d
         // 004014d2: mov ecx, ds:[0x410488]
      [-]8bc3890d
         // 004014de: mov eax, ebx
         // 004014e0: mov ds:[0x414464], ecx
      [-]83c42489
         // 004014e6: add esp, 0x24
         // 004014e9: mov ds:[0x414460], ebp
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
         // 00401653: sub eax, ecx
         // 00401655: mov esi, ecx
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
         // 0040171f: mov ecx, eax
         // 00401721: shr ecx, b1 0x2
         // 00401724: rep movsdd 
         // 00401726: mov ecx, eax
         // 00401728: and ecx, 0x3
         // 0040172b: cmp ds:[0x414798], 0x0
      [-]00f3a475
         // 00401732: rep movsbb 
         // 00401734: jnz 0x401759
      [-]6a006a006a006a0068
         // 00401736: push 0x0
         // 00401738: push 0x0
         // 0040173a: push 0x0
         // 0040173c: push 0x0
         // 0040173e: push 0x4104cc
      [-]5b5f32c05e
         // 0040173c: pop ebx
         // 0040173d: pop edi
         // 0040173e: xor b1 al, b1 al
         // 00401740: pop esi
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
         // 004017b0: push 0x0
         // 004017b2: push 0x1
         // 004017b4: call edi
      [-]000083c4
         // 0040180a: add esp, 0x4
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
      [-]00008bd883c40485db0f84
         // 004019e8: mov ebx, eax
         // 004019ea: add esp, 0x4
         // 004019ed: test ebx, ebx
         // 004019ef: jz 0x401b23
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
      [-]6a0068????????6a006a0068
         // 004019dc: push 0x0
         // 004019de: push 0x100
         // 004019e3: push 0x0
         // 004019e5: push 0x0
         // 004019e7: push 0x4104d8
      [-]57566a006a00
         // 004019d6: push edi
         // 004019d7: push esi
         // 004019d8: push 0x0
         // 004019da: push 0x0
      [-]400083f801
         // 004019e3: cmp eax, 0x1
      [-]000083c404eb
         // 00401a4f: add esp, 0x4
         // 00401a52: jmp 0x401a5c
      [-]81ec????????a1
         // 00401aa0: sub esp, 0x134
         // 00401aa6: mov eax, ds:[___security_cookie]
      [-]5668????????8d
         // 00401ab4: push esi
         // 00401ab5: push 0x12b
         // 00401aba: lea eax, ss:[esp+0xd]
      [-]6a0050c6
         // 00401abe: push 0x0
         // 00401ac0: push eax
         // 00401ac1: mov b1 ss:[esp+0x14], b1 0x0
      [-]000083c40cff15
         // 00401acb: add esp, 0xc
         // 00401ace: call ds:[GetTickCount]
      [-]4000508d
         // 00401ad4: push eax
         // 00401ad5: lea ecx, ss:[esp+0xc]
      [-]83c40c6a0068????????6a006a008d
         // 00401ae9: add esp, 0xc
         // 00401aec: push 0x0
         // 00401aee: push 0x100
         // 00401af3: push 0x0
         // 00401af5: push 0x0
         // 00401af7: lea edx, ss:[esp+0x18]
      [-]5250ff15
         // 00401afb: push edx
         // 00401afc: push eax
         // 00401afd: call ds:[InternetOpenUrlA]
      [-]40008bf085f674
         // 00401b03: mov esi, eax
         // 00401b05: test esi, esi
         // 00401b07: jz 0x401b5a
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
         // 00401c13: mov b1 al, b1 0x1
         // 00401c15: pop esi
         // 00401c16: mov ecx, ss:[esp+0x130]
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
      [-]85c07409
         // 00401c47: test eax, eax
         // 00401c49: jz 0x401c54
      [-]000083c404
         // 00401c51: add esp, 0x4
      [-]81ec????????a1
         // 00401cb3: sub esp, 0x10c
         // 00401cb9: mov eax, ds:[0x410004]
      [-]80781000538d581089
         // 00401cc6: cmp b1 ds:[eax+0x10], b1 0x0
         // 00401cca: push ebx
         // 00401ccb: lea ebx, ds:[eax+0x10]
         // 00401cce: mov ss:[ebp+0xfffffffffffffef4], ebx
      [-]32c05b8b
         // 00401dc9: xor b1 al, b1 al
         // 00401dcb: pop ebx
         // 00401dcc: mov ecx, ss:[esp+0x108]
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
         // 00401d3a: sub esi, ecx
         // 00401d3c: lea edi, ds:[esi+0x6]
         // 00401d3f: cmp esi, edi
         // 00401d41: jge 0x401d70
      [-]ffd333d2b9????????f7f16a0180c26188
         // 00401d37: call ebx
         // 00401d39: xor edx, edx
         // 00401d3b: mov ecx, 0x1a
         // 00401d40: div ecx
         // 00401d42: push 0x1
         // 00401d44: add b1 dl, b1 0x61
         // 00401d47: mov b1 ss:[ebp+esi+0xfffffffffffffef8], b1 dl
      [-]0089108848048d
         // 00401e76: mov ds:[eax], edx
         // 00401e78: mov b1 ds:[eax+0x4], b1 cl
         // 00401e7b: lea eax, ss:[esp+0x8]
      [-]8bd38bc82bd1
         // 00401e7f: mov edx, ebx
         // 00401e81: mov ecx, eax
         // 00401e83: sub edx, ecx
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
         // 00401df3: cmp eax, 0xffffffffffffffff
         // 00401df6: jnz 0x401e1b
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
         // 00401ec0: mov b1 dl, b1 ds:[edi+eax+0x1]
         // 00401ec4: mov b1 ds:[esi+eax], b1 dl
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
         // 004022e9: mov eax, ebx
      [-]83c00a50
         // 0040235b: add eax, 0xa
         // 0040235e: push eax
      [-]f5ffff83c4
         // 0040236a: add esp, 0xc
      [-]0fb6f0eb
         // 0040236d: movzx esi, b1 al
         // 00402370: jmp 0x40237a
      [-]000083c40485f60f95c0
         // 00402383: add esp, 0x4
         // 00402386: test esi, esi
         // 00402389: setnz b1 al
      [-]33c4898424
         // 00402801: xor eax, esp
         // 00402803: mov ss:[esp+0x250], eax
      [-]000083c40c68????????8d
         // 00402827: add esp, 0xc
         // 0040282a: push 0x104
         // 0040282f: lea ecx, ss:[esp+0x14c]
      [-]000083c40885c0740d
         // 00402a10: add esp, 0x8
         // 00402a13: test eax, eax
         // 00402a15: jz 0x402a24
      [-]000083c40432c05dc3
         // 00402e8d: add esp, 0x4
         // 00402e90: xor b1 al, b1 al
         // 00402e92: pop ebp
         // 00402e93: retn 
      [-]00008bf083c40885f67505
         // 00402ea4: mov esi, eax
         // 00402ea6: add esp, 0x8
         // 00402ea9: test esi, esi
         // 00402eab: jnz 0x402eb2
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
         // 00403233: or edi, 0xffffffffffffffff
         // 00403236: cmp ebx, edi
      [-]5068????????
         // 00403242: push eax
         // 00403243: push 0xf01ff
      [-]400085c075
         // 0040324f: test eax, eax
         // 00403251: jnz 0x40325c
      [-]68????????6a206a028d
         // 00403267: push 0x220
         // 0040326c: push 0x20
         // 0040326e: push 0x2
         // 00403270: lea edx, ss:[esp+0x4c]
      [-]400085c075
         // 0040327b: test eax, eax
         // 0040327d: jnz 0x403285
      [-]68????????e8
         // 00402fad: push 0x400
         // 00402fb2: call _malloc
      [-]000068????????8bf8
         // 00402fb7: push 0x400
         // 00402fbc: mov edi, eax
      [-]83c4108d
         // 00402fc8: add esp, 0x10
         // 00402fcb: lea eax, ss:[ebp+0xffffffffffffffdc]
      [-]5068????????576a0251ff15
         // 00402fce: push eax
         // 00402fcf: push 0x400
         // 00402fd4: push edi
         // 00402fd5: push 0x2
         // 00402fd7: push ecx
         // 00402fd8: call ds:[GetTokenInformation]
      [-]400085c075
         // 00403000: test eax, eax
         // 00403002: jnz 0x403060
      [-]000083c404
         // 00403309: add esp, 0x4
      [-]81ec????????a1
         // 00403083: sub esp, 0x114
         // 00403089: mov eax, ds:[0x410004]
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
