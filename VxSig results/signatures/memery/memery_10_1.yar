rule memery_10_1 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         8b442404565768????????50e87a0a0000
         // 00401000: mov eax, ss:[esp+0x4]
         // 00401004: push esi
         // 00401005: push edi
         // 00401006: push 0x40805c
         // 0040100b: push eax
         // 0040100c: call 0x401a8b
      [-]6a026a0056e8bb09000056e85d0800008b7c2424568907e8fd0700008b0f51e8430700008b54242883c418
         // 0040101a: push 0x2
         // 0040101c: push 0x0
         // 0040101e: push esi
         // 0040101f: call 0x4019df
         // 00401024: push esi
         // 00401025: call 0x401887
         // 0040102a: mov edi, ss:[esp+0x24]
         // 0040102e: push esi
         // 0040102f: mov ds:[edi], eax
         // 00401031: call 0x401833
         // 00401036: mov ecx, ds:[edi]
         // 00401038: push ecx
         // 00401039: call _malloc
         // 0040103e: mov edx, ss:[esp+0x28]
         // 00401042: add esp, 0x18
      [-]89027418
         // 00401047: mov ds:[edx], eax
         // 00401049: jz 0x401063
      [-]8b0f566a015150e84206000056e8e605000083c4145f5ec3
         // 0040104b: mov ecx, ds:[edi]
         // 0040104d: push esi
         // 0040104e: push 0x1
         // 00401050: push ecx
         // 00401051: push eax
         // 00401052: call _fread
         // 00401057: push esi
         // 00401058: call _fclose
         // 0040105d: add esp, 0x14
         // 00401060: pop edi
         // 00401061: pop esi
         // 00401062: retn 
      [-]68????????e8a505000083c4046a00e8c6040000
         // 00401063: push 0x408044
         // 00401068: call 0x401612
         // 0040106d: add esp, 0x4
         // 00401070: push 0x0
         // 00401072: call _exit
      [-]68????????e89105000083c4046a00e8b2040000
         // 00401077: push 0x408030
         // 0040107c: call 0x401612
         // 00401081: add esp, 0x4
         // 00401084: push 0x0
         // 00401086: call _exit
      [-]83ec088d442404568b7424108d4c2404505156c74424????????00c74424????????00e848ffffff68????????56e8c8090000
         // 00401090: sub esp, 0x8
         // 00401093: lea eax, ss:[esp+0x4]
         // 00401097: push esi
         // 00401098: mov esi, ss:[esp+0x10]
         // 0040109c: lea ecx, ss:[esp+0x4]
         // 004010a0: push eax
         // 004010a1: push ecx
         // 004010a2: push esi
         // 004010a3: mov ss:[esp+0x10], 0x0
         // 004010ab: mov ss:[esp+0x14], 0x0
         // 004010b3: call 0x401000
         // 004010b8: push 0x408060
         // 004010bd: push esi
         // 004010be: call 0x401a8b
      [-]8b5424188b442414566a015250e8290a00008b4c24188b542414566a015152e8170a000056e84d05000083c42468????????ff1500704000
         // 004010cc: mov edx, ss:[esp+0x18]
         // 004010d0: mov eax, ss:[esp+0x14]
         // 004010d4: push esi
         // 004010d5: push 0x1
         // 004010d7: push edx
         // 004010d8: push eax
         // 004010d9: call _fwrite
         // 004010de: mov ecx, ss:[esp+0x18]
         // 004010e2: mov edx, ss:[esp+0x14]
         // 004010e6: push esi
         // 004010e7: push 0x1
         // 004010e9: push ecx
         // 004010ea: push edx
         // 004010eb: call _fwrite
         // 004010f0: push esi
         // 004010f1: call _fclose
         // 004010f6: add esp, 0x24
         // 004010f9: push 0x1f4
         // 004010fe: call ds:[Sleep]
      [-]8b4424045e
         // 00401104: mov eax, ss:[esp+0x4]
         // 00401108: pop esi
      [-]50e88b09000083c404
         // 0040110d: push eax
         // 0040110e: call 0x401a9e
         // 00401113: add esp, 0x4
      [-]83c408c3
         // 00401116: add esp, 0x8
         // 00401119: retn 
      [-]81ec????????535557
         // 00401120: sub esp, 0x55c
         // 00401126: push ebx
         // 00401127: push ebp
         // 00401128: push edi
      [-]8dbc24????????889c2460030000f3ab66abaa8d8424????????68????????5053895c2418895c241cff15107040008d4c24108d54240c518d8424????????5250e888feffff8bac24????????83c40c8d4c24185155ff150c70400083f8ff89442414750a
         // 00401132: lea edi, ss:[esp+0x361]
         // 00401139: mov b1 ss:[esp+0x360], b1 bl
         // 00401140: rep stosdd 
         // 00401142: stosww 
         // 00401144: stosbb 
         // 00401145: lea eax, ss:[esp+0x360]
         // 0040114c: push 0x104
         // 00401151: push eax
         // 00401152: push ebx
         // 00401153: mov ss:[esp+0x18], ebx
         // 00401157: mov ss:[esp+0x1c], ebx
         // 0040115b: call ds:[GetModuleFileNameA]
         // 00401161: lea ecx, ss:[esp+0x10]
         // 00401165: lea edx, ss:[esp+0xc]
         // 00401169: push ecx
         // 0040116a: lea eax, ss:[esp+0x364]
         // 00401171: push edx
         // 00401172: push eax
         // 00401173: call 0x401000
         // 00401178: mov ebp, ss:[esp+0x578]
         // 0040117f: add esp, 0xc
         // 00401182: lea ecx, ss:[esp+0x18]
         // 00401186: push ecx
         // 00401187: push ebp
         // 00401188: call ds:[FindFirstFileA]
         // 0040118e: cmp eax, 0xffffffffffffffff
         // 00401191: mov ss:[esp+0x14], eax
         // 00401195: jnz 0x4011a1
      [-]68????????e950020000
         // 00401197: push 0x4080b0
         // 0040119c: jmp 0x4013f1
      [-]837c241c100f84d6000000
         // 004011a2: cmp ss:[esp+0x1c], 0x10
         // 004011a7: jz 0x401283
      [-]8d7c244883c9ff
         // 004011ad: lea edi, ss:[esp+0x48]
         // 004011b1: or ecx, 0xffffffffffffffff
      [-]6a04f2aef7d14968????????8d740c4c56e8540b000083c40c
         // 004011b6: push 0x4
         // 004011b8: repne scasbb 
         // 004011ba: not ecx
         // 004011bc: dec ecx
         // 004011bd: push 0x4080a8
         // 004011c2: lea esi, ss:[esp+ecx+0x4c]
         // 004011c6: push esi
         // 004011c7: call 0x401d20
         // 004011cc: add esp, 0xc
      [-]6a0468????????56e8400b000083c40c
         // 004011d3: push 0x4
         // 004011d5: push 0x4080a0
         // 004011da: push esi
         // 004011db: call 0x401d20
         // 004011e0: add esp, 0xc
      [-]0f85dd010000
         // 004011e5: jnz 0x4013c8
      [-]8dbc24????????889c2460020000f3ab66abaa8bfd83c9ff
         // 004011f2: lea edi, ss:[esp+0x261]
         // 004011f9: mov b1 ss:[esp+0x260], b1 bl
         // 00401200: rep stosdd 
         // 00401202: stosww 
         // 00401204: stosbb 
         // 00401205: mov edi, ebp
         // 00401207: or ecx, 0xffffffffffffffff
      [-]8d9424????????f2aef7d183c1fc515552e8fe0900008d7c245483c9ff
         // 0040120c: lea edx, ss:[esp+0x260]
         // 00401213: repne scasbb 
         // 00401215: not ecx
         // 00401217: add ecx, 0xfffffffffffffffc
         // 0040121a: push ecx
         // 0040121b: push ebp
         // 0040121c: push edx
         // 0040121d: call _strncpy
         // 00401222: lea edi, ss:[esp+0x54]
         // 00401226: or ecx, 0xffffffffffffffff
      [-]8d9424????????f2aef7d12bf9
         // 0040122b: lea edx, ss:[esp+0x26c]
         // 00401232: repne scasbb 
         // 00401234: not ecx
         // 00401236: sub edi, ecx
      [-]83c9fff2ae
         // 0040123e: or ecx, 0xffffffffffffffff
         // 00401241: repne scasbb 
      [-]4fc1e902f3a58b
         // 00401245: dec edi
         // 00401246: shr ecx, b1 0x2
         // 00401249: rep movsdd 
         // 0040124f: mov ecx, edx
      [-]83e10350f3a48b4c24208d9424????????5152e827feffff8d8424????????5068????????e89703000083c420e945010000
         // 00401251: and ecx, 0x3
         // 00401254: push eax
         // 00401255: rep movsbb 
         // 00401257: mov ecx, ss:[esp+0x20]
         // 0040125b: lea edx, ss:[esp+0x270]
         // 00401262: push ecx
         // 00401263: push edx
         // 00401264: call 0x401090
         // 00401269: lea eax, ss:[esp+0x278]
         // 00401270: push eax
         // 00401271: push 0x408094
         // 00401276: call 0x401612
         // 0040127b: add esp, 0x20
         // 0040127e: jmp 0x4013c8
      [-]be????????8d442448
         // 00401283: mov esi, 0x408090
         // 00401288: lea eax, ss:[esp+0x48]
      [-]8a108aca3a16751c
         // 0040128c: mov b1 dl, b1 ds:[eax]
         // 0040128e: mov b1 cl, b1 dl
         // 00401290: cmp b1 dl, b1 ds:[esi]
         // 00401292: jnz 0x4012b0
      [-]3acb7414
         // 00401294: cmp b1 cl, b1 bl
         // 00401296: jz 0x4012ac
      [-]8a50018aca3a5601750e
         // 00401298: mov b1 dl, b1 ds:[eax+0x1]
         // 0040129b: mov b1 cl, b1 dl
         // 0040129d: cmp b1 dl, b1 ds:[esi+0x1]
         // 004012a0: jnz 0x4012b0
      [-]3acb75e0
         // 004012a8: cmp b1 cl, b1 bl
         // 004012aa: jnz 0x40128c
      [-]1bc083d8ff
         // 004012b0: sbb eax, eax
         // 004012b2: sbb eax, 0xffffffffffffffff
      [-]3bc30f840b010000
         // 004012b5: cmp eax, ebx
         // 004012b7: jz 0x4013c8
      [-]be????????8d442448
         // 004012bd: mov esi, 0x40808c
         // 004012c2: lea eax, ss:[esp+0x48]
      [-]8a108aca3a16751c
         // 004012c6: mov b1 dl, b1 ds:[eax]
         // 004012c8: mov b1 cl, b1 dl
         // 004012ca: cmp b1 dl, b1 ds:[esi]
         // 004012cc: jnz 0x4012ea
      [-]3acb7414
         // 004012ce: cmp b1 cl, b1 bl
         // 004012d0: jz 0x4012e6
      [-]8a50018aca3a5601750e
         // 004012d2: mov b1 dl, b1 ds:[eax+0x1]
         // 004012d5: mov b1 cl, b1 dl
         // 004012d7: cmp b1 dl, b1 ds:[esi+0x1]
         // 004012da: jnz 0x4012ea
      [-]3acb75e0
         // 004012e2: cmp b1 cl, b1 bl
         // 004012e4: jnz 0x4012c6
      [-]1bc083d8ff
         // 004012ea: sbb eax, eax
         // 004012ec: sbb eax, 0xffffffffffffffff
      [-]3bc30f84d1000000
         // 004012ef: cmp eax, ebx
         // 004012f1: jz 0x4013c8
      [-]8dbc24????????889c245c010000f3ab66abaa8bfd83c9ff
         // 004012fe: lea edi, ss:[esp+0x15d]
         // 00401305: mov b1 ss:[esp+0x15c], b1 bl
         // 0040130c: rep stosdd 
         // 0040130e: stosww 
         // 00401310: stosbb 
         // 00401311: mov edi, ebp
         // 00401313: or ecx, 0xffffffffffffffff
      [-]f2aef7d183c1fc8d8424????????515550e8f208000083c9ff8d7c2454
         // 00401318: repne scasbb 
         // 0040131a: not ecx
         // 0040131c: add ecx, 0xfffffffffffffffc
         // 0040131f: lea eax, ss:[esp+0x15c]
         // 00401326: push ecx
         // 00401327: push ebp
         // 00401328: push eax
         // 00401329: call 0x401c20
         // 0040132e: or ecx, 0xffffffffffffffff
         // 00401331: lea edi, ss:[esp+0x54]
      [-]8d9424????????f2aef7d12bf9
         // 00401337: lea edx, ss:[esp+0x168]
         // 0040133e: repne scasbb 
         // 00401340: not ecx
         // 00401342: sub edi, ecx
      [-]83c9fff2ae
         // 0040134a: or ecx, 0xffffffffffffffff
         // 0040134d: repne scasbb 
      [-]4fc1e902f3a5
         // 00401351: dec edi
         // 00401352: shr ecx, b1 0x2
         // 00401355: rep movsdd 
      [-]8d9424????????83e103f3a48dbc24????????83c9fff2aef7d12bf9
         // 00401359: lea edx, ss:[esp+0x474]
         // 00401360: and ecx, 0x3
         // 00401363: rep movsbb 
         // 00401365: lea edi, ss:[esp+0x168]
         // 0040136c: or ecx, 0xffffffffffffffff
         // 0040136f: repne scasbb 
         // 00401371: not ecx
         // 00401373: sub edi, ecx
      [-]8d9424????????c1e902f3a5
         // 0040137b: lea edx, ss:[esp+0x168]
         // 00401382: shr ecx, b1 0x2
         // 00401385: rep movsdd 
      [-]83e103f3a4bf????????83c9fff2aef7d12bf9
         // 0040138b: and ecx, 0x3
         // 0040138e: rep movsbb 
         // 00401390: mov edi, 0x408084
         // 00401395: or ecx, 0xffffffffffffffff
         // 00401398: repne scasbb 
         // 0040139a: not ecx
         // 0040139c: sub edi, ecx
      [-]83c9fff2ae
         // 004013a4: or ecx, 0xffffffffffffffff
         // 004013a7: repne scasbb 
      [-]4fc1e902f3a5
         // 004013ab: dec edi
         // 004013ac: shr ecx, b1 0x2
         // 004013af: rep movsdd 
      [-]8d8424????????83e10350f3a4e85bfdffff83c410
         // 004013b3: lea eax, ss:[esp+0x168]
         // 004013ba: and ecx, 0x3
         // 004013bd: push eax
         // 004013be: rep movsbb 
         // 004013c0: call 0x401120
         // 004013c5: add esp, 0x10
      [-]8b7424188d4c241c5156ff1508704000
         // 004013c8: mov esi, ss:[esp+0x18]
         // 004013cc: lea ecx, ss:[esp+0x1c]
         // 004013d0: push ecx
         // 004013d1: push esi
         // 004013d2: call ds:[FindNextFileA]
      [-]0f85c2fdffff
         // 004013da: jnz 0x4011a2
      [-]56ff1504704000
         // 004013e0: push esi
         // 004013e1: call ds:[FindClose]
      [-]68????????
         // 004013ec: push 0x408064
      [-]e81c02000083c404
         // 004013f1: call 0x401612
         // 004013f6: add esp, 0x4
      [-]8b44240c5f5d3bc35b7409
         // 004013f9: mov eax, ss:[esp+0xc]
         // 004013fd: pop edi
         // 004013fe: pop ebp
         // 004013ff: cmp eax, ebx
         // 00401401: pop ebx
         // 00401402: jz 0x40140d
      [-]50e89406000083c404
         // 00401404: push eax
         // 00401405: call 0x401a9e
         // 0040140a: add esp, 0x4
      [-]81c4????????c3
         // 0040140d: add esp, 0x55c
         // 00401413: retn 
      [-]81ec????????
         // 00401420: sub esp, 0x208
      [-]55578dbc24????????f3ab8d8424????????5068????????ff15147040008a84240c0100008dac24????????84c00f84a2000000
         // 0040142d: push ebp
         // 0040142e: push edi
         // 0040142f: lea edi, ss:[esp+0x10c]
         // 00401436: rep stosdd 
         // 00401438: lea eax, ss:[esp+0x10c]
         // 0040143f: push eax
         // 00401440: push 0x104
         // 00401445: call ds:[GetLogicalDriveStringsA]
         // 0040144b: mov b1 al, b1 ss:[esp+0x10c]
         // 00401452: lea ebp, ss:[esp+0x10c]
         // 00401459: test b1 al, b1 al
         // 0040145b: jz 0x401503
      [-]8d7c240dc644240c00f3ab66abaa8bfd83c9ff
         // 00401469: lea edi, ss:[esp+0xd]
         // 0040146d: mov b1 ss:[esp+0xc], b1 0x0
         // 00401472: rep stosdd 
         // 00401474: stosww 
         // 00401476: stosbb 
         // 00401477: mov edi, ebp
         // 00401479: or ecx, 0xffffffffffffffff
      [-]8d54240cf2aef7d12bf9
         // 0040147e: lea edx, ss:[esp+0xc]
         // 00401482: repne scasbb 
         // 00401484: not ecx
         // 00401486: sub edi, ecx
      [-]83c9fff2ae
         // 0040148e: or ecx, 0xffffffffffffffff
         // 00401491: repne scasbb 
      [-]4fc1e902f3a5
         // 00401495: dec edi
         // 00401496: shr ecx, b1 0x2
         // 00401499: rep movsdd 
      [-]8d54240c83e103f3a4bf????????83c9fff2aef7d12bf9
         // 0040149d: lea edx, ss:[esp+0xc]
         // 004014a1: and ecx, 0x3
         // 004014a4: rep movsbb 
         // 004014a6: mov edi, 0x408084
         // 004014ab: or ecx, 0xffffffffffffffff
         // 004014ae: repne scasbb 
         // 004014b0: not ecx
         // 004014b2: sub edi, ecx
      [-]83c9fff2ae
         // 004014ba: or ecx, 0xffffffffffffffff
         // 004014bd: repne scasbb 
      [-]4fc1e902f3a5
         // 004014c1: dec edi
         // 004014c2: shr ecx, b1 0x2
         // 004014c5: rep movsdd 
      [-]8d44240c83e10350f3a4e848fcffff8bfd83c9ff
         // 004014c9: lea eax, ss:[esp+0xc]
         // 004014cd: and ecx, 0x3
         // 004014d0: push eax
         // 004014d1: rep movsbb 
         // 004014d3: call 0x401120
         // 004014d8: mov edi, ebp
         // 004014da: or ecx, 0xffffffffffffffff
      [-]83c404f2aef7d1498a4429018d6c290184c00f856bffffff
         // 004014df: add esp, 0x4
         // 004014e2: repne scasbb 
         // 004014e4: not ecx
         // 004014e6: dec ecx
         // 004014e7: mov b1 al, b1 ds:[ecx+ebp+0x1]
         // 004014eb: lea ebp, ds:[ecx+ebp+0x1]
         // 004014ef: test b1 al, b1 al
         // 004014f1: jnz 0x401462
      [-]5d81c4????????c3
         // 004014fb: pop ebp
         // 004014fc: add esp, 0x208
         // 00401502: retn 
      [-]5d81c4????????c3
         // 00401506: pop ebp
         // 00401507: add esp, 0x208
         // 0040150d: retn 
      [-]5356be008140005756e860080000
         // 00401612: push ebx
         // 00401613: push esi
         // 00401614: mov esi, File._ptr
         // 00401619: push edi
         // 0040161a: push esi
         // 0040161b: call __stbuf
      [-]8d44241850ff74241856e819090000
         // 00401622: lea eax, ss:[esp+0x18]
         // 00401626: push eax
         // 00401627: push ss:[esp+0x18]
         // 0040162b: push esi
         // 0040162c: call 0x401f4a
      [-]e8d308000083c418
         // 00401635: call __ftbuf
         // 0040163a: add esp, 0x18
      [-]5f5e5bc3
         // 0040163f: pop edi
         // 00401640: pop esi
         // 00401641: pop ebx
         // 00401642: retn 
      [-]a1????????568b74240883f8037515
         // 004017bf: mov eax, ds:[0x40ae84]
         // 004017c4: push esi
         // 004017c5: mov esi, ss:[esp+0x8]
         // 004017c9: cmp eax, 0x3
         // 004017cc: jnz 0x4017e3
      [-]3b35????????773f
         // 004017ce: cmp esi, ds:[0x40ae7c]
         // 004017d4: ja 0x401815
      [-]56e8121e0000
         // 004017d6: push esi
         // 004017d7: call 0x4035ee
      [-]83f802752d
         // 004017e3: cmp eax, 0x2
         // 004017e6: jnz 0x401815
      [-]8b442408
         // 004017e8: mov eax, ss:[esp+0x8]
      [-]8d700f83e6f0eb03
         // 004017f0: lea esi, ds:[eax+0xf]
         // 004017f3: and esi, 0xfffffffffffffff0
         // 004017f6: jmp 0x4017fb
      [-]3b35????????771f
         // 004017fb: cmp esi, ds:[0x40a38c]
         // 00401801: ja 0x401822
      [-]c1e80450e88d250000
         // 00401805: shr eax, b1 0x4
         // 00401808: push eax
         // 00401809: call 0x403d9b
      [-]83c60f83e6f0
         // 0040181c: add esi, 0xf
         // 0040181f: and esi, 0xfffffffffffffff0
      [-]566a00ff35????????ff1524704000
         // 00401822: push esi
         // 00401823: push 0x0
         // 00401825: push ds:[0x40ae80]
         // 0040182b: call ds:[HeapAlloc]
      [-]558bec51568b7508
         // 00401a9e: push ebp
         // 00401a9f: mov ebp, esp
         // 00401aa1: push ecx
         // 00401aa2: push esi
         // 00401aa3: mov esi, ss:[ebp+0x8]
      [-]a1????????83f8037516
         // 00401aaa: mov eax, ds:[0x40ae84]
         // 00401aaf: cmp eax, 0x3
         // 00401ab2: jnz 0x401aca
      [-]56e8e017000059
         // 00401ab4: push esi
         // 00401ab5: call 0x40329a
         // 00401aba: pop ecx
      [-]50e8ff1700005959eb3a
         // 00401ac0: push eax
         // 00401ac1: call 0x4032c5
         // 00401ac6: pop ecx
         // 00401ac7: pop ecx
         // 00401ac8: jmp 0x401b04
      [-]83f8027526
         // 00401aca: cmp eax, 0x2
         // 00401acd: jnz 0x401af5
      [-]8d4508508d45fc5056e82222000083c40c
         // 00401acf: lea eax, ss:[ebp+0x8]
         // 00401ad2: push eax
         // 00401ad3: lea eax, ss:[ebp+0xfffffffffffffffc]
         // 00401ad6: push eax
         // 00401ad7: push esi
         // 00401ad8: call 0x403cff
         // 00401add: add esp, 0xc
      [-]50ff7508ff75fce86622000083c40ceb0f
         // 00401ae4: push eax
         // 00401ae5: push ss:[ebp+0x8]
         // 00401ae8: push ss:[ebp+0xfffffffffffffffc]
         // 00401aeb: call 0x403d56
         // 00401af0: add esp, 0xc
         // 00401af3: jmp 0x401b04
      [-]6a00ff35????????ff1528704000
         // 00401af6: push 0x0
         // 00401af8: push ds:[0x40ae80]
         // 00401afe: call ds:[HeapFree]
      [-]558bec81ec????????53568b750c
         // 00401f4a: push ebp
         // 00401f4b: mov ebp, esp
         // 00401f4d: sub esp, 0x24c
         // 00401f53: push ebx
         // 00401f54: push esi
         // 00401f55: mov esi, ss:[ebp+0xc]
      [-]57894df08a1e4684db894dec894dd089750c0f844e070000
         // 00401f5a: push edi
         // 00401f5b: mov ss:[ebp+0xfffffffffffffff0], ecx
         // 00401f5e: mov b1 bl, b1 ds:[esi]
         // 00401f60: inc esi
         // 00401f61: test b1 bl, b1 bl
         // 00401f63: mov ss:[ebp+0xffffffffffffffec], ecx
         // 00401f66: mov ss:[ebp+0xffffffffffffffd0], ecx
         // 00401f69: mov ss:[ebp+0xc], esi
         // 00401f6c: jz 0x4026c0
      [-]bf????????ba????????eb0d
         // 00401f72: mov edi, 0x800
         // 00401f77: mov edx, 0x200
         // 00401f7c: jmp 0x401f8b
      [-]8b4dc4ba????????bf????????
         // 00401f7e: mov ecx, ss:[ebp+0xffffffffffffffc4]
         // 00401f81: mov edx, 0x200
         // 00401f86: mov edi, 0x800
      [-]837dec000f8c2b070000
         // 00401f8b: cmp ss:[ebp+0xffffffffffffffec], 0x0
         // 00401f8f: jl 0x4026c0
      [-]80fb207c13
         // 00401f95: cmp b1 bl, b1 0x20
         // 00401f98: jl 0x401fad
      [-]80fb787f0e
         // 00401f9a: cmp b1 bl, b1 0x78
         // 00401f9d: jg 0x401fad
      [-]0fbec38a80bc70400083e00feb02
         // 00401f9f: movsx eax, b1 bl
         // 00401fa2: mov b1 al, b1 ds:[eax+LCMapStringA]
         // 00401fa8: and eax, 0xf
         // 00401fab: jmp 0x401faf
      [-]0fbe84c1dc704000c1f80483f8078945c40f87e9060000
         // 00401faf: movsx eax, b1 ds:[ecx+eax*0x8]
         // 00401fb7: sar eax, b1 0x4
         // 00401fba: cmp eax, 0x7
         // 00401fbd: mov ss:[ebp+0xffffffffffffffc4], eax
         // 00401fc0: ja def_401FC6
      [-]ff2485c8264000
         // 00401fc6: jmp ds:[jpt_401FC6+eax*0x4]
      [-]834df8ff8945c08945c88945d88945dc8945fc8945d4e9c5060000
         // 00401fcf: or ss:[ebp+0xfffffffffffffff8], 0xffffffffffffffff
         // 00401fd3: mov ss:[ebp+0xffffffffffffffc0], eax
         // 00401fd6: mov ss:[ebp+0xffffffffffffffc8], eax
         // 00401fd9: mov ss:[ebp+0xffffffffffffffd8], eax
         // 00401fdc: mov ss:[ebp+0xffffffffffffffdc], eax
         // 00401fdf: mov ss:[ebp+0xfffffffffffffffc], eax
         // 00401fe2: mov ss:[ebp+0xffffffffffffffd4], eax
         // 00401fe5: jmp def_401FC6
      [-]0fbec383e820743b
         // 00401fea: movsx eax, b1 bl
         // 00401fed: sub eax, 0x20
         // 00401ff0: jz 0x40202d
      [-]83e803742d
         // 00401ff2: sub eax, 0x3
         // 00401ff5: jz 0x402024
      [-]83e808741f
         // 00401ff7: sub eax, 0x8
         // 00401ffa: jz 0x40201b
      [-]48487412
         // 00401ffc: dec eax
         // 00401ffd: dec eax
         // 00401ffe: jz 0x402012
      [-]0f85a6060000
         // 00402003: jnz def_401FC6
      [-]834dfc08e99d060000
         // 00402009: or ss:[ebp+0xfffffffffffffffc], 0x8
         // 0040200d: jmp def_401FC6
      [-]834dfc04e994060000
         // 00402012: or ss:[ebp+0xfffffffffffffffc], 0x4
         // 00402016: jmp def_401FC6
      [-]834dfc01e98b060000
         // 0040201b: or ss:[ebp+0xfffffffffffffffc], 0x1
         // 0040201f: jmp def_401FC6
      [-]804dfc80e982060000
         // 00402024: or b1 ss:[ebp+0xfffffffffffffffc], b1 0x80
         // 00402028: jmp def_401FC6
      [-]834dfc02e979060000
         // 0040202d: or ss:[ebp+0xfffffffffffffffc], 0x2
         // 00402031: jmp def_401FC6
      [-]80fb2a7523
         // 00402036: cmp b1 bl, b1 0x2a
         // 00402039: jnz 0x40205e
      [-]8d451050e842070000
         // 0040203b: lea eax, ss:[ebp+0x10]
         // 0040203e: push eax
         // 0040203f: call _get_int_arg
      [-]598945d80f8d5f060000
         // 00402046: pop ecx
         // 00402047: mov ss:[ebp+0xffffffffffffffd8], eax
         // 0040204a: jge def_401FC6
      [-]834dfc04f7d8
         // 00402050: or ss:[ebp+0xfffffffffffffffc], 0x4
         // 00402054: neg eax
      [-]8945d8e951060000
         // 00402056: mov ss:[ebp+0xffffffffffffffd8], eax
         // 00402059: jmp def_401FC6
      [-]8b45d80fbecb8d04808d4441d0ebe9
         // 0040205e: mov eax, ss:[ebp+0xffffffffffffffd8]
         // 00402061: movsx ecx, b1 bl
         // 00402064: lea eax, ds:[eax+eax*0x4]
         // 00402067: lea eax, ds:[ecx+eax*0x2]
         // 0040206b: jmp 0x402056
      [-]8365f800e939060000
         // 0040206d: and ss:[ebp+0xfffffffffffffff8], 0x0
         // 00402071: jmp def_401FC6
      [-]80fb2a751e
         // 00402076: cmp b1 bl, b1 0x2a
         // 00402079: jnz 0x402099
      [-]8d451050e802070000
         // 0040207b: lea eax, ss:[ebp+0x10]
         // 0040207e: push eax
         // 0040207f: call _get_int_arg
      [-]598945f80f8d1f060000
         // 00402086: pop ecx
         // 00402087: mov ss:[ebp+0xfffffffffffffff8], eax
         // 0040208a: jge def_401FC6
      [-]834df8ffe916060000
         // 00402090: or ss:[ebp+0xfffffffffffffff8], 0xffffffffffffffff
         // 00402094: jmp def_401FC6
      [-]8b45f80fbecb8d04808d4441d08945f8e901060000
         // 00402099: mov eax, ss:[ebp+0xfffffffffffffff8]
         // 0040209c: movsx ecx, b1 bl
         // 0040209f: lea eax, ds:[eax+eax*0x4]
         // 004020a2: lea eax, ds:[ecx+eax*0x2]
         // 004020a6: mov ss:[ebp+0xfffffffffffffff8], eax
         // 004020a9: jmp def_401FC6
      [-]80fb49742d
         // 004020ae: cmp b1 bl, b1 0x49
         // 004020b1: jz 0x4020e0
      [-]80fb68741f
         // 004020b3: cmp b1 bl, b1 0x68
         // 004020b6: jz 0x4020d7
      [-]80fb6c7411
         // 004020b8: cmp b1 bl, b1 0x6c
         // 004020bb: jz 0x4020ce
      [-]80fb770f85e9050000
         // 004020bd: cmp b1 bl, b1 0x77
         // 004020c0: jnz def_401FC6
      [-]097dfce9e1050000
         // 004020c6: or ss:[ebp+0xfffffffffffffffc], edi
         // 004020c9: jmp def_401FC6
      [-]834dfc10e9d8050000
         // 004020ce: or ss:[ebp+0xfffffffffffffffc], 0x10
         // 004020d2: jmp def_401FC6
      [-]834dfc20e9cf050000
         // 004020d7: or ss:[ebp+0xfffffffffffffffc], 0x20
         // 004020db: jmp def_401FC6
      [-]803e367514
         // 004020e0: cmp b1 ds:[esi], b1 0x36
         // 004020e3: jnz 0x4020f9
      [-]807e0134750e
         // 004020e5: cmp b1 ds:[esi+0x1], b1 0x34
         // 004020e9: jnz 0x4020f9
      [-]4646804dfd8089750ce9b6050000
         // 004020eb: inc esi
         // 004020ec: inc esi
         // 004020ed: or b1 ss:[ebp+0xfffffffffffffffd], b1 0x80
         // 004020f1: mov ss:[ebp+0xc], esi
         // 004020f4: jmp def_401FC6
      [-]8365c400
         // 004020f9: and ss:[ebp+0xffffffffffffffc4], 0x0
      [-]8b0d????????8365d4000fb6c3f6444101807419
         // 004020fd: mov ecx, ds:[0x40a4d8]
         // 00402103: and ss:[ebp+0xffffffffffffffd4], 0x0
         // 00402107: movzx eax, b1 bl
         // 0040210a: test b1 ds:[ecx+eax*0x2], b1 0x80
         // 0040210f: jz 0x40212a
      [-]8d45ec50ff75080fbec350e8c70500008a1e83c40c4689750c
         // 00402111: lea eax, ss:[ebp+0xffffffffffffffec]
         // 00402114: push eax
         // 00402115: push ss:[ebp+0x8]
         // 00402118: movsx eax, b1 bl
         // 0040211b: push eax
         // 0040211c: call _write_char
         // 00402121: mov b1 bl, b1 ds:[esi]
         // 00402123: add esp, 0xc
         // 00402126: inc esi
         // 00402127: mov ss:[ebp+0xc], esi
      [-]8d45ec50ff75080fbec350e8ae05000083c40ce96d050000
         // 0040212a: lea eax, ss:[ebp+0xffffffffffffffec]
         // 0040212d: push eax
         // 0040212e: push ss:[ebp+0x8]
         // 00402131: movsx eax, b1 bl
         // 00402134: push eax
         // 00402135: call _write_char
         // 0040213a: add esp, 0xc
         // 0040213d: jmp def_401FC6
      [-]0fbec383f8670f8f38020000
         // 00402142: movsx eax, b1 bl
         // 00402145: cmp eax, 0x67
         // 00402148: jg 0x402386
      [-]83f8650f8d96000000
         // 0040214e: cmp eax, 0x65
         // 00402151: jge 0x4021ed
      [-]83f8580f8fec000000
         // 00402157: cmp eax, 0x58
         // 0040215a: jg 0x40224c
      [-]0f8494020000
         // 00402160: jz 0x4023fa
      [-]83e8430f84a1000000
         // 00402166: sub eax, 0x43
         // 00402169: jz 0x402210
      [-]48487470
         // 0040216f: dec eax
         // 00402170: dec eax
         // 00402171: jz 0x4021e3
      [-]4848746c
         // 00402173: dec eax
         // 00402174: dec eax
         // 00402175: jz 0x4021e3
      [-]0f851e040000
         // 0040217a: jnz 0x40259e
      [-]66f745fc30087503
         // 00402180: test b2 ss:[ebp+0xfffffffffffffffc], b2 0x830
         // 00402186: jnz 0x40218b
      [-]837df8ffbe????????7403
         // 0040218b: cmp ss:[ebp+0xfffffffffffffff8], 0xffffffffffffffff
         // 0040218f: mov esi, 0x7fffffff
         // 00402194: jz 0x402199
      [-]8d451050e8e405000066f745fc100859
         // 00402199: lea eax, ss:[ebp+0x10]
         // 0040219c: push eax
         // 0040219d: call _get_int_arg
         // 004021a2: test b2 ss:[ebp+0xfffffffffffffffc], b2 0x810
         // 004021a8: pop ecx
      [-]894df40f841a020000
         // 004021ab: mov ss:[ebp+0xfffffffffffffff4], ecx
         // 004021ae: jz 0x4023ce
      [-]8b0d????????894df4
         // 004021b8: mov ecx, ds:[0x4080dc]
         // 004021be: mov ss:[ebp+0xfffffffffffffff4], ecx
      [-]c745d4????????
         // 004021c1: mov ss:[ebp+0xffffffffffffffd4], 0x1
      [-]0f84f0010000
         // 004021cf: jz 0x4023c5
      [-]668338000f84e6010000
         // 004021d5: cmp b2 ds:[eax], b2 0x0
         // 004021d9: jz 0x4023c5
      [-]4040ebe7
         // 004021df: inc eax
         // 004021e0: inc eax
         // 004021e1: jmp 0x4021ca
      [-]c745c0????????80c320
         // 004021e3: mov ss:[ebp+0xffffffffffffffc0], 0x1
         // 004021ea: add b1 bl, b1 0x20
      [-]834dfc40837df8008dbd????????897df40f8dcd000000
         // 004021ed: or ss:[ebp+0xfffffffffffffffc], 0x40
         // 004021f1: cmp ss:[ebp+0xfffffffffffffff8], 0x0
         // 004021f5: lea edi, ss:[ebp+0xfffffffffffffdb4]
         // 004021fb: mov ss:[ebp+0xfffffffffffffff4], edi
         // 004021fe: jge 0x4022d1
      [-]c745f8????????e906010000
         // 00402204: mov ss:[ebp+0xfffffffffffffff8], 0x6
         // 0040220b: jmp 0x402316
      [-]66f745fc30087503
         // 00402210: test b2 ss:[ebp+0xfffffffffffffffc], b2 0x830
         // 00402216: jnz 0x40221b
      [-]66f745fc10088d451050743b
         // 0040221b: test b2 ss:[ebp+0xfffffffffffffffc], b2 0x810
         // 00402221: lea eax, ss:[ebp+0x10]
         // 00402224: push eax
         // 00402225: jz 0x402262
      [-]e877050000508d85????????50e8422f000083c40c8945f0
         // 00402227: call _get_short_arg
         // 0040222c: push eax
         // 0040222d: lea eax, ss:[ebp+0xfffffffffffffdb4]
         // 00402233: push eax
         // 00402234: call 0x40517b
         // 00402239: add esp, 0xc
         // 0040223c: mov ss:[ebp+0xfffffffffffffff0], eax
      [-]c745c8????????eb29
         // 00402243: mov ss:[ebp+0xffffffffffffffc8], 0x1
         // 0040224a: jmp 0x402275
      [-]83e85a7432
         // 0040224c: sub eax, 0x5a
         // 0040224f: jz 0x402283
      [-]83e80974c5
         // 00402251: sub eax, 0x9
         // 00402254: jz 0x40221b
      [-]480f8402020000
         // 00402256: dec eax
         // 00402257: jz 0x40245f
      [-]e93c030000
         // 0040225d: jmp 0x40259e
      [-]e81f050000598885b4fdffffc745f0????????
         // 00402262: call _get_int_arg
         // 00402267: pop ecx
         // 00402268: mov b1 ss:[ebp+0xfffffffffffffdb4], b1 al
         // 0040226e: mov ss:[ebp+0xfffffffffffffff0], 0x1
      [-]8d85????????8945f4e91b030000
         // 00402275: lea eax, ss:[ebp+0xfffffffffffffdb4]
         // 0040227b: mov ss:[ebp+0xfffffffffffffff4], eax
         // 0040227e: jmp 0x40259e
      [-]8d451050e8fa040000
         // 00402283: lea eax, ss:[ebp+0x10]
         // 00402286: push eax
         // 00402287: call _get_int_arg
      [-]857dfc7417
         // 00402298: test ss:[ebp+0xfffffffffffffffc], edi
         // 0040229b: jz 0x4022b4
      [-]0fbf00d1e8894df48945f0c745d4????????e9ea020000
         // 0040229d: movsx eax, b2 ds:[eax]
         // 004022a0: shr eax, b1 0x1
         // 004022a2: mov ss:[ebp+0xfffffffffffffff4], ecx
         // 004022a5: mov ss:[ebp+0xfffffffffffffff0], eax
         // 004022a8: mov ss:[ebp+0xffffffffffffffd4], 0x1
         // 004022af: jmp 0x40259e
      [-]8365d400894df40fbf00e9d8020000
         // 004022b4: and ss:[ebp+0xffffffffffffffd4], 0x0
         // 004022b8: mov ss:[ebp+0xfffffffffffffff4], ecx
         // 004022bb: movsx eax, b2 ds:[eax]
         // 004022be: jmp 0x40259b
      [-]a1????????8945f450e9aa000000
         // 004022c3: mov eax, ds:[0x4080d8]
         // 004022c8: mov ss:[ebp+0xfffffffffffffff4], eax
         // 004022cb: push eax
         // 004022cc: jmp 0x40237b
      [-]e8802d000059e915020000
         // 0040237b: call _strlen
         // 00402380: pop ecx
         // 00402381: jmp 0x40259b
      [-]83e8690f84d0000000
         // 00402386: sub eax, 0x69
         // 00402389: jz 0x40245f
      [-]83e8050f849d000000
         // 0040238f: sub eax, 0x5
         // 00402392: jz 0x402435
      [-]480f8484000000
         // 00402398: dec eax
         // 00402399: jz 0x402423
      [-]83e8030f84e0fdffff
         // 004023a2: sub eax, 0x3
         // 004023a5: jz 0x40218b
      [-]48480f84b0000000
         // 004023ab: dec eax
         // 004023ac: dec eax
         // 004023ad: jz 0x402463
      [-]0f85e2010000
         // 004023b6: jnz 0x40259e
      [-]c745cc????????eb3c
         // 004023bc: mov ss:[ebp+0xffffffffffffffcc], 0x27
         // 004023c3: jmp 0x402401
      [-]2bc1d1f8e9cd010000
         // 004023c5: sub eax, ecx
         // 004023c7: sar eax, b1 0x1
         // 004023c9: jmp 0x40259b
      [-]8b0d????????894df4
         // 004023d2: mov ecx, ds:[0x4080d8]
         // 004023d8: mov ss:[ebp+0xfffffffffffffff4], ecx
      [-]8038007403
         // 004023e4: cmp b1 ds:[eax], b1 0x0
         // 004023e7: jz 0x4023ec
      [-]2bc1e9a8010000
         // 004023ec: sub eax, ecx
         // 004023ee: jmp 0x40259b
      [-]c745f8????????
         // 004023f3: mov ss:[ebp+0xfffffffffffffff8], 0x8
      [-]c745cc????????
         // 004023fa: mov ss:[ebp+0xffffffffffffffcc], 0x7
      [-]f645fc80c745f0????????745c
         // 00402401: test b1 ss:[ebp+0xfffffffffffffffc], b1 0x80
         // 00402405: mov ss:[ebp+0xfffffffffffffff0], 0x10
         // 0040240c: jz 0x40246a
      [-]8a45ccc645ea300451c745dc????????8845ebeb47
         // 0040240e: mov b1 al, b1 ss:[ebp+0xffffffffffffffcc]
         // 00402411: mov b1 ss:[ebp+0xffffffffffffffea], b1 0x30
         // 00402415: add b1 al, b1 0x51
         // 00402417: mov ss:[ebp+0xffffffffffffffdc], 0x2
         // 0040241e: mov b1 ss:[ebp+0xffffffffffffffeb], b1 al
         // 00402421: jmp 0x40246a
      [-]f645fc80c745f0????????743a
         // 00402423: test b1 ss:[ebp+0xfffffffffffffffc], b1 0x80
         // 00402427: mov ss:[ebp+0xfffffffffffffff0], 0x8
         // 0040242e: jz 0x40246a
      [-]0955fceb35
         // 00402430: or ss:[ebp+0xfffffffffffffffc], edx
         // 00402433: jmp 0x40246a
      [-]8d451050e848030000f645fc20597409
         // 00402435: lea eax, ss:[ebp+0x10]
         // 00402438: push eax
         // 00402439: call _get_int_arg
         // 0040243e: test b1 ss:[ebp+0xfffffffffffffffc], b1 0x20
         // 00402442: pop ecx
         // 00402443: jz 0x40244e
      [-]668b4dec668908eb05
         // 00402445: mov b2 cx, b2 ss:[ebp+0xffffffffffffffec]
         // 00402449: mov b2 ds:[eax], b2 cx
         // 0040244c: jmp 0x402453
      [-]8b4dec8908
         // 0040244e: mov ecx, ss:[ebp+0xffffffffffffffec]
         // 00402451: mov ds:[eax], ecx
      [-]c745c8????????e93d020000
         // 00402453: mov ss:[ebp+0xffffffffffffffc8], 0x1
         // 0040245a: jmp 0x40269c
      [-]834dfc40
         // 0040245f: or ss:[ebp+0xfffffffffffffffc], 0x40
      [-]c745f0????????
         // 00402463: mov ss:[ebp+0xfffffffffffffff0], 0xa
      [-]f645fd80740c
         // 0040246a: test b1 ss:[ebp+0xfffffffffffffffd], b1 0x80
         // 0040246e: jz 0x40247c
      [-]8d451050e81a03000059eb41
         // 00402470: lea eax, ss:[ebp+0x10]
         // 00402473: push eax
         // 00402474: call _get_int64_arg
         // 00402479: pop ecx
         // 0040247a: jmp 0x4024bd
      [-]f645fc207421
         // 0040247c: test b1 ss:[ebp+0xfffffffffffffffc], b1 0x20
         // 00402480: jz 0x4024a3
      [-]f645fc408d451050740c
         // 00402482: test b1 ss:[ebp+0xfffffffffffffffc], b1 0x40
         // 00402486: lea eax, ss:[ebp+0x10]
         // 00402489: push eax
         // 0040248a: jz 0x402498
      [-]e8f5020000590fbfc0
         // 0040248c: call _get_int_arg
         // 00402491: pop ecx
         // 00402492: movsx eax, b2 ax
      [-]e8e9020000590fb7c0ebf2
         // 00402498: call _get_int_arg
         // 0040249d: pop ecx
         // 0040249e: movzx eax, b2 ax
         // 004024a1: jmp 0x402495
      [-]f645fc408d4510507408
         // 004024a3: test b1 ss:[ebp+0xfffffffffffffffc], b1 0x40
         // 004024a7: lea eax, ss:[ebp+0x10]
         // 004024aa: push eax
         // 004024ab: jz 0x4024b5
      [-]e8d402000059ebe0
         // 004024ad: call _get_int_arg
         // 004024b2: pop ecx
         // 004024b3: jmp 0x402495
      [-]e8cc02000059
         // 004024b5: call _get_int_arg
         // 004024ba: pop ecx
      [-]f645fc40741d
         // 004024bd: test b1 ss:[ebp+0xfffffffffffffffc], b1 0x40
         // 004024c1: jz 0x4024e0
      [-]f7d883d2008945e0f7da804dfd018955e4eb06
         // 004024cd: neg eax
         // 004024cf: adc edx, 0x0
         // 004024d2: mov ss:[ebp+0xffffffffffffffe0], eax
         // 004024d5: neg edx
         // 004024d7: or b1 ss:[ebp+0xfffffffffffffffd], b1 0x1
         // 004024db: mov ss:[ebp+0xffffffffffffffe4], edx
         // 004024de: jmp 0x4024e6
      [-]8945e08955e4
         // 004024e0: mov ss:[ebp+0xffffffffffffffe0], eax
         // 004024e3: mov ss:[ebp+0xffffffffffffffe4], edx
      [-]f645fd807504
         // 004024e6: test b1 ss:[ebp+0xfffffffffffffffd], b1 0x80
         // 004024ea: jnz 0x4024f0
      [-]8365e400
         // 004024ec: and ss:[ebp+0xffffffffffffffe4], 0x0
      [-]837df8007d09
         // 004024f0: cmp ss:[ebp+0xfffffffffffffff8], 0x0
         // 004024f4: jge 0x4024ff
      [-]c745f8????????eb11
         // 004024f6: mov ss:[ebp+0xfffffffffffffff8], 0x1
         // 004024fd: jmp 0x402510
      [-]8365fcf7b8????????3945f87e03
         // 004024ff: and ss:[ebp+0xfffffffffffffffc], 0xfffffffffffffff7
         // 00402503: mov eax, 0x200
         // 00402508: cmp ss:[ebp+0xfffffffffffffff8], eax
         // 0040250b: jle 0x402510
      [-]8b45e00b45e47504
         // 00402510: mov eax, ss:[ebp+0xffffffffffffffe0]
         // 00402513: or eax, ss:[ebp+0xffffffffffffffe4]
         // 00402516: jnz 0x40251c
      [-]8365dc00
         // 00402518: and ss:[ebp+0xffffffffffffffdc], 0x0
      [-]8d45b38945f4
         // 0040251c: lea eax, ss:[ebp+0xffffffffffffffb3]
         // 0040251f: mov ss:[ebp+0xfffffffffffffff4], eax
      [-]8b45f8ff4df8
         // 00402522: mov eax, ss:[ebp+0xfffffffffffffff8]
         // 00402525: dec ss:[ebp+0xfffffffffffffff8]
      [-]8b45e00b45e4743f
         // 0040252c: mov eax, ss:[ebp+0xffffffffffffffe0]
         // 0040252f: or eax, ss:[ebp+0xffffffffffffffe4]
         // 00402532: jz 0x402573
      [-]8b45f099
         // 00402534: mov eax, ss:[ebp+0xfffffffffffffff0]
         // 00402537: cdq 
      [-]5756ff75e4ff75e0e8172d0000
         // 0040253c: push edi
         // 0040253d: push esi
         // 0040253e: push ss:[ebp+0xffffffffffffffe4]
         // 00402541: push ss:[ebp+0xffffffffffffffe0]
         // 00402544: call 0x405260
      [-]56ff75e4
         // 0040254a: push esi
         // 0040254b: push ss:[ebp+0xffffffffffffffe4]
      [-]83c330ff75e0e8952c000083fb398945e08955e47e03
         // 00402550: add ebx, 0x30
         // 00402553: push ss:[ebp+0xffffffffffffffe0]
         // 00402556: call 0x4051f0
         // 0040255b: cmp ebx, 0x39
         // 0040255e: mov ss:[ebp+0xffffffffffffffe0], eax
         // 00402561: mov ss:[ebp+0xffffffffffffffe4], edx
         // 00402564: jle 0x402569
      [-]8b45f4ff4df48818ebaf
         // 00402569: mov eax, ss:[ebp+0xfffffffffffffff4]
         // 0040256c: dec ss:[ebp+0xfffffffffffffff4]
         // 0040256f: mov b1 ds:[eax], b1 bl
         // 00402571: jmp 0x402522
      [-]8d45b32b45f4ff45f4f645fd028945f07419
         // 00402573: lea eax, ss:[ebp+0xffffffffffffffb3]
         // 00402576: sub eax, ss:[ebp+0xfffffffffffffff4]
         // 00402579: inc ss:[ebp+0xfffffffffffffff4]
         // 0040257c: test b1 ss:[ebp+0xfffffffffffffffd], b1 0x2
         // 00402580: mov ss:[ebp+0xfffffffffffffff0], eax
         // 00402583: jz 0x40259e
      [-]8b4df48039307504
         // 00402585: mov ecx, ss:[ebp+0xfffffffffffffff4]
         // 00402588: cmp b1 ds:[ecx], b1 0x30
         // 0040258b: jnz 0x402591
      [-]ff4df4408b4df4c60130
         // 00402591: dec ss:[ebp+0xfffffffffffffff4]
         // 00402594: inc eax
         // 00402595: mov ecx, ss:[ebp+0xfffffffffffffff4]
         // 00402598: mov b1 ds:[ecx], b1 0x30
      [-]837dc8000f85f4000000
         // 0040259e: cmp ss:[ebp+0xffffffffffffffc8], 0x0
         // 004025a2: jnz 0x40269c
      [-]8b5dfcf6c3407426
         // 004025a8: mov ebx, ss:[ebp+0xfffffffffffffffc]
         // 004025ab: test b1 bl, b1 0x40
         // 004025ae: jz 0x4025d6
      [-]f6c7017406
         // 004025b0: test b1 bh, b1 0x1
         // 004025b3: jz 0x4025bb
      [-]c645ea2deb14
         // 004025b5: mov b1 ss:[ebp+0xffffffffffffffea], b1 0x2d
         // 004025b9: jmp 0x4025cf
      [-]f6c3017406
         // 004025bb: test b1 bl, b1 0x1
         // 004025be: jz 0x4025c6
      [-]c645ea2beb09
         // 004025c0: mov b1 ss:[ebp+0xffffffffffffffea], b1 0x2b
         // 004025c4: jmp 0x4025cf
      [-]f6c302740b
         // 004025c6: test b1 bl, b1 0x2
         // 004025c9: jz 0x4025d6
      [-]c645ea20
         // 004025cb: mov b1 ss:[ebp+0xffffffffffffffea], b1 0x20
      [-]c745dc????????
         // 004025cf: mov ss:[ebp+0xffffffffffffffdc], 0x1
      [-]8b75d82b75dc2b75f0f6c30c7512
         // 004025d6: mov esi, ss:[ebp+0xffffffffffffffd8]
         // 004025d9: sub esi, ss:[ebp+0xffffffffffffffdc]
         // 004025dc: sub esi, ss:[ebp+0xfffffffffffffff0]
         // 004025df: test b1 bl, b1 0xc
         // 004025e2: jnz 0x4025f6
      [-]8d45ec50ff7508566a20e82a01000083c410
         // 004025e4: lea eax, ss:[ebp+0xffffffffffffffec]
         // 004025e7: push eax
         // 004025e8: push ss:[ebp+0x8]
         // 004025eb: push esi
         // 004025ec: push 0x20
         // 004025ee: call _write_multi_char
         // 004025f3: add esp, 0x10
      [-]8d45ec508d45eaff7508ff75dc50e84501000083c410f6c3087417
         // 004025f6: lea eax, ss:[ebp+0xffffffffffffffec]
         // 004025f9: push eax
         // 004025fa: lea eax, ss:[ebp+0xffffffffffffffea]
         // 004025fd: push ss:[ebp+0x8]
         // 00402600: push ss:[ebp+0xffffffffffffffdc]
         // 00402603: push eax
         // 00402604: call _write_string
         // 00402609: add esp, 0x10
         // 0040260c: test b1 bl, b1 0x8
         // 0040260f: jz 0x402628
      [-]f6c3047512
         // 00402611: test b1 bl, b1 0x4
         // 00402614: jnz 0x402628
      [-]8d45ec50ff7508566a30e8f800000083c410
         // 00402616: lea eax, ss:[ebp+0xffffffffffffffec]
         // 00402619: push eax
         // 0040261a: push ss:[ebp+0x8]
         // 0040261d: push esi
         // 0040261e: push 0x30
         // 00402620: call _write_multi_char
         // 00402625: add esp, 0x10
      [-]837dd4007441
         // 00402628: cmp ss:[ebp+0xffffffffffffffd4], 0x0
         // 0040262c: jz 0x40266f
      [-]837df0007e3b
         // 0040262e: cmp ss:[ebp+0xfffffffffffffff0], 0x0
         // 00402632: jle 0x40266f
      [-]8b45f08b5df48d78ff
         // 00402634: mov eax, ss:[ebp+0xfffffffffffffff0]
         // 00402637: mov ebx, ss:[ebp+0xfffffffffffffff4]
         // 0040263a: lea edi, ds:[eax+0xffffffffffffffff]
      [-]668b0343508d45bc5043e82f2b000059
         // 0040263d: mov b2 ax, b2 ds:[ebx]
         // 00402640: inc ebx
         // 00402641: push eax
         // 00402642: lea eax, ss:[ebp+0xffffffffffffffbc]
         // 00402645: push eax
         // 00402646: inc ebx
         // 00402647: call 0x40517b
         // 0040264c: pop ecx
      [-]8d4dec51ff7508508d45bc50e8eb00000083c410
         // 00402652: lea ecx, ss:[ebp+0xffffffffffffffec]
         // 00402655: push ecx
         // 00402656: push ss:[ebp+0x8]
         // 00402659: push eax
         // 0040265a: lea eax, ss:[ebp+0xffffffffffffffbc]
         // 0040265d: push eax
         // 0040265e: call 0x40274e
         // 00402663: add esp, 0x10
      [-]8d45ec50ff7508ff75f0ff75f4e8cd00000083c410
         // 0040266f: lea eax, ss:[ebp+0xffffffffffffffec]
         // 00402672: push eax
         // 00402673: push ss:[ebp+0x8]
         // 00402676: push ss:[ebp+0xfffffffffffffff0]
         // 00402679: push ss:[ebp+0xfffffffffffffff4]
         // 0040267c: call _write_string
         // 00402681: add esp, 0x10
      [-]f645fc047412
         // 00402684: test b1 ss:[ebp+0xfffffffffffffffc], b1 0x4
         // 00402688: jz 0x40269c
      [-]8d45ec50ff7508566a20e88400000083c410
         // 0040268a: lea eax, ss:[ebp+0xffffffffffffffec]
         // 0040268d: push eax
         // 0040268e: push ss:[ebp+0x8]
         // 00402691: push esi
         // 00402692: push 0x20
         // 00402694: call _write_multi_char
         // 00402699: add esp, 0x10
      [-]837dd000740d
         // 0040269c: cmp ss:[ebp+0xffffffffffffffd0], 0x0
         // 004026a0: jz def_401FC6
      [-]ff75d0e8f4f3ffff8365d00059
         // 004026a2: push ss:[ebp+0xffffffffffffffd0]
         // 004026a5: call 0x401a9e
         // 004026aa: and ss:[ebp+0xffffffffffffffd0], 0x0
         // 004026ae: pop ecx
      [-]8b750c8a1e4684db89750c0f85bef8ffff
         // 004026af: mov esi, ss:[ebp+0xc]
         // 004026b2: mov b1 bl, b1 ds:[esi]
         // 004026b4: inc esi
         // 004026b5: test b1 bl, b1 bl
         // 004026b7: mov ss:[ebp+0xc], esi
         // 004026ba: jnz 0x401f7e
      [-]8b45ec5f5e5bc9c3
         // 004026c0: mov eax, ss:[ebp+0xffffffffffffffec]
         // 004026c3: pop edi
         // 004026c4: pop esi
         // 004026c5: pop ebx
         // 004026c6: leave 
         // 004026c7: retn 
      [-]6a01e80200000059c3
         // 004029df: push 0x1
         // 004029e1: call _flsall
         // 004029e6: pop ecx
         // 004029e7: retn 
      [-]568b7424086a00832600ff15407040006681384d5a7514
         // 00403080: push esi
         // 00403081: mov esi, ss:[esp+0x8]
         // 00403085: push 0x0
         // 00403087: and ds:[esi], 0x0
         // 0040308a: call ds:[GetModuleHandleA]
         // 00403090: cmp b2 ds:[eax], b2 0x5a4d
         // 00403095: jnz 0x4030ab
      [-]03c18a481a880e8a401b884601
         // 0040309e: add eax, ecx
         // 004030a0: mov b1 cl, b1 ds:[eax+0x1a]
         // 004030a3: mov b1 ds:[esi], b1 cl
         // 004030a5: mov b1 al, b1 ds:[eax+0x1b]
         // 004030a8: mov b1 ds:[esi+0x1], b1 al
      [-]558becb8????????e8662900008d85????????5350c785????????????????ff1548704000
         // 004030ad: push ebp
         // 004030ae: mov ebp, esp
         // 004030b0: mov eax, 0x122c
         // 004030b5: call __alloca_probe
         // 004030ba: lea eax, ss:[ebp+0xffffffffffffff68]
         // 004030c0: push ebx
         // 004030c1: push eax
         // 004030c2: mov ss:[ebp+0xffffffffffffff68], 0x94
         // 004030cc: call ds:[GetVersionExA]
      [-]83bd????????027511
         // 004030d6: cmp ss:[ebp+0xffffffffffffff78], 0x2
         // 004030dd: jnz 0x4030f0
      [-]83bd????????057208
         // 004030df: cmp ss:[ebp+0xffffffffffffff6c], 0x5
         // 004030e6: jb 0x4030f0
      [-]6a0158e902010000
         // 004030e8: push 0x1
         // 004030ea: pop eax
         // 004030eb: jmp 0x4031f2
      [-]8d85????????68????????5068????????ff1544704000
         // 004030f0: lea eax, ss:[ebp+0xffffffffffffedd4]
         // 004030f6: push 0x1090
         // 004030fb: push eax
         // 004030fc: push 0x407168
         // 00403101: call ds:[GetEnvironmentVariableA]
      [-]0f84d0000000
         // 00403109: jz 0x4031df
      [-]8d8d????????389dd4edffff7413
         // 00403111: lea ecx, ss:[ebp+0xffffffffffffedd4]
         // 00403117: cmp b1 ss:[ebp+0xffffffffffffedd4], b1 bl
         // 0040311d: jz 0x403132
      [-]8a013c617c08
         // 0040311f: mov b1 al, b1 ds:[ecx]
         // 00403121: cmp b1 al, b1 0x61
         // 00403123: jl 0x40312d
      [-]3c7a7f04
         // 00403125: cmp b1 al, b1 0x7a
         // 00403127: jg 0x40312d
      [-]2c208801
         // 00403129: sub b1 al, b1 0x20
         // 0040312b: mov b1 ds:[ecx], b1 al
      [-]41381975ed
         // 0040312d: inc ecx
         // 0040312e: cmp b1 ds:[ecx], b1 bl
         // 00403130: jnz 0x40311f
      [-]8d85????????6a165068????????e8dbebffff83c40c
         // 00403132: lea eax, ss:[ebp+0xffffffffffffedd4]
         // 00403138: push 0x16
         // 0040313a: push eax
         // 0040313b: push 0x407150
         // 00403140: call 0x401d20
         // 00403145: add esp, 0xc
      [-]8d85????????eb49
         // 0040314c: lea eax, ss:[ebp+0xffffffffffffedd4]
         // 00403152: jmp 0x40319d
      [-]8d85????????68????????5053ff1510704000389d64feffff8d8d????????7413
         // 00403154: lea eax, ss:[ebp+0xfffffffffffffe64]
         // 0040315a: push 0x104
         // 0040315f: push eax
         // 00403160: push ebx
         // 00403161: call ds:[GetModuleFileNameA]
         // 00403167: cmp b1 ss:[ebp+0xfffffffffffffe64], b1 bl
         // 0040316d: lea ecx, ss:[ebp+0xfffffffffffffe64]
         // 00403173: jz 0x403188
      [-]8a013c617c08
         // 00403175: mov b1 al, b1 ds:[ecx]
         // 00403177: cmp b1 al, b1 0x61
         // 00403179: jl 0x403183
      [-]3c7a7f04
         // 0040317b: cmp b1 al, b1 0x7a
         // 0040317d: jg 0x403183
      [-]2c208801
         // 0040317f: sub b1 al, b1 0x20
         // 00403181: mov b1 ds:[ecx], b1 al
      [-]41381975ed
         // 00403183: inc ecx
         // 00403184: cmp b1 ds:[ecx], b1 bl
         // 00403186: jnz 0x403175
      [-]8d85????????508d85????????50e8052800005959
         // 00403188: lea eax, ss:[ebp+0xfffffffffffffe64]
         // 0040318e: push eax
         // 0040318f: lea eax, ss:[ebp+0xffffffffffffedd4]
         // 00403195: push eax
         // 00403196: call _strstr
         // 0040319b: pop ecx
         // 0040319c: pop ecx
      [-]3bc3743e
         // 0040319d: cmp eax, ebx
         // 0040319f: jz 0x4031df
      [-]6a2c50e837270000593bc3597430
         // 004031a1: push 0x2c
         // 004031a3: push eax
         // 004031a4: call _strchr
         // 004031a9: pop ecx
         // 004031aa: cmp eax, ebx
         // 004031ac: pop ecx
         // 004031ad: jz 0x4031df
      [-]3818740e
         // 004031b2: cmp b1 ds:[eax], b1 bl
         // 004031b4: jz 0x4031c4
      [-]80393b7504
         // 004031b6: cmp b1 ds:[ecx], b1 0x3b
         // 004031b9: jnz 0x4031bf
      [-]8819eb01
         // 004031bb: mov b1 ds:[ecx], b1 bl
         // 004031bd: jmp 0x4031c0
      [-]381975f2
         // 004031c0: cmp b1 ds:[ecx], b1 bl
         // 004031c2: jnz 0x4031b6
      [-]6a0a5350e8d624000083c40c83f802741d
         // 004031c4: push 0xa
         // 004031c6: push ebx
         // 004031c7: push eax
         // 004031c8: call _strtol
         // 004031cd: add esp, 0xc
         // 004031d0: cmp eax, 0x2
         // 004031d3: jz 0x4031f2
      [-]83f8037418
         // 004031d5: cmp eax, 0x3
         // 004031d8: jz 0x4031f2
      [-]83f8017413
         // 004031da: cmp eax, 0x1
         // 004031dd: jz 0x4031f2
      [-]8d45fc50e898feffff807dfc06591bc0
         // 004031df: lea eax, ss:[ebp+0xfffffffffffffffc]
         // 004031e2: push eax
         // 004031e3: call 0x403080
         // 004031e8: cmp b1 ss:[ebp+0xfffffffffffffffc], b1 0x6
         // 004031ec: pop ecx
         // 004031ed: sbb eax, eax
      [-]6a003944240868????????0f94c050ff1550704000
         // 004031f7: push 0x0
         // 004031f9: cmp ss:[esp+0x8], eax
         // 004031fd: push 0x1000
         // 00403202: setz b1 al
         // 00403205: push eax
         // 00403206: call ds:[HeapCreate]
      [-]a3????????7436
         // 0040320e: mov ds:[0x40ae80], eax
         // 00403213: jz 0x40324b
      [-]e893feffff83f803a3????????750d
         // 00403215: call 0x4030ad
         // 0040321a: cmp eax, 0x3
         // 0040321d: mov ds:[0x40ae84], eax
         // 00403222: jnz 0x403231
      [-]68????????e82400000059eb0a
         // 00403224: push 0x3f8
         // 00403229: call ___sbh_heap_init
         // 0040322e: pop ecx
         // 0040322f: jmp 0x40323b
      [-]83f8027518
         // 00403231: cmp eax, 0x2
         // 00403234: jnz 0x40324e
      [-]e868080000
         // 00403236: call 0x403aa3
      [-]ff35????????ff154c704000
         // 0040323f: push ds:[0x40ae80]
         // 00403245: call ds:[HeapDestroy]
      [-]6a0158c3
         // 0040324e: push 0x1
         // 00403250: pop eax
         // 00403251: retn 
      [-]558bec83ec108b4d0853568b750c8b411057
         // 004032c5: push ebp
         // 004032c6: mov ebp, esp
         // 004032c8: sub esp, 0x10
         // 004032cb: mov ecx, ss:[ebp+0x8]
         // 004032ce: push ebx
         // 004032cf: push esi
         // 004032d0: mov esi, ss:[ebp+0xc]
         // 004032d3: mov eax, ds:[ecx+0x10]
         // 004032d6: push edi
      [-]83c6fc2b790cc1ef0f
         // 004032d9: add esi, 0xfffffffffffffffc
         // 004032dc: sub edi, ds:[ecx+0xc]
         // 004032df: shr edi, b1 0xf
      [-]69c9????????8d8c01????????894df08b0e49f6c101894dfc0f85e6020000
         // 004032e4: imul ecx, 0x204
         // 004032ea: lea ecx, ds:[ecx+eax+0x144]
         // 004032f1: mov ss:[ebp+0xfffffffffffffff0], ecx
         // 004032f4: mov ecx, ds:[esi]
         // 004032f6: dec ecx
         // 004032f7: test b1 cl, b1 0x1
         // 004032fa: mov ss:[ebp+0xfffffffffffffffc], ecx
         // 004032fd: jnz 0x4035e9
      [-]8b14318d1c318955f48b56fc8955f88b55f4f6c201895d0c757e
         // 00403303: mov edx, ds:[ecx+esi]
         // 00403306: lea ebx, ds:[ecx+esi]
         // 00403309: mov ss:[ebp+0xfffffffffffffff4], edx
         // 0040330c: mov edx, ds:[esi+0xfffffffffffffffc]
         // 0040330f: mov ss:[ebp+0xfffffffffffffff8], edx
         // 00403312: mov edx, ss:[ebp+0xfffffffffffffff4]
         // 00403315: test b1 dl, b1 0x1
         // 00403318: mov ss:[ebp+0xc], ebx
         // 0040331b: jnz 0x40339b
      [-]c1fa044a83fa3f7603
         // 0040331d: sar edx, b1 0x4
         // 00403320: dec edx
         // 00403321: cmp edx, 0x3f
         // 00403324: jbe 0x403329
      [-]8b4b043b4b08754c
         // 00403329: mov ecx, ds:[ebx+0x4]
         // 0040332c: cmp ecx, ds:[ebx+0x8]
         // 0040332f: jnz 0x40337d
      [-]83fa20731e
         // 00403331: cmp edx, 0x20
         // 00403334: jnb 0x403354
      [-]bb????????
         // 00403336: mov ebx, 0xffffffff80000000
      [-]d3eb8d4c0204f7d3215cb844fe097528
         // 0040333d: shr ebx, b1 cl
         // 0040333f: lea ecx, ds:[edx+eax+0x4]
         // 00403343: not ebx
         // 00403345: and ds:[eax+edi*0x4], ebx
         // 00403349: dec b1 ds:[ecx]
         // 0040334b: jnz 0x403375
      [-]8b4d082119eb21
         // 0040334d: mov ecx, ss:[ebp+0x8]
         // 00403350: and ds:[ecx], ebx
         // 00403352: jmp 0x403375
      [-]8d4ae0bb????????d3eb8d4c0204f7d3219cb8c4000000fe097506
         // 00403354: lea ecx, ds:[edx+0xffffffffffffffe0]
         // 00403357: mov ebx, 0xffffffff80000000
         // 0040335c: shr ebx, b1 cl
         // 0040335e: lea ecx, ds:[edx+eax+0x4]
         // 00403362: not ebx
         // 00403364: and ds:[eax+edi*0x4], ebx
         // 0040336b: dec b1 ds:[ecx]
         // 0040336d: jnz 0x403375
      [-]8b4d08215904
         // 0040336f: mov ecx, ss:[ebp+0x8]
         // 00403372: and ds:[ecx+0x4], ebx
      [-]8b4dfc8b5d0ceb03
         // 00403375: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 00403378: mov ebx, ss:[ebp+0xc]
         // 0040337b: jmp 0x403380
      [-]8b53088b5b04034df4895a048b550c894dfc8b5a048b5208895308
         // 00403380: mov edx, ds:[ebx+0x8]
         // 00403383: mov ebx, ds:[ebx+0x4]
         // 00403386: add ecx, ss:[ebp+0xfffffffffffffff4]
         // 00403389: mov ds:[edx+0x4], ebx
         // 0040338c: mov edx, ss:[ebp+0xc]
         // 0040338f: mov ss:[ebp+0xfffffffffffffffc], ecx
         // 00403392: mov ebx, ds:[edx+0x4]
         // 00403395: mov edx, ds:[edx+0x8]
         // 00403398: mov ds:[ebx+0x8], edx
      [-]c1fa044a83fa3f7603
         // 0040339d: sar edx, b1 0x4
         // 004033a0: dec edx
         // 004033a1: cmp edx, 0x3f
         // 004033a4: jbe 0x4033a9
      [-]8b5df883e301895df40f8594000000
         // 004033a9: mov ebx, ss:[ebp+0xfffffffffffffff8]
         // 004033ac: and ebx, 0x1
         // 004033af: mov ss:[ebp+0xfffffffffffffff4], ebx
         // 004033b2: jnz 0x40344c
      [-]2b75f88b5df8c1fb046a3f89750c4b5e3bde7602
         // 004033b8: sub esi, ss:[ebp+0xfffffffffffffff8]
         // 004033bb: mov ebx, ss:[ebp+0xfffffffffffffff8]
         // 004033be: sar ebx, b1 0x4
         // 004033c1: push 0x3f
         // 004033c3: mov ss:[ebp+0xc], esi
         // 004033c6: dec ebx
         // 004033c7: pop esi
         // 004033c8: cmp ebx, esi
         // 004033ca: jbe 0x4033ce
      [-]894dfcc1fa044a3bd67602
         // 004033d3: mov ss:[ebp+0xfffffffffffffffc], ecx
         // 004033d6: sar edx, b1 0x4
         // 004033d9: dec edx
         // 004033da: cmp edx, esi
         // 004033dc: jbe 0x4033e0
      [-]3bda7463
         // 004033e0: cmp ebx, edx
         // 004033e2: jz 0x403447
      [-]8b4d0c8b71043b71087540
         // 004033e4: mov ecx, ss:[ebp+0xc]
         // 004033e7: mov esi, ds:[ecx+0x4]
         // 004033ea: cmp esi, ds:[ecx+0x8]
         // 004033ed: jnz 0x40342f
      [-]83fb20731c
         // 004033ef: cmp ebx, 0x20
         // 004033f2: jnb 0x403410
      [-]be????????
         // 004033f4: mov esi, 0xffffffff80000000
      [-]d3eef7d62174b844fe4c03047526
         // 004033fb: shr esi, b1 cl
         // 004033fd: not esi
         // 004033ff: and ds:[eax+edi*0x4], esi
         // 00403403: dec b1 ds:[ebx+eax+0x4]
         // 00403407: jnz 0x40342f
      [-]8b4d082131eb1f
         // 00403409: mov ecx, ss:[ebp+0x8]
         // 0040340c: and ds:[ecx], esi
         // 0040340e: jmp 0x40342f
      [-]8d4be0be????????d3eef7d621b4b8c4000000fe4c03047506
         // 00403410: lea ecx, ds:[ebx+0xffffffffffffffe0]
         // 00403413: mov esi, 0xffffffff80000000
         // 00403418: shr esi, b1 cl
         // 0040341a: not esi
         // 0040341c: and ds:[eax+edi*0x4], esi
         // 00403423: dec b1 ds:[ebx+eax+0x4]
         // 00403427: jnz 0x40342f
      [-]8b4d08217104
         // 00403429: mov ecx, ss:[ebp+0x8]
         // 0040342c: and ds:[ecx+0x4], esi
      [-]8b4d0c8b71088b4904894e048b4d0c8b71048b4908894e08
         // 0040342f: mov ecx, ss:[ebp+0xc]
         // 00403432: mov esi, ds:[ecx+0x8]
         // 00403435: mov ecx, ds:[ecx+0x4]
         // 00403438: mov ds:[esi+0x4], ecx
         // 0040343b: mov ecx, ss:[ebp+0xc]
         // 0040343e: mov esi, ds:[ecx+0x4]
         // 00403441: mov ecx, ds:[ecx+0x8]
         // 00403444: mov ds:[esi+0x8], ecx
      [-]8b750ceb03
         // 00403447: mov esi, ss:[ebp+0xc]
         // 0040344a: jmp 0x40344f
      [-]837df4007508
         // 0040344f: cmp ss:[ebp+0xfffffffffffffff4], 0x0
         // 00403453: jnz 0x40345d
      [-]3bda0f8481000000
         // 00403455: cmp ebx, edx
         // 00403457: jz 0x4034de
      [-]8b4df08b5cd1048d0cd1895e04894e088971048b4e048971088b4e043b4e087560
         // 0040345d: mov ecx, ss:[ebp+0xfffffffffffffff0]
         // 00403460: mov ebx, ds:[ecx+edx*0x8]
         // 00403464: lea ecx, ds:[ecx+edx*0x8]
         // 00403467: mov ds:[esi+0x4], ebx
         // 0040346a: mov ds:[esi+0x8], ecx
         // 0040346d: mov ds:[ecx+0x4], esi
         // 00403470: mov ecx, ds:[esi+0x4]
         // 00403473: mov ds:[ecx+0x8], esi
         // 00403476: mov ecx, ds:[esi+0x4]
         // 00403479: cmp ecx, ds:[esi+0x8]
         // 0040347c: jnz 0x4034de
      [-]8a4c020483fa20884d0ffec1884c02047325
         // 0040347e: mov b1 cl, b1 ds:[edx+eax+0x4]
         // 00403482: cmp edx, 0x20
         // 00403485: mov b1 ss:[ebp+0xf], b1 cl
         // 00403488: inc b1 cl
         // 0040348a: mov b1 ds:[edx+eax+0x4], b1 cl
         // 0040348e: jnb 0x4034b5
      [-]807d0f00750e
         // 00403490: cmp b1 ss:[ebp+0xf], b1 0x0
         // 00403494: jnz 0x4034a4
      [-]bb????????
         // 00403496: mov ebx, 0xffffffff80000000
      [-]d3eb8b4d080919
         // 0040349d: shr ebx, b1 cl
         // 0040349f: mov ecx, ss:[ebp+0x8]
         // 004034a2: or ds:[ecx], ebx
      [-]bb????????
         // 004034a4: mov ebx, 0xffffffff80000000
      [-]d3eb8d44b8440918eb29
         // 004034ab: shr ebx, b1 cl
         // 004034ad: lea eax, ds:[eax+edi*0x4]
         // 004034b1: or ds:[eax], ebx
         // 004034b3: jmp 0x4034de
      [-]807d0f007510
         // 004034b5: cmp b1 ss:[ebp+0xf], b1 0x0
         // 004034b9: jnz 0x4034cb
      [-]8d4ae0bb????????d3eb8b4d08095904
         // 004034bb: lea ecx, ds:[edx+0xffffffffffffffe0]
         // 004034be: mov ebx, 0xffffffff80000000
         // 004034c3: shr ebx, b1 cl
         // 004034c5: mov ecx, ss:[ebp+0x8]
         // 004034c8: or ds:[ecx+0x4], ebx
      [-]8d4ae0ba????????d3ea8d84b8c40000000910
         // 004034cb: lea ecx, ds:[edx+0xffffffffffffffe0]
         // 004034ce: mov edx, 0xffffffff80000000
         // 004034d3: shr edx, b1 cl
         // 004034d5: lea eax, ds:[eax+edi*0x4]
         // 004034dc: or ds:[eax], edx
      [-]8b45fc8906894430fc8b45f0ff080f85f7000000
         // 004034de: mov eax, ss:[ebp+0xfffffffffffffffc]
         // 004034e1: mov ds:[esi], eax
         // 004034e3: mov ds:[eax+esi+0xfffffffffffffffc], eax
         // 004034e7: mov eax, ss:[ebp+0xfffffffffffffff0]
         // 004034ea: dec ds:[eax]
         // 004034ec: jnz 0x4035e9
      [-]a1????????
         // 004034f2: mov eax, ds:[0x40ae70]
      [-]0f84dc000000
         // 004034f9: jz 0x4035db
      [-]8b0d????????8b3554704000c1e10f03480cbb????????68????????5351ffd68b0d????????a1????????ba????????d3ea095008a1????????8b0d????????8b401083a488c4????????a1????????8b4010fe4843a1????????8b4810807943007509
         // 004034ff: mov ecx, ds:[0x40ae68]
         // 00403505: mov esi, ds:[VirtualFree]
         // 0040350b: shl ecx, b1 0xf
         // 0040350e: add ecx, ds:[eax+0xc]
         // 00403511: mov ebx, 0x8000
         // 00403516: push 0x4000
         // 0040351b: push ebx
         // 0040351c: push ecx
         // 0040351d: call esi
         // 0040351f: mov ecx, ds:[0x40ae68]
         // 00403525: mov eax, ds:[0x40ae70]
         // 0040352a: mov edx, 0xffffffff80000000
         // 0040352f: shr edx, b1 cl
         // 00403531: or ds:[eax+0x8], edx
         // 00403534: mov eax, ds:[0x40ae70]
         // 00403539: mov ecx, ds:[0x40ae68]
         // 0040353f: mov eax, ds:[eax+0x10]
         // 00403542: and ds:[eax+ecx*0x4], 0x0
         // 0040354a: mov eax, ds:[0x40ae70]
         // 0040354f: mov eax, ds:[eax+0x10]
         // 00403552: dec b1 ds:[eax+0x43]
         // 00403555: mov eax, ds:[0x40ae70]
         // 0040355a: mov ecx, ds:[eax+0x10]
         // 0040355d: cmp b1 ds:[ecx+0x43], b1 0x0
         // 00403561: jnz 0x40356c
      [-]836004fea1????????
         // 00403563: and ds:[eax+0x4], 0xfffffffffffffffe
         // 00403567: mov eax, ds:[0x40ae70]
      [-]837808ff7569
         // 0040356c: cmp ds:[eax+0x8], 0xffffffffffffffff
         // 00403570: jnz 0x4035db
      [-]536a00ff700cffd6a1????????ff70106a00ff35????????ff1528704000a1????????8b15????????8d0480c1e002
         // 00403572: push ebx
         // 00403573: push 0x0
         // 00403575: push ds:[eax+0xc]
         // 00403578: call esi
         // 0040357a: mov eax, ds:[0x40ae70]
         // 0040357f: push ds:[eax+0x10]
         // 00403582: push 0x0
         // 00403584: push ds:[0x40ae80]
         // 0040358a: call ds:[HeapFree]
         // 00403590: mov eax, ds:[0x40ae74]
         // 00403595: mov edx, ds:[0x40ae78]
         // 0040359b: lea eax, ds:[eax+eax*0x4]
         // 0040359e: shl eax, b1 0x2
      [-]a1????????2bc88d4c11ec518d48145150e8972400008b450883c40cff0d????????3b05????????7604
         // 004035a3: mov eax, ds:[0x40ae70]
         // 004035a8: sub ecx, eax
         // 004035aa: lea ecx, ds:[ecx+edx+0xffffffffffffffec]
         // 004035ae: push ecx
         // 004035af: lea ecx, ds:[eax+0x14]
         // 004035b2: push ecx
         // 004035b3: push eax
         // 004035b4: call 0x405a50
         // 004035b9: mov eax, ss:[ebp+0x8]
         // 004035bc: add esp, 0xc
         // 004035bf: dec ds:[0x40ae74]
         // 004035c5: cmp eax, ds:[0x40ae70]
         // 004035cb: jbe 0x4035d1
      [-]836d0814
         // 004035cd: sub ss:[ebp+0x8], 0x14
      [-]a1????????a3????????
         // 004035d1: mov eax, ds:[0x40ae78]
         // 004035d6: mov ds:[0x40ae6c], eax
      [-]8b4508893d????????a3????????
         // 004035db: mov eax, ss:[ebp+0x8]
         // 004035de: mov ds:[0x40ae68], edi
         // 004035e4: mov ds:[0x40ae70], eax
      [-]5f5e5bc9c3
         // 004035e9: pop edi
         // 004035ea: pop esi
         // 004035eb: pop ebx
         // 004035ec: leave 
         // 004035ed: retn 
      [-]833d????????ff535556577507
         // 00403aa3: cmp ds:[0x408378], 0xffffffffffffffff
         // 00403aaa: push ebx
         // 00403aab: push ebp
         // 00403aac: push esi
         // 00403aad: push edi
         // 00403aae: jnz 0x403ab7
      [-]be????????eb1d
         // 00403ab0: mov esi, 0x408368
         // 00403ab5: jmp 0x403ad4
      [-]68????????6a00ff35????????ff1524704000
         // 00403ab7: push 0x2020
         // 00403abc: push 0x0
         // 00403abe: push ds:[0x40ae80]
         // 00403ac4: call ds:[HeapAlloc]
      [-]0f840c010000
         // 00403ace: jz 0x403be0
      [-]8b2d587040006a0468????????68????????6a00ffd5
         // 00403ad4: mov ebp, ds:[VirtualAlloc]
         // 00403ada: push 0x4
         // 00403adc: push 0x2000
         // 00403ae1: push 0x400000
         // 00403ae6: push 0x0
         // 00403ae8: call ebp
      [-]0f84d5000000
         // 00403aee: jz 0x403bc9
      [-]6a04bb????????68????????5357ffd5
         // 00403af4: push 0x4
         // 00403af6: mov ebx, 0x10000
         // 00403afb: push 0x1000
         // 00403b00: push ebx
         // 00403b01: push edi
         // 00403b02: call ebp
      [-]0f84af000000
         // 00403b06: jz 0x403bbb
      [-]b8????????3bf0751e
         // 00403b0c: mov eax, 0x408368
         // 00403b11: cmp esi, eax
         // 00403b13: jnz 0x403b33
      [-]833d????????007505
         // 00403b15: cmp ds:[0x408368], 0x0
         // 00403b1c: jnz 0x403b23
      [-]a3????????
         // 00403b1e: mov ds:[0x408368], eax
      [-]833d????????00751c
         // 00403b23: cmp ds:[0x40836c], 0x0
         // 00403b2a: jnz 0x403b48
      [-]a3????????eb15
         // 00403b2c: mov ds:[0x40836c], eax
         // 00403b31: jmp 0x403b48
      [-]8906a1????????8946048935????????8b46048930
         // 00403b33: mov ds:[esi], eax
         // 00403b35: mov eax, ds:[0x40836c]
         // 00403b3a: mov ds:[esi+0x4], eax
         // 00403b3d: mov ds:[0x40836c], esi
         // 00403b43: mov eax, ds:[esi+0x4]
         // 00403b46: mov ds:[eax], esi
      [-]8d87????????8d8e????????8946148d4618894e0c897e1089460833edb9????????
         // 00403b48: lea eax, ds:[edi+0x400000]
         // 00403b4e: lea ecx, ds:[esi+0x98]
         // 00403b54: mov ds:[esi+0x14], eax
         // 00403b57: lea eax, ds:[esi+0x18]
         // 00403b5a: mov ds:[esi+0xc], ecx
         // 00403b5d: mov ds:[esi+0x10], edi
         // 00403b60: mov ds:[esi+0x8], eax
         // 00403b63: xor ebp, ebp
         // 00403b65: mov ecx, 0xf1
      [-]83fd100f9dc24a23d14a458910894804
         // 00403b6c: cmp ebp, 0x10
         // 00403b6f: setnl b1 dl
         // 00403b72: dec edx
         // 00403b73: and edx, ecx
         // 00403b75: dec edx
         // 00403b76: inc ebp
         // 00403b77: mov ds:[eax], edx
         // 00403b79: mov ds:[eax+0x4], ecx
      [-]81fd????????7ce3
         // 00403b7f: cmp ebp, 0x400
         // 00403b85: jl 0x403b6a
      [-]536a0057e80022000083c40c
         // 00403b87: push ebx
         // 00403b88: push 0x0
         // 00403b8a: push edi
         // 00403b8b: call _memset
         // 00403b90: add esp, 0xc
      [-]8b461003c33bf8731b
         // 00403b93: mov eax, ds:[esi+0x10]
         // 00403b96: add eax, ebx
         // 00403b98: cmp edi, eax
         // 00403b9a: jnb 0x403bb7
      [-]808ff8000000ff8d47088907c74704????????
         // 00403b9c: or b1 ds:[edi+0xf8], b1 0xff
         // 00403ba3: lea eax, ds:[edi+0x8]
         // 00403ba6: mov ds:[edi], eax
         // 00403ba8: mov ds:[edi+0x4], 0xf0
      [-]68????????6a0057ff1554704000
         // 00403bbb: push 0x8000
         // 00403bc0: push 0x0
         // 00403bc2: push edi
         // 00403bc3: call ds:[VirtualFree]
      [-]81fe????????740f
         // 00403bc9: cmp esi, 0x408368
         // 00403bcf: jz 0x403be0
      [-]566a00ff35????????ff1528704000
         // 00403bd1: push esi
         // 00403bd2: push 0x0
         // 00403bd4: push ds:[0x40ae80]
         // 00403bda: call ds:[HeapFree]
      [-]5f5e5d5bc3
         // 00403be2: pop edi
         // 00403be3: pop esi
         // 00403be4: pop ebp
         // 00403be5: pop ebx
         // 00403be6: retn 
      [-]568b74240868????????6a00ff7610ff15547040003935????????7508
         // 00403be7: push esi
         // 00403be8: mov esi, ss:[esp+0x8]
         // 00403bec: push 0x8000
         // 00403bf1: push 0x0
         // 00403bf3: push ds:[esi+0x10]
         // 00403bf6: call ds:[VirtualFree]
         // 00403bfc: cmp ds:[0x40a388], esi
         // 00403c02: jnz 0x403c0c
      [-]8b4604a3????????
         // 00403c04: mov eax, ds:[esi+0x4]
         // 00403c07: mov ds:[0x40a388], eax
      [-]81fe????????7420
         // 00403c0c: cmp esi, 0x408368
         // 00403c12: jz 0x403c34
      [-]8b46048b0e566a0089088b068b4e04894804ff35????????ff15287040005ec3
         // 00403c14: mov eax, ds:[esi+0x4]
         // 00403c17: mov ecx, ds:[esi]
         // 00403c19: push esi
         // 00403c1a: push 0x0
         // 00403c1c: mov ds:[eax], ecx
         // 00403c1e: mov eax, ds:[esi]
         // 00403c20: mov ecx, ds:[esi+0x4]
         // 00403c23: mov ds:[eax+0x4], ecx
         // 00403c26: push ds:[0x40ae80]
         // 00403c2c: call ds:[HeapFree]
         // 00403c32: pop esi
         // 00403c33: retn 
      [-]830d????????ff5ec3
         // 00403c34: or ds:[0x408378], 0xffffffffffffffff
         // 00403c3b: pop esi
         // 00403c3c: retn 
      [-]558bec5153568b35????????57
         // 00403c3d: push ebp
         // 00403c3e: mov ebp, esp
         // 00403c40: push ecx
         // 00403c41: push ebx
         // 00403c42: push esi
         // 00403c43: mov esi, ds:[0x40836c]
         // 00403c49: push edi
      [-]837e10ff0f8494000000
         // 00403c4a: cmp ds:[esi+0x10], 0xffffffffffffffff
         // 00403c4e: jz 0x403ce8
      [-]8365fc008dbe????????bb????????
         // 00403c54: and ss:[ebp+0xfffffffffffffffc], 0x0
         // 00403c58: lea edi, ds:[esi+0x2010]
         // 00403c5e: mov ebx, 0x3ff000
      [-]813f????????7539
         // 00403c63: cmp ds:[edi], 0xf0
         // 00403c69: jnz 0x403ca4
      [-]68????????03461068????????50ff1554704000
         // 00403c6d: push 0x4000
         // 00403c72: add eax, ds:[esi+0x10]
         // 00403c75: push 0x1000
         // 00403c7a: push eax
         // 00403c7b: call ds:[VirtualFree]
      [-]830fffff0d????????8b460c
         // 00403c85: or ds:[edi], 0xffffffffffffffff
         // 00403c88: dec ds:[0x40a9d0]
         // 00403c8e: mov eax, ds:[esi+0xc]
      [-]3bc77603
         // 00403c95: cmp eax, edi
         // 00403c97: jbe 0x403c9c
      [-]ff45fcff4d08740d
         // 00403c9c: inc ss:[ebp+0xfffffffffffffffc]
         // 00403c9f: dec ss:[ebp+0x8]
         // 00403ca2: jz 0x403cb1
      [-]81eb????????
         // 00403ca4: sub ebx, 0x1000
      [-]837dfc00
         // 00403cb1: cmp ss:[ebp+0xfffffffffffffffc], 0x0
      [-]8b7604742c
         // 00403cb7: mov esi, ds:[esi+0x4]
         // 00403cba: jz 0x403ce8

  }
  condition:
    all of them
}
