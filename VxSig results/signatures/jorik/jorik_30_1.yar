rule jorik_30_1 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         555768????????6a006a008bf8ff15249040008be885ed7505
         // 00401000: push ebp
         // 00401001: push edi
         // 00401002: push 0xf003f
         // 00401007: push 0x0
         // 00401009: push 0x0
         // 0040100b: mov edi, eax
         // 0040100d: call ds:[OpenSCManagerW]
         // 00401013: mov ebp, eax
         // 00401015: test ebp, ebp
         // 00401017: jnz 0x40101e
      [-]5f32c05dc3
         // 00401019: pop edi
         // 0040101a: xor b1 al, b1 al
         // 0040101c: pop ebp
         // 0040101d: retn 
      [-]53566a006a006a006a006a0068????????6a006a036a0168????????575755ff15209040008bf085f67521
         // 0040101e: push ebx
         // 0040101f: push esi
         // 00401020: push 0x0
         // 00401022: push 0x0
         // 00401024: push 0x0
         // 00401026: push 0x0
         // 00401028: push 0x0
         // 0040102a: push 0x431d90
         // 0040102f: push 0x0
         // 00401031: push 0x3
         // 00401033: push 0x1
         // 00401035: push 0xf01ff
         // 0040103a: push edi
         // 0040103b: push edi
         // 0040103c: push ebp
         // 0040103d: call ds:[CreateServiceW]
         // 00401043: mov esi, eax
         // 00401045: test esi, esi
         // 00401047: jnz 0x40106a
      [-]8b1d78904000ffd368????????5755ff151c9040008bf085f67506
         // 00401049: mov ebx, ds:[GetLastError]
         // 0040104f: call ebx
         // 00401051: push 0xf01ff
         // 00401056: push edi
         // 00401057: push ebp
         // 00401058: call ds:[OpenServiceW]
         // 0040105e: mov esi, eax
         // 00401060: test esi, esi
         // 00401062: jnz 0x40106a
      [-]ffd332dbeb2a
         // 00401064: call ebx
         // 00401066: xor b1 bl, b1 bl
         // 00401068: jmp 0x401094
      [-]6a006a0056ff151890400085c00f95c384db7516
         // 0040106a: push 0x0
         // 0040106c: push 0x0
         // 0040106e: push esi
         // 0040106f: call ds:[StartServiceW]
         // 00401075: test eax, eax
         // 00401077: setnz b1 bl
         // 0040107a: test b1 bl, b1 bl
         // 0040107c: jnz 0x401094
      [-]ff15789040003d????????7407
         // 0040107e: call ds:[GetLastError]
         // 00401084: cmp eax, 0x3e5
         // 00401089: jz 0x401092
      [-]3d????????7502
         // 0040108b: cmp eax, 0x420
         // 00401090: jnz 0x401094
      [-]8b3d1490400085f67403
         // 00401094: mov edi, ds:[CloseServiceHandle]
         // 0040109a: test esi, esi
         // 0040109c: jz 0x4010a1
      [-]55ffd75e8ac35b5f5dc3
         // 004010a1: push ebp
         // 004010a2: call edi
         // 004010a4: pop esi
         // 004010a5: mov b1 al, b1 bl
         // 004010a7: pop ebx
         // 004010a8: pop edi
         // 004010a9: pop ebp
         // 004010aa: retn 
      [-]83ec108d44240450516a00c744240c????????ff15109040008b4424146a006a006a108d54240c526a0050c7442424????????ff150c904000ff1578904000f7d81bc04083c410c3
         // 004010b0: sub esp, 0x10
         // 004010b3: lea eax, ss:[esp+0x4]
         // 004010b7: push eax
         // 004010b8: push ecx
         // 004010b9: push 0x0
         // 004010bb: mov ss:[esp+0xc], 0x1
         // 004010c3: call ds:[LookupPrivilegeValueW]
         // 004010c9: mov eax, ss:[esp+0x14]
         // 004010cd: push 0x0
         // 004010cf: push 0x0
         // 004010d1: push 0x10
         // 004010d3: lea edx, ss:[esp+0xc]
         // 004010d7: push edx
         // 004010d8: push 0x0
         // 004010da: push eax
         // 004010db: mov ss:[esp+0x24], 0x2
         // 004010e3: call ds:[AdjustTokenPrivileges]
         // 004010e9: call ds:[GetLastError]
         // 004010ef: neg eax
         // 004010f1: sbb eax, eax
         // 004010f3: inc eax
         // 004010f4: add esp, 0x10
         // 004010f7: retn 
      [-]83ec58a104c0400033c489442450568d442408508d4c241033f6516a015689742418c744241c????????c7442420????????c7442428????????8974242c89742430c7442434????????89742438e81513000085c07578
         // 00401100: sub esp, 0x58
         // 00401103: mov eax, ds:[___security_cookie]
         // 00401108: xor eax, esp
         // 0040110a: mov ss:[esp+0x50], eax
         // 0040110e: push esi
         // 0040110f: lea eax, ss:[esp+0x8]
         // 00401113: push eax
         // 00401114: lea ecx, ss:[esp+0x10]
         // 00401118: xor esi, esi
         // 0040111a: push ecx
         // 0040111b: push 0x1
         // 0040111d: push esi
         // 0040111e: mov ss:[esp+0x18], esi
         // 00401122: mov ss:[esp+0x1c], 0x40a530
         // 0040112a: mov ss:[esp+0x20], 0x40a52c
         // 00401132: mov ss:[esp+0x28], 0x1
         // 0040113a: mov ss:[esp+0x2c], esi
         // 0040113e: mov ss:[esp+0x30], esi
         // 00401142: mov ss:[esp+0x34], 0x10040
         // 0040114a: mov ss:[esp+0x38], esi
         // 0040114e: call NetUserAdd
         // 00401153: test eax, eax
         // 00401155: jnz 0x4011cf
      [-]33d2668954242c8944242e89442432894424368944243a8944243e89442442894424468944244a8944244e6689442452eb07
         // 00401157: xor edx, edx
         // 00401159: mov b2 ss:[esp+0x2c], b2 dx
         // 0040115e: mov ss:[esp+0x2e], eax
         // 00401162: mov ss:[esp+0x32], eax
         // 00401166: mov ss:[esp+0x36], eax
         // 0040116a: mov ss:[esp+0x3a], eax
         // 0040116e: mov ss:[esp+0x3e], eax
         // 00401172: mov ss:[esp+0x42], eax
         // 00401176: mov ss:[esp+0x46], eax
         // 0040117a: mov ss:[esp+0x4a], eax
         // 0040117e: mov ss:[esp+0x4e], eax
         // 00401182: mov b2 ss:[esp+0x52], b2 ax
         // 00401187: jmp 0x401190
      [-]0fb78830a5400066894c042c83c002663bce75ec
         // 00401190: movzx ecx, b2 ds:[eax+0x40a530]
         // 00401197: mov b2 ss:[esp+eax+0x2c], b2 cx
         // 0040119c: add eax, 0x2
         // 0040119f: cmp b2 cx, b2 si
         // 004011a2: jnz 0x401190
      [-]6a018d4c2408516a0368????????8d44243c5689442418e8ae12000085c0741d
         // 004011a4: push 0x1
         // 004011a6: lea ecx, ss:[esp+0x8]
         // 004011aa: push ecx
         // 004011ab: push 0x3
         // 004011ad: push 0x40a368
         // 004011b2: lea eax, ss:[esp+0x3c]
         // 004011b6: push esi
         // 004011b7: mov ss:[esp+0x18], eax
         // 004011bb: call NetLocalGroupAddMembers
         // 004011c0: test eax, eax
         // 004011c2: jz 0x4011e1
      [-]68????????56e8a5120000
         // 004011c4: push 0x40a530
         // 004011c9: push esi
         // 004011ca: call NetUserDel
      [-]32c05e8b4c245033cce89d12000083c458c3
         // 004011cf: xor b1 al, b1 al
         // 004011d1: pop esi
         // 004011d2: mov ecx, ss:[esp+0x50]
         // 004011d6: xor ecx, esp
         // 004011d8: call @__security_check_cookie@4
         // 004011dd: add esp, 0x58
         // 004011e0: retn 
      [-]8b4c24545e33ccb001e88b12000083c458c3
         // 004011e1: mov ecx, ss:[esp+0x54]
         // 004011e5: pop esi
         // 004011e6: xor ecx, esp
         // 004011e8: mov b1 al, b1 0x1
         // 004011ea: call @__security_check_cookie@4
         // 004011ef: add esp, 0x58
         // 004011f2: retn 
      [-]83ec0c576a0068????????6a026a006a0168????????68????????ff15709040008bf883ffff7423
         // 00401200: sub esp, 0xc
         // 00401203: push edi
         // 00401204: push 0x0
         // 00401206: push 0x80
         // 0040120b: push 0x2
         // 0040120d: push 0x0
         // 0040120f: push 0x1
         // 00401211: push 0xffffffffe0000000
         // 00401216: push 0x40a388
         // 0040121b: call ds:[CreateFileW]
         // 00401221: mov edi, eax
         // 00401223: cmp edi, 0xffffffffffffffff
         // 00401226: jz 0x40124b
      [-]6a008d44240c5068????????68????????57ff156c90400085c0750e
         // 00401228: push 0x0
         // 0040122a: lea eax, ss:[esp+0xc]
         // 0040122e: push eax
         // 0040122f: push 0x1200
         // 00401234: push 0x430040
         // 00401239: push edi
         // 0040123a: call ds:[WriteFile]
         // 00401240: test eax, eax
         // 00401242: jnz 0x401252
      [-]57ff1574904000
         // 00401244: push edi
         // 00401245: call ds:[CloseHandle]
      [-]33c05f83c40cc3
         // 0040124b: xor eax, eax
         // 0040124d: pop edi
         // 0040124e: add esp, 0xc
         // 00401251: retn 
      [-]55566a0068????????6a006a406a0057ff15689040008b2d749040008bf083feff7448
         // 00401252: push ebp
         // 00401253: push esi
         // 00401254: push 0x0
         // 00401256: push 0x1200
         // 0040125b: push 0x0
         // 0040125d: push 0x40
         // 0040125f: push 0x0
         // 00401261: push edi
         // 00401262: call ds:[CreateFileMappingW]
         // 00401268: mov ebp, ds:[CloseHandle]
         // 0040126e: mov esi, eax
         // 00401270: cmp esi, 0xffffffffffffffff
         // 00401273: jz 0x4012bd
      [-]5368????????6a006a0068????????56ff15649040008bd885db7428
         // 00401275: push ebx
         // 00401276: push 0x1200
         // 0040127b: push 0x0
         // 0040127d: push 0x0
         // 0040127f: push 0xf001f
         // 00401284: push esi
         // 00401285: call ds:[MapViewOfFile]
         // 0040128b: mov ebx, eax
         // 0040128d: test ebx, ebx
         // 0040128f: jz 0x4012b9
      [-]8d4c2410518d54241c5268????????53ff156891400085c07407
         // 00401291: lea ecx, ss:[esp+0x10]
         // 00401295: push ecx
         // 00401296: lea edx, ss:[esp+0x1c]
         // 0040129a: push edx
         // 0040129b: push 0x1200
         // 004012a0: push ebx
         // 004012a1: call ds:[CheckSumMappedFile]
         // 004012a7: test eax, eax
         // 004012a9: jz 0x4012b2
      [-]8b4c2410894858
         // 004012ab: mov ecx, ss:[esp+0x10]
         // 004012af: mov ds:[eax+0x58], ecx
      [-]53ff1548904000
         // 004012b2: push ebx
         // 004012b3: call ds:[UnmapViewOfFile]
      [-]56ffd55b
         // 004012b9: push esi
         // 004012ba: call ebp
         // 004012bc: pop ebx
      [-]57ffd55e5db8????????5f83c40cc3
         // 004012bd: push edi
         // 004012be: call ebp
         // 004012c0: pop esi
         // 004012c1: pop ebp
         // 004012c2: mov eax, 0x1
         // 004012c7: pop edi
         // 004012c8: add esp, 0xc
         // 004012cb: retn 
      [-]81ec????????a104c0400033c4898424????????8b8424????????53558b2d34904000568944241033c0578b3d30904000c6442420008944242189442425894424298944242d8944243189442435894424398944243d33f6
         // 004012d0: sub esp, 0x240
         // 004012d6: mov eax, ds:[___security_cookie]
         // 004012db: xor eax, esp
         // 004012dd: mov ss:[esp+0x23c], eax
         // 004012e4: mov eax, ss:[esp+0x244]
         // 004012eb: push ebx
         // 004012ec: push ebp
         // 004012ed: mov ebp, ds:[Sleep]
         // 004012f3: push esi
         // 004012f4: mov ss:[esp+0x10], eax
         // 004012f8: xor eax, eax
         // 004012fa: push edi
         // 004012fb: mov edi, ds:[GetTickCount]
         // 00401301: mov b1 ss:[esp+0x20], b1 0x0
         // 00401306: mov ss:[esp+0x21], eax
         // 0040130a: mov ss:[esp+0x25], eax
         // 0040130e: mov ss:[esp+0x29], eax
         // 00401312: mov ss:[esp+0x2d], eax
         // 00401316: mov ss:[esp+0x31], eax
         // 0040131a: mov ss:[esp+0x35], eax
         // 0040131e: mov ss:[esp+0x39], eax
         // 00401322: mov ss:[esp+0x3d], eax
         // 00401326: xor esi, esi
      [-]ffd750e80012000083c404e80a12000099b9????????f7f96a148bdaffd580c3616a1e885c3424ffd54683fe207cd1
         // 00401328: call edi
         // 0040132a: push eax
         // 0040132b: call _srand
         // 00401330: add esp, 0x4
         // 00401333: call _rand
         // 00401338: cdq 
         // 00401339: mov ecx, 0x1a
         // 0040133e: idiv ecx
         // 00401340: push 0x14
         // 00401342: mov ebx, edx
         // 00401344: call ebp
         // 00401346: add b1 bl, b1 0x61
         // 00401349: push 0x1e
         // 0040134b: mov b1 ss:[esp+esi+0x24], b1 bl
         // 0040134f: call ebp
         // 00401351: inc esi
         // 00401352: cmp esi, 0x20
         // 00401355: jl 0x401328
      [-]68????????8d542448526a00ff15389040008b3d709040006a0068????????6a036a006a0068????????8d44245c50ffd78bf06a005689742420ff153c9040008bd853e81412000083c4046a008d4c241451538be85556c74424????????00ff15409040008b5424146a0068????????6a026a006a0068????????52ffd78d7d4ab9????????8d742420f3a56a008d7c2bd6b9????????8d742424f3a58d4c24145153555089442428ff156c9040008b5424108b7c24146a00526a006a406a0057ff15689040008bf083feff744e
         // 00401357: push 0x104
         // 0040135c: lea edx, ss:[esp+0x48]
         // 00401360: push edx
         // 00401361: push 0x0
         // 00401363: call ds:[GetModuleFileNameW]
         // 00401369: mov edi, ds:[CreateFileW]
         // 0040136f: push 0x0
         // 00401371: push 0x80
         // 00401376: push 0x3
         // 00401378: push 0x0
         // 0040137a: push 0x0
         // 0040137c: push 0xffffffff80000000
         // 00401381: lea eax, ss:[esp+0x5c]
         // 00401385: push eax
         // 00401386: call edi
         // 00401388: mov esi, eax
         // 0040138a: push 0x0
         // 0040138c: push esi
         // 0040138d: mov ss:[esp+0x20], esi
         // 00401391: call ds:[GetFileSize]
         // 00401397: mov ebx, eax
         // 00401399: push ebx
         // 0040139a: call _malloc
         // 0040139f: add esp, 0x4
         // 004013a2: push 0x0
         // 004013a4: lea ecx, ss:[esp+0x14]
         // 004013a8: push ecx
         // 004013a9: push ebx
         // 004013aa: mov ebp, eax
         // 004013ac: push ebp
         // 004013ad: push esi
         // 004013ae: mov ss:[esp+0x24], 0x0
         // 004013b6: call ds:[ReadFile]
         // 004013bc: mov edx, ss:[esp+0x14]
         // 004013c0: push 0x0
         // 004013c2: push 0x80
         // 004013c7: push 0x2
         // 004013c9: push 0x0
         // 004013cb: push 0x0
         // 004013cd: push 0x40000000
         // 004013d2: push edx
         // 004013d3: call edi
         // 004013d5: lea edi, ss:[ebp+0x4a]
         // 004013d8: mov ecx, 0x8
         // 004013dd: lea esi, ss:[esp+0x20]
         // 004013e1: rep movsdd 
         // 004013e3: push 0x0
         // 004013e5: lea edi, ds:[ebx+ebp+0xffffffffffffffd6]
         // 004013e9: mov ecx, 0x8
         // 004013ee: lea esi, ss:[esp+0x24]
         // 004013f2: rep movsdd 
         // 004013f4: lea ecx, ss:[esp+0x14]
         // 004013f8: push ecx
         // 004013f9: push ebx
         // 004013fa: push ebp
         // 004013fb: push eax
         // 004013fc: mov ss:[esp+0x28], eax
         // 00401400: call ds:[WriteFile]
         // 00401406: mov edx, ss:[esp+0x10]
         // 0040140a: mov edi, ss:[esp+0x14]
         // 0040140e: push 0x0
         // 00401410: push edx
         // 00401411: push 0x0
         // 00401413: push 0x40
         // 00401415: push 0x0
         // 00401417: push edi
         // 00401418: call ds:[CreateFileMappingW]
         // 0040141e: mov esi, eax
         // 00401420: cmp esi, 0xffffffffffffffff
         // 00401423: jz 0x401473
      [-]8b442410506a006a0068????????56ff15649040008bd885db7428
         // 00401425: mov eax, ss:[esp+0x10]
         // 00401429: push eax
         // 0040142a: push 0x0
         // 0040142c: push 0x0
         // 0040142e: push 0xf001f
         // 00401433: push esi
         // 00401434: call ds:[MapViewOfFile]
         // 0040143a: mov ebx, eax
         // 0040143c: test ebx, ebx
         // 0040143e: jz 0x401468
      [-]8b4424108d4c2414518d542420525053ff156891400085c07407
         // 00401440: mov eax, ss:[esp+0x10]
         // 00401444: lea ecx, ss:[esp+0x14]
         // 00401448: push ecx
         // 00401449: lea edx, ss:[esp+0x20]
         // 0040144d: push edx
         // 0040144e: push eax
         // 0040144f: push ebx
         // 00401450: call ds:[CheckSumMappedFile]
         // 00401456: test eax, eax
         // 00401458: jz 0x401461
      [-]8b4c2414894858
         // 0040145a: mov ecx, ss:[esp+0x14]
         // 0040145e: mov ds:[eax+0x58], ecx
      [-]53ff1548904000
         // 00401461: push ebx
         // 00401462: call ds:[UnmapViewOfFile]
      [-]568b3574904000ffd6eb06
         // 00401468: push esi
         // 00401469: mov esi, ds:[CloseHandle]
         // 0040146f: call esi
         // 00401471: jmp 0x401479
      [-]8b3574904000
         // 00401473: mov esi, ds:[CloseHandle]
      [-]55e8fe1100008b54241c83c40452ffd657ffd68b8c24????????5f5e5d5b33cce8dc0f000081c4????????c3
         // 00401479: push ebp
         // 0040147a: call _free
         // 0040147f: mov edx, ss:[esp+0x1c]
         // 00401483: add esp, 0x4
         // 00401486: push edx
         // 00401487: call esi
         // 00401489: push edi
         // 0040148a: call esi
         // 0040148c: mov ecx, ss:[esp+0x24c]
         // 00401493: pop edi
         // 00401494: pop esi
         // 00401495: pop ebp
         // 00401496: pop ebx
         // 00401497: xor ecx, esp
         // 00401499: call @__security_check_cookie@4
         // 0040149e: add esp, 0x240
         // 004014a4: retn 
      [-]81ec????????a104c0400033c4898424????????c7442404????????c7442408????????33c0eb08
         // 004014b0: sub esp, 0x5a0
         // 004014b6: mov eax, ds:[___security_cookie]
         // 004014bb: xor eax, esp
         // 004014bd: mov ss:[esp+0x59c], eax
         // 004014c4: mov ss:[esp+0x4], 0x1
         // 004014cc: mov ss:[esp+0x8], 0x2
         // 004014d4: xor eax, eax
         // 004014d6: jmp 0x4014e0
      [-]0fb788a8a3400066898c049c01000083c0026685c975e9
         // 004014e0: movzx ecx, b2 ds:[eax+0x40a3a8]
         // 004014e7: mov b2 ss:[esp+eax+0x19c], b2 cx
         // 004014ef: add eax, 0x2
         // 004014f2: test b2 cx, b2 cx
         // 004014f5: jnz 0x4014e0
      [-]b8????????8bd08bff
         // 004014f7: mov eax, 0x431d90
         // 004014fc: mov edx, eax
         // 004014fe: mov edi, edi
      [-]668b0883c0026685c975f5
         // 00401500: mov b2 cx, b2 ds:[eax]
         // 00401503: add eax, 0x2
         // 00401506: test b2 cx, b2 cx
         // 00401509: jnz 0x401500
      [-]5356578dbc24????????2bc283c7fe8d9b????????
         // 0040150b: push ebx
         // 0040150c: push esi
         // 0040150d: push edi
         // 0040150e: lea edi, ss:[esp+0x1a8]
         // 00401515: sub eax, edx
         // 00401517: add edi, 0xfffffffffffffffe
         // 0040151a: lea ebx, ds:[ebx+0x0]
      [-]668b4f0283c7026685c975f4
         // 00401520: mov b2 cx, b2 ds:[edi+0x2]
         // 00401524: add edi, 0x2
         // 00401527: test b2 cx, b2 cx
         // 0040152a: jnz 0x401520
      [-]8bc8c1e9028bf2f3a58bc883e10333c068????????f3a4508d4c2422516689442424e88d43000083c40c33c0eb06
         // 0040152c: mov ecx, eax
         // 0040152e: shr ecx, b1 0x2
         // 00401531: mov esi, edx
         // 00401533: rep movsdd 
         // 00401535: mov ecx, eax
         // 00401537: and ecx, 0x3
         // 0040153a: xor eax, eax
         // 0040153c: push 0x18e
         // 00401541: rep movsbb 
         // 00401543: push eax
         // 00401544: lea ecx, ss:[esp+0x22]
         // 00401548: push ecx
         // 00401549: mov b2 ss:[esp+0x24], b2 ax
         // 0040154e: call _memset
         // 00401553: add esp, 0xc
         // 00401556: xor eax, eax
         // 00401558: jmp 0x401560
      [-]0fb788b8a3400066894c041883c0026685c975ec
         // 00401560: movzx ecx, b2 ds:[eax+0x40a3b8]
         // 00401567: mov b2 ss:[esp+eax+0x18], b2 cx
         // 0040156c: add eax, 0x2
         // 0040156f: test b2 cx, b2 cx
         // 00401572: jnz 0x401560
      [-]8d44241883c0feeb03
         // 00401574: lea eax, ss:[esp+0x18]
         // 00401578: add eax, 0xfffffffffffffffe
         // 0040157b: jmp 0x401580
      [-]668b480283c0026685c975f4
         // 00401580: mov b2 cx, b2 ds:[eax+0x2]
         // 00401584: add eax, 0x2
         // 00401587: test b2 cx, b2 cx
         // 0040158a: jnz 0x401580
      [-]8b15????????8b0d????????89108b15????????894804668b0de0a640008950086689480c8d8424????????8d5002eb03
         // 0040158c: mov edx, ds:[0x40a6d4]
         // 00401592: mov ecx, ds:[0x40a6d8]
         // 00401598: mov ds:[eax], edx
         // 0040159a: mov edx, ds:[0x40a6dc]
         // 004015a0: mov ds:[eax+0x4], ecx
         // 004015a3: mov b2 cx, b2 ds:[0x40a6e0]
         // 004015aa: mov ds:[eax+0x8], edx
         // 004015ad: mov b2 ds:[eax+0xc], b2 cx
         // 004015b1: lea eax, ss:[esp+0x1a8]
         // 004015b8: lea edx, ds:[eax+0x2]
         // 004015bb: jmp 0x4015c0
      [-]668b0883c0026685c975f5
         // 004015c0: mov b2 cx, b2 ds:[eax]
         // 004015c3: add eax, 0x2
         // 004015c6: test b2 cx, b2 cx
         // 004015c9: jnz 0x4015c0
      [-]8b35089040006a002bc28d542410526a0068????????6a00d1f86a008bf86a008d4424345068????????ffd68b44240c8d4c3f028b3d04904000518d9424????????526a026a0068????????50ffd7b8????????8d4802
         // 004015cb: mov esi, ds:[RegCreateKeyExW]
         // 004015d1: push 0x0
         // 004015d3: sub eax, edx
         // 004015d5: lea edx, ss:[esp+0x10]
         // 004015d9: push edx
         // 004015da: push 0x0
         // 004015dc: push 0x20006
         // 004015e1: push 0x0
         // 004015e3: sar eax, b1 0x1
         // 004015e5: push 0x0
         // 004015e7: mov edi, eax
         // 004015e9: push 0x0
         // 004015eb: lea eax, ss:[esp+0x34]
         // 004015ef: push eax
         // 004015f0: push 0xffffffff80000002
         // 004015f5: call esi
         // 004015f7: mov eax, ss:[esp+0xc]
         // 004015fb: lea ecx, ds:[edi+edi+0x2]
         // 004015ff: mov edi, ds:[RegSetValueExW]
         // 00401605: push ecx
         // 00401606: lea edx, ss:[esp+0x1ac]
         // 0040160d: push edx
         // 0040160e: push 0x2
         // 00401610: push 0x0
         // 00401612: push 0x40a400
         // 00401617: push eax
         // 00401618: call edi
         // 0040161a: mov eax, 0x40a6d4
         // 0040161f: lea ecx, ds:[eax+0x2]
      [-]668b1083c0026685d275f5
         // 00401622: mov b2 dx, b2 ds:[eax]
         // 00401625: add eax, 0x2
         // 00401628: test b2 dx, b2 dx
         // 0040162b: jnz 0x401622
      [-]6a002bc18d4c2410516a0068????????6a006a006a008d54243452d1f868????????8bd8ffd68b4c240c8d441b025068????????6a016a0068????????51ffd76a008d542410526a0068????????6a006a006a008d4424345068????????ffd68b54240c6a048d4c2414516a046a0068????????52ffd76a008d442410506a0068????????6a006a006a008d4c24345168????????ffd68b44240c6a048d542414526a046a0068????????50ffd76a008d4c2410516a0068????????6a006a006a008d5424345268????????ffd66a0a68????????6a018b4424186a0068????????50ffd76a008d4c2410516a0068????????6a006a006a008d5424345268????????ffd68b4c240c6a048d442418506a046a0068????????51ffd76a008d542410526a0068????????6a006a006a008d4424345068????????ffd68b54240c6a048d4c2418516a046a0068????????52ffd78b8c24????????5f85c05e0f94c05b33cce8e40c000081c4????????c3
         // 0040162d: push 0x0
         // 0040162f: sub eax, ecx
         // 00401631: lea ecx, ss:[esp+0x10]
         // 00401635: push ecx
         // 00401636: push 0x0
         // 00401638: push 0x20006
         // 0040163d: push 0x0
         // 0040163f: push 0x0
         // 00401641: push 0x0
         // 00401643: lea edx, ss:[esp+0x34]
         // 00401647: push edx
         // 00401648: sar eax, b1 0x1
         // 0040164a: push 0xffffffff80000002
         // 0040164f: mov ebx, eax
         // 00401651: call esi
         // 00401653: mov ecx, ss:[esp+0xc]
         // 00401657: lea eax, ds:[ebx+ebx+0x2]
         // 0040165b: push eax
         // 0040165c: push 0x40a6d4
         // 00401661: push 0x1
         // 00401663: push 0x0
         // 00401665: push 0x40a414
         // 0040166a: push ecx
         // 0040166b: call edi
         // 0040166d: push 0x0
         // 0040166f: lea edx, ss:[esp+0x10]
         // 00401673: push edx
         // 00401674: push 0x0
         // 00401676: push 0x20006
         // 0040167b: push 0x0
         // 0040167d: push 0x0
         // 0040167f: push 0x0
         // 00401681: lea eax, ss:[esp+0x34]
         // 00401685: push eax
         // 00401686: push 0xffffffff80000002
         // 0040168b: call esi
         // 0040168d: mov edx, ss:[esp+0xc]
         // 00401691: push 0x4
         // 00401693: lea ecx, ss:[esp+0x14]
         // 00401697: push ecx
         // 00401698: push 0x4
         // 0040169a: push 0x0
         // 0040169c: push 0x40a42c
         // 004016a1: push edx
         // 004016a2: call edi
         // 004016a4: push 0x0
         // 004016a6: lea eax, ss:[esp+0x10]
         // 004016aa: push eax
         // 004016ab: push 0x0
         // 004016ad: push 0x20006
         // 004016b2: push 0x0
         // 004016b4: push 0x0
         // 004016b6: push 0x0
         // 004016b8: lea ecx, ss:[esp+0x34]
         // 004016bc: push ecx
         // 004016bd: push 0xffffffff80000002
         // 004016c2: call esi
         // 004016c4: mov eax, ss:[esp+0xc]
         // 004016c8: push 0x4
         // 004016ca: lea edx, ss:[esp+0x14]
         // 004016ce: push edx
         // 004016cf: push 0x4
         // 004016d1: push 0x0
         // 004016d3: push 0x40a448
         // 004016d8: push eax
         // 004016d9: call edi
         // 004016db: push 0x0
         // 004016dd: lea ecx, ss:[esp+0x10]
         // 004016e1: push ecx
         // 004016e2: push 0x0
         // 004016e4: push 0x20006
         // 004016e9: push 0x0
         // 004016eb: push 0x0
         // 004016ed: push 0x0
         // 004016ef: lea edx, ss:[esp+0x34]
         // 004016f3: push edx
         // 004016f4: push 0xffffffff80000002
         // 004016f9: call esi
         // 004016fb: push 0xa
         // 004016fd: push 0x40a454
         // 00401702: push 0x1
         // 00401704: mov eax, ss:[esp+0x18]
         // 00401708: push 0x0
         // 0040170a: push 0x40a460
         // 0040170f: push eax
         // 00401710: call edi
         // 00401712: push 0x0
         // 00401714: lea ecx, ss:[esp+0x10]
         // 00401718: push ecx
         // 00401719: push 0x0
         // 0040171b: push 0x20006
         // 00401720: push 0x0
         // 00401722: push 0x0
         // 00401724: push 0x0
         // 00401726: lea edx, ss:[esp+0x34]
         // 0040172a: push edx
         // 0040172b: push 0xffffffff80000002
         // 00401730: call esi
         // 00401732: mov ecx, ss:[esp+0xc]
         // 00401736: push 0x4
         // 00401738: lea eax, ss:[esp+0x18]
         // 0040173c: push eax
         // 0040173d: push 0x4
         // 0040173f: push 0x0
         // 00401741: push 0x40a46c
         // 00401746: push ecx
         // 00401747: call edi
         // 00401749: push 0x0
         // 0040174b: lea edx, ss:[esp+0x10]
         // 0040174f: push edx
         // 00401750: push 0x0
         // 00401752: push 0x20006
         // 00401757: push 0x0
         // 00401759: push 0x0
         // 0040175b: push 0x0
         // 0040175d: lea eax, ss:[esp+0x34]
         // 00401761: push eax
         // 00401762: push 0xffffffff80000002
         // 00401767: call esi
         // 00401769: mov edx, ss:[esp+0xc]
         // 0040176d: push 0x4
         // 0040176f: lea ecx, ss:[esp+0x18]
         // 00401773: push ecx
         // 00401774: push 0x4
         // 00401776: push 0x0
         // 00401778: push 0x40a474
         // 0040177d: push edx
         // 0040177e: call edi
         // 00401780: mov ecx, ss:[esp+0x5a8]
         // 00401787: pop edi
         // 00401788: test eax, eax
         // 0040178a: pop esi
         // 0040178b: setz b1 al
         // 0040178e: pop ebx
         // 0040178f: xor ecx, esp
         // 00401791: call @__security_check_cookie@4
         // 00401796: add esp, 0x5a0
         // 0040179c: retn 
      [-]83ec34a104c0400033c48944243033c0538b1d3490400056578b3d30904000c644241800894424198944241d8944242189442425894424298944242d894424318944243533f6
         // 004017a0: sub esp, 0x34
         // 004017a3: mov eax, ds:[___security_cookie]
         // 004017a8: xor eax, esp
         // 004017aa: mov ss:[esp+0x30], eax
         // 004017ae: xor eax, eax
         // 004017b0: push ebx
         // 004017b1: mov ebx, ds:[Sleep]
         // 004017b7: push esi
         // 004017b8: push edi
         // 004017b9: mov edi, ds:[GetTickCount]
         // 004017bf: mov b1 ss:[esp+0x18], b1 0x0
         // 004017c4: mov ss:[esp+0x19], eax
         // 004017c8: mov ss:[esp+0x1d], eax
         // 004017cc: mov ss:[esp+0x21], eax
         // 004017d0: mov ss:[esp+0x25], eax
         // 004017d4: mov ss:[esp+0x29], eax
         // 004017d8: mov ss:[esp+0x2d], eax
         // 004017dc: mov ss:[esp+0x31], eax
         // 004017e0: mov ss:[esp+0x35], eax
         // 004017e4: xor esi, esi
      [-]ffd750e8420d000083c404e84c0d000099b9????????f7f96a3280c2618854341cffd34683fe207cd7
         // 004017e6: call edi
         // 004017e8: push eax
         // 004017e9: call _srand
         // 004017ee: add esp, 0x4
         // 004017f1: call _rand
         // 004017f6: cdq 
         // 004017f7: mov ecx, 0x1a
         // 004017fc: idiv ecx
         // 004017fe: push 0x32
         // 00401800: add b1 dl, b1 0x61
         // 00401803: mov b1 ss:[esp+esi+0x1c], b1 dl
         // 00401807: call ebx
         // 00401809: inc esi
         // 0040180a: cmp esi, 0x20
         // 0040180d: jl 0x4017e6
      [-]6a0068????????6a026a006a0168????????68????????ff15709040008bd883fbff7433
         // 0040180f: push 0x0
         // 00401811: push 0x80
         // 00401816: push 0x2
         // 00401818: push 0x0
         // 0040181a: push 0x1
         // 0040181c: push 0xffffffffe0000000
         // 00401821: push 0x431d90
         // 00401826: call ds:[CreateFileW]
         // 0040182c: mov ebx, eax
         // 0040182e: cmp ebx, 0xffffffffffffffff
         // 00401831: jz 0x401866
      [-]6a008d5424145268????????68????????b9????????8d742428bf????????53f3a5ff156c90400085c0751b
         // 00401833: push 0x0
         // 00401835: lea edx, ss:[esp+0x14]
         // 00401839: push edx
         // 0040183a: push 0x23400
         // 0040183f: push 0x40cc40
         // 00401844: mov ecx, 0x8
         // 00401849: lea esi, ss:[esp+0x28]
         // 0040184d: mov edi, 0x430016
         // 00401852: push ebx
         // 00401853: rep movsdd 
         // 00401855: call ds:[WriteFile]
         // 0040185b: test eax, eax
         // 0040185d: jnz 0x40187a
      [-]53ff1574904000
         // 0040185f: push ebx
         // 00401860: call ds:[CloseHandle]
      [-]5f5e33c05b8b4c243033cce8040c000083c434c3
         // 00401866: pop edi
         // 00401867: pop esi
         // 00401868: xor eax, eax
         // 0040186a: pop ebx
         // 0040186b: mov ecx, ss:[esp+0x30]
         // 0040186f: xor ecx, esp
         // 00401871: call @__security_check_cookie@4
         // 00401876: add esp, 0x34
         // 00401879: retn 
      [-]556a0068????????6a006a406a0053ff15689040008b2d749040008bf083feff7446
         // 0040187a: push ebp
         // 0040187b: push 0x0
         // 0040187d: push 0x23400
         // 00401882: push 0x0
         // 00401884: push 0x40
         // 00401886: push 0x0
         // 00401888: push ebx
         // 00401889: call ds:[CreateFileMappingW]
         // 0040188f: mov ebp, ds:[CloseHandle]
         // 00401895: mov esi, eax
         // 00401897: cmp esi, 0xffffffffffffffff
         // 0040189a: jz 0x4018e2
      [-]68????????6a006a0068????????56ff15649040008bf885ff7428
         // 0040189c: push 0x23400
         // 004018a1: push 0x0
         // 004018a3: push 0x0
         // 004018a5: push 0xf001f
         // 004018aa: push esi
         // 004018ab: call ds:[MapViewOfFile]
         // 004018b1: mov edi, eax
         // 004018b3: test edi, edi
         // 004018b5: jz 0x4018df
      [-]8d442410508d4c241c5168????????57ff156891400085c07407
         // 004018b7: lea eax, ss:[esp+0x10]
         // 004018bb: push eax
         // 004018bc: lea ecx, ss:[esp+0x1c]
         // 004018c0: push ecx
         // 004018c1: push 0x23400
         // 004018c6: push edi
         // 004018c7: call ds:[CheckSumMappedFile]
         // 004018cd: test eax, eax
         // 004018cf: jz 0x4018d8
      [-]8b542410895058
         // 004018d1: mov edx, ss:[esp+0x10]
         // 004018d5: mov ds:[eax+0x58], edx
      [-]57ff1548904000
         // 004018d8: push edi
         // 004018d9: call ds:[UnmapViewOfFile]
      [-]53ffd58b4c24405d5f5e5b33ccb8????????e8810b000083c434c3
         // 004018e2: push ebx
         // 004018e3: call ebp
         // 004018e5: mov ecx, ss:[esp+0x40]
         // 004018e9: pop ebp
         // 004018ea: pop edi
         // 004018eb: pop esi
         // 004018ec: pop ebx
         // 004018ed: xor ecx, esp
         // 004018ef: mov eax, 0x1
         // 004018f4: call @__security_check_cookie@4
         // 004018f9: add esp, 0x34
         // 004018fc: retn 
      [-]558bec83e4f881ec????????a104c0400033c4898424????????53568b751057b9????????8bc6
         // 00401910: push ebp
         // 00401911: mov ebp, esp
         // 00401913: and esp, 0xfffffffffffffff8
         // 00401916: sub esp, 0x91c
         // 0040191c: mov eax, ds:[___security_cookie]
         // 00401921: xor eax, esp
         // 00401923: mov ss:[esp+0x918], eax
         // 0040192a: push ebx
         // 0040192b: push esi
         // 0040192c: mov esi, ss:[ebp+0x10]
         // 0040192f: push edi
         // 00401930: mov ecx, 0x40a480
         // 00401935: mov eax, esi
      [-]668b10663b11751e
         // 00401937: mov b2 dx, b2 ds:[eax]
         // 0040193a: cmp b2 dx, b2 ds:[ecx]
         // 0040193d: jnz 0x40195d
      [-]6685d27415
         // 0040193f: test b2 dx, b2 dx
         // 00401942: jz 0x401959
      [-]668b5002663b5102750f
         // 00401944: mov b2 dx, b2 ds:[eax+0x2]
         // 00401948: cmp b2 dx, b2 ds:[ecx+0x2]
         // 0040194c: jnz 0x40195d
      [-]83c00483c1046685d275de
         // 0040194e: add eax, 0x4
         // 00401951: add ecx, 0x4
         // 00401954: test b2 dx, b2 dx
         // 00401957: jnz 0x401937
      [-]33c0eb05
         // 00401959: xor eax, eax
         // 0040195b: jmp 0x401962
      [-]1bc083d8ff
         // 0040195d: sbb eax, eax
         // 0040195f: sbb eax, 0xffffffffffffffff
      [-]33db3bc30f85b5050000
         // 00401962: xor ebx, ebx
         // 00401964: cmp eax, ebx
         // 00401966: jnz 0x401f21
      [-]68????????53381d94214300744d
         // 0040196c: push 0x1ff
         // 00401971: push ebx
         // 00401972: cmp b1 ds:[0x432194], b1 bl
         // 00401978: jz 0x4019c7
      [-]8d8424????????50e8593f0000b9????????be????????8dbc24????????f3a5a48dbc24????????83c40c4f
         // 0040197a: lea eax, ss:[esp+0x109]
         // 00401981: push eax
         // 00401982: call _memset
         // 00401987: mov ecx, 0xc
         // 0040198c: mov esi, 0x40a484
         // 00401991: lea edi, ss:[esp+0x10c]
         // 00401998: rep movsdd 
         // 0040199a: movsbb 
         // 0040199b: lea edi, ss:[esp+0x10c]
         // 004019a2: add esp, 0xc
         // 004019a5: dec edi
      [-]8a47014784c075f8
         // 004019a6: mov b1 al, b1 ds:[edi+0x1]
         // 004019a9: inc edi
         // 004019aa: test b1 al, b1 al
         // 004019ac: jnz 0x4019a6
      [-]b9????????be????????f3a5538d8c24????????66a551eb49
         // 004019ae: mov ecx, 0x9
         // 004019b3: mov esi, 0x40a4b8
         // 004019b8: rep movsdd 
         // 004019ba: push ebx
         // 004019bb: lea ecx, ss:[esp+0x104]
         // 004019c2: movsww 
         // 004019c4: push ecx
         // 004019c5: jmp 0x401a10
      [-]8d9424????????52e80c3f0000b9????????be????????8dbc24????????f3a5a48dbc24????????83c40c4f
         // 004019c7: lea edx, ss:[esp+0x109]
         // 004019ce: push edx
         // 004019cf: call _memset
         // 004019d4: mov ecx, 0xc
         // 004019d9: mov esi, 0x40a484
         // 004019de: lea edi, ss:[esp+0x10c]
         // 004019e5: rep movsdd 
         // 004019e7: movsbb 
         // 004019e8: lea edi, ss:[esp+0x10c]
         // 004019ef: add esp, 0xc
         // 004019f2: dec edi
      [-]8a47014784c075f8
         // 004019f3: mov b1 al, b1 ds:[edi+0x1]
         // 004019f6: inc edi
         // 004019f7: test b1 al, b1 al
         // 004019f9: jnz 0x4019f3
      [-]b9????????be????????538d8424????????f3a550
         // 004019fb: mov ecx, 0x9
         // 00401a00: mov esi, 0x40a4e0
         // 00401a05: push ebx
         // 00401a06: lea eax, ss:[esp+0x104]
         // 00401a0d: rep movsdd 
         // 00401a0f: push eax
      [-]a4ff154490400068????????e8336c000083c404e8d7f7ffff
         // 00401a10: movsbb 
         // 00401a11: call ds:[WinExec]
         // 00401a17: push 0x40a508
         // 00401a1c: call __mkdir
         // 00401a21: add esp, 0x4
         // 00401a24: call 0x401200
      [-]8b1d349040008b3d309040006a006a006a036a006a0368????????68????????ff158490400083f8ff7408
         // 00401a29: mov ebx, ds:[Sleep]
         // 00401a2f: mov edi, ds:[GetTickCount]
         // 00401a35: push 0x0
         // 00401a37: push 0x0
         // 00401a39: push 0x3
         // 00401a3b: push 0x0
         // 00401a3d: push 0x3
         // 00401a3f: push 0xffffffff80000000
         // 00401a44: push 0x40a510
         // 00401a49: call ds:[CreateFileA]
         // 00401a4f: cmp eax, 0xffffffffffffffff
         // 00401a52: jz 0x401a5c
      [-]85c00f859f040000
         // 00401a54: test eax, eax
         // 00401a56: jnz 0x401efb
      [-]e89ff6ffff33c0c68424b800000000898424????????898424????????66898424c100000033f6
         // 00401a5c: call 0x401100
         // 00401a61: xor eax, eax
         // 00401a63: mov b1 ss:[esp+0xb8], b1 0x0
         // 00401a6b: mov ss:[esp+0xb9], eax
         // 00401a72: mov ss:[esp+0xbd], eax
         // 00401a79: mov b2 ss:[esp+0xc1], b2 ax
         // 00401a81: xor esi, esi
      [-]ffd750e8a50a000083c404e8af0a000099b9????????f7f96a3280c261889434bc000000ffd34683fe0a7cd4
         // 00401a83: call edi
         // 00401a85: push eax
         // 00401a86: call _srand
         // 00401a8b: add esp, 0x4
         // 00401a8e: call _rand
         // 00401a93: cdq 
         // 00401a94: mov ecx, 0x1a
         // 00401a99: idiv ecx
         // 00401a9b: push 0x32
         // 00401a9d: add b1 dl, b1 0x61
         // 00401aa0: mov b1 ss:[esp+esi+0xbc], b1 dl
         // 00401aa7: call ebx
         // 00401aa9: inc esi
         // 00401aaa: cmp esi, 0xa
         // 00401aad: jl 0x401a83
      [-]33d26a2a528d8424????????5066899424e0000000e8173e00008d8424????????83c40c8d5001
         // 00401aaf: xor edx, edx
         // 00401ab1: push 0x2a
         // 00401ab3: push edx
         // 00401ab4: lea eax, ss:[esp+0xde]
         // 00401abb: push eax
         // 00401abc: mov b2 ss:[esp+0xe0], b2 dx
         // 00401ac4: call _memset
         // 00401ac9: lea eax, ss:[esp+0xc4]
         // 00401ad0: add esp, 0xc
         // 00401ad3: lea edx, ds:[eax+0x1]
      [-]8a084084c975f9
         // 00401ad6: mov b1 cl, b1 ds:[eax]
         // 00401ad8: inc eax
         // 00401ad9: test b1 cl, b1 cl
         // 00401adb: jnz 0x401ad6
      [-]2bc28d1c008d8424????????8d50018d642400
         // 00401add: sub eax, edx
         // 00401adf: lea ebx, ds:[eax+eax]
         // 00401ae2: lea eax, ss:[esp+0xb8]
         // 00401ae9: lea edx, ds:[eax+0x1]
         // 00401aec: lea esp, ss:[esp+0x0]
      [-]8a084084c975f9
         // 00401af0: mov b1 cl, b1 ds:[eax]
         // 00401af2: inc eax
         // 00401af3: test b1 cl, b1 cl
         // 00401af5: jnz 0x401af0
      [-]6a006a002bc28bf8578d8c24????????516a006a00ff157c9040008bf03bf37203
         // 00401af7: push 0x0
         // 00401af9: push 0x0
         // 00401afb: sub eax, edx
         // 00401afd: mov edi, eax
         // 00401aff: push edi
         // 00401b00: lea ecx, ss:[esp+0xc4]
         // 00401b07: push ecx
         // 00401b08: push 0x0
         // 00401b0a: push 0x0
         // 00401b0c: call ds:[MultiByteToWideChar]
         // 00401b12: mov esi, eax
         // 00401b14: cmp esi, ebx
         // 00401b16: jb 0x401b1b
      [-]568d9424????????52578d8424????????5033db5353ff157c90400033c966898c74d400000033c0eb0b
         // 00401b1b: push esi
         // 00401b1c: lea edx, ss:[esp+0xd8]
         // 00401b23: push edx
         // 00401b24: push edi
         // 00401b25: lea eax, ss:[esp+0xc4]
         // 00401b2c: push eax
         // 00401b2d: xor ebx, ebx
         // 00401b2f: push ebx
         // 00401b30: push ebx
         // 00401b31: call ds:[MultiByteToWideChar]
         // 00401b37: xor ecx, ecx
         // 00401b39: mov b2 ss:[esp+esi*0x2], b2 cx
         // 00401b41: xor eax, eax
         // 00401b43: jmp 0x401b50
      [-]0fb7883ca5400066898c040001000083c002663bcb75e9
         // 00401b50: movzx ecx, b2 ds:[eax+0x40a53c]
         // 00401b57: mov b2 ss:[esp+eax+0x100], b2 cx
         // 00401b5f: add eax, 0x2
         // 00401b62: cmp b2 cx, b2 bx
         // 00401b65: jnz 0x401b50
      [-]8d8424????????8bd0
         // 00401b67: lea eax, ss:[esp+0xd4]
         // 00401b6e: mov edx, eax
      [-]668b0883c002663bcb75f5
         // 00401b70: mov b2 cx, b2 ds:[eax]
         // 00401b73: add eax, 0x2
         // 00401b76: cmp b2 cx, b2 bx
         // 00401b79: jnz 0x401b70
      [-]8dbc24????????2bc283c7feeb07
         // 00401b7b: lea edi, ss:[esp+0x100]
         // 00401b82: sub eax, edx
         // 00401b84: add edi, 0xfffffffffffffffe
         // 00401b87: jmp 0x401b90
      [-]668b4f0283c702663bcb75f4
         // 00401b90: mov b2 cx, b2 ds:[edi+0x2]
         // 00401b94: add edi, 0x2
         // 00401b97: cmp b2 cx, b2 bx
         // 00401b9a: jnz 0x401b90
      [-]8bc8c1e9028bf2f3a58bc883e1038d8424????????f3a483c0fe
         // 00401b9c: mov ecx, eax
         // 00401b9e: shr ecx, b1 0x2
         // 00401ba1: mov esi, edx
         // 00401ba3: rep movsdd 
         // 00401ba5: mov ecx, eax
         // 00401ba7: and ecx, 0x3
         // 00401baa: lea eax, ss:[esp+0x100]
         // 00401bb1: rep movsbb 
         // 00401bb3: add eax, 0xfffffffffffffffe
      [-]668b480283c002663bcb75f4
         // 00401bb6: mov b2 cx, b2 ds:[eax+0x2]
         // 00401bba: add eax, 0x2
         // 00401bbd: cmp b2 cx, b2 bx
         // 00401bc0: jnz 0x401bb6
      [-]8b15????????8b0d????????8910668b1558a54000894804668950088d8424????????50e8e5f6ffff83c40433c0
         // 00401bc2: mov edx, ds:[0x40a550]
         // 00401bc8: mov ecx, ds:[0x40a554]
         // 00401bce: mov ds:[eax], edx
         // 00401bd0: mov b2 dx, b2 ds:[0x40a558]
         // 00401bd7: mov ds:[eax+0x4], ecx
         // 00401bda: mov b2 ds:[eax+0x8], b2 dx
         // 00401bde: lea eax, ss:[esp+0x100]
         // 00401be5: push eax
         // 00401be6: call 0x4012d0
         // 00401beb: add esp, 0x4
         // 00401bee: xor eax, eax
      [-]0fb7885ca5400066898c041807000083c002663bcb75e9
         // 00401bf0: movzx ecx, b2 ds:[eax+0x40a55c]
         // 00401bf7: mov b2 ss:[esp+eax+0x718], b2 cx
         // 00401bff: add eax, 0x2
         // 00401c02: cmp b2 cx, b2 bx
         // 00401c05: jnz 0x401bf0
      [-]8d8424????????8bd0
         // 00401c07: lea eax, ss:[esp+0x100]
         // 00401c0e: mov edx, eax
      [-]668b0883c002663bcb75f5
         // 00401c10: mov b2 cx, b2 ds:[eax]
         // 00401c13: add eax, 0x2
         // 00401c16: cmp b2 cx, b2 bx
         // 00401c19: jnz 0x401c10
      [-]8dbc24????????2bc283c7feeb07
         // 00401c1b: lea edi, ss:[esp+0x718]
         // 00401c22: sub eax, edx
         // 00401c24: add edi, 0xfffffffffffffffe
         // 00401c27: jmp 0x401c30
      [-]668b4f0283c702663bcb75f4
         // 00401c30: mov b2 cx, b2 ds:[edi+0x2]
         // 00401c34: add edi, 0x2
         // 00401c37: cmp b2 cx, b2 bx
         // 00401c3a: jnz 0x401c30
      [-]8bc8c1e9028bf2f3a58bc883e1038d8424????????f3a483c0fe
         // 00401c3c: mov ecx, eax
         // 00401c3e: shr ecx, b1 0x2
         // 00401c41: mov esi, edx
         // 00401c43: rep movsdd 
         // 00401c45: mov ecx, eax
         // 00401c47: and ecx, 0x3
         // 00401c4a: lea eax, ss:[esp+0x718]
         // 00401c51: rep movsbb 
         // 00401c53: add eax, 0xfffffffffffffffe
      [-]668b480283c002663bcb75f4
         // 00401c56: mov b2 cx, b2 ds:[eax+0x2]
         // 00401c5a: add eax, 0x2
         // 00401c5d: cmp b2 cx, b2 bx
         // 00401c60: jnz 0x401c56
      [-]8b0d????????8b15????????89088b0d????????8950048b15????????894808668b0d8ca5400089500c6a408d542478535266894810895c247ce83f3c000083c40c33c0898424????????898424????????898424????????8d8424????????508d4c24745153536a105353538d9424????????5253899c24????????ff15549040008bf08b8424????????6aff50ff15589040003bf3741a
         // 00401c62: mov ecx, ds:[0x40a57c]
         // 00401c68: mov edx, ds:[0x40a580]
         // 00401c6e: mov ds:[eax], ecx
         // 00401c70: mov ecx, ds:[0x40a584]
         // 00401c76: mov ds:[eax+0x4], edx
         // 00401c79: mov edx, ds:[0x40a588]
         // 00401c7f: mov ds:[eax+0x8], ecx
         // 00401c82: mov b2 cx, b2 ds:[0x40a58c]
         // 00401c89: mov ds:[eax+0xc], edx
         // 00401c8c: push 0x40
         // 00401c8e: lea edx, ss:[esp+0x78]
         // 00401c92: push ebx
         // 00401c93: push edx
         // 00401c94: mov b2 ds:[eax+0x10], b2 cx
         // 00401c98: mov ss:[esp+0x7c], ebx
         // 00401c9c: call _memset
         // 00401ca1: add esp, 0xc
         // 00401ca4: xor eax, eax
         // 00401ca6: mov ss:[esp+0xc8], eax
         // 00401cad: mov ss:[esp+0xcc], eax
         // 00401cb4: mov ss:[esp+0xd0], eax
         // 00401cbb: lea eax, ss:[esp+0xc4]
         // 00401cc2: push eax
         // 00401cc3: lea ecx, ss:[esp+0x74]
         // 00401cc7: push ecx
         // 00401cc8: push ebx
         // 00401cc9: push ebx
         // 00401cca: push 0x10
         // 00401ccc: push ebx
         // 00401ccd: push ebx
         // 00401cce: push ebx
         // 00401ccf: lea edx, ss:[esp+0x738]
         // 00401cd6: push edx
         // 00401cd7: push ebx
         // 00401cd8: mov ss:[esp+0xec], ebx
         // 00401cdf: call ds:[CreateProcessW]
         // 00401ce5: mov esi, eax
         // 00401ce7: mov eax, ss:[esp+0xc4]
         // 00401cee: push 0xffffffffffffffff
         // 00401cf0: push eax
         // 00401cf1: call ds:[WaitForSingleObject]
         // 00401cf7: cmp esi, ebx
         // 00401cf9: jz 0x401d15
      [-]8b8c24????????8b357490400051ffd68b9424????????52ffd6
         // 00401cfb: mov ecx, ss:[esp+0xc8]
         // 00401d02: mov esi, ds:[CloseHandle]
         // 00401d08: push ecx
         // 00401d09: call esi
         // 00401d0b: mov edx, ss:[esp+0xc4]
         // 00401d12: push edx
         // 00401d13: call esi
      [-]8d8424????????50ff154c90400033c0eb09
         // 00401d15: lea eax, ss:[esp+0x100]
         // 00401d1c: push eax
         // 00401d1d: call ds:[DeleteFileW]
         // 00401d23: xor eax, eax
         // 00401d25: jmp 0x401d30
      [-]0fb78890a5400066898c041005000083c002663bcb75e9
         // 00401d30: movzx ecx, b2 ds:[eax+0x40a590]
         // 00401d37: mov b2 ss:[esp+eax+0x510], b2 cx
         // 00401d3f: add eax, 0x2
         // 00401d42: cmp b2 cx, b2 bx
         // 00401d45: jnz 0x401d30
      [-]8d8424????????8bd0
         // 00401d47: lea eax, ss:[esp+0xd4]
         // 00401d4e: mov edx, eax
      [-]668b0883c002663bcb75f5
         // 00401d50: mov b2 cx, b2 ds:[eax]
         // 00401d53: add eax, 0x2
         // 00401d56: cmp b2 cx, b2 bx
         // 00401d59: jnz 0x401d50
      [-]8dbc24????????2bc283c7feeb07
         // 00401d5b: lea edi, ss:[esp+0x510]
         // 00401d62: sub eax, edx
         // 00401d64: add edi, 0xfffffffffffffffe
         // 00401d67: jmp 0x401d70
      [-]668b4f0283c702663bcb75f4
         // 00401d70: mov b2 cx, b2 ds:[edi+0x2]
         // 00401d74: add edi, 0x2
         // 00401d77: cmp b2 cx, b2 bx
         // 00401d7a: jnz 0x401d70
      [-]8bc8c1e9028bf2f3a58bc883e1038d8424????????f3a483c0fe
         // 00401d7c: mov ecx, eax
         // 00401d7e: shr ecx, b1 0x2
         // 00401d81: mov esi, edx
         // 00401d83: rep movsdd 
         // 00401d85: mov ecx, eax
         // 00401d87: and ecx, 0x3
         // 00401d8a: lea eax, ss:[esp+0x510]
         // 00401d91: rep movsbb 
         // 00401d93: add eax, 0xfffffffffffffffe
      [-]668b480283c002663bcb75f4
         // 00401d96: mov b2 cx, b2 ds:[eax+0x2]
         // 00401d9a: add eax, 0x2
         // 00401d9d: cmp b2 cx, b2 bx
         // 00401da0: jnz 0x401d96
      [-]8b0d????????8b15????????8908668b0d58a540008950048d9424????????5266894808e805f5ffff83c40433c0
         // 00401da2: mov ecx, ds:[0x40a550]
         // 00401da8: mov edx, ds:[0x40a554]
         // 00401dae: mov ds:[eax], ecx
         // 00401db0: mov b2 cx, b2 ds:[0x40a558]
         // 00401db7: mov ds:[eax+0x4], edx
         // 00401dba: lea edx, ss:[esp+0x510]
         // 00401dc1: push edx
         // 00401dc2: mov b2 ds:[eax+0x8], b2 cx
         // 00401dc6: call 0x4012d0
         // 00401dcb: add esp, 0x4
         // 00401dce: xor eax, eax
      [-]0fb7885ca5400066898c040803000083c002663bcb75e9
         // 00401dd0: movzx ecx, b2 ds:[eax+0x40a55c]
         // 00401dd7: mov b2 ss:[esp+eax+0x308], b2 cx
         // 00401ddf: add eax, 0x2
         // 00401de2: cmp b2 cx, b2 bx
         // 00401de5: jnz 0x401dd0
      [-]8d8424????????8bd0
         // 00401de7: lea eax, ss:[esp+0x510]
         // 00401dee: mov edx, eax
      [-]668b0883c002663bcb75f5
         // 00401df0: mov b2 cx, b2 ds:[eax]
         // 00401df3: add eax, 0x2
         // 00401df6: cmp b2 cx, b2 bx
         // 00401df9: jnz 0x401df0
      [-]8dbc24????????2bc283c7feeb07
         // 00401dfb: lea edi, ss:[esp+0x308]
         // 00401e02: sub eax, edx
         // 00401e04: add edi, 0xfffffffffffffffe
         // 00401e07: jmp 0x401e10
      [-]668b4f0283c702663bcb75f4
         // 00401e10: mov b2 cx, b2 ds:[edi+0x2]
         // 00401e14: add edi, 0x2
         // 00401e17: cmp b2 cx, b2 bx
         // 00401e1a: jnz 0x401e10
      [-]8bc8c1e9028bf2f3a58bc883e1038d8424????????f3a483c0fe
         // 00401e1c: mov ecx, eax
         // 00401e1e: shr ecx, b1 0x2
         // 00401e21: mov esi, edx
         // 00401e23: rep movsdd 
         // 00401e25: mov ecx, eax
         // 00401e27: and ecx, 0x3
         // 00401e2a: lea eax, ss:[esp+0x308]
         // 00401e31: rep movsbb 
         // 00401e33: add eax, 0xfffffffffffffffe
      [-]668b480283c002663bcb75f4
         // 00401e36: mov b2 cx, b2 ds:[eax+0x2]
         // 00401e3a: add eax, 0x2
         // 00401e3d: cmp b2 cx, b2 bx
         // 00401e40: jnz 0x401e36
      [-]8b0d????????8b15????????89088b0d????????8950048b15????????894808668b0db8a5400089500c6a408d542430535266894810895c2434e85f3a000083c40c33c0894424188944241c894424208d442414508d4c242c5153536a105353538d9424????????5253895c243cff15549040008bf08b4424146aff50ff15589040003bf37414
         // 00401e42: mov ecx, ds:[0x40a5a8]
         // 00401e48: mov edx, ds:[0x40a5ac]
         // 00401e4e: mov ds:[eax], ecx
         // 00401e50: mov ecx, ds:[0x40a5b0]
         // 00401e56: mov ds:[eax+0x4], edx
         // 00401e59: mov edx, ds:[0x40a5b4]
         // 00401e5f: mov ds:[eax+0x8], ecx
         // 00401e62: mov b2 cx, b2 ds:[0x40a5b8]
         // 00401e69: mov ds:[eax+0xc], edx
         // 00401e6c: push 0x40
         // 00401e6e: lea edx, ss:[esp+0x30]
         // 00401e72: push ebx
         // 00401e73: push edx
         // 00401e74: mov b2 ds:[eax+0x10], b2 cx
         // 00401e78: mov ss:[esp+0x34], ebx
         // 00401e7c: call _memset
         // 00401e81: add esp, 0xc
         // 00401e84: xor eax, eax
         // 00401e86: mov ss:[esp+0x18], eax
         // 00401e8a: mov ss:[esp+0x1c], eax
         // 00401e8e: mov ss:[esp+0x20], eax
         // 00401e92: lea eax, ss:[esp+0x14]
         // 00401e96: push eax
         // 00401e97: lea ecx, ss:[esp+0x2c]
         // 00401e9b: push ecx
         // 00401e9c: push ebx
         // 00401e9d: push ebx
         // 00401e9e: push 0x10
         // 00401ea0: push ebx
         // 00401ea1: push ebx
         // 00401ea2: push ebx
         // 00401ea3: lea edx, ss:[esp+0x328]
         // 00401eaa: push edx
         // 00401eab: push ebx
         // 00401eac: mov ss:[esp+0x3c], ebx
         // 00401eb0: call ds:[CreateProcessW]
         // 00401eb6: mov esi, eax
         // 00401eb8: mov eax, ss:[esp+0x14]
         // 00401ebc: push 0xffffffffffffffff
         // 00401ebe: push eax
         // 00401ebf: call ds:[WaitForSingleObject]
         // 00401ec5: cmp esi, ebx
         // 00401ec7: jz 0x401edd
      [-]8b4c24188b357490400051ffd68b54241452ffd6
         // 00401ec9: mov ecx, ss:[esp+0x18]
         // 00401ecd: mov esi, ds:[CloseHandle]
         // 00401ed3: push ecx
         // 00401ed4: call esi
         // 00401ed6: mov edx, ss:[esp+0x14]
         // 00401eda: push edx
         // 00401edb: call esi
      [-]8d8424????????50ff154c90400068????????53e87e050000e92efbffff
         // 00401edd: lea eax, ss:[esp+0x510]
         // 00401ee4: push eax
         // 00401ee5: call ds:[DeleteFileW]
         // 00401eeb: push 0x40a530
         // 00401ef0: push ebx
         // 00401ef1: call NetUserDel
         // 00401ef6: jmp 0x401a29
      [-]6a0068????????e88d08000083c40885c0750b
         // 00401efb: push 0x0
         // 00401efd: push 0x40a51c
         // 00401f02: call __access
         // 00401f07: add esp, 0x8
         // 00401f0a: test eax, eax
         // 00401f0c: jnz 0x401f19
      [-]68????????ff154c904000
         // 00401f0e: push 0x40a388
         // 00401f13: call ds:[DeleteFileW]
      [-]6a00ff1550904000
         // 00401f19: push 0x0
         // 00401f1b: call ds:[ExitProcess]
      [-]b9????????8bc6
         // 00401f21: mov ecx, 0x40a5bc
         // 00401f26: mov eax, esi
      [-]668b10663b11751e
         // 00401f28: mov b2 dx, b2 ds:[eax]
         // 00401f2b: cmp b2 dx, b2 ds:[ecx]
         // 00401f2e: jnz 0x401f4e
      [-]663bd37415
         // 00401f30: cmp b2 dx, b2 bx
         // 00401f33: jz 0x401f4a
      [-]668b5002663b5102750f
         // 00401f35: mov b2 dx, b2 ds:[eax+0x2]
         // 00401f39: cmp b2 dx, b2 ds:[ecx+0x2]
         // 00401f3d: jnz 0x401f4e
      [-]83c00483c104663bd375de
         // 00401f3f: add eax, 0x4
         // 00401f42: add ecx, 0x4
         // 00401f45: cmp b2 dx, b2 bx
         // 00401f48: jnz 0x401f28
      [-]33c0eb05
         // 00401f4a: xor eax, eax
         // 00401f4c: jmp 0x401f53
      [-]1bc083d8ff
         // 00401f4e: sbb eax, eax
         // 00401f50: sbb eax, 0xffffffffffffffff
      [-]3bc30f85b2000000
         // 00401f53: cmp eax, ebx
         // 00401f55: jnz 0x40200d
      [-]33c08d4900
         // 00401f5b: xor eax, eax
         // 00401f5d: lea ecx, ds:[ecx+0x0]
      [-]0fb7885ca5400066898c040803000083c002663bcb75e9
         // 00401f60: movzx ecx, b2 ds:[eax+0x40a55c]
         // 00401f67: mov b2 ss:[esp+eax+0x308], b2 cx
         // 00401f6f: add eax, 0x2
         // 00401f72: cmp b2 cx, b2 bx
         // 00401f75: jnz 0x401f60
      [-]8dbc24????????83c7fe
         // 00401f77: lea edi, ss:[esp+0x308]
         // 00401f7e: add edi, 0xfffffffffffffffe
      [-]668b470283c702663bc375f4
         // 00401f81: mov b2 ax, b2 ds:[edi+0x2]
         // 00401f85: add edi, 0x2
         // 00401f88: cmp b2 ax, b2 bx
         // 00401f8b: jnz 0x401f81
      [-]b9????????be????????6a40f3a58d4c24305351895c2434e83639000083c40c33c08d542414528944241c89442420894424248d44242c5053536a105353538d8c24????????5153895c243cff15549040008b5424146aff528bf0ff15589040003bf37414
         // 00401f8d: mov ecx, 0x15
         // 00401f92: mov esi, 0x40a5d0
         // 00401f97: push 0x40
         // 00401f99: rep movsdd 
         // 00401f9b: lea ecx, ss:[esp+0x30]
         // 00401f9f: push ebx
         // 00401fa0: push ecx
         // 00401fa1: mov ss:[esp+0x34], ebx
         // 00401fa5: call _memset
         // 00401faa: add esp, 0xc
         // 00401fad: xor eax, eax
         // 00401faf: lea edx, ss:[esp+0x14]
         // 00401fb3: push edx
         // 00401fb4: mov ss:[esp+0x1c], eax
         // 00401fb8: mov ss:[esp+0x20], eax
         // 00401fbc: mov ss:[esp+0x24], eax
         // 00401fc0: lea eax, ss:[esp+0x2c]
         // 00401fc4: push eax
         // 00401fc5: push ebx
         // 00401fc6: push ebx
         // 00401fc7: push 0x10
         // 00401fc9: push ebx
         // 00401fca: push ebx
         // 00401fcb: push ebx
         // 00401fcc: lea ecx, ss:[esp+0x328]
         // 00401fd3: push ecx
         // 00401fd4: push ebx
         // 00401fd5: mov ss:[esp+0x3c], ebx
         // 00401fd9: call ds:[CreateProcessW]
         // 00401fdf: mov edx, ss:[esp+0x14]
         // 00401fe3: push 0xffffffffffffffff
         // 00401fe5: push edx
         // 00401fe6: mov esi, eax
         // 00401fe8: call ds:[WaitForSingleObject]
         // 00401fee: cmp esi, ebx
         // 00401ff0: jz 0x402006
      [-]8b4424188b357490400050ffd68b4c241451ffd6
         // 00401ff2: mov eax, ss:[esp+0x18]
         // 00401ff6: mov esi, ds:[CloseHandle]
         // 00401ffc: push eax
         // 00401ffd: call esi
         // 00401fff: mov ecx, ss:[esp+0x14]
         // 00402003: push ecx
         // 00402004: call esi
      [-]53ff1550904000
         // 00402006: push ebx
         // 00402007: call ds:[ExitProcess]
      [-]b9????????8bc6
         // 0040200d: mov ecx, 0x40a624
         // 00402012: mov eax, esi
      [-]668b10663b11751e
         // 00402014: mov b2 dx, b2 ds:[eax]
         // 00402017: cmp b2 dx, b2 ds:[ecx]
         // 0040201a: jnz 0x40203a
      [-]663bd37415
         // 0040201c: cmp b2 dx, b2 bx
         // 0040201f: jz 0x402036
      [-]668b5002663b5102750f
         // 00402021: mov b2 dx, b2 ds:[eax+0x2]
         // 00402025: cmp b2 dx, b2 ds:[ecx+0x2]
         // 00402029: jnz 0x40203a
      [-]83c00483c104663bd375de
         // 0040202b: add eax, 0x4
         // 0040202e: add ecx, 0x4
         // 00402031: cmp b2 dx, b2 bx
         // 00402034: jnz 0x402014
      [-]33c0eb05
         // 00402036: xor eax, eax
         // 00402038: jmp 0x40203f
      [-]1bc083d8ff
         // 0040203a: sbb eax, eax
         // 0040203c: sbb eax, 0xffffffffffffffff
      [-]3bc30f8507040000
         // 0040203f: cmp eax, ebx
         // 00402041: jnz 0x40244e
      [-]8d542424526a20ff155c90400050ff15009040008b44242450b9????????e846f0ffff83c40468????????8d8c24????????5351e86038000083c40c8d9424????????52c78424????????????????ff156090400083bc24????????068b3d309040000f9244241333c0889c24c40000008b1d34904000898424????????898424????????66898424cd00000033f6
         // 00402047: lea edx, ss:[esp+0x24]
         // 0040204b: push edx
         // 0040204c: push 0x20
         // 0040204e: call ds:[GetCurrentProcess]
         // 00402054: push eax
         // 00402055: call ds:[OpenProcessToken]
         // 0040205b: mov eax, ss:[esp+0x24]
         // 0040205f: push eax
         // 00402060: mov ecx, 0x40a634
         // 00402065: call 0x4010b0
         // 0040206a: add esp, 0x4
         // 0040206d: push 0x114
         // 00402072: lea ecx, ss:[esp+0x514]
         // 00402079: push ebx
         // 0040207a: push ecx
         // 0040207b: call _memset
         // 00402080: add esp, 0xc
         // 00402083: lea edx, ss:[esp+0x510]
         // 0040208a: push edx
         // 0040208b: mov ss:[esp+0x514], 0x114
         // 00402096: call ds:[GetVersionExW]
         // 0040209c: cmp ss:[esp+0x514], 0x6
         // 004020a4: mov edi, ds:[GetTickCount]
         // 004020aa: setb b1 ss:[esp+0x13]
         // 004020af: xor eax, eax
         // 004020b1: mov b1 ss:[esp+0xc4], b1 bl
         // 004020b8: mov ebx, ds:[Sleep]
         // 004020be: mov ss:[esp+0xc5], eax
         // 004020c5: mov ss:[esp+0xc9], eax
         // 004020cc: mov b2 ss:[esp+0xcd], b2 ax
         // 004020d4: xor esi, esi
      [-]ffd750e85204000083c404e85c04000099b9????????f7f96a3280c261889434c8000000ffd34683fe0a7cd4
         // 004020d6: call edi
         // 004020d8: push eax
         // 004020d9: call _srand
         // 004020de: add esp, 0x4
         // 004020e1: call _rand
         // 004020e6: cdq 
         // 004020e7: mov ecx, 0x1a
         // 004020ec: idiv ecx
         // 004020ee: push 0x32
         // 004020f0: add b1 dl, b1 0x61
         // 004020f3: mov b1 ss:[esp+esi+0xc8], b1 dl
         // 004020fa: call ebx
         // 004020fc: inc esi
         // 004020fd: cmp esi, 0xa
         // 00402100: jl 0x4020d6
      [-]33d26a2a528d8424????????5066899424e0000000e8c43700008d8424????????83c40c8d50018da424????????
         // 00402102: xor edx, edx
         // 00402104: push 0x2a
         // 00402106: push edx
         // 00402107: lea eax, ss:[esp+0xde]
         // 0040210e: push eax
         // 0040210f: mov b2 ss:[esp+0xe0], b2 dx
         // 00402117: call _memset
         // 0040211c: lea eax, ss:[esp+0xd0]
         // 00402123: add esp, 0xc
         // 00402126: lea edx, ds:[eax+0x1]
         // 00402129: lea esp, ss:[esp+0x0]
      [-]8a084084c975f9
         // 00402130: mov b1 cl, b1 ds:[eax]
         // 00402132: inc eax
         // 00402133: test b1 cl, b1 cl
         // 00402135: jnz 0x402130
      [-]2bc28d1c008d8424????????8d5001
         // 00402137: sub eax, edx
         // 00402139: lea ebx, ds:[eax+eax]
         // 0040213c: lea eax, ss:[esp+0xc4]
         // 00402143: lea edx, ds:[eax+0x1]
      [-]8a084084c975f9
         // 00402146: mov b1 cl, b1 ds:[eax]
         // 00402148: inc eax
         // 00402149: test b1 cl, b1 cl
         // 0040214b: jnz 0x402146
      [-]6a006a002bc28bf8578d8c24????????516a006a00ff157c9040008bf03bf37203
         // 0040214d: push 0x0
         // 0040214f: push 0x0
         // 00402151: sub eax, edx
         // 00402153: mov edi, eax
         // 00402155: push edi
         // 00402156: lea ecx, ss:[esp+0xd0]
         // 0040215d: push ecx
         // 0040215e: push 0x0
         // 00402160: push 0x0
         // 00402162: call ds:[MultiByteToWideChar]
         // 00402168: mov esi, eax
         // 0040216a: cmp esi, ebx
         // 0040216c: jb 0x402171
      [-]568d9424????????52578d8424????????5033db5353ff157c90400033c966898c74d400000033c08da424????????
         // 00402171: push esi
         // 00402172: lea edx, ss:[esp+0xd8]
         // 00402179: push edx
         // 0040217a: push edi
         // 0040217b: lea eax, ss:[esp+0xd0]
         // 00402182: push eax
         // 00402183: xor ebx, ebx
         // 00402185: push ebx
         // 00402186: push ebx
         // 00402187: call ds:[MultiByteToWideChar]
         // 0040218d: xor ecx, ecx
         // 0040218f: mov b2 ss:[esp+esi*0x2], b2 cx
         // 00402197: xor eax, eax
         // 00402199: lea esp, ss:[esp+0x0]
      [-]0fb7883ca54000668988901d430083c002663bcb75ea
         // 004021a0: movzx ecx, b2 ds:[eax+0x40a53c]
         // 004021a7: mov b2 ds:[eax+0x431d90], b2 cx
         // 004021ae: add eax, 0x2
         // 004021b1: cmp b2 cx, b2 bx
         // 004021b4: jnz 0x4021a0
      [-]8d8424????????8bd090
         // 004021b6: lea eax, ss:[esp+0xd4]
         // 004021bd: mov edx, eax
         // 004021bf: nop 
      [-]668b0883c002663bcb75f5
         // 004021c0: mov b2 cx, b2 ds:[eax]
         // 004021c3: add eax, 0x2
         // 004021c6: cmp b2 cx, b2 bx
         // 004021c9: jnz 0x4021c0
      [-]bf????????2bc283c7fe
         // 004021cb: mov edi, 0x431d90
         // 004021d0: sub eax, edx
         // 004021d2: add edi, 0xfffffffffffffffe
      [-]668b4f0283c702663bcb75f4
         // 004021d5: mov b2 cx, b2 ds:[edi+0x2]
         // 004021d9: add edi, 0x2
         // 004021dc: cmp b2 cx, b2 bx
         // 004021df: jnz 0x4021d5
      [-]8bc8c1e9028bf2f3a58bc883e103b8????????f3a483c0fe8da424????????
         // 004021e1: mov ecx, eax
         // 004021e3: shr ecx, b1 0x2
         // 004021e6: mov esi, edx
         // 004021e8: rep movsdd 
         // 004021ea: mov ecx, eax
         // 004021ec: and ecx, 0x3
         // 004021ef: mov eax, 0x431d90
         // 004021f4: rep movsbb 
         // 004021f6: add eax, 0xfffffffffffffffe
         // 004021f9: lea esp, ss:[esp+0x0]
      [-]668b480283c002663bcb75f4
         // 00402200: mov b2 cx, b2 ds:[eax+0x2]
         // 00402204: add eax, 0x2
         // 00402207: cmp b2 cx, b2 bx
         // 0040220a: jnz 0x402200
      [-]8b15????????8b0d????????8910668b1560a6400089480466895008e873f5ffff807c2413000f84d6000000
         // 0040220c: mov edx, ds:[0x40a658]
         // 00402212: mov ecx, ds:[0x40a65c]
         // 00402218: mov ds:[eax], edx
         // 0040221a: mov b2 dx, b2 ds:[0x40a660]
         // 00402221: mov ds:[eax+0x4], ecx
         // 00402224: mov b2 ds:[eax+0x8], b2 dx
         // 00402228: call 0x4017a0
         // 0040222d: cmp b1 ss:[esp+0x13], b1 0x0
         // 00402232: jz 0x40230e
      [-]33c08d9b????????
         // 00402238: xor eax, eax
         // 0040223a: lea ebx, ds:[ebx+0x0]
      [-]0fb78868a6400066898c040001000083c002663bcb75e9
         // 00402240: movzx ecx, b2 ds:[eax+0x40a668]
         // 00402247: mov b2 ss:[esp+eax+0x100], b2 cx
         // 0040224f: add eax, 0x2
         // 00402252: cmp b2 cx, b2 bx
         // 00402255: jnz 0x402240
      [-]8d8424????????83c0fe
         // 00402257: lea eax, ss:[esp+0x100]
         // 0040225e: add eax, 0xfffffffffffffffe
      [-]668b480283c002663bcb75f4
         // 00402261: mov b2 cx, b2 ds:[eax+0x2]
         // 00402265: add eax, 0x2
         // 00402268: cmp b2 cx, b2 bx
         // 0040226b: jnz 0x402261
      [-]8b0d????????8b15????????89088b0d????????895004668b15e0a640008948086689500c8d8424????????508d8c24????????51ff15????????8b7424248d5424185268????????53c7442420????????ff151090400053536a108d442420505356c7442438????????ff150c904000ff1578904000e8c7f1ffff8d8c24????????51ff15????????83c4048d9424????????528bf0ff15????????3bf3740c
         // 0040226d: mov ecx, ds:[0x40a6d4]
         // 00402273: mov edx, ds:[0x40a6d8]
         // 00402279: mov ds:[eax], ecx
         // 0040227b: mov ecx, ds:[0x40a6dc]
         // 00402281: mov ds:[eax+0x4], edx
         // 00402284: mov b2 dx, b2 ds:[0x40a6e0]
         // 0040228b: mov ds:[eax+0x8], ecx
         // 0040228e: mov b2 ds:[eax+0xc], b2 dx
         // 00402292: lea eax, ss:[esp+0x100]
         // 00402299: push eax
         // 0040229a: lea ecx, ss:[esp+0xbc]
         // 004022a1: push ecx
         // 004022a2: call ds:[0x432198]
         // 004022a8: mov esi, ss:[esp+0x24]
         // 004022ac: lea edx, ss:[esp+0x18]
         // 004022b0: push edx
         // 004022b1: push 0x40a6e4
         // 004022b6: push ebx
         // 004022b7: mov ss:[esp+0x20], 0x1
         // 004022bf: call ds:[LookupPrivilegeValueW]
         // 004022c5: push ebx
         // 004022c6: push ebx
         // 004022c7: push 0x10
         // 004022c9: lea eax, ss:[esp+0x20]
         // 004022cd: push eax
         // 004022ce: push ebx
         // 004022cf: push esi
         // 004022d0: mov ss:[esp+0x38], 0x2
         // 004022d8: call ds:[AdjustTokenPrivileges]
         // 004022de: call ds:[GetLastError]
         // 004022e4: call 0x4014b0
         // 004022e9: lea ecx, ss:[esp+0xb8]
         // 004022f0: push ecx
         // 004022f1: call ds:[0x43219c]
         // 004022f7: add esp, 0x4
         // 004022fa: lea edx, ss:[esp+0xb8]
         // 00402301: push edx
         // 00402302: mov esi, eax
         // 00402304: call ds:[0x4321a0]
         // 0040230a: cmp esi, ebx
         // 0040230c: jz 0x40231a
      [-]8d8424????????e8e6ecffff
         // 0040230e: lea eax, ss:[esp+0xd4]
         // 00402315: call 0x401000
      [-]53536a03536a0368????????68????????ff158490400083f8ff0f84ca000000
         // 0040231a: push ebx
         // 0040231b: push ebx
         // 0040231c: push 0x3
         // 0040231e: push ebx
         // 0040231f: push 0x3
         // 00402321: push 0xffffffff80000000
         // 00402326: push 0x40a510
         // 0040232b: call ds:[CreateFileA]
         // 00402331: cmp eax, 0xffffffffffffffff
         // 00402334: jz 0x402404
      [-]3bc30f84c2000000
         // 0040233a: cmp eax, ebx
         // 0040233c: jz 0x402404
      [-]68????????ff154c90400033c090
         // 00402342: push 0x431d90
         // 00402347: call ds:[DeleteFileW]
         // 0040234d: xor eax, eax
         // 0040234f: nop 
      [-]0fb7885ca5400066898c040803000083c002663bcb75e9
         // 00402350: movzx ecx, b2 ds:[eax+0x40a55c]
         // 00402357: mov b2 ss:[esp+eax+0x308], b2 cx
         // 0040235f: add eax, 0x2
         // 00402362: cmp b2 cx, b2 bx
         // 00402365: jnz 0x402350
      [-]8dbc24????
         // 00402367: lea edi, ss:[esp+0x308]
         // 0040236e: add edi, 0xfffffffffffffffe

  }
  condition:
    all of them
}
