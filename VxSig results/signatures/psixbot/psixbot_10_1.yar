rule psixbot_10_1 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         6a04b8????????e84a0d01008bf96a0ce8a50600008bf0598975f08365fc0085f67429
         // 00401000: push 0x4
         // 00401002: mov eax, 0x412918
         // 00401007: call __EH_prolog3
         // 0040100c: mov edi, ecx
         // 0040100e: push 0xc
         // 00401010: call ??2@YAPAXI@Z
         // 00401015: mov esi, eax
         // 00401017: pop ecx
         // 00401018: mov ss:[ebp+0xfffffffffffffff0], esi
         // 0040101b: and ss:[ebp+0xfffffffffffffffc], 0x0
         // 0040101f: test esi, esi
         // 00401021: jz 0x40104c
      [-]ff750883660400c74608????????ff1524314100890685c07511
         // 00401023: push ss:[ebp+0x8]
         // 00401026: and ds:[esi+0x4], 0x0
         // 0040102a: mov ds:[esi+0x8], 0x1
         // 00401031: call ds:[SysAllocString]
         // 00401037: mov ds:[esi], eax
         // 00401039: test eax, eax
         // 0040103b: jnz 0x40104e
      [-]394508740c
         // 0040103d: cmp ss:[ebp+0x8], eax
         // 00401040: jz 0x40104e
      [-]68????????e834130000
         // 00401042: push 0xffffffff8007000e
         // 00401047: call 0x402380
      [-]834dfcff893785f674ea
         // 0040104e: or ss:[ebp+0xfffffffffffffffc], 0xffffffffffffffff
         // 00401052: mov ds:[edi], esi
         // 00401054: test esi, esi
         // 00401056: jz 0x401042
      [-]8bc7e8e20c0100c20400
         // 00401058: mov eax, edi
         // 0040105a: call __EH_epilog3
         // 0040105f: retn b2 0x4
      [-]568bf18b0e85c97408
         // 00401062: push esi
         // 00401063: mov esi, ecx
         // 00401065: mov ecx, ds:[esi]
         // 00401067: test ecx, ecx
         // 00401069: jz 0x401073
      [-]e805000000832600
         // 0040106b: call 0x401075
         // 00401070: and ds:[esi], 0x0
      [-]56578bf183cffff00fc17e084f7531
         // 00401075: push esi
         // 00401076: push edi
         // 00401077: mov esi, ecx
         // 00401079: or edi, 0xffffffffffffffff
         // 0040107c: lock xadd ds:[esi+0x8], edi
         // 00401081: dec edi
         // 00401082: jnz 0x4010b5
      [-]85f6742d
         // 00401084: test esi, esi
         // 00401086: jz 0x4010b5
      [-]833e00740b
         // 00401088: cmp ds:[esi], 0x0
         // 0040108b: jz 0x401098
      [-]ff36ff1520314100832600
         // 0040108d: push ds:[esi]
         // 0040108f: call ds:[SysFreeString]
         // 00401095: and ds:[esi], 0x0
      [-]837e0400740d
         // 00401098: cmp ds:[esi+0x4], 0x0
         // 0040109c: jz 0x4010ab
      [-]ff7604e8670600008366040059
         // 0040109e: push ds:[esi+0x4]
         // 004010a1: call j_j__free
         // 004010a6: and ds:[esi+0x4], 0x0
         // 004010aa: pop ecx
      [-]6a0c56e8f90500005959
         // 004010ab: push 0xc
         // 004010ad: push esi
         // 004010ae: call 0x4016ac
         // 004010b3: pop ecx
         // 004010b4: pop ecx
      [-]8bc75f5ec3
         // 004010b5: mov eax, edi
         // 004010b7: pop edi
         // 004010b8: pop esi
         // 004010b9: retn 
      [-]51ff1528314100c3
         // 004010ba: push ecx
         // 004010bb: call ds:[VariantClear]
         // 004010c1: retn 
      [-]558bec83e4f868????????ff150030410083f8ff7409
         // 004010c2: push ebp
         // 004010c3: mov ebp, esp
         // 004010c5: and esp, 0xfffffffffffffff8
         // 004010c8: push 0x418728
         // 004010cd: call ds:[GetFileAttributesW]
         // 004010d3: cmp eax, 0xffffffffffffffff
         // 004010d6: jz 0x4010e1
      [-]e81100000085c07905
         // 004010d8: call 0x4010ee
         // 004010dd: test eax, eax
         // 004010df: jns 0x4010e6
      [-]e825030000
         // 004010e1: call 0x40140b
      [-]33c08be55dc21000
         // 004010e6: xor eax, eax
         // 004010e8: mov esp, ebp
         // 004010ea: pop ebp
         // 004010eb: retn b2 0x10
      [-]6a64b8????????e8900c010033db895dfc895dc4895dcc895dc8895ddc895de068????????8d4dd0c645fc02e8e1feffff895de468????????8d4dd4c645fc04e8cdfeffff895de88b351c3141008d459450ffd668????????8d4dd8c645fc07e8adfeffff8d45a450ffd68d45c4c645fc095068????????68????????ff15343141008b45c48d55cc5268????????be????????8b085650ff510c8b45cc8d55c052508b08ff51288bf8395dc00f8587000000
         // 004010ee: push 0x64
         // 004010f0: mov eax, 0x41297b
         // 004010f5: call __EH_prolog3_catch
         // 004010fa: xor ebx, ebx
         // 004010fc: mov ss:[ebp+0xfffffffffffffffc], ebx
         // 004010ff: mov ss:[ebp+0xffffffffffffffc4], ebx
         // 00401102: mov ss:[ebp+0xffffffffffffffcc], ebx
         // 00401105: mov ss:[ebp+0xffffffffffffffc8], ebx
         // 00401108: mov ss:[ebp+0xffffffffffffffdc], ebx
         // 0040110b: mov ss:[ebp+0xffffffffffffffe0], ebx
         // 0040110e: push 0x418784
         // 00401113: lea ecx, ss:[ebp+0xffffffffffffffd0]
         // 00401116: mov b1 ss:[ebp+0xfffffffffffffffc], b1 0x2
         // 0040111a: call 0x401000
         // 0040111f: mov ss:[ebp+0xffffffffffffffe4], ebx
         // 00401122: push 0x418788
         // 00401127: lea ecx, ss:[ebp+0xffffffffffffffd4]
         // 0040112a: mov b1 ss:[ebp+0xfffffffffffffffc], b1 0x4
         // 0040112e: call 0x401000
         // 00401133: mov ss:[ebp+0xffffffffffffffe8], ebx
         // 00401136: mov esi, ds:[VariantInit]
         // 0040113c: lea eax, ss:[ebp+0xffffffffffffff94]
         // 0040113f: push eax
         // 00401140: call esi
         // 00401142: push 0x4187b8
         // 00401147: lea ecx, ss:[ebp+0xffffffffffffffd8]
         // 0040114a: mov b1 ss:[ebp+0xfffffffffffffffc], b1 0x7
         // 0040114e: call 0x401000
         // 00401153: lea eax, ss:[ebp+0xffffffffffffffa4]
         // 00401156: push eax
         // 00401157: call esi
         // 00401159: lea eax, ss:[ebp+0xffffffffffffffc4]
         // 0040115c: mov b1 ss:[ebp+0xfffffffffffffffc], b1 0x9
         // 00401160: push eax
         // 00401161: push 0x41886c
         // 00401166: push 0x437c80
         // 0040116b: call ds:[CLRCreateInstance]
         // 00401171: mov eax, ss:[ebp+0xffffffffffffffc4]
         // 00401174: lea edx, ss:[ebp+0xffffffffffffffcc]
         // 00401177: push edx
         // 00401178: push 0x41885c
         // 0040117d: mov esi, 0x4187c4
         // 00401182: mov ecx, ds:[eax]
         // 00401184: push esi
         // 00401185: push eax
         // 00401186: call ds:[ecx+0xc]
         // 00401189: mov eax, ss:[ebp+0xffffffffffffffcc]
         // 0040118c: lea edx, ss:[ebp+0xffffffffffffffc0]
         // 0040118f: push edx
         // 00401190: push eax
         // 00401191: mov ecx, ds:[eax]
         // 00401193: call ds:[ecx+0x28]
         // 00401196: mov edi, eax
         // 00401198: cmp ss:[ebp+0xffffffffffffffc0], ebx
         // 0040119b: jnz 0x401228
      [-]5668????????e8bd0400008b35283141008d45a4595950ffd68b4dd885c97408
         // 004011a1: push esi
         // 004011a2: push 0x4187e0
         // 004011a7: call 0x401669
         // 004011ac: mov esi, ds:[VariantClear]
         // 004011b2: lea eax, ss:[ebp+0xffffffffffffffa4]
         // 004011b5: pop ecx
         // 004011b6: pop ecx
         // 004011b7: push eax
         // 004011b8: call esi
         // 004011ba: mov ecx, ss:[ebp+0xffffffffffffffd8]
         // 004011bd: test ecx, ecx
         // 004011bf: jz 0x4011c9
      [-]e8affeffff895dd8
         // 004011c1: call 0x401075
         // 004011c6: mov ss:[ebp+0xffffffffffffffd8], ebx
      [-]8d459450ffd6c645fc058b45e885c07406
         // 004011c9: lea eax, ss:[ebp+0xffffffffffffff94]
         // 004011cc: push eax
         // 004011cd: call esi
         // 004011cf: mov b1 ss:[ebp+0xfffffffffffffffc], b1 0x5
         // 004011d3: mov eax, ss:[ebp+0xffffffffffffffe8]
         // 004011d6: test eax, eax
         // 004011d8: jz 0x4011e0
      [-]8b0850ff5108
         // 004011da: mov ecx, ds:[eax]
         // 004011dc: push eax
         // 004011dd: call ds:[ecx+0x8]
      [-]8b4dd485c97408
         // 004011e0: mov ecx, ss:[ebp+0xffffffffffffffd4]
         // 004011e3: test ecx, ecx
         // 004011e5: jz 0x4011ef
      [-]e889feffff895dd4
         // 004011e7: call 0x401075
         // 004011ec: mov ss:[ebp+0xffffffffffffffd4], ebx
      [-]c645fc038b45e485c07406
         // 004011ef: mov b1 ss:[ebp+0xfffffffffffffffc], b1 0x3
         // 004011f3: mov eax, ss:[ebp+0xffffffffffffffe4]
         // 004011f6: test eax, eax
         // 004011f8: jz 0x401200
      [-]8b0850ff5108
         // 004011fa: mov ecx, ds:[eax]
         // 004011fc: push eax
         // 004011fd: call ds:[ecx+0x8]
      [-]8b4dd085c97408
         // 00401200: mov ecx, ss:[ebp+0xffffffffffffffd0]
         // 00401203: test ecx, ecx
         // 00401205: jz 0x40120f
      [-]e869feffff895dd0
         // 00401207: call 0x401075
         // 0040120c: mov ss:[ebp+0xffffffffffffffd0], ebx
      [-]c645fc018b45e085c07406
         // 0040120f: mov b1 ss:[ebp+0xfffffffffffffffc], b1 0x1
         // 00401213: mov eax, ss:[ebp+0xffffffffffffffe0]
         // 00401216: test eax, eax
         // 00401218: jz 0x401220
      [-]8b0850ff5108
         // 0040121a: mov ecx, ds:[eax]
         // 0040121c: push eax
         // 0040121d: call ds:[ecx+0x8]
      [-]885dfce9bc010000
         // 00401220: mov b1 ss:[ebp+0xfffffffffffffffc], b1 bl
         // 00401223: jmp 0x4013e4
      [-]8b45cc8d55c85268????????68????????8b0850ff51248b45c8508b08ff51288b45dc85c07406
         // 00401228: mov eax, ss:[ebp+0xffffffffffffffcc]
         // 0040122b: lea edx, ss:[ebp+0xffffffffffffffc8]
         // 0040122e: push edx
         // 0040122f: push 0x41884c
         // 00401234: push 0x437c90
         // 00401239: mov ecx, ds:[eax]
         // 0040123b: push eax
         // 0040123c: call ds:[ecx+0x24]
         // 0040123f: mov eax, ss:[ebp+0xffffffffffffffc8]
         // 00401242: push eax
         // 00401243: mov ecx, ds:[eax]
         // 00401245: call ds:[ecx+0x28]
         // 00401248: mov eax, ss:[ebp+0xffffffffffffffdc]
         // 0040124b: test eax, eax
         // 0040124d: jz 0x401255
      [-]8b0850ff5108
         // 0040124f: mov ecx, ds:[eax]
         // 00401251: push eax
         // 00401252: call ds:[ecx+0x8]
      [-]8b45c88d55dc895ddc52508b08ff51348b75dc85f6750a
         // 00401255: mov eax, ss:[ebp+0xffffffffffffffc8]
         // 00401258: lea edx, ss:[ebp+0xffffffffffffffdc]
         // 0040125b: mov ss:[ebp+0xffffffffffffffdc], ebx
         // 0040125e: push edx
         // 0040125f: push eax
         // 00401260: mov ecx, ds:[eax]
         // 00401262: call ds:[ecx+0x34]
         // 00401265: mov esi, ss:[ebp+0xffffffffffffffdc]
         // 00401268: test esi, esi
         // 0040126a: jnz 0x401276
      [-]68????????e80a110000
         // 0040126c: push 0xffffffff80004003
         // 00401271: call 0x402380
      [-]8b45e085c07406
         // 00401276: mov eax, ss:[ebp+0xffffffffffffffe0]
         // 00401279: test eax, eax
         // 0040127b: jz 0x401283
      [-]8b0850ff5108
         // 0040127d: mov ecx, ds:[eax]
         // 0040127f: push eax
         // 00401280: call ds:[ecx+0x8]
      [-]8d4de0895de08b065168????????56ff108d45b8895dbc506a01be????????6a118975b8ff15183141008bd853ff15143141005668????????ff730ce85c0e010083c40c53ff15103141008b75e085f67497
         // 00401283: lea ecx, ss:[ebp+0xffffffffffffffe0]
         // 00401286: mov ss:[ebp+0xffffffffffffffe0], ebx
         // 00401289: mov eax, ds:[esi]
         // 0040128b: push ecx
         // 0040128c: push 0x41883c
         // 00401291: push esi
         // 00401292: call ds:[eax]
         // 00401294: lea eax, ss:[ebp+0xffffffffffffffb8]
         // 00401297: mov ss:[ebp+0xffffffffffffffbc], ebx
         // 0040129a: push eax
         // 0040129b: push 0x1
         // 0040129d: mov esi, 0xfa00
         // 004012a2: push 0x11
         // 004012a4: mov ss:[ebp+0xffffffffffffffb8], esi
         // 004012a7: call ds:[SafeArrayCreate]
         // 004012ad: mov ebx, eax
         // 004012af: push ebx
         // 004012b0: call ds:[SafeArrayLock]
         // 004012b6: push esi
         // 004012b7: push 0x418880
         // 004012bc: push ds:[ebx+0xc]
         // 004012bf: call _memmove_0
         // 004012c4: add esp, 0xc
         // 004012c7: push ebx
         // 004012c8: call ds:[SafeArrayUnlock]
         // 004012ce: mov esi, ss:[ebp+0xffffffffffffffe0]
         // 004012d1: test esi, esi
         // 004012d3: jz 0x40126c
      [-]8b45e485c07406
         // 004012d5: mov eax, ss:[ebp+0xffffffffffffffe4]
         // 004012d8: test eax, eax
         // 004012da: jz 0x4012e2
      [-]8b0850ff5108
         // 004012dc: mov ecx, ds:[eax]
         // 004012de: push eax
         // 004012df: call ds:[ecx+0x8]
      [-]8d4de433ff51897de48b065356ff90????????8b75e485f60f846cffffff
         // 004012e2: lea ecx, ss:[ebp+0xffffffffffffffe4]
         // 004012e5: xor edi, edi
         // 004012e7: push ecx
         // 004012e8: mov ss:[ebp+0xffffffffffffffe4], edi
         // 004012eb: mov eax, ds:[esi]
         // 004012ed: push ebx
         // 004012ee: push esi
         // 004012ef: call ds:[eax+0xb4]
         // 004012f5: mov esi, ss:[ebp+0xffffffffffffffe4]
         // 004012f8: test esi, esi
         // 004012fa: jz 0x40126c
      [-]8b45e885c07406
         // 00401300: mov eax, ss:[ebp+0xffffffffffffffe8]
         // 00401303: test eax, eax
         // 00401305: jz 0x40130d
      [-]8b0850ff5108
         // 00401307: mov ecx, ds:[eax]
         // 00401309: push eax
         // 0040130a: call ds:[ecx+0x8]
      [-]8b45d4897de885c07404
         // 0040130d: mov eax, ss:[ebp+0xffffffffffffffd4]
         // 00401310: mov ss:[ebp+0xffffffffffffffe8], edi
         // 00401313: test eax, eax
         // 00401315: jz 0x40131b
      [-]8b08eb02
         // 00401317: mov ecx, ds:[eax]
         // 00401319: jmp 0x40131d
      [-]8b068d55e8525156ff50448b4de885c90f8439ffffff
         // 0040131d: mov eax, ds:[esi]
         // 0040131f: lea edx, ss:[ebp+0xffffffffffffffe8]
         // 00401322: push edx
         // 00401323: push ecx
         // 00401324: push esi
         // 00401325: call ds:[eax+0x44]
         // 00401328: mov ecx, ss:[ebp+0xffffffffffffffe8]
         // 0040132b: test ecx, ecx
         // 0040132d: jz 0x40126c
      [-]8b45d885c07404
         // 00401333: mov eax, ss:[ebp+0xffffffffffffffd8]
         // 00401336: test eax, eax
         // 00401338: jz 0x40133e
      [-]8b10eb02
         // 0040133a: mov edx, ds:[eax]
         // 0040133c: jmp 0x401340
      [-]8b018d75a4565783ec108d75948bfc6a00a568????????5251a5a5a5ff90????????538bf8ff150c3141008b35283141008d45a450ffd68b4dd885c97409
         // 00401340: mov eax, ds:[ecx]
         // 00401342: lea esi, ss:[ebp+0xffffffffffffffa4]
         // 00401345: push esi
         // 00401346: push edi
         // 00401347: sub esp, 0x10
         // 0040134a: lea esi, ss:[ebp+0xffffffffffffff94]
         // 0040134d: mov edi, esp
         // 0040134f: push 0x0
         // 00401351: movsdd 
         // 00401352: push 0x118
         // 00401357: push edx
         // 00401358: push ecx
         // 00401359: movsdd 
         // 0040135a: movsdd 
         // 0040135b: movsdd 
         // 0040135c: call ds:[eax+0xe4]
         // 00401362: push ebx
         // 00401363: mov edi, eax
         // 00401365: call ds:[SafeArrayDestroy]
         // 0040136b: mov esi, ds:[VariantClear]
         // 00401371: lea eax, ss:[ebp+0xffffffffffffffa4]
         // 00401374: push eax
         // 00401375: call esi
         // 00401377: mov ecx, ss:[ebp+0xffffffffffffffd8]
         // 0040137a: test ecx, ecx
         // 0040137c: jz 0x401387
      [-]e8f2fcffff8365d800
         // 0040137e: call 0x401075
         // 00401383: and ss:[ebp+0xffffffffffffffd8], 0x0
      [-]8d459450ffd6c645fc058b45e885c07406
         // 00401387: lea eax, ss:[ebp+0xffffffffffffff94]
         // 0040138a: push eax
         // 0040138b: call esi
         // 0040138d: mov b1 ss:[ebp+0xfffffffffffffffc], b1 0x5
         // 00401391: mov eax, ss:[ebp+0xffffffffffffffe8]
         // 00401394: test eax, eax
         // 00401396: jz 0x40139e
      [-]8b0850ff5108
         // 00401398: mov ecx, ds:[eax]
         // 0040139a: push eax
         // 0040139b: call ds:[ecx+0x8]
      [-]8b4dd485c97409
         // 0040139e: mov ecx, ss:[ebp+0xffffffffffffffd4]
         // 004013a1: test ecx, ecx
         // 004013a3: jz 0x4013ae
      [-]e8cbfcffff8365d400
         // 004013a5: call 0x401075
         // 004013aa: and ss:[ebp+0xffffffffffffffd4], 0x0
      [-]c645fc038b45e485c07406
         // 004013ae: mov b1 ss:[ebp+0xfffffffffffffffc], b1 0x3
         // 004013b2: mov eax, ss:[ebp+0xffffffffffffffe4]
         // 004013b5: test eax, eax
         // 004013b7: jz 0x4013bf
      [-]8b0850ff5108
         // 004013b9: mov ecx, ds:[eax]
         // 004013bb: push eax
         // 004013bc: call ds:[ecx+0x8]
      [-]8b4dd085c97409
         // 004013bf: mov ecx, ss:[ebp+0xffffffffffffffd0]
         // 004013c2: test ecx, ecx
         // 004013c4: jz 0x4013cf
      [-]e8aafcffff8365d000
         // 004013c6: call 0x401075
         // 004013cb: and ss:[ebp+0xffffffffffffffd0], 0x0
      [-]c645fc018b45e085c07406
         // 004013cf: mov b1 ss:[ebp+0xfffffffffffffffc], b1 0x1
         // 004013d3: mov eax, ss:[ebp+0xffffffffffffffe0]
         // 004013d6: test eax, eax
         // 004013d8: jz 0x4013e0
      [-]8b0850ff5108
         // 004013da: mov ecx, ds:[eax]
         // 004013dc: push eax
         // 004013dd: call ds:[ecx+0x8]
      [-]c645fc00
         // 004013e0: mov b1 ss:[ebp+0xfffffffffffffffc], b1 0x0
      [-]8b45dc85c07418
         // 004013e4: mov eax, ss:[ebp+0xffffffffffffffdc]
         // 004013e7: test eax, eax
         // 004013e9: jz 0x401403
      [-]8b0850ff5108eb10
         // 004013eb: mov ecx, ds:[eax]
         // 004013ed: push eax
         // 004013ee: call ds:[ecx+0x8]
         // 004013f1: jmp 0x401403
      [-]8bc7e837090100c3
         // 00401403: mov eax, edi
         // 00401405: call __EH_epilog3
         // 0040140a: retn 
      [-]6a54b8????????e87309010033db895dfc895dd8895ddc895de068????????8d4dccc645fc02e8cafbffff895de468????????8d4dd0c645fc04e8b6fbffff895de88b351c3141008d45a450ffd668????????8d4dd4c645fc07e896fbffff8d45b450ffd68d45d8c645fc095068????????68????????6a015368????????ff15303141008b45d8508b08ff51288b45dc85c07406
         // 0040140b: push 0x54
         // 0040140d: mov eax, 0x4129de
         // 00401412: call __EH_prolog3_catch
         // 00401417: xor ebx, ebx
         // 00401419: mov ss:[ebp+0xfffffffffffffffc], ebx
         // 0040141c: mov ss:[ebp+0xffffffffffffffd8], ebx
         // 0040141f: mov ss:[ebp+0xffffffffffffffdc], ebx
         // 00401422: mov ss:[ebp+0xffffffffffffffe0], ebx
         // 00401425: push 0x418784
         // 0040142a: lea ecx, ss:[ebp+0xffffffffffffffcc]
         // 0040142d: mov b1 ss:[ebp+0xfffffffffffffffc], b1 0x2
         // 00401431: call 0x401000
         // 00401436: mov ss:[ebp+0xffffffffffffffe4], ebx
         // 00401439: push 0x418788
         // 0040143e: lea ecx, ss:[ebp+0xffffffffffffffd0]
         // 00401441: mov b1 ss:[ebp+0xfffffffffffffffc], b1 0x4
         // 00401445: call 0x401000
         // 0040144a: mov ss:[ebp+0xffffffffffffffe8], ebx
         // 0040144d: mov esi, ds:[VariantInit]
         // 00401453: lea eax, ss:[ebp+0xffffffffffffffa4]
         // 00401456: push eax
         // 00401457: call esi
         // 00401459: push 0x4187b8
         // 0040145e: lea ecx, ss:[ebp+0xffffffffffffffd4]
         // 00401461: mov b1 ss:[ebp+0xfffffffffffffffc], b1 0x7
         // 00401465: call 0x401000
         // 0040146a: lea eax, ss:[ebp+0xffffffffffffffb4]
         // 0040146d: push eax
         // 0040146e: call esi
         // 00401470: lea eax, ss:[ebp+0xffffffffffffffd8]
         // 00401473: mov b1 ss:[ebp+0xfffffffffffffffc], b1 0x9
         // 00401477: push eax
         // 00401478: push 0x41884c
         // 0040147d: push 0x437c90
         // 00401482: push 0x1
         // 00401484: push ebx
         // 00401485: push 0x418824
         // 0040148a: call ds:[CorBindToRuntimeEx]
         // 00401490: mov eax, ss:[ebp+0xffffffffffffffd8]
         // 00401493: push eax
         // 00401494: mov ecx, ds:[eax]
         // 00401496: call ds:[ecx+0x28]
         // 00401499: mov eax, ss:[ebp+0xffffffffffffffdc]
         // 0040149c: test eax, eax
         // 0040149e: jz 0x4014a6
      [-]8b0850ff5108
         // 004014a0: mov ecx, ds:[eax]
         // 004014a2: push eax
         // 004014a3: call ds:[ecx+0x8]
      [-]8b45d88d55dc895ddc52508b08ff51348b75dc85f6750a
         // 004014a6: mov eax, ss:[ebp+0xffffffffffffffd8]
         // 004014a9: lea edx, ss:[ebp+0xffffffffffffffdc]
         // 004014ac: mov ss:[ebp+0xffffffffffffffdc], ebx
         // 004014af: push edx
         // 004014b0: push eax
         // 004014b1: mov ecx, ds:[eax]
         // 004014b3: call ds:[ecx+0x34]
         // 004014b6: mov esi, ss:[ebp+0xffffffffffffffdc]
         // 004014b9: test esi, esi
         // 004014bb: jnz 0x4014c7
      [-]68????????e8b90e0000
         // 004014bd: push 0xffffffff80004003
         // 004014c2: call 0x402380
      [-]8b45e085c07406
         // 004014c7: mov eax, ss:[ebp+0xffffffffffffffe0]
         // 004014ca: test eax, eax
         // 004014cc: jz 0x4014d4
      [-]8b0850ff5108
         // 004014ce: mov ecx, ds:[eax]
         // 004014d0: push eax
         // 004014d1: call ds:[ecx+0x8]
      [-]8d4de0895de08b065168????????56ff108d45c4895dc8506a01be????????6a118975c4ff15183141008bd853ff15143141005668????????ff730ce80b0c010083c40c53ff15103141008b75e085f67497
         // 004014d4: lea ecx, ss:[ebp+0xffffffffffffffe0]
         // 004014d7: mov ss:[ebp+0xffffffffffffffe0], ebx
         // 004014da: mov eax, ds:[esi]
         // 004014dc: push ecx
         // 004014dd: push 0x41883c
         // 004014e2: push esi
         // 004014e3: call ds:[eax]
         // 004014e5: lea eax, ss:[ebp+0xffffffffffffffc4]
         // 004014e8: mov ss:[ebp+0xffffffffffffffc8], ebx
         // 004014eb: push eax
         // 004014ec: push 0x1
         // 004014ee: mov esi, 0xfa00
         // 004014f3: push 0x11
         // 004014f5: mov ss:[ebp+0xffffffffffffffc4], esi
         // 004014f8: call ds:[SafeArrayCreate]
         // 004014fe: mov ebx, eax
         // 00401500: push ebx
         // 00401501: call ds:[SafeArrayLock]
         // 00401507: push esi
         // 00401508: push 0x428280
         // 0040150d: push ds:[ebx+0xc]
         // 00401510: call _memmove_0
         // 00401515: add esp, 0xc
         // 00401518: push ebx
         // 00401519: call ds:[SafeArrayUnlock]
         // 0040151f: mov esi, ss:[ebp+0xffffffffffffffe0]
         // 00401522: test esi, esi
         // 00401524: jz 0x4014bd
      [-]8b45e485c07406
         // 00401526: mov eax, ss:[ebp+0xffffffffffffffe4]
         // 00401529: test eax, eax
         // 0040152b: jz 0x401533
      [-]8b0850ff5108
         // 0040152d: mov ecx, ds:[eax]
         // 0040152f: push eax
         // 00401530: call ds:[ecx+0x8]
      [-]8d4de433ff51897de48b065356ff90????????8b75e485f60f846cffffff
         // 00401533: lea ecx, ss:[ebp+0xffffffffffffffe4]
         // 00401536: xor edi, edi
         // 00401538: push ecx
         // 00401539: mov ss:[ebp+0xffffffffffffffe4], edi
         // 0040153c: mov eax, ds:[esi]
         // 0040153e: push ebx
         // 0040153f: push esi
         // 00401540: call ds:[eax+0xb4]
         // 00401546: mov esi, ss:[ebp+0xffffffffffffffe4]
         // 00401549: test esi, esi
         // 0040154b: jz 0x4014bd
      [-]8b45e885c07406
         // 00401551: mov eax, ss:[ebp+0xffffffffffffffe8]
         // 00401554: test eax, eax
         // 00401556: jz 0x40155e
      [-]8b0850ff5108
         // 00401558: mov ecx, ds:[eax]
         // 0040155a: push eax
         // 0040155b: call ds:[ecx+0x8]
      [-]8b45d0897de885c07404
         // 0040155e: mov eax, ss:[ebp+0xffffffffffffffd0]
         // 00401561: mov ss:[ebp+0xffffffffffffffe8], edi
         // 00401564: test eax, eax
         // 00401566: jz 0x40156c
      [-]8b08eb02
         // 00401568: mov ecx, ds:[eax]
         // 0040156a: jmp 0x40156e
      [-]8b068d55e8525156ff50448b4de885c90f8439ffffff
         // 0040156e: mov eax, ds:[esi]
         // 00401570: lea edx, ss:[ebp+0xffffffffffffffe8]
         // 00401573: push edx
         // 00401574: push ecx
         // 00401575: push esi
         // 00401576: call ds:[eax+0x44]
         // 00401579: mov ecx, ss:[ebp+0xffffffffffffffe8]
         // 0040157c: test ecx, ecx
         // 0040157e: jz 0x4014bd
      [-]8b45d485c07404
         // 00401584: mov eax, ss:[ebp+0xffffffffffffffd4]
         // 00401587: test eax, eax
         // 00401589: jz 0x40158f
      [-]8b10eb02
         // 0040158b: mov edx, ds:[eax]
         // 0040158d: jmp 0x401591
      [-]8b018d75b4565783ec108d75a48bfc6a00a568????????5251a5a5a5ff90????????538bf8ff150c3141008b35283141008d45b450ffd68b4dd485c97409
         // 00401591: mov eax, ds:[ecx]
         // 00401593: lea esi, ss:[ebp+0xffffffffffffffb4]
         // 00401596: push esi
         // 00401597: push edi
         // 00401598: sub esp, 0x10
         // 0040159b: lea esi, ss:[ebp+0xffffffffffffffa4]
         // 0040159e: mov edi, esp
         // 004015a0: push 0x0
         // 004015a2: movsdd 
         // 004015a3: push 0x118
         // 004015a8: push edx
         // 004015a9: push ecx
         // 004015aa: movsdd 
         // 004015ab: movsdd 
         // 004015ac: movsdd 
         // 004015ad: call ds:[eax+0xe4]
         // 004015b3: push ebx
         // 004015b4: mov edi, eax
         // 004015b6: call ds:[SafeArrayDestroy]
         // 004015bc: mov esi, ds:[VariantClear]
         // 004015c2: lea eax, ss:[ebp+0xffffffffffffffb4]
         // 004015c5: push eax
         // 004015c6: call esi
         // 004015c8: mov ecx, ss:[ebp+0xffffffffffffffd4]
         // 004015cb: test ecx, ecx
         // 004015cd: jz 0x4015d8
      [-]e8a1faffff8365d400
         // 004015cf: call 0x401075
         // 004015d4: and ss:[ebp+0xffffffffffffffd4], 0x0
      [-]8d45a450ffd6c645fc058b45e885c07406
         // 004015d8: lea eax, ss:[ebp+0xffffffffffffffa4]
         // 004015db: push eax
         // 004015dc: call esi
         // 004015de: mov b1 ss:[ebp+0xfffffffffffffffc], b1 0x5
         // 004015e2: mov eax, ss:[ebp+0xffffffffffffffe8]
         // 004015e5: test eax, eax
         // 004015e7: jz 0x4015ef
      [-]8b0850ff5108
         // 004015e9: mov ecx, ds:[eax]
         // 004015eb: push eax
         // 004015ec: call ds:[ecx+0x8]
      [-]8b4dd085c97409
         // 004015ef: mov ecx, ss:[ebp+0xffffffffffffffd0]
         // 004015f2: test ecx, ecx
         // 004015f4: jz 0x4015ff
      [-]e87afaffff8365d000
         // 004015f6: call 0x401075
         // 004015fb: and ss:[ebp+0xffffffffffffffd0], 0x0
      [-]c645fc038b45e485c07406
         // 004015ff: mov b1 ss:[ebp+0xfffffffffffffffc], b1 0x3
         // 00401603: mov eax, ss:[ebp+0xffffffffffffffe4]
         // 00401606: test eax, eax
         // 00401608: jz 0x401610
      [-]8b0850ff5108
         // 0040160a: mov ecx, ds:[eax]
         // 0040160c: push eax
         // 0040160d: call ds:[ecx+0x8]
      [-]8b4dcc85c97409
         // 00401610: mov ecx, ss:[ebp+0xffffffffffffffcc]
         // 00401613: test ecx, ecx
         // 00401615: jz 0x401620
      [-]e859faffff8365cc00
         // 00401617: call 0x401075
         // 0040161c: and ss:[ebp+0xffffffffffffffcc], 0x0
      [-]c645fc018b45e085c07406
         // 00401620: mov b1 ss:[ebp+0xfffffffffffffffc], b1 0x1
         // 00401624: mov eax, ss:[ebp+0xffffffffffffffe0]
         // 00401627: test eax, eax
         // 00401629: jz 0x401631
      [-]8b0850ff5108
         // 0040162b: mov ecx, ds:[eax]
         // 0040162d: push eax
         // 0040162e: call ds:[ecx+0x8]
      [-]c645fc008b45dc85c07418
         // 00401631: mov b1 ss:[ebp+0xfffffffffffffffc], b1 0x0
         // 00401635: mov eax, ss:[ebp+0xffffffffffffffdc]
         // 00401638: test eax, eax
         // 0040163a: jz 0x401654
      [-]8b0850ff5108eb10
         // 0040163c: mov ecx, ds:[eax]
         // 0040163e: push eax
         // 0040163f: call ds:[ecx+0x8]
         // 00401642: jmp 0x401654
      [-]8bc7e8e6060100c3
         // 00401654: mov eax, edi
         // 00401656: call __EH_epilog3
         // 0040165b: retn 
      [-]8b0985c97406
         // 0040165c: mov ecx, ds:[ecx]
         // 0040165e: test ecx, ecx
         // 00401660: jz 0x401668
      [-]8b0151ff5008
         // 00401662: mov eax, ds:[ecx]
         // 00401664: push ecx
         // 00401665: call ds:[eax+0x8]
      [-]558bec568b75086a01e8a6320000598d4d0c516a005650e810000000ff7004ff30e8d246000083c4185e5dc3
         // 00401669: push ebp
         // 0040166a: mov ebp, esp
         // 0040166c: push esi
         // 0040166d: mov esi, ss:[ebp+0x8]
         // 00401670: push 0x1
         // 00401672: call ___acrt_iob_func
         // 00401677: pop ecx
         // 00401678: lea ecx, ss:[ebp+0xc]
         // 0040167b: push ecx
         // 0040167c: push 0x0
         // 0040167e: push esi
         // 0040167f: push eax
         // 00401680: call 0x401695
         // 00401685: push ds:[eax+0x4]
         // 00401688: push ds:[eax]
         // 0040168a: call 0x405d61
         // 0040168f: add esp, 0x18
         // 00401692: pop esi
         // 00401693: pop ebp
         // 00401694: retn 
      [-]b8????????c3
         // 00401695: mov eax, 0x43b380
         // 0040169a: retn 
      [-]558becff7508e8ae030000595dc3
         // 004016ac: push ebp
         // 004016ad: mov ebp, esp
         // 004016af: push ss:[ebp+0x8]
         // 004016b2: call j__free
         // 004016b7: pop ecx
         // 004016b8: pop ebp
         // 004016b9: retn 
      [-]558becf6450801568bf1c70694314100740a
         // 004016ea: push ebp
         // 004016eb: mov ebp, esp
         // 004016ed: test b1 ss:[ebp+0x8], b1 0x1
         // 004016f1: push esi
         // 004016f2: mov esi, ecx
         // 004016f4: mov ds:[esi], ??_7type_info@@6B@
         // 004016fa: jz 0x401706
      [-]6a0c56e8a8ffffff5959
         // 004016fc: push 0xc
         // 004016fe: push esi
         // 004016ff: call 0x4016ac
         // 00401704: pop ecx
         // 00401705: pop ecx
      [-]8bc65e5dc20400
         // 00401706: mov eax, esi
         // 00401708: pop esi
         // 00401709: pop ebp
         // 0040170a: retn b2 0x4
      [-]e953030000
         // 0040170d: jmp j__free
      [-]e82c07000033c0c3
         // 004017b6: call ___scrt_initialize_default_local_stdio_options
         // 004017bb: xor eax, eax
         // 004017bd: retn 
      [-]e8ef080000e8a308000050e82c53000059c3
         // 004017be: call 0x4020b2
         // 004017c3: call 0x40206b
         // 004017c8: push eax
         // 004017c9: call __set_new_mode
         // 004017ce: pop ecx
         // 004017cf: retn 
      [-]e9c5500000
         // 00401a65: jmp _free
      [-]558bec56ff75088bf1e858000000c706c43141008bc65e5dc20400
         // 00401a6a: push ebp
         // 00401a6b: mov ebp, esp
         // 00401a6d: push esi
         // 00401a6e: push ss:[ebp+0x8]
         // 00401a71: mov esi, ecx
         // 00401a73: call ??0exception@std@@QAE@ABV01@@Z
         // 00401a78: mov ds:[esi], ??_7bad_alloc@std@@6B@
         // 00401a7e: mov eax, esi
         // 00401a80: pop esi
         // 00401a81: pop ebp
         // 00401a82: retn b2 0x4
      [-]836104008bc183610800c74104????????c701c4314100c3
         // 00401a85: and ds:[ecx+0x4], 0x0
         // 00401a89: mov eax, ecx
         // 00401a8b: and ds:[ecx+0x8], 0x0
         // 00401a8f: mov ds:[ecx+0x4], 0x4131cc
         // 00401a96: mov ds:[ecx], ??_7bad_alloc@std@@6B@
         // 00401a9c: retn 
      [-]558bec56ff75088bf1e825000000c706e03141008bc65e5dc20400
         // 00401a9d: push ebp
         // 00401a9e: mov ebp, esp
         // 00401aa0: push esi
         // 00401aa1: push ss:[ebp+0x8]
         // 00401aa4: mov esi, ecx
         // 00401aa6: call ??0exception@std@@QAE@ABV01@@Z
         // 00401aab: mov ds:[esi], ??_7bad_array_new_length@std@@6B@
         // 00401ab1: mov eax, esi
         // 00401ab3: pop esi
         // 00401ab4: pop ebp
         // 00401ab5: retn b2 0x4
      [-]836104008bc183610800c74104????????c701e0314100c3
         // 00401ab8: and ds:[ecx+0x4], 0x0
         // 00401abc: mov eax, ecx
         // 00401abe: and ds:[ecx+0x8], 0x0
         // 00401ac2: mov ds:[ecx+0x4], 0x4131e8
         // 00401ac9: mov ds:[ecx], ??_7bad_array_new_length@std@@6B@
         // 00401acf: retn 
      [-]558bec83ec0c8d4df4e84effffff681c8443008d45f450e8830f0000
         // 00401b29: push ebp
         // 00401b2a: mov ebp, esp
         // 00401b2c: sub esp, 0xc
         // 00401b2f: lea ecx, ss:[ebp+0xfffffffffffffff4]
         // 00401b32: call 0x401a85
         // 00401b37: push __TI2?AVbad_alloc@std@@
         // 00401b3c: lea eax, ss:[ebp+0xfffffffffffffff4]
         // 00401b3f: push eax
         // 00401b40: call __CxxThrowException@8
      [-]558bec83ec0c8d4df4e864ffffff68708443008d45f450e8660f0000
         // 00401b46: push ebp
         // 00401b47: mov ebp, esp
         // 00401b49: sub esp, 0xc
         // 00401b4c: lea ecx, ss:[ebp+0xfffffffffffffff4]
         // 00401b4f: call 0x401ab8
         // 00401b54: push __TI3?AVbad_array_new_length@std@@
         // 00401b59: lea eax, ss:[ebp+0xfffffffffffffff4]
         // 00401b5c: push eax
         // 00401b5d: call __CxxThrowException@8
      [-]33c040c3
         // 00401eaa: xor eax, eax
         // 00401eac: inc eax
         // 00401ead: retn 
      [-]68a8ab4300ff1558304100c3
         // 00401eb4: push ListHead.Alignment
         // 00401eb9: call ds:[InitializeSListHead]
         // 00401ebf: retn 
      [-]b8????????c3
         // 00401ee1: mov eax, 0x43abb0
         // 00401ee6: retn 
      [-]33c03905????????0f94c0c3
         // 00401f04: xor eax, eax
         // 00401f06: cmp ds:[0x43a00c], eax
         // 00401f0c: setz b1 al
         // 00401f0f: retn 
      [-]b8????????c3
         // 00401f10: mov eax, 0x43b390
         // 00401f15: retn 
      [-]b8????????c3
         // 00401f16: mov eax, 0x43b38c
         // 00401f1b: retn 
      [-]68be204000ff1538304100c3
         // 004020b2: push ___scrt_unhandled_exception_filter@4
         // 004020b7: call ds:[SetUnhandledExceptionFilter]
         // 004020bd: retn 
      [-]8325????????00c3
         // 004020ff: and ds:[0x43abb8], 0x0
         // 00402106: retn 
      [-]5356be????????bb????????3bf37318
         // 00402107: push ebx
         // 00402108: push esi
         // 00402109: mov esi, 0x438280
         // 0040210e: mov ebx, 0x438280
         // 00402113: cmp esi, ebx
         // 00402115: jnb 0x40212f
      [-]8b3e85ff7409
         // 00402118: mov edi, ds:[esi]
         // 0040211a: test edi, edi
         // 0040211c: jz 0x402127
      [-]8bcfe838000000ffd7
         // 0040211e: mov ecx, edi
         // 00402120: call j_@_guard_check_icall_nop@4
         // 00402125: call edi
      [-]83c6043bf372ea
         // 00402127: add esi, 0x4
         // 0040212a: cmp esi, ebx
         // 0040212c: jb 0x402118
      [-]5356be????????bb????????3bf37318
         // 00402132: push ebx
         // 00402133: push esi
         // 00402134: mov esi, 0x438288
         // 00402139: mov ebx, 0x438288
         // 0040213e: cmp esi, ebx
         // 00402140: jnb 0x40215a
      [-]8b3e85ff7409
         // 00402143: mov edi, ds:[esi]
         // 00402145: test edi, edi
         // 00402147: jz 0x402152
      [-]8bcfe80d000000ffd7
         // 00402149: mov ecx, edi
         // 0040214b: call j_@_guard_check_icall_nop@4
         // 00402150: call edi
      [-]83c6043bf372ea
         // 00402152: add esi, 0x4
         // 00402155: cmp esi, ebx
         // 00402157: jb 0x402143
      [-]ff253c314100
         // 0040215d: jmp ds:[___guard_check_icall_fptr]
      [-]558bec568b35????????8bce6a00ff7508e8c7fdffffffd6
         // 00402380: push ebp
         // 00402381: mov ebp, esp
         // 00402383: push esi
         // 00402384: mov esi, ds:[0x43a014]
         // 0040238a: mov ecx, esi
         // 0040238c: push 0x0
         // 0040238e: push ss:[ebp+0x8]
         // 00402391: call j_@_guard_check_icall_nop@4
         // 00402396: call esi
      [-]558bec8b5508578bf9c707????????8b42048947048b42088bc8894708c747????????0085c97411
         // 004023a0: push ebp
         // 004023a1: mov ebp, esp
         // 004023a3: mov edx, ss:[ebp+0x8]
         // 004023a6: push edi
         // 004023a7: mov edi, ecx
         // 004023a9: mov ds:[edi], 0x413200
         // 004023af: mov eax, ds:[edx+0x4]
         // 004023b2: mov ds:[edi+0x4], eax
         // 004023b5: mov eax, ds:[edx+0x8]
         // 004023b8: mov ecx, eax
         // 004023ba: mov ds:[edi+0x8], eax
         // 004023bd: mov ds:[edi+0xc], 0x0
         // 004023c4: test ecx, ecx
         // 004023c6: jz 0x4023d9
      [-]8b0156518b70048bcee887fdffffffd65e
         // 004023c8: mov eax, ds:[ecx]
         // 004023ca: push esi
         // 004023cb: push ecx
         // 004023cc: mov esi, ds:[eax+0x4]
         // 004023cf: mov ecx, esi
         // 004023d1: call j_@_guard_check_icall_nop@4
         // 004023d6: call esi
         // 004023d8: pop esi
      [-]8bc75f5dc20400
         // 004023d9: mov eax, edi
         // 004023db: pop edi
         // 004023dc: pop ebp
         // 004023dd: retn b2 0x4
      [-]558bec8b4508578bf98b4d0cc707????????894704894f08c747????????0085c97417
         // 004023e0: push ebp
         // 004023e1: mov ebp, esp
         // 004023e3: mov eax, ss:[ebp+0x8]
         // 004023e6: push edi
         // 004023e7: mov edi, ecx
         // 004023e9: mov ecx, ss:[ebp+0xc]
         // 004023ec: mov ds:[edi], 0x413200
         // 004023f2: mov ds:[edi+0x4], eax
         // 004023f5: mov ds:[edi+0x8], ecx
         // 004023f8: mov ds:[edi+0xc], 0x0
         // 004023ff: test ecx, ecx
         // 00402401: jz 0x40241a
      [-]807d10007411
         // 00402403: cmp b1 ss:[ebp+0x10], b1 0x0
         // 00402407: jz 0x40241a
      [-]8b0156518b70048bcee846fdffffffd65e
         // 00402409: mov eax, ds:[ecx]
         // 0040240b: push esi
         // 0040240c: push ecx
         // 0040240d: mov esi, ds:[eax+0x4]
         // 00402410: mov ecx, esi
         // 00402412: call j_@_guard_check_icall_nop@4
         // 00402417: call esi
         // 00402419: pop esi
      [-]8bc75f5dc20c00
         // 0040241a: mov eax, edi
         // 0040241c: pop edi
         // 0040241d: pop ebp
         // 0040241e: retn b2 0xc
      [-]578bf98b4f08c707????????85c97411
         // 00402430: push edi
         // 00402431: mov edi, ecx
         // 00402433: mov ecx, ds:[edi+0x8]
         // 00402436: mov ds:[edi], 0x413200
         // 0040243c: test ecx, ecx
         // 0040243e: jz 0x402451
      [-]8b0156518b70088bcee80ffdffffffd65e
         // 00402440: mov eax, ds:[ecx]
         // 00402442: push esi
         // 00402443: push ecx
         // 00402444: mov esi, ds:[eax+0x8]
         // 00402447: mov ecx, esi
         // 00402449: call j_@_guard_check_icall_nop@4
         // 0040244e: call esi
         // 00402450: pop esi
      [-]8b470c5f85c07407
         // 00402451: mov eax, ds:[edi+0xc]
         // 00402454: pop edi
         // 00402455: test eax, eax
         // 00402457: jz 0x402460
      [-]50ff1568304100
         // 00402459: push eax
         // 0040245a: call ds:[LocalFree]
      [-]558bec578bf98b4f08c707????????85c97411
         // 00402470: push ebp
         // 00402471: mov ebp, esp
         // 00402473: push edi
         // 00402474: mov edi, ecx
         // 00402476: mov ecx, ds:[edi+0x8]
         // 00402479: mov ds:[edi], 0x413200
         // 0040247f: test ecx, ecx
         // 00402481: jz 0x402494
      [-]8b0156518b70088bcee8ccfcffffffd65e
         // 00402483: mov eax, ds:[ecx]
         // 00402485: push esi
         // 00402486: push ecx
         // 00402487: mov esi, ds:[eax+0x8]
         // 0040248a: mov ecx, esi
         // 0040248c: call j_@_guard_check_icall_nop@4
         // 00402491: call esi
         // 00402493: pop esi
      [-]8b470c85c07407
         // 00402494: mov eax, ds:[edi+0xc]
         // 00402497: test eax, eax
         // 00402499: jz 0x4024a2
      [-]50ff1568304100
         // 0040249b: push eax
         // 0040249c: call ds:[LocalFree]
      [-]f6450801740b
         // 004024a2: test b1 ss:[ebp+0x8], b1 0x1
         // 004024a6: jz 0x4024b3
      [-]6a1057e8fcf1ffff83c408
         // 004024a8: push 0x10
         // 004024aa: push edi
         // 004024ab: call 0x4016ac
         // 004024b0: add esp, 0x8
      [-]8bc75f5dc20400
         // 004024b3: mov eax, edi
         // 004024b5: pop edi
         // 004024b6: pop ebp
         // 004024b7: retn b2 0x4
      [-]558bec83ec108d4df06a00ff750cff7508e80affffff68cc8443008d45f050e8e4050000
         // 004024c0: push ebp
         // 004024c1: mov ebp, esp
         // 004024c3: sub esp, 0x10
         // 004024c6: lea ecx, ss:[ebp+0xfffffffffffffff0]
         // 004024c9: push 0x0
         // 004024cb: push ss:[ebp+0xc]
         // 004024ce: push ss:[ebp+0x8]
         // 004024d1: call 0x4023e0
         // 004024d6: push __TI1?AV_com_error@@
         // 004024db: lea eax, ss:[ebp+0xfffffffffffffff0]
         // 004024de: push eax
         // 004024df: call __CxxThrowException@8
      [-]558bec56ff75088bf1e846ecffffc706283241008bc65e5dc20400
         // 00402e7c: push ebp
         // 00402e7d: mov ebp, esp
         // 00402e7f: push esi
         // 00402e80: push ss:[ebp+0x8]
         // 00402e83: mov esi, ecx
         // 00402e85: call ??0exception@std@@QAE@ABV01@@Z
         // 00402e8a: mov ds:[esi], ??_7bad_exception@std@@6B@
         // 00402e90: mov eax, esi
         // 00402e92: pop esi
         // 00402e93: pop ebp
         // 00402e94: retn b2 0x4
      [-]836104008bc183610800c74104????????c70128324100c3
         // 00402e97: and ds:[ecx+0x4], 0x0
         // 00402e9b: mov eax, ecx
         // 00402e9d: and ds:[ecx+0x8], 0x0
         // 00402ea1: mov ds:[ecx+0x4], 0x413230
         // 00402ea8: mov ds:[ecx], ??_7bad_exception@std@@6B@
         // 00402eae: retn 
      [-]8bff568bf18d8e????????e8500b000084c07505
         // 0040504b: mov edi, edi
         // 0040504d: push esi
         // 0040504e: mov esi, ecx
         // 00405050: lea ecx, ds:[esi+0x448]
         // 00405056: call 0x405bab
         // 0040505b: test b1 al, b1 al
         // 0040505d: jnz 0x405064
      [-]83c8ff5ec3
         // 0040505f: or eax, 0xffffffffffffffff
         // 00405062: pop esi
         // 00405063: retn 
      [-]5333db395e100f85c0000000
         // 00405064: push ebx
         // 00405065: xor ebx, ebx
         // 00405067: cmp ds:[esi+0x10], ebx
         // 0040506a: jnz 0x405130
      [-]e85b2c0000c700????????e8932b0000
         // 00405070: call __errno
         // 00405075: mov ds:[eax], 0x16
         // 0040507b: call __invalid_parameter_noinfo
      [-]83c8ffe9be000000
         // 00405080: or eax, 0xffffffffffffffff
         // 00405083: jmp 0x405146
      [-]895e38895e1ce986000000
         // 00405088: mov ds:[esi+0x38], ebx
         // 0040508b: mov ds:[esi+0x1c], ebx
         // 0040508e: jmp 0x405119
      [-]83461002395e180f8c90000000
         // 00405093: add ds:[esi+0x10], 0x2
         // 00405097: cmp ds:[esi+0x18], ebx
         // 0040509a: jl 0x405130
      [-]ff761c0fb746328bce50e892feffff89461c83f80874b9
         // 004050a0: push ds:[esi+0x1c]
         // 004050a3: movzx eax, b2 ds:[esi+0x32]
         // 004050a7: mov ecx, esi
         // 004050a9: push eax
         // 004050aa: call 0x404f41
         // 004050af: mov ds:[esi+0x1c], eax
         // 004050b2: cmp eax, 0x8
         // 004050b5: jz 0x405070
      [-]83f80777c4
         // 004050b7: cmp eax, 0x7
         // 004050ba: ja def_4050BC
      [-]ff24854b514000
         // 004050bc: jmp ds:[jpt_4050BC+eax*0x4]
      [-]8bcee8de000000eb45
         // 004050c3: mov ecx, esi
         // 004050c5: call 0x4051a8
         // 004050ca: jmp 0x405111
      [-]834e28ff895e24885e30895e20895e2c885e3ceb38
         // 004050cc: or ds:[esi+0x28], 0xffffffffffffffff
         // 004050d0: mov ds:[esi+0x24], ebx
         // 004050d3: mov b1 ds:[esi+0x30], b1 bl
         // 004050d6: mov ds:[esi+0x20], ebx
         // 004050d9: mov ds:[esi+0x2c], ebx
         // 004050dc: mov b1 ds:[esi+0x3c], b1 bl
         // 004050df: jmp 0x405119
      [-]8bcee883000000eb27
         // 004050e1: mov ecx, esi
         // 004050e3: call 0x40516b
         // 004050e8: jmp 0x405111
      [-]8bcee80e050000eb1e
         // 004050ea: mov ecx, esi
         // 004050ec: call 0x4055ff
         // 004050f1: jmp 0x405111
      [-]895e28eb21
         // 004050f3: mov ds:[esi+0x28], ebx
         // 004050f6: jmp 0x405119
      [-]8bcee8f2000000eb10
         // 004050f8: mov ecx, esi
         // 004050fa: call 0x4051f1
         // 004050ff: jmp 0x405111
      [-]8bcee812010000eb07
         // 00405101: mov ecx, esi
         // 00405103: call 0x40521a
         // 00405108: jmp 0x405111
      [-]8bcee88d020000
         // 0040510a: mov ecx, esi
         // 0040510c: call 0x40539e
      [-]84c00f8467ffffff
         // 00405111: test b1 al, b1 al
         // 00405113: jz def_4050BC
      [-]8b46100fb700668946326685c00f8567ffffff
         // 00405119: mov eax, ds:[esi+0x10]
         // 0040511c: movzx eax, b2 ds:[eax]
         // 0040511f: mov b2 ds:[esi+0x32], b2 ax
         // 00405123: test b2 ax, b2 ax
         // 00405126: jnz 0x405093
      [-]83461002
         // 0040512c: add ds:[esi+0x10], 0x2
      [-]ff86????????83be????????020f8545ffffff
         // 00405130: inc ds:[esi+0x450]
         // 00405136: cmp ds:[esi+0x450], 0x2
         // 0040513d: jnz 0x405088
      [-]e81a00000084c07513
         // 004051a8: call 0x4051c7
         // 004051ad: test b1 al, b1 al
         // 004051af: jnz 0x4051c4
      [-]e81a2b0000c700????????e8522a000032c0c3
         // 004051b1: call __errno
         // 004051b6: mov ds:[eax], 0x16
         // 004051bc: call __invalid_parameter_noinfo
         // 004051c1: xor b1 al, b1 al
         // 004051c3: retn 
      [-]668379322a740a
         // 004051f1: cmp b2 ds:[ecx+0x32], b2 0x2a
         // 004051f6: jz 0x405202
      [-]8d412850e8d0fdffffc3
         // 004051f8: lea eax, ds:[ecx+0x28]
         // 004051fb: push eax
         // 004051fc: call 0x404fd1
         // 00405201: retn 
      [-]834114048b41148b40fc89412885c07904
         // 00405202: add ds:[ecx+0x14], 0x4
         // 00405206: mov eax, ds:[ecx+0x14]
         // 00405209: mov eax, ds:[eax+0xfffffffffffffffc]
         // 0040520c: mov ds:[ecx+0x28], eax
         // 0040520f: test eax, eax
         // 00405211: jns 0x405217
      [-]834928ff
         // 00405213: or ds:[ecx+0x28], 0xffffffffffffffff
      [-]0fb7413283f846751a
         // 0040521a: movzx eax, b2 ds:[ecx+0x32]
         // 0040521e: cmp eax, 0x46
         // 00405221: jnz 0x40523d
      [-]8b0183e00883c8000f856a010000
         // 00405223: mov eax, ds:[ecx]
         // 00405225: and eax, 0x8
         // 00405228: or eax, 0x0
         // 0040522b: jnz 0x40539b
      [-]c7411c????????e961010000
         // 00405231: mov ds:[ecx+0x1c], 0x7
         // 00405238: jmp 0x40539e
      [-]83f84e7526
         // 0040523d: cmp eax, 0x4e
         // 00405240: jnz 0x405268
      [-]8b016a085a23c283c8000f8549010000
         // 00405242: mov eax, ds:[ecx]
         // 00405244: push 0x8
         // 00405246: pop edx
         // 00405247: and eax, edx
         // 00405249: or eax, 0x0
         // 0040524c: jnz 0x40539b
      [-]e8762a0000c700????????e8ae29000032c0c3
         // 00405255: call __errno
         // 0040525a: mov ds:[eax], 0x16
         // 00405260: call __invalid_parameter_noinfo
         // 00405265: xor b1 al, b1 al
         // 00405267: retn 
      [-]83792c0075e7
         // 00405268: cmp ds:[ecx+0x2c], 0x0
         // 0040526c: jnz 0x405255
      [-]83f86a0f87d5000000
         // 0040526e: cmp eax, 0x6a
         // 00405271: ja 0x40534c
      [-]0f84c6000000
         // 00405277: jz 0x405343
      [-]83f8497453
         // 0040527d: cmp eax, 0x49
         // 00405280: jz 0x4052d5
      [-]83f84c7442
         // 00405282: cmp eax, 0x4c
         // 00405285: jz 0x4052c9
      [-]83f8547431
         // 00405287: cmp eax, 0x54
         // 0040528a: jz 0x4052bd
      [-]6a685a3bc20f8504010000
         // 0040528c: push 0x68
         // 0040528e: pop edx
         // 0040528f: cmp eax, edx
         // 00405291: jnz 0x40539b
      [-]8b41106639107512
         // 00405297: mov eax, ds:[ecx+0x10]
         // 0040529a: cmp b2 ds:[eax], b2 dx
         // 0040529d: jnz 0x4052b1
      [-]83c002c7412c????????894110e9ea000000
         // 0040529f: add eax, 0x2
         // 004052a2: mov ds:[ecx+0x2c], 0x1
         // 004052a9: mov ds:[ecx+0x10], eax
         // 004052ac: jmp 0x40539b
      [-]c7412c????????e9de000000
         // 004052b1: mov ds:[ecx+0x2c], 0x2
         // 004052b8: jmp 0x40539b
      [-]c7412c????????e9d2000000
         // 004052bd: mov ds:[ecx+0x2c], 0xd
         // 004052c4: jmp 0x40539b
      [-]c7412c????????e9c6000000
         // 004052c9: mov ds:[ecx+0x2c], 0x8
         // 004052d0: jmp 0x40539b
      [-]8b51100fb70283f833751d
         // 004052d5: mov edx, ds:[ecx+0x10]
         // 004052d8: movzx eax, b2 ds:[edx]
         // 004052db: cmp eax, 0x33
         // 004052de: jnz 0x4052fd
      [-]66837a02320f85b0000000
         // 004052e0: cmp b2 ds:[edx+0x2], b2 0x32
         // 004052e5: jnz 0x40539b
      [-]8d4204c7412c????????894110e99e000000
         // 004052eb: lea eax, ds:[edx+0x4]
         // 004052ee: mov ds:[ecx+0x2c], 0xa
         // 004052f5: mov ds:[ecx+0x10], eax
         // 004052f8: jmp 0x40539b
      [-]83f836751a
         // 004052fd: cmp eax, 0x36
         // 00405300: jnz 0x40531c
      [-]66837a02340f858e000000
         // 00405302: cmp b2 ds:[edx+0x2], b2 0x34
         // 00405307: jnz 0x40539b
      [-]8d4204c7412c????????894110eb7f
         // 0040530d: lea eax, ds:[edx+0x4]
         // 00405310: mov ds:[ecx+0x2c], 0xb
         // 00405317: mov ds:[ecx+0x10], eax
         // 0040531a: jmp 0x40539b
      [-]83f8647419
         // 0040531c: cmp eax, 0x64
         // 0040531f: jz 0x40533a
      [-]83f8697414
         // 00405321: cmp eax, 0x69
         // 00405324: jz 0x40533a
      [-]83f86f740f
         // 00405326: cmp eax, 0x6f
         // 00405329: jz 0x40533a
      [-]83f875740a
         // 0040532b: cmp eax, 0x75
         // 0040532e: jz 0x40533a
      [-]83f8787405
         // 00405330: cmp eax, 0x78
         // 00405333: jz 0x40533a
      [-]83f8587561
         // 00405335: cmp eax, 0x58
         // 00405338: jnz 0x40539b
      [-]c7412c????????eb58
         // 0040533a: mov ds:[ecx+0x2c], 0x9
         // 00405341: jmp 0x40539b
      [-]c7412c????????eb4f
         // 00405343: mov ds:[ecx+0x2c], 0x5
         // 0040534a: jmp 0x40539b
      [-]6a6c5a3bc2742a
         // 0040534c: push 0x6c
         // 0040534e: pop edx
         // 0040534f: cmp eax, edx
         // 00405351: jz 0x40537d
      [-]83f874741c
         // 00405353: cmp eax, 0x74
         // 00405356: jz 0x405374
      [-]83f877740e
         // 00405358: cmp eax, 0x77
         // 0040535b: jz 0x40536b
      [-]83f87a7539
         // 0040535d: cmp eax, 0x7a
         // 00405360: jnz 0x40539b
      [-]c7412c????????eb30
         // 00405362: mov ds:[ecx+0x2c], 0x6
         // 00405369: jmp 0x40539b
      [-]c7412c????????eb27
         // 0040536b: mov ds:[ecx+0x2c], 0xc
         // 00405372: jmp 0x40539b
      [-]c7412c????????eb1e
         // 00405374: mov ds:[ecx+0x2c], 0x7
         // 0040537b: jmp 0x40539b
      [-]8b4110663910750f
         // 0040537d: mov eax, ds:[ecx+0x10]
         // 00405380: cmp b2 ds:[eax], b2 dx
         // 00405383: jnz 0x405394
      [-]83c002c7412c????????894110eb07
         // 00405385: add eax, 0x2
         // 00405388: mov ds:[ecx+0x2c], 0x4
         // 0040538f: mov ds:[ecx+0x10], eax
         // 00405392: jmp 0x40539b
      [-]c7412c????????
         // 00405394: mov ds:[ecx+0x2c], 0x3
      [-]8bff558bec83ec10a100a0430033c58945fc53568bf133db6a415a6a580fb746325983f864776b
         // 0040539e: mov edi, edi
         // 004053a0: push ebp
         // 004053a1: mov ebp, esp
         // 004053a3: sub esp, 0x10
         // 004053a6: mov eax, ds:[___security_cookie]
         // 004053ab: xor eax, ebp
         // 004053ad: mov ss:[ebp+0xfffffffffffffffc], eax
         // 004053b0: push ebx
         // 004053b1: push esi
         // 004053b2: mov esi, ecx
         // 004053b4: xor ebx, ebx
         // 004053b6: push 0x41
         // 004053b8: pop edx
         // 004053b9: push 0x58
         // 004053bb: movzx eax, b2 ds:[esi+0x32]
         // 004053bf: pop ecx
         // 004053c0: cmp eax, 0x64
         // 004053c3: ja 0x405430
      [-]0f8497000000
         // 004053c5: jz 0x405462
      [-]3bc1773e
         // 004053cb: cmp eax, ecx
         // 004053cd: ja 0x40540d
      [-]3bc20f8499000000
         // 004053d1: cmp eax, edx
         // 004053d3: jz 0x405472
      [-]83f843743f
         // 004053d9: cmp eax, 0x43
         // 004053dc: jz 0x40541d
      [-]83f844761d
         // 004053de: cmp eax, 0x44
         // 004053e1: jbe 0x405400
      [-]83f8470f8686000000
         // 004053e3: cmp eax, 0x47
         // 004053e6: jbe 0x405472
      [-]83f853750f
         // 004053ec: cmp eax, 0x53
         // 004053ef: jnz 0x405400
      [-]8bcee802070000
         // 004053f1: mov ecx, esi
         // 004053f3: call 0x405afa
      [-]84c00f85a8000000
         // 004053f8: test b1 al, b1 al
         // 004053fa: jnz 0x4054a8
      [-]32c0e9e8010000
         // 00405400: xor b1 al, b1 al
         // 00405402: jmp 0x4055ef
      [-]6a10eb5c
         // 00405409: push 0x10
         // 0040540b: jmp 0x405469
      [-]83e85a7415
         // 0040540d: sub eax, 0x5a
         // 00405410: jz 0x405427
      [-]83e807745b
         // 00405412: sub eax, 0x7
         // 00405415: jz 0x405472
      [-]4883e80175e3
         // 00405417: dec eax
         // 00405418: sub eax, 0x1
         // 0040541b: jnz 0x405400
      [-]538bcee83d040000ebd1
         // 0040541d: push ebx
         // 0040541e: mov ecx, esi
         // 00405420: call 0x405862
         // 00405425: jmp 0x4053f8
      [-]8bcee85b020000ebc8
         // 00405427: mov ecx, esi
         // 00405429: call 0x405689
         // 0040542e: jmp 0x4053f8
      [-]83f8707755
         // 00405430: cmp eax, 0x70
         // 00405433: ja 0x40548a
      [-]83f86572c4
         // 00405437: cmp eax, 0x65
         // 0040543a: jb 0x405400
      [-]83f8677631
         // 0040543c: cmp eax, 0x67
         // 0040543f: jbe 0x405472
      [-]83f869741c
         // 00405441: cmp eax, 0x69
         // 00405444: jz 0x405462
      [-]83f86e740e
         // 00405446: cmp eax, 0x6e
         // 00405449: jz 0x405459
      [-]83f86f75b0
         // 0040544b: cmp eax, 0x6f
         // 0040544e: jnz 0x405400
      [-]8bcee86c060000eb9f
         // 00405450: mov ecx, esi
         // 00405452: call 0x405ac3
         // 00405457: jmp 0x4053f8
      [-]8bcee8ef050000eb96
         // 00405459: mov ecx, esi
         // 0040545b: call 0x405a4f
         // 00405460: jmp 0x4053f8
      [-]834e2010
         // 00405462: or ds:[esi+0x20], 0x10
      [-]8bcee88a040000eb86
         // 00405469: mov ecx, esi
         // 0040546b: call 0x4058fa
         // 00405470: jmp 0x4053f8
      [-]8bcee873020000e97affffff
         // 00405472: mov ecx, esi
         // 00405474: call 0x4056ec
         // 00405479: jmp 0x4053f8
      [-]8bcee85d060000e96effffff
         // 0040547e: mov ecx, esi
         // 00405480: call 0x405ae2
         // 00405485: jmp 0x4053f8
      [-]83e8730f845effffff
         // 0040548a: sub eax, 0x73
         // 0040548d: jz 0x4053f1
      [-]4883e80174cd
         // 00405493: dec eax
         // 00405494: sub eax, 0x1
         // 00405497: jz 0x405466
      [-]83e8030f855effffff
         // 00405499: sub eax, 0x3
         // 0040549c: jnz 0x405400
      [-]53e961ffffff
         // 004054a2: push ebx
         // 004054a3: jmp 0x405409
      [-]385e300f853c010000
         // 004054a8: cmp b1 ds:[esi+0x30], b1 bl
         // 004054ab: jnz 0x4055ed
      [-]8b562033c9578bc2895df4c1e8044166895df86a205f84c17428
         // 004054b1: mov edx, ds:[esi+0x20]
         // 004054b4: xor ecx, ecx
         // 004054b6: push edi
         // 004054b7: mov eax, edx
         // 004054b9: mov ss:[ebp+0xfffffffffffffff4], ebx
         // 004054bc: shr eax, b1 0x4
         // 004054bf: inc ecx
         // 004054c0: mov b2 ss:[ebp+0xfffffffffffffff8], b2 bx
         // 004054c4: push 0x20
         // 004054c6: pop edi
         // 004054c7: test b1 cl, b1 al
         // 004054c9: jz 0x4054f3
      [-]8bc2c1e80684c17409
         // 004054cb: mov eax, edx
         // 004054cd: shr eax, b1 0x6
         // 004054d0: test b1 cl, b1 al
         // 004054d2: jz 0x4054dd
      [-]58668945f4eb14
         // 004054d6: pop eax
         // 004054d7: mov b2 ss:[ebp+0xfffffffffffffff4], b2 ax
         // 004054db: jmp 0x4054f1
      [-]84d17404
         // 004054dd: test b1 cl, b1 dl
         // 004054df: jz 0x4054e5
      [-]6a2bebf1
         // 004054e1: push 0x2b
         // 004054e3: jmp 0x4054d6
      [-]8bc2d1e884c17406
         // 004054e5: mov eax, edx
         // 004054e7: shr eax, b1 0x1
         // 004054e9: test b1 cl, b1 al
         // 004054eb: jz 0x4054f3
      [-]66897df4
         // 004054ed: mov b2 ss:[ebp+0xfffffffffffffff4], b2 di
      [-]0fb74e326a785f663bcf7408
         // 004054f3: movzx ecx, b2 ds:[esi+0x32]
         // 004054f7: push 0x78
         // 004054f9: pop edi
         // 004054fa: cmp b2 cx, b2 di
         // 004054fd: jz 0x405507
      [-]6a5858663bc8750d
         // 004054ff: push 0x58
         // 00405501: pop eax
         // 00405502: cmp b2 cx, b2 ax
         // 00405505: jnz 0x405514
      [-]8bc2c1e805a8017404
         // 00405507: mov eax, edx
         // 00405509: shr eax, b1 0x5
         // 0040550c: test b1 al, b1 0x1
         // 0040550e: jz 0x405514
      [-]b201eb02
         // 00405510: mov b1 dl, b1 0x1
         // 00405512: jmp 0x405516
      [-]83f961740c
         // 00405516: cmp ecx, 0x61
         // 00405519: jz 0x405527
      [-]6a4158663bc87404
         // 0040551b: push 0x41
         // 0040551d: pop eax
         // 0040551e: cmp b2 cx, b2 ax
         // 00405521: jz 0x405527
      [-]32c0eb02
         // 00405523: xor b1 al, b1 al
         // 00405525: jmp 0x405529
      [-]c745f0????????84d27504
         // 00405529: mov ss:[ebp+0xfffffffffffffff0], 0x30
         // 00405530: test b1 dl, b1 dl
         // 00405532: jnz 0x405538
      [-]84c07422
         // 00405534: test b1 al, b1 al
         // 00405536: jz 0x40555a
      [-]8b45f06a586689445df458663bc87408
         // 00405538: mov eax, ss:[ebp+0xfffffffffffffff0]
         // 0040553b: push 0x58
         // 0040553d: mov b2 ss:[ebp+ebx*0x2], b2 ax
         // 00405542: pop eax
         // 00405543: cmp b2 cx, b2 ax
         // 00405546: jz 0x405550
      [-]6a415a663bca7502
         // 00405548: push 0x41
         // 0040554a: pop edx
         // 0040554b: cmp b2 cx, b2 dx
         // 0040554e: jnz 0x405552
      [-]66897c5df683c302
         // 00405552: mov b2 ss:[ebp+ebx*0x2], b2 di
         // 00405557: add ebx, 0x2
      [-]8b7e242b7e382bfbf646200c7516
         // 0040555a: mov edi, ds:[esi+0x24]
         // 0040555d: sub edi, ds:[esi+0x38]
         // 00405560: sub edi, ebx
         // 00405562: test b1 ds:[esi+0x20], b1 0xc
         // 00405566: jnz 0x40557e
      [-]8d461850578d86????????6a2050e82af7ffff83c410
         // 00405568: lea eax, ds:[esi+0x18]
         // 0040556b: push eax
         // 0040556c: push edi
         // 0040556d: lea eax, ds:[esi+0x448]
         // 00405573: push 0x20
         // 00405575: push eax
         // 00405576: call ??$write_multiple_characters@V?$stream_output_adapter@_W@__crt_stdio_output@@D@__crt_stdio_output@@YAXABV?$stream_output_adapter@_W@0@DHQAH@Z
         // 0040557b: add esp, 0x10
      [-]8d460c508d4e1851538d45f4508d8e????????e8fd0600008b4e208d5e188bc1c1e803a801741c
         // 0040557e: lea eax, ds:[esi+0xc]
         // 00405581: push eax
         // 00405582: lea ecx, ds:[esi+0x18]
         // 00405585: push ecx
         // 00405586: push ebx
         // 00405587: lea eax, ss:[ebp+0xfffffffffffffff4]
         // 0040558a: push eax
         // 0040558b: lea ecx, ds:[esi+0x448]
         // 00405591: call 0x405c93
         // 00405596: mov ecx, ds:[esi+0x20]
         // 00405599: lea ebx, ds:[esi+0x18]
         // 0040559c: mov eax, ecx
         // 0040559e: shr eax, b1 0x3
         // 004055a1: test b1 al, b1 0x1
         // 004055a3: jz 0x4055c1
      [-]c1e902f6c1017514
         // 004055a5: shr ecx, b1 0x2
         // 004055a8: test b1 cl, b1 0x1
         // 004055ab: jnz 0x4055c1
      [-]5357ff75f08d86????????50e8e7f6ffff83c410
         // 004055ad: push ebx
         // 004055ae: push edi
         // 004055af: push ss:[ebp+0xfffffffffffffff0]
         // 004055b2: lea eax, ds:[esi+0x448]
         // 004055b8: push eax
         // 004055b9: call ??$write_multiple_characters@V?$stream_output_adapter@_W@__crt_stdio_output@@D@__crt_stdio_output@@YAXABV?$stream_output_adapter@_W@0@DHQAH@Z
         // 004055be: add esp, 0x10
      [-]6a008bcee834060000833b007c1d
         // 004055c1: push 0x0
         // 004055c3: mov ecx, esi
         // 004055c5: call 0x405bfe
         // 004055ca: cmp ds:[ebx], 0x0
         // 004055cd: jl 0x4055ec
      [-]8b4620c1e802a8017413
         // 004055cf: mov eax, ds:[esi+0x20]
         // 004055d2: shr eax, b1 0x2
         // 004055d5: test b1 al, b1 0x1
         // 004055d7: jz 0x4055ec
      [-]53578d86????????6a2050e8bcf6ffff83c410
         // 004055d9: push ebx
         // 004055da: push edi
         // 004055db: lea eax, ds:[esi+0x448]
         // 004055e1: push 0x20
         // 004055e3: push eax
         // 004055e4: call ??$write_multiple_characters@V?$stream_output_adapter@_W@__crt_stdio_output@@D@__crt_stdio_output@@YAXABV?$stream_output_adapter@_W@0@DHQAH@Z
         // 004055e9: add esp, 0x10
      [-]8b4dfc5e33cd5be8a0c0ffff8be55dc3
         // 004055ef: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 004055f2: pop esi
         // 004055f3: xor ecx, ebp
         // 004055f5: pop ebx
         // 004055f6: call @__security_check_cookie@4
         // 004055fb: mov esp, ebp
         // 004055fd: pop ebp
         // 004055fe: retn 
      [-]668379322a740a
         // 004055ff: cmp b2 ds:[ecx+0x32], b2 0x2a
         // 00405604: jz 0x405610
      [-]8d412450e8c2f9ffffc3
         // 00405606: lea eax, ds:[ecx+0x24]
         // 00405609: push eax
         // 0040560a: call 0x404fd1
         // 0040560f: retn 
      [-]834114048b41148b40fc89412485c07909
         // 00405610: add ds:[ecx+0x14], 0x4
         // 00405614: mov eax, ds:[ecx+0x14]
         // 00405617: mov eax, ds:[eax+0xfffffffffffffffc]
         // 0040561a: mov ds:[ecx+0x24], eax
         // 0040561d: test eax, eax
         // 0040561f: jns 0x40562a
      [-]83492004f7d8894124
         // 00405621: or ds:[ecx+0x20], 0x4
         // 00405625: neg eax
         // 00405627: mov ds:[ecx+0x24], eax
      [-]8bff558bec5153568bf157ff762ce820fdffff598bc88945fc83e9017478
         // 004058fa: mov edi, edi
         // 004058fc: push ebp
         // 004058fd: mov ebp, esp
         // 004058ff: push ecx
         // 00405900: push ebx
         // 00405901: push esi
         // 00405902: mov esi, ecx
         // 00405904: push edi
         // 00405905: push ds:[esi+0x2c]
         // 00405908: call ?to_integer_size@__crt_stdio_output@@YAIW4length_modifier@1@@Z
         // 0040590d: pop ecx
         // 0040590e: mov ecx, eax
         // 00405910: mov ss:[ebp+0xfffffffffffffffc], eax
         // 00405913: sub ecx, 0x1
         // 00405916: jz 0x405990
      [-]83e9017456
         // 00405918: sub ecx, 0x1
         // 0040591b: jz 0x405973
      [-]4983e9017433
         // 0040591d: dec ecx
         // 0040591e: sub ecx, 0x1
         // 00405921: jz 0x405956
      [-]83e9047417
         // 00405923: sub ecx, 0x4
         // 00405926: jz 0x40593f
      [-]e8a3230000c700????????e8db22000032c0e907010000
         // 00405928: call __errno
         // 0040592d: mov ds:[eax], 0x16
         // 00405933: call __invalid_parameter_noinfo
         // 00405938: xor b1 al, b1 al
         // 0040593a: jmp 0x405a46
      [-]8b462083461408c1e804a8018b46148b78f88b58fceb5a
         // 0040593f: mov eax, ds:[esi+0x20]
         // 00405942: add ds:[esi+0x14], 0x8
         // 00405946: shr eax, b1 0x4
         // 00405949: test b1 al, b1 0x1
         // 0040594b: mov eax, ds:[esi+0x14]
         // 0040594e: mov edi, ds:[eax+0xfffffffffffffff8]
         // 00405951: mov ebx, ds:[eax+0xfffffffffffffffc]
         // 00405954: jmp 0x4059b0
      [-]8b462083461404c1e804a8018b46147405
         // 00405956: mov eax, ds:[esi+0x20]
         // 00405959: add ds:[esi+0x14], 0x4
         // 0040595d: shr eax, b1 0x4
         // 00405960: test b1 al, b1 0x1
         // 00405962: mov eax, ds:[esi+0x14]
         // 00405965: jz 0x40596c
      [-]8b40fceb3f
         // 00405967: mov eax, ds:[eax+0xfffffffffffffffc]
         // 0040596a: jmp 0x4059ab
      [-]8b78fc33dbeb3d
         // 0040596c: mov edi, ds:[eax+0xfffffffffffffffc]
         // 0040596f: xor ebx, ebx
         // 00405971: jmp 0x4059b0
      [-]8b462083461404c1e804a8018b46147406
         // 00405973: mov eax, ds:[esi+0x20]
         // 00405976: add ds:[esi+0x14], 0x4
         // 0040597a: shr eax, b1 0x4
         // 0040597d: test b1 al, b1 0x1
         // 0040597f: mov eax, ds:[esi+0x14]
         // 00405982: jz 0x40598a
      [-]0fbf40fceb21
         // 00405984: movsx eax, b2 ds:[eax+0xfffffffffffffffc]
         // 00405988: jmp 0x4059ab
      [-]0fb740fceb1b
         // 0040598a: movzx eax, b2 ds:[eax+0xfffffffffffffffc]
         // 0040598e: jmp 0x4059ab
      [-]8b462083461404c1e804a8018b46147406
         // 00405990: mov eax, ds:[esi+0x20]
         // 00405993: add ds:[esi+0x14], 0x4
         // 00405997: shr eax, b1 0x4
         // 0040599a: test b1 al, b1 0x1
         // 0040599c: mov eax, ds:[esi+0x14]
         // 0040599f: jz 0x4059a7
      [-]0fbe40fceb04
         // 004059a1: movsx eax, b1 ds:[eax+0xfffffffffffffffc]
         // 004059a5: jmp 0x4059ab
      [-]0fb640fc
         // 004059a7: movzx eax, b1 ds:[eax+0xfffffffffffffffc]
      [-]998bf88bda
         // 004059ab: cdq 
         // 004059ac: mov edi, eax
         // 004059ae: mov ebx, edx
      [-]8b4e208bc1c1e804a8017417
         // 004059b0: mov ecx, ds:[esi+0x20]
         // 004059b3: mov eax, ecx
         // 004059b5: shr eax, b1 0x4
         // 004059b8: test b1 al, b1 0x1
         // 004059ba: jz 0x4059d3
      [-]85db7f13
         // 004059bc: test ebx, ebx
         // 004059be: jg 0x4059d3
      [-]85ff730d
         // 004059c2: test edi, edi
         // 004059c4: jnb 0x4059d3
      [-]f7df83d300f7db83c940894e20
         // 004059c6: neg edi
         // 004059c8: adc ebx, 0x0
         // 004059cb: neg ebx
         // 004059cd: or ecx, 0x40
         // 004059d0: mov ds:[esi+0x20], ecx
      [-]837e28007d09
         // 004059d3: cmp ds:[esi+0x28], 0x0
         // 004059d7: jge 0x4059e2
      [-]c74628????????eb0f
         // 004059d9: mov ds:[esi+0x28], 0x1
         // 004059e0: jmp 0x4059f1
      [-]ff7628836620f78d4e40e8b1f0ffff
         // 004059e2: push ds:[esi+0x28]
         // 004059e5: and ds:[esi+0x20], 0xfffffffffffffff7
         // 004059e9: lea ecx, ds:[esi+0x40]
         // 004059ec: call ??$ensure_buffer_is_big_enough@_W@formatting_buffer@__crt_stdio_output@@QAE_NI@Z
      [-]8bc70bc37504
         // 004059f1: mov eax, edi
         // 004059f3: or eax, ebx
         // 004059f5: jnz 0x4059fb
      [-]836620df
         // 004059f7: and ds:[esi+0x20], 0xffffffffffffffdf
      [-]837dfc088bceff750cc6463c01ff75087509
         // 004059fb: cmp ss:[ebp+0xfffffffffffffffc], 0x8
         // 004059ff: mov ecx, esi
         // 00405a01: push ss:[ebp+0xc]
         // 00405a04: mov b1 ds:[esi+0x3c], b1 0x1
         // 00405a08: push ss:[ebp+0x8]
         // 00405a0b: jnz 0x405a16
      [-]5357e8fbf1ffffeb06
         // 00405a0d: push ebx
         // 00405a0e: push edi
         // 00405a0f: call 0x404c0f
         // 00405a14: jmp 0x405a1c
      [-]57e872f1ffff
         // 00405a16: push edi
         // 00405a17: call 0x404b8e
      [-]8b4620c1e807a801741e
         // 00405a1c: mov eax, ds:[esi+0x20]
         // 00405a1f: shr eax, b1 0x7
         // 00405a22: test b1 al, b1 0x1
         // 00405a24: jz 0x405a44
      [-]837e38006a305a7408
         // 00405a26: cmp ds:[esi+0x38], 0x0
         // 00405a2a: push 0x30
         // 00405a2c: pop edx
         // 00405a2d: jz 0x405a37
      [-]8b4634663910740d
         // 00405a2f: mov eax, ds:[esi+0x34]
         // 00405a32: cmp b2 ds:[eax], b2 dx
         // 00405a35: jz 0x405a44
      [-]834634fe8b4e34668911ff4638
         // 00405a37: add ds:[esi+0x34], 0xfffffffffffffffe
         // 00405a3b: mov ecx, ds:[esi+0x34]
         // 00405a3e: mov b2 ds:[ecx], b2 dx
         // 00405a41: inc ds:[esi+0x38]
      [-]5f5e5b8be55dc20800
         // 00405a46: pop edi
         // 00405a47: pop esi
         // 00405a48: pop ebx
         // 00405a49: mov esp, ebp
         // 00405a4b: pop ebp
         // 00405a4c: retn b2 0x8
      [-]8b51208bc2c1e805a8017409
         // 00405ac3: mov edx, ds:[ecx+0x20]
         // 00405ac6: mov eax, edx
         // 00405ac8: shr eax, b1 0x5
         // 00405acb: test b1 al, b1 0x1
         // 00405acd: jz 0x405ad8
      [-]81ca????????895120
         // 00405acf: or edx, 0x80
         // 00405ad5: mov ds:[ecx+0x20], edx
      [-]6a006a08e819feffffc3
         // 00405ad8: push 0x0
         // 00405ada: push 0x8
         // 00405adc: call 0x4058fa
         // 00405ae1: retn 
      [-]6a016a10c74128????????c7412c????????e801feffffc3
         // 00405ae2: push 0x1
         // 00405ae4: push 0x10
         // 00405ae6: mov ds:[ecx+0x28], 0x8
         // 00405aed: mov ds:[ecx+0x2c], 0xa
         // 00405af4: call 0x4058fa
         // 00405af9: retn 
      [-]8bff53568bf157834614048b46148b7e288b58fc895e3483ffff7505
         // 00405afa: mov edi, edi
         // 00405afc: push ebx
         // 00405afd: push esi
         // 00405afe: mov esi, ecx
         // 00405b00: push edi
         // 00405b01: add ds:[esi+0x14], 0x4
         // 00405b05: mov eax, ds:[esi+0x14]
         // 00405b08: mov edi, ds:[esi+0x28]
         // 00405b0b: mov ebx, ds:[eax+0xfffffffffffffffc]
         // 00405b0e: mov ds:[esi+0x34], ebx
         // 00405b11: cmp edi, 0xffffffffffffffff
         // 00405b14: jnz 0x405b1b
      [-]bf????????
         // 00405b16: mov edi, 0x7fffffff
      [-]ff762c0fb7463250ff7604ff36e8f5efffff83c41084c0741c
         // 00405b1b: push ds:[esi+0x2c]
         // 00405b1e: movzx eax, b2 ds:[esi+0x32]
         // 00405b22: push eax
         // 00405b23: push ds:[esi+0x4]
         // 00405b26: push ds:[esi]
         // 00405b28: call ??$is_wide_character_specifier@_W@__crt_stdio_output@@YA_N_K_WW4length_modifier@0@@Z
         // 00405b2d: add esp, 0x10
         // 00405b30: test b1 al, b1 al
         // 00405b32: jz 0x405b50
      [-]85db7507
         // 00405b34: test ebx, ebx
         // 00405b36: jnz 0x405b3f
      [-]c74634????????
         // 00405b38: mov ds:[esi+0x34], 0x413b44
      [-]57ff7634c6463c01e8533000005959eb15
         // 00405b3f: push edi
         // 00405b40: push ds:[esi+0x34]
         // 00405b43: mov b1 ds:[esi+0x3c], b1 0x1
         // 00405b47: call _wcsnlen
         // 00405b4c: pop ecx
         // 00405b4d: pop ecx
         // 00405b4e: jmp 0x405b65
      [-]85db7507
         // 00405b50: test ebx, ebx
         // 00405b52: jnz 0x405b5b
      [-]c74634????????
         // 00405b54: mov ds:[esi+0x34], 0x413b54
      [-]6a00578bcee809000000
         // 00405b5b: push 0x0
         // 00405b5d: push edi
         // 00405b5e: mov ecx, esi
         // 00405b60: call 0x405b6e
      [-]5f894638b0015e5bc3
         // 00405b65: pop edi
         // 00405b66: mov ds:[esi+0x38], eax
         // 00405b69: mov b1 al, b1 0x1
         // 00405b6b: pop esi
         // 00405b6c: pop ebx
         // 00405b6d: retn 
      [-]8bff558bec8b018b400cc1e80ca8017414
         // 00405c93: mov edi, edi
         // 00405c95: push ebp
         // 00405c96: mov ebp, esp
         // 00405c98: mov eax, ds:[ecx]
         // 00405c9a: mov eax, ds:[eax+0xc]
         // 00405c9d: shr eax, b1 0xc
         // 00405ca0: test b1 al, b1 0x1
         // 00405ca2: jz 0x405cb8
      [-]8b0183780400750c
         // 00405ca4: mov eax, ds:[ecx]
         // 00405ca6: cmp ds:[eax+0x4], 0x0
         // 00405caa: jnz 0x405cb8
      [-]8b4d108b450c01015dc21000
         // 00405cac: mov ecx, ss:[ebp+0x10]
         // 00405caf: mov eax, ss:[ebp+0xc]
         // 00405cb2: add ds:[ecx], eax
         // 00405cb4: pop ebp
         // 00405cb5: retn b2 0x10
      [-]5de9000000008bff558bec83ec1053568b75148bd18955fc833e00750a
         // 00405cb8: pop ebp
         // 00405cb9: jmp 0x405cbe
         // 00405cbe: mov edi, edi
         // 00405cc0: push ebp
         // 00405cc1: mov ebp, esp
         // 00405cc3: sub esp, 0x10
         // 00405cc6: push ebx
         // 00405cc7: push esi
         // 00405cc8: mov esi, ss:[ebp+0x14]
         // 00405ccb: mov edx, ecx
         // 00405ccd: mov ss:[ebp+0xfffffffffffffffc], edx
         // 00405cd0: cmp ds:[esi], 0x0
         // 00405cd3: jnz 0x405cdf
      [-]e8f61f00008b55fc8906
         // 00405cd5: call __errno
         // 00405cda: mov edx, ss:[ebp+0xfffffffffffffffc]
         // 00405cdd: mov ds:[esi], eax
      [-]8b068b5d088945f08b088320008b450c894df88d04438945f43bd8744f
         // 00405cdf: mov eax, ds:[esi]
         // 00405ce1: mov ebx, ss:[ebp+0x8]
         // 00405ce4: mov ss:[ebp+0xfffffffffffffff0], eax
         // 00405ce7: mov ecx, ds:[eax]
         // 00405ce9: and ds:[eax], 0x0
         // 00405cec: mov eax, ss:[ebp+0xc]
         // 00405cef: mov ss:[ebp+0xfffffffffffffff8], ecx
         // 00405cf2: lea eax, ds:[ebx+eax*0x2]
         // 00405cf5: mov ss:[ebp+0xfffffffffffffff4], eax
         // 00405cf8: cmp ebx, eax
         // 00405cfa: jz 0x405d4b
      [-]578b7d10
         // 00405cfc: push edi
         // 00405cfd: mov edi, ss:[ebp+0x10]
      [-]0fb7038bca50e8bbfeffff84c07521
         // 00405d00: movzx eax, b2 ds:[ebx]
         // 00405d03: mov ecx, edx
         // 00405d05: push eax
         // 00405d06: call ?write_character_without_count_update@?$stream_output_adapter@_W@__crt_stdio_output@@QBE_N_W@Z
         // 00405d0b: test b1 al, b1 al
         // 00405d0d: jnz 0x405d30
      [-]833e007507
         // 00405d0f: cmp ds:[esi], 0x0
         // 00405d12: jnz 0x405d1b
      [-]e8b71f00008906
         // 00405d14: call __errno
         // 00405d19: mov ds:[esi], eax
      [-]8b0683382a7522
         // 00405d1b: mov eax, ds:[esi]
         // 00405d1d: cmp ds:[eax], 0x2a
         // 00405d20: jnz 0x405d44
      [-]8b4dfc6a3fe89afeffff84c07404
         // 00405d22: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 00405d25: push 0x3f
         // 00405d27: call ?write_character_without_count_update@?$stream_output_adapter@_W@__crt_stdio_output@@QBE_N_W@Z
         // 00405d2c: test b1 al, b1 al
         // 00405d2e: jz 0x405d34
      [-]ff07eb03
         // 00405d30: inc ds:[edi]
         // 00405d32: jmp 0x405d37
      [-]8b55fc83c3023b5df475be
         // 00405d37: mov edx, ss:[ebp+0xfffffffffffffffc]
         // 00405d3a: add ebx, 0x2
         // 00405d3d: cmp ebx, ss:[ebp+0xfffffffffffffff4]
         // 00405d40: jnz 0x405d00
      [-]8b4df85f
         // 00405d47: mov ecx, ss:[ebp+0xfffffffffffffff8]
         // 00405d4a: pop edi
      [-]8b45f05e5b8338007506
         // 00405d4b: mov eax, ss:[ebp+0xfffffffffffffff0]
         // 00405d4e: pop esi
         // 00405d4f: pop ebx
         // 00405d50: cmp ds:[eax], 0x0
         // 00405d53: jnz 0x405d5b
      [-]85c97402
         // 00405d55: test ecx, ecx
         // 00405d57: jz 0x405d5b
      [-]8be55dc21000
         // 00405d5b: mov esp, ebp
         // 00405d5d: pop ebp
         // 00405d5e: retn b2 0x10
      [-]8bff558bec83ec388b451c8b4d108b55148945ec8b45188945f48b45088945dc8b450c8955f0894df88945e085c97515
         // 00405d61: mov edi, edi
         // 00405d63: push ebp
         // 00405d64: mov ebp, esp
         // 00405d66: sub esp, 0x38
         // 00405d69: mov eax, ss:[ebp+0x1c]
         // 00405d6c: mov ecx, ss:[ebp+0x10]
         // 00405d6f: mov edx, ss:[ebp+0x14]
         // 00405d72: mov ss:[ebp+0xffffffffffffffec], eax
         // 00405d75: mov eax, ss:[ebp+0x18]
         // 00405d78: mov ss:[ebp+0xfffffffffffffff4], eax
         // 00405d7b: mov eax, ss:[ebp+0x8]
         // 00405d7e: mov ss:[ebp+0xffffffffffffffdc], eax
         // 00405d81: mov eax, ss:[ebp+0xc]
         // 00405d84: mov ss:[ebp+0xfffffffffffffff0], edx
         // 00405d87: mov ss:[ebp+0xfffffffffffffff8], ecx
         // 00405d8a: mov ss:[ebp+0xffffffffffffffe0], eax
         // 00405d8d: test ecx, ecx
         // 00405d8f: jnz 0x405da6
      [-]e83a1f0000c700????????e8721e000083c8ffeb3c
         // 00405d91: call __errno
         // 00405d96: mov ds:[eax], 0x16
         // 00405d9c: call __invalid_parameter_noinfo
         // 00405da1: or eax, 0xffffffffffffffff
         // 00405da4: jmp 0x405de2
      [-]85d274e7
         // 00405da6: test edx, edx
         // 00405da8: jz 0x405d91
      [-]8d45f8894de88945c88d45f48945cc8d45dc8945d08d45f08945d48d45ec8945d88d45e8508d45c8894de4508d45e4508d4dffe8bfebffff
         // 00405daa: lea eax, ss:[ebp+0xfffffffffffffff8]
         // 00405dad: mov ss:[ebp+0xffffffffffffffe8], ecx
         // 00405db0: mov ss:[ebp+0xffffffffffffffc8], eax
         // 00405db3: lea eax, ss:[ebp+0xfffffffffffffff4]
         // 00405db6: mov ss:[ebp+0xffffffffffffffcc], eax
         // 00405db9: lea eax, ss:[ebp+0xffffffffffffffdc]
         // 00405dbc: mov ss:[ebp+0xffffffffffffffd0], eax
         // 00405dbf: lea eax, ss:[ebp+0xfffffffffffffff0]
         // 00405dc2: mov ss:[ebp+0xffffffffffffffd4], eax
         // 00405dc5: lea eax, ss:[ebp+0xffffffffffffffec]
         // 00405dc8: mov ss:[ebp+0xffffffffffffffd8], eax
         // 00405dcb: lea eax, ss:[ebp+0xffffffffffffffe8]
         // 00405dce: push eax
         // 00405dcf: lea eax, ss:[ebp+0xffffffffffffffc8]
         // 00405dd2: mov ss:[ebp+0xffffffffffffffe4], ecx
         // 00405dd5: push eax
         // 00405dd6: lea eax, ss:[ebp+0xffffffffffffffe4]
         // 00405dd9: push eax
         // 00405dda: lea ecx, ss:[ebp+0xffffffffffffffff]
         // 00405ddd: call ??$?RV_lambda_11b4f7b0d3157825a5656a18eba1ae27_@@AAV_lambda_b51c0495177f500e782686251704ae76_@@V_lambda_cf89b47920b5017557bfe891e78aca36_@@@?$__crt_seh_guarded_call@I@@QAEI$$QAV_lambda_11b4f7b0d3157825a5656a18eba1ae27_@@AAV_lambda_b51c0495177f500e782686251704ae76_@@$$QAV_lambda_cf89b47920b5017557bfe891e78aca36_@@@Z
      [-]8be55dc3
         // 00405de2: mov esp, ebp
         // 00405de4: pop ebp
         // 00405de5: retn 
      [-]8bff558bec8b4508a3????????5dc3
         // 00405de6: mov edi, edi
         // 00405de8: push ebp
         // 00405de9: mov ebp, esp
         // 00405deb: mov eax, ss:[ebp+0x8]
         // 00405dee: mov ds:[0x43ac78], eax
         // 00405df3: pop ebp
         // 00405df4: retn 
      [-]a1????????c3
         // 00406009: mov eax, ds:[0x43ac7c]
         // 0040600e: retn 
      [-]8bff558bec8b4508a3????????5dc3
         // 0040600f: mov edi, edi
         // 00406011: push ebp
         // 00406012: mov ebp, esp
         // 00406014: mov eax, ss:[ebp+0x8]
         // 00406017: mov ds:[0x43ac7c], eax
         // 0040601c: pop ebp
         // 0040601d: retn 
      [-]8bff558bec8b4508a3????????5dc3
         // 00406055: mov edi, edi
         // 00406057: push ebp
         // 00406058: mov ebp, esp
         // 0040605a: mov eax, ss:[ebp+0x8]
         // 0040605d: mov ds:[0x43ac80], eax
         // 00406062: pop ebp
         // 00406063: retn 
      [-]833d????????007403
         // 004063d2: cmp ds:[0x43ae98], 0x0
         // 004063d9: jz 0x4063de
      [-]5657e89b4a00008bf085
         // 004063de: push esi
         // 004063df: push edi
         // 004063e0: call ___dcrt_get_wide_environment_from_os
         // 004063e5: mov esi, eax
         // 004063e7: test esi, esi
         // 004063e9: jnz 0x4063f0

  }
  condition:
    all of them
}
