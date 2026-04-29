rule cosmicduke_10_3 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         558bec518b45080fb700535750ff1598f341000fb7c033ff8945fc39be????????7e2b
         // 00401000: push ebp
         // 00401001: mov ebp, esp
         // 00401003: push ecx
         // 00401004: mov eax, ss:[ebp+0x8]
         // 00401007: movzx eax, b2 ds:[eax]
         // 0040100a: push ebx
         // 0040100b: push edi
         // 0040100c: push eax
         // 0040100d: call ds:[CharLowerW]
         // 00401013: movzx eax, b2 ax
         // 00401016: xor edi, edi
         // 00401018: mov ss:[ebp+0xfffffffffffffffc], eax
         // 0040101b: cmp ds:[esi+0x880], edi
         // 00401021: jle 0x40104e
      [-]668b45fc663943fe7512
         // 00401026: mov b2 ax, b2 ss:[ebp+0xfffffffffffffffc]
         // 0040102a: cmp b2 ds:[ebx+0xfffffffffffffffe], b2 ax
         // 0040102e: jnz 0x401042
      [-]8b45085383c00250ff15b8f2410085c07414
         // 00401030: mov eax, ss:[ebp+0x8]
         // 00401033: push ebx
         // 00401034: add eax, 0x2
         // 00401037: push eax
         // 00401038: call ds:[lstrcmpiW]
         // 0040103e: test eax, eax
         // 00401040: jz 0x401056
      [-]4783c3443bbe????????7cd8
         // 00401042: inc edi
         // 00401043: add ebx, 0x44
         // 00401046: cmp edi, ds:[esi+0x880]
         // 0040104c: jl 0x401026
      [-]5f5bc9c20400
         // 00401050: pop edi
         // 00401051: pop ebx
         // 00401052: leave 
         // 00401053: retn b2 0x4
      [-]6bff448b0437ebf2
         // 00401056: imul edi, b1 0x44
         // 00401059: mov eax, ds:[edi+esi]
         // 0040105c: jmp 0x401050
      [-]85ff743a
         // 0040105e: test edi, edi
         // 00401060: jz 0x40109c
      [-]837c2404007433
         // 00401062: cmp ss:[esp+0x4], 0x0
         // 00401067: jz 0x40109c
      [-]8b86????????83f8207428
         // 00401069: mov eax, ds:[esi+0x880]
         // 0040106f: cmp eax, 0x20
         // 00401072: jz 0x40109c
      [-]6bc0446a1fff7424088d44300450ff15c0f2410085c08b86????????750f
         // 00401074: imul eax, b1 0x44
         // 00401077: push 0x1f
         // 00401079: push ss:[esp+0x8]
         // 0040107d: lea eax, ds:[eax+esi+0x4]
         // 00401081: push eax
         // 00401082: call ds:[lstrcpynW]
         // 00401088: test eax, eax
         // 0040108a: mov eax, ds:[esi+0x880]
         // 00401090: jnz 0x4010a1
      [-]6bc04433c966894c3004
         // 00401092: imul eax, b1 0x44
         // 00401095: xor ecx, ecx
         // 00401097: mov b2 ds:[eax+esi+0x4], b2 cx
      [-]6bc0448d44300450ff1598f341008b86????????6bc044893c30ff86????????b001ebd9
         // 004010a1: imul eax, b1 0x44
         // 004010a4: lea eax, ds:[eax+esi+0x4]
         // 004010a8: push eax
         // 004010a9: call ds:[CharLowerW]
         // 004010af: mov eax, ds:[esi+0x880]
         // 004010b5: imul eax, b1 0x44
         // 004010b8: mov ds:[eax+esi], edi
         // 004010bb: inc ds:[esi+0x880]
         // 004010c1: mov b1 al, b1 0x1
         // 004010c3: jmp 0x40109e
      [-]85db7504
         // 004010c5: test ebx, ebx
         // 004010c7: jnz 0x4010cd
      [-]33c0eb34
         // 004010c9: xor eax, eax
         // 004010cb: jmp 0x401101
      [-]56578db1????????53e825ffffff8bf885ff7513
         // 004010cd: push esi
         // 004010ce: push edi
         // 004010cf: lea esi, ds:[ecx+0x4f04]
         // 004010d5: push ebx
         // 004010d6: call 0x401000
         // 004010db: mov edi, eax
         // 004010dd: test edi, edi
         // 004010df: jnz 0x4010f4
      [-]53ff15e8f141008bf885ff7416
         // 004010e1: push ebx
         // 004010e2: call ds:[LoadLibraryW]
         // 004010e8: mov edi, eax
         // 004010ea: test edi, edi
         // 004010ec: jz 0x401104
      [-]53e86affffff
         // 004010ee: push ebx
         // 004010ef: call 0x40105e
      [-]ff74240c57ff15bcf24100
         // 004010f4: push ss:[esp+0xc]
         // 004010f8: push edi
         // 004010f9: call ds:[GetProcAddress]
      [-]33c0ebf7
         // 00401104: xor eax, eax
         // 00401106: jmp 0x4010ff
      [-]b8????????e8da87010056578b7d088d7704e8f24b00008365fc008d7714e8e64b0000c645fc01e89e04000033c0668907834dfcff8b4df48bc75f64890d????????5ec9c20400
         // 00401108: mov eax, 0x41d8e5
         // 0040110d: call __EH_prolog
         // 00401112: push esi
         // 00401113: push edi
         // 00401114: mov edi, ss:[ebp+0x8]
         // 00401117: lea esi, ds:[edi+0x4]
         // 0040111a: call 0x405d11
         // 0040111f: and ss:[ebp+0xfffffffffffffffc], 0x0
         // 00401123: lea esi, ds:[edi+0x14]
         // 00401126: call 0x405d11
         // 0040112b: mov b1 ss:[ebp+0xfffffffffffffffc], b1 0x1
         // 0040112f: call 0x4015d2
         // 00401134: xor eax, eax
         // 00401136: mov b2 ds:[edi], b2 ax
         // 00401139: or ss:[ebp+0xfffffffffffffffc], 0xffffffffffffffff
         // 0040113d: mov ecx, ss:[ebp+0xfffffffffffffff4]
         // 00401140: mov eax, edi
         // 00401142: pop edi
         // 00401143: mov fs:[0x0], ecx
         // 0040114a: pop esi
         // 0040114b: leave 
         // 0040114c: retn b2 0x4
      [-]b8????????e89387010056578b7d088365fc008d7714e8c24d0000834dfcff8d7704e8b64d00008b4df45f64890d????????5ec9c20400
         // 0040114f: mov eax, 0x41d8e5
         // 00401154: call __EH_prolog
         // 00401159: push esi
         // 0040115a: push edi
         // 0040115b: mov edi, ss:[ebp+0x8]
         // 0040115e: and ss:[ebp+0xfffffffffffffffc], 0x0
         // 00401162: lea esi, ds:[edi+0x14]
         // 00401165: call 0x405f2c
         // 0040116a: or ss:[ebp+0xfffffffffffffffc], 0xffffffffffffffff
         // 0040116e: lea esi, ds:[edi+0x4]
         // 00401171: call 0x405f2c
         // 00401176: mov ecx, ss:[ebp+0xfffffffffffffff4]
         // 00401179: pop edi
         // 0040117a: mov fs:[0x0], ecx
         // 00401181: pop esi
         // 00401182: leave 
         // 00401183: retn b2 0x4
      [-]558bec8b550883ec105685d2744d
         // 00401186: push ebp
         // 00401187: mov ebp, esp
         // 00401189: mov edx, ss:[ebp+0x8]
         // 0040118c: sub esp, 0x10
         // 0040118f: push esi
         // 00401190: test edx, edx
         // 00401192: jz 0x4011e1
      [-]85c07449
         // 00401194: test eax, eax
         // 00401196: jz 0x4011e1
      [-]85db7445
         // 00401198: test ebx, ebx
         // 0040119a: jz 0x4011e1
      [-]8955f0884df48945f580f901761d
         // 0040119c: mov ss:[ebp+0xfffffffffffffff0], edx
         // 0040119f: mov b1 ss:[ebp+0xfffffffffffffff4], b1 cl
         // 004011a2: mov ss:[ebp+0xfffffffffffffff5], eax
         // 004011a5: cmp b1 cl, b1 0x1
         // 004011a8: jbe 0x4011c7
      [-]80f9047605
         // 004011aa: cmp b1 cl, b1 0x4
         // 004011ad: jbe 0x4011b4
      [-]80f905762d
         // 004011af: cmp b1 cl, b1 0x5
         // 004011b2: jbe 0x4011e1
      [-]8b77186a00538d4f14e8fc4e00008975f9eb05
         // 004011b4: mov esi, ds:[edi+0x18]
         // 004011b7: push 0x0
         // 004011b9: push ebx
         // 004011ba: lea ecx, ds:[edi+0x14]
         // 004011bd: call 0x4060be
         // 004011c2: mov ss:[ebp+0xfffffffffffffff9], esi
         // 004011c5: jmp 0x4011cc
      [-]8b038945f9
         // 004011c7: mov eax, ds:[ebx]
         // 004011c9: mov ss:[ebp+0xfffffffffffffff9], eax
      [-]6a008d45f0506a0d8d4f0458e8e14e0000b001eb02
         // 004011cc: push 0x0
         // 004011ce: lea eax, ss:[ebp+0xfffffffffffffff0]
         // 004011d1: push eax
         // 004011d2: push 0xd
         // 004011d4: lea ecx, ds:[edi+0x4]
         // 004011d7: pop eax
         // 004011d8: call 0x4060be
         // 004011dd: mov b1 al, b1 0x1
         // 004011df: jmp 0x4011e3
      [-]5ec9c20400
         // 004011e3: pop esi
         // 004011e4: leave 
         // 004011e5: retn b2 0x4
      [-]51538bd985db7413
         // 004011e8: push ecx
         // 004011e9: push ebx
         // 004011ea: mov ebx, ecx
         // 004011ec: test ebx, ebx
         // 004011ee: jz 0x401203
      [-]85c0740f
         // 004011f0: test eax, eax
         // 004011f2: jz 0x401203
      [-]ff74240c03c0b106e885ffffffeb02
         // 004011f4: push ss:[esp+0xc]
         // 004011f8: add eax, eax
         // 004011fa: mov b1 cl, b1 0x6
         // 004011fc: call 0x401186
         // 00401201: jmp 0x401205
      [-]5b59c20400
         // 00401205: pop ebx
         // 00401206: pop ecx
         // 00401207: retn b2 0x4
      [-]b8????????e8d886010083ec185356578965f08bf18bda33ff897dec897de48b430833d26a0d59f7f18945e03bc77f07
         // 0040120a: mov eax, 0x41d9b2
         // 0040120f: call __EH_prolog
         // 00401214: sub esp, 0x18
         // 00401217: push ebx
         // 00401218: push esi
         // 00401219: push edi
         // 0040121a: mov ss:[ebp+0xfffffffffffffff0], esp
         // 0040121d: mov esi, ecx
         // 0040121f: mov ebx, edx
         // 00401221: xor edi, edi
         // 00401223: mov ss:[ebp+0xffffffffffffffec], edi
         // 00401226: mov ss:[ebp+0xffffffffffffffe4], edi
         // 00401229: mov eax, ds:[ebx+0x8]
         // 0040122c: xor edx, edx
         // 0040122e: push 0xd
         // 00401230: pop ecx
         // 00401231: div ecx
         // 00401233: mov ss:[ebp+0xffffffffffffffe0], eax
         // 00401236: cmp eax, edi
         // 00401238: jg 0x401241
      [-]32c0e9cf000000
         // 0040123a: xor b1 al, b1 al
         // 0040123c: jmp 0x401310
      [-]e8f84c0000834de8ff578d45e8506a04588bcee8654e0000897dfc
         // 00401241: call 0x405f3e
         // 00401246: or ss:[ebp+0xffffffffffffffe8], 0xffffffffffffffff
         // 0040124a: push edi
         // 0040124b: lea eax, ss:[ebp+0xffffffffffffffe8]
         // 0040124e: push eax
         // 0040124f: push 0x4
         // 00401251: pop eax
         // 00401252: mov ecx, esi
         // 00401254: call 0x4060be
         // 00401259: mov ss:[ebp+0xfffffffffffffffc], edi
      [-]8b7de43b7de00f8d8c000000
         // 0040125c: mov edi, ss:[ebp+0xffffffffffffffe4]
         // 0040125f: cmp edi, ss:[ebp+0xffffffffffffffe0]
         // 00401262: jge 0x4012f4
      [-]6bff0d037b048b460483c0045056e8484f00006a00576a0d588bcee8364e0000ff45ec8a47043c017611
         // 00401268: imul edi, b1 0xd
         // 0040126b: add edi, ds:[ebx+0x4]
         // 0040126e: mov eax, ds:[esi+0x4]
         // 00401271: add eax, 0x4
         // 00401274: push eax
         // 00401275: push esi
         // 00401276: call 0x4061c3
         // 0040127b: push 0x0
         // 0040127d: push edi
         // 0040127e: push 0xd
         // 00401280: pop eax
         // 00401281: mov ecx, esi
         // 00401283: call 0x4060be
         // 00401288: inc ss:[ebp+0xffffffffffffffec]
         // 0040128b: mov b1 al, b1 ds:[edi+0x4]
         // 0040128e: cmp b1 al, b1 0x1
         // 00401290: jbe 0x4012a3
      [-]3c047649
         // 00401292: cmp b1 al, b1 0x4
         // 00401294: jbe 0x4012df
      [-]3c05740e
         // 00401296: cmp b1 al, b1 0x5
         // 00401298: jz 0x4012a8
      [-]3c08763f
         // 0040129c: cmp b1 al, b1 0x8
         // 0040129e: jbe 0x4012df
      [-]ff45e4ebb4
         // 004012a3: inc ss:[ebp+0xffffffffffffffe4]
         // 004012a6: jmp 0x40125c
      [-]8b47098945e885c074ee
         // 004012a8: mov eax, ds:[edi+0x9]
         // 004012ab: mov ss:[ebp+0xffffffffffffffe8], eax
         // 004012ae: test eax, eax
         // 004012b0: jz 0x4012a0
      [-]ff770550ff15b4f2410085c0740e
         // 004012b2: push ds:[edi+0x5]
         // 004012b5: push eax
         // 004012b6: call ds:[IsBadReadPtr]
         // 004012bc: test eax, eax
         // 004012be: jz 0x4012ce
      [-]ff75e8e87f1e010059ebd5
         // 004012c3: push ss:[ebp+0xffffffffffffffe8]
         // 004012c6: call ??3@YAXPAX@Z
         // 004012cb: pop ecx
         // 004012cc: jmp 0x4012a3
      [-]6a00ff75e88b47058bcee8e14d0000ebe4
         // 004012ce: push 0x0
         // 004012d0: push ss:[ebp+0xffffffffffffffe8]
         // 004012d3: mov eax, ds:[edi+0x5]
         // 004012d6: mov ecx, esi
         // 004012d8: call 0x4060be
         // 004012dd: jmp 0x4012c3
      [-]6a008b4f09034b14518b47058bcee8cc4d0000ebaf
         // 004012df: push 0x0
         // 004012e1: mov ecx, ds:[edi+0x9]
         // 004012e4: add ecx, ds:[ebx+0x14]
         // 004012e7: push ecx
         // 004012e8: mov eax, ds:[edi+0x5]
         // 004012eb: mov ecx, esi
         // 004012ed: call 0x4060be
         // 004012f2: jmp 0x4012a3
      [-]ff75ec56e8c64e00008b460483c0045056e8b94e0000834dfcffb001
         // 004012f4: push ss:[ebp+0xffffffffffffffec]
         // 004012f7: push esi
         // 004012f8: call 0x4061c3
         // 004012fd: mov eax, ds:[esi+0x4]
         // 00401300: add eax, 0x4
         // 00401303: push eax
         // 00401304: push esi
         // 00401305: call 0x4061c3
         // 0040130a: or ss:[ebp+0xfffffffffffffffc], 0xffffffffffffffff
         // 0040130e: mov b1 al, b1 0x1
      [-]8b4df464890d????????5f5e5bc9c3
         // 00401310: mov ecx, ss:[ebp+0xfffffffffffffff4]
         // 00401313: mov fs:[0x0], ecx
         // 0040131a: pop edi
         // 0040131b: pop esi
         // 0040131c: pop ebx
         // 0040131d: leave 
         // 0040131e: retn 
      [-]558bec83ec2856578b7d088b470433d26a0d59f7f133d28bf08d46ff8975ec85c00f8e97000000
         // 00401329: push ebp
         // 0040132a: mov ebp, esp
         // 0040132c: sub esp, 0x28
         // 0040132f: push esi
         // 00401330: push edi
         // 00401331: mov edi, ss:[ebp+0x8]
         // 00401334: mov eax, ds:[edi+0x4]
         // 00401337: xor edx, edx
         // 00401339: push 0xd
         // 0040133b: pop ecx
         // 0040133c: div ecx
         // 0040133e: xor edx, edx
         // 00401340: mov esi, eax
         // 00401342: lea eax, ds:[esi+0xffffffffffffffff]
         // 00401345: mov ss:[ebp+0xffffffffffffffec], esi
         // 00401348: test eax, eax
         // 0040134a: jle 0x4013e7
      [-]8bca6bc90d030f8955f842894de88955f03bd67d71
         // 00401351: mov ecx, edx
         // 00401353: imul ecx, b1 0xd
         // 00401356: add ecx, ds:[edi]
         // 00401358: mov ss:[ebp+0xfffffffffffffff8], edx
         // 0040135b: inc edx
         // 0040135c: mov ss:[ebp+0xffffffffffffffe8], ecx
         // 0040135f: mov ss:[ebp+0xfffffffffffffff0], edx
         // 00401362: cmp edx, esi
         // 00401364: jge 0x4013d7
      [-]8bc26bc00d8945f4894dfc
         // 00401366: mov eax, edx
         // 00401368: imul eax, b1 0xd
         // 0040136b: mov ss:[ebp+0xfffffffffffffff4], eax
         // 0040136e: mov ss:[ebp+0xfffffffffffffffc], ecx
      [-]8b1f035df48b033b01754c
         // 00401371: mov ebx, ds:[edi]
         // 00401373: add ebx, ss:[ebp+0xfffffffffffffff4]
         // 00401376: mov eax, ds:[ebx]
         // 00401378: cmp eax, ds:[ecx]
         // 0040137a: jnz 0x4013c8
      [-]8a43043a41047544
         // 0040137c: mov b1 al, b1 ds:[ebx+0x4]
         // 0040137f: cmp b1 al, b1 ds:[ecx+0x4]
         // 00401382: jnz 0x4013c8
      [-]ff45f88345fc0d3b55f87438
         // 00401384: inc ss:[ebp+0xfffffffffffffff8]
         // 00401387: add ss:[ebp+0xfffffffffffffffc], 0xd
         // 0040138b: cmp edx, ss:[ebp+0xfffffffffffffff8]
         // 0040138e: jz 0x4013c8
      [-]8b75fc8d7dd8a5a56a0da553ff75fca4e8bb1901008b45d88b7d088b75ec8b4de889038b45e18943098b45dd8943058a45dc83c40c884304
         // 00401390: mov esi, ss:[ebp+0xfffffffffffffffc]
         // 00401393: lea edi, ss:[ebp+0xffffffffffffffd8]
         // 00401396: movsdd 
         // 00401397: movsdd 
         // 00401398: push 0xd
         // 0040139a: movsdd 
         // 0040139b: push ebx
         // 0040139c: push ss:[ebp+0xfffffffffffffffc]
         // 0040139f: movsbb 
         // 004013a0: call _memcpy
         // 004013a5: mov eax, ss:[ebp+0xffffffffffffffd8]
         // 004013a8: mov edi, ss:[ebp+0x8]
         // 004013ab: mov esi, ss:[ebp+0xffffffffffffffec]
         // 004013ae: mov ecx, ss:[ebp+0xffffffffffffffe8]
         // 004013b1: mov ds:[ebx], eax
         // 004013b3: mov eax, ss:[ebp+0xffffffffffffffe1]
         // 004013b6: mov ds:[ebx+0x9], eax
         // 004013b9: mov eax, ss:[ebp+0xffffffffffffffdd]
         // 004013bc: mov ds:[ebx+0x5], eax
         // 004013bf: mov b1 al, b1 ss:[ebp+0xffffffffffffffdc]
         // 004013c2: add esp, 0xc
         // 004013c5: mov b1 ds:[ebx+0x4], b1 al
      [-]8b55f08345f40d428955f03bd67c9a
         // 004013c8: mov edx, ss:[ebp+0xfffffffffffffff0]
         // 004013cb: add ss:[ebp+0xfffffffffffffff4], 0xd
         // 004013cf: inc edx
         // 004013d0: mov ss:[ebp+0xfffffffffffffff0], edx
         // 004013d3: cmp edx, esi
         // 004013d5: jl 0x401371
      [-]8b55f8428d46ff3bd00f8c6bffffff
         // 004013d7: mov edx, ss:[ebp+0xfffffffffffffff8]
         // 004013da: inc edx
         // 004013db: lea eax, ds:[esi+0xffffffffffffffff]
         // 004013de: cmp edx, eax
         // 004013e0: jl 0x401351
      [-]5fb0015ec9c20400
         // 004013e7: pop edi
         // 004013e8: mov b1 al, b1 0x1
         // 004013ea: pop esi
         // 004013eb: leave 
         // 004013ec: retn b2 0x4
      [-]558bec83ec208b48048365f400565785c90f8413010000
         // 004013ef: push ebp
         // 004013f0: mov ebp, esp
         // 004013f2: sub esp, 0x20
         // 004013f5: mov ecx, ds:[eax+0x4]
         // 004013f8: and ss:[ebp+0xfffffffffffffff4], 0x0
         // 004013fc: push esi
         // 004013fd: push edi
         // 004013fe: test ecx, ecx
         // 00401400: jz 0x401519
      [-]8b388b07897de83bc17e07
         // 00401406: mov edi, ds:[eax]
         // 00401408: mov eax, ds:[edi]
         // 0040140a: mov ss:[ebp+0xffffffffffffffe8], edi
         // 0040140d: cmp eax, ecx
         // 0040140f: jle 0x401418
      [-]32c0e903010000
         // 00401411: xor b1 al, b1 al
         // 00401413: jmp 0x40151b
      [-]83c0f883c7088d73048945fc897df8897de48975f0e80c4b00008d7314e8044b00008b45e8837804000f8eca000000
         // 00401418: add eax, 0xfffffffffffffff8
         // 0040141b: add edi, 0x8
         // 0040141e: lea esi, ds:[ebx+0x4]
         // 00401421: mov ss:[ebp+0xfffffffffffffffc], eax
         // 00401424: mov ss:[ebp+0xfffffffffffffff8], edi
         // 00401427: mov ss:[ebp+0xffffffffffffffe4], edi
         // 0040142a: mov ss:[ebp+0xfffffffffffffff0], esi
         // 0040142d: call 0x405f3e
         // 00401432: lea esi, ds:[ebx+0x14]
         // 00401435: call 0x405f3e
         // 0040143a: mov eax, ss:[ebp+0xffffffffffffffe8]
         // 0040143d: cmp ds:[eax+0x4], 0x0
         // 00401441: jle 0x401511
      [-]8b75f88b0683f8ff0f84bc000000
         // 00401447: mov esi, ss:[ebp+0xfffffffffffffff8]
         // 0040144a: mov eax, ds:[esi]
         // 0040144c: cmp eax, 0xffffffffffffffff
         // 0040144f: jz 0x401511
      [-]837dfc000f86b2000000
         // 00401455: cmp ss:[ebp+0xfffffffffffffffc], 0x0
         // 00401459: jbe 0x401511
      [-]8b55fc6a0d2bd0593bd172a6
         // 0040145f: mov edx, ss:[ebp+0xfffffffffffffffc]
         // 00401462: push 0xd
         // 00401464: sub edx, eax
         // 00401466: pop ecx
         // 00401467: cmp edx, ecx
         // 00401469: jb 0x401411
      [-]8b55e43b02777e
         // 0040146b: mov edx, ss:[ebp+0xffffffffffffffe4]
         // 0040146e: cmp eax, ds:[edx]
         // 00401470: ja 0x4014f0
      [-]03f88a4704894dec3c01764d
         // 00401472: add edi, eax
         // 00401474: mov b1 al, b1 ds:[edi+0x4]
         // 00401477: mov ss:[ebp+0xffffffffffffffec], ecx
         // 0040147a: cmp b1 al, b1 0x1
         // 0040147c: jbe 0x4014cb
      [-]3c047610
         // 0040147e: cmp b1 al, b1 0x4
         // 00401480: jbe 0x401492
      [-]3c057408
         // 00401482: cmp b1 al, b1 0x5
         // 00401484: jz 0x40148e
      [-]3c087606
         // 00401488: cmp b1 al, b1 0x8
         // 0040148a: jbe 0x401492
      [-]c6470406
         // 0040148e: mov b1 ds:[edi+0x4], b1 0x6
      [-]8b47058b168d480d03d1894dec3b55fc7734
         // 00401492: mov eax, ds:[edi+0x5]
         // 00401495: mov edx, ds:[esi]
         // 00401497: lea ecx, ds:[eax+0xd]
         // 0040149a: add edx, ecx
         // 0040149c: mov ss:[ebp+0xffffffffffffffec], ecx
         // 0040149f: cmp edx, ss:[ebp+0xfffffffffffffffc]
         // 004014a2: ja 0x4014d8
      [-]8b73186a008d4f0d518d4b14e8094c00008b4df06a00576a0d58897709e8f84b00008b75f8eb0d
         // 004014a4: mov esi, ds:[ebx+0x18]
         // 004014a7: push 0x0
         // 004014a9: lea ecx, ds:[edi+0xd]
         // 004014ac: push ecx
         // 004014ad: lea ecx, ds:[ebx+0x14]
         // 004014b0: call 0x4060be
         // 004014b5: mov ecx, ss:[ebp+0xfffffffffffffff0]
         // 004014b8: push 0x0
         // 004014ba: push edi
         // 004014bb: push 0xd
         // 004014bd: pop eax
         // 004014be: mov ds:[edi+0x9], esi
         // 004014c1: call 0x4060be
         // 004014c6: mov esi, ss:[ebp+0xfffffffffffffff8]
         // 004014c9: jmp 0x4014d8
      [-]6a008bc18b4df057e8e64b0000
         // 004014cb: push 0x0
         // 004014cd: mov eax, ecx
         // 004014cf: mov ecx, ss:[ebp+0xfffffffffffffff0]
         // 004014d2: push edi
         // 004014d3: call 0x4060be
      [-]807f04067512
         // 004014d8: cmp b1 ds:[edi+0x4], b1 0x6
         // 004014dc: jnz 0x4014f0
      [-]6a0068????????6a02588d4b14e8ce4b0000
         // 004014de: push 0x0
         // 004014e0: push 0x4213f8
         // 004014e5: push 0x2
         // 004014e7: pop eax
         // 004014e8: lea ecx, ds:[ebx+0x14]
         // 004014eb: call 0x4060be
      [-]6afc582b45ec8d7e040145fcff45f48b45e88b4df4897df83b48040f8c36ffffff
         // 004014f0: push 0xfffffffffffffffc
         // 004014f2: pop eax
         // 004014f3: sub eax, ss:[ebp+0xffffffffffffffec]
         // 004014f6: lea edi, ds:[esi+0x4]
         // 004014f9: add ss:[ebp+0xfffffffffffffffc], eax
         // 004014fc: inc ss:[ebp+0xfffffffffffffff4]
         // 004014ff: mov eax, ss:[ebp+0xffffffffffffffe8]
         // 00401502: mov ecx, ss:[ebp+0xfffffffffffffff4]
         // 00401505: mov ss:[ebp+0xfffffffffffffff8], edi
         // 00401508: cmp ecx, ds:[eax+0x4]
         // 0040150b: jl 0x401447
      [-]ff75f0e810feffff
         // 00401511: push ss:[ebp+0xfffffffffffffff0]
         // 00401514: call 0x401329
      [-]5f5ec9c3
         // 0040151b: pop edi
         // 0040151c: pop esi
         // 0040151d: leave 
         // 0040151e: retn 
      [-]558bec83ec0c5333c056578945f88845ff8b45088b308b41086a0d33d25bf7f333ff85c07e30
         // 0040151f: push ebp
         // 00401520: mov ebp, esp
         // 00401522: sub esp, 0xc
         // 00401525: push ebx
         // 00401526: xor eax, eax
         // 00401528: push esi
         // 00401529: push edi
         // 0040152a: mov ss:[ebp+0xfffffffffffffff8], eax
         // 0040152d: mov b1 ss:[ebp+0xffffffffffffffff], b1 al
         // 00401530: mov eax, ss:[ebp+0x8]
         // 00401533: mov esi, ds:[eax]
         // 00401535: mov eax, ds:[ecx+0x8]
         // 00401538: push 0xd
         // 0040153a: xor edx, edx
         // 0040153c: pop ebx
         // 0040153d: div ebx
         // 0040153f: xor edi, edi
         // 00401541: test eax, eax
         // 00401543: jle 0x401575
      [-]8b49048bd7
         // 00401545: mov ecx, ds:[ecx+0x4]
         // 00401548: mov edx, edi
      [-]3b317514
         // 0040154a: cmp esi, ds:[ecx]
         // 0040154c: jnz 0x401562
      [-]8a5d0c3a5904750c
         // 0040154e: mov b1 bl, b1 ss:[ebp+0xc]
         // 00401551: cmp b1 bl, b1 ds:[ecx+0x4]
         // 00401554: jnz 0x401562
      [-]423955107416
         // 00401556: inc edx
         // 00401557: cmp ss:[ebp+0x10], edx
         // 0040155a: jz 0x401572
      [-]c645ff01eb06
         // 0040155c: mov b1 ss:[ebp+0xffffffffffffffff], b1 0x1
         // 00401560: jmp 0x401568
      [-]807dff00750d
         // 00401562: cmp b1 ss:[ebp+0xffffffffffffffff], b1 0x0
         // 00401566: jnz 0x401575
      [-]4783c10d3bf87cda
         // 00401568: inc edi
         // 00401569: add ecx, 0xd
         // 0040156c: cmp edi, eax
         // 0040156e: jl 0x40154a
      [-]8b45f85f5e5bc9c20c00
         // 00401575: mov eax, ss:[ebp+0xfffffffffffffff8]
         // 00401578: pop edi
         // 00401579: pop esi
         // 0040157a: pop ebx
         // 0040157b: leave 
         // 0040157c: retn b2 0xc
      [-]830eff6a016a01ff74240ce890ffffff85c07504
         // 0040157f: or ds:[esi], 0xffffffffffffffff
         // 00401582: push 0x1
         // 00401584: push 0x1
         // 00401586: push ss:[esp+0xc]
         // 0040158a: call 0x40151f
         // 0040158f: test eax, eax
         // 00401591: jnz 0x401597
      [-]32c0eb12
         // 00401593: xor b1 al, b1 al
         // 00401595: jmp 0x4015a9
      [-]837805047405
         // 00401597: cmp ds:[eax+0x5], 0x4
         // 0040159b: jz 0x4015a2
      [-]832600ebf1
         // 0040159d: and ds:[esi], 0x0
         // 004015a0: jmp 0x401593
      [-]8b40098906b001
         // 004015a2: mov eax, ds:[eax+0x9]
         // 004015a5: mov ds:[esi], eax
         // 004015a7: mov b1 al, b1 0x1
      [-]6a016a06ff74240c8bce8937e862ffffff85c07504
         // 004015ac: push 0x1
         // 004015ae: push 0x6
         // 004015b0: push ss:[esp+0xc]
         // 004015b4: mov ecx, esi
         // 004015b6: mov ds:[edi], esi
         // 004015b8: call 0x40151f
         // 004015bd: test eax, eax
         // 004015bf: jnz 0x4015c5
      [-]32c0eb0a
         // 004015c1: xor b1 al, b1 al
         // 004015c3: jmp 0x4015cf
      [-]8b40090346148907b001
         // 004015c5: mov eax, ds:[eax+0x9]
         // 004015c8: add eax, ds:[esi+0x14]
         // 004015cb: mov ds:[edi], eax
         // 004015cd: mov b1 al, b1 0x1
      [-]568d7704e8634900008d7714e85b490000b0015ec3
         // 004015d2: push esi
         // 004015d3: lea esi, ds:[edi+0x4]
         // 004015d6: call 0x405f3e
         // 004015db: lea esi, ds:[edi+0x14]
         // 004015de: call 0x405f3e
         // 004015e3: mov b1 al, b1 0x1
         // 004015e5: pop esi
         // 004015e6: retn 
      [-]558bec515356578bf86a3f8bf25b83ff037c6c
         // 004015e7: push ebp
         // 004015e8: mov ebp, esp
         // 004015ea: push ecx
         // 004015eb: push ebx
         // 004015ec: push esi
         // 004015ed: push edi
         // 004015ee: mov edi, eax
         // 004015f0: push 0x3f
         // 004015f2: mov esi, edx
         // 004015f4: pop ebx
         // 004015f5: cmp edi, 0x3
         // 004015f8: jl 0x401666
      [-]6a035b33d2f7f36a3f5b8945fc6bc0fd03f8
         // 004015fa: push 0x3
         // 004015fc: pop ebx
         // 004015fd: xor edx, edx
         // 004015ff: div ebx
         // 00401601: push 0x3f
         // 00401603: pop ebx
         // 00401604: mov ss:[ebp+0xfffffffffffffffc], eax
         // 00401607: imul eax, b1 0xfd
         // 0040160a: add edi, eax
      [-]0fb6160fb64601c1e2080bd00fb64602c1e2080bd08bc2c1e81223c38a807014420088018bc2c1e80c23c38a80701442008841018bc2c1e80623c38a807014420023d38841028a827014420088410383c60383c104ff4dfc75a6
         // 0040160c: movzx edx, b1 ds:[esi]
         // 0040160f: movzx eax, b1 ds:[esi+0x1]
         // 00401613: shl edx, b1 0x8
         // 00401616: or edx, eax
         // 00401618: movzx eax, b1 ds:[esi+0x2]
         // 0040161c: shl edx, b1 0x8
         // 0040161f: or edx, eax
         // 00401621: mov eax, edx
         // 00401623: shr eax, b1 0x12
         // 00401626: and eax, ebx
         // 00401628: mov b1 al, b1 ds:[eax+0x421470]
         // 0040162e: mov b1 ds:[ecx], b1 al
         // 00401630: mov eax, edx
         // 00401632: shr eax, b1 0xc
         // 00401635: and eax, ebx
         // 00401637: mov b1 al, b1 ds:[eax+0x421470]
         // 0040163d: mov b1 ds:[ecx+0x1], b1 al
         // 00401640: mov eax, edx
         // 00401642: shr eax, b1 0x6
         // 00401645: and eax, ebx
         // 00401647: mov b1 al, b1 ds:[eax+0x421470]
         // 0040164d: and edx, ebx
         // 0040164f: mov b1 ds:[ecx+0x2], b1 al
         // 00401652: mov b1 al, b1 ds:[edx+0x421470]
         // 00401658: mov b1 ds:[ecx+0x3], b1 al
         // 0040165b: add esi, 0x3
         // 0040165e: add ecx, 0x4
         // 00401661: dec ss:[ebp+0xfffffffffffffffc]
         // 00401664: jnz 0x40160c
      [-]85ff7505
         // 00401666: test edi, edi
         // 00401668: jnz 0x40166f
      [-]c60100eb4b
         // 0040166a: mov b1 ds:[ecx], b1 0x0
         // 0040166d: jmp 0x4016ba
      [-]0fb606c1e0104f66c741033d00741b
         // 0040166f: movzx eax, b1 ds:[esi]
         // 00401672: shl eax, b1 0x10
         // 00401675: dec edi
         // 00401676: mov b2 ds:[ecx+0x3], b2 0x3d
         // 0040167c: jz 0x401699
      [-]0fb65601c1e2080bc28bd0c1ea0623d38a9270144200885102eb04
         // 0040167e: movzx edx, b1 ds:[esi+0x1]
         // 00401682: shl edx, b1 0x8
         // 00401685: or eax, edx
         // 00401687: mov edx, eax
         // 00401689: shr edx, b1 0x6
         // 0040168c: and edx, ebx
         // 0040168e: mov b1 dl, b1 ds:[edx+0x421470]
         // 00401694: mov b1 ds:[ecx+0x2], b1 dl
         // 00401697: jmp 0x40169d
      [-]c641023d
         // 00401699: mov b1 ds:[ecx+0x2], b1 0x3d
      [-]8bd0c1ea0c23d38a9270144200c1e81223c38851018a80701442008801
         // 0040169d: mov edx, eax
         // 0040169f: shr edx, b1 0xc
         // 004016a2: and edx, ebx
         // 004016a4: mov b1 dl, b1 ds:[edx+0x421470]
         // 004016aa: shr eax, b1 0x12
         // 004016ad: and eax, ebx
         // 004016af: mov b1 ds:[ecx+0x1], b1 dl
         // 004016b2: mov b1 al, b1 ds:[eax+0x421470]
         // 004016b8: mov b1 ds:[ecx], b1 al
      [-]5f5eb0015bc9c3
         // 004016ba: pop edi
         // 004016bb: pop esi
         // 004016bc: mov b1 al, b1 0x1
         // 004016be: pop ebx
         // 004016bf: leave 
         // 004016c0: retn 
      [-]833d????????0056be????????750e
         // 004016c1: cmp ds:[0x42c5e0], 0x0
         // 004016c8: push esi
         // 004016c9: mov esi, 0x42c5e0
         // 004016ce: jnz 0x4016de
      [-]68????????566a00ff1570f24100
         // 004016d0: push 0x410
         // 004016d5: push esi
         // 004016d6: push 0x0
         // 004016d8: call ds:[GetModuleFileNameW]
      [-]8bc65ec3
         // 004016de: mov eax, esi
         // 004016e0: pop esi
         // 004016e1: retn 
      [-]558bec81ec????????8365f800568d85????????5068????????ff1568f2410085c07e7f
         // 004016e2: push ebp
         // 004016e3: mov ebp, esp
         // 004016e5: sub esp, 0x228
         // 004016eb: and ss:[ebp+0xfffffffffffffff8], 0x0
         // 004016ef: push esi
         // 004016f0: lea eax, ss:[ebp+0xfffffffffffffddc]
         // 004016f6: push eax
         // 004016f7: push 0x104
         // 004016fc: call ds:[GetTempPathW]
         // 00401702: test eax, eax
         // 00401704: jle 0x401785
      [-]807d10007462
         // 00401706: cmp b1 ss:[ebp+0x10], b1 0x0
         // 0040170a: jz 0x40176e
      [-]8d45e850ff15ecf2410085c07554
         // 0040170c: lea eax, ss:[ebp+0xffffffffffffffe8]
         // 0040170f: push eax
         // 00401710: call ds:[UuidCreate]
         // 00401716: test eax, eax
         // 00401718: jnz 0x40176e
      [-]8d45f8508d45e850ff15f4f2410085c07542
         // 0040171a: lea eax, ss:[ebp+0xfffffffffffffff8]
         // 0040171d: push eax
         // 0040171e: lea eax, ss:[ebp+0xffffffffffffffe8]
         // 00401721: push eax
         // 00401722: call ds:[UuidToStringW]
         // 00401728: test eax, eax
         // 0040172a: jnz 0x40176e
      [-]8d85????????50ff156cf241006683bc45dafdffff5c8b3564f24100740e
         // 0040172c: lea eax, ss:[ebp+0xfffffffffffffddc]
         // 00401732: push eax
         // 00401733: call ds:[lstrlenW]
         // 00401739: cmp b2 ss:[ebp+eax*0x2], b2 0x5c
         // 00401742: mov esi, ds:[lstrcatW]
         // 00401748: jz 0x401758
      [-]68????????8d85????????50ffd6
         // 0040174a: push 0x4215cc
         // 0040174f: lea eax, ss:[ebp+0xfffffffffffffddc]
         // 00401755: push eax
         // 00401756: call esi
      [-]ff75f88d85????????50ffd68d45f850ff15f0f24100
         // 00401758: push ss:[ebp+0xfffffffffffffff8]
         // 0040175b: lea eax, ss:[ebp+0xfffffffffffffddc]
         // 00401761: push eax
         // 00401762: call esi
         // 00401764: lea eax, ss:[ebp+0xfffffffffffffff8]
         // 00401767: push eax
         // 00401768: call ds:[RpcStringFreeW]
      [-]ff750c8d85????????50ff7508ff15c0f24100b001eb02
         // 0040176e: push ss:[ebp+0xc]
         // 00401771: lea eax, ss:[ebp+0xfffffffffffffddc]
         // 00401777: push eax
         // 00401778: push ss:[ebp+0x8]
         // 0040177b: call ds:[lstrcpynW]
         // 00401781: mov b1 al, b1 0x1
         // 00401783: jmp 0x401787
      [-]5ec9c20c00
         // 00401787: pop esi
         // 00401788: leave 
         // 00401789: retn b2 0xc
      [-]85d27424
         // 0040178c: test edx, edx
         // 0040178e: jz 0x4017b4
      [-]833801761f
         // 00401790: cmp ds:[eax], 0x1
         // 00401793: jbe 0x4017b4
      [-]837c2408017618
         // 00401795: cmp ss:[esp+0x8], 0x1
         // 0040179a: jbe 0x4017b4
      [-]50ff7424088b442410e8b6430000f7d8591ac059fec0eb02
         // 0040179c: push eax
         // 0040179d: push ss:[esp+0x8]
         // 004017a1: mov eax, ss:[esp+0x10]
         // 004017a5: call 0x405b60
         // 004017aa: neg eax
         // 004017ac: pop ecx
         // 004017ad: sbb b1 al, b1 al
         // 004017af: pop ecx
         // 004017b0: inc b1 al
         // 004017b2: jmp 0x4017b6
      [-]51568d34015733ff8bd1b8????????3bce7334
         // 004017b9: push ecx
         // 004017ba: push esi
         // 004017bb: lea esi, ds:[ecx+eax]
         // 004017be: push edi
         // 004017bf: xor edi, edi
         // 004017c1: mov edx, ecx
         // 004017c3: mov eax, 0x80
         // 004017c8: cmp ecx, esi
         // 004017ca: jnb 0x401800
      [-]538a5c240f
         // 004017cc: push ebx
         // 004017cd: mov b1 bl, b1 ss:[esp+0xf]
      [-]03c03d????????7506
         // 004017d1: add eax, eax
         // 004017d3: cmp eax, 0x100
         // 004017d8: jnz 0x4017e0
      [-]8a1a33c04042
         // 004017da: mov b1 bl, b1 ds:[edx]
         // 004017dc: xor eax, eax
         // 004017de: inc eax
         // 004017df: inc edx
      [-]84d87415
         // 004017e0: test b1 al, b1 bl
         // 004017e2: jz 0x4017f9
      [-]0fb60ac1e90283c10383c202497808
         // 004017e4: movzx ecx, b1 ds:[edx]
         // 004017e7: shr ecx, b1 0x2
         // 004017ea: add ecx, 0x3
         // 004017ed: add edx, 0x2
         // 004017f0: dec ecx
         // 004017f1: js 0x4017fb
      [-]8d7c0f01eb02
         // 004017f3: lea edi, ds:[edi+ecx+0x1]
         // 004017f7: jmp 0x4017fb
      [-]3bd672d2
         // 004017fb: cmp edx, esi
         // 004017fd: jb 0x4017d1
      [-]8bc75f5e59c3
         // 00401800: mov eax, edi
         // 00401802: pop edi
         // 00401803: pop esi
         // 00401804: pop ecx
         // 00401805: retn 
      [-]33c983c8ff394c24087704
         // 00401806: xor ecx, ecx
         // 00401808: or eax, 0xffffffffffffffff
         // 0040180b: cmp ss:[esp+0x8], ecx
         // 0040180f: ja 0x401815
      [-]33c0eb21
         // 00401811: xor eax, eax
         // 00401813: jmp 0x401836
      [-]8b5424040fb6141133d081e2????????c1e808330495????????413b4c240872df
         // 00401815: mov edx, ss:[esp+0x4]
         // 00401819: movzx edx, b1 ds:[ecx+edx]
         // 0040181d: xor edx, eax
         // 0040181f: and edx, 0xff
         // 00401825: shr eax, b1 0x8
         // 00401828: xor eax, ds:[0x429878+edx*0x4]
         // 0040182f: inc ecx
         // 00401830: cmp ecx, ss:[esp+0x8]
         // 00401834: jb 0x401815
      [-]8b4804568b30c1e9028bc199572bc233ffd1f8
         // 00401839: mov ecx, ds:[eax+0x4]
         // 0040183c: push esi
         // 0040183d: mov esi, ds:[eax]
         // 0040183f: shr ecx, b1 0x2
         // 00401842: mov eax, ecx
         // 00401844: cdq 
         // 00401845: push edi
         // 00401846: sub eax, edx
         // 00401848: xor edi, edi
         // 0040184a: sar eax, b1 0x1
      [-]8b14863954240c7418
         // 0040184c: mov edx, ds:[esi+eax*0x4]
         // 0040184f: cmp ss:[esp+0xc], edx
         // 00401853: jz 0x40186d
      [-]8bc8eb03
         // 00401857: mov ecx, eax
         // 00401859: jmp 0x40185e
      [-]8bc12bc7992bc2d1f803c73bf97cdf
         // 0040185e: mov eax, ecx
         // 00401860: sub eax, edi
         // 00401862: cdq 
         // 00401863: sub eax, edx
         // 00401865: sar eax, b1 0x1
         // 00401867: add eax, edi
         // 00401869: cmp edi, ecx
         // 0040186b: jl 0x40184c
      [-]5f5ec20400
         // 0040186d: pop edi
         // 0040186e: pop esi
         // 0040186f: retn b2 0x4
      [-]558bec515156578bf88b770453c1ee02e8b2ffffff8945f83bc67d0b
         // 00401872: push ebp
         // 00401873: mov ebp, esp
         // 00401875: push ecx
         // 00401876: push ecx
         // 00401877: push esi
         // 00401878: push edi
         // 00401879: mov edi, eax
         // 0040187b: mov esi, ds:[edi+0x4]
         // 0040187e: push ebx
         // 0040187f: shr esi, b1 0x2
         // 00401882: call 0x401839
         // 00401887: mov ss:[ebp+0xfffffffffffffff8], eax
         // 0040188a: cmp eax, esi
         // 0040188c: jge 0x401899
      [-]8b0f391c81750e
         // 0040188e: mov ecx, ds:[edi]
         // 00401890: cmp ds:[ecx+eax*0x4], ebx
         // 00401893: jnz 0x4018a3
      [-]32c0eb3d
         // 00401895: xor b1 al, b1 al
         // 00401897: jmp 0x4018d6
      [-]538bcfe8c0480000eb31
         // 00401899: push ebx
         // 0040189a: mov ecx, edi
         // 0040189c: call 0x406161
         // 004018a1: jmp 0x4018d4
      [-]8365fc006a008d45fc506a04588bcfe8074800008b45f88b3f2bf08d3c87c1e602568d47045750e89114010083c40c891f
         // 004018a3: and ss:[ebp+0xfffffffffffffffc], 0x0
         // 004018a7: push 0x0
         // 004018a9: lea eax, ss:[ebp+0xfffffffffffffffc]
         // 004018ac: push eax
         // 004018ad: push 0x4
         // 004018af: pop eax
         // 004018b0: mov ecx, edi
         // 004018b2: call 0x4060be
         // 004018b7: mov eax, ss:[ebp+0xfffffffffffffff8]
         // 004018ba: mov edi, ds:[edi]
         // 004018bc: sub esi, eax
         // 004018be: lea edi, ds:[edi+eax*0x4]
         // 004018c1: shl esi, b1 0x2
         // 004018c4: push esi
         // 004018c5: lea eax, ds:[edi+0x4]
         // 004018c8: push edi
         // 004018c9: push eax
         // 004018ca: call _memcpy
         // 004018cf: add esp, 0xc
         // 004018d2: mov ds:[edi], ebx
      [-]5f5ec9c3
         // 004018d6: pop edi
         // 004018d7: pop esi
         // 004018d8: leave 
         // 004018d9: retn 
      [-]558bec51518365fc0053568b7004c1ee02578b3885f67e2a
         // 004018da: push ebp
         // 004018db: mov ebp, esp
         // 004018dd: push ecx
         // 004018de: push ecx
         // 004018df: and ss:[ebp+0xfffffffffffffffc], 0x0
         // 004018e3: push ebx
         // 004018e4: push esi
         // 004018e5: mov esi, ds:[eax+0x4]
         // 004018e8: shr esi, b1 0x2
         // 004018eb: push edi
         // 004018ec: mov edi, ds:[eax]
         // 004018ee: test esi, esi
         // 004018f0: jle 0x40191c
      [-]8b45fc8b1c878b4508e872fffffff645fc0f750e
         // 004018f2: mov eax, ss:[ebp+0xfffffffffffffffc]
         // 004018f5: mov ebx, ds:[edi+eax*0x4]
         // 004018f8: mov eax, ss:[ebp+0x8]
         // 004018fb: call 0x401872
         // 00401900: test b1 ss:[ebp+0xfffffffffffffffc], b1 0xf
         // 00401904: jnz 0x401914
      [-]8b1d58f241006a0affd36a00ffd3
         // 00401906: mov ebx, ds:[Sleep]
         // 0040190c: push 0xa
         // 0040190e: call ebx
         // 00401910: push 0x0
         // 00401912: call ebx
      [-]ff45fc3975fc7cd6
         // 00401914: inc ss:[ebp+0xfffffffffffffffc]
         // 00401917: cmp ss:[ebp+0xfffffffffffffffc], esi
         // 0040191a: jl 0x4018f2
      [-]5f5e5bc9c20400
         // 0040191c: pop edi
         // 0040191d: pop esi
         // 0040191e: pop ebx
         // 0040191f: leave 
         // 00401920: retn b2 0x4
      [-]558d6c249081ec????????837d7c017f07
         // 00401923: push ebp
         // 00401924: lea ebp, ss:[esp+0xffffffffffffff90]
         // 00401928: sub esp, 0x104
         // 0040192e: cmp ss:[ebp+0x7c], 0x1
         // 00401932: jg 0x40193b
      [-]32c0e942010000
         // 00401934: xor b1 al, b1 al
         // 00401936: jmp 0x401a7d
      [-]535633c957884d6e33c0bf????????
         // 0040193b: push ebx
         // 0040193c: push esi
         // 0040193d: xor ecx, ecx
         // 0040193f: push edi
         // 00401940: mov b1 ss:[ebp+0x6e], b1 cl
         // 00401943: xor eax, eax
         // 00401945: mov edi, 0x100
      [-]8884056effffff403bc77cf4
         // 0040194a: mov b1 ss:[ebp+eax+0xffffffffffffff6e], b1 al
         // 00401951: inc eax
         // 00401952: cmp eax, edi
         // 00401954: jl 0x40194a
      [-]66898d6cffffff33f6
         // 00401956: mov b2 ss:[ebp+0xffffffffffffff6c], b2 cx
         // 0040195d: xor esi, esi
      [-]0fb68d6cffffff0fb689549842008d8435????????0fb61003ca0fb6956dffffff03ca81e1????????7908
         // 0040195f: movzx ecx, b1 ss:[ebp+0xffffffffffffff6c]
         // 00401966: movzx ecx, b1 ds:[ecx+0x429854]
         // 0040196d: lea eax, ss:[ebp+esi+0xffffffffffffff6e]
         // 00401974: movzx edx, b1 ds:[eax]
         // 00401977: add ecx, edx
         // 00401979: movzx edx, b1 ss:[ebp+0xffffffffffffff6d]
         // 00401980: add ecx, edx
         // 00401982: and ecx, 0xffffffff800000ff
         // 00401988: jns 0x401992
      [-]4981c9????????41
         // 0040198a: dec ecx
         // 0040198b: or ecx, 0xffffffffffffff00
         // 00401991: inc ecx
      [-]888d6dffffff8a100fb6c98d8c0d????????8a19881888110fb6856cffffff4025????????7905
         // 00401992: mov b1 ss:[ebp+0xffffffffffffff6d], b1 cl
         // 00401998: mov b1 dl, b1 ds:[eax]
         // 0040199a: movzx ecx, b1 cl
         // 0040199d: lea ecx, ss:[ebp+ecx+0xffffffffffffff6e]
         // 004019a4: mov b1 bl, b1 ds:[ecx]
         // 004019a6: mov b1 ds:[eax], b1 bl
         // 004019a8: mov b1 ds:[ecx], b1 dl
         // 004019aa: movzx eax, b1 ss:[ebp+0xffffffffffffff6c]
         // 004019b1: inc eax
         // 004019b2: and eax, 0xffffffff8000001f
         // 004019b7: jns 0x4019be
      [-]4883c8e040
         // 004019b9: dec eax
         // 004019ba: or eax, 0xffffffffffffffe0
         // 004019bd: inc eax
      [-]4688856cffffff3bf77c96
         // 004019be: inc esi
         // 004019bf: mov b1 ss:[ebp+0xffffffffffffff6c], b1 al
         // 004019c5: cmp esi, edi
         // 004019c7: jl 0x40195f
      [-]33ffc6456e01397d7c0f8ea0000000
         // 004019c9: xor edi, edi
         // 004019cb: mov b1 ss:[ebp+0x6e], b1 0x1
         // 004019cf: cmp ss:[ebp+0x7c], edi
         // 004019d2: jle 0x401a78
      [-]0fb6b56dffffff0fb6c0
         // 004019d8: movzx esi, b1 ss:[ebp+0xffffffffffffff6d]
         // 004019df: movzx eax, b1 al
      [-]4025????????7907
         // 004019e2: inc eax
         // 004019e3: and eax, 0xffffffff800000ff
         // 004019e8: jns 0x4019f1
      [-]480d????????40
         // 004019ea: dec eax
         // 004019eb: or eax, 0xffffffffffffff00
         // 004019f0: inc eax
      [-]88856cffffff0fb6c08d8405????????0fb60803ce81e1????????7908
         // 004019f1: mov b1 ss:[ebp+0xffffffffffffff6c], b1 al
         // 004019f7: movzx eax, b1 al
         // 004019fa: lea eax, ss:[ebp+eax+0xffffffffffffff6e]
         // 00401a01: movzx ecx, b1 ds:[eax]
         // 00401a04: add ecx, esi
         // 00401a06: and ecx, 0xffffffff800000ff
         // 00401a0c: jns 0x401a16
      [-]4981c9????????41
         // 00401a0e: dec ecx
         // 00401a0f: or ecx, 0xffffffffffffff00
         // 00401a15: inc ecx
      [-]888d6dffffff8a100fb6c98d8c0d????????8a19881888110fb6b56dffffff0fb6856cffffff0fb694356effffff0fb69c056effffff8b4d7803d381e2????????7908
         // 00401a16: mov b1 ss:[ebp+0xffffffffffffff6d], b1 cl
         // 00401a1c: mov b1 dl, b1 ds:[eax]
         // 00401a1e: movzx ecx, b1 cl
         // 00401a21: lea ecx, ss:[ebp+ecx+0xffffffffffffff6e]
         // 00401a28: mov b1 bl, b1 ds:[ecx]
         // 00401a2a: mov b1 ds:[eax], b1 bl
         // 00401a2c: mov b1 ds:[ecx], b1 dl
         // 00401a2e: movzx esi, b1 ss:[ebp+0xffffffffffffff6d]
         // 00401a35: movzx eax, b1 ss:[ebp+0xffffffffffffff6c]
         // 00401a3c: movzx edx, b1 ss:[ebp+esi+0xffffffffffffff6e]
         // 00401a44: movzx ebx, b1 ss:[ebp+eax+0xffffffffffffff6e]
         // 00401a4c: mov ecx, ss:[ebp+0x78]
         // 00401a4f: add edx, ebx
         // 00401a51: and edx, 0xffffffff800000ff
         // 00401a57: jns 0x401a61
      [-]4a81ca????????42
         // 00401a59: dec edx
         // 00401a5a: or edx, 0xffffffffffffff00
         // 00401a60: inc edx
      [-]0fb6d28a94156effffff301439473b7d7c0f8c6affffff
         // 00401a61: movzx edx, b1 dl
         // 00401a64: mov b1 dl, b1 ss:[ebp+edx+0xffffffffffffff6e]
         // 00401a6b: xor b1 ds:[ecx+edi], b1 dl
         // 00401a6e: inc edi
         // 00401a6f: cmp edi, ss:[ebp+0x7c]
         // 00401a72: jl 0x4019e2
      [-]5f5eb0015b
         // 00401a78: pop edi
         // 00401a79: pop esi
         // 00401a7a: mov b1 al, b1 0x1
         // 00401a7c: pop ebx
      [-]83c570c9c20800
         // 00401a7d: add ebp, 0x70
         // 00401a80: leave 
         // 00401a81: retn b2 0x8
      [-]558bec83ec1053578bf98b088d570c894df0e84f04000084c00f841a030000
         // 00401a84: push ebp
         // 00401a85: mov ebp, esp
         // 00401a87: sub esp, 0x10
         // 00401a8a: push ebx
         // 00401a8b: push edi
         // 00401a8c: mov edi, ecx
         // 00401a8e: mov ecx, ds:[eax]
         // 00401a90: lea edx, ds:[edi+0xc]
         // 00401a93: mov ss:[ebp+0xfffffffffffffff0], ecx
         // 00401a96: call 0x401eea
         // 00401a9b: test b1 al, b1 al
         // 00401a9d: jz 0x401dbd
      [-]394f080f8311030000
         // 00401aa3: cmp ds:[edi+0x8], ecx
         // 00401aa6: jnb 0x401dbd
      [-]578d7df0e85d0400008bf8817f10????????590f85f4020000
         // 00401aac: push edi
         // 00401aad: lea edi, ss:[ebp+0xfffffffffffffff0]
         // 00401ab0: call 0x401f12
         // 00401ab5: mov edi, eax
         // 00401ab7: cmp ds:[edi+0x10], 0xffffffff80051a85
         // 00401abe: pop ecx
         // 00401abf: jnz 0x401db9
      [-]8365fc0083be????????000f8e0f010000
         // 00401ac5: and ss:[ebp+0xfffffffffffffffc], 0x0
         // 00401ac9: cmp ds:[esi+0x2bfc], 0x0
         // 00401ad0: jle 0x401be5
      [-]c745f4????????2975f48d9e????????
         // 00401ad6: mov ss:[ebp+0xfffffffffffffff4], 0xfffffffffffff5f8
         // 00401add: sub ss:[ebp+0xfffffffffffffff4], esi
         // 00401ae0: lea ebx, ds:[esi+0xa08]
      [-]8b47183b83????????0f85d8000000
         // 00401ae6: mov eax, ds:[edi+0x18]
         // 00401ae9: cmp eax, ds:[ebx+0xfffffffffffffef8]
         // 00401aef: jnz 0x401bcd
      [-]a1????????3b47200f84e2000000
         // 00401af5: mov eax, ds:[0x429ca4]
         // 00401afa: cmp eax, ds:[edi+0x20]
         // 00401afd: jz 0x401be5
      [-]8b0385c07e08
         // 00401b03: mov eax, ds:[ebx]
         // 00401b05: test eax, eax
         // 00401b07: jle 0x401b11
      [-]83f8107c03
         // 00401b09: cmp eax, 0x10
         // 00401b0c: jl 0x401b11
      [-]8b47248945f83d????????7746
         // 00401b11: mov eax, ds:[edi+0x24]
         // 00401b14: mov ss:[ebp+0xfffffffffffffff8], eax
         // 00401b17: cmp eax, 0x6400000
         // 00401b1c: ja 0x401b64
      [-]85c07507
         // 00401b1e: test eax, eax
         // 00401b20: jnz 0x401b29
      [-]c745f8????????
         // 00401b22: mov ss:[ebp+0xfffffffffffffff8], 0x1
      [-]8345f804833d????????007509
         // 00401b29: add ss:[ebp+0xfffffffffffffff8], 0x4
         // 00401b2d: cmp ds:[0x42ca0c], 0x0
         // 00401b34: jnz 0x401b3f
      [-]e8d540000084c07425
         // 00401b36: call 0x405c10
         // 00401b3b: test b1 al, b1 al
         // 00401b3d: jz 0x401b64
      [-]6a00ff15d4f04100ff75f86a08ff35????????ff15c8f0410085c0750a
         // 00401b3f: push 0x0
         // 00401b41: call ds:[SetLastError]
         // 00401b47: push ss:[ebp+0xfffffffffffffff8]
         // 00401b4a: push 0x8
         // 00401b4c: push ds:[0x42ca0c]
         // 00401b52: call ds:[HeapAlloc]
         // 00401b58: test eax, eax
         // 00401b5a: jnz 0x401b66
      [-]6a00ff1538f24100
         // 00401b5c: push 0x0
         // 00401b5e: call ds:[ExitProcess]
      [-]8b138b4df403cbc1e20403d1898432????????8b03c1e00403c183bc30????????007443
         // 00401b66: mov edx, ds:[ebx]
         // 00401b68: mov ecx, ss:[ebp+0xfffffffffffffff4]
         // 00401b6b: add ecx, ebx
         // 00401b6d: shl edx, b1 0x4
         // 00401b70: add edx, ecx
         // 00401b72: mov ds:[edx+esi+0x908], eax
         // 00401b79: mov eax, ds:[ebx]
         // 00401b7b: shl eax, b1 0x4
         // 00401b7e: add eax, ecx
         // 00401b80: cmp ds:[eax+esi+0x908], 0x0
         // 00401b88: jz 0x401bcd
      [-]8b5724899430????????8b038b572005????????c1e00403c18914308b4720ff7724a3????????8d4736508b03c1e00403c1ffb430????????e89811010083c40cff03
         // 00401b8a: mov edx, ds:[edi+0x24]
         // 00401b8d: mov ds:[eax+esi+0x90c], edx
         // 00401b94: mov eax, ds:[ebx]
         // 00401b96: mov edx, ds:[edi+0x20]
         // 00401b99: add eax, 0x91
         // 00401b9e: shl eax, b1 0x4
         // 00401ba1: add eax, ecx
         // 00401ba3: mov ds:[eax+esi], edx
         // 00401ba6: mov eax, ds:[edi+0x20]
         // 00401ba9: push ds:[edi+0x24]
         // 00401bac: mov ds:[0x429ca4], eax
         // 00401bb1: lea eax, ds:[edi+0x36]
         // 00401bb4: push eax
         // 00401bb5: mov eax, ds:[ebx]
         // 00401bb7: shl eax, b1 0x4
         // 00401bba: add eax, ecx
         // 00401bbc: push ds:[eax+esi+0x908]
         // 00401bc3: call _memcpy
         // 00401bc8: add esp, 0xc
         // 00401bcb: inc ds:[ebx]
      [-]ff45fc8b45fc81c3????????3b86????????0f8c01ffffff
         // 00401bcd: inc ss:[ebp+0xfffffffffffffffc]
         // 00401bd0: mov eax, ss:[ebp+0xfffffffffffffffc]
         // 00401bd3: add ebx, 0x118
         // 00401bd9: cmp eax, ds:[esi+0x2bfc]
         // 00401bdf: jl 0x401ae6
      [-]8365fc0083be????????000f8e18010000
         // 00401be5: and ss:[ebp+0xfffffffffffffffc], 0x0
         // 00401be9: cmp ds:[esi+0x4f00], 0x0
         // 00401bf0: jle 0x401d0e
      [-]c745f4????????2975f48d9e????????
         // 00401bf6: mov ss:[ebp+0xfffffffffffffff4], 0xffffffffffffd2f4
         // 00401bfd: sub ss:[ebp+0xfffffffffffffff4], esi
         // 00401c00: lea ebx, ds:[esi+0x2d0c]
      [-]8b47183b83????????0f85e1000000
         // 00401c06: mov eax, ds:[edi+0x18]
         // 00401c09: cmp eax, ds:[ebx+0xfffffffffffffef8]
         // 00401c0f: jnz 0x401cf6
      [-]a1????????3b47200f84eb000000
         // 00401c15: mov eax, ds:[0x429ca4]
         // 00401c1a: cmp eax, ds:[edi+0x20]
         // 00401c1d: jz 0x401d0e
      [-]8b0333c93bc17e07
         // 00401c23: mov eax, ds:[ebx]
         // 00401c25: xor ecx, ecx
         // 00401c27: cmp eax, ecx
         // 00401c29: jle 0x401c32
      [-]83f8107c02
         // 00401c2b: cmp eax, 0x10
         // 00401c2e: jl 0x401c32
      [-]8b47248945f83d????????7747
         // 00401c32: mov eax, ds:[edi+0x24]
         // 00401c35: mov ss:[ebp+0xfffffffffffffff8], eax
         // 00401c38: cmp eax, 0x6400000
         // 00401c3d: ja 0x401c86
      [-]3bc17507
         // 00401c3f: cmp eax, ecx
         // 00401c41: jnz 0x401c4a
      [-]c745f8????????
         // 00401c43: mov ss:[ebp+0xfffffffffffffff8], 0x1
      [-]8345f804390d????????750d
         // 00401c4a: add ss:[ebp+0xfffffffffffffff8], 0x4
         // 00401c4e: cmp ds:[0x42ca0c], ecx
         // 00401c54: jnz 0x401c63
      [-]e8b53f000084c07504
         // 00401c56: call 0x405c10
         // 00401c5b: test b1 al, b1 al
         // 00401c5d: jnz 0x401c63
      [-]33c9eb23
         // 00401c5f: xor ecx, ecx
         // 00401c61: jmp 0x401c86
      [-]6a00ff15d4f04100ff75f86a08ff35????????ff15c8f0410085c00f84d8feffff
         // 00401c63: push 0x0
         // 00401c65: call ds:[SetLastError]
         // 00401c6b: push ss:[ebp+0xfffffffffffffff8]
         // 00401c6e: push 0x8
         // 00401c70: push ds:[0x42ca0c]
         // 00401c76: call ds:[HeapAlloc]
         // 00401c7c: test eax, eax
         // 00401c7e: jz 0x401b5c
      [-]8b138b45f4c1e20403c303d0898c32????????8b0b8bd1c1e20403d083bc32????????00744a
         // 00401c86: mov edx, ds:[ebx]
         // 00401c88: mov eax, ss:[ebp+0xfffffffffffffff4]
         // 00401c8b: shl edx, b1 0x4
         // 00401c8e: add eax, ebx
         // 00401c90: add edx, eax
         // 00401c92: mov ds:[edx+esi+0x2c0c], ecx
         // 00401c99: mov ecx, ds:[ebx]
         // 00401c9b: mov edx, ecx
         // 00401c9d: shl edx, b1 0x4
         // 00401ca0: add edx, eax
         // 00401ca2: cmp ds:[edx+esi+0x2c0c], 0x0
         // 00401caa: jz 0x401cf6
      [-]8b572481c1????????c1e10403c88914318b0b8b5720c1e10403c8899431????????8b4f20ff7724890d????????8d4f36518b0bc1e10403c8ffb431????????e86f10010083c40cff03
         // 00401cac: mov edx, ds:[edi+0x24]
         // 00401caf: add ecx, 0x2c1
         // 00401cb5: shl ecx, b1 0x4
         // 00401cb8: add ecx, eax
         // 00401cba: mov ds:[ecx+esi], edx
         // 00401cbd: mov ecx, ds:[ebx]
         // 00401cbf: mov edx, ds:[edi+0x20]
         // 00401cc2: shl ecx, b1 0x4
         // 00401cc5: add ecx, eax
         // 00401cc7: mov ds:[ecx+esi+0x2c14], edx
         // 00401cce: mov ecx, ds:[edi+0x20]
         // 00401cd1: push ds:[edi+0x24]
         // 00401cd4: mov ds:[0x429ca4], ecx
         // 00401cda: lea ecx, ds:[edi+0x36]
         // 00401cdd: push ecx
         // 00401cde: mov ecx, ds:[ebx]
         // 00401ce0: shl ecx, b1 0x4
         // 00401ce3: add ecx, eax
         // 00401ce5: push ds:[ecx+esi+0x2c0c]
         // 00401cec: call _memcpy
         // 00401cf1: add esp, 0xc
         // 00401cf4: inc ds:[ebx]
      [-]ff45fc8b45fc81c3????????3b86????????0f8cf8feffff
         // 00401cf6: inc ss:[ebp+0xfffffffffffffffc]
         // 00401cf9: mov eax, ss:[ebp+0xfffffffffffffffc]
         // 00401cfc: add ebx, 0x118
         // 00401d02: cmp eax, ds:[esi+0x4f00]
         // 00401d08: jl 0x401c06
      [-]c6861c580000008b4f1881f9????????740f
         // 00401d0e: mov b1 ds:[esi+0x581c], b1 0x0
         // 00401d15: mov ecx, ds:[edi+0x18]
         // 00401d18: cmp ecx, 0xffffffffff00aaee
         // 00401d1e: jz 0x401d2f
      [-]81f9????????757d
         // 00401d20: cmp ecx, 0xffffffffff00bb00
         // 00401d26: jnz 0x401da5
      [-]c6861c58000001
         // 00401d28: mov b1 ds:[esi+0x581c], b1 0x1
      [-]ffb6????????e80a3f00008b5f2481fb????????773d
         // 00401d2f: push ds:[esi+0x5814]
         // 00401d35: call 0x405c44
         // 00401d3a: mov ebx, ds:[edi+0x24]
         // 00401d3d: cmp ebx, 0x6400000
         // 00401d43: ja 0x401d82
      [-]85db7501
         // 00401d45: test ebx, ebx
         // 00401d47: jnz 0x401d4a
      [-]83c304833d????????007509
         // 00401d4a: add ebx, 0x4
         // 00401d4d: cmp ds:[0x42ca0c], 0x0
         // 00401d54: jnz 0x401d5f
      [-]e8b53e000084c07423
         // 00401d56: call 0x405c10
         // 00401d5b: test b1 al, b1 al
         // 00401d5d: jz 0x401d82
      [-]6a00ff15d4f04100536a08ff35????????ff15c8f0410085c00f84defdffff
         // 00401d5f: push 0x0
         // 00401d61: call ds:[SetLastError]
         // 00401d67: push ebx
         // 00401d68: push 0x8
         // 00401d6a: push ds:[0x42ca0c]
         // 00401d70: call ds:[HeapAlloc]
         // 00401d76: test eax, eax
         // 00401d78: jz 0x401b5c
      [-]8bc8eb02
         // 00401d7e: mov ecx, eax
         // 00401d80: jmp 0x401d84
      [-]898e????????85c97417
         // 00401d84: mov ds:[esi+0x5814], ecx
         // 00401d8a: test ecx, ecx
         // 00401d8c: jz 0x401da5
      [-]8b4724508986????????8d47365051e8be0f010083c40c
         // 00401d8e: mov eax, ds:[edi+0x24]
         // 00401d91: push eax
         // 00401d92: mov ds:[esi+0x5818], eax
         // 00401d98: lea eax, ds:[edi+0x36]
         // 00401d9b: push eax
         // 00401d9c: push ecx
         // 00401d9d: call _memcpy
         // 00401da2: add esp, 0xc
      [-]578d7df0e8640100008bf85985ff0f850cfdffff
         // 00401da5: push edi
         // 00401da6: lea edi, ss:[ebp+0xfffffffffffffff0]
         // 00401da9: call 0x401f12
         // 00401dae: mov edi, eax
         // 00401db0: pop ecx
         // 00401db1: test edi, edi
         // 00401db3: jnz 0x401ac5
      [-]b001eb02
         // 00401db9: mov b1 al, b1 0x1
         // 00401dbb: jmp 0x401dbf
      [-]5f5bc9c3
         // 00401dbf: pop edi
         // 00401dc0: pop ebx
         // 00401dc1: leave 
         // 00401dc2: retn 
      [-]b8????????e81f7b0100515356578965f0e8740800008b75088b068365fc008b4e046bc9148d560c52ff760850ff9401????????83c40c884610834dfcff33c08b4df464890d????????5f5e5bc9c20400
         // 00401dc3: mov eax, 0x41d81e
         // 00401dc8: call __EH_prolog
         // 00401dcd: push ecx
         // 00401dce: push ebx
         // 00401dcf: push esi
         // 00401dd0: push edi
         // 00401dd1: mov ss:[ebp+0xfffffffffffffff0], esp
         // 00401dd4: call 0x40264d
         // 00401dd9: mov esi, ss:[ebp+0x8]
         // 00401ddc: mov eax, ds:[esi]
         // 00401dde: and ss:[ebp+0xfffffffffffffffc], 0x0
         // 00401de2: mov ecx, ds:[esi+0x4]
         // 00401de5: imul ecx, b1 0x14
         // 00401de8: lea edx, ds:[esi+0xc]
         // 00401deb: push edx
         // 00401dec: push ds:[esi+0x8]
         // 00401def: push eax
         // 00401df0: call ds:[ecx+eax+0x308]
         // 00401df7: add esp, 0xc
         // 00401dfa: mov b1 ds:[esi+0x10], b1 al
         // 00401dfd: or ss:[ebp+0xfffffffffffffffc], 0xffffffffffffffff
         // 00401e01: xor eax, eax
         // 00401e03: mov ecx, ss:[ebp+0xfffffffffffffff4]
         // 00401e06: mov fs:[0x0], ecx
         // 00401e0d: pop edi
         // 00401e0e: pop esi
         // 00401e0f: pop ebx
         // 00401e10: leave 
         // 00401e11: retn b2 0x4
      [-]565733f6e89e280000bf8c9c420057e8983e000084c07414
         // 00401e25: push esi
         // 00401e26: push edi
         // 00401e27: xor esi, esi
         // 00401e29: call 0x4046cc
         // 00401e2e: mov edi, stru_429C8C.DebugInfo
         // 00401e33: push edi
         // 00401e34: call 0x405cd1
         // 00401e39: test b1 al, b1 al
         // 00401e3b: jz 0x401e51
      [-]8b35????????c1ee02e88128000057e8a03e0000
         // 00401e3d: mov esi, ds:[0x429c80]
         // 00401e43: shr esi, b1 0x2
         // 00401e46: call 0x4046cc
         // 00401e4b: push edi
         // 00401e4c: call 0x405cf1
      [-]5f8bc65ec3
         // 00401e51: pop edi
         // 00401e52: mov eax, esi
         // 00401e54: pop esi
         // 00401e55: retn 
      [-]56e8702800008b006bc003992bc28bf0d1fee85f28000081fe????????7740
         // 00401e56: push esi
         // 00401e57: call 0x4046cc
         // 00401e5c: mov eax, ds:[eax]
         // 00401e5e: imul eax, b1 0x3
         // 00401e61: cdq 
         // 00401e62: sub eax, edx
         // 00401e64: mov esi, eax
         // 00401e66: sar esi, b1 0x1
         // 00401e68: call 0x4046cc
         // 00401e6d: cmp esi, 0x6400000
         // 00401e73: ja 0x401eb5
      [-]85f67501
         // 00401e75: test esi, esi
         // 00401e77: jnz 0x401e7a
      [-]83c604833d????????007509
         // 00401e7a: add esi, 0x4
         // 00401e7d: cmp ds:[0x42ca0c], 0x0
         // 00401e84: jnz 0x401e8f
      [-]e8853d000084c0742c
         // 00401e86: call 0x405c10
         // 00401e8b: test b1 al, b1 al
         // 00401e8d: jz 0x401ebb
      [-]6a00ff15d4f04100566a08ff35????????ff15c8f0410085c07507
         // 00401e8f: push 0x0
         // 00401e91: call ds:[SetLastError]
         // 00401e97: push esi
         // 00401e98: push 0x8
         // 00401e9a: push ds:[0x42ca0c]
         // 00401ea0: call ds:[HeapAlloc]
         // 00401ea6: test eax, eax
         // 00401ea8: jnz 0x401eb1
      [-]50ff1538f24100
         // 00401eaa: push eax
         // 00401eab: call ds:[ExitProcess]
      [-]8bf0eb02
         // 00401eb1: mov esi, eax
         // 00401eb3: jmp 0x401eb7
      [-]85f67504
         // 00401eb7: test esi, esi
         // 00401eb9: jnz 0x401ebf
      [-]33c05ec3
         // 00401ebb: xor eax, eax
         // 00401ebd: pop esi
         // 00401ebe: retn 
      [-]ff05????????a1????????6a108946048d460c68????????50c706????????e87d0e010083c40c8bc65ec3
         // 00401ebf: inc ds:[0x42c9f4]
         // 00401ec5: mov eax, ds:[0x42c9f4]
         // 00401eca: push 0x10
         // 00401ecc: mov ds:[esi+0x4], eax
         // 00401ecf: lea eax, ds:[esi+0xc]
         // 00401ed2: push 0x428e44
         // 00401ed7: push eax
         // 00401ed8: mov ds:[esi], 0xffffffffdeadface
         // 00401ede: call _memcpy
         // 00401ee3: add esp, 0xc
         // 00401ee6: mov eax, esi
         // 00401ee8: pop esi
         // 00401ee9: retn 
      [-]535633f6b00181ea????????
         // 00401eea: push ebx
         // 00401eeb: push esi
         // 00401eec: xor esi, esi
         // 00401eee: mov b1 al, b1 0x1
         // 00401ef0: sub edx, 0x428e44
      [-]8a9c32448e42003a9e448e42007508
         // 00401ef6: mov b1 bl, b1 ds:[edx+esi+0x428e44]
         // 00401efd: cmp b1 bl, b1 ds:[esi+0x428e44]
         // 00401f03: jnz 0x401f0d
      [-]4683fe107ceb
         // 00401f05: inc esi
         // 00401f06: cmp esi, 0x10
         // 00401f09: jl 0x401ef6
      [-]558bec51518b0783e8105333c95685c07e63
         // 00401f12: push ebp
         // 00401f13: mov ebp, esp
         // 00401f15: push ecx
         // 00401f16: push ecx
         // 00401f17: mov eax, ds:[edi]
         // 00401f19: sub eax, 0x10
         // 00401f1c: push ebx
         // 00401f1d: xor ecx, ecx
         // 00401f1f: push esi
         // 00401f20: test eax, eax
         // 00401f22: jle 0x401f87
      [-]8a033a05448e4200754b
         // 00401f27: mov b1 al, b1 ds:[ebx]
         // 00401f29: cmp b1 al, b1 ds:[0x428e44]
         // 00401f2f: jnz 0x401f7c
      [-]8bd3e8b2ffffff84c07440
         // 00401f31: mov edx, ebx
         // 00401f33: call 0x401eea
         // 00401f38: test b1 al, b1 al
         // 00401f3a: jz 0x401f7c
      [-]8b73348b450883c31083c11083c6328d440104894df88945fc3b377f2e
         // 00401f3c: mov esi, ds:[ebx+0x34]
         // 00401f3f: mov eax, ss:[ebp+0x8]
         // 00401f42: add ebx, 0x10
         // 00401f45: add ecx, 0x10
         // 00401f48: add esi, 0x32
         // 00401f4b: lea eax, ds:[ecx+eax+0x4]
         // 00401f4f: mov ss:[ebp+0xfffffffffffffff8], ecx
         // 00401f52: mov ss:[ebp+0xfffffffffffffffc], eax
         // 00401f55: cmp esi, ds:[edi]
         // 00401f57: jg 0x401f87
      [-]e86e27000033c03945fc7409
         // 00401f59: call 0x4046cc
         // 00401f5e: xor eax, eax
         // 00401f60: cmp ss:[ebp+0xfffffffffffffffc], eax
         // 00401f63: jz 0x401f6e
      [-]56ff75fce898f8ffff
         // 00401f65: push esi
         // 00401f66: push ss:[ebp+0xfffffffffffffffc]
         // 00401f69: call 0x401806
      [-]8b4b243b0f7304
         // 00401f6e: mov ecx, ds:[ebx+0x24]
         // 00401f71: cmp ecx, ds:[edi]
         // 00401f73: jnb 0x401f79
      [-]3b037414
         // 00401f75: cmp eax, ds:[ebx]
         // 00401f77: jz 0x401f8d
      [-]8b074183e810433bc87ca0
         // 00401f7c: mov eax, ds:[edi]
         // 00401f7e: inc ecx
         // 00401f7f: sub eax, 0x10
         // 00401f82: inc ebx
         // 00401f83: cmp ecx, eax
         // 00401f85: jl 0x401f27
      [-]5e5bc9c3
         // 00401f89: pop esi
         // 00401f8a: pop ebx
         // 00401f8b: leave 
         // 00401f8c: retn 
      [-]6ae8582bc601078bc3ebf1
         // 00401f8d: push 0xffffffffffffffe8
         // 00401f8f: pop eax
         // 00401f90: sub eax, esi
         // 00401f92: add ds:[edi], eax
         // 00401f94: mov eax, ebx
         // 00401f96: jmp 0x401f89
      [-]b8????????e84a790100515356578965f0e89f0600008b75088b068365fc008b4e086bc918ff760cff760450ff54010483c40c884610834dfcff33c08b4df464890d????????5f5e5bc9c20400
         // 00401f98: mov eax, 0x41d814
         // 00401f9d: call __EH_prolog
         // 00401fa2: push ecx
         // 00401fa3: push ebx
         // 00401fa4: push esi
         // 00401fa5: push edi
         // 00401fa6: mov ss:[ebp+0xfffffffffffffff0], esp
         // 00401fa9: call 0x40264d
         // 00401fae: mov esi, ss:[ebp+0x8]
         // 00401fb1: mov eax, ds:[esi]
         // 00401fb3: and ss:[ebp+0xfffffffffffffffc], 0x0
         // 00401fb7: mov ecx, ds:[esi+0x8]
         // 00401fba: imul ecx, b1 0x18
         // 00401fbd: push ds:[esi+0xc]
         // 00401fc0: push ds:[esi+0x4]
         // 00401fc3: push eax
         // 00401fc4: call ds:[ecx+eax+0x4]
         // 00401fc8: add esp, 0xc
         // 00401fcb: mov b1 ds:[esi+0x10], b1 al
         // 00401fce: or ss:[ebp+0xfffffffffffffffc], 0xffffffffffffffff
         // 00401fd2: xor eax, eax
         // 00401fd4: mov ecx, ss:[ebp+0xfffffffffffffff4]
         // 00401fd7: mov fs:[0x0], ecx
         // 00401fde: pop edi
         // 00401fdf: pop esi
         // 00401fe0: pop ebx
         // 00401fe1: leave 
         // 00401fe2: retn b2 0x4
      [-]558bec83ec1053568b35????????57c645ff00e8be2600008b0033ff8bce3bc77407
         // 00401ff6: push ebp
         // 00401ff7: mov ebp, esp
         // 00401ff9: sub esp, 0x10
         // 00401ffc: push ebx
         // 00401ffd: push esi
         // 00401ffe: mov esi, ds:[0x42c9f0]
         // 00402004: push edi
         // 00402005: mov b1 ss:[ebp+0xffffffffffffffff], b1 0x0
         // 00402009: call 0x4046cc
         // 0040200e: mov eax, ds:[eax]
         // 00402010: xor edi, edi
         // 00402012: mov ecx, esi
         // 00402014: cmp eax, edi
         // 00402016: jz 0x40201f
      [-]c60100414875f9
         // 00402018: mov b1 ds:[ecx], b1 0x0
         // 0040201b: inc ecx
         // 0040201c: dec eax
         // 0040201d: jnz 0x402018
      [-]6a108d460c68????????50e8310d010083c40c897e08e892260000688c9c4200e88d3c000084c00f84f7000000
         // 0040201f: push 0x10
         // 00402021: lea eax, ds:[esi+0xc]
         // 00402024: push 0x428e44
         // 00402029: push eax
         // 0040202a: call _memcpy
         // 0040202f: add esp, 0xc
         // 00402032: mov ds:[esi+0x8], edi
         // 00402035: call 0x4046cc
         // 0040203a: push stru_429C8C.DebugInfo
         // 0040203f: call 0x405cd1
         // 00402044: test b1 al, b1 al
         // 00402046: jz 0x402143
      [-]897df8397d080f8c8d000000
         // 0040204c: mov ss:[ebp+0xfffffffffffffff8], edi
         // 0040204f: cmp ss:[ebp+0x8], edi
         // 00402052: jl 0x4020e5
      [-]a1????????8b4df88b1c888b35????????8b46088b4b248d44086b8bfe8945f4e84f2600008b006bc003992bc2d1f83945f47f3d
         // 00402058: mov eax, ds:[0x429c7c]
         // 0040205d: mov ecx, ss:[ebp+0xfffffffffffffff8]
         // 00402060: mov ebx, ds:[eax+ecx*0x4]
         // 00402063: mov esi, ds:[0x42c9f0]
         // 00402069: mov eax, ds:[esi+0x8]
         // 0040206c: mov ecx, ds:[ebx+0x24]
         // 0040206f: lea eax, ds:[eax+ecx+0x6b]
         // 00402073: mov edi, esi
         // 00402075: mov ss:[ebp+0xfffffffffffffff4], eax
         // 00402078: call 0x4046cc
         // 0040207d: mov eax, ds:[eax]
         // 0040207f: imul eax, b1 0x3
         // 00402082: cdq 
         // 00402083: sub eax, edx
         // 00402085: sar eax, b1 0x1
         // 00402087: cmp ss:[ebp+0xfffffffffffffff4], eax
         // 0040208a: jg 0x4020c9
      [-]8b47048943148b46088d44071c8b7b2483c73a5753508945f4e8b60c01008b45f4017e0883c40c6a1003c768????????50e89e0c010083c40c83460810
         // 0040208c: mov eax, ds:[edi+0x4]
         // 0040208f: mov ds:[ebx+0x14], eax
         // 00402092: mov eax, ds:[esi+0x8]
         // 00402095: lea eax, ds:[edi+eax+0x1c]
         // 00402099: mov edi, ds:[ebx+0x24]
         // 0040209c: add edi, 0x3a
         // 0040209f: push edi
         // 004020a0: push ebx
         // 004020a1: push eax
         // 004020a2: mov ss:[ebp+0xfffffffffffffff4], eax
         // 004020a5: call _memcpy
         // 004020aa: mov eax, ss:[ebp+0xfffffffffffffff4]
         // 004020ad: add ds:[esi+0x8], edi
         // 004020b0: add esp, 0xc
         // 004020b3: push 0x10
         // 004020b5: add eax, edi
         // 004020b7: push 0x428e44
         // 004020bc: push eax
         // 004020bd: call _memcpy
         // 004020c2: add esp, 0xc
         // 004020c5: add ds:[esi+0x8], 0x10
      [-]8b4df8a1????????8b04888048340141894df83b4d080f8e73ffffff
         // 004020c9: mov ecx, ss:[ebp+0xfffffffffffffff8]
         // 004020cc: mov eax, ds:[0x429c7c]
         // 004020d1: mov eax, ds:[eax+ecx*0x4]
         // 004020d4: or b1 ds:[eax+0x34], b1 0x1
         // 004020d8: inc ecx
         // 004020d9: mov ss:[ebp+0xfffffffffffffff8], ecx
         // 004020dc: cmp ecx, ss:[ebp+0x8]
         // 004020df: jle 0x402058
      [-]e8e2250000688c9c4200e8fd3b0000a1????????8d70088b0e8945f485c97405
         // 004020e5: call 0x4046cc
         // 004020ea: push stru_429C8C.DebugInfo
         // 004020ef: call 0x405cf1
         // 004020f4: mov eax, ds:[0x42c9f0]
         // 004020f9: lea esi, ds:[eax+0x8]
         // 004020fc: mov ecx, ds:[esi]
         // 004020fe: mov ss:[ebp+0xfffffffffffffff4], eax
         // 00402101: test ecx, ecx
         // 00402103: jz 0x40210a
      [-]83c1f0890e
         // 00402105: add ecx, 0xfffffffffffffff0
         // 00402108: mov ds:[esi], ecx
      [-]8b3e8d580483c718e8b525000085db7409
         // 0040210a: mov edi, ds:[esi]
         // 0040210c: lea ebx, ds:[eax+0x4]
         // 0040210f: add edi, 0x18
         // 00402112: call 0x4046cc
         // 00402117: test ebx, ebx
         // 00402119: jz 0x402124
      [-]5753e8e4f6ffffeb02
         // 0040211b: push edi
         // 0040211c: push ebx
         // 0040211d: call 0x401806
         // 00402122: jmp 0x402126
      [-]8b4df489018945f06a048d45f0508b068d44081c50e8200c010083c40c
         // 00402126: mov ecx, ss:[ebp+0xfffffffffffffff4]
         // 00402129: mov ds:[ecx], eax
         // 0040212b: mov ss:[ebp+0xfffffffffffffff0], eax
         // 0040212e: push 0x4
         // 00402130: lea eax, ss:[ebp+0xfffffffffffffff0]
         // 00402133: push eax
         // 00402134: mov eax, ds:[esi]
         // 00402136: lea eax, ds:[eax+ecx+0x1c]
         // 0040213a: push eax
         // 0040213b: call _memcpy
         // 00402140: add esp, 0xc
      [-]a1????????837808007604
         // 00402143: mov eax, ds:[0x42c9f0]
         // 00402148: cmp ds:[eax+0x8], 0x0
         // 0040214c: jbe 0x402152
      [-]c645ff01
         // 0040214e: mov b1 ss:[ebp+0xffffffffffffffff], b1 0x1
      [-]8a45ff5f5e5bc9c3
         // 00402152: mov b1 al, b1 ss:[ebp+0xffffffffffffffff]
         // 00402155: pop edi
         // 00402156: pop esi
         // 00402157: pop ebx
         // 00402158: leave 
         // 00402159: retn 
      [-]558bec83e4f883ec1c535633db578bf0885c240f
         // 0040215a: push ebp
         // 0040215b: mov ebp, esp
         // 0040215d: and esp, 0xfffffffffffffff8
         // 00402160: sub esp, 0x1c
         // 00402163: push ebx
         // 00402164: push esi
         // 00402165: xor ebx, ebx
         // 00402167: push edi
         // 00402168: mov esi, eax
         // 0040216a: mov b1 ss:[esp+0xf], b1 bl
      [-]6a14598d442414
         // 0040216e: push 0x14
         // 00402170: pop ecx
         // 00402171: lea eax, ss:[esp+0x14]
      [-]8818404975fa
         // 00402175: mov b1 ds:[eax], b1 bl
         // 00402177: inc eax
         // 00402178: dec ecx
         // 00402179: jnz 0x402175
      [-]e84c250000894424148b068944241ca1????????894424188b4508894424208d44241050538d44241c5068????????68????????53885c243cff1548f241008bf883ffff743e
         // 0040217b: call 0x4046cc
         // 00402180: mov ss:[esp+0x14], eax
         // 00402184: mov eax, ds:[esi]
         // 00402186: mov ss:[esp+0x1c], eax
         // 0040218a: mov eax, ds:[0x42c9f0]
         // 0040218f: mov ss:[esp+0x18], eax
         // 00402193: mov eax, ss:[ebp+0x8]
         // 00402196: mov ss:[esp+0x20], eax
         // 0040219a: lea eax, ss:[esp+0x10]
         // 0040219e: push eax
         // 0040219f: push ebx
         // 004021a0: lea eax, ss:[esp+0x1c]
         // 004021a4: push eax
         // 004021a5: push 0x401f98
         // 004021aa: push 0x10000
         // 004021af: push ebx
         // 004021b0: mov b1 ss:[esp+0x3c], b1 bl
         // 004021b4: call ds:[CreateThread]
         // 004021ba: mov edi, eax
         // 004021bc: cmp edi, 0xffffffffffffffff
         // 004021bf: jz 0x4021ff
      [-]e8062500008b0e6bc918ff74081057ff1554f2410083f8ff7407
         // 004021c1: call 0x4046cc
         // 004021c6: mov ecx, ds:[esi]
         // 004021c8: imul ecx, b1 0x18
         // 004021cb: push ds:[eax+ecx+0x10]
         // 004021cf: push edi
         // 004021d0: call ds:[WaitForSingleObject]
         // 004021d6: cmp eax, 0xffffffffffffffff
         // 004021d9: jz 0x4021e2
      [-]3d????????7516
         // 004021db: cmp eax, 0x102
         // 004021e0: jnz 0x4021f8
      [-]e8e52400008b0e416bc918ff04085357ff1550f24100
         // 004021e2: call 0x4046cc
         // 004021e7: mov ecx, ds:[esi]
         // 004021e9: inc ecx
         // 004021ea: imul ecx, b1 0x18
         // 004021ed: inc ds:[eax+ecx]
         // 004021f0: push ebx
         // 004021f1: push edi
         // 004021f2: call ds:[TerminateThread]
      [-]57ff154cf24100
         // 004021f8: push edi
         // 004021f9: call ds:[CloseHandle]
      [-]385c24247545
         // 004021ff: cmp b1 ss:[esp+0x24], b1 bl
         // 00402203: jnz 0x40224a
      [-]e8c2240000506a7858e83a190000ff06e8b22400008bc88b0633d2f7b1????????89168bfae89d2400008b55088bcf6bc9183b540814773b
         // 00402205: call 0x4046cc
         // 0040220a: push eax
         // 0040220b: push 0x78
         // 0040220d: pop eax
         // 0040220e: call 0x403b4d
         // 00402213: inc ds:[esi]
         // 00402215: call 0x4046cc
         // 0040221a: mov ecx, eax
         // 0040221c: mov eax, ds:[esi]
         // 0040221e: xor edx, edx
         // 00402220: div ds:[ecx+0x304]
         // 00402226: mov ds:[esi], edx
         // 00402228: mov edi, edx
         // 0040222a: call 0x4046cc
         // 0040222f: mov edx, ss:[ebp+0x8]
         // 00402232: mov ecx, edi
         // 00402234: imul ecx, b1 0x18
         // 00402237: cmp edx, ds:[eax+ecx+0x14]
         // 0040223b: ja 0x402278
      [-]8b450c3b380f8526ffffff
         // 0040223d: mov eax, ss:[ebp+0xc]
         // 00402240: cmp edi, ds:[eax]
         // 00402242: jnz 0x40216e
      [-]8b068b4d0c8901e8cf1600008bf0e86f24000089b0????????e8642400008998????????e8663f0000c644240f01
         // 0040224a: mov eax, ds:[esi]
         // 0040224c: mov ecx, ss:[ebp+0xc]
         // 0040224f: mov ds:[ecx], eax
         // 00402251: call 0x403925
         // 00402256: mov esi, eax
         // 00402258: call 0x4046cc
         // 0040225d: mov ds:[eax+0x580c], esi
         // 00402263: call 0x4046cc
         // 00402268: mov ds:[eax+0x5950], ebx
         // 0040226e: call 0x4061d9
         // 00402273: mov b1 ss:[esp+0xf], b1 0x1
      [-]8a44240f5f5e5b8be55dc3
         // 00402278: mov b1 al, b1 ss:[esp+0xf]
         // 0040227c: pop edi
         // 0040227d: pop esi
         // 0040227e: pop ebx
         // 0040227f: mov esp, ebp
         // 00402281: pop ebp
         // 00402282: retn 
      [-]558bec83ec10535657e8bc0300008365fc008365f4008b5d08
         // 00402283: push ebp
         // 00402284: mov ebp, esp
         // 00402286: sub esp, 0x10
         // 00402289: push ebx
         // 0040228a: push esi
         // 0040228b: push edi
         // 0040228c: call 0x40264d
         // 00402291: and ss:[ebp+0xfffffffffffffffc], 0x0
         // 00402295: and ss:[ebp+0xfffffffffffffff4], 0x0
         // 00402299: mov ebx, ss:[ebp+0x8]
      [-]833d????????007512
         // 0040229c: cmp ds:[0x42c9f0], 0x0
         // 004022a3: jnz 0x4022b7
      [-]e8acfbffffa3????????85c00f8422010000
         // 004022a5: call 0x401e56
         // 004022aa: mov ds:[0x42c9f0], eax
         // 004022af: test eax, eax
         // 004022b1: jz 0x4023d9
      [-]e810240000506a0558e888180000833d????????0074e9
         // 004022b7: call 0x4046cc
         // 004022bc: push eax
         // 004022bd: push 0x5
         // 004022bf: pop eax
         // 004022c0: call 0x403b4d
         // 004022c5: cmp ds:[0x429c80], 0x0
         // 004022cc: jz 0x4022b7
      [-]6a1c5ee84ffbffff8b4dfc6bc9188b7c191433d289450885c07e1d
         // 004022ce: push 0x1c
         // 004022d0: pop esi
         // 004022d1: call 0x401e25
         // 004022d6: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 004022d9: imul ecx, b1 0x18
         // 004022dc: mov edi, ds:[ecx+ebx+0x14]
         // 004022e0: xor edx, edx
         // 004022e2: mov ss:[ebp+0x8], eax
         // 004022e5: test eax, eax
         // 004022e7: jle 0x402306
      [-]a1????????8b04908b48248d44314e3bc7770a
         // 004022e9: mov eax, ds:[0x429c7c]
         // 004022ee: mov eax, ds:[eax+edx*0x4]
         // 004022f1: mov ecx, ds:[eax+0x24]
         // 004022f4: lea eax, ds:[ecx+esi+0x4e]
         // 004022f8: cmp eax, edi
         // 004022fa: ja 0x402306

  }
  condition:
    all of them
}
