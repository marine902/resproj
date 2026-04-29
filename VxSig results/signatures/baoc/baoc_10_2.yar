rule baoc_10_2 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         e8c6250000c3
         // 0040132f: call 0x4038fa
         // 00401334: retn 
      [-]a9????????4c
         // 00401335: test eax, 0xffffffffce12a404
         // 0040133a: dec esp
      [-]558bec83ec108b450825????????b9????????eb05
         // 0040133b: push ebp
         // 0040133c: mov ebp, esp
         // 0040133e: sub esp, 0x10
         // 00401341: mov eax, ss:[ebp+0x8]
         // 00401344: and eax, 0xffffffffffff0000
         // 00401349: mov ecx, 0x5a4d
         // 0040134e: jmp 0x401355
      [-]2d????????
         // 00401350: sub eax, 0x10000
      [-]66390875f6
         // 00401355: cmp b2 ds:[eax], b2 cx
         // 00401358: jnz 0x401350
      [-]0fb7483c538945fc8d440118b9????????56576639080f8598000000
         // 0040135a: movzx ecx, b2 ds:[eax+0x3c]
         // 0040135e: push ebx
         // 0040135f: mov ss:[ebp+0xfffffffffffffffc], eax
         // 00401362: lea eax, ds:[ecx+eax+0x18]
         // 00401366: mov ecx, 0x10b
         // 0040136b: push esi
         // 0040136c: push edi
         // 0040136d: cmp b2 ds:[eax], b2 cx
         // 00401370: jnz 0x40140e
      [-]8b70600375fc8b7e208b4614037dfc8945f48b5d0c4b33c033c9fec8
         // 00401376: mov esi, ds:[eax+0x60]
         // 00401379: add esi, ss:[ebp+0xfffffffffffffffc]
         // 0040137c: mov edi, ds:[esi+0x20]
         // 0040137f: mov eax, ds:[esi+0x14]
         // 00401382: add edi, ss:[ebp+0xfffffffffffffffc]
         // 00401385: mov ss:[ebp+0xfffffffffffffff4], eax
         // 00401388: mov ebx, ss:[ebp+0xc]
         // 0040138b: dec ebx
         // 0040138c: xor eax, eax
         // 0040138e: xor ecx, ecx
         // 00401390: dec b1 al
      [-]fec0438a0b85c975f7
         // 00401392: inc b1 al
         // 00401394: inc ebx
         // 00401395: mov b1 cl, b1 ds:[ebx]
         // 00401397: test ecx, ecx
         // 00401399: jnz 0x401392
      [-]214df8394df48945f07668
         // 0040139b: and ss:[ebp+0xfffffffffffffff8], ecx
         // 0040139e: cmp ss:[ebp+0xfffffffffffffff4], ecx
         // 004013a1: mov ss:[ebp+0xfffffffffffffff0], eax
         // 004013a4: jbe 0x40140e
      [-]8b070345fc8bd84b33c0fec8
         // 004013a6: mov eax, ds:[edi]
         // 004013a8: add eax, ss:[ebp+0xfffffffffffffffc]
         // 004013ab: mov ebx, eax
         // 004013ad: dec ebx
         // 004013ae: xor eax, eax
         // 004013b0: dec b1 al
      [-]fec0438a0b80f90075f6
         // 004013b2: inc b1 al
         // 004013b4: inc ebx
         // 004013b5: mov b1 cl, b1 ds:[ebx]
         // 004013b7: cmp b1 cl, b1 0x0
         // 004013ba: jnz 0x4013b2
      [-]3b45f07512
         // 004013bc: cmp eax, ss:[ebp+0xfffffffffffffff0]
         // 004013bf: jnz 0x4013d3
      [-]8b070345fcff750c50e8971b000085c0740e
         // 004013c1: mov eax, ds:[edi]
         // 004013c3: add eax, ss:[ebp+0xfffffffffffffffc]
         // 004013c6: push ss:[ebp+0xc]
         // 004013c9: push eax
         // 004013ca: call 0x402f66
         // 004013cf: test eax, eax
         // 004013d1: jz 0x4013e1
      [-]83c704ff45f88b45f83b45f472c5
         // 004013d3: add edi, 0x4
         // 004013d6: inc ss:[ebp+0xfffffffffffffff8]
         // 004013d9: mov eax, ss:[ebp+0xfffffffffffffff8]
         // 004013dc: cmp eax, ss:[ebp+0xfffffffffffffff4]
         // 004013df: jb 0x4013a6
      [-]8b45f83b45f47325
         // 004013e1: mov eax, ss:[ebp+0xfffffffffffffff8]
         // 004013e4: cmp eax, ss:[ebp+0xfffffffffffffff4]
         // 004013e7: jnb 0x40140e
      [-]8b4e10492bc18b4e2403c803c88b45fc03c80fb7018b4e1c8d04818b4dfc8b040103c1eb02
         // 004013e9: mov ecx, ds:[esi+0x10]
         // 004013ec: dec ecx
         // 004013ed: sub eax, ecx
         // 004013ef: mov ecx, ds:[esi+0x24]
         // 004013f2: add ecx, eax
         // 004013f4: add ecx, eax
         // 004013f6: mov eax, ss:[ebp+0xfffffffffffffffc]
         // 004013f9: add ecx, eax
         // 004013fb: movzx eax, b2 ds:[ecx]
         // 004013fe: mov ecx, ds:[esi+0x1c]
         // 00401401: lea eax, ds:[ecx+eax*0x4]
         // 00401404: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 00401407: mov eax, ds:[ecx+eax]
         // 0040140a: add eax, ecx
         // 0040140c: jmp 0x401410
      [-]5f5e5b8be55dc20800
         // 00401410: pop edi
         // 00401411: pop esi
         // 00401412: pop ebx
         // 00401413: mov esp, ebp
         // 00401415: pop ebp
         // 00401416: retn b2 0x8
      [-]8b3d????????eb0003f88d0d????????57eb00c3
         // 00402bd5: mov edi, ds:[0x4046a0]
         // 00402bdb: jmp 0x402bdd
         // 00402bdd: add edi, eax
         // 00402bdf: lea ecx, ds:[0x4040f2]
         // 00402be5: push edi
         // 00402be6: jmp 0x402be8
         // 00402be8: retn 
      [-]ba????????8b0aeb05
         // 00402cd3: mov edx, 0x4046ac
         // 00402cd8: mov ecx, ds:[edx]
         // 00402cda: jmp 0x402ce1
      [-]8b7a048b0783c7048bf78bde03f8eb02
         // 00402ce1: mov edi, ds:[edx+0x4]
         // 00402ce4: mov eax, ds:[edi]
         // 00402ce6: add edi, 0x4
         // 00402ce9: mov esi, edi
         // 00402ceb: mov ebx, esi
         // 00402ced: add edi, eax
         // 00402cef: jmp 0x402cf3
      [-]8bd74a2bc883e90452ba????????890a897a045a
         // 00402cf3: mov edx, edi
         // 00402cf5: dec edx
         // 00402cf6: sub ecx, eax
         // 00402cf8: sub ecx, 0x4
         // 00402cfb: push edx
         // 00402cfc: mov edx, 0x4046ac
         // 00402d01: mov ds:[edx], ecx
         // 00402d03: mov ds:[edx+0x4], edi
         // 00402d06: pop edx
      [-]8a078a2602255341400032c4eb03
         // 00402d07: mov b1 al, b1 ds:[edi]
         // 00402d09: mov b1 ah, b1 ds:[esi]
         // 00402d0b: add b1 ah, b1 ds:[0x404153]
         // 00402d11: xor b1 al, b1 ah
         // 00402d13: jmp 0x402d18
      [-]88073bf27407
         // 00402d18: mov b1 ds:[edi], b1 al
         // 00402d1a: cmp esi, edx
         // 00402d1c: jz 0x402d25
      [-]474975e4
         // 00402d1f: inc edi
         // 00402d20: dec ecx
         // 00402d21: jnz 0x402d07
      [-]8bfe6a2568????????68????????eb03
         // 00402d2e: mov edi, esi
         // 00402d30: push 0x25
         // 00402d32: push 0x4046ac
         // 00402d37: push 0x111
         // 00402d3c: jmp 0x402d41
      [-]ff35????????eb05
         // 00402d41: push ds:[0x404650]
         // 00402d47: jmp 0x402d4e
      [-]8b0d????????8b3d????????eb05
         // 00402d54: mov ecx, ds:[0x4046ac]
         // 00402d5a: mov edi, ds:[0x4046b0]
         // 00402d60: jmp 0x402d67
      [-]8b35????????
         // 00402d67: mov esi, ds:[0x4046a0]
      [-]8a06880746474975f7
         // 00402d6d: mov b1 al, b1 ds:[esi]
         // 00402d6f: mov b1 ds:[edi], b1 al
         // 00402d71: inc esi
         // 00402d72: inc edi
         // 00402d73: dec ecx
         // 00402d74: jnz 0x402d6d
      [-]8b35????????8b0d????????51eb05
         // 00402d76: mov esi, ds:[0x40414e]
         // 00402d7c: mov ecx, ds:[0x40414a]
         // 00402d82: push ecx
         // 00402d83: jmp 0x402d8a
      [-]03ce890d????????598b0646469046468b3d????????8bde03d8891d????????8bd6eb05
         // 00402d8a: add ecx, esi
         // 00402d8c: mov ds:[0x404630], ecx
         // 00402d92: pop ecx
         // 00402d93: mov eax, ds:[esi]
         // 00402d95: inc esi
         // 00402d96: inc esi
         // 00402d97: nop 
         // 00402d98: inc esi
         // 00402d99: inc esi
         // 00402d9a: mov edi, ds:[0x4046a0]
         // 00402da0: mov ebx, esi
         // 00402da2: add ebx, eax
         // 00402da4: mov ds:[0x40462c], ebx
         // 00402daa: mov edx, esi
         // 00402dac: jmp 0x402db3
      [-]03f0b9????????0fb60240
         // 00402db3: add esi, eax
         // 00402db5: mov ecx, 0x0
         // 00402dba: movzx eax, b1 ds:[edx]
         // 00402dbd: inc eax
      [-]3bd37379
         // 00402dbe: cmp edx, ebx
         // 00402dc0: jnb 0x402e3b
      [-]3bc17308
         // 00402dc2: cmp eax, ecx
         // 00402dc4: jnb 0x402dce
      [-]2bc18bc885c97409
         // 00402dce: sub eax, ecx
         // 00402dd0: mov ecx, eax
         // 00402dd2: test ecx, ecx
         // 00402dd4: jz 0x402ddf
      [-]8a06880746474975f7
         // 00402dd6: mov b1 al, b1 ds:[esi]
         // 00402dd8: mov b1 ds:[edi], b1 al
         // 00402dda: inc esi
         // 00402ddb: inc edi
         // 00402ddc: dec ecx
         // 00402ddd: jnz 0x402dd6
      [-]428a02420fb60a85c97408
         // 00402ddf: inc edx
         // 00402de0: mov b1 al, b1 ds:[edx]
         // 00402de2: inc edx
         // 00402de3: movzx ecx, b1 ds:[edx]
         // 00402de6: test ecx, ecx
         // 00402de8: jz 0x402df2
      [-]8807474975fa
         // 00402deb: mov b1 ds:[edi], b1 al
         // 00402ded: inc edi
         // 00402dee: dec ecx
         // 00402def: jnz 0x402deb
      [-]420fb602eb05
         // 00402df2: inc edx
         // 00402df3: movzx eax, b1 ds:[edx]
         // 00402df6: jmp 0x402dfd
      [-]fec180f9007521
         // 00402dfd: inc b1 cl
         // 00402dff: cmp b1 cl, b1 0x0
         // 00402e02: jnz 0x402e25
      [-]fec03c00750e
         // 00402e04: inc b1 al
         // 00402e06: cmp b1 al, b1 0x0
         // 00402e08: jnz 0x402e18
      [-]0fb7024242eb09
         // 00402e11: movzx eax, b2 ds:[edx]
         // 00402e14: inc edx
         // 00402e15: inc edx
         // 00402e16: jmp 0x402e21
      [-]b000fec8eb03
         // 00402e18: mov b1 al, b1 0x0
         // 00402e1a: dec b1 al
         // 00402e1c: jmp 0x402e21
      [-]fec9eb12
         // 00402e21: dec b1 cl
         // 00402e23: jmp 0x402e37
      [-]fec9fec03c007508
         // 00402e25: dec b1 cl
         // 00402e27: inc b1 al
         // 00402e29: cmp b1 al, b1 0x0
         // 00402e2b: jnz 0x402e35
      [-]420fb7024242eb02
         // 00402e2d: inc edx
         // 00402e2e: movzx eax, b2 ds:[edx]
         // 00402e31: inc edx
         // 00402e32: inc edx
         // 00402e33: jmp 0x402e37
      [-]8b0d????????2bceeb05
         // 00402e3b: mov ecx, ds:[0x404630]
         // 00402e41: sub ecx, esi
         // 00402e43: jmp 0x402e4a
      [-]85c97409
         // 00402e4a: test ecx, ecx
         // 00402e4c: jz 0x402e57
      [-]8a06880746474975f7
         // 00402e4e: mov b1 al, b1 ds:[esi]
         // 00402e50: mov b1 ds:[edi], b1 al
         // 00402e52: inc esi
         // 00402e53: inc edi
         // 00402e54: dec ecx
         // 00402e55: jnz 0x402e4e
      [-]8b3d????????eb03
         // 00402e57: mov edi, ds:[0x4046a0]
         // 00402e5d: jmp 0x402e62
      [-]81ef????????893d????????eb03
         // 00402e62: sub edi, 0x3fd
         // 00402e68: mov ds:[0x4046a0], edi
         // 00402e6e: jmp 0x402e73
      [-]558bec56578b7d0c33c033c98b7508
         // 00402f66: push ebp
         // 00402f67: mov ebp, esp
         // 00402f69: push esi
         // 00402f6a: push edi
         // 00402f6b: mov edi, ss:[ebp+0xc]
         // 00402f6e: xor eax, eax
         // 00402f70: xor ecx, ecx
         // 00402f72: mov esi, ss:[ebp+0x8]
      [-]8a068a0f3bc17508
         // 00402f75: mov b1 al, b1 ds:[esi]
         // 00402f77: mov b1 cl, b1 ds:[edi]
         // 00402f79: cmp eax, ecx
         // 00402f7b: jnz 0x402f85
      [-]85c97407
         // 00402f7d: test ecx, ecx
         // 00402f7f: jz 0x402f88
      [-]4647ebf0
         // 00402f81: inc esi
         // 00402f82: inc edi
         // 00402f83: jmp 0x402f75
      [-]5f5e8be55dc20800
         // 00402f88: pop edi
         // 00402f89: pop esi
         // 00402f8a: mov esp, ebp
         // 00402f8c: pop ebp
         // 00402f8d: retn b2 0x8
      [-]558bec83c4a08b450c83f8010f855d010000
         // 00403153: push ebp
         // 00403154: mov ebp, esp
         // 00403156: add esp, 0xffffffffffffffa0
         // 00403159: mov eax, ss:[ebp+0xc]
         // 0040315c: cmp eax, 0x1
         // 0040315f: jnz 0x4032c2
      [-]8b7d086a00ff35????????6a02576a2868????????6a0a6a0a68????????68????????68????????6a00ff15
         // 00403165: mov edi, ss:[ebp+0x8]
         // 00403168: push 0x0
         // 0040316a: push ds:[0x4040f2]
         // 00403170: push 0x2
         // 00403172: push edi
         // 00403173: push 0x28
         // 00403175: push 0x140
         // 0040317a: push 0xa
         // 0040317c: push 0xa
         // 0040317e: push 0x10000001
         // 00403183: push 0x404559
         // 00403188: push 0x404592
         // 0040318d: push 0x0
         // 0040318f: call ds:[0x404050]
      [-]a3????????a3????????6a1c6a0068????????ff7508ff15
         // 004031a2: mov ds:[0x4046b8], eax
         // 004031a7: mov ds:[0x404640], eax
         // 004031ac: push 0x1c
         // 004031ae: push 0x0
         // 004031b0: push 0x111
         // 004031b5: push ss:[ebp+0x8]
         // 004031b8: call ds:[0x404060]
      [-]6a00ff35????????6a015768????????68????????6a466a0a68????????6a0068????????6a00ff15
         // 004031be: push 0x0
         // 004031c0: push ds:[0x4040f2]
         // 004031c6: push 0x1
         // 004031c8: push edi
         // 004031c9: push 0x1ae
         // 004031ce: push 0x1f4
         // 004031d3: push 0x46
         // 004031d5: push 0xa
         // 004031d7: push 0x40000000
         // 004031dc: push 0x0
         // 004031de: push 0x404585
         // 004031e3: push 0x0
         // 004031e5: call ds:[0x404050]
      [-]a3????????ff15
         // 004031eb: mov ds:[0x404638], eax
         // 004031f0: call ds:[0x404008]
      [-]a3????????eb03
         // 004031f6: mov ds:[0x40413a], eax
         // 004031fb: jmp 0x403200
      [-]6a00ff35????????6a02ff750c6a2268????????68????????6a0a68????????68????????68????????6a00ff15
         // 00403200: push 0x0
         // 00403202: push ds:[0x4040f2]
         // 00403208: push 0x2
         // 0040320a: push ss:[ebp+0xc]
         // 0040320d: push 0x22
         // 0040320f: push 0xa6
         // 00403214: push 0x17c
         // 00403219: push 0xa
         // 0040321b: push 0x40000001
         // 00403220: push 0x404559
         // 00403225: push 0x404585
         // 0040322a: push 0x0
         // 0040322c: call ds:[0x404050]
      [-]a3????????a3????????6a1d68????????68????????ff7508ff15
         // 00403238: mov ds:[0x40413a], eax
         // 0040323d: mov ds:[0x404640], eax
         // 00403242: push 0x1d
         // 00403244: push 0x4040c8
         // 00403249: push 0x111
         // 0040324e: push ss:[ebp+0x8]
         // 00403251: call ds:[0x404060]
      [-]a3????????6a0268????????68????????68????????68????????6a01ff7508ff15
         // 0040325c: mov ds:[0x404648], eax
         // 00403261: push 0x2
         // 00403263: push 0x1fe
         // 00403268: push 0x21c
         // 0040326d: push 0xfffffffffffff3f8
         // 00403272: push 0xfffffffffffff18c
         // 00403277: push 0x1
         // 00403279: push ss:[ebp+0x8]
         // 0040327c: call ds:[0x404070]
      [-]68????????68
         // 00403282: push 0x404567
         // 00403287: push 0x404678
      [-]c705????????????????c705????????????????68
         // 00403292: mov ds:[0x40466c], 0x14
         // 0040329c: mov ds:[0x40465c], 0xc
         // 004032a6: push 0x40465c
      [-]85c0a3????????e935060000
         // 004032b1: test eax, eax
         // 004032b3: mov ds:[0x40464c], eax
         // 004032b8: jmp 0x4038f2
      [-]3d????????7540
         // 004032c2: cmp eax, 0x401
         // 004032c7: jnz 0x403309
      [-]b9????????41418b5510eb03
         // 004032c9: mov ecx, 0x4
         // 004032ce: inc ecx
         // 004032cf: inc ecx
         // 004032d0: mov edx, ss:[ebp+0x10]
         // 004032d3: jmp 0x4032d8
      [-]8b3a4242eb03
         // 004032d8: mov edi, ds:[edx]
         // 004032da: inc edx
         // 004032db: inc edx
         // 004032dc: jmp 0x4032e1
      [-]42428b32eb05
         // 004032e1: inc edx
         // 004032e2: inc edx
         // 004032e3: mov esi, ds:[edx]
         // 004032e5: jmp 0x4032ec
      [-]8b551441
         // 004032ec: mov edx, ss:[ebp+0x14]
         // 004032ef: inc ecx
      [-]8a078806472bf24975f6
         // 004032f0: mov b1 al, b1 ds:[edi]
         // 004032f2: mov b1 ds:[esi], b1 al
         // 004032f4: inc edi
         // 004032f5: sub esi, edx
         // 004032f7: dec ecx
         // 004032f8: jnz 0x4032f0
      [-]e9ee050000
         // 004032ff: jmp 0x4038f2
      [-]83f8027516
         // 00403309: cmp eax, 0x2
         // 0040330c: jnz 0x403324
      [-]a1????????50ff15
         // 0040330e: mov eax, ds:[0x40413a]
         // 00403313: push eax
         // 00403314: call ds:[0x404044]
      [-]e9d3050000
         // 0040331a: jmp 0x4038f2
      [-]83f80f753a
         // 00403324: cmp eax, 0xf
         // 00403327: jnz 0x403363
      [-]8d45d850ff7508ff15
         // 00403329: lea eax, ss:[ebp+0xffffffffffffffd8]
         // 0040332c: push eax
         // 0040332d: push ss:[ebp+0x8]
         // 00403330: call ds:[0x404030]
      [-]6a01576a0868????????56ff15
         // 0040333b: push 0x1
         // 0040333d: push edi
         // 0040333e: push 0x8
         // 00403340: push 0x404574
         // 00403345: push esi
         // 00403346: call ds:[0x404038]
      [-]8d45d850ff7508ff15
         // 0040334c: lea eax, ss:[ebp+0xffffffffffffffd8]
         // 0040334f: push eax
         // 00403350: push ss:[ebp+0x8]
         // 00403353: call ds:[0x40403c]
      [-]e994050000
         // 00403359: jmp 0x4038f2
      [-]83f805753e
         // 00403363: cmp eax, 0x5
         // 00403366: jnz 0x4033a6
      [-]8d45f050ff7508ff15
         // 00403368: lea eax, ss:[ebp+0xfffffffffffffff0]
         // 0040336b: push eax
         // 0040336c: push ss:[ebp+0x8]
         // 0040336f: call ds:[0x404074]
      [-]8b45f88b4df02bc1508b45fc8b4df42bc18bc8582bc1506a0068????????ff7508ff15
         // 00403375: mov eax, ss:[ebp+0xfffffffffffffff8]
         // 00403378: mov ecx, ss:[ebp+0xfffffffffffffff0]
         // 0040337b: sub eax, ecx
         // 0040337d: push eax
         // 0040337e: mov eax, ss:[ebp+0xfffffffffffffffc]
         // 00403381: mov ecx, ss:[ebp+0xfffffffffffffff4]
         // 00403384: sub eax, ecx
         // 00403386: mov ecx, eax
         // 00403388: pop eax
         // 00403389: sub eax, ecx
         // 0040338b: push eax
         // 0040338c: push 0x0
         // 0040338e: push 0x111
         // 00403393: push ss:[ebp+0x8]
         // 00403396: call ds:[0x404060]
      [-]e951050000
         // 0040339c: jmp 0x4038f2
      [-]3d????????0f852d050000
         // 004033a6: cmp eax, 0x111
         // 004033ab: jnz 0x4038de
      [-]8b45108b5d14e9c7000000
         // 004033b1: mov eax, ss:[ebp+0x10]
         // 004033b4: mov ebx, ss:[ebp+0x14]
         // 004033b7: jmp 0x403483
      [-]83fb1b7530
         // 00403483: cmp ebx, 0x1b
         // 00403486: jnz 0x4034b8
      [-]6a0068????????6a036a00eb04
         // 00403494: push 0x0
         // 00403496: push 0x80
         // 0040349b: push 0x3
         // 0040349d: push 0x0
         // 0040349f: jmp 0x4034a5
      [-]6a0168????????68????????ffd0e93c040000
         // 004034a5: push 0x1
         // 004034a7: push 0xffffffff80000000
         // 004034ac: push 0x404574
         // 004034b1: call eax
         // 004034b3: jmp 0x4038f4
      [-]83fb1c753d
         // 004034b8: cmp ebx, 0x1c
         // 004034bb: jnz 0x4034fa
      [-]6a1b6a0068????????ff7508ff15
         // 004034c2: push 0x1b
         // 004034c4: push 0x0
         // 004034c6: push 0x111
         // 004034cb: push ss:[ebp+0x8]
         // 004034ce: call ds:[0x404060]
      [-]d1e0a3????????83f8047305
         // 004034e4: shl eax, b1 0x1
         // 004034e6: mov ds:[0x4046b4], eax
         // 004034eb: cmp eax, 0x4
         // 004034ee: jnb 0x4034f5
      [-]e919feffff
         // 004034f0: jmp 0x40330e
      [-]e9f8030000
         // 004034f5: jmp 0x4038f2
      [-]83fb1d7533
         // 004034fa: cmp ebx, 0x1d
         // 004034fd: jnz 0x403532
      [-]8b5510eb03
         // 004034ff: mov edx, ss:[ebp+0x10]
         // 00403502: jmp 0x403507
      [-]33c94141eb03
         // 00403507: xor ecx, ecx
         // 00403509: inc ecx
         // 0040350a: inc ecx
         // 0040350b: jmp 0x403510
      [-]41418bd941
         // 00403510: inc ecx
         // 00403511: inc ecx
         // 00403512: mov ebx, ecx
         // 00403514: inc ecx
      [-]8b4214eb03
         // 00403515: mov eax, ds:[edx+0x14]
         // 00403518: jmp 0x40351d
      [-]8b3a03c7eb03
         // 0040351d: mov edi, ds:[edx]
         // 0040351f: add eax, edi
         // 00403521: jmp 0x403526
      [-]890203d34975e8
         // 00403526: mov ds:[edx], eax
         // 00403528: add edx, ebx
         // 0040352a: dec ecx
         // 0040352b: jnz 0x403515
      [-]e9c0030000
         // 0040352d: jmp 0x4038f2
      [-]81fb????????754a
         // 00403532: cmp ebx, 0x579
         // 00403538: jnz 0x403584
      [-]a1????????eb03
         // 0040353a: mov eax, ds:[0x404570]
         // 0040353f: jmp 0x403544
      [-]480305????????ffd0eb03
         // 00403544: dec eax
         // 00403545: add eax, ds:[0x4046b8]
         // 0040354b: call eax
         // 0040354d: jmp 0x403552
      [-]e87cf7ffffa1????????5040eb03
         // 00403552: call 0x402cd3
         // 00403557: mov eax, ds:[0x4046b4]
         // 0040355c: push eax
         // 0040355d: inc eax
         // 0040355e: jmp 0x403563
      [-]40a3????????58c1e0080105????????ff35????????ff15
         // 00403563: inc eax
         // 00403564: mov ds:[0x40413a], eax
         // 00403569: pop eax
         // 0040356a: shl eax, b1 0x8
         // 0040356d: add ds:[0x4046a0], eax
         // 00403573: push ds:[0x404650]
         // 00403579: call ds:[0x404064]
      [-]e96e030000
         // 0040357f: jmp 0x4038f2
      [-]83fb237550
         // 00403584: cmp ebx, 0x23
         // 00403587: jnz 0x4035d9
      [-]a1????????508b4508a3????????5885c07507
         // 0040358e: mov eax, ds:[0x40413a]
         // 00403593: push eax
         // 00403594: mov eax, ss:[ebp+0x8]
         // 00403597: mov ds:[0x404650], eax
         // 0040359c: pop eax
         // 0040359d: test eax, eax
         // 0040359f: jnz 0x4035a8
      [-]a1????????ffd0
         // 004035a1: mov eax, ds:[0x4046a0]
         // 004035a6: call eax
      [-]40506a0068????????ff7508ff15
         // 004035a8: inc eax
         // 004035a9: push eax
         // 004035aa: push 0x0
         // 004035ac: push 0x111
         // 004035b1: push ss:[ebp+0x8]
         // 004035b4: call ds:[0x404060]
      [-]6a046a0068????????ff35????????ff15
         // 004035bf: push 0x4
         // 004035c1: push 0x0
         // 004035c3: push 0x404559
         // 004035c8: push ds:[0x404650]
         // 004035ce: call ds:[0x40405c]
      [-]e919030000
         // 004035d4: jmp 0x4038f2
      [-]eb0083fb250f8589000000
         // 004035d9: jmp 0x4035db
         // 004035db: cmp ebx, 0x25
         // 004035de: jnz 0x40366d
      [-]8b5510eb03
         // 004035e4: mov edx, ss:[ebp+0x10]
         // 004035e7: jmp 0x4035ec
      [-]8b0a8b7a048b35????????03f157514e0fb70df0404000eb03
         // 004035ec: mov ecx, ds:[edx]
         // 004035ee: mov edi, ds:[edx+0x4]
         // 004035f1: mov esi, ds:[0x4046a0]
         // 004035f7: add esi, ecx
         // 004035f9: push edi
         // 004035fa: push ecx
         // 004035fb: dec esi
         // 004035fc: movzx ecx, b2 ds:[0x4040f0]
         // 00403603: jmp 0x403608
      [-]8a07880647562bf2893d????????8935????????51525268????????68????????ff35????????ff15
         // 0040360a: mov b1 al, b1 ds:[edi]
         // 0040360c: mov b1 ds:[esi], b1 al
         // 0040360e: inc edi
         // 0040360f: push esi
         // 00403610: sub esi, edx
         // 00403612: mov ds:[0x4046a4], edi
         // 00403618: mov ds:[0x4046a8], esi
         // 0040361e: push ecx
         // 0040361f: push edx
         // 00403620: push edx
         // 00403621: push 0x4046a4
         // 00403626: push 0x401
         // 0040362b: push ds:[0x404650]
         // 00403631: call ds:[0x404060]
      [-]5a5983c7075e4e4975c9
         // 00403637: pop edx
         // 00403638: pop ecx
         // 00403639: add edi, 0x7
         // 0040363c: pop esi
         // 0040363d: dec esi
         // 0040363e: dec ecx
         // 0040363f: jnz 0x40360a
      [-]598bc183e1075f85c97417
         // 00403646: pop ecx
         // 00403647: mov eax, ecx
         // 00403649: and ecx, 0x7
         // 0040364c: pop edi
         // 0040364d: test ecx, ecx
         // 0040364f: jz 0x403668
      [-]8b35????????4903f103f8412bf9
         // 00403651: mov esi, ds:[0x4046a0]
         // 00403657: dec ecx
         // 00403658: add esi, ecx
         // 0040365a: add edi, eax
         // 0040365c: inc ecx
         // 0040365d: sub edi, ecx
      [-]8a078806474e4975f7
         // 0040365f: mov b1 al, b1 ds:[edi]
         // 00403661: mov b1 ds:[esi], b1 al
         // 00403663: inc edi
         // 00403664: dec esi
         // 00403665: dec ecx
         // 00403666: jnz 0x40365f
      [-]e985020000
         // 00403668: jmp 0x4038f2
      [-]83fb1f7558
         // 0040366d: cmp ebx, 0x1f
         // 00403670: jnz 0x4036ca
      [-]8d15????????eb03
         // 00403678: lea edx, ds:[0x40408c]
         // 0040367e: jmp 0x403683
      [-]83c2045256e8aedcffffeb03
         // 00403683: add edx, 0x4
         // 00403686: push edx
         // 00403687: push esi
         // 00403688: call 0x40133b
         // 0040368d: jmp 0x403692
      [-]a3????????8d15????????83c2054a5256eb03
         // 00403692: mov ds:[0x40469c], eax
         // 00403697: lea edx, ds:[0x4040c8]
         // 0040369d: add edx, 0x5
         // 004036a0: dec edx
         // 004036a1: push edx
         // 004036a2: push esi
         // 004036a3: jmp 0x4036a8
      [-]e88edcffffa3????????8935????????6a206a0068????????ff7508ff15
         // 004036a8: call 0x40133b
         // 004036ad: mov ds:[0x404698], eax
         // 004036b2: mov ds:[0x404102], esi
         // 004036b8: push 0x20
         // 004036ba: push 0x0
         // 004036bc: push 0x111
         // 004036c1: push ss:[ebp+0x8]
         // 004036c4: call ds:[0x404060]
      [-]83fb20757e
         // 004036ca: cmp ebx, 0x20
         // 004036cd: jnz 0x40374d
      [-]a1????????3b05????????7453
         // 004036cf: mov eax, ds:[0x404142]
         // 004036d4: cmp eax, ds:[0x4040f2]
         // 004036da: jz 0x40372f
      [-]8b1d????????eb07
         // 004036dc: mov ebx, ds:[0x404146]
         // 004036e2: jmp 0x4036eb
      [-]bf????????be????????6a0103dfeb02
         // 004036eb: mov edi, 0xfff
         // 004036f0: mov esi, 0xfffffffffffff000
         // 004036f5: push 0x1
         // 004036f7: add ebx, edi
         // 004036f9: jmp 0x4036fd
      [-]23de68????????53a1????????50a1????????ffd085c0eb05
         // 004036fd: and ebx, esi
         // 004036ff: push 0x2000
         // 00403704: push ebx
         // 00403705: mov eax, ds:[0x404142]
         // 0040370a: push eax
         // 0040370b: mov eax, ds:[0x404698]
         // 00403710: call eax
         // 00403712: test eax, eax
         // 00403714: jmp 0x40371b
      [-]6a216a0068????????ff7508ff15
         // 0040371d: push 0x21
         // 0040371f: push 0x0
         // 00403721: push 0x111
         // 00403726: push ss:[ebp+0x8]
         // 00403729: call ds:[0x404060]
      [-]a3????????eb05
         // 0040372f: mov ds:[0x4040f6], eax
         // 00403734: jmp 0x40373b
      [-]6a226a0068????????ff7508ff15
         // 0040373b: push 0x22
         // 0040373d: push 0x0
         // 0040373f: push 0x111
         // 00403744: push ss:[ebp+0x8]
         // 00403747: call ds:[0x404060]
      [-]83fb217555
         // 0040374d: cmp ebx, 0x21
         // 00403750: jnz 0x4037a7
      [-]8b1d????????bf????????eb03
         // 00403752: mov ebx, ds:[0x404146]
         // 00403758: mov edi, 0xfff
         // 0040375d: jmp 0x403762
      [-]be????????eb05
         // 00403762: mov esi, 0xfffffffffffff000
         // 00403767: jmp 0x40376e
      [-]6a0103df23de68????????53eb03
         // 0040376e: push 0x1
         // 00403770: add ebx, edi
         // 00403772: and ebx, esi
         // 00403774: push 0x2000
         // 00403779: push ebx
         // 0040377a: jmp 0x40377f
      [-]6a00a1????????ffd0a3????????85c00f8479fbffff
         // 0040377f: push 0x0
         // 00403781: mov eax, ds:[0x404698]
         // 00403786: call eax
         // 00403788: mov ds:[0x4040f6], eax
         // 0040378d: test eax, eax
         // 0040378f: jz 0x40330e
      [-]6a226a0068????????ff7508ff15
         // 00403795: push 0x22
         // 00403797: push 0x0
         // 00403799: push 0x111
         // 0040379e: push ss:[ebp+0x8]
         // 004037a1: call ds:[0x404060]
      [-]83fb220f859b000000
         // 004037a7: cmp ebx, 0x22
         // 004037aa: jnz 0x40384b
      [-]8b0d????????c1e1026a04bf????????03cf68????????eb03
         // 004037b0: mov ecx, ds:[0x40414a]
         // 004037b6: shl ecx, b1 0x2
         // 004037b9: push 0x4
         // 004037bb: mov edi, 0xfff
         // 004037c0: add ecx, edi
         // 004037c2: push 0x1000
         // 004037c7: jmp 0x4037cc
      [-]be????????23ce516a00a1????????eb03
         // 004037cc: mov esi, 0xfffffffffffff000
         // 004037d1: and ecx, esi
         // 004037d3: push ecx
         // 004037d4: push 0x0
         // 004037d6: mov eax, ds:[0x404698]
         // 004037db: jmp 0x4037e0
      [-]ffd0eb03
         // 004037e0: call eax
         // 004037e2: jmp 0x4037e7
      [-]85c00f841ffbffff
         // 004037e7: test eax, eax
         // 004037e9: jz 0x40330e
      [-]a3????????8d0d????????eb03
         // 004037ef: mov ds:[0x4046a0], eax
         // 004037f4: lea ecx, ds:[0x40413e]
         // 004037fa: jmp 0x4037ff
      [-]518b0d????????c1e10203cf6a4023ceeb03
         // 004037ff: push ecx
         // 00403800: mov ecx, ds:[0x40414a]
         // 00403806: shl ecx, b1 0x2
         // 00403809: add ecx, edi
         // 0040380b: push 0x40
         // 0040380d: and ecx, esi
         // 0040380f: jmp 0x403814
      [-]5150b8????????a3????????a1????????ffd0eb03
         // 00403814: push ecx
         // 00403815: push eax
         // 00403816: mov eax, 0x4
         // 0040381b: mov ds:[0x40413e], eax
         // 00403820: mov eax, ds:[0x40469c]
         // 00403825: call eax
         // 00403827: jmp 0x40382c
      [-]85c00f84dafaffff
         // 0040382c: test eax, eax
         // 0040382e: jz 0x40330e
      [-]6a236a0068????????ff7508ff15
         // 00403834: push 0x23
         // 00403836: push 0x0
         // 00403838: push 0x111
         // 0040383d: push ss:[ebp+0x8]
         // 00403840: call ds:[0x404060]
      [-]e9a7000000
         // 00403846: jmp 0x4038f2
      [-]83fb1e7550
         // 0040384b: cmp ebx, 0x1e
         // 0040384e: jnz 0x4038a0
      [-]6a1d68????????68????????ff7508ff15
         // 00403850: push 0x1d
         // 00403852: push 0x40408c
         // 00403857: push 0x111
         // 0040385c: push ss:[ebp+0x8]
         // 0040385f: call ds:[0x404060]
      [-]33c0404040408bc88d15????????8bfa83ef14
         // 00403865: xor eax, eax
         // 00403867: inc eax
         // 00403868: inc eax
         // 00403869: inc eax
         // 0040386a: inc eax
         // 0040386b: mov ecx, eax
         // 0040386d: lea edx, ds:[0x4040b4]
         // 00403873: mov edi, edx
         // 00403875: sub edi, 0x14
      [-]8b070302eb03
         // 00403878: mov eax, ds:[edi]
         // 0040387a: add eax, ds:[edx]
         // 0040387c: jmp 0x403881
      [-]890247474747424242424975ea
         // 00403881: mov ds:[edx], eax
         // 00403883: inc edi
         // 00403884: inc edi
         // 00403885: inc edi
         // 00403886: inc edi
         // 00403887: inc edx
         // 00403888: inc edx
         // 00403889: inc edx
         // 0040388a: inc edx
         // 0040388b: dec ecx
         // 0040388c: jnz 0x403878
      [-]6a1f6a0068????????ff7508ff15
         // 0040388e: push 0x1f
         // 00403890: push 0x0
         // 00403892: push 0x111
         // 00403897: push ss:[ebp+0x8]
         // 0040389a: call ds:[0x404060]
      [-]0bdb744e
         // 004038a0: or ebx, ebx
         // 004038a2: jz 0x4038f2
      [-]83f9017512
         // 004038aa: cmp ecx, 0x1
         // 004038ad: jnz 0x4038c1
      [-]a1????????48eb03
         // 004038af: mov eax, ds:[0x40463c]
         // 004038b4: dec eax
         // 004038b5: jmp 0x4038ba
      [-]a3????????eb31
         // 004038ba: mov ds:[0x40463c], eax
         // 004038bf: jmp 0x4038f2
      [-]83f9027516
         // 004038c1: cmp ecx, 0x2
         // 004038c4: jnz 0x4038dc
      [-]c1e910eb27
         // 004038c6: shr ecx, b1 0x10
         // 004038c9: jmp 0x4038f2
      [-]ff7514ff7510ff750cff7508ff15
         // 004038de: push ss:[ebp+0x14]
         // 004038e1: push ss:[ebp+0x10]
         // 004038e4: push ss:[ebp+0xc]
         // 004038e7: push ss:[ebp+0x8]
         // 004038ea: call ds:[0x404058]
      [-]8be55dc21000
         // 004038f4: mov esp, ebp
         // 004038f6: pop ebp
         // 004038f7: retn b2 0x10
      [-]8bcd558bec83c104890d????????ff15
         // 004038fa: mov ecx, ebp
         // 004038fc: push ebp
         // 004038fd: mov ebp, esp
         // 004038ff: add ecx, 0x4
         // 00403902: mov ds:[0x4040fa], ecx
         // 00403908: call ds:[0x404014]
      [-]a3????????6a00ff15
         // 0040390e: mov ds:[0x404658], eax
         // 00403913: push 0x0
         // 00403915: call ds:[0x404010]
      [-]a3????????a3????????c705????????????????c705????????????????eb04
         // 0040391b: mov ds:[0x4045ec], eax
         // 00403920: mov ds:[0x4040f2], eax
         // 00403925: mov ds:[0x4045d8], 0x30
         // 0040392f: mov ds:[0x4045dc], 0x2
         // 00403939: jmp 0x40393f
      [-]c705????????????????c705????????????????c705????????????????c705????????????????c705????????????????68????????6a00ff15
         // 0040393f: mov ds:[0x4045e0], 0x403153
         // 00403949: mov ds:[0x4045e4], 0x0
         // 00403953: mov ds:[0x4045e8], 0x0
         // 0040395d: mov ds:[0x404600], 0x40454e
         // 00403967: mov ds:[0x4045f8], 0xf
         // 00403971: push 0x7f00
         // 00403976: push 0x0
         // 00403978: call ds:[0x404068]
      [-]a3????????a3????????68????????6a00ff15
         // 0040397e: mov ds:[0x4045f0], eax
         // 00403983: mov ds:[0x404604], eax
         // 00403988: push 0x7f00
         // 0040398d: push 0x0
         // 0040398f: call ds:[0x40406c]
      [-]a3????????68
         // 00403995: mov ds:[0x4045f4], eax
         // 0040399a: push 0x4045d8
      [-]6a00ff35????????6a006a0068????????68????????68????????68????????68????????68????????68????????6a00ff15
         // 004039a5: push 0x0
         // 004039a7: push ds:[0x4040f2]
         // 004039ad: push 0x0
         // 004039af: push 0x0
         // 004039b1: push 0x1e5
         // 004039b6: push 0x203
         // 004039bb: push 0xfffffffffffff98e
         // 004039c0: push 0xfffffffffffff9c0
         // 004039c5: push 0xcf0000
         // 004039ca: push 0x404599
         // 004039cf: push 0x40454e
         // 004039d4: push 0x0
         // 004039d6: call ds:[0x404050]
      [-]a3????????6a05ff35????????ff15
         // 004039dc: mov ds:[0x404650], eax
         // 004039e1: push 0x5
         // 004039e3: push ds:[0x404650]
         // 004039e9: call ds:[0x404048]
      [-]ff35????????ff15
         // 004039ef: push ds:[0x404650]
         // 004039f5: call ds:[0x40404c]
      [-]33ff8d1d????????eb0e
         // 004039fb: xor edi, edi
         // 004039fd: lea ebx, ds:[0x404608]
         // 00403a03: jmp 0x403a13
      [-]57575753ff15
         // 00403a13: push edi
         // 00403a14: push edi
         // 00403a15: push edi
         // 00403a16: push ebx
         // 00403a17: call ds:[0x404078]
      [-]84c075e4
         // 00403a1d: test b1 al, b1 al
         // 00403a1f: jnz 0x403a05
      [-]a1????????eb06
         // 00403a21: mov eax, ds:[0x404610]
         // 00403a26: jmp 0x403a2e
      [-]e8a2f1ffffc3
         // 00403a2e: call 0x402bd5
         // 00403a33: retn 

  }
  condition:
    all of them
}
