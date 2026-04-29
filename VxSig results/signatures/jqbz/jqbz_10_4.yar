rule jqbz_10_4 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         0000e86c200000558bec83ec10eb07
         // 08001005: call 0x8003076
         // 0800100a: push ebp
         // 0800100b: mov ebp, esp
         // 0800100d: sub esp, 0x10
         // 08001010: jmp 0x8001019
      [-]570fb70b
         // 0800102e: push edi
         // 0800102f: movzx ecx, b2 ds:[ebx]
      [-]43438b32eb09
         // 08001032: inc ebx
         // 08001033: inc ebx
         // 08001034: mov esi, ds:[edx]
         // 08001036: jmp 0x8001041
      [-]4242eb02
         // 08001041: inc edx
         // 08001042: inc edx
         // 08001043: jmp 0x8001047
      [-]8a06880746474975f7
         // 08001049: mov b1 al, b1 ds:[esi]
         // 0800104b: mov b1 ds:[edi], b1 al
         // 0800104d: inc esi
         // 0800104e: inc edi
         // 0800104f: dec ecx
         // 08001050: jnz 0x8001049
      [-]0fb70b81f9????????72cc
         // 0800105b: movzx ecx, b2 ds:[ebx]
         // 0800105e: cmp ecx, 0x1770
         // 08001064: jb 0x8001032
      [-]5f8bf78b0d
         // 08001066: pop edi
         // 08001067: mov esi, edi
         // 08001069: mov ecx, ds:[0x8004126]
      [-]03f9eb0c
         // 0800106f: add edi, ecx
         // 08001071: jmp 0x800107f
      [-]03f903f9893d
         // 0800107f: add edi, ecx
         // 08001081: add edi, ecx
         // 08001083: mov ds:[0x8004478], edi
      [-]8975f0eb06
         // 08001096: mov ss:[ebp+0xfffffffffffffff0], esi
         // 08001099: jmp 0x80010a1
      [-]03f14e4e0fb706eb04
         // 080010a1: add esi, ecx
         // 080010a3: dec esi
         // 080010a4: dec esi
         // 080010a5: movzx eax, b2 ds:[esi]
         // 080010a8: jmp 0x80010ae
      [-]8945fc4e4e0fb71e895df8eb0b
         // 080010ae: mov ss:[ebp+0xfffffffffffffffc], eax
         // 080010b1: dec esi
         // 080010b2: dec esi
         // 080010b3: movzx ebx, b2 ds:[esi]
         // 080010b6: mov ss:[ebp+0xfffffffffffffff8], ebx
         // 080010b9: jmp 0x80010c6
      [-]f7e32bf08975f4
         // 080010c6: mul ebx
         // 080010c8: sub esi, eax
         // 080010ca: mov ss:[ebp+0xfffffffffffffff4], esi
      [-]8b5dfc8b55f4
         // 080010cd: mov ebx, ss:[ebp+0xfffffffffffffffc]
         // 080010d0: mov edx, ss:[ebp+0xfffffffffffffff4]
      [-]8b75f08b4df8eb0d
         // 080010d3: mov esi, ss:[ebp+0xfffffffffffffff0]
         // 080010d6: mov ecx, ss:[ebp+0xfffffffffffffff8]
         // 080010d9: jmp 0x80010e8
      [-]8a068a2238e07526
         // 080010e9: mov b1 al, b1 ds:[esi]
         // 080010eb: mov b1 ah, b1 ds:[edx]
         // 080010ed: cmp b1 al, b1 ah
         // 080010ef: jnz 0x8001117
      [-]4642eb03
         // 080010fe: inc esi
         // 080010ff: inc edx
         // 08001100: jmp 0x8001105
      [-]8975f03b75f47322
         // 0800110d: mov ss:[ebp+0xfffffffffffffff0], esi
         // 08001110: cmp esi, ss:[ebp+0xfffffffffffffff4]
         // 08001113: jnb 0x8001137
      [-]5a8b4df803d14b75ad
         // 0800111d: pop edx
         // 0800111e: mov ecx, ss:[ebp+0xfffffffffffffff8]
         // 08001121: add edx, ecx
         // 08001123: dec ebx
         // 08001124: jnz 0x80010d3
      [-]8b75f08a06880747468975f03b75f47596
         // 08001126: mov esi, ss:[ebp+0xfffffffffffffff0]
         // 08001129: mov b1 al, b1 ds:[esi]
         // 0800112b: mov b1 ds:[edi], b1 al
         // 0800112d: inc edi
         // 0800112e: inc esi
         // 0800112f: mov ss:[ebp+0xfffffffffffffff0], esi
         // 08001132: cmp esi, ss:[ebp+0xfffffffffffffff4]
         // 08001135: jnz 0x80010cd
      [-]8bc75f2bc7a3
         // 08001137: mov eax, edi
         // 08001139: pop edi
         // 0800113a: sub eax, edi
         // 0800113c: mov ds:[0x8004122], eax
      [-]8be55dc3
         // 08001146: mov esp, ebp
         // 08001148: pop ebp
         // 08001149: retn 
      [-]558bec83ec108b450825????????b9????????eb05
         // 080013b8: push ebp
         // 080013b9: mov ebp, esp
         // 080013bb: sub esp, 0x10
         // 080013be: mov eax, ss:[ebp+0x8]
         // 080013c1: and eax, 0xffffffffffff0000
         // 080013c6: mov ecx, 0x5a4d
         // 080013cb: jmp 0x80013d2
      [-]2d????????
         // 080013cd: sub eax, 0x10000
      [-]66390875f6
         // 080013d2: cmp b2 ds:[eax], b2 cx
         // 080013d5: jnz 0x80013cd
      [-]0fb7483c538945fc8d440118b9????????56576639080f8598000000
         // 080013d7: movzx ecx, b2 ds:[eax+0x3c]
         // 080013db: push ebx
         // 080013dc: mov ss:[ebp+0xfffffffffffffffc], eax
         // 080013df: lea eax, ds:[ecx+eax+0x18]
         // 080013e3: mov ecx, 0x10b
         // 080013e8: push esi
         // 080013e9: push edi
         // 080013ea: cmp b2 ds:[eax], b2 cx
         // 080013ed: jnz 0x800148b
      [-]8b70600375fc8b7e208b4614037dfc8945f48b5d0c4b33c033c9fec8
         // 080013f3: mov esi, ds:[eax+0x60]
         // 080013f6: add esi, ss:[ebp+0xfffffffffffffffc]
         // 080013f9: mov edi, ds:[esi+0x20]
         // 080013fc: mov eax, ds:[esi+0x14]
         // 080013ff: add edi, ss:[ebp+0xfffffffffffffffc]
         // 08001402: mov ss:[ebp+0xfffffffffffffff4], eax
         // 08001405: mov ebx, ss:[ebp+0xc]
         // 08001408: dec ebx
         // 08001409: xor eax, eax
         // 0800140b: xor ecx, ecx
         // 0800140d: dec b1 al
      [-]fec0438a0b85c975f7
         // 0800140f: inc b1 al
         // 08001411: inc ebx
         // 08001412: mov b1 cl, b1 ds:[ebx]
         // 08001414: test ecx, ecx
         // 08001416: jnz 0x800140f
      [-]214df8394df48945f07668
         // 08001418: and ss:[ebp+0xfffffffffffffff8], ecx
         // 0800141b: cmp ss:[ebp+0xfffffffffffffff4], ecx
         // 0800141e: mov ss:[ebp+0xfffffffffffffff0], eax
         // 08001421: jbe 0x800148b
      [-]8b070345fc8bd84b33c0fec8
         // 08001423: mov eax, ds:[edi]
         // 08001425: add eax, ss:[ebp+0xfffffffffffffffc]
         // 08001428: mov ebx, eax
         // 0800142a: dec ebx
         // 0800142b: xor eax, eax
         // 0800142d: dec b1 al
      [-]fec0438a0b80f90075f6
         // 0800142f: inc b1 al
         // 08001431: inc ebx
         // 08001432: mov b1 cl, b1 ds:[ebx]
         // 08001434: cmp b1 cl, b1 0x0
         // 08001437: jnz 0x800142f
      [-]3b45f07512
         // 08001439: cmp eax, ss:[ebp+0xfffffffffffffff0]
         // 0800143c: jnz 0x8001450
      [-]8b070345fcff750c50e8
         // 0800143e: mov eax, ds:[edi]
         // 08001440: add eax, ss:[ebp+0xfffffffffffffffc]
         // 08001443: push ss:[ebp+0xc]
         // 08001446: push eax
         // 08001447: call 0x80031f2
      [-]000085c0740e
         // 0800144c: test eax, eax
         // 0800144e: jz 0x800145e
      [-]83c704ff45f88b45f83b45f472c5
         // 08001450: add edi, 0x4
         // 08001453: inc ss:[ebp+0xfffffffffffffff8]
         // 08001456: mov eax, ss:[ebp+0xfffffffffffffff8]
         // 08001459: cmp eax, ss:[ebp+0xfffffffffffffff4]
         // 0800145c: jb 0x8001423
      [-]8b45f83b45f47325
         // 0800145e: mov eax, ss:[ebp+0xfffffffffffffff8]
         // 08001461: cmp eax, ss:[ebp+0xfffffffffffffff4]
         // 08001464: jnb 0x800148b
      [-]8b4e10492bc18b4e2403c803c88b45fc03c80fb7018b4e1c8d04818b4dfc8b040103c1eb02
         // 08001466: mov ecx, ds:[esi+0x10]
         // 08001469: dec ecx
         // 0800146a: sub eax, ecx
         // 0800146c: mov ecx, ds:[esi+0x24]
         // 0800146f: add ecx, eax
         // 08001471: add ecx, eax
         // 08001473: mov eax, ss:[ebp+0xfffffffffffffffc]
         // 08001476: add ecx, eax
         // 08001478: movzx eax, b2 ds:[ecx]
         // 0800147b: mov ecx, ds:[esi+0x1c]
         // 0800147e: lea eax, ds:[ecx+eax*0x4]
         // 08001481: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 08001484: mov eax, ds:[ecx+eax]
         // 08001487: add eax, ecx
         // 08001489: jmp 0x800148d
      [-]5f5e5b8be55dc20800
         // 0800148d: pop edi
         // 0800148e: pop esi
         // 0800148f: pop ebx
         // 08001490: mov esp, ebp
         // 08001492: pop ebp
         // 08001493: retn b2 0x8
      [-]eb0003f88d0d
         // 080029d3: jmp 0x80029d5
         // 080029d5: add edi, eax
         // 080029d7: lea ecx, ds:[0x80040f6]
      [-]57eb00c3
         // 080029dd: push edi
         // 080029de: jmp 0x80029e0
         // 080029e0: retn 
      [-]8b0aeb05
         // 08002c5e: mov ecx, ds:[edx]
         // 08002c60: jmp 0x8002c67
      [-]8b7a048b0783c7048bf78bde03f8eb02
         // 08002c67: mov edi, ds:[edx+0x4]
         // 08002c6a: mov eax, ds:[edi]
         // 08002c6c: add edi, 0x4
         // 08002c6f: mov esi, edi
         // 08002c71: mov ebx, esi
         // 08002c73: add edi, eax
         // 08002c75: jmp 0x8002c79
      [-]8bd74a2bc883e90452ba
         // 08002c79: mov edx, edi
         // 08002c7b: dec edx
         // 08002c7c: sub ecx, eax
         // 08002c7e: sub ecx, 0x4
         // 08002c81: push edx
         // 08002c82: mov edx, 0x8004474
      [-]890a897a045a
         // 08002c87: mov ds:[edx], ecx
         // 08002c89: mov ds:[edx+0x4], edi
         // 08002c8c: pop edx
      [-]8a078a260225
         // 08002c8d: mov b1 al, b1 ds:[edi]
         // 08002c8f: mov b1 ah, b1 ds:[esi]
         // 08002c91: add b1 ah, b1 ds:[0x800412b]
      [-]41000832c4eb03
         // 08002c97: xor b1 al, b1 ah
         // 08002c99: jmp 0x8002c9e
      [-]88073bf27407
         // 08002c9e: mov b1 ds:[edi], b1 al
         // 08002ca0: cmp esi, edx
         // 08002ca2: jz 0x8002cab
      [-]474975e4
         // 08002ca5: inc edi
         // 08002ca6: dec ecx
         // 08002ca7: jnz 0x8002c8d
      [-]8bfe6a3468
         // 08002cb4: mov edi, esi
         // 08002cb6: push 0x34
         // 08002cb8: push 0x8004474
      [-]68????????eb03
         // 08002cbd: push 0x111
         // 08002cc2: jmp 0x8002cc7
      [-]8a06880746474975f7
         // 08002cf3: mov b1 al, b1 ds:[esi]
         // 08002cf5: mov b1 ds:[edi], b1 al
         // 08002cf7: inc esi
         // 08002cf8: inc edi
         // 08002cf9: dec ecx
         // 08002cfa: jnz 0x8002cf3
      [-]03ce890d
         // 08002d10: add ecx, esi
         // 08002d12: mov ds:[0x80043f8], ecx
      [-]598b0646469046468b3d
         // 08002d18: pop ecx
         // 08002d19: mov eax, ds:[esi]
         // 08002d1b: inc esi
         // 08002d1c: inc esi
         // 08002d1d: nop 
         // 08002d1e: inc esi
         // 08002d1f: inc esi
         // 08002d20: mov edi, ds:[0x8004468]
      [-]8bde03d8891d
         // 08002d26: mov ebx, esi
         // 08002d28: add ebx, eax
         // 08002d2a: mov ds:[0x80043f4], ebx
      [-]8bd6eb05
         // 08002d30: mov edx, esi
         // 08002d32: jmp 0x8002d39
      [-]03f0b9????????0fb60240
         // 08002d39: add esi, eax
         // 08002d3b: mov ecx, 0x0
         // 08002d40: movzx eax, b1 ds:[edx]
         // 08002d43: inc eax
      [-]3bd37379
         // 08002d44: cmp edx, ebx
         // 08002d46: jnb 0x8002dc1
      [-]3bc17308
         // 08002d48: cmp eax, ecx
         // 08002d4a: jnb 0x8002d54
      [-]2bc18bc885c97409
         // 08002d54: sub eax, ecx
         // 08002d56: mov ecx, eax
         // 08002d58: test ecx, ecx
         // 08002d5a: jz 0x8002d65
      [-]8a06880746474975f7
         // 08002d5c: mov b1 al, b1 ds:[esi]
         // 08002d5e: mov b1 ds:[edi], b1 al
         // 08002d60: inc esi
         // 08002d61: inc edi
         // 08002d62: dec ecx
         // 08002d63: jnz 0x8002d5c
      [-]428a02420fb60a85c97408
         // 08002d65: inc edx
         // 08002d66: mov b1 al, b1 ds:[edx]
         // 08002d68: inc edx
         // 08002d69: movzx ecx, b1 ds:[edx]
         // 08002d6c: test ecx, ecx
         // 08002d6e: jz 0x8002d78
      [-]8807474975fa
         // 08002d71: mov b1 ds:[edi], b1 al
         // 08002d73: inc edi
         // 08002d74: dec ecx
         // 08002d75: jnz 0x8002d71
      [-]420fb602eb05
         // 08002d78: inc edx
         // 08002d79: movzx eax, b1 ds:[edx]
         // 08002d7c: jmp 0x8002d83
      [-]fec180f9007521
         // 08002d83: inc b1 cl
         // 08002d85: cmp b1 cl, b1 0x0
         // 08002d88: jnz 0x8002dab
      [-]fec03c00750e
         // 08002d8a: inc b1 al
         // 08002d8c: cmp b1 al, b1 0x0
         // 08002d8e: jnz 0x8002d9e
      [-]0fb7024242eb09
         // 08002d97: movzx eax, b2 ds:[edx]
         // 08002d9a: inc edx
         // 08002d9b: inc edx
         // 08002d9c: jmp 0x8002da7
      [-]b000fec8eb03
         // 08002d9e: mov b1 al, b1 0x0
         // 08002da0: dec b1 al
         // 08002da2: jmp 0x8002da7
      [-]fec9eb12
         // 08002da7: dec b1 cl
         // 08002da9: jmp 0x8002dbd
      [-]fec9fec03c007508
         // 08002dab: dec b1 cl
         // 08002dad: inc b1 al
         // 08002daf: cmp b1 al, b1 0x0
         // 08002db1: jnz 0x8002dbb
      [-]420fb7024242eb02
         // 08002db3: inc edx
         // 08002db4: movzx eax, b2 ds:[edx]
         // 08002db7: inc edx
         // 08002db8: inc edx
         // 08002db9: jmp 0x8002dbd
      [-]2bceeb05
         // 08002dc7: sub ecx, esi
         // 08002dc9: jmp 0x8002dd0
      [-]85c97409
         // 08002dd0: test ecx, ecx
         // 08002dd2: jz 0x8002ddd
      [-]8a06880746474975f7
         // 08002dd4: mov b1 al, b1 ds:[esi]
         // 08002dd6: mov b1 ds:[edi], b1 al
         // 08002dd8: inc esi
         // 08002dd9: inc edi
         // 08002dda: dec ecx
         // 08002ddb: jnz 0x8002dd4
      [-]81ef????????893d
         // 08002de8: sub edi, 0x3fd
         // 08002dee: mov ds:[0x8004468], edi
      [-]558bec56578b7d0c33c033c98b7508
         // 080031f2: push ebp
         // 080031f3: mov ebp, esp
         // 080031f5: push esi
         // 080031f6: push edi
         // 080031f7: mov edi, ss:[ebp+0xc]
         // 080031fa: xor eax, eax
         // 080031fc: xor ecx, ecx
         // 080031fe: mov esi, ss:[ebp+0x8]
      [-]8a068a0f3bc17508
         // 08003201: mov b1 al, b1 ds:[esi]
         // 08003203: mov b1 cl, b1 ds:[edi]
         // 08003205: cmp eax, ecx
         // 08003207: jnz 0x8003211
      [-]85c97407
         // 08003209: test ecx, ecx
         // 0800320b: jz 0x8003214
      [-]4647ebf0
         // 0800320d: inc esi
         // 0800320e: inc edi
         // 0800320f: jmp 0x8003201
      [-]5f5e8be55dc20800
         // 08003214: pop edi
         // 08003215: pop esi
         // 08003216: mov esp, ebp
         // 08003218: pop ebp
         // 08003219: retn b2 0x8
      [-]558bec83c4a08b450c83f8010f85
         // 080032e8: push ebp
         // 080032e9: mov ebp, esp
         // 080032eb: add esp, 0xffffffffffffffa0
         // 080032ee: mov eax, ss:[ebp+0xc]
         // 080032f1: cmp eax, 0x1
         // 080032f4: jnz 0x8003466
      [-]8b7d086a00ff35
         // 080032fa: mov edi, ss:[ebp+0x8]
         // 080032fd: push 0x0
         // 080032ff: push ds:[0x80040f6]
      [-]6a02576a2868????????6a0a6a0a68????????68
         // 08003305: push 0x2
         // 08003307: push edi
         // 08003308: push 0x28
         // 0800330a: push 0x140
         // 0800330f: push 0xa
         // 08003311: push 0xa
         // 08003313: push 0x10000001
         // 08003318: push 0x80041e0
      [-]6a00ff15
         // 08003322: push 0x0
         // 08003324: call ds:[CreateWindowExA]
      [-]85c0750b
         // 08003331: test eax, eax
         // 08003333: jnz 0x8003340
      [-]6a2b6a0068????????ff7508ff15
         // 08003345: push 0x2b
         // 08003347: push 0x0
         // 08003349: push 0x111
         // 0800334e: push ss:[ebp+0x8]
         // 08003351: call ds:[SendMessageA]
      [-]6a00ff35
         // 08003357: push 0x0
         // 08003359: push ds:[0x80040f6]
      [-]6a015768????????68????????6a466a0a68????????6a0068
         // 0800335f: push 0x1
         // 08003361: push edi
         // 08003362: push 0x1ae
         // 08003367: push 0x1f4
         // 0800336c: push 0x46
         // 0800336e: push 0xa
         // 08003370: push 0x40000000
         // 08003375: push 0x0
         // 08003377: push 0x8004242
      [-]6a00ff15
         // 0800337c: push 0x0
         // 0800337e: call ds:[CreateWindowExA]
      [-]85c0750b
         // 08003389: test eax, eax
         // 0800338b: jnz 0x8003398
      [-]6a00ff35
         // 0800339d: push 0x0
         // 0800339f: push ds:[0x80040f6]
      [-]6a02ff750c6a2268????????68????????6a0a68????????68
         // 080033a5: push 0x2
         // 080033a7: push ss:[ebp+0xc]
         // 080033aa: push 0x22
         // 080033ac: push 0xa6
         // 080033b1: push 0x17c
         // 080033b6: push 0xa
         // 080033b8: push 0x40000001
         // 080033bd: push 0x80041e0
      [-]6a00ff15
         // 080033c7: push 0x0
         // 080033c9: call ds:[CreateWindowExA]
      [-]85c0750b
         // 080033cf: test eax, eax
         // 080033d1: jnz 0x80033de
      [-]68????????ff7508ff15
         // 08003423: push 0x402
         // 08003428: push ss:[ebp+0x8]
         // 0800342b: call ds:[SendMessageA]
      [-]68????????68????????68????????68????????ff
         // 0800343d: push 0x1f9
         // 08003442: push 0x226
         // 08003447: push 0xfffffffffffff3f8
         // 0800344c: push 0xfffffffffffff18c
         // 08003456: call ds:[SetWindowPos]
      [-]e970050000
         // 0800345c: jmp 0x80039d1
      [-]3d????????7538
         // 08003466: cmp eax, 0x402
         // 0800346b: jnz 0x80034a5
      [-]8b5510eb03
         // 0800346d: mov edx, ss:[ebp+0x10]
         // 08003470: jmp 0x8003475
      [-]33c94141eb03
         // 08003475: xor ecx, ecx
         // 08003477: inc ecx
         // 08003478: inc ecx
         // 08003479: jmp 0x800347e
      [-]41418bd941
         // 0800347e: inc ecx
         // 0800347f: inc ecx
         // 08003480: mov ebx, ecx
         // 08003482: inc ecx
      [-]8b4214eb03
         // 08003483: mov eax, ds:[edx+0x14]
         // 08003486: jmp 0x800348b
      [-]8b3a03c7eb03
         // 0800348b: mov edi, ds:[edx]
         // 0800348d: add eax, edi
         // 0800348f: jmp 0x8003494
      [-]890203d34975e8
         // 08003494: mov ds:[edx], eax
         // 08003496: add edx, ebx
         // 08003498: dec ecx
         // 08003499: jnz 0x8003483
      [-]e931050000
         // 0800349b: jmp 0x80039d1
      [-]3d????????7539
         // 080034a5: cmp eax, 0x401
         // 080034aa: jnz 0x80034e5
      [-]b9????????8b5510eb03
         // 080034ac: mov ecx, 0x6
         // 080034b1: mov edx, ss:[ebp+0x10]
         // 080034b4: jmp 0x80034b9
      [-]8b3a424242428b32eb05
         // 080034b9: mov edi, ds:[edx]
         // 080034bb: inc edx
         // 080034bc: inc edx
         // 080034bd: inc edx
         // 080034be: inc edx
         // 080034bf: mov esi, ds:[edx]
         // 080034c1: jmp 0x80034c8
      [-]8b551441
         // 080034c8: mov edx, ss:[ebp+0x14]
         // 080034cb: inc ecx
      [-]8a078806472bf24975f6
         // 080034cc: mov b1 al, b1 ds:[edi]
         // 080034ce: mov b1 ds:[esi], b1 al
         // 080034d0: inc edi
         // 080034d1: sub esi, edx
         // 080034d3: dec ecx
         // 080034d4: jnz 0x80034cc
      [-]e9f1040000
         // 080034db: jmp 0x80039d1
      [-]83f8027516
         // 080034e5: cmp eax, 0x2
         // 080034e8: jnz 0x8003500
      [-]e9d6040000
         // 080034f6: jmp 0x80039d1
      [-]83f80f752e
         // 08003500: cmp eax, 0xf
         // 08003503: jnz 0x8003533
      [-]8d45d850ff7508ff15
         // 08003505: lea eax, ss:[ebp+0xffffffffffffffd8]
         // 08003508: push eax
         // 08003509: push ss:[ebp+0x8]
         // 0800350c: call ds:[BeginPaint]
      [-]8d45d850ff7508ff15
         // 08003517: lea eax, ss:[ebp+0xffffffffffffffd8]
         // 0800351a: push eax
         // 0800351b: push ss:[ebp+0x8]
         // 0800351e: call ds:[EndPaint]
      [-]e9a3040000
         // 08003529: jmp 0x80039d1
      [-]83f8057553
         // 08003533: cmp eax, 0x5
         // 08003536: jnz 0x800358b
      [-]68????????ff7508ff15
         // 0800353f: push 0x402
         // 08003544: push ss:[ebp+0x8]
         // 08003547: call ds:[SendMessageA]
      [-]8d45f050ff7508ff15
         // 0800354d: lea eax, ss:[ebp+0xfffffffffffffff0]
         // 08003550: push eax
         // 08003551: push ss:[ebp+0x8]
         // 08003554: call ds:[GetWindowRect]
      [-]8b45f88b4df02bc1508b45fc8b4df42bc18bc8582bc1506a0068????????ff7508ff15
         // 0800355a: mov eax, ss:[ebp+0xfffffffffffffff8]
         // 0800355d: mov ecx, ss:[ebp+0xfffffffffffffff0]
         // 08003560: sub eax, ecx
         // 08003562: push eax
         // 08003563: mov eax, ss:[ebp+0xfffffffffffffffc]
         // 08003566: mov ecx, ss:[ebp+0xfffffffffffffff4]
         // 08003569: sub eax, ecx
         // 0800356b: mov ecx, eax
         // 0800356d: pop eax
         // 0800356e: sub eax, ecx
         // 08003570: push eax
         // 08003571: push 0x0
         // 08003573: push 0x111
         // 08003578: push ss:[ebp+0x8]
         // 0800357b: call ds:[SendMessageA]
      [-]e94b040000
         // 08003581: jmp 0x80039d1
      [-]3d????????0f8527040000
         // 0800358b: cmp eax, 0x111
         // 08003590: jnz 0x80039bd
      [-]8b45108b5d1483fb2a7530
         // 08003596: mov eax, ss:[ebp+0x10]
         // 08003599: mov ebx, ss:[ebp+0x14]
         // 0800359c: cmp ebx, 0x2a
         // 0800359f: jnz 0x80035d1
      [-]6a0068????????6a036a00eb04
         // 080035ad: push 0x0
         // 080035af: push 0x80
         // 080035b4: push 0x3
         // 080035b6: push 0x0
         // 080035b8: jmp 0x80035be
      [-]6a0168????????68
         // 080035be: push 0x1
         // 080035c0: push 0xffffffff80000000
         // 080035c5: push 0x80041f8
      [-]ffd0e902040000
         // 080035ca: call eax
         // 080035cc: jmp 0x80039d3
      [-]83fb2b753d
         // 080035d1: cmp ebx, 0x2b
         // 080035d4: jnz 0x8003613
      [-]6a2a6a0068????????ff7508ff15
         // 080035db: push 0x2a
         // 080035dd: push 0x0
         // 080035df: push 0x111
         // 080035e4: push ss:[ebp+0x8]
         // 080035e7: call ds:[SendMessageA]
      [-]83f8047305
         // 08003604: cmp eax, 0x4
         // 08003607: jnb 0x800360e
      [-]e9dcfeffff
         // 08003609: jmp 0x80034ea
      [-]e9be030000
         // 0800360e: jmp 0x80039d1
      [-]81fb????????754a
         // 08003613: cmp ebx, 0x579
         // 08003619: jnz 0x8003665
      [-]ffd0eb03
         // 0800362c: call eax
         // 0800362e: jmp 0x8003633
      [-]5040eb03
         // 0800363d: push eax
         // 0800363e: inc eax
         // 0800363f: jmp 0x8003644
      [-]58c1e0080105
         // 0800364a: pop eax
         // 0800364b: shl eax, b1 0x8
         // 0800364e: add ds:[0x8004468], eax
      [-]e96c030000
         // 08003660: jmp 0x80039d1
      [-]83fb327550
         // 08003665: cmp ebx, 0x32
         // 08003668: jnz 0x80036ba
      [-]508b4508a3
         // 08003674: push eax
         // 08003675: mov eax, ss:[ebp+0x8]
         // 08003678: mov ds:[0x8004418], eax
      [-]5885c07507
         // 0800367d: pop eax
         // 0800367e: test eax, eax
         // 08003680: jnz 0x8003689
      [-]40506a0068????????ff7508ff15
         // 08003689: inc eax
         // 0800368a: push eax
         // 0800368b: push 0x0
         // 0800368d: push 0x111
         // 08003692: push ss:[ebp+0x8]
         // 08003695: call ds:[SendMessageA]
      [-]6a046a0068
         // 080036a0: push 0x4
         // 080036a2: push 0x0
         // 080036a4: push 0x80041e0
      [-]e917030000
         // 080036b5: jmp 0x80039d1
      [-]83fb340f8589000000
         // 080036ba: cmp ebx, 0x34
         // 080036bd: jnz 0x800374c
      [-]8b5510eb03
         // 080036c3: mov edx, ss:[ebp+0x10]
         // 080036c6: jmp 0x80036cb
      [-]8b0a8b7a048b35
         // 080036cb: mov ecx, ds:[edx]
         // 080036cd: mov edi, ds:[edx+0x4]
         // 080036d0: mov esi, ds:[0x8004468]
      [-]03f157514e0fb70d
         // 080036d6: add esi, ecx
         // 080036d8: push edi
         // 080036d9: push ecx
         // 080036da: dec esi
         // 080036db: movzx ecx, b2 ds:[0x80040f4]
      [-]400008eb03
         // 080036e2: jmp 0x80036e7
      [-]8a07880647562bf2893d
         // 080036e9: mov b1 al, b1 ds:[edi]
         // 080036eb: mov b1 ds:[esi], b1 al
         // 080036ed: inc edi
         // 080036ee: push esi
         // 080036ef: sub esi, edx
         // 080036f1: mov ds:[0x800446c], edi
      [-]51525268
         // 080036fd: push ecx
         // 080036fe: push edx
         // 080036ff: push edx
         // 08003700: push 0x800446c
      [-]68????????ff35
         // 08003705: push 0x401
         // 0800370a: push ds:[0x8004418]
      [-]5a5983c7075e4e4975c9
         // 08003716: pop edx
         // 08003717: pop ecx
         // 08003718: add edi, 0x7
         // 0800371b: pop esi
         // 0800371c: dec esi
         // 0800371d: dec ecx
         // 0800371e: jnz 0x80036e9
      [-]598bc183e1075f85c97417
         // 08003725: pop ecx
         // 08003726: mov eax, ecx
         // 08003728: and ecx, 0x7
         // 0800372b: pop edi
         // 0800372c: test ecx, ecx
         // 0800372e: jz 0x8003747
      [-]4903f103f8412bf9
         // 08003736: dec ecx
         // 08003737: add esi, ecx
         // 08003739: add edi, eax
         // 0800373b: inc ecx
         // 0800373c: sub edi, ecx
      [-]8a078806474e4975f7
         // 0800373e: mov b1 al, b1 ds:[edi]
         // 08003740: mov b1 ds:[esi], b1 al
         // 08003742: inc edi
         // 08003743: dec esi
         // 08003744: dec ecx
         // 08003745: jnz 0x800373e
      [-]e985020000
         // 08003747: jmp 0x80039d1
      [-]83fb2e7558
         // 0800374c: cmp ebx, 0x2e
         // 0800374f: jnz 0x80037a9
      [-]83c2045256e8
         // 08003762: add edx, 0x4
         // 08003765: push edx
         // 08003766: push esi
         // 08003767: call 0x80013b8
      [-]ffffeb03
         // 0800376c: jmp 0x8003771
      [-]83c2054a5256eb03
         // 0800377c: add edx, 0x5
         // 0800377f: dec edx
         // 08003780: push edx
         // 08003781: push esi
         // 08003782: jmp 0x8003787
      [-]6a2f6a0068????????ff7508ff15
         // 08003797: push 0x2f
         // 08003799: push 0x0
         // 0800379b: push 0x111
         // 080037a0: push ss:[ebp+0x8]
         // 080037a3: call ds:[SendMessageA]
      [-]83fb2f757e
         // 080037a9: cmp ebx, 0x2f
         // 080037ac: jnz 0x800382c
      [-]bf????????be????????6a0103dfeb02
         // 080037ca: mov edi, 0xfff
         // 080037cf: mov esi, 0xfffffffffffff000
         // 080037d4: push 0x1
         // 080037d6: add ebx, edi
         // 080037d8: jmp 0x80037dc
      [-]23de68????????53a1
         // 080037dc: and ebx, esi
         // 080037de: push 0x2000
         // 080037e3: push ebx
         // 080037e4: mov eax, ds:[0x800411a]
      [-]ffd085c0eb05
         // 080037ef: call eax
         // 080037f1: test eax, eax
         // 080037f3: jmp 0x80037fa
      [-]6a306a0068????????ff7508ff15
         // 080037fc: push 0x30
         // 080037fe: push 0x0
         // 08003800: push 0x111
         // 08003805: push ss:[ebp+0x8]
         // 08003808: call ds:[SendMessageA]
      [-]6a316a0068????????ff7508ff15
         // 0800381a: push 0x31
         // 0800381c: push 0x0
         // 0800381e: push 0x111
         // 08003823: push ss:[ebp+0x8]
         // 08003826: call ds:[SendMessageA]
      [-]eb0083fb2d753b
         // 0800382c: jmp 0x800382e
         // 0800382e: cmp ebx, 0x2d
         // 08003831: jnz 0x800386e
      [-]33c0404040408bc88d15
         // 08003833: xor eax, eax
         // 08003835: inc eax
         // 08003836: inc eax
         // 08003837: inc eax
         // 08003838: inc eax
         // 08003839: mov ecx, eax
         // 0800383b: lea edx, ds:[0x80040b8]
      [-]8bfa83ef14
         // 08003841: mov edi, edx
         // 08003843: sub edi, 0x14
      [-]8b070302eb03
         // 08003846: mov eax, ds:[edi]
         // 08003848: add eax, ds:[edx]
         // 0800384a: jmp 0x800384f
      [-]890247474747424242424975ea
         // 0800384f: mov ds:[edx], eax
         // 08003851: inc edi
         // 08003852: inc edi
         // 08003853: inc edi
         // 08003854: inc edi
         // 08003855: inc edx
         // 08003856: inc edx
         // 08003857: inc edx
         // 08003858: inc edx
         // 08003859: dec ecx
         // 0800385a: jnz 0x8003846
      [-]6a2e6a0068????????ff7508ff15
         // 0800385c: push 0x2e
         // 0800385e: push 0x0
         // 08003860: push 0x111
         // 08003865: push ss:[ebp+0x8]
         // 08003868: call ds:[SendMessageA]
      [-]83fb307555
         // 0800386e: cmp ebx, 0x30
         // 08003871: jnz 0x80038c8
      [-]bf????????eb03
         // 08003879: mov edi, 0xfff
         // 0800387e: jmp 0x8003883
      [-]be????????eb05
         // 08003883: mov esi, 0xfffffffffffff000
         // 08003888: jmp 0x800388f
      [-]6a0103df23de68????????53eb03
         // 0800388f: push 0x1
         // 08003891: add ebx, edi
         // 08003893: and ebx, esi
         // 08003895: push 0x2000
         // 0800389a: push ebx
         // 0800389b: jmp 0x80038a0
      [-]85c00f8434fcffff
         // 080038ae: test eax, eax
         // 080038b0: jz 0x80034ea
      [-]6a316a0068????????ff7508ff15
         // 080038b6: push 0x31
         // 080038b8: push 0x0
         // 080038ba: push 0x111
         // 080038bf: push ss:[ebp+0x8]
         // 080038c2: call ds:[SendMessageA]
      [-]83fb310f8598000000
         // 080038c8: cmp ebx, 0x31
         // 080038cb: jnz 0x8003969
      [-]c1e1026a04bf????????03cf68????????eb03
         // 080038d7: shl ecx, b1 0x2
         // 080038da: push 0x4
         // 080038dc: mov edi, 0xfff
         // 080038e1: add ecx, edi
         // 080038e3: push 0x1000
         // 080038e8: jmp 0x80038ed
      [-]be????????23ce516a00a1
         // 080038ed: mov esi, 0xfffffffffffff000
         // 080038f2: and ecx, esi
         // 080038f4: push ecx
         // 080038f5: push 0x0
         // 080038f7: mov eax, ds:[0x8004460]
      [-]ffd0eb03
         // 08003901: call eax
         // 08003903: jmp 0x8003908
      [-]85c00f84dafbffff
         // 08003908: test eax, eax
         // 0800390a: jz 0x80034ea
      [-]c1e10203cf6a4023ceeb03
         // 08003927: shl ecx, b1 0x2
         // 0800392a: add ecx, edi
         // 0800392c: push 0x40
         // 0800392e: and ecx, esi
         // 08003930: jmp 0x8003935
      [-]5150b8????????a3
         // 08003935: push ecx
         // 08003936: push eax
         // 08003937: mov eax, 0x4
         // 0800393c: mov ds:[0x8004116], eax
      [-]ffd0eb03
         // 08003946: call eax
         // 08003948: jmp 0x800394d
      [-]85c00f8495fbffff
         // 0800394d: test eax, eax
         // 0800394f: jz 0x80034ea
      [-]6a326a0068????????ff7508ff15
         // 08003955: push 0x32
         // 08003957: push 0x0
         // 08003959: push 0x111
         // 0800395e: push ss:[ebp+0x8]
         // 08003961: call ds:[SendMessageA]
      [-]0bdb7464
         // 08003969: or ebx, ebx
         // 0800396b: jz 0x80039d1
      [-]83f9037512
         // 08003973: cmp ecx, 0x3
         // 08003976: jnz 0x800398a
      [-]83f904752c
         // 0800398a: cmp ecx, 0x4
         // 0800398d: jnz 0x80039bb
      [-]c1e910eb3d
         // 0800398f: shr ecx, b1 0x10
         // 08003992: jmp 0x80039d1
      [-]ff7514ff7510ff750cff7508ff15
         // 080039bd: push ss:[ebp+0x14]
         // 080039c0: push ss:[ebp+0x10]
         // 080039c3: push ss:[ebp+0xc]
         // 080039c6: push ss:[ebp+0x8]
         // 080039c9: call ds:[DefWindowProcA]
      [-]8be55dc21000
         // 080039d3: mov esp, ebp
         // 080039d5: pop ebp
         // 080039d6: retn b2 0x10
      [-]558becc705
         // 080039fd: push ebp
         // 080039fe: mov ebp, esp
         // 08003a00: mov ds:[0x80043a0], 0x30
      [-]6a00ff15
         // 08003a32: push 0x0
         // 08003a34: call ds:[GetModuleHandleA]
      [-]68????????6a00ff15
         // 08003a5e: push 0x7f00
         // 08003a63: push 0x0
         // 08003a65: call ds:[LoadIconA]
      [-]68????????6a00ff15
         // 08003a75: push 0x7f00
         // 08003a7a: push 0x0
         // 08003a7c: call ds:[LoadCursorA]
      [-]6a00ff35
         // 08003aa3: push 0x0
         // 08003aa5: push ds:[0x80040f6]
      [-]6a006a0068????????68????????68????????68????????68????????68
         // 08003aab: push 0x0
         // 08003aad: push 0x0
         // 08003aaf: push 0x1ef
         // 08003ab4: push 0x21c
         // 08003ab9: push 0xffffffffffffe688
         // 08003abe: push 0xfffffffffffff524
         // 08003ac3: push 0xcf0000
         // 08003ac8: push 0x800424e
      [-]6a00ff15
         // 08003ad2: push 0x0
         // 08003ad4: call ds:[CreateWindowExA]
      [-]6a01ff35
         // 08003adf: push 0x1
         // 08003ae1: push ds:[0x8004418]
      [-]33ff8d1d
         // 08003afe: xor edi, edi
         // 08003b00: lea ebx, ds:[0x80043d0]
      [-]57575753ff15
         // 08003b16: push edi
         // 08003b17: push edi
         // 08003b18: push edi
         // 08003b19: push ebx
         // 08003b1a: call ds:[GetMessageA]
      [-]84c075e4
         // 08003b20: test b1 al, b1 al
         // 08003b22: jnz 0x8003b08
      [-]eeffffc3
         // 08003b34: retn 

  }
  condition:
    all of them
}
