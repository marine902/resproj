rule jqbz_30_2 {
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
         // 08001069: mov ecx, ds:[0x800411e]
      [-]03f9eb0c
         // 0800106f: add edi, ecx
         // 08001071: jmp 0x800107f
      [-]03f903f9893d
         // 0800107f: add edi, ecx
         // 08001081: add edi, ecx
         // 08001083: mov ds:[0x8004464], edi
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
         // 0800113c: mov ds:[0x800411a], eax
      [-]8be55dc3
         // 08001146: mov esp, ebp
         // 08001148: pop ebp
         // 08001149: retn 
      [-]558bec83ec108b450825????????b9????????eb05
         // 080013cf: push ebp
         // 080013d0: mov ebp, esp
         // 080013d2: sub esp, 0x10
         // 080013d5: mov eax, ss:[ebp+0x8]
         // 080013d8: and eax, 0xffffffffffff0000
         // 080013dd: mov ecx, 0x5a4d
         // 080013e2: jmp 0x80013e9
      [-]2d????????
         // 080013e4: sub eax, 0x10000
      [-]66390875f6
         // 080013e9: cmp b2 ds:[eax], b2 cx
         // 080013ec: jnz 0x80013e4
      [-]0fb7483c538945fc8d440118b9????????56576639080f8598000000
         // 080013ee: movzx ecx, b2 ds:[eax+0x3c]
         // 080013f2: push ebx
         // 080013f3: mov ss:[ebp+0xfffffffffffffffc], eax
         // 080013f6: lea eax, ds:[ecx+eax+0x18]
         // 080013fa: mov ecx, 0x10b
         // 080013ff: push esi
         // 08001400: push edi
         // 08001401: cmp b2 ds:[eax], b2 cx
         // 08001404: jnz 0x80014a2
      [-]8b70600375fc8b7e208b4614037dfc8945f48b5d0c4b33c033c9fec8
         // 0800140a: mov esi, ds:[eax+0x60]
         // 0800140d: add esi, ss:[ebp+0xfffffffffffffffc]
         // 08001410: mov edi, ds:[esi+0x20]
         // 08001413: mov eax, ds:[esi+0x14]
         // 08001416: add edi, ss:[ebp+0xfffffffffffffffc]
         // 08001419: mov ss:[ebp+0xfffffffffffffff4], eax
         // 0800141c: mov ebx, ss:[ebp+0xc]
         // 0800141f: dec ebx
         // 08001420: xor eax, eax
         // 08001422: xor ecx, ecx
         // 08001424: dec b1 al
      [-]fec0438a0b85c975f7
         // 08001426: inc b1 al
         // 08001428: inc ebx
         // 08001429: mov b1 cl, b1 ds:[ebx]
         // 0800142b: test ecx, ecx
         // 0800142d: jnz 0x8001426
      [-]214df8394df48945f07668
         // 0800142f: and ss:[ebp+0xfffffffffffffff8], ecx
         // 08001432: cmp ss:[ebp+0xfffffffffffffff4], ecx
         // 08001435: mov ss:[ebp+0xfffffffffffffff0], eax
         // 08001438: jbe 0x80014a2
      [-]8b070345fc8bd84b33c0fec8
         // 0800143a: mov eax, ds:[edi]
         // 0800143c: add eax, ss:[ebp+0xfffffffffffffffc]
         // 0800143f: mov ebx, eax
         // 08001441: dec ebx
         // 08001442: xor eax, eax
         // 08001444: dec b1 al
      [-]fec0438a0b80f90075f6
         // 08001446: inc b1 al
         // 08001448: inc ebx
         // 08001449: mov b1 cl, b1 ds:[ebx]
         // 0800144b: cmp b1 cl, b1 0x0
         // 0800144e: jnz 0x8001446
      [-]3b45f07512
         // 08001450: cmp eax, ss:[ebp+0xfffffffffffffff0]
         // 08001453: jnz 0x8001467
      [-]8b070345fcff750c50e8
         // 08001455: mov eax, ds:[edi]
         // 08001457: add eax, ss:[ebp+0xfffffffffffffffc]
         // 0800145a: push ss:[ebp+0xc]
         // 0800145d: push eax
         // 0800145e: call 0x80033fa
      [-]000085c0740e
         // 08001463: test eax, eax
         // 08001465: jz 0x8001475
      [-]83c704ff45f88b45f83b45f472c5
         // 08001467: add edi, 0x4
         // 0800146a: inc ss:[ebp+0xfffffffffffffff8]
         // 0800146d: mov eax, ss:[ebp+0xfffffffffffffff8]
         // 08001470: cmp eax, ss:[ebp+0xfffffffffffffff4]
         // 08001473: jb 0x800143a
      [-]8b45f83b45f47325
         // 08001475: mov eax, ss:[ebp+0xfffffffffffffff8]
         // 08001478: cmp eax, ss:[ebp+0xfffffffffffffff4]
         // 0800147b: jnb 0x80014a2
      [-]8b4e10492bc18b4e2403c803c88b45fc03c80fb7018b4e1c8d04818b4dfc8b040103c1eb02
         // 0800147d: mov ecx, ds:[esi+0x10]
         // 08001480: dec ecx
         // 08001481: sub eax, ecx
         // 08001483: mov ecx, ds:[esi+0x24]
         // 08001486: add ecx, eax
         // 08001488: add ecx, eax
         // 0800148a: mov eax, ss:[ebp+0xfffffffffffffffc]
         // 0800148d: add ecx, eax
         // 0800148f: movzx eax, b2 ds:[ecx]
         // 08001492: mov ecx, ds:[esi+0x1c]
         // 08001495: lea eax, ds:[ecx+eax*0x4]
         // 08001498: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 0800149b: mov eax, ds:[ecx+eax]
         // 0800149e: add eax, ecx
         // 080014a0: jmp 0x80014a4
      [-]5f5e5b8be55dc20800
         // 080014a4: pop edi
         // 080014a5: pop esi
         // 080014a6: pop ebx
         // 080014a7: mov esp, ebp
         // 080014a9: pop ebp
         // 080014aa: retn b2 0x8
      [-]eb0003f88d0d
         // 08002b25: jmp 0x8002b27
         // 08002b27: add edi, eax
         // 08002b29: lea ecx, ds:[0x80040ee]
      [-]57eb00c3
         // 08002b2f: push edi
         // 08002b30: jmp 0x8002b32
         // 08002b32: retn 
      [-]8b0aeb05
         // 08002ce9: mov ecx, ds:[edx]
         // 08002ceb: jmp 0x8002cf2
      [-]8b7a048b0783c7048bf78bde03f8eb02
         // 08002cf2: mov edi, ds:[edx+0x4]
         // 08002cf5: mov eax, ds:[edi]
         // 08002cf7: add edi, 0x4
         // 08002cfa: mov esi, edi
         // 08002cfc: mov ebx, esi
         // 08002cfe: add edi, eax
         // 08002d00: jmp 0x8002d04
      [-]8bd74a2bc883e90452ba
         // 08002d04: mov edx, edi
         // 08002d06: dec edx
         // 08002d07: sub ecx, eax
         // 08002d09: sub ecx, 0x4
         // 08002d0c: push edx
         // 08002d0d: mov edx, 0x8004460
      [-]890a897a045a
         // 08002d12: mov ds:[edx], ecx
         // 08002d14: mov ds:[edx+0x4], edi
         // 08002d17: pop edx
      [-]8a078a260225
         // 08002d18: mov b1 al, b1 ds:[edi]
         // 08002d1a: mov b1 ah, b1 ds:[esi]
         // 08002d1c: add b1 ah, b1 ds:[0x8004123]
      [-]41000832c4eb03
         // 08002d22: xor b1 al, b1 ah
         // 08002d24: jmp 0x8002d29
      [-]88073bf27407
         // 08002d29: mov b1 ds:[edi], b1 al
         // 08002d2b: cmp esi, edx
         // 08002d2d: jz 0x8002d36
      [-]474975e4
         // 08002d30: inc edi
         // 08002d31: dec ecx
         // 08002d32: jnz 0x8002d18
      [-]8bfe6a3468
         // 08002d3f: mov edi, esi
         // 08002d41: push 0x34
         // 08002d43: push 0x8004460
      [-]68????????eb03
         // 08002d48: push 0x111
         // 08002d4d: jmp 0x8002d52
      [-]8a06880746474975f7
         // 08002d7e: mov b1 al, b1 ds:[esi]
         // 08002d80: mov b1 ds:[edi], b1 al
         // 08002d82: inc esi
         // 08002d83: inc edi
         // 08002d84: dec ecx
         // 08002d85: jnz 0x8002d7e
      [-]03ce890d
         // 08002d9b: add ecx, esi
         // 08002d9d: mov ds:[0x80043e4], ecx
      [-]598b0646469046468b3d
         // 08002da3: pop ecx
         // 08002da4: mov eax, ds:[esi]
         // 08002da6: inc esi
         // 08002da7: inc esi
         // 08002da8: nop 
         // 08002da9: inc esi
         // 08002daa: inc esi
         // 08002dab: mov edi, ds:[0x8004454]
      [-]8bde03d8891d
         // 08002db1: mov ebx, esi
         // 08002db3: add ebx, eax
         // 08002db5: mov ds:[0x80043e0], ebx
      [-]8bd6eb05
         // 08002dbb: mov edx, esi
         // 08002dbd: jmp 0x8002dc4
      [-]03f0b9????????0fb60240
         // 08002dc4: add esi, eax
         // 08002dc6: mov ecx, 0x0
         // 08002dcb: movzx eax, b1 ds:[edx]
         // 08002dce: inc eax
      [-]3bd37379
         // 08002dcf: cmp edx, ebx
         // 08002dd1: jnb 0x8002e4c
      [-]3bc17308
         // 08002dd3: cmp eax, ecx
         // 08002dd5: jnb 0x8002ddf
      [-]2bc18bc885c97409
         // 08002ddf: sub eax, ecx
         // 08002de1: mov ecx, eax
         // 08002de3: test ecx, ecx
         // 08002de5: jz 0x8002df0
      [-]8a06880746474975f7
         // 08002de7: mov b1 al, b1 ds:[esi]
         // 08002de9: mov b1 ds:[edi], b1 al
         // 08002deb: inc esi
         // 08002dec: inc edi
         // 08002ded: dec ecx
         // 08002dee: jnz 0x8002de7
      [-]428a02420fb60a85c97408
         // 08002df0: inc edx
         // 08002df1: mov b1 al, b1 ds:[edx]
         // 08002df3: inc edx
         // 08002df4: movzx ecx, b1 ds:[edx]
         // 08002df7: test ecx, ecx
         // 08002df9: jz 0x8002e03
      [-]8807474975fa
         // 08002dfc: mov b1 ds:[edi], b1 al
         // 08002dfe: inc edi
         // 08002dff: dec ecx
         // 08002e00: jnz 0x8002dfc
      [-]420fb602eb05
         // 08002e03: inc edx
         // 08002e04: movzx eax, b1 ds:[edx]
         // 08002e07: jmp 0x8002e0e
      [-]fec180f9007521
         // 08002e0e: inc b1 cl
         // 08002e10: cmp b1 cl, b1 0x0
         // 08002e13: jnz 0x8002e36
      [-]fec03c00750e
         // 08002e15: inc b1 al
         // 08002e17: cmp b1 al, b1 0x0
         // 08002e19: jnz 0x8002e29
      [-]0fb7024242eb09
         // 08002e22: movzx eax, b2 ds:[edx]
         // 08002e25: inc edx
         // 08002e26: inc edx
         // 08002e27: jmp 0x8002e32
      [-]b000fec8eb03
         // 08002e29: mov b1 al, b1 0x0
         // 08002e2b: dec b1 al
         // 08002e2d: jmp 0x8002e32
      [-]fec9eb12
         // 08002e32: dec b1 cl
         // 08002e34: jmp 0x8002e48
      [-]fec9fec03c007508
         // 08002e36: dec b1 cl
         // 08002e38: inc b1 al
         // 08002e3a: cmp b1 al, b1 0x0
         // 08002e3c: jnz 0x8002e46
      [-]420fb7024242eb02
         // 08002e3e: inc edx
         // 08002e3f: movzx eax, b2 ds:[edx]
         // 08002e42: inc edx
         // 08002e43: inc edx
         // 08002e44: jmp 0x8002e48
      [-]2bceeb05
         // 08002e52: sub ecx, esi
         // 08002e54: jmp 0x8002e5b
      [-]85c97409
         // 08002e5b: test ecx, ecx
         // 08002e5d: jz 0x8002e68
      [-]8a06880746474975f7
         // 08002e5f: mov b1 al, b1 ds:[esi]
         // 08002e61: mov b1 ds:[edi], b1 al
         // 08002e63: inc esi
         // 08002e64: inc edi
         // 08002e65: dec ecx
         // 08002e66: jnz 0x8002e5f
      [-]81ef????????893d
         // 08002e73: sub edi, 0x3fd
         // 08002e79: mov ds:[0x8004454], edi
      [-]558bec56578b7d0c33c033c98b7508
         // 080033fa: push ebp
         // 080033fb: mov ebp, esp
         // 080033fd: push esi
         // 080033fe: push edi
         // 080033ff: mov edi, ss:[ebp+0xc]
         // 08003402: xor eax, eax
         // 08003404: xor ecx, ecx
         // 08003406: mov esi, ss:[ebp+0x8]
      [-]8a068a0f3bc17508
         // 08003409: mov b1 al, b1 ds:[esi]
         // 0800340b: mov b1 cl, b1 ds:[edi]
         // 0800340d: cmp eax, ecx
         // 0800340f: jnz 0x8003419
      [-]85c97407
         // 08003411: test ecx, ecx
         // 08003413: jz 0x800341c
      [-]4647ebf0
         // 08003415: inc esi
         // 08003416: inc edi
         // 08003417: jmp 0x8003409
      [-]5f5e8be55dc20800
         // 0800341c: pop edi
         // 0800341d: pop esi
         // 0800341e: mov esp, ebp
         // 08003420: pop ebp
         // 08003421: retn b2 0x8
      [-]558bec83c4a08b450c83f8010f85
         // 08003424: push ebp
         // 08003425: mov ebp, esp
         // 08003427: add esp, 0xffffffffffffffa0
         // 0800342a: mov eax, ss:[ebp+0xc]
         // 0800342d: cmp eax, 0x1
         // 08003430: jnz 0x80035a0
      [-]8b7d086a00ff35
         // 08003436: mov edi, ss:[ebp+0x8]
         // 08003439: push 0x0
         // 0800343b: push ds:[0x80040ee]
      [-]6a02576a2868????????6a0a6a0a68????????68
         // 08003441: push 0x2
         // 08003443: push edi
         // 08003444: push 0x28
         // 08003446: push 0x140
         // 0800344b: push 0xa
         // 0800344d: push 0xa
         // 0800344f: push 0x10000001
         // 08003454: push 0x80041d8
      [-]6a00ff15
         // 0800345e: push 0x0
         // 08003460: call ds:[CreateWindowExA]
      [-]85c0750b
         // 0800346d: test eax, eax
         // 0800346f: jnz 0x800347c
      [-]6a2b6a0068????????ff7508ff15
         // 08003481: push 0x2b
         // 08003483: push 0x0
         // 08003485: push 0x111
         // 0800348a: push ss:[ebp+0x8]
         // 0800348d: call ds:[SendMessageA]
      [-]6a00ff35
         // 08003493: push 0x0
         // 08003495: push ds:[0x80040ee]
      [-]6a015768????????68????????6a466a0a68????????6a0068
         // 0800349b: push 0x1
         // 0800349d: push edi
         // 0800349e: push 0x1ae
         // 080034a3: push 0x1f4
         // 080034a8: push 0x46
         // 080034aa: push 0xa
         // 080034ac: push 0x40000000
         // 080034b1: push 0x0
         // 080034b3: push 0x8004232
      [-]6a00ff15
         // 080034b8: push 0x0
         // 080034ba: call ds:[CreateWindowExA]
      [-]85c0750b
         // 080034c5: test eax, eax
         // 080034c7: jnz 0x80034d4
      [-]6a00ff35
         // 080034d9: push 0x0
         // 080034db: push ds:[0x80040ee]
      [-]6a02ff750c6a2268????????68????????6a0a68????????68
         // 080034e1: push 0x2
         // 080034e3: push ss:[ebp+0xc]
         // 080034e6: push 0x22
         // 080034e8: push 0xa6
         // 080034ed: push 0x17c
         // 080034f2: push 0xa
         // 080034f4: push 0x40000001
         // 080034f9: push 0x80041d8
      [-]6a00ff15
         // 08003503: push 0x0
         // 08003505: call ds:[CreateWindowExA]
      [-]85c0750b
         // 0800350b: test eax, eax
         // 0800350d: jnz 0x800351a
      [-]68????????ff7508ff15
         // 0800355f: push 0x402
         // 08003564: push ss:[ebp+0x8]
         // 08003567: call ds:[SendMessageA]
      [-]68????????68????????68????????68????????ff
         // 08003579: push 0x1f9
         // 0800357e: push 0x226
         // 08003583: push 0xfffffffffffff3f8
         // 08003588: push 0xfffffffffffff18c
         // 0800358d: push ss:[ebp+0x8]
      [-]e970050000
         // 08003596: jmp 0x8003b0b
      [-]3d????????7538
         // 080035a0: cmp eax, 0x402
         // 080035a5: jnz 0x80035df
      [-]8b5510eb03
         // 080035a7: mov edx, ss:[ebp+0x10]
         // 080035aa: jmp 0x80035af
      [-]33c94141eb03
         // 080035af: xor ecx, ecx
         // 080035b1: inc ecx
         // 080035b2: inc ecx
         // 080035b3: jmp 0x80035b8
      [-]41418bd941
         // 080035b8: inc ecx
         // 080035b9: inc ecx
         // 080035ba: mov ebx, ecx
         // 080035bc: inc ecx
      [-]8b4214eb03
         // 080035bd: mov eax, ds:[edx+0x14]
         // 080035c0: jmp 0x80035c5
      [-]8b3a03c7eb03
         // 080035c5: mov edi, ds:[edx]
         // 080035c7: add eax, edi
         // 080035c9: jmp 0x80035ce
      [-]890203d34975e8
         // 080035ce: mov ds:[edx], eax
         // 080035d0: add edx, ebx
         // 080035d2: dec ecx
         // 080035d3: jnz 0x80035bd
      [-]e931050000
         // 080035d5: jmp 0x8003b0b
      [-]3d????????7539
         // 080035df: cmp eax, 0x401
         // 080035e4: jnz 0x800361f
      [-]b9????????8b5510eb03
         // 080035e6: mov ecx, 0x6
         // 080035eb: mov edx, ss:[ebp+0x10]
         // 080035ee: jmp 0x80035f3
      [-]8b3a424242428b32eb05
         // 080035f3: mov edi, ds:[edx]
         // 080035f5: inc edx
         // 080035f6: inc edx
         // 080035f7: inc edx
         // 080035f8: inc edx
         // 080035f9: mov esi, ds:[edx]
         // 080035fb: jmp 0x8003602
      [-]8b551441
         // 08003602: mov edx, ss:[ebp+0x14]
         // 08003605: inc ecx
      [-]8a078806472bf24975f6
         // 08003606: mov b1 al, b1 ds:[edi]
         // 08003608: mov b1 ds:[esi], b1 al
         // 0800360a: inc edi
         // 0800360b: sub esi, edx
         // 0800360d: dec ecx
         // 0800360e: jnz 0x8003606
      [-]e9f1040000
         // 08003615: jmp 0x8003b0b
      [-]83f8027516
         // 0800361f: cmp eax, 0x2
         // 08003622: jnz 0x800363a
      [-]e9d6040000
         // 08003630: jmp 0x8003b0b
      [-]83f80f752e
         // 0800363a: cmp eax, 0xf
         // 0800363d: jnz 0x800366d
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
         // 0800366d: cmp eax, 0x5
         // 08003670: jnz 0x80036c5
      [-]68????????ff7508ff15
         // 08003679: push 0x402
         // 0800367e: push ss:[ebp+0x8]
         // 08003681: call ds:[SendMessageA]
      [-]8d45f050ff7508ff15
         // 08003687: lea eax, ss:[ebp+0xfffffffffffffff0]
         // 0800368a: push eax
         // 0800368b: push ss:[ebp+0x8]
         // 0800368e: call ds:[GetWindowRect]
      [-]8b45f88b4df02bc1508b45fc8b4df42bc18bc8582bc1506a0068????????ff7508ff15
         // 08003694: mov eax, ss:[ebp+0xfffffffffffffff8]
         // 08003697: mov ecx, ss:[ebp+0xfffffffffffffff0]
         // 0800369a: sub eax, ecx
         // 0800369c: push eax
         // 0800369d: mov eax, ss:[ebp+0xfffffffffffffffc]
         // 080036a0: mov ecx, ss:[ebp+0xfffffffffffffff4]
         // 080036a3: sub eax, ecx
         // 080036a5: mov ecx, eax
         // 080036a7: pop eax
         // 080036a8: sub eax, ecx
         // 080036aa: push eax
         // 080036ab: push 0x0
         // 080036ad: push 0x111
         // 080036b2: push ss:[ebp+0x8]
         // 080036b5: call ds:[SendMessageA]
      [-]e94b040000
         // 080036bb: jmp 0x8003b0b
      [-]3d????????0f8527040000
         // 080036c5: cmp eax, 0x111
         // 080036ca: jnz 0x8003af7
      [-]8b45108b5d1483fb2a7530
         // 080036d0: mov eax, ss:[ebp+0x10]
         // 080036d3: mov ebx, ss:[ebp+0x14]
         // 080036d6: cmp ebx, 0x2a
         // 080036d9: jnz 0x800370b
      [-]6a0068????????6a036a00eb04
         // 080036e7: push 0x0
         // 080036e9: push 0x80
         // 080036ee: push 0x3
         // 080036f0: push 0x0
         // 080036f2: jmp 0x80036f8
      [-]6a0168????????68
         // 080036f8: push 0x1
         // 080036fa: push 0xffffffff80000000
         // 080036ff: push 0x80041f0
      [-]ffd0e902040000
         // 08003704: call eax
         // 08003706: jmp 0x8003b0d
      [-]83fb2b753d
         // 0800370b: cmp ebx, 0x2b
         // 0800370e: jnz 0x800374d
      [-]6a2a6a0068????????ff7508ff15
         // 08003715: push 0x2a
         // 08003717: push 0x0
         // 08003719: push 0x111
         // 0800371e: push ss:[ebp+0x8]
         // 08003721: call ds:[SendMessageA]
      [-]83f8047305
         // 0800373e: cmp eax, 0x4
         // 08003741: jnb 0x8003748
      [-]e9dcfeffff
         // 08003743: jmp 0x8003624
      [-]e9be030000
         // 08003748: jmp 0x8003b0b
      [-]81fb????????754a
         // 0800374d: cmp ebx, 0x579
         // 08003753: jnz 0x800379f
      [-]ffd0eb03
         // 08003766: call eax
         // 08003768: jmp 0x800376d
      [-]5040eb03
         // 08003777: push eax
         // 08003778: inc eax
         // 08003779: jmp 0x800377e
      [-]58c1e0080105
         // 08003784: pop eax
         // 08003785: shl eax, b1 0x8
         // 08003788: add ds:[0x8004454], eax
      [-]e96c030000
         // 0800379a: jmp 0x8003b0b
      [-]83fb327550
         // 0800379f: cmp ebx, 0x32
         // 080037a2: jnz 0x80037f4
      [-]508b4508a3
         // 080037ae: push eax
         // 080037af: mov eax, ss:[ebp+0x8]
         // 080037b2: mov ds:[0x8004404], eax
      [-]5885c07507
         // 080037b7: pop eax
         // 080037b8: test eax, eax
         // 080037ba: jnz 0x80037c3
      [-]40506a0068????????ff7508ff15
         // 080037c3: inc eax
         // 080037c4: push eax
         // 080037c5: push 0x0
         // 080037c7: push 0x111
         // 080037cc: push ss:[ebp+0x8]
         // 080037cf: call ds:[SendMessageA]
      [-]6a046a0068
         // 080037da: push 0x4
         // 080037dc: push 0x0
         // 080037de: push 0x80041d8
      [-]e917030000
         // 080037ef: jmp 0x8003b0b
      [-]83fb340f8589000000
         // 080037f4: cmp ebx, 0x34
         // 080037f7: jnz 0x8003886
      [-]8b5510eb03
         // 080037fd: mov edx, ss:[ebp+0x10]
         // 08003800: jmp 0x8003805
      [-]8b0a8b7a048b35
         // 08003805: mov ecx, ds:[edx]
         // 08003807: mov edi, ds:[edx+0x4]
         // 0800380a: mov esi, ds:[0x8004454]
      [-]03f157514e0fb70d
         // 08003810: add esi, ecx
         // 08003812: push edi
         // 08003813: push ecx
         // 08003814: dec esi
         // 08003815: movzx ecx, b2 ds:[0x80040ec]
      [-]400008eb03
         // 0800381c: jmp 0x8003821
      [-]8a07880647562bf2893d
         // 08003823: mov b1 al, b1 ds:[edi]
         // 08003825: mov b1 ds:[esi], b1 al
         // 08003827: inc edi
         // 08003828: push esi
         // 08003829: sub esi, edx
         // 0800382b: mov ds:[0x8004458], edi
      [-]51525268
         // 08003837: push ecx
         // 08003838: push edx
         // 08003839: push edx
         // 0800383a: push 0x8004458
      [-]68????????ff35
         // 0800383f: push 0x401
         // 08003844: push ds:[0x8004404]
      [-]5a5983c7075e4e4975c9
         // 08003850: pop edx
         // 08003851: pop ecx
         // 08003852: add edi, 0x7
         // 08003855: pop esi
         // 08003856: dec esi
         // 08003857: dec ecx
         // 08003858: jnz 0x8003823
      [-]598bc183e1075f85c97417
         // 0800385f: pop ecx
         // 08003860: mov eax, ecx
         // 08003862: and ecx, 0x7
         // 08003865: pop edi
         // 08003866: test ecx, ecx
         // 08003868: jz 0x8003881
      [-]4903f103f8412bf9
         // 08003870: dec ecx
         // 08003871: add esi, ecx
         // 08003873: add edi, eax
         // 08003875: inc ecx
         // 08003876: sub edi, ecx
      [-]8a078806474e4975f7
         // 08003878: mov b1 al, b1 ds:[edi]
         // 0800387a: mov b1 ds:[esi], b1 al
         // 0800387c: inc edi
         // 0800387d: dec esi
         // 0800387e: dec ecx
         // 0800387f: jnz 0x8003878
      [-]e985020000
         // 08003881: jmp 0x8003b0b
      [-]83fb2e7558
         // 08003886: cmp ebx, 0x2e
         // 08003889: jnz 0x80038e3
      [-]83c2045256e8
         // 0800389c: add edx, 0x4
         // 0800389f: push edx
         // 080038a0: push esi
         // 080038a1: call 0x80013cf
      [-]ffffeb03
         // 080038a6: jmp 0x80038ab
      [-]83c2054a5256eb03
         // 080038b6: add edx, 0x5
         // 080038b9: dec edx
         // 080038ba: push edx
         // 080038bb: push esi
         // 080038bc: jmp 0x80038c1
      [-]6a2f6a0068????????ff7508ff15
         // 080038d1: push 0x2f
         // 080038d3: push 0x0
         // 080038d5: push 0x111
         // 080038da: push ss:[ebp+0x8]
         // 080038dd: call ds:[SendMessageA]
      [-]83fb2f757e
         // 080038e3: cmp ebx, 0x2f
         // 080038e6: jnz 0x8003966
      [-]bf????????be????????6a0103dfeb02
         // 08003904: mov edi, 0xfff
         // 08003909: mov esi, 0xfffffffffffff000
         // 0800390e: push 0x1
         // 08003910: add ebx, edi
         // 08003912: jmp 0x8003916
      [-]23de68????????53a1
         // 08003916: and ebx, esi
         // 08003918: push 0x2000
         // 0800391d: push ebx
         // 0800391e: mov eax, ds:[0x8004112]
      [-]ffd085c0eb05
         // 08003929: call eax
         // 0800392b: test eax, eax
         // 0800392d: jmp 0x8003934
      [-]6a306a0068????????ff7508ff15
         // 080037fc: push 0x30
         // 080037fe: push 0x0
         // 08003800: push 0x111
         // 08003805: push ss:[ebp+0x8]
         // 08003808: call ds:[SendMessageA]
      [-]6a316a0068????????ff7508ff15
         // 08003954: push 0x31
         // 08003956: push 0x0
         // 08003958: push 0x111
         // 0800395d: push ss:[ebp+0x8]
         // 08003960: call ds:[SendMessageA]
      [-]eb0083fb2d753b
         // 08003966: jmp 0x8003968
         // 08003968: cmp ebx, 0x2d
         // 0800396b: jnz 0x80039a8
      [-]33c0404040408bc88d15
         // 0800396d: xor eax, eax
         // 0800396f: inc eax
         // 08003970: inc eax
         // 08003971: inc eax
         // 08003972: inc eax
         // 08003973: mov ecx, eax
         // 08003975: lea edx, ds:[0x80040b0]
      [-]8bfa83ef14
         // 0800397b: mov edi, edx
         // 0800397d: sub edi, 0x14
      [-]8b070302eb03
         // 08003980: mov eax, ds:[edi]
         // 08003982: add eax, ds:[edx]
         // 08003984: jmp 0x8003989
      [-]890247474747424242424975ea
         // 08003989: mov ds:[edx], eax
         // 0800398b: inc edi
         // 0800398c: inc edi
         // 0800398d: inc edi
         // 0800398e: inc edi
         // 0800398f: inc edx
         // 08003990: inc edx
         // 08003991: inc edx
         // 08003992: inc edx
         // 08003993: dec ecx
         // 08003994: jnz 0x8003980
      [-]6a2e6a0068????????ff7508ff15
         // 0800385c: push 0x2e
         // 0800385e: push 0x0
         // 08003860: push 0x111
         // 08003865: push ss:[ebp+0x8]
         // 08003868: call ds:[SendMessageA]
      [-]83fb307555
         // 080039a8: cmp ebx, 0x30
         // 080039ab: jnz 0x8003a02
      [-]bf????????eb03
         // 080039b3: mov edi, 0xfff
         // 080039b8: jmp 0x80039bd
      [-]be????????eb05
         // 080039bd: mov esi, 0xfffffffffffff000
         // 080039c2: jmp 0x80039c9
      [-]6a0103df23de68????????53eb03
         // 080039c9: push 0x1
         // 080039cb: add ebx, edi
         // 080039cd: and ebx, esi
         // 080039cf: push 0x2000
         // 080039d4: push ebx
         // 080039d5: jmp 0x80039da
      [-]85c00f8434fcffff
         // 080039e8: test eax, eax
         // 080039ea: jz 0x8003624
      [-]6a316a0068????????ff7508ff15
         // 080038b6: push 0x31
         // 080038b8: push 0x0
         // 080038ba: push 0x111
         // 080038bf: push ss:[ebp+0x8]
         // 080038c2: call ds:[SendMessageA]
      [-]83fb310f8598000000
         // 08003a02: cmp ebx, 0x31
         // 08003a05: jnz 0x8003aa3
      [-]c1e1026a04bf????????03cf68????????eb03
         // 08003a11: shl ecx, b1 0x2
         // 08003a14: push 0x4
         // 08003a16: mov edi, 0xfff
         // 08003a1b: add ecx, edi
         // 08003a1d: push 0x1000
         // 08003a22: jmp 0x8003a27
      [-]be????????23ce516a00a1
         // 08003a27: mov esi, 0xfffffffffffff000
         // 08003a2c: and ecx, esi
         // 08003a2e: push ecx
         // 08003a2f: push 0x0
         // 08003a31: mov eax, ds:[0x800444c]
      [-]ffd0eb03
         // 08003a3b: call eax
         // 08003a3d: jmp 0x8003a42
      [-]85c00f84dafbffff
         // 08003a42: test eax, eax
         // 08003a44: jz 0x8003624
      [-]c1e10203cf6a4023ceeb03
         // 08003a61: shl ecx, b1 0x2
         // 08003a64: add ecx, edi
         // 08003a66: push 0x40
         // 08003a68: and ecx, esi
         // 08003a6a: jmp 0x8003a6f
      [-]5150b8????????a3
         // 08003a6f: push ecx
         // 08003a70: push eax
         // 08003a71: mov eax, 0x4
         // 08003a76: mov ds:[0x800410e], eax
      [-]ffd0eb03
         // 08003a80: call eax
         // 08003a82: jmp 0x8003a87
      [-]85c00f8495fbffff
         // 08003a87: test eax, eax
         // 08003a89: jz 0x8003624
      [-]6a326a0068????????ff7508ff15
         // 08003955: push 0x32
         // 08003957: push 0x0
         // 08003959: push 0x111
         // 0800395e: push ss:[ebp+0x8]
         // 08003961: call ds:[SendMessageA]
      [-]0bdb7464
         // 08003aa3: or ebx, ebx
         // 08003aa5: jz 0x8003b0b
      [-]83f9037512
         // 08003aad: cmp ecx, 0x3
         // 08003ab0: jnz 0x8003ac4
      [-]83f904752c
         // 08003ac4: cmp ecx, 0x4
         // 08003ac7: jnz 0x8003af5
      [-]c1e910eb3d
         // 08003ac9: shr ecx, b1 0x10
         // 08003acc: jmp 0x8003b0b
      [-]ff7514ff7510ff750cff7508ff15
         // 080039bd: push ss:[ebp+0x14]
         // 080039c0: push ss:[ebp+0x10]
         // 080039c3: push ss:[ebp+0xc]
         // 080039c6: push ss:[ebp+0x8]
         // 080039c9: call ds:[DefWindowProcA]
      [-]8be55dc21000
         // 08003b0d: mov esp, ebp
         // 08003b0f: pop ebp
         // 08003b10: retn b2 0x10
      [-]558becc705
         // 08003b13: push ebp
         // 08003b14: mov ebp, esp
         // 08003b16: mov ds:[0x800438c], 0x30
      [-]6a00ff15
         // 08003b48: push 0x0
         // 08003b4a: call ds:[GetModuleHandleA]
      [-]68????????6a00ff15
         // 08003b74: push 0x7f00
         // 08003b79: push 0x0
         // 08003b7b: call ds:[LoadIconA]
      [-]68????????6a00ff15
         // 08003b8b: push 0x7f00
         // 08003b90: push 0x0
         // 08003b92: call ds:[LoadCursorA]
      [-]6a00ff35
         // 08003bb9: push 0x0
         // 08003bbb: push ds:[0x80040ee]
      [-]6a006a0068????????68????????68????????68????????68????????68
         // 08003bc1: push 0x0
         // 08003bc3: push 0x0
         // 08003bc5: push 0x1ef
         // 08003bca: push 0x21c
         // 08003bcf: push 0xffffffffffffe688
         // 08003bd4: push 0xfffffffffffff524
         // 08003bd9: push 0xcf0000
         // 08003bde: push 0x800423e
      [-]6a00ff15
         // 08003be8: push 0x0
         // 08003bea: call ds:[CreateWindowExA]
      [-]6a01ff35
         // 08003bf5: push 0x1
         // 08003bf7: push ds:[0x8004404]
      [-]33ff8d1d
         // 08003c14: xor edi, edi
         // 08003c16: lea ebx, ds:[0x80043bc]
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
         // 08003c4a: retn 

  }
  condition:
    all of them
}
