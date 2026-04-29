rule genie_30_0 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         e903000000
         // 00403d2c: jmp @System@@Pow10$qqrv
      [-]0f849a000000
         // 00403d3b: jz 0x403ddb
      [-]3d????????0f8d81000000
         // 00403d41: cmp eax, 0x1400
         // 00403d46: jge 0x403dcd
      [-]83e21f8d1492dbac53
         // 00404b06: and edx, 0x1f
         // 00404b09: lea edx, ds:[edx+edx*0x4]
         // 00404b0c: fld b10 ds:[ebx+edx*0x2]
      [-]4000dec9c1e8057479
         // 00404b13: fmulp b8 st(1), b10 st(0)
         // 00404b15: shr eax, b1 0x5
         // 00404b18: jz 0x404b93
      [-]83e20f740c
         // 00403d64: and edx, 0xf
         // 00403d67: jz 0x403d75
      [-]8d1492dbac53
         // 00402df1: lea edx, ds:[edx+edx*0x4]
         // 00402df4: fld b10 ds:[ebx+edx*0x2]
      [-]4000dec9
         // 00402dfb: fmulp b8 st(1), b10 st(0)
      [-]c1e8047461
         // 00403d75: shr eax, b1 0x4
         // 00403d78: jz 0x403ddb
      [-]8d0480dbac43
         // 00402e02: lea eax, ds:[eax+eax*0x4]
         // 00402e05: fld b10 ds:[ebx+eax*0x2]
      [-]4000dec9eb53
         // 00402e0c: fmulp b8 st(1), b10 st(0)
         // 00402e0e: jmp 0x402e63
      [-]f7d83d????????7d46
         // 00403d88: neg eax
         // 00403d8a: cmp eax, 0x1400
         // 00403d8f: jge 0x403dd7
      [-]83e21f8d1492dbac53
         // 0040348b: and edx, 0x1f
         // 0040348e: lea edx, ds:[edx+edx*0x4]
         // 00403491: fld b10 ds:[ebx+edx*0x2]
      [-]4000def9c1e8057434
         // 00403498: fdivp b8 st(1), b10 st(0)
         // 0040349a: shr eax, b1 0x5
         // 0040349d: jz 0x4034d3
      [-]83e20f740c
         // 00403da9: and edx, 0xf
         // 00403dac: jz 0x403dba
      [-]8d1492dbac53
         // 00402e36: lea edx, ds:[edx+edx*0x4]
         // 00402e39: fld b10 ds:[ebx+edx*0x2]
      [-]4000def9
         // 00402e40: fdivp b8 st(1), b10 st(0)
      [-]c1e804741c
         // 00403dba: shr eax, b1 0x4
         // 00403dbd: jz 0x403ddb
      [-]8d0480dbac43
         // 00402e47: lea eax, ds:[eax+eax*0x4]
         // 00402e4a: fld b10 ds:[ebx+eax*0x2]
      [-]4000def9eb0e
         // 00402e51: fdivp b8 st(1), b10 st(0)
         // 00402e53: jmp 0x402e63
      [-]ddd8dbab
         // 00402e55: fstp b10 st(0)
         // 00402e57: fld b10 ds:[ebx+0x402e65]
      [-]4000eb04
         // 00402e5d: jmp 0x402e63
      [-]ddd8d9ee
         // 00403dd7: fstp b10 st(0)
         // 00403dd9: fldz 
      [-]e8a6000000
         // 00404199: call @System@TObject@CleanupInstance$qqrv
      [-]ffff5bc3
         // 004041a5: pop ebx
         // 004041a6: retn 
      [-]e8f3ffffff48c3
         // 0040673c: call 0x406734
         // 00406741: dec eax
         // 00406742: retn 
      [-]ac08c07503
         // 0040cb0a: lodsbb 
         // 0040cb0b: or b1 al, b1 al
         // 0040cb0d: jnz 0x40cb12
      [-]83fa127205
         // 0040cbb8: cmp edx, 0x12
         // 0040cbbb: jb 0x40cbc2
      [-]48b303f6f388e343
         // 0040cbd9: dec eax
         // 0040cbda: mov b1 bl, b1 0x3
         // 0040cbdc: div b1 bl
         // 0040cbde: mov b1 bl, b1 ah
         // 0040cbe0: inc ebx
      [-]242a4040402a2440404024202a40402a2024404028242a29402d242a4040242d2a4040242a2d????????2429402d????????2a2d2440402a242d40402d????????2d????????2a20242d4024202a2d4024202d2a402a2d????????24202a29282a202429
         // 0040cc7d: and b1 al, b1 0x2a
         // 0040cc7f: inc eax
         // 0040cc80: inc eax
         // 0040cc81: inc eax
         // 0040cc82: sub b1 ah, b1 ds:[eax+eax*0x2]
         // 0040cc85: inc eax
         // 0040cc86: inc eax
         // 0040cc87: and b1 al, b1 0x20
         // 0040cc89: sub b1 al, b1 ds:[eax+0x40]
         // 0040cc8c: sub b1 ah, b1 ds:[eax]
         // 0040cc8e: and b1 al, b1 0x40
         // 0040cc90: inc eax
         // 0040cc91: sub b1 ds:[edx+ebp], b1 ah
         // 0040cc94: sub ds:[eax+0x2d], eax
         // 0040cc97: and b1 al, b1 0x2a
         // 0040cc99: inc eax
         // 0040cc9a: inc eax
         // 0040cc9b: and b1 al, b1 0x2d
         // 0040cc9d: sub b1 al, b1 ds:[eax+0x40]
         // 0040cca0: and b1 al, b1 0x2a
         // 0040cca2: sub eax, 0x2a284040
         // 0040cca7: and b1 al, b1 0x29
         // 0040cca9: inc eax
         // 0040ccaa: sub eax, 0x4040242a
         // 0040ccaf: sub b1 ch, b1 ds:[0x2a404024]
         // 0040ccb5: and b1 al, b1 0x2d
         // 0040ccb7: inc eax
         // 0040ccb8: inc eax
         // 0040ccb9: sub eax, 0x4024202a
         // 0040ccbe: sub eax, 0x402a2024
         // 0040ccc3: sub b1 ah, b1 ds:[eax]
         // 0040ccc5: and b1 al, b1 0x2d
         // 0040ccc7: inc eax
         // 0040ccc8: and b1 al, b1 0x20
         // 0040ccca: sub b1 ch, b1 ds:[0x2d202440]
         // 0040ccd0: sub b1 al, b1 ds:[eax+0x2a]
         // 0040ccd3: sub eax, 0x28402420
         // 0040ccd8: and b1 al, b1 0x20
         // 0040ccda: sub b1 ch, b1 ds:[ecx]
         // 0040ccdc: sub b1 ds:[edx], b1 ch
         // 0040ccde: and b1 ds:[ecx+ebp], b1 ah
      [-]8be55dc2
         // 0040cce1: mov esp, ebp
         // 0040cce3: pop ebp
         // 0040cce4: retn b2 0xc
      [-]64ff306489208d55fca1
         // 00428d85: push fs:[eax]
         // 00428d88: mov fs:[eax], esp
         // 00428d8b: lea edx, ss:[ebp+0xfffffffffffffffc]
         // 00428d8e: mov eax, ds:[0x53f524]
      [-]8b4dfcb201a1
         // 00428d98: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 00428d9b: mov b1 dl, b1 0x1
         // 00428d9d: mov eax, ds:[0x428538]
      [-]5a595964891068
         // 00428dae: pop edx
         // 00428daf: pop ecx
         // 00428db0: pop ecx
         // 00428db1: mov fs:[eax], edx
         // 00428db4: push 0x428dc9
      [-]8d45fce8
         // 00428db9: lea eax, ss:[ebp+0xfffffffffffffffc]
         // 00428dbc: call 0x406968
      [-]83c4e45356
         // 00428dcf: add esp, 0xffffffffffffffe4
         // 00428dd2: push ebx
         // 00428dd3: push esi
      [-]64ff306489208d55ec
         // 00428deb: push fs:[eax]
         // 00428dee: mov fs:[eax], esp
         // 00428df1: lea edx, ss:[ebp+0xffffffffffffffec]
      [-]00008b45ec8945f0c645f4
         // 00428dfb: mov eax, ss:[ebp+0xffffffffffffffec]
         // 00428dfe: mov ss:[ebp+0xfffffffffffffff0], eax
         // 00428e01: mov b1 ss:[ebp+0xfffffffffffffff4], b1 0x11
      [-]00008b45e88945f8c645fc
         // 00428e0f: mov eax, ss:[ebp+0xffffffffffffffe8]
         // 00428e12: mov ss:[ebp+0xfffffffffffffff8], eax
         // 00428e15: mov b1 ss:[ebp+0xfffffffffffffffc], b1 0x11
      [-]8d45f0506a018d55e4a1
         // 00428e19: lea eax, ss:[ebp+0xfffffffffffffff0]
         // 00428e1c: push eax
         // 00428e1d: push 0x1
         // 00428e1f: lea edx, ss:[ebp+0xffffffffffffffe4]
         // 00428e22: mov eax, ds:[0x53ef48]
      [-]8b4de4b201a1
         // 00428e2c: mov ecx, ss:[ebp+0xffffffffffffffe4]
         // 00428e2f: mov b1 dl, b1 0x1
         // 00428e31: mov eax, ds:[0x428538]
      [-]5a595964891068
         // 00428e42: pop edx
         // 00428e43: pop ecx
         // 00428e44: pop ecx
         // 00428e45: mov fs:[eax], edx
         // 00428e48: push 0x428e62
      [-]558bec6a00
         // 0040e3cc: push ebp
         // 0040e3cd: mov ebp, esp
         // 0040e3cf: push 0x0
      [-]64ff306489208d55fca1
         // 0040e3d9: push fs:[eax]
         // 0040e3dc: mov fs:[eax], esp
         // 0040e3df: lea edx, ss:[ebp+0xfffffffffffffffc]
         // 0040e3e2: mov eax, ds:[0x450f1c]
      [-]8b4dfcb201a1
         // 0040e3ec: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 0040e3ef: mov b1 dl, b1 0x1
         // 0040e3f1: mov eax, ds:[0x40de20]
      [-]5a595964891068
         // 0040e402: pop edx
         // 0040e403: pop ecx
         // 0040e404: pop ecx
         // 0040e405: mov fs:[eax], edx
         // 0040e408: push 0x40e41d
      [-]8d45fce8
         // 0040e40d: lea eax, ss:[ebp+0xfffffffffffffffc]
         // 0040e410: call @System@@LStrClr$qqrpv
      [-]83c4e45356
         // 0041336f: add esp, 0xffffffffffffffe4
         // 00413372: push ebx
         // 00413373: push esi
      [-]64ff306489208d55ec
         // 0041338b: push fs:[eax]
         // 0041338e: mov fs:[eax], esp
         // 00413391: lea edx, ss:[ebp+0xffffffffffffffec]
      [-]00008b45ec8945f0c645f4
         // 0041339b: mov eax, ss:[ebp+0xffffffffffffffec]
         // 0041339e: mov ss:[ebp+0xfffffffffffffff0], eax
         // 004133a1: mov b1 ss:[ebp+0xfffffffffffffff4], b1 0xb
      [-]00008b45e88945f8c645fc
         // 004133af: mov eax, ss:[ebp+0xffffffffffffffe8]
         // 004133b2: mov ss:[ebp+0xfffffffffffffff8], eax
         // 004133b5: mov b1 ss:[ebp+0xfffffffffffffffc], b1 0xb
      [-]8d45f0506a018d55e4a1
         // 004133b9: lea eax, ss:[ebp+0xfffffffffffffff0]
         // 004133bc: push eax
         // 004133bd: push 0x1
         // 004133bf: lea edx, ss:[ebp+0xffffffffffffffe4]
         // 004133c2: mov eax, ds:[0xa09a98]
      [-]8b4de4b201a1
         // 004133cc: mov ecx, ss:[ebp+0xffffffffffffffe4]
         // 004133cf: mov b1 dl, b1 0x1
         // 004133d1: mov eax, ds:[0x412d78]
      [-]5a595964891068
         // 004133e2: pop edx
         // 004133e3: pop ecx
         // 004133e4: pop ecx
         // 004133e5: mov fs:[eax], edx
         // 004133e8: push 0x413402
      [-]64ff306489208d55fca1
         // 00428fb9: push fs:[eax]
         // 00428fbc: mov fs:[eax], esp
         // 00428fbf: lea edx, ss:[ebp+0xfffffffffffffffc]
         // 00428fc2: mov eax, ds:[0x53f3b4]
      [-]8b4dfcb201a1
         // 00428fcc: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 00428fcf: mov b1 dl, b1 0x1
         // 00428fd1: mov eax, ds:[0x428950]
      [-]5a595964891068
         // 00428fe2: pop edx
         // 00428fe3: pop ecx
         // 00428fe4: pop ecx
         // 00428fe5: mov fs:[eax], edx
         // 00428fe8: push 0x428ffd
      [-]8d45fce8
         // 00428fed: lea eax, ss:[ebp+0xfffffffffffffffc]
         // 00428ff0: call 0x406968
      [-]83c4f453
         // 0041fa6f: add esp, 0xfffffffffffffff4
         // 0041fa72: push ebx
      [-]64ff30648920895df8c645fc
         // 0041fa82: push fs:[eax]
         // 0041fa85: mov fs:[eax], esp
         // 0041fa88: mov ss:[ebp+0xfffffffffffffff8], ebx
         // 0041fa8b: mov b1 ss:[ebp+0xfffffffffffffffc], b1 0xb
      [-]8d45f8506a008d55f4a1
         // 0041fa8f: lea eax, ss:[ebp+0xfffffffffffffff8]
         // 0041fa92: push eax
         // 0041fa93: push 0x0
         // 0041fa95: lea edx, ss:[ebp+0xfffffffffffffff4]
         // 0041fa98: mov eax, ds:[0xa09df4]
      [-]ff8b4df4b201a1
         // 0041faa2: mov ecx, ss:[ebp+0xfffffffffffffff4]
         // 0041faa5: mov b1 dl, b1 0x1
         // 0041faa7: mov eax, ds:[0x41d90c]
      [-]5a595964891068
         // 0041fab8: pop edx
         // 0041fab9: pop ecx
         // 0041faba: pop ecx
         // 0041fabb: mov fs:[eax], edx
         // 0041fabe: push 0x41fad3
      [-]8d45f4e8
         // 0041fac3: lea eax, ss:[ebp+0xfffffffffffffff4]
         // 0041fac6: call @System@@LStrClr$qqrpv
      [-]8be55dc3
         // 0041fad4: mov esp, ebp
         // 0041fad6: pop ebp
         // 0041fad7: retn 
      [-]e8deffffffc3
         // 00416821: call 0x416804
         // 00416826: retn 
      [-]e8deffffffc3
         // 0041d621: call 0x41d604
         // 0041d626: retn 
      [-]e83dffffffc3
         // 0042f4c4: call 0x42f406
         // 0042f4c9: retn 
      [-]895020c3
         // 0049f884: mov ds:[eax+0x20], edx
         // 0049f887: retn 
      [-]8b400ce8
         // 0044b5a4: mov eax, ds:[eax+0xc]
         // 0044b5a7: call 0x44af14
      [-]f9ffffc3
         // 0044b5ac: retn 
      [-]8b4008e8
         // 0044b5cc: mov eax, ds:[eax+0x8]
         // 0044b5cf: call 0x44af14
      [-]f9ffffc3
         // 0044b5d4: retn 
      [-]ff406cc3
         // 0049fb38: inc ds:[eax+0x6c]
         // 0049fb3b: retn 
      [-]53568b45088b40fce8
         // 004b1d1b: push ebx
         // 004b1d1c: push esi
         // 004b1d1d: mov eax, ss:[ebp+0x8]
         // 004b1d20: mov eax, ds:[eax+0xfffffffffffffffc]
         // 004b1d23: call @Forms@TCustomForm@GetMDIChildCount$qqrv
      [-]8b45088b40fc
         // 00450cd7: mov eax, ss:[ebp+0x8]
         // 00450cda: mov eax, ds:[eax+0xfffffffffffffffc]
      [-]000080b8
         // 00450ce4: cmp b1 ds:[eax+0x273], b1 0x2
      [-]020000027504
         // 00450ceb: jnz 0x450cf1
      [-]b001eb06
         // 004b1d48: mov b1 al, b1 0x1
         // 004b1d4a: jmp 0x4b1d52
      [-]464b75e2
         // 004b1d4c: inc esi
         // 004b1d4d: dec ebx
         // 004b1d4e: jnz 0x4b1d32
      [-]5e5b5dc3
         // 004b1d52: pop esi
         // 004b1d53: pop ebx
         // 004b1d54: pop ebp
         // 004b1d55: retn 
      [-]83c4f0535657
         // 004519fc: add esp, 0xfffffffffffffff0
         // 004519ff: push ebx
         // 00451a00: push esi
         // 00451a01: push edi
      [-]64ff30648920
         // 00451a13: push fs:[eax]
         // 00451a16: mov fs:[eax], esp
      [-]408945fc
         // 00445cf9: inc eax
         // 00445cfa: mov ss:[ebp+0xfffffffffffffffc], eax
      [-]00003bb0
         // 00447235: cmp esi, ds:[eax+0x248]
      [-]00003bd87431
         // 004a9e7d: cmp ebx, eax
         // 004a9e7f: jz 0x4a9eb2
      [-]8b46088945f4c645f8
         // 004b2591: mov eax, ds:[esi+0x8]
         // 004b2594: mov ss:[ebp+0xfffffffffffffff4], eax
         // 004b2597: mov b1 ss:[ebp+0xfffffffffffffff8], b1 0xb
      [-]8d45f4506a008d55f0a1
         // 004b259b: lea eax, ss:[ebp+0xfffffffffffffff4]
         // 004b259e: push eax
         // 004b259f: push 0x0
         // 004b25a1: lea edx, ss:[ebp+0xfffffffffffffff0]
         // 004b25a4: mov eax, ds:[0xa09418]
      [-]ff8b4df0b201a1
         // 004b25ae: mov ecx, ss:[ebp+0xfffffffffffffff0]
         // 004b25b1: mov b1 dl, b1 0x1
         // 004b25b3: mov eax, ds:[0x41db8c]
      [-]47ff4dfc75a5
         // 004b25c2: inc edi
         // 004b25c3: dec ss:[ebp+0xfffffffffffffffc]
         // 004b25c6: jnz 0x4b256d
      [-]f6431c08750a
         // 004b25d9: test b1 ds:[ebx+0x1c], b1 0x8
         // 004b25dd: jnz 0x4b25e9
      [-]f6461c087402
         // 004b25e3: test b1 ds:[esi+0x1c], b1 0x8
         // 004b25e7: jz 0x4b25eb
      [-]0f84ab000000
         // 004b2600: jz 0x4b26b1
      [-]f6431c10750d
         // 004b2606: test b1 ds:[ebx+0x1c], b1 0x10
         // 004b260a: jnz 0x4b2619
      [-]020000030f8498000000
         // 00451ad8: jz 0x451b76
      [-]020000017506
         // 00451af1: jnz 0x451af9
      [-]f6431c107458
         // 004b262e: test b1 ds:[ebx+0x1c], b1 0x10
         // 004b2632: jz 0x4b268c
      [-]ff84c00f8488000000
         // 004472f7: test b1 al, b1 al
         // 004472f9: jz 0x447387
      [-]8b10ff52
         // 00445ddb: mov edx, ds:[eax]
         // 00445ddd: call ds:[edx+0x34]
      [-]ff3bf87419
         // 00445def: cmp edi, eax
         // 00445df1: jz 0x445e0c
      [-]8b10ff52
         // 00451b2c: mov edx, ds:[eax]
         // 00451b2e: call ds:[edx+0x34]
      [-]020000017436
         // 00451b58: jz 0x451b90
      [-]ff84c0742b
         // 00447358: test b1 al, b1 al
         // 0044735a: jz 0x447387
      [-]ff84c0740f
         // 00447374: test b1 al, b1 al
         // 00447376: jz 0x447387
      [-]020000007409
         // 00451b97: jz 0x451ba2
      [-]5356b3018b45088b40f0e8
         // 004b68e7: push ebx
         // 004b68e8: push esi
         // 004b68e9: mov b1 bl, b1 0x1
         // 004b68eb: mov eax, ss:[ebp+0x8]
         // 004b68ee: mov eax, ds:[eax+0xfffffffffffffff0]
         // 004b68f1: call @Forms@TScreen@GetCustomFormCount$qqrv
      [-]4e83fe007c34
         // 004b68f8: dec esi
         // 004b68f9: cmp esi, 0x0
         // 004b68fc: jl 0x4b6932
      [-]8b45088b40f0
         // 004afba6: mov eax, ss:[ebp+0x8]
         // 004afba9: mov eax, ds:[eax+0xfffffffffffffff0]
      [-]ffff8378
         // 004afbb3: cmp ds:[eax+0x34], 0x0
      [-]f6401c107515
         // 004b6911: test b1 ds:[eax+0x1c], b1 0x10
         // 004b6915: jnz 0x4b692c
      [-]020000017508
         // 00456987: jnz 0x456991
      [-]4e83feff75cc
         // 004b692c: dec esi
         // 004b692d: cmp esi, 0xffffffffffffffff
         // 004b6930: jnz 0x4b68fe
      [-]5e5b5dc3
         // 004b6936: pop esi
         // 004b6937: pop ebx
         // 004b6938: pop ebp
         // 004b6939: retn 
      [-]feffffc3
         // 004b0a4b: retn 

  }
  condition:
    all of them
}
