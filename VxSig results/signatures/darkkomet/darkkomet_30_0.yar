rule darkkomet_30_0 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         53568bf28bd880e37f833d??
         // 0040286c: push ebx
         // 0040286d: push esi
         // 0040286e: mov esi, edx
         // 00402870: mov ebx, eax
         // 00402872: and b1 bl, b1 0x7f
         // 00402875: cmp ds:[0x49e008], 0x0
      [-]8bd68bc3ff15??
         // 0040287e: mov edx, esi
         // 00402880: mov eax, ebx
         // 00402882: call ds:[0x49e008]
      [-]84db750d
         // 00402888: test b1 bl, b1 bl
         // 0040288a: jnz 0x402899
      [-]80fb18770a
         // 00402899: cmp b1 bl, b1 0x18
         // 0040289c: ja 0x4028a8
      [-]83e07f8b1424e9a9ffffff
         // 004028b8: and eax, 0x7f
         // 004028bb: mov edx, ss:[esp]
         // 004028be: jmp 0x40286c
      [-]e903000000
         // 00403738: jmp @System@@Pow10$qqrv
      [-]5331db85c07c4d
         // 00403740: push ebx
         // 00403741: xor ebx, ebx
         // 00403743: test eax, eax
         // 00403745: jl 0x403794
      [-]0f849a000000
         // 00403747: jz 0x4037e7
      [-]3d????????0f8d81000000
         // 0040374d: cmp eax, 0x1400
         // 00403752: jge 0x4037d9
      [-]89c283e21f8d1492dbac53
         // 00403758: mov edx, eax
         // 0040375a: and edx, 0x1f
         // 0040375d: lea edx, ds:[edx+edx*0x4]
         // 00403760: fld b10 ds:[ebx+edx*0x2]
      [-]4000dec9c1e8057479
         // 00403767: fmulp b8 st(1), b10 st(0)
         // 00403769: shr eax, b1 0x5
         // 0040376c: jz 0x4037e7
      [-]89c283e20f740c
         // 0040376e: mov edx, eax
         // 00403770: and edx, 0xf
         // 00403773: jz 0x403781
      [-]8d1492dbac53
         // 00403775: lea edx, ds:[edx+edx*0x4]
         // 00403778: fld b10 ds:[ebx+edx*0x2]
      [-]4000dec9
         // 0040377f: fmulp b8 st(1), b10 st(0)
      [-]c1e8047461
         // 00403781: shr eax, b1 0x4
         // 00403784: jz 0x4037e7
      [-]8d0480dbac43
         // 00403786: lea eax, ds:[eax+eax*0x4]
         // 00403789: fld b10 ds:[ebx+eax*0x2]
      [-]4000dec9eb53
         // 00403790: fmulp b8 st(1), b10 st(0)
         // 00403792: jmp 0x4037e7
      [-]f7d83d????????7d46
         // 00403794: neg eax
         // 00403796: cmp eax, 0x1400
         // 0040379b: jge 0x4037e3
      [-]89c283e21f8d1492dbac53
         // 0040379d: mov edx, eax
         // 0040379f: and edx, 0x1f
         // 004037a2: lea edx, ds:[edx+edx*0x4]
         // 004037a5: fld b10 ds:[ebx+edx*0x2]
      [-]4000def9c1e8057434
         // 004037ac: fdivp b8 st(1), b10 st(0)
         // 004037ae: shr eax, b1 0x5
         // 004037b1: jz 0x4037e7
      [-]89c283e20f740c
         // 004037b3: mov edx, eax
         // 004037b5: and edx, 0xf
         // 004037b8: jz 0x4037c6
      [-]8d1492dbac53
         // 004037ba: lea edx, ds:[edx+edx*0x4]
         // 004037bd: fld b10 ds:[ebx+edx*0x2]
      [-]4000def9
         // 004037c4: fdivp b8 st(1), b10 st(0)
      [-]c1e804741c
         // 004037c6: shr eax, b1 0x4
         // 004037c9: jz 0x4037e7
      [-]8d0480dbac43
         // 004037cb: lea eax, ds:[eax+eax*0x4]
         // 004037ce: fld b10 ds:[ebx+eax*0x2]
      [-]4000def9eb0e
         // 004037d5: fdivp b8 st(1), b10 st(0)
         // 004037d7: jmp 0x4037e7
      [-]ddd8dbab
         // 004037d9: fstp b10 st(0)
         // 004037db: fld b10 ds:[ebx+0x4037e9]
      [-]4000eb04
         // 004037e1: jmp 0x4037e7
      [-]ddd8d9ee
         // 004037e3: fstp b10 st(0)
         // 004037e5: fldz 
      [-]538bd88bc3e8a60000008bc3e8
         // 00403ba0: push ebx
         // 00403ba1: mov ebx, eax
         // 00403ba3: mov eax, ebx
         // 00403ba5: call @System@TObject@CleanupInstance$qqrv
         // 00403baa: mov eax, ebx
         // 00403bac: call @System@@FreeMem$qqrpv
      [-]ffff5bc3
         // 00403bb1: pop ebx
         // 00403bb2: retn 
      [-]8b442404f74004????????0f8513010000
         // 0040408c: mov eax, ss:[esp+0x4]
         // 00404090: test ds:[eax+0x4], 0x6
         // 00404097: jnz 0x4041b0
      [-]e8c6feffff803d
         // 004040d9: call 0x403fa4
         // 004040de: cmp b1 ds:[0x49b030], b1 0x0
      [-]4900007629
         // 004040e5: jbe 0x404110
      [-]4900007720
         // 004040ee: ja 0x404110
      [-]8d4c24045051e8
         // 004040f0: lea ecx, ss:[esp+0x4]
         // 004040f4: push eax
         // 004040f5: push ecx
         // 004040f6: call UnhandledExceptionFilter
      [-]ffff83f800580f84ab000000
         // 004040fb: cmp eax, 0x0
         // 004040fe: pop eax
         // 004040ff: jz 0x4041b0
      [-]89c28b4424048b480ceb30
         // 00404105: mov edx, eax
         // 00404107: mov eax, ss:[esp+0x4]
         // 0040410b: mov ecx, ds:[eax+0xc]
         // 0040410e: jmp 0x404140
      [-]89c28b4424048b480c
         // 00404110: mov edx, eax
         // 00404112: mov eax, ss:[esp+0x4]
         // 00404116: mov ecx, ds:[eax+0xc]
      [-]490001761e
         // 00404120: jbe 0x404140
      [-]4900007715
         // 00404129: ja 0x404140
      [-]e9e9ffffff
         // 00404936: jmp 0x404924
      [-]8b1085d27438
         // 00404e8c: mov edx, ds:[eax]
         // 00404e8e: test edx, edx
         // 00404e90: jz 0x404eca
      [-]8b4af8497432
         // 00404e92: mov ecx, ds:[edx+0xfffffffffffffff8]
         // 00404e95: dec ecx
         // 00404e96: jz 0x404eca
      [-]5389c38b42fce8
         // 00404e98: push ebx
         // 00404e99: mov ebx, eax
         // 00404e9b: mov eax, ds:[edx+0xfffffffffffffffc]
         // 00404e9e: call @System@@NewAnsiString$qqri
      [-]fbffff89c28b038913508b48fce8
         // 00404ea3: mov edx, eax
         // 00404ea5: mov eax, ds:[ebx]
         // 00404ea7: mov ds:[ebx], edx
         // 00404ea9: push eax
         // 00404eaa: mov ecx, ds:[eax+0xfffffffffffffffc]
         // 00404ead: call @System@Move$qqrpxvpvi
      [-]ffff588b48f8497c0e
         // 00404eb2: pop eax
         // 00404eb3: mov ecx, ds:[eax+0xfffffffffffffff8]
         // 00404eb6: dec ecx
         // 00404eb7: jl 0x404ec7
      [-]f0ff48f87508
         // 00404eb9: lock dec ds:[eax+0xfffffffffffffff8]
         // 00404ebd: jnz 0x404ec7
      [-]8d40f8e8
         // 00404ebf: lea eax, ds:[eax+0xfffffffffffffff8]
         // 00404ec2: call @System@@FreeMem$qqrpv
      [-]e9b7ffffff
         // 00404ed0: jmp 0x404e8c
      [-]e9afffffff
         // 00404ed8: jmp 0x404e8c
      [-]83f9000f84e0000000
         // 004054c8: cmp ecx, 0x0
         // 004054cb: jz 0x4055b1
      [-]5053565789c389d689cf31d28a068a56013c0a7425
         // 004054d1: push eax
         // 004054d2: push ebx
         // 004054d3: push esi
         // 004054d4: push edi
         // 004054d5: mov ebx, eax
         // 004054d7: mov esi, edx
         // 004054d9: mov edi, ecx
         // 004054db: xor edx, edx
         // 004054dd: mov b1 al, b1 ds:[esi]
         // 004054df: mov b1 dl, b1 ds:[esi+0x1]
         // 004054e2: cmp b1 al, b1 0xa
         // 004054e4: jz 0x40550b
      [-]3c0b743e
         // 004054e6: cmp b1 al, b1 0xb
         // 004054e8: jz 0x405528
      [-]3c0c7451
         // 004054ea: cmp b1 al, b1 0xc
         // 004054ec: jz 0x40553f
      [-]3c0d745c
         // 004054ee: cmp b1 al, b1 0xd
         // 004054f0: jz 0x40554e
      [-]3c0e7476
         // 004054f2: cmp b1 al, b1 0xe
         // 004054f4: jz 0x40556c
      [-]3c0f0f8484000000
         // 004054f6: cmp b1 al, b1 0xf
         // 004054f8: jz 0x405582
      [-]3c110f848b000000
         // 004054fe: cmp b1 al, b1 0x11
         // 00405500: jz 0x405591
      [-]e997000000
         // 00405506: jmp 0x4055a2
      [-]5f5e5b58b002e9
         // 004055a2: pop edi
         // 004055a3: pop esi
         // 004055a4: pop ebx
         // 004055a5: pop eax
         // 004055a6: mov b1 al, b1 0x2
         // 004055a8: jmp @System@Error$qqr20System@TRuntimeError
      [-]5f5e5b58
         // 004055ad: pop edi
         // 004055ae: pop esi
         // 004055af: pop ebx
         // 004055b0: pop eax
      [-]5356575583c4ec8914248bf0bd????????33ffc74424????????00c74424????????0085f6750b
         // 00405afc: push ebx
         // 00405afd: push esi
         // 00405afe: push edi
         // 00405aff: push ebp
         // 00405b00: add esp, 0xffffffffffffffec
         // 00405b03: mov ss:[esp], edx
         // 00405b06: mov esi, eax
         // 00405b08: mov ebp, 0x1
         // 00405b0d: xor edi, edi
         // 00405b0f: mov ss:[esp+0x8], 0x0
         // 00405b17: mov ss:[esp+0xc], 0x0
         // 00405b1f: test esi, esi
         // 00405b21: jnz 0x405b2e
      [-]8b04248928e9
         // 00405b23: mov eax, ss:[esp]
         // 00405b26: mov ds:[eax], ebp
         // 00405b28: jmp 0x405d1b
      [-]807c2eff2074f8
         // 00405b2e: cmp b1 ds:[esi+ebp+0xffffffffffffffff], b1 0x20
         // 00405b33: jz 0x405b2d
      [-]c644241000
         // 00405b35: mov b1 ss:[esp+0x10], b1 0x0
      [-]3c2d7508
         // 00405b3e: cmp b1 al, b1 0x2d
         // 00405b40: jnz 0x405b4a
      [-]c64424100145eb05
         // 00405b42: mov b1 ss:[esp+0x10], b1 0x1
         // 00405b47: inc ebp
         // 00405b48: jmp 0x405b4f
      [-]3c2b7501
         // 00405b4a: cmp b1 al, b1 0x2b
         // 00405b4c: jnz 0x405b4f
      [-]b301807c2eff2474
         // 00405b4f: mov b1 bl, b1 0x1
         // 00405b51: cmp b1 ds:[esi+ebp+0xffffffffffffffff], b1 0x24
         // 00405b56: jz 0x405b80
      [-]ffff3c5874
         // 004065bb: cmp b1 al, b1 0x58
         // 004065bd: jz 0x4065db
      [-]807c2eff300f85
         // 00405b65: cmp b1 ds:[esi+ebp+0xffffffffffffffff], b1 0x30
         // 00405b6a: jnz 0x405c4a
      [-]ffff3c580f85
         // 004065d3: cmp b1 al, b1 0x58
         // 004065d5: jnz 0x406691
      [-]807c2eff307501
         // 00405b80: cmp b1 ds:[esi+ebp+0xffffffffffffffff], b1 0x30
         // 00405b85: jnz 0x405b88
      [-]83ef30eb
         // 00406602: sub edi, 0x30
         // 00406605: jmp 0x406615
      [-]83ef37eb
         // 0040660a: sub edi, 0x37
         // 0040660d: jmp 0x406615
      [-]837c240c007509
         // 00405bce: cmp ss:[esp+0xc], 0x0
         // 00405bd3: jnz 0x405bde
      [-]837c2408007247
         // 00405bd5: cmp ss:[esp+0x8], 0x0
         // 00405bda: jb 0x405c23
      [-]817c240c????????7509
         // 00405be0: cmp ss:[esp+0xc], 0xfffffff
         // 00405be8: jnz 0x405bf3
      [-]837c2408ff7604
         // 00405bea: cmp ss:[esp+0x8], 0xffffffffffffffff
         // 00405bef: jbe 0x405bf5
      [-]8bc79952508b4424108b5424140fa4c204c1e0040304241354240483c408894424088954240c4533dbe9
         // 00405bf5: mov eax, edi
         // 00405bf7: cdq 
         // 00405bf8: push edx
         // 00405bf9: push eax
         // 00405bfa: mov eax, ss:[esp+0x10]
         // 00405bfe: mov edx, ss:[esp+0x14]
         // 00405c02: shld edx, eax, b1 0x4
         // 00405c06: shl eax, b1 0x4
         // 00405c09: add eax, ss:[esp]
         // 00405c0c: adc edx, ss:[esp+0x4]
         // 00405c10: add esp, 0x8
         // 00405c13: mov ss:[esp+0x8], eax
         // 00405c17: mov ss:[esp+0xc], edx
         // 00405c1b: inc ebp
         // 00405c1c: xor ebx, ebx
         // 00405c1e: jmp 0x405b89
      [-]807c2410000f84
         // 00405c23: cmp b1 ss:[esp+0x10], b1 0x0
         // 00405c28: jz 0x405d01
      [-]8b4424088b54240cf7d883d200f7da894424088954240ce9
         // 00405c2e: mov eax, ss:[esp+0x8]
         // 00405c32: mov edx, ss:[esp+0xc]
         // 00405c36: neg eax
         // 00405c38: adc edx, 0x0
         // 00405c3b: neg edx
         // 00405c3d: mov ss:[esp+0x8], eax
         // 00405c41: mov ss:[esp+0xc], edx
         // 00405c45: jmp 0x405d01
      [-]83ef30837c240c007509
         // 00405c60: sub edi, 0x30
         // 00405c63: cmp ss:[esp+0xc], 0x0
         // 00405c68: jnz 0x405c73
      [-]837c2408007249
         // 00405c6a: cmp ss:[esp+0x8], 0x0
         // 00405c6f: jb 0x405cba
      [-]817c240c????????750c
         // 00405c75: cmp ss:[esp+0xc], 0xccccccc
         // 00405c7d: jnz 0x405c8b
      [-]817c2408????????7604
         // 00405c7f: cmp ss:[esp+0x8], 0xffffffffcccccccc
         // 00405c87: jbe 0x405c8d
      [-]6a006a0a8b4424108b542414e8
         // 00405c8d: push 0x0
         // 00405c8f: push 0xa
         // 00405c91: mov eax, ss:[esp+0x10]
         // 00405c95: mov edx, ss:[esp+0x14]
         // 00405c99: call 0x4059a0
      [-]fdffff52508bc7990304241354240483c408894424088954240c4533dbeb
         // 00405c9e: push edx
         // 00405c9f: push eax
         // 00405ca0: mov eax, edi
         // 00405ca2: cdq 
         // 00405ca3: add eax, ss:[esp]
         // 00405ca6: adc edx, ss:[esp+0x4]
         // 00405caa: add esp, 0x8
         // 00405cad: mov ss:[esp+0x8], eax
         // 00405cb1: mov ss:[esp+0xc], edx
         // 00405cb5: inc ebp
         // 00405cb6: xor ebx, ebx
         // 00405cb8: jmp 0x405c4a
      [-]807c2410007417
         // 00405cba: cmp b1 ss:[esp+0x10], b1 0x0
         // 00405cbf: jz 0x405cd8
      [-]8b4424088b54240cf7d883d200f7da894424088954240c
         // 00405cc1: mov eax, ss:[esp+0x8]
         // 00405cc5: mov edx, ss:[esp+0xc]
         // 00405cc9: neg eax
         // 00405ccb: adc edx, 0x0
         // 00405cce: neg edx
         // 00405cd0: mov ss:[esp+0x8], eax
         // 00405cd4: mov ss:[esp+0xc], edx
      [-]837c240c007505
         // 00405cd8: cmp ss:[esp+0xc], 0x0
         // 00405cdd: jnz 0x405ce4
      [-]837c240800
         // 00405cdf: cmp ss:[esp+0x8], 0x0
      [-]837c240c00750a
         // 00405ce6: cmp ss:[esp+0xc], 0x0
         // 00405ceb: jnz 0x405cf7
      [-]837c2408000f92c0eb03
         // 00405ced: cmp ss:[esp+0x8], 0x0
         // 00405cf2: setb b1 al
         // 00405cf5: jmp 0x405cfa
      [-]3a4424107401
         // 00405cfa: cmp b1 al, b1 ss:[esp+0x10]
         // 00405cfe: jz 0x405d01
      [-]807c2eff000f95c00ad87407
         // 00405d01: cmp b1 ds:[esi+ebp+0xffffffffffffffff], b1 0x0
         // 00405d06: setnz b1 al
         // 00405d09: or b1 bl, b1 al
         // 00405d0b: jz 0x405d14
      [-]8b04248928eb07
         // 00405d0d: mov eax, ss:[esp]
         // 00405d10: mov ds:[eax], ebp
         // 00405d12: jmp 0x405d1b
      [-]8b042433d28910
         // 00405d14: mov eax, ss:[esp]
         // 00405d17: xor edx, edx
         // 00405d19: mov ds:[eax], edx
      [-]8b4424088b54240c83c4145d5f5e5bc3
         // 00405d1b: mov eax, ss:[esp+0x8]
         // 00405d1f: mov edx, ss:[esp+0xc]
         // 00405d23: add esp, 0x14
         // 00405d26: pop ebp
         // 00405d27: pop edi
         // 00405d28: pop esi
         // 00405d29: pop ebx
         // 00405d2a: retn 
      [-]e8f3ffffff48c3
         // 00405d34: call 0x405d2c
         // 00405d39: dec eax
         // 00405d3a: retn 
      [-]e89b010000c3
         // 00405d54: call @System@@DynArrayClear$qqrrpvpv
         // 00405d59: retn 
      [-]e8d3ffffffc3
         // 00405f8c: call @System@FindHInstance$qqrpv
         // 00405f91: retn 
      [-]e80b000000c3
         // 00406440: call @Sysutils@AddTerminateProc$qqrpqqrv$o
         // 00406445: retn 
      [-]e823000000c3
         // 00406448: call @System@RemoveModuleUnloadProc$qqrpqqrui$v
         // 0040644d: retn 
      [-]83c00450e8
         // 0040662c: add eax, 0x4
         // 0040662f: push eax
         // 00406630: call InterlockedDecrement
      [-]506a40e8e0ffffffc3
         // 00406c84: push eax
         // 00406c85: push 0x40
         // 00406c87: call LocalAlloc_0
         // 00406c8c: retn 
      [-]8901895104c3
         // 00406dc0: mov ds:[ecx], eax
         // 00406dc2: mov ds:[ecx+0x4], edx
         // 00406dc5: retn 
      [-]538bd88bcbb201a1
         // 00408c64: push ebx
         // 00408c65: mov ebx, eax
         // 00408c67: mov ecx, ebx
         // 00408c69: mov b1 dl, b1 0x1
         // 00408c6b: mov eax, ds:[0x4086b0]
      [-]ffff5bc3
         // 00408c7a: pop ebx
         // 00408c7b: retn 
      [-]5356578bf98bf28bd856578bcbb201a1
         // 00408c7c: push ebx
         // 00408c7d: push esi
         // 00408c7e: push edi
         // 00408c7f: mov edi, ecx
         // 00408c81: mov esi, edx
         // 00408c83: mov ebx, eax
         // 00408c85: push esi
         // 00408c86: push edi
         // 00408c87: mov ecx, ebx
         // 00408c89: mov b1 dl, b1 0x1
         // 00408c8b: mov eax, ds:[0x4086b0]
      [-]ffff5f5e5bc3
         // 00408c9a: pop edi
         // 00408c9b: pop esi
         // 00408c9c: pop ebx
         // 00408c9d: retn 
      [-]535657518bf98bf28bd86a008d44240450575653e8
         // 00409948: push ebx
         // 00409949: push esi
         // 0040994a: push edi
         // 0040994b: push ecx
         // 0040994c: mov edi, ecx
         // 0040994e: mov esi, edx
         // 00409950: mov ebx, eax
         // 00409952: push 0x0
         // 00409954: lea eax, ss:[esp+0x4]
         // 00409958: push eax
         // 00409959: push edi
         // 0040995a: push esi
         // 0040995b: push ebx
         // 0040995c: call ReadFile_0
      [-]ffff85c07507
         // 00409961: test eax, eax
         // 00409963: jnz 0x40996c
      [-]c70424????????
         // 00409965: mov ss:[esp], 0xffffffffffffffff
      [-]8b04245a5f5e5bc3
         // 0040996c: mov eax, ss:[esp]
         // 0040996f: pop edx
         // 00409970: pop edi
         // 00409971: pop esi
         // 00409972: pop ebx
         // 00409973: retn 
      [-]535657518bf98bf28bd86a008d44240450575653e8
         // 00409974: push ebx
         // 00409975: push esi
         // 00409976: push edi
         // 00409977: push ecx
         // 00409978: mov edi, ecx
         // 0040997a: mov esi, edx
         // 0040997c: mov ebx, eax
         // 0040997e: push 0x0
         // 00409980: lea eax, ss:[esp+0x4]
         // 00409984: push eax
         // 00409985: push edi
         // 00409986: push esi
         // 00409987: push ebx
         // 00409988: call WriteFile_0
      [-]ffff85c07507
         // 0040998d: test eax, eax
         // 0040998f: jnz 0x409998
      [-]c70424????????
         // 00409991: mov ss:[esp], 0xffffffffffffffff
      [-]8b04245a5f5e5bc3
         // 00409998: mov eax, ss:[esp]
         // 0040999b: pop edx
         // 0040999c: pop edi
         // 0040999d: pop esi
         // 0040999e: pop ebx
         // 0040999f: retn 
      [-]84c97503
         // 0040a10e: test b1 cl, b1 cl
         // 0040a110: jnz 0x40a115
      [-]ac08c07503
         // 0040a872: lodsbb 
         // 0040a873: or b1 al, b1 al
         // 0040a875: jnz 0x40a87a
      [-]8b550883fa127205
         // 0040a91d: mov edx, ss:[ebp+0x8]
         // 0040a920: cmp edx, 0x12
         // 0040a923: jb 0x40a92a
      [-]ba????????
         // 0040a925: mov edx, 0x12
      [-]0fbf4dd409c97f05
         // 0040a92a: movsx ecx, b2 ss:[ebp+0xffffffffffffffd4]
         // 0040a92e: or ecx, ecx
         // 0040a930: jg 0x40a937
      [-]b030aaeb2a
         // 0040a932: mov b1 al, b1 0x30
         // 0040a934: stosbb 
         // 0040a935: jmp 0x40a961
      [-]31db807d1002740a
         // 0040a937: xor ebx, ebx
         // 0040a939: cmp b1 ss:[ebp+0x10], b1 0x2
         // 0040a93d: jz 0x40a949
      [-]89c848b303f6f388e343
         // 0040a93f: mov eax, ecx
         // 0040a941: dec eax
         // 0040a942: mov b1 bl, b1 0x3
         // 0040a944: div b1 bl
         // 0040a946: mov b1 bl, b1 ah
         // 0040a948: inc ebx
      [-]e824ffffffaa49740f
         // 0040a949: call 0x40a872
         // 0040a94e: stosbb 
         // 0040a94f: dec ecx
         // 0040a950: jz 0x40a961
      [-]8a45fa84c074ed
         // 0040a955: mov b1 al, b1 ss:[ebp+0xfffffffffffffffa]
         // 0040a958: test b1 al, b1 al
         // 0040a95a: jz 0x40a949
      [-]aab303ebe8
         // 0040a95c: stosbb 
         // 0040a95d: mov b1 bl, b1 0x3
         // 0040a95f: jmp 0x40a949
      [-]09d2741c
         // 0040a961: or edx, edx
         // 0040a963: jz 0x40a981
      [-]8a45fb84c07401
         // 0040a965: mov b1 al, b1 ss:[ebp+0xfffffffffffffffb]
         // 0040a968: test b1 al, b1 al
         // 0040a96a: jz 0x40a96d
      [-]aa4a740c
         // 0040a971: stosbb 
         // 0040a972: dec edx
         // 0040a973: jz 0x40a981
      [-]e8f5feffffaa4a75f7
         // 0040a978: call 0x40a872
         // 0040a97d: stosbb 
         // 0040a97e: dec edx
         // 0040a97f: jnz 0x40a978
      [-]568b75f485f67405
         // 0040a9d6: push esi
         // 0040a9d7: mov esi, ss:[ebp+0xfffffffffffffff4]
         // 0040a9da: test esi, esi
         // 0040a9dc: jz 0x40a9e3
      [-]8b4efcf3a4
         // 0040a9de: mov ecx, ds:[esi+0xfffffffffffffffc]
         // 0040a9e1: rep movsbb 
      [-]242a4040402a2440404024202a40402a2024404028242a29402d242a4040242d2a4040242a2d????????2429402d????????2a2d2440402a242d40402d????????2d????????2a20242d4024202a2d4024202d2a402a2d????????24202a29282a202429
         // 0040a9e5: and b1 al, b1 0x2a
         // 0040a9e7: inc eax
         // 0040a9e8: inc eax
         // 0040a9e9: inc eax
         // 0040a9ea: sub b1 ah, b1 ds:[eax+eax*0x2]
         // 0040a9ed: inc eax
         // 0040a9ee: inc eax
         // 0040a9ef: and b1 al, b1 0x20
         // 0040a9f1: sub b1 al, b1 ds:[eax+0x40]
         // 0040a9f4: sub b1 ah, b1 ds:[eax]
         // 0040a9f6: and b1 al, b1 0x40
         // 0040a9f8: inc eax
         // 0040a9f9: sub b1 ds:[edx+ebp], b1 ah
         // 0040a9fc: sub ds:[eax+0x2d], eax
         // 0040a9ff: and b1 al, b1 0x2a
         // 0040aa01: inc eax
         // 0040aa02: inc eax
         // 0040aa03: and b1 al, b1 0x2d
         // 0040aa05: sub b1 al, b1 ds:[eax+0x40]
         // 0040aa08: and b1 al, b1 0x2a
         // 0040aa0a: sub eax, 0x2a284040
         // 0040aa0f: and b1 al, b1 0x29
         // 0040aa11: inc eax
         // 0040aa12: sub eax, 0x4040242a
         // 0040aa17: sub b1 ch, b1 ds:[0x2a404024]
         // 0040aa1d: and b1 al, b1 0x2d
         // 0040aa1f: inc eax
         // 0040aa20: inc eax
         // 0040aa21: sub eax, 0x4024202a
         // 0040aa26: sub eax, 0x402a2024
         // 0040aa2b: sub b1 ah, b1 ds:[eax]
         // 0040aa2d: and b1 al, b1 0x2d
         // 0040aa2f: inc eax
         // 0040aa30: and b1 al, b1 0x20
         // 0040aa32: sub b1 ch, b1 ds:[0x2d202440]
         // 0040aa38: sub b1 al, b1 ds:[eax+0x2a]
         // 0040aa3b: sub eax, 0x28402420
         // 0040aa40: and b1 al, b1 0x20
         // 0040aa42: sub b1 ch, b1 ds:[ecx]
         // 0040aa44: sub b1 ds:[edx], b1 ch
         // 0040aa46: and b1 ds:[ecx+ebp], b1 ah
      [-]8be55dc20c00
         // 0040aa49: mov esp, ebp
         // 0040aa4b: pop ebp
         // 0040aa4c: retn b2 0xc
      [-]558bec83c4
         // 0040b728: push ebp
         // 0040b729: mov ebp, esp
         // 0040b72b: add esp, 0xffffffffffffffd8
      [-]535633d28955
         // 0040b72e: push ebx
         // 0040b72f: push esi
         // 0040b730: xor edx, edx
         // 0040b732: mov ss:[ebp+0xffffffffffffffd8], edx
      [-]8945fc33c05568
         // 0040b738: mov ss:[ebp+0xfffffffffffffffc], eax
         // 0040b73b: xor eax, eax
         // 0040b73d: push ebp
         // 0040b73e: push 0x40bea9
      [-]64ff3064892083
         // 0040b743: push fs:[eax]
         // 0040b746: mov fs:[eax], esp
         // 0040b749: cmp ss:[ebp+0xfffffffffffffffc], 0x0
      [-]000f843b070000
         // 0040b74d: jz 0x40be8e
      [-]8b450883b8????????020f8d2b070000
         // 0040b753: mov eax, ss:[ebp+0x8]
         // 0040b756: cmp ds:[eax+0xfffffffffffffef8], 0x2
         // 0040b75d: jge 0x40be8e
      [-]8b4508ff80????????
         // 0040b763: mov eax, ss:[ebp+0x8]
         // 0040b766: inc ds:[eax+0xfffffffffffffef8]
      [-]20c645ed00c645e300c645
         // 0040b76c: mov b1 bl, b1 0x20
         // 0040b76e: mov b1 ss:[ebp+0xffffffffffffffed], b1 0x0
         // 0040b772: mov b1 ss:[ebp+0xffffffffffffffe3], b1 0x0
         // 0040b776: mov b1 ss:[ebp+0xffffffffffffffe2], b1 0x0
      [-]00e9f9060000
         // 0040b77a: jmp 0x40be78
      [-]8b4508508b
         // 0040b793: mov eax, ss:[ebp+0x8]
         // 0040b796: push eax
         // 0040b797: mov eax, ss:[ebp+0xfffffffffffffffc]
      [-]2500008bd08b
         // 0040b79f: mov edx, eax
         // 0040b7a1: mov eax, ss:[ebp+0xfffffffffffffffc]
      [-]fbffff598b
         // 0040b7a9: pop ecx
         // 0040b7aa: mov eax, ss:[ebp+0xfffffffffffffffc]
      [-]2500008945
         // 0040b7b2: mov ss:[ebp+0xfffffffffffffffc], eax
      [-]25000089
         // 0040b7c4: mov ss:[ebp+0xfffffffffffffffc], eax
      [-]83c0de83f8380f87
         // 0040c20e: add eax, 0xffffffffffffffde
         // 0040c211: cmp eax, 0x38
         // 0040c214: ja def_40C221
      [-]fbffff5955e8
         // 0040b88a: pop ecx
         // 0040b88b: push ebp
         // 0040b88c: call 0x40b440
      [-]fbffff59837df4027f23
         // 0040b891: pop ecx
         // 0040b892: cmp ss:[ebp+0xfffffffffffffff4], 0x2
         // 0040b896: jg 0x40b8bb
      [-]8b4508500fb745f2b9????????33d2f7f18bc2ba????????e8
         // 0040b898: mov eax, ss:[ebp+0x8]
         // 0040b89b: push eax
         // 0040b89c: movzx eax, b2 ss:[ebp+0xfffffffffffffff2]
         // 0040b8a0: mov ecx, 0x64
         // 0040b8a5: xor edx, edx
         // 0040b8a7: div ecx
         // 0040b8a9: mov eax, edx
         // 0040b8ab: mov edx, 0x2
         // 0040b8b0: call 0x40b3c8
      [-]ffff59e9bd050000
         // 0040b8b5: pop ecx
         // 0040b8b6: jmp 0x40be78
      [-]8b4508500fb745f2ba????????e8
         // 0040b8bb: mov eax, ss:[ebp+0x8]
         // 0040b8be: push eax
         // 0040b8bf: movzx eax, b2 ss:[ebp+0xfffffffffffffff2]
         // 0040b8c3: mov edx, 0x4
         // 0040b8c8: call 0x40b3c8
      [-]faffff59e9a5050000
         // 0040b8cd: pop ecx
         // 0040b8ce: jmp 0x40be78
      [-]fbffff5955e8
         // 0040b8d9: pop ecx
         // 0040b8da: push ebp
         // 0040b8db: call 0x40b440
      [-]fbffff598b450850558d55
         // 0040b8e0: pop ecx
         // 0040b8e1: mov eax, ss:[ebp+0x8]
         // 0040b8e4: push eax
         // 0040b8e5: push ebp
         // 0040b8e6: lea edx, ss:[ebp+0xffffffffffffffdc]
      [-]8b45f4e8
         // 0040b8e9: mov eax, ss:[ebp+0xfffffffffffffff4]
         // 0040b8ec: call @SysUtils@_16722
      [-]fbffff598b45
         // 0040b8f1: pop ecx
         // 0040b8f2: mov eax, ss:[ebp+0xffffffffffffffdc]
      [-]faffff59e978050000
         // 0040b8fa: pop ecx
         // 0040b8fb: jmp 0x40be78
      [-]ffff5955e8
         // 0040b906: pop ecx
         // 0040b907: push ebp
         // 0040b908: call 0x40b440
      [-]fbffff598b450850558d55
         // 0040b90d: pop ecx
         // 0040b90e: mov eax, ss:[ebp+0x8]
         // 0040b911: push eax
         // 0040b912: push ebp
         // 0040b913: lea edx, ss:[ebp+0xffffffffffffffd8]
      [-]8b45f4e8
         // 0040b916: mov eax, ss:[ebp+0xfffffffffffffff4]
         // 0040b919: call 0x40b620
      [-]ffff598b45
         // 0040b91e: pop ecx
         // 0040b91f: mov eax, ss:[ebp+0xffffffffffffffd8]
      [-]faffff59e94b050000
         // 0040b927: pop ecx
         // 0040b928: jmp 0x40be78
      [-]faffff5955e8
         // 0040b933: pop ecx
         // 0040b934: push ebp
         // 0040b935: call 0x40b440
      [-]ffff598b45f44883e8027204
         // 0040b93a: pop ecx
         // 0040b93b: mov eax, ss:[ebp+0xfffffffffffffff4]
         // 0040b93e: dec eax
         // 0040b93f: sub eax, 0x2
         // 0040b942: jb 0x40b948
      [-]8b4508500fb745f08b0485
         // 0040b978: mov eax, ss:[ebp+0x8]
         // 0040b97b: push eax
         // 0040b97c: movzx eax, b2 ss:[ebp+0xfffffffffffffff0]
         // 0040b980: mov eax, ds:[0x49e6d8+eax*0x4]
      [-]ffff59e9e6040000
         // 0040b98c: pop ecx
         // 0040b98d: jmp 0x40be78
      [-]faffff598b45f44883e802720a
         // 0040b998: pop ecx
         // 0040b999: mov eax, ss:[ebp+0xfffffffffffffff4]
         // 0040b99c: dec eax
         // 0040b99d: sub eax, 0x2
         // 0040b9a0: jb 0x40b9ac
      [-]8b450850a1
         // 0040ba2b: mov eax, ss:[ebp+0x8]
         // 0040ba2e: push eax
         // 0040ba2f: mov eax, ds:[0x49e694]
      [-]fcffff59e939040000
         // 0040ba39: pop ecx
         // 0040ba3a: jmp 0x40be78
      [-]f9ffff5955e8
         // 0040ba45: pop ecx
         // 0040ba46: push ebp
         // 0040ba47: call 0x40b478
      [-]faffff59c645
         // 0040ba4c: pop ecx
         // 0040ba4d: mov b1 ss:[ebp+0xffffffffffffffe1], b1 0x0
      [-]00008bf0eb7c
         // 0040ba6e: mov esi, eax
         // 0040ba70: jmp 0x40baee
      [-]83f8487f13
         // 0040ba76: cmp eax, 0x48
         // 0040ba79: jg 0x40ba8e
      [-]83e8227463
         // 0040ba7d: sub eax, 0x22
         // 0040ba80: jz 0x40bae5
      [-]83e805745e
         // 0040ba82: sub eax, 0x5
         // 0040ba85: jz 0x40bae5
      [-]83e81a740e
         // 0040ba87: sub eax, 0x1a
         // 0040ba8a: jz 0x40ba9a
      [-]83e8617407
         // 0040ba8e: sub eax, 0x61
         // 0040ba91: jz 0x40ba9a
      [-]83e8077460
         // 0040ba93: sub eax, 0x7
         // 0040ba96: jz 0x40baf8
      [-]b9????????8bc6e8
         // 0040baa5: mov ecx, 0x5
         // 0040baaa: mov eax, esi
         // 0040baac: call @Sysutils@StrLIComp$qqrpxct1ui
      [-]ffff85c0742a
         // 0040bab1: test eax, eax
         // 0040bab3: jz 0x40badf
      [-]b9????????8bc6e8
         // 0040baba: mov ecx, 0x3
         // 0040babf: mov eax, esi
         // 0040bac1: call @Sysutils@StrLIComp$qqrpxct1ui
      [-]ffff85c07415
         // 0040bac6: test eax, eax
         // 0040bac8: jz 0x40badf
      [-]b9????????8bc6e8
         // 0040bacf: mov ecx, 0x4
         // 0040bad4: mov eax, esi
         // 0040bad6: call @Sysutils@StrLIComp$qqrpxct1ui
      [-]e5ffff85c07519
         // 0040badb: test eax, eax
         // 0040badd: jnz 0x40baf8
      [-]34018845
         // 0040c505: xor b1 al, b1 0x1
         // 0040c507: mov b1 ss:[ebp+0xffffffffffffffe0], b1 al
      [-]0f8561ffffff
         // 0040baf2: jnz 0x40ba59
      [-]837df4027e07
         // 0040bb17: cmp ss:[ebp+0xfffffffffffffff4], 0x2
         // 0040bb1b: jle 0x40bb24
      [-]c745f4????????
         // 0040bb1d: mov ss:[ebp+0xfffffffffffffff4], 0x2
      [-]8b55f4e8
         // 0040bb2b: mov edx, ss:[ebp+0xfffffffffffffff4]
         // 0040bb2e: call 0x40b3c8
      [-]f8ffff59e9
         // 0040bb33: pop ecx
         // 0040bb34: jmp 0x40be78
      [-]f8ffff5955e8
         // 0040bb3f: pop ecx
         // 0040bb40: push ebp
         // 0040bb41: call 0x40b478
      [-]ffff59837df4027e07
         // 0040bb46: pop ecx
         // 0040bb47: cmp ss:[ebp+0xfffffffffffffff4], 0x2
         // 0040bb4b: jle 0x40bb54
      [-]c745f4????????
         // 0040bb4d: mov ss:[ebp+0xfffffffffffffff4], 0x2
      [-]8b4508500fb745e88b55f4e8
         // 0040bb54: mov eax, ss:[ebp+0x8]
         // 0040bb57: push eax
         // 0040bb58: movzx eax, b2 ss:[ebp+0xffffffffffffffe8]
         // 0040bb5c: mov edx, ss:[ebp+0xfffffffffffffff4]
         // 0040bb5f: call 0x40b3c8
      [-]f8ffff59e9
         // 0040bb64: pop ecx
         // 0040bb65: jmp 0x40be78
      [-]f8ffff5955e8
         // 0040bb70: pop ecx
         // 0040bb71: push ebp
         // 0040bb72: call 0x40b478
      [-]ffff59837df4027e07
         // 0040bb77: pop ecx
         // 0040bb78: cmp ss:[ebp+0xfffffffffffffff4], 0x2
         // 0040bb7c: jle 0x40bb85
      [-]c745f4????????
         // 0040bb7e: mov ss:[ebp+0xfffffffffffffff4], 0x2
      [-]8b4508500fb745e68b55f4e8
         // 0040bb85: mov eax, ss:[ebp+0x8]
         // 0040bb88: push eax
         // 0040bb89: movzx eax, b2 ss:[ebp+0xffffffffffffffe6]
         // 0040bb8d: mov edx, ss:[ebp+0xfffffffffffffff4]
         // 0040bb90: call 0x40b3c8
      [-]f8ffff59e9
         // 0040bb95: pop ecx
         // 0040bb96: jmp 0x40be78
      [-]f8ffff59837df4017514
         // 0040bba1: pop ecx
         // 0040bba2: cmp ss:[ebp+0xfffffffffffffff4], 0x1
         // 0040bba6: jnz 0x40bbbc
      [-]8b450850a1
         // 0040bba8: mov eax, ss:[ebp+0x8]
         // 0040bbab: push eax
         // 0040bbac: mov eax, ds:[0x49e6a4]
      [-]fbffff59e9
         // 0040bbb6: pop ecx
         // 0040bbb7: jmp 0x40be78
      [-]8b450850a1
         // 0040bbbc: mov eax, ss:[ebp+0x8]
         // 0040bbbf: push eax
         // 0040bbc0: mov eax, ds:[0x49e6a8]
      [-]fbffff59e9
         // 0040bbca: pop ecx
         // 0040bbcb: jmp 0x40be78
      [-]f8ffff5955e8
         // 0040bbd6: pop ecx
         // 0040bbd7: push ebp
         // 0040bbd8: call 0x40b478
      [-]f8ffff59837df4037e07
         // 0040bbdd: pop ecx
         // 0040bbde: cmp ss:[ebp+0xfffffffffffffff4], 0x3
         // 0040bbe2: jle 0x40bbeb
      [-]c745f4????????
         // 0040bbe4: mov ss:[ebp+0xfffffffffffffff4], 0x3
      [-]8b4508500fb745e48b55f4e8
         // 0040bbeb: mov eax, ss:[ebp+0x8]
         // 0040bbee: push eax
         // 0040bbef: movzx eax, b2 ss:[ebp+0xffffffffffffffe4]
         // 0040bbf3: mov edx, ss:[ebp+0xfffffffffffffff4]
         // 0040bbf6: call 0x40b3c8
      [-]f7ffff59e9
         // 0040bbfb: pop ecx
         // 0040bbfc: jmp 0x40be78
      [-]f8ffff598b
         // 0040bc07: pop ecx
         // 0040bc08: mov esi, ss:[ebp+0xfffffffffffffffc]
      [-]b9????????8bc6e8
         // 0040bc11: mov ecx, 0x5
         // 0040bc16: mov eax, esi
         // 0040bc18: call @Sysutils@StrLIComp$qqrpxct1ui
      [-]ffff85c075
         // 0040bc1d: test eax, eax
         // 0040bc1f: jnz 0x40bc49
      [-]66837dea0c7203
         // 0040bc21: cmp b2 ss:[ebp+0xffffffffffffffea], b2 0xc
         // 0040bc26: jb 0x40bc2b
      [-]8b450850ba????????8bc6e8
         // 0040bc2b: mov eax, ss:[ebp+0x8]
         // 0040bc2e: push eax
         // 0040bc2f: mov edx, 0x2
         // 0040bc34: mov eax, esi
         // 0040bc36: call 0x40b364
      [-]ffff5983
         // 0040bc3b: pop ecx
         // 0040bc3c: add ss:[ebp+0xfffffffffffffffc], 0x4
      [-]b9????????8bc6e8
         // 0040bc4e: mov ecx, 0x3
         // 0040bc53: mov eax, esi
         // 0040bc55: call @Sysutils@StrLIComp$qqrpxct1ui
      [-]ffff85c075
         // 0040bc5a: test eax, eax
         // 0040bc5c: jnz 0x40bc86
      [-]66837dea0c7203
         // 0040bc5e: cmp b2 ss:[ebp+0xffffffffffffffea], b2 0xc
         // 0040bc63: jb 0x40bc68
      [-]8b450850ba????????8bc6e8
         // 0040bc68: mov eax, ss:[ebp+0x8]
         // 0040bc6b: push eax
         // 0040bc6c: mov edx, 0x1
         // 0040bc71: mov eax, esi
         // 0040bc73: call 0x40b364
      [-]f6ffff5983
         // 0040bc78: pop ecx
         // 0040bc79: add ss:[ebp+0xfffffffffffffffc], 0x2
      [-]b9????????8bc6e8
         // 0040bc8b: mov ecx, 0x4
         // 0040bc90: mov eax, esi
         // 0040bc92: call @Sysutils@StrLIComp$qqrpxct1ui
      [-]ffff85c075
         // 0040bc97: test eax, eax
         // 0040bc99: jnz 0x40bccf
      [-]66837dea0c7311
         // 0040bc9b: cmp b2 ss:[ebp+0xffffffffffffffea], b2 0xc
         // 0040bca0: jnb 0x40bcb3
      [-]8b450850a1
         // 0040bca2: mov eax, ss:[ebp+0x8]
         // 0040bca5: push eax
         // 0040bca6: mov eax, ds:[0x49e69c]
      [-]f6ffff59eb0f
         // 0040bcb0: pop ecx
         // 0040bcb1: jmp 0x40bcc2
      [-]8b450850a1
         // 0040bcb3: mov eax, ss:[ebp+0x8]
         // 0040bcb6: push eax
         // 0040bcb7: mov eax, ds:[0x49e6a0]
      [-]f6ffff59
         // 0040bcc1: pop ecx
      [-]b9????????8bc6e8
         // 0040bcd4: mov ecx, 0x4
         // 0040bcd9: mov eax, esi
         // 0040bcdb: call @Sysutils@StrLIComp$qqrpxct1ui
      [-]ffff85c075
         // 0040bce0: test eax, eax
         // 0040bce2: jnz 0x40bd16
      [-]f7ffff598b4508508b4508ff700cff7008e8
         // 0040bcea: pop ecx
         // 0040bceb: mov eax, ss:[ebp+0x8]
         // 0040bcee: push eax
         // 0040bcef: mov eax, ss:[ebp+0x8]
         // 0040bcf2: push ds:[eax+0xc]
         // 0040bcf5: push ds:[eax+0x8]
         // 0040bcf8: call @Sysutils@DayOfWeek$qqrx16System@TDateTime
      [-]f5ffff0fb7c08b0485
         // 0040bcfd: movzx eax, b2 ax
         // 0040bd00: mov eax, ds:[0x49e724+eax*0x4]
      [-]f6ffff5983
         // 0040bd0c: pop ecx
         // 0040bd0d: add ss:[ebp+0xfffffffffffffffc], 0x3
      [-]b9????????8bc6e8
         // 0040bd1b: mov ecx, 0x3
         // 0040bd20: mov eax, esi
         // 0040bd22: call @Sysutils@StrLIComp$qqrpxct1ui
      [-]ffff85c075
         // 0040bd27: test eax, eax
         // 0040bd29: jnz 0x40bd5d
      [-]ffff598b4508508b4508ff700cff7008e8
         // 0040bd31: pop ecx
         // 0040bd32: mov eax, ss:[ebp+0x8]
         // 0040bd35: push eax
         // 0040bd36: mov eax, ss:[ebp+0x8]
         // 0040bd39: push ds:[eax+0xc]
         // 0040bd3c: push ds:[eax+0x8]
         // 0040bd3f: call @Sysutils@DayOfWeek$qqrx16System@TDateTime
      [-]f5ffff0fb7c08b0485
         // 0040bd44: movzx eax, b2 ax
         // 0040bd47: mov eax, ds:[0x49e708+eax*0x4]
      [-]f6ffff5983
         // 0040bd53: pop ecx
         // 0040bd54: add ss:[ebp+0xfffffffffffffffc], 0x2
      [-]8b4508508d45fbba????????e8
         // 0040bd5d: mov eax, ss:[ebp+0x8]
         // 0040bd60: push eax
         // 0040bd61: lea eax, ss:[ebp+0xfffffffffffffffb]
         // 0040bd64: mov edx, 0x1
         // 0040bd69: call 0x40b364
      [-]f5ffff59e9
         // 0040bd6e: pop ecx
         // 0040bd6f: jmp 0x40be78
      [-]f6ffff598b450850a1
         // 0040bd7a: pop ecx
         // 0040bd7b: mov eax, ss:[ebp+0x8]
         // 0040bd7e: push eax
         // 0040bd7f: mov eax, ds:[0x49e690]
      [-]f9ffff5955e8
         // 0040bd89: pop ecx
         // 0040bd8a: push ebp
         // 0040bd8b: call 0x40b478
      [-]f6ffff5966837dea007512
         // 0040bd90: pop ecx
         // 0040bd91: cmp b2 ss:[ebp+0xffffffffffffffea], b2 0x0
         // 0040bd96: jnz 0x40bdaa
      [-]66837de800750b
         // 0040bd98: cmp b2 ss:[ebp+0xffffffffffffffe8], b2 0x0
         // 0040bd9d: jnz 0x40bdaa
      [-]66837de6000f84
         // 0040bd9f: cmp b2 ss:[ebp+0xffffffffffffffe6], b2 0x0
         // 0040bda4: jz 0x40be78
      [-]8b450850b8
         // 0040bdaa: mov eax, ss:[ebp+0x8]
         // 0040bdad: push eax
         // 0040bdae: mov eax, 0x40bed8
      [-]ba????????e8
         // 0040bdb3: mov edx, 0x1
         // 0040bdb8: call 0x40b364
      [-]f5ffff598b450850a1
         // 0040bdbd: pop ecx
         // 0040bdbe: mov eax, ss:[ebp+0x8]
         // 0040bdc1: push eax
         // 0040bdc2: mov eax, ds:[0x49e6a8]
      [-]f9ffff59e9
         // 0040bdcc: pop ecx
         // 0040bdcd: jmp 0x40be78
      [-]4900000f84
         // 0040bdd9: jz 0x40be78
      [-]8b450850b8
         // 0040bddf: mov eax, ss:[ebp+0x8]
         // 0040bde2: push eax
         // 0040bde3: mov eax, 0x49e68d
      [-]ba????????e8
         // 0040bde8: mov edx, 0x1
         // 0040bded: call 0x40b364
      [-]f5ffff59
         // 0040bdf2: pop ecx
      [-]49000074
         // 0040bdff: jz 0x40be78
      [-]8b450850b8
         // 0040be01: mov eax, ss:[ebp+0x8]
         // 0040be04: push eax
         // 0040be05: mov eax, 0x49e698
      [-]ba????????e8
         // 0040be0a: mov edx, 0x1
         // 0040be0f: call 0x40b364
      [-]f5ffff59eb
         // 0040be14: pop ecx
         // 0040be15: jmp 0x40be78
      [-]1f000089
         // 0040be32: mov ss:[ebp+0xfffffffffffffffc], eax
      [-]3a45fb75
         // 0040be43: cmp b1 al, b1 ss:[ebp+0xfffffffffffffffb]
         // 0040be46: jnz 0x40be1c
      [-]8b4508508b
         // 0040be48: mov eax, ss:[ebp+0x8]
         // 0040be4b: push eax
         // 0040be4c: mov edx, ss:[ebp+0xfffffffffffffffc]
      [-]2bd68bc6e8
         // 0040be4f: sub edx, esi
         // 0040be51: mov eax, esi
         // 0040be53: call 0x40b364
      [-]ffff598b
         // 0040be58: pop ecx
         // 0040be59: mov eax, ss:[ebp+0xfffffffffffffffc]
      [-]80380074
         // 0040be5c: cmp b1 ds:[eax], b1 0x0
         // 0040be5f: jz 0x40be78
      [-]8b4508508d45fbba????????e8
         // 0040be66: mov eax, ss:[ebp+0x8]
         // 0040be69: push eax
         // 0040be6a: lea eax, ss:[ebp+0xfffffffffffffffb]
         // 0040be6d: mov edx, 0x1
         // 0040be72: call 0x40b364
      [-]f4ffff59
         // 0040be77: pop ecx
      [-]8b4508ff88????????
         // 0040be85: mov eax, ss:[ebp+0x8]
         // 0040be88: dec ds:[eax+0xfffffffffffffef8]
      [-]33c05a595964891068
         // 0040be8e: xor eax, eax
         // 0040be90: pop edx
         // 0040be91: pop ecx
         // 0040be92: pop ecx
         // 0040be93: mov fs:[eax], edx
         // 0040be96: push 0x40beb0
      [-]ba????????e8
         // 0040be9e: mov edx, 0x2
         // 0040bea3: call @System@@LStrArrayClr$qqrpvi
      [-]8be55dc3
         // 0040beb2: mov esp, ebp
         // 0040beb4: pop ebp
         // 0040beb5: retn 
      [-]5383c4f08bd88bd48bc3e82500000084c07519
         // 0040c858: push ebx
         // 0040c859: add esp, 0xfffffffffffffff0
         // 0040c85c: mov ebx, eax
         // 0040c85e: mov edx, esp
         // 0040c860: mov eax, ebx
         // 0040c862: call @Sysutils@TryStrToDateTime$qqrx17System@AnsiStringr16System@TDateTime
         // 0040c867: test b1 al, b1 al
         // 0040c869: jnz 0x40c884
      [-]895c2408c644240c0b8d542408a1
         // 0040c86b: mov ss:[esp+0x8], ebx
         // 0040c86f: mov b1 ss:[esp+0xc], b1 0xb
         // 0040c874: lea edx, ss:[esp+0x8]
         // 0040c878: mov eax, ds:[0x49d74c]
      [-]dd042483c4105bc3
         // 0040c884: fld b8 ss:[esp]
         // 0040c887: add esp, 0x10
         // 0040c88a: pop ebx
         // 0040c88b: retn 
      [-]558bec81c4????????535633c08985????????8985????????8985????????8985????????8945fc33c05568
         // 0040d5a0: push ebp
         // 0040d5a1: mov ebp, esp
         // 0040d5a3: add esp, 0xfffffffffffffe90
         // 0040d5a9: push ebx
         // 0040d5aa: push esi
         // 0040d5ab: xor eax, eax
         // 0040d5ad: mov ss:[ebp+0xfffffffffffffe90], eax
         // 0040d5b3: mov ss:[ebp+0xfffffffffffffeb4], eax
         // 0040d5b9: mov ss:[ebp+0xfffffffffffffeac], eax
         // 0040d5bf: mov ss:[ebp+0xfffffffffffffeb0], eax
         // 0040d5c5: mov ss:[ebp+0xfffffffffffffffc], eax
         // 0040d5c8: xor eax, eax
         // 0040d5ca: push ebp
         // 0040d5cb: push 0x40d75b
      [-]64ff306489208b45088b58fc837b1400750f
         // 0040d5d0: push fs:[eax]
         // 0040d5d3: mov fs:[eax], esp
         // 0040d5d6: mov eax, ss:[ebp+0x8]
         // 0040d5d9: mov ebx, ds:[eax+0xfffffffffffffffc]
         // 0040d5dc: cmp ds:[ebx+0x14], 0x0
         // 0040d5e0: jnz 0x40d5f1
      [-]8d55fca1
         // 0040d5e2: lea edx, ss:[ebp+0xfffffffffffffffc]
         // 0040d5e5: mov eax, ds:[0x49de48]
      [-]ffffeb0d
         // 0040d5ef: jmp 0x40d5fe
      [-]8d55fca1
         // 0040d5f1: lea edx, ss:[ebp+0xfffffffffffffffc]
         // 0040d5f4: mov eax, ds:[0x49dbd4]
      [-]8b73186a1c8d45e0508b430c50e8
         // 0040d5fe: mov esi, ds:[ebx+0x18]
         // 0040d601: push 0x1c
         // 0040d603: lea eax, ss:[ebp+0xffffffffffffffe0]
         // 0040d606: push eax
         // 0040d607: mov eax, ds:[ebx+0xc]
         // 0040d60a: push eax
         // 0040d60b: call VirtualQuery_0
      [-]ffff817df0????????0f85b3000000
         // 0040d610: cmp ss:[ebp+0xfffffffffffffff0], 0x1000
         // 0040d617: jnz 0x40d6d0
      [-]68????????8d85????????508b45e450e8
         // 0040d61d: push 0x105
         // 0040d622: lea eax, ss:[ebp+0xfffffffffffffedb]
         // 0040d628: push eax
         // 0040d629: mov eax, ss:[ebp+0xffffffffffffffe4]
         // 0040d62c: push eax
         // 0040d62d: call GetModuleFileNameA_0
      [-]ffff85c00f8496000000
         // 0040d632: test eax, eax
         // 0040d634: jz 0x40d6d0
      [-]8b430c8985????????c685bcfeffff058d85????????8d95????????b9????????e8
         // 0040d63a: mov eax, ds:[ebx+0xc]
         // 0040d63d: mov ss:[ebp+0xfffffffffffffeb8], eax
         // 0040d643: mov b1 ss:[ebp+0xfffffffffffffebc], b1 0x5
         // 0040d64a: lea eax, ss:[ebp+0xfffffffffffffeb0]
         // 0040d650: lea edx, ss:[ebp+0xfffffffffffffedb]
         // 0040d656: mov ecx, 0x105
         // 0040d65b: call 0x404c30
      [-]ffff8b85????????8d95????????e8
         // 0040d660: mov eax, ss:[ebp+0xfffffffffffffeb0]
         // 0040d666: lea edx, ss:[ebp+0xfffffffffffffeb4]
         // 0040d66c: call @Sysutils@ExtractFileName$qqrx17System@AnsiString
      [-]ffff8b85????????8985????????c685c4feffff0b8b45fc8985????????c685ccfeffff0b89b5????????c685d4feffff058d85????????506a038d95????????a1
         // 0040d671: mov eax, ss:[ebp+0xfffffffffffffeb4]
         // 0040d677: mov ss:[ebp+0xfffffffffffffec0], eax
         // 0040d67d: mov b1 ss:[ebp+0xfffffffffffffec4], b1 0xb
         // 0040d684: mov eax, ss:[ebp+0xfffffffffffffffc]
         // 0040d687: mov ss:[ebp+0xfffffffffffffec8], eax
         // 0040d68d: mov b1 ss:[ebp+0xfffffffffffffecc], b1 0xb
         // 0040d694: mov ss:[ebp+0xfffffffffffffed0], esi
         // 0040d69a: mov b1 ss:[ebp+0xfffffffffffffed4], b1 0x5
         // 0040d6a1: lea eax, ss:[ebp+0xfffffffffffffeb8]
         // 0040d6a7: push eax
         // 0040d6a8: push 0x3
         // 0040d6aa: lea edx, ss:[ebp+0xfffffffffffffeac]
         // 0040d6b0: mov eax, ds:[0x49dcbc]
      [-]ffff8b8d????????b201a1
         // 0040d6ba: mov ecx, ss:[ebp+0xfffffffffffffeac]
         // 0040d6c0: mov b1 dl, b1 0x1
         // 0040d6c2: mov eax, ds:[0x40870c]
      [-]faffff8bd8eb5a
         // 0040d6cc: mov ebx, eax
         // 0040d6ce: jmp 0x40d72a
      [-]8b430c8985????????c68598feffff058b45fc8985????????c685a0feffff0b89b5????????c685a8feffff058d85????????506a028d95????????a1
         // 0040d6d0: mov eax, ds:[ebx+0xc]
         // 0040d6d3: mov ss:[ebp+0xfffffffffffffe94], eax
         // 0040d6d9: mov b1 ss:[ebp+0xfffffffffffffe98], b1 0x5
         // 0040d6e0: mov eax, ss:[ebp+0xfffffffffffffffc]
         // 0040d6e3: mov ss:[ebp+0xfffffffffffffe9c], eax
         // 0040d6e9: mov b1 ss:[ebp+0xfffffffffffffea0], b1 0xb
         // 0040d6f0: mov ss:[ebp+0xfffffffffffffea4], esi
         // 0040d6f6: mov b1 ss:[ebp+0xfffffffffffffea8], b1 0x5
         // 0040d6fd: lea eax, ss:[ebp+0xfffffffffffffe94]
         // 0040d703: push eax
         // 0040d704: push 0x2
         // 0040d706: lea edx, ss:[ebp+0xfffffffffffffe90]
         // 0040d70c: mov eax, ds:[0x49dbfc]
      [-]ffff8b8d????????b201a1
         // 0040d716: mov ecx, ss:[ebp+0xfffffffffffffe90]
         // 0040d71c: mov b1 dl, b1 0x1
         // 0040d71e: mov eax, ds:[0x40870c]
      [-]faffff8bd8
         // 0040d728: mov ebx, eax
      [-]33c05a595964891068
         // 0040d72a: xor eax, eax
         // 0040d72c: pop edx
         // 0040d72d: pop ecx
         // 0040d72e: pop ecx
         // 0040d72f: mov fs:[eax], edx
         // 0040d732: push 0x40d762
      [-]8d85????????e8
         // 0040d737: lea eax, ss:[ebp+0xfffffffffffffe90]
         // 0040d73d: call @System@@LStrClr$qqrpv
      [-]ffff8d85????????ba????????e8
         // 0040d742: lea eax, ss:[ebp+0xfffffffffffffeac]
         // 0040d748: mov edx, 0x3
         // 0040d74d: call @System@@LStrArrayClr$qqrpvi
      [-]ffff8d45fce8
         // 0040d752: lea eax, ss:[ebp+0xfffffffffffffffc]
         // 0040d755: call @System@@LStrClr$qqrpv
      [-]8bc35e5b8be55dc3
         // 0040d762: mov eax, ebx
         // 0040d764: pop esi
         // 0040d765: pop ebx
         // 0040d766: mov esp, ebp
         // 0040d768: pop ebp
         // 0040d769: retn 
      [-]53568bf28bd8b8????????803d
         // 0040dd78: push ebx
         // 0040dd79: push esi
         // 0040dd7a: mov esi, edx
         // 0040dd7c: mov ebx, eax
         // 0040dd7e: mov eax, 0x1
         // 0040dd83: cmp b1 ds:[0x49e750], b1 0x0
      [-]49000074
         // 0040dd8a: jz 0x40ddae
      [-]ffff03c648e8
         // 0040dda6: add eax, esi
         // 0040dda8: dec eax
         // 0040dda9: call @Sysutils@StrCharLength$qqrpxc
      [-]53568bda8bf08d4301803d
         // 0040ddb4: push ebx
         // 0040ddb5: push esi
         // 0040ddb6: mov ebx, edx
         // 0040ddb8: mov esi, eax
         // 0040ddba: lea eax, ds:[ebx+0x1]
         // 0040ddbd: cmp b1 ds:[0x49e750], b1 0x0
      [-]49000074
         // 0040ddc4: jz 0x40ddea
      [-]ffff03c348e8
         // 0040dde0: add eax, ebx
         // 0040dde2: dec eax
         // 0040dde3: call @Sysutils@StrCharLength$qqrpxc
      [-]ffffff03c3
         // 0040dde8: add eax, ebx
      [-]871089d0c3
         // 0040e8f8: xchg edx, ds:[eax]
         // 0040e8fa: mov eax, edx
         // 0040e8fc: retn 
      [-]92f00fc102c3
         // 0040e900: xchg eax, edx
         // 0040e901: lock xadd ds:[edx], eax
         // 0040e905: retn 
      [-]53565755e8
         // 0040e908: push ebx
         // 0040e909: push esi
         // 0040e90a: push edi
         // 0040e90b: push ebp
         // 0040e90c: call @System@@BeforeDestruction$qqrp14System@TObjectzc
      [-]0433c08944
         // 0040e91b: xor eax, eax
         // 0040e91d: mov ds:[edi+esi*0x4], eax
      [-]80e2fc8b
         // 0040f568: and b1 dl, b1 0xfc
         // 0040f56b: mov eax, ebp
      [-]53565755518914248bf88bc7e8
         // 0040e970: push ebx
         // 0040e971: push esi
         // 0040e972: push edi
         // 0040e973: push ebp
         // 0040e974: push ecx
         // 0040e975: mov ss:[esp], edx
         // 0040e978: mov edi, eax
         // 0040e97a: mov eax, edi
         // 0040e97c: call @Sysutils@TThreadLocalCounter@HashIndex$qqrv
      [-]ffffff8bd8e8
         // 0040e981: mov ebx, eax
         // 0040e983: call GetCurrentThreadId_0
      [-]ffff8bf0
         // 0040e988: mov esi, eax
      [-]8b6c8704eb03
         // 0040e98e: mov ebp, ds:[edi+eax*0x4]
         // 0040e992: jmp 0x40e997
      [-]85ed7405
         // 0040e997: test ebp, ebp
         // 0040e999: jz 0x40e9a0
      [-]3b750475f4
         // 0040e99b: cmp esi, ss:[ebp+0x4]
         // 0040e99e: jnz 0x40e994
      [-]0000008be885ed75
         // 0040e9ab: mov ebp, eax
         // 0040e9ad: test ebp, ebp
         // 0040e9af: jnz 0x40e9dc
      [-]b8????????e8
         // 0040e9b1: mov eax, 0x10
         // 0040e9b6: call @Sysutils@AllocMem$qqrui
      [-]ffff8be8897504c74508????????896d00
         // 0040e9bb: mov ebp, eax
         // 0040e9bd: mov ss:[ebp+0x4], esi
         // 0040e9c0: mov ss:[ebp+0x8], 0x7fffffff
         // 0040e9c7: mov ss:[ebp+0x0], ebp
      [-]8d4487048bd5e8
         // 0040e9ce: lea eax, ds:[edi+eax*0x4]
         // 0040e9d2: mov edx, ebp
         // 0040e9d4: call 0x40e8f8
      [-]ffffff894500
         // 0040e9d9: mov ss:[ebp+0x0], eax
      [-]8b042489285a5d5f5e5bc3
         // 0040e9dc: mov eax, ss:[esp]
         // 0040e9df: mov ds:[eax], ebp
         // 0040e9e1: pop edx
         // 0040e9e2: pop ebp
         // 0040e9e3: pop edi
         // 0040e9e4: pop esi
         // 0040e9e5: pop ebx
         // 0040e9e6: retn 
      [-]538bd88bc3e8
         // 0040e9f8: push ebx
         // 0040e9f9: mov ebx, eax
         // 0040e9fb: mov eax, ebx
         // 0040e9fd: call @Sysutils@TThreadLocalCounter@HashIndex$qqrv
      [-]8b5c830485db74
         // 0040ea07: mov ebx, ds:[ebx+eax*0x4]
         // 0040ea0b: test ebx, ebx
         // 0040ea0d: jz 0x40ea33
      [-]8d4308ba????????e8
         // 0040ea0f: lea eax, ds:[ebx+0x8]
         // 0040ea12: mov edx, 0x7fffffff
         // 0040ea17: call 0x40e8f8
      [-]ffff894304eb06
         // 0040ea28: mov ds:[ebx+0x4], eax
         // 0040ea2b: jmp 0x40ea33
      [-]8b1b85db75
         // 0040ea2d: mov ebx, ds:[ebx]
         // 0040ea2f: test ebx, ebx
         // 0040ea31: jnz 0x40ea0f
      [-]53565755
         // 0040eb38: push ebx
         // 0040eb39: push esi
         // 0040eb3a: push edi
         // 0040eb3b: push ebp
      [-]ffffff8b
         // 0040eb54: mov ebp, ds:[edi+0x28]
      [-]feffff8b042483780c000f97c384db74
         // 0040eb61: mov eax, ss:[esp]
         // 0040eb64: cmp ds:[eax+0xc], 0x0
         // 0040eb68: setnbe b1 bl
         // 0040eb6b: test b1 bl, b1 bl
         // 0040eb6d: jz 0x40eb91
      [-]fdffffeb
         // 0040eb77: jmp 0x40eb91
      [-]0cba????????e8
         // 0040eb7c: mov edx, 0xffff
         // 0040eb81: call 0x40e900
      [-]fdffff85
         // 0040eb86: test eax, eax
      [-]0cba????????e8
         // 0040eb94: mov edx, 0xffffffffffff0001
         // 0040eb99: call 0x40e900
      [-]fdffff3d????????75
         // 0040eb9e: cmp eax, 0xffff
         // 0040eba3: jnz 0x40eb79
      [-]ffffff84db7408
         // 0040ebac: test b1 bl, b1 bl
         // 0040ebae: jz 0x40ebb8
      [-]fdffff483b
         // 0040ebc3: dec eax
         // 0040ebc4: cmp eax, ebp
      [-]1c8bc35a5d5f5e
         // 0040ebcc: mov eax, ebx
         // 0040ebce: pop edx
         // 0040ebcf: pop ebp
         // 0040ebd0: pop edi
         // 0040ebd1: pop esi
      [-]558bec6a00538b451885c07404
         // 0040f6a0: push ebp
         // 0040f6a1: mov ebp, esp
         // 0040f6a3: push 0x0
         // 0040f6a5: push ebx
         // 0040f6a6: mov eax, ss:[ebp+0x18]
         // 0040f6a9: test eax, eax
         // 0040f6ab: jz 0x40f6b1
      [-]33d28910
         // 0040f6ad: xor edx, edx
         // 0040f6af: mov ds:[eax], edx
      [-]33c05568??
         // 0040f6b1: xor eax, eax
         // 0040f6b3: push ebp
         // 0040f6b4: push 0x40f700
      [-]64ff30648920817d10????????7407
         // 0040f6b9: push fs:[eax]
         // 0040f6bc: mov fs:[eax], esp
         // 0040f6bf: cmp ss:[ebp+0x10], 0x400
         // 0040f6c6: jz 0x40f6cf
      [-]bb????????eb1b
         // 0040f6c8: mov ebx, 0xffffffff80004001
         // 0040f6cd: jmp 0x40f6ea
      [-]ff750cff75088d45fce8
         // 0040f6cf: push ss:[ebp+0xc]
         // 0040f6d2: push ss:[ebp+0x8]
         // 0040f6d5: lea eax, ss:[ebp+0xfffffffffffffffc]
         // 0040f6d8: call 0x40bf68
      [-]ffff8b55fc8b4518e8
         // 0040f6dd: mov edx, ss:[ebp+0xfffffffffffffffc]
         // 0040f6e0: mov eax, ss:[ebp+0x18]
         // 0040f6e3: call @System@@WStrFromLStr$qqrr17System@WideStringx17System@AnsiString
      [-]5bffff33db
         // 0040f6e8: xor ebx, ebx
      [-]33c05a595964891068
         // 0040f6ea: xor eax, eax
         // 0040f6ec: pop edx
         // 0040f6ed: pop ecx
         // 0040f6ee: pop ecx
         // 0040f6ef: mov fs:[eax], edx
         // 0040f6f2: push 0x40f707
      [-]8d45fce8
         // 0040f6f7: lea eax, ss:[ebp+0xfffffffffffffffc]
         // 0040f6fa: call @System@@LStrClr$qqrpv
      [-]8bc35b595dc21400
         // 0040f707: mov eax, ebx
         // 0040f709: pop ebx
         // 0040f70a: pop ecx
         // 0040f70b: pop ebp
         // 0040f70c: retn b2 0x14
      [-]558bec6a0033c05568
         // 0041015c: push ebp
         // 0041015d: mov ebp, esp
         // 0041015f: push 0x0
         // 00410161: xor eax, eax
         // 00410163: push ebp
         // 00410164: push 0x4101a6
      [-]64ff306489208d55fca1
         // 00410169: push fs:[eax]
         // 0041016c: mov fs:[eax], esp
         // 0041016f: lea edx, ss:[ebp+0xfffffffffffffffc]
         // 00410172: mov eax, ds:[0x49db04]
      [-]ffff8b4dfcb201a1
         // 0041017c: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 0041017f: mov b1 dl, b1 0x1
         // 00410181: mov eax, ds:[0x40fc9c]
      [-]ffff33c05a595964891068
         // 00410190: xor eax, eax
         // 00410192: pop edx
         // 00410193: pop ecx
         // 00410194: pop ecx
         // 00410195: mov fs:[eax], edx
         // 00410198: push 0x4101ad
      [-]8d45fce8
         // 0041019d: lea eax, ss:[ebp+0xfffffffffffffffc]
         // 004101a0: call @System@@LStrClr$qqrpv
      [-]558bec83c4e4535633c9894dec894de8894de48bf28bd833c05568
         // 004101b0: push ebp
         // 004101b1: mov ebp, esp
         // 004101b3: add esp, 0xffffffffffffffe4
         // 004101b6: push ebx
         // 004101b7: push esi
         // 004101b8: xor ecx, ecx
         // 004101ba: mov ss:[ebp+0xffffffffffffffec], ecx
         // 004101bd: mov ss:[ebp+0xffffffffffffffe8], ecx
         // 004101c0: mov ss:[ebp+0xffffffffffffffe4], ecx
         // 004101c3: mov esi, edx
         // 004101c5: mov ebx, eax
         // 004101c7: xor eax, eax
         // 004101c9: push ebp
         // 004101ca: push 0x41023f
      [-]64ff306489208d55ec8bc3e8
         // 004101cf: push fs:[eax]
         // 004101d2: mov fs:[eax], esp
         // 004101d5: lea edx, ss:[ebp+0xffffffffffffffec]
         // 004101d8: mov eax, ebx
         // 004101da: call @Variants@VarTypeAsText$qqrxus
      [-]00008b45ec8945f0c645f40b8d55e88bc6e8
         // 004101df: mov eax, ss:[ebp+0xffffffffffffffec]
         // 004101e2: mov ss:[ebp+0xfffffffffffffff0], eax
         // 004101e5: mov b1 ss:[ebp+0xfffffffffffffff4], b1 0xb
         // 004101e9: lea edx, ss:[ebp+0xffffffffffffffe8]
         // 004101ec: mov eax, esi
         // 004101ee: call @Variants@VarTypeAsText$qqrxus
      [-]00008b45e88945f8c645fc0b8d45f0506a018d55e4a1
         // 004101f3: mov eax, ss:[ebp+0xffffffffffffffe8]
         // 004101f6: mov ss:[ebp+0xfffffffffffffff8], eax
         // 004101f9: mov b1 ss:[ebp+0xfffffffffffffffc], b1 0xb
         // 004101fd: lea eax, ss:[ebp+0xfffffffffffffff0]
         // 00410200: push eax
         // 00410201: push 0x1
         // 00410203: lea edx, ss:[ebp+0xffffffffffffffe4]
         // 00410206: mov eax, ds:[0x49d6cc]
      [-]ffff8b4de4b201a1
         // 00410210: mov ecx, ss:[ebp+0xffffffffffffffe4]
         // 00410213: mov b1 dl, b1 0x1
         // 00410215: mov eax, ds:[0x40fc9c]
      [-]ffff33c05a595964891068
         // 00410224: xor eax, eax
         // 00410226: pop edx
         // 00410227: pop ecx
         // 00410228: pop ecx
         // 00410229: mov fs:[eax], edx
         // 0041022c: push 0x410246
      [-]8d45e4ba????????e8
         // 00410231: lea eax, ss:[ebp+0xffffffffffffffe4]
         // 00410234: mov edx, 0x3
         // 00410239: call @System@@LStrArrayClr$qqrpvi
      [-]5e5b8be55dc3
         // 00410246: pop esi
         // 00410247: pop ebx
         // 00410248: mov esp, ebp
         // 0041024a: pop ebp
         // 0041024b: retn 
      [-]558bec6a0033c05568
         // 0041024c: push ebp
         // 0041024d: mov ebp, esp
         // 0041024f: push 0x0
         // 00410251: xor eax, eax
         // 00410253: push ebp
         // 00410254: push 0x410296
      [-]64ff306489208d55fca1
         // 00410259: push fs:[eax]
         // 0041025c: mov fs:[eax], esp
         // 0041025f: lea edx, ss:[ebp+0xfffffffffffffffc]
         // 00410262: mov eax, ds:[0x49da7c]
      [-]ffff8b4dfcb201a1
         // 0041026c: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 0041026f: mov b1 dl, b1 0x1
         // 00410271: mov eax, ds:[0x40fc38]
      [-]ffff33c05a595964891068
         // 00410280: xor eax, eax
         // 00410282: pop edx
         // 00410283: pop ecx
         // 00410284: pop ecx
         // 00410285: mov fs:[eax], edx
         // 00410288: push 0x41029d
      [-]8d45fce8
         // 0041028d: lea eax, ss:[ebp+0xfffffffffffffffc]
         // 00410290: call @System@@LStrClr$qqrpv
      [-]558bec83c4e4535633c9894dec894de8894de48bf28bd833c05568
         // 004102f4: push ebp
         // 004102f5: mov ebp, esp
         // 004102f7: add esp, 0xffffffffffffffe4
         // 004102fa: push ebx
         // 004102fb: push esi
         // 004102fc: xor ecx, ecx
         // 004102fe: mov ss:[ebp+0xffffffffffffffec], ecx
         // 00410301: mov ss:[ebp+0xffffffffffffffe8], ecx
         // 00410304: mov ss:[ebp+0xffffffffffffffe4], ecx
         // 00410307: mov esi, edx
         // 00410309: mov ebx, eax
         // 0041030b: xor eax, eax
         // 0041030d: push ebp
         // 0041030e: push 0x410383
      [-]64ff306489208d55ec8bc3e8
         // 00410313: push fs:[eax]
         // 00410316: mov fs:[eax], esp
         // 00410319: lea edx, ss:[ebp+0xffffffffffffffec]
         // 0041031c: mov eax, ebx
         // 0041031e: call @Variants@VarTypeAsText$qqrxus
      [-]00008b45ec8945f0c645f40b8d55e88bc6e8
         // 00410323: mov eax, ss:[ebp+0xffffffffffffffec]
         // 00410326: mov ss:[ebp+0xfffffffffffffff0], eax
         // 00410329: mov b1 ss:[ebp+0xfffffffffffffff4], b1 0xb
         // 0041032d: lea edx, ss:[ebp+0xffffffffffffffe8]
         // 00410330: mov eax, esi
         // 00410332: call @Variants@VarTypeAsText$qqrxus
      [-]00008b45e88945f8c645fc0b8d45f0506a018d55e4a1
         // 00410337: mov eax, ss:[ebp+0xffffffffffffffe8]
         // 0041033a: mov ss:[ebp+0xfffffffffffffff8], eax
         // 0041033d: mov b1 ss:[ebp+0xfffffffffffffffc], b1 0xb
         // 00410341: lea eax, ss:[ebp+0xfffffffffffffff0]
         // 00410344: push eax
         // 00410345: push 0x1
         // 00410347: lea edx, ss:[ebp+0xffffffffffffffe4]
         // 0041034a: mov eax, ds:[0x49dbc4]
      [-]ffff8b4de4b201a1??
         // 00410354: mov ecx, ss:[ebp+0xffffffffffffffe4]
         // 00410357: mov b1 dl, b1 0x1
         // 00410359: mov eax, ds:[0x40fd00]
      [-]ffff33c05a595964891068
         // 00410368: xor eax, eax
         // 0041036a: pop edx
         // 0041036b: pop ecx
         // 0041036c: pop ecx
         // 0041036d: mov fs:[eax], edx
         // 00410370: push 0x41038a
      [-]8d45e4ba????????e8
         // 00410375: lea eax, ss:[ebp+0xffffffffffffffe4]
         // 00410378: mov edx, 0x3
         // 0041037d: call @System@@LStrArrayClr$qqrpvi
      [-]5e5b8be55dc3
         // 0041038a: pop esi
         // 0041038b: pop ebx
         // 0041038c: mov esp, ebp
         // 0041038e: pop ebp
         // 0041038f: retn 
      [-]558bec6a0033c05568
         // 00410390: push ebp
         // 00410391: mov ebp, esp
         // 00410393: push 0x0
         // 00410395: xor eax, eax
         // 00410397: push ebp
         // 00410398: push 0x4103da
      [-]64ff306489208d55fca1
         // 0041039d: push fs:[eax]
         // 004103a0: mov fs:[eax], esp
         // 004103a3: lea edx, ss:[ebp+0xfffffffffffffffc]
         // 004103a6: mov eax, ds:[0x49da00]
      [-]ffff8b4dfcb201a1
         // 004103b0: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 004103b3: mov b1 dl, b1 0x1
         // 004103b5: mov eax, ds:[0x40fef8]
      [-]ffff33c05a595964891068
         // 004103c4: xor eax, eax
         // 004103c6: pop edx
         // 004103c7: pop ecx
         // 004103c8: pop ecx
         // 004103c9: mov fs:[eax], edx
         // 004103cc: push 0x4103e1
      [-]8d45fce8
         // 004103d1: lea eax, ss:[ebp+0xfffffffffffffffc]
         // 004103d4: call @System@@LStrClr$qqrpv
      [-]45ffffc3
         // 004103d9: retn 
      [-]558bec6a0033c05568
         // 004106fc: push ebp
         // 004106fd: mov ebp, esp
         // 004106ff: push 0x0
         // 00410701: xor eax, eax
         // 00410703: push ebp
         // 00410704: push 0x410746
      [-]64ff306489208d55fca1
         // 00410709: push fs:[eax]
         // 0041070c: mov fs:[eax], esp
         // 0041070f: lea edx, ss:[ebp+0xfffffffffffffffc]
         // 00410712: mov eax, ds:[0x49d6c4]
      [-]ffff8b4dfcb201a1
         // 0041071c: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 0041071f: mov b1 dl, b1 0x1
         // 00410721: mov eax, ds:[0x410090]
      [-]ffff33c05a595964891068
         // 00410730: xor eax, eax
         // 00410732: pop edx
         // 00410733: pop ecx
         // 00410734: pop ecx
         // 00410735: mov fs:[eax], edx
         // 00410738: push 0x41074d
      [-]8d45fce8
         // 0041073d: lea eax, ss:[ebp+0xfffffffffffffffc]
         // 00410740: call @System@@LStrClr$qqrpv
      [-]50e8e6ffffff58c3
         // 004109fc: push eax
         // 004109fd: call @Variants@@VarClear$qqrr8TVarData
         // 00410a02: pop eax
         // 00410a03: retn 
      [-]558bec6a00538bd833c05568
         // 004111ac: push ebp
         // 004111ad: mov ebp, esp
         // 004111af: push 0x0
         // 004111b1: push ebx
         // 004111b2: mov ebx, eax
         // 004111b4: xor eax, eax
         // 004111b6: push ebp
         // 004111b7: push 0x4111ea
      [-]64ff306489208d45fce82e3c00008bc38b55fce8943f000033c05a595964891068
         // 004111bc: push fs:[eax]
         // 004111bf: mov fs:[eax], esp
         // 004111c2: lea eax, ss:[ebp+0xfffffffffffffffc]
         // 004111c5: call @Variants@@VarToDisp$qqrr36System@%DelphiInterface$t9IDispatch%rx8TVarData
         // 004111ca: mov eax, ebx
         // 004111cc: mov edx, ss:[ebp+0xfffffffffffffffc]
         // 004111cf: call @Variants@@VarFromDisp$qqrr8TVarDatax36System@%DelphiInterface$t9IDispatch%
         // 004111d4: xor eax, eax
         // 004111d6: pop edx
         // 004111d7: pop ecx
         // 004111d8: pop ecx
         // 004111d9: mov fs:[eax], edx
         // 004111dc: push 0x4111f1
      [-]8d45fce8
         // 004111e1: lea eax, ss:[ebp+0xfffffffffffffffc]
         // 004111e4: call @System@@IntfClear$qqrr45System@%DelphiInterface$t17System@IInterface%
      [-]5b595dc3
         // 004111f1: pop ebx
         // 004111f2: pop ecx
         // 004111f3: pop ebp
         // 004111f4: retn 
      [-]558bec6a00538bd833c05568
         // 004111f8: push ebp
         // 004111f9: mov ebp, esp
         // 004111fb: push 0x0
         // 004111fd: push ebx
         // 004111fe: mov ebx, eax
         // 00411200: xor eax, eax
         // 00411202: push ebp
         // 00411203: push 0x411236
      [-]64ff306489208d45fce8163b00008bc38b55fce81c3f000033c05a595964891068
         // 00411208: push fs:[eax]
         // 0041120b: mov fs:[eax], esp
         // 0041120e: lea eax, ss:[ebp+0xfffffffffffffffc]
         // 00411211: call @Variants@@VarToIntf$qqrr45System@%DelphiInterface$t17System@IInterface%rx8TVarData
         // 00411216: mov eax, ebx
         // 00411218: mov edx, ss:[ebp+0xfffffffffffffffc]
         // 0041121b: call @Variants@@VarFromIntf$qqrr8TVarDatax45System@%DelphiInterface$t17System@IInterface%
         // 00411220: xor eax, eax
         // 00411222: pop edx
         // 00411223: pop ecx
         // 00411224: pop ecx
         // 00411225: mov fs:[eax], edx
         // 00411228: push 0x41123d
      [-]8d45fce8
         // 0041122d: lea eax, ss:[ebp+0xfffffffffffffffc]
         // 00411230: call @System@@IntfClear$qqrr45System@%DelphiInterface$t17System@IInterface%
      [-]53ffffc3
         // 00411235: retn 
      [-]5b595dc3
         // 0041123d: pop ebx
         // 0041123e: pop ecx
         // 0041123f: pop ebp
         // 00411240: retn 
      [-]558becb9
         // 0041402c: push ebp
         // 0041402d: mov ebp, esp
         // 0041402f: mov ecx, 0xf
      [-]6a006a004975f9
         // 00414034: push 0x0
         // 00414036: push 0x0
         // 00414038: dec ecx
         // 00414039: jnz 0x414034
      [-]8bda8bf033c05568
         // 0041403d: mov ebx, edx
         // 0041403f: mov esi, eax
         // 00414041: xor eax, eax
         // 00414043: push ebp
         // 00414044: push 0x414563
      [-]0fb7d083fa140f87
         // 00414052: movzx edx, b2 ax
         // 00414055: cmp edx, 0x14
         // 00414058: ja def_41405E
      [-]490000740d
         // 004140cc: jz 0x4140db
      [-]66ba000166b80100e8
         // 004140ce: mov b2 dx, b2 0x100
         // 004140d2: mov b2 ax, b2 0x1
         // 004140d6: call 0x4101b0
      [-]8bc68b15
         // 004140db: mov eax, esi
         // 004140dd: mov edx, ds:[0x49b34c]
      [-]8d55fc0fbf4308e8
         // 004140ed: lea edx, ss:[ebp+0xfffffffffffffffc]
         // 004140f0: movsx eax, b2 ds:[ebx+0x8]
         // 004140f4: call @Sysutils@IntToStr$qqri
      [-]ffff8b55fc8bc6e8
         // 004140f9: mov edx, ss:[ebp+0xfffffffffffffffc]
         // 004140fc: mov eax, esi
         // 004140fe: call @System@@LStrAsg$qqrpvpxv
      [-]8d55f88b4308e8
         // 00414108: lea edx, ss:[ebp+0xfffffffffffffff8]
         // 0041410b: mov eax, ds:[ebx+0x8]
         // 0041410e: call @Sysutils@IntToStr$qqri
      [-]ffff8b55f88bc6e8
         // 00414113: mov edx, ss:[ebp+0xfffffffffffffff8]
         // 00414116: mov eax, esi
         // 00414118: call @System@@LStrAsg$qqrpvpxv
      [-]d9430883c4f4db3c249b8d45f4e8
         // 00414122: fld ds:[ebx+0x8]
         // 00414125: add esp, 0xfffffffffffffff4
         // 00414128: fstp b10 ss:[esp]
         // 0041412b: wait 
         // 0041412c: lea eax, ss:[ebp+0xfffffffffffffff4]
         // 0041412f: call @Sysutils@FloatToStr$qqrg
      [-]ffff8b55f48bc6e8
         // 00414134: mov edx, ss:[ebp+0xfffffffffffffff4]
         // 00414137: mov eax, esi
         // 00414139: call @System@@LStrAsg$qqrpvpxv
      [-]dd430883c4f4db3c249b8d45f0e8
         // 00414143: fld b8 ds:[ebx+0x8]
         // 00414146: add esp, 0xfffffffffffffff4
         // 00414149: fstp b10 ss:[esp]
         // 0041414c: wait 
         // 0041414d: lea eax, ss:[ebp+0xfffffffffffffff0]
         // 00414150: call @Sysutils@FloatToStr$qqrg
      [-]ffff8b55f08bc6e8
         // 00414155: mov edx, ss:[ebp+0xfffffffffffffff0]
         // 00414158: mov eax, esi
         // 0041415a: call @System@@LStrAsg$qqrpvpxv
      [-]ff730cff73088d45ece8
         // 00414164: push ds:[ebx+0xc]
         // 00414167: push ds:[ebx+0x8]
         // 0041416a: lea eax, ss:[ebp+0xffffffffffffffec]
         // 0041416d: call 0x413d44
      [-]fbffff8b55ec8bc6e8
         // 00414172: mov edx, ss:[ebp+0xffffffffffffffec]
         // 00414175: mov eax, esi
         // 00414177: call @System@@LStrFromWStr$qqrr17System@AnsiStringx17System@WideString
      [-]ff730cff73088d45e8e8
         // 00414181: push ds:[ebx+0xc]
         // 00414184: push ds:[ebx+0x8]
         // 00414187: lea eax, ss:[ebp+0xffffffffffffffe8]
         // 0041418a: call 0x413d7c
      [-]fbffff8b55e88bc6e8
         // 0041418f: mov edx, ss:[ebp+0xffffffffffffffe8]
         // 00414192: mov eax, esi
         // 00414194: call @System@@LStrFromWStr$qqrr17System@AnsiStringx17System@WideString
      [-]8d45e450
         // 0041419e: lea eax, ss:[ebp+0xffffffffffffffe4]
         // 004141a1: push eax
      [-]b9????????ba????????e8
         // 004141b0: mov ecx, 0x7fffffff
         // 004141b5: mov edx, 0x1
         // 004141ba: call @System@@WStrCopy$qqrx17System@WideStringii
      [-]ffff8b55e48bc6e8
         // 004141bf: mov edx, ss:[ebp+0xffffffffffffffe4]
         // 004141c2: mov eax, esi
         // 004141c4: call @System@@LStrFromWStr$qqrr17System@AnsiStringx17System@WideString
      [-]fbffff8b55
         // 004141da: mov edx, ss:[ebp+0xffffffffffffffdc]
      [-]0fbe4308e8
         // 004141ec: movsx eax, b1 ds:[ebx+0x8]
         // 004141f0: call @Sysutils@IntToStr$qqri
      [-]ffff8b55
         // 004141f5: mov edx, ss:[ebp+0xffffffffffffffd8]
      [-]52ffff8b55
         // 0041422c: mov edx, ss:[ebp+0xffffffffffffffd0]
      [-]8b430833d252508d45
         // 0041423b: mov eax, ds:[ebx+0x8]
         // 0041423e: xor edx, edx
         // 00414240: push edx
         // 00414241: push eax
         // 00414242: lea eax, ss:[ebp+0xffffffffffffffcc]
      [-]ffff8b55
         // 0041424a: mov edx, ss:[ebp+0xffffffffffffffcc]
      [-]ffffe9bb020000
         // 00414254: jmp 0x414514
      [-]ffff8b55c88bc6e8
         // 00414c9e: mov edx, ss:[ebp+0xffffffffffffffc8]
         // 00414ca1: mov eax, esi
         // 00414ca3: call 0x405584
      [-]8bd06681ea00017407
         // 004142a0: mov edx, eax
         // 004142a2: sub b2 dx, b2 0x100
         // 004142a7: jz 0x4142b0
      [-]66ffca7411
         // 004142a9: dec b2 dx
         // 004142ac: jz 0x4142bf
      [-]f6c4400f840b020000
         // 004142d8: test b1 ah, b1 0x40
         // 004142db: jz 0x4144ec
      [-]0fb7c025????????83f8140f87e4010000
         // 004142e1: movzx eax, b2 ax
         // 004142e4: and eax, 0xffffffffffffbfff
         // 004142e9: cmp eax, 0x14
         // 004142ec: ja def_4142F2
      [-]8b43080fbf00e8
         // 00414350: mov eax, ds:[ebx+0x8]
         // 00414353: movsx eax, b2 ds:[eax]
         // 00414356: call @Sysutils@IntToStr$qqri
      [-]ffff8b55
         // 0041435b: mov edx, ss:[ebp+0xffffffffffffffbc]
      [-]ffffe9aa010000
         // 00414365: jmp 0x414514
      [-]8b43088b00e8
         // 0041436d: mov eax, ds:[ebx+0x8]
         // 00414370: mov eax, ds:[eax]
         // 00414372: call @Sysutils@IntToStr$qqri
      [-]ffff8b55
         // 00414377: mov edx, ss:[ebp+0xffffffffffffffb8]
      [-]ffffe98e010000
         // 00414381: jmp 0x414514
      [-]8b4308d90083c4f4db3c249b8d45
         // 00414386: mov eax, ds:[ebx+0x8]
         // 00414389: fld ds:[eax]
         // 0041438b: add esp, 0xfffffffffffffff4
         // 0041438e: fstp b10 ss:[esp]
         // 00414391: wait 
         // 00414392: lea eax, ss:[ebp+0xffffffffffffffb4]
      [-]69ffff8b55
         // 0041439a: mov edx, ss:[ebp+0xffffffffffffffb4]
      [-]ffffe96b010000
         // 004143a4: jmp 0x414514
      [-]8b4308dd0083c4f4db3c249b8d45
         // 004143a9: mov eax, ds:[ebx+0x8]
         // 004143ac: fld b8 ds:[eax]
         // 004143ae: add esp, 0xfffffffffffffff4
         // 004143b1: fstp b10 ss:[esp]
         // 004143b4: wait 
         // 004143b5: lea eax, ss:[ebp+0xffffffffffffffb0]
      [-]69ffff8b55
         // 004143bd: mov edx, ss:[ebp+0xffffffffffffffb0]
      [-]ffffe948010000
         // 004143c7: jmp 0x414514
      [-]8b4308ff7004ff308d45
         // 004143cc: mov eax, ds:[ebx+0x8]
         // 004143cf: push ds:[eax+0x4]
         // 004143d2: push ds:[eax]
         // 004143d4: lea eax, ss:[ebp+0xffffffffffffffac]
      [-]f9ffff8b55
         // 004143dc: mov edx, ss:[ebp+0xffffffffffffffac]
      [-]ffffe929010000
         // 004143e6: jmp 0x414514
      [-]8b4308ff7004ff308d45
         // 004143eb: mov eax, ds:[ebx+0x8]
         // 004143ee: push ds:[eax+0x4]
         // 004143f1: push ds:[eax]
         // 004143f3: lea eax, ss:[ebp+0xffffffffffffffa8]
      [-]f9ffff8b55
         // 004143fb: mov edx, ss:[ebp+0xffffffffffffffa8]
      [-]ffffe90a010000
         // 00414405: jmp 0x414514
      [-]8bc68b53088b12e8
         // 0041440a: mov eax, esi
         // 0041440c: mov edx, ds:[ebx+0x8]
         // 0041440f: mov edx, ds:[edx]
         // 00414411: call 0x404be8
      [-]ffffe9f9000000
         // 00414416: jmp 0x414514
      [-]f9ffff8b55
         // 00414429: mov edx, ss:[ebp+0xffffffffffffffa4]
      [-]ffffe9dc000000
         // 00414433: jmp 0x414514
      [-]8b43080fbe00e8
         // 0041443b: mov eax, ds:[ebx+0x8]
         // 0041443e: movsx eax, b1 ds:[eax]
         // 00414441: call @Sysutils@IntToStr$qqri
      [-]ffff8b55
         // 00414446: mov edx, ss:[ebp+0xffffffffffffffa0]
      [-]ffffe9bf000000
         // 00414450: jmp 0x414514
      [-]8b43080fb600e8
         // 00414458: mov eax, ds:[ebx+0x8]
         // 0041445b: movzx eax, b1 ds:[eax]
         // 0041445e: call @Sysutils@IntToStr$qqri
      [-]ffff8b55
         // 00414463: mov edx, ss:[ebp+0xffffffffffffff9c]
      [-]ffffe9a2000000
         // 0041446d: jmp 0x414514
      [-]8b43080fb700e8
         // 00414475: mov eax, ds:[ebx+0x8]
         // 00414478: movzx eax, b2 ds:[eax]
         // 0041447b: call @Sysutils@IntToStr$qqri
      [-]ffff8b55
         // 00414480: mov edx, ss:[ebp+0xffffffffffffff98]
      [-]ffffe985000000
         // 0041448a: jmp 0x414514
      [-]8b43088b0033d252508d45
         // 0041448f: mov eax, ds:[ebx+0x8]
         // 00414492: mov eax, ds:[eax]
         // 00414494: xor edx, edx
         // 00414496: push edx
         // 00414497: push eax
         // 00414498: lea eax, ss:[ebp+0xffffffffffffff94]
      [-]ffff8b55
         // 004144a0: mov edx, ss:[ebp+0xffffffffffffff94]
      [-]ffffeb68
         // 004144aa: jmp 0x414514
      [-]8b4308ff7004ff308d45
         // 004144ac: mov eax, ds:[ebx+0x8]
         // 004144af: push ds:[eax+0x4]
         // 004144b2: push ds:[eax]
         // 004144b4: lea eax, ss:[ebp+0xffffffffffffff90]
      [-]ffff8b55
         // 004144bc: mov edx, ss:[ebp+0xffffffffffffff90]
      [-]ffffeb4c
         // 004144c6: jmp 0x414514
      [-]8b43088bd08bc6e8
         // 004144c8: mov eax, ds:[ebx+0x8]
         // 004144cb: mov edx, eax
         // 004144cd: mov eax, esi
         // 004144cf: call 0x41402c
      [-]fbffffeb3e
         // 004144d4: jmp 0x414514
      [-]f9ffff8b55
         // 004144e0: mov edx, ss:[ebp+0xffffffffffffff8c]
      [-]ffffeb28
         // 004144ea: jmp 0x414514
      [-]ffff8bd08bc3e8
         // 004144f3: mov edx, eax
         // 004144f5: mov eax, ebx
         // 004144f7: call @Variants@_16531
      [-]faffff84c07514
         // 004144fc: test b1 al, b1 al
         // 004144fe: jnz 0x414514
      [-]f9ffff8b55
         // 0041450a: mov edx, ss:[ebp+0xffffffffffffff88]
      [-]33c05a595964891068
         // 00414514: xor eax, eax
         // 00414516: pop edx
         // 00414517: pop ecx
         // 00414518: pop ecx
         // 00414519: mov fs:[eax], edx
         // 0041451c: push 0x41456a
      [-]ba????????e8
         // 00414524: mov edx, 0x7
         // 00414529: call @System@@LStrArrayClr$qqrpvi
      [-]ffff8d45
         // 0041452e: lea eax, ss:[ebp+0xffffffffffffffa4]
      [-]ba????????e8
         // 00414531: mov edx, 0x3
         // 00414536: call @System@@WStrArrayClr$qqrpvi
      [-]ffff8d45
         // 0041453b: lea eax, ss:[ebp+0xffffffffffffffb0]
      [-]ba????????e8
         // 0041453e: mov edx, 0xb
         // 00414543: call @System@@LStrArrayClr$qqrpvi
      [-]ffff8d45
         // 00414548: lea eax, ss:[ebp+0xffffffffffffffdc]
      [-]ffff8d45f0ba????????e8
         // 00414555: lea eax, ss:[ebp+0xfffffffffffffff0]
         // 00414558: mov edx, 0x4
         // 0041455d: call @System@@LStrArrayClr$qqrpvi
      [-]5e5b8be55dc3
         // 0041456a: pop esi
         // 0041456b: pop ebx
         // 0041456c: mov esp, ebp
         // 0041456e: pop ebp
         // 0041456f: retn 
      [-]558becb9????????
         // 00414754: push ebp
         // 00414755: mov ebp, esp
         // 00414757: mov ecx, 0xe
      [-]6a006a004975f9
         // 0041475c: push 0x0
         // 0041475e: push 0x0
         // 00414760: dec ecx
         // 00414761: jnz 0x41475c
      [-]8bda8bf033c05568
         // 00414766: mov ebx, edx
         // 00414768: mov esi, eax
         // 0041476a: xor eax, eax
         // 0041476c: push ebp
         // 0041476d: push 0x414ca6
      [-]0fb7d083fa140f87
         // 0041477b: movzx edx, b2 ax
         // 0041477e: cmp edx, 0x14
         // 00414781: ja def_414787
      [-]490000740d
         // 004147f5: jz 0x414804
      [-]66ba080066b80100e8
         // 004147f7: mov b2 dx, b2 0x8
         // 004147fb: mov b2 ax, b2 0x1
         // 004147ff: call 0x4101b0
      [-]8bc68b15
         // 00414804: mov eax, esi
         // 00414806: mov edx, ds:[0x49b34c]
      [-]8d55fc0fbf4308e8
         // 00414816: lea edx, ss:[ebp+0xfffffffffffffffc]
         // 00414819: movsx eax, b2 ds:[ebx+0x8]
         // 0041481d: call @Sysutils@IntToStr$qqri
      [-]ffff8b55fc8bc6e8
         // 00414822: mov edx, ss:[ebp+0xfffffffffffffffc]
         // 00414825: mov eax, esi
         // 00414827: call @System@@WStrFromLStr$qqrr17System@WideStringx17System@AnsiString
      [-]8d55f88b4308e8
         // 00414831: lea edx, ss:[ebp+0xfffffffffffffff8]
         // 00414834: mov eax, ds:[ebx+0x8]
         // 00414837: call @Sysutils@IntToStr$qqri
      [-]ffff8b55f88bc6e8
         // 0041483c: mov edx, ss:[ebp+0xfffffffffffffff8]
         // 0041483f: mov eax, esi
         // 00414841: call @System@@WStrFromLStr$qqrr17System@WideStringx17System@AnsiString
      [-]d9430883c4f4db3c249b8d45f4e8
         // 0041484b: fld ds:[ebx+0x8]
         // 0041484e: add esp, 0xfffffffffffffff4
         // 00414851: fstp b10 ss:[esp]
         // 00414854: wait 
         // 00414855: lea eax, ss:[ebp+0xfffffffffffffff4]
         // 00414858: call @Sysutils@FloatToStr$qqrg
      [-]ffff8b55f48bc6e8
         // 0041485d: mov edx, ss:[ebp+0xfffffffffffffff4]
         // 00414860: mov eax, esi
         // 00414862: call @System@@WStrFromLStr$qqrr17System@WideStringx17System@AnsiString
      [-]dd430883c4f4db3c249b8d45f0e8
         // 0041486c: fld b8 ds:[ebx+0x8]
         // 0041486f: add esp, 0xfffffffffffffff4
         // 00414872: fstp b10 ss:[esp]
         // 00414875: wait 
         // 00414876: lea eax, ss:[ebp+0xfffffffffffffff0]
         // 00414879: call @Sysutils@FloatToStr$qqrg
      [-]ffff8b55f08bc6e8
         // 0041487e: mov edx, ss:[ebp+0xfffffffffffffff0]
         // 00414881: mov eax, esi
         // 00414883: call @System@@WStrFromLStr$qqrr17System@WideStringx17System@AnsiString
      [-]ff730cff73088d45ece8
         // 0041488d: push ds:[ebx+0xc]
         // 00414890: push ds:[ebx+0x8]
         // 00414893: lea eax, ss:[ebp+0xffffffffffffffec]
         // 00414896: call 0x413d44
      [-]f4ffff8b55ec8bc6e8
         // 0041489b: mov edx, ss:[ebp+0xffffffffffffffec]
         // 0041489e: mov eax, esi
         // 004148a0: call @System@@WStrAsg$qqrr17System@WideStringx17System@WideString
      [-]ff730cff73088d45e8e8
         // 004148aa: push ds:[ebx+0xc]
         // 004148ad: push ds:[ebx+0x8]
         // 004148b0: lea eax, ss:[ebp+0xffffffffffffffe8]
         // 004148b3: call 0x413d7c
      [-]f4ffff8b55e88bc6e8
         // 004148b8: mov edx, ss:[ebp+0xffffffffffffffe8]
         // 004148bb: mov eax, esi
         // 004148bd: call @System@@WStrAsg$qqrr17System@WideStringx17System@WideString
      [-]b9????????ba????????e8
         // 004152da: mov ecx, 0x7fffffff
         // 004152df: mov edx, 0x1
         // 004152e4: call 0x405f58
      [-]f4ffff8b55
         // 004148f6: mov edx, ss:[ebp+0xffffffffffffffe0]
      [-]0fbe4308e8
         // 00414908: movsx eax, b1 ds:[ebx+0x8]
         // 0041490c: call @Sysutils@IntToStr$qqri
      [-]ffff8b55
         // 00414911: mov edx, ss:[ebp+0xffffffffffffffdc]
      [-]ffff8b55
         // 00414948: mov edx, ss:[ebp+0xffffffffffffffd4]
      [-]8b430833d252508d45
         // 00414957: mov eax, ds:[ebx+0x8]
         // 0041495a: xor edx, edx
         // 0041495c: push edx
         // 0041495d: push eax
         // 0041495e: lea eax, ss:[ebp+0xffffffffffffffd0]
      [-]ffff8b55
         // 00414966: mov edx, ss:[ebp+0xffffffffffffffd0]
      [-]ffffe9bb020000
         // 00414970: jmp 0x414c30
      [-]ffff8b55cc8bc6e8
         // 004153b0: mov edx, ss:[ebp+0xffffffffffffffcc]
         // 004153b3: mov eax, esi
         // 004153b5: call 0x405d64
      [-]8bd06681ea00017407
         // 004149bc: mov edx, eax
         // 004149be: sub b2 dx, b2 0x100
         // 004149c3: jz 0x4149cc
      [-]66ffca7411
         // 004149c5: dec b2 dx
         // 004149c8: jz 0x4149db
      [-]f6c4400f840b020000
         // 004149f4: test b1 ah, b1 0x40
         // 004149f7: jz 0x414c08
      [-]0fb7c025????????83f8140f87e4010000
         // 004149fd: movzx eax, b2 ax
         // 00414a00: and eax, 0xffffffffffffbfff
         // 00414a05: cmp eax, 0x14
         // 00414a08: ja def_414A0E
      [-]8b43080fbf00e8
         // 00414a6c: mov eax, ds:[ebx+0x8]
         // 00414a6f: movsx eax, b2 ds:[eax]
         // 00414a72: call @Sysutils@IntToStr$qqri
      [-]ffff8b55
         // 00414a77: mov edx, ss:[ebp+0xffffffffffffffc0]
      [-]ffffe9aa010000
         // 00414a81: jmp 0x414c30
      [-]8b43088b00e8
         // 00414a89: mov eax, ds:[ebx+0x8]
         // 00414a8c: mov eax, ds:[eax]
         // 00414a8e: call @Sysutils@IntToStr$qqri
      [-]ffff8b55
         // 00414a93: mov edx, ss:[ebp+0xffffffffffffffbc]
      [-]ffffe98e010000
         // 00414a9d: jmp 0x414c30
      [-]8b4308d90083c4f4db3c249b8d45
         // 00414aa2: mov eax, ds:[ebx+0x8]
         // 00414aa5: fld ds:[eax]
         // 00414aa7: add esp, 0xfffffffffffffff4
         // 00414aaa: fstp b10 ss:[esp]
         // 00414aad: wait 
         // 00414aae: lea eax, ss:[ebp+0xffffffffffffffb8]
      [-]62ffff8b55
         // 00414ab6: mov edx, ss:[ebp+0xffffffffffffffb8]
      [-]ffffe96b010000
         // 00414ac0: jmp 0x414c30
      [-]8b4308dd0083c4f4db3c249b8d45
         // 00414ac5: mov eax, ds:[ebx+0x8]
         // 00414ac8: fld b8 ds:[eax]
         // 00414aca: add esp, 0xfffffffffffffff4
         // 00414acd: fstp b10 ss:[esp]
         // 00414ad0: wait 
         // 00414ad1: lea eax, ss:[ebp+0xffffffffffffffb4]

  }
  condition:
    all of them
}
