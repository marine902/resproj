rule darkkomet_10_4 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         84db750d
         // 00402888: test b1 bl, b1 bl
         // 0040288a: jnz 0x402899
      [-]80fb18770a
         // 00402899: cmp b1 bl, b1 0x18
         // 0040289c: ja 0x4028a8
      [-]e903000000
         // 00403738: jmp @System@@Pow10$qqrv
      [-]0f849a000000
         // 00403747: jz 0x4037e7
      [-]3d????????0f8d81000000
         // 0040374d: cmp eax, 0x1400
         // 00403752: jge 0x4037d9
      [-]83e21f8d1492dbac53
         // 00404146: and edx, 0x1f
         // 00404149: lea edx, ds:[edx+edx*0x4]
         // 0040414c: fld b10 ds:[ebx+edx*0x2]
      [-]4000dec9c1e8057479
         // 00404153: fmulp b8 st(1), b10 st(0)
         // 00404155: shr eax, b1 0x5
         // 00404158: jz 0x4041d3
      [-]83e20f740c
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
      [-]83e21f8d1492dbac53
         // 0040418b: and edx, 0x1f
         // 0040418e: lea edx, ds:[edx+edx*0x4]
         // 00404191: fld b10 ds:[ebx+edx*0x2]
      [-]4000def9c1e8057434
         // 00404198: fdivp b8 st(1), b10 st(0)
         // 0040419a: shr eax, b1 0x5
         // 0040419d: jz 0x4041d3
      [-]83e20f740c
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
      [-]8b4424048b480ceb30
         // 00404107: mov eax, ss:[esp+0x4]
         // 0040410b: mov ecx, ds:[eax+0xc]
         // 0040410e: jmp 0x404140
      [-]8b4424048b480c
         // 00404112: mov eax, ss:[esp+0x4]
         // 00404116: mov ecx, ds:[eax+0xc]
      [-]490001761e
         // 00404120: jbe 0x404140
      [-]4900007715
         // 00404129: ja 0x404140
      [-]e9e9ffffff
         // 00404936: jmp 0x404924
      [-]8b4af8497432
         // 00404e92: mov ecx, ds:[edx+0xfffffffffffffff8]
         // 00404e95: dec ecx
         // 00404e96: jz 0x404eca
      [-]8b42fce8
         // 004059ff: mov eax, ds:[edx+0xfffffffffffffffc]
         // 00405a02: call 0x4055f4
      [-]8b038913508b48fce8
         // 00405a09: mov eax, ds:[ebx]
         // 00405a0b: mov ds:[ebx], edx
         // 00405a0d: push eax
         // 00405a0e: mov ecx, ds:[eax+0xfffffffffffffffc]
         // 00405a11: call 0x4030fc
      [-]ffff588b48f8497c0e
         // 00405a16: pop eax
         // 00405a17: mov ecx, ds:[eax+0xfffffffffffffff8]
         // 00405a1a: dec ecx
         // 00405a1b: jl 0x405a2b
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
      [-]50535657
         // 004054d1: push eax
         // 004054d2: push ebx
         // 004054d3: push esi
         // 004054d4: push edi
      [-]8a068a56013c0a7425
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
      [-]5356575583c4ec891424
         // 00405afc: push ebx
         // 00405afd: push esi
         // 00405afe: push edi
         // 00405aff: push ebp
         // 00405b00: add esp, 0xffffffffffffffec
         // 00405b03: mov ss:[esp], edx
      [-]bd????????
         // 00405b08: mov ebp, 0x1
      [-]c74424????????00c74424????????00
         // 00405b0f: mov ss:[esp+0x8], 0x0
         // 00405b17: mov ss:[esp+0xc], 0x0
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
         // 00405bb1: sub edi, 0x30
         // 00405bb4: jmp 0x405bce
      [-]83ef37eb
         // 00405bbe: sub edi, 0x37
         // 00405bc1: jmp 0x405bce
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
      [-]9952508b4424108b5424140fa4c204c1e0040304241354240483c408894424088954240c45
         // 0040663e: cdq 
         // 0040663f: push edx
         // 00406640: push eax
         // 00406641: mov eax, ss:[esp+0x10]
         // 00406645: mov edx, ss:[esp+0x14]
         // 00406649: shld edx, eax, b1 0x4
         // 0040664d: shl eax, b1 0x4
         // 00406650: add eax, ss:[esp]
         // 00406653: adc edx, ss:[esp+0x4]
         // 00406657: add esp, 0x8
         // 0040665a: mov ss:[esp+0x8], eax
         // 0040665e: mov ss:[esp+0xc], edx
         // 00406662: inc ebp
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
      [-]7c240c007509
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
      [-]fdffff5250
         // 00405c9e: push edx
         // 00405c9f: push eax
      [-]990304241354240483c408894424088954240c45
         // 00405ca2: cdq 
         // 00405ca3: add eax, ss:[esp]
         // 00405ca6: adc edx, ss:[esp+0x4]
         // 00405caa: add esp, 0x8
         // 00405cad: mov ss:[esp+0x8], eax
         // 00405cb1: mov ss:[esp+0xc], edx
         // 00405cb5: inc ebp
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
      [-]e823000000c3
         // 00406448: call @System@RemoveModuleUnloadProc$qqrpqqrui$v
         // 0040644d: retn 
      [-]506a40e8e0ffffffc3
         // 00406c84: push eax
         // 00406c85: push 0x40
         // 00406c87: call LocalAlloc_0
         // 00406c8c: retn 
      [-]ffff5bc3
         // 0040976a: pop ebx
         // 0040976b: retn 
      [-]ffff5f5e5bc3
         // 00408c9a: pop edi
         // 00408c9b: pop esi
         // 00408c9c: pop ebx
         // 00408c9d: retn 
      [-]53565751
         // 0040a1f0: push ebx
         // 0040a1f1: push esi
         // 0040a1f2: push edi
         // 0040a1f3: push ecx
      [-]6a008d44240450575653e8
         // 0040a1fa: push 0x0
         // 0040a1fc: lea eax, ss:[esp+0x4]
         // 0040a200: push eax
         // 0040a201: push edi
         // 0040a202: push esi
         // 0040a203: push ebx
         // 0040a204: call WriteFile_0
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
      [-]e85effffff
         // 0040a918: call 0x40a87b
      [-]8b550883fa127205
         // 0040a91d: mov edx, ss:[ebp+0x8]
         // 0040a920: cmp edx, 0x12
         // 0040a923: jb 0x40a92a
      [-]0fbf4dd4
         // 0040a92a: movsx ecx, b2 ss:[ebp+0xffffffffffffffd4]
      [-]b030aaeb2a
         // 0040a932: mov b1 al, b1 0x30
         // 0040a934: stosbb 
         // 0040a935: jmp 0x40a961
      [-]807d1002740a
         // 0040a939: cmp b1 ss:[ebp+0x10], b1 0x2
         // 0040a93d: jz 0x40a949
      [-]48b303f6f388e343
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
      [-]807dd6007408
         // 0040a98c: cmp b1 ss:[ebp+0xffffffffffffffd6], b1 0x0
         // 0040a990: jz 0x40a99a
      [-]8a5df2b9????????
         // 0040a992: mov b1 bl, b1 ss:[ebp+0xfffffffffffffff2]
         // 0040a995: mov ecx, 0x40f
      [-]38cb7602
         // 0040a99a: cmp b1 bl, b1 cl
         // 0040a99c: jbe 0x40a9a0
      [-]00eb8d9c9b
         // 0040a9a0: add b1 bl, b1 ch
         // 0040a9a2: lea ebx, ds:[ebx+ebx*0x4]
      [-]4000035dec
         // 0040a9a9: add ebx, ss:[ebp+0xffffffffffffffec]
      [-]8a033c40741e
         // 0040a9b1: mov b1 al, b1 ds:[ebx]
         // 0040a9b3: cmp b1 al, b1 0x40
         // 0040a9b5: jz 0x40a9d5
      [-]51533c247407
         // 0040a9b7: push ecx
         // 0040a9b8: push ebx
         // 0040a9b9: cmp b1 al, b1 0x24
         // 0040a9bb: jz 0x40a9c4
      [-]3c2a740a
         // 0040a9bd: cmp b1 al, b1 0x2a
         // 0040a9bf: jz 0x40a9cb
      [-]e80d000000eb05
         // 0040a9c4: call 0x40a9d6
         // 0040a9c9: jmp 0x40a9d0
      [-]e84dffffff
         // 0040a9cb: call 0x40a91d
      [-]5b5943e2dc
         // 0040a9d0: pop ebx
         // 0040a9d1: pop ecx
         // 0040a9d2: inc ebx
         // 0040a9d3: loop 0x40a9b1
      [-]568b75f4
         // 0040a9d6: push esi
         // 0040a9d7: mov esi, ss:[ebp+0xfffffffffffffff4]
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
      [-]2500008b
         // 0040b7a1: mov eax, ss:[ebp+0xfffffffffffffffc]
      [-]fbffff598b
         // 0040b7a9: pop ecx
         // 0040b7aa: mov eax, ss:[ebp+0xfffffffffffffffc]
      [-]25000089
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
      [-]8b4508500fb745f2
         // 0040c2b5: mov eax, ss:[ebp+0x8]
         // 0040c2b8: push eax
         // 0040c2b9: movzx eax, b2 ss:[ebp+0xfffffffffffffff2]
      [-]ffff59e9bd050000
         // 0040c2d2: pop ecx
         // 0040c2d3: jmp 0x40c895
      [-]8b4508500fb745f2
         // 0040c2d8: mov eax, ss:[ebp+0x8]
         // 0040c2db: push eax
         // 0040c2dc: movzx eax, b2 ss:[ebp+0xfffffffffffffff2]
      [-]faffff59e9a5050000
         // 0040c2ea: pop ecx
         // 0040c2eb: jmp 0x40c895
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
      [-]ffff598b45f448
         // 0040b93a: pop ecx
         // 0040b93b: mov eax, ss:[ebp+0xfffffffffffffff4]
         // 0040b93e: dec eax
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
      [-]f8ffff5955e8ff
         // 0040bb3f: pop ecx
         // 0040bb40: push ebp
         // 0040bb41: call 0x40b478
      [-]59837df4027e07
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
      [-]66837dea0c7203
         // 0040bc21: cmp b2 ss:[ebp+0xffffffffffffffea], b2 0xc
         // 0040bc26: jb 0x40bc2b
      [-]8b450850
         // 0040c651: mov eax, ss:[ebp+0x8]
         // 0040c654: push eax
      [-]ffff5983
         // 0040c661: pop ecx
         // 0040c662: add ds:[edi], 0x4
      [-]66837dea0c7203
         // 0040bc5e: cmp b2 ss:[ebp+0xffffffffffffffea], b2 0xc
         // 0040bc63: jb 0x40bc68
      [-]8b450850
         // 0040c68d: mov eax, ss:[ebp+0x8]
         // 0040c690: push eax
      [-]f6ffff5983
         // 0040c69d: pop ecx
         // 0040c69e: add ds:[edi], 0x2
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
      [-]8b4508508d45fb
         // 0040c77e: mov eax, ss:[ebp+0x8]
         // 0040c781: push eax
         // 0040c782: lea eax, ss:[ebp+0xfffffffffffffffb]
      [-]f5ffff59e9
         // 0040c78f: pop ecx
         // 0040c790: jmp 0x40c895
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
         // 0040c800: mov eax, ss:[ebp+0x8]
         // 0040c803: push eax
         // 0040c804: mov eax, 0x497811
      [-]f5ffff59
         // 0040c813: pop ecx
      [-]49000074
         // 0040bdff: jz 0x40be78
      [-]8b450850b8
         // 0040be01: mov eax, ss:[ebp+0x8]
         // 0040be04: push eax
         // 0040be05: mov eax, 0x49e698
      [-]f5ffff59eb
         // 0040be14: pop ecx
         // 0040be15: jmp 0x40be78
      [-]3a45fb75
         // 0040be43: cmp b1 al, b1 ss:[ebp+0xfffffffffffffffb]
         // 0040be46: jnz 0x40be1c
      [-]8b4508508b
         // 0040be48: mov eax, ss:[ebp+0x8]
         // 0040be4b: push eax
         // 0040be4c: mov edx, ss:[ebp+0xfffffffffffffffc]
      [-]ffff598b
         // 0040be58: pop ecx
         // 0040be59: mov eax, ss:[ebp+0xfffffffffffffffc]
      [-]80380074
         // 0040be5c: cmp b1 ds:[eax], b1 0x0
         // 0040be5f: jz 0x40be78
      [-]8b4508508d45fb
         // 0040c883: mov eax, ss:[ebp+0x8]
         // 0040c886: push eax
         // 0040c887: lea eax, ss:[ebp+0xfffffffffffffffb]
      [-]f4ffff59
         // 0040c894: pop ecx
      [-]8b4508ff88????????
         // 0040be85: mov eax, ss:[ebp+0x8]
         // 0040be88: dec ds:[eax+0xfffffffffffffef8]
      [-]5a595964891068
         // 0040be90: pop edx
         // 0040be91: pop ecx
         // 0040be92: pop ecx
         // 0040be93: mov fs:[eax], edx
         // 0040be96: push 0x40beb0
      [-]558bec81c4????????5356
         // 0040df54: push ebp
         // 0040df55: mov ebp, esp
         // 0040df57: add esp, 0xfffffffffffffe90
         // 0040df5d: push ebx
         // 0040df5e: push esi
      [-]8985????????8985????????8985????????8985????????8945fc
         // 0040df61: mov ss:[ebp+0xfffffffffffffe90], eax
         // 0040df67: mov ss:[ebp+0xfffffffffffffeb4], eax
         // 0040df6d: mov ss:[ebp+0xfffffffffffffeac], eax
         // 0040df73: mov ss:[ebp+0xfffffffffffffeb0], eax
         // 0040df79: mov ss:[ebp+0xfffffffffffffffc], eax
      [-]64ff306489208b45088b58fc837b1400750f
         // 0040df84: push fs:[eax]
         // 0040df87: mov fs:[eax], esp
         // 0040df8a: mov eax, ss:[ebp+0x8]
         // 0040df8d: mov ebx, ds:[eax+0xfffffffffffffffc]
         // 0040df90: cmp ds:[ebx+0x14], 0x0
         // 0040df94: jnz 0x40dfa5
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
      [-]0f8496000000
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
      [-]5a595964891068
         // 0040d72c: pop edx
         // 0040d72d: pop ecx
         // 0040d72e: pop ecx
         // 0040d72f: mov fs:[eax], edx
         // 0040d732: push 0x40d762
      [-]8d85????????e8
         // 0040d737: lea eax, ss:[ebp+0xfffffffffffffe90]
         // 0040d73d: call @System@@LStrClr$qqrpv
      [-]ffff8d85????????
         // 0040d742: lea eax, ss:[ebp+0xfffffffffffffeac]
      [-]ffff8d45fce8
         // 0040d752: lea eax, ss:[ebp+0xfffffffffffffffc]
         // 0040d755: call @System@@LStrClr$qqrpv
      [-]49000074
         // 0040e78a: jz 0x40e7ac
      [-]ffff03c648e8
         // 0040e7a4: add eax, esi
         // 0040e7a6: dec eax
         // 0040e7a7: call 0x40e750
      [-]8d4301803d
         // 0040e7b6: lea eax, ds:[ebx+0x1]
         // 0040e7b9: cmp b1 ds:[0x4978d4], b1 0x0
      [-]49000074
         // 0040e7c0: jz 0x40e7e4
      [-]ffff03c348e8
         // 0040e7da: add eax, ebx
         // 0040e7dc: dec eax
         // 0040e7dd: call 0x40e750
      [-]ffffff03c3
         // 0040e7e2: add eax, ebx
      [-]92f00fc102c3
         // 0040e900: xchg eax, edx
         // 0040e901: lock xadd ds:[edx], eax
         // 0040e905: retn 
      [-]53565755
         // 0040e908: push ebx
         // 0040e909: push esi
         // 0040e90a: push edi
         // 0040e90b: push ebp
      [-]5356575551891424
         // 0040f5a4: push ebx
         // 0040f5a5: push esi
         // 0040f5a6: push edi
         // 0040f5a7: push ebp
         // 0040f5a8: push ecx
         // 0040f5a9: mov ss:[esp], edx
      [-]6c8704eb03
         // 0040f5c5: jmp 0x40f5ca
      [-]85ed7405
         // 0040e997: test ebp, ebp
         // 0040e999: jz 0x40e9a0
      [-]3b750475f4
         // 0040e99b: cmp esi, ss:[ebp+0x4]
         // 0040e99e: jnz 0x40e994
      [-]0000008be885ed75
         // 0040f5de: mov ebp, eax
         // 0040f5e0: test ebp, ebp
         // 0040f5e2: jnz 0x40f60e
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
      [-]8b5c8304
         // 0040f63a: mov ebx, ds:[ebx+eax*0x4]
      [-]8d4308ba????????e8
         // 0040ea0f: lea eax, ds:[ebx+0x8]
         // 0040ea12: mov edx, 0x7fffffff
         // 0040ea17: call 0x40e8f8
      [-]ffff894304eb06
         // 0040ea28: mov ds:[ebx+0x4], eax
         // 0040ea2b: jmp 0x40ea33
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
         // 0040eb94: mov edx, 0xffffffffffff0001
         // 0040eb99: call 0x40e900
      [-]fdffff3d????????75
         // 0040eb9e: cmp eax, 0xffff
         // 0040eba3: jnz 0x40eb79
      [-]ffffff84db7408
         // 0040f7f0: test b1 bl, b1 bl
         // 0040f7f2: jz 0x40f7fc
      [-]fdffff483b
         // 0040ebc3: dec eax
         // 0040ebc4: cmp eax, ebp
      [-]5a5d5f5e
         // 0040ebce: pop edx
         // 0040ebcf: pop ebp
         // 0040ebd0: pop edi
         // 0040ebd1: pop esi
      [-]558bec6a00538b4518
         // 0040f6a0: push ebp
         // 0040f6a1: mov ebp, esp
         // 0040f6a3: push 0x0
         // 0040f6a5: push ebx
         // 0040f6a6: mov eax, ss:[ebp+0x18]
      [-]64ff30648920817d10????????7407
         // 00410365: push fs:[eax]
         // 00410368: mov fs:[eax], esp
         // 0041036b: cmp ss:[ebp+0x10], 0x400
         // 00410372: jz 0x41037b
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
      [-]5a595964891068
         // 0040f6ec: pop edx
         // 0040f6ed: pop ecx
         // 0040f6ee: pop ecx
         // 0040f6ef: mov fs:[eax], edx
         // 0040f6f2: push 0x40f707
      [-]8d45fce8
         // 0040f6f7: lea eax, ss:[ebp+0xfffffffffffffffc]
         // 0040f6fa: call 0x4049c0
      [-]558bec6a00
         // 00410e04: push ebp
         // 00410e05: mov ebp, esp
         // 00410e07: push 0x0
      [-]64ff306489208d55fca1
         // 00410e11: push fs:[eax]
         // 00410e14: mov fs:[eax], esp
         // 00410e17: lea edx, ss:[ebp+0xfffffffffffffffc]
         // 00410e1a: mov eax, ds:[0x494a98]
      [-]ffff8b4dfcb201a1
         // 00410e24: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 00410e27: mov b1 dl, b1 0x1
         // 00410e29: mov eax, ds:[0x4109ac]
      [-]5a595964891068
         // 00410e3a: pop edx
         // 00410e3b: pop ecx
         // 00410e3c: pop ecx
         // 00410e3d: mov fs:[eax], edx
         // 00410e40: push 0x410e55
      [-]8d45fce8
         // 00410e45: lea eax, ss:[ebp+0xfffffffffffffffc]
         // 00410e48: call 0x405530
      [-]558bec83c4e45356
         // 00410e58: push ebp
         // 00410e59: mov ebp, esp
         // 00410e5b: add esp, 0xffffffffffffffe4
         // 00410e5e: push ebx
         // 00410e5f: push esi
      [-]64ff306489208d55ec
         // 00410e77: push fs:[eax]
         // 00410e7a: mov fs:[eax], esp
         // 00410e7d: lea edx, ss:[ebp+0xffffffffffffffec]
      [-]00008b45ec8945f0c645f40b8d55e8
         // 00410e87: mov eax, ss:[ebp+0xffffffffffffffec]
         // 00410e8a: mov ss:[ebp+0xfffffffffffffff0], eax
         // 00410e8d: mov b1 ss:[ebp+0xfffffffffffffff4], b1 0xb
         // 00410e91: lea edx, ss:[ebp+0xffffffffffffffe8]
      [-]00008b45e88945f8c645fc0b8d45f0506a018d55e4a1
         // 00410e9b: mov eax, ss:[ebp+0xffffffffffffffe8]
         // 00410e9e: mov ss:[ebp+0xfffffffffffffff8], eax
         // 00410ea1: mov b1 ss:[ebp+0xfffffffffffffffc], b1 0xb
         // 00410ea5: lea eax, ss:[ebp+0xfffffffffffffff0]
         // 00410ea8: push eax
         // 00410ea9: push 0x1
         // 00410eab: lea edx, ss:[ebp+0xffffffffffffffe4]
         // 00410eae: mov eax, ds:[0x4947c8]
      [-]ffff8b4de4b201a1
         // 00410eb8: mov ecx, ss:[ebp+0xffffffffffffffe4]
         // 00410ebb: mov b1 dl, b1 0x1
         // 00410ebd: mov eax, ds:[0x4109ac]
      [-]5a595964891068
         // 00410ece: pop edx
         // 00410ecf: pop ecx
         // 00410ed0: pop ecx
         // 00410ed1: mov fs:[eax], edx
         // 00410ed4: push 0x410eee
      [-]558bec6a00
         // 00410ef4: push ebp
         // 00410ef5: mov ebp, esp
         // 00410ef7: push 0x0
      [-]64ff306489208d55fca1
         // 00410f01: push fs:[eax]
         // 00410f04: mov fs:[eax], esp
         // 00410f07: lea edx, ss:[ebp+0xfffffffffffffffc]
         // 00410f0a: mov eax, ds:[0x494a34]
      [-]ffff8b4dfcb201a1
         // 00410f14: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 00410f17: mov b1 dl, b1 0x1
         // 00410f19: mov eax, ds:[0x410948]
      [-]5a595964891068
         // 00410f2a: pop edx
         // 00410f2b: pop ecx
         // 00410f2c: pop ecx
         // 00410f2d: mov fs:[eax], edx
         // 00410f30: push 0x410f45
      [-]8d45fce8
         // 00410f35: lea eax, ss:[ebp+0xfffffffffffffffc]
         // 00410f38: call 0x405530
      [-]558bec83c4e45356
         // 00410f48: push ebp
         // 00410f49: mov ebp, esp
         // 00410f4b: add esp, 0xffffffffffffffe4
         // 00410f4e: push ebx
         // 00410f4f: push esi
      [-]64ff306489208d55ec
         // 00410f67: push fs:[eax]
         // 00410f6a: mov fs:[eax], esp
         // 00410f6d: lea edx, ss:[ebp+0xffffffffffffffec]
      [-]00008b45ec8945f0c645f40b8d55e8
         // 00410f77: mov eax, ss:[ebp+0xffffffffffffffec]
         // 00410f7a: mov ss:[ebp+0xfffffffffffffff0], eax
         // 00410f7d: mov b1 ss:[ebp+0xfffffffffffffff4], b1 0xb
         // 00410f81: lea edx, ss:[ebp+0xffffffffffffffe8]
      [-]00008b45e88945f8c645fc0b8d45f0506a018d55e4a1
         // 00410f8b: mov eax, ss:[ebp+0xffffffffffffffe8]
         // 00410f8e: mov ss:[ebp+0xfffffffffffffff8], eax
         // 00410f91: mov b1 ss:[ebp+0xfffffffffffffffc], b1 0xb
         // 00410f95: lea eax, ss:[ebp+0xfffffffffffffff0]
         // 00410f98: push eax
         // 00410f99: push 0x1
         // 00410f9b: lea edx, ss:[ebp+0xffffffffffffffe4]
         // 00410f9e: mov eax, ds:[0x494b00]
      [-]ffff8b4de4b201a1
         // 00410fa8: mov ecx, ss:[ebp+0xffffffffffffffe4]
         // 00410fab: mov b1 dl, b1 0x1
         // 00410fad: mov eax, ds:[0x410a10]
      [-]5a595964891068
         // 00410fbe: pop edx
         // 00410fbf: pop ecx
         // 00410fc0: pop ecx
         // 00410fc1: mov fs:[eax], edx
         // 00410fc4: push 0x410fde
      [-]558bec6a00
         // 00410fe4: push ebp
         // 00410fe5: mov ebp, esp
         // 00410fe7: push 0x0
      [-]64ff306489208d55fca1
         // 00410ff1: push fs:[eax]
         // 00410ff4: mov fs:[eax], esp
         // 00410ff7: lea edx, ss:[ebp+0xfffffffffffffffc]
         // 00410ffa: mov eax, ds:[0x4949d0]
      [-]ffff8b4dfcb201a1
         // 00411004: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 00411007: mov b1 dl, b1 0x1
         // 00411009: mov eax, ds:[0x410c08]
      [-]5a595964891068
         // 0041101a: pop edx
         // 0041101b: pop ecx
         // 0041101c: pop ecx
         // 0041101d: mov fs:[eax], edx
         // 00411020: push 0x411035
      [-]8d45fce8
         // 00411025: lea eax, ss:[ebp+0xfffffffffffffffc]
         // 00411028: call 0x405530
      [-]45ffffc3
         // 0041102d: retn 
      [-]558bec6a00
         // 00411350: push ebp
         // 00411351: mov ebp, esp
         // 00411353: push 0x0
      [-]64ff306489208d55fca1
         // 0041135d: push fs:[eax]
         // 00411360: mov fs:[eax], esp
         // 00411363: lea edx, ss:[ebp+0xfffffffffffffffc]
         // 00411366: mov eax, ds:[0x4947bc]
      [-]ffff8b4dfcb201a1
         // 00411370: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 00411373: mov b1 dl, b1 0x1
         // 00411375: mov eax, ds:[0x410da0]
      [-]5a595964891068
         // 00411386: pop edx
         // 00411387: pop ecx
         // 00411388: pop ecx
         // 00411389: mov fs:[eax], edx
         // 0041138c: push 0x4113a1
      [-]8d45fce8
         // 00411391: lea eax, ss:[ebp+0xfffffffffffffffc]
         // 00411394: call 0x405530
      [-]50e8e6ffffff58c3
         // 004109fc: push eax
         // 004109fd: call @Variants@@VarClear$qqrr8TVarData
         // 00410a02: pop eax
         // 00410a03: retn 
      [-]558bec6a0053
         // 00411bb0: push ebp
         // 00411bb1: mov ebp, esp
         // 00411bb3: push 0x0
         // 00411bb5: push ebx
      [-]64ff306489208d45fce82e3c00008b
         // 00411bc0: push fs:[eax]
         // 00411bc3: mov fs:[eax], esp
         // 00411bc6: lea eax, ss:[ebp+0xfffffffffffffffc]
         // 00411bc9: call 0x4157fc
         // 00411bd0: mov edx, ss:[ebp+0xfffffffffffffffc]
      [-]55fce8943f0000
         // 00411bd3: call 0x415b6c
      [-]5a595964891068
         // 00411bda: pop edx
         // 00411bdb: pop ecx
         // 00411bdc: pop ecx
         // 00411bdd: mov fs:[eax], edx
         // 00411be0: push 0x411bf5
      [-]8d45fce8
         // 00411be5: lea eax, ss:[ebp+0xfffffffffffffffc]
         // 00411be8: call 0x40700c
      [-]5b595dc3
         // 00411bf5: pop ebx
         // 00411bf6: pop ecx
         // 00411bf7: pop ebp
         // 00411bf8: retn 
      [-]558bec6a0053
         // 00411bfc: push ebp
         // 00411bfd: mov ebp, esp
         // 00411bff: push 0x0
         // 00411c01: push ebx
      [-]64ff306489208d45fce8163b00008b
         // 00411c0c: push fs:[eax]
         // 00411c0f: mov fs:[eax], esp
         // 00411c12: lea eax, ss:[ebp+0xfffffffffffffffc]
         // 00411c15: call 0x415730
         // 00411c1c: mov edx, ss:[ebp+0xfffffffffffffffc]
      [-]55fce81c3f0000
         // 00411c1f: call 0x415b40
      [-]5a595964891068??
         // 00411c26: pop edx
         // 00411c27: pop ecx
         // 00411c28: pop ecx
         // 00411c29: mov fs:[eax], edx
         // 00411c2c: push 0x411c41
      [-]8d45fce8
         // 00411c31: lea eax, ss:[ebp+0xfffffffffffffffc]
         // 00411c34: call 0x40700c
      [-]53ffffc3
         // 00411c39: retn 
      [-]5b595dc3
         // 00411c41: pop ebx
         // 00411c42: pop ecx
         // 00411c43: pop ebp
         // 00411c44: retn 
      [-]6a006a004975f9
         // 00414034: push 0x0
         // 00414036: push 0x0
         // 00414038: dec ecx
         // 00414039: jnz 0x414034
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
      [-]ffffe900
         // 00414103: jmp 0x414514
      [-]8d45e4508b
         // 0041419e: lea eax, ss:[ebp+0xffffffffffffffe4]
         // 004141a1: push eax
         // 004141ad: mov eax, ss:[ebp+0xffffffffffffffe0]
      [-]b9????????
         // 004141b0: mov ecx, 0x7fffffff
      [-]fdffffe98d020000
         // 00414c8f: jmp 0x414f21
      [-]6681ea00017407
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
      [-]53088b12e8
         // 00414e19: mov edx, ds:[ebx+0x8]
         // 00414e1c: mov edx, ds:[edx]
         // 00414e1e: call 0x405758
      [-]ffffe9f9000000
         // 00414e23: jmp 0x414f21
      [-]8b43080f
         // 00414458: mov eax, ds:[ebx+0x8]
         // 0041445b: movzx eax, b1 ds:[eax]
      [-]ffff8b55
         // 00414463: mov edx, ss:[ebp+0xffffffffffffff9c]
      [-]fbffffeb3e
         // 00414ee1: jmp 0x414f21
      [-]f9ffff8b
         // 004144e0: mov edx, ss:[ebp+0xffffffffffffff8c]
      [-]ffffeb28
         // 004144ea: jmp 0x414514
      [-]faffff84c07514
         // 00414f09: test b1 al, b1 al
         // 00414f0b: jnz 0x414f21
      [-]f9ffff8b
         // 0041450a: mov edx, ss:[ebp+0xffffffffffffff88]
      [-]5a595964891068
         // 00414516: pop edx
         // 00414517: pop ecx
         // 00414518: pop ecx
         // 00414519: mov fs:[eax], edx
         // 0041451c: push 0x41456a
      [-]ffff8d45
         // 0041452e: lea eax, ss:[ebp+0xffffffffffffffa4]
      [-]ffff8d45
         // 0041453b: lea eax, ss:[ebp+0xffffffffffffffb0]
      [-]ffff8d45f0
         // 00414555: lea eax, ss:[ebp+0xfffffffffffffff0]
      [-]6a006a004975f9
         // 0041475c: push 0x0
         // 0041475e: push 0x0
         // 00414760: dec ecx
         // 00414761: jnz 0x41475c
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
      [-]fdffffe98d020000
         // 004153a1: jmp 0x415633
      [-]6681ea00017407
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
      [-]53088b12e8
         // 0041552b: mov edx, ds:[ebx+0x8]
         // 0041552e: mov edx, ds:[edx]
         // 00415530: call 0x405e6c
      [-]ffffe9f9000000
         // 00415535: jmp 0x415633
      [-]8b43080f
         // 00414b74: mov eax, ds:[ebx+0x8]
         // 00414b77: movzx eax, b1 ds:[eax]
      [-]ffff8b55
         // 00414b7f: mov edx, ss:[ebp+0xffffffffffffffa0]
      [-]fbffffeb3e
         // 004155f3: jmp 0x415633
      [-]f9ffff8b
         // 00414bfc: mov edx, ss:[ebp+0xffffffffffffff90]
      [-]ffffeb28
         // 00414c06: jmp 0x414c30
      [-]faffff84c07514
         // 0041561b: test b1 al, b1 al
         // 0041561d: jnz 0x415633
      [-]f9ffff8b
         // 00414c26: mov edx, ss:[ebp+0xffffffffffffff8c]
      [-]5a595964891068
         // 00414c32: pop edx
         // 00414c33: pop ecx
         // 00414c34: pop ecx
         // 00414c35: mov fs:[eax], edx
         // 00414c38: push 0x414cad
      [-]ffff8d45
         // 00414c4a: lea eax, ss:[ebp+0xffffffffffffff94]
      [-]ffff8d45
         // 00414c64: lea eax, ss:[ebp+0xffffffffffffffb4]
      [-]ffff8d45
         // 00414c7e: lea eax, ss:[ebp+0xffffffffffffffcc]
      [-]ffff8d45f0
         // 00414c98: lea eax, ss:[ebp+0xfffffffffffffff0]
      [-]e8d7ffffffc3
         // 004170e8: call 0x4170c4
         // 004170ed: retn 
      [-]feff5e5bc3
         // 0041681b: pop esi
         // 0041681c: pop ebx
         // 0041681d: retn 
      [-]ffff5e5bc3
         // 00416bc7: pop esi
         // 00416bc8: pop ebx
         // 00416bc9: retn 
      [-]83c00850e8
         // 00419fd4: add eax, 0x8
         // 00419fd7: push eax
         // 00419fd8: call EnterCriticalSection_0
      [-]83c00850e8
         // 0041a08c: add eax, 0x8
         // 0041a08f: push eax
         // 0041a090: call LeaveCriticalSection_0
      [-]558bec83c4f453
         // 0041a2d8: push ebp
         // 0041a2d9: mov ebp, esp
         // 0041a2db: add esp, 0xfffffffffffffff4
         // 0041a2de: push ebx
      [-]64ff30648920895df8c645fc0b8d45f8506a008d55f4a1
         // 0041a2ee: push fs:[eax]
         // 0041a2f1: mov fs:[eax], esp
         // 0041a2f4: mov ss:[ebp+0xfffffffffffffff8], ebx
         // 0041a2f7: mov b1 ss:[ebp+0xfffffffffffffffc], b1 0xb
         // 0041a2fb: lea eax, ss:[ebp+0xfffffffffffffff8]
         // 0041a2fe: push eax
         // 0041a2ff: push 0x0
         // 0041a301: lea edx, ss:[ebp+0xfffffffffffffff4]
         // 0041a304: mov eax, ds:[0x49dd30]
      [-]feff8b4df4b201a1
         // 0041a30e: mov ecx, ss:[ebp+0xfffffffffffffff4]
         // 0041a311: mov b1 dl, b1 0x1
         // 0041a313: mov eax, ds:[0x4182a0]
      [-]5a595964891068
         // 0041a324: pop edx
         // 0041a325: pop ecx
         // 0041a326: pop ecx
         // 0041a327: mov fs:[eax], edx
         // 0041a32a: push 0x41a33f
      [-]8d45f4e8
         // 0041a32f: lea eax, ss:[ebp+0xfffffffffffffff4]
         // 0041a332: call @System@@LStrClr$qqrpv
      [-]5b8be55dc3
         // 0041a33f: pop ebx
         // 0041a340: mov esp, ebp
         // 0041a342: pop ebp
         // 0041a343: retn 
      [-]8b4504c3
         // 0041abbc: mov eax, ss:[ebp+0x4]
         // 0041abbf: retn 
      [-]83c00850e8
         // 0041b0d0: add eax, 0x8
         // 0041b0d3: push eax
         // 0041b0d4: call LeaveCriticalSection_0
      [-]8b4504c3
         // 0041c068: mov eax, ss:[ebp+0x4]
         // 0041c06b: retn 
      [-]64ff306489
         // 0041cca7: push fs:[eax]
         // 0041ccc6: mov fs:[eax], edx
      [-]30ff560c3bd87417
         // 0041d8df: mov esi, ds:[eax]
         // 0041d8e1: call ds:[esi+0xc]
         // 0041d8e4: cmp ebx, eax
         // 0041d8e6: jz 0x41d8ff
      [-]8b4004e8
         // 0041dadc: mov eax, ds:[eax+0x4]
         // 0041dadf: call 0x409974
      [-]feff83f8ff7502
         // 0041dae4: cmp eax, 0xffffffffffffffff
         // 0041dae7: jnz 0x41daeb
      [-]558bec83c4
         // 0041e61c: push ebp
         // 0041e61d: mov ebp, esp
         // 0041e61f: add esp, 0xfffffffffffffff4
      [-]535657a1
         // 0041e622: push ebx
         // 0041e623: push esi
         // 0041e624: push edi
         // 0041e625: mov eax, ds:[0x49e84c]
      [-]8b10ff5214
         // 0041e62a: mov edx, ds:[eax]
         // 0041e62c: call ds:[edx+0x14]
      [-]837f08000f8e
         // 0041e657: cmp ds:[edi+0x8], 0x0
         // 0041e65b: jle 0x41e77e
      [-]feff8945fc
         // 0041e66d: mov ss:[ebp+0xfffffffffffffffc], eax
      [-]feff8945f8
         // 0041e68a: mov ss:[ebp+0xfffffffffffffff8], eax
      [-]ffff8945f4837df400750f
         // 0041c7ed: mov ss:[ebp+0xfffffffffffffff4], eax
         // 0041c7f0: cmp ss:[ebp+0xfffffffffffffff4], 0x0
         // 0041c7f4: jnz 0x41c805
      [-]8b530c8b4304e8
         // 0041e6bb: mov edx, ds:[ebx+0xc]
         // 0041e6be: mov eax, ds:[ebx+0x4]
         // 0041e6c1: call @Typinfo@GetOrdProp$qqrp14System@TObjectp17Typinfo@TPropInfo
      [-]837df40074
         // 0041e6ca: cmp ss:[ebp+0xfffffffffffffff4], 0x0
         // 0041e6ce: jz 0x41e6e3
      [-]8b53148b45f4e8
         // 0041e6d0: mov edx, ds:[ebx+0x14]
         // 0041e6d3: mov eax, ss:[ebp+0xfffffffffffffff4]
         // 0041e6d6: call @Classes@FindNestedComponent$qqrp18Classes@TComponentx17System@AnsiString
      [-]558b4304e8
         // 0041e6e3: push ebp
         // 0041e6e4: mov eax, ds:[ebx+0x4]
         // 0041e6e7: call 0x41e59c
      [-]feffff59
         // 0041e6ec: pop ecx
      [-]feffeb0b
         // 0041e6fd: jmp 0x41e70a
      [-]558b4304e8
         // 0041e6ff: push ebp
         // 0041e700: mov eax, ds:[ebx+0x4]
         // 0041e703: call 0x41e5d4
      [-]feffff5946
         // 0041e708: pop ecx
         // 0041e709: inc esi
      [-]5a595964891068
         // 0041c86c: pop edx
         // 0041c86d: pop ecx
         // 0041c86e: pop ecx
         // 0041c86f: mov fs:[eax], edx
         // 0041c872: push 0x41c887
      [-]8b45f8e8
         // 0041c877: mov eax, ss:[ebp+0xfffffffffffffff8]
         // 0041c87a: call 0x404650
      [-]8b45fc8b58084b
         // 0041c887: mov eax, ss:[ebp+0xfffffffffffffffc]
         // 0041c88a: mov ebx, ds:[eax+0x8]
         // 0041c88d: dec ebx
      [-]feff84c07406
         // 0041c8ae: test b1 al, b1 al
         // 0041c8b0: jz 0x41c8b8
      [-]6681671c7fff
         // 0041e757: and b2 ds:[edi+0x1c], b2 0xffffffffffffff7f
      [-]464b75d9
         // 0041e75d: inc esi
         // 0041e75e: dec ebx
         // 0041e75f: jnz 0x41e73a
      [-]5a595964891068
         // 0041c8be: pop edx
         // 0041c8bf: pop ecx
         // 0041c8c0: pop ecx
         // 0041c8c1: mov fs:[eax], edx
         // 0041c8c4: push 0x41c8d9
      [-]8b45fce8
         // 0041c8c9: mov eax, ss:[ebp+0xfffffffffffffffc]
         // 0041c8cc: call 0x404650
      [-]5a595964891068
         // 0041c8db: pop edx
         // 0041c8dc: pop ecx
         // 0041c8dd: pop ecx
         // 0041c8de: mov fs:[eax], edx
         // 0041c8e1: push 0x41c8f8
      [-]5a595964891068
         // 0041c8fa: pop edx
         // 0041c8fb: pop ecx
         // 0041c8fc: pop ecx
         // 0041c8fd: mov fs:[eax], edx
         // 0041c900: push 0x41c917
      [-]8b10ff5218c3
         // 0041c90a: mov edx, ds:[eax]
         // 0041c90c: call ds:[edx+0x18]
         // 0041c90f: retn 
      [-]5f5e5b8be55dc3
         // 0041c917: pop edi
         // 0041c918: pop esi
         // 0041c919: pop ebx
         // 0041c91a: mov esp, ebp
         // 0041c91c: pop ebp
         // 0041c91d: retn 
      [-]feff5bc3
         // 0041e90a: pop ebx
         // 0041e90b: retn 
      [-]e8deffffffc3
         // 0041e911: call 0x41e8f4
         // 0041e916: retn 
      [-]558bec51
         // 0041ff20: push ebp
         // 0041ff21: mov ebp, esp
         // 0041ff23: push ecx
      [-]6a006a004975f9
         // 0041ff29: push 0x0
         // 0041ff2b: push 0x0
         // 0041ff2d: dec ecx
         // 0041ff2e: jnz 0x41ff29
      [-]874dfc53894df48955f88945fc
         // 0041e268: xchg ecx, ss:[ebp+0xfffffffffffffffc]
         // 0041e26b: push ebx
         // 0041e26c: mov ss:[ebp+0xfffffffffffffff4], ecx
         // 0041e26f: mov ss:[ebp+0xfffffffffffffff8], edx
         // 0041e272: mov ss:[ebp+0xfffffffffffffffc], eax
      [-]64ff306489208b45f4837808007541
         // 0041e27d: push fs:[eax]
         // 0041e280: mov fs:[eax], esp
         // 0041e283: mov eax, ss:[ebp+0xfffffffffffffff4]
         // 0041e286: cmp ds:[eax+0x8], 0x0
         // 0041e28a: jnz 0x41e2cd
      [-]8b45f48b008b00803807752b
         // 0041ff54: mov eax, ss:[ebp+0xfffffffffffffff4]
         // 0041ff57: mov eax, ds:[eax]
         // 0041ff59: mov eax, ds:[eax]
         // 0041ff5b: cmp b1 ds:[eax], b1 0x7
         // 0041ff5e: jnz 0x41ff8b
      [-]8b55f48b45f8e8
         // 0041ff60: mov edx, ss:[ebp+0xfffffffffffffff4]
         // 0041ff63: mov eax, ss:[ebp+0xfffffffffffffff8]
         // 0041ff66: call @Typinfo@GetOrdProp$qqrp14System@TObjectp17Typinfo@TPropInfo
      [-]ffff8b15
         // 0041ff6b: mov edx, ds:[0x419504]
      [-]feff84c07411
         // 0041ff76: test b1 al, b1 al
         // 0041ff78: jz 0x41ff8b
      [-]8b55f48b45f8e8
         // 0041ff7a: mov edx, ss:[ebp+0xfffffffffffffff4]
         // 0041ff7d: mov eax, ss:[ebp+0xfffffffffffffff8]
         // 0041ff80: call @Typinfo@GetOrdProp$qqrp14System@TObjectp17Typinfo@TPropInfo
      [-]fffff6402404750a
         // 0041ff85: test b1 ds:[eax+0x24], b1 0x4
         // 0041ff89: jnz 0x41ff95
      [-]8b45f48b008b18
         // 0041ff95: mov eax, ss:[ebp+0xfffffffffffffff4]
         // 0041ff98: mov eax, ds:[eax]
         // 0041ff9a: mov ebx, ds:[eax]
      [-]83f8100f87
         // 0041ffa0: cmp eax, 0x10
         // 0041ffa3: ja def_41FFA9
      [-]8b45fce8
         // 0041fff4: mov eax, ss:[ebp+0xfffffffffffffffc]
         // 0041fff7: call @Classes@TReader@NextValue$qqrv
      [-]ffff3c07751e
         // 0041fffc: cmp b1 al, b1 0x7
         // 0041fffe: jnz 0x42001e
      [-]8d55e88b45fce8
         // 00420000: lea edx, ss:[ebp+0xffffffffffffffe8]
         // 00420003: mov eax, ss:[ebp+0xfffffffffffffffc]
         // 00420006: call @Classes@TReader@ReadIdent$qqrv
      [-]f8ffff8b4de88b55f48b45f8e8
         // 0042000b: mov ecx, ss:[ebp+0xffffffffffffffe8]
         // 0042000e: mov edx, ss:[ebp+0xfffffffffffffff4]
         // 00420011: mov eax, ss:[ebp+0xfffffffffffffff8]
         // 00420014: call 0x41fd7c
      [-]fdffffe9
         // 00420019: jmp def_41FFA9
      [-]8b45fce8
         // 0042001e: mov eax, ss:[ebp+0xfffffffffffffffc]
         // 00420021: call @Classes@TReader@ReadInteger$qqrv
      [-]55f48b45f8e8
         // 00420028: mov edx, ss:[ebp+0xfffffffffffffff4]
         // 0042002b: mov eax, ss:[ebp+0xfffffffffffffff8]
         // 0042002e: call @Typinfo@SetOrdProp$qqrp14System@TObjectp17Typinfo@TPropInfoi
      [-]8d55e48b45fce8
         // 00420054: lea edx, ss:[ebp+0xffffffffffffffe4]
         // 00420057: mov eax, ss:[ebp+0xfffffffffffffffc]
         // 0042005a: call @Classes@TReader@ReadIdent$qqrv
      [-]ffff8b55e4
         // 0042005f: mov edx, ss:[ebp+0xffffffffffffffe4]
      [-]55f48b45f8e8
         // 0042006e: mov eax, ss:[ebp+0xfffffffffffffff8]
         // 00420071: call @Typinfo@SetOrdProp$qqrp14System@TObjectp17Typinfo@TPropInfoi
      [-]8b45fce8
         // 0042007b: mov eax, ss:[ebp+0xfffffffffffffffc]
         // 0042007e: call @Classes@TReader@ReadFloat$qqrv
      [-]f6ffff83c4f4db3c249b8b55f48b45f8e8
         // 00420083: add esp, 0xfffffffffffffff4
         // 00420086: fstp b10 ss:[esp]
         // 00420089: wait 
         // 0042008a: mov edx, ss:[ebp+0xfffffffffffffff4]
         // 0042008d: mov eax, ss:[ebp+0xfffffffffffffff8]
         // 00420090: call @Typinfo@SetFloatProp$qqrp14System@TObjectp17Typinfo@TPropInfoxg
      [-]8d55e08b45fce8
         // 0042009a: lea edx, ss:[ebp+0xffffffffffffffe0]
         // 0042009d: mov eax, ss:[ebp+0xfffffffffffffffc]
         // 004200a0: call @Classes@TReader@ReadString$qqrv
      [-]0600008b4de08b55f48b45f8e8
         // 004200a5: mov ecx, ss:[ebp+0xffffffffffffffe0]
         // 004200a8: mov edx, ss:[ebp+0xfffffffffffffff4]
         // 004200ab: mov eax, ss:[ebp+0xfffffffffffffff8]
         // 004200ae: call @Typinfo@SetStrProp$qqrp14System@TObjectp17Typinfo@TPropInfox17System@AnsiString
      [-]8d55dc8b45fce8
         // 004200b8: lea edx, ss:[ebp+0xffffffffffffffdc]
         // 004200bb: mov eax, ss:[ebp+0xfffffffffffffffc]
         // 004200be: call @Classes@TReader@ReadWideString$qqrv
      [-]0600008b4ddc8b55f48b45f8e8
         // 004200c3: mov ecx, ss:[ebp+0xffffffffffffffdc]
         // 004200c6: mov edx, ss:[ebp+0xfffffffffffffff4]
         // 004200c9: mov eax, ss:[ebp+0xfffffffffffffff8]
         // 004200cc: call @Typinfo@SetWideStrProp$qqrp14System@TObjectp17Typinfo@TPropInfox17System@WideString
      [-]0400008b
         // 0041e433: mov edx, ss:[ebp+0xfffffffffffffff4]
      [-]55f48b45f8e8
         // 0041e436: mov eax, ss:[ebp+0xfffffffffffffff8]
         // 0041e439: call 0x416688
      [-]8b45fce8
         // 004200f2: mov eax, ss:[ebp+0xfffffffffffffffc]
         // 004200f5: call @Classes@TReader@NextValue$qqrv
      [-]ffff2c0d7406
         // 004200fa: sub b1 al, b1 0xd
         // 004200fc: jz 0x420104
      [-]fec8741c
         // 004200fe: dec b1 al
         // 00420100: jz 0x42011e
      [-]558d55d88b45fce8
         // 00420140: push ebp
         // 00420141: lea edx, ss:[ebp+0xffffffffffffffd8]
         // 00420144: mov eax, ss:[ebp+0xfffffffffffffffc]
         // 00420147: call @Classes@TReader@ReadIdent$qqrv
      [-]ffff8b4dd88b55f48b45f8e8
         // 0042014c: mov ecx, ss:[ebp+0xffffffffffffffd8]
         // 0042014f: mov edx, ss:[ebp+0xfffffffffffffff4]
         // 00420152: mov eax, ss:[ebp+0xfffffffffffffff8]
         // 00420155: call 0x41fdc4
      [-]fcffff59e9
         // 0042015a: pop ecx
         // 0042015b: jmp def_41FFA9
      [-]8b45fce8
         // 00420160: mov eax, ss:[ebp+0xfffffffffffffffc]
         // 00420163: call @Classes@TReader@NextValue$qqrv
      [-]ffff3c0d751a
         // 00420168: cmp b1 al, b1 0xd
         // 0042016a: jnz 0x420186
      [-]8b45fce8
         // 0042016c: mov eax, ss:[ebp+0xfffffffffffffffc]
         // 0042016f: call 0x420870
      [-]060000b9
         // 00420174: mov ecx, 0x49b53c
      [-]8b55f48b45f8e8
         // 00420179: mov edx, ss:[ebp+0xfffffffffffffff4]
         // 0042017c: mov eax, ss:[ebp+0xfffffffffffffff8]
         // 0042017f: call @Typinfo@SetMethodProp$qqrp14System@TObjectp17Typinfo@TPropInforx14System@TMethod
      [-]8b45fce8
         // 00420189: mov eax, ss:[ebp+0xfffffffffffffffc]
         // 0042018c: call @Classes@TReader@ReadIdent$qqrv
      [-]f6ffff8b4dd48b45fc8b50188b45fc8b18ff5318837dec007437
         // 00420191: mov ecx, ss:[ebp+0xffffffffffffffd4]
         // 00420194: mov eax, ss:[ebp+0xfffffffffffffffc]
         // 00420197: mov edx, ds:[eax+0x18]
         // 0042019a: mov eax, ss:[ebp+0xfffffffffffffffc]
         // 0042019d: mov ebx, ds:[eax]
         // 0042019f: call ds:[ebx+0x18]
         // 004201ae: cmp ss:[ebp+0xffffffffffffffec], 0x0
         // 004201b2: jz def_41FFA9
      [-]8d4dec8b55f48b45f8e8
         // 004201b4: lea ecx, ss:[ebp+0xffffffffffffffec]
         // 004201b7: mov edx, ss:[ebp+0xfffffffffffffff4]
         // 004201ba: mov eax, ss:[ebp+0xfffffffffffffff8]
         // 004201bd: call @Typinfo@SetMethodProp$qqrp14System@TObjectp17Typinfo@TPropInforx14System@TMethod
      [-]ffffeb27
         // 004201c2: jmp def_41FFA9
      [-]fcffff59eb1e
         // 004201ca: pop ecx
         // 004201cb: jmp def_41FFA9
      [-]8b45fce8
         // 004201cd: mov eax, ss:[ebp+0xfffffffffffffffc]
         // 004201d0: call @Classes@TReader@ReadInt64$qqrv
      [-]ffff52508b55f48b45f8e8
         // 004201d5: push edx
         // 004201d6: push eax
         // 004201d7: mov edx, ss:[ebp+0xfffffffffffffff4]
         // 004201da: mov eax, ss:[ebp+0xfffffffffffffff8]
         // 004201dd: call @Typinfo@SetInt64Prop$qqrp14System@TObjectp17Typinfo@TPropInfoxj
      [-]ffffeb07
         // 004201e2: jmp def_41FFA9
      [-]fcffff59
         // 004201ea: pop ecx
      [-]5a595964891068
         // 004201ed: pop edx
         // 004201ee: pop ecx
         // 004201ef: pop ecx
         // 004201f0: mov fs:[eax], edx
         // 004201f3: push 0x420222
      [-]feff8d45dce8
         // 00420205: lea eax, ss:[ebp+0xffffffffffffffdc]
         // 00420208: call 0x4050a0
      [-]feff8d45e0
         // 0042020d: lea eax, ss:[ebp+0xffffffffffffffe0]
      [-]558bec5dc20800
         // 00421f40: push ebp
         // 00421f41: mov ebp, esp
         // 00421f43: pop ebp
         // 00421f44: retn b2 0x8
      [-]558bec5dc2
         // 004222c4: push ebp
         // 004222c5: mov ebp, esp
         // 004222c7: pop ebp
         // 004222c8: retn b2 0x4
      [-]83c00850e8
         // 00424168: add eax, 0x8
         // 0042416b: push eax
         // 0042416c: call EnterCriticalSection_0
      [-]83c00850e8
         // 00424174: add eax, 0x8
         // 00424177: push eax
         // 00424178: call LeaveCriticalSection_0
      [-]fdff5bc3
         // 004259de: pop ebx
         // 004259df: retn 
      [-]fdff5bc3
         // 004259f6: pop ebx
         // 004259f7: retn 
      [-]e8deffffffc3
         // 00425f45: call 0x425f28
         // 00425f4a: retn 
      [-]e8d2ffffffc3
         // 00425f51: call 0x425f28
         // 00425f56: retn 
      [-]e8c6ffffffc3
         // 00425f5d: call 0x425f28
         // 00425f62: retn 
      [-]558bec6a00
         // 00425a1c: push ebp
         // 00425a1d: mov ebp, esp
         // 00425a1f: push 0x0
      [-]64ff306489208d55fca1
         // 00425a29: push fs:[eax]
         // 00425a2c: mov fs:[eax], esp
         // 00425a2f: lea edx, ss:[ebp+0xfffffffffffffffc]
         // 00425a32: mov eax, ds:[0x494860]
      [-]feff8b4dfcb201a1
         // 00425a3c: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 00425a3f: mov b1 dl, b1 0x1
         // 00425a41: mov eax, ds:[0x417354]
      [-]5a595964891068
         // 00425a52: pop edx
         // 00425a53: pop ecx
         // 00425a54: pop ecx
         // 00425a55: mov fs:[eax], edx
         // 00425a58: push 0x425a6d
      [-]8d45fce8
         // 00425a5d: lea eax, ss:[ebp+0xfffffffffffffffc]
         // 00425a60: call 0x405530
      [-]535684d27408
         // 004271e0: push ebx
         // 004271e1: push esi
         // 004271e2: test b1 dl, b1 dl
         // 004271e4: jz 0x4271ee
      [-]83c4f0e8
         // 004271e6: add esp, 0xfffffffffffffff0
         // 004271e9: call @System@@ClassCreate$qqrp17System@TMetaClasso
      [-]84db740f
         // 00426cd1: test b1 bl, b1 bl
         // 00426cd3: jz 0x426ce4
      [-]fdff648f05????????83c40c
         // 00427206: pop fs:[0x0]
         // 0042720d: add esp, 0xc
      [-]558bec83c4f8538955fc8945f88b45f85068
         // 004277dc: push ebp
         // 004277dd: mov ebp, esp
         // 004277df: add esp, 0xfffffffffffffff8
         // 004277e2: push ebx
         // 004277e3: mov ss:[ebp+0xfffffffffffffffc], edx
         // 004277e6: mov ss:[ebp+0xfffffffffffffff8], eax
         // 004277e9: mov eax, ss:[ebp+0xfffffffffffffff8]
         // 004277ec: push eax
         // 004277ed: push 0x4275f4
      [-]8b45f85068
         // 004277f2: mov eax, ss:[ebp+0xfffffffffffffff8]
         // 004277f5: push eax
         // 004277f6: push 0x427708
      [-]55e85fffffff59
         // 004277fb: push ebp
         // 004277fc: call 0x427760
         // 00427801: pop ecx
      [-]8b45fc8b18ff53085b59595dc3
         // 00427809: mov eax, ss:[ebp+0xfffffffffffffffc]
         // 0042780c: mov ebx, ds:[eax]
         // 0042780e: call ds:[ebx+0x8]
         // 00427811: pop ebx
         // 00427812: pop ecx
         // 00427813: pop ecx
         // 00427814: pop ebp
         // 00427815: retn 
      [-]e81a000000
         // 00428cc1: call 0x428ce0
      [-]ffff84db7e07
         // 00428cd2: test b1 bl, b1 bl
         // 00428cd4: jle 0x428cdd
      [-]b101e801000000c3
         // 0042b048: mov b1 cl, b1 0x1
         // 0042b04a: call @Graphics@TBitmap@WriteStream$qqrp15Classes@TStreamo
         // 0042b04f: retn 
      [-]e841fdffffc3
         // 0042b30a: call @Graphics@TBitmap@WriteStream$qqrp15Classes@TStreamo
         // 0042b30f: retn 
      [-]83c00850e8
         // 0042ba10: add eax, 0x8
         // 0042ba13: push eax
         // 0042ba14: call EnterCriticalSection_0
      [-]83c00850e8
         // 0042ba1c: add eax, 0x8
         // 0042ba1f: push eax
         // 0042ba20: call LeaveCriticalSection_0
      [-]8b4004e8
         // 0042c3c4: mov eax, ds:[eax+0x4]
         // 0042c3c7: call @Classes@TList@Add$qqrpv
      [-]8b10ff12c3
         // 0042e1ac: mov edx, ds:[eax]
         // 0042e1ae: call ds:[edx]
         // 0042e1b0: retn 
      [-]8b10ff5204c3
         // 0042e1b4: mov edx, ds:[eax]
         // 0042e1b6: call ds:[edx+0x4]
         // 0042e1b9: retn 
      [-]8b442408c3
         // 00449f10: mov eax, ss:[esp+0x8]
         // 00449f14: retn 
      [-]837b5c00750a
         // 0044c8f2: cmp ds:[ebx+0x5c], 0x0
         // 0044c8f6: jnz 0x44c902
      [-]ff5e5bc3
         // 004365d0: pop esi
         // 004365d1: pop ebx
         // 004365d2: retn 
      [-]558bec83c4
         // 0044d33c: push ebp
         // 0044d33d: mov ebp, esp
         // 0044d33f: add esp, 0xfffffffffffffff0
      [-]4df88955fc
         // 0044d34d: mov ss:[ebp+0xfffffffffffffff8], ecx
         // 0044d350: mov ss:[ebp+0xfffffffffffffffc], edx
      [-]64ff30648920
         // 0044d35d: push fs:[eax]
         // 0044d360: mov fs:[eax], esp
      [-]0fa31173
         // 0044d387: bt ds:[ecx], edx
         // 0044d38a: jnb 0x44d390
      [-]ff75fc68
         // 0044d3f1: push ss:[ebp+0xfffffffffffffffc]
         // 0044d3f4: push _str_).Len
      [-]ff75fc68
         // 0044d418: push ss:[ebp+0xfffffffffffffffc]
         // 0044d41b: push _str_).Len
      [-]837df800740f
         // 0044d42e: cmp ss:[ebp+0xfffffffffffffff8], 0x0
         // 0044d432: jz 0x44d443
      [-]5a595964891068
         // 0044d445: pop edx
         // 0044d446: pop ecx
         // 0044d447: pop ecx
         // 0044d448: mov fs:[eax], edx
         // 0044d44b: push 0x44d465
      [-]8b4034e8
         // 0044dc38: mov eax, ds:[eax+0x34]
         // 0044dc3b: call @Menus@TMenuItem@GetHandle$qqrv
      [-]80780c0074
         // 0044f33b: cmp b1 ds:[eax+0xc], b1 0x0
         // 0044f33f: jz 0x44f377
      [-]558bec53568b45088b40fce8
         // 00454228: push ebp
         // 00454229: mov ebp, esp
         // 0045422b: push ebx
         // 0045422c: push esi
         // 0045422d: mov eax, ss:[ebp+0x8]
         // 00454230: mov eax, ds:[eax+0xfffffffffffffffc]
         // 00454233: call @Forms@TCustomForm@GetMDIChildCount$qqrv
      [-]8b45088b40fc
         // 0043ebf2: mov eax, ss:[ebp+0x8]
         // 0043ebf5: mov eax, ds:[eax+0xfffffffffffffffc]
      [-]000080b8
         // 0043ebff: cmp b1 ds:[eax+0x273], b1 0x2
      [-]020000027504
         // 0043ec06: jnz 0x43ec0c
      [-]b001eb06
         // 00454258: mov b1 al, b1 0x1
         // 0045425a: jmp 0x454262
      [-]464b75e2
         // 0045425c: inc esi
         // 0045425d: dec ebx
         // 0045425e: jnz 0x454242
      [-]5e5b5dc3
         // 00454262: pop esi
         // 00454263: pop ebx
         // 00454264: pop ebp
         // 00454265: retn 
      [-]558bec83c4f0535657
         // 00454a3f: push ebp
         // 00454a40: mov ebp, esp
         // 00454a42: add esp, 0xfffffffffffffff0
         // 00454a45: push ebx
         // 00454a46: push esi
         // 00454a47: push edi
      [-]64ff30648920
         // 00454a59: push fs:[eax]
         // 00454a5c: mov fs:[eax], esp
      [-]408945fc
         // 00454a77: inc eax
         // 00454a78: mov ss:[ebp+0xfffffffffffffffc], eax
      [-]00003bb0
         // 0043f959: cmp esi, ds:[eax+0x290]
      [-]00003bd87431
         // 0043f96d: cmp ebx, eax
         // 0043f96f: jz 0x43f9a2
      [-]8b46088945f4c645f80b8d45f4506a008d55f0a1
         // 00454aa1: mov eax, ds:[esi+0x8]
         // 00454aa4: mov ss:[ebp+0xfffffffffffffff4], eax
         // 00454aa7: mov b1 ss:[ebp+0xfffffffffffffff8], b1 0xb
         // 00454aab: lea eax, ss:[ebp+0xfffffffffffffff4]
         // 00454aae: push eax
         // 00454aaf: push 0x0
         // 00454ab1: lea edx, ss:[ebp+0xfffffffffffffff0]
         // 00454ab4: mov eax, ds:[0x49d8b4]
      [-]ff8b4df0b201a1
         // 00454abe: mov ecx, ss:[ebp+0xfffffffffffffff0]
         // 00454ac1: mov b1 dl, b1 0x1
         // 00454ac3: mov eax, ds:[0x418520]
      [-]47ff4dfc75a5
         // 00454ad2: inc edi
         // 00454ad3: dec ss:[ebp+0xfffffffffffffffc]
         // 00454ad6: jnz 0x454a7d
      [-]f6431c08750a
         // 00454ae9: test b1 ds:[ebx+0x1c], b1 0x8
         // 00454aed: jnz 0x454af9
      [-]f6461c087402
         // 00454af3: test b1 ds:[esi+0x1c], b1 0x8
         // 00454af7: jz 0x454afb
      [-]0f84ab000000
         // 00454b10: jz 0x454bc1
      [-]f6431c10750d
         // 00454b16: test b1 ds:[ebx+0x1c], b1 0x10
         // 00454b1a: jnz 0x454b29
      [-]020000030f8498000000
         // 00454b23: jz 0x454bc1
      [-]80785c007509
         // 00454b2f: cmp b1 ds:[eax+0x5c], b1 0x0
         // 00454b33: jnz 0x454b3e
      [-]020000017506
         // 00454b3c: jnz 0x454b44
      [-]f6431c107458
         // 00454b3e: test b1 ds:[ebx+0x1c], b1 0x10
         // 00454b42: jz 0x454b9c
      [-]84c00f8488000000
         // 0043fa1b: test b1 al, b1 al
         // 0043fa1d: jz 0x43faab
      [-]8b10ff5234
         // 00454b59: mov edx, ds:[eax]
         // 00454b5b: call ds:[edx+0x34]
      [-]ff3bf87419
         // 00454b6d: cmp edi, eax
         // 00454b6f: jz 0x454b8a
      [-]8b10ff523450
         // 00454b77: mov edx, ds:[eax]
         // 00454b79: call ds:[edx+0x34]
         // 00454b7c: push eax
      [-]ffffeb3f
         // 0043fa6a: jmp 0x43faab
      [-]020000017436
         // 00454ba3: jz 0x454bdb
      [-]84c0742b
         // 0043fa7c: test b1 al, b1 al
         // 0043fa7e: jz 0x43faab
      [-]84c0740f
         // 0043fa98: test b1 al, b1 al
         // 0043fa9a: jz 0x43faab
      [-]020000007409
         // 00454be2: jz 0x454bed
      [-]5a595964891068
         // 0043fb14: pop edx
         // 0043fb15: pop ecx
         // 0043fb16: pop ecx
         // 0043fb17: mov fs:[eax], edx
         // 0043fb1a: push 0x43fb2f
      [-]8d45f0e8
         // 0043fb1f: lea eax, ss:[ebp+0xfffffffffffffff0]
         // 0043fb22: call 0x405530
      [-]558bec51535684d27408
         // 00457adc: push ebp
         // 00457add: mov ebp, esp
         // 00457adf: push ecx
         // 00457ae0: push ebx
         // 00457ae1: push esi
         // 00457ae2: test b1 dl, b1 dl
         // 00457ae4: jz 0x457aee
      [-]83c4f0e8
         // 00457ae6: add esp, 0xfffffffffffffff0
         // 00457ae9: call @System@@ClassCreate$qqrp17System@TMetaClasso
      [-]8855ff8b
         // 0044363e: mov b1 ss:[ebp+0xffffffffffffffff], b1 dl
         // 00443641: mov ebx, eax
      [-]807dff00740f
         // 00443677: cmp b1 ss:[ebp+0xffffffffffffffff], b1 0x0
         // 0044367b: jz 0x44368c
      [-]ff648f05????????83c40c
         // 00457b32: pop fs:[0x0]
         // 00457b39: add esp, 0xc
      [-]5e5b595dc3
         // 00457b3e: pop esi
         // 00457b3f: pop ebx
         // 00457b40: pop ecx
         // 00457b41: pop ebp
         // 00457b42: retn 
      [-]040000c3
         // 004444c7: retn 
      [-]558bec5356b3018b45088b40f0e8
         // 00458c84: push ebp
         // 00458c85: mov ebp, esp
         // 00458c87: push ebx
         // 00458c88: push esi
         // 00458c89: mov b1 bl, b1 0x1
         // 00458c8b: mov eax, ss:[ebp+0x8]
         // 00458c8e: mov eax, ds:[eax+0xfffffffffffffff0]
         // 00458c91: call @Forms@TScreen@GetCustomFormCount$qqrv
      [-]4e83fe007c34
         // 00458c98: dec esi
         // 00458c99: cmp esi, 0x0
         // 00458c9c: jl 0x458cd2
      [-]8b45088b40f0
         // 00444876: mov eax, ss:[ebp+0x8]
         // 00444879: mov eax, ds:[eax+0xfffffffffffffff0]
      [-]f5ffff83783000751b
         // 00444883: cmp ds:[eax+0x30], 0x0
         // 00444887: jnz 0x4448a4
      [-]f6401c107515
         // 00458cb1: test b1 ds:[eax+0x1c], b1 0x10
         // 00458cb5: jnz 0x458ccc
      [-]80785b00740f
         // 00458cb7: cmp b1 ds:[eax+0x5b], b1 0x0
         // 00458cbb: jz 0x458ccc
      [-]807857007409
         // 00458cbd: cmp b1 ds:[eax+0x57], b1 0x0
         // 00458cc1: jz 0x458ccc
      [-]020000017508
         // 00458cca: jnz 0x458cd4
      [-]4e83feff75cc
         // 00458ccc: dec esi
         // 00458ccd: cmp esi, 0xffffffffffffffff
         // 00458cd0: jnz 0x458c9e
      [-]5e5b5dc3
         // 00458cd6: pop esi
         // 00458cd7: pop ebx
         // 00458cd8: pop ebp
         // 00458cd9: retn 
      [-]83c030e8
         // 00458dec: add eax, 0x30
         // 00458def: call 0x40ecf8
      [-]feffffc3
         // 00445437: retn 
      [-]feffffc3
         // 0045974b: retn 
      [-]558bec83c4f85356
         // 0045b58f: push ebp
         // 0045b590: mov ebp, esp
         // 0045b592: add esp, 0xfffffffffffffff8
         // 0045b595: push ebx
         // 0045b596: push esi
      [-]84c07408
         // 0045b5cb: test b1 al, b1 al
         // 0045b5cd: jz 0x45b5d7
      [-]2c0a7404
         // 0045b5cf: sub b1 al, b1 0xa
         // 0045b5d1: jz 0x45b5d7
      [-]2bce8d45
         // 0045b5d9: sub ecx, esi
         // 0045b5db: lea eax, ss:[ebp+0xfffffffffffffff8]
      [-]ff8b45088b40fc8b80????????8b80
         // 0045b5e5: mov eax, ss:[ebp+0x8]
         // 0045b5e8: mov eax, ds:[eax+0xfffffffffffffffc]
         // 0045b5eb: mov eax, ds:[eax+0x84]
         // 0045b5f1: mov eax, ds:[eax+0x208]
      [-]803b0d7501
         // 0045b607: cmp b1 ds:[ebx], b1 0xd
         // 0045b60a: jnz 0x45b60d
      [-]803b0a7501
         // 0045b60d: cmp b1 ds:[ebx], b1 0xa
         // 0045b610: jnz 0x45b613
      [-]803b0075
         // 0045b613: cmp b1 ds:[ebx], b1 0x0
         // 0045b616: jnz 0x45b5bc
      [-]5a595964
         // 0045b61a: pop edx
         // 0045b61b: pop ecx
         // 0045b61c: pop ecx
         // 0045b61d: mov fs:[eax], edx
         // 0045b620: push 0x45b635

  }
  condition:
    all of them
}
