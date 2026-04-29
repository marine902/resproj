rule eicv_20_0 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         50a1????????50a1????????50e81effffffc3
         // 00401138: push eax
         // 00401139: mov eax, ds:[0x405040]
         // 0040113e: push eax
         // 0040113f: mov eax, ds:[0x4063c4]
         // 00401144: push eax
         // 00401145: call HeapAlloc
         // 0040114a: retn 
      [-]538bd853a1????????83e00150a1????????50e814ffffff83f8011bc0f7d883e07f5bc3
         // 0040114c: push ebx
         // 0040114d: mov ebx, eax
         // 0040114f: push ebx
         // 00401150: mov eax, ds:[0x405040]
         // 00401155: and eax, 0x1
         // 00401158: push eax
         // 00401159: mov eax, ds:[0x4063c4]
         // 0040115e: push eax
         // 0040115f: call HeapFree
         // 00401164: cmp eax, 0x1
         // 00401167: sbb eax, eax
         // 00401169: neg eax
         // 0040116b: and eax, 0x7f
         // 0040116e: pop ebx
         // 0040116f: retn 
      [-]5250a1????????83e00050a1????????50e8eafeffffc3
         // 00401170: push edx
         // 00401171: push eax
         // 00401172: mov eax, ds:[0x405040]
         // 00401177: and eax, 0x0
         // 0040117a: push eax
         // 0040117b: mov eax, ds:[0x4063c4]
         // 00401180: push eax
         // 00401181: call HeapReAlloc
         // 00401186: retn 
      [-]85c0740a
         // 00401188: test eax, eax
         // 0040118a: jz 0x401196
      [-]ff15????????09c07401
         // 0040118c: call ds:[0x405044]
         // 00401192: or eax, eax
         // 00401194: jz 0x401197
      [-]b001e9c2000000
         // 00401197: mov b1 al, b1 0x1
         // 00401199: jmp @System@Error$qqr20System@TRuntimeError
      [-]85c0740a
         // 004011a0: test eax, eax
         // 004011a2: jz 0x4011ae
      [-]ff15????????09c07501
         // 004011a4: call ds:[0x405048]
         // 004011aa: or eax, eax
         // 004011ac: jnz 0x4011af
      [-]b002e9aa000000
         // 004011af: mov b1 al, b1 0x2
         // 004011b1: jmp @System@Error$qqr20System@TRuntimeError
      [-]8915????????e8f10d0000
         // 00401208: mov ds:[0x405004], edx
         // 0040120e: call 0x402004
      [-]53568bf28bd880e37f833d????????00740a
         // 00401214: push ebx
         // 00401215: push esi
         // 00401216: mov esi, edx
         // 00401218: mov ebx, eax
         // 0040121a: and b1 bl, b1 0x7f
         // 0040121d: cmp ds:[0x406004], 0x0
         // 00401224: jz 0x401230
      [-]8bd68bc3ff15????????
         // 00401226: mov edx, esi
         // 00401228: mov eax, ebx
         // 0040122a: call ds:[0x406004]
      [-]84db750d
         // 00401230: test b1 bl, b1 bl
         // 00401232: jnz 0x401241
      [-]e86f1600008b98????????eb0f
         // 00401234: call @Sysinit@@GetTls$qqrv
         // 00401239: mov ebx, ds:[eax+0x4]
         // 0040123f: jmp 0x401250
      [-]80fb18770a
         // 00401241: cmp b1 bl, b1 0x18
         // 00401244: ja 0x401250
      [-]33c08ac38a9850504000
         // 00401246: xor eax, eax
         // 00401248: mov b1 al, b1 bl
         // 0040124a: mov b1 bl, b1 ds:[eax+0x405050]
      [-]33c08ac38bd6e8adffffff
         // 00401250: xor eax, eax
         // 00401252: mov b1 al, b1 bl
         // 00401254: mov edx, esi
         // 00401256: call 0x401208
      [-]83e07f8b1424e9a9ffffff
         // 00401260: and eax, 0x7f
         // 00401263: mov edx, ss:[esp]
         // 00401266: jmp 0x401214
      [-]83f9047d1c
         // 00401288: cmp ecx, 0x4
         // 0040128b: jge 0x4012a9
      [-]39d07453
         // 00401290: cmp eax, edx
         // 00401292: jz 0x4012e7
      [-]565789c689d77709
         // 00401294: push esi
         // 00401295: push edi
         // 00401296: mov esi, eax
         // 00401298: mov edi, edx
         // 0040129a: ja 0x4012a5
      [-]8d7431ff8d7c39fffd
         // 0040129c: lea esi, ds:[ecx+esi+0xffffffffffffffff]
         // 004012a0: lea edi, ds:[ecx+edi+0xffffffffffffffff]
         // 004012a4: std 
      [-]f3a4eb2c
         // 004012a5: rep movsbb 
         // 004012a7: jmp 0x4012d5
      [-]39d0743a
         // 004012a9: cmp eax, edx
         // 004012ab: jz 0x4012e7
      [-]565789c689d789c87720
         // 004012ad: push esi
         // 004012ae: push edi
         // 004012af: mov esi, eax
         // 004012b1: mov edi, edx
         // 004012b3: mov eax, ecx
         // 004012b5: ja 0x4012d7
      [-]83e1038d7430ff8d7c38fffdf3a4c1f80289c1b8????????29c629c7f3a5
         // 004012b7: and ecx, 0x3
         // 004012ba: lea esi, ds:[eax+esi+0xffffffffffffffff]
         // 004012be: lea edi, ds:[eax+edi+0xffffffffffffffff]
         // 004012c2: std 
         // 004012c3: rep movsbb 
         // 004012c5: sar eax, b1 0x2
         // 004012c8: mov ecx, eax
         // 004012ca: mov eax, 0x3
         // 004012cf: sub esi, eax
         // 004012d1: sub edi, eax
         // 004012d3: rep movsdd 
      [-]c1f9027809
         // 004012d7: sar ecx, b1 0x2
         // 004012da: js 0x4012e5
      [-]f3a583e00389c1f3a4
         // 004012dc: rep movsdd 
         // 004012de: and eax, 0x3
         // 004012e1: mov ecx, eax
         // 004012e3: rep movsbb 
      [-]538bd88bc3e8860000008bc3e86bf7ffff5bc3
         // 00401a24: push ebx
         // 00401a25: mov ebx, eax
         // 00401a27: mov eax, ebx
         // 00401a29: call @System@TObject@CleanupInstance$qqrv
         // 00401a2e: mov eax, ebx
         // 00401a30: call 0x4011a0
         // 00401a35: pop ebx
         // 00401a36: retn 
      [-]53565755bf????????8b470885c0741e
         // 00401e24: push ebx
         // 00401e25: push esi
         // 00401e26: push edi
         // 00401e27: push ebp
         // 00401e28: mov edi, 0x4063c8
         // 00401e2d: mov eax, ds:[edi+0x8]
         // 00401e30: test eax, eax
         // 00401e32: jz 0x401e52
      [-]8b5f0c8b700485db7e14
         // 00401e34: mov ebx, ds:[edi+0xc]
         // 00401e37: mov esi, ds:[eax+0x4]
         // 00401e3a: test ebx, ebx
         // 00401e3c: jle 0x401e52
      [-]4b895f0c8b44de0485c07404
         // 00401e3e: dec ebx
         // 00401e3f: mov ds:[edi+0xc], ebx
         // 00401e42: mov eax, ds:[esi+ebx*0x8]
         // 00401e46: test eax, eax
         // 00401e48: jz 0x401e4e
      [-]8be8ffd5
         // 00401e4a: mov ebp, eax
         // 00401e4c: call ebp
      [-]85db7fec
         // 00401e4e: test ebx, ebx
         // 00401e50: jg 0x401e3e
      [-]5d5f5e5bc3
         // 00401e52: pop ebp
         // 00401e53: pop edi
         // 00401e54: pop esi
         // 00401e55: pop ebx
         // 00401e56: retn 
      [-]535657558bf98bea8bf0b8????????3b05????????0f94c33bfd7e33
         // 00401e58: push ebx
         // 00401e59: push esi
         // 00401e5a: push edi
         // 00401e5b: push ebp
         // 00401e5c: mov edi, ecx
         // 00401e5e: mov ebp, edx
         // 00401e60: mov esi, eax
         // 00401e62: mov eax, 0x401e58
         // 00401e67: cmp eax, ds:[0x405030]
         // 00401e6d: setz b1 bl
         // 00401e70: cmp edi, ebp
         // 00401e72: jle 0x401ea7
      [-]8b04ee45892d????????85c07402
         // 00401e74: mov eax, ds:[esi+ebp*0x8]
         // 00401e77: inc ebp
         // 00401e78: mov ds:[0x4063d4], ebp
         // 00401e7e: test eax, eax
         // 00401e80: jz 0x401e84
      [-]84db741b
         // 00401e84: test b1 bl, b1 bl
         // 00401e86: jz 0x401ea3
      [-]b8????????3b05????????740e
         // 00401e88: mov eax, 0x401e58
         // 00401e8d: cmp eax, ds:[0x405030]
         // 00401e93: jz 0x401ea3
      [-]8bcf8bd58bc6ff15????????eb04
         // 00401e95: mov ecx, edi
         // 00401e97: mov edx, ebp
         // 00401e99: mov eax, esi
         // 00401e9b: call ds:[0x405030]
         // 00401ea1: jmp 0x401ea7
      [-]3bfd7fcd
         // 00401ea3: cmp edi, ebp
         // 00401ea5: jg 0x401e74
      [-]5d5f5e5bc3
         // 00401ea7: pop ebp
         // 00401ea8: pop edi
         // 00401ea9: pop esi
         // 00401eaa: pop ebx
         // 00401eab: retn 
      [-]a1????????85c0740f
         // 00401eac: mov eax, ds:[0x4063d0]
         // 00401eb1: test eax, eax
         // 00401eb3: jz 0x401ec4
      [-]8b1033c98b400487caff15????????
         // 00401eb5: mov edx, ds:[eax]
         // 00401eb7: xor ecx, ecx
         // 00401eb9: mov eax, ds:[eax+0x4]
         // 00401ebc: xchg ecx, edx
         // 00401ebe: call ds:[0x405030]
      [-]a3????????e826ffffff
         // 00402004: mov ds:[0x405000], eax
         // 00402009: call @System@@Halt0$qqrv
      [-]8f05????????e9e9ffffff
         // 00402010: pop ds:[0x405004]
         // 00402016: jmp 0x402004
      [-]8b1085d2741b
         // 0040201c: mov edx, ds:[eax]
         // 0040201e: test edx, edx
         // 00402020: jz 0x40203d
      [-]c700????????8b4af8497c0f
         // 00402022: mov ds:[eax], 0x0
         // 00402028: mov ecx, ds:[edx+0xfffffffffffffff8]
         // 0040202b: dec ecx
         // 0040202c: jl 0x40203d
      [-]ff4af8750a
         // 0040202e: dec ds:[edx+0xfffffffffffffff8]
         // 00402031: jnz 0x40203d
      [-]508d42f8e864f1ffff58
         // 00402033: push eax
         // 00402034: lea eax, ds:[edx+0xfffffffffffffff8]
         // 00402037: call 0x4011a0
         // 0040203c: pop eax
      [-]535689c389d6
         // 00402040: push ebx
         // 00402041: push esi
         // 00402042: mov ebx, eax
         // 00402044: mov esi, edx
      [-]8b1385d27419
         // 00402046: mov edx, ds:[ebx]
         // 00402048: test edx, edx
         // 0040204a: jz 0x402065
      [-]c703????????8b4af8497c0d
         // 0040204c: mov ds:[ebx], 0x0
         // 00402052: mov ecx, ds:[edx+0xfffffffffffffff8]
         // 00402055: dec ecx
         // 00402056: jl 0x402065
      [-]ff4af87508
         // 00402058: dec ds:[edx+0xfffffffffffffff8]
         // 0040205b: jnz 0x402065
      [-]8d42f8e83bf1ffff
         // 0040205d: lea eax, ds:[edx+0xfffffffffffffff8]
         // 00402060: call 0x4011a0
      [-]83c3044e75db
         // 00402065: add ebx, 0x4
         // 00402068: dec esi
         // 00402069: jnz 0x402046
      [-]85d27423
         // 00402070: test edx, edx
         // 00402072: jz 0x402097
      [-]8b4af8417f1a
         // 00402074: mov ecx, ds:[edx+0xfffffffffffffff8]
         // 00402077: inc ecx
         // 00402078: jg 0x402094
      [-]50528b42fce85800000089c258528b48fce8f8f1ffff5a58eb03
         // 0040207a: push eax
         // 0040207b: push edx
         // 0040207c: mov eax, ds:[edx+0xfffffffffffffffc]
         // 0040207f: call @System@@NewAnsiString$qqri
         // 00402084: mov edx, eax
         // 00402086: pop eax
         // 00402087: push edx
         // 00402088: mov ecx, ds:[eax+0xfffffffffffffffc]
         // 0040208b: call 0x401288
         // 00402090: pop edx
         // 00402091: pop eax
         // 00402092: jmp 0x402097
      [-]871085d27413
         // 00402097: xchg edx, ds:[eax]
         // 00402099: test edx, edx
         // 0040209b: jz 0x4020b0
      [-]8b4af8497c0d
         // 0040209d: mov ecx, ds:[edx+0xfffffffffffffff8]
         // 004020a0: dec ecx
         // 004020a1: jl 0x4020b0
      [-]ff4af87508
         // 004020a3: dec ds:[edx+0xfffffffffffffff8]
         // 004020a6: jnz 0x4020b0
      [-]8d42f8e8f0f0ffff
         // 004020a8: lea eax, ds:[edx+0xfffffffffffffff8]
         // 004020ab: call 0x4011a0
      [-]85d27409
         // 004020b4: test edx, edx
         // 004020b6: jz 0x4020c1
      [-]8b4af8417e03
         // 004020b8: mov ecx, ds:[edx+0xfffffffffffffff8]
         // 004020bb: inc ecx
         // 004020bc: jle 0x4020c1
      [-]871085d27413
         // 004020c1: xchg edx, ds:[eax]
         // 004020c3: test edx, edx
         // 004020c5: jz 0x4020da
      [-]8b4af8497c0d
         // 004020c7: mov ecx, ds:[edx+0xfffffffffffffff8]
         // 004020ca: dec ecx
         // 004020cb: jl 0x4020da
      [-]ff4af87508
         // 004020cd: dec ds:[edx+0xfffffffffffffff8]
         // 004020d0: jnz 0x4020da
      [-]8d42f8e8c6f0ffff
         // 004020d2: lea eax, ds:[edx+0xfffffffffffffff8]
         // 004020d5: call 0x4011a0
      [-]85c07409
         // 00402374: test eax, eax
         // 00402376: jz 0x402381
      [-]8b50f8427e03
         // 00402378: mov edx, ds:[eax+0xfffffffffffffff8]
         // 0040237b: inc edx
         // 0040237c: jle 0x402381
      [-]8b1085d27437
         // 00402390: mov edx, ds:[eax]
         // 00402392: test edx, edx
         // 00402394: jz 0x4023cd
      [-]8b4af8497431
         // 00402396: mov ecx, ds:[edx+0xfffffffffffffff8]
         // 00402399: dec ecx
         // 0040239a: jz 0x4023cd
      [-]5389c38b42fce835fdffff89c28b038913508b48fce8d2eeffff588b48f8497c0d
         // 0040239c: push ebx
         // 0040239d: mov ebx, eax
         // 0040239f: mov eax, ds:[edx+0xfffffffffffffffc]
         // 004023a2: call @System@@NewAnsiString$qqri
         // 004023a7: mov edx, eax
         // 004023a9: mov eax, ds:[ebx]
         // 004023ab: mov ds:[ebx], edx
         // 004023ad: push eax
         // 004023ae: mov ecx, ds:[eax+0xfffffffffffffffc]
         // 004023b1: call 0x401288
         // 004023b6: pop eax
         // 004023b7: mov ecx, ds:[eax+0xfffffffffffffff8]
         // 004023ba: dec ecx
         // 004023bb: jl 0x4023ca
      [-]ff48f87508
         // 004023bd: dec ds:[eax+0xfffffffffffffff8]
         // 004023c0: jnz 0x4023ca
      [-]8d40f8e8d6edffff
         // 004023c2: lea eax, ds:[eax+0xfffffffffffffff8]
         // 004023c5: call 0x4011a0
      [-]e9bbffffff
         // 004023d0: jmp 0x402390
      [-]e9b3ffffff
         // 004023d8: jmp 0x402390
      [-]83f9000f84e2000000
         // 0040260c: cmp ecx, 0x0
         // 0040260f: jz 0x4026f7
      [-]5053565789c389d689cf31d28a068a56013c0a7425
         // 00402615: push eax
         // 00402616: push ebx
         // 00402617: push esi
         // 00402618: push edi
         // 00402619: mov ebx, eax
         // 0040261b: mov esi, edx
         // 0040261d: mov edi, ecx
         // 0040261f: xor edx, edx
         // 00402621: mov b1 al, b1 ds:[esi]
         // 00402623: mov b1 dl, b1 ds:[esi+0x1]
         // 00402626: cmp b1 al, b1 0xa
         // 00402628: jz 0x40264f
      [-]3c0b743e
         // 0040262a: cmp b1 al, b1 0xb
         // 0040262c: jz 0x40266c
      [-]3c0c7453
         // 0040262e: cmp b1 al, b1 0xc
         // 00402630: jz 0x402685
      [-]3c0d745e
         // 00402632: cmp b1 al, b1 0xd
         // 00402634: jz 0x402694
      [-]3c0e7478
         // 00402636: cmp b1 al, b1 0xe
         // 00402638: jz 0x4026b2
      [-]3c0f0f8486000000
         // 0040263a: cmp b1 al, b1 0xf
         // 0040263c: jz 0x4026c8
      [-]3c110f848d000000
         // 00402642: cmp b1 al, b1 0x11
         // 00402644: jz 0x4026d7
      [-]e999000000
         // 0040264a: jmp 0x4026e8
      [-]5f5e5b58b002e96debffff
         // 004026e8: pop edi
         // 004026e9: pop esi
         // 004026ea: pop ebx
         // 004026eb: pop eax
         // 004026ec: mov b1 al, b1 0x2
         // 004026ee: jmp @System@Error$qqr20System@TRuntimeError
      [-]5f5e5b58
         // 004026f3: pop edi
         // 004026f4: pop esi
         // 004026f5: pop ebx
         // 004026f6: pop eax
      [-]b010e95debffff
         // 004026fc: mov b1 al, b1 0x10
         // 004026fe: jmp @System@Error$qqr20System@TRuntimeError
      [-]50e8f2ffffff58c3
         // 00402744: push eax
         // 00402745: call 0x40273c
         // 0040274a: pop eax
         // 0040274b: retn 
      [-]b011e90debffff
         // 0040274c: mov b1 al, b1 0x11
         // 0040274e: jmp @System@Error$qqr20System@TRuntimeError
      [-]8b0885c97432
         // 00402754: mov ecx, ds:[eax]
         // 00402756: test ecx, ecx
         // 00402758: jz 0x40278c
      [-]c700????????ff49f87527
         // 0040275a: mov ds:[eax], 0x0
         // 00402760: dec ds:[ecx+0xfffffffffffffff8]
         // 00402763: jnz 0x40278c
      [-]5089c831c98a4a018b54110685d2740e
         // 00402765: push eax
         // 00402766: mov eax, ecx
         // 00402768: xor ecx, ecx
         // 0040276a: mov b1 cl, b1 ds:[edx+0x1]
         // 0040276d: mov edx, ds:[ecx+edx+0x6]
         // 00402771: test edx, edx
         // 00402773: jz 0x402783
      [-]8b48fc85c97407
         // 00402775: mov ecx, ds:[eax+0xfffffffffffffffc]
         // 00402778: test ecx, ecx
         // 0040277a: jz 0x402783
      [-]8b12e889feffff
         // 0040277c: mov edx, ds:[edx]
         // 0040277e: call 0x40260c
      [-]83e808e815eaffff58
         // 00402783: sub eax, 0x8
         // 00402786: call 0x4011a0
         // 0040278b: pop eax
      [-]53568bf08b1d????????85db740c
         // 004027a0: push ebx
         // 004027a1: push esi
         // 004027a2: mov esi, eax
         // 004027a4: mov ebx, ds:[0x405020]
         // 004027aa: test ebx, ebx
         // 004027ac: jz 0x4027ba
      [-]8b4604ff53048b1b85db75f4
         // 004027ae: mov eax, ds:[esi+0x4]
         // 004027b1: call ds:[ebx+0x4]
         // 004027b4: mov ebx, ds:[ebx]
         // 004027b6: test ebx, ebx
         // 004027b8: jnz 0x4027ae
      [-]b8????????c3
         // 0040285c: mov eax, 0x8
         // 00402861: retn 
      [-]5356e8d9efffff8bda8bf08bc6e81a0000008bd380e2fc8bc6e85aeeffff84db7e07
         // 00402bc8: push ebx
         // 00402bc9: push esi
         // 00402bca: call @System@@BeforeDestruction$qqrp14System@TObjectzc
         // 00402bcf: mov ebx, edx
         // 00402bd1: mov esi, eax
         // 00402bd3: mov eax, esi
         // 00402bd5: call @Registry@TRegistry@CloseKey$qqrv
         // 00402bda: mov edx, ebx
         // 00402bdc: and b1 dl, b1 0xfc
         // 00402bdf: mov eax, esi
         // 00402be1: call @System@TObject@$bdtr$qqrv
         // 00402be6: test b1 bl, b1 bl
         // 00402be8: jle 0x402bf1
      [-]8bc6e89fefffff
         // 00402bea: mov eax, esi
         // 00402bec: call @System@@ClassDestroy$qqrp14System@TObject
      [-]53565755518bf98bea8bf08bd58bc6e898ffffff8bd885db7e41
         // 00402e50: push ebx
         // 00402e51: push esi
         // 00402e52: push edi
         // 00402e53: push ebp
         // 00402e54: push ecx
         // 00402e55: mov edi, ecx
         // 00402e57: mov ebp, edx
         // 00402e59: mov esi, eax
         // 00402e5b: mov edx, ebp
         // 00402e5d: mov eax, esi
         // 00402e5f: call @Registry@TRegistry@GetDataSize$qqrx17System@AnsiString
         // 00402e64: mov ebx, eax
         // 00402e66: test ebx, ebx
         // 00402e68: jle 0x402eab
      [-]8bc78bcb33d2e893f2ffff538d442404508b07e802f5ffff8bc88bd58bc6e87b000000803c24017406
         // 00402e6a: mov eax, edi
         // 00402e6c: mov ecx, ebx
         // 00402e6e: xor edx, edx
         // 00402e70: call @System@@LStrFromPCharLen$qqrr17System@AnsiStringpci
         // 00402e75: push ebx
         // 00402e76: lea eax, ss:[esp+0x4]
         // 00402e7a: push eax
         // 00402e7b: mov eax, ds:[edi]
         // 00402e7d: call @System@@LStrToPChar$qqrx17System@AnsiString
         // 00402e82: mov ecx, eax
         // 00402e84: mov edx, ebp
         // 00402e86: mov eax, esi
         // 00402e88: call 0x402f08
         // 00402e8d: cmp b1 ss:[esp], b1 0x1
         // 00402e91: jz 0x402e99
      [-]803c24027519
         // 00402e93: cmp b1 ss:[esp], b1 0x2
         // 00402e97: jnz 0x402eb2
      [-]8b07e8ecf2ffff8bd08bc7e807f6ffffeb07
         // 00402e99: mov eax, ds:[edi]
         // 00402e9b: call 0x40218c
         // 00402ea0: mov edx, eax
         // 00402ea2: mov eax, edi
         // 00402ea4: call @System@@LStrSetLength$qqrv
         // 00402ea9: jmp 0x402eb2
      [-]8bc7e86af1ffff
         // 00402eab: mov eax, edi
         // 00402ead: call 0x40201c
      [-]5a5d5f5e5bc3
         // 00402eb2: pop edx
         // 00402eb3: pop ebp
         // 00402eb4: pop edi
         // 00402eb5: pop esi
         // 00402eb6: pop ebx
         // 00402eb7: retn 
      [-]558bec51535657894dfc8bfa8bd88a4508e85efcffff8bf08b450c508b45fc50566a008bc7e88ef4ffff508b430450e8d0faffff5f5e5b595dc20800
         // 00402ecc: push ebp
         // 00402ecd: mov ebp, esp
         // 00402ecf: push ecx
         // 00402ed0: push ebx
         // 00402ed1: push esi
         // 00402ed2: push edi
         // 00402ed3: mov ss:[ebp+0xfffffffffffffffc], ecx
         // 00402ed6: mov edi, edx
         // 00402ed8: mov ebx, eax
         // 00402eda: mov b1 al, b1 ss:[ebp+0x8]
         // 00402edd: call 0x402b40
         // 00402ee2: mov esi, eax
         // 00402ee4: mov eax, ss:[ebp+0xc]
         // 00402ee7: push eax
         // 00402ee8: mov eax, ss:[ebp+0xfffffffffffffffc]
         // 00402eeb: push eax
         // 00402eec: push esi
         // 00402eed: push 0x0
         // 00402eef: mov eax, edi
         // 00402ef1: call @System@@LStrToPChar$qqrx17System@AnsiString
         // 00402ef6: push eax
         // 00402ef7: mov eax, ds:[ebx+0x4]
         // 00402efa: push eax
         // 00402efb: call RegSetValueExA
         // 00402f00: pop edi
         // 00402f01: pop esi
         // 00402f02: pop ebx
         // 00402f03: pop ecx
         // 00402f04: pop ebp
         // 00402f05: retn b2 0x8
      [-]558bec515356578bf98bf28bd833c08945fc8d450c50578d45fc506a008bc6e858f4ffff508b430450e892faffff8b5d0c8b45fce8d7fbffff8b550888028bc35f5e5b595dc20800
         // 00402f08: push ebp
         // 00402f09: mov ebp, esp
         // 00402f0b: push ecx
         // 00402f0c: push ebx
         // 00402f0d: push esi
         // 00402f0e: push edi
         // 00402f0f: mov edi, ecx
         // 00402f11: mov esi, edx
         // 00402f13: mov ebx, eax
         // 00402f15: xor eax, eax
         // 00402f17: mov ss:[ebp+0xfffffffffffffffc], eax
         // 00402f1a: lea eax, ss:[ebp+0xc]
         // 00402f1d: push eax
         // 00402f1e: push edi
         // 00402f1f: lea eax, ss:[ebp+0xfffffffffffffffc]
         // 00402f22: push eax
         // 00402f23: push 0x0
         // 00402f25: mov eax, esi
         // 00402f27: call @System@@LStrToPChar$qqrx17System@AnsiString
         // 00402f2c: push eax
         // 00402f2d: mov eax, ds:[ebx+0x4]
         // 00402f30: push eax
         // 00402f31: call RegQueryValueExA
         // 00402f36: mov ebx, ss:[ebp+0xc]
         // 00402f39: mov eax, ss:[ebp+0xfffffffffffffffc]
         // 00402f3c: call 0x402b18
         // 00402f41: mov edx, ss:[ebp+0x8]
         // 00402f44: mov b1 ds:[edx], b1 al
         // 00402f46: mov eax, ebx
         // 00402f48: pop edi
         // 00402f49: pop esi
         // 00402f4a: pop ebx
         // 00402f4b: pop ecx
         // 00402f4c: pop ebp
         // 00402f4d: retn b2 0x8
      [-]558bec81c4????????8945fc8b45fce804f3ffff33c05568????????64ff30648920c745????????ffc745????????ff8d85????????508b45fce8e9f2ffff50e89ff9ffff83f8ff742c
         // 0040305c: push ebp
         // 0040305d: mov ebp, esp
         // 0040305f: add esp, 0xfffffffffffffeb0
         // 00403065: mov ss:[ebp+0xfffffffffffffffc], eax
         // 00403068: mov eax, ss:[ebp+0xfffffffffffffffc]
         // 0040306b: call 0x402374
         // 00403070: xor eax, eax
         // 00403072: push ebp
         // 00403073: push 0x4030e8
         // 00403078: push fs:[eax]
         // 0040307b: mov fs:[eax], esp
         // 0040307e: mov ss:[ebp+0xfffffffffffffff0], 0xffffffffffffffff
         // 00403085: mov ss:[ebp+0xfffffffffffffff4], 0xffffffffffffffff
         // 0040308c: lea eax, ss:[ebp+0xfffffffffffffeb0]
         // 00403092: push eax
         // 00403093: mov eax, ss:[ebp+0xfffffffffffffffc]
         // 00403096: call @System@@LStrToPChar$qqrx17System@AnsiString
         // 0040309b: push eax
         // 0040309c: call FindFirstFileA
         // 004030a1: cmp eax, 0xffffffffffffffff
         // 004030a4: jz 0x4030d2
      [-]50e88cf9ffff8b85????????33d28bd033c052508b85????????33d20304241354240483c4088945f08955f4
         // 004030a6: push eax
         // 004030a7: call FindClose
         // 004030ac: mov eax, ss:[ebp+0xfffffffffffffecc]
         // 004030b2: xor edx, edx
         // 004030b4: mov edx, eax
         // 004030b6: xor eax, eax
         // 004030b8: push edx
         // 004030b9: push eax
         // 004030ba: mov eax, ss:[ebp+0xfffffffffffffed0]
         // 004030c0: xor edx, edx
         // 004030c2: add eax, ss:[esp]
         // 004030c5: adc edx, ss:[esp+0x4]
         // 004030c9: add esp, 0x8
         // 004030cc: mov ss:[ebp+0xfffffffffffffff0], eax
         // 004030cf: mov ss:[ebp+0xfffffffffffffff4], edx
      [-]33c05a595964891068????????8d45fce835efffffc3
         // 004030d2: xor eax, eax
         // 004030d4: pop edx
         // 004030d5: pop ecx
         // 004030d6: pop ecx
         // 004030d7: mov fs:[eax], edx
         // 004030da: push 0x4030ef
         // 004030df: lea eax, ss:[ebp+0xfffffffffffffffc]
         // 004030e2: call 0x40201c
         // 004030e7: retn 
      [-]8b45f08b55f48be55dc3
         // 004030ef: mov eax, ss:[ebp+0xfffffffffffffff0]
         // 004030f2: mov edx, ss:[ebp+0xfffffffffffffff4]
         // 004030f5: mov esp, ebp
         // 004030f7: pop ebp
         // 004030f8: retn 
      [-]558bec51538945fc8b45fce868f2ffff33c05568????????64ff30648920b8????????e8d0feffff8bd88b45fce856f2ffff8bd08d4311b9????????e8ebfeffff8b45fce817ffffff89430889530cc643100033c05a595964891068????????8d45fce8b8eeffffc3
         // 004030fc: push ebp
         // 004030fd: mov ebp, esp
         // 004030ff: push ecx
         // 00403100: push ebx
         // 00403101: mov ss:[ebp+0xfffffffffffffffc], eax
         // 00403104: mov eax, ss:[ebp+0xfffffffffffffffc]
         // 00403107: call 0x402374
         // 0040310c: xor eax, eax
         // 0040310e: push ebp
         // 0040310f: push 0x403165
         // 00403114: push fs:[eax]
         // 00403117: mov fs:[eax], esp
         // 0040311a: mov eax, 0x118
         // 0040311f: call @Sysutils@AllocMem$qqrui
         // 00403124: mov ebx, eax
         // 00403126: mov eax, ss:[ebp+0xfffffffffffffffc]
         // 00403129: call @System@@LStrToPChar$qqrx17System@AnsiString
         // 0040312e: mov edx, eax
         // 00403130: lea eax, ds:[ebx+0x11]
         // 00403133: mov ecx, 0x104
         // 00403138: call @Sysutils@StrLCopy$qqrpcpxcui
         // 0040313d: mov eax, ss:[ebp+0xfffffffffffffffc]
         // 00403140: call 0x40305c
         // 00403145: mov ds:[ebx+0x8], eax
         // 00403148: mov ds:[ebx+0xc], edx
         // 0040314b: mov b1 ds:[ebx+0x10], b1 0x0
         // 0040314f: xor eax, eax
         // 00403151: pop edx
         // 00403152: pop ecx
         // 00403153: pop ecx
         // 00403154: mov fs:[eax], edx
         // 00403157: push 0x40316c
         // 0040315c: lea eax, ss:[ebp+0xfffffffffffffffc]
         // 0040315f: call 0x40201c
         // 00403164: retn 
      [-]8bc35b595dc3
         // 0040316c: mov eax, ebx
         // 0040316e: pop ebx
         // 0040316f: pop ecx
         // 00403170: pop ebp
         // 00403171: retn 
      [-]558bec81c4????????53565733d28995????????8995????????8995????????8995????????8995????????8995????????8995????????8995????????8995????????8955f08945fc8b45fce8aef1ffffbb????????be????????bf????????33c05568????????64ff306489208b55fc8d85????????e89be4ffffa1????????c60000ba????????8d85????????e86be7ffff8d85????????e8ece5ffff8945ec8d85????????e8dee5ffff8bd08d45f0e884f2ffff6a008d45f0e8a2f1ffff8bd08b4dec8d85????????e842e5ffff8d85????????e857e5ffff8b55f0b8ac354000e80af2ffff85c00f8f02030000
         // 00403174: push ebp
         // 00403175: mov ebp, esp
         // 00403177: add esp, 0xfffffffffffff678
         // 0040317d: push ebx
         // 0040317e: push esi
         // 0040317f: push edi
         // 00403180: xor edx, edx
         // 00403182: mov ss:[ebp+0xfffffffffffff678], edx
         // 00403188: mov ss:[ebp+0xfffffffffffff67c], edx
         // 0040318e: mov ss:[ebp+0xfffffffffffff680], edx
         // 00403194: mov ss:[ebp+0xfffffffffffff684], edx
         // 0040319a: mov ss:[ebp+0xfffffffffffff688], edx
         // 004031a0: mov ss:[ebp+0xfffffffffffff68c], edx
         // 004031a6: mov ss:[ebp+0xfffffffffffff690], edx
         // 004031ac: mov ss:[ebp+0xfffffffffffff694], edx
         // 004031b2: mov ss:[ebp+0xfffffffffffff698], edx
         // 004031b8: mov ss:[ebp+0xfffffffffffffff0], edx
         // 004031bb: mov ss:[ebp+0xfffffffffffffffc], eax
         // 004031be: mov eax, ss:[ebp+0xfffffffffffffffc]
         // 004031c1: call 0x402374
         // 004031c6: mov ebx, 0x4064d0
         // 004031cb: mov esi, 0x4064cc
         // 004031d0: mov edi, 0x4064d4
         // 004031d5: xor eax, eax
         // 004031d7: push ebp
         // 004031d8: push 0x403596
         // 004031dd: push fs:[eax]
         // 004031e0: mov fs:[eax], esp
         // 004031e3: mov edx, ss:[ebp+0xfffffffffffffffc]
         // 004031e6: lea eax, ss:[ebp+0xfffffffffffff69c]
         // 004031ec: call @System@@Assign$qqrr15System@TTextRecx17System@AnsiString
         // 004031f1: mov eax, ds:[0x4050b0]
         // 004031f6: mov b1 ds:[eax], b1 0x0
         // 004031f9: mov edx, 0x1
         // 004031fe: lea eax, ss:[ebp+0xfffffffffffff69c]
         // 00403204: call @System@@ResetFile$qqrr15System@TFileReci
         // 00403209: lea eax, ss:[ebp+0xfffffffffffff69c]
         // 0040320f: call @System@@FileSize$qqrr15System@TFileRec
         // 00403214: mov ss:[ebp+0xffffffffffffffec], eax
         // 00403217: lea eax, ss:[ebp+0xfffffffffffff69c]
         // 0040321d: call @System@@FileSize$qqrr15System@TFileRec
         // 00403222: mov edx, eax
         // 00403224: lea eax, ss:[ebp+0xfffffffffffffff0]
         // 00403227: call @System@@LStrSetLength$qqrv
         // 0040322c: push 0x0
         // 0040322e: lea eax, ss:[ebp+0xfffffffffffffff0]
         // 00403231: call 0x4023d8
         // 00403236: mov edx, eax
         // 00403238: mov ecx, ss:[ebp+0xffffffffffffffec]
         // 0040323b: lea eax, ss:[ebp+0xfffffffffffff69c]
         // 00403241: call @System@@BlockRead$qqrr15System@TFileRecpviri
         // 00403246: lea eax, ss:[ebp+0xfffffffffffff69c]
         // 0040324c: call @System@@Close$qqrr15System@TTextRec
         // 00403251: mov edx, ss:[ebp+0xfffffffffffffff0]
         // 00403254: mov eax, _str_BagarBubba.Len
         // 00403259: call 0x402468
         // 0040325e: test eax, eax
         // 00403260: jg 0x403568
      [-]8d85????????ba????????e8faf7ffff6a0068????????6a016a006a0268????????8d85????????b9c03540008b55fce83defffff8b85????????e8def0ffff50e83cf7ffff89038d95????????33c0e819e1ffff8b85????????e836feffffa3????????8d95????????a1????????83c011e836fdffff8b95????????b8????????e882edffff6a0068????????6a036a006a0168????????a1????????e87af0ffff50e8d8f6ffff8906
         // 00403266: lea eax, ss:[ebp+0xfffffffffffff7eb]
         // 0040326c: mov edx, 0x801
         // 00403271: call @Windows@ZeroMemory$qqrpvui
         // 00403276: push 0x0
         // 00403278: push 0x80
         // 0040327d: push 0x1
         // 0040327f: push 0x0
         // 00403281: push 0x2
         // 00403283: push 0x40000000
         // 00403288: lea eax, ss:[ebp+0xfffffffffffff698]
         // 0040328e: mov ecx, _str___0.Len
         // 00403293: mov edx, ss:[ebp+0xfffffffffffffffc]
         // 00403296: call @System@@LStrCat3$qqrv
         // 0040329b: mov eax, ss:[ebp+0xfffffffffffff698]
         // 004032a1: call @System@@LStrToPChar$qqrx17System@AnsiString
         // 004032a6: push eax
         // 004032a7: call CreateFileA
         // 004032ac: mov ds:[ebx], eax
         // 004032ae: lea edx, ss:[ebp+0xfffffffffffff694]
         // 004032b4: xor eax, eax
         // 004032b6: call @System@ParamStr$qqri
         // 004032bb: mov eax, ss:[ebp+0xfffffffffffff694]
         // 004032c1: call 0x4030fc
         // 004032c6: mov ds:[0x4065ec], eax
         // 004032cb: lea edx, ss:[ebp+0xfffffffffffff690]
         // 004032d1: mov eax, ds:[0x4065ec]
         // 004032d6: add eax, 0x11
         // 004032d9: call 0x403014
         // 004032de: mov edx, ss:[ebp+0xfffffffffffff690]
         // 004032e4: mov eax, 0x4065f0
         // 004032e9: call 0x402070
         // 004032ee: push 0x0
         // 004032f0: push 0x80
         // 004032f5: push 0x3
         // 004032f7: push 0x0
         // 004032f9: push 0x1
         // 004032fb: push 0xffffffff80000000
         // 00403300: mov eax, ds:[0x4065f0]
         // 00403305: call @System@@LStrToPChar$qqrx17System@AnsiString
         // 0040330a: push eax
         // 0040330b: call CreateFileA
         // 00403310: mov ds:[esi], eax
      [-]6a008d45f85068????????8d85????????508b0650e834f7ffff6a008d45f4508b45f8508d85????????508b0350e823f7ffff837df40075c7
         // 00403312: push 0x0
         // 00403314: lea eax, ss:[ebp+0xfffffffffffffff8]
         // 00403317: push eax
         // 00403318: push 0x800
         // 0040331d: lea eax, ss:[ebp+0xfffffffffffff7eb]
         // 00403323: push eax
         // 00403324: mov eax, ds:[esi]
         // 00403326: push eax
         // 00403327: call ReadFile
         // 0040332c: push 0x0
         // 0040332e: lea eax, ss:[ebp+0xfffffffffffffff4]
         // 00403331: push eax
         // 00403332: mov eax, ss:[ebp+0xfffffffffffffff8]
         // 00403335: push eax
         // 00403336: lea eax, ss:[ebp+0xfffffffffffff7eb]
         // 0040333c: push eax
         // 0040333d: mov eax, ds:[ebx]
         // 0040333f: push eax
         // 00403340: call WriteFile
         // 00403345: cmp ss:[ebp+0xfffffffffffffff4], 0x0
         // 00403349: jnz 0x403312
      [-]8b0650e885f6ffff8b45fce8a1fdffffa3????????8d95????????a1????????83c011e8a1fcffff8b95????????b8????????e8edecffffc707????????33c08947048b45fce8c6fcffff89470889570cc6471000a1????????56578d701183c711b9????????f3a5a45f5e6a008d45f45068????????578b0350e89df6ffff6a0068????????6a036a006a0168????????a1????????e89defffff50e8fbf5ffff8906
         // 0040334b: mov eax, ds:[esi]
         // 0040334d: push eax
         // 0040334e: call CloseHandle
         // 00403353: mov eax, ss:[ebp+0xfffffffffffffffc]
         // 00403356: call 0x4030fc
         // 0040335b: mov ds:[0x4065ec], eax
         // 00403360: lea edx, ss:[ebp+0xfffffffffffff68c]
         // 00403366: mov eax, ds:[0x4065ec]
         // 0040336b: add eax, 0x11
         // 0040336e: call 0x403014
         // 00403373: mov edx, ss:[ebp+0xfffffffffffff68c]
         // 00403379: mov eax, 0x4065f0
         // 0040337e: call 0x402070
         // 00403383: mov ds:[edi], 0xfffffffffeedbeef
         // 00403389: xor eax, eax
         // 0040338b: mov ds:[edi+0x4], eax
         // 0040338e: mov eax, ss:[ebp+0xfffffffffffffffc]
         // 00403391: call 0x40305c
         // 00403396: mov ds:[edi+0x8], eax
         // 00403399: mov ds:[edi+0xc], edx
         // 0040339c: mov b1 ds:[edi+0x10], b1 0x0
         // 004033a0: mov eax, ds:[0x4065ec]
         // 004033a5: push esi
         // 004033a6: push edi
         // 004033a7: lea esi, ds:[eax+0x11]
         // 004033aa: add edi, 0x11
         // 004033ad: mov ecx, 0x41
         // 004033b2: rep movsdd 
         // 004033b4: movsbb 
         // 004033b5: pop edi
         // 004033b6: pop esi
         // 004033b7: push 0x0
         // 004033b9: lea eax, ss:[ebp+0xfffffffffffffff4]
         // 004033bc: push eax
         // 004033bd: push 0x118
         // 004033c2: push edi
         // 004033c3: mov eax, ds:[ebx]
         // 004033c5: push eax
         // 004033c6: call WriteFile
         // 004033cb: push 0x0
         // 004033cd: push 0x80
         // 004033d2: push 0x3
         // 004033d4: push 0x0
         // 004033d6: push 0x1
         // 004033d8: push 0xffffffff80000000
         // 004033dd: mov eax, ds:[0x4065f0]
         // 004033e2: call @System@@LStrToPChar$qqrx17System@AnsiString
         // 004033e7: push eax
         // 004033e8: call CreateFileA
         // 004033ed: mov ds:[esi], eax
      [-]6a008d45f85068????????8d85????????508b0650e857f6ffff6a008d45f4508b45f8508d85????????508b0350e846f6ffff837df40075c7
         // 004033ef: push 0x0
         // 004033f1: lea eax, ss:[ebp+0xfffffffffffffff8]
         // 004033f4: push eax
         // 004033f5: push 0x800
         // 004033fa: lea eax, ss:[ebp+0xfffffffffffff7eb]
         // 00403400: push eax
         // 00403401: mov eax, ds:[esi]
         // 00403403: push eax
         // 00403404: call ReadFile
         // 00403409: push 0x0
         // 0040340b: lea eax, ss:[ebp+0xfffffffffffffff4]
         // 0040340e: push eax
         // 0040340f: mov eax, ss:[ebp+0xfffffffffffffff8]
         // 00403412: push eax
         // 00403413: lea eax, ss:[ebp+0xfffffffffffff7eb]
         // 00403419: push eax
         // 0040341a: mov eax, ds:[ebx]
         // 0040341c: push eax
         // 0040341d: call WriteFile
         // 00403422: cmp ss:[ebp+0xfffffffffffffff4], 0x0
         // 00403426: jnz 0x4033ef
      [-]8b0650e8a8f5ffff8d95????????33c0e897dfffff8b85????????e8b4fcffffa3????????8d95????????a1????????83c011e8b4fbffff8b95????????b8????????e800ecffff8d95????????33c0e857dfffff8b85????????e8d4fbffff8905????????8915????????c707????????33c08947048b05????????8947088b05????????89470cc64710018d471133c9ba????????e888e3ffff6a008d45f45068????????578b0350e890f5ffff8d45f0baac354000e8cfebffff6a008d45f4508b45f0e899ecffff508d45f0e8dceeffff508b0350e863f5ffff8b0350e8cbf4ffff8b45fce86feeffff8bd853e8fbf4ffff6a00538d85????????b9c03540008b55fce8a5ecffff8b85????????e846eeffff50e89cf4ffff8d85????????b9c03540008b55fce881ecffff8b85????????e822eeffff50e8b0f4ffff
         // 00403428: mov eax, ds:[esi]
         // 0040342a: push eax
         // 0040342b: call CloseHandle
         // 00403430: lea edx, ss:[ebp+0xfffffffffffff688]
         // 00403436: xor eax, eax
         // 00403438: call @System@ParamStr$qqri
         // 0040343d: mov eax, ss:[ebp+0xfffffffffffff688]
         // 00403443: call 0x4030fc
         // 00403448: mov ds:[0x4065ec], eax
         // 0040344d: lea edx, ss:[ebp+0xfffffffffffff684]
         // 00403453: mov eax, ds:[0x4065ec]
         // 00403458: add eax, 0x11
         // 0040345b: call 0x403014
         // 00403460: mov edx, ss:[ebp+0xfffffffffffff684]
         // 00403466: mov eax, 0x4065f0
         // 0040346b: call 0x402070
         // 00403470: lea edx, ss:[ebp+0xfffffffffffff680]
         // 00403476: xor eax, eax
         // 00403478: call @System@ParamStr$qqri
         // 0040347d: mov eax, ss:[ebp+0xfffffffffffff680]
         // 00403483: call 0x40305c
         // 00403488: mov ds:[0x4065f4], eax
         // 0040348e: mov ds:[0x4065f8], edx
         // 00403494: mov ds:[edi], 0xfffffffffeedbeef
         // 0040349a: xor eax, eax
         // 0040349c: mov ds:[edi+0x4], eax
         // 0040349f: mov eax, ds:[0x4065f4]
         // 004034a5: mov ds:[edi+0x8], eax
         // 004034a8: mov eax, ds:[0x4065f8]
         // 004034ae: mov ds:[edi+0xc], eax
         // 004034b1: mov b1 ds:[edi+0x10], b1 0x1
         // 004034b5: lea eax, ds:[edi+0x11]
         // 004034b8: xor ecx, ecx
         // 004034ba: mov edx, 0x105
         // 004034bf: call @System@@FillChar$qqrpvic
         // 004034c4: push 0x0
         // 004034c6: lea eax, ss:[ebp+0xfffffffffffffff4]
         // 004034c9: push eax
         // 004034ca: push 0x118
         // 004034cf: push edi
         // 004034d0: mov eax, ds:[ebx]
         // 004034d2: push eax
         // 004034d3: call WriteFile
         // 004034d8: lea eax, ss:[ebp+0xfffffffffffffff0]
         // 004034db: mov edx, _str_BagarBubba.Len
         // 004034e0: call 0x4020b4
         // 004034e5: push 0x0
         // 004034e7: lea eax, ss:[ebp+0xfffffffffffffff4]
         // 004034ea: push eax
         // 004034eb: mov eax, ss:[ebp+0xfffffffffffffff0]
         // 004034ee: call 0x40218c
         // 004034f3: push eax
         // 004034f4: lea eax, ss:[ebp+0xfffffffffffffff0]
         // 004034f7: call 0x4023d8
         // 004034fc: push eax
         // 004034fd: mov eax, ds:[ebx]
         // 004034ff: push eax
         // 00403500: call WriteFile
         // 00403505: mov eax, ds:[ebx]
         // 00403507: push eax
         // 00403508: call CloseHandle
         // 0040350d: mov eax, ss:[ebp+0xfffffffffffffffc]
         // 00403510: call @System@@LStrToPChar$qqrx17System@AnsiString
         // 00403515: mov ebx, eax
         // 00403517: push ebx
         // 00403518: call DeleteFileA
         // 0040351d: push 0x0
         // 0040351f: push ebx
         // 00403520: lea eax, ss:[ebp+0xfffffffffffff67c]
         // 00403526: mov ecx, _str___0.Len
         // 0040352b: mov edx, ss:[ebp+0xfffffffffffffffc]
         // 0040352e: call @System@@LStrCat3$qqrv
         // 00403533: mov eax, ss:[ebp+0xfffffffffffff67c]
         // 00403539: call @System@@LStrToPChar$qqrx17System@AnsiString
         // 0040353e: push eax
         // 0040353f: call CopyFileA
         // 00403544: lea eax, ss:[ebp+0xfffffffffffff678]
         // 0040354a: mov ecx, _str___0.Len
         // 0040354f: mov edx, ss:[ebp+0xfffffffffffffffc]
         // 00403552: call @System@@LStrCat3$qqrv
         // 00403557: mov eax, ss:[ebp+0xfffffffffffff678]
         // 0040355d: call @System@@LStrToPChar$qqrx17System@AnsiString
         // 00403562: push eax
         // 00403563: call DeleteFileA
      [-]33c05a595964891068????????8d85????????ba????????e8bbeaffff8d45f0e88feaffff8d45fce887eaffffc3
         // 00403568: xor eax, eax
         // 0040356a: pop edx
         // 0040356b: pop ecx
         // 0040356c: pop ecx
         // 0040356d: mov fs:[eax], edx
         // 00403570: push 0x40359d
         // 00403575: lea eax, ss:[ebp+0xfffffffffffff678]
         // 0040357b: mov edx, 0x9
         // 00403580: call 0x402040
         // 00403585: lea eax, ss:[ebp+0xfffffffffffffff0]
         // 00403588: call 0x40201c
         // 0040358d: lea eax, ss:[ebp+0xfffffffffffffffc]
         // 00403590: call 0x40201c
         // 00403595: retn 
      [-]5f5e5b8be55dc3
         // 0040359d: pop edi
         // 0040359e: pop esi
         // 0040359f: pop ebx
         // 004035a0: mov esp, ebp
         // 004035a2: pop ebp
         // 004035a3: retn 
      [-]558bec83c4f8538bd8eb18
         // 004035f4: push ebp
         // 004035f5: mov ebp, esp
         // 004035f7: add esp, 0xfffffffffffffff8
         // 004035fa: push ebx
         // 004035fb: mov ebx, eax
         // 004035fd: jmp 0x403617
      [-]8d4318508b431450e83cf4ffff85c07507
         // 004035ff: lea eax, ds:[ebx+0x18]
         // 00403602: push eax
         // 00403603: mov eax, ds:[ebx+0x14]
         // 00403606: push eax
         // 00403607: call FindNextFileA
         // 0040360c: test eax, eax
         // 0040360e: jnz 0x403617
      [-]e83bf4ffffeb41
         // 00403610: call GetLastError
         // 00403615: jmp 0x403658
      [-]8b431823431075e0
         // 00403617: mov eax, ds:[ebx+0x18]
         // 0040361a: and eax, ds:[ebx+0x10]
         // 0040361d: jnz 0x4035ff
      [-]8d45f8508d432c50e804f4ffff538d4302508d45f850e8eef3ffff8b43388943048b43188943088d430c8d5344b9????????e81eebffff33c0
         // 0040361f: lea eax, ss:[ebp+0xfffffffffffffff8]
         // 00403622: push eax
         // 00403623: lea eax, ds:[ebx+0x2c]
         // 00403626: push eax
         // 00403627: call FileTimeToLocalFileTime
         // 0040362c: push ebx
         // 0040362d: lea eax, ds:[ebx+0x2]
         // 00403630: push eax
         // 00403631: lea eax, ss:[ebp+0xfffffffffffffff8]
         // 00403634: push eax
         // 00403635: call FileTimeToDosDateTime
         // 0040363a: mov eax, ds:[ebx+0x38]
         // 0040363d: mov ds:[ebx+0x4], eax
         // 00403640: mov eax, ds:[ebx+0x18]
         // 00403643: mov ds:[ebx+0x8], eax
         // 00403646: lea eax, ds:[ebx+0xc]
         // 00403649: lea edx, ds:[ebx+0x44]
         // 0040364c: mov ecx, 0x104
         // 00403651: call 0x402174
         // 00403656: xor eax, eax
      [-]5b59595dc3
         // 00403658: pop ebx
         // 00403659: pop ecx
         // 0040365a: pop ecx
         // 0040365b: pop ebp
         // 0040365c: retn 
      [-]558bec51b9????????
         // 004036f0: push ebp
         // 004036f1: mov ebp, esp
         // 004036f3: push ecx
         // 004036f4: mov ecx, 0x36
      [-]6a006a004975f9
         // 004036f9: push 0x0
         // 004036fb: push 0x0
         // 004036fd: dec ecx
         // 004036fe: jnz 0x4036f9
      [-]874dfc53894df48955f88945fc8b45fce85fecffff8b45f8e857ecffff8b45f4e84fecffff8d85????????8b15????????e8deedffff33c05568????????64ff306489208b45fce840eaffff8b55fc807c02ff5c740d
         // 00403700: xchg ecx, ss:[ebp+0xfffffffffffffffc]
         // 00403703: push ebx
         // 00403704: mov ss:[ebp+0xfffffffffffffff4], ecx
         // 00403707: mov ss:[ebp+0xfffffffffffffff8], edx
         // 0040370a: mov ss:[ebp+0xfffffffffffffffc], eax
         // 0040370d: mov eax, ss:[ebp+0xfffffffffffffffc]
         // 00403710: call 0x402374
         // 00403715: mov eax, ss:[ebp+0xfffffffffffffff8]
         // 00403718: call 0x402374
         // 0040371d: mov eax, ss:[ebp+0xfffffffffffffff4]
         // 00403720: call 0x402374
         // 00403725: lea eax, ss:[ebp+0xfffffffffffffe9c]
         // 0040372b: mov edx, ds:[0x4035d4]
         // 00403731: call 0x402514
         // 00403736: xor eax, eax
         // 00403738: push ebp
         // 00403739: push 0x403b4e
         // 0040373e: push fs:[eax]
         // 00403741: mov fs:[eax], esp
         // 00403744: mov eax, ss:[ebp+0xfffffffffffffffc]
         // 00403747: call 0x40218c
         // 0040374c: mov edx, ss:[ebp+0xfffffffffffffffc]
         // 0040374f: cmp b1 ds:[edx+eax+0xffffffffffffffff], b1 0x5c
         // 00403754: jz 0x403763
      [-]8d45fcba683b4000e831eaffff
         // 00403756: lea eax, ss:[ebp+0xfffffffffffffffc]
         // 00403759: mov edx, _str___1.Len
         // 0040375e: call @System@@LStrCat$qqrv
      [-]8d85????????b9743b40008b55fce862eaffff8b85????????8d8d????????ba????????e8f0feffff85c00f85d6020000
         // 00403763: lea eax, ss:[ebp+0xfffffffffffffe98]
         // 00403769: mov ecx, _str__._.Len
         // 0040376e: mov edx, ss:[ebp+0xfffffffffffffffc]
         // 00403771: call @System@@LStrCat3$qqrv
         // 00403776: mov eax, ss:[ebp+0xfffffffffffffe98]
         // 0040377c: lea ecx, ss:[ebp+0xfffffffffffffe9c]
         // 00403782: mov edx, 0x10
         // 00403787: call @Sysutils@FindFirst$qqrx17System@AnsiStringir19Sysutils@TSearchRec
         // 0040378c: test eax, eax
         // 0040378e: jnz 0x403a6a
      [-]8b85????????83e01083f810753f
         // 00403794: mov eax, ss:[ebp+0xfffffffffffffea4]
         // 0040379a: and eax, 0x10
         // 0040379d: cmp eax, 0x10
         // 004037a0: jnz 0x4037e1
      [-]8b85????????80382e7434
         // 004037a2: mov eax, ss:[ebp+0xfffffffffffffea8]
         // 004037a8: cmp b1 ds:[eax], b1 0x2e
         // 004037ab: jz 0x4037e1
      [-]ff75fcffb5????????68683b40008d85????????ba????????e881eaffff8b85????????8b4df48b55f8e814ffffffe976020000
         // 004037ad: push ss:[ebp+0xfffffffffffffffc]
         // 004037b0: push ss:[ebp+0xfffffffffffffea8]
         // 004037b6: push _str___1.Len
         // 004037bb: lea eax, ss:[ebp+0xfffffffffffffe94]
         // 004037c1: mov edx, 0x3
         // 004037c6: call @System@@LStrCatN$qqrv
         // 004037cb: mov eax, ss:[ebp+0xfffffffffffffe94]
         // 004037d1: mov ecx, ss:[ebp+0xfffffffffffffff4]
         // 004037d4: mov edx, ss:[ebp+0xfffffffffffffff8]
         // 004037d7: call 0x4036f0
         // 004037dc: jmp 0x403a57
      [-]8d85????????508b85????????e899e9ffff8bd083ea02b9????????8b85????????e8d8ebffff8b85????????8d95????????e89ff7ffff8b85????????ba803b4000e8a7eaffff751f
         // 004037e1: lea eax, ss:[ebp+0xfffffffffffffe8c]
         // 004037e7: push eax
         // 004037e8: mov eax, ss:[ebp+0xfffffffffffffea8]
         // 004037ee: call 0x40218c
         // 004037f3: mov edx, eax
         // 004037f5: sub edx, 0x2
         // 004037f8: mov ecx, 0x3
         // 004037fd: mov eax, ss:[ebp+0xfffffffffffffea8]
         // 00403803: call @System@@LStrCopy$qqrv
         // 00403808: mov eax, ss:[ebp+0xfffffffffffffe8c]
         // 0040380e: lea edx, ss:[ebp+0xfffffffffffffe90]
         // 00403814: call @Sysutils@LowerCase$qqrx17System@AnsiString
         // 00403819: mov eax, ss:[ebp+0xfffffffffffffe90]
         // 0040381f: mov edx, _str_exe.Len
         // 00403824: call @System@@LStrCmp$qqrv
         // 00403829: jnz 0x40384a
      [-]8d85????????8b8d????????8b55fce899e9ffff8b85????????e82af9ffff
         // 0040382b: lea eax, ss:[ebp+0xfffffffffffffe88]
         // 00403831: mov ecx, ss:[ebp+0xfffffffffffffea8]
         // 00403837: mov edx, ss:[ebp+0xfffffffffffffffc]
         // 0040383a: call @System@@LStrCat3$qqrv
         // 0040383f: mov eax, ss:[ebp+0xfffffffffffffe88]
         // 00403845: call 0x403174
      [-]8d85????????508b85????????e830e9ffff8bd083ea02b9????????8b85????????e86febffff8b85????????8d95????????e836f7ffff8b85????????ba8c3b4000e83eeaffff751f
         // 0040384a: lea eax, ss:[ebp+0xfffffffffffffe80]
         // 00403850: push eax
         // 00403851: mov eax, ss:[ebp+0xfffffffffffffea8]
         // 00403857: call 0x40218c
         // 0040385c: mov edx, eax
         // 0040385e: sub edx, 0x2
         // 00403861: mov ecx, 0x3
         // 00403866: mov eax, ss:[ebp+0xfffffffffffffea8]
         // 0040386c: call @System@@LStrCopy$qqrv
         // 00403871: mov eax, ss:[ebp+0xfffffffffffffe80]
         // 00403877: lea edx, ss:[ebp+0xfffffffffffffe84]
         // 0040387d: call @Sysutils@LowerCase$qqrx17System@AnsiString
         // 00403882: mov eax, ss:[ebp+0xfffffffffffffe84]
         // 00403888: mov edx, _str_scr.Len
         // 0040388d: call @System@@LStrCmp$qqrv
         // 00403892: jnz 0x4038b3
      [-]8d85????????8b8d????????8b55fce830e9ffff8b85????????e8c1f8ffff
         // 00403894: lea eax, ss:[ebp+0xfffffffffffffe7c]
         // 0040389a: mov ecx, ss:[ebp+0xfffffffffffffea8]
         // 004038a0: mov edx, ss:[ebp+0xfffffffffffffffc]
         // 004038a3: call @System@@LStrCat3$qqrv
         // 004038a8: mov eax, ss:[ebp+0xfffffffffffffe7c]
         // 004038ae: call 0x403174
      [-]8d85????????508b85????????e8c7e8ffff8bd083ea02b9????????8b85????????e806ebffff8b85????????8d95????????e8cdf6ffff8b85????????ba983b4000e8d5e9ffff751f
         // 004038b3: lea eax, ss:[ebp+0xfffffffffffffe74]
         // 004038b9: push eax
         // 004038ba: mov eax, ss:[ebp+0xfffffffffffffea8]
         // 004038c0: call 0x40218c
         // 004038c5: mov edx, eax
         // 004038c7: sub edx, 0x2
         // 004038ca: mov ecx, 0x3
         // 004038cf: mov eax, ss:[ebp+0xfffffffffffffea8]
         // 004038d5: call @System@@LStrCopy$qqrv
         // 004038da: mov eax, ss:[ebp+0xfffffffffffffe74]
         // 004038e0: lea edx, ss:[ebp+0xfffffffffffffe78]
         // 004038e6: call @Sysutils@LowerCase$qqrx17System@AnsiString
         // 004038eb: mov eax, ss:[ebp+0xfffffffffffffe78]
         // 004038f1: mov edx, _str_com.Len
         // 004038f6: call @System@@LStrCmp$qqrv
         // 004038fb: jnz 0x40391c
      [-]8d85????????8b8d????????8b55fce8c7e8ffff8b85????????e858f8ffff
         // 004038fd: lea eax, ss:[ebp+0xfffffffffffffe70]
         // 00403903: mov ecx, ss:[ebp+0xfffffffffffffea8]
         // 00403909: mov edx, ss:[ebp+0xfffffffffffffffc]
         // 0040390c: call @System@@LStrCat3$qqrv
         // 00403911: mov eax, ss:[ebp+0xfffffffffffffe70]
         // 00403917: call 0x403174
      [-]8d85????????508b85????????e85ee8ffff8bd083ea02b9????????8b85????????e89deaffff8b85????????8d95????????e864f6ffff8b85????????baa43b4000e86ce9ffff751f
         // 0040391c: lea eax, ss:[ebp+0xfffffffffffffe68]
         // 00403922: push eax
         // 00403923: mov eax, ss:[ebp+0xfffffffffffffea8]
         // 00403929: call 0x40218c
         // 0040392e: mov edx, eax
         // 00403930: sub edx, 0x2
         // 00403933: mov ecx, 0x3
         // 00403938: mov eax, ss:[ebp+0xfffffffffffffea8]
         // 0040393e: call @System@@LStrCopy$qqrv
         // 00403943: mov eax, ss:[ebp+0xfffffffffffffe68]
         // 00403949: lea edx, ss:[ebp+0xfffffffffffffe6c]
         // 0040394f: call @Sysutils@LowerCase$qqrx17System@AnsiString
         // 00403954: mov eax, ss:[ebp+0xfffffffffffffe6c]
         // 0040395a: mov edx, _str_pif.Len
         // 0040395f: call @System@@LStrCmp$qqrv
         // 00403964: jnz 0x403985
      [-]8d85????????8b8d????????8b55fce85ee8ffff8b85????????e8eff7ffff
         // 00403966: lea eax, ss:[ebp+0xfffffffffffffe64]
         // 0040396c: mov ecx, ss:[ebp+0xfffffffffffffea8]
         // 00403972: mov edx, ss:[ebp+0xfffffffffffffffc]
         // 00403975: call @System@@LStrCat3$qqrv
         // 0040397a: mov eax, ss:[ebp+0xfffffffffffffe64]
         // 00403980: call 0x403174
      [-]8d85????????508b85????????e8f5e7ffff8bd083ea02b9????????8b85????????e834eaffff8b85????????8d95????????e8fbf5ffff8b85????????bab03b4000e803e9ffff751f
         // 00403985: lea eax, ss:[ebp+0xfffffffffffffe5c]
         // 0040398b: push eax
         // 0040398c: mov eax, ss:[ebp+0xfffffffffffffea8]
         // 00403992: call 0x40218c
         // 00403997: mov edx, eax
         // 00403999: sub edx, 0x2
         // 0040399c: mov ecx, 0x3
         // 004039a1: mov eax, ss:[ebp+0xfffffffffffffea8]
         // 004039a7: call @System@@LStrCopy$qqrv
         // 004039ac: mov eax, ss:[ebp+0xfffffffffffffe5c]
         // 004039b2: lea edx, ss:[ebp+0xfffffffffffffe60]
         // 004039b8: call @Sysutils@LowerCase$qqrx17System@AnsiString
         // 004039bd: mov eax, ss:[ebp+0xfffffffffffffe60]
         // 004039c3: mov edx, _str_cmd.Len
         // 004039c8: call @System@@LStrCmp$qqrv
         // 004039cd: jnz 0x4039ee
      [-]8d85????????8b8d????????8b55fce8f5e7ffff8b85????????e886f7ffff
         // 004039cf: lea eax, ss:[ebp+0xfffffffffffffe58]
         // 004039d5: mov ecx, ss:[ebp+0xfffffffffffffea8]
         // 004039db: mov edx, ss:[ebp+0xfffffffffffffffc]
         // 004039de: call @System@@LStrCat3$qqrv
         // 004039e3: mov eax, ss:[ebp+0xfffffffffffffe58]
         // 004039e9: call 0x403174
      [-]8d85????????508b85????????e88ce7ffff8bd083ea02b9????????8b85????????e8cbe9ffff8b85????????8d95????????e892f5ffff8b85????????babc3b4000e89ae8ffff751f
         // 004039ee: lea eax, ss:[ebp+0xfffffffffffffe50]
         // 004039f4: push eax
         // 004039f5: mov eax, ss:[ebp+0xfffffffffffffea8]
         // 004039fb: call 0x40218c
         // 00403a00: mov edx, eax
         // 00403a02: sub edx, 0x2
         // 00403a05: mov ecx, 0x3
         // 00403a0a: mov eax, ss:[ebp+0xfffffffffffffea8]
         // 00403a10: call @System@@LStrCopy$qqrv
         // 00403a15: mov eax, ss:[ebp+0xfffffffffffffe50]
         // 00403a1b: lea edx, ss:[ebp+0xfffffffffffffe54]
         // 00403a21: call @Sysutils@LowerCase$qqrx17System@AnsiString
         // 00403a26: mov eax, ss:[ebp+0xfffffffffffffe54]
         // 00403a2c: mov edx, _str_bat.Len
         // 00403a31: call @System@@LStrCmp$qqrv
         // 00403a36: jnz 0x403a57
      [-]8d85????????8b8d????????8b55fce88ce7ffff8b85????????e81df7ffff
         // 00403a38: lea eax, ss:[ebp+0xfffffffffffffe4c]
         // 00403a3e: mov ecx, ss:[ebp+0xfffffffffffffea8]
         // 00403a44: mov edx, ss:[ebp+0xfffffffffffffffc]
         // 00403a47: call @System@@LStrCat3$qqrv
         // 00403a4c: mov eax, ss:[ebp+0xfffffffffffffe4c]
         // 00403a52: call 0x403174
      [-]8d85????????e86afcffff85c00f842afdffff
         // 00403a57: lea eax, ss:[ebp+0xfffffffffffffe9c]
         // 00403a5d: call @Sysutils@FindNext$qqrr19Sysutils@TSearchRec
         // 00403a62: test eax, eax
         // 00403a64: jz 0x403794
      [-]8d85????????e8ebfbffff33c05a595964891068????????8d85????????e88fe5ffff8d85????????e884e5ffff8d85????????ba????????e898e5ffff8d85????????e869e5ffff8d85????????ba????????e87de5ffff8d85????????e84ee5ffff8d85????????ba????????e862e5ffff8d85????????e833e5ffff8d85????????ba????????e847e5ffff8d85????????e818e5ffff8d85????????ba????????e82ce5ffff8d85????????e8fde4ffff8d85????????ba????????e811e5ffff8d85????????8b15????????e898eaffff8d45f4ba????????e8f3e4ffffc3
         // 00403a6a: lea eax, ss:[ebp+0xfffffffffffffe9c]
         // 00403a70: call @Sysutils@FindClose$qqrr19Sysutils@TSearchRec
         // 00403a75: xor eax, eax
         // 00403a77: pop edx
         // 00403a78: pop ecx
         // 00403a79: pop ecx
         // 00403a7a: mov fs:[eax], edx
         // 00403a7d: push 0x403b58
         // 00403a82: lea eax, ss:[ebp+0xfffffffffffffe4c]
         // 00403a88: call 0x40201c
         // 00403a8d: lea eax, ss:[ebp+0xfffffffffffffe50]
         // 00403a93: call 0x40201c
         // 00403a98: lea eax, ss:[ebp+0xfffffffffffffe54]
         // 00403a9e: mov edx, 0x2
         // 00403aa3: call 0x402040
         // 00403aa8: lea eax, ss:[ebp+0xfffffffffffffe5c]
         // 00403aae: call 0x40201c
         // 00403ab3: lea eax, ss:[ebp+0xfffffffffffffe60]
         // 00403ab9: mov edx, 0x2
         // 00403abe: call 0x402040
         // 00403ac3: lea eax, ss:[ebp+0xfffffffffffffe68]
         // 00403ac9: call 0x40201c
         // 00403ace: lea eax, ss:[ebp+0xfffffffffffffe6c]
         // 00403ad4: mov edx, 0x2
         // 00403ad9: call 0x402040
         // 00403ade: lea eax, ss:[ebp+0xfffffffffffffe74]
         // 00403ae4: call 0x40201c
         // 00403ae9: lea eax, ss:[ebp+0xfffffffffffffe78]
         // 00403aef: mov edx, 0x2
         // 00403af4: call 0x402040
         // 00403af9: lea eax, ss:[ebp+0xfffffffffffffe80]
         // 00403aff: call 0x40201c
         // 00403b04: lea eax, ss:[ebp+0xfffffffffffffe84]
         // 00403b0a: mov edx, 0x2
         // 00403b0f: call 0x402040
         // 00403b14: lea eax, ss:[ebp+0xfffffffffffffe8c]
         // 00403b1a: call 0x40201c
         // 00403b1f: lea eax, ss:[ebp+0xfffffffffffffe90]
         // 00403b25: mov edx, 0x3
         // 00403b2a: call 0x402040
         // 00403b2f: lea eax, ss:[ebp+0xfffffffffffffe9c]
         // 00403b35: mov edx, ds:[0x4035d4]
         // 00403b3b: call @System@@FinalizeRecord$qqrpvt1
         // 00403b40: lea eax, ss:[ebp+0xfffffffffffffff4]
         // 00403b43: mov edx, 0x3
         // 00403b48: call 0x402040
         // 00403b4d: retn 
      [-]5b8be55dc3
         // 00403b58: pop ebx
         // 00403b59: mov esp, ebp
         // 00403b5b: pop ebp
         // 00403b5c: retn 
      [-]558bec81c4????????5333d28995????????8bd833c05568????????64ff3064892068????????8d85????????50e865eeffff8d85????????8d95????????b9????????e86be5ffff8b95????????8bc3b9483c4000e8bde5ffff33c05a595964891068????????8d85????????e8e9e3ffffc3
         // 00403bc0: push ebp
         // 00403bc1: mov ebp, esp
         // 00403bc3: add esp, 0xfffffffffffffef8
         // 00403bc9: push ebx
         // 00403bca: xor edx, edx
         // 00403bcc: mov ss:[ebp+0xfffffffffffffef8], edx
         // 00403bd2: mov ebx, eax
         // 00403bd4: xor eax, eax
         // 00403bd6: push ebp
         // 00403bd7: push 0x403c34
         // 00403bdc: push fs:[eax]
         // 00403bdf: mov fs:[eax], esp
         // 00403be2: push 0xff
         // 00403be7: lea eax, ss:[ebp+0xfffffffffffffeff]
         // 00403bed: push eax
         // 00403bee: call GetWindowsDirectoryA
         // 00403bf3: lea eax, ss:[ebp+0xfffffffffffffef8]
         // 00403bf9: lea edx, ss:[ebp+0xfffffffffffffeff]
         // 00403bff: mov ecx, 0x101
         // 00403c04: call 0x402174
         // 00403c09: mov edx, ss:[ebp+0xfffffffffffffef8]
         // 00403c0f: mov eax, ebx
         // 00403c11: mov ecx, _str___2.Len
         // 00403c16: call @System@@LStrCat3$qqrv
         // 00403c1b: xor eax, eax
         // 00403c1d: pop edx
         // 00403c1e: pop ecx
         // 00403c1f: pop ecx
         // 00403c20: mov fs:[eax], edx
         // 00403c23: push 0x403c3b
         // 00403c28: lea eax, ss:[ebp+0xfffffffffffffef8]
         // 00403c2e: call 0x40201c
         // 00403c33: retn 
      [-]5b8be55dc3
         // 00403c3b: pop ebx
         // 00403c3c: mov esp, ebp
         // 00403c3e: pop ebp
         // 00403c3f: retn 
      [-]558bec81c4????????535633c9894dfc8bf28bd833c05568????????64ff306489208d95????????8bc3e875ddffff8d95????????8d45fce8dfe4ffff8bc68b55fce8dde3ffff33c05a595964891068????????8d45fce874e3ffffc3
         // 00403c4c: push ebp
         // 00403c4d: mov ebp, esp
         // 00403c4f: add esp, 0xfffffffffffffefc
         // 00403c55: push ebx
         // 00403c56: push esi
         // 00403c57: xor ecx, ecx
         // 00403c59: mov ss:[ebp+0xfffffffffffffffc], ecx
         // 00403c5c: mov esi, edx
         // 00403c5e: mov ebx, eax
         // 00403c60: xor eax, eax
         // 00403c62: push ebp
         // 00403c63: push 0x403ca9
         // 00403c68: push fs:[eax]
         // 00403c6b: mov fs:[eax], esp
         // 00403c6e: lea edx, ss:[ebp+0xfffffffffffffefc]
         // 00403c74: mov eax, ebx
         // 00403c76: call 0x4019f0
         // 00403c7b: lea edx, ss:[ebp+0xfffffffffffffefc]
         // 00403c81: lea eax, ss:[ebp+0xfffffffffffffffc]
         // 00403c84: call 0x402168
         // 00403c89: mov eax, esi
         // 00403c8b: mov edx, ss:[ebp+0xfffffffffffffffc]
         // 00403c8e: call 0x402070
         // 00403c93: xor eax, eax
         // 00403c95: pop edx
         // 00403c96: pop ecx
         // 00403c97: pop ecx
         // 00403c98: mov fs:[eax], edx
         // 00403c9b: push 0x403cb0
         // 00403ca0: lea eax, ss:[ebp+0xfffffffffffffffc]
         // 00403ca3: call 0x40201c
         // 00403ca8: retn 
      [-]5e5b8be55dc3
         // 00403cb0: pop esi
         // 00403cb1: pop ebx
         // 00403cb2: mov esp, ebp
         // 00403cb4: pop ebp
         // 00403cb5: retn 
      [-]558bec51538955fc8bd88b45fce8aae6ffff33c05568????????64ff306489208bd3a1????????e840efffff33c98b55fca1????????e895effffff6d81bdb85db740a
         // 00403cb8: push ebp
         // 00403cb9: mov ebp, esp
         // 00403cbb: push ecx
         // 00403cbc: push ebx
         // 00403cbd: mov ss:[ebp+0xfffffffffffffffc], edx
         // 00403cc0: mov ebx, eax
         // 00403cc2: mov eax, ss:[ebp+0xfffffffffffffffc]
         // 00403cc5: call 0x402374
         // 00403cca: xor eax, eax
         // 00403ccc: push ebp
         // 00403ccd: push 0x403d1b
         // 00403cd2: push fs:[eax]
         // 00403cd5: mov fs:[eax], esp
         // 00403cd8: mov edx, ebx
         // 00403cda: mov eax, ds:[0x4064c8]
         // 00403cdf: call @Registry@TRegistry@SetRootKey$qqrui
         // 00403ce4: xor ecx, ecx
         // 00403ce6: mov edx, ss:[ebp+0xfffffffffffffffc]
         // 00403ce9: mov eax, ds:[0x4064c8]
         // 00403cee: call @Registry@TRegistry@OpenKey$qqrx17System@AnsiStringo
         // 00403cf3: neg b1 al
         // 00403cf5: sbb ebx, ebx
         // 00403cf7: test ebx, ebx
         // 00403cf9: jz 0x403d05
      [-]a1????????e8efeeffff
         // 00403cfb: mov eax, ds:[0x4064c8]
         // 00403d00: call @Registry@TRegistry@CloseKey$qqrv
      [-]33c05a595964891068????????8d45fce802e3ffffc3
         // 00403d05: xor eax, eax
         // 00403d07: pop edx
         // 00403d08: pop ecx
         // 00403d09: pop ecx
         // 00403d0a: mov fs:[eax], edx
         // 00403d0d: push 0x403d22
         // 00403d12: lea eax, ss:[ebp+0xfffffffffffffffc]
         // 00403d15: call 0x40201c
         // 00403d1a: retn 
      [-]8bc35b595dc3
         // 00403d22: mov eax, ebx
         // 00403d24: pop ebx
         // 00403d25: pop ecx
         // 00403d26: pop ebp
         // 00403d27: retn 
      [-]558bec6a0053568bd833c05568????????64ff30648920ba????????a1????????e8d6eeffff33c9badc3d4000a1????????e829efffff8bcbba143e4000a1????????e8e0f0ffff8b13b82c3e4000e8ece6ffff8bf06685f67625
         // 00403d28: push ebp
         // 00403d29: mov ebp, esp
         // 00403d2b: push 0x0
         // 00403d2d: push ebx
         // 00403d2e: push esi
         // 00403d2f: mov ebx, eax
         // 00403d31: xor eax, eax
         // 00403d33: push ebp
         // 00403d34: push 0x403dc8
         // 00403d39: push fs:[eax]
         // 00403d3c: mov fs:[eax], esp
         // 00403d3f: mov edx, 0xffffffff80000002
         // 00403d44: mov eax, ds:[0x4064c8]
         // 00403d49: call @Registry@TRegistry@SetRootKey$qqrui
         // 00403d4e: xor ecx, ecx
         // 00403d50: mov edx, _str_Windows_Current.Len
         // 00403d55: mov eax, ds:[0x4064c8]
         // 00403d5a: call @Registry@TRegistry@OpenKey$qqrx17System@AnsiStringo
         // 00403d5f: mov ecx, ebx
         // 00403d61: mov edx, _str_UninstallString.Len
         // 00403d66: mov eax, ds:[0x4064c8]
         // 00403d6b: call 0x402e50
         // 00403d70: mov edx, ds:[ebx]
         // 00403d72: mov eax, _str_uninstall.Len
         // 00403d77: call 0x402468
         // 00403d7c: mov esi, eax
         // 00403d7e: test b2 si, b2 si
         // 00403d81: jbe 0x403da8
      [-]8d45fc500fb7ce83e9028b03ba????????e847e6ffff8b55fc8bc3b9403e4000e830e4ffff
         // 00403d83: lea eax, ss:[ebp+0xfffffffffffffffc]
         // 00403d86: push eax
         // 00403d87: movzx ecx, b2 si
         // 00403d8a: sub ecx, 0x2
         // 00403d8d: mov eax, ds:[ebx]
         // 00403d8f: mov edx, 0x2
         // 00403d94: call @System@@LStrCopy$qqrv
         // 00403d99: mov edx, ss:[ebp+0xfffffffffffffffc]
         // 00403d9c: mov eax, ebx
         // 00403d9e: mov ecx, _str__incoming.Len
         // 00403da3: call @System@@LStrCat3$qqrv
      [-]a1????????e842eeffff33c05a595964891068????????8d45fce855e2ffffc3
         // 00403da8: mov eax, ds:[0x4064c8]
         // 00403dad: call @Registry@TRegistry@CloseKey$qqrv
         // 00403db2: xor eax, eax
         // 00403db4: pop edx
         // 00403db5: pop ecx
         // 00403db6: pop ecx
         // 00403db7: mov fs:[eax], edx
         // 00403dba: push 0x403dcf
         // 00403dbf: lea eax, ss:[ebp+0xfffffffffffffffc]
         // 00403dc2: call 0x40201c
         // 00403dc7: retn 
      [-]5e5b595dc3
         // 00403dcf: pop esi
         // 00403dd0: pop ebx
         // 00403dd1: pop ecx
         // 00403dd2: pop ebp
         // 00403dd3: retn 
      [-]558bec6a0053568bd833c05568????????64ff30648920ba????????a1????????e8b2edffff33c9ba003f4000a1????????e805eeffff8bcbba383f4000a1????????e8bcefffff8b13b8503f4000e8c8e5ffff8bf06685f67625
         // 00403e4c: push ebp
         // 00403e4d: mov ebp, esp
         // 00403e4f: push 0x0
         // 00403e51: push ebx
         // 00403e52: push esi
         // 00403e53: mov ebx, eax
         // 00403e55: xor eax, eax
         // 00403e57: push ebp
         // 00403e58: push 0x403eec
         // 00403e5d: push fs:[eax]
         // 00403e60: mov fs:[eax], esp
         // 00403e63: mov edx, 0xffffffff80000002
         // 00403e68: mov eax, ds:[0x4064c8]
         // 00403e6d: call @Registry@TRegistry@SetRootKey$qqrui
         // 00403e72: xor ecx, ecx
         // 00403e74: mov edx, _str_Windows_Current_0.Len
         // 00403e79: mov eax, ds:[0x4064c8]
         // 00403e7e: call @Registry@TRegistry@OpenKey$qqrx17System@AnsiStringo
         // 00403e83: mov ecx, ebx
         // 00403e85: mov edx, _str_UninstallString_0.Len
         // 00403e8a: mov eax, ds:[0x4064c8]
         // 00403e8f: call 0x402e50
         // 00403e94: mov edx, ds:[ebx]
         // 00403e96: mov eax, _str_UNWISE.EXE.Len
         // 00403e9b: call 0x402468
         // 00403ea0: mov esi, eax
         // 00403ea2: test b2 si, b2 si
         // 00403ea5: jbe 0x403ecc
      [-]8d45fc500fb7ce83e9028b03ba????????e823e5ffff8b55fc8bc3b9643f4000e80ce3ffff
         // 00403ea7: lea eax, ss:[ebp+0xfffffffffffffffc]
         // 00403eaa: push eax
         // 00403eab: movzx ecx, b2 si
         // 00403eae: sub ecx, 0x2
         // 00403eb1: mov eax, ds:[ebx]
         // 00403eb3: mov edx, 0x1
         // 00403eb8: call @System@@LStrCopy$qqrv
         // 00403ebd: mov edx, ss:[ebp+0xfffffffffffffffc]
         // 00403ec0: mov eax, ebx
         // 00403ec2: mov ecx, _str__My_Shared_Fold.Len
         // 00403ec7: call @System@@LStrCat3$qqrv
      [-]a1????????e81eedffff33c05a595964891068????????8d45fce831e1ffffc3
         // 00403ecc: mov eax, ds:[0x4064c8]
         // 00403ed1: call @Registry@TRegistry@CloseKey$qqrv
         // 00403ed6: xor eax, eax
         // 00403ed8: pop edx
         // 00403ed9: pop ecx
         // 00403eda: pop ecx
         // 00403edb: mov fs:[eax], edx
         // 00403ede: push 0x403ef3
         // 00403ee3: lea eax, ss:[ebp+0xfffffffffffffffc]
         // 00403ee6: call 0x40201c
         // 00403eeb: retn 
      [-]5e5b595dc3
         // 00403ef3: pop esi
         // 00403ef4: pop ebx
         // 00403ef5: pop ecx
         // 00403ef6: pop ebp
         // 00403ef7: retn 
      [-]558bec33c951515151538bd833c05568????????64ff30648920ba????????a1????????e883ecffff33c9ba6c404000a1????????e8d6ecffff8bcbba84404000a1????????e88deeffff8d45fce8f5fbffff8d45fcba98404000e8bce1ffff8b45fc8b13e886e4ffff85c07536
         // 00403f78: push ebp
         // 00403f79: mov ebp, esp
         // 00403f7b: xor ecx, ecx
         // 00403f7d: push ecx
         // 00403f7e: push ecx
         // 00403f7f: push ecx
         // 00403f80: push ecx
         // 00403f81: push ebx
         // 00403f82: mov ebx, eax
         // 00403f84: xor eax, eax
         // 00403f86: push ebp
         // 00403f87: push 0x404058
         // 00403f8c: push fs:[eax]
         // 00403f8f: mov fs:[eax], esp
         // 00403f92: mov edx, 0xffffffff80000001
         // 00403f97: mov eax, ds:[0x4064c8]
         // 00403f9c: call @Registry@TRegistry@SetRootKey$qqrui
         // 00403fa1: xor ecx, ecx
         // 00403fa3: mov edx, _str__software_Xolox.Len
         // 00403fa8: mov eax, ds:[0x4064c8]
         // 00403fad: call @Registry@TRegistry@OpenKey$qqrx17System@AnsiStringo
         // 00403fb2: mov ecx, ebx
         // 00403fb4: mov edx, _str_shareddirs.Len
         // 00403fb9: mov eax, ds:[0x4064c8]
         // 00403fbe: call 0x402e50
         // 00403fc3: lea eax, ss:[ebp+0xfffffffffffffffc]
         // 00403fc6: call 0x403bc0
         // 00403fcb: lea eax, ss:[ebp+0xfffffffffffffffc]
         // 00403fce: mov edx, _str_Drivers.Len
         // 00403fd3: call @System@@LStrCat$qqrv
         // 00403fd8: mov eax, ss:[ebp+0xfffffffffffffffc]
         // 00403fdb: mov edx, ds:[ebx]
         // 00403fdd: call 0x402468
         // 00403fe2: test eax, eax
         // 00403fe4: jnz 0x40401c
      [-]ff3368a84040008d45f4e8cbfbffffff75f468b44040008d45f8ba????????e842e2ffff8b4df8ba84404000a1????????e808eeffff
         // 00403fe6: push ds:[ebx]
         // 00403fe8: push _str___3.Len
         // 00403fed: lea eax, ss:[ebp+0xfffffffffffffff4]
         // 00403ff0: call 0x403bc0
         // 00403ff5: push ss:[ebp+0xfffffffffffffff4]
         // 00403ff8: push _str_Drivers_.Len
         // 00403ffd: lea eax, ss:[ebp+0xfffffffffffffff8]
         // 00404000: mov edx, 0x4
         // 00404005: call @System@@LStrCatN$qqrv
         // 0040400a: mov ecx, ss:[ebp+0xfffffffffffffff8]
         // 0040400d: mov edx, _str_shareddirs.Len
         // 00404012: mov eax, ds:[0x4064c8]
         // 00404017: call @Registry@TRegistry@WriteString$qqrx17System@AnsiStringt1
      [-]a1????????e8ceebffff8d45f0e892fbffff8b55f08bc3b998404000e89be1ffff33c05a595964891068????????8d45f0ba????????e8e9dfffffc3
         // 0040401c: mov eax, ds:[0x4064c8]
         // 00404021: call @Registry@TRegistry@CloseKey$qqrv
         // 00404026: lea eax, ss:[ebp+0xfffffffffffffff0]
         // 00404029: call 0x403bc0
         // 0040402e: mov edx, ss:[ebp+0xfffffffffffffff0]
         // 00404031: mov eax, ebx
         // 00404033: mov ecx, _str_Drivers.Len
         // 00404038: call @System@@LStrCat3$qqrv
         // 0040403d: xor eax, eax
         // 0040403f: pop edx
         // 00404040: pop ecx
         // 00404041: pop ecx
         // 00404042: mov fs:[eax], edx
         // 00404045: push 0x40405f
         // 0040404a: lea eax, ss:[ebp+0xfffffffffffffff0]
         // 0040404d: mov edx, 0x4
         // 00404052: call 0x402040
         // 00404057: retn 
      [-]5b8be55dc3
         // 0040405f: pop ebx
         // 00404060: mov esp, ebp
         // 00404062: pop ebp
         // 00404063: retn 
      [-]558bec33c951515151515356578bd8bf????????33c05568????????64ff30648920ba????????8b07e836ebffffb101bacc4140008b07e88cebffff33f6
         // 004040c0: push ebp
         // 004040c1: mov ebp, esp
         // 004040c3: xor ecx, ecx
         // 004040c5: push ecx
         // 004040c6: push ecx
         // 004040c7: push ecx
         // 004040c8: push ecx
         // 004040c9: push ecx
         // 004040ca: push ebx
         // 004040cb: push esi
         // 004040cc: push edi
         // 004040cd: mov ebx, eax
         // 004040cf: mov edi, 0x4064c8
         // 004040d4: xor eax, eax
         // 004040d6: push ebp
         // 004040d7: push 0x4041b6
         // 004040dc: push fs:[eax]
         // 004040df: mov fs:[eax], esp
         // 004040e2: mov edx, 0xffffffff80000001
         // 004040e7: mov eax, ds:[edi]
         // 004040e9: call @Registry@TRegistry@SetRootKey$qqrui
         // 004040ee: mov b1 cl, b1 0x1
         // 004040f0: mov edx, _str__software_kazaa.Len
         // 004040f5: mov eax, ds:[edi]
         // 004040f7: call @Registry@TRegistry@OpenKey$qqrx17System@AnsiStringo
         // 004040fc: xor esi, esi
      [-]8d55f80fb7c6e843fbffff8b4df88d45fcbaf4414000e8bfe0ffff468bcb8b55fc8b07e82aedffff833b007410
         // 004040fe: lea edx, ss:[ebp+0xfffffffffffffff8]
         // 00404101: movzx eax, b2 si
         // 00404104: call 0x403c4c
         // 00404109: mov ecx, ss:[ebp+0xfffffffffffffff8]
         // 0040410c: lea eax, ss:[ebp+0xfffffffffffffffc]
         // 0040410f: mov edx, _str_Dir.Len
         // 00404114: call @System@@LStrCat3$qqrv
         // 00404119: inc esi
         // 0040411a: mov ecx, ebx
         // 0040411c: mov edx, ss:[ebp+0xfffffffffffffffc]
         // 0040411f: mov eax, ds:[edi]
         // 00404121: call 0x402e50
         // 00404126: cmp ds:[ebx], 0x0
         // 00404129: jz 0x40413b
      [-]8b13b800424000e831e3ffff85c07ec3
         // 0040412b: mov edx, ds:[ebx]
         // 0040412d: mov eax, _str_Drivers_0.Len
         // 00404132: call 0x402468
         // 00404137: test eax, eax
         // 00404139: jle 0x4040fe
      [-]833b00752f
         // 0040413b: cmp ds:[ebx], 0x0
         // 0040413e: jnz 0x40416f
      [-]68104240008d45f0e873faffffff75f068004240008d45f4ba????????e8eae0ffff8b4df48b55
         // 00404140: push _str_012345:.Len
         // 00404145: lea eax, ss:[ebp+0xfffffffffffffff0]
         // 00404148: call 0x403bc0
         // 0040414d: push ss:[ebp+0xfffffffffffffff0]
         // 00404150: push _str_Drivers_0.Len
         // 00404155: lea eax, ss:[ebp+0xfffffffffffffff4]
         // 00404158: mov edx, 0x3
         // 0040415d: call @System@@LStrCatN$qqrv
         // 00404162: mov ecx, ss:[ebp+0xfffffffffffffff4]
         // 00404165: mov edx, ss:[ebp+0xfffffffffffffffc]
         // 00404168: mov eax, ds:[edi]
         // 0040416a: call @Registry@TRegistry@WriteString$qqrx17System@AnsiStringt1

  }
  condition:
    all of them
}
