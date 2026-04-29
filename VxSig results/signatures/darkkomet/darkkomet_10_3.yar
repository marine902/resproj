rule darkkomet_10_3 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         8900894004c3
         // 00401460: mov ds:[eax], eax
         // 00401462: mov ds:[eax+0x4], eax
         // 00401465: retn 
      [-]8915????????e8b9200000
         // 00402860: mov ds:[0x49b004], edx
         // 00402866: call 0x404924
      [-]53568bf28bd880e37f833d????????00740a
         // 0040286c: push ebx
         // 0040286d: push esi
         // 0040286e: mov esi, edx
         // 00402870: mov ebx, eax
         // 00402872: and b1 bl, b1 0x7f
         // 00402875: cmp ds:[0x49e008], 0x0
         // 0040287c: jz 0x402888
      [-]8bd68bc3ff15????????
         // 0040287e: mov edx, esi
         // 00402880: mov eax, ebx
         // 00402882: call ds:[0x49e008]
      [-]84db750d
         // 00402888: test b1 bl, b1 bl
         // 0040288a: jnz 0x402899
      [-]e84b4400008b98????????eb0f
         // 0040288c: call @Sysinit@@GetTls$qqrv
         // 00402891: mov ebx, ds:[eax+0x4]
         // 00402897: jmp 0x4028a8
      [-]80fb18770a
         // 00402899: cmp b1 bl, b1 0x18
         // 0040289c: ja 0x4028a8
      [-]33c08ac38a9850b04900
         // 0040289e: xor eax, eax
         // 004028a0: mov b1 al, b1 bl
         // 004028a2: mov b1 bl, b1 ds:[eax+0x49b050]
      [-]33c08ac38bd6e8adffffff
         // 004028a8: xor eax, eax
         // 004028aa: mov b1 al, b1 bl
         // 004028ac: mov edx, esi
         // 004028ae: call 0x402860
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
      [-]89c283e21f8d1492dbac53f3374000dec9c1e8057479
         // 00403758: mov edx, eax
         // 0040375a: and edx, 0x1f
         // 0040375d: lea edx, ds:[edx+edx*0x4]
         // 00403760: fld b10 ds:[ebx+edx*0x2]
         // 00403767: fmulp b8 st(1), b10 st(0)
         // 00403769: shr eax, b1 0x5
         // 0040376c: jz 0x4037e7
      [-]89c283e20f740c
         // 0040376e: mov edx, eax
         // 00403770: and edx, 0xf
         // 00403773: jz 0x403781
      [-]8d1492dbac5329394000dec9
         // 00403775: lea edx, ds:[edx+edx*0x4]
         // 00403778: fld b10 ds:[ebx+edx*0x2]
         // 0040377f: fmulp b8 st(1), b10 st(0)
      [-]c1e8047461
         // 00403781: shr eax, b1 0x4
         // 00403784: jz 0x4037e7
      [-]8d0480dbac43bf394000dec9eb53
         // 00403786: lea eax, ds:[eax+eax*0x4]
         // 00403789: fld b10 ds:[ebx+eax*0x2]
         // 00403790: fmulp b8 st(1), b10 st(0)
         // 00403792: jmp 0x4037e7
      [-]f7d83d????????7d46
         // 00403794: neg eax
         // 00403796: cmp eax, 0x1400
         // 0040379b: jge 0x4037e3
      [-]89c283e21f8d1492dbac53f3374000def9c1e8057434
         // 0040379d: mov edx, eax
         // 0040379f: and edx, 0x1f
         // 004037a2: lea edx, ds:[edx+edx*0x4]
         // 004037a5: fld b10 ds:[ebx+edx*0x2]
         // 004037ac: fdivp b8 st(1), b10 st(0)
         // 004037ae: shr eax, b1 0x5
         // 004037b1: jz 0x4037e7
      [-]89c283e20f740c
         // 004037b3: mov edx, eax
         // 004037b5: and edx, 0xf
         // 004037b8: jz 0x4037c6
      [-]8d1492dbac5329394000def9
         // 004037ba: lea edx, ds:[edx+edx*0x4]
         // 004037bd: fld b10 ds:[ebx+edx*0x2]
         // 004037c4: fdivp b8 st(1), b10 st(0)
      [-]c1e804741c
         // 004037c6: shr eax, b1 0x4
         // 004037c9: jz 0x4037e7
      [-]8d0480dbac43bf394000def9eb0e
         // 004037cb: lea eax, ds:[eax+eax*0x4]
         // 004037ce: fld b10 ds:[ebx+eax*0x2]
         // 004037d5: fdivp b8 st(1), b10 st(0)
         // 004037d7: jmp 0x4037e7
      [-]ddd8dbabe9374000eb04
         // 004037d9: fstp b10 st(0)
         // 004037db: fld b10 ds:[ebx+0x4037e9]
         // 004037e1: jmp 0x4037e7
      [-]ddd8d9ee
         // 004037e3: fstp b10 st(0)
         // 004037e5: fldz 
      [-]b004e985edffff
         // 00403b2c: mov b1 al, b1 0x4
         // 00403b2e: jmp @System@Error$qqr20System@TRuntimeError
      [-]538bd88bc3e8a60000008bc3e8cbebffff5bc3
         // 00403ba0: push ebx
         // 00403ba1: mov ebx, eax
         // 00403ba3: mov eax, ebx
         // 00403ba5: call @System@TObject@CleanupInstance$qqrv
         // 00403baa: mov eax, ebx
         // 00403bac: call @System@@FreeMem$qqrpv
         // 00403bb1: pop ebx
         // 00403bb2: retn 
      [-]8b442404f74004????????0f8513010000
         // 0040408c: mov eax, ss:[esp+0x4]
         // 00404090: test ds:[eax+0x4], 0x6
         // 00404097: jnz 0x4041b0
      [-]8138????????8b50188b4814746e
         // 0040409d: cmp ds:[eax], 0xeedfade
         // 004040a3: mov edx, ds:[eax+0x18]
         // 004040a6: mov ecx, ds:[eax+0x14]
         // 004040a9: jz 0x404119
      [-]fce86ffaffff8b15????????85d20f84f1000000
         // 004040ab: cld 
         // 004040ac: call 0x403b20
         // 004040b1: mov edx, ds:[0x49e010]
         // 004040b7: test edx, edx
         // 004040b9: jz 0x4041b0
      [-]ffd285c00f84e7000000
         // 004040bf: call edx
         // 004040c1: test eax, eax
         // 004040c3: jz 0x4041b0
      [-]8b54240c8b4c24048139????????7437
         // 004040c9: mov edx, ss:[esp+0xc]
         // 004040cd: mov ecx, ss:[esp+0x4]
         // 004040d1: cmp ds:[ecx], 0xeefface
         // 004040d7: jz 0x404110
      [-]e8c6feffff803d30b04900007629
         // 004040d9: call 0x403fa4
         // 004040de: cmp b1 ds:[0x49b030], b1 0x0
         // 004040e5: jbe 0x404110
      [-]803d2cb04900007720
         // 004040e7: cmp b1 ds:[0x49b02c], b1 0x0
         // 004040ee: ja 0x404110
      [-]8d4c24045051e879d1ffff83f800580f84ab000000
         // 004040f0: lea ecx, ss:[esp+0x4]
         // 004040f4: push eax
         // 004040f5: push ecx
         // 004040f6: call UnhandledExceptionFilter
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
      [-]803d30b0490001761e
         // 00404119: cmp b1 ds:[0x49b030], b1 0x1
         // 00404120: jbe 0x404140
      [-]803d2cb04900007715
         // 00404122: cmp b1 ds:[0x49b02c], b1 0x0
         // 00404129: ja 0x404140
      [-]508d442408525150e83cd1ffff83f800595a587470
         // 0040412b: push eax
         // 0040412c: lea eax, ss:[esp+0x8]
         // 00404130: push edx
         // 00404131: push ecx
         // 00404132: push eax
         // 00404133: call UnhandledExceptionFilter
         // 00404138: cmp eax, 0x0
         // 0040413b: pop ecx
         // 0040413c: pop edx
         // 0040413d: pop eax
         // 0040413e: jz 0x4041b0
      [-]834804025331db565755648b1b535052518b5424286a005068????????52ff15????????8b7c2428e86f2b0000ffb0????????89a0????????8b6f088b5f04c74704????????83c305e866feffffffe3
         // 00404140: or ds:[eax+0x4], 0x2
         // 00404144: push ebx
         // 00404145: xor ebx, ebx
         // 00404147: push esi
         // 00404148: push edi
         // 00404149: push ebp
         // 0040414a: mov ebx, fs:[ebx]
         // 0040414d: push ebx
         // 0040414e: push eax
         // 0040414f: push edx
         // 00404150: push ecx
         // 00404151: mov edx, ss:[esp+0x28]
         // 00404155: push 0x0
         // 00404157: push eax
         // 00404158: push 0x404164
         // 0040415d: push edx
         // 0040415e: call ds:[0x49e018]
         // 00404164: mov edi, ss:[esp+0x28]
         // 00404168: call @Sysinit@@GetTls$qqrv
         // 0040416d: push ds:[eax+0x0]
         // 00404173: mov ds:[eax+0x0], esp
         // 00404179: mov ebp, ds:[edi+0x8]
         // 0040417c: mov ebx, ds:[edi+0x4]
         // 0040417f: mov ds:[edi+0x4], 0x404190
         // 00404186: add ebx, 0x5
         // 00404189: call 0x403ff4
         // 0040418e: jmp ebx
      [-]b8????????c3
         // 004041b0: mov eax, 0x1
         // 004041b5: retn 
      [-]8b4424048b542408f74004????????741f
         // 00404340: mov eax, ss:[esp+0x4]
         // 00404344: mov edx, ss:[esp+0x8]
         // 00404348: test ds:[eax+0x4], 0x6
         // 0040434f: jz 0x404370
      [-]8b4a04c74204????????535657558b6a0883c105e8befcffffffd15d5f5e5b
         // 00404351: mov ecx, ds:[edx+0x4]
         // 00404354: mov ds:[edx+0x4], 0x404370
         // 0040435b: push ebx
         // 0040435c: push esi
         // 0040435d: push edi
         // 0040435e: push ebp
         // 0040435f: mov ebp, ds:[edx+0x8]
         // 00404362: add ecx, 0x5
         // 00404365: call 0x404028
         // 0040436a: call ecx
         // 0040436c: pop ebp
         // 0040436d: pop edi
         // 0040436e: pop esi
         // 0040436f: pop ebx
      [-]b8????????c3
         // 00404370: mov eax, 0x1
         // 00404375: retn 
      [-]a3????????e81effffff
         // 00404924: mov ds:[0x49b000], eax
         // 00404929: call @System@@Halt0$qqrv
      [-]8f05????????e9e9ffffff
         // 00404930: pop ds:[0x49b004]
         // 00404936: jmp 0x404924
      [-]8b1085d27438
         // 00404e8c: mov edx, ds:[eax]
         // 00404e8e: test edx, edx
         // 00404e90: jz 0x404eca
      [-]8b4af8497432
         // 00404e92: mov ecx, ds:[edx+0xfffffffffffffff8]
         // 00404e95: dec ecx
         // 00404e96: jz 0x404eca
      [-]5389c38b42fce8e1fbffff89c28b038913508b48fce82adbffff588b48f8497c0e
         // 00404e98: push ebx
         // 00404e99: mov ebx, eax
         // 00404e9b: mov eax, ds:[edx+0xfffffffffffffffc]
         // 00404e9e: call @System@@NewAnsiString$qqri
         // 00404ea3: mov edx, eax
         // 00404ea5: mov eax, ds:[ebx]
         // 00404ea7: mov ds:[ebx], edx
         // 00404ea9: push eax
         // 00404eaa: mov ecx, ds:[eax+0xfffffffffffffffc]
         // 00404ead: call @System@Move$qqrpxvpvi
         // 00404eb2: pop eax
         // 00404eb3: mov ecx, ds:[eax+0xfffffffffffffff8]
         // 00404eb6: dec ecx
         // 00404eb7: jl 0x404ec7
      [-]f0ff48f87508
         // 00404eb9: lock dec ds:[eax+0xfffffffffffffff8]
         // 00404ebd: jnz 0x404ec7
      [-]8d40f8e8b5d8ffff
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
      [-]5f5e5b58b002e90bd3ffff
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
      [-]8b04248928e9ee010000
         // 00405b23: mov eax, ss:[esp]
         // 00405b26: mov ds:[eax], ebp
         // 00405b28: jmp 0x405d1b
      [-]807c2eff2074f8
         // 00405b2e: cmp b1 ds:[esi+ebp+0xffffffffffffffff], b1 0x20
         // 00405b33: jz 0x405b2d
      [-]c6442410008a442eff3c2d7508
         // 00405b35: mov b1 ss:[esp+0x10], b1 0x0
         // 00405b3a: mov b1 al, b1 ds:[esi+ebp+0xffffffffffffffff]
         // 00405b3e: cmp b1 al, b1 0x2d
         // 00405b40: jnz 0x405b4a
      [-]c64424100145eb05
         // 00405b42: mov b1 ss:[esp+0x10], b1 0x1
         // 00405b47: inc ebp
         // 00405b48: jmp 0x405b4f
      [-]3c2b7501
         // 00405b4a: cmp b1 al, b1 0x2b
         // 00405b4c: jnz 0x405b4f
      [-]b301807c2eff247428
         // 00405b4f: mov b1 bl, b1 0x1
         // 00405b51: cmp b1 ds:[esi+ebp+0xffffffffffffffff], b1 0x24
         // 00405b56: jz 0x405b80
      [-]8a442effe88fd0ffff3c58741b
         // 00405b58: mov b1 al, b1 ds:[esi+ebp+0xffffffffffffffff]
         // 00405b5c: call @System@UpCase$qqrc
         // 00405b61: cmp b1 al, b1 0x58
         // 00405b63: jz 0x405b80
      [-]807c2eff300f85da000000
         // 00405b65: cmp b1 ds:[esi+ebp+0xffffffffffffffff], b1 0x30
         // 00405b6a: jnz 0x405c4a
      [-]8a042ee878d0ffff3c580f85ca000000
         // 00405b70: mov b1 al, b1 ds:[esi+ebp]
         // 00405b73: call @System@UpCase$qqrc
         // 00405b78: cmp b1 al, b1 0x58
         // 00405b7a: jnz 0x405c4a
      [-]807c2eff307501
         // 00405b80: cmp b1 ds:[esi+ebp+0xffffffffffffffff], b1 0x30
         // 00405b85: jnz 0x405b88
      [-]8a442eff8bd080c2d080ea0a7212
         // 00405b89: mov b1 al, b1 ds:[esi+ebp+0xffffffffffffffff]
         // 00405b8d: mov edx, eax
         // 00405b8f: add b1 dl, b1 0xd0
         // 00405b92: sub b1 dl, b1 0xa
         // 00405b95: jb 0x405ba9
      [-]80c2f980ea067217
         // 00405b97: add b1 dl, b1 0xf9
         // 00405b9a: sub b1 dl, b1 0x6
         // 00405b9d: jb 0x405bb6
      [-]80c2e680ea06721c
         // 00405b9f: add b1 dl, b1 0xe6
         // 00405ba2: sub b1 dl, b1 0x6
         // 00405ba5: jb 0x405bc3
      [-]8bf881e7????????83ef30eb18
         // 00405ba9: mov edi, eax
         // 00405bab: and edi, 0xff
         // 00405bb1: sub edi, 0x30
         // 00405bb4: jmp 0x405bce
      [-]8bf881e7????????83ef37eb0b
         // 00405bb6: mov edi, eax
         // 00405bb8: and edi, 0xff
         // 00405bbe: sub edi, 0x37
         // 00405bc1: jmp 0x405bce
      [-]8bf881e7????????83ef57
         // 00405bc3: mov edi, eax
         // 00405bc5: and edi, 0xff
         // 00405bcb: sub edi, 0x57
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
      [-]8bc79952508b4424108b5424140fa4c204c1e0040304241354240483c408894424088954240c4533dbe966ffffff
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
      [-]807c2410000f84d3000000
         // 00405c23: cmp b1 ss:[esp+0x10], b1 0x0
         // 00405c28: jz 0x405d01
      [-]8b4424088b54240cf7d883d200f7da894424088954240ce9b7000000
         // 00405c2e: mov eax, ss:[esp+0x8]
         // 00405c32: mov edx, ss:[esp+0xc]
         // 00405c36: neg eax
         // 00405c38: adc edx, 0x0
         // 00405c3b: neg edx
         // 00405c3d: mov ss:[esp+0x8], eax
         // 00405c41: mov ss:[esp+0xc], edx
         // 00405c45: jmp 0x405d01
      [-]8a442eff8bd080c2d080ea0a7362
         // 00405c4a: mov b1 al, b1 ds:[esi+ebp+0xffffffffffffffff]
         // 00405c4e: mov edx, eax
         // 00405c50: add b1 dl, b1 0xd0
         // 00405c53: sub b1 dl, b1 0xa
         // 00405c56: jnb 0x405cba
      [-]8bf881e7????????83ef30837c240c007509
         // 00405c58: mov edi, eax
         // 00405c5a: and edi, 0xff
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
      [-]6a006a0a8b4424108b542414e802fdffff52508bc7990304241354240483c408894424088954240c4533dbeb90
         // 00405c8d: push 0x0
         // 00405c8f: push 0xa
         // 00405c91: mov eax, ss:[esp+0x10]
         // 00405c95: mov edx, ss:[esp+0x14]
         // 00405c99: call 0x4059a0
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
      [-]e977f7ffff
         // 00405d4c: jmp @System@@FinalizeArray$qqrpvt1ui
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
      [-]83c00450e84fadffffc3
         // 0040662c: add eax, 0x4
         // 0040662f: push eax
         // 00406630: call InterlockedDecrement
         // 00406635: retn 
      [-]506a40e8e0ffffffc3
         // 00406c84: push eax
         // 00406c85: push 0x40
         // 00406c87: call LocalAlloc_0
         // 00406c8c: retn 
      [-]b8????????c3
         // 00406c90: mov eax, 0x10
         // 00406c95: retn 
      [-]558bec33c05568????????64ff30648920ff05????????33c05a595964891068????????c3
         // 00406d6c: push ebp
         // 00406d6d: mov ebp, esp
         // 00406d6f: xor eax, eax
         // 00406d71: push ebp
         // 00406d72: push 0x406d91
         // 00406d77: push fs:[eax]
         // 00406d7a: mov fs:[eax], esp
         // 00406d7d: inc ds:[0x49e66c]
         // 00406d83: xor eax, eax
         // 00406d85: pop edx
         // 00406d86: pop ecx
         // 00406d87: pop ecx
         // 00406d88: mov fs:[eax], edx
         // 00406d8b: push 0x406d98
         // 00406d90: retn 
      [-]832d????????01c3
         // 00406d9c: sub ds:[0x49e66c], 0x1
         // 00406da3: retn 
      [-]8901895104c3
         // 00406dc0: mov ds:[ecx], eax
         // 00406dc2: mov ds:[ecx+0x4], edx
         // 00406dc5: retn 
      [-]558bec33c05568????????64ff30648920ff05????????33c05a595964891068????????c3
         // 00406de4: push ebp
         // 00406de5: mov ebp, esp
         // 00406de7: xor eax, eax
         // 00406de9: push ebp
         // 00406dea: push 0x406e09
         // 00406def: push fs:[eax]
         // 00406df2: mov fs:[eax], esp
         // 00406df5: inc ds:[0x49e674]
         // 00406dfb: xor eax, eax
         // 00406dfd: pop edx
         // 00406dfe: pop ecx
         // 00406dff: pop ecx
         // 00406e00: mov fs:[eax], edx
         // 00406e03: push 0x406e10
         // 00406e08: retn 
      [-]832d????????01c3
         // 00406e14: sub ds:[0x49e674], 0x1
         // 00406e1b: retn 
      [-]c1e810c3
         // 004079dc: shr eax, b1 0x10
         // 004079df: retn 
      [-]e84bf7ffffc3
         // 004079e0: call GetTickCount_0
         // 004079e5: retn 
      [-]92e8eeafffffc3
         // 004079e8: xchg eax, edx
         // 004079e9: call @System@Move$qqrpxvpvi
         // 004079ee: retn 
      [-]e84fffffffc3
         // 00407a7c: call 0x4079d0
         // 00407a81: retn 
      [-]558bec33c05568????????64ff30648920ff05????????33c05a595964891068????????c3
         // 00407c34: push ebp
         // 00407c35: mov ebp, esp
         // 00407c37: xor eax, eax
         // 00407c39: push ebp
         // 00407c3a: push 0x407c59
         // 00407c3f: push fs:[eax]
         // 00407c42: mov fs:[eax], esp
         // 00407c45: inc ds:[0x49e678]
         // 00407c4b: xor eax, eax
         // 00407c4d: pop edx
         // 00407c4e: pop ecx
         // 00407c4f: pop ecx
         // 00407c50: mov fs:[eax], edx
         // 00407c53: push 0x407c60
         // 00407c58: retn 
      [-]832d????????01c3
         // 00407c64: sub ds:[0x49e678], 0x1
         // 00407c6b: retn 
      [-]558bec33c05568????????64ff30648920ff05????????33c05a595964891068????????c3
         // 00407c6c: push ebp
         // 00407c6d: mov ebp, esp
         // 00407c6f: xor eax, eax
         // 00407c71: push ebp
         // 00407c72: push 0x407c91
         // 00407c77: push fs:[eax]
         // 00407c7a: mov fs:[eax], esp
         // 00407c7d: inc ds:[0x49e67c]
         // 00407c83: xor eax, eax
         // 00407c85: pop edx
         // 00407c86: pop ecx
         // 00407c87: pop ecx
         // 00407c88: mov fs:[eax], edx
         // 00407c8b: push 0x407c98
         // 00407c90: retn 
      [-]832d????????01c3
         // 00407c9c: sub ds:[0x49e67c], 0x1
         // 00407ca3: retn 
      [-]558bec33c05568????????64ff30648920ff05????????33c05a595964891068????????c3
         // 00407fcc: push ebp
         // 00407fcd: mov ebp, esp
         // 00407fcf: xor eax, eax
         // 00407fd1: push ebp
         // 00407fd2: push 0x407ff1
         // 00407fd7: push fs:[eax]
         // 00407fda: mov fs:[eax], esp
         // 00407fdd: inc ds:[0x49e680]
         // 00407fe3: xor eax, eax
         // 00407fe5: pop edx
         // 00407fe6: pop ecx
         // 00407fe7: pop ecx
         // 00407fe8: mov fs:[eax], edx
         // 00407feb: push 0x407ff8
         // 00407ff0: retn 
      [-]832d????????01c3
         // 00407ffc: sub ds:[0x49e680], 0x1
         // 00408003: retn 
      [-]538bd88bcbb201a1????????e88b450000e8feb6ffff5bc3
         // 00408c64: push ebx
         // 00408c65: mov ebx, eax
         // 00408c67: mov ecx, ebx
         // 00408c69: mov b1 dl, b1 0x1
         // 00408c6b: mov eax, ds:[0x4086b0]
         // 00408c70: call @Sysutils@Exception@$bctr$qqrp20System@TResStringRec
         // 00408c75: call @System@@RaiseExcept$qqrv
         // 00408c7a: pop ebx
         // 00408c7b: retn 
      [-]5356578bf98bf28bd856578bcbb201a1????????e8a7450000e8deb6ffff5f5e5bc3
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
         // 00408c90: call @Sysutils@Exception@$bctr$qqrp20System@TResStringRecpx14System@TVarRecxi
         // 00408c95: call @System@@RaiseExcept$qqrv
         // 00408c9a: pop edi
         // 00408c9b: pop esi
         // 00408c9c: pop ebx
         // 00408c9d: retn 
      [-]e8d7ffffffc3
         // 00409940: call 0x40991c
         // 00409945: retn 
      [-]535657518bf98bf28bd86a008d44240450575653e88fd8ffff85c07507
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
      [-]535657518bf98bf28bd86a008d44240450575653e8fbd8ffff85c07507
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
      [-]50e872d5ffffc3
         // 004099d8: push eax
         // 004099d9: call CloseHandle_0
         // 004099de: retn 
      [-]53568bda8bf08bc3e853acffff508bc3e84baeffff8bd08bc659e8adffffff5e5bc3
         // 0040a020: push ebx
         // 0040a021: push esi
         // 0040a022: mov ebx, edx
         // 0040a024: mov esi, eax
         // 0040a026: mov eax, ebx
         // 0040a028: call 0x404c80
         // 0040a02d: push eax
         // 0040a02e: mov eax, ebx
         // 0040a030: call @System@@LStrToPChar$qqrx17System@AnsiString
         // 0040a035: mov edx, eax
         // 0040a037: mov eax, esi
         // 0040a039: pop ecx
         // 0040a03a: call @Sysutils@StrLCopy$qqrpcpxcui
         // 0040a03f: pop esi
         // 0040a040: pop ebx
         // 0040a041: retn 
      [-]84c97503
         // 0040a10e: test b1 cl, b1 cl
         // 0040a110: jnz 0x40a115
      [-]8a083ad175f2
         // 0040a116: mov b1 cl, b1 ds:[eax]
         // 0040a118: cmp b1 dl, b1 cl
         // 0040a11a: jnz 0x40a10e
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
      [-]31db8a5df3b9????????807dd6007408
         // 0040a982: xor ebx, ebx
         // 0040a984: mov b1 bl, b1 ss:[ebp+0xfffffffffffffff3]
         // 0040a987: mov ecx, 0x3
         // 0040a98c: cmp b1 ss:[ebp+0xffffffffffffffd6], b1 0x0
         // 0040a990: jz 0x40a99a
      [-]8a5df2b9????????
         // 0040a992: mov b1 bl, b1 ss:[ebp+0xfffffffffffffff2]
         // 0040a995: mov ecx, 0x40f
      [-]38cb7602
         // 0040a99a: cmp b1 bl, b1 cl
         // 0040a99c: jbe 0x40a9a0
      [-]00eb8d9c9be5a94000035decb9????????
         // 0040a9a0: add b1 bl, b1 ch
         // 0040a9a2: lea ebx, ds:[ebx+ebx*0x4]
         // 0040a9a9: add ebx, ss:[ebp+0xffffffffffffffec]
         // 0040a9ac: mov ecx, 0x5
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
      [-]558bec83c4d8535633d28955d88955dc8945fc33c05568????????64ff30648920837dfc000f843b070000
         // 0040b728: push ebp
         // 0040b729: mov ebp, esp
         // 0040b72b: add esp, 0xffffffffffffffd8
         // 0040b72e: push ebx
         // 0040b72f: push esi
         // 0040b730: xor edx, edx
         // 0040b732: mov ss:[ebp+0xffffffffffffffd8], edx
         // 0040b735: mov ss:[ebp+0xffffffffffffffdc], edx
         // 0040b738: mov ss:[ebp+0xfffffffffffffffc], eax
         // 0040b73b: xor eax, eax
         // 0040b73d: push ebp
         // 0040b73e: push 0x40bea9
         // 0040b743: push fs:[eax]
         // 0040b746: mov fs:[eax], esp
         // 0040b749: cmp ss:[ebp+0xfffffffffffffffc], 0x0
         // 0040b74d: jz 0x40be8e
      [-]8b450883b8????????020f8d2b070000
         // 0040b753: mov eax, ss:[ebp+0x8]
         // 0040b756: cmp ds:[eax+0xfffffffffffffef8], 0x2
         // 0040b75d: jge 0x40be8e
      [-]8b4508ff80????????b320c645ed00c645e300c645e200e9f9060000
         // 0040b763: mov eax, ss:[ebp+0x8]
         // 0040b766: inc ds:[eax+0xfffffffffffffef8]
         // 0040b76c: mov b1 bl, b1 0x20
         // 0040b76e: mov b1 ss:[ebp+0xffffffffffffffed], b1 0x0
         // 0040b772: mov b1 ss:[ebp+0xffffffffffffffe3], b1 0x0
         // 0040b776: mov b1 ss:[ebp+0xffffffffffffffe2], b1 0x0
         // 0040b77a: jmp 0x40be78
      [-]8845fb8a45fb25????????0fa305????????7329
         // 0040b77f: mov b1 ss:[ebp+0xfffffffffffffffb], b1 al
         // 0040b782: mov b1 al, b1 ss:[ebp+0xfffffffffffffffb]
         // 0040b785: and eax, 0xff
         // 0040b78a: bt ds:[0x49b134], eax
         // 0040b791: jnb 0x40b7bc
      [-]8b4508508b45fce8b12500008bd08b45fce8bbfbffff598b45fce8be2500008945fcb320e9bc060000
         // 0040b793: mov eax, ss:[ebp+0x8]
         // 0040b796: push eax
         // 0040b797: mov eax, ss:[ebp+0xfffffffffffffffc]
         // 0040b79a: call @Sysutils@StrCharLength$qqrpxc
         // 0040b79f: mov edx, eax
         // 0040b7a1: mov eax, ss:[ebp+0xfffffffffffffffc]
         // 0040b7a4: call 0x40b364
         // 0040b7a9: pop ecx
         // 0040b7aa: mov eax, ss:[ebp+0xfffffffffffffffc]
         // 0040b7ad: call 0x40dd70
         // 0040b7b2: mov ss:[ebp+0xfffffffffffffffc], eax
         // 0040b7b5: mov b1 bl, b1 0x20
         // 0040b7b7: jmp 0x40be78
      [-]8b45fce8ac2500008945fc8a45fb8bd080c29f80ea1a7302
         // 0040b7bc: mov eax, ss:[ebp+0xfffffffffffffffc]
         // 0040b7bf: call 0x40dd70
         // 0040b7c4: mov ss:[ebp+0xfffffffffffffffc], eax
         // 0040b7c7: mov b1 al, b1 ss:[ebp+0xfffffffffffffffb]
         // 0040b7ca: mov edx, eax
         // 0040b7cc: add b1 dl, b1 0x9f
         // 0040b7cf: sub b1 dl, b1 0x1a
         // 0040b7d2: jnb 0x40b7d6
      [-]8bd080c2bf80ea1a730d
         // 0040b7d6: mov edx, eax
         // 0040b7d8: add b1 dl, b1 0xbf
         // 0040b7db: sub b1 dl, b1 0x1a
         // 0040b7de: jnb 0x40b7ed
      [-]3c4d7507
         // 0040b7e0: cmp b1 al, b1 0x4d
         // 0040b7e2: jnz 0x40b7eb
      [-]80fb487502
         // 0040b7e4: cmp b1 bl, b1 0x48
         // 0040b7e7: jnz 0x40b7eb
      [-]25????????83c0de83f8380f8768060000
         // 0040b7ed: and eax, 0xff
         // 0040b7f2: add eax, 0xffffffffffffffde
         // 0040b7f5: cmp eax, 0x38
         // 0040b7f8: ja def_40B804
      [-]8a800bb84000ff248544b84000
         // 0040b7fe: mov b1 al, b1 ds:[eax+0x40b80b]
         // 0040b804: jmp ds:[jpt_40B804+eax*0x4]
      [-]55e88afbffff5955e8affbffff59837df4027f23
         // 0040b884: push ebp
         // 0040b885: call @SysUtils@_16719
         // 0040b88a: pop ecx
         // 0040b88b: push ebp
         // 0040b88c: call 0x40b440
         // 0040b891: pop ecx
         // 0040b892: cmp ss:[ebp+0xfffffffffffffff4], 0x2
         // 0040b896: jg 0x40b8bb
      [-]8b4508500fb745f2b9????????33d2f7f18bc2ba????????e813fbffff59e9bd050000
         // 0040b898: mov eax, ss:[ebp+0x8]
         // 0040b89b: push eax
         // 0040b89c: movzx eax, b2 ss:[ebp+0xfffffffffffffff2]
         // 0040b8a0: mov ecx, 0x64
         // 0040b8a5: xor edx, edx
         // 0040b8a7: div ecx
         // 0040b8a9: mov eax, edx
         // 0040b8ab: mov edx, 0x2
         // 0040b8b0: call 0x40b3c8
         // 0040b8b5: pop ecx
         // 0040b8b6: jmp 0x40be78
      [-]8b4508500fb745f2ba????????e8fbfaffff59e9a5050000
         // 0040b8bb: mov eax, ss:[ebp+0x8]
         // 0040b8be: push eax
         // 0040b8bf: movzx eax, b2 ss:[ebp+0xfffffffffffffff2]
         // 0040b8c3: mov edx, 0x4
         // 0040b8c8: call 0x40b3c8
         // 0040b8cd: pop ecx
         // 0040b8ce: jmp 0x40be78
      [-]55e83bfbffff5955e860fbffff598b450850558d55dc8b45f4e8c7fbffff598b45dce8aefaffff59e978050000
         // 0040b8d3: push ebp
         // 0040b8d4: call @SysUtils@_16719
         // 0040b8d9: pop ecx
         // 0040b8da: push ebp
         // 0040b8db: call 0x40b440
         // 0040b8e0: pop ecx
         // 0040b8e1: mov eax, ss:[ebp+0x8]
         // 0040b8e4: push eax
         // 0040b8e5: push ebp
         // 0040b8e6: lea edx, ss:[ebp+0xffffffffffffffdc]
         // 0040b8e9: mov eax, ss:[ebp+0xfffffffffffffff4]
         // 0040b8ec: call @SysUtils@_16722
         // 0040b8f1: pop ecx
         // 0040b8f2: mov eax, ss:[ebp+0xffffffffffffffdc]
         // 0040b8f5: call 0x40b3a8
         // 0040b8fa: pop ecx
         // 0040b8fb: jmp 0x40be78
      [-]55e80efbffff5955e833fbffff598b450850558d55d88b45f4e802fdffff598b45d8e881faffff59e94b050000
         // 0040b900: push ebp
         // 0040b901: call @SysUtils@_16719
         // 0040b906: pop ecx
         // 0040b907: push ebp
         // 0040b908: call 0x40b440
         // 0040b90d: pop ecx
         // 0040b90e: mov eax, ss:[ebp+0x8]
         // 0040b911: push eax
         // 0040b912: push ebp
         // 0040b913: lea edx, ss:[ebp+0xffffffffffffffd8]
         // 0040b916: mov eax, ss:[ebp+0xfffffffffffffff4]
         // 0040b919: call 0x40b620
         // 0040b91e: pop ecx
         // 0040b91f: mov eax, ss:[ebp+0xffffffffffffffd8]
         // 0040b922: call 0x40b3a8
         // 0040b927: pop ecx
         // 0040b928: jmp 0x40be78
      [-]55e8e1faffff5955e806fbffff598b45f44883e8027204
         // 0040b92d: push ebp
         // 0040b92e: call @SysUtils@_16719
         // 0040b933: pop ecx
         // 0040b934: push ebp
         // 0040b935: call 0x40b440
         // 0040b93a: pop ecx
         // 0040b93b: mov eax, ss:[ebp+0xfffffffffffffff4]
         // 0040b93e: dec eax
         // 0040b93f: sub eax, 0x2
         // 0040b942: jb 0x40b948
      [-]8b4508500fb745f08b0485????????e81cfaffff59e9e6040000
         // 0040b978: mov eax, ss:[ebp+0x8]
         // 0040b97b: push eax
         // 0040b97c: movzx eax, b2 ss:[ebp+0xfffffffffffffff0]
         // 0040b980: mov eax, ds:[0x49e6d8+eax*0x4]
         // 0040b987: call 0x40b3a8
         // 0040b98c: pop ecx
         // 0040b98d: jmp 0x40be78
      [-]55e87cfaffff598b45f44883e802720a
         // 0040b992: push ebp
         // 0040b993: call @SysUtils@_16719
         // 0040b998: pop ecx
         // 0040b999: mov eax, ss:[ebp+0xfffffffffffffff4]
         // 0040b99c: dec eax
         // 0040b99d: sub eax, 0x2
         // 0040b9a0: jb 0x40b9ac
      [-]8b450850a1????????e8effcffff59e939040000
         // 0040ba2b: mov eax, ss:[ebp+0x8]
         // 0040ba2e: push eax
         // 0040ba2f: mov eax, ds:[0x49e694]
         // 0040ba34: call 0x40b728
         // 0040ba39: pop ecx
         // 0040ba3a: jmp 0x40be78
      [-]55e8cff9ffff5955e82cfaffff59c645e1008b75fce995000000
         // 0040ba3f: push ebp
         // 0040ba40: call @SysUtils@_16719
         // 0040ba45: pop ecx
         // 0040ba46: push ebp
         // 0040ba47: call 0x40b478
         // 0040ba4c: pop ecx
         // 0040ba4d: mov b1 ss:[ebp+0xffffffffffffffe1], b1 0x0
         // 0040ba51: mov esi, ss:[ebp+0xfffffffffffffffc]
         // 0040ba54: jmp 0x40baee
      [-]25????????0fa305????????730b
         // 0040ba59: and eax, 0xff
         // 0040ba5e: bt ds:[0x49b134], eax
         // 0040ba65: jnb 0x40ba72
      [-]8bc6e8022300008bf0eb7c
         // 0040ba67: mov eax, esi
         // 0040ba69: call 0x40dd70
         // 0040ba6e: mov esi, eax
         // 0040ba70: jmp 0x40baee
      [-]33c08a0683f8487f13
         // 0040ba72: xor eax, eax
         // 0040ba74: mov b1 al, b1 ds:[esi]
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
      [-]807de100754d
         // 0040ba9a: cmp b1 ss:[ebp+0xffffffffffffffe1], b1 0x0
         // 0040ba9e: jnz 0x40baed
      [-]ba????????b9????????8bc6e817e6ffff85c0742a
         // 0040baa0: mov edx, 0x40beb8
         // 0040baa5: mov ecx, 0x5
         // 0040baaa: mov eax, esi
         // 0040baac: call @Sysutils@StrLIComp$qqrpxct1ui
         // 0040bab1: test eax, eax
         // 0040bab3: jz 0x40badf
      [-]ba????????b9????????8bc6e802e6ffff85c07415
         // 0040bab5: mov edx, 0x40bec0
         // 0040baba: mov ecx, 0x3
         // 0040babf: mov eax, esi
         // 0040bac1: call @Sysutils@StrLIComp$qqrpxct1ui
         // 0040bac6: test eax, eax
         // 0040bac8: jz 0x40badf
      [-]ba????????b9????????8bc6e8ede5ffff85c07519
         // 0040baca: mov edx, 0x40bec4
         // 0040bacf: mov ecx, 0x4
         // 0040bad4: mov eax, esi
         // 0040bad6: call @Sysutils@StrLIComp$qqrpxct1ui
         // 0040badb: test eax, eax
         // 0040badd: jnz 0x40baf8
      [-]c645e201eb13
         // 0040badf: mov b1 ss:[ebp+0xffffffffffffffe2], b1 0x1
         // 0040bae3: jmp 0x40baf8
      [-]8a45e134018845e1
         // 0040bae5: mov b1 al, b1 ss:[ebp+0xffffffffffffffe1]
         // 0040bae8: xor b1 al, b1 0x1
         // 0040baea: mov b1 ss:[ebp+0xffffffffffffffe1], b1 al
      [-]8a0684c00f8561ffffff
         // 0040baee: mov b1 al, b1 ds:[esi]
         // 0040baf0: test b1 al, b1 al
         // 0040baf2: jnz 0x40ba59
      [-]668b45ea807de2007415
         // 0040baf8: mov b2 ax, b2 ss:[ebp+0xffffffffffffffea]
         // 0040bafc: cmp b1 ss:[ebp+0xffffffffffffffe2], b1 0x0
         // 0040bb00: jz 0x40bb17
      [-]6685c07506
         // 0040bb02: test b2 ax, b2 ax
         // 0040bb05: jnz 0x40bb0d
      [-]66b80c00eb0a
         // 0040bb07: mov b2 ax, b2 0xc
         // 0040bb0b: jmp 0x40bb17
      [-]6683f80c7604
         // 0040bb0d: cmp b2 ax, b2 0xc
         // 0040bb11: jbe 0x40bb17
      [-]6683e80c
         // 0040bb13: sub b2 ax, b2 0xc
      [-]837df4027e07
         // 0040bb17: cmp ss:[ebp+0xfffffffffffffff4], 0x2
         // 0040bb1b: jle 0x40bb24
      [-]c745f4????????
         // 0040bb1d: mov ss:[ebp+0xfffffffffffffff4], 0x2
      [-]8b5508520fb7c08b55f4e895f8ffff59e93f030000
         // 0040bb24: mov edx, ss:[ebp+0x8]
         // 0040bb27: push edx
         // 0040bb28: movzx eax, b2 ax
         // 0040bb2b: mov edx, ss:[ebp+0xfffffffffffffff4]
         // 0040bb2e: call 0x40b3c8
         // 0040bb33: pop ecx
         // 0040bb34: jmp 0x40be78
      [-]55e8d5f8ffff5955e832f9ffff59837df4027e07
         // 0040bb39: push ebp
         // 0040bb3a: call @SysUtils@_16719
         // 0040bb3f: pop ecx
         // 0040bb40: push ebp
         // 0040bb41: call 0x40b478
         // 0040bb46: pop ecx
         // 0040bb47: cmp ss:[ebp+0xfffffffffffffff4], 0x2
         // 0040bb4b: jle 0x40bb54
      [-]c745f4????????
         // 0040bb4d: mov ss:[ebp+0xfffffffffffffff4], 0x2
      [-]8b4508500fb745e88b55f4e864f8ffff59e90e030000
         // 0040bb54: mov eax, ss:[ebp+0x8]
         // 0040bb57: push eax
         // 0040bb58: movzx eax, b2 ss:[ebp+0xffffffffffffffe8]
         // 0040bb5c: mov edx, ss:[ebp+0xfffffffffffffff4]
         // 0040bb5f: call 0x40b3c8
         // 0040bb64: pop ecx
         // 0040bb65: jmp 0x40be78
      [-]55e8a4f8ffff5955e801f9ffff59837df4027e07
         // 0040bb6a: push ebp
         // 0040bb6b: call @SysUtils@_16719
         // 0040bb70: pop ecx
         // 0040bb71: push ebp
         // 0040bb72: call 0x40b478
         // 0040bb77: pop ecx
         // 0040bb78: cmp ss:[ebp+0xfffffffffffffff4], 0x2
         // 0040bb7c: jle 0x40bb85
      [-]c745f4????????
         // 0040bb7e: mov ss:[ebp+0xfffffffffffffff4], 0x2
      [-]8b4508500fb745e68b55f4e833f8ffff59e9dd020000
         // 0040bb85: mov eax, ss:[ebp+0x8]
         // 0040bb88: push eax
         // 0040bb89: movzx eax, b2 ss:[ebp+0xffffffffffffffe6]
         // 0040bb8d: mov edx, ss:[ebp+0xfffffffffffffff4]
         // 0040bb90: call 0x40b3c8
         // 0040bb95: pop ecx
         // 0040bb96: jmp 0x40be78
      [-]55e873f8ffff59837df4017514
         // 0040bb9b: push ebp
         // 0040bb9c: call @SysUtils@_16719
         // 0040bba1: pop ecx
         // 0040bba2: cmp ss:[ebp+0xfffffffffffffff4], 0x1
         // 0040bba6: jnz 0x40bbbc
      [-]8b450850a1????????e872fbffff59e9bc020000
         // 0040bba8: mov eax, ss:[ebp+0x8]
         // 0040bbab: push eax
         // 0040bbac: mov eax, ds:[0x49e6a4]
         // 0040bbb1: call 0x40b728
         // 0040bbb6: pop ecx
         // 0040bbb7: jmp 0x40be78
      [-]8b450850a1????????e85efbffff59e9a8020000
         // 0040bbbc: mov eax, ss:[ebp+0x8]
         // 0040bbbf: push eax
         // 0040bbc0: mov eax, ds:[0x49e6a8]
         // 0040bbc5: call 0x40b728
         // 0040bbca: pop ecx
         // 0040bbcb: jmp 0x40be78
      [-]55e83ef8ffff5955e89bf8ffff59837df4037e07
         // 0040bbd0: push ebp
         // 0040bbd1: call @SysUtils@_16719
         // 0040bbd6: pop ecx
         // 0040bbd7: push ebp
         // 0040bbd8: call 0x40b478
         // 0040bbdd: pop ecx
         // 0040bbde: cmp ss:[ebp+0xfffffffffffffff4], 0x3
         // 0040bbe2: jle 0x40bbeb
      [-]c745f4????????
         // 0040bbe4: mov ss:[ebp+0xfffffffffffffff4], 0x3
      [-]8b4508500fb745e48b55f4e8cdf7ffff59e977020000
         // 0040bbeb: mov eax, ss:[ebp+0x8]
         // 0040bbee: push eax
         // 0040bbef: movzx eax, b2 ss:[ebp+0xffffffffffffffe4]
         // 0040bbf3: mov edx, ss:[ebp+0xfffffffffffffff4]
         // 0040bbf6: call 0x40b3c8
         // 0040bbfb: pop ecx
         // 0040bbfc: jmp 0x40be78
      [-]55e871f8ffff598b75fc4eba????????b9????????8bc6e8abe4ffff85c07528
         // 0040bc01: push ebp
         // 0040bc02: call 0x40b478
         // 0040bc07: pop ecx
         // 0040bc08: mov esi, ss:[ebp+0xfffffffffffffffc]
         // 0040bc0b: dec esi
         // 0040bc0c: mov edx, 0x40beb8
         // 0040bc11: mov ecx, 0x5
         // 0040bc16: mov eax, esi
         // 0040bc18: call @Sysutils@StrLIComp$qqrpxct1ui
         // 0040bc1d: test eax, eax
         // 0040bc1f: jnz 0x40bc49
      [-]66837dea0c7203
         // 0040bc21: cmp b2 ss:[ebp+0xffffffffffffffea], b2 0xc
         // 0040bc26: jb 0x40bc2b
      [-]8b450850ba????????8bc6e829f7ffff598345fc04c645e201e92f020000
         // 0040bc2b: mov eax, ss:[ebp+0x8]
         // 0040bc2e: push eax
         // 0040bc2f: mov edx, 0x2
         // 0040bc34: mov eax, esi
         // 0040bc36: call 0x40b364
         // 0040bc3b: pop ecx
         // 0040bc3c: add ss:[ebp+0xfffffffffffffffc], 0x4
         // 0040bc40: mov b1 ss:[ebp+0xffffffffffffffe2], b1 0x1
         // 0040bc44: jmp 0x40be78
      [-]ba????????b9????????8bc6e86ee4ffff85c07528
         // 0040bc49: mov edx, 0x40bec0
         // 0040bc4e: mov ecx, 0x3
         // 0040bc53: mov eax, esi
         // 0040bc55: call @Sysutils@StrLIComp$qqrpxct1ui
         // 0040bc5a: test eax, eax
         // 0040bc5c: jnz 0x40bc86
      [-]66837dea0c7203
         // 0040bc5e: cmp b2 ss:[ebp+0xffffffffffffffea], b2 0xc
         // 0040bc63: jb 0x40bc68
      [-]8b450850ba????????8bc6e8ecf6ffff598345fc02c645e201e9f2010000
         // 0040bc68: mov eax, ss:[ebp+0x8]
         // 0040bc6b: push eax
         // 0040bc6c: mov edx, 0x1
         // 0040bc71: mov eax, esi
         // 0040bc73: call 0x40b364
         // 0040bc78: pop ecx
         // 0040bc79: add ss:[ebp+0xfffffffffffffffc], 0x2
         // 0040bc7d: mov b1 ss:[ebp+0xffffffffffffffe2], b1 0x1
         // 0040bc81: jmp 0x40be78
      [-]ba????????b9????????8bc6e831e4ffff85c07534
         // 0040bc86: mov edx, 0x40bec4
         // 0040bc8b: mov ecx, 0x4
         // 0040bc90: mov eax, esi
         // 0040bc92: call @Sysutils@StrLIComp$qqrpxct1ui
         // 0040bc97: test eax, eax
         // 0040bc99: jnz 0x40bccf
      [-]66837dea0c7311
         // 0040bc9b: cmp b2 ss:[ebp+0xffffffffffffffea], b2 0xc
         // 0040bca0: jnb 0x40bcb3
      [-]8b450850a1????????e8f8f6ffff59eb0f
         // 0040bca2: mov eax, ss:[ebp+0x8]
         // 0040bca5: push eax
         // 0040bca6: mov eax, ds:[0x49e69c]
         // 0040bcab: call 0x40b3a8
         // 0040bcb0: pop ecx
         // 0040bcb1: jmp 0x40bcc2
      [-]8b450850a1????????e8e7f6ffff59
         // 0040bcb3: mov eax, ss:[ebp+0x8]
         // 0040bcb6: push eax
         // 0040bcb7: mov eax, ds:[0x49e6a0]
         // 0040bcbc: call 0x40b3a8
         // 0040bcc1: pop ecx
      [-]8345fc03c645e201e9a9010000
         // 0040bcc2: add ss:[ebp+0xfffffffffffffffc], 0x3
         // 0040bcc6: mov b1 ss:[ebp+0xffffffffffffffe2], b1 0x1
         // 0040bcca: jmp 0x40be78
      [-]ba????????b9????????8bc6e8e8e3ffff85c07532
         // 0040bccf: mov edx, 0x40becc
         // 0040bcd4: mov ecx, 0x4
         // 0040bcd9: mov eax, esi
         // 0040bcdb: call @Sysutils@StrLIComp$qqrpxct1ui
         // 0040bce0: test eax, eax
         // 0040bce2: jnz 0x40bd16
      [-]55e856f7ffff598b4508508b4508ff700cff7008e8aff5ffff0fb7c08b0485????????e89cf6ffff598345fc03e962010000
         // 0040bce4: push ebp
         // 0040bce5: call 0x40b440
         // 0040bcea: pop ecx
         // 0040bceb: mov eax, ss:[ebp+0x8]
         // 0040bcee: push eax
         // 0040bcef: mov eax, ss:[ebp+0x8]
         // 0040bcf2: push ds:[eax+0xc]
         // 0040bcf5: push ds:[eax+0x8]
         // 0040bcf8: call @Sysutils@DayOfWeek$qqrx16System@TDateTime
         // 0040bcfd: movzx eax, b2 ax
         // 0040bd00: mov eax, ds:[0x49e724+eax*0x4]
         // 0040bd07: call 0x40b3a8
         // 0040bd0c: pop ecx
         // 0040bd0d: add ss:[ebp+0xfffffffffffffffc], 0x3
         // 0040bd11: jmp 0x40be78
      [-]ba????????b9????????8bc6e8a1e3ffff85c07532
         // 0040bd16: mov edx, 0x40bed4
         // 0040bd1b: mov ecx, 0x3
         // 0040bd20: mov eax, esi
         // 0040bd22: call @Sysutils@StrLIComp$qqrpxct1ui
         // 0040bd27: test eax, eax
         // 0040bd29: jnz 0x40bd5d
      [-]55e80ff7ffff598b4508508b4508ff700cff7008e868f5ffff0fb7c08b0485????????e855f6ffff598345fc02e91b010000
         // 0040bd2b: push ebp
         // 0040bd2c: call 0x40b440
         // 0040bd31: pop ecx
         // 0040bd32: mov eax, ss:[ebp+0x8]
         // 0040bd35: push eax
         // 0040bd36: mov eax, ss:[ebp+0x8]
         // 0040bd39: push ds:[eax+0xc]
         // 0040bd3c: push ds:[eax+0x8]
         // 0040bd3f: call @Sysutils@DayOfWeek$qqrx16System@TDateTime
         // 0040bd44: movzx eax, b2 ax
         // 0040bd47: mov eax, ds:[0x49e708+eax*0x4]
         // 0040bd4e: call 0x40b3a8
         // 0040bd53: pop ecx
         // 0040bd54: add ss:[ebp+0xfffffffffffffffc], 0x2
         // 0040bd58: jmp 0x40be78
      [-]8b4508508d45fbba????????e8f6f5ffff59e904010000
         // 0040bd5d: mov eax, ss:[ebp+0x8]
         // 0040bd60: push eax
         // 0040bd61: lea eax, ss:[ebp+0xfffffffffffffffb]
         // 0040bd64: mov edx, 0x1
         // 0040bd69: call 0x40b364
         // 0040bd6e: pop ecx
         // 0040bd6f: jmp 0x40be78
      [-]55e89af6ffff598b450850a1????????e89ff9ffff5955e8e8f6ffff5966837dea007512
         // 0040bd74: push ebp
         // 0040bd75: call @SysUtils@_16719
         // 0040bd7a: pop ecx
         // 0040bd7b: mov eax, ss:[ebp+0x8]
         // 0040bd7e: push eax
         // 0040bd7f: mov eax, ds:[0x49e690]
         // 0040bd84: call 0x40b728
         // 0040bd89: pop ecx
         // 0040bd8a: push ebp
         // 0040bd8b: call 0x40b478
         // 0040bd90: pop ecx
         // 0040bd91: cmp b2 ss:[ebp+0xffffffffffffffea], b2 0x0
         // 0040bd96: jnz 0x40bdaa
      [-]66837de800750b
         // 0040bd98: cmp b2 ss:[ebp+0xffffffffffffffe8], b2 0x0
         // 0040bd9d: jnz 0x40bdaa
      [-]66837de6000f84ce000000
         // 0040bd9f: cmp b2 ss:[ebp+0xffffffffffffffe6], b2 0x0
         // 0040bda4: jz 0x40be78
      [-]8b450850b8????????ba????????e8a7f5ffff598b450850a1????????e85cf9ffff59e9a6000000
         // 0040bdaa: mov eax, ss:[ebp+0x8]
         // 0040bdad: push eax
         // 0040bdae: mov eax, 0x40bed8
         // 0040bdb3: mov edx, 0x1
         // 0040bdb8: call 0x40b364
         // 0040bdbd: pop ecx
         // 0040bdbe: mov eax, ss:[ebp+0x8]
         // 0040bdc1: push eax
         // 0040bdc2: mov eax, ds:[0x49e6a8]
         // 0040bdc7: call 0x40b728
         // 0040bdcc: pop ecx
         // 0040bdcd: jmp 0x40be78
      [-]803d8de64900000f8499000000
         // 0040bdd2: cmp b1 ds:[0x49e68d], b1 0x0
         // 0040bdd9: jz 0x40be78
      [-]8b450850b8????????ba????????e872f5ffff59e980000000
         // 0040bddf: mov eax, ss:[ebp+0x8]
         // 0040bde2: push eax
         // 0040bde3: mov eax, 0x49e68d
         // 0040bde8: mov edx, 0x1
         // 0040bded: call 0x40b364
         // 0040bdf2: pop ecx
         // 0040bdf3: jmp 0x40be78
      [-]803d98e64900007477
         // 0040bdf8: cmp b1 ds:[0x49e698], b1 0x0
         // 0040bdff: jz 0x40be78
      [-]8b450850b8????????ba????????e850f5ffff59eb61
         // 0040be01: mov eax, ss:[ebp+0x8]
         // 0040be04: push eax
         // 0040be05: mov eax, 0x49e698
         // 0040be0a: mov edx, 0x1
         // 0040be0f: call 0x40b364
         // 0040be14: pop ecx
         // 0040be15: jmp 0x40be78
      [-]8b75fceb1e
         // 0040be17: mov esi, ss:[ebp+0xfffffffffffffffc]
         // 0040be1a: jmp 0x40be3a
      [-]25????????0fa305????????730d
         // 0040be1c: and eax, 0xff
         // 0040be21: bt ds:[0x49b134], eax
         // 0040be28: jnb 0x40be37
      [-]8b45fce83e1f00008945fceb03
         // 0040be2a: mov eax, ss:[ebp+0xfffffffffffffffc]
         // 0040be2d: call 0x40dd70
         // 0040be32: mov ss:[ebp+0xfffffffffffffffc], eax
         // 0040be35: jmp 0x40be3a
      [-]8b45fc8a0084c07405
         // 0040be3a: mov eax, ss:[ebp+0xfffffffffffffffc]
         // 0040be3d: mov b1 al, b1 ds:[eax]
         // 0040be3f: test b1 al, b1 al
         // 0040be41: jz 0x40be48
      [-]3a45fb75d4
         // 0040be43: cmp b1 al, b1 ss:[ebp+0xfffffffffffffffb]
         // 0040be46: jnz 0x40be1c
      [-]8b4508508b55fc2bd68bc6e80cf5ffff598b45fc8038007417
         // 0040be48: mov eax, ss:[ebp+0x8]
         // 0040be4b: push eax
         // 0040be4c: mov edx, ss:[ebp+0xfffffffffffffffc]
         // 0040be4f: sub edx, esi
         // 0040be51: mov eax, esi
         // 0040be53: call 0x40b364
         // 0040be58: pop ecx
         // 0040be59: mov eax, ss:[ebp+0xfffffffffffffffc]
         // 0040be5c: cmp b1 ds:[eax], b1 0x0
         // 0040be5f: jz 0x40be78
      [-]ff45fceb12
         // 0040be61: inc ss:[ebp+0xfffffffffffffffc]
         // 0040be64: jmp 0x40be78
      [-]8b4508508d45fbba????????e8edf4ffff59
         // 0040be66: mov eax, ss:[ebp+0x8]
         // 0040be69: push eax
         // 0040be6a: lea eax, ss:[ebp+0xfffffffffffffffb]
         // 0040be6d: mov edx, 0x1
         // 0040be72: call 0x40b364
         // 0040be77: pop ecx
      [-]8b45fc8a0084c00f85faf8ffff
         // 0040be78: mov eax, ss:[ebp+0xfffffffffffffffc]
         // 0040be7b: mov b1 al, b1 ds:[eax]
         // 0040be7d: test b1 al, b1 al
         // 0040be7f: jnz 0x40b77f
      [-]8b4508ff88????????
         // 0040be85: mov eax, ss:[ebp+0x8]
         // 0040be88: dec ds:[eax+0xfffffffffffffef8]
      [-]33c05a595964891068????????8d45d8ba????????e83c8bffffc3
         // 0040be8e: xor eax, eax
         // 0040be90: pop edx
         // 0040be91: pop ecx
         // 0040be92: pop ecx
         // 0040be93: mov fs:[eax], edx
         // 0040be96: push 0x40beb0
         // 0040be9b: lea eax, ss:[ebp+0xffffffffffffffd8]
         // 0040be9e: mov edx, 0x2
         // 0040bea3: call @System@@LStrArrayClr$qqrpvi
         // 0040bea8: retn 
      [-]5e5b8be55dc3
         // 0040beb0: pop esi
         // 0040beb1: pop ebx
         // 0040beb2: mov esp, ebp
         // 0040beb4: pop ebp
         // 0040beb5: retn 
      [-]5383c4f08bd88bd48bc3e82500000084c07519
         // 0040c788: push ebx
         // 0040c789: add esp, 0xfffffffffffffff0
         // 0040c78c: mov ebx, eax
         // 0040c78e: mov edx, esp
         // 0040c790: mov eax, ebx
         // 0040c792: call 0x40c7bc
         // 0040c797: test b1 al, b1 al
         // 0040c799: jnz 0x40c7b4
      [-]895c2408c644240c0b8d542408a1????????33c9e8c8c4ffff
         // 0040c79b: mov ss:[esp+0x8], ebx
         // 0040c79f: mov b1 ss:[esp+0xc], b1 0xb
         // 0040c7a4: lea edx, ss:[esp+0x8]
         // 0040c7a8: mov eax, ds:[0x49da9c]
         // 0040c7ad: xor ecx, ecx
         // 0040c7af: call 0x408c7c
      [-]dd042483c4105bc3
         // 0040c7b4: fld b8 ss:[esp]
         // 0040c7b7: add esp, 0x10
         // 0040c7ba: pop ebx
         // 0040c7bb: retn 
      [-]5383c4f08bd88bd48bc3e82500000084c07519
         // 0040c7f0: push ebx
         // 0040c7f1: add esp, 0xfffffffffffffff0
         // 0040c7f4: mov ebx, eax
         // 0040c7f6: mov edx, esp
         // 0040c7f8: mov eax, ebx
         // 0040c7fa: call 0x40c824
         // 0040c7ff: test b1 al, b1 al
         // 0040c801: jnz 0x40c81c
      [-]895c2408c644240c0b8d542408a1????????33c9e860c4ffff
         // 0040c803: mov ss:[esp+0x8], ebx
         // 0040c807: mov b1 ss:[esp+0xc], b1 0xb
         // 0040c80c: lea edx, ss:[esp+0x8]
         // 0040c810: mov eax, ds:[0x49d8d4]
         // 0040c815: xor ecx, ecx
         // 0040c817: call 0x408c7c
      [-]dd042483c4105bc3
         // 0040c81c: fld b8 ss:[esp]
         // 0040c81f: add esp, 0x10
         // 0040c822: pop ebx
         // 0040c823: retn 
      [-]5383c4f08bd88bd48bc3e82500000084c07519
         // 0040c858: push ebx
         // 0040c859: add esp, 0xfffffffffffffff0
         // 0040c85c: mov ebx, eax
         // 0040c85e: mov edx, esp
         // 0040c860: mov eax, ebx
         // 0040c862: call @Sysutils@TryStrToDateTime$qqrx17System@AnsiStringr16System@TDateTime
         // 0040c867: test b1 al, b1 al
         // 0040c869: jnz 0x40c884
      [-]895c2408c644240c0b8d542408a1????????33c9e8f8c3ffff
         // 0040c86b: mov ss:[esp+0x8], ebx
         // 0040c86f: mov b1 ss:[esp+0xc], b1 0xb
         // 0040c874: lea edx, ss:[esp+0x8]
         // 0040c878: mov eax, ds:[0x49d74c]
         // 0040c87d: xor ecx, ecx
         // 0040c87f: call 0x408c7c
      [-]dd042483c4105bc3
         // 0040c884: fld b8 ss:[esp]
         // 0040c887: add esp, 0x10
         // 0040c88a: pop ebx
         // 0040c88b: retn 
      [-]8b4504c3
         // 0040d120: mov eax, ss:[ebp+0x4]
         // 0040d123: retn 
      [-]558bec81c4????????535633c08985????????8985????????8985????????8985????????8945fc33c05568????????64ff306489208b45088b58fc837b1400750f
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
         // 0040d5d0: push fs:[eax]
         // 0040d5d3: mov fs:[eax], esp
         // 0040d5d6: mov eax, ss:[ebp+0x8]
         // 0040d5d9: mov ebx, ds:[eax+0xfffffffffffffffc]
         // 0040d5dc: cmp ds:[ebx+0x14], 0x0
         // 0040d5e0: jnz 0x40d5f1
      [-]8d55fca1????????e88194ffffeb0d
         // 0040d5e2: lea edx, ss:[ebp+0xfffffffffffffffc]
         // 0040d5e5: mov eax, ds:[0x49de48]
         // 0040d5ea: call @System@LoadResString$qqrp20System@TResStringRec
         // 0040d5ef: jmp 0x40d5fe
      [-]8d55fca1????????e87294ffff
         // 0040d5f1: lea edx, ss:[ebp+0xfffffffffffffffc]
         // 0040d5f4: mov eax, ds:[0x49dbd4]
         // 0040d5f9: call @System@LoadResString$qqrp20System@TResStringRec
      [-]8b73186a1c8d45e0508b430c50e8609cffff817df0????????0f85b3000000
         // 0040d5fe: mov esi, ds:[ebx+0x18]
         // 0040d601: push 0x1c
         // 0040d603: lea eax, ss:[ebp+0xffffffffffffffe0]
         // 0040d606: push eax
         // 0040d607: mov eax, ds:[ebx+0xc]
         // 0040d60a: push eax
         // 0040d60b: call VirtualQuery_0
         // 0040d610: cmp ss:[ebp+0xfffffffffffffff0], 0x1000
         // 0040d617: jnz 0x40d6d0
      [-]68????????8d85????????508b45e450e8a69affff85c00f8496000000
         // 0040d61d: push 0x105
         // 0040d622: lea eax, ss:[ebp+0xfffffffffffffedb]
         // 0040d628: push eax
         // 0040d629: mov eax, ss:[ebp+0xffffffffffffffe4]
         // 0040d62c: push eax
         // 0040d62d: call GetModuleFileNameA_0
         // 0040d632: test eax, eax
         // 0040d634: jz 0x40d6d0
      [-]8b430c8985????????c685bcfeffff058d85????????8d95????????b9????????e8d075ffff8b85????????8d95????????e8a7c7ffff8b85????????8985????????c685c4feffff0b8b45fc8985????????c685ccfeffff0b89b5????????c685d4feffff058d85????????506a038d95????????a1????????e8b693ffff8b8d????????b201a1????????e8b4faffff8bd8eb5a
         // 0040d63a: mov eax, ds:[ebx+0xc]
         // 0040d63d: mov ss:[ebp+0xfffffffffffffeb8], eax
         // 0040d643: mov b1 ss:[ebp+0xfffffffffffffebc], b1 0x5
         // 0040d64a: lea eax, ss:[ebp+0xfffffffffffffeb0]
         // 0040d650: lea edx, ss:[ebp+0xfffffffffffffedb]
         // 0040d656: mov ecx, 0x105
         // 0040d65b: call 0x404c30
         // 0040d660: mov eax, ss:[ebp+0xfffffffffffffeb0]
         // 0040d666: lea edx, ss:[ebp+0xfffffffffffffeb4]
         // 0040d66c: call @Sysutils@ExtractFileName$qqrx17System@AnsiString
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
         // 0040d6b5: call @System@LoadResString$qqrp20System@TResStringRec
         // 0040d6ba: mov ecx, ss:[ebp+0xfffffffffffffeac]
         // 0040d6c0: mov b1 dl, b1 0x1
         // 0040d6c2: mov eax, ds:[0x40870c]
         // 0040d6c7: call @Sysutils@Exception@$bctr$qqrx17System@AnsiStringpx14System@TVarRecxi
         // 0040d6cc: mov ebx, eax
         // 0040d6ce: jmp 0x40d72a
      [-]8b430c8985????????c68598feffff058b45fc8985????????c685a0feffff0b89b5????????c685a8feffff058d85????????506a028d95????????a1????????e85a93ffff8b8d????????b201a1????????e858faffff8bd8
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
         // 0040d711: call @System@LoadResString$qqrp20System@TResStringRec
         // 0040d716: mov ecx, ss:[ebp+0xfffffffffffffe90]
         // 0040d71c: mov b1 dl, b1 0x1
         // 0040d71e: mov eax, ds:[0x40870c]
         // 0040d723: call @Sysutils@Exception@$bctr$qqrx17System@AnsiStringpx14System@TVarRecxi
         // 0040d728: mov ebx, eax
      [-]33c05a595964891068????????8d85????????e87e72ffff8d85????????ba????????e89272ffff8d45fce86672ffffc3
         // 0040d72a: xor eax, eax
         // 0040d72c: pop edx
         // 0040d72d: pop ecx
         // 0040d72e: pop ecx
         // 0040d72f: mov fs:[eax], edx
         // 0040d732: push 0x40d762
         // 0040d737: lea eax, ss:[ebp+0xfffffffffffffe90]
         // 0040d73d: call @System@@LStrClr$qqrpv
         // 0040d742: lea eax, ss:[ebp+0xfffffffffffffeac]
         // 0040d748: mov edx, 0x3
         // 0040d74d: call @System@@LStrArrayClr$qqrpvi
         // 0040d752: lea eax, ss:[ebp+0xfffffffffffffffc]
         // 0040d755: call @System@@LStrClr$qqrpv
         // 0040d75a: retn 
      [-]8bc35e5b8be55dc3
         // 0040d762: mov eax, ebx
         // 0040d764: pop esi
         // 0040d765: pop ebx
         // 0040d766: mov esp, ebp
         // 0040d768: pop ebp
         // 0040d769: retn 
      [-]50e87a97ffffc3
         // 0040dd70: push eax
         // 0040dd71: call CharNextA_0
         // 0040dd76: retn 
      [-]53568bf28bd8b8????????803d50e74900007422
         // 0040dd78: push ebx
         // 0040dd79: push esi
         // 0040dd7a: mov esi, edx
         // 0040dd7c: mov ebx, eax
         // 0040dd7e: mov eax, 0x1
         // 0040dd83: cmp b1 ds:[0x49e750], b1 0x0
         // 0040dd8a: jz 0x40ddae
      [-]8a5433ff81e2????????0fa315????????730f
         // 0040dd8c: mov b1 dl, b1 ds:[ebx+esi+0xffffffffffffffff]
         // 0040dd90: and edx, 0xff
         // 0040dd96: bt ds:[0x49b134], edx
         // 0040dd9d: jnb 0x40ddae
      [-]8bc3e8da70ffff03c648e8a2ffffff
         // 0040dd9f: mov eax, ebx
         // 0040dda1: call @System@@LStrToPChar$qqrx17System@AnsiString
         // 0040dda6: add eax, esi
         // 0040dda8: dec eax
         // 0040dda9: call @Sysutils@StrCharLength$qqrpxc
      [-]53568bda8bf08d4301803d50e74900007424
         // 0040ddb4: push ebx
         // 0040ddb5: push esi
         // 0040ddb6: mov ebx, edx
         // 0040ddb8: mov esi, eax
         // 0040ddba: lea eax, ds:[ebx+0x1]
         // 0040ddbd: cmp b1 ds:[0x49e750], b1 0x0
         // 0040ddc4: jz 0x40ddea
      [-]8a541eff81e2????????0fa315????????7311
         // 0040ddc6: mov b1 dl, b1 ds:[esi+ebx+0xffffffffffffffff]
         // 0040ddca: and edx, 0xff
         // 0040ddd0: bt ds:[0x49b134], edx
         // 0040ddd7: jnb 0x40ddea
      [-]8bc6e8a070ffff03c348e868ffffff03c3
         // 0040ddd9: mov eax, esi
         // 0040dddb: call @System@@LStrToPChar$qqrx17System@AnsiString
         // 0040dde0: add eax, ebx
         // 0040dde2: dec eax
         // 0040dde3: call @Sysutils@StrCharLength$qqrpxc
         // 0040dde8: add eax, ebx
      [-]53568bf28bd88bd68bc3e8050000005e5bc3
         // 0040de68: push ebx
         // 0040de69: push esi
         // 0040de6a: mov esi, edx
         // 0040de6c: mov ebx, eax
         // 0040de6e: mov edx, esi
         // 0040de70: mov eax, ebx
         // 0040de72: call @Idglobal@IncludeTrailingBackSlash$qqrx17System@AnsiString
         // 0040de77: pop esi
         // 0040de78: pop ebx
         // 0040de79: retn 
      [-]871089d0c3
         // 0040e8f8: xchg edx, ds:[eax]
         // 0040e8fa: mov eax, edx
         // 0040e8fc: retn 
      [-]92f00fc102c3
         // 0040e900: xchg eax, edx
         // 0040e901: lock xadd ds:[edx], eax
         // 0040e905: retn 
      [-]53565755e86756ffff8bda8bf833f6
         // 0040e908: push ebx
         // 0040e909: push esi
         // 0040e90a: push edi
         // 0040e90b: push ebp
         // 0040e90c: call @System@@BeforeDestruction$qqrp14System@TObjectzc
         // 0040e911: mov ebx, edx
         // 0040e913: mov edi, eax
         // 0040e915: xor esi, esi
      [-]8b6cb70433c08944b70485ed740e
         // 0040e917: mov ebp, ds:[edi+esi*0x4]
         // 0040e91b: xor eax, eax
         // 0040e91d: mov ds:[edi+esi*0x4], eax
         // 0040e921: test ebp, ebp
         // 0040e923: jz 0x40e933
      [-]8bc58b6d00e84d3effff85ed75f2
         // 0040e925: mov eax, ebp
         // 0040e927: mov ebp, ss:[ebp+0x0]
         // 0040e92a: call @System@@FreeMem$qqrpv
         // 0040e92f: test ebp, ebp
         // 0040e931: jnz 0x40e925
      [-]4683fe1075de
         // 0040e933: inc esi
         // 0040e934: cmp esi, 0x10
         // 0040e937: jnz 0x40e917
      [-]8bd380e2fc8bc7e89752ffff84db7e07
         // 0040e939: mov edx, ebx
         // 0040e93b: and b1 dl, b1 0xfc
         // 0040e93e: mov eax, edi
         // 0040e940: call @System@TObject@$bdtr$qqrv
         // 0040e945: test b1 bl, b1 bl
         // 0040e947: jle 0x40e950
      [-]8bc7e81056ffff
         // 0040e949: mov eax, edi
         // 0040e94b: call @System@@ClassDestroy$qqrp14System@TObject
      [-]5d5f5e5bc3
         // 0040e950: pop ebp
         // 0040e951: pop edi
         // 0040e952: pop esi
         // 0040e953: pop ebx
         // 0040e954: retn 
      [-]53565755518914248bf88bc7e8d7ffffff8bd8e8f086ffff8bf033c08ac38b6c8704eb03
         // 0040e970: push ebx
         // 0040e971: push esi
         // 0040e972: push edi
         // 0040e973: push ebp
         // 0040e974: push ecx
         // 0040e975: mov ss:[esp], edx
         // 0040e978: mov edi, eax
         // 0040e97a: mov eax, edi
         // 0040e97c: call @Sysutils@TThreadLocalCounter@HashIndex$qqrv
         // 0040e981: mov ebx, eax
         // 0040e983: call GetCurrentThreadId_0
         // 0040e988: mov esi, eax
         // 0040e98a: xor eax, eax
         // 0040e98c: mov b1 al, b1 bl
         // 0040e98e: mov ebp, ds:[edi+eax*0x4]
         // 0040e992: jmp 0x40e997
      [-]85ed7405
         // 0040e997: test ebp, ebp
         // 0040e999: jz 0x40e9a0
      [-]3b750475f4
         // 0040e99b: cmp esi, ss:[ebp+0x4]
         // 0040e99e: jnz 0x40e994
      [-]85ed7538
         // 0040e9a0: test ebp, ebp
         // 0040e9a2: jnz 0x40e9dc
      [-]8bc7e84d0000008be885ed752b
         // 0040e9a4: mov eax, edi
         // 0040e9a6: call 0x40e9f8
         // 0040e9ab: mov ebp, eax
         // 0040e9ad: test ebp, ebp
         // 0040e9af: jnz 0x40e9dc
      [-]b8????????e869a3ffff8be8897504c74508????????896d0033c08ac38d4487048bd5e81fffffff894500
         // 0040e9b1: mov eax, 0x10
         // 0040e9b6: call @Sysutils@AllocMem$qqrui
         // 0040e9bb: mov ebp, eax
         // 0040e9bd: mov ss:[ebp+0x4], esi
         // 0040e9c0: mov ss:[ebp+0x8], 0x7fffffff
         // 0040e9c7: mov ss:[ebp+0x0], ebp
         // 0040e9ca: xor eax, eax
         // 0040e9cc: mov b1 al, b1 bl
         // 0040e9ce: lea eax, ds:[edi+eax*0x4]
         // 0040e9d2: mov edx, ebp
         // 0040e9d4: call 0x40e8f8
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
      [-]538bd88bc3e856ffffff25??????
         // 0040e9f8: push ebx
         // 0040e9f9: mov ebx, eax
         // 0040e9fb: mov eax, ebx
         // 0040e9fd: call @Sysutils@TThreadLocalCounter@HashIndex$qqrv
         // 0040ea02: and eax, 0xff
         // 0040ea07: mov ebx, ds:[ebx+eax*0x4]
         // 0040ea0b: test ebx, ebx
         // 0040ea0d: jz 0x40ea33

  }
  condition:
    all of them
}
