rule urelas_20_0 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         088bf1e8
         // 002b77c7: mov esi, ecx
         // 002b77c9: call ??0exception@std@@QAE@ABV01@@Z
      [-]558bec83ec28a1
         // 002b799d: push ebp
         // 002b799e: mov ebp, esp
         // 002b79a0: sub esp, 0x28
         // 002b79a3: mov eax, ds:[0x2c2044]
      [-]33c58945fc53568b750857ff75108b7d0c8d4ddce8
         // 002b79a8: xor eax, ebp
         // 002b79aa: mov ss:[ebp+0xfffffffffffffffc], eax
         // 002b79ad: push ebx
         // 002b79ae: push esi
         // 002b79af: mov esi, ss:[ebp+0x8]
         // 002b79b2: push edi
         // 002b79b3: push ss:[ebp+0x10]
         // 002b79b6: mov edi, ss:[ebp+0xc]
         // 002b79b9: lea ecx, ss:[ebp+0xffffffffffffffdc]
         // 002b79bc: call ??0_LocaleUpdate@@QAE@PAUlocaleinfo_struct@@@Z
      [-]8d45dc5033db53535353578d45d8508d45f050e8
         // 002b79c1: lea eax, ss:[ebp+0xffffffffffffffdc]
         // 002b79c4: push eax
         // 002b79c5: xor ebx, ebx
         // 002b79c7: push ebx
         // 002b79c8: push ebx
         // 002b79c9: push ebx
         // 002b79ca: push ebx
         // 002b79cb: push edi
         // 002b79cc: lea eax, ss:[ebp+0xffffffffffffffd8]
         // 002b79cf: push eax
         // 002b79d0: lea eax, ss:[ebp+0xfffffffffffffff0]
         // 002b79d3: push eax
         // 002b79d4: call ___strgtold12_l
      [-]00008945ec8d45f05650e8
         // 002b79d9: mov ss:[ebp+0xffffffffffffffec], eax
         // 002b79dc: lea eax, ss:[ebp+0xfffffffffffffff0]
         // 002b79df: push esi
         // 002b79e0: push eax
         // 002b79e1: call 0x2b7e86
      [-]000083c428f645ec03752b
         // 002b79e6: add esp, 0x28
         // 002b79e9: test b1 ss:[ebp+0xffffffffffffffec], b1 0x3
         // 002b79ed: jnz 0x2b7a1a
      [-]83f8017511
         // 0041fc2e: cmp eax, 0x1
         // 0041fc31: jnz 0x41fc44
      [-]385de87407
         // 0041fc33: cmp b1 ss:[ebp+0xffffffffffffffe8], b1 bl
         // 0041fc36: jz 0x41fc3f
      [-]8b45e4836070fd
         // 0041fc38: mov eax, ss:[ebp+0xffffffffffffffe4]
         // 0041fc3b: and ds:[eax+0x70], 0xfffffffffffffffd
      [-]83f802751c
         // 0041fc44: cmp eax, 0x2
         // 0041fc47: jnz 0x41fc65
      [-]385de87407
         // 0041fc49: cmp b1 ss:[ebp+0xffffffffffffffe8], b1 bl
         // 0041fc4c: jz 0x41fc55
      [-]8b45e4836070fd
         // 0041fc4e: mov eax, ss:[ebp+0xffffffffffffffe4]
         // 0041fc51: and ds:[eax+0x70], 0xfffffffffffffffd
      [-]6a04ebe8
         // 0041fc55: push 0x4
         // 0041fc57: jmp 0x41fc41
      [-]f645ec0175ea
         // 0041fc59: test b1 ss:[ebp+0xffffffffffffffec], b1 0x1
         // 0041fc5d: jnz 0x41fc49
      [-]f645ec0275ce
         // 0041fc5f: test b1 ss:[ebp+0xffffffffffffffec], b1 0x2
         // 0041fc63: jnz 0x41fc33
      [-]385de87407
         // 0041fc65: cmp b1 ss:[ebp+0xffffffffffffffe8], b1 bl
         // 0041fc68: jz 0x41fc71
      [-]8b45e4836070fd
         // 0041fc6a: mov eax, ss:[ebp+0xffffffffffffffe4]
         // 0041fc6d: and ds:[eax+0x70], 0xfffffffffffffffd
      [-]8b4dfc5f5e33cd5be8
         // 00418d83: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 00418d86: pop edi
         // 00418d87: pop esi
         // 00418d88: xor ecx, ebp
         // 00418d8a: pop ebx
         // 00418d8b: call 0x408c2e
      [-]558bec83ec28a1
         // 002b7a45: push ebp
         // 002b7a46: mov ebp, esp
         // 002b7a48: sub esp, 0x28
         // 002b7a4b: mov eax, ds:[0x2c2044]
      [-]33c58945fc53568b750857ff75108b7d0c8d4ddce8
         // 002b7a50: xor eax, ebp
         // 002b7a52: mov ss:[ebp+0xfffffffffffffffc], eax
         // 002b7a55: push ebx
         // 002b7a56: push esi
         // 002b7a57: mov esi, ss:[ebp+0x8]
         // 002b7a5a: push edi
         // 002b7a5b: push ss:[ebp+0x10]
         // 002b7a5e: mov edi, ss:[ebp+0xc]
         // 002b7a61: lea ecx, ss:[ebp+0xffffffffffffffdc]
         // 002b7a64: call ??0_LocaleUpdate@@QAE@PAUlocaleinfo_struct@@@Z
      [-]8d45dc5033db53535353578d45d8508d45f050e8
         // 002b7a69: lea eax, ss:[ebp+0xffffffffffffffdc]
         // 002b7a6c: push eax
         // 002b7a6d: xor ebx, ebx
         // 002b7a6f: push ebx
         // 002b7a70: push ebx
         // 002b7a71: push ebx
         // 002b7a72: push ebx
         // 002b7a73: push edi
         // 002b7a74: lea eax, ss:[ebp+0xffffffffffffffd8]
         // 002b7a77: push eax
         // 002b7a78: lea eax, ss:[ebp+0xfffffffffffffff0]
         // 002b7a7b: push eax
         // 002b7a7c: call ___strgtold12_l
      [-]00008945ec8d45f05650e8
         // 002b7a81: mov ss:[ebp+0xffffffffffffffec], eax
         // 002b7a84: lea eax, ss:[ebp+0xfffffffffffffff0]
         // 002b7a87: push esi
         // 002b7a88: push eax
         // 002b7a89: call 0x2b83d7
      [-]000083c428f645ec03752b
         // 002b7a8e: add esp, 0x28
         // 002b7a91: test b1 ss:[ebp+0xffffffffffffffec], b1 0x3
         // 002b7a95: jnz 0x2b7ac2
      [-]83f8017511
         // 0041fcd4: cmp eax, 0x1
         // 0041fcd7: jnz 0x41fcea
      [-]385de87407
         // 0041fcd9: cmp b1 ss:[ebp+0xffffffffffffffe8], b1 bl
         // 0041fcdc: jz 0x41fce5
      [-]8b45e4836070fd
         // 0041fcde: mov eax, ss:[ebp+0xffffffffffffffe4]
         // 0041fce1: and ds:[eax+0x70], 0xfffffffffffffffd
      [-]83f802751c
         // 0041fcea: cmp eax, 0x2
         // 0041fced: jnz 0x41fd0b
      [-]385de87407
         // 0041fcef: cmp b1 ss:[ebp+0xffffffffffffffe8], b1 bl
         // 0041fcf2: jz 0x41fcfb
      [-]8b45e4836070fd
         // 0041fcf4: mov eax, ss:[ebp+0xffffffffffffffe4]
         // 0041fcf7: and ds:[eax+0x70], 0xfffffffffffffffd
      [-]6a04ebe8
         // 0041fcfb: push 0x4
         // 0041fcfd: jmp 0x41fce7
      [-]f645ec0175ea
         // 0041fcff: test b1 ss:[ebp+0xffffffffffffffec], b1 0x1
         // 0041fd03: jnz 0x41fcef
      [-]f645ec0275ce
         // 0041fd05: test b1 ss:[ebp+0xffffffffffffffec], b1 0x2
         // 0041fd09: jnz 0x41fcd9
      [-]385de87407
         // 0041fd0b: cmp b1 ss:[ebp+0xffffffffffffffe8], b1 bl
         // 0041fd0e: jz 0x41fd17
      [-]8b45e4836070fd
         // 0041fd10: mov eax, ss:[ebp+0xffffffffffffffe4]
         // 0041fd13: and ds:[eax+0x70], 0xfffffffffffffffd
      [-]8b4dfc5f5e33cd5be8
         // 00418e29: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 00418e2c: pop edi
         // 00418e2d: pop esi
         // 00418e2e: xor ecx, ebp
         // 00418e30: pop ebx
         // 00418e31: call 0x408c2e
      [-]558bec83ec
         // 004191a9: push ebp
         // 004191aa: mov ebp, esp
         // 004191ac: sub esp, 0x2c
      [-]0fb7480a538bd981e1????????894d
         // 004191b2: movzx ecx, b2 ds:[eax+0xa]
         // 004191b6: push ebx
         // 004191b7: mov ebx, ecx
         // 004191b9: and ecx, 0x8000
         // 004191bf: mov ss:[ebp+0xffffffffffffffec], ecx
      [-]8b4806894d
         // 004191c2: mov ecx, ds:[eax+0x6]
         // 004191c5: mov ss:[ebp+0xffffffffffffffe0], ecx
      [-]8b48020fb70081e3????????81eb????????c1e010
         // 004191c8: mov ecx, ds:[eax+0x2]
         // 004191cb: movzx eax, b2 ds:[eax]
         // 004191ce: and ebx, 0x7fff
         // 004191d4: sub ebx, 0x3fff
         // 004191da: shl eax, b1 0x10
      [-]33db33c0
         // 00420112: xor ebx, ebx
         // 00420114: xor eax, eax
      [-]4083f8037cf4
         // 0042011c: inc eax
         // 0042011d: cmp eax, 0x3
         // 00420120: jl 0x420116
      [-]33c08d7d
         // 00420129: xor eax, eax
         // 0042012b: lea edi, ss:[ebp+0xffffffffffffffe0]
      [-]abab6a02ab58e9
         // 0042012e: stosdd 
         // 0042012f: stosdd 
         // 00420130: push 0x2
         // 00420132: stosdd 
         // 00420133: pop eax
         // 00420134: jmp 0x4205ce
      [-]00568d75
         // 00425e98: push esi
         // 00425e99: lea esi, ss:[ebp+0xffffffffffffffe0]
      [-]a5a5a58b
         // 00425e9f: movsdd 
         // 00425ea0: movsdd 
         // 00425ea1: movsdd 
         // 00425ea2: mov esi, ds:[0x433c98]
      [-]9983e21f03c2c1f805
         // 00425eae: cdq 
         // 00425eaf: and edx, 0x1f
         // 00425eb2: add eax, edx
         // 00425eb4: sar eax, b1 0x5
      [-]81e2????????895d
         // 00425eb9: and edx, 0xffffffff8000001f
         // 00425ebf: mov ss:[ebp+0xfffffffffffffff0], ebx
      [-]4a83cae042
         // 0042016c: dec edx
         // 0042016d: or edx, 0xffffffffffffffe0
         // 00420170: inc edx
      [-]6a1f33c0592bca40d3e0894d
         // 00420175: push 0x1f
         // 00420177: xor eax, eax
         // 00420179: pop ecx
         // 0042017a: sub ecx, edx
         // 0042017c: inc eax
         // 0042017d: shl eax, b1 cl
         // 0042017f: mov ss:[ebp+0xfffffffffffffff8], ecx
      [-]0f848d000000
         // 00420184: jz 0x420217
      [-]83caffd3e2f7d2855485
         // 0042018d: or edx, 0xffffffffffffffff
         // 00420190: shl edx, b1 cl
         // 00420192: not edx
         // 00420194: test ss:[ebp+eax*0x4], edx
      [-]4083f8037cf3
         // 004201a1: inc eax
         // 004201a2: cmp eax, 0x3
         // 004201a5: jl 0x42019a
      [-]996a1f5923d103c2c1f80581
         // 004201ab: cdq 
         // 004201ac: push 0x1f
         // 004201ae: pop ecx
         // 004201af: and edx, ecx
         // 004201b1: add eax, edx
         // 004201b3: sar eax, b1 0x5
         // 004201b6: and esi, 0xffffffff8000001f
      [-]33d242d3e28d4c85
         // 004201c9: xor edx, edx
         // 004201cb: inc edx
         // 004201cc: shl edx, b1 cl
         // 004201ce: lea ecx, ss:[ebp+eax*0x4]
      [-]85c9742b
         // 004201e5: test ecx, ecx
         // 004201e7: jz 0x420214
      [-]008d4c85
         // 0041979d: lea ecx, ss:[ebp+eax*0x4]
      [-]89118b4d
         // 0042020d: mov ds:[ecx], edx
         // 0042020f: mov ecx, ss:[ebp+0xfffffffffffffffc]
      [-]83c8ffd3e021
         // 0042021a: or eax, 0xffffffffffffffff
         // 0042021d: shl eax, b1 cl
         // 0042021f: and ds:[edi], eax
      [-]2bc833c0f3ab
         // 002b7ff8: sub ecx, eax
         // 002b7ffa: xor eax, eax
         // 002b7ffc: rep stosdd 
      [-]8bc82b0d
         // 0041931d: mov ecx, eax
         // 0041931f: sub ecx, ds:[0x4236f8]
      [-]3bd97d0d
         // 00419325: cmp ebx, ecx
         // 00419327: jge 0x419336
      [-]33c08d7d
         // 0042024f: xor eax, eax
         // 00420251: lea edi, ss:[ebp+0xffffffffffffffe0]
      [-]abababe9
         // 00420254: stosdd 
         // 00420255: stosdd 
         // 00420256: stosdd 
         // 00420257: jmp 0x420469
      [-]3bd80f8f
         // 0042025c: cmp ebx, eax
         // 0042025e: jg 0x420473
      [-]8bc88d7d
         // 0042026a: mov ecx, eax
         // 0042026c: lea edi, ss:[ebp+0xffffffffffffffe0]
      [-]a59983e21f03c2a58bd1c1f80581e2????????a57905
         // 0042026f: movsdd 
         // 00420270: cdq 
         // 00420271: and edx, 0x1f
         // 00420274: add eax, edx
         // 00420276: movsdd 
         // 00420277: mov edx, ecx
         // 00420279: sar eax, b1 0x5
         // 0042027c: and edx, 0xffffffff8000001f
         // 00420282: movsdd 
         // 00420283: jns 0x42028a
      [-]4a83cae042
         // 00420285: dec edx
         // 00420286: or edx, 0xffffffffffffffe0
         // 00420289: inc edx
      [-]0083cfff8bcad3e7c745
         // 00420292: or edi, 0xffffffffffffffff
         // 00420295: mov ecx, edx
         // 00420297: shl edi, b1 cl
         // 00420299: mov ss:[ebp+0xfffffffffffffffc], 0x20
      [-]8b338bce23cf894d
         // 004202ac: mov esi, ds:[ebx]
         // 004202ae: mov ecx, esi
         // 004202b0: and ecx, edi
         // 004202b2: mov ss:[ebp+0xfffffffffffffff0], ecx
      [-]8bcad3ee8b4d
         // 004202b5: mov ecx, edx
         // 004202b7: shr esi, b1 cl
         // 004202b9: mov ecx, ss:[ebp+0xfffffffffffffffc]
      [-]89338b75
         // 004202bf: mov ds:[ebx], esi
         // 004202c1: mov esi, ss:[ebp+0xfffffffffffffff0]
      [-]d3e6ff45
         // 004202c4: shl esi, b1 cl
         // 004202c6: inc ss:[ebp+0x8]
      [-]8bf06a02c1e6028d4d
         // 004202d2: mov esi, eax
         // 004202d4: push 0x2
         // 004202d6: shl esi, b1 0x2
         // 004202d9: lea ecx, ss:[ebp+0xffffffffffffffe8]
      [-]3bd07c08
         // 004202df: cmp edx, eax
         // 004202e1: jl 0x4202eb
      [-]8b31897495
         // 004202e3: mov esi, ds:[ecx]
         // 004202e5: mov ss:[ebp+edx*0x4], esi
      [-]9983e21f03c2c1f805
         // 0042605f: cdq 
         // 00426060: and edx, 0x1f
         // 00426063: add eax, edx
         // 00426065: sar eax, b1 0x5
      [-]81e2????????8945
         // 0042606a: and edx, 0xffffffff8000001f
         // 00426070: mov ss:[ebp+0xfffffffffffffff4], eax
      [-]4a83cae042
         // 0042031a: dec edx
         // 0042031b: or edx, 0xffffffffffffffe0
         // 0042031e: inc edx
      [-]6a1f592bca33d242d3e28d5c85
         // 0042031f: push 0x1f
         // 00420321: pop ecx
         // 00420322: sub ecx, edx
         // 00420324: xor edx, edx
         // 00420326: inc edx
         // 00420327: shl edx, b1 cl
         // 00420329: lea ebx, ss:[ebp+eax*0x4]
      [-]85130f8482000000
         // 00420330: test ds:[ebx], edx
         // 00420332: jz 0x4203ba
      [-]83caffd3e2f7d2855485
         // 00420338: or edx, 0xffffffffffffffff
         // 0042033b: shl edx, b1 cl
         // 0042033d: not edx
         // 0042033f: test ss:[ebp+eax*0x4], edx
      [-]4083f8037cf3
         // 0042034c: inc eax
         // 0042034d: cmp eax, 0x3
         // 00420350: jl 0x420345
      [-]8bc6996a1f5923d103c2c1f80581e6????????7905
         // 00420354: mov eax, esi
         // 00420356: cdq 
         // 00420357: push 0x1f
         // 00420359: pop ecx
         // 0042035a: and edx, ecx
         // 0042035c: add eax, edx
         // 0042035e: sar eax, b1 0x5
         // 00420361: and esi, 0xffffffff8000001f
         // 00420367: jns 0x42036e
      [-]4e83cee046
         // 00420369: dec esi
         // 0042036a: or esi, 0xffffffffffffffe0
         // 0042036d: inc esi
      [-]0033d22bce42d3e28d4c85
         // 00420372: xor edx, edx
         // 00420374: sub ecx, esi
         // 00420376: inc edx
         // 00420377: shl edx, b1 cl
         // 00420379: lea ecx, ss:[ebp+eax*0x4]
      [-]8b318d3c163bfe7204
         // 0042037d: mov esi, ds:[ecx]
         // 0042037f: lea edi, ds:[esi+edx]
         // 00420382: cmp edi, esi
         // 00420384: jb 0x42038a
      [-]3bfa7307
         // 00420386: cmp edi, edx
         // 00420388: jnb 0x420391
      [-]89398b4d
         // 00420391: mov ds:[ecx], edi
         // 00420393: mov ecx, ss:[ebp+0x8]
      [-]85c9741e
         // 00420398: test ecx, ecx
         // 0042039a: jz 0x4203ba
      [-]8b118d720133ff3bf27205
         // 004203a0: mov edx, ds:[ecx]
         // 004203a2: lea esi, ds:[edx+0x1]
         // 004203a5: xor edi, edi
         // 004203a7: cmp esi, edx
         // 004203a9: jb 0x4203b0
      [-]83fe017303
         // 004203ab: cmp esi, 0x1
         // 004203ae: jnb 0x4203b3
      [-]89318bcf
         // 004203b3: mov ds:[ecx], esi
         // 004203b5: mov ecx, edi
      [-]83c8ffd3e021038b45
         // 004203bd: or eax, 0xffffffffffffffff
         // 004203c0: shl eax, b1 cl
         // 004203c2: and ds:[ebx], eax
         // 004203c4: mov eax, ss:[ebp+0xfffffffffffffff4]
      [-]4083f8037d0d
         // 004203c7: inc eax
         // 004203c8: cmp eax, 0x3
         // 004203cb: jge 0x4203da
      [-]6a03598d7c85
         // 004203cd: push 0x3
         // 004203cf: pop ecx
         // 004203d0: lea edi, ss:[ebp+eax*0x4]
      [-]2bc833c0f3ab
         // 004203d4: sub ecx, eax
         // 004203d6: xor eax, eax
         // 004203d8: rep stosdd 
      [-]9983e21f03c2
         // 0042613e: cdq 
         // 0042613f: and edx, 0x1f
         // 00426142: add eax, edx
      [-]c1f80581e2????????7905
         // 00426146: sar eax, b1 0x5
         // 00426149: and edx, 0xffffffff8000001f
         // 0042614f: jns 0x426156
      [-]4a83cae042
         // 004203f6: dec edx
         // 004203f7: or edx, 0xffffffffffffffe0
         // 004203fa: inc edx
      [-]0083cfff8bcad3e7c745
         // 00420403: or edi, 0xffffffffffffffff
         // 00420406: mov ecx, edx
         // 00420408: shl edi, b1 cl
         // 0042040a: mov ss:[ebp+0xfffffffffffffffc], 0x20
      [-]8b338bce23cf894d
         // 0042041d: mov esi, ds:[ebx]
         // 0042041f: mov ecx, esi
         // 00420421: and ecx, edi
         // 00420423: mov ss:[ebp+0xfffffffffffffff0], ecx
      [-]8bcad3ee8b4d
         // 00420426: mov ecx, edx
         // 00420428: shr esi, b1 cl
         // 0042042a: mov ecx, ss:[ebp+0xfffffffffffffffc]
      [-]89338b75
         // 00420430: mov ds:[ebx], esi
         // 00420432: mov esi, ss:[ebp+0xfffffffffffffff0]
      [-]d3e6ff45
         // 00420435: shl esi, b1 cl
         // 00420437: inc ss:[ebp+0x8]
      [-]8bf06a02c1e6028d4d
         // 00420443: mov esi, eax
         // 00420445: push 0x2
         // 00420447: shl esi, b1 0x2
         // 0042044a: lea ecx, ss:[ebp+0xffffffffffffffe8]
      [-]3bd07c08
         // 00420450: cmp edx, eax
         // 00420452: jl 0x42045c
      [-]8b31897495
         // 00420454: mov esi, ds:[ecx]
         // 00420456: mov ss:[ebp+edx*0x4], esi
      [-]6a0233db58e9
         // 00420469: push 0x2
         // 0042046b: xor ebx, ebx
         // 0042046d: pop eax
         // 0042046e: jmp 0x4205cd
      [-]33c08d7d
         // 00420485: xor eax, eax
         // 00420487: lea edi, ss:[ebp+0xffffffffffffffe0]
      [-]ababab814d
         // 0042048a: stosdd 
         // 0042048b: stosdd 
         // 0042048c: stosdd 
         // 0042048d: or ss:[ebp+0xffffffffffffffe0], 0xffffffff80000000
      [-]8bc19983e21f03c28bd1c1f80581e2????????7905
         // 00420494: mov eax, ecx
         // 00420496: cdq 
         // 00420497: and edx, 0x1f
         // 0042049a: add eax, edx
         // 0042049c: mov edx, ecx
         // 0042049e: sar eax, b1 0x5
         // 004204a1: and edx, 0xffffffff8000001f
         // 004204a7: jns 0x4204ae
      [-]4a83cae042
         // 004204a9: dec edx
         // 004204aa: or edx, 0xffffffffffffffe0
         // 004204ad: inc edx
      [-]0083cfff8bcad3e7c745
         // 004204b6: or edi, 0xffffffffffffffff
         // 004204b9: mov ecx, edx
         // 004204bb: shl edi, b1 cl
         // 004204bd: mov ss:[ebp+0xfffffffffffffffc], 0x20
      [-]8b338bce23cf894d
         // 004204d0: mov esi, ds:[ebx]
         // 004204d2: mov ecx, esi
         // 004204d4: and ecx, edi
         // 004204d6: mov ss:[ebp+0xfffffffffffffff0], ecx
      [-]8bcad3ee8b4d
         // 004204d9: mov ecx, edx
         // 004204db: shr esi, b1 cl
         // 004204dd: mov ecx, ss:[ebp+0xfffffffffffffffc]
      [-]89338b75
         // 004204e3: mov ds:[ebx], esi
         // 004204e5: mov esi, ss:[ebp+0xfffffffffffffff0]
      [-]d3e6ff45
         // 004204e8: shl esi, b1 cl
         // 004204ea: inc ss:[ebp+0x8]
      [-]8bf06a02c1e6028d4d
         // 004204f6: mov esi, eax
         // 004204f8: push 0x2
         // 004204fa: shl esi, b1 0x2
         // 004204fd: lea ecx, ss:[ebp+0xffffffffffffffe8]
      [-]3bd07c08
         // 00420503: cmp edx, eax
         // 00420505: jl 0x42050f
      [-]8b31897495
         // 00420507: mov esi, ds:[ecx]
         // 00420509: mov ss:[ebp+edx*0x4], esi
      [-]33c040e9
         // 00426285: xor eax, eax
         // 00426287: inc eax
         // 00426288: jmp 0x426328
      [-]8bc19983e21f03c28bd1c1f80581e2????????7905
         // 0041961a: mov eax, ecx
         // 0041961c: cdq 
         // 0041961d: and edx, 0x1f
         // 00419620: add eax, edx
         // 00419622: mov edx, ecx
         // 00419624: sar eax, b1 0x5
         // 00419627: and edx, 0xffffffff8000001f
         // 0041962d: jns 0x419634
      [-]4a83cae042
         // 00420555: dec edx
         // 00420556: or edx, 0xffffffffffffffe0
         // 00420559: inc edx
      [-]0083ceff8bcad3e6c745
         // 00420562: or esi, 0xffffffffffffffff
         // 00420565: mov ecx, edx
         // 00420567: shl esi, b1 cl
         // 00420569: mov ss:[ebp+0xfffffffffffffffc], 0x20
      [-]8bcf23ce894d
         // 0042057c: mov ecx, edi
         // 0042057e: and ecx, esi
         // 00420580: mov ss:[ebp+0xfffffffffffffff0], ecx
      [-]8bcad3ef8b4d
         // 00420583: mov ecx, edx
         // 00420585: shr edi, b1 cl
         // 00420587: mov ecx, ss:[ebp+0x8]
      [-]d3e7ff45
         // 00420597: shl edi, b1 cl
         // 00420599: inc ss:[ebp+0x8]
      [-]8bf06a02c1e6028d4d
         // 004205a5: mov esi, eax
         // 004205a7: push 0x2
         // 004205a9: shl esi, b1 0x2
         // 004205ac: lea ecx, ss:[ebp+0xffffffffffffffe8]
      [-]3bd07c08
         // 004205b2: cmp edx, eax
         // 004205b4: jl 0x4205be
      [-]8b31897495
         // 004205b6: mov esi, ds:[ecx]
         // 004205b8: mov ss:[ebp+edx*0x4], esi
      [-]6a1f592b0d
         // 00426329: push 0x1f
         // 0042632b: pop ecx
         // 0042632c: sub ecx, ds:[0x433c9c]
      [-]d3e38b4d
         // 00426332: shl ebx, b1 cl
         // 00426334: mov ecx, ss:[ebp+0xffffffffffffffec]
      [-]f7d91bc981e1????????0bd98b0d
         // 00426337: neg ecx
         // 00426339: sbb ecx, ecx
         // 0042633b: and ecx, 0xffffffff80000000
         // 00426341: or ebx, ecx
         // 00426343: mov ecx, ds:[0x433ca0]
      [-]83f940750d
         // 0042634c: cmp ecx, 0x40
         // 0042634f: jnz 0x42635e
      [-]8959048911eb0a
         // 004205fc: mov ds:[ecx+0x4], ebx
         // 004205ff: mov ds:[ecx], edx
         // 00420601: jmp 0x42060d
      [-]83f9207505
         // 00420603: cmp ecx, 0x20
         // 00420606: jnz 0x42060d
      [-]5f5bc9c3
         // 0042060d: pop edi
         // 0042060e: pop ebx
         // 0042060f: leave 
         // 00420610: retn 
      [-]558bec83ec
         // 004196eb: push ebp
         // 004196ec: mov ebp, esp
         // 004196ee: sub esp, 0x2c
      [-]0fb7480a538bd981e1????????894d
         // 004196f4: movzx ecx, b2 ds:[eax+0xa]
         // 004196f8: push ebx
         // 004196f9: mov ebx, ecx
         // 004196fb: and ecx, 0x8000
         // 00419701: mov ss:[ebp+0xffffffffffffffec], ecx
      [-]8b4806894d
         // 00419704: mov ecx, ds:[eax+0x6]
         // 00419707: mov ss:[ebp+0xffffffffffffffe0], ecx
      [-]8b48020fb70081e3????????81eb????????c1e010
         // 0041970a: mov ecx, ds:[eax+0x2]
         // 0041970d: movzx eax, b2 ds:[eax]
         // 00419710: and ebx, 0x7fff
         // 00419716: sub ebx, 0x3fff
         // 0041971c: shl eax, b1 0x10
      [-]33db33c0
         // 00420654: xor ebx, ebx
         // 00420656: xor eax, eax
      [-]4083f8037cf4
         // 0042065e: inc eax
         // 0042065f: cmp eax, 0x3
         // 00420662: jl 0x420658
      [-]33c08d7d
         // 0042066b: xor eax, eax
         // 0042066d: lea edi, ss:[ebp+0xffffffffffffffe0]
      [-]abab6a02ab58e9
         // 00420670: stosdd 
         // 00420671: stosdd 
         // 00420672: push 0x2
         // 00420674: stosdd 
         // 00420675: pop eax
         // 00420676: jmp 0x420b10
      [-]00568d75
         // 004263dc: push esi
         // 004263dd: lea esi, ss:[ebp+0xffffffffffffffe0]
      [-]a5a5a58b
         // 004263e3: movsdd 
         // 004263e4: movsdd 
         // 004263e5: movsdd 
         // 004263e6: mov esi, ds:[0x433cb0]
      [-]9983e21f03c2c1f805
         // 004263f2: cdq 
         // 004263f3: and edx, 0x1f
         // 004263f6: add eax, edx
         // 004263f8: sar eax, b1 0x5
      [-]81e2????????895d
         // 004263fd: and edx, 0xffffffff8000001f
         // 00426403: mov ss:[ebp+0xfffffffffffffff0], ebx
      [-]4a83cae042
         // 004206ae: dec edx
         // 004206af: or edx, 0xffffffffffffffe0
         // 004206b2: inc edx
      [-]6a1f33c0592bca40d3e0894d
         // 004206b7: push 0x1f
         // 004206b9: xor eax, eax
         // 004206bb: pop ecx
         // 004206bc: sub ecx, edx
         // 004206be: inc eax
         // 004206bf: shl eax, b1 cl
         // 004206c1: mov ss:[ebp+0xfffffffffffffff8], ecx
      [-]0f848d000000
         // 004206c6: jz 0x420759
      [-]83caffd3e2f7d2855485
         // 004206cf: or edx, 0xffffffffffffffff
         // 004206d2: shl edx, b1 cl
         // 004206d4: not edx
         // 004206d6: test ss:[ebp+eax*0x4], edx
      [-]4083f8037cf3
         // 004206e3: inc eax
         // 004206e4: cmp eax, 0x3
         // 004206e7: jl 0x4206dc
      [-]996a1f5923d103c2c1f80581
         // 004206ed: cdq 
         // 004206ee: push 0x1f
         // 004206f0: pop ecx
         // 004206f1: and edx, ecx
         // 004206f3: add eax, edx
         // 004206f5: sar eax, b1 0x5
         // 004206f8: and esi, 0xffffffff8000001f
      [-]33d242d3e28d4c85
         // 0042070b: xor edx, edx
         // 0042070d: inc edx
         // 0042070e: shl edx, b1 cl
         // 00420710: lea ecx, ss:[ebp+eax*0x4]
      [-]85c9742b
         // 00420727: test ecx, ecx
         // 00420729: jz 0x420756
      [-]008d4c85
         // 00419ce1: lea ecx, ss:[ebp+eax*0x4]
      [-]89118b4d
         // 0042074f: mov ds:[ecx], edx
         // 00420751: mov ecx, ss:[ebp+0xfffffffffffffffc]
      [-]83c8ffd3e021
         // 0042075c: or eax, 0xffffffffffffffff
         // 0042075f: shl eax, b1 cl
         // 00420761: and ds:[edi], eax
      [-]2bc833c0f3ab
         // 002b8549: sub ecx, eax
         // 002b854b: xor eax, eax
         // 002b854d: rep stosdd 
      [-]8bc82b0d
         // 0041985f: mov ecx, eax
         // 00419861: sub ecx, ds:[0x423710]
      [-]3bd97d0d
         // 00419867: cmp ebx, ecx
         // 00419869: jge 0x419878
      [-]33c08d7d
         // 00420791: xor eax, eax
         // 00420793: lea edi, ss:[ebp+0xffffffffffffffe0]
      [-]abababe9
         // 00420796: stosdd 
         // 00420797: stosdd 
         // 00420798: stosdd 
         // 00420799: jmp 0x4209ab
      [-]3bd80f8f
         // 0042079e: cmp ebx, eax
         // 004207a0: jg 0x4209b5
      [-]8bc88d7d
         // 004207ac: mov ecx, eax
         // 004207ae: lea edi, ss:[ebp+0xffffffffffffffe0]
      [-]a59983e21f03c2a58bd1c1f80581e2????????a57905
         // 004207b1: movsdd 
         // 004207b2: cdq 
         // 004207b3: and edx, 0x1f
         // 004207b6: add eax, edx
         // 004207b8: movsdd 
         // 004207b9: mov edx, ecx
         // 004207bb: sar eax, b1 0x5
         // 004207be: and edx, 0xffffffff8000001f
         // 004207c4: movsdd 
         // 004207c5: jns 0x4207cc
      [-]4a83cae042
         // 004207c7: dec edx
         // 004207c8: or edx, 0xffffffffffffffe0
         // 004207cb: inc edx
      [-]0083cfff8bcad3e7c745
         // 004207d4: or edi, 0xffffffffffffffff
         // 004207d7: mov ecx, edx
         // 004207d9: shl edi, b1 cl
         // 004207db: mov ss:[ebp+0xfffffffffffffffc], 0x20
      [-]8b338bce23cf894d
         // 004207ee: mov esi, ds:[ebx]
         // 004207f0: mov ecx, esi
         // 004207f2: and ecx, edi
         // 004207f4: mov ss:[ebp+0xfffffffffffffff0], ecx
      [-]8bcad3ee8b4d
         // 004207f7: mov ecx, edx
         // 004207f9: shr esi, b1 cl
         // 004207fb: mov ecx, ss:[ebp+0xfffffffffffffffc]
      [-]89338b75
         // 00420801: mov ds:[ebx], esi
         // 00420803: mov esi, ss:[ebp+0xfffffffffffffff0]
      [-]d3e6ff45
         // 00420806: shl esi, b1 cl
         // 00420808: inc ss:[ebp+0x8]
      [-]8bf06a02c1e6028d4d
         // 00420814: mov esi, eax
         // 00420816: push 0x2
         // 00420818: shl esi, b1 0x2
         // 0042081b: lea ecx, ss:[ebp+0xffffffffffffffe8]
      [-]3bd07c08
         // 00420821: cmp edx, eax
         // 00420823: jl 0x42082d
      [-]8b31897495
         // 00420825: mov esi, ds:[ecx]
         // 00420827: mov ss:[ebp+edx*0x4], esi
      [-]9983e21f03c2c1f805
         // 004265a3: cdq 
         // 004265a4: and edx, 0x1f
         // 004265a7: add eax, edx
         // 004265a9: sar eax, b1 0x5
      [-]81e2????????8945
         // 004265ae: and edx, 0xffffffff8000001f
         // 004265b4: mov ss:[ebp+0xfffffffffffffff4], eax
      [-]4a83cae042
         // 0042085c: dec edx
         // 0042085d: or edx, 0xffffffffffffffe0
         // 00420860: inc edx
      [-]6a1f592bca33d242d3e28d5c85
         // 00420861: push 0x1f
         // 00420863: pop ecx
         // 00420864: sub ecx, edx
         // 00420866: xor edx, edx
         // 00420868: inc edx
         // 00420869: shl edx, b1 cl
         // 0042086b: lea ebx, ss:[ebp+eax*0x4]
      [-]85130f8482000000
         // 00420872: test ds:[ebx], edx
         // 00420874: jz 0x4208fc
      [-]83caffd3e2f7d2855485
         // 0042087a: or edx, 0xffffffffffffffff
         // 0042087d: shl edx, b1 cl
         // 0042087f: not edx
         // 00420881: test ss:[ebp+eax*0x4], edx
      [-]4083f8037cf3
         // 0042088e: inc eax
         // 0042088f: cmp eax, 0x3
         // 00420892: jl 0x420887
      [-]8bc6996a1f5923d103c2c1f80581e6????????7905
         // 00420896: mov eax, esi
         // 00420898: cdq 
         // 00420899: push 0x1f
         // 0042089b: pop ecx
         // 0042089c: and edx, ecx
         // 0042089e: add eax, edx
         // 004208a0: sar eax, b1 0x5
         // 004208a3: and esi, 0xffffffff8000001f
         // 004208a9: jns 0x4208b0
      [-]4e83cee046
         // 004208ab: dec esi
         // 004208ac: or esi, 0xffffffffffffffe0
         // 004208af: inc esi
      [-]0033d22bce42d3e28d4c85
         // 004208b4: xor edx, edx
         // 004208b6: sub ecx, esi
         // 004208b8: inc edx
         // 004208b9: shl edx, b1 cl
         // 004208bb: lea ecx, ss:[ebp+eax*0x4]
      [-]8b318d3c163bfe7204
         // 004208bf: mov esi, ds:[ecx]
         // 004208c1: lea edi, ds:[esi+edx]
         // 004208c4: cmp edi, esi
         // 004208c6: jb 0x4208cc
      [-]3bfa7307
         // 004208c8: cmp edi, edx
         // 004208ca: jnb 0x4208d3
      [-]89398b4d
         // 004208d3: mov ds:[ecx], edi
         // 004208d5: mov ecx, ss:[ebp+0x8]
      [-]85c9741e
         // 004208da: test ecx, ecx
         // 004208dc: jz 0x4208fc
      [-]8b118d720133ff3bf27205
         // 004208e2: mov edx, ds:[ecx]
         // 004208e4: lea esi, ds:[edx+0x1]
         // 004208e7: xor edi, edi
         // 004208e9: cmp esi, edx
         // 004208eb: jb 0x4208f2
      [-]83fe017303
         // 004208ed: cmp esi, 0x1
         // 004208f0: jnb 0x4208f5
      [-]89318bcf
         // 004208f5: mov ds:[ecx], esi
         // 004208f7: mov ecx, edi
      [-]83c8ffd3e021038b45
         // 004208ff: or eax, 0xffffffffffffffff
         // 00420902: shl eax, b1 cl
         // 00420904: and ds:[ebx], eax
         // 00420906: mov eax, ss:[ebp+0xfffffffffffffff4]
      [-]4083f8037d0d
         // 00420909: inc eax
         // 0042090a: cmp eax, 0x3
         // 0042090d: jge 0x42091c
      [-]6a03598d7c85
         // 0042090f: push 0x3
         // 00420911: pop ecx
         // 00420912: lea edi, ss:[ebp+eax*0x4]
      [-]2bc833c0f3ab
         // 00420916: sub ecx, eax
         // 00420918: xor eax, eax
         // 0042091a: rep stosdd 
      [-]9983e21f03c2
         // 00426682: cdq 
         // 00426683: and edx, 0x1f
         // 00426686: add eax, edx
      [-]c1f80581e2????????7905
         // 0042668a: sar eax, b1 0x5
         // 0042668d: and edx, 0xffffffff8000001f
         // 00426693: jns 0x42669a
      [-]4a83cae042
         // 00420938: dec edx
         // 00420939: or edx, 0xffffffffffffffe0
         // 0042093c: inc edx
      [-]0083cfff8bcad3e7c745
         // 00420945: or edi, 0xffffffffffffffff
         // 00420948: mov ecx, edx
         // 0042094a: shl edi, b1 cl
         // 0042094c: mov ss:[ebp+0xfffffffffffffffc], 0x20
      [-]8b338bce23cf894d
         // 0042095f: mov esi, ds:[ebx]
         // 00420961: mov ecx, esi
         // 00420963: and ecx, edi
         // 00420965: mov ss:[ebp+0xfffffffffffffff0], ecx
      [-]8bcad3ee8b4d
         // 00420968: mov ecx, edx
         // 0042096a: shr esi, b1 cl
         // 0042096c: mov ecx, ss:[ebp+0xfffffffffffffffc]
      [-]89338b75
         // 00420972: mov ds:[ebx], esi
         // 00420974: mov esi, ss:[ebp+0xfffffffffffffff0]
      [-]d3e6ff45
         // 00420977: shl esi, b1 cl
         // 00420979: inc ss:[ebp+0x8]
      [-]8bf06a02c1e6028d4d
         // 00420985: mov esi, eax
         // 00420987: push 0x2
         // 00420989: shl esi, b1 0x2
         // 0042098c: lea ecx, ss:[ebp+0xffffffffffffffe8]
      [-]3bd07c08
         // 00420992: cmp edx, eax
         // 00420994: jl 0x42099e
      [-]8b31897495
         // 00420996: mov esi, ds:[ecx]
         // 00420998: mov ss:[ebp+edx*0x4], esi
      [-]6a0233db58e9
         // 004209ab: push 0x2
         // 004209ad: xor ebx, ebx
         // 004209af: pop eax
         // 004209b0: jmp 0x420b0f
      [-]33c08d7d
         // 004209c7: xor eax, eax
         // 004209c9: lea edi, ss:[ebp+0xffffffffffffffe0]
      [-]ababab814d
         // 004209cc: stosdd 
         // 004209cd: stosdd 
         // 004209ce: stosdd 
         // 004209cf: or ss:[ebp+0xffffffffffffffe0], 0xffffffff80000000
      [-]8bc19983e21f03c28bd1c1f80581e2????????7905
         // 004209d6: mov eax, ecx
         // 004209d8: cdq 
         // 004209d9: and edx, 0x1f
         // 004209dc: add eax, edx
         // 004209de: mov edx, ecx
         // 004209e0: sar eax, b1 0x5
         // 004209e3: and edx, 0xffffffff8000001f
         // 004209e9: jns 0x4209f0
      [-]4a83cae042
         // 004209eb: dec edx
         // 004209ec: or edx, 0xffffffffffffffe0
         // 004209ef: inc edx
      [-]0083cfff8bcad3e7c745
         // 004209f8: or edi, 0xffffffffffffffff
         // 004209fb: mov ecx, edx
         // 004209fd: shl edi, b1 cl
         // 004209ff: mov ss:[ebp+0xfffffffffffffffc], 0x20
      [-]8b338bce23cf894d
         // 00420a12: mov esi, ds:[ebx]
         // 00420a14: mov ecx, esi
         // 00420a16: and ecx, edi
         // 00420a18: mov ss:[ebp+0xfffffffffffffff0], ecx
      [-]8bcad3ee8b4d
         // 00420a1b: mov ecx, edx
         // 00420a1d: shr esi, b1 cl
         // 00420a1f: mov ecx, ss:[ebp+0xfffffffffffffffc]
      [-]89338b75
         // 00420a25: mov ds:[ebx], esi
         // 00420a27: mov esi, ss:[ebp+0xfffffffffffffff0]
      [-]d3e6ff45
         // 00420a2a: shl esi, b1 cl
         // 00420a2c: inc ss:[ebp+0x8]
      [-]8bf06a02c1e6028d4d
         // 00420a38: mov esi, eax
         // 00420a3a: push 0x2
         // 00420a3c: shl esi, b1 0x2
         // 00420a3f: lea ecx, ss:[ebp+0xffffffffffffffe8]
      [-]3bd07c08
         // 00420a45: cmp edx, eax
         // 00420a47: jl 0x420a51
      [-]8b31897495
         // 00420a49: mov esi, ds:[ecx]
         // 00420a4b: mov ss:[ebp+edx*0x4], esi
      [-]33c040e9
         // 004267c9: xor eax, eax
         // 004267cb: inc eax
         // 004267cc: jmp 0x42686c
      [-]8bc19983e21f03c28bd1c1f80581e2????????7905
         // 00419b5c: mov eax, ecx
         // 00419b5e: cdq 
         // 00419b5f: and edx, 0x1f
         // 00419b62: add eax, edx
         // 00419b64: mov edx, ecx
         // 00419b66: sar eax, b1 0x5
         // 00419b69: and edx, 0xffffffff8000001f
         // 00419b6f: jns 0x419b76
      [-]4a83cae042
         // 00420a97: dec edx
         // 00420a98: or edx, 0xffffffffffffffe0
         // 00420a9b: inc edx
      [-]0083ceff8bcad3e6c745
         // 00420aa4: or esi, 0xffffffffffffffff
         // 00420aa7: mov ecx, edx
         // 00420aa9: shl esi, b1 cl
         // 00420aab: mov ss:[ebp+0xfffffffffffffffc], 0x20
      [-]8bcf23ce894d
         // 00420abe: mov ecx, edi
         // 00420ac0: and ecx, esi
         // 00420ac2: mov ss:[ebp+0xfffffffffffffff0], ecx
      [-]8bcad3ef8b4d
         // 00420ac5: mov ecx, edx
         // 00420ac7: shr edi, b1 cl
         // 00420ac9: mov ecx, ss:[ebp+0x8]
      [-]d3e7ff45
         // 00420ad9: shl edi, b1 cl
         // 00420adb: inc ss:[ebp+0x8]
      [-]8bf06a02c1e6028d4d
         // 00420ae7: mov esi, eax
         // 00420ae9: push 0x2
         // 00420aeb: shl esi, b1 0x2
         // 00420aee: lea ecx, ss:[ebp+0xffffffffffffffe8]
      [-]3bd07c08
         // 00420af4: cmp edx, eax
         // 00420af6: jl 0x420b00
      [-]8b31897495
         // 00420af8: mov esi, ds:[ecx]
         // 00420afa: mov ss:[ebp+edx*0x4], esi
      [-]6a1f592b0d
         // 00420b10: push 0x1f
         // 00420b12: pop ecx
         // 00420b13: sub ecx, ds:[0x42c714]
      [-]d3e38b4d
         // 00420b19: shl ebx, b1 cl
         // 00420b1b: mov ecx, ss:[ebp+0xffffffffffffffec]
      [-]f7d91bc981e1????????0bd98b0d
         // 00420b1e: neg ecx
         // 00420b20: sbb ecx, ecx
         // 00420b22: and ecx, 0xffffffff80000000
         // 00420b28: or ebx, ecx
         // 00420b2a: mov ecx, ds:[0x42c718]
      [-]83f940750d
         // 00420b33: cmp ecx, 0x40
         // 00420b36: jnz 0x420b45
      [-]8959048911eb0a
         // 00420b3e: mov ds:[ecx+0x4], ebx
         // 00420b41: mov ds:[ecx], edx
         // 00420b43: jmp 0x420b4f
      [-]83f9207505
         // 00420b45: cmp ecx, 0x20
         // 00420b48: jnz 0x420b4f
      [-]5f5bc9c3
         // 00420b4f: pop edi
         // 00420b50: pop ebx
         // 00420b51: leave 
         // 00420b52: retn 

  }
  condition:
    all of them
}
