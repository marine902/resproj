rule urelas_10_0 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         568bf1c706
         // 002acdf7: push esi
         // 002acdf8: mov esi, ecx
         // 002acdfa: mov ds:[esi], ??_7exception@std@@6B@
      [-]08017407
         // 002ace09: jz 0x2ace12
      [-]088bf1e8
         // 0041904a: mov esi, ecx
         // 0041904c: call ??0exception@std@@QAE@ABV01@@Z
      [-]558bec83ec28a1
         // 00424f64: push ebp
         // 00424f65: mov ebp, esp
         // 00424f67: sub esp, 0x28
         // 00424f6a: mov eax, ds:[0x433c20]
      [-]33c58945fc53568b750857ff75108b7d0c8d4ddce8
         // 00424f6f: xor eax, ebp
         // 00424f71: mov ss:[ebp+0xfffffffffffffffc], eax
         // 00424f74: push ebx
         // 00424f75: push esi
         // 00424f76: mov esi, ss:[ebp+0x8]
         // 00424f79: push edi
         // 00424f7a: push ss:[ebp+0x10]
         // 00424f7d: mov edi, ss:[ebp+0xc]
         // 00424f80: lea ecx, ss:[ebp+0xffffffffffffffdc]
         // 00424f83: call ??0_LocaleUpdate@@QAE@PAUlocaleinfo_struct@@@Z
      [-]8d45dc5033db53535353578d45d8508d45f050e8
         // 00424f88: lea eax, ss:[ebp+0xffffffffffffffdc]
         // 00424f8b: push eax
         // 00424f8c: xor ebx, ebx
         // 00424f8e: push ebx
         // 00424f8f: push ebx
         // 00424f90: push ebx
         // 00424f91: push ebx
         // 00424f92: push edi
         // 00424f93: lea eax, ss:[ebp+0xffffffffffffffd8]
         // 00424f96: push eax
         // 00424f97: lea eax, ss:[ebp+0xfffffffffffffff0]
         // 00424f9a: push eax
         // 00424f9b: call ___strgtold12_l
      [-]00008945ec8d45f05650e8
         // 00424fa0: mov ss:[ebp+0xffffffffffffffec], eax
         // 00424fa3: lea eax, ss:[ebp+0xfffffffffffffff0]
         // 00424fa6: push esi
         // 00424fa7: push eax
         // 00424fa8: call 0x425cf4
      [-]000083c428f645ec03752b
         // 00424fad: add esp, 0x28
         // 00424fb0: test b1 ss:[ebp+0xffffffffffffffec], b1 0x3
         // 00424fb4: jnz 0x424fe1
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
         // 00418d92: push ebp
         // 00418d93: mov ebp, esp
         // 00418d95: sub esp, 0x28
         // 00418d98: mov eax, ds:[0x422044]
      [-]33c58945fc53568b750857ff75108b7d0c8d4ddce8
         // 00418d9d: xor eax, ebp
         // 00418d9f: mov ss:[ebp+0xfffffffffffffffc], eax
         // 00418da2: push ebx
         // 00418da3: push esi
         // 00418da4: mov esi, ss:[ebp+0x8]
         // 00418da7: push edi
         // 00418da8: push ss:[ebp+0x10]
         // 00418dab: mov edi, ss:[ebp+0xc]
         // 00418dae: lea ecx, ss:[ebp+0xffffffffffffffdc]
         // 00418db1: call ??0_LocaleUpdate@@QAE@PAUlocaleinfo_struct@@@Z
      [-]8d45dc5033db53535353578d45d8508d45f050e8
         // 00418db6: lea eax, ss:[ebp+0xffffffffffffffdc]
         // 00418db9: push eax
         // 00418dba: xor ebx, ebx
         // 00418dbc: push ebx
         // 00418dbd: push ebx
         // 00418dbe: push ebx
         // 00418dbf: push ebx
         // 00418dc0: push edi
         // 00418dc1: lea eax, ss:[ebp+0xffffffffffffffd8]
         // 00418dc4: push eax
         // 00418dc5: lea eax, ss:[ebp+0xfffffffffffffff0]
         // 00418dc8: push eax
         // 00418dc9: call ___strgtold12_l
      [-]00008945ec8d45f05650e8
         // 00418dce: mov ss:[ebp+0xffffffffffffffec], eax
         // 00418dd1: lea eax, ss:[ebp+0xfffffffffffffff0]
         // 00418dd4: push esi
         // 00418dd5: push eax
         // 00418dd6: call 0x4196eb
      [-]000083c428f645ec03752b
         // 00418ddb: add esp, 0x28
         // 00418dde: test b1 ss:[ebp+0xffffffffffffffec], b1 0x3
         // 00418de2: jnz 0x418e0f
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
         // 00419217: push esi
         // 00419218: lea esi, ss:[ebp+0xffffffffffffffe0]
      [-]a5a5a58b
         // 0041921e: movsdd 
         // 0041921f: movsdd 
         // 00419220: movsdd 
         // 00419221: mov esi, ds:[0x4236f8]
      [-]9983e21f03c2c1f805
         // 0041922d: cdq 
         // 0041922e: and edx, 0x1f
         // 00419231: add eax, edx
         // 00419233: sar eax, b1 0x5
      [-]81e2????????895d
         // 00419238: and edx, 0xffffffff8000001f
         // 0041923e: mov ss:[ebp+0xfffffffffffffff0], ebx
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
         // 004201ed: lea ecx, ss:[ebp+eax*0x4]
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
         // 004194bd: cdq 
         // 004194be: and edx, 0x1f
         // 004194c1: add eax, edx
      [-]c1f80581e2????????7905
         // 004194c5: sar eax, b1 0x5
         // 004194c8: and edx, 0xffffffff8000001f
         // 004194ce: jns 0x4194d5
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
         // 0042052a: xor eax, eax
         // 0042052c: inc eax
         // 0042052d: jmp 0x4205cd
      [-]8bc19983e21f03c28bd1c1f80581e2????????7905
         // 00420540: mov eax, ecx
         // 00420542: cdq 
         // 00420543: and edx, 0x1f
         // 00420546: add eax, edx
         // 00420548: mov edx, ecx
         // 0042054a: sar eax, b1 0x5
         // 0042054d: and edx, 0xffffffff8000001f
         // 00420553: jns 0x42055a
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
         // 004196a8: push 0x1f
         // 004196aa: pop ecx
         // 004196ab: sub ecx, ds:[0x4236fc]
      [-]d3e38b4d
         // 004196b1: shl ebx, b1 cl
         // 004196b3: mov ecx, ss:[ebp+0xffffffffffffffec]
      [-]f7d91bc981e1????????0bd98b0d
         // 004196b6: neg ecx
         // 004196b8: sbb ecx, ecx
         // 004196ba: and ecx, 0xffffffff80000000
         // 004196c0: or ebx, ecx
         // 004196c2: mov ecx, ds:[0x423700]
      [-]83f940750d
         // 004196cb: cmp ecx, 0x40
         // 004196ce: jnz 0x4196dd
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
         // 00419759: push esi
         // 0041975a: lea esi, ss:[ebp+0xffffffffffffffe0]
      [-]a5a5a58b
         // 00419760: movsdd 
         // 00419761: movsdd 
         // 00419762: movsdd 
         // 00419763: mov esi, ds:[0x423710]
      [-]9983e21f03c2c1f805
         // 0041976f: cdq 
         // 00419770: and edx, 0x1f
         // 00419773: add eax, edx
         // 00419775: sar eax, b1 0x5
      [-]81e2????????895d
         // 0041977a: and edx, 0xffffffff8000001f
         // 00419780: mov ss:[ebp+0xfffffffffffffff0], ebx
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
         // 0042072f: lea ecx, ss:[ebp+eax*0x4]
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
         // 004199ff: cdq 
         // 00419a00: and edx, 0x1f
         // 00419a03: add eax, edx
      [-]c1f80581e2????????7905
         // 00419a07: sar eax, b1 0x5
         // 00419a0a: and edx, 0xffffffff8000001f
         // 00419a10: jns 0x419a17
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
         // 00420a6c: xor eax, eax
         // 00420a6e: inc eax
         // 00420a6f: jmp 0x420b0f
      [-]8bc19983e21f03c28bd1c1f80581e2????????7905
         // 00420a82: mov eax, ecx
         // 00420a84: cdq 
         // 00420a85: and edx, 0x1f
         // 00420a88: add eax, edx
         // 00420a8a: mov edx, ecx
         // 00420a8c: sar eax, b1 0x5
         // 00420a8f: and edx, 0xffffffff8000001f
         // 00420a95: jns 0x420a9c
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
         // 00419bea: push 0x1f
         // 00419bec: pop ecx
         // 00419bed: sub ecx, ds:[0x423714]
      [-]d3e38b4d
         // 00419bf3: shl ebx, b1 cl
         // 00419bf5: mov ecx, ss:[ebp+0xffffffffffffffec]
      [-]f7d91bc981e1????????0bd98b0d
         // 00419bf8: neg ecx
         // 00419bfa: sbb ecx, ecx
         // 00419bfc: and ecx, 0xffffffff80000000
         // 00419c02: or ebx, ecx
         // 00419c04: mov ecx, ds:[0x423718]
      [-]83f940750d
         // 00419c0d: cmp ecx, 0x40
         // 00419c10: jnz 0x419c1f
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
