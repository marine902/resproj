rule urelas_10_2 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         85c07402
         // 0040b983: test eax, eax
         // 0040b985: jz 0x40b989
      [-]85c07402
         // 0040b9a7: test eax, eax
         // 0040b9a9: jz 0x40b9ad
      [-]ffff59c3
         // 00414f3d: pop ecx
         // 00414f3e: retn 
      [-]558bec83ec
         // 00414779: push ebp
         // 0041477a: mov ebp, esp
         // 0041477c: sub esp, 0x20
      [-]535657e8
         // 0041477f: push ebx
         // 00414780: push esi
         // 00414781: push edi
         // 00414782: call __encoded_null
      [-]ffffc70424
         // 0040ce81: mov ss:[esp], 0x423b6c
      [-]ffd650e8
         // 0040ce8e: call esi
         // 0040ce90: push eax
         // 0040ce91: call __encode_pointer
      [-]ffffc70424
         // 0040ce96: mov ss:[esp], 0x423b58
      [-]ffd650e8
         // 0040cea3: call esi
         // 0040cea5: push eax
         // 0040cea6: call __encode_pointer
      [-]57ffd650e8
         // 0040ceef: push edi
         // 0040cef0: call esi
         // 0040cef2: push eax
         // 0040cef3: call __encode_pointer
      [-]ffff59a3
         // 0040cef8: pop ecx
         // 0040cef9: mov ds:[0x42d4b4], eax
      [-]5f5e5bc9c3
         // 0040cfc2: pop edi
         // 0040cfc3: pop esi
         // 0040cfc4: pop ebx
         // 0040cfc5: leave 
         // 0040cfc6: retn 
      [-]558bec83ec28a1
         // 0041f81e: push ebp
         // 0041f81f: mov ebp, esp
         // 0041f821: sub esp, 0x28
         // 0041f824: mov eax, ds:[0x42a044]
      [-]33c58945fc53568b750857ff75108b7d0c8d4ddce8
         // 0041f829: xor eax, ebp
         // 0041f82b: mov ss:[ebp+0xfffffffffffffffc], eax
         // 0041f82e: push ebx
         // 0041f82f: push esi
         // 0041f830: mov esi, ss:[ebp+0x8]
         // 0041f833: push edi
         // 0041f834: push ss:[ebp+0x10]
         // 0041f837: mov edi, ss:[ebp+0xc]
         // 0041f83a: lea ecx, ss:[ebp+0xffffffffffffffdc]
         // 0041f83d: call ??0_LocaleUpdate@@QAE@PAUlocaleinfo_struct@@@Z
      [-]8d45dc5033db53535353578d45d8508d45f050e8
         // 0041f842: lea eax, ss:[ebp+0xffffffffffffffdc]
         // 0041f845: push eax
         // 0041f846: xor ebx, ebx
         // 0041f848: push ebx
         // 0041f849: push ebx
         // 0041f84a: push ebx
         // 0041f84b: push ebx
         // 0041f84c: push edi
         // 0041f84d: lea eax, ss:[ebp+0xffffffffffffffd8]
         // 0041f850: push eax
         // 0041f851: lea eax, ss:[ebp+0xfffffffffffffff0]
         // 0041f854: push eax
         // 0041f855: call ___strgtold12_l
      [-]00008945ec8d45f05650e8
         // 0041f85a: mov ss:[ebp+0xffffffffffffffec], eax
         // 0041f85d: lea eax, ss:[ebp+0xfffffffffffffff0]
         // 0041f860: push esi
         // 0041f861: push eax
         // 0041f862: call 0x41fd33
      [-]000083c428f645ec03752b
         // 0041f867: add esp, 0x28
         // 0041f86a: test b1 ss:[ebp+0xffffffffffffffec], b1 0x3
         // 0041f86e: jnz 0x41f89b
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
         // 0041cb27: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 0041cb2a: pop edi
         // 0041cb2b: pop esi
         // 0041cb2c: xor ecx, ebp
         // 0041cb2e: pop ebx
         // 0041cb2f: call @__security_check_cookie@4
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
         // 0041cbcf: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 0041cbd2: pop edi
         // 0041cbd3: pop esi
         // 0041cbd4: xor ecx, ebp
         // 0041cbd6: pop ebx
         // 0041cbd7: call @__security_check_cookie@4
      [-]558bec83ec2c8b45080fb7480a538bd981e1????????894dec8b4806894de08b48020fb70081e3????????81eb????????c1e01057894de48945e8
         // 004203d8: push ebp
         // 004203d9: mov ebp, esp
         // 004203db: sub esp, 0x2c
         // 004203de: mov eax, ss:[ebp+0x8]
         // 004203e1: movzx ecx, b2 ds:[eax+0xa]
         // 004203e5: push ebx
         // 004203e6: mov ebx, ecx
         // 004203e8: and ecx, 0x8000
         // 004203ee: mov ss:[ebp+0xffffffffffffffec], ecx
         // 004203f1: mov ecx, ds:[eax+0x6]
         // 004203f4: mov ss:[ebp+0xffffffffffffffe0], ecx
         // 004203f7: mov ecx, ds:[eax+0x2]
         // 004203fa: movzx eax, b2 ds:[eax]
         // 004203fd: and ebx, 0x7fff
         // 00420403: sub ebx, 0x3fff
         // 00420409: shl eax, b1 0x10
         // 0042040c: push edi
         // 0042040d: mov ss:[ebp+0xffffffffffffffe4], ecx
         // 00420410: mov ss:[ebp+0xffffffffffffffe8], eax
      [-]33db33c0
         // 00420112: xor ebx, ebx
         // 00420114: xor eax, eax
      [-]395c85e0750d
         // 00420116: cmp ss:[ebp+eax*0x4], ebx
         // 0042011a: jnz 0x420129
      [-]4083f8037cf4
         // 0042011c: inc eax
         // 0042011d: cmp eax, 0x3
         // 00420120: jl 0x420116
      [-]33c0e9a5040000
         // 00420122: xor eax, eax
         // 00420124: jmp 0x4205ce
      [-]33c08d7de0abab6a02ab58e995040000
         // 00420129: xor eax, eax
         // 0042012b: lea edi, ss:[ebp+0xffffffffffffffe0]
         // 0042012e: stosdd 
         // 0042012f: stosdd 
         // 00420130: push 0x2
         // 00420132: stosdd 
         // 00420133: pop eax
         // 00420134: jmp 0x4205ce
      [-]83650800568d75e08d7dd4a5a5a58b35
         // 00419b4f: and ss:[ebp+0x8], 0x0
         // 00419b53: push esi
         // 00419b54: lea esi, ss:[ebp+0xffffffffffffffe0]
         // 00419b57: lea edi, ss:[ebp+0xffffffffffffffd4]
         // 00419b5a: movsdd 
         // 00419b5b: movsdd 
         // 00419b5c: movsdd 
         // 00419b5d: mov esi, ds:[0x4236b8]
      [-]4e8d4e018bc19983e21f03c2c1f8058bd181e2????????895df08945f47905
         // 00419b63: dec esi
         // 00419b64: lea ecx, ds:[esi+0x1]
         // 00419b67: mov eax, ecx
         // 00419b69: cdq 
         // 00419b6a: and edx, 0x1f
         // 00419b6d: add eax, edx
         // 00419b6f: sar eax, b1 0x5
         // 00419b72: mov edx, ecx
         // 00419b74: and edx, 0xffffffff8000001f
         // 00419b7a: mov ss:[ebp+0xfffffffffffffff0], ebx
         // 00419b7d: mov ss:[ebp+0xfffffffffffffff4], eax
         // 00419b80: jns 0x419b87
      [-]4a83cae042
         // 0042016c: dec edx
         // 0042016d: or edx, 0xffffffffffffffe0
         // 00420170: inc edx
      [-]8d7c85e06a1f33c0592bca40d3e0894df885070f848d000000
         // 00420171: lea edi, ss:[ebp+eax*0x4]
         // 00420175: push 0x1f
         // 00420177: xor eax, eax
         // 00420179: pop ecx
         // 0042017a: sub ecx, edx
         // 0042017c: inc eax
         // 0042017d: shl eax, b1 cl
         // 0042017f: mov ss:[ebp+0xfffffffffffffff8], ecx
         // 00420182: test ds:[edi], eax
         // 00420184: jz 0x420217
      [-]8b45f483caffd3e2f7d2855485e0eb05
         // 0042018a: mov eax, ss:[ebp+0xfffffffffffffff4]
         // 0042018d: or edx, 0xffffffffffffffff
         // 00420190: shl edx, b1 cl
         // 00420192: not edx
         // 00420194: test ss:[ebp+eax*0x4], edx
         // 00420198: jmp 0x42019f
      [-]837c85e000
         // 0042019a: cmp ss:[ebp+eax*0x4], 0x0
      [-]4083f8037cf3
         // 004201a1: inc eax
         // 004201a2: cmp eax, 0x3
         // 004201a5: jl 0x42019a
      [-]8bc6996a1f5923d103c2c1f80581e6????????7905
         // 004201a9: mov eax, esi
         // 004201ab: cdq 
         // 004201ac: push 0x1f
         // 004201ae: pop ecx
         // 004201af: and edx, ecx
         // 004201b1: add eax, edx
         // 004201b3: sar eax, b1 0x5
         // 004201b6: and esi, 0xffffffff8000001f
         // 004201bc: jns 0x4201c3
      [-]4e83cee046
         // 004201be: dec esi
         // 004201bf: or esi, 0xffffffffffffffe0
         // 004201c2: inc esi
      [-]8365fc002bce33d242d3e28d4c85e08b3103f28975088b313975087222
         // 004201c3: and ss:[ebp+0xfffffffffffffffc], 0x0
         // 004201c7: sub ecx, esi
         // 004201c9: xor edx, edx
         // 004201cb: inc edx
         // 004201cc: shl edx, b1 cl
         // 004201ce: lea ecx, ss:[ebp+eax*0x4]
         // 004201d2: mov esi, ds:[ecx]
         // 004201d4: add esi, edx
         // 004201d6: mov ss:[ebp+0x8], esi
         // 004201d9: mov esi, ds:[ecx]
         // 004201db: cmp ss:[ebp+0x8], esi
         // 004201de: jb 0x420202
      [-]395508eb1b
         // 004201e0: cmp ss:[ebp+0x8], edx
         // 004201e3: jmp 0x420200
      [-]85c9742b
         // 004201e5: test ecx, ecx
         // 004201e7: jz 0x420214
      [-]8365fc008d4c85e08b118d7201
         // 004204f2: and ss:[ebp+0xfffffffffffffffc], 0x0
         // 004204f6: lea ecx, ss:[ebp+eax*0x4]
         // 004204fa: mov edx, ds:[ecx]
         // 004204fc: lea esi, ds:[edx+0x1]
      [-]c745fc????????
         // 00420202: mov ss:[ebp+0xfffffffffffffffc], 0x1
      [-]488b550889118b4dfc79d1
         // 00420209: dec eax
         // 0042020a: mov edx, ss:[ebp+0x8]
         // 0042020d: mov ds:[ecx], edx
         // 0042020f: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 00420212: jns 0x4201e5
      [-]8b4df883c8ffd3e021078b45f44083f8037d0d
         // 00420217: mov ecx, ss:[ebp+0xfffffffffffffff8]
         // 0042021a: or eax, 0xffffffffffffffff
         // 0042021d: shl eax, b1 cl
         // 0042021f: and ds:[edi], eax
         // 00420221: mov eax, ss:[ebp+0xfffffffffffffff4]
         // 00420224: inc eax
         // 00420225: cmp eax, 0x3
         // 00420228: jge 0x420237
      [-]6a03598d7c85e02bc833c0f3ab
         // 0042022a: push 0x3
         // 0042022c: pop ecx
         // 0042022d: lea edi, ss:[ebp+eax*0x4]
         // 00420231: sub ecx, eax
         // 00420233: xor eax, eax
         // 00420235: rep stosdd 
      [-]837d08007401
         // 00420237: cmp ss:[ebp+0x8], 0x0
         // 0042023b: jz 0x42023e
      [-]8bc82b0d
         // 00419c59: mov ecx, eax
         // 00419c5b: sub ecx, ds:[0x4236b8]
      [-]3bd97d0d
         // 00419c61: cmp ebx, ecx
         // 00419c63: jge 0x419c72
      [-]33c08d7de0abababe90d020000
         // 0042024f: xor eax, eax
         // 00420251: lea edi, ss:[ebp+0xffffffffffffffe0]
         // 00420254: stosdd 
         // 00420255: stosdd 
         // 00420256: stosdd 
         // 00420257: jmp 0x420469
      [-]3bd80f8f0f020000
         // 0042025c: cmp ebx, eax
         // 0042025e: jg 0x420473
      [-]2b45f08d75d48bc88d7de0a59983e21f03c2a58bd1c1f80581e2????????a57905
         // 00420264: sub eax, ss:[ebp+0xfffffffffffffff0]
         // 00420267: lea esi, ss:[ebp+0xffffffffffffffd4]
         // 0042026a: mov ecx, eax
         // 0042026c: lea edi, ss:[ebp+0xffffffffffffffe0]
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
      [-]8365f4008365080083cfff8bcad3e7c745fc????????2955fcf7d7
         // 0042028a: and ss:[ebp+0xfffffffffffffff4], 0x0
         // 0042028e: and ss:[ebp+0x8], 0x0
         // 00420292: or edi, 0xffffffffffffffff
         // 00420295: mov ecx, edx
         // 00420297: shl edi, b1 cl
         // 00420299: mov ss:[ebp+0xfffffffffffffffc], 0x20
         // 004202a0: sub ss:[ebp+0xfffffffffffffffc], edx
         // 004202a3: not edi
      [-]8b5d088d5c9de08b338bce23cf894df08bcad3ee8b4dfc0b75f489338b75f0d3e6ff4508837d08038975f47cd3
         // 004202a5: mov ebx, ss:[ebp+0x8]
         // 004202a8: lea ebx, ss:[ebp+ebx*0x4]
         // 004202ac: mov esi, ds:[ebx]
         // 004202ae: mov ecx, esi
         // 004202b0: and ecx, edi
         // 004202b2: mov ss:[ebp+0xfffffffffffffff0], ecx
         // 004202b5: mov ecx, edx
         // 004202b7: shr esi, b1 cl
         // 004202b9: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 004202bc: or esi, ss:[ebp+0xfffffffffffffff4]
         // 004202bf: mov ds:[ebx], esi
         // 004202c1: mov esi, ss:[ebp+0xfffffffffffffff0]
         // 004202c4: shl esi, b1 cl
         // 004202c6: inc ss:[ebp+0x8]
         // 004202c9: cmp ss:[ebp+0x8], 0x3
         // 004202cd: mov ss:[ebp+0xfffffffffffffff4], esi
         // 004202d0: jl 0x4202a5
      [-]8bf06a02c1e6028d4de85a2bce
         // 004202d2: mov esi, eax
         // 004202d4: push 0x2
         // 004202d6: shl esi, b1 0x2
         // 004202d9: lea ecx, ss:[ebp+0xffffffffffffffe8]
         // 004202dc: pop edx
         // 004202dd: sub ecx, esi
      [-]3bd07c08
         // 004202df: cmp edx, eax
         // 004202e1: jl 0x4202eb
      [-]8b31897495e0eb05
         // 004202e3: mov esi, ds:[ecx]
         // 004202e5: mov ss:[ebp+edx*0x4], esi
         // 004202e9: jmp 0x4202f0
      [-]836495e000
         // 004202eb: and ss:[ebp+edx*0x4], 0x0
      [-]4a83e90485d27de7
         // 004202f0: dec edx
         // 004202f1: sub ecx, 0x4
         // 004202f4: test edx, edx
         // 004202f6: jge 0x4202df
      [-]4e8d4e018bc19983e21f03c2c1f8058bd181e2????????8945f47905
         // 00419d14: dec esi
         // 00419d15: lea ecx, ds:[esi+0x1]
         // 00419d18: mov eax, ecx
         // 00419d1a: cdq 
         // 00419d1b: and edx, 0x1f
         // 00419d1e: add eax, edx
         // 00419d20: sar eax, b1 0x5
         // 00419d23: mov edx, ecx
         // 00419d25: and edx, 0xffffffff8000001f
         // 00419d2b: mov ss:[ebp+0xfffffffffffffff4], eax
         // 00419d2e: jns 0x419d35
      [-]4a83cae042
         // 0042031a: dec edx
         // 0042031b: or edx, 0xffffffffffffffe0
         // 0042031e: inc edx
      [-]6a1f592bca33d242d3e28d5c85e0894df085130f8482000000
         // 0042031f: push 0x1f
         // 00420321: pop ecx
         // 00420322: sub ecx, edx
         // 00420324: xor edx, edx
         // 00420326: inc edx
         // 00420327: shl edx, b1 cl
         // 00420329: lea ebx, ss:[ebp+eax*0x4]
         // 0042032d: mov ss:[ebp+0xfffffffffffffff0], ecx
         // 00420330: test ds:[ebx], edx
         // 00420332: jz 0x4203ba
      [-]83caffd3e2f7d2855485e0eb05
         // 00420338: or edx, 0xffffffffffffffff
         // 0042033b: shl edx, b1 cl
         // 0042033d: not edx
         // 0042033f: test ss:[ebp+eax*0x4], edx
         // 00420343: jmp 0x42034a
      [-]837c85e000
         // 00420345: cmp ss:[ebp+eax*0x4], 0x0
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
      [-]8365080033d22bce42d3e28d4c85e08b318d3c163bfe7204
         // 0042036e: and ss:[ebp+0x8], 0x0
         // 00420372: xor edx, edx
         // 00420374: sub ecx, esi
         // 00420376: inc edx
         // 00420377: shl edx, b1 cl
         // 00420379: lea ecx, ss:[ebp+eax*0x4]
         // 0042037d: mov esi, ds:[ecx]
         // 0042037f: lea edi, ds:[esi+edx]
         // 00420382: cmp edi, esi
         // 00420384: jb 0x42038a
      [-]3bfa7307
         // 00420386: cmp edi, edx
         // 00420388: jnb 0x420391
      [-]c74508????????
         // 0042038a: mov ss:[ebp+0x8], 0x1
      [-]89398b4d08eb1f
         // 00420391: mov ds:[ecx], edi
         // 00420393: mov ecx, ss:[ebp+0x8]
         // 00420396: jmp 0x4203b7
      [-]85c9741e
         // 00420398: test ecx, ecx
         // 0042039a: jz 0x4203ba
      [-]8d4c85e08b118d720133ff3bf27205
         // 0042039c: lea ecx, ss:[ebp+eax*0x4]
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
      [-]8b4df083c8ffd3e021038b45f44083f8037d0d
         // 004203ba: mov ecx, ss:[ebp+0xfffffffffffffff0]
         // 004203bd: or eax, 0xffffffffffffffff
         // 004203c0: shl eax, b1 cl
         // 004203c2: and ds:[ebx], eax
         // 004203c4: mov eax, ss:[ebp+0xfffffffffffffff4]
         // 004203c7: inc eax
         // 004203c8: cmp eax, 0x3
         // 004203cb: jge 0x4203da
      [-]6a03598d7c85e02bc833c0f3ab
         // 004203cd: push 0x3
         // 004203cf: pop ecx
         // 004203d0: lea edi, ss:[ebp+eax*0x4]
         // 004203d4: sub ecx, eax
         // 004203d6: xor eax, eax
         // 004203d8: rep stosdd 
      [-]418bc19983e21f03c28bd1c1f80581e2????????7905
         // 00419df6: inc ecx
         // 00419df7: mov eax, ecx
         // 00419df9: cdq 
         // 00419dfa: and edx, 0x1f
         // 00419dfd: add eax, edx
         // 00419dff: mov edx, ecx
         // 00419e01: sar eax, b1 0x5
         // 00419e04: and edx, 0xffffffff8000001f
         // 00419e0a: jns 0x419e11
      [-]4a83cae042
         // 004203f6: dec edx
         // 004203f7: or edx, 0xffffffffffffffe0
         // 004203fa: inc edx
      [-]8365f4008365080083cfff8bcad3e7c745fc????????2955fcf7d7
         // 004203fb: and ss:[ebp+0xfffffffffffffff4], 0x0
         // 004203ff: and ss:[ebp+0x8], 0x0
         // 00420403: or edi, 0xffffffffffffffff
         // 00420406: mov ecx, edx
         // 00420408: shl edi, b1 cl
         // 0042040a: mov ss:[ebp+0xfffffffffffffffc], 0x20
         // 00420411: sub ss:[ebp+0xfffffffffffffffc], edx
         // 00420414: not edi
      [-]8b5d088d5c9de08b338bce23cf894df08bcad3ee8b4dfc0b75f489338b75f0d3e6ff4508837d08038975f47cd3
         // 00420416: mov ebx, ss:[ebp+0x8]
         // 00420419: lea ebx, ss:[ebp+ebx*0x4]
         // 0042041d: mov esi, ds:[ebx]
         // 0042041f: mov ecx, esi
         // 00420421: and ecx, edi
         // 00420423: mov ss:[ebp+0xfffffffffffffff0], ecx
         // 00420426: mov ecx, edx
         // 00420428: shr esi, b1 cl
         // 0042042a: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 0042042d: or esi, ss:[ebp+0xfffffffffffffff4]
         // 00420430: mov ds:[ebx], esi
         // 00420432: mov esi, ss:[ebp+0xfffffffffffffff0]
         // 00420435: shl esi, b1 cl
         // 00420437: inc ss:[ebp+0x8]
         // 0042043a: cmp ss:[ebp+0x8], 0x3
         // 0042043e: mov ss:[ebp+0xfffffffffffffff4], esi
         // 00420441: jl 0x420416
      [-]8bf06a02c1e6028d4de85a2bce
         // 00420443: mov esi, eax
         // 00420445: push 0x2
         // 00420447: shl esi, b1 0x2
         // 0042044a: lea ecx, ss:[ebp+0xffffffffffffffe8]
         // 0042044d: pop edx
         // 0042044e: sub ecx, esi
      [-]3bd07c08
         // 00420450: cmp edx, eax
         // 00420452: jl 0x42045c
      [-]8b31897495e0eb05
         // 00420454: mov esi, ds:[ecx]
         // 00420456: mov ss:[ebp+edx*0x4], esi
         // 0042045a: jmp 0x420461
      [-]836495e000
         // 0042045c: and ss:[ebp+edx*0x4], 0x0
      [-]4a83e90485d27de7
         // 00420461: dec edx
         // 00420462: sub ecx, 0x4
         // 00420465: test edx, edx
         // 00420467: jge 0x420450
      [-]6a0233db58e95a010000
         // 00420469: push 0x2
         // 0042046b: xor ebx, ebx
         // 0042046d: pop eax
         // 0042046e: jmp 0x4205cd
      [-]0f8cad000000
         // 00419e95: jl 0x419f48
      [-]33c08d7de0ababab814de0????????8bc19983e21f03c28bd1c1f80581e2????????7905
         // 00420485: xor eax, eax
         // 00420487: lea edi, ss:[ebp+0xffffffffffffffe0]
         // 0042048a: stosdd 
         // 0042048b: stosdd 
         // 0042048c: stosdd 
         // 0042048d: or ss:[ebp+0xffffffffffffffe0], 0xffffffff80000000
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
      [-]8365f4008365080083cfff8bcad3e7c745fc????????2955fcf7d7
         // 004204ae: and ss:[ebp+0xfffffffffffffff4], 0x0
         // 004204b2: and ss:[ebp+0x8], 0x0
         // 004204b6: or edi, 0xffffffffffffffff
         // 004204b9: mov ecx, edx
         // 004204bb: shl edi, b1 cl
         // 004204bd: mov ss:[ebp+0xfffffffffffffffc], 0x20
         // 004204c4: sub ss:[ebp+0xfffffffffffffffc], edx
         // 004204c7: not edi
      [-]8b5d088d5c9de08b338bce23cf894df08bcad3ee8b4dfc0b75f489338b75f0d3e6ff4508837d08038975f47cd3
         // 004204c9: mov ebx, ss:[ebp+0x8]
         // 004204cc: lea ebx, ss:[ebp+ebx*0x4]
         // 004204d0: mov esi, ds:[ebx]
         // 004204d2: mov ecx, esi
         // 004204d4: and ecx, edi
         // 004204d6: mov ss:[ebp+0xfffffffffffffff0], ecx
         // 004204d9: mov ecx, edx
         // 004204db: shr esi, b1 cl
         // 004204dd: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 004204e0: or esi, ss:[ebp+0xfffffffffffffff4]
         // 004204e3: mov ds:[ebx], esi
         // 004204e5: mov esi, ss:[ebp+0xfffffffffffffff0]
         // 004204e8: shl esi, b1 cl
         // 004204ea: inc ss:[ebp+0x8]
         // 004204ed: cmp ss:[ebp+0x8], 0x3
         // 004204f1: mov ss:[ebp+0xfffffffffffffff4], esi
         // 004204f4: jl 0x4204c9
      [-]8bf06a02c1e6028d4de85a2bce
         // 004204f6: mov esi, eax
         // 004204f8: push 0x2
         // 004204fa: shl esi, b1 0x2
         // 004204fd: lea ecx, ss:[ebp+0xffffffffffffffe8]
         // 00420500: pop edx
         // 00420501: sub ecx, esi
      [-]3bd07c08
         // 00420503: cmp edx, eax
         // 00420505: jl 0x42050f
      [-]8b31897495e0eb05
         // 00420507: mov esi, ds:[ecx]
         // 00420509: mov ss:[ebp+edx*0x4], esi
         // 0042050d: jmp 0x420514
      [-]836495e000
         // 0042050f: and ss:[ebp+edx*0x4], 0x0
      [-]4a83e90485d27de7
         // 00420514: dec edx
         // 00420515: sub ecx, 0x4
         // 00420518: test edx, edx
         // 0042051a: jge 0x420503
      [-]8d1c0133c040e99b000000
         // 00419f3d: lea ebx, ds:[ecx+eax]
         // 00419f40: xor eax, eax
         // 00419f42: inc eax
         // 00419f43: jmp 0x419fe3
      [-]8165????????7f03d88bc19983e21f03c28bd1c1f80581e2????????7905
         // 00419f4d: and ss:[ebp+0xffffffffffffffe0], 0x7fffffff
         // 00419f54: add ebx, eax
         // 00419f56: mov eax, ecx
         // 00419f58: cdq 
         // 00419f59: and edx, 0x1f
         // 00419f5c: add eax, edx
         // 00419f5e: mov edx, ecx
         // 00419f60: sar eax, b1 0x5
         // 00419f63: and edx, 0xffffffff8000001f
         // 00419f69: jns 0x419f70
      [-]4a83cae042
         // 00420555: dec edx
         // 00420556: or edx, 0xffffffffffffffe0
         // 00420559: inc edx
      [-]8365f4008365080083ceff8bcad3e6c745fc????????2955fcf7d6
         // 0042055a: and ss:[ebp+0xfffffffffffffff4], 0x0
         // 0042055e: and ss:[ebp+0x8], 0x0
         // 00420562: or esi, 0xffffffffffffffff
         // 00420565: mov ecx, edx
         // 00420567: shl esi, b1 cl
         // 00420569: mov ss:[ebp+0xfffffffffffffffc], 0x20
         // 00420570: sub ss:[ebp+0xfffffffffffffffc], edx
         // 00420573: not esi
      [-]8b4d088b7c8de08bcf23ce894df08bcad3ef8b4d080b7df4897c8de08b7df08b4dfcd3e7ff4508837d0803897df47cd0
         // 00420575: mov ecx, ss:[ebp+0x8]
         // 00420578: mov edi, ss:[ebp+ecx*0x4]
         // 0042057c: mov ecx, edi
         // 0042057e: and ecx, esi
         // 00420580: mov ss:[ebp+0xfffffffffffffff0], ecx
         // 00420583: mov ecx, edx
         // 00420585: shr edi, b1 cl
         // 00420587: mov ecx, ss:[ebp+0x8]
         // 0042058a: or edi, ss:[ebp+0xfffffffffffffff4]
         // 0042058d: mov ss:[ebp+ecx*0x4], edi
         // 00420591: mov edi, ss:[ebp+0xfffffffffffffff0]
         // 00420594: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 00420597: shl edi, b1 cl
         // 00420599: inc ss:[ebp+0x8]
         // 0042059c: cmp ss:[ebp+0x8], 0x3
         // 004205a0: mov ss:[ebp+0xfffffffffffffff4], edi
         // 004205a3: jl 0x420575
      [-]8bf06a02c1e6028d4de85a2bce
         // 004205a5: mov esi, eax
         // 004205a7: push 0x2
         // 004205a9: shl esi, b1 0x2
         // 004205ac: lea ecx, ss:[ebp+0xffffffffffffffe8]
         // 004205af: pop edx
         // 004205b0: sub ecx, esi
      [-]3bd07c08
         // 004205b2: cmp edx, eax
         // 004205b4: jl 0x4205be
      [-]8b31897495e0eb05
         // 004205b6: mov esi, ds:[ecx]
         // 004205b8: mov ss:[ebp+edx*0x4], esi
         // 004205bc: jmp 0x4205c3
      [-]836495e000
         // 004205be: and ss:[ebp+edx*0x4], 0x0
      [-]4a83e90485d27de7
         // 004205c3: dec edx
         // 004205c4: sub ecx, 0x4
         // 004205c7: test edx, edx
         // 004205c9: jge 0x4205b2
      [-]6a1f592b0d
         // 00419fe4: push 0x1f
         // 00419fe6: pop ecx
         // 00419fe7: sub ecx, ds:[0x4236bc]
      [-]d3e38b4decf7d91bc981e1????????0bd98b0d
         // 00419fed: shl ebx, b1 cl
         // 00419fef: mov ecx, ss:[ebp+0xffffffffffffffec]
         // 00419ff2: neg ecx
         // 00419ff4: sbb ecx, ecx
         // 00419ff6: and ecx, 0xffffffff80000000
         // 00419ffc: or ebx, ecx
         // 00419ffe: mov ecx, ds:[0x4236c0]
      [-]0b5de083f940750d
         // 0041a004: or ebx, ss:[ebp+0xffffffffffffffe0]
         // 0041a007: cmp ecx, 0x40
         // 0041a00a: jnz 0x41a019
      [-]8b4d0c8b55e48959048911eb0a
         // 004205f6: mov ecx, ss:[ebp+0xc]
         // 004205f9: mov edx, ss:[ebp+0xffffffffffffffe4]
         // 004205fc: mov ds:[ecx+0x4], ebx
         // 004205ff: mov ds:[ecx], edx
         // 00420601: jmp 0x42060d
      [-]83f9207505
         // 00420603: cmp ecx, 0x20
         // 00420606: jnz 0x42060d
      [-]8b4d0c8919
         // 00420608: mov ecx, ss:[ebp+0xc]
         // 0042060b: mov ds:[ecx], ebx
      [-]5f5bc9c3
         // 0042060d: pop edi
         // 0042060e: pop ebx
         // 0042060f: leave 
         // 00420610: retn 
      [-]558bec83ec2c8b45080fb7480a538bd981e1????????894dec8b4806894de08b48020fb70081e3????????81eb????????c1e01057894de48945e8
         // 0042091c: push ebp
         // 0042091d: mov ebp, esp
         // 0042091f: sub esp, 0x2c
         // 00420922: mov eax, ss:[ebp+0x8]
         // 00420925: movzx ecx, b2 ds:[eax+0xa]
         // 00420929: push ebx
         // 0042092a: mov ebx, ecx
         // 0042092c: and ecx, 0x8000
         // 00420932: mov ss:[ebp+0xffffffffffffffec], ecx
         // 00420935: mov ecx, ds:[eax+0x6]
         // 00420938: mov ss:[ebp+0xffffffffffffffe0], ecx
         // 0042093b: mov ecx, ds:[eax+0x2]
         // 0042093e: movzx eax, b2 ds:[eax]
         // 00420941: and ebx, 0x7fff
         // 00420947: sub ebx, 0x3fff
         // 0042094d: shl eax, b1 0x10
         // 00420950: push edi
         // 00420951: mov ss:[ebp+0xffffffffffffffe4], ecx
         // 00420954: mov ss:[ebp+0xffffffffffffffe8], eax
      [-]33db33c0
         // 00420654: xor ebx, ebx
         // 00420656: xor eax, eax
      [-]395c85e0750d
         // 00420658: cmp ss:[ebp+eax*0x4], ebx
         // 0042065c: jnz 0x42066b
      [-]4083f8037cf4
         // 0042065e: inc eax
         // 0042065f: cmp eax, 0x3
         // 00420662: jl 0x420658
      [-]33c0e9a5040000
         // 00420664: xor eax, eax
         // 00420666: jmp 0x420b10
      [-]33c08d7de0abab6a02ab58e995040000
         // 0042066b: xor eax, eax
         // 0042066d: lea edi, ss:[ebp+0xffffffffffffffe0]
         // 00420670: stosdd 
         // 00420671: stosdd 
         // 00420672: push 0x2
         // 00420674: stosdd 
         // 00420675: pop eax
         // 00420676: jmp 0x420b10
      [-]83650800568d75e08d7dd4a5a5a58b35
         // 0041a093: and ss:[ebp+0x8], 0x0
         // 0041a097: push esi
         // 0041a098: lea esi, ss:[ebp+0xffffffffffffffe0]
         // 0041a09b: lea edi, ss:[ebp+0xffffffffffffffd4]
         // 0041a09e: movsdd 
         // 0041a09f: movsdd 
         // 0041a0a0: movsdd 
         // 0041a0a1: mov esi, ds:[0x4236d0]
      [-]4e8d4e018bc19983e21f03c2c1f8058bd181e2????????895df08945f47905
         // 0041a0a7: dec esi
         // 0041a0a8: lea ecx, ds:[esi+0x1]
         // 0041a0ab: mov eax, ecx
         // 0041a0ad: cdq 
         // 0041a0ae: and edx, 0x1f
         // 0041a0b1: add eax, edx
         // 0041a0b3: sar eax, b1 0x5
         // 0041a0b6: mov edx, ecx
         // 0041a0b8: and edx, 0xffffffff8000001f
         // 0041a0be: mov ss:[ebp+0xfffffffffffffff0], ebx
         // 0041a0c1: mov ss:[ebp+0xfffffffffffffff4], eax
         // 0041a0c4: jns 0x41a0cb
      [-]4a83cae042
         // 004206ae: dec edx
         // 004206af: or edx, 0xffffffffffffffe0
         // 004206b2: inc edx
      [-]8d7c85e06a1f33c0592bca40d3e0894df885070f848d000000
         // 004206b3: lea edi, ss:[ebp+eax*0x4]
         // 004206b7: push 0x1f
         // 004206b9: xor eax, eax
         // 004206bb: pop ecx
         // 004206bc: sub ecx, edx
         // 004206be: inc eax
         // 004206bf: shl eax, b1 cl
         // 004206c1: mov ss:[ebp+0xfffffffffffffff8], ecx
         // 004206c4: test ds:[edi], eax
         // 004206c6: jz 0x420759
      [-]8b45f483caffd3e2f7d2855485e0eb05
         // 004206cc: mov eax, ss:[ebp+0xfffffffffffffff4]
         // 004206cf: or edx, 0xffffffffffffffff
         // 004206d2: shl edx, b1 cl
         // 004206d4: not edx
         // 004206d6: test ss:[ebp+eax*0x4], edx
         // 004206da: jmp 0x4206e1
      [-]837c85e000
         // 004206dc: cmp ss:[ebp+eax*0x4], 0x0
      [-]4083f8037cf3
         // 004206e3: inc eax
         // 004206e4: cmp eax, 0x3
         // 004206e7: jl 0x4206dc
      [-]8bc6996a1f5923d103c2c1f80581e6????????7905
         // 004206eb: mov eax, esi
         // 004206ed: cdq 
         // 004206ee: push 0x1f
         // 004206f0: pop ecx
         // 004206f1: and edx, ecx
         // 004206f3: add eax, edx
         // 004206f5: sar eax, b1 0x5
         // 004206f8: and esi, 0xffffffff8000001f
         // 004206fe: jns 0x420705
      [-]4e83cee046
         // 00420700: dec esi
         // 00420701: or esi, 0xffffffffffffffe0
         // 00420704: inc esi
      [-]8365fc002bce33d242d3e28d4c85e08b3103f28975088b313975087222
         // 00420705: and ss:[ebp+0xfffffffffffffffc], 0x0
         // 00420709: sub ecx, esi
         // 0042070b: xor edx, edx
         // 0042070d: inc edx
         // 0042070e: shl edx, b1 cl
         // 00420710: lea ecx, ss:[ebp+eax*0x4]
         // 00420714: mov esi, ds:[ecx]
         // 00420716: add esi, edx
         // 00420718: mov ss:[ebp+0x8], esi
         // 0042071b: mov esi, ds:[ecx]
         // 0042071d: cmp ss:[ebp+0x8], esi
         // 00420720: jb 0x420744
      [-]395508eb1b
         // 00420722: cmp ss:[ebp+0x8], edx
         // 00420725: jmp 0x420742
      [-]85c9742b
         // 00420727: test ecx, ecx
         // 00420729: jz 0x420756
      [-]8365fc008d4c85e08b118d7201
         // 00420a36: and ss:[ebp+0xfffffffffffffffc], 0x0
         // 00420a3a: lea ecx, ss:[ebp+eax*0x4]
         // 00420a3e: mov edx, ds:[ecx]
         // 00420a40: lea esi, ds:[edx+0x1]
      [-]c745fc????????
         // 00420744: mov ss:[ebp+0xfffffffffffffffc], 0x1
      [-]488b550889118b4dfc79d1
         // 0042074b: dec eax
         // 0042074c: mov edx, ss:[ebp+0x8]
         // 0042074f: mov ds:[ecx], edx
         // 00420751: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 00420754: jns 0x420727
      [-]8b4df883c8ffd3e021078b45f44083f8037d0d
         // 00420759: mov ecx, ss:[ebp+0xfffffffffffffff8]
         // 0042075c: or eax, 0xffffffffffffffff
         // 0042075f: shl eax, b1 cl
         // 00420761: and ds:[edi], eax
         // 00420763: mov eax, ss:[ebp+0xfffffffffffffff4]
         // 00420766: inc eax
         // 00420767: cmp eax, 0x3
         // 0042076a: jge 0x420779
      [-]6a03598d7c85e02bc833c0f3ab
         // 0042076c: push 0x3
         // 0042076e: pop ecx
         // 0042076f: lea edi, ss:[ebp+eax*0x4]
         // 00420773: sub ecx, eax
         // 00420775: xor eax, eax
         // 00420777: rep stosdd 
      [-]837d08007401
         // 00420779: cmp ss:[ebp+0x8], 0x0
         // 0042077d: jz 0x420780
      [-]8bc82b0d
         // 0041a19d: mov ecx, eax
         // 0041a19f: sub ecx, ds:[0x4236d0]
      [-]3bd97d0d
         // 0041a1a5: cmp ebx, ecx
         // 0041a1a7: jge 0x41a1b6
      [-]33c08d7de0abababe90d020000
         // 00420791: xor eax, eax
         // 00420793: lea edi, ss:[ebp+0xffffffffffffffe0]
         // 00420796: stosdd 
         // 00420797: stosdd 
         // 00420798: stosdd 
         // 00420799: jmp 0x4209ab
      [-]3bd80f8f0f020000
         // 0042079e: cmp ebx, eax
         // 004207a0: jg 0x4209b5
      [-]2b45f08d75d48bc88d7de0a59983e21f03c2a58bd1c1f80581e2????????a57905
         // 004207a6: sub eax, ss:[ebp+0xfffffffffffffff0]
         // 004207a9: lea esi, ss:[ebp+0xffffffffffffffd4]
         // 004207ac: mov ecx, eax
         // 004207ae: lea edi, ss:[ebp+0xffffffffffffffe0]
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
      [-]8365f4008365080083cfff8bcad3e7c745fc????????2955fcf7d7
         // 004207cc: and ss:[ebp+0xfffffffffffffff4], 0x0
         // 004207d0: and ss:[ebp+0x8], 0x0
         // 004207d4: or edi, 0xffffffffffffffff
         // 004207d7: mov ecx, edx
         // 004207d9: shl edi, b1 cl
         // 004207db: mov ss:[ebp+0xfffffffffffffffc], 0x20
         // 004207e2: sub ss:[ebp+0xfffffffffffffffc], edx
         // 004207e5: not edi
      [-]8b5d088d5c9de08b338bce23cf894df08bcad3ee8b4dfc0b75f489338b75f0d3e6ff4508837d08038975f47cd3
         // 004207e7: mov ebx, ss:[ebp+0x8]
         // 004207ea: lea ebx, ss:[ebp+ebx*0x4]
         // 004207ee: mov esi, ds:[ebx]
         // 004207f0: mov ecx, esi
         // 004207f2: and ecx, edi
         // 004207f4: mov ss:[ebp+0xfffffffffffffff0], ecx
         // 004207f7: mov ecx, edx
         // 004207f9: shr esi, b1 cl
         // 004207fb: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 004207fe: or esi, ss:[ebp+0xfffffffffffffff4]
         // 00420801: mov ds:[ebx], esi
         // 00420803: mov esi, ss:[ebp+0xfffffffffffffff0]
         // 00420806: shl esi, b1 cl
         // 00420808: inc ss:[ebp+0x8]
         // 0042080b: cmp ss:[ebp+0x8], 0x3
         // 0042080f: mov ss:[ebp+0xfffffffffffffff4], esi
         // 00420812: jl 0x4207e7
      [-]8bf06a02c1e6028d4de85a2bce
         // 00420814: mov esi, eax
         // 00420816: push 0x2
         // 00420818: shl esi, b1 0x2
         // 0042081b: lea ecx, ss:[ebp+0xffffffffffffffe8]
         // 0042081e: pop edx
         // 0042081f: sub ecx, esi
      [-]3bd07c08
         // 00420821: cmp edx, eax
         // 00420823: jl 0x42082d
      [-]8b31897495e0eb05
         // 00420825: mov esi, ds:[ecx]
         // 00420827: mov ss:[ebp+edx*0x4], esi
         // 0042082b: jmp 0x420832
      [-]836495e000
         // 0042082d: and ss:[ebp+edx*0x4], 0x0
      [-]4a83e90485d27de7
         // 00420832: dec edx
         // 00420833: sub ecx, 0x4
         // 00420836: test edx, edx
         // 00420838: jge 0x420821
      [-]4e8d4e018bc19983e21f03c2c1f8058bd181e2????????8945f47905
         // 0041a258: dec esi
         // 0041a259: lea ecx, ds:[esi+0x1]
         // 0041a25c: mov eax, ecx
         // 0041a25e: cdq 
         // 0041a25f: and edx, 0x1f
         // 0041a262: add eax, edx
         // 0041a264: sar eax, b1 0x5
         // 0041a267: mov edx, ecx
         // 0041a269: and edx, 0xffffffff8000001f
         // 0041a26f: mov ss:[ebp+0xfffffffffffffff4], eax
         // 0041a272: jns 0x41a279
      [-]4a83cae042
         // 0042085c: dec edx
         // 0042085d: or edx, 0xffffffffffffffe0
         // 00420860: inc edx
      [-]6a1f592bca33d242d3e28d5c85e0894df085130f8482000000
         // 00420861: push 0x1f
         // 00420863: pop ecx
         // 00420864: sub ecx, edx
         // 00420866: xor edx, edx
         // 00420868: inc edx
         // 00420869: shl edx, b1 cl
         // 0042086b: lea ebx, ss:[ebp+eax*0x4]
         // 0042086f: mov ss:[ebp+0xfffffffffffffff0], ecx
         // 00420872: test ds:[ebx], edx
         // 00420874: jz 0x4208fc
      [-]83caffd3e2f7d2855485e0eb05
         // 0042087a: or edx, 0xffffffffffffffff
         // 0042087d: shl edx, b1 cl
         // 0042087f: not edx
         // 00420881: test ss:[ebp+eax*0x4], edx
         // 00420885: jmp 0x42088c
      [-]837c85e000
         // 00420887: cmp ss:[ebp+eax*0x4], 0x0
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
      [-]8365080033d22bce42d3e28d4c85e08b318d3c163bfe7204
         // 004208b0: and ss:[ebp+0x8], 0x0
         // 004208b4: xor edx, edx
         // 004208b6: sub ecx, esi
         // 004208b8: inc edx
         // 004208b9: shl edx, b1 cl
         // 004208bb: lea ecx, ss:[ebp+eax*0x4]
         // 004208bf: mov esi, ds:[ecx]
         // 004208c1: lea edi, ds:[esi+edx]
         // 004208c4: cmp edi, esi
         // 004208c6: jb 0x4208cc
      [-]3bfa7307
         // 004208c8: cmp edi, edx
         // 004208ca: jnb 0x4208d3
      [-]c74508????????
         // 004208cc: mov ss:[ebp+0x8], 0x1
      [-]89398b4d08eb1f
         // 004208d3: mov ds:[ecx], edi
         // 004208d5: mov ecx, ss:[ebp+0x8]
         // 004208d8: jmp 0x4208f9
      [-]85c9741e
         // 004208da: test ecx, ecx
         // 004208dc: jz 0x4208fc
      [-]8d4c85e08b118d720133ff3bf27205
         // 004208de: lea ecx, ss:[ebp+eax*0x4]
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
      [-]8b4df083c8ffd3e021038b45f44083f8037d0d
         // 004208fc: mov ecx, ss:[ebp+0xfffffffffffffff0]
         // 004208ff: or eax, 0xffffffffffffffff
         // 00420902: shl eax, b1 cl
         // 00420904: and ds:[ebx], eax
         // 00420906: mov eax, ss:[ebp+0xfffffffffffffff4]
         // 00420909: inc eax
         // 0042090a: cmp eax, 0x3
         // 0042090d: jge 0x42091c
      [-]6a03598d7c85e02bc833c0f3ab
         // 0042090f: push 0x3
         // 00420911: pop ecx
         // 00420912: lea edi, ss:[ebp+eax*0x4]
         // 00420916: sub ecx, eax
         // 00420918: xor eax, eax
         // 0042091a: rep stosdd 
      [-]418bc19983e21f03c28bd1c1f80581e2????????7905
         // 0041a33a: inc ecx
         // 0041a33b: mov eax, ecx
         // 0041a33d: cdq 
         // 0041a33e: and edx, 0x1f
         // 0041a341: add eax, edx
         // 0041a343: mov edx, ecx
         // 0041a345: sar eax, b1 0x5
         // 0041a348: and edx, 0xffffffff8000001f
         // 0041a34e: jns 0x41a355
      [-]4a83cae042
         // 00420938: dec edx
         // 00420939: or edx, 0xffffffffffffffe0
         // 0042093c: inc edx
      [-]8365f4008365080083cfff8bcad3e7c745fc????????2955fcf7d7
         // 0042093d: and ss:[ebp+0xfffffffffffffff4], 0x0
         // 00420941: and ss:[ebp+0x8], 0x0
         // 00420945: or edi, 0xffffffffffffffff
         // 00420948: mov ecx, edx
         // 0042094a: shl edi, b1 cl
         // 0042094c: mov ss:[ebp+0xfffffffffffffffc], 0x20
         // 00420953: sub ss:[ebp+0xfffffffffffffffc], edx
         // 00420956: not edi
      [-]8b5d088d5c9de08b338bce23cf894df08bcad3ee8b4dfc0b75f489338b75f0d3e6ff4508837d08038975f47cd3
         // 00420958: mov ebx, ss:[ebp+0x8]
         // 0042095b: lea ebx, ss:[ebp+ebx*0x4]
         // 0042095f: mov esi, ds:[ebx]
         // 00420961: mov ecx, esi
         // 00420963: and ecx, edi
         // 00420965: mov ss:[ebp+0xfffffffffffffff0], ecx
         // 00420968: mov ecx, edx
         // 0042096a: shr esi, b1 cl
         // 0042096c: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 0042096f: or esi, ss:[ebp+0xfffffffffffffff4]
         // 00420972: mov ds:[ebx], esi
         // 00420974: mov esi, ss:[ebp+0xfffffffffffffff0]
         // 00420977: shl esi, b1 cl
         // 00420979: inc ss:[ebp+0x8]
         // 0042097c: cmp ss:[ebp+0x8], 0x3
         // 00420980: mov ss:[ebp+0xfffffffffffffff4], esi
         // 00420983: jl 0x420958
      [-]8bf06a02c1e6028d4de85a2bce
         // 00420985: mov esi, eax
         // 00420987: push 0x2
         // 00420989: shl esi, b1 0x2
         // 0042098c: lea ecx, ss:[ebp+0xffffffffffffffe8]
         // 0042098f: pop edx
         // 00420990: sub ecx, esi
      [-]3bd07c08
         // 00420992: cmp edx, eax
         // 00420994: jl 0x42099e
      [-]8b31897495e0eb05
         // 00420996: mov esi, ds:[ecx]
         // 00420998: mov ss:[ebp+edx*0x4], esi
         // 0042099c: jmp 0x4209a3
      [-]836495e000
         // 0042099e: and ss:[ebp+edx*0x4], 0x0
      [-]4a83e90485d27de7
         // 004209a3: dec edx
         // 004209a4: sub ecx, 0x4
         // 004209a7: test edx, edx
         // 004209a9: jge 0x420992
      [-]6a0233db58e95a010000
         // 004209ab: push 0x2
         // 004209ad: xor ebx, ebx
         // 004209af: pop eax
         // 004209b0: jmp 0x420b0f
      [-]0f8cad000000
         // 0041a3d9: jl 0x41a48c
      [-]33c08d7de0ababab814de0????????8bc19983e21f03c28bd1c1f80581e2????????7905
         // 004209c7: xor eax, eax
         // 004209c9: lea edi, ss:[ebp+0xffffffffffffffe0]
         // 004209cc: stosdd 
         // 004209cd: stosdd 
         // 004209ce: stosdd 
         // 004209cf: or ss:[ebp+0xffffffffffffffe0], 0xffffffff80000000
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
      [-]8365f4008365080083cfff8bcad3e7c745fc????????2955fcf7d7
         // 004209f0: and ss:[ebp+0xfffffffffffffff4], 0x0
         // 004209f4: and ss:[ebp+0x8], 0x0
         // 004209f8: or edi, 0xffffffffffffffff
         // 004209fb: mov ecx, edx
         // 004209fd: shl edi, b1 cl
         // 004209ff: mov ss:[ebp+0xfffffffffffffffc], 0x20
         // 00420a06: sub ss:[ebp+0xfffffffffffffffc], edx
         // 00420a09: not edi
      [-]8b5d088d5c9de08b338bce23cf894df08bcad3ee8b4dfc0b75f489338b75f0d3e6ff4508837d08038975f47cd3
         // 00420a0b: mov ebx, ss:[ebp+0x8]
         // 00420a0e: lea ebx, ss:[ebp+ebx*0x4]
         // 00420a12: mov esi, ds:[ebx]
         // 00420a14: mov ecx, esi
         // 00420a16: and ecx, edi
         // 00420a18: mov ss:[ebp+0xfffffffffffffff0], ecx
         // 00420a1b: mov ecx, edx
         // 00420a1d: shr esi, b1 cl
         // 00420a1f: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 00420a22: or esi, ss:[ebp+0xfffffffffffffff4]
         // 00420a25: mov ds:[ebx], esi
         // 00420a27: mov esi, ss:[ebp+0xfffffffffffffff0]
         // 00420a2a: shl esi, b1 cl
         // 00420a2c: inc ss:[ebp+0x8]
         // 00420a2f: cmp ss:[ebp+0x8], 0x3
         // 00420a33: mov ss:[ebp+0xfffffffffffffff4], esi
         // 00420a36: jl 0x420a0b
      [-]8bf06a02c1e6028d4de85a2bce
         // 00420a38: mov esi, eax
         // 00420a3a: push 0x2
         // 00420a3c: shl esi, b1 0x2
         // 00420a3f: lea ecx, ss:[ebp+0xffffffffffffffe8]
         // 00420a42: pop edx
         // 00420a43: sub ecx, esi
      [-]3bd07c08
         // 00420a45: cmp edx, eax
         // 00420a47: jl 0x420a51
      [-]8b31897495e0eb05
         // 00420a49: mov esi, ds:[ecx]
         // 00420a4b: mov ss:[ebp+edx*0x4], esi
         // 00420a4f: jmp 0x420a56
      [-]836495e000
         // 00420a51: and ss:[ebp+edx*0x4], 0x0
      [-]4a83e90485d27de7
         // 00420a56: dec edx
         // 00420a57: sub ecx, 0x4
         // 00420a5a: test edx, edx
         // 00420a5c: jge 0x420a45
      [-]8d1c0133c040e99b000000
         // 0041a481: lea ebx, ds:[ecx+eax]
         // 0041a484: xor eax, eax
         // 0041a486: inc eax
         // 0041a487: jmp 0x41a527
      [-]8165????????7f03d88bc19983e21f03c28bd1c1f80581e2????????7905
         // 0041a491: and ss:[ebp+0xffffffffffffffe0], 0x7fffffff
         // 0041a498: add ebx, eax
         // 0041a49a: mov eax, ecx
         // 0041a49c: cdq 
         // 0041a49d: and edx, 0x1f
         // 0041a4a0: add eax, edx
         // 0041a4a2: mov edx, ecx
         // 0041a4a4: sar eax, b1 0x5
         // 0041a4a7: and edx, 0xffffffff8000001f
         // 0041a4ad: jns 0x41a4b4
      [-]4a83cae042
         // 00420a97: dec edx
         // 00420a98: or edx, 0xffffffffffffffe0
         // 00420a9b: inc edx
      [-]8365f4008365080083ceff8bcad3e6c745fc????????2955fcf7d6
         // 00420a9c: and ss:[ebp+0xfffffffffffffff4], 0x0
         // 00420aa0: and ss:[ebp+0x8], 0x0
         // 00420aa4: or esi, 0xffffffffffffffff
         // 00420aa7: mov ecx, edx
         // 00420aa9: shl esi, b1 cl
         // 00420aab: mov ss:[ebp+0xfffffffffffffffc], 0x20
         // 00420ab2: sub ss:[ebp+0xfffffffffffffffc], edx
         // 00420ab5: not esi
      [-]8b4d088b7c8de08bcf23ce894df08bcad3ef8b4d080b7df4897c8de08b7df08b4dfcd3e7ff4508837d0803897df47cd0
         // 00420ab7: mov ecx, ss:[ebp+0x8]
         // 00420aba: mov edi, ss:[ebp+ecx*0x4]
         // 00420abe: mov ecx, edi
         // 00420ac0: and ecx, esi
         // 00420ac2: mov ss:[ebp+0xfffffffffffffff0], ecx
         // 00420ac5: mov ecx, edx
         // 00420ac7: shr edi, b1 cl
         // 00420ac9: mov ecx, ss:[ebp+0x8]
         // 00420acc: or edi, ss:[ebp+0xfffffffffffffff4]
         // 00420acf: mov ss:[ebp+ecx*0x4], edi
         // 00420ad3: mov edi, ss:[ebp+0xfffffffffffffff0]
         // 00420ad6: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 00420ad9: shl edi, b1 cl
         // 00420adb: inc ss:[ebp+0x8]
         // 00420ade: cmp ss:[ebp+0x8], 0x3
         // 00420ae2: mov ss:[ebp+0xfffffffffffffff4], edi
         // 00420ae5: jl 0x420ab7
      [-]8bf06a02c1e6028d4de85a2bce
         // 00420ae7: mov esi, eax
         // 00420ae9: push 0x2
         // 00420aeb: shl esi, b1 0x2
         // 00420aee: lea ecx, ss:[ebp+0xffffffffffffffe8]
         // 00420af1: pop edx
         // 00420af2: sub ecx, esi
      [-]3bd07c08
         // 00420af4: cmp edx, eax
         // 00420af6: jl 0x420b00
      [-]8b31897495e0eb05
         // 00420af8: mov esi, ds:[ecx]
         // 00420afa: mov ss:[ebp+edx*0x4], esi
         // 00420afe: jmp 0x420b05
      [-]836495e000
         // 00420b00: and ss:[ebp+edx*0x4], 0x0
      [-]4a83e90485d27de7
         // 00420b05: dec edx
         // 00420b06: sub ecx, 0x4
         // 00420b09: test edx, edx
         // 00420b0b: jge 0x420af4
      [-]6a1f592b0d
         // 0041a528: push 0x1f
         // 0041a52a: pop ecx
         // 0041a52b: sub ecx, ds:[0x4236d4]
      [-]d3e38b4decf7d91bc981e1????????0bd98b0d
         // 0041a531: shl ebx, b1 cl
         // 0041a533: mov ecx, ss:[ebp+0xffffffffffffffec]
         // 0041a536: neg ecx
         // 0041a538: sbb ecx, ecx
         // 0041a53a: and ecx, 0xffffffff80000000
         // 0041a540: or ebx, ecx
         // 0041a542: mov ecx, ds:[0x4236d8]
      [-]0b5de083f940750d
         // 0041a548: or ebx, ss:[ebp+0xffffffffffffffe0]
         // 0041a54b: cmp ecx, 0x40
         // 0041a54e: jnz 0x41a55d
      [-]8b4d0c8b55e48959048911eb0a
         // 00420b38: mov ecx, ss:[ebp+0xc]
         // 00420b3b: mov edx, ss:[ebp+0xffffffffffffffe4]
         // 00420b3e: mov ds:[ecx+0x4], ebx
         // 00420b41: mov ds:[ecx], edx
         // 00420b43: jmp 0x420b4f
      [-]83f9207505
         // 00420b45: cmp ecx, 0x20
         // 00420b48: jnz 0x420b4f
      [-]8b4d0c8919
         // 00420b4a: mov ecx, ss:[ebp+0xc]
         // 00420b4d: mov ds:[ecx], ebx
      [-]5f5bc9c3
         // 00420b4f: pop edi
         // 00420b50: pop ebx
         // 00420b51: leave 
         // 00420b52: retn 

  }
  condition:
    all of them
}
