rule urelas_10_3 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         0083c40c68????????8d
         // 0040102c: add esp, 0xc
         // 0040102f: push 0x104
         // 00401034: lea edx, ss:[esp+0x8]
      [-]6a00ff15
         // 00401039: push 0x0
         // 0040103b: call ds:[GetModuleFileNameW]
      [-]6a01e81fffffff59c3
         // 0040e23e: push 0x1
         // 0040e240: call _flsall
         // 0040e245: pop ecx
         // 0040e246: retn 
      [-]85c07402
         // 00413417: test eax, eax
         // 00413419: jz 0x41341d
      [-]85c07402
         // 0041343d: test eax, eax
         // 0041343f: jz 0x413443
      [-]ffff59c3
         // 0041a2bd: pop ecx
         // 0041a2be: retn 
      [-]558bec83ec
         // 00414d19: push ebp
         // 00414d1a: mov ebp, esp
         // 00414d1c: sub esp, 0x20
      [-]535657e8
         // 00414d1f: push ebx
         // 00414d20: push esi
         // 00414d21: push edi
         // 00414d22: call __encoded_null
      [-]ffffc70424
         // 00423cf3: mov ss:[esp], 0x42b688
      [-]ffd650e8
         // 00423d00: call esi
         // 00423d02: push eax
         // 00423d03: call __encode_pointer
      [-]ffffc70424
         // 00423d08: mov ss:[esp], 0x42b674
      [-]ffd650e8
         // 00423d15: call esi
         // 00423d17: push eax
         // 00423d18: call __encode_pointer
      [-]57ffd650e8
         // 0041c680: push edi
         // 0041c681: call esi
         // 0041c683: push eax
         // 0041c684: call __encode_pointer
      [-]ffff59a3
         // 0041c689: pop ecx
         // 0041c68a: mov ds:[0x42db2c], eax
      [-]5f5e5bc9c3
         // 00415415: pop edi
         // 00415416: pop esi
         // 00415417: pop ebx
         // 00415418: leave 
         // 00415419: retn 
      [-]558bec83ec28a1
         // 00420479: push ebp
         // 0042047a: mov ebp, esp
         // 0042047c: sub esp, 0x28
         // 0042047f: mov eax, ds:[0x42cc20]
      [-]33c58945fc53568b750857ff75108b7d0c8d4ddce8
         // 00420484: xor eax, ebp
         // 00420486: mov ss:[ebp+0xfffffffffffffffc], eax
         // 00420489: push ebx
         // 0042048a: push esi
         // 0042048b: mov esi, ss:[ebp+0x8]
         // 0042048e: push edi
         // 0042048f: push ss:[ebp+0x10]
         // 00420492: mov edi, ss:[ebp+0xc]
         // 00420495: lea ecx, ss:[ebp+0xffffffffffffffdc]
         // 00420498: call ??0_LocaleUpdate@@QAE@PAUlocaleinfo_struct@@@Z
      [-]8d45dc5033db53535353578d45d8508d45f050e8
         // 0042049d: lea eax, ss:[ebp+0xffffffffffffffdc]
         // 004204a0: push eax
         // 004204a1: xor ebx, ebx
         // 004204a3: push ebx
         // 004204a4: push ebx
         // 004204a5: push ebx
         // 004204a6: push ebx
         // 004204a7: push edi
         // 004204a8: lea eax, ss:[ebp+0xffffffffffffffd8]
         // 004204ab: push eax
         // 004204ac: lea eax, ss:[ebp+0xfffffffffffffff0]
         // 004204af: push eax
         // 004204b0: call ___strgtold12_l
      [-]00008945ec8d45f05650e8
         // 004204b5: mov ss:[ebp+0xffffffffffffffec], eax
         // 004204b8: lea eax, ss:[ebp+0xfffffffffffffff0]
         // 004204bb: push esi
         // 004204bc: push eax
         // 004204bd: call 0x4212c4
      [-]000083c428f645ec03752b
         // 004204c2: add esp, 0x28
         // 004204c5: test b1 ss:[ebp+0xffffffffffffffec], b1 0x3
         // 004204c9: jnz 0x4204f6
      [-]83f8017511
         // 00419150: cmp eax, 0x1
         // 00419153: jnz 0x419166
      [-]385de87407
         // 00419155: cmp b1 ss:[ebp+0xffffffffffffffe8], b1 bl
         // 00419158: jz 0x419161
      [-]8b45e4836070fd
         // 0041915a: mov eax, ss:[ebp+0xffffffffffffffe4]
         // 0041915d: and ds:[eax+0x70], 0xfffffffffffffffd
      [-]83f802751c
         // 00419166: cmp eax, 0x2
         // 00419169: jnz 0x419187
      [-]385de87407
         // 0041916b: cmp b1 ss:[ebp+0xffffffffffffffe8], b1 bl
         // 0041916e: jz 0x419177
      [-]8b45e4836070fd
         // 00419170: mov eax, ss:[ebp+0xffffffffffffffe4]
         // 00419173: and ds:[eax+0x70], 0xfffffffffffffffd
      [-]6a04ebe8
         // 00419177: push 0x4
         // 00419179: jmp 0x419163
      [-]f645ec0175ea
         // 0041917b: test b1 ss:[ebp+0xffffffffffffffec], b1 0x1
         // 0041917f: jnz 0x41916b
      [-]f645ec0275ce
         // 00419181: test b1 ss:[ebp+0xffffffffffffffec], b1 0x2
         // 00419185: jnz 0x419155
      [-]385de87407
         // 00419187: cmp b1 ss:[ebp+0xffffffffffffffe8], b1 bl
         // 0041918a: jz 0x419193
      [-]8b45e4836070fd
         // 0041918c: mov eax, ss:[ebp+0xffffffffffffffe4]
         // 0041918f: and ds:[eax+0x70], 0xfffffffffffffffd
      [-]8b4dfc5f5e33cd5be8
         // 0041ee27: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 0041ee2a: pop edi
         // 0041ee2b: pop esi
         // 0041ee2c: xor ecx, ebp
         // 0041ee2e: pop ebx
         // 0041ee2f: call 0x410738
      [-]558bec83ec28a1
         // 004251cf: push ebp
         // 004251d0: mov ebp, esp
         // 004251d2: sub esp, 0x28
         // 004251d5: mov eax, ds:[___security_cookie]
      [-]33c58945fc53568b750857ff75108b7d0c8d4ddce8
         // 004251da: xor eax, ebp
         // 004251dc: mov ss:[ebp+0xfffffffffffffffc], eax
         // 004251df: push ebx
         // 004251e0: push esi
         // 004251e1: mov esi, ss:[ebp+0x8]
         // 004251e4: push edi
         // 004251e5: push ss:[ebp+0x10]
         // 004251e8: mov edi, ss:[ebp+0xc]
         // 004251eb: lea ecx, ss:[ebp+0xffffffffffffffdc]
         // 004251ee: call ??0_LocaleUpdate@@QAE@PAUlocaleinfo_struct@@@Z
      [-]8d45dc5033db53535353578d45d8508d45f050e8
         // 004251f3: lea eax, ss:[ebp+0xffffffffffffffdc]
         // 004251f6: push eax
         // 004251f7: xor ebx, ebx
         // 004251f9: push ebx
         // 004251fa: push ebx
         // 004251fb: push ebx
         // 004251fc: push ebx
         // 004251fd: push edi
         // 004251fe: lea eax, ss:[ebp+0xffffffffffffffd8]
         // 00425201: push eax
         // 00425202: lea eax, ss:[ebp+0xfffffffffffffff0]
         // 00425205: push eax
         // 00425206: call ___strgtold12_l
      [-]00008945ec8d45f05650e8
         // 0042520b: mov ss:[ebp+0xffffffffffffffec], eax
         // 0042520e: lea eax, ss:[ebp+0xfffffffffffffff0]
         // 00425211: push esi
         // 00425212: push eax
         // 00425213: call 0x42636c
      [-]000083c428f645ec03752b
         // 00425218: add esp, 0x28
         // 0042521b: test b1 ss:[ebp+0xffffffffffffffec], b1 0x3
         // 0042521f: jnz 0x42524c
      [-]83f8017511
         // 004191f8: cmp eax, 0x1
         // 004191fb: jnz 0x41920e
      [-]385de87407
         // 004191fd: cmp b1 ss:[ebp+0xffffffffffffffe8], b1 bl
         // 00419200: jz 0x419209
      [-]8b45e4836070fd
         // 00419202: mov eax, ss:[ebp+0xffffffffffffffe4]
         // 00419205: and ds:[eax+0x70], 0xfffffffffffffffd
      [-]83f802751c
         // 0041920e: cmp eax, 0x2
         // 00419211: jnz 0x41922f
      [-]385de87407
         // 00419213: cmp b1 ss:[ebp+0xffffffffffffffe8], b1 bl
         // 00419216: jz 0x41921f
      [-]8b45e4836070fd
         // 00419218: mov eax, ss:[ebp+0xffffffffffffffe4]
         // 0041921b: and ds:[eax+0x70], 0xfffffffffffffffd
      [-]6a04ebe8
         // 0041921f: push 0x4
         // 00419221: jmp 0x41920b
      [-]f645ec0175ea
         // 00419223: test b1 ss:[ebp+0xffffffffffffffec], b1 0x1
         // 00419227: jnz 0x419213
      [-]f645ec0275ce
         // 00419229: test b1 ss:[ebp+0xffffffffffffffec], b1 0x2
         // 0041922d: jnz 0x4191fd
      [-]385de87407
         // 0041922f: cmp b1 ss:[ebp+0xffffffffffffffe8], b1 bl
         // 00419232: jz 0x41923b
      [-]8b45e4836070fd
         // 00419234: mov eax, ss:[ebp+0xffffffffffffffe4]
         // 00419237: and ds:[eax+0x70], 0xfffffffffffffffd
      [-]8b4dfc5f5e33cd5be8
         // 0041eecf: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 0041eed2: pop edi
         // 0041eed3: pop esi
         // 0041eed4: xor ecx, ebp
         // 0041eed6: pop ebx
         // 0041eed7: call 0x410738
      [-]558bec83ec2c8b45080fb7480a538bd981e1????????894dec8b4806894de08b48020fb70081e3????????81eb????????c1e01057894de48945e8
         // 004199df: push ebp
         // 004199e0: mov ebp, esp
         // 004199e2: sub esp, 0x2c
         // 004199e5: mov eax, ss:[ebp+0x8]
         // 004199e8: movzx ecx, b2 ds:[eax+0xa]
         // 004199ec: push ebx
         // 004199ed: mov ebx, ecx
         // 004199ef: and ecx, 0x8000
         // 004199f5: mov ss:[ebp+0xffffffffffffffec], ecx
         // 004199f8: mov ecx, ds:[eax+0x6]
         // 004199fb: mov ss:[ebp+0xffffffffffffffe0], ecx
         // 004199fe: mov ecx, ds:[eax+0x2]
         // 00419a01: movzx eax, b2 ds:[eax]
         // 00419a04: and ebx, 0x7fff
         // 00419a0a: sub ebx, 0x3fff
         // 00419a10: shl eax, b1 0x10
         // 00419a19: push edi
         // 00419a1a: mov ss:[ebp+0xffffffffffffffe4], ecx
         // 00419a1d: mov ss:[ebp+0xffffffffffffffe8], eax
      [-]33db33c0
         // 00419658: xor ebx, ebx
         // 0041965a: xor eax, eax
      [-]395c85e0750d
         // 0041965c: cmp ss:[ebp+eax*0x4], ebx
         // 00419660: jnz 0x41966f
      [-]4083f8037cf4
         // 00419662: inc eax
         // 00419663: cmp eax, 0x3
         // 00419666: jl 0x41965c
      [-]33c0e9a5040000
         // 00419668: xor eax, eax
         // 0041966a: jmp 0x419b14
      [-]33c08d7de0abab6a02ab58e995040000
         // 0041966f: xor eax, eax
         // 00419671: lea edi, ss:[ebp+0xffffffffffffffe0]
         // 00419674: stosdd 
         // 00419675: stosdd 
         // 00419676: push 0x2
         // 00419678: stosdd 
         // 00419679: pop eax
         // 0041967a: jmp 0x419b14
      [-]83650800568d75e08d7dd4a5a5a58b35
         // 00420442: and ss:[ebp+0x8], 0x0
         // 00420446: push esi
         // 00420447: lea esi, ss:[ebp+0xffffffffffffffe0]
         // 0042044a: lea edi, ss:[ebp+0xffffffffffffffd4]
         // 0042044d: movsdd 
         // 0042044e: movsdd 
         // 0042044f: movsdd 
         // 00420450: mov esi, ds:[0x42c068]
      [-]4e8d4e018bc19983e21f03c2c1f8058bd181e2????????895df08945f47905
         // 00420456: dec esi
         // 00420457: lea ecx, ds:[esi+0x1]
         // 0042045a: mov eax, ecx
         // 0042045c: cdq 
         // 0042045d: and edx, 0x1f
         // 00420460: add eax, edx
         // 00420462: sar eax, b1 0x5
         // 00420465: mov edx, ecx
         // 00420467: and edx, 0xffffffff8000001f
         // 0042046d: mov ss:[ebp+0xfffffffffffffff0], ebx
         // 00420470: mov ss:[ebp+0xfffffffffffffff4], eax
         // 00420473: jns 0x42047a
      [-]4a83cae042
         // 004196b2: dec edx
         // 004196b3: or edx, 0xffffffffffffffe0
         // 004196b6: inc edx
      [-]8d7c85e06a1f33c0592bca40d3e0894df885070f848d000000
         // 004196b7: lea edi, ss:[ebp+eax*0x4]
         // 004196bb: push 0x1f
         // 004196bd: xor eax, eax
         // 004196bf: pop ecx
         // 004196c0: sub ecx, edx
         // 004196c2: inc eax
         // 004196c3: shl eax, b1 cl
         // 004196c5: mov ss:[ebp+0xfffffffffffffff8], ecx
         // 004196c8: test ds:[edi], eax
         // 004196ca: jz 0x41975d
      [-]8b45f483caffd3e2f7d2855485e0eb05
         // 004196d0: mov eax, ss:[ebp+0xfffffffffffffff4]
         // 004196d3: or edx, 0xffffffffffffffff
         // 004196d6: shl edx, b1 cl
         // 004196d8: not edx
         // 004196da: test ss:[ebp+eax*0x4], edx
         // 004196de: jmp 0x4196e5
      [-]837c85e000
         // 004196e0: cmp ss:[ebp+eax*0x4], 0x0
      [-]4083f8037cf3
         // 004196e7: inc eax
         // 004196e8: cmp eax, 0x3
         // 004196eb: jl 0x4196e0
      [-]8bc6996a1f5923d103c2c1f80581e6????????7905
         // 004196ef: mov eax, esi
         // 004196f1: cdq 
         // 004196f2: push 0x1f
         // 004196f4: pop ecx
         // 004196f5: and edx, ecx
         // 004196f7: add eax, edx
         // 004196f9: sar eax, b1 0x5
         // 004196fc: and esi, 0xffffffff8000001f
         // 00419702: jns 0x419709
      [-]4e83cee046
         // 00419704: dec esi
         // 00419705: or esi, 0xffffffffffffffe0
         // 00419708: inc esi
      [-]8365fc002bce33d242d3e28d4c85e08b3103f28975088b313975087222
         // 00419709: and ss:[ebp+0xfffffffffffffffc], 0x0
         // 0041970d: sub ecx, esi
         // 0041970f: xor edx, edx
         // 00419711: inc edx
         // 00419712: shl edx, b1 cl
         // 00419714: lea ecx, ss:[ebp+eax*0x4]
         // 00419718: mov esi, ds:[ecx]
         // 0041971a: add esi, edx
         // 0041971c: mov ss:[ebp+0x8], esi
         // 0041971f: mov esi, ds:[ecx]
         // 00419721: cmp ss:[ebp+0x8], esi
         // 00419724: jb 0x419748
      [-]395508eb1b
         // 00419726: cmp ss:[ebp+0x8], edx
         // 00419729: jmp 0x419746
      [-]85c9742b
         // 0041972b: test ecx, ecx
         // 0041972d: jz 0x41975a
      [-]8365fc008d4c85e08b118d7201
         // 00419af9: and ss:[ebp+0xfffffffffffffffc], 0x0
         // 00419afd: lea ecx, ss:[ebp+eax*0x4]
         // 00419b01: mov edx, ds:[ecx]
         // 00419b03: lea esi, ds:[edx+0x1]
      [-]c745fc????????
         // 00419748: mov ss:[ebp+0xfffffffffffffffc], 0x1
      [-]488b550889118b4dfc79d1
         // 0041974f: dec eax
         // 00419750: mov edx, ss:[ebp+0x8]
         // 00419753: mov ds:[ecx], edx
         // 00419755: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 00419758: jns 0x41972b
      [-]8b4df883c8ffd3e021078b45f44083f8037d0d
         // 0041975d: mov ecx, ss:[ebp+0xfffffffffffffff8]
         // 00419760: or eax, 0xffffffffffffffff
         // 00419763: shl eax, b1 cl
         // 00419765: and ds:[edi], eax
         // 00419767: mov eax, ss:[ebp+0xfffffffffffffff4]
         // 0041976a: inc eax
         // 0041976b: cmp eax, 0x3
         // 0041976e: jge 0x41977d
      [-]6a03598d7c85e02bc833c0f3ab
         // 00419770: push 0x3
         // 00419772: pop ecx
         // 00419773: lea edi, ss:[ebp+eax*0x4]
         // 00419777: sub ecx, eax
         // 00419779: xor eax, eax
         // 0041977b: rep stosdd 
      [-]837d08007401
         // 0041977d: cmp ss:[ebp+0x8], 0x0
         // 00419781: jz 0x419784
      [-]8bc82b0d
         // 0042054c: mov ecx, eax
         // 0042054e: sub ecx, ds:[0x42c068]
      [-]3bd97d0d
         // 00420554: cmp ebx, ecx
         // 00420556: jge 0x420565
      [-]33c08d7de0abababe90d020000
         // 00419795: xor eax, eax
         // 00419797: lea edi, ss:[ebp+0xffffffffffffffe0]
         // 0041979a: stosdd 
         // 0041979b: stosdd 
         // 0041979c: stosdd 
         // 0041979d: jmp 0x4199af
      [-]3bd80f8f0f020000
         // 004197a2: cmp ebx, eax
         // 004197a4: jg 0x4199b9
      [-]2b45f08d75d48bc88d7de0a59983e21f03c2a58bd1c1f80581e2????????a57905
         // 004197aa: sub eax, ss:[ebp+0xfffffffffffffff0]
         // 004197ad: lea esi, ss:[ebp+0xffffffffffffffd4]
         // 004197b0: mov ecx, eax
         // 004197b2: lea edi, ss:[ebp+0xffffffffffffffe0]
         // 004197b5: movsdd 
         // 004197b6: cdq 
         // 004197b7: and edx, 0x1f
         // 004197ba: add eax, edx
         // 004197bc: movsdd 
         // 004197bd: mov edx, ecx
         // 004197bf: sar eax, b1 0x5
         // 004197c2: and edx, 0xffffffff8000001f
         // 004197c8: movsdd 
         // 004197c9: jns 0x4197d0
      [-]4a83cae042
         // 004197cb: dec edx
         // 004197cc: or edx, 0xffffffffffffffe0
         // 004197cf: inc edx
      [-]8365f4008365080083cfff8bcad3e7c745fc????????2955fcf7d7
         // 004197d0: and ss:[ebp+0xfffffffffffffff4], 0x0
         // 004197d4: and ss:[ebp+0x8], 0x0
         // 004197d8: or edi, 0xffffffffffffffff
         // 004197db: mov ecx, edx
         // 004197dd: shl edi, b1 cl
         // 004197df: mov ss:[ebp+0xfffffffffffffffc], 0x20
         // 004197e6: sub ss:[ebp+0xfffffffffffffffc], edx
         // 004197e9: not edi
      [-]8b5d088d5c9de08b338bce23cf894df08bcad3ee8b4dfc0b75f489338b75f0d3e6ff4508837d08038975f47cd3
         // 004197eb: mov ebx, ss:[ebp+0x8]
         // 004197ee: lea ebx, ss:[ebp+ebx*0x4]
         // 004197f2: mov esi, ds:[ebx]
         // 004197f4: mov ecx, esi
         // 004197f6: and ecx, edi
         // 004197f8: mov ss:[ebp+0xfffffffffffffff0], ecx
         // 004197fb: mov ecx, edx
         // 004197fd: shr esi, b1 cl
         // 004197ff: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 00419802: or esi, ss:[ebp+0xfffffffffffffff4]
         // 00419805: mov ds:[ebx], esi
         // 00419807: mov esi, ss:[ebp+0xfffffffffffffff0]
         // 0041980a: shl esi, b1 cl
         // 0041980c: inc ss:[ebp+0x8]
         // 0041980f: cmp ss:[ebp+0x8], 0x3
         // 00419813: mov ss:[ebp+0xfffffffffffffff4], esi
         // 00419816: jl 0x4197eb
      [-]8bf06a02c1e6028d4de85a2bce
         // 00419818: mov esi, eax
         // 0041981a: push 0x2
         // 0041981c: shl esi, b1 0x2
         // 0041981f: lea ecx, ss:[ebp+0xffffffffffffffe8]
         // 00419822: pop edx
         // 00419823: sub ecx, esi
      [-]3bd07c08
         // 00419825: cmp edx, eax
         // 00419827: jl 0x419831
      [-]8b31897495e0eb05
         // 00419829: mov esi, ds:[ecx]
         // 0041982b: mov ss:[ebp+edx*0x4], esi
         // 0041982f: jmp 0x419836
      [-]836495e000
         // 00419831: and ss:[ebp+edx*0x4], 0x0
      [-]4a83e90485d27de7
         // 00419836: dec edx
         // 00419837: sub ecx, 0x4
         // 0041983a: test edx, edx
         // 0041983c: jge 0x419825
      [-]4e8d4e018bc19983e21f03c2c1f8058bd181e2????????8945f47905
         // 00420607: dec esi
         // 00420608: lea ecx, ds:[esi+0x1]
         // 0042060b: mov eax, ecx
         // 0042060d: cdq 
         // 0042060e: and edx, 0x1f
         // 00420611: add eax, edx
         // 00420613: sar eax, b1 0x5
         // 00420616: mov edx, ecx
         // 00420618: and edx, 0xffffffff8000001f
         // 0042061e: mov ss:[ebp+0xfffffffffffffff4], eax
         // 00420621: jns 0x420628
      [-]4a83cae042
         // 00419860: dec edx
         // 00419861: or edx, 0xffffffffffffffe0
         // 00419864: inc edx
      [-]6a1f592bca33d242d3e28d5c85e0894df085130f8482000000
         // 00419865: push 0x1f
         // 00419867: pop ecx
         // 00419868: sub ecx, edx
         // 0041986a: xor edx, edx
         // 0041986c: inc edx
         // 0041986d: shl edx, b1 cl
         // 0041986f: lea ebx, ss:[ebp+eax*0x4]
         // 00419873: mov ss:[ebp+0xfffffffffffffff0], ecx
         // 00419876: test ds:[ebx], edx
         // 00419878: jz 0x419900
      [-]83caffd3e2f7d2855485e0eb05
         // 0041987e: or edx, 0xffffffffffffffff
         // 00419881: shl edx, b1 cl
         // 00419883: not edx
         // 00419885: test ss:[ebp+eax*0x4], edx
         // 00419889: jmp 0x419890
      [-]837c85e000
         // 0041988b: cmp ss:[ebp+eax*0x4], 0x0
      [-]4083f8037cf3
         // 00419892: inc eax
         // 00419893: cmp eax, 0x3
         // 00419896: jl 0x41988b
      [-]8bc6996a1f5923d103c2c1f80581e6????????7905
         // 0041989a: mov eax, esi
         // 0041989c: cdq 
         // 0041989d: push 0x1f
         // 0041989f: pop ecx
         // 004198a0: and edx, ecx
         // 004198a2: add eax, edx
         // 004198a4: sar eax, b1 0x5
         // 004198a7: and esi, 0xffffffff8000001f
         // 004198ad: jns 0x4198b4
      [-]4e83cee046
         // 004198af: dec esi
         // 004198b0: or esi, 0xffffffffffffffe0
         // 004198b3: inc esi
      [-]8365080033d22bce42d3e28d4c85e08b318d3c163bfe7204
         // 004198b4: and ss:[ebp+0x8], 0x0
         // 004198b8: xor edx, edx
         // 004198ba: sub ecx, esi
         // 004198bc: inc edx
         // 004198bd: shl edx, b1 cl
         // 004198bf: lea ecx, ss:[ebp+eax*0x4]
         // 004198c3: mov esi, ds:[ecx]
         // 004198c5: lea edi, ds:[esi+edx]
         // 004198c8: cmp edi, esi
         // 004198ca: jb 0x4198d0
      [-]3bfa7307
         // 004198cc: cmp edi, edx
         // 004198ce: jnb 0x4198d7
      [-]c74508????????
         // 004198d0: mov ss:[ebp+0x8], 0x1
      [-]89398b4d08eb1f
         // 004198d7: mov ds:[ecx], edi
         // 004198d9: mov ecx, ss:[ebp+0x8]
         // 004198dc: jmp 0x4198fd
      [-]85c9741e
         // 004198de: test ecx, ecx
         // 004198e0: jz 0x419900
      [-]8d4c85e08b118d720133ff3bf27205
         // 004198e2: lea ecx, ss:[ebp+eax*0x4]
         // 004198e6: mov edx, ds:[ecx]
         // 004198e8: lea esi, ds:[edx+0x1]
         // 004198eb: xor edi, edi
         // 004198ed: cmp esi, edx
         // 004198ef: jb 0x4198f6
      [-]83fe017303
         // 004198f1: cmp esi, 0x1
         // 004198f4: jnb 0x4198f9
      [-]89318bcf
         // 004198f9: mov ds:[ecx], esi
         // 004198fb: mov ecx, edi
      [-]8b4df083c8ffd3e021038b45f44083f8037d0d
         // 00419900: mov ecx, ss:[ebp+0xfffffffffffffff0]
         // 00419903: or eax, 0xffffffffffffffff
         // 00419906: shl eax, b1 cl
         // 00419908: and ds:[ebx], eax
         // 0041990a: mov eax, ss:[ebp+0xfffffffffffffff4]
         // 0041990d: inc eax
         // 0041990e: cmp eax, 0x3
         // 00419911: jge 0x419920
      [-]6a03598d7c85e02bc833c0f3ab
         // 00419913: push 0x3
         // 00419915: pop ecx
         // 00419916: lea edi, ss:[ebp+eax*0x4]
         // 0041991a: sub ecx, eax
         // 0041991c: xor eax, eax
         // 0041991e: rep stosdd 
      [-]418bc19983e21f03c28bd1c1f80581e2????????7905
         // 004206e9: inc ecx
         // 004206ea: mov eax, ecx
         // 004206ec: cdq 
         // 004206ed: and edx, 0x1f
         // 004206f0: add eax, edx
         // 004206f2: mov edx, ecx
         // 004206f4: sar eax, b1 0x5
         // 004206f7: and edx, 0xffffffff8000001f
         // 004206fd: jns 0x420704
      [-]4a83cae042
         // 0041993c: dec edx
         // 0041993d: or edx, 0xffffffffffffffe0
         // 00419940: inc edx
      [-]8365f4008365080083cfff8bcad3e7c745fc????????2955fcf7d7
         // 00419941: and ss:[ebp+0xfffffffffffffff4], 0x0
         // 00419945: and ss:[ebp+0x8], 0x0
         // 00419949: or edi, 0xffffffffffffffff
         // 0041994c: mov ecx, edx
         // 0041994e: shl edi, b1 cl
         // 00419950: mov ss:[ebp+0xfffffffffffffffc], 0x20
         // 00419957: sub ss:[ebp+0xfffffffffffffffc], edx
         // 0041995a: not edi
      [-]8b5d088d5c9de08b338bce23cf894df08bcad3ee8b4dfc0b75f489338b75f0d3e6ff4508837d08038975f47cd3
         // 0041995c: mov ebx, ss:[ebp+0x8]
         // 0041995f: lea ebx, ss:[ebp+ebx*0x4]
         // 00419963: mov esi, ds:[ebx]
         // 00419965: mov ecx, esi
         // 00419967: and ecx, edi
         // 00419969: mov ss:[ebp+0xfffffffffffffff0], ecx
         // 0041996c: mov ecx, edx
         // 0041996e: shr esi, b1 cl
         // 00419970: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 00419973: or esi, ss:[ebp+0xfffffffffffffff4]
         // 00419976: mov ds:[ebx], esi
         // 00419978: mov esi, ss:[ebp+0xfffffffffffffff0]
         // 0041997b: shl esi, b1 cl
         // 0041997d: inc ss:[ebp+0x8]
         // 00419980: cmp ss:[ebp+0x8], 0x3
         // 00419984: mov ss:[ebp+0xfffffffffffffff4], esi
         // 00419987: jl 0x41995c
      [-]8bf06a02c1e6028d4de85a2bce
         // 00419989: mov esi, eax
         // 0041998b: push 0x2
         // 0041998d: shl esi, b1 0x2
         // 00419990: lea ecx, ss:[ebp+0xffffffffffffffe8]
         // 00419993: pop edx
         // 00419994: sub ecx, esi
      [-]3bd07c08
         // 00419996: cmp edx, eax
         // 00419998: jl 0x4199a2
      [-]8b31897495e0eb05
         // 0041999a: mov esi, ds:[ecx]
         // 0041999c: mov ss:[ebp+edx*0x4], esi
         // 004199a0: jmp 0x4199a7
      [-]836495e000
         // 004199a2: and ss:[ebp+edx*0x4], 0x0
      [-]4a83e90485d27de7
         // 004199a7: dec edx
         // 004199a8: sub ecx, 0x4
         // 004199ab: test edx, edx
         // 004199ad: jge 0x419996
      [-]6a0233db58e95a010000
         // 004199af: push 0x2
         // 004199b1: xor ebx, ebx
         // 004199b3: pop eax
         // 004199b4: jmp 0x419b13
      [-]0f8cad000000
         // 00420788: jl 0x42083b
      [-]33c08d7de0ababab814de0????????8bc19983e21f03c28bd1c1f80581e2????????7905
         // 004199cb: xor eax, eax
         // 004199cd: lea edi, ss:[ebp+0xffffffffffffffe0]
         // 004199d0: stosdd 
         // 004199d1: stosdd 
         // 004199d2: stosdd 
         // 004199d3: or ss:[ebp+0xffffffffffffffe0], 0xffffffff80000000
         // 004199da: mov eax, ecx
         // 004199dc: cdq 
         // 004199dd: and edx, 0x1f
         // 004199e0: add eax, edx
         // 004199e2: mov edx, ecx
         // 004199e4: sar eax, b1 0x5
         // 004199e7: and edx, 0xffffffff8000001f
         // 004199ed: jns 0x4199f4
      [-]4a83cae042
         // 004199ef: dec edx
         // 004199f0: or edx, 0xffffffffffffffe0
         // 004199f3: inc edx
      [-]8365f4008365080083cfff8bcad3e7c745fc????????2955fcf7d7
         // 004199f4: and ss:[ebp+0xfffffffffffffff4], 0x0
         // 004199f8: and ss:[ebp+0x8], 0x0
         // 004199fc: or edi, 0xffffffffffffffff
         // 004199ff: mov ecx, edx
         // 00419a01: shl edi, b1 cl
         // 00419a03: mov ss:[ebp+0xfffffffffffffffc], 0x20
         // 00419a0a: sub ss:[ebp+0xfffffffffffffffc], edx
         // 00419a0d: not edi
      [-]8b5d088d5c9de08b338bce23cf894df08bcad3ee8b4dfc0b75f489338b75f0d3e6ff4508837d08038975f47cd3
         // 00419a0f: mov ebx, ss:[ebp+0x8]
         // 00419a12: lea ebx, ss:[ebp+ebx*0x4]
         // 00419a16: mov esi, ds:[ebx]
         // 00419a18: mov ecx, esi
         // 00419a1a: and ecx, edi
         // 00419a1c: mov ss:[ebp+0xfffffffffffffff0], ecx
         // 00419a1f: mov ecx, edx
         // 00419a21: shr esi, b1 cl
         // 00419a23: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 00419a26: or esi, ss:[ebp+0xfffffffffffffff4]
         // 00419a29: mov ds:[ebx], esi
         // 00419a2b: mov esi, ss:[ebp+0xfffffffffffffff0]
         // 00419a2e: shl esi, b1 cl
         // 00419a30: inc ss:[ebp+0x8]
         // 00419a33: cmp ss:[ebp+0x8], 0x3
         // 00419a37: mov ss:[ebp+0xfffffffffffffff4], esi
         // 00419a3a: jl 0x419a0f
      [-]8bf06a02c1e6028d4de85a2bce
         // 00419a3c: mov esi, eax
         // 00419a3e: push 0x2
         // 00419a40: shl esi, b1 0x2
         // 00419a43: lea ecx, ss:[ebp+0xffffffffffffffe8]
         // 00419a46: pop edx
         // 00419a47: sub ecx, esi
      [-]3bd07c08
         // 00419a49: cmp edx, eax
         // 00419a4b: jl 0x419a55
      [-]8b31897495e0eb05
         // 00419a4d: mov esi, ds:[ecx]
         // 00419a4f: mov ss:[ebp+edx*0x4], esi
         // 00419a53: jmp 0x419a5a
      [-]836495e000
         // 00419a55: and ss:[ebp+edx*0x4], 0x0
      [-]4a83e90485d27de7
         // 00419a5a: dec edx
         // 00419a5b: sub ecx, 0x4
         // 00419a5e: test edx, edx
         // 00419a60: jge 0x419a49
      [-]8d1c0133c040e99b000000
         // 00420830: lea ebx, ds:[ecx+eax]
         // 00420833: xor eax, eax
         // 00420835: inc eax
         // 00420836: jmp 0x4208d6
      [-]8165????????7f03d88bc19983e21f03c28bd1c1f80581e2????????7905
         // 00420840: and ss:[ebp+0xffffffffffffffe0], 0x7fffffff
         // 00420847: add ebx, eax
         // 00420849: mov eax, ecx
         // 0042084b: cdq 
         // 0042084c: and edx, 0x1f
         // 0042084f: add eax, edx
         // 00420851: mov edx, ecx
         // 00420853: sar eax, b1 0x5
         // 00420856: and edx, 0xffffffff8000001f
         // 0042085c: jns 0x420863
      [-]4a83cae042
         // 00419a9b: dec edx
         // 00419a9c: or edx, 0xffffffffffffffe0
         // 00419a9f: inc edx
      [-]8365f4008365080083ceff8bcad3e6c745fc????????2955fcf7d6
         // 00419aa0: and ss:[ebp+0xfffffffffffffff4], 0x0
         // 00419aa4: and ss:[ebp+0x8], 0x0
         // 00419aa8: or esi, 0xffffffffffffffff
         // 00419aab: mov ecx, edx
         // 00419aad: shl esi, b1 cl
         // 00419aaf: mov ss:[ebp+0xfffffffffffffffc], 0x20
         // 00419ab6: sub ss:[ebp+0xfffffffffffffffc], edx
         // 00419ab9: not esi
      [-]8b4d088b7c8de08bcf23ce894df08bcad3ef8b4d080b7df4897c8de08b7df08b4dfcd3e7ff4508837d0803897df47cd0
         // 00419abb: mov ecx, ss:[ebp+0x8]
         // 00419abe: mov edi, ss:[ebp+ecx*0x4]
         // 00419ac2: mov ecx, edi
         // 00419ac4: and ecx, esi
         // 00419ac6: mov ss:[ebp+0xfffffffffffffff0], ecx
         // 00419ac9: mov ecx, edx
         // 00419acb: shr edi, b1 cl
         // 00419acd: mov ecx, ss:[ebp+0x8]
         // 00419ad0: or edi, ss:[ebp+0xfffffffffffffff4]
         // 00419ad3: mov ss:[ebp+ecx*0x4], edi
         // 00419ad7: mov edi, ss:[ebp+0xfffffffffffffff0]
         // 00419ada: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 00419add: shl edi, b1 cl
         // 00419adf: inc ss:[ebp+0x8]
         // 00419ae2: cmp ss:[ebp+0x8], 0x3
         // 00419ae6: mov ss:[ebp+0xfffffffffffffff4], edi
         // 00419ae9: jl 0x419abb
      [-]8bf06a02c1e6028d4de85a2bce
         // 00419aeb: mov esi, eax
         // 00419aed: push 0x2
         // 00419aef: shl esi, b1 0x2
         // 00419af2: lea ecx, ss:[ebp+0xffffffffffffffe8]
         // 00419af5: pop edx
         // 00419af6: sub ecx, esi
      [-]3bd07c08
         // 00419af8: cmp edx, eax
         // 00419afa: jl 0x419b04
      [-]8b31897495e0eb05
         // 00419afc: mov esi, ds:[ecx]
         // 00419afe: mov ss:[ebp+edx*0x4], esi
         // 00419b02: jmp 0x419b09
      [-]836495e000
         // 00419b04: and ss:[ebp+edx*0x4], 0x0
      [-]4a83e90485d27de7
         // 00419b09: dec edx
         // 00419b0a: sub ecx, 0x4
         // 00419b0d: test edx, edx
         // 00419b0f: jge 0x419af8
      [-]6a1f592b0d
         // 004208d7: push 0x1f
         // 004208d9: pop ecx
         // 004208da: sub ecx, ds:[0x42c06c]
      [-]d3e38b4decf7d91bc981e1????????0bd98b0d
         // 004208e0: shl ebx, b1 cl
         // 004208e2: mov ecx, ss:[ebp+0xffffffffffffffec]
         // 004208e5: neg ecx
         // 004208e7: sbb ecx, ecx
         // 004208e9: and ecx, 0xffffffff80000000
         // 004208ef: or ebx, ecx
         // 004208f1: mov ecx, ds:[0x42c070]
      [-]0b5de083f940750d
         // 004208f7: or ebx, ss:[ebp+0xffffffffffffffe0]
         // 004208fa: cmp ecx, 0x40
         // 004208fd: jnz 0x42090c
      [-]8b4d0c8b55e48959048911eb0a
         // 00419b3c: mov ecx, ss:[ebp+0xc]
         // 00419b3f: mov edx, ss:[ebp+0xffffffffffffffe4]
         // 00419b42: mov ds:[ecx+0x4], ebx
         // 00419b45: mov ds:[ecx], edx
         // 00419b47: jmp 0x419b53
      [-]83f9207505
         // 00419b49: cmp ecx, 0x20
         // 00419b4c: jnz 0x419b53
      [-]8b4d0c8919
         // 00419b4e: mov ecx, ss:[ebp+0xc]
         // 00419b51: mov ds:[ecx], ebx
      [-]5f5bc9c3
         // 00419b53: pop edi
         // 00419b54: pop ebx
         // 00419b55: leave 
         // 00419b56: retn 
      [-]558bec83ec2c8b45080fb7480a538bd981e1????????894dec8b4806894de08b48020fb70081e3????????81eb????????c1e01057894de48945e8
         // 00419f21: push ebp
         // 00419f22: mov ebp, esp
         // 00419f24: sub esp, 0x2c
         // 00419f27: mov eax, ss:[ebp+0x8]
         // 00419f2a: movzx ecx, b2 ds:[eax+0xa]
         // 00419f2e: push ebx
         // 00419f2f: mov ebx, ecx
         // 00419f31: and ecx, 0x8000
         // 00419f37: mov ss:[ebp+0xffffffffffffffec], ecx
         // 00419f3a: mov ecx, ds:[eax+0x6]
         // 00419f3d: mov ss:[ebp+0xffffffffffffffe0], ecx
         // 00419f40: mov ecx, ds:[eax+0x2]
         // 00419f43: movzx eax, b2 ds:[eax]
         // 00419f46: and ebx, 0x7fff
         // 00419f4c: sub ebx, 0x3fff
         // 00419f52: shl eax, b1 0x10
         // 00419f5b: push edi
         // 00419f5c: mov ss:[ebp+0xffffffffffffffe4], ecx
         // 00419f5f: mov ss:[ebp+0xffffffffffffffe8], eax
      [-]33db33c0
         // 00419b9c: xor ebx, ebx
         // 00419b9e: xor eax, eax
      [-]395c85e0750d
         // 00419ba0: cmp ss:[ebp+eax*0x4], ebx
         // 00419ba4: jnz 0x419bb3
      [-]4083f8037cf4
         // 00419ba6: inc eax
         // 00419ba7: cmp eax, 0x3
         // 00419baa: jl 0x419ba0
      [-]33c0e9a5040000
         // 00419bac: xor eax, eax
         // 00419bae: jmp 0x41a058
      [-]33c08d7de0abab6a02ab58e995040000
         // 00419bb3: xor eax, eax
         // 00419bb5: lea edi, ss:[ebp+0xffffffffffffffe0]
         // 00419bb8: stosdd 
         // 00419bb9: stosdd 
         // 00419bba: push 0x2
         // 00419bbc: stosdd 
         // 00419bbd: pop eax
         // 00419bbe: jmp 0x41a058
      [-]83650800568d75e08d7dd4a5a5a58b35
         // 00420986: and ss:[ebp+0x8], 0x0
         // 0042098a: push esi
         // 0042098b: lea esi, ss:[ebp+0xffffffffffffffe0]
         // 0042098e: lea edi, ss:[ebp+0xffffffffffffffd4]
         // 00420991: movsdd 
         // 00420992: movsdd 
         // 00420993: movsdd 
         // 00420994: mov esi, ds:[0x42c080]
      [-]4e8d4e018bc19983e21f03c2c1f8058bd181e2????????895df08945f47905
         // 0042099a: dec esi
         // 0042099b: lea ecx, ds:[esi+0x1]
         // 0042099e: mov eax, ecx
         // 004209a0: cdq 
         // 004209a1: and edx, 0x1f
         // 004209a4: add eax, edx
         // 004209a6: sar eax, b1 0x5
         // 004209a9: mov edx, ecx
         // 004209ab: and edx, 0xffffffff8000001f
         // 004209b1: mov ss:[ebp+0xfffffffffffffff0], ebx
         // 004209b4: mov ss:[ebp+0xfffffffffffffff4], eax
         // 004209b7: jns 0x4209be
      [-]4a83cae042
         // 00419bf6: dec edx
         // 00419bf7: or edx, 0xffffffffffffffe0
         // 00419bfa: inc edx
      [-]8d7c85e06a1f33c0592bca40d3e0894df885070f848d000000
         // 00419bfb: lea edi, ss:[ebp+eax*0x4]
         // 00419bff: push 0x1f
         // 00419c01: xor eax, eax
         // 00419c03: pop ecx
         // 00419c04: sub ecx, edx
         // 00419c06: inc eax
         // 00419c07: shl eax, b1 cl
         // 00419c09: mov ss:[ebp+0xfffffffffffffff8], ecx
         // 00419c0c: test ds:[edi], eax
         // 00419c0e: jz 0x419ca1
      [-]8b45f483caffd3e2f7d2855485e0eb05
         // 00419c14: mov eax, ss:[ebp+0xfffffffffffffff4]
         // 00419c17: or edx, 0xffffffffffffffff
         // 00419c1a: shl edx, b1 cl
         // 00419c1c: not edx
         // 00419c1e: test ss:[ebp+eax*0x4], edx
         // 00419c22: jmp 0x419c29
      [-]837c85e000
         // 00419c24: cmp ss:[ebp+eax*0x4], 0x0
      [-]4083f8037cf3
         // 00419c2b: inc eax
         // 00419c2c: cmp eax, 0x3
         // 00419c2f: jl 0x419c24
      [-]8bc6996a1f5923d103c2c1f80581e6????????7905
         // 00419c33: mov eax, esi
         // 00419c35: cdq 
         // 00419c36: push 0x1f
         // 00419c38: pop ecx
         // 00419c39: and edx, ecx
         // 00419c3b: add eax, edx
         // 00419c3d: sar eax, b1 0x5
         // 00419c40: and esi, 0xffffffff8000001f
         // 00419c46: jns 0x419c4d
      [-]4e83cee046
         // 00419c48: dec esi
         // 00419c49: or esi, 0xffffffffffffffe0
         // 00419c4c: inc esi
      [-]8365fc002bce33d242d3e28d4c85e08b3103f28975088b313975087222
         // 00419c4d: and ss:[ebp+0xfffffffffffffffc], 0x0
         // 00419c51: sub ecx, esi
         // 00419c53: xor edx, edx
         // 00419c55: inc edx
         // 00419c56: shl edx, b1 cl
         // 00419c58: lea ecx, ss:[ebp+eax*0x4]
         // 00419c5c: mov esi, ds:[ecx]
         // 00419c5e: add esi, edx
         // 00419c60: mov ss:[ebp+0x8], esi
         // 00419c63: mov esi, ds:[ecx]
         // 00419c65: cmp ss:[ebp+0x8], esi
         // 00419c68: jb 0x419c8c
      [-]395508eb1b
         // 00419c6a: cmp ss:[ebp+0x8], edx
         // 00419c6d: jmp 0x419c8a
      [-]85c9742b
         // 00419c6f: test ecx, ecx
         // 00419c71: jz 0x419c9e
      [-]8365fc008d4c85e08b118d7201
         // 0041a03b: and ss:[ebp+0xfffffffffffffffc], 0x0
         // 0041a03f: lea ecx, ss:[ebp+eax*0x4]
         // 0041a043: mov edx, ds:[ecx]
         // 0041a045: lea esi, ds:[edx+0x1]
      [-]c745fc????????
         // 00419c8c: mov ss:[ebp+0xfffffffffffffffc], 0x1
      [-]488b550889118b4dfc79d1
         // 00419c93: dec eax
         // 00419c94: mov edx, ss:[ebp+0x8]
         // 00419c97: mov ds:[ecx], edx
         // 00419c99: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 00419c9c: jns 0x419c6f
      [-]8b4df883c8ffd3e021078b45f44083f8037d0d
         // 00419ca1: mov ecx, ss:[ebp+0xfffffffffffffff8]
         // 00419ca4: or eax, 0xffffffffffffffff
         // 00419ca7: shl eax, b1 cl
         // 00419ca9: and ds:[edi], eax
         // 00419cab: mov eax, ss:[ebp+0xfffffffffffffff4]
         // 00419cae: inc eax
         // 00419caf: cmp eax, 0x3
         // 00419cb2: jge 0x419cc1
      [-]6a03598d7c85e02bc833c0f3ab
         // 00419cb4: push 0x3
         // 00419cb6: pop ecx
         // 00419cb7: lea edi, ss:[ebp+eax*0x4]
         // 00419cbb: sub ecx, eax
         // 00419cbd: xor eax, eax
         // 00419cbf: rep stosdd 
      [-]837d08007401
         // 00419cc1: cmp ss:[ebp+0x8], 0x0
         // 00419cc5: jz 0x419cc8
      [-]8bc82b0d
         // 00420a90: mov ecx, eax
         // 00420a92: sub ecx, ds:[0x42c080]
      [-]3bd97d0d
         // 00420a98: cmp ebx, ecx
         // 00420a9a: jge 0x420aa9
      [-]33c08d7de0abababe90d020000
         // 00419cd9: xor eax, eax
         // 00419cdb: lea edi, ss:[ebp+0xffffffffffffffe0]
         // 00419cde: stosdd 
         // 00419cdf: stosdd 
         // 00419ce0: stosdd 
         // 00419ce1: jmp 0x419ef3
      [-]3bd80f8f0f020000
         // 00419ce6: cmp ebx, eax
         // 00419ce8: jg 0x419efd
      [-]2b45f08d75d48bc88d7de0a59983e21f03c2a58bd1c1f80581e2????????a57905
         // 00419cee: sub eax, ss:[ebp+0xfffffffffffffff0]
         // 00419cf1: lea esi, ss:[ebp+0xffffffffffffffd4]
         // 00419cf4: mov ecx, eax
         // 00419cf6: lea edi, ss:[ebp+0xffffffffffffffe0]
         // 00419cf9: movsdd 
         // 00419cfa: cdq 
         // 00419cfb: and edx, 0x1f
         // 00419cfe: add eax, edx
         // 00419d00: movsdd 
         // 00419d01: mov edx, ecx
         // 00419d03: sar eax, b1 0x5
         // 00419d06: and edx, 0xffffffff8000001f
         // 00419d0c: movsdd 
         // 00419d0d: jns 0x419d14
      [-]4a83cae042
         // 00419d0f: dec edx
         // 00419d10: or edx, 0xffffffffffffffe0
         // 00419d13: inc edx
      [-]8365f4008365080083cfff8bcad3e7c745fc????????2955fcf7d7
         // 00419d14: and ss:[ebp+0xfffffffffffffff4], 0x0
         // 00419d18: and ss:[ebp+0x8], 0x0
         // 00419d1c: or edi, 0xffffffffffffffff
         // 00419d1f: mov ecx, edx
         // 00419d21: shl edi, b1 cl
         // 00419d23: mov ss:[ebp+0xfffffffffffffffc], 0x20
         // 00419d2a: sub ss:[ebp+0xfffffffffffffffc], edx
         // 00419d2d: not edi
      [-]8b5d088d5c9de08b338bce23cf894df08bcad3ee8b4dfc0b75f489338b75f0d3e6ff4508837d08038975f47cd3
         // 00419d2f: mov ebx, ss:[ebp+0x8]
         // 00419d32: lea ebx, ss:[ebp+ebx*0x4]
         // 00419d36: mov esi, ds:[ebx]
         // 00419d38: mov ecx, esi
         // 00419d3a: and ecx, edi
         // 00419d3c: mov ss:[ebp+0xfffffffffffffff0], ecx
         // 00419d3f: mov ecx, edx
         // 00419d41: shr esi, b1 cl
         // 00419d43: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 00419d46: or esi, ss:[ebp+0xfffffffffffffff4]
         // 00419d49: mov ds:[ebx], esi
         // 00419d4b: mov esi, ss:[ebp+0xfffffffffffffff0]
         // 00419d4e: shl esi, b1 cl
         // 00419d50: inc ss:[ebp+0x8]
         // 00419d53: cmp ss:[ebp+0x8], 0x3
         // 00419d57: mov ss:[ebp+0xfffffffffffffff4], esi
         // 00419d5a: jl 0x419d2f
      [-]8bf06a02c1e6028d4de85a2bce
         // 00419d5c: mov esi, eax
         // 00419d5e: push 0x2
         // 00419d60: shl esi, b1 0x2
         // 00419d63: lea ecx, ss:[ebp+0xffffffffffffffe8]
         // 00419d66: pop edx
         // 00419d67: sub ecx, esi
      [-]3bd07c08
         // 00419d69: cmp edx, eax
         // 00419d6b: jl 0x419d75
      [-]8b31897495e0eb05
         // 00419d6d: mov esi, ds:[ecx]
         // 00419d6f: mov ss:[ebp+edx*0x4], esi
         // 00419d73: jmp 0x419d7a
      [-]836495e000
         // 00419d75: and ss:[ebp+edx*0x4], 0x0
      [-]4a83e90485d27de7
         // 00419d7a: dec edx
         // 00419d7b: sub ecx, 0x4
         // 00419d7e: test edx, edx
         // 00419d80: jge 0x419d69
      [-]4e8d4e018bc19983e21f03c2c1f8058bd181e2????????8945f47905
         // 00420b4b: dec esi
         // 00420b4c: lea ecx, ds:[esi+0x1]
         // 00420b4f: mov eax, ecx
         // 00420b51: cdq 
         // 00420b52: and edx, 0x1f
         // 00420b55: add eax, edx
         // 00420b57: sar eax, b1 0x5
         // 00420b5a: mov edx, ecx
         // 00420b5c: and edx, 0xffffffff8000001f
         // 00420b62: mov ss:[ebp+0xfffffffffffffff4], eax
         // 00420b65: jns 0x420b6c
      [-]4a83cae042
         // 00419da4: dec edx
         // 00419da5: or edx, 0xffffffffffffffe0
         // 00419da8: inc edx
      [-]6a1f592bca33d242d3e28d5c85e0894df085130f8482000000
         // 00419da9: push 0x1f
         // 00419dab: pop ecx
         // 00419dac: sub ecx, edx
         // 00419dae: xor edx, edx
         // 00419db0: inc edx
         // 00419db1: shl edx, b1 cl
         // 00419db3: lea ebx, ss:[ebp+eax*0x4]
         // 00419db7: mov ss:[ebp+0xfffffffffffffff0], ecx
         // 00419dba: test ds:[ebx], edx
         // 00419dbc: jz 0x419e44
      [-]83caffd3e2f7d2855485e0eb05
         // 00419dc2: or edx, 0xffffffffffffffff
         // 00419dc5: shl edx, b1 cl
         // 00419dc7: not edx
         // 00419dc9: test ss:[ebp+eax*0x4], edx
         // 00419dcd: jmp 0x419dd4
      [-]837c85e000
         // 00419dcf: cmp ss:[ebp+eax*0x4], 0x0
      [-]4083f8037cf3
         // 00419dd6: inc eax
         // 00419dd7: cmp eax, 0x3
         // 00419dda: jl 0x419dcf
      [-]8bc6996a1f5923d103c2c1f80581e6????????7905
         // 00419dde: mov eax, esi
         // 00419de0: cdq 
         // 00419de1: push 0x1f
         // 00419de3: pop ecx
         // 00419de4: and edx, ecx
         // 00419de6: add eax, edx
         // 00419de8: sar eax, b1 0x5
         // 00419deb: and esi, 0xffffffff8000001f
         // 00419df1: jns 0x419df8
      [-]4e83cee046
         // 00419df3: dec esi
         // 00419df4: or esi, 0xffffffffffffffe0
         // 00419df7: inc esi
      [-]8365080033d22bce42d3e28d4c85e08b318d3c163bfe7204
         // 00419df8: and ss:[ebp+0x8], 0x0
         // 00419dfc: xor edx, edx
         // 00419dfe: sub ecx, esi
         // 00419e00: inc edx
         // 00419e01: shl edx, b1 cl
         // 00419e03: lea ecx, ss:[ebp+eax*0x4]
         // 00419e07: mov esi, ds:[ecx]
         // 00419e09: lea edi, ds:[esi+edx]
         // 00419e0c: cmp edi, esi
         // 00419e0e: jb 0x419e14
      [-]3bfa7307
         // 00419e10: cmp edi, edx
         // 00419e12: jnb 0x419e1b
      [-]c74508????????
         // 00419e14: mov ss:[ebp+0x8], 0x1
      [-]89398b4d08eb1f
         // 00419e1b: mov ds:[ecx], edi
         // 00419e1d: mov ecx, ss:[ebp+0x8]
         // 00419e20: jmp 0x419e41
      [-]85c9741e
         // 00419e22: test ecx, ecx
         // 00419e24: jz 0x419e44
      [-]8d4c85e08b118d720133ff3bf27205
         // 00419e26: lea ecx, ss:[ebp+eax*0x4]
         // 00419e2a: mov edx, ds:[ecx]
         // 00419e2c: lea esi, ds:[edx+0x1]
         // 00419e2f: xor edi, edi
         // 00419e31: cmp esi, edx
         // 00419e33: jb 0x419e3a
      [-]83fe017303
         // 00419e35: cmp esi, 0x1
         // 00419e38: jnb 0x419e3d
      [-]89318bcf
         // 00419e3d: mov ds:[ecx], esi
         // 00419e3f: mov ecx, edi
      [-]8b4df083c8ffd3e021038b45f44083f8037d0d
         // 00419e44: mov ecx, ss:[ebp+0xfffffffffffffff0]
         // 00419e47: or eax, 0xffffffffffffffff
         // 00419e4a: shl eax, b1 cl
         // 00419e4c: and ds:[ebx], eax
         // 00419e4e: mov eax, ss:[ebp+0xfffffffffffffff4]
         // 00419e51: inc eax
         // 00419e52: cmp eax, 0x3
         // 00419e55: jge 0x419e64
      [-]6a03598d7c85e02bc833c0f3ab
         // 00419e57: push 0x3
         // 00419e59: pop ecx
         // 00419e5a: lea edi, ss:[ebp+eax*0x4]
         // 00419e5e: sub ecx, eax
         // 00419e60: xor eax, eax
         // 00419e62: rep stosdd 
      [-]418bc19983e21f03c28bd1c1f80581e2????????7905
         // 00420c2d: inc ecx
         // 00420c2e: mov eax, ecx
         // 00420c30: cdq 
         // 00420c31: and edx, 0x1f
         // 00420c34: add eax, edx
         // 00420c36: mov edx, ecx
         // 00420c38: sar eax, b1 0x5
         // 00420c3b: and edx, 0xffffffff8000001f
         // 00420c41: jns 0x420c48
      [-]4a83cae042
         // 00419e80: dec edx
         // 00419e81: or edx, 0xffffffffffffffe0
         // 00419e84: inc edx
      [-]8365f4008365080083cfff8bcad3e7c745fc????????2955fcf7d7
         // 00419e85: and ss:[ebp+0xfffffffffffffff4], 0x0
         // 00419e89: and ss:[ebp+0x8], 0x0
         // 00419e8d: or edi, 0xffffffffffffffff
         // 00419e90: mov ecx, edx
         // 00419e92: shl edi, b1 cl
         // 00419e94: mov ss:[ebp+0xfffffffffffffffc], 0x20
         // 00419e9b: sub ss:[ebp+0xfffffffffffffffc], edx
         // 00419e9e: not edi
      [-]8b5d088d5c9de08b338bce23cf894df08bcad3ee8b4dfc0b75f489338b75f0d3e6ff4508837d08038975f47cd3
         // 00419ea0: mov ebx, ss:[ebp+0x8]
         // 00419ea3: lea ebx, ss:[ebp+ebx*0x4]
         // 00419ea7: mov esi, ds:[ebx]
         // 00419ea9: mov ecx, esi
         // 00419eab: and ecx, edi
         // 00419ead: mov ss:[ebp+0xfffffffffffffff0], ecx
         // 00419eb0: mov ecx, edx
         // 00419eb2: shr esi, b1 cl
         // 00419eb4: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 00419eb7: or esi, ss:[ebp+0xfffffffffffffff4]
         // 00419eba: mov ds:[ebx], esi
         // 00419ebc: mov esi, ss:[ebp+0xfffffffffffffff0]
         // 00419ebf: shl esi, b1 cl
         // 00419ec1: inc ss:[ebp+0x8]
         // 00419ec4: cmp ss:[ebp+0x8], 0x3
         // 00419ec8: mov ss:[ebp+0xfffffffffffffff4], esi
         // 00419ecb: jl 0x419ea0
      [-]8bf06a02c1e6028d4de85a2bce
         // 00419ecd: mov esi, eax
         // 00419ecf: push 0x2
         // 00419ed1: shl esi, b1 0x2
         // 00419ed4: lea ecx, ss:[ebp+0xffffffffffffffe8]
         // 00419ed7: pop edx
         // 00419ed8: sub ecx, esi
      [-]3bd07c08
         // 00419eda: cmp edx, eax
         // 00419edc: jl 0x419ee6
      [-]8b31897495e0eb05
         // 00419ede: mov esi, ds:[ecx]
         // 00419ee0: mov ss:[ebp+edx*0x4], esi
         // 00419ee4: jmp 0x419eeb
      [-]836495e000
         // 00419ee6: and ss:[ebp+edx*0x4], 0x0
      [-]4a83e90485d27de7
         // 00419eeb: dec edx
         // 00419eec: sub ecx, 0x4
         // 00419eef: test edx, edx
         // 00419ef1: jge 0x419eda
      [-]6a0233db58e95a010000
         // 00419ef3: push 0x2
         // 00419ef5: xor ebx, ebx
         // 00419ef7: pop eax
         // 00419ef8: jmp 0x41a057
      [-]0f8cad000000
         // 00420ccc: jl 0x420d7f
      [-]33c08d7de0ababab814de0????????8bc19983e21f03c28bd1c1f80581e2????????7905
         // 00419f0f: xor eax, eax
         // 00419f11: lea edi, ss:[ebp+0xffffffffffffffe0]
         // 00419f14: stosdd 
         // 00419f15: stosdd 
         // 00419f16: stosdd 
         // 00419f17: or ss:[ebp+0xffffffffffffffe0], 0xffffffff80000000
         // 00419f1e: mov eax, ecx
         // 00419f20: cdq 
         // 00419f21: and edx, 0x1f
         // 00419f24: add eax, edx
         // 00419f26: mov edx, ecx
         // 00419f28: sar eax, b1 0x5
         // 00419f2b: and edx, 0xffffffff8000001f
         // 00419f31: jns 0x419f38
      [-]4a83cae042
         // 00419f33: dec edx
         // 00419f34: or edx, 0xffffffffffffffe0
         // 00419f37: inc edx
      [-]8365f4008365080083cfff8bcad3e7c745fc????????2955fcf7d7
         // 00419f38: and ss:[ebp+0xfffffffffffffff4], 0x0
         // 00419f3c: and ss:[ebp+0x8], 0x0
         // 00419f40: or edi, 0xffffffffffffffff
         // 00419f43: mov ecx, edx
         // 00419f45: shl edi, b1 cl
         // 00419f47: mov ss:[ebp+0xfffffffffffffffc], 0x20
         // 00419f4e: sub ss:[ebp+0xfffffffffffffffc], edx
         // 00419f51: not edi
      [-]8b5d088d5c9de08b338bce23cf894df08bcad3ee8b4dfc0b75f489338b75f0d3e6ff4508837d08038975f47cd3
         // 00419f53: mov ebx, ss:[ebp+0x8]
         // 00419f56: lea ebx, ss:[ebp+ebx*0x4]
         // 00419f5a: mov esi, ds:[ebx]
         // 00419f5c: mov ecx, esi
         // 00419f5e: and ecx, edi
         // 00419f60: mov ss:[ebp+0xfffffffffffffff0], ecx
         // 00419f63: mov ecx, edx
         // 00419f65: shr esi, b1 cl
         // 00419f67: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 00419f6a: or esi, ss:[ebp+0xfffffffffffffff4]
         // 00419f6d: mov ds:[ebx], esi
         // 00419f6f: mov esi, ss:[ebp+0xfffffffffffffff0]
         // 00419f72: shl esi, b1 cl
         // 00419f74: inc ss:[ebp+0x8]
         // 00419f77: cmp ss:[ebp+0x8], 0x3
         // 00419f7b: mov ss:[ebp+0xfffffffffffffff4], esi
         // 00419f7e: jl 0x419f53
      [-]8bf06a02c1e6028d4de85a2bce
         // 00419f80: mov esi, eax
         // 00419f82: push 0x2
         // 00419f84: shl esi, b1 0x2
         // 00419f87: lea ecx, ss:[ebp+0xffffffffffffffe8]
         // 00419f8a: pop edx
         // 00419f8b: sub ecx, esi
      [-]3bd07c08
         // 00419f8d: cmp edx, eax
         // 00419f8f: jl 0x419f99
      [-]8b31897495e0eb05
         // 00419f91: mov esi, ds:[ecx]
         // 00419f93: mov ss:[ebp+edx*0x4], esi
         // 00419f97: jmp 0x419f9e
      [-]836495e000
         // 00419f99: and ss:[ebp+edx*0x4], 0x0
      [-]4a83e90485d27de7
         // 00419f9e: dec edx
         // 00419f9f: sub ecx, 0x4
         // 00419fa2: test edx, edx
         // 00419fa4: jge 0x419f8d
      [-]8d1c0133c040e99b000000
         // 00420d74: lea ebx, ds:[ecx+eax]
         // 00420d77: xor eax, eax
         // 00420d79: inc eax
         // 00420d7a: jmp 0x420e1a
      [-]8165????????7f03d88bc19983e21f03c28bd1c1f80581e2????????7905
         // 00420d84: and ss:[ebp+0xffffffffffffffe0], 0x7fffffff
         // 00420d8b: add ebx, eax
         // 00420d8d: mov eax, ecx
         // 00420d8f: cdq 
         // 00420d90: and edx, 0x1f
         // 00420d93: add eax, edx
         // 00420d95: mov edx, ecx
         // 00420d97: sar eax, b1 0x5
         // 00420d9a: and edx, 0xffffffff8000001f
         // 00420da0: jns 0x420da7
      [-]4a83cae042
         // 00419fdf: dec edx
         // 00419fe0: or edx, 0xffffffffffffffe0
         // 00419fe3: inc edx
      [-]8365f4008365080083ceff8bcad3e6c745fc????????2955fcf7d6
         // 00419fe4: and ss:[ebp+0xfffffffffffffff4], 0x0
         // 00419fe8: and ss:[ebp+0x8], 0x0
         // 00419fec: or esi, 0xffffffffffffffff
         // 00419fef: mov ecx, edx
         // 00419ff1: shl esi, b1 cl
         // 00419ff3: mov ss:[ebp+0xfffffffffffffffc], 0x20
         // 00419ffa: sub ss:[ebp+0xfffffffffffffffc], edx
         // 00419ffd: not esi
      [-]8b4d088b7c8de08bcf23ce894df08bcad3ef8b4d080b7df4897c8de08b7df08b4dfcd3e7ff4508837d0803897df47cd0
         // 00419fff: mov ecx, ss:[ebp+0x8]
         // 0041a002: mov edi, ss:[ebp+ecx*0x4]
         // 0041a006: mov ecx, edi
         // 0041a008: and ecx, esi
         // 0041a00a: mov ss:[ebp+0xfffffffffffffff0], ecx
         // 0041a00d: mov ecx, edx
         // 0041a00f: shr edi, b1 cl
         // 0041a011: mov ecx, ss:[ebp+0x8]
         // 0041a014: or edi, ss:[ebp+0xfffffffffffffff4]
         // 0041a017: mov ss:[ebp+ecx*0x4], edi
         // 0041a01b: mov edi, ss:[ebp+0xfffffffffffffff0]
         // 0041a01e: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 0041a021: shl edi, b1 cl
         // 0041a023: inc ss:[ebp+0x8]
         // 0041a026: cmp ss:[ebp+0x8], 0x3
         // 0041a02a: mov ss:[ebp+0xfffffffffffffff4], edi
         // 0041a02d: jl 0x419fff
      [-]8bf06a02c1e6028d4de85a2bce
         // 0041a02f: mov esi, eax
         // 0041a031: push 0x2
         // 0041a033: shl esi, b1 0x2
         // 0041a036: lea ecx, ss:[ebp+0xffffffffffffffe8]
         // 0041a039: pop edx
         // 0041a03a: sub ecx, esi
      [-]3bd07c08
         // 0041a03c: cmp edx, eax
         // 0041a03e: jl 0x41a048
      [-]8b31897495e0eb05
         // 0041a040: mov esi, ds:[ecx]
         // 0041a042: mov ss:[ebp+edx*0x4], esi
         // 0041a046: jmp 0x41a04d
      [-]836495e000
         // 0041a048: and ss:[ebp+edx*0x4], 0x0
      [-]4a83e90485d27de7
         // 0041a04d: dec edx
         // 0041a04e: sub ecx, 0x4
         // 0041a051: test edx, edx
         // 0041a053: jge 0x41a03c
      [-]6a1f592b0d
         // 00420e1b: push 0x1f
         // 00420e1d: pop ecx
         // 00420e1e: sub ecx, ds:[0x42c084]
      [-]d3e38b4decf7d91bc981e1????????0bd98b0d
         // 00420e24: shl ebx, b1 cl
         // 00420e26: mov ecx, ss:[ebp+0xffffffffffffffec]
         // 00420e29: neg ecx
         // 00420e2b: sbb ecx, ecx
         // 00420e2d: and ecx, 0xffffffff80000000
         // 00420e33: or ebx, ecx
         // 00420e35: mov ecx, ds:[0x42c088]
      [-]0b5de083f940750d
         // 00420e3b: or ebx, ss:[ebp+0xffffffffffffffe0]
         // 00420e3e: cmp ecx, 0x40
         // 00420e41: jnz 0x420e50
      [-]8b4d0c8b55e48959048911eb0a
         // 0041a080: mov ecx, ss:[ebp+0xc]
         // 0041a083: mov edx, ss:[ebp+0xffffffffffffffe4]
         // 0041a086: mov ds:[ecx+0x4], ebx
         // 0041a089: mov ds:[ecx], edx
         // 0041a08b: jmp 0x41a097
      [-]83f9207505
         // 0041a08d: cmp ecx, 0x20
         // 0041a090: jnz 0x41a097
      [-]8b4d0c8919
         // 0041a092: mov ecx, ss:[ebp+0xc]
         // 0041a095: mov ds:[ecx], ebx
      [-]5f5bc9c3
         // 0041a097: pop edi
         // 0041a098: pop ebx
         // 0041a099: leave 
         // 0041a09a: retn 

  }
  condition:
    all of them
}
