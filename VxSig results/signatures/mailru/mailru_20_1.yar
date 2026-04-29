rule mailru_20_1 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         558bec538b5d0856578b
         // 00401910: push ebp
         // 00401911: mov ebp, esp
         // 00401913: push ebx
         // 00401914: mov ebx, ss:[ebp+0x8]
         // 00401917: push esi
         // 00401918: push edi
         // 0040191b: mov ecx, ss:[ebp+0xc]
      [-]397d100f427d103bf375
         // 0040192b: cmp ss:[ebp+0x10], edi
         // 0040192e: cmovb edi, ss:[ebp+0x10]
         // 00401932: cmp esi, ebx
         // 00401934: jnz 0x40197d
      [-]837b14107202
         // 0040199f: cmp ds:[ebx+0x14], 0x10
         // 004019a3: jb 0x4019a7
      [-]837e141072
         // 004019a7: cmp ds:[esi+0x14], 0x10
         // 004019ab: jb 0x4019d7
      [-]000083c40c
         // 00401a58: add esp, 0xc
      [-]837e1410897e1072
         // 004019eb: cmp ds:[esi+0x14], 0x10
         // 004019ef: mov ds:[esi+0x10], edi
         // 004019f2: jb 0x401a03
      [-]5f8bc65e5b5dc20c00
         // 00401a09: pop edi
         // 00401a0a: mov eax, esi
         // 00401a0c: pop esi
         // 00401a0d: pop ebx
         // 00401a0e: pop ebp
         // 00401a0f: retn b2 0xc
      [-]558bec8b450883e8007418
         // 00407490: push ebp
         // 00407491: mov ebp, esp
         // 00407493: mov eax, ss:[ebp+0x8]
         // 00407496: sub eax, 0x0
         // 00407499: jz 0x4074b3
      [-]33c05dc3
         // 004074a1: xor eax, eax
         // 004074a3: pop ebp
         // 004074a4: retn 
      [-]b8????????5dc3
         // 004074a5: mov eax, 0x8003
         // 004074aa: pop ebp
         // 004074ab: retn 
      [-]b8????????5dc3
         // 004074ac: mov eax, 0x800c
         // 004074b1: pop ebp
         // 004074b2: retn 
      [-]558bec833d
         // 004074e1: push ebp
         // 004074e2: mov ebp, esp
         // 004074e4: cmp ds:[0x41aaac], 0x0
      [-]3908740d
         // 00407725: cmp ds:[eax], ecx
         // 00407727: jz 0x407736
      [-]83c0088378040075f3
         // 00407729: add eax, 0x8
         // 0040772c: cmp ds:[eax+0x4], 0x0
         // 00407730: jnz 0x407725
      [-]33c05dc3
         // 00407732: xor eax, eax
         // 00407734: pop ebp
         // 00407735: retn 
      [-]8b40045dc3
         // 00407736: mov eax, ds:[eax+0x4]
         // 00407739: pop ebp
         // 0040773a: retn 
      [-]558bec837d0800742d
         // 004092f9: push ebp
         // 004092fa: mov ebp, esp
         // 004092fc: cmp ss:[ebp+0x8], 0x0
         // 00409300: jz 0x40932f
      [-]ff75086a00ff35
         // 00409302: push ss:[ebp+0x8]
         // 00409305: push 0x0
         // 00409307: push ds:[0x4256a8]
      [-]85c07518
         // 00409313: test eax, eax
         // 00409315: jnz 0x40932f
      [-]00008bf0ff15
         // 004090ed: mov esi, eax
         // 004090ef: call ds:[GetLastError]
      [-]00005989065e
         // 004090fb: pop ecx
         // 004090fc: mov ds:[esi], eax
         // 004090fe: pop esi
      [-]e996000000
         // 004091fc: jmp ?_Tidy@exception@std@@AAEXXZ
      [-]568bf1807e08007409
         // 004094c7: push esi
         // 004094c8: mov esi, ecx
         // 004094ca: cmp b1 ds:[esi+0x8], b1 0x0
         // 004094ce: jz 0x4094d9
      [-]83660400c64608005ec3
         // 004094d9: and ds:[esi+0x4], 0x0
         // 004094dd: mov b1 ds:[esi+0x8], b1 0x0
         // 004094e1: pop esi
         // 004094e2: retn 
      [-]6a01e85b00000059c3
         // 0040981a: push 0x1
         // 0040981c: call _flsall
         // 00409821: pop ecx
         // 00409822: retn 
      [-]558bec8b4508a3
         // 0040f6bd: push ebp
         // 0040f6be: mov ebp, esp
         // 0040f6c0: mov eax, ss:[ebp+0x8]
         // 0040f6c3: mov ds:[0x425038], eax
      [-]558bec83ec24a1
         // 0040fad8: push ebp
         // 0040fad9: mov ebp, esp
         // 0040fadb: sub esp, 0x24
         // 0040fade: mov eax, ds:[0x4231e0]
      [-]33c58945fc8b4508538b1d
         // 0040fae3: xor eax, ebp
         // 0040fae5: mov ss:[ebp+0xfffffffffffffffc], eax
         // 0040fae8: mov eax, ss:[ebp+0x8]
         // 0040faeb: push ebx
         // 0040faec: mov ebx, ds:[unter]
      [-]56578945e433f68b450c568945e0ffd38bf8897de8e8
         // 0040faf2: push esi
         // 0040faf3: push edi
         // 0040faf4: mov ss:[ebp+0xffffffffffffffe4], eax
         // 0040faf7: xor esi, esi
         // 0040faf9: mov eax, ss:[ebp+0xc]
         // 0040fafc: push esi
         // 0040fafd: mov ss:[ebp+0xffffffffffffffe0], eax
         // 0040fb00: call ebx
         // 0040fb02: mov edi, eax
         // 0040fb04: mov ss:[ebp+0xffffffffffffffe8], edi
         // 0040fb07: call ___crtIsPackagedApp
      [-]ffff8945ec3935
         // 0040fb0c: mov ss:[ebp+0xffffffffffffffec], eax
         // 0040fb0f: cmp ds:[0x425020], esi
      [-]0f85b0000000
         // 0040fb15: jnz 0x40fbcb
      [-]68????????5668
         // 0040fcd2: push 0x800
         // 0040fcd7: push esi
         // 0040fcd8: push 0x41e910
      [-]8bf885ff7526
         // 0040fce3: mov edi, eax
         // 0040fce5: test edi, edi
         // 0040fce7: jnz 0x40fd0f
      [-]83f8570f856a010000
         // 0040fb38: cmp eax, 0x57
         // 0040fb3b: jnz 0x40fcab
      [-]8bf885ff0f8453010000
         // 0040fb4e: mov edi, eax
         // 0040fb50: test edi, edi
         // 0040fb52: jz 0x40fcab
      [-]85c00f843f010000
         // 0040fd1b: test eax, eax
         // 0040fd1d: jz 0x40fe62
      [-]50ffd368
         // 0040fd23: push eax
         // 0040fd24: call ebx
         // 0040fd26: push 0x41e934
      [-]50ffd368
         // 0040fd37: push eax
         // 0040fd38: call ebx
         // 0040fd3a: push 0x41e944
      [-]50ffd368
         // 0040fd4b: push eax
         // 0040fd4c: call ebx
         // 0040fd4e: push 0x41e958
      [-]50ffd3a3
         // 0040fd5f: push eax
         // 0040fd60: call ebx
         // 0040fd62: mov ds:[0x425070], eax
      [-]85c07414
         // 0040fd67: test eax, eax
         // 0040fd69: jz 0x40fd7f
      [-]50ffd3a3
         // 0040fd77: push eax
         // 0040fd78: call ebx
         // 0040fd7a: mov ds:[0x42506c], eax
      [-]85c0741b
         // 0040fbd1: test eax, eax
         // 0040fbd3: jz 0x40fbf0
      [-]8b45e485c07407
         // 0040fd8c: mov eax, ss:[ebp+0xffffffffffffffe4]
         // 0040fd8f: test eax, eax
         // 0040fd91: jz 0x40fd9a
      [-]3975ec741d
         // 0040fd9a: cmp ss:[ebp+0xffffffffffffffec], esi
         // 0040fd9d: jz 0x40fdbc
      [-]58e9bd000000
         // 0040fda1: pop eax
         // 0040fda2: jmp 0x40fe64
      [-]3975ec7410
         // 0040fda7: cmp ss:[ebp+0xffffffffffffffec], esi
         // 0040fdaa: jz 0x40fdbc
      [-]6a03ebe5
         // 0040fc01: push 0x3
         // 0040fc03: jmp 0x40fbea
      [-]3bc7744f
         // 0040fc10: cmp eax, edi
         // 0040fc12: jz 0x40fc63
      [-]50ffd3ff35
         // 0040fc1c: push eax
         // 0040fc1d: call ebx
         // 0040fc1f: push ds:[0x425030]
      [-]8945ecffd38b4dec8945e885c9742f
         // 0040fc25: mov ss:[ebp+0xffffffffffffffec], eax
         // 0040fc28: call ebx
         // 0040fc2a: mov ecx, ss:[ebp+0xffffffffffffffec]
         // 0040fc2d: mov ss:[ebp+0xffffffffffffffe8], eax
         // 0040fc30: test ecx, ecx
         // 0040fc32: jz 0x40fc63
      [-]85c0742b
         // 0040fdeb: test eax, eax
         // 0040fded: jz 0x40fe1a
      [-]ffd185c0741a
         // 0040fdef: call ecx
         // 0040fdf1: test eax, eax
         // 0040fdf3: jz 0x40fe0f
      [-]8d4ddc516a0c8d4df0516a0150ff55e885c07406
         // 0040fdf5: lea ecx, ss:[ebp+0xffffffffffffffdc]
         // 0040fdf8: push ecx
         // 0040fdf9: push 0xc
         // 0040fdfb: lea ecx, ss:[ebp+0xfffffffffffffff0]
         // 0040fdfe: push ecx
         // 0040fdff: push 0x1
         // 0040fe01: push eax
         // 0040fe02: call ss:[ebp+0xffffffffffffffe8]
         // 0040fe05: test eax, eax
         // 0040fe07: jz 0x40fe0f
      [-]f645f801750b
         // 0040fe09: test b1 ss:[ebp+0xfffffffffffffff8], b1 0x1
         // 0040fe0d: jnz 0x40fe1a
      [-]8b7d1081cf????????eb30
         // 0040fe0f: mov edi, ss:[ebp+0x10]
         // 0040fe12: or edi, 0x200000
         // 0040fe18: jmp 0x40fe4a
      [-]3bc77424
         // 0040fc68: cmp eax, edi
         // 0040fc6a: jz 0x40fc90
      [-]50ffd385c0741d
         // 0040fe23: push eax
         // 0040fe24: call ebx
         // 0040fe26: test eax, eax
         // 0040fe28: jz 0x40fe47
      [-]ffd08bf085f67415
         // 0040fe2a: call eax
         // 0040fe2c: mov esi, eax
         // 0040fe2e: test esi, esi
         // 0040fe30: jz 0x40fe47
      [-]3bc7740c
         // 0040fc80: cmp eax, edi
         // 0040fc82: jz 0x40fc90
      [-]50ffd385c07405
         // 0040fe3b: push eax
         // 0040fe3c: call ebx
         // 0040fe3e: test eax, eax
         // 0040fe40: jz 0x40fe47
      [-]56ffd08bf0
         // 0040fe42: push esi
         // 0040fe43: call eax
         // 0040fe45: mov esi, eax
      [-]ffd385c0740c
         // 0040fc99: call ebx
         // 0040fc9b: test eax, eax
         // 0040fc9d: jz 0x40fcab
      [-]57ff75e0ff75e456ffd0eb02
         // 0040fe56: push edi
         // 0040fe57: push ss:[ebp+0xffffffffffffffe0]
         // 0040fe5a: push ss:[ebp+0xffffffffffffffe4]
         // 0040fe5d: push esi
         // 0040fe5e: call eax
         // 0040fe60: jmp 0x40fe64
      [-]8b4dfc5f5e33cd5be8
         // 0040fcad: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 0040fcb0: pop edi
         // 0040fcb1: pop esi
         // 0040fcb2: xor ecx, ebp
         // 0040fcb4: pop ebx
         // 0040fcb5: call @__security_check_cookie@4
      [-]ffff8be55dc3
         // 0040fcba: mov esp, ebp
         // 0040fcbc: pop ebp
         // 0040fcbd: retn 
      [-]8b0685c07402
         // 00410a5f: mov eax, ds:[esi]
         // 00410a61: test eax, eax
         // 00410a63: jz 0x410a67
      [-]3bf772f1
         // 00410a6a: cmp esi, edi
         // 00410a6c: jb 0x410a5f
      [-]8b0685c07402
         // 00410a7f: mov eax, ds:[esi]
         // 00410a81: test eax, eax
         // 00410a83: jz 0x410a87
      [-]3bf772f1
         // 00410a8a: cmp esi, edi
         // 00410a8c: jb 0x410a7f
      [-]558bec83ec44a1
         // 00416b56: push ebp
         // 00416b57: mov ebp, esp
         // 00416b59: sub esp, 0x44
         // 00416b5c: mov eax, ds:[___security_cookie]
      [-]33c58945fc8b4d085356570fb7410a33db8b7d0c8bd025????????897dc08945bc81e2????????8b410681ea????????8945f08b41028945f40fb701c1e0108955e08945f881fa????????7525
         // 00416b61: xor eax, ebp
         // 00416b63: mov ss:[ebp+0xfffffffffffffffc], eax
         // 00416b66: mov ecx, ss:[ebp+0x8]
         // 00416b69: push ebx
         // 00416b6a: push esi
         // 00416b6b: push edi
         // 00416b6c: movzx eax, b2 ds:[ecx+0xa]
         // 00416b70: xor ebx, ebx
         // 00416b72: mov edi, ss:[ebp+0xc]
         // 00416b75: mov edx, eax
         // 00416b77: and eax, 0x8000
         // 00416b7c: mov ss:[ebp+0xffffffffffffffc0], edi
         // 00416b7f: mov ss:[ebp+0xffffffffffffffbc], eax
         // 00416b82: and edx, 0x7fff
         // 00416b88: mov eax, ds:[ecx+0x6]
         // 00416b8b: sub edx, 0x3fff
         // 00416b91: mov ss:[ebp+0xfffffffffffffff0], eax
         // 00416b94: mov eax, ds:[ecx+0x2]
         // 00416b97: mov ss:[ebp+0xfffffffffffffff4], eax
         // 00416b9a: movzx eax, b2 ds:[ecx]
         // 00416b9d: shl eax, b1 0x10
         // 00416ba0: mov ss:[ebp+0xffffffffffffffe0], edx
         // 00416ba3: mov ss:[ebp+0xfffffffffffffff8], eax
         // 00416ba6: cmp edx, 0xffffffffffffc001
         // 00416bac: jnz 0x416bd3
      [-]8bf38bc3
         // 00415324: mov esi, ebx
         // 00415326: mov eax, ebx
      [-]33c08d7df0ababab
         // 00415339: xor eax, eax
         // 0041533b: lea edi, ss:[ebp+0xfffffffffffffff0]
         // 0041533e: stosdd 
         // 0041533f: stosdd 
         // 00415340: stosdd 
      [-]6a025be9a6040000
         // 00415341: push 0x2
         // 00415343: pop ebx
         // 00415344: jmp 0x4157ef
      [-]8d75f08d7de48955dca5488945cc6a1f895dd4a58d48018bc199a55e23d603d0c1fa058955c481e1????????7905
         // 0041534e: lea esi, ss:[ebp+0xfffffffffffffff0]
         // 00415351: lea edi, ss:[ebp+0xffffffffffffffe4]
         // 00415354: mov ss:[ebp+0xffffffffffffffdc], edx
         // 00415357: movsdd 
         // 00415358: dec eax
         // 00415359: mov ss:[ebp+0xffffffffffffffcc], eax
         // 0041535c: push 0x1f
         // 0041535e: mov ss:[ebp+0xffffffffffffffd4], ebx
         // 00415361: movsdd 
         // 00415362: lea ecx, ds:[eax+0x1]
         // 00415365: mov eax, ecx
         // 00415367: cdq 
         // 00415368: movsdd 
         // 00415369: pop esi
         // 0041536a: and edx, esi
         // 0041536c: add edx, eax
         // 0041536e: sar edx, b1 0x5
         // 00415371: mov ss:[ebp+0xffffffffffffffc4], edx
         // 00415374: and ecx, 0xffffffff8000001f
         // 0041537a: jns 0x415381
      [-]4983c9e041
         // 0041537c: dec ecx
         // 0041537d: or ecx, 0xffffffffffffffe0
         // 00415380: inc ecx
      [-]2bf133c0408975d08bce83cfffd3e06a035e854495f00f84a4000000
         // 00415381: sub esi, ecx
         // 00415383: xor eax, eax
         // 00415385: inc eax
         // 00415386: mov ss:[ebp+0xffffffffffffffd0], esi
         // 00415389: mov ecx, esi
         // 0041538b: or edi, 0xffffffffffffffff
         // 0041538e: shl eax, b1 cl
         // 00415390: push 0x3
         // 00415392: pop esi
         // 00415393: test ss:[ebp+edx*0x4], eax
         // 00415397: jz 0x415441
      [-]8bc7d3e0f7d0854495f0eb04
         // 0041539d: mov eax, edi
         // 0041539f: shl eax, b1 cl
         // 004153a1: not eax
         // 004153a3: test ss:[ebp+edx*0x4], eax
         // 004153a7: jmp 0x4153ad
      [-]395c95f0
         // 004153a9: cmp ss:[ebp+edx*0x4], ebx
      [-]423bd67cf5
         // 004153af: inc edx
         // 004153b0: cmp edx, esi
         // 004153b2: jl 0x4153a9
      [-]e985000000
         // 004153b4: jmp 0x41543e
      [-]8b45cc996a1f5923d103d08b45ccc1fa0525????????7905
         // 004153b9: mov eax, ss:[ebp+0xffffffffffffffcc]
         // 004153bc: cdq 
         // 004153bd: push 0x1f
         // 004153bf: pop ecx
         // 004153c0: and edx, ecx
         // 004153c2: add edx, eax
         // 004153c4: mov eax, ss:[ebp+0xffffffffffffffcc]
         // 004153c7: sar edx, b1 0x5
         // 004153ca: and eax, 0xffffffff8000001f
         // 004153cf: jns 0x4153d6
      [-]4883c8e040
         // 004153d1: dec eax
         // 004153d2: or eax, 0xffffffffffffffe0
         // 004153d5: inc eax
      [-]2bc8895dd433c040d3e08945c88b4495f08b4dc803c8894dd83bc88b45d88bcb6aff5f7205
         // 004153d6: sub ecx, eax
         // 004153d8: mov ss:[ebp+0xffffffffffffffd4], ebx
         // 004153db: xor eax, eax
         // 004153dd: inc eax
         // 004153de: shl eax, b1 cl
         // 004153e0: mov ss:[ebp+0xffffffffffffffc8], eax
         // 004153e3: mov eax, ss:[ebp+edx*0x4]
         // 004153e7: mov ecx, ss:[ebp+0xffffffffffffffc8]
         // 004153ea: add ecx, eax
         // 004153ec: mov ss:[ebp+0xffffffffffffffd8], ecx
         // 004153ef: cmp ecx, eax
         // 004153f1: mov eax, ss:[ebp+0xffffffffffffffd8]
         // 004153f4: mov ecx, ebx
         // 004153f6: push 0xffffffffffffffff
         // 004153f8: pop edi
         // 004153f9: jb 0x415400
      [-]3b45c87306
         // 004153fb: cmp eax, ss:[ebp+0xffffffffffffffc8]
         // 004153fe: jnb 0x415406
      [-]33c941894dd4
         // 00415400: xor ecx, ecx
         // 00415402: inc ecx
         // 00415403: mov ss:[ebp+0xffffffffffffffd4], ecx
      [-]894495f04a782e
         // 00415406: mov ss:[ebp+edx*0x4], eax
         // 0041540a: dec edx
         // 0041540b: js 0x41543b
      [-]85c97427
         // 0041540d: test ecx, ecx
         // 0041540f: jz 0x415438
      [-]8b4495f08bcb895dd48d78013bf8897dd88bc77205
         // 00415411: mov eax, ss:[ebp+edx*0x4]
         // 00415415: mov ecx, ebx
         // 00415417: mov ss:[ebp+0xffffffffffffffd4], ebx
         // 0041541a: lea edi, ds:[eax+0x1]
         // 0041541d: cmp edi, eax
         // 0041541f: mov ss:[ebp+0xffffffffffffffd8], edi
         // 00415422: mov eax, edi
         // 00415424: jb 0x41542b
      [-]83f8017306
         // 00415426: cmp eax, 0x1
         // 00415429: jnb 0x415431
      [-]33c941894dd4
         // 0041542b: xor ecx, ecx
         // 0041542d: inc ecx
         // 0041542e: mov ss:[ebp+0xffffffffffffffd4], ecx
      [-]894495f04a79d5
         // 00415431: mov ss:[ebp+edx*0x4], eax
         // 00415435: dec edx
         // 00415436: jns 0x41540d
      [-]8bc7d3e0214495f08d42013bc67d11
         // 00415441: mov eax, edi
         // 00415443: shl eax, b1 cl
         // 00415445: and ss:[ebp+edx*0x4], eax
         // 00415449: lea eax, ds:[edx+0x1]
         // 0041544c: cmp eax, esi
         // 0041544e: jge 0x415461
      [-]8d7df08bce8d3c872bc833c0f3ab83cfff
         // 00415450: lea edi, ss:[ebp+0xfffffffffffffff0]
         // 00415453: mov ecx, esi
         // 00415455: lea edi, ds:[edi+eax*0x4]
         // 00415458: sub ecx, eax
         // 0041545a: xor eax, eax
         // 0041545c: rep stosdd 
         // 0041545e: or edi, 0xffffffffffffffff
      [-]8b4de0395dd47401
         // 00415461: mov ecx, ss:[ebp+0xffffffffffffffe0]
         // 00415464: cmp ss:[ebp+0xffffffffffffffd4], ebx
         // 00415467: jz 0x41546a
      [-]8bc22b05??
         // 00415470: mov eax, edx
         // 00415472: sub eax, ds:[0x424334]
      [-]3bc87d0f
         // 00415478: cmp ecx, eax
         // 0041547a: jge 0x41548b
      [-]33c08d7df0ababab
         // 0041547c: xor eax, eax
         // 0041547e: lea edi, ss:[ebp+0xfffffffffffffff0]
         // 00415481: stosdd 
         // 00415482: stosdd 
         // 00415483: stosdd 
      [-]8bf3e9b6feffff
         // 00415484: mov esi, ebx
         // 00415486: jmp 0x415341
      [-]3bca0f8f19020000
         // 0041548b: cmp ecx, edx
         // 0041548d: jg 0x4156ac
      [-]2b55dc8d75e48955d08d7df08bc2a59983e21f03c2c1f805a58945c48b45d0a525????????7905
         // 00415493: sub edx, ss:[ebp+0xffffffffffffffdc]
         // 00415496: lea esi, ss:[ebp+0xffffffffffffffe4]
         // 00415499: mov ss:[ebp+0xffffffffffffffd0], edx
         // 0041549c: lea edi, ss:[ebp+0xfffffffffffffff0]
         // 0041549f: mov eax, edx
         // 004154a1: movsdd 
         // 004154a2: cdq 
         // 004154a3: and edx, 0x1f
         // 004154a6: add eax, edx
         // 004154a8: sar eax, b1 0x5
         // 004154ab: movsdd 
         // 004154ac: mov ss:[ebp+0xffffffffffffffc4], eax
         // 004154af: mov eax, ss:[ebp+0xffffffffffffffd0]
         // 004154b2: movsdd 
         // 004154b3: and eax, 0xffffffff8000001f
         // 004154b8: jns 0x4154bf
      [-]4883c8e040
         // 004154ba: dec eax
         // 004154bb: or eax, 0xffffffffffffffe0
         // 004154be: inc eax
      [-]8945d083cfff8bc7895de08b7dd08bcfd3e0f7d06a208945d8582bc76a038945c85e
         // 004154bf: mov ss:[ebp+0xffffffffffffffd0], eax
         // 004154c2: or edi, 0xffffffffffffffff
         // 004154c5: mov eax, edi
         // 004154c7: mov ss:[ebp+0xffffffffffffffe0], ebx
         // 004154ca: mov edi, ss:[ebp+0xffffffffffffffd0]
         // 004154cd: mov ecx, edi
         // 004154cf: shl eax, b1 cl
         // 004154d1: not eax
         // 004154d3: push 0x20
         // 004154d5: mov ss:[ebp+0xffffffffffffffd8], eax
         // 004154d8: pop eax
         // 004154d9: sub eax, edi
         // 004154db: push 0x3
         // 004154dd: mov ss:[ebp+0xffffffffffffffc8], eax
         // 004154e0: pop esi
      [-]8b549df08bcf8bc2d3ea0b55e02345d88b4dc8d3e089549df0438945e03bde7cdf
         // 004154e1: mov edx, ss:[ebp+ebx*0x4]
         // 004154e5: mov ecx, edi
         // 004154e7: mov eax, edx
         // 004154e9: shr edx, b1 cl
         // 004154eb: or edx, ss:[ebp+0xffffffffffffffe0]
         // 004154ee: and eax, ss:[ebp+0xffffffffffffffd8]
         // 004154f1: mov ecx, ss:[ebp+0xffffffffffffffc8]
         // 004154f4: shl eax, b1 cl
         // 004154f6: mov ss:[ebp+ebx*0x4], edx
         // 004154fa: inc ebx
         // 004154fb: mov ss:[ebp+0xffffffffffffffe0], eax
         // 004154fe: cmp ebx, esi
         // 00415500: jl 0x4154e1
      [-]8b45c48d55f8c1e00233db6a022bd083cfff8b45c459
         // 00415502: mov eax, ss:[ebp+0xffffffffffffffc4]
         // 00415505: lea edx, ss:[ebp+0xfffffffffffffff8]
         // 00415508: shl eax, b1 0x2
         // 0041550b: xor ebx, ebx
         // 0041550d: push 0x2
         // 0041550f: sub edx, eax
         // 00415511: or edi, 0xffffffffffffffff
         // 00415514: mov eax, ss:[ebp+0xffffffffffffffc4]
         // 00415517: pop ecx
      [-]3bc87c0b
         // 00415518: cmp ecx, eax
         // 0041551a: jl 0x415527
      [-]8b0289448df08b45c4eb04
         // 0041551c: mov eax, ds:[edx]
         // 0041551e: mov ss:[ebp+ecx*0x4], eax
         // 00415522: mov eax, ss:[ebp+0xffffffffffffffc4]
         // 00415525: jmp 0x41552b
      [-]895c8df0
         // 00415527: mov ss:[ebp+ecx*0x4], ebx
      [-]83ea044979e7
         // 0041552b: sub edx, 0x4
         // 0041552e: dec ecx
         // 0041552f: jns 0x415518
      [-]8b4dcc418bc19983e21f03d0c1fa058955d481e1????????7905
         // 00415531: mov ecx, ss:[ebp+0xffffffffffffffcc]
         // 00415534: inc ecx
         // 00415535: mov eax, ecx
         // 00415537: cdq 
         // 00415538: and edx, 0x1f
         // 0041553b: add edx, eax
         // 0041553d: sar edx, b1 0x5
         // 00415540: mov ss:[ebp+0xffffffffffffffd4], edx
         // 00415543: and ecx, 0xffffffff8000001f
         // 00415549: jns 0x415550
      [-]4983c9e041
         // 0041554b: dec ecx
         // 0041554c: or ecx, 0xffffffffffffffe0
         // 0041554f: inc ecx
      [-]6a1f582bc18945d033c08b4dd040d3e0854495f00f8492000000
         // 00415550: push 0x1f
         // 00415552: pop eax
         // 00415553: sub eax, ecx
         // 00415555: mov ss:[ebp+0xffffffffffffffd0], eax
         // 00415558: xor eax, eax
         // 0041555a: mov ecx, ss:[ebp+0xffffffffffffffd0]
         // 0041555d: inc eax
         // 0041555e: shl eax, b1 cl
         // 00415560: test ss:[ebp+edx*0x4], eax
         // 00415564: jz 0x4155fc
      [-]8bc7d3e0f7d0854495f0eb04
         // 0041556a: mov eax, edi
         // 0041556c: shl eax, b1 cl
         // 0041556e: not eax
         // 00415570: test ss:[ebp+edx*0x4], eax
         // 00415574: jmp 0x41557a
      [-]395c95f0
         // 00415576: cmp ss:[ebp+edx*0x4], ebx
      [-]423bd67cf5
         // 0041557c: inc edx
         // 0041557d: cmp edx, esi
         // 0041557f: jl 0x415576
      [-]8b7dcc8bc76a1f995923d103d0c1fa0581e7????????7905
         // 00415583: mov edi, ss:[ebp+0xffffffffffffffcc]
         // 00415586: mov eax, edi
         // 00415588: push 0x1f
         // 0041558a: cdq 
         // 0041558b: pop ecx
         // 0041558c: and edx, ecx
         // 0041558e: add edx, eax
         // 00415590: sar edx, b1 0x5
         // 00415593: and edi, 0xffffffff8000001f
         // 00415599: jns 0x4155a0
      [-]4f83cfe047
         // 0041559b: dec edi
         // 0041559c: or edi, 0xffffffffffffffe0
         // 0041559f: inc edi
      [-]8b4495f02bcf33ff47d3e78bcb897ddc03f8897de03bf88b45e06aff5f7205
         // 004155a0: mov eax, ss:[ebp+edx*0x4]
         // 004155a4: sub ecx, edi
         // 004155a6: xor edi, edi
         // 004155a8: inc edi
         // 004155a9: shl edi, b1 cl
         // 004155ab: mov ecx, ebx
         // 004155ad: mov ss:[ebp+0xffffffffffffffdc], edi
         // 004155b0: add edi, eax
         // 004155b2: mov ss:[ebp+0xffffffffffffffe0], edi
         // 004155b5: cmp edi, eax
         // 004155b7: mov eax, ss:[ebp+0xffffffffffffffe0]
         // 004155ba: push 0xffffffffffffffff
         // 004155bc: pop edi
         // 004155bd: jb 0x4155c4
      [-]3b45dc7303
         // 004155bf: cmp eax, ss:[ebp+0xffffffffffffffdc]
         // 004155c2: jnb 0x4155c7
      [-]894495f04a7828
         // 004155c7: mov ss:[ebp+edx*0x4], eax
         // 004155cb: dec edx
         // 004155cc: js 0x4155f6
      [-]85c97421
         // 004155ce: test ecx, ecx
         // 004155d0: jz 0x4155f3
      [-]8b4495f08bcb8d78013bf8897de08bc77205
         // 004155d2: mov eax, ss:[ebp+edx*0x4]
         // 004155d6: mov ecx, ebx
         // 004155d8: lea edi, ds:[eax+0x1]
         // 004155db: cmp edi, eax
         // 004155dd: mov ss:[ebp+0xffffffffffffffe0], edi
         // 004155e0: mov eax, edi
         // 004155e2: jb 0x4155e9
      [-]83f8017303
         // 004155e4: cmp eax, 0x1
         // 004155e7: jnb 0x4155ec
      [-]894495f04a79db
         // 004155ec: mov ss:[ebp+edx*0x4], eax
         // 004155f0: dec edx
         // 004155f1: jns 0x4155ce
      [-]8bc7d3e0214495f0423bd67d11
         // 004155fc: mov eax, edi
         // 004155fe: shl eax, b1 cl
         // 00415600: and ss:[ebp+edx*0x4], eax
         // 00415604: inc edx
         // 00415605: cmp edx, esi
         // 00415607: jge 0x41561a
      [-]8d7df08bce8d3c972bca33c0f3ab83cfff
         // 00415609: lea edi, ss:[ebp+0xfffffffffffffff0]
         // 0041560c: mov ecx, esi
         // 0041560e: lea edi, ds:[edi+edx*0x4]
         // 00415611: sub ecx, edx
         // 00415613: xor eax, eax
         // 00415615: rep stosdd 
         // 00415617: or edi, 0xffffffffffffffff
      [-]418bc19983e21f03c2c1f8058945d881e1????????7905
         // 00415620: inc ecx
         // 00415621: mov eax, ecx
         // 00415623: cdq 
         // 00415624: and edx, 0x1f
         // 00415627: add eax, edx
         // 00415629: sar eax, b1 0x5
         // 0041562c: mov ss:[ebp+0xffffffffffffffd8], eax
         // 0041562f: and ecx, 0xffffffff8000001f
         // 00415635: jns 0x41563c
      [-]4983c9e041
         // 00415637: dec ecx
         // 00415638: or ecx, 0xffffffffffffffe0
         // 0041563b: inc ecx
      [-]894ddc8bc3d3e76a20895de0f7d78b5ddc592bcb8945cc894ddc
         // 0041563c: mov ss:[ebp+0xffffffffffffffdc], ecx
         // 0041563f: mov eax, ebx
         // 00415641: shl edi, b1 cl
         // 00415643: push 0x20
         // 00415645: mov ss:[ebp+0xffffffffffffffe0], ebx
         // 00415648: not edi
         // 0041564a: mov ebx, ss:[ebp+0xffffffffffffffdc]
         // 0041564d: pop ecx
         // 0041564e: sub ecx, ebx
         // 00415650: mov ss:[ebp+0xffffffffffffffcc], eax
         // 00415653: mov ss:[ebp+0xffffffffffffffdc], ecx
      [-]8b5485f08bcb8bc2d3ea8b4dcc23c70b55e089548df08b4ddcd3e08945e08b45cc408945cc3bc67cd7
         // 00415656: mov edx, ss:[ebp+eax*0x4]
         // 0041565a: mov ecx, ebx
         // 0041565c: mov eax, edx
         // 0041565e: shr edx, b1 cl
         // 00415660: mov ecx, ss:[ebp+0xffffffffffffffcc]
         // 00415663: and eax, edi
         // 00415665: or edx, ss:[ebp+0xffffffffffffffe0]
         // 00415668: mov ss:[ebp+ecx*0x4], edx
         // 0041566c: mov ecx, ss:[ebp+0xffffffffffffffdc]
         // 0041566f: shl eax, b1 cl
         // 00415671: mov ss:[ebp+0xffffffffffffffe0], eax
         // 00415674: mov eax, ss:[ebp+0xffffffffffffffcc]
         // 00415677: inc eax
         // 00415678: mov ss:[ebp+0xffffffffffffffcc], eax
         // 0041567b: cmp eax, esi
         // 0041567d: jl 0x415656
      [-]8b75d88d55f88bc6c1e0026a022bd033db59
         // 0041567f: mov esi, ss:[ebp+0xffffffffffffffd8]
         // 00415682: lea edx, ss:[ebp+0xfffffffffffffff8]
         // 00415685: mov eax, esi
         // 00415687: shl eax, b1 0x2
         // 0041568a: push 0x2
         // 0041568c: sub edx, eax
         // 0041568e: xor ebx, ebx
         // 00415690: pop ecx
      [-]3bce7c08
         // 00415691: cmp ecx, esi
         // 00415693: jl 0x41569d
      [-]8b0289448df0eb04
         // 00415695: mov eax, ds:[edx]
         // 00415697: mov ss:[ebp+ecx*0x4], eax
         // 0041569b: jmp 0x4156a1
      [-]895c8df0
         // 0041569d: mov ss:[ebp+ecx*0x4], ebx
      [-]83ea044979ea
         // 004156a1: sub edx, 0x4
         // 004156a4: dec ecx
         // 004156a5: jns 0x415691
      [-]e9d8fdffff
         // 004156a7: jmp 0x415484
      [-]0f8ca2000000
         // 004156b2: jl 0x41575a
      [-]8d7df033c0ababab8bc1814df0????????9983e21f03c2c1f8058945cc81e1????????7905
         // 004156be: lea edi, ss:[ebp+0xfffffffffffffff0]
         // 004156c1: xor eax, eax
         // 004156c3: stosdd 
         // 004156c4: stosdd 
         // 004156c5: stosdd 
         // 004156c6: mov eax, ecx
         // 004156c8: or ss:[ebp+0xfffffffffffffff0], 0xffffffff80000000
         // 004156cf: cdq 
         // 004156d0: and edx, 0x1f
         // 004156d3: add eax, edx
         // 004156d5: sar eax, b1 0x5
         // 004156d8: mov ss:[ebp+0xffffffffffffffcc], eax
         // 004156db: and ecx, 0xffffffff8000001f
         // 004156e1: jns 0x4156e8
      [-]4983c9e041
         // 004156e3: dec ecx
         // 004156e4: or ecx, 0xffffffffffffffe0
         // 004156e7: inc ecx
      [-]83cfff894dc86a20d3e7
         // 004156e8: or edi, 0xffffffffffffffff
         // 004156eb: mov ss:[ebp+0xffffffffffffffc8], ecx
         // 004156ee: push 0x20
         // 004156f0: shl edi, b1 cl
      [-]8165????????7f03f18b0d??
         // 00415760: and ss:[ebp+0xfffffffffffffff0], 0x7fffffff
         // 00415767: add esi, ecx
         // 00415769: mov ecx, ds:[0x424338]
      [-]8bc19983e21f8975c803c2c1f8058945d881e1????????7905
         // 0041576f: mov eax, ecx
         // 00415771: cdq 
         // 00415772: and edx, 0x1f
         // 00415775: mov ss:[ebp+0xffffffffffffffc8], esi
         // 00415778: add eax, edx
         // 0041577a: sar eax, b1 0x5
         // 0041577d: mov ss:[ebp+0xffffffffffffffd8], eax
         // 00415780: and ecx, 0xffffffff8000001f
         // 00415786: jns 0x41578d
      [-]4983c9e041
         // 00415788: dec ecx
         // 00415789: or ecx, 0xffffffffffffffe0
         // 0041578c: inc ecx
      [-]6a20895de08bf3d3e78bd9582bc3894ddcf7d78945dc
         // 0041578d: push 0x20
         // 0041578f: mov ss:[ebp+0xffffffffffffffe0], ebx
         // 00415792: mov esi, ebx
         // 00415794: shl edi, b1 cl
         // 00415796: mov ebx, ecx
         // 00415798: pop eax
         // 00415799: sub eax, ebx
         // 0041579b: mov ss:[ebp+0xffffffffffffffdc], ecx
         // 0041579e: not edi
         // 004157a0: mov ss:[ebp+0xffffffffffffffdc], eax
      [-]8b54b5f08bcb8bc2d3ea0b55e023c78b4ddcd3e08954b5f0468945e083fe037cdf
         // 004157a3: mov edx, ss:[ebp+esi*0x4]
         // 004157a7: mov ecx, ebx
         // 004157a9: mov eax, edx
         // 004157ab: shr edx, b1 cl
         // 004157ad: or edx, ss:[ebp+0xffffffffffffffe0]
         // 004157b0: and eax, edi
         // 004157b2: mov ecx, ss:[ebp+0xffffffffffffffdc]
         // 004157b5: shl eax, b1 cl
         // 004157b7: mov ss:[ebp+esi*0x4], edx
         // 004157bb: inc esi
         // 004157bc: mov ss:[ebp+0xffffffffffffffe0], eax
         // 004157bf: cmp esi, 0x3
         // 004157c2: jl 0x4157a3
      [-]8b7dd88d55f88b75c88bc7c1e0026a022bd033db59
         // 004157c4: mov edi, ss:[ebp+0xffffffffffffffd8]
         // 004157c7: lea edx, ss:[ebp+0xfffffffffffffff8]
         // 004157ca: mov esi, ss:[ebp+0xffffffffffffffc8]
         // 004157cd: mov eax, edi
         // 004157cf: shl eax, b1 0x2
         // 004157d2: push 0x2
         // 004157d4: sub edx, eax
         // 004157d6: xor ebx, ebx
         // 004157d8: pop ecx
      [-]3bcf7c08
         // 004157d9: cmp ecx, edi
         // 004157db: jl 0x4157e5
      [-]8b0289448df0eb04
         // 004157dd: mov eax, ds:[edx]
         // 004157df: mov ss:[ebp+ecx*0x4], eax
         // 004157e3: jmp 0x4157e9
      [-]895c8df0
         // 004157e5: mov ss:[ebp+ecx*0x4], ebx
      [-]83ea044979ea
         // 004157e9: sub edx, 0x4
         // 004157ec: dec ecx
         // 004157ed: jns 0x4157d9
      [-]8b45f48977048907eb07
         // 0041581a: mov eax, ss:[ebp+0xfffffffffffffff4]
         // 0041581d: mov ds:[edi+0x4], esi
         // 00415820: mov ds:[edi], eax
         // 00415822: jmp 0x41582b
      [-]83f8207502
         // 00415824: cmp eax, 0x20
         // 00415827: jnz 0x41582b
      [-]8b4dfc8bc35f5e33cd5be8
         // 004155eb: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 004155ee: mov eax, ebx
         // 004155f0: pop edi
         // 004155f1: pop esi
         // 004155f2: xor ecx, ebp
         // 004155f4: pop ebx
         // 004155f5: call @__security_check_cookie@4
      [-]ffff8be55dc3
         // 004155fa: mov esp, ebp
         // 004155fc: pop ebp
         // 004155fd: retn 
      [-]64a1????????50a1
         // 00419af7: mov eax, fs:[0x0]
         // 00419afd: push eax
         // 00419afe: mov eax, ds:[___security_cookie]
      [-]33c4508d44240464a3????????a1
         // 00419b03: xor eax, esp
         // 00419b05: push eax
         // 00419b06: lea eax, ss:[esp+0x4]
         // 00419b0a: mov fs:[0x0], eax
         // 00419b10: mov eax, ds:[0x4291bc]
      [-]a8017527
         // 00419b15: test b1 al, b1 0x1
         // 00419b17: jnz 0x419b40
      [-]83c801a3
         // 00418459: or eax, 0x1
         // 0041845c: mov ds:[0x425b6c], eax
      [-]c74424????????00c705
         // 00418466: mov ss:[esp+0x10], 0x0
         // 0041846e: mov ds:[0x425b68], ??_7generic_error_category@?A0x846d1564@system@boost@@6B@
      [-]8b4424148b4c24188908c74004
         // 004181d0: mov eax, ss:[esp+0x14]
         // 004181d4: mov ecx, ss:[esp+0x18]
         // 004181d8: mov ds:[eax], ecx
         // 004181da: mov ds:[eax+0x4], 0x425b24
      [-]8b4c240464890d????????5983c40cc3
         // 004181e1: mov ecx, ss:[esp+0x4]
         // 004181e5: mov fs:[0x0], ecx
         // 004181ec: pop ecx
         // 004181ed: add esp, 0xc
         // 004181f0: retn 

  }
  condition:
    all of them
}
