rule mailru_10_3 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         64a1????????50a1
         // 00401137: mov eax, fs:[0x0]
         // 0040113d: push eax
         // 0040113e: mov eax, ds:[___security_cookie]
      [-]33c4508d44240464a3????????a1
         // 00401143: xor eax, esp
         // 00401145: push eax
         // 00401146: lea eax, ss:[esp+0x4]
         // 0040114a: mov fs:[0x0], eax
         // 00401150: mov eax, ds:[0x425b28]
      [-]a8017527
         // 00401155: test b1 al, b1 0x1
         // 00401157: jnz 0x401180
      [-]83c801a3
         // 00401159: or eax, 0x1
         // 0040115c: mov ds:[0x425b28], eax
      [-]c74424????????00c705
         // 00401166: mov ss:[esp+0x10], 0x0
         // 0040116e: mov ds:[0x425b24], 0x420170
      [-]000083c404
         // 0040117d: add esp, 0x4
      [-]8b4c240464890d????????5983c40cc3
         // 0040126a: mov ecx, ss:[esp+0x4]
         // 0040126e: mov fs:[0x0], ecx
         // 00401275: pop ecx
         // 00401276: add esp, 0xc
         // 00401279: retn 
      [-]64a1????????50a1
         // 004011a7: mov eax, fs:[0x0]
         // 004011ad: push eax
         // 004011ae: mov eax, ds:[___security_cookie]
      [-]33c4508d44240464a3????????a1
         // 004011b3: xor eax, esp
         // 004011b5: push eax
         // 004011b6: lea eax, ss:[esp+0x4]
         // 004011ba: mov fs:[0x0], eax
         // 004011c0: mov eax, ds:[0x425b20]
      [-]a8017527
         // 004011c5: test b1 al, b1 0x1
         // 004011c7: jnz 0x4011f0
      [-]83c801a3
         // 004011c9: or eax, 0x1
         // 004011cc: mov ds:[0x425b20], eax
      [-]c74424????????00c705
         // 004011d6: mov ss:[esp+0x10], 0x0
         // 004011de: mov ds:[0x425b1c], ??_7system_error_category@?A0x846d1564@system@boost@@6B@
      [-]000083c404
         // 004011ed: add esp, 0x4
      [-]8b4c240464890d????????5983c40cc3
         // 004012da: mov ecx, ss:[esp+0x4]
         // 004012de: mov fs:[0x0], ecx
         // 004012e5: pop ecx
         // 004012e6: add esp, 0xc
         // 004012e9: retn 
      [-]538b5d0856578b
         // 00401983: push ebx
         // 00401984: mov ebx, ss:[ebp+0x8]
         // 00401987: push esi
         // 00401988: push edi
         // 0040198b: mov ecx, ss:[ebp+0xc]
      [-]8b7b103b
         // 0040198e: mov edi, ds:[ebx+0x10]
         // 00401991: cmp edi, ecx
      [-]397d100f427d103bf375
         // 0040199b: cmp ss:[ebp+0x10], edi
         // 0040199e: cmovb edi, ss:[ebp+0x10]
         // 004019a2: cmp esi, ebx
         // 004019a4: jnz 0x4019ed
      [-]837b14107202
         // 00401a0f: cmp ds:[ebx+0x14], 0x10
         // 00401a13: jb 0x401a17
      [-]837e141072
         // 00401a17: cmp ds:[esi+0x14], 0x10
         // 00401a1b: jb 0x401a47
      [-]000083c40c
         // 004019e8: add esp, 0xc
      [-]837e1410897e1072
         // 00401a5b: cmp ds:[esi+0x14], 0x10
         // 00401a5f: mov ds:[esi+0x10], edi
         // 00401a62: jb 0x401a73
      [-]5f8bc65e5b5dc20c00
         // 00401a79: pop edi
         // 00401a7a: mov eax, esi
         // 00401a7c: pop esi
         // 00401a7d: pop ebx
         // 00401a7e: pop ebp
         // 00401a7f: retn b2 0xc
      [-]558bec51
         // 004021f0: push ebp
         // 004021f1: mov ebp, esp
         // 004021f3: push ecx
      [-]ffffc21000
         // 0040273e: retn b2 0x10
      [-]837d0cff7614
         // 004044a3: cmp ss:[ebp+0xc], 0xffffffffffffffff
         // 004044a7: jbe 0x4044bd
      [-]8b450833c90b4d0c99c1e00f0b
         // 004044bd: mov eax, ss:[ebp+0x8]
         // 004044c0: xor ecx, ecx
         // 004044c2: or ecx, ss:[ebp+0xc]
         // 004044c5: cdq 
         // 004044c6: shl eax, b1 0xf
         // 004044c9: or eax, ebx
      [-]0d????????89
         // 004044cd: or eax, 0x7ff80000
         // 004044d2: mov ds:[edi+0x4], eax
      [-]5dc20800
         // 004044d9: pop ebp
         // 004044da: retn b2 0x8
      [-]8b7d088bf183c707
         // 00404c15: mov edi, ss:[ebp+0x8]
         // 00404c18: mov esi, ecx
         // 00404c1a: add edi, 0x7
      [-]83e7f88b0e85c974
         // 00404c1d: and edi, 0xfffffffffffffff8
         // 00404c20: mov ecx, ds:[esi]
         // 00404c22: test ecx, ecx
         // 00404c24: jz 0x404c3f
      [-]8b41048d1438
         // 00404c26: mov eax, ds:[ecx+0x4]
         // 00404c29: lea edx, ds:[eax+edi]
      [-]03c1895104
         // 00404c35: add eax, ecx
         // 00404c37: mov ds:[ecx+0x4], edx
      [-]83c7083b
         // 00404f64: add edi, 0x8
         // 00404f67: cmp edi, ecx
      [-]8bc70f46
         // 00404f69: mov eax, edi
         // 00404f6b: cmovbe eax, ecx
      [-]8bc885c9
         // 00404f74: mov ecx, eax
         // 00404f79: test ecx, ecx
      [-]8b0685c074
         // 00404c6e: mov eax, ds:[esi]
         // 00404c70: test eax, eax
         // 00404c72: jz 0x404c85
      [-]8b0089018b068908
         // 00404218: mov eax, ds:[eax]
         // 0040421a: mov ds:[ecx], eax
         // 0040421c: mov eax, ds:[esi]
         // 0040421e: mov ds:[eax], ecx
      [-]8b068901890e
         // 00404222: mov eax, ds:[esi]
         // 00404224: mov ds:[ecx], eax
         // 00404226: mov ds:[esi], ecx
      [-]558bec8a45083c2c7420
         // 00404cd0: push ebp
         // 00404cd1: mov ebp, esp
         // 00404cd3: mov b1 al, b1 ss:[ebp+0x8]
         // 00404cd6: cmp b1 al, b1 0x2c
         // 00404cd8: jz 0x404cfa
      [-]3c3a741c
         // 00404cda: cmp b1 al, b1 0x3a
         // 00404cdc: jz 0x404cfa
      [-]3c5d7418
         // 00404cde: cmp b1 al, b1 0x5d
         // 00404ce0: jz 0x404cfa
      [-]3c7d7414
         // 00404ce2: cmp b1 al, b1 0x7d
         // 00404ce4: jz 0x404cfa
      [-]3c207410
         // 00404ce6: cmp b1 al, b1 0x20
         // 00404ce8: jz 0x404cfa
      [-]3c097c04
         // 00404cea: cmp b1 al, b1 0x9
         // 00404cec: jl 0x404cf2
      [-]3c0d7e08
         // 00404cee: cmp b1 al, b1 0xd
         // 00404cf0: jle 0x404cfa
      [-]84c07404
         // 00404cf2: test b1 al, b1 al
         // 00404cf4: jz 0x404cfa
      [-]558bec8b45088378141072
         // 00406a10: push ebp
         // 00406a11: mov ebp, esp
         // 00406a13: mov eax, ss:[ebp+0x8]
         // 00406a16: cmp ds:[eax+0x14], 0x10
         // 00406a1a: jb 0x406a2c
      [-]558bec568b750c2b750857568bf9e8
         // 00406f00: push ebp
         // 00406f01: mov ebp, esp
         // 00406f03: push esi
         // 00406f04: mov esi, ss:[ebp+0xc]
         // 00406f07: sub esi, ss:[ebp+0x8]
         // 00406f0a: push edi
         // 00406f0b: push esi
         // 00406f0c: mov edi, ecx
         // 00406f0e: call 0x406d90
      [-]ffff84c07413
         // 00406f13: test b1 al, b1 al
         // 00406f15: jz 0x406f2a
      [-]56ff7508ff37e8
         // 00406f17: push esi
         // 00406f18: push ss:[ebp+0x8]
         // 00406f1b: push ds:[edi]
         // 00406f1d: call _memmove
      [-]000083c40c03c6894704
         // 00406f22: add esp, 0xc
         // 00406f25: add eax, esi
         // 00406f27: mov ds:[edi+0x4], eax
      [-]5f5e5dc20c00
         // 00406f2a: pop edi
         // 00406f2b: pop esi
         // 00406f2c: pop ebp
         // 00406f2d: retn b2 0xc
      [-]558bec6a00ff7508ff15
         // 004054ef: push ebp
         // 004054f0: mov ebp, esp
         // 004054f2: push 0x0
         // 004054f4: push ss:[ebp+0x8]
         // 004054f7: call ds:[CryptReleaseContext]
      [-]8b0985c97411
         // 00407210: mov ecx, ds:[ecx]
         // 00407212: test ecx, ecx
         // 00407214: jz 0x407227
      [-]8b01ff500885c07408
         // 00407216: mov eax, ds:[ecx]
         // 00407218: call ds:[eax+0x8]
         // 0040721b: test eax, eax
         // 0040721d: jz 0x407227
      [-]8b108bc86a01ff12
         // 0040721f: mov edx, ds:[eax]
         // 00407221: mov ecx, eax
         // 00407223: push 0x1
         // 00407225: call ds:[edx]
      [-]558bec8b450883e8007418
         // 00407260: push ebp
         // 00407261: mov ebp, esp
         // 00407263: mov eax, ss:[ebp+0x8]
         // 00407266: sub eax, 0x0
         // 00407269: jz 0x407283
      [-]33c05dc3
         // 00407271: xor eax, eax
         // 00407273: pop ebp
         // 00407274: retn 
      [-]b8????????5dc3
         // 00407275: mov eax, 0x8003
         // 0040727a: pop ebp
         // 0040727b: retn 
      [-]b8????????5dc3
         // 0040727c: mov eax, 0x800c
         // 00407281: pop ebp
         // 00407282: retn 
      [-]b8????????5dc3
         // 00407283: mov eax, 0x8004
         // 00407288: pop ebp
         // 00407289: retn 
      [-]558bec833d
         // 004074b7: push ebp
         // 004074b8: mov ebp, esp
         // 004074ba: cmp ds:[0x41ad04], 0x0
      [-]3908740d
         // 004074f5: cmp ds:[eax], ecx
         // 004074f7: jz 0x407506
      [-]83c0088378040075f3
         // 004074f9: add eax, 0x8
         // 004074fc: cmp ds:[eax+0x4], 0x0
         // 00407500: jnz 0x4074f5
      [-]33c05dc3
         // 00407502: xor eax, eax
         // 00407504: pop ebp
         // 00407505: retn 
      [-]8b40045dc3
         // 00407506: mov eax, ds:[eax+0x4]
         // 00407509: pop ebp
         // 0040750a: retn 
      [-]8b068bcea3
         // 004077b2: mov eax, ds:[esi]
         // 004077b4: mov ecx, esi
         // 004077b6: mov ds:[0x424a24], eax
      [-]e8daffffff56e8
         // 004077bb: call ??1_Fac_node@std@@QAE@XZ
         // 004077c0: push esi
         // 004077c1: call j__free
      [-]00000059
         // 004077c6: pop ecx
      [-]85f675e1
         // 004083b2: test esi, esi
         // 004083b4: jnz 0x408397
      [-]4150890d??
         // 004075d1: inc ecx
         // 004075d2: push eax
         // 004075d3: mov ds:[0x423028], ecx
      [-]85c07402
         // 004075df: test eax, eax
         // 004075e1: jz 0x4075e5
      [-]83f90a72da
         // 004075eb: cmp ecx, 0xa
         // 004075ee: jb 0x4075ca
      [-]000059c3
         // 004088b0: pop ecx
         // 004088b1: retn 
      [-]558bec837d0800742d
         // 004090c9: push ebp
         // 004090ca: mov ebp, esp
         // 004090cc: cmp ss:[ebp+0x8], 0x0
         // 004090d0: jz 0x4090ff
      [-]ff75086a00ff35
         // 00409302: push ss:[ebp+0x8]
         // 00409305: push 0x0
         // 00409307: push ds:[0x4256a8]
      [-]410085c07518
         // 00409313: test eax, eax
         // 00409315: jnz 0x40932f
      [-]00008bf0ff15
         // 0040931d: mov esi, eax
         // 0040931f: call ds:[GetLastError]
      [-]e996000000
         // 0040942c: jmp ?_Tidy@exception@std@@AAEXXZ
      [-]568bf1807e08007409
         // 00409297: push esi
         // 00409298: mov esi, ecx
         // 0040929a: cmp b1 ds:[esi+0x8], b1 0x0
         // 0040929e: jz 0x4092a9
      [-]ff7604e8
         // 004092a0: push ds:[esi+0x4]
         // 004092a3: call _free
      [-]6a01e85b00000059c3
         // 004095ea: push 0x1
         // 004095ec: call _flsall
         // 004095f1: pop ecx
         // 004095f2: retn 
      [-]558becff7508ff15
         // 0040c348: push ebp
         // 0040c349: mov ebp, esp
         // 0040c34b: push ss:[ebp+0x8]
         // 0040c34e: call ds:[Sleep]
      [-]41005dc3
         // 0040c354: pop ebp
         // 0040c355: retn 
      [-]558bec8b4508a3
         // 0040c8aa: push ebp
         // 0040c8ab: mov ebp, esp
         // 0040c8ad: mov eax, ss:[ebp+0x8]
         // 0040c8b0: mov ds:[0x424cd4], eax
      [-]558bec8b4508a3
         // 0040e6b6: push ebp
         // 0040e6b7: mov ebp, esp
         // 0040e6b9: mov eax, ss:[ebp+0x8]
         // 0040e6bc: mov ds:[0x425044], eax
      [-]558bec8b4508a3
         // 0040f874: push ebp
         // 0040f875: mov ebp, esp
         // 0040f877: mov eax, ss:[ebp+0x8]
         // 0040f87a: mov ds:[0x425078], eax
      [-]558bec83ec24a1
         // 0040fc8f: push ebp
         // 0040fc90: mov ebp, esp
         // 0040fc92: sub esp, 0x24
         // 0040fc95: mov eax, ds:[___security_cookie]
      [-]33c58945fc8b4508538b1d
         // 0040fc9a: xor eax, ebp
         // 0040fc9c: mov ss:[ebp+0xfffffffffffffffc], eax
         // 0040fc9f: mov eax, ss:[ebp+0x8]
         // 0040fca2: push ebx
         // 0040fca3: mov ebx, ds:[EncodePointer]
      [-]410056578945e433f68b450c568945e0ffd38bf8897de8e8
         // 0040fca9: push esi
         // 0040fcaa: push edi
         // 0040fcab: mov ss:[ebp+0xffffffffffffffe4], eax
         // 0040fcae: xor esi, esi
         // 0040fcb0: mov eax, ss:[ebp+0xc]
         // 0040fcb3: push esi
         // 0040fcb4: mov ss:[ebp+0xffffffffffffffe0], eax
         // 0040fcb7: call ebx
         // 0040fcb9: mov edi, eax
         // 0040fcbb: mov ss:[ebp+0xffffffffffffffe8], edi
         // 0040fcbe: call 0x40c06f
      [-]8b0685c07402
         // 004108a8: mov eax, ds:[esi]
         // 004108aa: test eax, eax
         // 004108ac: jz 0x4108b0
      [-]3bf772f1
         // 004108b3: cmp esi, edi
         // 004108b5: jb 0x4108a8
      [-]8b0685c07402
         // 004108c8: mov eax, ds:[esi]
         // 004108ca: test eax, eax
         // 004108cc: jz 0x4108d0
      [-]3bf772f1
         // 004108d3: cmp esi, edi
         // 004108d5: jb 0x4108c8
      [-]558bec8b4508a3
         // 004126ac: push ebp
         // 004126ad: mov ebp, esp
         // 004126af: mov eax, ss:[ebp+0x8]
         // 004126b2: mov ds:[0x425a9c], eax
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
         // 004150e4: mov esi, ebx
         // 004150e6: mov eax, ebx
      [-]395c85f0750b
         // 004150e8: cmp ss:[ebp+eax*0x4], ebx
         // 004150ec: jnz 0x4150f9
      [-]4083f8037cf4
         // 004150ee: inc eax
         // 004150ef: cmp eax, 0x3
         // 004150f2: jl 0x4150e8
      [-]e9b9040000
         // 004150f4: jmp 0x4155b2
      [-]33c08d7df0ab
         // 004150f9: xor eax, eax
         // 004150fb: lea edi, ss:[ebp+0xfffffffffffffff0]
         // 004150fe: stosdd 
      [-]6a025be9a6040000
         // 00415101: push 0x2
         // 00415103: pop ebx
         // 00415104: jmp 0x4155af
      [-]8d75f08d7de48955dca5488945cc6a1f895dd4a58d48018bc199a55e23d603d0c1fa058955c481e1????????7905
         // 0041510e: lea esi, ss:[ebp+0xfffffffffffffff0]
         // 00415111: lea edi, ss:[ebp+0xffffffffffffffe4]
         // 00415114: mov ss:[ebp+0xffffffffffffffdc], edx
         // 00415117: movsdd 
         // 00415118: dec eax
         // 00415119: mov ss:[ebp+0xffffffffffffffcc], eax
         // 0041511c: push 0x1f
         // 0041511e: mov ss:[ebp+0xffffffffffffffd4], ebx
         // 00415121: movsdd 
         // 00415122: lea ecx, ds:[eax+0x1]
         // 00415125: mov eax, ecx
         // 00415127: cdq 
         // 00415128: movsdd 
         // 00415129: pop esi
         // 0041512a: and edx, esi
         // 0041512c: add edx, eax
         // 0041512e: sar edx, b1 0x5
         // 00415131: mov ss:[ebp+0xffffffffffffffc4], edx
         // 00415134: and ecx, 0xffffffff8000001f
         // 0041513a: jns 0x415141
      [-]4983c9e041
         // 0041513c: dec ecx
         // 0041513d: or ecx, 0xffffffffffffffe0
         // 00415140: inc ecx
      [-]2bf133c0
         // 00416c0b: sub esi, ecx
         // 00416c0d: xor eax, eax
      [-]8975d08bce83cfffd3e0
         // 00416c10: mov ss:[ebp+0xffffffffffffffd0], esi
         // 00416c13: mov ecx, esi
         // 00416c15: or edi, 0xffffffffffffffff
         // 00416c18: shl eax, b1 cl
      [-]0f84a4000000
         // 00416c21: jz 0x416ccb
      [-]423bd67cf5
         // 0041516f: inc edx
         // 00415170: cmp edx, esi
         // 00415172: jl 0x415169
      [-]8b45cc996a1f5923d103d08b45ccc1fa0525????????7905
         // 00415179: mov eax, ss:[ebp+0xffffffffffffffcc]
         // 0041517c: cdq 
         // 0041517d: push 0x1f
         // 0041517f: pop ecx
         // 00415180: and edx, ecx
         // 00415182: add edx, eax
         // 00415184: mov eax, ss:[ebp+0xffffffffffffffcc]
         // 00415187: sar edx, b1 0x5
         // 0041518a: and eax, 0xffffffff8000001f
         // 0041518f: jns 0x415196
      [-]4883c8e040
         // 00415191: dec eax
         // 00415192: or eax, 0xffffffffffffffe0
         // 00415195: inc eax
      [-]33c040d3e08945c88b4495f0
         // 00416c65: xor eax, eax
         // 00416c67: inc eax
         // 00416c68: shl eax, b1 cl
         // 00416c6a: mov ss:[ebp+0xffffffffffffffc8], eax
         // 00416c6d: mov eax, ss:[ebp+edx*0x4]
      [-]8b45d88bcb
         // 00416c7b: mov eax, ss:[ebp+0xffffffffffffffd8]
         // 00416c7e: mov ecx, ebx
      [-]3b45c87306
         // 004151bb: cmp eax, ss:[ebp+0xffffffffffffffc8]
         // 004151be: jnb 0x4151c6
      [-]33c941894dd4
         // 004151c0: xor ecx, ecx
         // 004151c2: inc ecx
         // 004151c3: mov ss:[ebp+0xffffffffffffffd4], ecx
      [-]894495f04a782e
         // 004151c6: mov ss:[ebp+edx*0x4], eax
         // 004151ca: dec edx
         // 004151cb: js 0x4151fb
      [-]85c97427
         // 004151cd: test ecx, ecx
         // 004151cf: jz 0x4151f8
      [-]8b4495f0
         // 00416c9b: mov eax, ss:[ebp+edx*0x4]
      [-]8bc77205
         // 00416cac: mov eax, edi
         // 00416cae: jb 0x416cb5
      [-]83f8017306
         // 004151e6: cmp eax, 0x1
         // 004151e9: jnb 0x4151f1
      [-]33c941894dd4
         // 004151eb: xor ecx, ecx
         // 004151ed: inc ecx
         // 004151ee: mov ss:[ebp+0xffffffffffffffd4], ecx
      [-]894495f04a79d5
         // 004151f1: mov ss:[ebp+edx*0x4], eax
         // 004151f5: dec edx
         // 004151f6: jns 0x4151cd
      [-]2bc833c0f3ab83cfff
         // 00415458: sub ecx, eax
         // 0041545a: xor eax, eax
         // 0041545c: rep stosdd 
         // 0041545e: or edi, 0xffffffffffffffff
      [-]8bc22b05??
         // 00415230: mov eax, edx
         // 00415232: sub eax, ds:[0x424334]
      [-]3bc87d0f
         // 00415238: cmp ecx, eax
         // 0041523a: jge 0x41524b
      [-]33c08d7df0ababab
         // 0041523c: xor eax, eax
         // 0041523e: lea edi, ss:[ebp+0xfffffffffffffff0]
         // 00415241: stosdd 
         // 00415242: stosdd 
         // 00415243: stosdd 
      [-]e9b6feffff
         // 00415246: jmp 0x415101
      [-]3bca0f8f19020000
         // 0041524b: cmp ecx, edx
         // 0041524d: jg 0x41546c
      [-]83e21f03c2c1f805
         // 004154a3: and edx, 0x1f
         // 004154a6: add eax, edx
         // 004154a8: sar eax, b1 0x5
      [-]25????????7905
         // 004154b3: and eax, 0xffffffff8000001f
         // 004154b8: jns 0x4154bf
      [-]4883c8e040
         // 0041527a: dec eax
         // 0041527b: or eax, 0xffffffffffffffe0
         // 0041527e: inc eax
      [-]83cfff8bc7
         // 00416d4c: or edi, 0xffffffffffffffff
         // 00416d4f: mov eax, edi
      [-]8b7dd08bcfd3e0f7d0
         // 00416d54: mov edi, ss:[ebp+0xffffffffffffffd0]
         // 00416d57: mov ecx, edi
         // 00416d59: shl eax, b1 cl
         // 00416d5b: not eax
      [-]8945d8582bc76a038945c85e
         // 00416d5f: mov ss:[ebp+0xffffffffffffffd8], eax
         // 00416d62: pop eax
         // 00416d63: sub eax, edi
         // 00416d65: push 0x3
         // 00416d67: mov ss:[ebp+0xffffffffffffffc8], eax
         // 00416d6a: pop esi
      [-]8b549df08bcf8bc2d3ea0b55e0
         // 004154e1: mov edx, ss:[ebp+ebx*0x4]
         // 004154e5: mov ecx, edi
         // 004154e7: mov eax, edx
         // 004154e9: shr edx, b1 cl
         // 004154eb: or edx, ss:[ebp+0xffffffffffffffe0]
      [-]e089549df0
         // 004154f6: mov ss:[ebp+0xffffffffffffffe0], eax
         // 004154f9: mov ss:[ebp+ebx*0x4], edx
      [-]3bde7cdf
         // 004154fe: cmp ebx, esi
         // 00415500: jl 0x4154e1
      [-]8b45c48d55f8
         // 00416d8c: mov eax, ss:[ebp+0xffffffffffffffc4]
         // 00416d8f: lea edx, ss:[ebp+0xfffffffffffffff8]
      [-]2bd083cfff8b45c4
         // 00416d99: sub edx, eax
         // 00416d9b: or edi, 0xffffffffffffffff
         // 00416d9e: mov eax, ss:[ebp+0xffffffffffffffc4]
      [-]3bc87c0b
         // 004152d8: cmp ecx, eax
         // 004152da: jl 0x4152e7
      [-]83ea044979e7
         // 004152eb: sub edx, 0x4
         // 004152ee: dec ecx
         // 004152ef: jns 0x4152d8
      [-]8b4dcc418bc19983e21f03d0c1fa058955d481e1????????7905
         // 004152f1: mov ecx, ss:[ebp+0xffffffffffffffcc]
         // 004152f4: inc ecx
         // 004152f5: mov eax, ecx
         // 004152f7: cdq 
         // 004152f8: and edx, 0x1f
         // 004152fb: add edx, eax
         // 004152fd: sar edx, b1 0x5
         // 00415300: mov ss:[ebp+0xffffffffffffffd4], edx
         // 00415303: and ecx, 0xffffffff8000001f
         // 00415309: jns 0x415310
      [-]4983c9e041
         // 0041530b: dec ecx
         // 0041530c: or ecx, 0xffffffffffffffe0
         // 0041530f: inc ecx
      [-]6a1f582bc18945d033c08b4dd040d3e0
         // 00416dda: push 0x1f
         // 00416ddc: pop eax
         // 00416ddd: sub eax, ecx
         // 00416ddf: mov ss:[ebp+0xffffffffffffffd0], eax
         // 00416de2: xor eax, eax
         // 00416de4: mov ecx, ss:[ebp+0xffffffffffffffd0]
         // 00416de7: inc eax
         // 00416de8: shl eax, b1 cl
      [-]0f8492000000
         // 00416dee: jz 0x416e86
      [-]854495f0eb04
         // 00415330: test ss:[ebp+edx*0x4], eax
         // 00415334: jmp 0x41533a
      [-]423bd67cf5
         // 0041533c: inc edx
         // 0041533d: cmp edx, esi
         // 0041533f: jl 0x415336
      [-]8b7dcc8bc7
         // 00416e0d: mov edi, ss:[ebp+0xffffffffffffffcc]
         // 00416e10: mov eax, edi
      [-]23d103d0c1fa0581e7????????7905
         // 00416e16: and edx, ecx
         // 00416e18: add edx, eax
         // 00416e1a: sar edx, b1 0x5
         // 00416e1d: and edi, 0xffffffff8000001f
         // 00416e23: jns 0x416e2a
      [-]4f83cfe047
         // 0041535b: dec edi
         // 0041535c: or edi, 0xffffffffffffffe0
         // 0041535f: inc edi
      [-]8b4495f02bcf33ff47d3e7
         // 00416e2a: mov eax, ss:[ebp+edx*0x4]
         // 00416e2e: sub ecx, edi
         // 00416e30: xor edi, edi
         // 00416e32: inc edi
         // 00416e33: shl edi, b1 cl
      [-]897ddc03f8897de03bf88b45e0
         // 00416e37: mov ss:[ebp+0xffffffffffffffdc], edi
         // 00416e3a: add edi, eax
         // 00416e3c: mov ss:[ebp+0xffffffffffffffe0], edi
         // 00416e3f: cmp edi, eax
         // 00416e41: mov eax, ss:[ebp+0xffffffffffffffe0]
      [-]3b45dc7303
         // 0041537f: cmp eax, ss:[ebp+0xffffffffffffffdc]
         // 00415382: jnb 0x415387
      [-]894495f04a7828
         // 00415387: mov ss:[ebp+edx*0x4], eax
         // 0041538b: dec edx
         // 0041538c: js 0x4153b6
      [-]85c97421
         // 0041538e: test ecx, ecx
         // 00415390: jz 0x4153b3
      [-]8b4495f0
         // 00416e5c: mov eax, ss:[ebp+edx*0x4]
      [-]8d78013bf8
         // 00416e62: lea edi, ds:[eax+0x1]
         // 00416e65: cmp edi, eax
      [-]83f8017303
         // 004153a4: cmp eax, 0x1
         // 004153a7: jnb 0x4153ac
      [-]894495f04a79db
         // 004153ac: mov ss:[ebp+edx*0x4], eax
         // 004153b0: dec edx
         // 004153b1: jns 0x41538e
      [-]8bc7d3e0214495f0423bd67d11
         // 004153bc: mov eax, edi
         // 004153be: shl eax, b1 cl
         // 004153c0: and ss:[ebp+edx*0x4], eax
         // 004153c4: inc edx
         // 004153c5: cmp edx, esi
         // 004153c7: jge 0x4153da
      [-]f3ab83cfff
         // 00415615: rep stosdd 
         // 00415617: or edi, 0xffffffffffffffff
      [-]418bc19983e21f03c2c1f805
         // 00415620: inc ecx
         // 00415621: mov eax, ecx
         // 00415623: cdq 
         // 00415624: and edx, 0x1f
         // 00415627: add eax, edx
         // 00415629: sar eax, b1 0x5
      [-]81e1????????7905
         // 0041562c: and ecx, 0xffffffff8000001f
         // 00415632: jns 0x415639
      [-]592bcb89
         // 00416ed7: pop ecx
         // 00416ed8: sub ecx, ebx
         // 00416edd: mov ss:[ebp+0xffffffffffffffdc], ecx
      [-]8b5485f08b
         // 00416ee0: mov edx, ss:[ebp+eax*0x4]
         // 00416ee4: mov ecx, ebx
      [-]23c70b55e089548df08b
         // 00416eed: and eax, edi
         // 00416eef: or edx, ss:[ebp+0xffffffffffffffe0]
         // 00416ef2: mov ss:[ebp+ecx*0x4], edx
         // 00416ef6: mov ecx, ss:[ebp+0xffffffffffffffdc]
      [-]c6c1e002
         // 0041568c: shl eax, b1 0x2
      [-]3bce7c08
         // 00415451: cmp ecx, esi
         // 00415453: jl 0x41545d
      [-]83ea044979ea
         // 00415461: sub edx, 0x4
         // 00415464: dec ecx
         // 00415465: jns 0x415451
      [-]e9d8fdffff
         // 00415467: jmp 0x415244
      [-]0f8ca2000000
         // 00415472: jl 0x41551a
      [-]8d7df033c0ababab
         // 004156be: lea edi, ss:[ebp+0xfffffffffffffff0]
         // 004156c1: xor eax, eax
         // 004156c3: stosdd 
         // 004156c4: stosdd 
         // 004156c5: stosdd 
      [-]9983e21f03c2c1f8058945cc81e1????????7905
         // 004156cf: cdq 
         // 004156d0: and edx, 0x1f
         // 004156d3: add eax, edx
         // 004156d5: sar eax, b1 0x5
         // 004156d8: mov ss:[ebp+0xffffffffffffffcc], eax
         // 004156db: and ecx, 0xffffffff8000001f
         // 004156e1: jns 0x4156e8
      [-]4983c9e041
         // 004154a3: dec ecx
         // 004154a4: or ecx, 0xffffffffffffffe0
         // 004154a7: inc ecx
      [-]d3ea23c70b55e0
         // 00416f8d: shr edx, b1 cl
         // 00416f8f: and eax, edi
         // 00416f91: or edx, ss:[ebp+0xffffffffffffffe0]
      [-]89549df0
         // 00416f9c: mov ss:[ebp+ebx*0x4], edx
      [-]3bde7cdf
         // 00416fa4: cmp ebx, esi
         // 00416fa6: jl 0x416f87
      [-]c6c1e002
         // 0041572b: shl eax, b1 0x2
      [-]3bce7c08
         // 004154f0: cmp ecx, esi
         // 004154f2: jl 0x4154fc
      [-]83ea044979ea
         // 00415500: sub edx, 0x4
         // 00415503: dec ecx
         // 00415504: jns 0x4154f0
      [-]33db0335??
         // 0041550c: xor ebx, ebx
         // 0041550e: add esi, ds:[0x42432c]
      [-]43e995000000
         // 00415514: inc ebx
         // 00415515: jmp 0x4155af
      [-]8165????????7f03f18b0d??
         // 00415520: and ss:[ebp+0xfffffffffffffff0], 0x7fffffff
         // 00415527: add esi, ecx
         // 00415529: mov ecx, ds:[0x424338]
      [-]8bc19983e21f8975c803c2c1f8058945d881e1????????7905
         // 0041552f: mov eax, ecx
         // 00415531: cdq 
         // 00415532: and edx, 0x1f
         // 00415535: mov ss:[ebp+0xffffffffffffffc8], esi
         // 00415538: add eax, edx
         // 0041553a: sar eax, b1 0x5
         // 0041553d: mov ss:[ebp+0xffffffffffffffd8], eax
         // 00415540: and ecx, 0xffffffff8000001f
         // 00415546: jns 0x41554d
      [-]4983c9e041
         // 00415548: dec ecx
         // 00415549: or ecx, 0xffffffffffffffe0
         // 0041554c: inc ecx
      [-]895de08bf3
         // 00417019: mov ss:[ebp+0xffffffffffffffe0], ebx
         // 0041701c: mov esi, ebx
      [-]8b54b5f08bcb
         // 004157a3: mov edx, ss:[ebp+esi*0x4]
         // 004157a7: mov eax, edx
         // 004157ab: mov ecx, ebx
      [-]468945e083fe037cdf
         // 004157bb: inc esi
         // 004157bc: mov ss:[ebp+0xffffffffffffffe0], eax
         // 004157bf: cmp esi, 0x3
         // 004157c2: jl 0x4157a3
      [-]75c88bc7c1e0026a02
         // 004157cf: mov eax, edi
         // 004157d1: shl eax, b1 0x2
         // 004157d4: push 0x2
      [-]3bcf7c08
         // 00415599: cmp ecx, edi
         // 0041559b: jl 0x4155a5
      [-]83ea044979ea
         // 004155a9: sub edx, 0x4
         // 004155ac: dec ecx
         // 004155ad: jns 0x415599
      [-]6a1f582b05??
         // 004155b2: push 0x1f
         // 004155b4: pop eax
         // 004155b5: sub eax, ds:[0x424338]
      [-]8bc88b45bcd3e6f7d81bc025????????0bf0a1??
         // 004155bb: mov ecx, eax
         // 004155bd: mov eax, ss:[ebp+0xffffffffffffffbc]
         // 004155c0: shl esi, b1 cl
         // 004155c2: neg eax
         // 004155c4: sbb eax, eax
         // 004155c6: and eax, 0xffffffff80000000
         // 004155cb: or esi, eax
         // 004155cd: mov eax, ds:[0x42433c]
      [-]0b75f083f840750a
         // 004155d2: or esi, ss:[ebp+0xfffffffffffffff0]
         // 004155d5: cmp eax, 0x40
         // 004155d8: jnz 0x4155e4
      [-]83f8207502
         // 004155e4: cmp eax, 0x20
         // 004155e7: jnz 0x4155eb
      [-]8b4dfc8bc35f5e
         // 0041582b: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 0041582e: mov eax, ebx
         // 00415830: pop edi
         // 00415831: pop esi
      [-]ffff8be55dc3
         // 0041583a: mov esp, ebp
         // 0041583c: pop ebp
         // 0041583d: retn 
      [-]558bec83ec44a1
         // 004170c8: push ebp
         // 004170c9: mov ebp, esp
         // 004170cb: sub esp, 0x44
         // 004170ce: mov eax, ds:[___security_cookie]
      [-]33c58945fc8b4d085356570fb7410a33db8b7d0c8bd025????????897dc08945bc81e2????????8b410681ea????????8945f08b41028945f40fb701c1e0108955e08945f881fa????????7525
         // 004170d3: xor eax, ebp
         // 004170d5: mov ss:[ebp+0xfffffffffffffffc], eax
         // 004170d8: mov ecx, ss:[ebp+0x8]
         // 004170db: push ebx
         // 004170dc: push esi
         // 004170dd: push edi
         // 004170de: movzx eax, b2 ds:[ecx+0xa]
         // 004170e2: xor ebx, ebx
         // 004170e4: mov edi, ss:[ebp+0xc]
         // 004170e7: mov edx, eax
         // 004170e9: and eax, 0x8000
         // 004170ee: mov ss:[ebp+0xffffffffffffffc0], edi
         // 004170f1: mov ss:[ebp+0xffffffffffffffbc], eax
         // 004170f4: and edx, 0x7fff
         // 004170fa: mov eax, ds:[ecx+0x6]
         // 004170fd: sub edx, 0x3fff
         // 00417103: mov ss:[ebp+0xfffffffffffffff0], eax
         // 00417106: mov eax, ds:[ecx+0x2]
         // 00417109: mov ss:[ebp+0xfffffffffffffff4], eax
         // 0041710c: movzx eax, b2 ds:[ecx]
         // 0041710f: shl eax, b1 0x10
         // 00417112: mov ss:[ebp+0xffffffffffffffe0], edx
         // 00417115: mov ss:[ebp+0xfffffffffffffff8], eax
         // 00417118: cmp edx, 0xffffffffffffc001
         // 0041711e: jnz 0x417145
      [-]8bf38bc3
         // 00415656: mov esi, ebx
         // 00415658: mov eax, ebx
      [-]395c85f0750b
         // 0041565a: cmp ss:[ebp+eax*0x4], ebx
         // 0041565e: jnz 0x41566b
      [-]4083f8037cf4
         // 00415660: inc eax
         // 00415661: cmp eax, 0x3
         // 00415664: jl 0x41565a
      [-]e9b9040000
         // 00415666: jmp 0x415b24
      [-]33c08d7df0ababab
         // 0041566b: xor eax, eax
         // 0041566d: lea edi, ss:[ebp+0xfffffffffffffff0]
         // 00415670: stosdd 
         // 00415671: stosdd 
         // 00415672: stosdd 
      [-]6a025be9a6040000
         // 00415673: push 0x2
         // 00415675: pop ebx
         // 00415676: jmp 0x415b21
      [-]8d75f08d7de48955dca5488945cc6a1f895dd4a58d48018bc199a55e23d603d0c1fa058955c481e1????????7905
         // 00415680: lea esi, ss:[ebp+0xfffffffffffffff0]
         // 00415683: lea edi, ss:[ebp+0xffffffffffffffe4]
         // 00415686: mov ss:[ebp+0xffffffffffffffdc], edx
         // 00415689: movsdd 
         // 0041568a: dec eax
         // 0041568b: mov ss:[ebp+0xffffffffffffffcc], eax
         // 0041568e: push 0x1f
         // 00415690: mov ss:[ebp+0xffffffffffffffd4], ebx
         // 00415693: movsdd 
         // 00415694: lea ecx, ds:[eax+0x1]
         // 00415697: mov eax, ecx
         // 00415699: cdq 
         // 0041569a: movsdd 
         // 0041569b: pop esi
         // 0041569c: and edx, esi
         // 0041569e: add edx, eax
         // 004156a0: sar edx, b1 0x5
         // 004156a3: mov ss:[ebp+0xffffffffffffffc4], edx
         // 004156a6: and ecx, 0xffffffff8000001f
         // 004156ac: jns 0x4156b3
      [-]4983c9e041
         // 004156ae: dec ecx
         // 004156af: or ecx, 0xffffffffffffffe0
         // 004156b2: inc ecx
      [-]2bf133c0408975d08bce83cfffd3e06a035e854495f00f84a4000000
         // 004156b3: sub esi, ecx
         // 004156b5: xor eax, eax
         // 004156b7: inc eax
         // 004156b8: mov ss:[ebp+0xffffffffffffffd0], esi
         // 004156bb: mov ecx, esi
         // 004156bd: or edi, 0xffffffffffffffff
         // 004156c0: shl eax, b1 cl
         // 004156c2: push 0x3
         // 004156c4: pop esi
         // 004156c5: test ss:[ebp+edx*0x4], eax
         // 004156c9: jz 0x415773
      [-]8bc7d3e0f7d0854495f0eb04
         // 004156cf: mov eax, edi
         // 004156d1: shl eax, b1 cl
         // 004156d3: not eax
         // 004156d5: test ss:[ebp+edx*0x4], eax
         // 004156d9: jmp 0x4156df
      [-]395c95f0
         // 004156db: cmp ss:[ebp+edx*0x4], ebx
      [-]423bd67cf5
         // 004156e1: inc edx
         // 004156e2: cmp edx, esi
         // 004156e4: jl 0x4156db
      [-]e985000000
         // 004156e6: jmp 0x415770
      [-]8b45cc996a1f5923d103d08b45ccc1fa0525????????7905
         // 004156eb: mov eax, ss:[ebp+0xffffffffffffffcc]
         // 004156ee: cdq 
         // 004156ef: push 0x1f
         // 004156f1: pop ecx
         // 004156f2: and edx, ecx
         // 004156f4: add edx, eax
         // 004156f6: mov eax, ss:[ebp+0xffffffffffffffcc]
         // 004156f9: sar edx, b1 0x5
         // 004156fc: and eax, 0xffffffff8000001f
         // 00415701: jns 0x415708
      [-]4883c8e040
         // 00415703: dec eax
         // 00415704: or eax, 0xffffffffffffffe0
         // 00415707: inc eax
      [-]2bc8895dd433c040d3e08945c88b4495f08b4dc803c8894dd83bc88b45d88bcb6aff5f7205
         // 00415708: sub ecx, eax
         // 0041570a: mov ss:[ebp+0xffffffffffffffd4], ebx
         // 0041570d: xor eax, eax
         // 0041570f: inc eax
         // 00415710: shl eax, b1 cl
         // 00415712: mov ss:[ebp+0xffffffffffffffc8], eax
         // 00415715: mov eax, ss:[ebp+edx*0x4]
         // 00415719: mov ecx, ss:[ebp+0xffffffffffffffc8]
         // 0041571c: add ecx, eax
         // 0041571e: mov ss:[ebp+0xffffffffffffffd8], ecx
         // 00415721: cmp ecx, eax
         // 00415723: mov eax, ss:[ebp+0xffffffffffffffd8]
         // 00415726: mov ecx, ebx
         // 00415728: push 0xffffffffffffffff
         // 0041572a: pop edi
         // 0041572b: jb 0x415732
      [-]3b45c87306
         // 0041572d: cmp eax, ss:[ebp+0xffffffffffffffc8]
         // 00415730: jnb 0x415738
      [-]33c941894dd4
         // 00415732: xor ecx, ecx
         // 00415734: inc ecx
         // 00415735: mov ss:[ebp+0xffffffffffffffd4], ecx
      [-]894495f04a782e
         // 00415738: mov ss:[ebp+edx*0x4], eax
         // 0041573c: dec edx
         // 0041573d: js 0x41576d
      [-]85c97427
         // 0041573f: test ecx, ecx
         // 00415741: jz 0x41576a
      [-]8b4495f08bcb895dd48d78013bf8897dd88bc77205
         // 00415743: mov eax, ss:[ebp+edx*0x4]
         // 00415747: mov ecx, ebx
         // 00415749: mov ss:[ebp+0xffffffffffffffd4], ebx
         // 0041574c: lea edi, ds:[eax+0x1]
         // 0041574f: cmp edi, eax
         // 00415751: mov ss:[ebp+0xffffffffffffffd8], edi
         // 00415754: mov eax, edi
         // 00415756: jb 0x41575d
      [-]83f8017306
         // 00415758: cmp eax, 0x1
         // 0041575b: jnb 0x415763
      [-]33c941894dd4
         // 0041575d: xor ecx, ecx
         // 0041575f: inc ecx
         // 00415760: mov ss:[ebp+0xffffffffffffffd4], ecx
      [-]894495f04a79d5
         // 00415763: mov ss:[ebp+edx*0x4], eax
         // 00415767: dec edx
         // 00415768: jns 0x41573f
      [-]8bc7d3e0214495f08d42013bc67d11
         // 00415773: mov eax, edi
         // 00415775: shl eax, b1 cl
         // 00415777: and ss:[ebp+edx*0x4], eax
         // 0041577b: lea eax, ds:[edx+0x1]
         // 0041577e: cmp eax, esi
         // 00415780: jge 0x415793
      [-]8d7df08bce8d3c872bc833c0f3ab83cfff
         // 00415782: lea edi, ss:[ebp+0xfffffffffffffff0]
         // 00415785: mov ecx, esi
         // 00415787: lea edi, ds:[edi+eax*0x4]
         // 0041578a: sub ecx, eax
         // 0041578c: xor eax, eax
         // 0041578e: rep stosdd 
         // 00415790: or edi, 0xffffffffffffffff
      [-]8b4de0395dd47401
         // 00415793: mov ecx, ss:[ebp+0xffffffffffffffe0]
         // 00415796: cmp ss:[ebp+0xffffffffffffffd4], ebx
         // 00415799: jz 0x41579c
      [-]8bc22b05??
         // 004157a2: mov eax, edx
         // 004157a4: sub eax, ds:[0x42434c]
      [-]3bc87d0f
         // 004157aa: cmp ecx, eax
         // 004157ac: jge 0x4157bd
      [-]33c08d7df0ababab
         // 004157ae: xor eax, eax
         // 004157b0: lea edi, ss:[ebp+0xfffffffffffffff0]
         // 004157b3: stosdd 
         // 004157b4: stosdd 
         // 004157b5: stosdd 
      [-]8bf3e9b6feffff
         // 004157b6: mov esi, ebx
         // 004157b8: jmp 0x415673
      [-]3bca0f8f19020000
         // 004157bd: cmp ecx, edx
         // 004157bf: jg 0x4159de
      [-]2b55dc8d75e48955d08d7df08bc2a59983e21f03c2c1f805a58945c48b45d0a525????????7905
         // 004157c5: sub edx, ss:[ebp+0xffffffffffffffdc]
         // 004157c8: lea esi, ss:[ebp+0xffffffffffffffe4]
         // 004157cb: mov ss:[ebp+0xffffffffffffffd0], edx
         // 004157ce: lea edi, ss:[ebp+0xfffffffffffffff0]
         // 004157d1: mov eax, edx
         // 004157d3: movsdd 
         // 004157d4: cdq 
         // 004157d5: and edx, 0x1f
         // 004157d8: add eax, edx
         // 004157da: sar eax, b1 0x5
         // 004157dd: movsdd 
         // 004157de: mov ss:[ebp+0xffffffffffffffc4], eax
         // 004157e1: mov eax, ss:[ebp+0xffffffffffffffd0]
         // 004157e4: movsdd 
         // 004157e5: and eax, 0xffffffff8000001f
         // 004157ea: jns 0x4157f1
      [-]4883c8e040
         // 004157ec: dec eax
         // 004157ed: or eax, 0xffffffffffffffe0
         // 004157f0: inc eax
      [-]8945d083cfff8bc7895de08b7dd08bcfd3e0f7d06a208945d8582bc76a038945c85e
         // 004157f1: mov ss:[ebp+0xffffffffffffffd0], eax
         // 004157f4: or edi, 0xffffffffffffffff
         // 004157f7: mov eax, edi
         // 004157f9: mov ss:[ebp+0xffffffffffffffe0], ebx
         // 004157fc: mov edi, ss:[ebp+0xffffffffffffffd0]
         // 004157ff: mov ecx, edi
         // 00415801: shl eax, b1 cl
         // 00415803: not eax
         // 00415805: push 0x20
         // 00415807: mov ss:[ebp+0xffffffffffffffd8], eax
         // 0041580a: pop eax
         // 0041580b: sub eax, edi
         // 0041580d: push 0x3
         // 0041580f: mov ss:[ebp+0xffffffffffffffc8], eax
         // 00415812: pop esi
      [-]8b549df08bcf8bc2d3ea0b55e02345d88b4dc8d3e089549df0438945e03bde7cdf
         // 00415813: mov edx, ss:[ebp+ebx*0x4]
         // 00415817: mov ecx, edi
         // 00415819: mov eax, edx
         // 0041581b: shr edx, b1 cl
         // 0041581d: or edx, ss:[ebp+0xffffffffffffffe0]
         // 00415820: and eax, ss:[ebp+0xffffffffffffffd8]
         // 00415823: mov ecx, ss:[ebp+0xffffffffffffffc8]
         // 00415826: shl eax, b1 cl
         // 00415828: mov ss:[ebp+ebx*0x4], edx
         // 0041582c: inc ebx
         // 0041582d: mov ss:[ebp+0xffffffffffffffe0], eax
         // 00415830: cmp ebx, esi
         // 00415832: jl 0x415813
      [-]8b45c48d55f8c1e00233db6a022bd083cfff8b45c459
         // 00415834: mov eax, ss:[ebp+0xffffffffffffffc4]
         // 00415837: lea edx, ss:[ebp+0xfffffffffffffff8]
         // 0041583a: shl eax, b1 0x2
         // 0041583d: xor ebx, ebx
         // 0041583f: push 0x2
         // 00415841: sub edx, eax
         // 00415843: or edi, 0xffffffffffffffff
         // 00415846: mov eax, ss:[ebp+0xffffffffffffffc4]
         // 00415849: pop ecx
      [-]3bc87c0b
         // 0041584a: cmp ecx, eax
         // 0041584c: jl 0x415859
      [-]8b0289448df08b45c4eb04
         // 0041584e: mov eax, ds:[edx]
         // 00415850: mov ss:[ebp+ecx*0x4], eax
         // 00415854: mov eax, ss:[ebp+0xffffffffffffffc4]
         // 00415857: jmp 0x41585d
      [-]895c8df0
         // 00415859: mov ss:[ebp+ecx*0x4], ebx
      [-]83ea044979e7
         // 0041585d: sub edx, 0x4
         // 00415860: dec ecx
         // 00415861: jns 0x41584a
      [-]8b4dcc418bc19983e21f03d0c1fa058955d481e1????????7905
         // 00415863: mov ecx, ss:[ebp+0xffffffffffffffcc]
         // 00415866: inc ecx
         // 00415867: mov eax, ecx
         // 00415869: cdq 
         // 0041586a: and edx, 0x1f
         // 0041586d: add edx, eax
         // 0041586f: sar edx, b1 0x5
         // 00415872: mov ss:[ebp+0xffffffffffffffd4], edx
         // 00415875: and ecx, 0xffffffff8000001f
         // 0041587b: jns 0x415882
      [-]4983c9e041
         // 0041587d: dec ecx
         // 0041587e: or ecx, 0xffffffffffffffe0
         // 00415881: inc ecx
      [-]6a1f582bc18945d033c08b4dd040d3e0854495f00f8492000000
         // 00415882: push 0x1f
         // 00415884: pop eax
         // 00415885: sub eax, ecx
         // 00415887: mov ss:[ebp+0xffffffffffffffd0], eax
         // 0041588a: xor eax, eax
         // 0041588c: mov ecx, ss:[ebp+0xffffffffffffffd0]
         // 0041588f: inc eax
         // 00415890: shl eax, b1 cl
         // 00415892: test ss:[ebp+edx*0x4], eax
         // 00415896: jz 0x41592e
      [-]8bc7d3e0f7d0854495f0eb04
         // 0041589c: mov eax, edi
         // 0041589e: shl eax, b1 cl
         // 004158a0: not eax
         // 004158a2: test ss:[ebp+edx*0x4], eax
         // 004158a6: jmp 0x4158ac
      [-]395c95f0
         // 004158a8: cmp ss:[ebp+edx*0x4], ebx
      [-]423bd67cf5
         // 004158ae: inc edx
         // 004158af: cmp edx, esi
         // 004158b1: jl 0x4158a8
      [-]8b7dcc8bc76a1f995923d103d0c1fa0581e7????????7905
         // 004158b5: mov edi, ss:[ebp+0xffffffffffffffcc]
         // 004158b8: mov eax, edi
         // 004158ba: push 0x1f
         // 004158bc: cdq 
         // 004158bd: pop ecx
         // 004158be: and edx, ecx
         // 004158c0: add edx, eax
         // 004158c2: sar edx, b1 0x5
         // 004158c5: and edi, 0xffffffff8000001f
         // 004158cb: jns 0x4158d2
      [-]4f83cfe047
         // 004158cd: dec edi
         // 004158ce: or edi, 0xffffffffffffffe0
         // 004158d1: inc edi
      [-]8b4495f02bcf33ff47d3e78bcb897ddc03f8897de03bf88b45e06aff5f7205
         // 004158d2: mov eax, ss:[ebp+edx*0x4]
         // 004158d6: sub ecx, edi
         // 004158d8: xor edi, edi
         // 004158da: inc edi
         // 004158db: shl edi, b1 cl
         // 004158dd: mov ecx, ebx
         // 004158df: mov ss:[ebp+0xffffffffffffffdc], edi
         // 004158e2: add edi, eax
         // 004158e4: mov ss:[ebp+0xffffffffffffffe0], edi
         // 004158e7: cmp edi, eax
         // 004158e9: mov eax, ss:[ebp+0xffffffffffffffe0]
         // 004158ec: push 0xffffffffffffffff
         // 004158ee: pop edi
         // 004158ef: jb 0x4158f6
      [-]3b45dc7303
         // 004158f1: cmp eax, ss:[ebp+0xffffffffffffffdc]
         // 004158f4: jnb 0x4158f9
      [-]894495f04a7828
         // 004158f9: mov ss:[ebp+edx*0x4], eax
         // 004158fd: dec edx
         // 004158fe: js 0x415928
      [-]85c97421
         // 00415900: test ecx, ecx
         // 00415902: jz 0x415925
      [-]8b4495f08bcb8d78013bf8897de08bc77205
         // 00415904: mov eax, ss:[ebp+edx*0x4]
         // 00415908: mov ecx, ebx
         // 0041590a: lea edi, ds:[eax+0x1]
         // 0041590d: cmp edi, eax
         // 0041590f: mov ss:[ebp+0xffffffffffffffe0], edi
         // 00415912: mov eax, edi
         // 00415914: jb 0x41591b
      [-]83f8017303
         // 00415916: cmp eax, 0x1
         // 00415919: jnb 0x41591e
      [-]894495f04a79db
         // 0041591e: mov ss:[ebp+edx*0x4], eax
         // 00415922: dec edx
         // 00415923: jns 0x415900
      [-]8bc7d3e0214495f0423bd67d11
         // 0041592e: mov eax, edi
         // 00415930: shl eax, b1 cl
         // 00415932: and ss:[ebp+edx*0x4], eax
         // 00415936: inc edx
         // 00415937: cmp edx, esi
         // 00415939: jge 0x41594c
      [-]8d7df08bce8d3c972bca33c0f3ab83cfff
         // 0041593b: lea edi, ss:[ebp+0xfffffffffffffff0]
         // 0041593e: mov ecx, esi
         // 00415940: lea edi, ds:[edi+edx*0x4]
         // 00415943: sub ecx, edx
         // 00415945: xor eax, eax
         // 00415947: rep stosdd 
         // 00415949: or edi, 0xffffffffffffffff
      [-]418bc19983e21f03c2c1f8058945d881e1????????7905
         // 00415952: inc ecx
         // 00415953: mov eax, ecx
         // 00415955: cdq 
         // 00415956: and edx, 0x1f
         // 00415959: add eax, edx
         // 0041595b: sar eax, b1 0x5
         // 0041595e: mov ss:[ebp+0xffffffffffffffd8], eax
         // 00415961: and ecx, 0xffffffff8000001f
         // 00415967: jns 0x41596e
      [-]4983c9e041
         // 00415969: dec ecx
         // 0041596a: or ecx, 0xffffffffffffffe0
         // 0041596d: inc ecx
      [-]894ddc8bc3d3e76a20895de0f7d78b5ddc592bcb8945cc894ddc
         // 0041596e: mov ss:[ebp+0xffffffffffffffdc], ecx
         // 00415971: mov eax, ebx
         // 00415973: shl edi, b1 cl
         // 00415975: push 0x20
         // 00415977: mov ss:[ebp+0xffffffffffffffe0], ebx
         // 0041597a: not edi
         // 0041597c: mov ebx, ss:[ebp+0xffffffffffffffdc]
         // 0041597f: pop ecx
         // 00415980: sub ecx, ebx
         // 00415982: mov ss:[ebp+0xffffffffffffffcc], eax
         // 00415985: mov ss:[ebp+0xffffffffffffffdc], ecx
      [-]8b5485f08bcb8bc2d3ea8b4dcc23c70b55e089548df08b4ddcd3e08945e08b45cc408945cc3bc67cd7
         // 00415988: mov edx, ss:[ebp+eax*0x4]
         // 0041598c: mov ecx, ebx
         // 0041598e: mov eax, edx
         // 00415990: shr edx, b1 cl
         // 00415992: mov ecx, ss:[ebp+0xffffffffffffffcc]
         // 00415995: and eax, edi
         // 00415997: or edx, ss:[ebp+0xffffffffffffffe0]
         // 0041599a: mov ss:[ebp+ecx*0x4], edx
         // 0041599e: mov ecx, ss:[ebp+0xffffffffffffffdc]
         // 004159a1: shl eax, b1 cl
         // 004159a3: mov ss:[ebp+0xffffffffffffffe0], eax
         // 004159a6: mov eax, ss:[ebp+0xffffffffffffffcc]
         // 004159a9: inc eax
         // 004159aa: mov ss:[ebp+0xffffffffffffffcc], eax
         // 004159ad: cmp eax, esi
         // 004159af: jl 0x415988
      [-]8b75d88d55f88bc6c1e0026a022bd033db59
         // 004159b1: mov esi, ss:[ebp+0xffffffffffffffd8]
         // 004159b4: lea edx, ss:[ebp+0xfffffffffffffff8]
         // 004159b7: mov eax, esi
         // 004159b9: shl eax, b1 0x2
         // 004159bc: push 0x2
         // 004159be: sub edx, eax
         // 004159c0: xor ebx, ebx
         // 004159c2: pop ecx
      [-]3bce7c08
         // 004159c3: cmp ecx, esi
         // 004159c5: jl 0x4159cf
      [-]8b0289448df0eb04
         // 004159c7: mov eax, ds:[edx]
         // 004159c9: mov ss:[ebp+ecx*0x4], eax
         // 004159cd: jmp 0x4159d3
      [-]895c8df0
         // 004159cf: mov ss:[ebp+ecx*0x4], ebx
      [-]83ea044979ea
         // 004159d3: sub edx, 0x4
         // 004159d6: dec ecx
         // 004159d7: jns 0x4159c3
      [-]e9d8fdffff
         // 004159d9: jmp 0x4157b6
      [-]0f8ca2000000
         // 004159e4: jl 0x415a8c
      [-]8d7df033c0ababab8bc1814df0????????9983e21f03c2c1f8058945cc81e1????????7905
         // 004159f0: lea edi, ss:[ebp+0xfffffffffffffff0]
         // 004159f3: xor eax, eax
         // 004159f5: stosdd 
         // 004159f6: stosdd 
         // 004159f7: stosdd 
         // 004159f8: mov eax, ecx
         // 004159fa: or ss:[ebp+0xfffffffffffffff0], 0xffffffff80000000
         // 00415a01: cdq 
         // 00415a02: and edx, 0x1f
         // 00415a05: add eax, edx
         // 00415a07: sar eax, b1 0x5
         // 00415a0a: mov ss:[ebp+0xffffffffffffffcc], eax
         // 00415a0d: and ecx, 0xffffffff8000001f
         // 00415a13: jns 0x415a1a
      [-]4983c9e041
         // 00415a15: dec ecx
         // 00415a16: or ecx, 0xffffffffffffffe0
         // 00415a19: inc ecx
      [-]83cfff894dc86a20d3e7582bc1895de0f7d78945d8
         // 00415a1a: or edi, 0xffffffffffffffff
         // 00415a1d: mov ss:[ebp+0xffffffffffffffc8], ecx
         // 00415a20: push 0x20
         // 00415a22: shl edi, b1 cl
         // 00415a24: pop eax
         // 00415a25: sub eax, ecx
         // 00415a27: mov ss:[ebp+0xffffffffffffffe0], ebx
         // 00415a2a: not edi
         // 00415a2c: mov ss:[ebp+0xffffffffffffffd8], eax
      [-]8b549df08bc2d3ea23c70b55e08b4dd8d3e08b4dc889549df0438945e03bde7cdf
         // 00415a2f: mov edx, ss:[ebp+ebx*0x4]
         // 00415a33: mov eax, edx
         // 00415a35: shr edx, b1 cl
         // 00415a37: and eax, edi
         // 00415a39: or edx, ss:[ebp+0xffffffffffffffe0]
         // 00415a3c: mov ecx, ss:[ebp+0xffffffffffffffd8]
         // 00415a3f: shl eax, b1 cl
         // 00415a41: mov ecx, ss:[ebp+0xffffffffffffffc8]
         // 00415a44: mov ss:[ebp+ebx*0x4], edx
         // 00415a48: inc ebx
         // 00415a49: mov ss:[ebp+0xffffffffffffffe0], eax
         // 00415a4c: cmp ebx, esi
         // 00415a4e: jl 0x415a2f
      [-]8b75cc8d55f88bc6c1e0026a022bd033db59
         // 00415a50: mov esi, ss:[ebp+0xffffffffffffffcc]
         // 00415a53: lea edx, ss:[ebp+0xfffffffffffffff8]
         // 00415a56: mov eax, esi
         // 00415a58: shl eax, b1 0x2
         // 00415a5b: push 0x2
         // 00415a5d: sub edx, eax
         // 00415a5f: xor ebx, ebx
         // 00415a61: pop ecx
      [-]3bce7c08
         // 00415a62: cmp ecx, esi
         // 00415a64: jl 0x415a6e
      [-]8b0289448df0eb04
         // 00415a66: mov eax, ds:[edx]
         // 00415a68: mov ss:[ebp+ecx*0x4], eax
         // 00415a6c: jmp 0x415a72
      [-]895c8df0
         // 00415a6e: mov ss:[ebp+ecx*0x4], ebx
      [-]83ea044979ea
         // 00415a72: sub edx, 0x4
         // 00415a75: dec ecx
         // 00415a76: jns 0x415a62
      [-]33db0335??
         // 00415a7e: xor ebx, ebx
         // 00415a80: add esi, ds:[0x424344]
      [-]43e995000000
         // 00415a86: inc ebx
         // 00415a87: jmp 0x415b21
      [-]8165????????7f03f18b0d??
         // 00415a92: and ss:[ebp+0xfffffffffffffff0], 0x7fffffff
         // 00415a99: add esi, ecx
         // 00415a9b: mov ecx, ds:[0x424350]
      [-]8bc19983e21f8975c803c2c1f8058945d881e1????????7905
         // 00415aa1: mov eax, ecx
         // 00415aa3: cdq 
         // 00415aa4: and edx, 0x1f
         // 00415aa7: mov ss:[ebp+0xffffffffffffffc8], esi
         // 00415aaa: add eax, edx
         // 00415aac: sar eax, b1 0x5
         // 00415aaf: mov ss:[ebp+0xffffffffffffffd8], eax
         // 00415ab2: and ecx, 0xffffffff8000001f
         // 00415ab8: jns 0x415abf
      [-]4983c9e041
         // 00415aba: dec ecx
         // 00415abb: or ecx, 0xffffffffffffffe0
         // 00415abe: inc ecx
      [-]6a20895de08bf3d3e78bd9582bc3894ddcf7d78945dc
         // 00415abf: push 0x20
         // 00415ac1: mov ss:[ebp+0xffffffffffffffe0], ebx
         // 00415ac4: mov esi, ebx
         // 00415ac6: shl edi, b1 cl
         // 00415ac8: mov ebx, ecx
         // 00415aca: pop eax
         // 00415acb: sub eax, ebx
         // 00415acd: mov ss:[ebp+0xffffffffffffffdc], ecx
         // 00415ad0: not edi
         // 00415ad2: mov ss:[ebp+0xffffffffffffffdc], eax
      [-]8b54b5f08bcb8bc2d3ea0b55e023c78b4ddcd3e08954b5f0468945e083fe037cdf
         // 00415ad5: mov edx, ss:[ebp+esi*0x4]
         // 00415ad9: mov ecx, ebx
         // 00415adb: mov eax, edx
         // 00415add: shr edx, b1 cl
         // 00415adf: or edx, ss:[ebp+0xffffffffffffffe0]
         // 00415ae2: and eax, edi
         // 00415ae4: mov ecx, ss:[ebp+0xffffffffffffffdc]
         // 00415ae7: shl eax, b1 cl
         // 00415ae9: mov ss:[ebp+esi*0x4], edx
         // 00415aed: inc esi
         // 00415aee: mov ss:[ebp+0xffffffffffffffe0], eax
         // 00415af1: cmp esi, 0x3
         // 00415af4: jl 0x415ad5
      [-]8b7dd88d55f88b75c88bc7c1e0026a022bd033db59
         // 00415af6: mov edi, ss:[ebp+0xffffffffffffffd8]
         // 00415af9: lea edx, ss:[ebp+0xfffffffffffffff8]
         // 00415afc: mov esi, ss:[ebp+0xffffffffffffffc8]
         // 00415aff: mov eax, edi
         // 00415b01: shl eax, b1 0x2
         // 00415b04: push 0x2
         // 00415b06: sub edx, eax
         // 00415b08: xor ebx, ebx
         // 00415b0a: pop ecx
      [-]3bcf7c08
         // 00415b0b: cmp ecx, edi
         // 00415b0d: jl 0x415b17
      [-]8b0289448df0eb04
         // 00415b0f: mov eax, ds:[edx]
         // 00415b11: mov ss:[ebp+ecx*0x4], eax
         // 00415b15: jmp 0x415b1b
      [-]895c8df0
         // 00415b17: mov ss:[ebp+ecx*0x4], ebx
      [-]83ea044979ea
         // 00415b1b: sub edx, 0x4
         // 00415b1e: dec ecx
         // 00415b1f: jns 0x415b0b
      [-]6a1f582b05??
         // 00415b24: push 0x1f
         // 00415b26: pop eax
         // 00415b27: sub eax, ds:[0x424350]
      [-]8bc88b45bcd3e6f7d81bc025????????0bf0a1??
         // 00415b2d: mov ecx, eax
         // 00415b2f: mov eax, ss:[ebp+0xffffffffffffffbc]
         // 00415b32: shl esi, b1 cl
         // 00415b34: neg eax
         // 00415b36: sbb eax, eax
         // 00415b38: and eax, 0xffffffff80000000
         // 00415b3d: or esi, eax
         // 00415b3f: mov eax, ds:[0x424354]
      [-]0b75f083f840750a
         // 00415b44: or esi, ss:[ebp+0xfffffffffffffff0]
         // 00415b47: cmp eax, 0x40
         // 00415b4a: jnz 0x415b56
      [-]8b45f48977048907eb07
         // 00415b4c: mov eax, ss:[ebp+0xfffffffffffffff4]
         // 00415b4f: mov ds:[edi+0x4], esi
         // 00415b52: mov ds:[edi], eax
         // 00415b54: jmp 0x415b5d
      [-]83f8207502
         // 00415b56: cmp eax, 0x20
         // 00415b59: jnz 0x415b5d
      [-]8b4dfc8bc35f5e33cd5be8
         // 00415d9d: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 00415da0: mov eax, ebx
         // 00415da2: pop edi
         // 00415da3: pop esi
         // 00415da4: xor ecx, ebp
         // 00415da6: pop ebx
         // 00415da7: call @__security_check_cookie@4
      [-]ffff8be55dc3
         // 00415dac: mov esp, ebp
         // 00415dae: pop ebp
         // 00415daf: retn 
      [-]8b4424048b5424088910894804c20800
         // 004176c0: mov eax, ss:[esp+0x4]
         // 004176c4: mov edx, ss:[esp+0x8]
         // 004176c8: mov ds:[eax], edx
         // 004176ca: mov ds:[eax+0x4], ecx
         // 004176cd: retn b2 0x8
      [-]8b018d5424f883ec08ff74240c52ff500c8b5424108b48043b4a04750e
         // 004176f0: mov eax, ds:[ecx]
         // 004176f2: lea edx, ss:[esp+0xfffffffffffffff8]
         // 004176f6: sub esp, 0x8
         // 004176f9: push ss:[esp+0xc]
         // 004176fd: push edx
         // 004176fe: call ds:[eax+0xc]
         // 00417701: mov edx, ss:[esp+0x10]
         // 00417705: mov ecx, ds:[eax+0x4]
         // 00417708: cmp ecx, ds:[edx+0x4]
         // 0041770b: jnz 0x41771b
      [-]8b003b027508
         // 0041770d: mov eax, ds:[eax]
         // 0041770f: cmp eax, ds:[edx]
         // 00417711: jnz 0x41771b
      [-]b00183c408c20800
         // 00417713: mov b1 al, b1 0x1
         // 00417715: add esp, 0x8
         // 00417718: retn b2 0x8
      [-]32c083c408c20800
         // 0041771b: xor b1 al, b1 al
         // 0041771d: add esp, 0x8
         // 00417720: retn b2 0x8
      [-]64a1????????50a1
         // 00418187: mov eax, fs:[0x0]
         // 0041818d: push eax
         // 0041818e: mov eax, ds:[___security_cookie]
      [-]33c4508d44240464a3????????a1
         // 00418193: xor eax, esp
         // 00418195: push eax
         // 00418196: lea eax, ss:[esp+0x4]
         // 0041819a: mov fs:[0x0], eax
         // 004181a0: mov eax, ds:[0x425b28]
      [-]a8017527
         // 004181a5: test b1 al, b1 0x1
         // 004181a7: jnz 0x4181d0
      [-]83c801a3
         // 004181a9: or eax, 0x1
         // 004181ac: mov ds:[0x425b28], eax
      [-]c74424????????00c705
         // 004181b6: mov ss:[esp+0x10], 0x0
         // 004181be: mov ds:[0x425b24], ??_7generic_error_category@?A0x846d1564@system@boost@@6B@
      [-]feff83c404
         // 004181cd: add esp, 0x4
      [-]8b4424148b4c24188908c74004
         // 00418480: mov eax, ss:[esp+0x14]
         // 00418484: mov ecx, ss:[esp+0x18]
         // 00418488: mov ds:[eax], ecx
         // 0041848a: mov ds:[eax+0x4], 0x425b68
      [-]8b4c240464890d????????5983c40cc3
         // 00418491: mov ecx, ss:[esp+0x4]
         // 00418495: mov fs:[0x0], ecx
         // 0041849c: pop ecx
         // 0041849d: add esp, 0xc
         // 004184a0: retn 
      [-]64a1????????5083ec38a1
         // 00418207: mov eax, fs:[0x0]
         // 0041820d: push eax
         // 0041820e: sub esp, 0x38
         // 00418211: mov eax, ds:[___security_cookie]
      [-]33c489442434535657a1
         // 00418216: xor eax, esp
         // 00418218: mov ss:[esp+0x34], eax
         // 0041821c: push ebx
         // 0041821d: push esi
         // 0041821e: push edi
         // 0041821f: mov eax, ds:[___security_cookie]
      [-]33c4508d44244864a3????????8b7424588b7c245cc74424????????00a1
         // 00418224: xor eax, esp
         // 00418226: push eax
         // 00418227: lea eax, ss:[esp+0x48]
         // 0041822b: mov fs:[0x0], eax
         // 00418231: mov esi, ss:[esp+0x58]
         // 00418235: mov edi, ss:[esp+0x5c]
         // 00418239: mov ss:[esp+0x10], 0x0
         // 00418241: mov eax, ds:[0x425b18]
      [-]a8017551
         // 00418246: test b1 al, b1 0x1
         // 00418248: jnz 0x41829b
      [-]83c801a3
         // 004184fa: or eax, 0x1
         // 004184fd: mov ds:[0x425b5c], eax
      [-]c74424????????00c705
         // 0041850e: mov ss:[esp+0x58], 0x0
         // 00418516: mov ds:[0x425b58], 0xf
      [-]420000e8
         // 00418531: call 0x401a40
      [-]feff83c404c7442450????????
         // 00418540: add esp, 0x4
         // 00418543: mov ss:[esp+0x50], 0xffffffffffffffff
      [-]00008bd083c40485d2744d
         // 00419c11: mov edx, eax
         // 00419c13: add esp, 0x4
         // 00419c16: test edx, edx
         // 00419c18: jz 0x419c67
      [-]803a00c7442440????????c74424????????00c644242c007504
         // 004182aa: cmp b1 ds:[edx], b1 0x0
         // 004182ad: mov ss:[esp+0x40], 0xf
         // 004182b5: mov ss:[esp+0x3c], 0x0
         // 004182bd: mov b1 ss:[esp+0x2c], b1 0x0
         // 004182c2: jnz 0x4182c8
      [-]33c9eb11
         // 004182c4: xor ecx, ecx
         // 004182c6: jmp 0x4182d9
      [-]8bca8d79018d4900
         // 004182c8: mov ecx, edx
         // 004182ca: lea edi, ds:[ecx+0x1]
         // 004182cd: lea ecx, ds:[ecx+0x0]
      [-]8a014184c075f9
         // 004182d0: mov b1 al, b1 ds:[ecx]
         // 004182d2: inc ecx
         // 004182d3: test b1 al, b1 al
         // 004182d5: jnz 0x4182d0
      [-]51528d4c2434e8
         // 00419c49: push ecx
         // 00419c4a: push edx
         // 00419c4b: lea ecx, ss:[esp+0x34]
         // 00419c4f: call ?assign@?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QAEAAV12@PBDI@Z
      [-]feff8d7c242cc7442450????????bb????????eb30
         // 00419c54: lea edi, ss:[esp+0x2c]
         // 00419c58: mov ss:[esp+0x50], 0x1
         // 00419c60: mov ebx, 0x1
         // 00419c65: jmp 0x419c97
      [-]6aff6a0068
         // 004185a7: push 0xffffffffffffffff
         // 004185a9: push 0x0
         // 004185ab: push 0x425b44
      [-]8d4c2420c7442434????????c74424????????00c644242000e8
         // 004185b0: lea ecx, ss:[esp+0x20]
         // 004185b4: mov ss:[esp+0x34], 0xf
         // 004185bc: mov ss:[esp+0x30], 0x0
         // 004185c4: mov b1 ss:[esp+0x20], b1 0x0
         // 004185c9: call 0x401910
      [-]feff8d7c2414bb????????
         // 004185ce: lea edi, ss:[esp+0x14]
         // 004185d2: mov ebx, 0x2
      [-]c74614????????c746????????00c60600837f1410895c24107313
         // 00418327: mov ds:[esi+0x14], 0xf
         // 0041832e: mov ds:[esi+0x10], 0x0
         // 00418335: mov b1 ds:[esi], b1 0x0
         // 00418338: cmp ds:[edi+0x14], 0x10
         // 0041833c: mov ss:[esp+0x10], ebx
         // 00418340: jnb 0x418355
      [-]8b4710407417
         // 00418342: mov eax, ds:[edi+0x10]
         // 00418345: inc eax
         // 00418346: jz 0x41835f
      [-]505756e8
         // 00419cb8: push eax
         // 00419cb9: push edi
         // 00419cba: push esi
         // 00419cbb: call _memmove_0
      [-]feff83c40ceb0a
         // 00419cc0: add esp, 0xc
         // 00419cc3: jmp 0x419ccf
      [-]8b078906c707????????
         // 00418355: mov eax, ds:[edi]
         // 00418357: mov ds:[esi], eax
         // 00418359: mov ds:[edi], 0x0
      [-]8b471083cb048946108b4714894614c74714????????c747????????00c60700f6c302742b
         // 0041835f: mov eax, ds:[edi+0x10]
         // 00418362: or ebx, 0x4
         // 00418365: mov ds:[esi+0x10], eax
         // 00418368: mov eax, ds:[edi+0x14]
         // 0041836b: mov ds:[esi+0x14], eax
         // 0041836e: mov ds:[edi+0x14], 0xf
         // 00418375: mov ds:[edi+0x10], 0x0
         // 0041837c: mov b1 ds:[edi], b1 0x0
         // 0041837f: test b1 bl, b1 0x2
         // 00418382: jz 0x4183af
      [-]83e3fd837c242810720c
         // 00418384: and ebx, 0xfffffffffffffffd
         // 00418387: cmp ss:[esp+0x28], 0x10
         // 0041838c: jb 0x41839a
      [-]ff742414e8
         // 00419cfe: push ss:[esp+0x14]
         // 00419d02: call j__free
      [-]feff83c404
         // 00419d07: add esp, 0x4
      [-]c7442428????????c74424????????00c644241400
         // 0041839a: mov ss:[esp+0x28], 0xf
         // 004183a2: mov ss:[esp+0x24], 0x0
         // 004183aa: mov b1 ss:[esp+0x14], b1 0x0
      [-]f6c3017413
         // 004183af: test b1 bl, b1 0x1
         // 004183b2: jz 0x4183c7
      [-]837c244010720c
         // 004183b4: cmp ss:[esp+0x40], 0x10
         // 004183b9: jb 0x4183c7
      [-]ff74242ce8
         // 00419d2b: push ss:[esp+0x2c]
         // 00419d2f: call j__free
      [-]feff83c404
         // 00419d34: add esp, 0x4
      [-]8bc68b4c244864890d????????595f5e5b8b4c243433cce8
         // 00419d37: mov eax, esi
         // 00419d39: mov ecx, ss:[esp+0x48]
         // 00419d3d: mov fs:[0x0], ecx
         // 00419d44: pop ecx
         // 00419d45: pop edi
         // 00419d46: pop esi
         // 00419d47: pop ebx
         // 00419d48: mov ecx, ss:[esp+0x34]
         // 00419d4c: xor ecx, esp
         // 00419d4e: call @__security_check_cookie@4
      [-]feff83c444c20800
         // 00419d53: add esp, 0x44
         // 00419d56: retn b2 0x8
      [-]64a1????????5083ec2ca1
         // 00419d67: mov eax, fs:[0x0]
         // 00419d6d: push eax
         // 00419d6e: sub esp, 0x2c
         // 00419d71: mov eax, ds:[___security_cookie]
      [-]33c48944242853555657a1
         // 00419d76: xor eax, esp
         // 00419d78: mov ss:[esp+0x28], eax
         // 00419d7c: push ebx
         // 00419d7d: push ebp
         // 00419d7e: push esi
         // 00419d7f: push edi
         // 00419d80: mov eax, ds:[___security_cookie]
      [-]33c4508d44244064a3????????8b6c24508d4424146a006a005068????????ff742464c74424????????006a0068????????896c2438c74424????????00ff15
         // 00419d85: xor eax, esp
         // 00419d87: push eax
         // 00419d88: lea eax, ss:[esp+0x40]
         // 00419d8c: mov fs:[0x0], eax
         // 00419d92: mov ebp, ss:[esp+0x50]
         // 00419d96: lea eax, ss:[esp+0x14]
         // 00419d9a: push 0x0
         // 00419d9c: push 0x0
         // 00419d9e: push eax
         // 00419d9f: push 0x400
         // 00419da4: push ss:[esp+0x64]
         // 00419da8: mov ss:[esp+0x2c], 0x0
         // 00419db0: push 0x0
         // 00419db2: push 0x1300
         // 00419db7: mov ss:[esp+0x38], ebp
         // 00419dbb: mov ss:[esp+0x30], 0x0
         // 00419dc3: call ds:[FormatMessageA]
      [-]8b74241489742420c7442448????????85c07528
         // 00419dc9: mov esi, ss:[esp+0x14]
         // 00419dcd: mov ss:[esp+0x20], esi
         // 00419dd1: mov ss:[esp+0x48], 0x1
         // 00419dd9: test eax, eax
         // 00419ddb: jnz 0x419e05
      [-]6a0dc74514????????8bcd89451068
         // 0041871d: push 0xd
         // 0041871f: mov ss:[ebp+0x14], 0xf
         // 00418726: mov ecx, ebp
         // 00418728: mov ss:[ebp+0x10], eax
         // 0041872b: push 0x4201ec
      [-]884500e8
         // 00418730: mov b1 ss:[ebp+0x0], b1 al
         // 00418733: call 0x401a40
      [-]feffc7442418????????e9da000000
         // 00418738: mov ss:[esp+0x18], 0x1
         // 00418740: jmp 0x41881f
      [-]c7442438????????c74424????????00c644242400803e007504
         // 00418495: mov ss:[esp+0x38], 0xf
         // 0041849d: mov ss:[esp+0x34], 0x0
         // 004184a5: mov b1 ss:[esp+0x24], b1 0x0
         // 004184aa: cmp b1 ds:[esi], b1 0x0
         // 004184ad: jnz 0x4184b3
      [-]33c9eb0e
         // 004184af: xor ecx, ecx
         // 004184b1: jmp 0x4184c1
      [-]8bce8d5101
         // 004184b3: mov ecx, esi
         // 004184b5: lea edx, ds:[ecx+0x1]
      [-]8a014184c075f9
         // 004184b8: mov b1 al, b1 ds:[ecx]
         // 004184ba: inc ecx
         // 004184bb: test b1 al, b1 al
         // 004184bd: jnz 0x4184b8
      [-]51568d4c242ce8
         // 00419e31: push ecx
         // 00419e32: push esi
         // 00419e33: lea ecx, ss:[esp+0x2c]
         // 00419e37: call ?assign@?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QAEAAV12@PBDI@Z
      [-]feff8b4c2434c64424480285c9745a
         // 00419e3c: mov ecx, ss:[esp+0x34]
         // 00419e40: mov b1 ss:[esp+0x48], b1 0x2
         // 00419e45: test ecx, ecx
         // 00419e47: jz 0x419ea3
      [-]8da424????????
         // 004184d9: lea esp, ss:[esp+0x0]
      [-]8b5424388d4424248b7c242483fa100f43c7807c08ff0a7415
         // 004184e0: mov edx, ss:[esp+0x38]
         // 004184e4: lea eax, ss:[esp+0x24]
         // 004184e8: mov edi, ss:[esp+0x24]
         // 004184ec: cmp edx, 0x10
         // 004184ef: cmovnb eax, edi
         // 004184f2: cmp b1 ds:[eax+ecx+0xffffffffffffffff], b1 0xa
         // 004184f7: jz 0x41850e
      [-]83fa108d4424240f43c7807c08ff0d0f8590000000
         // 004184f9: cmp edx, 0x10
         // 004184fc: lea eax, ss:[esp+0x24]
         // 00418500: cmovnb eax, edi
         // 00418503: cmp b1 ds:[eax+ecx+0xffffffffffffffff], b1 0xd
         // 00418508: jnz 0x41859e
      [-]8d59ff3bcb0f82ac000000
         // 0041850e: lea ebx, ds:[ecx+0xffffffffffffffff]
         // 00418511: cmp ecx, ebx
         // 00418513: jb 0x4185c5
      [-]83fa10895c24348d4424240f43c7c60418008b4c243485c975ad
         // 00418519: cmp edx, 0x10
         // 0041851c: mov ss:[esp+0x34], ebx
         // 00418520: lea eax, ss:[esp+0x24]
         // 00418524: cmovnb eax, edi
         // 00418527: mov b1 ds:[eax+ebx], b1 0x0
         // 0041852b: mov ecx, ss:[esp+0x34]
         // 0041852f: test ecx, ecx
         // 00418531: jnz 0x4184e0
      [-]8d4424248bcd50e8
         // 004187e3: lea eax, ss:[esp+0x24]
         // 004187e7: mov ecx, ebp
         // 004187e9: push eax
         // 004187ea: call 0x405ab0
      [-]feff837c243810c7442418????????720c
         // 004187ef: cmp ss:[esp+0x38], 0x10
         // 004187f4: mov ss:[esp+0x18], 0x1
         // 004187fc: jb 0x41880a
      [-]ff742424e8
         // 004187fe: push ss:[esp+0x24]
         // 00418802: call j__free
      [-]feff83c404
         // 00418807: add esp, 0x4
      [-]c7442438????????c74424????????00c644242400
         // 0041855a: mov ss:[esp+0x38], 0xf
         // 00418562: mov ss:[esp+0x34], 0x0
         // 0041856a: mov b1 ss:[esp+0x24], b1 0x0
      [-]56c644244c00ff15
         // 0041881f: push esi
         // 00418820: mov b1 ss:[esp+0x4c], b1 0x0
         // 00418825: call ds:[LocalFree]
      [-]41008bc58b4c244064890d????????595f5e5d5b8b4c242833cce8
         // 0041882b: mov eax, ebp
         // 0041882d: mov ecx, ss:[esp+0x40]
         // 00418831: mov fs:[0x0], ecx
         // 00418838: pop ecx
         // 00418839: pop edi
         // 0041883a: pop esi
         // 0041883b: pop ebp
         // 0041883c: pop ebx
         // 0041883d: mov ecx, ss:[esp+0x28]
         // 00418841: xor ecx, esp
         // 00418843: call @__security_check_cookie@4
      [-]feff83c438c20800
         // 00418848: add esp, 0x38
         // 0041884b: retn b2 0x8
      [-]85c97491
         // 0041859e: test ecx, ecx
         // 004185a0: jz 0x418533
      [-]83fa108d4424240f43c7807c08ff2e7580
         // 004185a2: cmp edx, 0x10
         // 004185a5: lea eax, ss:[esp+0x24]
         // 004185a9: cmovnb eax, edi
         // 004185ac: cmp b1 ds:[eax+ecx+0xffffffffffffffff], b1 0x2e
         // 004185b1: jnz 0x418533
      [-]8d41ff508d4c2428e8
         // 00419f23: lea eax, ds:[ecx+0xffffffffffffffff]
         // 00419f26: push eax
         // 00419f27: lea ecx, ss:[esp+0x28]
         // 00419f2b: call ?erase@?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QAEAAV12@I@Z
      [-]feffe96effffff
         // 00419f30: jmp 0x419ea3
      [-]8d4c2407e8
         // 00419531: lea ecx, ss:[esp+0x7]
         // 00419535: call 0x401310
      [-]8d4c240be8
         // 0041953f: lea ecx, ss:[esp+0xb]
         // 00419543: call 0x401300
      [-]feff8d4c2407e8
         // 00419548: lea ecx, ss:[esp+0x7]
         // 0041954c: call 0x401310
      [-]feff56e8
         // 00419551: push esi
         // 00419552: call j__free
      [-]feff83c4045e
         // 00419557: add esp, 0x4
         // 0041955a: pop esi
      [-]42000059c3
         // 00419576: pop ecx
         // 00419577: retn 

  }
  condition:
    all of them
}
