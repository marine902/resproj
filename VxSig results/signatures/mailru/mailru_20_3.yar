rule mailru_20_3 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         ffffc21000
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
      [-]558bec56
         // 004041c7: push ebp
         // 004041c8: mov ebp, esp
         // 004041cb: push esi
      [-]8b7d088bf183c70783e7f88b0e85c974
         // 004041cd: mov edi, ss:[ebp+0x8]
         // 004041d0: mov esi, ecx
         // 004041d2: add edi, 0x7
         // 004041da: and edi, 0xfffffffffffffff8
         // 004041dd: mov ecx, ds:[esi]
         // 004041df: test ecx, ecx
         // 004041e1: jz 0x4041f4
      [-]8b41048d1438
         // 00404c26: mov eax, ds:[ecx+0x4]
         // 00404c29: lea edx, ds:[eax+edi]
      [-]03c1895104
         // 004041ed: add eax, ecx
         // 004041ef: mov ds:[ecx+0x4], edx
      [-]83c7083b
         // 00404f64: add edi, 0x8
         // 00404f67: cmp edi, ecx
      [-]8bc70f46
         // 00404f69: mov eax, edi
         // 00404f6b: cmovbe eax, ecx
      [-]00008bc8
         // 00404f74: mov ecx, eax
      [-]8b0685c074
         // 00404c6e: mov eax, ds:[esi]
         // 00404c70: test eax, eax
         // 00404c72: jz 0x404c85
      [-]8b0089018b06
         // 00404218: mov eax, ds:[eax]
         // 0040421a: mov ds:[ecx], eax
         // 0040421c: mov eax, ds:[esi]
      [-]8b068901
         // 00404222: mov eax, ds:[esi]
         // 00404224: mov ds:[ecx], eax
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
         // 00407801: inc ecx
         // 00407802: push eax
         // 00407803: mov ds:[0x423028], ecx
      [-]85c07402
         // 0040780f: test eax, eax
         // 00407811: jz 0x407815
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
      [-]85c07518
         // 00409313: test eax, eax
         // 00409315: jnz 0x40932f
      [-]00008bf0ff15
         // 0040931d: mov esi, eax
         // 0040931f: call ds:[0x41a030]
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
      [-]56578945e433f68b450c568945e0ffd38bf8897de8e8
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
         // 00416b5c: mov eax, ds:[0x4261e0]
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
         // 004170ce: mov eax, ds:[0x4261e0]
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
      [-]64a1????????5056a1
         // 00419057: mov eax, fs:[0x0]
         // 0041905d: push eax
         // 0041905e: push esi
         // 0041905f: mov eax, ds:[0x4261e0]
      [-]33c4508d44240864a3????????8b74241c81fe????????0f8f6c020000
         // 00419064: xor eax, esp
         // 00419066: push eax
         // 00419067: lea eax, ss:[esp+0x8]
         // 0041906b: mov fs:[0x0], eax
         // 00419071: mov esi, ss:[esp+0x1c]
         // 00419075: cmp esi, 0x10b
         // 0041907b: jg 0x4192ed
      [-]0f8412020000
         // 00417771: jz 0x417989
      [-]81fe????????0f873b070000
         // 00417777: cmp esi, 0xd4
         // 0041777d: ja def_41778A
      [-]4100ff2485
         // 0041909a: jmp ds:[jpt_41909A+eax*0x4]
      [-]8b7424186a0056e8
         // 00417791: mov esi, ss:[esp+0x18]
         // 00417795: push 0x0
         // 00417797: push esi
         // 00417798: call 0x418180
      [-]000083c4088bc68b4c240864890d????????595e83c40cc20800
         // 0041779d: add esp, 0x8
         // 004177a0: mov eax, esi
         // 004177a2: mov ecx, ss:[esp+0x8]
         // 004177a6: mov fs:[0x0], ecx
         // 004177ad: pop ecx
         // 004177ae: pop esi
         // 004177af: add esp, 0xc
         // 004177b2: retn b2 0x8
      [-]8b7424186a1156e8
         // 004177b5: mov esi, ss:[esp+0x18]
         // 004177b9: push 0x11
         // 004177bb: push esi
         // 004177bc: call 0x418180
      [-]000083c4088bc68b4c240864890d????????595e83c40cc20800
         // 004177c1: add esp, 0x8
         // 004177c4: mov eax, esi
         // 004177c6: mov ecx, ss:[esp+0x8]
         // 004177ca: mov fs:[0x0], ecx
         // 004177d1: pop ecx
         // 004177d2: pop esi
         // 004177d3: add esp, 0xc
         // 004177d6: retn b2 0x8
      [-]8b7424186a1356e8
         // 004177d9: mov esi, ss:[esp+0x18]
         // 004177dd: push 0x13
         // 004177df: push esi
         // 004177e0: call 0x418180
      [-]09000083c4088bc68b4c240864890d????????595e83c40cc20800
         // 004177e5: add esp, 0x8
         // 004177e8: mov eax, esi
         // 004177ea: mov ecx, ss:[esp+0x8]
         // 004177ee: mov fs:[0x0], ecx
         // 004177f5: pop ecx
         // 004177f6: pop esi
         // 004177f7: add esp, 0xc
         // 004177fa: retn b2 0x8
      [-]8b7424186a2656e8
         // 004177fd: mov esi, ss:[esp+0x18]
         // 00417801: push 0x26
         // 00417803: push esi
         // 00417804: call 0x418180
      [-]09000083c4088bc68b4c240864890d????????595e83c40cc20800
         // 00417809: add esp, 0x8
         // 0041780c: mov eax, esi
         // 0041780e: mov ecx, ss:[esp+0x8]
         // 00417812: mov fs:[0x0], ecx
         // 00417819: pop ecx
         // 0041781a: pop esi
         // 0041781b: add esp, 0xc
         // 0041781e: retn b2 0x8
      [-]8b7424186a2956e8
         // 00417821: mov esi, ss:[esp+0x18]
         // 00417825: push 0x29
         // 00417827: push esi
         // 00417828: call 0x418180
      [-]09000083c4088bc68b4c240864890d????????595e83c40cc20800
         // 0041782d: add esp, 0x8
         // 00417830: mov eax, esi
         // 00417832: mov ecx, ss:[esp+0x8]
         // 00417836: mov fs:[0x0], ecx
         // 0041783d: pop ecx
         // 0041783e: pop esi
         // 0041783f: add esp, 0xc
         // 00417842: retn b2 0x8
      [-]8b7424186a1c56e8
         // 00417845: mov esi, ss:[esp+0x18]
         // 00417849: push 0x1c
         // 0041784b: push esi
         // 0041784c: call 0x418180
      [-]09000083c4088bc68b4c240864890d????????595e83c40cc20800
         // 00417851: add esp, 0x8
         // 00417854: mov eax, esi
         // 00417856: mov ecx, ss:[esp+0x8]
         // 0041785a: mov fs:[0x0], ecx
         // 00417861: pop ecx
         // 00417862: pop esi
         // 00417863: add esp, 0xc
         // 00417866: retn b2 0x8
      [-]8b7424186a0256e8
         // 00417869: mov esi, ss:[esp+0x18]
         // 0041786d: push 0x2
         // 0041786f: push esi
         // 00417870: call 0x418180
      [-]09000083c4088bc68b4c240864890d????????595e83c40cc20800
         // 00417875: add esp, 0x8
         // 00417878: mov eax, esi
         // 0041787a: mov ecx, ss:[esp+0x8]
         // 0041787e: mov fs:[0x0], ecx
         // 00417885: pop ecx
         // 00417886: pop esi
         // 00417887: add esp, 0xc
         // 0041788a: retn b2 0x8
      [-]8b7424186a2856e8
         // 0041788d: mov esi, ss:[esp+0x18]
         // 00417891: push 0x28
         // 00417893: push esi
         // 00417894: call 0x418180
      [-]000083c4088bc68b4c240864890d????????595e83c40cc20800
         // 00417899: add esp, 0x8
         // 0041789c: mov eax, esi
         // 0041789e: mov ecx, ss:[esp+0x8]
         // 004178a2: mov fs:[0x0], ecx
         // 004178a9: pop ecx
         // 004178aa: pop esi
         // 004178ab: add esp, 0xc
         // 004178ae: retn b2 0x8
      [-]8b7424186a1656e8
         // 004178b1: mov esi, ss:[esp+0x18]
         // 004178b5: push 0x16
         // 004178b7: push esi
         // 004178b8: call 0x418180
      [-]000083c4088bc68b4c240864890d????????595e83c40cc20800
         // 004178bd: add esp, 0x8
         // 004178c0: mov eax, esi
         // 004178c2: mov ecx, ss:[esp+0x8]
         // 004178c6: mov fs:[0x0], ecx
         // 004178cd: pop ecx
         // 004178ce: pop esi
         // 004178cf: add esp, 0xc
         // 004178d2: retn b2 0x8
      [-]8b7424186a2756e8
         // 004178d5: mov esi, ss:[esp+0x18]
         // 004178d9: push 0x27
         // 004178db: push esi
         // 004178dc: call 0x418180
      [-]08000083c4088bc68b4c240864890d????????595e83c40cc20800
         // 004178e1: add esp, 0x8
         // 004178e4: mov eax, esi
         // 004178e6: mov ecx, ss:[esp+0x8]
         // 004178ea: mov fs:[0x0], ecx
         // 004178f1: pop ecx
         // 004178f2: pop esi
         // 004178f3: add esp, 0xc
         // 004178f6: retn b2 0x8
      [-]8b7424186a0c56e8
         // 004178f9: mov esi, ss:[esp+0x18]
         // 004178fd: push 0xc
         // 004178ff: push esi
         // 00417900: call 0x418180
      [-]08000083c4088bc68b4c240864890d????????595e83c40cc20800
         // 00417905: add esp, 0x8
         // 00417908: mov eax, esi
         // 0041790a: mov ecx, ss:[esp+0x8]
         // 0041790e: mov fs:[0x0], ecx
         // 00417915: pop ecx
         // 00417916: pop esi
         // 00417917: add esp, 0xc
         // 0041791a: retn b2 0x8
      [-]8b7424186a0b56e8
         // 0041791d: mov esi, ss:[esp+0x18]
         // 00417921: push 0xb
         // 00417923: push esi
         // 00417924: call 0x418180
      [-]08000083c4088bc68b4c240864890d????????595e83c40cc20800
         // 00417929: add esp, 0x8
         // 0041792c: mov eax, esi
         // 0041792e: mov ecx, ss:[esp+0x8]
         // 00417932: mov fs:[0x0], ecx
         // 00417939: pop ecx
         // 0041793a: pop esi
         // 0041793b: add esp, 0xc
         // 0041793e: retn b2 0x8
      [-]8b7424186a1256e8
         // 00417941: mov esi, ss:[esp+0x18]
         // 00417945: push 0x12
         // 00417947: push esi
         // 00417948: call 0x418180
      [-]08000083c4088bc68b4c240864890d????????595e83c40cc20800
         // 0041794d: add esp, 0x8
         // 00417950: mov eax, esi
         // 00417952: mov ecx, ss:[esp+0x8]
         // 00417956: mov fs:[0x0], ecx
         // 0041795d: pop ecx
         // 0041795e: pop esi
         // 0041795f: add esp, 0xc
         // 00417962: retn b2 0x8
      [-]8b7424186a1856e8
         // 00417965: mov esi, ss:[esp+0x18]
         // 00417969: push 0x18
         // 0041796b: push esi
         // 0041796c: call 0x418180
      [-]08000083c4088bc68b4c240864890d????????595e83c40cc20800
         // 00417971: add esp, 0x8
         // 00417974: mov eax, esi
         // 00417976: mov ecx, ss:[esp+0x8]
         // 0041797a: mov fs:[0x0], ecx
         // 00417981: pop ecx
         // 00417982: pop esi
         // 00417983: add esp, 0xc
         // 00417986: retn b2 0x8
      [-]a8017527
         // 00417c3e: test b1 al, b1 0x1
         // 00417c40: jnz 0x417c69
      [-]83c801a3
         // 004192a2: or eax, 0x1
         // 004192a5: mov ds:[0x4291bc], eax
      [-]c74424????????00c705
         // 004192af: mov ss:[esp+0x14], 0x0
         // 004192b7: mov ds:[0x4291b8], 0x4222e4
      [-]feff83c404
         // 004192c6: add esp, 0x4
      [-]8b442418c700????????c74004
         // 00417c69: mov eax, ss:[esp+0x18]
         // 00417c6d: mov ds:[eax], 0x16
         // 00417c73: mov ds:[eax+0x4], 0x425b68
      [-]8b4c240864890d????????595e83c40cc20800
         // 00417c7a: mov ecx, ss:[esp+0x8]
         // 00417c7e: mov fs:[0x0], ecx
         // 00417c85: pop ecx
         // 00417c86: pop esi
         // 00417c87: add esp, 0xc
         // 00417c8a: retn b2 0x8
      [-]81fe????????0f8fda000000
         // 004179dd: cmp esi, 0x2714
         // 004179e3: jg 0x417ac3
      [-]0f84b0000000
         // 004179e9: jz 0x417a9f
      [-]81fe????????7f67
         // 004179ef: cmp esi, 0x3f5
         // 004179f5: jg 0x417a5e
      [-]8d86????????83f8110f87b6040000
         // 004179f9: lea eax, ds:[esi+0xfffffffffffffc1d]
         // 004179ff: cmp eax, 0x11
         // 00417a02: ja def_41778A
      [-]4100ff2485
         // 0041931f: jmp ds:[jpt_41931F+eax*0x4]
      [-]8b7424186a0556e8
         // 00417a16: mov esi, ss:[esp+0x18]
         // 00417a1a: push 0x5
         // 00417a1c: push esi
         // 00417a1d: call 0x418180
      [-]07000083c4088bc68b4c240864890d????????595e83c40cc20800
         // 00417a22: add esp, 0x8
         // 00417a25: mov eax, esi
         // 00417a27: mov ecx, ss:[esp+0x8]
         // 00417a2b: mov fs:[0x0], ecx
         // 00417a32: pop ecx
         // 00417a33: pop esi
         // 00417a34: add esp, 0xc
         // 00417a37: retn b2 0x8
      [-]8b7424186a6956e8
         // 00417a3a: mov esi, ss:[esp+0x18]
         // 00417a3e: push 0x69
         // 00417a40: push esi
         // 00417a41: call 0x418180
      [-]07000083c4088bc68b4c240864890d????????595e83c40cc20800
         // 00417a46: add esp, 0x8
         // 00417a49: mov eax, esi
         // 00417a4b: mov ecx, ss:[esp+0x8]
         // 00417a4f: mov fs:[0x0], ecx
         // 00417a56: pop ecx
         // 00417a57: pop esi
         // 00417a58: add esp, 0xc
         // 00417a5b: retn b2 0x8
      [-]8bc62d????????0f84b2feffff
         // 00417a5e: mov eax, esi
         // 00417a60: sub eax, 0x4d5
         // 00417a65: jz 0x41791d
      [-]2d????????7409
         // 00417a6b: sub eax, 0x48c
         // 00417a70: jz 0x417a7b
      [-]83e8030f8543040000
         // 00417a72: sub eax, 0x3
         // 00417a75: jnz def_41778A
      [-]8b7424186a1056e8
         // 00417a7b: mov esi, ss:[esp+0x18]
         // 00417a7f: push 0x10
         // 00417a81: push esi
         // 00417a82: call 0x418180
      [-]000083c4088bc68b4c240864890d????????595e83c40cc20800
         // 00417a87: add esp, 0x8
         // 00417a8a: mov eax, esi
         // 00417a8c: mov ecx, ss:[esp+0x8]
         // 00417a90: mov fs:[0x0], ecx
         // 00417a97: pop ecx
         // 00417a98: pop esi
         // 00417a99: add esp, 0xc
         // 00417a9c: retn b2 0x8
      [-]8b7424186a0456e8
         // 00417a9f: mov esi, ss:[esp+0x18]
         // 00417aa3: push 0x4
         // 00417aa5: push esi
         // 00417aa6: call 0x418180
      [-]000083c4088bc68b4c240864890d????????595e83c40cc20800
         // 00417aab: add esp, 0x8
         // 00417aae: mov eax, esi
         // 00417ab0: mov ecx, ss:[esp+0x8]
         // 00417ab4: mov fs:[0x0], ecx
         // 00417abb: pop ecx
         // 00417abc: pop esi
         // 00417abd: add esp, 0xc
         // 00417ac0: retn b2 0x8
      [-]8d86????????83f8380f87ec030000
         // 00417ac3: lea eax, ds:[esi+0xffffffffffffd8e7]
         // 00417ac9: cmp eax, 0x38
         // 00417acc: ja def_41778A
      [-]4100ff2485
         // 004193e9: jmp ds:[jpt_4193E9+eax*0x4]
      [-]8b7424186a0d56e8
         // 00417ae0: mov esi, ss:[esp+0x18]
         // 00417ae4: push 0xd
         // 00417ae6: push esi
         // 00417ae7: call 0x418180
      [-]06000083c4088bc68b4c240864890d????????595e83c40cc20800
         // 00417aec: add esp, 0x8
         // 00417aef: mov eax, esi
         // 00417af1: mov ecx, ss:[esp+0x8]
         // 00417af5: mov fs:[0x0], ecx
         // 00417afc: pop ecx
         // 00417afd: pop esi
         // 00417afe: add esp, 0xc
         // 00417b01: retn b2 0x8
      [-]8b7424186a6456e8
         // 00417b04: mov esi, ss:[esp+0x18]
         // 00417b08: push 0x64
         // 00417b0a: push esi
         // 00417b0b: call 0x418180
      [-]06000083c4088bc68b4c240864890d????????595e83c40cc20800
         // 00417b10: add esp, 0x8
         // 00417b13: mov eax, esi
         // 00417b15: mov ecx, ss:[esp+0x8]
         // 00417b19: mov fs:[0x0], ecx
         // 00417b20: pop ecx
         // 00417b21: pop esi
         // 00417b22: add esp, 0xc
         // 00417b25: retn b2 0x8
      [-]8b7424186a6556e8
         // 00417b28: mov esi, ss:[esp+0x18]
         // 00417b2c: push 0x65
         // 00417b2e: push esi
         // 00417b2f: call 0x418180
      [-]06000083c4088bc68b4c240864890d????????595e83c40cc20800
         // 00417b34: add esp, 0x8
         // 00417b37: mov eax, esi
         // 00417b39: mov ecx, ss:[esp+0x8]
         // 00417b3d: mov fs:[0x0], ecx
         // 00417b44: pop ecx
         // 00417b45: pop esi
         // 00417b46: add esp, 0xc
         // 00417b49: retn b2 0x8
      [-]8b7424186a6656e8
         // 00417b4c: mov esi, ss:[esp+0x18]
         // 00417b50: push 0x66
         // 00417b52: push esi
         // 00417b53: call 0x418180
      [-]06000083c4088bc68b4c240864890d????????595e83c40cc20800
         // 00417b58: add esp, 0x8
         // 00417b5b: mov eax, esi
         // 00417b5d: mov ecx, ss:[esp+0x8]
         // 00417b61: mov fs:[0x0], ecx
         // 00417b68: pop ecx
         // 00417b69: pop esi
         // 00417b6a: add esp, 0xc
         // 00417b6d: retn b2 0x8
      [-]8b7424186a6756e8
         // 00417b70: mov esi, ss:[esp+0x18]
         // 00417b74: push 0x67
         // 00417b76: push esi
         // 00417b77: call 0x418180
      [-]06000083c4088bc68b4c240864890d????????595e83c40cc20800
         // 00417b7c: add esp, 0x8
         // 00417b7f: mov eax, esi
         // 00417b81: mov ecx, ss:[esp+0x8]
         // 00417b85: mov fs:[0x0], ecx
         // 00417b8c: pop ecx
         // 00417b8d: pop esi
         // 00417b8e: add esp, 0xc
         // 00417b91: retn b2 0x8
      [-]8b7424186a0956e8
         // 00417b94: mov esi, ss:[esp+0x18]
         // 00417b98: push 0x9
         // 00417b9a: push esi
         // 00417b9b: call 0x418180
      [-]000083c4088bc68b4c240864890d????????595e83c40cc20800
         // 00417ba0: add esp, 0x8
         // 00417ba3: mov eax, esi
         // 00417ba5: mov ecx, ss:[esp+0x8]
         // 00417ba9: mov fs:[0x0], ecx
         // 00417bb0: pop ecx
         // 00417bb1: pop esi
         // 00417bb2: add esp, 0xc
         // 00417bb5: retn b2 0x8
      [-]8b7424186a6a56e8
         // 00417bb8: mov esi, ss:[esp+0x18]
         // 00417bbc: push 0x6a
         // 00417bbe: push esi
         // 00417bbf: call 0x418180
      [-]000083c4088bc68b4c240864890d????????595e83c40cc20800
         // 00417bc4: add esp, 0x8
         // 00417bc7: mov eax, esi
         // 00417bc9: mov ecx, ss:[esp+0x8]
         // 00417bcd: mov fs:[0x0], ecx
         // 00417bd4: pop ecx
         // 00417bd5: pop esi
         // 00417bd6: add esp, 0xc
         // 00417bd9: retn b2 0x8
      [-]8b7424186a6b56e8
         // 00417bdc: mov esi, ss:[esp+0x18]
         // 00417be0: push 0x6b
         // 00417be2: push esi
         // 00417be3: call 0x418180
      [-]05000083c4088bc68b4c240864890d????????595e83c40cc20800
         // 00417be8: add esp, 0x8
         // 00417beb: mov eax, esi
         // 00417bed: mov ecx, ss:[esp+0x8]
         // 00417bf1: mov fs:[0x0], ecx
         // 00417bf8: pop ecx
         // 00417bf9: pop esi
         // 00417bfa: add esp, 0xc
         // 00417bfd: retn b2 0x8
      [-]8b7424186a6c56e8
         // 00417c00: mov esi, ss:[esp+0x18]
         // 00417c04: push 0x6c
         // 00417c06: push esi
         // 00417c07: call 0x418180
      [-]05000083c4088bc68b4c240864890d????????595e83c40cc20800
         // 00417c0c: add esp, 0x8
         // 00417c0f: mov eax, esi
         // 00417c11: mov ecx, ss:[esp+0x8]
         // 00417c15: mov fs:[0x0], ecx
         // 00417c1c: pop ecx
         // 00417c1d: pop esi
         // 00417c1e: add esp, 0xc
         // 00417c21: retn b2 0x8
      [-]8b7424186a6d56e8
         // 00417c24: mov esi, ss:[esp+0x18]
         // 00417c28: push 0x6d
         // 00417c2a: push esi
         // 00417c2b: call 0x418180
      [-]05000083c4088bc68b4c240864890d????????595e83c40cc20800
         // 00417c30: add esp, 0x8
         // 00417c33: mov eax, esi
         // 00417c35: mov ecx, ss:[esp+0x8]
         // 00417c39: mov fs:[0x0], ecx
         // 00417c40: pop ecx
         // 00417c41: pop esi
         // 00417c42: add esp, 0xc
         // 00417c45: retn b2 0x8
      [-]8b7424186a0e56e8
         // 00417c48: mov esi, ss:[esp+0x18]
         // 00417c4c: push 0xe
         // 00417c4e: push esi
         // 00417c4f: call 0x418180
      [-]05000083c4088bc68b4c240864890d????????595e83c40cc20800
         // 00417c54: add esp, 0x8
         // 00417c57: mov eax, esi
         // 00417c59: mov ecx, ss:[esp+0x8]
         // 00417c5d: mov fs:[0x0], ecx
         // 00417c64: pop ecx
         // 00417c65: pop esi
         // 00417c66: add esp, 0xc
         // 00417c69: retn b2 0x8
      [-]8b7424186a6e56e8
         // 00417c6c: mov esi, ss:[esp+0x18]
         // 00417c70: push 0x6e
         // 00417c72: push esi
         // 00417c73: call 0x418180
      [-]05000083c4088bc68b4c240864890d????????595e83c40cc20800
         // 00417c78: add esp, 0x8
         // 00417c7b: mov eax, esi
         // 00417c7d: mov ecx, ss:[esp+0x8]
         // 00417c81: mov fs:[0x0], ecx
         // 00417c88: pop ecx
         // 00417c89: pop esi
         // 00417c8a: add esp, 0xc
         // 00417c8d: retn b2 0x8
      [-]8b7424186a7056e8
         // 00417c90: mov esi, ss:[esp+0x18]
         // 00417c94: push 0x70
         // 00417c96: push esi
         // 00417c97: call 0x418180
      [-]000083c4088bc68b4c240864890d????????595e83c40cc20800
         // 00417c9c: add esp, 0x8
         // 00417c9f: mov eax, esi
         // 00417ca1: mov ecx, ss:[esp+0x8]
         // 00417ca5: mov fs:[0x0], ecx
         // 00417cac: pop ecx
         // 00417cad: pop esi
         // 00417cae: add esp, 0xc
         // 00417cb1: retn b2 0x8
      [-]8b7424186a7156e8
         // 00417cb4: mov esi, ss:[esp+0x18]
         // 00417cb8: push 0x71
         // 00417cba: push esi
         // 00417cbb: call 0x418180
      [-]000083c4088bc68b4c240864890d????????595e83c40cc20800
         // 00417cc0: add esp, 0x8
         // 00417cc3: mov eax, esi
         // 00417cc5: mov ecx, ss:[esp+0x8]
         // 00417cc9: mov fs:[0x0], ecx
         // 00417cd0: pop ecx
         // 00417cd1: pop esi
         // 00417cd2: add esp, 0xc
         // 00417cd5: retn b2 0x8
      [-]8b7424186a7356e8
         // 00417cd8: mov esi, ss:[esp+0x18]
         // 00417cdc: push 0x73
         // 00417cde: push esi
         // 00417cdf: call 0x418180
      [-]04000083c4088bc68b4c240864890d????????595e83c40cc20800
         // 00417ce4: add esp, 0x8
         // 00417ce7: mov eax, esi
         // 00417ce9: mov ecx, ss:[esp+0x8]
         // 00417ced: mov fs:[0x0], ecx
         // 00417cf4: pop ecx
         // 00417cf5: pop esi
         // 00417cf6: add esp, 0xc
         // 00417cf9: retn b2 0x8
      [-]8b7424186a7456e8
         // 00417cfc: mov esi, ss:[esp+0x18]
         // 00417d00: push 0x74
         // 00417d02: push esi
         // 00417d03: call 0x418180
      [-]04000083c4088bc68b4c240864890d????????595e83c40cc20800
         // 00417d08: add esp, 0x8
         // 00417d0b: mov eax, esi
         // 00417d0d: mov ecx, ss:[esp+0x8]
         // 00417d11: mov fs:[0x0], ecx
         // 00417d18: pop ecx
         // 00417d19: pop esi
         // 00417d1a: add esp, 0xc
         // 00417d1d: retn b2 0x8
      [-]8b7424186a7556e8
         // 00417d20: mov esi, ss:[esp+0x18]
         // 00417d24: push 0x75
         // 00417d26: push esi
         // 00417d27: call 0x418180
      [-]04000083c4088bc68b4c240864890d????????595e83c40cc20800
         // 00417d2c: add esp, 0x8
         // 00417d2f: mov eax, esi
         // 00417d31: mov ecx, ss:[esp+0x8]
         // 00417d35: mov fs:[0x0], ecx
         // 00417d3c: pop ecx
         // 00417d3d: pop esi
         // 00417d3e: add esp, 0xc
         // 00417d41: retn b2 0x8
      [-]8b7424186a7656e8
         // 00417d44: mov esi, ss:[esp+0x18]
         // 00417d48: push 0x76
         // 00417d4a: push esi
         // 00417d4b: call 0x418180
      [-]04000083c4088bc68b4c240864890d????????595e83c40cc20800
         // 00417d50: add esp, 0x8
         // 00417d53: mov eax, esi
         // 00417d55: mov ecx, ss:[esp+0x8]
         // 00417d59: mov fs:[0x0], ecx
         // 00417d60: pop ecx
         // 00417d61: pop esi
         // 00417d62: add esp, 0xc
         // 00417d65: retn b2 0x8
      [-]8b7424186a7756e8
         // 00417d68: mov esi, ss:[esp+0x18]
         // 00417d6c: push 0x77
         // 00417d6e: push esi
         // 00417d6f: call 0x418180
      [-]04000083c4088bc68b4c240864890d????????595e83c40cc20800
         // 00417d74: add esp, 0x8
         // 00417d77: mov eax, esi
         // 00417d79: mov ecx, ss:[esp+0x8]
         // 00417d7d: mov fs:[0x0], ecx
         // 00417d84: pop ecx
         // 00417d85: pop esi
         // 00417d86: add esp, 0xc
         // 00417d89: retn b2 0x8
      [-]8b7424186a7b56e8
         // 00417d8c: mov esi, ss:[esp+0x18]
         // 00417d90: push 0x7b
         // 00417d92: push esi
         // 00417d93: call 0x418180
      [-]000083c4088bc68b4c240864890d????????595e83c40cc20800
         // 00417d98: add esp, 0x8
         // 00417d9b: mov eax, esi
         // 00417d9d: mov ecx, ss:[esp+0x8]
         // 00417da1: mov fs:[0x0], ecx
         // 00417da8: pop ecx
         // 00417da9: pop esi
         // 00417daa: add esp, 0xc
         // 00417dad: retn b2 0x8
      [-]8b7424186a7e56e8
         // 00417db0: mov esi, ss:[esp+0x18]
         // 00417db4: push 0x7e
         // 00417db6: push esi
         // 00417db7: call 0x418180
      [-]000083c4088bc68b4c240864890d????????595e83c40cc20800
         // 00417dbc: add esp, 0x8
         // 00417dbf: mov eax, esi
         // 00417dc1: mov ecx, ss:[esp+0x8]
         // 00417dc5: mov fs:[0x0], ecx
         // 00417dcc: pop ecx
         // 00417dcd: pop esi
         // 00417dce: add esp, 0xc
         // 00417dd1: retn b2 0x8
      [-]8b74241868????????56e8
         // 00417dd4: mov esi, ss:[esp+0x18]
         // 00417dd8: push 0x80
         // 00417ddd: push esi
         // 00417dde: call 0x418180
      [-]03000083c4088bc68b4c240864890d????????595e83c40cc20800
         // 00417de3: add esp, 0x8
         // 00417de6: mov eax, esi
         // 00417de8: mov ecx, ss:[esp+0x8]
         // 00417dec: mov fs:[0x0], ecx
         // 00417df3: pop ecx
         // 00417df4: pop esi
         // 00417df5: add esp, 0xc
         // 00417df8: retn b2 0x8
      [-]8b74241868????????56e8
         // 00417dfb: mov esi, ss:[esp+0x18]
         // 00417dff: push 0x82
         // 00417e04: push esi
         // 00417e05: call 0x418180
      [-]03000083c4088bc68b4c240864890d????????595e83c40cc20800
         // 00417e0a: add esp, 0x8
         // 00417e0d: mov eax, esi
         // 00417e0f: mov ecx, ss:[esp+0x8]
         // 00417e13: mov fs:[0x0], ecx
         // 00417e1a: pop ecx
         // 00417e1b: pop esi
         // 00417e1c: add esp, 0xc
         // 00417e1f: retn b2 0x8
      [-]8b74241868????????56e8
         // 00417e22: mov esi, ss:[esp+0x18]
         // 00417e26: push 0x87
         // 00417e2b: push esi
         // 00417e2c: call 0x418180
      [-]03000083c4088bc68b4c240864890d????????595e83c40cc20800
         // 00417e31: add esp, 0x8
         // 00417e34: mov eax, esi
         // 00417e36: mov ecx, ss:[esp+0x8]
         // 00417e3a: mov fs:[0x0], ecx
         // 00417e41: pop ecx
         // 00417e42: pop esi
         // 00417e43: add esp, 0xc
         // 00417e46: retn b2 0x8
      [-]8b74241868????????56e8
         // 00417e49: mov esi, ss:[esp+0x18]
         // 00417e4d: push 0x88
         // 00417e52: push esi
         // 00417e53: call 0x418180
      [-]03000083c4088bc68b4c240864890d????????595e83c40cc20800
         // 00417e58: add esp, 0x8
         // 00417e5b: mov eax, esi
         // 00417e5d: mov ecx, ss:[esp+0x8]
         // 00417e61: mov fs:[0x0], ecx
         // 00417e68: pop ecx
         // 00417e69: pop esi
         // 00417e6a: add esp, 0xc
         // 00417e6d: retn b2 0x8
      [-]8b74241868????????56e8
         // 00417e70: mov esi, ss:[esp+0x18]
         // 00417e74: push 0x8a
         // 00417e79: push esi
         // 00417e7a: call 0x418180
      [-]03000083c4088bc68b4c240864890d????????595e83c40cc20800
         // 00417e7f: add esp, 0x8
         // 00417e82: mov eax, esi
         // 00417e84: mov ecx, ss:[esp+0x8]
         // 00417e88: mov fs:[0x0], ecx
         // 00417e8f: pop ecx
         // 00417e90: pop esi
         // 00417e91: add esp, 0xc
         // 00417e94: retn b2 0x8
      [-]8b74241868????????56e8
         // 00417e97: mov esi, ss:[esp+0x18]
         // 00417e9b: push 0x8c
         // 00417ea0: push esi
         // 00417ea1: call 0x418180
      [-]000083c4088bc68b4c240864890d????????595e83c40cc20800
         // 00417ea6: add esp, 0x8
         // 00417ea9: mov eax, esi
         // 00417eab: mov ecx, ss:[esp+0x8]
         // 00417eaf: mov fs:[0x0], ecx
         // 00417eb6: pop ecx
         // 00417eb7: pop esi
         // 00417eb8: add esp, 0xc
         // 00417ebb: retn b2 0x8
      [-]a8017527
         // 00418173: test b1 al, b1 0x1
         // 00418175: jnz 0x41819e
      [-]83c801a3
         // 00418177: or eax, 0x1
         // 0041817a: mov ds:[0x425b64], eax
      [-]c7442414????????c705
         // 00418184: mov ss:[esp+0x14], 0x1
         // 0041818c: mov ds:[0x425b60], 0x4201d4
      [-]feff83c404
         // 0041819b: add esp, 0x4
      [-]8b4424188930c74004
         // 0041819e: mov eax, ss:[esp+0x18]
         // 004181a2: mov ds:[eax], esi
         // 004181a4: mov ds:[eax+0x4], 0x425b60
      [-]8b4c240864890d????????595e83c40cc20800
         // 004181ab: mov ecx, ss:[esp+0x8]
         // 004181af: mov fs:[0x0], ecx
         // 004181b6: pop ecx
         // 004181b7: pop esi
         // 004181b8: add esp, 0xc
         // 004181bb: retn b2 0x8
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
      [-]51528d4c2434
         // 00419c49: push ecx
         // 00419c4a: push edx
         // 00419c4b: lea ecx, ss:[esp+0x34]
         // 00419c4f: call ?assign@?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QAEAAV12@PBDI@Z

  }
  condition:
    all of them
}
