rule mailru_30_2 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         837d0cff7614
         // 004037f3: cmp ss:[ebp+0xc], 0xffffffffffffffff
         // 004037f7: jbe 0x40380d
      [-]8b450833c90b4d0c99
         // 004044bd: mov eax, ss:[ebp+0x8]
         // 004044c0: xor ecx, ecx
         // 004044c2: or ecx, ss:[ebp+0xc]
         // 004044c5: cdq 
      [-]558bec8b450c568bf1
         // 00403b72: push ebp
         // 00403b73: mov ebp, esp
         // 00403b75: mov eax, ss:[ebp+0xc]
         // 00403b78: push esi
         // 00403b79: mov esi, ecx
      [-]8bc65e5dc20800
         // 00403b9a: mov eax, esi
         // 00403b9c: pop esi
         // 00403b9d: pop ebp
         // 00403b9e: retn b2 0x8
      [-]558bec6a00ff7508ff15
         // 00406f80: push ebp
         // 00406f81: mov ebp, esp
         // 00406f83: push 0x0
         // 00406f85: push ss:[ebp+0x8]
         // 00406f88: call ds:[CryptReleaseContext]
      [-]8b0985c97411
         // 004060ce: mov ecx, ds:[ecx]
         // 004060d0: test ecx, ecx
         // 004060d2: jz 0x4060e5
      [-]8b01ff500885c07408
         // 004060d4: mov eax, ds:[ecx]
         // 004060d6: call ds:[eax+0x8]
         // 004060d9: test eax, eax
         // 004060db: jz 0x4060e5
      [-]8b108bc86a01ff12
         // 004060dd: mov edx, ds:[eax]
         // 004060df: mov ecx, eax
         // 004060e1: push 0x1
         // 004060e3: call ds:[edx]
      [-]558bec8b450883e8007418
         // 00406af9: push ebp
         // 00406afa: mov ebp, esp
         // 00406afc: mov eax, ss:[ebp+0x8]
         // 00406aff: sub eax, 0x0
         // 00406b02: jz 0x406b1c
      [-]33c05dc3
         // 00406b0a: xor eax, eax
         // 00406b0c: pop ebp
         // 00406b0d: retn 
      [-]b8????????5dc3
         // 00406b0e: mov eax, 0x8003
         // 00406b13: pop ebp
         // 00406b14: retn 
      [-]b8????????5dc3
         // 00406b15: mov eax, 0x800c
         // 00406b1a: pop ebp
         // 00406b1b: retn 
      [-]b8????????5dc3
         // 00406b1c: mov eax, 0x8004
         // 00406b21: pop ebp
         // 00406b22: retn 
      [-]558bec833d
         // 00407711: push ebp
         // 00407712: mov ebp, esp
         // 00407714: cmp ds:[0x41aaec], 0x0
      [-]3908740d
         // 0040830a: cmp ds:[eax], ecx
         // 0040830c: jz 0x40831b
      [-]83c0088378040075f3
         // 0040830e: add eax, 0x8
         // 00408311: cmp ds:[eax+0x4], 0x0
         // 00408315: jnz 0x40830a
      [-]33c05dc3
         // 00408317: xor eax, eax
         // 00408319: pop ebp
         // 0040831a: retn 
      [-]8b40045dc3
         // 0040831b: mov eax, ds:[eax+0x4]
         // 0040831e: pop ebp
         // 0040831f: retn 
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
         // 004077cd: test esi, esi
         // 004077cf: jnz 0x4077b2
      [-]000059c3
         // 004088b0: pop ecx
         // 004088b1: retn 
      [-]558bec837d0800742d
         // 0040b8db: push ebp
         // 0040b8dc: mov ebp, esp
         // 0040b8de: cmp ss:[ebp+0x8], 0x0
         // 0040b8e2: jz 0x40b911
      [-]ff75086a00ff35
         // 0040b8e4: push ss:[ebp+0x8]
         // 0040b8e7: push 0x0
         // 0040b8e9: push ds:[0x428d30]
      [-]85c07518
         // 0040b8f5: test eax, eax
         // 0040b8f7: jnz 0x40b911
      [-]00008bf0ff15
         // 0040931d: mov esi, eax
         // 0040931f: call ds:[0x41a030]
      [-]e996000000
         // 004091fc: jmp ?_Tidy@exception@std@@AAEXXZ
      [-]568bf1807e08007409
         // 0040bc7a: push esi
         // 0040bc7b: mov esi, ecx
         // 0040bc7d: cmp b1 ds:[esi+0x8], b1 0x0
         // 0040bc81: jz 0x40bc8c
      [-]ff7604e8
         // 0040bc83: push ds:[esi+0x4]
         // 0040bc86: call _free
      [-]6a01e85b00000059c3
         // 0040be30: push 0x1
         // 0040be32: call _flsall
         // 0040be37: pop ecx
         // 0040be38: retn 
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
         // 00412e46: mov eax, ds:[esi]
         // 00412e48: test eax, eax
         // 00412e4a: jz 0x412e4e
      [-]3bf772f1
         // 00412e51: cmp esi, edi
         // 00412e53: jb 0x412e46
      [-]8b0685c07402
         // 00412e66: mov eax, ds:[esi]
         // 00412e68: test eax, eax
         // 00412e6a: jz 0x412e6e
      [-]3bf772f1
         // 00412e71: cmp esi, edi
         // 00412e73: jb 0x412e66
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
         // 00416bae: mov esi, ebx
         // 00416bb0: mov eax, ebx
      [-]33c08d7df0ab
         // 00416bc3: xor eax, eax
         // 00416bc5: lea edi, ss:[ebp+0xfffffffffffffff0]
         // 00416bc8: stosdd 
      [-]6a025be9a6040000
         // 00416bcb: push 0x2
         // 00416bcd: pop ebx
         // 00416bce: jmp 0x417079
      [-]8d75f08d7de48955dca5488945cc6a1f895dd4a58d48018bc199a55e23d603d0c1fa058955c481e1????????7905
         // 00416bd8: lea esi, ss:[ebp+0xfffffffffffffff0]
         // 00416bdb: lea edi, ss:[ebp+0xffffffffffffffe4]
         // 00416bde: mov ss:[ebp+0xffffffffffffffdc], edx
         // 00416be1: movsdd 
         // 00416be2: dec eax
         // 00416be3: mov ss:[ebp+0xffffffffffffffcc], eax
         // 00416be6: push 0x1f
         // 00416be8: mov ss:[ebp+0xffffffffffffffd4], ebx
         // 00416beb: movsdd 
         // 00416bec: lea ecx, ds:[eax+0x1]
         // 00416bef: mov eax, ecx
         // 00416bf1: cdq 
         // 00416bf2: movsdd 
         // 00416bf3: pop esi
         // 00416bf4: and edx, esi
         // 00416bf6: add edx, eax
         // 00416bf8: sar edx, b1 0x5
         // 00416bfb: mov ss:[ebp+0xffffffffffffffc4], edx
         // 00416bfe: and ecx, 0xffffffff8000001f
         // 00416c04: jns 0x416c0b
      [-]4983c9e041
         // 00416c06: dec ecx
         // 00416c07: or ecx, 0xffffffffffffffe0
         // 00416c0a: inc ecx
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
         // 00416c39: inc edx
         // 00416c3a: cmp edx, esi
         // 00416c3c: jl 0x416c33
      [-]8b45cc996a1f5923d103d08b45ccc1fa0525????????7905
         // 00416c43: mov eax, ss:[ebp+0xffffffffffffffcc]
         // 00416c46: cdq 
         // 00416c47: push 0x1f
         // 00416c49: pop ecx
         // 00416c4a: and edx, ecx
         // 00416c4c: add edx, eax
         // 00416c4e: mov eax, ss:[ebp+0xffffffffffffffcc]
         // 00416c51: sar edx, b1 0x5
         // 00416c54: and eax, 0xffffffff8000001f
         // 00416c59: jns 0x416c60
      [-]4883c8e040
         // 00416c5b: dec eax
         // 00416c5c: or eax, 0xffffffffffffffe0
         // 00416c5f: inc eax
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
         // 00416c85: cmp eax, ss:[ebp+0xffffffffffffffc8]
         // 00416c88: jnb 0x416c90
      [-]33c941894dd4
         // 00416c8a: xor ecx, ecx
         // 00416c8c: inc ecx
         // 00416c8d: mov ss:[ebp+0xffffffffffffffd4], ecx
      [-]894495f04a782e
         // 00416c90: mov ss:[ebp+edx*0x4], eax
         // 00416c94: dec edx
         // 00416c95: js 0x416cc5
      [-]85c97427
         // 00416c97: test ecx, ecx
         // 00416c99: jz 0x416cc2
      [-]8b4495f0
         // 00416c9b: mov eax, ss:[ebp+edx*0x4]
      [-]8bc77205
         // 00416cac: mov eax, edi
         // 00416cae: jb 0x416cb5
      [-]83f8017306
         // 00416cb0: cmp eax, 0x1
         // 00416cb3: jnb 0x416cbb
      [-]33c941894dd4
         // 00416cb5: xor ecx, ecx
         // 00416cb7: inc ecx
         // 00416cb8: mov ss:[ebp+0xffffffffffffffd4], ecx
      [-]894495f04a79d5
         // 00416cbb: mov ss:[ebp+edx*0x4], eax
         // 00416cbf: dec edx
         // 00416cc0: jns 0x416c97
      [-]2bc833c0f3ab83cfff
         // 00415458: sub ecx, eax
         // 0041545a: xor eax, eax
         // 0041545c: rep stosdd 
         // 0041545e: or edi, 0xffffffffffffffff
      [-]8bc22b05??
         // 00416cfa: mov eax, edx
         // 00416cfc: sub eax, ds:[0x427334]
      [-]3bc87d0f
         // 00416d02: cmp ecx, eax
         // 00416d04: jge 0x416d15
      [-]33c08d7df0ababab
         // 00416d06: xor eax, eax
         // 00416d08: lea edi, ss:[ebp+0xfffffffffffffff0]
         // 00416d0b: stosdd 
         // 00416d0c: stosdd 
         // 00416d0d: stosdd 
      [-]e9b6feffff
         // 00416d10: jmp 0x416bcb
      [-]3bca0f8f19020000
         // 00416d15: cmp ecx, edx
         // 00416d17: jg 0x416f36
      [-]83e21f03c2c1f805
         // 004154a3: and edx, 0x1f
         // 004154a6: add eax, edx
         // 004154a8: sar eax, b1 0x5
      [-]25????????7905
         // 004154b3: and eax, 0xffffffff8000001f
         // 004154b8: jns 0x4154bf
      [-]4883c8e040
         // 00416d44: dec eax
         // 00416d45: or eax, 0xffffffffffffffe0
         // 00416d48: inc eax
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
         // 00416da2: cmp ecx, eax
         // 00416da4: jl 0x416db1
      [-]83ea044979e7
         // 00416db5: sub edx, 0x4
         // 00416db8: dec ecx
         // 00416db9: jns 0x416da2
      [-]8b4dcc418bc19983e21f03d0c1fa058955d481e1????????7905
         // 00416dbb: mov ecx, ss:[ebp+0xffffffffffffffcc]
         // 00416dbe: inc ecx
         // 00416dbf: mov eax, ecx
         // 00416dc1: cdq 
         // 00416dc2: and edx, 0x1f
         // 00416dc5: add edx, eax
         // 00416dc7: sar edx, b1 0x5
         // 00416dca: mov ss:[ebp+0xffffffffffffffd4], edx
         // 00416dcd: and ecx, 0xffffffff8000001f
         // 00416dd3: jns 0x416dda
      [-]4983c9e041
         // 00416dd5: dec ecx
         // 00416dd6: or ecx, 0xffffffffffffffe0
         // 00416dd9: inc ecx
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
         // 00416dfa: test ss:[ebp+edx*0x4], eax
         // 00416dfe: jmp 0x416e04
      [-]423bd67cf5
         // 00416e06: inc edx
         // 00416e07: cmp edx, esi
         // 00416e09: jl 0x416e00
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
         // 00416e25: dec edi
         // 00416e26: or edi, 0xffffffffffffffe0
         // 00416e29: inc edi
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
         // 00416e49: cmp eax, ss:[ebp+0xffffffffffffffdc]
         // 00416e4c: jnb 0x416e51
      [-]894495f04a7828
         // 00416e51: mov ss:[ebp+edx*0x4], eax
         // 00416e55: dec edx
         // 00416e56: js 0x416e80
      [-]85c97421
         // 00416e58: test ecx, ecx
         // 00416e5a: jz 0x416e7d
      [-]8b4495f0
         // 00416e5c: mov eax, ss:[ebp+edx*0x4]
      [-]8d78013bf8
         // 00416e62: lea edi, ds:[eax+0x1]
         // 00416e65: cmp edi, eax
      [-]83f8017303
         // 00416e6e: cmp eax, 0x1
         // 00416e71: jnb 0x416e76
      [-]894495f04a79db
         // 00416e76: mov ss:[ebp+edx*0x4], eax
         // 00416e7a: dec edx
         // 00416e7b: jns 0x416e58
      [-]8bc7d3e0214495f0423bd67d11
         // 00416e86: mov eax, edi
         // 00416e88: shl eax, b1 cl
         // 00416e8a: and ss:[ebp+edx*0x4], eax
         // 00416e8e: inc edx
         // 00416e8f: cmp edx, esi
         // 00416e91: jge 0x416ea4
      [-]f3ab83cfff
         // 00415615: rep stosdd 
         // 00415617: or edi, 0xffffffffffffffff
      [-]418bc19983e21f03c2c1f805
         // 00416eaa: inc ecx
         // 00416eab: mov eax, ecx
         // 00416ead: cdq 
         // 00416eae: and edx, 0x1f
         // 00416eb1: add eax, edx
         // 00416eb3: sar eax, b1 0x5
      [-]81e1????????7905
         // 00416eb9: and ecx, 0xffffffff8000001f
         // 00416ebf: jns 0x416ec6
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
         // 00416f1b: cmp ecx, esi
         // 00416f1d: jl 0x416f27
      [-]83ea044979ea
         // 00416f2b: sub edx, 0x4
         // 00416f2e: dec ecx
         // 00416f2f: jns 0x416f1b
      [-]e9d8fdffff
         // 00416f31: jmp 0x416d0e
      [-]0f8ca2000000
         // 00416f3c: jl 0x416fe4
      [-]8d7df033c0ababab
         // 00416f48: lea edi, ss:[ebp+0xfffffffffffffff0]
         // 00416f4b: xor eax, eax
         // 00416f4d: stosdd 
         // 00416f4e: stosdd 
         // 00416f4f: stosdd 
      [-]9983e21f03c2c1f8058945cc81e1????????7905
         // 00416f59: cdq 
         // 00416f5a: and edx, 0x1f
         // 00416f5d: add eax, edx
         // 00416f5f: sar eax, b1 0x5
         // 00416f62: mov ss:[ebp+0xffffffffffffffcc], eax
         // 00416f65: and ecx, 0xffffffff8000001f
         // 00416f6b: jns 0x416f72
      [-]4983c9e041
         // 00416f6d: dec ecx
         // 00416f6e: or ecx, 0xffffffffffffffe0
         // 00416f71: inc ecx
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
         // 00416fba: cmp ecx, esi
         // 00416fbc: jl 0x416fc6
      [-]83ea044979ea
         // 00416fca: sub edx, 0x4
         // 00416fcd: dec ecx
         // 00416fce: jns 0x416fba
      [-]33db0335??
         // 00416fd6: xor ebx, ebx
         // 00416fd8: add esi, ds:[0x42732c]
      [-]43e995000000
         // 00416fde: inc ebx
         // 00416fdf: jmp 0x417079
      [-]8165????????7f03f18b0d??
         // 00416fea: and ss:[ebp+0xfffffffffffffff0], 0x7fffffff
         // 00416ff1: add esi, ecx
         // 00416ff3: mov ecx, ds:[0x427338]
      [-]8bc19983e21f8975c803c2c1f8058945d881e1????????7905
         // 00416ff9: mov eax, ecx
         // 00416ffb: cdq 
         // 00416ffc: and edx, 0x1f
         // 00416fff: mov ss:[ebp+0xffffffffffffffc8], esi
         // 00417002: add eax, edx
         // 00417004: sar eax, b1 0x5
         // 00417007: mov ss:[ebp+0xffffffffffffffd8], eax
         // 0041700a: and ecx, 0xffffffff8000001f
         // 00417010: jns 0x417017
      [-]4983c9e041
         // 00417012: dec ecx
         // 00417013: or ecx, 0xffffffffffffffe0
         // 00417016: inc ecx
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
         // 00417063: cmp ecx, edi
         // 00417065: jl 0x41706f
      [-]83ea044979ea
         // 00417073: sub edx, 0x4
         // 00417076: dec ecx
         // 00417077: jns 0x417063
      [-]83f8207502
         // 004170ae: cmp eax, 0x20
         // 004170b1: jnz 0x4170b5
      [-]8b4dfc8bc35f5e
         // 004155eb: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 004155ee: mov eax, ebx
         // 004155f0: pop edi
         // 004155f1: pop esi
      [-]ffff8be55dc3
         // 004155fa: mov esp, ebp
         // 004155fc: pop ebp
         // 004155fd: retn 
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
         // 00417120: mov esi, ebx
         // 00417122: mov eax, ebx
      [-]395c85f0750b
         // 00417124: cmp ss:[ebp+eax*0x4], ebx
         // 00417128: jnz 0x417135
      [-]4083f8037cf4
         // 0041712a: inc eax
         // 0041712b: cmp eax, 0x3
         // 0041712e: jl 0x417124
      [-]e9b9040000
         // 00417130: jmp 0x4175ee
      [-]33c08d7df0ababab
         // 00417135: xor eax, eax
         // 00417137: lea edi, ss:[ebp+0xfffffffffffffff0]
         // 0041713a: stosdd 
         // 0041713b: stosdd 
         // 0041713c: stosdd 
      [-]6a025be9a6040000
         // 0041713d: push 0x2
         // 0041713f: pop ebx
         // 00417140: jmp 0x4175eb
      [-]8d75f08d7de48955dca5488945cc6a1f895dd4a58d48018bc199a55e23d603d0c1fa058955c481e1????????7905
         // 0041714a: lea esi, ss:[ebp+0xfffffffffffffff0]
         // 0041714d: lea edi, ss:[ebp+0xffffffffffffffe4]
         // 00417150: mov ss:[ebp+0xffffffffffffffdc], edx
         // 00417153: movsdd 
         // 00417154: dec eax
         // 00417155: mov ss:[ebp+0xffffffffffffffcc], eax
         // 00417158: push 0x1f
         // 0041715a: mov ss:[ebp+0xffffffffffffffd4], ebx
         // 0041715d: movsdd 
         // 0041715e: lea ecx, ds:[eax+0x1]
         // 00417161: mov eax, ecx
         // 00417163: cdq 
         // 00417164: movsdd 
         // 00417165: pop esi
         // 00417166: and edx, esi
         // 00417168: add edx, eax
         // 0041716a: sar edx, b1 0x5
         // 0041716d: mov ss:[ebp+0xffffffffffffffc4], edx
         // 00417170: and ecx, 0xffffffff8000001f
         // 00417176: jns 0x41717d
      [-]4983c9e041
         // 00417178: dec ecx
         // 00417179: or ecx, 0xffffffffffffffe0
         // 0041717c: inc ecx
      [-]2bf133c0408975d08bce83cfffd3e06a035e854495f00f84a4000000
         // 0041717d: sub esi, ecx
         // 0041717f: xor eax, eax
         // 00417181: inc eax
         // 00417182: mov ss:[ebp+0xffffffffffffffd0], esi
         // 00417185: mov ecx, esi
         // 00417187: or edi, 0xffffffffffffffff
         // 0041718a: shl eax, b1 cl
         // 0041718c: push 0x3
         // 0041718e: pop esi
         // 0041718f: test ss:[ebp+edx*0x4], eax
         // 00417193: jz 0x41723d
      [-]8bc7d3e0f7d0854495f0eb04
         // 00417199: mov eax, edi
         // 0041719b: shl eax, b1 cl
         // 0041719d: not eax
         // 0041719f: test ss:[ebp+edx*0x4], eax
         // 004171a3: jmp 0x4171a9
      [-]395c95f0
         // 004171a5: cmp ss:[ebp+edx*0x4], ebx
      [-]423bd67cf5
         // 004171ab: inc edx
         // 004171ac: cmp edx, esi
         // 004171ae: jl 0x4171a5
      [-]e985000000
         // 004171b0: jmp 0x41723a
      [-]8b45cc996a1f5923d103d08b45ccc1fa0525????????7905
         // 004171b5: mov eax, ss:[ebp+0xffffffffffffffcc]
         // 004171b8: cdq 
         // 004171b9: push 0x1f
         // 004171bb: pop ecx
         // 004171bc: and edx, ecx
         // 004171be: add edx, eax
         // 004171c0: mov eax, ss:[ebp+0xffffffffffffffcc]
         // 004171c3: sar edx, b1 0x5
         // 004171c6: and eax, 0xffffffff8000001f
         // 004171cb: jns 0x4171d2
      [-]4883c8e040
         // 004171cd: dec eax
         // 004171ce: or eax, 0xffffffffffffffe0
         // 004171d1: inc eax
      [-]2bc8895dd433c040d3e08945c88b4495f08b4dc803c8894dd83bc88b45d88bcb6aff5f7205
         // 004171d2: sub ecx, eax
         // 004171d4: mov ss:[ebp+0xffffffffffffffd4], ebx
         // 004171d7: xor eax, eax
         // 004171d9: inc eax
         // 004171da: shl eax, b1 cl
         // 004171dc: mov ss:[ebp+0xffffffffffffffc8], eax
         // 004171df: mov eax, ss:[ebp+edx*0x4]
         // 004171e3: mov ecx, ss:[ebp+0xffffffffffffffc8]
         // 004171e6: add ecx, eax
         // 004171e8: mov ss:[ebp+0xffffffffffffffd8], ecx
         // 004171eb: cmp ecx, eax
         // 004171ed: mov eax, ss:[ebp+0xffffffffffffffd8]
         // 004171f0: mov ecx, ebx
         // 004171f2: push 0xffffffffffffffff
         // 004171f4: pop edi
         // 004171f5: jb 0x4171fc
      [-]3b45c87306
         // 004171f7: cmp eax, ss:[ebp+0xffffffffffffffc8]
         // 004171fa: jnb 0x417202
      [-]33c941894dd4
         // 004171fc: xor ecx, ecx
         // 004171fe: inc ecx
         // 004171ff: mov ss:[ebp+0xffffffffffffffd4], ecx
      [-]894495f04a782e
         // 00417202: mov ss:[ebp+edx*0x4], eax
         // 00417206: dec edx
         // 00417207: js 0x417237
      [-]85c97427
         // 00417209: test ecx, ecx
         // 0041720b: jz 0x417234
      [-]8b4495f08bcb895dd48d78013bf8897dd88bc77205
         // 0041720d: mov eax, ss:[ebp+edx*0x4]
         // 00417211: mov ecx, ebx
         // 00417213: mov ss:[ebp+0xffffffffffffffd4], ebx
         // 00417216: lea edi, ds:[eax+0x1]
         // 00417219: cmp edi, eax
         // 0041721b: mov ss:[ebp+0xffffffffffffffd8], edi
         // 0041721e: mov eax, edi
         // 00417220: jb 0x417227
      [-]83f8017306
         // 00417222: cmp eax, 0x1
         // 00417225: jnb 0x41722d
      [-]33c941894dd4
         // 00417227: xor ecx, ecx
         // 00417229: inc ecx
         // 0041722a: mov ss:[ebp+0xffffffffffffffd4], ecx
      [-]894495f04a79d5
         // 0041722d: mov ss:[ebp+edx*0x4], eax
         // 00417231: dec edx
         // 00417232: jns 0x417209
      [-]8bc7d3e0214495f08d42013bc67d11
         // 0041723d: mov eax, edi
         // 0041723f: shl eax, b1 cl
         // 00417241: and ss:[ebp+edx*0x4], eax
         // 00417245: lea eax, ds:[edx+0x1]
         // 00417248: cmp eax, esi
         // 0041724a: jge 0x41725d
      [-]8d7df08bce8d3c872bc833c0f3ab83cfff
         // 0041724c: lea edi, ss:[ebp+0xfffffffffffffff0]
         // 0041724f: mov ecx, esi
         // 00417251: lea edi, ds:[edi+eax*0x4]
         // 00417254: sub ecx, eax
         // 00417256: xor eax, eax
         // 00417258: rep stosdd 
         // 0041725a: or edi, 0xffffffffffffffff
      [-]8b4de0395dd47401
         // 0041725d: mov ecx, ss:[ebp+0xffffffffffffffe0]
         // 00417260: cmp ss:[ebp+0xffffffffffffffd4], ebx
         // 00417263: jz 0x417266
      [-]8bc22b05??
         // 0041726c: mov eax, edx
         // 0041726e: sub eax, ds:[0x42734c]
      [-]3bc87d0f
         // 00417274: cmp ecx, eax
         // 00417276: jge 0x417287
      [-]33c08d7df0ababab
         // 00417278: xor eax, eax
         // 0041727a: lea edi, ss:[ebp+0xfffffffffffffff0]
         // 0041727d: stosdd 
         // 0041727e: stosdd 
         // 0041727f: stosdd 
      [-]8bf3e9b6feffff
         // 00417280: mov esi, ebx
         // 00417282: jmp 0x41713d
      [-]3bca0f8f19020000
         // 00417287: cmp ecx, edx
         // 00417289: jg 0x4174a8
      [-]2b55dc8d75e48955d08d7df08bc2a59983e21f03c2c1f805a58945c48b45d0a525????????7905
         // 0041728f: sub edx, ss:[ebp+0xffffffffffffffdc]
         // 00417292: lea esi, ss:[ebp+0xffffffffffffffe4]
         // 00417295: mov ss:[ebp+0xffffffffffffffd0], edx
         // 00417298: lea edi, ss:[ebp+0xfffffffffffffff0]
         // 0041729b: mov eax, edx
         // 0041729d: movsdd 
         // 0041729e: cdq 
         // 0041729f: and edx, 0x1f
         // 004172a2: add eax, edx
         // 004172a4: sar eax, b1 0x5
         // 004172a7: movsdd 
         // 004172a8: mov ss:[ebp+0xffffffffffffffc4], eax
         // 004172ab: mov eax, ss:[ebp+0xffffffffffffffd0]
         // 004172ae: movsdd 
         // 004172af: and eax, 0xffffffff8000001f
         // 004172b4: jns 0x4172bb
      [-]4883c8e040
         // 004172b6: dec eax
         // 004172b7: or eax, 0xffffffffffffffe0
         // 004172ba: inc eax
      [-]8945d083cfff8bc7895de08b7dd08bcfd3e0f7d06a208945d8582bc76a038945c85e
         // 004172bb: mov ss:[ebp+0xffffffffffffffd0], eax
         // 004172be: or edi, 0xffffffffffffffff
         // 004172c1: mov eax, edi
         // 004172c3: mov ss:[ebp+0xffffffffffffffe0], ebx
         // 004172c6: mov edi, ss:[ebp+0xffffffffffffffd0]
         // 004172c9: mov ecx, edi
         // 004172cb: shl eax, b1 cl
         // 004172cd: not eax
         // 004172cf: push 0x20
         // 004172d1: mov ss:[ebp+0xffffffffffffffd8], eax
         // 004172d4: pop eax
         // 004172d5: sub eax, edi
         // 004172d7: push 0x3
         // 004172d9: mov ss:[ebp+0xffffffffffffffc8], eax
         // 004172dc: pop esi
      [-]8b549df08bcf8bc2d3ea0b55e02345d88b4dc8d3e089549df0438945e03bde7cdf
         // 004172dd: mov edx, ss:[ebp+ebx*0x4]
         // 004172e1: mov ecx, edi
         // 004172e3: mov eax, edx
         // 004172e5: shr edx, b1 cl
         // 004172e7: or edx, ss:[ebp+0xffffffffffffffe0]
         // 004172ea: and eax, ss:[ebp+0xffffffffffffffd8]
         // 004172ed: mov ecx, ss:[ebp+0xffffffffffffffc8]
         // 004172f0: shl eax, b1 cl
         // 004172f2: mov ss:[ebp+ebx*0x4], edx
         // 004172f6: inc ebx
         // 004172f7: mov ss:[ebp+0xffffffffffffffe0], eax
         // 004172fa: cmp ebx, esi
         // 004172fc: jl 0x4172dd
      [-]8b45c48d55f8c1e00233db6a022bd083cfff8b45c459
         // 004172fe: mov eax, ss:[ebp+0xffffffffffffffc4]
         // 00417301: lea edx, ss:[ebp+0xfffffffffffffff8]
         // 00417304: shl eax, b1 0x2
         // 00417307: xor ebx, ebx
         // 00417309: push 0x2
         // 0041730b: sub edx, eax
         // 0041730d: or edi, 0xffffffffffffffff
         // 00417310: mov eax, ss:[ebp+0xffffffffffffffc4]
         // 00417313: pop ecx
      [-]3bc87c0b
         // 00417314: cmp ecx, eax
         // 00417316: jl 0x417323
      [-]8b0289448df08b45c4eb04
         // 00417318: mov eax, ds:[edx]
         // 0041731a: mov ss:[ebp+ecx*0x4], eax
         // 0041731e: mov eax, ss:[ebp+0xffffffffffffffc4]
         // 00417321: jmp 0x417327
      [-]895c8df0
         // 00417323: mov ss:[ebp+ecx*0x4], ebx
      [-]83ea044979e7
         // 00417327: sub edx, 0x4
         // 0041732a: dec ecx
         // 0041732b: jns 0x417314
      [-]8b4dcc418bc19983e21f03d0c1fa058955d481e1????????7905
         // 0041732d: mov ecx, ss:[ebp+0xffffffffffffffcc]
         // 00417330: inc ecx
         // 00417331: mov eax, ecx
         // 00417333: cdq 
         // 00417334: and edx, 0x1f
         // 00417337: add edx, eax
         // 00417339: sar edx, b1 0x5
         // 0041733c: mov ss:[ebp+0xffffffffffffffd4], edx
         // 0041733f: and ecx, 0xffffffff8000001f
         // 00417345: jns 0x41734c
      [-]4983c9e041
         // 00417347: dec ecx
         // 00417348: or ecx, 0xffffffffffffffe0
         // 0041734b: inc ecx
      [-]6a1f582bc18945d033c08b4dd040d3e0854495f00f8492000000
         // 0041734c: push 0x1f
         // 0041734e: pop eax
         // 0041734f: sub eax, ecx
         // 00417351: mov ss:[ebp+0xffffffffffffffd0], eax
         // 00417354: xor eax, eax
         // 00417356: mov ecx, ss:[ebp+0xffffffffffffffd0]
         // 00417359: inc eax
         // 0041735a: shl eax, b1 cl
         // 0041735c: test ss:[ebp+edx*0x4], eax
         // 00417360: jz 0x4173f8
      [-]8bc7d3e0f7d0854495f0eb04
         // 00417366: mov eax, edi
         // 00417368: shl eax, b1 cl
         // 0041736a: not eax
         // 0041736c: test ss:[ebp+edx*0x4], eax
         // 00417370: jmp 0x417376
      [-]395c95f0
         // 00417372: cmp ss:[ebp+edx*0x4], ebx
      [-]423bd67cf5
         // 00417378: inc edx
         // 00417379: cmp edx, esi
         // 0041737b: jl 0x417372
      [-]8b7dcc8bc76a1f995923d103d0c1fa0581e7????????7905
         // 0041737f: mov edi, ss:[ebp+0xffffffffffffffcc]
         // 00417382: mov eax, edi
         // 00417384: push 0x1f
         // 00417386: cdq 
         // 00417387: pop ecx
         // 00417388: and edx, ecx
         // 0041738a: add edx, eax
         // 0041738c: sar edx, b1 0x5
         // 0041738f: and edi, 0xffffffff8000001f
         // 00417395: jns 0x41739c
      [-]4f83cfe047
         // 00417397: dec edi
         // 00417398: or edi, 0xffffffffffffffe0
         // 0041739b: inc edi
      [-]8b4495f02bcf33ff47d3e78bcb897ddc03f8897de03bf88b45e06aff5f7205
         // 0041739c: mov eax, ss:[ebp+edx*0x4]
         // 004173a0: sub ecx, edi
         // 004173a2: xor edi, edi
         // 004173a4: inc edi
         // 004173a5: shl edi, b1 cl
         // 004173a7: mov ecx, ebx
         // 004173a9: mov ss:[ebp+0xffffffffffffffdc], edi
         // 004173ac: add edi, eax
         // 004173ae: mov ss:[ebp+0xffffffffffffffe0], edi
         // 004173b1: cmp edi, eax
         // 004173b3: mov eax, ss:[ebp+0xffffffffffffffe0]
         // 004173b6: push 0xffffffffffffffff
         // 004173b8: pop edi
         // 004173b9: jb 0x4173c0
      [-]3b45dc7303
         // 004173bb: cmp eax, ss:[ebp+0xffffffffffffffdc]
         // 004173be: jnb 0x4173c3
      [-]894495f04a7828
         // 004173c3: mov ss:[ebp+edx*0x4], eax
         // 004173c7: dec edx
         // 004173c8: js 0x4173f2
      [-]85c97421
         // 004173ca: test ecx, ecx
         // 004173cc: jz 0x4173ef
      [-]8b4495f08bcb8d78013bf8897de08bc77205
         // 004173ce: mov eax, ss:[ebp+edx*0x4]
         // 004173d2: mov ecx, ebx
         // 004173d4: lea edi, ds:[eax+0x1]
         // 004173d7: cmp edi, eax
         // 004173d9: mov ss:[ebp+0xffffffffffffffe0], edi
         // 004173dc: mov eax, edi
         // 004173de: jb 0x4173e5
      [-]83f8017303
         // 004173e0: cmp eax, 0x1
         // 004173e3: jnb 0x4173e8
      [-]894495f04a79db
         // 004173e8: mov ss:[ebp+edx*0x4], eax
         // 004173ec: dec edx
         // 004173ed: jns 0x4173ca
      [-]8bc7d3e0214495f0423bd67d11
         // 004173f8: mov eax, edi
         // 004173fa: shl eax, b1 cl
         // 004173fc: and ss:[ebp+edx*0x4], eax
         // 00417400: inc edx
         // 00417401: cmp edx, esi
         // 00417403: jge 0x417416
      [-]8d7df08bce8d3c972bca33c0f3ab83cfff
         // 00417405: lea edi, ss:[ebp+0xfffffffffffffff0]
         // 00417408: mov ecx, esi
         // 0041740a: lea edi, ds:[edi+edx*0x4]
         // 0041740d: sub ecx, edx
         // 0041740f: xor eax, eax
         // 00417411: rep stosdd 
         // 00417413: or edi, 0xffffffffffffffff
      [-]418bc19983e21f03c2c1f8058945d881e1????????7905
         // 0041741c: inc ecx
         // 0041741d: mov eax, ecx
         // 0041741f: cdq 
         // 00417420: and edx, 0x1f
         // 00417423: add eax, edx
         // 00417425: sar eax, b1 0x5
         // 00417428: mov ss:[ebp+0xffffffffffffffd8], eax
         // 0041742b: and ecx, 0xffffffff8000001f
         // 00417431: jns 0x417438
      [-]4983c9e041
         // 00417433: dec ecx
         // 00417434: or ecx, 0xffffffffffffffe0
         // 00417437: inc ecx
      [-]894ddc8bc3d3e76a20895de0f7d78b5ddc592bcb8945cc894ddc
         // 00417438: mov ss:[ebp+0xffffffffffffffdc], ecx
         // 0041743b: mov eax, ebx
         // 0041743d: shl edi, b1 cl
         // 0041743f: push 0x20
         // 00417441: mov ss:[ebp+0xffffffffffffffe0], ebx
         // 00417444: not edi
         // 00417446: mov ebx, ss:[ebp+0xffffffffffffffdc]
         // 00417449: pop ecx
         // 0041744a: sub ecx, ebx
         // 0041744c: mov ss:[ebp+0xffffffffffffffcc], eax
         // 0041744f: mov ss:[ebp+0xffffffffffffffdc], ecx
      [-]8b5485f08bcb8bc2d3ea8b4dcc23c70b55e089548df08b4ddcd3e08945e08b45cc408945cc3bc67cd7
         // 00417452: mov edx, ss:[ebp+eax*0x4]
         // 00417456: mov ecx, ebx
         // 00417458: mov eax, edx
         // 0041745a: shr edx, b1 cl
         // 0041745c: mov ecx, ss:[ebp+0xffffffffffffffcc]
         // 0041745f: and eax, edi
         // 00417461: or edx, ss:[ebp+0xffffffffffffffe0]
         // 00417464: mov ss:[ebp+ecx*0x4], edx
         // 00417468: mov ecx, ss:[ebp+0xffffffffffffffdc]
         // 0041746b: shl eax, b1 cl
         // 0041746d: mov ss:[ebp+0xffffffffffffffe0], eax
         // 00417470: mov eax, ss:[ebp+0xffffffffffffffcc]
         // 00417473: inc eax
         // 00417474: mov ss:[ebp+0xffffffffffffffcc], eax
         // 00417477: cmp eax, esi
         // 00417479: jl 0x417452
      [-]8b75d88d55f88bc6c1e0026a022bd033db59
         // 0041747b: mov esi, ss:[ebp+0xffffffffffffffd8]
         // 0041747e: lea edx, ss:[ebp+0xfffffffffffffff8]
         // 00417481: mov eax, esi
         // 00417483: shl eax, b1 0x2
         // 00417486: push 0x2
         // 00417488: sub edx, eax
         // 0041748a: xor ebx, ebx
         // 0041748c: pop ecx
      [-]3bce7c08
         // 0041748d: cmp ecx, esi
         // 0041748f: jl 0x417499
      [-]8b0289448df0eb04
         // 00417491: mov eax, ds:[edx]
         // 00417493: mov ss:[ebp+ecx*0x4], eax
         // 00417497: jmp 0x41749d
      [-]895c8df0
         // 00417499: mov ss:[ebp+ecx*0x4], ebx
      [-]83ea044979ea
         // 0041749d: sub edx, 0x4
         // 004174a0: dec ecx
         // 004174a1: jns 0x41748d
      [-]e9d8fdffff
         // 004174a3: jmp 0x417280
      [-]0f8ca2000000
         // 004174ae: jl 0x417556
      [-]8d7df033c0ababab8bc1814df0????????9983e21f03c2c1f8058945cc81e1????????7905
         // 004174ba: lea edi, ss:[ebp+0xfffffffffffffff0]
         // 004174bd: xor eax, eax
         // 004174bf: stosdd 
         // 004174c0: stosdd 
         // 004174c1: stosdd 
         // 004174c2: mov eax, ecx
         // 004174c4: or ss:[ebp+0xfffffffffffffff0], 0xffffffff80000000
         // 004174cb: cdq 
         // 004174cc: and edx, 0x1f
         // 004174cf: add eax, edx
         // 004174d1: sar eax, b1 0x5
         // 004174d4: mov ss:[ebp+0xffffffffffffffcc], eax
         // 004174d7: and ecx, 0xffffffff8000001f
         // 004174dd: jns 0x4174e4
      [-]4983c9e041
         // 004174df: dec ecx
         // 004174e0: or ecx, 0xffffffffffffffe0
         // 004174e3: inc ecx
      [-]83cfff894dc86a20d3e7582bc1895de0f7d78945d8
         // 004174e4: or edi, 0xffffffffffffffff
         // 004174e7: mov ss:[ebp+0xffffffffffffffc8], ecx
         // 004174ea: push 0x20
         // 004174ec: shl edi, b1 cl
         // 004174ee: pop eax
         // 004174ef: sub eax, ecx
         // 004174f1: mov ss:[ebp+0xffffffffffffffe0], ebx
         // 004174f4: not edi
         // 004174f6: mov ss:[ebp+0xffffffffffffffd8], eax
      [-]8b549df08bc2d3ea23c70b55e08b4dd8d3e08b4dc889549df0438945e03bde7cdf
         // 004174f9: mov edx, ss:[ebp+ebx*0x4]
         // 004174fd: mov eax, edx
         // 004174ff: shr edx, b1 cl
         // 00417501: and eax, edi
         // 00417503: or edx, ss:[ebp+0xffffffffffffffe0]
         // 00417506: mov ecx, ss:[ebp+0xffffffffffffffd8]
         // 00417509: shl eax, b1 cl
         // 0041750b: mov ecx, ss:[ebp+0xffffffffffffffc8]
         // 0041750e: mov ss:[ebp+ebx*0x4], edx
         // 00417512: inc ebx
         // 00417513: mov ss:[ebp+0xffffffffffffffe0], eax
         // 00417516: cmp ebx, esi
         // 00417518: jl 0x4174f9
      [-]8b75cc8d55f88bc6c1e0026a022bd033db59
         // 0041751a: mov esi, ss:[ebp+0xffffffffffffffcc]
         // 0041751d: lea edx, ss:[ebp+0xfffffffffffffff8]
         // 00417520: mov eax, esi
         // 00417522: shl eax, b1 0x2
         // 00417525: push 0x2
         // 00417527: sub edx, eax
         // 00417529: xor ebx, ebx
         // 0041752b: pop ecx
      [-]3bce7c08
         // 0041752c: cmp ecx, esi
         // 0041752e: jl 0x417538
      [-]8b0289448df0eb04
         // 00417530: mov eax, ds:[edx]
         // 00417532: mov ss:[ebp+ecx*0x4], eax
         // 00417536: jmp 0x41753c
      [-]895c8df0
         // 00417538: mov ss:[ebp+ecx*0x4], ebx
      [-]83ea044979ea
         // 0041753c: sub edx, 0x4
         // 0041753f: dec ecx
         // 00417540: jns 0x41752c
      [-]33db0335??
         // 00417548: xor ebx, ebx
         // 0041754a: add esi, ds:[0x427344]
      [-]43e995000000
         // 00417550: inc ebx
         // 00417551: jmp 0x4175eb
      [-]8165????????7f03f18b0d??
         // 0041755c: and ss:[ebp+0xfffffffffffffff0], 0x7fffffff
         // 00417563: add esi, ecx
         // 00417565: mov ecx, ds:[0x427350]
      [-]8bc19983e21f8975c803c2c1f8058945d881e1????????7905
         // 0041756b: mov eax, ecx
         // 0041756d: cdq 
         // 0041756e: and edx, 0x1f
         // 00417571: mov ss:[ebp+0xffffffffffffffc8], esi
         // 00417574: add eax, edx
         // 00417576: sar eax, b1 0x5
         // 00417579: mov ss:[ebp+0xffffffffffffffd8], eax
         // 0041757c: and ecx, 0xffffffff8000001f
         // 00417582: jns 0x417589
      [-]4983c9e041
         // 00417584: dec ecx
         // 00417585: or ecx, 0xffffffffffffffe0
         // 00417588: inc ecx
      [-]6a20895de08bf3d3e78bd9582bc3894ddcf7d78945dc
         // 00417589: push 0x20
         // 0041758b: mov ss:[ebp+0xffffffffffffffe0], ebx
         // 0041758e: mov esi, ebx
         // 00417590: shl edi, b1 cl
         // 00417592: mov ebx, ecx
         // 00417594: pop eax
         // 00417595: sub eax, ebx
         // 00417597: mov ss:[ebp+0xffffffffffffffdc], ecx
         // 0041759a: not edi
         // 0041759c: mov ss:[ebp+0xffffffffffffffdc], eax
      [-]8b54b5f08bcb8bc2d3ea0b55e023c78b4ddcd3e08954b5f0468945e083fe037cdf
         // 0041759f: mov edx, ss:[ebp+esi*0x4]
         // 004175a3: mov ecx, ebx
         // 004175a5: mov eax, edx
         // 004175a7: shr edx, b1 cl
         // 004175a9: or edx, ss:[ebp+0xffffffffffffffe0]
         // 004175ac: and eax, edi
         // 004175ae: mov ecx, ss:[ebp+0xffffffffffffffdc]
         // 004175b1: shl eax, b1 cl
         // 004175b3: mov ss:[ebp+esi*0x4], edx
         // 004175b7: inc esi
         // 004175b8: mov ss:[ebp+0xffffffffffffffe0], eax
         // 004175bb: cmp esi, 0x3
         // 004175be: jl 0x41759f
      [-]8b7dd88d55f88b75c88bc7c1e0026a022bd033db59
         // 004175c0: mov edi, ss:[ebp+0xffffffffffffffd8]
         // 004175c3: lea edx, ss:[ebp+0xfffffffffffffff8]
         // 004175c6: mov esi, ss:[ebp+0xffffffffffffffc8]
         // 004175c9: mov eax, edi
         // 004175cb: shl eax, b1 0x2
         // 004175ce: push 0x2
         // 004175d0: sub edx, eax
         // 004175d2: xor ebx, ebx
         // 004175d4: pop ecx
      [-]3bcf7c08
         // 004175d5: cmp ecx, edi
         // 004175d7: jl 0x4175e1
      [-]8b0289448df0eb04
         // 004175d9: mov eax, ds:[edx]
         // 004175db: mov ss:[ebp+ecx*0x4], eax
         // 004175df: jmp 0x4175e5
      [-]895c8df0
         // 004175e1: mov ss:[ebp+ecx*0x4], ebx
      [-]83ea044979ea
         // 004175e5: sub edx, 0x4
         // 004175e8: dec ecx
         // 004175e9: jns 0x4175d5
      [-]6a1f582b05??
         // 004175ee: push 0x1f
         // 004175f0: pop eax
         // 004175f1: sub eax, ds:[0x427350]
      [-]8bc88b45bcd3e6f7d81bc025????????0bf0a1??
         // 004175f7: mov ecx, eax
         // 004175f9: mov eax, ss:[ebp+0xffffffffffffffbc]
         // 004175fc: shl esi, b1 cl
         // 004175fe: neg eax
         // 00417600: sbb eax, eax
         // 00417602: and eax, 0xffffffff80000000
         // 00417607: or esi, eax
         // 00417609: mov eax, ds:[0x427354]
      [-]0b75f083f840750a
         // 0041760e: or esi, ss:[ebp+0xfffffffffffffff0]
         // 00417611: cmp eax, 0x40
         // 00417614: jnz 0x417620
      [-]8b45f48977048907eb07
         // 00417616: mov eax, ss:[ebp+0xfffffffffffffff4]
         // 00417619: mov ds:[edi+0x4], esi
         // 0041761c: mov ds:[edi], eax
         // 0041761e: jmp 0x417627
      [-]83f8207502
         // 00417620: cmp eax, 0x20
         // 00417623: jnz 0x417627
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
         // 00419081: jz 0x419299
      [-]81fe????????0f873b070000
         // 00419087: cmp esi, 0xd4
         // 0041908d: ja def_41909A
      [-]4100ff2485
         // 00417a3a: jmp ds:[jpt_417A3A+eax*0x4]
      [-]8b7424186a0056e8
         // 004190a1: mov esi, ss:[esp+0x18]
         // 004190a5: push 0x0
         // 004190a7: push esi
         // 004190a8: call 0x419af0
      [-]000083c4088bc68b4c240864890d????????595e83c40cc20800
         // 004190ad: add esp, 0x8
         // 004190b0: mov eax, esi
         // 004190b2: mov ecx, ss:[esp+0x8]
         // 004190b6: mov fs:[0x0], ecx
         // 004190bd: pop ecx
         // 004190be: pop esi
         // 004190bf: add esp, 0xc
         // 004190c2: retn b2 0x8
      [-]8b7424186a1156e8
         // 004190c5: mov esi, ss:[esp+0x18]
         // 004190c9: push 0x11
         // 004190cb: push esi
         // 004190cc: call 0x419af0
      [-]000083c4088bc68b4c240864890d????????595e83c40cc20800
         // 004190d1: add esp, 0x8
         // 004190d4: mov eax, esi
         // 004190d6: mov ecx, ss:[esp+0x8]
         // 004190da: mov fs:[0x0], ecx
         // 004190e1: pop ecx
         // 004190e2: pop esi
         // 004190e3: add esp, 0xc
         // 004190e6: retn b2 0x8
      [-]8b7424186a1356e8
         // 004190e9: mov esi, ss:[esp+0x18]
         // 004190ed: push 0x13
         // 004190ef: push esi
         // 004190f0: call 0x419af0
      [-]09000083c4088bc68b4c240864890d????????595e83c40cc20800
         // 004190f5: add esp, 0x8
         // 004190f8: mov eax, esi
         // 004190fa: mov ecx, ss:[esp+0x8]
         // 004190fe: mov fs:[0x0], ecx
         // 00419105: pop ecx
         // 00419106: pop esi
         // 00419107: add esp, 0xc
         // 0041910a: retn b2 0x8
      [-]8b7424186a2656e8
         // 0041910d: mov esi, ss:[esp+0x18]
         // 00419111: push 0x26
         // 00419113: push esi
         // 00419114: call 0x419af0
      [-]09000083c4088bc68b4c240864890d????????595e83c40cc20800
         // 00419119: add esp, 0x8
         // 0041911c: mov eax, esi
         // 0041911e: mov ecx, ss:[esp+0x8]
         // 00419122: mov fs:[0x0], ecx
         // 00419129: pop ecx
         // 0041912a: pop esi
         // 0041912b: add esp, 0xc
         // 0041912e: retn b2 0x8
      [-]8b7424186a2956e8
         // 00419131: mov esi, ss:[esp+0x18]
         // 00419135: push 0x29
         // 00419137: push esi
         // 00419138: call 0x419af0
      [-]09000083c4088bc68b4c240864890d????????595e83c40cc20800
         // 0041913d: add esp, 0x8
         // 00419140: mov eax, esi
         // 00419142: mov ecx, ss:[esp+0x8]
         // 00419146: mov fs:[0x0], ecx
         // 0041914d: pop ecx
         // 0041914e: pop esi
         // 0041914f: add esp, 0xc
         // 00419152: retn b2 0x8
      [-]8b7424186a1c56e8
         // 00419155: mov esi, ss:[esp+0x18]
         // 00419159: push 0x1c
         // 0041915b: push esi
         // 0041915c: call 0x419af0
      [-]09000083c4088bc68b4c240864890d????????595e83c40cc20800
         // 00419161: add esp, 0x8
         // 00419164: mov eax, esi
         // 00419166: mov ecx, ss:[esp+0x8]
         // 0041916a: mov fs:[0x0], ecx
         // 00419171: pop ecx
         // 00419172: pop esi
         // 00419173: add esp, 0xc
         // 00419176: retn b2 0x8
      [-]8b7424186a0256e8
         // 00419179: mov esi, ss:[esp+0x18]
         // 0041917d: push 0x2
         // 0041917f: push esi
         // 00419180: call 0x419af0
      [-]09000083c4088bc68b4c240864890d????????595e83c40cc20800
         // 00419185: add esp, 0x8
         // 00419188: mov eax, esi
         // 0041918a: mov ecx, ss:[esp+0x8]
         // 0041918e: mov fs:[0x0], ecx
         // 00419195: pop ecx
         // 00419196: pop esi
         // 00419197: add esp, 0xc
         // 0041919a: retn b2 0x8
      [-]8b7424186a2856e8
         // 0041919d: mov esi, ss:[esp+0x18]
         // 004191a1: push 0x28
         // 004191a3: push esi
         // 004191a4: call 0x419af0
      [-]000083c4088bc68b4c240864890d????????595e83c40cc20800
         // 004191a9: add esp, 0x8
         // 004191ac: mov eax, esi
         // 004191ae: mov ecx, ss:[esp+0x8]
         // 004191b2: mov fs:[0x0], ecx
         // 004191b9: pop ecx
         // 004191ba: pop esi
         // 004191bb: add esp, 0xc
         // 004191be: retn b2 0x8
      [-]8b7424186a1656e8
         // 004191c1: mov esi, ss:[esp+0x18]
         // 004191c5: push 0x16
         // 004191c7: push esi
         // 004191c8: call 0x419af0
      [-]000083c4088bc68b4c240864890d????????595e83c40cc20800
         // 004191cd: add esp, 0x8
         // 004191d0: mov eax, esi
         // 004191d2: mov ecx, ss:[esp+0x8]
         // 004191d6: mov fs:[0x0], ecx
         // 004191dd: pop ecx
         // 004191de: pop esi
         // 004191df: add esp, 0xc
         // 004191e2: retn b2 0x8
      [-]8b7424186a2756e8
         // 004191e5: mov esi, ss:[esp+0x18]
         // 004191e9: push 0x27
         // 004191eb: push esi
         // 004191ec: call 0x419af0
      [-]08000083c4088bc68b4c240864890d????????595e83c40cc20800
         // 004191f1: add esp, 0x8
         // 004191f4: mov eax, esi
         // 004191f6: mov ecx, ss:[esp+0x8]
         // 004191fa: mov fs:[0x0], ecx
         // 00419201: pop ecx
         // 00419202: pop esi
         // 00419203: add esp, 0xc
         // 00419206: retn b2 0x8
      [-]8b7424186a0c56e8
         // 00419209: mov esi, ss:[esp+0x18]
         // 0041920d: push 0xc
         // 0041920f: push esi
         // 00419210: call 0x419af0
      [-]08000083c4088bc68b4c240864890d????????595e83c40cc20800
         // 00419215: add esp, 0x8
         // 00419218: mov eax, esi
         // 0041921a: mov ecx, ss:[esp+0x8]
         // 0041921e: mov fs:[0x0], ecx
         // 00419225: pop ecx
         // 00419226: pop esi
         // 00419227: add esp, 0xc
         // 0041922a: retn b2 0x8
      [-]8b7424186a0b56e8
         // 0041922d: mov esi, ss:[esp+0x18]
         // 00419231: push 0xb
         // 00419233: push esi
         // 00419234: call 0x419af0
      [-]08000083c4088bc68b4c240864890d????????595e83c40cc20800
         // 00419239: add esp, 0x8
         // 0041923c: mov eax, esi
         // 0041923e: mov ecx, ss:[esp+0x8]
         // 00419242: mov fs:[0x0], ecx
         // 00419249: pop ecx
         // 0041924a: pop esi
         // 0041924b: add esp, 0xc
         // 0041924e: retn b2 0x8
      [-]8b7424186a1256e8
         // 00419251: mov esi, ss:[esp+0x18]
         // 00419255: push 0x12
         // 00419257: push esi
         // 00419258: call 0x419af0
      [-]08000083c4088bc68b4c240864890d????????595e83c40cc20800
         // 0041925d: add esp, 0x8
         // 00419260: mov eax, esi
         // 00419262: mov ecx, ss:[esp+0x8]
         // 00419266: mov fs:[0x0], ecx
         // 0041926d: pop ecx
         // 0041926e: pop esi
         // 0041926f: add esp, 0xc
         // 00419272: retn b2 0x8
      [-]8b7424186a1856e8
         // 00419275: mov esi, ss:[esp+0x18]
         // 00419279: push 0x18
         // 0041927b: push esi
         // 0041927c: call 0x419af0
      [-]08000083c4088bc68b4c240864890d????????595e83c40cc20800
         // 00419281: add esp, 0x8
         // 00419284: mov eax, esi
         // 00419286: mov ecx, ss:[esp+0x8]
         // 0041928a: mov fs:[0x0], ecx
         // 00419291: pop ecx
         // 00419292: pop esi
         // 00419293: add esp, 0xc
         // 00419296: retn b2 0x8
      [-]a8017527
         // 00417c3e: test b1 al, b1 0x1
         // 00417c40: jnz 0x417c69
      [-]83c801a3
         // 00417992: or eax, 0x1
         // 00417995: mov ds:[0x425b28], eax
      [-]c74424????????00c705
         // 0041799f: mov ss:[esp+0x14], 0x0
         // 004179a7: mov ds:[0x425b24], ??_7generic_error_category@?A0x846d1564@system@boost@@6B@
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
         // 004192ed: cmp esi, 0x2714
         // 004192f3: jg 0x4193d3
      [-]0f84b0000000
         // 004192f9: jz 0x4193af
      [-]81fe????????7f67
         // 004192ff: cmp esi, 0x3f5
         // 00419305: jg 0x41936e
      [-]8d86????????83f8110f87b6040000
         // 00419309: lea eax, ds:[esi+0xfffffffffffffc1d]
         // 0041930f: cmp eax, 0x11
         // 00419312: ja def_41909A
      [-]4100ff2485
         // 00417cbf: jmp ds:[jpt_417CBF+eax*0x4]
      [-]8b7424186a0556e8
         // 00419326: mov esi, ss:[esp+0x18]
         // 0041932a: push 0x5
         // 0041932c: push esi
         // 0041932d: call 0x419af0
      [-]07000083c4088bc68b4c240864890d????????595e83c40cc20800
         // 00419332: add esp, 0x8
         // 00419335: mov eax, esi
         // 00419337: mov ecx, ss:[esp+0x8]
         // 0041933b: mov fs:[0x0], ecx
         // 00419342: pop ecx
         // 00419343: pop esi
         // 00419344: add esp, 0xc
         // 00419347: retn b2 0x8
      [-]8b7424186a6956e8
         // 0041934a: mov esi, ss:[esp+0x18]
         // 0041934e: push 0x69
         // 00419350: push esi
         // 00419351: call 0x419af0
      [-]07000083c4088bc68b4c240864890d????????595e83c40cc20800
         // 00419356: add esp, 0x8
         // 00419359: mov eax, esi
         // 0041935b: mov ecx, ss:[esp+0x8]
         // 0041935f: mov fs:[0x0], ecx
         // 00419366: pop ecx
         // 00419367: pop esi
         // 00419368: add esp, 0xc
         // 0041936b: retn b2 0x8
      [-]8bc62d????????0f84b2feffff
         // 0041936e: mov eax, esi
         // 00419370: sub eax, 0x4d5
         // 00419375: jz 0x41922d
      [-]2d????????7409
         // 0041937b: sub eax, 0x48c
         // 00419380: jz 0x41938b
      [-]83e8030f8543040000
         // 00419382: sub eax, 0x3
         // 00419385: jnz def_41909A
      [-]8b7424186a1056e8
         // 0041938b: mov esi, ss:[esp+0x18]
         // 0041938f: push 0x10
         // 00419391: push esi
         // 00419392: call 0x419af0
      [-]000083c4088bc68b4c240864890d????????595e83c40cc20800
         // 00419397: add esp, 0x8
         // 0041939a: mov eax, esi
         // 0041939c: mov ecx, ss:[esp+0x8]
         // 004193a0: mov fs:[0x0], ecx
         // 004193a7: pop ecx
         // 004193a8: pop esi
         // 004193a9: add esp, 0xc
         // 004193ac: retn b2 0x8
      [-]8b7424186a0456e8
         // 004193af: mov esi, ss:[esp+0x18]
         // 004193b3: push 0x4
         // 004193b5: push esi
         // 004193b6: call 0x419af0
      [-]000083c4088bc68b4c240864890d????????595e83c40cc20800
         // 004193bb: add esp, 0x8
         // 004193be: mov eax, esi
         // 004193c0: mov ecx, ss:[esp+0x8]
         // 004193c4: mov fs:[0x0], ecx
         // 004193cb: pop ecx
         // 004193cc: pop esi
         // 004193cd: add esp, 0xc
         // 004193d0: retn b2 0x8
      [-]8d86????????83f8380f87ec030000
         // 004193d3: lea eax, ds:[esi+0xffffffffffffd8e7]
         // 004193d9: cmp eax, 0x38
         // 004193dc: ja def_41909A
      [-]4100ff2485
         // 00417d89: jmp ds:[jpt_417D89+eax*0x4]
      [-]8b7424186a0d56e8
         // 004193f0: mov esi, ss:[esp+0x18]
         // 004193f4: push 0xd
         // 004193f6: push esi
         // 004193f7: call 0x419af0
      [-]06000083c4088bc68b4c240864890d????????595e83c40cc20800
         // 004193fc: add esp, 0x8
         // 004193ff: mov eax, esi
         // 00419401: mov ecx, ss:[esp+0x8]
         // 00419405: mov fs:[0x0], ecx
         // 0041940c: pop ecx
         // 0041940d: pop esi
         // 0041940e: add esp, 0xc
         // 00419411: retn b2 0x8
      [-]8b7424186a6456e8
         // 00419414: mov esi, ss:[esp+0x18]
         // 00419418: push 0x64
         // 0041941a: push esi
         // 0041941b: call 0x419af0
      [-]06000083c4088bc68b4c240864890d????????595e83c40cc20800
         // 00419420: add esp, 0x8
         // 00419423: mov eax, esi
         // 00419425: mov ecx, ss:[esp+0x8]
         // 00419429: mov fs:[0x0], ecx
         // 00419430: pop ecx
         // 00419431: pop esi
         // 00419432: add esp, 0xc
         // 00419435: retn b2 0x8
      [-]8b7424186a6556e8
         // 00419438: mov esi, ss:[esp+0x18]
         // 0041943c: push 0x65
         // 0041943e: push esi
         // 0041943f: call 0x419af0
      [-]06000083c4088bc68b4c240864890d????????595e83c40cc20800
         // 00419444: add esp, 0x8
         // 00419447: mov eax, esi
         // 00419449: mov ecx, ss:[esp+0x8]
         // 0041944d: mov fs:[0x0], ecx
         // 00419454: pop ecx
         // 00419455: pop esi
         // 00419456: add esp, 0xc
         // 00419459: retn b2 0x8
      [-]8b7424186a6656e8
         // 0041945c: mov esi, ss:[esp+0x18]
         // 00419460: push 0x66
         // 00419462: push esi
         // 00419463: call 0x419af0
      [-]06000083c4088bc68b4c240864890d????????595e83c40cc20800
         // 00419468: add esp, 0x8
         // 0041946b: mov eax, esi
         // 0041946d: mov ecx, ss:[esp+0x8]
         // 00419471: mov fs:[0x0], ecx
         // 00419478: pop ecx
         // 00419479: pop esi
         // 0041947a: add esp, 0xc
         // 0041947d: retn b2 0x8
      [-]8b7424186a6756e8
         // 00419480: mov esi, ss:[esp+0x18]
         // 00419484: push 0x67
         // 00419486: push esi
         // 00419487: call 0x419af0
      [-]06000083c4088bc68b4c240864890d????????595e83c40cc20800
         // 0041948c: add esp, 0x8
         // 0041948f: mov eax, esi
         // 00419491: mov ecx, ss:[esp+0x8]
         // 00419495: mov fs:[0x0], ecx
         // 0041949c: pop ecx
         // 0041949d: pop esi
         // 0041949e: add esp, 0xc
         // 004194a1: retn b2 0x8
      [-]8b7424186a0956e8
         // 004194a4: mov esi, ss:[esp+0x18]
         // 004194a8: push 0x9
         // 004194aa: push esi
         // 004194ab: call 0x419af0
      [-]000083c4088bc68b4c240864890d????????595e83c40cc20800
         // 004194b0: add esp, 0x8
         // 004194b3: mov eax, esi
         // 004194b5: mov ecx, ss:[esp+0x8]
         // 004194b9: mov fs:[0x0], ecx
         // 004194c0: pop ecx
         // 004194c1: pop esi
         // 004194c2: add esp, 0xc
         // 004194c5: retn b2 0x8
      [-]8b7424186a6a56e8
         // 004194c8: mov esi, ss:[esp+0x18]
         // 004194cc: push 0x6a
         // 004194ce: push esi
         // 004194cf: call 0x419af0
      [-]000083c4088bc68b4c240864890d????????595e83c40cc20800
         // 004194d4: add esp, 0x8
         // 004194d7: mov eax, esi
         // 004194d9: mov ecx, ss:[esp+0x8]
         // 004194dd: mov fs:[0x0], ecx
         // 004194e4: pop ecx
         // 004194e5: pop esi
         // 004194e6: add esp, 0xc
         // 004194e9: retn b2 0x8
      [-]8b7424186a6b56e8
         // 004194ec: mov esi, ss:[esp+0x18]
         // 004194f0: push 0x6b
         // 004194f2: push esi
         // 004194f3: call 0x419af0
      [-]05000083c4088bc68b4c240864890d????????595e83c40cc20800
         // 004194f8: add esp, 0x8
         // 004194fb: mov eax, esi
         // 004194fd: mov ecx, ss:[esp+0x8]
         // 00419501: mov fs:[0x0], ecx
         // 00419508: pop ecx
         // 00419509: pop esi
         // 0041950a: add esp, 0xc
         // 0041950d: retn b2 0x8
      [-]8b7424186a6c56e8
         // 00419510: mov esi, ss:[esp+0x18]
         // 00419514: push 0x6c
         // 00419516: push esi
         // 00419517: call 0x419af0
      [-]05000083c4088bc68b4c240864890d????????595e83c40cc20800
         // 0041951c: add esp, 0x8
         // 0041951f: mov eax, esi
         // 00419521: mov ecx, ss:[esp+0x8]
         // 00419525: mov fs:[0x0], ecx
         // 0041952c: pop ecx
         // 0041952d: pop esi
         // 0041952e: add esp, 0xc
         // 00419531: retn b2 0x8
      [-]8b7424186a6d56e8
         // 00419534: mov esi, ss:[esp+0x18]
         // 00419538: push 0x6d
         // 0041953a: push esi
         // 0041953b: call 0x419af0
      [-]05000083c4088bc68b4c240864890d????????595e83c40cc20800
         // 00419540: add esp, 0x8
         // 00419543: mov eax, esi
         // 00419545: mov ecx, ss:[esp+0x8]
         // 00419549: mov fs:[0x0], ecx
         // 00419550: pop ecx
         // 00419551: pop esi
         // 00419552: add esp, 0xc
         // 00419555: retn b2 0x8
      [-]8b7424186a0e56e8
         // 00419558: mov esi, ss:[esp+0x18]
         // 0041955c: push 0xe
         // 0041955e: push esi
         // 0041955f: call 0x419af0
      [-]05000083c4088bc68b4c240864890d????????595e83c40cc20800
         // 00419564: add esp, 0x8
         // 00419567: mov eax, esi
         // 00419569: mov ecx, ss:[esp+0x8]
         // 0041956d: mov fs:[0x0], ecx
         // 00419574: pop ecx
         // 00419575: pop esi
         // 00419576: add esp, 0xc
         // 00419579: retn b2 0x8
      [-]8b7424186a6e56e8
         // 0041957c: mov esi, ss:[esp+0x18]
         // 00419580: push 0x6e
         // 00419582: push esi
         // 00419583: call 0x419af0
      [-]05000083c4088bc68b4c240864890d????????595e83c40cc20800
         // 00419588: add esp, 0x8
         // 0041958b: mov eax, esi
         // 0041958d: mov ecx, ss:[esp+0x8]
         // 00419591: mov fs:[0x0], ecx
         // 00419598: pop ecx
         // 00419599: pop esi
         // 0041959a: add esp, 0xc
         // 0041959d: retn b2 0x8
      [-]8b7424186a7056e8
         // 004195a0: mov esi, ss:[esp+0x18]
         // 004195a4: push 0x70
         // 004195a6: push esi
         // 004195a7: call 0x419af0
      [-]000083c4088bc68b4c240864890d????????595e83c40cc20800
         // 004195ac: add esp, 0x8
         // 004195af: mov eax, esi
         // 004195b1: mov ecx, ss:[esp+0x8]
         // 004195b5: mov fs:[0x0], ecx
         // 004195bc: pop ecx
         // 004195bd: pop esi
         // 004195be: add esp, 0xc
         // 004195c1: retn b2 0x8
      [-]8b7424186a7156e8
         // 004195c4: mov esi, ss:[esp+0x18]
         // 004195c8: push 0x71
         // 004195ca: push esi
         // 004195cb: call 0x419af0
      [-]000083c4088bc68b4c240864890d????????595e83c40cc20800
         // 004195d0: add esp, 0x8
         // 004195d3: mov eax, esi
         // 004195d5: mov ecx, ss:[esp+0x8]
         // 004195d9: mov fs:[0x0], ecx
         // 004195e0: pop ecx
         // 004195e1: pop esi
         // 004195e2: add esp, 0xc
         // 004195e5: retn b2 0x8
      [-]8b7424186a7356e8
         // 004195e8: mov esi, ss:[esp+0x18]
         // 004195ec: push 0x73
         // 004195ee: push esi
         // 004195ef: call 0x419af0
      [-]04000083c4088bc68b4c240864890d????????595e83c40cc20800
         // 004195f4: add esp, 0x8
         // 004195f7: mov eax, esi
         // 004195f9: mov ecx, ss:[esp+0x8]
         // 004195fd: mov fs:[0x0], ecx
         // 00419604: pop ecx
         // 00419605: pop esi
         // 00419606: add esp, 0xc
         // 00419609: retn b2 0x8
      [-]8b7424186a7456e8
         // 0041960c: mov esi, ss:[esp+0x18]
         // 00419610: push 0x74
         // 00419612: push esi
         // 00419613: call 0x419af0
      [-]04000083c4088bc68b4c240864890d????????595e83c40cc20800
         // 00419618: add esp, 0x8
         // 0041961b: mov eax, esi
         // 0041961d: mov ecx, ss:[esp+0x8]
         // 00419621: mov fs:[0x0], ecx
         // 00419628: pop ecx
         // 00419629: pop esi
         // 0041962a: add esp, 0xc
         // 0041962d: retn b2 0x8
      [-]8b7424186a7556e8
         // 00419630: mov esi, ss:[esp+0x18]
         // 00419634: push 0x75
         // 00419636: push esi
         // 00419637: call 0x419af0
      [-]04000083c4088bc68b4c240864890d????????595e83c40cc20800
         // 0041963c: add esp, 0x8
         // 0041963f: mov eax, esi
         // 00419641: mov ecx, ss:[esp+0x8]
         // 00419645: mov fs:[0x0], ecx
         // 0041964c: pop ecx
         // 0041964d: pop esi
         // 0041964e: add esp, 0xc
         // 00419651: retn b2 0x8
      [-]8b7424186a7656e8
         // 00419654: mov esi, ss:[esp+0x18]
         // 00419658: push 0x76
         // 0041965a: push esi
         // 0041965b: call 0x419af0
      [-]04000083c4088bc68b4c240864890d????????595e83c40cc20800
         // 00419660: add esp, 0x8
         // 00419663: mov eax, esi
         // 00419665: mov ecx, ss:[esp+0x8]
         // 00419669: mov fs:[0x0], ecx
         // 00419670: pop ecx
         // 00419671: pop esi
         // 00419672: add esp, 0xc
         // 00419675: retn b2 0x8
      [-]8b7424186a7756e8
         // 00419678: mov esi, ss:[esp+0x18]
         // 0041967c: push 0x77
         // 0041967e: push esi
         // 0041967f: call 0x419af0
      [-]04000083c4088bc68b4c240864890d????????595e83c40cc20800
         // 00419684: add esp, 0x8
         // 00419687: mov eax, esi
         // 00419689: mov ecx, ss:[esp+0x8]
         // 0041968d: mov fs:[0x0], ecx
         // 00419694: pop ecx
         // 00419695: pop esi
         // 00419696: add esp, 0xc
         // 00419699: retn b2 0x8
      [-]8b7424186a7b56e8
         // 0041969c: mov esi, ss:[esp+0x18]
         // 004196a0: push 0x7b
         // 004196a2: push esi
         // 004196a3: call 0x419af0
      [-]000083c4088bc68b4c240864890d????????595e83c40cc20800
         // 004196a8: add esp, 0x8
         // 004196ab: mov eax, esi
         // 004196ad: mov ecx, ss:[esp+0x8]
         // 004196b1: mov fs:[0x0], ecx
         // 004196b8: pop ecx
         // 004196b9: pop esi
         // 004196ba: add esp, 0xc
         // 004196bd: retn b2 0x8
      [-]8b7424186a7e56e8
         // 004196c0: mov esi, ss:[esp+0x18]
         // 004196c4: push 0x7e
         // 004196c6: push esi
         // 004196c7: call 0x419af0
      [-]000083c4088bc68b4c240864890d????????595e83c40cc20800
         // 004196cc: add esp, 0x8
         // 004196cf: mov eax, esi
         // 004196d1: mov ecx, ss:[esp+0x8]
         // 004196d5: mov fs:[0x0], ecx
         // 004196dc: pop ecx
         // 004196dd: pop esi
         // 004196de: add esp, 0xc
         // 004196e1: retn b2 0x8
      [-]8b74241868????????56e8
         // 004196e4: mov esi, ss:[esp+0x18]
         // 004196e8: push 0x80
         // 004196ed: push esi
         // 004196ee: call 0x419af0
      [-]03000083c4088bc68b4c240864890d????????595e83c40cc20800
         // 004196f3: add esp, 0x8
         // 004196f6: mov eax, esi
         // 004196f8: mov ecx, ss:[esp+0x8]
         // 004196fc: mov fs:[0x0], ecx
         // 00419703: pop ecx
         // 00419704: pop esi
         // 00419705: add esp, 0xc
         // 00419708: retn b2 0x8
      [-]8b74241868????????56e8
         // 0041970b: mov esi, ss:[esp+0x18]
         // 0041970f: push 0x82
         // 00419714: push esi
         // 00419715: call 0x419af0
      [-]03000083c4088bc68b4c240864890d????????595e83c40cc20800
         // 0041971a: add esp, 0x8
         // 0041971d: mov eax, esi
         // 0041971f: mov ecx, ss:[esp+0x8]
         // 00419723: mov fs:[0x0], ecx
         // 0041972a: pop ecx
         // 0041972b: pop esi
         // 0041972c: add esp, 0xc
         // 0041972f: retn b2 0x8
      [-]8b74241868????????56e8
         // 00419732: mov esi, ss:[esp+0x18]
         // 00419736: push 0x87
         // 0041973b: push esi
         // 0041973c: call 0x419af0
      [-]03000083c4088bc68b4c240864890d????????595e83c40cc20800
         // 00419741: add esp, 0x8
         // 00419744: mov eax, esi
         // 00419746: mov ecx, ss:[esp+0x8]
         // 0041974a: mov fs:[0x0], ecx
         // 00419751: pop ecx
         // 00419752: pop esi
         // 00419753: add esp, 0xc
         // 00419756: retn b2 0x8
      [-]8b74241868????????56e8
         // 00419759: mov esi, ss:[esp+0x18]
         // 0041975d: push 0x88
         // 00419762: push esi
         // 00419763: call 0x419af0
      [-]03000083c4088bc68b4c240864890d????????595e83c40cc20800
         // 00419768: add esp, 0x8
         // 0041976b: mov eax, esi
         // 0041976d: mov ecx, ss:[esp+0x8]
         // 00419771: mov fs:[0x0], ecx
         // 00419778: pop ecx
         // 00419779: pop esi
         // 0041977a: add esp, 0xc
         // 0041977d: retn b2 0x8
      [-]8b74241868????????56e8
         // 00419780: mov esi, ss:[esp+0x18]
         // 00419784: push 0x8a
         // 00419789: push esi
         // 0041978a: call 0x419af0
      [-]03000083c4088bc68b4c240864890d????????595e83c40cc20800
         // 0041978f: add esp, 0x8
         // 00419792: mov eax, esi
         // 00419794: mov ecx, ss:[esp+0x8]
         // 00419798: mov fs:[0x0], ecx
         // 0041979f: pop ecx
         // 004197a0: pop esi
         // 004197a1: add esp, 0xc
         // 004197a4: retn b2 0x8
      [-]8b74241868????????56e8
         // 004197a7: mov esi, ss:[esp+0x18]
         // 004197ab: push 0x8c
         // 004197b0: push esi
         // 004197b1: call 0x419af0
      [-]000083c4088bc68b4c240864890d????????595e83c40cc20800
         // 004197b6: add esp, 0x8
         // 004197b9: mov eax, esi
         // 004197bb: mov ecx, ss:[esp+0x8]
         // 004197bf: mov fs:[0x0], ecx
         // 004197c6: pop ecx
         // 004197c7: pop esi
         // 004197c8: add esp, 0xc
         // 004197cb: retn b2 0x8
      [-]a8017527
         // 00418173: test b1 al, b1 0x1
         // 00418175: jnz 0x41819e
      [-]83c801a3
         // 00417ec7: or eax, 0x1
         // 00417eca: mov ds:[0x425b20], eax
      [-]c7442414????????c705
         // 00417ed4: mov ss:[esp+0x14], 0x1
         // 00417edc: mov ds:[0x425b1c], ??_7system_error_category@?A0x846d1564@system@boost@@6B@
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
      [-]00008bd083c40485d2744d
         // 00418551: mov edx, eax
         // 00418553: add esp, 0x4
         // 00418556: test edx, edx
         // 00418558: jz 0x4185a7
      [-]803a00c7442440????????c74424????????00c644242c007504
         // 00419c1a: cmp b1 ds:[edx], b1 0x0
         // 00419c1d: mov ss:[esp+0x40], 0xf
         // 00419c25: mov ss:[esp+0x3c], 0x0
         // 00419c2d: mov b1 ss:[esp+0x2c], b1 0x0
         // 00419c32: jnz 0x419c38
      [-]33c9eb11
         // 00419c34: xor ecx, ecx
         // 00419c36: jmp 0x419c49
      [-]8bca8d79018d4900
         // 00419c38: mov ecx, edx
         // 00419c3a: lea edi, ds:[ecx+0x1]
         // 00419c3d: lea ecx, ds:[ecx+0x0]
      [-]8a014184c075f9
         // 00419c40: mov b1 al, b1 ds:[ecx]
         // 00419c42: inc ecx
         // 00419c43: test b1 al, b1 al
         // 00419c45: jnz 0x419c40
      [-]51528d4c2434e8
         // 00418589: push ecx
         // 0041858a: push edx
         // 0041858b: lea ecx, ss:[esp+0x34]
         // 0041858f: call 0x401a40
      [-]feff8d7c242cc7442450????????bb????????eb30
         // 00418594: lea edi, ss:[esp+0x2c]
         // 00418598: mov ss:[esp+0x50], 0x1
         // 004185a0: mov ebx, 0x1
         // 004185a5: jmp 0x4185d7
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
         // 00419c97: mov ds:[esi+0x14], 0xf
         // 00419c9e: mov ds:[esi+0x10], 0x0
         // 00419ca5: mov b1 ds:[esi], b1 0x0
         // 00419ca8: cmp ds:[edi+0x14], 0x10
         // 00419cac: mov ss:[esp+0x10], ebx
         // 00419cb0: jnb 0x419cc5
      [-]8b4710407417
         // 00419cb2: mov eax, ds:[edi+0x10]
         // 00419cb5: inc eax
         // 00419cb6: jz 0x419ccf
      [-]505756e8
         // 004185f8: push eax
         // 004185f9: push edi
         // 004185fa: push esi
         // 004185fb: call _memmove
      [-]feff83c40ceb0a
         // 00418600: add esp, 0xc
         // 00418603: jmp 0x41860f
      [-]8b078906c707????????
         // 00419cc5: mov eax, ds:[edi]
         // 00419cc7: mov ds:[esi], eax
         // 00419cc9: mov ds:[edi], 0x0
      [-]8b471083cb048946108b4714894614c74714????????c747????????00c60700f6c302742b
         // 00419ccf: mov eax, ds:[edi+0x10]
         // 00419cd2: or ebx, 0x4
         // 00419cd5: mov ds:[esi+0x10], eax
         // 00419cd8: mov eax, ds:[edi+0x14]
         // 00419cdb: mov ds:[esi+0x14], eax
         // 00419cde: mov ds:[edi+0x14], 0xf
         // 00419ce5: mov ds:[edi+0x10], 0x0
         // 00419cec: mov b1 ds:[edi], b1 0x0
         // 00419cef: test b1 bl, b1 0x2
         // 00419cf2: jz 0x419d1f
      [-]83e3fd837c242810720c
         // 00419cf4: and ebx, 0xfffffffffffffffd
         // 00419cf7: cmp ss:[esp+0x28], 0x10
         // 00419cfc: jb 0x419d0a
      [-]ff742414e8
         // 0041863e: push ss:[esp+0x14]
         // 00418642: call j__free
      [-]feff83c404
         // 00418647: add esp, 0x4
      [-]c7442428????????c7
         // 00419d0a: mov ss:[esp+0x28], 0xf
         // 00419d12: mov ss:[esp+0x24], 0x0
         // 00419d1a: mov b1 ss:[esp+0x14], b1 0x0

  }
  condition:
    all of them
}
