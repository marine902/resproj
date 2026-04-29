rule mailru_40_0 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         538b5d0856578b
         // 00401983: push ebx
         // 00401984: mov ebx, ss:[ebp+0x8]
         // 00401987: push esi
         // 00401988: push edi
         // 0040198b: mov ecx, ss:[ebp+0xc]
      [-]8b7b103b
         // 0040198e: mov edi, ds:[ebx+0x10]
         // 00401991: cmp edi, ecx
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
      [-]558bec6a00ff7508ff15
         // 004054ef: push ebp
         // 004054f0: mov ebp, esp
         // 004054f2: push 0x0
         // 004054f4: push ss:[ebp+0x8]
         // 004054f7: call ds:[0x41c010]
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
      [-]558bec837d0800742d
         // 004092f9: push ebp
         // 004092fa: mov ebp, esp
         // 004092fc: cmp ss:[ebp+0x8], 0x0
         // 00409300: jz 0x40932f
      [-]558bec8b4508a3
         // 0040f6bd: push ebp
         // 0040f6be: mov ebp, esp
         // 0040f6c0: mov eax, ss:[ebp+0x8]
         // 0040f6c3: mov ds:[0x425038], eax
      [-]558bec83ec24a1
         // 0040fc8f: push ebp
         // 0040fc90: mov ebp, esp
         // 0040fc92: sub esp, 0x24
         // 0040fc95: mov eax, ds:[0x4231e0]
      [-]33c58945fc8b4508538b1d
         // 0040fc9a: xor eax, ebp
         // 0040fc9c: mov ss:[ebp+0xfffffffffffffffc], eax
         // 0040fc9f: mov eax, ss:[ebp+0x8]
         // 0040fca2: push ebx
         // 0040fca3: mov ebx, ds:[0x41a0b0]
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
         // 0040fcbe: call ___crtIsPackagedApp
      [-]8b0685c07402
         // 00410a5f: mov eax, ds:[esi]
         // 00410a61: test eax, eax
         // 00410a63: jz 0x410a67
      [-]3bf772f1
         // 00410a6a: cmp esi, edi
         // 00410a6c: jb 0x410a5f
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
      [-]33c08d7df0ab
         // 00415339: xor eax, eax
         // 0041533b: lea edi, ss:[ebp+0xfffffffffffffff0]
         // 0041533e: stosdd 
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
         // 004153af: inc edx
         // 004153b0: cmp edx, esi
         // 004153b2: jl 0x4153a9
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
      [-]8b4495f0
         // 00416c9b: mov eax, ss:[ebp+edx*0x4]
      [-]8bc77205
         // 00416cac: mov eax, edi
         // 00416cae: jb 0x416cb5
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
      [-]2bc833c0f3ab83cfff
         // 00415458: sub ecx, eax
         // 0041545a: xor eax, eax
         // 0041545c: rep stosdd 
         // 0041545e: or edi, 0xffffffffffffffff
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
      [-]e9b6feffff
         // 00415486: jmp 0x415341
      [-]3bca0f8f19020000
         // 0041548b: cmp ecx, edx
         // 0041548d: jg 0x4156ac
      [-]83e21f03c2c1f805
         // 004154a3: and edx, 0x1f
         // 004154a6: add eax, edx
         // 004154a8: sar eax, b1 0x5
      [-]25????????7905
         // 004154b3: and eax, 0xffffffff8000001f
         // 004154b8: jns 0x4154bf
      [-]4883c8e040
         // 004154ba: dec eax
         // 004154bb: or eax, 0xffffffffffffffe0
         // 004154be: inc eax
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
         // 00415518: cmp ecx, eax
         // 0041551a: jl 0x415527
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
         // 00415570: test ss:[ebp+edx*0x4], eax
         // 00415574: jmp 0x41557a
      [-]423bd67cf5
         // 0041557c: inc edx
         // 0041557d: cmp edx, esi
         // 0041557f: jl 0x415576
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
         // 0041559b: dec edi
         // 0041559c: or edi, 0xffffffffffffffe0
         // 0041559f: inc edi
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
         // 004155bf: cmp eax, ss:[ebp+0xffffffffffffffdc]
         // 004155c2: jnb 0x4155c7
      [-]894495f04a7828
         // 004155c7: mov ss:[ebp+edx*0x4], eax
         // 004155cb: dec edx
         // 004155cc: js 0x4155f6
      [-]85c97421
         // 004155ce: test ecx, ecx
         // 004155d0: jz 0x4155f3
      [-]8b4495f0
         // 00416e5c: mov eax, ss:[ebp+edx*0x4]
      [-]8d78013bf8
         // 00416e62: lea edi, ds:[eax+0x1]
         // 00416e65: cmp edi, eax
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
         // 00415691: cmp ecx, esi
         // 00415693: jl 0x41569d
      [-]83ea044979ea
         // 004156a1: sub edx, 0x4
         // 004156a4: dec ecx
         // 004156a5: jns 0x415691
      [-]e9d8fdffff
         // 004156a7: jmp 0x415484
      [-]0f8ca2000000
         // 004156b2: jl 0x41575a
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
         // 004156e3: dec ecx
         // 004156e4: or ecx, 0xffffffffffffffe0
         // 004156e7: inc ecx
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
         // 004157d9: cmp ecx, edi
         // 004157db: jl 0x4157e5
      [-]83ea044979ea
         // 004157e9: sub edx, 0x4
         // 004157ec: dec ecx
         // 004157ed: jns 0x4157d9
      [-]83f8207502
         // 00415824: cmp eax, 0x20
         // 00415827: jnz 0x41582b
      [-]8b4dfc8bc35f5e
         // 004155eb: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 004155ee: mov eax, ebx
         // 004155f0: pop edi
         // 004155f1: pop esi
      [-]ffff8be55dc3
         // 004155fa: mov esp, ebp
         // 004155fc: pop ebp
         // 004155fd: retn 
      [-]64a1????????5056a1
         // 00419057: mov eax, fs:[0x0]
         // 0041905d: push eax
         // 0041905e: push esi
         // 0041905f: mov eax, ds:[___security_cookie]
      [-]33c4508d44240864a3????????8b74241c81fe????????0f8f6c020000
         // 00419064: xor eax, esp
         // 00419066: push eax
         // 00419067: lea eax, ss:[esp+0x8]
         // 0041906b: mov fs:[0x0], eax
         // 00419071: mov esi, ss:[esp+0x1c]
         // 00419075: cmp esi, 0x10b
         // 0041907b: jg 0x4192ed
      [-]0f8412020000
         // 00417a21: jz 0x417c39
      [-]81fe????????0f873b070000
         // 00417a27: cmp esi, 0xd4
         // 00417a2d: ja def_417A3A
      [-]4100ff2485
         // 0041909a: jmp ds:[jpt_41909A+eax*0x4]
      [-]8b7424186a0056e8
         // 00417791: mov esi, ss:[esp+0x18]
         // 00417795: push 0x0
         // 00417797: push esi
         // 00417798: call 0x418180
      [-]4c240864890d????????595e83c40cc20800
         // 004177a6: mov fs:[0x0], ecx
         // 004177ad: pop ecx
         // 004177ae: pop esi
         // 004177af: add esp, 0xc
         // 004177b2: retn b2 0x8
      [-]8b7424186a1156e8
         // 00417a65: mov esi, ss:[esp+0x18]
         // 00417a69: push 0x11
         // 00417a6b: push esi
         // 00417a6c: call 0x418430
      [-]000083c4088b
         // 00417a71: add esp, 0x8
         // 00417a74: mov eax, esi
      [-]4c240864890d????????595e83c40cc20800
         // 00417a76: mov ecx, ss:[esp+0x8]
         // 00417a7a: mov fs:[0x0], ecx
         // 00417a81: pop ecx
         // 00417a82: pop esi
         // 00417a83: add esp, 0xc
         // 00417a86: retn b2 0x8
      [-]8b7424186a1356e8
         // 004177d9: mov esi, ss:[esp+0x18]
         // 004177dd: push 0x13
         // 004177df: push esi
         // 004177e0: call 0x418180
      [-]4c240864890d????????595e83c40cc20800
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
      [-]4c240864890d????????595e83c40cc20800
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
      [-]4c240864890d????????595e83c40cc20800
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
      [-]4c240864890d????????595e83c40cc20800
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
      [-]4c240864890d????????595e83c40cc20800
         // 0041787e: mov fs:[0x0], ecx
         // 00417885: pop ecx
         // 00417886: pop esi
         // 00417887: add esp, 0xc
         // 0041788a: retn b2 0x8
      [-]8b7424186a2856e8
         // 00417b3d: mov esi, ss:[esp+0x18]
         // 00417b41: push 0x28
         // 00417b43: push esi
         // 00417b44: call 0x418430
      [-]000083c4088b
         // 00417b49: add esp, 0x8
         // 00417b4e: mov ecx, ss:[esp+0x8]
      [-]4c240864890d????????595e83c40cc20800
         // 00417b52: mov fs:[0x0], ecx
         // 00417b59: pop ecx
         // 00417b5a: pop esi
         // 00417b5b: add esp, 0xc
         // 00417b5e: retn b2 0x8
      [-]8b7424186a1656e8
         // 00417b61: mov esi, ss:[esp+0x18]
         // 00417b65: push 0x16
         // 00417b67: push esi
         // 00417b68: call 0x418430
      [-]000083c4088bc68b4c240864890d????????595e83c40cc20800
         // 00417b6d: add esp, 0x8
         // 00417b70: mov eax, esi
         // 00417b72: mov ecx, ss:[esp+0x8]
         // 00417b76: mov fs:[0x0], ecx
         // 00417b7d: pop ecx
         // 00417b7e: pop esi
         // 00417b7f: add esp, 0xc
         // 00417b82: retn b2 0x8
      [-]8b7424186a2756e8
         // 004178d5: mov esi, ss:[esp+0x18]
         // 004178d9: push 0x27
         // 004178db: push esi
         // 004178dc: call 0x418180
      [-]4c240864890d????????595e83c40cc20800
         // 004178ea: mov fs:[0x0], ecx
         // 004178f1: pop ecx
         // 004178f2: pop esi
         // 004178f3: add esp, 0xc
         // 004178f6: retn b2 0x8
      [-]8b7424186a0c56e8
         // 00417ba9: mov esi, ss:[esp+0x18]
         // 00417bad: push 0xc
         // 00417baf: push esi
         // 00417bb0: call 0x418430
      [-]08000083c4088b
         // 00417bb5: add esp, 0x8
         // 00417bb8: mov eax, esi
      [-]4c240864890d????????595e83c40cc20800
         // 00417bba: mov ecx, ss:[esp+0x8]
         // 00417bbe: mov fs:[0x0], ecx
         // 00417bc5: pop ecx
         // 00417bc6: pop esi
         // 00417bc7: add esp, 0xc
         // 00417bca: retn b2 0x8
      [-]8b7424186a0b56e8
         // 00417bcd: mov esi, ss:[esp+0x18]
         // 00417bd1: push 0xb
         // 00417bd3: push esi
         // 00417bd4: call 0x418430
      [-]08000083c4088b
         // 00417bd9: add esp, 0x8
         // 00417bdc: mov eax, esi
      [-]4c240864890d????????595e83c40cc20800
         // 00417bde: mov ecx, ss:[esp+0x8]
         // 00417be2: mov fs:[0x0], ecx
         // 00417be9: pop ecx
         // 00417bea: pop esi
         // 00417beb: add esp, 0xc
         // 00417bee: retn b2 0x8
      [-]8b7424186a1256e8
         // 00417941: mov esi, ss:[esp+0x18]
         // 00417945: push 0x12
         // 00417947: push esi
         // 00417948: call 0x418180
      [-]4c240864890d????????595e83c40cc20800
         // 00417956: mov fs:[0x0], ecx
         // 0041795d: pop ecx
         // 0041795e: pop esi
         // 0041795f: add esp, 0xc
         // 00417962: retn b2 0x8
      [-]8b7424186a1856e8
         // 00417c15: mov esi, ss:[esp+0x18]
         // 00417c19: push 0x18
         // 00417c1b: push esi
         // 00417c1c: call 0x418430
      [-]08000083c4088bc68b4c240864890d????????595e83c40cc20800
         // 00417c21: add esp, 0x8
         // 00417c24: mov eax, esi
         // 00417c26: mov ecx, ss:[esp+0x8]
         // 00417c2a: mov fs:[0x0], ecx
         // 00417c31: pop ecx
         // 00417c32: pop esi
         // 00417c33: add esp, 0xc
         // 00417c36: retn b2 0x8
      [-]a8017527
         // 0041798e: test b1 al, b1 0x1
         // 00417990: jnz 0x4179b9
      [-]83c801a3
         // 00417c42: or eax, 0x1
         // 00417c45: mov ds:[0x425b6c], eax
      [-]c74424????????00c705
         // 00417c4f: mov ss:[esp+0x14], 0x0
         // 00417c57: mov ds:[0x425b68], 0x4201b8
      [-]8b442418c700????????c74004
         // 004179b9: mov eax, ss:[esp+0x18]
         // 004179bd: mov ds:[eax], 0x16
         // 004179c3: mov ds:[eax+0x4], 0x425b24
      [-]8b4c240864890d????????595e83c40cc20800
         // 004179ca: mov ecx, ss:[esp+0x8]
         // 004179ce: mov fs:[0x0], ecx
         // 004179d5: pop ecx
         // 004179d6: pop esi
         // 004179d7: add esp, 0xc
         // 004179da: retn b2 0x8
      [-]81fe????????0f8fda000000
         // 00417c8d: cmp esi, 0x2714
         // 00417c93: jg 0x417d73
      [-]0f84b0000000
         // 00417c99: jz 0x417d4f
      [-]81fe????????7f67
         // 00417c9f: cmp esi, 0x3f5
         // 00417ca5: jg 0x417d0e
      [-]8d86????????83f8110f87b6040000
         // 00417ca9: lea eax, ds:[esi+0xfffffffffffffc1d]
         // 00417caf: cmp eax, 0x11
         // 00417cb2: ja def_417A3A
      [-]4100ff2485
         // 0041931f: jmp ds:[jpt_41931F+eax*0x4]
      [-]8b7424186a0556e8
         // 00417a16: mov esi, ss:[esp+0x18]
         // 00417a1a: push 0x5
         // 00417a1c: push esi
         // 00417a1d: call 0x418180
      [-]4c240864890d????????595e83c40cc20800
         // 00417a2b: mov fs:[0x0], ecx
         // 00417a32: pop ecx
         // 00417a33: pop esi
         // 00417a34: add esp, 0xc
         // 00417a37: retn b2 0x8
      [-]8b7424186a6956e8
         // 00417cea: mov esi, ss:[esp+0x18]
         // 00417cee: push 0x69
         // 00417cf0: push esi
         // 00417cf1: call 0x418430
      [-]07000083c4088bc68b4c240864890d????????595e83c40cc20800
         // 00417cf6: add esp, 0x8
         // 00417cf9: mov eax, esi
         // 00417cfb: mov ecx, ss:[esp+0x8]
         // 00417cff: mov fs:[0x0], ecx
         // 00417d06: pop ecx
         // 00417d07: pop esi
         // 00417d08: add esp, 0xc
         // 00417d0b: retn b2 0x8
      [-]8bc62d????????0f84b2feffff
         // 00417d0e: mov eax, esi
         // 00417d10: sub eax, 0x4d5
         // 00417d15: jz 0x417bcd
      [-]2d????????7409
         // 00417d1b: sub eax, 0x48c
         // 00417d20: jz 0x417d2b
      [-]83e8030f8543040000
         // 00417d22: sub eax, 0x3
         // 00417d25: jnz def_417A3A
      [-]8b7424186a1056e8
         // 00417d2b: mov esi, ss:[esp+0x18]
         // 00417d2f: push 0x10
         // 00417d31: push esi
         // 00417d32: call 0x418430
      [-]000083c4088bc68b4c240864890d????????595e83c40cc20800
         // 00417d37: add esp, 0x8
         // 00417d3a: mov eax, esi
         // 00417d3c: mov ecx, ss:[esp+0x8]
         // 00417d40: mov fs:[0x0], ecx
         // 00417d47: pop ecx
         // 00417d48: pop esi
         // 00417d49: add esp, 0xc
         // 00417d4c: retn b2 0x8
      [-]8b7424186a0456e8
         // 00417a9f: mov esi, ss:[esp+0x18]
         // 00417aa3: push 0x4
         // 00417aa5: push esi
         // 00417aa6: call 0x418180
      [-]4c240864890d????????595e83c40cc20800
         // 00417ab4: mov fs:[0x0], ecx
         // 00417abb: pop ecx
         // 00417abc: pop esi
         // 00417abd: add esp, 0xc
         // 00417ac0: retn b2 0x8
      [-]8d86????????83f8380f87ec030000
         // 00417d73: lea eax, ds:[esi+0xffffffffffffd8e7]
         // 00417d79: cmp eax, 0x38
         // 00417d7c: ja def_417A3A
      [-]4100ff2485
         // 004193e9: jmp ds:[jpt_4193E9+eax*0x4]
      [-]8b7424186a0d56e8
         // 00417ae0: mov esi, ss:[esp+0x18]
         // 00417ae4: push 0xd
         // 00417ae6: push esi
         // 00417ae7: call 0x418180
      [-]4c240864890d????????595e83c40cc20800
         // 00417af5: mov fs:[0x0], ecx
         // 00417afc: pop ecx
         // 00417afd: pop esi
         // 00417afe: add esp, 0xc
         // 00417b01: retn b2 0x8
      [-]8b7424186a6456e8
         // 00417db4: mov esi, ss:[esp+0x18]
         // 00417db8: push 0x64
         // 00417dba: push esi
         // 00417dbb: call 0x418430
      [-]06000083c4088bc68b4c240864890d????????595e83c40cc20800
         // 00417dc0: add esp, 0x8
         // 00417dc3: mov eax, esi
         // 00417dc5: mov ecx, ss:[esp+0x8]
         // 00417dc9: mov fs:[0x0], ecx
         // 00417dd0: pop ecx
         // 00417dd1: pop esi
         // 00417dd2: add esp, 0xc
         // 00417dd5: retn b2 0x8
      [-]8b7424186a6556e8
         // 00417dd8: mov esi, ss:[esp+0x18]
         // 00417ddc: push 0x65
         // 00417dde: push esi
         // 00417ddf: call 0x418430
      [-]06000083c4088b
         // 00417de4: add esp, 0x8
         // 00417de9: mov ecx, ss:[esp+0x8]
      [-]4c240864890d????????595e83c40cc20800
         // 00417ded: mov fs:[0x0], ecx
         // 00417df4: pop ecx
         // 00417df5: pop esi
         // 00417df6: add esp, 0xc
         // 00417df9: retn b2 0x8
      [-]8b7424186a6656e8
         // 00417b4c: mov esi, ss:[esp+0x18]
         // 00417b50: push 0x66
         // 00417b52: push esi
         // 00417b53: call 0x418180
      [-]4c240864890d????????595e83c40cc20800
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
      [-]4c240864890d????????595e83c40cc20800
         // 00417b85: mov fs:[0x0], ecx
         // 00417b8c: pop ecx
         // 00417b8d: pop esi
         // 00417b8e: add esp, 0xc
         // 00417b91: retn b2 0x8
      [-]8b7424186a0956e8
         // 00417e44: mov esi, ss:[esp+0x18]
         // 00417e48: push 0x9
         // 00417e4a: push esi
         // 00417e4b: call 0x418430
      [-]000083c4088b
         // 00417e50: add esp, 0x8
         // 00417e53: mov eax, esi
      [-]4c240864890d????????595e83c40cc20800
         // 00417e55: mov ecx, ss:[esp+0x8]
         // 00417e59: mov fs:[0x0], ecx
         // 00417e60: pop ecx
         // 00417e61: pop esi
         // 00417e62: add esp, 0xc
         // 00417e65: retn b2 0x8
      [-]8b7424186a6a56e8
         // 00417bb8: mov esi, ss:[esp+0x18]
         // 00417bbc: push 0x6a
         // 00417bbe: push esi
         // 00417bbf: call 0x418180
      [-]4c240864890d????????595e83c40cc20800
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
      [-]4c240864890d????????595e83c40cc20800
         // 00417bf1: mov fs:[0x0], ecx
         // 00417bf8: pop ecx
         // 00417bf9: pop esi
         // 00417bfa: add esp, 0xc
         // 00417bfd: retn b2 0x8
      [-]8b7424186a6c56e8
         // 00417eb0: mov esi, ss:[esp+0x18]
         // 00417eb4: push 0x6c
         // 00417eb6: push esi
         // 00417eb7: call 0x418430
      [-]05000083c4088bc68b4c240864890d????????595e83c40cc20800
         // 00417ebc: add esp, 0x8
         // 00417ebf: mov eax, esi
         // 00417ec1: mov ecx, ss:[esp+0x8]
         // 00417ec5: mov fs:[0x0], ecx
         // 00417ecc: pop ecx
         // 00417ecd: pop esi
         // 00417ece: add esp, 0xc
         // 00417ed1: retn b2 0x8
      [-]8b7424186a6d56e8
         // 00417c24: mov esi, ss:[esp+0x18]
         // 00417c28: push 0x6d
         // 00417c2a: push esi
         // 00417c2b: call 0x418180
      [-]4c240864890d????????595e83c40cc20800
         // 00417c39: mov fs:[0x0], ecx
         // 00417c40: pop ecx
         // 00417c41: pop esi
         // 00417c42: add esp, 0xc
         // 00417c45: retn b2 0x8
      [-]8b7424186a0e56e8
         // 00417ef8: mov esi, ss:[esp+0x18]
         // 00417efc: push 0xe
         // 00417efe: push esi
         // 00417eff: call 0x418430
      [-]05000083c4088bc68b4c240864890d????????595e83c40cc20800
         // 00417f04: add esp, 0x8
         // 00417f07: mov eax, esi
         // 00417f09: mov ecx, ss:[esp+0x8]
         // 00417f0d: mov fs:[0x0], ecx
         // 00417f14: pop ecx
         // 00417f15: pop esi
         // 00417f16: add esp, 0xc
         // 00417f19: retn b2 0x8
      [-]8b7424186a6e56e8
         // 00417c6c: mov esi, ss:[esp+0x18]
         // 00417c70: push 0x6e
         // 00417c72: push esi
         // 00417c73: call 0x418180
      [-]4c240864890d????????595e83c40cc20800
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
      [-]4c240864890d????????595e83c40cc20800
         // 00417ca5: mov fs:[0x0], ecx
         // 00417cac: pop ecx
         // 00417cad: pop esi
         // 00417cae: add esp, 0xc
         // 00417cb1: retn b2 0x8
      [-]8b7424186a7156e8
         // 00417f64: mov esi, ss:[esp+0x18]
         // 00417f68: push 0x71
         // 00417f6a: push esi
         // 00417f6b: call 0x418430
      [-]000083c4088bc68b4c240864890d????????595e83c40cc20800
         // 00417f70: add esp, 0x8
         // 00417f73: mov eax, esi
         // 00417f75: mov ecx, ss:[esp+0x8]
         // 00417f79: mov fs:[0x0], ecx
         // 00417f80: pop ecx
         // 00417f81: pop esi
         // 00417f82: add esp, 0xc
         // 00417f85: retn b2 0x8
      [-]8b7424186a7356e8
         // 00417cd8: mov esi, ss:[esp+0x18]
         // 00417cdc: push 0x73
         // 00417cde: push esi
         // 00417cdf: call 0x418180
      [-]4c240864890d????????595e83c40cc20800
         // 00417ced: mov fs:[0x0], ecx
         // 00417cf4: pop ecx
         // 00417cf5: pop esi
         // 00417cf6: add esp, 0xc
         // 00417cf9: retn b2 0x8
      [-]8b7424186a7456e8
         // 00417fac: mov esi, ss:[esp+0x18]
         // 00417fb0: push 0x74
         // 00417fb2: push esi
         // 00417fb3: call 0x418430
      [-]04000083c4088b
         // 00417fb8: add esp, 0x8
         // 00417fbb: mov eax, esi
      [-]4c240864890d????????595e83c40cc20800
         // 00417fbd: mov ecx, ss:[esp+0x8]
         // 00417fc1: mov fs:[0x0], ecx
         // 00417fc8: pop ecx
         // 00417fc9: pop esi
         // 00417fca: add esp, 0xc
         // 00417fcd: retn b2 0x8
      [-]8b7424186a7556e8
         // 00417fd0: mov esi, ss:[esp+0x18]
         // 00417fd4: push 0x75
         // 00417fd6: push esi
         // 00417fd7: call 0x418430
      [-]04000083c4088bc68b4c240864890d????????595e83c40cc20800
         // 00417fdc: add esp, 0x8
         // 00417fdf: mov eax, esi
         // 00417fe1: mov ecx, ss:[esp+0x8]
         // 00417fe5: mov fs:[0x0], ecx
         // 00417fec: pop ecx
         // 00417fed: pop esi
         // 00417fee: add esp, 0xc
         // 00417ff1: retn b2 0x8
      [-]8b7424186a7656e8
         // 00417ff4: mov esi, ss:[esp+0x18]
         // 00417ff8: push 0x76
         // 00417ffa: push esi
         // 00417ffb: call 0x418430
      [-]04000083c4088b
         // 00418000: add esp, 0x8
         // 00418003: mov eax, esi
      [-]5e83c40cc20800
         // 00418011: pop esi
         // 00418012: add esp, 0xc
         // 00418015: retn b2 0x8
      [-]8b7424186a7756e8
         // 00418018: mov esi, ss:[esp+0x18]
         // 0041801c: push 0x77
         // 0041801e: push esi
         // 0041801f: call 0x418430
      [-]04000083c4088bc68b4c240864890d????????595e83c40cc20800
         // 00418024: add esp, 0x8
         // 00418027: mov eax, esi
         // 00418029: mov ecx, ss:[esp+0x8]
         // 0041802d: mov fs:[0x0], ecx
         // 00418034: pop ecx
         // 00418035: pop esi
         // 00418036: add esp, 0xc
         // 00418039: retn b2 0x8
      [-]8b7424186a7b56e8
         // 0041803c: mov esi, ss:[esp+0x18]
         // 00418040: push 0x7b
         // 00418042: push esi
         // 00418043: call 0x418430
      [-]000083c4088b
         // 00418048: add esp, 0x8
         // 0041804d: mov ecx, ss:[esp+0x8]
      [-]4c240864890d????????595e83c40cc20800
         // 00418051: mov fs:[0x0], ecx
         // 00418058: pop ecx
         // 00418059: pop esi
         // 0041805a: add esp, 0xc
         // 0041805d: retn b2 0x8
      [-]8b7424186a7e56e8
         // 00418060: mov esi, ss:[esp+0x18]
         // 00418064: push 0x7e
         // 00418066: push esi
         // 00418067: call 0x418430
      [-]000083c4088bc68b4c240864890d????????595e83c40cc20800
         // 0041806c: add esp, 0x8
         // 0041806f: mov eax, esi
         // 00418071: mov ecx, ss:[esp+0x8]
         // 00418075: mov fs:[0x0], ecx
         // 0041807c: pop ecx
         // 0041807d: pop esi
         // 0041807e: add esp, 0xc
         // 00418081: retn b2 0x8
      [-]8b74241868????????56e8
         // 00417dd4: mov esi, ss:[esp+0x18]
         // 00417dd8: push 0x80
         // 00417ddd: push esi
         // 00417dde: call 0x418180
      [-]4c240864890d????????595e83c40cc20800
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
      [-]4c240864890d????????595e83c40cc20800
         // 00417e13: mov fs:[0x0], ecx
         // 00417e1a: pop ecx
         // 00417e1b: pop esi
         // 00417e1c: add esp, 0xc
         // 00417e1f: retn b2 0x8
      [-]8b74241868????????56e8
         // 004180d2: mov esi, ss:[esp+0x18]
         // 004180d6: push 0x87
         // 004180db: push esi
         // 004180dc: call 0x418430
      [-]03000083c4088bc68b4c240864890d????????595e83c40cc20800
         // 004180e1: add esp, 0x8
         // 004180e4: mov eax, esi
         // 004180e6: mov ecx, ss:[esp+0x8]
         // 004180ea: mov fs:[0x0], ecx
         // 004180f1: pop ecx
         // 004180f2: pop esi
         // 004180f3: add esp, 0xc
         // 004180f6: retn b2 0x8
      [-]8b74241868????????56e8
         // 004180f9: mov esi, ss:[esp+0x18]
         // 004180fd: push 0x88
         // 00418102: push esi
         // 00418103: call 0x418430
      [-]03000083c4088bc68b4c240864890d????????595e83c40cc20800
         // 00418108: add esp, 0x8
         // 0041810b: mov eax, esi
         // 0041810d: mov ecx, ss:[esp+0x8]
         // 00418111: mov fs:[0x0], ecx
         // 00418118: pop ecx
         // 00418119: pop esi
         // 0041811a: add esp, 0xc
         // 0041811d: retn b2 0x8
      [-]8b74241868????????56e8
         // 00418120: mov esi, ss:[esp+0x18]
         // 00418124: push 0x8a
         // 00418129: push esi
         // 0041812a: call 0x418430
      [-]03000083c4088bc68b4c240864890d????????595e83c40cc20800
         // 0041812f: add esp, 0x8
         // 00418132: mov eax, esi
         // 00418134: mov ecx, ss:[esp+0x8]
         // 00418138: mov fs:[0x0], ecx
         // 0041813f: pop ecx
         // 00418140: pop esi
         // 00418141: add esp, 0xc
         // 00418144: retn b2 0x8
      [-]8b74241868????????56e8
         // 00418147: mov esi, ss:[esp+0x18]
         // 0041814b: push 0x8c
         // 00418150: push esi
         // 00418151: call 0x418430
      [-]000083c4088b
         // 00418156: add esp, 0x8
         // 00418159: mov eax, esi
      [-]4c240864890d????????595e83c40cc20800
         // 0041815b: mov ecx, ss:[esp+0x8]
         // 0041815f: mov fs:[0x0], ecx
         // 00418166: pop ecx
         // 00418167: pop esi
         // 00418168: add esp, 0xc
         // 0041816b: retn b2 0x8
      [-]a8017527
         // 00417ec3: test b1 al, b1 0x1
         // 00417ec5: jnz 0x417eee
      [-]83c801a3
         // 004197d7: or eax, 0x1
         // 004197da: mov ds:[0x4291b4], eax
      [-]c7442414????????c705
         // 004197e4: mov ss:[esp+0x14], 0x1
         // 004197ec: mov ds:[0x4291b0], ??_7system_error_category@?A0x846d1564@system@boost@@6B@
      [-]8b4424188930c74004
         // 00417eee: mov eax, ss:[esp+0x18]
         // 00417ef2: mov ds:[eax], esi
         // 00417ef4: mov ds:[eax+0x4], 0x425b1c
      [-]8b4c240864890d????????595e83c40cc20800
         // 00417efb: mov ecx, ss:[esp+0x8]
         // 00417eff: mov fs:[0x0], ecx
         // 00417f06: pop ecx
         // 00417f07: pop esi
         // 00417f08: add esp, 0xc
         // 00417f0b: retn b2 0x8
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
         // 004181a9: or eax, 0x1
         // 004181ac: mov ds:[0x425b28], eax
      [-]c74424????????00c705
         // 004181b6: mov ss:[esp+0x10], 0x0
         // 004181be: mov ds:[0x425b24], 0x420170
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
