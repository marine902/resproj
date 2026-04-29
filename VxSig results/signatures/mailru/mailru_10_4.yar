rule mailru_10_4 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         558bec56
         // 00401dc0: push ebp
         // 00401dc1: mov ebp, esp
         // 00401dc3: push esi
      [-]807d0c0074
         // 00401814: cmp b1 ss:[ebp+0xc], b1 0x0
         // 00401818: jz 0x40186d
      [-]558bec538b5d0856578b
         // 00401980: push ebp
         // 00401981: mov ebp, esp
         // 00401983: push ebx
         // 00401984: mov ebx, ss:[ebp+0x8]
         // 00401987: push esi
         // 00401988: push edi
         // 0040198b: mov ecx, ss:[ebp+0xc]
      [-]397d100f427d103bf375
         // 004020b0: cmp ss:[ebp+0x10], edi
         // 004020b3: cmovb edi, ss:[ebp+0x10]
         // 004020b7: cmp esi, ebx
         // 004020b9: jnz 0x4020d2
      [-]837b14107202
         // 004020de: cmp ds:[ebx+0x14], 0x10
         // 004020e2: jb 0x4020e6
      [-]837e141072
         // 004020e6: cmp ds:[esi+0x14], 0x10
         // 004020ea: jb 0x4020f0
      [-]000083c40c
         // 00401a58: add esp, 0xc
      [-]837e1410897e1072
         // 00402106: cmp ds:[esi+0x14], 0x10
         // 0040210a: mov ds:[esi+0x10], edi
         // 0040210d: jb 0x402113
      [-]5f8bc65e5b5dc20c00
         // 00402119: pop edi
         // 0040211a: mov eax, esi
         // 0040211c: pop esi
         // 0040211d: pop ebx
         // 0040211e: pop ebp
         // 0040211f: retn b2 0xc
      [-]ffffc21000
         // 00403165: retn b2 0x10
      [-]558bec51568bf1
         // 004033dd: push ebp
         // 004033de: mov ebp, esp
         // 004033e0: push ecx
         // 004033e6: push esi
         // 004033e7: mov esi, ecx
      [-]83c8ff2b
         // 00403c37: or eax, 0xffffffffffffffff
         // 00403c3a: sub eax, ebx
      [-]8b45fc2b
         // 00403440: mov eax, ss:[ebp+0xfffffffffffffffc]
         // 00403443: sub eax, ss:[ebp+0xc]
      [-]6a00508bcee8
         // 00403c37: push 0x0
         // 00403c39: push eax
         // 00403c3a: mov ecx, esi
         // 00403c3c: call 0x4017a0
      [-]ffff8b4d
         // 00403c41: mov ecx, ss:[ebp+0x18]
      [-]558bec5156ff750c
         // 00404440: push ebp
         // 00404441: mov ebp, esp
         // 00404443: push ecx
         // 00404444: push esi
         // 00404445: push ss:[ebp+0xc]
      [-]00008bf0
         // 00404454: mov esi, eax
      [-]ff750c6a0056e8
         // 0040445d: push ss:[ebp+0xc]
         // 00404460: push 0x0
         // 00404462: push esi
         // 00404463: call _memset
      [-]8be55dc3
         // 0040447f: mov esp, ebp
         // 00404481: pop ebp
         // 00404482: retn 
      [-]837d0cff7614
         // 004037f3: cmp ss:[ebp+0xc], 0xffffffffffffffff
         // 004037f7: jbe 0x40380d
      [-]8b450833c90b4d0c99c1e00f0b
         // 0040380d: mov eax, ss:[ebp+0x8]
         // 00403810: xor ecx, ecx
         // 00403812: or ecx, ss:[ebp+0xc]
         // 00403815: cdq 
         // 00403816: shl eax, b1 0xf
         // 00403819: or eax, edi
      [-]0d????????89
         // 0040381d: or eax, 0x7ff80000
         // 00403822: mov ds:[esi+0x4], eax
      [-]5dc20800
         // 00403829: pop ebp
         // 0040382a: retn b2 0x8
      [-]8b461040508d45
         // 00404534: mov eax, ds:[esi+0x10]
         // 00404537: inc eax
         // 00404538: push eax
         // 00404539: lea eax, ss:[ebp+0xffffffffffffff9c]
      [-]40505657e8
         // 0040455a: inc eax
         // 0040455b: push eax
         // 0040455c: push esi
         // 0040455d: push edi
         // 0040455e: call _memmove_0
      [-]c645fc01508d45
         // 00404574: mov b1 ss:[ebp+0xfffffffffffffffc], b1 0x1
         // 00404578: push eax
         // 00404579: lea eax, ss:[ebp+0xffffffffffffff94]
      [-]000083c4
         // 00404595: add esp, 0x1c
      [-]85c00f85
         // 00404598: test eax, eax
         // 0040459a: jnz 0x4047d0
      [-]0f95c3eb02
         // 004039e3: setnz b1 bl
         // 004039e6: jmp 0x4039ea
      [-]8d4da4c645fc00e8
         // 004047d2: lea ecx, ss:[ebp+0xffffffffffffffa4]
         // 004047d5: mov b1 ss:[ebp+0xfffffffffffffffc], b1 0x0
         // 004047d9: call 0x404ca0
      [-]000085ff74
         // 004047de: test edi, edi
         // 004047e0: jz 0x4047eb
      [-]558bec8b
         // 00404810: push ebp
         // 00404811: mov ebp, esp
         // 00404813: mov ecx, ss:[ebp+0x10]
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
         // 004041e3: mov eax, ds:[ecx+0x4]
         // 004041e6: lea edx, ds:[eax+edi]
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
         // 00404212: mov eax, ds:[esi]
         // 00404214: test eax, eax
         // 00404216: jz 0x404222
      [-]8b0089018b06
         // 00404c74: mov eax, ds:[eax]
         // 00404c76: mov ds:[ecx], eax
         // 00404c78: mov eax, ds:[esi]
      [-]8b068901
         // 00404c85: mov eax, ds:[esi]
         // 00404c87: mov ds:[ecx], eax
      [-]558bec8a45083c2c7420
         // 0040424f: push ebp
         // 00404250: mov ebp, esp
         // 00404252: mov b1 al, b1 ss:[ebp+0x8]
         // 00404255: cmp b1 al, b1 0x2c
         // 00404257: jz 0x404279
      [-]3c3a741c
         // 00404259: cmp b1 al, b1 0x3a
         // 0040425b: jz 0x404279
      [-]3c5d7418
         // 0040425d: cmp b1 al, b1 0x5d
         // 0040425f: jz 0x404279
      [-]3c7d7414
         // 00404261: cmp b1 al, b1 0x7d
         // 00404263: jz 0x404279
      [-]3c207410
         // 00404265: cmp b1 al, b1 0x20
         // 00404267: jz 0x404279
      [-]3c097c04
         // 00404269: cmp b1 al, b1 0x9
         // 0040426b: jl 0x404271
      [-]3c0d7e08
         // 0040426d: cmp b1 al, b1 0xd
         // 0040426f: jle 0x404279
      [-]84c07404
         // 00404271: test b1 al, b1 al
         // 00404273: jz 0x404279
      [-]5dc20400
         // 00405f22: pop ebp
         // 00405f23: retn b2 0x4
      [-]558bec568bf1578b7d088b
         // 00406150: push ebp
         // 00406151: mov ebp, esp
         // 00406153: push esi
         // 00406154: mov esi, ecx
         // 00406156: push edi
         // 00406157: mov edi, ss:[ebp+0x8]
         // 0040615a: mov edx, ds:[esi+0x4]
      [-]2bc83bcf77
         // 00406161: sub ecx, eax
         // 00406163: cmp ecx, edi
         // 00406165: ja 0x40618c
      [-]8bce03c750e8
         // 0040532a: mov ecx, esi
         // 0040532c: add eax, edi
         // 0040532e: push eax
         // 0040532f: call 0x40518c
      [-]03c7506a00
         // 00405339: add eax, edi
         // 0040533b: push eax
         // 0040533c: push 0x0
      [-]00008b0683c40c
         // 00405346: mov eax, ds:[esi]
         // 00405348: add esp, 0xc
      [-]03c7894604
         // 0040534b: add eax, edi
         // 0040534d: mov ds:[esi+0x4], eax
      [-]5f5e5dc20400
         // 00405350: pop edi
         // 00405351: pop esi
         // 00405352: pop ebp
         // 00405353: retn b2 0x4
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
         // 004074e1: push ebp
         // 004074e2: mov ebp, esp
         // 004074e4: cmp ds:[0x41aaac], 0x0
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
      [-]83c8fff00fc1017919
         // 0040835c: or eax, 0xffffffffffffffff
         // 0040835f: lock xadd ds:[ecx], eax
         // 00408363: jns 0x40837e
      [-]56e84700000083c6185981fe
         // 00407556: push esi
         // 00407557: call __Mtxdst
         // 0040755c: add esi, 0x18
         // 0040755f: pop ecx
         // 00407560: cmp esi, 0x4249d8
      [-]8b068bcea3
         // 00407582: mov eax, ds:[esi]
         // 00407584: mov ecx, esi
         // 00407586: mov ds:[0x4249e4], eax
      [-]e8daffffff56e8
         // 0040758b: call ??1_Fac_node@std@@QAE@XZ
         // 00407590: push esi
         // 00407591: call j__free
      [-]00000059
         // 00407596: pop ecx
      [-]85f675e1
         // 0040759d: test esi, esi
         // 0040759f: jnz 0x407582
      [-]4150890d??
         // 004083e6: inc ecx
         // 004083e7: push eax
         // 004083e8: mov ds:[0x426028], ecx
      [-]85c07402
         // 004083f4: test eax, eax
         // 004083f6: jz 0x4083fa
      [-]83f90a72da
         // 00408400: cmp ecx, 0xa
         // 00408403: jb 0x4083df
      [-]000059c3
         // 0040992c: pop ecx
         // 0040992d: retn 
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
         // 0040b8ff: mov esi, eax
         // 0040b901: call ds:[GetLastError]
      [-]00005989065e
         // 0040b90d: pop ecx
         // 0040b90e: mov ds:[esi], eax
         // 0040b910: pop esi
      [-]e996000000
         // 0040942c: jmp ?_Tidy@exception@std@@AAEXXZ
      [-]568bf1807e08007409
         // 0040bc7a: push esi
         // 0040bc7b: mov esi, ecx
         // 0040bc7d: cmp b1 ds:[esi+0x8], b1 0x0
         // 0040bc81: jz 0x40bc8c
      [-]83660400c64608005ec3
         // 0040bc8c: and ds:[esi+0x4], 0x0
         // 0040bc90: mov b1 ds:[esi+0x8], b1 0x0
         // 0040bc94: pop esi
         // 0040bc95: retn 
      [-]6a01e85b00000059c3
         // 0040be30: push 0x1
         // 0040be32: call _flsall
         // 0040be37: pop ecx
         // 0040be38: retn 
      [-]558becff7508ff15
         // 0040c348: push ebp
         // 0040c349: mov ebp, esp
         // 0040c34b: push ss:[ebp+0x8]
         // 0040c34e: call ds:[Sleep]
      [-]558bec8b4508a3
         // 0040c67a: push ebp
         // 0040c67b: mov ebp, esp
         // 0040c67d: mov eax, ss:[ebp+0x8]
         // 0040c680: mov ds:[0x424c94], eax
      [-]558bec8b4508a3
         // 0040c6ad: push ebp
         // 0040c6ae: mov ebp, esp
         // 0040c6b0: mov eax, ss:[ebp+0x8]
         // 0040c6b3: mov ds:[0x424c98], eax
      [-]558bec8b4508a3
         // 0040e486: push ebp
         // 0040e487: mov ebp, esp
         // 0040e489: mov eax, ss:[ebp+0x8]
         // 0040e48c: mov ds:[0x425004], eax
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
      [-]ffff8945ec3935
         // 0040fcc3: mov ss:[ebp+0xffffffffffffffec], eax
         // 0040fcc6: cmp ds:[0x425060], esi
      [-]0f85b0000000
         // 0040fccc: jnz 0x40fd82
      [-]68????????5668
         // 0041224d: push 0x800
         // 00412252: push esi
         // 00412253: push 0x420a80
      [-]8bf885ff7526
         // 0041225e: mov edi, eax
         // 00412260: test edi, edi
         // 00412262: jnz 0x41228a
      [-]83f8570f856a010000
         // 0040fcef: cmp eax, 0x57
         // 0040fcf2: jnz 0x40fe62
      [-]8bf885ff0f8453010000
         // 0040fd05: mov edi, eax
         // 0040fd07: test edi, edi
         // 0040fd09: jz 0x40fe62
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
         // 0040fd88: test eax, eax
         // 0040fd8a: jz 0x40fda7
      [-]8b45e485c07407
         // 00412307: mov eax, ss:[ebp+0xffffffffffffffe4]
         // 0041230a: test eax, eax
         // 0041230c: jz 0x412315
      [-]3975ec741d
         // 00412315: cmp ss:[ebp+0xffffffffffffffec], esi
         // 00412318: jz 0x412337
      [-]58e9bd000000
         // 0041231c: pop eax
         // 0041231d: jmp 0x4123df
      [-]3975ec7410
         // 00412322: cmp ss:[ebp+0xffffffffffffffec], esi
         // 00412325: jz 0x412337
      [-]6a03ebe5
         // 00412333: push 0x3
         // 00412335: jmp 0x41231c
      [-]3bc7744f
         // 00412342: cmp eax, edi
         // 00412344: jz 0x412395
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
         // 00412366: test eax, eax
         // 00412368: jz 0x412395
      [-]ffd185c0741a
         // 0041236a: call ecx
         // 0041236c: test eax, eax
         // 0041236e: jz 0x41238a
      [-]8d4ddc516a0c8d4df0516a0150ff55e885c07406
         // 00412370: lea ecx, ss:[ebp+0xffffffffffffffdc]
         // 00412373: push ecx
         // 00412374: push 0xc
         // 00412376: lea ecx, ss:[ebp+0xfffffffffffffff0]
         // 00412379: push ecx
         // 0041237a: push 0x1
         // 0041237c: push eax
         // 0041237d: call ss:[ebp+0xffffffffffffffe8]
         // 00412380: test eax, eax
         // 00412382: jz 0x41238a
      [-]f645f801750b
         // 00412384: test b1 ss:[ebp+0xfffffffffffffff8], b1 0x1
         // 00412388: jnz 0x412395
      [-]8b7d1081cf????????eb30
         // 0041238a: mov edi, ss:[ebp+0x10]
         // 0041238d: or edi, 0x200000
         // 00412393: jmp 0x4123c5
      [-]3bc77424
         // 0040fc68: cmp eax, edi
         // 0040fc6a: jz 0x40fc90
      [-]50ffd385c0741d
         // 0041239e: push eax
         // 0041239f: call ebx
         // 004123a1: test eax, eax
         // 004123a3: jz 0x4123c2
      [-]ffd08bf085f67415
         // 004123a5: call eax
         // 004123a7: mov esi, eax
         // 004123a9: test esi, esi
         // 004123ab: jz 0x4123c2
      [-]3bc7740c
         // 0040fc80: cmp eax, edi
         // 0040fc82: jz 0x40fc90
      [-]50ffd385c07405
         // 004123b6: push eax
         // 004123b7: call ebx
         // 004123b9: test eax, eax
         // 004123bb: jz 0x4123c2
      [-]56ffd08bf0
         // 004123bd: push esi
         // 004123be: call eax
         // 004123c0: mov esi, eax
      [-]ffd385c0740c
         // 0040fc99: call ebx
         // 0040fc9b: test eax, eax
         // 0040fc9d: jz 0x40fcab
      [-]57ff75e0ff75e456ffd0eb02
         // 004123d1: push edi
         // 004123d2: push ss:[ebp+0xffffffffffffffe0]
         // 004123d5: push ss:[ebp+0xffffffffffffffe4]
         // 004123d8: push esi
         // 004123d9: call eax
         // 004123db: jmp 0x4123df
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
         // 004124ec: push ebp
         // 004124ed: mov ebp, esp
         // 004124ef: mov eax, ss:[ebp+0x8]
         // 004124f2: mov ds:[0x425a5c], eax
      [-]558bec83ec44a1
         // 004152cc: push ebp
         // 004152cd: mov ebp, esp
         // 004152cf: sub esp, 0x44
         // 004152d2: mov eax, ds:[0x4231e0]
      [-]33c58945fc8b4d085356570fb7410a33db8b7d0c8bd025????????897dc08945bc81e2????????8b410681ea????????8945f08b41028945f40fb701c1e0108955e08945f881fa????????7525
         // 004152d7: xor eax, ebp
         // 004152d9: mov ss:[ebp+0xfffffffffffffffc], eax
         // 004152dc: mov ecx, ss:[ebp+0x8]
         // 004152df: push ebx
         // 004152e0: push esi
         // 004152e1: push edi
         // 004152e2: movzx eax, b2 ds:[ecx+0xa]
         // 004152e6: xor ebx, ebx
         // 004152e8: mov edi, ss:[ebp+0xc]
         // 004152eb: mov edx, eax
         // 004152ed: and eax, 0x8000
         // 004152f2: mov ss:[ebp+0xffffffffffffffc0], edi
         // 004152f5: mov ss:[ebp+0xffffffffffffffbc], eax
         // 004152f8: and edx, 0x7fff
         // 004152fe: mov eax, ds:[ecx+0x6]
         // 00415301: sub edx, 0x3fff
         // 00415307: mov ss:[ebp+0xfffffffffffffff0], eax
         // 0041530a: mov eax, ds:[ecx+0x2]
         // 0041530d: mov ss:[ebp+0xfffffffffffffff4], eax
         // 00415310: movzx eax, b2 ds:[ecx]
         // 00415313: shl eax, b1 0x10
         // 00415316: mov ss:[ebp+0xffffffffffffffe0], edx
         // 00415319: mov ss:[ebp+0xfffffffffffffff8], eax
         // 0041531c: cmp edx, 0xffffffffffffc001
         // 00415322: jnz 0x415349
      [-]8bf38bc3
         // 00416bae: mov esi, ebx
         // 00416bb0: mov eax, ebx
      [-]395c85f0750b
         // 00416bb2: cmp ss:[ebp+eax*0x4], ebx
         // 00416bb6: jnz 0x416bc3
      [-]4083f8037cf4
         // 00416bb8: inc eax
         // 00416bb9: cmp eax, 0x3
         // 00416bbc: jl 0x416bb2
      [-]e9b9040000
         // 00416bbe: jmp 0x41707c
      [-]33c08d7df0ababab
         // 00416bc3: xor eax, eax
         // 00416bc5: lea edi, ss:[ebp+0xfffffffffffffff0]
         // 00416bc8: stosdd 
         // 00416bc9: stosdd 
         // 00416bca: stosdd 
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
      [-]2bf133c0408975d08bce83cfffd3e06a035e854495f00f84a4000000
         // 00416c0b: sub esi, ecx
         // 00416c0d: xor eax, eax
         // 00416c0f: inc eax
         // 00416c10: mov ss:[ebp+0xffffffffffffffd0], esi
         // 00416c13: mov ecx, esi
         // 00416c15: or edi, 0xffffffffffffffff
         // 00416c18: shl eax, b1 cl
         // 00416c1a: push 0x3
         // 00416c1c: pop esi
         // 00416c1d: test ss:[ebp+edx*0x4], eax
         // 00416c21: jz 0x416ccb
      [-]8bc7d3e0f7d0854495f0eb04
         // 00416c27: mov eax, edi
         // 00416c29: shl eax, b1 cl
         // 00416c2b: not eax
         // 00416c2d: test ss:[ebp+edx*0x4], eax
         // 00416c31: jmp 0x416c37
      [-]395c95f0
         // 00416c33: cmp ss:[ebp+edx*0x4], ebx
      [-]423bd67cf5
         // 00416c39: inc edx
         // 00416c3a: cmp edx, esi
         // 00416c3c: jl 0x416c33
      [-]e985000000
         // 00416c3e: jmp 0x416cc8
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
      [-]2bc8895dd433c040d3e08945c88b4495f08b4dc803c8894dd83bc88b45d88bcb6aff5f7205
         // 00416c60: sub ecx, eax
         // 00416c62: mov ss:[ebp+0xffffffffffffffd4], ebx
         // 00416c65: xor eax, eax
         // 00416c67: inc eax
         // 00416c68: shl eax, b1 cl
         // 00416c6a: mov ss:[ebp+0xffffffffffffffc8], eax
         // 00416c6d: mov eax, ss:[ebp+edx*0x4]
         // 00416c71: mov ecx, ss:[ebp+0xffffffffffffffc8]
         // 00416c74: add ecx, eax
         // 00416c76: mov ss:[ebp+0xffffffffffffffd8], ecx
         // 00416c79: cmp ecx, eax
         // 00416c7b: mov eax, ss:[ebp+0xffffffffffffffd8]
         // 00416c7e: mov ecx, ebx
         // 00416c80: push 0xffffffffffffffff
         // 00416c82: pop edi
         // 00416c83: jb 0x416c8a
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
      [-]8b4495f08bcb895dd48d78013bf8897dd88bc77205
         // 00416c9b: mov eax, ss:[ebp+edx*0x4]
         // 00416c9f: mov ecx, ebx
         // 00416ca1: mov ss:[ebp+0xffffffffffffffd4], ebx
         // 00416ca4: lea edi, ds:[eax+0x1]
         // 00416ca7: cmp edi, eax
         // 00416ca9: mov ss:[ebp+0xffffffffffffffd8], edi
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
      [-]8bc7d3e0214495f08d42013bc67d11
         // 00416ccb: mov eax, edi
         // 00416ccd: shl eax, b1 cl
         // 00416ccf: and ss:[ebp+edx*0x4], eax
         // 00416cd3: lea eax, ds:[edx+0x1]
         // 00416cd6: cmp eax, esi
         // 00416cd8: jge 0x416ceb
      [-]8d7df08bce8d3c872bc833c0f3ab83cfff
         // 00416cda: lea edi, ss:[ebp+0xfffffffffffffff0]
         // 00416cdd: mov ecx, esi
         // 00416cdf: lea edi, ds:[edi+eax*0x4]
         // 00416ce2: sub ecx, eax
         // 00416ce4: xor eax, eax
         // 00416ce6: rep stosdd 
         // 00416ce8: or edi, 0xffffffffffffffff
      [-]8b4de0395dd47401
         // 00416ceb: mov ecx, ss:[ebp+0xffffffffffffffe0]
         // 00416cee: cmp ss:[ebp+0xffffffffffffffd4], ebx
         // 00416cf1: jz 0x416cf4
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
      [-]8bf3e9b6feffff
         // 00416d0e: mov esi, ebx
         // 00416d10: jmp 0x416bcb
      [-]3bca0f8f19020000
         // 00416d15: cmp ecx, edx
         // 00416d17: jg 0x416f36
      [-]2b55dc8d75e48955d08d7df08bc2a59983e21f03c2c1f805a58945c48b45d0a525????????7905
         // 00416d1d: sub edx, ss:[ebp+0xffffffffffffffdc]
         // 00416d20: lea esi, ss:[ebp+0xffffffffffffffe4]
         // 00416d23: mov ss:[ebp+0xffffffffffffffd0], edx
         // 00416d26: lea edi, ss:[ebp+0xfffffffffffffff0]
         // 00416d29: mov eax, edx
         // 00416d2b: movsdd 
         // 00416d2c: cdq 
         // 00416d2d: and edx, 0x1f
         // 00416d30: add eax, edx
         // 00416d32: sar eax, b1 0x5
         // 00416d35: movsdd 
         // 00416d36: mov ss:[ebp+0xffffffffffffffc4], eax
         // 00416d39: mov eax, ss:[ebp+0xffffffffffffffd0]
         // 00416d3c: movsdd 
         // 00416d3d: and eax, 0xffffffff8000001f
         // 00416d42: jns 0x416d49
      [-]4883c8e040
         // 00416d44: dec eax
         // 00416d45: or eax, 0xffffffffffffffe0
         // 00416d48: inc eax
      [-]8945d083cfff8bc7895de08b7dd08bcfd3e0f7d06a208945d8582bc76a038945c85e
         // 00416d49: mov ss:[ebp+0xffffffffffffffd0], eax
         // 00416d4c: or edi, 0xffffffffffffffff
         // 00416d4f: mov eax, edi
         // 00416d51: mov ss:[ebp+0xffffffffffffffe0], ebx
         // 00416d54: mov edi, ss:[ebp+0xffffffffffffffd0]
         // 00416d57: mov ecx, edi
         // 00416d59: shl eax, b1 cl
         // 00416d5b: not eax
         // 00416d5d: push 0x20
         // 00416d5f: mov ss:[ebp+0xffffffffffffffd8], eax
         // 00416d62: pop eax
         // 00416d63: sub eax, edi
         // 00416d65: push 0x3
         // 00416d67: mov ss:[ebp+0xffffffffffffffc8], eax
         // 00416d6a: pop esi
      [-]8b549df08bcf8bc2d3ea0b55e02345d88b4dc8d3e089549df0438945e03bde7cdf
         // 00416d6b: mov edx, ss:[ebp+ebx*0x4]
         // 00416d6f: mov ecx, edi
         // 00416d71: mov eax, edx
         // 00416d73: shr edx, b1 cl
         // 00416d75: or edx, ss:[ebp+0xffffffffffffffe0]
         // 00416d78: and eax, ss:[ebp+0xffffffffffffffd8]
         // 00416d7b: mov ecx, ss:[ebp+0xffffffffffffffc8]
         // 00416d7e: shl eax, b1 cl
         // 00416d80: mov ss:[ebp+ebx*0x4], edx
         // 00416d84: inc ebx
         // 00416d85: mov ss:[ebp+0xffffffffffffffe0], eax
         // 00416d88: cmp ebx, esi
         // 00416d8a: jl 0x416d6b
      [-]8b45c48d55f8c1e00233db6a022bd083cfff8b45c459
         // 00416d8c: mov eax, ss:[ebp+0xffffffffffffffc4]
         // 00416d8f: lea edx, ss:[ebp+0xfffffffffffffff8]
         // 00416d92: shl eax, b1 0x2
         // 00416d95: xor ebx, ebx
         // 00416d97: push 0x2
         // 00416d99: sub edx, eax
         // 00416d9b: or edi, 0xffffffffffffffff
         // 00416d9e: mov eax, ss:[ebp+0xffffffffffffffc4]
         // 00416da1: pop ecx
      [-]3bc87c0b
         // 00416da2: cmp ecx, eax
         // 00416da4: jl 0x416db1
      [-]8b0289448df08b45c4eb04
         // 00416da6: mov eax, ds:[edx]
         // 00416da8: mov ss:[ebp+ecx*0x4], eax
         // 00416dac: mov eax, ss:[ebp+0xffffffffffffffc4]
         // 00416daf: jmp 0x416db5
      [-]895c8df0
         // 00416db1: mov ss:[ebp+ecx*0x4], ebx
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
      [-]6a1f582bc18945d033c08b4dd040d3e0854495f00f8492000000
         // 00416dda: push 0x1f
         // 00416ddc: pop eax
         // 00416ddd: sub eax, ecx
         // 00416ddf: mov ss:[ebp+0xffffffffffffffd0], eax
         // 00416de2: xor eax, eax
         // 00416de4: mov ecx, ss:[ebp+0xffffffffffffffd0]
         // 00416de7: inc eax
         // 00416de8: shl eax, b1 cl
         // 00416dea: test ss:[ebp+edx*0x4], eax
         // 00416dee: jz 0x416e86
      [-]8bc7d3e0f7d0854495f0eb04
         // 00416df4: mov eax, edi
         // 00416df6: shl eax, b1 cl
         // 00416df8: not eax
         // 00416dfa: test ss:[ebp+edx*0x4], eax
         // 00416dfe: jmp 0x416e04
      [-]395c95f0
         // 00416e00: cmp ss:[ebp+edx*0x4], ebx
      [-]423bd67cf5
         // 00416e06: inc edx
         // 00416e07: cmp edx, esi
         // 00416e09: jl 0x416e00
      [-]8b7dcc8bc76a1f995923d103d0c1fa0581e7????????7905
         // 00416e0d: mov edi, ss:[ebp+0xffffffffffffffcc]
         // 00416e10: mov eax, edi
         // 00416e12: push 0x1f
         // 00416e14: cdq 
         // 00416e15: pop ecx
         // 00416e16: and edx, ecx
         // 00416e18: add edx, eax
         // 00416e1a: sar edx, b1 0x5
         // 00416e1d: and edi, 0xffffffff8000001f
         // 00416e23: jns 0x416e2a
      [-]4f83cfe047
         // 00416e25: dec edi
         // 00416e26: or edi, 0xffffffffffffffe0
         // 00416e29: inc edi
      [-]8b4495f02bcf33ff47d3e78bcb897ddc03f8897de03bf88b45e06aff5f7205
         // 00416e2a: mov eax, ss:[ebp+edx*0x4]
         // 00416e2e: sub ecx, edi
         // 00416e30: xor edi, edi
         // 00416e32: inc edi
         // 00416e33: shl edi, b1 cl
         // 00416e35: mov ecx, ebx
         // 00416e37: mov ss:[ebp+0xffffffffffffffdc], edi
         // 00416e3a: add edi, eax
         // 00416e3c: mov ss:[ebp+0xffffffffffffffe0], edi
         // 00416e3f: cmp edi, eax
         // 00416e41: mov eax, ss:[ebp+0xffffffffffffffe0]
         // 00416e44: push 0xffffffffffffffff
         // 00416e46: pop edi
         // 00416e47: jb 0x416e4e
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
      [-]8b4495f08bcb8d78013bf8897de08bc77205
         // 00416e5c: mov eax, ss:[ebp+edx*0x4]
         // 00416e60: mov ecx, ebx
         // 00416e62: lea edi, ds:[eax+0x1]
         // 00416e65: cmp edi, eax
         // 00416e67: mov ss:[ebp+0xffffffffffffffe0], edi
         // 00416e6a: mov eax, edi
         // 00416e6c: jb 0x416e73
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
      [-]8d7df08bce8d3c972bca33c0f3ab83cfff
         // 00416e93: lea edi, ss:[ebp+0xfffffffffffffff0]
         // 00416e96: mov ecx, esi
         // 00416e98: lea edi, ds:[edi+edx*0x4]
         // 00416e9b: sub ecx, edx
         // 00416e9d: xor eax, eax
         // 00416e9f: rep stosdd 
         // 00416ea1: or edi, 0xffffffffffffffff
      [-]418bc19983e21f03c2c1f8058945d881e1????????7905
         // 00416eaa: inc ecx
         // 00416eab: mov eax, ecx
         // 00416ead: cdq 
         // 00416eae: and edx, 0x1f
         // 00416eb1: add eax, edx
         // 00416eb3: sar eax, b1 0x5
         // 00416eb6: mov ss:[ebp+0xffffffffffffffd8], eax
         // 00416eb9: and ecx, 0xffffffff8000001f
         // 00416ebf: jns 0x416ec6
      [-]4983c9e041
         // 00416ec1: dec ecx
         // 00416ec2: or ecx, 0xffffffffffffffe0
         // 00416ec5: inc ecx
      [-]894ddc8bc3d3e76a20895de0f7d78b5ddc592bcb8945cc894ddc
         // 00416ec6: mov ss:[ebp+0xffffffffffffffdc], ecx
         // 00416ec9: mov eax, ebx
         // 00416ecb: shl edi, b1 cl
         // 00416ecd: push 0x20
         // 00416ecf: mov ss:[ebp+0xffffffffffffffe0], ebx
         // 00416ed2: not edi
         // 00416ed4: mov ebx, ss:[ebp+0xffffffffffffffdc]
         // 00416ed7: pop ecx
         // 00416ed8: sub ecx, ebx
         // 00416eda: mov ss:[ebp+0xffffffffffffffcc], eax
         // 00416edd: mov ss:[ebp+0xffffffffffffffdc], ecx
      [-]8b5485f08bcb8bc2d3ea8b4dcc23c70b55e089548df08b4ddcd3e08945e08b45cc408945cc3bc67cd7
         // 00416ee0: mov edx, ss:[ebp+eax*0x4]
         // 00416ee4: mov ecx, ebx
         // 00416ee6: mov eax, edx
         // 00416ee8: shr edx, b1 cl
         // 00416eea: mov ecx, ss:[ebp+0xffffffffffffffcc]
         // 00416eed: and eax, edi
         // 00416eef: or edx, ss:[ebp+0xffffffffffffffe0]
         // 00416ef2: mov ss:[ebp+ecx*0x4], edx
         // 00416ef6: mov ecx, ss:[ebp+0xffffffffffffffdc]
         // 00416ef9: shl eax, b1 cl
         // 00416efb: mov ss:[ebp+0xffffffffffffffe0], eax
         // 00416efe: mov eax, ss:[ebp+0xffffffffffffffcc]
         // 00416f01: inc eax
         // 00416f02: mov ss:[ebp+0xffffffffffffffcc], eax
         // 00416f05: cmp eax, esi
         // 00416f07: jl 0x416ee0
      [-]8b75d88d55f88bc6c1e0026a022bd033db59
         // 00416f09: mov esi, ss:[ebp+0xffffffffffffffd8]
         // 00416f0c: lea edx, ss:[ebp+0xfffffffffffffff8]
         // 00416f0f: mov eax, esi
         // 00416f11: shl eax, b1 0x2
         // 00416f14: push 0x2
         // 00416f16: sub edx, eax
         // 00416f18: xor ebx, ebx
         // 00416f1a: pop ecx
      [-]3bce7c08
         // 00416f1b: cmp ecx, esi
         // 00416f1d: jl 0x416f27
      [-]8b0289448df0eb04
         // 00416f1f: mov eax, ds:[edx]
         // 00416f21: mov ss:[ebp+ecx*0x4], eax
         // 00416f25: jmp 0x416f2b
      [-]895c8df0
         // 00416f27: mov ss:[ebp+ecx*0x4], ebx
      [-]83ea044979ea
         // 00416f2b: sub edx, 0x4
         // 00416f2e: dec ecx
         // 00416f2f: jns 0x416f1b
      [-]e9d8fdffff
         // 00416f31: jmp 0x416d0e
      [-]0f8ca2000000
         // 00416f3c: jl 0x416fe4
      [-]8d7df033c0ababab8bc1814df0????????9983e21f03c2c1f8058945cc81e1????????7905
         // 00416f48: lea edi, ss:[ebp+0xfffffffffffffff0]
         // 00416f4b: xor eax, eax
         // 00416f4d: stosdd 
         // 00416f4e: stosdd 
         // 00416f4f: stosdd 
         // 00416f50: mov eax, ecx
         // 00416f52: or ss:[ebp+0xfffffffffffffff0], 0xffffffff80000000
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
      [-]83cfff894dc86a20d3e7582bc1895de0f7d78945d8
         // 00416f72: or edi, 0xffffffffffffffff
         // 00416f75: mov ss:[ebp+0xffffffffffffffc8], ecx
         // 00416f78: push 0x20
         // 00416f7a: shl edi, b1 cl
         // 00416f7c: pop eax
         // 00416f7d: sub eax, ecx
         // 00416f7f: mov ss:[ebp+0xffffffffffffffe0], ebx
         // 00416f82: not edi
         // 00416f84: mov ss:[ebp+0xffffffffffffffd8], eax
      [-]8b549df08bc2d3ea23c70b55e08b4dd8d3e08b4dc889549df0438945e03bde7cdf
         // 00416f87: mov edx, ss:[ebp+ebx*0x4]
         // 00416f8b: mov eax, edx
         // 00416f8d: shr edx, b1 cl
         // 00416f8f: and eax, edi
         // 00416f91: or edx, ss:[ebp+0xffffffffffffffe0]
         // 00416f94: mov ecx, ss:[ebp+0xffffffffffffffd8]
         // 00416f97: shl eax, b1 cl
         // 00416f99: mov ecx, ss:[ebp+0xffffffffffffffc8]
         // 00416f9c: mov ss:[ebp+ebx*0x4], edx
         // 00416fa0: inc ebx
         // 00416fa1: mov ss:[ebp+0xffffffffffffffe0], eax
         // 00416fa4: cmp ebx, esi
         // 00416fa6: jl 0x416f87
      [-]8b75cc8d55f88bc6c1e0026a022bd033db59
         // 00416fa8: mov esi, ss:[ebp+0xffffffffffffffcc]
         // 00416fab: lea edx, ss:[ebp+0xfffffffffffffff8]
         // 00416fae: mov eax, esi
         // 00416fb0: shl eax, b1 0x2
         // 00416fb3: push 0x2
         // 00416fb5: sub edx, eax
         // 00416fb7: xor ebx, ebx
         // 00416fb9: pop ecx
      [-]3bce7c08
         // 00416fba: cmp ecx, esi
         // 00416fbc: jl 0x416fc6
      [-]8b0289448df0eb04
         // 00416fbe: mov eax, ds:[edx]
         // 00416fc0: mov ss:[ebp+ecx*0x4], eax
         // 00416fc4: jmp 0x416fca
      [-]895c8df0
         // 00416fc6: mov ss:[ebp+ecx*0x4], ebx
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
      [-]6a20895de08bf3d3e78bd9582bc3894ddcf7d78945dc
         // 00417017: push 0x20
         // 00417019: mov ss:[ebp+0xffffffffffffffe0], ebx
         // 0041701c: mov esi, ebx
         // 0041701e: shl edi, b1 cl
         // 00417020: mov ebx, ecx
         // 00417022: pop eax
         // 00417023: sub eax, ebx
         // 00417025: mov ss:[ebp+0xffffffffffffffdc], ecx
         // 00417028: not edi
         // 0041702a: mov ss:[ebp+0xffffffffffffffdc], eax
      [-]8b54b5f08bcb8bc2d3ea0b55e023c78b4ddcd3e08954b5f0468945e083fe037cdf
         // 0041702d: mov edx, ss:[ebp+esi*0x4]
         // 00417031: mov ecx, ebx
         // 00417033: mov eax, edx
         // 00417035: shr edx, b1 cl
         // 00417037: or edx, ss:[ebp+0xffffffffffffffe0]
         // 0041703a: and eax, edi
         // 0041703c: mov ecx, ss:[ebp+0xffffffffffffffdc]
         // 0041703f: shl eax, b1 cl
         // 00417041: mov ss:[ebp+esi*0x4], edx
         // 00417045: inc esi
         // 00417046: mov ss:[ebp+0xffffffffffffffe0], eax
         // 00417049: cmp esi, 0x3
         // 0041704c: jl 0x41702d
      [-]8b7dd88d55f88b75c88bc7c1e0026a022bd033db59
         // 0041704e: mov edi, ss:[ebp+0xffffffffffffffd8]
         // 00417051: lea edx, ss:[ebp+0xfffffffffffffff8]
         // 00417054: mov esi, ss:[ebp+0xffffffffffffffc8]
         // 00417057: mov eax, edi
         // 00417059: shl eax, b1 0x2
         // 0041705c: push 0x2
         // 0041705e: sub edx, eax
         // 00417060: xor ebx, ebx
         // 00417062: pop ecx
      [-]3bcf7c08
         // 00417063: cmp ecx, edi
         // 00417065: jl 0x41706f
      [-]8b0289448df0eb04
         // 00417067: mov eax, ds:[edx]
         // 00417069: mov ss:[ebp+ecx*0x4], eax
         // 0041706d: jmp 0x417073
      [-]895c8df0
         // 0041706f: mov ss:[ebp+ecx*0x4], ebx
      [-]83ea044979ea
         // 00417073: sub edx, 0x4
         // 00417076: dec ecx
         // 00417077: jns 0x417063
      [-]6a1f582b05??
         // 0041707c: push 0x1f
         // 0041707e: pop eax
         // 0041707f: sub eax, ds:[0x427338]
      [-]8bc88b45bcd3e6f7d81bc025????????0bf0a1??
         // 00417085: mov ecx, eax
         // 00417087: mov eax, ss:[ebp+0xffffffffffffffbc]
         // 0041708a: shl esi, b1 cl
         // 0041708c: neg eax
         // 0041708e: sbb eax, eax
         // 00417090: and eax, 0xffffffff80000000
         // 00417095: or esi, eax
         // 00417097: mov eax, ds:[0x42733c]
      [-]0b75f083f840750a
         // 0041709c: or esi, ss:[ebp+0xfffffffffffffff0]
         // 0041709f: cmp eax, 0x40
         // 004170a2: jnz 0x4170ae
      [-]8b45f48977048907eb07
         // 004170a4: mov eax, ss:[ebp+0xfffffffffffffff4]
         // 004170a7: mov ds:[edi+0x4], esi
         // 004170aa: mov ds:[edi], eax
         // 004170ac: jmp 0x4170b5
      [-]83f8207502
         // 004170ae: cmp eax, 0x20
         // 004170b1: jnz 0x4170b5
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
      [-]558bec83ec44a1
         // 0041583e: push ebp
         // 0041583f: mov ebp, esp
         // 00415841: sub esp, 0x44
         // 00415844: mov eax, ds:[0x4231e0]
      [-]33c58945fc8b4d085356570fb7410a33db8b7d0c8bd025????????897dc08945bc81e2????????8b410681ea????????8945f08b41028945f40fb701c1e0108955e08945f881fa????????7525
         // 00415849: xor eax, ebp
         // 0041584b: mov ss:[ebp+0xfffffffffffffffc], eax
         // 0041584e: mov ecx, ss:[ebp+0x8]
         // 00415851: push ebx
         // 00415852: push esi
         // 00415853: push edi
         // 00415854: movzx eax, b2 ds:[ecx+0xa]
         // 00415858: xor ebx, ebx
         // 0041585a: mov edi, ss:[ebp+0xc]
         // 0041585d: mov edx, eax
         // 0041585f: and eax, 0x8000
         // 00415864: mov ss:[ebp+0xffffffffffffffc0], edi
         // 00415867: mov ss:[ebp+0xffffffffffffffbc], eax
         // 0041586a: and edx, 0x7fff
         // 00415870: mov eax, ds:[ecx+0x6]
         // 00415873: sub edx, 0x3fff
         // 00415879: mov ss:[ebp+0xfffffffffffffff0], eax
         // 0041587c: mov eax, ds:[ecx+0x2]
         // 0041587f: mov ss:[ebp+0xfffffffffffffff4], eax
         // 00415882: movzx eax, b2 ds:[ecx]
         // 00415885: shl eax, b1 0x10
         // 00415888: mov ss:[ebp+0xffffffffffffffe0], edx
         // 0041588b: mov ss:[ebp+0xfffffffffffffff8], eax
         // 0041588e: cmp edx, 0xffffffffffffc001
         // 00415894: jnz 0x4158bb
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
         // 00415b5d: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 00415b60: mov eax, ebx
         // 00415b62: pop edi
         // 00415b63: pop esi
         // 00415b64: xor ecx, ebp
         // 00415b66: pop ebx
         // 00415b67: call @__security_check_cookie@4
      [-]ffff8be55dc3
         // 00415b6c: mov esp, ebp
         // 00415b6e: pop ebp
         // 00415b6f: retn 
      [-]8b4424048b5424088910894804c20800
         // 00419040: mov eax, ss:[esp+0x4]
         // 00419044: mov edx, ss:[esp+0x8]
         // 00419048: mov ds:[eax], edx
         // 0041904a: mov ds:[eax+0x4], ecx
         // 0041904d: retn b2 0x8
      [-]8b018d5424f883ec08ff74240c52ff500c8b5424108b48043b4a04750e
         // 00419a40: mov eax, ds:[ecx]
         // 00419a42: lea edx, ss:[esp+0xfffffffffffffff8]
         // 00419a46: sub esp, 0x8
         // 00419a49: push ss:[esp+0xc]
         // 00419a4d: push edx
         // 00419a4e: call ds:[eax+0xc]
         // 00419a51: mov edx, ss:[esp+0x10]
         // 00419a55: mov ecx, ds:[eax+0x4]
         // 00419a58: cmp ecx, ds:[edx+0x4]
         // 00419a5b: jnz 0x419a6b
      [-]8b003b027508
         // 00419a5d: mov eax, ds:[eax]
         // 00419a5f: cmp eax, ds:[edx]
         // 00419a61: jnz 0x419a6b
      [-]b00183c408c20800
         // 00419a63: mov b1 al, b1 0x1
         // 00419a65: add esp, 0x8
         // 00419a68: retn b2 0x8
      [-]32c083c408c20800
         // 00419a6b: xor b1 al, b1 al
         // 00419a6d: add esp, 0x8
         // 00419a70: retn b2 0x8
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
      [-]64a1????????5083ec38a1
         // 00419b77: mov eax, fs:[0x0]
         // 00419b7d: push eax
         // 00419b7e: sub esp, 0x38
         // 00419b81: mov eax, ds:[___security_cookie]
      [-]33c489442434535657a1
         // 00419b86: xor eax, esp
         // 00419b88: mov ss:[esp+0x34], eax
         // 00419b8c: push ebx
         // 00419b8d: push esi
         // 00419b8e: push edi
         // 00419b8f: mov eax, ds:[___security_cookie]
      [-]33c4508d44244864a3????????8b7424588b7c245cc74424????????00a1
         // 00419b94: xor eax, esp
         // 00419b96: push eax
         // 00419b97: lea eax, ss:[esp+0x48]
         // 00419b9b: mov fs:[0x0], eax
         // 00419ba1: mov esi, ss:[esp+0x58]
         // 00419ba5: mov edi, ss:[esp+0x5c]
         // 00419ba9: mov ss:[esp+0x10], 0x0
         // 00419bb1: mov eax, ds:[0x4291ac]
      [-]a8017551
         // 00419bb6: test b1 al, b1 0x1
         // 00419bb8: jnz 0x419c0b
      [-]83c801a3
         // 0041824a: or eax, 0x1
         // 0041824d: mov ds:[0x425b18], eax
      [-]c74424????????00c705
         // 0041825e: mov ss:[esp+0x58], 0x0
         // 00418266: mov ds:[0x425b14], 0xf
      [-]420000e8
         // 00418281: call 0x401ab0
      [-]feff83c404c7442450????????
         // 00418290: add esp, 0x4
         // 00418293: mov ss:[esp+0x50], 0xffffffffffffffff
      [-]00008bd083c40485d2744d
         // 004182a1: mov edx, eax
         // 004182a3: add esp, 0x4
         // 004182a6: test edx, edx
         // 004182a8: jz 0x4182f7
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
         // 004182d9: push ecx
         // 004182da: push edx
         // 004182db: lea ecx, ss:[esp+0x34]
         // 004182df: call 0x401ab0
      [-]feff8d7c242cc7442450????????bb????????eb30
         // 004182e4: lea edi, ss:[esp+0x2c]
         // 004182e8: mov ss:[esp+0x50], 0x1
         // 004182f0: mov ebx, 0x1
         // 004182f5: jmp 0x418327
      [-]6aff6a0068
         // 004182f7: push 0xffffffffffffffff
         // 004182f9: push 0x0
         // 004182fb: push 0x425b00
      [-]8d4c2420c7442434????????c74424????????00c644242000e8
         // 00418300: lea ecx, ss:[esp+0x20]
         // 00418304: mov ss:[esp+0x34], 0xf
         // 0041830c: mov ss:[esp+0x30], 0x0
         // 00418314: mov b1 ss:[esp+0x20], b1 0x0
         // 00418319: call 0x401980
      [-]feff8d7c2414bb????????
         // 0041831e: lea edi, ss:[esp+0x14]
         // 00418322: mov ebx, 0x2
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
         // 0041838e: push ss:[esp+0x14]
         // 00418392: call j__free
      [-]feff83c404
         // 00418397: add esp, 0x4
      [-]c7442428????????c74424????????00c644241400
         // 00419d0a: mov ss:[esp+0x28], 0xf
         // 00419d12: mov ss:[esp+0x24], 0x0
         // 00419d1a: mov b1 ss:[esp+0x14], b1 0x0
      [-]f6c3017413
         // 00419d1f: test b1 bl, b1 0x1
         // 00419d22: jz 0x419d37
      [-]837c244010720c
         // 00419d24: cmp ss:[esp+0x40], 0x10
         // 00419d29: jb 0x419d37
      [-]ff74242ce8
         // 004183bb: push ss:[esp+0x2c]
         // 004183bf: call j__free
      [-]feff83c404
         // 004183c4: add esp, 0x4
      [-]8bc68b4c244864890d????????595f5e5b8b4c243433cce8
         // 004183c7: mov eax, esi
         // 004183c9: mov ecx, ss:[esp+0x48]
         // 004183cd: mov fs:[0x0], ecx
         // 004183d4: pop ecx
         // 004183d5: pop edi
         // 004183d6: pop esi
         // 004183d7: pop ebx
         // 004183d8: mov ecx, ss:[esp+0x34]
         // 004183dc: xor ecx, esp
         // 004183de: call @__security_check_cookie@4
      [-]feff83c444c20800
         // 004183e3: add esp, 0x44
         // 004183e6: retn b2 0x8
      [-]64a1????????5083ec2ca1
         // 004186a7: mov eax, fs:[0x0]
         // 004186ad: push eax
         // 004186ae: sub esp, 0x2c
         // 004186b1: mov eax, ds:[0x4231e0]
      [-]33c48944242853555657a1
         // 004186b6: xor eax, esp
         // 004186b8: mov ss:[esp+0x28], eax
         // 004186bc: push ebx
         // 004186bd: push ebp
         // 004186be: push esi
         // 004186bf: push edi
         // 004186c0: mov eax, ds:[0x4231e0]
      [-]33c4508d44244064a3????????8b6c24508d4424146a006a005068????????ff742464c74424????????006a0068????????896c2438c74424????????00ff15
         // 004186c5: xor eax, esp
         // 004186c7: push eax
         // 004186c8: lea eax, ss:[esp+0x40]
         // 004186cc: mov fs:[0x0], eax
         // 004186d2: mov ebp, ss:[esp+0x50]
         // 004186d6: lea eax, ss:[esp+0x14]
         // 004186da: push 0x0
         // 004186dc: push 0x0
         // 004186de: push eax
         // 004186df: push 0x400
         // 004186e4: push ss:[esp+0x64]
         // 004186e8: mov ss:[esp+0x2c], 0x0
         // 004186f0: push 0x0
         // 004186f2: push 0x1300
         // 004186f7: mov ss:[esp+0x38], ebp
         // 004186fb: mov ss:[esp+0x30], 0x0
         // 00418703: call ds:[0x41a150]
      [-]8b74241489742420c7442448????????85c07528
         // 00418709: mov esi, ss:[esp+0x14]
         // 0041870d: mov ss:[esp+0x20], esi
         // 00418711: mov ss:[esp+0x48], 0x1
         // 00418719: test eax, eax
         // 0041871b: jnz 0x418745
      [-]6a0dc74514????????8bcd89451068
         // 0041846d: push 0xd
         // 0041846f: mov ss:[ebp+0x14], 0xf
         // 00418476: mov ecx, ebp
         // 00418478: mov ss:[ebp+0x10], eax
         // 0041847b: push 0x4201a4
      [-]884500e8
         // 00418480: mov b1 ss:[ebp+0x0], b1 al
         // 00418483: call 0x401ab0
      [-]feffc7442418????????e9da000000
         // 00418488: mov ss:[esp+0x18], 0x1
         // 00418490: jmp 0x41856f
      [-]c7442438????????c74424????????00c644242400803e007504
         // 00419e05: mov ss:[esp+0x38], 0xf
         // 00419e0d: mov ss:[esp+0x34], 0x0
         // 00419e15: mov b1 ss:[esp+0x24], b1 0x0
         // 00419e1a: cmp b1 ds:[esi], b1 0x0
         // 00419e1d: jnz 0x419e23
      [-]33c9eb0e
         // 00419e1f: xor ecx, ecx
         // 00419e21: jmp 0x419e31
      [-]8bce8d5101
         // 00419e23: mov ecx, esi
         // 00419e25: lea edx, ds:[ecx+0x1]
      [-]8a014184c075f9
         // 00419e28: mov b1 al, b1 ds:[ecx]
         // 00419e2a: inc ecx
         // 00419e2b: test b1 al, b1 al
         // 00419e2d: jnz 0x419e28
      [-]51568d4c242ce8
         // 004184c1: push ecx
         // 004184c2: push esi
         // 004184c3: lea ecx, ss:[esp+0x2c]
         // 004184c7: call 0x401ab0
      [-]feff8b4c2434c64424480285c9745a
         // 004184cc: mov ecx, ss:[esp+0x34]
         // 004184d0: mov b1 ss:[esp+0x48], b1 0x2
         // 004184d5: test ecx, ecx
         // 004184d7: jz 0x418533
      [-]8da424????????
         // 00419e49: lea esp, ss:[esp+0x0]
      [-]8b5424388d4424248b7c242483fa100f43c7807c08ff0a7415
         // 00419e50: mov edx, ss:[esp+0x38]
         // 00419e54: lea eax, ss:[esp+0x24]
         // 00419e58: mov edi, ss:[esp+0x24]
         // 00419e5c: cmp edx, 0x10
         // 00419e5f: cmovnb eax, edi
         // 00419e62: cmp b1 ds:[eax+ecx+0xffffffffffffffff], b1 0xa
         // 00419e67: jz 0x419e7e
      [-]83fa108d4424240f43c7807c08ff0d0f8590000000
         // 00419e69: cmp edx, 0x10
         // 00419e6c: lea eax, ss:[esp+0x24]
         // 00419e70: cmovnb eax, edi
         // 00419e73: cmp b1 ds:[eax+ecx+0xffffffffffffffff], b1 0xd
         // 00419e78: jnz 0x419f0e
      [-]8d59ff3bcb0f82ac000000
         // 00419e7e: lea ebx, ds:[ecx+0xffffffffffffffff]
         // 00419e81: cmp ecx, ebx
         // 00419e83: jb 0x419f35
      [-]83fa10895c24348d4424240f43c7c60418008b4c243485c975ad
         // 00419e89: cmp edx, 0x10
         // 00419e8c: mov ss:[esp+0x34], ebx
         // 00419e90: lea eax, ss:[esp+0x24]
         // 00419e94: cmovnb eax, edi
         // 00419e97: mov b1 ds:[eax+ebx], b1 0x0
         // 00419e9b: mov ecx, ss:[esp+0x34]
         // 00419e9f: test ecx, ecx
         // 00419ea1: jnz 0x419e50
      [-]8d4424248bcd50e8
         // 00418533: lea eax, ss:[esp+0x24]
         // 00418537: mov ecx, ebp
         // 00418539: push eax
         // 0041853a: call 0x405790
      [-]feff837c243810c7442418????????720c
         // 0041853f: cmp ss:[esp+0x38], 0x10
         // 00418544: mov ss:[esp+0x18], 0x1
         // 0041854c: jb 0x41855a
      [-]ff742424e8
         // 0041854e: push ss:[esp+0x24]
         // 00418552: call j__free
      [-]feff83c404
         // 00418557: add esp, 0x4
      [-]c7442438????????c74424????????00c644242400
         // 00419eca: mov ss:[esp+0x38], 0xf
         // 00419ed2: mov ss:[esp+0x34], 0x0
         // 00419eda: mov b1 ss:[esp+0x24], b1 0x0
      [-]56c644244c00ff15
         // 00419edf: push esi
         // 00419ee0: mov b1 ss:[esp+0x4c], b1 0x0
         // 00419ee5: call ds:[LocalFree]
      [-]8bc58b4c244064890d????????595f5e5d5b8b4c242833cce8
         // 00419eeb: mov eax, ebp
         // 00419eed: mov ecx, ss:[esp+0x40]
         // 00419ef1: mov fs:[0x0], ecx
         // 00419ef8: pop ecx
         // 00419ef9: pop edi
         // 00419efa: pop esi
         // 00419efb: pop ebp
         // 00419efc: pop ebx
         // 00419efd: mov ecx, ss:[esp+0x28]
         // 00419f01: xor ecx, esp
         // 00419f03: call @__security_check_cookie@4
      [-]feff83c438c20800
         // 00419f08: add esp, 0x38
         // 00419f0b: retn b2 0x8
      [-]85c97491
         // 00419f0e: test ecx, ecx
         // 00419f10: jz 0x419ea3
      [-]83fa108d4424240f43c7807c08ff2e7580
         // 00419f12: cmp edx, 0x10
         // 00419f15: lea eax, ss:[esp+0x24]
         // 00419f19: cmovnb eax, edi
         // 00419f1c: cmp b1 ds:[eax+ecx+0xffffffffffffffff], b1 0x2e
         // 00419f21: jnz 0x419ea3
      [-]8d41ff508d4c2428e8
         // 004185b3: lea eax, ds:[ecx+0xffffffffffffffff]
         // 004185b6: push eax
         // 004185b7: lea ecx, ss:[esp+0x28]
         // 004185bb: call 0x401e90
      [-]feffe96effffff
         // 004185c0: jmp 0x418533
      [-]568bf1e84b000000b8
         // 004188f5: push esi
         // 004188f6: mov esi, ecx
         // 004188f8: call 0x418948
         // 004188fd: mov eax, __ImageBase
      [-]c706????????8d4e14894608894604c7460c????????c74610
         // 00418902: mov ds:[esi], 0x38
         // 00418908: lea ecx, ds:[esi+0x14]
         // 0041890b: mov ds:[esi+0x8], eax
         // 0041890e: mov ds:[esi+0x4], eax
         // 00418911: mov ds:[esi+0xc], 0xc00
         // 00418918: mov ds:[esi+0x10], 0x4201fc
      [-]feff85c0791c
         // 00418924: test eax, eax
         // 00418926: jns 0x418944
      [-]85c0740b
         // 0041892e: test eax, eax
         // 00418930: jz 0x41893d
      [-]8bc65ec3
         // 0041a014: mov eax, esi
         // 0041a016: pop esi
         // 0041a017: retn 
      [-]56578bf133ff6a18578d461450e8
         // 00418948: push esi
         // 00418949: push edi
         // 0041894a: mov esi, ecx
         // 0041894c: xor edi, edi
         // 0041894e: push 0x18
         // 00418950: push edi
         // 00418951: lea eax, ds:[esi+0x14]
         // 00418954: push eax
         // 00418955: call _memset
      [-]83c40c897e2c897e308bc6897e345f5ec3
         // 0041895a: add esp, 0xc
         // 0041895d: mov ds:[esi+0x2c], edi
         // 00418960: mov ds:[esi+0x30], edi
         // 00418963: mov eax, esi
         // 00418965: mov ds:[esi+0x34], edi
         // 00418968: pop edi
         // 00418969: pop esi
         // 0041896a: retn 
      [-]8b5424088d420c8b4a
         // 0041a9bc: mov edx, ss:[esp+0x8]
         // 0041a9c0: lea eax, ds:[edx+0xc]
         // 0041a9c3: mov ecx, ds:[edx+0xffffffffffffffe8]
      [-]8b5424088d420c8b4a
         // 004192d8: mov edx, ss:[esp+0x8]
         // 004192dc: lea eax, ds:[edx+0xc]
         // 004192df: mov ecx, ds:[edx+0xffffffffffffff94]
      [-]8b5424088d
         // 00418e90: mov edx, ss:[esp+0x8]
         // 00418e94: lea eax, ds:[edx+0xc]
      [-]8b5424088d
         // 00419090: mov edx, ss:[esp+0x8]
         // 00419094: lea eax, ds:[edx+0xc]
      [-]8d4c2407e8
         // 00419011: lea ecx, ss:[esp+0x7]
         // 00419015: call 0x401310
      [-]8d4c240b
         // 0041901f: lea ecx, ss:[esp+0xb]
         // 00419023: call 0x401300

  }
  condition:
    all of them
}
