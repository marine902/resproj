rule mailru_10_0 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         64a1????????50a1
         // 00401137: mov eax, fs:[0x0]
         // 0040113d: push eax
         // 0040113e: mov eax, ds:[0x4231e0]
      [-]33c4508d44240464a3????????a1
         // 00401143: xor eax, esp
         // 00401145: push eax
         // 00401146: lea eax, ss:[esp+0x4]
         // 0040114a: mov fs:[0x0], eax
         // 00401150: mov eax, ds:[0x425b6c]
      [-]a8017527
         // 00401155: test b1 al, b1 0x1
         // 00401157: jnz 0x401180
      [-]83c801a3
         // 00401239: or eax, 0x1
         // 0040123c: mov ds:[0x425b6c], eax
      [-]c74424????????00c705
         // 00401246: mov ss:[esp+0x10], 0x0
         // 0040124e: mov ds:[0x425b68], ??_7generic_error_category@?A0x846d1564@system@boost@@6B@
      [-]000083c404
         // 0040125d: add esp, 0x4
      [-]8b4c240464890d????????5983c40cc3
         // 0040126a: mov ecx, ss:[esp+0x4]
         // 0040126e: mov fs:[0x0], ecx
         // 00401275: pop ecx
         // 00401276: add esp, 0xc
         // 00401279: retn 
      [-]64a1????????50a1
         // 00401217: mov eax, fs:[0x0]
         // 0040121d: push eax
         // 0040121e: mov eax, ds:[___security_cookie]
      [-]33c4508d44240464a3????????a1
         // 00401223: xor eax, esp
         // 00401225: push eax
         // 00401226: lea eax, ss:[esp+0x4]
         // 0040122a: mov fs:[0x0], eax
         // 00401230: mov eax, ds:[0x4291b4]
      [-]a8017527
         // 00401235: test b1 al, b1 0x1
         // 00401237: jnz 0x401260
      [-]83c801a3
         // 004011c9: or eax, 0x1
         // 004011cc: mov ds:[0x425b64], eax
      [-]c74424????????00c705
         // 004011d6: mov ss:[esp+0x10], 0x0
         // 004011de: mov ds:[0x425b60], 0x4201d4
      [-]000083c404
         // 004011ed: add esp, 0x4
      [-]8b4c240464890d????????5983c40cc3
         // 004012da: mov ecx, ss:[esp+0x4]
         // 004012de: mov fs:[0x0], ecx
         // 004012e5: pop ecx
         // 004012e6: add esp, 0xc
         // 004012e9: retn 
      [-]558bec568b
         // 00401720: push ebp
         // 00401721: mov ebp, esp
         // 00401723: push esi
         // 00401725: mov edi, ss:[ebp+0x8]
      [-]807d0c0074
         // 00401814: cmp b1 ss:[ebp+0xc], b1 0x0
         // 00401818: jz 0x40186d
      [-]ffffc21000
         // 0040273e: retn b2 0x10
      [-]558bec51
         // 00404440: push ebp
         // 00404441: mov ebp, esp
         // 00404443: push ecx
      [-]56ff750ce8
         // 00404444: push esi
         // 00404445: push ss:[ebp+0xc]
         // 0040444f: call ??_U@YAPAXI@Z
      [-]00008bf0
         // 00404454: mov esi, eax
      [-]ff750c6a0056e8
         // 004037c4: push ss:[ebp+0xc]
         // 004037c7: push 0x0
         // 004037c9: push esi
         // 004037ca: call _memset
      [-]000083c40c
         // 004037cf: add esp, 0xc
      [-]8be55dc3
         // 0040447f: mov esp, ebp
         // 00404481: pop ebp
         // 00404482: retn 
      [-]837d0cff7614
         // 00404553: cmp ss:[ebp+0xc], 0xffffffffffffffff
         // 00404557: jbe 0x40456d
      [-]8b450833c90b4d0c99c1e00f0b
         // 0040456d: mov eax, ss:[ebp+0x8]
         // 00404570: xor ecx, ecx
         // 00404572: or ecx, ss:[ebp+0xc]
         // 00404575: cdq 
         // 00404576: shl eax, b1 0xf
         // 00404579: or eax, ebx
      [-]0d????????89
         // 0040457d: or eax, 0x7ff80000
         // 00404582: mov ds:[edi+0x4], eax
      [-]5dc20800
         // 00404589: pop ebp
         // 0040458a: retn b2 0x8
      [-]8b5d0c8b461040508d45
         // 00403874: mov ebx, ss:[ebp+0xc]
         // 00403877: mov eax, ds:[esi+0x10]
         // 0040387a: inc eax
         // 0040387b: push eax
         // 0040387c: lea eax, ss:[ebp+0xffffffffffffff98]
      [-]40505657e8
         // 0040455a: inc eax
         // 0040455b: push eax
         // 0040455c: push esi
         // 0040455d: push edi
         // 0040455e: call _memmove_0
      [-]c645fc01
         // 00404574: mov b1 ss:[ebp+0xfffffffffffffffc], b1 0x1
      [-]000083c4
         // 00404595: add esp, 0x1c
      [-]85c00f85
         // 00404598: test eax, eax
         // 0040459a: jnz 0x4047d0
      [-]100f95c3eb02
         // 00404877: cmp ds:[ebx+0x10], 0x0
         // 0040487b: setnz b1 bl
         // 0040487e: jmp 0x404882
      [-]8d4da4c645fc00e8
         // 004047d2: lea ecx, ss:[ebp+0xffffffffffffffa4]
         // 004047d5: mov b1 ss:[ebp+0xfffffffffffffffc], b1 0x0
         // 004047d9: call 0x404ca0
      [-]000085ff74
         // 004047de: test edi, edi
         // 004047e0: jz 0x4047eb
      [-]8b7d088bf183c707
         // 004041cd: mov edi, ss:[ebp+0x8]
         // 004041d0: mov esi, ecx
         // 004041d2: add edi, 0x7
      [-]83e7f88b0e85c974
         // 004041da: and edi, 0xfffffffffffffff8
         // 004041dd: mov ecx, ds:[esi]
         // 004041df: test ecx, ecx
         // 004041e1: jz 0x4041f4
      [-]8b41048d1438
         // 00404f46: mov eax, ds:[ecx+0x4]
         // 00404f49: lea edx, ds:[eax+edi]
      [-]03c1895104
         // 004041ed: add eax, ecx
         // 004041ef: mov ds:[ecx+0x4], edx
      [-]83c7083b
         // 004041f4: add edi, 0x8
         // 004041f7: cmp edi, ebx
      [-]8bc70f46
         // 004041f9: mov eax, edi
         // 004041fb: cmovbe eax, ebx
      [-]8bc885c9
         // 00404205: mov ecx, eax
         // 00404207: test ecx, ecx
      [-]8b0685c074
         // 00404f8e: mov eax, ds:[esi]
         // 00404f90: test eax, eax
         // 00404f92: jz 0x404fa5
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
         // 00404ff0: push ebp
         // 00404ff1: mov ebp, esp
         // 00404ff3: mov b1 al, b1 ss:[ebp+0x8]
         // 00404ff6: cmp b1 al, b1 0x2c
         // 00404ff8: jz 0x40501a
      [-]3c3a741c
         // 00404ffa: cmp b1 al, b1 0x3a
         // 00404ffc: jz 0x40501a
      [-]3c5d7418
         // 00404ffe: cmp b1 al, b1 0x5d
         // 00405000: jz 0x40501a
      [-]3c7d7414
         // 00405002: cmp b1 al, b1 0x7d
         // 00405004: jz 0x40501a
      [-]3c207410
         // 00405006: cmp b1 al, b1 0x20
         // 00405008: jz 0x40501a
      [-]3c097c04
         // 0040500a: cmp b1 al, b1 0x9
         // 0040500c: jl 0x405012
      [-]3c0d7e08
         // 0040500e: cmp b1 al, b1 0xd
         // 00405010: jle 0x40501a
      [-]84c07404
         // 00405012: test b1 al, b1 al
         // 00405014: jz 0x40501a
      [-]837914107202
         // 00406843: cmp ds:[ecx+0x14], 0x10
         // 00406847: jb 0x40684b
      [-]558bec8b45088378141072
         // 00406c30: push ebp
         // 00406c31: mov ebp, esp
         // 00406c33: mov eax, ss:[ebp+0x8]
         // 00406c36: cmp ds:[eax+0x14], 0x10
         // 00406c3a: jb 0x406c4c
      [-]558bec568b750c2b750857568bf9e8
         // 00407130: push ebp
         // 00407131: mov ebp, esp
         // 00407133: push esi
         // 00407134: mov esi, ss:[ebp+0xc]
         // 00407137: sub esi, ss:[ebp+0x8]
         // 0040713a: push edi
         // 0040713b: push esi
         // 0040713c: mov edi, ecx
         // 0040713e: call 0x406fc0
      [-]ffff84c07413
         // 00407143: test b1 al, b1 al
         // 00407145: jz 0x40715a
      [-]56ff7508ff37e8
         // 00407147: push esi
         // 00407148: push ss:[ebp+0x8]
         // 0040714b: push ds:[edi]
         // 0040714d: call _memmove
      [-]000083c40c03c6894704
         // 00407152: add esp, 0xc
         // 00407155: add eax, esi
         // 00407157: mov ds:[edi+0x4], eax
      [-]5f5e5dc20c00
         // 0040715a: pop edi
         // 0040715b: pop esi
         // 0040715c: pop ebp
         // 0040715d: retn b2 0xc
      [-]558bec6a00ff7508ff15
         // 004054ef: push ebp
         // 004054f0: mov ebp, esp
         // 004054f2: push 0x0
         // 004054f4: push ss:[ebp+0x8]
         // 004054f7: call ds:[0x41c010]
      [-]8b0985c97411
         // 00407440: mov ecx, ds:[ecx]
         // 00407442: test ecx, ecx
         // 00407444: jz 0x407457
      [-]8b01ff500885c07408
         // 00407446: mov eax, ds:[ecx]
         // 00407448: call ds:[eax+0x8]
         // 0040744b: test eax, eax
         // 0040744d: jz 0x407457
      [-]8b108bc86a01ff12
         // 0040744f: mov edx, ds:[eax]
         // 00407451: mov ecx, eax
         // 00407453: push 0x1
         // 00407455: call ds:[edx]
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
      [-]b8????????5dc3
         // 004074b3: mov eax, 0x8004
         // 004074b8: pop ebp
         // 004074b9: retn 
      [-]4150890d??
         // 00407801: inc ecx
         // 00407802: push eax
         // 00407803: mov ds:[0x423028], ecx
      [-]85c07402
         // 0040780f: test eax, eax
         // 00407811: jz 0x407815
      [-]83f90a72da
         // 0040781b: cmp ecx, 0xa
         // 0040781e: jb 0x4077fa
      [-]000059c3
         // 00408ae0: pop ecx
         // 00408ae1: retn 
      [-]558bec837d0800742d
         // 004092f9: push ebp
         // 004092fa: mov ebp, esp
         // 004092fc: cmp ss:[ebp+0x8], 0x0
         // 00409300: jz 0x40932f
      [-]558becff7508ff15
         // 0040e706: push ebp
         // 0040e707: mov ebp, esp
         // 0040e709: push ss:[ebp+0x8]
         // 0040e70c: call ds:[0x41c06c]
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
         // 0041220a: push ebp
         // 0041220b: mov ebp, esp
         // 0041220d: sub esp, 0x24
         // 00412210: mov eax, ds:[___security_cookie]
      [-]33c58945fc8b4508538b1d
         // 00412215: xor eax, ebp
         // 00412217: mov ss:[ebp+0xfffffffffffffffc], eax
         // 0041221a: mov eax, ss:[ebp+0x8]
         // 0041221d: push ebx
         // 0041221e: mov ebx, ds:[0x41c0b0]
      [-]56578945e433f68b450c568945e0ffd38bf8897de8e8
         // 00412224: push esi
         // 00412225: push edi
         // 00412226: mov ss:[ebp+0xffffffffffffffe4], eax
         // 00412229: xor esi, esi
         // 0041222b: mov eax, ss:[ebp+0xc]
         // 0041222e: push esi
         // 0041222f: mov ss:[ebp+0xffffffffffffffe0], eax
         // 00412232: call ebx
         // 00412234: mov edi, eax
         // 00412236: mov ss:[ebp+0xffffffffffffffe8], edi
         // 00412239: call ___crtIsPackagedApp
      [-]ffff8945ec3935
         // 0041223e: mov ss:[ebp+0xffffffffffffffec], eax
         // 00412241: cmp ds:[0x4286ec], esi
      [-]0f85b0000000
         // 00412247: jnz 0x4122fd
      [-]68????????5668
         // 0040fcd2: push 0x800
         // 0040fcd7: push esi
         // 0040fcd8: push 0x41e910
      [-]8bf885ff7526
         // 0040fce3: mov edi, eax
         // 0040fce5: test edi, edi
         // 0040fce7: jnz 0x40fd0f
      [-]83f8570f856a010000
         // 0041226a: cmp eax, 0x57
         // 0041226d: jnz 0x4123dd
      [-]8bf885ff0f8453010000
         // 00412280: mov edi, eax
         // 00412282: test edi, edi
         // 00412284: jz 0x4123dd
      [-]85c00f843f010000
         // 00412296: test eax, eax
         // 00412298: jz 0x4123dd
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
         // 00412303: test eax, eax
         // 00412305: jz 0x412322
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
         // 0040fdb8: push 0x3
         // 0040fdba: jmp 0x40fda1
      [-]3bc7744f
         // 0040fdc7: cmp eax, edi
         // 0040fdc9: jz 0x40fe1a
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
      [-]558bec8b4508a3
         // 004124ec: push ebp
         // 004124ed: mov ebp, esp
         // 004124ef: mov eax, ss:[ebp+0x8]
         // 004124f2: mov ds:[0x425a5c], eax
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
      [-]395c85f0750b
         // 00415328: cmp ss:[ebp+eax*0x4], ebx
         // 0041532c: jnz 0x415339
      [-]4083f8037cf4
         // 0041532e: inc eax
         // 0041532f: cmp eax, 0x3
         // 00415332: jl 0x415328
      [-]e9b9040000
         // 00415334: jmp 0x4157f2
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
      [-]83cfff894dc86a20d3e7582bc1895de0f7d78945d8
         // 004156e8: or edi, 0xffffffffffffffff
         // 004156eb: mov ss:[ebp+0xffffffffffffffc8], ecx
         // 004156ee: push 0x20
         // 004156f0: shl edi, b1 cl
         // 004156f2: pop eax
         // 004156f3: sub eax, ecx
         // 004156f5: mov ss:[ebp+0xffffffffffffffe0], ebx
         // 004156f8: not edi
         // 004156fa: mov ss:[ebp+0xffffffffffffffd8], eax
      [-]8b549df08bc2d3ea23c70b55e08b4dd8d3e08b4dc889549df0438945e03bde7cdf
         // 004156fd: mov edx, ss:[ebp+ebx*0x4]
         // 00415701: mov eax, edx
         // 00415703: shr edx, b1 cl
         // 00415705: and eax, edi
         // 00415707: or edx, ss:[ebp+0xffffffffffffffe0]
         // 0041570a: mov ecx, ss:[ebp+0xffffffffffffffd8]
         // 0041570d: shl eax, b1 cl
         // 0041570f: mov ecx, ss:[ebp+0xffffffffffffffc8]
         // 00415712: mov ss:[ebp+ebx*0x4], edx
         // 00415716: inc ebx
         // 00415717: mov ss:[ebp+0xffffffffffffffe0], eax
         // 0041571a: cmp ebx, esi
         // 0041571c: jl 0x4156fd
      [-]8b75cc8d55f88bc6c1e0026a022bd033db59
         // 0041571e: mov esi, ss:[ebp+0xffffffffffffffcc]
         // 00415721: lea edx, ss:[ebp+0xfffffffffffffff8]
         // 00415724: mov eax, esi
         // 00415726: shl eax, b1 0x2
         // 00415729: push 0x2
         // 0041572b: sub edx, eax
         // 0041572d: xor ebx, ebx
         // 0041572f: pop ecx
      [-]3bce7c08
         // 00415730: cmp ecx, esi
         // 00415732: jl 0x41573c
      [-]8b0289448df0eb04
         // 00415734: mov eax, ds:[edx]
         // 00415736: mov ss:[ebp+ecx*0x4], eax
         // 0041573a: jmp 0x415740
      [-]895c8df0
         // 0041573c: mov ss:[ebp+ecx*0x4], ebx
      [-]83ea044979ea
         // 00415740: sub edx, 0x4
         // 00415743: dec ecx
         // 00415744: jns 0x415730
      [-]33db0335??
         // 0041574c: xor ebx, ebx
         // 0041574e: add esi, ds:[0x42432c]
      [-]43e995000000
         // 00415754: inc ebx
         // 00415755: jmp 0x4157ef
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
      [-]6a1f582b05??
         // 004157f2: push 0x1f
         // 004157f4: pop eax
         // 004157f5: sub eax, ds:[0x424338]
      [-]8bc88b45bcd3e6f7d81bc025????????0bf0a1??
         // 004157fb: mov ecx, eax
         // 004157fd: mov eax, ss:[ebp+0xffffffffffffffbc]
         // 00415800: shl esi, b1 cl
         // 00415802: neg eax
         // 00415804: sbb eax, eax
         // 00415806: and eax, 0xffffffff80000000
         // 0041580b: or esi, eax
         // 0041580d: mov eax, ds:[0x42433c]
      [-]0b75f083f840750a
         // 00415812: or esi, ss:[ebp+0xfffffffffffffff0]
         // 00415815: cmp eax, 0x40
         // 00415818: jnz 0x415824
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
         // 00415896: mov esi, ebx
         // 00415898: mov eax, ebx
      [-]395c85f0750b
         // 0041589a: cmp ss:[ebp+eax*0x4], ebx
         // 0041589e: jnz 0x4158ab
      [-]4083f8037cf4
         // 004158a0: inc eax
         // 004158a1: cmp eax, 0x3
         // 004158a4: jl 0x41589a
      [-]e9b9040000
         // 004158a6: jmp 0x415d64
      [-]33c08d7df0ababab
         // 004158ab: xor eax, eax
         // 004158ad: lea edi, ss:[ebp+0xfffffffffffffff0]
         // 004158b0: stosdd 
         // 004158b1: stosdd 
         // 004158b2: stosdd 
      [-]6a025be9a6040000
         // 004158b3: push 0x2
         // 004158b5: pop ebx
         // 004158b6: jmp 0x415d61
      [-]8d75f08d7de48955dca5488945cc6a1f895dd4a58d48018bc199a55e23d603d0c1fa058955c481e1????????7905
         // 004158c0: lea esi, ss:[ebp+0xfffffffffffffff0]
         // 004158c3: lea edi, ss:[ebp+0xffffffffffffffe4]
         // 004158c6: mov ss:[ebp+0xffffffffffffffdc], edx
         // 004158c9: movsdd 
         // 004158ca: dec eax
         // 004158cb: mov ss:[ebp+0xffffffffffffffcc], eax
         // 004158ce: push 0x1f
         // 004158d0: mov ss:[ebp+0xffffffffffffffd4], ebx
         // 004158d3: movsdd 
         // 004158d4: lea ecx, ds:[eax+0x1]
         // 004158d7: mov eax, ecx
         // 004158d9: cdq 
         // 004158da: movsdd 
         // 004158db: pop esi
         // 004158dc: and edx, esi
         // 004158de: add edx, eax
         // 004158e0: sar edx, b1 0x5
         // 004158e3: mov ss:[ebp+0xffffffffffffffc4], edx
         // 004158e6: and ecx, 0xffffffff8000001f
         // 004158ec: jns 0x4158f3
      [-]4983c9e041
         // 004158ee: dec ecx
         // 004158ef: or ecx, 0xffffffffffffffe0
         // 004158f2: inc ecx
      [-]2bf133c0408975d08bce83cfffd3e06a035e854495f00f84a4000000
         // 004158f3: sub esi, ecx
         // 004158f5: xor eax, eax
         // 004158f7: inc eax
         // 004158f8: mov ss:[ebp+0xffffffffffffffd0], esi
         // 004158fb: mov ecx, esi
         // 004158fd: or edi, 0xffffffffffffffff
         // 00415900: shl eax, b1 cl
         // 00415902: push 0x3
         // 00415904: pop esi
         // 00415905: test ss:[ebp+edx*0x4], eax
         // 00415909: jz 0x4159b3
      [-]8bc7d3e0f7d0854495f0eb04
         // 0041590f: mov eax, edi
         // 00415911: shl eax, b1 cl
         // 00415913: not eax
         // 00415915: test ss:[ebp+edx*0x4], eax
         // 00415919: jmp 0x41591f
      [-]395c95f0
         // 0041591b: cmp ss:[ebp+edx*0x4], ebx
      [-]423bd67cf5
         // 00415921: inc edx
         // 00415922: cmp edx, esi
         // 00415924: jl 0x41591b
      [-]e985000000
         // 00415926: jmp 0x4159b0
      [-]8b45cc996a1f5923d103d08b45ccc1fa0525????????7905
         // 0041592b: mov eax, ss:[ebp+0xffffffffffffffcc]
         // 0041592e: cdq 
         // 0041592f: push 0x1f
         // 00415931: pop ecx
         // 00415932: and edx, ecx
         // 00415934: add edx, eax
         // 00415936: mov eax, ss:[ebp+0xffffffffffffffcc]
         // 00415939: sar edx, b1 0x5
         // 0041593c: and eax, 0xffffffff8000001f
         // 00415941: jns 0x415948
      [-]4883c8e040
         // 00415943: dec eax
         // 00415944: or eax, 0xffffffffffffffe0
         // 00415947: inc eax
      [-]2bc8895dd433c040d3e08945c88b4495f08b4dc803c8894dd83bc88b45d88bcb6aff5f7205
         // 00415948: sub ecx, eax
         // 0041594a: mov ss:[ebp+0xffffffffffffffd4], ebx
         // 0041594d: xor eax, eax
         // 0041594f: inc eax
         // 00415950: shl eax, b1 cl
         // 00415952: mov ss:[ebp+0xffffffffffffffc8], eax
         // 00415955: mov eax, ss:[ebp+edx*0x4]
         // 00415959: mov ecx, ss:[ebp+0xffffffffffffffc8]
         // 0041595c: add ecx, eax
         // 0041595e: mov ss:[ebp+0xffffffffffffffd8], ecx
         // 00415961: cmp ecx, eax
         // 00415963: mov eax, ss:[ebp+0xffffffffffffffd8]
         // 00415966: mov ecx, ebx
         // 00415968: push 0xffffffffffffffff
         // 0041596a: pop edi
         // 0041596b: jb 0x415972
      [-]3b45c87306
         // 0041596d: cmp eax, ss:[ebp+0xffffffffffffffc8]
         // 00415970: jnb 0x415978
      [-]33c941894dd4
         // 00415972: xor ecx, ecx
         // 00415974: inc ecx
         // 00415975: mov ss:[ebp+0xffffffffffffffd4], ecx
      [-]894495f04a782e
         // 00415978: mov ss:[ebp+edx*0x4], eax
         // 0041597c: dec edx
         // 0041597d: js 0x4159ad
      [-]85c97427
         // 0041597f: test ecx, ecx
         // 00415981: jz 0x4159aa
      [-]8b4495f08bcb895dd48d78013bf8897dd88bc77205
         // 00415983: mov eax, ss:[ebp+edx*0x4]
         // 00415987: mov ecx, ebx
         // 00415989: mov ss:[ebp+0xffffffffffffffd4], ebx
         // 0041598c: lea edi, ds:[eax+0x1]
         // 0041598f: cmp edi, eax
         // 00415991: mov ss:[ebp+0xffffffffffffffd8], edi
         // 00415994: mov eax, edi
         // 00415996: jb 0x41599d
      [-]83f8017306
         // 00415998: cmp eax, 0x1
         // 0041599b: jnb 0x4159a3
      [-]33c941894dd4
         // 0041599d: xor ecx, ecx
         // 0041599f: inc ecx
         // 004159a0: mov ss:[ebp+0xffffffffffffffd4], ecx
      [-]894495f04a79d5
         // 004159a3: mov ss:[ebp+edx*0x4], eax
         // 004159a7: dec edx
         // 004159a8: jns 0x41597f
      [-]8bc7d3e0214495f08d42013bc67d11
         // 004159b3: mov eax, edi
         // 004159b5: shl eax, b1 cl
         // 004159b7: and ss:[ebp+edx*0x4], eax
         // 004159bb: lea eax, ds:[edx+0x1]
         // 004159be: cmp eax, esi
         // 004159c0: jge 0x4159d3
      [-]8d7df08bce8d3c872bc833c0f3ab83cfff
         // 004159c2: lea edi, ss:[ebp+0xfffffffffffffff0]
         // 004159c5: mov ecx, esi
         // 004159c7: lea edi, ds:[edi+eax*0x4]
         // 004159ca: sub ecx, eax
         // 004159cc: xor eax, eax
         // 004159ce: rep stosdd 
         // 004159d0: or edi, 0xffffffffffffffff
      [-]8b4de0395dd47401
         // 004159d3: mov ecx, ss:[ebp+0xffffffffffffffe0]
         // 004159d6: cmp ss:[ebp+0xffffffffffffffd4], ebx
         // 004159d9: jz 0x4159dc
      [-]8bc22b05??
         // 004159e2: mov eax, edx
         // 004159e4: sub eax, ds:[0x42434c]
      [-]3bc87d0f
         // 004159ea: cmp ecx, eax
         // 004159ec: jge 0x4159fd
      [-]33c08d7df0ababab
         // 004159ee: xor eax, eax
         // 004159f0: lea edi, ss:[ebp+0xfffffffffffffff0]
         // 004159f3: stosdd 
         // 004159f4: stosdd 
         // 004159f5: stosdd 
      [-]8bf3e9b6feffff
         // 004159f6: mov esi, ebx
         // 004159f8: jmp 0x4158b3
      [-]3bca0f8f19020000
         // 004159fd: cmp ecx, edx
         // 004159ff: jg 0x415c1e
      [-]2b55dc8d75e48955d08d7df08bc2a59983e21f03c2c1f805a58945c48b45d0a525????????7905
         // 00415a05: sub edx, ss:[ebp+0xffffffffffffffdc]
         // 00415a08: lea esi, ss:[ebp+0xffffffffffffffe4]
         // 00415a0b: mov ss:[ebp+0xffffffffffffffd0], edx
         // 00415a0e: lea edi, ss:[ebp+0xfffffffffffffff0]
         // 00415a11: mov eax, edx
         // 00415a13: movsdd 
         // 00415a14: cdq 
         // 00415a15: and edx, 0x1f
         // 00415a18: add eax, edx
         // 00415a1a: sar eax, b1 0x5
         // 00415a1d: movsdd 
         // 00415a1e: mov ss:[ebp+0xffffffffffffffc4], eax
         // 00415a21: mov eax, ss:[ebp+0xffffffffffffffd0]
         // 00415a24: movsdd 
         // 00415a25: and eax, 0xffffffff8000001f
         // 00415a2a: jns 0x415a31
      [-]4883c8e040
         // 00415a2c: dec eax
         // 00415a2d: or eax, 0xffffffffffffffe0
         // 00415a30: inc eax
      [-]8945d083cfff8bc7895de08b7dd08bcfd3e0f7d06a208945d8582bc76a038945c85e
         // 00415a31: mov ss:[ebp+0xffffffffffffffd0], eax
         // 00415a34: or edi, 0xffffffffffffffff
         // 00415a37: mov eax, edi
         // 00415a39: mov ss:[ebp+0xffffffffffffffe0], ebx
         // 00415a3c: mov edi, ss:[ebp+0xffffffffffffffd0]
         // 00415a3f: mov ecx, edi
         // 00415a41: shl eax, b1 cl
         // 00415a43: not eax
         // 00415a45: push 0x20
         // 00415a47: mov ss:[ebp+0xffffffffffffffd8], eax
         // 00415a4a: pop eax
         // 00415a4b: sub eax, edi
         // 00415a4d: push 0x3
         // 00415a4f: mov ss:[ebp+0xffffffffffffffc8], eax
         // 00415a52: pop esi
      [-]8b549df08bcf8bc2d3ea0b55e02345d88b4dc8d3e089549df0438945e03bde7cdf
         // 00415a53: mov edx, ss:[ebp+ebx*0x4]
         // 00415a57: mov ecx, edi
         // 00415a59: mov eax, edx
         // 00415a5b: shr edx, b1 cl
         // 00415a5d: or edx, ss:[ebp+0xffffffffffffffe0]
         // 00415a60: and eax, ss:[ebp+0xffffffffffffffd8]
         // 00415a63: mov ecx, ss:[ebp+0xffffffffffffffc8]
         // 00415a66: shl eax, b1 cl
         // 00415a68: mov ss:[ebp+ebx*0x4], edx
         // 00415a6c: inc ebx
         // 00415a6d: mov ss:[ebp+0xffffffffffffffe0], eax
         // 00415a70: cmp ebx, esi
         // 00415a72: jl 0x415a53
      [-]8b45c48d55f8c1e00233db6a022bd083cfff8b45c459
         // 00415a74: mov eax, ss:[ebp+0xffffffffffffffc4]
         // 00415a77: lea edx, ss:[ebp+0xfffffffffffffff8]
         // 00415a7a: shl eax, b1 0x2
         // 00415a7d: xor ebx, ebx
         // 00415a7f: push 0x2
         // 00415a81: sub edx, eax
         // 00415a83: or edi, 0xffffffffffffffff
         // 00415a86: mov eax, ss:[ebp+0xffffffffffffffc4]
         // 00415a89: pop ecx
      [-]3bc87c0b
         // 00415a8a: cmp ecx, eax
         // 00415a8c: jl 0x415a99
      [-]8b0289448df08b45c4eb04
         // 00415a8e: mov eax, ds:[edx]
         // 00415a90: mov ss:[ebp+ecx*0x4], eax
         // 00415a94: mov eax, ss:[ebp+0xffffffffffffffc4]
         // 00415a97: jmp 0x415a9d
      [-]895c8df0
         // 00415a99: mov ss:[ebp+ecx*0x4], ebx
      [-]83ea044979e7
         // 00415a9d: sub edx, 0x4
         // 00415aa0: dec ecx
         // 00415aa1: jns 0x415a8a
      [-]8b4dcc418bc19983e21f03d0c1fa058955d481e1????????7905
         // 00415aa3: mov ecx, ss:[ebp+0xffffffffffffffcc]
         // 00415aa6: inc ecx
         // 00415aa7: mov eax, ecx
         // 00415aa9: cdq 
         // 00415aaa: and edx, 0x1f
         // 00415aad: add edx, eax
         // 00415aaf: sar edx, b1 0x5
         // 00415ab2: mov ss:[ebp+0xffffffffffffffd4], edx
         // 00415ab5: and ecx, 0xffffffff8000001f
         // 00415abb: jns 0x415ac2
      [-]4983c9e041
         // 00415abd: dec ecx
         // 00415abe: or ecx, 0xffffffffffffffe0
         // 00415ac1: inc ecx
      [-]6a1f582bc18945d033c08b4dd040d3e0854495f00f8492000000
         // 00415ac2: push 0x1f
         // 00415ac4: pop eax
         // 00415ac5: sub eax, ecx
         // 00415ac7: mov ss:[ebp+0xffffffffffffffd0], eax
         // 00415aca: xor eax, eax
         // 00415acc: mov ecx, ss:[ebp+0xffffffffffffffd0]
         // 00415acf: inc eax
         // 00415ad0: shl eax, b1 cl
         // 00415ad2: test ss:[ebp+edx*0x4], eax
         // 00415ad6: jz 0x415b6e
      [-]8bc7d3e0f7d0854495f0eb04
         // 00415adc: mov eax, edi
         // 00415ade: shl eax, b1 cl
         // 00415ae0: not eax
         // 00415ae2: test ss:[ebp+edx*0x4], eax
         // 00415ae6: jmp 0x415aec
      [-]395c95f0
         // 00415ae8: cmp ss:[ebp+edx*0x4], ebx
      [-]423bd67cf5
         // 00415aee: inc edx
         // 00415aef: cmp edx, esi
         // 00415af1: jl 0x415ae8
      [-]8b7dcc8bc76a1f995923d103d0c1fa0581e7????????7905
         // 00415af5: mov edi, ss:[ebp+0xffffffffffffffcc]
         // 00415af8: mov eax, edi
         // 00415afa: push 0x1f
         // 00415afc: cdq 
         // 00415afd: pop ecx
         // 00415afe: and edx, ecx
         // 00415b00: add edx, eax
         // 00415b02: sar edx, b1 0x5
         // 00415b05: and edi, 0xffffffff8000001f
         // 00415b0b: jns 0x415b12
      [-]4f83cfe047
         // 00415b0d: dec edi
         // 00415b0e: or edi, 0xffffffffffffffe0
         // 00415b11: inc edi
      [-]8b4495f02bcf33ff47d3e78bcb897ddc03f8897de03bf88b45e06aff5f7205
         // 00415b12: mov eax, ss:[ebp+edx*0x4]
         // 00415b16: sub ecx, edi
         // 00415b18: xor edi, edi
         // 00415b1a: inc edi
         // 00415b1b: shl edi, b1 cl
         // 00415b1d: mov ecx, ebx
         // 00415b1f: mov ss:[ebp+0xffffffffffffffdc], edi
         // 00415b22: add edi, eax
         // 00415b24: mov ss:[ebp+0xffffffffffffffe0], edi
         // 00415b27: cmp edi, eax
         // 00415b29: mov eax, ss:[ebp+0xffffffffffffffe0]
         // 00415b2c: push 0xffffffffffffffff
         // 00415b2e: pop edi
         // 00415b2f: jb 0x415b36
      [-]3b45dc7303
         // 00415b31: cmp eax, ss:[ebp+0xffffffffffffffdc]
         // 00415b34: jnb 0x415b39
      [-]894495f04a7828
         // 00415b39: mov ss:[ebp+edx*0x4], eax
         // 00415b3d: dec edx
         // 00415b3e: js 0x415b68
      [-]85c97421
         // 00415b40: test ecx, ecx
         // 00415b42: jz 0x415b65
      [-]8b4495f08bcb8d78013bf8897de08bc77205
         // 00415b44: mov eax, ss:[ebp+edx*0x4]
         // 00415b48: mov ecx, ebx
         // 00415b4a: lea edi, ds:[eax+0x1]
         // 00415b4d: cmp edi, eax
         // 00415b4f: mov ss:[ebp+0xffffffffffffffe0], edi
         // 00415b52: mov eax, edi
         // 00415b54: jb 0x415b5b
      [-]83f8017303
         // 00415b56: cmp eax, 0x1
         // 00415b59: jnb 0x415b5e
      [-]894495f04a79db
         // 00415b5e: mov ss:[ebp+edx*0x4], eax
         // 00415b62: dec edx
         // 00415b63: jns 0x415b40
      [-]8bc7d3e0214495f0423bd67d11
         // 00415b6e: mov eax, edi
         // 00415b70: shl eax, b1 cl
         // 00415b72: and ss:[ebp+edx*0x4], eax
         // 00415b76: inc edx
         // 00415b77: cmp edx, esi
         // 00415b79: jge 0x415b8c
      [-]8d7df08bce8d3c972bca33c0f3ab83cfff
         // 00415b7b: lea edi, ss:[ebp+0xfffffffffffffff0]
         // 00415b7e: mov ecx, esi
         // 00415b80: lea edi, ds:[edi+edx*0x4]
         // 00415b83: sub ecx, edx
         // 00415b85: xor eax, eax
         // 00415b87: rep stosdd 
         // 00415b89: or edi, 0xffffffffffffffff
      [-]418bc19983e21f03c2c1f8058945d881e1????????7905
         // 00415b92: inc ecx
         // 00415b93: mov eax, ecx
         // 00415b95: cdq 
         // 00415b96: and edx, 0x1f
         // 00415b99: add eax, edx
         // 00415b9b: sar eax, b1 0x5
         // 00415b9e: mov ss:[ebp+0xffffffffffffffd8], eax
         // 00415ba1: and ecx, 0xffffffff8000001f
         // 00415ba7: jns 0x415bae
      [-]4983c9e041
         // 00415ba9: dec ecx
         // 00415baa: or ecx, 0xffffffffffffffe0
         // 00415bad: inc ecx
      [-]894ddc8bc3d3e76a20895de0f7d78b5ddc592bcb8945cc894ddc
         // 00415bae: mov ss:[ebp+0xffffffffffffffdc], ecx
         // 00415bb1: mov eax, ebx
         // 00415bb3: shl edi, b1 cl
         // 00415bb5: push 0x20
         // 00415bb7: mov ss:[ebp+0xffffffffffffffe0], ebx
         // 00415bba: not edi
         // 00415bbc: mov ebx, ss:[ebp+0xffffffffffffffdc]
         // 00415bbf: pop ecx
         // 00415bc0: sub ecx, ebx
         // 00415bc2: mov ss:[ebp+0xffffffffffffffcc], eax
         // 00415bc5: mov ss:[ebp+0xffffffffffffffdc], ecx
      [-]8b5485f08bcb8bc2d3ea8b4dcc23c70b55e089548df08b4ddcd3e08945e08b45cc408945cc3bc67cd7
         // 00415bc8: mov edx, ss:[ebp+eax*0x4]
         // 00415bcc: mov ecx, ebx
         // 00415bce: mov eax, edx
         // 00415bd0: shr edx, b1 cl
         // 00415bd2: mov ecx, ss:[ebp+0xffffffffffffffcc]
         // 00415bd5: and eax, edi
         // 00415bd7: or edx, ss:[ebp+0xffffffffffffffe0]
         // 00415bda: mov ss:[ebp+ecx*0x4], edx
         // 00415bde: mov ecx, ss:[ebp+0xffffffffffffffdc]
         // 00415be1: shl eax, b1 cl
         // 00415be3: mov ss:[ebp+0xffffffffffffffe0], eax
         // 00415be6: mov eax, ss:[ebp+0xffffffffffffffcc]
         // 00415be9: inc eax
         // 00415bea: mov ss:[ebp+0xffffffffffffffcc], eax
         // 00415bed: cmp eax, esi
         // 00415bef: jl 0x415bc8
      [-]8b75d88d55f88bc6c1e0026a022bd033db59
         // 00415bf1: mov esi, ss:[ebp+0xffffffffffffffd8]
         // 00415bf4: lea edx, ss:[ebp+0xfffffffffffffff8]
         // 00415bf7: mov eax, esi
         // 00415bf9: shl eax, b1 0x2
         // 00415bfc: push 0x2
         // 00415bfe: sub edx, eax
         // 00415c00: xor ebx, ebx
         // 00415c02: pop ecx
      [-]3bce7c08
         // 00415c03: cmp ecx, esi
         // 00415c05: jl 0x415c0f
      [-]8b0289448df0eb04
         // 00415c07: mov eax, ds:[edx]
         // 00415c09: mov ss:[ebp+ecx*0x4], eax
         // 00415c0d: jmp 0x415c13
      [-]895c8df0
         // 00415c0f: mov ss:[ebp+ecx*0x4], ebx
      [-]83ea044979ea
         // 00415c13: sub edx, 0x4
         // 00415c16: dec ecx
         // 00415c17: jns 0x415c03
      [-]e9d8fdffff
         // 00415c19: jmp 0x4159f6
      [-]0f8ca2000000
         // 00415c24: jl 0x415ccc
      [-]8d7df033c0ababab8bc1814df0????????9983e21f03c2c1f8058945cc81e1????????7905
         // 00415c30: lea edi, ss:[ebp+0xfffffffffffffff0]
         // 00415c33: xor eax, eax
         // 00415c35: stosdd 
         // 00415c36: stosdd 
         // 00415c37: stosdd 
         // 00415c38: mov eax, ecx
         // 00415c3a: or ss:[ebp+0xfffffffffffffff0], 0xffffffff80000000
         // 00415c41: cdq 
         // 00415c42: and edx, 0x1f
         // 00415c45: add eax, edx
         // 00415c47: sar eax, b1 0x5
         // 00415c4a: mov ss:[ebp+0xffffffffffffffcc], eax
         // 00415c4d: and ecx, 0xffffffff8000001f
         // 00415c53: jns 0x415c5a
      [-]4983c9e041
         // 00415c55: dec ecx
         // 00415c56: or ecx, 0xffffffffffffffe0
         // 00415c59: inc ecx
      [-]83cfff894dc86a20d3e7582bc1895de0f7d78945d8
         // 00415c5a: or edi, 0xffffffffffffffff
         // 00415c5d: mov ss:[ebp+0xffffffffffffffc8], ecx
         // 00415c60: push 0x20
         // 00415c62: shl edi, b1 cl
         // 00415c64: pop eax
         // 00415c65: sub eax, ecx
         // 00415c67: mov ss:[ebp+0xffffffffffffffe0], ebx
         // 00415c6a: not edi
         // 00415c6c: mov ss:[ebp+0xffffffffffffffd8], eax
      [-]8b549df08bc2d3ea23c70b55e08b4dd8d3e08b4dc889549df0438945e03bde7cdf
         // 00415c6f: mov edx, ss:[ebp+ebx*0x4]
         // 00415c73: mov eax, edx
         // 00415c75: shr edx, b1 cl
         // 00415c77: and eax, edi
         // 00415c79: or edx, ss:[ebp+0xffffffffffffffe0]
         // 00415c7c: mov ecx, ss:[ebp+0xffffffffffffffd8]
         // 00415c7f: shl eax, b1 cl
         // 00415c81: mov ecx, ss:[ebp+0xffffffffffffffc8]
         // 00415c84: mov ss:[ebp+ebx*0x4], edx
         // 00415c88: inc ebx
         // 00415c89: mov ss:[ebp+0xffffffffffffffe0], eax
         // 00415c8c: cmp ebx, esi
         // 00415c8e: jl 0x415c6f
      [-]8b75cc8d55f88bc6c1e0026a022bd033db59
         // 00415c90: mov esi, ss:[ebp+0xffffffffffffffcc]
         // 00415c93: lea edx, ss:[ebp+0xfffffffffffffff8]
         // 00415c96: mov eax, esi
         // 00415c98: shl eax, b1 0x2
         // 00415c9b: push 0x2
         // 00415c9d: sub edx, eax
         // 00415c9f: xor ebx, ebx
         // 00415ca1: pop ecx
      [-]3bce7c08
         // 00415ca2: cmp ecx, esi
         // 00415ca4: jl 0x415cae
      [-]8b0289448df0eb04
         // 00415ca6: mov eax, ds:[edx]
         // 00415ca8: mov ss:[ebp+ecx*0x4], eax
         // 00415cac: jmp 0x415cb2
      [-]895c8df0
         // 00415cae: mov ss:[ebp+ecx*0x4], ebx
      [-]83ea044979ea
         // 00415cb2: sub edx, 0x4
         // 00415cb5: dec ecx
         // 00415cb6: jns 0x415ca2
      [-]33db0335??
         // 00415cbe: xor ebx, ebx
         // 00415cc0: add esi, ds:[0x424344]
      [-]43e995000000
         // 00415cc6: inc ebx
         // 00415cc7: jmp 0x415d61
      [-]8165????????7f03f18b0d??
         // 00415cd2: and ss:[ebp+0xfffffffffffffff0], 0x7fffffff
         // 00415cd9: add esi, ecx
         // 00415cdb: mov ecx, ds:[0x424350]
      [-]8bc19983e21f8975c803c2c1f8058945d881e1????????7905
         // 00415ce1: mov eax, ecx
         // 00415ce3: cdq 
         // 00415ce4: and edx, 0x1f
         // 00415ce7: mov ss:[ebp+0xffffffffffffffc8], esi
         // 00415cea: add eax, edx
         // 00415cec: sar eax, b1 0x5
         // 00415cef: mov ss:[ebp+0xffffffffffffffd8], eax
         // 00415cf2: and ecx, 0xffffffff8000001f
         // 00415cf8: jns 0x415cff
      [-]4983c9e041
         // 00415cfa: dec ecx
         // 00415cfb: or ecx, 0xffffffffffffffe0
         // 00415cfe: inc ecx
      [-]6a20895de08bf3d3e78bd9582bc3894ddcf7d78945dc
         // 00415cff: push 0x20
         // 00415d01: mov ss:[ebp+0xffffffffffffffe0], ebx
         // 00415d04: mov esi, ebx
         // 00415d06: shl edi, b1 cl
         // 00415d08: mov ebx, ecx
         // 00415d0a: pop eax
         // 00415d0b: sub eax, ebx
         // 00415d0d: mov ss:[ebp+0xffffffffffffffdc], ecx
         // 00415d10: not edi
         // 00415d12: mov ss:[ebp+0xffffffffffffffdc], eax
      [-]8b54b5f08bcb8bc2d3ea0b55e023c78b4ddcd3e08954b5f0468945e083fe037cdf
         // 00415d15: mov edx, ss:[ebp+esi*0x4]
         // 00415d19: mov ecx, ebx
         // 00415d1b: mov eax, edx
         // 00415d1d: shr edx, b1 cl
         // 00415d1f: or edx, ss:[ebp+0xffffffffffffffe0]
         // 00415d22: and eax, edi
         // 00415d24: mov ecx, ss:[ebp+0xffffffffffffffdc]
         // 00415d27: shl eax, b1 cl
         // 00415d29: mov ss:[ebp+esi*0x4], edx
         // 00415d2d: inc esi
         // 00415d2e: mov ss:[ebp+0xffffffffffffffe0], eax
         // 00415d31: cmp esi, 0x3
         // 00415d34: jl 0x415d15
      [-]8b7dd88d55f88b75c88bc7c1e0026a022bd033db59
         // 00415d36: mov edi, ss:[ebp+0xffffffffffffffd8]
         // 00415d39: lea edx, ss:[ebp+0xfffffffffffffff8]
         // 00415d3c: mov esi, ss:[ebp+0xffffffffffffffc8]
         // 00415d3f: mov eax, edi
         // 00415d41: shl eax, b1 0x2
         // 00415d44: push 0x2
         // 00415d46: sub edx, eax
         // 00415d48: xor ebx, ebx
         // 00415d4a: pop ecx
      [-]3bcf7c08
         // 00415d4b: cmp ecx, edi
         // 00415d4d: jl 0x415d57
      [-]8b0289448df0eb04
         // 00415d4f: mov eax, ds:[edx]
         // 00415d51: mov ss:[ebp+ecx*0x4], eax
         // 00415d55: jmp 0x415d5b
      [-]895c8df0
         // 00415d57: mov ss:[ebp+ecx*0x4], ebx
      [-]83ea044979ea
         // 00415d5b: sub edx, 0x4
         // 00415d5e: dec ecx
         // 00415d5f: jns 0x415d4b
      [-]6a1f582b05??
         // 00415d64: push 0x1f
         // 00415d66: pop eax
         // 00415d67: sub eax, ds:[0x424350]
      [-]8bc88b45bcd3e6f7d81bc025????????0bf0a1??
         // 00415d6d: mov ecx, eax
         // 00415d6f: mov eax, ss:[ebp+0xffffffffffffffbc]
         // 00415d72: shl esi, b1 cl
         // 00415d74: neg eax
         // 00415d76: sbb eax, eax
         // 00415d78: and eax, 0xffffffff80000000
         // 00415d7d: or esi, eax
         // 00415d7f: mov eax, ds:[0x424354]
      [-]0b75f083f840750a
         // 00415d84: or esi, ss:[ebp+0xfffffffffffffff0]
         // 00415d87: cmp eax, 0x40
         // 00415d8a: jnz 0x415d96
      [-]8b45f48977048907eb07
         // 00415d8c: mov eax, ss:[ebp+0xfffffffffffffff4]
         // 00415d8f: mov ds:[edi+0x4], esi
         // 00415d92: mov ds:[edi], eax
         // 00415d94: jmp 0x415d9d
      [-]83f8207502
         // 00415d96: cmp eax, 0x20
         // 00415d99: jnz 0x415d9d
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
         // 00417a41: mov esi, ss:[esp+0x18]
         // 00417a45: push 0x0
         // 00417a47: push esi
         // 00417a48: call 0x418430
      [-]000083c4088bc68b4c240864890d????????595e83c40cc20800
         // 00417a4d: add esp, 0x8
         // 00417a50: mov eax, esi
         // 00417a52: mov ecx, ss:[esp+0x8]
         // 00417a56: mov fs:[0x0], ecx
         // 00417a5d: pop ecx
         // 00417a5e: pop esi
         // 00417a5f: add esp, 0xc
         // 00417a62: retn b2 0x8
      [-]8b7424186a1156e8
         // 00417a65: mov esi, ss:[esp+0x18]
         // 00417a69: push 0x11
         // 00417a6b: push esi
         // 00417a6c: call 0x418430
      [-]000083c4088bc68b4c240864890d????????595e83c40cc20800
         // 00417a71: add esp, 0x8
         // 00417a74: mov eax, esi
         // 00417a76: mov ecx, ss:[esp+0x8]
         // 00417a7a: mov fs:[0x0], ecx
         // 00417a81: pop ecx
         // 00417a82: pop esi
         // 00417a83: add esp, 0xc
         // 00417a86: retn b2 0x8
      [-]8b7424186a1356e8
         // 00417a89: mov esi, ss:[esp+0x18]
         // 00417a8d: push 0x13
         // 00417a8f: push esi
         // 00417a90: call 0x418430
      [-]09000083c4088bc68b4c240864890d????????595e83c40cc20800
         // 00417a95: add esp, 0x8
         // 00417a98: mov eax, esi
         // 00417a9a: mov ecx, ss:[esp+0x8]
         // 00417a9e: mov fs:[0x0], ecx
         // 00417aa5: pop ecx
         // 00417aa6: pop esi
         // 00417aa7: add esp, 0xc
         // 00417aaa: retn b2 0x8
      [-]8b7424186a2656e8
         // 00417aad: mov esi, ss:[esp+0x18]
         // 00417ab1: push 0x26
         // 00417ab3: push esi
         // 00417ab4: call 0x418430
      [-]09000083c4088bc68b4c240864890d????????595e83c40cc20800
         // 00417ab9: add esp, 0x8
         // 00417abc: mov eax, esi
         // 00417abe: mov ecx, ss:[esp+0x8]
         // 00417ac2: mov fs:[0x0], ecx
         // 00417ac9: pop ecx
         // 00417aca: pop esi
         // 00417acb: add esp, 0xc
         // 00417ace: retn b2 0x8
      [-]8b7424186a2956e8
         // 00417ad1: mov esi, ss:[esp+0x18]
         // 00417ad5: push 0x29
         // 00417ad7: push esi
         // 00417ad8: call 0x418430
      [-]09000083c4088bc68b4c240864890d????????595e83c40cc20800
         // 00417add: add esp, 0x8
         // 00417ae0: mov eax, esi
         // 00417ae2: mov ecx, ss:[esp+0x8]
         // 00417ae6: mov fs:[0x0], ecx
         // 00417aed: pop ecx
         // 00417aee: pop esi
         // 00417aef: add esp, 0xc
         // 00417af2: retn b2 0x8
      [-]8b7424186a1c56e8
         // 00417af5: mov esi, ss:[esp+0x18]
         // 00417af9: push 0x1c
         // 00417afb: push esi
         // 00417afc: call 0x418430
      [-]09000083c4088bc68b4c240864890d????????595e83c40cc20800
         // 00417b01: add esp, 0x8
         // 00417b04: mov eax, esi
         // 00417b06: mov ecx, ss:[esp+0x8]
         // 00417b0a: mov fs:[0x0], ecx
         // 00417b11: pop ecx
         // 00417b12: pop esi
         // 00417b13: add esp, 0xc
         // 00417b16: retn b2 0x8
      [-]8b7424186a0256e8
         // 00417b19: mov esi, ss:[esp+0x18]
         // 00417b1d: push 0x2
         // 00417b1f: push esi
         // 00417b20: call 0x418430
      [-]09000083c4088bc68b4c240864890d????????595e83c40cc20800
         // 00417b25: add esp, 0x8
         // 00417b28: mov eax, esi
         // 00417b2a: mov ecx, ss:[esp+0x8]
         // 00417b2e: mov fs:[0x0], ecx
         // 00417b35: pop ecx
         // 00417b36: pop esi
         // 00417b37: add esp, 0xc
         // 00417b3a: retn b2 0x8
      [-]8b7424186a2856e8
         // 00417b3d: mov esi, ss:[esp+0x18]
         // 00417b41: push 0x28
         // 00417b43: push esi
         // 00417b44: call 0x418430
      [-]000083c4088bc68b4c240864890d????????595e83c40cc20800
         // 00417b49: add esp, 0x8
         // 00417b4c: mov eax, esi
         // 00417b4e: mov ecx, ss:[esp+0x8]
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
         // 00417b85: mov esi, ss:[esp+0x18]
         // 00417b89: push 0x27
         // 00417b8b: push esi
         // 00417b8c: call 0x418430
      [-]08000083c4088bc68b4c240864890d????????595e83c40cc20800
         // 00417b91: add esp, 0x8
         // 00417b94: mov eax, esi
         // 00417b96: mov ecx, ss:[esp+0x8]
         // 00417b9a: mov fs:[0x0], ecx
         // 00417ba1: pop ecx
         // 00417ba2: pop esi
         // 00417ba3: add esp, 0xc
         // 00417ba6: retn b2 0x8
      [-]8b7424186a0c56e8
         // 00417ba9: mov esi, ss:[esp+0x18]
         // 00417bad: push 0xc
         // 00417baf: push esi
         // 00417bb0: call 0x418430
      [-]08000083c4088bc68b4c240864890d????????595e83c40cc20800
         // 00417bb5: add esp, 0x8
         // 00417bb8: mov eax, esi
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
      [-]08000083c4088bc68b4c240864890d????????595e83c40cc20800
         // 00417bd9: add esp, 0x8
         // 00417bdc: mov eax, esi
         // 00417bde: mov ecx, ss:[esp+0x8]
         // 00417be2: mov fs:[0x0], ecx
         // 00417be9: pop ecx
         // 00417bea: pop esi
         // 00417beb: add esp, 0xc
         // 00417bee: retn b2 0x8
      [-]8b7424186a1256e8
         // 00417bf1: mov esi, ss:[esp+0x18]
         // 00417bf5: push 0x12
         // 00417bf7: push esi
         // 00417bf8: call 0x418430
      [-]08000083c4088bc68b4c240864890d????????595e83c40cc20800
         // 00417bfd: add esp, 0x8
         // 00417c00: mov eax, esi
         // 00417c02: mov ecx, ss:[esp+0x8]
         // 00417c06: mov fs:[0x0], ecx
         // 00417c0d: pop ecx
         // 00417c0e: pop esi
         // 00417c0f: add esp, 0xc
         // 00417c12: retn b2 0x8
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
         // 00417c57: mov ds:[0x425b68], ??_7generic_error_category@?A0x846d1564@system@boost@@6B@
      [-]feff83c404
         // 00417c66: add esp, 0x4
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
         // 00417cc6: mov esi, ss:[esp+0x18]
         // 00417cca: push 0x5
         // 00417ccc: push esi
         // 00417ccd: call 0x418430
      [-]07000083c4088bc68b4c240864890d????????595e83c40cc20800
         // 00417cd2: add esp, 0x8
         // 00417cd5: mov eax, esi
         // 00417cd7: mov ecx, ss:[esp+0x8]
         // 00417cdb: mov fs:[0x0], ecx
         // 00417ce2: pop ecx
         // 00417ce3: pop esi
         // 00417ce4: add esp, 0xc
         // 00417ce7: retn b2 0x8
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
         // 00417d4f: mov esi, ss:[esp+0x18]
         // 00417d53: push 0x4
         // 00417d55: push esi
         // 00417d56: call 0x418430
      [-]000083c4088bc68b4c240864890d????????595e83c40cc20800
         // 00417d5b: add esp, 0x8
         // 00417d5e: mov eax, esi
         // 00417d60: mov ecx, ss:[esp+0x8]
         // 00417d64: mov fs:[0x0], ecx
         // 00417d6b: pop ecx
         // 00417d6c: pop esi
         // 00417d6d: add esp, 0xc
         // 00417d70: retn b2 0x8
      [-]8d86????????83f8380f87ec030000
         // 00417d73: lea eax, ds:[esi+0xffffffffffffd8e7]
         // 00417d79: cmp eax, 0x38
         // 00417d7c: ja def_417A3A
      [-]4100ff2485
         // 004193e9: jmp ds:[jpt_4193E9+eax*0x4]
      [-]8b7424186a0d56e8
         // 00417d90: mov esi, ss:[esp+0x18]
         // 00417d94: push 0xd
         // 00417d96: push esi
         // 00417d97: call 0x418430
      [-]06000083c4088bc68b4c240864890d????????595e83c40cc20800
         // 00417d9c: add esp, 0x8
         // 00417d9f: mov eax, esi
         // 00417da1: mov ecx, ss:[esp+0x8]
         // 00417da5: mov fs:[0x0], ecx
         // 00417dac: pop ecx
         // 00417dad: pop esi
         // 00417dae: add esp, 0xc
         // 00417db1: retn b2 0x8
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
      [-]06000083c4088bc68b4c240864890d????????595e83c40cc20800
         // 00417de4: add esp, 0x8
         // 00417de7: mov eax, esi
         // 00417de9: mov ecx, ss:[esp+0x8]
         // 00417ded: mov fs:[0x0], ecx
         // 00417df4: pop ecx
         // 00417df5: pop esi
         // 00417df6: add esp, 0xc
         // 00417df9: retn b2 0x8
      [-]8b7424186a6656e8
         // 00417dfc: mov esi, ss:[esp+0x18]
         // 00417e00: push 0x66
         // 00417e02: push esi
         // 00417e03: call 0x418430
      [-]06000083c4088bc68b4c240864890d????????595e83c40cc20800
         // 00417e08: add esp, 0x8
         // 00417e0b: mov eax, esi
         // 00417e0d: mov ecx, ss:[esp+0x8]
         // 00417e11: mov fs:[0x0], ecx
         // 00417e18: pop ecx
         // 00417e19: pop esi
         // 00417e1a: add esp, 0xc
         // 00417e1d: retn b2 0x8
      [-]8b7424186a6756e8
         // 00417e20: mov esi, ss:[esp+0x18]
         // 00417e24: push 0x67
         // 00417e26: push esi
         // 00417e27: call 0x418430
      [-]06000083c4088bc68b4c240864890d????????595e83c40cc20800
         // 00417e2c: add esp, 0x8
         // 00417e2f: mov eax, esi
         // 00417e31: mov ecx, ss:[esp+0x8]
         // 00417e35: mov fs:[0x0], ecx
         // 00417e3c: pop ecx
         // 00417e3d: pop esi
         // 00417e3e: add esp, 0xc
         // 00417e41: retn b2 0x8
      [-]8b7424186a0956e8
         // 00417e44: mov esi, ss:[esp+0x18]
         // 00417e48: push 0x9
         // 00417e4a: push esi
         // 00417e4b: call 0x418430
      [-]000083c4088bc68b4c240864890d????????595e83c40cc20800
         // 00417e50: add esp, 0x8
         // 00417e53: mov eax, esi
         // 00417e55: mov ecx, ss:[esp+0x8]
         // 00417e59: mov fs:[0x0], ecx
         // 00417e60: pop ecx
         // 00417e61: pop esi
         // 00417e62: add esp, 0xc
         // 00417e65: retn b2 0x8
      [-]8b7424186a6a56e8
         // 00417e68: mov esi, ss:[esp+0x18]
         // 00417e6c: push 0x6a
         // 00417e6e: push esi
         // 00417e6f: call 0x418430
      [-]000083c4088bc68b4c240864890d????????595e83c40cc20800
         // 00417e74: add esp, 0x8
         // 00417e77: mov eax, esi
         // 00417e79: mov ecx, ss:[esp+0x8]
         // 00417e7d: mov fs:[0x0], ecx
         // 00417e84: pop ecx
         // 00417e85: pop esi
         // 00417e86: add esp, 0xc
         // 00417e89: retn b2 0x8
      [-]8b7424186a6b56e8
         // 00417e8c: mov esi, ss:[esp+0x18]
         // 00417e90: push 0x6b
         // 00417e92: push esi
         // 00417e93: call 0x418430
      [-]05000083c4088bc68b4c240864890d????????595e83c40cc20800
         // 00417e98: add esp, 0x8
         // 00417e9b: mov eax, esi
         // 00417e9d: mov ecx, ss:[esp+0x8]
         // 00417ea1: mov fs:[0x0], ecx
         // 00417ea8: pop ecx
         // 00417ea9: pop esi
         // 00417eaa: add esp, 0xc
         // 00417ead: retn b2 0x8
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
         // 00417ed4: mov esi, ss:[esp+0x18]
         // 00417ed8: push 0x6d
         // 00417eda: push esi
         // 00417edb: call 0x418430
      [-]05000083c4088bc68b4c240864890d????????595e83
         // 00417ee0: add esp, 0x8
         // 00417ee3: mov eax, esi
         // 00417ee5: mov ecx, ss:[esp+0x8]
         // 00417ee9: mov fs:[0x0], ecx
         // 00417ef0: pop ecx
         // 00417ef1: pop esi
         // 00417ef2: add esp, 0xc
         // 00417ef5: retn b2 0x8

  }
  condition:
    all of them
}
