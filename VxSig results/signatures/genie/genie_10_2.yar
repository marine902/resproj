rule genie_10_2 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         e903000000
         // 00403d2c: jmp @System@@Pow10$qqrv
      [-]85c07c4d
         // 00403d37: test eax, eax
         // 00403d39: jl 0x403d88
      [-]0f849a000000
         // 00403d3b: jz 0x403ddb
      [-]3d????????0f8d81000000
         // 00403d41: cmp eax, 0x1400
         // 00403d46: jge 0x403dcd
      [-]83e21f8d1492dbac53
         // 00403262: and edx, 0x1f
         // 00403265: lea edx, ds:[edx+edx*0x4]
         // 00403268: fld b10 ds:[ebx+edx*0x2]
      [-]4000dec9c1e8057479
         // 0040326f: fmulp b8 st(1), b10 st(0)
         // 00403271: shr eax, b1 0x5
         // 00403274: jz 0x4032ef
      [-]89c283e20f740c
         // 00403d62: mov edx, eax
         // 00403d64: and edx, 0xf
         // 00403d67: jz 0x403d75
      [-]8d1492dbac53
         // 00404b21: lea edx, ds:[edx+edx*0x4]
         // 00404b24: fld b10 ds:[ebx+edx*0x2]
      [-]4000dec9
         // 00404b2b: fmulp b8 st(1), b10 st(0)
      [-]c1e8047461
         // 00403d75: shr eax, b1 0x4
         // 00403d78: jz 0x403ddb
      [-]8d0480dbac43
         // 00404b32: lea eax, ds:[eax+eax*0x4]
         // 00404b35: fld b10 ds:[ebx+eax*0x2]
      [-]4000dec9eb53
         // 00404b3c: fmulp b8 st(1), b10 st(0)
         // 00404b3e: jmp 0x404b93
      [-]f7d83d????????7d46
         // 00403d88: neg eax
         // 00403d8a: cmp eax, 0x1400
         // 00403d8f: jge 0x403dd7
      [-]83e21f8d1492dbac53
         // 004032a7: and edx, 0x1f
         // 004032aa: lea edx, ds:[edx+edx*0x4]
         // 004032ad: fld b10 ds:[ebx+edx*0x2]
      [-]4000def9c1e8057434
         // 004032b4: fdivp b8 st(1), b10 st(0)
         // 004032b6: shr eax, b1 0x5
         // 004032b9: jz 0x4032ef
      [-]83e20f740c
         // 00403da9: and edx, 0xf
         // 00403dac: jz 0x403dba
      [-]8d1492dbac53
         // 00404b66: lea edx, ds:[edx+edx*0x4]
         // 00404b69: fld b10 ds:[ebx+edx*0x2]
      [-]4000def9
         // 00404b70: fdivp b8 st(1), b10 st(0)
      [-]c1e804741c
         // 00403dba: shr eax, b1 0x4
         // 00403dbd: jz 0x403ddb
      [-]8d0480dbac43
         // 00404b77: lea eax, ds:[eax+eax*0x4]
         // 00404b7a: fld b10 ds:[ebx+eax*0x2]
      [-]4000def9eb0e
         // 00404b81: fdivp b8 st(1), b10 st(0)
         // 00404b83: jmp 0x404b93
      [-]ddd8dbab
         // 00404b85: fstp b10 st(0)
         // 00404b87: fld b10 ds:[ebx+0x404b95]
      [-]4000eb04
         // 00404b8d: jmp 0x404b93
      [-]ddd8d9ee
         // 00403dd7: fstp b10 st(0)
         // 00403dd9: fldz 
      [-]e8a6000000
         // 00404199: call @System@TObject@CleanupInstance$qqrv
      [-]ffff5bc3
         // 004041a5: pop ebx
         // 004041a6: retn 
      [-]e9e9ffffff
         // 0040679a: jmp 0x406788
      [-]83f9000f84
         // 00405e24: cmp ecx, 0x0
         // 00405e27: jz 0x405f0d
      [-]50535657
         // 00407b35: push eax
         // 00407b36: push ebx
         // 00407b37: push esi
         // 00407b38: push edi
      [-]31d28a068a56013c0a74
         // 00407b3f: xor edx, edx
         // 00407b41: mov b1 al, b1 ds:[esi]
         // 00407b43: mov b1 dl, b1 ds:[esi+0x1]
         // 00407b46: cmp b1 al, b1 0xa
         // 00407b48: jz 0x407b77
      [-]3c0f0f84
         // 00405e52: cmp b1 al, b1 0xf
         // 00405e54: jz 0x405ede
      [-]3c110f84
         // 00405e5a: cmp b1 al, b1 0x11
         // 00405e5c: jz 0x405eed
      [-]5f5e5b58b002e9
         // 00404fbe: pop edi
         // 00404fbf: pop esi
         // 00404fc0: pop ebx
         // 00404fc1: pop eax
         // 00404fc2: mov b1 al, b1 0x2
         // 00404fc4: jmp 0x402bb8
      [-]5f5e5b58
         // 00405f09: pop edi
         // 00405f0a: pop esi
         // 00405f0b: pop ebx
         // 00405f0c: pop eax
      [-]e8f3ffffff48c3
         // 0040673c: call 0x406734
         // 00406741: dec eax
         // 00406742: retn 
      [-]e8d3ffffffc3
         // 00406aa8: call @System@FindHInstance$qqrpv
         // 00406aad: retn 
      [-]ffffffc3
         // 004078ec: retn 
      [-]5f5e5bc3
         // 0041bbee: pop edi
         // 0041bbef: pop esi
         // 0041bbf0: pop ebx
         // 0041bbf1: retn 
      [-]535657518b
         // 0041cba4: push ebx
         // 0041cba5: push esi
         // 0041cba6: push edi
         // 0041cba7: push ecx
         // 0041cba8: mov edi, ecx
      [-]6a008d44240450575653e8
         // 0041cbae: push 0x0
         // 0041cbb0: lea eax, ss:[esp+0x4]
         // 0041cbb4: push eax
         // 0041cbb5: push edi
         // 0041cbb6: push esi
         // 0041cbb7: push ebx
         // 0041cbb8: call WriteFile_0
      [-]c70424????????
         // 0040b555: mov ss:[esp], 0xffffffffffffffff
      [-]8b04245a5f5e5bc3
         // 0040b55c: mov eax, ss:[esp]
         // 0040b55f: pop edx
         // 0040b560: pop edi
         // 0040b561: pop esi
         // 0040b562: pop ebx
         // 0040b563: retn 
      [-]ac08c07503
         // 0040cb0a: lodsbb 
         // 0040cb0b: or b1 al, b1 al
         // 0040cb0d: jnz 0x40cb12
      [-]83fa127205
         // 0040cbb8: cmp edx, 0x12
         // 0040cbbb: jb 0x40cbc2
      [-]31db807d
         // 0040cbcf: xor ebx, ebx
         // 0040cbd1: cmp b1 ss:[ebp+0x10], b1 0x2
      [-]48b303f6f388e343
         // 0040cbd9: dec eax
         // 0040cbda: mov b1 bl, b1 0x3
         // 0040cbdc: div b1 bl
         // 0040cbde: mov b1 bl, b1 ah
         // 0040cbe0: inc ebx
      [-]31db8a5d
         // 0040cc1a: xor ebx, ebx
         // 0040cc1c: mov b1 bl, b1 ss:[ebp+0xfffffffffffffff3]
      [-]b9????????807d
         // 0040cc1f: mov ecx, 0x3
         // 0040cc24: cmp b1 ss:[ebp+0xffffffffffffffd6], b1 0x0
      [-]b9????????
         // 0040cc2d: mov ecx, 0x40f
      [-]38cb7602
         // 0040cc32: cmp b1 bl, b1 cl
         // 0040cc34: jbe 0x40cc38
      [-]00eb8d9c9b
         // 004092ec: add b1 bl, b1 ch
         // 004092ee: lea ebx, ds:[ebx+ebx*0x4]
      [-]b9????????
         // 004092f8: mov ecx, 0x5
      [-]8a033c4074
         // 0040cc49: mov b1 al, b1 ds:[ebx]
         // 0040cc4b: cmp b1 al, b1 0x40
         // 0040cc4d: jz 0x40cc6d
      [-]51533c2474
         // 0040cc4f: push ecx
         // 0040cc50: push ebx
         // 0040cc51: cmp b1 al, b1 0x24
         // 0040cc53: jz 0x40cc5c
      [-]e80d000000eb05
         // 0040cc5c: call 0x40cc6e
         // 0040cc61: jmp 0x40cc68
      [-]5b5943e2
         // 0040cc68: pop ebx
         // 0040cc69: pop ecx
         // 0040cc6a: inc ebx
         // 0040cc6b: loop 0x40cc49
      [-]568b75f4
         // 0041e032: push esi
         // 0041e033: mov esi, ss:[ebp+0xfffffffffffffff4]
      [-]242a4040402a2440404024202a40402a2024404028242a29402d242a4040242d2a4040242a2d????????2429402d????????2a2d2440402a242d40402d????????2d????????2a20242d4024202a2d4024202d2a402a2d????????24202a29282a202429
         // 0040cc7d: and b1 al, b1 0x2a
         // 0040cc7f: inc eax
         // 0040cc80: inc eax
         // 0040cc81: inc eax
         // 0040cc82: sub b1 ah, b1 ds:[eax+eax*0x2]
         // 0040cc85: inc eax
         // 0040cc86: inc eax
         // 0040cc87: and b1 al, b1 0x20
         // 0040cc89: sub b1 al, b1 ds:[eax+0x40]
         // 0040cc8c: sub b1 ah, b1 ds:[eax]
         // 0040cc8e: and b1 al, b1 0x40
         // 0040cc90: inc eax
         // 0040cc91: sub b1 ds:[edx+ebp], b1 ah
         // 0040cc94: sub ds:[eax+0x2d], eax
         // 0040cc97: and b1 al, b1 0x2a
         // 0040cc99: inc eax
         // 0040cc9a: inc eax
         // 0040cc9b: and b1 al, b1 0x2d
         // 0040cc9d: sub b1 al, b1 ds:[eax+0x40]
         // 0040cca0: and b1 al, b1 0x2a
         // 0040cca2: sub eax, 0x2a284040
         // 0040cca7: and b1 al, b1 0x29
         // 0040cca9: inc eax
         // 0040ccaa: sub eax, 0x4040242a
         // 0040ccaf: sub b1 ch, b1 ds:[0x2a404024]
         // 0040ccb5: and b1 al, b1 0x2d
         // 0040ccb7: inc eax
         // 0040ccb8: inc eax
         // 0040ccb9: sub eax, 0x4024202a
         // 0040ccbe: sub eax, 0x402a2024
         // 0040ccc3: sub b1 ah, b1 ds:[eax]
         // 0040ccc5: and b1 al, b1 0x2d
         // 0040ccc7: inc eax
         // 0040ccc8: and b1 al, b1 0x20
         // 0040ccca: sub b1 ch, b1 ds:[0x2d202440]
         // 0040ccd0: sub b1 al, b1 ds:[eax+0x2a]
         // 0040ccd3: sub eax, 0x28402420
         // 0040ccd8: and b1 al, b1 0x20
         // 0040ccda: sub b1 ch, b1 ds:[ecx]
         // 0040ccdc: sub b1 ds:[edx], b1 ch
         // 0040ccde: and b1 ds:[ecx+ebp], b1 ah
      [-]8be55dc2
         // 0040cce1: mov esp, ebp
         // 0040cce3: pop ebp
         // 0040cce4: retn b2 0xc
      [-]64ff3064892083
         // 00409f7f: push fs:[eax]
         // 00409f82: mov fs:[eax], esp
         // 00409f85: cmp ds:[esi], 0x0
      [-]8b450883b8??
         // 00409f8e: mov eax, ss:[ebp+0x8]
         // 00409f91: cmp ds:[eax+0xfffffffffffffef8], 0x2
      [-]8b4508ff80??
         // 0040e2ab: mov eax, ss:[ebp+0x8]
         // 0040e2ae: inc ds:[eax+0xfffffffffffffef8]
      [-]83c0de83f8380f87
         // 0040a02e: add eax, 0xffffffffffffffde
         // 0040a031: cmp eax, 0x38
         // 0040a034: ja def_40A040
      [-]fbffff5955e8
         // 0040a0c6: pop ecx
         // 0040a0c7: push ebp
         // 0040a0c8: call 0x409c74
      [-]fbffff59837d
         // 0040a0cd: pop ecx
         // 0040a0ce: cmp ss:[ebp+0xfffffffffffffff4], 0x2
      [-]8b4508500fb745
         // 0040a0d4: mov eax, ss:[ebp+0x8]
         // 0040a0d7: push eax
         // 0040a0d8: movzx eax, b2 ss:[ebp+0xfffffffffffffff2]
      [-]b9????????33d2f7f18bc2ba????????e8
         // 0040a0dc: mov ecx, 0x64
         // 0040a0e1: xor edx, edx
         // 0040a0e3: div ecx
         // 0040a0e5: mov eax, edx
         // 0040a0e7: mov edx, 0x2
         // 0040a0ec: call 0x409bf8
      [-]ffff59e9
         // 0040a0f1: pop ecx
         // 0040a0f2: jmp 0x40a6d7
      [-]8b4508500fb745
         // 0040a0f7: mov eax, ss:[ebp+0x8]
         // 0040a0fa: push eax
         // 0040a0fb: movzx eax, b2 ss:[ebp+0xfffffffffffffff2]
      [-]ba????????e8
         // 0040a0ff: mov edx, 0x4
         // 0040a104: call 0x409bf8
      [-]faffff59e9
         // 0040a109: pop ecx
         // 0040a10a: jmp 0x40a6d7
      [-]ffff5955e8
         // 0040a115: pop ecx
         // 0040a116: push ebp
         // 0040a117: call 0x409c74
      [-]fbffff598b450850558d55
         // 0040a11c: pop ecx
         // 0040a11d: mov eax, ss:[ebp+0x8]
         // 0040a120: push eax
         // 0040a121: push ebp
         // 0040a122: lea edx, ss:[ebp+0xffffffffffffffd8]
      [-]fbffff598b45
         // 0040a12d: pop ecx
         // 0040a12e: mov eax, ss:[ebp+0xffffffffffffffd8]
      [-]faffff59e9
         // 0040a136: pop ecx
         // 0040a137: jmp 0x40a6d7
      [-]ffff5955e8
         // 0040a142: pop ecx
         // 0040a143: push ebp
         // 0040a144: call 0x409c74
      [-]ffff598b450850558d55
         // 0040a149: pop ecx
         // 0040a14a: mov eax, ss:[ebp+0x8]
         // 0040a14d: push eax
         // 0040a14e: push ebp
         // 0040a14f: lea edx, ss:[ebp+0xffffffffffffffd4]
      [-]ffff598b45
         // 0040a15a: pop ecx
         // 0040a15b: mov eax, ss:[ebp+0xffffffffffffffd4]
      [-]faffff59e9
         // 0040a163: pop ecx
         // 0040a164: jmp 0x40a6d7
      [-]faffff5955e8
         // 0040a16f: pop ecx
         // 0040a170: push ebp
         // 0040a171: call 0x409c74
      [-]ffff598b45
         // 0040a176: pop ecx
         // 0040a177: mov eax, ss:[ebp+0xfffffffffffffff4]
      [-]4883e8027204
         // 0040a17a: dec eax
         // 0040a17b: sub eax, 0x2
         // 0040a17e: jb 0x40a184
      [-]8b4508500fb745
         // 0040a1b4: mov eax, ss:[ebp+0x8]
         // 0040a1b7: push eax
         // 0040a1b8: movzx eax, b2 ss:[ebp+0xfffffffffffffff0]
      [-]ffff59e9
         // 0040a1c8: pop ecx
         // 0040a1c9: jmp 0x40a6d7
      [-]faffff598b45
         // 0040a1d4: pop ecx
         // 0040a1d5: mov eax, ss:[ebp+0xfffffffffffffff4]
      [-]4883e80272
         // 0040a1d8: dec eax
         // 0040a1d9: sub eax, 0x2
         // 0040a1dc: jb 0x40a1e8
      [-]8b450850
         // 0040a267: mov eax, ss:[ebp+0x8]
         // 0040a26a: push eax
      [-]fcffff59e9
         // 0040a275: pop ecx
         // 0040a276: jmp 0x40a6d7
      [-]f9ffff5955e8
         // 0040e58d: pop ecx
         // 0040e58e: push ebp
         // 0040e58f: call 0x40dfc0
      [-]ffff59c645
         // 0040e594: pop ecx
         // 0040e595: mov b1 ss:[ebp+0xffffffffffffffe1], b1 0x0
      [-]83e82274
         // 0040e5c5: sub eax, 0x22
         // 0040e5c8: jz 0x40e62d
      [-]83e80574
         // 0040e5ca: sub eax, 0x5
         // 0040e5cd: jz 0x40e62d
      [-]83e81a740e
         // 0040e5cf: sub eax, 0x1a
         // 0040e5d2: jz 0x40e5e2
      [-]83e8617407
         // 0040e5d6: sub eax, 0x61
         // 0040e5d9: jz 0x40e5e2
      [-]83e80774
         // 0041f285: sub eax, 0x7
         // 0041f288: jz 0x41f2ed
      [-]b9????????8b
         // 0040e5ed: mov ecx, 0x5
         // 0040e5f2: mov eax, esi
      [-]ffff85c074
         // 0040e5f9: test eax, eax
         // 0040e5fb: jz 0x40e627
      [-]b9????????8b
         // 0040e602: mov ecx, 0x3
         // 0040e607: mov eax, esi
      [-]ffff85c074
         // 0040e60e: test eax, eax
         // 0040e610: jz 0x40e627
      [-]b9????????8b
         // 0040e617: mov ecx, 0x4
         // 0040e61c: mov eax, esi
      [-]ffff85c075
         // 0040e623: test eax, eax
         // 0040e625: jnz 0x40e640
      [-]34018845
         // 0040e630: xor b1 al, b1 0x1
         // 0040e632: mov b1 ss:[ebp+0xffffffffffffffe1], b1 al
      [-]ffff59e9
         // 0040a388: pop ecx
         // 0040a389: jmp 0x40a6d7
      [-]f8ffff5955e8
         // 0040a394: pop ecx
         // 0040a395: push ebp
         // 0040a396: call 0x409cac
      [-]ffff59837d
         // 0040a39b: pop ecx
         // 0040a39c: cmp ss:[ebp+0xfffffffffffffff4], 0x2
      [-]8b4508500fb745
         // 0040a3a9: mov eax, ss:[ebp+0x8]
         // 0040a3ac: push eax
         // 0040a3ad: movzx eax, b2 ss:[ebp+0xffffffffffffffe8]
      [-]ffff59e9
         // 0040a3b9: pop ecx
         // 0040a3ba: jmp 0x40a6d7
      [-]f8ffff5955e8
         // 0040a3c5: pop ecx
         // 0040a3c6: push ebp
         // 0040a3c7: call 0x409cac
      [-]ffff59837d
         // 0040a3cc: pop ecx
         // 0040a3cd: cmp ss:[ebp+0xfffffffffffffff4], 0x2
      [-]8b4508500fb745
         // 0040a3da: mov eax, ss:[ebp+0x8]
         // 0040a3dd: push eax
         // 0040a3de: movzx eax, b2 ss:[ebp+0xffffffffffffffe6]
      [-]ffff59e9
         // 0040a3ea: pop ecx
         // 0040a3eb: jmp 0x40a6d7
      [-]ffff59837d
         // 0040a3f6: pop ecx
         // 0040a3f7: cmp ss:[ebp+0xfffffffffffffff4], 0x1
      [-]8b450850
         // 0040a3fd: mov eax, ss:[ebp+0x8]
         // 0040a400: push eax
      [-]fbffff59e9
         // 0040a40b: pop ecx
         // 0040a40c: jmp 0x40a6d7
      [-]8b450850
         // 0040a411: mov eax, ss:[ebp+0x8]
         // 0040a414: push eax
      [-]ffff59e9
         // 0040a41f: pop ecx
         // 0040a420: jmp 0x40a6d7
      [-]ffff5955e8
         // 0040a42b: pop ecx
         // 0040a42c: push ebp
         // 0040a42d: call 0x409cac
      [-]ffff59837d
         // 0040a432: pop ecx
         // 0040a433: cmp ss:[ebp+0xfffffffffffffff4], 0x3
      [-]8b4508500fb745
         // 0040a440: mov eax, ss:[ebp+0x8]
         // 0040a443: push eax
         // 0040a444: movzx eax, b2 ss:[ebp+0xffffffffffffffe4]
      [-]f7ffff59e9
         // 0040a450: pop ecx
         // 0040a451: jmp 0x40a6d7
      [-]ffff598b
         // 0040e74f: pop ecx
         // 0040e750: mov esi, ss:[ebp+0xfffffffffffffffc]
      [-]b9????????
         // 0040e759: mov ecx, 0x5
      [-]ffff85c075
         // 0040e765: test eax, eax
         // 0040e767: jnz 0x40e791
      [-]8b450850ba????????8b
         // 0040e773: mov eax, ss:[ebp+0x8]
         // 0040e776: push eax
         // 0040e777: mov edx, 0x2
         // 0040e77c: mov eax, esi
      [-]ffff5983
         // 0040e783: pop ecx
         // 0040e784: add ss:[ebp+0xfffffffffffffffc], 0x4
      [-]b9????????8b
         // 0040e796: mov ecx, 0x3
         // 0040e79b: mov eax, esi
      [-]ffff85c075
         // 0040e7a2: test eax, eax
         // 0040e7a4: jnz 0x40e7ce
      [-]8b450850ba????????8b
         // 0040e7b0: mov eax, ss:[ebp+0x8]
         // 0040e7b3: push eax
         // 0040e7b4: mov edx, 0x1
         // 0040e7b9: mov eax, esi
      [-]f6ffff5983
         // 0040e7c0: pop ecx
         // 0040e7c1: add ss:[ebp+0xfffffffffffffffc], 0x2
      [-]b9????????8b
         // 0040e7d3: mov ecx, 0x4
         // 0040e7d8: mov eax, esi
      [-]ffff85c075
         // 0040e7df: test eax, eax
         // 0040e7e1: jnz 0x40e817
      [-]8b450850
         // 0040a4fe: mov eax, ss:[ebp+0x8]
         // 0040a501: push eax
      [-]f6ffff59eb
         // 0040a50c: pop ecx
         // 0040a50d: jmp 0x40a51e
      [-]8b450850
         // 0040a50f: mov eax, ss:[ebp+0x8]
         // 0040a512: push eax
      [-]f6ffff59
         // 0040a51d: pop ecx
      [-]b9????????8b
         // 0040e81c: mov ecx, 0x4
         // 0040e821: mov eax, esi
      [-]ffff85c075
         // 0040e828: test eax, eax
         // 0040e82a: jnz 0x40e85e
      [-]ffff598b4508508b4508ff700cff7008e8
         // 0040a546: pop ecx
         // 0040a547: mov eax, ss:[ebp+0x8]
         // 0040a54a: push eax
         // 0040a54b: mov eax, ss:[ebp+0x8]
         // 0040a54e: push ds:[eax+0xc]
         // 0040a551: push ds:[eax+0x8]
         // 0040a554: call 0x409b58
      [-]ffff0fb7c08b
         // 0040a559: movzx eax, b2 ax
         // 0040a55c: mov eax, ds:[0x452718+eax*0x4]
      [-]ffff5983
         // 0040a568: pop ecx
         // 0040a569: add ds:[esi], 0x3
      [-]b9????????8b
         // 0040e863: mov ecx, 0x3
         // 0040e868: mov eax, esi
      [-]ffff85c075
         // 0040e86f: test eax, eax
         // 0040e871: jnz 0x40e8a5
      [-]ffff598b4508508b4508ff700cff7008e8
         // 0040a58d: pop ecx
         // 0040a58e: mov eax, ss:[ebp+0x8]
         // 0040a591: push eax
         // 0040a592: mov eax, ss:[ebp+0x8]
         // 0040a595: push ds:[eax+0xc]
         // 0040a598: push ds:[eax+0x8]
         // 0040a59b: call 0x409b58
      [-]ffff0fb7c08b
         // 0040a5a0: movzx eax, b2 ax
         // 0040a5a3: mov eax, ds:[0x4526fc+eax*0x4]
      [-]ffff5983
         // 0040a5aa: call 0x409bd8
         // 0040a5af: pop ecx
         // 0040a5b0: add ds:[esi], 0x2
      [-]8b4508508d45
         // 0040a5b8: mov eax, ss:[ebp+0x8]
         // 0040a5bb: push eax
         // 0040a5bc: lea eax, ss:[ebp+0xfffffffffffffffb]
      [-]ba????????e8
         // 0040a5bf: mov edx, 0x1
         // 0040a5c4: call 0x409b94
      [-]f5ffff59e9
         // 0040a5c9: pop ecx
         // 0040a5ca: jmp 0x40a6d7
      [-]ffff598b450850
         // 0040a5d5: pop ecx
         // 0040a5d6: mov eax, ss:[ebp+0x8]
         // 0040a5d9: push eax
      [-]f9ffff5955e8
         // 0040a5e4: pop ecx
         // 0040a5e5: push ebp
         // 0040a5e6: call 0x409cac
      [-]f6ffff5966837d
         // 0040a5eb: pop ecx
         // 0040a5ec: cmp b2 ss:[ebp+0xffffffffffffffea], b2 0x0
      [-]8b450850b8
         // 0040a605: mov eax, ss:[ebp+0x8]
         // 0040a608: push eax
         // 0040a609: mov eax, 0x40a734
      [-]ba????????e8
         // 0040a60e: mov edx, 0x1
         // 0040a613: call 0x409b94
      [-]ffff598b450850
         // 0040a618: pop ecx
         // 0040a619: mov eax, ss:[ebp+0x8]
         // 0040a61c: push eax
      [-]ffff59e9
         // 0040a627: pop ecx
         // 0040a628: jmp 0x40a6d7
      [-]8b450850
         // 0040a63a: mov eax, ss:[ebp+0x8]
         // 0040a63d: push eax
      [-]ffff59e9
         // 0040a64d: pop ecx
         // 0040a64e: jmp 0x40a6d7
      [-]8b450850
         // 0040a65c: mov eax, ss:[ebp+0x8]
         // 0040a65f: push eax
      [-]ffff59eb
         // 0040a66f: pop ecx
         // 0040a670: jmp 0x40a6d7
      [-]8b4508508b55
         // 0040e990: mov eax, ss:[ebp+0x8]
         // 0040e993: push eax
         // 0040e994: mov edx, ss:[ebp+0xfffffffffffffffc]
      [-]8b4508508d45
         // 0040a6c5: mov eax, ss:[ebp+0x8]
         // 0040a6c8: push eax
         // 0040a6c9: lea eax, ss:[ebp+0xfffffffffffffffb]
      [-]ba????????e8
         // 0040a6cc: mov edx, 0x1
         // 0040a6d1: call 0x409b94
      [-]8b4508ff88??
         // 0040e9cd: mov eax, ss:[ebp+0x8]
         // 0040e9d0: dec ds:[eax+0xfffffffffffffef8]
      [-]33c05a595964891068
         // 0040a6eb: xor eax, eax
         // 0040a6ed: pop edx
         // 0040a6ee: pop ecx
         // 0040a6ef: pop ecx
         // 0040a6f0: mov fs:[eax], edx
         // 0040a6f3: push 0x40a70d
      [-]ba????????e8
         // 0040a6fb: mov edx, 0x2
         // 0040a700: call 0x404488
      [-]8be55dc3
         // 0040a710: mov esp, ebp
         // 0040a712: pop ebp
         // 0040a713: retn 
      [-]64ff306489208b45088b58fc837b1400750f
         // 0040bcbb: push fs:[eax]
         // 0040bcbe: mov fs:[eax], esp
         // 0040bcc1: mov eax, ss:[ebp+0x8]
         // 0040bcc4: mov ebx, ds:[eax+0xfffffffffffffffc]
         // 0040bcc7: cmp ds:[ebx+0x14], 0x0
         // 0040bccb: jnz 0x40bcdc
      [-]8d55fca1
         // 0040bccd: lea edx, ss:[ebp+0xfffffffffffffffc]
         // 0040bcd0: mov eax, ds:[0x4510cc]
      [-]8d55fca1
         // 0040bcdc: lea edx, ss:[ebp+0xfffffffffffffffc]
         // 0040bcdf: mov eax, ds:[0x450f7c]
      [-]186a1c8d45
         // 00421b85: push 0x1c
         // 00421b87: lea eax, ss:[ebp+0xffffffffffffffe0]
      [-]508b430c50e8
         // 00421b8a: push eax
         // 00421b8b: mov eax, ds:[ebx+0xc]
         // 00421b8e: push eax
         // 00421b8f: call VirtualQuery_0
      [-]68????????8d85
         // 00410201: push 0x105
         // 00410206: lea eax, ss:[ebp+0xfffffffffffffedb]
      [-]85c00f84
         // 00410216: test eax, eax
         // 00410218: jz 0x4102b4
      [-]8b430c8985
         // 0041021e: mov eax, ds:[ebx+0xc]
         // 00410221: mov ss:[ebp+0xfffffffffffffeb8], eax
      [-]ffff058d85
         // 0041022e: lea eax, ss:[ebp+0xfffffffffffffeb0]
      [-]b9????????e8
         // 0041023a: mov ecx, 0x105
         // 0041023f: call 0x4052b0
      [-]ffff8b85
         // 00410255: mov eax, ss:[ebp+0xfffffffffffffeb4]
      [-]8b45fc8985
         // 00410268: mov eax, ss:[ebp+0xfffffffffffffffc]
         // 0041026b: mov ss:[ebp+0xfffffffffffffec8], eax
      [-]506a038d95
         // 0041028b: push eax
         // 0041028c: push 0x3
         // 0041028e: lea edx, ss:[ebp+0xfffffffffffffeac]
      [-]8b430c8985
         // 004102b4: mov eax, ds:[ebx+0xc]
         // 004102b7: mov ss:[ebp+0xfffffffffffffe94], eax
      [-]ffff058b45fc8985
         // 004102c4: mov eax, ss:[ebp+0xfffffffffffffffc]
         // 004102c7: mov ss:[ebp+0xfffffffffffffe9c], eax
      [-]506a028d95
         // 004102e7: push eax
         // 004102e8: push 0x2
         // 004102ea: lea edx, ss:[ebp+0xfffffffffffffe90]
      [-]5a595964891068
         // 00421cb0: pop edx
         // 00421cb1: pop ecx
         // 00421cb2: pop ecx
         // 00421cb3: mov fs:[eax], edx
         // 00421cb6: push 0x421ce6
      [-]8d45fce8
         // 00421cd6: lea eax, ss:[ebp+0xfffffffffffffffc]
         // 00421cd9: call 0x406968
      [-]64ff306489208d55fca1
         // 0040e681: push fs:[eax]
         // 0040e684: mov fs:[eax], esp
         // 0040e687: lea edx, ss:[ebp+0xfffffffffffffffc]
         // 0040e68a: mov eax, ds:[0x450f14]
      [-]8b4dfcb201a1
         // 0040e694: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 0040e697: mov b1 dl, b1 0x1
         // 0040e699: mov eax, ds:[0x40e21c]
      [-]5a595964891068
         // 0040e6aa: pop edx
         // 0040e6ab: pop ecx
         // 0040e6ac: pop ecx
         // 0040e6ad: mov fs:[eax], edx
         // 0040e6b0: push 0x40e6c5
      [-]8d45fce8
         // 0040e6b5: lea eax, ss:[ebp+0xfffffffffffffffc]
         // 0040e6b8: call 0x404464
      [-]83c4e45356
         // 0040e6cb: add esp, 0xffffffffffffffe4
         // 0040e6ce: push ebx
         // 0040e6cf: push esi
      [-]64ff306489208d55ec
         // 0040e6e7: push fs:[eax]
         // 0040e6ea: mov fs:[eax], esp
         // 0040e6ed: lea edx, ss:[ebp+0xffffffffffffffec]
      [-]00008b45ec8945f0c645f4
         // 0040e6f7: mov eax, ss:[ebp+0xffffffffffffffec]
         // 0040e6fa: mov ss:[ebp+0xfffffffffffffff0], eax
         // 0040e6fd: mov b1 ss:[ebp+0xfffffffffffffff4], b1 0xb
      [-]00008b45e88945f8c645fc
         // 0040e70b: mov eax, ss:[ebp+0xffffffffffffffe8]
         // 0040e70e: mov ss:[ebp+0xfffffffffffffff8], eax
         // 0040e711: mov b1 ss:[ebp+0xfffffffffffffffc], b1 0xb
      [-]8d45f0506a018d55e4a1
         // 0040e715: lea eax, ss:[ebp+0xfffffffffffffff0]
         // 0040e718: push eax
         // 0040e719: push 0x1
         // 0040e71b: lea edx, ss:[ebp+0xffffffffffffffe4]
         // 0040e71e: mov eax, ds:[0x450d24]
      [-]8b4de4b201a1
         // 0040e728: mov ecx, ss:[ebp+0xffffffffffffffe4]
         // 0040e72b: mov b1 dl, b1 0x1
         // 0040e72d: mov eax, ds:[0x40e21c]
      [-]5a595964891068
         // 0040e73e: pop edx
         // 0040e73f: pop ecx
         // 0040e740: pop ecx
         // 0040e741: mov fs:[eax], edx
         // 0040e744: push 0x40e75e
      [-]558bec6a00
         // 004132c4: push ebp
         // 004132c5: mov ebp, esp
         // 004132c7: push 0x0
      [-]64ff306489208d55fca1
         // 004132d1: push fs:[eax]
         // 004132d4: mov fs:[eax], esp
         // 004132d7: lea edx, ss:[ebp+0xfffffffffffffffc]
         // 004132da: mov eax, ds:[0xa097a0]
      [-]8b4dfcb201a1
         // 004132e4: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 004132e7: mov b1 dl, b1 0x1
         // 004132e9: mov eax, ds:[0x412cb0]
      [-]5a595964891068
         // 004132fa: pop edx
         // 004132fb: pop ecx
         // 004132fc: pop ecx
         // 004132fd: mov fs:[eax], edx
         // 00413300: push 0x413315
      [-]8d45fce8
         // 00413305: lea eax, ss:[ebp+0xfffffffffffffffc]
         // 00413308: call @System@@LStrClr$qqrpv
      [-]83c4e45356
         // 0041336f: add esp, 0xffffffffffffffe4
         // 00413372: push ebx
         // 00413373: push esi
      [-]64ff306489208d55ec8bc3e8
         // 0041338b: push fs:[eax]
         // 0041338e: mov fs:[eax], esp
         // 00413391: lea edx, ss:[ebp+0xffffffffffffffec]
         // 00413394: mov eax, ebx
         // 00413396: call @Variants@VarTypeAsText$qqrxus
      [-]00008b45ec8945f0c645f4
         // 0041339b: mov eax, ss:[ebp+0xffffffffffffffec]
         // 0041339e: mov ss:[ebp+0xfffffffffffffff0], eax
         // 004133a1: mov b1 ss:[ebp+0xfffffffffffffff4], b1 0xb
      [-]00008b45e88945f8c645fc
         // 004133af: mov eax, ss:[ebp+0xffffffffffffffe8]
         // 004133b2: mov ss:[ebp+0xfffffffffffffff8], eax
         // 004133b5: mov b1 ss:[ebp+0xfffffffffffffffc], b1 0xb
      [-]8d45f0506a018d55e4a1
         // 004133b9: lea eax, ss:[ebp+0xfffffffffffffff0]
         // 004133bc: push eax
         // 004133bd: push 0x1
         // 004133bf: lea edx, ss:[ebp+0xffffffffffffffe4]
         // 004133c2: mov eax, ds:[0xa09a98]
      [-]8b4de4b201a1
         // 004133cc: mov ecx, ss:[ebp+0xffffffffffffffe4]
         // 004133cf: mov b1 dl, b1 0x1
         // 004133d1: mov eax, ds:[0x412d78]
      [-]5a595964891068
         // 004133e2: pop edx
         // 004133e3: pop ecx
         // 004133e4: pop ecx
         // 004133e5: mov fs:[eax], edx
         // 004133e8: push 0x413402
      [-]64ff306489208d55fca1
         // 0040e861: push fs:[eax]
         // 0040e864: mov fs:[eax], esp
         // 0040e867: lea edx, ss:[ebp+0xfffffffffffffffc]
         // 0040e86a: mov eax, ds:[0x450e94]
      [-]8b4dfcb201a1
         // 0040e874: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 0040e877: mov b1 dl, b1 0x1
         // 0040e879: mov eax, ds:[0x40e478]
      [-]5a595964891068
         // 0040e88a: pop edx
         // 0040e88b: pop ecx
         // 0040e88c: pop ecx
         // 0040e88d: mov fs:[eax], edx
         // 0040e890: push 0x40e8a5
      [-]8d45fce8
         // 0040e895: lea eax, ss:[ebp+0xfffffffffffffffc]
         // 0040e898: call 0x404464
      [-]50e8e6ffffff58c3
         // 00413a74: push eax
         // 00413a75: call @Variants@@VarClear$qqrr8TVarData
         // 00413a7a: pop eax
         // 00413a7b: retn 
      [-]6a006a004975f9
         // 004170fc: push 0x0
         // 004170fe: push 0x0
         // 00417100: dec ecx
         // 00417101: jnz 0x4170fc
      [-]0fb7d083fa
         // 0041711a: movzx edx, b2 ax
         // 0041711d: cmp edx, 0x14
      [-]0000740d
         // 0042cdc9: jz 0x42cdd8
      [-]66ba000166b80100e8
         // 0042cdcb: mov b2 dx, b2 0x100
         // 0042cdcf: mov b2 ax, b2 0x1
         // 0042cdd3: call 0x428dcc
      [-]8bc68b15
         // 0040f540: mov eax, esi
         // 0040f542: mov edx, ds:[0x45031c]
      [-]8b43088bd08bc6e8
         // 0040f6d0: mov eax, ds:[ebx+0x8]
         // 0040f6d3: mov edx, eax
         // 0040f6d5: mov eax, esi
         // 0040f6d7: call 0x40f490
      [-]fdffffe9
         // 0040f6dc: jmp 0x40f96e
      [-]8bd06681ea000174
         // 00417368: mov edx, eax
         // 0041736a: sub b2 dx, b2 0x100
         // 0041736f: jz 0x417378
      [-]66ffca7411
         // 00417371: dec b2 dx
         // 00417374: jz 0x417387
      [-]f6c4400f84
         // 004173a0: test b1 ah, b1 0x40
         // 004173a3: jz 0x4175b4
      [-]0fb7c025????????83f8
         // 004173a9: movzx eax, b2 ax
         // 004173ac: and eax, 0xffffffffffffbfff
         // 004173b1: cmp eax, 0x14
      [-]8b43088bd08bc6e8
         // 0040f922: mov eax, ds:[ebx+0x8]
         // 0040f925: mov edx, eax
         // 0040f927: mov eax, esi
         // 0040f929: call 0x40f490
      [-]ff8bd08bc3e8
         // 0040f94d: mov edx, eax
         // 0040f94f: mov eax, ebx
         // 0040f951: call 0x40f40c
      [-]ffff84c075
         // 0040f956: test b1 al, b1 al
         // 0040f958: jnz 0x40f96e
      [-]33c05a595964891068
         // 0040f96e: xor eax, eax
         // 0040f970: pop edx
         // 0040f971: pop ecx
         // 0040f972: pop ecx
         // 0040f973: mov fs:[eax], edx
         // 0040f976: push 0x40f9c4
      [-]ba????????e8
         // 0040f98b: mov edx, 0x3
         // 0040f990: call 0x404b5c
      [-]ff8d45f0ba????????e8
         // 0040f9af: lea eax, ss:[ebp+0xfffffffffffffff0]
         // 0040f9b2: mov edx, 0x4
         // 0040f9b7: call 0x404488
      [-]5e5b8be55dc3
         // 0040f9c4: pop esi
         // 0040f9c5: pop ebx
         // 0040f9c6: mov esp, ebp
         // 0040f9c8: pop ebp
         // 0040f9c9: retn 
      [-]6a006a004975f9
         // 00417824: push 0x0
         // 00417826: push 0x0
         // 00417828: dec ecx
         // 00417829: jnz 0x417824
      [-]0fb7d083fa
         // 00417843: movzx edx, b2 ax
         // 00417846: cmp edx, 0x14
      [-]0000740d
         // 0042d728: jz 0x42d737
      [-]66ba080066b80100e8
         // 0042d72a: mov b2 dx, b2 0x8
         // 0042d72e: mov b2 ax, b2 0x1
         // 0042d732: call 0x428dcc
      [-]8bc68b15
         // 0040fc5f: mov eax, esi
         // 0040fc61: mov edx, ds:[0x45031c]
      [-]b9????????ba????????e8
         // 0042d818: mov ecx, 0x7fffffff
         // 0042d81d: mov edx, 0x1
         // 0042d822: call 0x407254
      [-]8b430833d252508d45
         // 0040fda7: mov eax, ds:[ebx+0x8]
         // 0040fdaa: xor edx, edx
         // 0040fdac: push edx
         // 0040fdad: push eax
         // 0040fdae: lea eax, ss:[ebp+0xffffffffffffffd4]
      [-]8b43088bd08bc6e8
         // 0040fde2: mov eax, ds:[ebx+0x8]
         // 0040fde5: mov edx, eax
         // 0040fde7: mov eax, esi
         // 0040fde9: call 0x40fbb0
      [-]fdffffe9
         // 0040fdee: jmp 0x410080
      [-]8bd06681ea000174
         // 00417a84: mov edx, eax
         // 00417a86: sub b2 dx, b2 0x100
         // 00417a8b: jz 0x417a94
      [-]66ffca7411
         // 00417a8d: dec b2 dx
         // 00417a90: jz 0x417aa3
      [-]f6c4400f84
         // 00417abc: test b1 ah, b1 0x40
         // 00417abf: jz 0x417cd0
      [-]0fb7c025????????83f8
         // 00417ac5: movzx eax, b2 ax
         // 00417ac8: and eax, 0xffffffffffffbfff
         // 00417acd: cmp eax, 0x14
      [-]8b43088b0033d252508d
         // 0040fffb: mov eax, ds:[ebx+0x8]
         // 0040fffe: mov eax, ds:[eax]
         // 00410000: xor edx, edx
         // 00410002: push edx
         // 00410003: push eax
         // 00410004: lea eax, ss:[ebp+0xffffffffffffff9c]
      [-]8b43088bd08bc6e8
         // 00410034: mov eax, ds:[ebx+0x8]
         // 00410037: mov edx, eax
         // 00410039: mov eax, esi
         // 0041003b: call 0x40fbb0
      [-]ff8bd08bc3e8
         // 0041005f: mov edx, eax
         // 00410061: mov eax, ebx
         // 00410063: call 0x40fae8
      [-]ffff84c075
         // 00410068: test b1 al, b1 al
         // 0041006a: jnz 0x410080
      [-]33c05a595964891068
         // 00410080: xor eax, eax
         // 00410082: pop edx
         // 00410083: pop ecx
         // 00410084: pop ecx
         // 00410085: mov fs:[eax], edx
         // 00410088: push 0x4100fd
      [-]ba????????e8
         // 00410090: mov edx, 0x2
         // 00410095: call 0x404b5c
      [-]ba????????e8
         // 004100aa: mov edx, 0x3
         // 004100af: call 0x404b5c
      [-]ba????????e8
         // 004100c4: mov edx, 0x2
         // 004100c9: call 0x404b5c
      [-]5e5b8be55dc3
         // 004100fd: pop esi
         // 004100fe: pop ebx
         // 004100ff: mov esp, ebp
         // 00410101: pop ebp
         // 00410102: retn 
      [-]ffff5e5bc3
         // 0041cdab: pop esi
         // 0041cdac: pop ebx
         // 0041cdad: retn 
      [-]83c00850e8
         // 0041f768: add eax, 0x8
         // 0041f76b: push eax
         // 0041f76c: call EnterCriticalSection_0
      [-]83c4f453
         // 0041fa6f: add esp, 0xfffffffffffffff4
         // 0041fa72: push ebx
      [-]64ff30648920895df8c645fc
         // 0041fa82: push fs:[eax]
         // 0041fa85: mov fs:[eax], esp
         // 0041fa88: mov ss:[ebp+0xfffffffffffffff8], ebx
         // 0041fa8b: mov b1 ss:[ebp+0xfffffffffffffffc], b1 0xb
      [-]8d45f8506a008d55f4a1
         // 0041fa8f: lea eax, ss:[ebp+0xfffffffffffffff8]
         // 0041fa92: push eax
         // 0041fa93: push 0x0
         // 0041fa95: lea edx, ss:[ebp+0xfffffffffffffff4]
         // 0041fa98: mov eax, ds:[0xa09df4]
      [-]ff8b4df4b201a1
         // 0041faa2: mov ecx, ss:[ebp+0xfffffffffffffff4]
         // 0041faa5: mov b1 dl, b1 0x1
         // 0041faa7: mov eax, ds:[0x41d90c]
      [-]5a595964891068
         // 0041fab8: pop edx
         // 0041fab9: pop ecx
         // 0041faba: pop ecx
         // 0041fabb: mov fs:[eax], edx
         // 0041fabe: push 0x41fad3
      [-]8d45f4e8
         // 0041fac3: lea eax, ss:[ebp+0xfffffffffffffff4]
         // 0041fac6: call @System@@LStrClr$qqrpv
      [-]5b8be55dc3
         // 0041fad3: pop ebx
         // 0041fad4: mov esp, ebp
         // 0041fad6: pop ebp
         // 0041fad7: retn 
      [-]ffffffc3
         // 0042105e: retn 
      [-]558bec6a0053568bf28bd833c05568
         // 004152c0: push ebp
         // 004152c1: mov ebp, esp
         // 004152c3: push 0x0
         // 004152c5: push ebx
         // 004152c6: push esi
         // 004152c7: mov esi, edx
         // 004152c9: mov ebx, eax
         // 004152cb: xor eax, eax
         // 004152cd: push ebp
         // 004152ce: push 0x415303
      [-]64ff306489208d45fc8bd6e8
         // 004152d3: push fs:[eax]
         // 004152d6: mov fs:[eax], esp
         // 004152d9: lea eax, ss:[ebp+0xfffffffffffffffc]
         // 004152dc: mov edx, esi
         // 004152de: call 0x40465c
      [-]ff8b55fc8bc38b08ff512c33c05a595964891068
         // 004152e3: mov edx, ss:[ebp+0xfffffffffffffffc]
         // 004152e6: mov eax, ebx
         // 004152e8: mov ecx, ds:[eax]
         // 004152ea: call ds:[ecx+0x2c]
         // 004152ed: xor eax, eax
         // 004152ef: pop edx
         // 004152f0: pop ecx
         // 004152f1: pop ecx
         // 004152f2: mov fs:[eax], edx
         // 004152f5: push 0x41530a
      [-]8d45fce8
         // 004152fa: lea eax, ss:[ebp+0xfffffffffffffffc]
         // 004152fd: call 0x404464
      [-]5e5b595dc3
         // 0041530a: pop esi
         // 0041530b: pop ebx
         // 0041530c: pop ecx
         // 0041530d: pop ebp
         // 0041530e: retn 
      [-]5356578b
         // 00441e00: push ebx
         // 00441e01: push esi
         // 00441e02: push edi
         // 00441e15: mov eax, ss:[esp]
      [-]30ff560c
         // 00423797: mov esi, ds:[eax]
         // 00423799: call ds:[esi+0xc]
      [-]8b4004e8
         // 00442530: mov eax, ds:[eax+0x4]
         // 00442533: call 0x41cba4
      [-]ff83f8ff7502
         // 00442538: cmp eax, 0xffffffffffffffff
         // 0044253b: jnz 0x44253f
      [-]535657a1
         // 004432ae: push ebx
         // 004432af: push esi
         // 004432b0: push edi
         // 004432b1: mov eax, ds:[0x544f64]
      [-]8b10ff5214
         // 004432b6: mov edx, ds:[eax]
         // 004432b8: call ds:[edx+0x14]
      [-]837f08000f8e
         // 004432e3: cmp ds:[edi+0x8], 0x0
         // 004432e7: jle 0x44342d
      [-]ff8945fc
         // 004245d5: mov ss:[ebp+0xfffffffffffffffc], eax
      [-]ff8945f8
         // 004245f2: mov ss:[ebp+0xfffffffffffffff8], eax
      [-]ffff8945f4837df400750f
         // 00443341: mov ss:[ebp+0xfffffffffffffff4], eax
         // 00443344: cmp ss:[ebp+0xfffffffffffffff4], 0x0
         // 00443348: jnz 0x443359
      [-]8b530c8b4304e8
         // 004169f3: mov edx, ds:[ebx+0xc]
         // 004169f6: mov eax, ds:[ebx+0x4]
         // 004169f9: call 0x410d58
      [-]837df40074
         // 00443359: cmp ss:[ebp+0xfffffffffffffff4], 0x0
         // 0044335d: jz 0x44338e
      [-]8b53148b45f4e8
         // 00443368: mov edx, ds:[ebx+0x14]
         // 0044336b: mov eax, ss:[ebp+0xfffffffffffffff4]
         // 0044336e: call 0x443130
      [-]fdffff8b
         // 00443376: mov edx, ss:[ebp+0xfffffffffffffff0]
      [-]558b4304e8
         // 0042464b: push ebp
         // 0042464c: mov eax, ds:[ebx+0x4]
         // 0042464f: call 0x424504
      [-]feffff59
         // 00424654: pop ecx
      [-]558b4304e8
         // 004433aa: push ebp
         // 004433ab: mov eax, ds:[ebx+0x4]
         // 004433ae: call 0x443260
      [-]feffff5946
         // 004433b3: pop ecx
         // 004433b4: inc esi
      [-]c05a595964891068
         // 00424677: xor eax, eax
         // 00424679: pop edx
         // 0042467a: pop ecx
         // 0042467b: pop ecx
         // 0042467c: mov fs:[eax], edx
         // 0042467f: push 0x424694
      [-]8b45f8e8
         // 00424684: mov eax, ss:[ebp+0xfffffffffffffff8]
         // 00424687: call @System@TObject@Free$qqrv
      [-]8b45fc8b58084b
         // 00424694: mov eax, ss:[ebp+0xfffffffffffffffc]
         // 00424697: mov ebx, ds:[eax+0x8]
         // 0042469a: dec ebx
      [-]ffff8bf88bc78b15
         // 00416a80: mov edi, eax
         // 00416a82: mov eax, edi
         // 00416a84: mov edx, ds:[0x41273c]
      [-]ff84c07406
         // 00416a8f: test b1 al, b1 al
         // 00416a91: jz 0x416a99
      [-]6681671c7fff
         // 004246bf: and b2 ds:[edi+0x1c], b2 0xffffffffffffff7f
      [-]464b75d9
         // 004246c5: inc esi
         // 004246c6: dec ebx
         // 004246c7: jnz 0x4246a2
      [-]33c05a595964891068
         // 00443410: xor eax, eax
         // 00443412: pop edx
         // 00443413: pop ecx
         // 00443414: pop ecx
         // 00443415: mov fs:[eax], edx
         // 00443418: push 0x44342d
      [-]8b45fce8
         // 0044341d: mov eax, ss:[ebp+0xfffffffffffffffc]
         // 00443420: call @System@TObject@Free$qqrv
      [-]33c05a595964891068
         // 00416aba: xor eax, eax
         // 00416abc: pop edx
         // 00416abd: pop ecx
         // 00416abe: pop ecx
         // 00416abf: mov fs:[eax], edx
         // 00416ac2: push 0x416ad9
      [-]33c05a595964891068
         // 00416ad9: xor eax, eax
         // 00416adb: pop edx
         // 00416adc: pop ecx
         // 00416add: pop ecx
         // 00416ade: mov fs:[eax], edx
         // 00416ae1: push 0x416af8
      [-]8b10ff5218c3
         // 00416aeb: mov edx, ds:[eax]
         // 00416aed: call ds:[edx+0x18]
         // 00416af0: retn 
      [-]5f5e5b8be55dc3
         // 00416af8: pop edi
         // 00416af9: pop esi
         // 00416afa: pop ebx
         // 00416afb: mov esp, ebp
         // 00416afd: pop ebp
         // 00416afe: retn 
      [-]cbb201a1
         // 00416c35: mov b1 dl, b1 0x1
         // 00416c37: mov eax, ds:[0x411778]
      [-]e8deffffffc3
         // 004435c9: call 0x4435ac
         // 004435ce: retn 
      [-]928b08ff5110c3
         // 0042a0c4: xchg eax, edx
         // 0042a0c5: mov ecx, ds:[eax]
         // 0042a0c7: call ds:[ecx+0x10]
         // 0042a0ca: retn 
      [-]8b501485d27406
         // 0042cdd0: mov edx, ds:[eax+0x14]
         // 0042cdd3: test edx, edx
         // 0042cdd5: jz 0x42cddd
      [-]8b501485d27406
         // 0042cde0: mov edx, ds:[eax+0x14]
         // 0042cde3: test edx, edx
         // 0042cde5: jz 0x42cded
      [-]e8deffffffc3
         // 0041da89: call 0x41da6c
         // 0041da8e: retn 
      [-]e8d2ffffffc3
         // 00459ca1: call 0x459c78
         // 00459ca6: retn 
      [-]6a0033c05568
         // 00459cb7: push 0x0
         // 00459cb9: xor eax, eax
         // 00459cbb: push ebp
         // 00459cbc: push 0x459cfe
      [-]64ff306489208d55fca1
         // 00459cc1: push fs:[eax]
         // 00459cc4: mov fs:[eax], esp
         // 00459cc7: lea edx, ss:[ebp+0xfffffffffffffffc]
         // 00459cca: mov eax, ds:[0x53f0a0]
      [-]ff8b4dfcb201a1
         // 00459cd4: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 00459cd7: mov b1 dl, b1 0x1
         // 00459cd9: mov eax, ds:[0x43247c]
      [-]5a595964891068
         // 00459cea: pop edx
         // 00459ceb: pop ecx
         // 00459cec: pop ecx
         // 00459ced: mov fs:[eax], edx
         // 00459cf0: push 0x459d05
      [-]8d45fce8
         // 00459cf5: lea eax, ss:[ebp+0xfffffffffffffffc]
         // 00459cf8: call 0x406968
      [-]ffffffc3
         // 0042fa6b: retn 
      [-]535684d27408
         // 0042fd3c: push ebx
         // 0042fd3d: push esi
         // 0042fd3e: test b1 dl, b1 dl
         // 0042fd40: jz 0x42fd4a
      [-]83c4f0e8
         // 0045afe6: add esp, 0xfffffffffffffff0
         // 0045afe9: call @System@@ClassCreate$qqrp17System@TMetaClasso
      [-]84db740f
         // 0041ed3d: test b1 bl, b1 bl
         // 0041ed3f: jz 0x41ed50
      [-]ff648f05????????83c40c
         // 0045b006: pop fs:[0x0]
         // 0045b00d: add esp, 0xc
      [-]ff8bda8bf08bc6e81a0000008bd380e2fc8bc6e8
         // 0045dd27: mov ebx, edx
         // 0045dd29: mov esi, eax
         // 0045dd2b: mov eax, esi
         // 0045dd2d: call 0x45dd4c
         // 0045dd32: mov edx, ebx
         // 0045dd34: and b1 dl, b1 0xfc
         // 0045dd37: mov eax, esi
         // 0045dd39: call 0x458c44
      [-]ffff84db7e07
         // 0045dd3e: test b1 bl, b1 bl
         // 0045dd40: jle 0x45dd49
      [-]ff4004c3
         // 00432600: inc ds:[eax+0x4]
         // 00432603: retn 
      [-]b101e801000000c3
         // 004349f8: mov b1 cl, b1 0x1
         // 004349fa: call @Graphics@TBitmap@WriteStream$qqrp15Classes@TStreamo
         // 004349ff: retn 
      [-]83c00850e8
         // 00462764: add eax, 0x8
         // 00462767: push eax
         // 00462768: call EnterCriticalSection_0
      [-]83c00850e8
         // 00462770: add eax, 0x8
         // 00462773: push eax
         // 00462774: call LeaveCriticalSection_0
      [-]535684d27408
         // 00436324: push ebx
         // 00436325: push esi
         // 00436326: test b1 dl, b1 dl
         // 00436328: jz 0x436332
      [-]83c4f0e8
         // 00462db2: add esp, 0xfffffffffffffff0
         // 00462db5: call @System@@ClassCreate$qqrp17System@TMetaClasso
      [-]ffb201a1
         // 00462dc7: mov b1 dl, b1 0x1
         // 00462dc9: mov eax, ds:[0x4328f8]
      [-]84db740f
         // 00462dd8: test b1 bl, b1 bl
         // 00462dda: jz 0x462deb
      [-]ff648f05????????83c40c
         // 00462de1: pop fs:[0x0]
         // 00462de8: add esp, 0xc
      [-]ff33c0a3
         // 004715f9: xor eax, eax
         // 004715fb: mov ds:[0x545178], eax
      [-]ff33c0a3
         // 00471609: xor eax, eax
         // 0047160b: mov ds:[0x545178], eax
      [-]ff8bda8bf08bc6e8
         // 0042afab: mov ebx, edx
         // 0042afad: mov esi, eax
         // 0042afaf: mov eax, esi
         // 0042afb1: call 0x42b078
      [-]0000008bd380e2fc8bc6e8
         // 0042afb6: mov edx, ebx
         // 0042afb8: and b1 dl, b1 0xfc
         // 0042afbb: mov eax, esi
         // 0042afbd: call 0x41d334
      [-]ff84db7e07
         // 0042afc2: test b1 bl, b1 bl
         // 0042afc4: jle 0x42afcd
      [-]33c089420cc3
         // 004987f0: xor eax, eax
         // 004987f2: mov ds:[edx+0xc], eax
         // 004987f5: retn 
      [-]e83dffffffc3
         // 00499c52: call @Controls@TWinControl@AlignControl$qqrp17Controls@TControl
         // 00499c57: retn 
      [-]895020c3
         // 0049f884: mov ds:[eax+0x20], edx
         // 0049f887: retn 
      [-]8b400ce8
         // 004805d4: mov eax, ds:[eax+0xc]
         // 004805d7: call 0x47ff28
      [-]f9ffffc3
         // 004805dc: retn 
      [-]8b4008e8
         // 004805fc: mov eax, ds:[eax+0x8]
         // 004805ff: call 0x47ff28
      [-]f9ffffc3
         // 00480604: retn 
      [-]ff406cc3
         // 0049fb38: inc ds:[eax+0x6c]
         // 0049fb3b: retn 
      [-]ff8bda8bf033d28bc6e8
         // 004371ab: mov ebx, edx
         // 004371ad: mov esi, eax
         // 004371af: xor edx, edx
         // 004371b1: mov eax, esi
         // 004371b3: call 0x437260
      [-]0000008bd380e2fc8bc6e8
         // 004371b8: mov edx, ebx
         // 004371ba: and b1 dl, b1 0xfc
         // 004371bd: mov eax, esi
         // 004371bf: call 0x4036e0
      [-]ff84db7e07
         // 004371c4: test b1 bl, b1 bl
         // 004371c6: jle 0x4371cf
      [-]558bec33c05568
         // 004378b4: push ebp
         // 004378b5: mov ebp, esp
         // 004378b7: xor eax, eax
         // 004378b9: push ebp
         // 004378ba: push 0x437913
      [-]64ff30648920ff05
         // 004378bf: push fs:[eax]
         // 004378c2: mov fs:[eax], esp
         // 004378c5: inc ds:[0x452aa8]
      [-]33c05a595964891068
         // 00485241: xor eax, eax
         // 00485243: pop edx
         // 00485244: pop ecx
         // 00485245: pop ecx
         // 00485246: mov fs:[eax], edx
         // 00485249: push 0x485256
      [-]8b442408c3
         // 004a6d48: mov eax, ss:[esp+0x8]
         // 004a6d4c: retn 
      [-]837b5c00750a
         // 004a972a: cmp ds:[ebx+0x5c], 0x0
         // 004a972e: jnz 0x4a973a
      [-]ff5e5bc3
         // 0043dce8: pop esi
         // 0043dce9: pop ebx
         // 0043dcea: retn 
      [-]e8c1ffffff
         // 004a9ab2: call 0x4a9a78
      [-]83feff750a
         // 004a9ab9: cmp esi, 0xffffffffffffffff
         // 004a9abc: jnz 0x4a9ac8
      [-]feffff5e5bc3
         // 00494d41: pop esi
         // 00494d42: pop ebx
         // 00494d43: retn 
      [-]558bec83c4
         // 00495440: push ebp
         // 00495441: mov ebp, esp
         // 00495443: add esp, 0xffffffffffffffe8
      [-]33c05568
         // 0049545a: xor eax, eax
         // 0049545c: push ebp
         // 0049545d: push 0x495598
      [-]64ff30648920
         // 00495462: push fs:[eax]
         // 00495465: mov fs:[eax], esp
      [-]b301eb04
         // 004aa1f0: mov b1 bl, b1 0x1
         // 004aa1f2: jmp 0x4aa1f8
      [-]84db0f84
         // 004aa1f8: test b1 bl, b1 bl
         // 004aa1fa: jz 0x4aa292
      [-]c05a595964891068
         // 0043e81f: xor eax, eax
         // 0043e821: pop edx
         // 0043e822: pop ecx
         // 0043e823: pop ecx
         // 0043e824: mov fs:[eax], edx
         // 0043e827: push 0x43e841
      [-]5356575583c4f4894c24048914248be88b04248b15
         // 004a877c: push ebx
         // 004a877d: push esi
         // 004a877e: push edi
         // 004a877f: push ebp
         // 004a8780: add esp, 0xfffffffffffffff4
         // 004a8783: mov ss:[esp+0x4], ecx
         // 004a8787: mov ss:[esp], edx
         // 004a878a: mov ebp, eax
         // 004a878c: mov eax, ss:[esp]
         // 004a878f: mov edx, ds:[0x46a638]
      [-]ff84c07410
         // 004a879a: test b1 al, b1 al
         // 004a879c: jz 0x4a87ae
      [-]8b4c24048b14248bc5e8
         // 00444e0e: mov ecx, ss:[esp+0x4]
         // 00444e12: mov edx, ss:[esp]
         // 00444e15: mov eax, ebp
         // 00444e17: call 0x4330a8
      [-]ff29442404c7442408????????8bc5e8
         // 00444e25: sub ss:[esp+0x4], eax
         // 00444e29: mov ss:[esp+0x8], 0xffffffffffffffff
         // 00444e31: mov eax, ebp
         // 00444e33: call 0x419f14
      [-]ff8bd84b85db7c37
         // 00444e38: mov ebx, eax
         // 00444e3a: dec ebx
         // 00444e3b: test ebx, ebx
         // 00444e3d: jl 0x444e76
      [-]8bd78bc5e8
         // 004a87d2: mov edx, edi
         // 004a87d4: mov eax, ebp
         // 004a87d6: call @Classes@TComponent@GetComponent$qqri
      [-]ff66bef1ffe8
         // 004a87db: mov b2 si, b2 0xfffffffffffffff1
         // 004a87df: call @System@@CallDynaInst$qqrv
      [-]ff84c0751a
         // 004a87e4: test b1 al, b1 al
         // 004a87e6: jnz 0x4a8802
      [-]ff4424088b4424083b442404750c
         // 004b16c0: inc ss:[esp+0x8]
         // 004b16c4: mov eax, ss:[esp+0x8]
         // 004b16c8: cmp eax, ss:[esp+0x4]
         // 004b16cc: jnz 0x4b16da
      [-]8bd78b0424e8
         // 004a87f6: mov edx, edi
         // 004a87f8: mov eax, ss:[esp]
         // 004a87fb: call @Classes@TComponent@SetComponentIndex$qqri
      [-]474b75cc
         // 004b16da: inc edi
         // 004b16db: dec ebx
         // 004b16dc: jnz 0x4b16aa
      [-]83c40c5d5f5e5bc3
         // 004b16de: add esp, 0xc
         // 004b16e1: pop ebp
         // 004b16e2: pop edi
         // 004b16e3: pop esi
         // 004b16e4: pop ebx
         // 004b16e5: retn 
      [-]53568b45088b40fce8
         // 004a9047: push ebx
         // 004a9048: push esi
         // 004a9049: mov eax, ss:[ebp+0x8]
         // 004a904c: mov eax, ds:[eax+0xfffffffffffffffc]
         // 004a904f: call 0x4a9a3c
      [-]8b45088b40fc
         // 004a905e: mov eax, ss:[ebp+0x8]
         // 004a9061: mov eax, ds:[eax+0xfffffffffffffffc]
      [-]000080b8
         // 004a906b: cmp b1 ds:[eax+0x29a], b1 0x2
      [-]020000027504
         // 004a9072: jnz 0x4a9078
      [-]b001eb06
         // 004b1d48: mov b1 al, b1 0x1
         // 004b1d4a: jmp 0x4b1d52
      [-]464b75e2
         // 004b1d4c: inc esi
         // 004b1d4d: dec ebx
         // 004b1d4e: jnz 0x4b1d32
      [-]5e5b5dc3
         // 004b1d52: pop esi
         // 004b1d53: pop ebx
         // 004b1d54: pop ebp
         // 004b1d55: retn 
      [-]83c4f0535657
         // 004b2537: add esp, 0xfffffffffffffff0
         // 004b253a: push ebx
         // 004b253b: push esi
         // 004b253c: push edi
      [-]64ff3064892085f67470
         // 004b254e: push fs:[eax]
         // 004b2551: mov fs:[eax], esp
         // 004b2554: test esi, esi
         // 004b2556: jz 0x4b25c8
      [-]00004885c07c61
         // 00445cfa: dec eax
         // 00445cfb: test eax, eax
         // 00445cfd: jl 0x445d60
      [-]408945fc
         // 004b2567: inc eax
         // 004b2568: mov ss:[ebp+0xfffffffffffffffc], eax
      [-]00003bb0
         // 004a9e69: cmp esi, ds:[eax+0x2b4]
      [-]00003bd87431
         // 00445d25: cmp ebx, eax
         // 00445d27: jz 0x445d5a
      [-]8b46088945f4c645f8
         // 004b2591: mov eax, ds:[esi+0x8]
         // 004b2594: mov ss:[ebp+0xfffffffffffffff4], eax
         // 004b2597: mov b1 ss:[ebp+0xfffffffffffffff8], b1 0xb
      [-]8d45f4506a008d55f0a1
         // 004b259b: lea eax, ss:[ebp+0xfffffffffffffff4]
         // 004b259e: push eax
         // 004b259f: push 0x0
         // 004b25a1: lea edx, ss:[ebp+0xfffffffffffffff0]
         // 004b25a4: mov eax, ds:[0xa09418]
      [-]ff8b4df0b201a1
         // 004b25ae: mov ecx, ss:[ebp+0xfffffffffffffff0]
         // 004b25b1: mov b1 dl, b1 0x1
         // 004b25b3: mov eax, ds:[0x41db8c]
      [-]47ff4dfc75a5
         // 004b25c2: inc edi
         // 004b25c3: dec ss:[ebp+0xfffffffffffffffc]
         // 004b25c6: jnz 0x4b256d
      [-]85c07407
         // 004b25ce: test eax, eax
         // 004b25d0: jz 0x4b25d9
      [-]f6431c08750a
         // 004b25d9: test b1 ds:[ebx+0x1c], b1 0x8
         // 004b25dd: jnz 0x4b25e9
      [-]f6461c087402
         // 004b25e3: test b1 ds:[esi+0x1c], b1 0x8
         // 004b25e7: jz 0x4b25eb
      [-]85f67409
         // 004b25f1: test esi, esi
         // 004b25f3: jz 0x4b25fe
      [-]0f84ab000000
         // 004b2600: jz 0x4b26b1
      [-]f6431c10750d
         // 004b2606: test b1 ds:[ebx+0x1c], b1 0x10
         // 004b260a: jnz 0x4b2619
      [-]020000030f8498000000
         // 004b2613: jz 0x4b26b1
      [-]020000017506
         // 004b262c: jnz 0x4b2634
      [-]f6431c107458
         // 004b262e: test b1 ds:[ebx+0x1c], b1 0x10
         // 004b2632: jz 0x4b268c
      [-]ff84c00f8488000000
         // 004a9f2b: test b1 al, b1 al
         // 004a9f2d: jz 0x4a9fbb
      [-]8b10ff52
         // 00445de1: mov edx, ds:[eax]
         // 00445de3: call ds:[edx+0x34]
      [-]ff3bf87419
         // 00445df5: cmp edi, eax
         // 00445df7: jz 0x445e12
      [-]8b10ff52
         // 00445dff: mov edx, ds:[eax]
         // 00445e01: call ds:[edx+0x34]
      [-]020000017436
         // 004b2693: jz 0x4b26cb
      [-]ff84c0742b
         // 00445e34: test b1 al, b1 al
         // 00445e36: jz 0x445e63
      [-]ff84c0740f
         // 004a9fa8: test b1 al, b1 al
         // 004a9faa: jz 0x4a9fbb
      [-]020000007409
         // 004b26d2: jz 0x4b26dd
      [-]5a595964891068
         // 00445e7e: pop edx
         // 00445e7f: pop ecx
         // 00445e80: pop ecx
         // 00445e81: mov fs:[eax], edx
         // 00445e84: push 0x445e99
      [-]8d45f0e8
         // 00445e89: lea eax, ss:[ebp+0xfffffffffffffff0]
         // 00445e8c: call 0x404464
      [-]5f5e5b8be55dc3
         // 00445e99: pop edi
         // 00445e9a: pop esi
         // 00445e9b: pop ebx
         // 00445e9c: mov esp, ebp
         // 00445e9e: pop ebp
         // 00445e9f: retn 
      [-]8b4008c3
         // 004b62ff: mov eax, ds:[eax+0x8]
         // 004b6302: retn 
      [-]040000c3
         // 004b6587: retn 
      [-]5356b3018b45088b40f0e8
         // 00449f43: push ebx
         // 00449f44: push esi
         // 00449f45: mov b1 bl, b1 0x1
         // 00449f47: mov eax, ss:[ebp+0x8]
         // 00449f4a: mov eax, ds:[eax+0xfffffffffffffff0]
         // 00449f4d: call 0x44951c
      [-]4e83fe007c34
         // 00449f54: dec esi
         // 00449f55: cmp esi, 0x0
         // 00449f58: jl 0x449f8e
      [-]8b45088b40f0
         // 004afba6: mov eax, ss:[ebp+0x8]
         // 004afba9: mov eax, ds:[eax+0xfffffffffffffff0]
      [-]ffff8378
         // 004afbb3: cmp ds:[eax+0x34], 0x0
      [-]f6401c107515
         // 004b6911: test b1 ds:[eax+0x1c], b1 0x10
         // 004b6915: jnz 0x4b692c
      [-]020000017508
         // 004b692a: jnz 0x4b6934
      [-]4e83feff75cc
         // 004b692c: dec esi
         // 004b692d: cmp esi, 0xffffffffffffffff
         // 004b6930: jnz 0x4b68fe
      [-]5e5b5dc3
         // 004b6936: pop esi
         // 004b6937: pop ebx
         // 004b6938: pop ebp
         // 004b6939: retn 
      [-]feffffc3
         // 004b0a4b: retn 
      [-]feffffc3
         // 004b74b3: retn 
      [-]ff8b45088b40fc8b80????????8b80
         // 004b9375: mov eax, ss:[ebp+0x8]
         // 004b9378: mov eax, ds:[eax+0xfffffffffffffffc]
         // 004b937b: mov eax, ds:[eax+0x84]
         // 004b9381: mov eax, ds:[eax+0x208]
      [-]5a595964891068
         // 0044c7cd: pop edx
         // 0044c7ce: pop ecx
         // 0044c7cf: pop ecx
         // 0044c7d0: mov fs:[eax], edx
         // 0044c7d3: push 0x44c7e8

  }
  condition:
    all of them
}
