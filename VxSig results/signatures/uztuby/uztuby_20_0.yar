rule uztuby_20_0 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         01000084c075
         // 004018cf: test b1 al, b1 al
         // 004018d1: jnz 0x4018f2
      [-]00000074
         // 0040198e: jz 0x4019aa
      [-]03d083b9
         // 00401997: add edx, eax
         // 00401999: cmp ds:[ecx+0x6cc8], 0x3
      [-]83c210eb
         // 00401b01: add edx, 0x10
         // 00401b04: jmp 0x401b09
      [-]000085c074
         // 00401a2a: test eax, eax
         // 00401a2c: jz 0x401a56
      [-]83f8010f85
         // 00401a34: cmp eax, 0x1
         // 00401a37: jnz 0x401b3c
      [-]2bc180781c527512
         // 00401b24: sub eax, ecx
         // 00401b26: cmp b1 ds:[eax+0x1c], b1 0x52
         // 00401b2a: jnz 0x401b3e
      [-]80781d53750c
         // 00401c82: cmp b1 ds:[eax+0x1d], b1 0x53
         // 00401c86: jnz 0x401c94
      [-]80781e467506
         // 00401c88: cmp b1 ds:[eax+0x1e], b1 0x46
         // 00401c8c: jnz 0x401c94
      [-]80781f5874
         // 00401c8e: cmp b1 ds:[eax+0x1f], b1 0x58
         // 00401c92: jz 0x401c9e
      [-]83f80475
         // 00401bc2: cmp eax, 0x4
         // 00401bc5: jnz 0x401bd4
      [-]83f80375
         // 140003682: cmp b4 eax, b4 0x3
         // 140003685: jnz 0x1400036bc
      [-]00007504
         // 00401c71: cmp b1 ds:[ebx+0x6cdc], b1 0x0
         // 00401c78: jnz 0x401c7e
      [-]00000f85
         // 00401cb6: cmp b1 ds:[ebx+0x6cd4], b1 0x0
         // 00401cbd: jnz 0x401dc1
      [-]83f80375
         // 00401d1e: cmp eax, 0x3
         // 00401d21: jnz 0x401d43
      [-]ff0f95c0c3
         // 00401dd4: setnz b1 al
         // 00401dd7: retn 
      [-]000084c0
         // 00401fe8: test b1 al, b1 al
      [-]ffff84c075
         // 00401f2b: test b1 al, b1 al
         // 00401f2d: jnz 0x401f43
      [-]00000075
         // 140006ae3: jnz 0x140006b34
      [-]0084c075
         // 00403e91: call 0x411b42
         // 00403e96: test b1 al, b1 al
         // 00403e98: jnz 0x403ece
      [-]bd????????eb
         // 00404c30: mov ebp, 0x200
         // 00404c3d: jmp 0x404c65
      [-]0f188f00020000
         // 00404c50: prefetcht0 b1 ds:[edi+0x200]
      [-]660f72d00c660f72
         // 004046e2: psrld b16 xmm0, b1 0xc
         // 004046e7: pslld b16 xmm3, b1 0x14
      [-]07660f72
         // 00404742: pslld b16 xmm0, b1 0x19
      [-]07660f72
         // 004049b5: pslld b16 xmm0, b1 0x19
      [-]660f72d00c660f72
         // 00404af3: psrld b16 xmm0, b1 0xc
         // 00404af8: pslld b16 xmm3, b1 0x14
      [-]07660f72
         // 00404b5b: pslld b16 xmm0, b1 0x19
      [-]660f72d00c660f72
         // 00404bbf: psrld b16 xmm0, b1 0xc
         // 00404bc4: pslld b16 xmm3, b1 0x14
      [-]07660f72
         // 00404c29: pslld b16 xmm0, b1 0x19
      [-]72d00c660f72
         // 00404d6c: pslld b16 xmm3, b1 0x14
      [-]07660f72
         // 00404dcd: pslld b16 xmm0, b1 0x19
      [-]660f72d00c660f72
         // 00404e33: psrld b16 xmm0, b1 0xc
         // 00404e38: pslld b16 xmm3, b1 0x14
      [-]07660f72
         // 00404e8a: pslld b16 xmm0, b1 0x19
      [-]660f72d00c660f72
         // 00404f09: psrld b16 xmm0, b1 0xc
         // 00404f0e: pslld b16 xmm3, b1 0x14
      [-]660f72d00c660f72
         // 00404fd5: psrld b16 xmm0, b1 0xc
         // 00404fda: pslld b16 xmm3, b1 0x14
      [-]07660f72
         // 0040503f: pslld b16 xmm0, b1 0x19
      [-]660f72d00c660f72
         // 004050a4: pxor b16 xmm0, b16 xmm3
         // 004050ab: psrld b16 xmm0, b1 0xc
         // 004050b0: pslld b16 xmm3, b1 0x14
      [-]07660f72
         // 0040510b: pslld b16 xmm0, b1 0x19
      [-]07660f72
         // 004051e5: pslld b16 xmm0, b1 0x19
      [-]660f72d00c660f72
         // 0040524d: psrld b16 xmm0, b1 0xc
         // 00405252: pslld b16 xmm3, b1 0x14
      [-]07660f72
         // 004052a4: pslld b16 xmm0, b1 0x19
      [-]660f72d00c660f72
         // 004053e9: psrld b16 xmm0, b1 0xc
         // 004053ee: pslld b16 xmm3, b1 0x14
      [-]07660f72
         // 0040551f: pslld b16 xmm0, b1 0x19
      [-]010000740a
         // 0040568d: cmp b1 ds:[esi+0x104], b1 0x0
         // 00405694: jz 0x4056a0
      [-]83ff207c
         // 00406273: cmp edi, 0x20
         // 00406276: jl 0x406264
      [-]83fa207c
         // 00405732: cmp edx, 0x20
         // 00405735: jl 0x405720
      [-]8130????????
         // 1400085cc: xor b4 ds:[rax], b4 0x2080020
      [-]ffffeb05
         // 140008922: jmp 0x140008929
      [-]83ff0872
         // 004058f8: cmp edi, 0x8
         // 004058fb: jb 0x4058e9
      [-]ffff84c07404
         // 00405c68: test b1 al, b1 al
         // 00405c6a: jz 0x405c70
      [-]0084c074
         // 0040632b: test b1 al, b1 al
         // 0040632d: jz 0x406360
      [-]c1e810884424
         // 140009eb8: shr b4 eax, b1 0x10
         // 140009ebb: mov b1 ss:[rsp+0x32], b1 al
      [-]c1e90e88
         // 0040624c: shr ecx, b1 0xe
         // 0040624f: mov b1 ss:[esp+ecx+0x28], b1 al
      [-]83e00389
         // 00407061: and eax, 0x3
         // 00407064: mov ds:[ebx+0xf0], eax
      [-]84c07508
         // 14000b526: test b1 al, b1 al
         // 14000b528: jnz 0x14000b532
      [-]0a01eb02
         // 00407b41: jmp 0x407b45
      [-]83e80174
         // 00406d89: sub eax, 0x1
         // 00406d8c: jz 0x406d9f
      [-]83e80174
         // 00407d0c: sub eax, 0x1
         // 00407d0f: jz 0x407d37
      [-]83e8017414
         // 00407d11: sub eax, 0x1
         // 00407d14: jz 0x407d2a
      [-]8339007502
         // 00407d1d: cmp ds:[ecx], 0x0
         // 00407d20: jnz 0x407d24
      [-]83390b74
         // 00407d2a: cmp ds:[ecx], 0xb
         // 00407d2d: jz 0x407d24
      [-]c701????????eb
         // 00407d2f: mov ds:[ecx], 0x3
         // 00407d35: jmp 0x407d24
      [-]c701????????eb
         // 00407d41: mov ds:[ecx], 0x2
         // 00407d47: jmp 0x407d24
      [-]8079080075
         // 14000bc50: cmp b1 ds:[rcx+0x8], b1 0x0
         // 14000bc54: jnz 0x14000bc5c
      [-]ffff84c00f84
         // 00407f31: test b1 al, b1 al
         // 00407f33: jz 0x407ff9
      [-]000084c074
         // 004075f4: test b1 al, b1 al
         // 004075f6: jz 0x40760b
      [-]00000075
         // 0040954c: jnz 0x40957c
      [-]ffff84c0
         // 14000ea1d: test b1 al, b1 al
      [-]000084c075
         // 00408411: test b1 al, b1 al
         // 00408413: jnz 0x4083f3
      [-]00000084c075
         // 004092de: test b1 al, b1 al
         // 004092e0: jnz 0x409323
      [-]000085c074
         // 00409306: test eax, eax
         // 00409308: jz 0x40932d
      [-]83f80174
         // 1400119ab: cmp b4 eax, b4 0x1
         // 1400119ae: jz 0x1400119f3
      [-]83f80675
         // 0040ac75: cmp eax, 0x6
         // 0040ac78: jnz 0x40ac89
      [-]000084c074
         // 004093a9: test b1 al, b1 al
         // 004093ab: jz 0x4093bc
      [-]85ff7403
         // 0040acb0: test edi, edi
         // 0040acb2: jz 0x40acb7
      [-]0000eb05
         // 004095cf: jmp 0x4095d6
      [-]84c07404
         // 00409f5f: test b1 al, b1 al
         // 00409f61: jz 0x409f67
      [-]ffff32c0
         // 00409e6a: xor b1 al, b1 al
      [-]000084c0
         // 0040a582: test b1 al, b1 al
      [-]83f8ff74
         // 0040c39f: cmp eax, 0xffffffffffffffff
         // 0040c3a2: jz 0x40c3d8
      [-]0085c075
         // 0040a5d8: test eax, eax
         // 0040a5da: jnz 0x40a5f0
      [-]0083f8120f95c0
         // 0040a73a: cmp eax, 0x12
         // 0040a73d: setnz b1 al
      [-]07c1e8030101
         // 0040c6a8: shr eax, b1 0x3
         // 0040c6ab: add ds:[ecx], eax
      [-]8941088901
         // 0040c6d8: mov ds:[ecx+0x8], eax
         // 0040c6db: mov ds:[ecx], eax
      [-]8339017505
         // 0040c87f: cmp ds:[ecx], 0x1
         // 0040c882: jnz 0x40c889
      [-]833a01740a
         // 0040c884: cmp ds:[edx], 0x1
         // 0040c887: jz 0x40c893
      [-]8339027510
         // 0040c889: cmp ds:[ecx], 0x2
         // 0040c88c: jnz 0x40c89e
      [-]833a0275
         // 1400146a1: cmp b4 ds:[rdx], b4 0x2
         // 1400146a4: jnz 0x1400146d2
      [-]83390375
         // 1400146b1: cmp b4 ds:[rcx], b4 0x3
         // 1400146b4: jnz 0x1400146d2
      [-]833a0375
         // 1400146b6: cmp b4 ds:[rdx], b4 0x3
         // 1400146b9: jnz 0x1400146d2
      [-]32c0eb02
         // 0040c8c2: xor b1 al, b1 al
         // 0040c8c4: jmp 0x40c8c8
      [-]8b410489
         // 14001483c: mov b4 eax, b4 ds:[rcx+0x4]
         // 14001483f: mov b4 ds:[rbx], b4 eax
      [-]83390275
         // 0040ca11: cmp ds:[ecx], 0x2
         // 0040ca14: jnz 0x40ca1d
      [-]8b4104f7d089
         // 140014846: mov b4 eax, b4 ds:[rcx+0x4]
         // 140014849: not b4 eax
         // 14001484b: mov b4 ds:[rbx], b4 eax
      [-]83390375
         // 0040ca1d: cmp ds:[ecx], 0x3
         // 0040ca20: jnz 0x40ca3d
      [-]3a0f94c0
         // 0040dbd9: setz b1 al
      [-]00000074
         // 0040f165: jz 0x40f188
      [-]84c00f84
         // 140017ab6: test b1 al, b1 al
         // 140017ab8: jz 0x140017bde
      [-]000084c074
         // 0040d280: test b1 al, b1 al
         // 0040d282: jz 0x40d291
      [-]04????????eb
         // 0040e122: jmp 0x40e13b
      [-]85ff0f84
         // 0040ea05: test edi, edi
         // 0040ea07: jz 0x40ee5f
      [-]8d40f0660f38dec8
         // 00410e7f: lea eax, ds:[eax+0xfffffffffffffff0]
         // 00410e82: aesdec b16 xmm1, b16 xmm0
      [-]807a0100
         // 0040eed7: cmp b1 ds:[edx+0x1], b1 0x0
      [-]660f38dfc874
         // 0040eedf: aesdeclast b16 xmm1, b16 xmm0
         // 0040eee4: jz 0x40eeea
      [-]8a41fc3001
         // 0040e8f5: mov b1 al, b1 ds:[ecx+0xfffffffffffffffc]
         // 0040e8f8: xor b1 ds:[ecx], b1 al
      [-]0000006689
         // 14001afef: mov b2 ds:[rbx+rdi*0x2], b2 si
      [-]83c00283
         // 0040f7dd: add eax, 0x2
         // 0040f7e0: and esi, 0xf
      [-]0f83e00f
         // 0040f7e3: and eax, 0xf
      [-]0783e10f
         // 0040f1a8: lea edi, ds:[eax+0x7]
         // 0040f1ab: and ecx, 0xf
      [-]83c00283
         // 0040f1ae: add eax, 0x2
         // 0040f1b1: and edi, 0xf
      [-]0f83e00f
         // 00411bd5: and eax, 0xf
      [-]04????????c7
         // 14001c4ba: mov b4 ds:[rcx+0x8], b4 0xffffffff98badcfe
      [-]08????????c7
         // 14001c4c1: mov b4 ds:[rcx+0xc], b4 0x10325476
      [-]0c????????c7
         // 14001c4c8: mov b4 ds:[rcx+0x10], b4 0xffffffffc3d2e1f0
      [-]10????????
      [-]83f83f76
         // 0040f5ce: cmp eax, 0x3f
         // 0040f5d1: jbe 0x40f628
      [-]04????????c7
         // 14001c8ae: mov b4 ds:[rcx+0x8], b4 0x3c6ef372
      [-]08????????c7
         // 14001c8b5: mov b4 ds:[rcx+0xc], b4 0xffffffffa54ff53a
      [-]0c????????c7
         // 14001c8bc: mov b4 ds:[rcx+0x10], b4 0x510e527f
      [-]10????????c7
         // 14001c8c3: mov b4 ds:[rcx+0x14], b4 0xffffffff9b05688c
      [-]14????????c7
         // 14001c8ca: mov b4 ds:[rcx+0x18], b4 0x1f83d9ab
      [-]18????????c7
         // 14001c8d1: mov b4 ds:[rcx+0x1c], b4 0x5be0cd19
      [-]1c????????
      [-]83ff4075
         // 0041210d: cmp edi, 0x40
         // 00412110: jnz 0x41211a
      [-]01008bf885
         // 00410b54: mov edi, eax
         // 00410b57: test edi, edi
      [-]ffff3d????????72
         // 00410c49: cmp eax, 0x600
         // 00410c4e: jb 0x410c7d
      [-]0083f80275
         // 0041044b: cmp eax, 0x2
         // 0041044e: jnz 0x410478
      [-]ffff3d????????
         // 00410d06: cmp eax, 0x600
      [-]ffffff15
         // 00410d9e: call ds:[AllocConsole]
      [-]0085c074
         // 00410da4: test eax, eax
         // 00410da6: jz 0x410df3
      [-]000084c074
         // 14001e816: test b1 al, b1 al
         // 14001e818: jz 0x14001e82b
      [-]0000ff15
         // 00412ff7: mov b1 ds:[esi+0x314], b1 0x1
         // 00413007: call ds:[ReleaseSemaphore]
      [-]0083f8ff75
         // 004107b8: cmp eax, 0xffffffffffffffff
         // 004107bb: jnz 0x4107e4
      [-]ffffff83f80173
         // 004108ab: cmp eax, 0x1
         // 004108ae: jnb 0x4108b4
      [-]feffff80bf
         // 00411101: cmp b1 ds:[edi+0x314], b1 0x0
      [-]0000007404
         // 00411108: jz 0x41110e
      [-]ffffff84c074
         // 0041094f: test b1 al, b1 al
         // 00410951: jz 0x41099c
      [-]ffff84c075
         // 004111c7: test b1 al, b1 al
         // 004111c9: jnz 0x41118a
      [-]010f97c0
         // 0041132a: setnbe b1 al
      [-]888700010000
         // 0041132d: mov b1 ds:[edi+0x100], b1 al
      [-]0085c00f95c0
         // 0041133a: test eax, eax
         // 0041133c: setnz b1 al
      [-]00006689
         // 0041217d: mov b2 ds:[esi+0x4c50], b2 bx
      [-]83fa2072
         // 0041449f: cmp edx, 0x20
         // 004144a2: jb 0x414497
      [-]02c1e10803c8
         // 00412acc: shl ecx, b1 0x8
         // 00412acf: add ecx, eax
      [-]c1e802c1e1082bc8
         // 00412ad3: shr eax, b1 0x2
         // 00412ad6: shl ecx, b1 0x8
         // 00412ad9: sub ecx, eax
      [-]03c88bc1
         // 00412adf: add ecx, eax
         // 00412ae1: mov eax, ecx
      [-]c1e808c1e910
         // 00412ae6: shr eax, b1 0x8
         // 00412ae9: shr ecx, b1 0x10
      [-]8d81????????8907eb
         // 00414ba2: lea eax, ds:[ecx+0x1000000]
         // 00414ba8: mov ds:[edi], eax
         // 00414baa: jmp 0x414bba
      [-]8d81????????85c079
         // 00414bac: lea eax, ds:[ecx+0xffffffffff000000]
         // 00414bb2: test eax, eax
         // 00414bb4: jns 0x414bba
      [-]83ee0175
         // 0041368e: sub esi, 0x1
         // 00413691: jnz 0x41364c
      [-]83e81039
         // 140022c3f: sub b4 eax, b4 0x10
         // 140022c42: cmp b4 ds:[rdx], b4 eax
      [-]000084c074
         // 00413fbd: test b1 al, b1 al
         // 00413fbf: jz 0x41401f
      [-]0000008b
         // 1400223da: call 0x14002244c
         // 1400223e1: mov rdx, rbx
      [-]2bfa7907
         // 00414e61: sub edi, edx
         // 00414e63: jns 0x414e6c
      [-]81fa????????7e
         // 00414e7d: cmp edx, 0x4000
         // 00414e83: jle 0x414ea9
      [-]ff0f95c0
         // 00414f20: setnz b1 al
      [-]00000074
         // 00414f4e: jz 0x414f96
      [-]ffff84c00f84
         // 140023159: test b1 al, b1 al
         // 14002315b: jz 0x1400239e5
      [-]ffff84c00f84
         // 00416290: test b1 al, b1 al
         // 00416292: jz 0x416917
      [-]ffff84c00f84
         // 004162a8: test b1 al, b1 al
         // 004162aa: jz 0x416917
      [-]00000f85
         // 140023a66: cmp b1 ds:[rbx+0xf0], b1 r15b
         // 140023a6d: jnz 0x1400241ff
      [-]ffff84c00f84
         // 00416317: test b1 al, b1 al
         // 00416319: jz 0x416916
      [-]ffff84c00f84
         // 0041633f: test b1 al, b1 al
         // 00416341: jz 0x41690f
      [-]00000f85
         // 00416391: cmp b1 ds:[esi+0x4c50], b1 0x0
         // 00416398: jnz 0x416cd0
      [-]81e2????????3b94
         // 004163ad: and edx, 0xfffe
         // 004163b3: cmp edx, ds:[esi+eax*0x4]
      [-]d3ea0fb6
         // 004163c1: shr edx, b1 cl
         // 004163c3: movzx ebx, b1 ds:[edx+esi+0x128]
      [-]07c1e803
         // 00415d30: shr eax, b1 0x3
      [-]83ff0873
         // 004164af: cmp edi, 0x8
         // 004164b2: jnb 0x4164bd
      [-]81e2????????3b94
         // 140023487: and b4 edx, b4 0xfffe
         // 14002348d: cmp b4 edx, b4 ds:[rbx+rax*0x4]
      [-]c183e107c1e803
         // 140023d41: and b4 ecx, b4 0x7
         // 140023d44: shr b4 eax, b1 0x3
      [-]85ed0f84
         // 140023dad: test b4 ebp, b4 ebp
         // 140023daf: jz 0x140023f7b
      [-]83fd040f82
         // 00415eca: cmp ebp, 0x4
         // 00415ecd: jb 0x416013
      [-]c183e107c1e803
         // 004166c8: mov eax, ecx
         // 004166ca: and ecx, 0x7
         // 004166cd: shr eax, b1 0x3
      [-]0183ff02
         // 00416119: cmp edi, 0x2
      [-]0283ff03
         // 00416128: cmp edi, 0x3
      [-]0383ff04
         // 00418824: cmp edi, 0x4
      [-]0483ff05
         // 0041882f: cmp edi, 0x5
      [-]ffff84c074
         // 004188a0: test b1 al, b1 al
         // 004188a2: jz 0x4188b8
      [-]ffff84c00f85
         // 00416907: test b1 al, b1 al
         // 00416909: jnz 0x4162ca
      [-]8a018802
         // 004162e2: mov b1 al, b1 ds:[ebx+0x1]
         // 004162e8: mov b1 ss:[ebp+0x1], b1 al
         // 004162eb: cmp edi, 0x2
      [-]81e2????????3b94
         // 00418a8b: and edx, 0xfffe
         // 00418a91: cmp edx, ds:[esi+eax*0x4]
      [-]0fb7f883ff0873
         // 00418b22: movzx edi, b2 ax
         // 00418b25: cmp edi, 0x8
         // 00418b28: jnb 0x418b2f
      [-]ffff84c0
         // 0041717c: test b1 al, b1 al
      [-]00000f84
         // 004171f2: cmp b1 ds:[esi+0x4ad2], b1 0x0
         // 004171f9: jz 0x4177af
      [-]0085c075
         // 004194ae: test eax, eax
         // 004194b0: jnz 0x4194b5
      [-]0085c075
         // 00419189: test eax, eax
         // 0041918b: jnz 0x419195
      [-]0085c075
         // 0041baa7: test eax, eax
         // 0041baa9: jnz 0x41bac6
      [-]83f82872
         // 0041bd26: cmp eax, 0x28
         // 0041bd29: jb 0x41bd0e
      [-]0000eb0a
         // 0041a425: jmp 0x41a431
      [-]000085c07403
         // 140027a5d: test b4 eax, b4 eax
         // 140027a5f: jz 0x140027a64
      [-]00000083f87d7d
         // 1400284aa: cmp b4 eax, b4 0x7d
         // 1400284ad: jge 0x1400284c2
      [-]00000083f87d7d
         // 1400284b9: cmp b4 eax, b4 0x7d
         // 1400284bc: jge 0x1400284c2
      [-]000085c07403
         // 0041a7ac: test eax, eax
         // 0041a7ae: jz 0x41a7b3
      [-]99f77c24
         // 0041ab14: cdq 
         // 0041ab15: idiv ss:[esp+0x20]
      [-]ffff84c00f84
         // 0041d6ad: test b1 al, b1 al
         // 0041d6af: jz 0x41d786
      [-]ffff85c075
         // 0041fa61: test eax, eax
         // 0041fa63: jnz 0x41fac9
      [-]1f3c0e75
         // 0041b92f: and eax, 0x1f
         // 0041b932: cmp b1 al, b1 0xe
         // 0041b934: jnz 0x41b987
      [-]00007409
         // 0041da31: jz 0x41da3c
      [-]85c07e0a
         // 0041e1ac: test eax, eax
         // 0041e1ae: jle 0x41e1ba
      [-]85c07902
         // 00420650: test eax, eax
         // 00420652: jns 0x420656
      [-]85c07505
         // 0041e6ba: test eax, eax
         // 0041e6bc: jnz 0x41e6c3
      [-]0085c07505
         // 14003184d: test b4 eax, b4 eax
         // 14003184f: jnz 0x140031856
      [-]85c07505
         // 14003c470: test rax, rax
         // 14003c473: jnz 0x14003c47a
      [-]83cfffeb
         // 0042aae7: or edi, 0xffffffffffffffff
         // 0042aaea: jmp 0x42aafe

  }
  condition:
    all of them
}
