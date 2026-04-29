rule uztuby_10_1 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         00006689
         // 1400035a7: mov b2 ds:[rbx+0x1468], b2 bp
      [-]01000084c075
         // 004018d3: test b1 al, b1 al
         // 004018d5: jnz 0x4018f6
      [-]00000074
         // 0040198e: jz 0x4019aa
      [-]03d083b9
         // 00401997: add edx, eax
         // 00401999: cmp ds:[ecx+0x6cc8], 0x3
      [-]83c210eb
         // 004019a2: add edx, 0x10
         // 004019a5: jmp 0x4019aa
      [-]000085c074
         // 00401a5d: test eax, eax
         // 00401a5f: jz 0x401aa0
      [-]83f8010f85
         // 00401a34: cmp eax, 0x1
         // 00401a37: jnz 0x401b3c
      [-]2bc180781c527512
         // 00401ac7: sub eax, ecx
         // 00401ac9: cmp b1 ds:[eax+0x1c], b1 0x52
         // 00401acd: jnz 0x401ae1
      [-]80781d53750c
         // 00401b2c: cmp b1 ds:[eax+0x1d], b1 0x53
         // 00401b30: jnz 0x401b3e
      [-]80781e467506
         // 00401b32: cmp b1 ds:[eax+0x1e], b1 0x46
         // 00401b36: jnz 0x401b3e
      [-]80781f5874
         // 00401b38: cmp b1 ds:[eax+0x1f], b1 0x58
         // 00401b3c: jz 0x401b48
      [-]83f80475
         // 00401b42: cmp eax, 0x4
         // 00401b45: jnz 0x401b57
      [-]83f80375
         // 00401b57: cmp eax, 0x3
         // 00401b5a: jnz 0x401b8a
      [-]00007504
         // 00401bff: cmp b1 ds:[edi+0x6cc4], b1 0x0
         // 00401c06: jnz 0x401c0c
      [-]0000740d
         // 00401c3b: cmp b1 ds:[edi+0x21e0], b1 0x0
         // 00401c42: jz 0x401c51
      [-]00000f85
         // 00401c44: cmp b1 ds:[edi+0x6cbc], b1 0x0
         // 00401c4b: jnz 0x401d36
      [-]83f80375
         // 00401ca1: cmp eax, 0x3
         // 00401ca4: jnz 0x401cc7
      [-]ff0f95c0c3
         // 00401d76: setnz b1 al
         // 00401d79: retn 
      [-]000084c0
         // 140003b82: test b1 al, b1 al
      [-]ffff84c075
         // 00401f2b: test b1 al, b1 al
         // 00401f2d: jnz 0x401f43
      [-]00000075
         // 00403e83: jnz 0x403edb
      [-]0084c075
         // 00403d53: test b1 al, b1 al
         // 00403d55: jnz 0x403d7f
      [-]bd????????eb
         // 004040c0: mov ebp, 0x200
         // 004040cd: jmp 0x4040f5
      [-]0f188f00020000
         // 004040e0: prefetcht0 b1 ds:[edi+0x200]
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
         // 00404e2c: pxor b16 xmm0, b16 xmm3
         // 00404e33: psrld b16 xmm0, b1 0xc
         // 00404e38: pslld b16 xmm3, b1 0x14
      [-]07660f72
         // 00404e8a: pslld b16 xmm0, b1 0x19
      [-]660f72d00c660f72
         // 00404f02: pxor b16 xmm0, b16 xmm3
         // 00404f09: psrld b16 xmm0, b1 0xc
         // 00404f0e: pslld b16 xmm3, b1 0x14
      [-]660f72d00c660f72
         // 00404fd5: psrld b16 xmm0, b1 0xc
         // 00404fda: pslld b16 xmm3, b1 0x14
      [-]07660f72
         // 0040503f: pslld b16 xmm0, b1 0x19
      [-]660f72d00c660f72
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
         // 004056e2: cmp edi, 0x20
         // 004056e5: jl 0x4056d3
      [-]83fa207c
         // 00405756: cmp edx, 0x20
         // 00405759: jl 0x405744
      [-]8130????????
         // 1400085cc: xor b4 ds:[rax], b4 0x2080020
      [-]ffffeb05
         // 140008922: jmp 0x140008929
      [-]83ff0872
         // 00405927: cmp edi, 0x8
         // 0040592a: jb 0x405918
      [-]ffff84c07404
         // 00405c68: test b1 al, b1 al
         // 00405c6a: jz 0x405c70
      [-]0084c074
         // 00406294: test b1 al, b1 al
         // 00406296: jz 0x4062c9
      [-]c1e810884424
         // 140009eb8: shr b4 eax, b1 0x10
         // 140009ebb: mov b1 ss:[rsp+0x32], b1 al
      [-]c1e90e8844
         // 14000a47d: shr rcx, b1 0xe
         // 14000a481: mov b1 ss:[rbp+rcx+0x40], b1 al
      [-]83e00389
         // 14000a5d0: and b4 eax, b4 0x3
         // 14000a5d3: mov b4 ds:[rbx+0x140], b4 eax
      [-]0085c00f84
         // 004065ad: test eax, eax
         // 004065af: jz 0x406757
      [-]84c07508
         // 14000b526: test b1 al, b1 al
         // 14000b528: jnz 0x14000b532
      [-]0a01eb02
         // 00406bcd: jmp 0x406bd1
      [-]83e80174
         // 00406d89: sub eax, 0x1
         // 00406d8c: jz 0x406d9f
      [-]83e80174
         // 00406d8e: sub eax, 0x1
         // 00406d91: jz 0x406db9
      [-]83e8017414
         // 00406d93: sub eax, 0x1
         // 00406d96: jz 0x406dac
      [-]8339007502
         // 00406d9f: cmp ds:[ecx], 0x0
         // 00406da2: jnz 0x406da6
      [-]83390b74
         // 00406dac: cmp ds:[ecx], 0xb
         // 00406daf: jz 0x406da6
      [-]c701????????eb
         // 00406db1: mov ds:[ecx], 0x3
         // 00406db7: jmp 0x406da6
      [-]c701????????eb
         // 00406dc3: mov ds:[ecx], 0x2
         // 00406dc9: jmp 0x406da6
      [-]8079080075
         // 00406e57: cmp b1 ds:[ecx+0x8], b1 0x0
         // 00406e5b: jnz 0x406e62
      [-]ffff84c00f84
         // 14000cf29: test b1 al, b1 al
         // 14000cf2b: jz 0x14000d077
      [-]000084c074
         // 00407509: test b1 al, b1 al
         // 0040750b: jz 0x407520
      [-]00000075
         // 0040812a: jnz 0x408160
      [-]ffff84c0
         // 14000ea1d: test b1 al, b1 al
      [-]000084c075
         // 00408411: test b1 al, b1 al
         // 00408413: jnz 0x4083f3
      [-]00000084c075
         // 004092de: test b1 al, b1 al
         // 004092e0: jnz 0x409323
      [-]000085c074
         // 00409206: test eax, eax
         // 00409208: jz 0x40922d
      [-]83f80174
         // 0040920a: cmp eax, 0x1
         // 0040920d: jz 0x40924e
      [-]83f80675
         // 0040930f: cmp eax, 0x6
         // 00409312: jnz 0x409323
      [-]000084c074
         // 00409246: test b1 al, b1 al
         // 00409248: jz 0x409259
      [-]85ff7403
         // 0040934a: test edi, edi
         // 0040934c: jz 0x409351
      [-]0000eb05
         // 004094bc: jmp 0x4094c3
      [-]84c07404
         // 00409bfd: test b1 al, b1 al
         // 00409bff: jz 0x409c05
      [-]ffff32c0
         // 00409c13: xor b1 al, b1 al
      [-]000084c0
         // 0040a582: test b1 al, b1 al
      [-]83f8ff74
         // 0040a592: cmp eax, 0xffffffffffffffff
         // 0040a595: jz 0x40a5cb
      [-]0085c075
         // 0040a364: test eax, eax
         // 0040a366: jnz 0x40a37c
      [-]0083f8120f95c0
         // 0040a370: cmp eax, 0x12
         // 0040a373: setnz b1 al
      [-]07c1e8030101
         // 0040a88d: shr eax, b1 0x3
         // 0040a890: add ds:[ecx], eax
      [-]8941088901
         // 0040a8d0: mov ds:[ecx+0x8], eax
         // 0040a8d3: mov ds:[ecx], eax
      [-]8339017505
         // 0040aa64: cmp ds:[ecx], 0x1
         // 0040aa67: jnz 0x40aa6e
      [-]833a01740a
         // 0040aa69: cmp ds:[edx], 0x1
         // 0040aa6c: jz 0x40aa78
      [-]8339027510
         // 0040aa6e: cmp ds:[ecx], 0x2
         // 0040aa71: jnz 0x40aa83
      [-]833a0275
         // 0040a68b: cmp ds:[edx], 0x2
         // 0040a68e: jnz 0x40a69b
      [-]83390375
         // 0040a69b: cmp ds:[ecx], 0x3
         // 0040a69e: jnz 0x40a6be
      [-]833a0375
         // 0040a6a0: cmp ds:[edx], 0x3
         // 0040a6a3: jnz 0x40a6be
      [-]32c0eb02
         // 0040aaa7: xor b1 al, b1 al
         // 0040aaa9: jmp 0x40aaad
      [-]83390175
         // 0040a79f: cmp ds:[ecx], 0x1
         // 0040a7a2: jnz 0x40a7aa
      [-]8b410489
         // 14001483c: mov b4 eax, b4 ds:[rcx+0x4]
         // 14001483f: mov b4 ds:[rbx], b4 eax
      [-]83390275
         // 0040abd4: cmp ds:[ecx], 0x2
         // 0040abd7: jnz 0x40abe0
      [-]8b4104f7d089
         // 140014846: mov b4 eax, b4 ds:[rcx+0x4]
         // 140014849: not b4 eax
         // 14001484b: mov b4 ds:[rbx], b4 eax
      [-]83390375
         // 0040abe0: cmp ds:[ecx], 0x3
         // 0040abe3: jnz 0x40ac00
      [-]3a0f94c0
         // 0040bc92: setz b1 al
      [-]00000074
         // 0040d1a2: jz 0x40d1c5
      [-]84c00f84
         // 140017ab6: test b1 al, b1 al
         // 140017ab8: jz 0x140017bde
      [-]000084c074
         // 0040c7eb: test b1 al, b1 al
         // 0040c7ed: jz 0x40c7fe
      [-]04????????eb
         // 14001ae6b: jmp 0x14001ae84
      [-]04????????
      [-]85ff0f84
         // 0040ea05: test edi, edi
         // 0040ea07: jz 0x40ee5f
      [-]8d40f0660f38dec8
         // 0040eecb: lea eax, ds:[eax+0xfffffffffffffff0]
         // 0040eece: aesdec b16 xmm1, b16 xmm0
      [-]807a0100
         // 0040eed7: cmp b1 ds:[edx+0x1], b1 0x0
      [-]660f38dfc874
         // 0040eedf: aesdeclast b16 xmm1, b16 xmm0
         // 0040eee4: jz 0x40eeea
      [-]83eb0175
         // 14001ab6d: sub r11, 0x1
         // 14001ab71: jnz 0x14001ab22
      [-]8a41fc3001
         // 0040dd47: mov b1 al, b1 ds:[ecx+0xfffffffffffffffc]
         // 0040dd4a: xor b1 ds:[ecx], b1 al
      [-]0000006689
         // 14001afef: mov b2 ds:[rbx+rdi*0x2], b2 si
      [-]83c00283
         // 0040f7dd: add eax, 0x2
         // 0040f7e0: and esi, 0xf
      [-]0f83e00f
         // 0040f7e3: and eax, 0xf
      [-]0783e10f
         // 0040f9c9: lea edi, ds:[eax+0x7]
         // 0040f9cc: and ecx, 0xf
      [-]83c00283
         // 0040f9cf: add eax, 0x2
         // 0040f9d2: and edi, 0xf
      [-]0f83e00f
         // 0040e7df: and esi, 0xf
         // 0040e7e2: and eax, 0xf
      [-]04????????c7
         // 14001c4ba: mov b4 ds:[rcx+0x8], b4 0xffffffff98badcfe
      [-]08????????c7
         // 14001c4c1: mov b4 ds:[rcx+0xc], b4 0x10325476
      [-]0c????????c7
         // 14001c4c8: mov b4 ds:[rcx+0x10], b4 0xffffffffc3d2e1f0
      [-]10????????
      [-]83f83f76
         // 0040fdeb: cmp eax, 0x3f
         // 0040fdee: jbe 0x40fe45
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
         // 14001c93a: cmp rdi, 0x40
         // 14001c93e: jnz 0x14001c94a
      [-]01008bf885
         // 00410b54: mov edi, eax
         // 00410b57: test edi, edi
      [-]ffff3d????????72
         // 14001e52a: cmp b4 eax, b4 0x600
         // 14001e52f: jb 0x14001e564
      [-]0083f80275
         // 0040f7ba: cmp eax, 0x2
         // 0040f7bd: jnz 0x40f7e3
      [-]ffff3d????????
         // 00410d06: cmp eax, 0x600
      [-]ffffff15
         // 00410d9e: call ds:[AllocConsole]
      [-]0085c074
         // 00410da4: test eax, eax
         // 00410da6: jz 0x410df3
      [-]000084c074
         // 0040f95a: test b1 al, b1 al
         // 0040f95c: jz 0x40f966
      [-]0000ff15
         // 00410f11: mov b1 ds:[esi+0x314], b1 0x1
         // 00410f21: call ds:[ReleaseSemaphore]
      [-]0083f8ff75
         // 00410ff0: cmp eax, 0xffffffffffffffff
         // 00410ff3: jnz 0x41101c
      [-]ffffff83f80173
         // 0040fcd9: cmp eax, 0x1
         // 0040fcdc: jnb 0x40fce2
      [-]feffff80bf
         // 00411101: cmp b1 ds:[edi+0x314], b1 0x0
      [-]0000007404
         // 00411108: jz 0x41110e
      [-]ffffff84c074
         // 0040fd6e: test b1 al, b1 al
         // 0040fd70: jz 0x40fdb2
      [-]ffff84c075
         // 004111c7: test b1 al, b1 al
         // 004111c9: jnz 0x41118a
      [-]010f97c0
         // 00411bd8: setnbe b1 al
      [-]888700010000
         // 00411bdb: mov b1 ds:[edi+0x100], b1 al
      [-]0085c00f95c0
         // 0041073b: test eax, eax
         // 0041073d: setnz b1 al
      [-]00006689
         // 0041217d: mov b2 ds:[esi+0x4c50], b2 bx
      [-]83fa2072
         // 004123b3: cmp edx, 0x20
         // 004123b6: jb 0x4123ab
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
         // 00412b45: lea eax, ds:[ecx+0x1000000]
         // 00412b4b: mov ds:[edi], eax
         // 00412b4d: jmp 0x412b5d
      [-]8d81????????85c079
         // 00412b4f: lea eax, ds:[ecx+0xffffffffff000000]
         // 00412b55: test eax, eax
         // 00412b57: jns 0x412b5d
      [-]83ee0175
         // 0041368e: sub esi, 0x1
         // 00413691: jnz 0x41364c
      [-]83e81039
         // 140022c3f: sub b4 eax, b4 0x10
         // 140022c42: cmp b4 ds:[rdx], b4 eax
      [-]000084c074
         // 00412cea: test b1 al, b1 al
         // 00412cec: jz 0x412d4b
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
         // 140022b71: jz 0x140022be1
      [-]ffff84c0
         // 0041717c: test b1 al, b1 al
      [-]00000f84
         // 1400254e2: cmp b1 ss:[rbp+0x2cde], b1 0x0
         // 1400254e9: jz 0x14002610b
      [-]8308ffb8????????
         // 00419474: or ds:[eax], 0xffffffffffffffff
         // 00419477: mov eax, 0xffffffff80020006
      [-]0085c075
         // 14002639a: test b4 eax, b4 eax
         // 14002639c: jnz 0x1400263a5
      [-]0085c075
         // 00418286: test eax, eax
         // 00418288: jnz 0x418292
      [-]0085c075
         // 140027669: test b4 eax, b4 eax
         // 14002766b: jnz 0x140027687
      [-]83f82872
         // 00419da6: cmp eax, 0x28
         // 00419da9: jb 0x419d8e
      [-]0000eb0a
         // 140028246: jmp 0x140028252
      [-]000085c07403
         // 140027a5d: test b4 eax, b4 eax
         // 140027a5f: jz 0x140027a64
      [-]00000083f87d7d
         // 00418ac6: cmp eax, 0x7d
         // 00418ac9: jge 0x418ada
      [-]00000083f87d7d
         // 00418ad2: cmp eax, 0x7d
         // 00418ad5: jge 0x418ada
      [-]000085c07403
         // 00418ca1: test eax, eax
         // 00418ca3: jz 0x418ca8
      [-]99f77c24
         // 140028903: cdq 
         // 140028904: idiv b4 ss:[rsp+0x64]
      [-]ffff84c00f84
         // 0041d6ad: test b1 al, b1 al
         // 0041d6af: jz 0x41d786
      [-]ffff85c075
         // 14002f413: test b4 eax, b4 eax
         // 14002f415: jnz 0x14002f496
      [-]1f3c0e75
         // 0041b92f: and eax, 0x1f
         // 0041b932: cmp b1 al, b1 0xe
         // 0041b934: jnz 0x41b987
      [-]00007409
         // 0041da31: jz 0x41da3c
      [-]85c07e0a
         // 0041c3c4: test eax, eax
         // 0041c3c6: jle 0x41c3d2
      [-]85c07902
         // 0041e1b4: test eax, eax
         // 0041e1b6: jns 0x41e1ba
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
         // 00428295: or edi, 0xffffffffffffffff
         // 00428298: jmp 0x4282ac

  }
  condition:
    all of them
}
