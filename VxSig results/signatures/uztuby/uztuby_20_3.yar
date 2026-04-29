rule uztuby_20_3 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         0085c074
         // 00401321: test eax, eax
         // 00401323: jz 0x401356
      [-]0085c074
         // 1400025b2: test rax, rax
         // 1400025b5: jz 0x1400025df
      [-]01000084c075
         // 004018d3: test b1 al, b1 al
         // 004018d5: jnz 0x4018f6
      [-]83e00f03d083b9
         // 0040190c: and eax, 0xf
         // 0040190f: add edx, eax
         // 00401911: cmp ds:[ecx+0x6cb0], 0x3
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
         // 140003682: cmp b4 eax, b4 0x3
         // 140003685: jnz 0x1400036bc
      [-]83f80375
         // 00401ca1: cmp eax, 0x3
         // 00401ca4: jnz 0x401cc7
      [-]000085c075
         // 00401cdf: test eax, eax
         // 00401ce1: jnz 0x401c9b
      [-]ff0f95c0c3
         // 00401d76: setnz b1 al
         // 00401d79: retn 
      [-]000084c0
         // 00401f5b: test b1 al, b1 al
      [-]ffff84c075
         // 140003b94: test b1 al, b1 al
         // 140003b96: jnz 0x140003bb8
      [-]00000075
         // 00403e83: jnz 0x403edb
      [-]bd????????
         // 004040c0: mov ebp, 0x200
      [-]0f188f00020000
         // 004040e0: prefetcht0 b1 ds:[edi+0x200]
      [-]000003fd2b
         // 140007268: add rdi, rbp
         // 14000726b: sub rbx, rbp
      [-]07660f72
         // 004046a2: pslld b16 xmm1, b1 0x19
      [-]07660f72
         // 00404930: pslld b16 xmm1, b1 0x19
      [-]72d00c660f72
         // 00404b5c: pslld b16 xmm4, b1 0x14
      [-]07660f72
         // 00404bc2: pslld b16 xmm1, b1 0x19
      [-]07660f72
         // 00404c8a: pslld b16 xmm1, b1 0x19
      [-]0c660f72
         // 00404d14: pslld b16 xmm4, b1 0x14
      [-]07660f72
         // 00404d75: psrld b16 xmm0, b1 0x7
         // 00404d7a: pslld b16 xmm1, b1 0x19
      [-]0c660f72
         // 00404dea: pslld b16 xmm4, b1 0x14
      [-]07660f72
         // 00404e58: pslld b16 xmm1, b1 0x19
      [-]0c660f72
         // 00404fa4: pslld b16 xmm4, b1 0x14
      [-]07660f72
         // 004050e6: pslld b16 xmm1, b1 0x19
      [-]07660f72
         // 0040529e: pslld b16 xmm1, b1 0x19
      [-]8300408b
         // 00405645: add ds:[eax], 0x40
         // 00405648: mov ecx, ds:[edi]
      [-]83c70483ff207c
         // 004056df: add edi, 0x4
         // 004056e2: cmp edi, 0x20
         // 004056e5: jl 0x4056d3
      [-]89040a83c20483fa207c
         // 00405750: mov ds:[edx+ecx], eax
         // 00405753: add edx, 0x4
         // 00405756: cmp edx, 0x20
         // 00405759: jl 0x405744
      [-]8130????????8b
         // 0040573d: xor ds:[eax], 0x2080020
         // 00405749: mov eax, ss:[esp+0xc]
      [-]8300408b
         // 004057b1: add ds:[eax], 0x40
         // 004057b4: mov ecx, ds:[esi+0xf8]
      [-]ffffeb05
         // 140008922: jmp 0x140008929
      [-]feffff83
         // 004059a9: add esi, 0x20
      [-]83ff0872
         // 140008aba: cmp b4 edi, b4 0x8
         // 140008abd: jb 0x140008aa4
      [-]08000001
         // 00405905: mov b1 ds:[esi+0x83c], b1 0x1
      [-]fdffff83c74081
         // 00405a89: add edi, 0x40
         // 00405a8c: add ebp, 0x108
      [-]83e103c1e103d3e033
         // 00405fc6: and ecx, 0x3
         // 00405fc9: shl ecx, b1 0x3
         // 00405fcc: shl eax, b1 cl
         // 00405fce: xor eax, ebx
      [-]030000eb1b
         // 0040621d: jmp 0x40623a
      [-]c1e810884424
         // 140009eb8: shr b4 eax, b1 0x10
         // 140009ebb: mov b1 ss:[rsp+0x32], b1 al
      [-]c1e90e8844
         // 0040639d: shr ecx, b1 0xe
         // 004063a0: mov b1 ss:[esp+ecx+0x28], b1 al
      [-]00005f5e
         // 14000a0ba: call __security_check_cookie
         // 14000a0ce: pop rdi
         // 14000a0cf: pop rsi
      [-]85c00f84
         // 14000a721: test b4 eax, b4 eax
         // 14000a723: jz 0x14000a8fd
      [-]2bc303cb
         // 00406859: sub eax, ebx
         // 0040685b: add ecx, ebx
      [-]00005f5e
         // 14000a7e3: call __security_check_cookie
         // 14000a7ff: pop rdi
         // 14000a800: pop rsi
      [-]84c07508
         // 00406d2c: test b1 al, b1 al
         // 00406d2e: jnz 0x406d38
      [-]0a01eb02
         // 00406bcd: jmp 0x406bd1
      [-]83e80174
         // 00406d8e: sub eax, 0x1
         // 00406d91: jz 0x406db9
      [-]83e8017414
         // 00406d93: sub eax, 0x1
         // 00406d96: jz 0x406dac
      [-]c701????????eb
         // 00406db1: mov ds:[ecx], 0x3
         // 00406db7: jmp 0x406da6
      [-]c701????????eb
         // 00406dc3: mov ds:[ecx], 0x2
         // 00406dc9: jmp 0x406da6
      [-]8079080075
         // 0040701e: cmp b1 ds:[ecx+0x8], b1 0x0
         // 00407022: jnz 0x40702b
      [-]00000075
         // 0040812a: jnz 0x408160
      [-]000084c0
         // 00408137: call 0x411b42
         // 0040813c: test b1 al, b1 al
      [-]0000eb05
         // 004094bc: jmp 0x4094c3
      [-]84c07404
         // 00409bfd: test b1 al, b1 al
         // 00409bff: jz 0x409c05
      [-]ffff32c0
         // 00409f2a: xor b1 al, b1 al
      [-]000084c0
         // 0040a582: test b1 al, b1 al
      [-]01000083f8ff74
         // 0040a592: cmp eax, 0xffffffffffffffff
         // 0040a595: jz 0x40a5cb
      [-]0085c075
         // 1400141dd: test b4 eax, b4 eax
         // 1400141df: jnz 0x1400141f3
      [-]07c1e803010189
         // 0040a88d: shr eax, b1 0x3
         // 0040a890: add ds:[ecx], eax
         // 0040a892: mov ds:[ecx+0x4], edx
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
         // 1400146a1: cmp b4 ds:[rdx], b4 0x2
         // 1400146a4: jnz 0x1400146d2
      [-]83390375
         // 1400146b1: cmp b4 ds:[rcx], b4 0x3
         // 1400146b4: jnz 0x1400146d2
      [-]833a0375
         // 1400146b6: cmp b4 ds:[rdx], b4 0x3
         // 1400146b9: jnz 0x1400146d2
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
      [-]0000008b
         // 1400156de: mov rax, rbx
      [-]3a0f94c0
         // 0040bc92: setz b1 al
      [-]00000000
      [-]84c00f84
         // 0040d1d8: test b1 al, b1 al
         // 0040d1da: jz 0x40d295
      [-]00000074
         // 0040c789: jz 0x40c79f
      [-]000084c074
         // 0040c7eb: test b1 al, b1 al
         // 0040c7ed: jz 0x40c7fe
      [-]0000008b
         // 0040cb03: mov ecx, esi
      [-]0085c074
         // 0040da67: test eax, eax
         // 0040da69: jz 0x40da6f
      [-]c1ef0480
         // 0040d64b: shr edi, b1 0x4
         // 0040d64e: cmp b1 ss:[ebp+0x0], b1 0x0
      [-]85ff0f84
         // 0040d682: test edi, edi
         // 0040d684: jz 0x40dadb
      [-]8bc1c1e00403
         // 0040db39: mov eax, ecx
         // 0040db3b: shl eax, b1 0x4
         // 0040db3e: add eax, ss:[esp+0x14]
      [-]8d40f0660f38dec885c97f
         // 0040eecb: lea eax, ds:[eax+0xfffffffffffffff0]
         // 0040eece: aesdec b16 xmm1, b16 xmm0
         // 0040eed3: test ecx, ecx
         // 0040eed5: jg 0x40eec7
      [-]807a0100
         // 0040eed7: cmp b1 ds:[edx+0x1], b1 0x0
      [-]660f38dfc874
         // 0040eedf: aesdeclast b16 xmm1, b16 xmm0
         // 0040eee4: jz 0x40eeea
      [-]8a41fc3001
         // 0040dd47: mov b1 al, b1 ds:[ecx+0xfffffffffffffffc]
         // 0040dd4a: xor b1 ds:[ecx], b1 al
      [-]55565774
         // 0040e0a0: push ebp
         // 0040e0a1: push esi
         // 0040e0a2: push edi
         // 0040e0a3: jz 0x40e0af
      [-]0f83e00f8b
         // 0040f7e3: and eax, 0xf
         // 0040f7e6: mov edx, ds:[edx+ecx*0x4]
      [-]0783e10f83c00283
         // 0040f9c9: lea edi, ds:[eax+0x7]
         // 0040f9cc: and ecx, 0xf
         // 0040f9cf: add eax, 0x2
         // 0040f9d2: and edi, 0xf
      [-]105f5e5d
         // 0040fcd0: pop edi
         // 0040fcd1: pop esi
         // 0040fcd2: pop ebp
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
      [-]ffff8d433f3b
         // 0040f75d: lea eax, ds:[ebx+0x3f]
         // 0040f760: cmp eax, esi
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
         // 0040f950: cmp edi, 0x40
         // 0040f953: jnz 0x40f95d
      [-]01008bf8
         // 0040f68d: mov edi, eax
      [-]ffff3d????????72
         // 0040f787: cmp eax, 0x600
         // 0040f78c: jb 0x40f799
      [-]0083f80275
         // 00410c78: cmp eax, 0x2
         // 00410c7b: jnz 0x410ca6
      [-]ffff3d????????
         // 0040f842: cmp eax, 0x600
      [-]0085c074
         // 00410da4: test eax, eax
         // 00410da6: jz 0x410df3
      [-]000000ff
         // 0040fa71: call ds:[CloseHandle]
      [-]0083f8ff75
         // 0041085a: cmp eax, 0xffffffffffffffff
         // 0041085d: jnz 0x410886
      [-]ffffff83f80173
         // 0040fcd9: cmp eax, 0x1
         // 0040fcdc: jnb 0x40fce2
      [-]ffff80bf
         // 0040fd0b: cmp b1 ds:[edi+0x194], b1 0x0
      [-]0000007404
         // 0040fd12: jz 0x40fd18
      [-]ffffff84c074
         // 0040fd6e: test b1 al, b1 al
         // 0040fd70: jz 0x40fdb2
      [-]8bf9ff15
         // 004113c2: mov edi, ecx
         // 004113c4: call ds:[GetCPInfo]
      [-]010f97c0888700010000
         // 004113ce: setnbe b1 al
         // 004113d1: mov b1 ds:[edi+0x100], b1 al
      [-]0085c00f95c088
         // 0041073b: test eax, eax
         // 0041073d: setnz b1 al
         // 00410740: mov b1 ds:[esi+edi], b1 al
      [-]00006689
         // 140020e07: mov b2 ds:[rdi+0x2fe0], b2 si
      [-]83fa2072
         // 004123b3: cmp edx, 0x20
         // 004123b6: jb 0x4123ab
      [-]010fb602c1e10803c8
         // 00412ac9: movzx eax, b1 ds:[edx]
         // 00412acc: shl ecx, b1 0x8
         // 00412acf: add ecx, eax
      [-]c1e802c1e1082bc80fb6
         // 00412ad3: shr eax, b1 0x2
         // 00412ad6: shl ecx, b1 0x8
         // 00412ad9: sub ecx, eax
         // 00412adb: movzx eax, b1 ds:[edx+0xffffffffffffffff]
      [-]03c88bc188
         // 00412adf: add ecx, eax
         // 00412ae1: mov eax, ecx
         // 00412ae3: mov b1 ds:[edx+0xffffffffffffffff], b1 cl
      [-]c1e808c1e910880288
         // 00412ae6: shr eax, b1 0x8
         // 00412ae9: shr ecx, b1 0x10
         // 00412aec: mov b1 ds:[edx], b1 al
         // 00412aee: mov b1 ds:[edx+0x1], b1 cl
      [-]8d81????????8907eb
         // 00412b45: lea eax, ds:[ecx+0x1000000]
         // 00412b4b: mov ds:[edi], eax
         // 00412b4d: jmp 0x412b5d
      [-]8d81????????85c079
         // 00412b4f: lea eax, ds:[ecx+0xffffffffff000000]
         // 00412b55: test eax, eax
         // 00412b57: jns 0x412b5d
      [-]83e81039
         // 140022c3f: sub b4 eax, b4 0x10
         // 140022c42: cmp b4 ds:[rdx], b4 eax
      [-]000084c074
         // 00412cea: test b1 al, b1 al
         // 00412cec: jz 0x412d4b
      [-]0000008b
         // 1400223da: call 0x14002244c
         // 1400223e4: mov rcx, rsi
      [-]2bfa7907
         // 00414e61: sub edi, edx
         // 00414e63: jns 0x414e6c
      [-]81fa????????7e
         // 00413b63: cmp edx, 0x4000
         // 00413b69: jle 0x413b8b
      [-]00000074
         // 140022b71: jz 0x140022be1
      [-]5f5e5d5b
         // 004141b7: pop edi
         // 004141b8: pop esi
         // 004141b9: pop ebp
         // 004141ba: pop ebx
      [-]ffff84c00f84
         // 140023159: test b1 al, b1 al
         // 14002315b: jz 0x1400239e5
      [-]ffff84c00f84
         // 00415c3d: test b1 al, b1 al
         // 00415c3f: jz 0x416268
      [-]ffff84c00f84
         // 00415c55: test b1 al, b1 al
         // 00415c57: jz 0x416268
      [-]ffff84c00f84
         // 00415001: test b1 al, b1 al
         // 00415003: jz 0x4155a4
      [-]ffff84c00f84
         // 00415029: test b1 al, b1 al
         // 0041502b: jz 0x41559d
      [-]81e2????????3b94
         // 004163ad: and edx, 0xfffe
         // 004163b3: cmp edx, ds:[esi+eax*0x4]
      [-]d3ea0fb6
         // 004163c1: shr edx, b1 cl
         // 004163c3: movzx ebx, b1 ds:[edx+esi+0x128]
      [-]01000003
         // 004163cb: add ebx, ss:[ebp+0x4]
      [-]83ff0873
         // 00415180: cmp edi, 0x8
         // 00415183: jnb 0x415189
      [-]81e2????????3b94
         // 00415e95: and edx, 0xfffe
         // 00415e9b: cmp edx, ds:[esi+eax*0x4]
      [-]85ed0f84
         // 140023568: test b4 ebp, b4 ebp
         // 14002356a: jz 0x14002373a
      [-]83fd040f82
         // 140023db5: cmp b4 ebp, b4 0x4
         // 140023db8: jb 0x140023f3a
      [-]ffff84c074
         // 004168f7: test b1 al, b1 al
         // 004168f9: jz 0x41690f
      [-]ffff84c00f85
         // 00415595: test b1 al, b1 al
         // 00415597: jnz 0x414fb4
      [-]81e2????????3b94
         // 00416ade: and edx, 0xfffe
         // 00416ae4: cmp edx, ds:[esi+eax*0x4]
      [-]d3ea0fb6
         // 140023c5e: shr rdx, b1 cl
         // 140023c61: movzx b4 ecx, b1 ds:[rdx+rbx+0x1c68]
      [-]040fb784
         // 140023c7c: movzx b4 eax, b2 ds:[rbx+rdx*0x2]
      [-]0fb7f883ff0873
         // 00416b7d: movzx edi, b2 ax
         // 00416b80: cmp edi, 0x8
         // 00416b83: jnb 0x416b8a
      [-]8308ffb8????????
         // 00419474: or ds:[eax], 0xffffffffffffffff
         // 00419477: mov eax, 0xffffffff80020006
      [-]0085c075
         // 140026b9a: test b4 eax, b4 eax
         // 140026b9c: jnz 0x140026ba5
      [-]83c00283f82872
         // 00419da3: add eax, 0x2
         // 00419da6: cmp eax, 0x28
         // 00419da9: jb 0x419d8e
      [-]0000eb0a
         // 00419b75: jmp 0x419b81
      [-]000085c07403
         // 140027a5d: test b4 eax, b4 eax
         // 140027a5f: jz 0x140027a64
      [-]00008bd0
         // 004189bf: mov edx, eax
      [-]00000083f87d7d
         // 1400284aa: cmp b4 eax, b4 0x7d
         // 1400284ad: jge 0x1400284c2
      [-]00000083f87d7d
         // 1400284b9: cmp b4 eax, b4 0x7d
         // 1400284bc: jge 0x1400284c2
      [-]000085c07403
         // 00418ca1: test eax, eax
         // 00418ca3: jz 0x418ca8
      [-]ffff84c075
         // 00418cfa: test b1 al, b1 al
         // 00418cfc: jnz 0x418d14
      [-]99f77c24
         // 140029117: cdq 
         // 140029118: idiv b4 ss:[rsp+0x64]
      [-]0085c074
         // 14002a5f8: test b4 eax, b4 eax
         // 14002a5fa: jz 0x14002a640
      [-]ffff84c00f84
         // 0041d6ad: test b1 al, b1 al
         // 0041d6af: jz 0x41d786
      [-]ffff85c075
         // 0041d702: test eax, eax
         // 0041d704: jnz 0x41d76a
      [-]1f3c0e75
         // 0041b92f: and eax, 0x1f
         // 0041b932: cmp b1 al, b1 0xe
         // 0041b934: jnz 0x41b987
      [-]0001c605
         // 14002f920: mov b1 cs:[0x140067de2], b1 0x1
      [-]0001ff15
         // 14002f927: call cs:[ShowWindow]
      [-]00007409
         // 0041da31: jz 0x41da3c
      [-]85c07e0a
         // 0041c3c4: test eax, eax
         // 0041c3c6: jle 0x41c3d2
      [-]85c07902
         // 0041e1b4: test eax, eax
         // 0041e1b6: jns 0x41e1ba
      [-]0085c07505
         // 0041e6ba: test eax, eax
         // 0041e6bc: jnz 0x41e6c3
      [-]33d28bc88b
         // 0041c925: xor edx, edx
         // 0041c927: mov ecx, eax
         // 0041c929: mov eax, ss:[ebp+0xc]
      [-]ffffff8b
         // 0041e7a2: mov esi, eax
      [-]0085c07505
         // 14003184d: test b4 eax, b4 eax
         // 14003184f: jnz 0x140031856
      [-]85c07505
         // 14003c470: test rax, rax
         // 14003c473: jnz 0x14003c47a
      [-]83cfffeb
         // 00428295: or edi, 0xffffffffffffffff
         // 00428298: jmp 0x4282ac
      [-]00b001c3
         // 00428ab3: mov b1 al, b1 0x1
         // 00428ab5: retn 

  }
  condition:
    all of them
}
