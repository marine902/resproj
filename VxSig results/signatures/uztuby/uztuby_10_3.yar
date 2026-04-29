rule uztuby_10_3 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         00006689
         // 140002afe: mov b2 ds:[rbx+0x1468], b2 bp
      [-]01000084c075
         // 004018d3: test b1 al, b1 al
         // 004018d5: jnz 0x4018f6
      [-]00000074
         // 00401905: jz 0x401922
      [-]03d083b9
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
      [-]00007504
         // 00401bff: cmp b1 ds:[edi+0x6cc4], b1 0x0
         // 00401c06: jnz 0x401c0c
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
         // 00401f5b: test b1 al, b1 al
      [-]ffff84c075
         // 140003b94: test b1 al, b1 al
         // 140003b96: jnz 0x140003bb8
      [-]00000075
         // 140006da3: jnz 0x140006df4
      [-]0084c075
         // 140006dba: test b1 al, b1 al
         // 140006dbc: jnz 0x140006de9
      [-]bd????????eb
         // 004040c0: mov ebp, 0x200
         // 004040cd: jmp 0x4040f5
      [-]0f188f00020000
         // 004040e0: prefetcht0 b1 ds:[edi+0x200]
      [-]84c07404
         // 140012cc1: test b1 al, b1 al
         // 140012cc3: jz 0x140012cc9
      [-]ffff32c0
         // 140012cd8: xor b1 al, b1 al
      [-]000084c0
         // 0040a582: test b1 al, b1 al
      [-]83f8ff74
         // 0040a592: cmp eax, 0xffffffffffffffff
         // 0040a595: jz 0x40a5cb
      [-]0085c075
         // 1400141dd: test b4 eax, b4 eax
         // 1400141df: jnz 0x1400141f3
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
      [-]3a0f94c0
         // 0040bc92: setz b1 al
      [-]00000074
         // 0040d1a2: jz 0x40d1c5
      [-]84c00f84
         // 140017ab6: test b1 al, b1 al
         // 140017ab8: jz 0x140017bde
      [-]000084c074
         // 0040d280: test b1 al, b1 al
         // 0040d282: jz 0x40d291
      [-]04????????eb
         // 0040e1e2: jmp 0x40e1fb
      [-]85ff0f84
         // 14001a623: test rdi, rdi
         // 14001a626: jz 0x14001a9bd
      [-]8d40f0660f38dec8
         // 0040eecb: lea eax, ds:[eax+0xfffffffffffffff0]
         // 0040eece: aesdec b16 xmm1, b16 xmm0
      [-]807a0100
         // 0040eed7: cmp b1 ds:[edx+0x1], b1 0x0
      [-]660f38dfc874
         // 0040eedf: aesdeclast b16 xmm1, b16 xmm0
         // 0040eee4: jz 0x40eeea
      [-]8a41fc3001
         // 0040dd47: mov b1 al, b1 ds:[ecx+0xfffffffffffffffc]
         // 0040dd4a: xor b1 ds:[ecx], b1 al
      [-]0000006689
         // 14001b94f: mov b2 ds:[rbx+rdi*0x2], b2 si
      [-]83c00283
         // 14001b64a: add rax, 0x2
         // 14001b64e: and b4 ebx, b4 0xf
      [-]0f83e00f
         // 14001b651: and b4 eax, b4 0xf
      [-]83c00283
         // 0040e5f1: add eax, 0x2
         // 0040e5f4: and edi, 0xf
      [-]8d48f983
         // 0040e69f: lea ecx, ds:[eax+0xfffffffffffffff9]
         // 0040e6a6: and ecx, 0xf
      [-]04????????c7
         // 14001c4ba: mov b4 ds:[rcx+0x8], b4 0xffffffff98badcfe
      [-]08????????c7
         // 14001c4c1: mov b4 ds:[rcx+0xc], b4 0x10325476
      [-]0c????????c7
         // 14001c4c8: mov b4 ds:[rcx+0x10], b4 0xffffffffc3d2e1f0
      [-]10????????
      [-]83f83f76
         // 0040ea11: cmp eax, 0x3f
         // 0040ea14: jbe 0x40ea6b
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
      [-]33c833ca
         // 0041010f: xor ecx, eax
         // 00410114: xor ecx, edx
      [-]01008bf885
         // 0040f68d: mov edi, eax
         // 0040f690: test edi, edi
      [-]ffff3d????????72
         // 0040f787: cmp eax, 0x600
         // 0040f78c: jb 0x40f799
      [-]0083f80275
         // 14001e55f: cmp b4 eax, b4 0x2
         // 14001e562: jnz 0x14001e5bd
      [-]ffff3d????????
         // 0040f842: cmp eax, 0x600
      [-]ffffff15
         // 00410d9e: call ds:[AllocConsole]
      [-]0085c074
         // 00410da4: test eax, eax
         // 00410da6: jz 0x410df3
      [-]000084c074
         // 00410692: test b1 al, b1 al
         // 00410694: jz 0x41069e
      [-]0000ff15
         // 00410f11: mov b1 ds:[esi+0x314], b1 0x1
         // 00410f21: call ds:[ReleaseSemaphore]
      [-]0083f8ff75
         // 0041085a: cmp eax, 0xffffffffffffffff
         // 0041085d: jnz 0x410886
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
      [-]010f97c0
         // 0041072b: setnbe b1 al
      [-]888700010000
         // 0041072e: mov b1 ds:[edi+0x100], b1 al
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
         // 00413b63: cmp edx, 0x4000
         // 00413b69: jle 0x413b8b
      [-]00000074
         // 140022b71: jz 0x140022be1
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
      [-]00000f85
         // 0041507c: cmp b1 ds:[esi+0x4c50], b1 0x0
         // 00415083: jnz 0x415977
      [-]81e2????????3b94
         // 004163ad: and edx, 0xfffe
         // 004163b3: cmp edx, ds:[esi+eax*0x4]
      [-]d3ea0fb6
         // 004163c1: shr edx, b1 cl
         // 004163c3: movzx ebx, b1 ds:[edx+esi+0x128]
      [-]07c1e803
         // 00416416: shr eax, b1 0x3
      [-]83ff0873
         // 00415180: cmp edi, 0x8
         // 00415183: jnb 0x415189
      [-]81e2????????3b94
         // 00415e95: and edx, 0xfffe
         // 00415e9b: cmp edx, ds:[esi+eax*0x4]
      [-]8bc183e107c1e803
         // 00416583: mov ecx, ss:[ebp+0x4]
         // 00416588: mov eax, ecx
         // 0041658a: and ecx, 0x7
         // 00416590: shr eax, b1 0x3
      [-]85ed0f84
         // 140023568: test b4 ebp, b4 ebp
         // 14002356a: jz 0x14002373a
      [-]83fd040f82
         // 140023db5: cmp b4 ebp, b4 0x4
         // 140023db8: jb 0x140023f3a
      [-]8bc183e107c1e803
         // 140023ef4: mov b4 eax, b4 ecx
         // 140023ef6: and b4 ecx, b4 0x7
         // 140023ef9: shr b4 eax, b1 0x3
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
         // 14002639a: test b4 eax, b4 eax
         // 14002639c: jnz 0x1400263a5
      [-]83f82872
         // 00419da6: cmp eax, 0x28
         // 00419da9: jb 0x419d8e
      [-]0000eb0a
         // 00419b75: jmp 0x419b81
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
         // 00418ca1: test eax, eax
         // 00418ca3: jz 0x418ca8
      [-]99f77c24
         // 00418f30: cdq 
         // 00418f31: idiv ss:[esp+0x20]
      [-]5f5e5d5b
         // 0041adcb: pop edi
         // 0041adcc: pop esi
         // 0041adcd: pop ebp
         // 0041adce: pop ebx
      [-]0085c074
         // 14002ae38: test b4 eax, b4 eax
         // 14002ae3a: jz 0x14002ae80
      [-]ffff84c074
         // 14002b078: test b1 al, b1 al
         // 14002b07a: jz 0x14002b0ce
      [-]ffff84c00f84
         // 0041b8c8: call 0x418abf
         // 0041b8cd: test b1 al, b1 al
         // 0041b8cf: jz 0x41b9a3
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
