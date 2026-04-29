rule uztuby_20_2 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         0084c07508
         // 00406e2e: test b1 al, b1 al
         // 00406e30: jnz 0x406e3a
      [-]0a01eb02
         // 14000abee: jmp 0x14000abf2
      [-]83e80174
         // 14000b0c9: sub b4 r8d, b4 0x1
         // 14000b0cd: jz 0x14000b0f6
      [-]83e8017414
         // 14000b0cf: sub b4 r8d, b4 0x1
         // 14000b0d3: jz 0x14000b0e9
      [-]8339007502
         // 14000b0de: cmp b4 ds:[rcx], b4 0x0
         // 14000b0e1: jnz 0x14000b0e5
      [-]83390b74
         // 14000b0e9: cmp b4 ds:[rcx], b4 0xb
         // 14000b0ec: jz 0x14000b0e5
      [-]c701????????eb
         // 14000b0ee: mov b4 ds:[rcx], b4 0x3
         // 14000b0f4: jmp 0x14000b0e5
      [-]c701????????eb
         // 14000b0fb: mov b4 ds:[rcx], b4 0x2
         // 14000b101: jmp 0x14000b0e5
      [-]8079080075
         // 0040701e: cmp b1 ds:[ecx+0x8], b1 0x0
         // 00407022: jnz 0x40702b
      [-]000084c0
         // 0040a582: test b1 al, b1 al
      [-]83f8ff74
         // 0040a4ef: cmp eax, 0xffffffffffffffff
         // 0040a4f2: jz 0x40a4df
      [-]0085c075
         // 0040a698: test eax, eax
         // 0040a69a: jnz 0x40a6b0
      [-]83c00283
         // 0040f07a: add eax, 0x2
         // 0040f07d: and esi, 0xf
      [-]0f83e00f
         // 0040f080: and eax, 0xf
      [-]83c00283
         // 14001c090: add rax, 0x2
         // 14001c094: and b4 eax, b4 0xf
      [-]8d48f983
         // 14001c13a: lea rcx, ds:[rax+0xfffffffffffffff9]
         // 14001c14a: and b4 eax, b4 0xf
      [-]83f83f76
         // 0040f68e: cmp eax, 0x3f
         // 0040f691: jbe 0x40f6e8
      [-]008bf885
         // 14001d8ec: mov b4 edi, b4 eax
         // 14001d8ee: test b4 eax, b4 eax
      [-]ffff3d????????72
         // 00410c49: cmp eax, 0x600
         // 00410c4e: jb 0x410c7d
      [-]0083f80275
         // 14001e55f: cmp b4 eax, b4 0x2
         // 14001e562: jnz 0x14001e5bd
      [-]ffff3d????????
         // 14001dc3d: cmp b4 eax, b4 0x600
      [-]010f97c0
         // 004113ce: setnbe b1 al
      [-]888700010000
         // 004113d1: mov b1 ds:[edi+0x100], b1 al
      [-]0085c00f95c0
         // 004113de: test eax, eax
         // 004113e0: setnz b1 al
      [-]8308ffb8????????
         // 140026325: or b4 ds:[rax], b4 0xffffffffffffffff
         // 140026328: mov b4 eax, b4 0xffffffff80020006
      [-]0085c075
         // 14001b66a: test b4 eax, b4 eax
         // 14001b66c: jnz 0x14001b675
      [-]83f82872
         // 1400271ea: cmp rax, 0x28
         // 1400271ee: jb 0x1400271d0
      [-]0000eb0a
         // 00419b75: jmp 0x419b81
      [-]000085c07403
         // 14001cd2d: test b4 eax, b4 eax
         // 14001cd2f: jz 0x14001cd34
      [-]00000083f87d7d
         // 00419d21: cmp eax, 0x7d
         // 00419d24: jge 0x419d35
      [-]00000083f87d7d
         // 00419d2d: cmp eax, 0x7d
         // 00419d30: jge 0x419d35
      [-]000085c07403
         // 00419f01: test eax, eax
         // 00419f03: jz 0x419f08
      [-]99f77c24
         // 14001db7f: cdq 
         // 14001db80: idiv b4 ss:[rsp+0x64]
      [-]0085c074
         // 14001f718: test b4 eax, b4 eax
         // 14001f71a: jz 0x14001f760
      [-]ffff84c074
         // 0041ae3d: test b1 al, b1 al
         // 0041ae3f: jz 0x41ae80
      [-]ffff84c00f84
         // 0041cd3d: test b1 al, b1 al
         // 0041cd3f: jz 0x41ce16
      [-]1f3c0e75
         // 0041cd9f: and eax, 0x1f
         // 0041cda2: cmp b1 al, b1 0xe
         // 0041cda4: jnz 0x41cdfa
      [-]00007409
         // 14002415d: jz 0x140024168
      [-]85c07e0a
         // 0041d86c: test eax, eax
         // 0041d86e: jle 0x41d87a
      [-]85c07902
         // 14003045f: test b4 eax, b4 eax
         // 140030461: jns 0x140030465
      [-]85c07505
         // 0041dd89: test eax, eax
         // 0041dd8b: jnz 0x41dd92
      [-]0085c07505
         // 0041dec7: test eax, eax
         // 0041dec9: jnz 0x41ded0
      [-]85c07505
         // 004279e0: test eax, eax
         // 004279e2: jnz 0x4279e9
      [-]83cfffeb
         // 14003e10c: or b4 edi, b4 0xffffffffffffffff
         // 14003e10f: jmp 0x14003e11f

  }
  condition:
    all of them
}
