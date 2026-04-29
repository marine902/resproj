rule uztuby_40_0 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         0084c07508
         // 00406e2e: test b1 al, b1 al
         // 00406e30: jnz 0x406e3a
      [-]0a01eb02
         // 00407b41: jmp 0x407b45
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
      [-]000084c0
         // 0040c38f: test b1 al, b1 al
      [-]83f8ff74
         // 0040c39f: cmp eax, 0xffffffffffffffff
         // 0040c3a2: jz 0x40c3d8
      [-]8a41fc3001
         // 0040e8f5: mov b1 al, b1 ds:[ecx+0xfffffffffffffffc]
         // 0040e8f8: xor b1 ds:[ecx], b1 al
      [-]83c00283
         // 14001b60a: add rax, 0x2
         // 14001b60e: and b4 ebx, b4 0xf
      [-]0f83e00f
         // 14001b611: and b4 eax, b4 0xf
      [-]83c00283
         // 14001b87c: add rax, 0x2
         // 14001b880: and b4 ebx, b4 0xf
      [-]83f83f76
         // 0040fdeb: cmp eax, 0x3f
         // 0040fdee: jbe 0x40fe45
      [-]008bf885
         // 00412c06: mov edi, eax
         // 00412c0b: test edi, edi
      [-]ffff3d????????72
         // 00410c49: cmp eax, 0x600
         // 00410c4e: jb 0x410c7d
      [-]0083f80275
         // 14001e55f: cmp b4 eax, b4 0x2
         // 14001e562: jnz 0x14001e5bd
      [-]ffff3d????????
         // 14001dbfd: cmp b4 eax, b4 0x600
      [-]010f97c0
         // 00413d6e: setnbe b1 al
      [-]888700010000
         // 00413d71: mov b1 ds:[edi+0x100], b1 al
      [-]0085c00f95c0
         // 00411be8: test eax, eax
         // 00411bea: setnz b1 al
      [-]0085c075
         // 140026b9a: test b4 eax, b4 eax
         // 140026b9c: jnz 0x140026ba5
      [-]83f82872
         // 0041bd26: cmp eax, 0x28
         // 0041bd29: jb 0x41bd0e
      [-]0000eb0a
         // 0041a425: jmp 0x41a431
      [-]000085c07403
         // 140027a5d: test b4 eax, b4 eax
         // 140027a5f: jz 0x140027a64
      [-]00000083f87d7d
         // 00419c91: cmp eax, 0x7d
         // 00419c94: jge 0x419ca5
      [-]00000083f87d7d
         // 00419c9d: cmp eax, 0x7d
         // 00419ca0: jge 0x419ca5
      [-]000085c07403
         // 0041c73c: test eax, eax
         // 0041c73e: jz 0x41c743
      [-]ffff84c00f84
         // 0041fa13: test b1 al, b1 al
         // 0041fa15: jz 0x41fae4
      [-]1f3c0e75
         // 14002f423: and b1 al, b1 0x1f
         // 14002f425: cmp b1 al, b1 0xe
         // 14002f427: jnz 0x14002f496
      [-]00007409
         // 0041da31: jz 0x41da3c
      [-]85c07e0a
         // 0041e1ac: test eax, eax
         // 0041e1ae: jle 0x41e1ba
      [-]85c07902
         // 00420650: test eax, eax
         // 00420652: jns 0x420656
      [-]85c07505
         // 00420b97: test eax, eax
         // 00420b99: jnz 0x420ba0
      [-]0085c07505
         // 0041e7ed: test eax, eax
         // 0041e7ef: jnz 0x41e7f6
      [-]85c07505
         // 0042aae3: test eax, eax
         // 0042aae5: jnz 0x42aaec
      [-]83cfffeb
         // 0042aae7: or edi, 0xffffffffffffffff
         // 0042aaea: jmp 0x42aafe

  }
  condition:
    all of them
}
