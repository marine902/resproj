rule uztuby_50_0 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         0085c074
         // 004013a0: test eax, eax
         // 004013a2: jz 0x4013d5
      [-]0085c074
         // 004013b0: test eax, eax
         // 004013b2: jz 0x4013d5
      [-]84c07508
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
      [-]01000083f8ff74
         // 0040c39f: cmp eax, 0xffffffffffffffff
         // 0040c3a2: jz 0x40c3d8
      [-]0000008b
         // 0040f94a: mov ecx, esi
      [-]0085c074
         // 00410213: test eax, eax
         // 00410215: jz 0x41021b
      [-]8a41fc3001
         // 0040e8f5: mov b1 al, b1 ds:[ecx+0xfffffffffffffffc]
         // 0040e8f8: xor b1 ds:[ecx], b1 al
      [-]55565774
         // 0040f46a: push ebp
         // 0040f46b: push esi
         // 0040f46c: push edi
         // 0040f46d: jz 0x40f479
      [-]0f83e00f8b
         // 14001b611: and b4 eax, b4 0xf
         // 14001b614: mov b4 edx, b4 ds:[r13+rcx*0x4]
      [-]0783e10f83c00283
         // 0040f9c9: lea edi, ds:[eax+0x7]
         // 0040f9cc: and ecx, 0xf
         // 0040f9cf: add eax, 0x2
         // 0040f9d2: and edi, 0xf
      [-]105f5e5d
         // 0040fccd: add ds:[eax+0x10], edi
         // 0040fcd0: pop edi
         // 0040fcd1: pop esi
         // 0040fcd2: pop ebp
      [-]83f83f76
         // 00411e30: cmp eax, 0x3f
         // 00411e33: jbe 0x411e8b
      [-]ffff3d????????72
         // 00410c49: cmp eax, 0x600
         // 00410c4e: jb 0x410c7d
      [-]0083f80275
         // 14001e55f: cmp b4 eax, b4 0x2
         // 14001e562: jnz 0x14001e5bd
      [-]ffff3d????????
         // 14001dbfd: cmp b4 eax, b4 0x600
      [-]010f97c0888700010000
         // 00411bd8: setnbe b1 al
         // 00411bdb: mov b1 ds:[edi+0x100], b1 al
      [-]0085c00f95c088
         // 00411be8: test eax, eax
         // 00411bea: setnz b1 al
         // 00411bed: mov b1 ds:[esi+edi], b1 al
      [-]0085c075
         // 004194ae: test eax, eax
         // 004194b0: jnz 0x4194b5
      [-]83c00283f82872
         // 0041bd23: add eax, 0x2
         // 0041bd26: cmp eax, 0x28
         // 0041bd29: jb 0x41bd0e
      [-]0000eb0a
         // 0041a425: jmp 0x41a431
      [-]000085c07403
         // 140027a5d: test b4 eax, b4 eax
         // 140027a5f: jz 0x140027a64
      [-]00008bd0
         // 0041a466: mov edx, eax
      [-]00000083f87d7d
         // 00419c91: cmp eax, 0x7d
         // 00419c94: jge 0x419ca5
      [-]00000083f87d7d
         // 00419c9d: cmp eax, 0x7d
         // 00419ca0: jge 0x419ca5
      [-]000085c07403
         // 0041c73c: test eax, eax
         // 0041c73e: jz 0x41c743
      [-]ffff84c075
         // 0041a814: test b1 al, b1 al
         // 0041a816: jnz 0x41a82e
      [-]ffff84c00f84
         // 0041fa13: test b1 al, b1 al
         // 0041fa15: jz 0x41fae4
      [-]1f3c0e75
         // 14002f423: and b1 al, b1 0x1f
         // 14002f425: cmp b1 al, b1 0xe
         // 14002f427: jnz 0x14002f496
      [-]0001c605
         // 0041da07: mov b1 ds:[0x448456], b1 0x1
      [-]0001ff15
         // 0041da0e: call ds:[ShowWindow]
      [-]00007409
         // 0041da31: jz 0x41da3c
      [-]85c07e0a
         // 0041e1ac: test eax, eax
         // 0041e1ae: jle 0x41e1ba
      [-]85c07902
         // 00420650: test eax, eax
         // 00420652: jns 0x420656
      [-]0085c07505
         // 0041e6ba: test eax, eax
         // 0041e6bc: jnz 0x41e6c3
      [-]33d28bc88b
         // 140031709: xor b4 edx, b4 edx
         // 14003170b: mov rcx, rax
         // 14003170e: mov rax, rdi
      [-]ffffff8b
         // 0041e7a2: mov esi, eax
      [-]0085c07505
         // 0041e7ed: test eax, eax
         // 0041e7ef: jnz 0x41e7f6
      [-]85c07505
         // 0042aae3: test eax, eax
         // 0042aae5: jnz 0x42aaec
      [-]83cfffeb
         // 0042aae7: or edi, 0xffffffffffffffff
         // 0042aaea: jmp 0x42aafe
      [-]00b001c3
         // 0042c057: mov b1 al, b1 0x1
         // 0042c059: retn 

  }
  condition:
    all of them
}
