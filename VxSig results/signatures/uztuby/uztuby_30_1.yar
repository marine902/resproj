rule uztuby_30_1 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         0084c07508
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
         // 0040701e: cmp b1 ds:[ecx+0x8], b1 0x0
         // 00407022: jnz 0x40702b
      [-]000084c0
         // 14001303d: test b1 al, b1 al
      [-]83f8ff74
         // 0040a592: cmp eax, 0xffffffffffffffff
         // 0040a595: jz 0x40a5cb
      [-]8a41fc3001
         // 0040dd47: mov b1 al, b1 ds:[ecx+0xfffffffffffffffc]
         // 0040dd4a: xor b1 ds:[ecx], b1 al
      [-]83c00283
         // 0040f7dd: add eax, 0x2
         // 0040f7e0: and esi, 0xf
      [-]0f83e00f
         // 0040f7e3: and eax, 0xf
      [-]83c00283
         // 14001c090: add rax, 0x2
         // 14001c094: and b4 eax, b4 0xf
      [-]83f83f76
         // 0040ea11: cmp eax, 0x3f
         // 0040ea14: jbe 0x40ea6b
      [-]008bf885
         // 00410b54: mov edi, eax
         // 00410b57: test edi, edi
      [-]ffff3d????????72
         // 14001e52a: cmp b4 eax, b4 0x600
         // 14001e52f: jb 0x14001e564
      [-]0083f80275
         // 14001e55f: cmp b4 eax, b4 0x2
         // 14001e562: jnz 0x14001e5bd
      [-]ffff3d????????
         // 14001dbfd: cmp b4 eax, b4 0x600
      [-]010f97c0
         // 00411bd8: setnbe b1 al
      [-]888700010000
         // 00411bdb: mov b1 ds:[edi+0x100], b1 al
      [-]0085c00f95c0
         // 00411be8: test eax, eax
         // 00411bea: setnz b1 al
      [-]0085c075
         // 140026b9a: test b4 eax, b4 eax
         // 140026b9c: jnz 0x140026ba5
      [-]83f82872
         // 00419da6: cmp eax, 0x28
         // 00419da9: jb 0x419d8e
      [-]0000eb0a
         // 00419b75: jmp 0x419b81
      [-]000085c07403
         // 0041a458: test eax, eax
         // 0041a45a: jz 0x41a45f
      [-]00000083f87d7d
         // 0041a5cd: cmp eax, 0x7d
         // 0041a5d0: jge 0x41a5e1
      [-]00000083f87d7d
         // 0041a5d9: cmp eax, 0x7d
         // 0041a5dc: jge 0x41a5e1
      [-]000085c07403
         // 0041a7ac: test eax, eax
         // 0041a7ae: jz 0x41a7b3
      [-]ffff84c00f84
         // 0041d6a8: call 0x41a5c6
         // 0041d6ad: test b1 al, b1 al
         // 0041d6af: jz 0x41d786
      [-]1f3c0e75
         // 14002f423: and b1 al, b1 0x1f
         // 14002f425: cmp b1 al, b1 0xe
         // 14002f427: jnz 0x14002f496
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
         // 0041e7ed: test eax, eax
         // 0041e7ef: jnz 0x41e7f6
      [-]85c07505
         // 00428291: test eax, eax
         // 00428293: jnz 0x42829a
      [-]83cfffeb
         // 00428295: or edi, 0xffffffffffffffff
         // 00428298: jmp 0x4282ac

  }
  condition:
    all of them
}
