rule uztuby_40_1 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         0085c074
         // 00401350: test eax, eax
         // 00401352: jz 0x401385
      [-]0085c074
         // 00401360: test eax, eax
         // 00401362: jz 0x401385
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
      [-]000084c0
         // 140013ee1: test b1 al, b1 al
      [-]01000083f8ff74
         // 0040a592: cmp eax, 0xffffffffffffffff
         // 0040a595: jz 0x40a5cb
      [-]0000008b
         // 0040da4e: mov ecx, esi
      [-]0085c074
         // 14001a463: test rax, rax
         // 14001a466: jz 0x14001a46c
      [-]8a41fc3001
         // 0040dd47: mov b1 al, b1 ds:[ecx+0xfffffffffffffffc]
         // 0040dd4a: xor b1 ds:[ecx], b1 al
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
         // 0040fdeb: cmp eax, 0x3f
         // 0040fdee: jbe 0x40fe45
      [-]ffff3d????????72
         // 14001e52a: cmp b4 eax, b4 0x600
         // 14001e52f: jb 0x14001e564
      [-]0083f80275
         // 14001e55f: cmp b4 eax, b4 0x2
         // 14001e562: jnz 0x14001e5bd
      [-]ffff3d????????
         // 14001dbfd: cmp b4 eax, b4 0x600
      [-]8bf9ff15
         // 00411bcc: mov edi, ecx
         // 00411bce: call ds:[GetCPInfo]
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
         // 00419da3: add eax, 0x2
         // 00419da6: cmp eax, 0x28
         // 00419da9: jb 0x419d8e
      [-]0000eb0a
         // 00419b75: jmp 0x419b81
      [-]000085c07403
         // 0041a458: test eax, eax
         // 0041a45a: jz 0x41a45f
      [-]00008bd0
         // 0041a466: mov edx, eax
      [-]00000083f87d7d
         // 0041a5cd: cmp eax, 0x7d
         // 0041a5d0: jge 0x41a5e1
      [-]00000083f87d7d
         // 0041a5d9: cmp eax, 0x7d
         // 0041a5dc: jge 0x41a5e1
      [-]000085c07403
         // 0041a7ac: test eax, eax
         // 0041a7ae: jz 0x41a7b3
      [-]ffff84c075
         // 140028e2c: test b1 al, b1 al
         // 140028e2e: jnz 0x140028e3f
      [-]ffff84c00f84
         // 0041d6a8: call 0x41a5c6
         // 0041d6ad: test b1 al, b1 al
         // 0041d6af: jz 0x41d786
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
         // 0041c3c4: test eax, eax
         // 0041c3c6: jle 0x41c3d2
      [-]85c07902
         // 0041e1b4: test eax, eax
         // 0041e1b6: jns 0x41e1ba
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
         // 00428291: test eax, eax
         // 00428293: jnz 0x42829a
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
