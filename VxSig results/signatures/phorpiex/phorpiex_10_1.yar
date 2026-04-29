rule phorpiex_10_1 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         b8????????6689
         // 004460bc: mov eax, 0x61
         // 004460c1: mov b2 ss:[ebp+0xfffffffffffff8a2], b2 ax
      [-]b8????????6689
         // 004460e0: mov eax, 0x64
         // 004460e5: mov b2 ss:[ebp+0xfffffffffffff8a8], b2 ax
      [-]b8????????6689
         // 00446104: mov eax, 0x61
         // 00446109: mov b2 ss:[ebp+0xfffffffffffff8ae], b2 ax
      [-]b8????????6689
         // 00446128: mov eax, 0x77
         // 0044612d: mov b2 ss:[ebp+0xfffffffffffff8b4], b2 ax
      [-]b8????????6689
         // 0044614c: mov eax, 0x64
         // 00446151: mov b2 ss:[ebp+0xfffffffffffff8ba], b2 ax
      [-]b8????????6689
         // 00446170: mov eax, 0x2e
         // 00446175: mov b2 ss:[ebp+0xfffffffffffff8c0], b2 ax
      [-]b8????????6689
         // 00446194: mov eax, 0x74
         // 00446199: mov b2 ss:[ebp+0xfffffffffffff8c6], b2 ax
      [-]83f8ff7405
         // 004461cf: cmp eax, 0xffffffffffffffff
         // 004461d2: jz 0x4461d9
      [-]85c07505
         // 1403142db: test b4 eax, b4 eax
         // 1403142dd: jnz 0x1403142e4
      [-]85c07505
         // 0040e2e0: test eax, eax
         // 0040e2e2: jnz 0x40e2e9
      [-]b8????????6689
         // 140314377: mov b4 eax, b4 0x65
         // 14031437c: mov b2 ss:[rsp+0x6e2], b2 ax
      [-]33c06689
         // 14031439e: xor b4 eax, b4 eax
         // 1403143a0: mov b2 ss:[rsp+0x6e8], b2 ax
      [-]b8????????6689
         // 0040e39c: mov eax, 0x74
         // 0040e3a1: mov b2 ss:[ebp+0xfffffffffffff95e], b2 ax
      [-]b8????????6689
         // 0040e3c0: mov eax, 0x3a
         // 0040e3c5: mov b2 ss:[ebp+0xfffffffffffff964], b2 ax
      [-]85c07405
         // 0040e503: test eax, eax
         // 0040e505: jz 0x40e50c
      [-]c1e80889
         // 14005b94b: shr b4 eax, b1 0x8
         // 14005b94e: mov b4 ss:[rsp+0x8], b4 eax
      [-]83c00289
         // 140314a41: add rax, 0x2
         // 140314a45: mov ss:[rsp+0x18], rax
      [-]2bc183f8207407
         // 14005ba99: sub b4 eax, b4 ecx
         // 14005ba9b: cmp b4 eax, b4 0x20
         // 14005ba9e: jz 0x14005baa7
      [-]b8????????eb
         // 14005baa0: mov b4 eax, b4 0x1
         // 14005baa5: jmp 0x14005baae
      [-]e8deffffff8b40
         // 14005bfad: call 0x14005bf90
         // 14005bfb2: mov rax, ds:[rax+0x18]
      [-]b8????????6689
         // 14005bfc9: mov b4 eax, b4 0x6b
         // 14005bfce: mov b2 ss:[rsp+0x20], b2 ax
      [-]b8????????6689
         // 14005bfe7: mov b4 eax, b4 0x6e
         // 14005bfec: mov b2 ss:[rsp+0x26], b2 ax

  }
  condition:
    all of them
}
