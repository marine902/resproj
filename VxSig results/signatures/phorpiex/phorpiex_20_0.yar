rule phorpiex_20_0 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         b8????????6689
         // 1403e00d4: mov b4 eax, b4 0x61
         // 1403e00d9: mov b2 ss:[rsp+0x81a], b2 ax
      [-]b8????????6689
         // 1403e00fb: mov b4 eax, b4 0x64
         // 1403e0100: mov b2 ss:[rsp+0x820], b2 ax
      [-]b8????????6689
         // 1403e0122: mov b4 eax, b4 0x61
         // 1403e0127: mov b2 ss:[rsp+0x826], b2 ax
      [-]b8????????6689
         // 1403e0149: mov b4 eax, b4 0x77
         // 1403e014e: mov b2 ss:[rsp+0x82c], b2 ax
      [-]b8????????6689
         // 1403e0170: mov b4 eax, b4 0x64
         // 1403e0175: mov b2 ss:[rsp+0x832], b2 ax
      [-]b8????????6689
         // 1403e0197: mov b4 eax, b4 0x2e
         // 1403e019c: mov b2 ss:[rsp+0x838], b2 ax
      [-]b8????????6689
         // 1403e01be: mov b4 eax, b4 0x74
         // 1403e01c3: mov b2 ss:[rsp+0x83e], b2 ax
      [-]83f8ff7405
         // 1403e0201: cmp b4 eax, b4 0xffffffffffffffff
         // 1403e0204: jz 0x1403e020b
      [-]85c07505
         // 1403e02db: test b4 eax, b4 eax
         // 1403e02dd: jnz 0x1403e02e4
      [-]85c07505
         // 004902e0: test eax, eax
         // 004902e2: jnz 0x4902e9
      [-]b8????????6689
         // 0040e31a: mov eax, 0x65
         // 0040e31f: mov b2 ss:[ebp+0xfffffffffffff9a6], b2 ax
      [-]33c06689
         // 0040e33e: xor eax, eax
         // 0040e340: mov b2 ss:[ebp+0xfffffffffffff9ac], b2 ax
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
         // 140f8695b: shr b4 eax, b1 0x8
         // 140f8695e: mov b4 ss:[rsp+0x8], b4 eax
      [-]83c00289
         // 140f86a41: add rax, 0x2
         // 140f86a45: mov ss:[rsp+0x18], rax
      [-]2bc183f8207407
         // 140f86aa9: sub b4 eax, b4 ecx
         // 140f86aab: cmp b4 eax, b4 0x20
         // 140f86aae: jz 0x140f86ab7
      [-]b8????????eb
         // 140f86ab0: mov b4 eax, b4 0x1
         // 140f86ab5: jmp 0x140f86abe
      [-]e8deffffff8b40
         // 140f86fbd: call 0x140f86fa0
         // 140f86fc2: mov rax, ds:[rax+0x18]
      [-]b8????????6689
         // 140f86fd9: mov b4 eax, b4 0x6b
         // 140f86fde: mov b2 ss:[rsp+0x20], b2 ax

  }
  condition:
    all of them
}
