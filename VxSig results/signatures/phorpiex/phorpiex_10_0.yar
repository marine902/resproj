rule phorpiex_10_0 {
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
         // 1403e0377: mov b4 eax, b4 0x65
         // 1403e037c: mov b2 ss:[rsp+0x6e2], b2 ax
      [-]33c06689
         // 1403e039e: xor b4 eax, b4 eax
         // 1403e03a0: mov b2 ss:[rsp+0x6e8], b2 ax
      [-]b8????????6689
         // 140102408: mov b4 eax, b4 0x74
         // 14010240d: mov b2 ss:[rsp+0x70a], b2 ax
      [-]b8????????6689
         // 14010242f: mov b4 eax, b4 0x3a
         // 140102434: mov b2 ss:[rsp+0x710], b2 ax
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
         // 00490ccd: call 0x490cb0
         // 00490cd2: mov eax, ds:[eax+0xc]
      [-]b8????????6689
         // 00490ce1: mov eax, 0x6b
         // 00490ce6: mov b2 ss:[ebp+0xffffffffffffffe4], b2 ax
      [-]b8????????6689
         // 00490cfc: mov eax, 0x6e
         // 00490d01: mov b2 ss:[ebp+0xffffffffffffffea], b2 ax
      [-]b8????????6689
         // 00490d17: mov eax, 0x33
         // 00490d1c: mov b2 ss:[ebp+0xfffffffffffffff0], b2 ax
      [-]b8????????6689
         // 00490d32: mov eax, 0x64
         // 00490d37: mov b2 ss:[ebp+0xfffffffffffffff6], b2 ax
      [-]33c06689
         // 00490d4d: xor eax, eax
         // 00490d4f: mov b2 ss:[ebp+0xfffffffffffffffc], b2 ax

  }
  condition:
    all of them
}
