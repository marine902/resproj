rule phorpiex_10_3 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         b8????????6689
         // 004100bc: mov eax, 0x61
         // 004100c1: mov b2 ss:[ebp+0xfffffffffffff8a2], b2 ax
      [-]b8????????6689
         // 004100e0: mov eax, 0x64
         // 004100e5: mov b2 ss:[ebp+0xfffffffffffff8a8], b2 ax
      [-]b8????????6689
         // 00410104: mov eax, 0x61
         // 00410109: mov b2 ss:[ebp+0xfffffffffffff8ae], b2 ax
      [-]b8????????6689
         // 00410128: mov eax, 0x77
         // 0041012d: mov b2 ss:[ebp+0xfffffffffffff8b4], b2 ax
      [-]b8????????6689
         // 0041014c: mov eax, 0x64
         // 00410151: mov b2 ss:[ebp+0xfffffffffffff8ba], b2 ax
      [-]b8????????6689
         // 00410170: mov eax, 0x2e
         // 00410175: mov b2 ss:[ebp+0xfffffffffffff8c0], b2 ax
      [-]b8????????6689
         // 00410194: mov eax, 0x74
         // 00410199: mov b2 ss:[ebp+0xfffffffffffff8c6], b2 ax
      [-]83f8ff7405
         // 004101cf: cmp eax, 0xffffffffffffffff
         // 004101d2: jz 0x4101d9
      [-]85c07505
         // 1402722db: test b4 eax, b4 eax
         // 1402722dd: jnz 0x1402722e4
      [-]85c07505
         // 140272338: test b4 eax, b4 eax
         // 14027233a: jnz 0x140272341
      [-]b8????????6689
         // 140097377: mov b4 eax, b4 0x65
         // 14009737c: mov b2 ss:[rsp+0x6e2], b2 ax
      [-]33c06689
         // 14009739e: xor b4 eax, b4 eax
         // 1400973a0: mov b2 ss:[rsp+0x6e8], b2 ax
      [-]b8????????6689
         // 140272408: mov b4 eax, b4 0x74
         // 14027240d: mov b2 ss:[rsp+0x70a], b2 ax
      [-]b8????????6689
         // 14027242f: mov b4 eax, b4 0x3a
         // 140272434: mov b2 ss:[rsp+0x710], b2 ax
      [-]85c07405
         // 140272589: test b4 eax, b4 eax
         // 14027258b: jz 0x140272592
      [-]000000c7
         // 00704727: mov ss:[ebp+0xfffffffffffff8c8], 0x44
      [-]c1e80889
         // 14027295b: shr b4 eax, b1 0x8
         // 14027295e: mov b4 ss:[rsp+0x8], b4 eax
      [-]2bc183f8207407
         // 004108fa: sub eax, ecx
         // 004108fc: cmp eax, 0x20
         // 004108ff: jz 0x410908
      [-]b8????????eb
         // 00410901: mov eax, 0x1
         // 00410906: jmp 0x41090c
      [-]e8deffffff
         // 1402bffbd: call 0x1402bffa0
      [-]b8????????6689
         // 1402bffd9: mov b4 eax, b4 0x6b
         // 1402bffde: mov b2 ss:[rsp+0x20], b2 ax
      [-]b8????????6689
         // 1402bffe3: mov b4 eax, b4 0x65
         // 1402bffe8: mov b2 ss:[rsp+0x22], b2 ax

  }
  condition:
    all of them
}
