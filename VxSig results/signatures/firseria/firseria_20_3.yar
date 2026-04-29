rule firseria_20_3 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         33c05ec3
         // 00401046: xor eax, eax
         // 00401048: pop esi
         // 00401049: retn 
      [-]5e1bc083e0fe40c3
         // 00401050: pop esi
         // 00401051: sbb eax, eax
         // 00401053: and eax, 0xfffffffffffffffe
         // 00401056: inc eax
         // 00401057: retn 
      [-]558bec81ec
         // 00406837: push ebp
         // 00406838: mov ebp, esp
         // 0040683a: sub esp, 0x4c0
      [-]68????????
         // 0040712f: push 0x20019
      [-]6a045839
         // 0040683b: push 0x4
         // 0040683d: pop eax
         // 0040683e: cmp ss:[ebp+0xfffffffffffffb48], eax
      [-]6a4050e8
         // 004068c3: push 0x40
         // 004068c5: push eax
         // 004068c6: call _swprintf
      [-]ffff6a07
         // 00406ed9: push 0x7
      [-]ffff85c075
         // 00406f4e: test eax, eax
         // 00406f50: jnz 0x406f7d
      [-]ffff85c075
         // 00406fbc: test eax, eax
         // 00406fbe: jnz 0x406fda
      [-]ffff6a07
         // 004071a3: push 0x7
      [-]f8ffff85c075
         // 004071c8: test eax, eax
         // 004071ca: jnz 0x407204
      [-]ffff85c075
         // 00407028: test eax, eax
         // 0040702a: jnz 0x407053
      [-]6a025839
         // 00406f85: push 0x2
         // 00406f87: pop eax
         // 00406f88: cmp ds:[ebx+0x3c], eax
      [-]ffff6a09
         // 00407223: push 0x9
      [-]f7ffff85c075
         // 00407248: test eax, eax
         // 0040724a: jnz 0x407284
      [-]ffff85c075
         // 004070a8: test eax, eax
         // 004070aa: jnz 0x4070d3
      [-]6a025839
         // 00407008: push 0x2
         // 0040700a: pop eax
         // 0040700b: cmp ds:[ebx+0x3c], eax
      [-]558bec568bf1c706
         // 0040bd1d: push ebp
         // 0040bd1e: mov ebp, esp
         // 0040bd20: push esi
         // 0040bd21: mov esi, ecx
         // 0040bd23: mov ds:[esi], ??_7exception@std@@6B@
      [-]f64508017407
         // 0040bd2e: test b1 ss:[ebp+0x8], b1 0x1
         // 0040bd32: jz 0x40bd3b
      [-]8bc65e5dc20400
         // 0040bf01: mov eax, esi
         // 0040bf03: pop esi
         // 0040bf04: pop ebp
         // 0040bf05: retn b2 0x4
      [-]85c07402
         // 00415449: test eax, eax
         // 0041544b: jz 0x41544f
      [-]83f8ff740c
         // 0041def5: cmp eax, 0xffffffffffffffff
         // 0041def8: jz 0x41df06
      [-]83f8fe7407
         // 0041d46a: cmp eax, 0xfffffffffffffffe
         // 0041d46d: jz 0x41d476

  }
  condition:
    all of them
}
