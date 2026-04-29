rule firseria_10_4 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         33c05ec3
         // 0040106e: xor eax, eax
         // 00401070: pop esi
         // 00401071: retn 
      [-]5e1bc083e0fe40c3
         // 00401078: pop esi
         // 00401079: sbb eax, eax
         // 0040107b: and eax, 0xfffffffffffffffe
         // 0040107e: inc eax
         // 0040107f: retn 
      [-]837f14087204
         // 0040134a: cmp ds:[edi+0x14], 0x8
         // 00401351: jb 0x401357
      [-]837f14087202
         // 004013a0: cmp ds:[edi+0x14], 0x8
         // 004013a4: jb 0x4013a8
      [-]00000084c074
         // 00401da6: test b1 al, b1 al
         // 00401da8: jz 0x401dd0
      [-]837b140872
         // 004016ef: cmp ds:[ebx+0x14], 0x8
         // 004016f3: jb 0x4016f9
      [-]14087204
         // 004016ff: jb 0x401705
      [-]b001eb02
         // 004017cf: mov b1 al, b1 0x1
         // 004017d1: jmp 0x4017d5
      [-]558bec81ec
         // 004076c2: push ebp
         // 004076c3: mov ebp, esp
         // 004076c5: sub esp, 0x4c0
      [-]68????????
         // 0040927c: push 0x20019
      [-]8b06eb02
         // 00407746: mov eax, ds:[esi]
         // 00407748: jmp 0x40774c
      [-]6a045839
         // 004071a3: push 0x4
         // 004071a5: pop eax
         // 004071a6: cmp ss:[ebp+0xfffffffffffffb50], eax
      [-]837e1408
         // 004077a1: cmp ds:[esi+0x14], 0x8
      [-]6a4050e8
         // 00406954: push 0x40
         // 00406956: push eax
         // 00406957: call _swprintf
      [-]ffff6a075b
         // 004098bc: push 0x7
         // 004098be: pop ebx
      [-]ffff85c075
         // 00409946: test eax, eax
         // 00409948: jnz 0x409993
      [-]ffff85c075
         // 0040782e: test eax, eax
         // 00407830: jnz 0x40784c
      [-]ffff6a07
         // 00406fa9: push 0x7
      [-]f8ffff85c075
         // 00406fce: test eax, eax
         // 00406fd0: jnz 0x40700a
      [-]ffff85c075
         // 00407895: call 0x406ed9
         // 0040789a: test eax, eax
         // 0040789c: jnz 0x4078c5
      [-]6a025839
         // 00407ea2: push 0x2
         // 00407ea4: pop eax
         // 00407ea5: cmp ds:[edi+0x3c], eax
      [-]ffff6a09
         // 00407029: push 0x9
      [-]f7ffff85c075
         // 0040704e: test eax, eax
         // 00407050: jnz 0x40708a
      [-]ffff85c075
         // 0040791a: test eax, eax
         // 0040791c: jnz 0x407945
      [-]6a025839
         // 00407f22: push 0x2
         // 00407f24: pop eax
         // 00407f25: cmp ds:[edi+0x3c], eax
      [-]00000084c07407
         // 00408152: test b1 al, b1 al
         // 00408154: jz 0x40815d
      [-]14087204
         // 00407f7c: jb 0x407f82
      [-]558bec568bf1c706
         // 0040cafa: push ebp
         // 0040cafb: mov ebp, esp
         // 0040cafd: push esi
         // 0040cafe: mov esi, ecx
         // 0040cb00: mov ds:[esi], ??_7exception@std@@6B@
      [-]f64508017407
         // 0040cb0b: test b1 ss:[ebp+0x8], b1 0x1
         // 0040cb0f: jz 0x40cb18
      [-]8bc65e5dc20400
         // 0040cb18: mov eax, esi
         // 0040cb1a: pop esi
         // 0040cb1b: pop ebp
         // 0040cb1c: retn b2 0x4
      [-]83f8ff740c
         // 0041d675: cmp eax, 0xffffffffffffffff
         // 0041d678: jz 0x41d686
      [-]83f8fe7407
         // 0041defa: cmp eax, 0xfffffffffffffffe
         // 0041defd: jz 0x41df06

  }
  condition:
    all of them
}
