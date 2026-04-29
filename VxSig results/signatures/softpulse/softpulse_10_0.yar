rule softpulse_10_0 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         000059c3
         // 0040a9d8: pop ecx
         // 0040a9d9: retn 
      [-]558bec568bf1e8
         // 00482082: push ebp
         // 00482083: mov ebp, esp
         // 00482085: push esi
         // 00482086: mov esi, ecx
         // 00482088: call 0x482070
      [-]fffffff64508017407
         // 0048208d: test b1 ss:[ebp+0x8], b1 0x1
         // 00482091: jz 0x48209a
      [-]8bc65e5dc20400
         // 0040aa70: mov eax, esi
         // 0040aa72: pop esi
         // 0040aa73: pop ebp
         // 0040aa74: retn b2 0x4
      [-]85c07402
         // 0040c059: test eax, eax
         // 0040c05b: jz 0x40c05f
      [-]85c07414
         // 00478299: test eax, eax
         // 0047829b: jz 0x4782b1
      [-]516a0c8d4d
         // 00410791: push ecx
         // 00410792: push 0xc
         // 00410794: lea ecx, ss:[ebp+0xfffffffffffffff0]
      [-]516a0150ff
         // 00410797: push ecx
         // 00410798: push 0x1
         // 0041079a: push eax
         // 0041079b: call ss:[ebp+0xffffffffffffffe8]
      [-]85c07406
         // 0041079e: test eax, eax
         // 004107a0: jz 0x4107a8
      [-]558bec83ec
         // 00412573: push ebp
         // 00412574: mov ebp, esp
         // 00412576: sub esp, 0x44
      [-]4083f8037cf4
         // 00412635: inc eax
         // 00412636: cmp eax, 0x3
         // 00412639: jl 0x41262f
      [-]996a1f5923d103
         // 004126c3: cdq 
         // 004126c4: push 0x1f
         // 004126c6: pop ecx
         // 004126c7: and edx, ecx
         // 004126c9: add edx, eax
      [-]2bc833c0f3ab
         // 0041275f: sub ecx, eax
         // 00412761: xor eax, eax
         // 00412763: rep stosdd 
      [-]33c08d7d
         // 0049ee19: xor eax, eax
         // 0049ee1b: lea edi, ss:[ebp+0xffffffffffffffe0]
      [-]83e21f03c2a58b
         // 0046be7e: and edx, 0x1f
         // 0046be81: add eax, edx
         // 0046be83: movsdd 
         // 0046be84: mov edx, ecx
      [-]8bc19983e21f03
         // 0041283c: mov eax, ecx
         // 0041283e: cdq 
         // 0041283f: and edx, 0x1f
         // 00412842: add edx, eax
      [-]5923d103
         // 0049ef23: pop ecx
         // 0049ef24: and edx, ecx
         // 0049ef26: add eax, edx
      [-]33c0f3ab
         // 0041291a: xor eax, eax
         // 0041291c: rep stosdd 
      [-]418bc19983e21f03c2
         // 004128c7: inc ecx
         // 004128c8: mov eax, ecx
         // 004128ca: cdq 
         // 004128cb: and edx, 0x1f
         // 004128ce: add eax, edx
      [-]9983e21f03c2
         // 004129d6: cdq 
         // 004129d7: and edx, 0x1f
         // 004129da: add eax, edx
      [-]9983e21f
         // 00412a78: cdq 
         // 00412a79: and edx, 0x1f

  }
  condition:
    all of them
}
