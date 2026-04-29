rule ibryte_10_4 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         8bff558bec8b45085633f63bc6751d
         // 004239cc: mov edi, edi
         // 004239ce: push ebp
         // 004239cf: mov ebp, esp
         // 004239d1: mov eax, ss:[ebp+0x8]
         // 004239d4: push esi
         // 004239d5: xor esi, esi
         // 004239d7: cmp eax, esi
         // 004239d9: jnz 0x4239f8
      [-]ff5656565656c700????????e8
         // 0048454e: push esi
         // 0048454f: push esi
         // 00484550: push esi
         // 00484551: push esi
         // 00484552: push esi
         // 00484553: mov ds:[eax], 0x16
         // 00484559: call __invalid_parameter
      [-]feff83c4146a1658eb0a
         // 0048455e: add esp, 0x14
         // 00484561: push 0x16
         // 00484563: pop eax
         // 00484564: jmp 0x484570
      [-]890833c0
         // 00473814: mov ds:[eax], ecx
         // 00473816: xor eax, eax
      [-]8bff558bec8b45085633f63bc6751d
         // 00423a05: mov edi, edi
         // 00423a07: push ebp
         // 00423a08: mov ebp, esp
         // 00423a0a: mov eax, ss:[ebp+0x8]
         // 00423a0d: push esi
         // 00423a0e: xor esi, esi
         // 00423a10: cmp eax, esi
         // 00423a12: jnz 0x423a31
      [-]ff5656565656c700????????e8
         // 00484587: push esi
         // 00484588: push esi
         // 00484589: push esi
         // 0048458a: push esi
         // 0048458b: push esi
         // 0048458c: mov ds:[eax], 0x16
         // 00484592: call __invalid_parameter
      [-]feff83c4146a1658eb0a
         // 00484597: add esp, 0x14
         // 0048459a: push 0x16
         // 0048459c: pop eax
         // 0048459d: jmp 0x4845a9
      [-]890833c0
         // 0047384d: mov ds:[eax], ecx
         // 0047384f: xor eax, eax
      [-]8bff558bec8b45085633f63bc6751d
         // 00423a3e: mov edi, edi
         // 00423a40: push ebp
         // 00423a41: mov ebp, esp
         // 00423a43: mov eax, ss:[ebp+0x8]
         // 00423a46: push esi
         // 00423a47: xor esi, esi
         // 00423a49: cmp eax, esi
         // 00423a4b: jnz 0x423a6a
      [-]ff5656565656c700????????e8
         // 004845c0: push esi
         // 004845c1: push esi
         // 004845c2: push esi
         // 004845c3: push esi
         // 004845c4: push esi
         // 004845c5: mov ds:[eax], 0x16
         // 004845cb: call __invalid_parameter
      [-]feff83c4146a1658eb0a
         // 004845d0: add esp, 0x14
         // 004845d3: push 0x16
         // 004845d5: pop eax
         // 004845d6: jmp 0x4845e2
      [-]890833c0
         // 00473886: mov ds:[eax], ecx
         // 00473888: xor eax, eax

  }
  condition:
    all of them
}
