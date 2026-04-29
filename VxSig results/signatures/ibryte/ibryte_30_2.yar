rule ibryte_30_2 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         8bff51c701
         // 00470d4a: mov edi, edi
         // 00470d4c: push ecx
         // 00470d4d: mov ds:[ecx], ??_7type_info@@6B@
      [-]000059c3
         // 00470d58: pop ecx
         // 00470d59: retn 
      [-]8bff558bec568bf1e8e3fffffff64508017407
         // 0046176e: mov edi, edi
         // 00461770: push ebp
         // 00461771: mov ebp, esp
         // 00461773: push esi
         // 00461774: mov esi, ecx
         // 00461776: call 0x46175e
         // 0046177b: test b1 ss:[ebp+0x8], b1 0x1
         // 0046177f: jz 0x461788
      [-]8bc65e5dc20400
         // 00461788: mov eax, esi
         // 0046178a: pop esi
         // 0046178b: pop ebp
         // 0046178c: retn b2 0x4
      [-]8bff56b8
         // 004819e6: mov edi, edi
         // 004819e8: push esi
         // 004819e9: mov eax, 0x4c5a60
      [-]578bf83bc6730f
         // 004819f3: push edi
         // 004819f4: mov edi, eax
         // 004819f6: cmp eax, esi
         // 004819f8: jnb 0x481a09
      [-]8b0785c07402
         // 0047239a: mov eax, ds:[edi]
         // 0047239c: test eax, eax
         // 0047239e: jz 0x4723a2
      [-]83c7043bfe72f1
         // 004723a2: add edi, 0x4
         // 004723a5: cmp edi, esi
         // 004723a7: jb 0x47239a
      [-]8bff56b8
         // 00481a0c: mov edi, edi
         // 00481a0e: push esi
         // 00481a0f: mov eax, 0x4c5a68
      [-]578bf83bc6730f
         // 00481a19: push edi
         // 00481a1a: mov edi, eax
         // 00481a1c: cmp eax, esi
         // 00481a1e: jnb 0x481a2f
      [-]8b0785c07402
         // 004723c0: mov eax, ds:[edi]
         // 004723c2: test eax, eax
         // 004723c4: jz 0x4723c8
      [-]83c7043bfe72f1
         // 004723c8: add edi, 0x4
         // 004723cb: cmp edi, esi
         // 004723cd: jb 0x4723c0
      [-]8bff558bec8b45085633f63bc6751d
         // 00475d72: mov edi, edi
         // 00475d74: push ebp
         // 00475d75: mov ebp, esp
         // 00475d77: mov eax, ss:[ebp+0x8]
         // 00475d7a: push esi
         // 00475d7b: xor esi, esi
         // 00475d7d: cmp eax, esi
         // 00475d7f: jnz 0x475d9e
      [-]ff5656565656c700????????e8
         // 0048527e: push esi
         // 0048527f: push esi
         // 00485280: push esi
         // 00485281: push esi
         // 00485282: push esi
         // 00485283: mov ds:[eax], 0x16
         // 00485289: call __invalid_parameter
      [-]feff83c4146a1658eb0a
         // 0048528e: add esp, 0x14
         // 00485291: push 0x16
         // 00485293: pop eax
         // 00485294: jmp 0x4852a0
      [-]890833c0
         // 0048529c: mov ds:[eax], ecx
         // 0048529e: xor eax, eax
      [-]8bff558bec8b45085633f63bc6751d
         // 00475dab: mov edi, edi
         // 00475dad: push ebp
         // 00475dae: mov ebp, esp
         // 00475db0: mov eax, ss:[ebp+0x8]
         // 00475db3: push esi
         // 00475db4: xor esi, esi
         // 00475db6: cmp eax, esi
         // 00475db8: jnz 0x475dd7
      [-]ff5656565656c700????????e8
         // 004852b7: push esi
         // 004852b8: push esi
         // 004852b9: push esi
         // 004852ba: push esi
         // 004852bb: push esi
         // 004852bc: mov ds:[eax], 0x16
         // 004852c2: call __invalid_parameter
      [-]feff83c4146a1658eb0a
         // 004852c7: add esp, 0x14
         // 004852ca: push 0x16
         // 004852cc: pop eax
         // 004852cd: jmp 0x4852d9
      [-]890833c0
         // 0047612d: mov ds:[eax], ecx
         // 0047612f: xor eax, eax
      [-]8bff558bec8b45085633f63bc6751d
         // 00475de4: mov edi, edi
         // 00475de6: push ebp
         // 00475de7: mov ebp, esp
         // 00475de9: mov eax, ss:[ebp+0x8]
         // 00475dec: push esi
         // 00475ded: xor esi, esi
         // 00475def: cmp eax, esi
         // 00475df1: jnz 0x475e10
      [-]ff5656565656c700????????e8
         // 004852f0: push esi
         // 004852f1: push esi
         // 004852f2: push esi
         // 004852f3: push esi
         // 004852f4: push esi
         // 004852f5: mov ds:[eax], 0x16
         // 004852fb: call __invalid_parameter
      [-]feff83c4146a1658eb0a
         // 00485300: add esp, 0x14
         // 00485303: push 0x16
         // 00485305: pop eax
         // 00485306: jmp 0x485312
      [-]890833c0
         // 0048530e: mov ds:[eax], ecx
         // 00485310: xor eax, eax

  }
  condition:
    all of them
}
