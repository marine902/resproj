rule ibryte_10_0 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         8bc18360040083600800c700
         // 004693d0: mov eax, ecx
         // 004693d2: and ds:[eax+0x4], 0x0
         // 004693d6: and ds:[eax+0x8], 0x0
         // 004693da: mov ds:[eax], ??_7exception@std@@6B@
      [-]8bff558bec568bf1e8
         // 004617cc: mov edi, edi
         // 004617ce: push ebp
         // 004617cf: mov ebp, esp
         // 004617d1: push esi
         // 004617d2: mov esi, ecx
         // 004617d4: call 0x461763
      [-]fffffff64508017407
         // 004617d9: test b1 ss:[ebp+0x8], b1 0x1
         // 004617dd: jz 0x4617e6
      [-]8bc65e5dc20400
         // 004617e6: mov eax, esi
         // 004617e8: pop esi
         // 004617e9: pop ebp
         // 004617ea: retn b2 0x4
      [-]8bff56b8
         // 0047a146: mov edi, edi
         // 0047a148: push esi
         // 0047a149: mov eax, 0x4ac538
      [-]578bf83bc6730f
         // 0047a153: push edi
         // 0047a154: mov edi, eax
         // 0047a156: cmp eax, esi
         // 0047a158: jnb 0x47a169
      [-]8b0785c07402
         // 0047243a: mov eax, ds:[edi]
         // 0047243c: test eax, eax
         // 0047243e: jz 0x472442
      [-]83c7043bfe72f1
         // 00472442: add edi, 0x4
         // 00472445: cmp edi, esi
         // 00472447: jb 0x47243a
      [-]8bff56b8
         // 0047a16c: mov edi, edi
         // 0047a16e: push esi
         // 0047a16f: mov eax, 0x4ac540
      [-]578bf83bc6730f
         // 0047a179: push edi
         // 0047a17a: mov edi, eax
         // 0047a17c: cmp eax, esi
         // 0047a17e: jnb 0x47a18f
      [-]8b0785c07402
         // 00472460: mov eax, ds:[edi]
         // 00472462: test eax, eax
         // 00472464: jz 0x472468
      [-]83c7043bfe72f1
         // 00472468: add edi, 0x4
         // 0047246b: cmp edi, esi
         // 0047246d: jb 0x472460
      [-]8bff558bec8b45085633f63bc6751d
         // 00475e12: mov edi, edi
         // 00475e14: push ebp
         // 00475e15: mov ebp, esp
         // 00475e17: mov eax, ss:[ebp+0x8]
         // 00475e1a: push esi
         // 00475e1b: xor esi, esi
         // 00475e1d: cmp eax, esi
         // 00475e1f: jnz 0x475e3e
      [-]ff5656565656c700????????e8
         // 0047db4c: push esi
         // 0047db4d: push esi
         // 0047db4e: push esi
         // 0047db4f: push esi
         // 0047db50: push esi
         // 0047db51: mov ds:[eax], 0x16
         // 0047db57: call __invalid_parameter
      [-]feff83c4146a1658eb0a
         // 0047db5c: add esp, 0x14
         // 0047db5f: push 0x16
         // 0047db61: pop eax
         // 0047db62: jmp 0x47db6e
      [-]890833c0
         // 004760f4: mov ds:[eax], ecx
         // 004760f6: xor eax, eax
      [-]8bff558bec8b45085633f63bc6751d
         // 00475e4b: mov edi, edi
         // 00475e4d: push ebp
         // 00475e4e: mov ebp, esp
         // 00475e50: mov eax, ss:[ebp+0x8]
         // 00475e53: push esi
         // 00475e54: xor esi, esi
         // 00475e56: cmp eax, esi
         // 00475e58: jnz 0x475e77
      [-]ff5656565656c700????????e8
         // 0047db85: push esi
         // 0047db86: push esi
         // 0047db87: push esi
         // 0047db88: push esi
         // 0047db89: push esi
         // 0047db8a: mov ds:[eax], 0x16
         // 0047db90: call __invalid_parameter
      [-]feff83c4146a1658eb0a
         // 0047db95: add esp, 0x14
         // 0047db98: push 0x16
         // 0047db9a: pop eax
         // 0047db9b: jmp 0x47dba7
      [-]890833c0
         // 0047612d: mov ds:[eax], ecx
         // 0047612f: xor eax, eax
      [-]8bff558bec8b45085633f63bc6751d
         // 00475e84: mov edi, edi
         // 00475e86: push ebp
         // 00475e87: mov ebp, esp
         // 00475e89: mov eax, ss:[ebp+0x8]
         // 00475e8c: push esi
         // 00475e8d: xor esi, esi
         // 00475e8f: cmp eax, esi
         // 00475e91: jnz 0x475eb0
      [-]ff5656565656c700????????e8
         // 0047dbbe: push esi
         // 0047dbbf: push esi
         // 0047dbc0: push esi
         // 0047dbc1: push esi
         // 0047dbc2: push esi
         // 0047dbc3: mov ds:[eax], 0x16
         // 0047dbc9: call __invalid_parameter
      [-]feff83c4146a1658eb0a
         // 0047dbce: add esp, 0x14
         // 0047dbd1: push 0x16
         // 0047dbd3: pop eax
         // 0047dbd4: jmp 0x47dbe0
      [-]890833c0
         // 00476166: mov ds:[eax], ecx
         // 00476168: xor eax, eax

  }
  condition:
    all of them
}
