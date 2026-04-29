rule ibryte_10_3 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         8bc18360040083600800c700
         // 00409be2: mov eax, ecx
         // 00409be4: and ds:[eax+0x4], 0x0
         // 00409be8: and ds:[eax+0x8], 0x0
         // 00409bec: mov ds:[eax], ??_7exception@std@@6B@
      [-]8bff558bec568d4508508bf1e8
         // 00459570: mov edi, edi
         // 00459572: push ebp
         // 00459573: mov ebp, esp
         // 00459575: push esi
         // 00459576: lea eax, ss:[ebp+0x8]
         // 00459579: push eax
         // 0045957a: mov esi, ecx
         // 0045957c: call ??0exception@std@@QAE@ABQBD@Z
      [-]ffffc706
         // 00459581: mov ds:[esi], ??_7bad_cast@std@@6B@
      [-]008bc65e5dc20400
         // 00459587: mov eax, esi
         // 00459589: pop esi
         // 0045958a: pop ebp
         // 0045958b: retn b2 0x4
      [-]8bff558bec568bf1e8
         // 00461a72: mov edi, edi
         // 00461a74: push ebp
         // 00461a75: mov ebp, esp
         // 00461a77: push esi
         // 00461a78: mov esi, ecx
         // 00461a7a: call 0x461a09
      [-]fffffff64508017407
         // 00461a7f: test b1 ss:[ebp+0x8], b1 0x1
         // 00461a83: jz 0x461a8c
      [-]8bc65e5dc20400
         // 00461a8c: mov eax, esi
         // 00461a8e: pop esi
         // 00461a8f: pop ebp
         // 00461a90: retn b2 0x4
      [-]8bff56b8
         // 00411928: mov edi, edi
         // 0041192a: push esi
         // 0041192b: mov eax, 0x42af48
      [-]578bf83bc6730f
         // 00411935: push edi
         // 00411936: mov edi, eax
         // 00411938: cmp eax, esi
         // 0041193a: jnb 0x41194b
      [-]8b0785c07402
         // 004726ea: mov eax, ds:[edi]
         // 004726ec: test eax, eax
         // 004726ee: jz 0x4726f2
      [-]83c7043bfe72f1
         // 004726f2: add edi, 0x4
         // 004726f5: cmp edi, esi
         // 004726f7: jb 0x4726ea
      [-]8bff56b8
         // 0041194e: mov edi, edi
         // 00411950: push esi
         // 00411951: mov eax, 0x42af50
      [-]578bf83bc6730f
         // 0041195b: push edi
         // 0041195c: mov edi, eax
         // 0041195e: cmp eax, esi
         // 00411960: jnb 0x411971
      [-]8b0785c07402
         // 00472710: mov eax, ds:[edi]
         // 00472712: test eax, eax
         // 00472714: jz 0x472718
      [-]83c7043bfe72f1
         // 00472718: add edi, 0x4
         // 0047271b: cmp edi, esi
         // 0047271d: jb 0x472710
      [-]8bff558bec8b45085633f63bc6751d
         // 004760c2: mov edi, edi
         // 004760c4: push ebp
         // 004760c5: mov ebp, esp
         // 004760c7: mov eax, ss:[ebp+0x8]
         // 004760ca: push esi
         // 004760cb: xor esi, esi
         // 004760cd: cmp eax, esi
         // 004760cf: jnz 0x4760ee
      [-]ff5656565656c700????????e8
         // 004773c6: push esi
         // 004773c7: push esi
         // 004773c8: push esi
         // 004773c9: push esi
         // 004773ca: push esi
         // 004773cb: mov ds:[eax], 0x16
         // 004773d1: call __invalid_parameter
      [-]feff83c4146a1658eb0a
         // 004773d6: add esp, 0x14
         // 004773d9: push 0x16
         // 004773db: pop eax
         // 004773dc: jmp 0x4773e8
      [-]890833c0
         // 00424267: mov ds:[eax], ecx
         // 00424269: xor eax, eax
      [-]8bff558bec8b45085633f63bc6751d
         // 004760fb: mov edi, edi
         // 004760fd: push ebp
         // 004760fe: mov ebp, esp
         // 00476100: mov eax, ss:[ebp+0x8]
         // 00476103: push esi
         // 00476104: xor esi, esi
         // 00476106: cmp eax, esi
         // 00476108: jnz 0x476127
      [-]ff5656565656c700????????e8
         // 0046cf1e: push esi
         // 0046cf1f: push esi
         // 0046cf20: push esi
         // 0046cf21: push esi
         // 0046cf22: push esi
         // 0046cf23: mov ds:[eax], 0x16
         // 0046cf29: call __invalid_parameter
      [-]feff83c4146a1658eb0a
         // 0046cf2e: add esp, 0x14
         // 0046cf31: push 0x16
         // 0046cf33: pop eax
         // 0046cf34: jmp 0x46cf40
      [-]890833c0
         // 004242a0: mov ds:[eax], ecx
         // 004242a2: xor eax, eax
      [-]8bff558bec8b45085633f63bc6751d
         // 00476134: mov edi, edi
         // 00476136: push ebp
         // 00476137: mov ebp, esp
         // 00476139: mov eax, ss:[ebp+0x8]
         // 0047613c: push esi
         // 0047613d: xor esi, esi
         // 0047613f: cmp eax, esi
         // 00476141: jnz 0x476160
      [-]ff5656565656c700????????e8
         // 0046cf57: push esi
         // 0046cf58: push esi
         // 0046cf59: push esi
         // 0046cf5a: push esi
         // 0046cf5b: push esi
         // 0046cf5c: mov ds:[eax], 0x16
         // 0046cf62: call __invalid_parameter
      [-]feff83c4146a1658eb0a
         // 0046cf67: add esp, 0x14
         // 0046cf6a: push 0x16
         // 0046cf6c: pop eax
         // 0046cf6d: jmp 0x46cf79
      [-]890833c0
         // 004242d9: mov ds:[eax], ecx
         // 004242db: xor eax, eax

  }
  condition:
    all of them
}
