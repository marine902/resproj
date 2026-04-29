rule coantor_30_0 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         558bec6a
         // 0040cc40: push ebp
         // 0040cc41: mov ebp, esp
         // 0040cc43: push 0xfffffffffffffffe
      [-]568bf16a
         // 0041367a: push esi
         // 0041367b: mov esi, ecx
         // 00413694: push 0x2
      [-]8bff51c701e8
         // 0041d3fa: mov edi, edi
         // 0041d3fc: push ecx
         // 0041d3fd: mov ds:[ecx], ??_7type_info@@6B@
         // 0041d403: call ?_Type_info_dtor@type_info@@CAXPAV1@@Z
      [-]8bff558bec568bf1e8e3fffffff64508017407
         // 0041d40a: mov edi, edi
         // 0041d40c: push ebp
         // 0041d40d: mov ebp, esp
         // 0041d40f: push esi
         // 0041d410: mov esi, ecx
         // 0041d412: call 0x41d3fa
         // 0041d417: test b1 ss:[ebp+0x8], b1 0x1
         // 0041d41b: jz 0x41d424
      [-]8bc65e5dc20400
         // 0041d424: mov eax, esi
         // 0041d426: pop esi
         // 0041d427: pop ebp
         // 0041d428: retn b2 0x4
      [-]420033c0c3
         // 0041f2cd: xor eax, eax
         // 0041f2cf: retn 
      [-]8bff56b8
         // 0041fed6: mov edi, edi
         // 0041fed8: push esi
         // 0041fed9: mov eax, 0x42e2a0
      [-]578bf83bc6730f
         // 0041fee3: push edi
         // 0041fee4: mov edi, eax
         // 0041fee6: cmp eax, esi
         // 0041fee8: jnb 0x41fef9
      [-]8b0785c07402
         // 0041feea: mov eax, ds:[edi]
         // 0041feec: test eax, eax
         // 0041feee: jz 0x41fef2
      [-]83c7043bfe72f1
         // 0041fef2: add edi, 0x4
         // 0041fef5: cmp edi, esi
         // 0041fef7: jb 0x41feea
      [-]8bff56b8
         // 0041fefc: mov edi, edi
         // 0041fefe: push esi
         // 0041feff: mov eax, 0x42e2a8
      [-]578bf83bc6730f
         // 0041ff09: push edi
         // 0041ff0a: mov edi, eax
         // 0041ff0c: cmp eax, esi
         // 0041ff0e: jnb 0x41ff1f
      [-]8b0785c07402
         // 0041ff10: mov eax, ds:[edi]
         // 0041ff12: test eax, eax
         // 0041ff14: jz 0x41ff18
      [-]83c7043bfe72f1
         // 0041ff18: add edi, 0x4
         // 0041ff1b: cmp edi, esi
         // 0041ff1d: jb 0x41ff10
      [-]8bff558bec8b4508a3
         // 004229da: mov edi, edi
         // 004229dc: push ebp
         // 004229dd: mov ebp, esp
         // 004229df: mov eax, ss:[ebp+0x8]
         // 004229e2: mov ds:[0x46a0f8], eax
      [-]8bff558bec8b4508a3
         // 004256b1: mov edi, edi
         // 004256b3: push ebp
         // 004256b4: mov ebp, esp
         // 004256b6: mov eax, ss:[ebp+0x8]
         // 004256b9: mov ds:[0x46a298], eax
      [-]8bff558bec8b4508a3
         // 004256c0: mov edi, edi
         // 004256c2: push ebp
         // 004256c3: mov ebp, esp
         // 004256c5: mov eax, ss:[ebp+0x8]
         // 004256c8: mov ds:[0x46a29c], eax
      [-]8bff558bec83ec
         // 0042584c: mov edi, edi
         // 0042584e: push ebp
         // 0042584f: mov ebp, esp
         // 00425851: sub esp, 0x24
      [-]ffff8365
         // 00425872: and ss:[ebp+0xffffffffffffffec], 0x0
      [-]85c00f84
         // 004258a5: test eax, eax
         // 004258a7: jz 0x4259a7
      [-]85c07419
         // 00425932: test eax, eax
         // 00425934: jz 0x42594f
      [-]516a0c8d4d
         // 00425939: push ecx
         // 0042593a: push 0xc
         // 0042593c: lea ecx, ss:[ebp+0xfffffffffffffff0]
      [-]516a0150ff
         // 0042593f: push ecx
         // 00425940: push 0x1
         // 00425942: push eax
         // 00425943: call ebx
      [-]85c07406
         // 00425945: test eax, eax
         // 00425947: jz 0x42594f
      [-]814d10????????eb
         // 0042594f: or ss:[ebp+0x10], 0x200000
         // 00425956: jmp 0x42598b
      [-]ffd08945
         // 00425969: call eax
         // 0042596b: mov ss:[ebp+0xffffffffffffffec], eax
      [-]85c07408
         // 0042597f: test eax, eax
         // 00425981: jz 0x42598b
      [-]ffd08945
         // 00425986: call eax
         // 00425988: mov ss:[ebp+0xffffffffffffffec], eax
      [-]85c07410
         // 00425993: test eax, eax
         // 00425995: jz 0x4259a7
      [-]ff7510ff75
         // 00425997: push ss:[ebp+0x10]
         // 0042599a: push ss:[ebp+0xffffffffffffffe4]
      [-]ffd0eb02
         // 004259a3: call eax
         // 004259a5: jmp 0x4259a9

  }
  condition:
    all of them
}
