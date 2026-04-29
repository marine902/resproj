rule jaik_10_0 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         558bec83ec
         // 00401000: push ebp
         // 00401001: mov ebp, esp
         // 00401003: sub esp, 0x18
      [-]4000ff15
         // 0040afce: call ds:[SetUnhandledExceptionFilter]
      [-]400033c0c3
         // 0040afd4: xor eax, eax
         // 0040afd6: retn 
      [-]8bff56b8
         // 0040b5b0: mov edi, edi
         // 0040b5b2: push esi
         // 0040b5b3: mov eax, 0x410740
      [-]578bf83bc6730f
         // 0040b5bd: push edi
         // 0040b5be: mov edi, eax
         // 0040b5c0: cmp eax, esi
         // 0040b5c2: jnb 0x40b5d3
      [-]8b0785c07402
         // 0040b5c4: mov eax, ds:[edi]
         // 0040b5c6: test eax, eax
         // 0040b5c8: jz 0x40b5cc
      [-]83c7043bfe72f1
         // 0040b5cc: add edi, 0x4
         // 0040b5cf: cmp edi, esi
         // 0040b5d1: jb 0x40b5c4
      [-]8bff56b8
         // 0040b5d6: mov edi, edi
         // 0040b5d8: push esi
         // 0040b5d9: mov eax, 0x410748
      [-]578bf83bc6730f
         // 0040b5e3: push edi
         // 0040b5e4: mov edi, eax
         // 0040b5e6: cmp eax, esi
         // 0040b5e8: jnb 0x40b5f9
      [-]8b0785c07402
         // 0040b5ea: mov eax, ds:[edi]
         // 0040b5ec: test eax, eax
         // 0040b5ee: jz 0x40b5f2
      [-]83c7043bfe72f1
         // 0040b5f2: add edi, 0x4
         // 0040b5f5: cmp edi, esi
         // 0040b5f7: jb 0x40b5ea
      [-]8bff558bec8b4508a3
         // 0040c7f2: mov edi, edi
         // 0040c7f4: push ebp
         // 0040c7f5: mov ebp, esp
         // 0040c7f7: mov eax, ss:[ebp+0x8]
         // 0040c7fa: mov ds:[0x4139a8], eax
      [-]8bff558bec8b4508a3
         // 0040c801: mov edi, edi
         // 0040c803: push ebp
         // 0040c804: mov ebp, esp
         // 0040c806: mov eax, ss:[ebp+0x8]
         // 0040c809: mov ds:[0x4139ac], eax
      [-]8bff558bec83ec
         // 0040cc7d: mov edi, edi
         // 0040cc7f: push ebp
         // 0040cc80: mov ebp, esp
         // 0040cc82: sub esp, 0x24
      [-]535657e8
         // 0040cc92: push ebx
         // 0040cc99: push esi
         // 0040cc9a: push edi
         // 0040cc9e: call __encoded_null
      [-]ffff8365
         // 0040cca3: and ss:[ebp+0xffffffffffffffec], 0x0
      [-]85c00f84
         // 0040ccd6: test eax, eax
         // 0040ccd8: jz 0x40cdd8
      [-]85c07419
         // 0040cd63: test eax, eax
         // 0040cd65: jz 0x40cd80
      [-]516a0c8d4d
         // 0040cd6a: push ecx
         // 0040cd6b: push 0xc
         // 0040cd6d: lea ecx, ss:[ebp+0xfffffffffffffff0]
      [-]516a0150ff
         // 0040cd70: push ecx
         // 0040cd71: push 0x1
         // 0040cd73: push eax
         // 0040cd74: call ebx
      [-]85c07406
         // 0040cd76: test eax, eax
         // 0040cd78: jz 0x40cd80
      [-]814d10????????eb
         // 0040cd80: or ss:[ebp+0x10], 0x200000
         // 0040cd87: jmp 0x40cdbc
      [-]ffd08945
         // 0040cd9a: call eax
         // 0040cd9c: mov ss:[ebp+0xffffffffffffffec], eax
      [-]85c07408
         // 0040cdb0: test eax, eax
         // 0040cdb2: jz 0x40cdbc
      [-]ffd08945
         // 0040cdb7: call eax
         // 0040cdb9: mov ss:[ebp+0xffffffffffffffec], eax
      [-]85c07410
         // 0040cdc4: test eax, eax
         // 0040cdc6: jz 0x40cdd8
      [-]ff7510ff75
         // 0040cdc8: push ss:[ebp+0x10]
         // 0040cdcb: push ss:[ebp+0xffffffffffffffe4]
      [-]ffd0eb02
         // 0040cdd4: call eax
         // 0040cdd6: jmp 0x40cdda
      [-]5f5e5bc9c3
         // 00403dd7: pop edi
         // 00403dd8: pop esi
         // 00403dd9: pop ebx
         // 00403dda: leave 
         // 00403ddb: retn 

  }
  condition:
    all of them
}
