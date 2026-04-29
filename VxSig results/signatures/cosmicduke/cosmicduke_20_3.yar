rule cosmicduke_20_3 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         64890d????????
         // 0040287f: mov fs:[0x0], ecx
      [-]8bff568bf1807e08007409
         // 00413789: mov edi, edi
         // 0041378b: push esi
         // 0041378c: mov esi, ecx
         // 0041378e: cmp b1 ds:[esi+0x8], b1 0x0
         // 00413792: jz 0x41379d
      [-]ff7604e8
         // 00413794: push ds:[esi+0x4]
         // 00413797: call _free
      [-]83660400c64608005ec3
         // 0041379d: and ds:[esi+0x4], 0x0
         // 004137a1: mov b1 ds:[esi+0x8], b1 0x0
         // 004137a5: pop esi
         // 004137a6: retn 
      [-]8bff51c701
         // 0041387e: mov edi, edi
         // 00413880: push ecx
         // 00413881: mov ds:[ecx], ??_7type_info@@6B@
      [-]000059c3
         // 0041388c: pop ecx
         // 0041388d: retn 
      [-]8bff558bec568bf1e8e3fffffff64508017407
         // 0041388e: mov edi, edi
         // 00413890: push ebp
         // 00413891: mov ebp, esp
         // 00413893: push esi
         // 00413894: mov esi, ecx
         // 00413896: call 0x41387e
         // 0041389b: test b1 ss:[ebp+0x8], b1 0x1
         // 0041389f: jz 0x4138a8
      [-]8bc65e5dc20400
         // 004138a8: mov eax, esi
         // 004138aa: pop esi
         // 004138ab: pop ebp
         // 004138ac: retn b2 0x4
      [-]6a0aff15
         // 00415211: push 0xa
         // 00415213: call ds:[IsProcessorFeaturePresent]
      [-]8bff558bec8b4508a3??
         // 004153a9: mov edi, edi
         // 004153ab: push ebp
         // 004153ac: mov ebp, esp
         // 004153ae: mov eax, ss:[ebp+0x8]
         // 004153b1: mov ds:[0x42a06c], eax
      [-]0033c0c3
         // 00416df4: xor eax, eax
         // 00416df6: retn 
      [-]8bff56b8
         // 004177bb: mov edi, edi
         // 004177bd: push esi
         // 004177be: mov eax, 0x423b9c
      [-]578bf83bc6730f
         // 004177c8: push edi
         // 004177c9: mov edi, eax
         // 004177cb: cmp eax, esi
         // 004177cd: jnb 0x4177de
      [-]8b0785c07402
         // 004177cf: mov eax, ds:[edi]
         // 004177d1: test eax, eax
         // 004177d3: jz 0x4177d7
      [-]83c7043bfe72f1
         // 004177d7: add edi, 0x4
         // 004177da: cmp edi, esi
         // 004177dc: jb 0x4177cf
      [-]8bff56b8
         // 004177e1: mov edi, edi
         // 004177e3: push esi
         // 004177e4: mov eax, 0x423ba4
      [-]578bf83bc6730f
         // 004177ee: push edi
         // 004177ef: mov edi, eax
         // 004177f1: cmp eax, esi
         // 004177f3: jnb 0x417804
      [-]8b0785c07402
         // 004177f5: mov eax, ds:[edi]
         // 004177f7: test eax, eax
         // 004177f9: jz 0x4177fd
      [-]83c7043bfe72f1
         // 004177fd: add edi, 0x4
         // 00417800: cmp edi, esi
         // 00417802: jb 0x4177f5
      [-]8bff558bec8b4508a3
         // 00417db0: mov edi, edi
         // 00417db2: push ebp
         // 00417db3: mov ebp, esp
         // 00417db5: mov eax, ss:[ebp+0x8]
         // 00417db8: mov ds:[0x42a988], eax
      [-]8bff558bec83ec24a1
         // 0041894f: mov edi, edi
         // 00418951: push ebp
         // 00418952: mov ebp, esp
         // 00418954: sub esp, 0x24
         // 00418957: mov eax, ds:[___security_cookie]
      [-]420033c58945fc8b4508538945e08b450c56578945e4e8
         // 0041895c: xor eax, ebp
         // 0041895e: mov ss:[ebp+0xfffffffffffffffc], eax
         // 00418961: mov eax, ss:[ebp+0x8]
         // 00418964: push ebx
         // 00418965: mov ss:[ebp+0xffffffffffffffe0], eax
         // 00418968: mov eax, ss:[ebp+0xc]
         // 0041896b: push esi
         // 0041896c: push edi
         // 0041896d: mov ss:[ebp+0xffffffffffffffe4], eax
         // 00418970: call __encoded_null
      [-]ffff8365ec00833d
         // 00418975: and ss:[ebp+0xffffffffffffffec], 0x0
         // 00418979: cmp ds:[0x42a9d0], 0x0
      [-]008945e8757d
         // 00418980: mov ss:[ebp+0xffffffffffffffe8], eax
         // 00418983: jnz 0x418a02
      [-]008bd885db0f8410010000
         // 00418990: mov ebx, eax
         // 00418992: test ebx, ebx
         // 00418994: jz 0x418aaa
      [-]53ffd785c00f84fa000000
         // 004189a5: push ebx
         // 004189a6: call edi
         // 004189a8: test eax, eax
         // 004189aa: jz 0x418aaa
      [-]0050ffd668
         // 004189b6: push eax
         // 004189b7: call esi
         // 004189b9: push 0x42133c
      [-]ffd750ffd668
         // 004189c4: call edi
         // 004189c6: push eax
         // 004189c7: call esi
         // 004189c9: push 0x421328
      [-]ffd750ffd668
         // 004189d4: call edi
         // 004189d6: push eax
         // 004189d7: call esi
         // 004189d9: push 0x42130c
      [-]ffd750ffd6a3
         // 004189e4: call edi
         // 004189e6: push eax
         // 004189e7: call esi
         // 004189e9: mov ds:[0x42a9e0], eax
      [-]85c07410
         // 004189ee: test eax, eax
         // 004189f0: jz 0x418a02
      [-]53ffd750ffd6a3
         // 004189f7: push ebx
         // 004189f8: call edi
         // 004189fa: push eax
         // 004189fb: call esi
         // 004189fd: mov ds:[0x42a9dc], eax
      [-]8b4de88b35
         // 00418a07: mov ecx, ss:[ebp+0xffffffffffffffe8]
         // 00418a0a: mov esi, ds:[DecodePointer]
      [-]003bc17447
         // 00418a10: cmp eax, ecx
         // 00418a12: jz 0x418a5b
      [-]50ffd6ff35
         // 00418a1c: push eax
         // 00418a1d: call esi
         // 00418a1f: push ds:[0x42a9e0]
      [-]8bf8ffd68bd885ff742c
         // 00418a25: mov edi, eax
         // 00418a27: call esi
         // 00418a29: mov ebx, eax
         // 00418a2b: test edi, edi
         // 00418a2d: jz 0x418a5b
      [-]85db7428
         // 00418a2f: test ebx, ebx
         // 00418a31: jz 0x418a5b
      [-]ffd785c07419
         // 00418a33: call edi
         // 00418a35: test eax, eax
         // 00418a37: jz 0x418a52
      [-]8d4ddc516a0c8d4df0516a0150ffd385c07406
         // 00418a39: lea ecx, ss:[ebp+0xffffffffffffffdc]
         // 00418a3c: push ecx
         // 00418a3d: push 0xc
         // 00418a3f: lea ecx, ss:[ebp+0xfffffffffffffff0]
         // 00418a42: push ecx
         // 00418a43: push 0x1
         // 00418a45: push eax
         // 00418a46: call ebx
         // 00418a48: test eax, eax
         // 00418a4a: jz 0x418a52
      [-]f645f8017509
         // 00418a4c: test b1 ss:[ebp+0xfffffffffffffff8], b1 0x1
         // 00418a50: jnz 0x418a5b
      [-]814d10????????eb33
         // 00418a52: or ss:[ebp+0x10], 0x200000
         // 00418a59: jmp 0x418a8e
      [-]3b45e87429
         // 00418a60: cmp eax, ss:[ebp+0xffffffffffffffe8]
         // 00418a63: jz 0x418a8e
      [-]50ffd685c07422
         // 00418a65: push eax
         // 00418a66: call esi
         // 00418a68: test eax, eax
         // 00418a6a: jz 0x418a8e
      [-]ffd08945ec85c07419
         // 00418a6c: call eax
         // 00418a6e: mov ss:[ebp+0xffffffffffffffec], eax
         // 00418a71: test eax, eax
         // 00418a73: jz 0x418a8e
      [-]3b45e8740f
         // 00418a7a: cmp eax, ss:[ebp+0xffffffffffffffe8]
         // 00418a7d: jz 0x418a8e
      [-]50ffd685c07408
         // 00418a7f: push eax
         // 00418a80: call esi
         // 00418a82: test eax, eax
         // 00418a84: jz 0x418a8e
      [-]ff75ecffd08945ec
         // 00418a86: push ss:[ebp+0xffffffffffffffec]
         // 00418a89: call eax
         // 00418a8b: mov ss:[ebp+0xffffffffffffffec], eax
      [-]ffd685c07410
         // 00418a94: call esi
         // 00418a96: test eax, eax
         // 00418a98: jz 0x418aaa
      [-]ff7510ff75e4ff75e0ff75ecffd0eb02
         // 00418a9a: push ss:[ebp+0x10]
         // 00418a9d: push ss:[ebp+0xffffffffffffffe4]
         // 00418aa0: push ss:[ebp+0xffffffffffffffe0]
         // 00418aa3: push ss:[ebp+0xffffffffffffffec]
         // 00418aa6: call eax
         // 00418aa8: jmp 0x418aac
      [-]8b4dfc5f5e33cd5be8
         // 00418aac: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 00418aaf: pop edi
         // 00418ab0: pop esi
         // 00418ab1: xor ecx, ebp
         // 00418ab3: pop ebx
         // 00418ab4: call @__security_check_cookie@4
      [-]ffffc9c3
         // 00418ab9: leave 
         // 00418aba: retn 
      [-]8bff558bec56ff75088bf1e8
         // 0041afd5: mov edi, edi
         // 0041afd7: push ebp
         // 0041afd8: mov ebp, esp
         // 0041afda: push esi
         // 0041afdb: push ss:[ebp+0x8]
         // 0041afde: mov esi, ecx
         // 0041afe0: call ??0exception@std@@QAE@ABV01@@Z
      [-]42008bc65e5dc20400
         // 0041afeb: mov eax, esi
         // 0041afed: pop esi
         // 0041afee: pop ebp
         // 0041afef: retn b2 0x4

  }
  condition:
    all of them
}
