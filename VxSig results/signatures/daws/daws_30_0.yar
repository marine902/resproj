rule daws_30_0 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         400033c4898424
         // 0040100b: xor eax, esp
         // 0040100d: mov ss:[esp+0x190], eax
      [-]400033c4894424
         // 00402008: xor eax, esp
         // 0040200a: mov ss:[esp+0x1c], eax
      [-]400033c489
         // 00401458: xor eax, esp
         // 0040145a: mov ss:[esp+0x30], eax
      [-]400033c489
         // 004015b8: xor eax, esp
         // 004015ba: mov ss:[esp+0x30], eax
      [-]5f5e33c0
         // 00401676: pop edi
         // 00401677: pop esi
         // 00401678: xor eax, eax
      [-]33ccb8????????e8
         // 004016fd: xor ecx, esp
         // 004016ff: mov eax, 0x1
         // 00401704: call @__security_check_cookie@4
      [-]400033c4898424
         // 004049eb: xor eax, esp
         // 004049ed: mov ss:[esp+0x154], eax
      [-]ffff85c0
         // 00404aaf: test eax, eax
      [-]ffff85c0
         // 00404ac1: test eax, eax
      [-]4000ff15
         // 00405a23: call ds:[SetUnhandledExceptionFilter]
      [-]400033c0c3
         // 00405a29: xor eax, eax
         // 00405a2b: retn 
      [-]8bff56b8
         // 00406161: mov edi, edi
         // 00406163: push esi
         // 00406164: mov eax, 0x40bd00
      [-]578bf83bc6730f
         // 0040616e: push edi
         // 0040616f: mov edi, eax
         // 00406171: cmp eax, esi
         // 00406173: jnb 0x406184
      [-]8b0785c07402
         // 00406175: mov eax, ds:[edi]
         // 00406177: test eax, eax
         // 00406179: jz 0x40617d
      [-]83c7043bfe72f1
         // 0040617d: add edi, 0x4
         // 00406180: cmp edi, esi
         // 00406182: jb 0x406175
      [-]8bff56b8
         // 00406187: mov edi, edi
         // 00406189: push esi
         // 0040618a: mov eax, 0x40bd08
      [-]578bf83bc6730f
         // 00406194: push edi
         // 00406195: mov edi, eax
         // 00406197: cmp eax, esi
         // 00406199: jnb 0x4061aa
      [-]8b0785c07402
         // 0040619b: mov eax, ds:[edi]
         // 0040619d: test eax, eax
         // 0040619f: jz 0x4061a3
      [-]83c7043bfe72f1
         // 004061a3: add edi, 0x4
         // 004061a6: cmp edi, esi
         // 004061a8: jb 0x40619b
      [-]ffff59c3
         // 00406bb6: pop ecx
         // 00406bb7: retn 
      [-]8bff558bec8b4508a3
         // 00406d68: mov edi, edi
         // 00406d6a: push ebp
         // 00406d6b: mov ebp, esp
         // 00406d6d: mov eax, ss:[ebp+0x8]
         // 00406d70: mov ds:[0x45937c], eax
      [-]8bff558bec8b4508a3
         // 00406d77: mov edi, edi
         // 00406d79: push ebp
         // 00406d7a: mov ebp, esp
         // 00406d7c: mov eax, ss:[ebp+0x8]
         // 00406d7f: mov ds:[0x459388], eax
      [-]8bff558bec83ec14535657e8
         // 00406d86: mov edi, edi
         // 00406d88: push ebp
         // 00406d89: mov ebp, esp
         // 00406d8b: sub esp, 0x14
         // 00406d8e: push ebx
         // 00406d8f: push esi
         // 00406d90: push edi
         // 00406d91: call __encoded_null
      [-]ffff8365fc00833d
         // 00406d96: and ss:[ebp+0xfffffffffffffffc], 0x0
         // 00406d9a: cmp ds:[0x45938c], 0x0
      [-]008bd80f858e000000
         // 00406da1: mov ebx, eax
         // 00406da3: jnz 0x406e37
      [-]40008bf885ff0f842a010000
         // 00406db4: mov edi, eax
         // 00406db6: test edi, edi
         // 00406db8: jz 0x406ee8
      [-]57ffd685c00f8414010000
         // 00406dc9: push edi
         // 00406dca: call esi
         // 00406dcc: test eax, eax
         // 00406dce: jz 0x406ee8
      [-]ffffc70424
         // 00406dda: mov ss:[esp], 0x40a97c
      [-]ffd650e8
         // 00406de7: call esi
         // 00406de9: push eax
         // 00406dea: call __encode_pointer
      [-]ffffc70424
         // 00406def: mov ss:[esp], 0x40a968
      [-]ffd650e8
         // 00406dfc: call esi
         // 00406dfe: push eax
         // 00406dff: call __encode_pointer
      [-]ffffc70424
         // 00406e04: mov ss:[esp], 0x40a94c
      [-]ffd650e8
         // 00406e11: call esi
         // 00406e13: push eax
         // 00406e14: call __encode_pointer
      [-]ffff59a3
         // 00406e19: pop ecx
         // 00406e1a: mov ds:[0x45939c], eax
      [-]85c07414
         // 00406e1f: test eax, eax
         // 00406e21: jz 0x406e37
      [-]57ffd650e8
         // 00406e28: push edi
         // 00406e29: call esi
         // 00406e2b: push eax
         // 00406e2c: call __encode_pointer
      [-]ffff59a3
         // 00406e31: pop ecx
         // 00406e32: mov ds:[0x459398], eax
      [-]3bc3744f
         // 00406e3c: cmp eax, ebx
         // 00406e3e: jz 0x406e8f
      [-]ffffff35
         // 00406e4e: push ds:[0x45939c]
      [-]ffff59598bf885f6742c
         // 00406e5b: pop ecx
         // 00406e5c: pop ecx
         // 00406e5d: mov edi, eax
         // 00406e5f: test esi, esi
         // 00406e61: jz 0x406e8f
      [-]85ff7428
         // 00406e63: test edi, edi
         // 00406e65: jz 0x406e8f
      [-]ffd685c07419
         // 00406e67: call esi
         // 00406e69: test eax, eax
         // 00406e6b: jz 0x406e86
      [-]8d4df8516a0c8d4dec516a0150ffd785c07406
         // 00406e6d: lea ecx, ss:[ebp+0xfffffffffffffff8]
         // 00406e70: push ecx
         // 00406e71: push 0xc
         // 00406e73: lea ecx, ss:[ebp+0xffffffffffffffec]
         // 00406e76: push ecx
         // 00406e77: push 0x1
         // 00406e79: push eax
         // 00406e7a: call edi
         // 00406e7c: test eax, eax
         // 00406e7e: jz 0x406e86
      [-]f645f4017509
         // 00406e80: test b1 ss:[ebp+0xfffffffffffffff4], b1 0x1
         // 00406e84: jnz 0x406e8f
      [-]814d10????????eb39
         // 00406e86: or ss:[ebp+0x10], 0x200000
         // 00406e8d: jmp 0x406ec8
      [-]3bc37430
         // 00406e94: cmp eax, ebx
         // 00406e96: jz 0x406ec8
      [-]ffff5985c07425
         // 00406e9e: pop ecx
         // 00406e9f: test eax, eax
         // 00406ea1: jz 0x406ec8
      [-]ffd08945fc85c0741c
         // 00406ea3: call eax
         // 00406ea5: mov ss:[ebp+0xfffffffffffffffc], eax
         // 00406ea8: test eax, eax
         // 00406eaa: jz 0x406ec8
      [-]3bc37413
         // 00406eb1: cmp eax, ebx
         // 00406eb3: jz 0x406ec8
      [-]ffff5985c07408
         // 00406ebb: pop ecx
         // 00406ebc: test eax, eax
         // 00406ebe: jz 0x406ec8
      [-]ff75fcffd08945fc
         // 00406ec0: push ss:[ebp+0xfffffffffffffffc]
         // 00406ec3: call eax
         // 00406ec5: mov ss:[ebp+0xfffffffffffffffc], eax
      [-]ffff5985c07410
         // 00406ed3: pop ecx
         // 00406ed4: test eax, eax
         // 00406ed6: jz 0x406ee8
      [-]ff7510ff750cff7508ff75fcffd0eb02
         // 00406ed8: push ss:[ebp+0x10]
         // 00406edb: push ss:[ebp+0xc]
         // 00406ede: push ss:[ebp+0x8]
         // 00406ee1: push ss:[ebp+0xfffffffffffffffc]
         // 00406ee4: call eax
         // 00406ee6: jmp 0x406eea
      [-]5f5e5bc9c3
         // 00406eea: pop edi
         // 00406eeb: pop esi
         // 00406eec: pop ebx
         // 00406eed: leave 
         // 00406eee: retn 

  }
  condition:
    all of them
}
