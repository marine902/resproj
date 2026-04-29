rule softcnapp_10_1 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         0033c58945fc8b45088985
         // 00462012: xor eax, ebp
         // 00462014: mov ss:[ebp+0xfffffffffffffffc], eax
         // 00462017: mov eax, ss:[ebp+0x8]
         // 0046201a: mov ss:[ebp+0xffffffffffffdfd4], eax
      [-]6a008985
         // 0046203a: push 0x0
         // 0046203c: mov ss:[ebp+0xffffffffffffdfcc], eax
      [-]6a018985
         // 00462053: push 0x1
         // 00462055: mov ss:[ebp+0xffffffffffffdfe4], eax
      [-]8b4dfc33cde8
         // 0051a46e: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 0051a471: xor ecx, ebp
         // 0051a473: call @__security_check_cookie@4
      [-]8be55dc3
         // 0051a478: mov esp, ebp
         // 0051a47a: pop ebp
         // 0051a47b: retn 
      [-]80f90975
         // 004620d5: cmp b1 cl, b1 0x9
         // 004620d8: jnz 0x4620e2
      [-]8a4e014684c975ee
         // 0051a4ca: mov b1 cl, b1 ds:[esi+0x1]
         // 0051a4cd: inc esi
         // 0051a4ce: test b1 cl, b1 cl
         // 0051a4d0: jnz 0x51a4c0
      [-]83c41083f8010f8c
         // 00515d23: add esp, 0x10
         // 00515d26: cmp eax, 0x1
         // 00515d29: jl 0x516055
      [-]84c075f9
         // 00509b89: test b1 al, b1 al
         // 00509b8b: jnz 0x509b86
      [-]8d70018a0684c074
         // 0051a844: lea esi, ds:[eax+0x1]
         // 0051a847: mov b1 al, b1 ds:[esi]
         // 0051a849: test b1 al, b1 al
         // 0051a84b: jz 0x51a860
      [-]3c207404
         // 0051a850: cmp b1 al, b1 0x20
         // 0051a852: jz 0x51a858
      [-]3c097508
         // 0051a854: cmp b1 al, b1 0x9
         // 0051a856: jnz 0x51a860
      [-]8a46014684c075f0
         // 0051a858: mov b1 al, b1 ds:[esi+0x1]
         // 0051a85b: inc esi
         // 0051a85c: test b1 al, b1 al
         // 0051a85e: jnz 0x51a850
      [-]0083c408eb0e
         // 004163b2: add esp, 0x8
         // 004163b5: jmp 0x4163c5
      [-]468d460150ff15
         // 00509f75: inc esi
         // 00509f76: lea eax, ds:[esi+0x1]
         // 00509f79: push eax
         // 00509f7a: call ds:[0x656020]
      [-]83c40489
         // 00509f80: add esp, 0x4
         // 00509f83: mov ds:[ebx+0xc], eax
      [-]803e230f84
         // 0046272a: cmp b1 ds:[esi], b1 0x23
         // 0046272d: jz 0x4620a8
      [-]6a0d56e8
         // 0051a9ab: push 0xd
         // 0051a9ad: push esi
         // 0051a9ae: call _strchr
      [-]6a0a56e8
         // 0051a9bd: push 0xa
         // 0051a9bf: push esi
         // 0051a9c0: call _strchr
      [-]83fe060f87
         // 004209bd: cmp esi, 0x6
         // 004209c0: ja def_4209C6
      [-]83c40c46
         // 00420b8e: add esp, 0xc
         // 00420b91: inc esi
      [-]83fe06751e
         // 0051aba6: cmp esi, 0x6
         // 0051aba9: jnz 0x51abc9
      [-]83c40489
         // 00416672: add esp, 0x4
         // 00416675: mov ds:[ebx+0x8], eax
      [-]83fe070f85
         // 00420bca: cmp esi, 0x7
         // 00420bcd: jnz 0x42091a
      [-]8be55dc3
         // 004168a4: mov esp, ebp
         // 004168a6: pop ebp
         // 004168a7: retn 
      [-]68????????ff15
         // 00416c5d: push 0x1388
         // 00416c62: call ds:[0x606664]
      [-]68????????56e8
         // 00416c72: push 0x1388
         // 00416c77: push esi
         // 00416c78: call 0x442ac1
      [-]6a0b5668
         // 00416c84: push 0xb
         // 00416c86: push esi
         // 00416c87: push 0x45a5d0
      [-]8a0184c074
         // 0051b1ea: mov b1 al, b1 ds:[ecx]
         // 0051b1ec: test b1 al, b1 al
         // 0051b1ee: jz 0x51b200
      [-]3c207404
         // 0051b1f0: cmp b1 al, b1 0x20
         // 0051b1f2: jz 0x51b1f8
      [-]3c097508
         // 0051b1f4: cmp b1 al, b1 0x9
         // 0051b1f6: jnz 0x51b200
      [-]8a41014184c075f0
         // 0051b1f8: mov b1 al, b1 ds:[ecx+0x1]
         // 0051b1fb: inc ecx
         // 0051b1fc: test b1 al, b1 al
         // 0051b1fe: jnz 0x51b1f0
      [-]6a006a0051ff75
         // 00416cbc: push 0x0
         // 00416cbe: push 0x0
         // 00416cc0: push ecx
         // 00416cc3: push ss:[ebp+0x8]
      [-]68????????56e8
         // 00416ccc: push 0x1388
         // 00416cd1: push esi
         // 00416cd2: call 0x442ac1
      [-]558bec568b750883be
         // 00421320: push ebp
         // 00421321: mov ebp, esp
         // 00421323: push esi
         // 00421324: mov esi, ss:[ebp+0x8]
         // 00421327: cmp ds:[esi+0x314], 0x0
      [-]ffffff83c404
         // 0046328f: add esp, 0x4
      [-]6a026a0256e8
         // 0051b352: push 0x2
         // 0051b354: push 0x2
         // 0051b356: push esi
         // 0051b357: call 0x527280
      [-]837d0c00741d
         // 0051b387: cmp ss:[ebp+0xc], 0x0
         // 0051b38b: jz 0x51b3aa
      [-]ffff83c404c786
         // 0042138d: add esp, 0x4
         // 00421390: mov ds:[esi+0x428], 0x0
      [-]6a026a0256e8
         // 00416e66: push 0x2
         // 00416e68: push 0x2
         // 00416e6a: push esi
         // 00416e6b: call 0x4237cc
      [-]837d0c0074
         // 0051b3b7: cmp ss:[ebp+0xc], 0x0
         // 0051b3bb: jz 0x51b3dd
      [-]faffff83c404
         // 004213ca: add esp, 0x4
      [-]6a0256e8
         // 00416e99: push 0x2
         // 00416e9b: push esi
         // 00416e9c: call 0x42380c
      [-]83c4085e5dc3
         // 00416ea1: add esp, 0x8
         // 00416ea4: pop esi
         // 00416ea5: pop ebp
         // 00416ea6: retn 
      [-]5e8be55dc3
         // 00516cc3: pop esi
         // 00516cc4: mov esp, ebp
         // 00516cc6: pop ebp
         // 00516cc7: retn 
      [-]5e8be55dc3
         // 00516cec: pop esi
         // 00516ced: mov esp, ebp
         // 00516cef: pop ebp
         // 00516cf0: retn 
      [-]8b5508b9
         // 0041707f: mov edx, ss:[ebp+0x8]
         // 00417082: mov ecx, 0x45a490
      [-]5356578b4208bf
         // 00417087: push ebx
         // 00417088: push esi
         // 00417089: push edi
         // 0041708a: mov eax, ds:[edx+0x8]
         // 0041708d: mov edi, 0x45a570
      [-]0f45c88b420c
         // 00417099: cmovnz ecx, eax
         // 0041709c: mov eax, ds:[edx+0xc]
      [-]0f45f88b42
         // 004170a1: cmovnz edi, eax
         // 004170a4: mov eax, ds:[edx+0x10]
      [-]80382ebe
         // 00516e1a: cmp b1 ds:[eax], b1 0x2e
         // 00516e1d: mov esi, 0x646638
      [-]7a300051ff7204b9
         // 00516e29: cmp ds:[edx+0x30], 0x0
         // 00516e2d: push ecx
         // 00516e2e: push ds:[edx+0x4]
         // 00516e31: mov ecx, 0x6465c0
      [-]ff72180f4445
         // 00516e42: push ds:[edx+0x18]
         // 00516e45: cmovz eax, ss:[ebp+0x8]
      [-]00500f444d
         // 00516e49: cmp ds:[edx+0x24], 0x0
         // 00516e4d: push eax
         // 00516e4e: cmovz ecx, ss:[ebp+0x8]
      [-]00575153b9
         // 00516e5b: push edi
         // 00516e5c: push ecx
         // 00516e5d: push ebx
         // 00516e5e: mov ecx, 0x559c01
      [-]560f44c15068
         // 00516e63: push esi
         // 00516e64: cmovz eax, ecx
         // 00516e67: push eax
         // 00516e68: push 0x64663c
      [-]83c42c5f5e5b
         // 00516e72: add esp, 0x2c
         // 00516e75: pop edi
         // 00516e76: pop esi
         // 00516e77: pop ebx
      [-]558bec568b75088b06
         // 0051bf80: push ebp
         // 0051bf81: mov ebp, esp
         // 0051bf83: push esi
         // 0051bf84: mov esi, ss:[ebp+0x8]
         // 0051bf87: mov eax, ds:[esi]
      [-]00ff36ff15
         // 005177c4: push ds:[esi]
         // 005177c6: call ds:[0x669024]
      [-]0083c404
         // 00417aa9: add esp, 0x4
      [-]6a0056e8
         // 00417aae: push 0x0
         // 00417ab0: push esi
         // 00417ab1: call 0x43ecbc
      [-]83c40c5e5dc3
         // 00417ab6: add esp, 0xc
         // 00417ab9: pop esi
         // 00417aba: pop ebp
         // 00417abb: retn 
      [-]558bec568b7508
         // 005179d0: push ebp
         // 005179d1: mov ebp, esp
         // 005179d3: push esi
         // 005179d4: mov esi, ss:[ebp+0x8]
      [-]83c41089
         // 005179ef: add esp, 0x10
         // 005179f2: mov ds:[esi], eax
      [-]00ff750cc7
         // 004644cf: push ss:[ebp+0xc]
         // 004644d2: mov ds:[edi+0x10], 0x0
      [-]83c40489
         // 004644df: add esp, 0x4
         // 004644e2: mov ds:[edi+0x8], eax
      [-]fdffff83c404
         // 00517a27: add esp, 0x4
      [-]558bec83ec08568b750883be
         // 00422420: push ebp
         // 00422421: mov ebp, esp
         // 00422423: sub esp, 0x8
         // 00422426: push esi
         // 00422427: mov esi, ss:[ebp+0x8]
         // 0042242a: cmp ds:[esi+0x290], 0xffffffffffffffff
      [-]6a026a0356e8
         // 00417e7a: push 0x2
         // 00417e7c: push 0x3
         // 00417e7e: push esi
         // 00417e7f: call 0x4237cc
      [-]8d45f850e8
         // 0051c39b: lea eax, ss:[ebp+0xfffffffffffffff8]
         // 0051c39e: push eax
         // 0051c39f: call __time64
      [-]ff75fcff75f8ffb6
         // 0051c3a4: push ss:[ebp+0xfffffffffffffffc]
         // 0051c3a7: push ss:[ebp+0xfffffffffffffff8]
         // 0051c3aa: push ds:[esi+0x264]
      [-]000083c41483
         // 0051c3b7: add esp, 0x14
         // 0051c3ba: cmp ds:[esi+0x10], 0x0
      [-]6a0356e8
         // 00417eac: push 0x3
         // 00417eae: push esi
         // 00417eaf: call 0x42380c
      [-]5e8be55dc3
         // 0051c3cb: pop esi
         // 0051c3cc: mov esp, ebp
         // 0051c3ce: pop ebp
         // 0051c3cf: retn 
      [-]558bec8b4d08
         // 0051c3f0: push ebp
         // 0051c3f1: mov ebp, esp
         // 0051c3f3: mov ecx, ss:[ebp+0x8]
      [-]0f1f4000
         // 0051c3fc: nop ds:[eax+0x0]
      [-]8b491c40
         // 0051c400: mov ecx, ds:[ecx+0x1c]
         // 0051c403: inc eax
      [-]558bec8b4d088b410483e80274
         // 0051c410: push ebp
         // 0051c411: mov ebp, esp
         // 0051c413: mov ecx, ss:[ebp+0x8]
         // 0051c416: mov eax, ds:[ecx+0x4]
         // 0051c419: sub eax, 0x2
         // 0051c41c: jz 0x51c422
      [-]ff75108b4118ff750c83c004506a02e8
         // 00417f0e: push ss:[ebp+0x10]
         // 00417f11: mov eax, ds:[ecx+0x18]
         // 00417f14: push ss:[ebp+0xc]
         // 00417f17: add eax, 0x4
         // 00417f1a: push eax
         // 00417f1b: push 0x2
         // 00417f1d: call 0x42635c
      [-]0083c4105dc3
         // 00417f22: add esp, 0x10
         // 00417f25: pop ebp
         // 00417f26: retn 
      [-]558bec83ec14a1
         // 00539eb0: push ebp
         // 00539eb1: mov ebp, esp
         // 00539eb3: sub esp, 0x14
         // 00539eb6: mov eax, ds:[___security_cookie]
      [-]0033c58945fc8b450c8b4d088945ec8b45108945f48b45148945f88d45ec68
         // 00539ebb: xor eax, ebp
         // 00539ebd: mov ss:[ebp+0xfffffffffffffffc], eax
         // 00539ec0: mov eax, ss:[ebp+0xc]
         // 00539ec3: mov ecx, ss:[ebp+0x8]
         // 00539ec6: mov ss:[ebp+0xffffffffffffffec], eax
         // 00539ec9: mov eax, ss:[ebp+0x10]
         // 00539ecc: mov ss:[ebp+0xfffffffffffffff4], eax
         // 00539ecf: mov eax, ss:[ebp+0x14]
         // 00539ed2: mov ss:[ebp+0xfffffffffffffff8], eax
         // 00539ed5: lea eax, ss:[ebp+0xffffffffffffffec]
         // 00539ed8: push 0x539f00
      [-]8b4dfc83c40c33cde8
         // 00539ee4: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 00539ee7: add esp, 0xc
         // 00539eea: xor ecx, ebp
         // 00539eec: call @__security_check_cookie@4
      [-]8be55dc3
         // 00539ef1: mov esp, ebp
         // 00539ef3: pop ebp
         // 00539ef4: retn 
      [-]558bec8b45088b00
         // 00522e90: push ebp
         // 00522e91: mov ebp, esp
         // 00522e93: mov eax, ss:[ebp+0x8]
         // 00522e96: mov eax, ds:[eax]
      [-]8b005dc3
         // 00522e9c: mov eax, ds:[eax]
         // 00522e9e: pop ebp
         // 00522e9f: retn 
      [-]558bec568b75088b86??
         // 0042a680: push ebp
         // 0042a681: mov ebp, esp
         // 0042a683: push esi
         // 0042a684: mov esi, ss:[ebp+0x8]
         // 0042a687: mov eax, ds:[esi+0x200]
      [-]0bc17411
         // 0051f934: or eax, ecx
         // 0051f936: jz 0x51f949
      [-]83c40ceb0f
         // 0051f944: add esp, 0xc
         // 0051f947: jmp 0x51f958
      [-]8d411b5e5dc3
         // 00524141: lea eax, ds:[ecx+0x1b]
         // 00524144: pop esi
         // 00524145: pop ebp
         // 00524146: retn 
      [-]558bec83ec
         // 0042ca10: push ebp
         // 0042ca11: mov ebp, esp
         // 0042ca13: sub esp, 0x8
      [-]83e80174
         // 00524aea: sub eax, 0x1
         // 00524aed: jz 0x524b1b
      [-]83e80174
         // 00524aef: sub eax, 0x1
         // 00524af2: jz 0x524b13
      [-]5b8be55dc3
         // 00524b01: pop ebx
         // 00524b02: mov esp, ebp
         // 00524b04: pop ebp
         // 00524b05: retn 
      [-]558bec8b450856508b30c786
         // 00435a30: push ebp
         // 00435a31: mov ebp, esp
         // 00435a33: mov eax, ss:[ebp+0x8]
         // 00435a36: push esi
         // 00435a37: push eax
         // 00435a38: mov esi, ds:[eax]
         // 00435a3a: mov ds:[esi+0x438], 0x0
      [-]000083c404
         // 00435a49: add esp, 0x4
      [-]ff83c408
         // 00478dbc: add esp, 0x8
      [-]558bec8b4d
         // 00435be0: push ebp
         // 00435be1: mov ebp, esp
         // 00435be3: mov ecx, ss:[ebp+0x10]
      [-]558bec8b4d
         // 00435cc0: push ebp
         // 00435cc1: mov ebp, esp
         // 00435cc3: mov ecx, ss:[ebp+0x10]
      [-]558bec568b7508c786
         // 0052a490: push ebp
         // 0052a491: mov ebp, esp
         // 0052a493: push esi
         // 0052a494: mov esi, ss:[ebp+0x8]
         // 0052a497: mov ds:[esi+0x518], 0x0
      [-]558bec81ec
         // 00479190: push ebp
         // 00479191: mov ebp, esp
         // 00479193: sub esp, 0xb4
      [-]0033c58945fc8b4508
         // 0047919e: xor eax, ebp
         // 004791a0: mov ss:[ebp+0xfffffffffffffffc], eax
         // 004791a3: mov eax, ss:[ebp+0x8]
      [-]5356578b
         // 004791ab: push ebx
         // 004791ac: push esi
         // 004791ad: push edi
         // 004791ae: mov ebx, ds:[eax]
      [-]3bc67c07
         // 0052efac: cmp eax, esi
         // 0052efae: jl 0x52efb7
      [-]3d????????76
         // 0052f004: cmp eax, 0x418937
         // 0052f009: jbe 0x52f035
      [-]a8100f85
         // 00436179: test b1 al, b1 0x10
         // 0043617b: jnz 0x4366a6
      [-]ff83c408
         // 0042caf5: add esp, 0x8
      [-]5e5b8b4dfc33cde8
         // 0042cafb: pop esi
         // 0042cafc: pop ebx
         // 0042cafd: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 0042cb00: xor ecx, ebp
         // 0042cb02: call @__security_check_cookie@4
      [-]8be55dc3
         // 0042cb07: mov esp, ebp
         // 0042cb09: pop ebp
         // 0042cb0a: retn 
      [-]84c07844
         // 0052f149: test b1 al, b1 al
         // 0052f14b: js 0x52f191
      [-]0bc17415
         // 0052a97b: or eax, ecx
         // 0052a97d: jz 0x52a994
      [-]ff83c410
         // 0043629a: add esp, 0x10
      [-]ff83c40881
         // 004362ad: add esp, 0x8
         // 004362b0: or ds:[edi+0x470], 0x80
      [-]0000200f84
         // 004362c1: jz 0x436381
      [-]81fe????????76
         // 0052f1dd: cmp esi, 0x2710
         // 0052f1e3: jbe 0x52f20e
      [-]6a006a64
         // 0043630e: push 0x0
         // 00436310: push 0x64
      [-]6a006a64ff
         // 0042cbf5: push 0x0
         // 0042cbf7: push 0x64
         // 0042cbf9: push ds:[edi+0x444]
      [-]565250e8
         // 0042cc0b: push esi
         // 0042cc0c: push edx
         // 0042cc0d: push eax
         // 0042cc0e: call 0x458d0c
      [-]00004089
         // 004363a0: mov ss:[ebp+0xffffffffffffff84], eax
      [-]3d????????7629
         // 0052f2c6: cmp eax, 0x2710
         // 0052f2cb: jbe 0x52f2f6
      [-]6a006a645150e8
         // 004363f9: push 0x0
         // 004363fb: push 0x64
         // 004363fd: push ecx
         // 004363fe: push eax
         // 004363ff: call __alldiv
      [-]6a006a64ff
         // 004b4b27: push 0x0
         // 004b4b29: push 0x64
         // 004b4b2b: push ds:[edi+0x43c]
      [-]3bf17c06
         // 0043649a: cmp esi, ecx
         // 0043649c: jl 0x4364a4
      [-]0f57c0660f1385
         // 0052f398: xorps b16 xmm0, b16 xmm0
         // 0052f39b: movlpd b8 ss:[ebp+0xffffffffffffff60], b16 xmm0
      [-]ffffff8b85
         // 0052f3a3: mov eax, ss:[ebp+0xffffffffffffff64]
      [-]50518d45
         // 004364db: push eax
         // 004364dc: push ecx
         // 004364dd: lea eax, ss:[ebp+0xfffffffffffffff0]
      [-]0000568d45
         // 004364e6: push esi
         // 004364e7: lea eax, ss:[ebp+0xffffffffffffffd8]
      [-]0000ffb5
         // 004364f1: push ss:[ebp+0xffffffffffffff74]
      [-]83c424f6c220740e
         // 0043650c: add esp, 0x24
         // 0043650f: test b1 dl, b1 0x20
         // 00436512: jz 0x436522
      [-]f6c240740e
         // 0052f402: test b1 dl, b1 0x40
         // 0052f405: jz 0x52f415
      [-]81fe????????76
         // 0052f44f: cmp esi, 0x2710
         // 0052f455: jbe 0x52f47a
      [-]6a006a64
         // 00436583: push 0x0
         // 00436585: push 0x64
      [-]5250ffb5
         // 0043658e: push edx
         // 0043658f: push eax
         // 00436590: push ss:[ebp+0xffffffffffffff70]
      [-]6a006a645150e8
         // 0052f484: push 0x0
         // 0052f486: push 0x64
         // 0052f488: push ecx
         // 0052f489: push eax
         // 0052f48a: call __allmul
      [-]565250e8
         // 0052f490: push esi
         // 0052f491: push edx
         // 0052f492: push eax
         // 0052f493: call __alldiv
      [-]83c40c508d45
         // 004bb390: add esp, 0xc
         // 004bb393: push eax
         // 004bb394: lea eax, ss:[ebp+0xfffffffffffffff0]
      [-]83c40c508d45
         // 004bb3b5: add esp, 0xc
         // 004bb3b8: push eax
         // 004bb3b9: lea eax, ss:[ebp+0xffffffffffffffba]
      [-]83c40c508d45
         // 004bb3ce: add esp, 0xc
         // 004bb3d1: push eax
         // 004bb3d2: lea eax, ss:[ebp+0xffffffffffffffa6]
      [-]83c40c50ff
         // 004bb3e7: add esp, 0xc
         // 004bb3ea: push eax
         // 004bb3eb: push ss:[ebp+0xffffffffffffff7c]
      [-]83c40c50ff75
         // 004bb409: add esp, 0xc
         // 004bb40c: push eax
         // 004bb40d: push ss:[ebp+0xffffffffffffff98]
      [-]83c40c50ff
         // 004bb41e: add esp, 0xc
         // 004bb421: push eax
         // 004bb422: push ss:[ebp+0xffffffffffffff8c]
      [-]5f5e33cd5be8
         // 004366ab: pop edi
         // 004366ac: pop esi
         // 004366ad: xor ecx, ebp
         // 004366af: pop ebx
         // 004366b0: call @__security_check_cookie@4
      [-]8be55dc3
         // 004366b5: mov esp, ebp
         // 004366b7: pop ebp
         // 004366b8: retn 
      [-]558bec568b7508578b7d0c
         // 0052f590: push ebp
         // 0052f591: mov ebp, esp
         // 0052f593: push esi
         // 0052f594: mov esi, ss:[ebp+0x8]
         // 0052f597: push edi
         // 0052f598: mov edi, ss:[ebp+0xc]
      [-]0f8fb5000000
         // 0052f59d: jg 0x52f658
      [-]81fe????????731b
         // 0052f5a5: cmp esi, 0x186a0
         // 0052f5ab: jnb 0x52f5c8
      [-]57568b751068??
         // 0051ec4d: push edi
         // 0051ec4e: push esi
         // 0051ec4f: mov esi, ss:[ebp+0x10]
         // 0051ec52: push 0x637fb0
      [-]6a0656e8
         // 0051ec57: push 0x6
         // 0051ec59: push esi
         // 0051ec5a: call _snprintf
      [-]ff83c414
         // 0051ec5f: add esp, 0x14
      [-]5f5e5dc3
         // 0051ec64: pop edi
         // 0051ec65: pop esi
         // 0051ec66: pop ebp
         // 0051ec67: retn 
      [-]0f8f88000000
         // 0052f5ca: jg 0x52f658
      [-]81fe????????7329
         // 0052f5d2: cmp esi, 0x9c4000
         // 0052f5d8: jnb 0x52f603
      [-]6a0068????????5756e8
         // 0051ec7a: push 0x0
         // 0051ec7c: push 0x400
         // 0051ec81: push edi
         // 0051ec82: push esi
         // 0051ec83: call __alldiv
      [-]8b7510525068
         // 0051ec88: mov esi, ss:[ebp+0x10]
         // 0051ec8b: push edx
         // 0051ec8c: push eax
         // 0051ec8d: push 0x637fb8
      [-]6a0656e8
         // 0051ec92: push 0x6
         // 0051ec94: push esi
         // 0051ec95: call _snprintf
      [-]ff83c414
         // 0051ec9a: add esp, 0x14
      [-]5f5e5dc3
         // 0051ec9f: pop edi
         // 0051eca0: pop esi
         // 0051eca1: pop ebp
         // 0051eca2: retn 
      [-]81fe????????7347
         // 0052f609: cmp esi, 0x6400000
         // 0052f60f: jnb 0x52f658
      [-]6a0068????????5756e8
         // 004b4e21: push 0x0
         // 004b4e23: push 0x100000
         // 004b4e28: push edi
         // 004b4e29: push esi
         // 004b4e2a: call __allrem
      [-]6a0068????????5250e8
         // 004b4e2f: push 0x0
         // 004b4e31: push 0x19999
         // 004b4e36: push edx
         // 004b4e37: push eax
         // 004b4e38: call __alldiv
      [-]52506a0068????????5756e8
         // 004b4e3d: push edx
         // 004b4e3e: push eax
         // 004b4e3f: push 0x0
         // 004b4e41: push 0x100000
         // 004b4e46: push edi
         // 004b4e47: push esi
         // 004b4e48: call __alldiv
      [-]8b7510525068
         // 004b4e4d: mov esi, ss:[ebp+0x10]
         // 004b4e50: push edx
         // 004b4e51: push eax
         // 004b4e52: push 0x53df38
      [-]6a0656e8
         // 004b4e57: push 0x6
         // 004b4e59: push esi
         // 004b4e5a: call _snprintf
      [-]ff83c41c
         // 004b4e5f: add esp, 0x1c
      [-]5f5e5dc3
         // 004b4e64: pop edi
         // 004b4e65: pop esi
         // 004b4e66: pop ebp
         // 004b4e67: retn 
      [-]83ff027f33
         // 0052f658: cmp edi, 0x2
         // 0052f65b: jg 0x52f690
      [-]81fe????????7329
         // 0052f65f: cmp esi, 0x71000000
         // 0052f665: jnb 0x52f690
      [-]6a0068????????5756e88b
         // 004bb537: push 0x0
         // 004bb539: push 0x100000
         // 004bb53e: push edi
         // 004bb53f: push esi
         // 004bb540: call __alldiv
      [-]7510525068
         // 004bb545: mov esi, ss:[ebp+0x10]
         // 004bb548: push edx
         // 004bb549: push eax
         // 004bb54a: push 0x78ca20
      [-]6a0656e8
         // 004bb54f: push 0x6
         // 004bb551: push esi
         // 004bb552: call _snprintf_0
      [-]ff83c414
         // 004bb557: add esp, 0x14
      [-]5f5e5dc3
         // 004bb55c: pop edi
         // 004bb55d: pop esi
         // 004bb55e: pop ebp
         // 004bb55f: retn 
      [-]83ff197f4d
         // 0052f690: cmp edi, 0x19
         // 0052f693: jg 0x52f6e2
      [-]6a0068????????5756e8
         // 004367cb: push 0x0
         // 004367cd: push 0x40000000
         // 004367d2: push edi
         // 004367d3: push esi
         // 004367d4: call __allrem
      [-]6a0068????????5250e8
         // 004367d9: push 0x0
         // 004367db: push 0x6666666
         // 004367e0: push edx
         // 004367e1: push eax
         // 004367e2: call __alldiv
      [-]52506a0068????????5756e8
         // 004367e7: push edx
         // 004367e8: push eax
         // 004367e9: push 0x0
         // 004367eb: push 0x40000000
         // 004367f0: push edi
         // 004367f1: push esi
         // 004367f2: call __alldiv
      [-]8b7510525068
         // 004367f7: mov esi, ss:[ebp+0x10]
         // 004367fa: push edx
         // 004367fb: push eax
         // 004367fc: push 0x581d28
      [-]6a0656e8
         // 00436801: push 0x6
         // 00436803: push esi
         // 00436804: call _snprintf
      [-]ff83c41c
         // 00436809: add esp, 0x1c
      [-]5f5e5dc3
         // 0043680e: pop edi
         // 0043680f: pop esi
         // 00436810: pop ebp
         // 00436811: retn 
      [-]81ff????????7f2f
         // 0052f6e2: cmp edi, 0x9c4
         // 0052f6e8: jg 0x52f719
      [-]6a0068????????5756e8
         // 00479d00: push 0x0
         // 00479d02: push 0x40000000
         // 00479d07: push edi
         // 00479d08: push esi
         // 00479d09: call __alldiv
      [-]8b7510525068
         // 00479d0e: mov esi, ss:[ebp+0x10]
         // 00479d11: push edx
         // 00479d12: push eax
         // 00479d13: push 0x57e1f0
      [-]6a0656e8
         // 00479d18: push 0x6
         // 00479d1a: push esi
         // 00479d1b: call _snprintf
      [-]ff83c414
         // 00479d20: add esp, 0x14
      [-]5f5e5dc3
         // 00479d25: pop edi
         // 00479d26: pop esi
         // 00479d27: pop ebp
         // 00479d28: retn 
      [-]81ff????????7f2f
         // 0052f719: cmp edi, 0x271000
         // 0052f71f: jg 0x52f750
      [-]68????????6a005756e8
         // 00436857: push 0x100
         // 0043685c: push 0x0
         // 0043685e: push edi
         // 0043685f: push esi
         // 00436860: call __alldiv
      [-]8b7510525068
         // 00436865: mov esi, ss:[ebp+0x10]
         // 00436868: push edx
         // 00436869: push eax
         // 0043686a: push 0x581d40
      [-]6a0656e8
         // 0043686f: push 0x6
         // 00436871: push esi
         // 00436872: call _snprintf
      [-]ff83c414
         // 00436877: add esp, 0x14
      [-]5f5e5dc3
         // 0043687c: pop edi
         // 0043687d: pop esi
         // 0043687e: pop ebp
         // 0043687f: retn 
      [-]68????????6a005756e8
         // 0052f750: push 0x40000
         // 0052f755: push 0x0
         // 0052f757: push edi
         // 0052f758: push esi
         // 0052f759: call __alldiv
      [-]8b7510525068
         // 0052f75e: mov esi, ss:[ebp+0x10]
         // 0052f761: push edx
         // 0052f762: push eax
         // 0052f763: push 0x65b8d8
      [-]6a0656e8
         // 0052f768: push 0x6
         // 0052f76a: push esi
         // 0052f76b: call _snprintf
      [-]ff83c414
         // 0052f770: add esp, 0x14
      [-]5f5e5dc3
         // 0052f775: pop edi
         // 0052f776: pop esi
         // 0052f777: pop ebp
         // 0052f778: retn 
      [-]558bec83ec08538b5d0c568b7510
         // 0052f780: push ebp
         // 0052f781: mov ebp, esp
         // 0052f783: sub esp, 0x8
         // 0052f786: push ebx
         // 0052f787: mov ebx, ss:[ebp+0xc]
         // 0052f78a: push esi
         // 0052f78b: mov esi, ss:[ebp+0x10]
      [-]8b4d08f30f7e05
         // 0052afb8: mov ecx, ss:[ebp+0x8]
         // 0052afbb: movq b16 xmm0, b8 ds:[0x6497e8]
      [-]005e5b660fd601a0
         // 0052afc3: pop esi
         // 0052afc4: pop ebx
         // 0052afc5: movq b8 ds:[ecx], b16 xmm0
         // 0052afc9: mov b1 al, b1 ds:[0x6497f0]
      [-]008841088be55dc3
         // 0052afce: mov b1 ds:[ecx+0x8], b1 al
         // 0052afd1: mov esp, ebp
         // 0052afd3: pop ebp
         // 0052afd4: retn 
      [-]576a0068????????5653e8
         // 00479dc5: push edi
         // 00479dc6: push 0x0
         // 00479dc8: push 0xe10
         // 00479dcd: push esi
         // 00479dce: push ebx
         // 00479dcf: call __alldiv
      [-]897df88945fc
         // 00479dd8: mov ss:[ebp+0xfffffffffffffff8], edi
         // 00479ddb: mov ss:[ebp+0xfffffffffffffffc], eax
      [-]0f8f8e000000
         // 00479de0: jg 0x479e74
      [-]83ff630f8783000000
         // 0052f7d8: cmp edi, 0x63
         // 0052f7db: ja 0x52f864
      [-]6a0068????????5057e8
         // 00436911: push 0x0
         // 00436913: push 0xe10
         // 00436918: push eax
         // 00436919: push edi
         // 0043691a: call __allmul
      [-]6a006a3c1bc250
         // 00436925: push 0x0
         // 00436927: push 0x3c
         // 00436929: sbb eax, edx
         // 00436971: push eax
      [-]6a0068????????5653e8
         // 0052f864: push 0x0
         // 0052f866: push 0x15180
         // 0052f86b: push esi
         // 0052f86c: push ebx
         // 0052f86d: call __alldiv
      [-]81ff????????773f
         // 0052f87f: cmp edi, 0x3e7
         // 0052f885: ja 0x52f8c6
      [-]6a0068????????5057e82b
         // 004369b7: push 0x0
         // 004369b9: push 0x15180
         // 004369be: push eax
         // 004369bf: push edi
         // 004369c0: call __allmul
         // 004369c5: sub ebx, eax
      [-]d86a0068????????1bf25653e8
         // 004369c7: push 0x0
         // 004369c9: push 0xe10
         // 004369ce: sbb esi, edx
         // 004369d0: push esi
         // 004369d1: push ebx
         // 004369d2: call __alldiv
      [-]5250ff75105768
         // 004369d7: push edx
         // 004369d8: push eax
         // 004369d9: push ss:[ebp+0x10]
         // 004369dc: push edi
         // 004369dd: push 0x581ce4
      [-]6a09ff7508e8
         // 004369e2: push 0x9
         // 004369e4: push ss:[ebp+0x8]
         // 004369e7: call _snprintf
      [-]ff83c41c5f5e5b8be55dc3
         // 004369ec: add esp, 0x1c
         // 004369ef: pop edi
         // 004369f0: pop esi
         // 004369f1: pop ebx
         // 004369f2: mov esp, ebp
         // 004369f4: pop ebp
         // 004369f5: retn 
      [-]6a09ff7508e8
         // 004369fd: push 0x9
         // 004369ff: push ss:[ebp+0x8]
         // 00436a02: call _snprintf
      [-]ff83c4145f5e5b8be55dc3
         // 00436a07: add esp, 0x14
         // 00436a0a: pop edi
         // 00436a0b: pop esi
         // 00436a0c: pop ebx
         // 00436a0d: mov esp, ebp
         // 00436a0f: pop ebp
         // 00436a10: retn 
      [-]558bec81ec????????a1
         // 00550000: push ebp
         // 00550001: mov ebp, esp
         // 00550003: sub esp, 0x194
         // 00550009: mov eax, ds:[___security_cookie]
      [-]0033c58945fc568b75088d85????????506a02ff15
         // 0055000e: xor eax, ebp
         // 00550010: mov ss:[ebp+0xfffffffffffffffc], eax
         // 00550013: push esi
         // 00550014: mov esi, ss:[ebp+0x8]
         // 00550017: lea eax, ss:[ebp+0xfffffffffffffe6c]
         // 0055001d: push eax
         // 0055001e: push 0x2
         // 00550020: call ds:[WSAStartup]
      [-]ff83c40c
         // 00440536: add esp, 0xc
      [-]5e8b4dfc33cde8
         // 0044053e: pop esi
         // 0044053f: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 00440542: xor ecx, ebp
         // 00440544: call @__security_check_cookie@4
      [-]8be55dc3
         // 00440549: mov esp, ebp
         // 0044054b: pop ebp
         // 0044054c: retn 
      [-]008b85????????3c027518
         // 0052c233: mov eax, ss:[ebp+0xfffffffffffffe6c]
         // 0052c239: cmp b1 al, b1 0x2
         // 0052c23b: jnz 0x52c255
      [-]c1e80884c07511
         // 00530a1d: shr eax, b1 0x8
         // 00530a20: test b1 al, b1 al
         // 00530a22: jnz 0x530a35
      [-]5e8b4dfc33cde8
         // 00440566: pop esi
         // 00440567: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 0044056a: xor ecx, ebp
         // 0044056c: call @__security_check_cookie@4
      [-]8be55dc3
         // 00440571: mov esp, ebp
         // 00440573: pop ebp
         // 00440574: retn 
      [-]ff8b4dfc83c40833cd
         // 00440580: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 00440583: add esp, 0x8
         // 00440586: xor ecx, ebp
      [-]8be55dc3
         // 00440593: mov esp, ebp
         // 00440595: pop ebp
         // 00440596: retn 
      [-]558bec538b5d085657
         // 00440630: push ebp
         // 00440631: mov ebp, esp
         // 00440633: push ebx
         // 00440634: mov ebx, ss:[ebp+0x8]
         // 00440637: push esi
         // 00440638: push edi
      [-]8b038bb8
         // 0044063b: mov eax, ds:[ebx]
         // 0044063d: mov edi, ds:[eax+0x114]
      [-]81c7????????0f1f80????????
         // 00440643: add edi, 0x1408
         // 00440649: nop ds:[eax+0x0]
      [-]83bf????????01750c
         // 00530af0: cmp ds:[edi+0xfffffffffffff400], 0x1
         // 00530af7: jnz 0x530b05
      [-]6a015653e8
         // 0048e99e: push 0x1
         // 0048e9a0: push esi
         // 0048e9a1: push ebx
         // 0048e9a2: call 0x48f3d0
      [-]000083c40c
         // 0048e9a7: add esp, 0xc
      [-]833f01750c
         // 00530b05: cmp ds:[edi], 0x1
         // 00530b08: jnz 0x530b16
      [-]6a015653e8
         // 0048e9af: push 0x1
         // 0048e9b1: push esi
         // 0048e9b2: push ebx
         // 0048e9b3: call 0x48f470
      [-]000083c40c
         // 0048e9b8: add esp, 0xc
      [-]4683c70483fe287c
         // 00530b16: inc esi
         // 00530b17: add edi, 0x4
         // 00530b1a: cmp esi, 0x28
         // 00530b1d: jl 0x530af0
      [-]5f5e5b5dc3
         // 00530b1f: pop edi
         // 00530b20: pop esi
         // 00530b21: pop ebx
         // 00530b22: pop ebp
         // 00530b23: retn 
      [-]558bec8b5508
         // 004c8ec0: push ebp
         // 004c8ec1: mov ebp, esp
         // 004c8ec3: mov edx, ss:[ebp+0x8]
      [-]0f84eb000000
         // 004c8ecd: jz 0x4c8fbe
      [-]8b4d1081f9????????753c
         // 00530b43: mov ecx, ss:[ebp+0x10]
         // 00530b46: cmp ecx, 0xff
         // 00530b4c: jnz 0x530b8a
      [-]8b4d148d81????????83f813771a
         // 00530b4e: mov ecx, ss:[ebp+0x14]
         // 00530b51: lea eax, ds:[ecx+0xffffffffffffff14]
         // 00530b57: cmp eax, 0x13
         // 00530b5a: ja 0x530b76
      [-]ff750c68
         // 0052c383: push ss:[ebp+0xc]
         // 0052c386: push 0x649b14
      [-]83c4105dc3
         // 0052c391: add esp, 0x10
         // 0052c394: pop ebp
         // 0052c395: retn 
      [-]51ff750c68
         // 004b6386: push ecx
         // 004b6387: push ss:[ebp+0xc]
         // 004b638a: push 0x53e22c
      [-]ff83c4105dc3
         // 004b6395: add esp, 0x10
         // 004b6398: pop ebp
         // 004b6399: retn 
      [-]5681f9????????7507
         // 00530b8a: push esi
         // 00530b8b: cmp ecx, 0xfb
         // 00530b91: jnz 0x530b9a
      [-]81f9????????7507
         // 00530b9a: cmp ecx, 0xfc
         // 00530ba0: jnz 0x530ba9
      [-]81f9????????7507
         // 00530ba9: cmp ecx, 0xfd
         // 00530baf: jnz 0x530bb8
      [-]81f9????????0f45c6
         // 0042e58b: cmp ecx, 0xfe
         // 0042e591: cmovnz eax, esi
      [-]8b4d1483f9277f21
         // 00530bcc: mov ecx, ss:[ebp+0x14]
         // 00530bcf: cmp ecx, 0x27
         // 00530bd2: jg 0x530bf5
      [-]5150ff750c68
         // 0052c3ff: push ecx
         // 0052c400: push eax
         // 0052c401: push ss:[ebp+0xc]
         // 0052c404: push 0x649b40
      [-]ff83c4145e5dc3
         // 0052c40f: add esp, 0x14
         // 0052c412: pop esi
         // 0052c413: pop ebp
         // 0052c414: retn 
      [-]81f9????????75e2
         // 00530bf5: cmp ecx, 0xff
         // 00530bfb: jnz 0x530bdf
      [-]5650ff750c68
         // 004b6412: push esi
         // 004b6413: push eax
         // 004b6414: push ss:[ebp+0xc]
         // 004b6417: push 0x53e240
      [-]ff83c4145e5dc3
         // 004b6422: add esp, 0x14
         // 004b6425: pop esi
         // 004b6426: pop ebp
         // 004b6427: retn 
      [-]ff751451ff750c68
         // 0052c438: push ss:[ebp+0x14]
         // 0052c43b: push ecx
         // 0052c43c: push ss:[ebp+0xc]
         // 0052c43f: push 0x649b4c
      [-]ff83c4145e
         // 0052c44a: add esp, 0x14
         // 0052c44d: pop esi
      [-]7d088b078b
         // 004b66e8: mov eax, ds:[edi]
         // 004b66ea: mov esi, ds:[eax+0x8664]
      [-]83e80074
         // 00440aae: sub eax, 0x0
         // 00440ab1: jz 0x440acc
      [-]08????????89
         // 00440ac1: mov ds:[ebx+esi*0x4], eax
      [-]0804000083
         // 00530f2f: sub edx, 0x0
      [-]08????????89
         // 00530f40: mov ds:[esi+eax*0x4], edx
      [-]08100000
      [-]68????????57e8
         // 00530f48: push 0xfc
         // 00530f4d: push edi
         // 00530f4e: call 0x5311b0
      [-]02000083c40c
         // 00530f53: add esp, 0xc
      [-]00000175
         // 00530f6d: jnz 0x530f47
      [-]558bec8b55088b4d0c568b028bb0
         // 0048eee0: push ebp
         // 0048eee1: mov ebp, esp
         // 0048eee3: mov edx, ss:[ebp+0x8]
         // 0048eee6: mov ecx, ss:[ebp+0xc]
         // 0048eee9: push esi
         // 0048eeea: mov eax, ds:[edx]
         // 0048eeec: mov esi, ds:[eax+0x154]
      [-]8b448e0883e8017466
         // 0048eef2: mov eax, ds:[esi+ecx*0x4]
         // 0048eef6: sub eax, 0x1
         // 0048eef9: jz 0x48ef61
      [-]83e8017437
         // 00530fab: sub eax, 0x1
         // 00530fae: jz 0x530fe7
      [-]83e8017573
         // 00530fb0: sub eax, 0x1
         // 00530fb3: jnz 0x531028
      [-]8b848e0804000083e8007445
         // 00530fb5: mov eax, ds:[esi+ecx*0x4]
         // 00530fbc: sub eax, 0x0
         // 00530fbf: jz 0x531006
      [-]5168????????52c7448e08????????89848e08040000e8cf01000083c40c5e5dc3
         // 00530fc6: push ecx
         // 00530fc7: push 0xfb
         // 00530fcc: push edx
         // 00530fcd: mov ds:[esi+ecx*0x4], 0x2
         // 00530fd5: mov ds:[esi+ecx*0x4], eax
         // 00530fdc: call 0x5311b0
         // 00530fe1: add esp, 0xc
         // 00530fe4: pop esi
         // 00530fe5: pop ebp
         // 00530fe6: retn 
      [-]8b848e0804000083e8007413
         // 00530fe7: mov eax, ds:[esi+ecx*0x4]
         // 00530fee: sub eax, 0x0
         // 00530ff1: jz 0x531006
      [-]83e8017530
         // 00530ff3: sub eax, 0x1
         // 00530ff6: jnz 0x531028
      [-]89448e0889848e080400005e5dc3
         // 00530ff8: mov ds:[esi+ecx*0x4], eax
         // 00530ffc: mov ds:[esi+ecx*0x4], eax
         // 00531003: pop esi
         // 00531004: pop ebp
         // 00531005: retn 
      [-]c7448e08????????5e5dc3
         // 00531006: mov ds:[esi+ecx*0x4], 0x0
         // 0053100e: pop esi
         // 0053100f: pop ebp
         // 00531010: retn 
      [-]5168????????52c7448e08????????e88b01000083c40c
         // 00531011: push ecx
         // 00531012: push 0xfc
         // 00531017: push edx
         // 00531018: mov ds:[esi+ecx*0x4], 0x0
         // 00531020: call 0x5311b0
         // 00531025: add esp, 0xc
      [-]558bec8b5508568b028bb0
         // 0048ef80: push ebp
         // 0048ef81: mov ebp, esp
         // 0048ef83: mov edx, ss:[ebp+0x8]
         // 0048ef86: push esi
         // 0048ef87: mov eax, ds:[edx]
         // 0048ef89: mov esi, ds:[eax+0x154]
      [-]8b450c8b8c86080c000083e9000f8481000000
         // 0048ef8f: mov eax, ss:[ebp+0xc]
         // 0048ef92: mov ecx, ds:[esi+eax*0x4]
         // 0048ef99: sub ecx, 0x0
         // 0048ef9c: jz 0x48f023
      [-]83e9027439
         // 00531052: sub ecx, 0x2
         // 00531055: jz 0x531090
      [-]83e9017566
         // 00531057: sub ecx, 0x1
         // 0053105a: jnz 0x5310c2
      [-]8b8c860810000083e900741a
         // 0053105c: mov ecx, ds:[esi+eax*0x4]
         // 00531063: sub ecx, 0x0
         // 00531066: jz 0x531082
      [-]83e9017555
         // 00531068: sub ecx, 0x1
         // 0053106b: jnz 0x5310c2
      [-]c78486080c0000????????898c86081000005e5dc3
         // 0053106d: mov ds:[esi+eax*0x4], 0x1
         // 00531078: mov ds:[esi+eax*0x4], ecx
         // 0053107f: pop esi
         // 00531080: pop ebp
         // 00531081: retn 
      [-]c78486080c0000????????5e5dc3
         // 00531082: mov ds:[esi+eax*0x4], 0x0
         // 0053108d: pop esi
         // 0053108e: pop ebp
         // 0053108f: retn 
      [-]8b8c860810000083e9007429
         // 00531090: mov ecx, ds:[esi+eax*0x4]
         // 00531097: sub ecx, 0x0
         // 0053109a: jz 0x5310c5
      [-]83e9017521
         // 0053109c: sub ecx, 0x1
         // 0053109f: jnz 0x5310c2
      [-]c78486080c0000????????898c8608100000
         // 005310a1: mov ds:[esi+eax*0x4], 0x3
         // 005310ac: mov ds:[esi+eax*0x4], ecx
      [-]5068????????52e8f100000083c40c
         // 005310b3: push eax
         // 005310b4: push 0xfe
         // 005310b9: push edx
         // 005310ba: call 0x5311b0
         // 005310bf: add esp, 0xc
      [-]c78486080c0000????????5e5dc3
         // 005310c5: mov ds:[esi+eax*0x4], 0x1
         // 005310d0: pop esi
         // 005310d1: pop ebp
         // 005310d2: retn 
      [-]83bc86081400000175d6
         // 005310d3: cmp ds:[esi+eax*0x4], 0x1
         // 005310db: jnz 0x5310b3
      [-]5068????????52c78486080c0000????????e8bc00000083c40c5e5dc3
         // 005310dd: push eax
         // 005310de: push 0xfd
         // 005310e3: push edx
         // 005310e4: mov ds:[esi+eax*0x4], 0x1
         // 005310ef: call 0x5311b0
         // 005310f4: add esp, 0xc
         // 005310f7: pop esi
         // 005310f8: pop ebp
         // 005310f9: retn 
      [-]558bec8b55088b4d0c568b028bb0
         // 0048f050: push ebp
         // 0048f051: mov ebp, esp
         // 0048f053: mov edx, ss:[ebp+0x8]
         // 0048f056: mov ecx, ss:[ebp+0xc]
         // 0048f059: push esi
         // 0048f05a: mov eax, ds:[edx]
         // 0048f05c: mov esi, ds:[eax+0x154]
      [-]8b848e080c000083e801746f
         // 0048f062: mov eax, ds:[esi+ecx*0x4]
         // 0048f069: sub eax, 0x1
         // 0048f06c: jz 0x48f0dd
      [-]83e801743a
         // 0053111e: sub eax, 0x1
         // 00531121: jz 0x53115d
      [-]83e801757f
         // 00531123: sub eax, 0x1
         // 00531126: jnz 0x5311a7
      [-]8b848e0810000083e800744b
         // 00531128: mov eax, ds:[esi+ecx*0x4]
         // 0053112f: sub eax, 0x0
         // 00531132: jz 0x53117f
      [-]5168????????52c7848e080c0000????????89848e08100000e85900000083c40c5e5dc3
         // 00531139: push ecx
         // 0053113a: push 0xfd
         // 0053113f: push edx
         // 00531140: mov ds:[esi+ecx*0x4], 0x2
         // 0053114b: mov ds:[esi+ecx*0x4], eax
         // 00531152: call 0x5311b0
         // 00531157: add esp, 0xc
         // 0053115a: pop esi
         // 0053115b: pop ebp
         // 0053115c: retn 
      [-]8b848e0810000083e8007416
         // 0053115d: mov eax, ds:[esi+ecx*0x4]
         // 00531164: sub eax, 0x0
         // 00531167: jz 0x53117f
      [-]83e8017539
         // 00531169: sub eax, 0x1
         // 0053116c: jnz 0x5311a7
      [-]89848e080c000089848e081000005e5dc3
         // 0053116e: mov ds:[esi+ecx*0x4], eax
         // 00531175: mov ds:[esi+ecx*0x4], eax
         // 0053117c: pop esi
         // 0053117d: pop ebp
         // 0053117e: retn 
      [-]c7848e080c0000????????5e5dc3
         // 0053117f: mov ds:[esi+ecx*0x4], 0x0
         // 0053118a: pop esi
         // 0053118b: pop ebp
         // 0053118c: retn 
      [-]5168????????52c7848e080c0000????????e80c00000083c40c
         // 0053118d: push ecx
         // 0053118e: push 0xfe
         // 00531193: push edx
         // 00531194: mov ds:[esi+ecx*0x4], 0x0
         // 0053119f: call 0x5311b0
         // 005311a4: add esp, 0xc
      [-]558bec8b4510538b5d0c568b7508576a0088450a8d45088b3e6a0350ffb6
         // 00520850: push ebp
         // 00520851: mov ebp, esp
         // 00520853: mov eax, ss:[ebp+0x10]
         // 00520856: push ebx
         // 00520857: mov ebx, ss:[ebp+0xc]
         // 0052085a: push esi
         // 0052085b: mov esi, ss:[ebp+0x8]
         // 0052085e: push edi
         // 0052085f: push 0x0
         // 00520861: mov b1 ss:[ebp+0xa], b1 al
         // 00520864: lea eax, ss:[ebp+0x8]
         // 00520867: mov edi, ds:[esi]
         // 00520869: push 0x3
         // 0052086b: push eax
         // 0052086c: push ds:[esi+0x130]
      [-]c64508ff885d09ff15
         // 00520872: mov b1 ss:[ebp+0x8], b1 0xff
         // 00520876: mov b1 ss:[ebp+0x9], b1 bl
         // 00520879: call ds:[send]
      [-]ff83c40c
         // 004b6a05: add esp, 0xc
      [-]ff75105368
         // 0042ebc4: push ss:[ebp+0x10]
         // 0042ebc7: push ebx
         // 0042ebc8: push 0x45dd40
      [-]ffff83c4105f5e5b5dc3
         // 0042ebd4: add esp, 0x10
         // 0042ebd7: pop edi
         // 0042ebd8: pop esi
         // 0042ebd9: pop ebx
         // 0042ebda: pop ebp
         // 0042ebdb: retn 
      [-]558bec83ec
         // 00531210: push ebp
         // 00531211: mov ebp, esp
         // 00531213: sub esp, 0x14
      [-]ff4083c40c83f80176
         // 0053126f: inc eax
         // 00531270: add esp, 0xc
         // 00531273: cmp eax, 0x1
         // 00531276: jbe 0x5312af
      [-]5b8be55dc3
         // 0048f264: pop ebx
         // 0048f265: mov esp, ebp
         // 0048f267: pop ebp
         // 0048f268: retn 
      [-]558bec837d10018b550c568b75088b068b88
         // 0048f3d0: push ebp
         // 0048f3d1: mov ebp, esp
         // 0048f3d3: cmp ss:[ebp+0x10], 0x1
         // 0048f3d7: mov edx, ss:[ebp+0xc]
         // 0048f3da: push esi
         // 0048f3db: mov esi, ss:[ebp+0x8]
         // 0048f3de: mov eax, ds:[esi]
         // 0048f3e0: mov ecx, ds:[eax+0x154]
      [-]8b4491087541
         // 0048f3e6: mov eax, ds:[ecx+edx*0x4]
         // 0048f3ea: jnz 0x48f42d
      [-]83e8007422
         // 005312ec: sub eax, 0x0
         // 005312ef: jz 0x531313
      [-]83e8027446
         // 005312f1: sub eax, 0x2
         // 005312f4: jz 0x53133c
      [-]83bc9108????????7564
         // 005312fb: cmp ds:[ecx+edx*0x4], 0x0
         // 00531303: jnz 0x531369
      [-]c7849108040000????????5e5dc3
         // 00531305: mov ds:[ecx+edx*0x4], 0x1
         // 00531310: pop esi
         // 00531311: pop ebp
         // 00531312: retn 
      [-]5268????????56c7449108????????e8
         // 0048f413: push edx
         // 0048f414: push 0xfb
         // 0048f419: push esi
         // 0048f41a: mov ds:[ecx+edx*0x4], 0x2
         // 0048f422: call 0x48f100
      [-]ffff83c40c5e5dc3
         // 0048f427: add esp, 0xc
         // 0048f42a: pop esi
         // 0048f42b: pop ebp
         // 0048f42c: retn 
      [-]83e8017420
         // 0053132d: sub eax, 0x1
         // 00531330: jz 0x531352
      [-]83e80174c4
         // 00531332: sub eax, 0x1
         // 00531335: jz 0x5312fb
      [-]83e801752d
         // 00531337: sub eax, 0x1
         // 0053133a: jnz 0x531369
      [-]8b84910804000083e8017521
         // 0053133c: mov eax, ds:[ecx+edx*0x4]
         // 00531343: sub eax, 0x1
         // 00531346: jnz 0x531369
      [-]898491080400005e5dc3
         // 00531348: mov ds:[ecx+edx*0x4], eax
         // 0053134f: pop esi
         // 00531350: pop ebp
         // 00531351: retn 
      [-]5268????????56c7449108????????e8
         // 0048f452: push edx
         // 0048f453: push 0xfc
         // 0048f458: push esi
         // 0048f459: mov ds:[ecx+edx*0x4], 0x3
         // 0048f461: call 0x48f100
      [-]ffff83c40c
         // 0048f466: add esp, 0xc
      [-]558bec837d10018b550c568b75088b068b88
         // 0048f470: push ebp
         // 0048f471: mov ebp, esp
         // 0048f473: cmp ss:[ebp+0x10], 0x1
         // 0048f477: mov edx, ss:[ebp+0xc]
         // 0048f47a: push esi
         // 0048f47b: mov esi, ss:[ebp+0x8]
         // 0048f47e: mov eax, ds:[esi]
         // 0048f480: mov ecx, ds:[eax+0x154]
      [-]8b8491080c00007544
         // 0048f486: mov eax, ds:[ecx+edx*0x4]
         // 0048f48d: jnz 0x48f4d3
      [-]83e8007422
         // 0053138f: sub eax, 0x0
         // 00531392: jz 0x5313b6
      [-]83e8027449
         // 00531394: sub eax, 0x2
         // 00531397: jz 0x5313e2
      [-]83bc910810000000756a
         // 0053139e: cmp ds:[ecx+edx*0x4], 0x0
         // 005313a6: jnz 0x531412
      [-]c7849108100000????????5e5dc3
         // 005313a8: mov ds:[ecx+edx*0x4], 0x1
         // 005313b3: pop esi
         // 005313b4: pop ebp
         // 005313b5: retn 
      [-]5268????????56c78491080c0000????????e8
         // 0048f4b6: push edx
         // 0048f4b7: push 0xfd
         // 0048f4bc: push esi
         // 0048f4bd: mov ds:[ecx+edx*0x4], 0x2
         // 0048f4c8: call 0x48f100
      [-]ffff83c40c5e5dc3
         // 0048f4cd: add esp, 0xc
         // 0048f4d0: pop esi
         // 0048f4d1: pop ebp
         // 0048f4d2: retn 
      [-]8b84910810000083e8017524
         // 005313e2: mov eax, ds:[ecx+edx*0x4]
         // 005313e9: sub eax, 0x1
         // 005313ec: jnz 0x531412
      [-]898491081000005e5dc3
         // 005313ee: mov ds:[ecx+edx*0x4], eax
         // 005313f5: pop esi
         // 005313f6: pop ebp
         // 005313f7: retn 
      [-]68????????6a01
         // 00531a54: push 0x168
         // 00531a59: push 0x1
      [-]81fb????????7f05
         // 00531a88: cmp ebx, 0xffb8
         // 00531a8e: jg 0x531a95
      [-]83fb087d
         // 00531a90: cmp ebx, 0x8
         // 00531a93: jge 0x531a9f
      [-]8d4304506a01ff15
         // 0048fc03: lea eax, ds:[ebx+0x4]
         // 0048fc06: push eax
         // 0048fc07: push 0x1
         // 0048fc09: call ds:[0x5d4c40]
      [-]83c40889
         // 0048fc0f: add esp, 0x8
         // 0048fc12: mov ds:[esi+0x15c], eax
      [-]8d4304506a01ff15
         // 00531aca: lea eax, ds:[ebx+0x4]
         // 00531acd: push eax
         // 00531ace: push 0x1
         // 00531ad0: call ds:[0x67b030]
      [-]83c40889
         // 00531ad6: add esp, 0x8
         // 00531ad9: mov ds:[edi+0x160], eax
      [-]08????????c7
         // 0052d32f: mov ds:[edi+0x154], 0x200
      [-]668b4004668903e8
         // 0052d33d: mov b2 ax, b2 ds:[eax+0x4]
         // 0052d341: mov b2 ds:[ebx], b2 ax
         // 0052d344: call 0x52e510
      [-]000083c4
         // 0052d349: add esp, 0x4
      [-]ff701053ff
         // 0048fc98: push ds:[eax+0x10]
         // 0048fc9b: push ebx
         // 0048fc9c: push ds:[esi+0x14]
      [-]5f5e5b5dc3
         // 004ca113: pop edi
         // 004ca114: pop esi
         // 004ca115: pop ebx
         // 004ca116: pop ebp
         // 004ca117: retn 
      [-]83c4045f5e
         // 0052d3a4: add esp, 0x4
         // 0052d3a7: pop edi
         // 0052d3a8: pop esi
      [-]558becff750c6a00ff7508e8
         // 00441be0: push ebp
         // 00441be1: mov ebp, esp
         // 00441be3: push ss:[ebp+0xc]
         // 00441be6: push 0x0
         // 00441be8: push ss:[ebp+0x8]
         // 00441beb: call _memchr
      [-]2b45085dc3
         // 00531e47: sub eax, ss:[ebp+0x8]
         // 00531e4a: pop ebp
         // 00531e4b: retn 
      [-]8b450c5dc3
         // 00531e4c: mov eax, ss:[ebp+0xc]
         // 00531e4f: pop ebp
         // 00531e50: retn 
      [-]558bec8b45088b080fb6
         // 0042f84c: push ebp
         // 0042f84d: mov ebp, esp
         // 0042f84f: mov eax, ss:[ebp+0x8]
         // 0042f852: mov ecx, ds:[eax]
         // 0042f854: movzx eax, b1 ds:[ecx]
      [-]558bec8b5514
         // 00532210: push ebp
         // 00532211: mov ebp, esp
         // 00532213: mov edx, ss:[ebp+0x14]
      [-]568d71010f1f4000
         // 00532218: push esi
         // 00532219: lea esi, ds:[ecx+0x1]
         // 0053221c: nop ds:[eax+0x0]
      [-]8a014184c075f9
         // 00532220: mov b1 al, b1 ds:[ecx]
         // 00532222: inc ecx
         // 00532223: test b1 al, b1 al
         // 00532225: jnz 0x532220
      [-]8b450c2bce4003c88b45083b88????????7605
         // 00532227: mov eax, ss:[ebp+0xc]
         // 0053222a: sub ecx, esi
         // 0053222c: inc eax
         // 0053222d: add ecx, eax
         // 0053222f: mov eax, ss:[ebp+0x8]
         // 00532232: cmp ecx, ds:[eax+0x154]
         // 00532238: jbe 0x53223f
      [-]8a018d490188440eff84c075f3
         // 00532246: mov b1 al, b1 ds:[ecx]
         // 00532248: lea ecx, ds:[ecx+0x1]
         // 0053224b: mov b1 ds:[esi+ecx+0xffffffffffffffff], b1 al
         // 0053224f: test b1 al, b1 al
         // 00532251: jnz 0x532246
      [-]8a024284c075f9
         // 00532256: mov b1 al, b1 ds:[edx]
         // 00532258: inc edx
         // 00532259: test b1 al, b1 al
         // 0053225b: jnz 0x532256
      [-]2bd15e8d42015dc3
         // 0053225d: sub edx, ecx
         // 0053225f: pop esi
         // 00532260: lea eax, ds:[edx+0x1]
         // 00532263: pop ebp
         // 00532264: retn 
      [-]558bec538b5d0856578b7d0c5753e8
         // 00532270: push ebp
         // 00532271: mov ebp, esp
         // 00532273: push ebx
         // 00532274: mov ebx, ss:[ebp+0x8]
         // 00532277: push esi
         // 00532278: push edi
         // 00532279: mov edi, ss:[ebp+0xc]
         // 0053227c: push edi
         // 0053227d: push ebx
         // 0053227e: call 0x531e30
      [-]ffff83c4088d70013bf77207
         // 00532283: add esp, 0x8
         // 00532286: lea esi, ds:[eax+0x1]
         // 00532289: cmp esi, edi
         // 0053228b: jb 0x532294
      [-]8b45108918
         // 00441d94: mov eax, ss:[ebp+0x10]
         // 00441d97: mov ds:[eax], ebx
      [-]2bc6508d041e50e8
         // 00441d9b: sub eax, esi
         // 00441d9d: push eax
         // 00441d9e: lea eax, ds:[esi+ebx]
         // 00441da1: push eax
         // 00441da2: call 0x441be0
      [-]ffff83c4088d500103d63bd777da
         // 00441da7: add esp, 0x8
         // 00441daa: lea edx, ds:[eax+0x1]
         // 00441dad: add edx, esi
         // 00441daf: cmp edx, edi
         // 00441db1: ja 0x441d8d
      [-]8b45108b088d71010f1f440000
         // 005322b3: mov eax, ss:[ebp+0x10]
         // 005322b6: mov ecx, ds:[eax]
         // 005322b8: lea esi, ds:[ecx+0x1]
         // 005322bb: nop ds:[eax+eax+0x0]
      [-]8a014184c075f9
         // 005322c0: mov b1 al, b1 ds:[ecx]
         // 005322c2: inc ecx
         // 005322c3: test b1 al, b1 al
         // 005322c5: jnz 0x5322c0
      [-]8b45142bce4103cb5f89088d041a5e5b5dc3
         // 005322c7: mov eax, ss:[ebp+0x14]
         // 005322ca: sub ecx, esi
         // 005322cc: inc ecx
         // 005322cd: add ecx, ebx
         // 005322cf: pop edi
         // 005322d0: mov ds:[eax], ecx
         // 005322d2: lea eax, ds:[edx+ebx]
         // 005322d5: pop esi
         // 005322d6: pop ebx
         // 005322d7: pop ebp
         // 005322d8: retn 
      [-]558bec83ec108b550c
         // 00490240: push ebp
         // 00490241: mov ebp, esp
         // 00490243: sub esp, 0x10
         // 00490246: mov edx, ss:[ebp+0xc]
      [-]538b5d0856578b43108b38c783????????????????8b5d108d041a8945f03bd00f83
         // 0049024b: push ebx
         // 0049024c: mov ebx, ss:[ebp+0x8]
         // 0049024f: push esi
         // 00490250: push edi
         // 00490251: mov eax, ds:[ebx+0x10]
         // 00490254: mov edi, ds:[eax]
         // 00490256: mov ds:[ebx+0x154], 0x200
         // 00490260: mov ebx, ss:[ebp+0x10]
         // 00490263: lea eax, ds:[edx+ebx]
         // 00490266: mov ss:[ebp+0xfffffffffffffff0], eax
         // 00490269: cmp edx, eax
         // 0049026b: jnb 0x490441
      [-]8d45fc2bd1508d45f803d3505251e84cffffff83c4108945f4
         // 00490271: lea eax, ss:[ebp+0xfffffffffffffffc]
         // 00490274: sub edx, ecx
         // 00490276: push eax
         // 00490277: lea eax, ss:[ebp+0xfffffffffffffff8]
         // 0049027a: add edx, ebx
         // 0049027c: push eax
         // 0049027d: push edx
         // 0049027e: push ecx
         // 0049027f: call 0x4901d0
         // 00490284: add esp, 0x10
         // 00490287: mov ss:[ebp+0xfffffffffffffff4], eax
      [-]8b5dfc8b75f8535668
         // 0042fcfe: mov ebx, ss:[ebp+0xfffffffffffffffc]
         // 0042fd01: mov esi, ss:[ebp+0xfffffffffffffff8]
         // 0042fd04: push ebx
         // 0042fd05: push esi
         // 0042fd06: push 0x45e41c
      [-]83c4108d51010f1f00
         // 0042fd13: add esp, 0x10
         // 0042fd16: lea edx, ds:[ecx+0x1]
         // 0042fd19: nop ds:[eax]
      [-]8a014184c075f9
         // 00532350: mov b1 al, b1 ds:[ecx]
         // 00532352: inc ecx
         // 00532353: test b1 al, b1 al
         // 00532355: jnz 0x532350
      [-]2bca5168
         // 0042fd23: sub ecx, edx
         // 0042fd25: push ecx
         // 0042fd26: push 0x45e438
      [-]ff83c40c
         // 0042fd31: add esp, 0xc
      [-]6a0a6a0053e8
         // 00441e6c: push 0xa
         // 00441e6e: push 0x0
         // 00441e70: push ebx
         // 00441e71: call _strtol
      [-]3d????????0f8f
         // 00532381: cmp eax, 0xffb8
         // 00532386: jg 0x53246b
      [-]83f8080f8c
         // 0053238c: cmp eax, 0x8
         // 0053238f: jl 0x532462
      [-]8b5d088b8b????????3bc10f8f
         // 00532395: mov ebx, ss:[ebp+0x8]
         // 00532398: mov ecx, ds:[ebx+0x158]
         // 0053239e: cmp eax, ecx
         // 005323a0: jg 0x532442
      [-]578983????????e8
         // 004b7bc7: push edi
         // 004b7bc8: mov ds:[ebx+0x154], eax
         // 004b7bce: call 0x4a8460
      [-]ff83c418eb
         // 004b7bd3: add esp, 0x18
         // 004b7bd6: jmp 0x4b7c3b
      [-]8d51010f1f00
         // 005323ca: lea edx, ds:[ecx+0x1]
         // 005323cd: nop ds:[eax]
      [-]8a014184c075f9
         // 005323d0: mov b1 al, b1 ds:[ecx]
         // 005323d2: inc ecx
         // 005323d3: test b1 al, b1 al
         // 005323d5: jnz 0x5323d0
      [-]2bca5168
         // 0042fda3: sub ecx, edx
         // 0042fda5: push ecx
         // 0042fda6: push 0x45e538
      [-]ff83c40c
         // 0042fdb1: add esp, 0xc
      [-]6a0a6a0053e8
         // 00441eec: push 0xa
         // 00441eee: push 0x0
         // 00441ef0: push ebx
         // 00441ef1: call _strtol
      [-]ff83c41c
         // 00441f09: add esp, 0x1c
      [-]0f848c000000
         // 00532417: jz 0x5324a9
      [-]99525057e8
         // 00490382: cdq 
         // 00490383: push edx
         // 00490384: push eax
         // 00490385: push edi
         // 00490386: call 0x478ee0
      [-]8b4df43b4df00f83a7000000
         // 0053242b: mov ecx, ss:[ebp+0xfffffffffffffff4]
         // 0053242e: cmp ecx, ss:[ebp+0xfffffffffffffff0]
         // 00532431: jnb 0x5324de
      [-]8b550c8b5d10e9
         // 00532437: mov edx, ss:[ebp+0xc]
         // 0053243a: mov ebx, ss:[ebp+0x10]
         // 0053243d: jmp 0x532311
      [-]ff83c410
         // 00441f53: add esp, 0x10
      [-]5f5e5b8be55dc3
         // 00441f5b: pop edi
         // 00441f5c: pop esi
         // 00441f5d: pop ebx
         // 00441f5e: mov esp, ebp
         // 00441f60: pop ebp
         // 00441f61: retn 
      [-]68????????68
         // 0052dc8b: push 0xffb8
         // 0052dc90: push 0x64a2a0
      [-]ff83c410
         // 00441f80: add esp, 0x10
      [-]5f5e5b8be55dc3
         // 00441f88: pop edi
         // 00441f89: pop esi
         // 00441f8a: pop ebx
         // 00441f8b: mov esp, ebp
         // 00441f8d: pop ebp
         // 00441f8e: retn 
      [-]ff83c408
         // 00441f9a: add esp, 0x8
      [-]5f5e5b8be55dc3
         // 00441fa2: pop edi
         // 00441fa3: pop esi
         // 00441fa4: pop ebx
         // 00441fa5: mov esp, ebp
         // 00441fa7: pop ebp
         // 00441fa8: retn 
      [-]ff83c40c
         // 00441fb5: add esp, 0xc
      [-]5f5e5b8be55dc3
         // 00441fbd: pop edi
         // 00441fbe: pop esi
         // 00441fbf: pop ebx
         // 00441fc0: mov esp, ebp
         // 00441fc2: pop ebp
         // 00441fc3: retn 
      [-]ff83c408
         // 00441fcf: add esp, 0x8
      [-]5f5e5b8be55dc3
         // 00441fd7: pop edi
         // 00441fd8: pop esi
         // 00441fd9: pop ebx
         // 00441fda: mov esp, ebp
         // 00441fdc: pop ebp
         // 00441fdd: retn 
      [-]5b8be55dc3
         // 005324e2: pop ebx
         // 005324e3: mov esp, ebp
         // 005324e5: pop ebp
         // 005324e6: retn 
      [-]558bec5356578b7d088b1f8d772856e8
         // 00432200: push ebp
         // 00432201: mov ebp, esp
         // 00432203: push ebx
         // 00432204: push esi
         // 00432205: push edi
         // 00432206: mov edi, ss:[ebp+0x8]
         // 00432209: mov ebx, ds:[edi]
         // 0043220b: lea esi, ds:[edi+0x28]
         // 0043220e: push esi
         // 0043220f: call 0x449ebd
      [-]508b47106a00ff30e8
         // 0043221b: push eax
         // 0043221c: mov eax, ds:[edi+0x10]
         // 0043221f: push 0x0
         // 00432221: push ds:[eax]
         // 00432223: call 0x422920
      [-]ff83c410
         // 00432228: add esp, 0x10
      [-]8b471068
         // 00442800: mov eax, ds:[edi+0x10]
         // 00442803: push 0x580974
      [-]ff83c408
         // 0044280f: add esp, 0x8
      [-]5f5e5b5dc3
         // 00442817: pop edi
         // 00442818: pop esi
         // 00442819: pop ebx
         // 0044281a: pop ebp
         // 0044281b: retn 
      [-]68????????5250e8
         // 00430712: push 0x3e8
         // 00430717: push edx
         // 00430718: push eax
         // 00430719: call 0x458d0c
      [-]89450803f389773013c8b8????????f7eb
         // 00430727: mov ss:[ebp+0x8], eax
         // 0043072a: add esi, ebx
         // 0043072c: mov ds:[edi+0x30], esi
         // 0043072f: adc ecx, eax
         // 00430731: mov eax, 0x66666667
         // 00430736: imul ebx
      [-]c1e81f03c283f8010f4cc1
         // 00430744: shr eax, b1 0x1f
         // 00430747: add eax, edx
         // 00430749: cmp eax, 0x1
         // 0043074c: cmovl eax, ecx
      [-]99f77f2089471c3bc17d
         // 00430754: cdq 
         // 00430755: idiv ds:[edi+0x20]
         // 00430758: mov ds:[edi+0x1c], eax
         // 0043075b: cmp eax, ecx
         // 0043075d: jge 0x4307ac
      [-]894f1ceb
         // 00532d93: mov ds:[edi+0x1c], ecx
         // 00532d96: jmp 0x532de0
      [-]68????????5250e8
         // 00430770: push 0x3e8
         // 00430775: push edx
         // 00430776: push eax
         // 00430777: call 0x458d0c
      [-]bb????????
         // 00532db4: mov ebx, 0xe10
      [-]8b0e8b460403cb89550813c2894f30894734b8????????f7ebd1fa
         // 00532dbb: mov ecx, ds:[esi]
         // 00532dbd: mov eax, ds:[esi+0x4]
         // 00532dc0: add ecx, ebx
         // 00532dc2: mov ss:[ebp+0x8], edx
         // 00532dc5: adc eax, edx
         // 00532dc7: mov ds:[edi+0x30], ecx
         // 00532dca: mov ds:[edi+0x34], eax
         // 00532dcd: mov eax, 0x66666667
         // 00532dd2: imul ebx
         // 00532dd4: sar edx, b1 0x1
      [-]c1e81f03c2894720
         // 00532dd8: shr eax, b1 0x1f
         // 00532ddb: add eax, edx
         // 00532ddd: mov ds:[edi+0x20], eax
      [-]837f20037d07
         // 00532de0: cmp ds:[edi+0x20], 0x3
         // 00532de4: jge 0x532ded
      [-]c74720????????
         // 00532de6: mov ds:[edi+0x20], 0x3
      [-]837f20327e07
         // 00532ded: cmp ds:[edi+0x20], 0x32
         // 00532df1: jle 0x532dfa
      [-]c74720????????
         // 00532df3: mov ds:[edi+0x20], 0x32
      [-]995250ff750853e8
         // 0055243f: cdq 
         // 00552440: push edx
         // 00552441: push eax
         // 00552442: push ss:[ebp+0x8]
         // 00552445: push ebx
         // 00552446: call __alldiv
      [-]560f4cc15089471c8b47302b472850ff378b471068
         // 00552453: push esi
         // 00552454: cmovl eax, ecx
         // 00552457: push eax
         // 00552458: mov ds:[edi+0x1c], eax
         // 0055245b: mov eax, ds:[edi+0x30]
         // 0055245e: sub eax, ds:[edi+0x28]
         // 00552461: push eax
         // 00552462: push ds:[edi]
         // 00552464: mov eax, ds:[edi+0x10]
         // 00552467: push 0x5a8430
      [-]ff8d473850e8
         // 00552473: lea eax, ds:[edi+0x38]
         // 00552476: push eax
         // 00552477: call __time64
      [-]5f5e5b5dc3
         // 00552481: pop edi
         // 00552482: pop esi
         // 00552483: pop ebx
         // 00552484: pop ebp
         // 00552485: retn 
      [-]558bec8b450883ec08568bb0
         // 0052e6f0: push ebp
         // 0052e6f1: mov ebp, esp
         // 0052e6f3: mov eax, ss:[ebp+0x8]
         // 0052e6f6: sub esp, 0x8
         // 0052e6f9: push esi
         // 0052e6fa: mov esi, ds:[eax+0x3d0]
      [-]578b7d0c
         // 0052e700: push edi
         // 0052e701: mov edi, ss:[ebp+0xc]
      [-]c707????????
         // 00532ee8: mov ds:[edi], 0xffffffffffffffff
      [-]8d45f850e8
         // 004429ce: lea eax, ss:[ebp+0xfffffffffffffff8]
         // 004429d1: push eax
         // 004429d2: call __time64
      [-]8b45fc83c4048b4df83b46347c1c
         // 004429d7: mov eax, ss:[ebp+0xfffffffffffffffc]
         // 004429da: add esp, 0x4
         // 004429dd: mov ecx, ss:[ebp+0xfffffffffffffff8]
         // 004429e0: cmp eax, ds:[esi+0x34]
         // 004429e3: jl 0x442a01
      [-]3b4e307615
         // 00532f07: cmp ecx, ds:[esi+0x30]
         // 00532f0a: jbe 0x532f21
      [-]5fc74608????????
         // 00532f0c: pop edi
         // 00532f0d: mov ds:[esi+0x8], 0xffffffffffffff9d
      [-]c706????????5e8be55dc3
         // 00532f16: mov ds:[esi], 0x3
         // 00532f1c: pop esi
         // 00532f1d: mov esp, ebp
         // 00532f1f: pop ebp
         // 00532f20: retn 
      [-]8b461c538d5e389903031353043955fc7c1c
         // 00532f21: mov eax, ds:[esi+0x1c]
         // 00532f24: push ebx
         // 00532f25: lea ebx, ds:[esi+0x38]
         // 00532f28: cdq 
         // 00532f29: add eax, ds:[ebx]
         // 00532f2b: adc edx, ds:[ebx+0x4]
         // 00532f2e: cmp ss:[ebp+0xfffffffffffffffc], edx
         // 00532f31: jl 0x532f4f
      [-]3bc87616
         // 00532f35: cmp ecx, eax
         // 00532f37: jbe 0x532f4f
      [-]c707????????
         // 00532f3d: mov ds:[edi], 0x7
      [-]8b4df883c404
         // 0052e769: mov ecx, ss:[ebp+0xfffffffffffffff8]
         // 0052e76c: add esp, 0x4
      [-]8b46305b5f2bc15e8be55dc3
         // 00532f4f: mov eax, ds:[esi+0x30]
         // 00532f52: pop ebx
         // 00532f53: pop edi
         // 00532f54: sub eax, ecx
         // 00532f56: pop esi
         // 00532f57: mov esp, ebp
         // 00532f59: pop ebp
         // 00532f5a: retn 
      [-]39450c0f95c0
         // 004c16f5: cmp ss:[ebp+0xc], eax
         // 004c16f8: setnz b1 al
      [-]558bec568b7508
         // 00439c8c: push ebp
         // 00439c8d: mov ebp, esp
         // 00439c8f: push esi
         // 00439c90: mov esi, ss:[ebp+0x8]
      [-]508b4e188b461c8b56
         // 00439c96: push eax
         // 00439c97: mov ecx, ds:[esi+0x18]
         // 00439c9a: mov eax, ds:[esi+0x1c]
         // 00439c9d: mov edx, ds:[esi+0x2c]
      [-]2bc10346145150ffb2
         // 00439ca0: sub eax, ecx
         // 00439ca2: add eax, ds:[esi+0x14]
         // 00439ca5: push ecx
         // 00439ca6: push eax
         // 00439ca7: push ds:[edx+0x130]
      [-]ff83c414
         // 00439cb3: add esp, 0x14
      [-]8b46188b4d083bc874
         // 0053c32e: mov eax, ds:[esi+0x18]
         // 0053c331: mov ecx, ss:[ebp+0x8]
         // 0053c334: cmp ecx, eax
         // 0053c336: jz 0x53c342
      [-]2bc1894618
         // 00537b68: sub eax, ecx
         // 00537b6a: mov ds:[esi+0x18], eax
      [-]ff7614ff15
         // 00498fb7: push ds:[esi+0x14]
         // 00498fba: call ds:[0x5d4c34]
      [-]c746????????00c746????????00c746????????00e8
         // 00498fc3: mov ds:[esi+0x14], 0x0
         // 00498fcb: mov ds:[esi+0x1c], 0x0
         // 00498fd2: mov ds:[esi+0x18], 0x0
         // 00498fd9: call 0x4712c0
      [-]558bec568b
         // 00439d4c: push ebp
         // 00439d4d: mov ebp, esp
         // 00439d4f: push esi
         // 00439d50: mov esi, ss:[ebp+0x8]
      [-]c746????????008b00
         // 00439d56: mov ds:[esi+0x8], 0x0
         // 00439d5d: mov eax, ds:[eax]
      [-]558bec83ec
         // 00537cc0: push ebp
         // 00537cc1: mov ebp, esp
         // 00537cc3: sub esp, 0x1c
      [-]53568b750c
         // 00537cc6: push ebx
         // 00537cc7: push esi
         // 00537cc8: mov esi, ss:[ebp+0xc]
      [-]8b451089
         // 00537ce9: mov eax, ss:[ebp+0x10]
         // 00537cef: mov ds:[eax], ecx
      [-]088b45148908
         // 00537cf1: mov eax, ss:[ebp+0x14]
         // 00537cf4: mov ds:[eax], ecx
      [-]8b4604ff368945
         // 004d83c0: mov eax, ds:[esi+0x4]
         // 004d83c3: push ds:[esi]
         // 004d83c5: mov ss:[ebp+0xc], eax
      [-]83c410c706????????c746????????00
         // 004d83d1: add esp, 0x10
         // 004d83d4: mov ds:[esi], 0x0
         // 004d83da: mov ds:[esi+0x4], 0x0
      [-]47803b0a75
         // 0053c594: inc edi
         // 0053c595: cmp b1 ds:[ebx], b1 0xa
         // 0053c598: jnz 0x53c5f2
      [-]57ff760c6a01
         // 004d8453: push edi
         // 004d8454: push ds:[esi+0xc]
         // 004d8457: push 0x1
      [-]57ff760c6a02ff75
         // 00537de5: push edi
         // 00537de6: push ds:[esi+0xc]
         // 00537de9: push 0x2
         // 00537deb: push ss:[ebp+0xffffffffffffffe8]
      [-]ff83c4108945
         // 00537dee: call 0x513e10
         // 00537df3: add esp, 0x10
         // 00537df6: mov ss:[ebp+0xfffffffffffffff4], eax
      [-]8d43018b55
         // 00537e14: lea eax, ds:[ebx+0x1]
         // 00537e17: mov edx, ss:[ebp+0xffffffffffffffec]
      [-]89460c8b45
         // 00537e1c: mov ds:[esi+0xc], eax
         // 00537e1f: mov eax, ss:[ebp+0xfffffffffffffff8]
      [-]ff83c40c
         // 004c1e12: add esp, 0xc
      [-]57897e04ff15
         // 0043a008: push edi
         // 0043a009: mov ds:[esi+0x4], edi
         // 0043a00c: call ds:[0x606664]
      [-]83c4048906
         // 0043a012: add esp, 0x4
         // 0043a015: mov ds:[esi], eax
      [-]ff7604ff760c50e8
         // 00537ebf: push ds:[esi+0x4]
         // 00537ec2: push ds:[esi+0xc]
         // 00537ec5: push eax
         // 00537ec6: call _memmove_0
      [-]5b8be55dc3
         // 0053c6d9: pop ebx
         // 0053c6da: mov esp, ebp
         // 0053c6dc: pop ebp
         // 0053c6dd: retn 
      [-]558bec8d451050
         // 0044fbe0: push ebp
         // 0044fbe1: mov ebp, esp
         // 0044fbe3: lea eax, ss:[ebp+0x10]
         // 0044fbe6: push eax
      [-]558bec83ec08
         // 0044fdc0: push ebp
         // 0044fdc1: mov ebp, esp
         // 0044fdc3: sub esp, 0x8
      [-]5e8be55dc3
         // 00499608: pop esi
         // 0049960a: mov esp, ebp
         // 0049960c: pop ebp
         // 0049960d: retn 
      [-]53ff751056e8
         // 0043a15c: push ebx
         // 0043a15d: push ss:[ebp+0x10]
         // 0043a160: push esi
         // 0043a161: call 0x42238c
      [-]8d431b5b
         // 0053c7ea: lea eax, ds:[ebx+0x1b]
         // 0053c7ed: pop ebx
      [-]5e8be55dc3
         // 0053c7ef: pop esi
         // 0053c7f0: mov esp, ebp
         // 0053c7f2: pop ebp
         // 0053c7f3: retn 
      [-]c745????????008d4e01
         // 0053c7f6: mov ss:[ebp+0x8], 0x0
         // 0053c7fd: lea ecx, ds:[esi+0x1]
      [-]8a064684c075f9
         // 0053c800: mov b1 al, b1 ds:[esi]
         // 0053c802: inc esi
         // 0053c803: test b1 al, b1 al
         // 0053c805: jnz 0x53c800
      [-]ffff8d4508508b45fc5653ffb0
         // 0053803f: lea eax, ss:[ebp+0x8]
         // 00538042: push eax
         // 00538043: mov eax, ss:[ebp+0xfffffffffffffffc]
         // 00538046: push esi
         // 00538047: push ebx
         // 00538048: push ds:[eax+0x130]
      [-]ff83c418
         // 00538054: add esp, 0x18
      [-]83c4045b5f
         // 00499678: add esp, 0x4
         // 0049967b: pop ebx
         // 0049967d: pop edi
      [-]8be55dc3
         // 0049967e: mov esp, ebp
         // 00499680: pop ebp
         // 00499681: retn 
      [-]558bec568b750c578b7d085657c60700ff15
         // 0049a180: push ebp
         // 0049a181: mov ebp, esp
         // 0049a183: push esi
         // 0049a184: mov esi, ss:[ebp+0xc]
         // 0049a187: push edi
         // 0049a188: mov edi, ss:[ebp+0x8]
         // 0049a18b: push esi
         // 0049a18c: push edi
         // 0049a18d: mov b1 ds:[edi], b1 0x0
         // 0049a190: call ds:[gethostname]
      [-]00c64437ff00
         // 0049a196: mov b1 ds:[edi+esi+0xffffffffffffffff], b1 0x0
      [-]6a2e57e8
         // 0043b8eb: push 0x2e
         // 0043b8ed: push edi
         // 0043b8ee: call 0x43f62c
      [-]5f5e5dc3
         // 0053df73: pop edi
         // 0053df74: pop esi
         // 0053df75: pop ebp
         // 0053df76: retn 
      [-]558bec83ec
         // 004c5480: push ebp
         // 004c5481: mov ebp, esp
         // 004c5483: sub esp, 0x20
      [-]0033c58945fc8b4d080f57c08b450c53568945ec
         // 004c548b: xor eax, ebp
         // 004c548d: mov ss:[ebp+0xfffffffffffffffc], eax
         // 004c5490: mov ecx, ss:[ebp+0x8]
         // 004c5493: xorps b16 xmm0, b16 xmm0
         // 004c5496: mov eax, ss:[ebp+0xc]
         // 004c5499: push ebx
         // 004c549a: push esi
         // 004c549b: mov ss:[ebp+0xffffffffffffffec], eax
      [-]8945e88845f0660fd645f18845f9
         // 004c54a8: mov ss:[ebp+0xffffffffffffffe8], eax
         // 004c54ab: mov b1 ss:[ebp+0xfffffffffffffff0], b1 al
         // 004c54ae: movq b8 ss:[ebp+0xfffffffffffffff1], b16 xmm0
         // 004c54b3: mov b1 ss:[ebp+0xfffffffffffffff9], b1 al
      [-]8a1f4783fe0a0f8d
         // 0053f126: mov b1 bl, b1 ds:[edi]
         // 0053f128: inc edi
         // 0053f129: cmp esi, 0xa
         // 0053f12c: jge 0x53f4c1
      [-]83e800740b
         // 0053f132: sub eax, 0x0
         // 0053f135: jz 0x53f142
      [-]83e80174
         // 0053f137: sub eax, 0x1
         // 0053f13a: jz 0x53f182
      [-]8b45e846ebe4
         // 0053f13c: mov eax, ss:[ebp+0xffffffffffffffe8]
         // 0053f13f: inc esi
         // 0053f140: jmp 0x53f126
      [-]0fb6c350
         // 0049c282: movzx eax, b1 bl
         // 0049c285: push eax
      [-]8b45e8885c35f046eb
         // 0053f164: mov eax, ss:[ebp+0xffffffffffffffe8]
         // 0053f167: mov b1 ss:[ebp+esi+0xfffffffffffffff0], b1 bl
         // 0053f16b: inc esi
         // 0053f16c: jmp 0x53f126
      [-]80fb3a0f854a030000
         // 0053f16e: cmp b1 bl, b1 0x3a
         // 0053f171: jnz 0x53f4c1
      [-]468945e8eb
         // 0049c2aa: inc esi
         // 0049c2ab: mov ss:[ebp+0xffffffffffffffe8], eax
         // 0049c2ae: jmp 0x49c266
      [-]80fb5d0f8536030000
         // 0053f182: cmp b1 bl, b1 0x5d
         // 0053f185: jnz 0x53f4c1
      [-]89388d45f0
         // 0043d6af: mov ds:[eax], edi
         // 0043d6b1: lea eax, ss:[ebp+0xfffffffffffffff0]
      [-]8a103a11751a
         // 0053f198: mov b1 dl, b1 ds:[eax]
         // 0053f19a: cmp b1 dl, b1 ds:[ecx]
         // 0053f19c: jnz 0x53f1b8
      [-]84d27412
         // 0053f19e: test b1 dl, b1 dl
         // 0053f1a0: jz 0x53f1b4
      [-]8a50013a5101750e
         // 0053f1a2: mov b1 dl, b1 ds:[eax+0x1]
         // 0053f1a5: cmp b1 dl, b1 ds:[ecx+0x1]
         // 0053f1a8: jnz 0x53f1b8
      [-]84d275e4
         // 0053f1b0: test b1 dl, b1 dl
         // 0053f1b2: jnz 0x53f198
      [-]1bc083c801
         // 0053f1b8: sbb eax, eax
         // 0053f1ba: or eax, 0x1
      [-]8b45ec5f5e5bc680
         // 004525f1: mov eax, ss:[ebp+0xffffffffffffffec]
         // 004525f4: pop edi
         // 004525f5: pop esi
         // 004525f6: pop ebx
         // 004525f7: mov b1 ds:[eax+0x102], b1 0x1
      [-]01000001
      [-]8b4dfc33cde8
         // 00452603: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 00452606: xor ecx, ebp
         // 00452608: call @__security_check_cookie@4
      [-]8be55dc3
         // 0045260d: mov esp, ebp
         // 0045260f: pop ebp
         // 00452610: retn 
      [-]8d45f00f1f80????????
         // 0053aa06: lea eax, ss:[ebp+0xfffffffffffffff0]
         // 0053aa09: nop ds:[eax+0x0]
      [-]8a103a11751a
         // 0053f1f0: mov b1 dl, b1 ds:[eax]
         // 0053f1f2: cmp b1 dl, b1 ds:[ecx]
         // 0053f1f4: jnz 0x53f210
      [-]84d27412
         // 0053f1f6: test b1 dl, b1 dl
         // 0053f1f8: jz 0x53f20c
      [-]8a50013a5101750e
         // 0053f1fa: mov b1 dl, b1 ds:[eax+0x1]
         // 0053f1fd: cmp b1 dl, b1 ds:[ecx+0x1]
         // 0053f200: jnz 0x53f210
      [-]84d275e4
         // 0053f208: test b1 dl, b1 dl
         // 0053f20a: jnz 0x53f1f0
      [-]1bc083c801
         // 0053f210: sbb eax, eax
         // 0053f212: or eax, 0x1
      [-]8b45ec5f5e5bc68001
         // 00452649: mov eax, ss:[ebp+0xffffffffffffffec]
         // 0045264c: pop edi
         // 0045264d: pop esi
         // 0045264e: pop ebx
         // 0045264f: mov b1 ds:[eax+0x101], b1 0x1
      [-]8b4dfc33cde8
         // 0045265b: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 0045265e: xor ecx, ebp
         // 00452660: call @__security_check_cookie@4
      [-]8be55dc3
         // 00452665: mov esp, ebp
         // 00452667: pop ebp
         // 00452668: retn 
      [-]8a103a11751a
         // 0053f241: mov b1 dl, b1 ds:[eax]
         // 0053f243: cmp b1 dl, b1 ds:[ecx]
         // 0053f245: jnz 0x53f261
      [-]84d27412
         // 0053f247: test b1 dl, b1 dl
         // 0053f249: jz 0x53f25d
      [-]8a50013a5101750e
         // 0053f24b: mov b1 dl, b1 ds:[eax+0x1]
         // 0053f24e: cmp b1 dl, b1 ds:[ecx+0x1]
         // 0053f251: jnz 0x53f261
      [-]84d275e4
         // 0053f259: test b1 dl, b1 dl
         // 0053f25b: jnz 0x53f241
      [-]1bc083c801
         // 0053f261: sbb eax, eax
         // 0053f263: or eax, 0x1
      [-]8b45ec5f5e5bc680
         // 0045269a: mov eax, ss:[ebp+0xffffffffffffffec]
         // 0045269d: pop edi
         // 0045269e: pop esi
         // 0045269f: pop ebx
         // 004526a0: mov b1 ds:[eax+0x104], b1 0x1
      [-]01000001
      [-]8b4dfc33cde8
         // 004526ac: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 004526af: xor ecx, ebp
         // 004526b1: call @__security_check_cookie@4
      [-]8be55dc3
         // 004526b6: mov esp, ebp
         // 004526b8: pop ebp
         // 004526b9: retn 
      [-]8a103a11751a
         // 0053f292: mov b1 dl, b1 ds:[eax]
         // 0053f294: cmp b1 dl, b1 ds:[ecx]
         // 0053f296: jnz 0x53f2b2
      [-]84d27412
         // 0053f298: test b1 dl, b1 dl
         // 0053f29a: jz 0x53f2ae
      [-]8a50013a5101750e
         // 0053f29c: mov b1 dl, b1 ds:[eax+0x1]
         // 0053f29f: cmp b1 dl, b1 ds:[ecx+0x1]
         // 0053f2a2: jnz 0x53f2b2
      [-]84d275e4
         // 0053f2aa: test b1 dl, b1 dl
         // 0053f2ac: jnz 0x53f292
      [-]1bc083c801
         // 0053f2b2: sbb eax, eax
         // 0053f2b4: or eax, 0x1
      [-]8b45ec5f5e5bc680
         // 0043d7d7: mov eax, ss:[ebp+0xffffffffffffffec]
         // 0043d7da: pop edi
         // 0043d7db: pop esi
         // 0043d7dc: pop ebx
         // 0043d7dd: mov b1 ds:[eax+0x103], b1 0x1
      [-]01000001
      [-]8b4dfc33cde8
         // 0043d7e9: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 0043d7ec: xor ecx, ebp
         // 0043d7ee: call @__security_check_cookie@4
      [-]8be55dc3
         // 0043d7f3: mov esp, ebp
         // 0043d7f5: pop ebp
         // 0043d7f6: retn 
      [-]8a103a11751a
         // 0053f2e3: mov b1 dl, b1 ds:[eax]
         // 0053f2e5: cmp b1 dl, b1 ds:[ecx]
         // 0053f2e7: jnz 0x53f303
      [-]84d27412
         // 0053f2e9: test b1 dl, b1 dl
         // 0053f2eb: jz 0x53f2ff
      [-]8a50013a5101750e
         // 0053f2ed: mov b1 dl, b1 ds:[eax+0x1]
         // 0053f2f0: cmp b1 dl, b1 ds:[ecx+0x1]
         // 0053f2f3: jnz 0x53f303
      [-]84d275e4
         // 0053f2fb: test b1 dl, b1 dl
         // 0053f2fd: jnz 0x53f2e3
      [-]1bc083c801
         // 0053f303: sbb eax, eax
         // 0053f305: or eax, 0x1
      [-]8b45ec5f5e5bc680
         // 0043d828: mov eax, ss:[ebp+0xffffffffffffffec]
         // 0043d82b: pop edi
         // 0043d82c: pop esi
         // 0043d82d: pop ebx
         // 0043d82e: mov b1 ds:[eax+0x105], b1 0x1
      [-]01000001
      [-]8b4dfc33cde8
         // 0043d83a: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 0043d83d: xor ecx, ebp
         // 0043d83f: call @__security_check_cookie@4
      [-]8be55dc3
         // 0043d844: mov esp, ebp
         // 0043d846: pop ebp
         // 0043d847: retn 
      [-]8a103a11751a
         // 0053f334: mov b1 dl, b1 ds:[eax]
         // 0053f336: cmp b1 dl, b1 ds:[ecx]
         // 0053f338: jnz 0x53f354
      [-]84d27412
         // 0053f33a: test b1 dl, b1 dl
         // 0053f33c: jz 0x53f350
      [-]8a50013a5101750e
         // 0053f33e: mov b1 dl, b1 ds:[eax+0x1]
         // 0053f341: cmp b1 dl, b1 ds:[ecx+0x1]
         // 0053f344: jnz 0x53f354
      [-]84d275e4
         // 0053f34c: test b1 dl, b1 dl
         // 0053f34e: jnz 0x53f334
      [-]1bc083c801
         // 0053f354: sbb eax, eax
         // 0053f356: or eax, 0x1
      [-]8b45ec5f5e5bc680
         // 0045278d: mov eax, ss:[ebp+0xffffffffffffffec]
         // 00452790: pop edi
         // 00452791: pop esi
         // 00452792: pop ebx
         // 00452793: mov b1 ds:[eax+0x108], b1 0x1
      [-]01000001
      [-]8b4dfc33cde8
         // 0045279f: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 004527a2: xor ecx, ebp
         // 004527a4: call @__security_check_cookie@4
      [-]8be55dc3
         // 004527a9: mov esp, ebp
         // 004527ab: pop ebp
         // 004527ac: retn 
      [-]8a103a11751a
         // 0053f385: mov b1 dl, b1 ds:[eax]
         // 0053f387: cmp b1 dl, b1 ds:[ecx]
         // 0053f389: jnz 0x53f3a5
      [-]84d27412
         // 0053f38b: test b1 dl, b1 dl
         // 0053f38d: jz 0x53f3a1
      [-]8a50013a5101750e
         // 0053f38f: mov b1 dl, b1 ds:[eax+0x1]
         // 0053f392: cmp b1 dl, b1 ds:[ecx+0x1]
         // 0053f395: jnz 0x53f3a5
      [-]84d275e4
         // 0053f39d: test b1 dl, b1 dl
         // 0053f39f: jnz 0x53f385
      [-]1bc083c801
         // 0053f3a5: sbb eax, eax
         // 0053f3a7: or eax, 0x1
      [-]8b45ec5f5e5bc680
         // 0052ea2e: mov eax, ss:[ebp+0xffffffffffffffec]
         // 0052ea31: pop edi
         // 0052ea32: pop esi
         // 0052ea33: pop ebx
         // 0052ea34: mov b1 ds:[eax+0x109], b1 0x1
      [-]01000001
      [-]8b4dfc33cde8
         // 0052ea40: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 0052ea43: xor ecx, ebp
         // 0052ea45: call @__security_check_cookie@4
      [-]8be55dc3
         // 0052ea4a: mov esp, ebp
         // 0052ea4c: pop ebp
         // 0052ea4d: retn 
      [-]8a103a11751a
         // 0053f3d6: mov b1 dl, b1 ds:[eax]
         // 0053f3d8: cmp b1 dl, b1 ds:[ecx]
         // 0053f3da: jnz 0x53f3f6
      [-]84d27412
         // 0053f3dc: test b1 dl, b1 dl
         // 0053f3de: jz 0x53f3f2
      [-]8a50013a5101750e
         // 0053f3e0: mov b1 dl, b1 ds:[eax+0x1]
         // 0053f3e3: cmp b1 dl, b1 ds:[ecx+0x1]
         // 0053f3e6: jnz 0x53f3f6
      [-]84d275e4
         // 0053f3ee: test b1 dl, b1 dl
         // 0053f3f0: jnz 0x53f3d6
      [-]1bc083c801
         // 0053f3f6: sbb eax, eax
         // 0053f3f8: or eax, 0x1
      [-]8b45ec5f5e5bc6800701000001
         // 0052eb21: mov eax, ss:[ebp+0xffffffffffffffec]
         // 0052eb24: pop edi
         // 0052eb25: pop esi
         // 0052eb26: pop ebx
         // 0052eb27: mov b1 ds:[eax+0x107], b1 0x1
      [-]8b4dfc33cde8
         // 0052eb33: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 0052eb36: xor ecx, ebp
         // 0052eb38: call @__security_check_cookie@4
      [-]8be55dc3
         // 0052eb3d: mov esp, ebp
         // 0052eb3f: pop ebp
         // 0052eb40: retn 
      [-]5f5e33cd5be8
         // 004528f6: pop edi
         // 004528f7: pop esi
         // 004528f8: xor ecx, ebp
         // 004528fa: pop ebx
         // 004528fb: call @__security_check_cookie@4
      [-]8be55dc3
         // 00452900: mov esp, ebp
         // 00452902: pop ebp
         // 00452903: retn 

  }
  condition:
    all of them
}
