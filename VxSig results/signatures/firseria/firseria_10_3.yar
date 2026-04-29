rule firseria_10_3 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         e24100e9
         // 00401006: jmp 0x40bfac
      [-]558bec568bf1c706
         // 0040100b: push ebp
         // 0040100c: mov ebp, esp
         // 0040100e: push esi
         // 0040100f: mov esi, ecx
         // 00401011: mov ds:[esi], ??_7bad_alloc@std@@6B@
      [-]e24100e8
         // 00401017: call 0x40bfac
      [-]0000f64508017407
         // 0040101c: test b1 ss:[ebp+0x8], b1 0x1
         // 00401020: jz 0x401029
      [-]8bc65e5dc20400
         // 00401029: mov eax, esi
         // 0040102b: pop esi
         // 0040102c: pop ebp
         // 0040102d: retn b2 0x4
      [-]5685d27411
         // 00401030: push esi
         // 00401031: test edx, edx
         // 00401033: jz 0x401046
      [-]668b30663b31750d
         // 00401035: mov b2 si, b2 ds:[eax]
         // 00401038: cmp b2 si, b2 ds:[ecx]
         // 0040103b: jnz 0x40104a
      [-]83c00283c1024a75ef
         // 0040103d: add eax, 0x2
         // 00401040: add ecx, 0x2
         // 00401043: dec edx
         // 00401044: jnz 0x401035
      [-]33c05ec3
         // 00401046: xor eax, eax
         // 00401048: pop esi
         // 00401049: retn 
      [-]0fb700663b015e1bc083e0fe40c3
         // 0040104a: movzx eax, b2 ds:[eax]
         // 0040104d: cmp b2 ax, b2 ds:[ecx]
         // 00401050: pop esi
         // 00401051: sbb eax, eax
         // 00401053: and eax, 0xfffffffffffffffe
         // 00401056: inc eax
         // 00401057: retn 
      [-]568bf0837e1408577202
         // 004011ce: push esi
         // 004011cf: mov esi, eax
         // 004011d1: cmp ds:[esi+0x14], 0x8
         // 004011d5: push edi
         // 004011d6: jb 0x4011da
      [-]837e14087204
         // 004011dc: cmp ds:[esi+0x14], 0x8
         // 004011e0: jb 0x4011e6
      [-]8b06eb02
         // 004011e2: mov eax, ds:[esi]
         // 004011e4: jmp 0x4011e8
      [-]8b4e108d04483bf87413
         // 004011e8: mov ecx, ds:[esi+0x10]
         // 004011eb: lea eax, ds:[eax+ecx*0x2]
         // 004011ee: cmp edi, eax
         // 004011f0: jz 0x401205
      [-]0fb70750e8
         // 004011f2: movzx eax, b2 ds:[edi]
         // 004011f5: push eax
         // 004011f6: call _isdigit
      [-]00005985c07405
         // 004011fb: pop ecx
         // 004011fc: test eax, eax
         // 004011fe: jz 0x401205
      [-]83c702ebd7
         // 00401200: add edi, 0x2
         // 00401203: jmp 0x4011dc
      [-]8b461085c07414
         // 00401205: mov eax, ds:[esi+0x10]
         // 00401208: test eax, eax
         // 0040120a: jz 0x401220
      [-]837e14087202
         // 0040120c: cmp ds:[esi+0x14], 0x8
         // 00401210: jb 0x401214
      [-]8d04463bf87505
         // 00401214: lea eax, ds:[esi+eax*0x2]
         // 00401217: cmp edi, eax
         // 00401219: jnz 0x401220
      [-]33c040eb02
         // 0040121b: xor eax, eax
         // 0040121d: inc eax
         // 0040121e: jmp 0x401222
      [-]558bec8b450c8d4802
         // 00401345: push ebp
         // 00401346: mov ebp, esp
         // 00401348: mov eax, ss:[ebp+0xc]
         // 0040134b: lea ecx, ds:[eax+0x2]
      [-]668b1083c0026685d275f5
         // 0040134e: mov b2 dx, b2 ds:[eax]
         // 00401351: add eax, 0x2
         // 00401354: test b2 dx, b2 dx
         // 00401357: jnz 0x40134e
      [-]2bc18b4d08d1f850ff750c8b4510e8
         // 00401359: sub eax, ecx
         // 0040135b: mov ecx, ss:[ebp+0x8]
         // 0040135e: sar eax, b1 0x1
         // 00401360: push eax
         // 00401361: push ss:[ebp+0xc]
         // 00401364: mov eax, ss:[ebp+0x10]
         // 00401367: call 0x4013b7
      [-]0000005dc20c00
         // 0040136c: pop ebp
         // 0040136d: retn b2 0xc
      [-]00000084c074
         // 004014e3: test b1 al, b1 al
         // 004014e5: jz 0x40151c
      [-]837f14087204
         // 004014e7: cmp ds:[edi+0x14], 0x8
         // 004014eb: jb 0x4014f1
      [-]000083c40c83
         // 00401501: add esp, 0xc
         // 00401504: cmp ds:[edi+0x14], 0x8
      [-]33c966890c
         // 004015c0: xor ecx, ecx
         // 004015c2: mov b2 ds:[edi+eax], b2 cx
      [-]558bec81
         // 004015bb: push ebp
         // 004015bc: mov ebp, esp
         // 004015be: cmp esi, 0x7ffffffe
      [-]000000eb
         // 004015e1: jmp 0x401614
      [-]807d080074
         // 004015e3: cmp b1 ss:[ebp+0x8], b1 0x0
         // 004015e7: jz 0x401601
      [-]feffffeb13
         // 004015ff: jmp 0x401614
      [-]1083f8087202
         // 00401608: cmp eax, 0x8
         // 0040160b: jb 0x40160f
      [-]33c06689
         // 0040160f: xor eax, eax
         // 00401611: mov b2 ds:[ecx], b2 ax
      [-]1bc0f7d8
         // 00401618: sbb eax, eax
         // 0040161a: neg eax
      [-]558bec837d0800742d
         // 00401620: push ebp
         // 00401621: mov ebp, esp
         // 00401623: cmp ss:[ebp+0x8], 0x0
         // 00401627: jz 0x401656
      [-]8b501483fa087204
         // 00401629: mov edx, ds:[eax+0x14]
         // 0040162c: cmp edx, 0x8
         // 0040162f: jb 0x401635
      [-]8b08eb02
         // 00401631: mov ecx, ds:[eax]
         // 00401633: jmp 0x401637
      [-]394d08721a
         // 00401637: cmp ss:[ebp+0x8], ecx
         // 0040163a: jb 0x401656
      [-]83fa087204
         // 0040163c: cmp edx, 0x8
         // 0040163f: jb 0x401645
      [-]8b08eb02
         // 00401641: mov ecx, ds:[eax]
         // 00401643: jmp 0x401647
      [-]8b40108d04413b45087604
         // 00401647: mov eax, ds:[eax+0x10]
         // 0040164a: lea eax, ds:[ecx+eax*0x2]
         // 0040164d: cmp eax, ss:[ebp+0x8]
         // 00401650: jbe 0x401656
      [-]b001eb02
         // 00401652: mov b1 al, b1 0x1
         // 00401654: jmp 0x401658
      [-]5dc20400
         // 00401658: pop ebp
         // 00401659: retn b2 0x4
      [-]578bf88b46103bc1730a
         // 0040165c: push edi
         // 0040165d: mov edi, eax
         // 0040165f: mov eax, ds:[esi+0x10]
         // 00401662: cmp eax, ecx
         // 00401664: jnb 0x401670
      [-]2bc13bc77302
         // 00401670: sub eax, ecx
         // 00401672: cmp eax, edi
         // 00401674: jnb 0x401678
      [-]85ff744d
         // 00401678: test edi, edi
         // 0040167a: jz 0x4016c9
      [-]8b56145383fa087204
         // 0040167c: mov edx, ds:[esi+0x14]
         // 0040167f: push ebx
         // 00401680: cmp edx, 0x8
         // 00401683: jb 0x401689
      [-]8b1eeb02
         // 00401685: mov ebx, ds:[esi]
         // 00401687: jmp 0x40168b
      [-]83fa087204
         // 0040168b: cmp edx, 0x8
         // 0040168e: jb 0x401694
      [-]8b16eb02
         // 00401690: mov edx, ds:[esi]
         // 00401692: jmp 0x401696
      [-]2bc703c0508d04398d0443508d044a50e8
         // 0040168a: sub eax, edi
         // 0040168c: add eax, eax
         // 0040168e: push eax
         // 0040168f: lea eax, ds:[ecx+edi]
         // 00401692: lea eax, ds:[ebx+eax*0x2]
         // 00401695: push eax
         // 00401696: lea eax, ds:[edx+ecx*0x2]
         // 00401699: push eax
         // 0040169a: call _memcpy
      [-]00008b461083c40c2bc7837e14088946105b7204
         // 0040169f: mov eax, ds:[esi+0x10]
         // 004016a2: add esp, 0xc
         // 004016a5: sub eax, edi
         // 004016a7: cmp ds:[esi+0x14], 0x8
         // 004016ab: mov ds:[esi+0x10], eax
         // 004016ae: pop ebx
         // 004016af: jb 0x4016b5
      [-]8b0eeb02
         // 004016bd: mov ecx, ds:[esi]
         // 004016bf: jmp 0x4016c3
      [-]33d266891441
         // 004016c3: xor edx, edx
         // 004016c5: mov b2 ds:[ecx+eax*0x2], b2 dx
      [-]8bc65fc3
         // 004016c9: mov eax, esi
         // 004016cb: pop edi
         // 004016cc: retn 
      [-]07b9????????3b
         // 004016e2: mov ecx, 0x7ffffffe
         // 004016e7: cmp esi, ecx
      [-]148945ecd16dec8b
         // 004016f3: mov ss:[ebp+0xffffffffffffffec], eax
         // 004016f6: shr ss:[ebp+0xffffffffffffffec], b1 0x1
         // 004016f9: mov eax, esi
      [-]33d26a03
         // 004016fb: xor edx, edx
         // 004016fd: push 0x3
      [-]8b55ec3bd07610
         // 00401702: mov edx, ss:[ebp+0xffffffffffffffec]
         // 00401705: cmp edx, eax
         // 00401707: jbe 0x401719
      [-]8365fc008d
         // 00401719: and ss:[ebp+0xfffffffffffffffc], 0x0
         // 0040171d: lea ecx, ds:[esi+0x1]
      [-]0000008945e8834dfcffeb2b
         // 00401725: mov ss:[ebp+0xffffffffffffffe8], eax
         // 00401728: or ss:[ebp+0xfffffffffffffffc], 0xffffffffffffffff
         // 0040172c: jmp 0x401759
      [-]14087204
         // 00401764: jb 0x40176a
      [-]5150ff75e8e8
         // 0040176f: push ecx
         // 00401770: push eax
         // 00401771: push ss:[ebp+0xffffffffffffffe8]
         // 00401774: call _memcpy_0
      [-]000083c40c
         // 00401779: add esp, 0xc
      [-]0000c20c00
         // 004017a4: retn b2 0xc
      [-]558bec83ec1033c085c9743b
         // 004017bc: push ebp
         // 004017bd: mov ebp, esp
         // 004017bf: sub esp, 0x10
         // 004017c2: xor eax, eax
         // 004017c4: test ecx, ecx
         // 004017c6: jz 0x401803
      [-]81f9????????770e
         // 004017c8: cmp ecx, 0x7fffffff
         // 004017ce: ja 0x4017de
      [-]8d040950e8
         // 004017c4: lea eax, ds:[ecx+ecx]
         // 004017c7: push eax
         // 004017c8: call ??2@YAPAXI@Z
      [-]00005985c07525
         // 004017cd: pop ecx
         // 004017ce: test eax, eax
         // 004017d0: jnz 0x4017f7
      [-]8365fc008d45fc508d4df0e8
         // 004017d2: and ss:[ebp+0xfffffffffffffffc], 0x0
         // 004017d6: lea eax, ss:[ebp+0xfffffffffffffffc]
         // 004017d9: push eax
         // 004017da: lea ecx, ss:[ebp+0xfffffffffffffff0]
         // 004017dd: call ??0exception@std@@QAE@ABQBD@Z
      [-]42008d45f050c745f0
         // 004017e7: lea eax, ss:[ebp+0xfffffffffffffff0]
         // 004017ea: push eax
         // 004017eb: mov ss:[ebp+0xfffffffffffffff0], ??_7bad_alloc@std@@6B@
      [-]e24100e8
         // 004017f2: call __CxxThrowException@8
      [-]558bec56ff75088bf1e8
         // 00401805: push ebp
         // 00401806: mov ebp, esp
         // 00401808: push esi
         // 00401809: push ss:[ebp+0x8]
         // 0040180c: mov esi, ecx
         // 0040180e: call ??0exception@std@@QAE@ABV01@@Z
      [-]0000c706
         // 00401813: mov ds:[esi], ??_7bad_alloc@std@@6B@
      [-]e241008bc65e5dc20400
         // 00401819: mov eax, esi
         // 0040181b: pop esi
         // 0040181c: pop ebp
         // 0040181d: retn b2 0x4
      [-]558bec83ec0c5333db538bcee8
         // 0040193b: push ebp
         // 0040193c: mov ebp, esp
         // 0040193e: sub esp, 0xc
         // 00401941: push ebx
         // 00401942: xor ebx, ebx
         // 00401944: push ebx
         // 00401945: mov ecx, esi
         // 00401947: call ??0_Lockit@std@@QAE@H@Z
      [-]0000395d08895e04885e08895e0c885e10895e14885e18895e1c885e205b7528
         // 0040194c: cmp ss:[ebp+0x8], ebx
         // 0040194f: mov ds:[esi+0x4], ebx
         // 00401952: mov b1 ds:[esi+0x8], b1 bl
         // 00401955: mov ds:[esi+0xc], ebx
         // 00401958: mov b1 ds:[esi+0x10], b1 bl
         // 0040195b: mov ds:[esi+0x14], ebx
         // 0040195e: mov b1 ds:[esi+0x18], b1 bl
         // 00401961: mov ds:[esi+0x1c], ebx
         // 00401964: mov b1 ds:[esi+0x20], b1 bl
         // 00401967: pop ebx
         // 00401968: jnz 0x401992
      [-]8d4508508d4df4c74508
         // 00401869: lea eax, ss:[ebp+0x8]
         // 0040186c: push eax
         // 0040186d: lea ecx, ss:[ebp+0xfffffffffffffff4]
         // 00401870: mov ss:[ebp+0x8], 0x42294c
      [-]42008d45f450c745f4
         // 00401881: lea eax, ss:[ebp+0xfffffffffffffff4]
         // 00401884: push eax
         // 00401885: mov ss:[ebp+0xfffffffffffffff4], ??_7runtime_error@std@@6B@
      [-]e24100e8
         // 0040188c: call __CxxThrowException@8
      [-]ff750856e8
         // 00401992: push ss:[ebp+0x8]
         // 00401995: push esi
         // 00401996: call ?_Locinfo_ctor@_Locinfo@std@@SAXPAV12@PBD@Z
      [-]000059598bc6c9c20400
         // 0040199b: pop ecx
         // 0040199c: pop ecx
         // 0040199d: mov eax, esi
         // 0040199f: leave 
         // 004019a0: retn b2 0x4
      [-]00008b461c5985c07407
         // 004019a9: mov eax, ds:[esi+0x1c]
         // 004019ac: pop ecx
         // 004019ad: test eax, eax
         // 004019af: jz 0x4019b8
      [-]83661c008b461485c07407
         // 0040189d: and ds:[esi+0x1c], 0x0
         // 004018a1: mov eax, ds:[esi+0x14]
         // 004018a4: test eax, eax
         // 004018a6: jz 0x4018af
      [-]836614008b460c85c07407
         // 004018af: and ds:[esi+0x14], 0x0
         // 004018b3: mov eax, ds:[esi+0xc]
         // 004018b6: test eax, eax
         // 004018b8: jz 0x4018c1
      [-]83660c008b460485c07407
         // 004018c1: and ds:[esi+0xc], 0x0
         // 004018c5: mov eax, ds:[esi+0x4]
         // 004018c8: test eax, eax
         // 004018ca: jz 0x4018d3
      [-]836604008bcee9
         // 004019ee: and ds:[esi+0x4], 0x0
         // 004019f2: mov ecx, esi
         // 004019f4: jmp ??1_Lockit@std@@QAE@XZ
      [-]558bec56ff75088bf1e8
         // 004018de: push ebp
         // 004018df: mov ebp, esp
         // 004018e1: push esi
         // 004018e2: push ss:[ebp+0x8]
         // 004018e5: mov esi, ecx
         // 004018e7: call ??0exception@std@@QAE@ABV01@@Z
      [-]0000c706
         // 004018ec: mov ds:[esi], ??_7runtime_error@std@@6B@
      [-]e241008bc65e5dc20400
         // 004018f2: mov eax, esi
         // 004018f4: pop esi
         // 004018f5: pop ebp
         // 004018f6: retn b2 0x4
      [-]558bec51833e007524
         // 004018f9: push ebp
         // 004018fa: mov ebp, esp
         // 004018fc: push ecx
         // 004018fd: cmp ds:[esi], 0x0
         // 00401900: jnz 0x401926
      [-]6a008d4dfce8
         // 00401a1d: push 0x0
         // 00401a1f: lea ecx, ss:[ebp+0xfffffffffffffffc]
         // 00401a22: call ??0_Lockit@std@@QAE@H@Z
      [-]0000833e00750d
         // 00401a27: cmp ds:[esi], 0x0
         // 00401a2a: jnz 0x401a39
      [-]8d4dfce8
         // 00401a39: lea ecx, ss:[ebp+0xfffffffffffffffc]
         // 00401a3c: call ??1_Lockit@std@@QAE@XZ
      [-]8b06c9c3
         // 00401926: mov eax, ds:[esi]
         // 00401928: leave 
         // 00401929: retn 
      [-]558bec5156578bf96a008d4dfce8
         // 00401971: push ebp
         // 00401972: mov ebp, esp
         // 00401974: push ecx
         // 00401975: push esi
         // 00401976: push edi
         // 00401977: mov edi, ecx
         // 00401979: push 0x0
         // 0040197b: lea ecx, ss:[ebp+0xfffffffffffffffc]
         // 0040197e: call ??0_Lockit@std@@QAE@H@Z
      [-]00008b470485c07409
         // 00401983: mov eax, ds:[edi+0x4]
         // 00401986: test eax, eax
         // 00401988: jz 0x401993
      [-]83f8ff7304
         // 0040196b: cmp eax, 0xffffffffffffffff
         // 0040196e: jnb 0x401974
      [-]48894704
         // 00401970: dec eax
         // 00401971: mov ds:[edi+0x4], eax
      [-]8b7704f7de1bf6f7d68d4dfc23f7e8
         // 00401a8f: mov esi, ds:[edi+0x4]
         // 00401a92: neg esi
         // 00401a94: sbb esi, esi
         // 00401a96: not esi
         // 00401a98: lea ecx, ss:[ebp+0xfffffffffffffffc]
         // 00401a9b: and esi, edi
         // 00401a9d: call ??1_Lockit@std@@QAE@XZ
      [-]00005f8bc65ec9c3
         // 00401aa2: pop edi
         // 00401aa3: mov eax, esi
         // 00401aa5: pop esi
         // 00401aa6: leave 
         // 00401aa7: retn 
      [-]8b0985c97411
         // 00401994: mov ecx, ds:[ecx]
         // 00401996: test ecx, ecx
         // 00401998: jz 0x4019ab
      [-]e8b3ffffff85c07408
         // 0040199a: call 0x401952
         // 0040199f: test eax, eax
         // 004019a1: jz 0x4019ab
      [-]8b106a018bc8ff12
         // 004019a3: mov edx, ds:[eax]
         // 004019a5: push 0x1
         // 004019a7: mov ecx, eax
         // 004019a9: call ds:[edx]
      [-]8b083b710c7308
         // 004019ac: mov ecx, ds:[eax]
         // 004019ae: cmp esi, ds:[ecx+0xc]
         // 004019b1: jnb 0x4019bb
      [-]8b41088b04b0eb02
         // 004019b3: mov eax, ds:[ecx+0x8]
         // 004019b6: mov eax, ds:[eax+esi*0x4]
         // 004019b9: jmp 0x4019bd
      [-]85c07518
         // 004019bd: test eax, eax
         // 004019bf: jnz 0x4019d9
      [-]3841147413
         // 004019c1: cmp b1 ds:[ecx+0x14], b1 al
         // 004019c4: jz 0x4019d9
      [-]00003b700c7307
         // 00401ae6: cmp esi, ds:[eax+0xc]
         // 00401ae9: jnb 0x401af2
      [-]8b40088b04b0c3
         // 004019d0: mov eax, ds:[eax+0x8]
         // 004019d3: mov eax, ds:[eax+esi*0x4]
         // 004019d6: retn 
      [-]33c040c3
         // 004019da: xor eax, eax
         // 004019dc: inc eax
         // 004019dd: retn 
      [-]558bec83ec288365fc0085db745f
         // 004019de: push ebp
         // 004019df: mov ebp, esp
         // 004019e1: sub esp, 0x28
         // 004019e4: and ss:[ebp+0xfffffffffffffffc], 0x0
         // 004019e8: test ebx, ebx
         // 004019ea: jz 0x401a4b
      [-]833b00755a
         // 004019ec: cmp ds:[ebx], 0x0
         // 004019ef: jnz 0x401a4b
      [-]56576a10e8
         // 00401b0c: push esi
         // 00401b0d: push edi
         // 00401b0e: push 0x10
         // 00401b10: call ??2@YAPAXI@Z
      [-]00008bf85985ff7436
         // 00401b15: mov edi, eax
         // 00401b17: pop ecx
         // 00401b18: test edi, edi
         // 00401b1a: jz 0x401b52
      [-]8b45088b008b4818c745fc????????85c97503
         // 00401a01: mov eax, ss:[ebp+0x8]
         // 00401a04: mov eax, ds:[eax]
         // 00401a06: mov ecx, ds:[eax+0x18]
         // 00401a09: mov ss:[ebp+0xfffffffffffffffc], 0x1
         // 00401a10: test ecx, ecx
         // 00401a12: jnz 0x401a17
      [-]518d75d8e800feffff83670400c707
         // 00401b32: push ecx
         // 00401b33: lea esi, ss:[ebp+0xffffffffffffffd8]
         // 00401b36: call 0x40193b
         // 00401b3b: and ds:[edi+0x4], 0x0
         // 00401b3f: mov ds:[edi], ??_7?$codecvt@_WDH@std@@6B@
      [-]000089470889570ceb02
         // 00401b4a: mov ds:[edi+0x8], eax
         // 00401b4d: mov ds:[edi+0xc], edx
         // 00401b50: jmp 0x401b54
      [-]f645fc01893b7408
         // 00401a39: test b1 ss:[ebp+0xfffffffffffffffc], b1 0x1
         // 00401a3d: mov ds:[ebx], edi
         // 00401a3f: jz 0x401a49
      [-]8d75d8e83ffeffff
         // 00401a41: lea esi, ss:[ebp+0xffffffffffffffd8]
         // 00401a44: call 0x401888
      [-]6a0258c9c3
         // 00401a4b: push 0x2
         // 00401a4d: pop eax
         // 00401a4e: leave 
         // 00401a4f: retn 
      [-]558bec518b450c538b5d10568b751489068b4518578b7d20894dfc33c989078b063bc30f95c1894d143bc37463
         // 00401a50: push ebp
         // 00401a51: mov ebp, esp
         // 00401a53: push ecx
         // 00401a54: mov eax, ss:[ebp+0xc]
         // 00401a57: push ebx
         // 00401a58: mov ebx, ss:[ebp+0x10]
         // 00401a5b: push esi
         // 00401a5c: mov esi, ss:[ebp+0x14]
         // 00401a5f: mov ds:[esi], eax
         // 00401a61: mov eax, ss:[ebp+0x18]
         // 00401a64: push edi
         // 00401a65: mov edi, ss:[ebp+0x20]
         // 00401a68: mov ss:[ebp+0xfffffffffffffffc], ecx
         // 00401a6b: xor ecx, ecx
         // 00401a6d: mov ds:[edi], eax
         // 00401a6f: mov eax, ds:[esi]
         // 00401a71: cmp eax, ebx
         // 00401a73: setnz b1 cl
         // 00401a76: mov ss:[ebp+0x14], ecx
         // 00401a79: cmp eax, ebx
         // 00401a7b: jz 0x401ae0
      [-]8b0f3b4d1c745c
         // 00401a7d: mov ecx, ds:[edi]
         // 00401a7f: cmp ecx, ss:[ebp+0x1c]
         // 00401a82: jz 0x401ae0
      [-]8b55fc8b0683c20852ff75088bd32bd0525051e8
         // 00401b9f: mov edx, ss:[ebp+0xfffffffffffffffc]
         // 00401ba2: mov eax, ds:[esi]
         // 00401ba4: add edx, 0x8
         // 00401ba7: push edx
         // 00401ba8: push ss:[ebp+0x8]
         // 00401bab: mov edx, ebx
         // 00401bad: sub edx, eax
         // 00401baf: push edx
         // 00401bb0: push eax
         // 00401bb1: push ecx
         // 00401bb2: call __Mbrtowc
      [-]000083c41483f8fe743a
         // 00401bb7: add esp, 0x14
         // 00401bba: cmp eax, 0xfffffffffffffffe
         // 00401bbd: jz 0x401bf9
      [-]83f8ff7430
         // 00401aa4: cmp eax, 0xffffffffffffffff
         // 00401aa7: jz 0x401ad9
      [-]85c07516
         // 00401aa9: test eax, eax
         // 00401aab: jnz 0x401ac3
      [-]8b0f6639017516
         // 00401aad: mov ecx, ds:[edi]
         // 00401aaf: cmp b2 ds:[ecx], b2 ax
         // 00401ab2: jnz 0x401aca
      [-]8b068d5001
         // 00401ab4: mov eax, ds:[esi]
         // 00401ab6: lea edx, ds:[eax+0x1]
      [-]8a084084c975f9
         // 00401ab9: mov b1 cl, b1 ds:[eax]
         // 00401abb: inc eax
         // 00401abc: test b1 cl, b1 cl
         // 00401abe: jnz 0x401ab9
      [-]83f8fd7502
         // 00401ac3: cmp eax, 0xfffffffffffffffd
         // 00401ac6: jnz 0x401aca
      [-]010683070283651400391e75a6
         // 00401aca: add ds:[esi], eax
         // 00401acc: add ds:[edi], 0x2
         // 00401acf: and ss:[ebp+0x14], 0x0
         // 00401ad3: cmp ds:[esi], ebx
         // 00401ad5: jnz 0x401a7d
      [-]6a0258eb05
         // 00401ad9: push 0x2
         // 00401adb: pop eax
         // 00401adc: jmp 0x401ae3
      [-]5f5e5bc9c21c00
         // 00401ae3: pop edi
         // 00401ae4: pop esi
         // 00401ae5: pop ebx
         // 00401ae6: leave 
         // 00401ae7: retn b2 0x1c
      [-]558bec83ec1ca1d455420033c58945fc8b450c538b5d08568b751489068b4518578b7d20894de833c989078b063b4510895de40f95c1894dec3b45100f84a7000000
         // 00401aea: push ebp
         // 00401aeb: mov ebp, esp
         // 00401aed: sub esp, 0x1c
         // 00401af0: mov eax, ds:[___security_cookie]
         // 00401af5: xor eax, ebp
         // 00401af7: mov ss:[ebp+0xfffffffffffffffc], eax
         // 00401afa: mov eax, ss:[ebp+0xc]
         // 00401afd: push ebx
         // 00401afe: mov ebx, ss:[ebp+0x8]
         // 00401b01: push esi
         // 00401b02: mov esi, ss:[ebp+0x14]
         // 00401b05: mov ds:[esi], eax
         // 00401b07: mov eax, ss:[ebp+0x18]
         // 00401b0a: push edi
         // 00401b0b: mov edi, ss:[ebp+0x20]
         // 00401b0e: mov ss:[ebp+0xffffffffffffffe8], ecx
         // 00401b11: xor ecx, ecx
         // 00401b13: mov ds:[edi], eax
         // 00401b15: mov eax, ds:[esi]
         // 00401b17: cmp eax, ss:[ebp+0x10]
         // 00401b1a: mov ss:[ebp+0xffffffffffffffe4], ebx
         // 00401b1d: setnz b1 cl
         // 00401b20: mov ss:[ebp+0xffffffffffffffec], ecx
         // 00401b23: cmp eax, ss:[ebp+0x10]
         // 00401b26: jz 0x401bd3
      [-]8b451c39070f849c000000
         // 00401b2c: mov eax, ss:[ebp+0x1c]
         // 00401b2f: cmp ds:[edi], eax
         // 00401b31: jz 0x401bd3
      [-]8b078945f0e8
         // 00401c52: mov eax, ds:[edi]
         // 00401c54: mov ss:[ebp+0xfffffffffffffff0], eax
         // 00401c57: call ____mb_cur_max_func
      [-]00008b4d1c2b4df03bc17f24
         // 00401c5c: mov ecx, ss:[ebp+0x1c]
         // 00401c5f: sub ecx, ss:[ebp+0xfffffffffffffff0]
         // 00401c62: cmp eax, ecx
         // 00401c64: jg 0x401c8a
      [-]8b45e883c008508b060fb7005350ff75f0e8
         // 00401c66: mov eax, ss:[ebp+0xffffffffffffffe8]
         // 00401c69: add eax, 0x8
         // 00401c6c: push eax
         // 00401c6d: mov eax, ds:[esi]
         // 00401c6f: movzx eax, b2 ds:[eax]
         // 00401c72: push ebx
         // 00401c73: push eax
         // 00401c74: push ss:[ebp+0xfffffffffffffff0]
         // 00401c77: call __Wcrtomb
      [-]000083c41085c0785e
         // 00401c7c: add esp, 0x10
         // 00401c7f: test eax, eax
         // 00401c81: js 0x401ce1
      [-]8306020107eb46
         // 00401b68: add ds:[esi], 0x2
         // 00401b6b: add ds:[edi], eax
         // 00401b6d: jmp 0x401bb5
      [-]8b038945f08b45e883c008508b060fb70053508d45f450e8
         // 00401c8a: mov eax, ds:[ebx]
         // 00401c8c: mov ss:[ebp+0xfffffffffffffff0], eax
         // 00401c8f: mov eax, ss:[ebp+0xffffffffffffffe8]
         // 00401c92: add eax, 0x8
         // 00401c95: push eax
         // 00401c96: mov eax, ds:[esi]
         // 00401c98: movzx eax, b2 ds:[eax]
         // 00401c9b: push ebx
         // 00401c9c: push eax
         // 00401c9d: lea eax, ss:[ebp+0xfffffffffffffff4]
         // 00401ca0: push eax
         // 00401ca1: call __Wcrtomb
      [-]00008bd883c41085db7832
         // 00401ca6: mov ebx, eax
         // 00401ca8: add esp, 0x10
         // 00401cab: test ebx, ebx
         // 00401cad: js 0x401ce1
      [-]8b078b4d1c2bc83bcb7c2c
         // 00401b94: mov eax, ds:[edi]
         // 00401b96: mov ecx, ss:[ebp+0x1c]
         // 00401b99: sub ecx, eax
         // 00401b9b: cmp ecx, ebx
         // 00401b9d: jl 0x401bcb
      [-]538d4df45150e8
         // 00401cba: push ebx
         // 00401cbb: lea ecx, ss:[ebp+0xfffffffffffffff4]
         // 00401cbe: push ecx
         // 00401cbf: push eax
         // 00401cc0: call _memcpy_0
      [-]000083060283c40c011f8b5de4
         // 00401cc5: add ds:[esi], 0x2
         // 00401cc8: add esp, 0xc
         // 00401ccb: add ds:[edi], ebx
         // 00401ccd: mov ebx, ss:[ebp+0xffffffffffffffe4]
      [-]8b45108365ec0039060f8568ffffff
         // 00401bb5: mov eax, ss:[ebp+0x10]
         // 00401bb8: and ss:[ebp+0xffffffffffffffec], 0x0
         // 00401bbc: cmp ds:[esi], eax
         // 00401bbe: jnz 0x401b2c
      [-]6a0258eb0b
         // 00401bc6: push 0x2
         // 00401bc8: pop eax
         // 00401bc9: jmp 0x401bd6
      [-]8b45f08b4de48901
         // 00401bcb: mov eax, ss:[ebp+0xfffffffffffffff0]
         // 00401bce: mov ecx, ss:[ebp+0xffffffffffffffe4]
         // 00401bd1: mov ds:[ecx], eax
      [-]8b4dfc5f5e33cd5be8
         // 00401cf1: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 00401cf4: pop edi
         // 00401cf5: pop esi
         // 00401cf6: xor ecx, ebp
         // 00401cf8: pop ebx
         // 00401cf9: call @__security_check_cookie@4
      [-]0000c9c21c00
         // 00401cfe: leave 
         // 00401cff: retn b2 0x1c
      [-]558bec83ec14a1d455420033c58945fc8365f00053568b75148bc18b4d0c578b7d0883c0085057890e8b0f8d45f46a0050894dece8
         // 00401d02: push ebp
         // 00401d03: mov ebp, esp
         // 00401d05: sub esp, 0x14
         // 00401d08: mov eax, ds:[___security_cookie]
         // 00401d0d: xor eax, ebp
         // 00401d0f: mov ss:[ebp+0xfffffffffffffffc], eax
         // 00401d12: and ss:[ebp+0xfffffffffffffff0], 0x0
         // 00401d16: push ebx
         // 00401d17: push esi
         // 00401d18: mov esi, ss:[ebp+0x14]
         // 00401d1b: mov eax, ecx
         // 00401d1d: mov ecx, ss:[ebp+0xc]
         // 00401d20: push edi
         // 00401d21: mov edi, ss:[ebp+0x8]
         // 00401d24: add eax, 0x8
         // 00401d27: push eax
         // 00401d28: push edi
         // 00401d29: mov ds:[esi], ecx
         // 00401d2b: mov ecx, ds:[edi]
         // 00401d2d: lea eax, ss:[ebp+0xfffffffffffffff4]
         // 00401d30: push 0x0
         // 00401d32: push eax
         // 00401d33: mov ss:[ebp+0xffffffffffffffec], ecx
         // 00401d36: call __Wcrtomb
      [-]00008bd883c41085db7f09
         // 00401d3b: mov ebx, eax
         // 00401d3d: add esp, 0x10
         // 00401d40: test ebx, ebx
         // 00401d42: jg 0x401d4d
      [-]c745f0????????eb2e
         // 00401c29: mov ss:[ebp+0xfffffffffffffff0], 0x2
         // 00401c30: jmp 0x401c60
      [-]8b068b4d104b2bc83bcb7d0e
         // 00401c32: mov eax, ds:[esi]
         // 00401c34: mov ecx, ss:[ebp+0x10]
         // 00401c37: dec ebx
         // 00401c38: sub ecx, eax
         // 00401c3a: cmp ecx, ebx
         // 00401c3c: jge 0x401c4c
      [-]8b45ec8907c745f0????????eb14
         // 00401c3e: mov eax, ss:[ebp+0xffffffffffffffec]
         // 00401c41: mov ds:[edi], eax
         // 00401c43: mov ss:[ebp+0xfffffffffffffff0], 0x1
         // 00401c4a: jmp 0x401c60
      [-]85db7e10
         // 00401c4c: test ebx, ebx
         // 00401c4e: jle 0x401c60
      [-]538d4df45150e8
         // 00401d6b: push ebx
         // 00401d6c: lea ecx, ss:[ebp+0xfffffffffffffff4]
         // 00401d6f: push ecx
         // 00401d70: push eax
         // 00401d71: call _memcpy_0
      [-]000083c40c011e
         // 00401d76: add esp, 0xc
         // 00401d79: add ds:[esi], ebx
      [-]8b4dfc8b45f05f5e33cd5be8
         // 00401d7b: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 00401d7e: mov eax, ss:[ebp+0xfffffffffffffff0]
         // 00401d81: pop edi
         // 00401d82: pop esi
         // 00401d83: xor ecx, ebp
         // 00401d85: pop ebx
         // 00401d86: call @__security_check_cookie@4
      [-]0000c9c21000
         // 00401d8b: leave 
         // 00401d8c: retn b2 0x10
      [-]558bec518b45088b0053568b750c33db578bf98945fc395d147652
         // 00401c74: push ebp
         // 00401c75: mov ebp, esp
         // 00401c77: push ecx
         // 00401c78: mov eax, ss:[ebp+0x8]
         // 00401c7b: mov eax, ds:[eax]
         // 00401c7d: push ebx
         // 00401c7e: push esi
         // 00401c7f: mov esi, ss:[ebp+0xc]
         // 00401c82: xor ebx, ebx
         // 00401c84: push edi
         // 00401c85: mov edi, ecx
         // 00401c87: mov ss:[ebp+0xfffffffffffffffc], eax
         // 00401c8a: cmp ss:[ebp+0x14], ebx
         // 00401c8d: jbe 0x401ce1
      [-]3b7510744d
         // 00401c8f: cmp esi, ss:[ebp+0x10]
         // 00401c92: jz 0x401ce1
      [-]8d4708508d45fc508b45102bc6508d45085650e8
         // 00401daf: lea eax, ds:[edi+0x8]
         // 00401db2: push eax
         // 00401db3: lea eax, ss:[ebp+0xfffffffffffffffc]
         // 00401db6: push eax
         // 00401db7: mov eax, ss:[ebp+0x10]
         // 00401dba: sub eax, esi
         // 00401dbc: push eax
         // 00401dbd: lea eax, ss:[ebp+0x8]
         // 00401dc0: push esi
         // 00401dc1: push eax
         // 00401dc2: call __Mbrtowc
      [-]000083c41483f8fe742d
         // 00401dc7: add esp, 0x14
         // 00401dca: cmp eax, 0xfffffffffffffffe
         // 00401dcd: jz 0x401dfc
      [-]83f8ff7428
         // 00401cb4: cmp eax, 0xffffffffffffffff
         // 00401cb7: jz 0x401ce1
      [-]85c07515
         // 00401cb9: test eax, eax
         // 00401cbb: jnz 0x401cd2
      [-]663945087516
         // 00401cbd: cmp b2 ss:[ebp+0x8], b2 ax
         // 00401cc1: jnz 0x401cd9
      [-]8bc68d5001
         // 00401cc3: mov eax, esi
         // 00401cc5: lea edx, ds:[eax+0x1]
      [-]8a084084c975f9
         // 00401cc8: mov b1 cl, b1 ds:[eax]
         // 00401cca: inc eax
         // 00401ccb: test b1 cl, b1 cl
         // 00401ccd: jnz 0x401cc8
      [-]83f8fd7502
         // 00401cd2: cmp eax, 0xfffffffffffffffd
         // 00401cd5: jnz 0x401cd9
      [-]03f0433b5d1472ae
         // 00401cd9: add esi, eax
         // 00401cdb: inc ebx
         // 00401cdc: cmp ebx, ss:[ebp+0x14]
         // 00401cdf: jb 0x401c8f
      [-]5f5e8bc35bc9c21000
         // 00401ce1: pop edi
         // 00401ce2: pop esi
         // 00401ce3: mov eax, ebx
         // 00401ce5: pop ebx
         // 00401ce6: leave 
         // 00401ce7: retn b2 0x10
      [-]6a0558c3
         // 00401ced: push 0x5
         // 00401cef: pop eax
         // 00401cf0: retn 
      [-]558becf6450801568bf1c706
         // 00401cf1: push ebp
         // 00401cf2: mov ebp, esp
         // 00401cf4: test b1 ss:[ebp+0x8], b1 0x1
         // 00401cf8: push esi
         // 00401cf9: mov esi, ecx
         // 00401cfb: mov ds:[esi], ??_7facet@locale@std@@6B@
      [-]41007407
         // 00401d01: jz 0x401d0a
      [-]8bc65e5dc20400
         // 00401d0a: mov eax, esi
         // 00401d0c: pop esi
         // 00401d0d: pop ebp
         // 00401d0e: retn b2 0x4
      [-]558bec83ec38568b75085733ff897dfc3bf77471
         // 00401d11: push ebp
         // 00401d12: mov ebp, esp
         // 00401d14: sub esp, 0x38
         // 00401d17: push esi
         // 00401d18: mov esi, ss:[ebp+0x8]
         // 00401d1b: push edi
         // 00401d1c: xor edi, edi
         // 00401d1e: mov ss:[ebp+0xfffffffffffffffc], edi
         // 00401d21: cmp esi, edi
         // 00401d23: jz 0x401d96
      [-]393e756d
         // 00401d25: cmp ds:[esi], edi
         // 00401d27: jnz 0x401d96
      [-]536a20e8
         // 00401e44: push ebx
         // 00401e45: push 0x20
         // 00401e47: call ??2@YAPAXI@Z
      [-]00008bd8593bdf744b
         // 00401e4c: mov ebx, eax
         // 00401e4e: pop ecx
         // 00401e4f: cmp ebx, edi
         // 00401e51: jz 0x401e9e
      [-]8b450c8b008b4818c745fc????????3bcf7503
         // 00401d38: mov eax, ss:[ebp+0xc]
         // 00401d3b: mov eax, ds:[eax]
         // 00401d3d: mov ecx, ds:[eax+0x18]
         // 00401d40: mov ss:[ebp+0xfffffffffffffffc], 0x1
         // 00401d47: cmp ecx, edi
         // 00401d49: jnz 0x401d4e
      [-]518d75c8e8c9faffff8d45ec50897b04c703
         // 00401d4e: push ecx
         // 00401d4f: lea esi, ss:[ebp+0xffffffffffffffc8]
         // 00401d52: call 0x401820
         // 00401d57: lea eax, ss:[ebp+0xffffffffffffffec]
         // 00401d5a: push eax
         // 00401d5b: mov ds:[ebx+0x4], edi
         // 00401d5e: mov ds:[ebx], ??_7?$ctype@_W@std@@6B@
      [-]00008bf08d7b08a5a5a559a5e8
         // 00401d69: mov esi, eax
         // 00401d6b: lea edi, ds:[ebx+0x8]
         // 00401d6e: movsdd 
         // 00401d6f: movsdd 
         // 00401d70: movsdd 
         // 00401d71: pop ecx
         // 00401d72: movsdd 
         // 00401d73: call __Getcvt
      [-]00008b750889431889531ceb02
         // 00401d78: mov esi, ss:[ebp+0x8]
         // 00401d7b: mov ds:[ebx+0x18], eax
         // 00401d7e: mov ds:[ebx+0x1c], edx
         // 00401d81: jmp 0x401d85
      [-]f645fc01891e5b7408
         // 00401d85: test b1 ss:[ebp+0xfffffffffffffffc], b1 0x1
         // 00401d89: mov ds:[esi], ebx
         // 00401d8b: pop ebx
         // 00401d8c: jz 0x401d96
      [-]8d75c8e8f2faffff
         // 00401d8e: lea esi, ss:[ebp+0xffffffffffffffc8]
         // 00401d91: call 0x401888
      [-]6a02585f5ec9c3
         // 00401d96: push 0x2
         // 00401d98: pop eax
         // 00401d99: pop edi
         // 00401d9a: pop esi
         // 00401d9b: leave 
         // 00401d9c: retn 
      [-]568bf1837e1400c706
         // 00401eb8: push esi
         // 00401eb9: mov esi, ecx
         // 00401ebb: cmp ds:[esi+0x14], 0x0
         // 00401ebf: mov ds:[esi], ??_7?$ctype@_W@std@@6B@
      [-]42007409
         // 00401ec5: jz 0x401ed0
      [-]ff7610e8
         // 00401ec7: push ds:[esi+0x10]
         // 00401eca: call _free
      [-]41005ec3
         // 00401dbb: pop esi
         // 00401dbc: retn 
      [-]558bec83c10851ff750ce8
         // 00401ed8: push ebp
         // 00401ed9: mov ebp, esp
         // 00401edb: add ecx, 0x8
         // 00401ede: push ecx
         // 00401edf: push ss:[ebp+0xc]
         // 00401ee2: call __Getwctype
      [-]00006685450859596a00580f95c05dc20800
         // 00401ee7: test b2 ss:[ebp+0x8], b2 ax
         // 00401eeb: pop ecx
         // 00401eec: pop ecx
         // 00401eed: push 0x0
         // 00401eef: pop eax
         // 00401ef0: setnz b1 al
         // 00401ef3: pop ebp
         // 00401ef4: retn b2 0x8
      [-]558bec83c10851ff7510ff750cff7508e8
         // 00401ddc: push ebp
         // 00401ddd: mov ebp, esp
         // 00401ddf: add ecx, 0x8
         // 00401de2: push ecx
         // 00401de3: push ss:[ebp+0x10]
         // 00401de6: push ss:[ebp+0xc]
         // 00401de9: push ss:[ebp+0x8]
         // 00401dec: call __Getwctypes
      [-]000083c4105dc20c00
         // 00401df1: add esp, 0x10
         // 00401df4: pop ebp
         // 00401df5: retn b2 0xc
      [-]558bec568b750c578bf9eb15
         // 00401df8: push ebp
         // 00401df9: mov ebp, esp
         // 00401dfb: push esi
         // 00401dfc: mov esi, ss:[ebp+0xc]
         // 00401dff: push edi
         // 00401e00: mov edi, ecx
         // 00401e02: jmp 0x401e19
      [-]0fb7068b1750ff75088bcfff520884c07508
         // 00401e04: movzx eax, b2 ds:[esi]
         // 00401e07: mov edx, ds:[edi]
         // 00401e09: push eax
         // 00401e0a: push ss:[ebp+0x8]
         // 00401e0d: mov ecx, edi
         // 00401e0f: call ds:[edx+0x8]
         // 00401e12: test b1 al, b1 al
         // 00401e14: jnz 0x401e1e
      [-]3b751075e6
         // 00401e19: cmp esi, ss:[ebp+0x10]
         // 00401e1c: jnz 0x401e04
      [-]5f8bc65e5dc20c00
         // 00401e1e: pop edi
         // 00401e1f: mov eax, esi
         // 00401e21: pop esi
         // 00401e22: pop ebp
         // 00401e23: retn b2 0xc
      [-]558bec568b750c578bf9eb15
         // 00401e26: push ebp
         // 00401e27: mov ebp, esp
         // 00401e29: push esi
         // 00401e2a: mov esi, ss:[ebp+0xc]
         // 00401e2d: push edi
         // 00401e2e: mov edi, ecx
         // 00401e30: jmp 0x401e47
      [-]0fb7068b1750ff75088bcfff520884c07408
         // 00401e32: movzx eax, b2 ds:[esi]
         // 00401e35: mov edx, ds:[edi]
         // 00401e37: push eax
         // 00401e38: push ss:[ebp+0x8]
         // 00401e3b: mov ecx, edi
         // 00401e3d: call ds:[edx+0x8]
         // 00401e40: test b1 al, b1 al
         // 00401e42: jz 0x401e4c
      [-]3b751075e6
         // 00401e47: cmp esi, ss:[ebp+0x10]
         // 00401e4a: jnz 0x401e32
      [-]5f8bc65e5dc20c00
         // 00401e4c: pop edi
         // 00401e4d: mov eax, esi
         // 00401e4f: pop esi
         // 00401e50: pop ebp
         // 00401e51: retn b2 0xc
      [-]558bec83c10851ff7508e8
         // 00401f6f: push ebp
         // 00401f70: mov ebp, esp
         // 00401f72: add ecx, 0x8
         // 00401f75: push ecx
         // 00401f76: push ss:[ebp+0x8]
         // 00401f79: call __Towlower
      [-]000059595dc20400
         // 00401f7e: pop ecx
         // 00401f7f: pop ecx
         // 00401f80: pop ebp
         // 00401f81: retn b2 0x4
      [-]558bec83c10851ff7508e8
         // 00401fb3: push ebp
         // 00401fb4: mov ebp, esp
         // 00401fb6: add ecx, 0x8
         // 00401fb9: push ecx
         // 00401fba: push ss:[ebp+0x8]
         // 00401fbd: call __Towupper
      [-]000059595dc20400
         // 00401fc2: pop ecx
         // 00401fc3: pop ecx
         // 00401fc4: pop ebp
         // 00401fc5: retn b2 0x4
      [-]558bec51518365f80083c018508d45f8506a018d4508508d45fc50e8
         // 00401efb: push ebp
         // 00401efc: mov ebp, esp
         // 00401efe: push ecx
         // 00401eff: push ecx
         // 00401f00: and ss:[ebp+0xfffffffffffffff8], 0x0
         // 00401f04: add eax, 0x18
         // 00401f07: push eax
         // 00401f08: lea eax, ss:[ebp+0xfffffffffffffff8]
         // 00401f0b: push eax
         // 00401f0c: push 0x1
         // 00401f0e: lea eax, ss:[ebp+0x8]
         // 00401f11: push eax
         // 00401f12: lea eax, ss:[ebp+0xfffffffffffffffc]
         // 00401f15: push eax
         // 00401f16: call __Mbrtowc
      [-]000083c41485c0b8????????7804
         // 00401f1b: add esp, 0x14
         // 00401f1e: test eax, eax
         // 00401f20: mov eax, 0xffff
         // 00401f25: js 0x401f2b
      [-]0fb745fc
         // 00401f08: movzx eax, b2 ss:[ebp+0xfffffffffffffffc]
      [-]c9c20400
         // 00401f0c: leave 
         // 00401f0d: retn b2 0x4
      [-]558bec8bc15de9c1ffffff
         // 00401f10: push ebp
         // 00401f11: mov ebp, esp
         // 00401f13: mov eax, ecx
         // 00401f15: pop ebp
         // 00401f16: jmp 0x401edc
      [-]558bec53568b75088bd93b750c741c
         // 00401f1b: push ebp
         // 00401f1c: mov ebp, esp
         // 00401f1e: push ebx
         // 00401f1f: push esi
         // 00401f20: mov esi, ss:[ebp+0x8]
         // 00401f23: mov ebx, ecx
         // 00401f25: cmp esi, ss:[ebp+0xc]
         // 00401f28: jz 0x401f46
      [-]578b7d10
         // 00401f2a: push edi
         // 00401f2b: mov edi, ss:[ebp+0x10]
      [-]0fb606508bc3e8a3ffffff6689074683c7023b750c75e9
         // 00401f2e: movzx eax, b1 ds:[esi]
         // 00401f31: push eax
         // 00401f32: mov eax, ebx
         // 00401f34: call 0x401edc
         // 00401f39: mov b2 ds:[edi], b2 ax
         // 00401f3c: inc esi
         // 00401f3d: add edi, 0x2
         // 00401f40: cmp esi, ss:[ebp+0xc]
         // 00401f43: jnz 0x401f2e
      [-]8bc65e5b5dc20c00
         // 00401f46: mov eax, esi
         // 00401f48: pop esi
         // 00401f49: pop ebx
         // 00401f4a: pop ebp
         // 00401f4b: retn b2 0xc
      [-]558bec83ec10a1d455420033c58945fc8b45088365f00083c018508d45f050ff750c8d45f450e8
         // 00401f4e: push ebp
         // 00401f4f: mov ebp, esp
         // 00401f51: sub esp, 0x10
         // 00401f54: mov eax, ds:[___security_cookie]
         // 00401f59: xor eax, ebp
         // 00401f5b: mov ss:[ebp+0xfffffffffffffffc], eax
         // 00401f5e: mov eax, ss:[ebp+0x8]
         // 00401f61: and ss:[ebp+0xfffffffffffffff0], 0x0
         // 00401f65: add eax, 0x18
         // 00401f68: push eax
         // 00401f69: lea eax, ss:[ebp+0xfffffffffffffff0]
         // 00401f6c: push eax
         // 00401f6d: push ss:[ebp+0xc]
         // 00401f70: lea eax, ss:[ebp+0xfffffffffffffff4]
         // 00401f73: push eax
         // 00401f74: call __Wcrtomb
      [-]000083c41083f8018a45107503
         // 00401f79: add esp, 0x10
         // 00401f7c: cmp eax, 0x1
         // 00401f7f: mov b1 al, b1 ss:[ebp+0x10]
         // 00401f82: jnz 0x401f87
      [-]8b4dfc33cde8
         // 004020a2: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 004020a5: xor ecx, ebp
         // 004020a7: call @__security_check_cookie@4
      [-]0000c9c20c00
         // 004020ac: leave 
         // 004020ad: retn b2 0xc
      [-]558becff750cff750851e8aaffffff5dc20800
         // 00401f95: push ebp
         // 00401f96: mov ebp, esp
         // 00401f98: push ss:[ebp+0xc]
         // 00401f9b: push ss:[ebp+0x8]
         // 00401f9e: push ecx
         // 00401f9f: call 0x401f4e
         // 00401fa4: pop ebp
         // 00401fa5: retn b2 0x8
      [-]558bec53568b75088bd93b750c741d
         // 00401fa8: push ebp
         // 00401fa9: mov ebp, esp
         // 00401fab: push ebx
         // 00401fac: push esi
         // 00401fad: mov esi, ss:[ebp+0x8]
         // 00401fb0: mov ebx, ecx
         // 00401fb2: cmp esi, ss:[ebp+0xc]
         // 00401fb5: jz 0x401fd4
      [-]578b7d14
         // 00401fb7: push edi
         // 00401fb8: mov edi, ss:[ebp+0x14]
      [-]ff75100fb7065053e886ffffff83c6028807473b750c75e8
         // 00401fbb: push ss:[ebp+0x10]
         // 00401fbe: movzx eax, b2 ds:[esi]
         // 00401fc1: push eax
         // 00401fc2: push ebx
         // 00401fc3: call 0x401f4e
         // 00401fc8: add esi, 0x2
         // 00401fcb: mov b1 ds:[edi], b1 al
         // 00401fcd: inc edi
         // 00401fce: cmp esi, ss:[ebp+0xc]
         // 00401fd1: jnz 0x401fbb
      [-]8bc65e5b5dc21000
         // 00401fd4: mov eax, esi
         // 00401fd6: pop esi
         // 00401fd7: pop ebx
         // 00401fd8: pop ebp
         // 00401fd9: retn b2 0x10
      [-]558bec568bf1e8b6fdfffff64508017407
         // 00401fdc: push ebp
         // 00401fdd: mov ebp, esp
         // 00401fdf: push esi
         // 00401fe0: mov esi, ecx
         // 00401fe2: call 0x401d9d
         // 00401fe7: test b1 ss:[ebp+0x8], b1 0x1
         // 00401feb: jz 0x401ff4
      [-]8bc65e5dc20400
         // 00401ff4: mov eax, esi
         // 00401ff6: pop esi
         // 00401ff7: pop ebp
         // 00401ff8: retn b2 0x4
      [-]558bec568bf1e8
         // 0040218e: push ebp
         // 0040218f: mov ebp, esp
         // 00402191: push esi
         // 00402192: mov esi, ecx
         // 00402194: call 0x40bceb
      [-]0000f64508017407
         // 00402199: test b1 ss:[ebp+0x8], b1 0x1
         // 0040219d: jz 0x4021a6
      [-]8bc65e5dc20400
         // 0040208b: mov eax, esi
         // 0040208d: pop esi
         // 0040208e: pop ebp
         // 0040208f: retn b2 0x4
      [-]558bec56ff75088bf1e80d000000c706
         // 004021b2: push ebp
         // 004021b3: mov ebp, esp
         // 004021b5: push esi
         // 004021b6: push ss:[ebp+0x8]
         // 004021b9: mov esi, ecx
         // 004021bb: call 0x4021cd
         // 004021c0: mov ds:[esi], ??_7failure@ios_base@std@@6B@
      [-]42008bc65e5dc20400
         // 004021c6: mov eax, esi
         // 004021c8: pop esi
         // 004021c9: pop ebp
         // 004021ca: retn b2 0x4
      [-]558bec56578b7d08578bf1e8
         // 004020b2: push ebp
         // 004020b3: mov ebp, esp
         // 004020b5: push esi
         // 004020b6: push edi
         // 004020b7: mov edi, ss:[ebp+0x8]
         // 004020ba: push edi
         // 004020bb: mov esi, ecx
         // 004020bd: call ??0exception@std@@QAE@ABV01@@Z
      [-]0000c706
         // 004020c2: mov ds:[esi], ??_7system_error@std@@6B@
      [-]42008b470c89460c8b47108946105f8bc65e5dc20400
         // 004020c8: mov eax, ds:[edi+0xc]
         // 004020cb: mov ds:[esi+0xc], eax
         // 004020ce: mov eax, ds:[edi+0x10]
         // 004020d1: mov ds:[esi+0x10], eax
         // 004020d4: pop edi
         // 004020d5: mov eax, esi
         // 004020d7: pop esi
         // 004020d8: pop ebp
         // 004020d9: retn b2 0x4
      [-]a1d455420033c58945fc53
         // 004025ab: mov eax, ds:[___security_cookie]
         // 004025b0: xor eax, ebp
         // 004025b2: mov ss:[ebp+0xfffffffffffffffc], eax
         // 004025b5: push ebx
      [-]33cd5be8
         // 004026d5: xor ecx, ebp
         // 004026d7: pop ebx
         // 004026d8: call @__security_check_cookie@4
      [-]558bec83e4f8b8
         // 00402780: push ebp
         // 00402781: mov ebp, esp
         // 00402783: and esp, 0xfffffffffffffff8
         // 00402786: mov eax, 0x812c
      [-]0100a1d455420033c4898424
         // 00402790: mov eax, ds:[___security_cookie]
         // 00402795: xor eax, esp
         // 00402797: mov ss:[esp+0x8128], eax
      [-]108b8c24
         // 00402826: mov ecx, ss:[esp+0x2d8]
      [-]8bc17307
         // 0040282d: mov eax, ecx
         // 0040282f: jnb 0x402838
      [-]50518d8424
         // 00402a3b: push eax
         // 00402a3c: push ecx
         // 00402a3d: lea eax, ss:[esp+0x2ac]
      [-]66899424
         // 00402a53: mov b2 ss:[esp+0x2b0], b2 dx
      [-]020000e8
         // 00402a5b: call 0x4067d0
      [-]ffff6a0568
         // 00402a7e: push 0x5
         // 00402a80: push 0x4267c8
      [-]ffff8bc88d5102
         // 00402a8a: mov ecx, eax
         // 00402a8c: lea edx, ds:[ecx+0x2]
      [-]668b3183c102
         // 00402a8f: mov b2 si, b2 ds:[ecx]
         // 00402a92: add ecx, 0x2
      [-]2bcad1f9515033c08d8c24
         // 00402a9a: sub ecx, edx
         // 00402a9c: sar ecx, b1 0x1
         // 00402a9e: push ecx
         // 00402a9f: push eax
         // 00402aa0: xor eax, eax
         // 00402aa2: lea ecx, ss:[esp+0x238]
      [-]68????????6a0368
         // 004028ee: push 0x40000
         // 004028f3: push 0x3
         // 004028f5: push 0x426690
      [-]ffff508db424
         // 00402920: push eax
         // 00402921: lea esi, ss:[esp+0x218]
      [-]ffff8bdee8
         // 0040292d: mov ebx, esi
         // 0040292f: call 0x402128
      [-]68????????e8
         // 00402a3d: push 0xd8
         // 00402a42: call ??2@YAPAXI@Z
      [-]088b8424
         // 00402c36: mov eax, ss:[esp+0x364]
      [-]506a1068
         // 00402a61: push eax
         // 00402a62: push 0x10
         // 00402a64: push 0x426818
      [-]ffff508d8424
         // 00402a6e: push eax
         // 00402a6f: lea eax, ss:[esp+0x3f8]
      [-]83c40c8d8424
         // 00402a79: add esp, 0xc
         // 00402a7c: lea eax, ss:[esp+0x3f0]
      [-]508db424
         // 00402a83: push eax
         // 00402a84: lea esi, ss:[esp+0x218]
      [-]ffff8bdee8
         // 00402a90: mov ebx, esi
         // 00402a92: call 0x402128
      [-]ffff803d
         // 00402aa2: cmp b1 ds:[0x4282ad], b1 0x0
      [-]088b8424
         // 00402ac6: mov eax, ss:[esp+0x1f8]
      [-]506a2068
         // 00402adb: push eax
         // 00402adc: push 0x20
         // 00402ade: push 0x426838
      [-]ffff508d8424
         // 00402ae8: push eax
         // 00402ae9: lea eax, ss:[esp+0x3f8]
      [-]83c40c8d8424
         // 00402af3: add esp, 0xc
         // 00402af6: lea eax, ss:[esp+0x3f0]
      [-]508db424
         // 00402afd: push eax
         // 00402afe: lea esi, ss:[esp+0x218]
      [-]ffff8bdee8
         // 00402b0a: mov ebx, esi
         // 00402b0c: call 0x402128
      [-]2bcad1f951
         // 00402b3d: sub ecx, edx
         // 00402b3f: sar ecx, b1 0x1
         // 00402b41: push ecx
      [-]33c08d8c24
         // 00402b43: xor eax, eax
         // 00402b45: lea ecx, ss:[esp+0x200]
      [-]ffff8bc88d5102
         // 00402b60: mov ecx, eax
         // 00402b62: lea edx, ds:[ecx+0x2]
      [-]2bcad1f9515033c08d8c24
         // 00402c6a: sub ecx, edx
         // 00402c6c: sar ecx, b1 0x1
         // 00402c6e: push ecx
         // 00402c6f: push eax
         // 00402c70: xor eax, eax
         // 00402c72: lea ecx, ss:[esp+0x200]
      [-]088b8424
         // 00402b81: mov eax, ss:[esp+0x27c]
      [-]506a1368
         // 00402e6d: push eax
         // 00402e6e: push 0x13
         // 00402e70: push 0x426878
      [-]ffff508d8424
         // 00402e7a: push eax
         // 00402e7b: lea eax, ss:[esp+0x3f0]
      [-]83c40c8d8424
         // 00402e85: add esp, 0xc
         // 00402e88: lea eax, ss:[esp+0x3e8]
      [-]508db424
         // 00402e8f: push eax
         // 00402e90: lea esi, ss:[esp+0x1d8]
      [-]ffff8bdee8
         // 00402e9c: mov ebx, esi
         // 00402e9e: call 0x402128
      [-]ffff5368
         // 00402ec0: push ebx
         // 00402ec1: push 0x421082
      [-]000083bc24
         // 00402eeb: cmp ss:[esp+0x290], 0x8
      [-]088b8424
         // 00402ef3: mov eax, ss:[esp+0x27c]
      [-]68????????6a03
         // 00402c2b: push 0x80
         // 00402c30: push 0x3
      [-]088b8424
         // 00402c53: mov eax, ss:[esp+0x27c]
      [-]506a1768
         // 00402f36: push eax
         // 00402f37: push 0x17
         // 00402f39: push 0x426994
      [-]ffff508d8424
         // 00402f43: push eax
         // 00402f44: lea eax, ss:[esp+0x3f0]
      [-]83c40c8d8424
         // 00402f4e: add esp, 0xc
         // 00402f51: lea eax, ss:[esp+0x3e8]
      [-]508db424
         // 00402f58: push eax
         // 00402f59: lea esi, ss:[esp+0x228]
      [-]ffff8bdee8
         // 00402f65: mov ebx, esi
         // 00402f67: call 0x402120
      [-]578d8c24
         // 00402f82: push edi
         // 00402f83: lea ecx, ss:[esp+0x210]
      [-]578d8c24
         // 00402d08: push edi
         // 00402d0a: lea ecx, ss:[esp+0x2d8]
      [-]8bf0ff15
         // 00402ec5: mov esi, eax
         // 00402ec7: call ds:[CloseHandle]
      [-]e041008d8424
         // 00402ecd: lea eax, ss:[esp+0x26c]
      [-]508d7c24
         // 00402ed4: push eax
         // 00402ed5: lea edi, ss:[esp+0x34]
      [-]1500008b4424
         // 00402ede: mov eax, ss:[esp+0x30]
      [-]8b4804395c0c
         // 00402ee2: mov ecx, ds:[eax+0x4]
         // 00402ee5: cmp ss:[esp+ecx+0x3c], ebx
      [-]8b4138f7d81bc083e0fc83c00483e01789410c8541107406
         // 00402d7d: mov eax, ds:[ecx+0x38]
         // 00402d80: neg eax
         // 00402d82: sbb eax, eax
         // 00402d84: and eax, 0xfffffffffffffffc
         // 00402d87: add eax, 0x4
         // 00402d8a: and eax, 0x17
         // 00402d8d: mov ds:[ecx+0xc], eax
         // 00402d90: test ds:[ecx+0x10], eax
         // 00402d93: jz 0x402d9b
      [-]83ec188bcc8d86????????9989590889590c8959108d5c24
         // 00403077: sub esp, 0x18
         // 0040307a: mov ecx, esp
         // 0040307c: lea eax, ds:[esi+0xffffffffffffc667]
         // 00403082: cdq 
         // 00403083: mov ds:[ecx+0x8], ebx
         // 00403086: mov ds:[ecx+0xc], ebx
         // 00403089: mov ds:[ecx+0x10], ebx
         // 0040308c: lea ebx, ss:[esp+0x50]
      [-]8901895104e8
         // 00403090: mov ds:[ecx], eax
         // 00403092: mov ds:[ecx+0x4], edx
         // 00403095: call 0x4041bc
      [-]1100008b4424
         // 0040309a: mov eax, ss:[esp+0x38]
      [-]8b400433
         // 0040309e: mov eax, ds:[eax+0x4]
         // 004030a1: xor ebx, ebx
      [-]8b106a016a01
         // 00402f48: mov edx, ds:[eax]
         // 00402f4a: push 0x1
         // 00402f4c: push 0x1
      [-]518bc8ff5228
         // 00402f57: push ecx
         // 00402f58: mov ecx, eax
         // 00402f5a: call ds:[edx+0x28]
      [-]508d4424
         // 00403104: push eax
         // 00403105: lea eax, ss:[esp+0x44]
      [-]000033c066898424
         // 0040310f: xor eax, eax
         // 00403111: mov b2 ss:[esp+0x214], b2 ax
      [-]0000b8????????8d8c24
         // 00403119: mov eax, 0x3999
         // 0040311e: lea ecx, ss:[esp+0xdf8]
      [-]5083c8ff8d
         // 0040314b: push eax
         // 0040314c: or eax, 0xffffffffffffffff
         // 0040314f: lea edi, ss:[esp+0x2a8]
      [-]2600008d4424
         // 0040315b: lea eax, ss:[esp+0x58]
      [-]000085c0752a
         // 00403164: test eax, eax
         // 00403166: jnz 0x403192
      [-]8b48048d4c0c
         // 00402fcc: mov ecx, ds:[eax+0x4]
         // 00402fcf: lea ecx, ss:[esp+ecx+0x30]
      [-]8b410c83c80239
         // 00402fd3: mov eax, ds:[ecx+0xc]
         // 00402fd6: or eax, 0x2
         // 00402fd9: cmp ds:[ecx+0x38], ebx
      [-]83e01789410c8541107406
         // 00402f73: and eax, 0x17
         // 00402f76: mov ds:[ecx+0xc], eax
         // 00402f79: test ds:[ecx+0x10], eax
         // 00402f7c: jz 0x402f84
      [-]33c066898424
         // 004031a0: xor eax, eax
         // 004031a2: mov b2 ss:[esp+0x2b8], b2 ax
      [-]0200008d
         // 004031aa: lea eax, ds:[edi+0x426e26]
      [-]5048508d8424
         // 004031b0: push eax
         // 004031b1: dec eax
         // 004031b2: push eax
         // 004031b3: lea eax, ss:[esp+0x2c0]
      [-]360000ff7424
         // 004031ce: push ss:[esp+0x2c]
      [-]33c066898424
         // 004031d2: xor eax, eax
         // 004031d4: mov b2 ss:[esp+0x22c], b2 ax
      [-]508d8424
         // 004031e9: push eax
         // 004031ea: lea eax, ss:[esp+0x234]
      [-]5083c8ff8d
         // 0040320d: push eax
         // 0040320e: or eax, 0xffffffffffffffff
         // 00403211: lea edi, ss:[esp+0x348]
      [-]5083c8ff8d
         // 00403225: push eax
         // 00403226: or eax, 0xffffffffffffffff
         // 00403229: lea edi, ss:[esp+0x2f4]
      [-]ffff834424
         // 00403253: add ss:[esp+0x10], 0x2
      [-]02ff4c24
         // 00403258: dec ss:[esp+0x20]
      [-]088b8424
         // 00402f86: mov eax, ss:[esp+0x324]
      [-]5033c0e8
         // 004030e7: push eax
         // 004030e8: xor eax, eax
         // 004030ea: call 0x4013b3
      [-]ffff83bc24
         // 004030ef: cmp ss:[esp+0x30c], 0x8
      [-]5033c0e8
         // 004031df: push eax
         // 004031e0: xor eax, eax
         // 004031e2: call 0x4013bf
      [-]ffff0f84
         // 004031e7: cmp edi, 0xffffffffffffffff
         // 004031ea: jz 0x4034a7
      [-]83f8ff0f84
         // 00402fe6: cmp eax, 0xffffffffffffffff
         // 00402fe9: jz 0x403295
      [-]508dbc24
         // 00403238: push eax
         // 00403239: lea edi, ss:[esp+0xfc]
      [-]000033c089
         // 00403245: xor eax, eax
         // 0040324e: mov ss:[esp+0x1c8], ebx
      [-]66898424
         // 00403255: mov b2 ss:[esp+0x1b8], b2 ax
      [-]010000e9
         // 0040325d: jmp 0x403432
      [-]66898424
         // 00403188: mov b2 ss:[esp+0x1e0], b2 ax
      [-]ffff33c0
         // 004031b2: xor eax, eax
      [-]6aff508d8424
         // 004031c1: push 0xffffffffffffffff
         // 004031c3: push eax
         // 004031c4: lea eax, ss:[esp+0x1c0]
      [-]33000085c075
         // 004031f6: test eax, eax
         // 004031f8: jnz 0x40320b
      [-]33000085c07516
         // 0040321c: test eax, eax
         // 0040321e: jnz 0x403236
      [-]11000033c066898424
         // 00403349: xor eax, eax
         // 0040334b: mov b2 ss:[esp+0x2f4], b2 ax
      [-]00008b8424
         // 00403353: mov eax, ss:[esp+0x1c8]
      [-]408d8c24
         // 0040335a: inc eax
         // 0040335b: lea ecx, ss:[esp+0x2f4]
      [-]5083c8ff8d
         // 00403393: push eax
         // 00403394: or eax, 0xffffffffffffffff
         // 00403397: lea edi, ss:[esp+0x2fc]
      [-]23000068
         // 004033a3: push 0x422954
      [-]5083c8ff8d
         // 004033c6: push eax
         // 004033c7: or eax, 0xffffffffffffffff
         // 004033ca: lea edi, ss:[esp+0x200]
      [-]ffff6a07
         // 00403411: push 0x7
      [-]000085c07507
         // 00403216: test eax, eax
         // 00403218: jnz 0x403221
      [-]00008b088b490403c88b410c24060fbec0f7d81bc0f7d085c1
         // 0040355a: mov ecx, ds:[eax]
         // 0040355c: mov ecx, ds:[ecx+0x4]
         // 0040355f: add ecx, eax
         // 00403561: mov eax, ds:[ecx+0xc]
         // 00403564: and b1 al, b1 0x6
         // 00403566: movsx eax, b1 al
         // 00403569: neg eax
         // 0040356b: sbb eax, eax
         // 0040356d: not eax
         // 0040356f: test ecx, eax
      [-]ffff8d8c24
         // 00403262: lea ecx, ss:[esp+0x148]
      [-]00008d8424
         // 0040326e: lea eax, ss:[esp+0x148]
      [-]50c78424
         // 00403275: push eax
         // 00403276: mov ss:[esp+0x14c], ??_7ios_base@std@@6B@
      [-]ffff8d8c24
         // 004035d9: lea ecx, ss:[esp+0xb0]
      [-]00008d8424
         // 004035e5: lea eax, ss:[esp+0xb0]
      [-]50c78424
         // 004035ec: push eax
         // 004035ed: mov ss:[esp+0xb4], ??_7ios_base@std@@6B@
      [-]00005953
         // 004035fd: pop ecx
         // 004035fe: push ebx
      [-]ffff508db424
         // 0040358d: push eax
         // 0040358e: lea esi, ss:[esp+0x1a0]
      [-]ffff8bce
         // 0040359a: mov ecx, esi
      [-]088b8424
         // 00403682: mov eax, ss:[esp+0x20c]
      [-]83c40c8d8424
         // 00403557: add esp, 0xc
         // 0040355a: lea eax, ss:[esp+0x3d8]
      [-]508db424
         // 00403561: push eax
         // 00403562: lea esi, ss:[esp+0x1a8]
      [-]ffff8bdee8
         // 0040356e: mov ebx, esi
         // 00403570: call 0x40228f
      [-]ffff508db424
         // 004036a4: push eax
         // 004036a5: lea esi, ss:[esp+0x198]
      [-]ffff8bcee9
         // 004036b1: mov ecx, esi
         // 004036b3: jmp 0x4035f3
      [-]6a1233c068
         // 00403495: push 0x12
         // 00403497: xor eax, eax
         // 00403499: push 0x426c2c
      [-]66898424
         // 004034b0: mov b2 ss:[esp+0x1dc], b2 ax
      [-]ffff508db424
         // 004034bd: push eax
         // 004034be: lea esi, ss:[esp+0x210]
      [-]ffff6a2068
         // 004034ca: push 0x20
         // 004034cc: push 0x426c50
      [-]ffff508db424
         // 004034d6: push eax
         // 004034d7: lea esi, ss:[esp+0x198]
      [-]ffff8bc6508d9424
         // 004034e3: mov eax, esi
         // 004034e5: push eax
         // 004034e6: lea edx, ss:[esp+0x1d8]
      [-]ffff508db424
         // 004036b0: push eax
         // 004036b1: lea esi, ss:[esp+0x1c4]
      [-]ffff83bc24
         // 004036bd: cmp ss:[esp+0x1d4], 0x8
      [-]088bb424
         // 004036c5: mov esi, ss:[esp+0x1c0]
      [-]8bfe0f8396000000
         // 004036cc: mov edi, esi
         // 004036ce: jnb 0x40376a
      [-]088b8c24
         // 0040355f: mov ecx, ss:[esp+0x1c0]
      [-]8d1c487307
         // 00403566: lea ebx, ds:[eax+ecx*0x2]
         // 00403569: jnb 0x403572
      [-]3bf37417
         // 0040368d: cmp esi, ebx
         // 0040368f: jz 0x4036a8
      [-]0fb70650e8
         // 0040378e: movzx eax, b2 ds:[esi]
         // 00403791: push eax
         // 00403792: call _tolower
      [-]0000668904
         // 00403797: mov b2 ds:[edi+esi], b2 ax
      [-]83c602593bf375eb
         // 0040379b: add esi, 0x2
         // 0040379e: pop ecx
         // 0040379f: cmp esi, ebx
         // 004037a1: jnz 0x40378e
      [-]088b8424
         // 00403595: mov eax, ss:[esp+0x1b0]
      [-]508b8424
         // 004036c7: push eax
         // 004036c8: mov eax, ss:[esp+0x1f0]
      [-]000085c07527
         // 004036db: test eax, eax
         // 004036dd: jnz 0x403706
      [-]ffff508db424
         // 00403731: push eax
         // 00403732: lea esi, ss:[esp+0x18c]
      [-]ffff8bcee9
         // 0040373e: mov ecx, esi
         // 00403740: jmp 0x4034e7
      [-]8bc6e96cffffff
         // 004036ff: mov eax, esi
         // 00403701: jmp 0x403672
      [-]ffff8d8424
         // 0040376e: lea eax, ss:[esp+0xbf0]
      [-]5068????????ff15
         // 00403775: push eax
         // 00403776: push 0x104
         // 0040377b: call ds:[GetTempPathW]
      [-]e0410085c074
         // 00403781: test eax, eax
         // 00403783: jz 0x4037b7
      [-]508db424
         // 004039d2: push eax
         // 004039d3: lea esi, ss:[esp+0x198]
      [-]ffff508db424
         // 004036c2: push eax
         // 004036c3: lea esi, ss:[esp+0x198]
      [-]ffff8bdee8
         // 004036cf: mov ebx, esi
         // 004036d1: call 0x402142
      [-]ffff8bc6e9
         // 004036f8: mov eax, esi
         // 004036fa: jmp 0x403364
      [-]ffff84c075
         // 00403975: test b1 al, b1 al
         // 00403977: jnz 0x4039b9
      [-]ffff508db424
         // 00403a80: push eax
         // 00403a81: lea esi, ss:[esp+0x1a0]
      [-]ffff8bcee9
         // 00403a8d: mov ecx, esi
         // 00403a8f: jmp 0x40359c
      [-]088b8424
         // 00403902: mov eax, ss:[esp+0x260]
      [-]50ff7424
         // 004039c8: push eax
         // 004039c9: push ss:[esp+0x28]
      [-]e0410085c075
         // 004039d9: test eax, eax
         // 004039db: jnz 0x4039e2
      [-]e04100ff7424
         // 00403b03: push ss:[esp+0x14]
      [-]000083bc24
         // 00403b0c: cmp ss:[esp+0x230], 0x8
      [-]088b8424
         // 00403b14: mov eax, ss:[esp+0x21c]
      [-]668b3183c1026685f675f5
         // 00403b18: mov b2 si, b2 ds:[ecx]
         // 00403b1b: add ecx, 0x2
         // 00403b1e: test b2 si, b2 si
         // 00403b21: jnz 0x403b18
      [-]2bcad1f9508b
         // 00403a69: sub ecx, edx
         // 00403a6b: sar ecx, b1 0x1
         // 00403a6d: push eax
         // 00403a6e: mov edi, ecx
      [-]8d8424??
         // 00403a70: lea eax, ss:[esp+0x1f4]
      [-]0000803d
         // 00403a7c: cmp b1 ds:[0x4282ad], b1 0x0
      [-]00006a0368
         // 00403bbb: push 0x3
         // 00403bbd: push 0x4267dc
      [-]508d9424
         // 00403e9e: push eax
         // 00403e9f: lea edx, ss:[esp+0x250]
      [-]ffff84c074
         // 00403eb2: test b1 al, b1 al
         // 00403eb4: jz 0x403f09
      [-]088b8424
         // 00403c9d: mov eax, ss:[esp+0x244]
      [-]506a2d68
         // 00403cad: push eax
         // 00403cae: push 0x2d
         // 00403cb0: push 0x426ac8
      [-]ffff508d8424
         // 00403cba: push eax
         // 00403cbb: lea eax, ss:[esp+0x3f0]
      [-]e1410083c40c68????????6a0368
         // 00403cc9: add esp, 0xc
         // 00403ccc: push 0x40000
         // 00403cd1: push 0x3
         // 00403cd3: push 0x4266a8
      [-]ffff508d8424
         // 00403cdd: push eax
         // 00403cde: lea eax, ss:[esp+0x3f0]
      [-]ffff508d8424
         // 00403fdb: push eax
         // 00403fdc: lea eax, ss:[esp+0x3f8]
      [-]e1410083c40c8d8424
         // 00403fea: add esp, 0xc
         // 00403fed: lea eax, ss:[esp+0x3f0]
      [-]508db424
         // 00403ff4: push eax
         // 00403ff5: lea esi, ss:[esp+0x1a0]
      [-]ffff8bdee8
         // 00404001: mov ebx, esi
         // 00404003: call 0x402128
      [-]5f5e5b33cce8
         // 00403de6: pop edi
         // 00403de7: pop esi
         // 00403de8: pop ebx
         // 00403de9: xor ecx, esp
         // 00403deb: call @__security_check_cookie@4
      [-]00008be55dc21000
         // 00403df0: mov esp, ebp
         // 00403df2: pop ebp
         // 00403df3: retn b2 0x10
      [-]558bec8b410c0b4508837938007503
         // 00403ef5: push ebp
         // 00403ef6: mov ebp, esp
         // 00403ef8: mov eax, ds:[ecx+0xc]
         // 00403efb: or eax, ss:[ebp+0x8]
         // 00403efe: cmp ds:[ecx+0x38], 0x0
         // 00403f02: jnz 0x403f07
      [-]83e01789410c8541107408
         // 00403f07: and eax, 0x17
         // 00403f0a: mov ds:[ecx+0xc], eax
         // 00403f0d: test ds:[ecx+0x10], eax
         // 00403f10: jz 0x403f1a
      [-]ff750ce8
         // 00403f6f: push ss:[ebp+0xc]
         // 00403f72: call 0x402116
      [-]5dc20800
         // 00403f1a: pop ebp
         // 00403f1b: retn b2 0x8
      [-]558bec8b038b500483ec1856576a0659844c1a0c755d
         // 00403ff8: push ebp
         // 00403ff9: mov ebp, esp
         // 00403ffb: mov eax, ds:[ebx]
         // 00403ffd: mov edx, ds:[eax+0x4]
         // 00404000: sub esp, 0x18
         // 00404003: push esi
         // 00404004: push edi
         // 00404005: push 0x6
         // 00404007: pop ecx
         // 00404008: test b1 ds:[edx+ebx+0xc], b1 cl
         // 0040400c: jnz 0x40406b
      [-]8b441a388b106a0183ec188bfc8d7508f3a58d4de8518bc8ff522c8b45f0990345e81355ec3b05
         // 0040421c: mov eax, ds:[edx+ebx+0x38]
         // 00404220: mov edx, ds:[eax]
         // 00404222: push 0x1
         // 00404224: sub esp, 0x18
         // 00404227: mov edi, esp
         // 00404229: lea esi, ss:[ebp+0x8]
         // 0040422c: rep movsdd 
         // 0040422e: lea ecx, ss:[ebp+0xffffffffffffffe8]
         // 00404231: push ecx
         // 00404232: mov ecx, eax
         // 00404234: call ds:[edx+0x2c]
         // 00404237: mov eax, ss:[ebp+0xfffffffffffffff0]
         // 0040423a: cdq 
         // 0040423b: add eax, ss:[ebp+0xffffffffffffffe8]
         // 0040423e: adc edx, ss:[ebp+0xffffffffffffffec]
         // 00404241: cmp eax, ds:[0x41e320]
      [-]8b038b480403cb8b410c83c802837938007503
         // 00404043: mov eax, ds:[ebx]
         // 00404045: mov ecx, ds:[eax+0x4]
         // 00404048: add ecx, ebx
         // 0040404a: mov eax, ds:[ecx+0xc]
         // 0040404d: or eax, 0x2
         // 00404050: cmp ds:[ecx+0x38], 0x0
         // 00404054: jnz 0x404059
      [-]83e01789410c8541107407
         // 00404059: and eax, 0x17
         // 0040405c: mov ds:[ecx+0xc], eax
         // 0040405f: test ds:[ecx+0x10], eax
         // 00404062: jz 0x40406b
      [-]5f8bc35ec9c21800
         // 0040406b: pop edi
         // 0040406c: mov eax, ebx
         // 0040406e: pop esi
         // 0040406f: leave 
         // 00404070: retn b2 0x18
      [-]568bf1578b7e38c706
         // 004040d0: push esi
         // 004040d1: mov esi, ecx
         // 004040d3: push edi
         // 004040d4: mov edi, ds:[esi+0x38]
         // 004040d7: mov ds:[esi], ??_7?$basic_streambuf@_WU?$char_traits@_W@std@@@std@@6B@
      [-]420085ff740e
         // 004040dd: test edi, edi
         // 004040df: jz 0x4040ef
      [-]ffff57e8
         // 004040e8: push edi
         // 004040e9: call ??3@YAXPAX@Z
      [-]5f8d4e045ee9
         // 0040418d: pop edi
         // 0040418e: lea ecx, ds:[esi+0x4]
         // 00404191: pop esi
         // 00404192: jmp ??1_Mutex@std@@QAE@XZ
      [-]8bff568bf1ff36e872050000ff36e8
         // 0040b8ed: mov edi, edi
         // 0040b8ef: push esi
         // 0040b8f0: mov esi, ecx
         // 0040b8f2: push ds:[esi]
         // 0040b8f4: call __Mtxdst
         // 0040b8f9: push ds:[esi]
         // 0040b8fb: call ??3@YAXPAX@Z
      [-]0b000059595ec3
         // 0040b900: pop ecx
         // 0040b901: pop ecx
         // 0040b902: pop esi
         // 0040b903: retn 
      [-]8bff558becff75108b450cff3485
         // 0040b81b: mov edi, edi
         // 0040b81d: push ebp
         // 0040b81e: mov ebp, esp
         // 0040b820: push ss:[ebp+0x10]
         // 0040b823: mov eax, ss:[ebp+0xc]
         // 0040b826: push ds:[0x41e328+eax*0x4]
      [-]ff7508e8
         // 0040b82d: push ss:[ebp+0x8]
         // 0040b830: call __wfsopen
      [-]000083c40c5dc3
         // 0040b835: add esp, 0xc
         // 0040b838: pop ebp
         // 0040b839: retn 
      [-]8bff558bec8b4d0c5333c08bd98bd183e30481e2????????4056f6c1407402
         // 0040b83a: mov edi, edi
         // 0040b83c: push ebp
         // 0040b83d: mov ebp, esp
         // 0040b83f: mov ecx, ss:[ebp+0xc]
         // 0040b842: push ebx
         // 0040b843: xor eax, eax
         // 0040b845: mov ebx, ecx
         // 0040b847: mov edx, ecx
         // 0040b849: and ebx, 0x4
         // 0040b84c: and edx, 0x80
         // 0040b852: inc eax
         // 0040b853: push esi
         // 0040b854: test b1 cl, b1 0x40
         // 0040b857: jz 0x40b85b
      [-]f6c1087403
         // 0040b85b: test b1 cl, b1 0x8
         // 0040b85e: jz 0x40b863
      [-]81e1????????33f6
         // 0040b863: and ecx, 0xffffffffffffff3b
         // 0040b869: xor esi, esi
      [-]3bc1740c
         // 0040b86b: cmp eax, ecx
         // 0040b86d: jz 0x40b87b
      [-]4685c075f0
         // 0040ba84: inc esi
         // 0040ba85: test eax, eax
         // 0040ba87: jnz 0x40ba79
      [-]33c0eb55
         // 0040b885: xor eax, eax
         // 0040b887: jmp 0x40b8de
      [-]85d27422
         // 0040b889: test edx, edx
         // 0040b88b: jz 0x40b8af
      [-]f6c10a741d
         // 0040b88d: test b1 cl, b1 0xa
         // 0040b890: jz 0x40b8af
      [-]ff75106a00ff7508e87cffffff83c40c85c07409
         // 0040b892: push ss:[ebp+0x10]
         // 0040b895: push 0x0
         // 0040b897: push ss:[ebp+0x8]
         // 0040b89a: call 0x40b81b
         // 0040b89f: add esp, 0xc
         // 0040b8a2: test eax, eax
         // 0040b8a4: jz 0x40b8af
      [-]000059ebd6
         // 0040b9a7: pop ecx
         // 0040b9a8: jmp 0x40b980
      [-]ff751056ff7508e860ffffff8bf083c40c85f674c1
         // 0040b8af: push ss:[ebp+0x10]
         // 0040b8b2: push esi
         // 0040b8b3: push ss:[ebp+0x8]
         // 0040b8b6: call 0x40b81b
         // 0040b8bb: mov esi, eax
         // 0040b8bd: add esp, 0xc
         // 0040b8c0: test esi, esi
         // 0040b8c2: jz 0x40b885
      [-]85db7414
         // 0040b8c4: test ebx, ebx
         // 0040b8c6: jz 0x40b8dc
      [-]6a026a0056e8
         // 0040b702: push 0x2
         // 0040b704: push 0x0
         // 0040b706: push esi
         // 0040b707: call _fseek
      [-]49000083c40c85c07403
         // 0040b70c: add esp, 0xc
         // 0040b70f: test eax, eax
         // 0040b711: jz 0x40b716
      [-]5e5b5dc3
         // 0040b8de: pop esi
         // 0040b8df: pop ebx
         // 0040b8e0: pop ebp
         // 0040b8e1: retn 
      [-]8bff558bec5de94dffffff
         // 0040b8e2: mov edi, edi
         // 0040b8e4: push ebp
         // 0040b8e5: mov ebp, esp
         // 0040b8e7: pop ebp
         // 0040b8e8: jmp 0x40b83a
      [-]a1????????8b0485
         // 0040be32: mov eax, ds:[0x425150]
         // 0040be37: mov eax, ds:[0x427ca8+eax*0x4]
      [-]ff05????????50ff15
         // 0040be3e: inc ds:[0x425150]
         // 0040be44: push eax
         // 0040be45: call ds:[DecodePointer]
      [-]e0410085c07402
         // 0040be4b: test eax, eax
         // 0040be4d: jz 0x40be51
      [-]833d????????0a72d8
         // 0040bd56: cmp ds:[0x425150], 0xa
         // 0040bd5d: jb 0x40bd37
      [-]8bff558becff7508ff15
         // 0040bbca: mov edi, edi
         // 0040bbcc: push ebp
         // 0040bbcd: mov ebp, esp
         // 0040bbcf: push ss:[ebp+0x8]
         // 0040bbd2: call ds:[LeaveCriticalSection]
      [-]41005dc3
         // 0040bbd8: pop ebp
         // 0040bbd9: retn 
      [-]8bff568bf1807e08007409
         // 0040be19: mov edi, edi
         // 0040be1b: push esi
         // 0040be1c: mov esi, ecx
         // 0040be1e: cmp b1 ds:[esi+0x8], b1 0x0
         // 0040be22: jz 0x40be2d
      [-]ff7604e8
         // 0040bc5e: push ds:[esi+0x4]
         // 0040bc61: call _free
      [-]08000059
         // 0040bc66: pop ecx
      [-]83660400c64608005ec3
         // 0040be2d: and ds:[esi+0x4], 0x0
         // 0040be31: mov b1 ds:[esi+0x8], b1 0x0
         // 0040be35: pop esi
         // 0040be36: retn 
      [-]8bff558bec568d4508508bf1e893ffffffc706
         // 0040c0a1: mov edi, edi
         // 0040c0a3: push ebp
         // 0040c0a4: mov ebp, esp
         // 0040c0a6: push esi
         // 0040c0a7: lea eax, ss:[ebp+0x8]
         // 0040c0aa: push eax
         // 0040c0ab: mov esi, ecx
         // 0040c0ad: call ??0exception@std@@QAE@ABQBD@Z
         // 0040c0b2: mov ds:[esi], ??_7bad_cast@std@@6B@
      [-]41008bc65e5dc20400
         // 0040c0b8: mov eax, esi
         // 0040c0ba: pop esi
         // 0040c0bb: pop ebp
         // 0040c0bc: retn b2 0x4
      [-]4100e95dffffff
         // 0040bcf1: jmp ?_Tidy@exception@std@@AAEXXZ
      [-]8bff558bec568bf1c706
         // 0040bd1b: mov edi, edi
         // 0040bd1d: push ebp
         // 0040bd1e: mov ebp, esp
         // 0040bd20: push esi
         // 0040bd21: mov esi, ecx
         // 0040bd23: mov ds:[esi], ??_7exception@std@@6B@
      [-]4100e825fffffff64508017407
         // 0040bd29: call ?_Tidy@exception@std@@AAEXXZ
         // 0040bd2e: test b1 ss:[ebp+0x8], b1 0x1
         // 0040bd32: jz 0x40bd3b
      [-]04000059
         // 0040bd3a: pop ecx
      [-]8bc65e5dc20400
         // 0040bf01: mov eax, esi
         // 0040bf03: pop esi
         // 0040bf04: pop ebp
         // 0040bf05: retn b2 0x4
      [-]8bff558bec56ff75088bf1e8a4ffffffc706
         // 0040c116: mov edi, edi
         // 0040c118: push ebp
         // 0040c119: mov ebp, esp
         // 0040c11b: push esi
         // 0040c11c: push ss:[ebp+0x8]
         // 0040c11f: mov esi, ecx
         // 0040c121: call ??0exception@std@@QAE@ABV01@@Z
         // 0040c126: mov ds:[esi], ??_7bad_cast@std@@6B@
      [-]41008bc65e5dc20400
         // 0040c12c: mov eax, esi
         // 0040c12e: pop esi
         // 0040c12f: pop ebp
         // 0040c130: retn b2 0x4
      [-]8bff51c701
         // 0040c3a2: mov edi, edi
         // 0040c3a4: push ecx
         // 0040c3a5: mov ds:[ecx], ??_7type_info@@6B@
      [-]56000059c3
         // 0040c3b0: pop ecx
         // 0040c3b1: retn 
      [-]8bff558bec568bf1e8e3fffffff64508017407
         // 0040c3b2: mov edi, edi
         // 0040c3b4: push ebp
         // 0040c3b5: mov ebp, esp
         // 0040c3b7: push esi
         // 0040c3b8: mov esi, ecx
         // 0040c3ba: call 0x40c3a2
         // 0040c3bf: test b1 ss:[ebp+0x8], b1 0x1
         // 0040c3c3: jz 0x40c3cc
      [-]56e8ccffffff59
         // 0040c3c5: push esi
         // 0040c3c6: call ??3@YAXPAX@Z
         // 0040c3cb: pop ecx
      [-]8bc65e5dc20400
         // 0040c3cc: mov eax, esi
         // 0040c3ce: pop esi
         // 0040c3cf: pop ebp
         // 0040c3d0: retn b2 0x4
      [-]b8????????c3
         // 0040c6a4: mov eax, 0x4251d8
         // 0040c6a9: retn 
      [-]6a01e8ccfeffff59c3
         // 0040cf21: push 0x1
         // 0040cf23: call _flsall
         // 0040cf28: pop ecx
         // 0040cf29: retn 
      [-]558bec83ec08535657fc8945fc33c0505050ff75fcff7514ff7510ff750cff7508e8
         // 0040ef8e: push ebp
         // 0040ef8f: mov ebp, esp
         // 0040ef91: sub esp, 0x8
         // 0040ef94: push ebx
         // 0040ef95: push esi
         // 0040ef96: push edi
         // 0040ef97: cld 
         // 0040ef98: mov ss:[ebp+0xfffffffffffffffc], eax
         // 0040ef9b: xor eax, eax
         // 0040ef9d: push eax
         // 0040ef9e: push eax
         // 0040ef9f: push eax
         // 0040efa0: push ss:[ebp+0xfffffffffffffffc]
         // 0040efa3: push ss:[ebp+0x14]
         // 0040efa6: push ss:[ebp+0x10]
         // 0040efa9: push ss:[ebp+0xc]
         // 0040efac: push ss:[ebp+0x8]
         // 0040efaf: call ___InternalCxxFrameHandler
      [-]000083c4208945f85f5e5b8b45f88be55dc3
         // 0040efb4: add esp, 0x20
         // 0040efb7: mov ss:[ebp+0xfffffffffffffff8], eax
         // 0040efba: pop edi
         // 0040efbb: pop esi
         // 0040efbc: pop ebx
         // 0040efbd: mov eax, ss:[ebp+0xfffffffffffffff8]
         // 0040efc0: mov esp, ebp
         // 0040efc2: pop ebp
         // 0040efc3: retn 
      [-]6a0aff15
         // 00410bf9: push 0xa
         // 00410bfb: call ds:[IsProcessorFeaturePresent]
      [-]8bff558bec8b4508a3
         // 00411c58: mov edi, edi
         // 00411c5a: push ebp
         // 00411c5b: mov ebp, esp
         // 00411c5d: mov eax, ss:[ebp+0x8]
         // 00411c60: mov ds:[0x428088], eax
      [-]8bff558bec8b4508a3
         // 00412344: mov edi, edi
         // 00412346: push ebp
         // 00412347: mov ebp, esp
         // 00412349: mov eax, ss:[ebp+0x8]
         // 0041234c: mov ds:[0x42808c], eax
      [-]8bff558bec8b4508a3
         // 00414de0: mov edi, edi
         // 00414de2: push ebp
         // 00414de3: mov ebp, esp
         // 00414de5: mov eax, ss:[ebp+0x8]
         // 00414de8: mov ds:[0x4281f0], eax
      [-]e04100c3
         // 00415370: retn 
      [-]8bff558bec8b4508a3
         // 00415514: mov edi, edi
         // 00415516: push ebp
         // 00415517: mov ebp, esp
         // 00415519: mov eax, ss:[ebp+0x8]
         // 0041551c: mov ds:[0x42820c], eax
      [-]8bff56b8
         // 00415263: mov edi, edi
         // 00415265: push esi
         // 00415266: mov eax, 0x4235ac
      [-]578bf83bc6730f
         // 00415270: push edi
         // 00415271: mov edi, eax
         // 00415273: cmp eax, esi
         // 00415275: jnb 0x415286
      [-]8b0785c07402
         // 00415447: mov eax, ds:[edi]
         // 00415449: test eax, eax
         // 0041544b: jz 0x41544f
      [-]83c7043bfe72f1
         // 0041544f: add edi, 0x4
         // 00415452: cmp edi, esi
         // 00415454: jb 0x415447
      [-]8bff56b8
         // 00415289: mov edi, edi
         // 0041528b: push esi
         // 0041528c: mov eax, 0x4235b4
      [-]578bf83bc6730f
         // 00415296: push edi
         // 00415297: mov edi, eax
         // 00415299: cmp eax, esi
         // 0041529b: jnb 0x4152ac
      [-]8b0785c07402
         // 0041546d: mov eax, ds:[edi]
         // 0041546f: test eax, eax
         // 00415471: jz 0x415475
      [-]83c7043bfe72f1
         // 00415475: add edi, 0x4
         // 00415478: cmp edi, esi
         // 0041547a: jb 0x41546d
      [-]4100ff15
         // 00415ce1: call ds:[SetUnhandledExceptionFilter]
      [-]410033c0c3
         // 00415ce7: xor eax, eax
         // 00415ce9: retn 
      [-]8bff558bec568bf1c706
         // 00416301: mov edi, edi
         // 00416303: push ebp
         // 00416304: mov ebp, esp
         // 00416306: push esi
         // 00416307: mov esi, ecx
         // 00416309: mov ds:[esi], ??_7bad_exception@std@@6B@
      [-]5cfffff64508017407
         // 00416314: test b1 ss:[ebp+0x8], b1 0x1
         // 00416318: jz 0x416321
      [-]61ffff59
         // 00416420: pop ecx
      [-]8bc65e5dc20400
         // 00416231: mov eax, esi
         // 00416233: pop esi
         // 00416234: pop ebp
         // 00416235: retn b2 0x4
      [-]8bff558bec56ff75088bf1e8
         // 00416ecb: mov edi, edi
         // 00416ecd: push ebp
         // 00416ece: mov ebp, esp
         // 00416ed0: push esi
         // 00416ed1: push ss:[ebp+0x8]
         // 00416ed4: mov esi, ecx
         // 00416ed6: call ??0exception@std@@QAE@ABV01@@Z
      [-]50ffffc706
         // 00416edb: mov ds:[esi], ??_7bad_exception@std@@6B@
      [-]41008bc65e5dc20400
         // 00416ee1: mov eax, esi
         // 00416ee3: pop esi
         // 00416ee4: pop ebp
         // 00416ee5: retn b2 0x4
      [-]b8????????c3
         // 00416f2c: mov eax, 0x425fd0
         // 00416f31: retn 
      [-]b8????????c3
         // 00416f32: mov eax, 0x425f20
         // 00416f37: retn 
      [-]8bff558bec83ec24a1d455420033c58945fc8b4508538945e08b450c56578945e4e8
         // 0041c303: mov edi, edi
         // 0041c305: push ebp
         // 0041c306: mov ebp, esp
         // 0041c308: sub esp, 0x24
         // 0041c30b: mov eax, ds:[___security_cookie]
         // 0041c310: xor eax, ebp
         // 0041c312: mov ss:[ebp+0xfffffffffffffffc], eax
         // 0041c315: mov eax, ss:[ebp+0x8]
         // 0041c318: push ebx
         // 0041c319: mov ss:[ebp+0xffffffffffffffe0], eax
         // 0041c31c: mov eax, ss:[ebp+0xc]
         // 0041c31f: push esi
         // 0041c320: push edi
         // 0041c321: mov ss:[ebp+0xffffffffffffffe4], eax
         // 0041c324: call __encoded_null
      [-]ffff8365ec00833d
         // 0041c329: and ss:[ebp+0xffffffffffffffec], 0x0
         // 0041c32d: cmp ds:[0x428294], 0x0
      [-]008945e8757d
         // 0041c334: mov ss:[ebp+0xffffffffffffffe8], eax
         // 0041c337: jnz 0x41c3b6
      [-]41008bd885db0f8410010000
         // 0041c594: mov ebx, eax
         // 0041c596: test ebx, ebx
         // 0041c598: jz 0x41c6ae
      [-]e0410068
         // 0041c5a4: push 0x420fcc
      [-]53ffd785c00f84fa000000
         // 0041c5a9: push ebx
         // 0041c5aa: call edi
         // 0041c5ac: test eax, eax
         // 0041c5ae: jz 0x41c6ae
      [-]e0410050ffd668
         // 0041c45a: push eax
         // 0041c45b: call esi
         // 0041c45d: push 0x420fa4
      [-]ffd750ffd668
         // 0041c468: call edi
         // 0041c46a: push eax
         // 0041c46b: call esi
         // 0041c46d: push 0x420f90
      [-]ffd750ffd668
         // 0041c478: call edi
         // 0041c47a: push eax
         // 0041c47b: call esi
         // 0041c47d: push 0x420f74
      [-]ffd750ffd6a3
         // 0041c488: call edi
         // 0041c48a: push eax
         // 0041c48b: call esi
         // 0041c48d: mov ds:[0x4289a4], eax
      [-]85c07410
         // 0041c492: test eax, eax
         // 0041c494: jz 0x41c4a6
      [-]53ffd750ffd6a3
         // 0041c49b: push ebx
         // 0041c49c: call edi
         // 0041c49e: push eax
         // 0041c49f: call esi
         // 0041c4a1: mov ds:[0x4289a0], eax
      [-]8b4de88b35
         // 0041c4ab: mov ecx, ss:[ebp+0xffffffffffffffe8]
         // 0041c4ae: mov esi, ds:[DecodePointer]
      [-]e041003bc17447
         // 0041c4b4: cmp eax, ecx
         // 0041c4b6: jz 0x41c4ff
      [-]50ffd6ff35
         // 0041c4c0: push eax
         // 0041c4c1: call esi
         // 0041c4c3: push ds:[0x4289a4]
      [-]8bf8ffd68bd885ff742c
         // 0041c4c9: mov edi, eax
         // 0041c4cb: call esi
         // 0041c4cd: mov ebx, eax
         // 0041c4cf: test edi, edi
         // 0041c4d1: jz 0x41c4ff
      [-]85db7428
         // 0041c3e3: test ebx, ebx
         // 0041c3e5: jz 0x41c40f
      [-]ffd785c07419
         // 0041c3e7: call edi
         // 0041c3e9: test eax, eax
         // 0041c3eb: jz 0x41c406
      [-]8d4ddc516a0c8d4df0516a0150ffd385c07406
         // 0041c3ed: lea ecx, ss:[ebp+0xffffffffffffffdc]
         // 0041c3f0: push ecx
         // 0041c3f1: push 0xc
         // 0041c3f3: lea ecx, ss:[ebp+0xfffffffffffffff0]
         // 0041c3f6: push ecx
         // 0041c3f7: push 0x1
         // 0041c3f9: push eax
         // 0041c3fa: call ebx
         // 0041c3fc: test eax, eax
         // 0041c3fe: jz 0x41c406
      [-]f645f8017509
         // 0041c400: test b1 ss:[ebp+0xfffffffffffffff8], b1 0x1
         // 0041c404: jnz 0x41c40f
      [-]814d10????????eb33
         // 0041c406: or ss:[ebp+0x10], 0x200000
         // 0041c40d: jmp 0x41c442
      [-]3b45e87429
         // 0041c504: cmp eax, ss:[ebp+0xffffffffffffffe8]
         // 0041c507: jz 0x41c532
      [-]50ffd685c07422
         // 0041c419: push eax
         // 0041c41a: call esi
         // 0041c41c: test eax, eax
         // 0041c41e: jz 0x41c442
      [-]ffd08945ec85c07419
         // 0041c420: call eax
         // 0041c422: mov ss:[ebp+0xffffffffffffffec], eax
         // 0041c425: test eax, eax
         // 0041c427: jz 0x41c442
      [-]3b45e8740f
         // 0041c51e: cmp eax, ss:[ebp+0xffffffffffffffe8]
         // 0041c521: jz 0x41c532
      [-]50ffd685c07408
         // 0041c433: push eax
         // 0041c434: call esi
         // 0041c436: test eax, eax
         // 0041c438: jz 0x41c442
      [-]ff75ecffd08945ec
         // 0041c43a: push ss:[ebp+0xffffffffffffffec]
         // 0041c43d: call eax
         // 0041c43f: mov ss:[ebp+0xffffffffffffffec], eax
      [-]ffd685c07410
         // 0041c538: call esi
         // 0041c53a: test eax, eax
         // 0041c53c: jz 0x41c54e
      [-]ff7510ff75e4ff75e0ff75ecffd0eb02
         // 0041c44e: push ss:[ebp+0x10]
         // 0041c451: push ss:[ebp+0xffffffffffffffe4]
         // 0041c454: push ss:[ebp+0xffffffffffffffe0]
         // 0041c457: push ss:[ebp+0xffffffffffffffec]
         // 0041c45a: call eax
         // 0041c45c: jmp 0x41c460
      [-]8b4dfc5f5e33cd5be8
         // 0041c550: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 0041c553: pop edi
         // 0041c554: pop esi
         // 0041c555: xor ecx, ebp
         // 0041c557: pop ebx
         // 0041c558: call @__security_check_cookie@4
      [-]feffc9c3
         // 0041c55d: leave 
         // 0041c55e: retn 
      [-]8bff558bec6a01ff7508ff7518ff7514ff7510ff750ce821ffffff83c4185dc3
         // 0041d265: mov edi, edi
         // 0041d267: push ebp
         // 0041d268: mov ebp, esp
         // 0041d26a: push 0x1
         // 0041d26c: push ss:[ebp+0x8]
         // 0041d26f: push ss:[ebp+0x18]
         // 0041d272: push ss:[ebp+0x14]
         // 0041d275: push ss:[ebp+0x10]
         // 0041d278: push ss:[ebp+0xc]
         // 0041d27b: call __sopen_helper_0
         // 0041d280: add esp, 0x18
         // 0041d283: pop ebp
         // 0041d284: retn 
      [-]a1????????83f8ff740c
         // 0041d460: mov eax, ds:[0x426160]
         // 0041d465: cmp eax, 0xffffffffffffffff
         // 0041d468: jz 0x41d476
      [-]83f8fe7407
         // 0041d46a: cmp eax, 0xfffffffffffffffe
         // 0041d46d: jz 0x41d476
      [-]8bff558bec8b450885c07515
         // 0041d6e8: mov edi, edi
         // 0041d6ea: push ebp
         // 0041d6eb: mov ebp, esp
         // 0041d6ed: mov eax, ss:[ebp+0x8]
         // 0041d6f0: test eax, eax
         // 0041d6f2: jnz 0x41d709
      [-]ffffc700????????e8
         // 0041d6f9: mov ds:[eax], 0x16
         // 0041d6ff: call __invalid_parameter_noinfo
      [-]4cffff6a16585dc3
         // 0041d704: push 0x16
         // 0041d706: pop eax
         // 0041d707: pop ebp
         // 0041d708: retn 
      [-]890833c05dc3
         // 0041d7ff: mov ds:[eax], ecx
         // 0041d801: xor eax, eax
         // 0041d803: pop ebp
         // 0041d804: retn 
      [-]8b5424088d420c8b4ae033c8e8
         // 0041dbd4: mov edx, ss:[esp+0x8]
         // 0041dbd8: lea eax, ds:[edx+0xc]
         // 0041dbdb: mov ecx, ds:[edx+0xffffffffffffffe0]
         // 0041dbde: xor ecx, eax
         // 0041dbe0: call @__security_check_cookie@4
      [-]e2feffb8
         // 0041dbe5: mov eax, stru_424014.magicNumber
      [-]8b5424088d420c
         // 0041dd4f: mov edx, ss:[esp+0x8]
         // 0041dd53: lea eax, ds:[edx+0xc]
         // 0041dd56: mov ecx, ds:[edx+0xffffffffffffffe4]
         // 0041dd59: xor ecx, eax
         // 0041dd5b: call @__security_check_cookie@4

  }
  condition:
    all of them
}
