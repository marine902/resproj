rule blackmoon_10_1 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         f7c1????????740f
         // 00401009: test ecx, 0x3
         // 0040100f: jz 0x401020
      [-]8a014184c0743b
         // 00401011: mov b1 al, b1 ds:[ecx]
         // 00401013: inc ecx
         // 00401014: test b1 al, b1 al
         // 00401016: jz 0x401053
      [-]f7c1????????75f1
         // 00401018: test ecx, 0x3
         // 0040101e: jnz 0x401011
      [-]8b01ba????????03d083f0ff33c283c104a9????????74e8
         // 00401020: mov eax, ds:[ecx]
         // 00401022: mov edx, 0x7efefeff
         // 00401027: add edx, eax
         // 00401029: xor eax, 0xffffffffffffffff
         // 0040102c: xor eax, edx
         // 0040102e: add ecx, 0x4
         // 00401031: test eax, 0xffffffff81010100
         // 00401036: jz 0x401020
      [-]8b41fc84c07426
         // 00401038: mov eax, ds:[ecx+0xfffffffffffffffc]
         // 0040103b: test b1 al, b1 al
         // 0040103d: jz 0x401065
      [-]84e4741c
         // 0040103f: test b1 ah, b1 ah
         // 00401041: jz 0x40105f
      [-]a9????????740f
         // 00401043: test eax, 0xff0000
         // 00401048: jz 0x401059
      [-]a9????????7402
         // 0040104a: test eax, 0xffffffffff000000
         // 0040104f: jz 0x401053
      [-]8d41ff2bc3c3
         // 00401053: lea eax, ds:[ecx+0xffffffffffffffff]
         // 00401056: sub eax, ebx
         // 00401058: retn 
      [-]8d41fe2bc3c3
         // 00401059: lea eax, ds:[ecx+0xfffffffffffffffe]
         // 0040105c: sub eax, ebx
         // 0040105e: retn 
      [-]8d41fd2bc3c3
         // 0040105f: lea eax, ds:[ecx+0xfffffffffffffffd]
         // 00401062: sub eax, ebx
         // 00401064: retn 
      [-]8d41fc2bc3c3
         // 00401065: lea eax, ds:[ecx+0xfffffffffffffffc]
         // 00401068: sub eax, ebx
         // 0040106a: retn 
      [-]40c1e0022be08d3c2451c745fc????????8d7508
         // 00401070: inc eax
         // 00401071: shl eax, b1 0x2
         // 00401074: sub esp, eax
         // 00401076: lea edi, ss:[esp]
         // 00401079: push ecx
         // 0040107a: mov ss:[ebp+0xfffffffffffffffc], 0x1
         // 00401081: lea esi, ss:[ebp+0x8]
      [-]51e871ffffff590145fc8907
         // 00401089: push ecx
         // 0040108a: call 0x401000
         // 0040108f: pop ecx
         // 00401090: add ss:[ebp+0xfffffffffffffffc], eax
         // 00401093: mov ds:[edi], eax
      [-]ff75fce8
         // 0040109b: push ss:[ebp+0xfffffffffffffffc]
         // 0040109e: call 0x404e3c
      [-]588d1c24578d5508
         // 004010a8: pop eax
         // 004010a9: lea ebx, ss:[esp]
         // 004010ac: push edi
         // 004010ad: lea edx, ss:[ebp+0x8]
      [-]f3a44875f1
         // 004010ba: rep movsbb 
         // 004010bc: dec eax
         // 004010bd: jnz 0x4010b0
      [-]c60700588be55dc3
         // 004010bf: mov b1 ds:[edi], b1 0x0
         // 004010c2: pop eax
         // 004010c3: mov esp, ebp
         // 004010c5: pop ebp
         // 004010c6: retn 
      [-]6a004b75fb
         // 00401165: push 0x0
         // 00401167: dec ebx
         // 00401168: jnz 0x401165
      [-]558bec51
         // 00401185: push ebp
         // 00401186: mov ebp, esp
         // 00401188: push ecx
      [-]5283c20852e8
         // 004011a5: push edx
         // 004011a6: add edx, 0x8
         // 004011a9: push edx
         // 004011aa: call 0x404e3c
      [-]c707????????8f4704
         // 004011b4: mov ds:[edi], 0x1
         // 004011ba: pop ds:[edi+0x4]
      [-]5a8d5d08
         // 004011c0: pop edx
         // 004011c1: lea ebx, ss:[ebp+0x8]
      [-]8be55dc3
         // 004011d8: mov esp, ebp
         // 004011da: pop ebp
         // 004011db: retn 
      [-]558bece80e000000
         // 00404d6c: push ebp
         // 00404d6d: mov ebp, esp
         // 00404d6f: call 0x404d82
      [-]e9000000008be55dc3
         // 00404d79: jmp 0x404d7e
         // 00404d7e: mov esp, ebp
         // 00404d80: pop ebp
         // 00404d81: retn 
      [-]558bec8be55dc3
         // 00404d82: push ebp
         // 00404d83: mov ebp, esp
         // 00404d85: mov esp, ebp
         // 00404d87: pop ebp
         // 00404d88: retn 
      [-]fcdbe3e8
         // 004c6bbd: cld 
         // 004c6bbe: fninit 
         // 004c6bc0: call 0x4c6b9d
      [-]000083c404e8
         // 004c6bd4: add esp, 0x4
         // 004c6bd7: call 0x4048dd
      [-]8b44240c
         // 00407750: mov eax, ss:[esp+0xc]
      [-]83f801750d
         // 00407758: cmp eax, 0x1
         // 0040775b: jnz 0x40776a
      [-]8b4424088b5424048a08880ac3
         // 0040775d: mov eax, ss:[esp+0x8]
         // 00407761: mov edx, ss:[esp+0x4]
         // 00407765: mov b1 cl, b1 ds:[eax]
         // 00407767: mov b1 ds:[edx], b1 cl
         // 00407769: retn 
      [-]83f802750f
         // 0040776a: cmp eax, 0x2
         // 0040776d: jnz 0x40777e
      [-]8b4424088b542404668b0866890ac3
         // 0040776f: mov eax, ss:[esp+0x8]
         // 00407773: mov edx, ss:[esp+0x4]
         // 00407777: mov b2 cx, b2 ds:[eax]
         // 0040777a: mov b2 ds:[edx], b2 cx
         // 0040777d: retn 
      [-]83f804750d
         // 0040777e: cmp eax, 0x4
         // 00407781: jnz 0x407790
      [-]8b4424088b5424048b08890ac3
         // 00407783: mov eax, ss:[esp+0x8]
         // 00407787: mov edx, ss:[esp+0x4]
         // 0040778b: mov ecx, ds:[eax]
         // 0040778d: mov ds:[edx], ecx
         // 0040778f: retn 
      [-]8b4c2404508b44240c5051e8
         // 00407790: mov ecx, ss:[esp+0x4]
         // 00407794: push eax
         // 00407795: mov eax, ss:[esp+0xc]
         // 00407799: push eax
         // 0040779a: push ecx
         // 0040779b: call 0x409b50
      [-]8b4c2408
         // 004077b0: mov ecx, ss:[esp+0x8]
      [-]83f9017508
         // 004077b8: cmp ecx, 0x1
         // 004077bb: jnz 0x4077c5
      [-]8b442404c60000c3
         // 004077bd: mov eax, ss:[esp+0x4]
         // 004077c1: mov b1 ds:[eax], b1 0x0
         // 004077c4: retn 
      [-]83f902750a
         // 004077c5: cmp ecx, 0x2
         // 004077c8: jnz 0x4077d4
      [-]8b4c240466c7010000c3
         // 004077ca: mov ecx, ss:[esp+0x4]
         // 004077ce: mov b2 ds:[ecx], b2 0x0
         // 004077d3: retn 
      [-]83f904750b
         // 004077d4: cmp ecx, 0x4
         // 004077d7: jnz 0x4077e4
      [-]8b542404c702????????c3
         // 004077d9: mov edx, ss:[esp+0x4]
         // 004077dd: mov ds:[edx], 0x0
         // 004077e3: retn 
      [-]578b7c2408
         // 004077e6: push edi
         // 004077e7: mov edi, ss:[esp+0x8]
      [-]c1e902f3ab
         // 004077ed: shr ecx, b1 0x2
         // 004077f0: rep stosdd 
      [-]83e103f3aa5f
         // 004077f4: and ecx, 0x3
         // 004077f7: rep stosbb 
         // 004077f9: pop edi
      [-]568b742408
         // 00407f40: push esi
         // 00407f41: mov esi, ss:[esp+0x8]
      [-]803e007439
         // 00407f49: cmp b1 ds:[esi], b1 0x0
         // 00407f4c: jz 0x407f87
      [-]f2aef7d149
         // 00407f57: repne scasbb 
         // 00407f59: not ecx
         // 00407f5b: dec ecx
      [-]8d43015068????????e873
         // 00407f5f: lea eax, ds:[ebx+0x1]
         // 00407f62: push eax
         // 00407f63: push 0x7e8
         // 00407f68: call 0x4081e0
      [-]c1e902f3a5
         // 00407f73: shr ecx, b1 0x2
         // 00407f76: rep movsdd 
      [-]83e103f3a4c60418005f5b5ec3
         // 00407f7a: and ecx, 0x3
         // 00407f7d: rep movsbb 
         // 00407f7f: mov b1 ds:[eax+ebx], b1 0x0
         // 00407f83: pop edi
         // 00407f84: pop ebx
         // 00407f85: pop esi
         // 00407f86: retn 
      [-]81ec????????8b8424????????568bb424????????c644240400c706????????8b0083f8017c74
         // 00408090: sub esp, 0x104
         // 00408096: mov eax, ss:[esp+0x110]
         // 0040809d: push esi
         // 0040809e: mov esi, ss:[esp+0x10c]
         // 004080a5: mov b1 ss:[esp+0x4], b1 0x0
         // 004080aa: mov ds:[esi], 0x0
         // 004080b0: mov eax, ds:[eax]
         // 004080b2: cmp eax, 0x1
         // 004080b5: jl 0x40812b
      [-]83f8087f6f
         // 004080b7: cmp eax, 0x8
         // 004080ba: jg 0x40812b
      [-]83f8017507
         // 004080bc: cmp eax, 0x1
         // 004080bf: jnz 0x4080c8
      [-]83f8027507
         // 004080c8: cmp eax, 0x2
         // 004080cb: jnz 0x4080d4
      [-]83f8037507
         // 004080d4: cmp eax, 0x3
         // 004080d7: jnz 0x4080e0
      [-]83f8047507
         // 004080e0: cmp eax, 0x4
         // 004080e3: jnz 0x4080ec
      [-]83f8057507
         // 004080ec: cmp eax, 0x5
         // 004080ef: jnz 0x4080f8
      [-]83f8067507
         // 004080f8: cmp eax, 0x6
         // 004080fb: jnz 0x408104
      [-]83e807f7d81bc083e01383c007
         // 00408104: sub eax, 0x7
         // 00408107: neg eax
         // 00408109: sbb eax, eax
         // 0040810b: and eax, 0x13
         // 0040810e: add eax, 0x7
      [-]6a008d4c240850516a00ff15
         // 00408111: push 0x0
         // 00408113: lea ecx, ss:[esp+0x8]
         // 00408117: push eax
         // 00408118: push ecx
         // 00408119: push 0x0
         // 0040811b: call ds:[SHGetSpecialFolderPathA]
      [-]0f8485000000
         // 00408123: jz 0x4081ae
      [-]83f8097512
         // 0040812b: cmp eax, 0x9
         // 0040812e: jnz 0x408142
      [-]8d54240468????????52ff15
         // 00408130: lea edx, ss:[esp+0x4]
         // 00408134: push 0x104
         // 00408139: push edx
         // 0040813a: call ds:[GetWindowsDirectoryA]
      [-]83f80a7512
         // 00408142: cmp eax, 0xa
         // 00408145: jnz 0x408159
      [-]8d54240468????????52ff15
         // 00408147: lea edx, ss:[esp+0x4]
         // 0040814b: push 0x104
         // 00408150: push edx
         // 00408151: call ds:[GetSystemDirectoryA]
      [-]83f80b7550
         // 00408159: cmp eax, 0xb
         // 0040815c: jnz 0x4081ae
      [-]8d5424045268????????ff15
         // 0040815e: lea edx, ss:[esp+0x4]
         // 00408162: push edx
         // 00408163: push 0x104
         // 00408168: call ds:[GetTempPathA]
      [-]3bc81bc0f7d8
         // 00408170: cmp ecx, eax
         // 00408172: sbb eax, eax
         // 00408174: neg eax
      [-]578d7c240883c9ff
         // 0040817a: push edi
         // 0040817b: lea edi, ss:[esp+0x8]
         // 0040817f: or ecx, 0xffffffffffffffff
      [-]f2aef7d1495f
         // 00408184: repne scasbb 
         // 00408186: not ecx
         // 00408188: dec ecx
         // 00408189: pop edi
      [-]807c0c035c740a
         // 0040818e: cmp b1 ss:[esp+ecx+0x3], b1 0x5c
         // 00408193: jz 0x40819f
      [-]c6440c045cc6440c0500
         // 00408195: mov b1 ss:[esp+ecx+0x4], b1 0x5c
         // 0040819a: mov b1 ss:[esp+ecx+0x5], b1 0x0
      [-]8d54240452e897
         // 0040819f: lea edx, ss:[esp+0x4]
         // 004081a3: push edx
         // 004081a4: call 0x407f40
      [-]ffff83c4048906
         // 004081a9: add esp, 0x4
         // 004081ac: mov ds:[esi], eax
      [-]5e81c4????????c3
         // 004081ae: pop esi
         // 004081af: add esp, 0x104
         // 004081b5: retn 
      [-]8b4c240c8b542408518b4c24085251ffd0c20c00
         // 004081e9: mov ecx, ss:[esp+0xc]
         // 004081ed: mov edx, ss:[esp+0x8]
         // 004081f1: push ecx
         // 004081f2: mov ecx, ss:[esp+0x8]
         // 004081f6: push edx
         // 004081f7: push ecx
         // 004081f8: call eax
         // 004081fa: retn b2 0xc
      [-]e814000000f6442408017407
         // 0040889f: call 0x4088b8
         // 004088a4: test b1 ss:[esp+0x8], b1 0x1
         // 004088a9: jz 0x4088b2
      [-]5ec20400
         // 004088b4: pop esi
         // 004088b5: retn b2 0x4
      [-]e814000000f6442408017407
         // 004088ec: call 0x408905
         // 004088f1: test b1 ss:[esp+0x8], b1 0x1
         // 004088f6: jz 0x4088ff
      [-]5ec20400
         // 00408901: pop esi
         // 00408902: retn b2 0x4
      [-]e814000000f6442408017407
         // 004090df: call 0x4090f8
         // 004090e4: test b1 ss:[esp+0x8], b1 0x1
         // 004090e9: jz 0x4090f2
      [-]5ec20400
         // 004090f4: pop esi
         // 004090f5: retn b2 0x4
      [-]e814000000f6442408017407
         // 0040912c: call 0x409145
         // 00409131: test b1 ss:[esp+0x8], b1 0x1
         // 00409136: jz 0x40913f
      [-]5ec20400
         // 00409141: pop esi
         // 00409142: retn b2 0x4
      [-]56577410
         // 0053a7af: push esi
         // 0053a7b0: push edi
         // 0053a7b1: jz 0x53a7c3
      [-]0f95c0e9b7000000
         // 0053a7bb: setnz b1 al
         // 0053a7be: jmp 0x53a87a
      [-]3bfb7476
         // 00409176: cmp edi, ebx
         // 00409178: jz 0x4091f0
      [-]57ffd63bc3a3
         // 00409185: push edi
         // 00409186: call esi
         // 00409188: cmp eax, ebx
         // 0040918a: mov ds:[0x4461e8], eax
      [-]57ffd63bc3a3
         // 00409196: push edi
         // 00409197: call esi
         // 00409199: cmp eax, ebx
         // 0040919b: mov ds:[0x4461ec], eax
      [-]57ffd63bc3a3
         // 004091a7: push edi
         // 004091a8: call esi
         // 004091aa: cmp eax, ebx
         // 004091ac: mov ds:[0x4461f0], eax
      [-]57ffd63bc3a3
         // 004091b8: push edi
         // 004091b9: call esi
         // 004091bb: cmp eax, ebx
         // 004091bd: mov ds:[0x4461f4], eax
      [-]57ffd63bc3a3
         // 004091c9: push edi
         // 004091ca: call esi
         // 004091cc: cmp eax, ebx
         // 004091ce: mov ds:[0x4461fc], eax
      [-]57ffd63bc3a3
         // 004091da: push edi
         // 004091db: call esi
         // 004091dd: cmp eax, ebx
         // 004091df: mov ds:[0x4461f8], eax
      [-]6a0158a3??
         // 004091e6: push 0x1
         // 004091e8: pop eax
         // 004091e9: mov ds:[0x446200], eax
      [-]5f5e5bc3
         // 00409220: pop edi
         // 00409221: pop esi
         // 00409222: pop ebx
         // 00409223: retn 
      [-]5657e821ffffff
         // 00409224: push esi
         // 00409225: push edi
         // 00409226: call 0x40914c
      [-]ff742410ff742410ff15
         // 0040922f: push ss:[esp+0x10]
         // 00409233: push ss:[esp+0x10]
         // 00409237: call ds:[0x4461f0]
      [-]f644241003752a
         // 0040923f: test b1 ss:[esp+0x10], b1 0x3
         // 00409244: jnz 0x409270
      [-]8b74240c
         // 00409246: mov esi, ss:[esp+0xc]
      [-]3946087e1b
         // 0040924c: cmp ds:[esi+0x8], eax
         // 0040924f: jle 0x40926c
      [-]39460c7e16
         // 00409251: cmp ds:[esi+0xc], eax
         // 00409254: jle 0x40926c
      [-]50ffd739067d09
         // 0040925c: push eax
         // 0040925d: call edi
         // 0040925f: cmp ds:[esi], eax
         // 00409261: jge 0x40926c
      [-]6a01ffd73946047c04
         // 00409263: push 0x1
         // 00409265: call edi
         // 00409267: cmp ds:[esi+0x4], eax
         // 0040926a: jl 0x409270
      [-]b8????????
         // 00409270: mov eax, 0x12340042
      [-]5f5ec20800
         // 00409275: pop edi
         // 00409276: pop esi
         // 00409277: retn b2 0x8
      [-]558bec83ec105356e85afeffff
         // 004092e5: push ebp
         // 004092e6: mov ebp, esp
         // 004092e8: sub esp, 0x10
         // 004092eb: push ebx
         // 004092ec: push esi
         // 004092ed: call 0x40914c
      [-]ff750cff7508ff15
         // 004092f6: push ss:[ebp+0xc]
         // 004092f9: push ss:[ebp+0x8]
         // 004092fc: call ds:[0x4461f8]
      [-]817d08????????7563
         // 00409304: cmp ss:[ebp+0x8], 0x12340042
         // 0040930b: jnz 0x409370
      [-]3bde745a
         // 00409312: cmp ebx, esi
         // 00409314: jz 0x409370
      [-]833b287255
         // 00409316: cmp ds:[ebx], 0x28
         // 00409319: jb 0x409370
      [-]8d45f05650566a30ff15
         // 0040931b: lea eax, ss:[ebp+0xfffffffffffffff0]
         // 0040931e: push esi
         // 0040931f: push eax
         // 00409320: push esi
         // 00409321: push 0x30
         // 00409323: call ds:[SystemParametersInfoA]
      [-]57897304897308568b35
         // 0040932d: push edi
         // 0040932e: mov ds:[ebx+0x4], esi
         // 00409331: mov ds:[ebx+0x8], esi
         // 00409334: push esi
         // 00409335: mov esi, ds:[GetSystemMetrics]
      [-]ffd66a0189430cffd68d7b148d75f0a5a5a5833b486a01a55e8943108973245f720f
         // 0040933b: call esi
         // 0040933d: push 0x1
         // 0040933f: mov ds:[ebx+0xc], eax
         // 00409342: call esi
         // 00409344: lea edi, ds:[ebx+0x14]
         // 00409347: lea esi, ss:[ebp+0xfffffffffffffff0]
         // 0040934a: movsdd 
         // 0040934b: movsdd 
         // 0040934c: movsdd 
         // 0040934d: cmp ds:[ebx], 0x48
         // 00409350: push 0x1
         // 00409352: movsdd 
         // 00409353: pop esi
         // 00409354: mov ds:[ebx+0x10], eax
         // 00409357: mov ds:[ebx+0x24], esi
         // 0040935a: pop edi
         // 0040935b: jb 0x40936c
      [-]83c32868
         // 0040935d: add ebx, 0x28
         // 00409360: push 0x41d05c
      [-]5e5bc9c20800
         // 00409372: pop esi
         // 00409373: pop ebx
         // 00409374: leave 
         // 00409375: retn b2 0x8
      [-]e80c00000083c61056ff15
         // 0053ab7d: call 0x53ab8e
         // 0053ab82: add esi, 0x10
         // 0053ab85: push esi
         // 0053ab86: call ds:[0x55c330]
      [-]578d7e1057ff15
         // 0053ab91: push edi
         // 0053ab92: lea edi, ds:[esi+0x10]
         // 0053ab95: push edi
         // 0053ab96: call ds:[0x55c2b4]
      [-]8b4e08e8
         // 0053ab9c: mov ecx, ds:[esi+0x8]
         // 0053ab9f: call 0x54b0a0
      [-]8366080083660c0057ff15
         // 0053aba4: and ds:[esi+0x8], 0x0
         // 0053aba8: and ds:[esi+0xc], 0x0
         // 0053abac: push edi
         // 0053abad: call ds:[0x55c2b8]
      [-]000083ec0c5356
         // 0040946e: sub esp, 0xc
         // 00409471: push ebx
         // 00409472: push esi
      [-]578965f08975ec8d5e1053ff15
         // 00409475: push edi
         // 00409476: mov ss:[ebp+0xfffffffffffffff0], esp
         // 00409479: mov ss:[ebp+0xffffffffffffffec], esi
         // 0040947c: lea ebx, ds:[esi+0x10]
         // 0040947f: push ebx
         // 00409480: call ds:[EnterCriticalSection]
      [-]837e0c007531
         // 00409486: cmp ds:[esi+0xc], 0x0
         // 0040948a: jnz 0x4094bd
      [-]ff368365fc008d4608ff760450e8
         // 0040948c: push ds:[esi]
         // 0040948e: and ss:[ebp+0xfffffffffffffffc], 0x0
         // 00409492: lea eax, ds:[esi+0x8]
         // 00409495: push ds:[esi+0x4]
         // 00409498: push eax
         // 00409499: call ?Create@CPlex@@SGPAU1@AAPAU1@II@Z
      [-]8b4e0449
         // 0040949e: mov ecx, ds:[esi+0x4]
         // 004094a1: dec ecx
      [-]8d4402047c0e
         // 004094a9: lea eax, ds:[edx+eax+0x4]
         // 004094ad: jl 0x4094bd
      [-]8b560c891089460c2b064975f3
         // 004094b0: mov edx, ds:[esi+0xc]
         // 004094b3: mov ds:[eax], edx
         // 004094b5: mov ds:[esi+0xc], eax
         // 004094b8: sub eax, ds:[esi]
         // 004094ba: dec ecx
         // 004094bb: jnz 0x4094b0
      [-]8b7e0c538b0789460cff15
         // 004094bd: mov edi, ds:[esi+0xc]
         // 004094c0: push ebx
         // 004094c1: mov eax, ds:[edi]
         // 004094c3: mov ds:[esi+0xc], eax
         // 004094c6: call ds:[LeaveCriticalSection]
      [-]5f5e64890d????????5bc9c3
         // 004094d1: pop edi
         // 004094d2: pop esi
         // 004094d3: mov fs:[0x0], ecx
         // 004094da: pop ebx
         // 004094db: leave 
         // 004094dc: retn 
      [-]56578b7c240c
         // 004094f3: push esi
         // 004094f4: push edi
         // 004094f5: mov edi, ss:[esp+0xc]
      [-]538d5e1053ff15
         // 004094ff: push ebx
         // 00409500: lea ebx, ds:[esi+0x10]
         // 00409503: push ebx
         // 00409504: call ds:[EnterCriticalSection]
      [-]8b460c538907897e0cff15
         // 0040950a: mov eax, ds:[esi+0xc]
         // 0040950d: push ebx
         // 0040950e: mov ds:[edi], eax
         // 00409510: mov ds:[esi+0xc], edi
         // 00409513: call ds:[LeaveCriticalSection]
      [-]5f5ec20400
         // 0040951a: pop edi
         // 0040951b: pop esi
         // 0040951c: retn b2 0x4
      [-]558bec6aff68
         // 00409fa6: push ebp
         // 00409fa7: mov ebp, esp
         // 00409fa9: push 0xffffffffffffffff
         // 00409fab: push stru_41D310.EnclosingLevel
      [-]64a1????????50648925????????83ec185356578b7508
         // 00409fb5: mov eax, fs:[0x0]
         // 00409fbb: push eax
         // 00409fbc: mov fs:[0x0], esp
         // 00409fc3: sub esp, 0x18
         // 00409fc6: push ebx
         // 00409fc7: push esi
         // 00409fc8: push edi
         // 00409fc9: mov esi, ss:[ebp+0x8]
      [-]0f84ac000000
         // 00409fce: jz 0x40a080
      [-]83f803753b
         // 00409fd9: cmp eax, 0x3
         // 00409fdc: jnz 0x40a019
      [-]0000598365fc0056e8
         // 00409fe5: pop ecx
         // 00409fe6: and ss:[ebp+0xfffffffffffffffc], 0x0
         // 00409fea: push esi
         // 00409feb: call 0x40ea6c
      [-]0000598945e4
         // 00409ff0: pop ecx
         // 00409ff1: mov ss:[ebp+0xffffffffffffffe4], eax
      [-]00005959
         // 00409fff: pop ecx
         // 0040a000: pop ecx
      [-]834dfcffe806000000837de400eb516a09e8
         // 0040a001: or ss:[ebp+0xfffffffffffffffc], 0xffffffffffffffff
         // 0040a005: call 0x40a010
         // 0040a00a: cmp ss:[ebp+0xffffffffffffffe4], 0x0
         // 0040a00e: jmp 0x40a061
         // 0040a010: push 0x9
         // 0040a012: call __unlock
      [-]000059c3
         // 0040a017: pop ecx
         // 0040a018: retn 
      [-]83f8027553
         // 0040a019: cmp eax, 0x2
         // 0040a01c: jnz 0x40a071
      [-]6a09e800
         // 0040a01e: push 0x9
         // 0040a020: call 0x40de25
      [-]59c745fc????????8d45e0508d45d85056e8
         // 0040a025: pop ecx
         // 0040a026: mov ss:[ebp+0xfffffffffffffffc], 0x1
         // 0040a02d: lea eax, ss:[ebp+0xffffffffffffffe0]
         // 0040a030: push eax
         // 0040a031: lea eax, ss:[ebp+0xffffffffffffffd8]
         // 0040a034: push eax
         // 0040a035: push esi
         // 0040a036: call 0x40f7c7
      [-]000083c40c8945dc
         // 0040a03b: add esp, 0xc
         // 0040a03e: mov ss:[ebp+0xffffffffffffffdc], eax
      [-]50ff75e0ff75d8e8
         // 0040a045: push eax
         // 0040a046: push ss:[ebp+0xffffffffffffffe0]
         // 0040a049: push ss:[ebp+0xffffffffffffffd8]
         // 0040a04c: call 0x40f81e
      [-]000083c40c
         // 0040a051: add esp, 0xc
      [-]834dfcffe80b000000837ddc00
         // 0040a054: or ss:[ebp+0xfffffffffffffffc], 0xffffffffffffffff
         // 0040a058: call 0x40a068
         // 0040a05d: cmp ss:[ebp+0xffffffffffffffdc], 0x0
      [-]000059c3
         // 0040a06f: pop ecx
         // 0040a070: retn 
      [-]6a00ff35
         // 0040a072: push 0x0
         // 0040a074: push ds:[0x447988]
      [-]8b4df064890d????????5f5e5bc9c3
         // 0040a080: mov ecx, ss:[ebp+0xfffffffffffffff0]
         // 0040a083: mov fs:[0x0], ecx
         // 0040a08a: pop edi
         // 0040a08b: pop esi
         // 0040a08c: pop ebx
         // 0040a08d: leave 
         // 0040a08e: retn 
      [-]558bec6aff68
         // 0040a0cd: push ebp
         // 0040a0ce: mov ebp, esp
         // 0040a0d0: push 0xffffffffffffffff
         // 0040a0d2: push stru_41D328.EnclosingLevel
      [-]64a1????????50648925????????83ec0c535657a1
         // 0040a0dc: mov eax, fs:[0x0]
         // 0040a0e2: push eax
         // 0040a0e3: mov fs:[0x0], esp
         // 0040a0ea: sub esp, 0xc
         // 0040a0ed: push ebx
         // 0040a0ee: push esi
         // 0040a0ef: push edi
         // 0040a0f0: mov eax, ds:[0x44798c]
      [-]83f8037543
         // 0040a0f5: cmp eax, 0x3
         // 0040a0f8: jnz 0x40a13d
      [-]8b75083b35
         // 0040a0fa: mov esi, ss:[ebp+0x8]
         // 0040a0fd: cmp esi, ds:[0x44797c]
      [-]0f8793000000
         // 0040a103: ja 0x40a19c
      [-]0000598365fc0056e8
         // 0040a110: pop ecx
         // 0040a111: and ss:[ebp+0xfffffffffffffffc], 0x0
         // 0040a115: push esi
         // 0040a116: call 0x40edc0
      [-]0000598945e4834dfcffe80c0000008b45e4
         // 0040a11b: pop ecx
         // 0040a11c: mov ss:[ebp+0xffffffffffffffe4], eax
         // 0040a11f: or ss:[ebp+0xfffffffffffffffc], 0xffffffffffffffff
         // 0040a123: call 0x40a134
         // 0040a128: mov eax, ss:[ebp+0xffffffffffffffe4]
      [-]000059c3
         // 0040a13b: pop ecx
         // 0040a13c: retn 
      [-]83f802755a
         // 0040a13d: cmp eax, 0x2
         // 0040a140: jnz 0x40a19c
      [-]8d700f83e6f0eb03
         // 0040a149: lea esi, ds:[eax+0xf]
         // 0040a14c: and esi, 0xfffffffffffffff0
         // 0040a14f: jmp 0x40a154
      [-]8975083b35
         // 0040a154: mov ss:[ebp+0x8], esi
         // 0040a157: cmp esi, ds:[0x425434]
      [-]000059c745fc????????
         // 0040a166: pop ecx
         // 0040a167: mov ss:[ebp+0xfffffffffffffffc], 0x1
      [-]c1e80450e8
         // 0040a170: shr eax, b1 0x4
         // 0040a173: push eax
         // 0040a174: call 0x40f863
      [-]0000598945e4834dfcffe80d0000008b45e4
         // 0040a179: pop ecx
         // 0040a17a: mov ss:[ebp+0xffffffffffffffe4], eax
         // 0040a17d: or ss:[ebp+0xfffffffffffffffc], 0xffffffffffffffff
         // 0040a181: call 0x40a193
         // 0040a186: mov eax, ss:[ebp+0xffffffffffffffe4]
      [-]000059c3
         // 0040a19a: pop ecx
         // 0040a19b: retn 
      [-]83c00f24f050
         // 0040a1a6: add eax, 0xf
         // 0040a1a9: and b1 al, b1 0xf0
         // 0040a1ab: push eax
      [-]6a00ff35
         // 0040a1ac: push 0x0
         // 0040a1ae: push ds:[0x447988]
      [-]8b4df064890d????????5f5e5bc9c3
         // 0040a1ba: mov ecx, ss:[ebp+0xfffffffffffffff0]
         // 0040a1bd: mov fs:[0x0], ecx
         // 0040a1c4: pop edi
         // 0040a1c5: pop esi
         // 0040a1c6: pop ebx
         // 0040a1c7: leave 
         // 0040a1c8: retn 
      [-]558bec6aff68
         // 0040a704: push ebp
         // 0040a705: mov ebp, esp
         // 0040a707: push 0xffffffffffffffff
         // 0040a709: push stru_41D348.EnclosingLevel
      [-]64a1????????50648925????????83ec285356578b5d08
         // 0040a713: mov eax, fs:[0x0]
         // 0040a719: push eax
         // 0040a71a: mov fs:[0x0], esp
         // 0040a721: sub esp, 0x28
         // 0040a724: push ebx
         // 0040a725: push esi
         // 0040a726: push edi
         // 0040a727: mov ebx, ss:[ebp+0x8]
      [-]3bdf750e
         // 0040a72c: cmp ebx, edi
         // 0040a72e: jnz 0x40a73e
      [-]ff750ce8
         // 0040a730: push ss:[ebp+0xc]
         // 0040a733: call _malloc
      [-]ffff59e9e6020000
         // 0040a738: pop ecx
         // 0040a739: jmp 0x40aa24
      [-]8b750c3bf7750c
         // 0040a73e: mov esi, ss:[ebp+0xc]
         // 0040a741: cmp esi, edi
         // 0040a743: jnz 0x40a751
      [-]ffff59e9d1020000
         // 0040a74b: pop ecx
         // 0040a74c: jmp 0x40aa22
      [-]83f8030f8539010000
         // 0040a756: cmp eax, 0x3
         // 0040a759: jnz 0x40a898
      [-]897ddc83fee00f87f1000000
         // 0040a75f: mov ss:[ebp+0xffffffffffffffdc], edi
         // 0040a762: cmp esi, 0xffffffffffffffe0
         // 0040a765: ja 0x40a85c
      [-]000059897dfc53e8
         // 0040a772: pop ecx
         // 0040a773: mov ss:[ebp+0xfffffffffffffffc], edi
         // 0040a776: push ebx
         // 0040a777: call 0x40ea6c
      [-]0000598945d83bc70f84a4000000
         // 0040a77c: pop ecx
         // 0040a77d: mov ss:[ebp+0xffffffffffffffd8], eax
         // 0040a780: cmp eax, edi
         // 0040a782: jz 0x40a82c
      [-]565350e8
         // 0040a790: push esi
         // 0040a791: push ebx
         // 0040a792: push eax
         // 0040a793: call 0x40f275
      [-]000083c40c
         // 0040a798: add esp, 0xc
      [-]895ddceb38
         // 0040a79f: mov ss:[ebp+0xffffffffffffffdc], ebx
         // 0040a7a2: jmp 0x40a7dc
      [-]0000598945dc3bc7742a
         // 0040a7aa: pop ecx
         // 0040a7ab: mov ss:[ebp+0xffffffffffffffdc], eax
         // 0040a7ae: cmp eax, edi
         // 0040a7b0: jz 0x40a7dc
      [-]8b43fc488945e03bc67202
         // 0040a7b2: mov eax, ds:[ebx+0xfffffffffffffffc]
         // 0040a7b5: dec eax
         // 0040a7b6: mov ss:[ebp+0xffffffffffffffe0], eax
         // 0040a7b9: cmp eax, esi
         // 0040a7bb: jb 0x40a7bf
      [-]5053ff75dce8
         // 0040a7bf: push eax
         // 0040a7c0: push ebx
         // 0040a7c1: push ss:[ebp+0xffffffffffffffdc]
         // 0040a7c4: call 0x40b1e0
      [-]000053e8
         // 0040a7c9: push ebx
         // 0040a7ca: call 0x40ea6c
      [-]00008945d85350e8
         // 0040a7cf: mov ss:[ebp+0xffffffffffffffd8], eax
         // 0040a7d2: push ebx
         // 0040a7d3: push eax
         // 0040a7d4: call 0x40ea97
      [-]000083c418
         // 0040a7d9: add esp, 0x18
      [-]397ddc754b
         // 0040a7dc: cmp ss:[ebp+0xffffffffffffffdc], edi
         // 0040a7df: jnz 0x40a82c
      [-]3bf77506
         // 0040a7e1: cmp esi, edi
         // 0040a7e3: jnz 0x40a7eb
      [-]6a015e89750c
         // 0040a7e5: push 0x1
         // 0040a7e7: pop esi
         // 0040a7e8: mov ss:[ebp+0xc], esi
      [-]83c60f83e6f089750c5657ff35
         // 0040a7eb: add esi, 0xf
         // 0040a7ee: and esi, 0xfffffffffffffff0
         // 0040a7f1: mov ss:[ebp+0xc], esi
         // 0040a7f4: push esi
         // 0040a7f5: push edi
         // 0040a7f6: push ds:[0x447988]
      [-]8945dc3bc77423
         // 0040a802: mov ss:[ebp+0xffffffffffffffdc], eax
         // 0040a805: cmp eax, edi
         // 0040a807: jz 0x40a82c
      [-]8b43fc488945e03bc67202
         // 0040a809: mov eax, ds:[ebx+0xfffffffffffffffc]
         // 0040a80c: dec eax
         // 0040a80d: mov ss:[ebp+0xffffffffffffffe0], eax
         // 0040a810: cmp eax, esi
         // 0040a812: jb 0x40a816
      [-]5053ff75dce8
         // 0040a816: push eax
         // 0040a817: push ebx
         // 0040a818: push ss:[ebp+0xffffffffffffffdc]
         // 0040a81b: call 0x40b1e0
      [-]000053ff75d8e8
         // 0040a820: push ebx
         // 0040a821: push ss:[ebp+0xffffffffffffffd8]
         // 0040a824: call 0x40ea97
      [-]000083c414
         // 0040a829: add esp, 0x14
      [-]834dfcffe85a000000397dd87522
         // 0040a82c: or ss:[ebp+0xfffffffffffffffc], 0xffffffffffffffff
         // 0040a830: call 0x40a88f
         // 0040a835: cmp ss:[ebp+0xffffffffffffffd8], edi
         // 0040a838: jnz 0x40a85c
      [-]000059c3
         // 0040a896: pop ecx
         // 0040a897: retn 
      [-]83f8020f8547010000
         // 0040a898: cmp eax, 0x2
         // 0040a89b: jnz 0x40a9e8
      [-]83fee07712
         // 0040a8a1: cmp esi, 0xffffffffffffffe0
         // 0040a8a4: ja 0x40a8b8
      [-]3bf77608
         // 0040a8a6: cmp esi, edi
         // 0040a8a8: jbe 0x40a8b2
      [-]83c60f83e6f0eb03
         // 0040a8aa: add esi, 0xf
         // 0040a8ad: and esi, 0xfffffffffffffff0
         // 0040a8b0: jmp 0x40a8b5
      [-]897ddc83fee00f87f3000000
         // 0040a8b8: mov ss:[ebp+0xffffffffffffffdc], edi
         // 0040a8bb: cmp esi, 0xffffffffffffffe0
         // 0040a8be: ja 0x40a9b7
      [-]000059c745fc????????8d45d4508d45c85053e8
         // 0040a8cb: pop ecx
         // 0040a8cc: mov ss:[ebp+0xfffffffffffffffc], 0x1
         // 0040a8d3: lea eax, ss:[ebp+0xffffffffffffffd4]
         // 0040a8d6: push eax
         // 0040a8d7: lea eax, ss:[ebp+0xffffffffffffffc8]
         // 0040a8da: push eax
         // 0040a8db: push ebx
         // 0040a8dc: call 0x40f7c7
      [-]000083c40c
         // 0040a8e1: add esp, 0xc
      [-]0f84aa000000
         // 0040a8eb: jz 0x40a99b
      [-]c1eb045357ff75d4ff75c8e8
         // 0053d766: shr ebx, b1 0x4
         // 0053d769: push ebx
         // 0053d76a: push edi
         // 0053d76b: push ss:[ebp+0xffffffffffffffd4]
         // 0053d76e: push ss:[ebp+0xffffffffffffffc8]
         // 0053d771: call 0x544770
      [-]000083c410
         // 0053d776: add esp, 0x10
      [-]8b45088945dceb38
         // 0040a912: mov eax, ss:[ebp+0x8]
         // 0040a915: mov ss:[ebp+0xffffffffffffffdc], eax
         // 0040a918: jmp 0x40a952
      [-]0000598945dc
         // 0040a920: pop ecx
         // 0040a921: mov ss:[ebp+0xffffffffffffffdc], eax
      [-]0fb607c1e0048945cc3bc67202
         // 0040a928: movzx eax, b1 ds:[edi]
         // 0040a92b: shl eax, b1 0x4
         // 0040a92e: mov ss:[ebp+0xffffffffffffffcc], eax
         // 0040a931: cmp eax, esi
         // 0040a933: jb 0x40a937
      [-]50ff7508ff75dce8
         // 0040a937: push eax
         // 0040a938: push ss:[ebp+0x8]
         // 0040a93b: push ss:[ebp+0xffffffffffffffdc]
         // 0040a93e: call 0x40b1e0
      [-]000057ff75d4ff75c8e8
         // 0040a943: push edi
         // 0040a944: push ss:[ebp+0xffffffffffffffd4]
         // 0040a947: push ss:[ebp+0xffffffffffffffc8]
         // 0040a94a: call 0x40f81e
      [-]000083c418
         // 0040a94f: add esp, 0x18
      [-]837ddc007553
         // 0040a955: cmp ss:[ebp+0xffffffffffffffdc], 0x0
         // 0040a959: jnz 0x40a9ae
      [-]566a00ff35
         // 0040a95b: push esi
         // 0040a95c: push 0x0
         // 0040a95e: push ds:[0x447988]
      [-]0fb607c1e0048945cc3bc67202
         // 0040a971: movzx eax, b1 ds:[edi]
         // 0040a974: shl eax, b1 0x4
         // 0040a977: mov ss:[ebp+0xffffffffffffffcc], eax
         // 0040a97a: cmp eax, esi
         // 0040a97c: jb 0x40a980
      [-]5053ff75dce8
         // 0040a980: push eax
         // 0040a981: push ebx
         // 0040a982: push ss:[ebp+0xffffffffffffffdc]
         // 0040a985: call 0x40b1e0
      [-]000057ff75d4ff75c8e8
         // 0040a98a: push edi
         // 0040a98b: push ss:[ebp+0xffffffffffffffd4]
         // 0040a98e: push ss:[ebp+0xffffffffffffffc8]
         // 0040a991: call 0x40f81e
      [-]000083c418eb13
         // 0040a996: add esp, 0x18
         // 0040a999: jmp 0x40a9ae
      [-]56536a00ff35
         // 0040a99b: push esi
         // 0040a99c: push ebx
         // 0040a99d: push 0x0
         // 0040a99f: push ds:[0x447988]
      [-]834dfcffe826000000
         // 0040a9ae: or ss:[ebp+0xfffffffffffffffc], 0xffffffffffffffff
         // 0040a9b2: call 0x40a9dd
      [-]83fee0771c
         // 0040a9ea: cmp esi, 0xffffffffffffffe0
         // 0040a9ed: ja 0x40aa0b
      [-]3bf77503
         // 0040a9ef: cmp esi, edi
         // 0040a9f1: jnz 0x40a9f6
      [-]83c60f83e6f0565357ff35
         // 0040a9f6: add esi, 0xf
         // 0040a9f9: and esi, 0xfffffffffffffff0
         // 0040a9fc: push esi
         // 0040a9fd: push ebx
         // 0040a9fe: push edi
         // 0040a9ff: push ds:[0x447988]
      [-]3bc77515
         // 0040aa0b: cmp eax, edi
         // 0040aa0d: jnz 0x40aa24
      [-]8b4df064890d????????5f5e5bc9c3
         // 0040aa24: mov ecx, ss:[ebp+0xfffffffffffffff0]
         // 0040aa27: mov fs:[0x0], ecx
         // 0040aa2e: pop edi
         // 0040aa2f: pop esi
         // 0040aa30: pop ebx
         // 0040aa31: leave 
         // 0040aa32: retn 
      [-]558bec6aff68
         // 0040b8c7: push ebp
         // 0040b8c8: mov ebp, esp
         // 0040b8ca: push 0xffffffffffffffff
         // 0040b8cc: push stru_41D380.EnclosingLevel
      [-]64a1????????50648925????????83ec1c5356578b750c83fee07607
         // 0040b8d6: mov eax, fs:[0x0]
         // 0040b8dc: push eax
         // 0040b8dd: mov fs:[0x0], esp
         // 0040b8e4: sub esp, 0x1c
         // 0040b8e7: push ebx
         // 0040b8e8: push esi
         // 0040b8e9: push edi
         // 0040b8ea: mov esi, ss:[ebp+0xc]
         // 0040b8ed: cmp esi, 0xffffffffffffffe0
         // 0040b8f0: jbe 0x40b8f9
      [-]e923010000
         // 0040b8f4: jmp 0x40ba1c
      [-]83f803755f
         // 0040b8fe: cmp eax, 0x3
         // 0040b901: jnz 0x40b962
      [-]0000598365fc008b7d0857e8
         // 0040b90a: pop ecx
         // 0040b90b: and ss:[ebp+0xfffffffffffffffc], 0x0
         // 0040b90f: mov edi, ss:[ebp+0x8]
         // 0040b912: push edi
         // 0040b913: call 0x40ea6c
      [-]0000598945e0
         // 0040b918: pop ecx
         // 0040b919: mov ss:[ebp+0xffffffffffffffe0], eax
      [-]8365e4003b35
         // 0040b920: and ss:[ebp+0xffffffffffffffe4], 0x0
         // 0040b924: cmp esi, ds:[0x44797c]
      [-]565750e8
         // 0040b92c: push esi
         // 0040b92d: push edi
         // 0040b92e: push eax
         // 0040b92f: call 0x40f275
      [-]000083c40c
         // 0040b934: add esp, 0xc
      [-]834dfcffe812000000837de0000f85c8000000
         // 0040b93e: or ss:[ebp+0xfffffffffffffffc], 0xffffffffffffffff
         // 0040b942: call 0x40b959
         // 0040b947: cmp ss:[ebp+0xffffffffffffffe0], 0x0
         // 0040b94b: jnz 0x40ba19
      [-]000059c3
         // 0040b960: pop ecx
         // 0040b961: retn 
      [-]83f8020f858c000000
         // 0040b962: cmp eax, 0x2
         // 0040b965: jnz 0x40b9f7
      [-]83c60f83e6f089750c6a09e8
         // 0040b972: add esi, 0xf
         // 0040b975: and esi, 0xfffffffffffffff0
         // 0040b978: mov ss:[ebp+0xc], esi
         // 0040b97b: push 0x9
         // 0040b97d: call 0x40de25
      [-]000059c745fc????????8d45dc508d45d4508b7d0857e8
         // 0040b982: pop ecx
         // 0040b983: mov ss:[ebp+0xfffffffffffffffc], 0x1
         // 0040b98a: lea eax, ss:[ebp+0xffffffffffffffdc]
         // 0040b98d: push eax
         // 0040b98e: lea eax, ss:[ebp+0xffffffffffffffd4]
         // 0040b991: push eax
         // 0040b992: mov edi, ss:[ebp+0x8]
         // 0040b995: push edi
         // 0040b996: call 0x40f7c7
      [-]000083c40c8945d8
         // 0040b99b: add esp, 0xc
         // 0040b99e: mov ss:[ebp+0xffffffffffffffd8], eax
      [-]8365e4003b35
         // 0040b9a5: and ss:[ebp+0xffffffffffffffe4], 0x0
         // 0040b9a9: cmp esi, ds:[0x425434]
      [-]c1ee045650ff75dcff75d4e8
         // 0040b9b1: shr esi, b1 0x4
         // 0040b9b4: push esi
         // 0040b9b5: push eax
         // 0040b9b6: push ss:[ebp+0xffffffffffffffdc]
         // 0040b9b9: push ss:[ebp+0xffffffffffffffd4]
         // 0040b9bc: call 0x40fb8f
      [-]000083c410
         // 0040b9c1: add esp, 0x10
      [-]6aff8d45f050e8
         // 0040b9cb: push 0xffffffffffffffff
         // 0040b9cd: lea eax, ss:[ebp+0xfffffffffffffff0]
         // 0040b9d0: push eax
         // 0040b9d1: call 0x40a4f2
      [-]ffff5959eb3f
         // 0040b9d6: pop ecx
         // 0040b9d7: pop ecx
         // 0040b9d8: jmp 0x40ba19
      [-]834dfcffe80b000000837dd8007530
         // 0040b9da: or ss:[ebp+0xfffffffffffffffc], 0xffffffffffffffff
         // 0040b9de: call 0x40b9ee
         // 0040b9e3: cmp ss:[ebp+0xffffffffffffffd8], 0x0
         // 0040b9e7: jnz 0x40ba19
      [-]000059c3
         // 0040b9f5: pop ecx
         // 0040b9f6: retn 
      [-]83c60f83e6f0
         // 0040b9fe: add esi, 0xf
         // 0040ba01: and esi, 0xfffffffffffffff0
      [-]56ff75086a10ff35
         // 0040ba04: push esi
         // 0040ba05: push ss:[ebp+0x8]
         // 0040ba08: push 0x10
         // 0040ba0a: push ds:[0x447988]
      [-]8b4df064890d????????5f5e5bc9c3
         // 0040ba1c: mov ecx, ss:[ebp+0xfffffffffffffff0]
         // 0040ba1f: mov fs:[0x0], ecx
         // 0040ba26: pop edi
         // 0040ba27: pop esi
         // 0040ba28: pop ebx
         // 0040ba29: leave 
         // 0040ba2a: retn 
      [-]558bec6aff68
         // 0040ba2b: push ebp
         // 0040ba2c: mov ebp, esp
         // 0040ba2e: push 0xffffffffffffffff
         // 0040ba30: push stru_41D398.EnclosingLevel
      [-]64a1????????50648925????????83ec1c535657a1
         // 0040ba3a: mov eax, fs:[0x0]
         // 0040ba40: push eax
         // 0040ba41: mov fs:[0x0], esp
         // 0040ba48: sub esp, 0x1c
         // 0040ba4b: push ebx
         // 0040ba4c: push esi
         // 0040ba4d: push edi
         // 0040ba4e: mov eax, ds:[0x44798c]
      [-]83f8037546
         // 0040ba53: cmp eax, 0x3
         // 0040ba56: jnz 0x40ba9e
      [-]0000598365fc008b750856e8
         // 0040ba5f: pop ecx
         // 0040ba60: and ss:[ebp+0xfffffffffffffffc], 0x0
         // 0040ba64: mov esi, ss:[ebp+0x8]
         // 0040ba67: push esi
         // 0040ba68: call 0x40ea6c
      [-]0000598945e4
         // 0040ba6d: pop ecx
         // 0040ba6e: mov ss:[ebp+0xffffffffffffffe4], eax
      [-]8b76fc83ee098975e0eb03
         // 0040ba75: mov esi, ds:[esi+0xfffffffffffffffc]
         // 0040ba78: sub esi, 0x9
         // 0040ba7b: mov ss:[ebp+0xffffffffffffffe0], esi
         // 0040ba7e: jmp 0x40ba83
      [-]834dfcffe809000000837de400eb55
         // 0040ba83: or ss:[ebp+0xfffffffffffffffc], 0xffffffffffffffff
         // 0040ba87: call 0x40ba95
         // 0040ba8c: cmp ss:[ebp+0xffffffffffffffe4], 0x0
         // 0040ba90: jmp 0x40bae7
      [-]000059c3
         // 0040ba9c: pop ecx
         // 0040ba9d: retn 
      [-]83f8027546
         // 0040ba9e: cmp eax, 0x2
         // 0040baa1: jnz 0x40bae9
      [-]000059c745fc????????8d45dc508d45d450ff7508e8
         // 0040baaa: pop ecx
         // 0040baab: mov ss:[ebp+0xfffffffffffffffc], 0x1
         // 0040bab2: lea eax, ss:[ebp+0xffffffffffffffdc]
         // 0040bab5: push eax
         // 0040bab6: lea eax, ss:[ebp+0xffffffffffffffd4]
         // 0040bab9: push eax
         // 0040baba: push ss:[ebp+0x8]
         // 0040babd: call 0x40f7c7
      [-]000083c40c8945d8
         // 0040bac2: add esp, 0xc
         // 0040bac5: mov ss:[ebp+0xffffffffffffffd8], eax
      [-]0fb630c1e6048975e0eb03
         // 0040bacc: movzx esi, b1 ds:[eax]
         // 0040bacf: shl esi, b1 0x4
         // 0040bad2: mov ss:[ebp+0xffffffffffffffe0], esi
         // 0040bad5: jmp 0x40bada
      [-]834dfcffe82d000000837dd800
         // 0040bada: or ss:[ebp+0xfffffffffffffffc], 0xffffffffffffffff
         // 0040bade: call 0x40bb10
         // 0040bae3: cmp ss:[ebp+0xffffffffffffffd8], 0x0
      [-]000059c3
         // 0040bb17: pop ecx
         // 0040bb18: retn 
      [-]568b7424086a00832600ff15
         // 0040cc80: push esi
         // 0040cc81: mov esi, ss:[esp+0x8]
         // 0040cc85: push 0x0
         // 0040cc87: and ds:[esi], 0x0
         // 0040cc8a: call ds:[GetModuleHandleA]
      [-]6681384d5a7514
         // 0040cc90: cmp b2 ds:[eax], b2 0x5a4d
         // 0040cc95: jnz 0x40ccab
      [-]03c18a481a880e8a401b884601
         // 0040cc9e: add eax, ecx
         // 0040cca0: mov b1 cl, b1 ds:[eax+0x1a]
         // 0040cca3: mov b1 ds:[esi], b1 cl
         // 0040cca5: mov b1 al, b1 ds:[eax+0x1b]
         // 0040cca8: mov b1 ds:[esi+0x1], b1 al
      [-]558becb8????????e8
         // 0040ccad: push ebp
         // 0040ccae: mov ebp, esp
         // 0040ccb0: mov eax, 0x122c
         // 0040ccb5: call __alloca_probe
      [-]ffff8d85????????5350c785????????????????ff15
         // 0040ccba: lea eax, ss:[ebp+0xffffffffffffff68]
         // 0040ccc0: push ebx
         // 0040ccc1: push eax
         // 0040ccc2: mov ss:[ebp+0xffffffffffffff68], 0x94
         // 0040cccc: call ds:[GetVersionExA]
      [-]83bd????????027511
         // 0040ccd6: cmp ss:[ebp+0xffffffffffffff78], 0x2
         // 0040ccdd: jnz 0x40ccf0
      [-]83bd????????057208
         // 0040ccdf: cmp ss:[ebp+0xffffffffffffff6c], 0x5
         // 0040cce6: jb 0x40ccf0
      [-]6a0158e902010000
         // 0040cce8: push 0x1
         // 0040ccea: pop eax
         // 0040cceb: jmp 0x40cdf2
      [-]8d85????????68????????5068
         // 0040ccf0: lea eax, ss:[ebp+0xffffffffffffedd4]
         // 0040ccf6: push 0x1090
         // 0040ccfb: push eax
         // 0040ccfc: push 0x41d4ec
      [-]0f84d0000000
         // 0040cd09: jz 0x40cddf
      [-]8d8d????????389dd4edffff7413
         // 0040cd11: lea ecx, ss:[ebp+0xffffffffffffedd4]
         // 0040cd17: cmp b1 ss:[ebp+0xffffffffffffedd4], b1 bl
         // 0040cd1d: jz 0x40cd32
      [-]8a013c617c08
         // 0040cd1f: mov b1 al, b1 ds:[ecx]
         // 0040cd21: cmp b1 al, b1 0x61
         // 0040cd23: jl 0x40cd2d
      [-]3c7a7f04
         // 0040cd25: cmp b1 al, b1 0x7a
         // 0040cd27: jg 0x40cd2d
      [-]2c208801
         // 0040cd29: sub b1 al, b1 0x20
         // 0040cd2b: mov b1 ds:[ecx], b1 al
      [-]41381975ed
         // 0040cd2d: inc ecx
         // 0040cd2e: cmp b1 ds:[ecx], b1 bl
         // 0040cd30: jnz 0x40cd1f
      [-]8d85????????6a165068
         // 0040cd32: lea eax, ss:[ebp+0xffffffffffffedd4]
         // 0040cd38: push 0x16
         // 0040cd3a: push eax
         // 0040cd3b: push 0x41d4d4
      [-]ffff83c40c
         // 0040cd45: add esp, 0xc
      [-]8d85????????eb49
         // 0040cd4c: lea eax, ss:[ebp+0xffffffffffffedd4]
         // 0040cd52: jmp 0x40cd9d
      [-]8d85????????68????????5053ff15
         // 0040cd54: lea eax, ss:[ebp+0xfffffffffffffe64]
         // 0040cd5a: push 0x104
         // 0040cd5f: push eax
         // 0040cd60: push ebx
         // 0040cd61: call ds:[GetModuleFileNameA]
      [-]389d64feffff8d8d????????7413
         // 0040cd67: cmp b1 ss:[ebp+0xfffffffffffffe64], b1 bl
         // 0040cd6d: lea ecx, ss:[ebp+0xfffffffffffffe64]
         // 0040cd73: jz 0x40cd88
      [-]8a013c617c08
         // 0040cd75: mov b1 al, b1 ds:[ecx]
         // 0040cd77: cmp b1 al, b1 0x61
         // 0040cd79: jl 0x40cd83
      [-]3c7a7f04
         // 0040cd7b: cmp b1 al, b1 0x7a
         // 0040cd7d: jg 0x40cd83
      [-]2c208801
         // 0040cd7f: sub b1 al, b1 0x20
         // 0040cd81: mov b1 ds:[ecx], b1 al
      [-]41381975ed
         // 0040cd83: inc ecx
         // 0040cd84: cmp b1 ds:[ecx], b1 bl
         // 0040cd86: jnz 0x40cd75
      [-]8d85????????508d85????????50e8
         // 0040cd88: lea eax, ss:[ebp+0xfffffffffffffe64]
         // 0040cd8e: push eax
         // 0040cd8f: lea eax, ss:[ebp+0xffffffffffffedd4]
         // 0040cd95: push eax
         // 0040cd96: call 0x40ae30
      [-]ffff5959
         // 0040cd9b: pop ecx
         // 0040cd9c: pop ecx
      [-]3bc3743e
         // 0040cd9d: cmp eax, ebx
         // 0040cd9f: jz 0x40cddf
      [-]6a2c50e8
         // 0040cda1: push 0x2c
         // 0040cda3: push eax
         // 0040cda4: call 0x409a90
      [-]ccffff593bc3597430
         // 0040cda9: pop ecx
         // 0040cdaa: cmp eax, ebx
         // 0040cdac: pop ecx
         // 0040cdad: jz 0x40cddf
      [-]3818740e
         // 0040cdb2: cmp b1 ds:[eax], b1 bl
         // 0040cdb4: jz 0x40cdc4
      [-]80393b7504
         // 0040cdb6: cmp b1 ds:[ecx], b1 0x3b
         // 0040cdb9: jnz 0x40cdbf
      [-]8819eb01
         // 0040cdbb: mov b1 ds:[ecx], b1 bl
         // 0040cdbd: jmp 0x40cdc0
      [-]381975f2
         // 0040cdc0: cmp b1 ds:[ecx], b1 bl
         // 0040cdc2: jnz 0x40cdb6
      [-]6a0a5350e8
         // 0040cdc4: push 0xa
         // 0040cdc6: push ebx
         // 0040cdc7: push eax
         // 0040cdc8: call _strtol
      [-]83c40c83f802741d
         // 0040cdcd: add esp, 0xc
         // 0040cdd0: cmp eax, 0x2
         // 0040cdd3: jz 0x40cdf2
      [-]83f8037418
         // 0040cdd5: cmp eax, 0x3
         // 0040cdd8: jz 0x40cdf2
      [-]83f8017413
         // 0040cdda: cmp eax, 0x1
         // 0040cddd: jz 0x40cdf2
      [-]8d45fc50e898feffff807dfc06591bc0
         // 0040cddf: lea eax, ss:[ebp+0xfffffffffffffffc]
         // 0040cde2: push eax
         // 0040cde3: call 0x40cc80
         // 0040cde8: cmp b1 ss:[ebp+0xfffffffffffffffc], b1 0x6
         // 0040cdec: pop ecx
         // 0040cded: sbb eax, eax
      [-]6a003944240868????????0f94c050ff15
         // 0053fd39: push 0x0
         // 0053fd3b: cmp ss:[esp+0x8], eax
         // 0053fd3f: push 0x1000
         // 0053fd44: setz b1 al
         // 0053fd47: push eax
         // 0053fd48: call ds:[0x55c254]
      [-]e893feffff83f803a3
         // 0040ce15: call 0x40ccad
         // 0040ce1a: cmp eax, 0x3
         // 0040ce1d: mov ds:[0x44798c], eax
      [-]68????????e8
         // 0040ce24: push 0x3f8
         // 0040ce29: call 0x40ea24
      [-]000059eb0a
         // 0040ce2e: pop ecx
         // 0040ce2f: jmp 0x40ce3b
      [-]83f8027518
         // 0040ce31: cmp eax, 0x2
         // 0040ce34: jnz 0x40ce4e
      [-]6a0158c3
         // 0040ce4e: push 0x1
         // 0040ce50: pop eax
         // 0040ce51: retn 
      [-]558bec81ec????????8b5508
         // 0053fdcd: push ebp
         // 0053fdce: mov ebp, esp
         // 0053fdd0: sub esp, 0x1a4
         // 0053fdd6: mov edx, ss:[ebp+0x8]
      [-]3b10740b
         // 0040ce9e: cmp edx, ds:[eax]
         // 0040cea0: jz 0x40cead
      [-]83c008413d
         // 0040cea2: add eax, 0x8
         // 0040cea5: inc ecx
         // 0040cea6: cmp eax, 0x422ef0
      [-]c1e6033b96
         // 0053fdf2: shl esi, b1 0x3
         // 0053fdf5: cmp edx, ds:[esi+0x5ae7e0]
      [-]0f851c010000
         // 0053fdfb: jnz 0x53ff1d
      [-]83f8010f84e8000000
         // 0040cec4: cmp eax, 0x1
         // 0040cec7: jz 0x40cfb5
      [-]010f84d7000000
         // 0040ced8: jz 0x40cfb5
      [-]81fa????????0f84f1000000
         // 0040cede: cmp edx, 0xfc
         // 0040cee4: jz 0x40cfdb
      [-]8d85????????68????????506a00ff15
         // 0040ceea: lea eax, ss:[ebp+0xfffffffffffffe5c]
         // 0040cef0: push 0x104
         // 0040cef5: push eax
         // 0040cef6: push 0x0
         // 0040cef8: call ds:[GetModuleFileNameA]
      [-]8d85????????68
         // 0040cf02: lea eax, ss:[ebp+0xfffffffffffffe5c]
         // 0040cf08: push 0x41d7dc
      [-]00005959
         // 0040cf13: pop ecx
         // 0040cf14: pop ecx
      [-]8d85????????57508dbd????????e8
         // 0040cf15: lea eax, ss:[ebp+0xfffffffffffffe5c]
         // 0040cf1b: push edi
         // 0040cf1c: push eax
         // 0040cf1d: lea edi, ss:[ebp+0xfffffffffffffe5c]
         // 0040cf23: call _strlen
      [-]ffff405983f83c7629
         // 0040cf28: inc eax
         // 0040cf29: pop ecx
         // 0040cf2a: cmp eax, 0x3c
         // 0040cf2d: jbe 0x40cf58
      [-]8d85????????50e8
         // 0040cf2f: lea eax, ss:[ebp+0xfffffffffffffe5c]
         // 0040cf35: push eax
         // 0040cf36: call _strlen
      [-]8d85????????83e83b6a0303f868
         // 0040cf3d: lea eax, ss:[ebp+0xfffffffffffffe5c]
         // 0040cf43: sub eax, 0x3b
         // 0040cf46: push 0x3
         // 0040cf48: add edi, eax
         // 0040cf4a: push 0x41d7d8
      [-]ffff83c410
         // 0040cf55: add esp, 0x10
      [-]8d85????????68
         // 0040cf58: lea eax, ss:[ebp+0xffffffffffffff60]
         // 0040cf5e: push 0x41d7bc
      [-]00008d85????????5750e8
         // 0040cf69: lea eax, ss:[ebp+0xffffffffffffff60]
         // 0040cf6f: push edi
         // 0040cf70: push eax
         // 0040cf71: call 0x410620
      [-]00008d85????????68
         // 0040cf76: lea eax, ss:[ebp+0xffffffffffffff60]
         // 0040cf7c: push 0x41d7b8
      [-]0000ffb6
         // 0040cf87: push ds:[esi+0x422e64]
      [-]8d85????????50e8
         // 0040cf8d: lea eax, ss:[ebp+0xffffffffffffff60]
         // 0040cf93: push eax
         // 0040cf94: call 0x410620
      [-]000068????????8d85????????68
         // 0040cf99: push 0x12010
         // 0040cf9e: lea eax, ss:[ebp+0xffffffffffffff60]
         // 0040cfa4: push 0x41d790
      [-]000083c42c5feb26
         // 0040cfaf: add esp, 0x2c
         // 0040cfb2: pop edi
         // 0040cfb3: jmp 0x40cfdb
      [-]8d45088db6
         // 0040cfb5: lea eax, ss:[ebp+0x8]
         // 0040cfb8: lea esi, ds:[esi+0x422e64]
      [-]6a0050ff36e8
         // 0040cfbe: push 0x0
         // 0040cfc0: push eax
         // 0040cfc1: push ds:[esi]
         // 0040cfc3: call _strlen
      [-]ffff5950ff366af4ff15
         // 0040cfc8: pop ecx
         // 0040cfc9: push eax
         // 0040cfca: push ds:[esi]
         // 0040cfcc: push 0xfffffffffffffff4
         // 0040cfce: call ds:[GetStdHandle]
      [-]558bec83ec108b4d0853568b750c8b411057
         // 0040ea97: push ebp
         // 0040ea98: mov ebp, esp
         // 0040ea9a: sub esp, 0x10
         // 0040ea9d: mov ecx, ss:[ebp+0x8]
         // 0040eaa0: push ebx
         // 0040eaa1: push esi
         // 0040eaa2: mov esi, ss:[ebp+0xc]
         // 0040eaa5: mov eax, ds:[ecx+0x10]
         // 0040eaa8: push edi
      [-]83c6fc2b790cc1ef0f
         // 0040eaab: add esi, 0xfffffffffffffffc
         // 0040eaae: sub edi, ds:[ecx+0xc]
         // 0040eab1: shr edi, b1 0xf
      [-]69c9????????8d8c01????????894df08b0e49f6c101894dfc0f85e6020000
         // 0040eab6: imul ecx, 0x204
         // 0040eabc: lea ecx, ds:[ecx+eax+0x144]
         // 0040eac3: mov ss:[ebp+0xfffffffffffffff0], ecx
         // 0040eac6: mov ecx, ds:[esi]
         // 0040eac8: dec ecx
         // 0040eac9: test b1 cl, b1 0x1
         // 0040eacc: mov ss:[ebp+0xfffffffffffffffc], ecx
         // 0040eacf: jnz 0x40edbb
      [-]8b14318d1c318955f48b56fc8955f88b55f4f6c201895d0c757e
         // 0040ead5: mov edx, ds:[ecx+esi]
         // 0040ead8: lea ebx, ds:[ecx+esi]
         // 0040eadb: mov ss:[ebp+0xfffffffffffffff4], edx
         // 0040eade: mov edx, ds:[esi+0xfffffffffffffffc]
         // 0040eae1: mov ss:[ebp+0xfffffffffffffff8], edx
         // 0040eae4: mov edx, ss:[ebp+0xfffffffffffffff4]
         // 0040eae7: test b1 dl, b1 0x1
         // 0040eaea: mov ss:[ebp+0xc], ebx
         // 0040eaed: jnz 0x40eb6d
      [-]c1fa044a83fa3f7603
         // 0040eaef: sar edx, b1 0x4
         // 0040eaf2: dec edx
         // 0040eaf3: cmp edx, 0x3f
         // 0040eaf6: jbe 0x40eafb
      [-]8b4b043b4b08754c
         // 0040eafb: mov ecx, ds:[ebx+0x4]
         // 0040eafe: cmp ecx, ds:[ebx+0x8]
         // 0040eb01: jnz 0x40eb4f
      [-]83fa20731e
         // 0040eb03: cmp edx, 0x20
         // 0040eb06: jnb 0x40eb26
      [-]bb????????
         // 0040eb08: mov ebx, 0xffffffff80000000
      [-]d3eb8d4c0204f7d3215cb844fe097528
         // 0040eb0f: shr ebx, b1 cl
         // 0040eb11: lea ecx, ds:[edx+eax+0x4]
         // 0040eb15: not ebx
         // 0040eb17: and ds:[eax+edi*0x4], ebx
         // 0040eb1b: dec b1 ds:[ecx]
         // 0040eb1d: jnz 0x40eb47
      [-]8b4d082119eb21
         // 0040eb1f: mov ecx, ss:[ebp+0x8]
         // 0040eb22: and ds:[ecx], ebx
         // 0040eb24: jmp 0x40eb47
      [-]8d4ae0bb????????d3eb8d4c0204f7d3219cb8c4000000fe097506
         // 0040eb26: lea ecx, ds:[edx+0xffffffffffffffe0]
         // 0040eb29: mov ebx, 0xffffffff80000000
         // 0040eb2e: shr ebx, b1 cl
         // 0040eb30: lea ecx, ds:[edx+eax+0x4]
         // 0040eb34: not ebx
         // 0040eb36: and ds:[eax+edi*0x4], ebx
         // 0040eb3d: dec b1 ds:[ecx]
         // 0040eb3f: jnz 0x40eb47
      [-]8b4d08215904
         // 0040eb41: mov ecx, ss:[ebp+0x8]
         // 0040eb44: and ds:[ecx+0x4], ebx
      [-]8b4dfc8b5d0ceb03
         // 0040eb47: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 0040eb4a: mov ebx, ss:[ebp+0xc]
         // 0040eb4d: jmp 0x40eb52
      [-]8b53088b5b04034df4895a048b550c894dfc8b5a048b5208895308
         // 0040eb52: mov edx, ds:[ebx+0x8]
         // 0040eb55: mov ebx, ds:[ebx+0x4]
         // 0040eb58: add ecx, ss:[ebp+0xfffffffffffffff4]
         // 0040eb5b: mov ds:[edx+0x4], ebx
         // 0040eb5e: mov edx, ss:[ebp+0xc]
         // 0040eb61: mov ss:[ebp+0xfffffffffffffffc], ecx
         // 0040eb64: mov ebx, ds:[edx+0x4]
         // 0040eb67: mov edx, ds:[edx+0x8]
         // 0040eb6a: mov ds:[ebx+0x8], edx
      [-]c1fa044a83fa3f7603
         // 0040eb6f: sar edx, b1 0x4
         // 0040eb72: dec edx
         // 0040eb73: cmp edx, 0x3f
         // 0040eb76: jbe 0x40eb7b
      [-]8b5df883e301895df40f8594000000
         // 0040eb7b: mov ebx, ss:[ebp+0xfffffffffffffff8]
         // 0040eb7e: and ebx, 0x1
         // 0040eb81: mov ss:[ebp+0xfffffffffffffff4], ebx
         // 0040eb84: jnz 0x40ec1e
      [-]2b75f88b5df8c1fb046a3f89750c4b5e3bde7602
         // 0040eb8a: sub esi, ss:[ebp+0xfffffffffffffff8]
         // 0040eb8d: mov ebx, ss:[ebp+0xfffffffffffffff8]
         // 0040eb90: sar ebx, b1 0x4
         // 0040eb93: push 0x3f
         // 0040eb95: mov ss:[ebp+0xc], esi
         // 0040eb98: dec ebx
         // 0040eb99: pop esi
         // 0040eb9a: cmp ebx, esi
         // 0040eb9c: jbe 0x40eba0
      [-]894dfcc1fa044a3bd67602
         // 0040eba5: mov ss:[ebp+0xfffffffffffffffc], ecx
         // 0040eba8: sar edx, b1 0x4
         // 0040ebab: dec edx
         // 0040ebac: cmp edx, esi
         // 0040ebae: jbe 0x40ebb2
      [-]3bda7463
         // 0040ebb2: cmp ebx, edx
         // 0040ebb4: jz 0x40ec19
      [-]8b4d0c8b71043b71087540
         // 0040ebb6: mov ecx, ss:[ebp+0xc]
         // 0040ebb9: mov esi, ds:[ecx+0x4]
         // 0040ebbc: cmp esi, ds:[ecx+0x8]
         // 0040ebbf: jnz 0x40ec01
      [-]83fb20731c
         // 0040ebc1: cmp ebx, 0x20
         // 0040ebc4: jnb 0x40ebe2
      [-]be????????
         // 0040ebc6: mov esi, 0xffffffff80000000
      [-]d3eef7d62174b844fe4c03047526
         // 0040ebcd: shr esi, b1 cl
         // 0040ebcf: not esi
         // 0040ebd1: and ds:[eax+edi*0x4], esi
         // 0040ebd5: dec b1 ds:[ebx+eax+0x4]
         // 0040ebd9: jnz 0x40ec01
      [-]8b4d082131eb1f
         // 0040ebdb: mov ecx, ss:[ebp+0x8]
         // 0040ebde: and ds:[ecx], esi
         // 0040ebe0: jmp 0x40ec01
      [-]8d4be0be????????d3eef7d621b4b8c4000000fe4c03047506
         // 0040ebe2: lea ecx, ds:[ebx+0xffffffffffffffe0]
         // 0040ebe5: mov esi, 0xffffffff80000000
         // 0040ebea: shr esi, b1 cl
         // 0040ebec: not esi
         // 0040ebee: and ds:[eax+edi*0x4], esi
         // 0040ebf5: dec b1 ds:[ebx+eax+0x4]
         // 0040ebf9: jnz 0x40ec01
      [-]8b4d08217104
         // 0040ebfb: mov ecx, ss:[ebp+0x8]
         // 0040ebfe: and ds:[ecx+0x4], esi
      [-]8b4d0c8b71088b4904894e048b4d0c8b71048b4908894e08
         // 0040ec01: mov ecx, ss:[ebp+0xc]
         // 0040ec04: mov esi, ds:[ecx+0x8]
         // 0040ec07: mov ecx, ds:[ecx+0x4]
         // 0040ec0a: mov ds:[esi+0x4], ecx
         // 0040ec0d: mov ecx, ss:[ebp+0xc]
         // 0040ec10: mov esi, ds:[ecx+0x4]
         // 0040ec13: mov ecx, ds:[ecx+0x8]
         // 0040ec16: mov ds:[esi+0x8], ecx
      [-]8b750ceb03
         // 0040ec19: mov esi, ss:[ebp+0xc]
         // 0040ec1c: jmp 0x40ec21
      [-]837df4007508
         // 0040ec21: cmp ss:[ebp+0xfffffffffffffff4], 0x0
         // 0040ec25: jnz 0x40ec2f
      [-]3bda0f8481000000
         // 0040ec27: cmp ebx, edx
         // 0040ec29: jz 0x40ecb0
      [-]8b4df08b5cd1048d0cd1895e04894e088971048b4e048971088b4e043b4e087560
         // 0040ec2f: mov ecx, ss:[ebp+0xfffffffffffffff0]
         // 0040ec32: mov ebx, ds:[ecx+edx*0x8]
         // 0040ec36: lea ecx, ds:[ecx+edx*0x8]
         // 0040ec39: mov ds:[esi+0x4], ebx
         // 0040ec3c: mov ds:[esi+0x8], ecx
         // 0040ec3f: mov ds:[ecx+0x4], esi
         // 0040ec42: mov ecx, ds:[esi+0x4]
         // 0040ec45: mov ds:[ecx+0x8], esi
         // 0040ec48: mov ecx, ds:[esi+0x4]
         // 0040ec4b: cmp ecx, ds:[esi+0x8]
         // 0040ec4e: jnz 0x40ecb0
      [-]8a4c020483fa20884d0ffec1884c02047325
         // 0040ec50: mov b1 cl, b1 ds:[edx+eax+0x4]
         // 0040ec54: cmp edx, 0x20
         // 0040ec57: mov b1 ss:[ebp+0xf], b1 cl
         // 0040ec5a: inc b1 cl
         // 0040ec5c: mov b1 ds:[edx+eax+0x4], b1 cl
         // 0040ec60: jnb 0x40ec87
      [-]807d0f00750e
         // 0040ec62: cmp b1 ss:[ebp+0xf], b1 0x0
         // 0040ec66: jnz 0x40ec76
      [-]bb????????
         // 0040ec68: mov ebx, 0xffffffff80000000
      [-]d3eb8b4d080919
         // 0040ec6f: shr ebx, b1 cl
         // 0040ec71: mov ecx, ss:[ebp+0x8]
         // 0040ec74: or ds:[ecx], ebx
      [-]bb????????
         // 0040ec76: mov ebx, 0xffffffff80000000
      [-]d3eb8d44b8440918eb29
         // 0040ec7d: shr ebx, b1 cl
         // 0040ec7f: lea eax, ds:[eax+edi*0x4]
         // 0040ec83: or ds:[eax], ebx
         // 0040ec85: jmp 0x40ecb0
      [-]807d0f007510
         // 0040ec87: cmp b1 ss:[ebp+0xf], b1 0x0
         // 0040ec8b: jnz 0x40ec9d
      [-]8d4ae0bb????????d3eb8b4d08095904
         // 0040ec8d: lea ecx, ds:[edx+0xffffffffffffffe0]
         // 0040ec90: mov ebx, 0xffffffff80000000
         // 0040ec95: shr ebx, b1 cl
         // 0040ec97: mov ecx, ss:[ebp+0x8]
         // 0040ec9a: or ds:[ecx+0x4], ebx
      [-]8d4ae0ba????????d3ea8d84b8c40000000910
         // 0040ec9d: lea ecx, ds:[edx+0xffffffffffffffe0]
         // 0040eca0: mov edx, 0xffffffff80000000
         // 0040eca5: shr edx, b1 cl
         // 0040eca7: lea eax, ds:[eax+edi*0x4]
         // 0040ecae: or ds:[eax], edx
      [-]8b45fc8906894430fc8b45f0ff080f85f7000000
         // 0040ecb0: mov eax, ss:[ebp+0xfffffffffffffffc]
         // 0040ecb3: mov ds:[esi], eax
         // 0040ecb5: mov ds:[eax+esi+0xfffffffffffffffc], eax
         // 0040ecb9: mov eax, ss:[ebp+0xfffffffffffffff0]
         // 0040ecbc: dec ds:[eax]
         // 0040ecbe: jnz 0x40edbb
      [-]0f84dc000000
         // 0040eccb: jz 0x40edad
      [-]e10f03480cbb????????68????????5351ffd68b0d
         // 0040ece0: add ecx, ds:[eax+0xc]
         // 0040ece3: mov ebx, 0x8000
         // 0040ece8: push 0x4000
         // 0040eced: push ebx
         // 0040ecee: push ecx
         // 0040ecef: call esi
         // 0040ecf1: mov ecx, ds:[0x447968]
      [-]ba????????d3ea095008a1
         // 0040ecfc: mov edx, 0xffffffff80000000
         // 0040ed01: shr edx, b1 cl
         // 0040ed03: or ds:[eax+0x8], edx
         // 0040ed06: mov eax, ds:[0x447970]
      [-]8b401083a488c4????????a1
         // 0040ed11: mov eax, ds:[eax+0x10]
         // 0040ed14: and ds:[eax+ecx*0x4], 0x0
         // 0040ed1c: mov eax, ds:[0x447970]
      [-]8b4010fe4843a1
         // 0040ed21: mov eax, ds:[eax+0x10]
         // 0040ed24: dec b1 ds:[eax+0x43]
         // 0040ed27: mov eax, ds:[0x447970]
      [-]8b4810807943007509
         // 0040ed2c: mov ecx, ds:[eax+0x10]
         // 0040ed2f: cmp b1 ds:[ecx+0x43], b1 0x0
         // 0040ed33: jnz 0x40ed3e
      [-]836004fea1
         // 0040ed35: and ds:[eax+0x4], 0xfffffffffffffffe
         // 0040ed39: mov eax, ds:[0x447970]
      [-]837808ff7569
         // 0040ed3e: cmp ds:[eax+0x8], 0xffffffffffffffff
         // 0040ed42: jnz 0x40edad
      [-]536a00ff700cffd6a1
         // 0040ed44: push ebx
         // 0040ed45: push 0x0
         // 0040ed47: push ds:[eax+0xc]
         // 0040ed4a: call esi
         // 0040ed4c: mov eax, ds:[0x447970]
      [-]ff70106a00ff35
         // 0040ed51: push ds:[eax+0x10]
         // 0040ed54: push 0x0
         // 0040ed56: push ds:[0x447988]
      [-]8d0480c1e002
         // 0040ed6d: lea eax, ds:[eax+eax*0x4]
         // 0040ed70: shl eax, b1 0x2
      [-]2bc88d4c11ec518d48145150e8
         // 0040ed7a: sub ecx, eax
         // 0040ed7c: lea ecx, ds:[ecx+edx+0xffffffffffffffec]
         // 0040ed80: push ecx
         // 0040ed81: lea ecx, ds:[eax+0x14]
         // 0040ed84: push ecx
         // 0040ed85: push eax
         // 0040ed86: call 0x409b50
      [-]ffff8b450883c40cff0d
         // 0040ed8b: mov eax, ss:[ebp+0x8]
         // 0040ed8e: add esp, 0xc
         // 0040ed91: dec ds:[0x447974]
      [-]836d0814
         // 0040ed9f: sub ss:[ebp+0x8], 0x14
      [-]8b4508893d
         // 0040edad: mov eax, ss:[ebp+0x8]
         // 0040edb0: mov ds:[0x447968], edi
      [-]5f5e5bc9c3
         // 0040edbb: pop edi
         // 0040edbc: pop esi
         // 0040edbd: pop ebx
         // 0040edbe: leave 
         // 0040edbf: retn 
      [-]ff535556577507
         // 0040f572: push ebx
         // 0040f573: push ebp
         // 0040f574: push esi
         // 0040f575: push edi
         // 0040f576: jnz 0x40f57f
      [-]68????????6a00ff35
         // 0040f57f: push 0x2020
         // 0040f584: push 0x0
         // 0040f586: push ds:[0x447988]
      [-]0f840c010000
         // 0040f596: jz 0x40f6a8
      [-]6a0468????????68????????6a00ffd5
         // 0040f5a2: push 0x4
         // 0040f5a4: push 0x2000
         // 0040f5a9: push 0x400000
         // 0040f5ae: push 0x0
         // 0040f5b0: call ebp
      [-]0f84d5000000
         // 0040f5b6: jz 0x40f691
      [-]6a04bb????????68????????5357ffd5
         // 0040f5bc: push 0x4
         // 0040f5be: mov ebx, 0x10000
         // 0040f5c3: push 0x1000
         // 0040f5c8: push ebx
         // 0040f5c9: push edi
         // 0040f5ca: call ebp
      [-]0f84af000000
         // 0040f5ce: jz 0x40f683
      [-]3bf0751e
         // 0040f5d9: cmp esi, eax
         // 0040f5db: jnz 0x40f5fb
      [-]8946048935
         // 0040f602: mov ds:[esi+0x4], eax
         // 0040f605: mov ds:[0x423414], esi
      [-]8b46048930
         // 0040f60b: mov eax, ds:[esi+0x4]
         // 0040f60e: mov ds:[eax], esi
      [-]8d87????????8d8e????????8946148d4618894e0c897e1089460833edb9????????
         // 0040f610: lea eax, ds:[edi+0x400000]
         // 0040f616: lea ecx, ds:[esi+0x98]
         // 0040f61c: mov ds:[esi+0x14], eax
         // 0040f61f: lea eax, ds:[esi+0x18]
         // 0040f622: mov ds:[esi+0xc], ecx
         // 0040f625: mov ds:[esi+0x10], edi
         // 0040f628: mov ds:[esi+0x8], eax
         // 0040f62b: xor ebp, ebp
         // 0040f62d: mov ecx, 0xf1
      [-]83fd100f9dc24a23d14a458910894804
         // 0040f634: cmp ebp, 0x10
         // 0040f637: setnl b1 dl
         // 0040f63a: dec edx
         // 0040f63b: and edx, ecx
         // 0040f63d: dec edx
         // 0040f63e: inc ebp
         // 0040f63f: mov ds:[eax], edx
         // 0040f641: mov ds:[eax+0x4], ecx
      [-]81fd????????7ce3
         // 0040f647: cmp ebp, 0x400
         // 0040f64d: jl 0x40f632
      [-]536a0057e8
         // 0040f64f: push ebx
         // 0040f650: push 0x0
         // 0040f652: push edi
         // 0040f653: call 0x40b0d0
      [-]ffff83c40c
         // 0040f658: add esp, 0xc
      [-]8b461003c33bf8731b
         // 0040f65b: mov eax, ds:[esi+0x10]
         // 0040f65e: add eax, ebx
         // 0040f660: cmp edi, eax
         // 0040f662: jnb 0x40f67f
      [-]808ff8000000ff8d47088907c74704????????
         // 0040f664: or b1 ds:[edi+0xf8], b1 0xff
         // 0040f66b: lea eax, ds:[edi+0x8]
         // 0040f66e: mov ds:[edi], eax
         // 0040f670: mov ds:[edi+0x4], 0xf0
      [-]68????????6a0057ff15
         // 0040f683: push 0x8000
         // 0040f688: push 0x0
         // 0040f68a: push edi
         // 0040f68b: call ds:[VirtualFree]
      [-]566a00ff35
         // 0040f699: push esi
         // 0040f69a: push 0x0
         // 0040f69c: push ds:[0x447988]
      [-]5f5e5d5bc3
         // 0040f6aa: pop edi
         // 0040f6ab: pop esi
         // 0040f6ac: pop ebp
         // 0040f6ad: pop ebx
         // 0040f6ae: retn 
      [-]568b74240868????????6a00ff7610ff15
         // 0040f6af: push esi
         // 0040f6b0: mov esi, ss:[esp+0x8]
         // 0040f6b4: push 0x8000
         // 0040f6b9: push 0x0
         // 0040f6bb: push ds:[esi+0x10]
         // 0040f6be: call ds:[VirtualFree]
      [-]8b4604a3
         // 0040f6cc: mov eax, ds:[esi+0x4]
         // 0040f6cf: mov ds:[0x425430], eax
      [-]8b46048b0e566a0089088b068b4e04894804ff35
         // 0040f6dc: mov eax, ds:[esi+0x4]
         // 0040f6df: mov ecx, ds:[esi]
         // 0040f6e1: push esi
         // 0040f6e2: push 0x0
         // 0040f6e4: mov ds:[eax], ecx
         // 0040f6e6: mov eax, ds:[esi]
         // 0040f6e8: mov ecx, ds:[esi+0x4]
         // 0040f6eb: mov ds:[eax+0x4], ecx
         // 0040f6ee: push ds:[0x447988]
      [-]558bec5153568b35
         // 0040f705: push ebp
         // 0040f706: mov ebp, esp
         // 0040f708: push ecx
         // 0040f709: push ebx
         // 0040f70a: push esi
         // 0040f70b: mov esi, ds:[0x423414]
      [-]837e10ff0f8494000000
         // 0040f712: cmp ds:[esi+0x10], 0xffffffffffffffff
         // 0040f716: jz 0x40f7b0
      [-]8365fc008dbe????????bb????????
         // 0040f71c: and ss:[ebp+0xfffffffffffffffc], 0x0
         // 0040f720: lea edi, ds:[esi+0x2010]
         // 0040f726: mov ebx, 0x3ff000
      [-]813f????????7539
         // 0040f72b: cmp ds:[edi], 0xf0
         // 0040f731: jnz 0x40f76c
      [-]68????????03461068????????50ff15
         // 00544316: push 0x4000
         // 0054431b: add eax, ds:[esi+0x10]
         // 0054431e: push 0x1000
         // 00544323: push eax
         // 00544324: call ds:[0x55c258]
      [-]830fffff0d
         // 0040f74d: or ds:[edi], 0xffffffffffffffff
         // 0040f750: dec ds:[0x4466e8]
      [-]3bc77603
         // 0040f75d: cmp eax, edi
         // 0040f75f: jbe 0x40f764
      [-]ff45fcff4d08740d
         // 0040f764: inc ss:[ebp+0xfffffffffffffffc]
         // 0040f767: dec ss:[ebp+0x8]
         // 0040f76a: jz 0x40f779
      [-]81eb????????
         // 0040f76c: sub ebx, 0x1000
      [-]837dfc00
         // 0040f779: cmp ss:[ebp+0xfffffffffffffffc], 0x0
      [-]8b7604742c
         // 0040f77f: mov esi, ds:[esi+0x4]
         // 0040f782: jz 0x40f7b0
      [-]837918ff7526
         // 0040f784: cmp ds:[ecx+0x18], 0xffffffffffffffff
         // 0040f788: jnz 0x40f7b0
      [-]6a018d41205a
         // 0040f78a: push 0x1
         // 0040f78c: lea eax, ds:[ecx+0x20]
         // 0040f78f: pop edx
      [-]8338ff750c
         // 0040f790: cmp ds:[eax], 0xffffffffffffffff
         // 0040f793: jnz 0x40f7a1
      [-]81fa????????7cef
         // 0040f799: cmp edx, 0x400
         // 0040f79f: jl 0x40f790
      [-]81fa????????7507
         // 0040f7a1: cmp edx, 0x400
         // 0040f7a7: jnz 0x40f7b0
      [-]51e800ffffff59
         // 0040f7a9: push ecx
         // 0040f7aa: call 0x40f6af
         // 0040f7af: pop ecx
      [-]837d08000f8f50ffffff
         // 0040f7b8: cmp ss:[ebp+0x8], 0x0
         // 0040f7bc: jg 0x40f712
      [-]5f5e5bc9c3
         // 0040f7c2: pop edi
         // 0040f7c3: pop esi
         // 0040f7c4: pop ebx
         // 0040f7c5: leave 
         // 0040f7c6: retn 
      [-]8b442404ba
         // 0040f7c7: mov eax, ss:[esp+0x4]
         // 0040f7cb: mov edx, 0x423410
      [-]3b41107605
         // 0040f7d3: cmp eax, ds:[ecx+0x10]
         // 0040f7d6: jbe 0x40f7dd
      [-]3b41147208
         // 0040f7d8: cmp eax, ds:[ecx+0x14]
         // 0040f7db: jb 0x40f7e5
      [-]8b093bca7437
         // 0040f7dd: mov ecx, ds:[ecx]
         // 0040f7df: cmp ecx, edx
         // 0040f7e1: jz 0x40f81a
      [-]a80f7531
         // 0040f7e5: test b1 al, b1 0xf
         // 0040f7e7: jnz 0x40f81a
      [-]ba????????81e6????????3bf27220
         // 0040f7eb: mov edx, 0x100
         // 0040f7f0: and esi, 0xfff
         // 0040f7f6: cmp esi, edx
         // 0040f7f8: jb 0x40f81a
      [-]8b74240c890e8b742410
         // 0040f7fa: mov esi, ss:[esp+0xc]
         // 0040f7fe: mov ds:[esi], ecx
         // 0040f800: mov esi, ss:[esp+0x10]
      [-]6681e100f02bc1890e2bc25ec1f8048d440808c3
         // 0040f806: and b2 cx, b2 0xfffffffffffff000
         // 0040f80b: sub eax, ecx
         // 0040f80d: mov ds:[esi], ecx
         // 0040f80f: sub eax, edx
         // 0040f811: pop esi
         // 0040f812: sar eax, b1 0x4
         // 0040f815: lea eax, ds:[eax+ecx+0x8]
         // 0040f819: retn 
      [-]8b4424048b4c24082b4810c1f90c8d44c8188b4c240c0fb61101108021008138????????c74004????????7517
         // 0040f81e: mov eax, ss:[esp+0x4]
         // 0040f822: mov ecx, ss:[esp+0x8]
         // 0040f826: sub ecx, ds:[eax+0x10]
         // 0040f829: sar ecx, b1 0xc
         // 0040f82c: lea eax, ds:[eax+ecx*0x8]
         // 0040f830: mov ecx, ss:[esp+0xc]
         // 0040f834: movzx edx, b1 ds:[ecx]
         // 0040f837: add ds:[eax], edx
         // 0040f839: and b1 ds:[ecx], b1 0x0
         // 0040f83c: cmp ds:[eax], 0xf0
         // 0040f842: mov ds:[eax+0x4], 0xf1
         // 0040f849: jnz 0x40f862
      [-]6a10e8a4feffff59
         // 0040f85a: push 0x10
         // 0040f85c: call 0x40f705
         // 0040f861: pop ecx
      [-]558bec515153568b35
         // 0040f863: push ebp
         // 0040f864: mov ebp, esp
         // 0040f866: push ecx
         // 0040f867: push ecx
         // 0040f868: push ebx
         // 0040f869: push esi
         // 0040f86a: mov esi, ds:[0x425430]
      [-]8b561083faff0f849f000000
         // 0040f871: mov edx, ds:[esi+0x10]
         // 0040f874: cmp edx, 0xffffffffffffffff
         // 0040f877: jz 0x40f91c
      [-]8b7e088d8e????????
         // 0040f87d: mov edi, ds:[esi+0x8]
         // 0040f880: lea ecx, ds:[esi+0x2018]
      [-]2bc683e818c1f803c1e00c03c23bf98945fc733a
         // 0040f888: sub eax, esi
         // 0040f88a: sub eax, 0x18
         // 0040f88d: sar eax, b1 0x3
         // 0040f890: shl eax, b1 0xc
         // 0040f893: add eax, edx
         // 0040f895: cmp edi, ecx
         // 0040f897: mov ss:[ebp+0xfffffffffffffffc], eax
         // 0040f89a: jnb 0x40f8d6
      [-]8b0f8b5d083bcb7c1a
         // 0040f89c: mov ecx, ds:[edi]
         // 0040f89e: mov ebx, ss:[ebp+0x8]
         // 0040f8a1: cmp ecx, ebx
         // 0040f8a3: jl 0x40f8bf
      [-]395f047615
         // 0040f8a5: cmp ds:[edi+0x4], ebx
         // 0040f8a8: jbe 0x40f8bf
      [-]535150e8b901000083c40c
         // 0040f8aa: push ebx
         // 0040f8ab: push ecx
         // 0040f8ac: push eax
         // 0040f8ad: call 0x40fa6b
         // 0040f8b2: add esp, 0xc
      [-]8b45fc895f04
         // 0040f8b9: mov eax, ss:[ebp+0xfffffffffffffffc]
         // 0040f8bc: mov ds:[edi+0x4], ebx
      [-]83c7088d8e????????05????????3bf98945fc72c8
         // 0040f8bf: add edi, 0x8
         // 0040f8c2: lea ecx, ds:[esi+0x2018]
         // 0040f8c8: add eax, 0x1000
         // 0040f8cd: cmp edi, ecx
         // 0040f8cf: mov ss:[ebp+0xfffffffffffffffc], eax
         // 0040f8d2: jb 0x40f89c
      [-]8b46088b4e108d7e188945f83bf8894dfc7333
         // 0040f8d9: mov eax, ds:[esi+0x8]
         // 0040f8dc: mov ecx, ds:[esi+0x10]
         // 0040f8df: lea edi, ds:[esi+0x18]
         // 0040f8e2: mov ss:[ebp+0xfffffffffffffff8], eax
         // 0040f8e5: cmp edi, eax
         // 0040f8e7: mov ss:[ebp+0xfffffffffffffffc], ecx
         // 0040f8ea: jnb 0x40f91f
      [-]8b073bc37c19
         // 0040f8ec: mov eax, ds:[edi]
         // 0040f8ee: cmp eax, ebx
         // 0040f8f0: jl 0x40f90b
      [-]395f047614
         // 0040f8f2: cmp ds:[edi+0x4], ebx
         // 0040f8f5: jbe 0x40f90b
      [-]5350ff75fce86a01000083c40c
         // 0040f8f7: push ebx
         // 0040f8f8: push eax
         // 0040f8f9: push ss:[ebp+0xfffffffffffffffc]
         // 0040f8fc: call 0x40fa6b
         // 0040f901: add esp, 0xc
      [-]8145fc????????83c7083b7df872d2
         // 0040f90b: add ss:[ebp+0xfffffffffffffffc], 0x1000
         // 0040f912: add edi, 0x8
         // 0040f915: cmp edi, ss:[ebp+0xfffffffffffffff8]
         // 0040f918: jb 0x40f8ec
      [-]8b363b35
         // 0040f91f: mov esi, ds:[esi]
         // 0040f921: cmp esi, ds:[0x425430]
      [-]e943ffffff
         // 0040f929: jmp 0x40f871
      [-]291f897e08e928010000
         // 0040f934: sub ds:[edi], ebx
         // 0040f936: mov ds:[esi+0x8], edi
         // 0040f939: jmp 0x40fa66
      [-]837f10ff7406
         // 0040f945: cmp ds:[edi+0x10], 0xffffffffffffffff
         // 0040f949: jz 0x40f951
      [-]837f0c00750c
         // 0040f94b: cmp ds:[edi+0xc], 0x0
         // 0040f94f: jnz 0x40f95d
      [-]8b3f3bf80f84d7000000
         // 0040f951: mov edi, ds:[edi]
         // 0040f953: cmp edi, eax
         // 0040f955: jz 0x40fa32
      [-]8b5f0c8365fc00
         // 0040f95d: mov ebx, ds:[edi+0xc]
         // 0040f960: and ss:[ebp+0xfffffffffffffffc], 0x0
      [-]2bf783ee18c1fe03c1e60c037710833bff7511
         // 0040f968: sub esi, edi
         // 0040f96a: sub esi, 0x18
         // 0040f96d: sar esi, b1 0x3
         // 0040f970: shl esi, b1 0xc
         // 0040f973: add esi, ds:[edi+0x10]
         // 0040f976: cmp ds:[ebx], 0xffffffffffffffff
         // 0040f979: jnz 0x40f98c
      [-]837dfc107d0b
         // 0040f97b: cmp ss:[ebp+0xfffffffffffffffc], 0x10
         // 0040f97f: jge 0x40f98c
      [-]83c008ff45fc8338ff74ef
         // 0040f981: add eax, 0x8
         // 0040f984: inc ss:[ebp+0xfffffffffffffffc]
         // 0040f987: cmp ds:[eax], 0xffffffffffffffff
         // 0040f98a: jz 0x40f97b
      [-]8b45fc6a04c1e00c68????????50568945f8ff15
         // 0040f98c: mov eax, ss:[ebp+0xfffffffffffffffc]
         // 0040f98f: push 0x4
         // 0040f991: shl eax, b1 0xc
         // 0040f994: push 0x1000
         // 0040f999: push eax
         // 0040f99a: push esi
         // 0040f99b: mov ss:[ebp+0xfffffffffffffff8], eax
         // 0040f99e: call ds:[VirtualAlloc]
      [-]3bc60f85b8000000
         // 0040f9a4: cmp eax, esi
         // 0040f9a6: jnz 0x40fa64
      [-]6a00ff75f856e8
         // 0040f9ac: push 0x0
         // 0040f9ae: push ss:[ebp+0xfffffffffffffff8]
         // 0040f9b1: push esi
         // 0040f9b2: call 0x40b0d0
      [-]ffff8b55fc83c40c
         // 0040f9b7: mov edx, ss:[ebp+0xfffffffffffffffc]
         // 0040f9ba: add esp, 0xc
      [-]8d46048955fc
         // 0040f9c3: lea eax, ds:[esi+0x4]
         // 0040f9c6: mov ss:[ebp+0xfffffffffffffffc], edx
      [-]8088f4000000ff8d50048950fcba????????89108911c74104????????05????????
         // 0040f9c9: or b1 ds:[eax+0xf4], b1 0xff
         // 0040f9d0: lea edx, ds:[eax+0x4]
         // 0040f9d3: mov ds:[eax+0xfffffffffffffffc], edx
         // 0040f9d6: mov edx, 0xf0
         // 0040f9db: mov ds:[eax], edx
         // 0040f9dd: mov ds:[ecx], edx
         // 0040f9df: mov ds:[ecx+0x4], 0xf1
         // 0040f9e6: add eax, 0x1000
      [-]ff4dfc75d6
         // 0040f9ee: dec ss:[ebp+0xfffffffffffffffc]
         // 0040f9f1: jnz 0x40f9c9
      [-]8d87????????
         // 0040f9f9: lea eax, ds:[edi+0x2018]
      [-]3bc8730c
         // 0040f9ff: cmp ecx, eax
         // 0040fa01: jnb 0x40fa0f
      [-]8339ff7405
         // 0040fa03: cmp ds:[ecx], 0xffffffffffffffff
         // 0040fa06: jz 0x40fa0d
      [-]83c108ebf2
         // 0040fa08: add ecx, 0x8
         // 0040fa0b: jmp 0x40f9ff
      [-]1bc023c189470c8b4508884608895f0829032946048d4c06088d86????????890eeb34
         // 0040fa0f: sbb eax, eax
         // 0040fa11: and eax, ecx
         // 0040fa13: mov ds:[edi+0xc], eax
         // 0040fa16: mov eax, ss:[ebp+0x8]
         // 0040fa19: mov b1 ds:[esi+0x8], b1 al
         // 0040fa1c: mov ds:[edi+0x8], ebx
         // 0040fa1f: sub ds:[ebx], eax
         // 0040fa21: sub ds:[esi+0x4], eax
         // 0040fa24: lea ecx, ds:[esi+eax+0x8]
         // 0040fa28: lea eax, ds:[esi+0x100]
         // 0040fa2e: mov ds:[esi], ecx
         // 0040fa30: jmp 0x40fa66
      [-]e834fbffff
         // 0040fa32: call 0x40f56b
      [-]8b48108859088d541908a3
         // 0040fa3b: mov ecx, ds:[eax+0x10]
         // 0040fa3e: mov b1 ds:[ecx+0x8], b1 bl
         // 0040fa41: lea edx, ds:[ecx+ebx+0x8]
         // 0040fa45: mov ds:[0x425430], eax
      [-]8911ba????????2bd38951040fb6d32950188d81????????eb02
         // 0040fa4a: mov ds:[ecx], edx
         // 0040fa4c: mov edx, 0xf0
         // 0040fa51: sub edx, ebx
         // 0040fa53: mov ds:[ecx+0x4], edx
         // 0040fa56: movzx edx, b1 bl
         // 0040fa59: sub ds:[eax+0x18], edx
         // 0040fa5c: lea eax, ds:[ecx+0x100]
         // 0040fa62: jmp 0x40fa66
      [-]5f5e5bc9c3
         // 0040fa66: pop edi
         // 0040fa67: pop esi
         // 0040fa68: pop ebx
         // 0040fa69: leave 
         // 0040fa6a: retn 
      [-]558bec518b4d088b551053568b7104578b398d99????????3bf2897dfc
         // 0040fa6b: push ebp
         // 0040fa6c: mov ebp, esp
         // 0040fa6e: push ecx
         // 0040fa6f: mov ecx, ss:[ebp+0x8]
         // 0040fa72: mov edx, ss:[ebp+0x10]
         // 0040fa75: push ebx
         // 0040fa76: push esi
         // 0040fa77: mov esi, ds:[ecx+0x4]
         // 0040fa7a: push edi
         // 0040fa7b: mov edi, ds:[ecx]
         // 0040fa7d: lea ebx, ds:[ecx+0xf8]
         // 0040fa83: cmp esi, edx
         // 0040fa85: mov ss:[ebp+0xfffffffffffffffc], edi
      [-]895d087221
         // 0040fa8a: mov ss:[ebp+0x8], ebx
         // 0040fa8d: jb 0x40fab0
      [-]8d041788173bc37307
         // 0040fa8f: lea eax, ds:[edi+edx]
         // 0040fa92: mov b1 ds:[edi], b1 dl
         // 0040fa94: cmp eax, ebx
         // 0040fa96: jnb 0x40fa9f
      [-]0111295104eb09
         // 0040fa98: add ds:[ecx], edx
         // 0040fa9a: sub ds:[ecx+0x4], edx
         // 0040fa9d: jmp 0x40faa8
      [-]836104008d41088901
         // 0040fa9f: and ds:[ecx+0x4], 0x0
         // 0040faa3: lea eax, ds:[ecx+0x8]
         // 0040faa6: mov ds:[ecx], eax
      [-]8d4708e9ce000000
         // 0040faa8: lea eax, ds:[edi+0x8]
         // 0040faab: jmp 0x40fb7e
      [-]03f7803e007402
         // 0040fab0: add esi, edi
         // 0040fab2: cmp b1 ds:[esi], b1 0x0
         // 0040fab5: jz 0x40fab9
      [-]8d34103bf37343
         // 0040fab9: lea esi, ds:[eax+edx]
         // 0040fabc: cmp esi, ebx
         // 0040fabe: jnb 0x40fb03
      [-]8a1884
         // 0040fac0: mov b1 bl, b1 ds:[eax]
         // 0040fac2: test b1 bl, b1 bl
         // 0040fac4: jnz 0x40faf6

  }
  condition:
    all of them
}
