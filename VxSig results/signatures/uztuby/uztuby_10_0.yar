rule uztuby_10_0 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         53578bc650e8
         // 004010fe: push ebx
         // 004010ff: push edi
         // 00401100: mov eax, esi
         // 00401102: push eax
         // 00401103: call 0x411908
      [-]8bc650e8
         // 00401108: mov eax, esi
         // 0040110a: push eax
         // 0040110b: call _wcslen
      [-]0200598d
         // 00401110: pop ecx
         // 00401111: lea esi, ss:[ebp+0xfffffffffffffbaa]
      [-]8d34468d
         // 00401117: lea esi, ds:[esi+eax*0x2]
         // 0040111a: lea eax, ss:[ebp+0xfffffffffffffba8]
      [-]8bce2bc88bc3d1f92bc1505756e8
         // 00401120: mov ecx, esi
         // 00401122: sub ecx, eax
         // 00401124: mov eax, ebx
         // 00401126: sar ecx, b1 0x1
         // 00401128: sub eax, ecx
         // 0040112a: push eax
         // 0040112b: push edi
         // 0040112c: push esi
         // 0040112d: call 0x411908
      [-]0200598d344683c602
         // 00401138: pop ecx
         // 00401139: lea esi, ds:[esi+eax*0x2]
         // 0040113c: add esi, 0x2
      [-]8bce2bc88bc3d1f92bc15068
         // 00401145: mov ecx, esi
         // 00401147: sub ecx, eax
         // 00401149: mov eax, ebx
         // 0040114b: sar ecx, b1 0x1
         // 0040114d: sub eax, ecx
         // 0040114f: push eax
         // 00401150: push 0xa3
      [-]00005056e8
         // 0040115a: push eax
         // 0040115b: push esi
         // 0040115c: call 0x411908
      [-]0200598d8d
         // 00401167: pop ecx
         // 00401168: lea ecx, ss:[ebp+0xfffffffffffffba8]
      [-]344683c6028bc62bc1d1f82bd85368
         // 0040116e: lea esi, ds:[esi+eax*0x2]
         // 00401171: add esi, 0x2
         // 00401174: mov eax, esi
         // 00401176: sub eax, ecx
         // 00401178: sar eax, b1 0x1
         // 0040117a: sub ebx, eax
         // 0040117c: push ebx
         // 0040117d: push 0x4345f0
      [-]020033c96a5866894c46028d
         // 0040118e: xor ecx, ecx
         // 00401190: push 0x58
         // 00401192: mov b2 ds:[esi+eax*0x2], b2 cx
         // 00401197: lea eax, ss:[ebp+0xffffffffffffffa8]
      [-]5e565150e8
         // 0040119a: pop esi
         // 0040119b: push esi
         // 0040119c: push ecx
         // 0040119d: push eax
         // 0040119e: call _memset
      [-]83c4108a
         // 004011a6: add esp, 0x10
         // 004011a9: mov b1 bl, b1 ss:[ebp+0x18]
      [-]5084db7408
         // 004011e0: push eax
         // 004011e1: test b1 bl, b1 bl
         // 004011e3: jz 0x4011ed
      [-]4600eb06
         // 004011fb: jmp 0x401203
      [-]8bf085f675
         // 00401221: mov esi, eax
         // 00401223: test esi, esi
         // 00401225: jnz 0x401255
      [-]46003d????????75
         // 0040120f: cmp eax, 0x3002
         // 00401214: jnz 0x401233
      [-]33c06689
         // 00401234: xor eax, eax
         // 00401236: mov b2 ss:[ebp+0x0], b2 ax
      [-]5084db7408
         // 0040123e: push eax
         // 0040123f: test b1 bl, b1 bl
         // 00401241: jz 0x40124b
      [-]4600eb06
         // 00401229: jmp 0x401231
      [-]460085c0
         // 00401254: test eax, eax
      [-]33c98945
         // 0040126a: xor ecx, ecx
         // 0040126c: mov ss:[ebp+0xffffffffffffffdc], eax
      [-]46008bf085f6
         // 00401298: mov esi, eax
         // 0040129a: test esi, esi
      [-]46008b4d
         // 004012a9: mov ecx, ss:[ebp+0xfffffffffffffffc]
      [-]8b118b72148bceff15
         // 004012b3: mov edx, ds:[ecx]
         // 004012b5: mov esi, ds:[edx+0x14]
         // 004012b8: mov ecx, esi
         // 004012ba: call ds:[___guard_check_icall_fptr]
      [-]4300ffd6
         // 004012c0: call esi
      [-]0fb644240c50ff74240cff74240cff15
         // 004012c8: movzx eax, b1 ss:[esp+0xc]
         // 004012cd: push eax
         // 004012ce: push ss:[esp+0xc]
         // 004012d2: push ss:[esp+0xc]
         // 004012d6: call ds:[GetDlgItem]
      [-]460050ff15
         // 004012dc: push eax
         // 004012dd: call ds:[EnableWindow]
      [-]4600c20c00
         // 004012e3: retn b2 0xc
      [-]0fb644240cf7d81bc083e00950ff74240cff74240cff15
         // 004012e6: movzx eax, b1 ss:[esp+0xc]
         // 004012eb: neg eax
         // 004012ed: sbb eax, eax
         // 004012ef: and eax, 0x9
         // 004012f2: push eax
         // 004012f3: push ss:[esp+0xc]
         // 004012f7: push ss:[esp+0xc]
         // 004012fb: call ds:[GetDlgItem]
      [-]460050ff15
         // 00401301: push eax
         // 00401302: call ds:[ShowWindow]
      [-]4600c20c00
         // 00401308: retn b2 0xc
      [-]558bec837d0c307459
         // 00401366: push ebp
         // 00401367: mov ebp, esp
         // 00401369: cmp ss:[ebp+0xc], 0x30
         // 0040136d: jz 0x4013c8
      [-]817d0c????????755d
         // 0040136f: cmp ss:[ebp+0xc], 0x110
         // 00401376: jnz 0x4013d5
      [-]8a4520b9
         // 00401328: mov b1 al, b1 ss:[ebp+0x20]
         // 0040132b: mov ecx, 0x441030
      [-]24010fb6c050ff7518ff7508e8
         // 00401330: and b1 al, b1 0x1
         // 00401332: movzx eax, b1 al
         // 00401335: push eax
         // 00401336: push ss:[ebp+0x18]
         // 00401339: push ss:[ebp+0x8]
         // 0040133c: call 0x40e2e8
      [-]0000f6452001743e
         // 00401341: test b1 ss:[ebp+0x20], b1 0x1
         // 00401345: jz 0x401385
      [-]ff7508ff15
         // 0040133c: push ss:[ebp+0x8]
         // 0040133f: call ds:[GetParent]
      [-]460085c07431
         // 00401345: test eax, eax
         // 00401347: jz 0x40137a
      [-]68????????50ff15
         // 00401349: push 0x3021
         // 0040134e: push eax
         // 0040134f: call ds:[GetDlgItem]
      [-]460085c07421
         // 00401355: test eax, eax
         // 00401357: jz 0x40137a
      [-]f6452008741b
         // 004013b4: test b1 ss:[ebp+0x20], b1 0x8
         // 004013b8: jz 0x4013d5
      [-]4600eb0d
         // 00401376: jmp 0x401385
      [-]ff7508b9
         // 00401378: push ss:[ebp+0x8]
         // 0040137b: mov ecx, 0x441030
      [-]32c05dc21c00
         // 004013d5: xor b1 al, b1 al
         // 004013d7: pop ebp
         // 004013d8: retn b2 0x1c
      [-]568bf180be
         // 00401692: push esi
         // 00401693: mov esi, ecx
         // 00401695: cmp b1 ds:[esi+0x21d0], b1 0x0
      [-]000000c706
         // 0040169c: mov ds:[esi], 0x4335f8
      [-]85ff7414
         // 0040167b: test edi, edi
         // 0040167d: jz 0x401693
      [-]01005959
         // 004016c1: pop ecx
         // 004016c2: pop ecx
      [-]ffffff8d8e
         // 0040169f: lea ecx, ds:[esi+0x32a8]
      [-]ffffff8d8e
         // 004016aa: lea ecx, ds:[esi+0x20e8]
      [-]00008d8e
         // 004016b5: lea ecx, ds:[esi+0x1024]
      [-]00008bce5ee9
         // 004016c0: mov ecx, esi
         // 004016c2: pop esi
         // 004016c3: jmp 0x4095e8
      [-]568bf1e8
         // 00401800: push esi
         // 00401801: mov esi, ecx
         // 00401803: call 0x401641
      [-]f644240801740d
         // 00401808: test b1 ss:[esp+0x8], b1 0x1
         // 0040180d: jz 0x40181c
      [-]01005959
         // 004016fa: pop ecx
         // 004016fb: pop ecx
      [-]8bc65ec20400
         // 004018ac: mov eax, esi
         // 004018ae: pop esi
         // 004018af: retn b2 0x4
      [-]4e043b4e08
         // 0040173c: mov ds:[esi+0x4], ecx
         // 0040173f: cmp ecx, ds:[esi+0x8]
      [-]8b460c5355bd
         // 00401748: mov eax, ds:[esi+0xc]
         // 0040174b: push ebx
         // 0040174c: push ebp
         // 0040174d: mov ebp, 0x441098
      [-]5785c0741a
         // 00401752: push edi
         // 00401753: test eax, eax
         // 00401755: jz 0x401771
      [-]3bc87616
         // 004018d3: cmp ecx, eax
         // 004018d5: jbe 0x4018ed
      [-]000083c40c8bcde8
         // 00401737: add esp, 0xc
         // 0040173a: mov ecx, ebp
         // 0040173c: call 0x406e92
      [-]8b46088b
         // 004018ed: mov eax, ds:[esi+0x8]
         // 004018f0: mov edi, ds:[esi+0x4]
      [-]04c1e80283c0200346083b
         // 004018f3: shr eax, b1 0x2
         // 004018f6: add eax, 0x20
         // 004018f9: add eax, ds:[esi+0x8]
         // 004018fc: cmp edi, eax
      [-]5ec20400
         // 00401921: pop esi
         // 00401922: retn b2 0x4
      [-]4e043b4e08
         // 004017f3: mov ds:[esi+0x4], ecx
         // 004017f6: cmp ecx, ds:[esi+0x8]
      [-]8b460c5355bd
         // 004017ff: mov eax, ds:[esi+0xc]
         // 00401802: push ebx
         // 00401803: push ebp
         // 00401804: mov ebp, 0x441098
      [-]5785c0741a
         // 00401809: push edi
         // 0040180a: test eax, eax
         // 0040180c: jz 0x401828
      [-]3bc87616
         // 00401946: cmp ecx, eax
         // 00401948: jbe 0x401960
      [-]000083c40c8bcde8
         // 004017ee: add esp, 0xc
         // 004017f1: mov ecx, ebp
         // 004017f3: call 0x406e92
      [-]8b46088b
         // 00401960: mov eax, ds:[esi+0x8]
         // 00401963: mov edi, ds:[esi+0x4]
      [-]04c1e80283c0200346083b
         // 00401966: shr eax, b1 0x2
         // 00401969: add eax, 0x20
         // 0040196c: add eax, ds:[esi+0x8]
         // 0040196f: cmp edi, eax
      [-]5ec20400
         // 00401997: pop esi
         // 00401998: retn b2 0x4
      [-]8b4424043b4108760b
         // 0040199b: mov eax, ss:[esp+0x4]
         // 0040199f: cmp eax, ds:[ecx+0x8]
         // 004019a2: jbe 0x4019af
      [-]2b410450e8
         // 004019a4: sub eax, ds:[ecx+0x4]
         // 004019a7: push eax
         // 004019a8: call 0x401925
      [-]ffffffeb03
         // 004019ad: jmp 0x4019b2
      [-]56ff7424088bf1e8
         // 00401893: push esi
         // 00401894: push ss:[esp+0x8]
         // 00401898: mov esi, ecx
         // 0040189a: call 0x4019d6
      [-]01000084c0751f
         // 0040189f: test b1 al, b1 al
         // 004018a1: jnz 0x4018c2
      [-]0000750b
         // 004018a9: jnz 0x4018b6
      [-]506a39e8
         // 004018de: push eax
         // 004018df: push 0x39
         // 004018e1: call 0x40138b
      [-]5ec20400
         // 004019e4: pop esi
         // 004019e5: retn b2 0x4
      [-]0000743d
         // 00401906: jz 0x401945
      [-]1083c0145350ff15
         // 00401911: add eax, 0x14
         // 00401914: push ebx
         // 00401915: push eax
         // 00401916: call ds:[___guard_check_icall_fptr]
      [-]000085c07415
         // 00401928: test eax, eax
         // 0040192a: jz 0x401941
      [-]8b4424103958040f97c0eb
         // 00401a94: mov eax, ss:[esp+0x10]
         // 00401a98: cmp ds:[eax+0x4], ebx
         // 00401a9b: setnbe b1 al
         // 00401a9e: jmp 0x401adc
      [-]105250ff15
         // 0040194d: push edx
         // 0040194e: push eax
         // 0040194f: call ds:[___guard_check_icall_fptr]
      [-]000085c074
         // 00401966: test eax, eax
         // 00401968: jz 0x40197b
      [-]ff7424108b
         // 0040196a: push ss:[esp+0x10]
         // 0040196e: mov ecx, esi
      [-]04000084c074
         // 00401975: test b1 al, b1 al
         // 00401977: jz 0x40197b
      [-]5f5e5bc20400
         // 00401adc: pop edi
         // 00401add: pop esi
         // 00401ade: pop ebx
         // 00401adf: retn b2 0x4
      [-]0000008b54240474
         // 0040198a: mov edx, ss:[esp+0x4]
         // 0040198e: jz 0x4019aa
      [-]83e00f03d083b9
         // 00401994: and eax, 0xf
         // 00401997: add edx, eax
         // 00401999: cmp ds:[ecx+0x6cc8], 0x3
      [-]83c210eb03
         // 00401b01: add edx, 0x10
         // 00401b04: jmp 0x401b09
      [-]8bc2c20400
         // 00401b09: mov eax, edx
         // 00401b0b: retn b2 0x4
      [-]558be980bd
         // 00401981: push ebp
         // 00401982: mov ebp, ecx
         // 00401984: cmp b1 ss:[ebp+0x6cb6], b1 0x0
      [-]0000007504
         // 0040198b: jnz 0x401991
      [-]32c0eb41
         // 00401b1a: xor b1 al, b1 al
         // 00401b1c: jmp 0x401b5f
      [-]8b45005356578b70148bceff15
         // 004019bf: mov eax, ss:[ebp+0x0]
         // 004019c2: push ebx
         // 004019c3: push esi
         // 004019c4: push edi
         // 004019c5: mov esi, ds:[eax+0x14]
         // 004019c8: mov ecx, esi
         // 004019ca: call ds:[___guard_check_icall_fptr]
      [-]43008bcdffd6ff7424148bcd8bf88bf2e8
         // 004019d0: mov ecx, ebp
         // 004019d2: call esi
         // 004019d4: push ss:[esp+0x14]
         // 004019d8: mov ecx, ebp
         // 004019da: mov edi, eax
         // 004019dc: mov esi, edx
         // 004019de: call 0x4018f6
      [-]ffffff8b4d008ad86a0056578b71108bceff15
         // 004019e3: mov ecx, ss:[ebp+0x0]
         // 004019e6: mov b1 bl, b1 al
         // 004019e8: push 0x0
         // 004019ea: push esi
         // 004019eb: push edi
         // 004019ec: mov esi, ds:[ecx+0x10]
         // 004019ef: mov ecx, esi
         // 004019f1: call ds:[___guard_check_icall_fptr]
      [-]43008bcdffd65f5e8ac35b
         // 004019f7: mov ecx, ebp
         // 004019f9: call esi
         // 004019fb: pop edi
         // 004019fc: pop esi
         // 004019fd: mov b1 al, b1 bl
         // 004019ff: pop ebx
      [-]5dc20400
         // 00401b5f: pop ebp
         // 00401b60: retn b2 0x4
      [-]000000ff15
         // 00401a36: call ds:[___guard_check_icall_fptr]
      [-]43008bcbffd6
         // 00401a3c: mov ecx, ebx
         // 00401a3e: call esi
      [-]03000085c074
         // 00401a5d: test eax, eax
         // 00401a5f: jz 0x401aa0
      [-]83f8010f85
         // 00401a36: cmp eax, 0x1
         // 00401a39: jnz 0x401b75
      [-]8b3b568b77148bceff15
         // 00401bcb: mov edi, ds:[ebx]
         // 00401bcd: push esi
         // 00401bce: mov esi, ds:[edi+0x14]
         // 00401bd1: mov ecx, esi
         // 00401bd3: call ds:[___guard_check_icall_fptr]
      [-]43008bcbffd68b4f1083e80783da005250ff15
         // 00401bd9: mov ecx, ebx
         // 00401bdb: call esi
         // 00401bdd: mov ecx, ds:[edi+0x10]
         // 00401be0: sub eax, 0x7
         // 00401be3: sbb edx, 0x0
         // 00401be6: push edx
         // 00401be7: push eax
         // 00401be8: call ds:[___guard_check_icall_fptr]
      [-]43008bcbff5710
         // 00401bee: mov ecx, ebx
         // 00401bf0: call ds:[edi+0x10]
      [-]68????????8d4d
         // 00401b6c: push 0x200000
         // 00401b71: lea ecx, ss:[ebp+0xffffffffffffffcc]
      [-]8b038975fc8b70148bceff15
         // 00401b79: mov eax, ds:[ebx]
         // 00401b7b: mov ss:[ebp+0xfffffffffffffffc], esi
         // 00401b7e: mov esi, ds:[eax+0x14]
         // 00401b81: mov ecx, esi
         // 00401b83: call ds:[___guard_check_icall_fptr]
      [-]43008bcbffd68b4d
         // 00401b89: mov ecx, ebx
         // 00401b8b: call esi
         // 00401b8f: mov ecx, ss:[ebp+0xffffffffffffffd0]
      [-]43008bcbff560c8bc833f6894dec85c90f8e
         // 00401ba6: mov ecx, ebx
         // 00401ba8: call ds:[esi+0xc]
         // 00401bab: mov ecx, eax
         // 00401bad: xor esi, esi
         // 00401baf: mov ss:[ebp+0xffffffffffffffec], ecx
         // 00401bb2: test ecx, ecx
         // 00401bb4: jle 0x401c5a
      [-]80395275
         // 00401abe: cmp b1 ds:[ecx], b1 0x52
         // 00401ac1: jnz 0x401b0d
      [-]2bc65051e8
         // 00401ac3: sub eax, esi
         // 00401ac5: push eax
         // 00401ac6: push ecx
         // 00401ac7: call 0x401dd8
      [-]000085c074
         // 00401acc: test eax, eax
         // 00401ace: jz 0x401b0a
      [-]8b4de88983
         // 00401ad0: mov ecx, ss:[ebp+0xffffffffffffffe8]
         // 00401ad3: mov ds:[ebx+0x6cb0], eax
      [-]83f80175
         // 00401ad9: cmp eax, 0x1
         // 00401adc: jnz 0x401b14
      [-]83f91c7d
         // 00401c6d: cmp ecx, 0x1c
         // 00401c70: jge 0x401c9e
      [-]837dec1f7e
         // 00401c72: cmp ss:[ebp+0xffffffffffffffec], 0x1f
         // 00401c76: jle 0x401c9e
      [-]2bc180781c527512
         // 00401c7a: sub eax, ecx
         // 00401c7c: cmp b1 ds:[eax+0x1c], b1 0x52
         // 00401c80: jnz 0x401c94
      [-]80781d53750c
         // 00401c82: cmp b1 ds:[eax+0x1d], b1 0x53
         // 00401c86: jnz 0x401c94
      [-]80781e467506
         // 00401c88: cmp b1 ds:[eax+0x1e], b1 0x46
         // 00401c8c: jnz 0x401c94
      [-]80781f58740a
         // 00401c8e: cmp b1 ds:[eax+0x1f], b1 0x58
         // 00401c92: jz 0x401c9e
      [-]463bf07c
         // 00401c97: inc esi
         // 00401c98: cmp esi, eax
         // 00401c9a: jl 0x401c46
      [-]8b0303ce6a006a00898b
         // 00401b48: mov eax, ds:[ebx]
         // 00401b4a: add ecx, esi
         // 00401b4c: push 0x0
         // 00401b4e: push 0x0
         // 00401b50: mov ds:[ebx+0x6cd8], ecx
      [-]8b7010518bceff15
         // 00401b56: mov esi, ds:[eax+0x10]
         // 00401b59: push ecx
         // 00401b5a: mov ecx, esi
         // 00401b5c: call ds:[___guard_check_icall_fptr]
      [-]43008bcbffd68b83
         // 00401b62: mov ecx, ebx
         // 00401b64: call esi
         // 00401b66: mov eax, ds:[ebx+0x6cc8]
      [-]83f8027405
         // 00401b6c: cmp eax, 0x2
         // 00401b6f: jz 0x401b76
      [-]83f80375
         // 00401b3d: cmp eax, 0x3
         // 00401b40: jnz 0x401b56
      [-]700c8bceff15
         // 00401b4a: mov ecx, esi
         // 00401b4c: call ds:[___guard_check_icall_fptr]
      [-]43008bcbffd6
         // 00401b52: mov ecx, ebx
         // 00401b54: call esi
      [-]83f80475
         // 00401bc2: cmp eax, 0x4
         // 00401bc5: jnz 0x401bd4
      [-]506a3ce8
         // 00401bca: push eax
         // 00401bcb: push 0x3c
         // 00401bcd: call 0x40138b
      [-]83f80375
         // 00401d2e: cmp eax, 0x3
         // 00401d31: jnz 0x401d5a
      [-]8b038dbb
         // 00401bd9: mov eax, ds:[ebx]
         // 00401bdb: lea edi, ds:[ebx+0x2217]
      [-]6a01578b700c8bceff15
         // 00401be1: push 0x1
         // 00401be3: push edi
         // 00401be4: mov esi, ds:[eax+0xc]
         // 00401be7: mov ecx, esi
         // 00401be9: call ds:[___guard_check_icall_fptr]
      [-]43008bcbffd683f801
         // 00401bef: mov ecx, ebx
         // 00401bf1: call esi
         // 00401bf3: cmp eax, 0x1
      [-]000085c00f95
         // 00401bb3: test eax, eax
         // 00401bb5: setnz b1 al
      [-]32c08845f3
         // 00401d76: xor b1 al, b1 al
         // 00401d78: mov b1 ss:[ebp+0xfffffffffffffff3], b1 al
      [-]00008b83
         // 00401c28: mov eax, ds:[ebx+0x21f4]
      [-]83f8010f84
         // 00401c2e: cmp eax, 0x1
         // 00401c31: jz 0x401d11
      [-]0000007409
         // 00401c11: jz 0x401c1c
      [-]83f8040f84
         // 00401d9a: cmp eax, 0x4
         // 00401d9d: jz 0x401e6b
      [-]000085c00f95
         // 00401bf3: test eax, eax
         // 00401bf5: setnz b1 al
      [-]000084c9740a
         // 00401c38: test b1 cl, b1 cl
         // 00401c3a: jz 0x401c46
      [-]807d08000f84
         // 00401d3e: cmp b1 ss:[ebp+0x8], b1 0x0
         // 00401d42: jz 0x401c6e
      [-]0000007504
         // 00401c4d: jnz 0x401c53
      [-]84c07519
         // 00401dd4: test b1 al, b1 al
         // 00401dd6: jnz 0x401df1
      [-]84c9750b
         // 00401dd8: test b1 cl, b1 cl
         // 00401dda: jnz 0x401de7
      [-]506a1be8
         // 00401c85: push eax
         // 00401c86: push 0x1b
         // 00401c88: call 0x40138b
      [-]807d08000f84
         // 00401d64: cmp b1 ss:[ebp+0x8], b1 0x0
         // 00401d68: jz 0x401c6e
      [-]807df2008a83
         // 00401c97: cmp b1 ss:[ebp+0xfffffffffffffff2], b1 0x0
         // 00401c9b: mov b1 al, b1 ds:[ebx+0x223c]
      [-]00008883
         // 00401ca1: mov b1 ds:[ebx+0x6cce], b1 al
      [-]00000f84
         // 00401ca7: jz 0x401dc1
      [-]0000000f85
         // 00401cbd: jnz 0x401dc1
      [-]8b038b70148bceff15
         // 00401ccd: mov eax, ds:[ebx]
         // 00401ccf: mov esi, ds:[eax+0x14]
         // 00401cd2: mov ecx, esi
         // 00401cd4: call ds:[___guard_check_icall_fptr]
      [-]43008bcbffd68bf08bfa8b83
         // 00401cda: mov ecx, ebx
         // 00401cdc: call esi
         // 00401cde: mov esi, eax
         // 00401ce0: mov edi, edx
         // 00401ce2: mov eax, ds:[ebx+0x6cb8]
      [-]8945e88b83
         // 00401ce8: mov ss:[ebp+0xffffffffffffffe8], eax
         // 00401ceb: mov eax, ds:[ebx+0x6cbc]
      [-]8945ec8b83
         // 00401cf1: mov ss:[ebp+0xffffffffffffffec], eax
         // 00401cf4: mov eax, ds:[ebx+0x6cc0]
      [-]8945e48b83
         // 00401cfa: mov ss:[ebp+0xffffffffffffffe4], eax
         // 00401cfd: mov eax, ds:[ebx+0x6cc4]
      [-]8945e08b83
         // 00401d03: mov ss:[ebp+0xffffffffffffffe0], eax
         // 00401d06: mov eax, ds:[ebx+0x21f4]
      [-]8945dceb
         // 00401d0c: mov ss:[ebp+0xffffffffffffffdc], eax
         // 00401d0f: jmp 0x401d54
      [-]83f80375
         // 00401d1e: cmp eax, 0x3
         // 00401d21: jnz 0x401d43
      [-]00000074
         // 00401d2a: jz 0x401d39
      [-]00000075
         // 00401d33: jnz 0x401d39
      [-]0000eb0a
         // 00401d0d: jmp 0x401d19
      [-]83f8027419
         // 00401e9d: cmp eax, 0x2
         // 00401ea0: jz 0x401ebb
      [-]83f80574
         // 00401ea2: cmp eax, 0x5
         // 00401ea5: jz 0x401ed9
      [-]000085c075
         // 00401d5b: test eax, eax
         // 00401d5d: jnz 0x401d18
      [-]00000074
         // 00401d68: jz 0x401d77
      [-]00000075
         // 00401d71: jnz 0x401d77
      [-]8b45e88983
         // 00401d7f: mov eax, ss:[ebp+0xffffffffffffffe8]
         // 00401d82: mov ds:[ebx+0x6cb8], eax
      [-]8b45ec8983
         // 00401d88: mov eax, ss:[ebp+0xffffffffffffffec]
         // 00401d8b: mov ds:[ebx+0x6cbc], eax
      [-]8b45e48983
         // 00401d91: mov eax, ss:[ebp+0xffffffffffffffe4]
         // 00401d94: mov ds:[ebx+0x6cc0], eax
      [-]8b45e08983
         // 00401d9a: mov eax, ss:[ebp+0xffffffffffffffe0]
         // 00401d9d: mov ds:[ebx+0x6cc4], eax
      [-]8b45dc8983
         // 00401da3: mov eax, ss:[ebp+0xffffffffffffffdc]
         // 00401da6: mov ds:[ebx+0x21f4], eax
      [-]8b036a0057568b70108bceff15
         // 00401dac: mov eax, ds:[ebx]
         // 00401dae: push 0x0
         // 00401db0: push edi
         // 00401db1: push esi
         // 00401db2: mov esi, ds:[eax+0x10]
         // 00401db5: mov ecx, esi
         // 00401db7: call ds:[___guard_check_icall_fptr]
      [-]43008bcbffd6
         // 00401dbd: mov ecx, ebx
         // 00401dbf: call esi
      [-]0000007409
         // 00401d95: jz 0x401da0
      [-]0000007415
         // 00401d9e: jz 0x401db5
      [-]68????????8d4b
         // 00401eaa: push 0x800
         // 00401eaf: lea ecx, ds:[ebx+0x32]
      [-]ff0f95c0c3
         // 00401f54: setnz b1 al
         // 00401f57: retn 
      [-]33c9837c240801724a
         // 00401f58: xor ecx, ecx
         // 00401f5a: cmp ss:[esp+0x8], 0x1
         // 00401f5f: jb 0x401fab
      [-]8b4424048038527541
         // 00401f61: mov eax, ss:[esp+0x4]
         // 00401f65: cmp b1 ds:[eax], b1 0x52
         // 00401f68: jnz 0x401fab
      [-]837c240807723a
         // 00401f6a: cmp ss:[esp+0x8], 0x7
         // 00401f6f: jb 0x401fab
      [-]807801617534
         // 00401f71: cmp b1 ds:[eax+0x1], b1 0x61
         // 00401f75: jnz 0x401fab
      [-]80780272752e
         // 00401f77: cmp b1 ds:[eax+0x2], b1 0x72
         // 00401f7b: jnz 0x401fab
      [-]807803217528
         // 00401f7d: cmp b1 ds:[eax+0x3], b1 0x21
         // 00401f81: jnz 0x401fab
      [-]8078041a7522
         // 00401f83: cmp b1 ds:[eax+0x4], b1 0x1a
         // 00401f87: jnz 0x401fab
      [-]80780507751c
         // 00401f89: cmp b1 ds:[eax+0x5], b1 0x7
         // 00401f8d: jnz 0x401fab
      [-]8a400684c07504
         // 00401f8f: mov b1 al, b1 ds:[eax+0x6]
         // 00401f92: test b1 al, b1 al
         // 00401f94: jnz 0x401f9a
      [-]6a02eb10
         // 00401f96: push 0x2
         // 00401f98: jmp 0x401faa
      [-]3c017504
         // 00401f9a: cmp b1 al, b1 0x1
         // 00401f9c: jnz 0x401fa2
      [-]6a03eb08
         // 00401f9e: push 0x3
         // 00401fa0: jmp 0x401faa
      [-]8bc1c20800
         // 00401fab: mov eax, ecx
         // 00401fad: retn b2 0x8
      [-]8bc18945f0895d
         // 00401e40: mov eax, ecx
         // 00401e42: mov ss:[ebp+0xfffffffffffffff0], eax
         // 00401e48: mov ss:[ebp+0xffffffffffffffe0], ebx
      [-]e0895de4895de8
         // 00401e4b: mov ss:[ebp+0xffffffffffffffe4], ebx
         // 00401e4e: mov ss:[ebp+0xffffffffffffffe8], ebx
      [-]53538d4d
         // 00401e54: push ebx
         // 00401e55: push ebx
         // 00401e56: lea ecx, ss:[ebp+0xffffffffffffffdc]
      [-]895dfc518bc8e8
         // 00401e59: mov ss:[ebp+0xfffffffffffffffc], ebx
         // 00401e5c: push ecx
         // 00401e5d: mov ecx, eax
         // 00401e5f: call 0x403b26
      [-]000084c0
         // 00401e64: test b1 al, b1 al
      [-]f8ffff8b4d
         // 00401e7b: mov ecx, ss:[ebp+0xffffffffffffffe0]
      [-]8b7508885c01ff8d4701508bcee8
         // 00401e81: mov esi, ss:[ebp+0x8]
         // 00401e84: mov b1 ds:[ecx+eax+0xffffffffffffffff], b1 bl
         // 00401e88: lea eax, ds:[edi+0x1]
         // 00401e8b: push eax
         // 00401e8c: mov ecx, esi
         // 00401e8e: call 0x401879
      [-]f9ffff8b45f083b8
         // 00401e93: mov eax, ss:[ebp+0xfffffffffffffff0]
         // 00401e96: cmp ds:[eax+0x6cb0], 0x3
      [-]ff7604ff36ff75
         // 00401e9f: push ds:[esi+0x4]
         // 00401ea2: push ds:[esi]
         // 00401ea4: push ss:[ebp+0xffffffffffffffdc]
      [-]0000017417
         // 00401eb5: jz 0x401ece
      [-]d1ef57ff36ff75
         // 00401eb7: shr edi, b1 0x1
         // 00401eb9: push edi
         // 00401eba: push ds:[esi]
         // 00401ebc: push ss:[ebp+0xffffffffffffffdc]
      [-]8b0633c966890c78eb0d
         // 00401ec4: mov eax, ds:[esi]
         // 00401ec6: xor ecx, ecx
         // 00401ec8: mov b2 ds:[eax+edi*0x2], b2 cx
         // 00401ecc: jmp 0x401edb
      [-]ff7604ff36ff75
         // 00401ece: push ds:[esi+0x4]
         // 00401ed1: push ds:[esi]
         // 00401ed3: push ss:[ebp+0xffffffffffffffdc]
      [-]020059508bcee8
         // 00401ee2: pop ecx
         // 00401ee3: push eax
         // 00401ee4: mov ecx, esi
         // 00401ee6: call 0x401879
      [-]56578bf96a008b07ffb7
         // 00401f47: push esi
         // 00401f48: push edi
         // 00401f49: mov edi, ecx
         // 00401f4b: push 0x0
         // 00401f4d: mov eax, ds:[edi]
         // 00401f4f: push ds:[edi+0x6cc4]
      [-]8b70108bceff15
         // 00401f5b: mov esi, ds:[eax+0x10]
         // 00401f5e: mov ecx, esi
         // 00401f60: call ds:[___guard_check_icall_fptr]
      [-]43008bcfffd65f5ec3
         // 00401f66: mov ecx, edi
         // 00401f68: call esi
         // 00401f6a: pop edi
         // 00401f6b: pop esi
         // 00401f6c: retn 
      [-]00000075
         // 00401f4a: jnz 0x401f71
      [-]33c08945
         // 004020bc: xor eax, eax
         // 004020be: mov ss:[ebp+0xffffffffffffffe4], eax
      [-]e48945e88945ec
         // 004020c1: mov ss:[ebp+0xffffffffffffffe8], eax
         // 004020c4: mov ss:[ebp+0xffffffffffffffec], eax
      [-]57ff7424088bf9e8
         // 00401f7f: push edi
         // 00401f80: push ss:[esp+0x8]
         // 00401f84: mov edi, ecx
         // 00401f86: call 0x409e37
      [-]000084c07431
         // 00401f8b: test b1 al, b1 al
         // 00401f8d: jz 0x401fc0
      [-]6a008bcfe8
         // 00401f8f: push 0x0
         // 00401f91: mov ecx, edi
         // 00401f93: call 0x4019d6
      [-]faffff84c07522
         // 00401f98: test b1 al, b1 al
         // 00401f9a: jnz 0x401fbe
      [-]506a39e8
         // 004020a4: push eax
         // 004020a5: push 0x39
         // 004020a7: call 0x401397
      [-]8b078b70088bceff15
         // 004020ac: mov eax, ds:[edi]
         // 004020ae: mov esi, ds:[eax+0x8]
         // 004020b1: mov ecx, esi
         // 004020b3: call ds:[___guard_check_icall_fptr]
      [-]43008bcfffd632c05eeb02
         // 004020b9: mov ecx, edi
         // 004020bb: call esi
         // 004020bd: xor b1 al, b1 al
         // 004020bf: pop esi
         // 004020c0: jmp 0x4020c4
      [-]5fc20400
         // 0040212c: pop edi
         // 0040212d: retn b2 0x4
      [-]558bec83ec
         // 004023c7: push ebp
         // 004023c8: mov ebp, esp
         // 004023ca: sub esp, 0x50
      [-]8b4424043b4108760b
         // 004025da: mov eax, ss:[esp+0x4]
         // 004025de: cmp eax, ds:[ecx+0x8]
         // 004025e1: jbe 0x4025ee
      [-]2b410450e8
         // 00402029: sub eax, ds:[ecx+0x4]
         // 0040202c: push eax
         // 0040202d: call 0x401702
      [-]ffffeb03
         // 00402032: jmp 0x402037
      [-]568bf18d46
         // 00402544: push esi
         // 00402545: mov esi, ecx
         // 00402547: lea eax, ds:[esi+0x32]
      [-]506a1ae8
         // 0040254a: push eax
         // 0040254b: push 0x1a
         // 0040254d: call 0x401397
      [-]000001e8
         // 00402560: call 0x407809
      [-]00005ec3
         // 00402565: pop esi
         // 00402566: retn 
      [-]33c03881
         // 00402066: xor eax, eax
         // 00402068: cmp b1 ds:[ecx+0x3371], b1 al
      [-]00000f94c04883e0f083c0208981
         // 0040206e: setz b1 al
         // 00402071: dec eax
         // 00402072: and eax, 0xfffffffffffffff0
         // 00402075: add eax, 0x20
         // 00402078: mov ds:[ecx+0x22a4], eax
      [-]568b742408578bf98b
         // 00402134: push esi
         // 00402135: mov esi, ss:[esp+0x8]
         // 00402139: push edi
         // 0040213a: mov edi, ecx
         // 0040213c: mov eax, ds:[esi+0x10fc]
      [-]33c03886
         // 004026c8: xor eax, eax
         // 004026ca: cmp b1 ds:[esi+0x10e9], b1 al
      [-]1000000f94c04883e0f083c020894624
         // 004026d0: setz b1 al
         // 004026d3: dec eax
         // 004026d4: and eax, 0xfffffffffffffff0
         // 004026d7: add eax, 0x20
         // 004026da: mov ds:[esi+0x24], eax
      [-]83f92f740e
         // 00402727: cmp ecx, 0x2f
         // 0040272a: jz 0x40273a
      [-]5f5ec20400
         // 0040274b: pop edi
         // 0040274c: pop esi
         // 0040274d: retn b2 0x4
      [-]568bf1578bbe
         // 00402753: push esi
         // 00402754: mov esi, ecx
         // 00402756: push edi
         // 00402757: mov edi, ds:[esi+0x6348]
      [-]00008bc885d20f8c
         // 00402198: mov ecx, eax
         // 0040219a: test edx, edx
         // 0040219c: jl 0x4027c7
      [-]85c90f84
         // 004021a4: test ecx, ecx
         // 004021a6: jz 0x4027c7
      [-]2bc60f84
         // 004021b2: sub eax, esi
         // 004021b4: jz 0x4027c7
      [-]85d20f8f
         // 004021ba: test edx, edx
         // 004021bc: jg 0x4027c7
      [-]3bc80f87
         // 004021c4: cmp ecx, eax
         // 004021c6: ja 0x4027c7
      [-]0e8bcf89
         // 00402292: mov ecx, edi
         // 00402294: mov ss:[esp+0x18], eax
      [-]00008bc80bca74
         // 00402228: mov ecx, eax
         // 0040222a: or ecx, edx
         // 0040222c: jz 0x40224c
      [-]837b04030f85
         // 0040232f: cmp ds:[ebx+0x4], 0x3
         // 00402333: jnz 0x402849
      [-]83fe070f87
         // 00402343: cmp esi, 0x7
         // 00402346: ja 0x402849
      [-]83ee010f84
         // 004022aa: sub esi, 0x1
         // 004022ad: jz 0x40265a
      [-]83ee010f84
         // 004022b3: sub esi, 0x1
         // 004022b6: jz 0x402633
      [-]8db3????????
         // 004022fa: lea esi, ds:[ebx+0x1028]
      [-]00008bc889
         // 00402332: mov ecx, eax
         // 00402334: mov ss:[esp+0x1c], eax
      [-]80e101888b
         // 00402341: and b1 cl, b1 0x1
         // 00402344: mov b1 ds:[ebx+0x2106], b1 cl
      [-]00008bc8c1e90380e101888b
         // 0040234a: mov ecx, eax
         // 0040234c: shr ecx, b1 0x3
         // 0040234f: and b1 cl, b1 0x1
         // 00402352: mov b1 ds:[ebx+0x2107], b1 cl
      [-]0000c683
         // 00402358: mov b1 ds:[ebx+0x2208], b1 0x0
      [-]22000000c6
         // 0040235f: mov b1 ss:[ebp+0x0], b1 0x0
      [-]0000a80174
         // 00402363: test b1 al, b1 0x1
         // 00402365: jz 0x40238c
      [-]00008bf0b8????????3bf07202
         // 00402383: mov esi, eax
         // 00402385: mov eax, 0xff
         // 0040238a: cmp esi, eax
         // 0040238c: jb 0x402390
      [-]000000740d
         // 00402bb7: jz 0x402bc6
      [-]000000740d
         // 00402bcd: jz 0x402bdc
      [-]00008983
         // 004023c9: mov ds:[ebx+0x230c], eax
      [-]00008bcfe8
         // 00402473: mov ecx, edi
         // 00402475: call 0x40c620
      [-]000085c00f84
         // 0040247a: test eax, eax
         // 0040247c: jz 0x4027b2
      [-]100000016a1450e8
         // 00402493: push 0x14
         // 00402495: push eax
         // 00402496: call 0x403fd6
      [-]000083c4108d
         // 0040249b: add esp, 0x10
         // 0040249e: lea eax, ss:[esp+0x30]
      [-]68????????508d432850e8
         // 004024a2: push 0x800
         // 004024a7: push eax
         // 004024a8: lea eax, ds:[ebx+0x28]
         // 004024ab: push eax
         // 004024ac: call 0x40fd6e
      [-]80e20288
         // 004024e0: and b1 dl, b1 0x2
         // 004024e3: mov b1 ss:[esp+0x15], b1 dl
      [-]8bcf84c07415
         // 00402ccf: mov ecx, edi
         // 00402cd1: test b1 al, b1 al
         // 00402cd3: jz 0x402cea
      [-]00006a00508d8b
         // 00402bec: push 0x0
         // 00402bee: push eax
         // 00402bef: lea ecx, ds:[ebx+0x1038]
      [-]000052508d8b
         // 00402c01: push edx
         // 00402c02: push eax
         // 00402c03: lea ecx, ds:[ebx+0x1038]
      [-]6a00508d8b
         // 004025c8: push 0x0
         // 004025ca: push eax
         // 004025cb: lea ecx, ds:[ebx+0x1040]
      [-]6a00508d8b
         // 004025f6: push 0x0
         // 004025f8: push eax
         // 004025f9: lea ecx, ds:[ebx+0x1048]
      [-]6a00508d8b
         // 00402620: push 0x0
         // 00402622: push eax
         // 00402623: lea ecx, ds:[ebx+0x1050]
      [-]000085c00f85
         // 0040263a: test eax, eax
         // 0040263c: jnz 0x4027b2
      [-]6a208d83
         // 00402642: push 0x20
         // 00402644: lea eax, ds:[ebx+0x1074]
      [-]000085c074
         // 00402661: test eax, eax
         // 00402663: jz 0x402691
      [-]6a1450e8
         // 0040266f: push 0x14
         // 00402671: push eax
         // 00402672: call 0x403fd6
      [-]83c410508d432850e8
         // 0040267f: add esp, 0x10
         // 00402682: push eax
         // 00402683: lea eax, ds:[ebx+0x28]
         // 00402686: push eax
         // 00402687: call 0x403f81
      [-]10000001c783
         // 00402f81: mov ds:[ebx+0x1094], 0x5
      [-]10000001
      [-]8bcbc645
         // 0040282e: mov ecx, ebx
         // 00402830: mov b1 ss:[ebp+0x5f], b1 0x1
      [-]00008b038d
         // 00402839: mov eax, ds:[ebx]
         // 0040283b: lea ecx, ss:[ebp+0x14]
      [-]6a08518b700c8bceff15
         // 0040283e: push 0x8
         // 00402840: push ecx
         // 00402841: mov esi, ds:[eax+0xc]
         // 00402844: mov ecx, esi
         // 00402846: call ds:[___guard_check_icall_fptr]
      [-]43008bcbffd683f808
         // 0040284c: mov ecx, ebx
         // 0040284e: call esi
         // 00402850: cmp eax, 0x8
      [-]f3a58a83
         // 00402a93: rep movsdd 
         // 00402a95: mov b1 al, b1 ds:[ebx+0x45b0]
      [-]00008b93
         // 00402a9b: mov edx, ds:[ebx+0x45b0]
      [-]24018883
         // 00402aa1: and b1 al, b1 0x1
         // 00402aa3: mov b1 ds:[ebx+0x45c4], b1 al
      [-]00008bca8bc2d1e9c1e80280e101c1ea03240180e201888b
         // 00402aa9: mov ecx, edx
         // 00402aab: mov eax, edx
         // 00402aad: shr ecx, b1 0x1
         // 00402aaf: shr eax, b1 0x2
         // 00402ab2: and b1 cl, b1 0x1
         // 00402ab5: shr edx, b1 0x3
         // 00402ab8: and b1 al, b1 0x1
         // 00402aba: and b1 dl, b1 0x1
         // 00402abd: mov b1 ds:[ebx+0x45c5], b1 cl
      [-]00008883
         // 00402ac3: mov b1 ds:[ebx+0x45c6], b1 al
      [-]00008893
         // 00402ac9: mov b1 ds:[ebx+0x45c7], b1 dl
      [-]000084c9740e
         // 00402acf: test b1 cl, b1 cl
         // 00402ad1: jz 0x402ae1
      [-]00008983
         // 00402a1d: mov ds:[ebx+0x45a4], eax
      [-]00000fb7c08983
         // 00402a38: movzx eax, b2 ax
         // 00402a3b: mov ds:[ebx+0x45a8], eax
      [-]b8????????
         // 0040335b: mov eax, 0x10000
      [-]c1e90583e107d3e0
         // 00403360: shr ecx, b1 0x5
         // 00403363: and ecx, 0x7
         // 00403366: shl eax, b1 cl
      [-]8bc2c1ea0bc1e80380e20124018896
         // 00403371: mov eax, edx
         // 00403373: shr edx, b1 0xb
         // 00403376: shr eax, b1 0x3
         // 00403379: and b1 dl, b1 0x1
         // 0040337c: and b1 al, b1 0x1
         // 0040337e: mov b1 ds:[esi+0x10eb], b1 dl
      [-]1000008886
         // 00403384: mov b1 ds:[esi+0x10ea], b1 al
      [-]100000e8
         // 0040338a: call 0x40eb9d
      [-]00008d4d
         // 0040338f: lea ecx, ss:[ebp+0xffffffffffffffc0]
      [-]894614e8
         // 00403392: mov ds:[esi+0x14], eax
         // 00403395: call 0x40eb9d
      [-]00008d4d
         // 0040339a: lea ecx, ss:[ebp+0xffffffffffffffc0]
      [-]00008d4d
         // 004033a5: lea ecx, ss:[ebp+0xffffffffffffffc0]
      [-]884618c786
         // 004033a8: mov b1 ds:[esi+0x18], b1 al
         // 004033ab: mov ds:[esi+0x1068], 0x2
      [-]00008d4d
         // 004033ba: lea ecx, ss:[ebp+0xffffffffffffffc0]
      [-]00008d4d
         // 004033c8: lea ecx, ss:[ebp+0xffffffffffffffc0]
      [-]00000fb6c8894e1c8d4d
         // 004033d3: movzx ecx, b1 al
         // 004033d6: mov ds:[esi+0x1c], ecx
         // 004033d9: lea ecx, ss:[ebp+0xffffffffffffffc0]
      [-]00002c308d4d
         // 004033e1: sub b1 al, b1 0x30
         // 004033e3: lea ecx, ss:[ebp+0xffffffffffffffc0]
      [-]884620e8
         // 004033e6: mov b1 ds:[esi+0x20], b1 al
         // 004033e9: call 0x40eb68
      [-]00000fb7
         // 004033ee: movzx ecx, b2 ax
      [-]10000001
      [-]1000007443
         // 004032ea: jz 0x40332f
      [-]8a4618c786
         // 0040332f: mov b1 al, b1 ds:[esi+0x18]
         // 00403332: mov ds:[esi+0x10f4], 0x2
      [-]33c0c786??
         // 004034af: xor eax, eax
         // 004034b1: mov ds:[esi+0x10f8], 0x1
      [-]83ff0274
         // 004034c2: cmp edi, 0x2
         // 004034c5: jz 0x4034ce
      [-]1000008b4608c1e80824018886
         // 00402c8b: mov eax, ds:[esi+0x8]
         // 00402c8e: shr eax, b1 0x8
         // 00402c91: and b1 al, b1 0x1
         // 00402c93: mov b1 ds:[esi+0x10f9], b1 al
      [-]10000074
         // 00402c99: jz 0x402cc7
      [-]00008d4d
         // 00402ca3: lea ecx, ss:[ebp+0x24]
      [-]0000837d
         // 00402cad: cmp ss:[ebp+0x54], 0xffffffffffffffff
      [-]33c00346148986
         // 00402d9d: xor eax, eax
         // 00402d9f: add eax, ds:[esi+0x14]
         // 00402da2: mov ds:[esi+0x1058], eax
      [-]33c00345
         // 00402daa: xor eax, eax
         // 00402dac: add eax, ss:[ebp+0x54]
      [-]f74608????????74
         // 004035ae: test ds:[esi+0x8], 0x200
         // 004035b5: jz 0x4035f0
      [-]020040593b
         // 00403490: inc eax
         // 00403491: pop ecx
         // 00403492: cmp edi, eax
      [-]68????????
         // 00402d8d: push 0x800
      [-]2bc8518d
         // 00402d95: sub ecx, eax
         // 00402d97: push ecx
         // 00402d98: lea ecx, ss:[ebp+0xffffffffffffdfd0]
      [-]03c1508bc18d4d
         // 00402d9e: add eax, ecx
         // 00402da0: push eax
         // 00402da1: mov eax, ecx
         // 00402da3: lea ecx, ss:[ebp+0x0]
      [-]6a0168????????
         // 00402da0: push 0x1
         // 00402da2: push 0x800
      [-]568bcbe8
         // 00402db4: push esi
         // 00402db5: mov ecx, ebx
         // 00402db7: call 0x40207f
      [-]68????????
         // 00403615: push 0x800
      [-]f74608????????
         // 0040362a: test ds:[esi+0x8], 0x400
      [-]0200595985c00f85
         // 00402e38: pop ecx
         // 00402e39: pop ecx
         // 00402e3a: test eax, eax
         // 00402e3c: jnz 0x402f13
      [-]83be????????140f82
         // 00402e2e: cmp ds:[esi+0x102c], 0x14
         // 00402e35: jb 0x402eff
      [-]8b70148bce
         // 0040359d: mov esi, ds:[eax+0x14]
         // 004035a0: mov ecx, esi
      [-]43008bcbffd68bf28bf85657ffb3
         // 004035ae: mov ecx, ebx
         // 004035b0: call esi
         // 004035b2: mov esi, edx
         // 004035b4: mov edi, eax
         // 004035b6: push esi
         // 004035b7: push edi
         // 004035b8: push ds:[ebx+0x1a54]
      [-]00005657
         // 004035c9: push esi
         // 004035ca: push edi
      [-]68????????5657
         // 004035cd: push 0xc8
         // 004035d2: push esi
         // 004035d3: push edi
      [-]01000383
         // 004035e2: add eax, ds:[ebx+0x1a50]
      [-]8d41018983
         // 00402ef1: lea eax, ds:[ecx+0x1]
         // 00402ef4: mov ds:[ebx+0x21c8], eax
      [-]0200595985c07507
         // 00402fc9: pop ecx
         // 00402fca: pop ecx
         // 00402fcb: test eax, eax
         // 00402fcd: jnz 0x402fd6
      [-]f74608????????7411
         // 00403752: test ds:[esi+0x8], 0x400
         // 00403759: jz 0x40376c
      [-]6a088d86
         // 00402f20: push 0x8
         // 00402f22: lea eax, ds:[esi+0x10a1]
      [-]0000f74608????????0f84
         // 00402f3f: test ds:[esi+0x8], 0x1000
         // 00402f46: jz 0x40302a
      [-]00000fb7c88d83
         // 0040365f: movzx ecx, b2 ax
         // 00403662: lea eax, ds:[ebx+0x2b70]
      [-]6a03592b
         // 00402f81: push 0x3
         // 00402f83: pop ecx
         // 00402f84: sub ecx, esi
      [-]c0e102d3
         // 00402f88: shl b1 cl, b1 0x2
         // 00402f8b: shr ebx, b1 cl
      [-]0fb6c0d3e083
         // 00402fe9: movzx eax, b1 al
         // 00402fec: shl eax, b1 cl
         // 00402fee: add esi, 0x8
      [-]0bc8894d
         // 00402ff4: or ecx, eax
         // 00402ff6: mov ss:[ebp+0xffffffffffffffe8], ecx
      [-]6bc1648b
         // 00403001: imul eax, ecx, b1 0x64
         // 00403004: mov ecx, ss:[ebp+esi*0x4]
      [-]000001e8
         // 00403137: call 0x406d83
      [-]0000807d
         // 0040313c: cmp b1 ss:[ebp+0x5a], b1 0x0
      [-]506a1ce8
         // 0040314c: push eax
         // 0040314d: push 0x1c
         // 0040314f: call 0x402021
      [-]33c0663983
         // 004031e2: xor eax, eax
         // 004031e4: cmp b2 ds:[ebx+0x2234], b2 ax
      [-]00008bc1d1e824018883
         // 0040316b: mov eax, ecx
         // 0040316d: shr eax, b1 0x1
         // 0040316f: and b1 al, b1 0x1
         // 00403171: mov b1 ds:[ebx+0x2224], b1 al
      [-]00008bc1c1e8082401c1e90480e1018883
         // 00403177: mov eax, ecx
         // 00403179: shr eax, b1 0x8
         // 0040317c: and b1 al, b1 0x1
         // 0040317e: shr ecx, b1 0x4
         // 00403181: and b1 cl, b1 0x1
         // 00403184: mov b1 ds:[ebx+0x6cb9], b1 al
      [-]0000888b
         // 0040318a: mov b1 ds:[ebx+0x6cba], b1 cl
      [-]00000fb7c03983
         // 0040319d: movzx eax, b2 ax
         // 004031a0: cmp ds:[ebx+0x21e4], eax
      [-]83f8790f84
         // 004031b2: cmp eax, 0x79
         // 004031b5: jz 0x40324a
      [-]83f8057553
         // 004039f8: cmp eax, 0x5
         // 004039fb: jnz 0x403a50
      [-]000000744a
         // 004031d0: jz 0x40321c
      [-]8b038b70148bceff15
         // 0040325c: mov eax, ds:[ebx]
         // 0040325e: mov esi, ds:[eax+0x14]
         // 00403261: mov ecx, esi
         // 00403263: call ds:[___guard_check_icall_fptr]
      [-]43008bcbffd68b3333c92bc7511bd18b4e105250ff15
         // 00403269: mov ecx, ebx
         // 0040326b: call esi
         // 0040326d: mov esi, ds:[ebx]
         // 0040326f: xor ecx, ecx
         // 00403271: sub eax, edi
         // 00403273: push ecx
         // 00403274: sbb edx, ecx
         // 00403276: mov ecx, ds:[esi+0x10]
         // 00403279: push edx
         // 0040327a: push eax
         // 0040327b: call ds:[___guard_check_icall_fptr]
      [-]43008bcbff5610c645
         // 00403281: mov ecx, ebx
         // 00403283: call ds:[esi+0x10]
         // 00403286: mov b1 ss:[ebp+0x5b], b1 0x1
      [-]0000f6d81ac0f6d02245
         // 00403207: neg b1 al
         // 00403209: sbb b1 al, b1 al
         // 0040320b: not b1 al
         // 0040320d: and b1 al, b1 ss:[ebp+0x5e]
      [-]83ef0175e8
         // 00403213: sub edi, 0x1
         // 00403216: jnz 0x403200
      [-]000000750d
         // 004032ff: jnz 0x40330e
      [-]0084c07404
         // 0040330a: test b1 al, b1 al
         // 0040330c: jz 0x403312
      [-]6a078d4d
         // 004033f7: push 0x7
         // 004033f9: lea ecx, ss:[ebp+0x30]
      [-]000083f807
         // 00403401: cmp eax, 0x7
      [-]00008d4d
         // 0040352e: lea ecx, ss:[ebp+0x30]
      [-]00008d4d
         // 00403538: lea ecx, ss:[ebp+0x30]
      [-]00008983
         // 00403546: mov ds:[ebx+0x2204], eax
      [-]c1e802240189
         // 0040354c: shr eax, b1 0x2
         // 0040354f: and b1 al, b1 0x1
         // 00403551: mov ds:[ebx+0x2208], edi
      [-]ffff6a03b9
         // 004034e9: push 0x3
         // 004034eb: mov ecx, 0x440f50
      [-]000001e8
         // 004034f7: call 0x406fc6
      [-]0000807d
         // 004034fc: cmp b1 ss:[ebp+0x6a], b1 0x0
      [-]33c0f683
         // 00403503: xor eax, eax
         // 00403505: test b1 ds:[ebx+0x21ec], b1 0x1
      [-]0000018945
         // 0040350c: mov ss:[ebp+0x58], eax
      [-]00008bf089
         // 00403555: mov esi, eax
         // 00403557: mov ss:[ebp+0x64], eax
      [-]f3a58d4d
         // 00403678: rep movsdd 
         // 0040367a: lea ecx, ss:[ebp+0x30]
      [-]000024018883
         // 00403682: and b1 al, b1 0x1
         // 00403684: mov b1 ds:[ebx+0x45c4], b1 al
      [-]000033c0668983
         // 0040368a: xor eax, eax
         // 0040368c: mov b2 ds:[ebx+0x45c6], b2 ax
      [-]00008883
         // 00403693: mov b1 ds:[ebx+0x45c5], b1 al
      [-]6a05598dbb
         // 004035f8: push 0x5
         // 004035fa: pop ecx
         // 004035fb: lea edi, ds:[ebx+0x2248]
      [-]f3a58d4d
         // 00403607: rep movsdd 
         // 00403609: lea ecx, ss:[ebp+0x30]
      [-]000085c074
         // 00403611: test eax, eax
         // 00403613: jz 0x40363d
      [-]6a1450e8
         // 0040361e: push 0x14
         // 00403620: push eax
         // 00403621: call 0x403fd6
      [-]000083c4108d
         // 00403626: add esp, 0x10
         // 00403629: lea eax, ss:[ebp+0x0]
      [-]8bcb508d43
         // 0040362c: mov ecx, ebx
         // 0040362e: push eax
         // 0040362f: lea eax, ds:[ebx+0x1e]
      [-]000024018d4d
         // 00403645: and b1 al, b1 0x1
         // 00403647: lea ecx, ss:[ebp+0x30]
      [-]00000fb6c08983
         // 00403655: movzx eax, b1 al
         // 00403658: mov ds:[ebx+0x2260], eax
      [-]83f8187608
         // 0040365e: cmp eax, 0x18
         // 00403661: jbe 0x40366b
      [-]6a108d83
         // 0040366b: push 0x10
         // 0040366d: lea eax, ds:[ebx+0x2264]
      [-]000080bb
         // 0040367c: cmp b1 ds:[ebx+0x225c], b1 0x0
      [-]00000074
         // 00403683: jz 0x4036e4
      [-]6a088db3
         // 00403e0e: push 0x8
         // 00403e10: lea esi, ds:[ebx+0x1b2c]
      [-]00006a048d45
         // 00403e1f: push 0x4
         // 00403e21: lea eax, ss:[ebp+0x58]
      [-]00008d45
         // 00403e2d: lea eax, ss:[ebp+0xffffffffffffff8c]
      [-]00006a08568d45
         // 00403e36: push 0x8
         // 00403e38: push esi
         // 00403e39: lea eax, ss:[ebp+0xffffffffffffff8c]
      [-]00006a048d
         // 00403e4f: push 0x4
         // 00403e51: lea eax, ss:[ebp+0x8]
      [-]010083c40cf7d81ac0fec08883
         // 00403e5e: add esp, 0xc
         // 00403e61: neg eax
         // 00403e63: sbb b1 al, b1 al
         // 00403e65: inc b1 al
         // 00403e67: mov b1 ds:[ebx+0x1b14], b1 al
      [-]000001e9
         // 004036eb: jmp 0x403a69
      [-]b8????????8986
         // 004040a2: mov eax, 0x7fffffff
         // 004040a7: mov ds:[esi+0x1058], eax
      [-]3bcf7c06
         // 004040cb: cmp ecx, edi
         // 004040cd: jl 0x4040d5
      [-]3bc27704
         // 004040d1: cmp eax, edx
         // 004040d3: ja 0x4040d9
      [-]8bc28bcf
         // 004040d5: mov eax, edx
         // 004040d7: mov ecx, edi
      [-]0000f686
         // 004037c5: test b1 ds:[esi+0x1094], b1 0x2
      [-]100000028946247416
         // 004037cc: mov ds:[esi+0x24], eax
         // 004037cf: jz 0x4037e7
      [-]00006a00508d8e
         // 004037d9: push 0x0
         // 004037db: push eax
         // 004037dc: lea ecx, ds:[esi+0x1040]
      [-]100000047418
         // 0040411d: jz 0x404137
      [-]00008986
         // 00403809: mov ds:[esi+0x1074], eax
      [-]00008bc8
         // 00404146: mov ecx, eax
      [-]c7461c????????
         // 00404164: mov ds:[esi+0x1c], 0x270f
      [-]00008d4d
         // 004038f1: lea ecx, ss:[ebp+0x30]
      [-]884618e8
         // 004038f4: mov b1 ds:[esi+0x18], b1 al
         // 004038f7: call 0x40ccfb
      [-]1000003ac27508
         // 0040391f: cmp b1 al, b1 dl
         // 00403921: jnz 0x40392b
      [-]84c07507
         // 004041ad: test b1 al, b1 al
         // 004041af: jnz 0x4041b8
      [-]8b4e088bc1c1e80322c28886
         // 00403890: mov ecx, ds:[esi+0x8]
         // 00403893: mov eax, ecx
         // 00403895: shr eax, b1 0x3
         // 00403898: and b1 al, b1 dl
         // 0040389a: mov b1 ds:[esi+0x1098], b1 al
      [-]1000008bc1c1e905c1e80422ca22c2888e
         // 004038a0: mov eax, ecx
         // 004038a2: shr ecx, b1 0x5
         // 004038a5: shr eax, b1 0x4
         // 004038a8: and b1 cl, b1 dl
         // 004038aa: and b1 al, b1 dl
         // 004038ac: mov b1 ds:[esi+0x10fa], b1 cl
      [-]100000837d
         // 004038b2: cmp ss:[ebp+0x60], 0x2
      [-]1000007509
         // 004038bf: jnz 0x4038ca
      [-]f6c1407404
         // 004041e9: test b1 cl, b1 0x40
         // 004041ec: jz 0x4041f2
      [-]56518d45
         // 00403954: push esi
         // 00403955: push ecx
         // 00403956: lea eax, ss:[ebp+0x30]
      [-]8bcb50e8
         // 00403959: mov ecx, ebx
         // 0040395b: push eax
         // 0040395c: call 0x40214e
      [-]568bcbe8
         // 00403a0d: push esi
         // 00403a0e: mov ecx, ebx
         // 00403a10: call 0x402134
      [-]00595985c075
         // 00403a22: pop ecx
         // 00403a23: pop ecx
         // 00403a24: test eax, eax
         // 00403a26: jnz 0x403a2f
      [-]00006a058bf78dbb
         // 00404325: push 0x5
         // 00404327: mov esi, edi
         // 00404329: lea edi, ds:[ebx+0x1a98]
      [-]59f3a58d4d
         // 0040432f: pop ecx
         // 00404330: rep movsdd 
         // 00404332: lea ecx, ss:[ebp+0xffffffffffffffc8]
      [-]00000074
         // 00403ad6: jz 0x403adc
      [-]578bf980bf
         // 00403a95: push edi
         // 00403a96: mov edi, ecx
         // 00403a98: cmp b1 ds:[edi+0x6cc5], b1 0x0
      [-]0000007404
         // 00403a9f: jz 0x403aa5
      [-]33c05fc3
         // 0040442a: xor eax, eax
         // 0040442c: pop edi
         // 0040442d: retn 
      [-]8b07568b70148bceff15
         // 00403b3d: mov eax, ds:[edi]
         // 00403b3f: push esi
         // 00403b40: mov esi, ds:[eax+0x14]
         // 00403b43: mov ecx, esi
         // 00403b45: call ds:[___guard_check_icall_fptr]
      [-]43008bcfffd68987
         // 00403b4b: mov ecx, edi
         // 00403b4d: call esi
         // 00403b4f: mov ds:[edi+0x6cb8], eax
      [-]33c98b87
         // 00403b55: xor ecx, ecx
         // 00403b57: mov eax, ds:[edi+0x6cc8]
      [-]5e83e801740e
         // 00403b64: pop esi
         // 00403b65: sub eax, 0x1
         // 00403b68: jz 0x403b78
      [-]83e80175
         // 0040445b: sub eax, 0x1
         // 0040445e: jnz 0x40449d
      [-]ffffeb07
         // 00403ade: jmp 0x403ae7
      [-]8bc885c974
         // 00404470: mov ecx, eax
         // 00404472: test ecx, ecx
         // 00404474: jz 0x40449d
      [-]ffff33c9
         // 00403b12: xor ecx, ecx
      [-]8bc15fc3
         // 004044a7: mov eax, ecx
         // 004044a9: pop edi
         // 004044aa: retn 
      [-]8bf180be
         // 00403b3b: mov esi, ecx
         // 00403b3d: cmp b1 ds:[esi+0x6cc4], b1 0x0
      [-]000000741c
         // 00403b44: jz 0x403b62
      [-]506a1de8
         // 00403b49: push eax
         // 00403b4a: push 0x1d
         // 00403b4c: call 0x401380
      [-]0000050f87
         // 00403b69: ja 0x403dab
      [-]33c083be
         // 00403b6f: xor eax, eax
         // 00403b71: cmp ds:[esi+0x6cb0], 0x3
      [-]030f95c04883e01583c01d3986
         // 00403b78: setnz b1 al
         // 00403b7b: dec eax
         // 00403b7c: and eax, 0x15
         // 00403b7f: add eax, 0x1d
         // 00403b82: cmp ds:[esi+0x45ec], eax
      [-]00007507
         // 00403ba2: jnz 0x403bab
      [-]0000538d8d
         // 00403bba: push ebx
         // 00403bbb: lea ecx, ss:[ebp+0xffffffffffff1914]
      [-]000033db8d8d
         // 00403bc6: xor ebx, ebx
         // 00403bc8: lea ecx, ss:[ebp+0xffffffffffff1914]
      [-]895dfce8
         // 00403bd5: mov ss:[ebp+0xfffffffffffffffc], ebx
         // 00403bd8: call 0x412bb2
      [-]506a1ee8
         // 004045aa: push eax
         // 004045ab: push 0x1e
         // 004045ad: call 0x401407
      [-]85ff7509
         // 004045b7: test edi, edi
         // 004045b9: jnz 0x4045c4
      [-]000001eb20
         // 00403c16: jmp 0x403c38
      [-]ffffffb6
         // 00403c25: push ds:[esi+0x5630]
      [-]0000745a
         // 00403c3e: jz 0x403c9a
      [-]00000f84
         // 00403c4c: jz 0x403d9a
      [-]23c88d82
         // 00404432: and ecx, eax
         // 00404434: lea eax, ds:[edx+0xb3d0]
      [-]5150ffb6
         // 0040443a: push ecx
         // 0040443b: push eax
         // 0040443c: push ds:[esi+0x4f14]
      [-]6a01ffb6
         // 00403cb1: push 0x1
         // 00403cb3: push ds:[esi+0x5640]
      [-]00008a45108886
         // 00403cf1: mov b1 al, b1 ss:[ebp+0x10]
         // 00403cfa: mov b1 ds:[esi+0x2111], b1 al
      [-]00008a86
         // 00403d00: mov b1 al, b1 ds:[esi+0x5669]
      [-]00008886
         // 00403d06: mov b1 ds:[esi+0x2137], b1 al
      [-]00008d86
         // 00403d0c: lea eax, ds:[esi+0x45d0]
      [-]65ffff389e
         // 00403d36: cmp b1 ds:[esi+0x45f0], b1 bl
      [-]0000eb12
         // 00403dd5: jmp 0x403de9
      [-]000084c0752b
         // 00403e0f: test b1 al, b1 al
         // 00403e11: jnz 0x403e3e
      [-]506a1fe8
         // 00403e1d: push eax
         // 00403e1e: push 0x1f
         // 00403e20: call 0x402021
      [-]000085ff740b
         // 00403e31: test edi, edi
         // 00403e33: jz 0x403e40
      [-]506a1ee8
         // 00403e54: push eax
         // 00403e55: push 0x1e
         // 00403e57: call 0x40138b
      [-]00000075
         // 004047a3: jnz 0x4047f4
      [-]506a02e8
         // 00403e8e: push eax
         // 00403e8f: push 0x2
         // 00403e91: call 0x411b42
      [-]000084c075
         // 00403e96: test b1 al, b1 al
         // 00403e98: jnz 0x403ece
      [-]8b07568b70088bceff15
         // 004047be: mov eax, ds:[edi]
         // 004047c0: push esi
         // 004047c1: mov esi, ds:[eax+0x8]
         // 004047c4: mov ecx, esi
         // 004047c6: call ds:[___guard_check_icall_fptr]
      [-]43008bcfffd66a02
         // 004047cc: mov ecx, edi
         // 004047ce: call esi
         // 004047d0: push 0x2
      [-]68????????b9
         // 004047d7: push 0xff
         // 004047dc: mov ecx, 0x4450c4
      [-]558bec8b550c5385d27c37
         // 00404815: push ebp
         // 00404816: mov ebp, esp
         // 00404818: mov edx, ss:[ebp+0xc]
         // 0040481b: push ebx
         // 0040481c: test edx, edx
         // 0040481e: jl 0x404857
      [-]8b4d087f04
         // 00404820: mov ecx, ss:[ebp+0x8]
         // 00404823: jg 0x404829
      [-]85c9722e
         // 00404825: test ecx, ecx
         // 00404827: jb 0x404857
      [-]837d14007c28
         // 00404829: cmp ss:[ebp+0x14], 0x0
         // 0040482d: jl 0x404857
      [-]837d10007220
         // 00404831: cmp ss:[ebp+0x10], 0x0
         // 00404835: jb 0x404857
      [-]83cbffb8????????2b5d101b45143bd07f0e
         // 00404837: or ebx, 0xffffffffffffffff
         // 0040483a: mov eax, 0x7fffffff
         // 0040483f: sub ebx, ss:[ebp+0x10]
         // 00404842: sbb eax, ss:[ebp+0x14]
         // 00404845: cmp edx, eax
         // 00404847: jg 0x404857
      [-]3bcb7708
         // 0040484b: cmp ecx, ebx
         // 0040484d: ja 0x404857
      [-]034d10135514eb06
         // 0040484f: add ecx, ss:[ebp+0x10]
         // 00404852: adc edx, ss:[ebp+0x14]
         // 00404855: jmp 0x40485d
      [-]8b4d188b551c
         // 00404857: mov ecx, ss:[ebp+0x18]
         // 0040485a: mov edx, ss:[ebp+0x1c]
      [-]8bc15b5dc21800
         // 0040485d: mov eax, ecx
         // 0040485f: pop ebx
         // 00404860: pop ebp
         // 00404861: retn b2 0x18
      [-]535556578bf133dbe8
         // 00403e8b: push ebx
         // 00403e8c: push ebp
         // 00403e8d: push esi
         // 00403e8e: push edi
         // 00403e8f: mov esi, ecx
         // 00403e91: xor ebx, ebx
         // 00403e93: call 0x403a95
      [-]fbffff8bf885ff7439
         // 00403e98: mov edi, eax
         // 00403e9a: test edi, edi
         // 00403e9c: jz 0x403ed7
      [-]8b6c2414
         // 00404877: mov ebp, ss:[esp+0x14]
      [-]83fd057409
         // 0040487b: cmp ebp, 0x5
         // 0040487e: jz 0x404889
      [-]43f6c37f7505
         // 00404889: inc ebx
         // 0040488a: test b1 bl, b1 0x7f
         // 0040488d: jnz 0x404894
      [-]ffff8bcee8
         // 00403eca: mov ecx, esi
         // 00403ecc: call 0x403a95
      [-]fbffff8bf885ff75cb
         // 00403ed1: mov edi, eax
         // 00403ed3: test edi, edi
         // 00403ed5: jnz 0x403ea2
      [-]5f5e5d5bc20400
         // 004048b2: pop edi
         // 004048b3: pop esi
         // 004048b4: pop ebp
         // 004048b5: pop ebx
         // 004048b6: retn b2 0x4
      [-]8bc7ebf5
         // 004048b9: mov eax, edi
         // 004048bb: jmp 0x4048b2
      [-]5356578bf133dbeb
         // 004048bd: push ebx
         // 004048be: push esi
         // 004048bf: push edi
         // 004048c0: mov esi, ecx
         // 004048c2: xor ebx, ebx
         // 004048c4: jmp 0x4048ff
      [-]43f6c37f7505
         // 004048cf: inc ebx
         // 004048d0: test b1 bl, b1 0x7f
         // 004048d3: jnz 0x4048da
      [-]ff7424108d
         // 00403fc9: push ss:[esp+0x10]
         // 00403fcd: lea ecx, ds:[esi+0x45e8]
      [-]ffff8bce
         // 00403f27: mov ecx, esi
      [-]fbffff8bf885ff75
         // 00403fea: mov edi, eax
         // 00403fec: test edi, edi
         // 00403fee: jnz 0x403fac
      [-]5f5e5bc20400
         // 0040490c: pop edi
         // 0040490d: pop esi
         // 0040490e: pop ebx
         // 0040490f: retn b2 0x4
      [-]8bc7ebf6
         // 00404912: mov eax, edi
         // 00404914: jmp 0x40490c
      [-]568bf1e8
         // 00403f40: push esi
         // 00403f41: mov esi, ecx
         // 00403f43: call 0x409885
      [-]00003986
         // 00403f48: cmp ds:[esi+0x6ca0], eax
      [-]506a38e8
         // 00403f6b: push eax
         // 00403f6c: push 0x38
         // 00403f6e: call 0x401380
      [-]2408506a22e8
         // 00403f88: push ss:[esp+0x8]
         // 00403f8c: push eax
         // 00403f8d: push 0x22
         // 00403f8f: call 0x401fc4
      [-]ffff6a01b9
         // 00403f94: push 0x1
         // 00403f96: mov ecx, 0x43ff50
      [-]0000c20800
         // 00403fa0: retn b2 0x8
      [-]8d442410506a00ff742414ff742414ff742414e8bbffffff83c414c3
         // 00404c00: lea eax, ss:[esp+0x10]
         // 00404c04: push eax
         // 00404c05: push 0x0
         // 00404c07: push ss:[esp+0x14]
         // 00404c0b: push ss:[esp+0x14]
         // 00404c0f: push ss:[esp+0x14]
         // 00404c13: call __vsprintf_s_l
         // 00404c18: add esp, 0x14
         // 00404c1b: retn 
      [-]8b4c2404e803000000c20400
         // 00404c20: mov ecx, ss:[esp+0x4]
         // 00404c24: call 0x404c2c
         // 00404c29: retn b2 0x4
      [-]53558bd9bd????????56578b73088b7b04eb26
         // 00404c2c: push ebx
         // 00404c2d: push ebp
         // 00404c2e: mov ebx, ecx
         // 00404c30: mov ebp, 0x200
         // 00404c35: push esi
         // 00404c36: push edi
         // 00404c37: mov esi, ds:[ebx+0x8]
         // 00404c3a: mov edi, ds:[ebx+0x4]
         // 00404c3d: jmp 0x404c65
      [-]81fe????????7207
         // 00404c48: cmp esi, 0x400
         // 00404c4e: jb 0x404c57
      [-]0f188f00020000
         // 00404c50: prefetcht0 b1 ds:[edi+0x200]
      [-]6a4057ff33e8
         // 004040e7: push 0x40
         // 004040e9: push edi
         // 004040ea: push ds:[ebx]
         // 004040ec: call 0x405769
      [-]000003fd2bf5
         // 004040f1: add edi, ebp
         // 004040f3: sub esi, ebp
      [-]3bf573d6
         // 00404c65: cmp esi, ebp
         // 00404c67: jnb 0x404c3f
      [-]5f5e5d5bc3
         // 00404c69: pop edi
         // 00404c6a: pop esi
         // 00404c6b: pop ebp
         // 00404c6c: pop ebx
         // 00404c6d: retn 
      [-]5355568b82????????8bb424
         // 0040410b: push ebx
         // 0040410c: push ebp
         // 0040410d: push esi
         // 0040410e: mov eax, ds:[edx+0xf8]
         // 00404114: mov esi, ss:[esp+0xe0]
      [-]a58bb2????????8d7c24
         // 0040413f: mov esi, ds:[edx+0xf4]
         // 00404145: lea edi, ss:[esp+0x5c]
      [-]6a0859f3a58b
         // 00404149: push 0x8
         // 0040414b: pop ecx
         // 0040414c: rep movsdd 
         // 00404150: mov eax, ds:[eax+0x4]
      [-]00000003
         // 00404164: add eax, ecx
      [-]00000003c603
         // 0040419e: add eax, esi
         // 004041a4: add esi, eax
      [-]00000003
         // 004041dc: add eax, ss:[esp+0x1c]
      [-]00000003
         // 004042b8: add eax, ss:[esp+0x3c]
      [-]00000003
         // 00404322: add eax, ss:[esp+0x1c]
      [-]00000003
         // 0040439c: add eax, edx
      [-]00000003
         // 00404414: add eax, edx
      [-]00000003
         // 00404488: add eax, ss:[esp+0x34]
      [-]00000003
         // 004044bc: add eax, ebx
      [-]442424c1
         // 004044dd: mov eax, ss:[esp+0x10]
         // 004044e1: ror ebx, b1 0x7
      [-]5f5e5d5b81c4
         // 00404516: pop edi
         // 00404517: pop esi
         // 00404518: pop ebp
         // 00404519: pop ebx
         // 0040451a: add esp, 0xbc
      [-]558bec83e4f083ec
         // 00404553: push ebp
         // 00404554: mov ebp, esp
         // 00404556: and esp, 0xfffffffffffffff0
         // 00404559: sub esp, 0x78
      [-]660f62ca660f6e
         // 004045a7: punpckldq b16 xmm1, b16 xmm2
         // 004045ab: movd b16 xmm6, edi
      [-]10660f72
         // 004045d9: psrld b16 xmm7, b1 0x10
      [-]89542420660ffe
         // 004045ec: mov ss:[esp+0x20], edx
         // 004045f0: paddd b16 xmm5, b16 ds:[0x43ee90]
      [-]28e0660f6e
         // 00404607: movd b16 xmm1, edi
      [-]660f72d00c660f72f414660f6ed2660fefe0660f62ca660f6e
         // 0040460b: psrld b16 xmm0, b1 0xc
         // 00404610: pslld b16 xmm4, b1 0x14
         // 00404615: movd b16 xmm2, edx
         // 00404619: pxor b16 xmm4, b16 xmm0
         // 0040461d: punpckldq b16 xmm1, b16 xmm2
         // 00404625: movd b16 xmm3, ecx
      [-]897424188b
         // 00404635: mov ss:[esp+0x18], esi
         // 00404639: mov esi, ds:[eax+0x30]
      [-]30660ffe
         // 0040463c: paddd b16 xmm3, b16 xmm4
      [-]897c24288b
         // 0040464c: mov ss:[esp+0x28], edi
         // 00404650: mov edi, ds:[eax+0x38]
      [-]89542414660fef
         // 0040465d: mov ss:[esp+0x14], edx
         // 00404661: pxor b16 xmm3, b16 xmm7
      [-]24100f28
         // 00404669: movaps b16 xmm2, b16 xmm3
      [-]897c2434660ffe
         // 0040466c: mov ss:[esp+0x34], edi
         // 00404670: paddd b16 xmm2, b16 xmm5
      [-]07660f72
         // 00404691: pslld b16 xmm1, b1 0x19
      [-]19660fef
         // 00404696: pxor b16 xmm1, b16 xmm0
      [-]20660f6ed78b
         // 004046a5: movd b16 xmm2, edi
         // 004046a9: mov edi, ds:[eax+0x3c]
      [-]3c660f6ec68b
         // 004046ac: movd b16 xmm0, esi
         // 004046b0: mov esi, ds:[eax+0x34]
      [-]34660f6eca660f62ca660f6e
         // 004046b3: movd b16 xmm1, edx
         // 004046b7: punpckldq b16 xmm1, b16 xmm2
         // 004046bb: movd b16 xmm7, ecx
      [-]8b7c2438660f
         // 004046f4: mov edi, ss:[esp+0x38]
         // 004046f8: movd b16 xmm1, ss:[esp+0xc]
      [-]6e4c240c660ffef40f28c6660f6e
         // 00404706: paddd b16 xmm6, b16 xmm4
         // 0040470a: movaps b16 xmm0, b16 xmm6
         // 0040470d: movd b16 xmm3, eax
      [-]72d00c660f72
         // 00404725: pslld b16 xmm4, b1 0x14
      [-]c6660f62
         // 00404732: punpckldq b16 xmm3, b16 xmm0
      [-]660f72d008660f72
         // 00404759: psrld b16 xmm0, b1 0x8
         // 0040475e: pslld b16 xmm3, b1 0x18
      [-]18660fef
         // 00404763: pxor b16 xmm3, b16 xmm0
      [-]07660f72
         // 0040478b: pslld b16 xmm1, b1 0x19
      [-]19660fef
         // 00404790: pxor b16 xmm1, b16 xmm0
      [-]93660f6e
         // 004047a1: movd b16 xmm1, ss:[esp+0x20]
      [-]10660f72
         // 004047c5: psrld b16 xmm0, b1 0x10
      [-]10660fef
         // 004047ca: pxor b16 xmm0, b16 xmm3
      [-]660f72d00c660f72
         // 004047e4: psrld b16 xmm0, b1 0xc
         // 004047e9: pslld b16 xmm4, b1 0x14
      [-]14660fef
         // 004047f4: pxor b16 xmm4, b16 xmm0
      [-]660f6ec7660f6e
         // 004047f8: movd b16 xmm0, edi
         // 004047fc: movd b16 xmm1, ecx
      [-]660f62ca660f6e
         // 00404800: punpckldq b16 xmm1, b16 xmm2
         // 00404804: movd b16 xmm3, edx
      [-]08660f72
         // 00404834: pslld b16 xmm3, b1 0x18
      [-]18660fef
         // 00404839: pxor b16 xmm3, b16 xmm0
      [-]07660f72
         // 00404863: pslld b16 xmm1, b1 0x19
      [-]19660fef
         // 00404868: pxor b16 xmm1, b16 xmm0
      [-]39660f6e
         // 0040487b: movd b16 xmm1, ss:[esp+0x2c]
      [-]660f72d00c660f72
         // 004048d4: psrld b16 xmm0, b1 0xc
         // 004048d9: pslld b16 xmm4, b1 0x14
      [-]14660fef
         // 004048de: pxor b16 xmm4, b16 xmm0
      [-]660f6e442414660f62
         // 004048e2: movd b16 xmm0, ss:[esp+0x14]
         // 004048e8: punpckldq b16 xmm3, b16 xmm0
      [-]660f72d008660f72
         // 00404909: psrld b16 xmm0, b1 0x8
         // 0040490e: pslld b16 xmm3, b1 0x18
      [-]93660f6e
         // 00404955: movd b16 xmm7, ss:[esp+0xc]
      [-]660f62f8660f62ca660f62f9660ffe7c24
         // 0040495b: punpckldq b16 xmm7, b16 xmm0
         // 0040495f: punpckldq b16 xmm1, b16 xmm2
         // 00404963: punpckldq b16 xmm7, b16 xmm1
         // 00404967: paddd b16 xmm7, b16 ss:[esp+0x50]
      [-]660f72d00c660f72
         // 004049ae: psrld b16 xmm0, b1 0xc
         // 004049b3: pslld b16 xmm4, b1 0x14
      [-]14660fef
         // 004049b8: pxor b16 xmm4, b16 xmm0
      [-]660f6e442424660f62
         // 004049bc: movd b16 xmm0, ss:[esp+0x24]
         // 004049c2: punpckldq b16 xmm3, b16 xmm0
      [-]660f6efa660ffe
         // 004049d3: movd b16 xmm7, edx
         // 004049d7: paddd b16 xmm3, b16 xmm4
      [-]660f72d008
         // 004049e7: psrld b16 xmm0, b1 0x8
      [-]18660fef
         // 004049f1: pxor b16 xmm3, b16 xmm0
      [-]07660f72
         // 00404a19: pslld b16 xmm1, b1 0x19
      [-]19660fef
         // 00404a1e: pxor b16 xmm1, b16 xmm0
      [-]39660f6e
         // 00404a31: movd b16 xmm1, ss:[esp+0x28]
      [-]ca660f62f9660ffe7c24
         // 00404a3b: punpckldq b16 xmm7, b16 xmm1
         // 00404a3f: paddd b16 xmm7, b16 ss:[esp+0x50]
      [-]660f6e542420660ffe
         // 00404a45: movd b16 xmm2, ss:[esp+0x20]
         // 00404a4b: paddd b16 xmm7, b16 xmm5
      [-]660f6e4c241c660f
         // 00404a4f: movd b16 xmm1, ss:[esp+0x1c]
         // 00404a55: pxor b16 xmm3, b16 xmm7
      [-]660f72d00c660f72
         // 00404a8a: psrld b16 xmm0, b1 0xc
         // 00404a8f: pslld b16 xmm4, b1 0x14
      [-]14660fef
         // 00404a94: pxor b16 xmm4, b16 xmm0
      [-]660f6e442410660f62
         // 00404a98: movd b16 xmm0, ss:[esp+0x10]
         // 00404a9e: punpckldq b16 xmm3, b16 xmm0
      [-]660f72d008660f72
         // 00404ac5: psrld b16 xmm0, b1 0x8
         // 00404aca: pslld b16 xmm3, b1 0x18
      [-]660f62f9660ffe7c24
         // 00404b19: punpckldq b16 xmm7, b16 xmm1
         // 00404b1d: paddd b16 xmm7, b16 ss:[esp+0x50]
      [-]660f6e4c24100f28
         // 00404b31: movd b16 xmm1, ss:[esp+0x10]
         // 00404b37: movaps b16 xmm0, b16 xmm3
      [-]660f62ca660f72
         // 00404b3a: punpckldq b16 xmm1, b16 xmm2
         // 00404b43: pslld b16 xmm3, b1 0x10
      [-]660f72d00c660f72
         // 00404b66: psrld b16 xmm0, b1 0xc
         // 00404b6b: pslld b16 xmm4, b1 0x14
      [-]14660fef
         // 00404b70: pxor b16 xmm4, b16 xmm0
      [-]660f6e442430660f62
         // 00404b74: movd b16 xmm0, ss:[esp+0x30]
         // 00404b7a: punpckldq b16 xmm3, b16 xmm0
      [-]660f6e7c2424660ffe
         // 00404b8b: movd b16 xmm7, ss:[esp+0x24]
         // 00404b91: paddd b16 xmm3, b16 xmm4
      [-]660f72d008660f72
         // 00404ba1: psrld b16 xmm0, b1 0x8
         // 00404ba6: pslld b16 xmm3, b1 0x18
      [-]07660f72
         // 00404bd3: pslld b16 xmm1, b1 0x19
      [-]19660fef
         // 00404bd8: pxor b16 xmm1, b16 xmm0
      [-]39660f6e
         // 00404be7: movd b16 xmm1, ss:[esp+0x18]
      [-]660f62f8660f62ca660f62f9660ffe7c24
         // 00404bed: punpckldq b16 xmm7, b16 xmm0
         // 00404bf1: punpckldq b16 xmm1, b16 xmm2
         // 00404bf5: punpckldq b16 xmm7, b16 xmm1
         // 00404bf9: paddd b16 xmm7, b16 ss:[esp+0x50]
      [-]10660f72
         // 00404c0f: psrld b16 xmm0, b1 0x10
      [-]660f72d00c660f72
         // 00404c40: psrld b16 xmm0, b1 0xc
         // 00404c45: pslld b16 xmm4, b1 0x14
      [-]14660fef
         // 00404c4a: pxor b16 xmm4, b16 xmm0
      [-]660f6e44242c660f62
         // 00404c4e: movd b16 xmm0, ss:[esp+0x2c]
         // 00404c54: punpckldq b16 xmm3, b16 xmm0
      [-]72d008660f72
         // 00404c7e: pslld b16 xmm3, b1 0x18
      [-]07660f72
         // 00404cab: pslld b16 xmm1, b1 0x19
      [-]19660fef
         // 00404cb0: pxor b16 xmm1, b16 xmm0
      [-]93660f6e
         // 00404cc3: movd b16 xmm1, ss:[esp+0x18]
      [-]ca660f62f9660ffe
         // 00404ccd: punpckldq b16 xmm7, b16 xmm1
         // 00404cd1: paddd b16 xmm7, b16 ss:[esp+0x50]
      [-]660f6ed70f28
         // 00404ce5: movd b16 xmm2, edi
         // 00404ce9: movaps b16 xmm0, b16 xmm3
      [-]660f62ca660f72
         // 00404cec: punpckldq b16 xmm1, b16 xmm2
         // 00404cf5: pslld b16 xmm3, b1 0x10
      [-]660f72d00c660f72
         // 00404d1a: psrld b16 xmm0, b1 0xc
         // 00404d1f: pslld b16 xmm4, b1 0x14
      [-]14660fef
         // 00404d24: pxor b16 xmm4, b16 xmm0
      [-]660f6e442420660f62
         // 00404d28: movd b16 xmm0, ss:[esp+0x20]
         // 00404d2e: punpckldq b16 xmm3, b16 xmm0
      [-]660f72d008660f72
         // 00404d4f: psrld b16 xmm0, b1 0x8
         // 00404d54: pslld b16 xmm3, b1 0x18
      [-]07660f72
         // 00404d73: pslld b16 xmm1, b1 0x19
      [-]19660fef
         // 00404d78: pxor b16 xmm1, b16 xmm0
      [-]660f6e4c240c660f
         // 00404d91: movd b16 xmm1, ss:[esp+0xc]
         // 00404d97: pshufd b16 xmm4, b16 xmm2, b1 0x4e
      [-]ca660f62f9660ffe7c24
         // 00404da6: punpckldq b16 xmm7, b16 xmm1
         // 00404daa: paddd b16 xmm7, b16 ss:[esp+0x50]
      [-]93660ffe
         // 00404db5: paddd b16 xmm7, b16 xmm5
      [-]10660ffe
         // 00404dea: paddd b16 xmm6, b16 xmm4
      [-]72d00c660f72
         // 00404dfd: pslld b16 xmm4, b1 0x14
      [-]14660fef
         // 00404e02: pxor b16 xmm4, b16 xmm0
      [-]660f6e7c2424660ffe
         // 00404e1b: movd b16 xmm7, ss:[esp+0x24]
         // 00404e21: paddd b16 xmm3, b16 xmm4
      [-]660f72d008
         // 00404e31: psrld b16 xmm0, b1 0x8
      [-]18660fef
         // 00404e3b: pxor b16 xmm3, b16 xmm0
      [-]07660f72
         // 00404e63: pslld b16 xmm1, b1 0x19
      [-]19660fef
         // 00404e68: pxor b16 xmm1, b16 xmm0
      [-]93660f6e
         // 00404e7b: movd b16 xmm1, ss:[esp+0x1c]
      [-]ca660f62f9660ffe
         // 00404e8b: punpckldq b16 xmm7, b16 xmm1
         // 00404e95: paddd b16 xmm7, b16 xmm5
      [-]10660f72
         // 00404ea9: psrld b16 xmm0, b1 0x10
      [-]10660fef
         // 00404eae: pxor b16 xmm0, b16 xmm3
      [-]660f72d00c660f72
         // 00404ece: psrld b16 xmm0, b1 0xc
         // 00404ed3: pslld b16 xmm4, b1 0x14
      [-]14660fef
         // 00404ed8: pxor b16 xmm4, b16 xmm0
      [-]660f6e44240c660f62
         // 00404edc: movd b16 xmm0, ss:[esp+0xc]
         // 00404eeb: punpckldq b16 xmm1, b16 xmm2
      [-]660f72d008660f72
         // 00404f0d: psrld b16 xmm0, b1 0x8
         // 00404f12: pslld b16 xmm3, b1 0x18
      [-]07660f72
         // 00404f41: pslld b16 xmm1, b1 0x19
      [-]19660fef
         // 00404f46: pxor b16 xmm1, b16 xmm0
      [-]f9660ffe7c24
         // 00404f65: paddd b16 xmm7, b16 ss:[esp+0x50]
      [-]660f72d00c660f72
         // 00404fac: psrld b16 xmm0, b1 0xc
         // 00404fb1: pslld b16 xmm4, b1 0x14
      [-]14660fef
         // 00404fb6: pxor b16 xmm4, b16 xmm0
      [-]660f6e442434660f62
         // 00404fba: movd b16 xmm0, ss:[esp+0x34]
         // 00404fc0: punpckldq b16 xmm3, b16 xmm0
      [-]660f6e7c2430660ffe
         // 00404fd1: movd b16 xmm7, ss:[esp+0x30]
         // 00404fd7: paddd b16 xmm3, b16 xmm4
      [-]660f72d008
         // 00404fe7: psrld b16 xmm0, b1 0x8
      [-]18660fef
         // 00404ff1: pxor b16 xmm3, b16 xmm0
      [-]93660f6e
         // 0040502f: movd b16 xmm1, ss:[esp+0x10]
      [-]660f62f8660f62ca660f62f9660ffe7c24
         // 00405035: punpckldq b16 xmm7, b16 xmm0
         // 00405039: punpckldq b16 xmm1, b16 xmm2
         // 0040503d: punpckldq b16 xmm7, b16 xmm1
         // 00405041: paddd b16 xmm7, b16 ss:[esp+0x50]
      [-]660f72d00c660f72
         // 00405088: psrld b16 xmm0, b1 0xc
         // 0040508d: pslld b16 xmm4, b1 0x14
      [-]14660fef
         // 00405092: pxor b16 xmm4, b16 xmm0
      [-]660f6ec6660f62
         // 00405096: movd b16 xmm0, esi
         // 0040509a: punpckldq b16 xmm3, b16 xmm0
      [-]660f72d008660f72
         // 004050c1: psrld b16 xmm0, b1 0x8
         // 004050c6: pslld b16 xmm3, b1 0x18
      [-]07660f72
         // 004050f3: pslld b16 xmm1, b1 0x19
      [-]19660fef
         // 004050f8: pxor b16 xmm1, b16 xmm0
      [-]660f62f9660ffe7c24
         // 00405113: punpckldq b16 xmm7, b16 xmm1
         // 00405117: paddd b16 xmm7, b16 ss:[esp+0x50]
      [-]660f6e4c24280f28
         // 0040512b: movd b16 xmm1, ss:[esp+0x28]
         // 00405131: movaps b16 xmm0, b16 xmm3
      [-]660f62ca660f72
         // 00405134: punpckldq b16 xmm1, b16 xmm2
         // 00405138: pslld b16 xmm3, b1 0x10
      [-]10660f72
         // 0040513d: psrld b16 xmm0, b1 0x10
      [-]660f72d00c660f72
         // 00405162: psrld b16 xmm0, b1 0xc
         // 00405167: pslld b16 xmm4, b1 0x14
      [-]14660fef
         // 0040516c: pxor b16 xmm4, b16 xmm0
      [-]660f6e442424660f62
         // 00405170: movd b16 xmm0, ss:[esp+0x24]
         // 00405176: punpckldq b16 xmm3, b16 xmm0
      [-]72d008660f72
         // 0040519c: pslld b16 xmm3, b1 0x18
      [-]07660f72
         // 004051cf: pslld b16 xmm1, b1 0x19
      [-]19660fef
         // 004051d4: pxor b16 xmm1, b16 xmm0
      [-]93660f6e
         // 004051e7: movd b16 xmm1, ss:[esp+0x14]
      [-]ca660f62f9660ffe7c24
         // 004051f1: punpckldq b16 xmm7, b16 xmm1
         // 004051f5: paddd b16 xmm7, b16 ss:[esp+0x50]
      [-]72d00c660f
         // 00405243: pslld b16 xmm4, b1 0x14
      [-]660f6e442410660f62
         // 0040524c: movd b16 xmm0, ss:[esp+0x10]
         // 00405252: punpckldq b16 xmm3, b16 xmm0
      [-]660f6e7c2418660ffe
         // 00405263: movd b16 xmm7, ss:[esp+0x18]
         // 00405269: paddd b16 xmm3, b16 xmm4
      [-]660f72d008
         // 00405279: psrld b16 xmm0, b1 0x8
      [-]18660fef
         // 00405283: pxor b16 xmm3, b16 xmm0
      [-]07660f72
         // 004052ad: pslld b16 xmm1, b1 0x19
      [-]19660fef
         // 004052b2: pxor b16 xmm1, b16 xmm0
      [-]660f62f9660ffe7c24
         // 004052cb: punpckldq b16 xmm7, b16 xmm1
         // 004052cf: paddd b16 xmm7, b16 ss:[esp+0x50]
      [-]10660f72
         // 004052e5: psrld b16 xmm0, b1 0x10
      [-]660f72d00c660f72
         // 00405310: psrld b16 xmm0, b1 0xc
         // 00405315: pslld b16 xmm4, b1 0x14
      [-]14660fef
         // 0040531e: pxor b16 xmm4, b16 xmm0
      [-]660f6e44241c660f62
         // 00405326: movd b16 xmm0, ss:[esp+0x1c]
         // 0040532c: punpckldq b16 xmm3, b16 xmm0
      [-]660f72d008660f72
         // 00405353: psrld b16 xmm0, b1 0x8
         // 00405358: pslld b16 xmm3, b1 0x18
      [-]07660f72
         // 00405387: pslld b16 xmm1, b1 0x19
      [-]19660fef
         // 0040538c: pxor b16 xmm1, b16 xmm0
      [-]ca660f62f9660ffe7c24
         // 004053a9: punpckldq b16 xmm7, b16 xmm1
         // 004053ad: paddd b16 xmm7, b16 ss:[esp+0x50]
      [-]660f72d00c660f72
         // 004053f2: psrld b16 xmm0, b1 0xc
         // 004053f7: pslld b16 xmm4, b1 0x14
      [-]14660fef
         // 004053fc: pxor b16 xmm4, b16 xmm0
      [-]660f6e442428660f62
         // 00405400: movd b16 xmm0, ss:[esp+0x28]
         // 00405406: punpckldq b16 xmm3, b16 xmm0
      [-]660f72d008
         // 00405427: psrld b16 xmm0, b1 0x8
      [-]18660fef
         // 00405431: pxor b16 xmm3, b16 xmm0
      [-]62f9660ffe7c24
         // 00405483: paddd b16 xmm7, b16 ss:[esp+0x50]
      [-]660f72d00c660f72
         // 004054ce: psrld b16 xmm0, b1 0xc
         // 004054d3: pslld b16 xmm4, b1 0x14
      [-]14660fef
         // 004054d8: pxor b16 xmm4, b16 xmm0
      [-]660f6e442420660f62
         // 004054dc: movd b16 xmm0, ss:[esp+0x20]
         // 004054e2: punpckldq b16 xmm3, b16 xmm0
      [-]72d008660f72
         // 0040550c: pslld b16 xmm3, b1 0x18
      [-]07660f72
         // 0040553b: pslld b16 xmm1, b1 0x19
      [-]19660fef
         // 00405540: pxor b16 xmm1, b16 xmm0
      [-]93660f6e
         // 00405553: movd b16 xmm1, ecx

  }
  condition:
    all of them
}
