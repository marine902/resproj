rule uztuby_10_4 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         010059c3
         // 004010a2: pop ecx
         // 004010a3: retn 
      [-]010059c3
         // 004010b8: pop ecx
         // 004010b9: retn 
      [-]bb????????85ff74
         // 00401115: mov ebx, 0x200
         // 0040111a: test edi, edi
         // 0040111c: jz 0x40115f
      [-]53578bc650e8
         // 004010de: push ebx
         // 004010df: push edi
         // 004010e0: mov eax, esi
         // 004010e2: push eax
         // 004010e3: call 0x40f160
      [-]00008bc650e8
         // 004010e8: mov eax, esi
         // 004010ea: push eax
         // 004010eb: call _wcslen
      [-]0200598d
         // 004010f0: pop ecx
         // 004010f1: lea esi, ss:[esp+0x6a]
      [-]8d34468d
         // 004010f5: lea esi, ds:[esi+eax*0x2]
         // 004010f8: lea eax, ss:[esp+0x68]
      [-]8bce2bc88bc3d1f92bc1505756e8
         // 004010fc: mov ecx, esi
         // 004010fe: sub ecx, eax
         // 00401100: mov eax, ebx
         // 00401102: sar ecx, b1 0x1
         // 00401104: sub eax, ecx
         // 00401106: push eax
         // 00401107: push edi
         // 00401108: push esi
         // 00401109: call 0x40f160
      [-]000056e8
         // 0040110e: push esi
         // 0040110f: call _wcslen
      [-]0200598d344683c602
         // 00401114: pop ecx
         // 00401115: lea esi, ds:[esi+eax*0x2]
         // 00401118: add esi, 0x2
      [-]8bce2bc88bc3d1f92bc15068
         // 0040111f: mov ecx, esi
         // 00401121: sub ecx, eax
         // 00401123: mov eax, ebx
         // 00401125: sar ecx, b1 0x1
         // 00401127: sub eax, ecx
         // 00401129: push eax
         // 0040112a: push 0xa2
      [-]00005056e8
         // 00401134: push eax
         // 00401135: push esi
         // 00401136: call 0x40f10e
      [-]000056e8
         // 0040113b: push esi
         // 0040113c: call _wcslen
      [-]0200598d8d
         // 00401141: pop ecx
         // 00401142: lea ecx, ss:[esp+0x68]
         // 00401146: lea esi, ds:[esi+eax*0x2]
      [-]344683c6028bc62bc1d1f82bd85368
         // 00401149: add esi, 0x2
         // 0040114c: mov eax, esi
         // 0040114e: sub eax, ecx
         // 00401150: sar eax, b1 0x1
         // 00401152: sub ebx, eax
         // 00401154: push ebx
         // 00401155: push 0x4302e0
      [-]000056e8
         // 00401160: push esi
         // 00401161: call _wcslen
      [-]020033c96a5866894c46028d
         // 00401166: xor ecx, ecx
         // 00401168: push 0x58
         // 0040116a: mov b2 ds:[esi+eax*0x2], b2 cx
         // 0040116f: lea eax, ss:[esp+0x18]
      [-]5e565150e8
         // 00401173: pop esi
         // 00401174: push esi
         // 00401175: push ecx
         // 00401176: push eax
         // 00401177: call _memset
      [-]8bf085f675
         // 004011e6: mov esi, eax
         // 004011e8: test esi, esi
         // 004011ea: jnz 0x401217
      [-]003d????????75
         // 0040120f: cmp eax, 0x3002
         // 00401214: jnz 0x401233
      [-]33c06689
         // 00401226: xor eax, eax
         // 00401228: mov b2 ds:[edi], b2 ax
      [-]5f5e0f95c05b
         // 00401245: pop edi
         // 00401246: pop esi
         // 00401247: setnz b1 al
         // 0040124a: pop ebx
      [-]0fb644240c50ff74240cff74240cff15
         // 004012c8: movzx eax, b1 ss:[esp+0xc]
         // 004012cd: push eax
         // 004012ce: push ss:[esp+0xc]
         // 004012d2: push ss:[esp+0xc]
         // 004012d6: call ds:[GetDlgItem]
      [-]0050ff15
         // 004012dc: push eax
         // 004012dd: call ds:[EnableWindow]
      [-]00c20c00
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
      [-]0050ff15
         // 00401301: push eax
         // 00401302: call ds:[ShowWindow]
      [-]00c20c00
         // 00401308: retn b2 0xc
      [-]558bec837d0c307459
         // 004012e7: push ebp
         // 004012e8: mov ebp, esp
         // 004012ea: cmp ss:[ebp+0xc], 0x30
         // 004012ee: jz 0x401349
      [-]817d0c????????755d
         // 004012f0: cmp ss:[ebp+0xc], 0x110
         // 004012f7: jnz 0x401356
      [-]8a4520b9
         // 004012f9: mov b1 al, b1 ss:[ebp+0x20]
         // 004012fc: mov ecx, 0x43cbd4
      [-]24010fb6c050ff7518ff7508e8
         // 00401301: and b1 al, b1 0x1
         // 00401303: movzx eax, b1 al
         // 00401306: push eax
         // 00401307: push ss:[ebp+0x18]
         // 0040130a: push ss:[ebp+0x8]
         // 0040130d: call 0x40cf27
      [-]0000f6452001743e
         // 00401312: test b1 ss:[ebp+0x20], b1 0x1
         // 00401316: jz 0x401356
      [-]ff7508ff15
         // 0040133c: push ss:[ebp+0x8]
         // 0040133f: call ds:[GetParent]
      [-]0085c07431
         // 00401345: test eax, eax
         // 00401347: jz 0x40137a
      [-]68????????50ff15
         // 00401349: push 0x3021
         // 0040134e: push eax
         // 0040134f: call ds:[GetDlgItem]
      [-]0085c07421
         // 00401355: test eax, eax
         // 00401357: jz 0x40137a
      [-]f6452008741b
         // 00401335: test b1 ss:[ebp+0x20], b1 0x8
         // 00401339: jz 0x401356
      [-]ff7508b9
         // 00401349: push ss:[ebp+0x8]
         // 0040134c: mov ecx, 0x43cbd4
      [-]32c05dc21c00
         // 00401356: xor b1 al, b1 al
         // 00401358: pop ebp
         // 00401359: retn b2 0x1c
      [-]8bf18975f0e8
         // 004013bc: mov esi, ecx
         // 004013be: mov ss:[ebp+0xfffffffffffffff0], esi
         // 004013c1: call 0x409451
      [-]000033dbc706
         // 004013c6: xor ebx, ebx
         // 004013c8: mov ds:[esi], 0x4302e8
      [-]895dfce8
         // 004013d4: mov ss:[ebp+0xfffffffffffffffc], ebx
         // 004013d7: call 0x405f9e
      [-]00008d8e
         // 004013dc: lea ecx, ds:[esi+0x20e8]
      [-]c645fc01e8
         // 004013e2: mov b1 ss:[ebp+0xfffffffffffffffc], b1 0x1
         // 004013e6: call 0x40c463
      [-]00008d8e
         // 004013eb: lea ecx, ds:[esi+0x2280]
      [-]0100008d8e
         // 00401402: lea ecx, ds:[esi+0x45d0]
      [-]c645fc040f94c0899e
         // 00401410: mov b1 ss:[ebp+0xfffffffffffffffc], b1 0x4
         // 00401414: setz b1 al
         // 00401417: mov ds:[esi+0x21bc], ebx
      [-]0100598945
         // 00401431: pop ecx
         // 00401432: mov ss:[ebp+0x8], eax
      [-]c645fc0585c07409
         // 00401435: mov b1 ss:[ebp+0xfffffffffffffffc], b1 0x5
         // 00401439: test eax, eax
         // 0040143b: jz 0x401446
      [-]0000838e
         // 00401428: or ds:[esi+0x21c0], 0xffffffffffffffff
      [-]ff6a408846
         // 0040143d: push 0x40
         // 0040143f: mov b1 ds:[esi+0x1c], b1 al
      [-]5350c786
         // 00401448: push ebx
         // 00401449: push eax
         // 0040144a: mov ds:[esi+0x6cb0], 0x2
      [-]6c000066899e
         // 00401478: mov b2 ds:[esi+0x6cc4], b2 bx
      [-]6c0000899e
         // 0040147f: mov ds:[esi+0x21d8], ebx
      [-]01006a348d86
         // 004014a2: push 0x34
         // 004014a4: lea eax, ds:[esi+0x2248]
      [-]01006a208d86
         // 004014b1: push 0x20
         // 004014b3: lea eax, ds:[esi+0x4590]
      [-]01008b4df483c424899e
         // 004014c0: mov ecx, ss:[ebp+0xfffffffffffffff4]
         // 004014c3: add esp, 0x24
         // 004014c6: mov ds:[esi+0x6cd8], ebx
      [-]33c0899e
         // 004014cc: xor eax, eax
         // 004014ce: mov ds:[esi+0x6ce0], ebx
      [-]00008bc6889e
         // 004014f9: mov eax, esi
         // 004014fb: mov b1 ds:[esi+0x6cd6], b1 bl
      [-]6c0000889e
         // 00401501: mov b1 ds:[esi+0x6cf8], b1 bl
      [-]0000889e
         // 00401507: mov b1 ds:[esi+0x21e0], b1 bl
      [-]2100005e5b64890d????????
         // 0040150d: pop esi
         // 0040150e: pop ebx
         // 0040150f: mov fs:[0x0], ecx
      [-]5133c0890c248981????????8981????????8981????????8981????????8881381000008981????????8981????????8981????????8981????????8981????????8981????????8bc159c3
         // 0040151c: push ecx
         // 0040151d: xor eax, eax
         // 0040151f: mov ss:[esp], ecx
         // 00401522: mov ds:[ecx+0x1028], eax
         // 00401528: mov ds:[ecx+0x102c], eax
         // 0040152e: mov ds:[ecx+0x1030], eax
         // 00401534: mov ds:[ecx+0x1034], eax
         // 0040153a: mov b1 ds:[ecx+0x1038], b1 al
         // 00401540: mov ds:[ecx+0x1040], eax
         // 00401546: mov ds:[ecx+0x1044], eax
         // 0040154c: mov ds:[ecx+0x1048], eax
         // 00401552: mov ds:[ecx+0x104c], eax
         // 00401558: mov ds:[ecx+0x1050], eax
         // 0040155e: mov ds:[ecx+0x1054], eax
         // 00401564: mov eax, ecx
         // 00401566: pop ecx
         // 00401567: retn 
      [-]56578bf1b8
         // 00401599: push esi
         // 0040159a: push edi
         // 0040159b: mov esi, ecx
         // 0040159d: mov eax, 0x4302e4
      [-]6a08598bfef3ab6a2033ff8d46205750e8
         // 004015a2: push 0x8
         // 004015a4: pop ecx
         // 004015a5: mov edi, esi
         // 004015a7: rep stosdd 
         // 004015a9: push 0x20
         // 004015ab: xor edi, edi
         // 004015ad: lea eax, ds:[esi+0x20]
         // 004015b0: push edi
         // 004015b1: push eax
         // 004015b2: call _memset
      [-]01008b44241883c40c897e40897e448946488bc65f5ec20400
         // 004015b7: mov eax, ss:[esp+0x18]
         // 004015bb: add esp, 0xc
         // 004015be: mov ds:[esi+0x40], edi
         // 004015c1: mov ds:[esi+0x44], edi
         // 004015c4: mov ds:[esi+0x48], eax
         // 004015c7: mov eax, esi
         // 004015c9: pop edi
         // 004015ca: pop esi
         // 004015cb: retn b2 0x4
      [-]558bec64a1????????6aff68
         // 00401615: push ebp
         // 00401616: mov ebp, esp
         // 00401618: mov eax, fs:[0x0]
         // 0040161e: push 0xffffffffffffffff
         // 00401620: push 0x42f605
      [-]50648925????????568bf1833e00741b
         // 00401625: push eax
         // 00401626: mov fs:[0x0], esp
         // 0040162d: push esi
         // 0040162e: mov esi, ecx
         // 00401630: cmp ds:[esi], 0x0
         // 00401633: jz 0x401650
      [-]807e1000740d
         // 00401604: cmp b1 ds:[esi+0x10], b1 0x0
         // 00401608: jz 0x401617
      [-]8b460803c050ff36e8
         // 0040163b: mov eax, ds:[esi+0x8]
         // 0040163e: add eax, eax
         // 00401640: push eax
         // 00401641: push ds:[esi]
         // 00401643: call 0x40e07b
      [-]8b4df464890d????????5e
         // 00401680: mov ecx, ss:[ebp+0xfffffffffffffff4]
         // 00401683: mov fs:[0x0], ecx
         // 0040168a: pop esi
      [-]568bf180be
         // 00401631: push esi
         // 00401632: mov esi, ecx
         // 00401634: cmp b1 ds:[esi+0x21b8], b1 0x0
      [-]21000000c706
         // 0040163b: mov ds:[esi], 0x4335b8
      [-]85ff7414
         // 00401647: test edi, edi
         // 00401649: jz 0x40165f
      [-]01005959
         // 0040168e: pop ecx
         // 0040168f: pop ecx
      [-]ffffff8d8e
         // 0040169c: lea ecx, ds:[esi+0x32a8]
      [-]ffffff8d8e
         // 004016a7: lea ecx, ds:[esi+0x20e8]
      [-]00008d8e
         // 004016b2: lea ecx, ds:[esi+0x1024]
      [-]00008bce5ee9
         // 004016bd: mov ecx, esi
         // 004016bf: pop esi
         // 004016c0: jmp 0x409487
      [-]568bf1e8
         // 004016b0: push esi
         // 004016b1: mov esi, ecx
         // 004016b3: call 0x401631
      [-]fffffff644240801740d
         // 004016b8: test b1 ss:[esp+0x8], b1 0x1
         // 004016bd: jz 0x4016cc
      [-]01005959
         // 0040172e: pop ecx
         // 0040172f: pop ecx
      [-]8bc65ec20400
         // 004016ff: mov eax, esi
         // 00401701: pop esi
         // 00401702: retn b2 0x4
      [-]8b4e043b4e080f869d000000
         // 0040170f: mov ecx, ds:[esi+0x4]
         // 00401712: cmp ecx, ds:[esi+0x8]
         // 00401715: jbe 0x4017b8
      [-]8b460c5355bd
         // 004016e8: mov eax, ds:[esi+0xc]
         // 004016eb: push ebx
         // 004016ec: push ebp
         // 004016ed: mov ebp, 0x440f50
      [-]5785c0741a
         // 004016f2: push edi
         // 004016f3: test eax, eax
         // 004016f5: jz 0x401711
      [-]3bc87616
         // 0040172a: cmp ecx, eax
         // 0040172c: jbe 0x401744
      [-]000083c40c8bcde8
         // 0040176b: add esp, 0xc
         // 0040176e: mov ecx, ebp
         // 00401770: call 0x406dc7
      [-]8b46088b5e04c1e80283c0200346083bd87702
         // 00401744: mov eax, ds:[esi+0x8]
         // 00401747: mov ebx, ds:[esi+0x4]
         // 0040174a: shr eax, b1 0x2
         // 0040174d: add eax, 0x20
         // 00401750: add eax, ds:[esi+0x8]
         // 00401753: cmp ebx, eax
         // 00401755: ja 0x401759
      [-]807e100053743a
         // 00401759: cmp b1 ds:[esi+0x10], b1 0x0
         // 0040175d: push ebx
         // 0040175e: jz 0x40179a
      [-]02008bf85985ff7507
         // 00401796: mov edi, eax
         // 00401798: pop ecx
         // 00401799: test edi, edi
         // 0040179b: jnz 0x4017a4
      [-]833e007438
         // 00401773: cmp ds:[esi], 0x0
         // 00401776: jz 0x4017b0
      [-]ff7608ff3657e8
         // 004017a9: push ds:[esi+0x8]
         // 004017ac: push ds:[esi]
         // 004017ae: push edi
         // 004017af: call _memmove
      [-]010083c40cff7608ff36e8
         // 004017b4: add esp, 0xc
         // 004017b7: push ds:[esi+0x8]
         // 004017ba: push ds:[esi]
         // 004017bc: call 0x40e07b
      [-]0000ff36e8
         // 004017c1: push ds:[esi]
         // 004017c3: call j___free_base
      [-]020059eb16
         // 004017c8: pop ecx
         // 004017c9: jmp 0x4017e1
      [-]02008bf8595985ff7507
         // 004017d2: mov edi, eax
         // 004017d4: pop ecx
         // 004017d5: pop ecx
         // 004017d6: test edi, edi
         // 004017d8: jnz 0x4017e1
      [-]893e5f5d895e085b
         // 004017b0: mov ds:[esi], edi
         // 004017b2: pop edi
         // 004017b3: pop ebp
         // 004017b4: mov ds:[esi+0x8], ebx
         // 004017b7: pop ebx
      [-]5ec20400
         // 004017b8: pop esi
         // 004017b9: retn b2 0x4
      [-]8b4e043b4e080f86a6000000
         // 004017c6: mov ecx, ds:[esi+0x4]
         // 004017c9: cmp ecx, ds:[esi+0x8]
         // 004017cc: jbe 0x401878
      [-]8b460c5355bd
         // 0040179f: mov eax, ds:[esi+0xc]
         // 004017a2: push ebx
         // 004017a3: push ebp
         // 004017a4: mov ebp, 0x440f50
      [-]5785c0741a
         // 004017a9: push edi
         // 004017aa: test eax, eax
         // 004017ac: jz 0x4017c8
      [-]3bc87616
         // 004017e1: cmp ecx, eax
         // 004017e3: jbe 0x4017fb
      [-]000083c40c8bcde8
         // 00401822: add esp, 0xc
         // 00401825: mov ecx, ebp
         // 00401827: call 0x406dc7
      [-]8b46088b5e04c1e80283c0200346083bd87702
         // 004017fb: mov eax, ds:[esi+0x8]
         // 004017fe: mov ebx, ds:[esi+0x4]
         // 00401801: shr eax, b1 0x2
         // 00401804: add eax, 0x20
         // 00401807: add eax, ds:[esi+0x8]
         // 0040180a: cmp ebx, eax
         // 0040180c: ja 0x401810
      [-]807e10008d041b507440
         // 00401810: cmp b1 ds:[esi+0x10], b1 0x0
         // 00401814: lea eax, ds:[ebx+ebx]
         // 00401817: push eax
         // 00401818: jz 0x40185a
      [-]02008bf85985ff7507
         // 00401850: mov edi, eax
         // 00401852: pop ecx
         // 00401853: test edi, edi
         // 00401855: jnz 0x40185e
      [-]833e00743e
         // 0040182d: cmp ds:[esi], 0x0
         // 00401830: jz 0x401870
      [-]8b460803c050ff3657e8
         // 00401863: mov eax, ds:[esi+0x8]
         // 00401866: add eax, eax
         // 00401868: push eax
         // 00401869: push ds:[esi]
         // 0040186b: push edi
         // 0040186c: call _memmove
      [-]01008b460883c40c03c050ff36e8
         // 00401871: mov eax, ds:[esi+0x8]
         // 00401874: add esp, 0xc
         // 00401877: add eax, eax
         // 00401879: push eax
         // 0040187a: push ds:[esi]
         // 0040187c: call 0x40e07b
      [-]0000ff36e8
         // 00401881: push ds:[esi]
         // 00401883: call j___free_base
      [-]020059eb16
         // 00401888: pop ecx
         // 00401889: jmp 0x4018a1
      [-]02008bf8595985ff7507
         // 00401892: mov edi, eax
         // 00401894: pop ecx
         // 00401895: pop ecx
         // 00401896: test edi, edi
         // 00401898: jnz 0x4018a1
      [-]893e5f5d895e085b
         // 00401870: mov ds:[esi], edi
         // 00401872: pop edi
         // 00401873: pop ebp
         // 00401874: mov ds:[esi+0x8], ebx
         // 00401877: pop ebx
      [-]5ec20400
         // 00401878: pop esi
         // 00401879: retn b2 0x4
      [-]8b4424043b4108760b
         // 0040187c: mov eax, ss:[esp+0x4]
         // 00401880: cmp eax, ds:[ecx+0x8]
         // 00401883: jbe 0x401890
      [-]2b410450e82effffffeb03
         // 00401885: sub eax, ds:[ecx+0x4]
         // 00401888: push eax
         // 00401889: call 0x4017bc
         // 0040188e: jmp 0x401893
      [-]56ff7424088bf1e8
         // 00401863: push esi
         // 00401864: push ss:[esp+0x8]
         // 00401868: mov esi, ecx
         // 0040186a: call 0x4019a6
      [-]01000084c0751f
         // 0040186f: test b1 al, b1 al
         // 00401871: jnz 0x401892
      [-]6c0000750b
         // 004018ac: jnz 0x4018b9
      [-]506a39e8
         // 004018e2: push eax
         // 004018e3: push 0x39
         // 004018e5: call 0x40135c
      [-]5ec20400
         // 004018c5: pop esi
         // 004018c6: retn b2 0x4
      [-]6c0000008b54240474
         // 004018d0: mov edx, ss:[esp+0x4]
         // 004018d4: jz 0x4018f1
      [-]83e00f03d083b9
         // 00401994: and eax, 0xf
         // 00401997: add edx, eax
         // 00401999: cmp ds:[ecx+0x6cc8], 0x3
      [-]83c210eb03
         // 004018e9: add edx, 0x10
         // 004018ec: jmp 0x4018f1
      [-]8bc2c20400
         // 004018f1: mov eax, edx
         // 004018f3: retn b2 0x4
      [-]6c00000075
         // 0040195b: jnz 0x401961
      [-]5dc20400
         // 004019ad: pop ebp
         // 004019ae: retn b2 0x4
      [-]010083ec
         // 004019b0: sub esp, 0x2c
      [-]6c000000
         // 004019c3: mov b1 ds:[ebx+0x6cbc], b1 0x0
         // 004019d6: call ds:[___guard_check_icall_fptr]
      [-]03000085c074
         // 00401a5d: test eax, eax
         // 00401a5f: jz 0x401aa0
      [-]83f8010f85
         // 00401a06: cmp eax, 0x1
         // 00401a09: jnz 0x401b45
      [-]68????????8d4d
         // 00401aa0: push 0x200000
         // 00401aa5: lea ecx, ss:[ebp+0xffffffffffffffc8]
      [-]83c1f051ff75
         // 00401ac6: add ecx, 0xfffffffffffffff0
         // 00401ac9: push ecx
         // 00401aca: push ss:[ebp+0xffffffffffffffc8]
      [-]894dec85c90f8e
         // 00401ae2: mov ss:[ebp+0xffffffffffffffec], ecx
         // 00401ae5: test ecx, ecx
         // 00401ae7: jle 0x401b8f
      [-]03ce803952754a
         // 00401a62: add ecx, esi
         // 00401a64: cmp b1 ds:[ecx], b1 0x52
         // 00401a67: jnz 0x401ab3
      [-]2bc65051e8
         // 00401af7: sub eax, esi
         // 00401af9: push eax
         // 00401afa: push ecx
         // 00401afb: call 0x401df8
      [-]000085c0743a
         // 00401b00: test eax, eax
         // 00401b02: jz 0x401b3e
      [-]8b4de889
         // 00401aa0: mov ecx, ss:[ebp+0xffffffffffffffe8]
         // 00401aa3: mov ds:[ebx+0x6cb0], eax
      [-]83f8017536
         // 00401aa9: cmp eax, 0x1
         // 00401aac: jnz 0x401ae4
      [-]85f67e32
         // 00401a84: test esi, esi
         // 00401a86: jle 0x401aba
      [-]83f91c7d2d
         // 00401a88: cmp ecx, 0x1c
         // 00401a8b: jge 0x401aba
      [-]837dec1f7e27
         // 00401a8d: cmp ss:[ebp+0xffffffffffffffec], 0x1f
         // 00401a91: jle 0x401aba
      [-]2bc180781c527512
         // 00401a96: sub eax, ecx
         // 00401a98: cmp b1 ds:[eax+0x1c], b1 0x52
         // 00401a9c: jnz 0x401ab0
      [-]80781d53750c
         // 00401a9e: cmp b1 ds:[eax+0x1d], b1 0x53
         // 00401aa2: jnz 0x401ab0
      [-]80781e467506
         // 00401aa4: cmp b1 ds:[eax+0x1e], b1 0x46
         // 00401aa8: jnz 0x401ab0
      [-]80781f58740a
         // 00401aaa: cmp b1 ds:[eax+0x1f], b1 0x58
         // 00401aae: jz 0x401aba
      [-]463bf07ca7
         // 00401ab3: inc esi
         // 00401ab4: cmp esi, eax
         // 00401ab6: jl 0x401a5f
      [-]83f8027405
         // 00401b6c: cmp eax, 0x2
         // 00401b6f: jz 0x401b76
      [-]83f80375
         // 00401b0d: cmp eax, 0x3
         // 00401b10: jnz 0x401b26
      [-]834dfcffe8
         // 00401b3c: or ss:[ebp+0xfffffffffffffffc], 0xffffffffffffffff
         // 00401b40: call 0x4015a0
      [-]83f80475
         // 00401b4b: cmp eax, 0x4
         // 00401b4e: jnz 0x401b60
      [-]506a3ce8
         // 00401b4a: push eax
         // 00401b4b: push 0x3c
         // 00401b4d: call 0x40135c
      [-]83f80375
         // 00401b60: cmp eax, 0x3
         // 00401b63: jnz 0x401b9d
      [-]000085c00f95
         // 00401b6d: test eax, eax
         // 00401b6f: setnz b1 al
      [-]83f8010f84
         // 00401bd1: cmp eax, 0x1
         // 00401bd4: jz 0x401cac
      [-]210000007409
         // 00401be1: jz 0x401bec
      [-]83f8040f84
         // 00401be3: cmp eax, 0x4
         // 00401be6: jz 0x401cac
      [-]1e000085c00f95
         // 00401bab: test eax, eax
         // 00401bad: setnz b1 al
      [-]6c000084c9740a
         // 00401c08: test b1 cl, b1 cl
         // 00401c0a: jz 0x401c16
      [-]807d08000f84
         // 00401c0c: cmp b1 ss:[ebp+0x8], b1 0x0
         // 00401c10: jz 0x4019e5
      [-]6c0000007504
         // 00401c1d: jnz 0x401c23
      [-]84c07519
         // 00401bd7: test b1 al, b1 al
         // 00401bd9: jnz 0x401bf4
      [-]84c9750b
         // 00401bdb: test b1 cl, b1 cl
         // 00401bdd: jnz 0x401bea
      [-]506a1be8
         // 00401c13: push eax
         // 00401c14: push 0x1b
         // 00401c16: call 0x40135c
      [-]807d08000f84
         // 00401c32: cmp b1 ss:[ebp+0x8], b1 0x0
         // 00401c36: jz 0x4019e5
      [-]807df2008a
         // 00401c3c: cmp b1 ss:[ebp+0xfffffffffffffff2], b1 0x0
         // 00401c40: mov b1 al, b1 ds:[ebx+0x2224]
      [-]22000088
         // 00401c46: mov b1 ds:[ebx+0x6cb6], b1 al
      [-]6c00000f84
         // 00401c4c: jz 0x401d5e
      [-]21000000740d
         // 00401c59: jz 0x401c68
      [-]6c0000000f85
         // 00401c62: jnz 0x401d5e
      [-]83f80375
         // 00401cb9: cmp eax, 0x3
         // 00401cbc: jnz 0x401cdf
      [-]6c00000074
         // 00401cc5: jz 0x401cd5
      [-]5600000075
         // 00401cce: jnz 0x401cd5
      [-]6c0000eb0a
         // 00401cdd: jmp 0x401ce9
      [-]83f8027419
         // 00401c96: cmp eax, 0x2
         // 00401c99: jz 0x401cb4
      [-]83f80574
         // 00401ce4: cmp eax, 0x5
         // 00401ce7: jz 0x401d1c
      [-]1d000085c075
         // 00401cdf: test eax, eax
         // 00401ce1: jnz 0x401c9b
      [-]6c00000074
         // 00401d04: jz 0x401d14
      [-]3300000075
         // 00401d0d: jnz 0x401d14
      [-]6c0000007409
         // 00401d65: jz 0x401d70
      [-]6c0000007415
         // 00401d6e: jz 0x401d85
      [-]68????????8d
         // 00401d48: push 0x800
         // 00401d4d: lea ecx, ds:[edi+0x1e]
      [-]ff0f95c0c3
         // 00401d45: setnz b1 al
         // 00401d48: retn 
      [-]33c9837c240801724a
         // 00401d49: xor ecx, ecx
         // 00401d4b: cmp ss:[esp+0x8], 0x1
         // 00401d50: jb 0x401d9c
      [-]8b4424048038527541
         // 00401d52: mov eax, ss:[esp+0x4]
         // 00401d56: cmp b1 ds:[eax], b1 0x52
         // 00401d59: jnz 0x401d9c
      [-]837c240807723a
         // 00401d5b: cmp ss:[esp+0x8], 0x7
         // 00401d60: jb 0x401d9c
      [-]807801617534
         // 00401d62: cmp b1 ds:[eax+0x1], b1 0x61
         // 00401d66: jnz 0x401d9c
      [-]80780272752e
         // 00401d68: cmp b1 ds:[eax+0x2], b1 0x72
         // 00401d6c: jnz 0x401d9c
      [-]807803217528
         // 00401d6e: cmp b1 ds:[eax+0x3], b1 0x21
         // 00401d72: jnz 0x401d9c
      [-]8078041a7522
         // 00401d74: cmp b1 ds:[eax+0x4], b1 0x1a
         // 00401d78: jnz 0x401d9c
      [-]80780507751c
         // 00401d7a: cmp b1 ds:[eax+0x5], b1 0x7
         // 00401d7e: jnz 0x401d9c
      [-]8a400684c07504
         // 00401d80: mov b1 al, b1 ds:[eax+0x6]
         // 00401d83: test b1 al, b1 al
         // 00401d85: jnz 0x401d8b
      [-]6a02eb10
         // 00401d87: push 0x2
         // 00401d89: jmp 0x401d9b
      [-]3c017504
         // 00401d8b: cmp b1 al, b1 0x1
         // 00401d8d: jnz 0x401d93
      [-]6a03eb08
         // 00401d8f: push 0x3
         // 00401d91: jmp 0x401d9b
      [-]8bc1c20800
         // 00401d9c: mov eax, ecx
         // 00401d9e: retn b2 0x8
      [-]01008b81
         // 00401ec9: mov eax, ds:[ecx+0x21bc]
      [-]83ec1480b8
         // 00401ecf: sub esp, 0x14
         // 00401ed2: cmp b1 ds:[eax+0x6152], b1 0x0
      [-]00000075
         // 00401ed9: jnz 0x401f00
      [-]33c08945e08945e48945e88945ec8845f08945fc8d45e050e8
         // 00401f89: xor eax, eax
         // 00401f8b: mov ss:[ebp+0xffffffffffffffe0], eax
         // 00401f8e: mov ss:[ebp+0xffffffffffffffe4], eax
         // 00401f91: mov ss:[ebp+0xffffffffffffffe8], eax
         // 00401f94: mov ss:[ebp+0xffffffffffffffec], eax
         // 00401f97: mov b1 ss:[ebp+0xfffffffffffffff0], b1 al
         // 00401f9a: mov ss:[ebp+0xfffffffffffffffc], eax
         // 00401f9d: lea eax, ss:[ebp+0xffffffffffffffe0]
         // 00401fa0: push eax
         // 00401fa1: call 0x4019af
      [-]8b4df464890d????????
         // 00401fd0: mov ecx, ss:[ebp+0xfffffffffffffff4]
         // 00401fd3: mov fs:[0x0], ecx
      [-]ff7424088b
         // 00401fdd: push ss:[esp+0x8]
         // 00401fe1: mov edi, ecx
      [-]000084c0
         // 00401fe8: test b1 al, b1 al
      [-]faffff84c075
         // 00401f68: test b1 al, b1 al
         // 00401f6a: jnz 0x401f8e
      [-]506a39e8
         // 00401f70: push eax
         // 00401f71: push 0x39
         // 00401f73: call 0x406dc1
      [-]558bec83ec4cff75088d4db4e8
         // 00402063: push ebp
         // 00402064: mov ebp, esp
         // 00402066: sub esp, 0x4c
         // 00402069: push ss:[ebp+0x8]
         // 0040206c: lea ecx, ss:[ebp+0xffffffffffffffb4]
         // 0040206f: call 0x4015c6
      [-]ffff8b4df483f9087330
         // 00402074: mov ecx, ss:[ebp+0xfffffffffffffff4]
         // 00402077: cmp ecx, 0x8
         // 0040207a: jnb 0x4020ac
      [-]8b450c89448db48b4df441894df483f908731d
         // 00401f75: mov eax, ss:[ebp+0xc]
         // 00401f78: mov ss:[ebp+ecx*0x4], eax
         // 00401f7c: mov ecx, ss:[ebp+0xfffffffffffffff4]
         // 00401f7f: inc ecx
         // 00401f80: mov ss:[ebp+0xfffffffffffffff4], ecx
         // 00401f83: cmp ecx, 0x8
         // 00401f86: jnb 0x401fa5
      [-]8b451089448db48b4df441894df483f908730a
         // 00401f88: mov eax, ss:[ebp+0x10]
         // 00401f8b: mov ss:[ebp+ecx*0x4], eax
         // 00401f8f: mov ecx, ss:[ebp+0xfffffffffffffff4]
         // 00401f92: inc ecx
         // 00401f93: mov ss:[ebp+0xfffffffffffffff4], ecx
         // 00401f96: cmp ecx, 0x8
         // 00401f99: jnb 0x401fa5
      [-]8b451489448db4ff45f4
         // 00401f9b: mov eax, ss:[ebp+0x14]
         // 00401f9e: mov ss:[ebp+ecx*0x4], eax
         // 00401fa2: inc ss:[ebp+0xfffffffffffffff4]
      [-]8d4db4e8
         // 00401fa5: lea ecx, ss:[ebp+0xffffffffffffffb4]
         // 00401fa8: call 0x4101df
      [-]8b4424043b4108760b
         // 00401fb8: mov eax, ss:[esp+0x4]
         // 00401fbc: cmp eax, ds:[ecx+0x8]
         // 00401fbf: jbe 0x401fcc
      [-]2b410450e8
         // 00401fae: sub eax, ds:[ecx+0x4]
         // 00401fb1: push eax
         // 00401fb2: call 0x401736
      [-]ffffeb03
         // 00401fb7: jmp 0x401fbc
      [-]568bf18d46
         // 00401fbf: push esi
         // 00401fc0: mov esi, ecx
         // 00401fc2: lea eax, ds:[esi+0x1e]
      [-]506a1ae8
         // 00401fc5: push eax
         // 00401fc6: push 0x1a
         // 00401fc8: call 0x40135c
      [-]6c000001e8
         // 00401fdb: call 0x406e8b
      [-]00005ec3
         // 00401fe0: pop esi
         // 00401fe1: retn 
      [-]33c03881
         // 00401ffe: xor eax, eax
         // 00402000: cmp b1 ds:[ecx+0x3371], b1 al
      [-]3300000f94c04883e0f083c0208981
         // 00402006: setz b1 al
         // 00402009: dec eax
         // 0040200a: and eax, 0xfffffffffffffff0
         // 0040200d: add eax, 0x20
         // 00402010: mov ds:[ecx+0x22a4], eax
      [-]568b742408578bf98b
         // 00402017: push esi
         // 00402018: mov esi, ss:[esp+0x8]
         // 0040201c: push edi
         // 0040201d: mov edi, ecx
         // 0040201f: mov edx, ds:[esi+0x10fc]
      [-]33c03886f11000000f94c04883e0f083c020894624
         // 0040202a: xor eax, eax
         // 0040202c: cmp b1 ds:[esi+0x10f1], b1 al
         // 00402032: setz b1 al
         // 00402035: dec eax
         // 00402036: and eax, 0xfffffffffffffff0
         // 00402039: add eax, 0x20
         // 0040203c: mov ds:[esi+0x24], eax
      [-]83f92f740e
         // 004021a6: cmp ecx, 0x2f
         // 004021a9: jz 0x4021b9
      [-]5f5ec20400
         // 0040209f: pop edi
         // 004020a0: pop esi
         // 004020a1: retn b2 0x4
      [-]568bf1578bbe
         // 004021cf: push esi
         // 004021d0: mov esi, ecx
         // 004021d2: push edi
         // 004021d3: mov edi, ds:[esi+0x6cd8]
      [-]5f13d25ec3
         // 00402202: pop edi
         // 00402203: adc edx, edx
         // 00402207: pop esi
         // 00402208: retn 
      [-]330000c3
         // 004020e5: retn 
      [-]0100578bbc24
         // 004020f0: push edi
         // 004020f1: mov edi, ss:[esp+0x20b8]
      [-]3b471c0f82
         // 00402108: cmp eax, ds:[edi+0x1c]
         // 0040210b: jb 0x402762
      [-]538b9c24
         // 0040211f: push ebx
         // 00402120: mov ebx, ss:[esp+0x20c4]
      [-]00008bc885d20f8c
         // 0040211d: mov ecx, eax
         // 0040211f: test edx, edx
         // 00402121: jl 0x40274c
      [-]85c90f84
         // 0040213c: test ecx, ecx
         // 0040213e: jz 0x40275f
      [-]8b47188b771c2bc60f84
         // 00402144: mov eax, ds:[edi+0x18]
         // 00402147: mov esi, ds:[edi+0x1c]
         // 0040214a: sub eax, esi
         // 0040214c: jz 0x40275f
      [-]85d20f8f05
         // 00402152: test edx, edx
         // 00402154: jg 0x40275f
      [-]3bc80f87
         // 0040215c: cmp ecx, eax
         // 0040215e: ja 0x40275f
      [-]0e8bcf89
         // 00402292: mov ecx, edi
         // 00402294: mov ss:[esp+0x18], eax
      [-]83fe0175
         // 0040219d: cmp esi, 0x1
         // 004021a0: jnz 0x40221f
      [-]0000894424
         // 0040219e: mov ss:[esp+0x1c], eax
      [-]00008bc80bca74
         // 004021ad: mov ecx, eax
         // 004021af: or ecx, edx
         // 004021b1: jz 0x4021d1
      [-]00008bc80bca74
         // 004021e0: mov ecx, eax
         // 004021e2: or ecx, edx
         // 004021e4: jz 0x402204
      [-]837b0402740a
         // 0040221f: cmp ds:[ebx+0x4], 0x2
         // 00402223: jz 0x40222f
      [-]837b04030f85
         // 00402225: cmp ds:[ebx+0x4], 0x3
         // 00402229: jnz 0x40274a
      [-]83fe070f87
         // 00402239: cmp esi, 0x7
         // 0040223c: ja 0x40274a
      [-]83ee010f84
         // 00402242: sub esi, 0x1
         // 00402245: jz 0x4025f2
      [-]83ee010f84
         // 0040224b: sub esi, 0x1
         // 0040224e: jz 0x4025cb
      [-]83ee010f84
         // 00402254: sub esi, 0x1
         // 00402257: jz 0x40244e
      [-]83ee010f84
         // 0040225d: sub esi, 0x1
         // 00402260: jz 0x4023f1
      [-]83ee010f84
         // 00402266: sub esi, 0x1
         // 00402269: jz 0x402373
      [-]83ee01743b
         // 0040226f: sub esi, 0x1
         // 00402272: jz 0x4022af
      [-]83ee010f85
         // 00402274: sub esi, 0x1
         // 00402277: jnz 0x40274a
      [-]8b47182b
         // 00402283: mov eax, ds:[edi+0x18]
         // 00402286: sub eax, ss:[esp+0x28]
      [-]83f8017503
         // 0040228a: cmp eax, 0x1
         // 0040228d: jnz 0x402292
      [-]8db3????????558bcee8
         // 00402292: lea esi, ds:[ebx+0x1028]
         // 00402298: push ebp
         // 00402299: mov ecx, esi
         // 0040229b: call 0x401fb8
      [-]fdffff55ff36
         // 004022a0: push ebp
         // 004022a1: push ds:[esi]
      [-]00008bc8894424
         // 004022a3: mov ecx, eax
         // 004022a5: mov ss:[esp+0x1c], eax
      [-]c1e9028dab????????80e101888b062100008bc8c1e90380e101888b07210000c6830822000000c6450000a80174
         // 004022a9: shr ecx, b1 0x2
         // 004022ac: lea ebp, ds:[ebx+0x2108]
         // 004022b2: and b1 cl, b1 0x1
         // 004022b5: mov b1 ds:[ebx+0x2106], b1 cl
         // 004022bb: mov ecx, eax
         // 004022bd: shr ecx, b1 0x3
         // 004022c0: and b1 cl, b1 0x1
         // 004022c3: mov b1 ds:[ebx+0x2107], b1 cl
         // 004022c9: mov b1 ds:[ebx+0x2208], b1 0x0
         // 004022d0: mov b1 ss:[ebp+0x0], b1 0x0
         // 004022d4: test b1 al, b1 0x1
         // 004022d6: jz 0x4022fd
      [-]00008bf0b8????????3bf07202
         // 004022df: mov esi, eax
         // 004022e1: mov eax, 0xff
         // 004022e6: cmp esi, eax
         // 004022e8: jb 0x4022ec
      [-]56558bcfe8
         // 004022ec: push esi
         // 004022ed: push ebp
         // 004022ee: mov ecx, edi
         // 004022f0: call 0x40c299
      [-]00008b4424
         // 004022f5: mov eax, ss:[esp+0x1c]
      [-]00008bf0b8????????3bf07202
         // 00402308: mov esi, eax
         // 0040230a: mov eax, 0xff
         // 0040230f: cmp esi, eax
         // 00402311: jb 0x402315
      [-]80bb0621000000740d
         // 0040233b: cmp b1 ds:[ebx+0x2106], b1 0x0
         // 00402342: jz 0x402351
      [-]00008983????????
         // 00402338: mov ds:[ebx+0x2308], eax
      [-]80bb0721000000740d
         // 00402351: cmp b1 ds:[ebx+0x2107], b1 0x0
         // 00402358: jz 0x402367
      [-]00008983????????
         // 0040234e: mov ds:[ebx+0x230c], eax
      [-]c6830521000001e9
         // 00402367: mov b1 ds:[ebx+0x2105], b1 0x1
         // 0040236e: jmp 0x40274a
      [-]00008bcf8983????????e8
         // 00402367: mov ecx, edi
         // 00402369: mov ds:[ebx+0x1100], eax
         // 0040236f: call 0x40c337
      [-]000024018bcf888304210000e8
         // 00402374: and b1 al, b1 0x1
         // 00402376: mov ecx, edi
         // 00402378: mov b1 ds:[ebx+0x2104], b1 al
         // 0040237e: call 0x40c337
      [-]00008bf0c68424
         // 00402383: mov esi, eax
         // 00402385: mov b1 ss:[esp+0xc0], b1 0x0
      [-]0000000081fe????????7318
         // 0040238d: cmp esi, 0x1fff
         // 00402393: jnb 0x4023ad
      [-]568d8424
         // 00402395: push esi
         // 00402396: lea eax, ss:[esp+0xc4]
      [-]8bcf50e8
         // 0040239d: mov ecx, edi
         // 0040239f: push eax
         // 004023a0: call 0x40c299
      [-]0000c68434
         // 004023a5: mov b1 ss:[esp+esi+0xc0], b1 0x0
      [-]00000000
      [-]68????????8d8424
         // 004023ad: push 0x2000
         // 004023b2: lea eax, ss:[esp+0xc4]
      [-]000068????????8d83????????508d8424
         // 004023c0: push 0x800
         // 004023c5: lea eax, ds:[ebx+0x1104]
         // 004023cb: push eax
         // 004023cc: lea eax, ss:[esp+0xc8]
      [-]00008bcfe8
         // 004023f8: mov ecx, edi
         // 004023fa: call 0x40c337
      [-]000085c00f84
         // 004023ff: test eax, eax
         // 00402401: jz 0x402737
      [-]c683f3100000016a1450e8
         // 00402411: mov b1 ds:[ebx+0x10f3], b1 0x1
         // 00402418: push 0x14
         // 0040241a: push eax
         // 0040241b: call 0x403f2b
      [-]1b000083c4108d4424
         // 00402420: add esp, 0x10
         // 00402423: lea eax, ss:[esp+0x30]
      [-]68????????508d432850e8
         // 00402427: push 0x800
         // 0040242c: push eax
         // 0040242d: lea eax, ds:[ebx+0x28]
         // 00402430: push eax
         // 00402431: call 0x40f138
      [-]00008844241324018a4c24138ad18844241480e202885424157435
         // 00402455: mov b1 ss:[esp+0x13], b1 al
         // 00402459: and b1 al, b1 0x1
         // 0040245b: mov b1 cl, b1 ss:[esp+0x13]
         // 0040245f: mov b1 dl, b1 cl
         // 00402461: mov b1 ss:[esp+0x14], b1 al
         // 00402465: and b1 dl, b1 0x2
         // 00402468: mov b1 ss:[esp+0x15], b1 dl
         // 0040246c: jz 0x4024a3
      [-]8bcf84c07415
         // 00402481: mov ecx, edi
         // 00402483: test b1 al, b1 al
         // 00402485: jz 0x40249c
      [-]00006a00508d8b????????e8
         // 00402479: push 0x0
         // 0040247b: push eax
         // 0040247c: lea ecx, ds:[ebx+0x1040]
         // 00402482: call 0x410153
      [-]0000eb12
         // 00402487: jmp 0x40249b
      [-]000052508d8b????????e8
         // 0040248e: push edx
         // 0040248f: push eax
         // 00402490: lea ecx, ds:[ebx+0x1040]
         // 00402496: call 0x410192
      [-]8a4c24138a442414
         // 004024ae: mov b1 cl, b1 ss:[esp+0x13]
         // 004024b2: mov b1 al, b1 ss:[esp+0x14]
      [-]80e104884c241674
         // 004024b6: and b1 cl, b1 0x4
         // 004024b9: mov b1 ss:[esp+0x16], b1 cl
         // 004024bd: jz 0x4024ec
      [-]8bcf84c074
         // 004025c3: mov ecx, edi
         // 004025c5: test b1 al, b1 al
         // 004025c7: jz 0x4025da
      [-]8a4424138ac880e108884c241774
         // 004024ec: mov b1 al, b1 ss:[esp+0x13]
         // 004024f0: mov b1 cl, b1 al
         // 004024f2: and b1 cl, b1 0x8
         // 004024f5: mov b1 ss:[esp+0x17], b1 cl
         // 004024f9: jz 0x40252f
      [-]807c2414008bcf7415
         // 004025f7: cmp b1 ss:[esp+0x14], b1 0x0
         // 00402602: mov ecx, edi
         // 00402604: jz 0x40261b
      [-]807c2414000f8410020000
         // 0040252f: cmp b1 ss:[esp+0x14], b1 0x0
         // 00402534: jz 0x40274a
      [-]a8100f8408020000
         // 0040253a: test b1 al, b1 0x10
         // 0040253c: jz 0x40274a
      [-]807c2415007427
         // 00402542: cmp b1 ss:[esp+0x15], b1 0x0
         // 00402547: jz 0x402570
      [-]0000bd????????be????????23c53bc6731a
         // 0040253d: mov ebp, 0x3fffffff
         // 00402542: mov esi, 0x3b9aca00
         // 00402547: and eax, ebp
         // 00402549: cmp eax, esi
         // 0040254b: jnb 0x402567
      [-]6a00508d8b????????e8
         // 0040254d: push 0x0
         // 0040254f: push eax
         // 00402550: lea ecx, ds:[ebx+0x1040]
         // 00402556: call 0x40fdfe
      [-]0000eb0a
         // 0040255b: jmp 0x402567
      [-]bd????????be????????
         // 00402570: mov ebp, 0x3fffffff
         // 00402575: mov esi, 0x3b9aca00
      [-]807c241600741b
         // 0040257a: cmp b1 ss:[esp+0x16], b1 0x0
         // 0040257f: jz 0x40259c
      [-]000023c53bc6730e
         // 00402575: and eax, ebp
         // 00402577: cmp eax, esi
         // 00402579: jnb 0x402589
      [-]6a00508d8b????????e8
         // 0040257b: push 0x0
         // 0040257d: push eax
         // 0040257e: lea ecx, ds:[ebx+0x1048]
         // 00402584: call 0x40fdfe
      [-]807c2417000f84a3010000
         // 0040259c: cmp b1 ss:[esp+0x17], b1 0x0
         // 004025a1: jz 0x40274a
      [-]000023c53bc60f8392010000
         // 0040259b: and eax, ebp
         // 0040259d: cmp eax, esi
         // 0040259f: jnb 0x402737
      [-]6a00508d8b????????e8
         // 004025a5: push 0x0
         // 004025a7: push eax
         // 004025a8: lea ecx, ds:[ebx+0x1050]
         // 004025ae: call 0x40fdfe
      [-]0000e97f010000
         // 004025b3: jmp 0x402737
      [-]000085c00f8570010000
         // 004025bf: test eax, eax
         // 004025c1: jnz 0x402737
      [-]6a208d83????????c783????????????????50e9
         // 004025da: push 0x20
         // 004025dc: lea eax, ds:[ebx+0x1074]
         // 004025e2: mov ds:[ebx+0x1070], 0x3
         // 004025ec: push eax
         // 004025ed: jmp 0x4022a3
      [-]000085c0742c
         // 004025e6: test eax, eax
         // 004025e8: jz 0x402616
      [-]6a1450e8
         // 004025f4: push 0x14
         // 004025f6: push eax
         // 004025f7: call 0x403f2b
      [-]1900008b4c24
         // 004025fc: mov ecx, ss:[esp+0x28]
      [-]83c410508d432850e8
         // 00402604: add esp, 0x10
         // 00402607: push eax
         // 00402608: lea eax, ds:[ebx+0x28]
         // 0040260b: push eax
         // 0040260c: call 0x403ed6
      [-]0000e921010000
         // 00402611: jmp 0x402737
      [-]00008ac8d1e880e1012401888bc11000008bcf8883ca100000e8
         // 0040261d: mov b1 cl, b1 al
         // 0040261f: shr eax, b1 0x1
         // 00402621: and b1 cl, b1 0x1
         // 00402624: and b1 al, b1 0x1
         // 00402626: mov b1 ds:[ebx+0x10c1], b1 cl
         // 0040262c: mov ecx, edi
         // 0040262e: mov b1 ds:[ebx+0x10ca], b1 al
         // 00402634: call 0x40c1ea
      [-]00000fb6c08983????????83f8187627
         // 00402639: movzx eax, b1 al
         // 0040263c: mov ds:[ebx+0x10ec], eax
         // 00402642: cmp eax, 0x18
         // 00402645: jbe 0x40266e
      [-]6a1450e8
         // 00402664: push 0x14
         // 00402666: push eax
         // 00402667: call 0x403f5b
      [-]00008b4c24
         // 0040266c: mov ecx, ss:[esp+0x28]
      [-]83c410508d432850e8
         // 00402674: add esp, 0x10
         // 00402677: push eax
         // 00402678: lea eax, ds:[ebx+0x28]
         // 0040267b: push eax
         // 0040267c: call 0x403f06
      [-]6a108d83????????8bcf50e8
         // 0040266e: push 0x10
         // 00402670: lea eax, ds:[ebx+0x10a1]
         // 00402676: mov ecx, edi
         // 00402678: push eax
         // 00402679: call 0x40c299
      [-]00006a108d83????????8bcf50e8
         // 0040267e: push 0x10
         // 00402680: lea eax, ds:[ebx+0x10b1]
         // 00402686: mov ecx, edi
         // 00402688: push eax
         // 00402689: call 0x40c299
      [-]000080bbc1100000000f8484000000
         // 0040268e: cmp b1 ds:[ebx+0x10c1], b1 0x0
         // 00402695: jz 0x40271f
      [-]6a088db3????????8bcf56e8
         // 0040269b: push 0x8
         // 0040269d: lea esi, ds:[ebx+0x10c2]
         // 004026a3: mov ecx, edi
         // 004026a5: push esi
         // 004026a6: call 0x40c299
      [-]00006a048d4424
         // 004026ab: push 0x4
         // 004026ad: lea eax, ss:[esp+0x30]
      [-]8bcf50e8
         // 004026b1: mov ecx, edi
         // 004026b3: push eax
         // 004026b4: call 0x40c299
      [-]00008d4424
         // 004026b9: lea eax, ss:[esp+0x58]
      [-]00006a08568d4424
         // 004026c3: push 0x8
         // 004026c5: push esi
         // 004026c6: lea eax, ss:[esp+0x60]
      [-]00008d4424
         // 004026d0: lea eax, ss:[esp+0x30]
      [-]508d4424
         // 004026d4: push eax
         // 004026d5: lea eax, ss:[esp+0x5c]
      [-]00006a048d4424
         // 004026df: push 0x4
         // 004026e1: lea eax, ss:[esp+0x34]
      [-]508d4424
         // 004026e5: push eax
         // 004026e6: lea eax, ss:[esp+0x34]
      [-]010083c40cf7d81ac0fec0837b04038883c1100000751a
         // 004026f0: add esp, 0xc
         // 004026f3: neg eax
         // 004026f5: sbb b1 al, b1 al
         // 004026f7: inc b1 al
         // 004026f9: cmp ds:[ebx+0x4], 0x3
         // 004026fd: mov b1 ds:[ebx+0x10c1], b1 al
         // 00402703: jnz 0x40271f
      [-]010083c40c85c07506
         // 00402712: add esp, 0xc
         // 00402715: test eax, eax
         // 00402717: jnz 0x40271f
      [-]8883c1100000
         // 0040272c: mov b1 ds:[ebx+0x10c1], b1 al
      [-]c683a010000001c783????????????????c6839b10000001
         // 00402732: mov b1 ds:[ebx+0x10a0], b1 0x1
         // 00402739: mov ds:[ebx+0x109c], 0x5
         // 00402743: mov b1 ds:[ebx+0x109b], b1 0x1
      [-]894f1c8b47182bc183f8020f83
         // 0040274e: mov ds:[edi+0x1c], ecx
         // 00402751: mov eax, ds:[edi+0x18]
         // 00402754: sub eax, ecx
         // 00402756: cmp eax, 0x2
         // 00402759: jnb 0x402129
      [-]8bcbc645
         // 004027b3: mov ecx, ebx
         // 004027b5: mov b1 ss:[ebp+0x5e], b1 0x1
      [-]1500008b038d4d
         // 004027be: mov eax, ds:[ebx]
         // 004027c0: lea ecx, ss:[ebp+0x14]
      [-]6a08518b
         // 004027c3: push 0x8
         // 004027c5: push ecx
         // 004027c6: mov ecx, ebx
      [-]33c98d45
         // 00402869: xor ecx, ecx
         // 0040286b: lea eax, ss:[ebp+0x14]
      [-]51515151508b83
         // 0040286e: push ecx
         // 0040286f: push ecx
         // 00402870: push ecx
         // 00402871: push ecx
         // 00402872: push eax
         // 00402873: mov eax, ds:[ebx+0x21bc]
      [-]506a04518bcee8
         // 00402884: push eax
         // 00402885: push 0x4
         // 00402887: push ecx
         // 00402888: mov ecx, esi
         // 0040288a: call 0x406249
      [-]00008975
         // 0040288f: mov ss:[ebp+0x44], esi
      [-]0000837d
         // 00402807: cmp ss:[ebp+0x3c], 0x0
      [-]00000fb7c08d4d
         // 00402821: movzx eax, b2 ax
         // 00402824: lea ecx, ss:[ebp+0x24]
      [-]000000e8
         // 00402834: call 0x40c1ea
      [-]00008d4d
         // 00402839: lea ecx, ss:[ebp+0x24]
      [-]0fb6f0e8
         // 0040283c: movzx esi, b1 al
         // 0040283f: call 0x40c202
      [-]00000fb7c08d4d
         // 00402844: movzx eax, b2 ax
         // 00402847: lea ecx, ss:[ebp+0x24]
      [-]c1e80e24018883
         // 00402850: shr eax, b1 0xe
         // 00402853: and b1 al, b1 0x1
         // 00402855: mov b1 ds:[ebx+0x21f4], b1 al
      [-]00000fb7c8898b
         // 00402860: movzx ecx, b2 ax
         // 00402863: mov ds:[ebx+0x21f0], ecx
      [-]3bcf730c
         // 0040286f: cmp ecx, edi
         // 00402871: jnb 0x40287f
      [-]f7ffffe9
         // 00402913: jmp 0x403264
      [-]0000ffb3
         // 00402903: push ds:[ebx+0x21f0]
      [-]efffff8b
         // 00402918: mov eax, ds:[ebx+0x6ca4]
      [-]f3a58a83
         // 00402a93: rep movsdd 
         // 00402a95: mov b1 al, b1 ds:[ebx+0x45b0]
      [-]4500008b93
         // 00402a9b: mov edx, ds:[ebx+0x45b0]
      [-]24018883
         // 00402aa1: and b1 al, b1 0x1
         // 00402aa3: mov b1 ds:[ebx+0x45c4], b1 al
      [-]4500008bca8bc2d1e9c1e80280e101c1ea03240180e201888b
         // 00402aa9: mov ecx, edx
         // 00402aab: mov eax, edx
         // 00402aad: shr ecx, b1 0x1
         // 00402aaf: shr eax, b1 0x2
         // 00402ab2: and b1 cl, b1 0x1
         // 00402ab5: shr edx, b1 0x3
         // 00402ab8: and b1 al, b1 0x1
         // 00402aba: and b1 dl, b1 0x1
         // 00402abd: mov b1 ds:[ebx+0x45c5], b1 cl
      [-]4500008883
         // 00402ac3: mov b1 ds:[ebx+0x45c6], b1 al
      [-]4500008893
         // 00402ac9: mov b1 ds:[ebx+0x45c7], b1 dl
      [-]45000084c9740e
         // 00402acf: test b1 cl, b1 cl
         // 00402ad1: jz 0x402ae1
      [-]00008983
         // 00402998: mov ds:[ebx+0x45a4], eax
      [-]450000000f84
         // 00402a3e: jz 0x4031a4
      [-]00000fb7c08983
         // 004029b3: movzx eax, b2 ax
         // 004029b6: mov ds:[ebx+0x45a8], eax
      [-]83ff0274
         // 00402b9d: cmp edi, 0x2
         // 00402ba0: jz 0x402ba8
      [-]8886fa100000b8????????23c83bc80f94c08886f110000081f9????????7507
         // 00402a72: mov b1 ds:[esi+0x10fa], b1 al
         // 00402a78: mov eax, 0xe0
         // 00402a7d: and ecx, eax
         // 00402a7f: cmp ecx, eax
         // 00402a81: setz b1 al
         // 00402a84: mov b1 ds:[esi+0x10f1], b1 al
         // 00402a8a: cmp ecx, 0xe0
         // 00402a90: jnz 0x402a99
      [-]8bc28b5608eb12
         // 00402a92: mov eax, edx
         // 00402a94: mov edx, ds:[esi+0x8]
         // 00402a97: jmp 0x402aab
      [-]8b5608b8????????8bcac1e90583e107d3e0
         // 00402a99: mov edx, ds:[esi+0x8]
         // 00402a9c: mov eax, 0x10000
         // 00402aa1: mov ecx, edx
         // 00402aa3: shr ecx, b1 0x5
         // 00402aa6: and ecx, 0x7
         // 00402aa9: shl eax, b1 cl
      [-]8986????????8d4d
         // 00402be3: mov ds:[esi+0x10f4], eax
         // 00402be9: lea ecx, ss:[ebp+0x1c]
      [-]8bc2c1ea0bc1e80380e20124018896f31000008886f2100000e8
         // 00402bec: mov eax, edx
         // 00402bee: shr edx, b1 0xb
         // 00402bf1: shr eax, b1 0x3
         // 00402bf4: and b1 dl, b1 0x1
         // 00402bf7: and b1 al, b1 0x1
         // 00402bf9: mov b1 ds:[esi+0x10f3], b1 dl
         // 00402bff: mov b1 ds:[esi+0x10f2], b1 al
         // 00402c05: call 0x40cbfb
      [-]00008d4d
         // 00402c0a: lea ecx, ss:[ebp+0x1c]
      [-]894614e8
         // 00402c0d: mov ds:[esi+0x14], eax
         // 00402c10: call 0x40cbfb
      [-]00008d4d
         // 00402c15: lea ecx, ss:[ebp+0x1c]
      [-]00008d4d
         // 00402c20: lea ecx, ss:[ebp+0x1c]
      [-]884618c786????????????????e8
         // 00402c23: mov b1 ds:[esi+0x18], b1 al
         // 00402c26: mov ds:[esi+0x1070], 0x2
         // 00402c30: call 0x40cbfb
      [-]00008d4d
         // 00402c35: lea ecx, ss:[ebp+0x1c]
      [-]8986????????e8
         // 00402c38: mov ds:[esi+0x1074], eax
         // 00402c3e: call 0x40cbfb
      [-]00008d4d
         // 00402c43: lea ecx, ss:[ebp+0x1c]
      [-]00000fb6c8894e1c
         // 00402c4e: movzx ecx, b1 al
         // 00402c51: mov ds:[esi+0x1c], ecx
      [-]c686f110000001
         // 00402b27: mov b1 ds:[esi+0x10f1], b1 0x1
      [-]33c9898e????????388e9b10000074
         // 00402b51: xor ecx, ecx
         // 00402b5b: mov ds:[esi+0x109c], ecx
         // 00402b61: cmp b1 ds:[esi+0x109b], b1 cl
         // 00402b67: jz 0x402bb2
      [-]4a83ea017422
         // 00402b71: dec edx
         // 00402b72: sub edx, 0x1
         // 00402b75: jz 0x402b99
      [-]83ea057411
         // 00402b77: sub edx, 0x5
         // 00402b7a: jz 0x402b8d
      [-]83ea06740c
         // 00402b7c: sub edx, 0x6
         // 00402b7f: jz 0x402b8d
      [-]c786????????????????eb22
         // 00402b81: mov ds:[esi+0x109c], 0x4
         // 00402b8b: jmp 0x402baf
      [-]c786????????????????eb16
         // 00402b8d: mov ds:[esi+0x109c], 0x3
         // 00402b97: jmp 0x402baf
      [-]c786????????????????eb0a
         // 00402b99: mov ds:[esi+0x109c], 0x2
         // 00402ba3: jmp 0x402baf
      [-]8a4618c786????????????????3c037410
         // 00402bb2: mov b1 al, b1 ds:[esi+0x18]
         // 00402bb5: mov ds:[esi+0x10fc], 0x2
         // 00402bbf: cmp b1 al, b1 0x3
         // 00402bc1: jz 0x402bd3
      [-]3c05740c
         // 00402bc3: cmp b1 al, b1 0x5
         // 00402bc5: jz 0x402bd3
      [-]3c067312
         // 00402bc7: cmp b1 al, b1 0x6
         // 00402bc9: jnb 0x402bdd
      [-]898e????????eb0a
         // 00402bcb: mov ds:[esi+0x10fc], ecx
         // 00402bd1: jmp 0x402bdd
      [-]c786????????????????
         // 00402bd3: mov ds:[esi+0x10fc], 0x1
      [-]898e????????3c0375
         // 00402bdd: mov ds:[esi+0x1100], ecx
         // 00402be3: cmp b1 al, b1 0x3
         // 00402be5: jnz 0x402c08
      [-]33c0c786????????????????66898604110000
         // 00402bf5: xor eax, eax
         // 00402bf7: mov ds:[esi+0x1100], 0x1
         // 00402c01: mov b2 ds:[esi+0x1104], b2 ax
      [-]83ff0274
         // 00402c08: cmp edi, 0x2
         // 00402c0b: jz 0x402c17
      [-]8886f81000008b4608c1e80824018886f910000074
         // 00402c19: mov b1 ds:[esi+0x10f8], b1 al
         // 00402c1f: mov eax, ds:[esi+0x8]
         // 00402c22: shr eax, b1 0x8
         // 00402c25: and b1 al, b1 0x1
         // 00402c27: mov b1 ds:[esi+0x10f9], b1 al
         // 00402c2d: jz 0x402c5b
      [-]00008d4d
         // 00402c24: lea ecx, ss:[ebp+0x24]
      [-]0000837d
         // 00402c2e: cmp ss:[ebp+0x50], 0xffffffffffffffff
      [-]ff8bd075
         // 00402c32: mov edx, eax
         // 00402c34: jnz 0x402c42
      [-]83faff75
         // 00402c49: cmp edx, 0xffffffffffffffff
         // 00402c4c: jnz 0x402c55
      [-]ff8bd18bf90f94c0
         // 00402c5f: mov edx, ecx
         // 00402c61: mov edi, ecx
         // 00402c63: setz b1 al
      [-]88869a10000033c00346148986????????13f933c00345
         // 00402ce6: mov b1 ds:[esi+0x109a], b1 al
         // 00402cec: xor eax, eax
         // 00402cee: add eax, ds:[esi+0x14]
         // 00402cf1: mov ds:[esi+0x1058], eax
         // 00402cf7: adc edi, ecx
         // 00402cf9: xor eax, eax
         // 00402cfb: add eax, ss:[ebp+0x54]
      [-]89be????????13d18986????????80
         // 00402cfe: mov ds:[esi+0x105c], edi
         // 00402d04: adc edx, ecx
         // 00402d06: mov ds:[esi+0x1060], eax
         // 00402d0c: cmp b1 ds:[esi+0x109a], b1 0x0
      [-]8996????????7411
         // 00402d13: mov ds:[esi+0x1064], edx
         // 00402d19: jz 0x402d2c
      [-]578d85????????508d4d
         // 00402cad: push edi
         // 00402cae: lea eax, ss:[ebp+0xffffffffffffdfd0]
         // 00402cb4: push eax
         // 00402cb5: lea ecx, ss:[ebp+0x24]
      [-]f74608????????74
         // 00402ce7: test ds:[esi+0x8], 0x200
         // 00402cee: jz 0x402d2f
      [-]8d4d00e8
         // 00402cf0: lea ecx, ss:[ebp+0x0]
         // 00402cf3: call 0x406af8
      [-]3e00008d85????????50e8
         // 00402cf8: lea eax, ss:[ebp+0xffffffffffffdfd0]
         // 00402cfe: push eax
         // 00402cff: call _strlen
      [-]68????????
         // 00402d8d: push 0x800
      [-]2bc8518d8d????????03c1508bc18d4d00
         // 00402d95: sub ecx, eax
         // 00402d97: push ecx
         // 00402d98: lea ecx, ss:[ebp+0xffffffffffffdfd0]
         // 00402d9e: add eax, ecx
         // 00402da0: push eax
         // 00402da1: mov eax, ecx
         // 00402da3: lea ecx, ss:[ebp+0x0]
      [-]6a0168????????
         // 00402d21: push 0x1
         // 00402d23: push 0x800
      [-]8d85????????50e8
         // 00402d29: lea eax, ss:[ebp+0xffffffffffffdfd0]
         // 00402d2f: push eax
         // 00402d30: call 0x40eec3
      [-]568bcbe8
         // 00402dc8: push esi
         // 00402dc9: mov ecx, ebx
         // 00402dcb: call 0x402093
      [-]f2ffffe9
         // 00402dd0: jmp 0x402f2b
      [-]68????????
         // 00402e97: push 0x800
      [-]8d85????????50e8
         // 00402e9d: lea eax, ss:[ebp+0xffffffffffffdfd0]
         // 00402ea3: push eax
         // 00402ea4: call 0x411b84
      [-]f74608????????7403
         // 00402eaf: test ds:[esi+0x8], 0x400
         // 00402eb9: jz 0x402ebe
      [-]00595985c00f85
         // 00402ef0: pop ecx
         // 00402ef1: pop ecx
         // 00402ef2: test eax, eax
         // 00402ef4: jnz 0x402fbc
      [-]83be????????140f82
         // 00402e42: cmp ds:[esi+0x102c], 0x14
         // 00402e49: jb 0x402f13
      [-]8bf28bf85657ffb3
         // 00402f66: mov esi, edx
         // 00402f68: mov edi, eax
         // 00402f6a: push esi
         // 00402f6b: push edi
         // 00402f6c: push ds:[ebx+0x21dc]
      [-]000056576a0068????????56578983
         // 00402f7d: push esi
         // 00402f7e: push edi
         // 00402f7f: push 0x0
         // 00402f81: push 0xc8
         // 00402f86: push esi
         // 00402f87: push edi
         // 00402f88: mov ds:[ebx+0x21e0], eax
      [-]01000383
         // 00402f96: add eax, ds:[ebx+0x21d8]
      [-]8d41018983
         // 00402e7b: lea eax, ds:[ecx+0x1]
         // 00402e7e: mov ds:[ebx+0x21c8], eax
      [-]00595985c07507
         // 00402e81: pop ecx
         // 00402e82: pop ecx
         // 00402e83: test eax, eax
         // 00402e85: jnz 0x402e8e
      [-]6c000001
      [-]f74608????????7411
         // 00402ea1: test ds:[esi+0x8], 0x400
         // 00402ea8: jz 0x402ebb
      [-]6a088d86????????508d4d
         // 00402e97: push 0x8
         // 00402e99: lea eax, ds:[esi+0x10a1]
         // 00402e9f: push eax
         // 00402ea0: lea ecx, ss:[ebp+0x24]
      [-]00000fb7c88d83
         // 00402ecb: movzx ecx, b2 ax
         // 00402ece: lea eax, ds:[ebx+0x32c0]
      [-]6a03592b
         // 00402f0b: push 0x3
         // 00402f0d: pop ecx
         // 00402f0e: sub ecx, esi
      [-]8bd8c0e102d3ebf6c308
         // 00402f10: mov ebx, eax
         // 00402f12: shl b1 cl, b1 0x2
         // 00402f15: shr ebx, b1 cl
         // 00402f17: test b1 bl, b1 0x8
      [-]00008b4c
         // 00402f20: mov ecx, ss:[ebp+esi*0x4]
      [-]8d45d050e8
         // 00402f2e: lea eax, ss:[ebp+0xffffffffffffffd0]
         // 00402f31: push eax
         // 00402f32: call 0x40fe0e
      [-]0000f6c3047403
         // 00402f37: test b1 bl, b1 0x4
         // 00402f3a: jz 0x402f3f
      [-]33c9894de883e30376
         // 00402f52: xor ecx, ecx
         // 00402f54: mov ss:[ebp+0xffffffffffffffe8], ecx
         // 00402f57: and ebx, 0x3
         // 00402f5a: jbe 0x402f8b
      [-]0fb6c0d3e083
         // 00402f60: movzx eax, b1 al
         // 00402f63: shl eax, b1 cl
         // 00402f65: add esi, 0x8
      [-]088b4de80bc8894de883eb0175e1
         // 00402f68: mov ecx, ss:[ebp+0xffffffffffffffe8]
         // 00402f6b: or ecx, eax
         // 00402f6d: mov ss:[ebp+0xffffffffffffffe8], ecx
         // 00402f70: sub ebx, 0x1
         // 00402f73: jnz 0x402f56
      [-]6bc1648b4c
         // 00402f78: imul eax, ecx, b1 0x64
         // 00402f7b: mov ecx, ss:[ebp+esi*0x4]
      [-]8945e88d45d050e8
         // 00402f7f: mov ss:[ebp+0xffffffffffffffe8], eax
         // 00402f82: lea eax, ss:[ebp+0xffffffffffffffd0]
         // 00402f85: push eax
         // 00402f86: call 0x41003e
      [-]00008b45
         // 00402f8b: mov eax, ss:[ebp+0x54]
      [-]33c05050ffb6????????ffb6????????ffb3
         // 00402fb4: xor eax, eax
         // 00402fb6: push eax
         // 00402fb7: push eax
         // 00402fb8: push ds:[esi+0x105c]
         // 00402fbe: push ds:[esi+0x1058]
         // 00402fc4: push ds:[ebx+0x6cac]
      [-]00008983
         // 00402fd5: mov ds:[ebx+0x6ca8], eax
      [-]8a86f21000008845
         // 00402fe4: mov b1 al, b1 ds:[esi+0x10f2]
         // 00402fea: mov b1 ss:[ebp+0x20], b1 al
      [-]00000fb7c039060f84
         // 00402ff5: movzx eax, b2 ax
         // 00402ff8: cmp ds:[esi], eax
         // 00402ffa: jz 0x40311a
      [-]6c000001e8
         // 00402ffb: call 0x406e8b
      [-]0000807d
         // 00403000: cmp b1 ss:[ebp+0x5e], b1 0x0
      [-]506a1ce8
         // 0040300e: push eax
         // 0040300f: push 0x1c
         // 00403011: call 0x406f5f
      [-]00006a05598db3
         // 00403052: push 0x5
         // 00403054: pop ecx
         // 00403055: lea esi, ds:[ebx+0x21e4]
      [-]f3a58d4d
         // 0040305b: rep movsdd 
         // 0040305d: lea ecx, ss:[ebp+0x24]
      [-]00008d4d
         // 00403065: lea ecx, ss:[ebp+0x24]
      [-]220000e8
         // 0040306f: call 0x40c237
      [-]00008a8b
         // 00403074: mov b1 cl, b1 ds:[ebx+0x2210]
      [-]2200008bd080e1018993
         // 0040307a: mov edx, eax
         // 0040307c: and b1 cl, b1 0x1
         // 0040307f: mov ds:[ebx+0x2220], edx
      [-]6c00008b8b
         // 0040308b: mov ecx, ds:[ebx+0x2210]
      [-]c1e90380e101888b
         // 00403091: shr ecx, b1 0x3
         // 00403094: and b1 cl, b1 0x1
         // 00403097: mov b1 ds:[ebx+0x6cb4], b1 cl
      [-]6c00008b8b
         // 0040309d: mov ecx, ds:[ebx+0x2210]
      [-]8bc1c1e80224018883
         // 004030a3: mov eax, ecx
         // 004030a5: shr eax, b1 0x2
         // 004030a8: and b1 al, b1 0x1
         // 004030aa: mov b1 ds:[ebx+0x6cb7], b1 al
      [-]6c00008bc1c1e80624018883
         // 004030b0: mov eax, ecx
         // 004030b2: shr eax, b1 0x6
         // 004030b5: and b1 al, b1 0x1
         // 004030b7: mov b1 ds:[ebx+0x6cbb], b1 al
      [-]6c00008bc1c1e80724018883
         // 004030bd: mov eax, ecx
         // 004030bf: shr eax, b1 0x7
         // 004030c2: and b1 al, b1 0x1
         // 004030c4: mov b1 ds:[ebx+0x6cbc], b1 al
      [-]6c000085d2750b
         // 004030ca: test edx, edx
         // 004030cc: jnz 0x4030d9
      [-]33c0663983
         // 004030e1: xor eax, eax
         // 004030e3: cmp b2 ds:[ebx+0x221c], b2 ax
      [-]22000074
         // 004030ea: jz 0x4030ef
      [-]6c00008bc1d1e824018883
         // 004030f5: mov eax, ecx
         // 004030f7: shr eax, b1 0x1
         // 004030f9: and b1 al, b1 0x1
         // 004030fb: mov b1 ds:[ebx+0x2224], b1 al
      [-]2200008bc1c1e8082401c1e90480e1018883
         // 00403101: mov eax, ecx
         // 00403103: shr eax, b1 0x8
         // 00403106: and b1 al, b1 0x1
         // 00403108: shr ecx, b1 0x4
         // 0040310b: and b1 cl, b1 0x1
         // 0040310e: mov b1 ds:[ebx+0x6cb9], b1 al
      [-]6c0000888b
         // 00403114: mov b1 ds:[ebx+0x6cba], b1 cl
      [-]6a008d4d
         // 0040310a: push 0x0
         // 0040310c: lea ecx, ss:[ebp+0x24]
      [-]00000fb7c03983
         // 00403114: movzx eax, b2 ax
         // 00403117: cmp ds:[ebx+0x21e4], eax
      [-]83f8790f84
         // 004031c6: cmp eax, 0x79
         // 004031c9: jz 0x40325e
      [-]83f8760f84
         // 00403145: cmp eax, 0x76
         // 00403148: jz 0x4031e0
      [-]83f80575
         // 0040314e: cmp eax, 0x5
         // 00403151: jnz 0x4031b2
      [-]3333c92bc7511bd18b
         // 0040326f: xor ecx, ecx
         // 00403271: sub eax, edi
         // 00403273: push ecx
         // 00403274: sbb edx, ecx
         // 00403276: mov ecx, ds:[esi+0x10]
      [-]5610c645
         // 00403286: mov b1 ss:[ebp+0x5b], b1 0x1
      [-]0000f6d81ac0f6d0
         // 0040321b: neg b1 al
         // 0040321d: sbb b1 al, b1 al
         // 0040321f: not b1 al
      [-]83ef0175
         // 00403227: sub edi, 0x1
         // 0040322a: jnz 0x403214
      [-]6c000001e8
         // 004031ad: call 0x406e8b
      [-]0000807d
         // 004031b2: cmp b1 ss:[ebp+0x5e], b1 0x0
      [-]50506a04e8
         // 004031ce: push eax
         // 004031cf: push eax
         // 004031d0: push 0x4
         // 004031d2: call 0x401f18
      [-]6c000001eb06
         // 004031de: jmp 0x4031e6
      [-]5583ec68
         // 00403203: push ebp
         // 00403204: sub esp, 0x68
      [-]0100b8????????e8
         // 004031fe: mov eax, 0x2068
         // 00403203: call __alloca_probe
      [-]010053568bd98d4d305753e8
         // 00403208: push ebx
         // 00403209: push esi
         // 0040320a: mov ebx, ecx
         // 0040320c: lea ecx, ss:[ebp+0x30]
         // 0040320f: push edi
         // 00403210: push ebx
         // 00403211: call 0x40c1bc
      [-]000033c9894d
         // 00403216: xor ecx, ecx
         // 00403218: mov ss:[ebp+0x60], ecx
      [-]894dfc388b
         // 0040321b: mov ss:[ebp+0xfffffffffffffffc], ecx
         // 0040321e: cmp b1 ds:[ebx+0x6cbc], b1 cl
      [-]6c00000f84
         // 00403224: jz 0x40336c
      [-]33c083c20813c13983
         // 004032c1: xor eax, eax
         // 004032c3: add edx, 0x8
         // 004032c6: adc eax, ecx
         // 004032c8: cmp ds:[ebx+0x6ca4], eax
      [-]c6456a01
         // 0040335e: mov b1 ss:[ebp+0x6a], b1 0x1
      [-]000000750d
         // 0040328b: jnz 0x40329a
      [-]0000c6456b0084c07404
         // 0040327f: mov b1 ss:[ebp+0x6b], b1 0x0
         // 00403283: test b1 al, b1 al
         // 00403285: jz 0x40328b
      [-]c6456b01
         // 0040329a: mov b1 ss:[ebp+0x6b], b1 0x1
      [-]0a00008d452833c95051ffb3
         // 0040332d: lea eax, ss:[ebp+0x28]
         // 00403330: xor ecx, ecx
         // 00403332: push eax
         // 00403333: push ecx
         // 00403334: push ds:[ebx+0x2260]
      [-]8d4518508b83
         // 0040333a: lea eax, ss:[ebp+0x18]
         // 0040333d: push eax
         // 0040333e: mov eax, ds:[ebx+0x21bc]
      [-]506a05518bcee8
         // 00403356: push eax
         // 00403357: push 0x5
         // 00403359: push ecx
         // 0040335a: mov ecx, esi
         // 0040335c: call 0x406249
      [-]000080bb
         // 00403361: cmp b1 ds:[ebx+0x225c], b1 0x0
      [-]2200000074
         // 00403368: jz 0x4033e7
      [-]6a08508d452850e8
         // 004032d5: push 0x8
         // 004032d7: push eax
         // 004032d8: lea eax, ss:[ebp+0x28]
         // 004032db: push eax
         // 004032dc: call _memcmp
      [-]010083c40c85c074
         // 004032e1: add esp, 0xc
         // 004032e4: test eax, eax
         // 004032e6: jz 0x403348
      [-]807d6b008d43
         // 0040341e: cmp b1 ss:[ebp+0x6b], b1 0x0
         // 00403422: lea eax, ds:[ebx+0x32]
      [-]00008bcbe8
         // 0040331d: mov ecx, ebx
         // 0040331f: call 0x403d3d
      [-]0a00008d452833c95051ffb3
         // 00403324: lea eax, ss:[ebp+0x28]
         // 00403327: xor ecx, ecx
         // 00403329: push eax
         // 0040332a: push ecx
         // 0040332b: push ds:[ebx+0x2260]
      [-]8d4518508b83
         // 00403331: lea eax, ss:[ebp+0x18]
         // 00403334: push eax
         // 00403335: mov eax, ds:[ebx+0x21bc]
      [-]506a05518bcee8
         // 00403341: push eax
         // 00403342: push 0x5
         // 00403344: push ecx
         // 00403345: mov ecx, esi
         // 00403347: call 0x406195
      [-]000080bb
         // 0040334c: cmp b1 ds:[ebx+0x225c], b1 0x0
      [-]220000008d83
         // 00403353: lea eax, ds:[ebx+0x2274]
      [-]897550eb22
         // 0040335b: mov ss:[ebp+0x50], esi
         // 0040335e: jmp 0x403382
      [-]6c000001e8
         // 00403362: call 0x406e8b
      [-]6a078d4d30e8
         // 0040336f: push 0x7
         // 00403371: lea ecx, ss:[ebp+0x30]
         // 00403374: call 0x40c3c7
      [-]000083f807730c
         // 00403379: cmp eax, 0x7
         // 0040337c: jnb 0x40338a
      [-]0b0000e9
         // 00403385: jmp 0x4039f0
      [-]8d4d30c683
         // 0040339d: lea ecx, ss:[ebp+0x30]
         // 004033a0: mov b1 ds:[ebx+0x21f4], b1 0x0
      [-]00006a048d4d3089
         // 004033b2: push 0x4
         // 004033b4: lea ecx, ss:[ebp+0x30]
         // 004033b7: mov ds:[edi], eax
      [-]00008d4d308bf0e8
         // 004033be: lea ecx, ss:[ebp+0x30]
         // 004033c1: mov esi, eax
         // 004033c3: call 0x40c2e7
      [-]00008bc80bca0f84
         // 004033c8: mov ecx, eax
         // 004033ca: or ecx, edx
         // 004033cc: jz 0x4039fc
      [-]85f60f84
         // 004033d2: test esi, esi
         // 004033d4: jz 0x4039fc
      [-]518d4d30e8
         // 004033e3: push ecx
         // 004033e4: lea ecx, ss:[ebp+0x30]
         // 004033e7: call 0x40c3c7
      [-]8d4d30e8
         // 00403526: lea ecx, ss:[ebp+0x30]
         // 00403529: call 0x40ccdb
      [-]00008d4d308bf0e8
         // 0040352e: lea ecx, ss:[ebp+0x30]
         // 00403531: mov esi, eax
         // 00403533: call 0x40ccfb
      [-]00008d4d308983
         // 00403538: lea ecx, ss:[ebp+0x30]
         // 0040353b: mov ds:[ebx+0x2200], eax
      [-]00008983
         // 00403546: mov ds:[ebx+0x2204], eax
      [-]c1e8022401
         // 0040354c: shr eax, b1 0x2
         // 0040354f: and b1 al, b1 0x1
      [-]ebffff6a03b9
         // 0040344a: push 0x3
         // 0040344c: mov ecx, 0x43cbe8
      [-]6c000001e8
         // 00403458: call 0x406e8b
      [-]0000807d6a0074
         // 0040345d: cmp b1 ss:[ebp+0x6a], b1 0x0
         // 00403461: jz 0x40347b
      [-]50506a04e8
         // 00403479: push eax
         // 0040347a: push eax
         // 0040347b: push 0x4
         // 0040347d: call 0x401f18
      [-]33c0f683
         // 0040348e: xor eax, eax
         // 00403490: test b1 ds:[ebx+0x21ec], b1 0x1
      [-]0000018945588945547428
         // 00403497: mov ss:[ebp+0x58], eax
         // 0040349a: mov ss:[ebp+0x54], eax
         // 0040349d: jz 0x4034c7
      [-]8d4d30e8
         // 0040348c: lea ecx, ss:[ebp+0x30]
         // 0040348f: call 0x40c337
      [-]00008bc889555433c0894d583bd07212
         // 00403494: mov ecx, eax
         // 00403496: mov ss:[ebp+0x54], edx
         // 00403499: xor eax, eax
         // 0040349b: mov ss:[ebp+0x58], ecx
         // 0040349e: cmp edx, eax
         // 004034a0: jb 0x4034b4
      [-]0000028bf08975
         // 004034ce: mov esi, eax
         // 004034d0: mov ss:[ebp+0x64], esi
      [-]89455c7410
         // 004034d3: mov ss:[ebp+0x5c], eax
         // 004034d6: jz 0x4034e8
      [-]8d4d30e8
         // 004034c5: lea ecx, ss:[ebp+0x30]
         // 004034c8: call 0x40c337
      [-]00008bf08945
         // 004034cd: mov esi, eax
         // 004034cf: mov ss:[ebp+0x64], eax
      [-]ffff8b8b
         // 0040360f: mov ecx, ds:[ebx+0x6cbc]
      [-]08000089
         // 00403632: mov ds:[ebx+0x6cc4], edx
      [-]f3a58d4d30e8
         // 0040354a: rep movsdd 
         // 0040354c: lea ecx, ss:[ebp+0x30]
         // 0040354f: call 0x40c337
      [-]000024018883
         // 00403554: and b1 al, b1 0x1
         // 00403556: mov b1 ds:[ebx+0x45ac], b1 al
      [-]45000033c0668983
         // 0040355c: xor eax, eax
         // 0040355e: mov b2 ds:[ebx+0x45ae], b2 ax
      [-]4500008883
         // 00403565: mov b1 ds:[ebx+0x45ad], b1 al
      [-]450000e9
         // 0040356b: jmp 0x4039e1
      [-]6a05598dbb
         // 00403570: push 0x5
         // 00403572: pop ecx
         // 00403573: lea edi, ds:[ebx+0x2248]
      [-]f3a58d4d30e8
         // 0040357f: rep movsdd 
         // 00403581: lea ecx, ss:[ebp+0x30]
         // 00403584: call 0x40c337
      [-]000085c07428
         // 00403589: test eax, eax
         // 0040358b: jz 0x4035b5
      [-]8d45006a1450e8
         // 00403593: lea eax, ss:[ebp+0x0]
         // 00403596: push 0x14
         // 00403598: push eax
         // 00403599: call 0x403f2b
      [-]09000083c4108d45008bcb508d43
         // 0040359e: add esp, 0x10
         // 004035a1: lea eax, ss:[ebp+0x0]
         // 004035a4: mov ecx, ebx
         // 004035a6: push eax
         // 004035a7: lea eax, ds:[ebx+0x1e]
      [-]090000e9
         // 004035b0: jmp 0x4039f0
      [-]8d4d30e8
         // 004035b5: lea ecx, ss:[ebp+0x30]
         // 004035b8: call 0x40c337
      [-]000024018d4d308883
         // 004035bd: and b1 al, b1 0x1
         // 004035bf: lea ecx, ss:[ebp+0x30]
         // 004035c2: mov b1 ds:[ebx+0x225c], b1 al
      [-]220000e8
         // 004035c8: call 0x40c1ea
      [-]00000fb6c08983
         // 004035cd: movzx eax, b1 al
         // 004035d0: mov ds:[ebx+0x2260], eax
      [-]83f8187608
         // 004035d6: cmp eax, 0x18
         // 004035d9: jbe 0x4035e3
      [-]6a108d83
         // 004035e3: push 0x10
         // 004035e5: lea eax, ds:[ebx+0x2264]
      [-]508d4d30e8
         // 004035eb: push eax
         // 004035ec: lea ecx, ss:[ebp+0x30]
         // 004035ef: call 0x40c299
      [-]000080bb
         // 004035f4: cmp b1 ds:[ebx+0x225c], b1 0x0
      [-]22000000745f
         // 004035fb: jz 0x40365c
      [-]6a088db3
         // 0040369c: push 0x8
         // 0040369e: lea esi, ds:[ebx+0x2274]
      [-]568d4d30e8
         // 004036a4: push esi
         // 004036a5: lea ecx, ss:[ebp+0x30]
         // 004036a8: call 0x40c642
      [-]00006a048d4564508d4d30e8
         // 004036ad: push 0x4
         // 004036af: lea eax, ss:[ebp+0x64]
         // 004036b2: push eax
         // 004036b3: lea ecx, ss:[ebp+0x30]
         // 004036b6: call 0x40c642
      [-]00008d458c50e8
         // 004036bb: lea eax, ss:[ebp+0xffffffffffffff8c]
         // 004036be: push eax
         // 004036bf: call 0x40f8c7
      [-]00006a08568d458c50e8
         // 004036c4: push 0x8
         // 004036c6: push esi
         // 004036c7: lea eax, ss:[ebp+0xffffffffffffff8c]
         // 004036ca: push eax
         // 004036cb: call 0x40f90d
      [-]00008d4508508d458c50e8
         // 004036d0: lea eax, ss:[ebp+0x8]
         // 004036d3: push eax
         // 004036d4: lea eax, ss:[ebp+0xffffffffffffff8c]
         // 004036d7: push eax
         // 004036d8: call 0x40f7d6
      [-]00006a048d4508508d456450e8
         // 004036dd: push 0x4
         // 004036df: lea eax, ss:[ebp+0x8]
         // 004036e2: push eax
         // 004036e3: lea eax, ss:[ebp+0x64]
         // 004036e6: push eax
         // 004036e7: call _memcmp
      [-]010083c40cf7d81ac0fec08883
         // 004036ec: add esp, 0xc
         // 004036ef: neg eax
         // 004036f1: sbb b1 al, b1 al
         // 004036f3: inc b1 al
         // 004036f5: mov b1 ds:[ebx+0x225c], b1 al
      [-]6c000001e9
         // 00403676: jmp 0x4039f4
      [-]33c083fa026a00
         // 00403796: xor eax, eax
         // 00403798: cmp edx, 0x2
         // 0040379b: push 0x0
      [-]8d78ff81e7
         // 004037a0: lea edi, ds:[eax+0xffffffffffffffff]
         // 004037a3: and edi, 0x2350
      [-]03fb8bcf897d2ce8
         // 004037af: add edi, ebx
         // 004037b1: mov ecx, edi
         // 004037b3: mov ss:[ebp+0x2c], edi
         // 004037b6: call 0x40acc4
      [-]00006a05598db3
         // 004037bb: push 0x5
         // 004037bd: pop ecx
         // 004037be: lea esi, ds:[ebx+0x21fc]
      [-]f3a58b83
         // 004037c4: rep movsdd 
         // 004037c6: mov eax, ds:[ebx+0x2200]
      [-]8d4d308b752c8945
         // 004037cc: lea ecx, ss:[ebp+0x30]
         // 004037cf: mov esi, ss:[ebp+0x2c]
         // 004037d2: mov ss:[ebp+0x64], eax
      [-]8986????????8b455cc686f9100000018986????????e8
         // 004037d8: mov ds:[esi+0x1058], eax
         // 004037de: mov eax, ss:[ebp+0x5c]
         // 004037e1: mov b1 ds:[esi+0x10f9], b1 0x1
         // 004037e8: mov ds:[esi+0x105c], eax
         // 004037ee: call 0x40ccfb
      [-]00008d4d308986????????e8
         // 004037f3: lea ecx, ss:[ebp+0x30]
         // 004037f6: mov ds:[esi+0x1094], eax
         // 004037fc: call 0x40ccfb
      [-]00008986????????8b86????????c1e80324018996????????88869a1000007411
         // 00403801: mov ds:[esi+0x1060], eax
         // 00403807: mov eax, ds:[esi+0x1094]
         // 0040380d: shr eax, b1 0x3
         // 00403810: and b1 al, b1 0x1
         // 00403812: mov ds:[esi+0x1064], edx
         // 00403818: mov b1 ds:[esi+0x109a], b1 al
         // 0040381e: jz 0x403831
      [-]b8????????8986????????8986????????
         // 00403705: mov eax, 0x7fffffff
         // 0040370a: mov ds:[esi+0x1060], eax
         // 00403710: mov ds:[esi+0x1064], eax
      [-]8b8e????????8bbe????????8b86????????8b96????????3bcf7c06
         // 00403716: mov ecx, ds:[esi+0x105c]
         // 0040371c: mov edi, ds:[esi+0x1064]
         // 00403722: mov eax, ds:[esi+0x1058]
         // 00403728: mov edx, ds:[esi+0x1060]
         // 0040372e: cmp ecx, edi
         // 00403730: jl 0x403738
      [-]3bc27704
         // 00403734: cmp eax, edx
         // 00403736: ja 0x40373c
      [-]8bc28bcf
         // 00403738: mov eax, edx
         // 0040373a: mov ecx, edi
      [-]898e????????8d4d308986????????e8
         // 00403729: mov ds:[esi+0x106c], ecx
         // 0040372f: lea ecx, ss:[ebp+0x30]
         // 00403732: mov ds:[esi+0x1068], eax
         // 00403738: call 0x40c337
      [-]0000f68694100000028946247416
         // 0040373d: test b1 ds:[esi+0x1094], b1 0x2
         // 00403744: mov ds:[esi+0x24], eax
         // 00403747: jz 0x40375f
      [-]8d4d30e8
         // 00403749: lea ecx, ss:[ebp+0x30]
         // 0040374c: call 0x40c237
      [-]00006a00508d8e????????e8
         // 00403751: push 0x0
         // 00403753: push eax
         // 00403754: lea ecx, ds:[esi+0x1040]
         // 0040375a: call 0x410153
      [-]83a6????????00f68694100000047418
         // 00403772: and ds:[esi+0x1070], 0x0
         // 00403779: test b1 ds:[esi+0x1094], b1 0x4
         // 00403780: jz 0x40379a
      [-]8d4d30c786??????????
         // 0040376f: lea ecx, ss:[ebp+0x30]
         // 00403772: mov ds:[esi+0x1070], 0x2
         // 0040377c: call 0x40c237

  }
  condition:
    all of them
}
