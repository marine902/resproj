rule dinwod_10_3 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         60be????????8dbe????????5789e58d9c24????????31c0
         // 00424640: pusha 
         // 00424641: mov esi, 0x41b000
         // 00424646: lea edi, ds:[esi+0xfffffffffffe6000]
         // 0042464c: push edi
         // 0042464d: mov ebp, esp
         // 0042464f: lea ebx, ss:[esp+0xffffffffffffc180]
         // 00424656: xor eax, eax
      [-]5039dc75fb
         // 00424658: push eax
         // 00424659: cmp esp, ebx
         // 0042465b: jnz 0x424658
      [-]46465368????????5783c3045368????????5683c3045350c703????????9090909090
         // 0042465d: inc esi
         // 0042465e: inc esi
         // 0042465f: push ebx
         // 00424660: push 0x22394
         // 00424665: push edi
         // 00424666: add ebx, 0x4
         // 00424669: push ebx
         // 0042466a: push 0x962f
         // 0042466f: push esi
         // 00424670: add ebx, 0x4
         // 00424673: push ebx
         // 00424674: push eax
         // 00424675: mov ds:[ebx], 0x20003
         // 0042467b: nop 
         // 0042467c: nop 
         // 0042467d: nop 
         // 0042467e: nop 
         // 0042467f: nop 
      [-]5557565383ec7c8b9424????????c74424????????00c6442473008bac24????????8d420489442478b8????????0fb64a0289c3d3e389d949894c246c0fb64a01d3e048894424688b8424????????0fb632c74500????????c74424????????00c700????????b8????????89742464c744245c????????c7442458????????c7442454????????c7442450????????0fb64a0101f1d3e08d88????????394c2474730e
         // 00424680: push ebp
         // 00424681: push edi
         // 00424682: push esi
         // 00424683: push ebx
         // 00424684: sub esp, 0x7c
         // 00424687: mov edx, ss:[esp+0x90]
         // 0042468e: mov ss:[esp+0x74], 0x0
         // 00424696: mov b1 ss:[esp+0x73], b1 0x0
         // 0042469b: mov ebp, ss:[esp+0x9c]
         // 004246a2: lea eax, ds:[edx+0x4]
         // 004246a5: mov ss:[esp+0x78], eax
         // 004246a9: mov eax, 0x1
         // 004246ae: movzx ecx, b1 ds:[edx+0x2]
         // 004246b2: mov ebx, eax
         // 004246b4: shl ebx, b1 cl
         // 004246b6: mov ecx, ebx
         // 004246b8: dec ecx
         // 004246b9: mov ss:[esp+0x6c], ecx
         // 004246bd: movzx ecx, b1 ds:[edx+0x1]
         // 004246c1: shl eax, b1 cl
         // 004246c3: dec eax
         // 004246c4: mov ss:[esp+0x68], eax
         // 004246c8: mov eax, ss:[esp+0xa8]
         // 004246cf: movzx esi, b1 ds:[edx]
         // 004246d2: mov ss:[ebp+0x0], 0x0
         // 004246d9: mov ss:[esp+0x60], 0x0
         // 004246e1: mov ds:[eax], 0x0
         // 004246e7: mov eax, 0x300
         // 004246ec: mov ss:[esp+0x64], esi
         // 004246f0: mov ss:[esp+0x5c], 0x1
         // 004246f8: mov ss:[esp+0x58], 0x1
         // 00424700: mov ss:[esp+0x54], 0x1
         // 00424708: mov ss:[esp+0x50], 0x1
         // 00424710: movzx ecx, b1 ds:[edx+0x1]
         // 00424714: add ecx, esi
         // 00424716: shl eax, b1 cl
         // 00424718: lea ecx, ds:[eax+0x736]
         // 0042471e: cmp ss:[esp+0x74], ecx
         // 00424722: jnb 0x424732
      [-]8b442478
         // 00424724: mov eax, ss:[esp+0x78]
      [-]66c700000483c002e2f6
         // 00424728: mov b2 ds:[eax], b2 0x400
         // 0042472d: add eax, 0x2
         // 00424730: loop 0x424728
      [-]8b9c24????????31ffc7442448????????89da039424????????8954244c31d2
         // 00424732: mov ebx, ss:[esp+0x94]
         // 00424739: xor edi, edi
         // 0042473b: mov ss:[esp+0x48], 0xffffffffffffffff
         // 00424743: mov edx, ebx
         // 00424745: add edx, ss:[esp+0x98]
         // 0042474c: mov ss:[esp+0x4c], edx
         // 00424750: xor edx, edx
      [-]3b5c244c0f847c090000
         // 00424752: cmp ebx, ss:[esp+0x4c]
         // 00424756: jz 0x4250d8
      [-]0fb603c1e708424309c783fa047ee7
         // 0042475c: movzx eax, b1 ds:[ebx]
         // 0042475f: shl edi, b1 0x8
         // 00424762: inc edx
         // 00424763: inc ebx
         // 00424764: or edi, eax
         // 00424766: cmp edx, 0x4
         // 00424769: jle 0x424752
      [-]8b8c24????????394c24740f8364090000
         // 0042476b: mov ecx, ss:[esp+0xa4]
         // 00424772: cmp ss:[esp+0x74], ecx
         // 00424776: jnb 0x4250e0
      [-]8b7424742374246c8b4424608b542478c1e0048974244401f0817c2448????????8d2c427718
         // 0042477c: mov esi, ss:[esp+0x74]
         // 00424780: and esi, ss:[esp+0x6c]
         // 00424784: mov eax, ss:[esp+0x60]
         // 00424788: mov edx, ss:[esp+0x78]
         // 0042478c: shl eax, b1 0x4
         // 0042478f: mov ss:[esp+0x44], esi
         // 00424793: add eax, esi
         // 00424795: cmp ss:[esp+0x48], 0xffffff
         // 0042479d: lea ebp, ds:[edx+eax*0x2]
         // 004247a0: ja 0x4247ba
      [-]3b5c244c0f842c090000
         // 004247a2: cmp ebx, ss:[esp+0x4c]
         // 004247a6: jz 0x4250d8
      [-]c1642448080fb603c1e7084309c7
         // 004247ac: shl ss:[esp+0x48], b1 0x8
         // 004247b1: movzx eax, b1 ds:[ebx]
         // 004247b4: shl edi, b1 0x8
         // 004247b7: inc ebx
         // 004247b8: or edi, eax
      [-]8b442448668b5500c1e80b0fb7ca0fafc139c70f83dd010000
         // 004247ba: mov eax, ss:[esp+0x48]
         // 004247be: mov b2 dx, b2 ss:[ebp+0x0]
         // 004247c2: shr eax, b1 0xb
         // 004247c5: movzx ecx, b2 dx
         // 004247c8: imul eax, ecx
         // 004247cb: cmp edi, eax
         // 004247cd: jnb 0x4249b0
      [-]89442448b8????????29c88a4c2464c1f805be????????8d04020fb6542473668945008b442474234424688b6c2478d3e0b9????????2b4c2464d3fa01d069c0????????837c2460068d8405????????894424140f8eca000000
         // 004247d3: mov ss:[esp+0x48], eax
         // 004247d7: mov eax, 0x800
         // 004247dc: sub eax, ecx
         // 004247de: mov b1 cl, b1 ss:[esp+0x64]
         // 004247e2: sar eax, b1 0x5
         // 004247e5: mov esi, 0x1
         // 004247ea: lea eax, ds:[edx+eax]
         // 004247ed: movzx edx, b1 ss:[esp+0x73]
         // 004247f2: mov b2 ss:[ebp+0x0], b2 ax
         // 004247f6: mov eax, ss:[esp+0x74]
         // 004247fa: and eax, ss:[esp+0x68]
         // 004247fe: mov ebp, ss:[esp+0x78]
         // 00424802: shl eax, b1 cl
         // 00424804: mov ecx, 0x8
         // 00424809: sub ecx, ss:[esp+0x64]
         // 0042480d: sar edx, b1 cl
         // 0042480f: add eax, edx
         // 00424811: imul eax, 0x600
         // 00424817: cmp ss:[esp+0x60], 0x6
         // 0042481c: lea eax, ss:[ebp+eax+0xe6c]
         // 00424823: mov ss:[esp+0x14], eax
         // 00424827: jle 0x4248f7
      [-]8b4424742b44245c8b9424????????0fb6040289442440
         // 0042482d: mov eax, ss:[esp+0x74]
         // 00424831: sub eax, ss:[esp+0x5c]
         // 00424835: mov edx, ss:[esp+0xa0]
         // 0042483c: movzx eax, b1 ds:[edx+eax]
         // 00424840: mov ss:[esp+0x40], eax
      [-]d16424408b4c24408d14368b6c241481e1????????817c2448????????8d444d00894c243c8d2c107718
         // 00424844: shl ss:[esp+0x40], b1 0x1
         // 00424848: mov ecx, ss:[esp+0x40]
         // 0042484c: lea edx, ds:[esi+esi]
         // 0042484f: mov ebp, ss:[esp+0x14]
         // 00424853: and ecx, 0x100
         // 00424859: cmp ss:[esp+0x48], 0xffffff
         // 00424861: lea eax, ss:[ebp+ecx*0x2]
         // 00424865: mov ss:[esp+0x3c], ecx
         // 00424869: lea ebp, ds:[eax+edx]
         // 0042486c: ja 0x424886
      [-]3b5c244c0f8460080000
         // 0042486e: cmp ebx, ss:[esp+0x4c]
         // 00424872: jz 0x4250d8
      [-]c1642448080fb603c1e7084309c7
         // 00424878: shl ss:[esp+0x48], b1 0x8
         // 0042487d: movzx eax, b1 ds:[ebx]
         // 00424880: shl edi, b1 0x8
         // 00424883: inc ebx
         // 00424884: or edi, eax
      [-]8b442448668b8d00020000c1e80b0fb7f10fafc639c77323
         // 00424886: mov eax, ss:[esp+0x48]
         // 0042488a: mov b2 cx, b2 ss:[ebp+0x200]
         // 00424891: shr eax, b1 0xb
         // 00424894: movzx esi, b2 cx
         // 00424897: imul eax, esi
         // 0042489a: cmp edi, eax
         // 0042489c: jnb 0x4248c1
      [-]89442448b8????????29f089d6c1f805837c243c008d0401668985000200007422
         // 0042489e: mov ss:[esp+0x48], eax
         // 004248a2: mov eax, 0x800
         // 004248a7: sub eax, esi
         // 004248a9: mov esi, edx
         // 004248ab: sar eax, b1 0x5
         // 004248ae: cmp ss:[esp+0x3c], 0x0
         // 004248b3: lea eax, ds:[ecx+eax]
         // 004248b6: mov b2 ss:[ebp+0x200], b2 ax
         // 004248bd: jz 0x4248e1
      [-]2944244829c789c88d720166c1e8056629c1837c243c0066898d00020000740e
         // 004248c1: sub ss:[esp+0x48], eax
         // 004248c5: sub edi, eax
         // 004248c7: mov eax, ecx
         // 004248c9: lea esi, ds:[edx+0x1]
         // 004248cc: shr b2 ax, b1 0x5
         // 004248d0: sub b2 cx, b2 ax
         // 004248d3: cmp ss:[esp+0x3c], 0x0
         // 004248d8: mov b2 ss:[ebp+0x200], b2 cx
         // 004248df: jz 0x4248ef
      [-]81fe????????0f8e57ffffff
         // 004248e1: cmp esi, 0xff
         // 004248e7: jle 0x424844
      [-]81fe????????7f71
         // 004248ef: cmp esi, 0xff
         // 004248f5: jg 0x424968
      [-]8d14368b6c241401d5817c2448????????7718
         // 004248f7: lea edx, ds:[esi+esi]
         // 004248fa: mov ebp, ss:[esp+0x14]
         // 004248fe: add ebp, edx
         // 00424900: cmp ss:[esp+0x48], 0xffffff
         // 00424908: ja 0x424922
      [-]3b5c244c0f84c4070000
         // 0042490a: cmp ebx, ss:[esp+0x4c]
         // 0042490e: jz 0x4250d8
      [-]c1642448080fb603c1e7084309c7
         // 00424914: shl ss:[esp+0x48], b1 0x8
         // 00424919: movzx eax, b1 ds:[ebx]
         // 0042491c: shl edi, b1 0x8
         // 0042491f: inc ebx
         // 00424920: or edi, eax
      [-]8b442448668b4d00c1e80b0fb7f10fafc639c77319
         // 00424922: mov eax, ss:[esp+0x48]
         // 00424926: mov b2 cx, b2 ss:[ebp+0x0]
         // 0042492a: shr eax, b1 0xb
         // 0042492d: movzx esi, b2 cx
         // 00424930: imul eax, esi
         // 00424933: cmp edi, eax
         // 00424935: jnb 0x424950
      [-]89442448b8????????29f089d6c1f8058d040166894500eb9f
         // 00424937: mov ss:[esp+0x48], eax
         // 0042493b: mov eax, 0x800
         // 00424940: sub eax, esi
         // 00424942: mov esi, edx
         // 00424944: sar eax, b1 0x5
         // 00424947: lea eax, ds:[ecx+eax]
         // 0042494a: mov b2 ss:[ebp+0x0], b2 ax
         // 0042494e: jmp 0x4248ef
      [-]2944244829c789c88d720166c1e8056629c166894d00eb87
         // 00424950: sub ss:[esp+0x48], eax
         // 00424954: sub edi, eax
         // 00424956: mov eax, ecx
         // 00424958: lea esi, ds:[edx+0x1]
         // 0042495b: shr b2 ax, b1 0x5
         // 0042495f: sub b2 cx, b2 ax
         // 00424962: mov b2 ss:[ebp+0x0], b2 cx
         // 00424966: jmp 0x4248ef
      [-]8b54247489f08b8c24????????8844247388040a42837c246003895424747f0d
         // 00424968: mov edx, ss:[esp+0x74]
         // 0042496c: mov eax, esi
         // 0042496e: mov ecx, ss:[esp+0xa0]
         // 00424975: mov b1 ss:[esp+0x73], b1 al
         // 00424979: mov b1 ds:[edx+ecx], b1 al
         // 0042497c: inc edx
         // 0042497d: cmp ss:[esp+0x60], 0x3
         // 00424982: mov ss:[esp+0x74], edx
         // 00424986: jg 0x424995
      [-]c74424????????00e91b070000
         // 00424988: mov ss:[esp+0x60], 0x0
         // 00424990: jmp 0x4250b0
      [-]837c2460097f0a
         // 00424995: cmp ss:[esp+0x60], 0x9
         // 0042499a: jg 0x4249a6
      [-]836c246003e90a070000
         // 0042499c: sub ss:[esp+0x60], 0x3
         // 004249a1: jmp 0x4250b0
      [-]836c246006e900070000
         // 004249a6: sub ss:[esp+0x60], 0x6
         // 004249ab: jmp 0x4250b0
      [-]8b4c244829c78b74246029c189d066c1e8056629c281f9????????668955008b6c24788d747500897424387716
         // 004249b0: mov ecx, ss:[esp+0x48]
         // 004249b4: sub edi, eax
         // 004249b6: mov esi, ss:[esp+0x60]
         // 004249ba: sub ecx, eax
         // 004249bc: mov eax, edx
         // 004249be: shr b2 ax, b1 0x5
         // 004249c2: sub b2 dx, b2 ax
         // 004249c5: cmp ecx, 0xffffff
         // 004249cb: mov b2 ss:[ebp+0x0], b2 dx
         // 004249cf: mov ebp, ss:[esp+0x78]
         // 004249d3: lea esi, ss:[ebp+esi*0x2]
         // 004249d7: mov ss:[esp+0x38], esi
         // 004249db: ja 0x4249f3
      [-]3b5c244c0f84f1060000
         // 004249dd: cmp ebx, ss:[esp+0x4c]
         // 004249e1: jz 0x4250d8
      [-]0fb603c1e708c1e1084309c7
         // 004249e7: movzx eax, b1 ds:[ebx]
         // 004249ea: shl edi, b1 0x8
         // 004249ed: shl ecx, b1 0x8
         // 004249f0: inc ebx
         // 004249f1: or edi, eax
      [-]8b6c243889c8c1e80b668b95800100000fb7ea0fafc539c77352
         // 004249f3: mov ebp, ss:[esp+0x38]
         // 004249f7: mov eax, ecx
         // 004249f9: shr eax, b1 0xb
         // 004249fc: mov b2 dx, b2 ss:[ebp+0x180]
         // 00424a03: movzx ebp, b2 dx
         // 00424a06: imul eax, ebp
         // 00424a09: cmp edi, eax
         // 00424a0b: jnb 0x424a5f
      [-]89c6b8????????29e88b6c2458c1f8058b4c24548d04028b542438894c24508b4c2478668982800100008b44245c896c24548944245831c0837c2460060f9fc081c1????????8d044089442460e974020000
         // 00424a0d: mov esi, eax
         // 00424a0f: mov eax, 0x800
         // 00424a14: sub eax, ebp
         // 00424a16: mov ebp, ss:[esp+0x58]
         // 00424a1a: sar eax, b1 0x5
         // 00424a1d: mov ecx, ss:[esp+0x54]
         // 00424a21: lea eax, ds:[edx+eax]
         // 00424a24: mov edx, ss:[esp+0x38]
         // 00424a28: mov ss:[esp+0x50], ecx
         // 00424a2c: mov ecx, ss:[esp+0x78]
         // 00424a30: mov b2 ds:[edx+0x180], b2 ax
         // 00424a37: mov eax, ss:[esp+0x5c]
         // 00424a3b: mov ss:[esp+0x54], ebp
         // 00424a3f: mov ss:[esp+0x58], eax
         // 00424a43: xor eax, eax
         // 00424a45: cmp ss:[esp+0x60], 0x6
         // 00424a4a: setnle b1 al
         // 00424a4d: add ecx, 0x664
         // 00424a53: lea eax, ds:[eax+eax*0x2]
         // 00424a56: mov ss:[esp+0x60], eax
         // 00424a5a: jmp 0x424cd3
      [-]89ce29c729c689d066c1e8058b4c24386629c281fe????????668991800100007716
         // 00424a5f: mov esi, ecx
         // 00424a61: sub edi, eax
         // 00424a63: sub esi, eax
         // 00424a65: mov eax, edx
         // 00424a67: shr b2 ax, b1 0x5
         // 00424a6b: mov ecx, ss:[esp+0x38]
         // 00424a6f: sub b2 dx, b2 ax
         // 00424a72: cmp esi, 0xffffff
         // 00424a78: mov b2 ds:[ecx+0x180], b2 dx
         // 00424a7f: ja 0x424a97
      [-]3b5c244c0f844d060000
         // 00424a81: cmp ebx, ss:[esp+0x4c]
         // 00424a85: jz 0x4250d8
      [-]0fb603c1e708c1e6084309c7
         // 00424a8b: movzx eax, b1 ds:[ebx]
         // 00424a8e: shl edi, b1 0x8
         // 00424a91: shl esi, b1 0x8
         // 00424a94: inc ebx
         // 00424a95: or edi, eax
      [-]8b6c243889f2c1ea0b668b8d980100000fb7c10fafd039d70f83e3000000
         // 00424a97: mov ebp, ss:[esp+0x38]
         // 00424a9b: mov edx, esi
         // 00424a9d: shr edx, b1 0xb
         // 00424aa0: mov b2 cx, b2 ss:[ebp+0x198]
         // 00424aa7: movzx eax, b2 cx
         // 00424aaa: imul edx, eax
         // 00424aad: cmp edi, edx
         // 00424aaf: jnb 0x424b98
      [-]bd????????89d629c5c7442434????????89e8c1f8058d04018b4c2438668981980100008b4424608b4c2444c1e0050344247881fa????????8d2c487716
         // 00424ab5: mov ebp, 0x800
         // 00424aba: mov esi, edx
         // 00424abc: sub ebp, eax
         // 00424abe: mov ss:[esp+0x34], 0x800
         // 00424ac6: mov eax, ebp
         // 00424ac8: sar eax, b1 0x5
         // 00424acb: lea eax, ds:[ecx+eax]
         // 00424ace: mov ecx, ss:[esp+0x38]
         // 00424ad2: mov b2 ds:[ecx+0x198], b2 ax
         // 00424ad9: mov eax, ss:[esp+0x60]
         // 00424add: mov ecx, ss:[esp+0x44]
         // 00424ae1: shl eax, b1 0x5
         // 00424ae4: add eax, ss:[esp+0x78]
         // 00424ae8: cmp edx, 0xffffff
         // 00424aee: lea ebp, ds:[eax+ecx*0x2]
         // 00424af1: ja 0x424b09
      [-]3b5c244c0f84db050000
         // 00424af3: cmp ebx, ss:[esp+0x4c]
         // 00424af7: jz 0x4250d8
      [-]0fb603c1e708c1e6084309c7
         // 00424afd: movzx eax, b1 ds:[ebx]
         // 00424b00: shl edi, b1 0x8
         // 00424b03: shl esi, b1 0x8
         // 00424b06: inc ebx
         // 00424b07: or edi, eax
      [-]668b95e001000089f0c1e80b0fb7ca0fafc139c77360
         // 00424b09: mov b2 dx, b2 ss:[ebp+0x1e0]
         // 00424b10: mov eax, esi
         // 00424b12: shr eax, b1 0xb
         // 00424b15: movzx ecx, b2 dx
         // 00424b18: imul eax, ecx
         // 00424b1b: cmp edi, eax
         // 00424b1d: jnb 0x424b7f
      [-]294c2434c17c2434058b74243489442448837c2474008d0432668985e00100000f8493050000
         // 00424b1f: sub ss:[esp+0x34], ecx
         // 00424b23: sar ss:[esp+0x34], b1 0x5
         // 00424b28: mov esi, ss:[esp+0x34]
         // 00424b2c: mov ss:[esp+0x48], eax
         // 00424b30: cmp ss:[esp+0x74], 0x0
         // 00424b35: lea eax, ds:[edx+esi]
         // 00424b38: mov b2 ss:[ebp+0x1e0], b2 ax
         // 00424b3f: jz 0x4250d8
      [-]31c0837c2460068bac24????????8b5424740f9fc08d440009894424608b4424742b44245c8a4405008844247388042a4289542474e931050000
         // 00424b45: xor eax, eax
         // 00424b47: cmp ss:[esp+0x60], 0x6
         // 00424b4c: mov ebp, ss:[esp+0xa0]
         // 00424b53: mov edx, ss:[esp+0x74]
         // 00424b57: setnle b1 al
         // 00424b5a: lea eax, ds:[eax+eax+0x9]
         // 00424b5e: mov ss:[esp+0x60], eax
         // 00424b62: mov eax, ss:[esp+0x74]
         // 00424b66: sub eax, ss:[esp+0x5c]
         // 00424b6a: mov b1 al, b1 ss:[ebp+eax+0x0]
         // 00424b6e: mov b1 ss:[esp+0x73], b1 al
         // 00424b72: mov b1 ds:[edx+ebp], b1 al
         // 00424b75: inc edx
         // 00424b76: mov ss:[esp+0x74], edx
         // 00424b7a: jmp 0x4250b0
      [-]29c629c789d066c1e8056629c2668995e0010000e91f010000
         // 00424b7f: sub esi, eax
         // 00424b81: sub edi, eax
         // 00424b83: mov eax, edx
         // 00424b85: shr b2 ax, b1 0x5
         // 00424b89: sub b2 dx, b2 ax
         // 00424b8c: mov b2 ss:[ebp+0x1e0], b2 dx
         // 00424b93: jmp 0x424cb7
      [-]89c829d666c1e8058b6c24386629c129d781fe????????66898d980100007716
         // 00424b98: mov eax, ecx
         // 00424b9a: sub esi, edx
         // 00424b9c: shr b2 ax, b1 0x5
         // 00424ba0: mov ebp, ss:[esp+0x38]
         // 00424ba4: sub b2 cx, b2 ax
         // 00424ba7: sub edi, edx
         // 00424ba9: cmp esi, 0xffffff
         // 00424baf: mov b2 ss:[ebp+0x198], b2 cx
         // 00424bb6: ja 0x424bce
      [-]3b5c244c0f8416050000
         // 00424bb8: cmp ebx, ss:[esp+0x4c]
         // 00424bbc: jz 0x4250d8
      [-]0fb603c1e708c1e6084309c7
         // 00424bc2: movzx eax, b1 ds:[ebx]
         // 00424bc5: shl edi, b1 0x8
         // 00424bc8: shl esi, b1 0x8
         // 00424bcb: inc ebx
         // 00424bcc: or edi, eax
      [-]8b4c243889f0c1e80b668b91b00100000fb7ca0fafc139c77323
         // 00424bce: mov ecx, ss:[esp+0x38]
         // 00424bd2: mov eax, esi
         // 00424bd4: shr eax, b1 0xb
         // 00424bd7: mov b2 dx, b2 ds:[ecx+0x1b0]
         // 00424bde: movzx ecx, b2 dx
         // 00424be1: imul eax, ecx
         // 00424be4: cmp edi, eax
         // 00424be6: jnb 0x424c0b
      [-]89c6b8????????29c88b6c2438c1f8058d0402668985b00100008b442458e9a0000000
         // 00424be8: mov esi, eax
         // 00424bea: mov eax, 0x800
         // 00424bef: sub eax, ecx
         // 00424bf1: mov ebp, ss:[esp+0x38]
         // 00424bf5: sar eax, b1 0x5
         // 00424bf8: lea eax, ds:[edx+eax]
         // 00424bfb: mov b2 ss:[ebp+0x1b0], b2 ax
         // 00424c02: mov eax, ss:[esp+0x58]
         // 00424c06: jmp 0x424cab
      [-]89f129c729c189d066c1e8056629c28b44243881f9????????668990b00100007716
         // 00424c0b: mov ecx, esi
         // 00424c0d: sub edi, eax
         // 00424c0f: sub ecx, eax
         // 00424c11: mov eax, edx
         // 00424c13: shr b2 ax, b1 0x5
         // 00424c17: sub b2 dx, b2 ax
         // 00424c1a: mov eax, ss:[esp+0x38]
         // 00424c1e: cmp ecx, 0xffffff
         // 00424c24: mov b2 ds:[eax+0x1b0], b2 dx
         // 00424c2b: ja 0x424c43
      [-]3b5c244c0f84a1040000
         // 00424c2d: cmp ebx, ss:[esp+0x4c]
         // 00424c31: jz 0x4250d8
      [-]0fb603c1e708c1e1084309c7
         // 00424c37: movzx eax, b1 ds:[ebx]
         // 00424c3a: shl edi, b1 0x8
         // 00424c3d: shl ecx, b1 0x8
         // 00424c40: inc ebx
         // 00424c41: or edi, eax
      [-]8b74243889c8c1e80b668b96c80100000fb7ea0fafc539c77320
         // 00424c43: mov esi, ss:[esp+0x38]
         // 00424c47: mov eax, ecx
         // 00424c49: shr eax, b1 0xb
         // 00424c4c: mov b2 dx, b2 ds:[esi+0x1c8]
         // 00424c53: movzx ebp, b2 dx
         // 00424c56: imul eax, ebp
         // 00424c59: cmp edi, eax
         // 00424c5b: jnb 0x424c7d
      [-]89c6b8????????29e88b6c2438c1f8058d0402668985c80100008b442454eb26
         // 00424c5d: mov esi, eax
         // 00424c5f: mov eax, 0x800
         // 00424c64: sub eax, ebp
         // 00424c66: mov ebp, ss:[esp+0x38]
         // 00424c6a: sar eax, b1 0x5
         // 00424c6d: lea eax, ds:[edx+eax]
         // 00424c70: mov b2 ss:[ebp+0x1c8], b2 ax
         // 00424c77: mov eax, ss:[esp+0x54]
         // 00424c7b: jmp 0x424ca3
      [-]89ce29c729c689d066c1e8056629c28b442438668990c80100008b5424548b44245089542450
         // 00424c7d: mov esi, ecx
         // 00424c7f: sub edi, eax
         // 00424c81: sub esi, eax
         // 00424c83: mov eax, edx
         // 00424c85: shr b2 ax, b1 0x5
         // 00424c89: sub b2 dx, b2 ax
         // 00424c8c: mov eax, ss:[esp+0x38]
         // 00424c90: mov b2 ds:[eax+0x1c8], b2 dx
         // 00424c97: mov edx, ss:[esp+0x54]
         // 00424c9b: mov eax, ss:[esp+0x50]
         // 00424c9f: mov ss:[esp+0x50], edx
      [-]8b4c2458894c2454
         // 00424ca3: mov ecx, ss:[esp+0x58]
         // 00424ca7: mov ss:[esp+0x54], ecx
      [-]8b6c245c8944245c896c2458
         // 00424cab: mov ebp, ss:[esp+0x5c]
         // 00424caf: mov ss:[esp+0x5c], eax
         // 00424cb3: mov ss:[esp+0x58], ebp
      [-]31c0837c2460068b4c24780f9fc081c1????????8d44400889442460
         // 00424cb7: xor eax, eax
         // 00424cb9: cmp ss:[esp+0x60], 0x6
         // 00424cbe: mov ecx, ss:[esp+0x78]
         // 00424cc2: setnle b1 al
         // 00424cc5: add ecx, 0xa68
         // 00424ccb: lea eax, ds:[eax+eax*0x2]
         // 00424ccf: mov ss:[esp+0x60], eax
      [-]81fe????????7716
         // 00424cd3: cmp esi, 0xffffff
         // 00424cd9: ja 0x424cf1
      [-]3b5c244c0f84f3030000
         // 00424cdb: cmp ebx, ss:[esp+0x4c]
         // 00424cdf: jz 0x4250d8
      [-]0fb603c1e708c1e6084309c7
         // 00424ce5: movzx eax, b1 ds:[ebx]
         // 00424ce8: shl edi, b1 0x8
         // 00424ceb: shl esi, b1 0x8
         // 00424cee: inc ebx
         // 00424cef: or edi, eax
      [-]668b1189f0c1e80b0fb7ea0fafc539c7732f
         // 00424cf1: mov b2 dx, b2 ds:[ecx]
         // 00424cf4: mov eax, esi
         // 00424cf6: shr eax, b1 0xb
         // 00424cf9: movzx ebp, b2 dx
         // 00424cfc: imul eax, ebp
         // 00424cff: cmp edi, eax
         // 00424d01: jnb 0x424d32
      [-]89442448b8????????29e8c164244404c1f805c74424????????008d04026689018b4424448d4c0104894c2410eb72
         // 00424d03: mov ss:[esp+0x48], eax
         // 00424d07: mov eax, 0x800
         // 00424d0c: sub eax, ebp
         // 00424d0e: shl ss:[esp+0x44], b1 0x4
         // 00424d13: sar eax, b1 0x5
         // 00424d16: mov ss:[esp+0x2c], 0x0
         // 00424d1e: lea eax, ds:[edx+eax]
         // 00424d21: mov b2 ds:[ecx], b2 ax
         // 00424d24: mov eax, ss:[esp+0x44]
         // 00424d28: lea ecx, ds:[ecx+eax+0x4]
         // 00424d2c: mov ss:[esp+0x10], ecx
         // 00424d30: jmp 0x424da4
      [-]29c629c789d066c1e8056629c281fe????????6689117716
         // 00424d32: sub esi, eax
         // 00424d34: sub edi, eax
         // 00424d36: mov eax, edx
         // 00424d38: shr b2 ax, b1 0x5
         // 00424d3c: sub b2 dx, b2 ax
         // 00424d3f: cmp esi, 0xffffff
         // 00424d45: mov b2 ds:[ecx], b2 dx
         // 00424d48: ja 0x424d60
      [-]3b5c244c0f8484030000
         // 00424d4a: cmp ebx, ss:[esp+0x4c]
         // 00424d4e: jz 0x4250d8
      [-]0fb603c1e708c1e6084309c7
         // 00424d54: movzx eax, b1 ds:[ebx]
         // 00424d57: shl edi, b1 0x8
         // 00424d5a: shl esi, b1 0x8
         // 00424d5d: inc ebx
         // 00424d5e: or edi, eax
      [-]668b510289f0c1e80b0fb7ea0fafc539c7733b
         // 00424d60: mov b2 dx, b2 ds:[ecx+0x2]
         // 00424d64: mov eax, esi
         // 00424d66: shr eax, b1 0xb
         // 00424d69: movzx ebp, b2 dx
         // 00424d6c: imul eax, ebp
         // 00424d6f: cmp edi, eax
         // 00424d71: jnb 0x424dae
      [-]89442448b8????????29e8c164244404c1f805c744242c????????8d04028b542444668941028d8c11????????894c2410
         // 00424d73: mov ss:[esp+0x48], eax
         // 00424d77: mov eax, 0x800
         // 00424d7c: sub eax, ebp
         // 00424d7e: shl ss:[esp+0x44], b1 0x4
         // 00424d83: sar eax, b1 0x5
         // 00424d86: mov ss:[esp+0x2c], 0x8
         // 00424d8e: lea eax, ds:[edx+eax]
         // 00424d91: mov edx, ss:[esp+0x44]
         // 00424d95: mov b2 ds:[ecx+0x2], b2 ax
         // 00424d99: lea ecx, ds:[ecx+edx+0x104]
         // 00424da0: mov ss:[esp+0x10], ecx
      [-]c7442430????????eb2f
         // 00424da4: mov ss:[esp+0x30], 0x3
         // 00424dac: jmp 0x424ddd
      [-]29c629c789d08974244866c1e805c744242c????????6629c2c7442430????????6689510281c1????????894c2410
         // 00424dae: sub esi, eax
         // 00424db0: sub edi, eax
         // 00424db2: mov eax, edx
         // 00424db4: mov ss:[esp+0x48], esi
         // 00424db8: shr b2 ax, b1 0x5
         // 00424dbc: mov ss:[esp+0x2c], 0x10
         // 00424dc4: sub b2 dx, b2 ax
         // 00424dc7: mov ss:[esp+0x30], 0x8
         // 00424dcf: mov b2 ds:[ecx+0x2], b2 dx
         // 00424dd3: add ecx, 0x204
         // 00424dd9: mov ss:[esp+0x10], ecx
      [-]8b4c2430ba????????894c2428
         // 00424ddd: mov ecx, ss:[esp+0x30]
         // 00424de1: mov edx, 0x1
         // 00424de6: mov ss:[esp+0x28], ecx
      [-]8d2c128b74241001ee817c2448????????7718
         // 00424dea: lea ebp, ds:[edx+edx]
         // 00424ded: mov esi, ss:[esp+0x10]
         // 00424df1: add esi, ebp
         // 00424df3: cmp ss:[esp+0x48], 0xffffff
         // 00424dfb: ja 0x424e15
      [-]3b5c244c0f84d1020000
         // 00424dfd: cmp ebx, ss:[esp+0x4c]
         // 00424e01: jz 0x4250d8
      [-]c1642448080fb603c1e7084309c7
         // 00424e07: shl ss:[esp+0x48], b1 0x8
         // 00424e0c: movzx eax, b1 ds:[ebx]
         // 00424e0f: shl edi, b1 0x8
         // 00424e12: inc ebx
         // 00424e13: or edi, eax
      [-]8b442448668b16c1e80b0fb7ca0fafc139c77318
         // 00424e15: mov eax, ss:[esp+0x48]
         // 00424e19: mov b2 dx, b2 ds:[esi]
         // 00424e1c: shr eax, b1 0xb
         // 00424e1f: movzx ecx, b2 dx
         // 00424e22: imul eax, ecx
         // 00424e25: cmp edi, eax
         // 00424e27: jnb 0x424e41
      [-]89442448b8????????29c8c1f8058d040289ea668906eb15
         // 00424e29: mov ss:[esp+0x48], eax
         // 00424e2d: mov eax, 0x800
         // 00424e32: sub eax, ecx
         // 00424e34: sar eax, b1 0x5
         // 00424e37: lea eax, ds:[edx+eax]
         // 00424e3a: mov edx, ebp
         // 00424e3c: mov b2 ds:[esi], b2 ax
         // 00424e3f: jmp 0x424e56
      [-]2944244829c789d066c1e8056629c26689168d5501
         // 00424e41: sub ss:[esp+0x48], eax
         // 00424e45: sub edi, eax
         // 00424e47: mov eax, edx
         // 00424e49: shr b2 ax, b1 0x5
         // 00424e4d: sub b2 dx, b2 ax
         // 00424e50: mov b2 ds:[esi], b2 dx
         // 00424e53: lea edx, ss:[ebp+0x1]
      [-]8b7424284e897424287589
         // 00424e56: mov esi, ss:[esp+0x28]
         // 00424e5a: dec esi
         // 00424e5b: mov ss:[esp+0x28], esi
         // 00424e5f: jnz 0x424dea
      [-]8a4c2430b8????????d3e029c20354242c837c2460038954240c0f8fe7010000
         // 00424e61: mov b1 cl, b1 ss:[esp+0x30]
         // 00424e65: mov eax, 0x1
         // 00424e6a: shl eax, b1 cl
         // 00424e6c: sub edx, eax
         // 00424e6e: add edx, ss:[esp+0x2c]
         // 00424e72: cmp ss:[esp+0x60], 0x3
         // 00424e77: mov ss:[esp+0xc], edx
         // 00424e7b: jg 0x425068
      [-]834424600783fa0389d07e05
         // 00424e81: add ss:[esp+0x60], 0x7
         // 00424e86: cmp edx, 0x3
         // 00424e89: mov eax, edx
         // 00424e8b: jle 0x424e92
      [-]b8????????
         // 00424e8d: mov eax, 0x3
      [-]8b742478c1e007c7442424????????8d8406????????89442408b8????????
         // 00424e92: mov esi, ss:[esp+0x78]
         // 00424e96: shl eax, b1 0x7
         // 00424e99: mov ss:[esp+0x24], 0x6
         // 00424ea1: lea eax, ds:[esi+eax+0x360]
         // 00424ea8: mov ss:[esp+0x8], eax
         // 00424eac: mov eax, 0x1
      [-]8d2c008b74240801ee817c2448????????7718
         // 00424eb1: lea ebp, ds:[eax+eax]
         // 00424eb4: mov esi, ss:[esp+0x8]
         // 00424eb8: add esi, ebp
         // 00424eba: cmp ss:[esp+0x48], 0xffffff
         // 00424ec2: ja 0x424edc
      [-]3b5c244c0f840a020000
         // 00424ec4: cmp ebx, ss:[esp+0x4c]
         // 00424ec8: jz 0x4250d8
      [-]c1642448080fb603c1e7084309c7
         // 00424ece: shl ss:[esp+0x48], b1 0x8
         // 00424ed3: movzx eax, b1 ds:[ebx]
         // 00424ed6: shl edi, b1 0x8
         // 00424ed9: inc ebx
         // 00424eda: or edi, eax
      [-]8b442448668b16c1e80b0fb7ca0fafc139c77318
         // 00424edc: mov eax, ss:[esp+0x48]
         // 00424ee0: mov b2 dx, b2 ds:[esi]
         // 00424ee3: shr eax, b1 0xb
         // 00424ee6: movzx ecx, b2 dx
         // 00424ee9: imul eax, ecx
         // 00424eec: cmp edi, eax
         // 00424eee: jnb 0x424f08
      [-]89442448b8????????29c8c1f8058d040266890689e8eb15
         // 00424ef0: mov ss:[esp+0x48], eax
         // 00424ef4: mov eax, 0x800
         // 00424ef9: sub eax, ecx
         // 00424efb: sar eax, b1 0x5
         // 00424efe: lea eax, ds:[edx+eax]
         // 00424f01: mov b2 ds:[esi], b2 ax
         // 00424f04: mov eax, ebp
         // 00424f06: jmp 0x424f1d
      [-]2944244829c789d066c1e8056629c28d4501668916
         // 00424f08: sub ss:[esp+0x48], eax
         // 00424f0c: sub edi, eax
         // 00424f0e: mov eax, edx
         // 00424f10: shr b2 ax, b1 0x5
         // 00424f14: sub b2 dx, b2 ax
         // 00424f17: lea eax, ss:[ebp+0x1]
         // 00424f1a: mov b2 ds:[esi], b2 dx
      [-]8b6c24244d896c24247589
         // 00424f1d: mov ebp, ss:[esp+0x24]
         // 00424f21: dec ebp
         // 00424f22: mov ss:[esp+0x24], ebp
         // 00424f26: jnz 0x424eb1
      [-]8d50c083fa038914240f8e27010000
         // 00424f28: lea edx, ds:[eax+0xffffffffffffffc0]
         // 00424f2b: cmp edx, 0x3
         // 00424f2e: mov ss:[esp], edx
         // 00424f31: jle 0x42505e
      [-]89d089d6d1f883e6018d48ff83ce0283fa0d894c24207f1c
         // 00424f37: mov eax, edx
         // 00424f39: mov esi, edx
         // 00424f3b: sar eax, b1 0x1
         // 00424f3d: and esi, 0x1
         // 00424f40: lea ecx, ds:[eax+0xffffffffffffffff]
         // 00424f43: or esi, 0x2
         // 00424f46: cmp edx, 0xd
         // 00424f49: mov ss:[esp+0x20], ecx
         // 00424f4d: jg 0x424f6b
      [-]8b6c2478d3e601d28934248d44750029d005????????89442404eb56
         // 00424f4f: mov ebp, ss:[esp+0x78]
         // 00424f53: shl esi, b1 cl
         // 00424f55: add edx, edx
         // 00424f57: mov ss:[esp], esi
         // 00424f5a: lea eax, ss:[ebp+esi*0x2]
         // 00424f5e: sub eax, edx
         // 00424f60: add eax, 0x55e
         // 00424f65: mov ss:[esp+0x4], eax
         // 00424f69: jmp 0x424fc1
      [-]817c2448????????7718
         // 00424f6e: cmp ss:[esp+0x48], 0xffffff
         // 00424f76: ja 0x424f90
      [-]3b5c244c0f8456010000
         // 00424f78: cmp ebx, ss:[esp+0x4c]
         // 00424f7c: jz 0x4250d8
      [-]c1642448080fb603c1e7084309c7
         // 00424f82: shl ss:[esp+0x48], b1 0x8
         // 00424f87: movzx eax, b1 ds:[ebx]
         // 00424f8a: shl edi, b1 0x8
         // 00424f8d: inc ebx
         // 00424f8e: or edi, eax
      [-]d16c244801f63b7c24487207
         // 00424f90: shr ss:[esp+0x48], b1 0x1
         // 00424f94: add esi, esi
         // 00424f96: cmp edi, ss:[esp+0x48]
         // 00424f9a: jb 0x424fa3
      [-]2b7c244883ce01
         // 00424f9c: sub edi, ss:[esp+0x48]
         // 00424fa0: or esi, 0x1
      [-]8b442478c1e60489342405????????c7442420????????89442404
         // 00424fa6: mov eax, ss:[esp+0x78]
         // 00424faa: shl esi, b1 0x4
         // 00424fad: mov ss:[esp], esi
         // 00424fb0: add eax, 0x644
         // 00424fb5: mov ss:[esp+0x20], 0x4
         // 00424fbd: mov ss:[esp+0x4], eax
      [-]c744241c????????b8????????
         // 00424fc1: mov ss:[esp+0x1c], 0x1
         // 00424fc9: mov eax, 0x1
      [-]8b6c240401c08944241801c5817c2448????????7718
         // 00424fce: mov ebp, ss:[esp+0x4]
         // 00424fd2: add eax, eax
         // 00424fd4: mov ss:[esp+0x18], eax
         // 00424fd8: add ebp, eax
         // 00424fda: cmp ss:[esp+0x48], 0xffffff
         // 00424fe2: ja 0x424ffc
      [-]3b5c244c0f84ea000000
         // 00424fe4: cmp ebx, ss:[esp+0x4c]
         // 00424fe8: jz 0x4250d8
      [-]c1642448080fb603c1e7084309c7
         // 00424fee: shl ss:[esp+0x48], b1 0x8
         // 00424ff3: movzx eax, b1 ds:[ebx]
         // 00424ff6: shl edi, b1 0x8
         // 00424ff9: inc ebx
         // 00424ffa: or edi, eax
      [-]8b442448668b5500c1e80b0fb7f20fafc639c7731b
         // 00424ffc: mov eax, ss:[esp+0x48]
         // 00425000: mov b2 dx, b2 ss:[ebp+0x0]
         // 00425004: shr eax, b1 0xb
         // 00425007: movzx esi, b2 dx
         // 0042500a: imul eax, esi
         // 0042500d: cmp edi, eax
         // 0042500f: jnb 0x42502c
      [-]89442448b8????????29f0c1f8058d0402668945008b442418eb1f
         // 00425011: mov ss:[esp+0x48], eax
         // 00425015: mov eax, 0x800
         // 0042501a: sub eax, esi
         // 0042501c: sar eax, b1 0x5
         // 0042501f: lea eax, ds:[edx+eax]
         // 00425022: mov b2 ss:[ebp+0x0], b2 ax
         // 00425026: mov eax, ss:[esp+0x18]
         // 0042502a: jmp 0x42504b
      [-]2944244829c789d066c1e8056629c28b442418668955008b54241c40091424
         // 0042502c: sub ss:[esp+0x48], eax
         // 00425030: sub edi, eax
         // 00425032: mov eax, edx
         // 00425034: shr b2 ax, b1 0x5
         // 00425038: sub b2 dx, b2 ax
         // 0042503b: mov eax, ss:[esp+0x18]
         // 0042503f: mov b2 ss:[ebp+0x0], b2 dx
         // 00425043: mov edx, ss:[esp+0x1c]
         // 00425047: inc eax
         // 00425048: or ss:[esp], edx
      [-]8b4c2420d164241c49894c24200f8570ffffff
         // 0042504b: mov ecx, ss:[esp+0x20]
         // 0042504f: shl ss:[esp+0x1c], b1 0x1
         // 00425053: dec ecx
         // 00425054: mov ss:[esp+0x20], ecx
         // 00425058: jnz 0x424fce
      [-]8b3424468974245c7459
         // 0042505e: mov esi, ss:[esp]
         // 00425061: inc esi
         // 00425062: mov ss:[esp+0x5c], esi
         // 00425066: jz 0x4250c1
      [-]8b4c240c8b6c247483c102396c245c775f
         // 00425068: mov ecx, ss:[esp+0xc]
         // 0042506c: mov ebp, ss:[esp+0x74]
         // 00425070: add ecx, 0x2
         // 00425073: cmp ss:[esp+0x5c], ebp
         // 00425077: ja 0x4250d8
      [-]8b8424????????89ea2b44245c039424????????8d3428
         // 00425079: mov eax, ss:[esp+0xa0]
         // 00425080: mov edx, ebp
         // 00425082: sub eax, ss:[esp+0x5c]
         // 00425086: add edx, ss:[esp+0xa0]
         // 0042508d: lea esi, ds:[eax+ebp]
      [-]8a064688442473880242ff44247449740f
         // 00425090: mov b1 al, b1 ds:[esi]
         // 00425092: inc esi
         // 00425093: mov b1 ss:[esp+0x73], b1 al
         // 00425097: mov b1 ds:[edx], b1 al
         // 00425099: inc edx
         // 0042509a: inc ss:[esp+0x74]
         // 0042509e: dec ecx
         // 0042509f: jz 0x4250b0
      [-]8bac24????????396c247472e2
         // 004250a1: mov ebp, ss:[esp+0xa4]
         // 004250a8: cmp ss:[esp+0x74], ebp
         // 004250ac: jb 0x425090
      [-]8b8424????????394424740f82bbf6ffff
         // 004250b0: mov eax, ss:[esp+0xa4]
         // 004250b7: cmp ss:[esp+0x74], eax
         // 004250bb: jb 0x42477c
      [-]817c2448????????7715
         // 004250c1: cmp ss:[esp+0x48], 0xffffff
         // 004250c9: ja 0x4250e0
      [-]3b5c244cb8????????7429
         // 004250cb: cmp ebx, ss:[esp+0x4c]
         // 004250cf: mov eax, 0x1
         // 004250d4: jz 0x4250ff
      [-]2b9c24????????31c08b9424????????8b4c2474891a8b9c24????????890b
         // 004250e0: sub ebx, ss:[esp+0x94]
         // 004250e7: xor eax, eax
         // 004250e9: mov edx, ss:[esp+0x9c]
         // 004250f0: mov ecx, ss:[esp+0x74]
         // 004250f4: mov ds:[edx], ebx
         // 004250f6: mov ebx, ss:[esp+0xa8]
         // 004250fd: mov ds:[ebx], ecx
      [-]83c47c5b5e5f5d0373fc037bf831c08d8c24????????89ec
         // 004250ff: add esp, 0x7c
         // 00425102: pop ebx
         // 00425103: pop esi
         // 00425104: pop edi
         // 00425105: pop ebp
         // 00425106: add esi, ds:[ebx+0xfffffffffffffffc]
         // 00425109: add edi, ds:[ebx+0xfffffffffffffff8]
         // 0042510c: xor eax, eax
         // 0042510e: lea ecx, ss:[esp+0xffffffffffffff00]
         // 00425115: mov esp, ebp
      [-]5039cc75fb
         // 00425117: push eax
         // 00425118: cmp esp, ecx
         // 0042511a: jnz 0x425117
      [-]89ec31c95e89f7b9????????
         // 0042511c: mov esp, ebp
         // 0042511e: xor ecx, ecx
         // 00425120: pop esi
         // 00425121: mov edi, esi
         // 00425123: mov ecx, 0xc8
      [-]8a07472ce8
         // 00425128: mov b1 al, b1 ds:[edi]
         // 0042512a: inc edi
         // 0042512b: sub b1 al, b1 0xe8
      [-]3c0177f7
         // 0042512d: cmp b1 al, b1 0x1
         // 0042512f: ja 0x425128
      [-]803f0475f2
         // 00425131: cmp b1 ds:[edi], b1 0x4
         // 00425134: jnz 0x425128
      [-]8b078a5f0466c1e808c1c01086c429f880ebe801f0890783c70588d8e2d9
         // 00425136: mov eax, ds:[edi]
         // 00425138: mov b1 bl, b1 ds:[edi+0x4]
         // 0042513b: shr b2 ax, b1 0x8
         // 0042513f: rol eax, b1 0x10
         // 00425142: xchg b1 al, b1 ah
         // 00425144: sub eax, edi
         // 00425146: sub b1 bl, b1 0xe8
         // 00425149: add eax, esi
         // 0042514b: mov ds:[edi], eax
         // 0042514d: add edi, 0x5
         // 00425150: mov b1 al, b1 bl
         // 00425152: loop 0x42512d
      [-]8dbe????????
         // 00425154: lea edi, ds:[esi+0x22000]
      [-]8b0709c0743c
         // 0042515a: mov eax, ds:[edi]
         // 0042515c: or eax, eax
         // 0042515e: jz 0x42519c
      [-]8b5f048d8430????????01f35083c708ff96????????95
         // 00425160: mov ebx, ds:[edi+0x4]
         // 00425163: lea eax, ds:[eax+esi+0x25000]
         // 0042516a: add ebx, esi
         // 0042516c: push eax
         // 0042516d: add edi, 0x8
         // 00425170: call ds:[esi+0x25064]
         // 00425176: xchg eax, ebp
      [-]8a074708c074dc
         // 00425177: mov b1 al, b1 ds:[edi]
         // 00425179: inc edi
         // 0042517a: or b1 al, b1 al
         // 0042517c: jz 0x42515a
      [-]89f95748f2ae55ff96????????09c07407
         // 0042517e: mov ecx, edi
         // 00425180: push edi
         // 00425181: dec eax
         // 00425182: repne scasbb 
         // 00425184: push ebp
         // 00425185: call ds:[esi+0x25068]
         // 0042518b: or eax, eax
         // 0042518d: jz 0x425196
      [-]890383c304ebe1
         // 0042518f: mov ds:[ebx], eax
         // 00425191: add ebx, 0x4
         // 00425194: jmp 0x425177
      [-]ff96????????
         // 00425196: call ds:[esi+0x25078]
      [-]8bae????????8dbe????????bb????????50546a045357ffd58d87????????80207f8060287f585054505357ffd558618d442480
         // 0042519c: mov ebp, ds:[esi+0x2506c]
         // 004251a2: lea edi, ds:[esi+0xfffffffffffff000]
         // 004251a8: mov ebx, 0x1000
         // 004251ad: push eax
         // 004251ae: push esp
         // 004251af: push 0x4
         // 004251b1: push ebx
         // 004251b2: push edi
         // 004251b3: call ebp
         // 004251b5: lea eax, ds:[edi+0x1ef]
         // 004251bb: and b1 ds:[eax], b1 0x7f
         // 004251be: and b1 ds:[eax+0x28], b1 0x7f
         // 004251c2: pop eax
         // 004251c3: push eax
         // 004251c4: push esp
         // 004251c5: push eax
         // 004251c6: push ebx
         // 004251c7: push edi
         // 004251c8: call ebp
         // 004251ca: pop eax
         // 004251cb: popa 
         // 004251cc: lea eax, ss:[esp+0xffffffffffffff80]
      [-]6a0039c475fa
         // 004251d0: push 0x0
         // 004251d2: cmp esp, eax
         // 004251d4: jnz 0x4251d0
      [-]83ec80e922befdff
         // 004251d6: sub esp, 0xffffffffffffff80
         // 004251d9: jmp 0x401000

  }
  condition:
    all of them
}
