rule recex_10_1 {
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
      [-]8b01ba????????03d083f0ff33c2
         // 00401020: mov eax, ds:[ecx]
         // 00401022: mov edx, 0x7efefeff
         // 00401027: add edx, eax
         // 00401029: xor eax, 0xffffffffffffffff
         // 0040102c: xor eax, edx
      [-]a9????????74e8
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
      [-]ff75fce8993d000083c404
         // 0040109b: push ss:[ebp+0xfffffffffffffffc]
         // 0040109e: call 0x404e3c
         // 004010a3: add esp, 0x4
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
      [-]8b5424048b4c2408
         // 004010c7: mov edx, ss:[esp+0x4]
         // 004010cb: mov ecx, ss:[esp+0x8]
      [-]8039007401
         // 004010d9: cmp b1 ds:[ecx], b1 0x0
         // 004010dc: jz 0x4010df
      [-]803a007401
         // 004010e6: cmp b1 ds:[edx], b1 0x0
         // 004010e9: jz 0x4010ec
      [-]f7c2????????7537
         // 004010ed: test edx, 0x3
         // 004010f3: jnz 0x40112c
      [-]8b023a01752b
         // 004010f5: mov eax, ds:[edx]
         // 004010f7: cmp b1 al, b1 ds:[ecx]
         // 004010f9: jnz 0x401126
      [-]0ac07424
         // 004010fb: or b1 al, b1 al
         // 004010fd: jz 0x401123
      [-]3a61017522
         // 004010ff: cmp b1 ah, b1 ds:[ecx+0x1]
         // 00401102: jnz 0x401126
      [-]0ae4741b
         // 00401104: or b1 ah, b1 ah
         // 00401106: jz 0x401123
      [-]c1e8103a41027516
         // 00401108: shr eax, b1 0x10
         // 0040110b: cmp b1 al, b1 ds:[ecx+0x2]
         // 0040110e: jnz 0x401126
      [-]0ac0740f
         // 00401110: or b1 al, b1 al
         // 00401112: jz 0x401123
      [-]3a6103750d
         // 00401114: cmp b1 ah, b1 ds:[ecx+0x3]
         // 00401117: jnz 0x401126
      [-]0ae475d2
         // 0040111f: or b1 ah, b1 ah
         // 00401121: jnz 0x4010f5
      [-]1bc0d1e040c3
         // 00401126: sbb eax, eax
         // 00401128: shl eax, b1 0x1
         // 0040112a: inc eax
         // 0040112b: retn 
      [-]f7c2????????7414
         // 0040112c: test edx, 0x1
         // 00401132: jz 0x401148
      [-]8a02423a0175eb
         // 00401134: mov b1 al, b1 ds:[edx]
         // 00401136: inc edx
         // 00401137: cmp b1 al, b1 ds:[ecx]
         // 00401139: jnz 0x401126
      [-]410ac074e3
         // 0040113b: inc ecx
         // 0040113c: or b1 al, b1 al
         // 0040113e: jz 0x401123
      [-]f7c2????????74ad
         // 00401140: test edx, 0x2
         // 00401146: jz 0x4010f5
      [-]3a0175d4
         // 0040114e: cmp b1 al, b1 ds:[ecx]
         // 00401150: jnz 0x401126
      [-]0ac074cd
         // 00401152: or b1 al, b1 al
         // 00401154: jz 0x401123
      [-]3a610175cb
         // 00401156: cmp b1 ah, b1 ds:[ecx+0x1]
         // 00401159: jnz 0x401126
      [-]0ae474c4
         // 0040115b: or b1 ah, b1 ah
         // 0040115d: jz 0x401123
      [-]6a004b75fb
         // 00401165: push 0x0
         // 00401167: dec ebx
         // 00401168: jnz 0x401165
      [-]0faf03ebf5
         // 0040117f: imul eax, ds:[ebx]
         // 00401182: jmp 0x401179
      [-]558bec51
         // 00401185: push ebp
         // 00401186: mov ebp, esp
         // 00401188: push ecx
      [-]5283c20852e88d3c000083c404
         // 004011a5: push edx
         // 004011a6: add edx, 0x8
         // 004011a9: push edx
         // 004011aa: call 0x404e3c
         // 004011af: add esp, 0x4
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
      [-]558bec81ec????????c745fc????????6a00ff75fce8400e0000c745fc????????6a00ff75fcc745f8????????6a00ff75f8e81b10000068????????bb????????e8ce40000083c4048945fc68????????6a0068????????68????????
         // 004011dc: push ebp
         // 004011dd: mov ebp, esp
         // 004011df: sub esp, 0x1c
         // 004011e5: mov ss:[ebp+0xfffffffffffffffc], 0x0
         // 004011ec: push 0x0
         // 004011ee: push ss:[ebp+0xfffffffffffffffc]
         // 004011f1: call 0x402036
         // 004011f6: mov ss:[ebp+0xfffffffffffffffc], 0x0
         // 004011fd: push 0x0
         // 004011ff: push ss:[ebp+0xfffffffffffffffc]
         // 00401202: mov ss:[ebp+0xfffffffffffffff8], 0x0
         // 00401209: push 0x0
         // 0040120b: push ss:[ebp+0xfffffffffffffff8]
         // 0040120e: call 0x40222e
         // 00401213: push 0x0
         // 00401218: mov ebx, 0x104
         // 0040121d: call 0x4052f0
         // 00401222: add esp, 0x4
         // 00401225: mov ss:[ebp+0xfffffffffffffffc], eax
         // 00401228: push 0xffffffff80000301
         // 0040122d: push 0x0
         // 0040122f: push 0x9
         // 00401234: push 0x1
      [-]b8????????e80840000083c4108945f8
         // 0040123e: mov eax, 0x408090
         // 00401243: call 0x405250
         // 00401248: add esp, 0x10
         // 0040124b: mov ss:[ebp+0xfffffffffffffff8], eax
      [-]e80bfeffff83c4088945f48b5df8
         // 0040125b: call 0x40106b
         // 00401260: add esp, 0x8
         // 00401263: mov ss:[ebp+0xfffffffffffffff4], eax
         // 00401266: mov ebx, ss:[ebp+0xfffffffffffffff8]
      [-]53e8c33b000083c404
         // 0040126d: push ebx
         // 0040126e: call 0x404e36
         // 00401273: add esp, 0x4
      [-]8b45f450ff75fce845feffff83c40883f800
         // 00401276: mov eax, ss:[ebp+0xfffffffffffffff4]
         // 00401279: push eax
         // 0040127a: push ss:[ebp+0xfffffffffffffffc]
         // 0040127d: call 0x4010c7
         // 00401282: add esp, 0x8
         // 00401285: cmp eax, 0x0
      [-]0f95c08945f08b5dfc
         // 0040128d: setnz b1 al
         // 00401290: mov ss:[ebp+0xfffffffffffffff0], eax
         // 00401293: mov ebx, ss:[ebp+0xfffffffffffffffc]
      [-]53e8963b000083c404
         // 0040129a: push ebx
         // 0040129b: call 0x404e36
         // 004012a0: add esp, 0x4
      [-]53e8863b000083c404
         // 004012aa: push ebx
         // 004012ab: call 0x404e36
         // 004012b0: add esp, 0x4
      [-]837df0000f8447030000
         // 004012b3: cmp ss:[ebp+0xfffffffffffffff0], 0x0
         // 004012b7: jz 0x401604
      [-]68????????6a0068????????68????????
         // 004012bd: push 0xffffffff80000301
         // 004012c2: push 0x0
         // 004012c4: push 0x9
         // 004012c9: push 0x1
      [-]b8????????e8733f000083c4108945fc
         // 004012d3: mov eax, 0x408090
         // 004012d8: call 0x405250
         // 004012dd: add esp, 0x10
         // 004012e0: mov ss:[ebp+0xfffffffffffffffc], eax
      [-]e876fdffff83c4088945f88b5dfc
         // 004012f0: call 0x40106b
         // 004012f5: add esp, 0x8
         // 004012f8: mov ss:[ebp+0xfffffffffffffff8], eax
         // 004012fb: mov ebx, ss:[ebp+0xfffffffffffffffc]
      [-]53e82e3b000083c404
         // 00401302: push ebx
         // 00401303: call 0x404e36
         // 00401308: add esp, 0x4
      [-]68????????6a008b45f8
         // 0040130b: push 0xffffffff80000004
         // 00401310: push 0x0
         // 00401312: mov eax, ss:[ebp+0xfffffffffffffff8]
      [-]b8????????
         // 00401319: mov eax, 0x4212e9
      [-]5068????????bb????????e86240000083c4108b5df8
         // 0040131e: push eax
         // 0040131f: push 0x1
         // 00401324: mov ebx, 0x234
         // 00401329: call 0x405390
         // 0040132e: add esp, 0x10
         // 00401331: mov ebx, ss:[ebp+0xfffffffffffffff8]
      [-]53e8f83a000083c404
         // 00401338: push ebx
         // 00401339: call 0x404e36
         // 0040133e: add esp, 0x4
      [-]68????????6a0068????????68????????
         // 00401341: push 0xffffffff80000301
         // 00401346: push 0x0
         // 00401348: push 0x9
         // 0040134d: push 0x1
      [-]b8????????e8ef3e000083c4108945fc
         // 00401357: mov eax, 0x408090
         // 0040135c: call 0x405250
         // 00401361: add esp, 0x10
         // 00401364: mov ss:[ebp+0xfffffffffffffffc], eax
      [-]e8f2fcffff83c4088945f88b5dfc
         // 00401374: call 0x40106b
         // 00401379: add esp, 0x8
         // 0040137c: mov ss:[ebp+0xfffffffffffffff8], eax
         // 0040137f: mov ebx, ss:[ebp+0xfffffffffffffffc]
      [-]53e8aa3a000083c404
         // 00401386: push ebx
         // 00401387: call 0x404e36
         // 0040138c: add esp, 0x4
      [-]68????????6a008b45f8
         // 0040138f: push 0xffffffff80000004
         // 00401394: push 0x0
         // 00401396: mov eax, ss:[ebp+0xfffffffffffffff8]
      [-]b8????????
         // 0040139d: mov eax, 0x4212e9
      [-]5068????????bb????????e8de3f000083c4108b5df8
         // 004013a2: push eax
         // 004013a3: push 0x1
         // 004013a8: mov ebx, 0x234
         // 004013ad: call 0x405390
         // 004013b2: add esp, 0x10
         // 004013b5: mov ebx, ss:[ebp+0xfffffffffffffff8]
      [-]53e8743a000083c404
         // 004013bc: push ebx
         // 004013bd: call 0x404e36
         // 004013c2: add esp, 0x4
      [-]68????????6a0068????????68????????
         // 004013c5: push 0xffffffff80000301
         // 004013ca: push 0x0
         // 004013cc: push 0x9
         // 004013d1: push 0x1
      [-]b8????????e86b3e000083c4108945fc
         // 004013db: mov eax, 0x408090
         // 004013e0: call 0x405250
         // 004013e5: add esp, 0x10
         // 004013e8: mov ss:[ebp+0xfffffffffffffffc], eax
      [-]e86efcffff83c4088945f88b5dfc
         // 004013f8: call 0x40106b
         // 004013fd: add esp, 0x8
         // 00401400: mov ss:[ebp+0xfffffffffffffff8], eax
         // 00401403: mov ebx, ss:[ebp+0xfffffffffffffffc]
      [-]53e8263a000083c404
         // 0040140a: push ebx
         // 0040140b: call 0x404e36
         // 00401410: add esp, 0x4
      [-]68????????6a008b45f8
         // 00401413: push 0xffffffff80000004
         // 00401418: push 0x0
         // 0040141a: mov eax, ss:[ebp+0xfffffffffffffff8]
      [-]b8????????
         // 00401421: mov eax, 0x4212e9
      [-]5068????????bb????????e85a3f000083c4108b5df8
         // 00401426: push eax
         // 00401427: push 0x1
         // 0040142c: mov ebx, 0x234
         // 00401431: call 0x405390
         // 00401436: add esp, 0x10
         // 00401439: mov ebx, ss:[ebp+0xfffffffffffffff8]
      [-]53e8f039000083c404
         // 00401440: push ebx
         // 00401441: call 0x404e36
         // 00401446: add esp, 0x4
      [-]68????????bb????????e8983e000083c4048945fc68????????bb????????e8533f000083c4048945f8ff75f868????????ff75fc
         // 00401449: push 0x0
         // 0040144e: mov ebx, 0x104
         // 00401453: call 0x4052f0
         // 00401458: add esp, 0x4
         // 0040145b: mov ss:[ebp+0xfffffffffffffffc], eax
         // 0040145e: push 0x0
         // 00401463: mov ebx, 0x108
         // 00401468: call 0x4053c0
         // 0040146d: add esp, 0x4
         // 00401470: mov ss:[ebp+0xfffffffffffffff8], eax
         // 00401473: push ss:[ebp+0xfffffffffffffff8]
         // 00401476: push 0x4212f6
         // 0040147b: push ss:[ebp+0xfffffffffffffffc]
      [-]e8e3fbffff83c40c8945f48b5dfc
         // 00401483: call 0x40106b
         // 00401488: add esp, 0xc
         // 0040148b: mov ss:[ebp+0xfffffffffffffff4], eax
         // 0040148e: mov ebx, ss:[ebp+0xfffffffffffffffc]
      [-]53e89b39000083c404
         // 00401495: push ebx
         // 00401496: call 0x404e36
         // 0040149b: add esp, 0x4
      [-]53e88b39000083c404
         // 004014a5: push ebx
         // 004014a6: call 0x404e36
         // 004014ab: add esp, 0x4
      [-]68????????6a0068????????68????????
         // 004014ae: push 0xffffffff80000301
         // 004014b3: push 0x0
         // 004014b5: push 0x9
         // 004014ba: push 0x1
      [-]b8????????e8823d000083c4108945f0
         // 004014c4: mov eax, 0x408090
         // 004014c9: call 0x405250
         // 004014ce: add esp, 0x10
         // 004014d1: mov ss:[ebp+0xfffffffffffffff0], eax
      [-]e885fbffff83c4088945ec8b5df0
         // 004014e1: call 0x40106b
         // 004014e6: add esp, 0x8
         // 004014e9: mov ss:[ebp+0xffffffffffffffec], eax
         // 004014ec: mov ebx, ss:[ebp+0xfffffffffffffff0]
      [-]53e83d39000083c404
         // 004014f3: push ebx
         // 004014f4: call 0x404e36
         // 004014f9: add esp, 0x4
      [-]68????????6a008b45ec
         // 004014fc: push 0xffffffff80000004
         // 00401501: push 0x0
         // 00401503: mov eax, ss:[ebp+0xffffffffffffffec]
      [-]b8????????
         // 0040150a: mov eax, 0x4212e9
      [-]5068????????6a008b45f4
         // 0040150f: push eax
         // 00401510: push 0xffffffff80000004
         // 00401515: push 0x0
         // 00401517: mov eax, ss:[ebp+0xfffffffffffffff4]
      [-]b8????????
         // 0040151e: mov eax, 0x4212e9
      [-]5068????????bb????????e82d3f000083c41c8b5df4
         // 00401523: push eax
         // 00401524: push 0x2
         // 00401529: mov ebx, 0x23c
         // 0040152e: call 0x405460
         // 00401533: add esp, 0x1c
         // 00401536: mov ebx, ss:[ebp+0xfffffffffffffff4]
      [-]53e8f338000083c404
         // 0040153d: push ebx
         // 0040153e: call 0x404e36
         // 00401543: add esp, 0x4
      [-]53e8e338000083c404
         // 0040154d: push ebx
         // 0040154e: call 0x404e36
         // 00401553: add esp, 0x4
      [-]68????????6a0068????????68????????
         // 00401556: push 0xffffffff80000301
         // 0040155b: push 0x0
         // 0040155d: push 0x9
         // 00401562: push 0x1
      [-]b8????????e8da3c000083c4108945fc
         // 0040156c: mov eax, 0x408090
         // 00401571: call 0x405250
         // 00401576: add esp, 0x10
         // 00401579: mov ss:[ebp+0xfffffffffffffffc], eax
      [-]e8ddfaffff83c4088945f88b5dfc
         // 00401589: call 0x40106b
         // 0040158e: add esp, 0x8
         // 00401591: mov ss:[ebp+0xfffffffffffffff8], eax
         // 00401594: mov ebx, ss:[ebp+0xfffffffffffffffc]
      [-]53e89538000083c404
         // 0040159b: push ebx
         // 0040159c: call 0x404e36
         // 004015a1: add esp, 0x4
      [-]e8b6fbffff68????????6a008b45f8
         // 004015a9: call 0x401164
         // 004015ae: push 0xffffffff80000004
         // 004015b3: push 0x0
         // 004015b5: mov eax, ss:[ebp+0xfffffffffffffff8]
      [-]b8????????
         // 004015bc: mov eax, 0x4212e9
      [-]5068????????6a0068????????68????????
         // 004015c1: push eax
         // 004015c2: push 0xffffffff80000301
         // 004015c7: push 0x0
         // 004015c9: push 0x4
         // 004015ce: push 0x5
      [-]b8????????e86e3c000083c4408b5df8
         // 004015d8: mov eax, 0x407f90
         // 004015dd: call 0x405250
         // 004015e2: add esp, 0x40
         // 004015e5: mov ebx, ss:[ebp+0xfffffffffffffff8]
      [-]53e84438000083c404
         // 004015ec: push ebx
         // 004015ed: call 0x404e36
         // 004015f2: add esp, 0x4
      [-]6a00e82838000083c404e9240a0000
         // 004015f5: push 0x0
         // 004015f7: call 0x404e24
         // 004015fc: add esp, 0x4
         // 004015ff: jmp 0x402028
      [-]c745fc????????6a00ff75fcc745f8????????6a00ff75f8c745f4????????6a008d45f450c745f0????????6a00ff75f06a01b8????????8945ec8d45ec50e8730d00008b5dec
         // 00401604: mov ss:[ebp+0xfffffffffffffffc], 0x0
         // 0040160b: push 0x0
         // 0040160d: push ss:[ebp+0xfffffffffffffffc]
         // 00401610: mov ss:[ebp+0xfffffffffffffff8], 0x0
         // 00401617: push 0x0
         // 00401619: push ss:[ebp+0xfffffffffffffff8]
         // 0040161c: mov ss:[ebp+0xfffffffffffffff4], 0x0
         // 00401623: push 0x0
         // 00401625: lea eax, ss:[ebp+0xfffffffffffffff4]
         // 00401628: push eax
         // 00401629: mov ss:[ebp+0xfffffffffffffff0], 0x0
         // 00401630: push 0x0
         // 00401632: push ss:[ebp+0xfffffffffffffff0]
         // 00401635: push 0x1
         // 00401637: mov eax, 0x42131f
         // 0040163c: mov ss:[ebp+0xffffffffffffffec], eax
         // 0040163f: lea eax, ss:[ebp+0xffffffffffffffec]
         // 00401642: push eax
         // 00401643: call 0x4023bb
         // 00401648: mov ebx, ss:[ebp+0xffffffffffffffec]
      [-]53e8e137000083c404
         // 0040164f: push ebx
         // 00401650: call 0x404e36
         // 00401655: add esp, 0x4
      [-]53e8d137000083c404
         // 0040165f: push ebx
         // 00401660: call 0x404e36
         // 00401665: add esp, 0x4
      [-]68????????e8741d000068????????bb????????e86f3c000083c4048945fc68????????ff75fc
         // 00401668: push 0xffffffffffffffff
         // 0040166d: call 0x4033e6
         // 00401672: push 0x0
         // 00401677: mov ebx, 0x104
         // 0040167c: call 0x4052f0
         // 00401681: add esp, 0x4
         // 00401684: mov ss:[ebp+0xfffffffffffffffc], eax
         // 00401687: push 0x421330
         // 0040168c: push ss:[ebp+0xfffffffffffffffc]
      [-]e8d2f9ffff83c4088945f88b5dfc
         // 00401694: call 0x40106b
         // 00401699: add esp, 0x8
         // 0040169c: mov ss:[ebp+0xfffffffffffffff8], eax
         // 0040169f: mov ebx, ss:[ebp+0xfffffffffffffffc]
      [-]53e88a37000083c404
         // 004016a6: push ebx
         // 004016a7: call 0x404e36
         // 004016ac: add esp, 0x4
      [-]68????????6a0068????????68????????6a008b45f8
         // 004016af: push 0xffffffff80000301
         // 004016b4: push 0x0
         // 004016b6: push 0x7
         // 004016bb: push 0xffffffff80000004
         // 004016c0: push 0x0
         // 004016c2: mov eax, ss:[ebp+0xfffffffffffffff8]
      [-]b8????????
         // 004016c9: mov eax, 0x4212e9
      [-]5068????????bb????????e8a23d000083c41c8b5df8
         // 004016ce: push eax
         // 004016cf: push 0x2
         // 004016d4: mov ebx, 0x260
         // 004016d9: call 0x405480
         // 004016de: add esp, 0x1c
         // 004016e1: mov ebx, ss:[ebp+0xfffffffffffffff8]
      [-]53e84837000083c404
         // 004016e8: push ebx
         // 004016e9: call 0x404e36
         // 004016ee: add esp, 0x4
      [-]68????????6a0068????????68????????6a0068????????68????????6a0068????????68????????bb????????e87c3d000083c42868????????bb????????e8ba3b000083c4048945fc68????????bb????????e8753c000083c4048945f8ff75f868????????ff75fc
         // 004016f1: push 0xffffffff80000301
         // 004016f6: push 0x0
         // 004016f8: push 0x0
         // 004016fd: push 0xffffffff80000004
         // 00401702: push 0x0
         // 00401704: push 0x421343
         // 00401709: push 0xffffffff80000301
         // 0040170e: push 0x0
         // 00401710: push 0x4
         // 00401715: push 0x3
         // 0040171a: mov ebx, 0x6a4
         // 0040171f: call 0x4054a0
         // 00401724: add esp, 0x28
         // 00401727: push 0x0
         // 0040172c: mov ebx, 0x104
         // 00401731: call 0x4052f0
         // 00401736: add esp, 0x4
         // 00401739: mov ss:[ebp+0xfffffffffffffffc], eax
         // 0040173c: push 0x0
         // 00401741: mov ebx, 0x108
         // 00401746: call 0x4053c0
         // 0040174b: add esp, 0x4
         // 0040174e: mov ss:[ebp+0xfffffffffffffff8], eax
         // 00401751: push ss:[ebp+0xfffffffffffffff8]
         // 00401754: push 0x4212f6
         // 00401759: push ss:[ebp+0xfffffffffffffffc]
      [-]e805f9ffff83c40c8945f48b5dfc
         // 00401761: call 0x40106b
         // 00401766: add esp, 0xc
         // 00401769: mov ss:[ebp+0xfffffffffffffff4], eax
         // 0040176c: mov ebx, ss:[ebp+0xfffffffffffffffc]
      [-]53e8bd36000083c404
         // 00401773: push ebx
         // 00401774: call 0x404e36
         // 00401779: add esp, 0x4
      [-]53e8ad36000083c404
         // 00401783: push ebx
         // 00401784: call 0x404e36
         // 00401789: add esp, 0x4
      [-]68????????6a0068????????68????????6a008b45f4
         // 0040178c: push 0xffffffff80000301
         // 00401791: push 0x0
         // 00401793: push 0x0
         // 00401798: push 0xffffffff80000004
         // 0040179d: push 0x0
         // 0040179f: mov eax, ss:[ebp+0xfffffffffffffff4]
      [-]b8????????
         // 004017a6: mov eax, 0x4212e9
      [-]5068????????6a0068????????68????????
         // 004017ab: push eax
         // 004017ac: push 0xffffffff80000004
         // 004017b1: push 0x0
         // 004017b3: push 0x421387
         // 004017b8: push 0x3
      [-]b8????????e8843a000083c4288b5df4
         // 004017c2: mov eax, 0x4082a0
         // 004017c7: call 0x405250
         // 004017cc: add esp, 0x28
         // 004017cf: mov ebx, ss:[ebp+0xfffffffffffffff4]
      [-]53e85a36000083c404
         // 004017d6: push ebx
         // 004017d7: call 0x404e36
         // 004017dc: add esp, 0x4
      [-]68????????bb????????e8023b000083c4048945fc68????????bb????????e8bd3b000083c4048945f8ff75f868????????ff75fc
         // 004017df: push 0x0
         // 004017e4: mov ebx, 0x104
         // 004017e9: call 0x4052f0
         // 004017ee: add esp, 0x4
         // 004017f1: mov ss:[ebp+0xfffffffffffffffc], eax
         // 004017f4: push 0x0
         // 004017f9: mov ebx, 0x108
         // 004017fe: call 0x4053c0
         // 00401803: add esp, 0x4
         // 00401806: mov ss:[ebp+0xfffffffffffffff8], eax
         // 00401809: push ss:[ebp+0xfffffffffffffff8]
         // 0040180c: push 0x4212f6
         // 00401811: push ss:[ebp+0xfffffffffffffffc]
      [-]e84df8ffff83c40c8945f48b5dfc
         // 00401819: call 0x40106b
         // 0040181e: add esp, 0xc
         // 00401821: mov ss:[ebp+0xfffffffffffffff4], eax
         // 00401824: mov ebx, ss:[ebp+0xfffffffffffffffc]
      [-]53e80536000083c404
         // 0040182b: push ebx
         // 0040182c: call 0x404e36
         // 00401831: add esp, 0x4
      [-]53e8f535000083c404
         // 0040183b: push ebx
         // 0040183c: call 0x404e36
         // 00401841: add esp, 0x4
      [-]68????????6a0068????????68????????6a008b45f4
         // 00401844: push 0xffffffff80000301
         // 00401849: push 0x0
         // 0040184b: push 0x1
         // 00401850: push 0xffffffff80000004
         // 00401855: push 0x0
         // 00401857: mov eax, ss:[ebp+0xfffffffffffffff4]
      [-]b8????????
         // 0040185e: mov eax, 0x4212e9
      [-]5068????????6a0068????????68????????
         // 00401863: push eax
         // 00401864: push 0xffffffff80000004
         // 00401869: push 0x0
         // 0040186b: push 0x421387
         // 00401870: push 0x3
      [-]b8????????e8cc39000083c4288b5df4
         // 0040187a: mov eax, 0x4082a0
         // 0040187f: call 0x405250
         // 00401884: add esp, 0x28
         // 00401887: mov ebx, ss:[ebp+0xfffffffffffffff4]
      [-]53e8a235000083c404
         // 0040188e: push ebx
         // 0040188f: call 0x404e36
         // 00401894: add esp, 0x4
      [-]68????????6a0068????????68????????6a0068????????68????????6a0068????????68????????bb????????e8d63b000083c42868????????6a0068????????68????????6a0068????????68????????6a0068????????68????????bb????????e8a03b000083c42868????????6a0068????????68????????6a0068????????68????????6a0068????????68????????bb????????e86a3b000083c42868????????bb????????e8a839000083c4048945fc68????????bb????????e8633a000083c4048945f8ff75f868????????ff75fc
         // 00401897: push 0xffffffff80000301
         // 0040189c: push 0x0
         // 0040189e: push 0x1
         // 004018a3: push 0xffffffff80000004
         // 004018a8: push 0x0
         // 004018aa: push 0x421395
         // 004018af: push 0xffffffff80000301
         // 004018b4: push 0x0
         // 004018b6: push 0x3
         // 004018bb: push 0x3
         // 004018c0: mov ebx, 0x6a4
         // 004018c5: call 0x4054a0
         // 004018ca: add esp, 0x28
         // 004018cd: push 0xffffffff80000301
         // 004018d2: push 0x0
         // 004018d4: push 0x0
         // 004018d9: push 0xffffffff80000004
         // 004018de: push 0x0
         // 004018e0: push 0x4213e4
         // 004018e5: push 0xffffffff80000301
         // 004018ea: push 0x0
         // 004018ec: push 0x4
         // 004018f1: push 0x3
         // 004018f6: mov ebx, 0x6a4
         // 004018fb: call 0x4054a0
         // 00401900: add esp, 0x28
         // 00401903: push 0xffffffff80000301
         // 00401908: push 0x0
         // 0040190a: push 0x1
         // 0040190f: push 0xffffffff80000004
         // 00401914: push 0x0
         // 00401916: push 0x421443
         // 0040191b: push 0xffffffff80000301
         // 00401920: push 0x0
         // 00401922: push 0x3
         // 00401927: push 0x3
         // 0040192c: mov ebx, 0x6a4
         // 00401931: call 0x4054a0
         // 00401936: add esp, 0x28
         // 00401939: push 0x0
         // 0040193e: mov ebx, 0x104
         // 00401943: call 0x4052f0
         // 00401948: add esp, 0x4
         // 0040194b: mov ss:[ebp+0xfffffffffffffffc], eax
         // 0040194e: push 0x0
         // 00401953: mov ebx, 0x108
         // 00401958: call 0x4053c0
         // 0040195d: add esp, 0x4
         // 00401960: mov ss:[ebp+0xfffffffffffffff8], eax
         // 00401963: push ss:[ebp+0xfffffffffffffff8]
         // 00401966: push 0x4212f6
         // 0040196b: push ss:[ebp+0xfffffffffffffffc]
      [-]e8f3f6ffff83c40c8945f48b5dfc
         // 00401973: call 0x40106b
         // 00401978: add esp, 0xc
         // 0040197b: mov ss:[ebp+0xfffffffffffffff4], eax
         // 0040197e: mov ebx, ss:[ebp+0xfffffffffffffffc]
      [-]53e8ab34000083c404
         // 00401985: push ebx
         // 00401986: call 0x404e36
         // 0040198b: add esp, 0x4
      [-]53e89b34000083c404
         // 00401995: push ebx
         // 00401996: call 0x404e36
         // 0040199b: add esp, 0x4
      [-]68????????6a008b45f4
         // 0040199e: push 0xffffffff80000004
         // 004019a3: push 0x0
         // 004019a5: mov eax, ss:[ebp+0xfffffffffffffff4]
      [-]b8????????
         // 004019ac: mov eax, 0x4212e9
      [-]5068????????6a0068????????68????????6a0068????????68????????bb????????e8c73a000083c4288b5df4
         // 004019b1: push eax
         // 004019b2: push 0xffffffff80000004
         // 004019b7: push 0x0
         // 004019b9: push 0x42148f
         // 004019be: push 0xffffffff80000301
         // 004019c3: push 0x0
         // 004019c5: push 0x4
         // 004019ca: push 0x3
         // 004019cf: mov ebx, 0x6a4
         // 004019d4: call 0x4054a0
         // 004019d9: add esp, 0x28
         // 004019dc: mov ebx, ss:[ebp+0xfffffffffffffff4]
      [-]53e84d34000083c404
         // 004019e3: push ebx
         // 004019e4: call 0x404e36
         // 004019e9: add esp, 0x4
      [-]68????????6a0068????????68????????6a0068????????68????????bb????????e85d3c000083c41c68????????6a0068????????68????????6a0068????????68????????bb????????e8333c000083c41c6a0168????????e85c1a00008b1d????????e815f7ffff
         // 004019ec: push 0xffffffff80000004
         // 004019f1: push 0x0
         // 004019f3: push 0x4214cf
         // 004019f8: push 0xffffffff80000301
         // 004019fd: push 0x0
         // 004019ff: push 0x4
         // 00401a04: push 0x2
         // 00401a09: mov ebx, 0x6a8
         // 00401a0e: call 0x405670
         // 00401a13: add esp, 0x1c
         // 00401a16: push 0xffffffff80000004
         // 00401a1b: push 0x0
         // 00401a1d: push 0x421501
         // 00401a22: push 0xffffffff80000301
         // 00401a27: push 0x0
         // 00401a29: push 0x4
         // 00401a2e: push 0x2
         // 00401a33: mov ebx, 0x6a8
         // 00401a38: call 0x405670
         // 00401a3d: add esp, 0x1c
         // 00401a40: push 0x1
         // 00401a42: push 0x422058
         // 00401a47: call 0x4034a8
         // 00401a4c: mov ebx, ds:[0x422058]
         // 00401a52: call 0x40116c
      [-]415153890b503bc80f8fcf020000
         // 00401a62: inc ecx
         // 00401a63: push ecx
         // 00401a64: push ebx
         // 00401a65: mov ds:[ebx], ecx
         // 00401a67: push eax
         // 00401a68: cmp ecx, eax
         // 00401a6a: jg 0x401d3f
      [-]8b1d????????8b0b41c1e10203d953a1????????485bc1e00203d8895dfc68????????8b5dfcff33
         // 00401a70: mov ebx, ds:[0x422058]
         // 00401a76: mov ecx, ds:[ebx]
         // 00401a78: inc ecx
         // 00401a79: shl ecx, b1 0x2
         // 00401a7c: add ebx, ecx
         // 00401a7e: push ebx
         // 00401a7f: mov eax, ds:[0x42205c]
         // 00401a84: dec eax
         // 00401a85: pop ebx
         // 00401a86: shl eax, b1 0x2
         // 00401a89: add ebx, eax
         // 00401a8b: mov ss:[ebp+0xfffffffffffffffc], ebx
         // 00401a8e: push 0x421533
         // 00401a93: mov ebx, ss:[ebp+0xfffffffffffffffc]
         // 00401a96: push ds:[ebx]
      [-]e8c9f5ffff83c4088945f868????????6a0068????????68????????6a008b45f8
         // 00401a9d: call 0x40106b
         // 00401aa2: add esp, 0x8
         // 00401aa5: mov ss:[ebp+0xfffffffffffffff8], eax
         // 00401aa8: push 0xffffffff80000005
         // 00401aad: push 0x0
         // 00401aaf: push 0x421541
         // 00401ab4: push 0xffffffff80000004
         // 00401ab9: push 0x0
         // 00401abb: mov eax, ss:[ebp+0xfffffffffffffff8]
      [-]b8????????
         // 00401ac2: mov eax, 0x4212e9
      [-]5068????????bb????????e8793c000083c41c8b5df8
         // 00401ac7: push eax
         // 00401ac8: push 0x2
         // 00401acd: mov ebx, 0x26c
         // 00401ad2: call 0x405750
         // 00401ad7: add esp, 0x1c
         // 00401ada: mov ebx, ss:[ebp+0xfffffffffffffff8]
      [-]53e84f33000083c404
         // 00401ae1: push ebx
         // 00401ae2: call 0x404e36
         // 00401ae7: add esp, 0x4
      [-]8b1d????????8b0b41c1e10203d953a1????????485bc1e00203d8895dfc68????????8b5dfcff33
         // 00401aea: mov ebx, ds:[0x422058]
         // 00401af0: mov ecx, ds:[ebx]
         // 00401af2: inc ecx
         // 00401af3: shl ecx, b1 0x2
         // 00401af6: add ebx, ecx
         // 00401af8: push ebx
         // 00401af9: mov eax, ds:[0x42205c]
         // 00401afe: dec eax
         // 00401aff: pop ebx
         // 00401b00: shl eax, b1 0x2
         // 00401b03: add ebx, eax
         // 00401b05: mov ss:[ebp+0xfffffffffffffffc], ebx
         // 00401b08: push 0x421533
         // 00401b0d: mov ebx, ss:[ebp+0xfffffffffffffffc]
         // 00401b10: push ds:[ebx]
      [-]e84ff5ffff83c4088945f868????????6a0068????????68????????6a008b45f8
         // 00401b17: call 0x40106b
         // 00401b1c: add esp, 0x8
         // 00401b1f: mov ss:[ebp+0xfffffffffffffff8], eax
         // 00401b22: push 0xffffffff80000301
         // 00401b27: push 0x0
         // 00401b29: push 0x3
         // 00401b2e: push 0xffffffff80000004
         // 00401b33: push 0x0
         // 00401b35: mov eax, ss:[ebp+0xfffffffffffffff8]
      [-]b8????????
         // 00401b3c: mov eax, 0x4212e9
      [-]5068????????bb????????e82f39000083c41c8b5df8
         // 00401b41: push eax
         // 00401b42: push 0x2
         // 00401b47: mov ebx, 0x260
         // 00401b4c: call 0x405480
         // 00401b51: add esp, 0x1c
         // 00401b54: mov ebx, ss:[ebp+0xfffffffffffffff8]
      [-]53e8d532000083c404
         // 00401b5b: push ebx
         // 00401b5c: call 0x404e36
         // 00401b61: add esp, 0x4
      [-]8b1d????????8b0b41c1e10203d953a1????????485bc1e00203d8895dfc68????????8b5dfcff33
         // 00401b64: mov ebx, ds:[0x422058]
         // 00401b6a: mov ecx, ds:[ebx]
         // 00401b6c: inc ecx
         // 00401b6d: shl ecx, b1 0x2
         // 00401b70: add ebx, ecx
         // 00401b72: push ebx
         // 00401b73: mov eax, ds:[0x42205c]
         // 00401b78: dec eax
         // 00401b79: pop ebx
         // 00401b7a: shl eax, b1 0x2
         // 00401b7d: add ebx, eax
         // 00401b7f: mov ss:[ebp+0xfffffffffffffffc], ebx
         // 00401b82: push 0x4218c7
         // 00401b87: mov ebx, ss:[ebp+0xfffffffffffffffc]
         // 00401b8a: push ds:[ebx]
      [-]e8d5f4ffff83c4088945f868????????6a008b45f8
         // 00401b91: call 0x40106b
         // 00401b96: add esp, 0x8
         // 00401b99: mov ss:[ebp+0xfffffffffffffff8], eax
         // 00401b9c: push 0xffffffff80000004
         // 00401ba1: push 0x0
         // 00401ba3: mov eax, ss:[ebp+0xfffffffffffffff8]
      [-]b8????????
         // 00401baa: mov eax, 0x4212e9
      [-]5068????????bb????????e8d137000083c4108b5df8
         // 00401baf: push eax
         // 00401bb0: push 0x1
         // 00401bb5: mov ebx, 0x234
         // 00401bba: call 0x405390
         // 00401bbf: add esp, 0x10
         // 00401bc2: mov ebx, ss:[ebp+0xfffffffffffffff8]
      [-]53e86732000083c404
         // 00401bc9: push ebx
         // 00401bca: call 0x404e36
         // 00401bcf: add esp, 0x4
      [-]8b1d????????8b0b41c1e10203d953a1????????485bc1e00203d8895dfc68????????8b5dfcff33
         // 00401bd2: mov ebx, ds:[0x422058]
         // 00401bd8: mov ecx, ds:[ebx]
         // 00401bda: inc ecx
         // 00401bdb: shl ecx, b1 0x2
         // 00401bde: add ebx, ecx
         // 00401be0: push ebx
         // 00401be1: mov eax, ds:[0x42205c]
         // 00401be6: dec eax
         // 00401be7: pop ebx
         // 00401be8: shl eax, b1 0x2
         // 00401beb: add ebx, eax
         // 00401bed: mov ss:[ebp+0xfffffffffffffffc], ebx
         // 00401bf0: push 0x4218d2
         // 00401bf5: mov ebx, ss:[ebp+0xfffffffffffffffc]
         // 00401bf8: push ds:[ebx]
      [-]e867f4ffff83c4088945f868????????6a008b45f8
         // 00401bff: call 0x40106b
         // 00401c04: add esp, 0x8
         // 00401c07: mov ss:[ebp+0xfffffffffffffff8], eax
         // 00401c0a: push 0xffffffff80000004
         // 00401c0f: push 0x0
         // 00401c11: mov eax, ss:[ebp+0xfffffffffffffff8]
      [-]b8????????
         // 00401c18: mov eax, 0x4212e9
      [-]5068????????bb????????e86337000083c4108b5df8
         // 00401c1d: push eax
         // 00401c1e: push 0x1
         // 00401c23: mov ebx, 0x234
         // 00401c28: call 0x405390
         // 00401c2d: add esp, 0x10
         // 00401c30: mov ebx, ss:[ebp+0xfffffffffffffff8]
      [-]53e8f931000083c404
         // 00401c37: push ebx
         // 00401c38: call 0x404e36
         // 00401c3d: add esp, 0x4
      [-]68????????bb????????e8a136000083c4048945fc68????????bb????????e85c37000083c4048945f8ff75f868????????ff75fc
         // 00401c40: push 0x0
         // 00401c45: mov ebx, 0x104
         // 00401c4a: call 0x4052f0
         // 00401c4f: add esp, 0x4
         // 00401c52: mov ss:[ebp+0xfffffffffffffffc], eax
         // 00401c55: push 0x0
         // 00401c5a: mov ebx, 0x108
         // 00401c5f: call 0x4053c0
         // 00401c64: add esp, 0x4
         // 00401c67: mov ss:[ebp+0xfffffffffffffff8], eax
         // 00401c6a: push ss:[ebp+0xfffffffffffffff8]
         // 00401c6d: push 0x4212f6
         // 00401c72: push ss:[ebp+0xfffffffffffffffc]
      [-]e8ecf3ffff83c40c8945f48b5dfc
         // 00401c7a: call 0x40106b
         // 00401c7f: add esp, 0xc
         // 00401c82: mov ss:[ebp+0xfffffffffffffff4], eax
         // 00401c85: mov ebx, ss:[ebp+0xfffffffffffffffc]
      [-]53e8a431000083c404
         // 00401c8c: push ebx
         // 00401c8d: call 0x404e36
         // 00401c92: add esp, 0x4
      [-]53e89431000083c404
         // 00401c9c: push ebx
         // 00401c9d: call 0x404e36
         // 00401ca2: add esp, 0x4
      [-]8b1d????????8b0b41c1e10203d953a1????????485bc1e00203d8895df068????????8b5df0ff33
         // 00401ca5: mov ebx, ds:[0x422058]
         // 00401cab: mov ecx, ds:[ebx]
         // 00401cad: inc ecx
         // 00401cae: shl ecx, b1 0x2
         // 00401cb1: add ebx, ecx
         // 00401cb3: push ebx
         // 00401cb4: mov eax, ds:[0x42205c]
         // 00401cb9: dec eax
         // 00401cba: pop ebx
         // 00401cbb: shl eax, b1 0x2
         // 00401cbe: add ebx, eax
         // 00401cc0: mov ss:[ebp+0xfffffffffffffff0], ebx
         // 00401cc3: push 0x42190b
         // 00401cc8: mov ebx, ss:[ebp+0xfffffffffffffff0]
         // 00401ccb: push ds:[ebx]
      [-]e894f3ffff83c4088945ec68????????6a008b45ec
         // 00401cd2: call 0x40106b
         // 00401cd7: add esp, 0x8
         // 00401cda: mov ss:[ebp+0xffffffffffffffec], eax
         // 00401cdd: push 0xffffffff80000004
         // 00401ce2: push 0x0
         // 00401ce4: mov eax, ss:[ebp+0xffffffffffffffec]
      [-]b8????????
         // 00401ceb: mov eax, 0x4212e9
      [-]5068????????6a008b45f4
         // 00401cf0: push eax
         // 00401cf1: push 0xffffffff80000004
         // 00401cf6: push 0x0
         // 00401cf8: mov eax, ss:[ebp+0xfffffffffffffff4]
      [-]b8????????
         // 00401cff: mov eax, 0x4212e9
      [-]5068????????bb????????e84c37000083c41c8b5df4
         // 00401d04: push eax
         // 00401d05: push 0x2
         // 00401d0a: mov ebx, 0x23c
         // 00401d0f: call 0x405460
         // 00401d14: add esp, 0x1c
         // 00401d17: mov ebx, ss:[ebp+0xfffffffffffffff4]
      [-]53e81231000083c404
         // 00401d1e: push ebx
         // 00401d1f: call 0x404e36
         // 00401d24: add esp, 0x4
      [-]53e80231000083c404
         // 00401d2e: push ebx
         // 00401d2f: call 0x404e36
         // 00401d34: add esp, 0x4
      [-]585b59e923fdffff
         // 00401d37: pop eax
         // 00401d38: pop ebx
         // 00401d39: pop ecx
         // 00401d3a: jmp 0x401a62
      [-]83c40c68????????6a0068????????68????????
         // 00401d3f: add esp, 0xc
         // 00401d42: push 0xffffffff80000301
         // 00401d47: push 0x0
         // 00401d49: push 0xa
         // 00401d4e: push 0x1
      [-]b8????????e8ee34000083c4108945fc
         // 00401d58: mov eax, 0x408090
         // 00401d5d: call 0x405250
         // 00401d62: add esp, 0x10
         // 00401d65: mov ss:[ebp+0xfffffffffffffffc], eax
      [-]e8f1f2ffff83c4088945f88b5dfc
         // 00401d75: call 0x40106b
         // 00401d7a: add esp, 0x8
         // 00401d7d: mov ss:[ebp+0xfffffffffffffff8], eax
         // 00401d80: mov ebx, ss:[ebp+0xfffffffffffffffc]
      [-]53e8a930000083c404
         // 00401d87: push ebx
         // 00401d88: call 0x404e36
         // 00401d8d: add esp, 0x4
      [-]68????????6a0068????????68????????6a008b45f8
         // 00401d90: push 0xffffffff80000301
         // 00401d95: push 0x0
         // 00401d97: push 0x0
         // 00401d9c: push 0xffffffff80000004
         // 00401da1: push 0x0
         // 00401da3: mov eax, ss:[ebp+0xfffffffffffffff8]
      [-]b8????????
         // 00401daa: mov eax, 0x4212e9
      [-]5068????????bb????????e8c136000083c41c8b5df8
         // 00401daf: push eax
         // 00401db0: push 0x2
         // 00401db5: mov ebx, 0x260
         // 00401dba: call 0x405480
         // 00401dbf: add esp, 0x1c
         // 00401dc2: mov ebx, ss:[ebp+0xfffffffffffffff8]
      [-]53e86730000083c404
         // 00401dc9: push ebx
         // 00401dca: call 0x404e36
         // 00401dcf: add esp, 0x4
      [-]68????????6a0068????????68????????
         // 00401dd2: push 0xffffffff80000301
         // 00401dd7: push 0x0
         // 00401dd9: push 0xa
         // 00401dde: push 0x1
      [-]b8????????e85e34000083c4108945fc
         // 00401de8: mov eax, 0x408090
         // 00401ded: call 0x405250
         // 00401df2: add esp, 0x10
         // 00401df5: mov ss:[ebp+0xfffffffffffffffc], eax
      [-]e861f2ffff83c4088945f88b5dfc
         // 00401e05: call 0x40106b
         // 00401e0a: add esp, 0x8
         // 00401e0d: mov ss:[ebp+0xfffffffffffffff8], eax
         // 00401e10: mov ebx, ss:[ebp+0xfffffffffffffffc]
      [-]53e81930000083c404
         // 00401e17: push ebx
         // 00401e18: call 0x404e36
         // 00401e1d: add esp, 0x4
      [-]68????????6a0068????????68????????
         // 00401e20: push 0xffffffff80000301
         // 00401e25: push 0x0
         // 00401e27: push 0xa
         // 00401e2c: push 0x1
      [-]b8????????e81034000083c4108945f4
         // 00401e36: mov eax, 0x408090
         // 00401e3b: call 0x405250
         // 00401e40: add esp, 0x10
         // 00401e43: mov ss:[ebp+0xfffffffffffffff4], eax
      [-]e813f2ffff83c4088945f08b5df4
         // 00401e53: call 0x40106b
         // 00401e58: add esp, 0x8
         // 00401e5b: mov ss:[ebp+0xfffffffffffffff0], eax
         // 00401e5e: mov ebx, ss:[ebp+0xfffffffffffffff4]
      [-]53e8cb2f000083c404
         // 00401e65: push ebx
         // 00401e66: call 0x404e36
         // 00401e6b: add esp, 0x4
      [-]68????????6a008b45f0
         // 00401e6e: push 0xffffffff80000004
         // 00401e73: push 0x0
         // 00401e75: mov eax, ss:[ebp+0xfffffffffffffff0]
      [-]b8????????
         // 00401e7c: mov eax, 0x4212e9
      [-]5068????????bb????????e85f39000083c4108945ec8b5df0
         // 00401e81: push eax
         // 00401e82: push 0x1
         // 00401e87: mov ebx, 0x268
         // 00401e8c: call 0x4057f0
         // 00401e91: add esp, 0x10
         // 00401e94: mov ss:[ebp+0xffffffffffffffec], eax
         // 00401e97: mov ebx, ss:[ebp+0xfffffffffffffff0]
      [-]53e8922f000083c404
         // 00401e9e: push ebx
         // 00401e9f: call 0x404e36
         // 00401ea4: add esp, 0x4
      [-]68????????6a0068????????68????????bb????????e83e3b000083c4108945e8ff75e8ff75ec
         // 00401ea7: push 0xffffffff80000004
         // 00401eac: push 0x0
         // 00401eae: push 0x421968
         // 00401eb3: push 0x1
         // 00401eb8: mov ebx, 0x198
         // 00401ebd: call 0x405a00
         // 00401ec2: add esp, 0x10
         // 00401ec5: mov ss:[ebp+0xffffffffffffffe8], eax
         // 00401ec8: push ss:[ebp+0xffffffffffffffe8]
         // 00401ecb: push ss:[ebp+0xffffffffffffffec]
      [-]e8adf2ffff83c4088945e48b5dec
         // 00401ed3: call 0x401185
         // 00401ed8: add esp, 0x8
         // 00401edb: mov ss:[ebp+0xffffffffffffffe4], eax
         // 00401ede: mov ebx, ss:[ebp+0xffffffffffffffec]
      [-]53e84b2f000083c404
         // 00401ee5: push ebx
         // 00401ee6: call 0x404e36
         // 00401eeb: add esp, 0x4
      [-]53e83b2f000083c404
         // 00401ef5: push ebx
         // 00401ef6: call 0x404e36
         // 00401efb: add esp, 0x4
      [-]68????????6a008b45e4
         // 00401efe: push 0xffffffff80000005
         // 00401f03: push 0x0
         // 00401f05: mov eax, ss:[ebp+0xffffffffffffffe4]
      [-]b8????????
         // 00401f0c: mov eax, 0x421caf
      [-]5068????????6a008b45f8
         // 00401f11: push eax
         // 00401f12: push 0xffffffff80000004
         // 00401f17: push 0x0
         // 00401f19: mov eax, ss:[ebp+0xfffffffffffffff8]
      [-]b8????????
         // 00401f20: mov eax, 0x4212e9
      [-]5068????????bb????????e81b38000083c41c8b5df8
         // 00401f25: push eax
         // 00401f26: push 0x2
         // 00401f2b: mov ebx, 0x26c
         // 00401f30: call 0x405750
         // 00401f35: add esp, 0x1c
         // 00401f38: mov ebx, ss:[ebp+0xfffffffffffffff8]
      [-]53e8f12e000083c404
         // 00401f3f: push ebx
         // 00401f40: call 0x404e36
         // 00401f45: add esp, 0x4
      [-]53e8e12e000083c404
         // 00401f4f: push ebx
         // 00401f50: call 0x404e36
         // 00401f55: add esp, 0x4
      [-]68????????6a0068????????68????????
         // 00401f58: push 0xffffffff80000301
         // 00401f5d: push 0x0
         // 00401f5f: push 0xa
         // 00401f64: push 0x1
      [-]b8????????e8d832000083c4108945fc
         // 00401f6e: mov eax, 0x408090
         // 00401f73: call 0x405250
         // 00401f78: add esp, 0x10
         // 00401f7b: mov ss:[ebp+0xfffffffffffffffc], eax
      [-]e8dbf0ffff83c4088945f88b5dfc
         // 00401f8b: call 0x40106b
         // 00401f90: add esp, 0x8
         // 00401f93: mov ss:[ebp+0xfffffffffffffff8], eax
         // 00401f96: mov ebx, ss:[ebp+0xfffffffffffffffc]
      [-]53e8932e000083c404
         // 00401f9d: push ebx
         // 00401f9e: call 0x404e36
         // 00401fa3: add esp, 0x4
      [-]68????????6a0068????????68????????6a008b45f8
         // 00401fa6: push 0xffffffff80000301
         // 00401fab: push 0x0
         // 00401fad: push 0x3
         // 00401fb2: push 0xffffffff80000004
         // 00401fb7: push 0x0
         // 00401fb9: mov eax, ss:[ebp+0xfffffffffffffff8]
      [-]b8????????
         // 00401fc0: mov eax, 0x4212e9
      [-]5068????????bb????????e8ab34000083c41c8b5df8
         // 00401fc5: push eax
         // 00401fc6: push 0x2
         // 00401fcb: mov ebx, 0x260
         // 00401fd0: call 0x405480
         // 00401fd5: add esp, 0x1c
         // 00401fd8: mov ebx, ss:[ebp+0xfffffffffffffff8]
      [-]53e8512e000083c404
         // 00401fdf: push ebx
         // 00401fe0: call 0x404e36
         // 00401fe5: add esp, 0x4
      [-]c745fc????????6a008d45fc50c745f8????????6a00ff75f868????????e830180000c745fc????????6a00ff75fcc745f8????????6a00ff75f8e85e180000
         // 00401fe8: mov ss:[ebp+0xfffffffffffffffc], 0x0
         // 00401fef: push 0x0
         // 00401ff1: lea eax, ss:[ebp+0xfffffffffffffffc]
         // 00401ff4: push eax
         // 00401ff5: mov ss:[ebp+0xfffffffffffffff8], 0x0
         // 00401ffc: push 0x0
         // 00401ffe: push ss:[ebp+0xfffffffffffffff8]
         // 00402001: push 0x404d60
         // 00402006: call 0x40383b
         // 0040200b: mov ss:[ebp+0xfffffffffffffffc], 0x0
         // 00402012: push 0x0
         // 00402014: push ss:[ebp+0xfffffffffffffffc]
         // 00402017: mov ss:[ebp+0xfffffffffffffff8], 0x0
         // 0040201e: push 0x0
         // 00402020: push ss:[ebp+0xfffffffffffffff8]
         // 00402023: call 0x403886
      [-]e9000000008be55dc3
         // 0040202d: jmp 0x402032
         // 00402032: mov esp, ebp
         // 00402034: pop ebp
         // 00402035: retn 
      [-]558bec81ec????????c745fc????????c745f8????????68????????e8e52d000083c4048945f4
         // 00402036: push ebp
         // 00402037: mov ebp, esp
         // 00402039: sub esp, 0x1c
         // 0040203f: mov ss:[ebp+0xfffffffffffffffc], 0x0
         // 00402046: mov ss:[ebp+0xfffffffffffffff8], 0x0
         // 0040204d: push 0x8
         // 00402052: call 0x404e3c
         // 00402057: add esp, 0x4
         // 0040205a: mov ss:[ebp+0xfffffffffffffff4], eax
      [-]c703????????c743????????0068????????e8c62d000083c404
         // 0040205f: mov ds:[ebx], 0x0
         // 00402065: mov ds:[ebx+0x4], 0x0
         // 0040206c: push 0x10
         // 00402071: call 0x404e3c
         // 00402076: add esp, 0x4
      [-]c703????????c743????????00c743????????00c743????????00c745ec????????837d0c000f8522000000
         // 0040207e: mov ds:[ebx], 0x0
         // 00402084: mov ds:[ebx+0x4], 0x0
         // 0040208b: mov ds:[ebx+0x8], 0x0
         // 00402092: mov ds:[ebx+0xc], 0x0
         // 00402099: mov ss:[ebp+0xffffffffffffffec], 0x0
         // 004020a0: cmp ss:[ebp+0xc], 0x0
         // 004020a4: jnz 0x4020cc
      [-]8965e8ff15b8c14100909090903965e8740d
         // 004020aa: mov ss:[ebp+0xffffffffffffffe8], esp
         // 004020ad: call ds:[GetCurrentProcessId]
         // 004020b3: nop 
         // 004020b4: nop 
         // 004020b5: nop 
         // 004020b6: nop 
         // 004020b7: cmp ss:[ebp+0xffffffffffffffe8], esp
         // 004020ba: jz 0x4020c9
      [-]68????????e8822d000083c404
         // 004020bc: push 0x6
         // 004020c1: call 0x404e48
         // 004020c6: add esp, 0x4
      [-]8965e8ff750868????????68????????ff1580c24100909090903965e8740d
         // 004020cc: mov ss:[ebp+0xffffffffffffffe8], esp
         // 004020cf: push ss:[ebp+0x8]
         // 004020d2: push 0x0
         // 004020d7: push 0x1f0fff
         // 004020dc: call ds:[OpenProcess]
         // 004020e2: nop 
         // 004020e3: nop 
         // 004020e4: nop 
         // 004020e5: nop 
         // 004020e6: cmp ss:[ebp+0xffffffffffffffe8], esp
         // 004020e9: jz 0x4020f8
      [-]68????????e8532d000083c404
         // 004020eb: push 0x6
         // 004020f0: call 0x404e48
         // 004020f5: add esp, 0x4
      [-]8945fc8965e88d45f85068????????ff75fcff1524c04100909090903965e8740d
         // 004020f8: mov ss:[ebp+0xfffffffffffffffc], eax
         // 004020fb: mov ss:[ebp+0xffffffffffffffe8], esp
         // 004020fe: lea eax, ss:[ebp+0xfffffffffffffff8]
         // 00402101: push eax
         // 00402102: push 0xf01ff
         // 00402107: push ss:[ebp+0xfffffffffffffffc]
         // 0040210a: call ds:[OpenProcessToken]
         // 00402110: nop 
         // 00402111: nop 
         // 00402112: nop 
         // 00402113: nop 
         // 00402114: cmp ss:[ebp+0xffffffffffffffe8], esp
         // 00402117: jz 0x402126
      [-]68????????e8252d000083c404
         // 00402119: push 0x6
         // 0040211e: call 0x404e48
         // 00402123: add esp, 0x4
      [-]8965e8ff75f468????????68????????ff1504c04100909090903965e8740d
         // 00402126: mov ss:[ebp+0xffffffffffffffe8], esp
         // 00402129: push ss:[ebp+0xfffffffffffffff4]
         // 0040212c: push 0x421cb7
         // 00402131: push 0x0
         // 00402136: call ds:[LookupPrivilegeValueA]
         // 0040213c: nop 
         // 0040213d: nop 
         // 0040213e: nop 
         // 0040213f: nop 
         // 00402140: cmp ss:[ebp+0xffffffffffffffe8], esp
         // 00402143: jz 0x402152
      [-]68????????e8f92c000083c404
         // 00402145: push 0x6
         // 0040214a: call 0x404e48
         // 0040214f: add esp, 0x4
      [-]8b5df0895de88b5de8c703????????8b5df083c30c895de88b5de8c703????????8b5df083c304895de88b5df4895de48b5de48b038b5de889038b5df083c308895de88b5df483c304895de48b5de48b038b5de889038965e868????????68????????68????????ff75f068????????ff75f8ff1520c04100909090903965e8740d
         // 00402152: mov ebx, ss:[ebp+0xfffffffffffffff0]
         // 00402155: mov ss:[ebp+0xffffffffffffffe8], ebx
         // 00402158: mov ebx, ss:[ebp+0xffffffffffffffe8]
         // 0040215b: mov ds:[ebx], 0x1
         // 00402161: mov ebx, ss:[ebp+0xfffffffffffffff0]
         // 00402164: add ebx, 0xc
         // 00402167: mov ss:[ebp+0xffffffffffffffe8], ebx
         // 0040216a: mov ebx, ss:[ebp+0xffffffffffffffe8]
         // 0040216d: mov ds:[ebx], 0x2
         // 00402173: mov ebx, ss:[ebp+0xfffffffffffffff0]
         // 00402176: add ebx, 0x4
         // 00402179: mov ss:[ebp+0xffffffffffffffe8], ebx
         // 0040217c: mov ebx, ss:[ebp+0xfffffffffffffff4]
         // 0040217f: mov ss:[ebp+0xffffffffffffffe4], ebx
         // 00402182: mov ebx, ss:[ebp+0xffffffffffffffe4]
         // 00402185: mov eax, ds:[ebx]
         // 00402187: mov ebx, ss:[ebp+0xffffffffffffffe8]
         // 0040218a: mov ds:[ebx], eax
         // 0040218c: mov ebx, ss:[ebp+0xfffffffffffffff0]
         // 0040218f: add ebx, 0x8
         // 00402192: mov ss:[ebp+0xffffffffffffffe8], ebx
         // 00402195: mov ebx, ss:[ebp+0xfffffffffffffff4]
         // 00402198: add ebx, 0x4
         // 0040219b: mov ss:[ebp+0xffffffffffffffe4], ebx
         // 0040219e: mov ebx, ss:[ebp+0xffffffffffffffe4]
         // 004021a1: mov eax, ds:[ebx]
         // 004021a3: mov ebx, ss:[ebp+0xffffffffffffffe8]
         // 004021a6: mov ds:[ebx], eax
         // 004021a8: mov ss:[ebp+0xffffffffffffffe8], esp
         // 004021ab: push 0x0
         // 004021b0: push 0x0
         // 004021b5: push 0x0
         // 004021ba: push ss:[ebp+0xfffffffffffffff0]
         // 004021bd: push 0x0
         // 004021c2: push ss:[ebp+0xfffffffffffffff8]
         // 004021c5: call ds:[AdjustTokenPrivileges]
         // 004021cb: nop 
         // 004021cc: nop 
         // 004021cd: nop 
         // 004021ce: nop 
         // 004021cf: cmp ss:[ebp+0xffffffffffffffe8], esp
         // 004021d2: jz 0x4021e1
      [-]68????????e86a2c000083c404
         // 004021d4: push 0x6
         // 004021d9: call 0x404e48
         // 004021de: add esp, 0x4
      [-]8945ec8965e8ff75fcff15????????909090903965e8740d
         // 004021e1: mov ss:[ebp+0xffffffffffffffec], eax
         // 004021e4: mov ss:[ebp+0xffffffffffffffe8], esp
         // 004021e7: push ss:[ebp+0xfffffffffffffffc]
         // 004021ea: call ds:[0x422060]
         // 004021f0: nop 
         // 004021f1: nop 
         // 004021f2: nop 
         // 004021f3: nop 
         // 004021f4: cmp ss:[ebp+0xffffffffffffffe8], esp
         // 004021f7: jz 0x402206
      [-]68????????e8452c000083c404
         // 004021f9: push 0x6
         // 004021fe: call 0x404e48
         // 00402203: add esp, 0x4
      [-]8b45ece900000000508b5df453e81e2c000083c4048b5df053e8122c000083c404588be55dc20800
         // 00402206: mov eax, ss:[ebp+0xffffffffffffffec]
         // 00402209: jmp 0x40220e
         // 0040220e: push eax
         // 0040220f: mov ebx, ss:[ebp+0xfffffffffffffff4]
         // 00402212: push ebx
         // 00402213: call 0x404e36
         // 00402218: add esp, 0x4
         // 0040221b: mov ebx, ss:[ebp+0xfffffffffffffff0]
         // 0040221e: push ebx
         // 0040221f: call 0x404e36
         // 00402224: add esp, 0x4
         // 00402227: pop eax
         // 00402228: mov esp, ebp
         // 0040222a: pop ebp
         // 0040222b: retn b2 0x8
      [-]558bec81ec????????c745fc????????c745f8????????837d10000f8507000000
         // 0040222e: push ebp
         // 0040222f: mov ebp, esp
         // 00402231: sub esp, 0x20
         // 00402237: mov ss:[ebp+0xfffffffffffffffc], 0x0
         // 0040223e: mov ss:[ebp+0xfffffffffffffff8], 0x0
         // 00402245: cmp ss:[ebp+0x10], 0x0
         // 00402249: jnz 0x402256
      [-]c74510????????
         // 0040224f: mov ss:[ebp+0x10], 0x80
      [-]837d10010f8507000000
         // 00402256: cmp ss:[ebp+0x10], 0x1
         // 0040225a: jnz 0x402267
      [-]c74510????????
         // 00402260: mov ss:[ebp+0x10], 0x8000
      [-]837d10020f8507000000
         // 00402267: cmp ss:[ebp+0x10], 0x2
         // 0040226b: jnz 0x402278
      [-]c74510????????
         // 00402271: mov ss:[ebp+0x10], 0x100
      [-]837d10030f8507000000
         // 00402278: cmp ss:[ebp+0x10], 0x3
         // 0040227c: jnz 0x402289
      [-]c74510????????
         // 00402282: mov ss:[ebp+0x10], 0x20
      [-]837d10040f8507000000
         // 00402289: cmp ss:[ebp+0x10], 0x4
         // 0040228d: jnz 0x40229a
      [-]c74510????????
         // 00402293: mov ss:[ebp+0x10], 0x4000
      [-]837d10050f8507000000
         // 0040229a: cmp ss:[ebp+0x10], 0x5
         // 0040229e: jnz 0x4022ab
      [-]c74510????????
         // 004022a4: mov ss:[ebp+0x10], 0x40
      [-]837d14000f840e000000
         // 004022ab: cmp ss:[ebp+0x14], 0x0
         // 004022af: jz 0x4022c3
      [-]837d10000f8404000000
         // 004022b5: cmp ss:[ebp+0x10], 0x0
         // 004022b9: jz 0x4022c3
      [-]0f8407000000
         // 004022ca: jz 0x4022d7
      [-]c74510????????
         // 004022d0: mov ss:[ebp+0x10], 0x80
      [-]837d0c00
         // 004022d7: cmp ss:[ebp+0xc], 0x0
      [-]0f94c08945f48965f0ff157cc24100909090903965f0740d
         // 004022e0: setz b1 al
         // 004022e3: mov ss:[ebp+0xfffffffffffffff4], eax
         // 004022e6: mov ss:[ebp+0xfffffffffffffff0], esp
         // 004022e9: call ds:[GetCurrentProcess]
         // 004022ef: nop 
         // 004022f0: nop 
         // 004022f1: nop 
         // 004022f2: nop 
         // 004022f3: cmp ss:[ebp+0xfffffffffffffff0], esp
         // 004022f6: jz 0x402305
      [-]68????????e8462b000083c404
         // 004022f8: push 0x6
         // 004022fd: call 0x404e48
         // 00402302: add esp, 0x4
      [-]8945ec8965e8ff750868????????68????????ff1580c24100909090903965e8740d
         // 00402305: mov ss:[ebp+0xffffffffffffffec], eax
         // 00402308: mov ss:[ebp+0xffffffffffffffe8], esp
         // 0040230b: push ss:[ebp+0x8]
         // 0040230e: push 0x0
         // 00402313: push 0x200
         // 00402318: call ds:[OpenProcess]
         // 0040231e: nop 
         // 0040231f: nop 
         // 00402320: nop 
         // 00402321: nop 
         // 00402322: cmp ss:[ebp+0xffffffffffffffe8], esp
         // 00402325: jz 0x402334
      [-]68????????e8172b000083c404
         // 00402327: push 0x6
         // 0040232c: call 0x404e48
         // 00402331: add esp, 0x4
      [-]8945e4837df4000f8408000000
         // 00402334: mov ss:[ebp+0xffffffffffffffe4], eax
         // 00402337: cmp ss:[ebp+0xfffffffffffffff4], 0x0
         // 0040233b: jz 0x402349
      [-]8b45ece903000000
         // 00402341: mov eax, ss:[ebp+0xffffffffffffffec]
         // 00402344: jmp 0x40234c
      [-]8945fc837dfc000f850a000000
         // 0040234c: mov ss:[ebp+0xfffffffffffffffc], eax
         // 0040234f: cmp ss:[ebp+0xfffffffffffffffc], 0x0
         // 00402353: jnz 0x402363
      [-]e952000000
         // 0040235e: jmp 0x4023b5
      [-]8965f4ff7510ff75fcff15????????909090903965f4740d
         // 00402363: mov ss:[ebp+0xfffffffffffffff4], esp
         // 00402366: push ss:[ebp+0x10]
         // 00402369: push ss:[ebp+0xfffffffffffffffc]
         // 0040236c: call ds:[0x422064]
         // 00402372: nop 
         // 00402373: nop 
         // 00402374: nop 
         // 00402375: nop 
         // 00402376: cmp ss:[ebp+0xfffffffffffffff4], esp
         // 00402379: jz 0x402388
      [-]68????????e8c32a000083c404
         // 0040237b: push 0x6
         // 00402380: call 0x404e48
         // 00402385: add esp, 0x4
      [-]8945f88965f4ff75fcff15????????909090903965f4740d
         // 00402388: mov ss:[ebp+0xfffffffffffffff8], eax
         // 0040238b: mov ss:[ebp+0xfffffffffffffff4], esp
         // 0040238e: push ss:[ebp+0xfffffffffffffffc]
         // 00402391: call ds:[0x422060]
         // 00402397: nop 
         // 00402398: nop 
         // 00402399: nop 
         // 0040239a: nop 
         // 0040239b: cmp ss:[ebp+0xfffffffffffffff4], esp
         // 0040239e: jz 0x4023ad
      [-]68????????e89e2a000083c404
         // 004023a0: push 0x6
         // 004023a5: call 0x404e48
         // 004023aa: add esp, 0x4
      [-]8b45f8e900000000
         // 004023ad: mov eax, ss:[ebp+0xfffffffffffffff8]
         // 004023b0: jmp 0x4023b5
      [-]8be55dc21000
         // 004023b5: mov esp, ebp
         // 004023b7: pop ebp
         // 004023b8: retn b2 0x10
      [-]558bec81ec????????68????????8b5d08ff33e8f4ecffff83c40883f8000f85f6000000
         // 004023bb: push ebp
         // 004023bc: mov ebp, esp
         // 004023be: sub esp, 0x10
         // 004023c4: push 0x4212e9
         // 004023c9: mov ebx, ss:[ebp+0x8]
         // 004023cc: push ds:[ebx]
         // 004023ce: call 0x4010c7
         // 004023d3: add esp, 0x8
         // 004023d6: cmp eax, 0x0
         // 004023d9: jnz 0x4024d5
      [-]68????????bb????????e8022f000083c4048945fc68????????bb????????e8bd2f000083c4048945f8ff75f868????????ff75fc
         // 004023df: push 0x0
         // 004023e4: mov ebx, 0x104
         // 004023e9: call 0x4052f0
         // 004023ee: add esp, 0x4
         // 004023f1: mov ss:[ebp+0xfffffffffffffffc], eax
         // 004023f4: push 0x0
         // 004023f9: mov ebx, 0x108
         // 004023fe: call 0x4053c0
         // 00402403: add esp, 0x4
         // 00402406: mov ss:[ebp+0xfffffffffffffff8], eax
         // 00402409: push ss:[ebp+0xfffffffffffffff8]
         // 0040240c: push 0x4212f6
         // 00402411: push ss:[ebp+0xfffffffffffffffc]
      [-]e84decffff83c40c8945f48b5dfc
         // 00402419: call 0x40106b
         // 0040241e: add esp, 0xc
         // 00402421: mov ss:[ebp+0xfffffffffffffff4], eax
         // 00402424: mov ebx, ss:[ebp+0xfffffffffffffffc]
      [-]53e8052a000083c404
         // 0040242b: push ebx
         // 0040242c: call 0x404e36
         // 00402431: add esp, 0x4
      [-]53e8f529000083c404
         // 0040243b: push ebx
         // 0040243c: call 0x404e36
         // 00402441: add esp, 0x4
      [-]8b45f4508b5d088b1b
         // 00402444: mov eax, ss:[ebp+0xfffffffffffffff4]
         // 00402447: push eax
         // 00402448: mov ebx, ss:[ebp+0x8]
         // 0040244b: mov ebx, ds:[ebx]
      [-]53e8df29000083c404
         // 00402451: push ebx
         // 00402452: call 0x404e36
         // 00402457: add esp, 0x4
      [-]588b5d08890368????????6a0068????????
         // 0040245a: pop eax
         // 0040245b: mov ebx, ss:[ebp+0x8]
         // 0040245e: mov ds:[ebx], eax
         // 00402460: push 0xffffffff80000002
         // 00402465: push 0x0
         // 00402467: push 0x1
      [-]e8eeecffff68????????6a0068????????68????????6a0068????????68????????6a008b5d088b03
         // 00402471: call 0x401164
         // 00402476: push 0xffffffff80000004
         // 0040247b: push 0x0
         // 0040247d: push 0x421cc8
         // 00402482: push 0xffffffff80000004
         // 00402487: push 0x0
         // 00402489: push 0x4212f6
         // 0040248e: push 0xffffffff80000004
         // 00402493: push 0x0
         // 00402495: mov ebx, ss:[ebp+0x8]
         // 00402498: mov eax, ds:[ebx]
      [-]b8????????
         // 0040249e: mov eax, 0x4212e9
      [-]5068????????bb????????e82d36000083c44c8945fc8b45fc508b5d088b1b
         // 004024a3: push eax
         // 004024a4: push 0x6
         // 004024a9: mov ebx, 0x180
         // 004024ae: call 0x405ae0
         // 004024b3: add esp, 0x4c
         // 004024b6: mov ss:[ebp+0xfffffffffffffffc], eax
         // 004024b9: mov eax, ss:[ebp+0xfffffffffffffffc]
         // 004024bc: push eax
         // 004024bd: mov ebx, ss:[ebp+0x8]
         // 004024c0: mov ebx, ds:[ebx]
      [-]53e86a29000083c404
         // 004024c6: push ebx
         // 004024c7: call 0x404e36
         // 004024cc: add esp, 0x4
      [-]588b5d088903
         // 004024cf: pop eax
         // 004024d0: mov ebx, ss:[ebp+0x8]
         // 004024d3: mov ds:[ebx], eax
      [-]8965fc8b5d08ff3368????????68????????ff1578c24100909090903965fc740d
         // 004024d5: mov ss:[ebp+0xfffffffffffffffc], esp
         // 004024d8: mov ebx, ss:[ebp+0x8]
         // 004024db: push ds:[ebx]
         // 004024dd: push 0x0
         // 004024e2: push 0x1f0003
         // 004024e7: call ds:[OpenEventA]
         // 004024ed: nop 
         // 004024ee: nop 
         // 004024ef: nop 
         // 004024f0: nop 
         // 004024f1: cmp ss:[ebp+0xfffffffffffffffc], esp
         // 004024f4: jz 0x402503
      [-]68????????e84829000083c404
         // 004024f6: push 0x6
         // 004024fb: call 0x404e48
         // 00402500: add esp, 0x4
      [-]8945f4837df4000f84cf000000
         // 00402503: mov ss:[ebp+0xfffffffffffffff4], eax
         // 00402506: cmp ss:[ebp+0xfffffffffffffff4], 0x0
         // 0040250a: jz 0x4025df
      [-]837d10000f846c000000
         // 00402510: cmp ss:[ebp+0x10], 0x0
         // 00402514: jz 0x402586
      [-]837d1c000f851e000000
         // 0040251a: cmp ss:[ebp+0x1c], 0x0
         // 0040251e: jnz 0x402542
      [-]b8????????508b5d188b1b
         // 00402524: mov eax, 0x421cca
         // 00402529: push eax
         // 0040252a: mov ebx, ss:[ebp+0x18]
         // 0040252d: mov ebx, ds:[ebx]
      [-]53e8fd28000083c404
         // 00402533: push ebx
         // 00402534: call 0x404e36
         // 00402539: add esp, 0x4
      [-]588b5d188903
         // 0040253c: pop eax
         // 0040253d: mov ebx, ss:[ebp+0x18]
         // 00402540: mov ds:[ebx], eax
      [-]6a006a006a0068????????6a0068????????68????????6a00ff752068????????6a008b5d188b03
         // 00402542: push 0x0
         // 00402544: push 0x0
         // 00402546: push 0x0
         // 00402548: push 0xffffffff80000004
         // 0040254d: push 0x0
         // 0040254f: push 0x421cdf
         // 00402554: push 0xffffffff80000301
         // 00402559: push 0x0
         // 0040255b: push ss:[ebp+0x20]
         // 0040255e: push 0xffffffff80000004
         // 00402563: push 0x0
         // 00402565: mov ebx, ss:[ebp+0x18]
         // 00402568: mov eax, ds:[ebx]
      [-]b8????????
         // 0040256e: mov eax, 0x4212e9
      [-]5068????????bb????????e8ad37000083c434
         // 00402573: push eax
         // 00402574: push 0x4
         // 00402579: mov ebx, 0x300
         // 0040257e: call 0x405d30
         // 00402583: add esp, 0x34
      [-]837d28000f8445000000
         // 00402586: cmp ss:[ebp+0x28], 0x0
         // 0040258a: jz 0x4025d5
      [-]68????????bb????????e8212e00
         // 00402590: push 0x0
         // 00402595: mov ebx, 0x108
         // 0040259a: call 0x4053c0
         // 0040259f: add esp, 0x4
         // 004025a2: mov ss:[ebp+0xfffffffffffffffc], eax
         // 004025a5: lea eax, ss:[ebp+0xfffffffffffffffc]
         // 004025a8: push eax
         // 004025a9: call 0x402618
         // 004025ae: mov ss:[ebp+0xfffffffffffffff8], eax
         // 004025b1: mov ebx, ss:[ebp+0xfffffffffffffffc]

  }
  condition:
    all of them
}
