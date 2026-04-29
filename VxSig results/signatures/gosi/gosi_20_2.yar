rule gosi_20_2 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         558bec81ec????????e81d010000c745fc????????6a00ff75fce813010000e896010000e81f0a0000e8c30a0000e8442e0000e8e0900000e8a69400006a0168????????6a0168????????6a01b8????????8945fc8d45fc506a0168????????6a01b8????????8945f88d45f850e8d3e800008b5df885db7409
         // 00401004: push ebp
         // 00401005: mov ebp, esp
         // 00401007: sub esp, 0x14
         // 0040100d: call 0x40112f
         // 00401012: mov ss:[ebp+0xfffffffffffffffc], 0x0
         // 00401019: push 0x0
         // 0040101b: push ss:[ebp+0xfffffffffffffffc]
         // 0040101e: call 0x401136
         // 00401023: call 0x4011be
         // 00401028: call 0x401a4c
         // 0040102d: call 0x401af5
         // 00401032: call 0x403e7b
         // 00401037: call 0x40a11c
         // 0040103c: call 0x40a4e7
         // 00401041: push 0x1
         // 00401043: push 0x1
         // 00401048: push 0x1
         // 0040104a: push 0x10
         // 0040104f: push 0x1
         // 00401051: mov eax, 0x717bac
         // 00401056: mov ss:[ebp+0xfffffffffffffffc], eax
         // 00401059: lea eax, ss:[ebp+0xfffffffffffffffc]
         // 0040105c: push eax
         // 0040105d: push 0x1
         // 0040105f: push 0x1
         // 00401064: push 0x1
         // 00401066: mov eax, 0x717bdf
         // 0040106b: mov ss:[ebp+0xfffffffffffffff8], eax
         // 0040106e: lea eax, ss:[ebp+0xfffffffffffffff8]
         // 00401071: push eax
         // 00401072: call 0x40f94a
         // 00401077: mov ebx, ss:[ebp+0xfffffffffffffff8]
         // 0040107a: test ebx, ebx
         // 0040107c: jz 0x401087
      [-]53e83d70040083c404
         // 0040107e: push ebx
         // 0040107f: call 0x4480c1
         // 00401084: add esp, 0x4
      [-]8b5dfc85db7409
         // 00401087: mov ebx, ss:[ebp+0xfffffffffffffffc]
         // 0040108a: test ebx, ebx
         // 0040108c: jz 0x401097
      [-]53e82d70040083c404
         // 0040108e: push ebx
         // 0040108f: call 0x4480c1
         // 00401094: add esp, 0x4
      [-]68????????6a0068????????68????????bb????????e82770040083c4108945fcc745f8????????6a008d45f850c745f4????????6a00ff75f4c745f0????????6a00ff75f0c745ec????????6a00ff75ec68????????68????????8d45fc50e8faff00008b5dfc85db7409
         // 00401097: push 0xffffffffa0000101
         // 0040109c: push 0x0
         // 0040109e: push 0x717beb
         // 004010a3: push 0x1
         // 004010a8: mov ebx, 0x44a610
         // 004010ad: call 0x4480d9
         // 004010b2: add esp, 0x10
         // 004010b5: mov ss:[ebp+0xfffffffffffffffc], eax
         // 004010b8: mov ss:[ebp+0xfffffffffffffff8], 0x0
         // 004010bf: push 0x0
         // 004010c1: lea eax, ss:[ebp+0xfffffffffffffff8]
         // 004010c4: push eax
         // 004010c5: mov ss:[ebp+0xfffffffffffffff4], 0x0
         // 004010cc: push 0x0
         // 004010ce: push ss:[ebp+0xfffffffffffffff4]
         // 004010d1: mov ss:[ebp+0xfffffffffffffff0], 0x0
         // 004010d8: push 0x0
         // 004010da: push ss:[ebp+0xfffffffffffffff0]
         // 004010dd: mov ss:[ebp+0xffffffffffffffec], 0x0
         // 004010e4: push 0x0
         // 004010e6: push ss:[ebp+0xffffffffffffffec]
         // 004010e9: push 0x1a4
         // 004010ee: push 0x1f40
         // 004010f3: lea eax, ss:[ebp+0xfffffffffffffffc]
         // 004010f6: push eax
         // 004010f7: call 0x4110f6
         // 004010fc: mov ebx, ss:[ebp+0xfffffffffffffffc]
         // 004010ff: test ebx, ebx
         // 00401101: jz 0x40110c
      [-]53e8b86f040083c404
         // 00401103: push ebx
         // 00401104: call 0x4480c1
         // 00401109: add esp, 0x4
      [-]8b5df885db7409
         // 0040110c: mov ebx, ss:[ebp+0xfffffffffffffff8]
         // 0040110f: test ebx, ebx
         // 00401111: jz 0x40111c
      [-]53e8a86f040083c404
         // 00401113: push ebx
         // 00401114: call 0x4480c1
         // 00401119: add esp, 0x4
      [-]e8170a0100b8????????e9000000008be55dc3
         // 0040111c: call 0x411b38
         // 00401121: mov eax, 0x0
         // 00401126: jmp 0x40112b
         // 0040112b: mov esp, ebp
         // 0040112d: pop ebp
         // 0040112e: retn 
      [-]558bec8be55dc3
         // 0040112f: push ebp
         // 00401130: mov ebp, esp
         // 00401132: mov esp, ebp
         // 00401134: pop ebp
         // 00401135: retn 
      [-]558bec81ec????????8965fcb8????????e8876f04003965fc7417
         // 00401136: push ebp
         // 00401137: mov ebp, esp
         // 00401139: sub esp, 0x10
         // 0040113f: mov ss:[ebp+0xfffffffffffffffc], esp
         // 00401142: mov eax, 0x0
         // 00401147: call 0x4480d3
         // 0040114c: cmp ss:[ebp+0xfffffffffffffffc], esp
         // 0040114f: jz 0x401168
      [-]68????????68????????68????????e8686f0400
         // 00401151: push 0x24
         // 00401156: push 0x4015048
         // 0040115b: push 0x6
         // 00401160: call 0x4480cd
      [-]8945f4837df4020f8d0a000000
         // 00401168: mov ss:[ebp+0xfffffffffffffff4], eax
         // 0040116b: cmp ss:[ebp+0xfffffffffffffff4], 0x2
         // 0040116f: jge 0x40117f
      [-]b8????????e931000000
         // 00401175: mov eax, 0x0
         // 0040117a: jmp 0x4011b0
      [-]8965fcff7508b8????????e8446f04003965fc7417
         // 0040117f: mov ss:[ebp+0xfffffffffffffffc], esp
         // 00401182: push ss:[ebp+0x8]
         // 00401185: mov eax, 0x1
         // 0040118a: call 0x4480d3
         // 0040118f: cmp ss:[ebp+0xfffffffffffffffc], esp
         // 00401192: jz 0x4011ab
      [-]68????????68????????68????????e8256f0400
         // 00401194: push 0x6c
         // 00401199: push 0x4015048
         // 0040119e: push 0x6
         // 004011a3: call 0x4480cd
      [-]e900000000
         // 004011ab: jmp 0x4011b0
      [-]8be55dc20800
         // 004011b0: mov esp, ebp
         // 004011b2: pop ebp
         // 004011b3: retn b2 0x8
      [-]6a004b75fb
         // 004011b7: push 0x0
         // 004011b9: dec ebx
         // 004011ba: jnz 0x4011b7
      [-]558bec81ec????????c745fc????????6a00ff75fcb8????????8945f88d45f850e8a70300008945f48b5df885db7409
         // 004011be: push ebp
         // 004011bf: mov ebp, esp
         // 004011c1: sub esp, 0xc
         // 004011c7: mov ss:[ebp+0xfffffffffffffffc], 0x0
         // 004011ce: push 0x0
         // 004011d0: push ss:[ebp+0xfffffffffffffffc]
         // 004011d3: mov eax, 0x717c02
         // 004011d8: mov ss:[ebp+0xfffffffffffffff8], eax
         // 004011db: lea eax, ss:[ebp+0xfffffffffffffff8]
         // 004011de: push eax
         // 004011df: call 0x40158b
         // 004011e4: mov ss:[ebp+0xfffffffffffffff4], eax
         // 004011e7: mov ebx, ss:[ebp+0xfffffffffffffff8]
         // 004011ea: test ebx, ebx
         // 004011ec: jz 0x4011f7
      [-]53e8cd6e040083c404
         // 004011ee: push ebx
         // 004011ef: call 0x4480c1
         // 004011f4: add esp, 0x4
      [-]837df4000f843e000000
         // 004011f7: cmp ss:[ebp+0xfffffffffffffff4], 0x0
         // 004011fb: jz 0x40123f
      [-]bb????????e8abffffff68????????6a0068????????68????????6a0068????????68????????bb????????e8a76e040083c4346a00e8bb6e0400
         // 00401201: mov ebx, 0x6
         // 00401206: call 0x4011b6
         // 0040120b: push 0xffffffff80000301
         // 00401210: push 0x0
         // 00401212: push 0x1000
         // 00401217: push 0xffffffff80000004
         // 0040121c: push 0x0
         // 0040121e: push 0x717c0e
         // 00401223: push 0x4
         // 00401228: mov ebx, 0x44bed0
         // 0040122d: call 0x4480d9
         // 00401232: add esp, 0x34
         // 00401235: push 0x0
         // 00401237: call 0x4480f7
      [-]c745fc????????6a00ff75fcb8????????8945f88d45f850e82f0300008945f48b5df885db7409
         // 0040123f: mov ss:[ebp+0xfffffffffffffffc], 0x0
         // 00401246: push 0x0
         // 00401248: push ss:[ebp+0xfffffffffffffffc]
         // 0040124b: mov eax, 0x717c30
         // 00401250: mov ss:[ebp+0xfffffffffffffff8], eax
         // 00401253: lea eax, ss:[ebp+0xfffffffffffffff8]
         // 00401256: push eax
         // 00401257: call 0x40158b
         // 0040125c: mov ss:[ebp+0xfffffffffffffff4], eax
         // 0040125f: mov ebx, ss:[ebp+0xfffffffffffffff8]
         // 00401262: test ebx, ebx
         // 00401264: jz 0x40126f
      [-]53e8556e040083c404
         // 00401266: push ebx
         // 00401267: call 0x4480c1
         // 0040126c: add esp, 0x4
      [-]837df4000f843e000000
         // 0040126f: cmp ss:[ebp+0xfffffffffffffff4], 0x0
         // 00401273: jz 0x4012b7
      [-]bb????????e833ffffff68????????6a0068????????68????????6a0068????????68????????bb????????e82f6e040083c4346a00e8436e0400
         // 00401279: mov ebx, 0x6
         // 0040127e: call 0x4011b6
         // 00401283: push 0xffffffff80000301
         // 00401288: push 0x0
         // 0040128a: push 0x1000
         // 0040128f: push 0xffffffff80000004
         // 00401294: push 0x0
         // 00401296: push 0x717c0e
         // 0040129b: push 0x4
         // 004012a0: mov ebx, 0x44bed0
         // 004012a5: call 0x4480d9
         // 004012aa: add esp, 0x34
         // 004012ad: push 0x0
         // 004012af: call 0x4480f7
      [-]c745fc????????6a00ff75fcb8????????8945f88d45f850e8b70200008945f48b5df885db7409
         // 004012b7: mov ss:[ebp+0xfffffffffffffffc], 0x0
         // 004012be: push 0x0
         // 004012c0: push ss:[ebp+0xfffffffffffffffc]
         // 004012c3: mov eax, 0x717c3c
         // 004012c8: mov ss:[ebp+0xfffffffffffffff8], eax
         // 004012cb: lea eax, ss:[ebp+0xfffffffffffffff8]
         // 004012ce: push eax
         // 004012cf: call 0x40158b
         // 004012d4: mov ss:[ebp+0xfffffffffffffff4], eax
         // 004012d7: mov ebx, ss:[ebp+0xfffffffffffffff8]
         // 004012da: test ebx, ebx
         // 004012dc: jz 0x4012e7
      [-]53e8dd6d040083c404
         // 004012de: push ebx
         // 004012df: call 0x4480c1
         // 004012e4: add esp, 0x4
      [-]837df4000f843e000000
         // 004012e7: cmp ss:[ebp+0xfffffffffffffff4], 0x0
         // 004012eb: jz 0x40132f
      [-]bb????????e8bbfeffff68????????6a0068????????68????????6a0068????????68????????bb????????e8b76d040083c4346a00e8cb6d0400
         // 004012f1: mov ebx, 0x6
         // 004012f6: call 0x4011b6
         // 004012fb: push 0xffffffff80000301
         // 00401300: push 0x0
         // 00401302: push 0x1000
         // 00401307: push 0xffffffff80000004
         // 0040130c: push 0x0
         // 0040130e: push 0x717c49
         // 00401313: push 0x4
         // 00401318: mov ebx, 0x44bed0
         // 0040131d: call 0x4480d9
         // 00401322: add esp, 0x34
         // 00401325: push 0x0
         // 00401327: call 0x4480f7
      [-]c745fc????????6a00ff75fcb8????????8945f88d45f850e83f0200008945f48b5df885db7409
         // 0040132f: mov ss:[ebp+0xfffffffffffffffc], 0x0
         // 00401336: push 0x0
         // 00401338: push ss:[ebp+0xfffffffffffffffc]
         // 0040133b: mov eax, 0x717c6a
         // 00401340: mov ss:[ebp+0xfffffffffffffff8], eax
         // 00401343: lea eax, ss:[ebp+0xfffffffffffffff8]
         // 00401346: push eax
         // 00401347: call 0x40158b
         // 0040134c: mov ss:[ebp+0xfffffffffffffff4], eax
         // 0040134f: mov ebx, ss:[ebp+0xfffffffffffffff8]
         // 00401352: test ebx, ebx
         // 00401354: jz 0x40135f
      [-]53e8656d040083c404
         // 00401356: push ebx
         // 00401357: call 0x4480c1
         // 0040135c: add esp, 0x4
      [-]837df4000f843e000000
         // 0040135f: cmp ss:[ebp+0xfffffffffffffff4], 0x0
         // 00401363: jz 0x4013a7
      [-]bb????????e843feffff68????????6a0068????????68????????6a0068????????68????????bb????????e83f6d040083c4346a00e8536d0400
         // 00401369: mov ebx, 0x6
         // 0040136e: call 0x4011b6
         // 00401373: push 0xffffffff80000301
         // 00401378: push 0x0
         // 0040137a: push 0x1000
         // 0040137f: push 0xffffffff80000004
         // 00401384: push 0x0
         // 00401386: push 0x717c74
         // 0040138b: push 0x4
         // 00401390: mov ebx, 0x44bed0
         // 00401395: call 0x4480d9
         // 0040139a: add esp, 0x34
         // 0040139d: push 0x0
         // 0040139f: call 0x4480f7
      [-]c745fc????????6a00ff75fcb8????????8945f88d45f850e8c70100008945f48b5df885db7409
         // 004013a7: mov ss:[ebp+0xfffffffffffffffc], 0x0
         // 004013ae: push 0x0
         // 004013b0: push ss:[ebp+0xfffffffffffffffc]
         // 004013b3: mov eax, 0x717c96
         // 004013b8: mov ss:[ebp+0xfffffffffffffff8], eax
         // 004013bb: lea eax, ss:[ebp+0xfffffffffffffff8]
         // 004013be: push eax
         // 004013bf: call 0x40158b
         // 004013c4: mov ss:[ebp+0xfffffffffffffff4], eax
         // 004013c7: mov ebx, ss:[ebp+0xfffffffffffffff8]
         // 004013ca: test ebx, ebx
         // 004013cc: jz 0x4013d7
      [-]53e8ed6c040083c404
         // 004013ce: push ebx
         // 004013cf: call 0x4480c1
         // 004013d4: add esp, 0x4
      [-]837df4000f843e000000
         // 004013d7: cmp ss:[ebp+0xfffffffffffffff4], 0x0
         // 004013db: jz 0x40141f
      [-]bb????????e8cbfdffff68????????6a0068????????68????????6a0068????????68????????bb????????e8c76c040083c4346a00e8db6c0400
         // 004013e1: mov ebx, 0x6
         // 004013e6: call 0x4011b6
         // 004013eb: push 0xffffffff80000301
         // 004013f0: push 0x0
         // 004013f2: push 0x1000
         // 004013f7: push 0xffffffff80000004
         // 004013fc: push 0x0
         // 004013fe: push 0x717ca2
         // 00401403: push 0x4
         // 00401408: mov ebx, 0x44bed0
         // 0040140d: call 0x4480d9
         // 00401412: add esp, 0x34
         // 00401415: push 0x0
         // 00401417: call 0x4480f7
      [-]c745fc????????6a00ff75fcb8????????8945f88d45f850e84f0100008945f48b5df885db7409
         // 0040141f: mov ss:[ebp+0xfffffffffffffffc], 0x0
         // 00401426: push 0x0
         // 00401428: push ss:[ebp+0xfffffffffffffffc]
         // 0040142b: mov eax, 0x717cc1
         // 00401430: mov ss:[ebp+0xfffffffffffffff8], eax
         // 00401433: lea eax, ss:[ebp+0xfffffffffffffff8]
         // 00401436: push eax
         // 00401437: call 0x40158b
         // 0040143c: mov ss:[ebp+0xfffffffffffffff4], eax
         // 0040143f: mov ebx, ss:[ebp+0xfffffffffffffff8]
         // 00401442: test ebx, ebx
         // 00401444: jz 0x40144f
      [-]53e8756c040083c404
         // 00401446: push ebx
         // 00401447: call 0x4480c1
         // 0040144c: add esp, 0x4
      [-]837df4000f843e000000
         // 0040144f: cmp ss:[ebp+0xfffffffffffffff4], 0x0
         // 00401453: jz 0x401497
      [-]bb????????e853fdffff68????????6a0068????????68????????6a0068????????68????????bb????????e84f6c040083c4346a00e8636c0400
         // 00401459: mov ebx, 0x6
         // 0040145e: call 0x4011b6
         // 00401463: push 0xffffffff80000301
         // 00401468: push 0x0
         // 0040146a: push 0x1000
         // 0040146f: push 0xffffffff80000004
         // 00401474: push 0x0
         // 00401476: push 0x717cce
         // 0040147b: push 0x4
         // 00401480: mov ebx, 0x44bed0
         // 00401485: call 0x4480d9
         // 0040148a: add esp, 0x34
         // 0040148d: push 0x0
         // 0040148f: call 0x4480f7
      [-]c745fc????????6a00ff75fcb8????????8945f88d45f850e8d70000008945f48b5df885db7409
         // 00401497: mov ss:[ebp+0xfffffffffffffffc], 0x0
         // 0040149e: push 0x0
         // 004014a0: push ss:[ebp+0xfffffffffffffffc]
         // 004014a3: mov eax, 0x717ced
         // 004014a8: mov ss:[ebp+0xfffffffffffffff8], eax
         // 004014ab: lea eax, ss:[ebp+0xfffffffffffffff8]
         // 004014ae: push eax
         // 004014af: call 0x40158b
         // 004014b4: mov ss:[ebp+0xfffffffffffffff4], eax
         // 004014b7: mov ebx, ss:[ebp+0xfffffffffffffff8]
         // 004014ba: test ebx, ebx
         // 004014bc: jz 0x4014c7
      [-]53e8fd6b040083c404
         // 004014be: push ebx
         // 004014bf: call 0x4480c1
         // 004014c4: add esp, 0x4
      [-]837df4000f843e000000
         // 004014c7: cmp ss:[ebp+0xfffffffffffffff4], 0x0
         // 004014cb: jz 0x40150f
      [-]bb????????e8dbfcffff68????????6a0068????????68????????6a0068????????68????????bb????????e8d76b040083c4346a00e8eb6b0400
         // 004014d1: mov ebx, 0x6
         // 004014d6: call 0x4011b6
         // 004014db: push 0xffffffff80000301
         // 004014e0: push 0x0
         // 004014e2: push 0x1000
         // 004014e7: push 0xffffffff80000004
         // 004014ec: push 0x0
         // 004014ee: push 0x717cf9
         // 004014f3: push 0x4
         // 004014f8: mov ebx, 0x44bed0
         // 004014fd: call 0x4480d9
         // 00401502: add esp, 0x34
         // 00401505: push 0x0
         // 00401507: call 0x4480f7
      [-]c745fc????????6a00ff75fcb8????????8945f88d45f850e85f0000008945f48b5df885db7409
         // 0040150f: mov ss:[ebp+0xfffffffffffffffc], 0x0
         // 00401516: push 0x0
         // 00401518: push ss:[ebp+0xfffffffffffffffc]
         // 0040151b: mov eax, 0x717d18
         // 00401520: mov ss:[ebp+0xfffffffffffffff8], eax
         // 00401523: lea eax, ss:[ebp+0xfffffffffffffff8]
         // 00401526: push eax
         // 00401527: call 0x40158b
         // 0040152c: mov ss:[ebp+0xfffffffffffffff4], eax
         // 0040152f: mov ebx, ss:[ebp+0xfffffffffffffff8]
         // 00401532: test ebx, ebx
         // 00401534: jz 0x40153f
      [-]53e8856b040083c404
         // 00401536: push ebx
         // 00401537: call 0x4480c1
         // 0040153c: add esp, 0x4
      [-]837df4000f843e000000
         // 0040153f: cmp ss:[ebp+0xfffffffffffffff4], 0x0
         // 00401543: jz 0x401587
      [-]bb????????e863fcffff68????????6a0068????????68????????6a0068????????68????????bb????????e85f6b040083c4346a00e8736b0400
         // 00401549: mov ebx, 0x6
         // 0040154e: call 0x4011b6
         // 00401553: push 0xffffffff80000301
         // 00401558: push 0x0
         // 0040155a: push 0x1000
         // 0040155f: push 0xffffffff80000004
         // 00401564: push 0x0
         // 00401566: push 0x717d22
         // 0040156b: push 0x4
         // 00401570: mov ebx, 0x44bed0
         // 00401575: call 0x4480d9
         // 0040157a: add esp, 0x34
         // 0040157d: push 0x0
         // 0040157f: call 0x4480f7
      [-]8be55dc3
         // 00401587: mov esp, ebp
         // 00401589: pop ebp
         // 0040158a: retn 
      [-]558bec81ec????????c745fc????????68????????e8226b040083c4048945f88bd88bf833c0b9????????f3ab83c3245368????????e8016b040083c4045b89038bf8be????????adabadab33c0b9????????f3abc745f4????????8965f068????????68????????b8????????e8d56a04003965f07417
         // 0040158b: push ebp
         // 0040158c: mov ebp, esp
         // 0040158e: sub esp, 0x1c
         // 00401594: mov ss:[ebp+0xfffffffffffffffc], 0x0
         // 0040159b: push 0x28
         // 004015a0: call 0x4480c7
         // 004015a5: add esp, 0x4
         // 004015a8: mov ss:[ebp+0xfffffffffffffff8], eax
         // 004015ab: mov ebx, eax
         // 004015ad: mov edi, eax
         // 004015af: xor eax, eax
         // 004015b1: mov ecx, 0xa
         // 004015b6: rep stosdd 
         // 004015b8: add ebx, 0x24
         // 004015bb: push ebx
         // 004015bc: push 0x10c
         // 004015c1: call 0x4480c7
         // 004015c6: add esp, 0x4
         // 004015c9: pop ebx
         // 004015ca: mov ds:[ebx], eax
         // 004015cc: mov edi, eax
         // 004015ce: mov esi, 0x717d42
         // 004015d3: lodsdd 
         // 004015d4: stosdd 
         // 004015d5: lodsdd 
         // 004015d6: stosdd 
         // 004015d7: xor eax, eax
         // 004015d9: mov ecx, 0x41
         // 004015de: rep stosdd 
         // 004015e0: mov ss:[ebp+0xfffffffffffffff4], 0x0
         // 004015e7: mov ss:[ebp+0xfffffffffffffff0], esp
         // 004015ea: push 0x0
         // 004015ef: push 0xf
         // 004015f4: mov eax, 0x2
         // 004015f9: call 0x4480d3
         // 004015fe: cmp ss:[ebp+0xfffffffffffffff0], esp
         // 00401601: jz 0x40161a
      [-]68????????68????????68????????e8b66a0400
         // 00401603: push 0x19
         // 00401608: push 0x401bf9f
         // 0040160d: push 0x6
         // 00401612: call 0x4480cd
      [-]8945fc837dfcff0f850a000000
         // 0040161a: mov ss:[ebp+0xfffffffffffffffc], eax
         // 0040161d: cmp ss:[ebp+0xfffffffffffffffc], 0xffffffffffffffff
         // 00401621: jnz 0x401631
      [-]b8????????e9f7030000
         // 00401627: mov eax, 0x0
         // 0040162c: jmp 0x401a28
      [-]8b5df8895df08b5df0c703????????8965f08b45f85068????????e8766a040083c4048bf85b50895de88945ec8b0383c304890783c7048b0383c304890783c7048b0383c304890783c7048b0383c304890783c7048b0383c304890783c7048b0383c304890783c7048b0383c304890783c7048b0383c304890783c7048b0383c304890783c704538b1b81c3????????b9????????8bf3f3a45b83c304ff75fcb8????????e8f86904003965f07417
         // 00401631: mov ebx, ss:[ebp+0xfffffffffffffff8]
         // 00401634: mov ss:[ebp+0xfffffffffffffff0], ebx
         // 00401637: mov ebx, ss:[ebp+0xfffffffffffffff0]
         // 0040163a: mov ds:[ebx], 0x128
         // 00401640: mov ss:[ebp+0xfffffffffffffff0], esp
         // 00401643: mov eax, ss:[ebp+0xfffffffffffffff8]
         // 00401646: push eax
         // 00401647: push 0x128
         // 0040164c: call 0x4480c7
         // 00401651: add esp, 0x4
         // 00401654: mov edi, eax
         // 00401656: pop ebx
         // 00401657: push eax
         // 00401658: mov ss:[ebp+0xffffffffffffffe8], ebx
         // 0040165b: mov ss:[ebp+0xffffffffffffffec], eax
         // 0040165e: mov eax, ds:[ebx]
         // 00401660: add ebx, 0x4
         // 00401663: mov ds:[edi], eax
         // 00401665: add edi, 0x4
         // 00401668: mov eax, ds:[ebx]
         // 0040166a: add ebx, 0x4
         // 0040166d: mov ds:[edi], eax
         // 0040166f: add edi, 0x4
         // 00401672: mov eax, ds:[ebx]
         // 00401674: add ebx, 0x4
         // 00401677: mov ds:[edi], eax
         // 00401679: add edi, 0x4
         // 0040167c: mov eax, ds:[ebx]
         // 0040167e: add ebx, 0x4
         // 00401681: mov ds:[edi], eax
         // 00401683: add edi, 0x4
         // 00401686: mov eax, ds:[ebx]
         // 00401688: add ebx, 0x4
         // 0040168b: mov ds:[edi], eax
         // 0040168d: add edi, 0x4
         // 00401690: mov eax, ds:[ebx]
         // 00401692: add ebx, 0x4
         // 00401695: mov ds:[edi], eax
         // 00401697: add edi, 0x4
         // 0040169a: mov eax, ds:[ebx]
         // 0040169c: add ebx, 0x4
         // 0040169f: mov ds:[edi], eax
         // 004016a1: add edi, 0x4
         // 004016a4: mov eax, ds:[ebx]
         // 004016a6: add ebx, 0x4
         // 004016a9: mov ds:[edi], eax
         // 004016ab: add edi, 0x4
         // 004016ae: mov eax, ds:[ebx]
         // 004016b0: add ebx, 0x4
         // 004016b3: mov ds:[edi], eax
         // 004016b5: add edi, 0x4
         // 004016b8: push ebx
         // 004016b9: mov ebx, ds:[ebx]
         // 004016bb: add ebx, 0x8
         // 004016c1: mov ecx, 0x104
         // 004016c6: mov esi, ebx
         // 004016c8: rep movsbb 
         // 004016ca: pop ebx
         // 004016cb: add ebx, 0x4
         // 004016ce: push ss:[ebp+0xfffffffffffffffc]
         // 004016d1: mov eax, 0x3
         // 004016d6: call 0x4480d3
         // 004016db: cmp ss:[ebp+0xfffffffffffffff0], esp
         // 004016de: jz 0x4016f7
      [-]68????????68????????68????????e8d9690400
         // 004016e0: push 0xe1
         // 004016e5: push 0x401bf9f
         // 004016ea: push 0x6
         // 004016ef: call 0x4480cd
      [-]508b5dec538b7de88b0383c304890783c7048b0383c304890783c7048b0383c304890783c7048b0383c304890783c7048b0383c304890783c7048b0383c304890783c7048b0383c304890783c7048b0383c304890783c7048b0383c304890783c70453576a01b8????????e85469040083c4045f5b53578b3f8b0f83c70485c9740f
         // 004016f7: push eax
         // 004016f8: mov ebx, ss:[ebp+0xffffffffffffffec]
         // 004016fb: push ebx
         // 004016fc: mov edi, ss:[ebp+0xffffffffffffffe8]
         // 004016ff: mov eax, ds:[ebx]
         // 00401701: add ebx, 0x4
         // 00401704: mov ds:[edi], eax
         // 00401706: add edi, 0x4
         // 00401709: mov eax, ds:[ebx]
         // 0040170b: add ebx, 0x4
         // 0040170e: mov ds:[edi], eax
         // 00401710: add edi, 0x4
         // 00401713: mov eax, ds:[ebx]
         // 00401715: add ebx, 0x4
         // 00401718: mov ds:[edi], eax
         // 0040171a: add edi, 0x4
         // 0040171d: mov eax, ds:[ebx]
         // 0040171f: add ebx, 0x4
         // 00401722: mov ds:[edi], eax
         // 00401724: add edi, 0x4
         // 00401727: mov eax, ds:[ebx]
         // 00401729: add ebx, 0x4
         // 0040172c: mov ds:[edi], eax
         // 0040172e: add edi, 0x4
         // 00401731: mov eax, ds:[ebx]
         // 00401733: add ebx, 0x4
         // 00401736: mov ds:[edi], eax
         // 00401738: add edi, 0x4
         // 0040173b: mov eax, ds:[ebx]
         // 0040173d: add ebx, 0x4
         // 00401740: mov ds:[edi], eax
         // 00401742: add edi, 0x4
         // 00401745: mov eax, ds:[ebx]
         // 00401747: add ebx, 0x4
         // 0040174a: mov ds:[edi], eax
         // 0040174c: add edi, 0x4
         // 0040174f: mov eax, ds:[ebx]
         // 00401751: add ebx, 0x4
         // 00401754: mov ds:[edi], eax
         // 00401756: add edi, 0x4
         // 00401759: push ebx
         // 0040175a: push edi
         // 0040175b: push 0x1
         // 0040175d: mov eax, 0x2
         // 00401762: call 0x4480bb
         // 00401767: add esp, 0x4
         // 0040176a: pop edi
         // 0040176b: pop ebx
         // 0040176c: push ebx
         // 0040176d: push edi
         // 0040176e: mov edi, ds:[edi]
         // 00401770: mov ecx, ds:[edi]
         // 00401772: add edi, 0x4
         // 00401775: test ecx, ecx
         // 00401777: jz 0x401788
      [-]83c704497405
         // 0040177b: add edi, 0x4
         // 0040177e: dec ecx
         // 0040177f: jz 0x401786
      [-]0faf07ebf5
         // 00401781: imul eax, ds:[edi]
         // 00401784: jmp 0x40177b
      [-]81f9????????7e05
         // 00401788: cmp ecx, 0x104
         // 0040178e: jle 0x401795
      [-]b9????????
         // 00401790: mov ecx, 0x104
      [-]8bf3f3a45f5b83c70481c3????????e81869040083c404588945f4
         // 00401795: mov esi, ebx
         // 00401797: rep movsbb 
         // 00401799: pop edi
         // 0040179a: pop ebx
         // 0040179b: add edi, 0x4
         // 0040179e: add ebx, 0x104
         // 004017a4: call 0x4480c1
         // 004017a9: add esp, 0x4
         // 004017ac: pop eax
         // 004017ad: mov ss:[ebp+0xfffffffffffffff4], eax
      [-]837df4000f8438020000
         // 004017b0: cmp ss:[ebp+0xfffffffffffffff4], 0x0
         // 004017b4: jz 0x4019f2
      [-]8b5df883c324895df068????????6a008b5df0ff3368????????bb????????e8fb68040083c4108945ec68????????6a00ff750c68????????6a008b45ec85c07505
         // 004017ba: mov ebx, ss:[ebp+0xfffffffffffffff8]
         // 004017bd: add ebx, 0x24
         // 004017c0: mov ss:[ebp+0xfffffffffffffff0], ebx
         // 004017c3: push 0xffffffffa0000101
         // 004017c8: push 0x0
         // 004017ca: mov ebx, ss:[ebp+0xfffffffffffffff0]
         // 004017cd: push ds:[ebx]
         // 004017cf: push 0x1
         // 004017d4: mov ebx, 0x44a610
         // 004017d9: call 0x4480d9
         // 004017de: add esp, 0x10
         // 004017e1: mov ss:[ebp+0xffffffffffffffec], eax
         // 004017e4: push 0xffffffff80000002
         // 004017e9: push 0x0
         // 004017eb: push ss:[ebp+0xc]
         // 004017ee: push 0xffffffff80000004
         // 004017f3: push 0x0
         // 004017f5: mov eax, ss:[ebp+0xffffffffffffffec]
         // 004017f8: test eax, eax
         // 004017fa: jnz 0x401801
      [-]b8????????
         // 004017fc: mov eax, 0x717d41
      [-]5068????????6a008b5d088b0385c07505
         // 00401801: push eax
         // 00401802: push 0xffffffff80000004
         // 00401807: push 0x0
         // 00401809: mov ebx, ss:[ebp+0x8]
         // 0040180c: mov eax, ds:[ebx]
         // 0040180e: test eax, eax
         // 00401810: jnz 0x401817
      [-]b8????????
         // 00401812: mov eax, 0x717d41
      [-]5068????????bb????????e8b268040083c4288945e88b5dec85db7409
         // 00401817: push eax
         // 00401818: push 0x3
         // 0040181d: mov ebx, 0x449c80
         // 00401822: call 0x4480d9
         // 00401827: add esp, 0x28
         // 0040182a: mov ss:[ebp+0xffffffffffffffe8], eax
         // 0040182d: mov ebx, ss:[ebp+0xffffffffffffffec]
         // 00401830: test ebx, ebx
         // 00401832: jz 0x40183d
      [-]53e88768040083c404
         // 00401834: push ebx
         // 00401835: call 0x4480c1
         // 0040183a: add esp, 0x4
      [-]837de8000f8536000000
         // 0040183d: cmp ss:[ebp+0xffffffffffffffe8], 0x0
         // 00401841: jnz 0x40187d
      [-]8965f0ff75fcb8????????e87c6804003965f07417
         // 00401847: mov ss:[ebp+0xfffffffffffffff0], esp
         // 0040184a: push ss:[ebp+0xfffffffffffffffc]
         // 0040184d: mov eax, 0x4
         // 00401852: call 0x4480d3
         // 00401857: cmp ss:[ebp+0xfffffffffffffff0], esp
         // 0040185a: jz 0x401873
      [-]68????????68????????68????????e85d680400
         // 0040185c: push 0x1ac
         // 00401861: push 0x401bf9f
         // 00401866: push 0x6
         // 0040186b: call 0x4480cd
      [-]b8????????e9ab010000
         // 00401873: mov eax, 0x1
         // 00401878: jmp 0x401a28
      [-]8965f08b45f85068????????e83968040083c4048bf85b50895de88945ec8b0383c304890783c7048b0383c304890783c7048b0383c304890783c7048b0383c304890783c7048b0383c304890783c7048b0383c304890783c7048b0383c304890783c7048b0383c304890783c7048b0383c304890783c704538b1b81c3????????b9????????8bf3f3a45b83c304ff75fcb8????????e8bb6704003965f07417
         // 0040187d: mov ss:[ebp+0xfffffffffffffff0], esp
         // 00401880: mov eax, ss:[ebp+0xfffffffffffffff8]
         // 00401883: push eax
         // 00401884: push 0x128
         // 00401889: call 0x4480c7
         // 0040188e: add esp, 0x4
         // 00401891: mov edi, eax
         // 00401893: pop ebx
         // 00401894: push eax
         // 00401895: mov ss:[ebp+0xffffffffffffffe8], ebx
         // 00401898: mov ss:[ebp+0xffffffffffffffec], eax
         // 0040189b: mov eax, ds:[ebx]
         // 0040189d: add ebx, 0x4
         // 004018a0: mov ds:[edi], eax
         // 004018a2: add edi, 0x4
         // 004018a5: mov eax, ds:[ebx]
         // 004018a7: add ebx, 0x4
         // 004018aa: mov ds:[edi], eax
         // 004018ac: add edi, 0x4
         // 004018af: mov eax, ds:[ebx]
         // 004018b1: add ebx, 0x4
         // 004018b4: mov ds:[edi], eax
         // 004018b6: add edi, 0x4
         // 004018b9: mov eax, ds:[ebx]
         // 004018bb: add ebx, 0x4
         // 004018be: mov ds:[edi], eax
         // 004018c0: add edi, 0x4
         // 004018c3: mov eax, ds:[ebx]
         // 004018c5: add ebx, 0x4
         // 004018c8: mov ds:[edi], eax
         // 004018ca: add edi, 0x4
         // 004018cd: mov eax, ds:[ebx]
         // 004018cf: add ebx, 0x4
         // 004018d2: mov ds:[edi], eax
         // 004018d4: add edi, 0x4
         // 004018d7: mov eax, ds:[ebx]
         // 004018d9: add ebx, 0x4
         // 004018dc: mov ds:[edi], eax
         // 004018de: add edi, 0x4
         // 004018e1: mov eax, ds:[ebx]
         // 004018e3: add ebx, 0x4
         // 004018e6: mov ds:[edi], eax
         // 004018e8: add edi, 0x4
         // 004018eb: mov eax, ds:[ebx]
         // 004018ed: add ebx, 0x4
         // 004018f0: mov ds:[edi], eax
         // 004018f2: add edi, 0x4
         // 004018f5: push ebx
         // 004018f6: mov ebx, ds:[ebx]
         // 004018f8: add ebx, 0x8
         // 004018fe: mov ecx, 0x104
         // 00401903: mov esi, ebx
         // 00401905: rep movsbb 
         // 00401907: pop ebx
         // 00401908: add ebx, 0x4
         // 0040190b: push ss:[ebp+0xfffffffffffffffc]
         // 0040190e: mov eax, 0x5
         // 00401913: call 0x4480d3
         // 00401918: cmp ss:[ebp+0xfffffffffffffff0], esp
         // 0040191b: jz 0x401934
      [-]68????????68????????68????????e89c670400
         // 0040191d: push 0x1f7
         // 00401922: push 0x401bf9f
         // 00401927: push 0x6
         // 0040192c: call 0x4480cd
      [-]508b5dec538b7de88b0383c304890783c7048b0383c304890783c7048b0383c304890783c7048b0383c304890783c7048b0383c304890783c7048b0383c304890783c7048b0383c304890783c7048b0383c304890783c7048b0383c304890783c70453576a01b8????????e81767040083c4045f5b53578b3f8b0f83c70485c9740f
         // 00401934: push eax
         // 00401935: mov ebx, ss:[ebp+0xffffffffffffffec]
         // 00401938: push ebx
         // 00401939: mov edi, ss:[ebp+0xffffffffffffffe8]
         // 0040193c: mov eax, ds:[ebx]
         // 0040193e: add ebx, 0x4
         // 00401941: mov ds:[edi], eax
         // 00401943: add edi, 0x4
         // 00401946: mov eax, ds:[ebx]
         // 00401948: add ebx, 0x4
         // 0040194b: mov ds:[edi], eax
         // 0040194d: add edi, 0x4
         // 00401950: mov eax, ds:[ebx]
         // 00401952: add ebx, 0x4
         // 00401955: mov ds:[edi], eax
         // 00401957: add edi, 0x4
         // 0040195a: mov eax, ds:[ebx]
         // 0040195c: add ebx, 0x4
         // 0040195f: mov ds:[edi], eax
         // 00401961: add edi, 0x4
         // 00401964: mov eax, ds:[ebx]
         // 00401966: add ebx, 0x4
         // 00401969: mov ds:[edi], eax
         // 0040196b: add edi, 0x4
         // 0040196e: mov eax, ds:[ebx]
         // 00401970: add ebx, 0x4
         // 00401973: mov ds:[edi], eax
         // 00401975: add edi, 0x4
         // 00401978: mov eax, ds:[ebx]
         // 0040197a: add ebx, 0x4
         // 0040197d: mov ds:[edi], eax
         // 0040197f: add edi, 0x4
         // 00401982: mov eax, ds:[ebx]
         // 00401984: add ebx, 0x4
         // 00401987: mov ds:[edi], eax
         // 00401989: add edi, 0x4
         // 0040198c: mov eax, ds:[ebx]
         // 0040198e: add ebx, 0x4
         // 00401991: mov ds:[edi], eax
         // 00401993: add edi, 0x4
         // 00401996: push ebx
         // 00401997: push edi
         // 00401998: push 0x1
         // 0040199a: mov eax, 0x2
         // 0040199f: call 0x4480bb
         // 004019a4: add esp, 0x4
         // 004019a7: pop edi
         // 004019a8: pop ebx
         // 004019a9: push ebx
         // 004019aa: push edi
         // 004019ab: mov edi, ds:[edi]
         // 004019ad: mov ecx, ds:[edi]
         // 004019af: add edi, 0x4
         // 004019b2: test ecx, ecx
         // 004019b4: jz 0x4019c5
      [-]83c704497405
         // 004019b8: add edi, 0x4
         // 004019bb: dec ecx
         // 004019bc: jz 0x4019c3
      [-]0faf07ebf5
         // 004019be: imul eax, ds:[edi]
         // 004019c1: jmp 0x4019b8
      [-]81f9????????7e05
         // 004019c5: cmp ecx, 0x104
         // 004019cb: jle 0x4019d2
      [-]b9????????
         // 004019cd: mov ecx, 0x104
      [-]8bf3f3a45f5b83c70481c3????????e8db66040083c404588945f4e9befdffff
         // 004019d2: mov esi, ebx
         // 004019d4: rep movsbb 
         // 004019d6: pop edi
         // 004019d7: pop ebx
         // 004019d8: add edi, 0x4
         // 004019db: add ebx, 0x104
         // 004019e1: call 0x4480c1
         // 004019e6: add esp, 0x4
         // 004019e9: pop eax
         // 004019ea: mov ss:[ebp+0xfffffffffffffff4], eax
         // 004019ed: jmp 0x4017b0
      [-]8965f0ff75fcb8????????e8d16604003965f07417
         // 004019f2: mov ss:[ebp+0xfffffffffffffff0], esp
         // 004019f5: push ss:[ebp+0xfffffffffffffffc]
         // 004019f8: mov eax, 0x4
         // 004019fd: call 0x4480d3
         // 00401a02: cmp ss:[ebp+0xfffffffffffffff0], esp
         // 00401a05: jz 0x401a1e
      [-]68????????68????????68????????e8b2660400
         // 00401a07: push 0x22d
         // 00401a0c: push 0x401bf9f
         // 00401a11: push 0x6
         // 00401a16: call 0x4480cd
      [-]b8????????e900000000
         // 00401a1e: mov eax, 0x0
         // 00401a23: jmp 0x401a28
      [-]508b5df85383c324538b1b53e88866040083c4045be87f66040083c404588be55dc20c00
         // 00401a28: push eax
         // 00401a29: mov ebx, ss:[ebp+0xfffffffffffffff8]
         // 00401a2c: push ebx
         // 00401a2d: add ebx, 0x24
         // 00401a30: push ebx
         // 00401a31: mov ebx, ds:[ebx]
         // 00401a33: push ebx
         // 00401a34: call 0x4480c1
         // 00401a39: add esp, 0x4
         // 00401a3c: pop ebx
         // 00401a3d: call 0x4480c1
         // 00401a42: add esp, 0x4
         // 00401a45: pop eax
         // 00401a46: mov esp, ebp
         // 00401a48: pop ebp
         // 00401a49: retn b2 0xc
      [-]558bec81ec????????e84f0000008945f8837df8000f853e000000
         // 00401a4c: push ebp
         // 00401a4d: mov ebp, esp
         // 00401a4f: sub esp, 0xc
         // 00401a55: call 0x401aa9
         // 00401a5a: mov ss:[ebp+0xfffffffffffffff8], eax
         // 00401a5d: cmp ss:[ebp+0xfffffffffffffff8], 0x0
         // 00401a61: jnz 0x401aa5
      [-]bb????????e845f7ffff68????????6a0068????????68????????6a0068????????68????????bb????????e84166040083c4346a00e855660400
         // 00401a67: mov ebx, 0x6
         // 00401a6c: call 0x4011b6
         // 00401a71: push 0xffffffff80000301
         // 00401a76: push 0x0
         // 00401a78: push 0x1000
         // 00401a7d: push 0xffffffff80000004
         // 00401a82: push 0x0
         // 00401a84: push 0x717d4a
         // 00401a89: push 0x4
         // 00401a8e: mov ebx, 0x44bed0
         // 00401a93: call 0x4480d9
         // 00401a98: add esp, 0x34
         // 00401a9b: push 0x0
         // 00401a9d: call 0x4480f7
      [-]8be55dc3
         // 00401aa5: mov esp, ebp
         // 00401aa7: pop ebp
         // 00401aa8: retn 
      [-]558bec81ec????????8965fcb8????????8945f88d45f85068????????b8????????e8036604003965fc7417
         // 00401aa9: push ebp
         // 00401aaa: mov ebp, esp
         // 00401aac: sub esp, 0xc
         // 00401ab2: mov ss:[ebp+0xfffffffffffffffc], esp
         // 00401ab5: mov eax, 0x0
         // 00401aba: mov ss:[ebp+0xfffffffffffffff8], eax
         // 00401abd: lea eax, ss:[ebp+0xfffffffffffffff8]
         // 00401ac0: push eax
         // 00401ac1: push 0x0
         // 00401ac6: mov eax, 0x6
         // 00401acb: call 0x4480d3
         // 00401ad0: cmp ss:[ebp+0xfffffffffffffffc], esp
         // 00401ad3: jz 0x401aec
      [-]68????????68????????68????????e8e4650400
         // 00401ad5: push 0x12
         // 00401ada: push 0x401c6d7
         // 00401adf: push 0x6
         // 00401ae4: call 0x4480cd
      [-]e9000000008be55dc3
         // 00401aec: jmp 0x401af1
         // 00401af1: mov esp, ebp
         // 00401af3: pop ebp
         // 00401af4: retn 
      [-]558bec81ec????????c745fc????????6a00ff75fcb8????????8945f88d45f850e8a70200008945f48b5df885db7409
         // 00401af5: push ebp
         // 00401af6: mov ebp, esp
         // 00401af8: sub esp, 0x48
         // 00401afe: mov ss:[ebp+0xfffffffffffffffc], 0x0
         // 00401b05: push 0x0
         // 00401b07: push ss:[ebp+0xfffffffffffffffc]
         // 00401b0a: mov eax, 0x717d6f
         // 00401b0f: mov ss:[ebp+0xfffffffffffffff8], eax
         // 00401b12: lea eax, ss:[ebp+0xfffffffffffffff8]
         // 00401b15: push eax
         // 00401b16: call 0x401dc2
         // 00401b1b: mov ss:[ebp+0xfffffffffffffff4], eax
         // 00401b1e: mov ebx, ss:[ebp+0xfffffffffffffff8]
         // 00401b21: test ebx, ebx
         // 00401b23: jz 0x401b2e
      [-]53e89665040083c404
         // 00401b25: push ebx
         // 00401b26: call 0x4480c1
         // 00401b2b: add esp, 0x4
      [-]ff75f4e85e0800008945f0c745ec????????6a008d45ec50c745e8????????6a008d45e850c745e4????????6a008d45e450c745e0????????6a008d45e050c745dc????????6a008d45dc50c745d8????????6a008d45d850c745d4????????6a008d45d450c745d0????????6a008d45d050b8????????8945cc8d45cc50b8????????8945c88d45c850c745c4????????6a00ff75c4c745c0????????6a00ff75c0c745bc????????6a00ff75bc8d45f050e8ce1c00008945b88b5df085db7409
         // 00401b2e: push ss:[ebp+0xfffffffffffffff4]
         // 00401b31: call 0x402394
         // 00401b36: mov ss:[ebp+0xfffffffffffffff0], eax
         // 00401b39: mov ss:[ebp+0xffffffffffffffec], 0x0
         // 00401b40: push 0x0
         // 00401b42: lea eax, ss:[ebp+0xffffffffffffffec]
         // 00401b45: push eax
         // 00401b46: mov ss:[ebp+0xffffffffffffffe8], 0x0
         // 00401b4d: push 0x0
         // 00401b4f: lea eax, ss:[ebp+0xffffffffffffffe8]
         // 00401b52: push eax
         // 00401b53: mov ss:[ebp+0xffffffffffffffe4], 0x0
         // 00401b5a: push 0x0
         // 00401b5c: lea eax, ss:[ebp+0xffffffffffffffe4]
         // 00401b5f: push eax
         // 00401b60: mov ss:[ebp+0xffffffffffffffe0], 0x0
         // 00401b67: push 0x0
         // 00401b69: lea eax, ss:[ebp+0xffffffffffffffe0]
         // 00401b6c: push eax
         // 00401b6d: mov ss:[ebp+0xffffffffffffffdc], 0x0
         // 00401b74: push 0x0
         // 00401b76: lea eax, ss:[ebp+0xffffffffffffffdc]
         // 00401b79: push eax
         // 00401b7a: mov ss:[ebp+0xffffffffffffffd8], 0x0
         // 00401b81: push 0x0
         // 00401b83: lea eax, ss:[ebp+0xffffffffffffffd8]
         // 00401b86: push eax
         // 00401b87: mov ss:[ebp+0xffffffffffffffd4], 0x0
         // 00401b8e: push 0x0
         // 00401b90: lea eax, ss:[ebp+0xffffffffffffffd4]
         // 00401b93: push eax
         // 00401b94: mov ss:[ebp+0xffffffffffffffd0], 0x0
         // 00401b9b: push 0x0
         // 00401b9d: lea eax, ss:[ebp+0xffffffffffffffd0]
         // 00401ba0: push eax
         // 00401ba1: mov eax, 0x717d41
         // 00401ba6: mov ss:[ebp+0xffffffffffffffcc], eax
         // 00401ba9: lea eax, ss:[ebp+0xffffffffffffffcc]
         // 00401bac: push eax
         // 00401bad: mov eax, 0x717d6f
         // 00401bb2: mov ss:[ebp+0xffffffffffffffc8], eax
         // 00401bb5: lea eax, ss:[ebp+0xffffffffffffffc8]
         // 00401bb8: push eax
         // 00401bb9: mov ss:[ebp+0xffffffffffffffc4], 0x0
         // 00401bc0: push 0x0
         // 00401bc2: push ss:[ebp+0xffffffffffffffc4]
         // 00401bc5: mov ss:[ebp+0xffffffffffffffc0], 0x0
         // 00401bcc: push 0x0
         // 00401bce: push ss:[ebp+0xffffffffffffffc0]
         // 00401bd1: mov ss:[ebp+0xffffffffffffffbc], 0x0
         // 00401bd8: push 0x0
         // 00401bda: push ss:[ebp+0xffffffffffffffbc]
         // 00401bdd: lea eax, ss:[ebp+0xfffffffffffffff0]
         // 00401be0: push eax
         // 00401be1: call 0x4038b4
         // 00401be6: mov ss:[ebp+0xffffffffffffffb8], eax
         // 00401be9: mov ebx, ss:[ebp+0xfffffffffffffff0]
         // 00401bec: test ebx, ebx
         // 00401bee: jz 0x401bf9
      [-]53e8cb64040083c404
         // 00401bf0: push ebx
         // 00401bf1: call 0x4480c1
         // 00401bf6: add esp, 0x4
      [-]8b5dc885db7409
         // 00401bf9: mov ebx, ss:[ebp+0xffffffffffffffc8]
         // 00401bfc: test ebx, ebx
         // 00401bfe: jz 0x401c09
      [-]53e8bb64040083c404
         // 00401c00: push ebx
         // 00401c01: call 0x4480c1
         // 00401c06: add esp, 0x4
      [-]8b5dcc85db7409
         // 00401c09: mov ebx, ss:[ebp+0xffffffffffffffcc]
         // 00401c0c: test ebx, ebx
         // 00401c0e: jz 0x401c19
      [-]53e8ab64040083c404
         // 00401c10: push ebx
         // 00401c11: call 0x4480c1
         // 00401c16: add esp, 0x4
      [-]8b5dd085db7409
         // 00401c19: mov ebx, ss:[ebp+0xffffffffffffffd0]
         // 00401c1c: test ebx, ebx
         // 00401c1e: jz 0x401c29
      [-]53e89b64040083c404
         // 00401c20: push ebx
         // 00401c21: call 0x4480c1
         // 00401c26: add esp, 0x4
      [-]8b5dd485db7409
         // 00401c29: mov ebx, ss:[ebp+0xffffffffffffffd4]
         // 00401c2c: test ebx, ebx
         // 00401c2e: jz 0x401c39
      [-]53e88b64040083c404
         // 00401c30: push ebx
         // 00401c31: call 0x4480c1
         // 00401c36: add esp, 0x4
      [-]8b5dd885db7409
         // 00401c39: mov ebx, ss:[ebp+0xffffffffffffffd8]
         // 00401c3c: test ebx, ebx
         // 00401c3e: jz 0x401c49
      [-]53e87b64040083c404
         // 00401c40: push ebx
         // 00401c41: call 0x4480c1
         // 00401c46: add esp, 0x4
      [-]8b5ddc85db7409
         // 00401c49: mov ebx, ss:[ebp+0xffffffffffffffdc]
         // 00401c4c: test ebx, ebx
         // 00401c4e: jz 0x401c59
      [-]53e86b64040083c404
         // 00401c50: push ebx
         // 00401c51: call 0x4480c1
         // 00401c56: add esp, 0x4
      [-]8b5de085db7409
         // 00401c59: mov ebx, ss:[ebp+0xffffffffffffffe0]
         // 00401c5c: test ebx, ebx
         // 00401c5e: jz 0x401c69
      [-]53e85b64040083c404
         // 00401c60: push ebx
         // 00401c61: call 0x4480c1
         // 00401c66: add esp, 0x4
      [-]8b5de485db7409
         // 00401c69: mov ebx, ss:[ebp+0xffffffffffffffe4]
         // 00401c6c: test ebx, ebx
         // 00401c6e: jz 0x401c79
      [-]53e84b64040083c404
         // 00401c70: push ebx
         // 00401c71: call 0x4480c1
         // 00401c76: add esp, 0x4
      [-]8b5de885db7409
         // 00401c79: mov ebx, ss:[ebp+0xffffffffffffffe8]
         // 00401c7c: test ebx, ebx
         // 00401c7e: jz 0x401c89
      [-]53e83b64040083c404
         // 00401c80: push ebx
         // 00401c81: call 0x4480c1
         // 00401c86: add esp, 0x4
      [-]8b5dec85db7409
         // 00401c89: mov ebx, ss:[ebp+0xffffffffffffffec]
         // 00401c8c: test ebx, ebx
         // 00401c8e: jz 0x401c99
      [-]53e82b64040083c404
         // 00401c90: push ebx
         // 00401c91: call 0x4480c1
         // 00401c96: add esp, 0x4
      [-]8b45b8508b1d????????85db7409
         // 00401c99: mov eax, ss:[ebp+0xffffffffffffffb8]
         // 00401c9c: push eax
         // 00401c9d: mov ebx, ds:[0xcf7e68]
         // 00401ca3: test ebx, ebx
         // 00401ca5: jz 0x401cb0
      [-]53e81464040083c404
         // 00401ca7: push ebx
         // 00401ca8: call 0x4480c1
         // 00401cad: add esp, 0x4
      [-]58a3????????68????????6a0068????????6a006a006a0068????????6a0068????????68????????6a00a1????????85c07505
         // 00401cb0: pop eax
         // 00401cb1: mov ds:[0xcf7e68], eax
         // 00401cb6: push 0xffffffff80000002
         // 00401cbb: push 0x0
         // 00401cbd: push 0x0
         // 00401cc2: push 0x0
         // 00401cc4: push 0x0
         // 00401cc6: push 0x0
         // 00401cc8: push 0xffffffff80000004
         // 00401ccd: push 0x0
         // 00401ccf: push 0x717d7c
         // 00401cd4: push 0xffffffff80000004
         // 00401cd9: push 0x0
         // 00401cdb: mov eax, ds:[0xcf7e68]
         // 00401ce0: test eax, eax
         // 00401ce2: jnz 0x401ce9
      [-]b8????????
         // 00401ce4: mov eax, 0x717d41
      [-]5068????????bb????????e8e063040083c4348945f8837df8ff0f8543000000
         // 00401ce9: push eax
         // 00401cea: push 0x4
         // 00401cef: mov ebx, 0x448bf0
         // 00401cf4: call 0x4480d9
         // 00401cf9: add esp, 0x34
         // 00401cfc: mov ss:[ebp+0xfffffffffffffff8], eax
         // 00401cff: cmp ss:[ebp+0xfffffffffffffff8], 0xffffffffffffffff
         // 00401d03: jnz 0x401d4c
      [-]68????????6a0068????????68????????b8????????bb????????e8c863040083c4108945fc8b45fc508b1d????????85db7409
         // 00401d09: push 0xffffffff80000301
         // 00401d0e: push 0x0
         // 00401d10: push 0x9
         // 00401d15: push 0x1
         // 00401d1a: mov eax, 0x6
         // 00401d1f: mov ebx, 0x6d7e60
         // 00401d24: call 0x4480f1
         // 00401d29: add esp, 0x10
         // 00401d2c: mov ss:[ebp+0xfffffffffffffffc], eax
         // 00401d2f: mov eax, ss:[ebp+0xfffffffffffffffc]
         // 00401d32: push eax
         // 00401d33: mov ebx, ds:[0xcf7e68]
         // 00401d39: test ebx, ebx
         // 00401d3b: jz 0x401d46
      [-]53e87e63040083c404
         // 00401d3d: push ebx
         // 00401d3e: call 0x4480c1
         // 00401d43: add esp, 0x4
      [-]58a3????????
         // 00401d46: pop eax
         // 00401d47: mov ds:[0xcf7e68], eax
      [-]68????????6a0068????????6a006a006a0068????????6a0068????????68????????6a00a1????????85c07505
         // 00401d4c: push 0xffffffff80000002
         // 00401d51: push 0x0
         // 00401d53: push 0x0
         // 00401d58: push 0x0
         // 00401d5a: push 0x0
         // 00401d5c: push 0x0
         // 00401d5e: push 0xffffffff80000004
         // 00401d63: push 0x0
         // 00401d65: push 0x717d7c
         // 00401d6a: push 0xffffffff80000004
         // 00401d6f: push 0x0
         // 00401d71: mov eax, ds:[0xcf7e68]
         // 00401d76: test eax, eax
         // 00401d78: jnz 0x401d7f
      [-]b8????????
         // 00401d7a: mov eax, 0x717d41
      [-]5068????????bb????????e84a63040083c4348945f8837df8ff0f851f000000
         // 00401d7f: push eax
         // 00401d80: push 0x4
         // 00401d85: mov ebx, 0x448bf0
         // 00401d8a: call 0x4480d9
         // 00401d8f: add esp, 0x34
         // 00401d92: mov ss:[ebp+0xfffffffffffffff8], eax
         // 00401d95: cmp ss:[ebp+0xfffffffffffffff8], 0xffffffffffffffff
         // 00401d99: jnz 0x401dbe
      [-]b8????????508b1d????????85db7409
         // 00401d9f: mov eax, 0x717d84
         // 00401da4: push eax
         // 00401da5: mov ebx, ds:[0xcf7e68]
         // 00401dab: test ebx, ebx
         // 00401dad: jz 0x401db8
      [-]53e80c63040083c404
         // 00401daf: push ebx
         // 00401db0: call 0x4480c1
         // 00401db5: add esp, 0x4
      [-]58a3????????
         // 00401db8: pop eax
         // 00401db9: mov ds:[0xcf7e68], eax
      [-]8be55dc3
         // 00401dbe: mov esp, ebp
         // 00401dc0: pop ebp
         // 00401dc1: retn 
      [-]558bec81ec????????c745fc????????68????????e8eb62040083c4048945f88bd88bf833c0b9????????f3ab83c3245368????????e8ca62040083c4045b89038bf8be????????adabadab33c0b9????????f3abc745f4????????8965f068????????68????????b8????????e89e6204003965f07417
         // 00401dc2: push ebp
         // 00401dc3: mov ebp, esp
         // 00401dc5: sub esp, 0x1c
         // 00401dcb: mov ss:[ebp+0xfffffffffffffffc], 0x0
         // 00401dd2: push 0x28
         // 00401dd7: call 0x4480c7
         // 00401ddc: add esp, 0x4
         // 00401ddf: mov ss:[ebp+0xfffffffffffffff8], eax
         // 00401de2: mov ebx, eax
         // 00401de4: mov edi, eax
         // 00401de6: xor eax, eax
         // 00401de8: mov ecx, 0xa
         // 00401ded: rep stosdd 
         // 00401def: add ebx, 0x24
         // 00401df2: push ebx
         // 00401df3: push 0x10c
         // 00401df8: call 0x4480c7
         // 00401dfd: add esp, 0x4
         // 00401e00: pop ebx
         // 00401e01: mov ds:[ebx], eax
         // 00401e03: mov edi, eax
         // 00401e05: mov esi, 0x717d42
         // 00401e0a: lodsdd 
         // 00401e0b: stosdd 
         // 00401e0c: lodsdd 
         // 00401e0d: stosdd 
         // 00401e0e: xor eax, eax
         // 00401e10: mov ecx, 0x41
         // 00401e15: rep stosdd 
         // 00401e17: mov ss:[ebp+0xfffffffffffffff4], 0x0
         // 00401e1e: mov ss:[ebp+0xfffffffffffffff0], esp
         // 00401e21: push 0x0
         // 00401e26: push 0x2
         // 00401e2b: mov eax, 0x2
         // 00401e30: call 0x4480d3
         // 00401e35: cmp ss:[ebp+0xfffffffffffffff0], esp
         // 00401e38: jz 0x401e51
      [-]68????????68????????68????????e87f620400
         // 00401e3a: push 0x19
         // 00401e3f: push 0x401c13f
         // 00401e44: push 0x6
         // 00401e49: call 0x4480cd
      [-]8945fc837dfcff0f850a000000
         // 00401e51: mov ss:[ebp+0xfffffffffffffffc], eax
         // 00401e54: cmp ss:[ebp+0xfffffffffffffffc], 0xffffffffffffffff
         // 00401e58: jnz 0x401e68
      [-]b8????????e900040000
         // 00401e5e: mov eax, 0x0
         // 00401e63: jmp 0x402268
      [-]8b5df8895df08b5df0c703????????8965f08b45f85068????????e83f62040083c4048bf85b50895de88945ec8b0383c304890783c7048b0383c304890783c7048b0383c304890783c7048b0383c304890783c7048b0383c304890783c7048b0383c304890783c7048b0383c304890783c7048b0383c304890783c7048b0383c304890783c704538b1b81c3????????b9????????8bf3f3a45b83c304ff75fcb8????????e8c16104003965f07417
         // 00401e68: mov ebx, ss:[ebp+0xfffffffffffffff8]
         // 00401e6b: mov ss:[ebp+0xfffffffffffffff0], ebx
         // 00401e6e: mov ebx, ss:[ebp+0xfffffffffffffff0]
         // 00401e71: mov ds:[ebx], 0x128
         // 00401e77: mov ss:[ebp+0xfffffffffffffff0], esp
         // 00401e7a: mov eax, ss:[ebp+0xfffffffffffffff8]
         // 00401e7d: push eax
         // 00401e7e: push 0x128
         // 00401e83: call 0x4480c7
         // 00401e88: add esp, 0x4
         // 00401e8b: mov edi, eax
         // 00401e8d: pop ebx
         // 00401e8e: push eax
         // 00401e8f: mov ss:[ebp+0xffffffffffffffe8], ebx
         // 00401e92: mov ss:[ebp+0xffffffffffffffec], eax
         // 00401e95: mov eax, ds:[ebx]
         // 00401e97: add ebx, 0x4
         // 00401e9a: mov ds:[edi], eax
         // 00401e9c: add edi, 0x4
         // 00401e9f: mov eax, ds:[ebx]
         // 00401ea1: add ebx, 0x4
         // 00401ea4: mov ds:[edi], eax
         // 00401ea6: add edi, 0x4
         // 00401ea9: mov eax, ds:[ebx]
         // 00401eab: add ebx, 0x4
         // 00401eae: mov ds:[edi], eax
         // 00401eb0: add edi, 0x4
         // 00401eb3: mov eax, ds:[ebx]
         // 00401eb5: add ebx, 0x4
         // 00401eb8: mov ds:[edi], eax
         // 00401eba: add edi, 0x4
         // 00401ebd: mov eax, ds:[ebx]
         // 00401ebf: add ebx, 0x4
         // 00401ec2: mov ds:[edi], eax
         // 00401ec4: add edi, 0x4
         // 00401ec7: mov eax, ds:[ebx]
         // 00401ec9: add ebx, 0x4
         // 00401ecc: mov ds:[edi], eax
         // 00401ece: add edi, 0x4
         // 00401ed1: mov eax, ds:[ebx]
         // 00401ed3: add ebx, 0x4
         // 00401ed6: mov ds:[edi], eax
         // 00401ed8: add edi, 0x4
         // 00401edb: mov eax, ds:[ebx]
         // 00401edd: add ebx, 0x4
         // 00401ee0: mov ds:[edi], eax
         // 00401ee2: add edi, 0x4
         // 00401ee5: mov eax, ds:[ebx]
         // 00401ee7: add ebx, 0x4
         // 00401eea: mov ds:[edi], eax
         // 00401eec: add edi, 0x4
         // 00401eef: push ebx
         // 00401ef0: mov ebx, ds:[ebx]
         // 00401ef2: add ebx, 0x8
         // 00401ef8: mov ecx, 0x104
         // 00401efd: mov esi, ebx
         // 00401eff: rep movsbb 
         // 00401f01: pop ebx
         // 00401f02: add ebx, 0x4
         // 00401f05: push ss:[ebp+0xfffffffffffffffc]
         // 00401f08: mov eax, 0x3
         // 00401f0d: call 0x4480d3
         // 00401f12: cmp ss:[ebp+0xfffffffffffffff0], esp
         // 00401f15: jz 0x401f2e
      [-]68????????68????????68????????e8a2610400
         // 00401f17: push 0xe7
         // 00401f1c: push 0x401c13f
         // 00401f21: push 0x6
         // 00401f26: call 0x4480cd
      [-]508b5dec538b7de88b0383c304890783c7048b0383c304890783c7048b0383c304890783c7048b0383c304890783c7048b0383c304890783c7048b0383c304890783c7048b0383c304890783c7048b0383c304890783c7048b0383c304890783c70453576a01b8????????e81d61040083c4045f5b53578b3f8b0f83c70485c9740f
         // 00401f2e: push eax
         // 00401f2f: mov ebx, ss:[ebp+0xffffffffffffffec]
         // 00401f32: push ebx
         // 00401f33: mov edi, ss:[ebp+0xffffffffffffffe8]
         // 00401f36: mov eax, ds:[ebx]
         // 00401f38: add ebx, 0x4
         // 00401f3b: mov ds:[edi], eax
         // 00401f3d: add edi, 0x4
         // 00401f40: mov eax, ds:[ebx]
         // 00401f42: add ebx, 0x4
         // 00401f45: mov ds:[edi], eax
         // 00401f47: add edi, 0x4
         // 00401f4a: mov eax, ds:[ebx]
         // 00401f4c: add ebx, 0x4
         // 00401f4f: mov ds:[edi], eax
         // 00401f51: add edi, 0x4
         // 00401f54: mov eax, ds:[ebx]
         // 00401f56: add ebx, 0x4
         // 00401f59: mov ds:[edi], eax
         // 00401f5b: add edi, 0x4
         // 00401f5e: mov eax, ds:[ebx]
         // 00401f60: add ebx, 0x4
         // 00401f63: mov ds:[edi], eax
         // 00401f65: add edi, 0x4
         // 00401f68: mov eax, ds:[ebx]
         // 00401f6a: add ebx, 0x4
         // 00401f6d: mov ds:[edi], eax
         // 00401f6f: add edi, 0x4
         // 00401f72: mov eax, ds:[ebx]
         // 00401f74: add ebx, 0x4
         // 00401f77: mov ds:[edi], eax
         // 00401f79: add edi, 0x4
         // 00401f7c: mov eax, ds:[ebx]
         // 00401f7e: add ebx, 0x4
         // 00401f81: mov ds:[edi], eax
         // 00401f83: add edi, 0x4
         // 00401f86: mov eax, ds:[ebx]
         // 00401f88: add ebx, 0x4
         // 00401f8b: mov ds:[edi], eax
         // 00401f8d: add edi, 0x4
         // 00401f90: push ebx
         // 00401f91: push edi
         // 00401f92: push 0x1
         // 00401f94: mov eax, 0x2
         // 00401f99: call 0x4480bb
         // 00401f9e: add esp, 0x4
         // 00401fa1: pop edi
         // 00401fa2: pop ebx
         // 00401fa3: push ebx
         // 00401fa4: push edi
         // 00401fa5: mov edi, ds:[edi]
         // 00401fa7: mov ecx, ds:[edi]
         // 00401fa9: add edi, 0x4
         // 00401fac: test ecx, ecx
         // 00401fae: jz 0x401fbf
      [-]83c704497405
         // 00401fb2: add edi, 0x4
         // 00401fb5: dec ecx
         // 00401fb6: jz 0x401fbd
      [-]0faf07ebf5
         // 00401fb8: imul eax, ds:[edi]
         // 00401fbb: jmp 0x401fb2
      [-]81f9????????7e05
         // 00401fbf: cmp ecx, 0x104
         // 00401fc5: jle 0x401fcc
      [-]b9????????
         // 00401fc7: mov ecx, 0x104
      [-]8bf3f3a45f5b83c70481c3????????e8e160040083c404588945f4
         // 00401fcc: mov esi, ebx
         // 00401fce: rep movsbb 
         // 00401fd0: pop edi
         // 00401fd1: pop ebx
         // 00401fd2: add edi, 0x4
         // 00401fd5: add ebx, 0x104
         // 00401fdb: call 0x4480c1
         // 00401fe0: add esp, 0x4
         // 00401fe3: pop eax
         // 00401fe4: mov ss:[ebp+0xfffffffffffffff4], eax
      [-]837df4000f8441020000
         // 00401fe7: cmp ss:[ebp+0xfffffffffffffff4], 0x0
         // 00401feb: jz 0x402232
      [-]8b5df883c324895df068????????6a008b5df0ff3368????????bb????????e8c460040083c4108945ec68????????6a00ff750c68????????6a008b45ec85c07505
         // 00401ff1: mov ebx, ss:[ebp+0xfffffffffffffff8]
         // 00401ff4: add ebx, 0x24
         // 00401ff7: mov ss:[ebp+0xfffffffffffffff0], ebx
         // 00401ffa: push 0xffffffffa0000101
         // 00401fff: push 0x0
         // 00402001: mov ebx, ss:[ebp+0xfffffffffffffff0]
         // 00402004: push ds:[ebx]
         // 00402006: push 0x1
         // 0040200b: mov ebx, 0x44a610
         // 00402010: call 0x4480d9
         // 00402015: add esp, 0x10
         // 00402018: mov ss:[ebp+0xffffffffffffffec], eax
         // 0040201b: push 0xffffffff80000002
         // 00402020: push 0x0
         // 00402022: push ss:[ebp+0xc]
         // 00402025: push 0xffffffff80000004
         // 0040202a: push 0x0
         // 0040202c: mov eax, ss:[ebp+0xffffffffffffffec]
         // 0040202f: test eax, eax
         // 00402031: jnz 0x402038
      [-]b8????????
         // 00402033: mov eax, 0x717d41
      [-]5068????????6a008b5d088b0385c07505
         // 00402038: push eax
         // 00402039: push 0xffffffff80000004
         // 0040203e: push 0x0
         // 00402040: mov ebx, ss:[ebp+0x8]
         // 00402043: mov eax, ds:[ebx]
         // 00402045: test eax, eax
         // 00402047: jnz 0x40204e
      [-]b8????????
         // 00402049: mov eax, 0x717d41
      [-]5068????????bb????????e87b60040083c4288945e88b5dec85db7409
         // 0040204e: push eax
         // 0040204f: push 0x3
         // 00402054: mov ebx, 0x449c80
         // 00402059: call 0x4480d9
         // 0040205e: add esp, 0x28
         // 00402061: mov ss:[ebp+0xffffffffffffffe8], eax
         // 00402064: mov ebx, ss:[ebp+0xffffffffffffffec]
         // 00402067: test ebx, ebx
         // 00402069: jz 0x402074
      [-]53e85060040083c404
         // 0040206b: push ebx
         // 0040206c: call 0x4480c1
         // 00402071: add esp, 0x4
      [-]837de8000f853f000000
         // 00402074: cmp ss:[ebp+0xffffffffffffffe8], 0x0
         // 00402078: jnz 0x4020bd
      [-]8965f0ff75fcb8????????e8456004003965f07417
         // 0040207e: mov ss:[ebp+0xfffffffffffffff0], esp
         // 00402081: push ss:[ebp+0xfffffffffffffffc]
         // 00402084: mov eax, 0x4
         // 00402089: call 0x4480d3
         // 0040208e: cmp ss:[ebp+0xfffffffffffffff0], esp
         // 00402091: jz 0x4020aa
      [-]68????????68????????68????????e826600400
         // 00402093: push 0x1b2
         // 00402098: push 0x401c13f
         // 0040209d: push 0x6
         // 004020a2: call 0x4480cd
      [-]8b5df883c308895df08b5df08b03e9ab010000
         // 004020aa: mov ebx, ss:[ebp+0xfffffffffffffff8]
         // 004020ad: add ebx, 0x8
         // 004020b0: mov ss:[ebp+0xfffffffffffffff0], ebx
         // 004020b3: mov ebx, ss:[ebp+0xfffffffffffffff0]
         // 004020b6: mov eax, ds:[ebx]
         // 004020b8: jmp 0x402268
      [-]8965f08b45f85068????????e8f95f040083c4048bf85b50895de88945ec8b0383c304890783c7048b0383c304890783c7048b0383c304890783c7048b0383c304890783c7048b0383c304890783c7048b0383c304890783c7048b0383c304890783c7048b0383c304890783c7048b0383c304890783c704538b1b81c3????????b9????????8bf3f3a45b83c304ff75fcb8????????e87b5f04003965f07417
         // 004020bd: mov ss:[ebp+0xfffffffffffffff0], esp
         // 004020c0: mov eax, ss:[ebp+0xfffffffffffffff8]
         // 004020c3: push eax
         // 004020c4: push 0x128
         // 004020c9: call 0x4480c7
         // 004020ce: add esp, 0x4
         // 004020d1: mov edi, eax
         // 004020d3: pop ebx
         // 004020d4: push eax
         // 004020d5: mov ss:[ebp+0xffffffffffffffe8], ebx
         // 004020d8: mov ss:[ebp+0xffffffffffffffec], eax
         // 004020db: mov eax, ds:[ebx]
         // 004020dd: add ebx, 0x4
         // 004020e0: mov ds:[edi], eax
         // 004020e2: add edi, 0x4
         // 004020e5: mov eax, ds:[ebx]
         // 004020e7: add ebx, 0x4
         // 004020ea: mov ds:[edi], eax
         // 004020ec: add edi, 0x4
         // 004020ef: mov eax, ds:[ebx]
         // 004020f1: add ebx, 0x4
         // 004020f4: mov ds:[edi], eax
         // 004020f6: add edi, 0x4
         // 004020f9: mov eax, ds:[ebx]
         // 004020fb: add ebx, 0x4
         // 004020fe: mov ds:[edi], eax
         // 00402100: add edi, 0x4
         // 00402103: mov eax, ds:[ebx]
         // 00402105: add ebx, 0x4
         // 00402108: mov ds:[edi], eax
         // 0040210a: add edi, 0x4
         // 0040210d: mov eax, ds:[ebx]
         // 0040210f: add ebx, 0x4
         // 00402112: mov ds:[edi], eax
         // 00402114: add edi, 0x4
         // 00402117: mov eax, ds:[ebx]
         // 00402119: add ebx, 0x4
         // 0040211c: mov ds:[edi], eax
         // 0040211e: add edi, 0x4
         // 00402121: mov eax, ds:[ebx]
         // 00402123: add ebx, 0x4
         // 00402126: mov ds:[edi], eax
         // 00402128: add edi, 0x4
         // 0040212b: mov eax, ds:[ebx]
         // 0040212d: add ebx, 0x4
         // 00402130: mov ds:[edi], eax
         // 00402132: add edi, 0x4
         // 00402135: push ebx
         // 00402136: mov ebx, ds:[ebx]
         // 00402138: add ebx, 0x8
         // 0040213e: mov ecx, 0x104
         // 00402143: mov esi, ebx
         // 00402145: rep movsbb 
         // 00402147: pop ebx
         // 00402148: add ebx, 0x4
         // 0040214b: push ss:[ebp+0xfffffffffffffffc]
         // 0040214e: mov eax, 0x5
         // 00402153: call 0x4480d3
         // 00402158: cmp ss:[ebp+0xfffffffffffffff0], esp
         // 0040215b: jz 0x402174
      [-]68????????68????????68????????e85c5f0400
         // 0040215d: push 0x20a
         // 00402162: push 0x401c13f
         // 00402167: push 0x6
         // 0040216c: call 0x4480cd
      [-]508b5dec538b7de88b0383c304890783c7048b0383c304890783c7048b0383c304890783c7048b0383c304890783c7048b0383c304890783c7048b0383c304890783c7048b0383c304890783c7048b0383c304890783c7048b0383c304890783c70453576a01b8????????e8d75e040083c4045f5b53578b3f8b0f83c70485c9740f
         // 00402174: push eax
         // 00402175: mov ebx, ss:[ebp+0xffffffffffffffec]
         // 00402178: push ebx
         // 00402179: mov edi, ss:[ebp+0xffffffffffffffe8]
         // 0040217c: mov eax, ds:[ebx]
         // 0040217e: add ebx, 0x4
         // 00402181: mov ds:[edi], eax
         // 00402183: add edi, 0x4
         // 00402186: mov eax, ds:[ebx]
         // 00402188: add ebx, 0x4
         // 0040218b: mov ds:[edi], eax
         // 0040218d: add edi, 0x4
         // 00402190: mov eax, ds:[ebx]
         // 00402192: add ebx, 0x4
         // 00402195: mov ds:[edi], eax
         // 00402197: add edi, 0x4
         // 0040219a: mov eax, ds:[ebx]
         // 0040219c: add ebx, 0x4
         // 0040219f: mov ds:[edi], eax
         // 004021a1: add edi, 0x4
         // 004021a4: mov eax, ds:[ebx]
         // 004021a6: add ebx, 0x4
         // 004021a9: mov ds:[edi], eax
         // 004021ab: add edi, 0x4
         // 004021ae: mov eax, ds:[ebx]
         // 004021b0: add ebx, 0x4
         // 004021b3: mov ds:[edi], eax
         // 004021b5: add edi, 0x4
         // 004021b8: mov eax, ds:[ebx]
         // 004021ba: add ebx, 0x4
         // 004021bd: mov ds:[edi], eax
         // 004021bf: add edi, 0x4
         // 004021c2: mov eax, ds:[ebx]
         // 004021c4: add ebx, 0x4
         // 004021c7: mov ds:[edi], eax
         // 004021c9: add edi, 0x4
         // 004021cc: mov eax, ds:[ebx]
         // 004021ce: add ebx, 0x4
         // 004021d1: mov ds:[edi], eax
         // 004021d3: add edi, 0x4
         // 004021d6: push ebx
         // 004021d7: push edi
         // 004021d8: push 0x1
         // 004021da: mov eax, 0x2
         // 004021df: call 0x4480bb
         // 004021e4: add esp, 0x4
         // 004021e7: pop edi
         // 004021e8: pop ebx
         // 004021e9: push ebx
         // 004021ea: push edi
         // 004021eb: mov edi, ds:[edi]
         // 004021ed: mov ecx, ds:[edi]
         // 004021ef: add edi, 0x4
         // 004021f2: test ecx, ecx
         // 004021f4: jz 0x402205
      [-]83c704497405
         // 004021f8: add edi, 0x4
         // 004021fb: dec ecx
         // 004021fc: jz 0x402203
      [-]0faf07ebf5
         // 004021fe: imul eax, ds:[edi]
         // 00402201: jmp 0x4021f8
      [-]81f9????????7e05
         // 00402205: cmp ecx, 0x104
         // 0040220b: jle 0x402212
      [-]b9????????
         // 0040220d: mov ecx, 0x104
      [-]8bf3f3a45f5b83c70481c3????????e89b5e040083c404588945f4e9b5fdffff
         // 00402212: mov esi, ebx
         // 00402214: rep movsbb 
         // 00402216: pop edi
         // 00402217: pop ebx
         // 00402218: add edi, 0x4
         // 0040221b: add ebx, 0x104
         // 00402221: call 0x4480c1
         // 00402226: add esp, 0x4
         // 00402229: pop eax
         // 0040222a: mov ss:[ebp+0xfffffffffffffff4], eax
         // 0040222d: jmp 0x401fe7
      [-]8965f0ff75fcb8????????e8915e04003965f07417
         // 00402232: mov ss:[ebp+0xfffffffffffffff0], esp
         // 00402235: push ss:[ebp+0xfffffffffffffffc]
         // 00402238: mov eax, 0x4
         // 0040223d: call 0x4480d3
         // 00402242: cmp ss:[ebp+0xfffffffffffffff0], esp
         // 00402245: jz 0x40225e
      [-]68????????68????????68????????e8725e0400
         // 00402247: push 0x240
         // 0040224c: push 0x401c13f
         // 00402251: push 0x6
         // 00402256: call 0x4480cd
      [-]b8????????e900000000
         // 0040225e: mov eax, 0x0
         // 00402263: jmp 0x402268
      [-]508b5df85383c324538b1b53e8485e040083c4045be83f5e040083c404588be55dc20c00
         // 00402268: push eax
         // 00402269: mov ebx, ss:[ebp+0xfffffffffffffff8]
         // 0040226c: push ebx
         // 0040226d: add ebx, 0x24
         // 00402270: push ebx
         // 00402271: mov ebx, ds:[ebx]
         // 00402273: push ebx
         // 00402274: call 0x4480c1
         // 00402279: add esp, 0x4
         // 0040227c: pop ebx
         // 0040227d: call 0x4480c1
         // 00402282: add esp, 0x4
         // 00402285: pop eax
         // 00402286: mov esp, ebp
         // 00402288: pop ebp
         // 00402289: retn b2 0xc
      [-]8b5424048b4c240885d2750d
         // 0040228c: mov edx, ss:[esp+0x4]
         // 00402290: mov ecx, ss:[esp+0x8]
         // 00402294: test edx, edx
         // 00402296: jnz 0x4022a5
      [-]33c085c97406
         // 00402298: xor eax, eax
         // 0040229a: test ecx, ecx
         // 0040229c: jz 0x4022a4
      [-]8039007401
         // 0040229e: cmp b1 ds:[ecx], b1 0x0
         // 004022a1: jz 0x4022a4
      [-]85c97509
         // 004022a5: test ecx, ecx
         // 004022a7: jnz 0x4022b2
      [-]33c0803a007401
         // 004022a9: xor eax, eax
         // 004022ab: cmp b1 ds:[edx], b1 0x0
         // 004022ae: jz 0x4022b1
      [-]f7c2????????7537
         // 004022b2: test edx, 0x3
         // 004022b8: jnz 0x4022f1
      [-]8b023a01752b
         // 004022ba: mov eax, ds:[edx]
         // 004022bc: cmp b1 al, b1 ds:[ecx]
         // 004022be: jnz 0x4022eb
      [-]0ac07424
         // 004022c0: or b1 al, b1 al
         // 004022c2: jz 0x4022e8
      [-]3a61017522
         // 004022c4: cmp b1 ah, b1 ds:[ecx+0x1]
         // 004022c7: jnz 0x4022eb
      [-]0ae4741b
         // 004022c9: or b1 ah, b1 ah
         // 004022cb: jz 0x4022e8
      [-]c1e8103a41027516
         // 004022cd: shr eax, b1 0x10
         // 004022d0: cmp b1 al, b1 ds:[ecx+0x2]
         // 004022d3: jnz 0x4022eb
      [-]0ac0740f
         // 004022d5: or b1 al, b1 al
         // 004022d7: jz 0x4022e8
      [-]3a6103750d
         // 004022d9: cmp b1 ah, b1 ds:[ecx+0x3]
         // 004022dc: jnz 0x4022eb
      [-]83c10483c2040ae475d2
         // 004022de: add ecx, 0x4
         // 004022e1: add edx, 0x4
         // 004022e4: or b1 ah, b1 ah
         // 004022e6: jnz 0x4022ba
      [-]1bc0d1e040c3
         // 004022eb: sbb eax, eax
         // 004022ed: shl eax, b1 0x1
         // 004022ef: inc eax
         // 004022f0: retn 
      [-]f7c2????????7414
         // 004022f1: test edx, 0x1
         // 004022f7: jz 0x40230d
      [-]8a02423a0175eb
         // 004022f9: mov b1 al, b1 ds:[edx]
         // 004022fb: inc edx
         // 004022fc: cmp b1 al, b1 ds:[ecx]
         // 004022fe: jnz 0x4022eb
      [-]410ac074e3
         // 00402300: inc ecx
         // 00402301: or b1 al, b1 al
         // 00402303: jz 0x4022e8
      [-]f7c2????????74ad
         // 00402305: test edx, 0x2
         // 0040230b: jz 0x4022ba
      [-]668b0283c2023a0175d4
         // 0040230d: mov b2 ax, b2 ds:[edx]
         // 00402310: add edx, 0x2
         // 00402313: cmp b1 al, b1 ds:[ecx]
         // 00402315: jnz 0x4022eb
      [-]0ac074cd
         // 00402317: or b1 al, b1 al
         // 00402319: jz 0x4022e8
      [-]3a610175cb
         // 0040231b: cmp b1 ah, b1 ds:[ecx+0x1]
         // 0040231e: jnz 0x4022eb
      [-]0ae474c4
         // 00402320: or b1 ah, b1 ah
         // 00402322: jz 0x4022e8
      [-]83c102eb91
         // 00402324: add ecx, 0x2
         // 00402327: jmp 0x4022ba

  }
  condition:
    all of them
}
