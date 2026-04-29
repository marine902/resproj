rule snojan_10_0 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         558b0d0053420089e55dffe1
         // 00401000: push ebp
         // 00401001: mov ecx, ds:[atexit]
         // 00401007: mov ebp, esp
         // 00401009: pop ebp
         // 0040100a: jmp ecx
      [-]558b0de452420089e55dffe1
         // 00401010: push ebp
         // 00401011: mov ecx, ds:[_onexit]
         // 00401017: mov ebp, esp
         // 00401019: pop ebp
         // 0040101a: jmp ecx
      [-]5589e55383ec2068????????e8bfcc010083c40ce8dfbc0100e8eabd010083ec0c8d45f4c745f4????????508d45f88b1d????????535068????????68????????e81ac90100a1????????83c42085c07544
         // 00401020: push ebp
         // 00401021: mov ebp, esp
         // 00401023: push ebx
         // 00401024: sub esp, 0x20
         // 00401027: push 0x401150
         // 0040102c: call SetUnhandledExceptionFilter
         // 00401031: add esp, 0xc
         // 00401034: call 0x41cd18
         // 00401039: call 0x41ce28
         // 0040103e: sub esp, 0xc
         // 00401041: lea eax, ss:[ebp+0xfffffffffffffff4]
         // 00401044: mov ss:[ebp+0xfffffffffffffff4], 0x0
         // 0040104b: push eax
         // 0040104c: lea eax, ss:[ebp+0xfffffffffffffff8]
         // 0040104f: mov ebx, ds:[0x41e01c]
         // 00401055: push ebx
         // 00401056: push eax
         // 00401057: push 0x423004
         // 0040105c: push 0x423000
         // 00401061: call __getmainargs
         // 00401066: mov eax, ds:[0x4230d8]
         // 0040106b: add esp, 0x20
         // 0040106e: test eax, eax
         // 00401070: jnz 0x4010b6
      [-]e829c901008b15????????8910e8b4bd010083e4f0e894020000e82fc90100538b08518b15????????52a1????????50e8f902000089c3e822c90100891c24e84acc0100
         // 00401072: call __p__fmode
         // 00401077: mov edx, ds:[0x41e02c]
         // 0040107d: mov ds:[eax], edx
         // 0040107f: call 0x41ce38
         // 00401084: and esp, 0xfffffffffffffff0
         // 00401087: call 0x401320
         // 0040108c: call __p__environ
         // 00401091: push ebx
         // 00401092: mov ecx, ds:[eax]
         // 00401094: push ecx
         // 00401095: mov edx, ds:[0x423004]
         // 0040109b: push edx
         // 0040109c: mov eax, ds:[0x423000]
         // 004010a1: push eax
         // 004010a2: call 0x4013a0
         // 004010a7: mov ebx, eax
         // 004010a9: call _cexit
         // 004010ae: mov ss:[esp], ebx
         // 004010b1: call ExitProcess
      [-]8b1ddc524200a3????????5151508b531052e8c3c8010083c41083fbe07419
         // 004010b6: mov ebx, ds:[_iob]
         // 004010bc: mov ds:[0x41e02c], eax
         // 004010c1: push ecx
         // 004010c2: push ecx
         // 004010c3: push eax
         // 004010c4: mov edx, ds:[ebx+0x10]
         // 004010c7: push edx
         // 004010c8: call _setmode
         // 004010cd: add esp, 0x10
         // 004010d0: cmp ebx, 0xffffffffffffffe0
         // 004010d3: jz 0x4010ee
      [-]5050a1????????508b433050e8aac8010083c41083fbc07484
         // 004010d5: push eax
         // 004010d6: push eax
         // 004010d7: mov eax, ds:[0x4230d8]
         // 004010dc: push eax
         // 004010dd: mov eax, ds:[ebx+0x30]
         // 004010e0: push eax
         // 004010e1: call _setmode
         // 004010e6: add esp, 0x10
         // 004010e9: cmp ebx, 0xffffffffffffffc0
         // 004010ec: jz 0x401072
      [-]5050a1????????508b435050e891c8010083c410e96bffffff
         // 004010ee: push eax
         // 004010ef: push eax
         // 004010f0: mov eax, ds:[0x4230d8]
         // 004010f5: push eax
         // 004010f6: mov eax, ds:[ebx+0x50]
         // 004010f9: push eax
         // 004010fa: call _setmode
         // 004010ff: add esp, 0x10
         // 00401102: jmp 0x401072
      [-]5589e583ec146a01ff15d0524200e8ddfeffff
         // 00401130: push ebp
         // 00401131: mov ebp, esp
         // 00401133: sub esp, 0x14
         // 00401136: push 0x1
         // 00401138: call ds:[__set_app_type]
         // 0040113e: call 0x401020
      [-]5589e55383ec048b45088b008b003d????????773b
         // 00401150: push ebp
         // 00401151: mov ebp, esp
         // 00401153: push ebx
         // 00401154: sub esp, 0x4
         // 00401157: mov eax, ss:[ebp+0x8]
         // 0040115a: mov eax, ds:[eax]
         // 0040115c: mov eax, ds:[eax]
         // 0040115e: cmp eax, 0xffffffffc0000091
         // 00401163: ja 0x4011a0
      [-]3d????????724b
         // 00401165: cmp eax, 0xffffffffc000008d
         // 0040116a: jb 0x4011b7
      [-]bb????????
         // 0040116c: mov ebx, 0x1
      [-]50506a006a08e834c8010083c41083f8010f84d6000000
         // 00401171: push eax
         // 00401172: push eax
         // 00401173: push 0x0
         // 00401175: push 0x8
         // 00401177: call signal
         // 0040117c: add esp, 0x10
         // 0040117f: cmp eax, 0x1
         // 00401182: jz 0x40125e
      [-]85c00f8590000000
         // 00401188: test eax, eax
         // 0040118a: jnz 0x401220
      [-]8b5dfcc9c20400
         // 00401192: mov ebx, ss:[ebp+0xfffffffffffffffc]
         // 00401195: leave 
         // 00401196: retn b2 0x4
      [-]3d????????7449
         // 004011a0: cmp eax, 0xffffffffc0000094
         // 004011a5: jz 0x4011f0
      [-]3d????????7417
         // 004011a7: cmp eax, 0xffffffffc0000096
         // 004011ac: jz 0x4011c5
      [-]3d????????75db
         // 004011ae: cmp eax, 0xffffffffc0000093
         // 004011b3: jnz 0x401190
      [-]3d????????7439
         // 004011b7: cmp eax, 0xffffffffc0000005
         // 004011bc: jz 0x4011f7
      [-]3d????????75cb
         // 004011be: cmp eax, 0xffffffffc000001d
         // 004011c3: jnz 0x401190
      [-]50506a006a04e8e0c7010083c41083f801745a
         // 004011c5: push eax
         // 004011c6: push eax
         // 004011c7: push 0x0
         // 004011c9: push 0x4
         // 004011cb: call signal
         // 004011d0: add esp, 0x10
         // 004011d3: cmp eax, 0x1
         // 004011d6: jz 0x401232
      [-]85c074b4
         // 004011d8: test eax, eax
         // 004011da: jz 0x401190
      [-]83ec0c6a04ffd083c8ff83c410eba7
         // 004011dc: sub esp, 0xc
         // 004011df: push 0x4
         // 004011e1: call eax
         // 004011e3: or eax, 0xffffffffffffffff
         // 004011e6: add esp, 0x10
         // 004011e9: jmp 0x401192
      [-]31dbe97affffff
         // 004011f0: xor ebx, ebx
         // 004011f2: jmp 0x401171
      [-]50506a006a0be8aec7010083c41083f801743e
         // 004011f7: push eax
         // 004011f8: push eax
         // 004011f9: push 0x0
         // 004011fb: push 0xb
         // 004011fd: call signal
         // 00401202: add esp, 0x10
         // 00401205: cmp eax, 0x1
         // 00401208: jz 0x401248
      [-]85c07482
         // 0040120a: test eax, eax
         // 0040120c: jz 0x401190
      [-]83ec0c6a0bffd083c8ff83c410e972ffffff
         // 0040120e: sub esp, 0xc
         // 00401211: push 0xb
         // 00401213: call eax
         // 00401215: or eax, 0xffffffffffffffff
         // 00401218: add esp, 0x10
         // 0040121b: jmp 0x401192
      [-]83ec0c6a08ffd083c8ff83c410e960ffffff
         // 00401220: sub esp, 0xc
         // 00401223: push 0x8
         // 00401225: call eax
         // 00401227: or eax, 0xffffffffffffffff
         // 0040122a: add esp, 0x10
         // 0040122d: jmp 0x401192
      [-]50506a016a04e873c7010083c8ff83c410e94affffff
         // 00401232: push eax
         // 00401233: push eax
         // 00401234: push 0x1
         // 00401236: push 0x4
         // 00401238: call signal
         // 0040123d: or eax, 0xffffffffffffffff
         // 00401240: add esp, 0x10
         // 00401243: jmp 0x401192
      [-]50506a016a0be85dc7010083c8ff83c410e934ffffff
         // 00401248: push eax
         // 00401249: push eax
         // 0040124a: push 0x1
         // 0040124c: push 0xb
         // 0040124e: call signal
         // 00401253: or eax, 0xffffffffffffffff
         // 00401256: add esp, 0x10
         // 00401259: jmp 0x401192
      [-]50506a016a08e847c7010083c41083c8ff85db0f841bffffff
         // 0040125e: push eax
         // 0040125f: push eax
         // 00401260: push 0x1
         // 00401262: push 0x8
         // 00401264: call signal
         // 00401269: add esp, 0x10
         // 0040126c: or eax, 0xffffffffffffffff
         // 0040126f: test ebx, ebx
         // 00401271: jz 0x401192
      [-]e8acbb010083c8ffe90effffff
         // 00401277: call 0x41ce28
         // 0040127c: or eax, 0xffffffffffffffff
         // 0040127f: jmp 0x401192
      [-]5589e583ec08a1????????85c0743b
         // 00401290: push ebp
         // 00401291: mov ebp, esp
         // 00401293: sub esp, 0x8
         // 00401296: mov eax, ds:[0x41e03c]
         // 0040129b: test eax, eax
         // 0040129d: jz 0x4012da
      [-]83ec0c68????????e864ca010089c283c40cb8????????85d2740f
         // 0040129f: sub esp, 0xc
         // 004012a2: push 0x41f000
         // 004012a7: call GetModuleHandleA
         // 004012ac: mov edx, eax
         // 004012ae: add esp, 0xc
         // 004012b1: mov eax, 0x0
         // 004012b6: test edx, edx
         // 004012b8: jz 0x4012c9
      [-]505068????????52e859ca01005a59
         // 004012ba: push eax
         // 004012bb: push eax
         // 004012bc: push 0x41f00d
         // 004012c1: push edx
         // 004012c2: call GetProcAddress
         // 004012c7: pop edx
         // 004012c8: pop ecx
      [-]85c0740d
         // 004012c9: test eax, eax
         // 004012cb: jz 0x4012da
      [-]83ec0c68????????ffd083c410
         // 004012cd: sub esp, 0xc
         // 004012d0: push 0x41e03c
         // 004012d5: call eax
         // 004012d7: add esp, 0x10
      [-]5589e583ec08a1????????8b0085c07415
         // 004012f0: push ebp
         // 004012f1: mov ebp, esp
         // 004012f3: sub esp, 0x8
         // 004012f6: mov eax, ds:[0x41e004]
         // 004012fb: mov eax, ds:[eax]
         // 004012fd: test eax, eax
         // 004012ff: jz 0x401316
      [-]ffd0a1????????83c004a3????????8b0085c075eb
         // 00401301: call eax
         // 00401303: mov eax, ds:[0x41e004]
         // 00401308: add eax, 0x4
         // 0040130b: mov ds:[0x41e004], eax
         // 00401310: mov eax, ds:[eax]
         // 00401312: test eax, eax
         // 00401314: jnz 0x401301
      [-]5589e556538b0d????????85c97407
         // 00401320: push ebp
         // 00401321: mov ebp, esp
         // 00401323: push esi
         // 00401324: push ebx
         // 00401325: mov ecx, ds:[0x41e000]
         // 0040132b: test ecx, ecx
         // 0040132d: jz 0x401336
      [-]8d65f85b5e5dc3
         // 0040132f: lea esp, ss:[ebp+0xfffffffffffffff8]
         // 00401332: pop ebx
         // 00401333: pop esi
         // 00401334: pop ebp
         // 00401335: retn 
      [-]8b1d????????c705????????????????e845ffffff83fbff742f
         // 00401336: mov ebx, ds:[0x41de20]
         // 0040133c: mov ds:[0x41e000], 0x1
         // 00401346: call 0x401290
         // 0040134b: cmp ebx, 0xffffffffffffffff
         // 0040134e: jz 0x40137f
      [-]85db7414
         // 00401350: test ebx, ebx
         // 00401352: jz 0x401368
      [-]8d349d????????908d742600
         // 00401354: lea esi, ds:[0x41de20+ebx*0x4]
         // 0040135b: nop 
         // 0040135c: lea esi, ds:[esi+0x0]
      [-]ff1683ee044b75f8
         // 00401360: call ds:[esi]
         // 00401362: sub esi, 0x4
         // 00401365: dec ebx
         // 00401366: jnz 0x401360
      [-]83ec0c68????????e88bfcffff83c4108d65f85b5e5dc3
         // 00401368: sub esp, 0xc
         // 0040136b: push 0x4012f0
         // 00401370: call 0x401000
         // 00401375: add esp, 0x10
         // 00401378: lea esp, ss:[ebp+0xfffffffffffffff8]
         // 0040137b: pop ebx
         // 0040137c: pop esi
         // 0040137d: pop ebp
         // 0040137e: retn 
      [-]31dbeb02
         // 0040137f: xor ebx, ebx
         // 00401381: jmp 0x401385
      [-]8d43018b1485????????85d275f0
         // 00401385: lea eax, ds:[ebx+0x1]
         // 00401388: mov edx, ds:[0x41de20+eax*0x4]
         // 0040138f: test edx, edx
         // 00401391: jnz 0x401383
      [-]8d4c240483e4f0ff71fc5589e5575653518d9d????????81ec????????8b7904e85bffffff5068????????536a00e85dc901005068????????53e841c6010083c41089c385c00f84e5020000
         // 004013a0: lea ecx, ss:[esp+0x4]
         // 004013a4: and esp, 0xfffffffffffffff0
         // 004013a7: push ds:[ecx+0xfffffffffffffffc]
         // 004013aa: push ebp
         // 004013ab: mov ebp, esp
         // 004013ad: push edi
         // 004013ae: push esi
         // 004013af: push ebx
         // 004013b0: push ecx
         // 004013b1: lea ebx, ss:[ebp+0xfffffffffffffba5]
         // 004013b7: sub esp, 0x458
         // 004013bd: mov edi, ds:[ecx+0x4]
         // 004013c0: call 0x401320
         // 004013c5: push eax
         // 004013c6: push 0x400
         // 004013cb: push ebx
         // 004013cc: push 0x0
         // 004013ce: call GetModuleFileNameA
         // 004013d3: push eax
         // 004013d4: push 0x41f024
         // 004013d9: push ebx
         // 004013da: call fopen
         // 004013df: add esp, 0x10
         // 004013e2: mov ebx, eax
         // 004013e4: test eax, eax
         // 004013e6: jz 0x4016d1
      [-]506a026a0053e849c60100891c24e831c6010083c40ca3????????6a006a0053e82fc6010058ff35????????e833c60100a3????????53ff35????????6a0150e82fc6010083c41453e836c601000f31c70424????????89d689c3e844c6010031f3331f31c3891c2431dbe824c601008b3d????????83ef0a8b35????????83c410eb25
         // 004013ec: push eax
         // 004013ed: push 0x2
         // 004013ef: push 0x0
         // 004013f1: push ebx
         // 004013f2: call fseek
         // 004013f7: mov ss:[esp], ebx
         // 004013fa: call ftell
         // 004013ff: add esp, 0xc
         // 00401402: mov ds:[0x423010], eax
         // 00401407: push 0x0
         // 00401409: push 0x0
         // 0040140b: push ebx
         // 0040140c: call fseek
         // 00401411: pop eax
         // 00401412: push ds:[0x423010]
         // 00401418: call malloc
         // 0040141d: mov ds:[0x423020], eax
         // 00401422: push ebx
         // 00401423: push ds:[0x423010]
         // 00401429: push 0x1
         // 0040142b: push eax
         // 0040142c: call fread
         // 00401431: add esp, 0x14
         // 00401434: push ebx
         // 00401435: call fclose
         // 0040143a: rdtsc 
         // 0040143c: mov ss:[esp], 0x0
         // 00401443: mov esi, edx
         // 00401445: mov ebx, eax
         // 00401447: call time
         // 0040144c: xor ebx, esi
         // 0040144e: xor ebx, ds:[edi]
         // 00401450: xor ebx, eax
         // 00401452: mov ss:[esp], ebx
         // 00401455: xor ebx, ebx
         // 00401457: call srand
         // 0040145c: mov edi, ds:[0x423010]
         // 00401462: sub edi, 0xa
         // 00401465: mov esi, ds:[0x423020]
         // 0040146b: add esp, 0x10
         // 0040146e: jmp 0x401495
      [-]508d041e6a0a68????????50e85fc5010083c41085c0750c
         // 00401470: push eax
         // 00401471: lea eax, ds:[esi+ebx]
         // 00401474: push 0xa
         // 00401476: push 0x41f108
         // 0040147b: push eax
         // 0040147c: call memcmp
         // 00401481: add esp, 0x10
         // 00401484: test eax, eax
         // 00401486: jnz 0x401494
      [-]8d430aa3????????31c0eb0a
         // 00401488: lea eax, ds:[ebx+0xa]
         // 0040148b: mov ds:[0x423030], eax
         // 00401490: xor eax, eax
         // 00401492: jmp 0x40149e
      [-]39fb7cd7
         // 00401495: cmp ebx, edi
         // 00401497: jl 0x401470
      [-]b8????????
         // 00401499: mov eax, 0x1
      [-]85c00f852b020000
         // 0040149e: test eax, eax
         // 004014a0: jnz 0x4016d1
      [-]83ec0c68????????e80dc60100c70424????????e801c601008b0ddc52420083c14083c410898d????????
         // 004014a6: sub esp, 0xc
         // 004014a9: push 0x41f027
         // 004014ae: call puts
         // 004014b3: mov ss:[esp], 0x41f044
         // 004014ba: call puts
         // 004014bf: mov ecx, ds:[_iob]
         // 004014c5: add ecx, 0x40
         // 004014c8: add esp, 0x10
         // 004014cb: mov ss:[ebp+0xfffffffffffffb9c], ecx
      [-]83ec0cbb????????8d75cd68????????e85ac8010083c40ce8b2c50100ba????????89d199f7f98d7a01
         // 004014d1: sub esp, 0xc
         // 004014d4: mov ebx, 0x1
         // 004014d9: lea esi, ss:[ebp+0xffffffffffffffcd]
         // 004014dc: push 0x7530
         // 004014e1: call Sleep
         // 004014e6: add esp, 0xc
         // 004014e9: call rand
         // 004014ee: mov edx, 0x7
         // 004014f3: mov ecx, edx
         // 004014f5: cdq 
         // 004014f6: idiv ecx
         // 004014f8: lea edi, ds:[edx+0x1]
      [-]e8a0c50100ba????????89d199f7f98a8224f14100884433ff4383fb1175e1
         // 004014fb: call rand
         // 00401500: mov edx, 0x3e
         // 00401505: mov ecx, edx
         // 00401507: cdq 
         // 00401508: idiv ecx
         // 0040150a: mov b1 al, b1 ds:[edx+0x41f124]
         // 00401510: mov b1 ds:[ebx+esi+0xffffffffffffffff], b1 al
         // 00401514: inc ebx
         // 00401515: cmp ebx, 0x11
         // 00401518: jnz 0x4014fb
      [-]c645dd00538d5da55668????????53e8d2c4010083c40c575368????????e873c501008b1d????????be????????031d????????83c410
         // 0040151a: mov b1 ss:[ebp+0xffffffffffffffdd], b1 0x0
         // 0040151e: push ebx
         // 0040151f: lea ebx, ss:[ebp+0xffffffffffffffa5]
         // 00401522: push esi
         // 00401523: push 0x41f045
         // 00401528: push ebx
         // 00401529: call sprintf
         // 0040152e: add esp, 0xc
         // 00401531: push edi
         // 00401532: push ebx
         // 00401533: push 0x41f055
         // 00401538: call printf
         // 0040153d: mov ebx, ds:[0x423030]
         // 00401543: mov esi, 0x1
         // 00401548: add ebx, ds:[0x423020]
         // 0040154e: add esp, 0x10
      [-]e84ac5010088441eff4683fe1175f1
         // 00401551: call rand
         // 00401556: mov b1 ds:[esi+ebx+0xffffffffffffffff], b1 al
         // 0040155a: inc esi
         // 0040155b: cmp esi, 0x11
         // 0040155e: jnz 0x401551
      [-]8d75a5515168????????56e8b0c4010089c383c410b8????????85db0f8432010000
         // 00401560: lea esi, ss:[ebp+0xffffffffffffffa5]
         // 00401563: push ecx
         // 00401564: push ecx
         // 00401565: push 0x41f086
         // 0040156a: push esi
         // 0040156b: call fopen
         // 00401570: mov ebx, eax
         // 00401572: add esp, 0x10
         // 00401575: mov eax, 0x1
         // 0040157a: test ebx, ebx
         // 0040157c: jz 0x4016b4
      [-]53ff35????????6a01ff35????????e85ac40100891c24e8d2c40100c745ec????????c745e8????????c70424????????e84a08000083c40c578d7dde68????????57e836c4010083c40c8d5dec6a11568d75e86a0a68????????6a015653e85315000083c41c6a11576a0468????????6a015653e83d15000083c41c6a1168????????6a0468????????6a015653e82315000083c420e89608000089c385c0747a
         // 00401582: push ebx
         // 00401583: push ds:[0x423010]
         // 00401589: push 0x1
         // 0040158b: push ds:[0x423020]
         // 00401591: call fwrite
         // 00401596: mov ss:[esp], ebx
         // 00401599: call fclose
         // 0040159e: mov ss:[ebp+0xffffffffffffffec], 0x0
         // 004015a5: mov ss:[ebp+0xffffffffffffffe8], 0x0
         // 004015ac: mov ss:[esp], 0x3
         // 004015b3: call curl_global_init
         // 004015b8: add esp, 0xc
         // 004015bb: push edi
         // 004015bc: lea edi, ss:[ebp+0xffffffffffffffde]
         // 004015bf: push 0x41f089
         // 004015c4: push edi
         // 004015c5: call sprintf
         // 004015ca: add esp, 0xc
         // 004015cd: lea ebx, ss:[ebp+0xffffffffffffffec]
         // 004015d0: push 0x11
         // 004015d2: push esi
         // 004015d3: lea esi, ss:[ebp+0xffffffffffffffe8]
         // 004015d6: push 0xa
         // 004015d8: push 0x41f090
         // 004015dd: push 0x1
         // 004015df: push esi
         // 004015e0: push ebx
         // 004015e1: call curl_formadd
         // 004015e6: add esp, 0x1c
         // 004015e9: push 0x11
         // 004015eb: push edi
         // 004015ec: push 0x4
         // 004015ee: push 0x41f097
         // 004015f3: push 0x1
         // 004015f5: push esi
         // 004015f6: push ebx
         // 004015f7: call curl_formadd
         // 004015fc: add esp, 0x1c
         // 004015ff: push 0x11
         // 00401601: push 0x41f09c
         // 00401606: push 0x4
         // 00401608: push 0x41f0a1
         // 0040160d: push 0x1
         // 0040160f: push esi
         // 00401610: push ebx
         // 00401611: call curl_formadd
         // 00401616: add esp, 0x20
         // 00401619: call curl_easy_init
         // 0040161e: mov ebx, eax
         // 00401620: test eax, eax
         // 00401622: jz 0x40169e
      [-]5268????????68????????50e86d07000083c40cff75ec68????????53e85c07000083c40c6a016a2953e84f070000891c24e8af05000083c41085c07427
         // 00401624: push edx
         // 00401625: push 0x41f0a8
         // 0040162a: push 0x2712
         // 0040162f: push eax
         // 00401630: call curl_easy_setopt
         // 00401635: add esp, 0xc
         // 00401638: push ss:[ebp+0xffffffffffffffec]
         // 0040163b: push 0x2728
         // 00401640: push ebx
         // 00401641: call curl_easy_setopt
         // 00401646: add esp, 0xc
         // 00401649: push 0x1
         // 0040164b: push 0x29
         // 0040164d: push ebx
         // 0040164e: call curl_easy_setopt
         // 00401653: mov ss:[esp], ebx
         // 00401656: call curl_easy_perform
         // 0040165b: add esp, 0x10
         // 0040165e: test eax, eax
         // 00401660: jz 0x401689
      [-]83ec0c50e84d1c000083c40c5068????????ffb5????????e891c30100b8????????83c410eb2b
         // 00401662: sub esp, 0xc
         // 00401665: push eax
         // 00401666: call curl_easy_strerror
         // 0040166b: add esp, 0xc
         // 0040166e: push eax
         // 0040166f: push 0x41f0ce
         // 00401674: push ss:[ebp+0xfffffffffffffb9c]
         // 0040167a: call fprintf
         // 0040167f: mov eax, 0x1
         // 00401684: add esp, 0x10
         // 00401687: jmp 0x4016b4
      [-]83ec0c53e86605000058ff75ece87309000083c410
         // 00401689: sub esp, 0xc
         // 0040168c: push ebx
         // 0040168d: call curl_easy_cleanup
         // 00401692: pop eax
         // 00401693: push ss:[ebp+0xffffffffffffffec]
         // 00401696: call curl_formfree
         // 0040169b: add esp, 0x10
      [-]83ec0c8d45a550e836bc010031c083c41085db0f94c0
         // 0040169e: sub esp, 0xc
         // 004016a1: lea eax, ss:[ebp+0xffffffffffffffa5]
         // 004016a4: push eax
         // 004016a5: call _unlink
         // 004016aa: xor eax, eax
         // 004016ac: add esp, 0x10
         // 004016af: test ebx, ebx
         // 004016b1: setz b1 al
      [-]85c00f8415feffff
         // 004016b4: test eax, eax
         // 004016b6: jz 0x4014d1
      [-]83ec0c68????????e8f7c3010083c410e900feffff
         // 004016bc: sub esp, 0xc
         // 004016bf: push 0x41f0ee
         // 004016c4: call puts
         // 004016c9: add esp, 0x10
         // 004016cc: jmp 0x4014d1
      [-]8d65f0b8????????595b5e5f5d8d61fcc3
         // 004016d1: lea esp, ss:[ebp+0xfffffffffffffff0]
         // 004016d4: mov eax, 0x1
         // 004016d9: pop ecx
         // 004016da: pop ebx
         // 004016db: pop esi
         // 004016dc: pop edi
         // 004016dd: pop ebp
         // 004016de: lea esp, ds:[ecx+0xfffffffffffffffc]
         // 004016e1: retn 
      [-]5585c089e55689d653ba????????89c3743a
         // 004016e4: push ebp
         // 004016e5: test eax, eax
         // 004016e7: mov ebp, esp
         // 004016e9: push esi
         // 004016ea: mov esi, edx
         // 004016ec: push ebx
         // 004016ed: mov edx, 0x2b
         // 004016f2: mov ebx, eax
         // 004016f4: jz 0x401730
      [-]80b8e1020000007509
         // 004016f6: cmp b1 ds:[eax+0x2e1], b1 0x0
         // 004016fd: jnz 0x401708
      [-]515168????????eb1a
         // 004016ff: push ecx
         // 00401700: push ecx
         // 00401701: push 0x41f164
         // 00401706: jmp 0x401722
      [-]52525150e86ad0000083c410890631d2407515
         // 00401708: push edx
         // 00401709: push edx
         // 0040170a: push ecx
         // 0040170b: push eax
         // 0040170c: call 0x40e77b
         // 00401711: add esp, 0x10
         // 00401714: mov ds:[esi], eax
         // 00401716: xor edx, edx
         // 00401718: inc eax
         // 00401719: jnz 0x401730
      [-]505068????????
         // 0040171b: push eax
         // 0040171c: push eax
         // 0040171d: push 0x41f17e
      [-]53e821cb0000ba????????83c410
         // 00401722: push ebx
         // 00401723: call 0x40e249
         // 00401728: mov edx, 0x1
         // 0040172d: add esp, 0x10
      [-]8d65f889d05b5e5dc3
         // 00401730: lea esp, ss:[ebp+0xfffffffffffffff8]
         // 00401733: mov eax, edx
         // 00401735: pop ebx
         // 00401736: pop esi
         // 00401737: pop ebp
         // 00401738: retn 
      [-]5589e58b450885c07406
         // 00401bf8: push ebp
         // 00401bf9: mov ebp, esp
         // 00401bfb: mov eax, ss:[ebp+0x8]
         // 00401bfe: test eax, eax
         // 00401c00: jz 0x401c08
      [-]5de961810000
         // 00401c02: pop ebp
         // 00401c03: jmp 0x409d69
      [-]5589e557565383ec1cbb????????837d08000f8476010000
         // 00401c0a: push ebp
         // 00401c0b: mov ebp, esp
         // 00401c0d: push edi
         // 00401c0e: push esi
         // 00401c0f: push ebx
         // 00401c10: sub esp, 0x1c
         // 00401c13: mov ebx, 0x2b
         // 00401c18: cmp ss:[ebp+0x8], 0x0
         // 00401c1c: jz 0x401d98
      [-]8b4508837840007414
         // 00401c22: mov eax, ss:[ebp+0x8]
         // 00401c25: cmp ds:[eax+0x40], 0x0
         // 00401c29: jz 0x401c3f
      [-]565668????????50e811c60000b302e94f010000
         // 00401c2b: push esi
         // 00401c2c: push esi
         // 00401c2d: push 0x41f19a
         // 00401c32: push eax
         // 00401c33: call 0x40e249
         // 00401c38: mov b1 bl, b1 0x2
         // 00401c3a: jmp 0x401d8e
      [-]8b55088b424489c685c0751e
         // 00401c3f: mov edx, ss:[ebp+0x8]
         // 00401c42: mov eax, ds:[edx+0x44]
         // 00401c45: mov esi, eax
         // 00401c47: test eax, eax
         // 00401c49: jnz 0x401c69
      [-]53536a036a01e88ca5000083c41089c685c00f8430010000
         // 00401c4b: push ebx
         // 00401c4c: push ebx
         // 00401c4d: push 0x3
         // 00401c4f: push 0x1
         // 00401c51: call 0x40c1e2
         // 00401c56: add esp, 0x10
         // 00401c59: mov esi, eax
         // 00401c5b: test eax, eax
         // 00401c5d: jz 0x401d93
      [-]8b4508897044
         // 00401c63: mov eax, ss:[ebp+0x8]
         // 00401c66: mov ds:[eax+0x44], esi
      [-]8b550851ffb2????????6a0656e89d990000585aff750856e825a4000083c41089c785c0741f
         // 00401c69: mov edx, ss:[ebp+0x8]
         // 00401c6c: push ecx
         // 00401c6d: push ds:[edx+0x3d8]
         // 00401c73: push 0x6
         // 00401c75: push esi
         // 00401c76: call curl_multi_setopt
         // 00401c7b: pop eax
         // 00401c7c: pop edx
         // 00401c7d: push ss:[ebp+0x8]
         // 00401c80: push esi
         // 00401c81: call curl_multi_add_handle
         // 00401c86: add esp, 0x10
         // 00401c89: mov edi, eax
         // 00401c8b: test eax, eax
         // 00401c8d: jz 0x401cae
      [-]83ec0cbb????????56e8809b000083c41083ff030f85ef000000
         // 00401c8f: sub esp, 0xc
         // 00401c92: mov ebx, 0x2
         // 00401c97: push esi
         // 00401c98: call curl_multi_cleanup
         // 00401c9d: add esp, 0x10
         // 00401ca0: cmp edi, 0x3
         // 00401ca3: jnz 0x401d98
      [-]e9e5000000
         // 00401ca9: jmp 0x401d93
      [-]8b450831db8d7dec897040
         // 00401cae: mov eax, ss:[ebp+0x8]
         // 00401cb1: xor ebx, ebx
         // 00401cb3: lea edi, ss:[ebp+0xffffffffffffffec]
         // 00401cb6: mov ds:[eax+0x40], esi
      [-]e8b6a6000083ec0c8955dc8d55e8528945d868????????6a006a0056e8e39f000083c42085c00f858f000000
         // 00401cb9: call 0x40c374
         // 00401cbe: sub esp, 0xc
         // 00401cc1: mov ss:[ebp+0xffffffffffffffdc], edx
         // 00401cc4: lea edx, ss:[ebp+0xffffffffffffffe8]
         // 00401cc7: push edx
         // 00401cc8: mov ss:[ebp+0xffffffffffffffd8], eax
         // 00401ccb: push 0x3e8
         // 00401cd0: push 0x0
         // 00401cd2: push 0x0
         // 00401cd4: push esi
         // 00401cd5: call curl_multi_wait
         // 00401cda: add esp, 0x20
         // 00401cdd: test eax, eax
         // 00401cdf: jnz 0x401d74
      [-]8b45e883f8ff750a
         // 00401ce5: mov eax, ss:[ebp+0xffffffffffffffe8]
         // 00401ce8: cmp eax, 0xffffffffffffffff
         // 00401ceb: jnz 0x401cf7
      [-]bb????????e98c000000
         // 00401ced: mov ebx, 0x38
         // 00401cf2: jmp 0x401d83
      [-]85c07541
         // 00401cf7: test eax, eax
         // 00401cf9: jnz 0x401d3c
      [-]e874a60000ff75dcff75d85250e8fba5000083c41083f80a7f27
         // 00401cfb: call 0x40c374
         // 00401d00: push ss:[ebp+0xffffffffffffffdc]
         // 00401d03: push ss:[ebp+0xffffffffffffffd8]
         // 00401d06: push edx
         // 00401d07: push eax
         // 00401d08: call 0x40c308
         // 00401d0d: add esp, 0x10
         // 00401d10: cmp eax, 0xa
         // 00401d13: jg 0x401d3c
      [-]4383fb027e23
         // 00401d15: inc ebx
         // 00401d16: cmp ebx, 0x2
         // 00401d19: jle 0x401d3e
      [-]b8????????83fb097f09
         // 00401d1b: mov eax, 0x3e8
         // 00401d20: cmp ebx, 0x9
         // 00401d23: jg 0x401d2e
      [-]8d4bff66b80100d3e0
         // 00401d25: lea ecx, ds:[ebx+0xffffffffffffffff]
         // 00401d28: mov b2 ax, b2 0x1
         // 00401d2c: shl eax, b1 cl
      [-]83ec0c50e8c916000083c410eb02
         // 00401d2e: sub esp, 0xc
         // 00401d31: push eax
         // 00401d32: call 0x403400
         // 00401d37: add esp, 0x10
         // 00401d3a: jmp 0x401d3e
      [-]50505756e8079c000083c41085c07526
         // 00401d3e: push eax
         // 00401d3f: push eax
         // 00401d40: push edi
         // 00401d41: push esi
         // 00401d42: call curl_multi_perform
         // 00401d47: add esp, 0x10
         // 00401d4a: test eax, eax
         // 00401d4c: jnz 0x401d74
      [-]837dec000f8561ffffff
         // 00401d4e: cmp ss:[ebp+0xffffffffffffffec], 0x0
         // 00401d52: jnz 0x401cb9
      [-]50508d45e45056e8519a000083c41085c00f844affffff
         // 00401d58: push eax
         // 00401d59: push eax
         // 00401d5a: lea eax, ss:[ebp+0xffffffffffffffe4]
         // 00401d5d: push eax
         // 00401d5e: push esi
         // 00401d5f: call curl_multi_info_read
         // 00401d64: add esp, 0x10
         // 00401d67: test eax, eax
         // 00401d69: jz 0x401cb9
      [-]8b5808eb0f
         // 00401d6f: mov ebx, ds:[eax+0x8]
         // 00401d72: jmp 0x401d83
      [-]31db83f8030f95c34b83e3f083c32b
         // 00401d74: xor ebx, ebx
         // 00401d76: cmp eax, 0x3
         // 00401d79: setnz b1 bl
         // 00401d7c: dec ebx
         // 00401d7d: and ebx, 0xfffffffffffffff0
         // 00401d80: add ebx, 0x2b
      [-]5050ff750856e865a10000
         // 00401d83: push eax
         // 00401d84: push eax
         // 00401d85: push ss:[ebp+0x8]
         // 00401d88: push esi
         // 00401d89: call curl_multi_remove_handle
      [-]83c410eb05
         // 00401d8e: add esp, 0x10
         // 00401d91: jmp 0x401d98
      [-]bb????????
         // 00401d93: mov ebx, 0x1b
      [-]8d65f489d85b5e5f5dc3
         // 00401d98: lea esp, ss:[ebp+0xfffffffffffffff4]
         // 00401d9b: mov eax, ebx
         // 00401d9d: pop ebx
         // 00401d9e: pop esi
         // 00401d9f: pop edi
         // 00401da0: pop ebp
         // 00401da1: retn 
      [-]55b8????????89e583ec188b550885d27414
         // 00401da2: push ebp
         // 00401da3: mov eax, 0x2b
         // 00401da8: mov ebp, esp
         // 00401daa: sub esp, 0x18
         // 00401dad: mov edx, ss:[ebp+0x8]
         // 00401db0: test edx, edx
         // 00401db2: jz 0x401dc8
      [-]8d451051508945fcff750c52e8f05f000083c410
         // 00401db4: lea eax, ss:[ebp+0x10]
         // 00401db7: push ecx
         // 00401db8: push eax
         // 00401db9: mov ss:[ebp+0xfffffffffffffffc], eax
         // 00401dbc: push ss:[ebp+0xc]
         // 00401dbf: push edx
         // 00401dc0: call 0x407db5
         // 00401dc5: add esp, 0x10
      [-]5531d289e55381ec????????a1????????8b5d0840a3????????480f858a000000
         // 00401e02: push ebp
         // 00401e03: xor edx, edx
         // 00401e05: mov ebp, esp
         // 00401e07: push ebx
         // 00401e08: sub esp, 0x194
         // 00401e0e: mov eax, ds:[0x423040]
         // 00401e13: mov ebx, ss:[ebp+0x8]
         // 00401e16: inc eax
         // 00401e17: mov ds:[0x423040], eax
         // 00401e1c: dec eax
         // 00401e1d: jnz 0x401ead
      [-]c705????????50da4100c705????????d0da4100c705????????e0da4100c705????????f0d24100c705????????f0da4100f6c302743c
         // 00401e23: mov ds:[0x41e008], malloc
         // 00401e2d: mov ds:[0x41e00c], free
         // 00401e37: mov ds:[0x41e010], realloc
         // 00401e41: mov ds:[0x41e014], _strdup
         // 00401e4b: mov ds:[0x41e018], calloc
         // 00401e55: test b1 bl, b1 0x2
         // 00401e58: jz 0x401e96
      [-]50508d85????????5068????????e86bad01005a85c059ba????????7535
         // 00401e5a: push eax
         // 00401e5b: push eax
         // 00401e5c: lea eax, ss:[ebp+0xfffffffffffffe6c]
         // 00401e62: push eax
         // 00401e63: push 0x202
         // 00401e68: call WSAStartup
         // 00401e6d: pop edx
         // 00401e6e: test eax, eax
         // 00401e70: pop ecx
         // 00401e71: mov edx, 0x2
         // 00401e76: jnz 0x401ead
      [-]8b85????????3c027508
         // 00401e78: mov eax, ss:[ebp+0xfffffffffffffe6c]
         // 00401e7e: cmp b1 al, b1 0x2
         // 00401e80: jnz 0x401e8a
      [-]66c1e8083c02740c
         // 00401e82: shr b2 ax, b1 0x8
         // 00401e86: cmp b1 al, b1 0x2
         // 00401e88: jz 0x401e96
      [-]e839ad0100ba????????eb17
         // 00401e8a: call WSACleanup
         // 00401e8f: mov edx, 0x2
         // 00401e94: jmp 0x401ead
      [-]f6c304740a
         // 00401e96: test b1 bl, b1 0x4
         // 00401e99: jz 0x401ea5
      [-]c705????????????????
         // 00401e9b: mov ds:[0x423060], 0x1
      [-]891d????????31d2
         // 00401ea5: mov ds:[0x423050], ebx
         // 00401eab: xor edx, edx
      [-]89d08b5dfcc9c3
         // 00401ead: mov eax, edx
         // 00401eaf: mov ebx, ss:[ebp+0xfffffffffffffffc]
         // 00401eb2: leave 
         // 00401eb3: retn 
      [-]5589e583ec18833d????????007511
         // 00401eb4: push ebp
         // 00401eb5: mov ebp, esp
         // 00401eb7: sub esp, 0x18
         // 00401eba: cmp ds:[0x423040], 0x0
         // 00401ec1: jnz 0x401ed4
      [-]83ec0c6a03e835ffffff83c41085c07518
         // 00401ec3: sub esp, 0xc
         // 00401ec6: push 0x3
         // 00401ec8: call curl_global_init
         // 00401ecd: add esp, 0x10
         // 00401ed0: test eax, eax
         // 00401ed2: jnz 0x401eec
      [-]83ec0c8d45fc50e8bb24000083c41085c07505
         // 00401ed4: sub esp, 0xc
         // 00401ed7: lea eax, ss:[ebp+0xfffffffffffffffc]
         // 00401eda: push eax
         // 00401edb: call 0x40439b
         // 00401ee0: add esp, 0x10
         // 00401ee3: test eax, eax
         // 00401ee5: jnz 0x401eec
      [-]8b45fceb02
         // 00401ee7: mov eax, ss:[ebp+0xfffffffffffffffc]
         // 00401eea: jmp 0x401eee
      [-]5589e557565383ec1489d789c689cb6a406a01ff15????????83c41031d285c07424
         // 00401f74: push ebp
         // 00401f75: mov ebp, esp
         // 00401f77: push edi
         // 00401f78: push esi
         // 00401f79: push ebx
         // 00401f7a: sub esp, 0x14
         // 00401f7d: mov edi, edx
         // 00401f7f: mov esi, eax
         // 00401f81: mov ebx, ecx
         // 00401f83: push 0x40
         // 00401f85: push 0x1
         // 00401f87: call ds:[0x41e018]
         // 00401f8d: add esp, 0x10
         // 00401f90: xor edx, edx
         // 00401f92: test eax, eax
         // 00401f94: jz 0x401fba
      [-]89c285f67403
         // 00401f96: mov edx, eax
         // 00401f98: test esi, esi
         // 00401f9a: jz 0x401f9f
      [-]85ff7403
         // 00401f9f: test edi, edi
         // 00401fa1: jz 0x401fa6
      [-]c74220????????85db7409
         // 00401fa6: mov ds:[edx+0x20], 0x1
         // 00401fad: test ebx, ebx
         // 00401faf: jz 0x401fba
      [-]8b433c89423c89533c
         // 00401fb1: mov eax, ds:[ebx+0x3c]
         // 00401fb4: mov ds:[edx+0x3c], eax
         // 00401fb7: mov ds:[ebx+0x3c], edx
      [-]8d65f489d05b5e5f5dc3
         // 00401fba: lea esp, ss:[ebp+0xfffffffffffffff4]
         // 00401fbd: mov eax, edx
         // 00401fbf: pop ebx
         // 00401fc0: pop esi
         // 00401fc1: pop edi
         // 00401fc2: pop ebp
         // 00401fc3: retn 
      [-]5589e557565383ec0c8b7d088b1f85db7430
         // 00401fc4: push ebp
         // 00401fc5: mov ebp, esp
         // 00401fc7: push edi
         // 00401fc8: push esi
         // 00401fc9: push ebx
         // 00401fca: sub esp, 0xc
         // 00401fcd: mov edi, ss:[ebp+0x8]
         // 00401fd0: mov ebx, ds:[edi]
         // 00401fd2: test ebx, ebx
         // 00401fd4: jz 0x402006
      [-]8b33837b0401770f
         // 00401fd6: mov esi, ds:[ebx]
         // 00401fd8: cmp ds:[ebx+0x4], 0x1
         // 00401fdc: ja 0x401fed
      [-]83ec0cff7308ff15????????83c410
         // 00401fde: sub esp, 0xc
         // 00401fe1: push ds:[ebx+0x8]
         // 00401fe4: call ds:[0x41e00c]
         // 00401fea: add esp, 0x10
      [-]83ec0c5389f3ff15????????83c41085f675d6
         // 00401fed: sub esp, 0xc
         // 00401ff0: push ebx
         // 00401ff1: mov ebx, esi
         // 00401ff3: call ds:[0x41e00c]
         // 00401ff9: add esp, 0x10
         // 00401ffc: test esi, esi
         // 00401ffe: jnz 0x401fd6
      [-]c707????????
         // 00402000: mov ds:[edi], 0x0
      [-]8d65f45b5e5f5dc3
         // 00402006: lea esp, ss:[ebp+0xfffffffffffffff4]
         // 00402009: pop ebx
         // 0040200a: pop esi
         // 0040200b: pop edi
         // 0040200c: pop ebp
         // 0040200d: retn 
      [-]5589e556538b5d08
         // 0040200e: push ebp
         // 0040200f: mov ebp, esp
         // 00402011: push esi
         // 00402012: push ebx
         // 00402013: mov ebx, ss:[ebp+0x8]
      [-]85db0f8485000000
         // 00402016: test ebx, ebx
         // 00402018: jz 0x4020a3
      [-]8b43248b3385c0740c
         // 0040201e: mov eax, ds:[ebx+0x24]
         // 00402021: mov esi, ds:[ebx]
         // 00402023: test eax, eax
         // 00402025: jz 0x402033
      [-]83ec0c50e8deffffff83c410
         // 00402027: sub esp, 0xc
         // 0040202a: push eax
         // 0040202b: call curl_formfree
         // 00402030: add esp, 0x10
      [-]f64328047514
         // 00402033: test b1 ds:[ebx+0x28], b1 0x4
         // 00402037: jnz 0x40204d
      [-]8b430485c0740d
         // 00402039: mov eax, ds:[ebx+0x4]
         // 0040203c: test eax, eax
         // 0040203e: jz 0x40204d
      [-]83ec0c50ff15????????83c410
         // 00402040: sub esp, 0xc
         // 00402043: push eax
         // 00402044: call ds:[0x41e00c]
         // 0040204a: add esp, 0x10
      [-]f64328587514
         // 0040204d: test b1 ds:[ebx+0x28], b1 0x58
         // 00402051: jnz 0x402067
      [-]8b430c85c0740d
         // 00402053: mov eax, ds:[ebx+0xc]
         // 00402056: test eax, eax
         // 00402058: jz 0x402067
      [-]83ec0c50ff15????????83c410
         // 0040205a: sub esp, 0xc
         // 0040205d: push eax
         // 0040205e: call ds:[0x41e00c]
         // 00402064: add esp, 0x10
      [-]8b431c85c0740d
         // 00402067: mov eax, ds:[ebx+0x1c]
         // 0040206a: test eax, eax
         // 0040206c: jz 0x40207b
      [-]83ec0c50ff15????????83c410
         // 0040206e: sub esp, 0xc
         // 00402071: push eax
         // 00402072: call ds:[0x41e00c]
         // 00402078: add esp, 0x10
      [-]8b432c85c0740d
         // 0040207b: mov eax, ds:[ebx+0x2c]
         // 0040207e: test eax, eax
         // 00402080: jz 0x40208f
      [-]83ec0c50ff15????????83c410
         // 00402082: sub esp, 0xc
         // 00402085: push eax
         // 00402086: call ds:[0x41e00c]
         // 0040208c: add esp, 0x10
      [-]83ec0c53ff15????????89f383c410e973ffffff
         // 0040208f: sub esp, 0xc
         // 00402092: push ebx
         // 00402093: call ds:[0x41e00c]
         // 00402099: mov ebx, esi
         // 0040209b: add esp, 0x10
         // 0040209e: jmp 0x402016
      [-]8d65f85b5e5dc3
         // 004020a3: lea esp, ss:[ebp+0xfffffffffffffff8]
         // 004020a6: pop ebx
         // 004020a7: pop esi
         // 004020a8: pop ebp
         // 004020a9: retn 
      [-]55b8????????89e58b4d0c8b550885c97419
         // 004020aa: push ebp
         // 004020ab: mov eax, 0x1
         // 004020b0: mov ebp, esp
         // 004020b2: mov ecx, ss:[ebp+0xc]
         // 004020b5: mov edx, ss:[ebp+0x8]
         // 004020b8: test ecx, ecx
         // 004020ba: jz 0x4020d5
      [-]890ac742????????00c742????????00c742????????0030c0
         // 004020bc: mov ds:[edx], ecx
         // 004020be: mov ds:[edx+0x4], 0x0
         // 004020c5: mov ds:[edx+0x8], 0x0
         // 004020cc: mov ds:[edx+0xc], 0x0
         // 004020d3: xor b1 al, b1 al
      [-]5589e5565331db8b75088b0e85c9740f
         // 004020d7: push ebp
         // 004020d8: mov ebp, esp
         // 004020da: push esi
         // 004020db: push ebx
         // 004020dc: xor ebx, ebx
         // 004020de: mov esi, ss:[ebp+0x8]
         // 004020e1: mov ecx, ds:[esi]
         // 004020e3: test ecx, ecx
         // 004020e5: jz 0x4020f6
      [-]8b550c8b410c8b590889028b018906
         // 004020e7: mov edx, ss:[ebp+0xc]
         // 004020ea: mov eax, ds:[ecx+0xc]
         // 004020ed: mov ebx, ds:[ecx+0x8]
         // 004020f0: mov ds:[edx], eax
         // 004020f2: mov eax, ds:[ecx]
         // 004020f4: mov ds:[esi], eax
      [-]89d85b5e5dc3
         // 004020f6: mov eax, ebx
         // 004020f8: pop ebx
         // 004020f9: pop esi
         // 004020fa: pop ebp
         // 004020fb: retn 
      [-]5589e557565383ec0c89c38b008955f089cf837804027516
         // 004020fc: push ebp
         // 004020fd: mov ebp, esp
         // 004020ff: push edi
         // 00402100: push esi
         // 00402101: push ebx
         // 00402102: sub esp, 0xc
         // 00402105: mov ebx, eax
         // 00402107: mov eax, ds:[eax]
         // 00402109: mov ss:[ebp+0xfffffffffffffff0], edx
         // 0040210c: mov edi, ecx
         // 0040210e: cmp ds:[eax+0x4], 0x2
         // 00402112: jnz 0x40212a
      [-]8b530c31f685d27466
         // 00402114: mov edx, ds:[ebx+0xc]
         // 00402117: xor esi, esi
         // 00402119: test edx, edx
         // 0040211b: jz 0x402183
      [-]ff7008516a01ff75f0ffd2eb30
         // 0040211d: push ds:[eax+0x8]
         // 00402120: push ecx
         // 00402121: push 0x1
         // 00402123: push ss:[ebp+0xfffffffffffffff0]
         // 00402126: call edx
         // 00402128: jmp 0x40215a
      [-]837b0800751c
         // 0040212a: cmp ds:[ebx+0x8], 0x0
         // 0040212e: jnz 0x40214c
      [-]525268????????83ceffff7008e8deb8010083c41089430885c07437
         // 00402130: push edx
         // 00402131: push edx
         // 00402132: push 0x41f1c4
         // 00402137: or esi, 0xffffffffffffffff
         // 0040213a: push ds:[eax+0x8]
         // 0040213d: call fopen
         // 00402142: add esp, 0x10
         // 00402145: mov ds:[ebx+0x8], eax
         // 00402148: test eax, eax
         // 0040214a: jz 0x402183
      [-]ff7308576a01ff75f0e806b90100
         // 0040214c: push ds:[ebx+0x8]
         // 0040214f: push edi
         // 00402150: push 0x1
         // 00402152: push ss:[ebp+0xfffffffffffffff0]
         // 00402155: call fread
      [-]83c41089c685c07520
         // 0040215a: add esp, 0x10
         // 0040215d: mov esi, eax
         // 0040215f: test eax, eax
         // 00402161: jnz 0x402183
      [-]8b430885c07413
         // 00402163: mov eax, ds:[ebx+0x8]
         // 00402166: test eax, eax
         // 00402168: jz 0x40217d
      [-]83ec0c50e8fdb80100c743????????0083c410
         // 0040216a: sub esp, 0xc
         // 0040216d: push eax
         // 0040216e: call fclose
         // 00402173: mov ds:[ebx+0x8], 0x0
         // 0040217a: add esp, 0x10
      [-]8b038b008903
         // 0040217d: mov eax, ds:[ebx]
         // 0040217f: mov eax, ds:[eax]
         // 00402181: mov ds:[ebx], eax
      [-]8d65f489f05b5e5f5dc3
         // 00402183: lea esp, ss:[ebp+0xfffffffffffffff4]
         // 00402186: mov eax, esi
         // 00402188: pop ebx
         // 00402189: pop esi
         // 0040218a: pop edi
         // 0040218b: pop ebp
         // 0040218c: retn 
      [-]5589e557565383ec0c31f68b7d148b0785c00f8495000000
         // 0040218d: push ebp
         // 0040218e: mov ebp, esp
         // 00402190: push edi
         // 00402191: push esi
         // 00402192: push ebx
         // 00402193: sub esp, 0xc
         // 00402196: xor esi, esi
         // 00402198: mov edi, ss:[ebp+0x14]
         // 0040219b: mov eax, ds:[edi]
         // 0040219d: test eax, eax
         // 0040219f: jz 0x40223a
      [-]8b550c8b40040faf551083e8028955f083f8017712
         // 004021a5: mov edx, ss:[ebp+0xc]
         // 004021a8: mov eax, ds:[eax+0x4]
         // 004021ab: imul edx, ss:[ebp+0x10]
         // 004021af: sub eax, 0x2
         // 004021b2: mov ss:[ebp+0xfffffffffffffff0], edx
         // 004021b5: cmp eax, 0x1
         // 004021b8: ja 0x4021cc
      [-]89d189f88b5508e836ffffff89c685c0756e
         // 004021ba: mov ecx, edx
         // 004021bc: mov eax, edi
         // 004021be: mov edx, ss:[ebp+0x8]
         // 004021c1: call 0x4020fc
         // 004021c6: mov esi, eax
         // 004021c8: test eax, eax
         // 004021ca: jnz 0x40223a
      [-]8b0f8b4704894de88b5df08b510c8b4d0829c229f38d0c3139da894dec761a
         // 004021ce: mov ecx, ds:[edi]
         // 004021d0: mov eax, ds:[edi+0x4]
         // 004021d3: mov ss:[ebp+0xffffffffffffffe8], ecx
         // 004021d6: mov ebx, ss:[ebp+0xfffffffffffffff0]
         // 004021d9: mov edx, ds:[ecx+0xc]
         // 004021dc: mov ecx, ss:[ebp+0x8]
         // 004021df: sub edx, eax
         // 004021e1: sub ebx, esi
         // 004021e3: lea ecx, ds:[ecx+esi]
         // 004021e6: cmp edx, ebx
         // 004021e8: mov ss:[ebp+0xffffffffffffffec], ecx
         // 004021eb: jbe 0x402207
      [-]8b55e803420856535051e814b90100015f048b75f083c410eb33
         // 004021ed: mov edx, ss:[ebp+0xffffffffffffffe8]
         // 004021f0: add eax, ds:[edx+0x8]
         // 004021f3: push esi
         // 004021f4: push ebx
         // 004021f5: push eax
         // 004021f6: push ecx
         // 004021f7: call memcpy
         // 004021fc: add ds:[edi+0x4], ebx
         // 004021ff: mov esi, ss:[ebp+0xfffffffffffffff0]
         // 00402202: add esp, 0x10
         // 00402205: jmp 0x40223a
      [-]8b4de8034108515250ff75ece8f8b801008b178b420c83c4102b4704c747????????0001c68b02890785c07406
         // 00402207: mov ecx, ss:[ebp+0xffffffffffffffe8]
         // 0040220a: add eax, ds:[ecx+0x8]
         // 0040220d: push ecx
         // 0040220e: push edx
         // 0040220f: push eax
         // 00402210: push ss:[ebp+0xffffffffffffffec]
         // 00402213: call memcpy
         // 00402218: mov edx, ds:[edi]
         // 0040221a: mov eax, ds:[edx+0xc]
         // 0040221d: add esp, 0x10
         // 00402220: sub eax, ds:[edi+0x4]
         // 00402223: mov ds:[edi+0x4], 0x0
         // 0040222a: add esi, eax
         // 0040222c: mov eax, ds:[edx]
         // 0040222e: mov ds:[edi], eax
         // 00402230: test eax, eax
         // 00402232: jz 0x40223a
      [-]837804017694
         // 00402234: cmp ds:[eax+0x4], 0x1
         // 00402238: jbe 0x4021ce
      [-]8d65f489f05b5e5f5dc3
         // 0040223a: lea esp, ss:[ebp+0xfffffffffffffff4]
         // 0040223d: mov eax, esi
         // 0040223f: pop ebx
         // 00402240: pop esi
         // 00402241: pop edi
         // 00402242: pop ebp
         // 00402243: retn 
      [-]5589e5565389c383ec0c50e836e90000891c2489c6e82ce9000083c40c565068????????e88be600008d65f85b5e5dc3
         // 00402244: push ebp
         // 00402245: mov ebp, esp
         // 00402247: push esi
         // 00402248: push ebx
         // 00402249: mov ebx, eax
         // 0040224b: sub esp, 0xc
         // 0040224e: push eax
         // 0040224f: call 0x410b8a
         // 00402254: mov ss:[esp], ebx
         // 00402257: mov esi, eax
         // 00402259: call 0x410b8a
         // 0040225e: add esp, 0xc
         // 00402261: push esi
         // 00402262: push eax
         // 00402263: push 0x41f1c7
         // 00402268: call curl_maprintf
         // 0040226d: lea esp, ss:[ebp+0xfffffffffffffff8]
         // 00402270: pop ebx
         // 00402271: pop esi
         // 00402272: pop ebp
         // 00402273: retn 
      [-]5589e557565383ec0c89c685d2752e
         // 00402274: push ebp
         // 00402275: mov ebp, esp
         // 00402277: push edi
         // 00402278: push esi
         // 00402279: push ebx
         // 0040227a: sub esp, 0xc
         // 0040227d: mov esi, eax
         // 0040227f: test edx, edx
         // 00402281: jnz 0x4022b1
      [-]85c07415
         // 00402283: test eax, eax
         // 00402285: jz 0x40229c
      [-]fc83c9ff31c089f7f2aef7d1c645f3018d59ffeb1b
         // 00402287: cld 
         // 00402288: or ecx, 0xffffffffffffffff
         // 0040228b: xor eax, eax
         // 0040228d: mov edi, esi
         // 0040228f: repne scasbb 
         // 00402291: not ecx
         // 00402293: mov b1 ss:[ebp+0xfffffffffffffff3], b1 0x1
         // 00402297: lea ebx, ds:[ecx+0xffffffffffffffff]
         // 0040229a: jmp 0x4022b7
      [-]83ec0c68????????ff15????????83c41089c7eb37
         // 0040229c: sub esp, 0xc
         // 0040229f: push 0x41f1e8
         // 004022a4: call ds:[0x41e014]
         // 004022aa: add esp, 0x10
         // 004022ad: mov edi, eax
         // 004022af: jmp 0x4022e8
      [-]89d3c645f300
         // 004022b1: mov ebx, edx
         // 004022b3: mov b1 ss:[ebp+0xfffffffffffffff3], b1 0x0
      [-]0fb645f383ec0c01d831ff50ff15????????83c41085c07418
         // 004022b7: movzx eax, b1 ss:[ebp+0xfffffffffffffff3]
         // 004022bb: sub esp, 0xc
         // 004022be: add eax, ebx
         // 004022c0: xor edi, edi
         // 004022c2: push eax
         // 004022c3: call ds:[0x41e008]
         // 004022c9: add esp, 0x10
         // 004022cc: test eax, eax
         // 004022ce: jz 0x4022e8
      [-]89c750535657e835b8010083c410807df3007404
         // 004022d0: mov edi, eax
         // 004022d2: push eax
         // 004022d3: push ebx
         // 004022d4: push esi
         // 004022d5: push edi
         // 004022d6: call memcpy
         // 004022db: add esp, 0x10
         // 004022de: cmp b1 ss:[ebp+0xfffffffffffffff3], b1 0x0
         // 004022e2: jz 0x4022e8
      [-]c6041f00
         // 004022e4: mov b1 ds:[edi+ebx], b1 0x0
      [-]8d65f489f85b5e5f5dc3
         // 004022e8: lea esp, ss:[ebp+0xfffffffffffffff4]
         // 004022eb: mov eax, edi
         // 004022ed: pop ebx
         // 004022ee: pop esi
         // 004022ef: pop edi
         // 004022f0: pop ebp
         // 004022f1: retn 
      [-]5589e557565383ec488945bc8955b889ce6a108b7d08ff15????????83c41089c3b8????????85db0f84e8000000
         // 004022f2: push ebp
         // 004022f3: mov ebp, esp
         // 004022f5: push edi
         // 004022f6: push esi
         // 004022f7: push ebx
         // 004022f8: sub esp, 0x48
         // 004022fb: mov ss:[ebp+0xffffffffffffffbc], eax
         // 004022fe: mov ss:[ebp+0xffffffffffffffb8], edx
         // 00402301: mov esi, ecx
         // 00402303: push 0x10
         // 00402305: mov edi, ss:[ebp+0x8]
         // 00402308: call ds:[0x41e008]
         // 0040230e: add esp, 0x10
         // 00402311: mov ebx, eax
         // 00402313: mov eax, 0x1b
         // 00402318: test ebx, ebx
         // 0040231a: jz 0x402408
      [-]c703????????837db8017759
         // 00402320: mov ds:[ebx], 0x0
         // 00402326: cmp ss:[ebp+0xffffffffffffffb8], 0x1
         // 0040232a: ja 0x402385
      [-]85ff750f
         // 0040232c: test edi, edi
         // 0040232e: jnz 0x40233f
      [-]fc89f783c9ff31c0f2aef7d18d79ff
         // 00402330: cld 
         // 00402331: mov edi, esi
         // 00402333: or ecx, 0xffffffffffffffff
         // 00402336: xor eax, eax
         // 00402338: repne scasbb 
         // 0040233a: not ecx
         // 0040233c: lea edi, ds:[ecx+0xffffffffffffffff]
      [-]83ec0c8d470150ff15????????83c41089430885c07517
         // 0040233f: sub esp, 0xc
         // 00402342: lea eax, ds:[edi+0x1]
         // 00402345: push eax
         // 00402346: call ds:[0x41e008]
         // 0040234c: add esp, 0x10
         // 0040234f: mov ds:[ebx+0x8], eax
         // 00402352: test eax, eax
         // 00402354: jnz 0x40236d
      [-]83ec0c53ff15????????b8????????83c410e99b000000
         // 00402356: sub esp, 0xc
         // 00402359: push ebx
         // 0040235a: call ds:[0x41e00c]
         // 00402360: mov eax, 0x1b
         // 00402365: add esp, 0x10
         // 00402368: jmp 0x402408
      [-]52575650e89ab701008b430883c410897b0cc6043800eb03
         // 0040236d: push edx
         // 0040236e: push edi
         // 0040236f: push esi
         // 00402370: push eax
         // 00402371: call memcpy
         // 00402376: mov eax, ds:[ebx+0x8]
         // 00402379: add esp, 0x10
         // 0040237c: mov ds:[ebx+0xc], edi
         // 0040237f: mov b1 ds:[eax+edi], b1 0x0
         // 00402383: jmp 0x402388
      [-]8b55bc8b45b88943048b0285c07406
         // 00402388: mov edx, ss:[ebp+0xffffffffffffffbc]
         // 0040238b: mov eax, ss:[ebp+0xffffffffffffffb8]
         // 0040238e: mov ds:[ebx+0x4], eax
         // 00402391: mov eax, ds:[edx]
         // 00402393: test eax, eax
         // 00402395: jz 0x40239d
      [-]8918891aeb05
         // 00402397: mov ds:[eax], ebx
         // 00402399: mov ds:[edx], ebx
         // 0040239b: jmp 0x4023a2
      [-]8b4dbc8919
         // 0040239d: mov ecx, ss:[ebp+0xffffffffffffffbc]
         // 004023a0: mov ds:[ecx], ebx
      [-]837d0c00745e
         // 004023a2: cmp ss:[ebp+0xc], 0x0
         // 004023a6: jz 0x402406
      [-]837db8037406
         // 004023a8: cmp ss:[ebp+0xffffffffffffffb8], 0x3
         // 004023ac: jz 0x4023b4
      [-]89f831d2eb41
         // 004023ae: mov eax, edi
         // 004023b0: xor edx, edx
         // 004023b2: jmp 0x4023f5
      [-]5050ff730868????????e826e6000083c41085c0753c
         // 004023b4: push eax
         // 004023b5: push eax
         // 004023b6: push ds:[ebx+0x8]
         // 004023b9: push 0x41f1e9
         // 004023be: call curl_strequal
         // 004023c3: add esp, 0x10
         // 004023c6: test eax, eax
         // 004023c8: jnz 0x402406
      [-]50508d45c050ff7308e848b7010083c41085c07520
         // 004023ca: push eax
         // 004023cb: push eax
         // 004023cc: lea eax, ss:[ebp+0xffffffffffffffc0]
         // 004023cf: push eax
         // 004023d0: push ds:[ebx+0x8]
         // 004023d3: call _stati64
         // 004023d8: add esp, 0x10
         // 004023db: test eax, eax
         // 004023dd: jnz 0x4023ff
      [-]0fb745c625????????3d????????7410
         // 004023df: movzx eax, b2 ss:[ebp+0xffffffffffffffc6]
         // 004023e3: and eax, 0xf000
         // 004023e8: cmp eax, 0x4000
         // 004023ed: jz 0x4023ff
      [-]8b45d88b55dc
         // 004023ef: mov eax, ss:[ebp+0xffffffffffffffd8]
         // 004023f2: mov edx, ss:[ebp+0xffffffffffffffdc]
      [-]8b4d0c0101115104eb07
         // 004023f5: mov ecx, ss:[ebp+0xc]
         // 004023f8: add ds:[ecx], eax
         // 004023fa: adc ds:[ecx+0x4], edx
         // 004023fd: jmp 0x402406
      [-]b8????????eb02
         // 004023ff: mov eax, 0x2b
         // 00402404: jmp 0x402408
      [-]8d65f45b5e5f5dc3
         // 00402408: lea esp, ss:[ebp+0xfffffffffffffff4]
         // 0040240b: pop ebx
         // 0040240c: pop esi
         // 0040240d: pop edi
         // 0040240e: pop ebp
         // 0040240f: retn 
      [-]55b8????????89e553e84aaa01008d4514508d9d????????ff75108945f868????????53e844e500005958ff750c89d98b450831d26a00e8a6feffff8b5dfcc9c3
         // 00402410: push ebp
         // 00402411: mov eax, 0x1014
         // 00402416: mov ebp, esp
         // 00402418: push ebx
         // 00402419: call 0x41ce68
         // 0040241e: lea eax, ss:[ebp+0x14]
         // 00402421: push eax
         // 00402422: lea ebx, ss:[ebp+0xffffffffffffeff8]
         // 00402428: push ss:[ebp+0x10]
         // 0040242b: mov ss:[ebp+0xfffffffffffffff8], eax
         // 0040242e: push 0x1000
         // 00402433: push ebx
         // 00402434: call curl_mvsnprintf
         // 00402439: pop ecx
         // 0040243a: pop eax
         // 0040243b: push ss:[ebp+0xc]
         // 0040243e: mov ecx, ebx
         // 00402440: mov eax, ss:[ebp+0x8]
         // 00402443: xor edx, edx
         // 00402445: push 0x0
         // 00402447: call 0x4022f2
         // 0040244c: mov ebx, ss:[ebp+0xfffffffffffffffc]
         // 0040244f: leave 
         // 00402450: retn 
      [-]5589e557565383ec1c8955ec8b582c894de8c745f0????????85db7549
         // 00402451: push ebp
         // 00402452: mov ebp, esp
         // 00402454: push edi
         // 00402455: push esi
         // 00402456: push ebx
         // 00402457: sub esp, 0x1c
         // 0040245a: mov ss:[ebp+0xffffffffffffffec], edx
         // 0040245d: mov ebx, ds:[eax+0x2c]
         // 00402460: mov ss:[ebp+0xffffffffffffffe8], ecx
         // 00402463: mov ss:[ebp+0xfffffffffffffff0], 0x0
         // 0040246a: test ebx, ebx
         // 0040246c: jnz 0x4024b7
      [-]83ec0cff700cff15????????83c41089c785c00f84f3000000
         // 0040246e: sub esp, 0xc
         // 00402471: push ds:[eax+0xc]
         // 00402474: call ds:[0x41e014]
         // 0040247a: add esp, 0x10
         // 0040247d: mov edi, eax
         // 0040247f: test eax, eax
         // 00402481: jz 0x40257a
      [-]83ec0c8b1d????????50e88aae0100890424ffd3893c248945f0ff15????????83c410837df0000f84c6000000
         // 00402487: sub esp, 0xc
         // 0040248a: mov ebx, ds:[0x41e014]
         // 00402490: push eax
         // 00402491: call 0x41d320
         // 00402496: mov ss:[esp], eax
         // 00402499: call ebx
         // 0040249b: mov ss:[esp], edi
         // 0040249e: mov ss:[ebp+0xfffffffffffffff0], eax
         // 004024a1: call ds:[0x41e00c]
         // 004024a7: add esp, 0x10
         // 004024aa: cmp ss:[ebp+0xfffffffffffffff0], 0x0
         // 004024ae: jz 0x40257a
      [-]50506a5c53e86fb6010083c41085c07513
         // 004024b7: push eax
         // 004024b8: push eax
         // 004024b9: push 0x5c
         // 004024bb: push ebx
         // 004024bc: call strchr
         // 004024c1: add esp, 0x10
         // 004024c4: test eax, eax
         // 004024c6: jnz 0x4024db
      [-]50506a2253e85eb6010031f683c41085c07461
         // 004024c8: push eax
         // 004024c9: push eax
         // 004024ca: push 0x22
         // 004024cc: push ebx
         // 004024cd: call strchr
         // 004024d2: xor esi, esi
         // 004024d4: add esp, 0x10
         // 004024d7: test eax, eax
         // 004024d9: jz 0x40253c
      [-]fc31c083c9ff89df83ec0cf2aef7d18d4c09ff51ff15????????83c41089c185c07408
         // 004024db: cld 
         // 004024dc: xor eax, eax
         // 004024de: or ecx, 0xffffffffffffffff
         // 004024e1: mov edi, ebx
         // 004024e3: sub esp, 0xc
         // 004024e6: repne scasbb 
         // 004024e8: not ecx
         // 004024ea: lea ecx, ds:[ecx+ecx+0xffffffffffffffff]
         // 004024ee: push ecx
         // 004024ef: call ds:[0x41e008]
         // 004024f5: add esp, 0x10
         // 004024f8: mov ecx, eax
         // 004024fa: test eax, eax
         // 004024fc: jz 0x402506
      [-]89c689c289dfeb2b
         // 004024fe: mov esi, eax
         // 00402500: mov edx, eax
         // 00402502: mov edi, ebx
         // 00402504: jmp 0x402531
      [-]837df000746e
         // 00402506: cmp ss:[ebp+0xfffffffffffffff0], 0x0
         // 0040250a: jz 0x40257a
      [-]83ec0cbb????????ff75f0ff15????????eb56
         // 0040250c: sub esp, 0xc
         // 0040250f: mov ebx, 0x1b
         // 00402514: push ss:[ebp+0xfffffffffffffff0]
         // 00402517: call ds:[0x41e00c]
         // 0040251d: jmp 0x402575
      [-]3c5c7404
         // 0040251f: cmp b1 al, b1 0x5c
         // 00402521: jz 0x402527
      [-]3c227504
         // 00402523: cmp b1 al, b1 0x22
         // 00402525: jnz 0x40252b
      [-]c6025c42
         // 00402527: mov b1 ds:[edx], b1 0x5c
         // 0040252a: inc edx
      [-]8a0747880242
         // 0040252b: mov b1 al, b1 ds:[edi]
         // 0040252d: inc edi
         // 0040252e: mov b1 ds:[edx], b1 al
         // 00402530: inc edx
      [-]8a0784c075e8
         // 00402531: mov b1 al, b1 ds:[edi]
         // 00402533: test b1 al, b1 al
         // 00402535: jnz 0x40251f
      [-]c6020089cb
         // 00402537: mov b1 ds:[edx], b1 0x0
         // 0040253a: mov ebx, ecx
      [-]5368????????ff75e8ff75ece8c3feffff83c41089c385f6740d
         // 0040253c: push ebx
         // 0040253d: push 0x41f1eb
         // 00402542: push ss:[ebp+0xffffffffffffffe8]
         // 00402545: push ss:[ebp+0xffffffffffffffec]
         // 00402548: call 0x402410
         // 0040254d: add esp, 0x10
         // 00402550: mov ebx, eax
         // 00402552: test esi, esi
         // 00402554: jz 0x402563
      [-]83ec0c56ff15????????83c410
         // 00402556: sub esp, 0xc
         // 00402559: push esi
         // 0040255a: call ds:[0x41e00c]
         // 00402560: add esp, 0x10
      [-]837df0007416
         // 00402563: cmp ss:[ebp+0xfffffffffffffff0], 0x0
         // 00402567: jz 0x40257f
      [-]83ec0cff75f0ff15????????
         // 00402569: sub esp, 0xc
         // 0040256c: push ss:[ebp+0xfffffffffffffff0]
         // 0040256f: call ds:[0x41e00c]
      [-]83c410eb05
         // 00402575: add esp, 0x10
         // 00402578: jmp 0x40257f
      [-]bb????????
         // 0040257a: mov ebx, 0x1b
      [-]8d65f489d85b5e5f5dc3
         // 0040257f: lea esp, ss:[ebp+0xfffffffffffffff4]
         // 00402582: mov eax, ebx
         // 00402584: pop ebx
         // 00402585: pop esi
         // 00402586: pop edi
         // 00402587: pop ebp
         // 00402588: retn 
      [-]5589e557565381ec????????31f68b450c8b7d10c745ec????????8b5d14c745e0????????c745e4????????c700????????85ff0f8489040000
         // 00402589: push ebp
         // 0040258a: mov ebp, esp
         // 0040258c: push edi
         // 0040258d: push esi
         // 0040258e: push ebx
         // 0040258f: sub esp, 0x22c
         // 00402595: xor esi, esi
         // 00402597: mov eax, ss:[ebp+0xc]
         // 0040259a: mov edi, ss:[ebp+0x10]
         // 0040259d: mov ss:[ebp+0xffffffffffffffec], 0x0
         // 004025a4: mov ebx, ss:[ebp+0x14]
         // 004025a7: mov ss:[ebp+0xffffffffffffffe0], 0x0
         // 004025ae: mov ss:[ebp+0xffffffffffffffe4], 0x0
         // 004025b5: mov ds:[eax], 0x0
         // 004025bb: test edi, edi
         // 004025bd: jz 0x402a4c
      [-]8b450866be1b00e875fcffff8985????????85c00f846f040000
         // 004025c3: mov eax, ss:[ebp+0x8]
         // 004025c6: mov b2 si, b2 0x1b
         // 004025ca: call 0x402244
         // 004025cf: mov ss:[ebp+0xfffffffffffffdd8], eax
         // 004025d5: test eax, eax
         // 004025d7: jz 0x402a4c
      [-]85db7505
         // 004025dd: test ebx, ebx
         // 004025df: jnz 0x4025e6
      [-]bb????????
         // 004025e1: mov ebx, 0x41f1fb
      [-]83ec0cffb5????????538d5dec68????????6a0053e810feffff83c42089c685c00f85d8030000
         // 004025e6: sub esp, 0xc
         // 004025e9: push ss:[ebp+0xfffffffffffffdd8]
         // 004025ef: push ebx
         // 004025f0: lea ebx, ss:[ebp+0xffffffffffffffec]
         // 004025f3: push 0x41f21d
         // 004025f8: push 0x0
         // 004025fa: push ebx
         // 004025fb: call 0x402410
         // 00402600: add esp, 0x20
         // 00402603: mov esi, eax
         // 00402605: test eax, eax
         // 00402607: jnz 0x4029e5
      [-]8b45ecc785????????????????8945e8
         // 0040260d: mov eax, ss:[ebp+0xffffffffffffffec]
         // 00402610: mov ss:[ebp+0xfffffffffffffddc], 0x0
         // 0040261a: mov ss:[ebp+0xffffffffffffffe8], eax
      [-]8b45e00b45e47420
         // 0040261d: mov eax, ss:[ebp+0xffffffffffffffe0]
         // 00402620: or eax, ss:[ebp+0xffffffffffffffe4]
         // 00402623: jz 0x402645
      [-]8d45ec528d55e068????????5250e8d8fdffff83c41089c685c00f8576030000
         // 00402625: lea eax, ss:[ebp+0xffffffffffffffec]
         // 00402628: push edx
         // 00402629: lea edx, ss:[ebp+0xffffffffffffffe0]
         // 0040262c: push 0x41f22f
         // 00402631: push edx
         // 00402632: push eax
         // 00402633: call 0x402410
         // 00402638: add esp, 0x10
         // 0040263b: mov esi, eax
         // 0040263d: test eax, eax
         // 0040263f: jnz 0x4029bb
      [-]ffb5????????8d55e08d45ec68????????5250e8b3fdffff83c41089c685c00f8551030000
         // 00402645: push ss:[ebp+0xfffffffffffffdd8]
         // 0040264b: lea edx, ss:[ebp+0xffffffffffffffe0]
         // 0040264e: lea eax, ss:[ebp+0xffffffffffffffec]
         // 00402651: push 0x41f232
         // 00402656: push edx
         // 00402657: push eax
         // 00402658: call 0x402410
         // 0040265d: add esp, 0x10
         // 00402660: mov esi, eax
         // 00402662: test eax, eax
         // 00402664: jnz 0x4029bb
      [-]8d55e0508d45ec68????????5250e893fdffff83c41089c685c00f8531030000
         // 0040266a: lea edx, ss:[ebp+0xffffffffffffffe0]
         // 0040266d: push eax
         // 0040266e: lea eax, ss:[ebp+0xffffffffffffffec]
         // 00402671: push 0x41f239
         // 00402676: push edx
         // 00402677: push eax
         // 00402678: call 0x402410
         // 0040267d: add esp, 0x10
         // 00402680: mov esi, eax
         // 00402682: test eax, eax
         // 00402684: jnz 0x4029bb
      [-]8d55e050508d45ec8b4f0452ff770831d2e852fcffff83c41089c685c00f850e030000
         // 0040268a: lea edx, ss:[ebp+0xffffffffffffffe0]
         // 0040268d: push eax
         // 0040268e: push eax
         // 0040268f: lea eax, ss:[ebp+0xffffffffffffffec]
         // 00402692: mov ecx, ds:[edi+0x4]
         // 00402695: push edx
         // 00402696: push ds:[edi+0x8]
         // 00402699: xor edx, edx
         // 0040269b: call 0x4022f2
         // 004026a0: add esp, 0x10
         // 004026a3: mov esi, eax
         // 004026a5: test eax, eax
         // 004026a7: jnz 0x4029bb
      [-]8d55ec508d45e068????????5052e850fdffff83c41085c00f857a030000
         // 004026ad: lea edx, ss:[ebp+0xffffffffffffffec]
         // 004026b0: push eax
         // 004026b1: lea eax, ss:[ebp+0xffffffffffffffe0]
         // 004026b4: push 0x41f260
         // 004026b9: push eax
         // 004026ba: push edx
         // 004026bb: call 0x402410
         // 004026c0: add esp, 0x10
         // 004026c3: test eax, eax
         // 004026c5: jnz 0x402a45
      [-]837f24007451
         // 004026cb: cmp ds:[edi+0x24], 0x0
         // 004026cf: jz 0x402722
      [-]83bd????????007412
         // 004026d1: cmp ss:[ebp+0xfffffffffffffddc], 0x0
         // 004026d8: jz 0x4026ec
      [-]83ec0cffb5????????ff15????????83c410
         // 004026da: sub esp, 0xc
         // 004026dd: push ss:[ebp+0xfffffffffffffddc]
         // 004026e3: call ds:[0x41e00c]
         // 004026e9: add esp, 0x10
      [-]8b4508e850fbffff8985????????85c00f8439030000
         // 004026ec: mov eax, ss:[ebp+0x8]
         // 004026ef: call 0x402244
         // 004026f4: mov ss:[ebp+0xfffffffffffffddc], eax
         // 004026fa: test eax, eax
         // 004026fc: jz 0x402a3b
      [-]508d55ec8d45e068????????5052e8fbfcffff83c41089c685c00f8599020000
         // 00402702: push eax
         // 00402703: lea edx, ss:[ebp+0xffffffffffffffec]
         // 00402706: lea eax, ss:[ebp+0xffffffffffffffe0]
         // 00402709: push 0x41f262
         // 0040270e: push eax
         // 0040270f: push edx
         // 00402710: call 0x402410
         // 00402715: add esp, 0x10
         // 00402718: mov esi, eax
         // 0040271a: test eax, eax
         // 0040271c: jnz 0x4029bb
      [-]89bd????????31f6
         // 00402722: mov ss:[ebp+0xfffffffffffffdd4], edi
         // 00402728: xor esi, esi
      [-]837f24007433
         // 0040272a: cmp ds:[edi+0x24], 0x0
         // 0040272e: jz 0x402763
      [-]ffb5????????8d45e08d55ec68????????5052e8c8fcffff83c41089c685c00f8566020000
         // 00402730: push ss:[ebp+0xfffffffffffffddc]
         // 00402736: lea eax, ss:[ebp+0xffffffffffffffe0]
         // 00402739: lea edx, ss:[ebp+0xffffffffffffffec]
         // 0040273c: push 0x41f291
         // 00402741: push eax
         // 00402742: push edx
         // 00402743: call 0x402410
         // 00402748: add esp, 0x10
         // 0040274b: mov esi, eax
         // 0040274d: test eax, eax
         // 0040274f: jnz 0x4029bb
      [-]8d4de08d55ec8b85????????eb19
         // 00402755: lea ecx, ss:[ebp+0xffffffffffffffe0]
         // 00402758: lea edx, ss:[ebp+0xffffffffffffffec]
         // 0040275b: mov eax, ss:[ebp+0xfffffffffffffdd4]
         // 00402761: jmp 0x40277c
      [-]8b4728a8517421
         // 00402763: mov eax, ds:[edi+0x28]
         // 00402766: test b1 al, b1 0x51
         // 00402768: jz 0x40278b
      [-]837f2c007504
         // 0040276a: cmp ds:[edi+0x2c], 0x0
         // 0040276e: jnz 0x402774
      [-]a801740f
         // 00402770: test b1 al, b1 0x1
         // 00402772: jz 0x402783
      [-]8d4de08d55ec89f8
         // 00402774: lea ecx, ss:[ebp+0xffffffffffffffe0]
         // 00402777: lea edx, ss:[ebp+0xffffffffffffffec]
         // 0040277a: mov eax, edi
      [-]e8d0fcffff89c6
         // 0040277c: call 0x402451
         // 00402781: mov esi, eax
      [-]85f60f8530020000
         // 00402783: test esi, esi
         // 00402785: jnz 0x4029bb
      [-]8b95????????8b421c85c07420
         // 0040278b: mov edx, ss:[ebp+0xfffffffffffffdd4]
         // 00402791: mov eax, ds:[edx+0x1c]
         // 00402794: test eax, eax
         // 00402796: jz 0x4027b8
      [-]508d55ec8d45e068????????5052e865fcffff83c41089c685c00f8503020000
         // 00402798: push eax
         // 00402799: lea edx, ss:[ebp+0xffffffffffffffec]
         // 0040279c: lea eax, ss:[ebp+0xffffffffffffffe0]
         // 0040279f: push 0x41f2b9
         // 004027a4: push eax
         // 004027a5: push edx
         // 004027a6: call 0x402410
         // 004027ab: add esp, 0x10
         // 004027ae: mov esi, eax
         // 004027b0: test eax, eax
         // 004027b2: jnz 0x4029bb
      [-]8b85????????8b5820eb24
         // 004027b8: mov eax, ss:[ebp+0xfffffffffffffdd4]
         // 004027be: mov ebx, ds:[eax+0x20]
         // 004027c1: jmp 0x4027e7
      [-]ff338d55e08d45ec68????????5250e839fcffff83c41089c685c00f85d7010000
         // 004027c3: push ds:[ebx]
         // 004027c5: lea edx, ss:[ebp+0xffffffffffffffe0]
         // 004027c8: lea eax, ss:[ebp+0xffffffffffffffec]
         // 004027cb: push 0x41f2cc
         // 004027d0: push edx
         // 004027d1: push eax
         // 004027d2: call 0x402410
         // 004027d7: add esp, 0x10
         // 004027da: mov esi, eax
         // 004027dc: test eax, eax
         // 004027de: jnz 0x4029bb
      [-]85db75d8
         // 004027e7: test ebx, ebx
         // 004027e9: jnz 0x4027c3
      [-]85f60f85c8010000
         // 004027eb: test esi, esi
         // 004027ed: jnz 0x4029bb
      [-]8d55e0508d45ec68????????5250e80afcffff83c41089c685c00f85a8010000
         // 004027f3: lea edx, ss:[ebp+0xffffffffffffffe0]
         // 004027f6: push eax
         // 004027f7: lea eax, ss:[ebp+0xffffffffffffffec]
         // 004027fa: push 0x41f2d1
         // 004027ff: push edx
         // 00402800: push eax
         // 00402801: call 0x402410
         // 00402806: add esp, 0x10
         // 00402809: mov esi, eax
         // 0040280b: test eax, eax
         // 0040280d: jnz 0x4029bb
      [-]f64728030f84e2000000
         // 00402813: test b1 ds:[edi+0x28], b1 0x3
         // 00402817: jz 0x4028ff
      [-]8b95????????5050ff720c68????????e8b7e1000083c41085c07408
         // 0040281d: mov edx, ss:[ebp+0xfffffffffffffdd4]
         // 00402823: push eax
         // 00402824: push eax
         // 00402825: push ds:[edx+0xc]
         // 00402828: push 0x41f1e9
         // 0040282d: call curl_strequal
         // 00402832: add esp, 0x10
         // 00402835: test eax, eax
         // 00402837: jz 0x402841
      [-]8b1ddc524200eb1a
         // 00402839: mov ebx, ds:[_iob]
         // 0040283f: jmp 0x40285b
      [-]50508b85????????68????????ff700ce8cab1010083c41089c3
         // 00402841: push eax
         // 00402842: push eax
         // 00402843: mov eax, ss:[ebp+0xfffffffffffffdd4]
         // 00402849: push 0x41f1c4
         // 0040284e: push ds:[eax+0xc]
         // 00402851: call fopen
         // 00402856: add esp, 0x10
         // 00402859: mov ebx, eax
      [-]85db7470
         // 0040285b: test ebx, ebx
         // 0040285d: jz 0x4028cf
      [-]3b1ddc524200744b
         // 0040285f: cmp ebx, ds:[_iob]
         // 00402865: jz 0x4028b2
      [-]83ec0c53e800b201008b95????????5b8d45e05e8b4a0c50ba????????6a00e9b1000000
         // 00402867: sub esp, 0xc
         // 0040286a: push ebx
         // 0040286b: call fclose
         // 00402870: mov edx, ss:[ebp+0xfffffffffffffdd4]
         // 00402876: pop ebx
         // 00402877: lea eax, ss:[ebp+0xffffffffffffffe0]
         // 0040287a: pop esi
         // 0040287b: mov ecx, ds:[edx+0xc]
         // 0040287e: push eax
         // 0040287f: mov edx, 0x3
         // 00402884: push 0x0
         // 00402886: jmp 0x40293c
      [-]8d55e051518d8d????????52ba????????508d45ece84dfa
         // 0040288b: lea edx, ss:[ebp+0xffffffffffffffe0]
         // 0040288e: push ecx
         // 0040288f: push ecx
         // 00402890: lea ecx, ss:[ebp+0xfffffffffffffde0]
         // 00402896: push edx
         // 00402897: mov edx, 0x1
         // 0040289c: push eax
         // 0040289d: lea eax, ss:[ebp+0xffffffffffffffec]
         // 004028a0: call 0x4022f2
         // 004028a5: add esp, 0x10
         // 004028a8: mov esi, eax
         // 004028aa: test eax, eax
         // 004028ac: jnz 0x402949

  }
  condition:
    all of them
}
