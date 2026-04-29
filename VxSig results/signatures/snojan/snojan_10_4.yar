rule snojan_10_4 {
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
      [-]5589e55383ec2068????????e8bfcc010083c40ce8dfbc0100e8eabd010083ec0c8d45f4c745f4????????508d45f88b1d????????535068????????68????????e81ac90100a1????????83c420
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
      [-]e829c901008b15????????8910e8b4bd010083e4f0e894020000e82fc90100538b08518b15????????52a1????????50e8f9020000
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
      [-]e822c90100891c24e84acc0100
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
      [-]50506a006a08e834c8010083c41083f8010f84d6000000
         // 00401171: push eax
         // 00401172: push eax
         // 00401173: push 0x0
         // 00401175: push 0x8
         // 00401177: call signal
         // 0040117c: add esp, 0x10
         // 0040117f: cmp eax, 0x1
         // 00401182: jz 0x40125e
      [-]0f8590000000
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
      [-]83ec0c6a04ffd083c8ff83c410eba7
         // 004011dc: sub esp, 0xc
         // 004011df: push 0x4
         // 004011e1: call eax
         // 004011e3: or eax, 0xffffffffffffffff
         // 004011e6: add esp, 0x10
         // 004011e9: jmp 0x401192
      [-]e97affffff
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
      [-]50506a016a08e847c7010083c41083c8ff
         // 0040125e: push eax
         // 0040125f: push eax
         // 00401260: push 0x1
         // 00401262: push 0x8
         // 00401264: call signal
         // 00401269: add esp, 0x10
         // 0040126c: or eax, 0xffffffffffffffff
      [-]0f841bffffff
         // 00401271: jz 0x401192
      [-]e8acbb010083c8ffe90effffff
         // 00401277: call 0x41ce28
         // 0040127c: or eax, 0xffffffffffffffff
         // 0040127f: jmp 0x401192
      [-]5589e583ec08a1????????
         // 00401290: push ebp
         // 00401291: mov ebp, esp
         // 00401293: sub esp, 0x8
         // 00401296: mov eax, ds:[0x41e03c]
      [-]83ec0c68????????e864ca0100
         // 0040129f: sub esp, 0xc
         // 004012a2: push 0x41f000
         // 004012a7: call GetModuleHandleA
      [-]505068????????52e859ca01005a59
         // 004012ba: push eax
         // 004012bb: push eax
         // 004012bc: push 0x41f00d
         // 004012c1: push edx
         // 004012c2: call GetProcAddress
         // 004012c7: pop edx
         // 004012c8: pop ecx
      [-]83ec0c68????????ffd083c410
         // 004012cd: sub esp, 0xc
         // 004012d0: push 0x41e03c
         // 004012d5: call eax
         // 004012d7: add esp, 0x10
      [-]5589e583ec08a1????????8b00
         // 004012f0: push ebp
         // 004012f1: mov ebp, esp
         // 004012f3: sub esp, 0x8
         // 004012f6: mov eax, ds:[0x41e004]
         // 004012fb: mov eax, ds:[eax]
      [-]ffd0a1????????83c004a3????????8b00
         // 00401301: call eax
         // 00401303: mov eax, ds:[0x41e004]
         // 00401308: add eax, 0x4
         // 0040130b: mov ds:[0x41e004], eax
         // 00401310: mov eax, ds:[eax]
      [-]5589e556538b0d????????
         // 00401320: push ebp
         // 00401321: mov ebp, esp
         // 00401323: push esi
         // 00401324: push ebx
         // 00401325: mov ecx, ds:[0x41e000]
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
      [-]8d349d????????908d742600
         // 00401354: lea esi, ds:[0x41de20+ebx*0x4]
         // 0040135b: nop 
         // 0040135c: lea esi, ds:[esi+0x0]
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
      [-]8d43018b1485????????
         // 00401385: lea eax, ds:[ebx+0x1]
         // 00401388: mov edx, ds:[0x41de20+eax*0x4]
      [-]8d4c240483e4f0ff71fc5589e5575653518d9d????????81ec????????8b7904e85bffffff5068????????536a00e85dc901005068????????53e841c6010083c410
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
      [-]0f84e5020000
         // 004013e6: jz 0x4016d1
      [-]506a026a0053e849c60100891c24e831c6010083c40ca3????????6a006a0053e82fc6010058ff35????????e833c60100a3????????53ff35????????6a0150e82fc6010083c41453e836c601000f31c70424????????
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
      [-]e844c6010031f3331f31c3891c24
         // 00401447: call time
         // 0040144c: xor ebx, esi
         // 0040144e: xor ebx, ds:[edi]
         // 00401450: xor ebx, eax
         // 00401452: mov ss:[esp], ebx
      [-]e824c601008b3d????????
         // 00401457: call srand
         // 0040145c: mov edi, ds:[0x423010]
      [-]8b35????????83c410eb25
         // 00401465: mov esi, ds:[0x423020]
         // 0040146b: add esp, 0x10
         // 0040146e: jmp 0x401495
      [-]508d041e6a0a68????????50e85fc5010083c410
         // 00401470: push eax
         // 00401471: lea eax, ds:[esi+ebx]
         // 00401474: push 0xa
         // 00401476: push 0x41f108
         // 0040147b: push eax
         // 0040147c: call memcmp
         // 00401481: add esp, 0x10
      [-]8d430aa3????????
         // 00401488: lea eax, ds:[ebx+0xa]
         // 0040148b: mov ds:[0x423030], eax
      [-]39fb7cd7
         // 00401495: cmp ebx, edi
         // 00401497: jl 0x401470
      [-]0f852b020000
         // 004014a0: jnz 0x4016d1
      [-]83ec0c68????????e80dc60100c70424????????e801c601008b0ddc52420083
         // 004014a6: sub esp, 0xc
         // 004014a9: push 0x41f027
         // 004014ae: call puts
         // 004014b3: mov ss:[esp], 0x41f044
         // 004014ba: call puts
         // 004014bf: mov ecx, ds:[_iob]
         // 004014c8: add esp, 0x10
      [-]c410898d????????
         // 004014cb: mov ss:[ebp+0xfffffffffffffb9c], ecx
      [-]8d75cd68????????e85ac8010083c40ce8b2c50100
         // 004014d9: lea esi, ss:[ebp+0xffffffffffffffcd]
         // 004014dc: push 0x7530
         // 004014e1: call Sleep
         // 004014e6: add esp, 0xc
         // 004014e9: call rand
      [-]99f7f98d7a01
         // 004014f5: cdq 
         // 004014f6: idiv ecx
         // 004014f8: lea edi, ds:[edx+0x1]
      [-]e8a0c50100
         // 004014fb: call rand
      [-]99f7f98a8224f14100884433ff4383fb1175e1
         // 00401507: cdq 
         // 00401508: idiv ecx
         // 0040150a: mov b1 al, b1 ds:[edx+0x41f124]
         // 00401510: mov b1 ds:[ebx+esi+0xffffffffffffffff], b1 al
         // 00401514: inc ebx
         // 00401515: cmp ebx, 0x11
         // 00401518: jnz 0x4014fb
      [-]c645dd00538d5da55668????????53e8d2c4010083c40c575368????????e873c501008b1d????????
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
      [-]031d????????83c410
         // 00401548: add ebx, ds:[0x423020]
         // 0040154e: add esp, 0x10
      [-]e84ac5010088441eff4683fe1175f1
         // 00401551: call rand
         // 00401556: mov b1 ds:[esi+ebx+0xffffffffffffffff], b1 al
         // 0040155a: inc esi
         // 0040155b: cmp esi, 0x11
         // 0040155e: jnz 0x401551
      [-]8d75a5515168????????56e8b0c40100
         // 00401560: lea esi, ss:[ebp+0xffffffffffffffa5]
         // 00401563: push ecx
         // 00401564: push ecx
         // 00401565: push 0x41f086
         // 0040156a: push esi
         // 0040156b: call fopen
      [-]0f8432010000
         // 0040157c: jz 0x4016b4
      [-]53ff35????????6a01ff35????????e85ac40100891c24e8d2c40100c745ec????????c745e8????????c70424????????e84a08000083c40c578d7dde68????????57e836c4010083c40c8d5dec6a11568d75e86a0a68????????6a015653e85315000083c41c6a11576a0468????????6a015653e83d15000083c41c6a1168????????6a0468????????6a015653e82315000083c420e896080000
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
      [-]5268????????68????????50e86d07000083c40cff75ec68????????53e85c07000083c40c6a016a2953e84f070000891c24e8af05000083c410
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
      [-]83ec0c50e84d1c000083c40c5068????????ffb5????????e891c30100
         // 00401662: sub esp, 0xc
         // 00401665: push eax
         // 00401666: call curl_easy_strerror
         // 0040166b: add esp, 0xc
         // 0040166e: push eax
         // 0040166f: push 0x41f0ce
         // 00401674: push ss:[ebp+0xfffffffffffffb9c]
         // 0040167a: call fprintf
      [-]83c410eb2b
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
      [-]83ec0c8d45a550e836bc0100
         // 0040169e: sub esp, 0xc
         // 004016a1: lea eax, ss:[ebp+0xffffffffffffffa5]
         // 004016a4: push eax
         // 004016a5: call _unlink
      [-]0f8415feffff
         // 004016b6: jz 0x4014d1
      [-]83ec0c68????????e8f7c3010083c410e900feffff
         // 004016bc: sub esp, 0xc
         // 004016bf: push 0x41f0ee
         // 004016c4: call puts
         // 004016c9: add esp, 0x10
         // 004016cc: jmp 0x4014d1
      [-]595b5e5f5d8d61fcc3
         // 004016d9: pop ecx
         // 004016da: pop ebx
         // 004016db: pop esi
         // 004016dc: pop edi
         // 004016dd: pop ebp
         // 004016de: lea esp, ds:[ecx+0xfffffffffffffffc]
         // 004016e1: retn 
      [-]80b8e1020000007509
         // 004016f6: cmp b1 ds:[eax+0x2e1], b1 0x0
         // 004016fd: jnz 0x401708
      [-]515168????????eb1a
         // 004016ff: push ecx
         // 00401700: push ecx
         // 00401701: push 0x41f164
         // 00401706: jmp 0x401722
      [-]52525150e86ad0000083c4108906
         // 00401708: push edx
         // 00401709: push edx
         // 0040170a: push ecx
         // 0040170b: push eax
         // 0040170c: call 0x40e77b
         // 00401711: add esp, 0x10
         // 00401714: mov ds:[esi], eax
      [-]505068????????
         // 0040171b: push eax
         // 0040171c: push eax
         // 0040171d: push 0x41f17e
      [-]53e821cb0000
         // 00401722: push ebx
         // 00401723: call 0x40e249
      [-]5b5e5dc3
         // 00401735: pop ebx
         // 00401736: pop esi
         // 00401737: pop ebp
         // 00401738: retn 
      [-]5589e55383ec148d4df08d55f88b45088b5d14c745f0????????e88cffffff
         // 00401739: push ebp
         // 0040173a: mov ebp, esp
         // 0040173c: push ebx
         // 0040173d: sub esp, 0x14
         // 00401740: lea ecx, ss:[ebp+0xfffffffffffffff0]
         // 00401743: lea edx, ss:[ebp+0xfffffffffffffff8]
         // 00401746: mov eax, ss:[ebp+0x8]
         // 00401749: mov ebx, ss:[ebp+0x14]
         // 0040174c: mov ss:[ebp+0xfffffffffffffff0], 0x0
         // 00401753: call 0x4016e4
      [-]83ec0c8d45f4c703????????50ff7510ff750cff75f8ff75f0e8c6c600008b55f483c42083faff7507
         // 0040175c: sub esp, 0xc
         // 0040175f: lea eax, ss:[ebp+0xfffffffffffffff4]
         // 00401762: mov ds:[ebx], 0x0
         // 00401768: push eax
         // 00401769: push ss:[ebp+0x10]
         // 0040176c: push ss:[ebp+0xc]
         // 0040176f: push ss:[ebp+0xfffffffffffffff8]
         // 00401772: push ss:[ebp+0xfffffffffffffff0]
         // 00401775: call 0x40de40
         // 0040177a: mov edx, ss:[ebp+0xfffffffffffffff4]
         // 0040177d: add esp, 0x20
         // 00401780: cmp edx, 0xffffffffffffffff
         // 00401783: jnz 0x40178c
      [-]b051eb02
         // 00401794: mov b1 al, b1 0x51
         // 00401796: jmp 0x40179a
      [-]8b5dfcc9c3
         // 0040179a: mov ebx, ss:[ebp+0xfffffffffffffffc]
         // 0040179d: leave 
         // 0040179e: retn 
      [-]5589e55383ec148d55f88d4df08b45088b5d14e82dffffff
         // 0040179f: push ebp
         // 004017a0: mov ebp, esp
         // 004017a2: push ebx
         // 004017a3: sub esp, 0x14
         // 004017a6: lea edx, ss:[ebp+0xfffffffffffffff8]
         // 004017a9: lea ecx, ss:[ebp+0xfffffffffffffff0]
         // 004017ac: mov eax, ss:[ebp+0x8]
         // 004017af: mov ebx, ss:[ebp+0x14]
         // 004017b2: call 0x4016e4
      [-]83ec0c8d45f4c703????????50ff7510ff750cff75f8ff75f0e804c8000083c420
         // 004017bd: sub esp, 0xc
         // 004017c0: lea eax, ss:[ebp+0xfffffffffffffff4]
         // 004017c3: mov ds:[ebx], 0x0
         // 004017c9: push eax
         // 004017ca: push ss:[ebp+0x10]
         // 004017cd: push ss:[ebp+0xc]
         // 004017d0: push ss:[ebp+0xfffffffffffffff8]
         // 004017d3: push ss:[ebp+0xfffffffffffffff0]
         // 004017d6: call 0x40dfdf
         // 004017db: add esp, 0x20
      [-]8b45f48903
         // 004017e4: mov eax, ss:[ebp+0xfffffffffffffff4]
         // 004017e7: mov ds:[ebx], eax
      [-]8b5dfcc9c3
         // 004017eb: mov ebx, ss:[ebp+0xfffffffffffffffc]
         // 004017ee: leave 
         // 004017ef: retn 
      [-]5589e557565383ec1c8b450c8b4d08
         // 004017f0: push ebp
         // 004017f1: mov ebp, esp
         // 004017f3: push edi
         // 004017f4: push esi
         // 004017f5: push ebx
         // 004017f6: sub esp, 0x1c
         // 004017f9: mov eax, ss:[ebp+0xc]
         // 004017fc: mov ecx, ss:[ebp+0x8]
      [-]83e00483e7018b91????????f7df83e71083f80119c083e2cff7d083e02009d709c789b9????????f7c7????????0f85e5000000
         // 00401801: and eax, 0x4
         // 00401804: and edi, 0x1
         // 00401807: mov edx, ds:[ecx+0xf4]
         // 0040180d: neg edi
         // 0040180f: and edi, 0x10
         // 00401812: cmp eax, 0x1
         // 00401815: sbb eax, eax
         // 00401817: and edx, 0xffffffffffffffcf
         // 0040181a: not eax
         // 0040181c: and eax, 0x20
         // 0040181f: or edi, edx
         // 00401821: or edi, eax
         // 00401823: mov ds:[ecx+0xf4], edi
         // 00401829: test edi, 0x10
         // 0040182f: jnz 0x40191a
      [-]8b81????????8945f0
         // 00401835: mov eax, ds:[ecx+0x8550]
         // 0040183b: mov ss:[ebp+0xfffffffffffffff0], eax
      [-]0f84d4000000
         // 00401840: jz 0x40191a
      [-]8b91????????8bb1????????8955ecc781????????????????8945e8
         // 00401846: mov edx, ds:[ecx+0x8558]
         // 0040184c: mov esi, ds:[ecx+0x8554]
         // 00401852: mov ss:[ebp+0xffffffffffffffec], edx
         // 00401855: mov ds:[ecx+0x8550], 0x0
         // 0040185f: mov ss:[ebp+0xffffffffffffffe8], eax
      [-]81fe????????7605
         // 00401864: cmp esi, 0x4000
         // 0040186a: jbe 0x401871
      [-]bb????????
         // 0040186c: mov ebx, 0x4000
      [-]538b4d08ff75e8ff75ecff7108e86cca000083c4108945e4
         // 00401871: push ebx
         // 00401872: mov ecx, ss:[ebp+0x8]
         // 00401875: push ss:[ebp+0xffffffffffffffe8]
         // 00401878: push ss:[ebp+0xffffffffffffffec]
         // 0040187b: push ds:[ecx+0x8]
         // 0040187e: call 0x40e2ef
         // 00401883: add esp, 0x10
         // 00401886: mov ss:[ebp+0xffffffffffffffe4], eax
      [-]8b55088b82????????
         // 0040188d: mov edx, ss:[ebp+0x8]
         // 00401890: mov eax, ds:[edx+0x8550]
      [-]39de745b
         // 0040189a: cmp esi, ebx
         // 0040189c: jz 0x4018f9
      [-]51515650ff15????????83c410
         // 0040189e: push ecx
         // 0040189f: push ecx
         // 004018a0: push esi
         // 004018a1: push eax
         // 004018a2: call ds:[0x41e010]
         // 004018a8: add esp, 0x10
      [-]8b4d0883ec0cffb1????????ff15????????8b4508c745e4????????c780????????????????eb1d
         // 004018af: mov ecx, ss:[ebp+0x8]
         // 004018b2: sub esp, 0xc
         // 004018b5: push ds:[ecx+0x8550]
         // 004018bb: call ds:[0x41e00c]
         // 004018c1: mov eax, ss:[ebp+0x8]
         // 004018c4: mov ss:[ebp+0xffffffffffffffe4], 0x1b
         // 004018cb: mov ds:[eax+0x8550], 0x0
         // 004018d5: jmp 0x4018f4
      [-]8b55088982????????5256ff75e850e825c201008b4d0889b1????????
         // 004018d7: mov edx, ss:[ebp+0x8]
         // 004018da: mov ds:[edx+0x8550], eax
         // 004018e0: push edx
         // 004018e1: push esi
         // 004018e2: push ss:[ebp+0xffffffffffffffe8]
         // 004018e5: push eax
         // 004018e6: call memcpy
         // 004018eb: mov ecx, ss:[ebp+0x8]
         // 004018ee: mov ds:[ecx+0x8554], esi
      [-]83c410eb0c
         // 004018f4: add esp, 0x10
         // 004018f7: jmp 0x401905
      [-]29de7408
         // 004018f9: sub esi, ebx
         // 004018fb: jz 0x401905
      [-]015de8e95dffffff
         // 004018fd: add ss:[ebp+0xffffffffffffffe8], ebx
         // 00401900: jmp 0x401862
      [-]83ec0cff75f0ff15????????83c410837de4007525
         // 00401905: sub esp, 0xc
         // 00401908: push ss:[ebp+0xfffffffffffffff0]
         // 0040190b: call ds:[0x41e00c]
         // 00401911: add esp, 0x10
         // 00401914: cmp ss:[ebp+0xffffffffffffffe4], 0x0
         // 00401918: jnz 0x40193f
      [-]83e730c745e4????????83ff307416
         // 0040191a: and edi, 0x30
         // 0040191d: mov ss:[ebp+0xffffffffffffffe4], 0x0
         // 00401924: cmp edi, 0x30
         // 00401927: jz 0x40193f
      [-]53536a01ff7508e80a890000c745e4????????83c410
         // 00401929: push ebx
         // 0040192a: push ebx
         // 0040192b: push 0x1
         // 0040192d: push ss:[ebp+0x8]
         // 00401930: call 0x40a23f
         // 00401935: mov ss:[ebp+0xffffffffffffffe4], 0x0
         // 0040193c: add esp, 0x10
      [-]8b45e48d65f45b5e5f5dc3
         // 0040193f: mov eax, ss:[ebp+0xffffffffffffffe4]
         // 00401942: lea esp, ss:[ebp+0xfffffffffffffff4]
         // 00401945: pop ebx
         // 00401946: pop esi
         // 00401947: pop edi
         // 00401948: pop ebp
         // 00401949: retn 
      [-]5589e556538b75088b86????????
         // 0040194a: push ebp
         // 0040194b: mov ebp, esp
         // 0040194d: push esi
         // 0040194e: push ebx
         // 0040194f: mov esi, ss:[ebp+0x8]
         // 00401952: mov eax, ds:[esi+0x8614]
      [-]83ec0c50ff15????????c786????????????????83c410
         // 0040195c: sub esp, 0xc
         // 0040195f: push eax
         // 00401960: call ds:[0x41e00c]
         // 00401966: mov ds:[esi+0x8614], 0x0
         // 00401970: add esp, 0x10
      [-]83ec0cc786????????????????8d9e????????56e8a52b0000893424e89827000083c40c68????????6a0053e85cc10100891c24e84828000083c40c8d86????????68????????6a0050e83ec10100838e????????10c786????????????????c786????????????????83c4108d65f85b5e5dc3
         // 00401973: sub esp, 0xc
         // 00401976: mov ds:[esi+0x8618], 0x0
         // 00401980: lea ebx, ds:[esi+0x118]
         // 00401986: push esi
         // 00401987: call 0x404531
         // 0040198c: mov ss:[esp], esi
         // 0040198f: call 0x40412c
         // 00401994: add esp, 0xc
         // 00401997: push 0x2d0
         // 0040199c: push 0x0
         // 0040199e: push ebx
         // 0040199f: call memset
         // 004019a4: mov ss:[esp], ebx
         // 004019a7: call 0x4041f4
         // 004019ac: add esp, 0xc
         // 004019af: lea eax, ds:[esi+0x408]
         // 004019b5: push 0x110
         // 004019ba: push 0x0
         // 004019bc: push eax
         // 004019bd: call memset
         // 004019c2: or ds:[esi+0x440], 0x10
         // 004019c9: mov ds:[esi+0x8538], 0xffffffffffffffff
         // 004019d3: mov ds:[esi+0x853c], 0xffffffffffffffff
         // 004019dd: add esp, 0x10
         // 004019e0: lea esp, ss:[ebp+0xfffffffffffffff8]
         // 004019e3: pop ebx
         // 004019e4: pop esi
         // 004019e5: pop ebp
         // 004019e6: retn 
      [-]5589e55653508b75085068????????6a01ff15????????83c410
         // 004019e7: push ebp
         // 004019e8: mov ebp, esp
         // 004019ea: push esi
         // 004019eb: push ebx
         // 004019ec: push eax
         // 004019ed: mov esi, ss:[ebp+0x8]
         // 004019f0: push eax
         // 004019f1: push 0x8710
         // 004019f6: push 0x1
         // 004019f8: call ds:[0x41e018]
         // 004019fe: add esp, 0x10
      [-]0f84c8010000
         // 00401a07: jz 0x401bd5
      [-]83ec0c68????????ff15????????83c4108983????????
         // 00401a0d: sub esp, 0xc
         // 00401a10: push 0x100
         // 00401a15: call ds:[0x41e008]
         // 00401a1b: add esp, 0x10
         // 00401a1e: mov ds:[ebx+0x52c], eax
      [-]0f847b010000
         // 00401a26: jz 0x401ba7
      [-]c783????????????????50505653e8173a000083c410
         // 00401a2c: mov ds:[ebx+0x530], 0x100
         // 00401a36: push eax
         // 00401a37: push eax
         // 00401a38: push esi
         // 00401a39: push ebx
         // 00401a3a: call 0x405456
         // 00401a3f: add esp, 0x10
      [-]0f855d010000
         // 00401a44: jnz 0x401ba7
      [-]8b86????????8b96????????8983????????8a8638040000c783????????????????c783????????????????888338040000
         // 00401a4a: mov eax, ds:[esi+0x440]
         // 00401a50: mov edx, ds:[esi+0x400]
         // 00401a56: mov ds:[ebx+0x440], eax
         // 00401a5c: mov b1 al, b1 ds:[esi+0x438]
         // 00401a62: mov ds:[ebx+0x518], 0x0
         // 00401a6c: mov ds:[ebx+0x528], 0x0
         // 00401a76: mov b1 ds:[ebx+0x438], b1 al
      [-]0fb6861502000050ffb3????????ff720456e841bf000083c4108983????????
         // 00401a80: movzx eax, b1 ds:[esi+0x215]
         // 00401a87: push eax
         // 00401a88: push ds:[ebx+0x400]
         // 00401a8e: push ds:[edx+0x4]
         // 00401a91: push esi
         // 00401a92: call 0x40d9d8
         // 00401a97: add esp, 0x10
         // 00401a9a: mov ds:[ebx+0x400], eax
      [-]0f84ff000000
         // 00401aa2: jz 0x401ba7
      [-]8b86????????
         // 00401aa8: mov eax, ds:[esi+0x3f8]
      [-]83ec0c50e843c3000083c4108983????????
         // 00401ab2: sub esp, 0xc
         // 00401ab5: push eax
         // 00401ab6: call 0x40ddfe
         // 00401abb: add esp, 0x10
         // 00401abe: mov ds:[ebx+0x3f8], eax
      [-]0f84db000000
         // 00401ac6: jz 0x401ba7
      [-]8b86????????
         // 00401acc: mov eax, ds:[esi+0x3e8]
      [-]83ec0c50ff15????????83c4108983????????
         // 00401ad6: sub esp, 0xc
         // 00401ad9: push eax
         // 00401ada: call ds:[0x41e014]
         // 00401ae0: add esp, 0x10
         // 00401ae3: mov ds:[ebx+0x3e8], eax
      [-]0f84b6000000
         // 00401aeb: jz 0x401ba7
      [-]c683ec03000001
         // 00401af1: mov b1 ds:[ebx+0x3ec], b1 0x1
      [-]8b86????????
         // 00401af8: mov eax, ds:[esi+0x3f0]
      [-]83ec0c50ff15????????83c4108983????????
         // 00401b02: sub esp, 0xc
         // 00401b05: push eax
         // 00401b06: call ds:[0x41e014]
         // 00401b0c: add esp, 0x10
         // 00401b0f: mov ds:[ebx+0x3f0], eax
      [-]0f848a000000
         // 00401b17: jz 0x401ba7
      [-]c683f403000001
         // 00401b1d: mov b1 ds:[ebx+0x3f4], b1 0x1
      [-]c783????????????????e9a0000000
         // 00401b26: mov ds:[ebx+0x870c], 0xffffffffc0dedbad
         // 00401b30: jmp 0x401bd5
      [-]83ec0c50ff15????????c783????????????????83c410
         // 00401b35: sub esp, 0xc
         // 00401b38: push eax
         // 00401b39: call ds:[0x41e00c]
         // 00401b3f: mov ds:[ebx+0x52c], 0x0
         // 00401b49: add esp, 0x10
      [-]8b83????????
         // 00401b4c: mov eax, ds:[ebx+0x3e8]
      [-]83ec0c50ff15????????c783????????????????83c410
         // 00401b56: sub esp, 0xc
         // 00401b59: push eax
         // 00401b5a: call ds:[0x41e00c]
         // 00401b60: mov ds:[ebx+0x3e8], 0x0
         // 00401b6a: add esp, 0x10
      [-]8b83????????
         // 00401b6d: mov eax, ds:[ebx+0x3f0]
      [-]83ec0c50ff15????????c783????????????????83c410
         // 00401b77: sub esp, 0xc
         // 00401b7a: push eax
         // 00401b7b: call ds:[0x41e00c]
         // 00401b81: mov ds:[ebx+0x3f0], 0x0
         // 00401b8b: add esp, 0x10
      [-]83ec0c53e895250000891c24ff15????????
         // 00401b8e: sub esp, 0xc
         // 00401b91: push ebx
         // 00401b92: call 0x40412c
         // 00401b97: mov ss:[esp], ebx
         // 00401b9a: call ds:[0x41e00c]
      [-]83c410eb2e
         // 00401ba2: add esp, 0x10
         // 00401ba5: jmp 0x401bd5
      [-]83ec0cffb3????????e805c200008b83????????83c410c783????????????????
         // 00401ba7: sub esp, 0xc
         // 00401baa: push ds:[ebx+0x3f8]
         // 00401bb0: call curl_slist_free_all
         // 00401bb5: mov eax, ds:[ebx+0x52c]
         // 00401bbb: add esp, 0x10
         // 00401bbe: mov ds:[ebx+0x3f8], 0x0
      [-]0f8565ffffff
         // 00401bca: jnz 0x401b35
      [-]e977ffffff
         // 00401bd0: jmp 0x401b4c
      [-]8d65f85b5e5dc3
         // 00401bd5: lea esp, ss:[ebp+0xfffffffffffffff8]
         // 00401bd8: pop ebx
         // 00401bd9: pop esi
         // 00401bda: pop ebp
         // 00401bdb: retn 
      [-]5589e583ec1cff7510ff750cff75088d45148945fce861a80000c9c3
         // 00401bdc: push ebp
         // 00401bdd: mov ebp, esp
         // 00401bdf: sub esp, 0x1c
         // 00401be2: push ss:[ebp+0x10]
         // 00401be5: push ss:[ebp+0xc]
         // 00401be8: push ss:[ebp+0x8]
         // 00401beb: lea eax, ss:[ebp+0x14]
         // 00401bee: mov ss:[ebp+0xfffffffffffffffc], eax
         // 00401bf1: call 0x40c457
         // 00401bf6: leave 
         // 00401bf7: retn 
      [-]5589e58b4508
         // 00401bf8: push ebp
         // 00401bf9: mov ebp, esp
         // 00401bfb: mov eax, ss:[ebp+0x8]
      [-]5de961810000
         // 00401c02: pop ebp
         // 00401c03: jmp 0x409d69
      [-]5589e557565383ec1c
         // 00401c0a: push ebp
         // 00401c0b: mov ebp, esp
         // 00401c0d: push edi
         // 00401c0e: push esi
         // 00401c0f: push ebx
         // 00401c10: sub esp, 0x1c
      [-]837d08000f8476010000
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
      [-]8b55088b4244
         // 00401c3f: mov edx, ss:[ebp+0x8]
         // 00401c42: mov eax, ds:[edx+0x44]
      [-]53536a036a01e88ca5000083c410
         // 00401c4b: push ebx
         // 00401c4c: push ebx
         // 00401c4d: push 0x3
         // 00401c4f: push 0x1
         // 00401c51: call 0x40c1e2
         // 00401c56: add esp, 0x10
      [-]0f8430010000
         // 00401c5d: jz 0x401d93
      [-]8b4508897044
         // 00401c63: mov eax, ss:[ebp+0x8]
         // 00401c66: mov ds:[eax+0x44], esi
      [-]8b550851ffb2????????6a0656e89d990000585aff750856e825a4000083c410
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
      [-]56e8809b000083c41083ff030f85ef000000
         // 00401c97: push esi
         // 00401c98: call curl_multi_cleanup
         // 00401c9d: add esp, 0x10
         // 00401ca0: cmp edi, 0x3
         // 00401ca3: jnz 0x401d98
      [-]e9e5000000
         // 00401ca9: jmp 0x401d93
      [-]8d7dec897040
         // 00401cb3: lea edi, ss:[ebp+0xffffffffffffffec]
         // 00401cb6: mov ds:[eax+0x40], esi
      [-]e8b6a6000083ec0c8955dc8d55e8528945d868????????6a006a0056e8e39f000083c420
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
      [-]0f858f000000
         // 00401cdf: jnz 0x401d74
      [-]8b45e883f8ff750a
         // 00401ce5: mov eax, ss:[ebp+0xffffffffffffffe8]
         // 00401ce8: cmp eax, 0xffffffffffffffff
         // 00401ceb: jnz 0x401cf7
      [-]e98c000000
         // 00401cf2: jmp 0x401d83
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
      [-]50505756e8079c000083c410
         // 00401d3e: push eax
         // 00401d3f: push eax
         // 00401d40: push edi
         // 00401d41: push esi
         // 00401d42: call curl_multi_perform
         // 00401d47: add esp, 0x10
      [-]837dec000f8561ffffff
         // 00401d4e: cmp ss:[ebp+0xffffffffffffffec], 0x0
         // 00401d52: jnz 0x401cb9
      [-]50508d45e45056e8519a000083c410
         // 00401d58: push eax
         // 00401d59: push eax
         // 00401d5a: lea eax, ss:[ebp+0xffffffffffffffe4]
         // 00401d5d: push eax
         // 00401d5e: push esi
         // 00401d5f: call curl_multi_info_read
         // 00401d64: add esp, 0x10
      [-]0f844affffff
         // 00401d69: jz 0x401cb9
      [-]8b5808eb0f
         // 00401d6f: mov ebx, ds:[eax+0x8]
         // 00401d72: jmp 0x401d83
      [-]83f8030f95c34b83e3f0
         // 00401d76: cmp eax, 0x3
         // 00401d79: setnz b1 bl
         // 00401d7c: dec ebx
         // 00401d7d: and ebx, 0xfffffffffffffff0
      [-]5050ff750856e865a10000
         // 00401d83: push eax
         // 00401d84: push eax
         // 00401d85: push ss:[ebp+0x8]
         // 00401d88: push esi
         // 00401d89: call curl_multi_remove_handle
      [-]83c410eb05
         // 00401d8e: add esp, 0x10
         // 00401d91: jmp 0x401d98
      [-]5b5e5f5dc3
         // 00401d9d: pop ebx
         // 00401d9e: pop esi
         // 00401d9f: pop edi
         // 00401da0: pop ebp
         // 00401da1: retn 
      [-]89e583ec188b5508
         // 00401da8: mov ebp, esp
         // 00401daa: sub esp, 0x18
         // 00401dad: mov edx, ss:[ebp+0x8]
      [-]8d451051508945fcff750c52e8f05f000083c410
         // 00401db4: lea eax, ss:[ebp+0x10]
         // 00401db7: push ecx
         // 00401db8: push eax
         // 00401db9: mov ss:[ebp+0xfffffffffffffffc], eax
         // 00401dbc: push ss:[ebp+0xc]
         // 00401dbf: push edx
         // 00401dc0: call 0x407db5
         // 00401dc5: add esp, 0x10
      [-]5589e583ec08a1????????
         // 00401dca: push ebp
         // 00401dcb: mov ebp, esp
         // 00401dcd: sub esp, 0x8
         // 00401dd0: mov eax, ds:[0x423040]
      [-]48a3????????
         // 00401dd9: dec eax
         // 00401dda: mov ds:[0x423040], eax
      [-]e8c0220000f60550304200027405
         // 00401de3: call 0x4040a8
         // 00401de8: test b1 ds:[0x423050], b1 0x2
         // 00401def: jz 0x401df6
      [-]e8d2ad0100
         // 00401df1: call WSACleanup
      [-]c705????????????????
         // 00401df6: mov ds:[0x423050], 0x0
      [-]89e55381ec????????a1????????8b5d0840a3????????480f858a000000
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
      [-]50508d85????????5068????????e86bad01005a
         // 00401e5a: push eax
         // 00401e5b: push eax
         // 00401e5c: lea eax, ss:[ebp+0xfffffffffffffe6c]
         // 00401e62: push eax
         // 00401e63: push 0x202
         // 00401e68: call WSAStartup
         // 00401e6d: pop edx
      [-]8b85????????3c027508
         // 00401e78: mov eax, ss:[ebp+0xfffffffffffffe6c]
         // 00401e7e: cmp b1 al, b1 0x2
         // 00401e80: jnz 0x401e8a
      [-]66c1e8083c02740c
         // 00401e82: shr b2 ax, b1 0x8
         // 00401e86: cmp b1 al, b1 0x2
         // 00401e88: jz 0x401e96
      [-]e839ad0100
         // 00401e8a: call WSACleanup
      [-]f6c304740a
         // 00401e96: test b1 bl, b1 0x4
         // 00401e99: jz 0x401ea5
      [-]c705????????????????
         // 00401e9b: mov ds:[0x423060], 0x1
      [-]891d????????
         // 00401ea5: mov ds:[0x423050], ebx
      [-]8b5dfcc9c3
         // 00401eaf: mov ebx, ss:[ebp+0xfffffffffffffffc]
         // 00401eb2: leave 
         // 00401eb3: retn 
      [-]5589e583ec18833d????????007511
         // 00401eb4: push ebp
         // 00401eb5: mov ebp, esp
         // 00401eb7: sub esp, 0x18
         // 00401eba: cmp ds:[0x423040], 0x0
         // 00401ec1: jnz 0x401ed4
      [-]83ec0c6a03e835ffffff83c410
         // 00401ec3: sub esp, 0xc
         // 00401ec6: push 0x3
         // 00401ec8: call curl_global_init
         // 00401ecd: add esp, 0x10
      [-]83ec0c8d45fc50e8bb24000083c410
         // 00401ed4: sub esp, 0xc
         // 00401ed7: lea eax, ss:[ebp+0xfffffffffffffffc]
         // 00401eda: push eax
         // 00401edb: call 0x40439b
         // 00401ee0: add esp, 0x10
      [-]8b45fceb02
         // 00401ee7: mov eax, ss:[ebp+0xfffffffffffffffc]
         // 00401eea: jmp 0x401eee
      [-]5589e557565383ec0c8b750c8b7d108b5d18
         // 00401ef0: push ebp
         // 00401ef1: mov ebp, esp
         // 00401ef3: push edi
         // 00401ef4: push esi
         // 00401ef5: push ebx
         // 00401ef6: sub esp, 0xc
         // 00401ef9: mov esi, ss:[ebp+0xc]
         // 00401efc: mov edi, ss:[ebp+0x10]
         // 00401eff: mov ebx, ss:[ebp+0x18]
      [-]837d14007455
         // 00401f0a: cmp ss:[ebp+0x14], 0x0
         // 00401f0e: jz 0x401f65
      [-]837d1c00744b
         // 00401f14: cmp ss:[ebp+0x1c], 0x0
         // 00401f18: jz 0x401f65
      [-]a1????????
         // 00401f1a: mov eax, ds:[0x423040]
      [-]40a3????????
         // 00401f23: inc eax
         // 00401f24: mov ds:[0x423040], eax
      [-]83ec0cff7508e8cafeffff83c410
         // 00401f2d: sub esp, 0xc
         // 00401f30: push ss:[ebp+0x8]
         // 00401f33: call curl_global_init
         // 00401f38: add esp, 0x10
      [-]8b55148935????????8915????????8b551c893d????????891d????????8915????????eb05
         // 00401f3f: mov edx, ss:[ebp+0x14]
         // 00401f42: mov ds:[0x41e008], esi
         // 00401f48: mov ds:[0x41e010], edx
         // 00401f4e: mov edx, ss:[ebp+0x1c]
         // 00401f51: mov ds:[0x41e00c], edi
         // 00401f57: mov ds:[0x41e014], ebx
         // 00401f5d: mov ds:[0x41e018], edx
         // 00401f63: jmp 0x401f6a
      [-]8d65f45b5e5f5dc3
         // 00401f6a: lea esp, ss:[ebp+0xfffffffffffffff4]
         // 00401f6d: pop ebx
         // 00401f6e: pop esi
         // 00401f6f: pop edi
         // 00401f70: pop ebp
         // 00401f71: retn 
      [-]5589e557565383ec14
         // 00401f74: push ebp
         // 00401f75: mov ebp, esp
         // 00401f77: push edi
         // 00401f78: push esi
         // 00401f79: push ebx
         // 00401f7a: sub esp, 0x14
      [-]6a406a01ff15????????83c410
         // 00401f83: push 0x40
         // 00401f85: push 0x1
         // 00401f87: call ds:[0x41e018]
         // 00401f8d: add esp, 0x10
      [-]c74220????????
         // 00401fa6: mov ds:[edx+0x20], 0x1
      [-]8b433c89423c89533c
         // 00401fb1: mov eax, ds:[ebx+0x3c]
         // 00401fb4: mov ds:[edx+0x3c], eax
         // 00401fb7: mov ds:[ebx+0x3c], edx
      [-]5b5e5f5dc3
         // 00401fbf: pop ebx
         // 00401fc0: pop esi
         // 00401fc1: pop edi
         // 00401fc2: pop ebp
         // 00401fc3: retn 
      [-]5589e557565383ec0c8b7d088b1f
         // 00401fc4: push ebp
         // 00401fc5: mov ebp, esp
         // 00401fc7: push edi
         // 00401fc8: push esi
         // 00401fc9: push ebx
         // 00401fca: sub esp, 0xc
         // 00401fcd: mov edi, ss:[ebp+0x8]
         // 00401fd0: mov ebx, ds:[edi]
      [-]8b33837b0401770f
         // 00401fd6: mov esi, ds:[ebx]
         // 00401fd8: cmp ds:[ebx+0x4], 0x1
         // 00401fdc: ja 0x401fed
      [-]83ec0cff7308ff15????????83c410
         // 00401fde: sub esp, 0xc
         // 00401fe1: push ds:[ebx+0x8]
         // 00401fe4: call ds:[0x41e00c]
         // 00401fea: add esp, 0x10
      [-]83ec0c53
         // 00401fed: sub esp, 0xc
         // 00401ff0: push ebx
      [-]ff15????????83c410
         // 00401ff3: call ds:[0x41e00c]
         // 00401ff9: add esp, 0x10
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
      [-]0f8485000000
         // 00402018: jz 0x4020a3
      [-]8b43248b33
         // 0040201e: mov eax, ds:[ebx+0x24]
         // 00402021: mov esi, ds:[ebx]
      [-]83ec0c50e8deffffff83c410
         // 00402027: sub esp, 0xc
         // 0040202a: push eax
         // 0040202b: call curl_formfree
         // 00402030: add esp, 0x10
      [-]f64328047514
         // 00402033: test b1 ds:[ebx+0x28], b1 0x4
         // 00402037: jnz 0x40204d
      [-]83ec0c50ff15????????83c410
         // 00402040: sub esp, 0xc
         // 00402043: push eax
         // 00402044: call ds:[0x41e00c]
         // 0040204a: add esp, 0x10
      [-]f64328587514
         // 0040204d: test b1 ds:[ebx+0x28], b1 0x58
         // 00402051: jnz 0x402067
      [-]83ec0c50ff15????????83c410
         // 0040205a: sub esp, 0xc
         // 0040205d: push eax
         // 0040205e: call ds:[0x41e00c]
         // 00402064: add esp, 0x10
      [-]83ec0c50ff15????????83c410
         // 0040206e: sub esp, 0xc
         // 00402071: push eax
         // 00402072: call ds:[0x41e00c]
         // 00402078: add esp, 0x10
      [-]83ec0c50ff15????????83c410
         // 00402082: sub esp, 0xc
         // 00402085: push eax
         // 00402086: call ds:[0x41e00c]
         // 0040208c: add esp, 0x10
      [-]83ec0c53ff15????????
         // 0040208f: sub esp, 0xc
         // 00402092: push ebx
         // 00402093: call ds:[0x41e00c]
      [-]83c410e973ffffff
         // 0040209b: add esp, 0x10
         // 0040209e: jmp 0x402016
      [-]8d65f85b5e5dc3
         // 004020a3: lea esp, ss:[ebp+0xfffffffffffffff8]
         // 004020a6: pop ebx
         // 004020a7: pop esi
         // 004020a8: pop ebp
         // 004020a9: retn 
      [-]89e58b4d0c8b5508
         // 004020b0: mov ebp, esp
         // 004020b2: mov ecx, ss:[ebp+0xc]
         // 004020b5: mov edx, ss:[ebp+0x8]
      [-]890ac742????????00c742????????00c742????????0030c0
         // 004020bc: mov ds:[edx], ecx
         // 004020be: mov ds:[edx+0x4], 0x0
         // 004020c5: mov ds:[edx+0x8], 0x0
         // 004020cc: mov ds:[edx+0xc], 0x0
         // 004020d3: xor b1 al, b1 al
      [-]5589e557565383ec0c89
         // 004020fc: push ebp
         // 004020fd: mov ebp, esp
         // 004020ff: push edi
         // 00402100: push esi
         // 00402101: push ebx
         // 00402102: sub esp, 0xc
         // 00402109: mov ss:[ebp+0xfffffffffffffff0], edx
      [-]837804027516
         // 0040210e: cmp ds:[eax+0x4], 0x2
         // 00402112: jnz 0x40212a
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
      [-]525268????????83ceffff7008e8deb8010083c410894308
         // 00402130: push edx
         // 00402131: push edx
         // 00402132: push 0x41f1c4
         // 00402137: or esi, 0xffffffffffffffff
         // 0040213a: push ds:[eax+0x8]
         // 0040213d: call fopen
         // 00402142: add esp, 0x10
         // 00402145: mov ds:[ebx+0x8], eax
      [-]ff7308576a01ff75f0e806b90100
         // 0040214c: push ds:[ebx+0x8]
         // 0040214f: push edi
         // 00402150: push 0x1
         // 00402152: push ss:[ebp+0xfffffffffffffff0]
         // 00402155: call fread
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
      [-]5b5e5f5dc3
         // 00402188: pop ebx
         // 00402189: pop esi
         // 0040218a: pop edi
         // 0040218b: pop ebp
         // 0040218c: retn 
      [-]5589e557565383ec0c
         // 0040218d: push ebp
         // 0040218e: mov ebp, esp
         // 00402190: push edi
         // 00402191: push esi
         // 00402192: push ebx
         // 00402193: sub esp, 0xc
      [-]8b7d148b07
         // 00402198: mov edi, ss:[ebp+0x14]
         // 0040219b: mov eax, ds:[edi]
      [-]0f8495000000
         // 0040219f: jz 0x40223a
      [-]8b550c8b40040faf5510
         // 004021a5: mov edx, ss:[ebp+0xc]
         // 004021a8: mov eax, ds:[eax+0x4]
         // 004021ab: imul edx, ss:[ebp+0x10]
      [-]8955f083f8017712
         // 004021b2: mov ss:[ebp+0xfffffffffffffff0], edx
         // 004021b5: cmp eax, 0x1
         // 004021b8: ja 0x4021cc
      [-]8b5508e836ffffff
         // 004021be: mov edx, ss:[ebp+0x8]
         // 004021c1: call 0x4020fc
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
      [-]8b4de8034108515250ff75ece8f8b801008b178b420c83c4102b4704c747????????0001c68b028907
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
      [-]837804017694
         // 00402234: cmp ds:[eax+0x4], 0x1
         // 00402238: jbe 0x4021ce
      [-]5b5e5f5dc3
         // 0040223f: pop ebx
         // 00402240: pop esi
         // 00402241: pop edi
         // 00402242: pop ebp
         // 00402243: retn 
      [-]5589e55653
         // 00402244: push ebp
         // 00402245: mov ebp, esp
         // 00402247: push esi
         // 00402248: push ebx
      [-]83ec0c50e836e9000089
         // 0040224b: sub esp, 0xc
         // 0040224e: push eax
         // 0040224f: call 0x410b8a
         // 00402257: mov esi, eax
      [-]e82ce9000083c40c565068????????e88be600008d65f85b5e5dc3
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
      [-]5589e557565383ec0c
         // 00402274: push ebp
         // 00402275: mov ebp, esp
         // 00402277: push edi
         // 00402278: push esi
         // 00402279: push ebx
         // 0040227a: sub esp, 0xc
      [-]fc83c9ff
         // 00402287: cld 
         // 00402288: or ecx, 0xffffffffffffffff
      [-]f2aef7d1c645f3018d59ffeb1b
         // 0040228f: repne scasbb 
         // 00402291: not ecx
         // 00402293: mov b1 ss:[ebp+0xfffffffffffffff3], b1 0x1
         // 00402297: lea ebx, ds:[ecx+0xffffffffffffffff]
         // 0040229a: jmp 0x4022b7
      [-]83ec0c68????????ff15????????83c410
         // 0040229c: sub esp, 0xc
         // 0040229f: push 0x41f1e8
         // 004022a4: call ds:[0x41e014]
         // 004022aa: add esp, 0x10
      [-]c645f300
         // 004022b3: mov b1 ss:[ebp+0xfffffffffffffff3], b1 0x0
      [-]0fb645f383ec0c01d8
         // 004022b7: movzx eax, b1 ss:[ebp+0xfffffffffffffff3]
         // 004022bb: sub esp, 0xc
         // 004022be: add eax, ebx
      [-]50ff15????????83c410
         // 004022c2: push eax
         // 004022c3: call ds:[0x41e008]
         // 004022c9: add esp, 0x10
      [-]50535657e835b8010083c410807df3007404
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
      [-]5b5e5f5dc3
         // 004022ed: pop ebx
         // 004022ee: pop esi
         // 004022ef: pop edi
         // 004022f0: pop ebp
         // 004022f1: retn 
      [-]5589e557565383ec488945bc8955b8
         // 004022f2: push ebp
         // 004022f3: mov ebp, esp
         // 004022f5: push edi
         // 004022f6: push esi
         // 004022f7: push ebx
         // 004022f8: sub esp, 0x48
         // 004022fb: mov ss:[ebp+0xffffffffffffffbc], eax
         // 004022fe: mov ss:[ebp+0xffffffffffffffb8], edx
      [-]6a108b7d08ff15????????83c410
         // 00402303: push 0x10
         // 00402305: mov edi, ss:[ebp+0x8]
         // 00402308: call ds:[0x41e008]
         // 0040230e: add esp, 0x10
      [-]0f84e8000000
         // 0040231a: jz 0x402408
      [-]c703????????837db8017759
         // 00402320: mov ds:[ebx], 0x0
         // 00402326: cmp ss:[ebp+0xffffffffffffffb8], 0x1
         // 0040232a: ja 0x402385
      [-]f2aef7d18d79ff
         // 00402338: repne scasbb 
         // 0040233a: not ecx
         // 0040233c: lea edi, ds:[ecx+0xffffffffffffffff]
      [-]83ec0c8d470150ff15????????83c410894308
         // 0040233f: sub esp, 0xc
         // 00402342: lea eax, ds:[edi+0x1]
         // 00402345: push eax
         // 00402346: call ds:[0x41e008]
         // 0040234c: add esp, 0x10
         // 0040234f: mov ds:[ebx+0x8], eax
      [-]83ec0c53ff15????????
         // 00402356: sub esp, 0xc
         // 00402359: push ebx
         // 0040235a: call ds:[0x41e00c]
      [-]83c410e99b000000
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
      [-]8b55bc8b45b88943048b02
         // 00402388: mov edx, ss:[ebp+0xffffffffffffffbc]
         // 0040238b: mov eax, ss:[ebp+0xffffffffffffffb8]
         // 0040238e: mov ds:[ebx+0x4], eax
         // 00402391: mov eax, ds:[edx]
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
      [-]5050ff730868????????e826e6000083c410
         // 004023b4: push eax
         // 004023b5: push eax
         // 004023b6: push ds:[ebx+0x8]
         // 004023b9: push 0x41f1e9
         // 004023be: call curl_strequal
         // 004023c3: add esp, 0x10
      [-]50508d45c050ff7308e848b7010083c410
         // 004023ca: push eax
         // 004023cb: push eax
         // 004023cc: lea eax, ss:[ebp+0xffffffffffffffc0]
         // 004023cf: push eax
         // 004023d0: push ds:[ebx+0x8]
         // 004023d3: call _stati64
         // 004023d8: add esp, 0x10
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
      [-]8d65f45b5e5f5dc3
         // 00402408: lea esp, ss:[ebp+0xfffffffffffffff4]
         // 0040240b: pop ebx
         // 0040240c: pop esi
         // 0040240d: pop edi
         // 0040240e: pop ebp
         // 0040240f: retn 
      [-]55b8????????89e553e84aaa01008d4514508d9d????????ff75108945f868????????53e844e500005958ff750c
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
      [-]6a00e8a6feffff8b5dfcc9c3
         // 00402445: push 0x0
         // 00402447: call 0x4022f2
         // 0040244c: mov ebx, ss:[ebp+0xfffffffffffffffc]
         // 0040244f: leave 
         // 00402450: retn 
      [-]5589e557565383ec1c8955ec8b582c894de8c745f0????????
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
      [-]83ec0cff700cff15????????83c410
         // 0040246e: sub esp, 0xc
         // 00402471: push ds:[eax+0xc]
         // 00402474: call ds:[0x41e014]
         // 0040247a: add esp, 0x10
      [-]0f84f3000000
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
      [-]50506a5c53e86fb6010083c410
         // 004024b7: push eax
         // 004024b8: push eax
         // 004024b9: push 0x5c
         // 004024bb: push ebx
         // 004024bc: call strchr
         // 004024c1: add esp, 0x10
      [-]50506a2253e85eb60100
         // 004024c8: push eax
         // 004024c9: push eax
         // 004024ca: push 0x22
         // 004024cc: push ebx
         // 004024cd: call strchr
      [-]83ec0cf2aef7d18d4c09ff51ff15????????83c410
         // 004024e3: sub esp, 0xc
         // 004024e6: repne scasbb 
         // 004024e8: not ecx
         // 004024ea: lea ecx, ds:[ecx+ecx+0xffffffffffffffff]
         // 004024ee: push ecx
         // 004024ef: call ds:[0x41e008]
         // 004024f5: add esp, 0x10
      [-]837df000746e
         // 00402506: cmp ss:[ebp+0xfffffffffffffff0], 0x0
         // 0040250a: jz 0x40257a
      [-]ff75f0ff15????????eb56
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
      [-]5368????????ff75e8ff75ece8c3feffff83c410
         // 0040253c: push ebx
         // 0040253d: push 0x41f1eb
         // 00402542: push ss:[ebp+0xffffffffffffffe8]
         // 00402545: push ss:[ebp+0xffffffffffffffec]
         // 00402548: call 0x402410
         // 0040254d: add esp, 0x10
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
      [-]5b5e5f5dc3
         // 00402584: pop ebx
         // 00402585: pop esi
         // 00402586: pop edi
         // 00402587: pop ebp
         // 00402588: retn 
      [-]5589e557565381ec????????
         // 00402589: push ebp
         // 0040258a: mov ebp, esp
         // 0040258c: push edi
         // 0040258d: push esi
         // 0040258e: push ebx
         // 0040258f: sub esp, 0x22c
      [-]8b450c8b7d10c745ec????????8b5d14c745e0????????c745e4????????c700????????
         // 00402597: mov eax, ss:[ebp+0xc]
         // 0040259a: mov edi, ss:[ebp+0x10]
         // 0040259d: mov ss:[ebp+0xffffffffffffffec], 0x0
         // 004025a4: mov ebx, ss:[ebp+0x14]
         // 004025a7: mov ss:[ebp+0xffffffffffffffe0], 0x0
         // 004025ae: mov ss:[ebp+0xffffffffffffffe4], 0x0
         // 004025b5: mov ds:[eax], 0x0
      [-]0f8489040000
         // 004025bd: jz 0x402a4c
      [-]8b450866be1b00e875fcffff8985????????
         // 004025c3: mov eax, ss:[ebp+0x8]
         // 004025c6: mov b2 si, b2 0x1b
         // 004025ca: call 0x402244
         // 004025cf: mov ss:[ebp+0xfffffffffffffdd8], eax
      [-]0f846f040000
         // 004025d7: jz 0x402a4c
      [-]bb????????
         // 004025e1: mov ebx, 0x41f1fb
      [-]83ec0cffb5????????538d5dec68????????6a0053e810feffff83c420
         // 004025e6: sub esp, 0xc
         // 004025e9: push ss:[ebp+0xfffffffffffffdd8]
         // 004025ef: push ebx
         // 004025f0: lea ebx, ss:[ebp+0xffffffffffffffec]
         // 004025f3: push 0x41f21d
         // 004025f8: push 0x0
         // 004025fa: push ebx
         // 004025fb: call 0x402410
         // 00402600: add esp, 0x20
      [-]0f85d8030000
         // 00402607: jnz 0x4029e5
      [-]8b45ecc785????????????????8945e8
         // 0040260d: mov eax, ss:[ebp+0xffffffffffffffec]
         // 00402610: mov ss:[ebp+0xfffffffffffffddc], 0x0
         // 0040261a: mov ss:[ebp+0xffffffffffffffe8], eax
      [-]8b45e00b45e47420
         // 0040261d: mov eax, ss:[ebp+0xffffffffffffffe0]
         // 00402620: or eax, ss:[ebp+0xffffffffffffffe4]
         // 00402623: jz 0x402645
      [-]8d45ec528d55e068????????5250e8d8fdffff83c410
         // 00402625: lea eax, ss:[ebp+0xffffffffffffffec]
         // 00402628: push edx
         // 00402629: lea edx, ss:[ebp+0xffffffffffffffe0]
         // 0040262c: push 0x41f22f
         // 00402631: push edx
         // 00402632: push eax
         // 00402633: call 0x402410
         // 00402638: add esp, 0x10
      [-]0f8576030000
         // 0040263f: jnz 0x4029bb
      [-]ffb5????????8d55e08d45ec68
         // 00402645: push ss:[ebp+0xfffffffffffffdd8]
         // 0040264b: lea edx, ss:[ebp+0xffffffffffffffe0]
         // 0040264e: lea eax, ss:[ebp+0xffffffffffffffec]
         // 00402651: push 0x41f232
         // 00402656: push edx
         // 00402657: push eax
         // 00402658: call 0x402410
         // 0040265d: add esp, 0x10

  }
  condition:
    all of them
}
