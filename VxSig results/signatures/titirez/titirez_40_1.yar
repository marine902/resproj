rule titirez_40_1 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         83ec1c8b4424208b008b003d????????741b
         // 00401000: sub esp, 0x1c
         // 00401003: mov eax, ss:[esp+0x20]
         // 00401007: mov eax, ds:[eax]
         // 00401009: mov eax, ds:[eax]
         // 0040100b: cmp eax, 0xffffffffc0000093
         // 00401010: jz 0x40102d
      [-]3d????????0f84cc000000
         // 00401014: cmp eax, 0xffffffffc000001d
         // 00401019: jz 0x4010eb
      [-]05????????31d283f8047727
         // 00401021: add eax, 0x3fffff73
         // 00401026: xor edx, edx
         // 00401028: cmp eax, 0x4
         // 0040102b: ja 0x401054
      [-]c74424????????00c70424????????e8bfe9030083f8010f84d6000000
         // 0040102d: mov ss:[esp+0x4], 0x0
         // 00401035: mov ss:[esp], 0x8
         // 0040103c: call signal
         // 00401041: cmp eax, 0x1
         // 00401044: jz 0x401120
      [-]85c00f85fe000000
         // 0040104a: test eax, eax
         // 0040104c: jnz 0x401150
      [-]89d083c41cc20400
         // 00401054: mov eax, edx
         // 00401056: add esp, 0x1c
         // 00401059: retn b2 0x4
      [-]3d????????7579
         // 00401060: cmp eax, 0xffffffffc0000094
         // 00401065: jnz 0x4010e0
      [-]c74424????????00c70424????????e885e9030083f80175ca
         // 00401067: mov ss:[esp+0x4], 0x0
         // 0040106f: mov ss:[esp], 0x8
         // 00401076: call signal
         // 0040107b: cmp eax, 0x1
         // 0040107e: jnz 0x40104a
      [-]c7442404????????c70424????????e86ce90300ba????????ebb9
         // 00401080: mov ss:[esp+0x4], 0x1
         // 00401088: mov ss:[esp], 0x8
         // 0040108f: call signal
         // 00401094: mov edx, 0xffffffffffffffff
         // 00401099: jmp 0x401054
      [-]3d????????75ab
         // 004010a0: cmp eax, 0xffffffffc0000005
         // 004010a5: jnz 0x401052
      [-]c74424????????00c70424????????e845e9030083f8010f849f000000
         // 004010a7: mov ss:[esp+0x4], 0x0
         // 004010af: mov ss:[esp], 0xb
         // 004010b6: call signal
         // 004010bb: cmp eax, 0x1
         // 004010be: jz 0x401163
      [-]85c0748a
         // 004010c4: test eax, eax
         // 004010c6: jz 0x401052
      [-]c70424????????ffd0ba????????e979ffffff
         // 004010c8: mov ss:[esp], 0xb
         // 004010cf: call eax
         // 004010d1: mov edx, 0xffffffffffffffff
         // 004010d6: jmp 0x401054
      [-]3d????????0f8567ffffff
         // 004010e0: cmp eax, 0xffffffffc0000096
         // 004010e5: jnz 0x401052
      [-]c74424????????00c70424????????e801e9030083f801747b
         // 004010eb: mov ss:[esp+0x4], 0x0
         // 004010f3: mov ss:[esp], 0x4
         // 004010fa: call signal
         // 004010ff: cmp eax, 0x1
         // 00401102: jz 0x40117f
      [-]85c00f8446ffffff
         // 00401104: test eax, eax
         // 00401106: jz 0x401052
      [-]c70424????????ffd0ba????????e935ffffff
         // 0040110c: mov ss:[esp], 0x4
         // 00401113: call eax
         // 00401115: mov edx, 0xffffffffffffffff
         // 0040111a: jmp 0x401054
      [-]c7442404????????c70424????????e8cce80300c70424????????e880310300ba????????e90affffff
         // 00401120: mov ss:[esp+0x4], 0x1
         // 00401128: mov ss:[esp], 0x8
         // 0040112f: call signal
         // 00401134: mov ss:[esp], 0x0
         // 0040113b: call 0x4342c0
         // 00401140: mov edx, 0xffffffffffffffff
         // 00401145: jmp 0x401054
      [-]c70424????????ffd0ba????????e9f1feffff
         // 00401150: mov ss:[esp], 0x8
         // 00401157: call eax
         // 00401159: mov edx, 0xffffffffffffffff
         // 0040115e: jmp 0x401054
      [-]c7442404????????c70424????????e889e8030083caffe9d5feffff
         // 00401163: mov ss:[esp+0x4], 0x1
         // 0040116b: mov ss:[esp], 0xb
         // 00401172: call signal
         // 00401177: or edx, 0xffffffffffffffff
         // 0040117a: jmp 0x401054
      [-]c7442404????????c70424????????e86de8030083caffe9b9feffff
         // 0040117f: mov ss:[esp+0x4], 0x1
         // 00401187: mov ss:[esp], 0x4
         // 0040118e: call signal
         // 00401193: or edx, 0xffffffffffffffff
         // 00401196: jmp 0x401054
      [-]5383ec18a1????????85c0741c
         // 004011a0: push ebx
         // 004011a1: sub esp, 0x18
         // 004011a4: mov eax, ds:[0x4da7d4]
         // 004011a9: test eax, eax
         // 004011ab: jz 0x4011c9
      [-]c74424????????00c7442404????????c70424????????ffd083ec0c
         // 004011ad: mov ss:[esp+0x8], 0x0
         // 004011b5: mov ss:[esp+0x4], 0x2
         // 004011bd: mov ss:[esp], 0x0
         // 004011c4: call eax
         // 004011c6: sub esp, 0xc
      [-]c70424????????e8932e030083ec04e8f3740200a1????????890424e8d6300300e881700200a1????????85c0754a
         // 004011c9: mov ss:[esp], 0x401000
         // 004011d0: call SetUnhandledExceptionFilter
         // 004011d5: sub esp, 0x4
         // 004011d8: call 0x4286d0
         // 004011dd: mov eax, ds:[0x4d40d0]
         // 004011e2: mov ss:[esp], eax
         // 004011e5: call 0x4342c0
         // 004011ea: call 0x428270
         // 004011ef: mov eax, ds:[0x4e7770]
         // 004011f4: test eax, eax
         // 004011f6: jnz 0x401242
      [-]e88be903008b15????????8910e8167b020083e4f0e86e760200e879e903008b0089442408a1????????89442404a1????????890424e8a81f000089c3e836e90300891c24e8b62f0300
         // 004011f8: call __p__fmode
         // 004011fd: mov edx, ds:[0x4d40d4]
         // 00401203: mov ds:[eax], edx
         // 00401205: call 0x428d20
         // 0040120a: and esp, 0xfffffffffffffff0
         // 0040120d: call 0x428880
         // 00401212: call __p__environ
         // 00401217: mov eax, ds:[eax]
         // 00401219: mov ss:[esp+0x8], eax
         // 0040121d: mov eax, ds:[0x4e6000]
         // 00401222: mov ss:[esp+0x4], eax
         // 00401226: mov eax, ds:[0x4e6004]
         // 0040122b: mov ss:[esp], eax
         // 0040122e: call 0x4031db
         // 00401233: mov ebx, eax
         // 00401235: call _cexit
         // 0040123a: mov ss:[esp], ebx
         // 0040123d: call ExitProcess
      [-]8b1dc0944e0089442404a3????????8b4310890424e8c4e80300a1????????894424048b4330890424e8b0e80300a1????????894424048b4350890424e89ce80300e96fffffff
         // 00401242: mov ebx, ds:[_iob]
         // 00401248: mov ss:[esp+0x4], eax
         // 0040124c: mov ds:[0x4d40d4], eax
         // 00401251: mov eax, ds:[ebx+0x10]
         // 00401254: mov ss:[esp], eax
         // 00401257: call _setmode
         // 0040125c: mov eax, ds:[0x4e7770]
         // 00401261: mov ss:[esp+0x4], eax
         // 00401265: mov eax, ds:[ebx+0x30]
         // 00401268: mov ss:[esp], eax
         // 0040126b: call _setmode
         // 00401270: mov eax, ds:[0x4e7770]
         // 00401275: mov ss:[esp+0x4], eax
         // 00401279: mov eax, ds:[ebx+0x50]
         // 0040127c: mov ss:[esp], eax
         // 0040127f: call _setmode
         // 00401284: jmp 0x4011f8
      [-]83ec3c8d44242cc7442404????????89442410a1????????c70424????????83e001c74424????????008944240c8d44242889442408e8cde8030083c43cc3
         // 00401290: sub esp, 0x3c
         // 00401293: lea eax, ss:[esp+0x2c]
         // 00401297: mov ss:[esp+0x4], 0x4e6000
         // 0040129f: mov ss:[esp+0x10], eax
         // 004012a3: mov eax, ds:[0x4d40cc]
         // 004012a8: mov ss:[esp], 0x4e6004
         // 004012af: and eax, 0x1
         // 004012b2: mov ss:[esp+0x2c], 0x0
         // 004012ba: mov ss:[esp+0xc], eax
         // 004012be: lea eax, ss:[esp+0x28]
         // 004012c2: mov ss:[esp+0x8], eax
         // 004012c6: call __getmainargs
         // 004012cb: add esp, 0x3c
         // 004012ce: retn 
      [-]83ec1cc70424????????ff15a0944e00e8bbfeffff
         // 004012d0: sub esp, 0x1c
         // 004012d3: mov ss:[esp], 0x1
         // 004012da: call ds:[__set_app_type]
         // 004012e0: call 0x4011a0
      [-]83ec1cc70424????????ff15a0944e00e89bfeffff
         // 004012f0: sub esp, 0x1c
         // 004012f3: mov ss:[esp], 0x2
         // 004012fa: call ds:[__set_app_type]
         // 00401300: call 0x4011a0
      [-]5589e583ec18c70424????????e8ceffffffc9c3
         // 00401330: push ebp
         // 00401331: mov ebp, esp
         // 00401333: sub esp, 0x18
         // 00401336: mov ss:[esp], 0x401350
         // 0040133d: call atexit
         // 00401342: leave 
         // 00401343: retn 
      [-]5589e583ec388b4d08e872750400c74424????????00c74424????????00c74424????????00c74424????????00c744240c????????89442408c74424????????00c70424????????e8522c030083ec208945f48b45f4890424e8a13700008945f08b4d08e816750400c74424????????00c74424????????008b55f4895424148b55f089542410c744240c????????89442408c74424????????00c70424????????e8f82b030083ec208b45f0c9c3
         // 00401360: push ebp
         // 00401361: mov ebp, esp
         // 00401363: sub esp, 0x38
         // 00401366: mov ecx, ss:[ebp+0x8]
         // 00401369: call 0x4488e0
         // 0040136e: mov ss:[esp+0x1c], 0x0
         // 00401376: mov ss:[esp+0x18], 0x0
         // 0040137e: mov ss:[esp+0x14], 0x0
         // 00401386: mov ss:[esp+0x10], 0x0
         // 0040138e: mov ss:[esp+0xc], 0xffffffffffffffff
         // 00401396: mov ss:[esp+0x8], eax
         // 0040139a: mov ss:[esp+0x4], 0x0
         // 004013a2: mov ss:[esp], 0x0
         // 004013a9: call WideCharToMultiByte
         // 004013ae: sub esp, 0x20
         // 004013b1: mov ss:[ebp+0xfffffffffffffff4], eax
         // 004013b4: mov eax, ss:[ebp+0xfffffffffffffff4]
         // 004013b7: mov ss:[esp], eax
         // 004013ba: call 0x404b60
         // 004013bf: mov ss:[ebp+0xfffffffffffffff0], eax
         // 004013c2: mov ecx, ss:[ebp+0x8]
         // 004013c5: call 0x4488e0
         // 004013ca: mov ss:[esp+0x1c], 0x0
         // 004013d2: mov ss:[esp+0x18], 0x0
         // 004013da: mov edx, ss:[ebp+0xfffffffffffffff4]
         // 004013dd: mov ss:[esp+0x14], edx
         // 004013e1: mov edx, ss:[ebp+0xfffffffffffffff0]
         // 004013e4: mov ss:[esp+0x10], edx
         // 004013e8: mov ss:[esp+0xc], 0xffffffffffffffff
         // 004013f0: mov ss:[esp+0x8], eax
         // 004013f4: mov ss:[esp+0x4], 0x0
         // 004013fc: mov ss:[esp], 0x0
         // 00401403: call WideCharToMultiByte
         // 00401408: sub esp, 0x20
         // 0040140b: mov eax, ss:[ebp+0xfffffffffffffff0]
         // 0040140e: leave 
         // 0040140f: retn 
      [-]5589e557565381ec????????c785????????????????c785????????????????8d85????????8928ba????????8950048960088d85????????890424e8f18602008d85????????c7442404????????8b5508891424c785????????????????89c1e84c870a0083ec088d85????????83c070c785????????????????89c1e88fe0070084c0740f
         // 0040164e: push ebp
         // 0040164f: mov ebp, esp
         // 00401651: push edi
         // 00401652: push esi
         // 00401653: push ebx
         // 00401654: sub esp, 0x19c
         // 0040165a: mov ss:[ebp+0xfffffffffffffe9c], 0x403d70
         // 00401664: mov ss:[ebp+0xfffffffffffffea0], 0x4d19d0
         // 0040166e: lea eax, ss:[ebp+0xfffffffffffffea4]
         // 00401674: mov ds:[eax], ebp
         // 00401676: mov edx, 0x4017fe
         // 0040167b: mov ds:[eax+0x4], edx
         // 0040167e: mov ds:[eax+0x8], esp
         // 00401681: lea eax, ss:[ebp+0xfffffffffffffe84]
         // 00401687: mov ss:[esp], eax
         // 0040168a: call 0x429d80
         // 0040168f: lea eax, ss:[ebp+0xfffffffffffffeb8]
         // 00401695: mov ss:[esp+0x4], 0x4
         // 0040169d: mov edx, ss:[ebp+0x8]
         // 004016a0: mov ss:[esp], edx
         // 004016a3: mov ss:[ebp+0xfffffffffffffe88], 0xffffffffffffffff
         // 004016ad: mov ecx, eax
         // 004016af: call 0x4a9e00
         // 004016b4: sub esp, 0x8
         // 004016b7: lea eax, ss:[ebp+0xfffffffffffffeb8]
         // 004016bd: add eax, 0x70
         // 004016c0: mov ss:[ebp+0xfffffffffffffe88], 0x1
         // 004016ca: mov ecx, eax
         // 004016cc: call 0x47f760
         // 004016d1: test b1 al, b1 al
         // 004016d3: jz 0x4016e4
      [-]c785????????????????e9ff000000
         // 004016d5: mov ss:[ebp+0xfffffffffffffe80], 0x0
         // 004016df: jmp 0x4017e3
      [-]8d85????????c785????????????????89c1e8853e04008945e48b55e48d45b0c7442410????????c744240c????????c74424????????00c74424????????0089142489c1e892f50a0083ec148d45b089c1e8c541040089c28b450c89108b45e48985????????8d45d0c70424????????c74424????????0089c1e8b4780b0083ec088d45c0c7442414????????8b55d0895424048b55d4895424088b55d88954240c8b55dc895424108b9d????????891c2489c1e8a2f50a0083ec188b450c8b00890424e8b23300008945e08b45e48b550c8b12895424048b55e089142489c1e886f70a0083ec088d85????????89c1e846840a008b45e08985????????
         // 004016e4: lea eax, ss:[ebp+0xfffffffffffffeb8]
         // 004016ea: mov ss:[ebp+0xfffffffffffffe88], 0x1
         // 004016f4: mov ecx, eax
         // 004016f6: call 0x445580
         // 004016fb: mov ss:[ebp+0xffffffffffffffe4], eax
         // 004016fe: mov edx, ss:[ebp+0xffffffffffffffe4]
         // 00401701: lea eax, ss:[ebp+0xffffffffffffffb0]
         // 00401704: mov ss:[esp+0x10], 0x8
         // 0040170c: mov ss:[esp+0xc], 0x2
         // 00401714: mov ss:[esp+0x4], 0x0
         // 0040171c: mov ss:[esp+0x8], 0x0
         // 00401724: mov ss:[esp], edx
         // 00401727: mov ecx, eax
         // 00401729: call 0x4b0cc0
         // 0040172e: sub esp, 0x14
         // 00401731: lea eax, ss:[ebp+0xffffffffffffffb0]
         // 00401734: mov ecx, eax
         // 00401736: call 0x445900
         // 0040173b: mov edx, eax
         // 0040173d: mov eax, ss:[ebp+0xc]
         // 00401740: mov ds:[eax], edx
         // 00401742: mov eax, ss:[ebp+0xffffffffffffffe4]
         // 00401745: mov ss:[ebp+0xfffffffffffffe80], eax
         // 0040174b: lea eax, ss:[ebp+0xffffffffffffffd0]
         // 0040174e: mov ss:[esp], 0x0
         // 00401755: mov ss:[esp+0x4], 0x0
         // 0040175d: mov ecx, eax
         // 0040175f: call 0x4b9018
         // 00401764: sub esp, 0x8
         // 00401767: lea eax, ss:[ebp+0xffffffffffffffc0]
         // 0040176a: mov ss:[esp+0x14], 0x8
         // 00401772: mov edx, ss:[ebp+0xffffffffffffffd0]
         // 00401775: mov ss:[esp+0x4], edx
         // 00401779: mov edx, ss:[ebp+0xffffffffffffffd4]
         // 0040177c: mov ss:[esp+0x8], edx
         // 00401780: mov edx, ss:[ebp+0xffffffffffffffd8]
         // 00401783: mov ss:[esp+0xc], edx
         // 00401787: mov edx, ss:[ebp+0xffffffffffffffdc]
         // 0040178a: mov ss:[esp+0x10], edx
         // 0040178e: mov ebx, ss:[ebp+0xfffffffffffffe80]
         // 00401794: mov ss:[esp], ebx
         // 00401797: mov ecx, eax
         // 00401799: call 0x4b0d40
         // 0040179e: sub esp, 0x18
         // 004017a1: mov eax, ss:[ebp+0xc]
         // 004017a4: mov eax, ds:[eax]
         // 004017a6: mov ss:[esp], eax
         // 004017a9: call 0x404b60
         // 004017ae: mov ss:[ebp+0xffffffffffffffe0], eax
         // 004017b1: mov eax, ss:[ebp+0xffffffffffffffe4]
         // 004017b4: mov edx, ss:[ebp+0xc]
         // 004017b7: mov edx, ds:[edx]
         // 004017b9: mov ss:[esp+0x4], edx
         // 004017bd: mov edx, ss:[ebp+0xffffffffffffffe0]
         // 004017c0: mov ss:[esp], edx
         // 004017c3: mov ecx, eax
         // 004017c5: call 0x4b0f50
         // 004017ca: sub esp, 0x8
         // 004017cd: lea eax, ss:[ebp+0xfffffffffffffeb8]
         // 004017d3: mov ecx, eax
         // 004017d5: call 0x4a9c20
         // 004017da: mov eax, ss:[ebp+0xffffffffffffffe0]
         // 004017dd: mov ss:[ebp+0xfffffffffffffe80], eax
      [-]8d85????????89c1e800940a008b85????????8985????????eb31
         // 004017e3: lea eax, ss:[ebp+0xfffffffffffffeb8]
         // 004017e9: mov ecx, eax
         // 004017eb: call 0x4aabf0
         // 004017f0: mov eax, ss:[ebp+0xfffffffffffffe80]
         // 004017f6: mov ss:[ebp+0xfffffffffffffe80], eax
         // 004017fc: jmp 0x40182f
      [-]8d85????????890424e8138802008b85????????8d65f45b5e5f5dc3
         // 0040182f: lea eax, ss:[ebp+0xfffffffffffffe84]
         // 00401835: mov ss:[esp], eax
         // 00401838: call 0x42a050
         // 0040183d: mov eax, ss:[ebp+0xfffffffffffffe80]
         // 00401843: lea esp, ss:[ebp+0xfffffffffffffff4]
         // 00401846: pop ebx
         // 00401847: pop esi
         // 00401848: pop edi
         // 00401849: pop ebp
         // 0040184a: retn 
      [-]5589e583ec18c74424????????008b450c894424048b4508890424e8f529030083ec0c85c00f94c084c07453
         // 0040184b: push ebp
         // 0040184c: mov ebp, esp
         // 0040184e: sub esp, 0x18
         // 00401851: mov ss:[esp+0x8], 0x0
         // 00401859: mov eax, ss:[ebp+0xc]
         // 0040185c: mov ss:[esp+0x4], eax
         // 00401860: mov eax, ss:[ebp+0x8]
         // 00401863: mov ss:[esp], eax
         // 00401866: call CopyFileA
         // 0040186b: sub esp, 0xc
         // 0040186e: test eax, eax
         // 00401870: setz b1 al
         // 00401873: test b1 al, b1 al
         // 00401875: jz 0x4018ca
      [-]c7442404????????c70424????????e875c20c008b550889542404890424e866c20c00c7442404????????890424e856c20c008b550c89542404890424e847c20c00c70424????????89c1e829f5080083ec04
         // 00401877: mov ss:[esp+0x4], 0x4d5004
         // 0040187f: mov ss:[esp], 0x4e67c0
         // 00401886: call 0x4cdb00
         // 0040188b: mov edx, ss:[ebp+0x8]
         // 0040188e: mov ss:[esp+0x4], edx
         // 00401892: mov ss:[esp], eax
         // 00401895: call 0x4cdb00
         // 0040189a: mov ss:[esp+0x4], 0x4d5019
         // 004018a2: mov ss:[esp], eax
         // 004018a5: call 0x4cdb00
         // 004018aa: mov edx, ss:[ebp+0xc]
         // 004018ad: mov ss:[esp+0x4], edx
         // 004018b1: mov ss:[esp], eax
         // 004018b4: call 0x4cdb00
         // 004018b9: mov ss:[esp], 0x4cba40
         // 004018c0: mov ecx, eax
         // 004018c2: call 0x490df0
         // 004018c7: sub esp, 0x4
      [-]5589e583ec188b4508890424e84229030083ec0485c00f94c084c07434
         // 004018cd: push ebp
         // 004018ce: mov ebp, esp
         // 004018d0: sub esp, 0x18
         // 004018d3: mov eax, ss:[ebp+0x8]
         // 004018d6: mov ss:[esp], eax
         // 004018d9: call DeleteFileA
         // 004018de: sub esp, 0x4
         // 004018e1: test eax, eax
         // 004018e3: setz b1 al
         // 004018e6: test b1 al, b1 al
         // 004018e8: jz 0x40191e
      [-]c7442404????????c70424????????e802c20c008b550889542404890424e8f3c10c00c70424????????89c1e8d5f4080083ec04
         // 004018ea: mov ss:[esp+0x4], 0x4d501e
         // 004018f2: mov ss:[esp], 0x4e67c0
         // 004018f9: call 0x4cdb00
         // 004018fe: mov edx, ss:[ebp+0x8]
         // 00401901: mov ss:[esp+0x4], edx
         // 00401905: mov ss:[esp], eax
         // 00401908: call 0x4cdb00
         // 0040190d: mov ss:[esp], 0x4cba40
         // 00401914: mov ecx, eax
         // 00401916: call 0x490df0
         // 0040191b: sub esp, 0x4
      [-]5589e583ec38c74424????????00c74424????????00c7442410????????c74424????????00c74424????????00c74424????????c08b4508890424e82e28030083ec1c8945f4837df4ff7516
         // 004019e1: push ebp
         // 004019e2: mov ebp, esp
         // 004019e4: sub esp, 0x38
         // 004019e7: mov ss:[esp+0x18], 0x0
         // 004019ef: mov ss:[esp+0x14], 0x0
         // 004019f7: mov ss:[esp+0x10], 0x3
         // 004019ff: mov ss:[esp+0xc], 0x0
         // 00401a07: mov ss:[esp+0x8], 0x0
         // 00401a0f: mov ss:[esp+0x4], 0xffffffffc0000000
         // 00401a17: mov eax, ss:[ebp+0x8]
         // 00401a1a: mov ss:[esp], eax
         // 00401a1d: call CreateFileA
         // 00401a22: sub esp, 0x1c
         // 00401a25: mov ss:[ebp+0xfffffffffffffff4], eax
         // 00401a28: cmp ss:[ebp+0xfffffffffffffff4], 0xffffffffffffffff
         // 00401a2c: jnz 0x401a44
      [-]e84527030083f8200f94c084c07415
         // 00401a2e: call GetLastError
         // 00401a33: cmp eax, 0x20
         // 00401a36: setz b1 al
         // 00401a39: test b1 al, b1 al
         // 00401a3b: jz 0x401a52
      [-]b8????????eb13
         // 00401a3d: mov eax, 0x1
         // 00401a42: jmp 0x401a57
      [-]8b45f4890424e81928030083ec04
         // 00401a44: mov eax, ss:[ebp+0xfffffffffffffff4]
         // 00401a47: mov ss:[esp], eax
         // 00401a4a: call CloseHandle
         // 00401a4f: sub esp, 0x4
      [-]b8????????
         // 00401a52: mov eax, 0x0
      [-]5589e557565381ec????????c785????????????????c785????????????????8d85????????8928ba????????8950048960088d85????????890424e8e68202008d85????????c7442404????????8b5508891424c785????????????????89c1e841830a0083ec088d85????????83c070c785????????????????89c1e884dc070084c0740c
         // 00401a59: push ebp
         // 00401a5a: mov ebp, esp
         // 00401a5c: push edi
         // 00401a5d: push esi
         // 00401a5e: push ebx
         // 00401a5f: sub esp, 0x17c
         // 00401a65: mov ss:[ebp+0xfffffffffffffeac], 0x403d70
         // 00401a6f: mov ss:[ebp+0xfffffffffffffeb0], 0x4d19d6
         // 00401a79: lea eax, ss:[ebp+0xfffffffffffffeb4]
         // 00401a7f: mov ds:[eax], ebp
         // 00401a81: mov edx, 0x401bf5
         // 00401a86: mov ds:[eax+0x4], edx
         // 00401a89: mov ds:[eax+0x8], esp
         // 00401a8c: lea eax, ss:[ebp+0xfffffffffffffe94]
         // 00401a92: mov ss:[esp], eax
         // 00401a95: call 0x429d80
         // 00401a9a: lea eax, ss:[ebp+0xfffffffffffffed8]
         // 00401aa0: mov ss:[esp+0x4], 0x4
         // 00401aa8: mov edx, ss:[ebp+0x8]
         // 00401aab: mov ss:[esp], edx
         // 00401aae: mov ss:[ebp+0xfffffffffffffe98], 0xffffffffffffffff
         // 00401ab8: mov ecx, eax
         // 00401aba: call 0x4a9e00
         // 00401abf: sub esp, 0x8
         // 00401ac2: lea eax, ss:[ebp+0xfffffffffffffed8]
         // 00401ac8: add eax, 0x70
         // 00401acb: mov ss:[ebp+0xfffffffffffffe98], 0x1
         // 00401ad5: mov ecx, eax
         // 00401ad7: call 0x47f760
         // 00401adc: test b1 al, b1 al
         // 00401ade: jz 0x401aec
      [-]c68590feffff00e9ed000000
         // 00401ae0: mov b1 ss:[ebp+0xfffffffffffffe90], b1 0x0
         // 00401ae7: jmp 0x401bd9
      [-]8d85????????c7442408????????c70424????????c74424????????00c785????????????????89c1e896af080083ec0c8d45d08d95????????89142489c1e850b1080083ec048d45d089c1e8c33d04008945e4837de402770c
         // 00401aec: lea eax, ss:[ebp+0xfffffffffffffed8]
         // 00401af2: mov ss:[esp+0x8], 0x2
         // 00401afa: mov ss:[esp], 0x0
         // 00401b01: mov ss:[esp+0x4], 0x0
         // 00401b09: mov ss:[ebp+0xfffffffffffffe98], 0x1
         // 00401b13: mov ecx, eax
         // 00401b15: call 0x48cab0
         // 00401b1a: sub esp, 0xc
         // 00401b1d: lea eax, ss:[ebp+0xffffffffffffffd0]
         // 00401b20: lea edx, ss:[ebp+0xfffffffffffffed8]
         // 00401b26: mov ss:[esp], edx
         // 00401b29: mov ecx, eax
         // 00401b2b: call 0x48cc80
         // 00401b30: sub esp, 0x4
         // 00401b33: lea eax, ss:[ebp+0xffffffffffffffd0]
         // 00401b36: mov ecx, eax
         // 00401b38: call 0x445900
         // 00401b3d: mov ss:[ebp+0xffffffffffffffe4], eax
         // 00401b40: cmp ss:[ebp+0xffffffffffffffe4], 0x2
         // 00401b44: ja 0x401b52
      [-]c68590feffff00e987000000
         // 00401b46: mov b1 ss:[ebp+0xfffffffffffffe90], b1 0x0
         // 00401b4d: jmp 0x401bd9
      [-]8b45e483e803ba????????8d8d????????c74424????????0089042489542404c785????????????????e82faf080083ec0c8d85????????c7442404????????8d95????????89142489c1e8eea8080083ec088d85????????89c1e86e800a00c7442408????????c7442404????????8d85????????890424e878de030085c00f948590feffff
         // 00401b52: mov eax, ss:[ebp+0xffffffffffffffe4]
         // 00401b55: sub eax, 0x3
         // 00401b58: mov edx, 0x0
         // 00401b5d: lea ecx, ss:[ebp+0xfffffffffffffed8]
         // 00401b63: mov ss:[esp+0x8], 0x0
         // 00401b6b: mov ss:[esp], eax
         // 00401b6e: mov ss:[esp+0x4], edx
         // 00401b72: mov ss:[ebp+0xfffffffffffffe98], 0x1
         // 00401b7c: call 0x48cab0
         // 00401b81: sub esp, 0xc
         // 00401b84: lea eax, ss:[ebp+0xfffffffffffffed8]
         // 00401b8a: mov ss:[esp+0x4], 0x3
         // 00401b92: lea edx, ss:[ebp+0xfffffffffffffed5]
         // 00401b98: mov ss:[esp], edx
         // 00401b9b: mov ecx, eax
         // 00401b9d: call 0x48c490
         // 00401ba2: sub esp, 0x8
         // 00401ba5: lea eax, ss:[ebp+0xfffffffffffffed8]
         // 00401bab: mov ecx, eax
         // 00401bad: call 0x4a9c20
         // 00401bb2: mov ss:[esp+0x8], 0x3
         // 00401bba: mov ss:[esp+0x4], 0x4d5054
         // 00401bc2: lea eax, ss:[ebp+0xfffffffffffffed5]
         // 00401bc8: mov ss:[esp], eax
         // 00401bcb: call memcmp
         // 00401bd0: test eax, eax
         // 00401bd2: setz b1 ss:[ebp+0xfffffffffffffe90]
      [-]8d85????????89c1e80a900a000fb68590feffff888590feffffeb31
         // 00401bd9: lea eax, ss:[ebp+0xfffffffffffffed8]
         // 00401bdf: mov ecx, eax
         // 00401be1: call 0x4aabf0
         // 00401be6: movzx eax, b1 ss:[ebp+0xfffffffffffffe90]
         // 00401bed: mov b1 ss:[ebp+0xfffffffffffffe90], b1 al
         // 00401bf3: jmp 0x401c26
      [-]8d85????????890424e81c8402000fb68590feffff8d65f45b5e5f5dc3
         // 00401c26: lea eax, ss:[ebp+0xfffffffffffffe94]
         // 00401c2c: mov ss:[esp], eax
         // 00401c2f: call 0x42a050
         // 00401c34: movzx eax, b1 ss:[ebp+0xfffffffffffffe90]
         // 00401c3b: lea esp, ss:[ebp+0xfffffffffffffff4]
         // 00401c3e: pop ebx
         // 00401c3f: pop esi
         // 00401c40: pop edi
         // 00401c41: pop ebp
         // 00401c42: retn 
      [-]5589e583ec28c70424????????e83325030083ec048945f4837df4ff7411
         // 00401c43: push ebp
         // 00401c44: mov ebp, esp
         // 00401c46: sub esp, 0x28
         // 00401c49: mov ss:[esp], 0x4d5058
         // 00401c50: call GetFileAttributesA
         // 00401c55: sub esp, 0x4
         // 00401c58: mov ss:[ebp+0xfffffffffffffff4], eax
         // 00401c5b: cmp ss:[ebp+0xfffffffffffffff4], 0xffffffffffffffff
         // 00401c5f: jz 0x401c72
      [-]8b45f483e01085c07507
         // 00401c61: mov eax, ss:[ebp+0xfffffffffffffff4]
         // 00401c64: and eax, 0x10
         // 00401c67: test eax, eax
         // 00401c69: jnz 0x401c72
      [-]b8????????eb05
         // 00401c6b: mov eax, 0x1
         // 00401c70: jmp 0x401c77
      [-]b8????????
         // 00401c72: mov eax, 0x0
      [-]5589e557565381ec????????c785????????????????c785????????????????8d85????????8928ba????????8950048960088d85????????890424e8c68002008b4d08e8d6820b00c745????????ff8d85????????c7442408????????8b551089542404890424c785????????????????e830cc0c008d85????????89c1e8e36b04008d95????????89542404890424c785????????????????e8c724030083ec088945e4837de4ff0f844e030000
         // 00401c79: push ebp
         // 00401c7a: mov ebp, esp
         // 00401c7c: push edi
         // 00401c7d: push esi
         // 00401c7e: push ebx
         // 00401c7f: sub esp, 0x34c
         // 00401c85: mov ss:[ebp+0xfffffffffffffcdc], 0x403d70
         // 00401c8f: mov ss:[ebp+0xfffffffffffffce0], 0x4d19dc
         // 00401c99: lea eax, ss:[ebp+0xfffffffffffffce4]
         // 00401c9f: mov ds:[eax], ebp
         // 00401ca1: mov edx, 0x402174
         // 00401ca6: mov ds:[eax+0x4], edx
         // 00401ca9: mov ds:[eax+0x8], esp
         // 00401cac: lea eax, ss:[ebp+0xfffffffffffffcc4]
         // 00401cb2: mov ss:[esp], eax
         // 00401cb5: call 0x429d80
         // 00401cba: mov ecx, ss:[ebp+0x8]
         // 00401cbd: call 0x4b9f98
         // 00401cc2: mov ss:[ebp+0xffffffffffffffe4], 0xffffffffffffffff
         // 00401cc9: lea eax, ss:[ebp+0xfffffffffffffd40]
         // 00401ccf: mov ss:[esp+0x8], 0x4d5074
         // 00401cd7: mov edx, ss:[ebp+0x10]
         // 00401cda: mov ss:[esp+0x4], edx
         // 00401cde: mov ss:[esp], eax
         // 00401ce1: mov ss:[ebp+0xfffffffffffffcc8], 0x1
         // 00401ceb: call 0x4ce920
         // 00401cf0: lea eax, ss:[ebp+0xfffffffffffffd40]
         // 00401cf6: mov ecx, eax
         // 00401cf8: call 0x4488e0
         // 00401cfd: lea edx, ss:[ebp+0xfffffffffffffd58]
         // 00401d03: mov ss:[esp+0x4], edx
         // 00401d07: mov ss:[esp], eax
         // 00401d0a: mov ss:[ebp+0xfffffffffffffcc8], 0x2
         // 00401d14: call FindFirstFileW
         // 00401d19: sub esp, 0x8
         // 00401d1c: mov ss:[ebp+0xffffffffffffffe4], eax
         // 00401d1f: cmp ss:[ebp+0xffffffffffffffe4], 0xffffffffffffffff
         // 00401d23: jz 0x402077
      [-]8d45ab89c1e84d4e08008d85????????8d55ab895424048d95????????83c22c891424c785????????????????89c1e893f70b0083ec088d45ab89c1e8464e08008d45acc7442408????????8b551089542404890424c785????????????????e892cb0c008d85????????8d95????????895424088d55ac89542404890424c785????????????????e829ca0c008d45ac89c1e83f000c00c7442404????????8d85????????890424e8a1bc0c0084c0751a
         // 00401d29: lea eax, ss:[ebp+0xffffffffffffffab]
         // 00401d2c: mov ecx, eax
         // 00401d2e: call 0x486b80
         // 00401d33: lea eax, ss:[ebp+0xfffffffffffffd28]
         // 00401d39: lea edx, ss:[ebp+0xffffffffffffffab]
         // 00401d3c: mov ss:[esp+0x4], edx
         // 00401d40: lea edx, ss:[ebp+0xfffffffffffffd58]
         // 00401d46: add edx, 0x2c
         // 00401d49: mov ss:[esp], edx
         // 00401d4c: mov ss:[ebp+0xfffffffffffffcc8], 0x3
         // 00401d56: mov ecx, eax
         // 00401d58: call 0x4c14f0
         // 00401d5d: sub esp, 0x8
         // 00401d60: lea eax, ss:[ebp+0xffffffffffffffab]
         // 00401d63: mov ecx, eax
         // 00401d65: call 0x486bb0
         // 00401d6a: lea eax, ss:[ebp+0xffffffffffffffac]
         // 00401d6d: mov ss:[esp+0x8], 0x4d507a
         // 00401d75: mov edx, ss:[ebp+0x10]
         // 00401d78: mov ss:[esp+0x4], edx
         // 00401d7c: mov ss:[esp], eax
         // 00401d7f: mov ss:[ebp+0xfffffffffffffcc8], 0x4
         // 00401d89: call 0x4ce920
         // 00401d8e: lea eax, ss:[ebp+0xfffffffffffffd10]
         // 00401d94: lea edx, ss:[ebp+0xfffffffffffffd28]
         // 00401d9a: mov ss:[esp+0x8], edx
         // 00401d9e: lea edx, ss:[ebp+0xffffffffffffffac]
         // 00401da1: mov ss:[esp+0x4], edx
         // 00401da5: mov ss:[esp], eax
         // 00401da8: mov ss:[ebp+0xfffffffffffffcc8], 0x5
         // 00401db2: call 0x4ce7e0
         // 00401db7: lea eax, ss:[ebp+0xffffffffffffffac]
         // 00401dba: mov ecx, eax
         // 00401dbc: call 0x4c1e00
         // 00401dc1: mov ss:[esp+0x4], 0x4d507e
         // 00401dc9: lea eax, ss:[ebp+0xfffffffffffffd28]
         // 00401dcf: mov ss:[esp], eax
         // 00401dd2: call 0x4cda78
         // 00401dd7: test b1 al, b1 al
         // 00401dd9: jnz 0x401df5
      [-]c7442404????????8d85????????890424e887bc0c0084c07407
         // 00401ddb: mov ss:[esp+0x4], 0x4d5082
         // 00401de3: lea eax, ss:[ebp+0xfffffffffffffd28]
         // 00401de9: mov ss:[esp], eax
         // 00401dec: call 0x4cda78
         // 00401df1: test b1 al, b1 al
         // 00401df3: jz 0x401dfc
      [-]b8????????eb05
         // 00401df5: mov eax, 0x1
         // 00401dfa: jmp 0x401e01
      [-]b8????????
         // 00401dfc: mov eax, 0x0
      [-]84c0740f
         // 00401e01: test b1 al, b1 al
         // 00401e03: jz 0x401e14
      [-]c785????????????????e9d9010000
         // 00401e05: mov ss:[ebp+0xfffffffffffffcbc], 0x0
         // 00401e0f: jmp 0x401fed
      [-]8b85????????83e01085c00f8401010000
         // 00401e14: mov eax, ss:[ebp+0xfffffffffffffd58]
         // 00401e1a: and eax, 0x10
         // 00401e1d: test eax, eax
         // 00401e1f: jz 0x401f26
      [-]c7442404????????8d85????????890424e83dbc0c0084c0751a
         // 00401e25: mov ss:[esp+0x4], 0x4d5088
         // 00401e2d: lea eax, ss:[ebp+0xfffffffffffffd10]
         // 00401e33: mov ss:[esp], eax
         // 00401e36: call 0x4cda78
         // 00401e3b: test b1 al, b1 al
         // 00401e3d: jnz 0x401e59
      [-]c7442404????????8d85????????890424e823bc0c0084c07407
         // 00401e3f: mov ss:[esp+0x4], 0x4d50b0
         // 00401e47: lea eax, ss:[ebp+0xfffffffffffffd10]
         // 00401e4d: mov ss:[esp], eax
         // 00401e50: call 0x4cda78
         // 00401e55: test b1 al, b1 al
         // 00401e57: jz 0x401e60
      [-]b8????????eb05
         // 00401e59: mov eax, 0x1
         // 00401e5e: jmp 0x401e65
      [-]b8????????
         // 00401e60: mov eax, 0x0
      [-]84c0740f
         // 00401e65: test b1 al, b1 al
         // 00401e67: jz 0x401e78
      [-]c785????????????????e975010000
         // 00401e69: mov ss:[ebp+0xfffffffffffffcbc], 0x0
         // 00401e73: jmp 0x401fed
      [-]8d85????????8d95????????895424088b550c89542404890424c785????????????????e8d8fdffff8d85????????89c1e89a7f0b008985????????8d85????????89c1e8ab7f0b008985????????8b4d08e8797f0b008945c88d45c48d55c889142489c1e886ef030083ec048b9d????????895c24088b85????????894424048b45c4890424c785????????????????8b4d08e87f7f0b0083ec0c8d85????????89c1e88f800b00e9bd000000
         // 00401e78: lea eax, ss:[ebp+0xfffffffffffffd04]
         // 00401e7e: lea edx, ss:[ebp+0xfffffffffffffd10]
         // 00401e84: mov ss:[esp+0x8], edx
         // 00401e88: mov edx, ss:[ebp+0xc]
         // 00401e8b: mov ss:[esp+0x4], edx
         // 00401e8f: mov ss:[esp], eax
         // 00401e92: mov ss:[ebp+0xfffffffffffffcc8], 0x7
         // 00401e9c: call 0x401c79
         // 00401ea1: lea eax, ss:[ebp+0xfffffffffffffd04]
         // 00401ea7: mov ecx, eax
         // 00401ea9: call 0x4b9e48
         // 00401eae: mov ss:[ebp+0xfffffffffffffcb8], eax
         // 00401eb4: lea eax, ss:[ebp+0xfffffffffffffd04]
         // 00401eba: mov ecx, eax
         // 00401ebc: call 0x4b9e6c
         // 00401ec1: mov ss:[ebp+0xfffffffffffffcbc], eax
         // 00401ec7: mov ecx, ss:[ebp+0x8]
         // 00401eca: call 0x4b9e48
         // 00401ecf: mov ss:[ebp+0xffffffffffffffc8], eax
         // 00401ed2: lea eax, ss:[ebp+0xffffffffffffffc4]
         // 00401ed5: lea edx, ss:[ebp+0xffffffffffffffc8]
         // 00401ed8: mov ss:[esp], edx
         // 00401edb: mov ecx, eax
         // 00401edd: call 0x440e68
         // 00401ee2: sub esp, 0x4
         // 00401ee5: mov ebx, ss:[ebp+0xfffffffffffffcb8]
         // 00401eeb: mov ss:[esp+0x8], ebx
         // 00401eef: mov eax, ss:[ebp+0xfffffffffffffcbc]
         // 00401ef5: mov ss:[esp+0x4], eax
         // 00401ef9: mov eax, ss:[ebp+0xffffffffffffffc4]
         // 00401efc: mov ss:[esp], eax
         // 00401eff: mov ss:[ebp+0xfffffffffffffcc8], 0x6
         // 00401f09: mov ecx, ss:[ebp+0x8]
         // 00401f0c: call 0x4b9e90
         // 00401f11: sub esp, 0xc
         // 00401f14: lea eax, ss:[ebp+0xfffffffffffffd04]
         // 00401f1a: mov ecx, eax
         // 00401f1c: call 0x4b9fb0
         // 00401f21: jmp 0x401fe3
      [-]c685c0fcffff008d85????????89c1e88669040083f8047663
         // 00401f26: mov b1 ss:[ebp+0xfffffffffffffcc0], b1 0x0
         // 00401f2d: lea eax, ss:[ebp+0xfffffffffffffd28]
         // 00401f33: mov ecx, eax
         // 00401f35: call 0x4488c0
         // 00401f3a: cmp eax, 0x4
         // 00401f3d: jbe 0x401fa2
      [-]8d85????????89c1e8746904008d50fc8d45ccc7442408????????895424048d95????????891424c785????????????????89c1e8986b040083ec0cc685c0fcffff01c7442404????????8d45cc890424e8e3ba0c0084c07409
         // 00401f3f: lea eax, ss:[ebp+0xfffffffffffffd28]
         // 00401f45: mov ecx, eax
         // 00401f47: call 0x4488c0
         // 00401f4c: lea edx, ds:[eax+0xfffffffffffffffc]
         // 00401f4f: lea eax, ss:[ebp+0xffffffffffffffcc]
         // 00401f52: mov ss:[esp+0x8], 0xffffffffffffffff
         // 00401f5a: mov ss:[esp+0x4], edx
         // 00401f5e: lea edx, ss:[ebp+0xfffffffffffffd28]
         // 00401f64: mov ss:[esp], edx
         // 00401f67: mov ss:[ebp+0xfffffffffffffcc8], 0x8
         // 00401f71: mov ecx, eax
         // 00401f73: call 0x448b10
         // 00401f78: sub esp, 0xc
         // 00401f7b: mov b1 ss:[ebp+0xfffffffffffffcc0], b1 0x1
         // 00401f82: mov ss:[esp+0x4], 0x4d50d8
         // 00401f8a: lea eax, ss:[ebp+0xffffffffffffffcc]
         // 00401f8d: mov ss:[esp], eax
         // 00401f90: call 0x4cda78
         // 00401f95: test b1 al, b1 al
         // 00401f97: jz 0x401fa2
      [-]c685bcfcffff01eb07
         // 00401f99: mov b1 ss:[ebp+0xfffffffffffffcbc], b1 0x1
         // 00401fa0: jmp 0x401fa9
      [-]c685bcfcffff00
         // 00401fa2: mov b1 ss:[ebp+0xfffffffffffffcbc], b1 0x0
      [-]80bdc0fcffff00740a
         // 00401fa9: cmp b1 ss:[ebp+0xfffffffffffffcc0], b1 0x0
         // 00401fb0: jz 0x401fbc
      [-]8d45cc89c1e844fe0b00
         // 00401fb2: lea eax, ss:[ebp+0xffffffffffffffcc]
         // 00401fb5: mov ecx, eax
         // 00401fb7: call 0x4c1e00
      [-]80bdbcfcffff00741e
         // 00401fbc: cmp b1 ss:[ebp+0xfffffffffffffcbc], b1 0x0
         // 00401fc3: jz 0x401fe3
      [-]8d85????????890424c785????????????????8b4d08e8487f0b0083ec04
         // 00401fc5: lea eax, ss:[ebp+0xfffffffffffffd10]
         // 00401fcb: mov ss:[esp], eax
         // 00401fce: mov ss:[ebp+0xfffffffffffffcc8], 0x7
         // 00401fd8: mov ecx, ss:[ebp+0x8]
         // 00401fdb: call 0x4b9f28
         // 00401fe0: sub esp, 0x4
      [-]c785????????????????
         // 00401fe3: mov ss:[ebp+0xfffffffffffffcbc], 0x1
      [-]8d85????????89c1e806fe0b0083bd????????01740c
         // 00401fed: lea eax, ss:[ebp+0xfffffffffffffd10]
         // 00401ff3: mov ecx, eax
         // 00401ff5: call 0x4c1e00
         // 00401ffa: cmp ss:[ebp+0xfffffffffffffcbc], 0x1
         // 00402001: jz 0x40200f
      [-]c785????????????????eb0a
         // 00402003: mov ss:[ebp+0xfffffffffffffcbc], 0x0
         // 0040200d: jmp 0x402019
      [-]c785????????????????
         // 0040200f: mov ss:[ebp+0xfffffffffffffcbc], 0x1
      [-]8d85????????89c1e8dafd0b0083bd????????018d85????????894424048b45e4890424c785????????????????e88c21030083ec0885c00f95c084c07405
         // 00402019: lea eax, ss:[ebp+0xfffffffffffffd28]
         // 0040201f: mov ecx, eax
         // 00402021: call 0x4c1e00
         // 00402026: cmp ss:[ebp+0xfffffffffffffcbc], 0x1
         // 0040202d: lea eax, ss:[ebp+0xfffffffffffffd58]
         // 00402033: mov ss:[esp+0x4], eax
         // 00402037: mov eax, ss:[ebp+0xffffffffffffffe4]
         // 0040203a: mov ss:[esp], eax
         // 0040203d: mov ss:[ebp+0xfffffffffffffcc8], 0x2
         // 00402047: call FindNextFileW
         // 0040204c: sub esp, 0x8
         // 0040204f: test eax, eax
         // 00402051: setnz b1 al
         // 00402054: test b1 al, b1 al
         // 00402056: jz 0x40205d
      [-]e9ccfcffff
         // 00402058: jmp 0x401d29
      [-]8b45e4890424c785????????????????e87621030083ec04eb01
         // 0040205d: mov eax, ss:[ebp+0xffffffffffffffe4]
         // 00402060: mov ss:[esp], eax
         // 00402063: mov ss:[ebp+0xfffffffffffffcc8], 0x2
         // 0040206d: call FindClose
         // 00402072: sub esp, 0x4
         // 00402075: jmp 0x402078
      [-]8d85????????89c1e87bfd0b00e934010000
         // 00402078: lea eax, ss:[ebp+0xfffffffffffffd40]
         // 0040207e: mov ecx, eax
         // 00402080: call 0x4c1e00
         // 00402085: jmp 0x4021be
      [-]8d85????????890424e8847e02008b45088d65f45b5e5f5dc3
         // 004021be: lea eax, ss:[ebp+0xfffffffffffffcc4]
         // 004021c4: mov ss:[esp], eax
         // 004021c7: call 0x42a050
         // 004021cc: mov eax, ss:[ebp+0x8]
         // 004021cf: lea esp, ss:[ebp+0xfffffffffffffff4]
         // 004021d2: pop ebx
         // 004021d3: pop esi
         // 004021d4: pop edi
         // 004021d5: pop ebp
         // 004021d6: retn 
      [-]5589e583ec488b45148945f48b450c894424088b4510894424048b4508890424e8d41f030083ec0c8945f0837df0000f8485000000
         // 004021d7: push ebp
         // 004021d8: mov ebp, esp
         // 004021da: sub esp, 0x48
         // 004021dd: mov eax, ss:[ebp+0x14]
         // 004021e0: mov ss:[ebp+0xfffffffffffffff4], eax
         // 004021e3: mov eax, ss:[ebp+0xc]
         // 004021e6: mov ss:[esp+0x8], eax
         // 004021ea: mov eax, ss:[ebp+0x10]
         // 004021ed: mov ss:[esp+0x4], eax
         // 004021f1: mov eax, ss:[ebp+0x8]
         // 004021f4: mov ss:[esp], eax
         // 004021f7: call FindResourceA
         // 004021fc: sub esp, 0xc
         // 004021ff: mov ss:[ebp+0xfffffffffffffff0], eax
         // 00402202: cmp ss:[ebp+0xfffffffffffffff0], 0x0
         // 00402206: jz 0x402291
      [-]8b45f0894424048b4508890424e8e21e030083ec088945ec837dec007467
         // 0040220c: mov eax, ss:[ebp+0xfffffffffffffff0]
         // 0040220f: mov ss:[esp+0x4], eax
         // 00402213: mov eax, ss:[ebp+0x8]
         // 00402216: mov ss:[esp], eax
         // 00402219: call LoadResource
         // 0040221e: sub esp, 0x8
         // 00402221: mov ss:[ebp+0xffffffffffffffec], eax
         // 00402224: cmp ss:[ebp+0xffffffffffffffec], 0x0
         // 00402228: jz 0x402291
      [-]8b45ec890424e8bb1e030083ec048945e88b45f0894424048b4508890424e8131e030083ec088945e4837de8007438
         // 0040222a: mov eax, ss:[ebp+0xffffffffffffffec]
         // 0040222d: mov ss:[esp], eax
         // 00402230: call LockResource
         // 00402235: sub esp, 0x4
         // 00402238: mov ss:[ebp+0xffffffffffffffe8], eax
         // 0040223b: mov eax, ss:[ebp+0xfffffffffffffff0]
         // 0040223e: mov ss:[esp+0x4], eax
         // 00402242: mov eax, ss:[ebp+0x8]
         // 00402245: mov ss:[esp], eax
         // 00402248: call SizeofResource
         // 0040224d: sub esp, 0x8
         // 00402250: mov ss:[ebp+0xffffffffffffffe4], eax
         // 00402253: cmp ss:[ebp+0xffffffffffffffe8], 0x0
         // 00402257: jz 0x402291
      [-]837de4007432
         // 00402259: cmp ss:[ebp+0xffffffffffffffe4], 0x0
         // 0040225d: jz 0x402291
      [-]8b45e4894424148b45e889442410c74424????????008b4510894424088b450c894424048b45f4890424e89a1d030083ec18
         // 0040225f: mov eax, ss:[ebp+0xffffffffffffffe4]
         // 00402262: mov ss:[esp+0x14], eax
         // 00402266: mov eax, ss:[ebp+0xffffffffffffffe8]
         // 00402269: mov ss:[esp+0x10], eax
         // 0040226d: mov ss:[esp+0xc], 0x0
         // 00402275: mov eax, ss:[ebp+0x10]
         // 00402278: mov ss:[esp+0x8], eax
         // 0040227c: mov eax, ss:[ebp+0xc]
         // 0040227f: mov ss:[esp+0x4], eax
         // 00402283: mov eax, ss:[ebp+0xfffffffffffffff4]
         // 00402286: mov ss:[esp], eax
         // 00402289: call UpdateResourceA
         // 0040228e: sub esp, 0x18
      [-]b8????????c9c21000
         // 00402291: mov eax, 0x1
         // 00402296: leave 
         // 00402297: retn b2 0x10
      [-]5589e583ec28c7442408????????c74424????????008b4508890424e84d1e030083ec0c8945f4837df4007479
         // 0040229a: push ebp
         // 0040229b: mov ebp, esp
         // 0040229d: sub esp, 0x28
         // 004022a0: mov ss:[esp+0x8], 0x2
         // 004022a8: mov ss:[esp+0x4], 0x0
         // 004022b0: mov eax, ss:[ebp+0x8]
         // 004022b3: mov ss:[esp], eax
         // 004022b6: call LoadLibraryExA
         // 004022bb: sub esp, 0xc
         // 004022be: mov ss:[ebp+0xfffffffffffffff4], eax
         // 004022c1: cmp ss:[ebp+0xfffffffffffffff4], 0x0
         // 004022c5: jz 0x402340
      [-]c74424????????008b450c890424e8961f030083ec088945f0837df0007510
         // 004022c7: mov ss:[esp+0x4], 0x0
         // 004022cf: mov eax, ss:[ebp+0xc]
         // 004022d2: mov ss:[esp], eax
         // 004022d5: call BeginUpdateResourceA
         // 004022da: sub esp, 0x8
         // 004022dd: mov ss:[ebp+0xfffffffffffffff0], eax
         // 004022e0: cmp ss:[ebp+0xfffffffffffffff0], 0x0
         // 004022e4: jnz 0x4022f6
      [-]8b45f4890424e8cf1e030083ec04eb4b
         // 004022e6: mov eax, ss:[ebp+0xfffffffffffffff4]
         // 004022e9: mov ss:[esp], eax
         // 004022ec: call FreeLibrary
         // 004022f1: sub esp, 0x4
         // 004022f4: jmp 0x402341
      [-]8b45f08944240cc7442408????????8b4510894424048b45f4890424e8e91e030083ec10c74424????????008b45f0890424e8e31e030083ec088b45f4890424e8851e030083ec04eb01
         // 004022f6: mov eax, ss:[ebp+0xfffffffffffffff0]
         // 004022f9: mov ss:[esp+0xc], eax
         // 004022fd: mov ss:[esp+0x8], 0x4021d7
         // 00402305: mov eax, ss:[ebp+0x10]
         // 00402308: mov ss:[esp+0x4], eax
         // 0040230c: mov eax, ss:[ebp+0xfffffffffffffff4]
         // 0040230f: mov ss:[esp], eax
         // 00402312: call EnumResourceNamesA
         // 00402317: sub esp, 0x10
         // 0040231a: mov ss:[esp+0x4], 0x0
         // 00402322: mov eax, ss:[ebp+0xfffffffffffffff0]
         // 00402325: mov ss:[esp], eax
         // 00402328: call EndUpdateResourceA
         // 0040232d: sub esp, 0x8
         // 00402330: mov eax, ss:[ebp+0xfffffffffffffff4]
         // 00402333: mov ss:[esp], eax
         // 00402336: call FreeLibrary
         // 0040233b: sub esp, 0x4
         // 0040233e: jmp 0x402341
      [-]5589e557565381ec????????c785????????????????c785????????????????8d85????????8928ba????????8950048960088d85????????890424e8fc790200c7442404????????c70424????????e838be0c0089c28d85????????895424048b5508891424c785????????????????89c1e8457a0a0083ec088d85????????83c070c785????????????????89c1e888d3070084c0740c
         // 00402343: push ebp
         // 00402344: mov ebp, esp
         // 00402346: push edi
         // 00402347: push esi
         // 00402348: push ebx
         // 00402349: sub esp, 0x16c
         // 0040234f: mov ss:[ebp+0xfffffffffffffebc], 0x403d70
         // 00402359: mov ss:[ebp+0xfffffffffffffec0], 0x4d19f0
         // 00402363: lea eax, ss:[ebp+0xfffffffffffffec4]
         // 00402369: mov ds:[eax], ebp
         // 0040236b: mov edx, 0x402446
         // 00402370: mov ds:[eax+0x4], edx
         // 00402373: mov ds:[eax+0x8], esp
         // 00402376: lea eax, ss:[ebp+0xfffffffffffffea4]
         // 0040237c: mov ss:[esp], eax
         // 0040237f: call 0x429d80
         // 00402384: mov ss:[esp+0x4], 0x2
         // 0040238c: mov ss:[esp], 0x4
         // 00402393: call 0x4ce1d0
         // 00402398: mov edx, eax
         // 0040239a: lea eax, ss:[ebp+0xfffffffffffffed8]
         // 004023a0: mov ss:[esp+0x4], edx
         // 004023a4: mov edx, ss:[ebp+0x8]
         // 004023a7: mov ss:[esp], edx
         // 004023aa: mov ss:[ebp+0xfffffffffffffea8], 0xffffffffffffffff
         // 004023b4: mov ecx, eax
         // 004023b6: call 0x4a9e00
         // 004023bb: sub esp, 0x8
         // 004023be: lea eax, ss:[ebp+0xfffffffffffffed8]
         // 004023c4: add eax, 0x70
         // 004023c7: mov ss:[ebp+0xfffffffffffffea8], 0x1
         // 004023d1: mov ecx, eax
         // 004023d3: call 0x47f760
         // 004023d8: test b1 al, b1 al
         // 004023da: jz 0x4023e8
      [-]c785????????????????eb43
         // 004023dc: mov ss:[ebp+0xfffffffffffffea0], 0x0
         // 004023e6: jmp 0x40242b
      [-]8d45d08d95????????891424c785????????????????89c1e87ba8080083ec048d45d089c1e8ee3404008945e48d85????????89c1e8fe770a008b45e48985????????
         // 004023e8: lea eax, ss:[ebp+0xffffffffffffffd0]
         // 004023eb: lea edx, ss:[ebp+0xfffffffffffffed8]
         // 004023f1: mov ss:[esp], edx
         // 004023f4: mov ss:[ebp+0xfffffffffffffea8], 0x1
         // 004023fe: mov ecx, eax
         // 00402400: call 0x48cc80
         // 00402405: sub esp, 0x4
         // 00402408: lea eax, ss:[ebp+0xffffffffffffffd0]
         // 0040240b: mov ecx, eax
         // 0040240d: call 0x445900
         // 00402412: mov ss:[ebp+0xffffffffffffffe4], eax
         // 00402415: lea eax, ss:[ebp+0xfffffffffffffed8]
         // 0040241b: mov ecx, eax
         // 0040241d: call 0x4a9c20
         // 00402422: mov eax, ss:[ebp+0xffffffffffffffe4]
         // 00402425: mov ss:[ebp+0xfffffffffffffea0], eax
      [-]8d85????????89c1e8b8870a008b85????????8985????????eb31
         // 0040242b: lea eax, ss:[ebp+0xfffffffffffffed8]
         // 00402431: mov ecx, eax
         // 00402433: call 0x4aabf0
         // 00402438: mov eax, ss:[ebp+0xfffffffffffffea0]
         // 0040243e: mov ss:[ebp+0xfffffffffffffea0], eax
         // 00402444: jmp 0x402477
      [-]8d85????????890424e8cb7b02008b85????????8d65f45b5e5f5dc3
         // 00402477: lea eax, ss:[ebp+0xfffffffffffffea4]
         // 0040247d: mov ss:[esp], eax
         // 00402480: call 0x42a050
         // 00402485: mov eax, ss:[ebp+0xfffffffffffffea0]
         // 0040248b: lea esp, ss:[ebp+0xfffffffffffffff4]
         // 0040248e: pop ebx
         // 0040248f: pop esi
         // 00402490: pop edi
         // 00402491: pop ebp
         // 00402492: retn 
      [-]5589e557565381ec????????c785????????????????c785????????????????8d85????????8928ba????????8950048960088d85????????890424e8ac7802008b4508890424c785????????????????e8f8f4ffff84c07439
         // 00402493: push ebp
         // 00402494: mov ebp, esp
         // 00402496: push edi
         // 00402497: push esi
         // 00402498: push ebx
         // 00402499: sub esp, 0x36c
         // 0040249f: mov ss:[ebp+0xfffffffffffffcbc], 0x403d70
         // 004024a9: mov ss:[ebp+0xfffffffffffffcc0], 0x4d19f6
         // 004024b3: lea eax, ss:[ebp+0xfffffffffffffcc4]
         // 004024b9: mov ds:[eax], ebp
         // 004024bb: mov edx, 0x40293d
         // 004024c0: mov ds:[eax+0x4], edx
         // 004024c3: mov ds:[eax+0x8], esp
         // 004024c6: lea eax, ss:[ebp+0xfffffffffffffca4]
         // 004024cc: mov ss:[esp], eax
         // 004024cf: call 0x429d80
         // 004024d4: mov eax, ss:[ebp+0x8]
         // 004024d7: mov ss:[esp], eax
         // 004024da: mov ss:[ebp+0xfffffffffffffca8], 0xffffffffffffffff
         // 004024e4: call 0x4019e1
         // 004024e9: test b1 al, b1 al
         // 004024eb: jz 0x402526
      [-]c7442404????????c70424????????e8ffb50c008b550889542404890424e8f0b50c00c70424????????89c1e8d2e8080083ec04e948040000
         // 004024ed: mov ss:[esp+0x4], 0x4d5104
         // 004024f5: mov ss:[esp], 0x4e67c0
         // 004024fc: call 0x4cdb00
         // 00402501: mov edx, ss:[ebp+0x8]
         // 00402504: mov ss:[esp+0x4], edx
         // 00402508: mov ss:[esp], eax
         // 0040250b: call 0x4cdb00
         // 00402510: mov ss:[esp], 0x4cba40
         // 00402517: mov ecx, eax
         // 00402519: call 0x490df0
         // 0040251e: sub esp, 0x4
         // 00402521: jmp 0x40296e
      [-]8d85????????89442404c70424????????c785????????????????e8121c030083ec088d85????????89442404c70424????????e8f91b030083ec088d85????????890424e858d4030089c28d85????????01d0c700????????c74004????????c74008????????66c7400c7865c6400e008d85????????890424e822d4030089c28d85????????01d0c700????????c74004????????c74008????????c7400c????????66c7401065008d85????????894424048b4508890424e865f2ffff8d85????????894424048b450c890424e850f2ffffc7442408????????8d85????????894424048b4508890424e882fcffffc7442408????????8d85????????894424048b4508890424e865fcffff8d85????????890424e800fdffff8985????????8b85????????85c07535
         // 00402526: lea eax, ss:[ebp+0xfffffffffffffedc]
         // 0040252c: mov ss:[esp+0x4], eax
         // 00402530: mov ss:[esp], 0x104
         // 00402537: mov ss:[ebp+0xfffffffffffffca8], 0xffffffffffffffff
         // 00402541: call GetTempPathA
         // 00402546: sub esp, 0x8
         // 00402549: lea eax, ss:[ebp+0xfffffffffffffdd8]
         // 0040254f: mov ss:[esp+0x4], eax
         // 00402553: mov ss:[esp], 0x104
         // 0040255a: call GetTempPathA
         // 0040255f: sub esp, 0x8
         // 00402562: lea eax, ss:[ebp+0xfffffffffffffedc]
         // 00402568: mov ss:[esp], eax
         // 0040256b: call strlen
         // 00402570: mov edx, eax
         // 00402572: lea eax, ss:[ebp+0xfffffffffffffedc]
         // 00402578: add eax, edx
         // 0040257a: mov ds:[eax], 0x75726976
         // 00402580: mov ds:[eax+0x4], 0x65745f73
         // 00402587: mov ds:[eax+0x8], 0x652e706d
         // 0040258e: mov b2 ds:[eax+0xc], b2 0x6578
         // 00402594: mov b1 ds:[eax+0xe], b1 0x0
         // 00402598: lea eax, ss:[ebp+0xfffffffffffffdd8]
         // 0040259e: mov ss:[esp], eax
         // 004025a1: call strlen
         // 004025a6: mov edx, eax
         // 004025a8: lea eax, ss:[ebp+0xfffffffffffffdd8]
         // 004025ae: add eax, edx
         // 004025b0: mov ds:[eax], 0x6769726f
         // 004025b6: mov ds:[eax+0x4], 0x6c616e69
         // 004025bd: mov ds:[eax+0x8], 0x6d65745f
         // 004025c4: mov ds:[eax+0xc], 0x78652e70
         // 004025cb: mov b2 ds:[eax+0x10], b2 0x65
         // 004025d1: lea eax, ss:[ebp+0xfffffffffffffdd8]
         // 004025d7: mov ss:[esp+0x4], eax
         // 004025db: mov eax, ss:[ebp+0x8]
         // 004025de: mov ss:[esp], eax
         // 004025e1: call 0x40184b
         // 004025e6: lea eax, ss:[ebp+0xfffffffffffffedc]
         // 004025ec: mov ss:[esp+0x4], eax
         // 004025f0: mov eax, ss:[ebp+0xc]
         // 004025f3: mov ss:[esp], eax
         // 004025f6: call 0x40184b
         // 004025fb: mov ss:[esp+0x8], 0xe
         // 00402603: lea eax, ss:[ebp+0xfffffffffffffedc]
         // 00402609: mov ss:[esp+0x4], eax
         // 0040260d: mov eax, ss:[ebp+0x8]
         // 00402610: mov ss:[esp], eax
         // 00402613: call 0x40229a
         // 00402618: mov ss:[esp+0x8], 0x3
         // 00402620: lea eax, ss:[ebp+0xfffffffffffffedc]
         // 00402626: mov ss:[esp+0x4], eax
         // 0040262a: mov eax, ss:[ebp+0x8]
         // 0040262d: mov ss:[esp], eax
         // 00402630: call 0x40229a
         // 00402635: lea eax, ss:[ebp+0xfffffffffffffedc]
         // 0040263b: mov ss:[esp], eax
         // 0040263e: call 0x402343
         // 00402643: mov ss:[ebp+0xfffffffffffffdd4], eax
         // 00402649: mov eax, ss:[ebp+0xfffffffffffffdd4]
         // 0040264f: test eax, eax
         // 00402651: jnz 0x402688
      [-]c7442404????????c70424????????e899b40c008d85????????890424e858f2ffff8d85????????890424e84af2ffffe9e6020000
         // 00402653: mov ss:[esp+0x4], 0x4d5115
         // 0040265b: mov ss:[esp], 0x4e67c0
         // 00402662: call 0x4cdb00
         // 00402667: lea eax, ss:[ebp+0xfffffffffffffedc]
         // 0040266d: mov ss:[esp], eax
         // 00402670: call 0x4018cd
         // 00402675: lea eax, ss:[ebp+0xfffffffffffffdd8]
         // 0040267b: mov ss:[esp], eax
         // 0040267e: call 0x4018cd
         // 00402683: jmp 0x40296e
      [-]8d85????????c7442404????????8b5508891424c785????????????????89c1e853a90a0083ec088d85????????83c06cc785????????????????89c1e896d0070084c0745f
         // 00402688: lea eax, ss:[ebp+0xfffffffffffffce0]
         // 0040268e: mov ss:[esp+0x4], 0x4
         // 00402696: mov edx, ss:[ebp+0x8]
         // 00402699: mov ss:[esp], edx
         // 0040269c: mov ss:[ebp+0xfffffffffffffca8], 0xffffffffffffffff
         // 004026a6: mov ecx, eax
         // 004026a8: call 0x4ad000
         // 004026ad: sub esp, 0x8
         // 004026b0: lea eax, ss:[ebp+0xfffffffffffffce0]
         // 004026b6: add eax, 0x6c
         // 004026b9: mov ss:[ebp+0xfffffffffffffca8], 0x1
         // 004026c3: mov ecx, eax
         // 004026c5: call 0x47f760
         // 004026ca: test b1 al, b1 al
         // 004026cc: jz 0x40272d
      [-]c7442404????????c70424????????e81eb40c008b550889542404890424e80fb40c00c70424????????89c1e8f1e6080083ec048d85????????890424e8bdf1ffff8d85????????890424e8aff1ffffc785????????????????e9fa010000
         // 004026ce: mov ss:[esp+0x4], 0x4d5130
         // 004026d6: mov ss:[esp], 0x4e67c0
         // 004026dd: call 0x4cdb00
         // 004026e2: mov edx, ss:[ebp+0x8]
         // 004026e5: mov ss:[esp+0x4], edx
         // 004026e9: mov ss:[esp], eax
         // 004026ec: call 0x4cdb00
         // 004026f1: mov ss:[esp], 0x4cba40
         // 004026f8: mov ecx, eax
         // 004026fa: call 0x490df0
         // 004026ff: sub esp, 0x4
         // 00402702: lea eax, ss:[ebp+0xfffffffffffffedc]
         // 00402708: mov ss:[esp], eax
         // 0040270b: call 0x4018cd
         // 00402710: lea eax, ss:[ebp+0xfffffffffffffdd8]
         // 00402716: mov ss:[esp], eax
         // 00402719: call 0x4018cd
         // 0040271e: mov ss:[ebp+0xfffffffffffffca0], 0x0
         // 00402728: jmp 0x402927
      [-]8d85????????894424048d85????????890424c785????????????????e8ffeeffff8945e4837de4007435
         // 0040272d: lea eax, ss:[ebp+0xfffffffffffffdd4]
         // 00402733: mov ss:[esp+0x4], eax
         // 00402737: lea eax, ss:[ebp+0xfffffffffffffedc]
         // 0040273d: mov ss:[esp], eax
         // 00402740: mov ss:[ebp+0xfffffffffffffca8], 0x1
         // 0040274a: call 0x40164e
         // 0040274f: mov ss:[ebp+0xffffffffffffffe4], eax
         // 00402752: cmp ss:[ebp+0xffffffffffffffe4], 0x0
         // 00402756: jz 0x40278d
      [-]8b85????????89c28d85????????895424048b55e489142489c1e899c7080083ec08837de4007463
         // 00402758: mov eax, ss:[ebp+0xfffffffffffffdd4]
         // 0040275e: mov edx, eax
         // 00402760: lea eax, ss:[ebp+0xfffffffffffffce0]
         // 00402766: mov ss:[esp+0x4], edx
         // 0040276a: mov edx, ss:[ebp+0xffffffffffffffe4]
         // 0040276d: mov ss:[esp], edx
         // 00402770: mov ecx, eax
         // 00402772: call 0x48ef10
         // 00402777: sub esp, 0x8
         // 0040277a: cmp ss:[ebp+0xffffffffffffffe4], 0x0
         // 0040277e: jz 0x4027e3
      [-]8b45e4890424e8250b0000eb56
         // 00402780: mov eax, ss:[ebp+0xffffffffffffffe4]
         // 00402783: mov ss:[esp], eax
         // 00402786: call 0x4032b0
         // 0040278b: jmp 0x4027e3
      [-]c7442404????????c70424????????c785????????????????e855b30c008d85????????89c1e878a60a008d85????????890424e807f1ffff8d85????????890424e8f9f0ffffc785????????????????e944010000
         // 0040278d: mov ss:[esp+0x4], 0x4d5152
         // 00402795: mov ss:[esp], 0x4e67c0
         // 0040279c: mov ss:[ebp+0xfffffffffffffca8], 0x1
         // 004027a6: call 0x4cdb00
         // 004027ab: lea eax, ss:[ebp+0xfffffffffffffce0]
         // 004027b1: mov ecx, eax
         // 004027b3: call 0x4ace30
         // 004027b8: lea eax, ss:[ebp+0xfffffffffffffedc]
         // 004027be: mov ss:[esp], eax
         // 004027c1: call 0x4018cd
         // 004027c6: lea eax, ss:[ebp+0xfffffffffffffdd8]
         // 004027cc: mov ss:[esp], eax
         // 004027cf: call 0x4018cd
         // 004027d4: mov ss:[ebp+0xfffffffffffffca0], 0x0
         // 004027de: jmp 0x402927
      [-]8d85????????890424c785????????????????e848fbffff8985????????8d85????????894424048d85????????890424e835eeffff8945e0837de0007435
         // 004027e3: lea eax, ss:[ebp+0xfffffffffffffdd8]
         // 004027e9: mov ss:[esp], eax
         // 004027ec: mov ss:[ebp+0xfffffffffffffca8], 0x1
         // 004027f6: call 0x402343
         // 004027fb: mov ss:[ebp+0xfffffffffffffcdc], eax
         // 00402801: lea eax, ss:[ebp+0xfffffffffffffcdc]
         // 00402807: mov ss:[esp+0x4], eax
         // 0040280b: lea eax, ss:[ebp+0xfffffffffffffdd8]
         // 00402811: mov ss:[esp], eax
         // 00402814: call 0x40164e
         // 00402819: mov ss:[ebp+0xffffffffffffffe0], eax
         // 0040281c: cmp ss:[ebp+0xffffffffffffffe0], 0x0
         // 00402820: jz 0x402857
      [-]8b85????????89c28d85????????895424048b55e089142489c1e8cfc6080083ec08837de0007460
         // 00402822: mov eax, ss:[ebp+0xfffffffffffffcdc]
         // 00402828: mov edx, eax
         // 0040282a: lea eax, ss:[ebp+0xfffffffffffffce0]
         // 00402830: mov ss:[esp+0x4], edx
         // 00402834: mov edx, ss:[ebp+0xffffffffffffffe0]
         // 00402837: mov ss:[esp], edx
         // 0040283a: mov ecx, eax
         // 0040283c: call 0x48ef10
         // 00402841: sub esp, 0x8
         // 00402844: cmp ss:[ebp+0xffffffffffffffe0], 0x0
         // 00402848: jz 0x4028aa
      [-]8b45e0890424e85b0a0000eb53
         // 0040284a: mov eax, ss:[ebp+0xffffffffffffffe0]
         // 0040284d: mov ss:[esp], eax
         // 00402850: call 0x4032b0
         // 00402855: jmp 0x4028aa
      [-]c7442404????????c704
         // 00402857: mov ss:[esp+0x4], 0x4d5170
         // 0040285f: mov ss:[esp], 0x4e67c0
         // 00402866: mov ss:[ebp+0xfffffffffffffca8], 0x1
         // 00402870: call 0x4cdb00
         // 00402875: lea eax, ss:[ebp+0xfffffffffffffce0]
         // 0040287b: mov ecx, eax
         // 0040287d: call 0x4ace30
         // 00402882: lea eax, ss:[ebp+0xfffffffffffffedc]
         // 00402888: mov ss:[esp], eax
         // 0040288b: call 0x4018cd
         // 00402890: lea eax, ss:[ebp+0xfffffffffffffdd8]
         // 00402896: mov ss:[esp], eax
         // 00402899: call 0x4018cd
         // 0040289e: mov ss:[ebp+0xfffffffffffffca0], 0x0
         // 004028a8: jmp 0x402927

  }
  condition:
    all of them
}
