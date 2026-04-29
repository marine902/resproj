rule buterat_10_2 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         558bec83ec10f605
         // 00401010: push ebp
         // 00401011: mov ebp, esp
         // 00401013: sub esp, 0x10
         // 00401016: test b1 ds:[0x428804], b1 0x1
      [-]4200017513
         // 0040101d: jnz 0x401032
      [-]5333c9394d08568b750c57894df07515
         // 00401037: push ebx
         // 00401038: xor ecx, ecx
         // 0040103a: cmp ss:[ebp+0x8], ecx
         // 0040103d: push esi
         // 0040103e: mov esi, ss:[ebp+0xc]
         // 00401041: push edi
         // 00401042: mov ss:[ebp+0xfffffffffffffff0], ecx
         // 00401045: jnz 0x40105c
      [-]394d187544
         // 00401047: cmp ss:[ebp+0x18], ecx
         // 0040104a: jnz 0x401090
      [-]33db891d
         // 0040104c: xor ebx, ebx
         // 0040104e: mov ds:[0x4287a8], ebx
      [-]394d18752f
         // 00401062: cmp ss:[ebp+0x18], ecx
         // 00401065: jnz 0x401096
      [-]c6466701c6466804c646693c884e6ac6466b0ac6466c05898e
         // 00401067: mov b1 ds:[esi+0x67], b1 0x1
         // 0040106b: mov b1 ds:[esi+0x68], b1 0x4
         // 0040106f: mov b1 ds:[esi+0x69], b1 0x3c
         // 00401073: mov b1 ds:[esi+0x6a], b1 cl
         // 00401076: mov b1 ds:[esi+0x6b], b1 0xa
         // 0040107a: mov b1 ds:[esi+0x6c], b1 0x5
         // 0040107e: mov ds:[esi+0x80], ecx
      [-]c74660????????894e0ceb06
         // 00401084: mov ds:[esi+0x60], 0x3
         // 0040108b: mov ds:[esi+0xc], ecx
         // 0040108e: jmp 0x401096
      [-]8b7d143bf80f8d02020000
         // 00401096: mov edi, ss:[ebp+0x14]
         // 00401099: cmp edi, eax
         // 0040109b: jge 0x4012a3
      [-]6bc0033945180f8df6010000
         // 004010a1: imul eax, b1 0x3
         // 004010a4: cmp ss:[ebp+0x18], eax
         // 004010a7: jge 0x4012a3
      [-]394d10740e
         // 004010b6: cmp ss:[ebp+0x10], ecx
         // 004010b9: jz 0x4010c9
      [-]837d10057408
         // 004010bb: cmp ss:[ebp+0x10], 0x5
         // 004010bf: jz 0x4010c9
      [-]00008b1d
         // 004010ce: mov ebx, ds:[0x4287a8]
      [-]39017312
         // 004010db: cmp ds:[ecx], eax
         // 004010dd: jnb 0x4010f1
      [-]0fb6015032c9e8
         // 004010df: movzx eax, b1 ds:[ecx]
         // 004010e2: push eax
         // 004010e3: xor b1 cl, b1 cl
         // 004010e5: call 0x4076a9
      [-]00008b1d
         // 004010ea: mov ebx, ds:[0x4287a8]
      [-]0043891d
         // 004010f8: inc ebx
         // 004010f9: mov ds:[0x4287a8], ebx
      [-]837d1004750a
         // 00401101: cmp ss:[ebp+0x10], 0x4
         // 00401105: jnz 0x401111
      [-]8d470289049d
         // 00401107: lea eax, ds:[edi+0x2]
         // 0040110a: mov ds:[0x424660+ebx*0x4], eax
      [-]483bd87d6b
         // 0040111f: dec eax
         // 00401120: cmp ebx, eax
         // 00401122: jge 0x40118f
      [-]8bc3c1e0028d88
         // 00401124: mov eax, ebx
         // 00401126: shl eax, b1 0x2
         // 00401129: lea ecx, ds:[eax+0x424660]
      [-]8b118955088d90
         // 0040112f: mov edx, ds:[ecx]
         // 00401131: mov ss:[ebp+0x8], edx
         // 00401134: lea edx, ds:[eax+0x4241a0]
      [-]8b3a897df88325
         // 0040113a: mov edi, ds:[edx]
         // 0040113c: mov ss:[ebp+0xfffffffffffffff8], edi
         // 0040113f: and ds:[0x4287ac], 0x0
      [-]897d188b3f897df48db8
         // 0040114c: mov ss:[ebp+0x18], edi
         // 0040114f: mov edi, ds:[edi]
         // 00401151: mov ss:[ebp+0xfffffffffffffff4], edi
         // 00401154: lea edi, ds:[eax+0x424664]
      [-]897dfc8b3f89398d88
         // 0040115a: mov ss:[ebp+0xfffffffffffffffc], edi
         // 0040115d: mov edi, ds:[edi]
         // 0040115f: mov ds:[ecx], edi
         // 00401161: lea ecx, ds:[eax+0x4241a4]
      [-]8b39893a8b7d188d80
         // 00401167: mov edi, ds:[ecx]
         // 00401169: mov ds:[edx], edi
         // 0040116b: mov edi, ss:[ebp+0x18]
         // 0040116e: lea eax, ds:[eax+0x420e04]
      [-]8b1089178b55088b7dfc89178b55f88b7d1489118b4df4890833c9
         // 00401174: mov edx, ds:[eax]
         // 00401176: mov ds:[edi], edx
         // 00401178: mov edx, ss:[ebp+0x8]
         // 0040117b: mov edi, ss:[ebp+0xfffffffffffffffc]
         // 0040117e: mov ds:[edi], edx
         // 00401180: mov edx, ss:[ebp+0xfffffffffffffff8]
         // 00401183: mov edi, ss:[ebp+0x14]
         // 00401186: mov ds:[ecx], edx
         // 00401188: mov ecx, ss:[ebp+0xfffffffffffffff4]
         // 0040118b: mov ds:[eax], ecx
         // 0040118d: xor ecx, ecx
      [-]8bc3c1e0028945188b80
         // 0040118f: mov eax, ebx
         // 00401191: shl eax, b1 0x2
         // 00401194: mov ss:[ebp+0x18], eax
         // 00401197: mov eax, ds:[eax+0x4241a0]
      [-]3bc17409
         // 0040119d: cmp eax, ecx
         // 0040119f: jz 0x4011aa
      [-]668b0066a3
         // 004011a1: mov b2 ax, b2 ds:[eax]
         // 004011a4: mov b2 ds:[0x4246bc], b2 ax
      [-]8b5608e8
         // 004011b1: mov edx, ds:[esi+0x8]
         // 004011b4: call 0x40714a
      [-]0000ff368b15??
         // 004011b9: push ds:[esi]
         // 004011bb: mov edx, ds:[0x423c00]
      [-]0000ff7608ff36e8
         // 004011c6: push ds:[esi+0x8]
         // 004011c9: push ds:[esi]
         // 004011cb: call 0x405529
      [-]00008b45148b3c85
         // 004011d0: mov eax, ss:[ebp+0x14]
         // 004011d3: mov edi, ds:[0x41fde8+eax*0x4]
      [-]83c40c85ff7449
         // 004011da: add esp, 0xc
         // 004011dd: test edi, edi
         // 004011df: jz 0x40122a
      [-]000085c0ff7604741c
         // 004011e8: test eax, eax
         // 004011ea: push ds:[esi+0x4]
         // 004011ed: jz 0x40120b
      [-]0000ff7608ff7604e8
         // 004011fb: push ds:[esi+0x8]
         // 004011fe: push ds:[esi+0x4]
         // 00401201: call 0x405526
      [-]000083c40ceb08
         // 00401206: add esp, 0xc
         // 00401209: jmp 0x401213
      [-]8b7e048b5608e8
         // 00401213: mov edi, ds:[esi+0x4]
         // 00401216: mov edx, ds:[esi+0x8]
         // 00401219: call 0x407197
      [-]0000ff7608ff36e8
         // 0040121e: push ds:[esi+0x8]
         // 00401221: push ds:[esi]
         // 00401223: call 0x405526
      [-]00005959
         // 00401228: pop ecx
         // 00401229: pop ecx
      [-]8b45148d48018b45183b88
         // 00401232: mov eax, ss:[ebp+0x14]
         // 00401235: lea ecx, ds:[eax+0x1]
         // 00401238: mov eax, ss:[ebp+0x18]
         // 0040123b: cmp ecx, ds:[eax+0x424660]
      [-]c646650fc6466605c6466b00c6466c058bb8
         // 00401243: mov b1 ds:[esi+0x65], b1 0xf
         // 00401247: mov b1 ds:[esi+0x66], b1 0x5
         // 0040124b: mov b1 ds:[esi+0x6b], b1 0x0
         // 0040124f: mov b1 ds:[esi+0x6c], b1 0x5
         // 00401253: mov edi, ds:[eax+0x4205f0]
      [-]8bd743e8
         // 00401260: mov edx, edi
         // 00401262: inc ebx
         // 00401263: call 0x405467
      [-]000085c0ff76087505
         // 00401268: test eax, eax
         // 0040126a: push ds:[esi+0x8]
         // 0040126d: jnz 0x401274
      [-]8b5604eb02
         // 0040126f: mov edx, ds:[esi+0x4]
         // 00401272: jmp 0x401276
      [-]000059eb1a
         // 0040127b: pop ecx
         // 0040127c: jmp 0x401298
      [-]8b46088b5df0c6466502c6466604c6466b00c6466c0066832000
         // 0040127e: mov eax, ds:[esi+0x8]
         // 00401281: mov ebx, ss:[ebp+0xfffffffffffffff0]
         // 00401284: mov b1 ds:[esi+0x65], b1 0x2
         // 00401288: mov b1 ds:[esi+0x66], b1 0x4
         // 0040128c: mov b1 ds:[esi+0x6b], b1 0x0
         // 00401290: mov b1 ds:[esi+0x6c], b1 0x0
         // 00401294: and b2 ds:[eax], b2 0x0
      [-]33c0899e
         // 00401298: xor eax, eax
         // 0040129a: mov ds:[esi+0x80], ebx
      [-]5f5e5bc9c3
         // 004012a5: pop edi
         // 004012a6: pop esi
         // 004012a7: pop ebx
         // 004012a8: leave 
         // 004012a9: retn 
      [-]558bec518b450853568b750c5733ff397d18897dfc7518
         // 004012aa: push ebp
         // 004012ab: mov ebp, esp
         // 004012ad: push ecx
         // 004012ae: mov eax, ss:[ebp+0x8]
         // 004012b1: push ebx
         // 004012b2: push esi
         // 004012b3: mov esi, ss:[ebp+0xc]
         // 004012b6: push edi
         // 004012b7: xor edi, edi
         // 004012b9: cmp ss:[ebp+0x18], edi
         // 004012bc: mov ss:[ebp+0xfffffffffffffffc], edi
         // 004012bf: jnz 0x4012d9
      [-]c6467500c64674008b0c85
         // 004012c1: mov b1 ds:[esi+0x75], b1 0x0
         // 004012c5: mov b1 ds:[esi+0x74], b1 0x0
         // 004012c9: mov ecx, ds:[0x424228+eax*0x4]
      [-]894e7089be
         // 004012d0: mov ds:[esi+0x70], ecx
         // 004012d3: mov ds:[esi+0x80], edi
      [-]3bc7754b
         // 004012d9: cmp eax, edi
         // 004012db: jnz 0x401328
      [-]397d187546
         // 004012dd: cmp ss:[ebp+0x18], edi
         // 004012e0: jnz 0x401328
      [-]c6466701c6466804c646693cc6466a41c6466b0ac6466c05c6466e32c74660????????894e0c893d
         // 004012e8: mov b1 ds:[esi+0x67], b1 0x1
         // 004012ec: mov b1 ds:[esi+0x68], b1 0x4
         // 004012f0: mov b1 ds:[esi+0x69], b1 0x3c
         // 004012f4: mov b1 ds:[esi+0x6a], b1 0x41
         // 004012f8: mov b1 ds:[esi+0x6b], b1 0xa
         // 004012fc: mov b1 ds:[esi+0x6c], b1 0x5
         // 00401300: mov b1 ds:[esi+0x6e], b1 0x32
         // 00401304: mov ds:[esi+0x60], 0x6
         // 0040130b: mov ds:[esi+0xc], ecx
         // 0040130e: mov ds:[0x427fa0], edi
      [-]8b5d148bd0c1e2028b82
         // 0040132e: mov ebx, ss:[ebp+0x14]
         // 00401331: mov edx, eax
         // 00401333: shl edx, b1 0x2
         // 00401336: mov eax, ds:[edx+0x41f958]
      [-]3bd88955080f8d1f010000
         // 0040133c: cmp ebx, eax
         // 0040133e: mov ss:[ebp+0x8], edx
         // 00401341: jge 0x401466
      [-]8bc86bc903394d180f8d11010000
         // 00401347: mov ecx, eax
         // 00401349: imul ecx, b1 0x3
         // 0040134c: cmp ss:[ebp+0x18], ecx
         // 0040134f: jge 0x401466
      [-]83f901885e747509
         // 0040135b: cmp ecx, 0x1
         // 0040135e: mov b1 ds:[esi+0x74], b1 bl
         // 00401361: jnz 0x40136c
      [-]837d10007503
         // 00401363: cmp ss:[ebp+0x10], 0x0
         // 00401367: jnz 0x40136c
      [-]85c07409
         // 00401373: test eax, eax
         // 00401375: jz 0x401380
      [-]668b0066a3
         // 00401377: mov b2 ax, b2 ds:[eax]
         // 0040137a: mov b2 ds:[0x4246c4], b2 ax
      [-]83f901753e
         // 00401380: cmp ecx, 0x1
         // 00401383: jnz 0x4013c3
      [-]837d10007406
         // 00401385: cmp ss:[ebp+0x10], 0x0
         // 00401389: jz 0x401391
      [-]837d10057532
         // 0040138b: cmp ss:[ebp+0x10], 0x5
         // 0040138f: jnz 0x4013c3
      [-]00008b3d
         // 00401396: mov edi, ds:[0x4287bc]
      [-]39017312
         // 004013a3: cmp ds:[ecx], eax
         // 004013a5: jnb 0x4013b9
      [-]0fb6015032c9e8
         // 004013a7: movzx eax, b1 ds:[ecx]
         // 004013aa: push eax
         // 004013ab: xor b1 cl, b1 cl
         // 004013ad: call 0x4076a9
      [-]00008b3d
         // 004013b2: mov edi, ds:[0x4287bc]
      [-]8b550847893d
         // 004013b9: mov edx, ss:[ebp+0x8]
         // 004013bc: inc edi
         // 004013bd: mov ds:[0x4287bc], edi
      [-]ff76048b92
         // 004013c3: push ds:[esi+0x4]
         // 004013c6: mov edx, ds:[edx+0x424228]
      [-]000085db597416
         // 004013d1: test ebx, ebx
         // 004013d3: pop ecx
         // 004013d4: jz 0x4013ec
      [-]03c38b0c85
         // 004013db: add eax, ebx
         // 004013dd: mov ecx, ds:[0x423890+eax*0x4]
      [-]8b4604e8
         // 004013e4: mov eax, ds:[esi+0x4]
         // 004013e7: call 0x4054ea
      [-]ff368b15
         // 004013ec: push ds:[esi]
         // 004013ee: mov edx, ds:[0x4205ec]
      [-]0000ff7604ff36e8
         // 004013f9: push ds:[esi+0x4]
         // 004013fc: push ds:[esi]
         // 004013fe: call 0x405529
      [-]000083c40c3b3d
         // 00401403: add esp, 0xc
         // 00401406: cmp edi, ds:[0x41fde4]
      [-]8d4418013904bd
         // 00401413: lea eax, ds:[eax+ebx+0x1]
         // 00401417: cmp ds:[0x415058+edi*0x4], eax
      [-]ff76088b560433ff47c646650fc6466605c6466b00c6466c05e8
         // 00401420: push ds:[esi+0x8]
         // 00401423: mov edx, ds:[esi+0x4]
         // 00401426: xor edi, edi
         // 00401428: inc edi
         // 00401429: mov b1 ds:[esi+0x65], b1 0xf
         // 0040142d: mov b1 ds:[esi+0x66], b1 0x5
         // 00401431: mov b1 ds:[esi+0x6b], b1 0x0
         // 00401435: mov b1 ds:[esi+0x6c], b1 0x5
         // 00401439: call 0x40550e
      [-]000059eb1a
         // 0040143e: pop ecx
         // 0040143f: jmp 0x40145b
      [-]8b46088b7dfcc6466502c6466604c6466b00c6466c0066832000
         // 00401441: mov eax, ds:[esi+0x8]
         // 00401444: mov edi, ss:[ebp+0xfffffffffffffffc]
         // 00401447: mov b1 ds:[esi+0x65], b1 0x2
         // 0040144b: mov b1 ds:[esi+0x66], b1 0x4
         // 0040144f: mov b1 ds:[esi+0x6b], b1 0x0
         // 00401453: mov b1 ds:[esi+0x6c], b1 0x0
         // 00401457: and b2 ds:[eax], b2 0x0
      [-]33c089be
         // 0040145b: xor eax, eax
         // 0040145d: mov ds:[esi+0x80], edi
      [-]5f5e5bc9c3
         // 0040146e: pop edi
         // 0040146f: pop esi
         // 00401470: pop ebx
         // 00401471: leave 
         // 00401472: retn 
      [-]558becb8????????e8
         // 00401473: push ebp
         // 00401474: mov ebp, esp
         // 00401476: mov eax, 0x2118
         // 0040147b: call __alloca_probe
      [-]000053568b750c5733ff397d187506
         // 00401480: push ebx
         // 00401481: push esi
         // 00401482: mov esi, ss:[ebp+0xc]
         // 00401485: push edi
         // 00401486: xor edi, edi
         // 00401488: cmp ss:[ebp+0x18], edi
         // 0040148b: jnz 0x401493
      [-]8b45083bc77554
         // 00401493: mov eax, ss:[ebp+0x8]
         // 00401496: cmp eax, edi
         // 00401498: jnz 0x4014ee
      [-]397d187506
         // 0040149a: cmp ss:[ebp+0x18], edi
         // 0040149d: jnz 0x4014a5
      [-]397d147544
         // 004014a5: cmp ss:[ebp+0x14], edi
         // 004014a8: jnz 0x4014ee
      [-]c6466701c6466804c646693cc6466a41c646650fc64666058a0d
         // 004014aa: mov b1 ds:[esi+0x67], b1 0x1
         // 004014ae: mov b1 ds:[esi+0x68], b1 0x4
         // 004014b2: mov b1 ds:[esi+0x69], b1 0x3c
         // 004014b6: mov b1 ds:[esi+0x6a], b1 0x41
         // 004014ba: mov b1 ds:[esi+0x65], b1 0xf
         // 004014be: mov b1 ds:[esi+0x66], b1 0x5
         // 004014c2: mov b1 cl, b1 ds:[0x420ea0]
      [-]00884e6b8a0d
         // 004014c8: mov b1 ds:[esi+0x6b], b1 cl
         // 004014cb: mov b1 cl, b1 ds:[0x420ea4]
      [-]00884e6c8b0d
         // 004014d1: mov b1 ds:[esi+0x6c], b1 cl
         // 004014d4: mov ecx, ds:[0x41a640]
      [-]c6466e00c74660????????894e0c
         // 004014e0: mov b1 ds:[esi+0x6e], b1 0x0
         // 004014e4: mov ds:[esi+0x60], 0x8
         // 004014eb: mov ds:[esi+0xc], ecx
      [-]8bd8c1e3028b83
         // 004014ee: mov ebx, eax
         // 004014f0: shl ebx, b1 0x2
         // 004014f3: mov eax, ds:[ebx+0x413258]
      [-]3945140f8d
         // 004014f9: cmp ss:[ebp+0x14], eax
         // 004014fc: jge 0x401645
      [-]8bc86bc903394d180f8d
         // 00401502: mov ecx, eax
         // 00401504: imul ecx, b1 0x3
         // 00401507: cmp ss:[ebp+0x18], ecx
         // 0040150a: jge 0x401645
      [-]3bcf750c
         // 00401516: cmp ecx, edi
         // 00401518: jnz 0x401526
      [-]66c745d8300066897ddaeb08
         // 0040151a: mov b2 ss:[ebp+0xffffffffffffffd8], b2 0x30
         // 00401520: mov b2 ss:[ebp+0xffffffffffffffda], b2 di
         // 00401524: jmp 0x40152e
      [-]8d45d8e8
         // 00401526: lea eax, ss:[ebp+0xffffffffffffffd8]
         // 00401529: call 0x4056f6
      [-]3bcf750c
         // 00401534: cmp ecx, edi
         // 00401536: jnz 0x401544
      [-]66c745b0300066897db2eb08
         // 00401538: mov b2 ss:[ebp+0xffffffffffffffb0], b2 0x30
         // 0040153e: mov b2 ss:[ebp+0xffffffffffffffb2], b2 di
         // 00401542: jmp 0x40154c
      [-]8d45b0e8
         // 00401544: lea eax, ss:[ebp+0xffffffffffffffb0]
         // 00401547: call 0x4056f6
      [-]0000397d14ff76046689bde8eeffff7520
         // 00401557: cmp ss:[ebp+0x14], edi
         // 0040155a: push ds:[esi+0x4]
         // 0040155d: mov b2 ss:[ebp+0xffffffffffffeee8], b2 di
         // 00401564: jnz 0x401586
      [-]00008b1759b8
         // 00401573: mov edx, ds:[edi]
         // 00401575: pop ecx
         // 00401576: mov eax, 0x40e26c
      [-]000085c07419
         // 00401580: test eax, eax
         // 00401582: jz 0x40159d
      [-]8b5608e8
         // 00401586: mov edx, ds:[esi+0x8]
         // 00401589: call 0x40550e
      [-]8b7e048d95????????e8
         // 0040158f: mov edi, ds:[esi+0x4]
         // 00401592: lea edx, ss:[ebp+0xffffffffffffeee8]
         // 00401598: call 0x407197
      [-]ff76088b93
         // 0040159d: push ds:[esi+0x8]
         // 004015a0: mov edx, ds:[ebx+0x41f450]
      [-]598b4d1403c18b3c85
         // 004015b0: pop ecx
         // 004015b1: mov ecx, ss:[ebp+0x14]
         // 004015b4: add eax, ecx
         // 004015b6: mov edi, ds:[0x41b578+eax*0x4]
      [-]000085c0740a
         // 004015c9: test eax, eax
         // 004015cb: jz 0x4015d7
      [-]8b46088bcfe8
         // 004015cd: mov eax, ds:[esi+0x8]
         // 004015d0: mov ecx, edi
         // 004015d2: call 0x4054ea
      [-]ff76048b5608e8
         // 004015d7: push ds:[esi+0x4]
         // 004015da: mov edx, ds:[esi+0x8]
         // 004015dd: call 0x40550e
      [-]00008b7e088d95????????e8
         // 004015e2: mov edi, ds:[esi+0x8]
         // 004015e5: lea edx, ss:[ebp+0xffffffffffffdee8]
         // 004015eb: call 0x407197
      [-]0000ff368b15
         // 004015f0: push ds:[esi]
         // 004015f2: mov edx, ds:[0x4236f8]
      [-]00008d85????????50ff36e8
         // 004015fd: lea eax, ss:[ebp+0xffffffffffffeee8]
         // 00401603: push eax
         // 00401604: push ds:[esi]
         // 00401606: call 0x405526
      [-]00008d45d850ff36e8
         // 0040160b: lea eax, ss:[ebp+0xffffffffffffffd8]
         // 0040160e: push eax
         // 0040160f: push ds:[esi]
         // 00401611: call 0x405526
      [-]00008d45b050ff36e8
         // 00401616: lea eax, ss:[ebp+0xffffffffffffffb0]
         // 00401619: push eax
         // 0040161a: push ds:[esi]
         // 0040161c: call 0x405526
      [-]00008d85????????50ff36e8
         // 00401621: lea eax, ss:[ebp+0xffffffffffffdee8]
         // 00401627: push eax
         // 00401628: push ds:[esi]
         // 0040162a: call 0x405526
      [-]00008d85????????50ff36e8
         // 0040162f: lea eax, ss:[ebp+0xfffffffffffffee8]
         // 00401635: push eax
         // 00401636: push ds:[esi]
         // 00401638: call 0x405526
      [-]000033c083c43040eb08
         // 0040163d: xor eax, eax
         // 0040163f: add esp, 0x30
         // 00401642: inc eax
         // 00401643: jmp 0x40164d
      [-]5f5e5bc9c3
         // 0040164d: pop edi
         // 0040164e: pop esi
         // 0040164f: pop ebx
         // 00401650: leave 
         // 00401651: retn 
      [-]558bec5133c9394d0853568b750c894dfc750b
         // 00401652: push ebp
         // 00401653: mov ebp, esp
         // 00401655: push ecx
         // 00401656: xor ecx, ecx
         // 00401658: cmp ss:[ebp+0x8], ecx
         // 0040165b: push ebx
         // 0040165c: push esi
         // 0040165d: mov esi, ss:[ebp+0xc]
         // 00401660: mov ss:[ebp+0xfffffffffffffffc], ecx
         // 00401663: jnz 0x401670
      [-]394d18753b
         // 00401665: cmp ss:[ebp+0x18], ecx
         // 00401668: jnz 0x4016a5
      [-]394d187530
         // 00401670: cmp ss:[ebp+0x18], ecx
         // 00401673: jnz 0x4016a5
      [-]c6466701c6466804c646693cc6466a41c6466b0ac6466c05898e
         // 0040167a: mov b1 ds:[esi+0x67], b1 0x1
         // 0040167e: mov b1 ds:[esi+0x68], b1 0x4
         // 00401682: mov b1 ds:[esi+0x69], b1 0x3c
         // 00401686: mov b1 ds:[esi+0x6a], b1 0x41
         // 0040168a: mov b1 ds:[esi+0x6b], b1 0xa
         // 0040168e: mov b1 ds:[esi+0x6c], b1 0x5
         // 00401692: mov ds:[esi+0x80], ecx
      [-]884e6ec74660????????89460c
         // 00401698: mov b1 ds:[esi+0x6e], b1 cl
         // 0040169b: mov ds:[esi+0x60], 0x4
         // 004016a2: mov ds:[esi+0xc], eax
      [-]8b5d143bd80f8d7f010000
         // 004016aa: mov ebx, ss:[ebp+0x14]
         // 004016ad: cmp ebx, eax
         // 004016af: jge 0x401834
      [-]6bc0033945180f8d73010000
         // 004016b5: imul eax, b1 0x3
         // 004016b8: cmp ss:[ebp+0x18], eax
         // 004016bb: jge 0x401834
      [-]394d107406
         // 004016ca: cmp ss:[ebp+0x10], ecx
         // 004016cd: jz 0x4016d5
      [-]837d1005752a
         // 004016cf: cmp ss:[ebp+0x10], 0x5
         // 004016d3: jnz 0x4016ff
      [-]00008b0d
         // 004016da: mov ecx, ds:[0x4287c4]
      [-]3901730c
         // 004016e7: cmp ds:[ecx], eax
         // 004016e9: jnb 0x4016f7
      [-]0fb6015032c9e8
         // 004016eb: movzx eax, b1 ds:[ecx]
         // 004016ee: push eax
         // 004016ef: xor b1 cl, b1 cl
         // 004016f1: call 0x4076a9
      [-]837d10047510
         // 004016ff: cmp ss:[ebp+0x10], 0x4
         // 00401703: jnz 0x401715
      [-]8d4302890495
         // 0040170b: lea eax, ds:[ebx+0x2]
         // 0040170e: mov ds:[0x414d38+edx*0x4], eax
      [-]c1e7028b87
         // 0040171c: shl edi, b1 0x2
         // 0040171f: mov eax, ds:[edi+0x413208]
      [-]3bc17409
         // 00401725: cmp eax, ecx
         // 00401727: jz 0x401732
      [-]668b0066a3
         // 00401729: mov b2 ax, b2 ds:[eax]
         // 0040172c: mov b2 ds:[0x4246c0], b2 ax
      [-]ff368b15
         // 00401732: push ds:[esi]
         // 00401734: mov edx, ds:[0x41526c]
      [-]0000ff349d
         // 0040173f: push ds:[0x417988+ebx*0x4]
      [-]0000ff35
         // 0040174d: push ds:[0x41a110]
      [-]0000ff35
         // 0040175a: push ds:[0x417660]
      [-]3d00008b1c9d
         // 00401767: mov ebx, ds:[0x4171b0+ebx*0x4]
      [-]83c41c85db7445
         // 0040176e: add esp, 0x1c
         // 00401771: test ebx, ebx
         // 00401773: jz 0x4017ba
      [-]000085c0ff76047423
         // 0040177c: test eax, eax
         // 0040177e: push ds:[esi+0x4]
         // 00401781: jz 0x4017a6
      [-]00008b4514ff3485
         // 0040178f: mov eax, ss:[ebp+0x14]
         // 00401792: push ds:[0x417988+eax*0x4]
      [-]ff7604e8
         // 00401799: push ds:[esi+0x4]
         // 0040179c: call 0x405526
      [-]000083c40ceb08
         // 004017a1: add esp, 0xc
         // 004017a4: jmp 0x4017ae
      [-]ff7604ff36e8
         // 004017ae: push ds:[esi+0x4]
         // 004017b1: push ds:[esi]
         // 004017b3: call 0x405526
      [-]00005959
         // 004017b8: pop ecx
         // 004017b9: pop ecx
      [-]8b4514403b87
         // 004017c7: mov eax, ss:[ebp+0x14]
         // 004017ca: inc eax
         // 004017cb: cmp eax, ds:[edi+0x414d38]
      [-]c646650fc6466605c6466b00c6466c058bbf
         // 004017d3: mov b1 ds:[esi+0x65], b1 0xf
         // 004017d7: mov b1 ds:[esi+0x66], b1 0x5
         // 004017db: mov b1 ds:[esi+0x6b], b1 0x0
         // 004017df: mov b1 ds:[esi+0x6c], b1 0x5
         // 004017e3: mov edi, ds:[edi+0x424538]
      [-]8bd743e8
         // 004017f0: mov edx, edi
         // 004017f2: inc ebx
         // 004017f3: call 0x405464
      [-]000085c0ff76087505
         // 004017f8: test eax, eax
         // 004017fa: push ds:[esi+0x8]
         // 004017fd: jnz 0x401804
      [-]8b5604eb02
         // 004017ff: mov edx, ds:[esi+0x4]
         // 00401802: jmp 0x401806
      [-]000059eb1a
         // 0040180b: pop ecx
         // 0040180c: jmp 0x401828
      [-]8b46088b5dfcc6466502c6466604c6466b00c6466c0066832000
         // 0040180e: mov eax, ds:[esi+0x8]
         // 00401811: mov ebx, ss:[ebp+0xfffffffffffffffc]
         // 00401814: mov b1 ds:[esi+0x65], b1 0x2
         // 00401818: mov b1 ds:[esi+0x66], b1 0x4
         // 0040181c: mov b1 ds:[esi+0x6b], b1 0x0
         // 00401820: mov b1 ds:[esi+0x6c], b1 0x0
         // 00401824: and b2 ds:[eax], b2 0x0
      [-]33c0899e
         // 00401828: xor eax, eax
         // 0040182a: mov ds:[esi+0x80], ebx
      [-]405feb02
         // 00401830: inc eax
         // 00401831: pop edi
         // 00401832: jmp 0x401836
      [-]5e5bc9c3
         // 00401836: pop esi
         // 00401837: pop ebx
         // 00401838: leave 
         // 00401839: retn 
      [-]558bec83e4f851538b5d0833c03bd8568b750c578944240c753e
         // 0040183a: push ebp
         // 0040183b: mov ebp, esp
         // 0040183d: and esp, 0xfffffffffffffff8
         // 00401840: push ecx
         // 00401841: push ebx
         // 00401842: mov ebx, ss:[ebp+0x8]
         // 00401845: xor eax, eax
         // 00401847: cmp ebx, eax
         // 00401849: push esi
         // 0040184a: mov esi, ss:[ebp+0xc]
         // 0040184d: push edi
         // 0040184e: mov ss:[esp+0xc], eax
         // 00401852: jnz 0x401892
      [-]394518750f
         // 00401854: cmp ss:[ebp+0x18], eax
         // 00401857: jnz 0x401868
      [-]3945147525
         // 00401868: cmp ss:[ebp+0x14], eax
         // 0040186b: jnz 0x401892
      [-]88466688466ea1
         // 0040186d: mov b1 ds:[esi+0x66], b1 al
         // 00401870: mov b1 ds:[esi+0x6e], b1 al
         // 00401873: mov eax, ds:[0x417664]
      [-]c6466701c6466804c646650fc6466a01c74660????????89460c
         // 00401878: mov b1 ds:[esi+0x67], b1 0x1
         // 0040187c: mov b1 ds:[esi+0x68], b1 0x4
         // 00401880: mov b1 ds:[esi+0x65], b1 0xf
         // 00401884: mov b1 ds:[esi+0x6a], b1 0x1
         // 00401888: mov ds:[esi+0x60], 0x1
         // 0040188f: mov ds:[esi+0xc], eax
      [-]8bfbc1e7028b87
         // 00401892: mov edi, ebx
         // 00401894: shl edi, b1 0x2
         // 00401897: mov eax, ds:[edi+0x423700]
      [-]3945140f8dd5000000
         // 0040189d: cmp ss:[ebp+0x14], eax
         // 004018a0: jge 0x40197b
      [-]8bc86bc903394d180f8dc7000000
         // 004018a6: mov ecx, eax
         // 004018a8: imul ecx, b1 0x3
         // 004018ab: cmp ss:[ebp+0x18], ecx
         // 004018ae: jge 0x40197b
      [-]837d14007554
         // 004018b4: cmp ss:[ebp+0x14], 0x0
         // 004018b8: jnz 0x40190e
      [-]ff368b97
         // 004018ba: push ds:[esi]
         // 004018bc: mov edx, ds:[edi+0x417668]
      [-]00008b97
         // 004018c7: mov edx, ds:[edi+0x423078]
      [-]59ff7604e8
         // 004018cd: pop ecx
         // 004018ce: push ds:[esi+0x4]
         // 004018d1: call 0x40550e
      [-]433b1c85
         // 004018db: inc ebx
         // 004018dc: cmp ebx, ds:[0x41a190+eax*0x4]
      [-]00008b8f
         // 004018eb: mov ecx, ds:[edi+0x423700]
      [-]494999f7f942ff05
         // 004018f1: dec ecx
         // 004018f2: dec ecx
         // 004018f3: cdq 
         // 004018f4: idiv ecx
         // 004018f6: inc edx
         // 004018f7: inc ds:[0x4287d0]
      [-]ff76048b16e8
         // 0040190e: push ds:[esi+0x4]
         // 00401911: mov edx, ds:[esi]
         // 00401913: call 0x40550e
      [-]00008b97
         // 00401918: mov edx, ds:[edi+0x417668]
      [-]59ff36e8
         // 0040191e: pop ecx
         // 0040191f: push ds:[esi]
         // 00401921: call 0x40550e
      [-]598b4d1403c18b0c85
         // 0040192b: pop ecx
         // 0040192c: mov ecx, ss:[ebp+0x14]
         // 0040192f: add eax, ecx
         // 00401931: mov ecx, ds:[0x415270+eax*0x4]
      [-]00008846658b0d
         // 0040194a: mov b1 ds:[esi+0x65], b1 al
         // 0040194d: mov ecx, ds:[0x41f9b0]
      [-]00008846698b4514403905
         // 00401958: mov b1 ds:[esi+0x69], b1 al
         // 0040195b: mov eax, ss:[ebp+0x14]
         // 0040195e: inc eax
         // 0040195f: cmp ds:[0x4287c8], eax
      [-]33c040eb04
         // 00401967: xor eax, eax
         // 00401969: inc eax
         // 0040196a: jmp 0x401970
      [-]8b44240c
         // 0040196c: mov eax, ss:[esp+0xc]
      [-]33c040eb08
         // 00401976: xor eax, eax
         // 00401978: inc eax
         // 00401979: jmp 0x401983
      [-]5f5e5b8be55dc3
         // 00401983: pop edi
         // 00401984: pop esi
         // 00401985: pop ebx
         // 00401986: mov esp, ebp
         // 00401988: pop ebp
         // 00401989: retn 
      [-]558bec51
         // 00401aa0: push ebp
         // 00401aa1: mov ebp, esp
         // 00401aa3: push ecx
      [-]394518568b750c5789
         // 00401ab7: cmp ss:[ebp+0x18], eax
         // 00401aba: push esi
         // 00401abb: mov esi, ss:[ebp+0xc]
         // 00401abe: push edi
         // 00401ac2: mov ss:[ebp+0xfffffffffffffffc], ecx
      [-]8846758846748b0c9d
         // 00401ac7: mov b1 ds:[esi+0x75], b1 al
         // 00401aca: mov b1 ds:[esi+0x74], b1 al
         // 00401acd: mov ecx, ds:[0x4233d8+ebx*0x4]
      [-]894e708986
         // 00401ad4: mov ds:[esi+0x70], ecx
         // 00401ad7: mov ds:[esi+0x80], eax
      [-]3bd87561
         // 00401add: cmp ebx, eax
         // 00401adf: jnz 0x401b42
      [-]394518750f
         // 00401ae1: cmp ss:[ebp+0x18], eax
         // 00401ae4: jnz 0x401af5
      [-]3945147548
         // 00401af5: cmp ss:[ebp+0x14], eax
         // 00401af8: jnz 0x401b42
      [-]c6466701c6466804c6466b0fc6466c058a0d
         // 00401afa: mov b1 ds:[esi+0x67], b1 0x1
         // 00401afe: mov b1 ds:[esi+0x68], b1 0x4
         // 00401b02: mov b1 ds:[esi+0x6b], b1 0xf
         // 00401b06: mov b1 ds:[esi+0x6c], b1 0x5
         // 00401b0a: mov b1 cl, b1 ds:[0x41a8a4]
      [-]4100884e658a0d
         // 00401b10: mov b1 ds:[esi+0x65], b1 cl
         // 00401b13: mov b1 cl, b1 ds:[0x41a8a8]
      [-]4100884e668a0d
         // 00401b19: mov b1 ds:[esi+0x66], b1 cl
         // 00401b1c: mov b1 cl, b1 ds:[0x41a8ac]
      [-]4100884e698a0d
         // 00401b22: mov b1 ds:[esi+0x69], b1 cl
         // 00401b25: mov b1 cl, b1 ds:[0x41a8b0]
      [-]4100884e6a8b0d
         // 00401b2b: mov b1 ds:[esi+0x6a], b1 cl
         // 00401b2e: mov ecx, ds:[0x4150d0]
      [-]c6466e36c74660????????894e0c
         // 00401b34: mov b1 ds:[esi+0x6e], b1 0x36
         // 00401b38: mov ds:[esi+0x60], 0x5
         // 00401b3f: mov ds:[esi+0xc], ecx
      [-]018b4d14884e747508
         // 00401b49: mov ecx, ss:[ebp+0x14]
         // 00401b4c: mov b1 ds:[esi+0x74], b1 cl
         // 00401b4f: jnz 0x401b59
      [-]3945107503
         // 00401b51: cmp ss:[ebp+0x10], eax
         // 00401b54: jnz 0x401b59
      [-]8bfbc1e7028b87
         // 00401b59: mov edi, ebx
         // 00401b5b: shl edi, b1 0x2
         // 00401b5e: mov eax, ds:[edi+0x423d68]
      [-]3bc80f8d
         // 00401b64: cmp ecx, eax
         // 00401b66: jge 0x401c34
      [-]8bd06bd2033955180f8d
         // 00401b6c: mov edx, eax
         // 00401b6e: imul edx, b1 0x3
         // 00401b71: cmp ss:[ebp+0x18], edx
         // 00401b74: jge 0x401c34
      [-]ff368b97
         // 00401b7e: push ds:[esi]
         // 00401b80: mov edx, ds:[edi+0x422bc8]
      [-]0000ff76048b97
         // 00401b8b: push ds:[esi+0x4]
         // 00401b8e: mov edx, ds:[edi+0x422d58]
      [-]433b1c85
         // 00401b9e: inc ebx
         // 00401b9f: cmp ebx, ds:[0x414b58+eax*0x4]
      [-]00008b8f
         // 00401bb5: mov ecx, ds:[edi+0x423d68]
      [-]494999f7f9428915
         // 00401bbb: dec ecx
         // 00401bbc: dec ecx
         // 00401bbd: cdq 
         // 00401bbe: idiv ecx
         // 00401bc0: inc edx
         // 00401bc1: mov ds:[0x4287d8], edx
      [-]ff76048b16e8
         // 00401be4: push ds:[esi+0x4]
         // 00401be7: mov edx, ds:[esi]
         // 00401be9: call 0x40550e
      [-]0000ff368b97
         // 00401bee: push ds:[esi]
         // 00401bf0: mov edx, ds:[edi+0x4233d8]
      [-]59598b4d1403c18b0c85
         // 00401c00: pop ecx
         // 00401c01: pop ecx
         // 00401c02: mov ecx, ss:[ebp+0x14]
         // 00401c05: add eax, ecx
         // 00401c07: mov ecx, ds:[0x41d4c0+eax*0x4]
      [-]8b4514403905
         // 00401c15: mov eax, ss:[ebp+0x14]
         // 00401c18: inc eax
         // 00401c19: cmp ds:[0x4287d8], eax
      [-]33c040eb03
         // 00401c21: xor eax, eax
         // 00401c23: inc eax
         // 00401c24: jmp 0x401c29
      [-]33c040eb08
         // 00401c2f: xor eax, eax
         // 00401c31: inc eax
         // 00401c32: jmp 0x401c3c
      [-]5f5e5bc9c3
         // 00401c3c: pop edi
         // 00401c3d: pop esi
         // 00401c3e: pop ebx
         // 00401c3f: leave 
         // 00401c40: retn 
      [-]558becb8
         // 00401c41: push ebp
         // 00401c42: mov ebp, esp
         // 00401c44: mov eax, 0x319c
      [-]00008b45
         // 00401c4e: mov eax, ss:[ebp+0xc]
      [-]81f9????????73
         // 00401c60: cmp ecx, 0x10000
         // 00401c66: jnb 0x401c80
      [-]30006689
         // 00401c8d: mov b2 ss:[ebp+0xffffffffffffffd2], b2 di
      [-]0000598b4d
         // 00401caa: pop ecx
         // 00401cab: mov ecx, ss:[ebp+0x18]
      [-]3bcf740b
         // 00401cae: cmp ecx, edi
         // 00401cb0: jz 0x401cbd
      [-]3bcf750c
         // 00401cd6: cmp ecx, edi
         // 00401cd8: jnz 0x401ce6
      [-]300066897d
         // 00401ce0: mov b2 ss:[ebp+0xffffffffffffffaa], b2 di
      [-]00008d45
         // 00401cf8: lea eax, ss:[ebp+0xffffffffffffffa8]
      [-]000083c410
         // 00401d02: add esp, 0x10
      [-]00008bc83bcf750c
         // 004035ae: mov ecx, eax
         // 004035b0: cmp ecx, edi
         // 004035b2: jnz 0x4035c0
      [-]300066897d
         // 00401d21: mov b2 ss:[ebp+0xffffffffffffffaa], b2 di
      [-]3bcf750c
         // 00401d35: cmp ecx, edi
         // 00401d37: jnz 0x401d45
      [-]300066897d
         // 00401d3f: mov b2 ss:[ebp+0xffffffffffffff82], b2 di
      [-]30006689
         // 00401d60: mov b2 ss:[ebp+0xffffffffffffff56], b2 di
      [-]00008d45
         // 00401d8f: lea eax, ss:[ebp+0xffffffffffffffa8]
      [-]00008b7d
         // 00401d99: mov edi, ss:[ebp+0x1c]
      [-]83c41085ff7428
         // 00401d9c: add esp, 0x10
         // 00401d9f: test edi, edi
         // 00401da1: jz 0x401dcb
      [-]00008d85
         // 00401db9: lea eax, ss:[ebp+0xffffffffffffee64]
      [-]000083c410eb0d
         // 00401dc6: add esp, 0x10
         // 00401dc9: jmp 0x401dd8
      [-]00005959
         // 00401dd6: pop ecx
         // 00401dd7: pop ecx
      [-]00008d45
         // 00401de5: lea eax, ss:[ebp+0xffffffffffffff80]
      [-]000083c418
         // 00401dfc: add esp, 0x18
      [-]33c040e9
         // 00401dff: xor eax, eax
         // 00401e01: inc eax
         // 00401e02: jmp 0x402210
      [-]00008bc83bcf75
         // 004036a8: mov ecx, eax
         // 004036aa: cmp ecx, edi
         // 004036ac: jnz 0x4036ba
      [-]30006689
         // 00401e26: mov b2 ss:[ebp+0xffffffffffffff56], b2 di
      [-]3bcf750c
         // 00401e40: cmp ecx, edi
         // 00401e42: jnz 0x401e50
      [-]300066897d
         // 00401e4a: mov b2 ss:[ebp+0xffffffffffffff82], b2 di
      [-]3bcf750c
         // 00401e5e: cmp ecx, edi
         // 00401e60: jnz 0x401e6e
      [-]300066897d
         // 00401e68: mov b2 ss:[ebp+0xffffffffffffffaa], b2 di
      [-]6a208d8d
         // 00401e76: push 0x20
         // 00401e78: lea ecx, ss:[ebp+0xfffffffffffffe64]
      [-]000025????????7905
         // 00401e84: and eax, 0xffffffff8000000f
         // 00401e89: jns 0x401e90
      [-]4883c8f040
         // 00401e8b: dec eax
         // 00401e8c: or eax, 0xfffffffffffffff0
         // 00401e8f: inc eax
      [-]83f80a7d05
         // 00401e90: cmp eax, 0xa
         // 00401e93: jge 0x401e9a
      [-]83c030eb03
         // 00401e95: add eax, 0x30
         // 00401e98: jmp 0x401e9d
      [-]0fb7c066890141414a75d7
         // 00401e9d: movzx eax, b2 ax
         // 00401ea0: mov b2 ds:[ecx], b2 ax
         // 00401ea3: inc ecx
         // 00401ea4: inc ecx
         // 00401ea5: dec edx
         // 00401ea6: jnz 0x401e7f
      [-]6689398dbd
         // 00401ea8: mov b2 ds:[ecx], b2 di
         // 00401eab: lea edi, ss:[ebp+0xffffffffffffde64]
      [-]0000ff75
         // 00401ec6: push ss:[ebp+0x24]
      [-]00008d45
         // 00401edc: lea eax, ss:[ebp+0xffffffffffffff80]
      [-]00008d45
         // 00401ee6: lea eax, ss:[ebp+0xffffffffffffffa8]
      [-]00008d85
         // 00401ef0: lea eax, ss:[ebp+0xfffffffffffffe64]
      [-]00008b7d
         // 00401efd: mov edi, ss:[ebp+0x1c]
      [-]83c43085ff7428
         // 00401f00: add esp, 0x30
         // 00401f03: test edi, edi
         // 00401f05: jz 0x401f2f
      [-]00008d85
         // 00401f1d: lea eax, ss:[ebp+0xffffffffffffce64]
      [-]000083c410eb0d
         // 00401f2a: add esp, 0x10
         // 00401f2d: jmp 0x401f3c
      [-]00005959
         // 00401f3a: pop ecx
         // 00401f3b: pop ecx
      [-]00005959e9
         // 00401f49: pop ecx
         // 00401f4a: pop ecx
         // 00401f4b: jmp 0x401dff
      [-]0000595933f6
         // 00401f5f: pop ecx
         // 00401f60: pop ecx
         // 00401f61: xor esi, esi
      [-]8b3cb08d95
         // 00401f66: mov edi, ds:[eax+esi*0x4]
         // 00401f69: lea edx, ss:[ebp+0xfffffffffffffe64]
      [-]00008d85
         // 00401f74: lea eax, ss:[ebp+0xfffffffffffffe64]
      [-]00004683fe0b59597c
         // 00401f81: inc esi
         // 00401f82: cmp esi, 0xb
         // 00401f85: pop ecx
         // 00401f86: pop ecx
         // 00401f87: jl 0x401f63
      [-]00005959
         // 00401fa7: pop ecx
         // 00401fa8: pop ecx
      [-]eeffff7410
         // 00401fb8: jz 0x401fca
      [-]000033ff
         // 00401fc8: xor edi, edi
      [-]000083c410
         // 00401fe1: add esp, 0x10
      [-]00008dbd
         // 00401ffb: lea edi, ss:[ebp+0xffffffffffffde64]
      [-]00008b7d
         // 0040200c: mov edi, ss:[ebp+0x1c]
      [-]85ff740d
         // 0040200f: test edi, edi
         // 00402011: jz 0x402020
      [-]0000eb08
         // 0040201e: jmp 0x402028
      [-]eeffff00
      [-]00008d85
         // 00402032: lea eax, ss:[ebp+0xffffffffffffee64]
      [-]00008d85
         // 0040203f: lea eax, ss:[ebp+0xffffffffffffce64]
      [-]00008d85
         // 0040204c: lea eax, ss:[ebp+0xfffffffffffffe64]
      [-]000083c42033ff
         // 00402059: add esp, 0x20
         // 0040205c: xor edi, edi
      [-]00008b45
         // 00402072: mov eax, ss:[ebp+0x24]
      [-]83c00850
         // 00402075: add eax, 0x8
         // 00402078: push eax
      [-]000083c4
         // 004020a0: add esp, 0x1c
      [-]30006689
         // 00402157: mov b2 ss:[ebp+0xffffffffffffff56], b2 di
      [-]3bcf750c
         // 00402171: cmp ecx, edi
         // 00402173: jnz 0x402181
      [-]300066897d
         // 0040217b: mov b2 ss:[ebp+0xffffffffffffff82], b2 di
      [-]00008b7d
         // 004021a4: mov edi, ss:[ebp+0x1c]
      [-]85ff59597428
         // 004021a7: test edi, edi
         // 004021a9: pop ecx
         // 004021aa: pop ecx
         // 004021ab: jz 0x4021d5
      [-]00008d85
         // 004021c3: lea eax, ss:[ebp+0xffffffffffffee64]
      [-]000083c410eb17
         // 004021d0: add esp, 0x10
         // 004021d3: jmp 0x4021ec
      [-]eeffff008d85
         // 004021dd: lea eax, ss:[ebp+0xffffffffffffee64]
      [-]00005959
         // 004021ea: pop ecx
         // 004021eb: pop ecx
      [-]00008d45
         // 00402206: lea eax, ss:[ebp+0xffffffffffffff80]
      [-]5f5ec9c3
         // 00402210: pop edi
         // 00402211: pop esi
         // 00402212: leave 
         // 00402213: retn 
      [-]558bec83e4f883ec1c538b5d08568b750c5733ff3bdf6a02897c24
         // 00402214: push ebp
         // 00402215: mov ebp, esp
         // 00402217: and esp, 0xfffffffffffffff8
         // 0040221a: sub esp, 0x1c
         // 0040221d: push ebx
         // 0040221e: mov ebx, ss:[ebp+0x8]
         // 00402221: push esi
         // 00402222: mov esi, ss:[ebp+0xc]
         // 00402225: push edi
         // 00402226: xor edi, edi
         // 00402228: cmp ebx, edi
         // 0040222a: push 0x2
         // 0040222c: mov ss:[esp+0x1c], edi
      [-]397d180f85
         // 00402233: cmp ss:[ebp+0x18], edi
         // 00402236: jnz 0x402334
      [-]4100046488466ea1
         // 00402241: add b1 al, b1 0x64
         // 00402243: mov b1 ds:[esi+0x6e], b1 al
         // 00402246: mov eax, ds:[0x417664]
      [-]c6466701c646680489460c894e60
         // 0040226d: mov b1 ds:[esi+0x67], b1 0x1
         // 00402271: mov b1 ds:[esi+0x68], b1 0x4
         // 00402275: mov ds:[esi+0xc], eax
         // 00402278: mov ds:[esi+0x60], ecx
      [-]397d180f85
         // 0040227b: cmp ss:[ebp+0x18], edi
         // 0040227e: jnz 0x402334
      [-]8d43013b0495
         // 0040228a: lea eax, ds:[ebx+0x1]
         // 0040228d: cmp eax, ds:[0x41a190+edx*0x4]
      [-]00008b3c9d
         // 0040229b: mov edi, ds:[0x423700+ebx*0x4]
      [-]2bf999f7ff42ff05
         // 004022a2: sub edi, ecx
         // 004022a4: cdq 
         // 004022a5: idiv edi
         // 004022a7: inc edx
         // 004022a8: inc ds:[0x4287f8]
      [-]0000996a6459f7f933c0bf????????85d20f9cc0
         // 004022c1: cdq 
         // 004022c2: push 0x64
         // 004022c4: pop ecx
         // 004022c5: idiv ecx
         // 004022c7: xor eax, eax
         // 004022c9: mov edi, 0x10000
         // 004022ce: test edx, edx
         // 004022d0: setl b1 al
      [-]c700????????
         // 004022ec: mov ds:[eax], 0x90
      [-]85c27401
         // 004022f6: test edx, eax
         // 004022f8: jz 0x4022fb
      [-]03d23bd772f5
         // 004022fb: add edx, edx
         // 004022fd: cmp edx, edi
         // 004022ff: jb 0x4022f6
      [-]0000884669c6466a01c6467500c64674008b049d
         // 00402319: mov b1 ds:[esi+0x69], b1 al
         // 0040231c: mov b1 ds:[esi+0x6a], b1 0x1
         // 00402320: mov b1 ds:[esi+0x75], b1 0x0
         // 00402324: mov b1 ds:[esi+0x74], b1 0x0
         // 00402328: mov eax, ds:[0x417668+ebx*0x4]
      [-]89467033ff
         // 0040232f: mov ds:[esi+0x70], eax
         // 00402332: xor edi, edi
      [-]8b45188b0d
         // 00402334: mov eax, ss:[ebp+0x18]
         // 00402337: mov ecx, ds:[0x4287f4]
      [-]99f7f93bd789542410752b
         // 0040233d: cdq 
         // 0040233e: idiv ecx
         // 00402340: cmp edx, edi
         // 00402342: mov ss:[esp+0x10], edx
         // 00402346: jnz 0x402373
      [-]397d187426
         // 00402348: cmp ss:[ebp+0x18], edi
         // 0040234b: jz 0x402373
      [-]fe467483f8017512
         // 00402359: inc b1 ds:[esi+0x74]
         // 0040235c: cmp eax, 0x1
         // 0040235f: jnz 0x402373
      [-]fe46753bc0750b
         // 00402361: inc b1 ds:[esi+0x75]
         // 00402364: cmp eax, eax
         // 00402366: jnz 0x402373
      [-]397d107406
         // 00402368: cmp ss:[ebp+0x10], edi
         // 0040236b: jz 0x402373
      [-]8bfbc1e7028b87
         // 00402373: mov edi, ebx
         // 00402375: shl edi, b1 0x2
         // 00402378: mov eax, ds:[edi+0x423700]
      [-]0fafc13945187c07
         // 0040237e: imul eax, ecx
         // 00402381: cmp ss:[ebp+0x18], eax
         // 00402384: jl 0x40238d
      [-]895424248b12894424
         // 004023a5: mov ss:[esp+0x24], edx
         // 004023a9: mov edx, ds:[edx]
         // 004023ab: mov ss:[esp+0x20], eax
      [-]89542414750e
         // 004023af: mov ss:[esp+0x14], edx
         // 004023b3: jnz 0x4023c3
      [-]8364241400
         // 004023be: and ss:[esp+0x14], 0x0
      [-]4a3bc27513
         // 004023c9: dec edx
         // 004023ca: cmp eax, edx
         // 004023cc: jnz 0x4023e1
      [-]49394c2410750c
         // 004023ce: dec ecx
         // 004023cf: cmp ss:[esp+0x10], ecx
         // 004023d3: jnz 0x4023e1
      [-]85c08b4e04894c24
         // 004023e1: test eax, eax
         // 004023e3: mov ecx, ds:[esi+0x4]
         // 004023e6: mov ss:[esp+0x1c], ecx
      [-]00008b97
         // 004023f8: mov edx, ds:[edi+0x423078]
      [-]0000f7d81bc02387
         // 00402409: neg eax
         // 0040240b: sbb eax, eax
         // 0040240d: and eax, ds:[edi+0x423078]
      [-]0000833d
         // 00402424: cmp ds:[0x4287fc], 0x0
      [-]0059740f
         // 0040242b: pop ecx
         // 0040242c: jz 0x40243d
      [-]8b4424248b48fc8b4604e8
         // 0040242e: mov eax, ss:[esp+0x24]
         // 00402432: mov ecx, ds:[eax+0xfffffffffffffffc]
         // 00402435: mov eax, ds:[esi+0x4]
         // 00402438: call 0x4054ea
      [-]6bdb3c81c3
         // 0040243d: imul ebx, b1 0x3c
         // 00402440: add ebx, 0x4133e8
      [-]ff742424ffb7
         // 00402459: push ss:[esp+0x24]
         // 0040245d: push ds:[edi+0x417678]
      [-]ff74242cffb7
         // 00402469: push ss:[esp+0x2c]
         // 0040246d: push ds:[edi+0x41fc20]
      [-]ffff8b1d
         // 00402478: mov ebx, ds:[0x427fd4]
      [-]403bd8750c
         // 0040248e: inc eax
         // 0040248f: cmp ebx, eax
         // 00402491: jnz 0x40249f
      [-]ff76048946
         // 004024ac: push ds:[esi+0x4]
         // 004024af: mov ds:[esi+0x78], eax
      [-]0000598b4c241485c97408
         // 004024bd: pop ecx
         // 004024be: mov ecx, ss:[esp+0x14]
         // 004024c2: test ecx, ecx
         // 004024c4: jz 0x4024ce
      [-]8b4604e8
         // 004024c6: mov eax, ds:[esi+0x4]
         // 004024c9: call 0x4054ea
      [-]ff76088b5604e8
         // 004024ce: push ds:[esi+0x8]
         // 004024d1: mov edx, ds:[esi+0x4]
         // 004024d4: call 0x40550e
      [-]00008b4424
         // 004024d9: mov eax, ss:[esp+0x24]
      [-]403bd8a1
         // 004024dd: inc eax
         // 004024de: cmp ebx, eax
         // 004024e0: mov eax, ds:[0x4287f4]
      [-]8d48ff394c241075
         // 004024e8: lea ecx, ds:[eax+0xffffffffffffffff]
         // 004024eb: cmp ss:[esp+0x10], ecx
         // 004024ef: jnz 0x4024f9
      [-]48394424107518
         // 004024f9: dec eax
         // 004024fa: cmp ss:[esp+0x10], eax
         // 004024fe: jnz 0x402518
      [-]c6466b0fc6466c058b0d
         // 00402500: mov b1 ds:[esi+0x6b], b1 0xf
         // 00402504: mov b1 ds:[esi+0x6c], b1 0x5
         // 00402508: mov ecx, ds:[0x41f9ac]
      [-]0000884665eb0c
         // 00402513: mov b1 ds:[esi+0x65], b1 al
         // 00402516: jmp 0x402524
      [-]c6466500c6466b00c6466c00
         // 00402518: mov b1 ds:[esi+0x65], b1 0x0
         // 0040251c: mov b1 ds:[esi+0x6b], b1 0x0
         // 00402520: mov b1 ds:[esi+0x6c], b1 0x0
      [-]c646660040
         // 00403d31: mov b1 ds:[esi+0x66], b1 0x0
         // 00403d3b: inc eax
      [-]5f5e5b8be55dc3
         // 00402535: pop edi
         // 00402536: pop esi
         // 00402537: pop ebx
         // 00402538: mov esp, ebp
         // 0040253a: pop ebp
         // 0040253b: retn 
      [-]558becb8
         // 0040253c: push ebp
         // 0040253d: mov ebp, esp
         // 0040253f: mov eax, 0x2064
      [-]5633f63935
         // 00402550: push esi
         // 00402551: xor esi, esi
         // 00402553: cmp ds:[0x4114e4], esi
      [-]68????????ff
         // 00402561: push 0x2710
         // 00402566: call ebx
      [-]000083f80175ef
         // 0040256d: cmp eax, 0x1
         // 00402570: jnz 0x402561
      [-]ff750cff7508e8
         // 0040259b: push ss:[ebp+0xc]
         // 0040259e: push ss:[ebp+0x8]
         // 004025a1: call 0x407083
      [-]000083c4
         // 004025a6: add esp, 0x10
      [-]85c07514
         // 004025a9: test eax, eax
         // 004025ab: jnz 0x4025c1
      [-]68????????
         // 004025ad: push 0xea60
      [-]6a448d45
         // 004025d3: push 0x44
         // 004025d5: lea eax, ss:[ebp+0xffffffffffffffa0]
      [-]00008d85
         // 004025df: lea eax, ss:[ebp+0xffffffffffffdfa0]
      [-]83c40c50ba
         // 004025e5: add esp, 0xc
         // 004025e8: push eax
         // 004025e9: mov edx, 0x40e314
      [-]0000598b4d
         // 004025f3: pop ecx
         // 004025f4: mov ecx, ss:[ebp+0x10]
      [-]00003975
         // 0040260c: cmp ss:[ebp+0x14], esi
      [-]000085c0740e
         // 0040261e: test eax, eax
         // 00402620: jz 0x402630
      [-]566a205656568d85
         // 0040263d: push esi
         // 0040263e: push 0x20
         // 00402640: push esi
         // 00402641: push esi
         // 00402642: push esi
         // 00402643: lea eax, ss:[ebp+0xffffffffffffdfa0]
      [-]400085c07506
         // 00402653: test eax, eax
         // 00402655: jnz 0x40265d
      [-]5f5e5bc9c3
         // 00402675: pop edi
         // 00402676: pop esi
         // 00402677: pop ebx
         // 00402678: leave 
         // 00402679: retn 
      [-]558bec83e4f8b8????????e8
         // 0040267a: push ebp
         // 0040267b: mov ebp, esp
         // 0040267d: and esp, 0xfffffffffffffff8
         // 00402680: mov eax, 0x309c
         // 00402685: call __alloca_probe
      [-]00008a4518888424810000000fb6c08d8c24????????6bc014894c24148d8c24????????894c24185333db395d088d8c24????????894c24208b4d1c565766899c24a800000066899c24a810000066899c24a82000008988
         // 0040268a: mov b1 al, b1 ss:[ebp+0x18]
         // 0040268d: mov b1 ss:[esp+0x81], b1 al
         // 00402694: movzx eax, b1 al
         // 00402697: lea ecx, ss:[esp+0x209c]
         // 0040269e: imul eax, b1 0x14
         // 004026a1: mov ss:[esp+0x14], ecx
         // 004026a5: lea ecx, ss:[esp+0x109c]
         // 004026ac: mov ss:[esp+0x18], ecx
         // 004026b0: push ebx
         // 004026b1: xor ebx, ebx
         // 004026b3: cmp ss:[ebp+0x8], ebx
         // 004026b6: lea ecx, ss:[esp+0xa0]
         // 004026bd: mov ss:[esp+0x20], ecx
         // 004026c1: mov ecx, ss:[ebp+0x1c]
         // 004026c4: push esi
         // 004026c5: push edi
         // 004026c6: mov b2 ss:[esp+0xa8], b2 bx
         // 004026ce: mov b2 ss:[esp+0x10a8], b2 bx
         // 004026d6: mov b2 ss:[esp+0x20a8], b2 bx
         // 004026de: mov ds:[eax+0x427ed8], ecx
      [-]895c24100f8e
         // 004026e4: mov ss:[esp+0x10], ebx
         // 004026e8: jle 0x4027dd
      [-]895c2420895c2424895c241c53eb5b
         // 004026f0: mov ss:[esp+0x20], ebx
         // 004026f4: mov ss:[esp+0x24], ebx
         // 004026f8: mov ss:[esp+0x1c], ebx
         // 004026fc: push ebx
         // 004026fd: jmp 0x40275a
      [-]837c2414057367
         // 0040270a: cmp ss:[esp+0x14], 0x5
         // 0040270f: jnb 0x402778
      [-]598db424
         // 00402719: pop ecx
         // 0040271a: lea esi, ss:[esp+0xa4]
      [-]8bfcf3a5e8bc0000008bf081c4
         // 00402721: mov edi, esp
         // 00402723: rep movsdd 
         // 00402725: call 0x4027e6
         // 0040272a: mov esi, eax
         // 0040272c: add esp, 0x84
      [-]3bf3750a
         // 00402732: cmp esi, ebx
         // 00402734: jnz 0x402740
      [-]ff442418895c2414eb04
         // 00402736: inc ss:[esp+0x18]
         // 0040273a: mov ss:[esp+0x14], ebx
         // 0040273e: jmp 0x402744
      [-]ff442414
         // 00402740: inc ss:[esp+0x14]
      [-]ffb424????????8a8c2490000000ff442420e8
         // 00402739: push ss:[esp+0x8b]
         // 00402740: mov b1 cl, b1 ss:[esp+0x90]
         // 00402747: inc ss:[esp+0x20]
         // 0040274b: call 0x4076a9
      [-]000059ff74241cff74241c56
         // 00402750: pop ecx
         // 00402751: push ss:[esp+0x1c]
         // 00402755: push ss:[esp+0x1c]
         // 00402759: push esi
      [-]8d44242c50ff742420ff550c83c41485c07592
         // 00402765: lea eax, ss:[esp+0x2c]
         // 00402769: push eax
         // 0040276a: push ss:[esp+0x20]
         // 0040276e: call ss:[ebp+0xc]
         // 00402771: add esp, 0x14
         // 00402774: test eax, eax
         // 00402776: jnz 0x40270a
      [-]33c93bc37407
         // 0040277d: xor ecx, ecx
         // 0040277f: cmp eax, ebx
         // 00402781: jz 0x40278a
      [-]389c248e000000742d
         // 0040278a: cmp b1 ss:[esp+0x8e], b1 bl
         // 00402791: jz 0x4027c0
      [-]0fb6842495000000500fb6842498000000500fb6842496000000518b8c24????????6a0150e8
         // 00402788: movzx eax, b1 ss:[esp+0x95]
         // 00402790: push eax
         // 00402791: movzx eax, b1 ss:[esp+0x98]
         // 00402799: push eax
         // 0040279a: movzx eax, b1 ss:[esp+0x96]
         // 004027a2: push ecx
         // 004027a3: mov ecx, ss:[esp+0x9c]
         // 004027aa: push 0x1
         // 004027ac: push eax
         // 004027ad: call 0x40aa07
      [-]000083c414
         // 004027b2: add esp, 0x14
      [-]ff75108a4d14e8
         // 004047d4: push ss:[ebp+0x10]
         // 004047d7: mov b1 cl, b1 ss:[ebp+0x14]
         // 004047da: call 0x407298
      [-]0000ff4424148b4424143b4508590f8c
         // 004047df: inc ss:[esp+0x14]
         // 004047e3: mov eax, ss:[esp+0x14]
         // 004047e7: cmp eax, ss:[ebp+0x8]
         // 004047ea: pop ecx
         // 004047eb: jl 0x404702
      [-]5f5e33c05b8be55dc3
         // 004027dd: pop edi
         // 004027de: pop esi
         // 004027df: xor eax, eax
         // 004027e1: pop ebx
         // 004027e2: mov esp, ebp
         // 004027e4: pop ebp
         // 004027e5: retn 
      [-]558bec81ec
         // 004027db: push ebp
         // 004027dc: mov ebp, esp
         // 004027de: sub esp, 0x8e0
      [-]53565733f656ff15
         // 004027e4: push ebx
         // 004027e5: push esi
         // 004027e6: push edi
         // 004027e7: xor esi, esi
         // 004027e9: push esi
         // 004027ea: call ds:[OleInitialize]
      [-]40008b5d755333c0e8
         // 004027f0: mov ebx, ss:[ebp+0x75]
         // 004027f3: push ebx
         // 004027f4: xor eax, eax
         // 004027f6: call 0x40a578
      [-]000085c0597508
         // 004027fb: test eax, eax
         // 004027fd: pop ecx
         // 004027fe: jnz 0x402808
      [-]8b7d6883ff017405
         // 00402813: mov edi, ss:[ebp+0x68]
         // 00402816: cmp edi, 0x1
         // 00402819: jz 0x402820
      [-]83ff057518
         // 0040281b: cmp edi, 0x5
         // 0040281e: jnz 0x402838
      [-]0000598db5
         // 00402826: pop ecx
         // 00402827: lea esi, ss:[ebp+0xfffffffffffff724]
      [-]5653ff751433c9ff750cff7508e8
         // 0040282d: push esi
         // 0040282e: push ebx
         // 0040282f: push ss:[ebp+0x14]
         // 00402832: xor ecx, ecx
         // 00402834: push ss:[ebp+0xc]
         // 00402837: push ss:[ebp+0x8]
         // 0040283a: call 0x40a454
      [-]000083c41485c0750e
         // 0040283f: add esp, 0x14
         // 00402842: test eax, eax
         // 00402844: jnz 0x402854
      [-]33c040e9
         // 00402857: xor eax, eax
         // 00402859: inc eax
         // 0040285a: jmp 0x402c2c
      [-]83ff027405
         // 0040285f: cmp edi, 0x2
         // 00402862: jz 0x402869
      [-]83ff077510
         // 00402864: cmp edi, 0x7
         // 00402867: jnz 0x402879
      [-]8b4d6d518acde8
         // 0040286e: mov ecx, ss:[ebp+0x6d]
         // 00402871: push ecx
         // 00402872: mov b1 cl, b1 ch
         // 00402874: call 0x40a03a
      [-]000083ff02597409
         // 00402879: cmp edi, 0x2
         // 0040287c: pop ecx
         // 0040287d: jz 0x402888
      [-]83ff070f85d7000000
         // 0040288a: cmp edi, 0x7
         // 0040288d: jnz 0x40296a
      [-]33c03905
         // 00402888: xor eax, eax
         // 0040288a: cmp ds:[0x4246cc], eax
      [-]505033f68ac3e8
         // 0040289e: push eax
         // 0040289f: push eax
         // 004028a0: xor esi, esi
         // 004028a2: mov b1 al, b1 bl
         // 004028a4: call 0x409040
      [-]000083c414
         // 004028a9: add esp, 0x14
      [-]000f84a6000000
         // 004028b3: jz 0x40295f
      [-]80ff6ab8
         // 004028b9: cmp b1 bh, b1 0x6a
         // 004028bc: mov eax, 0x40989c
      [-]6a2157508d85
         // 004028c8: push 0x21
         // 004028ca: push edi
         // 004028cb: push eax
         // 004028cc: lea eax, ss:[ebp+0xffffffffffffff24]
      [-]6a21508d75
         // 004028d2: push 0x21
         // 004028d4: push eax
         // 004028d5: lea esi, ss:[ebp+0xfffffffffffffff4]
      [-]000083c41485c07465
         // 004028df: add esp, 0x14
         // 004028e2: test eax, eax
         // 004028e4: jz 0x40294b
      [-]00008b3d
         // 00402904: mov edi, ds:[SysAllocString]
      [-]40008bf0ffb4b5
         // 0040290a: mov esi, eax
         // 0040290c: push ss:[ebp+esi*0x4]
      [-]ffffffffd78935
         // 00402913: call edi
         // 00402915: mov ds:[0x4114dc], esi
      [-]33f63975
         // 0040291b: xor esi, esi
         // 0040291d: cmp ss:[ebp+0xfffffffffffffff4], esi
      [-]ffffffff15
         // 00402923: call ds:[SysFreeString]
      [-]4000463b75
         // 00402929: inc esi
         // 0040292a: cmp esi, ss:[ebp+0xfffffffffffffff4]
      [-]33c0eb08
         // 00402943: xor eax, eax
         // 00402945: jmp 0x40294f
      [-]8a4575e8
         // 0040293c: mov b1 al, b1 ss:[ebp+0x75]
         // 0040293f: call 0x4092cc
      [-]5333c0e800
         // 00402956: push ebx
         // 00402957: xor eax, eax
         // 00402959: call 0x40a65e
      [-]00e9edfeffff
         // 00402965: jmp 0x402857
      [-]33db399d
         // 00402970: xor ebx, ebx
         // 00402972: cmp ss:[ebp+0x88], ebx
      [-]33f6837d68017536
         // 0040297e: xor esi, esi
         // 00402980: cmp ss:[ebp+0x68], 0x1
         // 00402984: jnz 0x4029bc
      [-]8a4575e8
         // 0040297b: mov b1 al, b1 ss:[ebp+0x75]
         // 0040297e: call 0x40a678
      [-]00006a2168
         // 00402983: push 0x21
         // 00402985: push 0x409511
      [-]6a218d8d
         // 0040298a: push 0x21
         // 0040298c: lea ecx, ss:[ebp+0xffffffffffffff24]
      [-]51508d5d
         // 00402992: push ecx
         // 00402993: push eax
         // 00402994: lea ebx, ss:[ebp+0xfffffffffffffff8]
      [-]000083c4148d55
         // 0040299f: add esp, 0x14
         // 004029a2: lea edx, ss:[ebp+0xfffffffffffffff4]
      [-]8bf08b45
         // 004029a5: mov esi, eax
         // 004029a7: mov eax, ss:[ebp+0xfffffffffffffff0]
      [-]8b085250ff5178
         // 004029aa: mov ecx, ds:[eax]
         // 004029ac: push edx
         // 004029ad: push eax
         // 004029ae: call ds:[ecx+0x78]
      [-]837d68057536
         // 004029bc: cmp ss:[ebp+0x68], 0x5
         // 004029c0: jnz 0x4029f8
      [-]8a4575e8
         // 004029b7: mov b1 al, b1 ss:[ebp+0x75]
         // 004029ba: call 0x40a678
      [-]00006a0b68
         // 004029bf: push 0xb
         // 004029c1: push 0x409554
      [-]6a0b8d8d
         // 004029c6: push 0xb
         // 004029c8: lea ecx, ss:[ebp+0xffffffffffffff24]
      [-]51508d5d
         // 004029ce: push ecx
         // 004029cf: push eax
         // 004029d0: lea ebx, ss:[ebp+0xfffffffffffffff8]
      [-]000083c4148d55
         // 004029db: add esp, 0x14
         // 004029de: lea edx, ss:[ebp+0xfffffffffffffff4]
      [-]8bf08b45
         // 004029e1: mov esi, eax
         // 004029e3: mov eax, ss:[ebp+0xfffffffffffffff0]
      [-]8b085250ff5178
         // 004029e6: mov ecx, ds:[eax]
         // 004029e8: push edx
         // 004029e9: push eax
         // 004029ea: call ds:[ecx+0x78]
      [-]837d68027406
         // 004029f8: cmp ss:[ebp+0x68], 0x2
         // 004029fc: jz 0x402a04
      [-]837d68077537
         // 004029fe: cmp ss:[ebp+0x68], 0x7
         // 00402a02: jnz 0x402a3b
      [-]33f63935
         // 00402a04: xor esi, esi
         // 00402a06: cmp ds:[0x4114d8], esi
      [-]00008985
         // 00404a2b: mov ss:[ebp+0xffffffffffffff28], eax
      [-]0000ff7510ffd7ff35
         // 00404a3b: push ss:[ebp+0x10]
         // 00404a3e: call edi
         // 00404a40: push ds:[0x40d3d8]
      [-]837d6803bb
         // 00402a30: cmp ss:[ebp+0x68], 0x3
         // 00402a34: mov ebx, 0x409a18
      [-]6a0b508a45758d75
         // 00402a49: push 0xb
         // 00402a4b: push eax
         // 00402a4c: mov b1 al, b1 ss:[ebp+0x75]
         // 00402a4f: lea esi, ss:[ebp+0xfffffffffffffff8]
      [-]000083c414ff75108bf0ffd78945
         // 00402a57: add esp, 0x14
         // 00402a5a: push ss:[ebp+0x10]
         // 00402a5d: mov esi, eax
         // 00402a5f: call edi
         // 00402a61: mov ss:[ebp+0xfffffffffffffff4], eax
      [-]837d6806752d
         // 00402a6f: cmp ss:[ebp+0x68], 0x6
         // 00402a73: jnz 0x402aa2
      [-]6a0b508a45758d75
         // 00402a7c: push 0xb
         // 00402a7e: push eax
         // 00402a7f: mov b1 al, b1 ss:[ebp+0x75]
         // 00402a82: lea esi, ss:[ebp+0xfffffffffffffff8]
      [-]000083c414ff75108bf0ffd78945
         // 00402a8a: add esp, 0x14
         // 00402a8d: push ss:[ebp+0x10]
         // 00402a90: mov esi, eax
         // 00402a92: call edi
         // 00402a94: mov ss:[ebp+0xfffffffffffffff4], eax
      [-]6a0b508a45758d75
         // 00402ade: push 0xb
         // 00402ae0: push eax
         // 00402ae1: mov b1 al, b1 ss:[ebp+0x75]
         // 00402ae4: lea esi, ss:[ebp+0xfffffffffffffff8]
      [-]000083c414ff75108bf0ffd78945
         // 00402aec: add esp, 0x14
         // 00402aef: push ss:[ebp+0x10]
         // 00402af2: mov esi, eax
         // 00402af4: call edi
         // 00402af6: mov ss:[ebp+0xfffffffffffffff4], eax
      [-]ff757533c0e8
         // 00402af9: push ss:[ebp+0x75]
         // 00402afc: xor eax, eax
         // 00402afe: call 0x40a76d
      [-]000085f6597507
         // 00402b03: test esi, esi
         // 00402b05: pop ecx
         // 00402b06: jnz 0x402b0f
      [-]33db837d6801c745
         // 00402b15: xor ebx, ebx
         // 00402b17: cmp ss:[ebp+0x68], 0x1
         // 00402b1b: mov ss:[ebp+0xfffffffffffffff0], 0x1
      [-]6a035999f7f98bdebf
         // 00402b27: push 0x3
         // 00402b29: pop ecx
         // 00402b2a: cdq 
         // 00402b2b: idiv ecx
         // 00402b2d: mov ebx, esi
         // 00402b2f: mov edi, 0x4245e4
      [-]00008bd8
         // 00402b3c: mov ebx, eax
      [-]837d68047406
         // 00402b49: cmp ss:[ebp+0x68], 0x4
         // 00402b4d: jz 0x402b55
      [-]837d68037516
         // 00402b4f: cmp ss:[ebp+0x68], 0x3
         // 00402b53: jnz 0x402b6b
      [-]00008bd8e8
         // 00402b59: mov ebx, eax
         // 00402b5b: call 0x409d58
      [-]000099f77d
         // 00402b76: cdq 
         // 00402b77: idiv ss:[ebp+0xfffffffffffffff8]
      [-]837d6806750b
         // 00402b9e: cmp ss:[ebp+0x68], 0x6
         // 00402ba2: jnz 0x402baf
      [-]000099f77d
         // 00402b9e: cdq 
         // 00402b9f: idiv ss:[ebp+0xfffffffffffffff8]
      [-]83fb037502
         // 00402bfa: cmp ebx, 0x3
         // 00402bfd: jnz 0x402c01
      [-]4000ffd6397d
         // 00402bff: call esi
         // 00402c01: cmp ss:[ebp+0xfffffffffffffff8], edi
      [-]ffffffffd6473b7d
         // 00402c18: call esi
         // 00402c1a: inc edi
         // 00402c1b: cmp edi, ss:[ebp+0xfffffffffffffff8]
      [-]ff757533c0e8
         // 00402c15: push ss:[ebp+0x75]
         // 00402c18: xor eax, eax
         // 00402c1a: call 0x40a76d
      [-]00008bc3
         // 00402c1f: mov eax, ebx
      [-]5f5e5bc9c3
         // 00402c2d: pop edi
         // 00402c2e: pop esi
         // 00402c2f: pop ebx
         // 00402c30: leave 
         // 00402c31: retn 
      [-]006a02ff7424086a0a6a0a68
         // 00402c40: push 0x2
         // 00402c42: push ss:[esp+0x8]
         // 00402c46: push 0xa
         // 00402c48: push 0xa
         // 00402c4a: push 0x401010
      [-]faffff83c418e8
         // 00402c56: add esp, 0x18
         // 00402c59: call 0x409c6f
      [-]000033c040c3
         // 00402c5e: xor eax, eax
         // 00402c60: inc eax
         // 00402c61: retn 
      [-]006a02ff7424086a0a6a0a68
         // 00402d1c: push 0x2
         // 00402d1e: push ss:[esp+0x8]
         // 00402d22: push 0xa
         // 00402d24: push 0xa
         // 00402d26: push 0x401652
      [-]ffff83c418e8
         // 00402d32: add esp, 0x18
         // 00402d35: call 0x409c6f
      [-]000033c040c3
         // 00402d3a: xor eax, eax
         // 00402d3c: inc eax
         // 00402d3d: retn 
      [-]558bec81ec????????568d85????????5750e8
         // 00402d33: push ebp
         // 00402d34: mov ebp, esp
         // 00402d36: sub esp, 0x800
         // 00402d3c: push esi
         // 00402d3d: lea eax, ss:[ebp+0xfffffffffffff800]
         // 00402d43: push edi
         // 00402d44: push eax
         // 00402d45: call 0x406c74
      [-]000059e8
         // 00402d4a: pop ecx
         // 00402d4b: call 0x406cb2
      [-]00008b0d
         // 00402d50: mov ecx, ds:[0x41d4b8]
      [-]33f683c1643935
         // 00402d56: xor esi, esi
         // 00402d58: add ecx, 0x64
         // 00402d5b: cmp ds:[0x42458c], esi
      [-]6a025f7403
         // 00402d61: push 0x2
         // 00402d63: pop edi
         // 00402d64: jz 0x402d69
      [-]56505656518d8d????????e8
         // 00402d74: push esi
         // 00402d75: push eax
         // 00402d76: push esi
         // 00402d77: push esi
         // 00402d78: push ecx
         // 00402d79: lea ecx, ss:[ebp+0xfffffffffffff800]
         // 00402d7f: call 0x40a8f9
      [-]000057ff75088935
         // 00402d84: push edi
         // 00402d85: push ss:[ebp+0x8]
         // 00402d88: mov ds:[0x4121fc], esi
      [-]6a146a1468
         // 00402d8e: push 0x14
         // 00402d90: push 0x14
         // 00402d92: push 0x402214
      [-]ffff83c42ce8
         // 00402da8: add esp, 0x2c
         // 00402dab: call 0x409c6f
      [-]000033c05f405ec9c3
         // 00402db0: xor eax, eax
         // 00402db2: pop edi
         // 00402db3: inc eax
         // 00402db4: pop esi
         // 00402db5: leave 
         // 00402db6: retn 
      [-]6a01ff7424086a146a1468
         // 00402dac: push 0x1
         // 00402dae: push ss:[esp+0x8]
         // 00402db2: push 0x14
         // 00402db4: push 0x14
         // 00402db6: push 0x40183a
      [-]ffff83c418c3
         // 00402dc6: add esp, 0x18
         // 00402dc9: retn 
      [-]6a02ff7424086a146a1468
         // 00402dd5: push 0x2
         // 00402dd7: push ss:[esp+0x8]
         // 00402ddb: push 0x14
         // 00402ddd: push 0x14
         // 00402ddf: push 0x401473
      [-]ffff83c418c3
         // 00402def: add esp, 0x18
         // 00402df2: retn 
      [-]6a7cc1e602508b86
         // 00402e74: push 0x7c
         // 00402e76: shl esi, b1 0x2
         // 00402e79: push eax
         // 00402e7a: mov eax, ds:[esi+0x4239e8]
      [-]6633ffe8
         // 00402e80: xor b2 di, b2 di
         // 00402e83: call 0x40586b
      [-]0000eb0c
         // 00402ec9: jmp 0x402ed7
      [-]5768????????ff15
         // 00402ed6: push edi
         // 00402ed7: push 0x1000
         // 00402edc: call ds:[GetCurrentDirectoryW]
      [-]508bd7e8
         // 00402ee8: push eax
         // 00402ee9: mov edx, edi
         // 00402eeb: call 0x405511
      [-]000059b9
         // 00402ef0: pop ecx
         // 00402ef1: mov ecx, 0x40e33c
      [-]00008b8e
         // 00402f01: mov ecx, ds:[esi+0x4236e8]
      [-]00008b96
         // 00402f0c: mov edx, ds:[esi+0x4150b8]
      [-]000085c07506
         // 00402f15: test eax, eax
         // 00402f17: jnz 0x402f1f
      [-]6a03ffb6
         // 00404f22: push 0x3
         // 00404f24: push ds:[esi+0x410600]
      [-]ffff83c4
         // 00404f39: add esp, 0x1c
      [-]6a03ffb6
         // 00403201: push 0x3
         // 00403203: push ds:[esi+0x4150b8]
      [-]ffff83c4
         // 00403223: add esp, 0x20
      [-]6a00ff15
         // 004032af: push 0x0
         // 004032b1: call ds:[ExitProcess]
      [-]558bec51535657e8
         // 004032b8: push ebp
         // 004032b9: mov ebp, esp
         // 004032bb: push ecx
         // 004032bc: push ebx
         // 004032bd: push esi
         // 004032be: push edi
         // 004032bf: call 0x406a68
      [-]00008b35
         // 004032ce: mov esi, ds:[GetSystemMetrics]
      [-]400033ff33db4753a3
         // 004032d4: xor edi, edi
         // 004032d6: xor ebx, ebx
         // 004032d8: inc edi
         // 004032d9: push ebx
         // 004032da: mov ds:[0x423ea8], eax
      [-]ffd657a3??
         // 004032e5: call esi
         // 004032e7: push edi
         // 004032e8: mov ds:[0x41fdb0], eax
      [-]ffd68b35
         // 004032ed: call esi
         // 004032ef: mov esi, ds:[MessageBoxW]
      [-]40008b3d
         // 004032f5: mov edi, ds:[VirtualProtect]
      [-]8d45fc506a086a0a56ffd7c606b8468bc6c6000740881840881840881840c600c240c60010408d4dfc518818ff75fc406a0a50ffd768
         // 00403300: lea eax, ss:[ebp+0xfffffffffffffffc]
         // 00403303: push eax
         // 00403304: push 0x8
         // 00403306: push 0xa
         // 00403308: push esi
         // 00403309: call edi
         // 0040330b: mov b1 ds:[esi], b1 0xb8
         // 0040330e: inc esi
         // 0040330f: mov eax, esi
         // 00403311: mov b1 ds:[eax], b1 0x7
         // 00403314: inc eax
         // 00403315: mov b1 ds:[eax], b1 bl
         // 00403317: inc eax
         // 00403318: mov b1 ds:[eax], b1 bl
         // 0040331a: inc eax
         // 0040331b: mov b1 ds:[eax], b1 bl
         // 0040331d: inc eax
         // 0040331e: mov b1 ds:[eax], b1 0xc2
         // 00403321: inc eax
         // 00403322: mov b1 ds:[eax], b1 0x10
         // 00403325: inc eax
         // 00403326: lea ecx, ss:[ebp+0xfffffffffffffffc]
         // 00403329: push ecx
         // 0040332a: mov b1 ds:[eax], b1 bl
         // 0040332c: push ss:[ebp+0xfffffffffffffffc]
         // 0040332f: inc eax
         // 00403330: push 0xa
         // 00403332: push eax
         // 00403333: call edi
         // 00403335: push 0x4032af
      [-]40008bf83bfb7448
         // 0040334b: mov edi, eax
         // 0040334d: cmp edi, ebx
         // 0040334f: jz 0x403399
      [-]57ffd668
         // 0040335c: push edi
         // 0040335d: call esi
         // 0040335f: push 0x40e3b8
      [-]ffd6391d??
         // 00403377: call esi
         // 00403379: cmp ds:[0x413200], ebx
      [-]33c0891d
         // 00403383: xor eax, eax
         // 00403385: mov ds:[0x411094], ebx
      [-]5f5e5bc9c3
         // 0040339b: pop edi
         // 0040339c: pop esi
         // 0040339d: pop ebx
         // 0040339e: leave 
         // 0040339f: retn 
      [-]8b442404
         // 00405451: mov eax, ss:[esp+0x4]
      [-]668b0840406685c975f6
         // 00405455: mov b2 cx, b2 ds:[eax]
         // 00405458: inc eax
         // 00405459: inc eax
         // 0040545a: test b2 cx, b2 cx
         // 0040545d: jnz 0x405455
      [-]2b442404d1f848c3
         // 0040545f: sub eax, ss:[esp+0x4]
         // 00405463: sar eax, b1 0x1
         // 00405465: dec eax
         // 00405466: retn 
      [-]56578bf0eb09
         // 00405467: push esi
         // 00405468: push edi
         // 00405469: mov esi, eax
         // 0040546b: jmp 0x405476
      [-]6685c97411
         // 0040546d: test b2 cx, b2 cx
         // 00405470: jz 0x405483
      [-]42424646
         // 00405472: inc edx
         // 00405473: inc edx
         // 00405474: inc esi
         // 00405475: inc esi
      [-]0fb70e0fb7020fb7f92bc774ea
         // 00405476: movzx ecx, b2 ds:[esi]
         // 00405479: movzx eax, b2 ds:[edx]
         // 0040547c: movzx edi, b2 cx
         // 0040547f: sub eax, edi
         // 00405481: jz 0x40546d
      [-]85c05f5e7d04
         // 00405483: test eax, eax
         // 00405485: pop edi
         // 00405486: pop esi
         // 00405487: jge 0x40548d
      [-]83c8ffc3
         // 00405489: or eax, 0xffffffffffffffff
         // 0040548c: retn 
      [-]66833800568bf18bc87408
         // 004054ed: cmp b2 ds:[eax], b2 0x0
         // 004054f1: push esi
         // 004054f2: mov esi, ecx
         // 004054f4: mov ecx, eax
         // 004054f6: jz 0x405500
      [-]41416683390075f8
         // 004054f8: inc ecx
         // 004054f9: inc ecx
         // 004054fa: cmp b2 ds:[ecx], b2 0x0
         // 004054fe: jnz 0x4054f8
      [-]0fb716668911414146466685d275f1
         // 00405500: movzx edx, b2 ds:[esi]
         // 00405503: mov b2 ds:[ecx], b2 dx
         // 00405506: inc ecx
         // 00405507: inc ecx
         // 00405508: inc esi
         // 00405509: inc esi
         // 0040550a: test b2 dx, b2 dx
         // 0040550d: jnz 0x405500
      [-]8b4c2404
         // 00405511: mov ecx, ss:[esp+0x4]
      [-]0fb702668901414142426685c075f1
         // 00405515: movzx eax, b2 ds:[edx]
         // 00405518: mov b2 ds:[ecx], b2 ax
         // 0040551b: inc ecx
         // 0040551c: inc ecx
         // 0040551d: inc edx
         // 0040551e: inc edx
         // 0040551f: test b2 ax, b2 ax
         // 00405522: jnz 0x405515
      [-]8b442404c3
         // 00405524: mov eax, ss:[esp+0x4]
         // 00405528: retn 
      [-]663d09007206
         // 004055bb: cmp b2 ax, b2 0x9
         // 004055bf: jb 0x4055c7
      [-]663d0d007606
         // 004055c1: cmp b2 ax, b2 0xd
         // 004055c5: jbe 0x4055cd
      [-]663d20007504
         // 004055c7: cmp b2 ax, b2 0x20
         // 004055cb: jnz 0x4055d1
      [-]33c040c3
         // 004055cd: xor eax, eax
         // 004055cf: inc eax
         // 004055d0: retn 
      [-]8bf033ffeb02
         // 0040562a: mov esi, eax
         // 0040562c: xor edi, edi
         // 0040562e: jmp 0x405632
      [-]668b06e8
         // 00405632: mov b2 ax, b2 ds:[esi]
         // 00405635: call 0x4055bb
      [-]ffffff85c075f2
         // 0040563a: test eax, eax
         // 0040563c: jnz 0x405630
      [-]66833e2d75
         // 0040563e: cmp b2 ds:[esi], b2 0x2d
         // 00405642: jnz 0x405649
      [-]66833e2b751a
         // 00405649: cmp b2 ds:[esi], b2 0x2b
         // 0040564d: jnz 0x405669
      [-]663d300072
         // 00405651: cmp b2 ax, b2 0x30
         // 00405655: jb 0x40567a
      [-]663d390077
         // 00405657: cmp b2 ax, b2 0x39
         // 0040565b: ja 0x40567a
      [-]6bff0a0fb7c08d7c07d0
         // 0040565d: imul edi, b1 0xa
         // 00405660: movzx eax, b2 ax
         // 00405663: lea edi, ds:[edi+eax+0xffffffffffffffd0]
      [-]0fb7066685c075e0
         // 00405669: movzx eax, b2 ds:[esi]
         // 0040566c: test b2 ax, b2 ax
         // 0040566f: jnz 0x405651
      [-]558bec515153565733ff8bf033dbeb02
         // 0040567e: push ebp
         // 0040567f: mov ebp, esp
         // 00405681: push ecx
         // 00405682: push ecx
         // 00405683: push ebx
         // 00405684: push esi
         // 00405685: push edi
         // 00405686: xor edi, edi
         // 00405688: mov esi, eax
         // 0040568a: xor ebx, ebx
         // 0040568c: jmp 0x405690
      [-]668b06e8
         // 00405690: mov b2 ax, b2 ds:[esi]
         // 00405693: call 0x4055bb
      [-]ffffff85c075f2
         // 00405698: test eax, eax
         // 0040569a: jnz 0x40568e
      [-]66833e2d7502
         // 0040569c: cmp b2 ds:[esi], b2 0x2d
         // 004056a0: jnz 0x4056a4
      [-]66833e2b7538
         // 004056a4: cmp b2 ds:[esi], b2 0x2b
         // 004056a8: jnz 0x4056e2
      [-]663d30007241
         // 004056ac: cmp b2 ax, b2 0x30
         // 004056b0: jb 0x4056f3
      [-]663d3900773b
         // 004056b2: cmp b2 ax, b2 0x39
         // 004056b6: ja 0x4056f3
      [-]0fb7c06a0083e830996a0a538bca578945fc894df8e8
         // 004056b5: movzx eax, b2 ax
         // 004056b8: push 0x0
         // 004056ba: sub eax, 0x30
         // 004056bd: cdq 
         // 004056be: push 0xa
         // 004056c0: push ebx
         // 004056c1: mov ecx, edx
         // 004056c3: push edi
         // 004056c4: mov ss:[ebp+0xfffffffffffffffc], eax
         // 004056c7: mov ss:[ebp+0xfffffffffffffff8], ecx
         // 004056ca: call 0x40d540
      [-]00008b4dfc03c88b45f813c28bf98bd8
         // 004056cf: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 004056d2: add ecx, eax
         // 004056d4: mov eax, ss:[ebp+0xfffffffffffffff8]
         // 004056d7: adc eax, edx
         // 004056d9: mov edi, ecx
         // 004056db: mov ebx, eax
      [-]0fb7066685c075c2
         // 004056e2: movzx eax, b2 ds:[esi]
         // 004056e5: test b2 ax, b2 ax
         // 004056e8: jnz 0x4056ac
      [-]8bc78bd3
         // 004056ea: mov eax, edi
         // 004056ec: mov edx, ebx
      [-]5f5e5bc9c3
         // 004056ee: pop edi
         // 004056ef: pop esi
         // 004056f0: pop ebx
         // 004056f1: leave 
         // 004056f2: retn 
      [-]33c033d2ebf5
         // 004056f3: xor eax, eax
         // 004056f5: xor edx, edx
         // 004056f7: jmp 0x4056ee
      [-]53568bf0578bf9b8????????3bf88bde8bc87311
         // 004056f9: push ebx
         // 004056fa: push esi
         // 004056fb: mov esi, eax
         // 004056fd: push edi
         // 004056fe: mov edi, ecx
         // 00405700: mov eax, 0x3b9aca00
         // 00405705: cmp edi, eax
         // 00405707: mov ebx, esi
         // 00405709: mov ecx, eax
         // 0040570b: jnb 0x40571e
      [-]8bc16a0a33d259f7f18bc83bf972f1
         // 0040570d: mov eax, ecx
         // 0040570f: push 0xa
         // 00405711: xor edx, edx
         // 00405713: pop ecx
         // 00405714: div ecx
         // 00405716: mov ecx, eax
         // 00405718: cmp edi, ecx
         // 0040571a: jb 0x40570d
      [-]33d28bc7f7f16a0a8d50300fafc12bf86689168bc133d259f7f146468bc8
         // 0040571e: xor edx, edx
         // 00405720: mov eax, edi
         // 00405722: div ecx
         // 00405724: push 0xa
         // 00405726: lea edx, ds:[eax+0x30]
         // 00405729: imul eax, ecx
         // 0040572c: sub edi, eax
         // 0040572e: mov b2 ds:[esi], b2 dx
         // 00405731: mov eax, ecx
         // 00405733: xor edx, edx
         // 00405735: pop ecx
         // 00405736: div ecx
         // 00405738: inc esi
         // 00405739: inc esi
         // 0040573a: mov ecx, eax
      [-]85c975de
         // 0040573c: test ecx, ecx
         // 0040573e: jnz 0x40571e
      [-]66210e5f5e8bc35bc3
         // 00405740: and b2 ds:[esi], b2 cx
         // 00405743: pop edi
         // 00405744: pop esi
         // 00405745: mov eax, ebx
         // 00405747: pop ebx
         // 00405748: retn 
      [-]558bec51538bd88b45080b450c5657895dfc750d
         // 004057b5: push ebp
         // 004057b6: mov ebp, esp
         // 004057b8: push ecx
         // 004057b9: push ebx
         // 004057ba: mov ebx, eax
         // 004057bc: mov eax, ss:[ebp+0x8]
         // 004057bf: or eax, ss:[ebp+0xc]
         // 004057c2: push esi
         // 004057c3: push edi
         // 004057c4: mov ss:[ebp+0xfffffffffffffffc], ebx
         // 004057c7: jnz 0x4057d6
      [-]66c7033000662143028bc3eb72
         // 004057c9: mov b2 ds:[ebx], b2 0x30
         // 004057ce: and b2 ds:[ebx+0x2], b2 ax
         // 004057d2: mov eax, ebx
         // 004057d4: jmp 0x405848
      [-]be????????39750cbf????????7724
         // 004057d6: mov esi, 0xffffffff8ac72304
         // 004057db: cmp ss:[ebp+0xc], esi
         // 004057de: mov edi, 0xffffffff89e80000
         // 004057e3: ja 0x405809
      [-]397d08731d
         // 004057e7: cmp ss:[ebp+0x8], edi
         // 004057ea: jnb 0x405809
      [-]6a006a0a5657e8
         // 004057e9: push 0x0
         // 004057eb: push 0xa
         // 004057ed: push esi
         // 004057ee: push edi
         // 004057ef: call 0x40d4d0
      [-]00008bf239750c8bf872ec
         // 004057f4: mov esi, edx
         // 004057f6: cmp ss:[ebp+0xc], esi
         // 004057f9: mov edi, eax
         // 004057fb: jb 0x4057e9
      [-]397d0872e5
         // 00405802: cmp ss:[ebp+0x8], edi
         // 00405805: jb 0x4057ec
      [-]5657ff750cff7508e8
         // 00405806: push esi
         // 00405807: push edi
         // 00405808: push ss:[ebp+0xc]
         // 0040580b: push ss:[ebp+0x8]
         // 0040580e: call 0x40d4d0
      [-]00005657528d48305066890be8
         // 00405813: push esi
         // 00405814: push edi
         // 00405815: push edx
         // 00405816: lea ecx, ds:[eax+0x30]
         // 00405819: push eax
         // 0040581a: mov b2 ds:[ebx], b2 cx
         // 0040581d: call 0x40d540
      [-]00002945086a006a0a19550c5657e8
         // 00405822: sub ss:[ebp+0x8], eax
         // 00405825: push 0x0
         // 00405827: push 0xa
         // 00405829: sbb ss:[ebp+0xc], edx
         // 0040582c: push esi
         // 0040582d: push edi
         // 0040582e: call 0x40d4d0
      [-]0000438bf88bf243
         // 00405833: inc ebx
         // 00405834: mov edi, eax
         // 00405836: mov esi, edx
         // 00405838: inc ebx
      [-]8bc70bc675c7
         // 0040583c: mov eax, edi
         // 0040583e: or eax, esi
         // 00405840: jnz 0x405809
      [-]6621038b45fc
         // 00405842: and b2 ds:[ebx], b2 ax
         // 00405845: mov eax, ss:[ebp+0xfffffffffffffffc]
      [-]5f5e5bc9c3
         // 00405848: pop edi
         // 00405849: pop esi
         // 0040584a: pop ebx
         // 0040584b: leave 
         // 0040584c: retn 
      [-]69c0????????05????????a3
         // 00405852: imul eax, 0x343fd
         // 00405858: add eax, 0x269ec3
         // 0040585d: mov ds:[0x4114e0], eax
      [-]c1e81025????????c3
         // 00405862: shr eax, b1 0x10
         // 00405865: and eax, 0x7fff
         // 0040586a: retn 
      [-]558bec83ec2c8365fc00
         // 0040556c: push ebp
         // 0040556d: mov ebp, esp
         // 0040556f: sub esp, 0x2c
         // 00405572: and ss:[ebp+0xfffffffffffffffc], 0x0
      [-]508b450883c012
         // 00405580: push eax
         // 00405581: mov eax, ss:[ebp+0x8]
         // 00405584: add eax, 0x12
      [-]85c07415
         // 00405593: test eax, eax
         // 00405596: jz 0x4055ad
      [-]837dfc01750f
         // 004059a0: cmp ss:[ebp+0xfffffffffffffffc], 0x1
         // 004059a4: jnz 0x4059b5
      [-]8b45d4a3
         // 004059a3: mov eax, ss:[ebp+0xffffffffffffffd4]
         // 004059a6: mov ds:[0x424408], eax
      [-]33c0c9c3
         // 004059b5: xor eax, eax
         // 004059b7: leave 
         // 004059b8: retn 
      [-]558bec83ec348365fc005356578bf08d45fc506a226a5e5b538d45cc5083c61256c745f4????????c745f8????????e8
         // 004059b9: push ebp
         // 004059ba: mov ebp, esp
         // 004059bc: sub esp, 0x34
         // 004059bf: and ss:[ebp+0xfffffffffffffffc], 0x0
         // 004059c3: push ebx
         // 004059c4: push esi
         // 004059c5: push edi
         // 004059c6: mov esi, eax
         // 004059c8: lea eax, ss:[ebp+0xfffffffffffffffc]
         // 004059cb: push eax
         // 004059cc: push 0x22
         // 004059ce: push 0x5e
         // 004059d0: pop ebx
         // 004059d1: push ebx
         // 004059d2: lea eax, ss:[ebp+0xffffffffffffffcc]
         // 004059d5: push eax
         // 004059d6: add esi, 0x12
         // 004059d9: push esi
         // 004059da: mov ss:[ebp+0xfffffffffffffff4], 0x3
         // 004059e1: mov ss:[ebp+0xfffffffffffffff8], 0x1
         // 004059e8: call 0x4058fb
      [-]ffffff83c41485c07425
         // 004059ed: add esp, 0x14
         // 004059f0: test eax, eax
         // 004059f2: jz 0x405a19
      [-]837dfc02751f
         // 004059f4: cmp ss:[ebp+0xfffffffffffffffc], 0x2
         // 004059f8: jnz 0x405a19
      [-]8b45cc85c07418
         // 004059fa: mov eax, ss:[ebp+0xffffffffffffffcc]
         // 004059fd: test eax, eax
         // 004059ff: jz 0x405a19
      [-]8945f48b45d083f8098945f8760a
         // 00405a01: mov ss:[ebp+0xfffffffffffffff4], eax
         // 00405a04: mov eax, ss:[ebp+0xffffffffffffffd0]
         // 00405a07: cmp eax, 0x9
         // 00405a0a: mov ss:[ebp+0xfffffffffffffff8], eax
         // 00405a0d: jbe 0x405a19
      [-]6a0a33d259f7f18955f8
         // 00405a0f: push 0xa
         // 00405a11: xor edx, edx
         // 00405a13: pop ecx
         // 00405a14: div ecx
         // 00405a16: mov ss:[ebp+0xfffffffffffffff8], edx
      [-]6a275f8bc6e8
         // 00405a28: push 0x27
         // 00405a2a: pop edi
         // 00405a2b: mov eax, esi
         // 00405a2d: call 0x405868
      [-]feffff83c40c85
         // 00405a32: add esp, 0xc
         // 00405a35: test eax, eax
         // 00405a37: jz 0x405b11

  }
  condition:
    all of them
}
