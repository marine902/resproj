rule buterat_10_1 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         558bec83ec10f605
         // 00401010: push ebp
         // 00401011: mov ebp, esp
         // 00401013: sub esp, 0x10
         // 00401016: test b1 ds:[0x427ff4], b1 0x1
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
         // 0040104e: mov ds:[0x427f98], ebx
      [-]394d18752f
         // 00401062: cmp ss:[ebp+0x18], ecx
         // 00401065: jnz 0x401096
      [-]c6466701c6466804c646693c884e6ac6466b0ac6466c05898e????????c74660????????894e0ceb06
         // 00401067: mov b1 ds:[esi+0x67], b1 0x1
         // 0040106b: mov b1 ds:[esi+0x68], b1 0x4
         // 0040106f: mov b1 ds:[esi+0x69], b1 0x3c
         // 00401073: mov b1 ds:[esi+0x6a], b1 cl
         // 00401076: mov b1 ds:[esi+0x6b], b1 0xa
         // 0040107a: mov b1 ds:[esi+0x6c], b1 0x5
         // 0040107e: mov ds:[esi+0x80], ecx
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
      [-]83be????????01755b
         // 004010ad: cmp ds:[esi+0x80], 0x1
         // 004010b4: jnz 0x401111
      [-]394d10740e
         // 004010b6: cmp ss:[ebp+0x10], ecx
         // 004010b9: jz 0x4010c9
      [-]837d10057408
         // 004010bb: cmp ss:[ebp+0x10], 0x5
         // 004010bf: jz 0x4010c9
      [-]00008b1d
         // 004010ce: mov ebx, ds:[0x427f98]
      [-]8d0c9d??
         // 004010d4: lea ecx, ds:[0x41f000+ebx*0x4]
      [-]39017312
         // 004010db: cmp ds:[ecx], eax
         // 004010dd: jnb 0x4010f1
      [-]0fb6015032c9e8
         // 004010df: movzx eax, b1 ds:[ecx]
         // 004010e2: push eax
         // 004010e3: xor b1 cl, b1 cl
         // 004010e5: call 0x407552
      [-]00008b1d
         // 004010ea: mov ebx, ds:[0x427f98]
      [-]0043891d
         // 004010f8: inc ebx
         // 004010f9: mov ds:[0x427f98], ebx
      [-]837d1004750a
         // 00401101: cmp ss:[ebp+0x10], 0x4
         // 00401105: jnz 0x401111
      [-]8d470289049d
         // 00401107: lea eax, ds:[edi+0x2]
         // 0040110a: mov ds:[0x423e50+ebx*0x4], eax
      [-]483bd87d6b
         // 0040111f: dec eax
         // 00401120: cmp ebx, eax
         // 00401122: jge 0x40118f
      [-]8bc3c1e0028d88
         // 00401124: mov eax, ebx
         // 00401126: shl eax, b1 0x2
         // 00401129: lea ecx, ds:[eax+0x423e50]
      [-]8b118955088d90
         // 0040112f: mov edx, ds:[ecx]
         // 00401131: mov ss:[ebp+0x8], edx
         // 00401134: lea edx, ds:[eax+0x423990]
      [-]8b3a897df88325
         // 0040113a: mov edi, ds:[edx]
         // 0040113c: mov ss:[ebp+0xfffffffffffffff8], edi
         // 0040113f: and ds:[0x427f9c], 0x0
      [-]897d188b3f897df48db8
         // 0040114c: mov ss:[ebp+0x18], edi
         // 0040114f: mov edi, ds:[edi]
         // 00401151: mov ss:[ebp+0xfffffffffffffff4], edi
         // 00401154: lea edi, ds:[eax+0x423e54]
      [-]897dfc8b3f89398d88
         // 0040115a: mov ss:[ebp+0xfffffffffffffffc], edi
         // 0040115d: mov edi, ds:[edi]
         // 0040115f: mov ds:[ecx], edi
         // 00401161: lea ecx, ds:[eax+0x423994]
      [-]8b39893a8b7d188d80
         // 00401167: mov edi, ds:[ecx]
         // 00401169: mov ds:[edx], edi
         // 0040116b: mov edi, ss:[ebp+0x18]
         // 0040116e: lea eax, ds:[eax+0x4205f4]
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
         // 00401197: mov eax, ds:[eax+0x423990]
      [-]3bc17409
         // 0040119d: cmp eax, ecx
         // 0040119f: jz 0x4011aa
      [-]668b0066a3
         // 004011a1: mov b2 ax, b2 ds:[eax]
         // 004011a4: mov b2 ds:[0x423eac], b2 ax
      [-]8b3cbd??
         // 004011aa: mov edi, ds:[0x41f768+edi*0x4]
      [-]8b5608e8
         // 004011b1: mov edx, ds:[esi+0x8]
         // 004011b4: call 0x40714a
      [-]5f0000ff368b15
         // 004011b9: push ds:[esi]
         // 004011bb: mov edx, ds:[0x423c00]
      [-]430000ff7608ff36e8
         // 004011c6: push ds:[esi+0x8]
         // 004011c9: push ds:[esi]
         // 004011cb: call 0x405529
      [-]4300008b45148b3c85
         // 004011d0: mov eax, ss:[ebp+0x14]
         // 004011d3: mov edi, ds:[0x41fde8+eax*0x4]
      [-]83c40c85ff7449
         // 004011da: add esp, 0xc
         // 004011dd: test edi, edi
         // 004011df: jz 0x40122a
      [-]43000085c0ff7604741c
         // 004011e8: test eax, eax
         // 004011ea: push ds:[esi+0x4]
         // 004011ed: jz 0x40120b
      [-]430000ff7608ff7604e8
         // 004011fb: push ds:[esi+0x8]
         // 004011fe: push ds:[esi+0x4]
         // 00401201: call 0x405529
      [-]43000083c40ceb08
         // 00401206: add esp, 0xc
         // 00401209: jmp 0x401213
      [-]42000059
         // 00401212: pop ecx
      [-]8b7e048b5608e8
         // 00401213: mov edi, ds:[esi+0x4]
         // 00401216: mov edx, ds:[esi+0x8]
         // 00401219: call 0x40714a
      [-]5f0000ff7608ff36e8
         // 0040121e: push ds:[esi+0x8]
         // 00401221: push ds:[esi]
         // 00401223: call 0x405529
      [-]00005959
         // 00401228: pop ecx
         // 00401229: pop ecx
      [-]8b45148d48018b45183b88
         // 00401232: mov eax, ss:[ebp+0x14]
         // 00401235: lea ecx, ds:[eax+0x1]
         // 00401238: mov eax, ss:[ebp+0x18]
         // 0040123b: cmp ecx, ds:[eax+0x423e50]
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
      [-]41000085c0ff76087505
         // 00401268: test eax, eax
         // 0040126a: push ds:[esi+0x8]
         // 0040126d: jnz 0x401274
      [-]8b5604eb02
         // 0040126f: mov edx, ds:[esi+0x4]
         // 00401272: jmp 0x401276
      [-]42000059eb1a
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
      [-]33c0899e????????40eb02
         // 00401298: xor eax, eax
         // 0040129a: mov ds:[esi+0x80], ebx
         // 004012a0: inc eax
         // 004012a1: jmp 0x4012a5
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
         // 004012c9: mov ecx, ds:[0x423a18+eax*0x4]
      [-]894e7089be????????
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
      [-]8b5d148bd0c1e2028b82??
         // 0040132e: mov ebx, ss:[ebp+0x14]
         // 00401331: mov edx, eax
         // 00401333: shl edx, b1 0x2
         // 00401336: mov eax, ds:[edx+0x41f558]
      [-]3bd88955080f8d1f010000
         // 0040133c: cmp ebx, eax
         // 0040133e: mov ss:[ebp+0x8], edx
         // 00401341: jge 0x401466
      [-]8bc86bc903394d180f8d11010000
         // 00401347: mov ecx, eax
         // 00401349: imul ecx, b1 0x3
         // 0040134c: cmp ss:[ebp+0x18], ecx
         // 0040134f: jge 0x401466
      [-]8b8e????????83f901885e747509
         // 00401355: mov ecx, ds:[esi+0x80]
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
         // 0040137a: mov b2 ds:[0x423eb4], b2 ax
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
         // 00401396: mov edi, ds:[0x427fac]
      [-]8d0cbd??
         // 0040139c: lea ecx, ds:[0x41f1e0+edi*0x4]
      [-]39017312
         // 004013a3: cmp ds:[ecx], eax
         // 004013a5: jnb 0x4013b9
      [-]0fb6015032c9e8
         // 004013a7: movzx eax, b1 ds:[ecx]
         // 004013aa: push eax
         // 004013ab: xor b1 cl, b1 cl
         // 004013ad: call 0x407552
      [-]00008b3d
         // 004013b2: mov edi, ds:[0x427fac]
      [-]8b550847893d
         // 004013b9: mov edx, ss:[ebp+0x8]
         // 004013bc: inc edi
         // 004013bd: mov ds:[0x427fac], edi
      [-]ff76048b92
         // 004013c3: push ds:[esi+0x4]
         // 004013c6: mov edx, ds:[edx+0x423a18]
      [-]41000085db597416
         // 004013d1: test ebx, ebx
         // 004013d3: pop ecx
         // 004013d4: jz 0x4013ec
      [-]03c38b0c85
         // 004013db: add eax, ebx
         // 004013dd: mov ecx, ds:[0x423080+eax*0x4]
      [-]8b4604e8
         // 004013e4: mov eax, ds:[esi+0x4]
         // 004013e7: call 0x4054ed
      [-]ff368b15
         // 004013ec: push ds:[esi]
         // 004013ee: mov edx, ds:[0x4205ec]
      [-]410000ff7604ff36e8
         // 004013f9: push ds:[esi+0x4]
         // 004013fc: push ds:[esi]
         // 004013fe: call 0x405529
      [-]41000083c40c3b3d
         // 00401403: add esp, 0xc
         // 00401406: cmp edi, ds:[0x41fde4]
      [-]8d4418013904bd
         // 00401413: lea eax, ds:[eax+ebx+0x1]
         // 00401417: cmp ds:[0x415068+edi*0x4], eax
      [-]ff76088b560433ff47c646650fc6466605c6466b00c6466c05e8
         // 00401420: push ds:[esi+0x8]
         // 00401423: mov edx, ds:[esi+0x4]
         // 00401426: xor edi, edi
         // 00401428: inc edi
         // 00401429: mov b1 ds:[esi+0x65], b1 0xf
         // 0040142d: mov b1 ds:[esi+0x66], b1 0x5
         // 00401431: mov b1 ds:[esi+0x6b], b1 0x0
         // 00401435: mov b1 ds:[esi+0x6c], b1 0x5
         // 00401439: call 0x405511
      [-]40000059eb1a
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
      [-]33c089be????????40eb08
         // 0040145b: xor eax, eax
         // 0040145d: mov ds:[esi+0x80], edi
         // 00401463: inc eax
         // 00401464: jmp 0x40146e
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
      [-]c1000053568b750c5733ff397d187506
         // 00401480: push ebx
         // 00401481: push esi
         // 00401482: mov esi, ss:[ebp+0xc]
         // 00401485: push edi
         // 00401486: xor edi, edi
         // 00401488: cmp ss:[ebp+0x18], edi
         // 0040148b: jnz 0x401493
      [-]89be????????
         // 0040148d: mov ds:[esi+0x80], edi
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
         // 004014c2: mov b1 cl, b1 ds:[0x420690]
      [-]4200884e6b8a0d
         // 004014c8: mov b1 ds:[esi+0x6b], b1 cl
         // 004014cb: mov b1 cl, b1 ds:[0x420694]
      [-]4200884e6c8b0d
         // 004014d1: mov b1 ds:[esi+0x6c], b1 cl
         // 004014d4: mov ecx, ds:[0x41a448]
      [-]89be????????c6466e00c74660????????894e0c
         // 004014da: mov ds:[esi+0x80], edi
         // 004014e0: mov b1 ds:[esi+0x6e], b1 0x0
         // 004014e4: mov ds:[esi+0x60], 0x8
         // 004014eb: mov ds:[esi+0xc], ecx
      [-]8bd8c1e3028b83
         // 004014ee: mov ebx, eax
         // 004014f0: shl ebx, b1 0x2
         // 004014f3: mov eax, ds:[ebx+0x413258]
      [-]3945140f8d43010000
         // 004014f9: cmp ss:[ebp+0x14], eax
         // 004014fc: jge 0x401645
      [-]8bc86bc903394d180f8d35010000
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
         // 00401529: call 0x4056f9
      [-]3bcf750c
         // 00401534: cmp ecx, edi
         // 00401536: jnz 0x401544
      [-]66c745b0300066897db2eb08
         // 00401538: mov b2 ss:[ebp+0xffffffffffffffb0], b2 0x30
         // 0040153e: mov b2 ss:[ebp+0xffffffffffffffb2], b2 di
         // 00401542: jmp 0x40154c
      [-]8d45b0e8
         // 00401544: lea eax, ss:[ebp+0xffffffffffffffb0]
         // 00401547: call 0x4056f9
      [-]8d85????????e8
         // 0040154c: lea eax, ss:[ebp+0xfffffffffffffee8]
         // 00401552: call 0x407237
      [-]0000397d14ff76046689bde8eeffff7520
         // 00401557: cmp ss:[ebp+0x14], edi
         // 0040155a: push ds:[esi+0x4]
         // 0040155d: mov b2 ss:[ebp+0xffffffffffffeee8], b2 di
         // 00401564: jnz 0x401586
      [-]3f00008b1759b8
         // 00401573: mov edx, ds:[edi]
         // 00401575: pop ecx
         // 00401576: mov eax, 0x40e26c
      [-]3e000085c07419
         // 00401580: test eax, eax
         // 00401582: jz 0x40159d
      [-]8b5608e8
         // 00401586: mov edx, ds:[esi+0x8]
         // 00401589: call 0x405511
      [-]3f000059
         // 0040158e: pop ecx
      [-]8b7e048d95????????e8
         // 0040158f: mov edi, ds:[esi+0x4]
         // 00401592: lea edx, ss:[ebp+0xffffffffffffeee8]
         // 00401598: call 0x40714a
      [-]ff76088b93??
         // 0040159d: push ds:[esi+0x8]
         // 004015a0: mov edx, ds:[ebx+0x41f050]
      [-]3f0000a1
         // 004015ab: mov eax, ds:[0x427fb0]
      [-]598b4d1403c18b3c85??
         // 004015b0: pop ecx
         // 004015b1: mov ecx, ss:[ebp+0x14]
         // 004015b4: add eax, ecx
         // 004015b6: mov edi, ds:[0x41b178+eax*0x4]
      [-]3e000085c0740a
         // 004015c9: test eax, eax
         // 004015cb: jz 0x4015d7
      [-]8b46088bcfe8
         // 004015cd: mov eax, ds:[esi+0x8]
         // 004015d0: mov ecx, edi
         // 004015d2: call 0x4054ed
      [-]ff76048b5608e8
         // 004015d7: push ds:[esi+0x4]
         // 004015da: mov edx, ds:[esi+0x8]
         // 004015dd: call 0x405511
      [-]3f00008b7e088d95????????e8
         // 004015e2: mov edi, ds:[esi+0x8]
         // 004015e5: lea edx, ss:[ebp+0xffffffffffffdee8]
         // 004015eb: call 0x40714a
      [-]5b0000ff368b15
         // 004015f0: push ds:[esi]
         // 004015f2: mov edx, ds:[0x422ee8]
      [-]3f00008d85????????50ff36e8
         // 004015fd: lea eax, ss:[ebp+0xffffffffffffeee8]
         // 00401603: push eax
         // 00401604: push ds:[esi]
         // 00401606: call 0x405529
      [-]3f00008d45d850ff36e8
         // 0040160b: lea eax, ss:[ebp+0xffffffffffffffd8]
         // 0040160e: push eax
         // 0040160f: push ds:[esi]
         // 00401611: call 0x405529
      [-]3f00008d45b050ff36e8
         // 00401616: lea eax, ss:[ebp+0xffffffffffffffb0]
         // 00401619: push eax
         // 0040161a: push ds:[esi]
         // 0040161c: call 0x405529
      [-]3f00008d85????????50ff36e8
         // 00401621: lea eax, ss:[ebp+0xffffffffffffdee8]
         // 00401627: push eax
         // 00401628: push ds:[esi]
         // 0040162a: call 0x405529
      [-]3e00008d85????????50ff36e8
         // 0040162f: lea eax, ss:[ebp+0xfffffffffffffee8]
         // 00401635: push eax
         // 00401636: push ds:[esi]
         // 00401638: call 0x405529
      [-]3e000033c083c43040eb08
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
      [-]c6466701c6466804c646693cc6466a41c6466b0ac6466c05898e????????884e6ec74660????????89460c
         // 0040167a: mov b1 ds:[esi+0x67], b1 0x1
         // 0040167e: mov b1 ds:[esi+0x68], b1 0x4
         // 00401682: mov b1 ds:[esi+0x69], b1 0x3c
         // 00401686: mov b1 ds:[esi+0x6a], b1 0x41
         // 0040168a: mov b1 ds:[esi+0x6b], b1 0xa
         // 0040168e: mov b1 ds:[esi+0x6c], b1 0x5
         // 00401692: mov ds:[esi+0x80], ecx
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
      [-]83be????????01754b
         // 004016c1: cmp ds:[esi+0x80], 0x1
         // 004016c8: jnz 0x401715
      [-]394d107406
         // 004016ca: cmp ss:[ebp+0x10], ecx
         // 004016cd: jz 0x4016d5
      [-]837d1005752a
         // 004016cf: cmp ss:[ebp+0x10], 0x5
         // 004016d3: jnz 0x4016ff
      [-]00008b0d
         // 004016da: mov ecx, ds:[0x427fb4]
      [-]3901730c
         // 004016e7: cmp ds:[ecx], eax
         // 004016e9: jnb 0x4016f7
      [-]0fb6015032c9e8
         // 004016eb: movzx eax, b1 ds:[ecx]
         // 004016ee: push eax
         // 004016ef: xor b1 cl, b1 cl
         // 004016f1: call 0x407552
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
         // 0040172c: mov b2 ds:[0x423eb0], b2 ax
      [-]ff368b15
         // 00401732: push ds:[esi]
         // 00401734: mov edx, ds:[0x41527c]
      [-]3d0000ff349d
         // 0040173f: push ds:[0x417998+ebx*0x4]
      [-]3d0000ff35
         // 0040174d: push ds:[0x419f18]
      [-]3d0000ff35
         // 0040175a: push ds:[0x417670]
      [-]3d00008b1c9d
         // 00401767: mov ebx, ds:[0x4171c0+ebx*0x4]
      [-]83c41c85db7445
         // 0040176e: add esp, 0x1c
         // 00401771: test ebx, ebx
         // 00401773: jz 0x4017ba
      [-]3e000085c0ff76047423
         // 0040177c: test eax, eax
         // 0040177e: push ds:[esi+0x4]
         // 00401781: jz 0x4017a6
      [-]3d00008b4514ff3485
         // 0040178f: mov eax, ss:[ebp+0x14]
         // 00401792: push ds:[0x417998+eax*0x4]
      [-]ff7604e8
         // 00401799: push ds:[esi+0x4]
         // 0040179c: call 0x405529
      [-]3d000083c40ceb08
         // 004017a1: add esp, 0xc
         // 004017a4: jmp 0x4017ae
      [-]3d000059
         // 004017ad: pop ecx
      [-]ff7604ff36e8
         // 004017ae: push ds:[esi+0x4]
         // 004017b1: push ds:[esi]
         // 004017b3: call 0x405529
      [-]3d00005959
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
         // 004017e3: mov edi, ds:[edi+0x423d28]
      [-]8bd743e8
         // 004017f0: mov edx, edi
         // 004017f2: inc ebx
         // 004017f3: call 0x405467
      [-]3c000085c0ff76087505
         // 004017f8: test eax, eax
         // 004017fa: push ds:[esi+0x8]
         // 004017fd: jnz 0x401804
      [-]8b5604eb02
         // 004017ff: mov edx, ds:[esi+0x4]
         // 00401802: jmp 0x401806
      [-]3d000059eb1a
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
      [-]33c0899e????????405feb02
         // 00401828: xor eax, eax
         // 0040182a: mov ds:[esi+0x80], ebx
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
         // 00401873: mov eax, ds:[0x417674]
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
         // 00401897: mov eax, ds:[edi+0x422ef0]
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
         // 004018bc: mov edx, ds:[edi+0x417678]
      [-]3c00008b97
         // 004018c7: mov edx, ds:[edi+0x422868]
      [-]59ff7604e8
         // 004018cd: pop ecx
         // 004018ce: push ds:[esi+0x4]
         // 004018d1: call 0x405511
      [-]3c0000a1
         // 004018d6: mov eax, ds:[0x427fc0]
      [-]433b1c85
         // 004018db: inc ebx
         // 004018dc: cmp ebx, ds:[0x419f98+eax*0x4]
      [-]3f00008b8f
         // 004018eb: mov ecx, ds:[edi+0x422ef0]
      [-]494999f7f942ff05
         // 004018f1: dec ecx
         // 004018f2: dec ecx
         // 004018f3: cdq 
         // 004018f4: idiv ecx
         // 004018f6: inc edx
         // 004018f7: inc ds:[0x427fc0]
      [-]ff76048b16e8
         // 0040190e: push ds:[esi+0x4]
         // 00401911: mov edx, ds:[esi]
         // 00401913: call 0x405511
      [-]3b00008b97
         // 00401918: mov edx, ds:[edi+0x417678]
      [-]59ff36e8
         // 0040191e: pop ecx
         // 0040191f: push ds:[esi]
         // 00401921: call 0x405511
      [-]3b0000a1
         // 00401926: mov eax, ds:[0x427fbc]
      [-]598b4d1403c18b0c85
         // 0040192b: pop ecx
         // 0040192c: mov ecx, ss:[ebp+0x14]
         // 0040192f: add eax, ecx
         // 00401931: mov ecx, ds:[0x415280+eax*0x4]
      [-]00008846658b0d??
         // 0040194a: mov b1 ds:[esi+0x65], b1 al
         // 0040194d: mov ecx, ds:[0x41f5b0]
      [-]00008846698b4514403905
         // 00401958: mov b1 ds:[esi+0x69], b1 al
         // 0040195b: mov eax, ss:[ebp+0x14]
         // 0040195e: inc eax
         // 0040195f: cmp ds:[0x427fb8], eax
      [-]33c040eb04
         // 00401967: xor eax, eax
         // 00401969: inc eax
         // 0040196a: jmp 0x401970
      [-]8b44240c
         // 0040196c: mov eax, ss:[esp+0xc]
      [-]8986????????33c040eb08
         // 00401970: mov ds:[esi+0x80], eax
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
      [-]558bec5153568b750c33db395d18578b7d08895dfc7516
         // 0040198a: push ebp
         // 0040198b: mov ebp, esp
         // 0040198d: push ecx
         // 0040198e: push ebx
         // 0040198f: push esi
         // 00401990: mov esi, ss:[ebp+0xc]
         // 00401993: xor ebx, ebx
         // 00401995: cmp ss:[ebp+0x18], ebx
         // 00401998: push edi
         // 00401999: mov edi, ss:[ebp+0x8]
         // 0040199c: mov ss:[ebp+0xfffffffffffffffc], ebx
         // 0040199f: jnz 0x4019b7
      [-]885e75885e748b04bd
         // 004019a1: mov b1 ds:[esi+0x75], b1 bl
         // 004019a4: mov b1 ds:[esi+0x74], b1 bl
         // 004019a7: mov eax, ds:[0x414dd8+edi*0x4]
      [-]894670899e????????
         // 004019ae: mov ds:[esi+0x70], eax
         // 004019b1: mov ds:[esi+0x80], ebx
      [-]3bfb7547
         // 004019b7: cmp edi, ebx
         // 004019b9: jnz 0x401a02
      [-]395d187514
         // 004019bb: cmp ss:[ebp+0x18], ebx
         // 004019be: jnz 0x4019d4
      [-]ff7604ba
         // 004019c0: push ds:[esi+0x4]
         // 004019c3: mov edx, 0x40e26c
      [-]3b000059
         // 004019d3: pop ecx
      [-]395d147529
         // 004019d4: cmp ss:[ebp+0x14], ebx
         // 004019d7: jnz 0x401a02
      [-]c6466701c6466807885e6b885e6cc646691ec6466a3cc6466e38c74660????????89460c
         // 004019de: mov b1 ds:[esi+0x67], b1 0x1
         // 004019e2: mov b1 ds:[esi+0x68], b1 0x7
         // 004019e6: mov b1 ds:[esi+0x6b], b1 bl
         // 004019e9: mov b1 ds:[esi+0x6c], b1 bl
         // 004019ec: mov b1 ds:[esi+0x69], b1 0x1e
         // 004019f0: mov b1 ds:[esi+0x6a], b1 0x3c
         // 004019f4: mov b1 ds:[esi+0x6e], b1 0x38
         // 004019f8: mov ds:[esi+0x60], 0x9
         // 004019ff: mov ds:[esi+0xc], eax
      [-]83be????????018b4d14884e747508
         // 00401a02: cmp ds:[esi+0x80], 0x1
         // 00401a09: mov ecx, ss:[ebp+0x14]
         // 00401a0c: mov b1 ds:[esi+0x74], b1 cl
         // 00401a0f: jnz 0x401a19
      [-]395d107503
         // 00401a11: cmp ss:[ebp+0x10], ebx
         // 00401a14: jnz 0x401a19
      [-]3bc87d75
         // 00401a20: cmp ecx, eax
         // 00401a22: jge 0x401a99
      [-]6bc0033945187d6d
         // 00401a24: imul eax, b1 0x3
         // 00401a27: cmp ss:[ebp+0x18], eax
         // 00401a2a: jge 0x401a99
      [-]3bcb7555
         // 00401a2c: cmp ecx, ebx
         // 00401a2e: jnz 0x401a85
      [-]ff368b15
         // 00401a30: push ds:[esi]
         // 00401a32: mov edx, ds:[0x423c04]
      [-]3a0000ff34bd
         // 00401a3d: push ds:[0x414dd8+edi*0x4]
      [-]3a0000a1
         // 00401a4b: mov eax, ds:[0x427fc4]
      [-]83c40cc1e002473bb8
         // 00401a50: add esp, 0xc
         // 00401a53: shl eax, b1 0x2
         // 00401a56: inc edi
         // 00401a57: cmp edi, ds:[eax+0x417808]
      [-]ff76088b90
         // 00401a5f: push ds:[esi+0x8]
         // 00401a62: mov edx, ds:[eax+0x420458]
      [-]3a0000ff05
         // 00401a6d: inc ds:[0x427fc4]
      [-]59c745fc????????c6466505c646660aeb06
         // 00401a73: pop ecx
         // 00401a74: mov ss:[ebp+0xfffffffffffffffc], 0x1
         // 00401a7b: mov b1 ds:[esi+0x65], b1 0x5
         // 00401a7f: mov b1 ds:[esi+0x66], b1 0xa
         // 00401a83: jmp 0x401a8b
      [-]885e66885e65
         // 00401a85: mov b1 ds:[esi+0x66], b1 bl
         // 00401a88: mov b1 ds:[esi+0x65], b1 bl
      [-]8b45fc8986????????33c040eb02
         // 00401a8b: mov eax, ss:[ebp+0xfffffffffffffffc]
         // 00401a8e: mov ds:[esi+0x80], eax
         // 00401a94: xor eax, eax
         // 00401a96: inc eax
         // 00401a97: jmp 0x401a9b
      [-]5f5e5bc9c3
         // 00401a9b: pop edi
         // 00401a9c: pop esi
         // 00401a9d: pop ebx
         // 00401a9e: leave 
         // 00401a9f: retn 
      [-]558bec515133c933c0833d??
         // 00401aa0: push ebp
         // 00401aa1: mov ebp, esp
         // 00401aa3: push ecx
         // 00401aa4: push ecx
         // 00401aa5: xor ecx, ecx
         // 00401aa7: xor eax, eax
         // 00401aa9: cmp ds:[0x41a4b4], 0x1
      [-]01538b5d080f95c1394518568b750c578945f8894dfc7516
         // 00401ab0: push ebx
         // 00401ab1: mov ebx, ss:[ebp+0x8]
         // 00401ab4: setnz b1 cl
         // 00401ab7: cmp ss:[ebp+0x18], eax
         // 00401aba: push esi
         // 00401abb: mov esi, ss:[ebp+0xc]
         // 00401abe: push edi
         // 00401abf: mov ss:[ebp+0xfffffffffffffff8], eax
         // 00401ac2: mov ss:[ebp+0xfffffffffffffffc], ecx
         // 00401ac5: jnz 0x401add
      [-]8846758846748b0c9d
         // 00401ac7: mov b1 ds:[esi+0x75], b1 al
         // 00401aca: mov b1 ds:[esi+0x74], b1 al
         // 00401acd: mov ecx, ds:[0x422bc8+ebx*0x4]
      [-]894e708986????????
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
      [-]c6466701c6466804c6466b0fc6466c058a0da4
         // 00401afa: mov b1 ds:[esi+0x67], b1 0x1
         // 00401afe: mov b1 ds:[esi+0x68], b1 0x4
         // 00401b02: mov b1 ds:[esi+0x6b], b1 0xf
         // 00401b06: mov b1 ds:[esi+0x6c], b1 0x5
         // 00401b0a: mov b1 cl, b1 ds:[0x41a4a4]
      [-]4100884e658a0da8
         // 00401b10: mov b1 ds:[esi+0x65], b1 cl
         // 00401b13: mov b1 cl, b1 ds:[0x41a4a8]
      [-]4100884e668a0dac
         // 00401b19: mov b1 ds:[esi+0x66], b1 cl
         // 00401b1c: mov b1 cl, b1 ds:[0x41a4ac]
      [-]4100884e698a0db0
         // 00401b22: mov b1 ds:[esi+0x69], b1 cl
         // 00401b25: mov b1 cl, b1 ds:[0x41a4b0]
      [-]4100884e6a8b0d
         // 00401b2b: mov b1 ds:[esi+0x6a], b1 cl
         // 00401b2e: mov ecx, ds:[0x4150e0]
      [-]c6466e36c74660????????894e0c
         // 00401b34: mov b1 ds:[esi+0x6e], b1 0x36
         // 00401b38: mov ds:[esi+0x60], 0x5
         // 00401b3f: mov ds:[esi+0xc], ecx
      [-]83be????????018b4d14884e747508
         // 00401b42: cmp ds:[esi+0x80], 0x1
         // 00401b49: mov ecx, ss:[ebp+0x14]
         // 00401b4c: mov b1 ds:[esi+0x74], b1 cl
         // 00401b4f: jnz 0x401b59
      [-]3945107503
         // 00401b51: cmp ss:[ebp+0x10], eax
         // 00401b54: jnz 0x401b59
      [-]8bfbc1e7028b87
         // 00401b59: mov edi, ebx
         // 00401b5b: shl edi, b1 0x2
         // 00401b5e: mov eax, ds:[edi+0x423558]
      [-]3bc80f8dc8000000
         // 00401b64: cmp ecx, eax
         // 00401b66: jge 0x401c34
      [-]8bd06bd2033955180f8dba000000
         // 00401b6c: mov edx, eax
         // 00401b6e: imul edx, b1 0x3
         // 00401b71: cmp ss:[ebp+0x18], edx
         // 00401b74: jge 0x401c34
      [-]85c97566
         // 00401b7a: test ecx, ecx
         // 00401b7c: jnz 0x401be4
      [-]ff368b97
         // 00401b7e: push ds:[esi]
         // 00401b80: mov edx, ds:[edi+0x422bc8]
      [-]390000ff76048b97
         // 00401b8b: push ds:[esi+0x4]
         // 00401b8e: mov edx, ds:[edi+0x422d58]
      [-]390000a1
         // 00401b99: mov eax, ds:[0x427fd0]
      [-]433b1c85
         // 00401b9e: inc ebx
         // 00401b9f: cmp ebx, ds:[0x414b58+eax*0x4]
      [-]59597531
         // 00401ba6: pop ecx
         // 00401ba7: pop ecx
         // 00401ba8: jnz 0x401bdb
      [-]837dfc007419
         // 00401baa: cmp ss:[ebp+0xfffffffffffffffc], 0x0
         // 00401bae: jz 0x401bc9
      [-]3c00008b8f
         // 00401bb5: mov ecx, ds:[edi+0x423558]
      [-]494999f7f9428915
         // 00401bbb: dec ecx
         // 00401bbc: dec ecx
         // 00401bbd: cdq 
         // 00401bbe: idiv ecx
         // 00401bc0: inc edx
         // 00401bc1: mov ds:[0x427fc8], edx
      [-]ff76048b16e8
         // 00401be4: push ds:[esi+0x4]
         // 00401be7: mov edx, ds:[esi]
         // 00401be9: call 0x405511
      [-]390000ff368b97
         // 00401bee: push ds:[esi]
         // 00401bf0: mov edx, ds:[edi+0x422bc8]
      [-]390000a1
         // 00401bfb: mov eax, ds:[0x427fcc]
      [-]59598b4d1403c18b0c85??
         // 00401c00: pop ecx
         // 00401c01: pop ecx
         // 00401c02: mov ecx, ss:[ebp+0x14]
         // 00401c05: add eax, ecx
         // 00401c07: mov ecx, ds:[0x41d0c0+eax*0x4]
      [-]8b4514403905
         // 00401c15: mov eax, ss:[ebp+0x14]
         // 00401c18: inc eax
         // 00401c19: cmp ds:[0x427fc8], eax
      [-]33c040eb03
         // 00401c21: xor eax, eax
         // 00401c23: inc eax
         // 00401c24: jmp 0x401c29
      [-]8986????????33c040eb08
         // 00401c29: mov ds:[esi+0x80], eax
         // 00401c2f: xor eax, eax
         // 00401c31: inc eax
         // 00401c32: jmp 0x401c3c
      [-]5f5e5bc9c3
         // 00401c3c: pop edi
         // 00401c3d: pop esi
         // 00401c3e: pop ebx
         // 00401c3f: leave 
         // 00401c40: retn 
      [-]558becb8????????e8
         // 00401c41: push ebp
         // 00401c42: mov ebp, esp
         // 00401c44: mov eax, 0x319c
         // 00401c49: call __alloca_probe
      [-]b900008b450c5633c95733ff4133f6897df840eb1c
         // 00401c4e: mov eax, ss:[ebp+0xc]
         // 00401c51: push esi
         // 00401c52: xor ecx, ecx
         // 00401c54: push edi
         // 00401c55: xor edi, edi
         // 00401c57: inc ecx
         // 00401c58: xor esi, esi
         // 00401c5a: mov ss:[ebp+0xfffffffffffffff8], edi
         // 00401c5d: inc eax
         // 00401c5e: jmp 0x401c7c
      [-]81f9????????7318
         // 00401c60: cmp ecx, 0x10000
         // 00401c66: jnb 0x401c80
      [-]854d087401
         // 00401c71: test ss:[ebp+0x8], ecx
         // 00401c74: jz 0x401c77
      [-]ff45f803c9
         // 00401c77: inc ss:[ebp+0xfffffffffffffff8]
         // 00401c7a: add ecx, ecx
      [-]3bc775e0
         // 00401c7c: cmp eax, edi
         // 00401c7e: jnz 0x401c60
      [-]8b4d103bcf750c
         // 00401c80: mov ecx, ss:[ebp+0x10]
         // 00401c83: cmp ecx, edi
         // 00401c85: jnz 0x401c93
      [-]66c745d0300066897dd2eb08
         // 00401c87: mov b2 ss:[ebp+0xffffffffffffffd0], b2 0x30
         // 00401c8d: mov b2 ss:[ebp+0xffffffffffffffd2], b2 di
         // 00401c91: jmp 0x401c9b
      [-]8d45d0e8
         // 00401c93: lea eax, ss:[ebp+0xffffffffffffffd0]
         // 00401c96: call 0x4056f9
      [-]8b55148d85????????50e8
         // 00401c9b: mov edx, ss:[ebp+0x14]
         // 00401c9e: lea eax, ss:[ebp+0xffffffffffffde64]
         // 00401ca4: push eax
         // 00401ca5: call 0x405511
      [-]380000598b4d183bcf740b
         // 00401caa: pop ecx
         // 00401cab: mov ecx, ss:[ebp+0x18]
         // 00401cae: cmp ecx, edi
         // 00401cb0: jz 0x401cbd
      [-]8d85????????e8
         // 00401cb2: lea eax, ss:[ebp+0xffffffffffffde64]
         // 00401cb8: call 0x4054ed
      [-]3800008b75f883fe01597532
         // 00401cca: mov esi, ss:[ebp+0xfffffffffffffff8]
         // 00401ccd: cmp esi, 0x1
         // 00401cd0: pop ecx
         // 00401cd1: jnz 0x401d05
      [-]8b4d203bcf750c
         // 00401cd3: mov ecx, ss:[ebp+0x20]
         // 00401cd6: cmp ecx, edi
         // 00401cd8: jnz 0x401ce6
      [-]66c745a8300066897daaeb08
         // 00401cda: mov b2 ss:[ebp+0xffffffffffffffa8], b2 0x30
         // 00401ce0: mov b2 ss:[ebp+0xffffffffffffffaa], b2 di
         // 00401ce4: jmp 0x401cee
      [-]8d45a8e8
         // 00401ce6: lea eax, ss:[ebp+0xffffffffffffffa8]
         // 00401ce9: call 0x4056f9
      [-]8d45d05053e8
         // 00401cee: lea eax, ss:[ebp+0xffffffffffffffd0]
         // 00401cf1: push eax
         // 00401cf2: push ebx
         // 00401cf3: call 0x405529
      [-]3800008d45a85053e8
         // 00401cf8: lea eax, ss:[ebp+0xffffffffffffffa8]
         // 00401cfb: push eax
         // 00401cfc: push ebx
         // 00401cfd: call 0x405529
      [-]38000083c410
         // 00401d02: add esp, 0x10
      [-]83fe050f85f9000000
         // 00401d05: cmp esi, 0x5
         // 00401d08: jnz 0x401e07
      [-]00008bc83bcf750c
         // 00401d15: mov ecx, eax
         // 00401d17: cmp ecx, edi
         // 00401d19: jnz 0x401d27
      [-]66c745a8300066897daaeb08
         // 00401d1b: mov b2 ss:[ebp+0xffffffffffffffa8], b2 0x30
         // 00401d21: mov b2 ss:[ebp+0xffffffffffffffaa], b2 di
         // 00401d25: jmp 0x401d2f
      [-]8d45a8e8
         // 00401d27: lea eax, ss:[ebp+0xffffffffffffffa8]
         // 00401d2a: call 0x4056f9
      [-]3bcf750c
         // 00401d35: cmp ecx, edi
         // 00401d37: jnz 0x401d45
      [-]66c74580300066897d82eb08
         // 00401d39: mov b2 ss:[ebp+0xffffffffffffff80], b2 0x30
         // 00401d3f: mov b2 ss:[ebp+0xffffffffffffff82], b2 di
         // 00401d43: jmp 0x401d4d
      [-]8d4580e8
         // 00401d45: lea eax, ss:[ebp+0xffffffffffffff80]
         // 00401d48: call 0x4056f9
      [-]3bcf7512
         // 00401d53: cmp ecx, edi
         // 00401d55: jnz 0x401d69
      [-]66c78554ffffff30006689bd56ffffffeb0b
         // 00401d57: mov b2 ss:[ebp+0xffffffffffffff54], b2 0x30
         // 00401d60: mov b2 ss:[ebp+0xffffffffffffff56], b2 di
         // 00401d67: jmp 0x401d74
      [-]8d85????????e8
         // 00401d69: lea eax, ss:[ebp+0xffffffffffffff54]
         // 00401d6f: call 0x4056f9
      [-]8dbd????????8d95????????e8
         // 00401d74: lea edi, ss:[ebp+0xffffffffffffde64]
         // 00401d7a: lea edx, ss:[ebp+0xffffffffffffce64]
         // 00401d80: call 0x40714a
      [-]00008d45d05053e8
         // 00401d85: lea eax, ss:[ebp+0xffffffffffffffd0]
         // 00401d88: push eax
         // 00401d89: push ebx
         // 00401d8a: call 0x405529
      [-]3700008d45a85053e8
         // 00401d8f: lea eax, ss:[ebp+0xffffffffffffffa8]
         // 00401d92: push eax
         // 00401d93: push ebx
         // 00401d94: call 0x405529
      [-]3700008b7d1c83c41085ff7428
         // 00401d99: mov edi, ss:[ebp+0x1c]
         // 00401d9c: add esp, 0x10
         // 00401d9f: test edi, edi
         // 00401da1: jz 0x401dcb
      [-]8d95????????e8
         // 00401da3: lea edx, ss:[ebp+0xffffffffffffee64]
         // 00401da9: call 0x40714a
      [-]53000068
         // 00401dae: push 0x40e284
      [-]3700008d85????????5053e8
         // 00401db9: lea eax, ss:[ebp+0xffffffffffffee64]
         // 00401dbf: push eax
         // 00401dc0: push ebx
         // 00401dc1: call 0x405529
      [-]37000083c410eb0d
         // 00401dc6: add esp, 0x10
         // 00401dc9: jmp 0x401dd8
      [-]3700005959
         // 00401dd6: pop ecx
         // 00401dd7: pop ecx
      [-]8d85????????5053e8
         // 00401dd8: lea eax, ss:[ebp+0xffffffffffffce64]
         // 00401dde: push eax
         // 00401ddf: push ebx
         // 00401de0: call 0x405529
      [-]3700008d45805053e8
         // 00401de5: lea eax, ss:[ebp+0xffffffffffffff80]
         // 00401de8: push eax
         // 00401de9: push ebx
         // 00401dea: call 0x405529
      [-]3700008d85????????
         // 00401def: lea eax, ss:[ebp+0xffffffffffffff54]
      [-]37000083c418
         // 00401dfc: add esp, 0x18
      [-]33c040e909040000
         // 00401dff: xor eax, eax
         // 00401e01: inc eax
         // 00401e02: jmp 0x402210
      [-]83fe060f8540010000
         // 00401e07: cmp esi, 0x6
         // 00401e0a: jnz 0x401f50
      [-]00008bc83bcf7512
         // 00401e17: mov ecx, eax
         // 00401e19: cmp ecx, edi
         // 00401e1b: jnz 0x401e2f
      [-]66c78554ffffff30006689bd56ffffffeb0b
         // 00401e1d: mov b2 ss:[ebp+0xffffffffffffff54], b2 0x30
         // 00401e26: mov b2 ss:[ebp+0xffffffffffffff56], b2 di
         // 00401e2d: jmp 0x401e3a
      [-]8d85????????e8
         // 00401e2f: lea eax, ss:[ebp+0xffffffffffffff54]
         // 00401e35: call 0x4056f9
      [-]3bcf750c
         // 00401e40: cmp ecx, edi
         // 00401e42: jnz 0x401e50
      [-]66c74580300066897d82eb08
         // 00401e44: mov b2 ss:[ebp+0xffffffffffffff80], b2 0x30
         // 00401e4a: mov b2 ss:[ebp+0xffffffffffffff82], b2 di
         // 00401e4e: jmp 0x401e58
      [-]8d4580e8
         // 00401e50: lea eax, ss:[ebp+0xffffffffffffff80]
         // 00401e53: call 0x4056f9
      [-]3bcf750c
         // 00401e5e: cmp ecx, edi
         // 00401e60: jnz 0x401e6e
      [-]66c745a8300066897daaeb08
         // 00401e62: mov b2 ss:[ebp+0xffffffffffffffa8], b2 0x30
         // 00401e68: mov b2 ss:[ebp+0xffffffffffffffaa], b2 di
         // 00401e6c: jmp 0x401e76
      [-]8d45a8e8
         // 00401e6e: lea eax, ss:[ebp+0xffffffffffffffa8]
         // 00401e71: call 0x4056f9
      [-]6a208d8d????????5a
         // 00401e76: push 0x20
         // 00401e78: lea ecx, ss:[ebp+0xfffffffffffffe64]
         // 00401e7e: pop edx
      [-]39000025????????7905
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
      [-]6689398dbd????????8d95????????e8
         // 00401ea8: mov b2 ds:[ecx], b2 di
         // 00401eab: lea edi, ss:[ebp+0xffffffffffffde64]
         // 00401eb1: lea edx, ss:[ebp+0xffffffffffffee64]
         // 00401eb7: call 0x40714a
      [-]5200008d45d05053e8
         // 00401ebc: lea eax, ss:[ebp+0xffffffffffffffd0]
         // 00401ebf: push eax
         // 00401ec0: push ebx
         // 00401ec1: call 0x405529
      [-]360000ff752453e8
         // 00401ec6: push ss:[ebp+0x24]
         // 00401ec9: push ebx
         // 00401eca: call 0x405529
      [-]3600008d85????????5053e8
         // 00401ecf: lea eax, ss:[ebp+0xffffffffffffff54]
         // 00401ed5: push eax
         // 00401ed6: push ebx
         // 00401ed7: call 0x405529
      [-]3600008d45805053e8
         // 00401edc: lea eax, ss:[ebp+0xffffffffffffff80]
         // 00401edf: push eax
         // 00401ee0: push ebx
         // 00401ee1: call 0x405529
      [-]3600008d45a85053e8
         // 00401ee6: lea eax, ss:[ebp+0xffffffffffffffa8]
         // 00401ee9: push eax
         // 00401eea: push ebx
         // 00401eeb: call 0x405529
      [-]3600008d85????????5053e8
         // 00401ef0: lea eax, ss:[ebp+0xfffffffffffffe64]
         // 00401ef6: push eax
         // 00401ef7: push ebx
         // 00401ef8: call 0x405529
      [-]3600008b7d1c83c43085ff7428
         // 00401efd: mov edi, ss:[ebp+0x1c]
         // 00401f00: add esp, 0x30
         // 00401f03: test edi, edi
         // 00401f05: jz 0x401f2f
      [-]8d95????????e8
         // 00401f07: lea edx, ss:[ebp+0xffffffffffffce64]
         // 00401f0d: call 0x40714a
      [-]52000068
         // 00401f12: push 0x40e284
      [-]3600008d85????????5053e8
         // 00401f1d: lea eax, ss:[ebp+0xffffffffffffce64]
         // 00401f23: push eax
         // 00401f24: push ebx
         // 00401f25: call 0x405529
      [-]35000083c410eb0d
         // 00401f2a: add esp, 0x10
         // 00401f2d: jmp 0x401f3c
      [-]3500005959
         // 00401f3a: pop ecx
         // 00401f3b: pop ecx
      [-]8d85????????5053e8
         // 00401f3c: lea eax, ss:[ebp+0xffffffffffffee64]
         // 00401f42: push eax
         // 00401f43: push ebx
         // 00401f44: call 0x405529
      [-]3500005959e9affeffff
         // 00401f49: pop ecx
         // 00401f4a: pop ecx
         // 00401f4b: jmp 0x401dff
      [-]83fe077536
         // 00401f50: cmp esi, 0x7
         // 00401f53: jnz 0x401f8b
      [-]8d45d05053e8
         // 00401f55: lea eax, ss:[ebp+0xffffffffffffffd0]
         // 00401f58: push eax
         // 00401f59: push ebx
         // 00401f5a: call 0x405529
      [-]350000595933f6
         // 00401f5f: pop ecx
         // 00401f60: pop ecx
         // 00401f61: xor esi, esi
      [-]8b45288b3cb08d95????????e8
         // 00401f63: mov eax, ss:[ebp+0x28]
         // 00401f66: mov edi, ds:[eax+esi*0x4]
         // 00401f69: lea edx, ss:[ebp+0xfffffffffffffe64]
         // 00401f6f: call 0x40714a
      [-]00008d85????????5053e8
         // 00401f74: lea eax, ss:[ebp+0xfffffffffffffe64]
         // 00401f7a: push eax
         // 00401f7b: push ebx
         // 00401f7c: call 0x405529
      [-]3500004683fe0b59597cda
         // 00401f81: inc esi
         // 00401f82: cmp esi, 0xb
         // 00401f85: pop ecx
         // 00401f86: pop ecx
         // 00401f87: jl 0x401f63
      [-]8b75f883fe08740a
         // 00401f8b: mov esi, ss:[ebp+0xfffffffffffffff8]
         // 00401f8e: cmp esi, 0x8
         // 00401f91: jz 0x401f9d
      [-]83fe0e7405
         // 00401f93: cmp esi, 0xe
         // 00401f96: jz 0x401f9d
      [-]83fe0f750c
         // 00401f98: cmp esi, 0xf
         // 00401f9b: jnz 0x401fa9
      [-]8d45d05053e8
         // 00401f9d: lea eax, ss:[ebp+0xffffffffffffffd0]
         // 00401fa0: push eax
         // 00401fa1: push ebx
         // 00401fa2: call 0x405529
      [-]3500005959
         // 00401fa7: pop ecx
         // 00401fa8: pop ecx
      [-]83fe097536
         // 00401fa9: cmp esi, 0x9
         // 00401fac: jnz 0x401fe4
      [-]397d1c6689bd64eeffff7410
         // 00401fae: cmp ss:[ebp+0x1c], edi
         // 00401fb1: mov b2 ss:[ebp+0xffffffffffffee64], b2 di
         // 00401fb8: jz 0x401fca
      [-]8b7d1c8d95????????e8
         // 00401fba: mov edi, ss:[ebp+0x1c]
         // 00401fbd: lea edx, ss:[ebp+0xffffffffffffee64]
         // 00401fc3: call 0x40714a
      [-]51000033ff
         // 00401fc8: xor edi, edi
      [-]8d85????????5053e8
         // 00401fca: lea eax, ss:[ebp+0xffffffffffffee64]
         // 00401fd0: push eax
         // 00401fd1: push ebx
         // 00401fd2: call 0x405529
      [-]3500008d45d05053e8
         // 00401fd7: lea eax, ss:[ebp+0xffffffffffffffd0]
         // 00401fda: push eax
         // 00401fdb: push ebx
         // 00401fdc: call 0x405529
      [-]35000083c410
         // 00401fe1: add esp, 0x10
      [-]837df80b7406
         // 00401fe4: cmp ss:[ebp+0xfffffffffffffff8], 0xb
         // 00401fe8: jz 0x401ff0
      [-]837df80d756e
         // 00401fea: cmp ss:[ebp+0xfffffffffffffff8], 0xd
         // 00401fee: jnz 0x40205e
      [-]8d85????????e8
         // 00401ff0: lea eax, ss:[ebp+0xfffffffffffffe64]
         // 00401ff6: call 0x407237
      [-]5200008dbd????????8d95????????e8
         // 00401ffb: lea edi, ss:[ebp+0xffffffffffffde64]
         // 00402001: lea edx, ss:[ebp+0xffffffffffffce64]
         // 00402007: call 0x4071fa
      [-]00008b7d1c85ff740d
         // 0040200c: mov edi, ss:[ebp+0x1c]
         // 0040200f: test edi, edi
         // 00402011: jz 0x402020
      [-]8d95????????e8
         // 00402013: lea edx, ss:[ebp+0xffffffffffffee64]
         // 00402019: call 0x4071fa
      [-]0000eb08
         // 0040201e: jmp 0x402028
      [-]6683a564eeffff00
         // 00402020: and b2 ss:[ebp+0xffffffffffffee64], b2 0x0
      [-]8d45d05053e8
         // 00402028: lea eax, ss:[ebp+0xffffffffffffffd0]
         // 0040202b: push eax
         // 0040202c: push ebx
         // 0040202d: call 0x405529
      [-]3400008d85????????5053e8
         // 00402032: lea eax, ss:[ebp+0xffffffffffffee64]
         // 00402038: push eax
         // 00402039: push ebx
         // 0040203a: call 0x405529
      [-]3400008d85????????5053e8
         // 0040203f: lea eax, ss:[ebp+0xffffffffffffce64]
         // 00402045: push eax
         // 00402046: push ebx
         // 00402047: call 0x405529
      [-]3400008d85????????5053e8
         // 0040204c: lea eax, ss:[ebp+0xfffffffffffffe64]
         // 00402052: push eax
         // 00402053: push ebx
         // 00402054: call 0x405529
      [-]34000083c42033ff
         // 00402059: add esp, 0x20
         // 0040205c: xor edi, edi
      [-]837df80c0f85d2000000
         // 0040205e: cmp ss:[ebp+0xfffffffffffffff8], 0xc
         // 00402062: jnz 0x40213a
      [-]8d45d05053e8
         // 00402068: lea eax, ss:[ebp+0xffffffffffffffd0]
         // 0040206b: push eax
         // 0040206c: push ebx
         // 0040206d: call 0x405529
      [-]3400008b452483c0085053e8
         // 00402072: mov eax, ss:[ebp+0x24]
         // 00402075: add eax, 0x8
         // 00402078: push eax
         // 00402079: push ebx
         // 0040207a: call 0x405529
      [-]3400008d450c508d85????????6a5e6689bd64eeffff506633ffb8
         // 0040207f: lea eax, ss:[ebp+0xc]
         // 00402082: push eax
         // 00402083: lea eax, ss:[ebp+0xffffffffffffff2c]
         // 00402089: push 0x5e
         // 0040208b: mov b2 ss:[ebp+0xffffffffffffee64], b2 di
         // 00402092: push eax
         // 00402093: xor b2 di, b2 di
         // 00402096: mov eax, 0x412202
      [-]37000083c41c33f685c07424
         // 004020a0: add esp, 0x1c
         // 004020a3: xor esi, esi
         // 004020a5: test eax, eax
         // 004020a7: jz 0x4020cd
      [-]3b750c7d1f
         // 004020a9: cmp esi, ss:[ebp+0xc]
         // 004020ac: jge 0x4020cd
      [-]8d85????????e8
         // 004020b3: lea eax, ss:[ebp+0xffffffffffffee64]
         // 004020b9: call 0x4054ed
      [-]3400008b8cb52cffffffe8
         // 004020be: mov ecx, ss:[ebp+esi*0x4]
         // 004020c5: call 0x4054ed
      [-]34000046ebdc
         // 004020ca: inc esi
         // 004020cb: jmp 0x4020a9
      [-]8d85????????5053e8
         // 004020cd: lea eax, ss:[ebp+0xffffffffffffee64]
         // 004020d3: push eax
         // 004020d4: push ebx
         // 004020d5: call 0x405529
      [-]3400006683a564eeffff008d450c508d85????????6a5e506633ffb8
         // 004020da: and b2 ss:[ebp+0xffffffffffffee64], b2 0x0
         // 004020e2: lea eax, ss:[ebp+0xc]
         // 004020e5: push eax
         // 004020e6: lea eax, ss:[ebp+0xffffffffffffff2c]
         // 004020ec: push 0x5e
         // 004020ee: push eax
         // 004020ef: xor b2 di, b2 di
         // 004020f2: mov eax, 0x411952
      [-]37000083c41433f685c07424
         // 004020fc: add esp, 0x14
         // 004020ff: xor esi, esi
         // 00402101: test eax, eax
         // 00402103: jz 0x402129
      [-]3b750c7d1f
         // 00402105: cmp esi, ss:[ebp+0xc]
         // 00402108: jge 0x402129
      [-]8d85????????e8
         // 0040210f: lea eax, ss:[ebp+0xffffffffffffee64]
         // 00402115: call 0x4054ed
      [-]3300008b8cb52cffffffe8
         // 0040211a: mov ecx, ss:[ebp+esi*0x4]
         // 00402121: call 0x4054ed
      [-]33000046ebdc
         // 00402126: inc esi
         // 00402127: jmp 0x402105
      [-]8d85????????5053e8
         // 00402129: lea eax, ss:[ebp+0xffffffffffffee64]
         // 0040212f: push eax
         // 00402130: push ebx
         // 00402131: call 0x405529
      [-]330000595933ff
         // 00402136: pop ecx
         // 00402137: pop ecx
         // 00402138: xor edi, edi
      [-]837df8100f85ca000000
         // 0040213a: cmp ss:[ebp+0xfffffffffffffff8], 0x10
         // 0040213e: jnz 0x40220e
      [-]3bcf7512
         // 0040214a: cmp ecx, edi
         // 0040214c: jnz 0x402160
      [-]66c78554ffffff30006689bd56ffffffeb0b
         // 0040214e: mov b2 ss:[ebp+0xffffffffffffff54], b2 0x30
         // 00402157: mov b2 ss:[ebp+0xffffffffffffff56], b2 di
         // 0040215e: jmp 0x40216b
      [-]8d85????????e8
         // 00402160: lea eax, ss:[ebp+0xffffffffffffff54]
         // 00402166: call 0x4056f9
      [-]3bcf750c
         // 00402171: cmp ecx, edi
         // 00402173: jnz 0x402181
      [-]66c74580300066897d82eb08
         // 00402175: mov b2 ss:[ebp+0xffffffffffffff80], b2 0x30
         // 0040217b: mov b2 ss:[ebp+0xffffffffffffff82], b2 di
         // 0040217f: jmp 0x402189
      [-]8d4580e8
         // 00402181: lea eax, ss:[ebp+0xffffffffffffff80]
         // 00402184: call 0x4056f9
      [-]8dbd????????8d95????????e8
         // 00402189: lea edi, ss:[ebp+0xffffffffffffde64]
         // 0040218f: lea edx, ss:[ebp+0xffffffffffffce64]
         // 00402195: call 0x40714a
      [-]4f00008d45d05053e8
         // 0040219a: lea eax, ss:[ebp+0xffffffffffffffd0]
         // 0040219d: push eax
         // 0040219e: push ebx
         // 0040219f: call 0x405529
      [-]3300008b7d1c85ff59597428
         // 004021a4: mov edi, ss:[ebp+0x1c]
         // 004021a7: test edi, edi
         // 004021a9: pop ecx
         // 004021aa: pop ecx
         // 004021ab: jz 0x4021d5
      [-]8d95????????e8
         // 004021ad: lea edx, ss:[ebp+0xffffffffffffee64]
         // 004021b3: call 0x40714a
      [-]4f000068
         // 004021b8: push 0x40e304
      [-]3300008d85????????5053e8
         // 004021c3: lea eax, ss:[ebp+0xffffffffffffee64]
         // 004021c9: push eax
         // 004021ca: push ebx
         // 004021cb: call 0x405529
      [-]33000083c410eb17
         // 004021d0: add esp, 0x10
         // 004021d3: jmp 0x4021ec
      [-]6683a564eeffff008d85????????5053e8
         // 004021d5: and b2 ss:[ebp+0xffffffffffffee64], b2 0x0
         // 004021dd: lea eax, ss:[ebp+0xffffffffffffee64]
         // 004021e3: push eax
         // 004021e4: push ebx
         // 004021e5: call 0x405529
      [-]3300005959
         // 004021ea: pop ecx
         // 004021eb: pop ecx
      [-]8d85????????5053e8
         // 004021ec: lea eax, ss:[ebp+0xffffffffffffce64]
         // 004021f2: push eax
         // 004021f3: push ebx
         // 004021f4: call 0x405529
      [-]3300008d85????????5053e8
         // 004021f9: lea eax, ss:[ebp+0xffffffffffffff54]
         // 004021ff: push eax
         // 00402200: push ebx
         // 00402201: call 0x405529
      [-]3300008d4580e9e7fbffff
         // 00402206: lea eax, ss:[ebp+0xffffffffffffff80]
         // 00402209: jmp 0x401df5
      [-]5f5ec9c3
         // 00402210: pop edi
         // 00402211: pop esi
         // 00402212: leave 
         // 00402213: retn 
      [-]558bec83e4f883ec1c538b5d08568b750c5733ff3bdf6a02897c241c597548
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
         // 00402230: pop ecx
         // 00402231: jnz 0x40227b
      [-]397d180f85f8000000
         // 00402233: cmp ss:[ebp+0x18], edi
         // 00402236: jnz 0x402334
      [-]4100046488466ea1
         // 00402241: add b1 al, b1 0x64
         // 00402243: mov b1 ds:[esi+0x6e], b1 al
         // 00402246: mov eax, ds:[0x417674]
      [-]897c2418893d
         // 0040224b: mov ss:[esp+0x18], edi
         // 0040224f: mov ds:[0x427fd4], edi
      [-]c6466701c646680489460c894e60
         // 0040226d: mov b1 ds:[esi+0x67], b1 0x1
         // 00402271: mov b1 ds:[esi+0x68], b1 0x4
         // 00402275: mov ds:[esi+0xc], eax
         // 00402278: mov ds:[esi+0x60], ecx
      [-]397d180f85b0000000
         // 0040227b: cmp ss:[ebp+0x18], edi
         // 0040227e: jnz 0x402334
      [-]8d43013b0495
         // 0040228a: lea eax, ds:[ebx+0x1]
         // 0040228d: cmp eax, ds:[0x419f98+edx*0x4]
      [-]3500008b3c9d
         // 0040229b: mov edi, ds:[0x422ef0+ebx*0x4]
      [-]2bf999f7ff42ff05
         // 004022a2: sub edi, ecx
         // 004022a4: cdq 
         // 004022a5: idiv edi
         // 004022a7: inc edx
         // 004022a8: inc ds:[0x427fe8]
      [-]350000996a6459f7f933c0bf????????85d20f9cc033d242a3
         // 004022c1: cdq 
         // 004022c2: push 0x64
         // 004022c4: pop ecx
         // 004022c5: idiv ecx
         // 004022c7: xor eax, eax
         // 004022c9: mov edi, 0x10000
         // 004022ce: test edx, edx
         // 004022d0: setl b1 al
         // 004022d3: xor edx, edx
         // 004022d5: inc edx
         // 004022d6: mov ds:[0x427fec], eax
      [-]8d049d??
         // 004022db: lea eax, ds:[0x41fc20+ebx*0x4]
      [-]8b083bca7c04
         // 004022e2: mov ecx, ds:[eax]
         // 004022e4: cmp ecx, edx
         // 004022e6: jl 0x4022ec
      [-]3bcf7e06
         // 004022e8: cmp ecx, edi
         // 004022ea: jle 0x4022f2
      [-]c700????????
         // 004022ec: mov ds:[eax], 0x90
      [-]8b0033c9
         // 004022f2: mov eax, ds:[eax]
         // 004022f4: xor ecx, ecx
      [-]85c27401
         // 004022f6: test edx, eax
         // 004022f8: jz 0x4022fb
      [-]03d23bd772f5
         // 004022fb: add edx, edx
         // 004022fd: cmp edx, edi
         // 004022ff: jb 0x4022f6
      [-]83a6????????00890d
         // 00402301: and ds:[esi+0x80], 0x0
         // 00402308: mov ds:[0x427fe4], ecx
      [-]0000884669c6466a01c6467500c64674008b049d
         // 00402319: mov b1 ds:[esi+0x69], b1 al
         // 0040231c: mov b1 ds:[esi+0x6a], b1 0x1
         // 00402320: mov b1 ds:[esi+0x75], b1 0x0
         // 00402324: mov b1 ds:[esi+0x74], b1 0x0
         // 00402328: mov eax, ds:[0x417678+ebx*0x4]
      [-]89467033ff
         // 0040232f: mov ds:[esi+0x70], eax
         // 00402332: xor edi, edi
      [-]8b45188b0d
         // 00402334: mov eax, ss:[ebp+0x18]
         // 00402337: mov ecx, ds:[0x427fe4]
      [-]99f7f93bd789542410752b
         // 0040233d: cdq 
         // 0040233e: idiv ecx
         // 00402340: cmp edx, edi
         // 00402342: mov ss:[esp+0x10], edx
         // 00402346: jnz 0x402373
      [-]397d187426
         // 00402348: cmp ss:[ebp+0x18], edi
         // 0040234b: jz 0x402373
      [-]8b86????????fe467483f8017512
         // 00402353: mov eax, ds:[esi+0x80]
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
         // 00402378: mov eax, ds:[edi+0x422ef0]
      [-]0fafc13945187c07
         // 0040237e: imul eax, ecx
         // 00402381: cmp ss:[ebp+0x18], eax
         // 00402384: jl 0x40238d
      [-]33c0e9a8010000
         // 00402386: xor eax, eax
         // 00402388: jmp 0x402535
      [-]895424248b128944242089542414750e
         // 004023a5: mov ss:[esp+0x24], edx
         // 004023a9: mov edx, ds:[edx]
         // 004023ab: mov ss:[esp+0x20], eax
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
      [-]85c08b4e04894c241c51752c
         // 004023e1: test eax, eax
         // 004023e3: mov ecx, ds:[esi+0x4]
         // 004023e6: mov ss:[esp+0x1c], ecx
         // 004023ea: push ecx
         // 004023eb: jnz 0x402419
      [-]3100008b97
         // 004023f8: mov edx, ds:[edi+0x422868]
      [-]300000f7d81bc02387
         // 00402409: neg eax
         // 0040240b: sbb eax, eax
         // 0040240d: and eax, ds:[edi+0x422868]
      [-]8944241ceb24
         // 00402413: mov ss:[esp+0x1c], eax
         // 00402417: jmp 0x40243d
      [-]300000833d
         // 00402424: cmp ds:[0x427fec], 0x0
      [-]0059740f
         // 0040242b: pop ecx
         // 0040242c: jz 0x40243d
      [-]8b4424248b48fc8b4604e8
         // 0040242e: mov eax, ss:[esp+0x24]
         // 00402432: mov ecx, ds:[eax+0xfffffffffffffffc]
         // 00402435: mov eax, ds:[esi+0x4]
         // 00402438: call 0x4054ed
      [-]6bdb3c81c3
         // 0040243d: imul ebx, b1 0x3c
         // 00402440: add ebx, 0x4133e8
      [-]53ffb7??
         // 00402446: push ebx
         // 00402447: push ds:[edi+0x41f5d8]
      [-]8b1effb7
         // 0040244d: mov ebx, ds:[esi]
         // 0040244f: push ds:[edi+0x4237b0]
      [-]ff742428ff742424ffb7
         // 00402455: push ss:[esp+0x28]
         // 00402459: push ss:[esp+0x24]
         // 0040245d: push ds:[edi+0x417678]
      [-]ff74242cffb7??
         // 00402469: push ss:[esp+0x2c]
         // 0040246d: push ds:[edi+0x41fc20]
      [-]e8c9f7ffff8b1d
         // 00402473: call 0x401c41
         // 00402478: mov ebx, ds:[0x427fd4]
      [-]83c42485c0a3
         // 0040247e: add esp, 0x24
         // 00402481: test eax, eax
         // 00402483: mov ds:[0x423ebc], eax
      [-]8b442420403bd8750c
         // 0040248a: mov eax, ss:[esp+0x20]
         // 0040248e: inc eax
         // 0040248f: cmp ebx, eax
         // 00402491: jnz 0x40249f
      [-]ff76048946788b97
         // 004024ac: push ds:[esi+0x4]
         // 004024af: mov ds:[esi+0x78], eax
         // 004024b2: mov edx, ds:[edi+0x417678]
      [-]300000598b4c241485c97408
         // 004024bd: pop ecx
         // 004024be: mov ecx, ss:[esp+0x14]
         // 004024c2: test ecx, ecx
         // 004024c4: jz 0x4024ce
      [-]8b4604e8
         // 004024c6: mov eax, ds:[esi+0x4]
         // 004024c9: call 0x4054ed
      [-]ff76088b5604e8
         // 004024ce: push ds:[esi+0x8]
         // 004024d1: mov edx, ds:[esi+0x4]
         // 004024d4: call 0x405511
      [-]3000008b442424403bd8a1
         // 004024d9: mov eax, ss:[esp+0x24]
         // 004024dd: inc eax
         // 004024de: cmp ebx, eax
         // 004024e0: mov eax, ds:[0x427fe4]
      [-]8d48ff394c24107508
         // 004024e8: lea ecx, ds:[eax+0xffffffffffffffff]
         // 004024eb: cmp ss:[esp+0x10], ecx
         // 004024ef: jnz 0x4024f9
      [-]c7442418????????
         // 004024f1: mov ss:[esp+0x18], 0x1
      [-]48394424107518
         // 004024f9: dec eax
         // 004024fa: cmp ss:[esp+0x10], eax
         // 004024fe: jnz 0x402518
      [-]c6466b0fc6466c058b0d??
         // 00402500: mov b1 ds:[esi+0x6b], b1 0xf
         // 00402504: mov b1 ds:[esi+0x6c], b1 0x5
         // 00402508: mov ecx, ds:[0x41f5ac]
      [-]0000884665eb0c
         // 00402513: mov b1 ds:[esi+0x65], b1 al
         // 00402516: jmp 0x402524
      [-]c6466500c6466b00c6466c00
         // 00402518: mov b1 ds:[esi+0x65], b1 0x0
         // 0040251c: mov b1 ds:[esi+0x6b], b1 0x0
         // 00402520: mov b1 ds:[esi+0x6c], b1 0x0
      [-]8b4424188986????????33c0c646660040
         // 00402524: mov eax, ss:[esp+0x18]
         // 00402528: mov ds:[esi+0x80], eax
         // 0040252e: xor eax, eax
         // 00402530: mov b1 ds:[esi+0x66], b1 0x0
         // 00402534: inc eax
      [-]5f5e5b8be55dc3
         // 00402535: pop edi
         // 00402536: pop esi
         // 00402537: pop ebx
         // 00402538: mov esp, ebp
         // 0040253a: pop ebp
         // 0040253b: retn 
      [-]558becb8????????e8
         // 0040253c: push ebp
         // 0040253d: mov ebp, esp
         // 0040253f: mov eax, 0x2064
         // 00402544: call __alloca_probe
      [-]b00000538b1d
         // 00402549: push ebx
         // 0040254a: mov ebx, ds:[Sleep]
      [-]e040005633f63935
         // 00402550: push esi
         // 00402551: xor esi, esi
         // 00402553: cmp ds:[0x4114e4], esi
      [-]578975fc7513
         // 00402559: push edi
         // 0040255a: mov ss:[ebp+0xfffffffffffffffc], esi
         // 0040255d: jnz 0x402572
      [-]68????????ffd3
         // 00402561: push 0x2710
         // 00402566: call ebx
      [-]000083f80175ef
         // 0040256d: cmp eax, 0x1
         // 00402570: jnz 0x402561
      [-]39751c740d
         // 00402572: cmp ss:[ebp+0x1c], esi
         // 00402575: jz 0x402584
      [-]6a04566a07e8
         // 00402577: push 0x4
         // 00402579: push esi
         // 0040257a: push 0x7
         // 0040257c: call 0x40a786
      [-]000083c40c
         // 00402581: add esp, 0xc
      [-]ff7510ff15
         // 00402584: push ss:[ebp+0x10]
         // 00402587: call ds:[DeleteFileW]
      [-]e0400033ff3975187e26
         // 0040258d: xor edi, edi
         // 0040258f: cmp ss:[ebp+0x18], esi
         // 00402592: jle 0x4025ba
      [-]8d45fc50ff7510ff750cff7508e8
         // 00402594: lea eax, ss:[ebp+0xfffffffffffffffc]
         // 00402597: push eax
         // 00402598: push ss:[ebp+0x10]
         // 0040259b: push ss:[ebp+0xc]
         // 0040259e: push ss:[ebp+0x8]
         // 004025a1: call 0x407036
      [-]4a000083c41085c07514
         // 004025a6: add esp, 0x10
         // 004025a9: test eax, eax
         // 004025ab: jnz 0x4025c1
      [-]68????????47ffd33b7d187cda
         // 004025ad: push 0xea60
         // 004025b2: inc edi
         // 004025b3: call ebx
         // 004025b5: cmp edi, ss:[ebp+0x18]
         // 004025b8: jl 0x402594
      [-]33c0e99f000000
         // 004025ba: xor eax, eax
         // 004025bc: jmp 0x402660
      [-]39751c740d
         // 004025c1: cmp ss:[ebp+0x1c], esi
         // 004025c4: jz 0x4025d3
      [-]6a04566a08e8
         // 004025c6: push 0x4
         // 004025c8: push esi
         // 004025c9: push 0x8
         // 004025cb: call 0x40a786
      [-]000083c40c
         // 004025d0: add esp, 0xc
      [-]6a448d45a05650e8
         // 004025d3: push 0x44
         // 004025d5: lea eax, ss:[ebp+0xffffffffffffffa0]
         // 004025d8: push esi
         // 004025d9: push eax
         // 004025da: call 0x40d540
      [-]af00008d85????????83c40c50ba
         // 004025df: lea eax, ss:[ebp+0xffffffffffffdfa0]
         // 004025e5: add esp, 0xc
         // 004025e8: push eax
         // 004025e9: mov edx, 0x40e314
      [-]2f0000598b4d108d85????????e8
         // 004025f3: pop ecx
         // 004025f4: mov ecx, ss:[ebp+0x10]
         // 004025f7: lea eax, ss:[ebp+0xffffffffffffdfa0]
         // 004025fd: call 0x4054ed
      [-]2e0000b9
         // 00402602: mov ecx, 0x40e318
      [-]2e0000397514741f
         // 0040260c: cmp ss:[ebp+0x14], esi
         // 0040260f: jz 0x402630
      [-]8b5514b8
         // 00402611: mov edx, ss:[ebp+0x14]
         // 00402614: mov eax, 0x40e26c
      [-]2e000085c0740e
         // 0040261e: test eax, eax
         // 00402620: jz 0x402630
      [-]8b4d148d85????????e8
         // 00402622: mov ecx, ss:[ebp+0x14]
         // 00402625: lea eax, ss:[ebp+0xffffffffffffdfa0]
         // 0040262b: call 0x4054ed
      [-]8d45ec508d45a05068
         // 00402630: lea eax, ss:[ebp+0xffffffffffffffec]
         // 00402633: push eax
         // 00402634: lea eax, ss:[ebp+0xffffffffffffffa0]
         // 00402637: push eax
         // 00402638: push 0x420840
      [-]566a205656568d85????????50ff7510ff15
         // 0040263d: push esi
         // 0040263e: push 0x20
         // 00402640: push esi
         // 00402641: push esi
         // 00402642: push esi
         // 00402643: lea eax, ss:[ebp+0xffffffffffffdfa0]
         // 00402649: push eax
         // 0040264a: push ss:[ebp+0x10]
         // 0040264d: call ds:[CreateProcessW]
      [-]e0400085c07506
         // 00402653: test eax, eax
         // 00402655: jnz 0x40265d
      [-]834dfc08eb03
         // 00402657: or ss:[ebp+0xfffffffffffffffc], 0x8
         // 0040265b: jmp 0x402660
      [-]8b4d203bce7405
         // 00402660: mov ecx, ss:[ebp+0x20]
         // 00402663: cmp ecx, esi
         // 00402665: jz 0x40266c
      [-]8b55fc8911
         // 00402667: mov edx, ss:[ebp+0xfffffffffffffffc]
         // 0040266a: mov ds:[ecx], edx
      [-]8b4d243bce7402
         // 0040266c: mov ecx, ss:[ebp+0x24]
         // 0040266f: cmp ecx, esi
         // 00402671: jz 0x402675
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
      [-]af00008a4518888424810000000fb6c08d8c24????????6bc014894c24148d8c24????????894c24185333db395d088d8c24????????894c24208b4d1c565766899c24a800000066899c24a810000066899c24a82000008988
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
      [-]81ec????????6a21598db424????????8bfcf3a5e8bc0000008bf081c4????????3bf3750a
         // 00402711: sub esp, 0x84
         // 00402717: push 0x21
         // 00402719: pop ecx
         // 0040271a: lea esi, ss:[esp+0xa4]
         // 00402721: mov edi, esp
         // 00402723: rep movsdd 
         // 00402725: call 0x4027e6
         // 0040272a: mov esi, eax
         // 0040272c: add esp, 0x84
         // 00402732: cmp esi, ebx
         // 00402734: jnz 0x402740
      [-]ff442418895c2414eb04
         // 00402736: inc ss:[esp+0x18]
         // 0040273a: mov ss:[esp+0x14], ebx
         // 0040273e: jmp 0x402744
      [-]ff442414
         // 00402740: inc ss:[esp+0x14]
      [-]ffb424????????8a8c2490000000ff442420e8
         // 00402744: push ss:[esp+0x8b]
         // 0040274b: mov b1 cl, b1 ss:[esp+0x90]
         // 00402752: inc ss:[esp+0x20]
         // 00402756: call 0x407552
      [-]000059ff74241cff74241c56
         // 0040275b: pop ecx
         // 0040275c: push ss:[esp+0x1c]
         // 00402760: push ss:[esp+0x1c]
         // 00402764: push esi
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
      [-]0fb6842495000000500fb6842498000000500fb6842496000000518b
         // 00402793: movzx eax, b1 ss:[esp+0x95]
         // 0040279b: push eax
         // 0040279c: movzx eax, b1 ss:[esp+0x98]
         // 004027a4: push eax
         // 004027a5: movzx eax, b1 ss:[esp+0x96]
         // 004027ad: push ecx
         // 004027ae: mov ecx, ss:[esp+0x9c]
         // 004027b5: push 0x1
         // 004027b7: push eax
         // 004027b8: call 0x40a8f9

  }
  condition:
    all of them
}
