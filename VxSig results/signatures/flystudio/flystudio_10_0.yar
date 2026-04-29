rule flystudio_10_0 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         85db7503
         // 0040119b: test ebx, ebx
         // 0040119d: jnz 0x4011a2
      [-]8b0b83c30485c9740f
         // 004011a2: mov ecx, ds:[ebx]
         // 004011a4: add ebx, 0x4
         // 004011a7: test ecx, ecx
         // 004011a9: jz 0x4011ba
      [-]83c304497405
         // 004011ad: add ebx, 0x4
         // 004011b0: dec ecx
         // 004011b1: jz 0x4011b8
      [-]0faf03ebf5
         // 004011b3: imul eax, ds:[ebx]
         // 004011b6: jmp 0x4011ad
      [-]83ec1c8d442400
         // 00430270: sub esp, 0x1c
         // 00430273: lea eax, ss:[esp+0x0]
      [-]6a006a006a006a0050ff
         // 0043027e: push 0x0
         // 00430280: push 0x0
         // 00430282: push 0x0
         // 00430284: push 0x0
         // 00430286: push eax
         // 00430287: call esi
      [-]6a006a006a008d
         // 004302a0: push 0x0
         // 004302a2: push 0x0
         // 004302a4: push 0x0
         // 004302a6: lea eax, ss:[esp+0x10]
      [-]83c41cc3
         // 0040b8fb: add esp, 0x1c
         // 0040b8fe: retn 
      [-]0083c404
         // 004445ec: call 0x47d12e
         // 004445f1: add esp, 0x4
      [-]8b4c240433c0497406
         // 0040ca10: mov ecx, ss:[esp+0x4]
         // 0040ca14: xor eax, eax
         // 0040ca16: dec ecx
         // 0040ca17: jz 0x40ca1f
      [-]83c8ffc20c00
         // 0040ca19: or eax, 0xffffffffffffffff
         // 0040ca1c: retn b2 0xc
      [-]8b4c2408890d
         // 0047836f: mov ecx, ss:[esp+0x8]
         // 00478373: mov ds:[0x4fc240], ecx
      [-]558bec6aff68
         // 0056610e: push ebp
         // 0056610f: mov ebp, esp
         // 00566111: push 0xffffffffffffffff
         // 00566113: push stru_5C4DB8.EnclosingLevel
      [-]64a1????????50648925????????83ec185356578b750885f60f84ac000000
         // 0056611d: mov eax, fs:[0x0]
         // 00566123: push eax
         // 00566124: mov fs:[0x0], esp
         // 0056612b: sub esp, 0x18
         // 0056612e: push ebx
         // 0056612f: push esi
         // 00566130: push edi
         // 00566131: mov esi, ss:[ebp+0x8]
         // 00566134: test esi, esi
         // 00566136: jz 0x5661e8
      [-]83f803753b
         // 0047d161: cmp eax, 0x3
         // 0047d164: jnz 0x47d1a1
      [-]0000598365fc0056e8
         // 0047d16d: pop ecx
         // 0047d16e: and ss:[ebp+0xfffffffffffffffc], 0x0
         // 0047d172: push esi
         // 0047d173: call ___sbh_find_block
      [-]0000598945e485c07409
         // 0047d178: pop ecx
         // 0047d179: mov ss:[ebp+0xffffffffffffffe4], eax
         // 0047d17c: test eax, eax
         // 0047d17e: jz 0x47d189
      [-]00005959
         // 0047d187: pop ecx
         // 0047d188: pop ecx
      [-]834dfcffe806000000837de400eb516a09e8
         // 0047d189: or ss:[ebp+0xfffffffffffffffc], 0xffffffffffffffff
         // 0047d18d: call 0x47d198
         // 0047d192: cmp ss:[ebp+0xffffffffffffffe4], 0x0
         // 0047d196: jmp 0x47d1e9
         // 0047d198: push 0x9
         // 0047d19a: call __unlock
      [-]000059c3
         // 0047d19f: pop ecx
         // 0047d1a0: retn 
      [-]83f8027553
         // 0040d39b: cmp eax, 0x2
         // 0040d39e: jnz 0x40d3f3
      [-]000059c745fc????????8d45e0508d45d85056e8
         // 0047d1ad: pop ecx
         // 0047d1ae: mov ss:[ebp+0xfffffffffffffffc], 0x1
         // 0047d1b5: lea eax, ss:[ebp+0xffffffffffffffe0]
         // 0047d1b8: push eax
         // 0047d1b9: lea eax, ss:[ebp+0xffffffffffffffd8]
         // 0047d1bc: push eax
         // 0047d1bd: push esi
         // 0047d1be: call 0x4858b8
      [-]000083c40c8945dc85c0740f
         // 0047d1c3: add esp, 0xc
         // 0047d1c6: mov ss:[ebp+0xffffffffffffffdc], eax
         // 0047d1c9: test eax, eax
         // 0047d1cb: jz 0x47d1dc
      [-]50ff75e0ff75d8e8
         // 0047d1cd: push eax
         // 0047d1ce: push ss:[ebp+0xffffffffffffffe0]
         // 0047d1d1: push ss:[ebp+0xffffffffffffffd8]
         // 0047d1d4: call 0x48590f
      [-]000083c40c
         // 0047d1d9: add esp, 0xc
      [-]834dfcffe80b000000837ddc00
         // 0047d1dc: or ss:[ebp+0xfffffffffffffffc], 0xffffffffffffffff
         // 0047d1e0: call 0x47d1f0
         // 0047d1e5: cmp ss:[ebp+0xffffffffffffffdc], 0x0
      [-]000059c3
         // 0047d1f7: pop ecx
         // 0047d1f8: retn 
      [-]6a00ff35
         // 0040d3f4: push 0x0
         // 0040d3f6: push ds:[0x67962c]
      [-]8b4df064890d????????5f5e5bc9c3
         // 0040d402: mov ecx, ss:[ebp+0xfffffffffffffff0]
         // 0040d405: mov fs:[0x0], ecx
         // 0040d40c: pop edi
         // 0040d40d: pop esi
         // 0040d40e: pop ebx
         // 0040d40f: leave 
         // 0040d410: retn 
      [-]558bec6aff68
         // 00566235: push ebp
         // 00566236: mov ebp, esp
         // 00566238: push 0xffffffffffffffff
         // 0056623a: push stru_5C4DD0.EnclosingLevel
      [-]64a1????????50648925????????83ec0c535657a1
         // 00566244: mov eax, fs:[0x0]
         // 0056624a: push eax
         // 0056624b: mov fs:[0x0], esp
         // 00566252: sub esp, 0xc
         // 00566255: push ebx
         // 00566256: push esi
         // 00566257: push edi
         // 00566258: mov eax, ds:[0x6177f8]
      [-]83f8037543
         // 0056625d: cmp eax, 0x3
         // 00566260: jnz 0x5662a5
      [-]8b75083b35
         // 0047d282: mov esi, ss:[ebp+0x8]
         // 0047d285: cmp esi, ds:[0x50d860]
      [-]0f8793000000
         // 0047d28b: ja 0x47d324
      [-]0000598365fc0056e8
         // 00566278: pop ecx
         // 00566279: and ss:[ebp+0xfffffffffffffffc], 0x0
         // 0056627d: push esi
         // 0056627e: call 0x56d711
      [-]0000598945e4834dfcffe80c0000008b45e485c0746d
         // 00566283: pop ecx
         // 00566284: mov ss:[ebp+0xffffffffffffffe4], eax
         // 00566287: or ss:[ebp+0xfffffffffffffffc], 0xffffffffffffffff
         // 0056628b: call 0x56629c
         // 00566290: mov eax, ss:[ebp+0xffffffffffffffe4]
         // 00566293: test eax, eax
         // 00566295: jz 0x566304
      [-]000059c3
         // 005662a3: pop ecx
         // 005662a4: retn 
      [-]83f802755a
         // 0040d4bf: cmp eax, 0x2
         // 0040d4c2: jnz 0x40d51e
      [-]8b450885c07408
         // 0040d4c4: mov eax, ss:[ebp+0x8]
         // 0040d4c7: test eax, eax
         // 0040d4c9: jz 0x40d4d3
      [-]8d700f83e6f0eb03
         // 0040d4cb: lea esi, ds:[eax+0xf]
         // 0040d4ce: and esi, 0xfffffffffffffff0
         // 0040d4d1: jmp 0x40d4d6
      [-]8975083b35
         // 0047d2dc: mov ss:[ebp+0x8], esi
         // 0047d2df: cmp esi, ds:[0x4ca274]
      [-]000059c745fc????????8bc6c1e80450e8
         // 0047d2ee: pop ecx
         // 0047d2ef: mov ss:[ebp+0xfffffffffffffffc], 0x1
         // 0047d2f6: mov eax, esi
         // 0047d2f8: shr eax, b1 0x4
         // 0047d2fb: push eax
         // 0047d2fc: call 0x485954
      [-]0000598945e4834dfcffe80d0000008b45e485c0752d
         // 0047d301: pop ecx
         // 0047d302: mov ss:[ebp+0xffffffffffffffe4], eax
         // 0047d305: or ss:[ebp+0xfffffffffffffffc], 0xffffffffffffffff
         // 0047d309: call 0x47d31b
         // 0047d30e: mov eax, ss:[ebp+0xffffffffffffffe4]
         // 0047d311: test eax, eax
         // 0047d313: jnz 0x47d342
      [-]000059c3
         // 0047d322: pop ecx
         // 0047d323: retn 
      [-]8b450885c07503
         // 0040d51e: mov eax, ss:[ebp+0x8]
         // 0040d521: test eax, eax
         // 0040d523: jnz 0x40d528
      [-]83c00f24f050
         // 0040d528: add eax, 0xf
         // 0040d52b: and b1 al, b1 0xf0
         // 0040d52d: push eax
      [-]6a00ff35
         // 0040d52e: push 0x0
         // 0040d530: push ds:[0x67962c]
      [-]8b4df064890d????????5f5e5bc9c3
         // 0040d53c: mov ecx, ss:[ebp+0xfffffffffffffff0]
         // 0040d53f: mov fs:[0x0], ecx
         // 0040d546: pop edi
         // 0040d547: pop esi
         // 0040d548: pop ebx
         // 0040d549: leave 
         // 0040d54a: retn 
      [-]568b7424086a00832600ff15
         // 00569902: push esi
         // 00569903: mov esi, ss:[esp+0x8]
         // 00569907: push 0x0
         // 00569909: and ds:[esi], 0x0
         // 0056990c: call ds:[0x5883c0]
      [-]6681384d5a7514
         // 00569912: cmp b2 ds:[eax], b2 0x5a4d
         // 00569917: jnz 0x56992d
      [-]8b483c85c9740d
         // 0040e46e: mov ecx, ds:[eax+0x3c]
         // 0040e471: test ecx, ecx
         // 0040e473: jz 0x40e482
      [-]03c18a481a880e8a401b884601
         // 0040e475: add eax, ecx
         // 0040e477: mov b1 cl, b1 ds:[eax+0x1a]
         // 0040e47a: mov b1 ds:[esi], b1 cl
         // 0040e47c: mov b1 al, b1 ds:[eax+0x1b]
         // 0040e47f: mov b1 ds:[esi+0x1], b1 al
      [-]558becb8????????e8
         // 0056992f: push ebp
         // 00569930: mov ebp, esp
         // 00569932: mov eax, 0x122c
         // 00569937: call __alloca_probe
      [-]ffff8d85????????5350c785????????????????ff15
         // 0056993c: lea eax, ss:[ebp+0xffffffffffffff68]
         // 00569942: push ebx
         // 00569943: push eax
         // 00569944: mov ss:[ebp+0xffffffffffffff68], 0x94
         // 0056994e: call ds:[0x588370]
      [-]85c0741a
         // 00569954: test eax, eax
         // 00569956: jz 0x569972
      [-]83bd????????027511
         // 0040e4ad: cmp ss:[ebp+0xffffffffffffff78], 0x2
         // 0040e4b4: jnz 0x40e4c7
      [-]83bd????????057208
         // 0040e4b6: cmp ss:[ebp+0xffffffffffffff6c], 0x5
         // 0040e4bd: jb 0x40e4c7
      [-]6a0158e902010000
         // 0040e4bf: push 0x1
         // 0040e4c1: pop eax
         // 0040e4c2: jmp 0x40e5c9
      [-]8d85????????68????????5068
         // 00569972: lea eax, ss:[ebp+0xffffffffffffedd4]
         // 00569978: push 0x1090
         // 0056997d: push eax
         // 0056997e: push 0x5c4fa8
      [-]85c00f84d0000000
         // 00569989: test eax, eax
         // 0056998b: jz 0x569a61
      [-]33db8d8d????????389dd4edffff7413
         // 0040e4e6: xor ebx, ebx
         // 0040e4e8: lea ecx, ss:[ebp+0xffffffffffffedd4]
         // 0040e4ee: cmp b1 ss:[ebp+0xffffffffffffedd4], b1 bl
         // 0040e4f4: jz 0x40e509
      [-]8a013c617c08
         // 0040e4f6: mov b1 al, b1 ds:[ecx]
         // 0040e4f8: cmp b1 al, b1 0x61
         // 0040e4fa: jl 0x40e504
      [-]3c7a7f04
         // 0040e4fc: cmp b1 al, b1 0x7a
         // 0040e4fe: jg 0x40e504
      [-]2c208801
         // 0040e500: sub b1 al, b1 0x20
         // 0040e502: mov b1 ds:[ecx], b1 al
      [-]41381975ed
         // 0040e504: inc ecx
         // 0040e505: cmp b1 ds:[ecx], b1 bl
         // 0040e507: jnz 0x40e4f6
      [-]8d85????????6a165068
         // 00481178: lea eax, ss:[ebp+0xffffffffffffedd4]
         // 0048117e: push 0x16
         // 00481180: push eax
         // 00481181: push 0x4aa0a0
      [-]ffff83c40c85c07508
         // 0048118b: add esp, 0xc
         // 0048118e: test eax, eax
         // 00481190: jnz 0x48119a
      [-]8d85????????eb49
         // 0040e523: lea eax, ss:[ebp+0xffffffffffffedd4]
         // 0040e529: jmp 0x40e574
      [-]8d85????????68????????5053ff15
         // 005699d6: lea eax, ss:[ebp+0xfffffffffffffe64]
         // 005699dc: push 0x104
         // 005699e1: push eax
         // 005699e2: push ebx
         // 005699e3: call ds:[0x588318]
      [-]389d64feffff8d8d????????7413
         // 005699e9: cmp b1 ss:[ebp+0xfffffffffffffe64], b1 bl
         // 005699ef: lea ecx, ss:[ebp+0xfffffffffffffe64]
         // 005699f5: jz 0x569a0a
      [-]8a013c617c08
         // 0040e54c: mov b1 al, b1 ds:[ecx]
         // 0040e54e: cmp b1 al, b1 0x61
         // 0040e550: jl 0x40e55a
      [-]3c7a7f04
         // 0040e552: cmp b1 al, b1 0x7a
         // 0040e554: jg 0x40e55a
      [-]2c208801
         // 0040e556: sub b1 al, b1 0x20
         // 0040e558: mov b1 ds:[ecx], b1 al
      [-]41381975ed
         // 0040e55a: inc ecx
         // 0040e55b: cmp b1 ds:[ecx], b1 bl
         // 0040e55d: jnz 0x40e54c
      [-]8d85????????508d85????????50e8
         // 004811ce: lea eax, ss:[ebp+0xfffffffffffffe64]
         // 004811d4: push eax
         // 004811d5: lea eax, ss:[ebp+0xffffffffffffedd4]
         // 004811db: push eax
         // 004811dc: call _strstr
      [-]3bc3743e
         // 0040e574: cmp eax, ebx
         // 0040e576: jz 0x40e5b6
      [-]6a2c50e8
         // 004811e7: push 0x2c
         // 004811e9: push eax
         // 004811ea: call _strchr
      [-]ffff593bc3597430
         // 004811ef: pop ecx
         // 004811f0: cmp eax, ebx
         // 004811f2: pop ecx
         // 004811f3: jz 0x481225
      [-]408bc83818740e
         // 0040e586: inc eax
         // 0040e587: mov ecx, eax
         // 0040e589: cmp b1 ds:[eax], b1 bl
         // 0040e58b: jz 0x40e59b
      [-]80393b7504
         // 0040e58d: cmp b1 ds:[ecx], b1 0x3b
         // 0040e590: jnz 0x40e596
      [-]8819eb01
         // 0040e592: mov b1 ds:[ecx], b1 bl
         // 0040e594: jmp 0x40e597
      [-]381975f2
         // 0040e597: cmp b1 ds:[ecx], b1 bl
         // 0040e599: jnz 0x40e58d
      [-]6a0a5350e8
         // 0048120a: push 0xa
         // 0048120c: push ebx
         // 0048120d: push eax
         // 0048120e: call _strtol
      [-]83c40c83f802741d
         // 00481213: add esp, 0xc
         // 00481216: cmp eax, 0x2
         // 00481219: jz 0x481238
      [-]83f8037418
         // 0040e5ac: cmp eax, 0x3
         // 0040e5af: jz 0x40e5c9
      [-]83f8017413
         // 0040e5b1: cmp eax, 0x1
         // 0040e5b4: jz 0x40e5c9
      [-]8d45fc50e898feffff807dfc06591bc083c003
         // 0040e5b6: lea eax, ss:[ebp+0xfffffffffffffffc]
         // 0040e5b9: push eax
         // 0040e5ba: call 0x40e457
         // 0040e5bf: cmp b1 ss:[ebp+0xfffffffffffffffc], b1 0x6
         // 0040e5c3: pop ecx
         // 0040e5c4: sbb eax, eax
         // 0040e5c6: add eax, 0x3
      [-]33c06a003944240868????????0f94c050ff15
         // 004b7575: xor eax, eax
         // 004b7577: push 0x0
         // 004b7579: cmp ss:[esp+0x8], eax
         // 004b757d: push 0x1000
         // 004b7582: setz b1 al
         // 004b7585: push eax
         // 004b7586: call ds:[HeapCreate]
      [-]e893feffff83f803a3
         // 0048125b: call 0x4810f3
         // 00481260: cmp eax, 0x3
         // 00481263: mov ds:[0x50d868], eax
      [-]68????????e8
         // 0048126a: push 0x3f8
         // 0048126f: call ___sbh_heap_init
      [-]000059eb0a
         // 00481274: pop ecx
         // 00481275: jmp 0x481281
      [-]83f8027518
         // 0040e608: cmp eax, 0x2
         // 0040e60b: jnz 0x40e625
      [-]85c0750f
         // 0040e612: test eax, eax
         // 0040e614: jnz 0x40e625
      [-]6a0158c3
         // 0040e625: push 0x1
         // 0040e627: pop eax
         // 0040e628: retn 
      [-]558bec81ec????????8b550833c9b8
         // 004812d1: push ebp
         // 004812d2: mov ebp, esp
         // 004812d4: sub esp, 0x1a4
         // 004812da: mov edx, ss:[ebp+0x8]
         // 004812dd: xor ecx, ecx
         // 004812df: mov eax, 0x4c7ba0
      [-]3b10740b
         // 0040e758: cmp edx, ds:[eax]
         // 0040e75a: jz 0x40e767
      [-]83c008413d
         // 004812e8: add eax, 0x8
         // 004812eb: inc ecx
         // 004812ec: cmp eax, 0x4c7c30
      [-]568bf1c1e6033b96
         // 004812f3: push esi
         // 004812f4: mov esi, ecx
         // 004812f6: shl esi, b1 0x3
         // 004812f9: cmp edx, ds:[esi+0x4c7ba0]
      [-]0f851c010000
         // 004812ff: jnz 0x481421
      [-]83f8010f84e8000000
         // 0048130a: cmp eax, 0x1
         // 0048130d: jz 0x4813fb
      [-]85c0750d
         // 0040e787: test eax, eax
         // 0040e789: jnz 0x40e798
      [-]010f84d7000000
         // 0048131e: jz 0x4813fb
      [-]81fa????????0f84f1000000
         // 0040e798: cmp edx, 0xfc
         // 0040e79e: jz 0x40e895
      [-]8d85????????68????????506a00ff15
         // 00569b6c: lea eax, ss:[ebp+0xfffffffffffffe5c]
         // 00569b72: push 0x104
         // 00569b77: push eax
         // 00569b78: push 0x0
         // 00569b7a: call ds:[0x588318]
      [-]85c07513
         // 00569b80: test eax, eax
         // 00569b82: jnz 0x569b97
      [-]8d85????????68
         // 0040e7bc: lea eax, ss:[ebp+0xfffffffffffffe5c]
         // 0040e7c2: push 0x4155b8
      [-]8d85????????57508dbd????????e8
         // 0048135b: lea eax, ss:[ebp+0xfffffffffffffe5c]
         // 00481361: push edi
         // 00481362: push eax
         // 00481363: lea edi, ss:[ebp+0xfffffffffffffe5c]
         // 00481369: call _strlen
      [-]405983f83c7629
         // 0048136e: inc eax
         // 0048136f: pop ecx
         // 00481370: cmp eax, 0x3c
         // 00481373: jbe 0x48139e
      [-]8d85????????50e8
         // 00481375: lea eax, ss:[ebp+0xfffffffffffffe5c]
         // 0048137b: push eax
         // 0048137c: call _strlen
      [-]8bf88d85????????83e83b6a0303f868
         // 00481381: mov edi, eax
         // 00481383: lea eax, ss:[ebp+0xfffffffffffffe5c]
         // 00481389: sub eax, 0x3b
         // 0048138c: push 0x3
         // 0048138e: add edi, eax
         // 00481390: push 0x4bdb34
      [-]ffff83c410
         // 0048139b: add esp, 0x10
      [-]8d85????????68
         // 0040e812: lea eax, ss:[ebp+0xffffffffffffff60]
         // 0040e818: push 0x415598
      [-]8d85????????5750e8
         // 0040e823: lea eax, ss:[ebp+0xffffffffffffff60]
         // 0040e829: push edi
         // 0040e82a: push eax
         // 0040e82b: call _strcat
      [-]8d85????????68
         // 0040e830: lea eax, ss:[ebp+0xffffffffffffff60]
         // 0040e836: push 0x415594
      [-]8d85????????50e8
         // 0040e847: lea eax, ss:[ebp+0xffffffffffffff60]
         // 0040e84d: push eax
         // 0040e84e: call _strcat
      [-]68????????8d85????????68
         // 0040e853: push 0x12010
         // 0040e858: lea eax, ss:[ebp+0xffffffffffffff60]
         // 0040e85e: push 0x41556c
      [-]000083c42c5feb26
         // 0040e869: add esp, 0x2c
         // 0040e86c: pop edi
         // 0040e86d: jmp 0x40e895
      [-]8d45088db6
         // 004858bb: lea eax, ss:[ebp+0x8]
         // 004858be: lea esi, ds:[esi+0x115d414]
      [-]6a0050ff36e8
         // 004858c4: push 0x0
         // 004858c6: push eax
         // 004858c7: push ds:[esi]
         // 004858c9: call _strlen
      [-]5950ff366af4ff15
         // 004858ce: pop ecx
         // 004858cf: push eax
         // 004858d0: push ds:[esi]
         // 004858d2: push 0xfffffffffffffff4
         // 004858d4: call ds:[GetStdHandle]
      [-]558bec83ec108b4d0853568b750c8b4110578bfe83c6fc2b790cc1ef0f8bcf69c9????????8d8c01????????894df08b0e49f6c101894dfc0f85e6020000
         // 0041038c: push ebp
         // 0041038d: mov ebp, esp
         // 0041038f: sub esp, 0x10
         // 00410392: mov ecx, ss:[ebp+0x8]
         // 00410395: push ebx
         // 00410396: push esi
         // 00410397: mov esi, ss:[ebp+0xc]
         // 0041039a: mov eax, ds:[ecx+0x10]
         // 0041039d: push edi
         // 0041039e: mov edi, esi
         // 004103a0: add esi, 0xfffffffffffffffc
         // 004103a3: sub edi, ds:[ecx+0xc]
         // 004103a6: shr edi, b1 0xf
         // 004103a9: mov ecx, edi
         // 004103ab: imul ecx, 0x204
         // 004103b1: lea ecx, ds:[ecx+eax+0x144]
         // 004103b8: mov ss:[ebp+0xfffffffffffffff0], ecx
         // 004103bb: mov ecx, ds:[esi]
         // 004103bd: dec ecx
         // 004103be: test b1 cl, b1 0x1
         // 004103c1: mov ss:[ebp+0xfffffffffffffffc], ecx
         // 004103c4: jnz 0x4106b0
      [-]8b14318d1c318955f48b56fc8955f88b55f4f6c201895d0c757e
         // 004103ca: mov edx, ds:[ecx+esi]
         // 004103cd: lea ebx, ds:[ecx+esi]
         // 004103d0: mov ss:[ebp+0xfffffffffffffff4], edx
         // 004103d3: mov edx, ds:[esi+0xfffffffffffffffc]
         // 004103d6: mov ss:[ebp+0xfffffffffffffff8], edx
         // 004103d9: mov edx, ss:[ebp+0xfffffffffffffff4]
         // 004103dc: test b1 dl, b1 0x1
         // 004103df: mov ss:[ebp+0xc], ebx
         // 004103e2: jnz 0x410462
      [-]c1fa044a83fa3f7603
         // 004103e4: sar edx, b1 0x4
         // 004103e7: dec edx
         // 004103e8: cmp edx, 0x3f
         // 004103eb: jbe 0x4103f0
      [-]8b4b043b4b08754c
         // 004103f0: mov ecx, ds:[ebx+0x4]
         // 004103f3: cmp ecx, ds:[ebx+0x8]
         // 004103f6: jnz 0x410444
      [-]83fa20731e
         // 004103f8: cmp edx, 0x20
         // 004103fb: jnb 0x41041b
      [-]bb????????8bcad3eb8d4c0204f7d3215cb844fe097528
         // 004103fd: mov ebx, 0xffffffff80000000
         // 00410402: mov ecx, edx
         // 00410404: shr ebx, b1 cl
         // 00410406: lea ecx, ds:[edx+eax+0x4]
         // 0041040a: not ebx
         // 0041040c: and ds:[eax+edi*0x4], ebx
         // 00410410: dec b1 ds:[ecx]
         // 00410412: jnz 0x41043c
      [-]8b4d082119eb21
         // 00410414: mov ecx, ss:[ebp+0x8]
         // 00410417: and ds:[ecx], ebx
         // 00410419: jmp 0x41043c
      [-]8d4ae0bb????????d3eb8d4c0204f7d3219cb8c4000000fe097506
         // 0041041b: lea ecx, ds:[edx+0xffffffffffffffe0]
         // 0041041e: mov ebx, 0xffffffff80000000
         // 00410423: shr ebx, b1 cl
         // 00410425: lea ecx, ds:[edx+eax+0x4]
         // 00410429: not ebx
         // 0041042b: and ds:[eax+edi*0x4], ebx
         // 00410432: dec b1 ds:[ecx]
         // 00410434: jnz 0x41043c
      [-]8b4d08215904
         // 00410436: mov ecx, ss:[ebp+0x8]
         // 00410439: and ds:[ecx+0x4], ebx
      [-]8b4dfc8b5d0ceb03
         // 0041043c: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 0041043f: mov ebx, ss:[ebp+0xc]
         // 00410442: jmp 0x410447
      [-]8b53088b5b04034df4895a048b550c894dfc8b5a048b5208895308
         // 00410447: mov edx, ds:[ebx+0x8]
         // 0041044a: mov ebx, ds:[ebx+0x4]
         // 0041044d: add ecx, ss:[ebp+0xfffffffffffffff4]
         // 00410450: mov ds:[edx+0x4], ebx
         // 00410453: mov edx, ss:[ebp+0xc]
         // 00410456: mov ss:[ebp+0xfffffffffffffffc], ecx
         // 00410459: mov ebx, ds:[edx+0x4]
         // 0041045c: mov edx, ds:[edx+0x8]
         // 0041045f: mov ds:[ebx+0x8], edx
      [-]8bd1c1fa044a83fa3f7603
         // 00410462: mov edx, ecx
         // 00410464: sar edx, b1 0x4
         // 00410467: dec edx
         // 00410468: cmp edx, 0x3f
         // 0041046b: jbe 0x410470
      [-]8b5df883e301895df40f8594000000
         // 00410470: mov ebx, ss:[ebp+0xfffffffffffffff8]
         // 00410473: and ebx, 0x1
         // 00410476: mov ss:[ebp+0xfffffffffffffff4], ebx
         // 00410479: jnz 0x410513
      [-]2b75f88b5df8c1fb046a3f89750c4b5e3bde7602
         // 0041047f: sub esi, ss:[ebp+0xfffffffffffffff8]
         // 00410482: mov ebx, ss:[ebp+0xfffffffffffffff8]
         // 00410485: sar ebx, b1 0x4
         // 00410488: push 0x3f
         // 0041048a: mov ss:[ebp+0xc], esi
         // 0041048d: dec ebx
         // 0041048e: pop esi
         // 0041048f: cmp ebx, esi
         // 00410491: jbe 0x410495
      [-]034df88bd1894dfcc1fa044a3bd67602
         // 00410495: add ecx, ss:[ebp+0xfffffffffffffff8]
         // 00410498: mov edx, ecx
         // 0041049a: mov ss:[ebp+0xfffffffffffffffc], ecx
         // 0041049d: sar edx, b1 0x4
         // 004104a0: dec edx
         // 004104a1: cmp edx, esi
         // 004104a3: jbe 0x4104a7
      [-]3bda7463
         // 004104a7: cmp ebx, edx
         // 004104a9: jz 0x41050e
      [-]8b4d0c8b71043b71087540
         // 004104ab: mov ecx, ss:[ebp+0xc]
         // 004104ae: mov esi, ds:[ecx+0x4]
         // 004104b1: cmp esi, ds:[ecx+0x8]
         // 004104b4: jnz 0x4104f6
      [-]83fb20731c
         // 004104b6: cmp ebx, 0x20
         // 004104b9: jnb 0x4104d7
      [-]be????????8bcbd3eef7d62174b844fe4c03047526
         // 004104bb: mov esi, 0xffffffff80000000
         // 004104c0: mov ecx, ebx
         // 004104c2: shr esi, b1 cl
         // 004104c4: not esi
         // 004104c6: and ds:[eax+edi*0x4], esi
         // 004104ca: dec b1 ds:[ebx+eax+0x4]
         // 004104ce: jnz 0x4104f6
      [-]8b4d082131eb1f
         // 004104d0: mov ecx, ss:[ebp+0x8]
         // 004104d3: and ds:[ecx], esi
         // 004104d5: jmp 0x4104f6
      [-]8d4be0be????????d3eef7d621b4b8c4000000fe4c03047506
         // 004104d7: lea ecx, ds:[ebx+0xffffffffffffffe0]
         // 004104da: mov esi, 0xffffffff80000000
         // 004104df: shr esi, b1 cl
         // 004104e1: not esi
         // 004104e3: and ds:[eax+edi*0x4], esi
         // 004104ea: dec b1 ds:[ebx+eax+0x4]
         // 004104ee: jnz 0x4104f6
      [-]8b4d08217104
         // 004104f0: mov ecx, ss:[ebp+0x8]
         // 004104f3: and ds:[ecx+0x4], esi
      [-]8b4d0c8b71088b4904894e048b4d0c8b71048b4908894e08
         // 004104f6: mov ecx, ss:[ebp+0xc]
         // 004104f9: mov esi, ds:[ecx+0x8]
         // 004104fc: mov ecx, ds:[ecx+0x4]
         // 004104ff: mov ds:[esi+0x4], ecx
         // 00410502: mov ecx, ss:[ebp+0xc]
         // 00410505: mov esi, ds:[ecx+0x4]
         // 00410508: mov ecx, ds:[ecx+0x8]
         // 0041050b: mov ds:[esi+0x8], ecx
      [-]8b750ceb03
         // 0041050e: mov esi, ss:[ebp+0xc]
         // 00410511: jmp 0x410516
      [-]837df4007508
         // 00410516: cmp ss:[ebp+0xfffffffffffffff4], 0x0
         // 0041051a: jnz 0x410524
      [-]3bda0f8481000000
         // 0041051c: cmp ebx, edx
         // 0041051e: jz 0x4105a5
      [-]8b4df08b5cd1048d0cd1895e04894e088971048b4e048971088b4e043b4e087560
         // 00410524: mov ecx, ss:[ebp+0xfffffffffffffff0]
         // 00410527: mov ebx, ds:[ecx+edx*0x8]
         // 0041052b: lea ecx, ds:[ecx+edx*0x8]
         // 0041052e: mov ds:[esi+0x4], ebx
         // 00410531: mov ds:[esi+0x8], ecx
         // 00410534: mov ds:[ecx+0x4], esi
         // 00410537: mov ecx, ds:[esi+0x4]
         // 0041053a: mov ds:[ecx+0x8], esi
         // 0041053d: mov ecx, ds:[esi+0x4]
         // 00410540: cmp ecx, ds:[esi+0x8]
         // 00410543: jnz 0x4105a5
      [-]8a4c020483fa20884d0ffec1884c02047325
         // 00410545: mov b1 cl, b1 ds:[edx+eax+0x4]
         // 00410549: cmp edx, 0x20
         // 0041054c: mov b1 ss:[ebp+0xf], b1 cl
         // 0041054f: inc b1 cl
         // 00410551: mov b1 ds:[edx+eax+0x4], b1 cl
         // 00410555: jnb 0x41057c
      [-]807d0f00750e
         // 00410557: cmp b1 ss:[ebp+0xf], b1 0x0
         // 0041055b: jnz 0x41056b
      [-]bb????????8bcad3eb8b4d080919
         // 0041055d: mov ebx, 0xffffffff80000000
         // 00410562: mov ecx, edx
         // 00410564: shr ebx, b1 cl
         // 00410566: mov ecx, ss:[ebp+0x8]
         // 00410569: or ds:[ecx], ebx
      [-]bb????????8bcad3eb8d44b8440918eb29
         // 0041056b: mov ebx, 0xffffffff80000000
         // 00410570: mov ecx, edx
         // 00410572: shr ebx, b1 cl
         // 00410574: lea eax, ds:[eax+edi*0x4]
         // 00410578: or ds:[eax], ebx
         // 0041057a: jmp 0x4105a5
      [-]807d0f007510
         // 0041057c: cmp b1 ss:[ebp+0xf], b1 0x0
         // 00410580: jnz 0x410592
      [-]8d4ae0bb????????d3eb8b4d08095904
         // 00410582: lea ecx, ds:[edx+0xffffffffffffffe0]
         // 00410585: mov ebx, 0xffffffff80000000
         // 0041058a: shr ebx, b1 cl
         // 0041058c: mov ecx, ss:[ebp+0x8]
         // 0041058f: or ds:[ecx+0x4], ebx
      [-]8d4ae0ba????????d3ea8d84b8c40000000910
         // 00410592: lea ecx, ds:[edx+0xffffffffffffffe0]
         // 00410595: mov edx, 0xffffffff80000000
         // 0041059a: shr edx, b1 cl
         // 0041059c: lea eax, ds:[eax+edi*0x4]
         // 004105a3: or ds:[eax], edx
      [-]8b45fc8906894430fc8b45f0ff080f85f7000000
         // 004105a5: mov eax, ss:[ebp+0xfffffffffffffffc]
         // 004105a8: mov ds:[esi], eax
         // 004105aa: mov ds:[eax+esi+0xfffffffffffffffc], eax
         // 004105ae: mov eax, ss:[ebp+0xfffffffffffffff0]
         // 004105b1: dec ds:[eax]
         // 004105b3: jnz 0x4106b0
      [-]85c00f84dc000000
         // 00484dba: test eax, eax
         // 00484dbc: jz 0x484e9e
      [-]c1e10f03480cbb????????68????????5351ffd68b0d
         // 0056d62e: shl ecx, b1 0xf
         // 0056d631: add ecx, ds:[eax+0xc]
         // 0056d634: mov ebx, 0x8000
         // 0056d639: push 0x4000
         // 0056d63e: push ebx
         // 0056d63f: push ecx
         // 0056d640: call esi
         // 0056d642: mov ecx, ds:[0x6177dc]
      [-]ba????????d3ea095008a1
         // 0056d64d: mov edx, 0xffffffff80000000
         // 0056d652: shr edx, b1 cl
         // 0056d654: or ds:[eax+0x8], edx
         // 0056d657: mov eax, ds:[0x6177e4]
      [-]8b401083a488c4????????a1
         // 0056d662: mov eax, ds:[eax+0x10]
         // 0056d665: and ds:[eax+ecx*0x4], 0x0
         // 0056d66d: mov eax, ds:[0x6177e4]
      [-]8b4010fe4843a1
         // 0056d672: mov eax, ds:[eax+0x10]
         // 0056d675: dec b1 ds:[eax+0x43]
         // 0056d678: mov eax, ds:[0x6177e4]
      [-]8b4810807943007509
         // 0056d67d: mov ecx, ds:[eax+0x10]
         // 0056d680: cmp b1 ds:[ecx+0x43], b1 0x0
         // 0056d684: jnz 0x56d68f
      [-]836004fea1
         // 00484e26: and ds:[eax+0x4], 0xfffffffffffffffe
         // 00484e2a: mov eax, ds:[0x50d854]
      [-]837808ff7569
         // 00410633: cmp ds:[eax+0x8], 0xffffffffffffffff
         // 00410637: jnz 0x4106a2
      [-]536a00ff700cffd6a1
         // 0056d695: push ebx
         // 0056d696: push 0x0
         // 0056d698: push ds:[eax+0xc]
         // 0056d69b: call esi
         // 0056d69d: mov eax, ds:[0x6177e4]
      [-]ff70106a00ff35
         // 0056d6a2: push ds:[eax+0x10]
         // 0056d6a5: push 0x0
         // 0056d6a7: push ds:[0x6177f4]
      [-]8d0480c1e0028bc8a1
         // 0056d6be: lea eax, ds:[eax+eax*0x4]
         // 0056d6c1: shl eax, b1 0x2
         // 0056d6c4: mov ecx, eax
         // 0056d6c6: mov eax, ds:[0x6177e4]
      [-]2bc88d4c11ec518d48145150e8
         // 0056d6cb: sub ecx, eax
         // 0056d6cd: lea ecx, ds:[ecx+edx+0xffffffffffffffec]
         // 0056d6d1: push ecx
         // 0056d6d2: lea ecx, ds:[eax+0x14]
         // 0056d6d5: push ecx
         // 0056d6d6: push eax
         // 0056d6d7: call 0x565a90
      [-]ffff8b450883c40cff0d
         // 0056d6dc: mov eax, ss:[ebp+0x8]
         // 0056d6df: add esp, 0xc
         // 0056d6e2: dec ds:[0x6177e8]
      [-]836d0814
         // 00410694: sub ss:[ebp+0x8], 0x14
      [-]8b4508893d
         // 00484e9e: mov eax, ss:[ebp+0x8]
         // 00484ea1: mov ds:[0x50d84c], edi
      [-]5f5e5bc9c3
         // 004106b0: pop edi
         // 004106b1: pop esi
         // 004106b2: pop ebx
         // 004106b3: leave 
         // 004106b4: retn 
      [-]ff535556577507
         // 00485663: push ebx
         // 00485664: push ebp
         // 00485665: push esi
         // 00485666: push edi
         // 00485667: jnz 0x485670
      [-]68????????6a00ff35
         // 0056ded0: push 0x2020
         // 0056ded5: push 0x0
         // 0056ded7: push ds:[0x6177f4]
      [-]8bf085f60f840c010000
         // 0056dee3: mov esi, eax
         // 0056dee5: test esi, esi
         // 0056dee7: jz 0x56dff9
      [-]6a0468????????68????????6a00ffd58bf885ff0f84d5000000
         // 00489b83: push 0x4
         // 00489b85: push 0x2000
         // 00489b8a: push 0x400000
         // 00489b8f: push 0x0
         // 00489b91: call ebp
         // 00489b93: mov edi, eax
         // 00489b95: test edi, edi
         // 00489b97: jz 0x489c72
      [-]6a04bb????????68????????5357ffd585c00f84af000000
         // 00410bbb: push 0x4
         // 00410bbd: mov ebx, 0x10000
         // 00410bc2: push 0x1000
         // 00410bc7: push ebx
         // 00410bc8: push edi
         // 00410bc9: call ebp
         // 00410bcb: test eax, eax
         // 00410bcd: jz 0x410c82
      [-]3bf0751e
         // 004856ca: cmp esi, eax
         // 004856cc: jnz 0x4856ec
      [-]8946048935
         // 004856f3: mov ds:[esi+0x4], eax
         // 004856f6: mov ds:[0x4c8254], esi
      [-]8b46048930
         // 004856fc: mov eax, ds:[esi+0x4]
         // 004856ff: mov ds:[eax], esi
      [-]8d87????????8d8e????????8946148d4618894e0c897e1089460833edb9????????
         // 00410c0f: lea eax, ds:[edi+0x400000]
         // 00410c15: lea ecx, ds:[esi+0x98]
         // 00410c1b: mov ds:[esi+0x14], eax
         // 00410c1e: lea eax, ds:[esi+0x18]
         // 00410c21: mov ds:[esi+0xc], ecx
         // 00410c24: mov ds:[esi+0x10], edi
         // 00410c27: mov ds:[esi+0x8], eax
         // 00410c2a: xor ebp, ebp
         // 00410c2c: mov ecx, 0xf1
      [-]33d283fd100f9dc24a23d14a45891089480483c00881fd????????7ce3
         // 00410c31: xor edx, edx
         // 00410c33: cmp ebp, 0x10
         // 00410c36: setnl b1 dl
         // 00410c39: dec edx
         // 00410c3a: and edx, ecx
         // 00410c3c: dec edx
         // 00410c3d: inc ebp
         // 00410c3e: mov ds:[eax], edx
         // 00410c40: mov ds:[eax+0x4], ecx
         // 00410c43: add eax, 0x8
         // 00410c46: cmp ebp, 0x400
         // 00410c4c: jl 0x410c31
      [-]536a0057e8
         // 00485740: push ebx
         // 00485741: push 0x0
         // 00485743: push edi
         // 00485744: call _memset
      [-]8b461003c33bf8731b
         // 00410c5a: mov eax, ds:[esi+0x10]
         // 00410c5d: add eax, ebx
         // 00410c5f: cmp edi, eax
         // 00410c61: jnb 0x410c7e
      [-]808ff8000000ff8d47088907c74704????????81c7????????ebdc
         // 00410c63: or b1 ds:[edi+0xf8], b1 0xff
         // 00410c6a: lea eax, ds:[edi+0x8]
         // 00410c6d: mov ds:[edi], eax
         // 00410c6f: mov ds:[edi+0x4], 0xf0
         // 00410c76: add edi, 0x1000
         // 00410c7c: jmp 0x410c5a
      [-]8bc6eb27
         // 00410c7e: mov eax, esi
         // 00410c80: jmp 0x410ca9
      [-]68????????6a0057ff15
         // 00410c82: push 0x8000
         // 00410c87: push 0x0
         // 00410c89: push edi
         // 00410c8a: call ds:[VirtualFree]
      [-]566a00ff35
         // 00410c98: push esi
         // 00410c99: push 0x0
         // 00410c9b: push ds:[0x67962c]
      [-]5f5e5d5bc3
         // 00410ca9: pop edi
         // 00410caa: pop esi
         // 00410cab: pop ebp
         // 00410cac: pop ebx
         // 00410cad: retn 
      [-]568b74240868????????6a00ff7610ff15
         // 0056e000: push esi
         // 0056e001: mov esi, ss:[esp+0x8]
         // 0056e005: push 0x8000
         // 0056e00a: push 0x0
         // 0056e00c: push ds:[esi+0x10]
         // 0056e00f: call ds:[0x58828c]
      [-]8b4604a3
         // 004857bd: mov eax, ds:[esi+0x4]
         // 004857c0: mov ds:[0x4ca270], eax
      [-]8b46048b0e566a0089088b068b4e04894804ff35
         // 00410cdb: mov eax, ds:[esi+0x4]
         // 00410cde: mov ecx, ds:[esi]
         // 00410ce0: push esi
         // 00410ce1: push 0x0
         // 00410ce3: mov ds:[eax], ecx
         // 00410ce5: mov eax, ds:[esi]
         // 00410ce7: mov ecx, ds:[esi+0x4]
         // 00410cea: mov ds:[eax+0x4], ecx
         // 00410ced: push ds:[0x67962c]
      [-]558bec5153568b35
         // 004857f6: push ebp
         // 004857f7: mov ebp, esp
         // 004857f9: push ecx
         // 004857fa: push ebx
         // 004857fb: push esi
         // 004857fc: mov esi, ds:[0x4c8254]
      [-]837e10ff0f8494000000
         // 00410d11: cmp ds:[esi+0x10], 0xffffffffffffffff
         // 00410d15: jz 0x410daf
      [-]8365fc008dbe????????bb????????
         // 00410d1b: and ss:[ebp+0xfffffffffffffffc], 0x0
         // 00410d1f: lea edi, ds:[esi+0x2010]
         // 00410d25: mov ebx, 0x3ff000
      [-]813f????????7539
         // 00410d2a: cmp ds:[edi], 0xf0
         // 00410d30: jnz 0x410d6b
      [-]8bc368????????03461068????????50ff15
         // 0056e084: mov eax, ebx
         // 0056e086: push 0x4000
         // 0056e08b: add eax, ds:[esi+0x10]
         // 0056e08e: push 0x1000
         // 0056e093: push eax
         // 0056e094: call ds:[0x58828c]
      [-]85c0741f
         // 0056e09a: test eax, eax
         // 0056e09c: jz 0x56e0bd
      [-]830fffff0d
         // 0048583e: or ds:[edi], 0xffffffffffffffff
         // 00485841: dec ds:[0x50d58c]
      [-]8b460c85c07404
         // 00485847: mov eax, ds:[esi+0xc]
         // 0048584a: test eax, eax
         // 0048584c: jz 0x485852
      [-]3bc77603
         // 00410d5c: cmp eax, edi
         // 00410d5e: jbe 0x410d63
      [-]ff45fcff4d08740d
         // 00410d63: inc ss:[ebp+0xfffffffffffffffc]
         // 00410d66: dec ss:[ebp+0x8]
         // 00410d69: jz 0x410d78
      [-]81eb????????83ef0885db7db2
         // 00410d6b: sub ebx, 0x1000
         // 00410d71: sub edi, 0x8
         // 00410d74: test ebx, ebx
         // 00410d76: jge 0x410d2a
      [-]837dfc008bce8b7604742c
         // 00410d78: cmp ss:[ebp+0xfffffffffffffffc], 0x0
         // 00410d7c: mov ecx, esi
         // 00410d7e: mov esi, ds:[esi+0x4]
         // 00410d81: jz 0x410daf
      [-]837918ff7526
         // 00410d83: cmp ds:[ecx+0x18], 0xffffffffffffffff
         // 00410d87: jnz 0x410daf
      [-]6a018d41205a
         // 00410d89: push 0x1
         // 00410d8b: lea eax, ds:[ecx+0x20]
         // 00410d8e: pop edx
      [-]8338ff750c
         // 00410d8f: cmp ds:[eax], 0xffffffffffffffff
         // 00410d92: jnz 0x410da0
      [-]4283c00881fa????????7cef
         // 00410d94: inc edx
         // 00410d95: add eax, 0x8
         // 00410d98: cmp edx, 0x400
         // 00410d9e: jl 0x410d8f
      [-]81fa????????7507
         // 00410da0: cmp edx, 0x400
         // 00410da6: jnz 0x410daf
      [-]51e800ffffff59
         // 00410da8: push ecx
         // 00410da9: call 0x410cae
         // 00410dae: pop ecx
      [-]837d08000f8f50ffffff
         // 00410db7: cmp ss:[ebp+0x8], 0x0
         // 00410dbb: jg 0x410d11
      [-]5f5e5bc9c3
         // 00410dc1: pop edi
         // 00410dc2: pop esi
         // 00410dc3: pop ebx
         // 00410dc4: leave 
         // 00410dc5: retn 
      [-]8b442404ba
         // 004858b8: mov eax, ss:[esp+0x4]
         // 004858bc: mov edx, 0x4c8250
      [-]3b41107605
         // 00410dd2: cmp eax, ds:[ecx+0x10]
         // 00410dd5: jbe 0x410ddc
      [-]3b41147208
         // 00410dd7: cmp eax, ds:[ecx+0x14]
         // 00410dda: jb 0x410de4
      [-]8b093bca7437
         // 00410ddc: mov ecx, ds:[ecx]
         // 00410dde: cmp ecx, edx
         // 00410de0: jz 0x410e19
      [-]a80f7531
         // 00410de4: test b1 al, b1 0xf
         // 00410de6: jnz 0x410e19
      [-]8bf0ba????????81e6????????3bf27220
         // 00410de8: mov esi, eax
         // 00410dea: mov edx, 0x100
         // 00410def: and esi, 0xfff
         // 00410df5: cmp esi, edx
         // 00410df7: jb 0x410e19
      [-]8b74240c890e8b7424108bc86681e100f02bc1890e2bc25ec1f8048d440808c3
         // 00410df9: mov esi, ss:[esp+0xc]
         // 00410dfd: mov ds:[esi], ecx
         // 00410dff: mov esi, ss:[esp+0x10]
         // 00410e03: mov ecx, eax
         // 00410e05: and b2 cx, b2 0xfffffffffffff000
         // 00410e0a: sub eax, ecx
         // 00410e0c: mov ds:[esi], ecx
         // 00410e0e: sub eax, edx
         // 00410e10: pop esi
         // 00410e11: sar eax, b1 0x4
         // 00410e14: lea eax, ds:[eax+ecx+0x8]
         // 00410e18: retn 
      [-]33c05ec3
         // 00410e19: xor eax, eax
         // 00410e1b: pop esi
         // 00410e1c: retn 
      [-]8b4424048b4c24082b4810c1f90c8d44c8188b4c240c0fb61101108021008138????????c74004????????7517
         // 00410e1d: mov eax, ss:[esp+0x4]
         // 00410e21: mov ecx, ss:[esp+0x8]
         // 00410e25: sub ecx, ds:[eax+0x10]
         // 00410e28: sar ecx, b1 0xc
         // 00410e2b: lea eax, ds:[eax+ecx*0x8]
         // 00410e2f: mov ecx, ss:[esp+0xc]
         // 00410e33: movzx edx, b1 ds:[ecx]
         // 00410e36: add ds:[eax], edx
         // 00410e38: and b1 ds:[ecx], b1 0x0
         // 00410e3b: cmp ds:[eax], 0xf0
         // 00410e41: mov ds:[eax+0x4], 0xf1
         // 00410e48: jnz 0x410e61
      [-]6a10e8a4feffff59
         // 00410e59: push 0x10
         // 00410e5b: call 0x410d04
         // 00410e60: pop ecx
      [-]558bec515153568b35
         // 00485954: push ebp
         // 00485955: mov ebp, esp
         // 00485957: push ecx
         // 00485958: push ecx
         // 00485959: push ebx
         // 0048595a: push esi
         // 0048595b: mov esi, ds:[0x4ca270]
      [-]8b561083faff0f849f000000
         // 00410e70: mov edx, ds:[esi+0x10]
         // 00410e73: cmp edx, 0xffffffffffffffff
         // 00410e76: jz 0x410f1b
      [-]8b7e088d8e????????8bc72bc683e818c1f803c1e00c03c23bf98945fc733a
         // 00410e7c: mov edi, ds:[esi+0x8]
         // 00410e7f: lea ecx, ds:[esi+0x2018]
         // 00410e85: mov eax, edi
         // 00410e87: sub eax, esi
         // 00410e89: sub eax, 0x18
         // 00410e8c: sar eax, b1 0x3
         // 00410e8f: shl eax, b1 0xc
         // 00410e92: add eax, edx
         // 00410e94: cmp edi, ecx
         // 00410e96: mov ss:[ebp+0xfffffffffffffffc], eax
         // 00410e99: jnb 0x410ed5
      [-]8b0f8b5d083bcb7c1a
         // 00410e9b: mov ecx, ds:[edi]
         // 00410e9d: mov ebx, ss:[ebp+0x8]
         // 00410ea0: cmp ecx, ebx
         // 00410ea2: jl 0x410ebe
      [-]395f047615
         // 00410ea4: cmp ds:[edi+0x4], ebx
         // 00410ea7: jbe 0x410ebe
      [-]535150e8b901000083c40c85c07575
         // 00410ea9: push ebx
         // 00410eaa: push ecx
         // 00410eab: push eax
         // 00410eac: call 0x41106a
         // 00410eb1: add esp, 0xc
         // 00410eb4: test eax, eax
         // 00410eb6: jnz 0x410f2d
      [-]8b45fc895f04
         // 00410eb8: mov eax, ss:[ebp+0xfffffffffffffffc]
         // 00410ebb: mov ds:[edi+0x4], ebx
      [-]83c7088d8e????????05????????3bf98945fc72c8
         // 00410ebe: add edi, 0x8
         // 00410ec1: lea ecx, ds:[esi+0x2018]
         // 00410ec7: add eax, 0x1000
         // 00410ecc: cmp edi, ecx
         // 00410ece: mov ss:[ebp+0xfffffffffffffffc], eax
         // 00410ed1: jb 0x410e9b
      [-]8b46088b4e108d7e188945f83bf8894dfc7333
         // 00410ed8: mov eax, ds:[esi+0x8]
         // 00410edb: mov ecx, ds:[esi+0x10]
         // 00410ede: lea edi, ds:[esi+0x18]
         // 00410ee1: mov ss:[ebp+0xfffffffffffffff8], eax
         // 00410ee4: cmp edi, eax
         // 00410ee6: mov ss:[ebp+0xfffffffffffffffc], ecx
         // 00410ee9: jnb 0x410f1e
      [-]8b073bc37c19
         // 00410eeb: mov eax, ds:[edi]
         // 00410eed: cmp eax, ebx
         // 00410eef: jl 0x410f0a
      [-]395f047614
         // 00410ef1: cmp ds:[edi+0x4], ebx
         // 00410ef4: jbe 0x410f0a
      [-]5350ff75fce86a01000083c40c85c07526
         // 00410ef6: push ebx
         // 00410ef7: push eax
         // 00410ef8: push ss:[ebp+0xfffffffffffffffc]
         // 00410efb: call 0x41106a
         // 00410f00: add esp, 0xc
         // 00410f03: test eax, eax
         // 00410f05: jnz 0x410f2d
      [-]8145fc????????83c7083b7df872d2
         // 00410f0a: add ss:[ebp+0xfffffffffffffffc], 0x1000
         // 00410f11: add edi, 0x8
         // 00410f14: cmp edi, ss:[ebp+0xfffffffffffffff8]
         // 00410f17: jb 0x410eeb
      [-]8b363b35
         // 00485a10: mov esi, ds:[esi]
         // 00485a12: cmp esi, ds:[0x4ca270]
      [-]e943ffffff
         // 00410f28: jmp 0x410e70
      [-]291f897e08e928010000
         // 00485a25: sub ds:[edi], ebx
         // 00485a27: mov ds:[esi+0x8], edi
         // 00485a2a: jmp 0x485b57
      [-]837f10ff7406
         // 00410f44: cmp ds:[edi+0x10], 0xffffffffffffffff
         // 00410f48: jz 0x410f50
      [-]837f0c00750c
         // 00410f4a: cmp ds:[edi+0xc], 0x0
         // 00410f4e: jnz 0x410f5c
      [-]8b3f3bf80f84d7000000
         // 00410f50: mov edi, ds:[edi]
         // 00410f52: cmp edi, eax
         // 00410f54: jz 0x411031
      [-]8b5f0c8365fc008bf38bc32bf783ee18c1fe03c1e60c037710833bff7511
         // 00410f5c: mov ebx, ds:[edi+0xc]
         // 00410f5f: and ss:[ebp+0xfffffffffffffffc], 0x0
         // 00410f63: mov esi, ebx
         // 00410f65: mov eax, ebx
         // 00410f67: sub esi, edi
         // 00410f69: sub esi, 0x18
         // 00410f6c: sar esi, b1 0x3
         // 00410f6f: shl esi, b1 0xc
         // 00410f72: add esi, ds:[edi+0x10]
         // 00410f75: cmp ds:[ebx], 0xffffffffffffffff
         // 00410f78: jnz 0x410f8b
      [-]837dfc107d0b
         // 00410f7a: cmp ss:[ebp+0xfffffffffffffffc], 0x10
         // 00410f7e: jge 0x410f8b
      [-]83c008ff45fc8338ff74ef
         // 00410f80: add eax, 0x8
         // 00410f83: inc ss:[ebp+0xfffffffffffffffc]
         // 00410f86: cmp ds:[eax], 0xffffffffffffffff
         // 00410f89: jz 0x410f7a
      [-]8b45fc6a04c1e00c68????????50568945f8ff15
         // 0056e2dd: mov eax, ss:[ebp+0xfffffffffffffffc]
         // 0056e2e0: push 0x4
         // 0056e2e2: shl eax, b1 0xc
         // 0056e2e5: push 0x1000
         // 0056e2ea: push eax
         // 0056e2eb: push esi
         // 0056e2ec: mov ss:[ebp+0xfffffffffffffff8], eax
         // 0056e2ef: call ds:[0x58829c]
      [-]3bc60f85b8000000
         // 0056e2f5: cmp eax, esi
         // 0056e2f7: jnz 0x56e3b5
      [-]6a00ff75f856e8
         // 00485a9d: push 0x0
         // 00485a9f: push ss:[ebp+0xfffffffffffffff8]
         // 00485aa2: push esi
         // 00485aa3: call _memset
      [-]8b55fc83c40c85d28bcb7e30
         // 00485aa8: mov edx, ss:[ebp+0xfffffffffffffffc]
         // 00485aab: add esp, 0xc
         // 00485aae: test edx, edx
         // 00485ab0: mov ecx, ebx
         // 00485ab2: jle 0x485ae4
      [-]8d46048955fc
         // 00410fc2: lea eax, ds:[esi+0x4]
         // 00410fc5: mov ss:[ebp+0xfffffffffffffffc], edx
      [-]8088f4000000ff8d50048950fcba????????89108911c74104????????05????????83c108ff4dfc75d6
         // 00410fc8: or b1 ds:[eax+0xf4], b1 0xff
         // 00410fcf: lea edx, ds:[eax+0x4]
         // 00410fd2: mov ds:[eax+0xfffffffffffffffc], edx
         // 00410fd5: mov edx, 0xf0
         // 00410fda: mov ds:[eax], edx
         // 00410fdc: mov ds:[ecx], edx
         // 00410fde: mov ds:[ecx+0x4], 0xf1
         // 00410fe5: add eax, 0x1000
         // 00410fea: add ecx, 0x8
         // 00410fed: dec ss:[ebp+0xfffffffffffffffc]
         // 00410ff0: jnz 0x410fc8
      [-]8d87????????
         // 00485aea: lea eax, ds:[edi+0x2018]
      [-]3bc8730c
         // 00410ffe: cmp ecx, eax
         // 00411000: jnb 0x41100e
      [-]8339ff7405
         // 00411002: cmp ds:[ecx], 0xffffffffffffffff
         // 00411005: jz 0x41100c
      [-]83c108ebf2
         // 00411007: add ecx, 0x8
         // 0041100a: jmp 0x410ffe
      [-]1bc023c189470c8b4508884608895f0829032946048d4c06088d86????????890eeb34
         // 0041100e: sbb eax, eax
         // 00411010: and eax, ecx
         // 00411012: mov ds:[edi+0xc], eax
         // 00411015: mov eax, ss:[ebp+0x8]
         // 00411018: mov b1 ds:[esi+0x8], b1 al
         // 0041101b: mov ds:[edi+0x8], ebx
         // 0041101e: sub ds:[ebx], eax
         // 00411020: sub ds:[esi+0x4], eax
         // 00411023: lea ecx, ds:[esi+eax+0x8]
         // 00411027: lea eax, ds:[esi+0x100]
         // 0041102d: mov ds:[esi], ecx
         // 0041102f: jmp 0x411065
      [-]e834fbffff85c07429
         // 00411031: call 0x410b6a
         // 00411036: test eax, eax
         // 00411038: jz 0x411063
      [-]8b48108859088d541908a3
         // 00485b2c: mov ecx, ds:[eax+0x10]
         // 00485b2f: mov b1 ds:[ecx+0x8], b1 bl
         // 00485b32: lea edx, ds:[ecx+ebx+0x8]
         // 00485b36: mov ds:[0x4ca270], eax
      [-]8911ba????????2bd38951040fb6d32950188d81????????eb02
         // 00485b3b: mov ds:[ecx], edx
         // 00485b3d: mov edx, 0xf0
         // 00485b42: sub edx, ebx
         // 00485b44: mov ds:[ecx+0x4], edx
         // 00485b47: movzx edx, b1 bl
         // 00485b4a: sub ds:[eax+0x18], edx
         // 00485b4d: lea eax, ds:[ecx+0x100]
         // 00485b53: jmp 0x485b57
      [-]5f5e5bc9c3
         // 00411065: pop edi
         // 00411066: pop esi
         // 00411067: pop ebx
         // 00411068: leave 
         // 00411069: retn 
      [-]558bec518b4d088b551053568b7104578b398d99????????3bf2897dfc8bc7895d087221
         // 0041106a: push ebp
         // 0041106b: mov ebp, esp
         // 0041106d: push ecx
         // 0041106e: mov ecx, ss:[ebp+0x8]
         // 00411071: mov edx, ss:[ebp+0x10]
         // 00411074: push ebx
         // 00411075: push esi
         // 00411076: mov esi, ds:[ecx+0x4]
         // 00411079: push edi
         // 0041107a: mov edi, ds:[ecx]
         // 0041107c: lea ebx, ds:[ecx+0xf8]
         // 00411082: cmp esi, edx
         // 00411084: mov ss:[ebp+0xfffffffffffffffc], edi
         // 00411087: mov eax, edi
         // 00411089: mov ss:[ebp+0x8], ebx
         // 0041108c: jb 0x4110af
      [-]8d041788173bc37307
         // 0041108e: lea eax, ds:[edi+edx]
         // 00411091: mov b1 ds:[edi], b1 dl
         // 00411093: cmp eax, ebx
         // 00411095: jnb 0x41109e
      [-]0111295104eb09
         // 00411097: add ds:[ecx], edx
         // 00411099: sub ds:[ecx+0x4], edx
         // 0041109c: jmp 0x4110a7
      [-]836104008d41088901
         // 0041109e: and ds:[ecx+0x4], 0x0
         // 004110a2: lea eax, ds:[ecx+0x8]
         // 004110a5: mov ds:[ecx], eax
      [-]8d4708e9ce000000
         // 004110a7: lea eax, ds:[edi+0x8]
         // 004110aa: jmp 0x41117d
      [-]03f7803e007402
         // 004110af: add esi, edi
         // 004110b1: cmp b1 ds:[esi], b1 0x0
         // 004110b4: jz 0x4110b8
      [-]8d34103bf37343
         // 004110b8: lea esi, ds:[eax+edx]
         // 004110bb: cmp esi, ebx
         // 004110bd: jnb 0x411102
      [-]8a1884db7530
         // 004110bf: mov b1 bl, b1 ds:[eax]
         // 004110c1: test b1 bl, b1 bl
         // 004110c3: jnz 0x4110f5
      [-]6a018d58015e
         // 004110c5: push 0x1
         // 004110c7: lea ebx, ds:[eax+0x1]
         // 004110ca: pop esi
      [-]803b007504
         // 004110cb: cmp b1 ds:[ebx], b1 0x0
         // 004110ce: jnz 0x4110d4
      [-]4346ebf7
         // 004110d0: inc ebx
         // 004110d1: inc esi
         // 004110d2: jmp 0x4110cb
      [-]3bf2734e
         // 004110d4: cmp esi, edx
         // 004110d6: jnb 0x411126
      [-]3b45fc7505
         // 004110d8: cmp eax, ss:[ebp+0xfffffffffffffffc]
         // 004110db: jnz 0x4110e2
      [-]897104eb0c
         // 004110dd: mov ds:[ecx+0x4], esi
         // 004110e0: jmp 0x4110ee
      [-]29750c39550c0f8299000000
         // 004110e2: sub ss:[ebp+0xc], esi
         // 004110e5: cmp ss:[ebp+0xc], edx
         // 004110e8: jb 0x411187
      [-]8b7dfc8bc3eb05
         // 004110ee: mov edi, ss:[ebp+0xfffffffffffffffc]
         // 004110f1: mov eax, ebx
         // 004110f3: jmp 0x4110fa
      [-]0fb6f303c6
         // 004110f5: movzx esi, b1 bl
         // 004110f8: add eax, esi
      [-]8d34103b750872bd
         // 004110fa: lea esi, ds:[eax+edx]
         // 004110fd: cmp esi, ss:[ebp+0x8]
         // 00411100: jb 0x4110bf
      [-]3bf7737e
         // 00411105: cmp esi, edi
         // 00411107: jnb 0x411187
      [-]8d04163b45087376
         // 00411109: lea eax, ds:[esi+edx]
         // 0041110c: cmp eax, ss:[ebp+0x8]
         // 0041110f: jnb 0x411187
      [-]8a0684c07540
         // 00411111: mov b1 al, b1 ds:[esi]
         // 00411113: test b1 al, b1 al
         // 00411115: jnz 0x411157
      [-]6a018d5e0158
         // 00411117: push 0x1
         // 00411119: lea ebx, ds:[esi+0x1]
         // 0041111c: pop eax
      [-]803b007525
         // 0041111d: cmp b1 ds:[ebx], b1 0x0
         // 00411120: jnz 0x411147
      [-]4340ebf7
         // 00411122: inc ebx
         // 00411123: inc eax
         // 00411124: jmp 0x41111d
      [-]8d1c103b5d087309
         // 00411126: lea ebx, ds:[eax+edx]
         // 00411129: cmp ebx, ss:[ebp+0x8]
         // 0041112c: jnb 0x411137
      [-]2bf28919897104eb09
         // 0041112e: sub esi, edx
         // 00411130: mov ds:[ecx], ebx
         // 00411132: mov ds:[ecx+0x4], esi
         // 00411135: jmp 0x411140
      [-]836104008d71088931
         // 00411137: and ds:[ecx+0x4], 0x0
         // 0041113b: lea esi, ds:[ecx+0x8]
         // 0041113e: mov ds:[ecx], esi
      [-]881083c008eb36
         // 00411140: mov b1 ds:[eax], b1 dl
         // 00411142: add eax, 0x8
         // 00411145: jmp 0x41117d
      [-]3bc27313
         // 00411147: cmp eax, edx
         // 00411149: jnb 0x41115e
      [-]29450c39550c7234
         // 0041114b: sub ss:[ebp+0xc], eax
         // 0041114e: cmp ss:[ebp+0xc], edx
         // 00411151: jb 0x411187
      [-]8bf3ebae
         // 00411153: mov esi, ebx
         // 00411155: jmp 0x411105
      [-]0fb6c003f0eba7
         // 00411157: movzx eax, b1 al
         // 0041115a: add esi, eax
         // 0041115c: jmp 0x411105
      [-]8d1c163b5d087309
         // 0041115e: lea ebx, ds:[esi+edx]
         // 00411161: cmp ebx, ss:[ebp+0x8]
         // 00411164: jnb 0x41116f
      [-]2bc28919894104eb09
         // 00411166: sub eax, edx
         // 00411168: mov ds:[ecx], ebx
         // 0041116a: mov ds:[ecx+0x4], eax
         // 0041116d: jmp 0x411178
      [-]836104008d41088901
         // 0041116f: and ds:[ecx+0x4], 0x0
         // 00411173: lea eax, ds:[ecx+0x8]
         // 00411176: mov ds:[ecx], eax
      [-]88168d4608
         // 00411178: mov b1 ds:[esi], b1 dl
         // 0041117a: lea eax, ds:[esi+0x8]
      [-]6bc90fc1e0042bc1eb02
         // 0041117d: imul ecx, b1 0xf
         // 00411180: shl eax, b1 0x4
         // 00411183: sub eax, ecx
         // 00411185: jmp 0x411189
      [-]5f5e5bc9c3
         // 00411189: pop edi
         // 0041118a: pop esi
         // 0041118b: pop ebx
         // 0041118c: leave 
         // 0041118d: retn 
      [-]ff74240cff74240ce882feffff83c40cc3
         // 00488b1f: push ss:[esp+0xc]
         // 00488b23: push ss:[esp+0xc]
         // 00488b27: call __ld12cvt
         // 00488b2c: add esp, 0xc
         // 00488b2f: retn 
      [-]ff74240cff74240ce86cfeffff83c40cc3
         // 00488b35: push ss:[esp+0xc]
         // 00488b39: push ss:[esp+0xc]
         // 00488b3d: call __ld12cvt
         // 00488b42: add esp, 0xc
         // 00488b45: retn 
      [-]558bec83ec0c33c050505050ff750c8d450c508d45f450e8
         // 00488b46: push ebp
         // 00488b47: mov ebp, esp
         // 00488b49: sub esp, 0xc
         // 00488b4c: xor eax, eax
         // 00488b4e: push eax
         // 00488b4f: push eax
         // 00488b50: push eax
         // 00488b51: push eax
         // 00488b52: push ss:[ebp+0xc]
         // 00488b55: lea eax, ss:[ebp+0xc]
         // 00488b58: push eax
         // 00488b59: lea eax, ss:[ebp+0xfffffffffffffff4]
         // 00488b5c: push eax
         // 00488b5d: call ___strgtold12
      [-]0000ff75088d45f450e8acffffff83c424c9c3
         // 00488b62: push ss:[ebp+0x8]
         // 00488b65: lea eax, ss:[ebp+0xfffffffffffffff4]
         // 00488b68: push eax
         // 00488b69: call 0x488b1a
         // 00488b6e: add esp, 0x24
         // 00488b71: leave 
         // 00488b72: retn 
      [-]558bec83ec0c33c050505050ff750c8d450c508d45f450e8
         // 00488b73: push ebp
         // 00488b74: mov ebp, esp
         // 00488b76: sub esp, 0xc
         // 00488b79: xor eax, eax
         // 00488b7b: push eax
         // 00488b7c: push eax
         // 00488b7d: push eax
         // 00488b7e: push eax
         // 00488b7f: push ss:[ebp+0xc]
         // 00488b82: lea eax, ss:[ebp+0xc]
         // 00488b85: push eax
         // 00488b86: lea eax, ss:[ebp+0xfffffffffffffff4]
         // 00488b89: push eax
         // 00488b8a: call ___strgtold12
      [-]0000ff75088d45f450e895ffffff83c424c9c3
         // 00488b8f: push ss:[ebp+0x8]
         // 00488b92: lea eax, ss:[ebp+0xfffffffffffffff4]
         // 00488b95: push eax
         // 00488b96: call 0x488b30
         // 00488b9b: add esp, 0x24
         // 00488b9e: leave 
         // 00488b9f: retn 

  }
  condition:
    all of them
}
