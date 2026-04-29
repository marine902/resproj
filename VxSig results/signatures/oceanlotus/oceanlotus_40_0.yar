rule oceanlotus_40_0 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         558bec8b4d088b450c538d1c018b45148b10c700????????568b75108bc303d62bc157895d0c89550883f8010f8271030000
         // 004034e0: push ebp
         // 004034e1: mov ebp, esp
         // 004034e3: mov ecx, ss:[ebp+0x8]
         // 004034e6: mov eax, ss:[ebp+0xc]
         // 004034e9: push ebx
         // 004034ea: lea ebx, ds:[ecx+eax]
         // 004034ed: mov eax, ss:[ebp+0x14]
         // 004034f0: mov edx, ds:[eax]
         // 004034f2: mov ds:[eax], 0x0
         // 004034f8: push esi
         // 004034f9: mov esi, ss:[ebp+0x10]
         // 004034fc: mov eax, ebx
         // 004034fe: add edx, esi
         // 00403500: sub eax, ecx
         // 00403502: push edi
         // 00403503: mov ss:[ebp+0xc], ebx
         // 00403506: mov ss:[ebp+0x8], edx
         // 00403509: cmp eax, 0x1
         // 0040350c: jb 0x403883
      [-]8a013c117637
         // 00403512: mov b1 al, b1 ds:[ecx]
         // 00403514: cmp b1 al, b1 0x11
         // 00403516: jbe 0x40354f
      [-]0fb6c083e8114183f8040f823c010000
         // 00403518: movzx eax, b1 al
         // 0040351b: sub eax, 0x11
         // 0040351e: inc ecx
         // 0040351f: cmp eax, 0x4
         // 00403522: jb 0x403664
      [-]2bd63bd00f8283030000
         // 00403528: sub edx, esi
         // 0040352a: cmp edx, eax
         // 0040352c: jb 0x4038b5
      [-]8bd32bd18d78033bd70f8242030000
         // 00403532: mov edx, ebx
         // 00403534: sub edx, ecx
         // 00403536: lea edi, ds:[eax+0x3]
         // 00403539: cmp edx, edi
         // 0040353b: jb 0x403883
      [-]8a11881646414875f7
         // 00403541: mov b1 dl, b1 ds:[ecx]
         // 00403543: mov b1 ds:[esi], b1 dl
         // 00403545: inc esi
         // 00403546: inc ecx
         // 00403547: dec eax
         // 00403548: jnz 0x403541
      [-]e9ab000000
         // 0040354a: jmp 0x4035fa
      [-]8bc32bc183f8030f8227030000
         // 0040354f: mov eax, ebx
         // 00403551: sub eax, ecx
         // 00403553: cmp eax, 0x3
         // 00403556: jb 0x403883
      [-]0fb6014183f8100f8337010000
         // 0040355c: movzx eax, b1 ds:[ecx]
         // 0040355f: inc ecx
         // 00403560: cmp eax, 0x10
         // 00403563: jnb 0x4036a0
      [-]85c0752f
         // 00403569: test eax, eax
         // 0040356b: jnz 0x40359c
      [-]38017523
         // 0040356d: cmp b1 ds:[ecx], b1 al
         // 0040356f: jnz 0x403594
      [-]05????????413d????????0f8701030000
         // 00403571: add eax, 0xff
         // 00403576: inc ecx
         // 00403577: cmp eax, 0xfffffffffffffe01
         // 0040357c: ja 0x403883
      [-]8bfb2bf983ff010f82f4020000
         // 00403582: mov edi, ebx
         // 00403584: sub edi, ecx
         // 00403586: cmp edi, 0x1
         // 00403589: jb 0x403883
      [-]80390074dd
         // 0040358f: cmp b1 ds:[ecx], b1 0x0
         // 00403592: jz 0x403571
      [-]0fb6398d44380f41
         // 00403594: movzx edi, b1 ds:[ecx]
         // 00403597: lea eax, ds:[eax+edi+0xf]
         // 0040359b: inc ecx
      [-]2bd68d78033bd70f820c030000
         // 0040359c: sub edx, esi
         // 0040359e: lea edi, ds:[eax+0x3]
         // 004035a1: cmp edx, edi
         // 004035a3: jb 0x4038b5
      [-]8bd32bd18d78063bd70f82cb020000
         // 004035a9: mov edx, ebx
         // 004035ab: sub edx, ecx
         // 004035ad: lea edi, ds:[eax+0x6]
         // 004035b0: cmp edx, edi
         // 004035b2: jb 0x403883
      [-]8b11891683c60483c104487435
         // 004035b8: mov edx, ds:[ecx]
         // 004035ba: mov ds:[esi], edx
         // 004035bc: add esi, 0x4
         // 004035bf: add ecx, 0x4
         // 004035c2: dec eax
         // 004035c3: jz 0x4035fa
      [-]83f8047227
         // 004035c5: cmp eax, 0x4
         // 004035c8: jb 0x4035f1
      [-]8d9b????????
         // 004035ca: lea ebx, ds:[ebx+0x0]
      [-]8b11891683e80483c60483c10483f80473ee
         // 004035d0: mov edx, ds:[ecx]
         // 004035d2: mov ds:[esi], edx
         // 004035d4: sub eax, 0x4
         // 004035d7: add esi, 0x4
         // 004035da: add ecx, 0x4
         // 004035dd: cmp eax, 0x4
         // 004035e0: jnb 0x4035d0
      [-]85c07414
         // 004035e2: test eax, eax
         // 004035e4: jz 0x4035fa
      [-]8a11881646414875f7
         // 004035e6: mov b1 dl, b1 ds:[ecx]
         // 004035e8: mov b1 ds:[esi], b1 dl
         // 004035ea: inc esi
         // 004035eb: inc ecx
         // 004035ec: dec eax
         // 004035ed: jnz 0x4035e6
      [-]8a11881646414875f7
         // 004035f1: mov b1 dl, b1 ds:[ecx]
         // 004035f3: mov b1 ds:[esi], b1 dl
         // 004035f5: inc esi
         // 004035f6: inc ecx
         // 004035f7: dec eax
         // 004035f8: jnz 0x4035f1
      [-]0fb6014183f8100f8399000000
         // 004035fa: movzx eax, b1 ds:[ecx]
         // 004035fd: inc ecx
         // 004035fe: cmp eax, 0x10
         // 00403601: jnb 0x4036a0
      [-]0fb63903ff03ff8bd62bd7c1e8022bd081ea????????413b55100f82a0020000
         // 00403607: movzx edi, b1 ds:[ecx]
         // 0040360a: add edi, edi
         // 0040360c: add edi, edi
         // 0040360e: mov edx, esi
         // 00403610: sub edx, edi
         // 00403612: shr eax, b1 0x2
         // 00403615: sub edx, eax
         // 00403617: sub edx, 0x801
         // 0040361d: inc ecx
         // 0040361e: cmp edx, ss:[ebp+0x10]
         // 00403621: jb 0x4038c7
      [-]3bd60f8398020000
         // 00403627: cmp edx, esi
         // 00403629: jnb 0x4038c7
      [-]8b45082bc683f8030f8278020000
         // 0040362f: mov eax, ss:[ebp+0x8]
         // 00403632: sub eax, esi
         // 00403634: cmp eax, 0x3
         // 00403637: jb 0x4038b5
      [-]0fb60288060fb642018846018a520288560283c603eb03
         // 0040363d: movzx eax, b1 ds:[edx]
         // 00403640: mov b1 ds:[esi], b1 al
         // 00403642: movzx eax, b1 ds:[edx+0x1]
         // 00403646: mov b1 ds:[esi+0x1], b1 al
         // 00403649: mov b1 dl, b1 ds:[edx+0x2]
         // 0040364c: mov b1 ds:[esi+0x2], b1 dl
         // 0040364f: add esi, 0x3
         // 00403652: jmp 0x403657
      [-]0fb641fe83e0030f8417020000
         // 00403657: movzx eax, b1 ds:[ecx+0xfffffffffffffffe]
         // 0040365b: and eax, 0x3
         // 0040365e: jz 0x40387b
      [-]8b55082bd63bd00f8244020000
         // 00403664: mov edx, ss:[ebp+0x8]
         // 00403667: sub edx, esi
         // 00403669: cmp edx, eax
         // 0040366b: jb 0x4038b5
      [-]8bd32bd18d78033bd70f8203020000
         // 00403671: mov edx, ebx
         // 00403673: sub edx, ecx
         // 00403675: lea edi, ds:[eax+0x3]
         // 00403678: cmp edx, edi
         // 0040367a: jb 0x403883
      [-]8a118816464183f8017611
         // 00403680: mov b1 dl, b1 ds:[ecx]
         // 00403682: mov b1 ds:[esi], b1 dl
         // 00403684: inc esi
         // 00403685: inc ecx
         // 00403686: cmp eax, 0x1
         // 00403689: jbe 0x40369c
      [-]8a118816464183f8027606
         // 0040368b: mov b1 dl, b1 ds:[ecx]
         // 0040368d: mov b1 ds:[esi], b1 dl
         // 0040368f: inc esi
         // 00403690: inc ecx
         // 00403691: cmp eax, 0x2
         // 00403694: jbe 0x40369c
      [-]8a0188064641
         // 00403696: mov b1 al, b1 ds:[ecx]
         // 00403698: mov b1 ds:[esi], b1 al
         // 0040369a: inc esi
         // 0040369b: inc ecx
      [-]0fb60141
         // 0040369c: movzx eax, b1 ds:[ecx]
         // 0040369f: inc ecx
      [-]83f840725e
         // 004036a0: cmp eax, 0x40
         // 004036a3: jb 0x403703
      [-]8bd0c1ea0283e2078bfe2bfa0fb61103d203d203d22bfac1e8054f41483b7d100f82fc010000
         // 004036a5: mov edx, eax
         // 004036a7: shr edx, b1 0x2
         // 004036aa: and edx, 0x7
         // 004036ad: mov edi, esi
         // 004036af: sub edi, edx
         // 004036b1: movzx edx, b1 ds:[ecx]
         // 004036b4: add edx, edx
         // 004036b6: add edx, edx
         // 004036b8: add edx, edx
         // 004036ba: sub edi, edx
         // 004036bc: shr eax, b1 0x5
         // 004036bf: dec edi
         // 004036c0: inc ecx
         // 004036c1: dec eax
         // 004036c2: cmp edi, ss:[ebp+0x10]
         // 004036c5: jb 0x4038c7
      [-]3bfe0f83f4010000
         // 004036cb: cmp edi, esi
         // 004036cd: jnb 0x4038c7
      [-]8b55082bd68d58023bd30f82d2010000
         // 004036d3: mov edx, ss:[ebp+0x8]
         // 004036d6: sub edx, esi
         // 004036d8: lea ebx, ds:[eax+0x2]
         // 004036db: cmp edx, ebx
         // 004036dd: jb 0x4038b5
      [-]0fb61788160fb6570188560183c60283c702
         // 004036e3: movzx edx, b1 ds:[edi]
         // 004036e6: mov b1 ds:[esi], b1 dl
         // 004036e8: movzx edx, b1 ds:[edi+0x1]
         // 004036ec: mov b1 ds:[esi+0x1], b1 dl
         // 004036ef: add esi, 0x2
         // 004036f2: add edi, 0x2
      [-]8a17881646474875f7
         // 004036f5: mov b1 dl, b1 ds:[edi]
         // 004036f7: mov b1 ds:[esi], b1 dl
         // 004036f9: inc esi
         // 004036fa: inc edi
         // 004036fb: dec eax
         // 004036fc: jnz 0x4036f5
      [-]e951ffffff
         // 004036fe: jmp 0x403654
      [-]83f8207252
         // 00403703: cmp eax, 0x20
         // 00403706: jb 0x40375a
      [-]83e01f753a
         // 00403708: and eax, 0x1f
         // 0040370b: jnz 0x403747
      [-]38017523
         // 0040370d: cmp b1 ds:[ecx], b1 al
         // 0040370f: jnz 0x403734
      [-]05????????413d????????0f8793010000
         // 00403711: add eax, 0xff
         // 00403716: inc ecx
         // 00403717: cmp eax, 0xfffffffffffffe01
         // 0040371c: ja 0x4038b5
      [-]8bd32bd183fa010f8254010000
         // 00403722: mov edx, ebx
         // 00403724: sub edx, ecx
         // 00403726: cmp edx, 0x1
         // 00403729: jb 0x403883
      [-]80390074dd
         // 0040372f: cmp b1 ds:[ecx], b1 0x0
         // 00403732: jz 0x403711
      [-]0fb611412bd98d44101f83fb020f823c010000
         // 00403734: movzx edx, b1 ds:[ecx]
         // 00403737: inc ecx
         // 00403738: sub ebx, ecx
         // 0040373a: lea eax, ds:[eax+edx+0x1f]
         // 0040373e: cmp ebx, 0x2
         // 00403741: jb 0x403883
      [-]668b110fb7d2c1ea028d7eff2bfa83c102eb7a
         // 00403747: mov b2 dx, b2 ds:[ecx]
         // 0040374a: movzx edx, b2 dx
         // 0040374d: shr edx, b1 0x2
         // 00403750: lea edi, ds:[esi+0xffffffffffffffff]
         // 00403753: sub edi, edx
         // 00403755: add ecx, 0x2
         // 00403758: jmp 0x4037d4
      [-]83f8100f82dd000000
         // 0040375a: cmp eax, 0x10
         // 0040375d: jb 0x403840
      [-]8bd083e208c1e20b8bfe2bfa83e0077544
         // 00403763: mov edx, eax
         // 00403765: and edx, 0x8
         // 00403768: shl edx, b1 0xb
         // 0040376b: mov edi, esi
         // 0040376d: sub edi, edx
         // 0040376f: and eax, 0x7
         // 00403772: jnz 0x4037b8
      [-]3801752b
         // 00403774: cmp b1 ds:[ecx], b1 al
         // 00403776: jnz 0x4037a3
      [-]05????????413d????????0f8724010000
         // 00403780: add eax, 0xff
         // 00403785: inc ecx
         // 00403786: cmp eax, 0xfffffffffffffe01
         // 0040378b: ja 0x4038b5
      [-]8bd32bd183fa010f82e5000000
         // 00403791: mov edx, ebx
         // 00403793: sub edx, ecx
         // 00403795: cmp edx, 0x1
         // 00403798: jb 0x403883
      [-]80390074dd
         // 0040379e: cmp b1 ds:[ecx], b1 0x0
         // 004037a1: jz 0x403780
      [-]0fb6118d441007418bd32bd183fa020f82cb000000
         // 004037a3: movzx edx, b1 ds:[ecx]
         // 004037a6: lea eax, ds:[eax+edx+0x7]
         // 004037aa: inc ecx
         // 004037ab: mov edx, ebx
         // 004037ad: sub edx, ecx
         // 004037af: cmp edx, 0x2
         // 004037b2: jb 0x403883
      [-]668b110fb7d2c1ea022bfa83c1023bfe0f84c7000000
         // 004037b8: mov b2 dx, b2 ds:[ecx]
         // 004037bb: movzx edx, b2 dx
         // 004037be: shr edx, b1 0x2
         // 004037c1: sub edi, edx
         // 004037c3: add ecx, 0x2
         // 004037c6: cmp edi, esi
         // 004037c8: jz 0x403895
      [-]81ef????????
         // 004037ce: sub edi, 0x4000
      [-]3b7d100f82ea000000
         // 004037d4: cmp edi, ss:[ebp+0x10]
         // 004037d7: jb 0x4038c7
      [-]3bfe0f83e2000000
         // 004037dd: cmp edi, esi
         // 004037df: jnb 0x4038c7
      [-]8b55082bd68d58023bd30f82c0000000
         // 004037e5: mov edx, ss:[ebp+0x8]
         // 004037e8: sub edx, esi
         // 004037ea: lea ebx, ds:[eax+0x2]
         // 004037ed: cmp edx, ebx
         // 004037ef: jb 0x4038b5
      [-]83f8060f82e5feffff
         // 004037f5: cmp eax, 0x6
         // 004037f8: jb 0x4036e3
      [-]8bd62bd783fa040f8cd8feffff
         // 004037fe: mov edx, esi
         // 00403800: sub edx, edi
         // 00403802: cmp edx, 0x4
         // 00403805: jl 0x4036e3
      [-]8b17891683c60483c70483e802
         // 0040380b: mov edx, ds:[edi]
         // 0040380d: mov ds:[esi], edx
         // 0040380f: add esi, 0x4
         // 00403812: add edi, 0x4
         // 00403815: sub eax, 0x2
      [-]8b17891683e80483c60483c70483f80473ee
         // 00403818: mov edx, ds:[edi]
         // 0040381a: mov ds:[esi], edx
         // 0040381c: sub eax, 0x4
         // 0040381f: add esi, 0x4
         // 00403822: add edi, 0x4
         // 00403825: cmp eax, 0x4
         // 00403828: jnb 0x403818
      [-]85c00f8422feffff
         // 0040382a: test eax, eax
         // 0040382c: jz 0x403654
      [-]8a17881646474875f7
         // 00403832: mov b1 dl, b1 ds:[edi]
         // 00403834: mov b1 ds:[esi], b1 dl
         // 00403836: inc esi
         // 00403837: inc edi
         // 00403838: dec eax
         // 00403839: jnz 0x403832
      [-]e914feffff
         // 0040383b: jmp 0x403654
      [-]0fb63903ff03ff8bd62bd7c1e8022bd04a413b55100f826c000000
         // 00403840: movzx edi, b1 ds:[ecx]
         // 00403843: add edi, edi
         // 00403845: add edi, edi
         // 00403847: mov edx, esi
         // 00403849: sub edx, edi
         // 0040384b: shr eax, b1 0x2
         // 0040384e: sub edx, eax
         // 00403850: dec edx
         // 00403851: inc ecx
         // 00403852: cmp edx, ss:[ebp+0x10]
         // 00403855: jb 0x4038c7
      [-]3bd67368
         // 0040385b: cmp edx, esi
         // 0040385d: jnb 0x4038c7
      [-]8b45082bc683f802724c
         // 0040385f: mov eax, ss:[ebp+0x8]
         // 00403862: sub eax, esi
         // 00403864: cmp eax, 0x2
         // 00403867: jb 0x4038b5
      [-]8a0288068a520188560183c602e9dcfdffff
         // 00403869: mov b1 al, b1 ds:[edx]
         // 0040386b: mov b1 ds:[esi], b1 al
         // 0040386d: mov b1 dl, b1 ds:[edx+0x1]
         // 00403870: mov b1 ds:[esi+0x1], b1 dl
         // 00403873: add esi, 0x2
         // 00403876: jmp 0x403657
      [-]8b5508e9ccfcffff
         // 0040387b: mov edx, ss:[ebp+0x8]
         // 0040387e: jmp 0x40354f
      [-]2b75108b45145f89305eb8????????5b5dc3
         // 00403883: sub esi, ss:[ebp+0x10]
         // 00403886: mov eax, ss:[ebp+0x14]
         // 00403889: pop edi
         // 0040388a: mov ds:[eax], esi
         // 0040388c: pop esi
         // 0040388d: mov eax, 0xfffffffffffffffc
         // 00403892: pop ebx
         // 00403893: pop ebp
         // 00403894: retn 
      [-]2b75108b551489323bcb7507
         // 00403895: sub esi, ss:[ebp+0x10]
         // 00403898: mov edx, ss:[ebp+0x14]
         // 0040389b: mov ds:[edx], esi
         // 0040389d: cmp ecx, ebx
         // 0040389f: jnz 0x4038a8
      [-]5f5e33c05b5dc3
         // 004038a1: pop edi
         // 004038a2: pop esi
         // 004038a3: xor eax, eax
         // 004038a5: pop ebx
         // 004038a6: pop ebp
         // 004038a7: retn 
      [-]1bc05f83e0fc5e83c0fc5b5dc3
         // 004038a8: sbb eax, eax
         // 004038aa: pop edi
         // 004038ab: and eax, 0xfffffffffffffffc
         // 004038ae: pop esi
         // 004038af: add eax, 0xfffffffffffffffc
         // 004038b2: pop ebx
         // 004038b3: pop ebp
         // 004038b4: retn 
      [-]2b75108b45145f89305eb8????????5b5dc3
         // 004038b5: sub esi, ss:[ebp+0x10]
         // 004038b8: mov eax, ss:[ebp+0x14]
         // 004038bb: pop edi
         // 004038bc: mov ds:[eax], esi
         // 004038be: pop esi
         // 004038bf: mov eax, 0xfffffffffffffffb
         // 004038c4: pop ebx
         // 004038c5: pop ebp
         // 004038c6: retn 
      [-]2b75108b4d145f89315eb8????????5b5dc3
         // 004038c7: sub esi, ss:[ebp+0x10]
         // 004038ca: mov ecx, ss:[ebp+0x14]
         // 004038cd: pop edi
         // 004038ce: mov ds:[ecx], esi
         // 004038d0: pop esi
         // 004038d1: mov eax, 0xfffffffffffffffa
         // 004038d6: pop ebx
         // 004038d7: pop ebp
         // 004038d8: retn 
      [-]558bec53568b750833c95733c08d4900
         // 004038e0: push ebp
         // 004038e1: mov ebp, esp
         // 004038e3: push ebx
         // 004038e4: push esi
         // 004038e5: mov esi, ss:[ebp+0x8]
         // 004038e8: xor ecx, ecx
         // 004038ea: push edi
         // 004038eb: xor eax, eax
         // 004038ed: lea ecx, ds:[ecx+0x0]
      [-]880430403d????????7cf5
         // 004038f0: mov b1 ds:[eax+esi], b1 al
         // 004038f3: inc eax
         // 004038f4: cmp eax, 0x100
         // 004038f9: jl 0x4038f0
      [-]8b7d1066898e0001000032db
         // 004038fb: mov edi, ss:[ebp+0x10]
         // 004038fe: mov b2 ds:[esi+0x100], b2 cx
         // 00403905: xor b1 bl, b1 bl
      [-]8bc199f7ff8b450c410fb61402025431ff02da0fb65431ff0fb6c388550b0fb61430885431ff0fb6550b88143081f9????????7ccb
         // 00403907: mov eax, ecx
         // 00403909: cdq 
         // 0040390a: idiv edi
         // 0040390c: mov eax, ss:[ebp+0xc]
         // 0040390f: inc ecx
         // 00403910: movzx edx, b1 ds:[edx+eax]
         // 00403914: add b1 dl, b1 ds:[ecx+esi+0xffffffffffffffff]
         // 00403918: add b1 bl, b1 dl
         // 0040391a: movzx edx, b1 ds:[ecx+esi+0xffffffffffffffff]
         // 0040391f: movzx eax, b1 bl
         // 00403922: mov b1 ss:[ebp+0xb], b1 dl
         // 00403925: movzx edx, b1 ds:[eax+esi]
         // 00403929: mov b1 ds:[ecx+esi+0xffffffffffffffff], b1 dl
         // 0040392d: movzx edx, b1 ss:[ebp+0xb]
         // 00403931: mov b1 ds:[eax+esi], b1 dl
         // 00403934: cmp ecx, 0x100
         // 0040393a: jl 0x403907
      [-]5f5e5b5dc3
         // 0040393c: pop edi
         // 0040393d: pop esi
         // 0040393e: pop ebx
         // 0040393f: pop ebp
         // 00403940: retn 
      [-]558bec518b551485d20f8e7e000000
         // 00403950: push ebp
         // 00403951: mov ebp, esp
         // 00403953: push ecx
         // 00403954: mov edx, ss:[ebp+0x14]
         // 00403957: test edx, edx
         // 00403959: jle 0x4039dd
      [-]8b4d0c8b45085356578b7d102bcf894dfc895514b9????????eb06
         // 0040395f: mov ecx, ss:[ebp+0xc]
         // 00403962: mov eax, ss:[ebp+0x8]
         // 00403965: push ebx
         // 00403966: push esi
         // 00403967: push edi
         // 00403968: mov edi, ss:[ebp+0x10]
         // 0040396b: sub ecx, edi
         // 0040396d: mov ss:[ebp+0xfffffffffffffffc], ecx
         // 00403970: mov ss:[ebp+0x14], edx
         // 00403973: mov ecx, 0x1
         // 00403978: jmp 0x403980
      [-]0088000100000fb6b0000100000fb614060090010100000fb688010100008a1c018a1406881c068814010fb688010100000fb60c010fb69000010000020c020fb6d10fb60c028b55fc320c3a880fb9????????03f9294d1475a6
         // 00403980: add b1 ds:[eax+0x100], b1 cl
         // 00403986: movzx esi, b1 ds:[eax+0x100]
         // 0040398d: movzx edx, b1 ds:[esi+eax]
         // 00403991: add b1 ds:[eax+0x101], b1 dl
         // 00403997: movzx ecx, b1 ds:[eax+0x101]
         // 0040399e: mov b1 bl, b1 ds:[ecx+eax]
         // 004039a1: mov b1 dl, b1 ds:[esi+eax]
         // 004039a4: mov b1 ds:[esi+eax], b1 bl
         // 004039a7: mov b1 ds:[ecx+eax], b1 dl
         // 004039aa: movzx ecx, b1 ds:[eax+0x101]
         // 004039b1: movzx ecx, b1 ds:[ecx+eax]
         // 004039b5: movzx edx, b1 ds:[eax+0x100]
         // 004039bc: add b1 cl, b1 ds:[edx+eax]
         // 004039bf: movzx edx, b1 cl
         // 004039c2: movzx ecx, b1 ds:[edx+eax]
         // 004039c6: mov edx, ss:[ebp+0xfffffffffffffffc]
         // 004039c9: xor b1 cl, b1 ds:[edx+edi]
         // 004039cc: mov b1 ds:[edi], b1 cl
         // 004039ce: mov ecx, 0x1
         // 004039d3: add edi, ecx
         // 004039d5: sub ss:[ebp+0x14], ecx
         // 004039d8: jnz 0x403980
      [-]8be55dc3
         // 004039dd: mov esp, ebp
         // 004039df: pop ebp
         // 004039e0: retn 
      [-]c701b4124000e98d230000
         // 004039f0: mov ds:[ecx], ??_7bad_alloc@std@@6B@
         // 004039f6: jmp 0x405d88
      [-]558bec568bf1c706b4124000e877230000f64508017409
         // 00403a00: push ebp
         // 00403a01: mov ebp, esp
         // 00403a03: push esi
         // 00403a04: mov esi, ecx
         // 00403a06: mov ds:[esi], ??_7bad_alloc@std@@6B@
         // 00403a0c: call 0x405d88
         // 00403a11: test b1 ss:[ebp+0x8], b1 0x1
         // 00403a15: jz 0x403a20
      [-]56e87c22000083c404
         // 00403a17: push esi
         // 00403a18: call ??3@YAXPAX@Z
         // 00403a1d: add esp, 0x4
      [-]8bc65e5dc20400
         // 00403a20: mov eax, esi
         // 00403a22: pop esi
         // 00403a23: pop ebp
         // 00403a24: retn b2 0x4
      [-]558bec8b450856508bf1e87b230000c706b41240008bc65e5dc20400
         // 00403a30: push ebp
         // 00403a31: mov ebp, esp
         // 00403a33: mov eax, ss:[ebp+0x8]
         // 00403a36: push esi
         // 00403a37: push eax
         // 00403a38: mov esi, ecx
         // 00403a3a: call ??0exception@std@@QAE@ABV01@@Z
         // 00403a3f: mov ds:[esi], ??_7bad_alloc@std@@6B@
         // 00403a45: mov eax, esi
         // 00403a47: pop esi
         // 00403a48: pop ebp
         // 00403a49: retn b2 0x4
      [-]558bec8b45086844cf40008d4d0851894508e81a250000
         // 00403a50: push ebp
         // 00403a51: mov ebp, esp
         // 00403a53: mov eax, ss:[ebp+0x8]
         // 00403a56: push __TI1?AVCAtlException@ATL@@
         // 00403a5b: lea ecx, ss:[ebp+0x8]
         // 00403a5e: push ecx
         // 00403a5f: mov ss:[ebp+0x8], eax
         // 00403a62: call __CxxThrowException@8
      [-]ff150c10400085c07e0a
         // 00403a70: call ds:[GetLastError]
         // 00403a76: test eax, eax
         // 00403a78: jle 0x403a84
      [-]25????????0d????????
         // 00403a7a: and eax, 0xffff
         // 00403a7f: or eax, 0xffffffff80070000
      [-]50e8c6ffffff
         // 00403a84: push eax
         // 00403a85: call 0x403a50
      [-]558bec538b5d08578b7d0c5753ff151810400085c07504
         // 00403a90: push ebp
         // 00403a91: mov ebp, esp
         // 00403a93: push ebx
         // 00403a94: mov ebx, ss:[ebp+0x8]
         // 00403a97: push edi
         // 00403a98: mov edi, ss:[ebp+0xc]
         // 00403a9b: push edi
         // 00403a9c: push ebx
         // 00403a9d: call ds:[LoadResource]
         // 00403aa3: test eax, eax
         // 00403aa5: jnz 0x403aab
      [-]5f5b5dc3
         // 00403aa7: pop edi
         // 00403aa8: pop ebx
         // 00403aa9: pop ebp
         // 00403aaa: retn 
      [-]5650ff15141040008bf085f67429
         // 00403aab: push esi
         // 00403aac: push eax
         // 00403aad: call ds:[LockResource]
         // 00403ab3: mov esi, eax
         // 00403ab5: test esi, esi
         // 00403ab7: jz 0x403ae2
      [-]5753ff15101040008b4d1003c683e10f7613
         // 00403ab9: push edi
         // 00403aba: push ebx
         // 00403abb: call ds:[SizeofResource]
         // 00403ac1: mov ecx, ss:[ebp+0x10]
         // 00403ac4: add eax, esi
         // 00403ac6: and ecx, 0xf
         // 00403ac9: jbe 0x403ade
      [-]3bf0730e
         // 00403ad0: cmp esi, eax
         // 00403ad2: jnb 0x403ae2
      [-]490fb7168d74560275f2
         // 00403ad4: dec ecx
         // 00403ad5: movzx edx, b2 ds:[esi]
         // 00403ad8: lea esi, ds:[esi+edx*0x2]
         // 00403adc: jnz 0x403ad0
      [-]3bf07207
         // 00403ade: cmp esi, eax
         // 00403ae0: jb 0x403ae9
      [-]5e5f33c05b5dc3
         // 00403ae2: pop esi
         // 00403ae3: pop edi
         // 00403ae4: xor eax, eax
         // 00403ae6: pop ebx
         // 00403ae7: pop ebp
         // 00403ae8: retn 
      [-]0fb706f7d81bc023c65e5f5b5dc3
         // 00403ae9: movzx eax, b2 ds:[esi]
         // 00403aec: neg eax
         // 00403aee: sbb eax, eax
         // 00403af0: and eax, esi
         // 00403af2: pop esi
         // 00403af3: pop edi
         // 00403af4: pop ebx
         // 00403af5: pop ebp
         // 00403af6: retn 
      [-]558bec5153565733ff57b9????????e84f9000008bf0c745fc????????85f6744a
         // 00403b00: push ebp
         // 00403b01: mov ebp, esp
         // 00403b03: push ecx
         // 00403b04: push ebx
         // 00403b05: push esi
         // 00403b06: push edi
         // 00403b07: xor edi, edi
         // 00403b09: push edi
         // 00403b0a: mov ecx, 0x47d280
         // 00403b0f: call 0x40cb63
         // 00403b14: mov esi, eax
         // 00403b16: mov ss:[ebp+0xfffffffffffffffc], 0x1
         // 00403b1d: test esi, esi
         // 00403b1f: jz 0x403b6b
      [-]85ff7543
         // 00403b24: test edi, edi
         // 00403b26: jnz 0x403b6b
      [-]8b450c8bcbc1e90441500fb7d1526a0656ff152010400085c07411
         // 00403b28: mov eax, ss:[ebp+0xc]
         // 00403b2b: mov ecx, ebx
         // 00403b2d: shr ecx, b1 0x4
         // 00403b30: inc ecx
         // 00403b31: push eax
         // 00403b32: movzx edx, b2 cx
         // 00403b35: push edx
         // 00403b36: push 0x6
         // 00403b38: push esi
         // 00403b39: call ds:[FindResourceExW]
         // 00403b3f: test eax, eax
         // 00403b41: jz 0x403b54
      [-]535056e845ffffff8bf883c40c85ff7520
         // 00403b43: push ebx
         // 00403b44: push eax
         // 00403b45: push esi
         // 00403b46: call 0x403a90
         // 00403b4b: mov edi, eax
         // 00403b4d: add esp, 0xc
         // 00403b50: test edi, edi
         // 00403b52: jnz 0x403b74
      [-]8b45fc50b9????????e801900000ff45fc8bf085f675b9
         // 00403b54: mov eax, ss:[ebp+0xfffffffffffffffc]
         // 00403b57: push eax
         // 00403b58: mov ecx, 0x47d280
         // 00403b5d: call 0x40cb63
         // 00403b62: inc ss:[ebp+0xfffffffffffffffc]
         // 00403b65: mov esi, eax
         // 00403b67: test esi, esi
         // 00403b69: jnz 0x403b24
      [-]5f5e33c05b8be55dc3
         // 00403b6b: pop edi
         // 00403b6c: pop esi
         // 00403b6d: xor eax, eax
         // 00403b6f: pop ebx
         // 00403b70: mov esp, ebp
         // 00403b72: pop ebp
         // 00403b73: retn 
      [-]5f8bc65e5b8be55dc3
         // 00403b74: pop edi
         // 00403b75: mov eax, esi
         // 00403b77: pop esi
         // 00403b78: pop ebx
         // 00403b79: mov esp, ebp
         // 00403b7b: pop ebp
         // 00403b7c: retn 
      [-]558bec53568b75085785f60f84b4000000
         // 00403b80: push ebp
         // 00403b81: mov ebp, esp
         // 00403b83: push ebx
         // 00403b84: push esi
         // 00403b85: mov esi, ss:[ebp+0x8]
         // 00403b88: push edi
         // 00403b89: test esi, esi
         // 00403b8b: jz 0x403c45
      [-]8b5d1085db0f84a9000000
         // 00403b91: mov ebx, ss:[ebp+0x10]
         // 00403b94: test ebx, ebx
         // 00403b96: jz 0x403c45
      [-]8b7d1485ff0f849e000000
         // 00403b9c: mov edi, ss:[ebp+0x14]
         // 00403b9f: test edi, edi
         // 00403ba1: jz 0x403c45
      [-]8b4d0c8bc1992bc2d1f839070f8c8c000000
         // 00403ba7: mov ecx, ss:[ebp+0xc]
         // 00403baa: mov eax, ecx
         // 00403bac: cdq 
         // 00403bad: sub eax, edx
         // 00403baf: sar eax, b1 0x1
         // 00403bb1: cmp ds:[edi], eax
         // 00403bb3: jl 0x403c45
      [-]33ff897d083bcf7e71
         // 00403bb9: xor edi, edi
         // 00403bbb: mov ss:[ebp+0x8], edi
         // 00403bbe: cmp ecx, edi
         // 00403bc0: jle 0x403c33
      [-]8a068d48d080f909761f
         // 00403bc2: mov b1 al, b1 ds:[esi]
         // 00403bc4: lea ecx, ds:[eax+0xffffffffffffffd0]
         // 00403bc7: cmp b1 cl, b1 0x9
         // 00403bca: jbe 0x403beb
      [-]8d48bf80f9057706
         // 00403bcc: lea ecx, ds:[eax+0xffffffffffffffbf]
         // 00403bcf: cmp b1 cl, b1 0x5
         // 00403bd2: ja 0x403bda
      [-]2c378ac8eb11
         // 00403bd4: sub b1 al, b1 0x37
         // 00403bd6: mov b1 cl, b1 al
         // 00403bd8: jmp 0x403beb
      [-]8d509f80fa057706
         // 00403bda: lea edx, ds:[eax+0xffffffffffffff9f]
         // 00403bdd: cmp b1 dl, b1 0x5
         // 00403be0: ja 0x403be8
      [-]2c578ac8eb03
         // 00403be2: sub b1 al, b1 0x57
         // 00403be4: mov b1 cl, b1 al
         // 00403be6: jmp 0x403beb
      [-]8a46018d50d080fa097704
         // 00403beb: mov b1 al, b1 ds:[esi+0x1]
         // 00403bee: lea edx, ds:[eax+0xffffffffffffffd0]
         // 00403bf1: cmp b1 dl, b1 0x9
         // 00403bf4: ja 0x403bfa
      [-]8ac2eb1a
         // 00403bf6: mov b1 al, b1 dl
         // 00403bf8: jmp 0x403c14
      [-]8d50bf80fa057704
         // 00403bfa: lea edx, ds:[eax+0xffffffffffffffbf]
         // 00403bfd: cmp b1 dl, b1 0x5
         // 00403c00: ja 0x403c06
      [-]2c37eb0e
         // 00403c02: sub b1 al, b1 0x37
         // 00403c04: jmp 0x403c14
      [-]8d509f80fa057704
         // 00403c06: lea edx, ds:[eax+0xffffffffffffff9f]
         // 00403c09: cmp b1 dl, b1 0x5
         // 00403c0c: ja 0x403c12
      [-]2c57eb02
         // 00403c0e: sub b1 al, b1 0x57
         // 00403c10: jmp 0x403c14
      [-]83c60280f9ff7429
         // 00403c14: add esi, 0x2
         // 00403c17: cmp b1 cl, b1 0xff
         // 00403c1a: jz 0x403c45
      [-]3cff7425
         // 00403c1c: cmp b1 al, b1 0xff
         // 00403c1e: jz 0x403c45
      [-]ff4508c0e10402c8880b83c702433b7d0c7c8f
         // 00403c20: inc ss:[ebp+0x8]
         // 00403c23: shl b1 cl, b1 0x4
         // 00403c26: add b1 cl, b1 al
         // 00403c28: mov b1 ds:[ebx], b1 cl
         // 00403c2a: add edi, 0x2
         // 00403c2d: inc ebx
         // 00403c2e: cmp edi, ss:[ebp+0xc]
         // 00403c31: jl 0x403bc2
      [-]8b45148b4d085f5e8908b8????????5b5dc3
         // 00403c33: mov eax, ss:[ebp+0x14]
         // 00403c36: mov ecx, ss:[ebp+0x8]
         // 00403c39: pop edi
         // 00403c3a: pop esi
         // 00403c3b: mov ds:[eax], ecx
         // 00403c3d: mov eax, 0x1
         // 00403c42: pop ebx
         // 00403c43: pop ebp
         // 00403c44: retn 
      [-]5f5e33c05b5dc3
         // 00403c45: pop edi
         // 00403c46: pop esi
         // 00403c47: xor eax, eax
         // 00403c49: pop ebx
         // 00403c4a: pop ebp
         // 00403c4b: retn 
      [-]558bec568b75085785f6750a
         // 00403c50: push ebp
         // 00403c51: mov ebp, esp
         // 00403c53: push esi
         // 00403c54: mov esi, ss:[ebp+0x8]
         // 00403c57: push edi
         // 00403c58: test esi, esi
         // 00403c5a: jnz 0x403c66
      [-]68????????e8eafdffff
         // 00403c5c: push 0xffffffff80070057
         // 00403c61: call 0x403a50
      [-]8b4d0c85c9790a
         // 00403c66: mov ecx, ss:[ebp+0xc]
         // 00403c69: test ecx, ecx
         // 00403c6b: jns 0x403c77
      [-]68????????e8d9fdffff
         // 00403c6d: push 0xffffffff80070057
         // 00403c72: call 0x403a50
      [-]8b7d1085ff750a
         // 00403c77: mov edi, ss:[ebp+0x10]
         // 00403c7a: test edi, edi
         // 00403c7c: jnz 0x403c88
      [-]68????????e8c8fdffff
         // 00403c7e: push 0xffffffff80070057
         // 00403c83: call 0x403a50
      [-]8b063bc7743b
         // 00403c88: mov eax, ds:[esi]
         // 00403c8a: cmp eax, edi
         // 00403c8c: jz 0x403cc9
      [-]3b4d147e1a
         // 00403c8e: cmp ecx, ss:[ebp+0x14]
         // 00403c91: jle 0x403cad
      [-]6a015150e8f323000083c40c85c07536
         // 00403c93: push 0x1
         // 00403c95: push ecx
         // 00403c96: push eax
         // 00403c97: call __recalloc
         // 00403c9c: add esp, 0xc
         // 00403c9f: test eax, eax
         // 00403ca1: jnz 0x403cd9
      [-]68????????e8a3fdffff
         // 00403ca3: push 0xffffffff8007000e
         // 00403ca8: call 0x403a50
      [-]50e81422000083c404
         // 00403cad: push eax
         // 00403cae: call _free
         // 00403cb3: add esp, 0x4
      [-]833e005f5e751e
         // 00403cb8: cmp ds:[esi], 0x0
         // 00403cbb: pop edi
         // 00403cbc: pop esi
         // 00403cbd: jnz 0x403cdd
      [-]68????????e887fdffff
         // 00403cbf: push 0xffffffff8007000e
         // 00403cc4: call 0x403a50
      [-]3b4d147ee8
         // 00403cc9: cmp ecx, ss:[ebp+0x14]
         // 00403ccc: jle 0x403cb6
      [-]6a0151e87923000083c408
         // 00403cce: push 0x1
         // 00403cd0: push ecx
         // 00403cd1: call _calloc
         // 00403cd6: add esp, 0x8
      [-]8906ebdb
         // 00403cd9: mov ds:[esi], eax
         // 00403cdb: jmp 0x403cb8
      [-]558bec8b4508538bd985c07507
         // 00403ce0: push ebp
         // 00403ce1: mov ebp, esp
         // 00403ce3: mov eax, ss:[ebp+0x8]
         // 00403ce6: push ebx
         // 00403ce7: mov ebx, ecx
         // 00403ce9: test eax, eax
         // 00403ceb: jnz 0x403cf4
      [-]89035b5dc20800
         // 00403ced: mov ds:[ebx], eax
         // 00403cef: pop ebx
         // 00403cf0: pop ebp
         // 00403cf1: retn b2 0x8
      [-]565750ff152c1040008d780168????????8d4304508d34bd000000005653e839ffffff8b038b4d088b550c83c4106a006a00565057516a0052ff15281040008bf0f7de1bf6467462
         // 00403cf4: push esi
         // 00403cf5: push edi
         // 00403cf6: push eax
         // 00403cf7: call ds:[lstrlenW]
         // 00403cfd: lea edi, ds:[eax+0x1]
         // 00403d00: push 0x80
         // 00403d05: lea eax, ds:[ebx+0x4]
         // 00403d08: push eax
         // 00403d09: lea esi, ds:[edi*0x4]
         // 00403d10: push esi
         // 00403d11: push ebx
         // 00403d12: call 0x403c50
         // 00403d17: mov eax, ds:[ebx]
         // 00403d19: mov ecx, ss:[ebp+0x8]
         // 00403d1c: mov edx, ss:[ebp+0xc]
         // 00403d1f: add esp, 0x10
         // 00403d22: push 0x0
         // 00403d24: push 0x0
         // 00403d26: push esi
         // 00403d27: push eax
         // 00403d28: push edi
         // 00403d29: push ecx
         // 00403d2a: push 0x0
         // 00403d2c: push edx
         // 00403d2d: call ds:[WideCharToMultiByte]
         // 00403d33: mov esi, eax
         // 00403d35: neg esi
         // 00403d37: sbb esi, esi
         // 00403d39: inc esi
         // 00403d3a: jz 0x403d9e
      [-]ff150c10400083f87a754e
         // 00403d3c: call ds:[GetLastError]
         // 00403d42: cmp eax, 0x7a
         // 00403d45: jnz 0x403d95
      [-]8b45088b4d0c6a006a006a006a0057506a0051ff15281040008bf068????????8d4304505653e8defeffff8b138b45088b4d0c83c4106a006a00565257506a0051ff15281040008bf0f7de1bf646
         // 00403d47: mov eax, ss:[ebp+0x8]
         // 00403d4a: mov ecx, ss:[ebp+0xc]
         // 00403d4d: push 0x0
         // 00403d4f: push 0x0
         // 00403d51: push 0x0
         // 00403d53: push 0x0
         // 00403d55: push edi
         // 00403d56: push eax
         // 00403d57: push 0x0
         // 00403d59: push ecx
         // 00403d5a: call ds:[WideCharToMultiByte]
         // 00403d60: mov esi, eax
         // 00403d62: push 0x80
         // 00403d67: lea eax, ds:[ebx+0x4]
         // 00403d6a: push eax
         // 00403d6b: push esi
         // 00403d6c: push ebx
         // 00403d6d: call 0x403c50
         // 00403d72: mov edx, ds:[ebx]
         // 00403d74: mov eax, ss:[ebp+0x8]
         // 00403d77: mov ecx, ss:[ebp+0xc]
         // 00403d7a: add esp, 0x10
         // 00403d7d: push 0x0
         // 00403d7f: push 0x0
         // 00403d81: push esi
         // 00403d82: push edx
         // 00403d83: push edi
         // 00403d84: push eax
         // 00403d85: push 0x0
         // 00403d87: push ecx
         // 00403d88: call ds:[WideCharToMultiByte]
         // 00403d8e: mov esi, eax
         // 00403d90: neg esi
         // 00403d92: sbb esi, esi
         // 00403d94: inc esi
      [-]85f67405
         // 00403d95: test esi, esi
         // 00403d97: jz 0x403d9e
      [-]e8d2fcffff
         // 00403d99: call 0x403a70
      [-]5f5e5b5dc20800
         // 00403d9e: pop edi
         // 00403d9f: pop esi
         // 00403da0: pop ebx
         // 00403da1: pop ebp
         // 00403da2: retn b2 0x8
      [-]558bec8b4d0883ec0c33c085c9743a
         // 00403db0: push ebp
         // 00403db1: mov ebp, esp
         // 00403db3: mov ecx, ss:[ebp+0x8]
         // 00403db6: sub esp, 0xc
         // 00403db9: xor eax, eax
         // 00403dbb: test ecx, ecx
         // 00403dbd: jz 0x403df9
      [-]83f9ff770d
         // 00403dbf: cmp ecx, 0xffffffffffffffff
         // 00403dc2: ja 0x403dd1
      [-]51e83721000083c40485c07528
         // 00403dc4: push ecx
         // 00403dc5: call ??2@YAPAXI@Z
         // 00403dca: add esp, 0x4
         // 00403dcd: test eax, eax
         // 00403dcf: jnz 0x403df9
      [-]8d4508508d4df4c745????????00e8481f000068f0ce40008d4df451c745f4b4124000e888210000
         // 00403dd1: lea eax, ss:[ebp+0x8]
         // 00403dd4: push eax
         // 00403dd5: lea ecx, ss:[ebp+0xfffffffffffffff4]
         // 00403dd8: mov ss:[ebp+0x8], 0x0
         // 00403ddf: call ??0exception@std@@QAE@ABQBD@Z
         // 00403de4: push __TI2?AVbad_alloc@std@@
         // 00403de9: lea ecx, ss:[ebp+0xfffffffffffffff4]
         // 00403dec: push ecx
         // 00403ded: mov ss:[ebp+0xfffffffffffffff4], ??_7bad_alloc@std@@6B@
         // 00403df4: call __CxxThrowException@8
      [-]8be55dc20400
         // 00403df9: mov esp, ebp
         // 00403dfb: pop ebp
         // 00403dfc: retn b2 0x4
      [-]68????????e846fcffff
         // 00403e00: push 0xffffffff8007000e
         // 00403e05: call 0x403a50
      [-]558bec568b75085785f6750a
         // 00403e10: push ebp
         // 00403e11: mov ebp, esp
         // 00403e13: push esi
         // 00403e14: mov esi, ss:[ebp+0x8]
         // 00403e17: push edi
         // 00403e18: test esi, esi
         // 00403e1a: jnz 0x403e26
      [-]68????????e82afcffff
         // 00403e1c: push 0xffffffff80070057
         // 00403e21: call 0x403a50
      [-]8b4d0c85c9790a
         // 00403e26: mov ecx, ss:[ebp+0xc]
         // 00403e29: test ecx, ecx
         // 00403e2b: jns 0x403e37
      [-]68????????e819fcffff
         // 00403e2d: push 0xffffffff80070057
         // 00403e32: call 0x403a50
      [-]8b7d1085ff750a
         // 00403e37: mov edi, ss:[ebp+0x10]
         // 00403e3a: test edi, edi
         // 00403e3c: jnz 0x403e48
      [-]68????????e808fcffff
         // 00403e3e: push 0xffffffff80070057
         // 00403e43: call 0x403a50
      [-]8b063bc7743b
         // 00403e48: mov eax, ds:[esi]
         // 00403e4a: cmp eax, edi
         // 00403e4c: jz 0x403e89
      [-]3b4d147e1a
         // 00403e4e: cmp ecx, ss:[ebp+0x14]
         // 00403e51: jle 0x403e6d
      [-]6a025150e83322000083c40c85c07536
         // 00403e53: push 0x2
         // 00403e55: push ecx
         // 00403e56: push eax
         // 00403e57: call __recalloc
         // 00403e5c: add esp, 0xc
         // 00403e5f: test eax, eax
         // 00403e61: jnz 0x403e99
      [-]68????????e8e3fbffff
         // 00403e63: push 0xffffffff8007000e
         // 00403e68: call 0x403a50
      [-]50e85420000083c404
         // 00403e6d: push eax
         // 00403e6e: call _free
         // 00403e73: add esp, 0x4
      [-]833e005f5e751e
         // 00403e78: cmp ds:[esi], 0x0
         // 00403e7b: pop edi
         // 00403e7c: pop esi
         // 00403e7d: jnz 0x403e9d
      [-]68????????e8c7fbffff
         // 00403e7f: push 0xffffffff8007000e
         // 00403e84: call 0x403a50
      [-]3b4d147ee8
         // 00403e89: cmp ecx, ss:[ebp+0x14]
         // 00403e8c: jle 0x403e76
      [-]6a0251e8b921000083c408
         // 00403e8e: push 0x2
         // 00403e90: push ecx
         // 00403e91: call _calloc
         // 00403e96: add esp, 0x8
      [-]8906ebdb
         // 00403e99: mov ds:[esi], eax
         // 00403e9b: jmp 0x403e78
      [-]558bec8b45088b4d0c3bc1740e
         // 00403ea0: push ebp
         // 00403ea1: mov ebp, esp
         // 00403ea3: mov eax, ss:[ebp+0x8]
         // 00403ea6: mov ecx, ss:[ebp+0xc]
         // 00403ea9: cmp eax, ecx
         // 00403eab: jz 0x403ebb
      [-]568b7510
         // 00403ead: push esi
         // 00403eae: mov esi, ss:[ebp+0x10]
      [-]8a168810403bc175f7
         // 00403eb1: mov b1 dl, b1 ds:[esi]
         // 00403eb3: mov b1 ds:[eax], b1 dl
         // 00403eb5: inc eax
         // 00403eb6: cmp eax, ecx
         // 00403eb8: jnz 0x403eb1
      [-]568bf18b0e8379f4008d41f0578b38744e
         // 00403ec0: push esi
         // 00403ec1: mov esi, ecx
         // 00403ec3: mov ecx, ds:[esi]
         // 00403ec5: cmp ds:[ecx+0xfffffffffffffff4], 0x0
         // 00403ec9: lea eax, ds:[ecx+0xfffffffffffffff0]
         // 00403ecc: push edi
         // 00403ecd: mov edi, ds:[eax]
         // 00403ecf: jz 0x403f1f
      [-]83780c008d500c7d21
         // 00403ed1: cmp ds:[eax+0xc], 0x0
         // 00403ed5: lea edx, ds:[eax+0xc]
         // 00403ed8: jge 0x403efb
      [-]8379f8007d0a
         // 00403eda: cmp ds:[ecx+0xfffffffffffffff8], 0x0
         // 00403ede: jge 0x403eea
      [-]68????????e866fbffff
         // 00403ee0: push 0xffffffff80070057
         // 00403ee5: call 0x403a50
      [-]c741f4????????8b0633c95f6689085ec3
         // 00403eea: mov ds:[ecx+0xfffffffffffffff4], 0x0
         // 00403ef1: mov eax, ds:[esi]
         // 00403ef3: xor ecx, ecx
         // 00403ef5: pop edi
         // 00403ef6: mov b2 ds:[eax], b2 cx
         // 00403ef9: pop esi
         // 00403efa: retn 
      [-]83c9fff00fc10a4985c97f0a
         // 00403efb: or ecx, 0xffffffffffffffff
         // 00403efe: lock xadd ds:[edx], ecx
         // 00403f02: dec ecx
         // 00403f03: test ecx, ecx
         // 00403f05: jg 0x403f11
      [-]8b088b11508b4204ffd0
         // 00403f07: mov ecx, ds:[eax]
         // 00403f09: mov edx, ds:[ecx]
         // 00403f0b: push eax
         // 00403f0c: mov eax, ds:[edx+0x4]
         // 00403f0f: call eax
      [-]8b178b420c8bcfffd083c0108906
         // 00403f11: mov edx, ds:[edi]
         // 00403f13: mov eax, ds:[edx+0xc]
         // 00403f16: mov ecx, edi
         // 00403f18: call eax
         // 00403f1a: add eax, 0x10
         // 00403f1d: mov ds:[esi], eax
      [-]558bec53568b75088bd985f67508
         // 00403f30: push ebp
         // 00403f31: mov ebp, esp
         // 00403f33: push ebx
         // 00403f34: push esi
         // 00403f35: mov esi, ss:[ebp+0x8]
         // 00403f38: mov ebx, ecx
         // 00403f3a: test esi, esi
         // 00403f3c: jnz 0x403f46
      [-]89335e5b5dc20800
         // 00403f3e: mov ds:[ebx], esi
         // 00403f40: pop esi
         // 00403f41: pop ebx
         // 00403f42: pop ebp
         // 00403f43: retn b2 0x8
      [-]5756ff15341040008d780168????????8d4304505753e8affeffff8b038b4d0c83c410575057566a0051ff15301040008bf0f7de1bf646745a
         // 00403f46: push edi
         // 00403f47: push esi
         // 00403f48: call ds:[lstrlenA]
         // 00403f4e: lea edi, ds:[eax+0x1]
         // 00403f51: push 0x80
         // 00403f56: lea eax, ds:[ebx+0x4]
         // 00403f59: push eax
         // 00403f5a: push edi
         // 00403f5b: push ebx
         // 00403f5c: call 0x403e10
         // 00403f61: mov eax, ds:[ebx]
         // 00403f63: mov ecx, ss:[ebp+0xc]
         // 00403f66: add esp, 0x10
         // 00403f69: push edi
         // 00403f6a: push eax
         // 00403f6b: push edi
         // 00403f6c: push esi
         // 00403f6d: push 0x0
         // 00403f6f: push ecx
         // 00403f70: call ds:[MultiByteToWideChar]
         // 00403f76: mov esi, eax
         // 00403f78: neg esi
         // 00403f7a: sbb esi, esi
         // 00403f7c: inc esi
         // 00403f7d: jz 0x403fd9
      [-]ff150c10400083f87a7546
         // 00403f7f: call ds:[GetLastError]
         // 00403f85: cmp eax, 0x7a
         // 00403f88: jnz 0x403fd0
      [-]8b55088b450c6a006a0057526a0050ff15301040008bf068????????8d4304505653e85ffeffff8b0b8b55088b450c83c410565157526a0050ff15301040008bf0f7de1bf646
         // 00403f8a: mov edx, ss:[ebp+0x8]
         // 00403f8d: mov eax, ss:[ebp+0xc]
         // 00403f90: push 0x0
         // 00403f92: push 0x0
         // 00403f94: push edi
         // 00403f95: push edx
         // 00403f96: push 0x0
         // 00403f98: push eax
         // 00403f99: call ds:[MultiByteToWideChar]
         // 00403f9f: mov esi, eax
         // 00403fa1: push 0x80
         // 00403fa6: lea eax, ds:[ebx+0x4]
         // 00403fa9: push eax
         // 00403faa: push esi
         // 00403fab: push ebx
         // 00403fac: call 0x403e10
         // 00403fb1: mov ecx, ds:[ebx]
         // 00403fb3: mov edx, ss:[ebp+0x8]
         // 00403fb6: mov eax, ss:[ebp+0xc]
         // 00403fb9: add esp, 0x10
         // 00403fbc: push esi
         // 00403fbd: push ecx
         // 00403fbe: push edi
         // 00403fbf: push edx
         // 00403fc0: push 0x0
         // 00403fc2: push eax
         // 00403fc3: call ds:[MultiByteToWideChar]
         // 00403fc9: mov esi, eax
         // 00403fcb: neg esi
         // 00403fcd: sbb esi, esi
         // 00403fcf: inc esi
      [-]85f67405
         // 00403fd0: test esi, esi
         // 00403fd2: jz 0x403fd9
      [-]e897faffff
         // 00403fd4: call 0x403a70
      [-]5f5e5b5dc20800
         // 00403fd9: pop edi
         // 00403fda: pop esi
         // 00403fdb: pop ebx
         // 00403fdc: pop ebp
         // 00403fdd: retn b2 0x8
      [-]558bec5153568b318b5ef483ee10894dfc8b0e8b018b501057ffd28b4d088b108b126a02518bc8ffd28bf885ff7505
         // 00403fe0: push ebp
         // 00403fe1: mov ebp, esp
         // 00403fe3: push ecx
         // 00403fe4: push ebx
         // 00403fe5: push esi
         // 00403fe6: mov esi, ds:[ecx]
         // 00403fe8: mov ebx, ds:[esi+0xfffffffffffffff4]
         // 00403feb: sub esi, 0x10
         // 00403fee: mov ss:[ebp+0xfffffffffffffffc], ecx
         // 00403ff1: mov ecx, ds:[esi]
         // 00403ff3: mov eax, ds:[ecx]
         // 00403ff5: mov edx, ds:[eax+0x10]
         // 00403ff8: push edi
         // 00403ff9: call edx
         // 00403ffb: mov ecx, ss:[ebp+0x8]
         // 00403ffe: mov edx, ds:[eax]
         // 00404000: mov edx, ds:[edx]
         // 00404002: push 0x2
         // 00404004: push ecx
         // 00404005: mov ecx, eax
         // 00404007: call edx
         // 00404009: mov edi, eax
         // 0040400b: test edi, edi
         // 0040400d: jnz 0x404014
      [-]e8ecfdffff
         // 0040400f: call 0x403e00
      [-]8b45083bd87d02
         // 00404014: mov eax, ss:[ebp+0x8]
         // 00404017: cmp ebx, eax
         // 00404019: jge 0x40401d
      [-]8d440002508d5610528d4f105051894d08e8cc1d000083c410895f048d460c83c9fff00fc1084985c97f0a
         // 0040401d: lea eax, ds:[eax+eax+0x2]
         // 00404021: push eax
         // 00404022: lea edx, ds:[esi+0x10]
         // 00404025: push edx
         // 00404026: lea ecx, ds:[edi+0x10]
         // 00404029: push eax
         // 0040402a: push ecx
         // 0040402b: mov ss:[ebp+0x8], ecx
         // 0040402e: call _memcpy_s
         // 00404033: add esp, 0x10
         // 00404036: mov ds:[edi+0x4], ebx
         // 00404039: lea eax, ds:[esi+0xc]
         // 0040403c: or ecx, 0xffffffffffffffff
         // 0040403f: lock xadd ds:[eax], ecx
         // 00404043: dec ecx
         // 00404044: test ecx, ecx
         // 00404046: jg 0x404052
      [-]8b0e8b118b420456ffd0
         // 00404048: mov ecx, ds:[esi]
         // 0040404a: mov edx, ds:[ecx]
         // 0040404c: mov eax, ds:[edx+0x4]
         // 0040404f: push esi
         // 00404050: call eax
      [-]8b4d088b55fc5f5e890a5b8be55dc20400
         // 00404052: mov ecx, ss:[ebp+0x8]
         // 00404055: mov edx, ss:[ebp+0xfffffffffffffffc]
         // 00404058: pop edi
         // 00404059: pop esi
         // 0040405a: mov ds:[edx], ecx
         // 0040405c: pop ebx
         // 0040405d: mov esp, ebp
         // 0040405f: pop ebp
         // 00404060: retn b2 0x4
      [-]558bec8b5508568bf18b068b48f083e8103950087d15
         // 00404070: push ebp
         // 00404071: mov ebp, esp
         // 00404073: mov edx, ss:[ebp+0x8]
         // 00404076: push esi
         // 00404077: mov esi, ecx
         // 00404079: mov eax, ds:[esi]
         // 0040407b: mov ecx, ds:[eax+0xfffffffffffffff0]
         // 0040407e: sub eax, 0x10
         // 00404081: cmp ds:[eax+0x8], edx
         // 00404084: jge 0x40409b
      [-]85d27e11
         // 00404086: test edx, edx
         // 00404088: jle 0x40409b
      [-]578b396a0252508b4708ffd05f85c07505
         // 0040408a: push edi
         // 0040408b: mov edi, ds:[ecx]
         // 0040408d: push 0x2
         // 0040408f: push edx
         // 00404090: push eax
         // 00404091: mov eax, ds:[edi+0x8]
         // 00404094: call eax
         // 00404096: pop edi
         // 00404097: test eax, eax
         // 00404099: jnz 0x4040a0
      [-]e860fdffff
         // 0040409b: call 0x403e00
      [-]83c01089065e5dc20400
         // 004040a0: add eax, 0x10
         // 004040a3: mov ds:[esi], eax
         // 004040a5: pop esi
         // 004040a6: pop ebp
         // 004040a7: retn b2 0x4
      [-]568bf18b0e8379f4008d41f0578b38744c
         // 004040b0: push esi
         // 004040b1: mov esi, ecx
         // 004040b3: mov ecx, ds:[esi]
         // 004040b5: cmp ds:[ecx+0xfffffffffffffff4], 0x0
         // 004040b9: lea eax, ds:[ecx+0xfffffffffffffff0]
         // 004040bc: push edi
         // 004040bd: mov edi, ds:[eax]
         // 004040bf: jz 0x40410d
      [-]83780c008d500c7d1f
         // 004040c1: cmp ds:[eax+0xc], 0x0
         // 004040c5: lea edx, ds:[eax+0xc]
         // 004040c8: jge 0x4040e9
      [-]8379f8007d0a
         // 004040ca: cmp ds:[ecx+0xfffffffffffffff8], 0x0
         // 004040ce: jge 0x4040da
      [-]68????????e876f9ffff
         // 004040d0: push 0xffffffff80070057
         // 004040d5: call 0x403a50
      [-]c741f4????????8b065fc600005ec3
         // 004040da: mov ds:[ecx+0xfffffffffffffff4], 0x0
         // 004040e1: mov eax, ds:[esi]
         // 004040e3: pop edi
         // 004040e4: mov b1 ds:[eax], b1 0x0
         // 004040e7: pop esi
         // 004040e8: retn 
      [-]83c9fff00fc10a4985c97f0a
         // 004040e9: or ecx, 0xffffffffffffffff
         // 004040ec: lock xadd ds:[edx], ecx
         // 004040f0: dec ecx
         // 004040f1: test ecx, ecx
         // 004040f3: jg 0x4040ff
      [-]8b088b11508b4204ffd0
         // 004040f5: mov ecx, ds:[eax]
         // 004040f7: mov edx, ds:[ecx]
         // 004040f9: push eax
         // 004040fa: mov eax, ds:[edx+0x4]
         // 004040fd: call eax
      [-]8b178b420c8bcfffd083c0108906
         // 004040ff: mov edx, ds:[edi]
         // 00404101: mov eax, ds:[edx+0xc]
         // 00404104: mov ecx, edi
         // 00404106: call eax
         // 00404108: add eax, 0x10
         // 0040410b: mov ds:[esi], eax
      [-]558bec5153568b318b5ef483ee10894dfc8b0e8b018b501057ffd28b4d088b108b126a01518bc8ffd28bf885ff7505
         // 00404110: push ebp
         // 00404111: mov ebp, esp
         // 00404113: push ecx
         // 00404114: push ebx
         // 00404115: push esi
         // 00404116: mov esi, ds:[ecx]
         // 00404118: mov ebx, ds:[esi+0xfffffffffffffff4]
         // 0040411b: sub esi, 0x10
         // 0040411e: mov ss:[ebp+0xfffffffffffffffc], ecx
         // 00404121: mov ecx, ds:[esi]
         // 00404123: mov eax, ds:[ecx]
         // 00404125: mov edx, ds:[eax+0x10]
         // 00404128: push edi
         // 00404129: call edx
         // 0040412b: mov ecx, ss:[ebp+0x8]
         // 0040412e: mov edx, ds:[eax]
         // 00404130: mov edx, ds:[edx]
         // 00404132: push 0x1
         // 00404134: push ecx
         // 00404135: mov ecx, eax
         // 00404137: call edx
         // 00404139: mov edi, eax
         // 0040413b: test edi, edi
         // 0040413d: jnz 0x404144
      [-]e8bcfcffff
         // 0040413f: call 0x403e00
      [-]8b45083bd87d02
         // 00404144: mov eax, ss:[ebp+0x8]
         // 00404147: cmp ebx, eax
         // 00404149: jge 0x40414d
      [-]40508d5610528d4f105051894d08e89f1c000083c410895f048d460c83c9fff00fc1084985c97f0a
         // 0040414d: inc eax
         // 0040414e: push eax
         // 0040414f: lea edx, ds:[esi+0x10]
         // 00404152: push edx
         // 00404153: lea ecx, ds:[edi+0x10]
         // 00404156: push eax
         // 00404157: push ecx
         // 00404158: mov ss:[ebp+0x8], ecx
         // 0040415b: call _memcpy_s
         // 00404160: add esp, 0x10
         // 00404163: mov ds:[edi+0x4], ebx
         // 00404166: lea eax, ds:[esi+0xc]
         // 00404169: or ecx, 0xffffffffffffffff
         // 0040416c: lock xadd ds:[eax], ecx
         // 00404170: dec ecx
         // 00404171: test ecx, ecx
         // 00404173: jg 0x40417f
      [-]8b0e8b118b420456ffd0
         // 00404175: mov ecx, ds:[esi]
         // 00404177: mov edx, ds:[ecx]
         // 00404179: mov eax, ds:[edx+0x4]
         // 0040417c: push esi
         // 0040417d: call eax
      [-]8b4d088b55fc5f5e890a5b8be55dc20400
         // 0040417f: mov ecx, ss:[ebp+0x8]
         // 00404182: mov edx, ss:[ebp+0xfffffffffffffffc]
         // 00404185: pop edi
         // 00404186: pop esi
         // 00404187: mov ds:[edx], ecx
         // 00404189: pop ebx
         // 0040418a: mov esp, ebp
         // 0040418c: pop ebp
         // 0040418d: retn b2 0x4
      [-]558bec8b5508568bf18b068b48f083e8103950087d15
         // 00404190: push ebp
         // 00404191: mov ebp, esp
         // 00404193: mov edx, ss:[ebp+0x8]
         // 00404196: push esi
         // 00404197: mov esi, ecx
         // 00404199: mov eax, ds:[esi]
         // 0040419b: mov ecx, ds:[eax+0xfffffffffffffff0]
         // 0040419e: sub eax, 0x10
         // 004041a1: cmp ds:[eax+0x8], edx
         // 004041a4: jge 0x4041bb
      [-]85d27e11
         // 004041a6: test edx, edx
         // 004041a8: jle 0x4041bb
      [-]578b396a0152508b4708ffd05f85c07505
         // 004041aa: push edi
         // 004041ab: mov edi, ds:[ecx]
         // 004041ad: push 0x1
         // 004041af: push edx
         // 004041b0: push eax
         // 004041b1: mov eax, ds:[edi+0x8]
         // 004041b4: call eax
         // 004041b6: pop edi
         // 004041b7: test eax, eax
         // 004041b9: jnz 0x4041c0
      [-]e840fcffff
         // 004041bb: call 0x403e00
      [-]83c01089065e5dc20400
         // 004041c0: add eax, 0x10
         // 004041c3: mov ds:[esi], eax
         // 004041c5: pop esi
         // 004041c6: pop ebp
         // 004041c7: retn b2 0x4
      [-]558bec8b018b50f4578b7d083bd77e02
         // 004041d0: push ebp
         // 004041d1: mov ebp, esp
         // 004041d3: mov eax, ds:[ecx]
         // 004041d5: mov edx, ds:[eax+0xfffffffffffffff4]
         // 004041d8: push edi
         // 004041d9: mov edi, ss:[ebp+0x8]
         // 004041dc: cmp edx, edi
         // 004041de: jle 0x4041e2
      [-]8378fc017e0b
         // 004041e2: cmp ds:[eax+0xfffffffffffffffc], 0x1
         // 004041e6: jle 0x4041f3
      [-]57e8f2fdffff5f5dc20400
         // 004041e8: push edi
         // 004041e9: call 0x403fe0
         // 004041ee: pop edi
         // 004041ef: pop ebp
         // 004041f0: retn b2 0x4
      [-]8b40f83bc77d27
         // 004041f3: mov eax, ds:[eax+0xfffffffffffffff8]
         // 004041f6: cmp eax, edi
         // 004041f8: jge 0x404221
      [-]568bf081fe????????7e08
         // 004041fa: push esi
         // 004041fb: mov esi, eax
         // 004041fd: cmp esi, 0x40000000
         // 00404203: jle 0x40420d
      [-]81c6????????eb07
         // 00404205: add esi, 0x100000
         // 0040420b: jmp 0x404214
      [-]992bc2d1f803f0
         // 0040420d: cdq 
         // 0040420e: sub eax, edx
         // 00404210: sar eax, b1 0x1
         // 00404212: add esi, eax
      [-]3bf77d02
         // 00404214: cmp esi, edi
         // 00404216: jge 0x40421a
      [-]56e850feffff5e
         // 0040421a: push esi
         // 0040421b: call 0x404070
         // 00404220: pop esi
      [-]5f5dc20400
         // 00404221: pop edi
         // 00404222: pop ebp
         // 00404223: retn b2 0x4
      [-]558bec8b4508568bf183f8ff760a
         // 00404230: push ebp
         // 00404231: mov ebp, esp
         // 00404233: mov eax, ss:[ebp+0x8]
         // 00404236: push esi
         // 00404237: mov esi, ecx
         // 00404239: cmp eax, 0xffffffffffffffff
         // 0040423c: jbe 0x404248
      [-]68????????e81b860000
         // 0040423e: push 0x401268
         // 00404243: call ?_Xlength_error@std@@YAXPBD@Z
      [-]8b4e082b0e3bc87345
         // 00404248: mov ecx, ds:[esi+0x8]
         // 0040424b: sub ecx, ds:[esi]
         // 0040424d: cmp ecx, eax
         // 0040424f: jnb 0x404296
      [-]5357508d4e0ce854fbffff8b56048bf88b062bd0525057e8331600008b068b5e0483c40c2bd885c07409
         // 00404251: push ebx
         // 00404252: push edi
         // 00404253: push eax
         // 00404254: lea ecx, ds:[esi+0xc]
         // 00404257: call 0x403db0
         // 0040425c: mov edx, ds:[esi+0x4]
         // 0040425f: mov edi, eax
         // 00404261: mov eax, ds:[esi]
         // 00404263: sub edx, eax
         // 00404265: push edx
         // 00404266: push eax
         // 00404267: push edi
         // 00404268: call _memcpy_0
         // 0040426d: mov eax, ds:[esi]
         // 0040426f: mov ebx, ds:[esi+0x4]
         // 00404272: add esp, 0xc
         // 00404275: sub ebx, eax
         // 00404277: test eax, eax
         // 00404279: jz 0x404284
      [-]50e8181a000083c404
         // 0040427b: push eax
         // 0040427c: call ??3@YAXPAX@Z
         // 00404281: add esp, 0x4
      [-]8b450803df8d0c07893e5f895e04894e085b
         // 00404284: mov eax, ss:[ebp+0x8]
         // 00404287: add ebx, edi
         // 00404289: lea ecx, ds:[edi+eax]
         // 0040428c: mov ds:[esi], edi
         // 0040428e: pop edi
         // 0040428f: mov ds:[esi+0x4], ebx
         // 00404292: mov ds:[esi+0x8], ecx
         // 00404295: pop ebx
      [-]5e5dc20400
         // 00404296: pop esi
         // 00404297: pop ebp
         // 00404298: retn b2 0x4
      [-]558bec8b5508578b7d0c8bc78bca85ff740f
         // 004042a0: push ebp
         // 004042a1: mov ebp, esp
         // 004042a3: mov edx, ss:[ebp+0x8]
         // 004042a6: push edi
         // 004042a7: mov edi, ss:[ebp+0xc]
         // 004042aa: mov eax, edi
         // 004042ac: mov ecx, edx
         // 004042ae: test edi, edi
         // 004042b0: jz 0x4042c1
      [-]53568b7510
         // 004042b2: push ebx
         // 004042b3: push esi
         // 004042b4: mov esi, ss:[ebp+0x10]
      [-]8a1e8819414875f8
         // 004042b7: mov b1 bl, b1 ds:[esi]
         // 004042b9: mov b1 ds:[ecx], b1 bl
         // 004042bb: inc ecx
         // 004042bc: dec eax
         // 004042bd: jnz 0x4042b7
      [-]8d043a5f5dc20c00
         // 004042c1: lea eax, ds:[edx+edi]
         // 004042c4: pop edi
         // 004042c5: pop ebp
         // 004042c6: retn b2 0xc
      [-]558bec8b018b50f4578b7d083bd77e02
         // 004042d0: push ebp
         // 004042d1: mov ebp, esp
         // 004042d3: mov eax, ds:[ecx]
         // 004042d5: mov edx, ds:[eax+0xfffffffffffffff4]
         // 004042d8: push edi
         // 004042d9: mov edi, ss:[ebp+0x8]
         // 004042dc: cmp edx, edi
         // 004042de: jle 0x4042e2
      [-]8378fc017e0b
         // 004042e2: cmp ds:[eax+0xfffffffffffffffc], 0x1
         // 004042e6: jle 0x4042f3
      [-]57e822feffff5f5dc20400
         // 004042e8: push edi
         // 004042e9: call 0x404110
         // 004042ee: pop edi
         // 004042ef: pop ebp
         // 004042f0: retn b2 0x4
      [-]8b40f83bc77d27
         // 004042f3: mov eax, ds:[eax+0xfffffffffffffff8]
         // 004042f6: cmp eax, edi
         // 004042f8: jge 0x404321
      [-]568bf081fe????????7e08
         // 004042fa: push esi
         // 004042fb: mov esi, eax
         // 004042fd: cmp esi, 0x40000000
         // 00404303: jle 0x40430d
      [-]81c6????????eb07
         // 00404305: add esi, 0x100000
         // 0040430b: jmp 0x404314
      [-]992bc2d1f803f0
         // 0040430d: cdq 
         // 0040430e: sub eax, edx
         // 00404310: sar eax, b1 0x1
         // 00404312: add esi, eax
      [-]3bf77d02
         // 00404314: cmp esi, edi
         // 00404316: jge 0x40431a
      [-]56e870feffff5e
         // 0040431a: push esi
         // 0040431b: call 0x404190
         // 00404320: pop esi
      [-]5f5dc20400
         // 00404321: pop edi
         // 00404322: pop ebp
         // 00404323: retn b2 0x4
      [-]568bf18b0685c07409
         // 00404330: push esi
         // 00404331: mov esi, ecx
         // 00404333: mov eax, ds:[esi]
         // 00404335: test eax, eax
         // 00404337: jz 0x404342
      [-]50e85a19000083c404
         // 00404339: push eax
         // 0040433a: call ??3@YAXPAX@Z
         // 0040433f: add esp, 0x4
      [-]c706????????c746????????00c746????????005ec3
         // 00404342: mov ds:[esi], 0x0
         // 00404348: mov ds:[esi+0x4], 0x0
         // 0040434f: mov ds:[esi+0x8], 0x0
         // 00404356: pop esi
         // 00404357: retn 
      [-]558bec8b41048b5508568b315783cfff2bc62bfa3bf8730a
         // 00404360: push ebp
         // 00404361: mov ebp, esp
         // 00404363: mov eax, ds:[ecx+0x4]
         // 00404366: mov edx, ss:[ebp+0x8]
         // 00404369: push esi
         // 0040436a: mov esi, ds:[ecx]
         // 0040436c: push edi
         // 0040436d: or edi, 0xffffffffffffffff
         // 00404370: sub eax, esi
         // 00404372: sub edi, edx
         // 00404374: cmp edi, eax
         // 00404376: jnb 0x404382
      [-]68????????e8e1840000
         // 00404378: push 0x401268
         // 0040437d: call ?_Xlength_error@std@@YAXPBD@Z
      [-]03c28b51082bd63bc2761f
         // 00404382: add eax, edx
         // 00404384: mov edx, ds:[ecx+0x8]
         // 00404387: sub edx, esi
         // 00404389: cmp eax, edx
         // 0040438b: jbe 0x4043ac
      [-]8bf2d1ee83cfff2bfe3bfa7304
         // 0040438d: mov esi, edx
         // 0040438f: shr esi, b1 0x1
         // 00404391: or edi, 0xffffffffffffffff
         // 00404394: sub edi, esi
         // 00404396: cmp edi, edx
         // 00404398: jnb 0x40439e
      [-]33d2eb02
         // 0040439a: xor edx, edx
         // 0040439c: jmp 0x4043a0
      [-]3bd07302
         // 004043a0: cmp edx, eax
         // 004043a2: jnb 0x4043a6
      [-]52e884feffff
         // 004043a6: push edx
         // 004043a7: call 0x404230
      [-]5f5e5dc20400
         // 004043ac: pop edi
         // 004043ad: pop esi
         // 004043ae: pop ebp
         // 004043af: retn b2 0x4
      [-]558bec5156578b7d0c8bf185ff0f8470010000
         // 004043c0: push ebp
         // 004043c1: mov ebp, esp
         // 004043c3: push ecx
         // 004043c4: push esi
         // 004043c5: push edi
         // 004043c6: mov edi, ss:[ebp+0xc]
         // 004043c9: mov esi, ecx
         // 004043cb: test edi, edi
         // 004043cd: jz 0x404543
      [-]8b0e538b5e048bc12bc3483bc7730a
         // 004043d3: mov ecx, ds:[esi]
         // 004043d5: push ebx
         // 004043d6: mov ebx, ds:[esi+0x4]
         // 004043d9: mov eax, ecx
         // 004043db: sub eax, ebx
         // 004043dd: dec eax
         // 004043de: cmp eax, edi
         // 004043e0: jnb 0x4043ec
      [-]68????????e877840000
         // 004043e2: push 0x401268
         // 004043e7: call ?_Xlength_error@std@@YAXPBD@Z
      [-]8b46088bd32bd103d72bc13bc20f83a5000000
         // 004043ec: mov eax, ds:[esi+0x8]
         // 004043ef: mov edx, ebx
         // 004043f1: sub edx, ecx
         // 004043f3: add edx, edi
         // 004043f5: sub eax, ecx
         // 004043f7: cmp eax, edx
         // 004043f9: jnb 0x4044a4
      [-]8bc8d1e983cbff2bd93bd8730c
         // 004043ff: mov ecx, eax
         // 00404401: shr ecx, b1 0x1
         // 00404403: or ebx, 0xffffffffffffffff
         // 00404406: sub ebx, ecx
         // 00404408: cmp ebx, eax
         // 0040440a: jnb 0x404418
      [-]c745????????008b450ceb05
         // 0040440c: mov ss:[ebp+0xc], 0x0
         // 00404413: mov eax, ss:[ebp+0xc]
         // 00404416: jmp 0x40441d
      [-]03c189450c
         // 00404418: add eax, ecx
         // 0040441a: mov ss:[ebp+0xc], eax
      [-]3bc27305
         // 0040441d: cmp eax, edx
         // 0040441f: jnb 0x404426
      [-]89550c8bc2
         // 00404421: mov ss:[ebp+0xc], edx
         // 00404424: mov eax, edx
      [-]508d4e0ce881f9ffff8b4d088bd88bc12b068bd703c38945fc85ff740e
         // 00404426: push eax
         // 00404427: lea ecx, ds:[esi+0xc]
         // 0040442a: call 0x403db0
         // 0040442f: mov ecx, ss:[ebp+0x8]
         // 00404432: mov ebx, eax
         // 00404434: mov eax, ecx
         // 00404436: sub eax, ds:[esi]
         // 00404438: mov edx, edi
         // 0040443a: add eax, ebx
         // 0040443c: mov ss:[ebp+0xfffffffffffffffc], eax
         // 0040443f: test edi, edi
         // 00404441: jz 0x404451
      [-]8b4d108a098808404a75f5
         // 00404443: mov ecx, ss:[ebp+0x10]
         // 00404446: mov b1 cl, b1 ds:[ecx]
         // 00404448: mov b1 ds:[eax], b1 cl
         // 0040444a: inc eax
         // 0040444b: dec edx
         // 0040444c: jnz 0x404443
      [-]8b062bc8515053e8431400008b45088b56042bd052508b45fc03c750e82e1400008b068b4e042bc883c41803f985c07409
         // 00404451: mov eax, ds:[esi]
         // 00404453: sub ecx, eax
         // 00404455: push ecx
         // 00404456: push eax
         // 00404457: push ebx
         // 00404458: call _memcpy_0
         // 0040445d: mov eax, ss:[ebp+0x8]
         // 00404460: mov edx, ds:[esi+0x4]
         // 00404463: sub edx, eax
         // 00404465: push edx
         // 00404466: push eax
         // 00404467: mov eax, ss:[ebp+0xfffffffffffffffc]
         // 0040446a: add eax, edi
         // 0040446c: push eax
         // 0040446d: call _memcpy_0
         // 00404472: mov eax, ds:[esi]
         // 00404474: mov ecx, ds:[esi+0x4]
         // 00404477: sub ecx, eax
         // 00404479: add esp, 0x18
         // 0040447c: add edi, ecx
         // 0040447e: test eax, eax
         // 00404480: jz 0x40448b
      [-]50e81118000083c404
         // 00404482: push eax
         // 00404483: call ??3@YAXPAX@Z
         // 00404488: add esp, 0x4
      [-]8b550c8d043b03d3891e5b5f8956088946045e8be55dc20c00
         // 0040448b: mov edx, ss:[ebp+0xc]
         // 0040448e: lea eax, ds:[ebx+edi]
         // 00404491: add edx, ebx
         // 00404493: mov ds:[esi], ebx
         // 00404495: pop ebx
         // 00404496: pop edi
         // 00404497: mov ds:[esi+0x8], edx
         // 0040449a: mov ds:[esi+0x4], eax
         // 0040449d: pop esi
         // 0040449e: mov esp, ebp
         // 004044a0: pop ebp
         // 004044a1: retn b2 0xc
      [-]8b4d088b55108bc32bc13bc7734b
         // 004044a4: mov ecx, ss:[ebp+0x8]
         // 004044a7: mov edx, ss:[ebp+0x10]
         // 004044aa: mov eax, ebx
         // 004044ac: sub eax, ecx
         // 004044ae: cmp eax, edi
         // 004044b0: jnb 0x4044fd
      [-]8a12505103cf51885513e8df1300008b46048b550883c40c8d4d13512bd003d752508bcee8c5fdffff017e048b76048b4d088d4513502bf75651e8aff9ffff83c40c5b5f5e8be55dc20c00
         // 004044b2: mov b1 dl, b1 ds:[edx]
         // 004044b4: push eax
         // 004044b5: push ecx
         // 004044b6: add ecx, edi
         // 004044b8: push ecx
         // 004044b9: mov b1 ss:[ebp+0x13], b1 dl
         // 004044bc: call _memcpy_0
         // 004044c1: mov eax, ds:[esi+0x4]
         // 004044c4: mov edx, ss:[ebp+0x8]
         // 004044c7: add esp, 0xc
         // 004044ca: lea ecx, ss:[ebp+0x13]
         // 004044cd: push ecx
         // 004044ce: sub edx, eax
         // 004044d0: add edx, edi
         // 004044d2: push edx
         // 004044d3: push eax
         // 004044d4: mov ecx, esi
         // 004044d6: call 0x4042a0
         // 004044db: add ds:[esi+0x4], edi
         // 004044de: mov esi, ds:[esi+0x4]
         // 004044e1: mov ecx, ss:[ebp+0x8]
         // 004044e4: lea eax, ss:[ebp+0x13]
         // 004044e7: push eax
         // 004044e8: sub esi, edi
         // 004044ea: push esi
         // 004044eb: push ecx
         // 004044ec: call 0x403ea0
         // 004044f1: add esp, 0xc
         // 004044f4: pop ebx
         // 004044f5: pop edi
         // 004044f6: pop esi
         // 004044f7: mov esp, ebp
         // 004044f9: pop ebp
         // 004044fa: retn b2 0xc
      [-]8a028845138bc32bc78bcb2bc8515053894d0ce88b13000003450c8b4d088946048bc32bc12bc750512bd853e8721300008b45088d4d13518d14385250e861f9ffff83c4245b
         // 004044fd: mov b1 al, b1 ds:[edx]
         // 004044ff: mov b1 ss:[ebp+0x13], b1 al
         // 00404502: mov eax, ebx
         // 00404504: sub eax, edi
         // 00404506: mov ecx, ebx
         // 00404508: sub ecx, eax
         // 0040450a: push ecx
         // 0040450b: push eax
         // 0040450c: push ebx
         // 0040450d: mov ss:[ebp+0xc], ecx
         // 00404510: call _memcpy_0
         // 00404515: add eax, ss:[ebp+0xc]
         // 00404518: mov ecx, ss:[ebp+0x8]
         // 0040451b: mov ds:[esi+0x4], eax
         // 0040451e: mov eax, ebx
         // 00404520: sub eax, ecx
         // 00404522: sub eax, edi
         // 00404524: push eax
         // 00404525: push ecx
         // 00404526: sub ebx, eax
         // 00404528: push ebx
         // 00404529: call _memcpy_0
         // 0040452e: mov eax, ss:[ebp+0x8]
         // 00404531: lea ecx, ss:[ebp+0x13]
         // 00404534: push ecx
         // 00404535: lea edx, ds:[eax+edi]
         // 00404538: push edx
         // 00404539: push eax
         // 0040453a: call 0x403ea0
         // 0040453f: add esp, 0x24
         // 00404542: pop ebx
      [-]5f5e8be55dc20c00
         // 00404543: pop edi
         // 00404544: pop esi
         // 00404545: mov esp, ebp
         // 00404547: pop ebp
         // 00404548: retn b2 0xc
      [-]558bec568bf18b4e048b068bd1578b7d082bd03bd77623
         // 00404550: push ebp
         // 00404551: mov ebp, esp
         // 00404553: push esi
         // 00404554: mov esi, ecx
         // 00404556: mov ecx, ds:[esi+0x4]
         // 00404559: mov eax, ds:[esi]
         // 0040455b: mov edx, ecx
         // 0040455d: push edi
         // 0040455e: mov edi, ss:[ebp+0x8]
         // 00404561: sub edx, eax
         // 00404563: cmp edx, edi
         // 00404565: jbe 0x40458a
      [-]538d1c383bd97414
         // 00404567: push ebx
         // 00404568: lea ebx, ds:[eax+edi]
         // 0040456b: cmp ebx, ecx
         // 0040456d: jz 0x404583
      [-]8bf92bf9575153e82513000083c40c03fb897e04
         // 0040456f: mov edi, ecx
         // 00404571: sub edi, ecx
         // 00404573: push edi
         // 00404574: push ecx
         // 00404575: push ebx
         // 00404576: call _memcpy_0
         // 0040457b: add esp, 0xc
         // 0040457e: add edi, ebx
         // 00404580: mov ds:[esi+0x4], edi
      [-]5f5e5dc20400
         // 00404584: pop edi
         // 00404585: pop esi
         // 00404586: pop ebp
         // 00404587: retn b2 0x4
      [-]2bc103c7508bcee8c8fdffff8b4e048b062bc103c7740c
         // 0040458c: sub eax, ecx
         // 0040458e: add eax, edi
         // 00404590: push eax
         // 00404591: mov ecx, esi
         // 00404593: call 0x404360
         // 00404598: mov ecx, ds:[esi+0x4]
         // 0040459b: mov eax, ds:[esi]
         // 0040459d: sub eax, ecx
         // 0040459f: add eax, edi
         // 004045a1: jz 0x4045af
      [-]506a0051e86416000083c40c
         // 004045a3: push eax
         // 004045a4: push 0x0
         // 004045a6: push ecx
         // 004045a7: call _memset
         // 004045ac: add esp, 0xc
      [-]8b0603c75f8946045e5dc20400
         // 004045af: mov eax, ds:[esi]
         // 004045b1: add eax, edi
         // 004045b3: pop edi
         // 004045b4: mov ds:[esi+0x4], eax
         // 004045b7: pop esi
         // 004045b8: pop ebp
         // 004045b9: retn b2 0x4
      [-]558bec53568b750c8bd985f6750b
         // 004045c0: push ebp
         // 004045c1: mov ebp, esp
         // 004045c3: push ebx
         // 004045c4: push esi
         // 004045c5: mov esi, ss:[ebp+0xc]
         // 004045c8: mov ebx, ecx
         // 004045ca: test esi, esi
         // 004045cc: jnz 0x4045d9
      [-]e8ddfaffff5e5b5dc20800
         // 004045ce: call 0x4040b0
         // 004045d3: pop esi
         // 004045d4: pop ebx
         // 004045d5: pop ebp
         // 004045d6: retn b2 0x8
      [-]8b4d0885c9750a
         // 004045d9: mov ecx, ss:[ebp+0x8]
         // 004045dc: test ecx, ecx
         // 004045de: jnz 0x4045ea
      [-]68????????e866f4ffff
         // 004045e0: push 0xffffffff80070057
         // 004045e5: call 0x403a50
      [-]8b038b50f4578bf92bf889550c85f6790a
         // 004045ea: mov eax, ds:[ebx]
         // 004045ec: mov edx, ds:[eax+0xfffffffffffffff4]
         // 004045ef: push edi
         // 004045f0: mov edi, ecx
         // 004045f2: sub edi, eax
         // 004045f4: mov ss:[ebp+0xc], edx
         // 004045f7: test esi, esi
         // 004045f9: jns 0x404605
      [-]68????????e84bf4ffff
         // 004045fb: push 0xffffffff80070057
         // 00404600: call 0x403a50
      [-]ba????????2b50fc8b40f82bc60bd07d0b
         // 00404605: mov edx, 0x1
         // 0040460a: sub edx, ds:[eax+0xfffffffffffffffc]
         // 0040460d: mov eax, ds:[eax+0xfffffffffffffff8]
         // 00404610: sub eax, esi
         // 00404612: or edx, eax
         // 00404614: jge 0x404621
      [-]568bcbe8b2fcffff8b4d08
         // 00404616: push esi
         // 00404617: mov ecx, ebx
         // 00404619: call 0x4042d0
         // 0040461e: mov ecx, ss:[ebp+0x8]
      [-]8b03563b7d0c7710
         // 00404621: mov eax, ds:[ebx]
         // 00404623: push esi
         // 00404624: cmp edi, ss:[ebp+0xc]
         // 00404627: ja 0x404639
      [-]8b50f88d0c38515250e83d180000eb0b
         // 00404629: mov edx, ds:[eax+0xfffffffffffffff8]
         // 0040462c: lea ecx, ds:[eax+edi]
         // 0040462f: push ecx
         // 00404630: push edx
         // 00404631: push eax
         // 00404632: call _memmove_s
         // 00404637: jmp 0x404644
      [-]518b48f85150e8bb170000
         // 00404639: push ecx
         // 0040463a: mov ecx, ds:[eax+0xfffffffffffffff8]
         // 0040463d: push ecx
         // 0040463e: push eax
         // 0040463f: call _memcpy_s
      [-]8b0383c4105f3b70f87f91
         // 00404644: mov eax, ds:[ebx]
         // 00404646: add esp, 0x10
         // 00404649: pop edi
         // 0040464a: cmp esi, ds:[eax+0xfffffffffffffff8]
         // 0040464d: jg 0x4045e0
      [-]8970f48b13c60416005e5b5dc20800
         // 0040464f: mov ds:[eax+0xfffffffffffffff4], esi
         // 00404652: mov edx, ds:[ebx]
         // 00404654: mov b1 ds:[esi+edx], b1 0x0
         // 00404658: pop esi
         // 00404659: pop ebx
         // 0040465a: pop ebp
         // 0040465b: retn b2 0x8
      [-]558bec8b45085356576a006a00508bf1ff15241040008bf833db85ff7510
         // 00404660: push ebp
         // 00404661: mov ebp, esp
         // 00404663: mov eax, ss:[ebp+0x8]
         // 00404666: push ebx
         // 00404667: push esi
         // 00404668: push edi
         // 00404669: push 0x0
         // 0040466b: push 0x0
         // 0040466d: push eax
         // 0040466e: mov esi, ecx
         // 00404670: call ds:[GetEnvironmentVariableW]
         // 00404676: mov edi, eax
         // 00404678: xor ebx, ebx
         // 0040467a: test edi, edi
         // 0040467c: jnz 0x40468e
      [-]8bcee83bf8ffff5f5e8bc35b5dc20400
         // 0040467e: mov ecx, esi
         // 00404680: call 0x403ec0
         // 00404685: pop edi
         // 00404686: pop esi
         // 00404687: mov eax, ebx
         // 00404689: pop ebx
         // 0040468a: pop ebp
         // 0040468b: retn b2 0x4
      [-]68????????e8b6f3ffff
         // 00404690: push 0xffffffff80070057
         // 00404695: call 0x403a50
      [-]8b068b50f8b9????????2b48fc2bd70bca7d08
         // 0040469a: mov eax, ds:[esi]
         // 0040469c: mov edx, ds:[eax+0xfffffffffffffff8]
         // 0040469f: mov ecx, 0x1
         // 004046a4: sub ecx, ds:[eax+0xfffffffffffffffc]
         // 004046a7: sub edx, edi
         // 004046a9: or ecx, edx
         // 004046ab: jge 0x4046b5
      [-]578bcee81bfbffff
         // 004046ad: push edi
         // 004046ae: mov ecx, esi
         // 004046b0: call 0x4041d0
      [-]8b068b4d08575051ff15241040008b068b48f885c0740e
         // 004046b5: mov eax, ds:[esi]
         // 004046b7: mov ecx, ss:[ebp+0x8]
         // 004046ba: push edi
         // 004046bb: push eax
         // 004046bc: push ecx
         // 004046bd: call ds:[GetEnvironmentVariableW]
         // 004046c3: mov eax, ds:[esi]
         // 004046c5: mov ecx, ds:[eax+0xfffffffffffffff8]
         // 004046c8: test eax, eax
         // 004046ca: jz 0x4046da
      [-]5150e80c17000083c40885c078b6
         // 004046cc: push ecx
         // 004046cd: push eax
         // 004046ce: call _wcsnlen
         // 004046d3: add esp, 0x8
         // 004046d6: test eax, eax
         // 004046d8: js 0x404690
      [-]8b0e3b41f87faf
         // 004046da: mov ecx, ds:[esi]
         // 004046dc: cmp eax, ds:[ecx+0xfffffffffffffff8]
         // 004046df: jg 0x404690
      [-]8941f48b165f33c9bb????????66890c425e8bc35b5dc20400
         // 004046e1: mov ds:[ecx+0xfffffffffffffff4], eax
         // 004046e4: mov edx, ds:[esi]
         // 004046e6: pop edi
         // 004046e7: xor ecx, ecx
         // 004046e9: mov ebx, 0x1
         // 004046ee: mov b2 ds:[edx+eax*0x2], b2 cx
         // 004046f2: pop esi
         // 004046f3: mov eax, ebx
         // 004046f5: pop ebx
         // 004046f6: pop ebp
         // 004046f7: retn b2 0x4
      [-]558bec53568b750c8bc6c1e804578b7d08408bd90fb7c86a065157ff151c10400085c07411
         // 00404700: push ebp
         // 00404701: mov ebp, esp
         // 00404703: push ebx
         // 00404704: push esi
         // 00404705: mov esi, ss:[ebp+0xc]
         // 00404708: mov eax, esi
         // 0040470a: shr eax, b1 0x4
         // 0040470d: push edi
         // 0040470e: mov edi, ss:[ebp+0x8]
         // 00404711: inc eax
         // 00404712: mov ebx, ecx
         // 00404714: movzx ecx, b2 ax
         // 00404717: push 0x6
         // 00404719: push ecx
         // 0040471a: push edi
         // 0040471b: call ds:[FindResourceW]
         // 00404721: test eax, eax
         // 00404723: jz 0x404736
      [-]565057e863f3ffff8bf883c40c85ff7509
         // 00404725: push esi
         // 00404726: push eax
         // 00404727: push edi
         // 00404728: call 0x403a90
         // 0040472d: mov edi, eax
         // 0040472f: add esp, 0xc
         // 00404732: test edi, edi
         // 00404734: jnz 0x40473f
      [-]5f5e33c05b5dc20800
         // 00404736: pop edi
         // 00404737: pop esi
         // 00404738: xor eax, eax
         // 0040473a: pop ebx
         // 0040473b: pop ebp
         // 0040473c: retn b2 0x8
      [-]0fb7076a006a006a006a00508d4f02516a006a03894d0cff15281040008bf085f6790a
         // 0040473f: movzx eax, b2 ds:[edi]
         // 00404742: push 0x0
         // 00404744: push 0x0
         // 00404746: push 0x0
         // 00404748: push 0x0
         // 0040474a: push eax
         // 0040474b: lea ecx, ds:[edi+0x2]
         // 0040474e: push ecx
         // 0040474f: push 0x0
         // 00404751: push 0x3
         // 00404753: mov ss:[ebp+0xc], ecx
         // 00404756: call ds:[WideCharToMultiByte]
         // 0040475c: mov esi, eax
         // 0040475e: test esi, esi
         // 00404760: jns 0x40476c
      [-]68????????e8e4f2ffff
         // 00404762: push 0xffffffff80070057
         // 00404767: call 0x403a50
      [-]8b03ba????????2b50fc8b40f82bc60bd07d08
         // 0040476c: mov eax, ds:[ebx]
         // 0040476e: mov edx, 0x1
         // 00404773: sub edx, ds:[eax+0xfffffffffffffffc]
         // 00404776: mov eax, ds:[eax+0xfffffffffffffff8]
         // 00404779: sub eax, esi
         // 0040477b: or edx, eax
         // 0040477d: jge 0x404787
      [-]568bcbe849fbffff
         // 0040477f: push esi
         // 00404780: mov ecx, ebx
         // 00404782: call 0x4042d0
      [-]8b0b0fb7178b450c6a006a00565152506a006a03ff15281040008b033b70f87fba
         // 00404787: mov ecx, ds:[ebx]
         // 00404789: movzx edx, b2 ds:[edi]
         // 0040478c: mov eax, ss:[ebp+0xc]
         // 0040478f: push 0x0
         // 00404791: push 0x0
         // 00404793: push esi
         // 00404794: push ecx
         // 00404795: push edx
         // 00404796: push eax
         // 00404797: push 0x0
         // 00404799: push 0x3
         // 0040479b: call ds:[WideCharToMultiByte]
         // 004047a1: mov eax, ds:[ebx]
         // 004047a3: cmp esi, ds:[eax+0xfffffffffffffff8]
         // 004047a6: jg 0x404762
      [-]8970f48b0b5fc6040e005eb8????????5b5dc20800
         // 004047a8: mov ds:[eax+0xfffffffffffffff4], esi
         // 004047ab: mov ecx, ds:[ebx]
         // 004047ad: pop edi
         // 004047ae: mov b1 ds:[esi+ecx], b1 0x0
         // 004047b2: pop esi
         // 004047b3: mov eax, 0x1
         // 004047b8: pop ebx
         // 004047b9: pop ebp
         // 004047ba: retn b2 0x8
      [-]558bec81ec????????a150b6470033c58945fca1????????8b500c535657b9????????ffd283c01068????????8d8d????????8985????????e862feffff8b95????????85c00f84bc060000
         // 004047c0: push ebp
         // 004047c1: mov ebp, esp
         // 004047c3: sub esp, 0x7f0
         // 004047c9: mov eax, ds:[___security_cookie]
         // 004047ce: xor eax, ebp
         // 004047d0: mov ss:[ebp+0xfffffffffffffffc], eax
         // 004047d3: mov eax, ds:[0x47c470]
         // 004047d8: mov edx, ds:[eax+0xc]
         // 004047db: push ebx
         // 004047dc: push esi
         // 004047dd: push edi
         // 004047de: mov ecx, 0x47c470
         // 004047e3: call edx
         // 004047e5: add eax, 0x10
         // 004047e8: push 0x401240
         // 004047ed: lea ecx, ss:[ebp+0xfffffffffffff878]
         // 004047f3: mov ss:[ebp+0xfffffffffffff878], eax
         // 004047f9: call 0x404660
         // 004047fe: mov edx, ss:[ebp+0xfffffffffffff878]
         // 00404804: test eax, eax
         // 00404806: jz 0x404ec8
      [-]8bc28d7002
         // 0040480c: mov eax, edx
         // 0040480e: lea esi, ds:[eax+0x2]
      [-]668b0883c0026685c975f5
         // 00404811: mov b2 cx, b2 ds:[eax]
         // 00404814: add eax, 0x2
         // 00404817: test b2 cx, b2 cx
         // 0040481a: jnz 0x404811
      [-]2bc6d1f80f84a2060000
         // 0040481c: sub eax, esi
         // 0040481e: sar eax, b1 0x1
         // 00404820: jz 0x404ec8
      [-]52ff15641040006a0a6a016a00ff151c1040008bf085f60f84cf010000
         // 00404826: push edx
         // 00404827: call ds:[DeleteFileW]
         // 0040482d: push 0xa
         // 0040482f: push 0x1
         // 00404831: push 0x0
         // 00404833: call ds:[FindResourceW]
         // 00404839: mov esi, eax
         // 0040483b: test esi, esi
         // 0040483d: jz 0x404a12
      [-]566a00
         // 00404843: push esi
         // 00404844: push 0x0
         // 00404846: call ds:[SizeofResource]
         // 0040484c: mov ebx, eax
         // 0040484e: test ebx, ebx
         // 00404850: jz 0x404a12

  }
  condition:
    all of them
}
