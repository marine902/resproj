rule uztuby_10_2 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         0085c074
         // 00401345: test eax, eax
         // 00401347: jz 0x40137a
      [-]0085c074
         // 00401355: test eax, eax
         // 00401357: jz 0x40137a
      [-]000084c07508
         // 00406e2e: test b1 al, b1 al
         // 00406e30: jnz 0x406e3a
      [-]0a01eb02
         // 14000abee: jmp 0x14000abf2
      [-]83e80174
         // 14000b0c9: sub b4 r8d, b4 0x1
         // 14000b0cd: jz 0x14000b0f6
      [-]83e8017414
         // 14000b0cf: sub b4 r8d, b4 0x1
         // 14000b0d3: jz 0x14000b0e9
      [-]8339007502
         // 14000b0de: cmp b4 ds:[rcx], b4 0x0
         // 14000b0e1: jnz 0x14000b0e5
      [-]83390b74
         // 14000b0e9: cmp b4 ds:[rcx], b4 0xb
         // 14000b0ec: jz 0x14000b0e5
      [-]c701????????eb
         // 14000b0ee: mov b4 ds:[rcx], b4 0x3
         // 14000b0f4: jmp 0x14000b0e5
      [-]c701????????eb
         // 14000b0fb: mov b4 ds:[rcx], b4 0x2
         // 14000b101: jmp 0x14000b0e5
      [-]8079080075
         // 0040701e: cmp b1 ds:[ecx+0x8], b1 0x0
         // 00407022: jnz 0x40702b
      [-]0085c075
         // 140004fed: test b4 eax, b4 eax
         // 140004fef: jnz 0x14000504e
      [-]000084c074
         // 00409887: test b1 al, b1 al
         // 00409889: jz 0x4098a2
      [-]b8????????
         // 14001155d: mov b4 r8d, b4 0x4e20
      [-]ffffffeb
         // 140011573: jmp 0x1400115b2
      [-]83f86d7504
         // 140005020: cmp b4 eax, b4 0x6d
         // 140005023: jnz 0x140005029
      [-]bf????????
         // 14001158f: mov b4 edi, b4 0x8000
      [-]83f82175
         // 14000503f: cmp b4 eax, b4 0x21
         // 140005042: jnz 0x140005049
      [-]83c8ffeb
         // 1400115a9: or b4 eax, b4 0xffffffffffffffff
         // 1400115ac: jmp 0x1400115b2
      [-]000084c0
         // 0040a582: test b1 al, b1 al
      [-]01000083f8ff74
         // 0040a4ef: cmp eax, 0xffffffffffffffff
         // 0040a4f2: jz 0x40a4df
      [-]85c07403
         // 0040cf48: test eax, eax
         // 0040cf4a: jz 0x40cf4f
      [-]85c07403
         // 0040cf70: test eax, eax
         // 0040cf72: jz 0x40cf77
      [-]1bc083e0fe
         // 1400181a0: sbb b4 eax, b4 eax
         // 1400181a2: and b4 eax, b4 0xfffffffffffffffe
      [-]85c07403
         // 0040d73c: test eax, eax
         // 0040d73e: jz 0x40d743
      [-]1bc083e0fe
         // 14001827c: sbb b4 eax, b4 eax
         // 14001827e: and b4 eax, b4 0xfffffffffffffffe
      [-]558d6c24
         // 0040d8ec: push ebp
         // 0040d8ed: lea ebp, ss:[esp+0xffffffffffffff9c]
      [-]0000008b
         // 0040da4e: mov ecx, esi
      [-]83f80375
         // 0040ded3: cmp eax, 0x3
         // 0040ded6: jnz 0x40defc
      [-]85c00f84
         // 140018eeb: test rax, rax
         // 140018eee: jz 0x140018fca
      [-]0085c07404
         // 0040da67: test eax, eax
         // 0040da69: jz 0x40da6f
      [-]ffff84c074
         // 0040e380: test b1 al, b1 al
         // 0040e382: jz 0x40e395
      [-]ffff84c074
         // 0040dc88: test b1 al, b1 al
         // 0040dc8a: jz 0x40dc9b
      [-]55565774
         // 0040ed1d: push ebp
         // 0040ed1e: push esi
         // 0040ed1f: push edi
         // 0040ed20: jz 0x40ed2c
      [-]85d3feffff
      [-]8b442428
         // 0040f069: mov eax, ss:[esp+0x28]
      [-]0f83e00f8b
         // 0040f080: and eax, 0xf
         // 0040f086: mov ecx, ss:[esp+0x24]
      [-]8b442428
         // 0040f0c8: mov eax, ss:[esp+0x28]
      [-]8d48f883c0fe83
         // 0040f0d0: lea ecx, ds:[eax+0xfffffffffffffff8]
         // 0040f0d3: add eax, 0xfffffffffffffffe
         // 0040f0d6: and ecx, 0xf
      [-]8b442428894c24
         // 0040f121: mov eax, ss:[esp+0x28]
         // 0040f125: mov ss:[esp+0x1c], ecx
      [-]8d48f983e10f4883e00f8b
         // 0040f129: lea ecx, ds:[eax+0xfffffffffffffff9]
         // 0040f12c: and ecx, 0xf
         // 0040f12f: dec eax
         // 0040f130: and eax, 0xf
         // 0040f133: mov edx, ds:[edi+ecx*0x4]
      [-]83e10f8d
         // 0040f904: and ecx, 0xf
         // 0040f907: lea edx, ds:[esi+0x3]
      [-]288d48fd8d
         // 0040f9c6: lea ecx, ds:[eax+0xfffffffffffffffd]
         // 0040f9c9: lea edi, ds:[eax+0x7]
      [-]0783e10f83c00283
         // 0040f9cc: and ecx, 0xf
         // 0040f9cf: add eax, 0x2
         // 0040f9d2: and edi, 0xf
      [-]0f83e00f8b
         // 0040f9d5: and eax, 0xf
         // 0040f9d8: mov esi, ds:[edx+ecx*0x4]
      [-]4883e00f8b
         // 0040fa8a: dec eax
         // 0040fa8b: and eax, 0xf
         // 0040fa8e: mov esi, ss:[ebp+ecx*0x4]
      [-]89542428
         // 0040faea: mov ss:[esp+0x28], edx
      [-]8b442428
         // 0040f445: mov eax, ss:[esp+0x28]
      [-]0f83e00f8b
         // 0040f45f: and eax, 0xf
         // 0040f465: mov ecx, ss:[esp+0x24]
      [-]8d48f883c0fe83e00f83e10f8b
         // 0040f4ad: lea ecx, ds:[eax+0xfffffffffffffff8]
         // 0040f4b0: add eax, 0xfffffffffffffffe
         // 0040f4b3: and eax, 0xf
         // 0040f4b6: and ecx, 0xf
         // 0040f4b9: mov edx, ds:[ebx+ecx*0x4]
      [-]24288d48f983e10f4883e00f8b
         // 0040f4fa: mov eax, ss:[esp+0x28]
         // 0040f4fe: lea ecx, ds:[eax+0xfffffffffffffff9]
         // 0040f501: and ecx, 0xf
         // 0040f504: dec eax
         // 0040f505: and eax, 0xf
         // 0040f508: mov edx, ds:[ebx+ecx*0x4]
      [-]01700401
         // 0040f561: add ds:[eax+0x4], esi
         // 0040f564: add ds:[eax+0x8], ebp
      [-]105f5e5d
         // 0040f56c: add ds:[eax+0x10], edi
         // 0040f56f: pop edi
         // 0040f570: pop esi
         // 0040f571: pop ebp
      [-]83f83f76
         // 14001bdf5: cmp rax, 0x3f
         // 14001bdf9: jbe 0x14001be55
      [-]ffff3d????????72
         // 00410c49: cmp eax, 0x600
         // 00410c4e: jb 0x410c7d
      [-]0083f80275
         // 004104ed: cmp eax, 0x2
         // 004104f0: jnz 0x41051a
      [-]ffff3d????????
         // 14000f72d: cmp b4 eax, b4 0x600
      [-]010f97c0888700010000
         // 14001172a: setnbe b1 al
         // 14001172f: mov b1 ds:[rdi+0x100], b1 al
      [-]0085c00f95c088
         // 004113de: test eax, eax
         // 004113e0: setnz b1 al
         // 004113e3: mov b1 ds:[esi+edi], b1 al
      [-]0000008b
         // 00418a2f: mov ebx, eax
      [-]85c0782c
         // 14001b590: test b4 eax, b4 eax
         // 14001b592: js 0x14001b5c0
      [-]8308ffb8????????
         // 140026325: or b4 ds:[rax], b4 0xffffffffffffffff
         // 140026328: mov b4 eax, b4 0xffffffff80020006
      [-]0085c075
         // 00418c0e: test eax, eax
         // 00418c10: jnz 0x418c15
      [-]85c00f84
         // 00418fe0: test eax, eax
         // 00418fe2: jz 0x419092
      [-]83c00283f82872
         // 1400271e6: add rax, 0x2
         // 1400271ea: cmp rax, 0x28
         // 1400271ee: jb 0x1400271d0
      [-]85c0783d
         // 14001caae: test b4 eax, b4 eax
         // 14001cab0: js 0x14001caef
      [-]0000eb0a
         // 00419b75: jmp 0x419b81
      [-]000085c07403
         // 0041a458: test eax, eax
         // 0041a45a: jz 0x41a45f
      [-]00008bd0
         // 00419bb6: mov edx, eax
      [-]00000083f87d7d
         // 00419d21: cmp eax, 0x7d
         // 00419d24: jge 0x419d35
      [-]00000083f87d7d
         // 00419d2d: cmp eax, 0x7d
         // 00419d30: jge 0x419d35
      [-]008bf885
         // 00419e4c: mov edi, eax
         // 00419e4e: test edi, edi
      [-]0085c00f84
         // 14001d111: test rax, rax
         // 14001d114: jz 0x14001d1e2
      [-]000085c07403
         // 00419f01: test eax, eax
         // 00419f03: jz 0x419f08
      [-]ffff84c075
         // 00419f65: test b1 al, b1 al
         // 00419f67: jnz 0x419f7f
      [-]020000e9
         // 00419f7a: jmp 0x41a1df
      [-]99f77c24
         // 1400288c3: cdq 
         // 1400288c4: idiv b4 ss:[rsp+0x64]
      [-]0085c074
         // 14001f718: test b4 eax, b4 eax
         // 14001f71a: jz 0x14001f760
      [-]0085c075
         // 0041b5a4: test eax, eax
         // 0041b5a6: jnz 0x41b5bc
      [-]ffff84c074
         // 0041ae3d: test b1 al, b1 al
         // 0041ae3f: jz 0x41ae80
      [-]ffff84c00f84
         // 0041cd3d: test b1 al, b1 al
         // 0041cd3f: jz 0x41ce16
      [-]1f3c0e75
         // 0041cd9f: and eax, 0x1f
         // 0041cda2: cmp b1 al, b1 0xe
         // 0041cda4: jnz 0x41cdfa
      [-]0001c605
         // 140024130: mov b1 cs:[0x140070722], b1 0x1
      [-]0001ff15
         // 140024137: call cs:[ShowWindow]
      [-]00007409
         // 14002415d: jz 0x140024168
      [-]0085c074
         // 0041d312: test eax, eax
         // 0041d314: jz 0x41d337
      [-]85c07e0a
         // 0041d86c: test eax, eax
         // 0041d86e: jle 0x41d87a
      [-]85c07902
         // 14003045f: test b4 eax, b4 eax
         // 140030461: jns 0x140030465
      [-]0085c07505
         // 0041dd89: test eax, eax
         // 0041dd8b: jnz 0x41dd92
      [-]33d28bc88b
         // 140030efd: xor b4 edx, b4 edx
         // 140030eff: mov rcx, rax
         // 140030f02: mov rax, rdi
      [-]ffffff8b
         // 0041de7c: mov esi, eax
      [-]0085c07505
         // 0041dec7: test eax, eax
         // 0041dec9: jnz 0x41ded0
      [-]85c07505
         // 004279e0: test eax, eax
         // 004279e2: jnz 0x4279e9
      [-]83cfffeb
         // 14003e10c: or b4 edi, b4 0xffffffffffffffff
         // 14003e10f: jmp 0x14003e11f
      [-]00b001c3
         // 0042b737: mov b1 al, b1 0x1
         // 0042b739: retn 

  }
  condition:
    all of them
}
