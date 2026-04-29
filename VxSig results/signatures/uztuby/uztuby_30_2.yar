rule uztuby_30_2 {
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
      [-]84c07508
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
      [-]c701????????eb
         // 14000b0ee: mov b4 ds:[rcx], b4 0x3
         // 14000b0f4: jmp 0x14000b0e5
      [-]c701????????eb
         // 14000b0fb: mov b4 ds:[rcx], b4 0x2
         // 14000b101: jmp 0x14000b0e5
      [-]8079080075
         // 0040701e: cmp b1 ds:[ecx+0x8], b1 0x0
         // 00407022: jnz 0x40702b
      [-]000084c0
         // 0040a582: test b1 al, b1 al
      [-]01000083f8ff74
         // 0040a4ef: cmp eax, 0xffffffffffffffff
         // 0040a4f2: jz 0x40a4df
      [-]0085c075
         // 0040a698: test eax, eax
         // 0040a69a: jnz 0x40a6b0
      [-]0000008b
         // 0040cb03: mov ecx, esi
      [-]0085c074
         // 0040da67: test eax, eax
         // 0040da69: jz 0x40da6f
      [-]55565774
         // 0040ed1d: push ebp
         // 0040ed1e: push esi
         // 0040ed1f: push edi
         // 0040ed20: jz 0x40ed2c
      [-]0f83e00f8b
         // 0040f080: and eax, 0xf
         // 0040f083: mov edx, ds:[edx+ecx*0x4]
      [-]0783e10f83c00283
         // 0040f268: lea edi, ds:[eax+0x7]
         // 0040f26b: and ecx, 0xf
         // 0040f26e: add eax, 0x2
         // 0040f271: and edi, 0xf
      [-]0f83e00f8b
         // 0040fbc0: and eax, 0xf
         // 0040fbc6: mov ecx, ss:[esp+0x24]
      [-]105f5e5d
         // 0040fcd0: pop edi
         // 0040fcd1: pop esi
         // 0040fcd2: pop ebp
      [-]83f83f76
         // 14001bdf5: cmp rax, 0x3f
         // 14001bdf9: jbe 0x14001be55
      [-]ffff3d????????72
         // 00410c49: cmp eax, 0x600
         // 00410c4e: jb 0x410c7d
      [-]0083f80275
         // 14001e55f: cmp b4 eax, b4 0x2
         // 14001e562: jnz 0x14001e5bd
      [-]ffff3d????????
         // 14001dc3d: cmp b4 eax, b4 0x600
      [-]010f97c0888700010000
         // 14001172a: setnbe b1 al
         // 14001172f: mov b1 ds:[rdi+0x100], b1 al
      [-]0085c00f95c088
         // 004113de: test eax, eax
         // 004113e0: setnz b1 al
         // 004113e3: mov b1 ds:[esi+edi], b1 al
      [-]8308ffb8????????
         // 140026325: or b4 ds:[rax], b4 0xffffffffffffffff
         // 140026328: mov b4 eax, b4 0xffffffff80020006
      [-]0085c075
         // 00418c0e: test eax, eax
         // 00418c10: jnz 0x418c15
      [-]83c00283f82872
         // 1400271e6: add rax, 0x2
         // 1400271ea: cmp rax, 0x28
         // 1400271ee: jb 0x1400271d0
      [-]0000eb0a
         // 00419b75: jmp 0x419b81
      [-]000085c07403
         // 14001cd2d: test b4 eax, b4 eax
         // 14001cd2f: jz 0x14001cd34
      [-]00008bd0
         // 00419bb6: mov edx, eax
      [-]00000083f87d7d
         // 00419d21: cmp eax, 0x7d
         // 00419d24: jge 0x419d35
      [-]00000083f87d7d
         // 00419d2d: cmp eax, 0x7d
         // 00419d30: jge 0x419d35
      [-]000085c07403
         // 00419f01: test eax, eax
         // 00419f03: jz 0x419f08
      [-]ffff84c075
         // 00419f65: test b1 al, b1 al
         // 00419f67: jnz 0x419f7f
      [-]99f77c24
         // 00418f30: cdq 
         // 00418f31: idiv ss:[esp+0x20]
      [-]0085c074
         // 14001f718: test b4 eax, b4 eax
         // 14001f71a: jz 0x14001f760
      [-]ffff84c00f84
         // 0041d6a8: call 0x41a5c6
         // 0041d6ad: test b1 al, b1 al
         // 0041d6af: jz 0x41d786
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
         // 0041e6f3: xor edx, edx
         // 0041e6f5: mov ecx, eax
         // 0041e6f7: mov eax, ss:[ebp+0xc]
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
