rule wingo_10_0 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         f30f6f06f30f6f0ff30f6f5610f30f6f5f10f30f6f6620f30f6f6f20f30f6f7630f30f6f7f30660f74c1660f74d3660f74e5660f74f7660fdbc2660fdbe6660fdbc4660fd7d083c64083c74083eb4081fa????????74
         // 0040353a: movdqu b16 xmm0, b16 ds:[rsi]
         // 0040353e: movdqu b16 xmm1, b16 ds:[rdi]
         // 00403542: movdqu b16 xmm2, b16 ds:[rsi+0x10]
         // 00403547: movdqu b16 xmm3, b16 ds:[rdi+0x10]
         // 0040354c: movdqu b16 xmm4, b16 ds:[rsi+0x20]
         // 00403551: movdqu b16 xmm5, b16 ds:[rdi+0x20]
         // 00403556: movdqu b16 xmm6, b16 ds:[rsi+0x30]
         // 0040355b: movdqu b16 xmm7, b16 ds:[rdi+0x30]
         // 00403560: pcmpeqb b16 xmm0, b16 xmm1
         // 00403564: pcmpeqb b16 xmm2, b16 xmm3
         // 00403568: pcmpeqb b16 xmm4, b16 xmm5
         // 0040356c: pcmpeqb b16 xmm6, b16 xmm7
         // 00403570: pand b16 xmm0, b16 xmm2
         // 00403574: pand b16 xmm4, b16 xmm6
         // 00403578: pand b16 xmm0, b16 xmm4
         // 0040357c: pmovmskb b4 edx, b16 xmm0
         // 00403580: add rsi, 0x40
         // 00403584: add rdi, 0x40
         // 00403588: sub rbx, 0x40
         // 0040358c: cmp b4 edx, b4 0xffff
         // 00403592: jz 0x403530
      [-]8b0e8b1783c6
         // 004035f6: mov rcx, ds:[rsi]
         // 004035f9: mov rdx, ds:[rdi]
         // 004035fc: add rsi, 0x8
      [-]39d10f94
         // 0040361b: cmp rcx, rdx
         // 0040361e: setz b1 al
      [-]83fb0074
         // 00403622: cmp rbx, 0x0
         // 00403626: jz 0x40365f
      [-]8d0cdd00000000f7d9
         // 00403296: lea ecx, ds:[ebx*0x8]
         // 0040329d: neg ecx
      [-]29f7d3e7
         // 00403659: sub rdi, rsi
         // 0040365c: shl rdi, b1 cl
      [-]8b0881c1
         // 00469bfd: mov ecx, ds:[eax]
         // 00469bff: add ecx, 0xba0
      [-]83f8047d
         // 00469d17: cmp eax, 0x4
         // 00469d1a: jge 0x469d5a
      [-]046c657507
         // 0046f134: jnz 0x46f13d
      [-]04656d75
         // 0046f14b: jnz 0x46f154
      [-]48894c2424
         // 00471f12: mov ss:[rsp+0x38], rsi
         // 00471f1c: mov ss:[rsp+0x48], r9
         // 00471f21: mov ss:[rsp+0x50], r10
      [-]8b238b43
         // 00460fbd: mov esp, ds:[ebx]
         // 00460fbf: mov eax, ds:[ebx+0x10]
      [-]24897c24
         // 00461a72: mov ss:[rsp+0x8], rdi
      [-]04f30f70c000660f6fc8660fef05
         // 0046bfdb: pshufhw b16 xmm0, b16 xmm0, b1 0x0
         // 0046bfe0: movdqa b16 xmm1, b16 xmm0
         // 0046bfe4: pxor b16 xmm0, b16 ds:[0xf25de0]
      [-]00660f38dcc083
         // 0046bfec: aesenc b16 xmm0, b16 xmm0
         // 0046bff1: cmp ebx, 0x10
      [-]660f6fd1660f6fd9660fef
         // 0046ef4b: movdqa b16 xmm2, b16 xmm1
         // 0046ef4f: movdqa b16 xmm3, b16 xmm1
         // 0046ef53: pxor b16 xmm1, b16 ds:[0x5e81d0]
      [-]00660fef
         // 0046ef5b: pxor b16 xmm2, b16 ds:[0x5e81e0]
      [-]00660fef
         // 0046ef63: pxor b16 xmm3, b16 ds:[0x5e81f0]
      [-]00660f38dc
         // 0046ef6b: aesenc b16 xmm1, b16 xmm1
      [-]660f38dc
         // 0046ef70: aesenc b16 xmm2, b16 xmm2
      [-]660f38dc
         // 0046ef75: aesenc b16 xmm3, b16 xmm3
      [-]f30f6f00f30f6f4810f30f6f5020f30f6f5830660f38dc
         // 0046efaa: movdqu b16 xmm0, b16 ds:[eax]
         // 0046efae: movdqu b16 xmm1, b16 ds:[eax+0x10]
         // 0046efb3: movdqu b16 xmm2, b16 ds:[eax+0x20]
         // 0046efb8: movdqu b16 xmm3, b16 ds:[eax+0x30]
         // 0046efbd: aesenc b16 xmm4, b16 xmm0
      [-]660f38dc
         // 0046efc2: aesenc b16 xmm5, b16 xmm1
      [-]660f38dc
         // 0046efc7: aesenc b16 xmm6, b16 xmm2
      [-]660f38dc
         // 0046efcc: aesenc b16 xmm7, b16 xmm3
      [-]660f38dce4660f38dced660f38dcf6660f38dcff
         // 0046efd1: aesenc b16 xmm4, b16 xmm4
         // 0046efd6: aesenc b16 xmm5, b16 xmm5
         // 0046efdb: aesenc b16 xmm6, b16 xmm6
         // 0046efe0: aesenc b16 xmm7, b16 xmm7
      [-]660f38dc
         // 0046c1eb: aesenc b16 xmm4, b16 xmm4
      [-]660f38dc
         // 0046c1f0: aesenc b16 xmm5, b16 xmm5
      [-]660f38dc
         // 0046c1f5: aesenc b16 xmm6, b16 xmm6
      [-]660f38dc
         // 0046c1fa: aesenc b16 xmm7, b16 xmm7
      [-]660f38dce4660f38dced660f38dcf6660f38dcff660f38dc
         // 0046c1ff: aesenc b16 xmm4, b16 xmm4
         // 0046c204: aesenc b16 xmm5, b16 xmm5
         // 0046c209: aesenc b16 xmm6, b16 xmm6
         // 0046c20e: aesenc b16 xmm7, b16 xmm7
         // 0046c213: aesenc b16 xmm4, b16 xmm4
      [-]660f38dc
         // 0046c218: aesenc b16 xmm5, b16 xmm5
      [-]660f38dc
         // 0046c21d: aesenc b16 xmm6, b16 xmm6
      [-]660f38dc
         // 0046c222: aesenc b16 xmm7, b16 xmm7
      [-]8b1339d074
         // 00461559: mov edx, ds:[ebx]
         // 0046155b: cmp eax, edx
         // 0046155d: jz 0x4615a5
      [-]89fa8b3fffe7
         // 00458c5d: mov rdx, rdi
         // 00458c60: mov rdi, ds:[rdi]
         // 00458c63: jmp rdi
      [-]cccccccccccc
         // 00474059: int b1 0x3
         // 0047405a: int b1 0x3
         // 0047405b: int b1 0x3
         // 0047405c: int b1 0x3
         // 0047405d: int b1 0x3
         // 0047405e: int b1 0x3
      [-]ba????????e9
         // 00461650: mov edx, 0x0
         // 00461655: jmp runtime.morestack
      [-]89e7f3a48b
         // 0046363d: mov rdi, rsp
         // 00463640: rep movsbb 
         // 00463642: mov r12, ss:[rsp+0x2038]
      [-]89e601df01de29d9e8
         // 00463688: mov rsi, rsp
         // 0046368b: add rdi, rbx
         // 0046368e: add rsi, rbx
         // 00463691: sub rcx, rbx
         // 00463694: call callRet
      [-]ffff81c4
         // 004636a1: add rsp, 0x2008
      [-]89e7f3a48b
         // 00474ccb: mov rdi, rsp
         // 00474cce: rep movsbb 
         // 00474cd0: mov r12, ss:[rsp+0x4038]
      [-]89e601df01de29d9e8
         // 00474d16: mov rsi, rsp
         // 00474d19: add rdi, rbx
         // 00474d1c: add rsi, rbx
         // 00474d1f: sub rcx, rbx
         // 00474d22: call callRet
      [-]ffff81c4
         // 00474d27: add rsp, 0x4000
      [-]89e7f3a48b
         // 0046383d: mov rdi, rsp
         // 00463840: rep movsbb 
         // 00463842: mov r12, ss:[rsp+0x8038]
      [-]89e601df01de29d9e8
         // 00463888: mov rsi, rsp
         // 0046388b: add rdi, rbx
         // 0046388e: add rsi, rbx
         // 00463891: sub rcx, rbx
         // 00463894: call callRet
      [-]ffff81c4
         // 004638a1: add rsp, 0x8008
      [-]89e7f3a48b
         // 140075f2b: mov rdi, rsp
         // 140075f2e: rep movsbb 
         // 140075f30: mov r12, ss:[rsp+0x10038]
      [-]89e601df01de29d9e8
         // 140075f76: mov rsi, rsp
         // 140075f79: add rdi, rbx
         // 140075f7c: add rsi, rbx
         // 140075f7f: sub rcx, rbx
         // 140075f82: call callRet
      [-]ffff81c4
         // 140075f87: add rsp, 0x10000
      [-]89e7f3a48b
         // 00474f6b: mov rdi, rsp
         // 00474f6e: rep movsbb 
         // 00474f70: mov r12, ss:[rsp+0x20038]
      [-]89e601df01de29d9e8
         // 00474fb6: mov rsi, rsp
         // 00474fb9: add rdi, rbx
         // 00474fbc: add rsi, rbx
         // 00474fbf: sub rcx, rbx
         // 00474fc2: call callRet
      [-]ffff81c4
         // 00474fc7: add rsp, 0x20000
      [-]89e7f3a48b
         // 00463b3d: mov rdi, rsp
         // 00463b40: rep movsbb 
         // 00463b42: mov r12, ss:[rsp+0x40038]
      [-]89e601df01de29d9e8
         // 00463b88: mov rsi, rsp
         // 00463b8b: add rdi, rbx
         // 00463b8e: add rsi, rbx
         // 00463b91: sub rcx, rbx
         // 00463b94: call callRet
      [-]ffff81c4
         // 00463ba1: add rsp, 0x40008
      [-]89e7f3a48b
         // 00463c3d: mov rdi, rsp
         // 00463c40: rep movsbb 
         // 00463c42: mov r12, ss:[rsp+0x80038]
      [-]89e601df01de29d9e8
         // 00463c88: mov rsi, rsp
         // 00463c8b: add rdi, rbx
         // 00463c8e: add rsi, rbx
         // 00463c91: sub rcx, rbx
         // 00463c94: call callRet
      [-]ffff81c4
         // 00463ca1: add rsp, 0x80008
      [-]89e7f3a48b
         // 00463d3d: mov rdi, rsp
         // 00463d40: rep movsbb 
         // 00463d42: mov r12, ss:[rsp+0x100038]
      [-]89e601df01de29d9e8
         // 00463d88: mov rsi, rsp
         // 00463d8b: add rdi, rbx
         // 00463d8e: add rsi, rbx
         // 00463d91: sub rcx, rbx
         // 00463d94: call callRet
      [-]ffff81c4
         // 00463da1: add rsp, 0x100008
      [-]89e7f3a48b
         // 004752eb: mov rdi, rsp
         // 004752ee: rep movsbb 
         // 004752f0: mov r12, ss:[rsp+0x200038]
      [-]89e601df01de29d9e8
         // 00475336: mov rsi, rsp
         // 00475339: add rdi, rbx
         // 0047533c: add rsi, rbx
         // 0047533f: sub rcx, rbx
         // 00475342: call callRet
      [-]ffff81c4
         // 00475347: add rsp, 0x200000
      [-]89e7f3a48b
         // 004753cb: mov rdi, rsp
         // 004753ce: rep movsbb 
         // 004753d0: mov r12, ss:[rsp+0x400038]
      [-]89e601df01de29d9e8
         // 00475416: mov rsi, rsp
         // 00475419: add rdi, rbx
         // 0047541c: add rsi, rbx
         // 0047541f: sub rcx, rbx
         // 00475422: call callRet
      [-]ffff81c4
         // 00475427: add rsp, 0x400000
      [-]89e7f3a48b
         // 14007654b: mov rdi, rsp
         // 14007654e: rep movsbb 
         // 140076550: mov r12, ss:[rsp+0x800038]
      [-]89e601df01de29d9e8
         // 140076596: mov rsi, rsp
         // 140076599: add rdi, rbx
         // 14007659c: add rsi, rbx
         // 14007659f: sub rcx, rbx
         // 1400765a2: call callRet
      [-]ffff81c4
         // 1400765a7: add rsp, 0x800000
      [-]89e7f3a48b
         // 0046413d: mov rdi, rsp
         // 00464140: rep movsbb 
         // 00464142: mov r12, ss:[rsp+0x1000038]
      [-]89e601df01de29d9e8
         // 00464188: mov rsi, rsp
         // 0046418b: add rdi, rbx
         // 0046418e: add rsi, rbx
         // 00464191: sub rcx, rbx
         // 00464194: call callRet
      [-]ffff81c4
         // 004641a1: add rsp, 0x1000008
      [-]89e7f3a48b
         // 0046423d: mov rdi, rsp
         // 00464240: rep movsbb 
         // 00464242: mov r12, ss:[rsp+0x2000038]
      [-]89e601df01de29d9e8
         // 00464288: mov rsi, rsp
         // 0046428b: add rdi, rbx
         // 0046428e: add rsi, rbx
         // 00464291: sub rcx, rbx
         // 00464294: call callRet
      [-]ffff81c4
         // 004642a1: add rsp, 0x2000008
      [-]89e7f3a48b
         // 0046433d: mov rdi, rsp
         // 00464340: rep movsbb 
         // 00464342: mov r12, ss:[rsp+0x4000038]
      [-]89e601df01de29d9e8
         // 00464388: mov rsi, rsp
         // 0046438b: add rdi, rbx
         // 0046438e: add rsi, rbx
         // 00464391: sub rcx, rbx
         // 00464394: call callRet
      [-]ffff81c4
         // 004643a1: add rsp, 0x4000008
      [-]89e7f3a48b
         // 0046443d: mov rdi, rsp
         // 00464440: rep movsbb 
         // 00464442: mov r12, ss:[rsp+0x8000038]
      [-]89e601df01de29d9e8
         // 00464488: mov rsi, rsp
         // 0046448b: add rdi, rbx
         // 0046448e: add rsi, rbx
         // 00464491: sub rcx, rbx
         // 00464494: call callRet
      [-]ffff81c4
         // 004644a1: add rsp, 0x8000008
      [-]89e7f3a48b
         // 0046453d: mov rdi, rsp
         // 00464540: rep movsbb 
         // 00464542: mov r12, ss:[rsp+0x10000038]
      [-]89e601df01de29d9e8
         // 00464588: mov rsi, rsp
         // 0046458b: add rdi, rbx
         // 0046458e: add rsi, rbx
         // 00464591: sub rcx, rbx
         // 00464594: call callRet
      [-]ffff81c4
         // 004645a1: add rsp, 0x10000008
      [-]89e7f3a48b
         // 0046463d: mov rdi, rsp
         // 00464640: rep movsbb 
         // 00464642: mov r12, ss:[rsp+0x20000038]
      [-]89e601df01de29d9e8
         // 00464688: mov rsi, rsp
         // 0046468b: add rdi, rbx
         // 0046468e: add rsi, rbx
         // 00464691: sub rcx, rbx
         // 00464694: call callRet
      [-]ffff81c4
         // 004646a1: add rsp, 0x20000008
      [-]89e7f3a48b
         // 0046473d: mov rdi, rsp
         // 00464740: rep movsbb 
         // 00464742: mov r12, ss:[rsp+0x40000038]
      [-]89e601df01de29d9e8
         // 00464788: mov rsi, rsp
         // 0046478b: add rdi, rbx
         // 0046478e: add rsi, rbx
         // 00464791: sub rcx, rbx
         // 00464794: call callRet
      [-]ffff81c4
         // 004647a1: add rsp, 0x40000008
      [-]8904248966
         // 140076dba: mov ss:[rsp], rax
         // 140076dbe: mov ds:[rsi+0x38], rsp
      [-]894c2408
         // 140076df9: mov ss:[rsp+0x8], rcx
      [-]8b04248946
         // 140076e45: mov rax, ss:[rsp]
         // 140076e49: mov ds:[rsi+0x38], rax
      [-]85db0f84
         // 0045ba66: test rbx, rbx
         // 0045ba69: jz 0x45bc27
      [-]83fb400f86
         // 0045baa7: cmp rbx, 0x40
         // 0045baab: jbe 0x45bc52
      [-]10f30f7f
         // 00476b19: movdqu b16 ds:[rdi+0x20], b16 xmm15
      [-]20f30f7f
         // 00476b1f: movdqu b16 ds:[rdi+0x30], b16 xmm15
      [-]30f30f7f
         // 00476b25: movdqu b16 ds:[rdi+0x40], b16 xmm15
      [-]40f30f7f
         // 00476b2b: movdqu b16 ds:[rdi+0x50], b16 xmm15
      [-]50f30f7f
         // 00476b31: movdqu b16 ds:[rdi+0x60], b16 xmm15
      [-]60f30f7f
         // 00476b37: movdqu b16 ds:[rdi+0x70], b16 xmm15
      [-]70f30f7f
         // 00476b3d: movdqu b16 ds:[rdi+0x80], b16 xmm15
      [-]80000000f30f7f
         // 00476b46: movdqu b16 ds:[rdi+0x90], b16 xmm15
      [-]90000000f30f7f
         // 00476b4f: movdqu b16 ds:[rdi+0xa0], b16 xmm15
      [-]a0000000f30f7f
         // 00476b58: movdqu b16 ds:[rdi+0xb0], b16 xmm15
      [-]b0000000f30f7f
         // 00476b61: movdqu b16 ds:[rdi+0xc0], b16 xmm15
      [-]c0000000f30f7f
         // 00476b6a: movdqu b16 ds:[rdi+0xd0], b16 xmm15
      [-]d0000000f30f7f
         // 00476b73: movdqu b16 ds:[rdi+0xe0], b16 xmm15
      [-]e0000000f30f7f
         // 00476b7c: movdqu b16 ds:[rdi+0xf0], b16 xmm15
      [-]f000000081eb
         // 00476b85: sub rbx, 0x100
      [-]890789441f
         // 00476c9b: mov ds:[rdi], rax
         // 00476c9e: mov ds:[rdi+rbx+0xfffffffffffffff8], rax
      [-]10f30f7f
         // 00476cbc: movdqu b16 ds:[rdi+rbx+0xffffffffffffffe0], b16 xmm15
      [-]1fe0f30f7f
         // 00476cc3: movdqu b16 ds:[rdi+rbx+0xfffffffffffffff0], b16 xmm15
      [-]10f30f7f
         // 00476cd6: movdqu b16 ds:[rdi+0x20], b16 xmm15
      [-]20f30f7f
         // 00476cdc: movdqu b16 ds:[rdi+0x30], b16 xmm15
      [-]30f30f7f
         // 00476ce2: movdqu b16 ds:[rdi+rbx+0xffffffffffffffc0], b16 xmm15
      [-]1fc0f30f7f
         // 00476ce9: movdqu b16 ds:[rdi+rbx+0xffffffffffffffd0], b16 xmm15
      [-]1fd0f30f7f
         // 00476cf0: movdqu b16 ds:[rdi+rbx+0xffffffffffffffe0], b16 xmm15
      [-]1fe0f30f7f
         // 00476cf7: movdqu b16 ds:[rdi+rbx+0xfffffffffffffff0], b16 xmm15
      [-]10f30f7f
         // 00476d0a: movdqu b16 ds:[rdi+0x20], b16 xmm15
      [-]20f30f7f
         // 00476d10: movdqu b16 ds:[rdi+0x30], b16 xmm15
      [-]30f30f7f
         // 00476d16: movdqu b16 ds:[rdi+0x40], b16 xmm15
      [-]40f30f7f
         // 00476d1c: movdqu b16 ds:[rdi+0x50], b16 xmm15
      [-]50f30f7f
         // 00476d22: movdqu b16 ds:[rdi+0x60], b16 xmm15
      [-]60f30f7f
         // 00476d28: movdqu b16 ds:[rdi+0x70], b16 xmm15
      [-]70f30f7f
         // 00476d2e: movdqu b16 ds:[rdi+rbx+0xffffffffffffff80], b16 xmm15
      [-]1f80f30f7f
         // 00476d35: movdqu b16 ds:[rdi+rbx+0xffffffffffffff90], b16 xmm15
      [-]1f90f30f7f
         // 00476d3c: movdqu b16 ds:[rdi+rbx+0xffffffffffffffa0], b16 xmm15
      [-]1fa0f30f7f
         // 00476d43: movdqu b16 ds:[rdi+rbx+0xffffffffffffffb0], b16 xmm15
      [-]1fb0f30f7f
         // 00476d4a: movdqu b16 ds:[rdi+rbx+0xffffffffffffffc0], b16 xmm15
      [-]1fc0f30f7f
         // 00476d51: movdqu b16 ds:[rdi+rbx+0xffffffffffffffd0], b16 xmm15
      [-]1fd0f30f7f
         // 00476d58: movdqu b16 ds:[rdi+rbx+0xffffffffffffffe0], b16 xmm15
      [-]1fe0f30f7f
         // 00476d5f: movdqu b16 ds:[rdi+rbx+0xfffffffffffffff0], b16 xmm15
      [-]85db0f84
         // 0045bd29: test rbx, rbx
         // 0045bd2c: jz 0x45be29
      [-]83fb020f86
         // 0045bd32: cmp rbx, 0x2
         // 0045bd36: jbe 0x45be1c
      [-]83fb200f86
         // 0045bd66: cmp rbx, 0x20
         // 0045bd6a: jbe 0x45be61
      [-]83fb400f86
         // 0045bd70: cmp rbx, 0x40
         // 0045bd74: jbe 0x45be76
      [-]89f009f8a9
         // 00476e32: mov b4 eax, b4 esi
         // 00476e34: or b4 eax, b4 edi
         // 00476e36: test b4 eax, b4 0x7
      [-]89d9f3a4c3
         // 00476e3d: mov rcx, rbx
         // 00476e40: rep movsbb 
         // 00476e42: retn 
      [-]89f101d939f976
         // 0045bde0: mov rcx, rsi
         // 0045bde3: add rcx, rbx
         // 0045bde6: cmp rcx, rdi
         // 0045bde9: jbe 0x45bda6
      [-]01df01defd89d9c1e9
         // 0046e45d: add edi, ebx
         // 0046e45f: add esi, ebx
         // 0046e461: std 
         // 0046e462: mov ecx, ebx
         // 0046e464: shr ecx, b1 0x2
      [-]29df29dee9
         // 0046e479: sub edi, ebx
         // 0046e47b: sub esi, ebx
         // 0046e47d: jmp 0x46e3dc
      [-]8a068a4c1eff8807884c1fffc3
         // 00476ea0: mov b1 al, b1 ds:[rsi]
         // 00476ea2: mov b1 cl, b1 ds:[rsi+rbx+0xffffffffffffffff]
         // 00476ea6: mov b1 ds:[rdi], b1 al
         // 00476ea8: mov b1 ds:[rdi+rbx+0xffffffffffffffff], b1 cl
         // 00476eac: retn 
      [-]668b068a4e02668907884f02c3
         // 00476eb3: mov b2 ax, b2 ds:[rsi]
         // 00476eb6: mov b1 cl, b1 ds:[rsi+0x2]
         // 00476eb9: mov b2 ds:[rdi], b2 ax
         // 00476ebc: mov b1 ds:[rdi+0x2], b1 cl
         // 00476ebf: retn 
      [-]8b068907c3
         // 00476ecd: mov rax, ds:[rsi]
         // 00476ed0: mov ds:[rdi], rax
         // 00476ed3: retn 
      [-]8b068b4c1e
         // 00476ed4: mov rax, ds:[rsi]
         // 00476ed7: mov rcx, ds:[rsi+rbx+0xfffffffffffffff8]
      [-]8907894c1f
         // 00476edc: mov ds:[rdi], rax
         // 00476edf: mov ds:[rdi+rbx+0xfffffffffffffff8], rcx
      [-]f30f6f06f30f6f4c1ef0f30f7f07f30f7f4c1ff0c3
         // 00476ee5: movdqu b16 xmm0, b16 ds:[rsi]
         // 00476ee9: movdqu b16 xmm1, b16 ds:[rsi+rbx+0xfffffffffffffff0]
         // 00476eef: movdqu b16 ds:[rdi], b16 xmm0
         // 00476ef3: movdqu b16 ds:[rdi+rbx+0xfffffffffffffff0], b16 xmm1
         // 00476ef9: retn 
      [-]f30f6f06f30f6f4e10f30f6f541ee0f30f6f5c1ef0f30f7f07f30f7f4f10f30f7f541fe0f30f7f5c1ff0c3
         // 00476efa: movdqu b16 xmm0, b16 ds:[rsi]
         // 00476efe: movdqu b16 xmm1, b16 ds:[rsi+0x10]
         // 00476f03: movdqu b16 xmm2, b16 ds:[rsi+rbx+0xffffffffffffffe0]
         // 00476f09: movdqu b16 xmm3, b16 ds:[rsi+rbx+0xfffffffffffffff0]
         // 00476f0f: movdqu b16 ds:[rdi], b16 xmm0
         // 00476f13: movdqu b16 ds:[rdi+0x10], b16 xmm1
         // 00476f18: movdqu b16 ds:[rdi+rbx+0xffffffffffffffe0], b16 xmm2
         // 00476f1e: movdqu b16 ds:[rdi+rbx+0xfffffffffffffff0], b16 xmm3
         // 00476f24: retn 
      [-]f30f6f06f30f6f4e10f30f6f5620f30f6f5e30f30f6f641ec0f30f6f6c1ed0f30f6f741ee0f30f6f7c1ef0f30f7f07f30f7f4f10f30f7f5720f30f7f5f30f30f7f641fc0f30f7f6c1fd0f30f7f741fe0f30f7f7c1ff0c3
         // 00476f25: movdqu b16 xmm0, b16 ds:[rsi]
         // 00476f29: movdqu b16 xmm1, b16 ds:[rsi+0x10]
         // 00476f2e: movdqu b16 xmm2, b16 ds:[rsi+0x20]
         // 00476f33: movdqu b16 xmm3, b16 ds:[rsi+0x30]
         // 00476f38: movdqu b16 xmm4, b16 ds:[rsi+rbx+0xffffffffffffffc0]
         // 00476f3e: movdqu b16 xmm5, b16 ds:[rsi+rbx+0xffffffffffffffd0]
         // 00476f44: movdqu b16 xmm6, b16 ds:[rsi+rbx+0xffffffffffffffe0]
         // 00476f4a: movdqu b16 xmm7, b16 ds:[rsi+rbx+0xfffffffffffffff0]
         // 00476f50: movdqu b16 ds:[rdi], b16 xmm0
         // 00476f54: movdqu b16 ds:[rdi+0x10], b16 xmm1
         // 00476f59: movdqu b16 ds:[rdi+0x20], b16 xmm2
         // 00476f5e: movdqu b16 ds:[rdi+0x30], b16 xmm3
         // 00476f63: movdqu b16 ds:[rdi+rbx+0xffffffffffffffc0], b16 xmm4
         // 00476f69: movdqu b16 ds:[rdi+rbx+0xffffffffffffffd0], b16 xmm5
         // 00476f6f: movdqu b16 ds:[rdi+rbx+0xffffffffffffffe0], b16 xmm6
         // 00476f75: movdqu b16 ds:[rdi+rbx+0xfffffffffffffff0], b16 xmm7
         // 00476f7b: retn 
      [-]0f114424
         // 004712f2: movups b16 ss:[esp+0x1c], b16 xmm0
      [-]0f11bc24
         // 00471315: movups b16 ss:[esp+0x8c], b16 xmm7
      [-]0000000f
         // 0047132a: movups b16 xmm6, b16 ss:[esp+0x7c]
      [-]008d4424
         // 004714f6: lea eax, ss:[esp+0xc]
      [-]00894424
         // 00471502: mov ss:[esp+0x4], eax

  }
  condition:
    all of them
}
