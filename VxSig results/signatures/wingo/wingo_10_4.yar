rule wingo_10_4 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         f30f6f06f30f6f0ff30f6f5610f30f6f5f10f30f6f6620f30f6f6f20f30f6f7630f30f6f7f30660f74c1660f74d3660f74e5660f74f7660fdbc2660fdbe6660fdbc4660fd7d083c64083c74083eb4081fa????????74
         // 00402487: movdqu b16 xmm0, b16 ds:[rsi]
         // 0040248b: movdqu b16 xmm1, b16 ds:[rdi]
         // 0040248f: movdqu b16 xmm2, b16 ds:[rsi+0x10]
         // 00402494: movdqu b16 xmm3, b16 ds:[rdi+0x10]
         // 00402499: movdqu b16 xmm4, b16 ds:[rsi+0x20]
         // 0040249e: movdqu b16 xmm5, b16 ds:[rdi+0x20]
         // 004024a3: movdqu b16 xmm6, b16 ds:[rsi+0x30]
         // 004024a8: movdqu b16 xmm7, b16 ds:[rdi+0x30]
         // 004024ad: pcmpeqb b16 xmm0, b16 xmm1
         // 004024b1: pcmpeqb b16 xmm2, b16 xmm3
         // 004024b5: pcmpeqb b16 xmm4, b16 xmm5
         // 004024b9: pcmpeqb b16 xmm6, b16 xmm7
         // 004024bd: pand b16 xmm0, b16 xmm2
         // 004024c1: pand b16 xmm4, b16 xmm6
         // 004024c5: pand b16 xmm0, b16 xmm4
         // 004024c9: pmovmskb b4 edx, b16 xmm0
         // 004024cd: add rsi, 0x40
         // 004024d1: add rdi, 0x40
         // 004024d5: sub rbx, 0x40
         // 004024d9: cmp b4 edx, b4 0xffff
         // 004024df: jz 0x40247d
      [-]8b0e8b1783c6
         // 00402531: mov rcx, ds:[rsi]
         // 00402534: mov rdx, ds:[rdi]
         // 00402537: add rsi, 0x8
      [-]39d10f94
         // 00402556: cmp rcx, rdx
         // 00402559: setz b1 al
      [-]83fb0074
         // 0040255d: cmp rbx, 0x0
         // 00402561: jz 0x40259a
      [-]8d0cdd00000000f7d9
         // 00402563: lea rcx, ds:[rbx*0x8]
         // 0040256b: neg rcx
      [-]29f7d3e7
         // 00402594: sub rdi, rsi
         // 00402597: shl rdi, b1 cl
      [-]31c0c60000c3
         // 00447da0: xor b4 eax, b4 eax
         // 00447da2: mov b1 ds:[rax], b1 0x0
         // 00447da5: retn 
      [-]8b0881c1
         // 00469bfd: mov ecx, ds:[eax]
         // 00469bff: add ecx, 0xba0
      [-]046c657507
         // 00457914: jnz 0x45791d
      [-]04656d75
         // 0045792b: jnz 0x457934
      [-]8b238b43
         // 0046befb: mov esp, ds:[ebx]
         // 0046befd: mov eax, ds:[ebx+0x10]
      [-]24897c24
         // 004553d2: mov ss:[rsp+0x8], rdi
      [-]04f30f70c000660f6fc8660fef05
         // 0046bfdb: pshufhw b16 xmm0, b16 xmm0, b1 0x0
         // 0046bfe0: movdqa b16 xmm1, b16 xmm0
         // 0046bfe4: pxor b16 xmm0, b16 ds:[0xf1dc80]
      [-]660f38dcc083
         // 0046bfec: aesenc b16 xmm0, b16 xmm0
         // 0046bff1: cmp ebx, 0x10
      [-]660f6fd1660f6fd9660fef
         // 0046c14b: movdqa b16 xmm2, b16 xmm1
         // 0046c14f: movdqa b16 xmm3, b16 xmm1
         // 0046c153: pxor b16 xmm1, b16 ds:[0xf1dc90]
      [-]00660fef
         // 0046c163: pxor b16 xmm3, b16 ds:[0xf1dcb0]
      [-]660f38dc
         // 0046c16b: aesenc b16 xmm1, b16 xmm1
      [-]660f38dc
         // 0046c170: aesenc b16 xmm2, b16 xmm2
      [-]660f38dc
         // 0046c175: aesenc b16 xmm3, b16 xmm3
      [-]f30f6f00f30f6f4810f30f6f5020f30f6f5830660f38dc
         // 004786ba: movdqu b16 xmm0, b16 ds:[eax]
         // 004786be: movdqu b16 xmm1, b16 ds:[eax+0x10]
         // 004786c3: movdqu b16 xmm2, b16 ds:[eax+0x20]
         // 004786c8: movdqu b16 xmm3, b16 ds:[eax+0x30]
         // 004786cd: aesenc b16 xmm4, b16 xmm0
      [-]660f38dc
         // 004786d2: aesenc b16 xmm5, b16 xmm1
      [-]660f38dc
         // 004786d7: aesenc b16 xmm6, b16 xmm2
      [-]660f38dc
         // 004786dc: aesenc b16 xmm7, b16 xmm3
      [-]660f38dce4660f38dced660f38dcf6660f38dcff
         // 004786e1: aesenc b16 xmm4, b16 xmm4
         // 004786e6: aesenc b16 xmm5, b16 xmm5
         // 004786eb: aesenc b16 xmm6, b16 xmm6
         // 004786f0: aesenc b16 xmm7, b16 xmm7
      [-]660f38dc
         // 00469586: aesenc b16 xmm8, b16 xmm8
      [-]660f38dc
         // 0046958c: aesenc b16 xmm9, b16 xmm9
      [-]660f38dc
         // 00469592: aesenc b16 xmm10, b16 xmm10
      [-]660f38dc
         // 00469598: aesenc b16 xmm11, b16 xmm11
      [-]660f38dce4660f38dced660f38dcf6660f38dcff660f38dc
         // 0046959e: aesenc b16 xmm12, b16 xmm12
         // 004695a4: aesenc b16 xmm13, b16 xmm13
         // 004695aa: aesenc b16 xmm14, b16 xmm14
         // 004695b0: aesenc b16 xmm15, b16 xmm15
         // 004695b6: aesenc b16 xmm8, b16 xmm8
      [-]660f38dc
         // 004695bc: aesenc b16 xmm9, b16 xmm9
      [-]660f38dc
         // 004695c2: aesenc b16 xmm10, b16 xmm10
      [-]660f38dc
         // 004695c8: aesenc b16 xmm11, b16 xmm11
      [-]8b1339d074
         // 0045e61d: mov rdx, ds:[rbx]
         // 0045e620: cmp rax, rdx
         // 0045e623: jz 0x45e671
      [-]89fa8b3fffe7
         // 004598dd: mov rdx, rdi
         // 004598e0: mov rdi, ds:[rdi]
         // 004598e3: jmp rdi
      [-]cccccccccccc
         // 0046a019: int b1 0x3
         // 0046a01a: int b1 0x3
         // 0046a01b: int b1 0x3
         // 0046a01c: int b1 0x3
         // 0046a01d: int b1 0x3
         // 0046a01e: int b1 0x3
      [-]ba????????e9
         // 004599a0: mov b4 edx, b4 0x0
         // 004599a5: jmp runtime.morestack
      [-]89e7f3a48b
         // 0045eb14: mov rdi, rsp
         // 0045eb17: rep movsbb 
         // 0045eb2e: mov r12, ss:[rsp+0x48]
      [-]89e601df01de29d9e8
         // 0045eb4a: mov rsi, rsp
         // 0045eb4d: add rdi, rbx
         // 0045eb50: add rsi, rbx
         // 0045eb53: sub rcx, rbx
         // 0045eb56: call callRet
      [-]ffff83c4
         // 0045eb60: add rsp, 0x18
      [-]89e7f3a48b
         // 0046a50e: mov rdi, rsp
         // 0046a511: rep movsbb 
         // 0046a528: mov r12, ss:[rsp+0x58]
      [-]89e601df01de29d9e8
         // 0046a544: mov rsi, rsp
         // 0046a547: add rdi, rbx
         // 0046a54a: add rsi, rbx
         // 0046a54d: sub rcx, rbx
         // 0046a550: call callRet
      [-]ffff83c4
         // 0046a555: add rsp, 0x20
      [-]89e7f3a48b
         // 0046a5ae: mov rdi, rsp
         // 0046a5b1: rep movsbb 
         // 0046a5b3: mov r12, ss:[rsp+0x78]
      [-]245489e601df01de29d9e8
         // 0046a5df: mov rdx, ss:[rsp+0x50]
         // 0046a5e4: mov rsi, rsp
         // 0046a5e7: add rdi, rbx
         // 0046a5ea: add rsi, rbx
         // 0046a5ed: sub rcx, rbx
         // 0046a5f0: call callRet
      [-]ffff83c4
         // 0046a5f5: add rsp, 0x40
      [-]89e7f3a48b
         // 0046a65d: mov rdi, rsp
         // 0046a660: rep movsbb 
         // 0046a662: mov r12, ss:[rsp+0xb8]
      [-]89e601df01de29d9e8
         // 0046a6a8: mov rsi, rsp
         // 0046a6ab: add rdi, rbx
         // 0046a6ae: add rsi, rbx
         // 0046a6b1: sub rcx, rbx
         // 0046a6b4: call callRet
      [-]89e7f3a48b
         // 0045ee13: mov rdi, rsp
         // 0045ee16: rep movsbb 
         // 0045ee18: mov r12, ss:[rsp+0x138]
      [-]89e601df01de29d9e8
         // 0045ee5e: mov rsi, rsp
         // 0045ee61: add rdi, rbx
         // 0045ee64: add rsi, rbx
         // 0045ee67: sub rcx, rbx
         // 0045ee6a: call callRet
      [-]ffff81c4
         // 0045ee77: add rsp, 0x108
      [-]89e7f3a48b
         // 0045ef13: mov rdi, rsp
         // 0045ef16: rep movsbb 
         // 0045ef18: mov r12, ss:[rsp+0x238]
      [-]89e601df01de29d9e8
         // 0045ef5e: mov rsi, rsp
         // 0045ef61: add rdi, rbx
         // 0045ef64: add rsi, rbx
         // 0045ef67: sub rcx, rbx
         // 0045ef6a: call callRet
      [-]ffff81c4
         // 0045ef77: add rsp, 0x208
      [-]89e7f3a48b
         // 0045f013: mov rdi, rsp
         // 0045f016: rep movsbb 
         // 0045f018: mov r12, ss:[rsp+0x438]
      [-]89e601df01de29d9e8
         // 0045f05e: mov rsi, rsp
         // 0045f061: add rdi, rbx
         // 0045f064: add rsi, rbx
         // 0045f067: sub rcx, rbx
         // 0045f06a: call callRet
      [-]ffff81c4
         // 0045f077: add rsp, 0x408
      [-]89e7f3a48b
         // 0045f113: mov rdi, rsp
         // 0045f116: rep movsbb 
         // 0045f118: mov r12, ss:[rsp+0x838]
      [-]89e601df01de29d9e8
         // 0045f15e: mov rsi, rsp
         // 0045f161: add rdi, rbx
         // 0045f164: add rsi, rbx
         // 0045f167: sub rcx, rbx
         // 0045f16a: call callRet
      [-]ffff81c4
         // 0045f177: add rsp, 0x808
      [-]8b8c24??
         // 0046aac4: mov b4 ecx, b4 ss:[rsp+0x1028]
      [-]89e7f3a48b
         // 0046aacb: mov rdi, rsp
         // 0046aace: rep movsbb 
         // 0046aad0: mov r12, ss:[rsp+0x1038]
      [-]89e601df01de29d9e8
         // 0046ab16: mov rsi, rsp
         // 0046ab19: add rdi, rbx
         // 0046ab1c: add rsi, rbx
         // 0046ab1f: sub rcx, rbx
         // 0046ab22: call callRet
      [-]ffff81c4
         // 0046ab27: add rsp, 0x1000
      [-]89e7f3a48b
         // 0045f31b: mov rdi, rsp
         // 0045f31e: rep movsbb 
         // 0045f320: mov r12, ss:[rsp+0x2038]
      [-]89e601df01de29d9e8
         // 0045f366: mov rsi, rsp
         // 0045f369: add rdi, rbx
         // 0045f36c: add rsi, rbx
         // 0045f36f: sub rcx, rbx
         // 0045f372: call callRet
      [-]ffff81c4
         // 0045f37f: add rsp, 0x2008
      [-]89e7f3a48b
         // 0046ac8b: mov rdi, rsp
         // 0046ac8e: rep movsbb 
         // 0046ac90: mov r12, ss:[rsp+0x4038]
      [-]89e601df01de29d9e8
         // 0046acd6: mov rsi, rsp
         // 0046acd9: add rdi, rbx
         // 0046acdc: add rsi, rbx
         // 0046acdf: sub rcx, rbx
         // 0046ace2: call callRet
      [-]ffff81c4
         // 0046ace7: add rsp, 0x4000
      [-]89e7f3a48b
         // 0045f51b: mov rdi, rsp
         // 0045f51e: rep movsbb 
         // 0045f520: mov r12, ss:[rsp+0x8038]
      [-]89e601df01de29d9e8
         // 0045f566: mov rsi, rsp
         // 0045f569: add rdi, rbx
         // 0045f56c: add rsi, rbx
         // 0045f56f: sub rcx, rbx
         // 0045f572: call callRet
      [-]ffff81c4
         // 0045f57f: add rsp, 0x8008
      [-]89e7f3a48b
         // 0046ae4b: mov rdi, rsp
         // 0046ae4e: rep movsbb 
         // 0046ae50: mov r12, ss:[rsp+0x10038]
      [-]89e601df01de29d9e8
         // 0046ae96: mov rsi, rsp
         // 0046ae99: add rdi, rbx
         // 0046ae9c: add rsi, rbx
         // 0046ae9f: sub rcx, rbx
         // 0046aea2: call callRet
      [-]ffff81c4
         // 0046aea7: add rsp, 0x10000
      [-]89e7f3a48b
         // 0046af2b: mov rdi, rsp
         // 0046af2e: rep movsbb 
         // 0046af30: mov r12, ss:[rsp+0x20038]
      [-]89e601df01de29d9e8
         // 0046af76: mov rsi, rsp
         // 0046af79: add rdi, rbx
         // 0046af7c: add rsi, rbx
         // 0046af7f: sub rcx, rbx
         // 0046af82: call callRet
      [-]ffff81c4
         // 0046af87: add rsp, 0x20000
      [-]89e7f3a48b
         // 0045f81b: mov rdi, rsp
         // 0045f81e: rep movsbb 
         // 0045f820: mov r12, ss:[rsp+0x40038]
      [-]89e601df01de29d9e8
         // 0045f866: mov rsi, rsp
         // 0045f869: add rdi, rbx
         // 0045f86c: add rsi, rbx
         // 0045f86f: sub rcx, rbx
         // 0045f872: call callRet
      [-]ffff81c4
         // 0045f87f: add rsp, 0x40008
      [-]89e7f3a48b
         // 0046b0eb: mov rdi, rsp
         // 0046b0ee: rep movsbb 
         // 0046b0f0: mov r12, ss:[rsp+0x80038]
      [-]89e601df01de29d9e8
         // 0046b136: mov rsi, rsp
         // 0046b139: add rdi, rbx
         // 0046b13c: add rsi, rbx
         // 0046b13f: sub rcx, rbx
         // 0046b142: call callRet
      [-]ffff81c4
         // 0046b147: add rsp, 0x80000
      [-]89e7f3a48b
         // 0045fa1b: mov rdi, rsp
         // 0045fa1e: rep movsbb 
         // 0045fa20: mov r12, ss:[rsp+0x100038]
      [-]89e601df01de29d9e8
         // 0045fa66: mov rsi, rsp
         // 0045fa69: add rdi, rbx
         // 0045fa6c: add rsi, rbx
         // 0045fa6f: sub rcx, rbx
         // 0045fa72: call callRet
      [-]ffff81c4
         // 0045fa7f: add rsp, 0x100008
      [-]89e7f3a48b
         // 0046b2ab: mov rdi, rsp
         // 0046b2ae: rep movsbb 
         // 0046b2b0: mov r12, ss:[rsp+0x200038]
      [-]89e601df01de29d9e8
         // 0046b2f6: mov rsi, rsp
         // 0046b2f9: add rdi, rbx
         // 0046b2fc: add rsi, rbx
         // 0046b2ff: sub rcx, rbx
         // 0046b302: call callRet
      [-]ffff81c4
         // 0046b307: add rsp, 0x200000
      [-]89e7f3a48b
         // 0046b38b: mov rdi, rsp
         // 0046b38e: rep movsbb 
         // 0046b390: mov r12, ss:[rsp+0x400038]
      [-]89e601df01de29d9e8
         // 0046b3d6: mov rsi, rsp
         // 0046b3d9: add rdi, rbx
         // 0046b3dc: add rsi, rbx
         // 0046b3df: sub rcx, rbx
         // 0046b3e2: call callRet
      [-]ffff81c4
         // 0046b3e7: add rsp, 0x400000
      [-]89e7f3a48b
         // 0046b46b: mov rdi, rsp
         // 0046b46e: rep movsbb 
         // 0046b470: mov r12, ss:[rsp+0x800038]
      [-]89e601df01de29d9e8
         // 0046b4b6: mov rsi, rsp
         // 0046b4b9: add rdi, rbx
         // 0046b4bc: add rsi, rbx
         // 0046b4bf: sub rcx, rbx
         // 0046b4c2: call callRet
      [-]ffff81c4
         // 0046b4c7: add rsp, 0x800000
      [-]89e7f3a48b
         // 0046b54b: mov rdi, rsp
         // 0046b54e: rep movsbb 
         // 0046b550: mov r12, ss:[rsp+0x1000038]
      [-]89e601df01de29d9e8
         // 0046b596: mov rsi, rsp
         // 0046b599: add rdi, rbx
         // 0046b59c: add rsi, rbx
         // 0046b59f: sub rcx, rbx
         // 0046b5a2: call callRet
      [-]ffff81c4
         // 0046b5a7: add rsp, 0x1000000
      [-]89e7f3a48b
         // 0046b62b: mov rdi, rsp
         // 0046b62e: rep movsbb 
         // 0046b630: mov r12, ss:[rsp+0x2000038]
      [-]89e601df01de29d9e8
         // 0046b676: mov rsi, rsp
         // 0046b679: add rdi, rbx
         // 0046b67c: add rsi, rbx
         // 0046b67f: sub rcx, rbx
         // 0046b682: call callRet
      [-]ffff81c4
         // 0046b687: add rsp, 0x2000000
      [-]89e7f3a48b
         // 0046b70b: mov rdi, rsp
         // 0046b70e: rep movsbb 
         // 0046b710: mov r12, ss:[rsp+0x4000038]
      [-]89e601df01de29d9e8
         // 0046b756: mov rsi, rsp
         // 0046b759: add rdi, rbx
         // 0046b75c: add rsi, rbx
         // 0046b75f: sub rcx, rbx
         // 0046b762: call callRet
      [-]ffff81c4
         // 0046b767: add rsp, 0x4000000
      [-]89e7f3a48b
         // 0046b7eb: mov rdi, rsp
         // 0046b7ee: rep movsbb 
         // 0046b7f0: mov r12, ss:[rsp+0x8000038]
      [-]89e601df01de29d9e8
         // 0046b836: mov rsi, rsp
         // 0046b839: add rdi, rbx
         // 0046b83c: add rsi, rbx
         // 0046b83f: sub rcx, rbx
         // 0046b842: call callRet
      [-]ffff81c4
         // 0046b847: add rsp, 0x8000000
      [-]89e7f3a48b
         // 0046021b: mov rdi, rsp
         // 0046021e: rep movsbb 
         // 00460220: mov r12, ss:[rsp+0x10000038]
      [-]89e601df01de29d9e8
         // 00460266: mov rsi, rsp
         // 00460269: add rdi, rbx
         // 0046026c: add rsi, rbx
         // 0046026f: sub rcx, rbx
         // 00460272: call callRet
      [-]ffff81c4
         // 0046027f: add rsp, 0x10000008
      [-]89e7f3a48b
         // 0046031b: mov rdi, rsp
         // 0046031e: rep movsbb 
         // 00460320: mov r12, ss:[rsp+0x20000038]
      [-]89e601df01de29d9e8
         // 00460366: mov rsi, rsp
         // 00460369: add rdi, rbx
         // 0046036c: add rsi, rbx
         // 0046036f: sub rcx, rbx
         // 00460372: call callRet
      [-]ffff81c4
         // 0046037f: add rsp, 0x20000008
      [-]89e7f3a48b
         // 0046041b: mov rdi, rsp
         // 0046041e: rep movsbb 
         // 00460420: mov r12, ss:[rsp+0x40000038]
      [-]89e601df01de29d9e8
         // 00460466: mov rsi, rsp
         // 00460469: add rdi, rbx
         // 0046046c: add rsi, rbx
         // 0046046f: sub rcx, rbx
         // 00460472: call callRet
      [-]ffff81c4
         // 0046047f: add rsp, 0x40000008
      [-]ffd0c74424
         // 0046c54f: call rax
         // 0046c551: mov ss:[rsp+0x10], 0x0
      [-]8904248966
         // 0046bcda: mov ss:[rsp], rax
         // 0046bcde: mov ds:[rsi+0x38], rsp
      [-]8b04248946
         // 0046bd65: mov rax, ss:[rsp]
         // 0046bd69: mov ds:[rsi+0x38], rax
      [-]3b207705
         // 0045ba3b: cmp rsp, ds:[rax]
         // 0045ba3e: ja 0x45ba45
      [-]0faef00faee80f31eb
         // 0045ba79: mfence 
         // 0045ba7c: lfence 
         // 0045ba7f: rdtsc 
         // 0045ba81: jmp 0x45ba6c
      [-]85db0f84
         // 00459086: test rbx, rbx
         // 00459089: jz 0x459247
      [-]83fb400f86
         // 004590c7: cmp rbx, 0x40
         // 004590cb: jbe 0x459272
      [-]10f30f7f
         // 0045c759: movdqu b16 ds:[rdi+0x20], b16 xmm15
      [-]20f30f7f
         // 0045c75f: movdqu b16 ds:[rdi+0x30], b16 xmm15
      [-]30f30f7f
         // 0045c765: movdqu b16 ds:[rdi+0x40], b16 xmm15
      [-]40f30f7f
         // 0045c76b: movdqu b16 ds:[rdi+0x50], b16 xmm15
      [-]50f30f7f
         // 0045c771: movdqu b16 ds:[rdi+0x60], b16 xmm15
      [-]60f30f7f
         // 0045c777: movdqu b16 ds:[rdi+0x70], b16 xmm15
      [-]70f30f7f
         // 0045c77d: movdqu b16 ds:[rdi+0x80], b16 xmm15
      [-]80000000f30f7f
         // 0045c786: movdqu b16 ds:[rdi+0x90], b16 xmm15
      [-]90000000f30f7f
         // 0045c78f: movdqu b16 ds:[rdi+0xa0], b16 xmm15
      [-]a0000000f30f7f
         // 0045c798: movdqu b16 ds:[rdi+0xb0], b16 xmm15
      [-]b0000000f30f7f
         // 0045c7a1: movdqu b16 ds:[rdi+0xc0], b16 xmm15
      [-]c0000000f30f7f
         // 0045c7aa: movdqu b16 ds:[rdi+0xd0], b16 xmm15
      [-]d0000000f30f7f
         // 0045c7b3: movdqu b16 ds:[rdi+0xe0], b16 xmm15
      [-]e0000000f30f7f
         // 0045c7bc: movdqu b16 ds:[rdi+0xf0], b16 xmm15
      [-]f000000081eb
         // 0045c7c5: sub rbx, 0x100
      [-]890789441f
         // 0045c8db: mov ds:[rdi], rax
         // 0045c8de: mov ds:[rdi+rbx+0xfffffffffffffff8], rax
      [-]10f30f7f
         // 0045c8fc: movdqu b16 ds:[rdi+rbx+0xffffffffffffffe0], b16 xmm15
      [-]1fe0f30f7f
         // 0045c903: movdqu b16 ds:[rdi+rbx+0xfffffffffffffff0], b16 xmm15
      [-]10f30f7f
         // 0045c916: movdqu b16 ds:[rdi+0x20], b16 xmm15
      [-]20f30f7f
         // 0045c91c: movdqu b16 ds:[rdi+0x30], b16 xmm15
      [-]30f30f7f
         // 0045c922: movdqu b16 ds:[rdi+rbx+0xffffffffffffffc0], b16 xmm15
      [-]1fc0f30f7f
         // 0045c929: movdqu b16 ds:[rdi+rbx+0xffffffffffffffd0], b16 xmm15
      [-]1fd0f30f7f
         // 0045c930: movdqu b16 ds:[rdi+rbx+0xffffffffffffffe0], b16 xmm15
      [-]1fe0f30f7f
         // 0045c937: movdqu b16 ds:[rdi+rbx+0xfffffffffffffff0], b16 xmm15
      [-]10f30f7f
         // 0045c94a: movdqu b16 ds:[rdi+0x20], b16 xmm15
      [-]20f30f7f
         // 0045c950: movdqu b16 ds:[rdi+0x30], b16 xmm15
      [-]30f30f7f
         // 0045c956: movdqu b16 ds:[rdi+0x40], b16 xmm15
      [-]40f30f7f
         // 0045c95c: movdqu b16 ds:[rdi+0x50], b16 xmm15
      [-]50f30f7f
         // 0045c962: movdqu b16 ds:[rdi+0x60], b16 xmm15
      [-]60f30f7f
         // 0045c968: movdqu b16 ds:[rdi+0x70], b16 xmm15
      [-]70f30f7f
         // 0045c96e: movdqu b16 ds:[rdi+rbx+0xffffffffffffff80], b16 xmm15
      [-]1f80f30f7f
         // 0045c975: movdqu b16 ds:[rdi+rbx+0xffffffffffffff90], b16 xmm15
      [-]1f90f30f7f
         // 0045c97c: movdqu b16 ds:[rdi+rbx+0xffffffffffffffa0], b16 xmm15
      [-]1fa0f30f7f
         // 0045c983: movdqu b16 ds:[rdi+rbx+0xffffffffffffffb0], b16 xmm15
      [-]1fb0f30f7f
         // 0045c98a: movdqu b16 ds:[rdi+rbx+0xffffffffffffffc0], b16 xmm15
      [-]1fc0f30f7f
         // 0045c991: movdqu b16 ds:[rdi+rbx+0xffffffffffffffd0], b16 xmm15
      [-]1fd0f30f7f
         // 0045c998: movdqu b16 ds:[rdi+rbx+0xffffffffffffffe0], b16 xmm15
      [-]1fe0f30f7f
         // 0045c99f: movdqu b16 ds:[rdi+rbx+0xfffffffffffffff0], b16 xmm15
      [-]85db0f84
         // 0045c9c9: test rbx, rbx
         // 0045c9cc: jz 0x45cac9
      [-]83fb020f86
         // 0045c9d2: cmp rbx, 0x2
         // 0045c9d6: jbe 0x45cabc
      [-]83fb200f86
         // 0045ca06: cmp rbx, 0x20
         // 0045ca0a: jbe 0x45cb01
      [-]83fb400f86
         // 0045ca10: cmp rbx, 0x40
         // 0045ca14: jbe 0x45cb16
      [-]89f009f8a9
         // 0045ca5c: mov b4 eax, b4 esi
         // 0045ca5e: or b4 eax, b4 edi
         // 0045ca60: test b4 eax, b4 0x7
      [-]89d9f3a4c3
         // 0045ca67: mov rcx, rbx
         // 0045ca6a: rep movsbb 
         // 0045ca6c: retn 
      [-]89f101d939f976
         // 00472d5c: mov rcx, rsi
         // 00472d5f: add rcx, rbx
         // 00472d62: cmp rcx, rdi
         // 00472d65: jbe 0x472d07
      [-]01df01defd89d9c1e9
         // 00472d6f: add rdi, rbx
         // 00472d72: add rsi, rbx
         // 00472d75: std 
         // 00472d76: mov rcx, rbx
         // 00472d79: shr rcx, b1 0x3
      [-]29df29dee9
         // 00472d95: sub rdi, rbx
         // 00472d98: sub rsi, rbx
         // 00472d9b: jmp 0x472c89
      [-]8a068a4c1eff8807884c1fffc3
         // 0045cabc: mov b1 al, b1 ds:[rsi]
         // 0045cabe: mov b1 cl, b1 ds:[rsi+rbx+0xffffffffffffffff]
         // 0045cac2: mov b1 ds:[rdi], b1 al
         // 0045cac4: mov b1 ds:[rdi+rbx+0xffffffffffffffff], b1 cl
         // 0045cac8: retn 
      [-]668b068a4e02668907884f02c3
         // 0045cacf: mov b2 ax, b2 ds:[rsi]
         // 0045cad2: mov b1 cl, b1 ds:[rsi+0x2]
         // 0045cad5: mov b2 ds:[rdi], b2 ax
         // 0045cad8: mov b1 ds:[rdi+0x2], b1 cl
         // 0045cadb: retn 
      [-]8b068907c3
         // 0045cae9: mov rax, ds:[rsi]
         // 0045caec: mov ds:[rdi], rax
         // 0045caef: retn 
      [-]8b068b4c1e
         // 0045caf0: mov rax, ds:[rsi]
         // 0045caf3: mov rcx, ds:[rsi+rbx+0xfffffffffffffff8]
      [-]8907894c1f
         // 0045caf8: mov ds:[rdi], rax
         // 0045cafb: mov ds:[rdi+rbx+0xfffffffffffffff8], rcx
      [-]f30f6f06f30f6f4c1ef0f30f7f07f30f7f4c1ff0c3
         // 0045cb01: movdqu b16 xmm0, b16 ds:[rsi]
         // 0045cb05: movdqu b16 xmm1, b16 ds:[rsi+rbx+0xfffffffffffffff0]
         // 0045cb0b: movdqu b16 ds:[rdi], b16 xmm0
         // 0045cb0f: movdqu b16 ds:[rdi+rbx+0xfffffffffffffff0], b16 xmm1
         // 0045cb15: retn 
      [-]f30f6f06f30f6f4e10f30f6f541ee0f30f6f5c1ef0f30f7f07f30f7f4f10f30f7f541fe0f30f7f5c1ff0c3
         // 0045cb16: movdqu b16 xmm0, b16 ds:[rsi]
         // 0045cb1a: movdqu b16 xmm1, b16 ds:[rsi+0x10]
         // 0045cb1f: movdqu b16 xmm2, b16 ds:[rsi+rbx+0xffffffffffffffe0]
         // 0045cb25: movdqu b16 xmm3, b16 ds:[rsi+rbx+0xfffffffffffffff0]
         // 0045cb2b: movdqu b16 ds:[rdi], b16 xmm0
         // 0045cb2f: movdqu b16 ds:[rdi+0x10], b16 xmm1
         // 0045cb34: movdqu b16 ds:[rdi+rbx+0xffffffffffffffe0], b16 xmm2
         // 0045cb3a: movdqu b16 ds:[rdi+rbx+0xfffffffffffffff0], b16 xmm3
         // 0045cb40: retn 
      [-]f30f6f06f30f6f4e10f30f6f5620f30f6f5e30f30f6f641ec0f30f6f6c1ed0f30f6f741ee0f30f6f7c1ef0f30f7f07f30f7f4f10f30f7f5720f30f7f5f30f30f7f641fc0f30f7f6c1fd0f30f7f741fe0f30f7f7c1ff0c3
         // 0045cb41: movdqu b16 xmm0, b16 ds:[rsi]
         // 0045cb45: movdqu b16 xmm1, b16 ds:[rsi+0x10]
         // 0045cb4a: movdqu b16 xmm2, b16 ds:[rsi+0x20]
         // 0045cb4f: movdqu b16 xmm3, b16 ds:[rsi+0x30]
         // 0045cb54: movdqu b16 xmm4, b16 ds:[rsi+rbx+0xffffffffffffffc0]
         // 0045cb5a: movdqu b16 xmm5, b16 ds:[rsi+rbx+0xffffffffffffffd0]
         // 0045cb60: movdqu b16 xmm6, b16 ds:[rsi+rbx+0xffffffffffffffe0]
         // 0045cb66: movdqu b16 xmm7, b16 ds:[rsi+rbx+0xfffffffffffffff0]
         // 0045cb6c: movdqu b16 ds:[rdi], b16 xmm0
         // 0045cb70: movdqu b16 ds:[rdi+0x10], b16 xmm1
         // 0045cb75: movdqu b16 ds:[rdi+0x20], b16 xmm2
         // 0045cb7a: movdqu b16 ds:[rdi+0x30], b16 xmm3
         // 0045cb7f: movdqu b16 ds:[rdi+rbx+0xffffffffffffffc0], b16 xmm4
         // 0045cb85: movdqu b16 ds:[rdi+rbx+0xffffffffffffffd0], b16 xmm5
         // 0045cb8b: movdqu b16 ds:[rdi+rbx+0xffffffffffffffe0], b16 xmm6
         // 0045cb91: movdqu b16 ds:[rdi+rbx+0xfffffffffffffff0], b16 xmm7
         // 0045cb97: retn 
      [-]0f114424
         // 0046d411: movups b16 ss:[rsp+0x70], b16 xmm0
      [-]0f11bc24
         // 0046d446: movups b16 ss:[rsp+0xe0], b16 xmm7
      [-]248c0000000f
         // 0046d457: movups b16 ss:[rsp+0x100], b16 xmm9
         // 0046d460: movups b16 ss:[rsp+0x110], b16 xmm10
      [-]008d4424
         // 00473a32: lea rax, ss:[rsp+0x18]
      [-]00894424
         // 00473a40: mov ss:[rsp+0x8], rax

  }
  condition:
    all of them
}
