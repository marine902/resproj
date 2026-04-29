rule wingo_10_1 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         f30f6f06f30f6f0f660f74c8660fd7
         // 0040305b: movdqu b16 xmm0, b16 ds:[rsi]
         // 0040305f: movdqu b16 xmm1, b16 ds:[rdi]
         // 00403063: pcmpeqb b16 xmm1, b16 xmm0
         // 00403067: pmovmskb b4 eax, b16 xmm1
      [-]8a0c1e3a0c1f0f97
         // 004030a4: mov b1 cl, b1 ds:[rsi+rbx]
         // 004030a7: cmp b1 cl, b1 ds:[rdi+rbx]
         // 004030aa: setnbe b1 al
      [-]0fbdc9d3
         // 004030df: bsr rcx, rcx
         // 004030e3: shr rax, b1 cl
      [-]00000000f7d974
         // 004030fb: neg rcx
         // 004030fe: jz 0x40314b
      [-]d3e70fce0fcf31f774
         // 00403129: shl rdi, b1 cl
         // 0040312c: bswap rsi
         // 0040312f: bswap rdi
         // 00403132: xor rdi, rsi
         // 00403135: jz 0x40314b
      [-]0fbdcfd3ee83e6018d
         // 00403137: bsr rcx, rdi
         // 0040313b: shr rsi, b1 cl
         // 0040313e: and rsi, 0x1
         // 00403142: lea rax, ds:[0xffffffffffffffff+rsi*0x2]
      [-]f30f6f06f30f6f0ff30f6f5610f30f6f5f10f30f6f6620f30f6f6f20f30f6f7630f30f6f7f30660f74c1660f74d3660f74e5660f74f7660fdbc2660fdbe6660fdbc4660fd7d083c64083c74083eb4081fa????????74
         // 004034da: movdqu b16 xmm0, b16 ds:[rsi]
         // 004034de: movdqu b16 xmm1, b16 ds:[rdi]
         // 004034e2: movdqu b16 xmm2, b16 ds:[rsi+0x10]
         // 004034e7: movdqu b16 xmm3, b16 ds:[rdi+0x10]
         // 004034ec: movdqu b16 xmm4, b16 ds:[rsi+0x20]
         // 004034f1: movdqu b16 xmm5, b16 ds:[rdi+0x20]
         // 004034f6: movdqu b16 xmm6, b16 ds:[rsi+0x30]
         // 004034fb: movdqu b16 xmm7, b16 ds:[rdi+0x30]
         // 00403500: pcmpeqb b16 xmm0, b16 xmm1
         // 00403504: pcmpeqb b16 xmm2, b16 xmm3
         // 00403508: pcmpeqb b16 xmm4, b16 xmm5
         // 0040350c: pcmpeqb b16 xmm6, b16 xmm7
         // 00403510: pand b16 xmm0, b16 xmm2
         // 00403514: pand b16 xmm4, b16 xmm6
         // 00403518: pand b16 xmm0, b16 xmm4
         // 0040351c: pmovmskb b4 edx, b16 xmm0
         // 00403520: add rsi, 0x40
         // 00403524: add rdi, 0x40
         // 00403528: sub rbx, 0x40
         // 0040352c: cmp b4 edx, b4 0xffff
         // 00403532: jz 0x4034d0
      [-]8b0e8b1783c6
         // 00403596: mov rcx, ds:[rsi]
         // 00403599: mov rdx, ds:[rdi]
         // 0040359c: add rsi, 0x8
      [-]39d10f94
         // 004035bb: cmp rcx, rdx
         // 004035be: setz b1 al
      [-]83fb0074
         // 004035c2: cmp rbx, 0x0
         // 004035c6: jz 0x4035ff
      [-]8d0cdd00000000f7d9
         // 004035c8: lea rcx, ds:[rbx*0x8]
         // 004035d0: neg rcx
      [-]29f7d3e7
         // 004035f9: sub rdi, rsi
         // 004035fc: shl rdi, b1 cl
      [-]90908d05
         // 00438a4e: nop 
         // 00438a4f: nop 
         // 00438a50: lea rax, cs:[0x5e3cb8]
      [-]31c0c60000c3
         // 004523a0: xor b4 eax, b4 eax
         // 004523a2: mov b1 ds:[rax], b1 0x0
         // 004523a5: retn 
      [-]83ec108b
         // 00465a8e: sub rsp, 0x10
         // 00465a93: mov b4 edx, b4 ds:[rax+0x18]
      [-]83c410c3
         // 00465b74: add rsp, 0x10
         // 00465b79: retn 
      [-]90908b4424
         // 00466b02: nop 
         // 00466b03: nop 
         // 00466b04: mov rax, ss:[rsp+0x30]
      [-]faff8b4424
         // 00466b0e: mov rax, ss:[rsp+0x28]
      [-]10894424
         // 00466c2e: mov ss:[rsp+0x20], rax
      [-]8b0881c1
         // 0045f7d3: mov ecx, ds:[eax]
         // 0045f7d5: add ecx, 0xba0
      [-]046c657507
         // 004672d4: jnz 0x4672dd
      [-]04656d75
         // 004672eb: jnz 0x4672f4
      [-]9090908d05
         // 00466f7d: nop 
         // 00466f7e: nop 
         // 00466f7f: nop 
         // 00466f80: lea rax, cs:[runtime.reflectOffs]
      [-]faff8b4424
         // 00466f8c: mov b4 eax, b4 ss:[rsp+0x1c]
      [-]feff83c4
         // 00467945: add rsp, 0x28
      [-]83ec08e8
         // 00460362: sub esp, 0x8
         // 00460365: call runtime.nanotime1
      [-]83c408c3
         // 00460379: add esp, 0x8
         // 0046037c: retn 
      [-]80f90e0f84
         // 0046068a: cmp b1 cl, b1 0xe
         // 0046068d: jz 0x4608c2
      [-]b9????????e8
         // 00476ffd: mov ecx, 0x7d0
         // 00477002: call runtime.panicIndex
      [-]9090908d05
         // 00468e93: nop 
         // 00468e94: nop 
         // 00468e95: nop 
         // 00468e96: lea rax, cs:[runtime.cbs]
      [-]faff8d05
         // 00468ea5: lea rax, cs:[0x4e1c4f]
      [-]8b238b43
         // 00469031: mov rsp, ds:[rbx]
         // 00469034: mov rax, ds:[rbx+0x20]
      [-]891424897c24
         // 00469088: mov ss:[rsp], rdx
         // 0046908c: mov ss:[rsp+0x8], rdi
      [-]04f30f70c000660f6fc8660fef05
         // 0046146b: pshufhw b16 xmm0, b16 xmm0, b1 0x0
         // 00461470: movdqa b16 xmm1, b16 xmm0
         // 00461474: pxor b16 xmm0, b16 ds:[0x9161c0]
      [-]660f38dcc083
         // 0046147c: aesenc b16 xmm0, b16 xmm0
         // 00461481: cmp ebx, 0x10
      [-]660f6fd1660f6fd9660fef
         // 0047865b: movdqa b16 xmm2, b16 xmm1
         // 0047865f: movdqa b16 xmm3, b16 xmm1
         // 00478663: pxor b16 xmm1, b16 ds:[0x17942f0]
      [-]00660fef
         // 00478673: pxor b16 xmm3, b16 ds:[0x1794310]
      [-]660f38dc
         // 0047867b: aesenc b16 xmm1, b16 xmm1
      [-]660f38dc
         // 00478680: aesenc b16 xmm2, b16 xmm2
      [-]660f38dc
         // 00478685: aesenc b16 xmm3, b16 xmm3
      [-]f30f6f64
         // 0047868a: movdqu b16 xmm4, b16 ds:[eax+ebx+0xffffffffffffffc0]
      [-]c0f30f6f6c
         // 00478690: movdqu b16 xmm5, b16 ds:[eax+ebx+0xffffffffffffffd0]
      [-]d0f30f6f74
         // 00478696: movdqu b16 xmm6, b16 ds:[eax+ebx+0xffffffffffffffe0]
      [-]e0f30f6f7c
         // 0047869c: movdqu b16 xmm7, b16 ds:[eax+ebx+0xfffffffffffffff0]
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
         // 0046ac66: aesenc b16 xmm8, b16 xmm8
      [-]660f38dc
         // 0046ac6c: aesenc b16 xmm9, b16 xmm9
      [-]660f38dc
         // 0046ac72: aesenc b16 xmm10, b16 xmm10
      [-]660f38dc
         // 0046ac78: aesenc b16 xmm11, b16 xmm11
      [-]660f38dce4660f38dced660f38dcf6660f38dcff660f38dc
         // 0046ac7e: aesenc b16 xmm12, b16 xmm12
         // 0046ac84: aesenc b16 xmm13, b16 xmm13
         // 0046ac8a: aesenc b16 xmm14, b16 xmm14
         // 0046ac90: aesenc b16 xmm15, b16 xmm15
         // 0046ac96: aesenc b16 xmm8, b16 xmm8
      [-]660f38dc
         // 0046ac9c: aesenc b16 xmm9, b16 xmm9
      [-]660f38dc
         // 0046aca2: aesenc b16 xmm10, b16 xmm10
      [-]660f38dc
         // 0046aca8: aesenc b16 xmm11, b16 xmm11
      [-]8b1339d074
         // 00461919: mov edx, ds:[ebx]
         // 0046191b: cmp eax, edx
         // 0046191d: jz 0x461965
      [-]89fa8b3fffe7
         // 0046b6df: mov rdx, rdi
         // 0046b6e2: mov rdi, ds:[rdi]
         // 0046b6e6: jmp rdi
      [-]cccccccccccc
         // 0046a059: int b1 0x3
         // 0046a05a: int b1 0x3
         // 0046a05b: int b1 0x3
         // 0046a05c: int b1 0x3
         // 0046a05d: int b1 0x3
         // 0046a05e: int b1 0x3
      [-]ba????????e9
         // 0046a0e0: mov b4 edx, b4 0x0
         // 0046a0e5: jmp runtime.morestack
      [-]89e7f3a48b
         // 0046c28b: mov rdi, rsp
         // 0046c28e: rep movsbb 
         // 0046c290: mov r12, ss:[rsp+0x2038]
      [-]89e601df01de29d9e8
         // 0046c2d6: mov rsi, rsp
         // 0046c2d9: add rdi, rbx
         // 0046c2dc: add rsi, rbx
         // 0046c2df: sub rcx, rbx
         // 0046c2e2: call callRet
      [-]ffff81c4
         // 0046c2e7: add rsp, 0x2000
      [-]89e7f3a48b
         // 0046c36b: mov rdi, rsp
         // 0046c36e: rep movsbb 
         // 0046c370: mov r12, ss:[rsp+0x4038]
      [-]89e601df01de29d9e8
         // 0046c3b6: mov rsi, rsp
         // 0046c3b9: add rdi, rbx
         // 0046c3bc: add rsi, rbx
         // 0046c3bf: sub rcx, rbx
         // 0046c3c2: call callRet
      [-]ffff81c4
         // 0046c3c7: add rsp, 0x4000
      [-]89e7f3a48b
         // 0046c44b: mov rdi, rsp
         // 0046c44e: rep movsbb 
         // 0046c450: mov r12, ss:[rsp+0x8038]
      [-]89e601df01de29d9e8
         // 0046c496: mov rsi, rsp
         // 0046c499: add rdi, rbx
         // 0046c49c: add rsi, rbx
         // 0046c49f: sub rcx, rbx
         // 0046c4a2: call callRet
      [-]ffff81c4
         // 0046c4a7: add rsp, 0x8000
      [-]89e7f3a48b
         // 0046ae8b: mov rdi, rsp
         // 0046ae8e: rep movsbb 
         // 0046ae90: mov r12, ss:[rsp+0x10038]
      [-]89e601df01de29d9e8
         // 0046aed6: mov rsi, rsp
         // 0046aed9: add rdi, rbx
         // 0046aedc: add rsi, rbx
         // 0046aedf: sub rcx, rbx
         // 0046aee2: call callRet
      [-]ffff81c4
         // 0046aee7: add rsp, 0x10000
      [-]89e7f3a48b
         // 0046c60b: mov rdi, rsp
         // 0046c60e: rep movsbb 
         // 0046c610: mov r12, ss:[rsp+0x20038]
      [-]89e601df01de29d9e8
         // 0046c656: mov rsi, rsp
         // 0046c659: add rdi, rbx
         // 0046c65c: add rsi, rbx
         // 0046c65f: sub rcx, rbx
         // 0046c662: call callRet
      [-]ffff81c4
         // 0046c667: add rsp, 0x20000
      [-]89e7f3a48b
         // 0046c6eb: mov rdi, rsp
         // 0046c6ee: rep movsbb 
         // 0046c6f0: mov r12, ss:[rsp+0x40038]
      [-]89e601df01de29d9e8
         // 0046c736: mov rsi, rsp
         // 0046c739: add rdi, rbx
         // 0046c73c: add rsi, rbx
         // 0046c73f: sub rcx, rbx
         // 0046c742: call callRet
      [-]ffff81c4
         // 0046c747: add rsp, 0x40000
      [-]89e7f3a48b
         // 0046c7cb: mov rdi, rsp
         // 0046c7ce: rep movsbb 
         // 0046c7d0: mov r12, ss:[rsp+0x80038]
      [-]89e601df01de29d9e8
         // 0046c816: mov rsi, rsp
         // 0046c819: add rdi, rbx
         // 0046c81c: add rsi, rbx
         // 0046c81f: sub rcx, rbx
         // 0046c822: call callRet
      [-]ffff81c4
         // 0046c827: add rsp, 0x80000
      [-]89e7f3a48b
         // 0046c8ab: mov rdi, rsp
         // 0046c8ae: rep movsbb 
         // 0046c8b0: mov r12, ss:[rsp+0x100038]
      [-]89e601df01de29d9e8
         // 0046c8f6: mov rsi, rsp
         // 0046c8f9: add rdi, rbx
         // 0046c8fc: add rsi, rbx
         // 0046c8ff: sub rcx, rbx
         // 0046c902: call callRet
      [-]ffff81c4
         // 0046c907: add rsp, 0x100000
      [-]89e7f3a48b
         // 0046c98b: mov rdi, rsp
         // 0046c98e: rep movsbb 
         // 0046c990: mov r12, ss:[rsp+0x200038]
      [-]89e601df01de29d9e8
         // 0046c9d6: mov rsi, rsp
         // 0046c9d9: add rdi, rbx
         // 0046c9dc: add rsi, rbx
         // 0046c9df: sub rcx, rbx
         // 0046c9e2: call callRet
      [-]ffff81c4
         // 0046c9e7: add rsp, 0x200000
      [-]89e7f3a48b
         // 0046b3cb: mov rdi, rsp
         // 0046b3ce: rep movsbb 
         // 0046b3d0: mov r12, ss:[rsp+0x400038]
      [-]89e601df01de29d9e8
         // 0046b416: mov rsi, rsp
         // 0046b419: add rdi, rbx
         // 0046b41c: add rsi, rbx
         // 0046b41f: sub rcx, rbx
         // 0046b422: call callRet
      [-]ffff81c4
         // 0046b427: add rsp, 0x400000
      [-]89e7f3a48b
         // 0046b4ab: mov rdi, rsp
         // 0046b4ae: rep movsbb 
         // 0046b4b0: mov r12, ss:[rsp+0x800038]
      [-]89e601df01de29d9e8
         // 0046b4f6: mov rsi, rsp
         // 0046b4f9: add rdi, rbx
         // 0046b4fc: add rsi, rbx
         // 0046b4ff: sub rcx, rbx
         // 0046b502: call callRet
      [-]ffff81c4
         // 0046b507: add rsp, 0x800000
      [-]89e7f3a48b
         // 0046b58b: mov rdi, rsp
         // 0046b58e: rep movsbb 
         // 0046b590: mov r12, ss:[rsp+0x1000038]
      [-]89e601df01de29d9e8
         // 0046b5d6: mov rsi, rsp
         // 0046b5d9: add rdi, rbx
         // 0046b5dc: add rsi, rbx
         // 0046b5df: sub rcx, rbx
         // 0046b5e2: call callRet
      [-]ffff81c4
         // 0046b5e7: add rsp, 0x1000000
      [-]89e7f3a48b
         // 0046cd0b: mov rdi, rsp
         // 0046cd0e: rep movsbb 
         // 0046cd10: mov r12, ss:[rsp+0x2000038]
      [-]89e601df01de29d9e8
         // 0046cd56: mov rsi, rsp
         // 0046cd59: add rdi, rbx
         // 0046cd5c: add rsi, rbx
         // 0046cd5f: sub rcx, rbx
         // 0046cd62: call callRet
      [-]ffff81c4
         // 0046cd67: add rsp, 0x2000000
      [-]89e7f3a48b
         // 0046cdeb: mov rdi, rsp
         // 0046cdee: rep movsbb 
         // 0046cdf0: mov r12, ss:[rsp+0x4000038]
      [-]89e601df01de29d9e8
         // 0046ce36: mov rsi, rsp
         // 0046ce39: add rdi, rbx
         // 0046ce3c: add rsi, rbx
         // 0046ce3f: sub rcx, rbx
         // 0046ce42: call callRet
      [-]ffff81c4
         // 0046ce47: add rsp, 0x4000000
      [-]89e7f3a48b
         // 0046cecb: mov rdi, rsp
         // 0046cece: rep movsbb 
         // 0046ced0: mov r12, ss:[rsp+0x8000038]
      [-]89e601df01de29d9e8
         // 0046cf16: mov rsi, rsp
         // 0046cf19: add rdi, rbx
         // 0046cf1c: add rsi, rbx
         // 0046cf1f: sub rcx, rbx
         // 0046cf22: call callRet
      [-]ffff81c4
         // 0046cf27: add rsp, 0x8000000
      [-]89e7f3a48b
         // 0046cfab: mov rdi, rsp
         // 0046cfae: rep movsbb 
         // 0046cfb0: mov r12, ss:[rsp+0x10000038]
      [-]89e601df01de29d9e8
         // 0046cff6: mov rsi, rsp
         // 0046cff9: add rdi, rbx
         // 0046cffc: add rsi, rbx
         // 0046cfff: sub rcx, rbx
         // 0046d002: call callRet
      [-]ffff81c4
         // 0046d007: add rsp, 0x10000000
      [-]89e7f3a48b
         // 0046d08b: mov rdi, rsp
         // 0046d08e: rep movsbb 
         // 0046d090: mov r12, ss:[rsp+0x20000038]
      [-]89e601df01de29d9e8
         // 0046d0d6: mov rsi, rsp
         // 0046d0d9: add rdi, rbx
         // 0046d0dc: add rsi, rbx
         // 0046d0df: sub rcx, rbx
         // 0046d0e2: call callRet
      [-]ffff81c4
         // 0046d0e7: add rsp, 0x20000000
      [-]89e7f3a48b
         // 0046d16b: mov rdi, rsp
         // 0046d16e: rep movsbb 
         // 0046d170: mov r12, ss:[rsp+0x40000038]
      [-]89e601df01de29d9e8
         // 0046d1b6: mov rsi, rsp
         // 0046d1b9: add rdi, rbx
         // 0046d1bc: add rsi, rbx
         // 0046d1bf: sub rcx, rbx
         // 0046d1c2: call callRet
      [-]ffff81c4
         // 0046d1c7: add rsp, 0x40000000
      [-]ffd0c74424
         // 0046bce8: lea rax, cs:[runtime.needAndBindM]
         // 0046bcef: call rax
         // 0046bcf1: mov ss:[rsp+0x10], 0x0
      [-]8904248966
         // 0046bd1a: mov ss:[rsp], rax
         // 0046bd1e: mov ds:[rsi+0x38], rsp
      [-]8b04248946
         // 0046bda5: mov rax, ss:[rsp]
         // 0046bda9: mov ds:[rsi+0x38], rax
      [-]0faef00faee80f31eb
         // 0046be99: mfence 
         // 0046be9c: lfence 
         // 0046be9f: rdtsc 
         // 0046bea1: jmp 0x46be8c
      [-]b8????????c3
         // 0046bfa0: mov b4 eax, b4 0x0
         // 0046bfa5: retn 
      [-]85db0f84
         // 0046ca86: test rbx, rbx
         // 0046ca89: jz 0x46cc86
      [-]83fb400f86
         // 0046cac7: cmp rbx, 0x40
         // 0046cacb: jbe 0x46ccb1
      [-]10f30f7f
         // 0046cb19: movdqu b16 ds:[rdi+0x20], b16 xmm15
      [-]20f30f7f
         // 0046cb1f: movdqu b16 ds:[rdi+0x30], b16 xmm15
      [-]30f30f7f
         // 0046cb25: movdqu b16 ds:[rdi+0x40], b16 xmm15
      [-]40f30f7f
         // 0046cb2b: movdqu b16 ds:[rdi+0x50], b16 xmm15
      [-]50f30f7f
         // 0046cb31: movdqu b16 ds:[rdi+0x60], b16 xmm15
      [-]60f30f7f
         // 0046cb37: movdqu b16 ds:[rdi+0x70], b16 xmm15
      [-]70f30f7f
         // 0046cb3d: movdqu b16 ds:[rdi+0x80], b16 xmm15
      [-]80000000f30f7f
         // 0046cb46: movdqu b16 ds:[rdi+0x90], b16 xmm15
      [-]90000000f30f7f
         // 0046cb4f: movdqu b16 ds:[rdi+0xa0], b16 xmm15
      [-]a0000000f30f7f
         // 0046cb58: movdqu b16 ds:[rdi+0xb0], b16 xmm15
      [-]b0000000f30f7f
         // 0046cb61: movdqu b16 ds:[rdi+0xc0], b16 xmm15
      [-]c0000000f30f7f
         // 0046cb6a: movdqu b16 ds:[rdi+0xd0], b16 xmm15
      [-]d0000000f30f7f
         // 0046cb73: movdqu b16 ds:[rdi+0xe0], b16 xmm15
      [-]e0000000f30f7f
         // 0046cb7c: movdqu b16 ds:[rdi+0xf0], b16 xmm15
      [-]f000000081eb
         // 0046cb85: sub rbx, 0x100
      [-]890789441f
         // 0046cc9b: mov ds:[rdi], rax
         // 0046cc9e: mov ds:[rdi+rbx+0xfffffffffffffff8], rax
      [-]10f30f7f
         // 0046ccbc: movdqu b16 ds:[rdi+rbx+0xffffffffffffffe0], b16 xmm15
      [-]1fe0f30f7f
         // 0046ccc3: movdqu b16 ds:[rdi+rbx+0xfffffffffffffff0], b16 xmm15
      [-]10f30f7f
         // 0046ccd6: movdqu b16 ds:[rdi+0x20], b16 xmm15
      [-]20f30f7f
         // 0046ccdc: movdqu b16 ds:[rdi+0x30], b16 xmm15
      [-]30f30f7f
         // 0046cce2: movdqu b16 ds:[rdi+rbx+0xffffffffffffffc0], b16 xmm15
      [-]1fc0f30f7f
         // 0046cce9: movdqu b16 ds:[rdi+rbx+0xffffffffffffffd0], b16 xmm15
      [-]1fd0f30f7f
         // 0046ccf0: movdqu b16 ds:[rdi+rbx+0xffffffffffffffe0], b16 xmm15
      [-]1fe0f30f7f
         // 0046ccf7: movdqu b16 ds:[rdi+rbx+0xfffffffffffffff0], b16 xmm15
      [-]10f30f7f
         // 0046cd0a: movdqu b16 ds:[rdi+0x20], b16 xmm15
      [-]20f30f7f
         // 0046cd10: movdqu b16 ds:[rdi+0x30], b16 xmm15
      [-]30f30f7f
         // 0046cd16: movdqu b16 ds:[rdi+0x40], b16 xmm15
      [-]40f30f7f
         // 0046cd1c: movdqu b16 ds:[rdi+0x50], b16 xmm15
      [-]50f30f7f
         // 0046cd22: movdqu b16 ds:[rdi+0x60], b16 xmm15
      [-]60f30f7f
         // 0046cd28: movdqu b16 ds:[rdi+0x70], b16 xmm15
      [-]70f30f7f
         // 0046cd2e: movdqu b16 ds:[rdi+rbx+0xffffffffffffff80], b16 xmm15
      [-]1f80f30f7f
         // 0046cd35: movdqu b16 ds:[rdi+rbx+0xffffffffffffff90], b16 xmm15
      [-]1f90f30f7f
         // 0046cd3c: movdqu b16 ds:[rdi+rbx+0xffffffffffffffa0], b16 xmm15
      [-]1fa0f30f7f
         // 0046cd43: movdqu b16 ds:[rdi+rbx+0xffffffffffffffb0], b16 xmm15
      [-]1fb0f30f7f
         // 0046cd4a: movdqu b16 ds:[rdi+rbx+0xffffffffffffffc0], b16 xmm15
      [-]1fc0f30f7f
         // 0046cd51: movdqu b16 ds:[rdi+rbx+0xffffffffffffffd0], b16 xmm15
      [-]1fd0f30f7f
         // 0046cd58: movdqu b16 ds:[rdi+rbx+0xffffffffffffffe0], b16 xmm15
      [-]1fe0f30f7f
         // 0046cd5f: movdqu b16 ds:[rdi+rbx+0xfffffffffffffff0], b16 xmm15
      [-]85db0f84
         // 0046cd89: test rbx, rbx
         // 0046cd8c: jz 0x46ce89
      [-]83fb020f86
         // 0046cd92: cmp rbx, 0x2
         // 0046cd96: jbe 0x46ce7c
      [-]83fb200f86
         // 0046cdc6: cmp rbx, 0x20
         // 0046cdca: jbe 0x46cec1
      [-]83fb400f86
         // 0046cdd0: cmp rbx, 0x40
         // 0046cdd4: jbe 0x46ced6
      [-]89f009f8a9
         // 0046ce1c: mov b4 eax, b4 esi
         // 0046ce1e: or b4 eax, b4 edi
         // 0046ce20: test b4 eax, b4 0x7
      [-]89d9f3a4c3
         // 0046ce27: mov rcx, rbx
         // 0046ce2a: rep movsbb 
         // 0046ce2c: retn 
      [-]89d9c1e9
         // 0046e48d: mov rcx, rbx
         // 0046e490: shr rcx, b1 0x3
      [-]89f101d939f976
         // 0046ce40: mov rcx, rsi
         // 0046ce43: add rcx, rbx
         // 0046ce46: cmp rcx, rdi
         // 0046ce49: jbe 0x46ce06
      [-]01df01defd89d9c1e9
         // 0046e4ab: add rdi, rbx
         // 0046e4ae: add rsi, rbx
         // 0046e4b1: std 
         // 0046e4b2: mov rcx, rbx
         // 0046e4b5: shr rcx, b1 0x3
      [-]29df29dee9
         // 0046e4d1: sub rdi, rbx
         // 0046e4d4: sub rsi, rbx
         // 0046e4d7: jmp 0x46e3e9
      [-]8a068a4c1eff8807884c1fffc3
         // 0046ce7c: mov b1 al, b1 ds:[rsi]
         // 0046ce7e: mov b1 cl, b1 ds:[rsi+rbx+0xffffffffffffffff]
         // 0046ce82: mov b1 ds:[rdi], b1 al
         // 0046ce84: mov b1 ds:[rdi+rbx+0xffffffffffffffff], b1 cl
         // 0046ce88: retn 
      [-]668b068a4e02668907884f02c3
         // 0046ce8f: mov b2 ax, b2 ds:[rsi]
         // 0046ce92: mov b1 cl, b1 ds:[rsi+0x2]
         // 0046ce95: mov b2 ds:[rdi], b2 ax
         // 0046ce98: mov b1 ds:[rdi+0x2], b1 cl
         // 0046ce9b: retn 
      [-]8b068907c3
         // 0046cea9: mov rax, ds:[rsi]
         // 0046ceac: mov ds:[rdi], rax
         // 0046ceaf: retn 
      [-]8b068b4c1e
         // 0046ceb0: mov rax, ds:[rsi]
         // 0046ceb3: mov rcx, ds:[rsi+rbx+0xfffffffffffffff8]
      [-]8907894c1f
         // 0046ceb8: mov ds:[rdi], rax
         // 0046cebb: mov ds:[rdi+rbx+0xfffffffffffffff8], rcx
      [-]f30f6f06f30f6f4c1ef0f30f7f07f30f7f4c1ff0c3
         // 0046cec1: movdqu b16 xmm0, b16 ds:[rsi]
         // 0046cec5: movdqu b16 xmm1, b16 ds:[rsi+rbx+0xfffffffffffffff0]
         // 0046cecb: movdqu b16 ds:[rdi], b16 xmm0
         // 0046cecf: movdqu b16 ds:[rdi+rbx+0xfffffffffffffff0], b16 xmm1
         // 0046ced5: retn 
      [-]f30f6f06f30f6f4e10f30f6f541ee0f30f6f5c1ef0f30f7f07f30f7f4f10f30f7f541fe0f30f7f5c1ff0c3
         // 0046ced6: movdqu b16 xmm0, b16 ds:[rsi]
         // 0046ceda: movdqu b16 xmm1, b16 ds:[rsi+0x10]
         // 0046cedf: movdqu b16 xmm2, b16 ds:[rsi+rbx+0xffffffffffffffe0]
         // 0046cee5: movdqu b16 xmm3, b16 ds:[rsi+rbx+0xfffffffffffffff0]
         // 0046ceeb: movdqu b16 ds:[rdi], b16 xmm0
         // 0046ceef: movdqu b16 ds:[rdi+0x10], b16 xmm1
         // 0046cef4: movdqu b16 ds:[rdi+rbx+0xffffffffffffffe0], b16 xmm2
         // 0046cefa: movdqu b16 ds:[rdi+rbx+0xfffffffffffffff0], b16 xmm3
         // 0046cf00: retn 
      [-]f30f6f06f30f6f4e10f30f6f5620f30f6f5e30f30f6f641ec0f30f6f6c1ed0f30f6f741ee0f30f6f7c1ef0f30f7f07f30f7f4f10f30f7f5720f30f7f5f30f30f7f641fc0f30f7f6c1fd0f30f7f741fe0f30f7f7c1ff0c3
         // 0046cf01: movdqu b16 xmm0, b16 ds:[rsi]
         // 0046cf05: movdqu b16 xmm1, b16 ds:[rsi+0x10]
         // 0046cf0a: movdqu b16 xmm2, b16 ds:[rsi+0x20]
         // 0046cf0f: movdqu b16 xmm3, b16 ds:[rsi+0x30]
         // 0046cf14: movdqu b16 xmm4, b16 ds:[rsi+rbx+0xffffffffffffffc0]
         // 0046cf1a: movdqu b16 xmm5, b16 ds:[rsi+rbx+0xffffffffffffffd0]
         // 0046cf20: movdqu b16 xmm6, b16 ds:[rsi+rbx+0xffffffffffffffe0]
         // 0046cf26: movdqu b16 xmm7, b16 ds:[rsi+rbx+0xfffffffffffffff0]
         // 0046cf2c: movdqu b16 ds:[rdi], b16 xmm0
         // 0046cf30: movdqu b16 ds:[rdi+0x10], b16 xmm1
         // 0046cf35: movdqu b16 ds:[rdi+0x20], b16 xmm2
         // 0046cf3a: movdqu b16 ds:[rdi+0x30], b16 xmm3
         // 0046cf3f: movdqu b16 ds:[rdi+rbx+0xffffffffffffffc0], b16 xmm4
         // 0046cf45: movdqu b16 ds:[rdi+rbx+0xffffffffffffffd0], b16 xmm5
         // 0046cf4b: movdqu b16 ds:[rdi+rbx+0xffffffffffffffe0], b16 xmm6
         // 0046cf51: movdqu b16 ds:[rdi+rbx+0xfffffffffffffff0], b16 xmm7
         // 0046cf57: retn 
      [-]0f114424
         // 0047aa42: movups b16 ss:[esp+0x1c], b16 xmm0
      [-]0f11bc24
         // 0047aa65: movups b16 ss:[esp+0x8c], b16 xmm7
      [-]0000000f
         // 0047aa7a: movups b16 xmm6, b16 ss:[esp+0x7c]
      [-]008d4424
         // 0046daf2: lea rax, ss:[rsp+0x18]
      [-]00894424
         // 0046db00: mov ss:[rsp+0x8], rax
      [-]83ec188b
         // 00471dca: sub rsp, 0x18
         // 00471dce: mov r12, ds:[r14+0x20]
      [-]83c418c3
         // 00471df3: add rsp, 0x18
         // 00471df8: retn 
      [-]660f2ec175
         // 00471928: ucomisd b16 xmm0, b16 xmm1
         // 0047192c: jnz 0x4719a1
      [-]08f20f10
         // 00472d35: movsd b16 xmm1, ds:[rbx+0x8]
      [-]08660f2ec875
         // 00472d3a: ucomisd b16 xmm1, b16 xmm0
         // 00472d40: jnz 0x472da1
      [-]10f20f10
         // 00471949: movsd b16 xmm1, ds:[rbx+0x10]
      [-]10660f2ec875
         // 0047194e: ucomisd b16 xmm1, b16 xmm0
         // 00471952: jnz 0x4719a1
      [-]18f20f10
         // 0047195b: movsd b16 xmm1, ds:[rbx+0x18]
      [-]18660f2ec175
         // 00471960: ucomisd b16 xmm0, b16 xmm1
         // 00471964: jnz 0x4719a1
      [-]20f20f10
         // 0047196d: movsd b16 xmm1, ds:[rbx+0x20]
      [-]20660f2ec175
         // 00471972: ucomisd b16 xmm0, b16 xmm1
         // 00471976: jnz 0x4719a1
      [-]28f20f10
         // 0047197f: movsd b16 xmm1, ds:[rbx+0x28]
      [-]28660f2ec175
         // 00471984: ucomisd b16 xmm0, b16 xmm1
         // 00471988: jnz 0x4719a1
      [-]310f94c0
         // 00472d9c: setz b1 al
      [-]8914248d
         // 004a7d17: mov ss:[esp], edx
         // 004a7d1a: lea ecx, ss:[esp+0x18]
      [-]008d4424
         // 004a7d27: lea eax, ss:[esp+0x10]
      [-]008b5424
         // 004a76e0: mov rdx, ss:[rsp+0x48]
      [-]85c00f85
         // 004a7860: test rax, rax
         // 004a7863: jnz 0x4a78f7
      [-]b8????????
         // 0063c925: mov b4 eax, b4 0x1
      [-]008b5424
         // 004a78dd: mov rdx, ss:[rsp+0x48]
      [-]008b5424
         // 004a7906: mov rdx, ss:[rsp+0x48]
      [-]b8????????
         // 005a0cd7: mov eax, 0x104
      [-]31c089c1e8
         // 004a7d54: xor b4 eax, b4 eax
         // 004a7d56: mov rcx, rax
         // 004a7d59: call runtime.panicIndex
      [-]44242489
         // 004f3bd0: mov eax, ss:[esp+0x24]
         // 004f3bd4: mov ss:[esp+0x4], eax
      [-]31c089c1e8
         // 004a853f: xor b4 eax, b4 eax
         // 004a8541: mov rcx, rax
         // 004a8544: call runtime.panicIndex
      [-]85c00f85
         // 005a1346: test eax, eax
         // 005a1348: jnz 0x5a13e4

  }
  condition:
    all of them
}
