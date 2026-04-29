rule hive_50_0 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         8b4424088b4c240c0fa289442410895c2414894c24188954241cc3
         // 00401ba0: mov b4 eax, b4 ss:[rsp+0x8]
         // 00401ba4: mov b4 ecx, b4 ss:[rsp+0xc]
         // 00401ba8: cpuid 
         // 00401baa: mov b4 ss:[rsp+0x10], b4 eax
         // 00401bae: mov b4 ss:[rsp+0x14], b4 ebx
         // 00401bb2: mov b4 ss:[rsp+0x18], b4 ecx
         // 00401bb6: mov b4 ss:[rsp+0x1c], b4 edx
         // 00401bba: retn 
      [-]b9????????0f01d0894424088954240cc3
         // 00401bc0: mov b4 ecx, b4 0x0
         // 00401bc5: xgetbv 
         // 00401bc8: mov b4 ss:[rsp+0x8], b4 eax
         // 00401bcc: mov b4 ss:[rsp+0xc], b4 edx
         // 00401bd0: retn 
      [-]493b66107663
         // 00401be0: cmp rsp, ds:[r14+0x10]
         // 00401be4: jbe 0x401c49
      [-]4883ec2048896c2418488d6c2418488b4808488b13488b30669048394b087519
         // 00401be6: sub rsp, 0x20
         // 00401bea: mov ss:[rsp+0x18], rbp
         // 00401bef: lea rbp, ss:[rsp+0x18]
         // 00401bf4: mov rcx, ds:[rax+0x8]
         // 00401bf8: mov rdx, ds:[rbx]
         // 00401bfb: mov rsi, ds:[rax]
         // 00401bfe: xchg b2 ax, b2 ax
         // 00401c00: cmp ds:[rbx+0x8], rcx
         // 00401c04: jnz 0x401c1f
      [-]488944242848895c24304889f04889d3e8e50d000084c07504
         // 00401c06: mov ss:[rsp+0x28], rax
         // 00401c0b: mov ss:[rsp+0x30], rbx
         // 00401c10: mov rax, rsi
         // 00401c13: mov rbx, rdx
         // 00401c16: call runtime.memequal
         // 00401c1b: test b1 al, b1 al
         // 00401c1d: jnz 0x401c23
      [-]31c0eb1c
         // 00401c1f: xor b4 eax, b4 eax
         // 00401c21: jmp 0x401c3f
      [-]488b542428488d4210488b542430488d5a10b9????????e8c10d0000
         // 00401c23: mov rdx, ss:[rsp+0x28]
         // 00401c28: lea rax, ds:[rdx+0x10]
         // 00401c2c: mov rdx, ss:[rsp+0x30]
         // 00401c31: lea rbx, ds:[rdx+0x10]
         // 00401c35: mov b4 ecx, b4 0xb
         // 00401c3a: call runtime.memequal
      [-]488b6c24184883c420c3
         // 00401c3f: mov rbp, ss:[rsp+0x18]
         // 00401c44: add rsp, 0x20
         // 00401c48: retn 
      [-]488944240848895c2410e8e8e10500488b442408488b5c2410e979ffffff
         // 00401c49: mov ss:[rsp+0x8], rax
         // 00401c4e: mov ss:[rsp+0x10], rbx
         // 00401c53: call runtime.morestack_noctxt
         // 00401c58: mov rax, ss:[rsp+0x8]
         // 00401c5d: mov rbx, ss:[rsp+0x10]
         // 00401c62: jmp type..eq.internal_cpu.option
      [-]493b6610766f
         // 00401c80: cmp rsp, ds:[r14+0x10]
         // 00401c84: jbe 0x401cf5
      [-]4883ec2048896c2418488d6c2418488944242848895c243031c9eb13
         // 00401c86: sub rsp, 0x20
         // 00401c8a: mov ss:[rsp+0x18], rbp
         // 00401c8f: lea rbp, ss:[rsp+0x18]
         // 00401c94: mov ss:[rsp+0x28], rax
         // 00401c99: mov ss:[rsp+0x30], rbx
         // 00401c9e: xor b4 ecx, b4 ecx
         // 00401ca0: jmp 0x401cb5
      [-]488b542410488d4a01488b442428488b5c2430
         // 00401ca2: mov rdx, ss:[rsp+0x10]
         // 00401ca7: lea rcx, ds:[rdx+0x1]
         // 00401cab: mov rax, ss:[rsp+0x28]
         // 00401cb0: mov rbx, ss:[rsp+0x30]
      [-]4883f90f7d2b
         // 00401cb5: cmp rcx, 0xf
         // 00401cb9: jge 0x401ce6
      [-]48894c241048c1e105488d34014801d94889f04889cbe80affffff84c075c8
         // 00401cbb: mov ss:[rsp+0x10], rcx
         // 00401cc0: shl rcx, b1 0x5
         // 00401cc4: lea rsi, ds:[rcx+rax]
         // 00401cc8: add rcx, rbx
         // 00401ccb: mov rax, rsi
         // 00401cce: mov rbx, rcx
         // 00401cd1: call type..eq.internal_cpu.option
         // 00401cd6: test b1 al, b1 al
         // 00401cd8: jnz 0x401ca2
      [-]31c0488b6c24184883c420c3
         // 00401cda: xor b4 eax, b4 eax
         // 00401cdc: mov rbp, ss:[rsp+0x18]
         // 00401ce1: add rsp, 0x20
         // 00401ce5: retn 
      [-]b8????????488b6c24184883c420c3
         // 00401ce6: mov b4 eax, b4 0x1
         // 00401ceb: mov rbp, ss:[rsp+0x18]
         // 00401cf0: add rsp, 0x20
         // 00401cf4: retn 
      [-]488944240848895c241090e83be10500488b442408488b5c2410e96cffffff
         // 00401cf5: mov ss:[rsp+0x8], rax
         // 00401cfa: mov ss:[rsp+0x10], rbx
         // 00401cff: nop 
         // 00401d00: call runtime.morestack_noctxt
         // 00401d05: mov rax, ss:[rsp+0x8]
         // 00401d0a: mov rbx, ss:[rsp+0x10]
         // 00401d0f: jmp type..eq._15_internal_cpu.option
      [-]488718c3
         // 00401e60: xchg rbx, ds:[rax]
         // 00401e63: retn 
      [-]4839fe0f8422010000
         // 004024a0: cmp rsi, rdi
         // 004024a3: jz 0x4025cb
      [-]4839d34989d04c0f4cc34983f8080f82b6000000
         // 004024a9: cmp rbx, rdx
         // 004024ac: mov r8, rdx
         // 004024af: cmovl r8, rbx
         // 004024b3: cmp r8, 0x8
         // 004024b7: jb 0x402573
      [-]4983f83f7612
         // 004024bd: cmp r8, 0x3f
         // 004024c1: jbe 0x4024d5
      [-]803d59983100010f84a1010000
         // 004024c3: cmp b1 cs:[0x71bd23], b1 0x1
         // 004024ca: jz 0x402671
      [-]e90b010000
         // 004024d0: jmp 0x4025e0
      [-]4983f810765b
         // 004024d5: cmp r8, 0x10
         // 004024d9: jbe 0x402536
      [-]f30f6f06f30f6f0f660f74c8660fd7c14835ffff0000752a
         // 004024db: movdqu b16 xmm0, b16 ds:[rsi]
         // 004024df: movdqu b16 xmm1, b16 ds:[rdi]
         // 004024e3: pcmpeqb b16 xmm1, b16 xmm0
         // 004024e7: pmovmskb b4 eax, b16 xmm1
         // 004024eb: xor rax, 0xffff
         // 004024f1: jnz 0x40251d
      [-]4883c6104883c7104983e810ebd4
         // 004024f3: add rsi, 0x10
         // 004024f7: add rdi, 0x10
         // 004024fb: sub r8, 0x10
         // 004024ff: jmp 0x4024d5
      [-]4883c6304883c730eb12
         // 00402501: add rsi, 0x30
         // 00402505: add rdi, 0x30
         // 00402509: jmp 0x40251d
      [-]4883c6204883c720eb08
         // 0040250b: add rsi, 0x20
         // 0040250f: add rdi, 0x20
         // 00402513: jmp 0x40251d
      [-]4883c6104883c710
         // 00402515: add rsi, 0x10
         // 00402519: add rdi, 0x10
      [-]480fbcd84831c08a0c1e3a0c1f0f97c0488d0445ffffffffc3
         // 0040251d: bsf rbx, rax
         // 00402521: xor rax, rax
         // 00402524: mov b1 cl, b1 ds:[rsi+rbx]
         // 00402527: cmp b1 cl, b1 ds:[rdi+rbx]
         // 0040252a: setnbe b1 al
         // 0040252d: lea rax, ds:[0xffffffffffffffff+rax*0x2]
         // 00402535: retn 
      [-]4983f808760b
         // 00402536: cmp r8, 0x8
         // 0040253a: jbe 0x402547
      [-]488b06488b0f4839c8750f
         // 0040253c: mov rax, ds:[rsi]
         // 0040253f: mov rcx, ds:[rdi]
         // 00402542: cmp rax, rcx
         // 00402545: jnz 0x402556
      [-]4a8b4406f84a8b4c07f84839c87475
         // 00402547: mov rax, ds:[rsi+r8+0xfffffffffffffff8]
         // 0040254c: mov rcx, ds:[rdi+r8+0xfffffffffffffff8]
         // 00402551: cmp rax, rcx
         // 00402554: jz 0x4025cb
      [-]480fc8480fc94831c1480fbdc948d3e84883e001488d0445ffffffffc3
         // 00402556: bswap rax
         // 00402559: bswap rcx
         // 0040255c: xor rcx, rax
         // 0040255f: bsr rcx, rcx
         // 00402563: shr rax, b1 cl
         // 00402566: and rax, 0x1
         // 0040256a: lea rax, ds:[0xffffffffffffffff+rax*0x2]
         // 00402572: retn 
      [-]4a8d0cc50000000048f7d9744b
         // 00402573: lea rcx, ds:[r8*0x8]
         // 0040257b: neg rcx
         // 0040257e: jz 0x4025cb
      [-]4080fef87705
         // 00402580: cmp b1 sil, b1 0xf8
         // 00402584: ja 0x40258b
      [-]488b36eb08
         // 00402586: mov rsi, ds:[rsi]
         // 00402589: jmp 0x402593
      [-]4a8b7406f848d3ee
         // 0040258b: mov rsi, ds:[rsi+r8+0xfffffffffffffff8]
         // 00402590: shr rsi, b1 cl
      [-]48d3e64080fff87705
         // 00402593: shl rsi, b1 cl
         // 00402596: cmp b1 dil, b1 0xf8
         // 0040259a: ja 0x4025a1
      [-]488b3feb08
         // 0040259c: mov rdi, ds:[rdi]
         // 0040259f: jmp 0x4025a9
      [-]4a8b7c07f848d3ef
         // 004025a1: mov rdi, ds:[rdi+r8+0xfffffffffffffff8]
         // 004025a6: shr rdi, b1 cl
      [-]48d3e7480fce480fcf4831f77414
         // 004025a9: shl rdi, b1 cl
         // 004025ac: bswap rsi
         // 004025af: bswap rdi
         // 004025b2: xor rdi, rsi
         // 004025b5: jz 0x4025cb
      [-]480fbdcf48d3ee4883e601488d0475ffffffffc3
         // 004025b7: bsr rcx, rdi
         // 004025bb: shr rsi, b1 cl
         // 004025be: and rsi, 0x1
         // 004025c2: lea rax, ds:[0xffffffffffffffff+rsi*0x2]
         // 004025ca: retn 
      [-]4831c04831c94839d30f9fc00f94c1488d4441ffc3
         // 004025cb: xor rax, rax
         // 004025ce: xor rcx, rcx
         // 004025d1: cmp rbx, rdx
         // 004025d4: setnle b1 al
         // 004025d7: setz b1 cl
         // 004025da: lea rax, ds:[rcx+rax*0x2]
         // 004025df: retn 
      [-]f30f6f06f30f6f0f660f74c8660fd7c14835ffff00000f8521ffffff
         // 004025e0: movdqu b16 xmm0, b16 ds:[rsi]
         // 004025e4: movdqu b16 xmm1, b16 ds:[rdi]
         // 004025e8: pcmpeqb b16 xmm1, b16 xmm0
         // 004025ec: pmovmskb b4 eax, b16 xmm1
         // 004025f0: xor rax, 0xffff
         // 004025f6: jnz 0x40251d
      [-]f30f6f4610f30f6f4f10660f74c8660fd7c14835ffff00000f85fbfeffff
         // 004025fc: movdqu b16 xmm0, b16 ds:[rsi+0x10]
         // 00402601: movdqu b16 xmm1, b16 ds:[rdi+0x10]
         // 00402606: pcmpeqb b16 xmm1, b16 xmm0
         // 0040260a: pmovmskb b4 eax, b16 xmm1
         // 0040260e: xor rax, 0xffff
         // 00402614: jnz 0x402515
      [-]f30f6f4620f30f6f4f20660f74c8660fd7c14835ffff00000f85d3feffff
         // 0040261a: movdqu b16 xmm0, b16 ds:[rsi+0x20]
         // 0040261f: movdqu b16 xmm1, b16 ds:[rdi+0x20]
         // 00402624: pcmpeqb b16 xmm1, b16 xmm0
         // 00402628: pmovmskb b4 eax, b16 xmm1
         // 0040262c: xor rax, 0xffff
         // 00402632: jnz 0x40250b
      [-]f30f6f4630f30f6f4f30660f74c8660fd7c14835ffff00000f85abfeffff
         // 00402638: movdqu b16 xmm0, b16 ds:[rsi+0x30]
         // 0040263d: movdqu b16 xmm1, b16 ds:[rdi+0x30]
         // 00402642: pcmpeqb b16 xmm1, b16 xmm0
         // 00402646: pmovmskb b4 eax, b16 xmm1
         // 0040264a: xor rax, 0xffff
         // 00402650: jnz 0x402501
      [-]4883c6404883c7404983e8404983f8400f8669feffff
         // 00402656: add rsi, 0x40
         // 0040265a: add rdi, 0x40
         // 0040265e: sub r8, 0x40
         // 00402662: cmp r8, 0x40
         // 00402666: jbe 0x4024d5
      [-]e96fffffff
         // 0040266c: jmp 0x4025e0
      [-]c5fe6f16c5fe6f1fc5fe6f6620c5fe6f6f20c5e574c2c5fdd7c035????????7523
         // 00402671: vmovdqu b32 ymm2, b32 ds:[rsi]
         // 00402675: vmovdqu b32 ymm3, b32 ds:[rdi]
         // 00402679: vmovdqu b32 ymm4, b32 ds:[rsi+0x20]
         // 0040267e: vmovdqu b32 ymm5, b32 ds:[rdi+0x20]
         // 00402683: vpcmpeqb b32 ymm0, b32 ymm3, b32 ymm2
         // 00402687: vpmovmskb b4 eax, b32 ymm0
         // 0040268b: xor b4 eax, b4 0xffffffffffffffff
         // 00402690: jnz 0x4026b5
      [-]c5d574f4c5fdd7c635????????751c
         // 00402692: vpcmpeqb b32 ymm6, b32 ymm5, b32 ymm4
         // 00402696: vpmovmskb b4 eax, b32 ymm6
         // 0040269a: xor b4 eax, b4 0xffffffffffffffff
         // 0040269f: jnz 0x4026bd
      [-]4883c6404883c7404983e8404983f8407212
         // 004026a1: add rsi, 0x40
         // 004026a5: add rdi, 0x40
         // 004026a9: sub r8, 0x40
         // 004026ad: cmp r8, 0x40
         // 004026b1: jb 0x4026c5
      [-]c5f877e960feffff
         // 004026b5: vzeroupper 
         // 004026b8: jmp 0x40251d
      [-]c5f877e946feffff
         // 004026bd: vzeroupper 
         // 004026c0: jmp 0x40250b
      [-]c5f877e908feffff
         // 004026c5: vzeroupper 
         // 004026c8: jmp 0x4024d5
      [-]4889c64889fa4889cfe9b2fdffff
         // 004026e0: mov rsi, rax
         // 004026e3: mov rdx, rdi
         // 004026e6: mov rdi, rcx
         // 004026e9: jmp cmpbody
      [-]66480f6ec0660f60c0660f60c0660f70c0004883fb107c6e
         // 00402700: movq b16 xmm0, rax
         // 00402705: punpcklbw b16 xmm0, b16 xmm0
         // 00402709: punpcklbw b16 xmm0, b16 xmm0
         // 0040270d: pshufd b16 xmm0, b16 xmm0, b1 0x0
         // 00402712: cmp rbx, 0x10
         // 00402716: jl 0x402786
      [-]49c7c4000000004889f74883fb200f87c8000000
         // 00402718: mov r12, 0x0
         // 0040271f: mov rdi, rsi
         // 00402722: cmp rbx, 0x20
         // 00402726: ja 0x4027f4
      [-]488d441ef0eb17
         // 0040272c: lea rax, ds:[rsi+rbx+0xfffffffffffffff0]
         // 00402731: jmp 0x40274a
      [-]f30f6f0f660f74c8660fd7d1f30fb8d24901d44883c710
         // 00402733: movdqu b16 xmm1, b16 ds:[rdi]
         // 00402737: pcmpeqb b16 xmm1, b16 xmm0
         // 0040273b: pmovmskb b4 edx, b16 xmm1
         // 0040273f: popcnt b4 edx, b4 edx
         // 00402743: add r12, rdx
         // 00402746: add rdi, 0x10
      [-]4839c776e4
         // 0040274a: cmp rdi, rax
         // 0040274d: jbe 0x402733
      [-]4883e30f742d
         // 0040274f: and rbx, 0xf
         // 00402753: jz 0x402782
      [-]48c7c1100000004829d949c7c2ffff000049d3fa49d3e2f30f6f08660f74c8660fd7d14c21d2f30fb8d24901d4
         // 00402755: mov rcx, 0x10
         // 0040275c: sub rcx, rbx
         // 0040275f: mov r10, 0xffff
         // 00402766: sar r10, b1 cl
         // 00402769: shl r10, b1 cl
         // 0040276c: movdqu b16 xmm1, b16 ds:[rax]
         // 00402770: pcmpeqb b16 xmm1, b16 xmm0
         // 00402774: pmovmskb b4 edx, b16 xmm1
         // 00402778: and rdx, r10
         // 0040277b: popcnt b4 edx, b4 edx
         // 0040277f: add r12, rdx
      [-]4d8920c3
         // 00402782: mov ds:[r8], r12
         // 00402785: retn 
      [-]4885db7431
         // 00402786: test rbx, rbx
         // 00402789: jz 0x4027bc
      [-]488d461066a9f00f742f
         // 0040278b: lea rax, ds:[rsi+0x10]
         // 0040278f: test b2 ax, b2 0xff0
         // 00402793: jz 0x4027c4
      [-]88d949c7c20100000049d3e24983ea01f30f6f0e660f74c8660fd7d14c21d2f30fb8d2498910c3
         // 00402795: mov b1 cl, b1 bl
         // 00402797: mov r10, 0x1
         // 0040279e: shl r10, b1 cl
         // 004027a1: sub r10, 0x1
         // 004027a5: movdqu b16 xmm1, b16 ds:[rsi]
         // 004027a9: pcmpeqb b16 xmm1, b16 xmm0
         // 004027ad: pmovmskb b4 edx, b16 xmm1
         // 004027b1: and rdx, r10
         // 004027b4: popcnt b4 edx, b4 edx
         // 004027b8: mov ds:[r8], rdx
         // 004027bb: retn 
      [-]49c70000000000c3
         // 004027bc: mov ds:[r8], 0x0
         // 004027c3: retn 
      [-]48c7c1100000004829d949c7c2ffff000049d3fa49d3e2f30f6f4c1ef0660f74c8660fd7d14c21d2f30fb8d2498910c3
         // 004027c4: mov rcx, 0x10
         // 004027cb: sub rcx, rbx
         // 004027ce: mov r10, 0xffff
         // 004027d5: sar r10, b1 cl
         // 004027d8: shl r10, b1 cl
         // 004027db: movdqu b16 xmm1, b16 ds:[rsi+rbx+0xfffffffffffffff0]
         // 004027e1: pcmpeqb b16 xmm1, b16 xmm0
         // 004027e5: pmovmskb b4 edx, b16 xmm1
         // 004027e9: and rdx, r10
         // 004027ec: popcnt b4 edx, b4 edx
         // 004027f0: mov ds:[r8], rdx
         // 004027f3: retn 
      [-]803d28953100010f852bffffff
         // 004027f4: cmp b1 cs:[0x71bd23], b1 0x1
         // 004027fb: jnz 0x40272c
      [-]66480f6ec04c8d5c1ee0c4e27d78c8
         // 00402801: movq b16 xmm0, rax
         // 00402806: lea r11, ds:[rsi+rbx+0xffffffffffffffe0]
         // 0040280b: vpbroadcastb b32 ymm1, b16 xmm0
      [-]c5fe6f17c5ed74d9c5fdd7d3f30fb8d24901d44883c7204c39df7ee4
         // 00402810: vmovdqu b32 ymm2, b32 ds:[rdi]
         // 00402814: vpcmpeqb b32 ymm3, b32 ymm2, b32 ymm1
         // 00402818: vpmovmskb b4 edx, b32 ymm3
         // 0040281c: popcnt b4 edx, b4 edx
         // 00402820: add r12, rdx
         // 00402823: add rdi, 0x20
         // 00402827: cmp rdi, r11
         // 0040282a: jle 0x402810
      [-]4c39df743a
         // 0040282c: cmp rdi, r11
         // 0040282f: jz 0x40286b
      [-]4c89dfc5fe6f17c5ed74d9c5fdd7d3c5f8774883e31f48c7c1200000004829d941ba????????49d3fa49d3e24c21d2f30fb8d24901d44d8920c3
         // 00402831: mov rdi, r11
         // 00402834: vmovdqu b32 ymm2, b32 ds:[rdi]
         // 00402838: vpcmpeqb b32 ymm3, b32 ymm2, b32 ymm1
         // 0040283c: vpmovmskb b4 edx, b32 ymm3
         // 00402840: vzeroupper 
         // 00402843: and rbx, 0x1f
         // 00402847: mov rcx, 0x20
         // 0040284e: sub rcx, rbx
         // 00402851: mov b4 r10d, b4 0xffffffffffffffff
         // 00402857: sar r10, b1 cl
         // 0040285a: shl r10, b1 cl
         // 0040285d: and rdx, r10
         // 00402860: popcnt b4 edx, b4 edx
         // 00402864: add r12, rdx
         // 00402867: mov ds:[r8], r12
         // 0040286a: retn 
      [-]c5f8774d8920c3
         // 0040286b: vzeroupper 
         // 0040286e: mov ds:[r8], r12
         // 00402871: retn 
      [-]803da3943100017405
         // 00402880: cmp b1 cs:[0x71bd2a], b1 0x1
         // 00402887: jz 0x40288e
      [-]e992060000
         // 00402889: jmp internal_bytealg.countGenericString_0
      [-]488b742408488b5c24108a4424184c8d442420e95afeffff
         // 0040288e: mov rsi, ss:[rsp+0x8]
         // 00402893: mov rbx, ss:[rsp+0x10]
         // 00402898: mov b1 al, b1 ss:[rsp+0x18]
         // 0040289c: lea r8, ss:[rsp+0x20]
         // 004028a1: jmp countbody
      [-]4883fb080f82f3000000
         // 004028c0: cmp rbx, 0x8
         // 004028c4: jb 0x4029bd
      [-]4883fb400f82b7000000
         // 004028ca: cmp rbx, 0x40
         // 004028ce: jb 0x40298b
      [-]803d48943100017468
         // 004028d4: cmp b1 cs:[0x71bd23], b1 0x1
         // 004028db: jz 0x402945
      [-]4883fb400f82a4000000
         // 004028dd: cmp rbx, 0x40
         // 004028e1: jb 0x40298b
      [-]f30f6f06f30f6f0ff30f6f5610f30f6f5f10f30f6f6620f30f6f6f20f30f6f7630f30f6f7f30660f74c1660f74d3660f74e5660f74f7660fdbc2660fdbe6660fdbc4660fd7d04883c6404883c7404883eb4081fa????????749c
         // 004028e7: movdqu b16 xmm0, b16 ds:[rsi]
         // 004028eb: movdqu b16 xmm1, b16 ds:[rdi]
         // 004028ef: movdqu b16 xmm2, b16 ds:[rsi+0x10]
         // 004028f4: movdqu b16 xmm3, b16 ds:[rdi+0x10]
         // 004028f9: movdqu b16 xmm4, b16 ds:[rsi+0x20]
         // 004028fe: movdqu b16 xmm5, b16 ds:[rdi+0x20]
         // 00402903: movdqu b16 xmm6, b16 ds:[rsi+0x30]
         // 00402908: movdqu b16 xmm7, b16 ds:[rdi+0x30]
         // 0040290d: pcmpeqb b16 xmm0, b16 xmm1
         // 00402911: pcmpeqb b16 xmm2, b16 xmm3
         // 00402915: pcmpeqb b16 xmm4, b16 xmm5
         // 00402919: pcmpeqb b16 xmm6, b16 xmm7
         // 0040291d: pand b16 xmm0, b16 xmm2
         // 00402921: pand b16 xmm4, b16 xmm6
         // 00402925: pand b16 xmm0, b16 xmm4
         // 00402929: pmovmskb b4 edx, b16 xmm0
         // 0040292d: add rsi, 0x40
         // 00402931: add rdi, 0x40
         // 00402935: sub rbx, 0x40
         // 00402939: cmp b4 edx, b4 0xffff
         // 0040293f: jz 0x4028dd
      [-]4831c0c3
         // 00402941: xor rax, rax
         // 00402944: retn 
      [-]4883fb40723d
         // 00402945: cmp rbx, 0x40
         // 00402949: jb 0x402988
      [-]c5fe6f06c5fe6f0fc5fe6f5620c5fe6f5f20c5fd74e1c5e574eac5d5dbf4c5fdd7d64883c6404883c7404883eb4081fa????????74c4
         // 0040294b: vmovdqu b32 ymm0, b32 ds:[rsi]
         // 0040294f: vmovdqu b32 ymm1, b32 ds:[rdi]
         // 00402953: vmovdqu b32 ymm2, b32 ds:[rsi+0x20]
         // 00402958: vmovdqu b32 ymm3, b32 ds:[rdi+0x20]
         // 0040295d: vpcmpeqb b32 ymm4, b32 ymm0, b32 ymm1
         // 00402961: vpcmpeqb b32 ymm5, b32 ymm3, b32 ymm2
         // 00402965: vpand b32 ymm6, b32 ymm5, b32 ymm4
         // 00402969: vpmovmskb b4 edx, b32 ymm6
         // 0040296d: add rsi, 0x40
         // 00402971: add rdi, 0x40
         // 00402975: sub rbx, 0x40
         // 00402979: cmp b4 edx, b4 0xffffffffffffffff
         // 0040297f: jz 0x402945
      [-]c5f8774831c0c3
         // 00402981: vzeroupper 
         // 00402984: xor rax, rax
         // 00402987: retn 
      [-]4883fb08761b
         // 0040298b: cmp rbx, 0x8
         // 0040298f: jbe 0x4029ac
      [-]488b0e488b174883c6084883c7084883eb084839d174e3
         // 00402991: mov rcx, ds:[rsi]
         // 00402994: mov rdx, ds:[rdi]
         // 00402997: add rsi, 0x8
         // 0040299b: add rdi, 0x8
         // 0040299f: sub rbx, 0x8
         // 004029a3: cmp rcx, rdx
         // 004029a6: jz 0x40298b
      [-]4831c0c3
         // 004029a8: xor rax, rax
         // 004029ab: retn 
      [-]488b4c1ef8488b541ff84839d10f94c0c3
         // 004029ac: mov rcx, ds:[rsi+rbx+0xfffffffffffffff8]
         // 004029b1: mov rdx, ds:[rdi+rbx+0xfffffffffffffff8]
         // 004029b6: cmp rcx, rdx
         // 004029b9: setz b1 al
         // 004029bc: retn 
      [-]4883fb007437
         // 004029bd: cmp rbx, 0x0
         // 004029c1: jz 0x4029fa
      [-]488d0cdd0000000048f7d94080fef87705
         // 004029c3: lea rcx, ds:[rbx*0x8]
         // 004029cb: neg rcx
         // 004029ce: cmp b1 sil, b1 0xf8
         // 004029d2: ja 0x4029d9
      [-]488b36eb08
         // 004029d4: mov rsi, ds:[rsi]
         // 004029d7: jmp 0x4029e1
      [-]488b741ef848d3ee
         // 004029d9: mov rsi, ds:[rsi+rbx+0xfffffffffffffff8]
         // 004029de: shr rsi, b1 cl
      [-]4080fff87705
         // 004029e1: cmp b1 dil, b1 0xf8
         // 004029e5: ja 0x4029ec
      [-]488b3feb08
         // 004029e7: mov rdi, ds:[rdi]
         // 004029ea: jmp 0x4029f4
      [-]488b7c1ff848d3ef
         // 004029ec: mov rdi, ds:[rdi+rbx+0xfffffffffffffff8]
         // 004029f1: shr rdi, b1 cl
      [-]4829f748d3e7
         // 004029f4: sub rdi, rsi
         // 004029f7: shl rdi, b1 cl
      [-]0f94c0c3
         // 004029fa: setz b1 al
         // 004029fd: retn 
      [-]4839d87508
         // 00402a00: cmp rax, rbx
         // 00402a03: jnz 0x402a0d
      [-]48c7c001000000c3
         // 00402a05: mov rax, 0x1
         // 00402a0c: retn 
      [-]4889c64889df4889cbe9a5feffff
         // 00402a0d: mov rsi, rax
         // 00402a10: mov rdi, rbx
         // 00402a13: mov rbx, rcx
         // 00402a16: jmp memeqbody
      [-]4839d87508
         // 00402a20: cmp rax, rbx
         // 00402a23: jnz 0x402a2d
      [-]48c7c001000000c3
         // 00402a25: mov rax, 0x1
         // 00402a2c: retn 
      [-]4889c64889df488b5a08e984feffff
         // 00402a2d: mov rsi, rax
         // 00402a30: mov rdi, rbx
         // 00402a33: mov rbx, ds:[rdx+0x8]
         // 00402a37: jmp memeqbody
      [-]4839d00f8777020000
         // 00402a40: cmp rax, rdx
         // 00402a43: ja 0x402cc0
      [-]4883fa100f837a020000
         // 00402a49: cmp rdx, 0x10
         // 00402a4d: jnb 0x402ccd
      [-]4883f8027724
         // 00402a53: cmp rax, 0x2
         // 00402a57: ja 0x402a7d
      [-]66458b00488d5417ff
         // 00402a59: mov b2 r8w, b2 ds:[r8]
         // 00402a5d: lea rdx, ds:[rdi+rdx+0xffffffffffffffff]
      [-]668b37664439c60f84be020000
         // 00402a62: mov b2 si, b2 ds:[rdi]
         // 00402a65: cmp b2 si, b2 r8w
         // 00402a69: jz 0x402d2d
      [-]4883c7014839d772ea
         // 00402a6f: add rdi, 0x1
         // 00402a73: cmp rdi, rdx
         // 00402a76: jb 0x402a62
      [-]e943020000
         // 00402a78: jmp 0x402cc0
      [-]4883f8037740
         // 00402a7d: cmp rax, 0x3
         // 00402a81: ja 0x402ac3
      [-]66418b580166458b00488d5417fe
         // 00402a83: mov b2 bx, b2 ds:[r8+0x1]
         // 00402a88: mov b2 r8w, b2 ds:[r8]
         // 00402a8c: lea rdx, ds:[rdi+rdx+0xfffffffffffffffe]
      [-]668b37664439c6740e
         // 00402a91: mov b2 si, b2 ds:[rdi]
         // 00402a94: cmp b2 si, b2 r8w
         // 00402a98: jz 0x402aa8
      [-]4883c7014839d772ee
         // 00402a9a: add rdi, 0x1
         // 00402a9e: cmp rdi, rdx
         // 00402aa1: jb 0x402a91
      [-]e918020000
         // 00402aa3: jmp 0x402cc0
      [-]668b77016639de0f8478020000
         // 00402aa8: mov b2 si, b2 ds:[rdi+0x1]
         // 00402aac: cmp b2 si, b2 bx
         // 00402aaf: jz 0x402d2d
      [-]4883c7014839d772d3
         // 00402ab5: add rdi, 0x1
         // 00402ab9: cmp rdi, rdx
         // 00402abc: jb 0x402a91
      [-]e9fd010000
         // 00402abe: jmp 0x402cc0
      [-]4883f8047721
         // 00402ac3: cmp rax, 0x4
         // 00402ac7: ja 0x402aea
      [-]458b00488d5417fd
         // 00402ac9: mov b4 r8d, b4 ds:[r8]
         // 00402acc: lea rdx, ds:[rdi+rdx+0xfffffffffffffffd]
      [-]8b374439c60f8451020000
         // 00402ad1: mov b4 esi, b4 ds:[rdi]
         // 00402ad3: cmp b4 esi, b4 r8d
         // 00402ad6: jz 0x402d2d
      [-]4883c7014839d772ec
         // 00402adc: add rdi, 0x1
         // 00402ae0: cmp rdi, rdx
         // 00402ae3: jb 0x402ad1
      [-]e9d6010000
         // 00402ae5: jmp 0x402cc0
      [-]4883f807773f
         // 00402aea: cmp rax, 0x7
         // 00402aee: ja 0x402b2f
      [-]488d5417014829c2418b5c00fc458b00
         // 00402af0: lea rdx, ds:[rdi+rdx+0x1]
         // 00402af5: sub rdx, rax
         // 00402af8: mov b4 ebx, b4 ds:[r8+rax+0xfffffffffffffffc]
         // 00402afd: mov b4 r8d, b4 ds:[r8]
      [-]8b374439c6740e
         // 00402b00: mov b4 esi, b4 ds:[rdi]
         // 00402b02: cmp b4 esi, b4 r8d
         // 00402b05: jz 0x402b15
      [-]4883c7014839d772f0
         // 00402b07: add rdi, 0x1
         // 00402b0b: cmp rdi, rdx
         // 00402b0e: jb 0x402b00
      [-]e9ab010000
         // 00402b10: jmp 0x402cc0
      [-]8b7438fc39de0f840c020000
         // 00402b15: mov b4 esi, b4 ds:[rax+rdi+0xfffffffffffffffc]
         // 00402b19: cmp b4 esi, b4 ebx
         // 00402b1b: jz 0x402d2d
      [-]4883c7014839d772d6
         // 00402b21: add rdi, 0x1
         // 00402b25: cmp rdi, rdx
         // 00402b28: jb 0x402b00
      [-]e991010000
         // 00402b2a: jmp 0x402cc0
      [-]4883f8087722
         // 00402b2f: cmp rax, 0x8
         // 00402b33: ja 0x402b57
      [-]4d8b00488d5417f9
         // 00402b35: mov r8, ds:[r8]
         // 00402b38: lea rdx, ds:[rdi+rdx+0xfffffffffffffff9]
      [-]488b374c39c60f84e4010000
         // 00402b3d: mov rsi, ds:[rdi]
         // 00402b40: cmp rsi, r8
         // 00402b43: jz 0x402d2d
      [-]4883c7014839d772eb
         // 00402b49: add rdi, 0x1
         // 00402b4d: cmp rdi, rdx
         // 00402b50: jb 0x402b3d
      [-]e969010000
         // 00402b52: jmp 0x402cc0
      [-]4883f80f7742
         // 00402b57: cmp rax, 0xf
         // 00402b5b: ja 0x402b9f
      [-]488d5417014829c2498b5c00f84d8b00
         // 00402b5d: lea rdx, ds:[rdi+rdx+0x1]
         // 00402b62: sub rdx, rax
         // 00402b65: mov rbx, ds:[r8+rax+0xfffffffffffffff8]
         // 00402b6a: mov r8, ds:[r8]
      [-]488b374c39c6740e
         // 00402b6d: mov rsi, ds:[rdi]
         // 00402b70: cmp rsi, r8
         // 00402b73: jz 0x402b83
      [-]4883c7014839d772ef
         // 00402b75: add rdi, 0x1
         // 00402b79: cmp rdi, rdx
         // 00402b7c: jb 0x402b6d
      [-]e93d010000
         // 00402b7e: jmp 0x402cc0
      [-]488b7438f84839de0f849c010000
         // 00402b83: mov rsi, ds:[rax+rdi+0xfffffffffffffff8]
         // 00402b88: cmp rsi, rbx
         // 00402b8b: jz 0x402d2d
      [-]4883c7014839d772d3
         // 00402b91: add rdi, 0x1
         // 00402b95: cmp rdi, rdx
         // 00402b98: jb 0x402b6d
      [-]e921010000
         // 00402b9a: jmp 0x402cc0
      [-]4883f8107731
         // 00402b9f: cmp rax, 0x10
         // 00402ba3: ja 0x402bd6
      [-]f3410f6f08488d5417f1
         // 00402ba5: movdqu b16 xmm1, b16 ds:[r8]
         // 00402baa: lea rdx, ds:[rdi+rdx+0xfffffffffffffff1]
      [-]f30f6f17660f74d1660fd7f24881feffff00000f8465010000
         // 00402baf: movdqu b16 xmm2, b16 ds:[rdi]
         // 00402bb3: pcmpeqb b16 xmm2, b16 xmm1
         // 00402bb7: pmovmskb b4 esi, b16 xmm2
         // 00402bbb: cmp rsi, 0xffff
         // 00402bc2: jz 0x402d2d
      [-]4883c7014839d772de
         // 00402bc8: add rdi, 0x1
         // 00402bcc: cmp rdi, rdx
         // 00402bcf: jb 0x402baf
      [-]e9ea000000
         // 00402bd1: jmp 0x402cc0
      [-]4883f81f7760
         // 00402bd6: cmp rax, 0x1f
         // 00402bda: ja 0x402c3c
      [-]488d5417014829c2f3410f6f4400f0f3410f6f08
         // 00402bdc: lea rdx, ds:[rdi+rdx+0x1]
         // 00402be1: sub rdx, rax
         // 00402be4: movdqu b16 xmm0, b16 ds:[r8+rax+0xfffffffffffffff0]
         // 00402beb: movdqu b16 xmm1, b16 ds:[r8]
      [-]f30f6f17660f74d1660fd7f24881feffff0000740e
         // 00402bf0: movdqu b16 xmm2, b16 ds:[rdi]
         // 00402bf4: pcmpeqb b16 xmm2, b16 xmm1
         // 00402bf8: pmovmskb b4 esi, b16 xmm2
         // 00402bfc: cmp rsi, 0xffff
         // 00402c03: jz 0x402c13
      [-]4883c7014839d772e2
         // 00402c05: add rdi, 0x1
         // 00402c09: cmp rdi, rdx
         // 00402c0c: jb 0x402bf0
      [-]e9ad000000
         // 00402c0e: jmp 0x402cc0
      [-]f30f6f5c38f0660f74d8660fd7f34881feffff00000f84ff000000
         // 00402c13: movdqu b16 xmm3, b16 ds:[rax+rdi+0xfffffffffffffff0]
         // 00402c19: pcmpeqb b16 xmm3, b16 xmm0
         // 00402c1d: pmovmskb b4 esi, b16 xmm3
         // 00402c21: cmp rsi, 0xffff
         // 00402c28: jz 0x402d2d
      [-]4883c7014839d772b9
         // 00402c2e: add rdi, 0x1
         // 00402c32: cmp rdi, rdx
         // 00402c35: jb 0x402bf0
      [-]e984000000
         // 00402c37: jmp 0x402cc0
      [-]4883f8207729
         // 00402c3c: cmp rax, 0x20
         // 00402c40: ja 0x402c6b
      [-]c4c17e6f08488d5417e1
         // 00402c42: vmovdqu b32 ymm1, b32 ds:[r8]
         // 00402c47: lea rdx, ds:[rdi+rdx+0xffffffffffffffe1]
      [-]c5fe6f17c5ed74d9c5fdd7f381fe????????7468
         // 00402c4c: vmovdqu b32 ymm2, b32 ds:[rdi]
         // 00402c50: vpcmpeqb b32 ymm3, b32 ymm2, b32 ymm1
         // 00402c54: vpmovmskb b4 esi, b32 ymm3
         // 00402c58: cmp b4 esi, b4 0xffffffffffffffff
         // 00402c5e: jz 0x402cc8
      [-]4883c7014839d772e3
         // 00402c60: add rdi, 0x1
         // 00402c64: cmp rdi, rdx
         // 00402c67: jb 0x402c4c
      [-]488d5417014829c2c4c17e6f4400e0c4c17e6f08
         // 00402c6b: lea rdx, ds:[rdi+rdx+0x1]
         // 00402c70: sub rdx, rax
         // 00402c73: vmovdqu b32 ymm0, b32 ds:[r8+rax+0xffffffffffffffe0]
         // 00402c7a: vmovdqu b32 ymm1, b32 ds:[r8]
      [-]c5fe6f17c5ed74d9c5fdd7f381fe????????740b
         // 00402c7f: vmovdqu b32 ymm2, b32 ds:[rdi]
         // 00402c83: vpcmpeqb b32 ymm3, b32 ymm2, b32 ymm1
         // 00402c87: vpmovmskb b4 esi, b32 ymm3
         // 00402c8b: cmp b4 esi, b4 0xffffffffffffffff
         // 00402c91: jz 0x402c9e
      [-]4883c7014839d772e3
         // 00402c93: add rdi, 0x1
         // 00402c97: cmp rdi, rdx
         // 00402c9a: jb 0x402c7f
      [-]c5fe6f5c38e0c5e574e0c5fdd7f481fe????????7414
         // 00402c9e: vmovdqu b32 ymm3, b32 ds:[rax+rdi+0xffffffffffffffe0]
         // 00402ca4: vpcmpeqb b32 ymm4, b32 ymm3, b32 ymm0
         // 00402ca8: vpmovmskb b4 esi, b32 ymm4
         // 00402cac: cmp b4 esi, b4 0xffffffffffffffff
         // 00402cb2: jz 0x402cc8
      [-]4883c7014839d772c2
         // 00402cb4: add rdi, 0x1
         // 00402cb8: cmp rdi, rdx
         // 00402cbb: jb 0x402c7f
      [-]49c703ffffffffc3
         // 00402cc0: mov ds:[r11], 0xffffffffffffffff
         // 00402cc7: retn 
      [-]c5f877eb60
         // 00402cc8: vzeroupper 
         // 00402ccb: jmp 0x402d2d
      [-]803d5b903100010f8579fdffff
         // 00402ccd: cmp b1 cs:[0x71bd2f], b1 0x1
         // 00402cd4: jnz 0x402a53
      [-]4883f80c0f8373feffff
         // 00402cda: cmp rax, 0xc
         // 00402cde: jnb 0x402b57
      [-]498d701066f7c6f00f0f8460fdffff
         // 00402ce4: lea rsi, ds:[r8+0x10]
         // 00402ce8: test b2 si, b2 0xff0
         // 00402ced: jz 0x402a53
      [-]f3410f6f08488d7417f149c7c1100000004929c1
         // 00402cf3: movdqu b16 xmm1, b16 ds:[r8]
         // 00402cf8: lea rsi, ds:[rdi+rdx+0xfffffffffffffff1]
         // 00402cfd: mov r9, 0x10
         // 00402d04: sub r9, rax
      [-]660f3a610f0c4c39c97618
         // 00402d07: pcmpestri b16 xmm1, b16 ds:[rdi], b1 0xc
         // 00402d0d: cmp rcx, r9
         // 00402d10: jbe 0x402d2a
      [-]4c01cf4839f772ed
         // 00402d12: add rdi, r9
         // 00402d15: cmp rdi, rsi
         // 00402d18: jb 0x402d07
      [-]660f3a614eff0c4c39c9779a
         // 00402d1a: pcmpestri b16 xmm1, b16 ds:[rsi+0xffffffffffffffff], b1 0xc
         // 00402d21: cmp rcx, r9
         // 00402d24: ja 0x402cc0
      [-]488d7eff
         // 00402d26: lea rdi, ds:[rsi+0xffffffffffffffff]
      [-]4c29d749893bc3
         // 00402d2d: sub rdi, r10
         // 00402d30: mov ds:[r11], rdi
         // 00402d33: retn 
      [-]488b7c2408488b5424104c8b442420488b4424284989fa4c8d5c2438e9dffcffff
         // 00402d40: mov rdi, ss:[rsp+0x8]
         // 00402d45: mov rdx, ss:[rsp+0x10]
         // 00402d4a: mov r8, ss:[rsp+0x20]
         // 00402d4f: mov rax, ss:[rsp+0x28]
         // 00402d54: mov r10, rdi
         // 00402d57: lea r11, ss:[rsp+0x38]
         // 00402d5c: jmp indexbody
      [-]488b7c2408488b5424104c8b442418488b4424204989fa4c8d5c2428e99ffcffff
         // 00402d80: mov rdi, ss:[rsp+0x8]
         // 00402d85: mov rdx, ss:[rsp+0x10]
         // 00402d8a: mov r8, ss:[rsp+0x18]
         // 00402d8f: mov rax, ss:[rsp+0x20]
         // 00402d94: mov r10, rdi
         // 00402d97: lea r11, ss:[rsp+0x28]
         // 00402d9c: jmp indexbody
      [-]66480f6ec0660f60c0660f60c0660f70c0004883fb107c54
         // 00402dc0: movq b16 xmm0, rax
         // 00402dc5: punpcklbw b16 xmm0, b16 xmm0
         // 00402dc9: punpcklbw b16 xmm0, b16 xmm0
         // 00402dcd: pshufd b16 xmm0, b16 xmm0, b1 0x0
         // 00402dd2: cmp rbx, 0x10
         // 00402dd6: jl 0x402e2c
      [-]4889f74883fb200f878d000000
         // 00402dd8: mov rdi, rsi
         // 00402ddb: cmp rbx, 0x20
         // 00402ddf: ja 0x402e72
      [-]488d441ef0eb15
         // 00402de5: lea rax, ds:[rsi+rbx+0xfffffffffffffff0]
         // 00402dea: jmp 0x402e01
      [-]f30f6f0f660f74c8660fd7d10fbcd27525
         // 00402dec: movdqu b16 xmm1, b16 ds:[rdi]
         // 00402df0: pcmpeqb b16 xmm1, b16 xmm0
         // 00402df4: pmovmskb b4 edx, b16 xmm1
         // 00402df8: bsf b4 edx, b4 edx
         // 00402dfb: jnz 0x402e22
      [-]4883c710
         // 00402dfd: add rdi, 0x10
      [-]4839c772e6
         // 00402e01: cmp rdi, rax
         // 00402e04: jb 0x402dec
      [-]4889c7f30f6f08660f74c8660fd7d10fbcd27508
         // 00402e06: mov rdi, rax
         // 00402e09: movdqu b16 xmm1, b16 ds:[rax]
         // 00402e0d: pcmpeqb b16 xmm1, b16 xmm0
         // 00402e11: pmovmskb b4 edx, b16 xmm1
         // 00402e15: bsf b4 edx, b4 edx
         // 00402e18: jnz 0x402e22
      [-]49c700ffffffffc3
         // 00402e1a: mov ds:[r8], 0xffffffffffffffff
         // 00402e21: retn 
      [-]4829f74801d7498938c3
         // 00402e22: sub rdi, rsi
         // 00402e25: add rdi, rdx
         // 00402e28: mov ds:[r8], rdi
         // 00402e2b: retn 
      [-]4885db74e9
         // 00402e2c: test rbx, rbx
         // 00402e2f: jz 0x402e1a
      [-]488d461066a9f00f7419
         // 00402e31: lea rax, ds:[rsi+0x10]
         // 00402e35: test b2 ax, b2 0xff0
         // 00402e39: jz 0x402e54
      [-]f30f6f0e660f74c8660fd7d10fbcd274ce
         // 00402e3b: movdqu b16 xmm1, b16 ds:[rsi]
         // 00402e3f: pcmpeqb b16 xmm1, b16 xmm0
         // 00402e43: pmovmskb b4 edx, b16 xmm1
         // 00402e47: bsf b4 edx, b4 edx
         // 00402e4a: jz 0x402e1a
      [-]39da73ca
         // 00402e4c: cmp b4 edx, b4 ebx
         // 00402e4e: jnb 0x402e1a
      [-]498910c3
         // 00402e50: mov ds:[r8], rdx
         // 00402e53: retn 
      [-]f30f6f4c1ef0660f74c8660fd7d189d9d3e2c1ea100fbcd274ac
         // 00402e54: movdqu b16 xmm1, b16 ds:[rsi+rbx+0xfffffffffffffff0]
         // 00402e5a: pcmpeqb b16 xmm1, b16 xmm0
         // 00402e5e: pmovmskb b4 edx, b16 xmm1
         // 00402e62: mov b4 ecx, b4 ebx
         // 00402e64: shl b4 edx, b1 cl
         // 00402e66: shr b4 edx, b1 0x10
         // 00402e69: bsf b4 edx, b4 edx
         // 00402e6c: jz 0x402e1a
      [-]498910c3
         // 00402e6e: mov ds:[r8], rdx
         // 00402e71: retn 
      [-]803daa8e3100010f8566ffffff
         // 00402e72: cmp b1 cs:[0x71bd23], b1 0x1
         // 00402e79: jnz 0x402de5
      [-]66480f6ec04c8d5c1ee0c4e27d78c8
         // 00402e7f: movq b16 xmm0, rax
         // 00402e84: lea r11, ds:[rsi+rbx+0xffffffffffffffe0]
         // 00402e89: vpbroadcastb b32 ymm1, b16 xmm0
      [-]c5fe6f17c5ed74d9c4e27d17db7526
         // 00402e8e: vmovdqu b32 ymm2, b32 ds:[rdi]
         // 00402e92: vpcmpeqb b32 ymm3, b32 ymm2, b32 ymm1
         // 00402e96: vptest b32 ymm3, b32 ymm3
         // 00402e9b: jnz 0x402ec3
      [-]4883c7204c39df7ce8
         // 00402e9d: add rdi, 0x20
         // 00402ea1: cmp rdi, r11
         // 00402ea4: jl 0x402e8e
      [-]4c89dfc5fe6f17c5ed74d9c4e27d17db750b
         // 00402ea6: mov rdi, r11
         // 00402ea9: vmovdqu b32 ymm2, b32 ds:[rdi]
         // 00402ead: vpcmpeqb b32 ymm3, b32 ymm2, b32 ymm1
         // 00402eb1: vptest b32 ymm3, b32 ymm3
         // 00402eb6: jnz 0x402ec3
      [-]c5f87749c700ffffffffc3
         // 00402eb8: vzeroupper 
         // 00402ebb: mov ds:[r8], 0xffffffffffffffff
         // 00402ec2: retn 
      [-]c5fdd7d30fbcd24829f74801fa498910c5f877c3
         // 00402ec3: vpmovmskb b4 edx, b32 ymm3
         // 00402ec7: bsf b4 edx, b4 edx
         // 00402eca: sub rdi, rsi
         // 00402ecd: add rdx, rdi
         // 00402ed0: mov ds:[r8], rdx
         // 00402ed3: vzeroupper 
         // 00402ed6: retn 
      [-]488b742408488b5c24108a4424204c8d442428e9c8feffff
         // 00402ee0: mov rsi, ss:[rsp+0x8]
         // 00402ee5: mov rbx, ss:[rsp+0x10]
         // 00402eea: mov b1 al, b1 ss:[rsp+0x20]
         // 00402eee: lea r8, ss:[rsp+0x28]
         // 00402ef3: jmp indexbytebody
      [-]488b742408488b5c24108a4424184c8d442420e9a8feffff
         // 00402f00: mov rsi, ss:[rsp+0x8]
         // 00402f05: mov rbx, ss:[rsp+0x10]
         // 00402f0a: mov b1 al, b1 ss:[rsp+0x18]
         // 00402f0e: lea r8, ss:[rsp+0x20]
         // 00402f13: jmp indexbytebody
      [-]4883ec2048896c2418488d6c2418488b442428488b5c24300fb64c2438450f57ff654c8b3425280000004d8bb600000000e8caf4ffff4889442440488b6c24184883c420c3
         // 00402f20: sub rsp, 0x20
         // 00402f24: mov ss:[rsp+0x18], rbp
         // 00402f29: lea rbp, ss:[rsp+0x18]
         // 00402f2e: mov rax, ss:[rsp+0x28]
         // 00402f33: mov rbx, ss:[rsp+0x30]
         // 00402f38: movzx b4 ecx, b1 ss:[rsp+0x38]
         // 00402f3d: xorps b16 xmm15, b16 xmm15
         // 00402f41: mov r14, gs:[0x28]
         // 00402f4a: mov r14, ds:[r14+0x0]
         // 00402f51: call internal_bytealg.countGenericString
         // 00402f56: mov ss:[rsp+0x40], rax
         // 00402f5b: mov rbp, ss:[rsp+0x18]
         // 00402f60: add rsp, 0x20
         // 00402f64: retn 
      [-]493b66107622
         // 00402f80: cmp rsp, ds:[r14+0x10]
         // 00402f84: jbe 0x402fa8
      [-]4883ec2048896c2418488d6c2418b9????????e862faffff488b6c24184883c420c3
         // 00402f86: sub rsp, 0x20
         // 00402f8a: mov ss:[rsp+0x18], rbp
         // 00402f8f: lea rbp, ss:[rsp+0x18]
         // 00402f94: mov b4 ecx, b4 0x10a
         // 00402f99: call runtime.memequal
         // 00402f9e: mov rbp, ss:[rsp+0x18]
         // 00402fa3: add rsp, 0x20
         // 00402fa7: retn 
      [-]488944240848895c2410e889ce0500488b442408488b5c2410ebbd
         // 00402fa8: mov ss:[rsp+0x8], rax
         // 00402fad: mov ss:[rsp+0x10], rbx
         // 00402fb2: call runtime.morestack_noctxt
         // 00402fb7: mov rax, ss:[rsp+0x8]
         // 00402fbc: mov rbx, ss:[rsp+0x10]
         // 00402fc1: jmp type..eq.internal_abi.RegArgs
      [-]493b66107629
         // 00403100: cmp rsp, ds:[r14+0x10]
         // 00403104: jbe 0x40312f
      [-]4883ec2048896c2418488d6c2418488b10488b48084889d06690e83b670000488b6c24184883c420c3
         // 00403106: sub rsp, 0x20
         // 0040310a: mov ss:[rsp+0x18], rbp
         // 0040310f: lea rbp, ss:[rsp+0x18]
         // 00403114: mov rdx, ds:[rax]
         // 00403117: mov rcx, ds:[rax+0x8]
         // 0040311b: mov rax, rdx
         // 0040311e: xchg b2 ax, b2 ax
         // 00403120: call runtime.memhashFallback
         // 00403125: mov rbp, ss:[rsp+0x18]
         // 0040312a: add rsp, 0x20
         // 0040312e: retn 
      [-]488944240848895c2410e802cd0500488b442408488b5c2410ebb6
         // 0040312f: mov ss:[rsp+0x8], rax
         // 00403134: mov ss:[rsp+0x10], rbx
         // 00403139: call runtime.morestack_noctxt
         // 0040313e: mov rax, ss:[rsp+0x8]
         // 00403143: mov rbx, ss:[rsp+0x10]
         // 00403148: jmp runtime.strhashFallback
      [-]b8????????c3
         // 00403960: mov b4 eax, b4 0x1
         // 00403965: retn 
      [-]0fb608380b0f94c0c3
         // 00403980: movzx b4 ecx, b1 ds:[rax]
         // 00403983: cmp b1 ds:[rbx], b1 cl
         // 00403985: setz b1 al
         // 00403988: retn 
      [-]0fb70866390b0f94c0c3
         // 004039a0: movzx b4 ecx, b2 ds:[rax]
         // 004039a3: cmp b2 ds:[rbx], b2 cx
         // 004039a6: setz b1 al
         // 004039a9: retn 
      [-]8b08390b0f94c0c3
         // 004039c0: mov b4 ecx, b4 ds:[rax]
         // 004039c2: cmp b4 ds:[rbx], b4 ecx
         // 004039c4: setz b1 al
         // 004039c7: retn 
      [-]488b0848390b0f94c0c3
         // 004039e0: mov rcx, ds:[rax]
         // 004039e3: cmp ds:[rbx], rcx
         // 004039e6: setz b1 al
         // 004039e9: retn 
      [-]493b6610762a
         // 00404580: cmp rsp, ds:[r14+0x10]
         // 00404584: jbe 0x4045b0
      [-]4883ec1048896c2408488d6c24084d8b66204d85e4751a
         // 00404586: sub rsp, 0x10
         // 0040458a: mov ss:[rsp+0x8], rbp
         // 0040458f: lea rbp, ss:[rsp+0x8]
         // 00404594: mov r12, ds:[r14+0x20]
         // 00404598: test r12, r12
         // 0040459b: jnz 0x4045b7
      [-]488b4208e89a000000488b6c24084883c410c3
         // 0040459d: mov rax, ds:[rdx+0x8]
         // 004045a1: call runtime.unwindm
         // 004045a6: mov rbp, ss:[rsp+0x8]
         // 004045ab: add rsp, 0x10
         // 004045af: retn 
      [-]e8ebb70500ebc9
         // 004045b0: call runtime.morestack
         // 004045b5: jmp runtime.cgocallbackg1_dwrap_2
      [-]4c8d6c24180f1f40004d392c2475d7
         // 004045b7: lea r13, ss:[rsp+0x18]
         // 004045bc: nop b4 ds:[rax+0x0]
         // 004045c0: cmp ds:[r12], r13
         // 004045c4: jnz 0x40459d
      [-]49892424ebd1
         // 004045c6: mov ds:[r12], rsp
         // 004045ca: jmp 0x40459d
      [-]4889442408c3
         // 00407fa0: mov ss:[rsp+0x8], rax
         // 00407fa5: retn 
      [-]48331dd91e310048ba2f64bd78641d76a04831d34885c90f84a7000000
         // 00409860: xor rbx, cs:[runtime.hashkey]
         // 00409867: mov rdx, 0xa0761d6478bd642f
         // 00409871: xor rbx, rdx
         // 00409874: test rcx, rcx
         // 00409877: jz 0x409924
      [-]0f1f004883f904726e
         // 0040987d: nop b4 ds:[rax]
         // 00409880: cmp rcx, 0x4
         // 00409884: jb 0x4098f4
      [-]4883f9087244
         // 00409888: cmp rcx, 0x8
         // 0040988c: jb 0x4098d2
      [-]4883f910761c
         // 00409890: cmp rcx, 0x10
         // 00409894: jbe 0x4098b2
      [-]4883f930760e
         // 00409896: cmp rcx, 0x30
         // 0040989a: jbe 0x4098aa
      [-]4889ca4889de4889f7e9a0010000
         // 0040989c: mov rdx, rcx
         // 0040989f: mov rsi, rbx
         // 004098a2: mov rdi, rsi
         // 004098a5: jmp 0x409a4a
      [-]4889cae9dd000000
         // 004098aa: mov rdx, rcx
         // 004098ad: jmp 0x40998f
      [-]4889c2488d3401488d76f89090488b1290488b36eb60
         // 004098b2: mov rdx, rax
         // 004098b5: lea rsi, ds:[rcx+rax]
         // 004098b9: lea rsi, ds:[rsi+0xfffffffffffffff8]
         // 004098bd: nop 
         // 004098be: nop 
         // 004098bf: mov rdx, ds:[rdx]
         // 004098c2: nop 
         // 004098c3: mov rsi, ds:[rsi]
         // 004098c6: jmp 0x409928
      [-]9090488b304889f2eb56
         // 004098c8: nop 
         // 004098c9: nop 
         // 004098ca: mov rsi, ds:[rax]
         // 004098cd: mov rdx, rsi
         // 004098d0: jmp 0x409928
      [-]4889c2488d3c01488d7ffc90908b32908b1789d089f289c6eb3c
         // 004098d2: mov rdx, rax
         // 004098d5: lea rdi, ds:[rcx+rax]
         // 004098d9: lea rdi, ds:[rdi+0xfffffffffffffffc]
         // 004098dd: nop 
         // 004098de: nop 
         // 004098df: mov b4 esi, b4 ds:[rdx]
         // 004098e1: nop 
         // 004098e2: mov b4 edx, b4 ds:[rdi]
         // 004098e4: mov b4 eax, b4 edx
         // 004098e6: mov b4 edx, b4 esi
         // 004098e8: mov b4 esi, b4 eax
         // 004098ea: jmp 0x409928
      [-]90908b1089d6eb34
         // 004098ec: nop 
         // 004098ed: nop 
         // 004098ee: mov b4 edx, b4 ds:[rax]
         // 004098f0: mov b4 esi, b4 edx
         // 004098f2: jmp 0x409928
      [-]4889c6488d3c01488d7fff0fb6164989c848d1e90fb60c0e48c1e1084809ca0fb60f48c1e1104809ca4c89c131f6eb04
         // 004098f4: mov rsi, rax
         // 004098f7: lea rdi, ds:[rcx+rax]
         // 004098fb: lea rdi, ds:[rdi+0xffffffffffffffff]
         // 004098ff: movzx b4 edx, b1 ds:[rsi]
         // 00409902: mov r8, rcx
         // 00409905: shr rcx, b1 0x1
         // 00409908: movzx b4 ecx, b1 ds:[rsi+rcx]
         // 0040990c: shl rcx, b1 0x8
         // 00409910: or rdx, rcx
         // 00409913: movzx b4 ecx, b1 ds:[rdi]
         // 00409916: shl rcx, b1 0x10
         // 0040991a: or rdx, rcx
         // 0040991d: mov rcx, r8
         // 00409920: xor b4 esi, b4 esi
         // 00409922: jmp 0x409928
      [-]4889d8c3
         // 00409924: mov rax, rbx
         // 00409927: retn 
      [-]48bfdb28b4a0d17e03e74831d74831de4889f048f7e748bb4f127dc4274e8e1d4831cb4831d048f7e34831d0c3
         // 00409928: mov rdi, 0xe7037ed1a0b428db
         // 00409932: xor rdi, rdx
         // 00409935: xor rsi, rbx
         // 00409938: mov rax, rsi
         // 0040993b: mul rdi
         // 0040993e: mov rbx, 0x1d8e4e27c47d124f
         // 00409948: xor rbx, rcx
         // 0040994b: xor rax, rdx
         // 0040994e: mul rbx
         // 00409951: xor rax, rdx
         // 00409954: retn 
      [-]488b3048bfdb28b4a0d17e03e74831fe4c8b40084931d84889c34c89c04989d048f7e64883c1f09090904831d0488d73104c89c24889c34889f0
         // 00409955: mov rsi, ds:[rax]
         // 00409958: mov rdi, 0xe7037ed1a0b428db
         // 00409962: xor rsi, rdi
         // 00409965: mov r8, ds:[rax+0x8]
         // 00409969: xor r8, rbx
         // 0040996c: mov rbx, rax
         // 0040996f: mov rax, r8
         // 00409972: mov r8, rdx
         // 00409975: mul rsi
         // 00409978: add rcx, 0xfffffffffffffff0
         // 0040997c: nop 
         // 0040997d: nop 
         // 0040997e: nop 
         // 0040997f: xor rax, rdx
         // 00409982: lea rsi, ds:[rbx+0x10]
         // 00409986: mov rdx, r8
         // 00409989: mov rbx, rax
         // 0040998c: mov rax, rsi
      [-]4883f91077c0
         // 0040998f: cmp rcx, 0x10
         // 00409993: ja 0x409955
      [-]488d3c01488d7ff04c8d04084d8d40f890488b3f90498b304889d14889fae970ffffff
         // 00409995: lea rdi, ds:[rcx+rax]
         // 00409999: lea rdi, ds:[rdi+0xfffffffffffffff0]
         // 0040999d: lea r8, ds:[rax+rcx]
         // 004099a1: lea r8, ds:[r8+0xfffffffffffffff8]
         // 004099a5: nop 
         // 004099a6: mov rdi, ds:[rdi]
         // 004099a9: nop 
         // 004099aa: mov rsi, ds:[r8]
         // 004099ad: mov rcx, rdx
         // 004099b0: mov rdx, rdi
         // 004099b3: jmp 0x409928
      [-]4c8b0049b9db28b4a0d17e03e74d31c84c8b50084931da4889c34c89d04989d249f7e04c8b431049bbe3c6889cf06abc8e4d31d84c8b63184931f44889c64c89e04989d449f7e04c8b432049bdc34c3775cc6599584d31e84c8b7b284931ff4889c74c89f84989d749f7e04883c1d09090904c31e690904c31ff90904831d04c8d43304c89d24889f34889fe4889c74c89c0
         // 004099b8: mov r8, ds:[rax]
         // 004099bb: mov r9, 0xe7037ed1a0b428db
         // 004099c5: xor r8, r9
         // 004099c8: mov r10, ds:[rax+0x8]
         // 004099cc: xor r10, rbx
         // 004099cf: mov rbx, rax
         // 004099d2: mov rax, r10
         // 004099d5: mov r10, rdx
         // 004099d8: mul r8
         // 004099db: mov r8, ds:[rbx+0x10]
         // 004099df: mov r11, 0x8ebc6af09c88c6e3
         // 004099e9: xor r8, r11
         // 004099ec: mov r12, ds:[rbx+0x18]
         // 004099f0: xor r12, rsi
         // 004099f3: mov rsi, rax
         // 004099f6: mov rax, r12
         // 004099f9: mov r12, rdx
         // 004099fc: mul r8
         // 004099ff: mov r8, ds:[rbx+0x20]
         // 00409a03: mov r13, 0x589965cc75374cc3
         // 00409a0d: xor r8, r13
         // 00409a10: mov r15, ds:[rbx+0x28]
         // 00409a14: xor r15, rdi
         // 00409a17: mov rdi, rax
         // 00409a1a: mov rax, r15
         // 00409a1d: mov r15, rdx
         // 00409a20: mul r8
         // 00409a23: add rcx, 0xffffffffffffffd0
         // 00409a27: nop 
         // 00409a28: nop 
         // 00409a29: nop 
         // 00409a2a: xor rsi, r12
         // 00409a2d: nop 
         // 00409a2e: nop 
         // 00409a2f: xor rdi, r15
         // 00409a32: nop 
         // 00409a33: nop 
         // 00409a34: xor rax, rdx
         // 00409a37: lea r8, ds:[rbx+0x30]
         // 00409a3b: mov rdx, r10
         // 00409a3e: mov rbx, rsi
         // 00409a41: mov rsi, rdi
         // 00409a44: mov rdi, rax
         // 00409a47: mov rax, r8
      [-]4883f9300f8764ffffff
         // 00409a4a: cmp rcx, 0x30
         // 00409a4e: ja 0x4099b8
      [-]4831fe4831f3e930ffffff
         // 00409a54: xor rsi, rdi
         // 00409a57: xor rbx, rsi
         // 00409a5a: jmp 0x40998f
      [-]8b0048b9db28b4a0d17e03e74831c14831d8483305c71c310048ba2f64bd78641d76a04831c24889c848f7e24831d04889c148b84b127dc4274e8e1d48f7e190904831d0c3
         // 00409a60: mov b4 eax, b4 ds:[rax]
         // 00409a62: mov rcx, 0xe7037ed1a0b428db
         // 00409a6c: xor rcx, rax
         // 00409a6f: xor rax, rbx
         // 00409a72: xor rax, cs:[runtime.hashkey]
         // 00409a79: mov rdx, 0xa0761d6478bd642f
         // 00409a83: xor rdx, rax
         // 00409a86: mov rax, rcx
         // 00409a89: mul rdx
         // 00409a8c: xor rax, rdx
         // 00409a8f: mov rcx, rax
         // 00409a92: mov rax, 0x1d8e4e27c47d124b
         // 00409a9c: mul rcx
         // 00409a9f: nop 
         // 00409aa0: nop 
         // 00409aa1: xor rax, rdx
         // 00409aa4: retn 
      [-]488b0048b9db28b4a0d17e03e74831c14831d8483305661c310048ba2f64bd78641d76a04831c24889c848f7e24831d04889c148b847127dc4274e8e1d48f7e190904831d0c3
         // 00409ac0: mov rax, ds:[rax]
         // 00409ac3: mov rcx, 0xe7037ed1a0b428db
         // 00409acd: xor rcx, rax
         // 00409ad0: xor rax, rbx
         // 00409ad3: xor rax, cs:[runtime.hashkey]
         // 00409ada: mov rdx, 0xa0761d6478bd642f
         // 00409ae4: xor rdx, rax
         // 00409ae7: mov rax, rcx
         // 00409aea: mul rdx
         // 00409aed: xor rax, rdx
         // 00409af0: mov rcx, rax
         // 00409af3: mov rax, 0x1d8e4e27c47d1247
         // 00409afd: mul rcx
         // 00409b00: nop 
         // 00409b01: nop 
         // 00409b02: xor rax, rdx
         // 00409b05: retn 
      [-]493b66100f8601010000
         // 004301e0: cmp rsp, ds:[r14+0x10]
         // 004301e4: jbe 0x4302eb
      [-]4883ec5848896c2450488d6c2450488d05e13416008400488b05d8341600833dc1b42e00007509
         // 004301ea: sub rsp, 0x58
         // 004301ee: mov ss:[rsp+0x50], rbp
         // 004301f3: lea rbp, ss:[rsp+0x50]
         // 004301f8: lea rax, cs:[0x5936e0]
         // 004301ff: test b1 ds:[rax], b1 al
         // 00430201: mov rax, cs:[0x5936e0]
         // 00430208: cmp b4 cs:[runtime.writeBarrier], b4 0x0
         // 0043020f: jnz 0x43021a
      [-]48890578442900eb0c
         // 00430211: mov cs:[runtime.asmstdcallAddr], rax
         // 00430218: jmp 0x430226
      [-]488d3d6f442900e87a1e0300
         // 0043021a: lea rdi, cs:[runtime.asmstdcallAddr]
         // 00430221: call runtime.gcWriteBarrier
      [-]e8b5870100e8b0f1ffffe86b7e0100e8067f0100e821fcffff31c0e85afbffff8905a0b12e00e8cffcffffe82afaffff890570b12e00488d442420440f1138488d4c2430440f1139488d4c2440440f1139488b0d52be250048890c244889442408e8d41a0000450f57ff654c8b3425280000004d8bb6000000008b4424244889059db22e00488b05cebd25004889042448c7442408ffffffff48c744241001000000e8131b0000450f57ff654c8b3425280000004d8bb600000000488b6c24504883c458c3
         // 00430226: call runtime.setBadSignalMsg
         // 0043022b: call runtime.loadOptionalSyscalls
         // 00430230: call runtime.disableWER
         // 00430235: call runtime.initExceptionHandler
         // 0043023a: call runtime.initHighResTimer
         // 0043023f: xor b4 eax, b4 eax
         // 00430241: call runtime.osRelax
         // 00430246: mov b4 cs:[runtime.timeBeginPeriodRetValue], b4 eax
         // 0043024c: call runtime.initLongPathSupport
         // 00430251: call runtime.getproccount
         // 00430256: mov b4 cs:[runtime.ncpu], b4 eax
         // 0043025c: lea rax, ss:[rsp+0x20]
         // 00430261: movups b16 ds:[rax], b16 xmm15
         // 00430265: lea rcx, ss:[rsp+0x30]
         // 0043026a: movups b16 ds:[rcx], b16 xmm15
         // 0043026e: lea rcx, ss:[rsp+0x40]
         // 00430273: movups b16 ds:[rcx], b16 xmm15
         // 00430277: mov rcx, cs:[GetSystemInfo]
         // 0043027e: mov ss:[rsp], rcx
         // 00430282: mov ss:[rsp+0x8], rax
         // 00430287: call runtime.stdcall1
         // 0043028c: xorps b16 xmm15, b16 xmm15
         // 00430290: mov r14, gs:[0x28]
         // 00430299: mov r14, ds:[r14+0x0]
         // 004302a0: mov b4 eax, b4 ss:[rsp+0x24]
         // 004302a4: mov cs:[runtime.physPageSize], rax
         // 004302ab: mov rax, cs:[SetProcessPriorityBoost]
         // 004302b2: mov ss:[rsp], rax
         // 004302b6: mov ss:[rsp+0x8], 0xffffffffffffffff
         // 004302bf: mov ss:[rsp+0x10], 0x1
         // 004302c8: call runtime.stdcall2
         // 004302cd: xorps b16 xmm15, b16 xmm15
         // 004302d1: mov r14, gs:[0x28]
         // 004302da: mov r14, ds:[r14+0x0]
         // 004302e1: mov rbp, ss:[rsp+0x50]
         // 004302e6: add rsp, 0x58
         // 004302ea: retn 
      [-]e850fb0200e9ebfeffff
         // 004302eb: call runtime.morestack_noctxt
         // 004302f0: jmp runtime.osinit
      [-]493b66107670
         // 00432980: cmp rsp, ds:[r14+0x10]
         // 00432984: jbe 0x4329f6
      [-]4883ec3848896c2430488d6c2430488944244048895c2448b9????????488b442438488d1dcc091500e88cfeffff440f117c241866c74424280000488b5424404889542418c644242801488b5424484889542420c644242900488d05faef1300488d5c2418e8907ffdffe8ab27000090
         // 00432986: sub rsp, 0x38
         // 0043298a: mov ss:[rsp+0x30], rbp
         // 0043298f: lea rbp, ss:[rsp+0x30]
         // 00432994: mov ss:[rsp+0x40], rax
         // 00432999: mov ss:[rsp+0x48], rbx
         // 0043299e: mov b4 ecx, b4 0x12
         // 004329a3: mov rax, ss:[rsp+0x38]
         // 004329a8: lea rbx, cs:[0x58337b]
         // 004329af: call runtime.panicCheck1
         // 004329b4: movups b16 ss:[rsp+0x18], b16 xmm15
         // 004329ba: mov b2 ss:[rsp+0x28], b2 0x0
         // 004329c1: mov rdx, ss:[rsp+0x40]
         // 004329c6: mov ss:[rsp+0x18], rdx
         // 004329cb: mov b1 ss:[rsp+0x28], b1 0x1
         // 004329d0: mov rdx, ss:[rsp+0x48]
         // 004329d5: mov ss:[rsp+0x20], rdx
         // 004329da: mov b1 ss:[rsp+0x29], b1 0x0
         // 004329df: lea rax, cs:[RTYPE_runtime_boundsError]
         // 004329e6: lea rbx, ss:[rsp+0x18]
         // 004329eb: call runtime.convT2Enoptr
         // 004329f0: call runtime.gopanic
         // 004329f5: nop 
      [-]488944240848895c2410e83bd40200488b442408488b5c2410e96cffffff
         // 004329f6: mov ss:[rsp+0x8], rax
         // 004329fb: mov ss:[rsp+0x10], rbx
         // 00432a00: call runtime.morestack_noctxt
         // 00432a05: mov rax, ss:[rsp+0x8]
         // 00432a0a: mov rbx, ss:[rsp+0x10]
         // 00432a0f: jmp runtime.goPanicIndex
      [-]493b66107670
         // 00432a20: cmp rsp, ds:[r14+0x10]
         // 00432a24: jbe 0x432a96
      [-]4883ec3848896c2430488d6c2430488944244048895c2448b9????????488b442438488d1d2c091500e8ecfdffff440f117c241866c74424280000488b5424404889542418c644242800488b5424484889542420c644242900488d055aef1300488d5c2418e8f07efdffe80b27000090
         // 00432a26: sub rsp, 0x38
         // 00432a2a: mov ss:[rsp+0x30], rbp
         // 00432a2f: lea rbp, ss:[rsp+0x30]
         // 00432a34: mov ss:[rsp+0x40], rax
         // 00432a39: mov ss:[rsp+0x48], rbx
         // 00432a3e: mov b4 ecx, b4 0x12
         // 00432a43: mov rax, ss:[rsp+0x38]
         // 00432a48: lea rbx, cs:[0x58337b]
         // 00432a4f: call runtime.panicCheck1
         // 00432a54: movups b16 ss:[rsp+0x18], b16 xmm15
         // 00432a5a: mov b2 ss:[rsp+0x28], b2 0x0
         // 00432a61: mov rdx, ss:[rsp+0x40]
         // 00432a66: mov ss:[rsp+0x18], rdx
         // 00432a6b: mov b1 ss:[rsp+0x28], b1 0x0
         // 00432a70: mov rdx, ss:[rsp+0x48]
         // 00432a75: mov ss:[rsp+0x20], rdx
         // 00432a7a: mov b1 ss:[rsp+0x29], b1 0x0
         // 00432a7f: lea rax, cs:[RTYPE_runtime_boundsError]
         // 00432a86: lea rbx, ss:[rsp+0x18]
         // 00432a8b: call runtime.convT2Enoptr
         // 00432a90: call runtime.gopanic
         // 00432a95: nop 
      [-]488944240848895c2410e89bd30200488b442408488b5c2410e96cffffff
         // 00432a96: mov ss:[rsp+0x8], rax
         // 00432a9b: mov ss:[rsp+0x10], rbx
         // 00432aa0: call runtime.morestack_noctxt
         // 00432aa5: mov rax, ss:[rsp+0x8]
         // 00432aaa: mov rbx, ss:[rsp+0x10]
         // 00432aaf: jmp runtime.goPanicIndexU
      [-]493b66107670
         // 00432ac0: cmp rsp, ds:[r14+0x10]
         // 00432ac4: jbe 0x432b36
      [-]4883ec3848896c2430488d6c2430488944244048895c2448b9????????488b442438488d1dad3b1500e84cfdffff440f117c241866c74424280000488b5424404889542418c644242801488b5424484889542420c644242901488d05baee1300488d5c2418e8507efdffe86b26000090
         // 00432ac6: sub rsp, 0x38
         // 00432aca: mov ss:[rsp+0x30], rbp
         // 00432acf: lea rbp, ss:[rsp+0x30]
         // 00432ad4: mov ss:[rsp+0x40], rax
         // 00432ad9: mov ss:[rsp+0x48], rbx
         // 00432ade: mov b4 ecx, b4 0x19
         // 00432ae3: mov rax, ss:[rsp+0x38]
         // 00432ae8: lea rbx, cs:[0x58669c]
         // 00432aef: call runtime.panicCheck1
         // 00432af4: movups b16 ss:[rsp+0x18], b16 xmm15
         // 00432afa: mov b2 ss:[rsp+0x28], b2 0x0
         // 00432b01: mov rdx, ss:[rsp+0x40]
         // 00432b06: mov ss:[rsp+0x18], rdx
         // 00432b0b: mov b1 ss:[rsp+0x28], b1 0x1
         // 00432b10: mov rdx, ss:[rsp+0x48]
         // 00432b15: mov ss:[rsp+0x20], rdx
         // 00432b1a: mov b1 ss:[rsp+0x29], b1 0x1
         // 00432b1f: lea rax, cs:[RTYPE_runtime_boundsError]
         // 00432b26: lea rbx, ss:[rsp+0x18]
         // 00432b2b: call runtime.convT2Enoptr
         // 00432b30: call runtime.gopanic
         // 00432b35: nop 
      [-]488944240848895c2410e8fbd20200488b442408488b5c2410e96cffffff
         // 00432b36: mov ss:[rsp+0x8], rax
         // 00432b3b: mov ss:[rsp+0x10], rbx
         // 00432b40: call runtime.morestack_noctxt
         // 00432b45: mov rax, ss:[rsp+0x8]
         // 00432b4a: mov rbx, ss:[rsp+0x10]
         // 00432b4f: jmp runtime.goPanicSliceAlen
      [-]493b66107670
         // 00432b60: cmp rsp, ds:[r14+0x10]
         // 00432b64: jbe 0x432bd6
      [-]4883ec3848896c2430488d6c2430488944244048895c2448b9????????488b442438488d1d0d3b1500e8acfcffff440f117c241866c74424280000488b5424404889542418c644242800488b5424484889542420c644242901488d051aee1300488d5c2418e8b07dfdffe8cb25000090
         // 00432b66: sub rsp, 0x38
         // 00432b6a: mov ss:[rsp+0x30], rbp
         // 00432b6f: lea rbp, ss:[rsp+0x30]
         // 00432b74: mov ss:[rsp+0x40], rax
         // 00432b79: mov ss:[rsp+0x48], rbx
         // 00432b7e: mov b4 ecx, b4 0x19
         // 00432b83: mov rax, ss:[rsp+0x38]
         // 00432b88: lea rbx, cs:[0x58669c]
         // 00432b8f: call runtime.panicCheck1
         // 00432b94: movups b16 ss:[rsp+0x18], b16 xmm15
         // 00432b9a: mov b2 ss:[rsp+0x28], b2 0x0
         // 00432ba1: mov rdx, ss:[rsp+0x40]
         // 00432ba6: mov ss:[rsp+0x18], rdx
         // 00432bab: mov b1 ss:[rsp+0x28], b1 0x0
         // 00432bb0: mov rdx, ss:[rsp+0x48]
         // 00432bb5: mov ss:[rsp+0x20], rdx
         // 00432bba: mov b1 ss:[rsp+0x29], b1 0x1
         // 00432bbf: lea rax, cs:[RTYPE_runtime_boundsError]
         // 00432bc6: lea rbx, ss:[rsp+0x18]
         // 00432bcb: call runtime.convT2Enoptr
         // 00432bd0: call runtime.gopanic
         // 00432bd5: nop 
      [-]488944240848895c2410e85bd20200488b442408488b5c2410e96cffffff
         // 00432bd6: mov ss:[rsp+0x8], rax
         // 00432bdb: mov ss:[rsp+0x10], rbx
         // 00432be0: call runtime.morestack_noctxt
         // 00432be5: mov rax, ss:[rsp+0x8]
         // 00432bea: mov rbx, ss:[rsp+0x10]
         // 00432bef: jmp runtime.goPanicSliceAlenU
      [-]493b66107670
         // 00432c00: cmp rsp, ds:[r14+0x10]
         // 00432c04: jbe 0x432c76
      [-]4883ec3848896c2430488d6c2430488944244048895c2448b9????????488b442438488d1d6d3a1500e80cfcffff440f117c241866c74424280000
         // 00432c06: sub rsp, 0x38
         // 00432c0a: mov ss:[rsp+0x30], rbp
         // 00432c0f: lea rbp, ss:[rsp+0x30]
         // 00432c14: mov ss:[rsp+0x40], rax
         // 00432c19: mov ss:[rsp+0x48], rbx
         // 00432c1e: mov b4 ecx, b4 0x19
         // 00432c23: mov rax, ss:[rsp+0x38]
         // 00432c28: lea rbx, cs:[0x58669c]
         // 00432c2f: call runtime.panicCheck1
         // 00432c34: movups b16 ss:[rsp+0x18], b16 xmm15
         // 00432c3a: mov b2 ss:[rsp+0x28], b2 0x0
         // 00432c41: mov rdx, ss:[rsp+0x40]
         // 00432c46: mov ss:[rsp+0x18], rdx
         // 00432c4b: mov b1 ss:[rsp+0x28], b1 0x1
         // 00432c50: mov rdx, ss:[rsp+0x48]
         // 00432c55: mov ss:[rsp+0x20], rdx
         // 00432c5a: mov b1 ss:[rsp+0x29], b1 0x2
         // 00432c5f: lea rax, cs:[RTYPE_runtime_boundsError]
         // 00432c66: lea rbx, ss:[rsp+0x18]
         // 00432c6b: call runtime.convT2Enoptr
         // 00432c70: call runtime.gopanic
         // 00432c75: nop 

  }
  condition:
    all of them
}
