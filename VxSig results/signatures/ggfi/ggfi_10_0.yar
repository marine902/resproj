rule ggfi_10_0 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         8b4424088b4c240c0fa289442410895c2414894c24188954241cc3
         // 00401e60: mov b4 eax, b4 ss:[rsp+0x8]
         // 00401e64: mov b4 ecx, b4 ss:[rsp+0xc]
         // 00401e68: cpuid 
         // 00401e6a: mov b4 ss:[rsp+0x10], b4 eax
         // 00401e6e: mov b4 ss:[rsp+0x14], b4 ebx
         // 00401e72: mov b4 ss:[rsp+0x18], b4 ecx
         // 00401e76: mov b4 ss:[rsp+0x1c], b4 edx
         // 00401e7a: retn 
      [-]b9????????0f01d0894424088954240cc3
         // 00401e80: mov b4 ecx, b4 0x0
         // 00401e85: xgetbv 
         // 00401e88: mov b4 ss:[rsp+0x8], b4 eax
         // 00401e8c: mov b4 ss:[rsp+0xc], b4 edx
         // 00401e90: retn 
      [-]c7442408????????c3
         // 00401ea0: mov b4 ss:[rsp+0x8], b4 0x1
         // 00401ea8: retn 
      [-]493b66107659
         // 00401ec0: cmp rsp, ds:[r14+0x10]
         // 00401ec4: jbe 0x401f1f
      [-]4883ec2048896c2418488d6c2418488b4808488b13488b30669048394b08752d
         // 00401ec6: sub rsp, 0x20
         // 00401eca: mov ss:[rsp+0x18], rbp
         // 00401ecf: lea rbp, ss:[rsp+0x18]
         // 00401ed4: mov rcx, ds:[rax+0x8]
         // 00401ed8: mov rdx, ds:[rbx]
         // 00401edb: mov rsi, ds:[rax]
         // 00401ede: xchg b2 ax, b2 ax
         // 00401ee0: cmp ds:[rbx+0x8], rcx
         // 00401ee4: jnz 0x401f13
      [-]488b781048397b107523
         // 00401ee6: mov rdi, ds:[rax+0x10]
         // 00401eea: cmp ds:[rbx+0x10], rdi
         // 00401eee: jnz 0x401f13
      [-]0fb6781840387b187519
         // 00401ef0: movzx b4 edi, b1 ds:[rax+0x18]
         // 00401ef4: cmp b1 ds:[rbx+0x18], b1 dil
         // 00401ef8: jnz 0x401f13
      [-]0fb67819669040387b19750d
         // 00401efa: movzx b4 edi, b1 ds:[rax+0x19]
         // 00401efe: xchg b2 ax, b2 ax
         // 00401f00: cmp b1 ds:[rbx+0x19], b1 dil
         // 00401f04: jnz 0x401f13
      [-]4889f04889d3e84f0e0000eb02
         // 00401f06: mov rax, rsi
         // 00401f09: mov rbx, rdx
         // 00401f0c: call runtime.memequal
         // 00401f11: jmp 0x401f15
      [-]488b6c24184883c420c3
         // 00401f15: mov rbp, ss:[rsp+0x18]
         // 00401f1a: add rsp, 0x20
         // 00401f1e: retn 
      [-]488944240848895c2410e8d2180600488b442408488b5c2410eb86
         // 00401f1f: mov ss:[rsp+0x8], rax
         // 00401f24: mov ss:[rsp+0x10], rbx
         // 00401f29: call runtime.morestack_noctxt
         // 00401f2e: mov rax, ss:[rsp+0x8]
         // 00401f33: mov rbx, ss:[rsp+0x10]
         // 00401f38: jmp type:.eq.internal_cpu.option
      [-]493b66100f86be000000
         // 00401f40: cmp rsp, ds:[r14+0x10]
         // 00401f44: jbe 0x402008
      [-]4883ec2848896c2420488d6c2420488944243048895c243831c9eb12
         // 00401f4a: sub rsp, 0x28
         // 00401f4e: mov ss:[rsp+0x20], rbp
         // 00401f53: lea rbp, ss:[rsp+0x20]
         // 00401f58: mov ss:[rsp+0x30], rax
         // 00401f5d: mov ss:[rsp+0x38], rbx
         // 00401f62: xor b4 ecx, b4 ecx
         // 00401f64: jmp 0x401f78
      [-]488b4c241848ffc1488b5c2438488b442430
         // 00401f66: mov rcx, ss:[rsp+0x18]
         // 00401f6b: inc rcx
         // 00401f6e: mov rbx, ss:[rsp+0x38]
         // 00401f73: mov rax, ss:[rsp+0x30]
      [-]4883f9067d7b
         // 00401f78: cmp rcx, 0x6
         // 00401f7c: jge 0x401ff9
      [-]4889ca48c1e105488b740808488b3c014c8b04194c8b4c0b084939f17551
         // 00401f7e: mov rdx, rcx
         // 00401f81: shl rcx, b1 0x5
         // 00401f85: mov rsi, ds:[rax+rcx+0x8]
         // 00401f8a: mov rdi, ds:[rcx+rax]
         // 00401f8e: mov r8, ds:[rcx+rbx]
         // 00401f92: mov r9, ds:[rbx+rcx+0x8]
         // 00401f97: cmp r9, rsi
         // 00401f9a: jnz 0x401fed
      [-]4c8b4c0b104c8b5408104d39d17542
         // 00401f9c: mov r9, ds:[rbx+rcx+0x10]
         // 00401fa1: mov r10, ds:[rax+rcx+0x10]
         // 00401fa6: cmp r9, r10
         // 00401fa9: jnz 0x401fed
      [-]440fb64c0b18440fb65408184538d17531
         // 00401fab: movzx b4 r9d, b1 ds:[rbx+rcx+0x18]
         // 00401fb1: movzx b4 r10d, b1 ds:[rax+rcx+0x18]
         // 00401fb7: cmp b1 r9b, b1 r10b
         // 00401fba: jnz 0x401fed
      [-]440fb64c0b19440fb65408194538d17520
         // 00401fbc: movzx b4 r9d, b1 ds:[rbx+rcx+0x19]
         // 00401fc2: movzx b4 r10d, b1 ds:[rax+rcx+0x19]
         // 00401fc8: cmp b1 r9b, b1 r10b
         // 00401fcb: jnz 0x401fed
      [-]48895424184889f84c89c34889f10f1f440000e87b0d000084c00f8579ffffff
         // 00401fcd: mov ss:[rsp+0x18], rdx
         // 00401fd2: mov rax, rdi
         // 00401fd5: mov rbx, r8
         // 00401fd8: mov rcx, rsi
         // 00401fdb: nop b4 ds:[rax+rax+0x0]
         // 00401fe0: call runtime.memequal
         // 00401fe5: test b1 al, b1 al
         // 00401fe7: jnz 0x401f66
      [-]31c0488b6c24204883c428c3
         // 00401fed: xor b4 eax, b4 eax
         // 00401fef: mov rbp, ss:[rsp+0x20]
         // 00401ff4: add rsp, 0x28
         // 00401ff8: retn 
      [-]b8????????488b6c24204883c428c3
         // 00401ff9: mov b4 eax, b4 0x1
         // 00401ffe: mov rbp, ss:[rsp+0x20]
         // 00402003: add rsp, 0x28
         // 00402007: retn 
      [-]488944240848895c2410e8e9170600488b442408488b5c2410e91affffff
         // 00402008: mov ss:[rsp+0x8], rax
         // 0040200d: mov ss:[rsp+0x10], rbx
         // 00402012: call runtime.morestack_noctxt
         // 00402017: mov rax, ss:[rsp+0x8]
         // 0040201c: mov rbx, ss:[rsp+0x10]
         // 00402021: jmp type:.eq._..._internal_cpu.option
      [-]488b0848390b0f94c0c3
         // 00402080: mov rcx, ds:[rax]
         // 00402083: cmp ds:[rbx], rcx
         // 00402086: setz b1 al
         // 00402089: retn 
      [-]488b0848390b0f94c0c3
         // 004020a0: mov rcx, ds:[rax]
         // 004020a3: cmp ds:[rbx], rcx
         // 004020a6: setz b1 al
         // 004020a9: retn 
      [-]b8????????c3
         // 00402140: mov b4 eax, b4 0x1
         // 00402145: retn 
      [-]493b66107622
         // 00402160: cmp rsp, ds:[r14+0x10]
         // 00402164: jbe 0x402188
      [-]4883ec2048896c2418488d6c2418b9????????e8e20b0000488b6c24184883c420c3
         // 00402166: sub rsp, 0x20
         // 0040216a: mov ss:[rsp+0x18], rbp
         // 0040216f: lea rbp, ss:[rsp+0x18]
         // 00402174: mov b4 ecx, b4 0x10a
         // 00402179: call runtime.memequal
         // 0040217e: mov rbp, ss:[rsp+0x18]
         // 00402183: add rsp, 0x20
         // 00402187: retn 
      [-]488944240848895c2410e869160600488b442408488b5c2410ebbd
         // 00402188: mov ss:[rsp+0x8], rax
         // 0040218d: mov ss:[rsp+0x10], rbx
         // 00402192: call runtime.morestack_noctxt
         // 00402197: mov rax, ss:[rsp+0x8]
         // 0040219c: mov rbx, ss:[rsp+0x10]
         // 004021a1: jmp type:.eq.internal_abi.RegArgs
      [-]4839fe0f8422010000
         // 004027a0: cmp rsi, rdi
         // 004027a3: jz 0x4028cb
      [-]4839d34989d04c0f4cc34983f8080f82b6000000
         // 004027a9: cmp rbx, rdx
         // 004027ac: mov r8, rdx
         // 004027af: cmovl r8, rbx
         // 004027b3: cmp r8, 0x8
         // 004027b7: jb 0x402873
      [-]4983f83f7612
         // 004027bd: cmp r8, 0x3f
         // 004027c1: jbe 0x4027d5
      [-]803d39246200010f84a1010000
         // 004027c3: cmp b1 cs:[0xa24c03], b1 0x1
         // 004027ca: jz 0x402971
      [-]e90b010000
         // 004027d0: jmp 0x4028e0
      [-]4983f810765b
         // 004027d5: cmp r8, 0x10
         // 004027d9: jbe 0x402836
      [-]f30f6f06f30f6f0f660f74c8660fd7c14835ffff0000752a
         // 004027db: movdqu b16 xmm0, b16 ds:[rsi]
         // 004027df: movdqu b16 xmm1, b16 ds:[rdi]
         // 004027e3: pcmpeqb b16 xmm1, b16 xmm0
         // 004027e7: pmovmskb b4 eax, b16 xmm1
         // 004027eb: xor rax, 0xffff
         // 004027f1: jnz 0x40281d
      [-]4883c6104883c7104983e810ebd4
         // 004027f3: add rsi, 0x10
         // 004027f7: add rdi, 0x10
         // 004027fb: sub r8, 0x10
         // 004027ff: jmp 0x4027d5
      [-]4883c6304883c730eb12
         // 00402801: add rsi, 0x30
         // 00402805: add rdi, 0x30
         // 00402809: jmp 0x40281d
      [-]4883c6204883c720eb08
         // 0040280b: add rsi, 0x20
         // 0040280f: add rdi, 0x20
         // 00402813: jmp 0x40281d
      [-]4883c6104883c710
         // 00402815: add rsi, 0x10
         // 00402819: add rdi, 0x10
      [-]480fbcd84831c08a0c1e3a0c1f0f97c0488d0445ffffffffc3
         // 0040281d: bsf rbx, rax
         // 00402821: xor rax, rax
         // 00402824: mov b1 cl, b1 ds:[rsi+rbx]
         // 00402827: cmp b1 cl, b1 ds:[rdi+rbx]
         // 0040282a: setnbe b1 al
         // 0040282d: lea rax, ds:[0xffffffffffffffff+rax*0x2]
         // 00402835: retn 
      [-]4983f808760b
         // 00402836: cmp r8, 0x8
         // 0040283a: jbe 0x402847
      [-]488b06488b0f4839c8750f
         // 0040283c: mov rax, ds:[rsi]
         // 0040283f: mov rcx, ds:[rdi]
         // 00402842: cmp rax, rcx
         // 00402845: jnz 0x402856
      [-]4a8b4406f84a8b4c07f84839c87475
         // 00402847: mov rax, ds:[rsi+r8+0xfffffffffffffff8]
         // 0040284c: mov rcx, ds:[rdi+r8+0xfffffffffffffff8]
         // 00402851: cmp rax, rcx
         // 00402854: jz 0x4028cb
      [-]480fc8480fc94831c1480fbdc948d3e84883e001488d0445ffffffffc3
         // 00402856: bswap rax
         // 00402859: bswap rcx
         // 0040285c: xor rcx, rax
         // 0040285f: bsr rcx, rcx
         // 00402863: shr rax, b1 cl
         // 00402866: and rax, 0x1
         // 0040286a: lea rax, ds:[0xffffffffffffffff+rax*0x2]
         // 00402872: retn 
      [-]4a8d0cc50000000048f7d9744b
         // 00402873: lea rcx, ds:[r8*0x8]
         // 0040287b: neg rcx
         // 0040287e: jz 0x4028cb
      [-]4080fef87705
         // 00402880: cmp b1 sil, b1 0xf8
         // 00402884: ja 0x40288b
      [-]488b36eb08
         // 00402886: mov rsi, ds:[rsi]
         // 00402889: jmp 0x402893
      [-]4a8b7406f848d3ee
         // 0040288b: mov rsi, ds:[rsi+r8+0xfffffffffffffff8]
         // 00402890: shr rsi, b1 cl
      [-]48d3e64080fff87705
         // 00402893: shl rsi, b1 cl
         // 00402896: cmp b1 dil, b1 0xf8
         // 0040289a: ja 0x4028a1
      [-]488b3feb08
         // 0040289c: mov rdi, ds:[rdi]
         // 0040289f: jmp 0x4028a9
      [-]4a8b7c07f848d3ef
         // 004028a1: mov rdi, ds:[rdi+r8+0xfffffffffffffff8]
         // 004028a6: shr rdi, b1 cl
      [-]48d3e7480fce480fcf4831f77414
         // 004028a9: shl rdi, b1 cl
         // 004028ac: bswap rsi
         // 004028af: bswap rdi
         // 004028b2: xor rdi, rsi
         // 004028b5: jz 0x4028cb
      [-]480fbdcf48d3ee4883e601488d0475ffffffffc3
         // 004028b7: bsr rcx, rdi
         // 004028bb: shr rsi, b1 cl
         // 004028be: and rsi, 0x1
         // 004028c2: lea rax, ds:[0xffffffffffffffff+rsi*0x2]
         // 004028ca: retn 
      [-]4831c04831c94839d30f9fc00f94c1488d4441ffc3
         // 004028cb: xor rax, rax
         // 004028ce: xor rcx, rcx
         // 004028d1: cmp rbx, rdx
         // 004028d4: setnle b1 al
         // 004028d7: setz b1 cl
         // 004028da: lea rax, ds:[rcx+rax*0x2]
         // 004028df: retn 
      [-]f30f6f06f30f6f0f660f74c8660fd7c14835ffff00000f8521ffffff
         // 004028e0: movdqu b16 xmm0, b16 ds:[rsi]
         // 004028e4: movdqu b16 xmm1, b16 ds:[rdi]
         // 004028e8: pcmpeqb b16 xmm1, b16 xmm0
         // 004028ec: pmovmskb b4 eax, b16 xmm1
         // 004028f0: xor rax, 0xffff
         // 004028f6: jnz 0x40281d
      [-]f30f6f4610f30f6f4f10660f74c8660fd7c14835ffff00000f85fbfeffff
         // 004028fc: movdqu b16 xmm0, b16 ds:[rsi+0x10]
         // 00402901: movdqu b16 xmm1, b16 ds:[rdi+0x10]
         // 00402906: pcmpeqb b16 xmm1, b16 xmm0
         // 0040290a: pmovmskb b4 eax, b16 xmm1
         // 0040290e: xor rax, 0xffff
         // 00402914: jnz 0x402815
      [-]f30f6f4620f30f6f4f20660f74c8660fd7c14835ffff00000f85d3feffff
         // 0040291a: movdqu b16 xmm0, b16 ds:[rsi+0x20]
         // 0040291f: movdqu b16 xmm1, b16 ds:[rdi+0x20]
         // 00402924: pcmpeqb b16 xmm1, b16 xmm0
         // 00402928: pmovmskb b4 eax, b16 xmm1
         // 0040292c: xor rax, 0xffff
         // 00402932: jnz 0x40280b
      [-]f30f6f4630f30f6f4f30660f74c8660fd7c14835ffff00000f85abfeffff
         // 00402938: movdqu b16 xmm0, b16 ds:[rsi+0x30]
         // 0040293d: movdqu b16 xmm1, b16 ds:[rdi+0x30]
         // 00402942: pcmpeqb b16 xmm1, b16 xmm0
         // 00402946: pmovmskb b4 eax, b16 xmm1
         // 0040294a: xor rax, 0xffff
         // 00402950: jnz 0x402801
      [-]4883c6404883c7404983e8404983f8400f8669feffff
         // 00402956: add rsi, 0x40
         // 0040295a: add rdi, 0x40
         // 0040295e: sub r8, 0x40
         // 00402962: cmp r8, 0x40
         // 00402966: jbe 0x4027d5
      [-]e96fffffff
         // 0040296c: jmp 0x4028e0
      [-]c5fe6f16c5fe6f1fc5fe6f6620c5fe6f6f20c5e574c2c5fdd7c035????????7523
         // 00402971: vmovdqu b32 ymm2, b32 ds:[rsi]
         // 00402975: vmovdqu b32 ymm3, b32 ds:[rdi]
         // 00402979: vmovdqu b32 ymm4, b32 ds:[rsi+0x20]
         // 0040297e: vmovdqu b32 ymm5, b32 ds:[rdi+0x20]
         // 00402983: vpcmpeqb b32 ymm0, b32 ymm3, b32 ymm2
         // 00402987: vpmovmskb b4 eax, b32 ymm0
         // 0040298b: xor b4 eax, b4 0xffffffffffffffff
         // 00402990: jnz 0x4029b5
      [-]c5d574f4c5fdd7c635????????751c
         // 00402992: vpcmpeqb b32 ymm6, b32 ymm5, b32 ymm4
         // 00402996: vpmovmskb b4 eax, b32 ymm6
         // 0040299a: xor b4 eax, b4 0xffffffffffffffff
         // 0040299f: jnz 0x4029bd
      [-]4883c6404883c7404983e8404983f8407212
         // 004029a1: add rsi, 0x40
         // 004029a5: add rdi, 0x40
         // 004029a9: sub r8, 0x40
         // 004029ad: cmp r8, 0x40
         // 004029b1: jb 0x4029c5
      [-]c5f877e960feffff
         // 004029b5: vzeroupper 
         // 004029b8: jmp 0x40281d
      [-]c5f877e946feffff
         // 004029bd: vzeroupper 
         // 004029c0: jmp 0x40280b
      [-]c5f877e908feffff
         // 004029c5: vzeroupper 
         // 004029c8: jmp 0x4027d5
      [-]4889f24889c6e9b5fdffff
         // 004029e0: mov rdx, rsi
         // 004029e3: mov rsi, rax
         // 004029e6: jmp cmpbody
      [-]4889c64889fa4889cfe992fdffff
         // 00402a00: mov rsi, rax
         // 00402a03: mov rdx, rdi
         // 00402a06: mov rdi, rcx
         // 00402a09: jmp cmpbody
      [-]66480f6ec0660f60c0660f60c0660f70c0004883fb107c6e
         // 00402a20: movq b16 xmm0, rax
         // 00402a25: punpcklbw b16 xmm0, b16 xmm0
         // 00402a29: punpcklbw b16 xmm0, b16 xmm0
         // 00402a2d: pshufd b16 xmm0, b16 xmm0, b1 0x0
         // 00402a32: cmp rbx, 0x10
         // 00402a36: jl 0x402aa6
      [-]49c7c4000000004889f74883fb200f87c8000000
         // 00402a38: mov r12, 0x0
         // 00402a3f: mov rdi, rsi
         // 00402a42: cmp rbx, 0x20
         // 00402a46: ja 0x402b14
      [-]488d441ef0eb17
         // 00402a4c: lea rax, ds:[rsi+rbx+0xfffffffffffffff0]
         // 00402a51: jmp 0x402a6a
      [-]f30f6f0f660f74c8660fd7d1f30fb8d24901d44883c710
         // 00402a53: movdqu b16 xmm1, b16 ds:[rdi]
         // 00402a57: pcmpeqb b16 xmm1, b16 xmm0
         // 00402a5b: pmovmskb b4 edx, b16 xmm1
         // 00402a5f: popcnt b4 edx, b4 edx
         // 00402a63: add r12, rdx
         // 00402a66: add rdi, 0x10
      [-]4839c776e4
         // 00402a6a: cmp rdi, rax
         // 00402a6d: jbe 0x402a53
      [-]4883e30f742d
         // 00402a6f: and rbx, 0xf
         // 00402a73: jz 0x402aa2
      [-]48c7c1100000004829d949c7c2ffff000049d3fa49d3e2f30f6f08660f74c8660fd7d14c21d2f30fb8d24901d4
         // 00402a75: mov rcx, 0x10
         // 00402a7c: sub rcx, rbx
         // 00402a7f: mov r10, 0xffff
         // 00402a86: sar r10, b1 cl
         // 00402a89: shl r10, b1 cl
         // 00402a8c: movdqu b16 xmm1, b16 ds:[rax]
         // 00402a90: pcmpeqb b16 xmm1, b16 xmm0
         // 00402a94: pmovmskb b4 edx, b16 xmm1
         // 00402a98: and rdx, r10
         // 00402a9b: popcnt b4 edx, b4 edx
         // 00402a9f: add r12, rdx
      [-]4d8920c3
         // 00402aa2: mov ds:[r8], r12
         // 00402aa5: retn 
      [-]4885db7431
         // 00402aa6: test rbx, rbx
         // 00402aa9: jz 0x402adc
      [-]488d461066a9f00f742f
         // 00402aab: lea rax, ds:[rsi+0x10]
         // 00402aaf: test b2 ax, b2 0xff0
         // 00402ab3: jz 0x402ae4
      [-]88d949c7c20100000049d3e24983ea01f30f6f0e660f74c8660fd7d14c21d2f30fb8d2498910c3
         // 00402ab5: mov b1 cl, b1 bl
         // 00402ab7: mov r10, 0x1
         // 00402abe: shl r10, b1 cl
         // 00402ac1: sub r10, 0x1
         // 00402ac5: movdqu b16 xmm1, b16 ds:[rsi]
         // 00402ac9: pcmpeqb b16 xmm1, b16 xmm0
         // 00402acd: pmovmskb b4 edx, b16 xmm1
         // 00402ad1: and rdx, r10
         // 00402ad4: popcnt b4 edx, b4 edx
         // 00402ad8: mov ds:[r8], rdx
         // 00402adb: retn 
      [-]49c70000000000c3
         // 00402adc: mov ds:[r8], 0x0
         // 00402ae3: retn 
      [-]48c7c1100000004829d949c7c2ffff000049d3fa49d3e2f30f6f4c1ef0660f74c8660fd7d14c21d2f30fb8d2498910c3
         // 00402ae4: mov rcx, 0x10
         // 00402aeb: sub rcx, rbx
         // 00402aee: mov r10, 0xffff
         // 00402af5: sar r10, b1 cl
         // 00402af8: shl r10, b1 cl
         // 00402afb: movdqu b16 xmm1, b16 ds:[rsi+rbx+0xfffffffffffffff0]
         // 00402b01: pcmpeqb b16 xmm1, b16 xmm0
         // 00402b05: pmovmskb b4 edx, b16 xmm1
         // 00402b09: and rdx, r10
         // 00402b0c: popcnt b4 edx, b4 edx
         // 00402b10: mov ds:[r8], rdx
         // 00402b13: retn 
      [-]803de8206200010f852bffffff
         // 00402b14: cmp b1 cs:[0xa24c03], b1 0x1
         // 00402b1b: jnz 0x402a4c
      [-]66480f6ec04c8d5c1ee0c4e27d78c8
         // 00402b21: movq b16 xmm0, rax
         // 00402b26: lea r11, ds:[rsi+rbx+0xffffffffffffffe0]
         // 00402b2b: vpbroadcastb b32 ymm1, b16 xmm0
      [-]c5fe6f17c5ed74d9c5fdd7d3f30fb8d24901d44883c7204c39df7ee4
         // 00402b30: vmovdqu b32 ymm2, b32 ds:[rdi]
         // 00402b34: vpcmpeqb b32 ymm3, b32 ymm2, b32 ymm1
         // 00402b38: vpmovmskb b4 edx, b32 ymm3
         // 00402b3c: popcnt b4 edx, b4 edx
         // 00402b40: add r12, rdx
         // 00402b43: add rdi, 0x20
         // 00402b47: cmp rdi, r11
         // 00402b4a: jle 0x402b30
      [-]4c39df743a
         // 00402b4c: cmp rdi, r11
         // 00402b4f: jz 0x402b8b
      [-]4c89dfc5fe6f17c5ed74d9c5fdd7d3c5f8774883e31f48c7c1200000004829d941ba????????49d3fa49d3e24c21d2f30fb8d24901d44d8920c3
         // 00402b51: mov rdi, r11
         // 00402b54: vmovdqu b32 ymm2, b32 ds:[rdi]
         // 00402b58: vpcmpeqb b32 ymm3, b32 ymm2, b32 ymm1
         // 00402b5c: vpmovmskb b4 edx, b32 ymm3
         // 00402b60: vzeroupper 
         // 00402b63: and rbx, 0x1f
         // 00402b67: mov rcx, 0x20
         // 00402b6e: sub rcx, rbx
         // 00402b71: mov b4 r10d, b4 0xffffffffffffffff
         // 00402b77: sar r10, b1 cl
         // 00402b7a: shl r10, b1 cl
         // 00402b7d: and rdx, r10
         // 00402b80: popcnt b4 edx, b4 edx
         // 00402b84: add r12, rdx
         // 00402b87: mov ds:[r8], r12
         // 00402b8a: retn 
      [-]c5f8774d8920c3
         // 00402b8b: vzeroupper 
         // 00402b8e: mov ds:[r8], r12
         // 00402b91: retn 
      [-]803d63206200017405
         // 00402ba0: cmp b1 cs:[0xa24c0a], b1 0x1
         // 00402ba7: jz 0x402bae
      [-]e9d2060000
         // 00402ba9: jmp internal_bytealg.countGeneric_0
      [-]488b742408488b5c24108a4424204c8d442428e95afeffff
         // 00402bae: mov rsi, ss:[rsp+0x8]
         // 00402bb3: mov rbx, ss:[rsp+0x10]
         // 00402bb8: mov b1 al, b1 ss:[rsp+0x20]
         // 00402bbc: lea r8, ss:[rsp+0x28]
         // 00402bc1: jmp countbody
      [-]803d23206200017405
         // 00402be0: cmp b1 cs:[0xa24c0a], b1 0x1
         // 00402be7: jz 0x402bee
      [-]e9f2060000
         // 00402be9: jmp internal_bytealg.countGenericString_0
      [-]488b742408488b5c24108a4424184c8d442420e91afeffff
         // 00402bee: mov rsi, ss:[rsp+0x8]
         // 00402bf3: mov rbx, ss:[rsp+0x10]
         // 00402bf8: mov b1 al, b1 ss:[rsp+0x18]
         // 00402bfc: lea r8, ss:[rsp+0x20]
         // 00402c01: jmp countbody
      [-]4883fb080f82f3000000
         // 00402c20: cmp rbx, 0x8
         // 00402c24: jb 0x402d1d
      [-]4883fb400f82b7000000
         // 00402c2a: cmp rbx, 0x40
         // 00402c2e: jb 0x402ceb
      [-]803dc81f6200017468
         // 00402c34: cmp b1 cs:[0xa24c03], b1 0x1
         // 00402c3b: jz 0x402ca5
      [-]4883fb400f82a4000000
         // 00402c3d: cmp rbx, 0x40
         // 00402c41: jb 0x402ceb
      [-]f30f6f06f30f6f0ff30f6f5610f30f6f5f10f30f6f6620f30f6f6f20f30f6f7630f30f6f7f30660f74c1660f74d3660f74e5660f74f7660fdbc2660fdbe6660fdbc4660fd7d04883c6404883c7404883eb4081fa????????749c
         // 00402c47: movdqu b16 xmm0, b16 ds:[rsi]
         // 00402c4b: movdqu b16 xmm1, b16 ds:[rdi]
         // 00402c4f: movdqu b16 xmm2, b16 ds:[rsi+0x10]
         // 00402c54: movdqu b16 xmm3, b16 ds:[rdi+0x10]
         // 00402c59: movdqu b16 xmm4, b16 ds:[rsi+0x20]
         // 00402c5e: movdqu b16 xmm5, b16 ds:[rdi+0x20]
         // 00402c63: movdqu b16 xmm6, b16 ds:[rsi+0x30]
         // 00402c68: movdqu b16 xmm7, b16 ds:[rdi+0x30]
         // 00402c6d: pcmpeqb b16 xmm0, b16 xmm1
         // 00402c71: pcmpeqb b16 xmm2, b16 xmm3
         // 00402c75: pcmpeqb b16 xmm4, b16 xmm5
         // 00402c79: pcmpeqb b16 xmm6, b16 xmm7
         // 00402c7d: pand b16 xmm0, b16 xmm2
         // 00402c81: pand b16 xmm4, b16 xmm6
         // 00402c85: pand b16 xmm0, b16 xmm4
         // 00402c89: pmovmskb b4 edx, b16 xmm0
         // 00402c8d: add rsi, 0x40
         // 00402c91: add rdi, 0x40
         // 00402c95: sub rbx, 0x40
         // 00402c99: cmp b4 edx, b4 0xffff
         // 00402c9f: jz 0x402c3d
      [-]4831c0c3
         // 00402ca1: xor rax, rax
         // 00402ca4: retn 
      [-]4883fb40723d
         // 00402ca5: cmp rbx, 0x40
         // 00402ca9: jb 0x402ce8
      [-]c5fe6f06c5fe6f0fc5fe6f5620c5fe6f5f20c5fd74e1c5e574eac5d5dbf4c5fdd7d64883c6404883c7404883eb4081fa????????74c4
         // 00402cab: vmovdqu b32 ymm0, b32 ds:[rsi]
         // 00402caf: vmovdqu b32 ymm1, b32 ds:[rdi]
         // 00402cb3: vmovdqu b32 ymm2, b32 ds:[rsi+0x20]
         // 00402cb8: vmovdqu b32 ymm3, b32 ds:[rdi+0x20]
         // 00402cbd: vpcmpeqb b32 ymm4, b32 ymm0, b32 ymm1
         // 00402cc1: vpcmpeqb b32 ymm5, b32 ymm3, b32 ymm2
         // 00402cc5: vpand b32 ymm6, b32 ymm5, b32 ymm4
         // 00402cc9: vpmovmskb b4 edx, b32 ymm6
         // 00402ccd: add rsi, 0x40
         // 00402cd1: add rdi, 0x40
         // 00402cd5: sub rbx, 0x40
         // 00402cd9: cmp b4 edx, b4 0xffffffffffffffff
         // 00402cdf: jz 0x402ca5
      [-]c5f8774831c0c3
         // 00402ce1: vzeroupper 
         // 00402ce4: xor rax, rax
         // 00402ce7: retn 
      [-]4883fb08761b
         // 00402ceb: cmp rbx, 0x8
         // 00402cef: jbe 0x402d0c
      [-]488b0e488b174883c6084883c7084883eb084839d174e3
         // 00402cf1: mov rcx, ds:[rsi]
         // 00402cf4: mov rdx, ds:[rdi]
         // 00402cf7: add rsi, 0x8
         // 00402cfb: add rdi, 0x8
         // 00402cff: sub rbx, 0x8
         // 00402d03: cmp rcx, rdx
         // 00402d06: jz 0x402ceb
      [-]4831c0c3
         // 00402d08: xor rax, rax
         // 00402d0b: retn 
      [-]488b4c1ef8488b541ff84839d10f94c0c3
         // 00402d0c: mov rcx, ds:[rsi+rbx+0xfffffffffffffff8]
         // 00402d11: mov rdx, ds:[rdi+rbx+0xfffffffffffffff8]
         // 00402d16: cmp rcx, rdx
         // 00402d19: setz b1 al
         // 00402d1c: retn 
      [-]4883fb007437
         // 00402d1d: cmp rbx, 0x0
         // 00402d21: jz 0x402d5a
      [-]488d0cdd0000000048f7d94080fef87705
         // 00402d23: lea rcx, ds:[rbx*0x8]
         // 00402d2b: neg rcx
         // 00402d2e: cmp b1 sil, b1 0xf8
         // 00402d32: ja 0x402d39
      [-]488b36eb08
         // 00402d34: mov rsi, ds:[rsi]
         // 00402d37: jmp 0x402d41
      [-]488b741ef848d3ee
         // 00402d39: mov rsi, ds:[rsi+rbx+0xfffffffffffffff8]
         // 00402d3e: shr rsi, b1 cl
      [-]4080fff87705
         // 00402d41: cmp b1 dil, b1 0xf8
         // 00402d45: ja 0x402d4c
      [-]488b3feb08
         // 00402d47: mov rdi, ds:[rdi]
         // 00402d4a: jmp 0x402d54
      [-]488b7c1ff848d3ef
         // 00402d4c: mov rdi, ds:[rdi+rbx+0xfffffffffffffff8]
         // 00402d51: shr rdi, b1 cl
      [-]4829f748d3e7
         // 00402d54: sub rdi, rsi
         // 00402d57: shl rdi, b1 cl
      [-]0f94c0c3
         // 00402d5a: setz b1 al
         // 00402d5d: retn 
      [-]4839d87508
         // 00402d60: cmp rax, rbx
         // 00402d63: jnz 0x402d6d
      [-]48c7c001000000c3
         // 00402d65: mov rax, 0x1
         // 00402d6c: retn 
      [-]4889c64889df4889cbe9a5feffff
         // 00402d6d: mov rsi, rax
         // 00402d70: mov rdi, rbx
         // 00402d73: mov rbx, rcx
         // 00402d76: jmp memeqbody
      [-]4839d87508
         // 00402d80: cmp rax, rbx
         // 00402d83: jnz 0x402d8d
      [-]48c7c001000000c3
         // 00402d85: mov rax, 0x1
         // 00402d8c: retn 
      [-]4889c64889df488b5a08e984feffff
         // 00402d8d: mov rsi, rax
         // 00402d90: mov rdi, rbx
         // 00402d93: mov rbx, ds:[rdx+0x8]
         // 00402d97: jmp memeqbody
      [-]4839d00f8777020000
         // 00402da0: cmp rax, rdx
         // 00402da3: ja 0x403020
      [-]4883fa100f837a020000
         // 00402da9: cmp rdx, 0x10
         // 00402dad: jnb 0x40302d
      [-]4883f8027724
         // 00402db3: cmp rax, 0x2
         // 00402db7: ja 0x402ddd
      [-]66458b00488d5417ff
         // 00402db9: mov b2 r8w, b2 ds:[r8]
         // 00402dbd: lea rdx, ds:[rdi+rdx+0xffffffffffffffff]
      [-]668b37664439c60f84be020000
         // 00402dc2: mov b2 si, b2 ds:[rdi]
         // 00402dc5: cmp b2 si, b2 r8w
         // 00402dc9: jz 0x40308d
      [-]4883c7014839d772ea
         // 00402dcf: add rdi, 0x1
         // 00402dd3: cmp rdi, rdx
         // 00402dd6: jb 0x402dc2
      [-]e943020000
         // 00402dd8: jmp 0x403020
      [-]4883f8037740
         // 00402ddd: cmp rax, 0x3
         // 00402de1: ja 0x402e23
      [-]66418b580166458b00488d5417fe
         // 00402de3: mov b2 bx, b2 ds:[r8+0x1]
         // 00402de8: mov b2 r8w, b2 ds:[r8]
         // 00402dec: lea rdx, ds:[rdi+rdx+0xfffffffffffffffe]
      [-]668b37664439c6740e
         // 00402df1: mov b2 si, b2 ds:[rdi]
         // 00402df4: cmp b2 si, b2 r8w
         // 00402df8: jz 0x402e08
      [-]4883c7014839d772ee
         // 00402dfa: add rdi, 0x1
         // 00402dfe: cmp rdi, rdx
         // 00402e01: jb 0x402df1
      [-]e918020000
         // 00402e03: jmp 0x403020
      [-]668b77016639de0f8478020000
         // 00402e08: mov b2 si, b2 ds:[rdi+0x1]
         // 00402e0c: cmp b2 si, b2 bx
         // 00402e0f: jz 0x40308d
      [-]4883c7014839d772d3
         // 00402e15: add rdi, 0x1
         // 00402e19: cmp rdi, rdx
         // 00402e1c: jb 0x402df1
      [-]e9fd010000
         // 00402e1e: jmp 0x403020
      [-]4883f8047721
         // 00402e23: cmp rax, 0x4
         // 00402e27: ja 0x402e4a
      [-]458b00488d5417fd
         // 00402e29: mov b4 r8d, b4 ds:[r8]
         // 00402e2c: lea rdx, ds:[rdi+rdx+0xfffffffffffffffd]
      [-]8b374439c60f8451020000
         // 00402e31: mov b4 esi, b4 ds:[rdi]
         // 00402e33: cmp b4 esi, b4 r8d
         // 00402e36: jz 0x40308d
      [-]4883c7014839d772ec
         // 00402e3c: add rdi, 0x1
         // 00402e40: cmp rdi, rdx
         // 00402e43: jb 0x402e31
      [-]e9d6010000
         // 00402e45: jmp 0x403020
      [-]4883f807773f
         // 00402e4a: cmp rax, 0x7
         // 00402e4e: ja 0x402e8f
      [-]488d5417014829c2418b5c00fc458b00
         // 00402e50: lea rdx, ds:[rdi+rdx+0x1]
         // 00402e55: sub rdx, rax
         // 00402e58: mov b4 ebx, b4 ds:[r8+rax+0xfffffffffffffffc]
         // 00402e5d: mov b4 r8d, b4 ds:[r8]
      [-]8b374439c6740e
         // 00402e60: mov b4 esi, b4 ds:[rdi]
         // 00402e62: cmp b4 esi, b4 r8d
         // 00402e65: jz 0x402e75
      [-]4883c7014839d772f0
         // 00402e67: add rdi, 0x1
         // 00402e6b: cmp rdi, rdx
         // 00402e6e: jb 0x402e60
      [-]e9ab010000
         // 00402e70: jmp 0x403020
      [-]8b7438fc39de0f840c020000
         // 00402e75: mov b4 esi, b4 ds:[rax+rdi+0xfffffffffffffffc]
         // 00402e79: cmp b4 esi, b4 ebx
         // 00402e7b: jz 0x40308d
      [-]4883c7014839d772d6
         // 00402e81: add rdi, 0x1
         // 00402e85: cmp rdi, rdx
         // 00402e88: jb 0x402e60
      [-]e991010000
         // 00402e8a: jmp 0x403020
      [-]4883f8087722
         // 00402e8f: cmp rax, 0x8
         // 00402e93: ja 0x402eb7
      [-]4d8b00488d5417f9
         // 00402e95: mov r8, ds:[r8]
         // 00402e98: lea rdx, ds:[rdi+rdx+0xfffffffffffffff9]
      [-]488b374c39c60f84e4010000
         // 00402e9d: mov rsi, ds:[rdi]
         // 00402ea0: cmp rsi, r8
         // 00402ea3: jz 0x40308d
      [-]4883c7014839d772eb
         // 00402ea9: add rdi, 0x1
         // 00402ead: cmp rdi, rdx
         // 00402eb0: jb 0x402e9d
      [-]e969010000
         // 00402eb2: jmp 0x403020
      [-]4883f80f7742
         // 00402eb7: cmp rax, 0xf
         // 00402ebb: ja 0x402eff
      [-]488d5417014829c2498b5c00f84d8b00
         // 00402ebd: lea rdx, ds:[rdi+rdx+0x1]
         // 00402ec2: sub rdx, rax
         // 00402ec5: mov rbx, ds:[r8+rax+0xfffffffffffffff8]
         // 00402eca: mov r8, ds:[r8]
      [-]488b374c39c6740e
         // 00402ecd: mov rsi, ds:[rdi]
         // 00402ed0: cmp rsi, r8
         // 00402ed3: jz 0x402ee3
      [-]4883c7014839d772ef
         // 00402ed5: add rdi, 0x1
         // 00402ed9: cmp rdi, rdx
         // 00402edc: jb 0x402ecd
      [-]e93d010000
         // 00402ede: jmp 0x403020
      [-]488b7438f84839de0f849c010000
         // 00402ee3: mov rsi, ds:[rax+rdi+0xfffffffffffffff8]
         // 00402ee8: cmp rsi, rbx
         // 00402eeb: jz 0x40308d
      [-]4883c7014839d772d3
         // 00402ef1: add rdi, 0x1
         // 00402ef5: cmp rdi, rdx
         // 00402ef8: jb 0x402ecd
      [-]e921010000
         // 00402efa: jmp 0x403020
      [-]4883f8107731
         // 00402eff: cmp rax, 0x10
         // 00402f03: ja 0x402f36
      [-]f3410f6f08488d5417f1
         // 00402f05: movdqu b16 xmm1, b16 ds:[r8]
         // 00402f0a: lea rdx, ds:[rdi+rdx+0xfffffffffffffff1]
      [-]f30f6f17660f74d1660fd7f24881feffff00000f8465010000
         // 00402f0f: movdqu b16 xmm2, b16 ds:[rdi]
         // 00402f13: pcmpeqb b16 xmm2, b16 xmm1
         // 00402f17: pmovmskb b4 esi, b16 xmm2
         // 00402f1b: cmp rsi, 0xffff
         // 00402f22: jz 0x40308d
      [-]4883c7014839d772de
         // 00402f28: add rdi, 0x1
         // 00402f2c: cmp rdi, rdx
         // 00402f2f: jb 0x402f0f
      [-]e9ea000000
         // 00402f31: jmp 0x403020
      [-]4883f81f7760
         // 00402f36: cmp rax, 0x1f
         // 00402f3a: ja 0x402f9c
      [-]488d5417014829c2f3410f6f4400f0f3410f6f08
         // 00402f3c: lea rdx, ds:[rdi+rdx+0x1]
         // 00402f41: sub rdx, rax
         // 00402f44: movdqu b16 xmm0, b16 ds:[r8+rax+0xfffffffffffffff0]
         // 00402f4b: movdqu b16 xmm1, b16 ds:[r8]
      [-]f30f6f17660f74d1660fd7f24881feffff0000740e
         // 00402f50: movdqu b16 xmm2, b16 ds:[rdi]
         // 00402f54: pcmpeqb b16 xmm2, b16 xmm1
         // 00402f58: pmovmskb b4 esi, b16 xmm2
         // 00402f5c: cmp rsi, 0xffff
         // 00402f63: jz 0x402f73
      [-]4883c7014839d772e2
         // 00402f65: add rdi, 0x1
         // 00402f69: cmp rdi, rdx
         // 00402f6c: jb 0x402f50
      [-]e9ad000000
         // 00402f6e: jmp 0x403020
      [-]f30f6f5c38f0660f74d8660fd7f34881feffff00000f84ff000000
         // 00402f73: movdqu b16 xmm3, b16 ds:[rax+rdi+0xfffffffffffffff0]
         // 00402f79: pcmpeqb b16 xmm3, b16 xmm0
         // 00402f7d: pmovmskb b4 esi, b16 xmm3
         // 00402f81: cmp rsi, 0xffff
         // 00402f88: jz 0x40308d
      [-]4883c7014839d772b9
         // 00402f8e: add rdi, 0x1
         // 00402f92: cmp rdi, rdx
         // 00402f95: jb 0x402f50
      [-]e984000000
         // 00402f97: jmp 0x403020
      [-]4883f8207729
         // 00402f9c: cmp rax, 0x20
         // 00402fa0: ja 0x402fcb
      [-]c4c17e6f08488d5417e1
         // 00402fa2: vmovdqu b32 ymm1, b32 ds:[r8]
         // 00402fa7: lea rdx, ds:[rdi+rdx+0xffffffffffffffe1]
      [-]c5fe6f17c5ed74d9c5fdd7f381fe????????7468
         // 00402fac: vmovdqu b32 ymm2, b32 ds:[rdi]
         // 00402fb0: vpcmpeqb b32 ymm3, b32 ymm2, b32 ymm1
         // 00402fb4: vpmovmskb b4 esi, b32 ymm3
         // 00402fb8: cmp b4 esi, b4 0xffffffffffffffff
         // 00402fbe: jz 0x403028
      [-]4883c7014839d772e3
         // 00402fc0: add rdi, 0x1
         // 00402fc4: cmp rdi, rdx
         // 00402fc7: jb 0x402fac
      [-]488d5417014829c2c4c17e6f4400e0c4c17e6f08
         // 00402fcb: lea rdx, ds:[rdi+rdx+0x1]
         // 00402fd0: sub rdx, rax
         // 00402fd3: vmovdqu b32 ymm0, b32 ds:[r8+rax+0xffffffffffffffe0]
         // 00402fda: vmovdqu b32 ymm1, b32 ds:[r8]
      [-]c5fe6f17c5ed74d9c5fdd7f381fe????????740b
         // 00402fdf: vmovdqu b32 ymm2, b32 ds:[rdi]
         // 00402fe3: vpcmpeqb b32 ymm3, b32 ymm2, b32 ymm1
         // 00402fe7: vpmovmskb b4 esi, b32 ymm3
         // 00402feb: cmp b4 esi, b4 0xffffffffffffffff
         // 00402ff1: jz 0x402ffe
      [-]4883c7014839d772e3
         // 00402ff3: add rdi, 0x1
         // 00402ff7: cmp rdi, rdx
         // 00402ffa: jb 0x402fdf
      [-]c5fe6f5c38e0c5e574e0c5fdd7f481fe????????7414
         // 00402ffe: vmovdqu b32 ymm3, b32 ds:[rax+rdi+0xffffffffffffffe0]
         // 00403004: vpcmpeqb b32 ymm4, b32 ymm3, b32 ymm0
         // 00403008: vpmovmskb b4 esi, b32 ymm4
         // 0040300c: cmp b4 esi, b4 0xffffffffffffffff
         // 00403012: jz 0x403028
      [-]4883c7014839d772c2
         // 00403014: add rdi, 0x1
         // 00403018: cmp rdi, rdx
         // 0040301b: jb 0x402fdf
      [-]49c703ffffffffc3
         // 00403020: mov ds:[r11], 0xffffffffffffffff
         // 00403027: retn 
      [-]c5f877eb60
         // 00403028: vzeroupper 
         // 0040302b: jmp 0x40308d
      [-]803ddc1b6200010f8579fdffff
         // 0040302d: cmp b1 cs:[0xa24c10], b1 0x1
         // 00403034: jnz 0x402db3
      [-]4883f80c0f8373feffff
         // 0040303a: cmp rax, 0xc
         // 0040303e: jnb 0x402eb7
      [-]498d701066f7c6f00f0f8460fdffff
         // 00403044: lea rsi, ds:[r8+0x10]
         // 00403048: test b2 si, b2 0xff0
         // 0040304d: jz 0x402db3
      [-]f3410f6f08488d7417f149c7c1100000004929c1
         // 00403053: movdqu b16 xmm1, b16 ds:[r8]
         // 00403058: lea rsi, ds:[rdi+rdx+0xfffffffffffffff1]
         // 0040305d: mov r9, 0x10
         // 00403064: sub r9, rax
      [-]660f3a610f0c4c39c97618
         // 00403067: pcmpestri b16 xmm1, b16 ds:[rdi], b1 0xc
         // 0040306d: cmp rcx, r9
         // 00403070: jbe 0x40308a
      [-]4c01cf4839f772ed
         // 00403072: add rdi, r9
         // 00403075: cmp rdi, rsi
         // 00403078: jb 0x403067
      [-]660f3a614eff0c4c39c9779a
         // 0040307a: pcmpestri b16 xmm1, b16 ds:[rsi+0xffffffffffffffff], b1 0xc
         // 00403081: cmp rcx, r9
         // 00403084: ja 0x403020
      [-]488d7eff
         // 00403086: lea rdi, ds:[rsi+0xffffffffffffffff]
      [-]4c29d749893bc3
         // 0040308d: sub rdi, r10
         // 00403090: mov ds:[r11], rdi
         // 00403093: retn 
      [-]488b7c2408488b5424104c8b442420488b4424284989fa4c8d5c2438e9dffcffff
         // 004030a0: mov rdi, ss:[rsp+0x8]
         // 004030a5: mov rdx, ss:[rsp+0x10]
         // 004030aa: mov r8, ss:[rsp+0x20]
         // 004030af: mov rax, ss:[rsp+0x28]
         // 004030b4: mov r10, rdi
         // 004030b7: lea r11, ss:[rsp+0x38]
         // 004030bc: jmp indexbody
      [-]488b7c2408488b5424104c8b442418488b4424204989fa4c8d5c2428e99ffcffff
         // 004030e0: mov rdi, ss:[rsp+0x8]
         // 004030e5: mov rdx, ss:[rsp+0x10]
         // 004030ea: mov r8, ss:[rsp+0x18]
         // 004030ef: mov rax, ss:[rsp+0x20]
         // 004030f4: mov r10, rdi
         // 004030f7: lea r11, ss:[rsp+0x28]
         // 004030fc: jmp indexbody
      [-]66480f6ec0660f60c0660f60c0660f70c0004883fb107c54
         // 00403120: movq b16 xmm0, rax
         // 00403125: punpcklbw b16 xmm0, b16 xmm0
         // 00403129: punpcklbw b16 xmm0, b16 xmm0
         // 0040312d: pshufd b16 xmm0, b16 xmm0, b1 0x0
         // 00403132: cmp rbx, 0x10
         // 00403136: jl 0x40318c
      [-]4889f74883fb200f878d000000
         // 00403138: mov rdi, rsi
         // 0040313b: cmp rbx, 0x20
         // 0040313f: ja 0x4031d2
      [-]488d441ef0eb15
         // 00403145: lea rax, ds:[rsi+rbx+0xfffffffffffffff0]
         // 0040314a: jmp 0x403161
      [-]f30f6f0f660f74c8660fd7d10fbcd27525
         // 0040314c: movdqu b16 xmm1, b16 ds:[rdi]
         // 00403150: pcmpeqb b16 xmm1, b16 xmm0
         // 00403154: pmovmskb b4 edx, b16 xmm1
         // 00403158: bsf b4 edx, b4 edx
         // 0040315b: jnz 0x403182
      [-]4883c710
         // 0040315d: add rdi, 0x10
      [-]4839c772e6
         // 00403161: cmp rdi, rax
         // 00403164: jb 0x40314c
      [-]4889c7f30f6f08660f74c8660fd7d10fbcd27508
         // 00403166: mov rdi, rax
         // 00403169: movdqu b16 xmm1, b16 ds:[rax]
         // 0040316d: pcmpeqb b16 xmm1, b16 xmm0
         // 00403171: pmovmskb b4 edx, b16 xmm1
         // 00403175: bsf b4 edx, b4 edx
         // 00403178: jnz 0x403182
      [-]49c700ffffffffc3
         // 0040317a: mov ds:[r8], 0xffffffffffffffff
         // 00403181: retn 
      [-]4829f74801d7498938c3
         // 00403182: sub rdi, rsi
         // 00403185: add rdi, rdx
         // 00403188: mov ds:[r8], rdi
         // 0040318b: retn 
      [-]4885db74e9
         // 0040318c: test rbx, rbx
         // 0040318f: jz 0x40317a
      [-]488d461066a9f00f7419
         // 00403191: lea rax, ds:[rsi+0x10]
         // 00403195: test b2 ax, b2 0xff0
         // 00403199: jz 0x4031b4
      [-]f30f6f0e660f74c8660fd7d10fbcd274ce
         // 0040319b: movdqu b16 xmm1, b16 ds:[rsi]
         // 0040319f: pcmpeqb b16 xmm1, b16 xmm0
         // 004031a3: pmovmskb b4 edx, b16 xmm1
         // 004031a7: bsf b4 edx, b4 edx
         // 004031aa: jz 0x40317a
      [-]39da73ca
         // 004031ac: cmp b4 edx, b4 ebx
         // 004031ae: jnb 0x40317a
      [-]498910c3
         // 004031b0: mov ds:[r8], rdx
         // 004031b3: retn 
      [-]f30f6f4c1ef0660f74c8660fd7d189d9d3e2c1ea100fbcd274ac
         // 004031b4: movdqu b16 xmm1, b16 ds:[rsi+rbx+0xfffffffffffffff0]
         // 004031ba: pcmpeqb b16 xmm1, b16 xmm0
         // 004031be: pmovmskb b4 edx, b16 xmm1
         // 004031c2: mov b4 ecx, b4 ebx
         // 004031c4: shl b4 edx, b1 cl
         // 004031c6: shr b4 edx, b1 0x10
         // 004031c9: bsf b4 edx, b4 edx
         // 004031cc: jz 0x40317a
      [-]498910c3
         // 004031ce: mov ds:[r8], rdx
         // 004031d1: retn 
      [-]803d2a1a6200010f8566ffffff
         // 004031d2: cmp b1 cs:[0xa24c03], b1 0x1
         // 004031d9: jnz 0x403145
      [-]66480f6ec04c8d5c1ee0c4e27d78c8
         // 004031df: movq b16 xmm0, rax
         // 004031e4: lea r11, ds:[rsi+rbx+0xffffffffffffffe0]
         // 004031e9: vpbroadcastb b32 ymm1, b16 xmm0
      [-]c5fe6f17c5ed74d9c4e27d17db7526
         // 004031ee: vmovdqu b32 ymm2, b32 ds:[rdi]
         // 004031f2: vpcmpeqb b32 ymm3, b32 ymm2, b32 ymm1
         // 004031f6: vptest b32 ymm3, b32 ymm3
         // 004031fb: jnz 0x403223
      [-]4883c7204c39df7ce8
         // 004031fd: add rdi, 0x20
         // 00403201: cmp rdi, r11
         // 00403204: jl 0x4031ee
      [-]4c89dfc5fe6f17c5ed74d9c4e27d17db750b
         // 00403206: mov rdi, r11
         // 00403209: vmovdqu b32 ymm2, b32 ds:[rdi]
         // 0040320d: vpcmpeqb b32 ymm3, b32 ymm2, b32 ymm1
         // 00403211: vptest b32 ymm3, b32 ymm3
         // 00403216: jnz 0x403223
      [-]c5f87749c700ffffffffc3
         // 00403218: vzeroupper 
         // 0040321b: mov ds:[r8], 0xffffffffffffffff
         // 00403222: retn 
      [-]c5fdd7d30fbcd24829f74801fa498910c5f877c3
         // 00403223: vpmovmskb b4 edx, b32 ymm3
         // 00403227: bsf b4 edx, b4 edx
         // 0040322a: sub rdi, rsi
         // 0040322d: add rdx, rdi
         // 00403230: mov ds:[r8], rdx
         // 00403233: vzeroupper 
         // 00403236: retn 
      [-]488b742408488b5c24108a4424204c8d442428e9c8feffff
         // 00403240: mov rsi, ss:[rsp+0x8]
         // 00403245: mov rbx, ss:[rsp+0x10]
         // 0040324a: mov b1 al, b1 ss:[rsp+0x20]
         // 0040324e: lea r8, ss:[rsp+0x28]
         // 00403253: jmp indexbytebody
      [-]488b742408488b5c24108a4424184c8d442420e9a8feffff
         // 00403260: mov rsi, ss:[rsp+0x8]
         // 00403265: mov rbx, ss:[rsp+0x10]
         // 0040326a: mov b1 al, b1 ss:[rsp+0x18]
         // 0040326e: lea r8, ss:[rsp+0x20]
         // 00403273: jmp indexbytebody
      [-]4883ec2848896c2420488d6c2420488b442430488b5c2438488b4c24400fb67c2448450f57ff4c8b3593106200654d8b364d8b36e827f4ffff4889442450488b6c24204883c428c3
         // 00403280: sub rsp, 0x28
         // 00403284: mov ss:[rsp+0x20], rbp
         // 00403289: lea rbp, ss:[rsp+0x20]
         // 0040328e: mov rax, ss:[rsp+0x30]
         // 00403293: mov rbx, ss:[rsp+0x38]
         // 00403298: mov rcx, ss:[rsp+0x40]
         // 0040329d: movzx b4 edi, b1 ss:[rsp+0x48]
         // 004032a2: xorps b16 xmm15, b16 xmm15
         // 004032a6: mov r14, cs:[0xa24340]
         // 004032ad: mov r14, gs:[r14]
         // 004032b1: mov r14, ds:[r14]
         // 004032b4: call internal_bytealg.countGeneric
         // 004032b9: mov ss:[rsp+0x50], rax
         // 004032be: mov rbp, ss:[rsp+0x20]
         // 004032c3: add rsp, 0x28
         // 004032c7: retn 
      [-]4883ec2048896c2418488d6c2418488b442428488b5c24300fb64c2438450f57ff4c8b3538106200654d8b364d8b36e80cf4ffff4889442440488b6c24184883c420c3
         // 004032e0: sub rsp, 0x20
         // 004032e4: mov ss:[rsp+0x18], rbp
         // 004032e9: lea rbp, ss:[rsp+0x18]
         // 004032ee: mov rax, ss:[rsp+0x28]
         // 004032f3: mov rbx, ss:[rsp+0x30]
         // 004032f8: movzx b4 ecx, b1 ss:[rsp+0x38]
         // 004032fd: xorps b16 xmm15, b16 xmm15
         // 00403301: mov r14, cs:[0xa24340]
         // 00403308: mov r14, gs:[r14]
         // 0040330c: mov r14, ds:[r14]
         // 0040330f: call internal_bytealg.countGenericString
         // 00403314: mov ss:[rsp+0x40], rax
         // 00403319: mov rbp, ss:[rsp+0x18]
         // 0040331e: add rsp, 0x20
         // 00403322: retn 
      [-]493b66107629
         // 004034a0: cmp rsp, ds:[r14+0x10]
         // 004034a4: jbe 0x4034cf
      [-]4883ec2048896c2418488d6c2418488b10488b48084889d06690e85b690000488b6c24184883c420c3
         // 004034a6: sub rsp, 0x20
         // 004034aa: mov ss:[rsp+0x18], rbp
         // 004034af: lea rbp, ss:[rsp+0x18]
         // 004034b4: mov rdx, ds:[rax]
         // 004034b7: mov rcx, ds:[rax+0x8]
         // 004034bb: mov rax, rdx
         // 004034be: xchg b2 ax, b2 ax
         // 004034c0: call runtime.memhashFallback
         // 004034c5: mov rbp, ss:[rsp+0x18]
         // 004034ca: add rsp, 0x20
         // 004034ce: retn 
      [-]488944240848895c2410e822030600488b442408488b5c2410ebb6
         // 004034cf: mov ss:[rsp+0x8], rax
         // 004034d4: mov ss:[rsp+0x10], rbx
         // 004034d9: call runtime.morestack_noctxt
         // 004034de: mov rax, ss:[rsp+0x8]
         // 004034e3: mov rbx, ss:[rsp+0x10]
         // 004034e8: jmp runtime.strhashFallback
      [-]b8????????c3
         // 00403ca0: mov b4 eax, b4 0x1
         // 00403ca5: retn 
      [-]0fb608380b0f94c0c3
         // 00403cc0: movzx b4 ecx, b1 ds:[rax]
         // 00403cc3: cmp b1 ds:[rbx], b1 cl
         // 00403cc5: setz b1 al
         // 00403cc8: retn 
      [-]0fb70866390b0f94c0c3
         // 00403ce0: movzx b4 ecx, b2 ds:[rax]
         // 00403ce3: cmp b2 ds:[rbx], b2 cx
         // 00403ce6: setz b1 al
         // 00403ce9: retn 
      [-]8b08390b0f94c0c3
         // 00403d00: mov b4 ecx, b4 ds:[rax]
         // 00403d02: cmp b4 ds:[rbx], b4 ecx
         // 00403d04: setz b1 al
         // 00403d07: retn 
      [-]488b0848390b0f94c0c3
         // 00403d20: mov rcx, ds:[rax]
         // 00403d23: cmp ds:[rbx], rcx
         // 00403d26: setz b1 al
         // 00403d29: retn 
      [-]493b6610762a
         // 00404be0: cmp rsp, ds:[r14+0x10]
         // 00404be4: jbe 0x404c10
      [-]4883ec1048896c2408488d6c24084d8b66204d85e4751a
         // 00404be6: sub rsp, 0x10
         // 00404bea: mov ss:[rsp+0x8], rbp
         // 00404bef: lea rbp, ss:[rsp+0x8]
         // 00404bf4: mov r12, ds:[r14+0x20]
         // 00404bf8: test r12, r12
         // 00404bfb: jnz 0x404c17
      [-]488b4208e89a000000488b6c24084883c410c3
         // 00404bfd: mov rax, ds:[rdx+0x8]
         // 00404c01: call runtime.unwindm
         // 00404c06: mov rbp, ss:[rsp+0x8]
         // 00404c0b: add rsp, 0x10
         // 00404c0f: retn 
      [-]e84beb0500ebc9
         // 00404c10: call runtime.morestack
         // 00404c15: jmp runtime.cgocallbackg1.func3
      [-]4c8d6c24180f1f40004d392c2475d7
         // 00404c17: lea r13, ss:[rsp+0x18]
         // 00404c1c: nop b4 ds:[rax+0x0]
         // 00404c20: cmp ds:[r12], r13
         // 00404c24: jnz 0x404bfd
      [-]49892424ebd1
         // 00404c26: mov ds:[r12], rsp
         // 00404c2a: jmp 0x404bfd
      [-]4889442408c3
         // 00408440: mov ss:[rsp+0x8], rax
         // 00408445: retn 
      [-]48331d79a8610048ba2f64bd78641d76a04831d34885c90f84a5000000
         // 00409e20: xor rbx, cs:[0xa246a0]
         // 00409e27: mov rdx, 0xa0761d6478bd642f
         // 00409e31: xor rbx, rdx
         // 00409e34: test rcx, rcx
         // 00409e37: jz 0x409ee2
      [-]0f1f004883f904726c
         // 00409e3d: nop b4 ds:[rax]
         // 00409e40: cmp rcx, 0x4
         // 00409e44: jb 0x409eb2
      [-]4883f9087243
         // 00409e48: cmp rcx, 0x8
         // 00409e4c: jb 0x409e91
      [-]4883f910761c
         // 00409e50: cmp rcx, 0x10
         // 00409e54: jbe 0x409e72
      [-]4883f930760e
         // 00409e56: cmp rcx, 0x30
         // 00409e5a: jbe 0x409e6a
      [-]4889ca4889de4889f7e996010000
         // 00409e5c: mov rdx, rcx
         // 00409e5f: mov rsi, rbx
         // 00409e62: mov rdi, rsi
         // 00409e65: jmp 0x40a000
      [-]4889cae9d8000000
         // 00409e6a: mov rdx, rcx
         // 00409e6d: jmp 0x409f4a
      [-]4889c2488d71f84801c6909090488b12488b36eb5f
         // 00409e72: mov rdx, rax
         // 00409e75: lea rsi, ds:[rcx+0xfffffffffffffff8]
         // 00409e79: add rsi, rax
         // 00409e7c: nop 
         // 00409e7d: nop 
         // 00409e7e: nop 
         // 00409e7f: mov rdx, ds:[rdx]
         // 00409e82: mov rsi, ds:[rsi]
         // 00409e85: jmp 0x409ee6
      [-]9090488b304889f2eb55
         // 00409e87: nop 
         // 00409e88: nop 
         // 00409e89: mov rsi, ds:[rax]
         // 00409e8c: mov rdx, rsi
         // 00409e8f: jmp 0x409ee6
      [-]4889c2488d79fc4801c79090908b328b1789d089f289c6eb3c
         // 00409e91: mov rdx, rax
         // 00409e94: lea rdi, ds:[rcx+0xfffffffffffffffc]
         // 00409e98: add rdi, rax
         // 00409e9b: nop 
         // 00409e9c: nop 
         // 00409e9d: nop 
         // 00409e9e: mov b4 esi, b4 ds:[rdx]
         // 00409ea0: mov b4 edx, b4 ds:[rdi]
         // 00409ea2: mov b4 eax, b4 edx
         // 00409ea4: mov b4 edx, b4 esi
         // 00409ea6: mov b4 esi, b4 eax
         // 00409ea8: jmp 0x409ee6
      [-]90908b1089d6eb34
         // 00409eaa: nop 
         // 00409eab: nop 
         // 00409eac: mov b4 edx, b4 ds:[rax]
         // 00409eae: mov b4 esi, b4 edx
         // 00409eb0: jmp 0x409ee6
      [-]4889c6488d79ff4801c70fb6164989c848d1e90fb60c0e48c1e1084809ca0fb60f48c1e1104809ca4c89c131f690eb04
         // 00409eb2: mov rsi, rax
         // 00409eb5: lea rdi, ds:[rcx+0xffffffffffffffff]
         // 00409eb9: add rdi, rax
         // 00409ebc: movzx b4 edx, b1 ds:[rsi]
         // 00409ebf: mov r8, rcx
         // 00409ec2: shr rcx, b1 0x1
         // 00409ec5: movzx b4 ecx, b1 ds:[rsi+rcx]
         // 00409ec9: shl rcx, b1 0x8
         // 00409ecd: or rdx, rcx
         // 00409ed0: movzx b4 ecx, b1 ds:[rdi]
         // 00409ed3: shl rcx, b1 0x10
         // 00409ed7: or rdx, rcx
         // 00409eda: mov rcx, r8
         // 00409edd: xor b4 esi, b4 esi
         // 00409edf: nop 
         // 00409ee0: jmp 0x409ee6
      [-]4889d8c3
         // 00409ee2: mov rax, rbx
         // 00409ee5: retn 
      [-]48bfdb28b4a0d17e03e74831fa4831f34889d848f7e248bb4f127dc4274e8e1d4831cb4831d048f7e34831d0c3
         // 00409ee6: mov rdi, 0xe7037ed1a0b428db
         // 00409ef0: xor rdx, rdi
         // 00409ef3: xor rbx, rsi
         // 00409ef6: mov rax, rbx
         // 00409ef9: mul rdx
         // 00409efc: mov rbx, 0x1d8e4e27c47d124f
         // 00409f06: xor rbx, rcx
         // 00409f09: xor rax, rdx
         // 00409f0c: mul rbx
         // 00409f0f: xor rax, rdx
         // 00409f12: retn 
      [-]488b3048bfdb28b4a0d17e03e74831fe4c8b40084931d84889c34c89c04989d048f7e64883c1f09090904831c2488d43104889d34c89c2
         // 00409f13: mov rsi, ds:[rax]
         // 00409f16: mov rdi, 0xe7037ed1a0b428db
         // 00409f20: xor rsi, rdi
         // 00409f23: mov r8, ds:[rax+0x8]
         // 00409f27: xor r8, rbx
         // 00409f2a: mov rbx, rax
         // 00409f2d: mov rax, r8
         // 00409f30: mov r8, rdx
         // 00409f33: mul rsi
         // 00409f36: add rcx, 0xfffffffffffffff0
         // 00409f3a: nop 
         // 00409f3b: nop 
         // 00409f3c: nop 
         // 00409f3d: xor rdx, rax
         // 00409f40: lea rax, ds:[rbx+0x10]
         // 00409f44: mov rbx, rdx
         // 00409f47: mov rdx, r8
      [-]4883f91077c3
         // 00409f4a: cmp rcx, 0x10
         // 00409f4e: ja 0x409f13
      [-]488d79f04801c74c8d41f84901c09090488b3f498b304889d14889fae975ffffff
         // 00409f50: lea rdi, ds:[rcx+0xfffffffffffffff0]
         // 00409f54: add rdi, rax
         // 00409f57: lea r8, ds:[rcx+0xfffffffffffffff8]
         // 00409f5b: add r8, rax
         // 00409f5e: nop 
         // 00409f5f: nop 
         // 00409f60: mov rdi, ds:[rdi]
         // 00409f63: mov rsi, ds:[r8]
         // 00409f66: mov rcx, rdx
         // 00409f69: mov rdx, rdi
         // 00409f6c: jmp 0x409ee6
      [-]4c8b0049b9db28b4a0d17e03e74d31c84c8b50084931da4889c34c89d04989d249f7e04c8b431049bbe3c6889cf06abc8e4d31d84c8b63184931f44889c64c89e04989d449f7e04c8b432049bdc34c3775cc6599584d31e84c8b7b284931ff4889c74c89f84989d749f7e04883c1d09090904931f490904931ff90904831c2488d43304c89e34c89fe4889d74c89d2
         // 00409f71: mov r8, ds:[rax]
         // 00409f74: mov r9, 0xe7037ed1a0b428db
         // 00409f7e: xor r8, r9
         // 00409f81: mov r10, ds:[rax+0x8]
         // 00409f85: xor r10, rbx
         // 00409f88: mov rbx, rax
         // 00409f8b: mov rax, r10
         // 00409f8e: mov r10, rdx
         // 00409f91: mul r8
         // 00409f94: mov r8, ds:[rbx+0x10]
         // 00409f98: mov r11, 0x8ebc6af09c88c6e3
         // 00409fa2: xor r8, r11
         // 00409fa5: mov r12, ds:[rbx+0x18]
         // 00409fa9: xor r12, rsi
         // 00409fac: mov rsi, rax
         // 00409faf: mov rax, r12
         // 00409fb2: mov r12, rdx
         // 00409fb5: mul r8
         // 00409fb8: mov r8, ds:[rbx+0x20]
         // 00409fbc: mov r13, 0x589965cc75374cc3
         // 00409fc6: xor r8, r13
         // 00409fc9: mov r15, ds:[rbx+0x28]
         // 00409fcd: xor r15, rdi
         // 00409fd0: mov rdi, rax
         // 00409fd3: mov rax, r15
         // 00409fd6: mov r15, rdx
         // 00409fd9: mul r8
         // 00409fdc: add rcx, 0xffffffffffffffd0
         // 00409fe0: nop 
         // 00409fe1: nop 
         // 00409fe2: nop 
         // 00409fe3: xor r12, rsi
         // 00409fe6: nop 
         // 00409fe7: nop 
         // 00409fe8: xor r15, rdi
         // 00409feb: nop 
         // 00409fec: nop 
         // 00409fed: xor rdx, rax
         // 00409ff0: lea rax, ds:[rbx+0x30]
         // 00409ff4: mov rbx, r12
         // 00409ff7: mov rsi, r15
         // 00409ffa: mov rdi, rdx
         // 00409ffd: mov rdx, r10
      [-]4883f9300f8767ffffff
         // 0040a000: cmp rcx, 0x30
         // 0040a004: ja 0x409f71
      [-]4831fe4831f3e935ffffff
         // 0040a00a: xor rsi, rdi
         // 0040a00d: xor rbx, rsi
         // 0040a010: jmp 0x409f4a
      [-]8b0048b9db28b4a0d17e03e74831c14831d848330567a6610048ba2f64bd78641d76a04831c24889c848f7e24831d04889c148b84b127dc4274e8e1d48f7e190904831d0c3
         // 0040a020: mov b4 eax, b4 ds:[rax]
         // 0040a022: mov rcx, 0xe7037ed1a0b428db
         // 0040a02c: xor rcx, rax
         // 0040a02f: xor rax, rbx
         // 0040a032: xor rax, cs:[0xa246a0]
         // 0040a039: mov rdx, 0xa0761d6478bd642f
         // 0040a043: xor rdx, rax
         // 0040a046: mov rax, rcx
         // 0040a049: mul rdx
         // 0040a04c: xor rax, rdx
         // 0040a04f: mov rcx, rax
         // 0040a052: mov rax, 0x1d8e4e27c47d124b
         // 0040a05c: mul rcx
         // 0040a05f: nop 
         // 0040a060: nop 
         // 0040a061: xor rax, rdx
         // 0040a064: retn 
      [-]488b0048b9db28b4a0d17e03e74831c14831d848330506a6610048ba2f64bd78641d76a04831c24889c848f7e24831d04889c148b847127dc4274e8e1d48f7e190904831d0c3
         // 0040a080: mov rax, ds:[rax]
         // 0040a083: mov rcx, 0xe7037ed1a0b428db
         // 0040a08d: xor rcx, rax
         // 0040a090: xor rax, rbx
         // 0040a093: xor rax, cs:[0xa246a0]
         // 0040a09a: mov rdx, 0xa0761d6478bd642f
         // 0040a0a4: xor rdx, rax
         // 0040a0a7: mov rax, rcx
         // 0040a0aa: mul rdx
         // 0040a0ad: xor rax, rdx
         // 0040a0b0: mov rcx, rax
         // 0040a0b3: mov rax, 0x1d8e4e27c47d1247
         // 0040a0bd: mul rcx
         // 0040a0c0: nop 
         // 0040a0c1: nop 
         // 0040a0c2: xor rax, rdx
         // 0040a0c5: retn 
      [-]493b66100f866a010000
         // 00432140: cmp rsp, ds:[r14+0x10]
         // 00432144: jbe 0x4322b4
      [-]4883ec6048896c2458488d6c2458833d61245f0000907510
         // 0043214a: sub rsp, 0x60
         // 0043214e: mov ss:[rsp+0x58], rbp
         // 00432153: lea rbp, ss:[rsp+0x58]
         // 00432158: cmp b4 cs:[0xa245c0], b4 0x0
         // 0043215f: nop 
         // 00432160: jnz 0x432172
      [-]488d157751030048891598b95900eb13
         // 00432162: lea rdx, cs:[runtime.asmstdcall]
         // 00432169: mov cs:[0x9cdb08], rdx
         // 00432170: jmp 0x432185
      [-]488d3d8fb95900488d1560510300e85b390300
         // 00432172: lea rdi, cs:[0x9cdb08]
         // 00432179: lea rdx, cs:[runtime.asmstdcall]
         // 00432180: call runtime.gcWriteBarrierDX
      [-]31c0eb17
         // 00432185: xor b4 eax, b4 eax
         // 00432187: jmp 0x4321a0
      [-]4c8d0510285f0041883400ff058a1f5f004889f80f1f00
         // 00432189: lea r8, cs:[0xa249a0]
         // 00432190: mov b1 ds:[r8+rax], b1 sil
         // 00432194: inc b4 cs:[0xa24124]
         // 0043219a: mov rax, rdi
         // 0043219d: nop b4 ds:[rax]
      [-]4883f8367d4a
         // 004321a0: cmp rax, 0x36
         // 004321a4: jge 0x4321f0
      [-]488d15101f34000fb6340281fe????????7d06
         // 004321a6: lea rdx, cs:[0x7740bd]
         // 004321ad: movzx b4 esi, b1 ds:[rdx+rax]
         // 004321b1: cmp b4 esi, b4 0x80
         // 004321b7: jge 0x4321bf
      [-]488d7801eb26
         // 004321b9: lea rdi, ds:[rax+0x1]
         // 004321bd: jmp 0x4321e5
      [-]4889442420bb????????4889c14889d0e84caf0200488d15e21e340089c64889df488b442420
         // 004321bf: mov ss:[rsp+0x20], rax
         // 004321c4: mov b4 ebx, b4 0x36
         // 004321c9: mov rcx, rax
         // 004321cc: mov rax, rdx
         // 004321cf: call runtime.decoderune
         // 004321d4: lea rdx, cs:[0x7740bd]
         // 004321db: mov b4 esi, b4 eax
         // 004321dd: mov rdi, rbx
         // 004321e0: mov rax, ss:[rsp+0x20]
      [-]4883f864729e
         // 004321e5: cmp rax, 0x64
         // 004321e9: jb 0x432189
      [-]e9b9000000
         // 004321eb: jmp 0x4322a9
      [-]b9????????e8ad3b0300
         // 004322a9: mov b4 ecx, b4 0x64
         // 004322ae: call runtime.panicIndex
      [-]e847150300e982feffff
         // 004322b4: call runtime.morestack_noctxt
         // 004322b9: jmp runtime.osinit
      [-]493b6610767a
         // 004348e0: cmp rsp, ds:[r14+0x10]
         // 004348e4: jbe 0x434960
      [-]4883ec3848896c2430488d6c2430488944244048895c2448b9????????488b442438488d1d73ef3200e88cfeffff440f117c241866c74424280000488b5424404889542418c644242801488b5424484889542420c644242900488d05facc3000488d5c2418e8b064fdff4889c3488d05e6cc3000e8411b000090
         // 004348e6: sub rsp, 0x38
         // 004348ea: mov ss:[rsp+0x30], rbp
         // 004348ef: lea rbp, ss:[rsp+0x30]
         // 004348f4: mov ss:[rsp+0x40], rax
         // 004348f9: mov ss:[rsp+0x48], rbx
         // 004348fe: mov b4 ecx, b4 0x12
         // 00434903: mov rax, ss:[rsp+0x38]
         // 00434908: lea rbx, cs:[0x763882]
         // 0043490f: call runtime.panicCheck1
         // 00434914: movups b16 ss:[rsp+0x18], b16 xmm15
         // 0043491a: mov b2 ss:[rsp+0x28], b2 0x0
         // 00434921: mov rdx, ss:[rsp+0x40]
         // 00434926: mov ss:[rsp+0x18], rdx
         // 0043492b: mov b1 ss:[rsp+0x28], b1 0x1
         // 00434930: mov rdx, ss:[rsp+0x48]
         // 00434935: mov ss:[rsp+0x20], rdx
         // 0043493a: mov b1 ss:[rsp+0x29], b1 0x0
         // 0043493f: lea rax, cs:[RTYPE_runtime_boundsError]
         // 00434946: lea rbx, ss:[rsp+0x18]
         // 0043494b: call runtime.convTnoptr
         // 00434950: mov rbx, rax
         // 00434953: lea rax, cs:[RTYPE_runtime_boundsError]
         // 0043495a: call runtime.gopanic
         // 0043495f: nop 
      [-]488944240848895c2410e891ee0200488b442408488b5c2410e962ffffff
         // 00434960: mov ss:[rsp+0x8], rax
         // 00434965: mov ss:[rsp+0x10], rbx
         // 0043496a: call runtime.morestack_noctxt
         // 0043496f: mov rax, ss:[rsp+0x8]
         // 00434974: mov rbx, ss:[rsp+0x10]
         // 00434979: jmp runtime.goPanicIndex
      [-]493b6610767a
         // 00434980: cmp rsp, ds:[r14+0x10]
         // 00434984: jbe 0x434a00
      [-]4883ec3848896c2430488d6c2430488944244048895c2448b9????????488b442438488d1dd3ee3200e8ecfdffff440f117c241866c74424280000488b5424404889542418c644242800488b5424484889542420c644242900488d055acc3000488d5c2418e81064fdff4889c3488d0546cc3000e8a11a000090
         // 00434986: sub rsp, 0x38
         // 0043498a: mov ss:[rsp+0x30], rbp
         // 0043498f: lea rbp, ss:[rsp+0x30]
         // 00434994: mov ss:[rsp+0x40], rax
         // 00434999: mov ss:[rsp+0x48], rbx
         // 0043499e: mov b4 ecx, b4 0x12
         // 004349a3: mov rax, ss:[rsp+0x38]
         // 004349a8: lea rbx, cs:[0x763882]
         // 004349af: call runtime.panicCheck1
         // 004349b4: movups b16 ss:[rsp+0x18], b16 xmm15
         // 004349ba: mov b2 ss:[rsp+0x28], b2 0x0
         // 004349c1: mov rdx, ss:[rsp+0x40]
         // 004349c6: mov ss:[rsp+0x18], rdx
         // 004349cb: mov b1 ss:[rsp+0x28], b1 0x0
         // 004349d0: mov rdx, ss:[rsp+0x48]
         // 004349d5: mov ss:[rsp+0x20], rdx
         // 004349da: mov b1 ss:[rsp+0x29], b1 0x0
         // 004349df: lea rax, cs:[RTYPE_runtime_boundsError]
         // 004349e6: lea rbx, ss:[rsp+0x18]
         // 004349eb: call runtime.convTnoptr
         // 004349f0: mov rbx, rax
         // 004349f3: lea rax, cs:[RTYPE_runtime_boundsError]
         // 004349fa: call runtime.gopanic
         // 004349ff: nop 
      [-]488944240848895c2410e8f1ed0200488b442408488b5c2410e962ffffff
         // 00434a00: mov ss:[rsp+0x8], rax
         // 00434a05: mov ss:[rsp+0x10], rbx
         // 00434a0a: call runtime.morestack_noctxt
         // 00434a0f: mov rax, ss:[rsp+0x8]
         // 00434a14: mov rbx, ss:[rsp+0x10]
         // 00434a19: jmp runtime.goPanicIndexU
      [-]493b6610767a
         // 00434a20: cmp rsp, ds:[r14+0x10]
         // 00434a24: jbe 0x434aa0
      [-]4883ec3848896c2430488d6c2430488944244048895c2448b9????????488b442438488d1d43343300e84cfdffff440f117c241866c74424280000488b5424404889542418c644242801488b5424484889542420c644242901488d05bacb3000488d5c2418e87063fdff4889c3488d05a6cb3000e8011a000090
         // 00434a26: sub rsp, 0x38
         // 00434a2a: mov ss:[rsp+0x30], rbp
         // 00434a2f: lea rbp, ss:[rsp+0x30]
         // 00434a34: mov ss:[rsp+0x40], rax
         // 00434a39: mov ss:[rsp+0x48], rbx
         // 00434a3e: mov b4 ecx, b4 0x19
         // 00434a43: mov rax, ss:[rsp+0x38]
         // 00434a48: lea rbx, cs:[0x767e92]
         // 00434a4f: call runtime.panicCheck1
         // 00434a54: movups b16 ss:[rsp+0x18], b16 xmm15
         // 00434a5a: mov b2 ss:[rsp+0x28], b2 0x0
         // 00434a61: mov rdx, ss:[rsp+0x40]
         // 00434a66: mov ss:[rsp+0x18], rdx
         // 00434a6b: mov b1 ss:[rsp+0x28], b1 0x1
         // 00434a70: mov rdx, ss:[rsp+0x48]
         // 00434a75: mov ss:[rsp+0x20], rdx
         // 00434a7a: mov b1 ss:[rsp+0x29], b1 0x1
         // 00434a7f: lea rax, cs:[RTYPE_runtime_boundsError]
         // 00434a86: lea rbx, ss:[rsp+0x18]
         // 00434a8b: call runtime.convTnoptr
         // 00434a90: mov rbx, rax
         // 00434a93: lea rax, cs:[RTYPE_runtime_boundsError]
         // 00434a9a: call runtime.gopanic
         // 00434a9f: nop 
      [-]488944240848895c2410e851ed0200488b442408488b5c2410e962ffffff
         // 00434aa0: mov ss:[rsp+0x8], rax
         // 00434aa5: mov ss:[rsp+0x10], rbx
         // 00434aaa: call runtime.morestack_noctxt
         // 00434aaf: mov rax, ss:[rsp+0x8]
         // 00434ab4: mov rbx, ss:[rsp+0x10]
         // 00434ab9: jmp runtime.goPanicSliceAlen
      [-]493b6610767a
         // 00434ac0: cmp rsp, ds:[r14+0x10]
         // 00434ac4: jbe 0x434b40
      [-]4883ec3848896c2430488d6c2430488944244048895c2448b9????????488b4424
         // 00434ac6: sub rsp, 0x38
         // 00434aca: mov ss:[rsp+0x30], rbp
         // 00434acf: lea rbp, ss:[rsp+0x30]
         // 00434ad4: mov ss:[rsp+0x40], rax
         // 00434ad9: mov ss:[rsp+0x48], rbx
         // 00434ade: mov b4 ecx, b4 0x19
         // 00434ae3: mov rax, ss:[rsp+0x38]
         // 00434ae8: lea rbx, cs:[0x767e92]
         // 00434aef: call runtime.panicCheck1
         // 00434af4: movups b16 ss:[rsp+0x18], b16 xmm15
         // 00434afa: mov b2 ss:[rsp+0x28], b2 0x0
         // 00434b01: mov rdx, ss:[rsp+0x40]
         // 00434b06: mov ss:[rsp+0x18], rdx
         // 00434b0b: mov b1 ss:[rsp+0x28], b1 0x0
         // 00434b10: mov rdx, ss:[rsp+0x48]
         // 00434b15: mov ss:[rsp+0x20], rdx
         // 00434b1a: mov b1 ss:[rsp+0x29], b1 0x1
         // 00434b1f: lea rax, cs:[RTYPE_runtime_boundsError]
         // 00434b26: lea rbx, ss:[rsp+0x18]
         // 00434b2b: call runtime.convTnoptr
         // 00434b30: mov rbx, rax
         // 00434b33: lea rax, cs:[RTYPE_runtime_boundsError]
         // 00434b3a: call runtime.gopanic
         // 00434b3f: nop 

  }
  condition:
    all of them
}
