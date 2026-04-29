rule wingo_20_1 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         0000eb02
         // 00402be5: jmp 0x402be9
      [-]f30f6f06f30f6f0f660f74c8660fd7
         // 0040305b: movdqu b16 xmm0, b16 ds:[rsi]
         // 0040305f: movdqu b16 xmm1, b16 ds:[rdi]
         // 00403063: pcmpeqb b16 xmm1, b16 xmm0
         // 00403067: pmovmskb b4 eax, b16 xmm1
      [-]00000000
      [-]f30f6f06f30f6f0ff30f6f5610f30f6f5f10f30f6f6620f30f6f6f20f30f6f7630f30f6f7f30660f74c1660f74d3660f74e5660f74f7660fdbc2660fdbe6660fdbc4660fd7d0
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
      [-]83eb4081fa????????74
         // 00403528: sub rbx, 0x40
         // 0040352c: cmp b4 edx, b4 0xffff
         // 00403532: jz 0x4034d0
      [-]39d10f94
         // 004035bb: cmp rcx, rdx
         // 004035be: setz b1 al
      [-]83fb0074
         // 004035c2: cmp rbx, 0x0
         // 004035c6: jz 0x4035ff
      [-]8d0cdd00000000
         // 00402a36: lea ecx, ds:[ebx*0x8]
      [-]31c0c60000c3
         // 004523a0: xor b4 eax, b4 eax
         // 004523a2: mov b1 ds:[rax], b1 0x0
         // 004523a5: retn 
      [-]ff84c075
         // 0045ed27: test b1 al, b1 al
         // 0045ed29: jnz 0x45ed4f
      [-]046c657507
         // 004672d4: jnz 0x4672dd
      [-]04656d75
         // 004672eb: jnz 0x4672f4
      [-]04f30f70c000660f6fc8660fef05
         // 00472e6a: pshufhw b16 xmm0, b16 xmm0, b1 0x0
         // 00472e6f: movdqa b16 xmm1, b16 xmm0
         // 00472e73: pxor b16 xmm0, b16 cs:[runtime.aeskeysched]
      [-]660f38dcc0
         // 00472e7b: aesenc b16 xmm0, b16 xmm0
      [-]660f6fd1660f6fd9660f
         // 0046beac: movdqa b16 xmm2, b16 xmm1
         // 0046beb0: movdqa b16 xmm3, b16 xmm1
         // 0046bee4: pxor b16 xmm5, b16 cs:[0x5eee50]
      [-]00660fef
         // 0046bef4: pxor b16 xmm7, b16 cs:[0x5eee70]
      [-]660f38dc
         // 0046bf01: aesenc b16 xmm2, b16 xmm2
      [-]660f38dc
         // 0046bf06: aesenc b16 xmm3, b16 xmm3
      [-]f30f6f00f30f6f4810f30f6f5020f30f6f583066
         // 004786ba: movdqu b16 xmm0, b16 ds:[eax]
         // 004786be: movdqu b16 xmm1, b16 ds:[eax+0x10]
         // 004786c3: movdqu b16 xmm2, b16 ds:[eax+0x20]
         // 004786c8: movdqu b16 xmm3, b16 ds:[eax+0x30]
         // 004786cd: aesenc b16 xmm4, b16 xmm0
      [-]0f38dce466
         // 004786e6: aesenc b16 xmm5, b16 xmm5
      [-]0f38dced66
         // 004786eb: aesenc b16 xmm6, b16 xmm6
      [-]0f38dcf666
         // 004786f0: aesenc b16 xmm7, b16 xmm7
      [-]0f38dcff
      [-]0f38dce466
         // 0046960e: aesenc b16 xmm12, b16 xmm12
         // 00469614: aesenc b16 xmm13, b16 xmm13
      [-]0f38dced66
         // 0046961a: aesenc b16 xmm14, b16 xmm14
      [-]0f38dcf666
         // 00469620: aesenc b16 xmm15, b16 xmm15
      [-]0f38dcff66
         // 00469626: aesenc b16 xmm8, b16 xmm8
      [-]cccccccccccc
         // 0046a059: int b1 0x3
         // 0046a05a: int b1 0x3
         // 0046a05b: int b1 0x3
         // 0046a05c: int b1 0x3
         // 0046a05d: int b1 0x3
         // 0046a05e: int b1 0x3
      [-]ba????????e9
         // 00461180: mov b4 edx, b4 0x0
         // 00461185: jmp runtime.morestack
      [-]89e7f3a4
         // 0046c28b: mov rdi, rsp
         // 0046c28e: rep movsbb 
      [-]89e7f3a4
         // 0046c36b: mov rdi, rsp
         // 0046c36e: rep movsbb 
      [-]89e7f3a4
         // 0046c44b: mov rdi, rsp
         // 0046c44e: rep movsbb 
      [-]89e7f3a4
         // 1400764ab: mov rdi, rsp
         // 1400764ae: rep movsbb 
      [-]89e7f3a4
         // 0046c60b: mov rdi, rsp
         // 0046c60e: rep movsbb 
      [-]89e7f3a4
         // 0046c6eb: mov rdi, rsp
         // 0046c6ee: rep movsbb 
      [-]89e7f3a4
         // 0046c7cb: mov rdi, rsp
         // 0046c7ce: rep movsbb 
      [-]89e7f3a4
         // 0046c8ab: mov rdi, rsp
         // 0046c8ae: rep movsbb 
      [-]89e7f3a4
         // 0046c98b: mov rdi, rsp
         // 0046c98e: rep movsbb 
      [-]89e7f3a4
         // 0046ca6b: mov rdi, rsp
         // 0046ca6e: rep movsbb 
      [-]89e7f3a4
         // 0046cb4b: mov rdi, rsp
         // 0046cb4e: rep movsbb 
      [-]89e7f3a4
         // 0046cc2b: mov rdi, rsp
         // 0046cc2e: rep movsbb 
      [-]89e7f3a4
         // 0046cd0b: mov rdi, rsp
         // 0046cd0e: rep movsbb 
      [-]89e7f3a4
         // 0046cdeb: mov rdi, rsp
         // 0046cdee: rep movsbb 
      [-]89e7f3a4
         // 0046cecb: mov rdi, rsp
         // 0046cece: rep movsbb 
      [-]89e7f3a4
         // 0046cfab: mov rdi, rsp
         // 0046cfae: rep movsbb 
      [-]89e7f3a4
         // 0046d08b: mov rdi, rsp
         // 0046d08e: rep movsbb 
      [-]89e7f3a4
         // 0046d16b: mov rdi, rsp
         // 0046d16e: rep movsbb 
      [-]894c2408
         // 00462bc1: mov ss:[esp+0x8], ecx
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
      [-]80000000f3
         // 0046cb46: movdqu b16 ds:[rdi+0x90], b16 xmm15
      [-]90000000f3
         // 0046cb4f: movdqu b16 ds:[rdi+0xa0], b16 xmm15
      [-]a0000000f3
         // 0046cb58: movdqu b16 ds:[rdi+0xb0], b16 xmm15
      [-]b0000000f3
         // 0046cb61: movdqu b16 ds:[rdi+0xc0], b16 xmm15
      [-]c0000000f3
         // 0046cb6a: movdqu b16 ds:[rdi+0xd0], b16 xmm15
      [-]d0000000f3
         // 0046cb73: movdqu b16 ds:[rdi+0xe0], b16 xmm15
      [-]e0000000f3
         // 0046cb7c: movdqu b16 ds:[rdi+0xf0], b16 xmm15
      [-]f0000000
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
      [-]0f94c0c3
         // 004645c1: setz b1 al
         // 004645c8: retn 
      [-]660f2ec175
         // 00471928: ucomisd b16 xmm0, b16 xmm1
         // 0047192c: jnz 0x4719a1
      [-]08f20f10
         // 00472d35: movsd b16 xmm1, ds:[rbx+0x8]
      [-]08660f2ec8
         // 00472d3a: ucomisd b16 xmm1, b16 xmm0
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
      [-]ff84c074
         // 00486a1c: test b1 al, b1 al
         // 00486a1e: jz 0x486a3f
      [-]ff84c074
         // 0048a9b2: test b1 al, b1 al
         // 0048a9b4: jz 0x48aa13

  }
  condition:
    all of them
}
