rule wingo_10_2 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         0000eb02
         // 00402945: jmp 0x402949
      [-]83f9067d
         // 00402218: cmp rcx, 0x6
         // 0040221c: jge 0x402299
      [-]f30f6f06f30f6f0f660f74c8660fd7
         // 00402ddb: movdqu b16 xmm0, b16 ds:[rsi]
         // 00402ddf: movdqu b16 xmm1, b16 ds:[rdi]
         // 00402de3: pcmpeqb b16 xmm1, b16 xmm0
         // 00402de7: pmovmskb b4 eax, b16 xmm1
      [-]00000000
      [-]f30f6f06f30f6f0ff30f6f5610f30f6f5f10f30f6f6620f30f6f6f20f30f6f7630f30f6f7f30660f74c1660f74d3660f74e5660f74f7660fdbc2660fdbe6660fdbc4660fd7d0
         // 0040301a: movdqu b16 xmm0, b16 ds:[rsi]
         // 0040301e: movdqu b16 xmm1, b16 ds:[rdi]
         // 00403022: movdqu b16 xmm2, b16 ds:[rsi+0x10]
         // 00403027: movdqu b16 xmm3, b16 ds:[rdi+0x10]
         // 0040302c: movdqu b16 xmm4, b16 ds:[rsi+0x20]
         // 00403031: movdqu b16 xmm5, b16 ds:[rdi+0x20]
         // 00403036: movdqu b16 xmm6, b16 ds:[rsi+0x30]
         // 0040303b: movdqu b16 xmm7, b16 ds:[rdi+0x30]
         // 00403040: pcmpeqb b16 xmm0, b16 xmm1
         // 00403044: pcmpeqb b16 xmm2, b16 xmm3
         // 00403048: pcmpeqb b16 xmm4, b16 xmm5
         // 0040304c: pcmpeqb b16 xmm6, b16 xmm7
         // 00403050: pand b16 xmm0, b16 xmm2
         // 00403054: pand b16 xmm4, b16 xmm6
         // 00403058: pand b16 xmm0, b16 xmm4
         // 0040305c: pmovmskb b4 edx, b16 xmm0
      [-]83eb4081fa????????74
         // 00403068: sub rbx, 0x40
         // 0040306c: cmp b4 edx, b4 0xffff
         // 00403072: jz 0x403010
      [-]39d10f94
         // 004030fb: cmp rcx, rdx
         // 004030fe: setz b1 al
      [-]83fb0074
         // 00403102: cmp rbx, 0x0
         // 00403106: jz 0x40313f
      [-]8d0cdd00000000
         // 00403108: lea rcx, ds:[rbx*0x8]
      [-]fcff0fb605
         // 140040b25: movzx b4 eax, b1 cs:[0x14080154e]
      [-]31c0c60000c3
         // 00450280: xor b4 eax, b4 eax
         // 00450282: mov b1 ds:[rax], b1 0x0
         // 00450285: retn 
      [-]ff84c075
         // 00473455: test b1 al, b1 al
         // 00473457: jnz 0x47347d
      [-]046c657507
         // 004688f4: jnz 0x4688fd
      [-]04656d75
         // 0046890b: jnz 0x468914
      [-]faff8b4424
         // 00468bac: mov b4 eax, b4 ss:[rsp+0x1c]
      [-]04f30f70c000660f6fc8660fef05
         // 004784eb: pshufhw b16 xmm0, b16 xmm0, b1 0x0
         // 004784f0: movdqa b16 xmm1, b16 xmm0
         // 004784f4: pxor b16 xmm0, b16 ds:[runtime.aeskeysched]
      [-]660f38dcc0
         // 004784fc: aesenc b16 xmm0, b16 xmm0
      [-]660f6fd1660f6fd9660f
         // 140074fac: movdqa b16 xmm2, b16 xmm1
         // 140074fb0: movdqa b16 xmm3, b16 xmm1
         // 140074fc0: movdqa b16 xmm7, b16 xmm1
      [-]00660fef
         // 140074ff4: pxor b16 xmm7, b16 cs:[0x1408013d0]
      [-]660f38dc
         // 140075001: aesenc b16 xmm2, b16 xmm2
      [-]660f38dc
         // 140075006: aesenc b16 xmm3, b16 xmm3
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
         // 00473324: aesenc b16 xmm13, b16 xmm13
      [-]0f38dced66
         // 0047332a: aesenc b16 xmm14, b16 xmm14
      [-]0f38dcf666
         // 00473330: aesenc b16 xmm15, b16 xmm15
      [-]0f38dcff66
         // 00473336: aesenc b16 xmm8, b16 xmm8
      [-]cccccccccccc
         // 0046cab9: int b1 0x3
         // 0046caba: int b1 0x3
         // 0046cabb: int b1 0x3
         // 0046cabc: int b1 0x3
         // 0046cabd: int b1 0x3
         // 0046cabe: int b1 0x3
      [-]ba????????e9
         // 0046cb40: mov b4 edx, b4 0x0
         // 0046cb45: jmp runtime.morestack
      [-]89e7f3a4
         // 004741ee: mov rdi, rsp
         // 004741f1: rep movsbb 
      [-]89e7f3a4
         // 0047428e: mov rdi, rsp
         // 00474291: rep movsbb 
      [-]89e7f3a4
         // 0047432e: mov rdi, rsp
         // 00474331: rep movsbb 
      [-]89e7f3a4
         // 004743dd: mov rdi, rsp
         // 004743e0: rep movsbb 
      [-]89e7f3a4
         // 004744c3: mov rdi, rsp
         // 004744c6: rep movsbb 
      [-]89e7f3a4
         // 004745a3: mov rdi, rsp
         // 004745a6: rep movsbb 
      [-]89e7f3a4
         // 00474683: mov rdi, rsp
         // 00474686: rep movsbb 
      [-]89e7f3a4
         // 00474763: mov rdi, rsp
         // 00474766: rep movsbb 
      [-]89e7f3a4
         // 0047484b: mov rdi, rsp
         // 0047484e: rep movsbb 
      [-]89e7f3a4
         // 0047492b: mov rdi, rsp
         // 0047492e: rep movsbb 
      [-]89e7f3a4
         // 00474a0b: mov rdi, rsp
         // 00474a0e: rep movsbb 
      [-]89e7f3a4
         // 00474aeb: mov rdi, rsp
         // 00474aee: rep movsbb 
      [-]89e7f3a4
         // 00474bcb: mov rdi, rsp
         // 00474bce: rep movsbb 
      [-]89e7f3a4
         // 00474cab: mov rdi, rsp
         // 00474cae: rep movsbb 
      [-]89e7f3a4
         // 00474d8b: mov rdi, rsp
         // 00474d8e: rep movsbb 
      [-]89e7f3a4
         // 00474e6b: mov rdi, rsp
         // 00474e6e: rep movsbb 
      [-]89e7f3a4
         // 00474f4b: mov rdi, rsp
         // 00474f4e: rep movsbb 
      [-]89e7f3a4
         // 0047502b: mov rdi, rsp
         // 0047502e: rep movsbb 
      [-]89e7f3a4
         // 0047510b: mov rdi, rsp
         // 0047510e: rep movsbb 
      [-]89e7f3a4
         // 004751eb: mov rdi, rsp
         // 004751ee: rep movsbb 
      [-]89e7f3a4
         // 004752cb: mov rdi, rsp
         // 004752ce: rep movsbb 
      [-]89e7f3a4
         // 004753ab: mov rdi, rsp
         // 004753ae: rep movsbb 
      [-]89e7f3a4
         // 0047548b: mov rdi, rsp
         // 0047548e: rep movsbb 
      [-]89e7f3a4
         // 0047556b: mov rdi, rsp
         // 0047556e: rep movsbb 
      [-]89e7f3a4
         // 0047564b: mov rdi, rsp
         // 0047564e: rep movsbb 
      [-]89e7f3a4
         // 0047572b: mov rdi, rsp
         // 0047572e: rep movsbb 
      [-]89e7f3a4
         // 0047580b: mov rdi, rsp
         // 0047580e: rep movsbb 
      [-]894c2408
         // 00475a99: mov ss:[rsp+0x8], rcx
      [-]3b207705
         // 0046e8b9: cmp rsp, ds:[rax]
         // 0046e8bc: ja 0x46e8c3
      [-]0faef00faee80f31eb
         // 0046e8f9: mfence 
         // 0046e8fc: lfence 
         // 0046e8ff: rdtsc 
         // 0046e901: jmp 0x46e8ec
      [-]b8????????c3
         // 0046ea00: mov b4 eax, b4 0x0
         // 0046ea05: retn 
      [-]85db0f84
         // 0046f4a6: test rbx, rbx
         // 0046f4a9: jz 0x46f6a6
      [-]83fb400f86
         // 0046f4e7: cmp rbx, 0x40
         // 0046f4eb: jbe 0x46f6d1
      [-]80000000f3
         // 0046f566: movdqu b16 ds:[rdi+0x90], b16 xmm15
      [-]90000000f3
         // 0046f56f: movdqu b16 ds:[rdi+0xa0], b16 xmm15
      [-]a0000000f3
         // 0046f578: movdqu b16 ds:[rdi+0xb0], b16 xmm15
      [-]b0000000f3
         // 0046f581: movdqu b16 ds:[rdi+0xc0], b16 xmm15
      [-]c0000000f3
         // 0046f58a: movdqu b16 ds:[rdi+0xd0], b16 xmm15
      [-]d0000000f3
         // 0046f593: movdqu b16 ds:[rdi+0xe0], b16 xmm15
      [-]e0000000f3
         // 0046f59c: movdqu b16 ds:[rdi+0xf0], b16 xmm15
      [-]f0000000
      [-]85db0f84
         // 00464189: test rbx, rbx
         // 0046418c: jz 0x464289
      [-]83fb020f86
         // 00464192: cmp rbx, 0x2
         // 00464196: jbe 0x46427c
      [-]83fb200f86
         // 004641c6: cmp rbx, 0x20
         // 004641ca: jbe 0x4642c1
      [-]83fb400f86
         // 004641d0: cmp rbx, 0x40
         // 004641d4: jbe 0x4642d6
      [-]89f009f8a9
         // 0046f852: mov b4 eax, b4 esi
         // 0046f854: or b4 eax, b4 edi
         // 0046f856: test b4 eax, b4 0x7
      [-]89d9f3a4c3
         // 0046f85d: mov rcx, rbx
         // 0046f860: rep movsbb 
         // 0046f862: retn 
      [-]8a068a4c1eff8807884c1fffc3
         // 0046f8c0: mov b1 al, b1 ds:[rsi]
         // 0046f8c2: mov b1 cl, b1 ds:[rsi+rbx+0xffffffffffffffff]
         // 0046f8c6: mov b1 ds:[rdi], b1 al
         // 0046f8c8: mov b1 ds:[rdi+rbx+0xffffffffffffffff], b1 cl
         // 0046f8cc: retn 
      [-]668b068a4e02668907884f02c3
         // 0046f8d3: mov b2 ax, b2 ds:[rsi]
         // 0046f8d6: mov b1 cl, b1 ds:[rsi+0x2]
         // 0046f8d9: mov b2 ds:[rdi], b2 ax
         // 0046f8dc: mov b1 ds:[rdi+0x2], b1 cl
         // 0046f8df: retn 
      [-]f30f6f06f30f6f4c1ef0f30f7f07f30f7f4c1ff0c3
         // 0046f905: movdqu b16 xmm0, b16 ds:[rsi]
         // 0046f909: movdqu b16 xmm1, b16 ds:[rsi+rbx+0xfffffffffffffff0]
         // 0046f90f: movdqu b16 ds:[rdi], b16 xmm0
         // 0046f913: movdqu b16 ds:[rdi+rbx+0xfffffffffffffff0], b16 xmm1
         // 0046f919: retn 
      [-]f30f6f06f30f6f4e10f30f6f541ee0f30f6f5c1ef0f30f7f07f30f7f4f10f30f7f541fe0f30f7f5c1ff0c3
         // 0046f91a: movdqu b16 xmm0, b16 ds:[rsi]
         // 0046f91e: movdqu b16 xmm1, b16 ds:[rsi+0x10]
         // 0046f923: movdqu b16 xmm2, b16 ds:[rsi+rbx+0xffffffffffffffe0]
         // 0046f929: movdqu b16 xmm3, b16 ds:[rsi+rbx+0xfffffffffffffff0]
         // 0046f92f: movdqu b16 ds:[rdi], b16 xmm0
         // 0046f933: movdqu b16 ds:[rdi+0x10], b16 xmm1
         // 0046f938: movdqu b16 ds:[rdi+rbx+0xffffffffffffffe0], b16 xmm2
         // 0046f93e: movdqu b16 ds:[rdi+rbx+0xfffffffffffffff0], b16 xmm3
         // 0046f944: retn 
      [-]f30f6f06f30f6f4e10f30f6f5620f30f6f5e30f30f6f641ec0f30f6f6c1ed0f30f6f741ee0f30f6f7c1ef0f30f7f07f30f7f4f10f30f7f5720f30f7f5f30f30f7f641fc0f30f7f6c1fd0f30f7f741fe0f30f7f7c1ff0c3
         // 0046f945: movdqu b16 xmm0, b16 ds:[rsi]
         // 0046f949: movdqu b16 xmm1, b16 ds:[rsi+0x10]
         // 0046f94e: movdqu b16 xmm2, b16 ds:[rsi+0x20]
         // 0046f953: movdqu b16 xmm3, b16 ds:[rsi+0x30]
         // 0046f958: movdqu b16 xmm4, b16 ds:[rsi+rbx+0xffffffffffffffc0]
         // 0046f95e: movdqu b16 xmm5, b16 ds:[rsi+rbx+0xffffffffffffffd0]
         // 0046f964: movdqu b16 xmm6, b16 ds:[rsi+rbx+0xffffffffffffffe0]
         // 0046f96a: movdqu b16 xmm7, b16 ds:[rsi+rbx+0xfffffffffffffff0]
         // 0046f970: movdqu b16 ds:[rdi], b16 xmm0
         // 0046f974: movdqu b16 ds:[rdi+0x10], b16 xmm1
         // 0046f979: movdqu b16 ds:[rdi+0x20], b16 xmm2
         // 0046f97e: movdqu b16 ds:[rdi+0x30], b16 xmm3
         // 0046f983: movdqu b16 ds:[rdi+rbx+0xffffffffffffffc0], b16 xmm4
         // 0046f989: movdqu b16 ds:[rdi+rbx+0xffffffffffffffd0], b16 xmm5
         // 0046f98f: movdqu b16 ds:[rdi+rbx+0xffffffffffffffe0], b16 xmm6
         // 0046f995: movdqu b16 ds:[rdi+rbx+0xfffffffffffffff0], b16 xmm7
         // 0046f99b: retn 
      [-]0f114424
         // 00477211: movups b16 ss:[rsp+0x70], b16 xmm0
      [-]0f11bc24
         // 00477246: movups b16 ss:[rsp+0xe0], b16 xmm7
      [-]83f94072
         // 1400793c5: cmp rcx, 0x40
         // 1400793c9: jb 0x1400793d4
      [-]ff84c074
         // 14007c9f1: test b1 al, b1 al
         // 14007c9f3: jz 0x14007ca32
      [-]ff84c074
         // 004738b0: test b1 al, b1 al
         // 004738b2: jz 0x4738d2
      [-]0f94c0c3
         // 00466339: setz b1 al
         // 0046633c: retn 
      [-]660f2ec175
         // 00474168: ucomisd b16 xmm0, b16 xmm1
         // 0047416c: jnz 0x4741e1
      [-]08f20f10
         // 0047b555: movsd b16 xmm1, ds:[rbx+0x8]
      [-]08660f2ec8
         // 0047b55a: ucomisd b16 xmm1, b16 xmm0
      [-]10f20f10
         // 00474189: movsd b16 xmm1, ds:[rbx+0x10]
      [-]10660f2ec875
         // 0047418e: ucomisd b16 xmm1, b16 xmm0
         // 00474192: jnz 0x4741e1
      [-]18f20f10
         // 0047419b: movsd b16 xmm1, ds:[rbx+0x18]
      [-]18660f2ec175
         // 004741a0: ucomisd b16 xmm0, b16 xmm1
         // 004741a4: jnz 0x4741e1
      [-]20f20f10
         // 004741ad: movsd b16 xmm1, ds:[rbx+0x20]
      [-]20660f2ec175
         // 004741b2: ucomisd b16 xmm0, b16 xmm1
         // 004741b6: jnz 0x4741e1
      [-]28f20f10
         // 004741bf: movsd b16 xmm1, ds:[rbx+0x28]
      [-]28660f2ec175
         // 004741c4: ucomisd b16 xmm0, b16 xmm1
         // 004741c8: jnz 0x4741e1
      [-]310f94c0
         // 0047b5bc: setz b1 al
      [-]ff84c074
         // 004768e0: test b1 al, b1 al
         // 004768e2: jz 0x476936
      [-]ff84c074
         // 140098f26: test b1 al, b1 al
         // 140098f28: jz 0x140098f47
      [-]488b5424
         // 140098f33: mov rdx, ss:[rsp+0x28]
      [-]0a0f94c0c3
         // 0049b401: setz b1 al
         // 0049b404: retn 
      [-]ff84c074
         // 1400adcbb: test b1 al, b1 al
         // 1400adcbd: jz 0x1400adcdc
      [-]488b5424
         // 0049b468: mov rdx, ss:[rsp+0x28]
      [-]ff84c074
         // 1400d843b: test b1 al, b1 al
         // 1400d843d: jz 0x1400d8487
      [-]ff84c074
         // 1400d845a: test b1 al, b1 al
         // 1400d845c: jz 0x1400d8487
      [-]ff84c074
         // 1400e9e8d: test b1 al, b1 al
         // 1400e9e8f: jz 0x1400e9ece
      [-]ff84c074
         // 004a908d: test b1 al, b1 al
         // 004a908f: jz 0x4a90ae
      [-]85c00f84
         // 004da036: test rax, rax
         // 004da039: jz 0x4da4da
      [-]ff84c074
         // 1400f50cd: test b1 al, b1 al
         // 1400f50cf: jz 0x1400f50f9

  }
  condition:
    all of them
}
