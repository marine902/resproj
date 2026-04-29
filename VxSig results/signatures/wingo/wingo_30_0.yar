rule wingo_30_0 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         f30f6f06f30f6f0ff30f6f5610f30f6f5f10f30f6f6620f30f6f6f20f30f6f7630f30f6f7f30660f74c1660f74d3660f74e5660f74f7660fdbc2660fdbe6660fdbc4660fd7d0
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
      [-]83eb4081fa????????74
         // 00403588: sub rbx, 0x40
         // 0040358c: cmp b4 edx, b4 0xffff
         // 00403592: jz 0x403530
      [-]39d10f94
         // 0040361b: cmp rcx, rdx
         // 0040361e: setz b1 al
      [-]83fb0074
         // 00403622: cmp rbx, 0x0
         // 00403626: jz 0x40365f
      [-]8d0cdd00000000
         // 00403296: lea ecx, ds:[ebx*0x8]
      [-]046c657507
         // 0046f134: jnz 0x46f13d
      [-]04656d75
         // 0046f14b: jnz 0x46f154
      [-]04f30f70c000660f6fc8660fef05
         // 0046bfdb: pshufhw b16 xmm0, b16 xmm0, b1 0x0
         // 0046bfe0: movdqa b16 xmm1, b16 xmm0
         // 0046bfe4: pxor b16 xmm0, b16 ds:[0xf24de0]
      [-]660f38dcc0
         // 0046bfec: aesenc b16 xmm0, b16 xmm0
      [-]660f6fd1660f6fd9660f
         // 0046c14b: movdqa b16 xmm2, b16 xmm1
         // 0046c14f: movdqa b16 xmm3, b16 xmm1
         // 0046c153: pxor b16 xmm1, b16 ds:[0xf24df0]
      [-]00660fef
         // 0046c163: pxor b16 xmm3, b16 ds:[0xf24e10]
      [-]660f38dc
         // 0046c170: aesenc b16 xmm2, b16 xmm2
      [-]660f38dc
         // 0046c175: aesenc b16 xmm3, b16 xmm3
      [-]f30f6f00f30f6f4810f30f6f5020f30f6f583066
         // 0046efaa: movdqu b16 xmm0, b16 ds:[eax]
         // 0046efae: movdqu b16 xmm1, b16 ds:[eax+0x10]
         // 0046efb3: movdqu b16 xmm2, b16 ds:[eax+0x20]
         // 0046efb8: movdqu b16 xmm3, b16 ds:[eax+0x30]
         // 0046efbd: aesenc b16 xmm4, b16 xmm0
      [-]0f38dce466
         // 0046efd6: aesenc b16 xmm5, b16 xmm5
      [-]0f38dced66
         // 0046efdb: aesenc b16 xmm6, b16 xmm6
      [-]0f38dcf666
         // 0046efe0: aesenc b16 xmm7, b16 xmm7
      [-]0f38dcff
      [-]0f38dce466
         // 0046c204: aesenc b16 xmm5, b16 xmm5
      [-]0f38dced66
         // 0046c209: aesenc b16 xmm6, b16 xmm6
      [-]0f38dcf666
         // 0046c20e: aesenc b16 xmm7, b16 xmm7
      [-]0f38dcff66
         // 0046c213: aesenc b16 xmm4, b16 xmm4
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
      [-]89e7f3a4
         // 0046363d: mov rdi, rsp
         // 00463640: rep movsbb 
      [-]89e7f3a4
         // 00474ccb: mov rdi, rsp
         // 00474cce: rep movsbb 
      [-]89e7f3a4
         // 0046383d: mov rdi, rsp
         // 00463840: rep movsbb 
      [-]89e7f3a4
         // 140075f2b: mov rdi, rsp
         // 140075f2e: rep movsbb 
      [-]89e7f3a4
         // 00474f6b: mov rdi, rsp
         // 00474f6e: rep movsbb 
      [-]89e7f3a4
         // 00463b3d: mov rdi, rsp
         // 00463b40: rep movsbb 
      [-]89e7f3a4
         // 00463c3d: mov rdi, rsp
         // 00463c40: rep movsbb 
      [-]89e7f3a4
         // 00463d3d: mov rdi, rsp
         // 00463d40: rep movsbb 
      [-]89e7f3a4
         // 004752eb: mov rdi, rsp
         // 004752ee: rep movsbb 
      [-]89e7f3a4
         // 004753cb: mov rdi, rsp
         // 004753ce: rep movsbb 
      [-]89e7f3a4
         // 004754ab: mov rdi, rsp
         // 004754ae: rep movsbb 
      [-]89e7f3a4
         // 0046413d: mov rdi, rsp
         // 00464140: rep movsbb 
      [-]89e7f3a4
         // 0046423d: mov rdi, rsp
         // 00464240: rep movsbb 
      [-]89e7f3a4
         // 0047574b: mov rdi, rsp
         // 0047574e: rep movsbb 
      [-]89e7f3a4
         // 0046443d: mov rdi, rsp
         // 00464440: rep movsbb 
      [-]89e7f3a4
         // 0046453d: mov rdi, rsp
         // 00464540: rep movsbb 
      [-]89e7f3a4
         // 0046463d: mov rdi, rsp
         // 00464640: rep movsbb 
      [-]89e7f3a4
         // 0046473d: mov rdi, rsp
         // 00464740: rep movsbb 
      [-]894c2408
         // 140076df9: mov ss:[rsp+0x8], rcx
      [-]85db0f84
         // 0045ba66: test rbx, rbx
         // 0045ba69: jz 0x45bc27
      [-]83fb400f86
         // 0045baa7: cmp rbx, 0x40
         // 0045baab: jbe 0x45bc52
      [-]80000000f3
         // 00476b46: movdqu b16 ds:[rdi+0x90], b16 xmm15
      [-]90000000f3
         // 00476b4f: movdqu b16 ds:[rdi+0xa0], b16 xmm15
      [-]a0000000f3
         // 00476b58: movdqu b16 ds:[rdi+0xb0], b16 xmm15
      [-]b0000000f3
         // 00476b61: movdqu b16 ds:[rdi+0xc0], b16 xmm15
      [-]c0000000f3
         // 00476b6a: movdqu b16 ds:[rdi+0xd0], b16 xmm15
      [-]d0000000f3
         // 00476b73: movdqu b16 ds:[rdi+0xe0], b16 xmm15
      [-]e0000000f3
         // 00476b7c: movdqu b16 ds:[rdi+0xf0], b16 xmm15
      [-]f0000000
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
         // 1400785b1: movups b16 ss:[rsp+0x70], b16 xmm0
      [-]0f11bc24
         // 1400785e6: movups b16 ss:[rsp+0xe0], b16 xmm7
      [-]ff84c074
         // 0047af25: test b1 al, b1 al
         // 0047af27: jz 0x47af47
      [-]ff84c074
         // 004c229b: test b1 al, b1 al
         // 004c229d: jz 0x4c22e7
      [-]ff84c074
         // 004da576: test b1 al, b1 al
         // 004da578: jz 0x4da5ab

  }
  condition:
    all of them
}
