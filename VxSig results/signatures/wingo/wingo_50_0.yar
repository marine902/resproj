rule wingo_50_0 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         8b0881c1
         // 00469bfd: mov ecx, ds:[eax]
         // 00469bff: add ecx, 0xba0
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

  }
  condition:
    all of them
}
