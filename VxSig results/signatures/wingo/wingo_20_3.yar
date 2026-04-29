rule wingo_20_3 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         31c0c60000c3
         // 00453be0: xor eax, eax
         // 00453be2: mov b1 ds:[eax], b1 0x0
         // 00453be5: retn 
      [-]8b0881c1
         // 004746a6: mov ecx, ds:[eax]
         // 004746a8: add ecx, 0x13a0
      [-]8b1339d074
         // 004573a9: mov edx, ds:[ebx]
         // 004573ab: cmp eax, edx
         // 004573ad: jz 0x4573f5
      [-]89fa8b3fffe7
         // 0046b9bf: mov rdx, rdi
         // 0046b9c2: mov rdi, ds:[rdi]
         // 0046b9c6: jmp rdi
      [-]cccccccccccc
         // 0046a8b9: int b1 0x3
         // 0046a8ba: int b1 0x3
         // 0046a8bb: int b1 0x3
         // 0046a8bc: int b1 0x3
         // 0046a8bd: int b1 0x3
         // 0046a8be: int b1 0x3
      [-]ba????????e9
         // 00462900: mov b4 edx, b4 0x0
         // 00462905: jmp runtime.morestack
      [-]85db0f84
         // 00459086: test rbx, rbx
         // 00459089: jz 0x459247
      [-]83fb400f86
         // 004590c7: cmp rbx, 0x40
         // 004590cb: jbe 0x459272
      [-]10f30f7f
         // 0046e273: movdqu b16 ds:[edi+0x20], b16 xmm0
      [-]20f30f7f
         // 0046e278: movdqu b16 ds:[edi+0x30], b16 xmm0
      [-]30f30f7f
         // 0046e27d: movdqu b16 ds:[edi+0x40], b16 xmm0
      [-]40f30f7f
         // 0046e282: movdqu b16 ds:[edi+0x50], b16 xmm0
      [-]50f30f7f
         // 0046e287: movdqu b16 ds:[edi+0x60], b16 xmm0
      [-]60f30f7f
         // 0046e28c: movdqu b16 ds:[edi+0x70], b16 xmm0
      [-]70f30f7f
         // 0046e291: movdqu b16 ds:[edi+0x80], b16 xmm0
      [-]80000000f30f7f
         // 0046e299: movdqu b16 ds:[edi+0x90], b16 xmm0
      [-]90000000f30f7f
         // 0046e2a1: movdqu b16 ds:[edi+0xa0], b16 xmm0
      [-]a0000000f30f7f
         // 0046e2a9: movdqu b16 ds:[edi+0xb0], b16 xmm0
      [-]b0000000f30f7f
         // 0046e2b1: movdqu b16 ds:[edi+0xc0], b16 xmm0
      [-]c0000000f30f7f
         // 0046e2b9: movdqu b16 ds:[edi+0xd0], b16 xmm0
      [-]d0000000f30f7f
         // 0046e2c1: movdqu b16 ds:[edi+0xe0], b16 xmm0
      [-]e0000000f30f7f
         // 0046e2c9: movdqu b16 ds:[edi+0xf0], b16 xmm0
      [-]f000000081eb
         // 0046e2d1: sub ebx, 0x100
      [-]890789441f
         // 0046e2fc: mov ds:[edi], eax
         // 0046e2fe: mov ds:[edi+ebx+0xfffffffffffffffc], eax
      [-]10f30f7f
         // 0046e325: movdqu b16 ds:[edi+ebx+0xffffffffffffffe0], b16 xmm0
      [-]1fe0f30f7f
         // 0046e32b: movdqu b16 ds:[edi+ebx+0xfffffffffffffff0], b16 xmm0
      [-]10f30f7f
         // 0046e33b: movdqu b16 ds:[edi+0x20], b16 xmm0
      [-]20f30f7f
         // 0046e340: movdqu b16 ds:[edi+0x30], b16 xmm0
      [-]30f30f7f
         // 0046e345: movdqu b16 ds:[edi+ebx+0xffffffffffffffc0], b16 xmm0
      [-]1fc0f30f7f
         // 0046e34b: movdqu b16 ds:[edi+ebx+0xffffffffffffffd0], b16 xmm0
      [-]1fd0f30f7f
         // 0046e351: movdqu b16 ds:[edi+ebx+0xffffffffffffffe0], b16 xmm0
      [-]1fe0f30f7f
         // 0046e357: movdqu b16 ds:[edi+ebx+0xfffffffffffffff0], b16 xmm0
      [-]10f30f7f
         // 0046e367: movdqu b16 ds:[edi+0x20], b16 xmm0
      [-]20f30f7f
         // 0046e36c: movdqu b16 ds:[edi+0x30], b16 xmm0
      [-]30f30f7f
         // 0046e371: movdqu b16 ds:[edi+0x40], b16 xmm0
      [-]40f30f7f
         // 0046e376: movdqu b16 ds:[edi+0x50], b16 xmm0
      [-]50f30f7f
         // 0046e37b: movdqu b16 ds:[edi+0x60], b16 xmm0
      [-]60f30f7f
         // 0046e380: movdqu b16 ds:[edi+0x70], b16 xmm0
      [-]70f30f7f
         // 0046e385: movdqu b16 ds:[edi+ebx+0xffffffffffffff80], b16 xmm0
      [-]1f80f30f7f
         // 0046e38b: movdqu b16 ds:[edi+ebx+0xffffffffffffff90], b16 xmm0
      [-]1f90f30f7f
         // 0046e391: movdqu b16 ds:[edi+ebx+0xffffffffffffffa0], b16 xmm0
      [-]1fa0f30f7f
         // 0046e397: movdqu b16 ds:[edi+ebx+0xffffffffffffffb0], b16 xmm0
      [-]1fb0f30f7f
         // 0046e39d: movdqu b16 ds:[edi+ebx+0xffffffffffffffc0], b16 xmm0
      [-]1fc0f30f7f
         // 0046e3a3: movdqu b16 ds:[edi+ebx+0xffffffffffffffd0], b16 xmm0
      [-]1fd0f30f7f
         // 0046e3a9: movdqu b16 ds:[edi+ebx+0xffffffffffffffe0], b16 xmm0
      [-]1fe0f30f7f
         // 0046e3af: movdqu b16 ds:[edi+ebx+0xfffffffffffffff0], b16 xmm0
      [-]85db0f84
         // 0046d5a9: test rbx, rbx
         // 0046d5ac: jz 0x46d6a9
      [-]83fb020f86
         // 0046d5b2: cmp rbx, 0x2
         // 0046d5b6: jbe 0x46d69c
      [-]83fb200f86
         // 0046d5e6: cmp rbx, 0x20
         // 0046d5ea: jbe 0x46d6e1
      [-]83fb400f86
         // 0046d5f0: cmp rbx, 0x40
         // 0046d5f4: jbe 0x46d6f6
      [-]89f009f8a9
         // 0046e439: mov eax, esi
         // 0046e43b: or eax, edi
         // 0046e43d: test eax, 0x3
      [-]89d9f3a4c3
         // 0046e444: mov ecx, ebx
         // 0046e446: rep movsbb 
         // 0046e448: retn 
      [-]89f101d939f976
         // 0046e79c: mov rcx, rsi
         // 0046e79f: add rcx, rbx
         // 0046e7a2: cmp rcx, rdi
         // 0046e7a5: jbe 0x46e747
      [-]01df01defd89d9c1e9
         // 0046e7af: add rdi, rbx
         // 0046e7b2: add rsi, rbx
         // 0046e7b5: std 
         // 0046e7b6: mov rcx, rbx
         // 0046e7b9: shr rcx, b1 0x3
      [-]29df29dee9
         // 0046e7d5: sub rdi, rbx
         // 0046e7d8: sub rsi, rbx
         // 0046e7db: jmp 0x46e6c9
      [-]8a068a4c1eff8807884c1fffc3
         // 0046e482: mov b1 al, b1 ds:[esi]
         // 0046e484: mov b1 cl, b1 ds:[esi+ebx+0xffffffffffffffff]
         // 0046e488: mov b1 ds:[edi], b1 al
         // 0046e48a: mov b1 ds:[edi+ebx+0xffffffffffffffff], b1 cl
         // 0046e48e: retn 
      [-]668b068a4e02668907884f02c3
         // 0046e490: mov b2 ax, b2 ds:[esi]
         // 0046e493: mov b1 cl, b1 ds:[esi+0x2]
         // 0046e496: mov b2 ds:[edi], b2 ax
         // 0046e499: mov b1 ds:[edi+0x2], b1 cl
         // 0046e49c: retn 
      [-]8b068907c3
         // 0046e49d: mov eax, ds:[esi]
         // 0046e49f: mov ds:[edi], eax
         // 0046e4a1: retn 
      [-]8b068b4c1e
         // 0046e4a2: mov eax, ds:[esi]
         // 0046e4a4: mov ecx, ds:[esi+ebx+0xfffffffffffffffc]
      [-]8907894c1f
         // 0046e4a8: mov ds:[edi], eax
         // 0046e4aa: mov ds:[edi+ebx+0xfffffffffffffffc], ecx
      [-]f30f6f06f30f6f4c1ef0f30f7f07f30f7f4c1ff0c3
         // 0046e4ca: movdqu b16 xmm0, b16 ds:[esi]
         // 0046e4ce: movdqu b16 xmm1, b16 ds:[esi+ebx+0xfffffffffffffff0]
         // 0046e4d4: movdqu b16 ds:[edi], b16 xmm0
         // 0046e4d8: movdqu b16 ds:[edi+ebx+0xfffffffffffffff0], b16 xmm1
         // 0046e4de: retn 
      [-]f30f6f06f30f6f4e10f30f6f541ee0f30f6f5c1ef0f30f7f07f30f7f4f10f30f7f541fe0f30f7f5c1ff0c3
         // 0046e4df: movdqu b16 xmm0, b16 ds:[esi]
         // 0046e4e3: movdqu b16 xmm1, b16 ds:[esi+0x10]
         // 0046e4e8: movdqu b16 xmm2, b16 ds:[esi+ebx+0xffffffffffffffe0]
         // 0046e4ee: movdqu b16 xmm3, b16 ds:[esi+ebx+0xfffffffffffffff0]
         // 0046e4f4: movdqu b16 ds:[edi], b16 xmm0
         // 0046e4f8: movdqu b16 ds:[edi+0x10], b16 xmm1
         // 0046e4fd: movdqu b16 ds:[edi+ebx+0xffffffffffffffe0], b16 xmm2
         // 0046e503: movdqu b16 ds:[edi+ebx+0xfffffffffffffff0], b16 xmm3
         // 0046e509: retn 
      [-]f30f6f06f30f6f4e10f30f6f5620f30f6f5e30f30f6f641ec0f30f6f6c1ed0f30f6f741ee0f30f6f7c1ef0f30f7f07f30f7f4f10f30f7f5720f30f7f5f30f30f7f641fc0f30f7f6c1fd0f30f7f741fe0f30f7f7c1ff0c3
         // 0046e50a: movdqu b16 xmm0, b16 ds:[esi]
         // 0046e50e: movdqu b16 xmm1, b16 ds:[esi+0x10]
         // 0046e513: movdqu b16 xmm2, b16 ds:[esi+0x20]
         // 0046e518: movdqu b16 xmm3, b16 ds:[esi+0x30]
         // 0046e51d: movdqu b16 xmm4, b16 ds:[esi+ebx+0xffffffffffffffc0]
         // 0046e523: movdqu b16 xmm5, b16 ds:[esi+ebx+0xffffffffffffffd0]
         // 0046e529: movdqu b16 xmm6, b16 ds:[esi+ebx+0xffffffffffffffe0]
         // 0046e52f: movdqu b16 xmm7, b16 ds:[esi+ebx+0xfffffffffffffff0]
         // 0046e535: movdqu b16 ds:[edi], b16 xmm0
         // 0046e539: movdqu b16 ds:[edi+0x10], b16 xmm1
         // 0046e53e: movdqu b16 ds:[edi+0x20], b16 xmm2
         // 0046e543: movdqu b16 ds:[edi+0x30], b16 xmm3
         // 0046e548: movdqu b16 ds:[edi+ebx+0xffffffffffffffc0], b16 xmm4
         // 0046e54e: movdqu b16 ds:[edi+ebx+0xffffffffffffffd0], b16 xmm5
         // 0046e554: movdqu b16 ds:[edi+ebx+0xffffffffffffffe0], b16 xmm6
         // 0046e55a: movdqu b16 ds:[edi+ebx+0xfffffffffffffff0], b16 xmm7
         // 0046e560: retn 

  }
  condition:
    all of them
}
