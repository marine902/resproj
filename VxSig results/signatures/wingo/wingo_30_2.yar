rule wingo_30_2 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         31c0c60000c3
         // 00450280: xor b4 eax, b4 eax
         // 00450282: mov b1 ds:[rax], b1 0x0
         // 00450285: retn 
      [-]8b0881c1
         // 00469bfd: mov ecx, ds:[eax]
         // 00469bff: add ecx, 0xba0
      [-]8b1339d074
         // 0046105d: mov rdx, ds:[rbx]
         // 00461060: cmp rax, rdx
         // 00461063: jz 0x4610b1
      [-]89fa8b3fffe7
         // 00473d7f: mov rdx, rdi
         // 00473d82: mov rdi, ds:[rdi]
         // 00473d86: jmp rdi
      [-]cccccccccccc
         // 00473d99: int b1 0x3
         // 00473d9a: int b1 0x3
         // 00473d9b: int b1 0x3
         // 00473d9c: int b1 0x3
         // 00473d9d: int b1 0x3
         // 00473d9e: int b1 0x3
      [-]ba????????e9
         // 004574a0: mov edx, 0x0
         // 004574a5: jmp runtime.morestack
      [-]85db0f84
         // 00459086: test rbx, rbx
         // 00459089: jz 0x459247
      [-]83fb400f86
         // 004590c7: cmp rbx, 0x40
         // 004590cb: jbe 0x459272
      [-]10f30f7f
         // 0046f539: movdqu b16 ds:[rdi+0x20], b16 xmm15
      [-]20f30f7f
         // 0046f53f: movdqu b16 ds:[rdi+0x30], b16 xmm15
      [-]30f30f7f
         // 0046f545: movdqu b16 ds:[rdi+0x40], b16 xmm15
      [-]40f30f7f
         // 0046f54b: movdqu b16 ds:[rdi+0x50], b16 xmm15
      [-]50f30f7f
         // 0046f551: movdqu b16 ds:[rdi+0x60], b16 xmm15
      [-]60f30f7f
         // 0046f557: movdqu b16 ds:[rdi+0x70], b16 xmm15
      [-]70f30f7f
         // 0046f55d: movdqu b16 ds:[rdi+0x80], b16 xmm15
      [-]80000000f30f7f
         // 0046f566: movdqu b16 ds:[rdi+0x90], b16 xmm15
      [-]90000000f30f7f
         // 0046f56f: movdqu b16 ds:[rdi+0xa0], b16 xmm15
      [-]a0000000f30f7f
         // 0046f578: movdqu b16 ds:[rdi+0xb0], b16 xmm15
      [-]b0000000f30f7f
         // 0046f581: movdqu b16 ds:[rdi+0xc0], b16 xmm15
      [-]c0000000f30f7f
         // 0046f58a: movdqu b16 ds:[rdi+0xd0], b16 xmm15
      [-]d0000000f30f7f
         // 0046f593: movdqu b16 ds:[rdi+0xe0], b16 xmm15
      [-]e0000000f30f7f
         // 0046f59c: movdqu b16 ds:[rdi+0xf0], b16 xmm15
      [-]f000000081eb
         // 0046f5a5: sub rbx, 0x100
      [-]890789441f
         // 0046f6bb: mov ds:[rdi], rax
         // 0046f6be: mov ds:[rdi+rbx+0xfffffffffffffff8], rax
      [-]10f30f7f
         // 0046f6dc: movdqu b16 ds:[rdi+rbx+0xffffffffffffffe0], b16 xmm15
      [-]1fe0f30f7f
         // 0046f6e3: movdqu b16 ds:[rdi+rbx+0xfffffffffffffff0], b16 xmm15
      [-]10f30f7f
         // 0046f6f6: movdqu b16 ds:[rdi+0x20], b16 xmm15
      [-]20f30f7f
         // 0046f6fc: movdqu b16 ds:[rdi+0x30], b16 xmm15
      [-]30f30f7f
         // 0046f702: movdqu b16 ds:[rdi+rbx+0xffffffffffffffc0], b16 xmm15
      [-]1fc0f30f7f
         // 0046f709: movdqu b16 ds:[rdi+rbx+0xffffffffffffffd0], b16 xmm15
      [-]1fd0f30f7f
         // 0046f710: movdqu b16 ds:[rdi+rbx+0xffffffffffffffe0], b16 xmm15
      [-]1fe0f30f7f
         // 0046f717: movdqu b16 ds:[rdi+rbx+0xfffffffffffffff0], b16 xmm15
      [-]10f30f7f
         // 0046f72a: movdqu b16 ds:[rdi+0x20], b16 xmm15
      [-]20f30f7f
         // 0046f730: movdqu b16 ds:[rdi+0x30], b16 xmm15
      [-]30f30f7f
         // 0046f736: movdqu b16 ds:[rdi+0x40], b16 xmm15
      [-]40f30f7f
         // 0046f73c: movdqu b16 ds:[rdi+0x50], b16 xmm15
      [-]50f30f7f
         // 0046f742: movdqu b16 ds:[rdi+0x60], b16 xmm15
      [-]60f30f7f
         // 0046f748: movdqu b16 ds:[rdi+0x70], b16 xmm15
      [-]70f30f7f
         // 0046f74e: movdqu b16 ds:[rdi+rbx+0xffffffffffffff80], b16 xmm15
      [-]1f80f30f7f
         // 0046f755: movdqu b16 ds:[rdi+rbx+0xffffffffffffff90], b16 xmm15
      [-]1f90f30f7f
         // 0046f75c: movdqu b16 ds:[rdi+rbx+0xffffffffffffffa0], b16 xmm15
      [-]1fa0f30f7f
         // 0046f763: movdqu b16 ds:[rdi+rbx+0xffffffffffffffb0], b16 xmm15
      [-]1fb0f30f7f
         // 0046f76a: movdqu b16 ds:[rdi+rbx+0xffffffffffffffc0], b16 xmm15
      [-]1fc0f30f7f
         // 0046f771: movdqu b16 ds:[rdi+rbx+0xffffffffffffffd0], b16 xmm15
      [-]1fd0f30f7f
         // 0046f778: movdqu b16 ds:[rdi+rbx+0xffffffffffffffe0], b16 xmm15
      [-]1fe0f30f7f
         // 0046f77f: movdqu b16 ds:[rdi+rbx+0xfffffffffffffff0], b16 xmm15
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
      [-]89f101d939f976
         // 00464240: mov rcx, rsi
         // 00464243: add rcx, rbx
         // 00464246: cmp rcx, rdi
         // 00464249: jbe 0x464206
      [-]01df01defd89d9c1e9
         // 0046424b: add rdi, rbx
         // 0046424e: add rsi, rbx
         // 00464251: std 
         // 00464252: mov rcx, rbx
         // 00464255: shr rcx, b1 0x3
      [-]29df29dee9
         // 00464271: sub rdi, rbx
         // 00464274: sub rsi, rbx
         // 00464277: jmp 0x464189
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
      [-]8b068907c3
         // 0046f8ed: mov rax, ds:[rsi]
         // 0046f8f0: mov ds:[rdi], rax
         // 0046f8f3: retn 
      [-]8b068b4c1e
         // 0046f8f4: mov rax, ds:[rsi]
         // 0046f8f7: mov rcx, ds:[rsi+rbx+0xfffffffffffffff8]
      [-]8907894c1f
         // 0046f8fc: mov ds:[rdi], rax
         // 0046f8ff: mov ds:[rdi+rbx+0xfffffffffffffff8], rcx
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

  }
  condition:
    all of them
}
