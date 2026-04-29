rule wingo_40_1 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         31c0c60000c3
         // 004523a0: xor b4 eax, b4 eax
         // 004523a2: mov b1 ds:[rax], b1 0x0
         // 004523a5: retn 
      [-]8b0881c1
         // 0045f7d3: mov ecx, ds:[eax]
         // 0045f7d5: add ecx, 0xba0
      [-]8b1339d074
         // 00461919: mov edx, ds:[ebx]
         // 0046191b: cmp eax, edx
         // 0046191d: jz 0x461965
      [-]89fa8b3fffe7
         // 0046b6df: mov rdx, rdi
         // 0046b6e2: mov rdi, ds:[rdi]
         // 0046b6e6: jmp rdi
      [-]cccccccccccc
         // 0046b6f9: int b1 0x3
         // 0046b6fa: int b1 0x3
         // 0046b6fb: int b1 0x3
         // 0046b6fc: int b1 0x3
         // 0046b6fd: int b1 0x3
         // 0046b6fe: int b1 0x3
      [-]ba????????e9
         // 00461180: mov b4 edx, b4 0x0
         // 00461185: jmp runtime.morestack
      [-]85db0f84
         // 00459086: test rbx, rbx
         // 00459089: jz 0x459247
      [-]83fb400f86
         // 004590c7: cmp rbx, 0x40
         // 004590cb: jbe 0x459272
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
      [-]89f101d939f976
         // 0046f87c: mov rcx, rsi
         // 0046f87f: add rcx, rbx
         // 0046f882: cmp rcx, rdi
         // 0046f885: jbe 0x46f827
      [-]01df01defd89d9c1e9
         // 0046ce4b: add rdi, rbx
         // 0046ce4e: add rsi, rbx
         // 0046ce51: std 
         // 0046ce52: mov rcx, rbx
         // 0046ce55: shr rcx, b1 0x3
      [-]29df29dee9
         // 0046ce71: sub rdi, rbx
         // 0046ce74: sub rsi, rbx
         // 0046ce77: jmp 0x46cd89
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

  }
  condition:
    all of them
}
