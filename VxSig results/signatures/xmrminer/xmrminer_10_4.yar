rule xmrminer_10_4 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         488d0d491d1100e904b40800
         // 140001000: lea rcx, cs:[0x140112d50]
         // 140001007: jmp atexit
      [-]488d0d491d1100e9f4b30800
         // 140001010: lea rcx, cs:[0x140112d60]
         // 140001017: jmp atexit
      [-]40534883ec20b9????????e864b1080033d2488944243041b8????????488bc8488bd8e8089f0a00488d8b00100000ba????????e89394080033c048891d66e314004889835010000048898358100000488983601000004883c4205bc3
         // 140001020: push rbx
         // 140001022: sub rsp, 0x20
         // 140001026: mov b4 ecx, b4 0x1068
         // 14000102b: call ??2@YAPEAX_K@Z
         // 140001030: xor b4 edx, b4 edx
         // 140001032: mov ss:[rsp+0x30], rax
         // 140001037: mov b4 r8d, b4 0x1000
         // 14000103d: mov rcx, rax
         // 140001040: mov rbx, rax
         // 140001043: call memset
         // 140001048: lea rcx, ds:[rbx+0x1000]
         // 14000104f: mov b4 edx, b4 0x2
         // 140001054: call _Mtx_init_in_situ
         // 140001059: xor b4 eax, b4 eax
         // 14000105b: mov cs:[0x14014f3c8], rbx
         // 140001062: mov ds:[rbx+0x1050], rax
         // 140001069: mov ds:[rbx+0x1058], rax
         // 140001070: mov ds:[rbx+0x1060], rax
         // 140001077: add rsp, 0x20
         // 14000107b: pop rbx
         // 14000107c: retn 
      [-]488d0de91c1100e984b30800
         // 140001080: lea rcx, cs:[0x140112d70]
         // 140001087: jmp atexit
      [-]4883ec28b9????????e8f6b00800488d0ddb1c1100488900488940084889401066c74018010148890543e3140048c70548e31400000000004883c428e93fb30800
         // 140001090: sub rsp, 0x28
         // 140001094: mov b4 ecx, b4 0x30
         // 140001099: call ??2@YAPEAX_K@Z
         // 14000109e: lea rcx, cs:[0x140112d80]
         // 1400010a5: mov ds:[rax], rax
         // 1400010a8: mov ds:[rax+0x8], rax
         // 1400010ac: mov ds:[rax+0x10], rax
         // 1400010b0: mov b2 ds:[rax+0x18], b2 0x101
         // 1400010b6: mov cs:[0x14014f400], rax
         // 1400010bd: mov cs:[0x14014f410], 0x0
         // 1400010c8: add rsp, 0x28
         // 1400010cc: jmp atexit
      [-]488d0da91c1100e924b30800
         // 1400010e0: lea rcx, cs:[0x140112d90]
         // 1400010e7: jmp atexit
      [-]4883ec28b9????????e896b00800488d0d9b1c1100488900488940084889401066c74018010148890513e3140048c70518e31400000000004883c428e9dfb20800
         // 1400010f0: sub rsp, 0x28
         // 1400010f4: mov b4 ecx, b4 0x30
         // 1400010f9: call ??2@YAPEAX_K@Z
         // 1400010fe: lea rcx, cs:[0x140112da0]
         // 140001105: mov ds:[rax], rax
         // 140001108: mov ds:[rax+0x8], rax
         // 14000110c: mov ds:[rax+0x10], rax
         // 140001110: mov b2 ds:[rax+0x18], b2 0x101
         // 140001116: mov cs:[0x14014f430], rax
         // 14000111d: mov cs:[0x14014f440], 0x0
         // 140001128: add rsp, 0x28
         // 14000112c: jmp atexit
      [-]4883ec28b9????????e86eb508004c8b05139d1400488d1558a6120049ffc0488905fa9c1400488bc8e8d2990a00488d0d3b1c11004883c428e992b20800
         // 140001140: sub rsp, 0x28
         // 140001144: mov b4 ecx, b4 0x2
         // 140001149: call j_??2@YAPEAX_K@Z
         // 14000114e: mov r8, cs:[0x14014ae68]
         // 140001155: lea rdx, cs:[0x14012b7b4]
         // 14000115c: inc r8
         // 14000115f: mov cs:[0x14014ae60], rax
         // 140001166: mov rcx, rax
         // 140001169: call memmove
         // 14000116e: lea rcx, cs:[0x140112db0]
         // 140001175: add rsp, 0x28
         // 140001179: jmp atexit
      [-]4883ec28b9????????e82eb508004c8b05e39c1400488d1528a6120049ffc0488905ca9c1400488bc8e892990a00488d0d0b1c11004883c428e952b20800
         // 140001180: sub rsp, 0x28
         // 140001184: mov b4 ecx, b4 0x2
         // 140001189: call j_??2@YAPEAX_K@Z
         // 14000118e: mov r8, cs:[0x14014ae78]
         // 140001195: lea rdx, cs:[0x14012b7c4]
         // 14000119c: inc r8
         // 14000119f: mov cs:[0x14014ae70], rax
         // 1400011a6: mov rcx, rax
         // 1400011a9: call memmove
         // 1400011ae: lea rcx, cs:[0x140112dc0]
         // 1400011b5: add rsp, 0x28
         // 1400011b9: jmp atexit
      [-]4883ec28b9????????e8eeb408004c8b05b39c1400488d15e8ac120049ffc04889059a9c1400488bc8e852990a00488d0d4b1c11004883c428e912b20800
         // 1400011c0: sub rsp, 0x28
         // 1400011c4: mov b4 ecx, b4 0x4
         // 1400011c9: call j_??2@YAPEAX_K@Z
         // 1400011ce: mov r8, cs:[0x14014ae88]
         // 1400011d5: lea rdx, cs:[0x14012bec4]
         // 1400011dc: inc r8
         // 1400011df: mov cs:[0x14014ae80], rax
         // 1400011e6: mov rcx, rax
         // 1400011e9: call memmove
         // 1400011ee: lea rcx, cs:[0x140112e40]
         // 1400011f5: add rsp, 0x28
         // 1400011f9: jmp atexit
      [-]488d0d491c1100e904b20800
         // 140001200: lea rcx, cs:[0x140112e50]
         // 140001207: jmp atexit
      [-]e96bbd1000
         // 140001210: jmp 0x14010cf80
      [-]b8????????ba????????8605e4e01400488d0541e11400660f1f840000000000
         // 140001250: mov b4 eax, b4 0x1
         // 140001255: mov b4 edx, b4 0x3
         // 14000125a: xchg b1 al, b1 cs:[0x14014f344]
         // 140001260: lea rax, cs:[0x14014f3a8]
         // 140001267: nop b2 ds:[rax+rax+0x0]
      [-]488d4008b9????????488748f84883ea0175ed
         // 140001270: lea rax, ds:[rax+0x8]
         // 140001274: mov b4 ecx, b4 0x1
         // 140001279: xchg rcx, ds:[rax+0xfffffffffffffff8]
         // 14000127d: sub rdx, 0x1
         // 140001281: jnz 0x140001270
      [-]4883ec28488d0de1c41400e820960800488d0d311c11004883c428e96cb10800
         // 140001284: sub rsp, 0x28
         // 140001288: lea rcx, cs:[0x14014d770]
         // 14000128f: call ??0_Init_locks@std@@QEAA@XZ
         // 140001294: lea rcx, cs:[0x140112ecc]
         // 14000129b: add rsp, 0x28
         // 14000129f: jmp atexit
      [-]488d0d2d1c1100e960b10800
         // 1400012a4: lea rcx, cs:[0x140112ed8]
         // 1400012ab: jmp atexit
      [-]488d0d7d1c1100e954b10800
         // 1400012b0: lea rcx, cs:[??__Fclassic_locale@std@@YAXXZ]
         // 1400012b7: jmp atexit
      [-]488d0db11c1100e948b10800
         // 1400012bc: lea rcx, cs:[??__Finit_atexit@@YAXXZ]
         // 1400012c3: jmp atexit
      [-]4883ec28488d0d6dc81400e8dc950800488d0ddd1c11004883c428e928b10800
         // 1400012c8: sub rsp, 0x28
         // 1400012cc: lea rcx, cs:[0x14014db40]
         // 1400012d3: call ??0_Init_locks@std@@QEAA@XZ
         // 1400012d8: lea rcx, cs:[0x140112fbc]
         // 1400012df: add rsp, 0x28
         // 1400012e3: jmp atexit
      [-]488d0dd91c1100e91cb10800
         // 1400012e8: lea rcx, cs:[0x140112fc8]
         // 1400012ef: jmp atexit
      [-]4883ec28b9????????e8dac70a00488905efcf14004883c428c3
         // 1400012f4: sub rsp, 0x28
         // 1400012f8: mov b4 ecx, b4 0x2
         // 1400012fd: call __acrt_iob_func
         // 140001302: mov cs:[0x14014e2f8], rax
         // 140001309: add rsp, 0x28
         // 14000130d: retn 
      [-]4883ec28e86be9080048890568d014004883c428c3
         // 140001310: sub rsp, 0x28
         // 140001314: call 0x14008fc84
         // 140001319: mov cs:[0x14014e388], rax
         // 140001320: add rsp, 0x28
         // 140001324: retn 
      [-]488d0d71d0140048ff2552221100
         // 140001328: lea rcx, cs:[0x14014e3a0]
         // 14000132f: jmp cs:[InitializeSListHead]
      [-]ba????????e986ae0800
         // 140001340: mov b4 edx, b4 0x60
         // 140001345: jmp j_j_free
      [-]48895c2418488974242057415641574883ec20488b590849bfffffffffffff0000448b314923df49c1e605498bf84c03f348891a488bf2493bde0f84b2000000
         // 140001360: mov ss:[rsp+0x18], rbx
         // 140001365: mov ss:[rsp+0x20], rsi
         // 14000136a: push rdi
         // 14000136b: push r14
         // 14000136d: push r15
         // 14000136f: sub rsp, 0x20
         // 140001373: mov rbx, ds:[rcx+0x8]
         // 140001377: mov r15, 0xffffffffffff
         // 140001381: mov b4 r14d, b4 ds:[rcx]
         // 140001384: and rbx, r15
         // 140001387: shl r14, b1 0x5
         // 14000138b: mov rdi, r8
         // 14000138e: add r14, rbx
         // 140001391: mov ds:[rdx], rbx
         // 140001394: mov rsi, rdx
         // 140001397: cmp rbx, r14
         // 14000139a: jz 0x140001452
      [-]48896c2440410fb7680e4c8964244841bc????????664123ec0f1f80????????
         // 1400013a0: mov ss:[rsp+0x40], rbp
         // 1400013a5: movzx b4 ebp, b2 ds:[r8+0xe]
         // 1400013aa: mov ss:[rsp+0x48], r12
         // 1400013af: mov b4 r12d, b4 0x1000
         // 1400013b5: and b2 bp, b2 r12w
         // 1400013b9: nop b4 ds:[rax+0x0]
      [-]6685ed740f
         // 1400013c0: test b2 bp, b2 bp
         // 1400013c3: jz 0x1400013d4
      [-]0fbe470d41b8????????442bc0eb03
         // 1400013c5: movsx b4 eax, b1 ds:[rdi+0xd]
         // 1400013c9: mov b4 r8d, b4 0xd
         // 1400013cf: sub b4 r8d, b4 eax
         // 1400013d2: jmp 0x1400013d7
      [-]0fb7530e664123d4740d
         // 1400013d7: movzx b4 edx, b2 ds:[rbx+0xe]
         // 1400013db: and b2 dx, b2 r12w
         // 1400013df: jz 0x1400013ee
      [-]0fbe430db9????????2bc8eb02
         // 1400013e1: movsx b4 eax, b1 ds:[rbx+0xd]
         // 1400013e5: mov b4 ecx, b4 0xd
         // 1400013ea: sub b4 ecx, b4 eax
         // 1400013ec: jmp 0x1400013f0
      [-]443bc17530
         // 1400013f0: cmp b4 r8d, b4 ecx
         // 1400013f3: jnz 0x140001425
      [-]6685ed7405
         // 1400013f5: test b2 bp, b2 bp
         // 1400013f8: jz 0x1400013ff
      [-]488bcfeb07
         // 1400013fa: mov rcx, rdi
         // 1400013fd: jmp 0x140001406
      [-]488b4f084923cf
         // 1400013ff: mov rcx, ds:[rdi+0x8]
         // 140001403: and rcx, r15
      [-]6685d27405
         // 140001406: test b2 dx, b2 dx
         // 140001409: jz 0x140001410
      [-]488bd3eb07
         // 14000140b: mov rdx, rbx
         // 14000140e: jmp 0x140001417
      [-]488b53084923d7
         // 140001410: mov rdx, ds:[rbx+0x8]
         // 140001414: and rdx, r15
      [-]483bca7415
         // 140001417: cmp rcx, rdx
         // 14000141a: jz 0x140001431
      [-]e82f9e0a0085c0740c
         // 14000141c: call memcmp
         // 140001421: test b4 eax, b4 eax
         // 140001423: jz 0x140001431
      [-]4883c32048891e493bde758f
         // 140001425: add rbx, 0x20
         // 140001429: mov ds:[rsi], rbx
         // 14000142c: cmp rbx, r14
         // 14000142f: jnz 0x1400013c0
      [-]488b6c2440488bc64c8b642448
         // 140001431: mov rbp, ss:[rsp+0x40]
         // 140001436: mov rax, rsi
         // 140001439: mov r12, ss:[rsp+0x48]
      [-]488b5c2450488b7424584883c420415f415e5fc3
         // 14000143e: mov rbx, ss:[rsp+0x50]
         // 140001443: mov rsi, ss:[rsp+0x58]
         // 140001448: add rsp, 0x20
         // 14000144c: pop r15
         // 14000144e: pop r14
         // 140001450: pop rdi
         // 140001451: retn 
      [-]488bc6ebe7
         // 140001452: mov rax, rsi
         // 140001455: jmp 0x14000143e
      [-]488b09e968ad0800
         // 140001460: mov rcx, ds:[rcx]
         // 140001463: jmp j_j_free
      [-]48895c2408574883ec20488bd9488bfa488b09e848ad08004885ff7517
         // 140001470: mov ss:[rsp+0x8], rbx
         // 140001475: push rdi
         // 140001476: sub rsp, 0x20
         // 14000147a: mov rbx, rcx
         // 14000147d: mov rdi, rdx
         // 140001480: mov rcx, ds:[rcx]
         // 140001483: call j_j_free
         // 140001488: test rdi, rdi
         // 14000148b: jnz 0x1400014a4
      [-]33c048894308488903488bc3488b5c24304883c4205fc3
         // 14000148d: xor b4 eax, b4 eax
         // 14000148f: mov ds:[rbx+0x8], rax
         // 140001493: mov ds:[rbx], rax
         // 140001496: mov rax, rbx
         // 140001499: mov rbx, ss:[rsp+0x30]
         // 14000149e: add rsp, 0x20
         // 1400014a2: pop rdi
         // 1400014a3: retn 
      [-]48c7c1ffffffff0f1f440000
         // 1400014a4: mov rcx, 0xffffffffffffffff
         // 1400014ab: nop b4 ds:[rax+rax+0x0]
      [-]48ffc1803c0f0075f7
         // 1400014b0: inc rcx
         // 1400014b3: cmp b1 ds:[rdi+rcx], b1 0x0
         // 1400014b7: jnz 0x1400014b0
      [-]48894b0848ffc1e8f7b108004c8b4308488bd749ffc0488903488bc8e866960a00488bc3488b5c24304883c4205fc3
         // 1400014b9: mov ds:[rbx+0x8], rcx
         // 1400014bd: inc rcx
         // 1400014c0: call j_??2@YAPEAX_K@Z
         // 1400014c5: mov r8, ds:[rbx+0x8]
         // 1400014c9: mov rdx, rdi
         // 1400014cc: inc r8
         // 1400014cf: mov ds:[rbx], rax
         // 1400014d2: mov rcx, rax
         // 1400014d5: call memmove
         // 1400014da: mov rax, rbx
         // 1400014dd: mov rbx, ss:[rsp+0x30]
         // 1400014e2: add rsp, 0x20
         // 1400014e6: pop rdi
         // 1400014e7: retn 
      [-]81fa????????7d33
         // 1400014f0: cmp b4 edx, b4 0xfffffffffffffecc
         // 1400014f6: jge 0x14000152b
      [-]f20f5e05201f13008d82????????3d????????7d04
         // 1400014f8: divsd b16 xmm0, cs:[0x140133420]
         // 140001500: lea b4 eax, b4 ds:[rdx+0x134]
         // 140001506: cmp b4 eax, b4 0xfffffffffffffecc
         // 14000150b: jge 0x140001511
      [-]0f57c0c3
         // 14000150d: xorps b16 xmm0, b16 xmm0
         // 140001510: retn 
      [-]4863c2488d04c5a0090000
         // 140001511: movsxd rax, b4 edx
         // 140001514: lea rax, ds:[0x9a0+rax*0x8]
      [-]488d0dad8f1200482bc8f20f5e01c3
         // 14000151c: lea rcx, cs:[0x14012a4d0]
         // 140001523: sub rcx, rax
         // 140001526: divsd b16 xmm0, ds:[rcx]
         // 14000152a: retn 
      [-]4863c2488d04c50000000085d278e2
         // 14000152b: movsxd rax, b4 edx
         // 14000152e: lea rax, ds:[rax*0x8]
         // 140001536: test b4 edx, b4 edx
         // 140001538: js 0x14000151c
      [-]488d0d8f8f1200f20f590408c3
         // 14000153a: lea rcx, cs:[0x14012a4d0]
         // 140001541: mulsd b16 xmm0, ds:[rax+rcx]
         // 140001546: retn 
      [-]4883ec28480fbe01488bd13c200f8701010000
         // 140001550: sub rsp, 0x28
         // 140001554: movsx rax, b1 ds:[rcx]
         // 140001558: mov rdx, rcx
         // 14000155b: cmp b1 al, b1 0x20
         // 14000155d: ja 0x140001664
      [-]49b80026000001000000490fa3c00f83ed000000
         // 140001563: mov r8, 0x100002600
         // 14000156d: bt r8, rax
         // 140001571: jnb 0x140001664
      [-]4883c21048ffc14883e2f0483bca7427
         // 140001577: add rdx, 0x10
         // 14000157b: inc rcx
         // 14000157e: and rdx, 0xfffffffffffffff0
         // 140001582: cmp rcx, rdx
         // 140001585: jz 0x1400015ae
      [-]660f1f840000000000
         // 140001587: nop b2 ds:[rax+rax+0x0]
      [-]480fbe013c200f87c8000000
         // 140001590: movsx rax, b1 ds:[rcx]
         // 140001594: cmp b1 al, b1 0x20
         // 140001596: ja 0x140001664
      [-]490fa3c00f83be000000
         // 14000159c: bt r8, rax
         // 1400015a0: jnb 0x140001664
      [-]48ffc1483bca75e2
         // 1400015a6: inc rcx
         // 1400015a9: cmp rcx, rdx
         // 1400015ac: jnz 0x140001590
      [-]f30f6f11f30f6f25b6891200660f6fdaf30f6f2dba891200660f6fc2660f74dd0f29742410f30f6f35b5891200660f6fca660f74c40f293c24f30f6f3db1891200660febd8660f74ce660f74d7660febd9660febda660fd7c366f7d06685c0753e
         // 1400015ae: movdqu b16 xmm2, b16 ds:[rcx]
         // 1400015b2: movdqu b16 xmm4, b16 cs:[0x140129f70]
         // 1400015ba: movdqa b16 xmm3, b16 xmm2
         // 1400015be: movdqu b16 xmm5, b16 cs:[0x140129f80]
         // 1400015c6: movdqa b16 xmm0, b16 xmm2
         // 1400015ca: pcmpeqb b16 xmm3, b16 xmm5
         // 1400015ce: movaps b16 ss:[rsp+0x10], b16 xmm6
         // 1400015d3: movdqu b16 xmm6, b16 cs:[0x140129f90]
         // 1400015db: movdqa b16 xmm1, b16 xmm2
         // 1400015df: pcmpeqb b16 xmm0, b16 xmm4
         // 1400015e3: movaps b16 ss:[rsp], b16 xmm7
         // 1400015e7: movdqu b16 xmm7, b16 cs:[0x140129fa0]
         // 1400015ef: por b16 xmm3, b16 xmm0
         // 1400015f3: pcmpeqb b16 xmm1, b16 xmm6
         // 1400015f7: pcmpeqb b16 xmm2, b16 xmm7
         // 1400015fb: por b16 xmm3, b16 xmm1
         // 1400015ff: por b16 xmm3, b16 xmm2
         // 140001603: pmovmskb b4 eax, b16 xmm3
         // 140001607: not b2 ax
         // 14000160a: test b2 ax, b2 ax
         // 14000160d: jnz 0x14000164d
      [-]f30f6f51104883c110660f6fda660f6fc2660f74dd660f6fca660f74c4660f74ce660febd8660f74d7660febd9660febda660fd7c366f7d06685c074c3
         // 140001610: movdqu b16 xmm2, b16 ds:[rcx+0x10]
         // 140001615: add rcx, 0x10
         // 140001619: movdqa b16 xmm3, b16 xmm2
         // 14000161d: movdqa b16 xmm0, b16 xmm2
         // 140001621: pcmpeqb b16 xmm3, b16 xmm5
         // 140001625: movdqa b16 xmm1, b16 xmm2
         // 140001629: pcmpeqb b16 xmm0, b16 xmm4
         // 14000162d: pcmpeqb b16 xmm1, b16 xmm6
         // 140001631: por b16 xmm3, b16 xmm0
         // 140001635: pcmpeqb b16 xmm2, b16 xmm7
         // 140001639: por b16 xmm3, b16 xmm1
         // 14000163d: por b16 xmm3, b16 xmm2
         // 140001641: pmovmskb b4 eax, b16 xmm3
         // 140001645: not b2 ax
         // 140001648: test b2 ax, b2 ax
         // 14000164b: jz 0x140001610
      [-]0f283c240f287424100fb7c00fbcc04803c14883c428c3
         // 14000164d: movaps b16 xmm7, b16 ss:[rsp]
         // 140001651: movaps b16 xmm6, b16 ss:[rsp+0x10]
         // 140001656: movzx b4 eax, b2 ax
         // 140001659: bsf b4 eax, b4 eax
         // 14000165c: add rax, rcx
         // 14000165f: add rsp, 0x28
         // 140001663: retn 
      [-]488bc14883c428c3
         // 140001664: mov rax, rcx
         // 140001667: add rsp, 0x28
         // 14000166b: retn 
      [-]488b4110483941080f94c0c3
         // 140001670: mov rax, ds:[rcx+0x10]
         // 140001674: cmp ds:[rcx+0x8], rax
         // 140001678: setz b1 al
         // 14000167b: retn 
      [-]48895c2408574883ec20488bf98bda488b4920e838ab0800488d4f08e84f000000f6c301740d
         // 140001680: mov ss:[rsp+0x8], rbx
         // 140001685: push rdi
         // 140001686: sub rsp, 0x20
         // 14000168a: mov rdi, rcx
         // 14000168d: mov b4 ebx, b4 edx
         // 14000168f: mov rcx, ds:[rcx+0x20]
         // 140001693: call j_j_free
         // 140001698: lea rcx, ds:[rdi+0x8]
         // 14000169c: call 0x1400016f0
         // 1400016a1: test b1 bl, b1 0x1
         // 1400016a4: jz 0x1400016b3
      [-]ba????????488bcfe81dab0800
         // 1400016a6: mov b4 edx, b4 0x30
         // 1400016ab: mov rcx, rdi
         // 1400016ae: call j_j_free
      [-]488b5c2430488bc74883c4205fc3
         // 1400016b3: mov rbx, ss:[rsp+0x30]
         // 1400016b8: mov rax, rdi
         // 1400016bb: add rsp, 0x20
         // 1400016bf: pop rdi
         // 1400016c0: retn 
      [-]40534883ec20488bd9488b4920e8eeaa0800488d4b084883c4205be900000000
         // 1400016d0: push rbx
         // 1400016d2: sub rsp, 0x20
         // 1400016d6: mov rbx, rcx
         // 1400016d9: mov rcx, ds:[rcx+0x20]
         // 1400016dd: call j_j_free
         // 1400016e2: lea rcx, ds:[rbx+0x8]
         // 1400016e6: add rsp, 0x20
         // 1400016ea: pop rbx
         // 1400016eb: jmp 0x1400016f0
      [-]48895c2410574883ec20488b19488bf94885db0f849e000000
         // 1400016f0: mov ss:[rsp+0x10], rbx
         // 1400016f5: push rdi
         // 1400016f6: sub rsp, 0x20
         // 1400016fa: mov rbx, ds:[rcx]
         // 1400016fd: mov rdi, rcx
         // 140001700: test rbx, rbx
         // 140001703: jz 0x1400017a7
      [-]4889742430488b7108483bde742b
         // 140001709: mov ss:[rsp+0x30], rsi
         // 14000170e: mov rsi, ds:[rcx+0x8]
         // 140001712: cmp rbx, rsi
         // 140001715: jz 0x140001742
      [-]488bcbe8f1020000488b4b30e898bf0a00488b4b28ba????????e89aaa08004883c360483bde75d8
         // 140001717: mov rcx, rbx
         // 14000171a: call 0x140001a10
         // 14000171f: mov rcx, ds:[rbx+0x30]
         // 140001723: call free
         // 140001728: mov rcx, ds:[rbx+0x28]
         // 14000172c: mov b4 edx, b4 0x1
         // 140001731: call j_j_free
         // 140001736: add rbx, 0x60
         // 14000173a: cmp rbx, rsi
         // 14000173d: jnz 0x140001717
      [-]488b4f1048b8abaaaaaaaaaaaa2a488b742430482bcb48f7e948c1fa04488bc248c1e83f4803d0488d145248c1e2054881fa001000007218
         // 140001742: mov rcx, ds:[rdi+0x10]
         // 140001746: mov rax, 0x2aaaaaaaaaaaaaab
         // 140001750: mov rsi, ss:[rsp+0x30]
         // 140001755: sub rcx, rbx
         // 140001758: imul rcx
         // 14000175b: sar rdx, b1 0x4
         // 14000175f: mov rax, rdx
         // 140001762: shr rax, b1 0x3f
         // 140001766: add rdx, rax
         // 140001769: lea rdx, ds:[rdx+rdx*0x2]
         // 14000176d: shl rdx, b1 0x5
         // 140001771: cmp rdx, 0x1000
         // 140001778: jb 0x140001792
      [-]488b43f84883c227482bd84883c3f84883fb1f7723
         // 14000177a: mov rax, ds:[rbx+0xfffffffffffffff8]
         // 14000177e: add rdx, 0x27
         // 140001782: sub rbx, rax
         // 140001785: add rbx, 0xfffffffffffffff8
         // 140001789: cmp rbx, 0x1f
         // 14000178d: ja 0x1400017b2
      [-]488bcbe836aa080033c04889074889470848894710
         // 140001792: mov rcx, rbx
         // 140001795: call j_j_free
         // 14000179a: xor b4 eax, b4 eax
         // 14000179c: mov ds:[rdi], rax
         // 14000179f: mov ds:[rdi+0x8], rax
         // 1400017a3: mov ds:[rdi+0x10], rax
      [-]488b5c24384883c4205fc3
         // 1400017a7: mov rbx, ss:[rsp+0x38]
         // 1400017ac: add rsp, 0x20
         // 1400017b0: pop rdi
         // 1400017b1: retn 
      [-]e851c10a00
         // 1400017b2: call _invalid_parameter_noinfo_noreturn
      [-]40534883ec20488bd9e842020000488b4b30e8e9be0a00488b4b28ba????????4883c4205be9e6a90800
         // 1400017c0: push rbx
         // 1400017c2: sub rsp, 0x20
         // 1400017c6: mov rbx, rcx
         // 1400017c9: call 0x140001a10
         // 1400017ce: mov rcx, ds:[rbx+0x30]
         // 1400017d2: call free
         // 1400017d7: mov rcx, ds:[rbx+0x28]
         // 1400017db: mov b4 edx, b4 0x1
         // 1400017e0: add rsp, 0x20
         // 1400017e4: pop rbx
         // 1400017e5: jmp j_j_free
      [-]48894c2408574883ec3048c7442420feffffff48895c2448488bd90f57c00f110133ff6689790e4889791048897918488979204889792848897930488979384889794048c74148000400008979504889795848397910752c
         // 1400017f0: mov ss:[rsp+0x8], rcx
         // 1400017f5: push rdi
         // 1400017f6: sub rsp, 0x30
         // 1400017fa: mov ss:[rsp+0x20], 0xfffffffffffffffe
         // 140001803: mov ss:[rsp+0x48], rbx
         // 140001808: mov rbx, rcx
         // 14000180b: xorps b16 xmm0, b16 xmm0
         // 14000180e: movups b16 ds:[rcx], b16 xmm0
         // 140001811: xor b4 edi, b4 edi
         // 140001813: mov b2 ds:[rcx+0xe], b2 di
         // 140001817: mov ds:[rcx+0x10], rdi
         // 14000181b: mov ds:[rcx+0x18], rdi
         // 14000181f: mov ds:[rcx+0x20], rdi
         // 140001823: mov ds:[rcx+0x28], rdi
         // 140001827: mov ds:[rcx+0x30], rdi
         // 14000182b: mov ds:[rcx+0x38], rdi
         // 14000182f: mov ds:[rcx+0x40], rdi
         // 140001833: mov ds:[rcx+0x48], 0x400
         // 14000183b: mov b4 ds:[rcx+0x50], b4 edi
         // 14000183e: mov ds:[rcx+0x58], rdi
         // 140001842: cmp ds:[rcx+0x10], rdi
         // 140001846: jnz 0x140001874
      [-]8d4f28e844a90800488944245848893848c74008000001004889781048897818488978204889431048894318
         // 140001848: lea b4 ecx, b4 ds:[rdi+0x28]
         // 14000184b: call ??2@YAPEAX_K@Z
         // 140001850: mov ss:[rsp+0x58], rax
         // 140001855: mov ds:[rax], rdi
         // 140001858: mov ds:[rax+0x8], 0x10000
         // 140001860: mov ds:[rax+0x10], rdi
         // 140001864: mov ds:[rax+0x18], rdi
         // 140001868: mov ds:[rax+0x20], rdi
         // 14000186c: mov ds:[rbx+0x10], rax
         // 140001870: mov ds:[rbx+0x18], rax
      [-]488bc3488b5c24484883c4305fc3
         // 140001874: mov rax, rbx
         // 140001877: mov rbx, ss:[rsp+0x48]
         // 14000187c: add rsp, 0x30
         // 140001880: pop rdi
         // 140001881: retn 
      [-]48894c2408574883ec3048c7442420feffffff48895c2448488bd90f57c00f1101b8????????6689410e33ff4889791048897918488979204889792848897930488979384889794048c74148000400008979504889795848397910752c
         // 140001890: mov ss:[rsp+0x8], rcx
         // 140001895: push rdi
         // 140001896: sub rsp, 0x30
         // 14000189a: mov ss:[rsp+0x20], 0xfffffffffffffffe
         // 1400018a3: mov ss:[rsp+0x48], rbx
         // 1400018a8: mov rbx, rcx
         // 1400018ab: xorps b16 xmm0, b16 xmm0
         // 1400018ae: movups b16 ds:[rcx], b16 xmm0
         // 1400018b1: mov b4 eax, b4 0x3
         // 1400018b6: mov b2 ds:[rcx+0xe], b2 ax
         // 1400018ba: xor b4 edi, b4 edi
         // 1400018bc: mov ds:[rcx+0x10], rdi
         // 1400018c0: mov ds:[rcx+0x18], rdi
         // 1400018c4: mov ds:[rcx+0x20], rdi
         // 1400018c8: mov ds:[rcx+0x28], rdi
         // 1400018cc: mov ds:[rcx+0x30], rdi
         // 1400018d0: mov ds:[rcx+0x38], rdi
         // 1400018d4: mov ds:[rcx+0x40], rdi
         // 1400018d8: mov ds:[rcx+0x48], 0x400
         // 1400018e0: mov b4 ds:[rcx+0x50], b4 edi
         // 1400018e3: mov ds:[rcx+0x58], rdi
         // 1400018e7: cmp ds:[rcx+0x10], rdi
         // 1400018eb: jnz 0x140001919
      [-]8d4825e89fa80800488944245848893848c74008000001004889781048897818488978204889431048894318
         // 1400018ed: lea b4 ecx, b4 ds:[rax+0x25]
         // 1400018f0: call ??2@YAPEAX_K@Z
         // 1400018f5: mov ss:[rsp+0x58], rax
         // 1400018fa: mov ds:[rax], rdi
         // 1400018fd: mov ds:[rax+0x8], 0x10000
         // 140001905: mov ds:[rax+0x10], rdi
         // 140001909: mov ds:[rax+0x18], rdi
         // 14000190d: mov ds:[rax+0x20], rdi
         // 140001911: mov ds:[rbx+0x10], rax
         // 140001915: mov ds:[rbx+0x18], rax
      [-]488bc3488b5c24484883c4305fc3
         // 140001919: mov rax, rbx
         // 14000191c: mov rbx, ss:[rsp+0x48]
         // 140001921: add rsp, 0x30
         // 140001925: pop rdi
         // 140001926: retn 
      [-]48896c24104889742418574883ec20488bf94d8bd08b09488bf248bdffffffffffff00008b47043bc87252
         // 140001930: mov ss:[rsp+0x10], rbp
         // 140001935: mov ss:[rsp+0x18], rsi
         // 14000193a: push rdi
         // 14000193b: sub rsp, 0x20
         // 14000193f: mov rdi, rcx
         // 140001942: mov r10, r8
         // 140001945: mov b4 ecx, b4 ds:[rcx]
         // 140001947: mov rsi, rdx
         // 14000194a: mov rbp, 0xffffffffffff
         // 140001954: mov b4 eax, b4 ds:[rdi+0x4]
         // 140001957: cmp b4 ecx, b4 eax
         // 140001959: jb 0x1400019ad
      [-]48895c243085c07505
         // 14000195b: mov ss:[rsp+0x30], rbx
         // 140001960: test b4 eax, b4 eax
         // 140001962: jnz 0x140001969
      [-]8d5810eb0b
         // 140001964: lea b4 ebx, b4 ds:[rax+0x10]
         // 140001967: jmp 0x140001974
      [-]8d5801d1eb03d83bd87634
         // 140001969: lea b4 ebx, b4 ds:[rax+0x1]
         // 14000196c: shr b4 ebx, b1 0x1
         // 14000196e: add b4 ebx, b4 eax
         // 140001970: cmp b4 ebx, b4 eax
         // 140001972: jbe 0x1400019a8
      [-]488b57084c8bc0448bcb4823d549c1e104498bca49c1e004e8ff00000048b9000000000000ffff895f0448214f08480947088b0f
         // 140001974: mov rdx, ds:[rdi+0x8]
         // 140001978: mov r8, rax
         // 14000197b: mov b4 r9d, b4 ebx
         // 14000197e: and rdx, rbp
         // 140001981: shl r9, b1 0x4
         // 140001985: mov rcx, r10
         // 140001988: shl r8, b1 0x4
         // 14000198c: call 0x140001a90
         // 140001991: mov rcx, 0xffff000000000000
         // 14000199b: mov b4 ds:[rdi+0x4], b4 ebx
         // 14000199e: and ds:[rdi+0x8], rcx
         // 1400019a2: or ds:[rdi+0x8], rax
         // 1400019a6: mov b4 ecx, b4 ds:[rdi]
      [-]488b5c2430
         // 1400019a8: mov rbx, ss:[rsp+0x30]
      [-]8d41014803c98907488b47080f10064823c5488b6c24380f1104c833c06689460e488bc7488b7424404883c4205fc3
         // 1400019ad: lea b4 eax, b4 ds:[rcx+0x1]
         // 1400019b0: add rcx, rcx
         // 1400019b3: mov b4 ds:[rdi], b4 eax
         // 1400019b5: mov rax, ds:[rdi+0x8]
         // 1400019b9: movups b16 xmm0, b16 ds:[rsi]
         // 1400019bc: and rax, rbp
         // 1400019bf: mov rbp, ss:[rsp+0x38]
         // 1400019c4: movups b16 ds:[rax+rcx*0x8], b16 xmm0
         // 1400019c8: xor b4 eax, b4 eax
         // 1400019ca: mov b2 ds:[rsi+0xe], b2 ax
         // 1400019ce: mov rax, rdi
         // 1400019d1: mov rsi, ss:[rsp+0x40]
         // 1400019d6: add rsp, 0x20
         // 1400019da: pop rdi
         // 1400019db: retn 
      [-]40534883ec20488bd9488b4910e8cebc0a00488b4b08ba????????4883c4205be9cba70800
         // 1400019e0: push rbx
         // 1400019e2: sub rsp, 0x20
         // 1400019e6: mov rbx, rcx
         // 1400019e9: mov rcx, ds:[rcx+0x10]
         // 1400019ed: call free
         // 1400019f2: mov rcx, ds:[rbx+0x8]
         // 1400019f6: mov b4 edx, b4 0x1
         // 1400019fb: add rsp, 0x20
         // 1400019ff: pop rbx
         // 140001a00: jmp j_j_free
      [-]40574883ec20488b79184885ff7463
         // 140001a10: push rdi
         // 140001a12: sub rsp, 0x20
         // 140001a16: mov rdi, ds:[rcx+0x18]
         // 140001a1a: test rdi, rdi
         // 140001a1d: jz 0x140001a82
      [-]488b0f4885c9743b
         // 140001a1f: mov rcx, ds:[rdi]
         // 140001a22: test rcx, rcx
         // 140001a25: jz 0x140001a62
      [-]48895c2430488bd990
         // 140001a27: mov ss:[rsp+0x30], rbx
         // 140001a2c: mov rbx, rcx
         // 140001a2f: nop 
      [-]483b4f107414
         // 140001a30: cmp rcx, ds:[rdi+0x10]
         // 140001a34: jz 0x140001a4a
      [-]488b5910e881bc0a0048891f488bcb4885db75e6
         // 140001a36: mov rbx, ds:[rcx+0x10]
         // 140001a3a: call free
         // 140001a3f: mov ds:[rdi], rbx
         // 140001a42: mov rcx, rbx
         // 140001a45: test rbx, rbx
         // 140001a48: jnz 0x140001a30
      [-]4885db740e
         // 140001a4a: test rbx, rbx
         // 140001a4d: jz 0x140001a5d
      [-]483b5f107508
         // 140001a4f: cmp rbx, ds:[rdi+0x10]
         // 140001a53: jnz 0x140001a5d
      [-]48c7430800000000
         // 140001a55: mov ds:[rbx+0x8], 0x0
      [-]488b5c2430
         // 140001a5d: mov rbx, ss:[rsp+0x30]
      [-]488b4f20ba????????e860a70800ba????????488bcf4883c4205fe94ea70800
         // 140001a62: mov rcx, ds:[rdi+0x20]
         // 140001a66: mov b4 edx, b4 0x1
         // 140001a6b: call j_j_free
         // 140001a70: mov b4 edx, b4 0x28
         // 140001a75: mov rcx, rdi
         // 140001a78: add rsp, 0x20
         // 140001a7c: pop rdi
         // 140001a7d: jmp j_j_free
      [-]4883c4205fc3
         // 140001a82: add rsp, 0x20
         // 140001a86: pop rdi
         // 140001a87: retn 
      [-]40534883ec20488bda4c8bd14885d2750d
         // 140001a90: push rbx
         // 140001a92: sub rsp, 0x20
         // 140001a96: mov rbx, rdx
         // 140001a99: mov r10, rcx
         // 140001a9c: test rdx, rdx
         // 140001a9f: jnz 0x140001aae
      [-]498bd14883c4205be9b2000000
         // 140001aa1: mov rdx, r9
         // 140001aa4: add rsp, 0x20
         // 140001aa8: pop rbx
         // 140001aa9: jmp 0x140001b60
      [-]488974243048897c24384d85c90f8481000000
         // 140001aae: mov ss:[rsp+0x30], rsi
         // 140001ab3: mov ss:[rsp+0x38], rdi
         // 140001ab8: test r9, r9
         // 140001abb: jz 0x140001b42
      [-]498d7807498d51074883e7f84883e2f8483bfa7323
         // 140001ac1: lea rdi, ds:[r8+0x7]
         // 140001ac5: lea rdx, ds:[r9+0x7]
         // 140001ac9: and rdi, 0xfffffffffffffff8
         // 140001acd: and rdx, 0xfffffffffffffff8
         // 140001ad1: cmp rdi, rdx
         // 140001ad4: jnb 0x140001af9
      [-]488b094c8b4108488d41184c2bc74903c0483bd87520
         // 140001ad6: mov rcx, ds:[rcx]
         // 140001ad9: mov r8, ds:[rcx+0x8]
         // 140001add: lea rax, ds:[rcx+0x18]
         // 140001ae1: sub r8, rdi
         // 140001ae4: add rax, r8
         // 140001ae7: cmp rbx, rax
         // 140001aea: jnz 0x140001b0c
      [-]498d0410483b017717
         // 140001aec: lea rax, ds:[r8+rdx]
         // 140001af0: cmp rax, ds:[rcx]
         // 140001af3: ja 0x140001b0c
      [-]48894108
         // 140001af5: mov ds:[rcx+0x8], rax
      [-]488b742430488bc3488b7c24384883c4205bc3
         // 140001af9: mov rsi, ss:[rsp+0x30]
         // 140001afe: mov rax, rbx
         // 140001b01: mov rdi, ss:[rsp+0x38]
         // 140001b06: add rsp, 0x20
         // 140001b0a: pop rbx
         // 140001b0b: retn 
      [-]498bcae84c000000488bf04885c07426
         // 140001b0c: mov rcx, r10
         // 140001b0f: call 0x140001b60
         // 140001b14: mov rsi, rax
         // 140001b17: test rax, rax
         // 140001b1a: jz 0x140001b42
      [-]4885ff740e
         // 140001b1c: test rdi, rdi
         // 140001b1f: jz 0x140001b2f
      [-]4c8bc7488bd3488bc8e811900a00
         // 140001b21: mov r8, rdi
         // 140001b24: mov rdx, rbx
         // 140001b27: mov rcx, rax
         // 140001b2a: call memmove
      [-]488b7c2438488bc6488b7424304883c4205bc3
         // 140001b2f: mov rdi, ss:[rsp+0x38]
         // 140001b34: mov rax, rsi
         // 140001b37: mov rsi, ss:[rsp+0x30]
         // 140001b3c: add rsp, 0x20
         // 140001b40: pop rbx
         // 140001b41: retn 
      [-]488b74243033c0488b7c24384883c4205bc3
         // 140001b42: mov rsi, ss:[rsp+0x30]
         // 140001b47: xor b4 eax, b4 eax
         // 140001b49: mov rdi, ss:[rsp+0x38]
         // 140001b4e: add rsp, 0x20
         // 140001b52: pop rbx
         // 140001b53: retn 
      [-]48895c24084889742410574883ec20488bd94885d20f848d000000
         // 140001b60: mov ss:[rsp+0x8], rbx
         // 140001b65: mov ss:[rsp+0x10], rsi
         // 140001b6a: push rdi
         // 140001b6b: sub rsp, 0x20
         // 140001b6f: mov rbx, rcx
         // 140001b72: test rdx, rdx
         // 140001b75: jz 0x140001c08
      [-]488d7207488b114883e6f84885d2740c
         // 140001b7b: lea rsi, ds:[rdx+0x7]
         // 140001b7f: mov rdx, ds:[rcx]
         // 140001b82: and rsi, 0xfffffffffffffff8
         // 140001b86: test rdx, rdx
         // 140001b89: jz 0x140001b97
      [-]488b4a084803ce483b0a764f
         // 140001b8b: mov rcx, ds:[rdx+0x8]
         // 140001b8f: add rcx, rsi
         // 140001b92: cmp rcx, ds:[rdx]
         // 140001b95: jbe 0x140001be6
      [-]488b7b08483bfe480f46fe48837b18007512
         // 140001b97: mov rdi, ds:[rbx+0x8]
         // 140001b9b: cmp rdi, rsi
         // 140001b9e: cmovbe rdi, rsi
         // 140001ba2: cmp ds:[rbx+0x18], 0x0
         // 140001ba7: jnz 0x140001bbb
      [-]b9????????e8e1a508004889431848894320
         // 140001ba9: mov b4 ecx, b4 0x1
         // 140001bae: call ??2@YAPEAX_K@Z
         // 140001bb3: mov ds:[rbx+0x18], rax
         // 140001bb7: mov ds:[rbx+0x20], rax
      [-]488d4f184885c97444
         // 140001bbb: lea rcx, ds:[rdi+0x18]
         // 140001bbf: test rcx, rcx
         // 140001bc2: jz 0x140001c08
      [-]e8ebbd0a00488bd04885c07437
         // 140001bc4: call j__malloc_base
         // 140001bc9: mov rdx, rax
         // 140001bcc: test rax, rax
         // 140001bcf: jz 0x140001c08
      [-]488b0b4889481048893848c7400800000000488903
         // 140001bd1: mov rcx, ds:[rbx]
         // 140001bd4: mov ds:[rax+0x10], rcx
         // 140001bd8: mov ds:[rax], rdi
         // 140001bdb: mov ds:[rax+0x8], 0x0
         // 140001be3: mov ds:[rbx], rax
      [-]488b4a08488d42184803c14803ce48894a08488b5c2430488b7424384883c4205fc3
         // 140001be6: mov rcx, ds:[rdx+0x8]
         // 140001bea: lea rax, ds:[rdx+0x18]
         // 140001bee: add rax, rcx
         // 140001bf1: add rcx, rsi
         // 140001bf4: mov ds:[rdx+0x8], rcx
         // 140001bf8: mov rbx, ss:[rsp+0x30]
         // 140001bfd: mov rsi, ss:[rsp+0x38]
         // 140001c02: add rsp, 0x20
         // 140001c06: pop rdi
         // 140001c07: retn 
      [-]488b5c243033c0488b7424384883c4205fc3
         // 140001c08: mov rbx, ss:[rsp+0x30]
         // 140001c0d: xor b4 eax, b4 eax
         // 140001c0f: mov rsi, ss:[rsp+0x38]
         // 140001c14: add rsp, 0x20
         // 140001c18: pop rdi
         // 140001c19: retn 
      [-]4053555641544883ec384c8b114c8bca488bea49bbabaaaaaaaaaaaa2a4d2bca488bf1488b4908498bc349f7e9492bca4d8be0488bda49b8aaaaaaaaaaaaaa0248c1fb04488bc348c1e83f4803d8498bc348f7e948c1fa04488bc248c1e83f4803d0493bd00f845e020000
         // 140001c20: push rbx
         // 140001c22: push rbp
         // 140001c23: push rsi
         // 140001c24: push r12
         // 140001c26: sub rsp, 0x38
         // 140001c2a: mov r10, ds:[rcx]
         // 140001c2d: mov r9, rdx
         // 140001c30: mov rbp, rdx
         // 140001c33: mov r11, 0x2aaaaaaaaaaaaaab
         // 140001c3d: sub r9, r10
         // 140001c40: mov rsi, rcx
         // 140001c43: mov rcx, ds:[rcx+0x8]
         // 140001c47: mov rax, r11
         // 140001c4a: imul r9
         // 140001c4d: sub rcx, r10
         // 140001c50: mov r12, r8
         // 140001c53: mov rbx, rdx
         // 140001c56: mov r8, 0x2aaaaaaaaaaaaaa
         // 140001c60: sar rbx, b1 0x4
         // 140001c64: mov rax, rbx
         // 140001c67: shr rax, b1 0x3f
         // 140001c6b: add rbx, rax
         // 140001c6e: mov rax, r11
         // 140001c71: imul rcx
         // 140001c74: sar rdx, b1 0x4
         // 140001c78: mov rax, rdx
         // 140001c7b: shr rax, b1 0x3f
         // 140001c7f: add rdx, rax
         // 140001c82: cmp rdx, r8
         // 140001c85: jz 0x140001ee9
      [-]488b4e10498bc3492bca4c897424704c8d72014c897c243048f7e948c1fa04488bc248c1e83f4803d0498bc0488bca48d1e9482bc1483bd07605
         // 140001c8b: mov rcx, ds:[rsi+0x10]
         // 140001c8f: mov rax, r11
         // 140001c92: sub rcx, r10
         // 140001c95: mov ss:[rsp+0x70], r14
         // 140001c9a: lea r14, ds:[rdx+0x1]
         // 140001c9e: mov ss:[rsp+0x30], r15
         // 140001ca3: imul rcx
         // 140001ca6: sar rdx, b1 0x4
         // 140001caa: mov rax, rdx
         // 140001cad: shr rax, b1 0x3f
         // 140001cb1: add rdx, rax
         // 140001cb4: mov rax, r8
         // 140001cb7: mov rcx, rdx
         // 140001cba: shr rcx, b1 0x1
         // 140001cbd: sub rax, rcx
         // 140001cc0: cmp rdx, rax
         // 140001cc3: jbe 0x140001cca
      [-]498bc6eb0b
         // 140001cc5: mov rax, r14
         // 140001cc8: jmp 0x140001cd5
      [-]488d0411493bc6490f42c6
         // 140001cca: lea rax, ds:[rcx+rdx]
         // 140001cce: cmp rax, r14
         // 140001cd1: cmovb rax, r14
      [-]33c948897c24604c8d3c404c896c246849c1e705498bd74c8d49ff493bc07605
         // 140001cd5: xor b4 ecx, b4 ecx
         // 140001cd7: mov ss:[rsp+0x60], rdi
         // 140001cdc: lea r15, ds:[rax+rax*0x2]
         // 140001ce0: mov ss:[rsp+0x68], r13
         // 140001ce5: shl r15, b1 0x5
         // 140001ce9: mov rdx, r15
         // 140001cec: lea r9, ds:[rcx+0xffffffffffffffff]
         // 140001cf0: cmp rax, r8
         // 140001cf3: jbe 0x140001cfa
      [-]498bd1eb09
         // 140001cf5: mov rdx, r9
         // 140001cf8: jmp 0x140001d03
      [-]4881fa001000007229
         // 140001cfa: cmp rdx, 0x1000
         // 140001d01: jb 0x140001d2c
      [-]488d4a27483bca490f46c9e881a408004885c00f84d3010000
         // 140001d03: lea rcx, ds:[rdx+0x27]
         // 140001d07: cmp rcx, rdx
         // 140001d0a: cmovbe rcx, r9
         // 140001d0e: call ??2@YAPEAX_K@Z
         // 140001d13: test rax, rax
         // 140001d16: jz 0x140001eef
      [-]488d78274883e7e033c9488947f8eb17
         // 140001d1c: lea rdi, ds:[rax+0x27]
         // 140001d20: and rdi, 0xffffffffffffffe0
         // 140001d24: xor b4 ecx, b4 ecx
         // 140001d26: mov ds:[rdi+0xfffffffffffffff8], rax
         // 140001d2a: jmp 0x140001d43
      [-]4885d2740f
         // 140001d2c: test rdx, rdx
         // 140001d2f: jz 0x140001d40
      [-]488bcae85ba40800488bf833c9eb03
         // 140001d31: mov rcx, rdx
         // 140001d34: call ??2@YAPEAX_K@Z
         // 140001d39: mov rdi, rax
         // 140001d3c: xor b4 ecx, b4 ecx
         // 140001d3e: jmp 0x140001d43
      [-]410f1004244c8d2c5b894c242049c1e5054c8bc74c03ef48894c2428410f114500498b4424106641894c240e49894510498b44241849894518498b44242049894520498b44242849894528498b44243049894530498b44243849894538498b44244049894540498b4424484989454849894c242049894c242849894c243049894c243849894c244049894c2448410f10442450410f11455049894c24100f1044242049894c2418410f11442450488b5608488b0e483bea7413
         // 140001d43: movups b16 xmm0, b16 ds:[r12]
         // 140001d48: lea r13, ds:[rbx+rbx*0x2]
         // 140001d4c: mov b4 ss:[rsp+0x20], b4 ecx
         // 140001d50: shl r13, b1 0x5
         // 140001d54: mov r8, rdi
         // 140001d57: add r13, rdi
         // 140001d5a: mov ss:[rsp+0x28], rcx
         // 140001d5f: movups b16 ds:[r13+0x0], b16 xmm0
         // 140001d64: mov rax, ds:[r12+0x10]
         // 140001d69: mov b2 ds:[r12+0xe], b2 cx
         // 140001d6f: mov ds:[r13+0x10], rax
         // 140001d73: mov rax, ds:[r12+0x18]
         // 140001d78: mov ds:[r13+0x18], rax
         // 140001d7c: mov rax, ds:[r12+0x20]
         // 140001d81: mov ds:[r13+0x20], rax
         // 140001d85: mov rax, ds:[r12+0x28]
         // 140001d8a: mov ds:[r13+0x28], rax
         // 140001d8e: mov rax, ds:[r12+0x30]
         // 140001d93: mov ds:[r13+0x30], rax
         // 140001d97: mov rax, ds:[r12+0x38]
         // 140001d9c: mov ds:[r13+0x38], rax
         // 140001da0: mov rax, ds:[r12+0x40]
         // 140001da5: mov ds:[r13+0x40], rax
         // 140001da9: mov rax, ds:[r12+0x48]
         // 140001dae: mov ds:[r13+0x48], rax
         // 140001db2: mov ds:[r12+0x20], rcx
         // 140001db7: mov ds:[r12+0x28], rcx
         // 140001dbc: mov ds:[r12+0x30], rcx
         // 140001dc1: mov ds:[r12+0x38], rcx
         // 140001dc6: mov ds:[r12+0x40], rcx
         // 140001dcb: mov ds:[r12+0x48], rcx
         // 140001dd0: movups b16 xmm0, b16 ds:[r12+0x50]
         // 140001dd6: movups b16 ds:[r13+0x50], b16 xmm0
         // 140001ddb: mov ds:[r12+0x10], rcx
         // 140001de0: movups b16 xmm0, b16 ss:[rsp+0x20]
         // 140001de5: mov ds:[r12+0x18], rcx
         // 140001dea: movups b16 ds:[r12+0x50], b16 xmm0
         // 140001df0: mov rdx, ds:[rsi+0x8]
         // 140001df4: mov rcx, ds:[rsi]
         // 140001df7: cmp rbp, rdx
         // 140001dfa: jz 0x140001e0f
      [-]488bd5e81c010000488b56084d8d4560488bcd
         // 140001dfc: mov rdx, rbp
         // 140001dff: call 0x140001f20
         // 140001e04: mov rdx, ds:[rsi+0x8]
         // 140001e08: lea r8, ds:[r13+0x60]
         // 140001e0c: mov rcx, rbp
      [-]e80c010000488b1e4885db0f848e000000
         // 140001e0f: call 0x140001f20
         // 140001e14: mov rbx, ds:[rsi]
         // 140001e17: test rbx, rbx
         // 140001e1a: jz 0x140001eae
      [-]488b6e08483bdd7432
         // 140001e20: mov rbp, ds:[rsi+0x8]
         // 140001e24: cmp rbx, rbp
         // 140001e27: jz 0x140001e5b
      [-]0f1f80????????
         // 140001e29: nop b4 ds:[rax+0x0]
      [-]488bcbe8d8fbffff488b4b30e87fb80a00488b4b28ba????????e881a308004883c360483bdd75d8
         // 140001e30: mov rcx, rbx
         // 140001e33: call 0x140001a10
         // 140001e38: mov rcx, ds:[rbx+0x30]
         // 140001e3c: call free
         // 140001e41: mov rcx, ds:[rbx+0x28]
         // 140001e45: mov b4 edx, b4 0x1
         // 140001e4a: call j_j_free
         // 140001e4f: add rbx, 0x60
         // 140001e53: cmp rbx, rbp
         // 140001e56: jnz 0x140001e30
      [-]488b4e1048b8abaaaaaaaaaaaa2a482bcb48f7e948c1fa04488bc248c1e83f4803d0488d145248c1e2054881fa001000007218
         // 140001e5b: mov rcx, ds:[rsi+0x10]
         // 140001e5f: mov rax, 0x2aaaaaaaaaaaaaab
         // 140001e69: sub rcx, rbx
         // 140001e6c: imul rcx
         // 140001e6f: sar rdx, b1 0x4
         // 140001e73: mov rax, rdx
         // 140001e76: shr rax, b1 0x3f
         // 140001e7a: add rdx, rax
         // 140001e7d: lea rdx, ds:[rdx+rdx*0x2]
         // 140001e81: shl rdx, b1 0x5
         // 140001e85: cmp rdx, 0x1000
         // 140001e8c: jb 0x140001ea6
      [-]488b43f84883c227482bd84883c3f84883fb1f774c
         // 140001e8e: mov rax, ds:[rbx+0xfffffffffffffff8]
         // 140001e92: add rdx, 0x27
         // 140001e96: sub rbx, rax
         // 140001e99: add rbx, 0xfffffffffffffff8
         // 140001e9d: cmp rbx, 0x1f
         // 140001ea1: ja 0x140001eef
      [-]488bcbe822a30800
         // 140001ea6: mov rcx, rbx
         // 140001ea9: call j_j_free
      [-]48893e4b8d0c764c8b742470498bc54c8b6c246848c1e1054803cf48894e08498d0c3f488b7c24604c8b7c243048894e104883c438415c5e5d5bc3
         // 140001eae: mov ds:[rsi], rdi
         // 140001eb1: lea rcx, ds:[r14+r14*0x2]
         // 140001eb5: mov r14, ss:[rsp+0x70]
         // 140001eba: mov rax, r13
         // 140001ebd: mov r13, ss:[rsp+0x68]
         // 140001ec2: shl rcx, b1 0x5
         // 140001ec6: add rcx, rdi
         // 140001ec9: mov ds:[rsi+0x8], rcx
         // 140001ecd: lea rcx, ds:[r15+rdi]
         // 140001ed1: mov rdi, ss:[rsp+0x60]
         // 140001ed6: mov r15, ss:[rsp+0x30]
         // 140001edb: mov ds:[rsi+0x10], rcx
         // 140001edf: add rsp, 0x38
         // 140001ee3: pop r12
         // 140001ee5: pop rsi
         // 140001ee6: pop rbp
         // 140001ee7: pop rbx
         // 140001ee8: retn 
      [-]e812000000
         // 140001ee9: call 0x140001f00
      [-]e814ba0a00
         // 140001eef: call _invalid_parameter_noinfo_noreturn
      [-]4883ec184d8bd0483bca0f84bb000000
         // 140001f20: sub rsp, 0x18
         // 140001f24: mov r10, r8
         // 140001f27: cmp rcx, rdx
         // 140001f2a: jz 0x140001feb
      [-]4d8bca4c8d41304c2bc94533db0f1f00
         // 140001f30: mov r9, r10
         // 140001f33: lea r8, ds:[rcx+0x30]
         // 140001f37: sub r9, rcx
         // 140001f3a: xor b4 r11d, b4 r11d
         // 140001f3d: nop b4 ds:[rax]
      [-]410f1040d044891c244d8d40604c895c2408498d48d0410f1102498b40804983c260664589987effffff4b89440180498b40884b89440188498b40904b89440890498b40984b89440198498b40a04b894401a0498b40a84b894401a8498b40b04b894401b0498b40b84b894401b84d8958904d8958984d8958a04d8958a84d8958b04d8958b8410f1040c0430f114408c04d8958804d8958880f100424410f1140c0483bca0f8555ffffff
         // 140001f40: movups b16 xmm0, b16 ds:[r8+0xffffffffffffffd0]
         // 140001f45: mov b4 ss:[rsp], b4 r11d
         // 140001f49: lea r8, ds:[r8+0x60]
         // 140001f4d: mov ss:[rsp+0x8], r11
         // 140001f52: lea rcx, ds:[r8+0xffffffffffffffd0]
         // 140001f56: movups b16 ds:[r10], b16 xmm0
         // 140001f5a: mov rax, ds:[r8+0xffffffffffffff80]
         // 140001f5e: add r10, 0x60
         // 140001f62: mov b2 ds:[r8+0xffffffffffffff7e], b2 r11w
         // 140001f6a: mov ds:[r9+r8+0xffffffffffffff80], rax
         // 140001f6f: mov rax, ds:[r8+0xffffffffffffff88]
         // 140001f73: mov ds:[r9+r8+0xffffffffffffff88], rax
         // 140001f78: mov rax, ds:[r8+0xffffffffffffff90]
         // 140001f7c: mov ds:[r8+r9+0xffffffffffffff90], rax
         // 140001f81: mov rax, ds:[r8+0xffffffffffffff98]
         // 140001f85: mov ds:[r9+r8+0xffffffffffffff98], rax
         // 140001f8a: mov rax, ds:[r8+0xffffffffffffffa0]
         // 140001f8e: mov ds:[r9+r8+0xffffffffffffffa0], rax
         // 140001f93: mov rax, ds:[r8+0xffffffffffffffa8]
         // 140001f97: mov ds:[r9+r8+0xffffffffffffffa8], rax
         // 140001f9c: mov rax, ds:[r8+0xffffffffffffffb0]
         // 140001fa0: mov ds:[r9+r8+0xffffffffffffffb0], rax
         // 140001fa5: mov rax, ds:[r8+0xffffffffffffffb8]
         // 140001fa9: mov ds:[r9+r8+0xffffffffffffffb8], rax
         // 140001fae: mov ds:[r8+0xffffffffffffff90], r11
         // 140001fb2: mov ds:[r8+0xffffffffffffff98], r11
         // 140001fb6: mov ds:[r8+0xffffffffffffffa0], r11
         // 140001fba: mov ds:[r8+0xffffffffffffffa8], r11
         // 140001fbe: mov ds:[r8+0xffffffffffffffb0], r11
         // 140001fc2: mov ds:[r8+0xffffffffffffffb8], r11
         // 140001fc6: movups b16 xmm0, b16 ds:[r8+0xffffffffffffffc0]
         // 140001fcb: movups b16 ds:[r8+r9+0xffffffffffffffc0], b16 xmm0
         // 140001fd1: mov ds:[r8+0xffffffffffffff80], r11
         // 140001fd5: mov ds:[r8+0xffffffffffffff88], r11
         // 140001fd9: movups b16 xmm0, b16 ss:[rsp]
         // 140001fdd: movups b16 ds:[r8+0xffffffffffffffc0], b16 xmm0
         // 140001fe2: cmp rcx, rdx
         // 140001fe5: jnz 0x140001f40
      [-]498bc24883c418c3
         // 140001feb: mov rax, r10
         // 140001fee: add rsp, 0x18
         // 140001ff2: retn 
      [-]40555657488bec4881ec8000000048c745a0feffffff48899c24b0000000488bda488bf9488b4120488945b033f6488975b80f57c0660f7f45c0660f6f0d2e141300660f7f4dd0c745f0????????48894d208975e0488975e8488d45b048894528488b0a
         // 140002000: push rbp
         // 140002002: push rsi
         // 140002003: push rdi
         // 140002004: mov rbp, rsp
         // 140002007: sub rsp, 0x80
         // 14000200e: mov ss:[rbp+0xffffffffffffffa0], 0xfffffffffffffffe
         // 140002016: mov ss:[rsp+0xb0], rbx
         // 14000201e: mov rbx, rdx
         // 140002021: mov rdi, rcx
         // 140002024: mov rax, ds:[rcx+0x20]
         // 140002028: mov ss:[rbp+0xffffffffffffffb0], rax
         // 14000202c: xor b4 esi, b4 esi
         // 14000202e: mov ss:[rbp+0xffffffffffffffb8], rsi
         // 140002032: xorps b16 xmm0, b16 xmm0
         // 140002035: movdqa b16 ss:[rbp+0xffffffffffffffc0], b16 xmm0
         // 14000203a: movdqa b16 xmm1, b16 cs:[0x140133470]
         // 140002042: movdqa b16 ss:[rbp+0xffffffffffffffd0], b16 xmm1
         // 140002047: mov b4 ss:[rbp+0xfffffffffffffff0], b4 0x2
         // 14000204e: mov ss:[rbp+0x20], rcx
         // 140002052: mov b4 ss:[rbp+0xffffffffffffffe0], b4 esi
         // 140002055: mov ss:[rbp+0xffffffffffffffe8], rsi
         // 140002059: lea rax, ss:[rbp+0xffffffffffffffb0]
         // 14000205d: mov ss:[rbp+0x28], rax
         // 140002061: mov rcx, ds:[rdx]
      [-]e8e7f4ffff4889030fb60880f92f7563
         // 140002064: call 0x140001550
         // 140002069: mov ds:[rbx], rax
         // 14000206c: movzx b4 ecx, b1 ds:[rax]
         // 14000206f: cmp b1 cl, b1 0x2f
         // 140002072: jnz 0x1400020d7
      [-]48ffc04889030fb60880f92a7526
         // 140002074: inc rax
         // 140002077: mov ds:[rbx], rax
         // 14000207a: movzx b4 ecx, b1 ds:[rax]
         // 14000207d: cmp b1 cl, b1 0x2a
         // 140002080: jnz 0x1400020a8
      [-]48ffc0488903
         // 140002082: inc rax
         // 140002085: mov ds:[rbx], rax
      [-]0fb60884c9743f
         // 140002088: movzx b4 ecx, b1 ds:[rax]
         // 14000208b: test b1 cl, b1 cl
         // 14000208d: jz 0x1400020ce
      [-]48ffc048890380f92a75ee
         // 14000208f: inc rax
         // 140002092: mov ds:[rbx], rax
         // 140002095: cmp b1 cl, b1 0x2a
         // 140002098: jnz 0x140002088
      [-]80382f75e9
         // 14000209a: cmp b1 ds:[rax], b1 0x2f
         // 14000209d: jnz 0x140002088
      [-]488d480148890bebbc
         // 14000209f: lea rcx, ds:[rax+0x1]
         // 1400020a3: mov ds:[rbx], rcx
         // 1400020a6: jmp 0x140002064
      [-]80f92f7521
         // 1400020a8: cmp b1 cl, b1 0x2f
         // 1400020ab: jnz 0x1400020ce
      [-]48ffc0488903
         // 1400020ad: inc rax
         // 1400020b0: mov ds:[rbx], rax
      [-]0fb610488bc884d274a7
         // 1400020b3: movzx b4 edx, b1 ds:[rax]
         // 1400020b6: mov rcx, rax
         // 1400020b9: test b1 dl, b1 dl
         // 1400020bb: jz 0x140002064
      [-]488d480148890b488bc180fa0a75e7
         // 1400020bd: lea rcx, ds:[rax+0x1]
         // 1400020c1: mov ds:[rbx], rcx
         // 1400020c4: mov rax, rcx
         // 1400020c7: cmp b1 dl, b1 0xa
         // 1400020ca: jnz 0x1400020b3
      [-]c745e0????????eb49
         // 1400020ce: mov b4 ss:[rbp+0xffffffffffffffe0], b4 0x11
         // 1400020d5: jmp 0x140002120
      [-]837de000754b
         // 1400020d7: cmp b4 ss:[rbp+0xffffffffffffffe0], b4 0x0
         // 1400020db: jnz 0x140002128
      [-]84c97509
         // 1400020dd: test b1 cl, b1 cl
         // 1400020df: jnz 0x1400020ea
      [-]c745e0????????eb36
         // 1400020e1: mov b4 ss:[rbp+0xffffffffffffffe0], b4 0x1
         // 1400020e8: jmp 0x140002120
      [-]4c8bc7488bd3488d4db0e887010000837de0007529
         // 1400020ea: mov r8, rdi
         // 1400020ed: mov rdx, rbx
         // 1400020f0: lea rcx, ss:[rbp+0xffffffffffffffb0]
         // 1400020f4: call 0x140002280
         // 1400020f9: cmp b4 ss:[rbp+0xffffffffffffffe0], b4 0x0
         // 1400020fd: jnz 0x140002128
      [-]488bd3488d4db0e8e5000000837de0007517
         // 1400020ff: mov rdx, rbx
         // 140002102: lea rcx, ss:[rbp+0xffffffffffffffb0]
         // 140002106: call 0x1400021f0
         // 14000210b: cmp b4 ss:[rbp+0xffffffffffffffe0], b4 0x0
         // 14000210f: jnz 0x140002128
      [-]488b03803800740f
         // 140002111: mov rax, ds:[rbx]
         // 140002114: cmp b1 ds:[rax], b1 0x0
         // 140002117: jz 0x140002128
      [-]c745e0????????
         // 140002119: mov b4 ss:[rbp+0xffffffffffffffe0], b4 0x2
      [-]482b4308488945e8
         // 140002120: sub rax, ds:[rbx+0x8]
         // 140002124: mov ss:[rbp+0xffffffffffffffe8], rax
      [-]488b45c0488945c80f2845e00f114750837f50007523
         // 140002128: mov rax, ss:[rbp+0xffffffffffffffc0]
         // 14000212c: mov ss:[rbp+0xffffffffffffffc8], rax
         // 140002130: movaps b16 xmm0, b16 ss:[rbp+0xffffffffffffffe0]
         // 140002134: movups b16 ds:[rdi+0x50], b16 xmm0
         // 140002138: cmp b4 ds:[rdi+0x50], b4 0x0
         // 14000213c: jnz 0x140002161
      [-]488b5f384883c3f048895f38483bfb7412
         // 14000213e: mov rbx, ds:[rdi+0x38]
         // 140002142: add rbx, 0xfffffffffffffff0
         // 140002146: mov ds:[rdi+0x38], rbx
         // 14000214a: cmp rdi, rbx
         // 14000214d: jz 0x140002161
      [-]488bcfe8f9f1ffff0f10030f11076689730e
         // 14000214f: mov rcx, rdi
         // 140002152: call _guard_check_icall_nop
         // 140002157: movups b16 xmm0, b16 ds:[rbx]
         // 14000215a: movups b16 ds:[rdi], b16 xmm0
         // 14000215d: mov b2 ds:[rbx+0xe], b2 si
      [-]488b4f3048894f38e852b50a0090488977304889773848897740488b4dc0e83cb50a00ba????????488b4db8e83ea00800488bc7488b9c24b00000004881c4800000005f5e5dc3
         // 140002161: mov rcx, ds:[rdi+0x30]
         // 140002165: mov ds:[rdi+0x38], rcx
         // 140002169: call free
         // 14000216e: nop 
         // 14000216f: mov ds:[rdi+0x30], rsi
         // 140002173: mov ds:[rdi+0x38], rsi
         // 140002177: mov ds:[rdi+0x40], rsi
         // 14000217b: mov rcx, ss:[rbp+0xffffffffffffffc0]
         // 14000217f: call free
         // 140002184: mov b4 edx, b4 0x1
         // 140002189: mov rcx, ss:[rbp+0xffffffffffffffb8]
         // 14000218d: call j_j_free
         // 140002192: mov rax, rdi
         // 140002195: mov rbx, ss:[rsp+0xb0]
         // 14000219d: add rsp, 0x80
         // 1400021a4: pop rdi
         // 1400021a5: pop rsi
         // 1400021a6: pop rbp
         // 1400021a7: retn 
      [-]40534883ec20488b19488b4b3048894b38e8fab40a0033c04889433048894338488943404883c4205bc3
         // 1400021b0: push rbx
         // 1400021b2: sub rsp, 0x20
         // 1400021b6: mov rbx, ds:[rcx]
         // 1400021b9: mov rcx, ds:[rbx+0x30]
         // 1400021bd: mov ds:[rbx+0x38], rcx
         // 1400021c1: call free
         // 1400021c6: xor b4 eax, b4 eax
         // 1400021c8: mov ds:[rbx+0x30], rax
         // 1400021cc: mov ds:[rbx+0x38], rax
         // 1400021d0: mov ds:[rbx+0x40], rax
         // 1400021d4: add rsp, 0x20
         // 1400021d8: pop rbx
         // 1400021d9: retn 
      [-]488b11488b421048894218c3
         // 1400021e0: mov rdx, ds:[rcx]
         // 1400021e3: mov rax, ds:[rdx+0x10]
         // 1400021e7: mov ds:[rdx+0x18], rax
         // 1400021eb: retn 
      [-]4883ec284c8bd14c8bca488b0a
         // 1400021f0: sub rsp, 0x28
         // 1400021f4: mov r10, rcx
         // 1400021f7: mov r9, rdx
         // 1400021fa: mov rcx, ds:[rdx]
      [-]e84ef3ffff49890180382f756e
         // 1400021fd: call 0x140001550
         // 140002202: mov ds:[r9], rax
         // 140002205: cmp b1 ds:[rax], b1 0x2f
         // 140002208: jnz 0x140002278
      [-]48ffc04989010fb60880f92a7528
         // 14000220a: inc rax
         // 14000220d: mov ds:[r9], rax
         // 140002210: movzx b4 ecx, b1 ds:[rax]
         // 140002213: cmp b1 cl, b1 0x2a
         // 140002216: jnz 0x140002240
      [-]48ffc04989016690
         // 140002218: inc rax
         // 14000221b: mov ds:[r9], rax
         // 14000221e: xchg b2 ax, b2 ax
      [-]0fb60884c97441
         // 140002220: movzx b4 ecx, b1 ds:[rax]
         // 140002223: test b1 cl, b1 cl
         // 140002225: jz 0x140002268
      [-]48ffc049890180f92a75ee
         // 140002227: inc rax
         // 14000222a: mov ds:[r9], rax
         // 14000222d: cmp b1 cl, b1 0x2a
         // 140002230: jnz 0x140002220
      [-]80382f75e9
         // 140002232: cmp b1 ds:[rax], b1 0x2f
         // 140002235: jnz 0x140002220
      [-]488d4801498909ebbd
         // 140002237: lea rcx, ds:[rax+0x1]
         // 14000223b: mov ds:[r9], rcx
         // 14000223e: jmp 0x1400021fd
      [-]80f92f7523
         // 140002240: cmp b1 cl, b1 0x2f
         // 140002243: jnz 0x140002268
      [-]48ffc0498901488bc86690
         // 140002245: inc rax
         // 140002248: mov ds:[r9], rax
         // 14000224b: mov rcx, rax
         // 14000224e: xchg b2 ax, b2 ax
      [-]0fb61084d274a6
         // 140002250: movzx b4 edx, b1 ds:[rax]
         // 140002253: test b1 dl, b1 dl
         // 140002255: jz 0x1400021fd
      [-]488d4801498909488bc180fa0a75ea
         // 140002257: lea rcx, ds:[rax+0x1]
         // 14000225b: mov ds:[r9], rcx
         // 14000225e: mov rax, rcx
         // 140002261: cmp b1 dl, b1 0xa
         // 140002264: jnz 0x140002250
      [-]492b41084989423841c74230????????
         // 140002268: sub rax, ds:[r9+0x8]
         // 14000226c: mov ds:[r10+0x38], rax
         // 140002270: mov b4 ds:[r10+0x30], b4 0x11
      [-]4883c428c3
         // 140002278: add rsp, 0x28
         // 14000227c: retn 
      [-]48895c2408574883ec20488bf9488bda488b0a0fbe0183c0de83f8590f8746010000
         // 140002280: mov ss:[rsp+0x8], rbx
         // 140002285: push rdi
         // 140002286: sub rsp, 0x20
         // 14000228a: mov rdi, rcx
         // 14000228d: mov rbx, rdx
         // 140002290: mov rcx, ds:[rdx]
         // 140002293: movsx b4 eax, b1 ds:[rcx]
         // 140002296: add b4 eax, b4 0xffffffffffffffde
         // 140002299: cmp b4 eax, b4 0x59
         // 14000229c: ja def_1400022BE
      [-]488d1557ddffff48980fb684021c240000448b8c82002400004c03ca41ffe1
         // 1400022a2: lea rdx, cs:[0x140000000]
         // 1400022a9: cdqe 
         // 1400022ab: movzx b4 eax, b1 ds:[rdx+rax+0x241c]
         // 1400022b3: mov b4 r9d, b4 ds:[rdx+rax*0x4]
         // 1400022bb: add r9, rdx
         // 1400022be: jmp r9
      [-]488d41014889038038757549
         // 1400022c1: lea rax, ds:[rcx+0x1]
         // 1400022c5: mov ds:[rbx], rax
         // 1400022c8: cmp b1 ds:[rax], b1 0x75
         // 1400022cb: jnz 0x140002316
      [-]48ffc048890380386c753e
         // 1400022cd: inc rax
         // 1400022d0: mov ds:[rbx], rax
         // 1400022d3: cmp b1 ds:[rax], b1 0x6c
         // 1400022d6: jnz 0x140002316
      [-]48ffc048890380386c7533
         // 1400022d8: inc rax
         // 1400022db: mov ds:[rbx], rax
         // 1400022de: cmp b1 ds:[rax], b1 0x6c
         // 1400022e1: jnz 0x140002316
      [-]48ffc0498bc8488903e87f160000
         // 1400022e3: inc rax
         // 1400022e6: mov rcx, r8
         // 1400022e9: mov ds:[rbx], rax
         // 1400022ec: call 0x140003970
      [-]84c00f85fa000000
         // 1400022f1: test b1 al, b1 al
         // 1400022f3: jnz 0x1400023f3
      [-]488b03482b4308c74730????????48894738488b5c24304883c4205fc3
         // 1400022f9: mov rax, ds:[rbx]
         // 1400022fc: sub rax, ds:[rbx+0x8]
         // 140002300: mov b4 ds:[rdi+0x30], b4 0x10
         // 140002307: mov ds:[rdi+0x38], rax
         // 14000230b: mov rbx, ss:[rsp+0x30]
         // 140002310: add rsp, 0x20
         // 140002314: pop rdi
         // 140002315: retn 
      [-]482b4308c74730????????48894738488b5c24304883c4205fc3
         // 140002316: sub rax, ds:[rbx+0x8]
         // 14000231a: mov b4 ds:[rdi+0x30], b4 0x3
         // 140002321: mov ds:[rdi+0x38], rax
         // 140002325: mov rbx, ss:[rsp+0x30]
         // 14000232a: add rsp, 0x20
         // 14000232e: pop rdi
         // 14000232f: retn 
      [-]488d410148890380387275da
         // 140002330: lea rax, ds:[rcx+0x1]
         // 140002334: mov ds:[rbx], rax
         // 140002337: cmp b1 ds:[rax], b1 0x72
         // 14000233a: jnz 0x140002316
      [-]48ffc048890380387575cf
         // 14000233c: inc rax
         // 14000233f: mov ds:[rbx], rax
         // 140002342: cmp b1 ds:[rax], b1 0x75
         // 140002345: jnz 0x140002316
      [-]48ffc048890380386575c4
         // 140002347: inc rax
         // 14000234a: mov ds:[rbx], rax
         // 14000234d: cmp b1 ds:[rax], b1 0x65
         // 140002350: jnz 0x140002316
      [-]48ffc0b201498bc8488903e8be150000eb8d
         // 140002352: inc rax
         // 140002355: mov b1 dl, b1 0x1
         // 140002357: mov rcx, r8
         // 14000235a: mov ds:[rbx], rax
         // 14000235d: call 0x140003920
         // 140002362: jmp 0x1400022f1
      [-]488d410148890380386175a6
         // 140002364: lea rax, ds:[rcx+0x1]
         // 140002368: mov ds:[rbx], rax
         // 14000236b: cmp b1 ds:[rax], b1 0x61
         // 14000236e: jnz 0x140002316
      [-]48ffc048890380386c759b
         // 140002370: inc rax
         // 140002373: mov ds:[rbx], rax
         // 140002376: cmp b1 ds:[rax], b1 0x6c
         // 140002379: jnz 0x140002316
      [-]48ffc04889038038737590
         // 14000237b: inc rax
         // 14000237e: mov ds:[rbx], rax
         // 140002381: cmp b1 ds:[rax], b1 0x73
         // 140002384: jnz 0x140002316
      [-]48ffc04889038038657585
         // 140002386: inc rax
         // 140002389: mov ds:[rbx], rax
         // 14000238c: cmp b1 ds:[rax], b1 0x65
         // 14000238f: jnz 0x140002316
      [-]48ffc033d2498bc8488903e87f150000e94bffffff
         // 140002391: inc rax
         // 140002394: xor b4 edx, b4 edx
         // 140002396: mov rcx, r8
         // 140002399: mov ds:[rbx], rax
         // 14000239c: call 0x140003920
         // 1400023a1: jmp 0x1400022f1
      [-]4533c9488bd3488bcf488b5c24304883c4205fe9c2000000
         // 1400023a6: xor b4 r9d, b4 r9d
         // 1400023a9: mov rdx, rbx
         // 1400023ac: mov rcx, rdi
         // 1400023af: mov rbx, ss:[rsp+0x30]
         // 1400023b4: add rsp, 0x20
         // 1400023b8: pop rdi
         // 1400023b9: jmp 0x140002480
      [-]488bd3488bcf488b5c24304883c4205fe99d050000
         // 1400023be: mov rdx, rbx
         // 1400023c1: mov rcx, rdi
         // 1400023c4: mov rbx, ss:[rsp+0x30]
         // 1400023c9: add rsp, 0x20
         // 1400023cd: pop rdi
         // 1400023ce: jmp 0x140002970
      [-]488bd3488bcf488b5c24304883c4205fe938090000
         // 1400023d3: mov rdx, rbx
         // 1400023d6: mov rcx, rdi
         // 1400023d9: mov rbx, ss:[rsp+0x30]
         // 1400023de: add rsp, 0x20
         // 1400023e2: pop rdi
         // 1400023e3: jmp 0x140002d20
      [-]488bd3488bcfe88d0b0000
         // 1400023e8: mov rdx, rbx
         // 1400023eb: mov rcx, rdi
         // 1400023ee: call 0x140002f80
      [-]488b5c24304883c4205fc3
         // 1400023f3: mov rbx, ss:[rsp+0x30]
         // 1400023f8: add rsp, 0x20
         // 1400023fc: pop rdi
         // 1400023fd: retn 
      [-]488bc4448848204c894018488950105556574154415541564157488d68a14881ec9000000048c745b7feffffff488958080f2970b80f2978a844
         // 140002480: mov rax, rsp
         // 140002483: mov b1 ds:[rax+0x20], b1 r9b
         // 140002487: mov ds:[rax+0x18], r8
         // 14000248b: mov ds:[rax+0x10], rdx
         // 14000248f: push rbp
         // 140002490: push rsi
         // 140002491: push rdi
         // 140002492: push r12
         // 140002494: push r13
         // 140002496: push r14
         // 140002498: push r15
         // 14000249a: lea rbp, ds:[rax+0xffffffffffffffa1]
         // 14000249e: sub rsp, 0x90
         // 1400024a5: mov ss:[rbp+0xffffffffffffffb7], 0xfffffffffffffffe
         // 1400024ad: mov ds:[rax+0x8], rbx
         // 1400024b1: movaps b16 ds:[rax+0xffffffffffffffb8], b16 xmm6
         // 1400024b5: movaps b16 ds:[rax+0xffffffffffffffa8], b16 xmm7
         // 1400024b9: movaps b16 ds:[rax+0xffffffffffffff98], b16 xmm8
         // 1400024be: movaps b16 ds:[rax+0xffffffffffffff88], b16 xmm9
         // 1400024c3: mov r13, rcx
         // 1400024c6: movups b16 xmm0, b16 ds:[rdx]
         // 1400024c9: movups b16 ss:[rbp+0xffffffffffffffcf], b16 xmm0
         // 1400024cd: mov ss:[rbp+0xffffffffffffffdf], rdx
         // 1400024d1: movq rbx, b16 xmm0
         // 1400024d6: inc rbx
         // 1400024d9: mov ss:[rbp+0xffffffffffffffcf], rbx
         // 1400024dd: mov rdi, rcx
         // 1400024e0: mov ss:[rbp+0xffffffffffffffbf], rcx
         // 1400024e4: xor b4 r14d, b4 r14d
         // 1400024e7: mov r12, ss:[rbp+0xffffffffffffffd7]

  }
  condition:
    all of them
}
