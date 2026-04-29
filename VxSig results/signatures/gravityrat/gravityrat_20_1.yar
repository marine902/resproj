rule gravityrat_20_1 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         e9db100000
         // 004011b0: jmp runtime_internal_atomic.Casuintptr
      [-]e9eb100000
         // 004011c0: jmp runtime_internal_atomic.Xadd
      [-]e9fb100000
         // 004011d0: jmp runtime_internal_atomic.Store
      [-]e9bb100000
         // 004011e0: jmp runtime_internal_atomic.Storeuintptr
      [-]488b4424104889442418c3
         // 00401d80: mov rax, ss:[rsp+0x10]
         // 00401d85: mov ss:[rsp+0x18], rax
         // 00401d8a: retn 
      [-]c644241801c3
         // 00401d90: mov b1 ss:[rsp+0x18], b1 0x1
         // 00401d95: retn 
      [-]65488b0c2528000000488b8900000000483b6110765f
         // 00401e80: mov rcx, gs:[0x28]
         // 00401e89: mov rcx, ds:[rcx+0x0]
         // 00401e90: cmp rsp, ds:[rcx+0x10]
         // 00401e94: jbe 0x401ef5
      [-]4883ec2848896c2420488d6c2420488b44243048890424488b4c243848894c2408e834110000488b442410488b4c24304883c11048890c24488944240848c74424100b000000e84f620000488b4424184889442440488b6c24204883c428c3
         // 00401e96: sub rsp, 0x28
         // 00401e9a: mov ss:[rsp+0x20], rbp
         // 00401e9f: lea rbp, ss:[rsp+0x20]
         // 00401ea4: mov rax, ss:[rsp+0x30]
         // 00401ea9: mov ss:[rsp], rax
         // 00401ead: mov rcx, ss:[rsp+0x38]
         // 00401eb2: mov ss:[rsp+0x8], rcx
         // 00401eb7: call runtime.strhash
         // 00401ebc: mov rax, ss:[rsp+0x10]
         // 00401ec1: mov rcx, ss:[rsp+0x30]
         // 00401ec6: add rcx, 0x10
         // 00401eca: mov ss:[rsp], rcx
         // 00401ece: mov ss:[rsp+0x8], rax
         // 00401ed3: mov ss:[rsp+0x10], 0xb
         // 00401edc: call runtime.memhash
         // 00401ee1: mov rax, ss:[rsp+0x18]
         // 00401ee6: mov ss:[rsp+0x40], rax
         // 00401eeb: mov rbp, ss:[rsp+0x20]
         // 00401ef0: add rsp, 0x28
         // 00401ef4: retn 
      [-]e8b6350500eb84
         // 00401ef5: call runtime.morestack_noctxt
         // 00401efa: jmp type..hash.internal_cpu.option
      [-]488b5c2408488b442410488b4c2418f0480fb10b0f94442420c3
         // 00402270: mov rbx, ss:[rsp+0x8]
         // 00402275: mov rax, ss:[rsp+0x10]
         // 0040227a: mov rcx, ss:[rsp+0x18]
         // 0040227f: lock cmpxchg ds:[rbx], rcx
         // 00402284: setz b1 ss:[rsp+0x20]
         // 00402289: retn 
      [-]e9dbffffff
         // 00402290: jmp runtime_internal_atomic.Cas64
      [-]e93b000000
         // 004022a0: jmp runtime_internal_atomic.Store64
      [-]488b5c24088b44241089c1f00fc10301c889442418c3
         // 004022b0: mov rbx, ss:[rsp+0x8]
         // 004022b5: mov b4 eax, b4 ss:[rsp+0x10]
         // 004022b9: mov b4 ecx, b4 eax
         // 004022bb: lock xadd b4 ds:[rbx], b4 eax
         // 004022bf: add b4 eax, b4 ecx
         // 004022c1: mov b4 ss:[rsp+0x18], b4 eax
         // 004022c5: retn 
      [-]488b5c24088b4424108703c3
         // 004022d0: mov rbx, ss:[rsp+0x8]
         // 004022d5: mov b4 eax, b4 ss:[rsp+0x10]
         // 004022d9: xchg b4 eax, b4 ds:[rbx]
         // 004022db: retn 
      [-]488b5c2408488b442410488703c3
         // 004022e0: mov rbx, ss:[rsp+0x8]
         // 004022e5: mov rax, ss:[rsp+0x10]
         // 004022ea: xchg rax, ds:[rbx]
         // 004022ed: retn 
      [-]488b4424104889442418c3
         // 00402e70: mov rax, ss:[rsp+0x10]
         // 00402e75: mov ss:[rsp+0x18], rax
         // 00402e7a: retn 
      [-]c644241801c3
         // 004036b0: mov b1 ss:[rsp+0x18], b1 0x1
         // 004036b5: retn 
      [-]65488b0c2528000000488b8900000000483b61180f863a020000
         // 00404810: mov rcx, gs:[0x28]
         // 00404819: mov rcx, ds:[rcx+0x0]
         // 00404820: cmp rsp, ds:[rcx+0x18]
         // 00404824: jbe 0x404a64
      [-]4883ec7048896c2468488d6c2468488b4424780fb64817f6c1800f85f5010000
         // 0040482a: sub rsp, 0x70
         // 0040482e: mov ss:[rsp+0x68], rbp
         // 00404833: lea rbp, ss:[rsp+0x68]
         // 00404838: mov rax, ss:[rsp+0x78]
         // 0040483d: movzx b4 ecx, b1 ds:[rax+0x17]
         // 00404841: test b1 cl, b1 0x80
         // 00404844: jnz 0x404a3f
      [-]488b5008488b9c24880000004839da0f86d6010000
         // 0040484a: mov rdx, ds:[rax+0x8]
         // 0040484e: mov rbx, ss:[rsp+0x88]
         // 00404856: cmp rdx, rbx
         // 00404859: jbe 0x404a35
      [-]4829da488bb424900000004839d6480f47f2f6c1400f848d010000
         // 0040485f: sub rdx, rbx
         // 00404862: mov rsi, ss:[rsp+0x90]
         // 0040486a: cmp rsi, rdx
         // 0040486d: cmova rsi, rdx
         // 00404871: test b1 cl, b1 0x40
         // 00404874: jz 0x404a07
      [-]83e11f80f9110f85ac000000
         // 0040487a: and b4 ecx, b4 0x1f
         // 0040487d: cmp b1 cl, b1 0x11
         // 00404880: jnz 0x404932
      [-]488b8c248000000031d2eb09
         // 00404886: mov rcx, ss:[rsp+0x80]
         // 0040488e: xor b4 edx, b4 edx
         // 00404890: jmp 0x40489b
      [-]48ffc24829fe4c89c3
         // 00404892: inc rdx
         // 00404895: sub rsi, rdi
         // 00404898: mov rbx, r8
      [-]483950400f8683000000
         // 0040489b: cmp ds:[rax+0x40], rdx
         // 0040489f: jbe 0x404928
      [-]488b783048391f772d
         // 004048a5: mov rdi, ds:[rax+0x30]
         // 004048a9: cmp ds:[rdi], rbx
         // 004048ac: ja 0x4048db
      [-]488b7830488b3f4839fb4989d8480f47df904989f94829df4929d84c01c94839fe77c1
         // 004048ae: mov rdi, ds:[rax+0x30]
         // 004048b2: mov rdi, ds:[rdi]
         // 004048b5: cmp rbx, rdi
         // 004048b8: mov r8, rbx
         // 004048bb: cmova rbx, rdi
         // 004048bf: nop 
         // 004048c0: mov r9, rdi
         // 004048c3: sub rdi, rbx
         // 004048c6: sub r8, rbx
         // 004048c9: add rcx, r9
         // 004048cc: cmp rsi, rdi
         // 004048cf: ja 0x404892
      [-]488b6c24684883c470c3
         // 004048d1: mov rbp, ss:[rsp+0x68]
         // 004048d6: add rsp, 0x70
         // 004048da: retn 
      [-]48895424304889b4249000000048894c245048895c242848893c2448894c240848895c24104889742418e806ffffff488b442478488b4c2450488b542430488b5c2428488bb42490000000eb86
         // 004048db: mov ss:[rsp+0x30], rdx
         // 004048e0: mov ss:[rsp+0x90], rsi
         // 004048e8: mov ss:[rsp+0x50], rcx
         // 004048ed: mov ss:[rsp+0x28], rbx
         // 004048f2: mov ss:[rsp], rdi
         // 004048f6: mov ss:[rsp+0x8], rcx
         // 004048fb: mov ss:[rsp+0x10], rbx
         // 00404900: mov ss:[rsp+0x18], rsi
         // 00404905: call runtime.cgoCheckUsingType
         // 0040490a: mov rax, ss:[rsp+0x78]
         // 0040490f: mov rcx, ss:[rsp+0x50]
         // 00404914: mov rdx, ss:[rsp+0x30]
         // 00404919: mov rbx, ss:[rsp+0x28]
         // 0040491e: mov rsi, ss:[rsp+0x90]
         // 00404926: jmp 0x4048ae
      [-]488b6c24684883c470c3
         // 00404928: mov rbp, ss:[rsp+0x68]
         // 0040492d: add rsp, 0x70
         // 00404931: retn 
      [-]80f9190f850e010000
         // 00404932: cmp b1 cl, b1 0x19
         // 00404935: jnz 0x404a49
      [-]488b4838488b40404885c07ee0
         // 0040493b: mov rcx, ds:[rax+0x38]
         // 0040493f: mov rax, ds:[rax+0x40]
         // 00404943: test rax, rax
         // 00404946: jle 0x404928
      [-]4889442440488b94248000000031ffeb0a
         // 00404948: mov ss:[rsp+0x40], rax
         // 0040494d: mov rdx, ss:[rsp+0x80]
         // 00404955: xor b4 edi, b4 edi
         // 00404957: jmp 0x404963
      [-]4883c1184889df4c89cb
         // 00404959: add rcx, 0x18
         // 0040495d: mov rdi, rbx
         // 00404960: mov rbx, r9
      [-]4c8b41084939187737
         // 00404963: mov r8, ds:[rcx+0x8]
         // 00404967: cmp ds:[r8], rbx
         // 0040496a: ja 0x4049a3
      [-]4d8b004c39c34989d9490f47d8904d89c24929d84929d94c01d24c39c6760e
         // 0040496c: mov r8, ds:[r8]
         // 0040496f: cmp rbx, r8
         // 00404972: mov r9, rbx
         // 00404975: cmova rbx, r8
         // 00404979: nop 
         // 0040497a: mov r10, r8
         // 0040497d: sub r8, rbx
         // 00404980: sub r9, rbx
         // 00404983: add rdx, r10
         // 00404986: cmp rsi, r8
         // 00404989: jbe 0x404999
      [-]488d5f014c29c64839c37cc2
         // 0040498b: lea rbx, ds:[rdi+0x1]
         // 0040498f: sub rsi, r8
         // 00404992: cmp rbx, rax
         // 00404995: jl 0x404959
      [-]488b6c24684883c470c3
         // 00404999: mov rbp, ss:[rsp+0x68]
         // 0040499e: add rsp, 0x70
         // 004049a2: retn 
      [-]48894c246048897c243848895c24204889b4249000000048895424484c894424584c890424488954240848895c24104889742418e834feffff488b442440488b4c2460488b542448488b5c2420488bb42490000000488b7c24384c8b442458e965ffffff
         // 004049a3: mov ss:[rsp+0x60], rcx
         // 004049a8: mov ss:[rsp+0x38], rdi
         // 004049ad: mov ss:[rsp+0x20], rbx
         // 004049b2: mov ss:[rsp+0x90], rsi
         // 004049ba: mov ss:[rsp+0x48], rdx
         // 004049bf: mov ss:[rsp+0x58], r8
         // 004049c4: mov ss:[rsp], r8
         // 004049c8: mov ss:[rsp+0x8], rdx
         // 004049cd: mov ss:[rsp+0x10], rbx
         // 004049d2: mov ss:[rsp+0x18], rsi
         // 004049d7: call runtime.cgoCheckUsingType
         // 004049dc: mov rax, ss:[rsp+0x40]
         // 004049e1: mov rcx, ss:[rsp+0x60]
         // 004049e6: mov rdx, ss:[rsp+0x48]
         // 004049eb: mov rbx, ss:[rsp+0x20]
         // 004049f0: mov rsi, ss:[rsp+0x90]
         // 004049f8: mov rdi, ss:[rsp+0x38]
         // 004049fd: mov r8, ss:[rsp+0x58]
         // 00404a02: jmp 0x40496c
      [-]488b4020488b8c248000000048890c24488944240848895c24104889742418e8f5fcffff488b6c24684883c470c3
         // 00404a07: mov rax, ds:[rax+0x20]
         // 00404a0b: mov rcx, ss:[rsp+0x80]
         // 00404a13: mov ss:[rsp], rcx
         // 00404a17: mov ss:[rsp+0x8], rax
         // 00404a1c: mov ss:[rsp+0x10], rbx
         // 00404a21: mov ss:[rsp+0x18], rsi
         // 00404a26: call runtime.cgoCheckBits
         // 00404a2b: mov rbp, ss:[rsp+0x68]
         // 00404a30: add rsp, 0x70
         // 00404a34: retn 
      [-]488b6c24684883c470c3
         // 00404a35: mov rbp, ss:[rsp+0x68]
         // 00404a3a: add rsp, 0x70
         // 00404a3e: retn 
      [-]488b6c24684883c470c3
         // 00404a3f: mov rbp, ss:[rsp+0x68]
         // 00404a44: add rsp, 0x70
         // 00404a48: retn 
      [-]488d052c3c2b004889042448c74424080c000000e89e9702000f0b
         // 00404a49: lea rax, cs:[0x6b867c]
         // 00404a50: mov ss:[rsp], rax
         // 00404a54: mov ss:[rsp+0x8], 0xc
         // 00404a5d: call runtime.throw
         // 00404a62: ud2 
      [-]e8e7f70300
         // 00404a64: call runtime.morestackc
      [-]e9a2fdffff
         // 00404a69: jmp runtime.cgoCheckUsingType
      [-]f20f10442408f20f11442410c3
         // 00408120: movsd b16 xmm0, ss:[rsp+0x8]
         // 00408126: movsd ss:[rsp+0x10], b16 xmm0
         // 0040812c: retn 
      [-]65488b0c2528000000488b8900000000483b61180f8605030000
         // 0040c5d0: mov rcx, gs:[0x28]
         // 0040c5d9: mov rcx, ds:[rcx+0x0]
         // 0040c5e0: cmp rsp, ds:[rcx+0x18]
         // 0040c5e4: jbe 0x40c8ef
      [-]4883ec4848896c2440488d6c2440488b4424504885c00f84ce020000
         // 0040c5ea: sub rsp, 0x48
         // 0040c5ee: mov ss:[rsp+0x40], rbp
         // 0040c5f3: lea rbp, ss:[rsp+0x40]
         // 0040c5f8: mov rax, ss:[rsp+0x50]
         // 0040c5fd: test rax, rax
         // 0040c600: jz 0x40c8d4
      [-]488b4c24584885c90f8465020000
         // 0040c606: mov rcx, ss:[rsp+0x58]
         // 0040c60b: test rcx, rcx
         // 0040c60e: jz 0x40c879
      [-]488d51ff4885d10f8598020000
         // 0040c614: lea rdx, ds:[rcx+0xffffffffffffffff]
         // 0040c618: test rcx, rdx
         // 0040c61b: jnz 0x40c8b9
      [-]4881f9002000000f8770020000
         // 0040c621: cmp rcx, 0x2000
         // 0040c628: ja 0x40c89e
      [-]483d000001000f8313020000
         // 0040c62e: cmp rax, 0x10000
         // 0040c634: jnb 0x40c84d
      [-]48894c241865488b142528000000488b9200000000488b5a3090ff83????????488b523048895424284885d20f84b6010000
         // 0040c63a: mov ss:[rsp+0x18], rcx
         // 0040c63f: mov rdx, gs:[0x28]
         // 0040c648: mov rdx, ds:[rdx+0x0]
         // 0040c64f: mov rbx, ds:[rdx+0x30]
         // 0040c653: nop 
         // 0040c654: inc b4 ds:[rbx+0xd8]
         // 0040c65a: mov rdx, ds:[rdx+0x30]
         // 0040c65e: mov ss:[rsp+0x28], rdx
         // 0040c663: test rdx, rdx
         // 0040c666: jz 0x40c822
      [-]488b9aa00000004885db0f84a6010000
         // 0040c66c: mov rbx, ds:[rdx+0xa0]
         // 0040c673: test rbx, rbx
         // 0040c676: jz 0x40c822
      [-]84034881c33812000090
         // 0040c67c: test b1 ds:[rbx], b1 al
         // 0040c67e: add rbx, 0x1238
         // 0040c685: nop 
      [-]48895c242090488b7308488d3431488d76ff48ffc948f7d14821f148894b084801c14881f9000004000f865b010000
         // 0040c686: mov ss:[rsp+0x20], rbx
         // 0040c68b: nop 
         // 0040c68c: mov rsi, ds:[rbx+0x8]
         // 0040c690: lea rsi, ds:[rcx+rsi]
         // 0040c694: lea rsi, ds:[rsi+0xffffffffffffffff]
         // 0040c698: dec rcx
         // 0040c69b: not rcx
         // 0040c69e: and rcx, rsi
         // 0040c6a1: mov ds:[rbx+0x8], rcx
         // 0040c6a5: add rcx, rax
         // 0040c6a8: cmp rcx, 0x40000
         // 0040c6af: jbe 0x40c810
      [-]48c7042400000400488d053cd05a004889442408e8d2ae0000488b4424104889442438488b4c2420488901488339007505
         // 0040c6b5: mov ss:[rsp], 0x40000
         // 0040c6bd: lea rax, cs:[0x9b9700]
         // 0040c6c4: mov ss:[rsp+0x8], rax
         // 0040c6c9: call runtime.sysAlloc
         // 0040c6ce: mov rax, ss:[rsp+0x10]
         // 0040c6d3: mov ss:[rsp+0x38], rax
         // 0040c6d8: mov rcx, ss:[rsp+0x20]
         // 0040c6dd: mov ds:[rcx], rax
         // 0040c6e0: cmp ds:[rcx], 0x0
         // 0040c6e4: jnz 0x40c6eb
      [-]e903010000
         // 0040c6e6: jmp 0x40c7ee
      [-]488d05b3ff58004839c10f8585000000
         // 0040c7ee: lea rax, cs:[0x99c7a8]
         // 0040c7f5: cmp rcx, rax
         // 0040c7f8: jnz 0x40c883
      [-]488d059bff580048890424e882d8ffffeb73
         // 0040c7fe: lea rax, cs:[0x99c7a0]
         // 0040c805: mov ss:[rsp], rax
         // 0040c809: call runtime.unlock
         // 0040c80e: jmp 0x40c883
      [-]48833b000f849bfeffff
         // 0040c810: cmp ds:[rbx], 0x0
         // 0040c814: jz 0x40c6b5
      [-]4889d9e9f9feffff
         // 0040c81a: mov rcx, rbx
         // 0040c81d: jmp 0x40c71b
      [-]488d0577ff580048890424e86ed6ffff488b442450488b4c2418488b542428488d1d60ff5800e939feffff
         // 0040c822: lea rax, cs:[0x99c7a0]
         // 0040c829: mov ss:[rsp], rax
         // 0040c82d: call runtime.lock
         // 0040c832: mov rax, ss:[rsp+0x50]
         // 0040c837: mov rcx, ss:[rsp+0x18]
         // 0040c83c: mov rdx, ss:[rsp+0x28]
         // 0040c841: lea rbx, cs:[0x99c7a8]
         // 0040c848: jmp 0x40c686
      [-]48890424488b4424604889442408e840ad0000488b44241048894424384889442468488b6c24404883c448c3
         // 0040c84d: mov ss:[rsp], rax
         // 0040c851: mov rax, ss:[rsp+0x60]
         // 0040c856: mov ss:[rsp+0x8], rax
         // 0040c85b: call runtime.sysAlloc
         // 0040c860: mov rax, ss:[rsp+0x10]
         // 0040c865: mov ss:[rsp+0x38], rax
         // 0040c86a: mov ss:[rsp+0x68], rax
         // 0040c86f: mov rbp, ss:[rsp+0x40]
         // 0040c874: add rsp, 0x48
         // 0040c878: retn 
      [-]b9????????e9abfdffff
         // 0040c879: mov b4 ecx, b4 0x8
         // 0040c87e: jmp 0x40c62e
      [-]488d0550332b004889042448c74424081f000000e8641902000f0b
         // 0040c883: lea rax, cs:[0x6bfbda]
         // 0040c88a: mov ss:[rsp], rax
         // 0040c88e: mov ss:[rsp+0x8], 0x1f
         // 0040c897: call runtime.throw
         // 0040c89c: ud2 
      [-]488d0529492b004889042448c744240823000000e8491902000f0b
         // 0040c89e: lea rax, cs:[0x6c11ce]
         // 0040c8a5: mov ss:[rsp], rax
         // 0040c8a9: mov ss:[rsp+0x8], 0x23
         // 0040c8b2: call runtime.throw
         // 0040c8b7: ud2 
      [-]488d05356b2b004889042448c74424082a000000e82e1902000f0b
         // 0040c8b9: lea rax, cs:[0x6c33f5]
         // 0040c8c0: mov ss:[rsp], rax
         // 0040c8c4: mov ss:[rsp+0x8], 0x2a
         // 0040c8cd: call runtime.throw
         // 0040c8d2: ud2 
      [-]488d0513152b004889042448c74424081a000000e8131902000f0b
         // 0040c8d4: lea rax, cs:[0x6bddee]
         // 0040c8db: mov ss:[rsp], rax
         // 0040c8df: mov ss:[rsp+0x8], 0x1a
         // 0040c8e8: call runtime.throw
         // 0040c8ed: ud2 
      [-]e85c790300
         // 0040c8ef: call runtime.morestackc
      [-]e9d7fcffff
         // 0040c8f4: jmp runtime.persistentalloc1
      [-]488b442408488b004889442410c3
         // 0040f860: mov rax, ss:[rsp+0x8]
         // 0040f865: mov rax, ds:[rax]
         // 0040f868: mov ss:[rsp+0x10], rax
         // 0040f86d: retn 
      [-]488b442408488b40084889442410c3
         // 0040f870: mov rax, ss:[rsp+0x8]
         // 0040f875: mov rax, ds:[rax+0x8]
         // 0040f879: mov ss:[rsp+0x10], rax
         // 0040f87e: retn 
      [-]65488b0c2528000000488b8900000000483b61180f8631030000
         // 0041e420: mov rcx, gs:[0x28]
         // 0041e429: mov rcx, ds:[rcx+0x0]
         // 0041e430: cmp rsp, ds:[rcx+0x18]
         // 0041e434: jbe 0x41e76b
      [-]4883ec4848896c2440488d6c2440488b4c24508401488db988000000833da3935900000f8500020000
         // 0041e43a: sub rsp, 0x48
         // 0041e43e: mov ss:[rsp+0x40], rbp
         // 0041e443: lea rbp, ss:[rsp+0x40]
         // 0041e448: mov rcx, ss:[rsp+0x50]
         // 0041e44d: test b1 ds:[rcx], b1 al
         // 0041e44f: lea rdi, ds:[rcx+0x88]
         // 0041e456: cmp b4 cs:[0x9b7800], b4 0x0
         // 0041e45d: jnz 0x41e663
      [-]48c7818800000000000000
         // 0041e463: mov ds:[rcx+0x88], 0x0
      [-]8b05b090590085c07515
         // 0041e46e: mov b4 eax, b4 cs:[0x9b7524]
         // 0041e474: test b4 eax, b4 eax
         // 0041e476: jnz 0x41e48d
      [-]48c7817001000000000000488b6c24404883c448c3
         // 0041e478: mov ds:[rcx+0x170], 0x0
         // 0041e483: mov rbp, ss:[rsp+0x40]
         // 0041e488: add rsp, 0x48
         // 0041e48c: retn 
      [-]48897c2438e8f9aa0300488b0424b9????????488d15b9ee5700f00fc10affc98b1d9dee570039d90f8432020000
         // 0041e48d: mov ss:[rsp+0x38], rdi
         // 0041e492: call runtime.nanotime
         // 0041e497: mov rax, ss:[rsp]
         // 0041e49b: mov b4 ecx, b4 0xffffffffffffffff
         // 0041e4a0: lea rdx, cs:[0x99d360]
         // 0041e4a7: lock xadd b4 ds:[rdx], b4 ecx
         // 0041e4ab: dec b4 ecx
         // 0041e4ad: mov b4 ebx, b4 cs:[0x99d350]
         // 0041e4b3: cmp b4 ecx, b4 ebx
         // 0041e4b5: jz 0x41e6ed
      [-]4889442430488b4424504889042448b9020000000400000048894c2408e8d3340100488b442450c680b00000000165488b0c2528000000488b8900000000488b4930488b91a000000084028401488d8a701200009048890c24488b4c245848894c2408e8bd120000488b4424104889442428488b4c245048890c2448ba04000000020000004889542408e866340100488b4424280f57c0f2480f2ac0f20f5905a9975900f2480f2cc0488b4c24504803817001000048ffc048898170010000b8????????488d15daed5700f00fc102ffc08b15beed570039d00f87d5000000
         // 0041e4bb: mov ss:[rsp+0x30], rax
         // 0041e4c0: mov rax, ss:[rsp+0x50]
         // 0041e4c5: mov ss:[rsp], rax
         // 0041e4c9: mov rcx, 0x400000002
         // 0041e4d3: mov ss:[rsp+0x8], rcx
         // 0041e4d8: call runtime.casgstatus
         // 0041e4dd: mov rax, ss:[rsp+0x50]
         // 0041e4e2: mov b1 ds:[rax+0xb0], b1 0x1
         // 0041e4e9: mov rcx, gs:[0x28]
         // 0041e4f2: mov rcx, ds:[rcx+0x0]
         // 0041e4f9: mov rcx, ds:[rcx+0x30]
         // 0041e4fd: mov rdx, ds:[rcx+0xa0]
         // 0041e504: test b1 ds:[rdx], b1 al
         // 0041e506: test b1 ds:[rcx], b1 al
         // 0041e508: lea rcx, ds:[rdx+0x1270]
         // 0041e50f: nop 
         // 0041e510: mov ss:[rsp], rcx
         // 0041e514: mov rcx, ss:[rsp+0x58]
         // 0041e519: mov ss:[rsp+0x8], rcx
         // 0041e51e: call runtime.gcDrainN
         // 0041e523: mov rax, ss:[rsp+0x10]
         // 0041e528: mov ss:[rsp+0x28], rax
         // 0041e52d: mov rcx, ss:[rsp+0x50]
         // 0041e532: mov ss:[rsp], rcx
         // 0041e536: mov rdx, 0x200000004
         // 0041e540: mov ss:[rsp+0x8], rdx
         // 0041e545: call runtime.casgstatus
         // 0041e54a: mov rax, ss:[rsp+0x28]
         // 0041e54f: xorps b16 xmm0, b16 xmm0
         // 0041e552: cvtsi2sd b16 xmm0, rax
         // 0041e557: mulsd b16 xmm0, cs:[0x9b7d08]
         // 0041e55f: cvttsd2si rax, b16 xmm0
         // 0041e564: mov rcx, ss:[rsp+0x50]
         // 0041e569: add rax, ds:[rcx+0x170]
         // 0041e570: inc rax
         // 0041e573: mov ds:[rcx+0x170], rax
         // 0041e57a: mov b4 eax, b4 0x1
         // 0041e57f: lea rdx, cs:[0x99d360]
         // 0041e586: lock xadd b4 ds:[rdx], b4 eax
         // 0041e58a: inc b4 eax
         // 0041e58c: mov b4 edx, b4 cs:[0x99d350]
         // 0041e592: cmp b4 eax, b4 edx
         // 0041e594: ja 0x41e66f
      [-]0f85bc000000
         // 0041e59a: jnz 0x41e65c
      [-]9090488b1517ed57004885d20f85a0000000
         // 0041e5a0: nop 
         // 0041e5a1: nop 
         // 0041e5a2: mov rdx, cs:[0x99d2c0]
         // 0041e5a9: test rdx, rdx
         // 0041e5ac: jnz 0x41e652
      [-]8b1594ed570039158aed57000f8387000000
         // 0041e5b2: mov b4 edx, b4 cs:[0x99d34c]
         // 0041e5b8: cmp b4 cs:[0x99d348], b4 edx
         // 0041e5be: jnb 0x41e64b
      [-]b8????????
         // 0041e5c4: mov b4 eax, b4 0x1
      [-]84c07410
         // 0041e5cc: test b1 al, b1 al
         // 0041e5ce: jz 0x41e5e0
      [-]833d29925900007563
         // 0041e5d0: cmp b4 cs:[0x9b7800], b4 0x0
         // 0041e5d7: jnz 0x41e63c
      [-]48898988000000
         // 0041e5d9: mov ds:[rcx+0x88], rcx
      [-]e8aba90300488b442450488b4030488b80a00000008400488b0c24488b5424304829d19048038848120000488988481200004881f9881300007e17
         // 0041e5e0: call runtime.nanotime
         // 0041e5e5: mov rax, ss:[rsp+0x50]
         // 0041e5ea: mov rax, ds:[rax+0x30]
         // 0041e5ee: mov rax, ds:[rax+0xa0]
         // 0041e5f5: test b1 ds:[rax], b1 al
         // 0041e5f7: mov rcx, ss:[rsp]
         // 0041e5fb: mov rdx, ss:[rsp+0x30]
         // 0041e600: sub rcx, rdx
         // 0041e603: nop 
         // 0041e604: add rcx, ds:[rax+0x1248]
         // 0041e60b: mov ds:[rax+0x1248], rcx
         // 0041e612: cmp rcx, 0x1388
         // 0041e619: jle 0x41e632
      [-]488d15ae965900f0480fc10a48c7804812000000000000
         // 0041e61b: lea rdx, cs:[0x9b7cd0]
         // 0041e622: lock xadd ds:[rdx], rcx
         // 0041e627: mov ds:[rax+0x1248], 0x0
      [-]488b6c24404883c448c3
         // 0041e632: mov rbp, ss:[rsp+0x40]
         // 0041e637: add rsp, 0x48
         // 0041e63b: retn 
      [-]488b7c24384889c8e8f78c0300eb95
         // 0041e63c: mov rdi, ss:[rsp+0x38]
         // 0041e641: mov rax, rcx
         // 0041e644: call runtime.gcWriteBarrier
         // 0041e649: jmp 0x41e5e0
      [-]31c0e977ffffff
         // 0041e64b: xor b4 eax, b4 eax
         // 0041e64d: jmp 0x41e5c9
      [-]b8????????e96dffffff
         // 0041e652: mov b4 eax, b4 0x1
         // 0041e657: jmp 0x41e5c9
      [-]31c0e969ffffff
         // 0041e65c: xor b4 eax, b4 eax
         // 0041e65e: jmp 0x41e5cc
      [-]31c0e8d68c0300e9fffdffff
         // 0041e663: xor b4 eax, b4 eax
         // 0041e665: call runtime.gcWriteBarrier
         // 0041e66a: jmp 0x41e46e
      [-]8944241c89542424e894050100488d0586d529004889042448c744240815000000e81b0f01008b44241c48890424e83e0c0100488d056aa229004889042448c74424080d000000e8f50e01008b44242448890424e8180c0100e8f3070100e8ce050100488d053ee529004889042448c744240817000000e815fb00000f0b
         // 0041e66f: mov b4 ss:[rsp+0x1c], b4 eax
         // 0041e673: mov b4 ss:[rsp+0x24], b4 edx
         // 0041e677: call runtime.printlock
         // 0041e67c: lea rax, cs:[0x6bbc09]
         // 0041e683: mov ss:[rsp], rax
         // 0041e687: mov ss:[rsp+0x8], 0x15
         // 0041e690: call runtime.printstring
         // 0041e695: mov b4 eax, b4 ss:[rsp+0x1c]
         // 0041e699: mov ss:[rsp], rax
         // 0041e69d: call runtime.printuint
         // 0041e6a2: lea rax, cs:[0x6b8913]
         // 0041e6a9: mov ss:[rsp], rax
         // 0041e6ad: mov ss:[rsp+0x8], 0xd
         // 0041e6b6: call runtime.printstring
         // 0041e6bb: mov b4 eax, b4 ss:[rsp+0x24]
         // 0041e6bf: mov ss:[rsp], rax
         // 0041e6c3: call runtime.printuint
         // 0041e6c8: call runtime.printnl
         // 0041e6cd: call runtime.printunlock
         // 0041e6d2: lea rax, cs:[0x6bcc17]
         // 0041e6d9: mov ss:[rsp], rax
         // 0041e6dd: mov ss:[rsp+0x8], 0x17
         // 0041e6e6: call runtime.throw
         // 0041e6eb: ud2 
      [-]894c2420895c2424e816050100488d0570db29004889042448c744240816000000e89d0e01008b44242048890424e8c00b0100488d05eca129004889042448c74424080d000000e8770e01008b44242448890424e89a0b0100e875070100e850050100488d05aac629004889042448c744240813000000e897fa00000f0b
         // 0041e6ed: mov b4 ss:[rsp+0x20], b4 ecx
         // 0041e6f1: mov b4 ss:[rsp+0x24], b4 ebx
         // 0041e6f5: call runtime.printlock
         // 0041e6fa: lea rax, cs:[0x6bc271]
         // 0041e701: mov ss:[rsp], rax
         // 0041e705: mov ss:[rsp+0x8], 0x16
         // 0041e70e: call runtime.printstring
         // 0041e713: mov b4 eax, b4 ss:[rsp+0x20]
         // 0041e717: mov ss:[rsp], rax
         // 0041e71b: call runtime.printuint
         // 0041e720: lea rax, cs:[0x6b8913]
         // 0041e727: mov ss:[rsp], rax
         // 0041e72b: mov ss:[rsp+0x8], 0xd
         // 0041e734: call runtime.printstring
         // 0041e739: mov b4 eax, b4 ss:[rsp+0x24]
         // 0041e73d: mov ss:[rsp], rax
         // 0041e741: call runtime.printuint
         // 0041e746: call runtime.printnl
         // 0041e74b: call runtime.printunlock
         // 0041e750: lea rax, cs:[0x6bae01]
         // 0041e757: mov ss:[rsp], rax
         // 0041e75b: mov ss:[rsp+0x8], 0x13
         // 0041e764: call runtime.throw
         // 0041e769: ud2 
      [-]e8e05a0200
         // 0041e76b: call runtime.morestackc
      [-]e9abfcffff
         // 0041e770: jmp runtime.gcAssistAlloc1
      [-]65488b0c2528000000488b8900000000488d842490feffff483b41180f86a0060000
         // 0041eaf0: mov rcx, gs:[0x28]
         // 0041eaf9: mov rcx, ds:[rcx+0x0]
         // 0041eb00: lea rax, ss:[rsp+0xfffffffffffffe90]
         // 0041eb08: cmp rax, ds:[rcx+0x18]
         // 0041eb0c: jbe 0x41f1b2
      [-]4881ecf00100004889ac24e8010000488dac24e8010000488b8424f801000080b8b5000000000f8500040000
         // 0041eb12: sub rsp, 0x1f0
         // 0041eb19: mov ss:[rsp+0x1e8], rbp
         // 0041eb21: lea rbp, ss:[rsp+0x1e8]
         // 0041eb29: mov rax, ss:[rsp+0x1f8]
         // 0041eb31: cmp b1 ds:[rax+0xb5], b1 0x0
         // 0041eb38: jnz 0x41ef3e
      [-]908b88????????0fbae10c0f83a9050000
         // 0041eb3e: nop 
         // 0041eb3f: mov b4 ecx, b4 ds:[rax+0x90]
         // 0041eb45: bt b4 ecx, b1 0xc
         // 0041eb49: jnb 0x41f0f8
      [-]908b88????????0fbaf10c83f9020f87b6030000
         // 0041eb4f: nop 
         // 0041eb50: mov b4 ecx, b4 ds:[rax+0x90]
         // 0041eb56: btr b4 ecx, b1 0xc
         // 0041eb5a: cmp b4 ecx, b4 0x2
         // 0041eb5d: ja 0x41ef19
      [-]83f9010f85a2030000
         // 0041eb63: cmp b4 ecx, b4 0x1
         // 0041eb66: jnz 0x41ef0e
      [-]65488b0c2528000000488b89000000004839c80f84e4030000
         // 0041eb6c: mov rcx, gs:[0x28]
         // 0041eb75: mov rcx, ds:[rcx+0x0]
         // 0041eb7c: cmp rax, rcx
         // 0041eb7f: jz 0x41ef69
      [-]48890424e8b24a0200488dbc24a80000000f57c048896c24f0488d6c24f0e829920300488b6d00488b8424f8010000488b4808488b1048899424a801000048898c24b001000048837850000f85ec020000
         // 0041eb85: mov ss:[rsp], rax
         // 0041eb89: call runtime.shrinkstack
         // 0041eb8e: lea rdi, ss:[rsp+0xa8]
         // 0041eb96: xorps b16 xmm0, b16 xmm0
         // 0041eb99: mov ss:[rsp+0xfffffffffffffff0], rbp
         // 0041eb9e: lea rbp, ss:[rsp+0xfffffffffffffff0]
         // 0041eba3: call 0x457dd1
         // 0041eba8: mov rbp, ss:[rbp+0x0]
         // 0041ebac: mov rax, ss:[rsp+0x1f8]
         // 0041ebb4: mov rcx, ds:[rax+0x8]
         // 0041ebb8: mov rdx, ds:[rax]
         // 0041ebbb: mov ss:[rsp+0x1a8], rdx
         // 0041ebc3: mov ss:[rsp+0x1b0], rcx
         // 0041ebcb: cmp ds:[rax+0x50], 0x0
         // 0041ebd0: jnz 0x41eec2
      [-]0f1184249000000048c78424a000000000000000488d0d6f42030048898c2490000000488d8c24a800000048898c2498000000488b94240002000048899424a000000048c70424ffffffff48c7442408ffffffff48c74424100000000048894424180f1144242048c7442430ffffff7f488d9c249000000048895c24380f11442440e893c90200488b8424f801000048890424488d8c249000000048894c240848c744241000000000e83cc70200488b8424f8010000488b4828eb04
         // 0041ebd6: movups b16 ss:[rsp+0x90], b16 xmm0
         // 0041ebde: mov ss:[rsp+0xa0], 0x0
         // 0041ebea: lea rcx, cs:[runtime.scanstack.func1]
         // 0041ebf1: mov ss:[rsp+0x90], rcx
         // 0041ebf9: lea rcx, ss:[rsp+0xa8]
         // 0041ec01: mov ss:[rsp+0x98], rcx
         // 0041ec09: mov rdx, ss:[rsp+0x200]
         // 0041ec11: mov ss:[rsp+0xa0], rdx
         // 0041ec19: mov ss:[rsp], 0xffffffffffffffff
         // 0041ec21: mov ss:[rsp+0x8], 0xffffffffffffffff
         // 0041ec2a: mov ss:[rsp+0x10], 0x0
         // 0041ec33: mov ss:[rsp+0x18], rax
         // 0041ec38: movups b16 ss:[rsp+0x20], b16 xmm0
         // 0041ec3d: mov ss:[rsp+0x30], 0x7fffffff
         // 0041ec46: lea rbx, ss:[rsp+0x90]
         // 0041ec4e: mov ss:[rsp+0x38], rbx
         // 0041ec53: movups b16 ss:[rsp+0x40], b16 xmm0
         // 0041ec58: call runtime.gentraceback
         // 0041ec5d: mov rax, ss:[rsp+0x1f8]
         // 0041ec65: mov ss:[rsp], rax
         // 0041ec69: lea rcx, ss:[rsp+0x90]
         // 0041ec71: mov ss:[rsp+0x8], rcx
         // 0041ec76: mov ss:[rsp+0x10], 0x0
         // 0041ec7f: call runtime.tracebackdefers
         // 0041ec84: mov rax, ss:[rsp+0x1f8]
         // 0041ec8c: mov rcx, ds:[rax+0x28]
         // 0041ec90: jmp 0x41ec96
      [-]488b4928
         // 0041ec92: mov rcx, ds:[rcx+0x28]
      [-]4885c9745d
         // 0041ec96: test rcx, rcx
         // 0041ec99: jz 0x41ecf8
      [-]488379180074f0
         // 0041ec9b: cmp ds:[rcx+0x18], 0x0
         // 0041eca0: jz 0x41ec92
      [-]48898c2488000000488d41184889042448c744240808000000488d053f8454004889442410488b8424000200004889442418488d9424a80000004889542420e83a0d0000488b8424f8010000488b8c2488000000eb9a
         // 0041eca2: mov ss:[rsp+0x88], rcx
         // 0041ecaa: lea rax, ds:[rcx+0x18]
         // 0041ecae: mov ss:[rsp], rax
         // 0041ecb2: mov ss:[rsp+0x8], 0x8
         // 0041ecbb: lea rax, cs:[0x967101]
         // 0041ecc2: mov ss:[rsp+0x10], rax
         // 0041ecc7: mov rax, ss:[rsp+0x200]
         // 0041eccf: mov ss:[rsp+0x18], rax
         // 0041ecd4: lea rdx, ss:[rsp+0xa8]
         // 0041ecdc: mov ss:[rsp+0x20], rdx
         // 0041ece1: call runtime.scanblock
         // 0041ece6: mov rax, ss:[rsp+0x1f8]
         // 0041ecee: mov rcx, ss:[rsp+0x88]
         // 0041ecf6: jmp 0x41ec92
      [-]488b48204885c90f85a2010000
         // 0041ecf8: mov rcx, ds:[rax+0x20]
         // 0041ecfc: test rcx, rcx
         // 0041ecff: jnz 0x41eea7
      [-]90488b8424c8010000488b8c24d80100004889042448c74424080000000048894c2410e883250000488b44241848898424e0010000
         // 0041ed05: nop 
         // 0041ed06: mov rax, ss:[rsp+0x1c8]
         // 0041ed0e: mov rcx, ss:[rsp+0x1d8]
         // 0041ed16: mov ss:[rsp], rax
         // 0041ed1a: mov ss:[rsp+0x8], 0x0
         // 0041ed23: mov ss:[rsp+0x10], rcx
         // 0041ed28: call runtime.binarySearchTree
         // 0041ed2d: mov rax, ss:[rsp+0x18]
         // 0041ed32: mov ss:[rsp+0x1e0], rax
      [-]488d8424a800000048890424e8e522000048837c2408000f8406010000
         // 0041ed3a: lea rax, ss:[rsp+0xa8]
         // 0041ed42: mov ss:[rsp], rax
         // 0041ed46: call runtime._ptr_stackScanState.getPtr
         // 0041ed4b: cmp ss:[rsp+0x8], 0x0
         // 0041ed51: jz 0x41ee5d
      [-]488d8424a800000048890424e8b8260000488b4424104885c074c8
         // 0041ed57: lea rax, ss:[rsp+0xa8]
         // 0041ed5f: mov ss:[rsp], rax
         // 0041ed63: call runtime._ptr_stackScanState.findObject
         // 0041ed68: mov rax, ss:[rsp+0x10]
         // 0041ed6d: test rax, rax
         // 0041ed70: jz 0x41ed3a
      [-]488b48084885c974bf
         // 0041ed72: mov rcx, ds:[rax+0x8]
         // 0041ed76: test rcx, rcx
         // 0041ed79: jz 0x41ed3a
      [-]9031d248895008488b51200fb65917f6c3407577
         // 0041ed7b: nop 
         // 0041ed7c: xor b4 edx, b4 edx
         // 0041ed7e: mov ds:[rax+0x8], rdx
         // 0041ed82: mov rdx, ds:[rcx+0x20]
         // 0041ed86: movzx b4 ebx, b1 ds:[rcx+0x17]
         // 0041ed8a: test b1 bl, b1 0x40
         // 0041ed8d: jnz 0x41ee06
      [-]48895c24788b0048038424a8010000488b49084889042448894c24084889542410488b8424000200004889442418488d8c24a800000048894c2420e84f0c0000488b4424784885c00f845bffffff
         // 0041ed91: mov ss:[rsp+0x78], rbx
         // 0041ed96: mov b4 eax, b4 ds:[rax]
         // 0041ed98: add rax, ss:[rsp+0x1a8]
         // 0041eda0: mov rcx, ds:[rcx+0x8]
         // 0041eda4: mov ss:[rsp], rax
         // 0041eda8: mov ss:[rsp+0x8], rcx
         // 0041edad: mov ss:[rsp+0x10], rdx
         // 0041edb2: mov rax, ss:[rsp+0x200]
         // 0041edba: mov ss:[rsp+0x18], rax
         // 0041edbf: lea rcx, ss:[rsp+0xa8]
         // 0041edc7: mov ss:[rsp+0x20], rcx
         // 0041edcc: call runtime.scanblock
         // 0041edd1: mov rax, ss:[rsp+0x78]
         // 0041edd6: test rax, rax
         // 0041edd9: jz 0x41ed3a
      [-]90488d0d391e580048890c244889442408488d0501a959004889442410e8ef660000e934ffffff
         // 0041eddf: nop 
         // 0041ede0: lea rcx, cs:[0x9a0c20]
         // 0041ede7: mov ss:[rsp], rcx
         // 0041edeb: mov ss:[rsp+0x8], rax
         // 0041edf0: lea rax, cs:[0x9b96f8]
         // 0041edf7: mov ss:[rsp+0x10], rax
         // 0041edfc: call runtime._ptr_mheap.freeManual
         // 0041ee01: jmp 0x41ed3a
      [-]488984248000000048894c2470488b4108488904244889542408e86b79ffff488b5c2410488b5318488b842480000000488b4c2470e951ffffff
         // 0041ee06: mov ss:[rsp+0x80], rax
         // 0041ee0e: mov ss:[rsp+0x70], rcx
         // 0041ee13: mov rax, ds:[rcx+0x8]
         // 0041ee17: mov ss:[rsp], rax
         // 0041ee1b: mov ss:[rsp+0x8], rdx
         // 0041ee20: call runtime.materializeGCProg
         // 0041ee25: mov rbx, ss:[rsp+0x10]
         // 0041ee2a: mov rdx, ds:[rbx+0x18]
         // 0041ee2e: mov rax, ss:[rsp+0x80]
         // 0041ee36: mov rcx, ss:[rsp+0x70]
         // 0041ee3b: jmp 0x41ed91
      [-]488b481848898c24c801000048c740100000000048890424e803440000
         // 0041ee40: mov rcx, ds:[rax+0x18]
         // 0041ee44: mov ss:[rsp+0x1c8], rcx
         // 0041ee4c: mov ds:[rax+0x10], 0x0
         // 0041ee54: mov ss:[rsp], rax
         // 0041ee58: call runtime.putempty
      [-]488b8424c80100004885c075d6
         // 0041ee5d: mov rax, ss:[rsp+0x1c8]
         // 0041ee65: test rax, rax
         // 0041ee68: jnz 0x41ee40
      [-]4883bc24b8010000000f85d5000000
         // 0041ee6a: cmp ss:[rsp+0x1b8], 0x0
         // 0041ee73: jnz 0x41ef4e
      [-]4883bc24c0010000000f85c6000000
         // 0041ee79: cmp ss:[rsp+0x1c0], 0x0
         // 0041ee82: jnz 0x41ef4e
      [-]488b8424f8010000c680b500000001488bac24e80100004881c4f0010000c3
         // 0041ee88: mov rax, ss:[rsp+0x1f8]
         // 0041ee90: mov b1 ds:[rax+0xb5], b1 0x1
         // 0041ee97: mov rbp, ss:[rsp+0x1e8]
         // 0041ee9f: add rsp, 0x1f0
         // 0041eea6: retn 
      [-]488d8424a80000004889042448894c2408e853200000e943feffff
         // 0041eea7: lea rax, ss:[rsp+0xa8]
         // 0041eeaf: mov ss:[rsp], rax
         // 0041eeb3: mov ss:[rsp+0x8], rcx
         // 0041eeb8: call runtime._ptr_stackScanState.putPtr
         // 0041eebd: jmp 0x41ed05
      [-]488d485048890c2448c744240808000000488d0d2782540048894c2410488b8c240002000048894c2418488d9424a80000004889542420e8220b0000488b8424f80100000f57c0e9c8fcffff
         // 0041eec2: lea rcx, ds:[rax+0x50]
         // 0041eec6: mov ss:[rsp], rcx
         // 0041eeca: mov ss:[rsp+0x8], 0x8
         // 0041eed3: lea rcx, cs:[0x967101]
         // 0041eeda: mov ss:[rsp+0x10], rcx
         // 0041eedf: mov rcx, ss:[rsp+0x200]
         // 0041eee7: mov ss:[rsp+0x18], rcx
         // 0041eeec: lea rdx, ss:[rsp+0xa8]
         // 0041eef4: mov ss:[rsp+0x20], rdx
         // 0041eef9: call runtime.scanblock
         // 0041eefe: mov rax, ss:[rsp+0x1f8]
         // 0041ef06: xorps b16 xmm0, b16 xmm0
         // 0041ef09: jmp 0x41ebd6
      [-]83f9020f8527010000
         // 0041ef0e: cmp b4 ecx, b4 0x2
         // 0041ef11: jnz 0x41f03e
      [-]908b88????????894c245c488b90980000004889542468e870fc0000488d05499829004889042448c74424080c000000e8f7050100488b8424f801000048890424e896050100488d05eb8029004889042448c744240807000000e8cd050100488b44246848890424e8ef030100488d058bb829004889042448c744240813000000e8a60501008b44245c89c048890424e8c7020100e8a2fe0000e87dfc0000488d0527112a004889042448c744240820000000e8c4f100000f0b
         // 0041ef84: nop 
         // 0041ef85: mov b4 ecx, b4 ds:[rax+0x90]
         // 0041ef8b: mov b4 ss:[rsp+0x5c], b4 ecx
         // 0041ef8f: mov rdx, ds:[rax+0x98]
         // 0041ef96: mov ss:[rsp+0x68], rdx
         // 0041ef9b: call runtime.printlock
         // 0041efa0: lea rax, cs:[0x6b87f0]
         // 0041efa7: mov ss:[rsp], rax
         // 0041efab: mov ss:[rsp+0x8], 0xc
         // 0041efb4: call runtime.printstring
         // 0041efb9: mov rax, ss:[rsp+0x1f8]
         // 0041efc1: mov ss:[rsp], rax
         // 0041efc5: call runtime.printpointer
         // 0041efca: lea rax, cs:[0x6b70bc]
         // 0041efd1: mov ss:[rsp], rax
         // 0041efd5: mov ss:[rsp+0x8], 0x7
         // 0041efde: call runtime.printstring
         // 0041efe3: mov rax, ss:[rsp+0x68]
         // 0041efe8: mov ss:[rsp], rax
         // 0041efec: call runtime.printint
         // 0041eff1: lea rax, cs:[0x6ba883]
         // 0041eff8: mov ss:[rsp], rax
         // 0041effc: mov ss:[rsp+0x8], 0x13
         // 0041f005: call runtime.printstring
         // 0041f00a: mov b4 eax, b4 ss:[rsp+0x5c]
         // 0041f00e: mov b4 eax, b4 eax
         // 0041f010: mov ss:[rsp], rax
         // 0041f014: call runtime.printuint
         // 0041f019: call runtime.printnl
         // 0041f01e: call runtime.printunlock
         // 0041f023: lea rax, cs:[0x6c0151]
         // 0041f02a: mov ss:[rsp], rax
         // 0041f02e: mov ss:[rsp+0x8], 0x20
         // 0041f037: call runtime.throw
         // 0041f03c: ud2 
      [-]908b88????????894c2460488b90980000004889542468e8b6fb0000488d058f9729004889042448c74424080c000000e83d050100488b8424f801000048890424e8dc040100488d05318029004889042448c744240807000000e813050100488b44246848890424e835030100488d05d1b729004889042448c744240813000000e8ec0401008b44246089c048890424e80d020100e8e8fd0000e8c3fb0000488d05faaf29004889042448c744240811000000e80af100000f0b
         // 0041f03e: nop 
         // 0041f03f: mov b4 ecx, b4 ds:[rax+0x90]
         // 0041f045: mov b4 ss:[rsp+0x60], b4 ecx
         // 0041f049: mov rdx, ds:[rax+0x98]
         // 0041f050: mov ss:[rsp+0x68], rdx
         // 0041f055: call runtime.printlock
         // 0041f05a: lea rax, cs:[0x6b87f0]
         // 0041f061: mov ss:[rsp], rax
         // 0041f065: mov ss:[rsp+0x8], 0xc
         // 0041f06e: call runtime.printstring
         // 0041f073: mov rax, ss:[rsp+0x1f8]
         // 0041f07b: mov ss:[rsp], rax
         // 0041f07f: call runtime.printpointer
         // 0041f084: lea rax, cs:[0x6b70bc]
         // 0041f08b: mov ss:[rsp], rax
         // 0041f08f: mov ss:[rsp+0x8], 0x7
         // 0041f098: call runtime.printstring
         // 0041f09d: mov rax, ss:[rsp+0x68]
         // 0041f0a2: mov ss:[rsp], rax
         // 0041f0a6: call runtime.printint
         // 0041f0ab: lea rax, cs:[0x6ba883]
         // 0041f0b2: mov ss:[rsp], rax
         // 0041f0b6: mov ss:[rsp+0x8], 0x13
         // 0041f0bf: call runtime.printstring
         // 0041f0c4: mov b4 eax, b4 ss:[rsp+0x60]
         // 0041f0c8: mov b4 eax, b4 eax
         // 0041f0ca: mov ss:[rsp], rax
         // 0041f0ce: call runtime.printuint
         // 0041f0d3: call runtime.printnl
         // 0041f0d8: call runtime.printunlock
         // 0041f0dd: lea rax, cs:[0x6ba0de]
         // 0041f0e4: mov ss:[rsp], rax
         // 0041f0e8: mov ss:[rsp+0x8], 0x11
         // 0041f0f1: call runtime.throw
         // 0041f0f6: ud2 
      [-]908b88????????894c2464488b90980000004889542468e8fcfa0000488d056cd129004889042448c744240816000000e883040100488b8424f801000048890424e822040100488d05777f29004889042448c744240807000000e859040100488b44246848890424e87b020100488d0517b729004889042448c744240813000000e8320401008b44246489c048890424e8c3020100e82efd0000e809fb0000488d0515d129004889042448c744240816000000e850f000000f0b
         // 0041f0f8: nop 
         // 0041f0f9: mov b4 ecx, b4 ds:[rax+0x90]
         // 0041f0ff: mov b4 ss:[rsp+0x64], b4 ecx
         // 0041f103: mov rdx, ds:[rax+0x98]
         // 0041f10a: mov ss:[rsp+0x68], rdx
         // 0041f10f: call runtime.printlock
         // 0041f114: lea rax, cs:[0x6bc287]
         // 0041f11b: mov ss:[rsp], rax
         // 0041f11f: mov ss:[rsp+0x8], 0x16
         // 0041f128: call runtime.printstring
         // 0041f12d: mov rax, ss:[rsp+0x1f8]
         // 0041f135: mov ss:[rsp], rax
         // 0041f139: call runtime.printpointer
         // 0041f13e: lea rax, cs:[0x6b70bc]
         // 0041f145: mov ss:[rsp], rax
         // 0041f149: mov ss:[rsp+0x8], 0x7
         // 0041f152: call runtime.printstring
         // 0041f157: mov rax, ss:[rsp+0x68]
         // 0041f15c: mov ss:[rsp], rax
         // 0041f160: call runtime.printint
         // 0041f165: lea rax, cs:[0x6ba883]
         // 0041f16c: mov ss:[rsp], rax
         // 0041f170: mov ss:[rsp+0x8], 0x13
         // 0041f179: call runtime.printstring
         // 0041f17e: mov b4 eax, b4 ss:[rsp+0x64]
         // 0041f182: mov b4 eax, b4 eax
         // 0041f184: mov ss:[rsp], rax
         // 0041f188: call runtime.printhex
         // 0041f18d: call runtime.printnl
         // 0041f192: call runtime.printunlock
         // 0041f197: lea rax, cs:[0x6bc2b3]
         // 0041f19e: mov ss:[rsp], rax
         // 0041f1a2: mov ss:[rsp+0x8], 0x16
         // 0041f1ab: call runtime.throw
         // 0041f1b0: ud2 
      [-]e899500200
         // 0041f1b2: call runtime.morestackc
      [-]e934f9ffff
         // 0041f1b7: jmp runtime.scanstack
      [-]65488b0c2528000000488b8900000000483b61180f8619020000
         // 0041f7e0: mov rcx, gs:[0x28]
         // 0041f7e9: mov rcx, ds:[rcx+0x0]
         // 0041f7f0: cmp rsp, ds:[rcx+0x18]
         // 0041f7f4: jbe 0x41fa13
      [-]4883ec2848896c2420488d6c2420803df57f5900000f84e3010000
         // 0041f7fa: sub rsp, 0x28
         // 0041f7fe: mov ss:[rsp+0x20], rbp
         // 0041f803: lea rbp, ss:[rsp+0x20]
         // 0041f808: cmp b1 cs:[0x9b7804], b1 0x0
         // 0041f80f: jz 0x41f9f8
      [-]65488b042528000000488b8000000000488b4030488b4c2430488b511848f7da488b80900000004889442418488b5c2438eb1b
         // 0041f815: mov rax, gs:[0x28]
         // 0041f81e: mov rax, ds:[rax+0x0]
         // 0041f825: mov rax, ds:[rax+0x30]
         // 0041f829: mov rcx, ss:[rsp+0x30]
         // 0041f82e: mov rdx, ds:[rcx+0x18]
         // 0041f832: neg rdx
         // 0041f835: mov rax, ds:[rax+0x90]
         // 0041f83c: mov ss:[rsp+0x18], rax
         // 0041f841: mov rbx, ss:[rsp+0x38]
         // 0041f846: jmp 0x41f863
      [-]488b742418488b7c24304c8b4424384889f94c89c34889c24889f0
         // 0041f848: mov rsi, ss:[rsp+0x18]
         // 0041f84d: mov rdi, ss:[rsp+0x30]
         // 0041f852: mov r8, ss:[rsp+0x38]
         // 0041f857: mov rcx, rdi
         // 0041f85a: mov rbx, r8
         // 0041f85d: mov rdx, rax
         // 0041f860: mov rax, rsi
      [-]80b8b1000000000f8588000000
         // 0041f863: cmp b1 ds:[rax+0xb1], b1 0x0
         // 0041f86a: jnz 0x41f8f8
      [-]488b71184801d64839de7d7c
         // 0041f870: mov rsi, ds:[rcx+0x18]
         // 0041f874: add rsi, rdx
         // 0041f877: cmp rsi, rbx
         // 0041f87a: jge 0x41f8f8
      [-]488954241048833d37da5700000f8440010000
         // 0041f87c: mov ss:[rsp+0x10], rdx
         // 0041f881: cmp cs:[0x99d2c0], 0x0
         // 0041f889: jz 0x41f9cf
      [-]90488b314885f60f842c010000
         // 0041f88f: nop 
         // 0041f890: mov rsi, ds:[rcx]
         // 0041f893: test rsi, rsi
         // 0041f896: jz 0x41f9c8
      [-]488b7e104885ff0f8504010000
         // 0041f89c: mov rdi, ds:[rsi+0x10]
         // 0041f8a0: test rdi, rdi
         // 0041f8a3: jnz 0x41f9ad
      [-]4885f60f84a9000000
         // 0041f8ab: test rsi, rsi
         // 0041f8ae: jz 0x41f95d
      [-]4885f67555
         // 0041f8b4: test rsi, rsi
         // 0041f8b7: jnz 0x41f90e
      [-]8b358dda5700393583da57007331
         // 0041f8b9: mov b4 esi, b4 cs:[0x99d34c]
         // 0041f8bf: cmp b4 cs:[0x99d348], b4 esi
         // 0041f8c5: jnb 0x41f8f8
      [-]be????????488d3d75da5700f00fc1378b3d6fda570039fe7317
         // 0041f8c7: mov b4 esi, b4 0x1
         // 0041f8cc: lea rdi, cs:[0x99d348]
         // 0041f8d3: lock xadd b4 ds:[rdi], b4 esi
         // 0041f8d7: mov b4 edi, b4 cs:[0x99d34c]
         // 0041f8dd: cmp b4 esi, b4 edi
         // 0041f8df: jnb 0x41f8f8
      [-]48890c2489742408e8b2e0ffff488b442410e950ffffff
         // 0041f8e1: mov ss:[rsp], rcx
         // 0041f8e5: mov b4 ss:[rsp+0x8], b4 esi
         // 0041f8e9: call runtime.markroot
         // 0041f8ee: mov rax, ss:[rsp+0x10]
         // 0041f8f3: jmp 0x41f848
      [-]488b41184801d04889442440488b6c24204883c428c3
         // 0041f8f8: mov rax, ds:[rcx+0x18]
         // 0041f8fc: add rax, rdx
         // 0041f8ff: mov ss:[rsp+0x40], rax
         // 0041f904: mov rbp, ss:[rsp+0x20]
         // 0041f909: add rsp, 0x28
         // 0041f90d: retn 
      [-]4889342448894c2408e884020000488b442430488b48184881f9d00700007c28
         // 0041f90e: mov ss:[rsp], rsi
         // 0041f912: mov ss:[rsp+0x8], rcx
         // 0041f917: call runtime.scanobject
         // 0041f91c: mov rax, ss:[rsp+0x30]
         // 0041f921: mov rcx, ds:[rax+0x18]
         // 0041f925: cmp rcx, 0x7d0
         // 0041f92c: jl 0x41f956
      [-]488d158b835900f0480fc10a488b481848c7401800000000488b5424104801d1
         // 0041f92e: lea rdx, cs:[0x9b7cc0]
         // 0041f935: lock xadd ds:[rdx], rcx
         // 0041f93a: mov rcx, ds:[rax+0x18]
         // 0041f93e: mov ds:[rax+0x18], 0x0
         // 0041f946: mov rdx, ss:[rsp+0x10]
         // 0041f94b: add rcx, rdx
      [-]4889c8e9f2feffff
         // 0041f94e: mov rax, rcx
         // 0041f951: jmp 0x41f848
      [-]488b4c2410ebf1
         // 0041f956: mov rcx, ss:[rsp+0x10]
         // 0041f95b: jmp 0x41f94e
      [-]48890c24e82a330000488b4424084885c0741c
         // 0041f95d: mov ss:[rsp], rcx
         // 0041f961: call runtime._ptr_gcWork.tryGet
         // 0041f966: mov rax, ss:[rsp+0x8]
         // 0041f96b: test rax, rax
         // 0041f96e: jz 0x41f98c
      [-]488b4c2430488b542410488b5c24384889c6488b442418e928ffffff
         // 0041f970: mov rcx, ss:[rsp+0x30]
         // 0041f975: mov rdx, ss:[rsp+0x10]
         // 0041f97a: mov rbx, ss:[rsp+0x38]
         // 0041f97f: mov rsi, rax
         // 0041f982: mov rax, ss:[rsp+0x18]
         // 0041f987: jmp 0x41f8b4
      [-]0f57c00f110424e8288e0000488b44243048890424e8ea320000488b442408ebc3
         // 0041f98c: xorps b16 xmm0, b16 xmm0
         // 0041f98f: movups b16 ss:[rsp], b16 xmm0
         // 0041f993: call runtime.wbBufFlush
         // 0041f998: mov rax, ss:[rsp+0x30]
         // 0041f99d: mov ss:[rsp], rax
         // 0041f9a1: call runtime._ptr_gcWork.tryGet
         // 0041f9a6: mov rax, ss:[rsp+0x8]
         // 0041f9ab: jmp 0x41f970
      [-]4c8d47ff4c8946104981f8fd0000007333
         // 0041f9ad: lea r8, ds:[rdi+0xffffffffffffffff]
         // 0041f9b1: mov ds:[rsi+0x10], r8
         // 0041f9b5: cmp r8, 0xfd
         // 0041f9bc: jnb 0x41f9f1
      [-]488b74fe10e9e3feffff
         // 0041f9be: mov rsi, ds:[rsi+rdi*0x8]
         // 0041f9c3: jmp 0x41f8ab
      [-]31f6e9dcfeffff
         // 0041f9c8: xor b4 esi, b4 esi
         // 0041f9ca: jmp 0x41f8ab
      [-]48890c24e898340000488b442418488b4c2430488b542410488b5c2438e99efeffff
         // 0041f9cf: mov ss:[rsp], rcx
         // 0041f9d3: call runtime._ptr_gcWork.balance
         // 0041f9d8: mov rax, ss:[rsp+0x18]
         // 0041f9dd: mov rcx, ss:[rsp+0x30]
         // 0041f9e2: mov rdx, ss:[rsp+0x10]
         // 0041f9e7: mov rbx, ss:[rsp+0x38]
         // 0041f9ec: jmp 0x41f88f
      [-]e8bad10000
         // 0041f9f1: call runtime.panicindex
      [-]488d0547d529004889042448c744240818000000e8efe700000f0b
         // 0041f9f8: lea rax, cs:[0x6bcf46]
         // 0041f9ff: mov ss:[rsp], rax
         // 0041fa03: mov ss:[rsp+0x8], 0x18
         // 0041fa0c: call runtime.throw
         // 0041fa11: ud2 
      [-]e838480200
         // 0041fa13: call runtime.morestackc
      [-]e9c3fdffff
         // 0041fa18: jmp runtime.gcDrainN
      [-]65488b0c2528000000488b8900000000483b61180f86ff020000
         // 00424690: mov rcx, gs:[0x28]
         // 00424699: mov rcx, ds:[rcx+0x0]
         // 004246a0: cmp rsp, ds:[rcx+0x18]
         // 004246a4: jbe 0x4249a9
      [-]4883ec4848896c2440488d6c244065488b042528000000488b80000000004889442438488b4c245083791c000f84a2020000
         // 004246aa: sub rsp, 0x48
         // 004246ae: mov ss:[rsp+0x40], rbp
         // 004246b3: lea rbp, ss:[rsp+0x40]
         // 004246b8: mov rax, gs:[0x28]
         // 004246c1: mov rax, ds:[rax+0x0]
         // 004246c8: mov ss:[rsp+0x38], rax
         // 004246cd: mov rcx, ss:[rsp+0x50]
         // 004246d2: cmp b4 ds:[rcx+0x1c], b4 0x0
         // 004246d6: jz 0x42497e
      [-]48890c24e8bb57feff488b442438488b4830488b8930010000488b490848010da8665900488b4830488b893001000048c7410800000000488b4830488b8930010000488b492048010d5f665900488b4030488b803001000048c7402000000000488b44245048890424488b4c245848894c2408488d15524f59004889542410e870060000488b44241848894424304885c00f8594000000
         // 004246dc: mov ss:[rsp], rcx
         // 004246e0: call runtime.lock
         // 004246e5: mov rax, ss:[rsp+0x38]
         // 004246ea: mov rcx, ds:[rax+0x30]
         // 004246ee: mov rcx, ds:[rcx+0x130]
         // 004246f5: mov rcx, ds:[rcx+0x8]
         // 004246f9: add cs:[0x9bada8], rcx
         // 00424700: mov rcx, ds:[rax+0x30]
         // 00424704: mov rcx, ds:[rcx+0x130]
         // 0042470b: mov ds:[rcx+0x8], 0x0
         // 00424713: mov rcx, ds:[rax+0x30]
         // 00424717: mov rcx, ds:[rcx+0x130]
         // 0042471e: mov rcx, ds:[rcx+0x20]
         // 00424722: add cs:[0x9bad88], rcx
         // 00424729: mov rax, ds:[rax+0x30]
         // 0042472d: mov rax, ds:[rax+0x130]
         // 00424734: mov ds:[rax+0x20], 0x0
         // 0042473c: mov rax, ss:[rsp+0x50]
         // 00424741: mov ss:[rsp], rax
         // 00424745: mov rcx, ss:[rsp+0x58]
         // 0042474a: mov ss:[rsp+0x8], rcx
         // 0042474f: lea rdx, cs:[0x9b96a8]
         // 00424756: mov ss:[rsp+0x10], rdx
         // 0042475b: call runtime._ptr_mheap.allocSpanLocked
         // 00424760: mov rax, ss:[rsp+0x18]
         // 00424765: mov ss:[rsp+0x30], rax
         // 0042476a: test rax, rax
         // 0042476d: jnz 0x424807
      [-]833daa2d5900007571
         // 00424773: cmp b4 cs:[0x9b7524], b4 0x0
         // 0042477a: jnz 0x4247ed
      [-]803d2d2c5800007522
         // 0042477c: cmp b1 cs:[0x9a73b0], b1 0x0
         // 00424783: jnz 0x4247a7
      [-]488b44245048890424e8fd58feff488b4424304889442468488b6c24404883c448c3
         // 00424785: mov rax, ss:[rsp+0x50]
         // 0042478a: mov ss:[rsp], rax
         // 0042478e: call runtime.unlock
         // 00424793: mov rax, ss:[rsp+0x30]
         // 00424798: mov ss:[rsp+0x68], rax
         // 0042479d: mov rbp, ss:[rsp+0x40]
         // 004247a2: add rsp, 0x48
         // 004247a6: retn 
      [-]9048c744242800000000488b05e86559004889442428c604242148c7442408ffffffff488d442428488944241048
         // 004247a7: nop 
         // 004247a8: mov ss:[rsp+0x28], 0x0
         // 004247b1: mov rax, cs:[0x9bada0]
         // 004247b8: mov ss:[rsp+0x28], rax
         // 004247bd: mov b1 ss:[rsp], b1 0x21
         // 004247c1: mov ss:[rsp+0x8], 0xffffffffffffffff
         // 004247ca: lea rax, ss:[rsp+0x28]
         // 004247cf: mov ss:[rsp+0x10], rax
         // 004247d4: mov ss:[rsp+0x18], 0x1
         // 004247dd: mov ss:[rsp+0x20], 0x1
         // 004247e6: call runtime.traceEvent
         // 004247eb: jmp 0x424785

  }
  condition:
    all of them
}
