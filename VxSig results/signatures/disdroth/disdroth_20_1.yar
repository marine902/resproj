rule disdroth_20_1 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         4883ec284c89c04c8b4424504989d24929ca7210
         // 140001000: sub rsp, 0x28
         // 140001004: mov rax, r8
         // 140001007: mov r8, ss:[rsp+0x50]
         // 14000100c: mov r10, rdx
         // 14000100f: sub r10, rcx
         // 140001012: jb 0x140001024
      [-]4c39ca7712
         // 140001014: cmp rdx, r9
         // 140001017: ja 0x14000102b
      [-]4801c84c89d24883c428c3
         // 140001019: add rax, rcx
         // 14000101c: mov rdx, r10
         // 14000101f: add rsp, 0x28
         // 140001023: retn 
      [-]e817d00300
         // 140001024: call 0x14003e040
      [-]4889d14c89cae8aacf0300
         // 14000102b: mov rcx, rdx
         // 14000102e: mov rdx, r9
         // 140001031: call 0x14003dfe0
      [-]4883ec284d89c24929ca720e
         // 140001038: sub rsp, 0x28
         // 14000103c: mov r10, r8
         // 14000103f: sub r10, rcx
         // 140001042: jb 0x140001052
      [-]4801ca4889d04c89d24883c428c3
         // 140001044: add rdx, rcx
         // 140001047: mov rax, rdx
         // 14000104a: mov rdx, r10
         // 14000104d: add rsp, 0x28
         // 140001051: retn 
      [-]4c89c24d89c8e873cf0300
         // 140001052: mov rdx, r8
         // 140001055: mov r8, r9
         // 140001058: call 0x14003dfd0
      [-]4883ec28ffd1904883c428c3
         // 14000105f: sub rsp, 0x28
         // 140001063: call rcx
         // 140001065: nop 
         // 140001066: add rsp, 0x28
         // 14000106a: retn 
      [-]5657534883ec204889ce488b4910488b7e184829cf
         // 14000106b: push rsi
         // 14000106c: push rdi
         // 14000106d: push rbx
         // 14000106e: sub rsp, 0x20
         // 140001072: mov rsi, rcx
         // 140001075: mov rcx, ds:[rcx+0x10]
         // 140001079: mov rdi, ds:[rsi+0x18]
         // 14000107d: sub rdi, rcx
      [-]4885ff7412
         // 140001080: test rdi, rdi
         // 140001083: jz 0x140001097
      [-]488d5920e88a0000004883c7e04889d9ebe9
         // 140001085: lea rbx, ds:[rcx+0x20]
         // 140001089: call 0x140001118
         // 14000108e: add rdi, 0xffffffffffffffe0
         // 140001092: mov rcx, rbx
         // 140001095: jmp 0x140001080
      [-]488b56084885d27419
         // 140001097: mov rdx, ds:[rsi+0x8]
         // 14000109b: test rdx, rdx
         // 14000109e: jz 0x1400010b9
      [-]488b0e48c1e20541b8????????4883c4205b5f5ee9d7030000
         // 1400010a0: mov rcx, ds:[rsi]
         // 1400010a3: shl rdx, b1 0x5
         // 1400010a7: mov b4 r8d, b4 0x8
         // 1400010ad: add rsp, 0x20
         // 1400010b1: pop rbx
         // 1400010b2: pop rdi
         // 1400010b3: pop rsi
         // 1400010b4: jmp 0x140001490
      [-]904883c4205b5f5ec3
         // 1400010b9: nop 
         // 1400010ba: add rsp, 0x20
         // 1400010be: pop rbx
         // 1400010bf: pop rdi
         // 1400010c0: pop rsi
         // 1400010c1: retn 
      [-]e951000000
         // 1400010c2: jmp 0x140001118
      [-]56574883ec28488b3989f883e00383f8017536
         // 1400010c7: push rsi
         // 1400010c8: push rdi
         // 1400010c9: sub rsp, 0x28
         // 1400010cd: mov rdi, ds:[rcx]
         // 1400010d0: mov b4 eax, b4 edi
         // 1400010d2: and b4 eax, b4 0x3
         // 1400010d5: cmp b4 eax, b4 0x1
         // 1400010d8: jnz 0x140001110
      [-]488d77ff488b4fff488b4707ff10488b4fff488b4707488b50084c8b4010e893030000ba????????4889f14883c4285f5ee9f05e0000
         // 1400010da: lea rsi, ds:[rdi+0xffffffffffffffff]
         // 1400010de: mov rcx, ds:[rdi+0xffffffffffffffff]
         // 1400010e2: mov rax, ds:[rdi+0x7]
         // 1400010e6: call ds:[rax]
         // 1400010e8: mov rcx, ds:[rdi+0xffffffffffffffff]
         // 1400010ec: mov rax, ds:[rdi+0x7]
         // 1400010f0: mov rdx, ds:[rax+0x8]
         // 1400010f4: mov r8, ds:[rax+0x10]
         // 1400010f8: call 0x140001490
         // 1400010fd: mov b4 edx, b4 0x8
         // 140001102: mov rcx, rsi
         // 140001105: add rsp, 0x28
         // 140001109: pop rdi
         // 14000110a: pop rsi
         // 14000110b: jmp 0x140007000
      [-]904883c4285f5ec3
         // 140001110: nop 
         // 140001111: add rsp, 0x28
         // 140001115: pop rdi
         // 140001116: pop rsi
         // 140001117: retn 
      [-]4883790800740d
         // 140001118: cmp ds:[rcx+0x8], 0x0
         // 14000111d: jz 0x14000112c
      [-]488b09ba????????e9d45e0000
         // 14000111f: mov rcx, ds:[rcx]
         // 140001122: mov b4 edx, b4 0x1
         // 140001127: jmp 0x140007000
      [-]807918020f85e1ffffff
         // 14000112d: cmp b1 ds:[rcx+0x18], b1 0x2
         // 140001131: jnz 0x140001118
      [-]4883f905770c
         // 140001138: cmp rcx, 0x5
         // 14000113c: ja 0x14000114a
      [-]b8????????480fa3c87301
         // 14000113e: mov b4 eax, b4 0x27
         // 140001143: bt rax, rcx
         // 140001147: jnb 0x14000114a
      [-]4889d148ff25d4ee0300
         // 14000114a: mov rcx, rdx
         // 14000114d: jmp cs:[__imp_CloseHandle]
      [-]4883ec284889d04c39ca750f
         // 140001154: sub rsp, 0x28
         // 140001158: mov rax, rdx
         // 14000115b: cmp rdx, r9
         // 14000115e: jnz 0x14000116f
      [-]4c89c24989c04883c428e911fa0200
         // 140001160: mov rdx, r8
         // 140001163: mov r8, rax
         // 140001166: add rsp, 0x28
         // 14000116a: jmp memmove
      [-]4c8b4424504889c14c89cae841d00300
         // 14000116f: mov r8, ss:[rsp+0x50]
         // 140001174: mov rcx, rax
         // 140001177: mov rdx, r9
         // 14000117a: call 0x14003e1c0
      [-]4883ec284c89c04c8b4424504d89ca4929c27213
         // 140001181: sub rsp, 0x28
         // 140001185: mov rax, r8
         // 140001188: mov r8, ss:[rsp+0x50]
         // 14000118d: mov r10, r9
         // 140001190: sub r10, rax
         // 140001193: jb 0x1400011a8
      [-]4939d1771b
         // 140001195: cmp r9, rdx
         // 140001198: ja 0x1400011b5
      [-]4801c14889c84c89d24883c428c3
         // 14000119a: add rcx, rax
         // 14000119d: mov rax, rcx
         // 1400011a0: mov rdx, r10
         // 1400011a3: add rsp, 0x28
         // 1400011a7: retn 
      [-]4889c14c89cae88dce0300
         // 1400011a8: mov rcx, rax
         // 1400011ab: mov rdx, r9
         // 1400011ae: call 0x14003e040
      [-]4c89c9e823ce0300
         // 1400011b5: mov rcx, r9
         // 1400011b8: call 0x14003dfe0
      [-]4883ec284889c84889d14c29c1720b
         // 1400011bf: sub rsp, 0x28
         // 1400011c3: mov rax, rcx
         // 1400011c6: mov rcx, rdx
         // 1400011c9: sub rcx, r8
         // 1400011cc: jb 0x1400011d9
      [-]4c01c04889ca4883c428c3
         // 1400011ce: add rax, r8
         // 1400011d1: mov rdx, rcx
         // 1400011d4: add rsp, 0x28
         // 1400011d8: retn 
      [-]4c89c14d89c8e8eccd0300
         // 1400011d9: mov rcx, r8
         // 1400011dc: mov r8, r9
         // 1400011df: call 0x14003dfd0
      [-]4883ec3884c97505
         // 1400011e6: sub rsp, 0x38
         // 1400011ea: test b1 cl, b1 cl
         // 1400011ec: jnz 0x1400011f3
      [-]4883c438c3
         // 1400011ee: add rsp, 0x38
         // 1400011f2: retn 
      [-]488d05cef303004889442420488d0d8af303004c8d0dd3f303004c8d442430ba????????e8e4ce0300
         // 1400011f3: lea rax, cs:[0x1400405c8]
         // 1400011fa: mov ss:[rsp+0x20], rax
         // 1400011ff: lea rcx, cs:[0x140040590]
         // 140001206: lea r9, cs:[0x1400405e0]
         // 14000120d: lea r8, ss:[rsp+0x30]
         // 140001212: mov b4 edx, b4 0x37
         // 140001217: call 0x14003e100
      [-]4883ec68488d05f7f60300488d542428488902488d05584a0400488d4c243848890141b8????????4c8941084883611000488d05ea70010048894208488951204c894128488d15c7f60300e8a2cc0300
         // 14000121e: sub rsp, 0x68
         // 140001222: lea rax, cs:[0x140040920]
         // 140001229: lea rdx, ss:[rsp+0x28]
         // 14000122e: mov ds:[rdx], rax
         // 140001231: lea rax, cs:[0x140045c90]
         // 140001238: lea rcx, ss:[rsp+0x38]
         // 14000123d: mov ds:[rcx], rax
         // 140001240: mov b4 r8d, b4 0x1
         // 140001246: mov ds:[rcx+0x8], r8
         // 14000124a: and ds:[rcx+0x10], 0x0
         // 14000124f: lea rax, cs:[0x140018340]
         // 140001256: mov ds:[rdx+0x8], rax
         // 14000125a: mov ds:[rcx+0x20], rdx
         // 14000125e: mov ds:[rcx+0x28], r8
         // 140001262: lea rdx, cs:[0x140040930]
         // 140001269: call 0x14003df10
      [-]488b014c8b51104c8b42204c8b4a284889c14c89d2e906a40000
         // 140001270: mov rax, ds:[rcx]
         // 140001273: mov r10, ds:[rcx+0x10]
         // 140001277: mov r8, ds:[rdx+0x20]
         // 14000127b: mov r9, ds:[rdx+0x28]
         // 14000127f: mov rcx, rax
         // 140001282: mov rdx, r10
         // 140001285: jmp 0x14000b690
      [-]56574883ec3889d74889ce81fa????????7329
         // 14000128a: push rsi
         // 14000128b: push rdi
         // 14000128c: sub rsp, 0x38
         // 140001290: mov b4 edi, b4 edx
         // 140001292: mov rsi, rcx
         // 140001295: cmp b4 edx, b4 0x80
         // 14000129b: jnb 0x1400012c6
      [-]488b5610483b5608750c
         // 14000129d: mov rdx, ds:[rsi+0x10]
         // 1400012a1: cmp rdx, ds:[rsi+0x8]
         // 1400012a5: jnz 0x1400012b3
      [-]4889f1e82aed0200488b5610
         // 1400012a7: mov rcx, rsi
         // 1400012aa: call 0x14002ffd9
         // 1400012af: mov rdx, ds:[rsi+0x10]
      [-]488b0640883c1048ffc248895610e9c1000000
         // 1400012b3: mov rax, ds:[rsi]
         // 1400012b6: mov b1 ds:[rax+rdx], b1 dil
         // 1400012ba: inc rdx
         // 1400012bd: mov ds:[rsi+0x10], rdx
         // 1400012c1: jmp 0x140001387
      [-]836424340089f881ff????????731d
         // 1400012c6: and b4 ss:[rsp+0x34], b4 0x0
         // 1400012cb: mov b4 eax, b4 edi
         // 1400012cd: cmp b4 edi, b4 0x800
         // 1400012d3: jnb 0x1400012f2
      [-]c1e8060cc0884424344080e73f4080cf8040887c2435ba????????eb69
         // 1400012d5: shr b4 eax, b1 0x6
         // 1400012d8: or b1 al, b1 0xc0
         // 1400012da: mov b1 ss:[rsp+0x34], b1 al
         // 1400012de: and b1 dil, b1 0x3f
         // 1400012e2: or b1 dil, b1 0x80
         // 1400012e6: mov b1 ss:[rsp+0x35], b1 dil
         // 1400012eb: mov b4 edx, b4 0x2
         // 1400012f0: jmp 0x14000135b
      [-]81ff????????732a
         // 1400012f2: cmp b4 edi, b4 0x10000
         // 1400012f8: jnb 0x140001324
      [-]c1e80c0ce08844243489f8c1e806243f0c80884424354080e73f4080cf8040887c2436ba????????eb37
         // 1400012fa: shr b4 eax, b1 0xc
         // 1400012fd: or b1 al, b1 0xe0
         // 1400012ff: mov b1 ss:[rsp+0x34], b1 al
         // 140001303: mov b4 eax, b4 edi
         // 140001305: shr b4 eax, b1 0x6
         // 140001308: and b1 al, b1 0x3f
         // 14000130a: or b1 al, b1 0x80
         // 14000130c: mov b1 ss:[rsp+0x35], b1 al
         // 140001310: and b1 dil, b1 0x3f
         // 140001314: or b1 dil, b1 0x80
         // 140001318: mov b1 ss:[rsp+0x36], b1 dil
         // 14000131d: mov b4 edx, b4 0x3
         // 140001322: jmp 0x14000135b
      [-]c1e81224070cf08844243489f8c1e80c243f0c808844243589f8c1e806243f0c80884424364080e73f4080cf8040887c2437ba????????
         // 140001324: shr b4 eax, b1 0x12
         // 140001327: and b1 al, b1 0x7
         // 140001329: or b1 al, b1 0xf0
         // 14000132b: mov b1 ss:[rsp+0x34], b1 al
         // 14000132f: mov b4 eax, b4 edi
         // 140001331: shr b4 eax, b1 0xc
         // 140001334: and b1 al, b1 0x3f
         // 140001336: or b1 al, b1 0x80
         // 140001338: mov b1 ss:[rsp+0x35], b1 al
         // 14000133c: mov b4 eax, b4 edi
         // 14000133e: shr b4 eax, b1 0x6
         // 140001341: and b1 al, b1 0x3f
         // 140001343: or b1 al, b1 0x80
         // 140001345: mov b1 ss:[rsp+0x36], b1 al
         // 140001349: and b1 dil, b1 0x3f
         // 14000134d: or b1 dil, b1 0x80
         // 140001351: mov b1 ss:[rsp+0x37], b1 dil
         // 140001356: mov b4 edx, b4 0x4
      [-]488d05de44040048894424204c8d44243441b9????????31c9e887fcffff4989d04889f14889c2e858660000
         // 14000135b: lea rax, cs:[0x140045840]
         // 140001362: mov ss:[rsp+0x20], rax
         // 140001367: lea r8, ss:[rsp+0x34]
         // 14000136c: mov b4 r9d, b4 0x4
         // 140001372: xor b4 ecx, b4 ecx
         // 140001374: call 0x140001000
         // 140001379: mov r8, rdx
         // 14000137c: mov rcx, rsi
         // 14000137f: mov rdx, rax
         // 140001382: call 0x1400079df
      [-]31c04883c4385f5ec3
         // 140001387: xor b4 eax, b4 eax
         // 140001389: add rsp, 0x38
         // 14000138d: pop rdi
         // 14000138e: pop rsi
         // 14000138f: retn 
      [-]4883ec28e84666000031c04883c428c3
         // 140001390: sub rsp, 0x28
         // 140001394: call 0x1400079df
         // 140001399: xor b4 eax, b4 eax
         // 14000139b: add rsp, 0x28
         // 14000139f: retn 
      [-]4d89c1498b004885c07419
         // 1400013a0: mov r9, r8
         // 1400013a3: mov rax, ds:[r8]
         // 1400013a6: test rax, rax
         // 1400013a9: jz 0x1400013c4
      [-]4c8d4201450fb791d00300004c8901488941084c895110eb05
         // 1400013ab: lea r8, ds:[rdx+0x1]
         // 1400013af: movzx b4 r10d, b2 ds:[r9+0x3d0]
         // 1400013b7: mov ds:[rcx], r8
         // 1400013ba: mov ds:[rcx+0x8], rax
         // 1400013be: mov ds:[rcx+0x10], r10
         // 1400013c2: jmp 0x1400013c9
      [-]4883610800
         // 1400013c4: and ds:[rcx+0x8], 0x0
      [-]4885d2b8????????ba????????480f44d041b8????????4c89c9e9a8000000
         // 1400013c9: test rdx, rdx
         // 1400013cc: mov b4 eax, b4 0x3d8
         // 1400013d1: mov b4 edx, b4 0x438
         // 1400013d6: cmovz rdx, rax
         // 1400013da: mov b4 r8d, b4 0x8
         // 1400013e0: mov rcx, r9
         // 1400013e3: jmp 0x140001490
      [-]56574883ec284889ce4885c97441
         // 1400013e8: push rsi
         // 1400013e9: push rdi
         // 1400013ea: sub rsp, 0x28
         // 1400013ee: mov rsi, rcx
         // 1400013f1: test rcx, rcx
         // 1400013f4: jz 0x140001437
      [-]4889f748f7d748c1ef3f84d27438
         // 1400013f8: mov rdi, rsi
         // 1400013fb: not rdi
         // 1400013fe: shr rdi, b1 0x3f
         // 140001402: test b1 dl, b1 dl
         // 140001404: jz 0x14000143e
      [-]488b0d6b6705004885c97515
         // 140001406: mov rcx, cs:[0x140057b78]
         // 14000140d: test rcx, rcx
         // 140001410: jnz 0x140001427
      [-]ff1518ec03004885c0743b
         // 140001412: call cs:[GetProcessHeap]
         // 140001418: test rax, rax
         // 14000141b: jz 0x140001458
      [-]4889c148890551670500
         // 14000141d: mov rcx, rax
         // 140001420: mov cs:[0x140057b78], rax
      [-]ba????????4989f0ff1503ec0300eb12
         // 140001427: mov b4 edx, b4 0x8
         // 14000142c: mov r8, rsi
         // 14000142f: call cs:[HeapAlloc]
         // 140001435: jmp 0x140001449
      [-]b8????????eb10
         // 140001437: mov b4 eax, b4 0x1
         // 14000143c: jmp 0x14000144e
      [-]4889f14889fae855000000
         // 14000143e: mov rcx, rsi
         // 140001441: mov rdx, rdi
         // 140001444: call 0x14000149e
      [-]4885c0740a
         // 140001449: test rax, rax
         // 14000144c: jz 0x140001458
      [-]4889f24883c4285f5ec3
         // 14000144e: mov rdx, rsi
         // 140001451: add rsp, 0x28
         // 140001455: pop rdi
         // 140001456: pop rsi
         // 140001457: retn 
      [-]4889f14889fae8ddc90300
         // 140001458: mov rcx, rsi
         // 14000145b: mov rdx, rdi
         // 14000145e: call 0x14003de40
      [-]e8e65b0000
         // 140001465: call 0x140007050
      [-]4889d0488b114c8b41104889c1e95e830000
         // 140001470: mov rax, rdx
         // 140001473: mov rdx, ds:[rcx]
         // 140001476: mov r8, ds:[rcx+0x10]
         // 14000147a: mov rcx, rax
         // 14000147d: jmp 0x1400097e0
      [-]4885d27408
         // 140001490: test rdx, rdx
         // 140001493: jz 0x14000149d
      [-]4c89c2e9635b0000
         // 140001495: mov rdx, r8
         // 140001498: jmp 0x140007000
      [-]4885c90f85095b0000
         // 14000149e: test rcx, rcx
         // 1400014a1: jnz 0x140006fb0
      [-]4889d0c3
         // 1400014a7: mov rax, rdx
         // 1400014aa: retn 
      [-]4883ec284c39ca7515
         // 1400014ab: sub rsp, 0x28
         // 1400014af: cmp rdx, r9
         // 1400014b2: jnz 0x1400014c9
      [-]4889d04c89c24989c0e84efd020085c00f94c0eb02
         // 1400014b4: mov rax, rdx
         // 1400014b7: mov rdx, r8
         // 1400014ba: mov r8, rax
         // 1400014bd: call memcmp
         // 1400014c2: test b4 eax, b4 eax
         // 1400014c4: setz b1 al
         // 1400014c7: jmp 0x1400014cb
      [-]4883c428c3
         // 1400014cb: add rsp, 0x28
         // 1400014cf: retn 
      [-]4883ec284c39c2760f
         // 1400014d0: sub rsp, 0x28
         // 1400014d4: cmp rdx, r8
         // 1400014d7: jbe 0x1400014e8
      [-]496bc0184801c14889c84883c428c3
         // 1400014d9: imul rax, r8, b1 0x18
         // 1400014dd: add rcx, rax
         // 1400014e0: mov rax, rcx
         // 1400014e3: add rsp, 0x28
         // 1400014e7: retn 
      [-]4c89c14d89c8e85dca0300
         // 1400014e8: mov rcx, r8
         // 1400014eb: mov r8, r9
         // 1400014ee: call 0x14003df50
      [-]5541574156415541545657534881ec18030000488dac24800000000f29b58002000048c78578020000feffffffff1515eb030048c785b0010000080000000f57c00f1185b80100004885c00f84ef040000
         // 1400014f8: push rbp
         // 1400014f9: push r15
         // 1400014fb: push r14
         // 1400014fd: push r13
         // 1400014ff: push r12
         // 140001501: push rsi
         // 140001502: push rdi
         // 140001503: push rbx
         // 140001504: sub rsp, 0x318
         // 14000150b: lea rbp, ss:[rsp+0x80]
         // 140001513: movaps b16 ss:[rbp+0x280], b16 xmm6
         // 14000151a: mov ss:[rbp+0x278], 0xfffffffffffffffe
         // 140001525: call cs:[GetCommandLineW]
         // 14000152b: mov ss:[rbp+0x1b0], 0x8
         // 140001536: xorps b16 xmm0, b16 xmm0
         // 140001539: movups b16 ss:[rbp+0x1b8], b16 xmm0
         // 140001540: test rax, rax
         // 140001543: jz 0x140001a38
      [-]4889c60fb7386685ff0f84e0040000
         // 140001549: mov rsi, rax
         // 14000154c: movzx b4 edi, b2 ds:[rax]
         // 14000154f: test b2 di, b2 di
         // 140001552: jz 0x140001a38
      [-]6a02584c8d752049c706020000000f57c0410f1146084531c031db
         // 140001558: push 0x2
         // 14000155a: pop rax
         // 14000155b: lea r14, ss:[rbp+0x20]
         // 14000155f: mov ds:[r14], 0x2
         // 140001566: xorps b16 xmm0, b16 xmm0
         // 140001569: movups b16 ds:[r14+0x8], b16 xmm0
         // 14000156e: xor b4 r8d, b4 r8d
         // 140001571: xor b4 ebx, b4 ebx
      [-]6685ff7451
         // 140001573: test b2 di, b2 di
         // 140001576: jz 0x1400015c9
      [-]4883c6026683ff097414
         // 140001578: add rsi, 0x2
         // 14000157c: cmp b2 di, b2 0x9
         // 140001580: jz 0x140001596
      [-]0fb7cf83f920740c
         // 140001582: movzx b4 ecx, b2 di
         // 140001585: cmp b4 ecx, b4 0x20
         // 140001588: jz 0x140001596
      [-]83f922750c
         // 14000158a: cmp b4 ecx, b4 0x22
         // 14000158d: jnz 0x14000159b
      [-]f6d380e301eb2a
         // 14000158f: not b1 bl
         // 140001591: and b1 bl, b1 0x1
         // 140001594: jmp 0x1400015c0
      [-]f6c301742e
         // 140001596: test b1 bl, b1 0x1
         // 140001599: jz 0x1400015c9
      [-]4c3b45287513
         // 14000159b: cmp r8, ss:[rbp+0x28]
         // 14000159f: jnz 0x1400015b4
      [-]4c89f14c89c2e8646b0100488b45204c8b4530
         // 1400015a1: mov rcx, r14
         // 1400015a4: mov rdx, r8
         // 1400015a7: call 0x140018110
         // 1400015ac: mov rax, ss:[rbp+0x20]
         // 1400015b0: mov r8, ss:[rbp+0x30]
      [-]6642893c4049ffc04c894530
         // 1400015b4: mov b2 ds:[rax+r8*0x2], b2 di
         // 1400015b9: inc r8
         // 1400015bc: mov ss:[rbp+0x30], r8
      [-]0fb73eebae
         // 1400015c0: movzx b4 edi, b2 ds:[rsi]
         // 1400015c3: jmp 0x140001573
      [-]4883c602
         // 1400015c5: add rsi, 0x2
      [-]0fb70683f82074f4
         // 1400015c9: movzx b4 eax, b2 ds:[rsi]
         // 1400015cc: cmp b4 eax, b4 0x20
         // 1400015cf: jz 0x1400015c5
      [-]83f80974ef
         // 1400015d1: cmp b4 eax, b4 0x9
         // 1400015d4: jz 0x1400015c5
      [-]4c8b6d20488d4d604c89eae8ea7a0100488d8db001000031d2e86cbf0100488d9db0010000488b03488b4b104889ca48c1e205488d7d600f10070f104f100f114c10100f11041048ffc148894b10488d85f801000048c700020000000f57c00f1140086a02415c4531c00f283519ee03004531f6
         // 1400015d6: mov r13, ss:[rbp+0x20]
         // 1400015da: lea rcx, ss:[rbp+0x60]
         // 1400015de: mov rdx, r13
         // 1400015e1: call 0x1400190d0
         // 1400015e6: lea rcx, ss:[rbp+0x1b0]
         // 1400015ed: xor b4 edx, b4 edx
         // 1400015ef: call 0x14001d560
         // 1400015f4: lea rbx, ss:[rbp+0x1b0]
         // 1400015fb: mov rax, ds:[rbx]
         // 1400015fe: mov rcx, ds:[rbx+0x10]
         // 140001602: mov rdx, rcx
         // 140001605: shl rdx, b1 0x5
         // 140001609: lea rdi, ss:[rbp+0x60]
         // 14000160d: movups b16 xmm0, b16 ds:[rdi]
         // 140001610: movups b16 xmm1, b16 ds:[rdi+0x10]
         // 140001614: movups b16 ds:[rax+rdx+0x10], b16 xmm1
         // 140001619: movups b16 ds:[rax+rdx], b16 xmm0
         // 14000161d: inc rcx
         // 140001620: mov ds:[rbx+0x10], rcx
         // 140001624: lea rax, ss:[rbp+0x1f8]
         // 14000162b: mov ds:[rax], 0x2
         // 140001632: xorps b16 xmm0, b16 xmm0
         // 140001635: movups b16 ds:[rax+0x8], b16 xmm0
         // 140001639: push 0x2
         // 14000163b: pop r12
         // 14000163d: xor b4 r8d, b4 r8d
         // 140001640: movaps b16 xmm6, b16 cs:[0x140040460]
         // 140001647: xor b4 r14d, b4 r14d
      [-]488d4e024883c6044889f04889ce
         // 14000164d: lea rcx, ds:[rsi+0x2]
         // 140001651: add rsi, 0x4
         // 140001655: mov rax, rsi
         // 140001658: mov rsi, rcx
      [-]6685ff0f84cf040000
         // 14000165b: test b2 di, b2 di
         // 14000165e: jz 0x140001b33
      [-]6683ff227529
         // 140001664: cmp b2 di, b2 0x22
         // 140001668: jnz 0x140001693
      [-]4584f60f84a5010000
         // 14000166a: test b1 r14b, b1 r14b
         // 14000166d: jz 0x140001818
      [-]0fb73e85ff0f84cf040000
         // 140001673: movzx b4 edi, b2 ds:[rsi]
         // 140001676: test b4 edi, b4 edi
         // 140001678: jz 0x140001b4d
      [-]4883c6024883c0024531f683ff2275cd
         // 14000167e: add rsi, 0x2
         // 140001682: add rax, 0x2
         // 140001686: xor b4 r14d, b4 r14d
         // 140001689: cmp b4 edi, b4 0x22
         // 14000168c: jnz 0x14000165b
      [-]e941010000
         // 14000168e: jmp 0x1400017d4
      [-]4c3b85000200007516
         // 1400017d4: cmp r8, ss:[rbp+0x200]
         // 1400017db: jnz 0x1400017f3
      [-]488d8df80100004c89c2e8246901004c8b8508020000
         // 1400017dd: lea rcx, ss:[rbp+0x1f8]
         // 1400017e4: mov rdx, r8
         // 1400017e7: call 0x140018110
         // 1400017ec: mov r8, ss:[rbp+0x208]
      [-]4c8ba5f80100006643c70444220049ffc04c89850802000066837efe00488d46fe480f44f0
         // 1400017f3: mov r12, ss:[rbp+0x1f8]
         // 1400017fa: mov b2 ds:[r12+r8*0x2], b2 0x22
         // 140001801: inc r8
         // 140001804: mov ss:[rbp+0x208], r8
         // 14000180b: cmp b2 ds:[rsi+0xfffffffffffffffe], b2 0x0
         // 140001810: lea rax, ds:[rsi+0xfffffffffffffffe]
         // 140001814: cmovz rsi, rax
      [-]41b601e92afeffff
         // 140001818: mov b1 r14b, b1 0x1
         // 14000181b: jmp 0x14000164a
      [-]488b85000200004c29c04839f87345
         // 140001820: mov rax, ss:[rbp+0x200]
         // 140001827: sub rax, r8
         // 14000182a: cmp rax, rdi
         // 14000182d: jnb 0x140001874
      [-]488d8df80100004c89c24989f8e83fd203004c8ba5f80100004c8b8508020000eb2c
         // 14000182f: lea rcx, ss:[rbp+0x1f8]
         // 140001836: mov rdx, r8
         // 140001839: mov r8, rdi
         // 14000183c: call 0x14003ea80
         // 140001841: mov r12, ss:[rbp+0x1f8]
         // 140001848: mov r8, ss:[rbp+0x208]
         // 14000184f: jmp 0x14000187d
      [-]4c8ba5f80100004883ff020f8283010000
         // 140001851: mov r12, ss:[rbp+0x1f8]
         // 140001858: cmp rdi, 0x2
         // 14000185c: jb 0x1400019e5
      [-]4b8d04444883ff207347
         // 140001862: lea rax, ds:[r12+r8*0x2]
         // 140001866: cmp rdi, 0x20
         // 14000186a: jnb 0x1400018b3
      [-]4c89f9e95e010000
         // 14000186c: mov rcx, r15
         // 14000186f: jmp 0x1400019d2
      [-]4885ff0f84de000000
         // 140001874: test rdi, rdi
         // 140001877: jz 0x14000195b
      [-]4b8d04444883ff107308
         // 14000187d: lea rax, ds:[r12+r8*0x2]
         // 140001881: cmp rdi, 0x10
         // 140001885: jnb 0x14000188f
      [-]4889f9e9b9000000
         // 140001887: mov rcx, rdi
         // 14000188a: jmp 0x140001948
      [-]4989f94983e1f0498d59f04889da48c1ea0448ffc289d183e1034883fb30732f
         // 14000188f: mov r9, rdi
         // 140001892: and r9, 0xfffffffffffffff0
         // 140001896: lea rbx, ds:[r9+0xfffffffffffffff0]
         // 14000189a: mov rdx, rbx
         // 14000189d: shr rdx, b1 0x4
         // 1400018a1: inc rdx
         // 1400018a4: mov b4 ecx, b4 edx
         // 1400018a6: and b4 ecx, b4 0x3
         // 1400018a9: cmp rbx, 0x30
         // 1400018ad: jnb 0x1400018de
      [-]31dbeb62
         // 1400018af: xor b4 ebx, b4 ebx
         // 1400018b1: jmp 0x140001915
      [-]4d89f94983e1f0498d59f04889da48c1ea0448ffc289d183e1034883fb300f8390000000
         // 1400018b3: mov r9, r15
         // 1400018b6: and r9, 0xfffffffffffffff0
         // 1400018ba: lea rbx, ds:[r9+0xfffffffffffffff0]
         // 1400018be: mov rdx, rbx
         // 1400018c1: shr rdx, b1 0x4
         // 1400018c5: inc rdx
         // 1400018c8: mov b4 ecx, b4 edx
         // 1400018ca: and b4 ecx, b4 0x3
         // 1400018cd: cmp rbx, 0x30
         // 1400018d1: jnb 0x140001967
      [-]31dbe9c0000000
         // 1400018d7: xor b4 ebx, b4 ebx
         // 1400018d9: jmp 0x14000199e
      [-]4883e2fc31db
         // 1400018de: and rdx, 0xfffffffffffffffc
         // 1400018e2: xor b4 ebx, b4 ebx
      [-]0f1134580f117458100f117458200f117458300f117458400f117458500f117458600f117458704883c3404883c2fc75cf
         // 1400018e4: movups b16 ds:[rax+rbx*0x2], b16 xmm6
         // 1400018e8: movups b16 ds:[rax+rbx*0x2], b16 xmm6
         // 1400018ed: movups b16 ds:[rax+rbx*0x2], b16 xmm6
         // 1400018f2: movups b16 ds:[rax+rbx*0x2], b16 xmm6
         // 1400018f7: movups b16 ds:[rax+rbx*0x2], b16 xmm6
         // 1400018fc: movups b16 ds:[rax+rbx*0x2], b16 xmm6
         // 140001901: movups b16 ds:[rax+rbx*0x2], b16 xmm6
         // 140001906: movups b16 ds:[rax+rbx*0x2], b16 xmm6
         // 14000190b: add rbx, 0x40
         // 14000190f: add rdx, 0xfffffffffffffffc
         // 140001913: jnz 0x1400018e4
      [-]4885c97420
         // 140001915: test rcx, rcx
         // 140001918: jz 0x14000193a
      [-]488d14584883c21048c1e10531db
         // 14000191a: lea rdx, ds:[rax+rbx*0x2]
         // 14000191e: add rdx, 0x10
         // 140001922: shl rcx, b1 0x5
         // 140001926: xor b4 ebx, b4 ebx
      [-]0f11741af00f11341a4883c3204839d975ee
         // 140001928: movups b16 ds:[rdx+rbx+0xfffffffffffffff0], b16 xmm6
         // 14000192d: movups b16 ds:[rdx+rbx], b16 xmm6
         // 140001931: add rbx, 0x20
         // 140001935: cmp rcx, rbx
         // 140001938: jnz 0x140001928
      [-]4c39cf7419
         // 14000193a: cmp rdi, r9
         // 14000193d: jz 0x140001958
      [-]89f983e10f4a8d0448
         // 14000193f: mov b4 ecx, b4 edi
         // 140001941: and b4 ecx, b4 0xf
         // 140001944: lea rax, ds:[rax+r9*0x2]
      [-]66c704505c0048ffc24839d175f2
         // 14000194a: mov b2 ds:[rax+rdx*0x2], b2 0x5c
         // 140001950: inc rdx
         // 140001953: cmp rcx, rdx
         // 140001956: jnz 0x14000194a
      [-]4c898508020000e9e3fcffff
         // 14000195b: mov ss:[rbp+0x208], r8
         // 140001962: jmp 0x14000164a
      [-]4883e2fc31db
         // 140001967: and rdx, 0xfffffffffffffffc
         // 14000196b: xor b4 ebx, b4 ebx
      [-]0f1134580f117458100f117458200f117458300f117458400f117458500f117458600f117458704883c3404883c2fc75cf
         // 14000196d: movups b16 ds:[rax+rbx*0x2], b16 xmm6
         // 140001971: movups b16 ds:[rax+rbx*0x2], b16 xmm6
         // 140001976: movups b16 ds:[rax+rbx*0x2], b16 xmm6
         // 14000197b: movups b16 ds:[rax+rbx*0x2], b16 xmm6
         // 140001980: movups b16 ds:[rax+rbx*0x2], b16 xmm6
         // 140001985: movups b16 ds:[rax+rbx*0x2], b16 xmm6
         // 14000198a: movups b16 ds:[rax+rbx*0x2], b16 xmm6
         // 14000198f: movups b16 ds:[rax+rbx*0x2], b16 xmm6
         // 140001994: add rbx, 0x40
         // 140001998: add rdx, 0xfffffffffffffffc
         // 14000199c: jnz 0x14000196d
      [-]4885c97420
         // 14000199e: test rcx, rcx
         // 1400019a1: jz 0x1400019c3
      [-]488d14584883c21048c1e10531db
         // 1400019a3: lea rdx, ds:[rax+rbx*0x2]
         // 1400019a7: add rdx, 0x10
         // 1400019ab: shl rcx, b1 0x5
         // 1400019af: xor b4 ebx, b4 ebx
      [-]0f11741af00f11341a4883c3204839d975ee
         // 1400019b1: movups b16 ds:[rdx+rbx+0xfffffffffffffff0], b16 xmm6
         // 1400019b6: movups b16 ds:[rdx+rbx], b16 xmm6
         // 1400019ba: add rbx, 0x20
         // 1400019be: cmp rcx, rbx
         // 1400019c1: jnz 0x1400019b1
      [-]4d39cf741a
         // 1400019c3: cmp r15, r9
         // 1400019c6: jz 0x1400019e2
      [-]4489f983e10f4a8d0448
         // 1400019c8: mov b4 ecx, b4 r15d
         // 1400019cb: and b4 ecx, b4 0xf
         // 1400019ce: lea rax, ds:[rax+r9*0x2]
      [-]66c704505c0048ffc24839d175f2
         // 1400019d4: mov b2 ds:[rax+rdx*0x2], b2 0x5c
         // 1400019da: inc rdx
         // 1400019dd: cmp rcx, rdx
         // 1400019e0: jnz 0x1400019d4
      [-]4c89850802000040f6c7010f8454fcffff
         // 1400019e5: mov ss:[rbp+0x208], r8
         // 1400019ec: test b1 dil, b1 0x1
         // 1400019f0: jz 0x14000164a
      [-]31ff66833e000f95c34c3b8500020000751d
         // 1400019f6: xor b4 edi, b4 edi
         // 1400019f8: cmp b2 ds:[rsi], b2 0x0
         // 1400019fc: setnz b1 bl
         // 1400019ff: cmp r8, ss:[rbp+0x200]
         // 140001a06: jnz 0x140001a25
      [-]488d8df80100004c89c2e8f96601004c8ba5f80100004c8b8508020000
         // 140001a08: lea rcx, ss:[rbp+0x1f8]
         // 140001a0f: mov rdx, r8
         // 140001a12: call 0x140018110
         // 140001a17: mov r12, ss:[rbp+0x1f8]
         // 140001a1e: mov r8, ss:[rbp+0x208]
      [-]4088df488d347e6643c704442200e994fdffff
         // 140001a25: mov b1 dil, b1 bl
         // 140001a28: lea rsi, ds:[rsi+rdi*0x2]
         // 140001a2c: mov b2 ds:[r12+r8*0x2], b2 0x22
         // 140001a33: jmp 0x1400017cc
      [-]488d4d60e8bfb801008a4578488b55603c027574
         // 140001a38: lea rcx, ss:[rbp+0x60]
         // 140001a3c: call 0x14001d300
         // 140001a41: mov b1 al, b1 ss:[rbp+0x78]
         // 140001a44: mov rdx, ss:[rbp+0x60]
         // 140001a48: cmp b1 al, b1 0x2
         // 140001a4a: jnz 0x140001ac0
      [-]48c785f8010000010000000f57c00f118500020000c685100200000189d083e00383f8017578
         // 140001a4c: mov ss:[rbp+0x1f8], 0x1
         // 140001a57: xorps b16 xmm0, b16 xmm0
         // 140001a5a: movups b16 ss:[rbp+0x200], b16 xmm0
         // 140001a61: mov b1 ss:[rbp+0x210], b1 0x1
         // 140001a68: mov b4 eax, b4 edx
         // 140001a6a: and b4 eax, b4 0x3
         // 140001a6d: cmp b4 eax, b4 0x1
         // 140001a70: jnz 0x140001aea
      [-]488d42ff48898538010000488b4aff48899578010000488b4207ff10488b8578010000488b40074883780800488bb538010000740c
         // 140001a72: lea rax, ds:[rdx+0xffffffffffffffff]
         // 140001a76: mov ss:[rbp+0x138], rax
         // 140001a7d: mov rcx, ds:[rdx+0xffffffffffffffff]
         // 140001a81: mov ss:[rbp+0x178], rdx
         // 140001a88: mov rax, ds:[rdx+0x7]
         // 140001a8c: call ds:[rax]
         // 140001a8e: mov rax, ss:[rbp+0x178]
         // 140001a95: mov rax, ds:[rax+0x7]
         // 140001a99: cmp ds:[rax+0x8], 0x0
         // 140001a9e: mov rsi, ss:[rbp+0x138]
         // 140001aa5: jz 0x140001ab3
      [-]488b5010488b0ee84d550000
         // 140001aa7: mov rdx, ds:[rax+0x10]
         // 140001aab: mov rcx, ds:[rsi]
         // 140001aae: call 0x140007000
      [-]6a085a4889f1e842550000eb2a
         // 140001ab3: push 0x8
         // 140001ab5: pop rdx
         // 140001ab6: mov rcx, rsi
         // 140001ab9: call 0x140007000
         // 140001abe: jmp 0x140001aea
      [-]0f1045680f1185000200008b4d79898d????????8b4d7c898d????????488995f8010000888510020000
         // 140001ac0: movups b16 xmm0, b16 ss:[rbp+0x68]
         // 140001ac4: movups b16 ss:[rbp+0x200], b16 xmm0
         // 140001acb: mov b4 ecx, b4 ss:[rbp+0x79]
         // 140001ace: mov b4 ss:[rbp+0x211], b4 ecx
         // 140001ad4: mov b4 ecx, b4 ss:[rbp+0x7c]
         // 140001ad7: mov b4 ss:[rbp+0x214], b4 ecx
         // 140001add: mov ss:[rbp+0x1f8], rdx
         // 140001ae4: mov b1 ss:[rbp+0x210], b1 al
      [-]488d8db001000031d2e868ba0100488bbdb0010000488bb5c00100004889f048c1e0050f1085f80100000f108d080200000f114c07100f11040748ffc6488b9db8010000e9a4000000
         // 140001aea: lea rcx, ss:[rbp+0x1b0]
         // 140001af1: xor b4 edx, b4 edx
         // 140001af3: call 0x14001d560
         // 140001af8: mov rdi, ss:[rbp+0x1b0]
         // 140001aff: mov rsi, ss:[rbp+0x1c0]
         // 140001b06: mov rax, rsi
         // 140001b09: shl rax, b1 0x5
         // 140001b0d: movups b16 xmm0, b16 ss:[rbp+0x1f8]
         // 140001b14: movups b16 xmm1, b16 ss:[rbp+0x208]
         // 140001b1b: movups b16 ds:[rdi+rax+0x10], b16 xmm1
         // 140001b20: movups b16 ds:[rdi+rax], b16 xmm0
         // 140001b24: inc rsi
         // 140001b27: mov rbx, ss:[rbp+0x1b8]
         // 140001b2e: jmp 0x140001bd7
      [-]4d85c07515
         // 140001b33: test r8, r8
         // 140001b36: jnz 0x140001b4d
      [-]4584f67510
         // 140001b38: test b1 r14b, b1 r14b
         // 140001b3b: jnz 0x140001b4d
      [-]488bbdb0010000488bb5c0010000eb58
         // 140001b3d: mov rdi, ss:[rbp+0x1b0]
         // 140001b44: mov rsi, ss:[rbp+0x1c0]
         // 140001b4b: jmp 0x140001ba5
      [-]488b95f8010000488d4d60e873750100488bb5c0010000483bb5b80100007516
         // 140001b4d: mov rdx, ss:[rbp+0x1f8]
         // 140001b54: lea rcx, ss:[rbp+0x60]
         // 140001b58: call 0x1400190d0
         // 140001b5d: mov rsi, ss:[rbp+0x1c0]
         // 140001b64: cmp rsi, ss:[rbp+0x1b8]
         // 140001b6b: jnz 0x140001b83
      [-]488d8db00100004889f2e8e4b90100488bb5c0010000
         // 140001b6d: lea rcx, ss:[rbp+0x1b0]
         // 140001b74: mov rdx, rsi
         // 140001b77: call 0x14001d560
         // 140001b7c: mov rsi, ss:[rbp+0x1c0]
      [-]488bbdb00100004889f048c1e0050f1045600f104d700f114c07100f11040748ffc6
         // 140001b83: mov rdi, ss:[rbp+0x1b0]
         // 140001b8a: mov rax, rsi
         // 140001b8d: shl rax, b1 0x5
         // 140001b91: movups b16 xmm0, b16 ss:[rbp+0x60]
         // 140001b95: movups b16 xmm1, b16 ss:[rbp+0x70]
         // 140001b99: movups b16 ds:[rdi+rax+0x10], b16 xmm1
         // 140001b9e: movups b16 ds:[rdi+rax], b16 xmm0
         // 140001ba2: inc rsi
      [-]488b9db80100004883bd0002000000740f
         // 140001ba5: mov rbx, ss:[rbp+0x1b8]
         // 140001bac: cmp ss:[rbp+0x200], 0x0
         // 140001bb4: jz 0x140001bc5
      [-]488b8df80100006a025ae83b540000
         // 140001bb6: mov rcx, ss:[rbp+0x1f8]
         // 140001bbd: push 0x2
         // 140001bbf: pop rdx
         // 140001bc0: call 0x140007000
      [-]48837d2800740b
         // 140001bc5: cmp ss:[rbp+0x28], 0x0
         // 140001bca: jz 0x140001bd7
      [-]6a025a4c89e9e829540000
         // 140001bcc: push 0x2
         // 140001bce: pop rdx
         // 140001bcf: mov rcx, r13
         // 140001bd2: call 0x140007000
      [-]48c1e6054801fe488d95f801000048893a48895a0848897a1048897218488d75604889f1e8a0ba010048833e000f84bf020000
         // 140001bd7: shl rsi, b1 0x5
         // 140001bdb: add rsi, rdi
         // 140001bde: lea rdx, ss:[rbp+0x1f8]
         // 140001be5: mov ds:[rdx], rdi
         // 140001be8: mov ds:[rdx+0x8], rbx
         // 140001bec: mov ds:[rdx+0x10], rdi
         // 140001bf0: mov ds:[rdx+0x18], rsi
         // 140001bf4: lea rsi, ss:[rbp+0x60]
         // 140001bf8: mov rcx, rsi
         // 140001bfb: call 0x14001d6a0
         // 140001c00: cmp ds:[rsi], 0x0
         // 140001c04: jz 0x140001ec9
      [-]6a0358488b8d10020000482b8d0802000048c1e9054883f904480f42c848b8555555555555550531f64839c10f92c00f8358480000
         // 140001c0a: push 0x3
         // 140001c0c: pop rax
         // 140001c0d: mov rcx, ss:[rbp+0x210]
         // 140001c14: sub rcx, ss:[rbp+0x208]
         // 140001c1b: shr rcx, b1 0x5
         // 140001c1f: cmp rcx, 0x4
         // 140001c23: cmovb rcx, rax
         // 140001c27: mov rax, 0x555555555555555
         // 140001c31: xor b4 esi, b4 esi
         // 140001c33: cmp rcx, rax
         // 140001c36: setb b1 al
         // 140001c39: jnb 0x140006497
      [-]48ffc148898d38010000486bf9184088c648c1e6034889f94889f2e83ff8ffff4885c00f84ca490000
         // 140001c3f: inc rcx
         // 140001c42: mov ss:[rbp+0x138], rcx
         // 140001c49: imul rdi, rcx, b1 0x18
         // 140001c4d: mov b1 sil, b1 al
         // 140001c50: shl rsi, b1 0x3
         // 140001c54: mov rcx, rdi
         // 140001c57: mov rdx, rsi
         // 140001c5a: call 0x14000149e
         // 140001c5f: test rax, rax
         // 140001c62: jz 0x140006632
      [-]6a015e488d7d60488b4f10488948100f1007488985780100000f11000f1085f80100000f108d080200000f294f100f29076a02415e6a18415d488d9d600100004c8dbdb00100004c8d6520
         // 140001c68: push 0x1
         // 140001c6a: pop rsi
         // 140001c6b: lea rdi, ss:[rbp+0x60]
         // 140001c6f: mov rcx, ds:[rdi+0x10]
         // 140001c73: mov ds:[rax+0x10], rcx
         // 140001c77: movups b16 xmm0, b16 ds:[rdi]
         // 140001c7a: mov ss:[rbp+0x178], rax
         // 140001c81: movups b16 ds:[rax], b16 xmm0
         // 140001c84: movups b16 xmm0, b16 ss:[rbp+0x1f8]
         // 140001c8b: movups b16 xmm1, b16 ss:[rbp+0x208]
         // 140001c92: movaps b16 ds:[rdi+0x10], b16 xmm1
         // 140001c96: movaps b16 ds:[rdi], b16 xmm0
         // 140001c99: push 0x2
         // 140001c9b: pop r14
         // 140001c9d: push 0x18
         // 140001c9f: pop r13
         // 140001ca1: lea rbx, ss:[rbp+0x160]
         // 140001ca8: lea r15, ss:[rbp+0x1b0]
         // 140001caf: lea r12, ss:[rbp+0x20]
      [-]4889d94889fae8e2b901004883bd60010000000f84ef000000
         // 140001cb3: mov rcx, rbx
         // 140001cb6: mov rdx, rdi
         // 140001cb9: call 0x14001d6a0
         // 140001cbe: cmp ss:[rbp+0x160], 0x0
         // 140001cc6: jz 0x140001dbb
      [-]483bb5380100000f85b3000000
         // 140001ccc: cmp rsi, ss:[rbp+0x138]
         // 140001cd3: jnz 0x140001d8c
      [-]488b4578482b457048c1e80548ffc04801f00f82a6470000
         // 140001cd9: mov rax, ss:[rbp+0x78]
         // 140001cdd: sub rax, ss:[rbp+0x70]
         // 140001ce1: shr rax, b1 0x5
         // 140001ce5: inc rax
         // 140001ce8: add rax, rsi
         // 140001ceb: jb 0x140006497
      [-]4c89f14939c67703
         // 140001cf1: mov rcx, r14
         // 140001cf4: cmp r14, rax
         // 140001cf7: ja 0x140001cfc
      [-]4883f9057303
         // 140001cfc: cmp rcx, 0x5
         // 140001d00: jnb 0x140001d05
      [-]4531c048b856555555555555054839c1410f92c048898d38010000486bd11849c1e0034885f67414
         // 140001d05: xor b4 r8d, b4 r8d
         // 140001d08: mov rax, 0x555555555555556
         // 140001d12: cmp rcx, rax
         // 140001d15: setb b1 r8b
         // 140001d19: mov ss:[rbp+0x138], rcx
         // 140001d20: imul rdx, rcx, b1 0x18
         // 140001d24: shl r8, b1 0x3
         // 140001d28: test rsi, rsi
         // 140001d2b: jz 0x140001d41
      [-]488b8578010000488945204c896d286a0858eb02
         // 140001d2d: mov rax, ss:[rbp+0x178]
         // 140001d34: mov ss:[rbp+0x20], rax
         // 140001d38: mov ss:[rbp+0x28], r13
         // 140001d3c: push 0x8
         // 140001d3e: pop rax
         // 140001d3f: jmp 0x140001d43
      [-]488945304c89f94d89e1e8b65b00004883bdb001000000488b8db80100007422
         // 140001d43: mov ss:[rbp+0x30], rax
         // 140001d47: mov rcx, r15
         // 140001d4a: mov r9, r12
         // 140001d4d: call 0x140007908
         // 140001d52: cmp ss:[rbp+0x1b0], 0x0
         // 140001d5a: mov rcx, ss:[rbp+0x1b8]
         // 140001d61: jz 0x140001d85
      [-]488b95c00100004889b53801000048b801000000000000804839c2740c
         // 140001d63: mov rdx, ss:[rbp+0x1c0]
         // 140001d6a: mov ss:[rbp+0x138], rsi
         // 140001d71: mov rax, 0x8000000000000001
         // 140001d7b: cmp rdx, rax
         // 140001d7e: jz 0x140001d8c
      [-]e909470000
         // 140001d80: jmp 0x14000648e
      [-]4885d20f85a1010000
         // 14000648e: test rdx, rdx
         // 140006491: jnz 0x140006638
      [-]e8b40b0000
         // 140006497: call 0x140007050
      [-]4c8d054bbf0300e9a1feffff
         // 1400064b6: lea r8, cs:[0x140042408]
         // 1400064bd: jmp 0x140006363
      [-]488d0d7fbd03004c8d0598bd0300eb0e
         // 1400064c2: lea rcx, cs:[0x140042248]
         // 1400064c9: lea r8, cs:[0x140042268]
         // 1400064d0: jmp 0x1400064e0
      [-]488d0d6fbd03004c8d05d0bd0300
         // 1400064d2: lea rcx, cs:[0x140042248]
         // 1400064d9: lea r8, cs:[0x1400422b0]
      [-]6a1ee928ffffff
         // 1400064e0: push 0x1e
         // 1400064e2: jmp 0x14000640f
      [-]4829c1bb????????4889c831d248f7f34889c16bc264bb????????31d2f7f34c8d456049890841895008488d0565d203004889442420488d0d35d203004c8d0dd2b003006a1de941020000
         // 1400064fa: sub rcx, rax
         // 1400064fd: mov b4 ebx, b4 0x989680
         // 140006502: mov rax, rcx
         // 140006505: xor b4 edx, b4 edx
         // 140006507: div rbx
         // 14000650a: mov rcx, rax
         // 14000650d: imul b4 eax, b4 edx, b1 0x64
         // 140006510: mov b4 ebx, b4 0x3b9aca00
         // 140006515: xor b4 edx, b4 edx
         // 140006517: div b4 ebx
         // 140006519: lea r8, ss:[rbp+0x60]
         // 14000651d: mov ds:[r8], rcx
         // 140006520: mov b4 ds:[r8+0x8], b4 edx
         // 140006524: lea rax, cs:[0x140043790]
         // 14000652b: mov ss:[rsp+0x20], rax
         // 140006530: lea rcx, cs:[0x14004376c]
         // 140006537: lea r9, cs:[0x140041610]
         // 14000653e: push 0x1d
         // 140006540: jmp 0x140006786
      [-]e86b200000488d8d6001000048890148898df8010000488d05c6d20300488d4d604889016a0158488941084883611000488d153453010048899500020000488d95f80100004889512048894128488d159fd20300eb54
         // 140006545: call 0x1400085b5
         // 14000654a: lea rcx, ss:[rbp+0x160]
         // 140006551: mov ds:[rcx], rax
         // 140006554: mov ss:[rbp+0x1f8], rcx
         // 14000655b: lea rax, cs:[0x140043828]
         // 140006562: lea rcx, ss:[rbp+0x60]
         // 140006566: mov ds:[rcx], rax
         // 140006569: push 0x1
         // 14000656b: pop rax
         // 14000656c: mov ds:[rcx+0x8], rax
         // 140006570: and ds:[rcx+0x10], 0x0
         // 140006575: lea rdx, cs:[0x14001b8b0]
         // 14000657c: mov ss:[rbp+0x200], rdx
         // 140006583: lea rdx, ss:[rbp+0x1f8]
         // 14000658a: mov ds:[rcx+0x20], rdx
         // 14000658e: mov ds:[rcx+0x28], rax
         // 140006592: lea rdx, cs:[0x140043838]
         // 140006599: jmp 0x1400065ef
      [-]e815200000488d8d6001000048890148898df8010000488d0520d20300488d4d604889016a0158488941084883611000488d15de52010048899500020000488d95f80100004889512048894128488d15f9d10300
         // 14000659b: call 0x1400085b5
         // 1400065a0: lea rcx, ss:[rbp+0x160]
         // 1400065a7: mov ds:[rcx], rax
         // 1400065aa: mov ss:[rbp+0x1f8], rcx
         // 1400065b1: lea rax, cs:[0x1400437d8]
         // 1400065b8: lea rcx, ss:[rbp+0x60]
         // 1400065bc: mov ds:[rcx], rax
         // 1400065bf: push 0x1
         // 1400065c1: pop rax
         // 1400065c2: mov ds:[rcx+0x8], rax
         // 1400065c6: and ds:[rcx+0x10], 0x0
         // 1400065cb: lea rdx, cs:[0x14001b8b0]
         // 1400065d2: mov ss:[rbp+0x200], rdx
         // 1400065d9: lea rdx, ss:[rbp+0x1f8]
         // 1400065e0: mov ds:[rcx+0x20], rdx
         // 1400065e4: mov ds:[rcx+0x28], rax
         // 1400065e8: lea rdx, cs:[0x1400437e8]
      [-]e81c790300
         // 1400065ef: call 0x14003df10
      [-]488d0da7c003004c8d0524c103006a1ceb22
         // 1400065f6: lea rcx, cs:[0x1400426a4]
         // 1400065fd: lea r8, cs:[0x140042728]
         // 140006604: push 0x1c
         // 140006606: jmp 0x14000662a
      [-]488d0d31c103004c8d050ace03006a0ceb10
         // 140006608: lea rcx, cs:[0x140042740]
         // 14000660f: lea r8, cs:[0x140043420]
         // 140006616: push 0xc
         // 140006618: jmp 0x14000662a
      [-]488d0defce03004c8d0570cf03006a1f
         // 14000661a: lea rcx, cs:[0x140043510]
         // 140006621: lea r8, cs:[0x140043598]
         // 140006628: push 0x1f
      [-]5ae8207a0300
         // 14000662a: pop rdx
         // 14000662b: call 0x14003e050
      [-]4889f94889f2
         // 140006632: mov rcx, rdi
         // 140006635: mov rdx, rsi
      [-]e803780300
         // 140006638: call 0x14003de40
      [-]488d0ddaa003004c8d05fba003006a23ebd9
         // 14000663f: lea rcx, cs:[0x140040720]
         // 140006646: lea r8, cs:[0x140040748]
         // 14000664d: push 0x23
         // 14000664f: jmp 0x14000662a
      [-]488d0da0ac03004c8d0531ad03006a33ebc7
         // 140006651: lea rcx, cs:[0x1400412f8]
         // 140006658: lea r8, cs:[0x140041390]
         // 14000665f: push 0x33
         // 140006661: jmp 0x14000662a
      [-]0fb78584010000668985b40100008b85????????8985????????488d4d60e892aaffffeb03
         // 140006663: movzx b4 eax, b2 ss:[rbp+0x184]
         // 14000666a: mov b2 ss:[rbp+0x1b4], b2 ax
         // 140006671: mov b4 eax, b4 ss:[rbp+0x180]
         // 140006677: mov b4 ss:[rbp+0x1b0], b4 eax
         // 14000667d: lea rcx, ss:[rbp+0x60]
         // 140006681: call 0x140001118
         // 140006686: jmp 0x14000668b
      [-]4c8d4560418818458870018b85????????418940020fb785b401000066418940064d896808488d0591a303004889442420488d0da5f203004c8d0d769f03006a2be9b5000000
         // 14000668b: lea r8, ss:[rbp+0x60]
         // 14000668f: mov b1 ds:[r8], b1 bl
         // 140006692: mov b1 ds:[r8+0x1], b1 r14b
         // 140006696: mov b4 eax, b4 ss:[rbp+0x1b0]
         // 14000669c: mov b4 ds:[r8+0x2], b4 eax
         // 1400066a0: movzx b4 eax, b2 ss:[rbp+0x1b4]
         // 1400066a7: mov b2 ds:[r8+0x6], b2 ax
         // 1400066ac: mov ds:[r8+0x8], r13
         // 1400066b0: lea rax, cs:[0x140040a48]
         // 1400066b7: mov ss:[rsp+0x20], rax
         // 1400066bc: lea rcx, cs:[0x140045968]
         // 1400066c3: lea r9, cs:[0x140040640]
         // 1400066ca: push 0x2b
         // 1400066cc: jmp 0x140006786
      [-]4c8d0550a603004889c1488b95a8010000e8e9780300
         // 1400066d1: lea r8, cs:[0x140040d28]
         // 1400066d8: mov rcx, rax
         // 1400066db: mov rdx, ss:[rbp+0x1a8]
         // 1400066e2: call 0x14003dfd0
      [-]488d0d50a603004c8d0579a603006a2ae92cffffff
         // 1400066e9: lea rcx, cs:[0x140040d40]
         // 1400066f0: lea r8, cs:[0x140040d70]
         // 1400066f7: push 0x2a
         // 1400066f9: jmp 0x14000662a
      [-]6a015a4889f1e92fffffff
         // 1400066fe: push 0x1
         // 140006700: pop rdx
         // 140006701: mov rcx, rsi
         // 140006704: jmp 0x140006638
      [-]4c8d85f8010000498908488d05cea303004889442420488d0df70204004c8d0df39e03006a05eb55
         // 140006709: lea r8, ss:[rbp+0x1f8]
         // 140006710: mov ds:[r8], rcx
         // 140006713: lea rax, cs:[0x140040ae8]
         // 14000671a: mov ss:[rsp+0x20], rax
         // 14000671f: lea rcx, cs:[0x140046a1d]
         // 140006726: lea r9, cs:[0x140040620]
         // 14000672d: push 0x5
         // 14000672f: jmp 0x140006786
      [-]4c8d4560488b9570020000498910488b9530010000498950084989781049894018418848208b85????????8b8d????????4189402141894824488d0577a203004889442420488d0d5ba203004c8d0d7c9e03006a0c
         // 140006731: lea r8, ss:[rbp+0x60]
         // 140006735: mov rdx, ss:[rbp+0x270]
         // 14000673c: mov ds:[r8], rdx
         // 14000673f: mov rdx, ss:[rbp+0x130]
         // 140006746: mov ds:[r8+0x8], rdx
         // 14000674a: mov ds:[r8+0x10], rdi
         // 14000674e: mov ds:[r8+0x18], rax
         // 140006752: mov b1 ds:[r8+0x20], b1 cl
         // 140006756: mov b4 eax, b4 ss:[rbp+0x1b0]
         // 14000675c: mov b4 ecx, b4 ss:[rbp+0x1b3]
         // 140006762: mov b4 ds:[r8+0x21], b4 eax
         // 140006766: mov b4 ds:[r8+0x24], b4 ecx
         // 14000676a: lea rax, cs:[0x1400409e8]
         // 140006771: mov ss:[rsp+0x20], rax
         // 140006776: lea rcx, cs:[0x1400409d8]
         // 14000677d: lea r9, cs:[0x140040600]
         // 140006784: push 0xc
      [-]5ae874790300
         // 140006786: pop rdx
         // 140006787: call 0x14003e100
      [-]488d0dbbb203004c8d05dcb203006a275ae85d850300
         // 14000678e: lea rcx, cs:[0x140041a50]
         // 140006795: lea r8, cs:[0x140041a78]
         // 14000679c: push 0x27
         // 14000679e: pop rdx
         // 14000679f: call 0x14003ed01
      [-]e873aaffff
         // 1400067a6: call 0x14000121e
      [-]48895424105541574156415541545657534883ec48488daa800000000f29742430488d8df8010000e8069402000f287424304883c4485b5f5e415c415d415e415f5dc3
         // 1400067ad: mov ss:[rsp+0x10], rdx
         // 1400067b2: push rbp
         // 1400067b3: push r15
         // 1400067b5: push r14
         // 1400067b7: push r13
         // 1400067b9: push r12
         // 1400067bb: push rsi
         // 1400067bc: push rdi
         // 1400067bd: push rbx
         // 1400067be: sub rsp, 0x48
         // 1400067c2: lea rbp, ds:[rdx+0x80]
         // 1400067c9: movaps b16 ss:[rsp+0x30], b16 xmm6
         // 1400067ce: lea rcx, ss:[rbp+0x1f8]
         // 1400067d5: call 0x14002fbe0
         // 1400067da: movaps b16 xmm6, b16 ss:[rsp+0x30]
         // 1400067df: add rsp, 0x48
         // 1400067e3: pop rbx
         // 1400067e4: pop rdi
         // 1400067e5: pop rsi
         // 1400067e6: pop r12
         // 1400067e8: pop r13
         // 1400067ea: pop r14
         // 1400067ec: pop r15
         // 1400067ee: pop rbp
         // 1400067ef: retn 
      [-]48895424105541574156415541545657534883ec48488daa800000000f29742430488d4d60e8060001000f287424304883c4485b5f5e415c415d415e415f5dc3
         // 1400067f0: mov ss:[rsp+0x10], rdx
         // 1400067f5: push rbp
         // 1400067f6: push r15
         // 1400067f8: push r14
         // 1400067fa: push r13
         // 1400067fc: push r12
         // 1400067fe: push rsi
         // 1400067ff: push rdi
         // 140006800: push rbx
         // 140006801: sub rsp, 0x48
         // 140006805: lea rbp, ds:[rdx+0x80]
         // 14000680c: movaps b16 ss:[rsp+0x30], b16 xmm6
         // 140006811: lea rcx, ss:[rbp+0x60]
         // 140006815: call 0x140016820
         // 14000681a: movaps b16 xmm6, b16 ss:[rsp+0x30]
         // 14000681f: add rsp, 0x48
         // 140006823: pop rbx
         // 140006824: pop rdi
         // 140006825: pop rsi
         // 140006826: pop r12
         // 140006828: pop r13
         // 14000682a: pop r14
         // 14000682c: pop r15
         // 14000682e: pop rbp
         // 14000682f: retn 
      [-]48895424105541574156415541545657534883ec48488daa800000000f29742430488b8578010000488b48ff488b4007488b50084c8b4010e823acffff488b8d38010000e897ff00000f287424304883c4485b5f5e415c415d415e415f5dc3
         // 140006830: mov ss:[rsp+0x10], rdx
         // 140006835: push rbp
         // 140006836: push r15
         // 140006838: push r14
         // 14000683a: push r13
         // 14000683c: push r12
         // 14000683e: push rsi
         // 14000683f: push rdi
         // 140006840: push rbx
         // 140006841: sub rsp, 0x48
         // 140006845: lea rbp, ds:[rdx+0x80]
         // 14000684c: movaps b16 ss:[rsp+0x30], b16 xmm6
         // 140006851: mov rax, ss:[rbp+0x178]
         // 140006858: mov rcx, ds:[rax+0xffffffffffffffff]
         // 14000685c: mov rax, ds:[rax+0x7]
         // 140006860: mov rdx, ds:[rax+0x8]
         // 140006864: mov r8, ds:[rax+0x10]
         // 140006868: call 0x140001490
         // 14000686d: mov rcx, ss:[rbp+0x138]
         // 140006874: call 0x140016810
         // 140006879: movaps b16 xmm6, b16 ss:[rsp+0x30]
         // 14000687e: add rsp, 0x48
         // 140006882: pop rbx
         // 140006883: pop rdi
         // 140006884: pop rsi
         // 140006885: pop r12
         // 140006887: pop r13
         // 140006889: pop r14
         // 14000688b: pop r15
         // 14000688d: pop rbp
         // 14000688e: retn 
      [-]48895424105541574156415541545657534883ec48488daa800000000f29742430488d4d60e867ff00000f287424304883c4485b5f5e415c415d415e415f5dc3
         // 14000688f: mov ss:[rsp+0x10], rdx
         // 140006894: push rbp
         // 140006895: push r15
         // 140006897: push r14
         // 140006899: push r13
         // 14000689b: push r12
         // 14000689d: push rsi
         // 14000689e: push rdi
         // 14000689f: push rbx
         // 1400068a0: sub rsp, 0x48
         // 1400068a4: lea rbp, ds:[rdx+0x80]
         // 1400068ab: movaps b16 ss:[rsp+0x30], b16 xmm6
         // 1400068b0: lea rcx, ss:[rbp+0x60]
         // 1400068b4: call 0x140016820
         // 1400068b9: movaps b16 xmm6, b16 ss:[rsp+0x30]
         // 1400068be: add rsp, 0x48
         // 1400068c2: pop rbx
         // 1400068c3: pop rdi
         // 1400068c4: pop rsi
         // 1400068c5: pop r12
         // 1400068c7: pop r13
         // 1400068c9: pop r14
         // 1400068cb: pop r15
         // 1400068cd: pop rbp
         // 1400068ce: retn 
      [-]48895424105541574156415541545657534883ec48488daa800000000f29742430488d4d60e827ff00000f287424304883c4485b5f5e415c415d415e415f5dc3
         // 1400068cf: mov ss:[rsp+0x10], rdx
         // 1400068d4: push rbp
         // 1400068d5: push r15
         // 1400068d7: push r14
         // 1400068d9: push r13
         // 1400068db: push r12
         // 1400068dd: push rsi
         // 1400068de: push rdi
         // 1400068df: push rbx
         // 1400068e0: sub rsp, 0x48
         // 1400068e4: lea rbp, ds:[rdx+0x80]
         // 1400068eb: movaps b16 ss:[rsp+0x30], b16 xmm6
         // 1400068f0: lea rcx, ss:[rbp+0x60]
         // 1400068f4: call 0x140016820
         // 1400068f9: movaps b16 xmm6, b16 ss:[rsp+0x30]
         // 1400068fe: add rsp, 0x48
         // 140006902: pop rbx
         // 140006903: pop rdi
         // 140006904: pop rsi
         // 140006905: pop r12
         // 140006907: pop r13
         // 140006909: pop r14
         // 14000690b: pop r15
         // 14000690d: pop rbp
         // 14000690e: retn 
      [-]48895424105541574156415541545657534883ec48488daa800000000f29742430488d8df8010000e8e4fe00000f287424304883c4485b5f5e415c415d415e415f5dc3
         // 14000690f: mov ss:[rsp+0x10], rdx
         // 140006914: push rbp
         // 140006915: push r15
         // 140006917: push r14
         // 140006919: push r13
         // 14000691b: push r12
         // 14000691d: push rsi
         // 14000691e: push rdi
         // 14000691f: push rbx
         // 140006920: sub rsp, 0x48
         // 140006924: lea rbp, ds:[rdx+0x80]
         // 14000692b: movaps b16 ss:[rsp+0x30], b16 xmm6
         // 140006930: lea rcx, ss:[rbp+0x1f8]
         // 140006937: call 0x140016820
         // 14000693c: movaps b16 xmm6, b16 ss:[rsp+0x30]
         // 140006941: add rsp, 0x48
         // 140006945: pop rbx
         // 140006946: pop rdi
         // 140006947: pop rsi
         // 140006948: pop r12
         // 14000694a: pop r13
         // 14000694c: pop r14
         // 14000694e: pop r15
         // 140006950: pop rbp
         // 140006951: retn 
      [-]48895424105541574156415541545657534883ec48488daa800000000f29742430488b8df8010000488b9500020000e82a1601000f287424304883c4485b5f5e415c415d415e415f5dc3
         // 140006952: mov ss:[rsp+0x10], rdx
         // 140006957: push rbp
         // 140006958: push r15
         // 14000695a: push r14
         // 14000695c: push r13
         // 14000695e: push r12
         // 140006960: push rsi
         // 140006961: push rdi
         // 140006962: push rbx
         // 140006963: sub rsp, 0x48
         // 140006967: lea rbp, ds:[rdx+0x80]
         // 14000696e: movaps b16 ss:[rsp+0x30], b16 xmm6
         // 140006973: mov rcx, ss:[rbp+0x1f8]
         // 14000697a: mov rdx, ss:[rbp+0x200]
         // 140006981: call 0x140017fb0
         // 140006986: movaps b16 xmm6, b16 ss:[rsp+0x30]
         // 14000698b: add rsp, 0x48
         // 14000698f: pop rbx
         // 140006990: pop rdi
         // 140006991: pop rsi
         // 140006992: pop r12
         // 140006994: pop r13
         // 140006996: pop r14
         // 140006998: pop r15
         // 14000699a: pop rbp
         // 14000699b: retn 
      [-]48895424105541574156415541545657534883ec48488daa800000000f29742430488b4d20488b5528e8e61501000f287424304883c4485b5f5e415c415d415e415f5dc3
         // 14000699c: mov ss:[rsp+0x10], rdx
         // 1400069a1: push rbp
         // 1400069a2: push r15
         // 1400069a4: push r14
         // 1400069a6: push r13
         // 1400069a8: push r12
         // 1400069aa: push rsi
         // 1400069ab: push rdi
         // 1400069ac: push rbx
         // 1400069ad: sub rsp, 0x48
         // 1400069b1: lea rbp, ds:[rdx+0x80]
         // 1400069b8: movaps b16 ss:[rsp+0x30], b16 xmm6
         // 1400069bd: mov rcx, ss:[rbp+0x20]
         // 1400069c1: mov rdx, ss:[rbp+0x28]
         // 1400069c5: call 0x140017fb0
         // 1400069ca: movaps b16 xmm6, b16 ss:[rsp+0x30]
         // 1400069cf: add rsp, 0x48
         // 1400069d3: pop rbx
         // 1400069d4: pop rdi
         // 1400069d5: pop rsi
         // 1400069d6: pop r12
         // 1400069d8: pop r13
         // 1400069da: pop r14
         // 1400069dc: pop r15
         // 1400069de: pop rbp
         // 1400069df: retn 
      [-]48895424105541574156415541545657534883ec48488daa800000000f29742430488d8db0010000e8236c01000f287424304883c4485b5f5e415c415d415e415f5dc3
         // 1400069e0: mov ss:[rsp+0x10], rdx
         // 1400069e5: push rbp
         // 1400069e6: push r15
         // 1400069e8: push r14
         // 1400069ea: push r13
         // 1400069ec: push r12
         // 1400069ee: push rsi
         // 1400069ef: push rdi
         // 1400069f0: push rbx
         // 1400069f1: sub rsp, 0x48
         // 1400069f5: lea rbp, ds:[rdx+0x80]
         // 1400069fc: movaps b16 ss:[rsp+0x30], b16 xmm6
         // 140006a01: lea rcx, ss:[rbp+0x1b0]
         // 140006a08: call 0x14001d630
         // 140006a0d: movaps b16 xmm6, b16 ss:[rsp+0x30]
         // 140006a12: add rsp, 0x48
         // 140006a16: pop rbx
         // 140006a17: pop rdi
         // 140006a18: pop rsi
         // 140006a19: pop r12
         // 140006a1b: pop r13
         // 140006a1d: pop r14
         // 140006a1f: pop r15
         // 140006a21: pop rbp
         // 140006a22: retn 
      [-]5556574881ecf0000000488dac248000000048c74558feffffff488d158fe3000031c9ff15df9303004885c00f84bd010000
         // 140006c60: push rbp
         // 140006c61: push rsi
         // 140006c62: push rdi
         // 140006c63: sub rsp, 0xf0
         // 140006c6a: lea rbp, ss:[rsp+0x80]
         // 140006c72: mov ss:[rbp+0x58], 0xfffffffffffffffe
         // 140006c7a: lea rdx, cs:[0x140015010]
         // 140006c81: xor b4 ecx, b4 ecx
         // 140006c83: call cs:[AddVectoredExceptionHandler]
         // 140006c89: test rax, rax
         // 140006c8c: jz 0x140006e4f
      [-]c74520????????488d7d204889f9ff15ca93030085c0750f
         // 140006c92: mov b4 ss:[rbp+0x20], b4 0x5000
         // 140006c99: lea rdi, ss:[rbp+0x20]
         // 140006c9d: mov rcx, rdi
         // 140006ca0: call cs:[SetThreadStackGuarantee]
         // 140006ca6: test b4 eax, b4 eax
         // 140006ca8: jnz 0x140006cb9
      [-]ff15c893030083f8780f85e7010000
         // 140006caa: call cs:[GetLastError]
         // 140006cb0: cmp b4 eax, b4 0x78
         // 140006cb3: jnz 0x140006ea0
      [-]488d0dc0140400ba????????e8e6e40000b9????????e8dc0200004885c00f84b2010000
         // 140006cb9: lea rcx, cs:[0x140048180]
         // 140006cc0: mov b4 edx, b4 0x5
         // 140006cc5: call 0x1400151b0
         // 140006cca: mov b4 ecx, b4 0x5
         // 140006ccf: call 0x140006fb0
         // 140006cd4: test rax, rax
         // 140006cd7: jz 0x140006e8f
      [-]c700????????31c9488d3524f603000f1f4000
         // 140006cdd: mov b4 ds:[rax], b4 0x6e69616d
         // 140006ce3: xor b4 ecx, b4 ecx
         // 140006ce5: lea rsi, cs:[0x140046310]
         // 140006cec: nop b4 ds:[rax+0x0]
      [-]0fb6143184d20f8490000000
         // 140006cf0: movzx b4 edx, b1 ds:[rcx+rsi]
         // 140006cf4: test b1 dl, b1 dl
         // 140006cf6: jz 0x140006d8c
      [-]48ffc14883f90475eb
         // 140006cfc: inc rcx
         // 140006cff: cmp rcx, 0x4
         // 140006d03: jnz 0x140006cf0
      [-]885557c64004004889451048c745180500000048c7450800000000ba????????4889c1e893e500004889c1e84be90000488d0dbca7ffffe81ea3ffff488b05980d05004883f8037431
         // 140006d05: mov b1 ss:[rbp+0x57], b1 dl
         // 140006d08: mov b1 ds:[rax+0x4], b1 0x0
         // 140006d0c: mov ss:[rbp+0x10], rax
         // 140006d10: mov ss:[rbp+0x18], 0x5
         // 140006d18: mov ss:[rbp+0x8], 0x0
         // 140006d20: mov b4 edx, b4 0x5
         // 140006d25: mov rcx, rax
         // 140006d28: call 0x1400152c0
         // 140006d2d: mov rcx, rax
         // 140006d30: call 0x140015680
         // 140006d35: lea rcx, cs:[0x1400014f8]
         // 140006d3c: call 0x14000105f
         // 140006d41: mov rax, cs:[0x140057ae0]
         // 140006d48: cmp rax, 0x3
         // 140006d4c: jz 0x140006d7f
      [-]c645a801488d45a848894520488d053ff603004889442420488d0d730d05004c8d0d440104004c8d452031d2e821750300
         // 140006d4e: mov b1 ss:[rbp+0xffffffffffffffa8], b1 0x1
         // 140006d52: lea rax, ss:[rbp+0xffffffffffffffa8]
         // 140006d56: mov ss:[rbp+0x20], rax
         // 140006d5a: lea rax, cs:[0x1400463a0]
         // 140006d61: mov ss:[rsp+0x20], rax
         // 140006d66: lea rcx, cs:[0x140057ae0]
         // 140006d6d: lea r9, cs:[0x140046eb8]
         // 140006d74: lea r8, ss:[rbp+0x20]
         // 140006d78: xor b4 edx, b4 edx
         // 140006d7a: call 0x14003e2a0
      [-]31c04881c4f00000005f5e5dc3
         // 140006d7f: xor b4 eax, b4 eax
         // 140006d81: add rsp, 0xf0
         // 140006d88: pop rdi
         // 140006d89: pop rsi
         // 140006d8a: pop rbp
         // 140006d8b: retn 
      [-]8855574889450848c745100500000048c745180400000048894d004889e8488945f8c6455400c745????????00488d45
         // 140006d8c: mov b1 ss:[rbp+0x57], b1 dl
         // 140006d8f: mov ss:[rbp+0x8], rax
         // 140006d93: mov ss:[rbp+0x10], 0x5
         // 140006d9b: mov ss:[rbp+0x18], 0x4
         // 140006da3: mov ss:[rbp+0x0], rcx
         // 140006da7: mov rax, rbp
         // 140006daa: mov ss:[rbp+0xfffffffffffffff8], rax
         // 140006dae: mov b1 ss:[rbp+0x54], b1 0x0
         // 140006db2: mov b4 ss:[rbp+0x50], b4 0x0
         // 140006db9: lea rax, ss:[rbp+0xfffffffffffffff8]
         // 140006dbd: mov ss:[rbp+0xffffffffffffffd8], rax
         // 140006dc1: lea rax, cs:[0x1400153d0]
         // 140006dc8: mov ss:[rbp+0xffffffffffffffe0], rax
         // 140006dcc: lea rax, cs:[0x140046378]
         // 140006dd3: mov ss:[rbp+0x20], rax
         // 140006dd7: mov ss:[rbp+0x28], 0x1
         // 140006ddf: mov ss:[rbp+0x30], 0x0
         // 140006de7: lea rax, ss:[rbp+0xffffffffffffffd8]
         // 140006deb: mov ss:[rbp+0x40], rax
         // 140006def: mov ss:[rbp+0x48], 0x1
         // 140006df7: mov ss:[rbp+0xffffffffffffffe8], rdi
         // 140006dfb: lea rax, cs:[0x140009db0]
         // 140006e02: mov ss:[rbp+0xfffffffffffffff0], rax
         // 140006e06: lea rax, cs:[0x140046330]
         // 140006e0d: mov ss:[rbp+0xffffffffffffffa8], rax
         // 140006e11: mov ss:[rbp+0xffffffffffffffb0], 0x2
         // 140006e19: mov ss:[rbp+0xffffffffffffffb8], 0x0
         // 140006e21: lea rax, ss:[rbp+0xffffffffffffffe8]
         // 140006e25: mov ss:[rbp+0xffffffffffffffc8], rax
         // 140006e29: mov ss:[rbp+0xffffffffffffffd0], 0x1
         // 140006e31: lea rcx, ss:[rbp+0x50]
         // 140006e35: lea rdx, ss:[rbp+0xffffffffffffffa8]
         // 140006e39: call 0x140015440
         // 140006e3e: mov rcx, rax
         // 140006e41: call 0x140015560
         // 140006e46: mov b4 ecx, b4 0x7
         // 140006e4b: int b1 0x29

  }
  condition:
    all of them
}
