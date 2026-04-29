rule banload_10_3 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         488d0d89aa0900e9388b0900
         // 140001000: lea rcx, cs:[0x14009ba90]
         // 140001007: jmp atexit
      [-]488d0d81aa0900e92c8b0900
         // 14000100c: lea rcx, cs:[0x14009ba94]
         // 140001013: jmp atexit
      [-]40534883ec20b9????????e8a08809004889442430488bd84885c0743b
         // 140001018: push rbx
         // 14000101a: sub rsp, 0x20
         // 14000101e: mov b4 ecx, b4 0x1068
         // 140001023: call ??2@YAPEAX_K@Z
         // 140001028: mov ss:[rsp+0x30], rax
         // 14000102d: mov rbx, rax
         // 140001030: test rax, rax
         // 140001033: jz 0x140001070
      [-]33d241b8????????488bc8e8b39b0900488d8b00100000ba????????e8d38709004883a350100000004883a358100000004883a36010000000eb02
         // 140001035: xor b4 edx, b4 edx
         // 140001037: mov b4 r8d, b4 0x1000
         // 14000103d: mov rcx, rax
         // 140001040: call memset
         // 140001045: lea rcx, ds:[rbx+0x1000]
         // 14000104c: mov b4 edx, b4 0x2
         // 140001051: call _Mtx_init_in_situ
         // 140001056: and ds:[rbx+0x1050], 0x0
         // 14000105e: and ds:[rbx+0x1058], 0x0
         // 140001066: and ds:[rbx+0x1060], 0x0
         // 14000106e: jmp 0x140001072
      [-]48891da74f0b004883c4205bc3
         // 140001072: mov cs:[0x1400b6020], rbx
         // 140001079: add rsp, 0x20
         // 14000107d: pop rbx
         // 14000107e: retn 
      [-]488d0d11aa0900e9b88a0900
         // 140001080: lea rcx, cs:[0x14009ba98]
         // 140001087: jmp atexit
      [-]4883ec28b9????????e82e880900488d0d03aa0900488900488940084889401066c740180101488325ae4f0b0000488905974f0b004883c428e97a8a0900
         // 14000108c: sub rsp, 0x28
         // 140001090: mov b4 ecx, b4 0x30
         // 140001095: call ??2@YAPEAX_K@Z
         // 14000109a: lea rcx, cs:[0x14009baa4]
         // 1400010a1: mov ds:[rax], rax
         // 1400010a4: mov ds:[rax+0x8], rax
         // 1400010a8: mov ds:[rax+0x10], rax
         // 1400010ac: mov b2 ds:[rax+0x18], b2 0x101
         // 1400010b2: and cs:[0x1400b6068], 0x0
         // 1400010ba: mov cs:[0x1400b6058], rax
         // 1400010c1: add rsp, 0x28
         // 1400010c5: jmp atexit
      [-]488d0d2daa0900e96c8a0900
         // 1400010cc: lea rcx, cs:[0x14009bb00]
         // 1400010d3: jmp atexit
      [-]4883ec28b9????????e8e2870900488d0d1faa0900488900488940084889401066c740180101488325924f0b00004889057b4f0b004883c428e92e8a0900
         // 1400010d8: sub rsp, 0x28
         // 1400010dc: mov b4 ecx, b4 0x30
         // 1400010e1: call ??2@YAPEAX_K@Z
         // 1400010e6: lea rcx, cs:[0x14009bb0c]
         // 1400010ed: mov ds:[rax], rax
         // 1400010f0: mov ds:[rax+0x8], rax
         // 1400010f4: mov ds:[rax+0x10], rax
         // 1400010f8: mov b2 ds:[rax+0x18], b2 0x101
         // 1400010fe: and cs:[0x1400b6098], 0x0
         // 140001106: mov cs:[0x1400b6088], rax
         // 14000110d: add rsp, 0x28
         // 140001111: jmp atexit
      [-]4883ec28488d158de70900488d0d764f0b00e8edec0100488d0d32aa09004883c428e9058a0900
         // 140001118: sub rsp, 0x28
         // 14000111c: lea rdx, cs:[0x14009f8b0]
         // 140001123: lea rcx, cs:[0x1400b60a0]
         // 14000112a: call 0x14001fe1c
         // 14000112f: lea rcx, cs:[0x14009bb68]
         // 140001136: add rsp, 0x28
         // 14000113a: jmp atexit
      [-]4883ec28488d1565e70900488d0d5e4f0b00e8c5ec0100488d0d16aa09004883c428e9dd890900
         // 140001140: sub rsp, 0x28
         // 140001144: lea rdx, cs:[0x14009f8b0]
         // 14000114b: lea rcx, cs:[0x1400b60b0]
         // 140001152: call 0x14001fe1c
         // 140001157: lea rcx, cs:[0x14009bb74]
         // 14000115e: add rsp, 0x28
         // 140001162: jmp atexit
      [-]4883ec28488d15c5ed0900488d0d7e4f0b00e89dec0100488d0d5eaa09004883c428e9b5890900
         // 140001168: sub rsp, 0x28
         // 14000116c: lea rdx, cs:[0x14009ff38]
         // 140001173: lea rcx, cs:[0x1400b60f8]
         // 14000117a: call 0x14001fe1c
         // 14000117f: lea rcx, cs:[0x14009bbe4]
         // 140001186: add rsp, 0x28
         // 14000118a: jmp atexit
      [-]488d0d59aa0900e9a8890900
         // 140001190: lea rcx, cs:[0x14009bbf0]
         // 140001197: jmp atexit
      [-]488d0d2d500b00e99c1e0800
         // 14000119c: lea rcx, cs:[0x1400b61d0]
         // 1400011a3: jmp 0x140083044
      [-]488d0dc1640b00e900330800
         // 1400011d0: lea rcx, cs:[0x1400b7698]
         // 1400011d7: jmp 0x1400844dc
      [-]488d0d7daa0900e95c890900
         // 1400011dc: lea rcx, cs:[0x14009bc60]
         // 1400011e3: jmp atexit
      [-]488d05e9003400c3
         // 1400011f0: lea rax, cs:[0x1403412e0]
         // 1400011f7: retn 
      [-]48895424104c894424184c894c24205356574883ec30488bfa488d742460488bd9e8caffffff4533c948897424204c8bc7488bd3488b08ff15a3b609004883c4305f5e5bc3
         // 140001200: mov ss:[rsp+0x10], rdx
         // 140001205: mov ss:[rsp+0x18], r8
         // 14000120a: mov ss:[rsp+0x20], r9
         // 14000120f: push rbx
         // 140001210: push rsi
         // 140001211: push rdi
         // 140001212: sub rsp, 0x30
         // 140001216: mov rdi, rdx
         // 140001219: lea rsi, ss:[rsp+0x60]
         // 14000121e: mov rbx, rcx
         // 140001221: call 0x1400011f0
         // 140001226: xor b4 r9d, b4 r9d
         // 140001229: mov ss:[rsp+0x20], rsi
         // 14000122e: mov r8, rdi
         // 140001231: mov rdx, rbx
         // 140001234: mov rcx, ds:[rax]
         // 140001237: call cs:[__stdio_common_vfprintf]
         // 14000123d: add rsp, 0x30
         // 140001241: pop rdi
         // 140001242: pop rsi
         // 140001243: pop rbx
         // 140001244: retn 
      [-]48895c2408574883ec20488bd9ff15f5b40900488bcb8b38ff15c2420b00ff15e4b40900488b5c243089384883c4205fc3
         // 1400012b0: mov ss:[rsp+0x8], rbx
         // 1400012b5: push rdi
         // 1400012b6: sub rsp, 0x20
         // 1400012ba: mov rbx, rcx
         // 1400012bd: call cs:[_errno]
         // 1400012c3: mov rcx, rbx
         // 1400012c6: mov b4 edi, b4 ds:[rax]
         // 1400012c8: call cs:[0x1400b5590]
         // 1400012ce: call cs:[_errno]
         // 1400012d4: mov rbx, ss:[rsp+0x30]
         // 1400012d9: mov b4 ds:[rax], b4 edi
         // 1400012db: add rsp, 0x20
         // 1400012df: pop rdi
         // 1400012e0: retn 
      [-]48895108488bc1448901c3
         // 1400012f0: mov ds:[rcx+0x8], rdx
         // 1400012f4: mov rax, rcx
         // 1400012f7: mov b4 ds:[rcx], b4 r8d
         // 1400012fa: retn 
      [-]48895c2420574883ec200f57c0488bf9b8????????0fb7ca410f110066418900498bd8ff1567b3090066894302488d53044885ff7417
         // 140001300: mov ss:[rsp+0x20], rbx
         // 140001305: push rdi
         // 140001306: sub rsp, 0x20
         // 14000130a: xorps b16 xmm0, b16 xmm0
         // 14000130d: mov rdi, rcx
         // 140001310: mov b4 eax, b4 0x2
         // 140001315: movzx b4 ecx, b2 dx
         // 140001318: movups b16 ds:[r8], b16 xmm0
         // 14000131c: mov b2 ds:[r8], b2 ax
         // 140001320: mov rbx, r8
         // 140001323: call cs:[htons]
         // 140001329: mov b2 ds:[rbx+0x2], b2 ax
         // 14000132d: lea rdx, ds:[rbx+0x4]
         // 140001331: test rdi, rdi
         // 140001334: jz 0x14000134d
      [-]4885d27412
         // 140001336: test rdx, rdx
         // 140001339: jz 0x14000134d
      [-]488bcf488b5c24484883c4205fe9c3aa0000
         // 14000133b: mov rcx, rdi
         // 14000133e: mov rbx, ss:[rsp+0x48]
         // 140001343: add rsp, 0x20
         // 140001347: pop rdi
         // 140001348: jmp 0x14000be10
      [-]488b5c2448b8????????4883c4205fc3
         // 14000134d: mov rbx, ss:[rsp+0x48]
         // 140001352: mov b4 eax, b4 0xfffffffffffff019
         // 140001357: add rsp, 0x20
         // 14000135b: pop rdi
         // 14000135c: retn 
      [-]48895c24205556574881ec80000000488b05b2410b004833c4488944247833c00f57c0410f110049894010488bf9418940180fb7cab8????????498bf066418900ff15e9b20900ba????????488bcf66894602ff15dfb10900488be84885c07444
         // 140001360: mov ss:[rsp+0x20], rbx
         // 140001365: push rbp
         // 140001366: push rsi
         // 140001367: push rdi
         // 140001368: sub rsp, 0x80
         // 14000136f: mov rax, cs:[__security_cookie]
         // 140001376: xor rax, rsp
         // 140001379: mov ss:[rsp+0x78], rax
         // 14000137e: xor b4 eax, b4 eax
         // 140001380: xorps b16 xmm0, b16 xmm0
         // 140001383: movups b16 ds:[r8], b16 xmm0
         // 140001387: mov ds:[r8+0x10], rax
         // 14000138b: mov rdi, rcx
         // 14000138e: mov b4 ds:[r8+0x18], b4 eax
         // 140001392: movzx b4 ecx, b2 dx
         // 140001395: mov b4 eax, b4 0x17
         // 14000139a: mov rsi, r8
         // 14000139d: mov b2 ds:[r8], b2 ax
         // 1400013a1: call cs:[htons]
         // 1400013a7: mov b4 edx, b4 0x25
         // 1400013ac: mov rcx, rdi
         // 1400013af: mov b2 ds:[rsi+0x2], b2 ax
         // 1400013b3: call cs:[__imp_strchr]
         // 1400013b9: mov rbp, rax
         // 1400013bc: test rax, rax
         // 1400013bf: jz 0x140001405
      [-]488bd8488d4c2420482bdfb8????????4883fb28488bd7480f43d84c8bc3e8089809004883fb280f8391000000
         // 1400013c1: mov rbx, rax
         // 1400013c4: lea rcx, ss:[rsp+0x20]
         // 1400013c9: sub rbx, rdi
         // 1400013cc: mov b4 eax, b4 0x27
         // 1400013d1: cmp rbx, 0x28
         // 1400013d5: mov rdx, rdi
         // 1400013d8: cmovnb rbx, rax
         // 1400013dc: mov r8, rbx
         // 1400013df: call memcpy
         // 1400013e4: cmp rbx, 0x28
         // 1400013e8: jnb 0x14000147f
      [-]488d4d01c6441c2000488d7c2420ff15ceb20900894618
         // 1400013ee: lea rcx, ss:[rbp+0x1]
         // 1400013f2: mov b1 ss:[rsp+rbx+0x20], b1 0x0
         // 1400013f7: lea rdi, ss:[rsp+0x20]
         // 1400013fc: call cs:[atoi]
         // 140001402: mov b4 ds:[rsi+0x18], b4 eax
      [-]4883c6084885ff744c
         // 140001405: add rsi, 0x8
         // 140001409: test rdi, rdi
         // 14000140c: jz 0x14000145a
      [-]4885f67447
         // 14000140e: test rsi, rsi
         // 140001411: jz 0x14000145a
      [-]ba????????488bcf488befff1574b109004885c07424
         // 140001413: mov b4 edx, b4 0x25
         // 140001418: mov rcx, rdi
         // 14000141b: mov rbp, rdi
         // 14000141e: call cs:[__imp_strchr]
         // 140001424: test rax, rax
         // 140001427: jz 0x14000144d
      [-]2bc7488d6c244883f82d7f25
         // 140001429: sub b4 eax, b4 edi
         // 14000142b: lea rbp, ss:[rsp+0x48]
         // 140001430: cmp b4 eax, b4 0x2d
         // 140001433: jg 0x14000145a
      [-]4863d8488d4c24484c8bc3488bd7e8a4970900c6441c4800
         // 140001435: movsxd rbx, b4 eax
         // 140001438: lea rcx, ss:[rsp+0x48]
         // 14000143d: mov r8, rbx
         // 140001440: mov rdx, rdi
         // 140001443: call memcpy
         // 140001448: mov b1 ss:[rsp+rbx+0x48], b1 0x0
      [-]488bd6488bcde898aa0000eb05
         // 14000144d: mov rdx, rsi
         // 140001450: mov rcx, rbp
         // 140001453: call 0x14000bef0
         // 140001458: jmp 0x14000145f
      [-]b8????????
         // 14000145a: mov b4 eax, b4 0xfffffffffffff019
      [-]488b4c24784833cce884870900488b9c24b80000004881c4800000005f5e5dc3
         // 14000145f: mov rcx, ss:[rsp+0x78]
         // 140001464: xor rcx, rsp
         // 140001467: call __security_check_cookie
         // 14000146c: mov rbx, ss:[rsp+0xb8]
         // 140001474: add rsp, 0x80
         // 14000147b: pop rdi
         // 14000147c: pop rsi
         // 14000147d: pop rbp
         // 14000147e: retn 
      [-]e8d08f0900
         // 14000147f: call __report_rangecheckfailure
      [-]4883c104e9e7a50000
         // 140001490: add rcx, 0x4
         // 140001494: jmp 0x14000ba80
      [-]4883c108e997a60000
         // 1400014a0: add rcx, 0x8
         // 1400014a4: jmp 0x14000bb40
      [-]4883ec38837a100c4d8bd1753e
         // 1400014b0: sub rsp, 0x38
         // 1400014b4: cmp b4 ds:[rdx+0x10], b4 0xc
         // 1400014b8: mov r10, r9
         // 1400014bb: jnz 0x1400014fb
      [-]410fb7006683f8027508
         // 1400014bd: movzx b4 eax, b2 ds:[r8]
         // 1400014c1: cmp b2 ax, b2 0x2
         // 1400014c5: jnz 0x1400014cf
      [-]41b9????????eb0c
         // 1400014c7: mov b4 r9d, b4 0x10
         // 1400014cd: jmp 0x1400014db
      [-]6683f8177526
         // 1400014cf: cmp b2 ax, b2 0x17
         // 1400014d3: jnz 0x1400014fb
      [-]41b9????????
         // 1400014d5: mov b4 r9d, b4 0x1c
      [-]4c89542420e8ab76000085c0740b
         // 1400014db: mov ss:[rsp+0x20], r10
         // 1400014e0: call 0x140008b90
         // 1400014e5: test b4 eax, b4 eax
         // 1400014e7: jz 0x1400014f4
      [-]8bc84883c438e99cd30000
         // 1400014e9: mov b4 ecx, b4 eax
         // 1400014eb: add rsp, 0x38
         // 1400014ef: jmp 0x14000e890
      [-]33c04883c438c3
         // 1400014f4: xor b4 eax, b4 eax
         // 1400014f6: add rsp, 0x38
         // 1400014fa: retn 
      [-]b8????????4883c438c3
         // 1400014fb: mov b4 eax, b4 0xfffffffffffff019
         // 140001500: add rsp, 0x38
         // 140001504: retn 
      [-]8379100f7406
         // 140001510: cmp b4 ds:[rcx+0x10], b4 0xf
         // 140001514: jz 0x14000151c
      [-]b8????????c3
         // 140001516: mov b4 eax, b4 0xfffffffffffff019
         // 14000151b: retn 
      [-]8b41580fbae00c7333
         // 14000151c: mov b4 eax, b4 ds:[rcx+0x58]
         // 14000151f: bt b4 eax, b1 0xc
         // 140001523: jnb 0x140001558
      [-]0fbaf00c894158488b4108ff88????????83697c01751c
         // 140001525: btr b4 eax, b1 0xc
         // 140001529: mov b4 ds:[rcx+0x58], b4 eax
         // 14000152c: mov rax, ds:[rcx+0x8]
         // 140001530: dec b4 ds:[rax+0xac]
         // 140001536: sub b4 ds:[rcx+0x7c], b4 0x1
         // 14000153a: jnz 0x140001558
      [-]8b4158a8017515
         // 14000153c: mov b4 eax, b4 ds:[rcx+0x58]
         // 14000153f: test b1 al, b1 0x1
         // 140001541: jnz 0x140001558
      [-]a8047411
         // 140001543: test b1 al, b1 0x4
         // 140001545: jz 0x140001558
      [-]83e0fb894158a8087407
         // 140001547: and b4 eax, b4 0xfffffffffffffffb
         // 14000154a: mov b4 ds:[rcx+0x58], b4 eax
         // 14000154d: test b1 al, b1 0x8
         // 14000154f: jz 0x140001558
      [-]488b4108ff4808
         // 140001551: mov rax, ds:[rcx+0x8]
         // 140001555: dec b4 ds:[rax+0x8]
      [-]48895c2410574533c9448bda488bf9458bd1418bd983fa027247
         // 140001560: mov ss:[rsp+0x10], rbx
         // 140001565: push rdi
         // 140001566: xor b4 r9d, b4 r9d
         // 140001569: mov b4 r11d, b4 edx
         // 14000156c: mov rdi, rcx
         // 14000156f: mov b4 r10d, b4 r9d
         // 140001572: mov b4 ebx, b4 r9d
         // 140001575: cmp b4 edx, b4 0x2
         // 140001578: jb 0x1400015c1
      [-]8d42fe4889742410d1e84c8bc1ffc08bd08d3400488d0c00
         // 14000157a: lea b4 eax, b4 ds:[rdx+0xfffffffffffffffe]
         // 14000157d: mov ss:[rsp+0x10], rsi
         // 140001582: shr b4 eax, b1 0x1
         // 140001584: mov r8, rcx
         // 140001587: inc b4 eax
         // 140001589: mov b4 edx, b4 eax
         // 14000158b: lea b4 esi, b4 ds:[rax+rax]
         // 14000158e: lea rcx, ds:[rax+rax]
      [-]418b004d8d40204c03c8418b40f04c03d04883ea0175e9
         // 140001592: mov b4 eax, b4 ds:[r8]
         // 140001595: lea r8, ds:[r8+0x20]
         // 140001599: add r9, rax
         // 14000159c: mov b4 eax, b4 ds:[r8+0xfffffffffffffff0]
         // 1400015a0: add r10, rax
         // 1400015a3: sub rdx, 0x1
         // 1400015a7: jnz 0x140001592
      [-]413bf3488b742410721d
         // 1400015a9: cmp b4 esi, b4 r11d
         // 1400015ac: mov rsi, ss:[rsp+0x10]
         // 1400015b1: jb 0x1400015d0
      [-]4b8d040a4803c3488b5c24185fc3
         // 1400015b3: lea rax, ds:[r10+r9]
         // 1400015b7: add rax, rbx
         // 1400015ba: mov rbx, ss:[rsp+0x18]
         // 1400015bf: pop rdi
         // 1400015c0: retn 
      [-]4585db7410
         // 1400015c1: test b4 r11d, b4 r11d
         // 1400015c4: jz 0x1400015d6
      [-]498bc90f1f80????????
         // 1400015c6: mov rcx, r9
         // 1400015c9: nop b4 ds:[rax+0x0]
      [-]4803c98b1ccf
         // 1400015d0: add rcx, rcx
         // 1400015d3: mov b4 ebx, b4 ds:[rdi+rcx*0x8]
      [-]4b8d040a4803c3488b5c24185fc3
         // 1400015d6: lea rax, ds:[r10+r9]
         // 1400015da: add rax, rbx
         // 1400015dd: mov rbx, ss:[rsp+0x18]
         // 1400015e2: pop rdi
         // 1400015e3: retn 
      [-]4883ec28488b0515680b004885c0751e
         // 1400015f0: sub rsp, 0x28
         // 1400015f4: mov rax, cs:[0x1400b7e10]
         // 1400015fb: test rax, rax
         // 1400015fe: jnz 0x14000161e
      [-]e87b90000085c07407
         // 140001600: call 0x14000a680
         // 140001605: test b4 eax, b4 eax
         // 140001607: jz 0x140001610
      [-]33c04883c428c3
         // 140001609: xor b4 eax, b4 eax
         // 14000160b: add rsp, 0x28
         // 14000160f: retn 
      [-]488d0509680b00488905f2670b00
         // 140001610: lea rax, cs:[0x1400b7e20]
         // 140001617: mov cs:[0x1400b7e10], rax
      [-]4883c428c3
         // 14000161e: add rsp, 0x28
         // 140001622: retn 
      [-]40564883ec2083792000488bf10f8748020000
         // 140001630: push rsi
         // 140001632: sub rsp, 0x20
         // 140001636: cmp b4 ds:[rcx+0x20], b4 0x0
         // 14000163a: mov rsi, rcx
         // 14000163d: ja 0x14000188b
      [-]488b41104883c110483bc17412
         // 140001643: mov rax, ds:[rcx+0x10]
         // 140001647: add rcx, 0x10
         // 14000164b: cmp rax, rcx
         // 14000164e: jz 0x140001662
      [-]f64038100f8431020000
         // 140001650: test b1 ds:[rax+0x38], b1 0x10
         // 140001654: jz 0x14000188b
      [-]488b00483bc175ee
         // 14000165a: mov rax, ds:[rax]
         // 14000165d: cmp rax, rcx
         // 140001660: jnz 0x140001650
      [-]48895c2430488d0d226a0b0048896c243848897c2440ff158aab09008b15386a0b0033ed488b3dfb690b008bcd85d27e12
         // 140001662: mov ss:[rsp+0x30], rbx
         // 140001667: lea rcx, cs:[0x1400b8090]
         // 14000166e: mov ss:[rsp+0x38], rbp
         // 140001673: mov ss:[rsp+0x40], rdi
         // 140001678: call cs:[EnterCriticalSection]
         // 14000167e: mov b4 edx, b4 cs:[0x1400b80bc]
         // 140001684: xor b4 ebp, b4 ebp
         // 140001686: mov rdi, cs:[0x1400b8088]
         // 14000168d: mov b4 ecx, b4 ebp
         // 14000168f: test b4 edx, b4 edx
         // 140001691: jle 0x1400016a5
      [-]483930740a
         // 140001696: cmp ds:[rax], rsi
         // 140001699: jz 0x1400016a5
      [-]ffc14883c0083bca7cf1
         // 14000169b: inc b4 ecx
         // 14000169d: add rax, 0x8
         // 1400016a1: cmp b4 ecx, b4 edx
         // 1400016a3: jl 0x140001696
      [-]3bca0f84a5000000
         // 1400016a5: cmp b4 ecx, b4 edx
         // 1400016a7: jz 0x140001752
      [-]448d42ff4863c94963c0448905fe690b00488d14c7488b04c7488904cf48892a4585c07526
         // 1400016ad: lea b4 r8d, b4 ds:[rdx+0xffffffffffffffff]
         // 1400016b1: movsxd rcx, b4 ecx
         // 1400016b4: movsxd rax, b4 r8d
         // 1400016b7: mov b4 cs:[0x1400b80bc], b4 r8d
         // 1400016be: lea rdx, ds:[rdi+rax*0x8]
         // 1400016c2: mov rax, ds:[rdi+rax*0x8]
         // 1400016c6: mov ds:[rdi+rcx*0x8], rax
         // 1400016ca: mov ds:[rdx], rbp
         // 1400016cd: test b4 r8d, b4 r8d
         // 1400016d0: jnz 0x1400016f8
      [-]892de0690b00ff15dab00900488bcf8b18ff15a73e0b00ff15c9b0090048892d92690b00eb58
         // 1400016d2: mov b4 cs:[0x1400b80b8], b4 ebp
         // 1400016d8: call cs:[_errno]
         // 1400016de: mov rcx, rdi
         // 1400016e1: mov b4 ebx, b4 ds:[rax]
         // 1400016e3: call cs:[0x1400b5590]
         // 1400016e9: call cs:[_errno]
         // 1400016ef: mov cs:[0x1400b8088], rbp
         // 1400016f6: jmp 0x140001750
      [-]8b05ba690b0083f8207c4f
         // 1400016f8: mov b4 eax, b4 cs:[0x1400b80b8]
         // 1400016fe: cmp b4 eax, b4 0x20
         // 140001701: jl 0x140001752
      [-]992bc2d1f84863d8443bc37d42
         // 140001703: cdq 
         // 140001704: sub b4 eax, b4 edx
         // 140001706: sar b4 eax, b1 0x1
         // 140001708: movsxd rbx, b4 eax
         // 14000170b: cmp b4 r8d, b4 ebx
         // 14000170e: jge 0x140001752
      [-]488bd348c1e2034885d2741d
         // 140001710: mov rdx, rbx
         // 140001713: shl rdx, b1 0x3
         // 140001717: test rdx, rdx
         // 14000171a: jz 0x140001739
      [-]488bcfff155b3e0b004885c07428
         // 14000171c: mov rcx, rdi
         // 14000171f: call cs:[0x1400b5580]
         // 140001725: test rax, rax
         // 140001728: jz 0x140001752
      [-]48890557690b00891d81690b00eb19
         // 14000172a: mov cs:[0x1400b8088], rax
         // 140001731: mov b4 cs:[0x1400b80b8], b4 ebx
         // 140001737: jmp 0x140001752
      [-]ff1579b00900488bcf8b18ff15463e0b00ff1568b00900
         // 140001739: call cs:[_errno]
         // 14000173f: mov rcx, rdi
         // 140001742: mov b4 ebx, b4 ds:[rax]
         // 140001744: call cs:[0x1400b5590]
         // 14000174a: call cs:[_errno]
      [-]488d0d37690b00ff15b9aa09008b8e????????8bc183e00c4889ae080100003c0c7410
         // 140001752: lea rcx, cs:[0x1400b8090]
         // 140001759: call cs:[LeaveCriticalSection]
         // 14000175f: mov b4 ecx, b4 ds:[rsi+0x148]
         // 140001765: mov b4 eax, b4 ecx
         // 140001767: and b4 eax, b4 0xc
         // 14000176a: mov ds:[rsi+0x108], rbp
         // 140001771: cmp b1 al, b1 0xc
         // 140001773: jz 0x140001785
      [-]488b86f8000000ff40088b8e????????
         // 140001775: mov rax, ds:[rsi+0xf8]
         // 14000177c: inc b4 ds:[rax+0x8]
         // 14000177f: mov b4 ecx, b4 ds:[rsi+0x148]
      [-]488b861001000083e1fb83c901898e????????488b8e18010000488901488b8618010000488b8e1001000048894108488b86f8000000ff4808838e????????02488b86080100004885c07409
         // 140001785: mov rax, ds:[rsi+0x110]
         // 14000178c: and b4 ecx, b4 0xfffffffffffffffb
         // 14000178f: or b4 ecx, b4 0x1
         // 140001792: mov b4 ds:[rsi+0x148], b4 ecx
         // 140001798: mov rcx, ds:[rsi+0x118]
         // 14000179f: mov ds:[rcx], rax
         // 1400017a2: mov rax, ds:[rsi+0x118]
         // 1400017a9: mov rcx, ds:[rsi+0x110]
         // 1400017b0: mov ds:[rcx+0x8], rax
         // 1400017b4: mov rax, ds:[rsi+0xf8]
         // 1400017bb: dec b4 ds:[rax+0x8]
         // 1400017be: or b4 ds:[rsi+0x148], b4 0x2
         // 1400017c5: mov rax, ds:[rsi+0x108]
         // 1400017cc: test rax, rax
         // 1400017cf: jz 0x1400017da
      [-]488d8ef0000000ffd0
         // 1400017d1: lea rcx, ds:[rsi+0xf0]
         // 1400017d8: call rax
      [-]488d9e90000000bf????????66660f1f840000000000
         // 1400017da: lea rbx, ds:[rsi+0x90]
         // 1400017e1: mov b4 edi, b4 0x3
         // 1400017e6: nop b2 ds:[rax+rax+0x0]
      [-]488b0b488d41ff4883f8fd7706
         // 1400017f0: mov rcx, ds:[rbx]
         // 1400017f3: lea rax, ds:[rcx+0xffffffffffffffff]
         // 1400017f7: cmp rax, 0xfffffffffffffffd
         // 1400017fb: ja 0x140001803
      [-]ff152dae0900
         // 1400017fd: call cs:[closesocket]
      [-]4883c3084883ef0175e3
         // 140001803: add rbx, 0x8
         // 140001807: sub rdi, 0x1
         // 14000180b: jnz 0x1400017f0
      [-]488d8ec8000000ff15eea90900488d8ec8000000ff15f1a90900488d8ec8000000ff15b4aa0900488b5e58ff157aaf0900488bcb8b38ff15473d0b00ff1569af09008938488b4e3848896e58ff15b1a80900488b05aa650b00488b7c2440483bf0488b5c2430480f44c5488b6c24384889058d650b0033c04883c4205ec3
         // 14000180d: lea rcx, ds:[rsi+0xc8]
         // 140001814: call cs:[EnterCriticalSection]
         // 14000181a: lea rcx, ds:[rsi+0xc8]
         // 140001821: call cs:[LeaveCriticalSection]
         // 140001827: lea rcx, ds:[rsi+0xc8]
         // 14000182e: call cs:[DeleteCriticalSection]
         // 140001834: mov rbx, ds:[rsi+0x58]
         // 140001838: call cs:[_errno]
         // 14000183e: mov rcx, rbx
         // 140001841: mov b4 edi, b4 ds:[rax]
         // 140001843: call cs:[0x1400b5590]
         // 140001849: call cs:[_errno]
         // 14000184f: mov b4 ds:[rax], b4 edi
         // 140001851: mov rcx, ds:[rsi+0x38]
         // 140001855: mov ds:[rsi+0x58], rbp
         // 140001859: call cs:[CloseHandle]
         // 14000185f: mov rax, cs:[0x1400b7e10]
         // 140001866: mov rdi, ss:[rsp+0x40]
         // 14000186b: cmp rsi, rax
         // 14000186e: mov rbx, ss:[rsp+0x30]
         // 140001873: cmovz rax, rbp
         // 140001877: mov rbp, ss:[rsp+0x38]
         // 14000187c: mov cs:[0x1400b7e10], rax
         // 140001883: xor b4 eax, b4 eax
         // 140001885: add rsp, 0x20
         // 140001889: pop rsi
         // 14000188a: retn 
      [-]b8????????4883c4205ec3
         // 14000188b: mov b4 eax, b4 0xfffffffffffff00e
         // 140001890: add rsp, 0x20
         // 140001894: pop rsi
         // 140001895: retn 
      [-]4883ec2885c97907
         // 1400018a0: sub rsp, 0x28
         // 1400018a4: test b4 ecx, b4 ecx
         // 1400018a6: jns 0x1400018af
      [-]33c04883c428c3
         // 1400018a8: xor b4 eax, b4 eax
         // 1400018aa: add rsp, 0x28
         // 1400018ae: retn 
      [-]48895c2420ff156eb00900488bc8488bd8ff159aa8090083e801743c
         // 1400018af: mov ss:[rsp+0x20], rbx
         // 1400018b4: call cs:[_get_osfhandle]
         // 1400018ba: mov rcx, rax
         // 1400018bd: mov rbx, rax
         // 1400018c0: call cs:[GetFileType]
         // 1400018c6: sub b4 eax, b4 0x1
         // 1400018c9: jz 0x140001907
      [-]83e8017420
         // 1400018cb: sub b4 eax, b4 0x1
         // 1400018ce: jz 0x1400018f0
      [-]83f801740c
         // 1400018d0: cmp b4 eax, b4 0x1
         // 1400018d3: jz 0x1400018e1
      [-]488b5c242033c04883c428c3
         // 1400018d5: mov rbx, ss:[rsp+0x20]
         // 1400018da: xor b4 eax, b4 eax
         // 1400018dc: add rsp, 0x28
         // 1400018e0: retn 
      [-]488b5c2420b8????????4883c428c3
         // 1400018e1: mov rbx, ss:[rsp+0x20]
         // 1400018e6: mov b4 eax, b4 0x7
         // 1400018eb: add rsp, 0x28
         // 1400018ef: retn 
      [-]488d542430488bcbff15a2a7090085c0b8????????7505
         // 1400018f0: lea rdx, ss:[rsp+0x30]
         // 1400018f5: mov rcx, rbx
         // 1400018f8: call cs:[GetConsoleMode]
         // 1400018fe: test b4 eax, b4 eax
         // 140001900: mov b4 eax, b4 0xe
         // 140001905: jnz 0x14000190c
      [-]b8????????
         // 140001907: mov b4 eax, b4 0x11
      [-]488b5c24204883c428c3
         // 14000190c: mov rbx, ss:[rsp+0x20]
         // 140001911: add rsp, 0x28
         // 140001915: retn 
      [-]48895c2408574883ec20448b4158488bd9488b790841f6c0010f856b010000
         // 140001920: mov ss:[rsp+0x8], rbx
         // 140001925: push rdi
         // 140001926: sub rsp, 0x20
         // 14000192a: mov b4 r8d, b4 ds:[rcx+0x58]
         // 14000192e: mov rbx, rcx
         // 140001931: mov rdi, ds:[rcx+0x8]
         // 140001935: test b1 r8b, b1 0x1
         // 140001939: jnz 0x140001aaa
      [-]8b4110ffc84889511883f80f0f8789040000
         // 14000193f: mov b4 eax, b4 ds:[rcx+0x10]
         // 140001942: dec b4 eax
         // 140001944: mov ds:[rcx+0x18], rdx
         // 140001948: cmp b4 eax, b4 0xf
         // 14000194b: ja def_140001964
      [-]488d15a8e6ffff48988b8c82f81d00004803caffe1
         // 140001951: lea rdx, cs:[0x140000000]
         // 140001958: cdqe 
         // 14000195a: mov b4 ecx, b4 ds:[rdx+rax*0x4]
         // 140001961: add rcx, rdx
         // 140001964: jmp rcx
      [-]488bd3488b5c24304883c4205fe9687b0000
         // 140001966: mov rdx, rbx
         // 140001969: mov rbx, ss:[rsp+0x30]
         // 14000196e: add rsp, 0x20
         // 140001972: pop rdi
         // 140001973: jmp 0x1400094e0
      [-]488bd3488bcf488b5c24304883c4205fe9d3b50000
         // 140001978: mov rdx, rbx
         // 14000197b: mov rcx, rdi
         // 14000197e: mov rbx, ss:[rsp+0x30]
         // 140001983: add rsp, 0x20
         // 140001987: pop rdi
         // 140001988: jmp 0x14000cf60
      [-]410fbae00c7308
         // 14000198d: bt b4 r8d, b1 0xc
         // 140001992: jnb 0x14000199c
      [-]488bcbe864210000
         // 140001994: mov rcx, rbx
         // 140001997: call 0x140003b00
      [-]8b4b3083f9ff750f
         // 14000199c: mov b4 ecx, b4 ds:[rbx+0x30]
         // 14000199f: cmp b4 ecx, b4 0xffffffffffffffff
         // 1400019a2: jnz 0x1400019b3
      [-]488b8b10010000ff155fa70900eb05
         // 1400019a4: mov rcx, ds:[rbx+0x110]
         // 1400019ab: call cs:[CloseHandle]
         // 1400019b1: jmp 0x1400019b8
      [-]e8be920900
         // 1400019b3: call _close
      [-]816358????????8b4b588bc183e00cc74330????????48c78310010000ffffffff3c0c740a
         // 1400019b8: and b4 ds:[rbx+0x58], b4 0xffffffffffff3fff
         // 1400019bf: mov b4 ecx, b4 ds:[rbx+0x58]
         // 1400019c2: mov b4 eax, b4 ecx
         // 1400019c4: and b4 eax, b4 0xc
         // 1400019c7: mov b4 ds:[rbx+0x30], b4 0xffffffffffffffff
         // 1400019ce: mov ds:[rbx+0x110], 0xffffffffffffffff
         // 1400019d9: cmp b1 al, b1 0xc
         // 1400019db: jz 0x1400019e7
      [-]488b4308ff40088b4b58
         // 1400019dd: mov rax, ds:[rbx+0x8]
         // 1400019e1: inc b4 ds:[rax+0x8]
         // 1400019e4: mov b4 ecx, b4 ds:[rbx+0x58]
      [-]83e1fb83c901837b7800894b580f85b0000000
         // 1400019e7: and b4 ecx, b4 0xfffffffffffffffb
         // 1400019ea: or b4 ecx, b4 0x1
         // 1400019ed: cmp b4 ds:[rbx+0x78], b4 0x0
         // 1400019f1: mov b4 ds:[rbx+0x58], b4 ecx
         // 1400019f4: jnz 0x140001aaa
      [-]488b5308f6c1200f85a3000000
         // 1400019fa: mov rdx, ds:[rbx+0x8]
         // 1400019fe: test b1 cl, b1 0x20
         // 140001a01: jnz 0x140001aaa
      [-]83c920894b58488b42504889435048895a50488b5c24304883c4205fc3
         // 140001a07: or b4 ecx, b4 0x20
         // 140001a0a: mov b4 ds:[rbx+0x58], b4 ecx
         // 140001a0d: mov rax, ds:[rdx+0x50]
         // 140001a11: mov ds:[rbx+0x50], rax
         // 140001a15: mov ds:[rdx+0x50], rbx
         // 140001a19: mov rbx, ss:[rsp+0x30]
         // 140001a1e: add rsp, 0x20
         // 140001a22: pop rdi
         // 140001a23: retn 
      [-]410fbae00c7331
         // 140001a24: bt b4 r8d, b1 0xc
         // 140001a29: jnb 0x140001a5c
      [-]410fbaf00c44894358ff8f????????836b7c01751c
         // 140001a2b: btr b4 r8d, b1 0xc
         // 140001a30: mov b4 ds:[rbx+0x58], b4 r8d
         // 140001a34: dec b4 ds:[rdi+0xac]
         // 140001a3a: sub b4 ds:[rbx+0x7c], b4 0x1
         // 140001a3e: jnz 0x140001a5c
      [-]8b4358a8017515
         // 140001a40: mov b4 eax, b4 ds:[rbx+0x58]
         // 140001a43: test b1 al, b1 0x1
         // 140001a45: jnz 0x140001a5c
      [-]a8047411
         // 140001a47: test b1 al, b1 0x4
         // 140001a49: jz 0x140001a5c
      [-]83e0fb894358a8087407
         // 140001a4b: and b4 eax, b4 0xfffffffffffffffb
         // 140001a4e: mov b4 ds:[rbx+0x58], b4 eax
         // 140001a51: test b1 al, b1 0x8
         // 140001a53: jz 0x140001a5c
      [-]488b4308ff4808
         // 140001a55: mov rax, ds:[rbx+0x8]
         // 140001a59: dec b4 ds:[rax+0x8]
      [-]488b4b70ff15caab09008b4b588bc183e00c48c74370ffffffff3c0c740a
         // 140001a5c: mov rcx, ds:[rbx+0x70]
         // 140001a60: call cs:[closesocket]
         // 140001a66: mov b4 ecx, b4 ds:[rbx+0x58]
         // 140001a69: mov b4 eax, b4 ecx
         // 140001a6b: and b4 eax, b4 0xc
         // 140001a6e: mov ds:[rbx+0x70], 0xffffffffffffffff
         // 140001a76: cmp b1 al, b1 0xc
         // 140001a78: jz 0x140001a84
      [-]488b4308ff40088b4b58
         // 140001a7a: mov rax, ds:[rbx+0x8]
         // 140001a7e: inc b4 ds:[rax+0x8]
         // 140001a81: mov b4 ecx, b4 ds:[rbx+0x58]
      [-]83e1fb83c901837b7800
         // 140001a84: and b4 ecx, b4 0xfffffffffffffffb
         // 140001a87: or b4 ecx, b4 0x1
         // 140001a8a: cmp b4 ds:[rbx+0x78], b4 0x0
      [-]894b587517
         // 140001a8e: mov b4 ds:[rbx+0x58], b4 ecx
         // 140001a91: jnz 0x140001aaa
      [-]f6c1207512
         // 140001a93: test b1 cl, b1 0x20
         // 140001a96: jnz 0x140001aaa
      [-]83c920894b58
         // 140001a98: or b4 ecx, b4 0x20
         // 140001a9b: mov b4 ds:[rbx+0x58], b4 ecx
      [-]488b47504889435048895f50
         // 140001a9e: mov rax, ds:[rdi+0x50]
         // 140001aa2: mov ds:[rbx+0x50], rax
         // 140001aa6: mov ds:[rdi+0x50], rbx
      [-]488b5c24304883c4205fc3
         // 140001aaa: mov rbx, ss:[rsp+0x30]
         // 140001aaf: add rsp, 0x20
         // 140001ab3: pop rdi
         // 140001ab4: retn 
      [-]410fbae0187215
         // 140001ab5: bt b4 r8d, b1 0x18
         // 140001aba: jb 0x140001ad1
      [-]488bd3488bcf488b5c24304883c4205fe99fc80000
         // 140001abc: mov rdx, rbx
         // 140001abf: mov rcx, rdi
         // 140001ac2: mov rbx, ss:[rsp+0x30]
         // 140001ac7: add rsp, 0x20
         // 140001acb: pop rdi
         // 140001acc: jmp 0x14000e370
      [-]418bc0c6839c0100000083e00c3c0c7407
         // 140001ad1: mov b4 eax, b4 r8d
         // 140001ad4: mov b1 ds:[rbx+0x19c], b1 0x0
         // 140001adb: and b4 eax, b4 0xc
         // 140001ade: cmp b1 al, b1 0xc
         // 140001ae0: jz 0x140001ae9
      [-]ff4708448b4358
         // 140001ae2: inc b4 ds:[rdi+0x8]
         // 140001ae5: mov b4 r8d, b4 ds:[rbx+0x58]
      [-]4183e0fb4183c80180bb98010000004489435875ac
         // 140001ae9: and b4 r8d, b4 0xfffffffffffffffb
         // 140001aed: or b4 r8d, b4 0x1
         // 140001af1: cmp b1 ds:[rbx+0x198], b1 0x0
         // 140001af8: mov b4 ds:[rbx+0x58], b4 r8d
         // 140001afc: jnz 0x140001aaa
      [-]80bb990100000075a3
         // 140001afe: cmp b1 ds:[rbx+0x199], b1 0x0
         // 140001b05: jnz 0x140001aaa
      [-]e9b4000000
         // 140001b07: jmp 0x140001bc0
      [-]488bcbe85c8000008b4b588bc183e00c3c0c740a
         // 140001b0c: mov rcx, rbx
         // 140001b0f: call 0x140009b70
         // 140001b14: mov b4 ecx, b4 ds:[rbx+0x58]
         // 140001b17: mov b4 eax, b4 ecx
         // 140001b19: and b4 eax, b4 0xc
         // 140001b1c: cmp b1 al, b1 0xc
         // 140001b1e: jz 0x140001b2a
      [-]488b4308ff40088b4b58
         // 140001b20: mov rax, ds:[rbx+0x8]
         // 140001b24: inc b4 ds:[rax+0x8]
         // 140001b27: mov b4 ecx, b4 ds:[rbx+0x58]
      [-]83e1fb83c901894b58e95bffffff
         // 140001b2a: and b4 ecx, b4 0xfffffffffffffffb
         // 140001b2d: or b4 ecx, b4 0x1
         // 140001b30: mov b4 ds:[rbx+0x58], b4 ecx
         // 140001b33: jmp 0x140001a93
      [-]41f6c0047461
         // 140001b38: test b1 r8b, b1 0x4
         // 140001b3c: jz 0x140001b9f
      [-]48395f607508
         // 140001b3e: cmp ds:[rdi+0x60], rbx
         // 140001b42: jnz 0x140001b4c
      [-]488b436848894760
         // 140001b44: mov rax, ds:[rbx+0x68]
         // 140001b48: mov ds:[rdi+0x60], rax
      [-]48395f787508
         // 140001b4c: cmp ds:[rdi+0x78], rbx
         // 140001b50: jnz 0x140001b5a
      [-]488b436848894778
         // 140001b52: mov rax, ds:[rbx+0x68]
         // 140001b56: mov ds:[rdi+0x78], rax
      [-]488b4b604885c97408
         // 140001b5a: mov rcx, ds:[rbx+0x60]
         // 140001b5e: test rcx, rcx
         // 140001b61: jz 0x140001b6b
      [-]488b436848894168
         // 140001b63: mov rax, ds:[rbx+0x68]
         // 140001b67: mov ds:[rcx+0x68], rax
      [-]488b4b684885c97408
         // 140001b6b: mov rcx, ds:[rbx+0x68]
         // 140001b6f: test rcx, rcx
         // 140001b72: jz 0x140001b7c
      [-]488b436048894160
         // 140001b74: mov rax, ds:[rbx+0x60]
         // 140001b78: mov ds:[rcx+0x60], rax
      [-]448b435841f6c0047419
         // 140001b7c: mov b4 r8d, b4 ds:[rbx+0x58]
         // 140001b80: test b1 r8b, b1 0x4
         // 140001b84: jz 0x140001b9f
      [-]4183e0fb4489435841f6c008740b
         // 140001b86: and b4 r8d, b4 0xfffffffffffffffb
         // 140001b8a: mov b4 ds:[rbx+0x58], b4 r8d
         // 140001b8e: test b1 r8b, b1 0x8
         // 140001b92: jz 0x140001b9f
      [-]488b4308ff4808448b4358
         // 140001b94: mov rax, ds:[rbx+0x8]
         // 140001b98: dec b4 ds:[rax+0x8]
         // 140001b9b: mov b4 r8d, b4 ds:[rbx+0x58]
      [-]418bc083e00c3c0c740b
         // 140001b9f: mov b4 eax, b4 r8d
         // 140001ba2: and b4 eax, b4 0xc
         // 140001ba5: cmp b1 al, b1 0xc
         // 140001ba7: jz 0x140001bb4
      [-]488b4308ff4008448b4358
         // 140001ba9: mov rax, ds:[rbx+0x8]
         // 140001bad: inc b4 ds:[rax+0x8]
         // 140001bb0: mov b4 r8d, b4 ds:[rbx+0x58]
      [-]4183e0fb4183c80144894358
         // 140001bb4: and b4 r8d, b4 0xfffffffffffffffb
         // 140001bb8: or b4 r8d, b4 0x1
         // 140001bbc: mov b4 ds:[rbx+0x58], b4 r8d
      [-]41f6c0200f85e0feffff
         // 140001bc0: test b1 r8b, b1 0x20
         // 140001bc4: jnz 0x140001aaa
      [-]4183c82044894358e9c7feffff
         // 140001bca: or b4 r8d, b4 0x20
         // 140001bce: mov b4 ds:[rbx+0x58], b4 r8d
         // 140001bd2: jmp 0x140001a9e
      [-]41f6c00474c2
         // 140001bd7: test b1 r8b, b1 0x4
         // 140001bdb: jz 0x140001b9f
      [-]48395f687508
         // 140001bdd: cmp ds:[rdi+0x68], rbx
         // 140001be1: jnz 0x140001beb
      [-]488b436848894768
         // 140001be3: mov rax, ds:[rbx+0x68]
         // 140001be7: mov ds:[rdi+0x68], rax
      [-]48399f800000000f8562ffffff
         // 140001beb: cmp ds:[rdi+0x80], rbx
         // 140001bf2: jnz 0x140001b5a
      [-]488b436848898780000000e952ffffff
         // 140001bf8: mov rax, ds:[rbx+0x68]
         // 140001bfc: mov ds:[rdi+0x80], rax
         // 140001c03: jmp 0x140001b5a
      [-]41f6c0047491
         // 140001c08: test b1 r8b, b1 0x4
         // 140001c0c: jz 0x140001b9f
      [-]48395f707508
         // 140001c0e: cmp ds:[rdi+0x70], rbx
         // 140001c12: jnz 0x140001c1c
      [-]488b436848894770
         // 140001c14: mov rax, ds:[rbx+0x68]
         // 140001c18: mov ds:[rdi+0x70], rax
      [-]48399f880000000f8531ffffff
         // 140001c1c: cmp ds:[rdi+0x88], rbx
         // 140001c23: jnz 0x140001b5a
      [-]488b436848898788000000e921ffffff
         // 140001c29: mov rax, ds:[rbx+0x68]
         // 140001c2d: mov ds:[rdi+0x88], rax
         // 140001c34: jmp 0x140001b5a
      [-]0fb683d800000084c07519
         // 140001c39: movzx b4 eax, b1 ds:[rbx+0xd8]
         // 140001c40: test b1 al, b1 al
         // 140001c42: jnz 0x140001c5d
      [-]8b4358a8207512
         // 140001c44: mov b4 eax, b4 ds:[rbx+0x58]
         // 140001c47: test b1 al, b1 0x20
         // 140001c49: jnz 0x140001c5d
      [-]83c820894358488b47504889435048895f50
         // 140001c4b: or b4 eax, b4 0x20
         // 140001c4e: mov b4 ds:[rbx+0x58], b4 eax
         // 140001c51: mov rax, ds:[rdi+0x50]
         // 140001c55: mov ds:[rbx+0x50], rax
         // 140001c59: mov ds:[rdi+0x50], rbx
      [-]8b4b588bc183e00c3c0c740a
         // 140001c5d: mov b4 ecx, b4 ds:[rbx+0x58]
         // 140001c60: mov b4 eax, b4 ecx
         // 140001c62: and b4 eax, b4 0xc
         // 140001c65: cmp b1 al, b1 0xc
         // 140001c67: jz 0x140001c73
      [-]488b4308ff40088b4b58
         // 140001c69: mov rax, ds:[rbx+0x8]
         // 140001c6d: inc b4 ds:[rax+0x8]
         // 140001c70: mov b4 ecx, b4 ds:[rbx+0x58]
      [-]83e1fb83c901894b58488b5c24304883c4205fc3
         // 140001c73: and b4 ecx, b4 0xfffffffffffffffb
         // 140001c76: or b4 ecx, b4 0x1
         // 140001c79: mov b4 ds:[rbx+0x58], b4 ecx
         // 140001c7c: mov rbx, ss:[rsp+0x30]
         // 140001c81: add rsp, 0x20
         // 140001c85: pop rdi
         // 140001c86: retn 
      [-]488bcbe8915900008b4b588bc183e00c3c0c740a
         // 140001c87: mov rcx, rbx
         // 140001c8a: call 0x140007620
         // 140001c8f: mov b4 ecx, b4 ds:[rbx+0x58]
         // 140001c92: mov b4 eax, b4 ecx
         // 140001c94: and b4 eax, b4 0xc
         // 140001c97: cmp b1 al, b1 0xc
         // 140001c99: jz 0x140001ca5
      [-]488b4308ff40088b4b58
         // 140001c9b: mov rax, ds:[rbx+0x8]
         // 140001c9f: inc b4 ds:[rax+0x8]
         // 140001ca2: mov b4 ecx, b4 ds:[rbx+0x58]
      [-]83e1fb83c90183bb????????00e9d7fdffff
         // 140001ca5: and b4 ecx, b4 0xfffffffffffffffb
         // 140001ca8: or b4 ecx, b4 0x1
         // 140001cab: cmp b4 ds:[rbx+0x100], b4 0x0
         // 140001cb2: jmp 0x140001a8e
      [-]418bc083e00c3c0c7407
         // 140001cb7: mov b4 eax, b4 r8d
         // 140001cba: and b4 eax, b4 0xc
         // 140001cbd: cmp b1 al, b1 0xc
         // 140001cbf: jz 0x140001cc8
      [-]ff4708448b4358
         // 140001cc1: inc b4 ds:[rdi+0x8]
         // 140001cc4: mov b4 r8d, b4 ds:[rbx+0x58]
      [-]488b8bf00000004183e0fb4183c801448943584883f9ff7420
         // 140001cc8: mov rcx, ds:[rbx+0xf0]
         // 140001ccf: and b4 r8d, b4 0xfffffffffffffffb
         // 140001cd3: or b4 r8d, b4 0x1
         // 140001cd7: mov b4 ds:[rbx+0x58], b4 r8d
         // 140001cdb: cmp rcx, 0xffffffffffffffff
         // 140001cdf: jz 0x140001d01
      [-]48c7c2ffffffffff158aa6090085c00f84eb000000
         // 140001ce1: mov rdx, 0xffffffffffffffff
         // 140001ce8: call cs:[UnregisterWaitEx]
         // 140001cee: test b4 eax, b4 eax
         // 140001cf0: jz 0x140001de1
      [-]48c783f0000000ffffffff
         // 140001cf6: mov ds:[rbx+0xf0], 0xffffffffffffffff
      [-]0fb6830001000084c00f859afdffff
         // 140001d01: movzx b4 eax, b1 ds:[rbx+0x100]
         // 140001d08: test b1 al, b1 al
         // 140001d0a: jnz 0x140001aaa
      [-]8b4358a8200f858ffdffff
         // 140001d10: mov b4 eax, b4 ds:[rbx+0x58]
         // 140001d13: test b1 al, b1 0x20
         // 140001d15: jnz 0x140001aaa
      [-]83c820894358e978fdffff
         // 140001d1b: or b4 eax, b4 0x20
         // 140001d1e: mov b4 ds:[rbx+0x58], b4 eax
         // 140001d21: jmp 0x140001a9e
      [-]488bd3488bcf488b5c24304883c4205fe985a90000
         // 140001d26: mov rdx, rbx
         // 140001d29: mov rcx, rdi
         // 140001d2c: mov rbx, ss:[rsp+0x30]
         // 140001d31: add rsp, 0x20
         // 140001d35: pop rdi
         // 140001d36: jmp 0x14000c6c0
      [-]418bc024053c047540
         // 140001d3b: mov b4 eax, b4 r8d
         // 140001d3e: and b1 al, b1 0x5
         // 140001d40: cmp b1 al, b1 0x4
         // 140001d42: jnz 0x140001d84
      [-]488b4b604883c1288b415824053c047510
         // 140001d44: mov rcx, ds:[rbx+0x60]
         // 140001d48: add rcx, 0x28
         // 140001d4c: mov b4 eax, b4 ds:[rcx+0x58]
         // 140001d4f: and b1 al, b1 0x5
         // 140001d51: cmp b1 al, b1 0x4
         // 140001d53: jnz 0x140001d65
      [-]488d15b4a30000e8bffbffff448b4358
         // 140001d55: lea rdx, cs:[0x14000c110]
         // 140001d5c: call 0x140001920
         // 140001d61: mov b4 r8d, b4 ds:[rbx+0x58]
      [-]41f6c0047419
         // 140001d65: test b1 r8b, b1 0x4
         // 140001d69: jz 0x140001d84
      [-]4183e0fb4489435841f6c008740b
         // 140001d6b: and b4 r8d, b4 0xfffffffffffffffb
         // 140001d6f: mov b4 ds:[rbx+0x58], b4 r8d
         // 140001d73: test b1 r8b, b1 0x8
         // 140001d77: jz 0x140001d84
      [-]488b4308ff4808448b4358
         // 140001d79: mov rax, ds:[rbx+0x8]
         // 140001d7d: dec b4 ds:[rax+0x8]
         // 140001d80: mov b4 r8d, b4 ds:[rbx+0x58]
      [-]48837b6000418bc87521
         // 140001d84: cmp ds:[rbx+0x60], 0x0
         // 140001d89: mov b4 ecx, b4 r8d
         // 140001d8c: jnz 0x140001daf
      [-]488b530841f6c0207517
         // 140001d8e: mov rdx, ds:[rbx+0x8]
         // 140001d92: test b1 r8b, b1 0x20
         // 140001d96: jnz 0x140001daf
      [-]4183c82044894358488b42504889435048895a508b4b58
         // 140001d98: or b4 r8d, b4 0x20
         // 140001d9c: mov b4 ds:[rbx+0x58], b4 r8d
         // 140001da0: mov rax, ds:[rdx+0x50]
         // 140001da4: mov ds:[rbx+0x50], rax
         // 140001da8: mov ds:[rdx+0x50], rbx
         // 140001dac: mov b4 ecx, b4 ds:[rbx+0x58]
      [-]8bc183e00c3c0c0f84b7feffff
         // 140001daf: mov b4 eax, b4 ecx
         // 140001db1: and b4 eax, b4 0xc
         // 140001db4: cmp b1 al, b1 0xc
         // 140001db6: jz 0x140001c73
      [-]488b4308ff40088b4b5883e1fb83c901894b58488b5c24304883c4205fc3
         // 140001dbc: mov rax, ds:[rbx+0x8]
         // 140001dc0: inc b4 ds:[rax+0x8]
         // 140001dc3: mov b4 ecx, b4 ds:[rbx+0x58]
         // 140001dc6: and b4 ecx, b4 0xfffffffffffffffb
         // 140001dc9: or b4 ecx, b4 0x1
         // 140001dcc: mov b4 ds:[rbx+0x58], b4 ecx
         // 140001dcf: mov rbx, ss:[rsp+0x30]
         // 140001dd4: add rsp, 0x20
         // 140001dd8: pop rdi
         // 140001dd9: retn 
      [-]ff15e8a90900
         // 140001dda: call cs:[abort]
      [-]ff15c9a209008bc8488d1540800a00e8dbc90000
         // 140001de1: call cs:[GetLastError]
         // 140001de7: mov b4 ecx, b4 eax
         // 140001de9: lea rdx, cs:[0x1400a9e30]
         // 140001df0: call 0x14000e7d0
      [-]f6415803b8????????0f95c0c3
         // 140001e40: test b1 ds:[rcx+0x58], b1 0x3
         // 140001e44: mov b4 eax, b4 0x0
         // 140001e49: setnz b1 al
         // 140001e4c: retn 
      [-]40534883ec20448b49584d8bd0488bd9410fbae10c730b
         // 140001e50: push rbx
         // 140001e52: sub rsp, 0x20
         // 140001e56: mov b4 r9d, b4 ds:[rcx+0x58]
         // 140001e5a: mov r10, r8
         // 140001e5d: mov rbx, rcx
         // 140001e60: bt b4 r9d, b1 0xc
         // 140001e65: jnb 0x140001e72
      [-]b8????????4883c4205bc3
         // 140001e67: mov b4 eax, b4 0xfffffffffffff00c
         // 140001e6c: add rsp, 0x20
         // 140001e70: pop rbx
         // 140001e71: retn 
      [-]410fbae10e720b
         // 140001e72: bt b4 r9d, b1 0xe
         // 140001e77: jb 0x140001e84
      [-]b8????????4883c4205bc3
         // 140001e79: mov b4 eax, b4 0xfffffffffffff02b
         // 140001e7e: add rsp, 0x20
         // 140001e82: pop rbx
         // 140001e83: retn 
      [-]8b4910b8????????48897c243083f9070f84a5000000
         // 140001e84: mov b4 ecx, b4 ds:[rcx+0x10]
         // 140001e87: mov b4 eax, b4 0x57
         // 140001e8c: mov ss:[rsp+0x30], rdi
         // 140001e91: cmp b4 ecx, b4 0x7
         // 140001e94: jz 0x140001f3f
      [-]83f90c7422
         // 140001e9a: cmp b4 ecx, b4 0xc
         // 140001e9d: jz 0x140001ec1
      [-]83f90e0f85e6000000
         // 140001e9f: cmp b4 ecx, b4 0xe
         // 140001ea2: jnz 0x140001f8e
      [-]488bcbe8701b00008bc8488b7c24304883c4205be9cfc90000
         // 140001ea8: mov rcx, rbx
         // 140001eab: call 0x140003a20
         // 140001eb0: mov b4 ecx, b4 eax
         // 140001eb2: mov rdi, ss:[rsp+0x30]
         // 140001eb7: add rsp, 0x20
         // 140001ebb: pop rbx
         // 140001ebc: jmp 0x14000e890
      [-]8b4b7c410fbae90c488b7b0844894b584c895370488953688d410189437c418bc185c97516
         // 140001ec1: mov b4 ecx, b4 ds:[rbx+0x7c]
         // 140001ec4: bts b4 r9d, b1 0xc
         // 140001ec9: mov rdi, ds:[rbx+0x8]
         // 140001ecd: mov b4 ds:[rbx+0x58], b4 r9d
         // 140001ed1: mov ds:[rbx+0x70], r10
         // 140001ed5: mov ds:[rbx+0x68], rdx
         // 140001ed9: lea b4 eax, b4 ds:[rcx+0x1]
         // 140001edc: mov b4 ds:[rbx+0x7c], b4 eax
         // 140001edf: mov b4 eax, b4 r9d
         // 140001ee2: test b4 ecx, b4 ecx
         // 140001ee4: jnz 0x140001efc
      [-]41f6c1047510
         // 140001ee6: test b1 r9b, b1 0x4
         // 140001eea: jnz 0x140001efc
      [-]83c804894358a8087406
         // 140001eec: or b4 eax, b4 0x4
         // 140001eef: mov b4 ds:[rbx+0x58], b4 eax
         // 140001ef2: test b1 al, b1 0x8
         // 140001ef4: jz 0x140001efc
      [-]ff47088b4358
         // 140001ef6: inc b4 ds:[rdi+0x8]
         // 140001ef9: mov b4 eax, b4 ds:[rbx+0x58]
      [-]0fbae0100f8286000000
         // 140001efc: bt b4 eax, b1 0x10
         // 140001f00: jb 0x140001f8c
      [-]0fbae0137326
         // 140001f06: bt b4 eax, b1 0x13
         // 140001f0a: jnb 0x140001f32
      [-]4883bbf000000000751c
         // 140001f0c: cmp ds:[rbx+0xf0], 0x0
         // 140001f14: jnz 0x140001f32
      [-]4533c94533c033d233c9ff154aa30900488983f00000004885c0746d
         // 140001f16: xor b4 r9d, b4 r9d
         // 140001f19: xor b4 r8d, b4 r8d
         // 140001f1c: xor b4 edx, b4 edx
         // 140001f1e: xor b4 ecx, b4 ecx
         // 140001f20: call cs:[CreateEventA]
         // 140001f26: mov ds:[rbx+0xf0], rax
         // 140001f2d: test rax, rax
         // 140001f30: jz 0x140001f9f
      [-]488bd3488bcfe8636a0000eb4d
         // 140001f32: mov rdx, rbx
         // 140001f35: mov rcx, rdi
         // 140001f38: call 0x1400089a0
         // 140001f3d: jmp 0x140001f8c
      [-]8b4b7c410fbae90c4c8b430844894b588d410189437c418bc185c97517
         // 140001f3f: mov b4 ecx, b4 ds:[rbx+0x7c]
         // 140001f42: bts b4 r9d, b1 0xc
         // 140001f47: mov r8, ds:[rbx+0x8]
         // 140001f4b: mov b4 ds:[rbx+0x58], b4 r9d
         // 140001f4f: lea b4 eax, b4 ds:[rcx+0x1]
         // 140001f52: mov b4 ds:[rbx+0x7c], b4 eax
         // 140001f55: mov b4 eax, b4 r9d
         // 140001f58: test b4 ecx, b4 ecx
         // 140001f5a: jnz 0x140001f73
      [-]41f6c1047511
         // 140001f5c: test b1 r9b, b1 0x4
         // 140001f60: jnz 0x140001f73
      [-]83c804894358a8087407
         // 140001f62: or b4 eax, b4 0x4
         // 140001f65: mov b4 ds:[rbx+0x58], b4 eax
         // 140001f68: test b1 al, b1 0x8
         // 140001f6a: jz 0x140001f73
      [-]41ff40088b4358
         // 140001f6c: inc b4 ds:[r8+0x8]
         // 140001f70: mov b4 eax, b4 ds:[rbx+0x58]
      [-]4c895370488953680fbae010720b
         // 140001f73: mov ds:[rbx+0x70], r10
         // 140001f77: mov ds:[rbx+0x68], rdx
         // 140001f7b: bt b4 eax, b1 0x10
         // 140001f7f: jb 0x140001f8c
      [-]488bd3498bc8e894b40000
         // 140001f81: mov rdx, rbx
         // 140001f84: mov rcx, r8
         // 140001f87: call 0x14000d420
      [-]8bc8488b7c24304883c4205be9f1c80000
         // 140001f8e: mov b4 ecx, b4 eax
         // 140001f90: mov rdi, ss:[rsp+0x30]
         // 140001f95: add rsp, 0x20
         // 140001f99: pop rbx
         // 140001f9a: jmp 0x14000e890
      [-]ff150ba109008bc8488d15e27b0a00e81dc80000
         // 140001f9f: call cs:[GetLastError]
         // 140001fa5: mov b4 ecx, b4 eax
         // 140001fa7: lea rdx, cs:[0x1400a9b90]
         // 140001fae: call 0x14000e7d0
      [-]4883ec288b51580fbae20c7207
         // 140001fc0: sub rsp, 0x28
         // 140001fc4: mov b4 edx, b4 ds:[rcx+0x58]
         // 140001fc7: bt b4 edx, b1 0xc
         // 140001fcb: jb 0x140001fd4
      [-]33c04883c428c3
         // 140001fcd: xor b4 eax, b4 eax
         // 140001fcf: add rsp, 0x28
         // 140001fd3: retn 
      [-]448b491048895c242033db4183f90e7517
         // 140001fd4: mov b4 r9d, b4 ds:[rcx+0x10]
         // 140001fd8: mov ss:[rsp+0x20], rbx
         // 140001fdd: xor b4 ebx, b4 ebx
         // 140001fdf: cmp b4 r9d, b4 0xe
         // 140001fe3: jnz 0x140001ffc
      [-]e8161b00008bc88bd8488b5c24204883c428e994c80000
         // 140001fe5: call 0x140003b00
         // 140001fea: mov b4 ecx, b4 eax
         // 140001fec: mov b4 ebx, b4 eax
         // 140001fee: mov rbx, ss:[rsp+0x20]
         // 140001ff3: add rsp, 0x28
         // 140001ff7: jmp 0x14000e890
      [-]8b417c448bc2410fbaf00cffc84489415889417c4183f9077539
         // 140001ffc: mov b4 eax, b4 ds:[rcx+0x7c]
         // 140001fff: mov b4 r8d, b4 edx
         // 140002002: btr b4 r8d, b1 0xc
         // 140002007: dec b4 eax
         // 140002009: mov b4 ds:[rcx+0x58], b4 r8d
         // 14000200d: mov b4 ds:[rcx+0x7c], b4 eax
         // 140002010: cmp b4 r9d, b4 0x7
         // 140002014: jnz 0x14000204f
      [-]85c07520
         // 140002016: test b4 eax, b4 eax
         // 140002018: jnz 0x14000203a
      [-]41f6c001751a
         // 14000201a: test b1 r8b, b1 0x1
         // 14000201e: jnz 0x14000203a
      [-]f6c2047415
         // 140002020: test b1 dl, b1 0x4
         // 140002023: jz 0x14000203a
      [-]81e2????????895158f6c2087407
         // 140002025: and b4 edx, b4 0xffffffffffffeffb
         // 14000202b: mov b4 ds:[rcx+0x58], b4 edx
         // 14000202e: test b1 dl, b1 0x8
         // 140002031: jz 0x14000203a
      [-]488b4108ff4808
         // 140002033: mov rax, ds:[rcx+0x8]
         // 140002037: dec b4 ds:[rax+0x8]
      [-]e841ad00008bcb488b5c24204883c428e941c80000
         // 14000203a: call 0x14000cd80
         // 14000203f: mov b4 ecx, b4 ebx
         // 140002041: mov rbx, ss:[rsp+0x20]
         // 140002046: add rsp, 0x28
         // 14000204a: jmp 0x14000e890
      [-]85c07520
         // 14000204f: test b4 eax, b4 eax
         // 140002051: jnz 0x140002073
      [-]41f6c001751a
         // 140002053: test b1 r8b, b1 0x1
         // 140002057: jnz 0x140002073
      [-]f6c2047415
         // 140002059: test b1 dl, b1 0x4
         // 14000205c: jz 0x140002073
      [-]81e2????????895158f6c2087407
         // 14000205e: and b4 edx, b4 0xffffffffffffeffb
         // 140002064: mov b4 ds:[rcx+0x58], b4 edx
         // 140002067: test b1 dl, b1 0x8
         // 14000206a: jz 0x140002073
      [-]488b4108ff4808
         // 14000206c: mov rax, ds:[rcx+0x8]
         // 140002070: dec b4 ds:[rax+0x8]
      [-]8bcb488b5c24204883c428e90dc80000
         // 140002073: mov b4 ecx, b4 ebx
         // 140002075: mov rbx, ss:[rsp+0x20]
         // 14000207a: add rsp, 0x28
         // 14000207e: jmp 0x14000e890
      [-]48895c2410574883ec408b4158418bd8488bfaa8017410
         // 140002090: mov ss:[rsp+0x10], rbx
         // 140002095: push rdi
         // 140002096: sub rsp, 0x40
         // 14000209a: mov b4 eax, b4 ds:[rcx+0x58]
         // 14000209d: mov b4 ebx, b4 r8d
         // 1400020a0: mov rdi, rdx
         // 1400020a3: test b1 al, b1 0x1
         // 1400020a5: jz 0x1400020b7
      [-]b8????????488b5c24584883c4405fc3
         // 1400020a7: mov b4 eax, b4 0xfffffffffffff00d
         // 1400020ac: mov rbx, ss:[rsp+0x58]
         // 1400020b1: add rsp, 0x40
         // 1400020b5: pop rdi
         // 1400020b6: retn 
      [-]0fbae00f7210
         // 1400020b7: bt b4 eax, b1 0xf
         // 1400020bb: jb 0x1400020cd
      [-]b8????????488b5c24584883c4405fc3
         // 1400020bd: mov b4 eax, b4 0xfffffffffffff031
         // 1400020c2: mov rbx, ss:[rsp+0x58]
         // 1400020c7: add rsp, 0x40
         // 1400020cb: pop rdi
         // 1400020cc: retn 
      [-]8b411083f8070f84b2000000
         // 1400020cd: mov b4 eax, b4 ds:[rcx+0x10]
         // 1400020d0: cmp b4 eax, b4 0x7
         // 1400020d3: jz 0x14000218b
      [-]83f80c7457
         // 1400020d9: cmp b4 eax, b4 0xc
         // 1400020dc: jz 0x140002135
      [-]83f80e7410
         // 1400020de: cmp b4 eax, b4 0xe
         // 1400020e1: jz 0x1400020f3
      [-]b8????????488b5c24584883c4405fc3
         // 1400020e3: mov b4 eax, b4 0xfffffffffffff02a
         // 1400020e8: mov rbx, ss:[rsp+0x58]
         // 1400020ed: add rsp, 0x40
         // 1400020f1: pop rdi
         // 1400020f2: retn 
      [-]83b9????????000f878b000000
         // 1400020f3: cmp b4 ds:[rcx+0x100], b4 0x0
         // 1400020fa: ja 0x14000218b
      [-]4c8d4c2450e8e625000085c07413
         // 140002100: lea r9, ss:[rsp+0x50]
         // 140002105: call 0x1400046f0
         // 14000210a: test b4 eax, b4 eax
         // 14000210c: jz 0x140002121
      [-]8b4c2450488b5c24584883c4405fe96fc70000
         // 14000210e: mov b4 ecx, b4 ss:[rsp+0x50]
         // 140002112: mov rbx, ss:[rsp+0x58]
         // 140002117: add rsp, 0x40
         // 14000211b: pop rdi
         // 14000211c: jmp 0x14000e890
      [-]8bd3488bcf488b5c24584883c4405fe92bf4ffff
         // 140002121: mov b4 edx, b4 ebx
         // 140002123: mov rcx, rdi
         // 140002126: mov rbx, ss:[rsp+0x58]
         // 14000212b: add rsp, 0x40
         // 14000212f: pop rdi
         // 140002130: jmp 0x140001560
      [-]83b9????????00774d
         // 140002135: cmp b4 ds:[rcx+0x100], b4 0x0
         // 14000213c: ja 0x14000218b
      [-]488b89100100004c8d4c245033c04889442430488944242889442420ff15d8a4090083f8ff7517
         // 14000213e: mov rcx, ds:[rcx+0x110]
         // 140002145: lea r9, ss:[rsp+0x50]
         // 14000214a: xor b4 eax, b4 eax
         // 14000214c: mov ss:[rsp+0x30], rax
         // 140002151: mov ss:[rsp+0x28], rax
         // 140002156: mov b4 ss:[rsp+0x20], b4 eax
         // 14000215a: call cs:[WSASend]
         // 140002160: cmp b4 eax, b4 0xffffffffffffffff
         // 140002163: jnz 0x14000217c
      [-]ff158da409008bc8488b5c24584883c4405fe914c70000
         // 140002165: call cs:[WSAGetLastError]
         // 14000216b: mov b4 ecx, b4 eax
         // 14000216d: mov rbx, ss:[rsp+0x58]
         // 140002172: add rsp, 0x40
         // 140002176: pop rdi
         // 140002177: jmp 0x14000e890
      [-]8b442450488b5c24584883c4405fc3
         // 14000217c: mov b4 eax, b4 ss:[rsp+0x50]
         // 140002180: mov rbx, ss:[rsp+0x58]
         // 140002185: add rsp, 0x40
         // 140002189: pop rdi
         // 14000218a: retn 
      [-]488b5c2458b8????????4883c4405fc3
         // 14000218b: mov rbx, ss:[rsp+0x58]
         // 140002190: mov b4 eax, b4 0xfffffffffffff008
         // 140002195: add rsp, 0x40
         // 140002199: pop rdi
         // 14000219a: retn 
      [-]8b4158c1e80e83e001c3
         // 1400021a0: mov b4 eax, b4 ds:[rcx+0x58]
         // 1400021a3: shr b4 eax, b1 0xe
         // 1400021a6: and b4 eax, b4 0x1
         // 1400021a9: retn 
      [-]8b4158c1e80f83e001c3
         // 1400021b0: mov b4 eax, b4 ds:[rcx+0x58]
         // 1400021b3: shr b4 eax, b1 0xf
         // 1400021b6: and b4 eax, b4 0x1
         // 1400021b9: retn 
      [-]405355564881ec90000000488b0556330b004833c44889442470418bf0488bda488be9e8f88700008bceff1538a7090048894424484883f8ff750a
         // 1400021c0: push rbx
         // 1400021c2: push rbp
         // 1400021c3: push rsi
         // 1400021c4: sub rsp, 0x90
         // 1400021cb: mov rax, cs:[__security_cookie]
         // 1400021d2: xor rax, rsp
         // 1400021d5: mov ss:[rsp+0x70], rax
         // 1400021da: mov b4 esi, b4 r8d
         // 1400021dd: mov rbx, rdx
         // 1400021e0: mov rbp, rcx
         // 1400021e3: call 0x14000a9e0
         // 1400021e8: mov b4 ecx, b4 esi
         // 1400021ea: call cs:[_get_osfhandle]
         // 1400021f0: mov ss:[rsp+0x48], rax
         // 1400021f5: cmp rax, 0xffffffffffffffff
         // 1400021f9: jnz 0x140002205
      [-]b8????????e968030000
         // 1400021fb: mov b4 eax, b4 0xfffffffffffff00d
         // 140002200: jmp 0x14000256d
      [-]4c89bc24800000004533ff83fe027f4a
         // 140002205: mov ss:[rsp+0x80], r15
         // 14000220d: xor b4 r15d, b4 r15d
         // 140002210: cmp b4 esi, b4 0x2
         // 140002213: jg 0x14000225f
      [-]49c7c0ffffffffc7442430????????498bc844897c24284c8d4c244844897c2420488bd0ff15599f090085c07512
         // 140002215: mov r8, 0xffffffffffffffff
         // 14000221c: mov b4 ss:[rsp+0x30], b4 0x2
         // 140002224: mov rcx, r8
         // 140002227: mov b4 ss:[rsp+0x28], b4 r15d
         // 14000222c: lea r9, ss:[rsp+0x48]
         // 140002231: mov b4 ss:[rsp+0x20], b4 r15d
         // 140002236: mov rdx, rax
         // 140002239: call cs:[DuplicateHandle]
         // 14000223f: test b4 eax, b4 eax
         // 140002241: jnz 0x140002255
      [-]ff15679e09008bc8e840c60000e910030000
         // 140002243: call cs:[GetLastError]
         // 140002249: mov b4 ecx, b4 eax
         // 14000224b: call 0x14000e890
         // 140002250: jmp 0x140002565
      [-]488b442448be????????
         // 140002255: mov rax, ss:[rsp+0x48]
         // 14000225a: mov b4 esi, b4 0xffffffffffffffff
      [-]488d5424504c89b42488000000488bc8ff157b9f0900448bf085c00f85f3010000
         // 14000225f: lea rdx, ss:[rsp+0x50]
         // 140002264: mov ss:[rsp+0x88], r14
         // 14000226c: mov rcx, rax
         // 14000226f: call cs:[GetNumberOfConsoleInputEvents]
         // 140002275: mov b4 r14d, b4 eax
         // 140002278: test b4 eax, b4 eax
         // 14000227a: jnz 0x140002473
      [-]488b4c2448488d542458ff15d89e090085c07512
         // 140002280: mov rcx, ss:[rsp+0x48]
         // 140002285: lea rdx, ss:[rsp+0x58]
         // 14000228a: call cs:[GetConsoleScreenBufferInfo]
         // 140002290: test b4 eax, b4 eax
         // 140002292: jnz 0x1400022a6
      [-]ff15169e09008bc8e8efc50000e9b7020000
         // 140002294: call cs:[GetLastError]
         // 14000229a: mov b4 ecx, b4 eax
         // 14000229c: call 0x14000e890
         // 1400022a1: jmp 0x14000255d
      [-]488b0d635d0b00ba????????ff1510a0090085c00f85ac010000
         // 1400022a6: mov rcx, cs:[0x1400b8010]
         // 1400022ad: mov b4 edx, b4 0xffffffffffffffff
         // 1400022b2: call cs:[WaitForSingleObject]
         // 1400022b8: test b4 eax, b4 eax
         // 1400022ba: jnz 0x14000246c
      [-]833dd1320b00017555
         // 1400022c0: cmp b4 cs:[0x1400b5598], b4 0x1
         // 1400022c7: jnz 0x14000231e
      [-]4889bc24c8000000488d542440488b7c2448488bcf44897c2440ff15b79d090085c0741f
         // 1400022c9: mov ss:[rsp+0xc8], rdi
         // 1400022d1: lea rdx, ss:[rsp+0x40]
         // 1400022d6: mov rdi, ss:[rsp+0x48]
         // 1400022db: mov rcx, rdi
         // 1400022de: mov b4 ss:[rsp+0x40], b4 r15d
         // 1400022e3: call cs:[GetConsoleMode]
         // 1400022e9: test b4 eax, b4 eax
         // 1400022eb: jz 0x14000230c
      [-]8b542440488bcf83ca0489542440ff15a79d090044893d90320b0085c0750a
         // 1400022ed: mov b4 edx, b4 ss:[rsp+0x40]
         // 1400022f1: mov rcx, rdi
         // 1400022f4: or b4 edx, b4 0x4
         // 1400022f7: mov b4 ss:[rsp+0x40], b4 edx
         // 1400022fb: call cs:[SetConsoleMode]
         // 140002301: mov b4 cs:[0x1400b5598], b4 r15d
         // 140002308: test b4 eax, b4 eax
         // 14000230a: jnz 0x140002316
      [-]c70582320b00????????
         // 14000230c: mov b4 cs:[0x1400b5598], b4 0x2
      [-]488bbc24c8000000
         // 140002316: mov rdi, ss:[rsp+0xc8]
      [-]44393df35a0b0041b9????????0f85c6000000
         // 14000231e: cmp b4 cs:[0x1400b7e18], b4 r15d
         // 140002325: mov b4 r9d, b4 0x1
         // 14000232b: jnz 0x1400023f7
      [-]0fb74c246066890d6f320b006685c9750c
         // 140002331: movzx b4 ecx, b2 ss:[rsp+0x60]
         // 140002336: mov b2 cs:[0x1400b55ac], b2 cx
         // 14000233d: test b2 cx, b2 cx
         // 140002340: jnz 0x14000234e
      [-]b9????????66890d5e320b00
         // 140002342: mov b4 ecx, b4 0x7
         // 140002347: mov b2 cs:[0x1400b55ac], b2 cx
      [-]32d244883d51320b004532c044883dbd5a0b004532d232c0f6c104740b
         // 14000234e: xor b1 dl, b1 dl
         // 140002350: mov b1 cs:[0x1400b55a8], b1 r15b
         // 140002357: xor b1 r8b, b1 r8b
         // 14000235a: mov b1 cs:[0x1400b7e1e], b1 r15b
         // 140002361: xor b1 r10b, b1 r10b
         // 140002364: xor b1 al, b1 al
         // 140002366: test b1 cl, b1 0x4
         // 140002369: jz 0x140002376
      [-]44880d36320b00410fb6c1
         // 14000236b: mov b1 cs:[0x1400b55a8], b1 r9b
         // 140002372: movzx b4 eax, b1 r9b
      [-]f6c1027408
         // 140002376: test b1 cl, b1 0x2
         // 140002379: jz 0x140002383
      [-]0c02880525320b00
         // 14000237b: or b1 al, b1 0x2
         // 14000237d: mov b1 cs:[0x1400b55a8], b1 al
      [-]4184c97408
         // 140002383: test b1 r9b, b1 cl
         // 140002386: jz 0x140002390
      [-]0c04880518320b00
         // 140002388: or b1 al, b1 0x4
         // 14000238a: mov b1 cs:[0x1400b55a8], b1 al
      [-]32c0f6c140740b
         // 140002390: xor b1 al, b1 al
         // 140002392: test b1 cl, b1 0x40
         // 140002395: jz 0x1400023a2
      [-]44880d805a0b00410fb6c1
         // 140002397: mov b1 cs:[0x1400b7e1e], b1 r9b
         // 14000239e: movzx b4 eax, b1 r9b
      [-]f6c1207408
         // 1400023a2: test b1 cl, b1 0x20
         // 1400023a5: jz 0x1400023af
      [-]0c0288056f5a0b00
         // 1400023a7: or b1 al, b1 0x2
         // 1400023a9: mov b1 cs:[0x1400b7e1e], b1 al
      [-]f6c1107408
         // 1400023af: test b1 cl, b1 0x10
         // 1400023b2: jz 0x1400023bc
      [-]0c048805625a0b00
         // 1400023b4: or b1 al, b1 0x4
         // 1400023b6: mov b1 cs:[0x1400b7e1e], b1 al
      [-]f6c1080fb6c244890d4f5a0b00410f45c1f6c1808805475a0b00410fb6c0410f45c1660fbae10e8805335a0b00410fb6c2410f42c18805285a0b00
         // 1400023bc: test b1 cl, b1 0x8
         // 1400023bf: movzx b4 eax, b1 dl
         // 1400023c2: mov b4 cs:[0x1400b7e18], b4 r9d
         // 1400023c9: cmovnz b4 eax, b4 r9d
         // 1400023cd: test b1 cl, b1 0x80
         // 1400023d0: mov b1 cs:[0x1400b7e1d], b1 al
         // 1400023d6: movzx b4 eax, b1 r8b
         // 1400023da: cmovnz b4 eax, b4 r9d
         // 1400023de: bt b2 cx, b1 0xe
         // 1400023e3: mov b1 cs:[0x1400b7e1c], b1 al
         // 1400023e9: movzx b4 eax, b1 r10b
         // 1400023ed: cmovb b4 eax, b4 r9d
         // 1400023f1: mov b1 cs:[0x1400b7e1f], b1 al
      [-]0fbf4424580fbf5424
         // 1400023f7: movsx b4 eax, b2 ss:[rsp+0x58]
         // 1400023fc: movsx b4 edx, b2 ss:[rsp+0x68]
         // 140002401: mov b4 ecx, b4 cs:[0x1400b559c]
         // 140002407: mov b4 cs:[0x1400b55b0], b4 eax
         // 14000240d: movsx b4 eax, b2 ss:[rsp+0x64]
         // 140002412: sub b4 edx, b4 eax
         // 140002414: inc b4 edx
         // 140002416: mov b4 cs:[0x1400b55a0], b4 edx
         // 14000241c: cmp b4 ecx, b4 0xffffffffffffffff
         // 14000241f: jnz 0x140002428

  }
  condition:
    all of them
}
