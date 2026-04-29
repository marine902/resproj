rule neshta_10_0 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         a1????????
         // 140001c3a: mov b4 eax, b4 ds:[0x8b02c8830040a604]
      [-]53565783c4f08bf08d3c24a5a58bfce8a0ffffff8d4c24088bd7b8????????e810f5ffff8b5c240885db7504
         // 00401c68: push ebx
         // 00401c69: push esi
         // 00401c6a: push edi
         // 00401c6b: add esp, 0xfffffffffffffff0
         // 00401c6e: mov esi, eax
         // 00401c70: lea edi, ss:[esp]
         // 00401c73: movsdd 
         // 00401c74: movsdd 
         // 00401c75: mov edi, esp
         // 00401c77: call 0x401c1c
         // 00401c7c: lea ecx, ss:[esp+0x8]
         // 00401c80: mov edx, edi
         // 00401c82: mov eax, 0x40a610
         // 00401c87: call 0x40119c
         // 00401c8c: mov ebx, ss:[esp+0x8]
         // 00401c90: test ebx, ebx
         // 00401c92: jnz 0x401c98
      [-]33c0eb52
         // 00401c94: xor eax, eax
         // 00401c96: jmp 0x401cea
      [-]8b073bd8730a
         // 00401c98: mov eax, ds:[edi]
         // 00401c9a: cmp ebx, eax
         // 00401c9c: jnb 0x401ca8
      [-]e899fdffff2907014704
         // 00401c9e: call 0x401a3c
         // 00401ca3: sub ds:[edi], eax
         // 00401ca5: add ds:[edi+0x4], eax
      [-]8b070347048bf30374240c3bc67308
         // 00401ca8: mov eax, ds:[edi]
         // 00401caa: add eax, ds:[edi+0x4]
         // 00401cad: mov esi, ebx
         // 00401caf: add esi, ss:[esp+0xc]
         // 00401cb3: cmp eax, esi
         // 00401cb5: jnb 0x401cbf
      [-]e8f0fdffff014704
         // 00401cb7: call 0x401aac
         // 00401cbc: add ds:[edi+0x4], eax
      [-]8b070347043bf07511
         // 00401cbf: mov eax, ds:[edi]
         // 00401cc1: add eax, ds:[edi+0x4]
         // 00401cc4: cmp esi, eax
         // 00401cc6: jnz 0x401cd9
      [-]83e804ba????????e8ebfcffff836f0404
         // 00401cc8: sub eax, 0x4
         // 00401ccb: mov edx, 0x4
         // 00401cd0: call 0x4019c0
         // 00401cd5: sub ds:[edi+0x4], 0x4
      [-]83c4105f5e5bc3
         // 00401cea: add esp, 0x10
         // 00401ced: pop edi
         // 00401cee: pop esi
         // 00401cef: pop ebx
         // 00401cf0: retn 
      [-]5383c4f88bd88bd48d4304e844f8ffff833c2400740b
         // 00401cf4: push ebx
         // 00401cf5: add esp, 0xfffffffffffffff8
         // 00401cf8: mov ebx, eax
         // 00401cfa: mov edx, esp
         // 00401cfc: lea eax, ds:[ebx+0x4]
         // 00401cff: call 0x401548
         // 00401d04: cmp ss:[esp], 0x0
         // 00401d08: jz 0x401d15
      [-]8bc4e857ffffff84c07504
         // 00401d0a: mov eax, esp
         // 00401d0c: call 0x401c68
         // 00401d11: test b1 al, b1 al
         // 00401d13: jnz 0x401d19
      [-]33c0eb02
         // 00401d15: xor eax, eax
         // 00401d17: jmp 0x401d1b
      [-]595a5bc3
         // 00401d1b: pop ecx
         // 00401d1c: pop edx
         // 00401d1d: pop ebx
         // 00401d1e: retn 
      [-]535683c4f88bf28bd88bcc8d56048bc3e8a3f8ffff833c2400740b
         // 00401d20: push ebx
         // 00401d21: push esi
         // 00401d22: add esp, 0xfffffffffffffff8
         // 00401d25: mov esi, edx
         // 00401d27: mov ebx, eax
         // 00401d29: mov ecx, esp
         // 00401d2b: lea edx, ds:[esi+0x4]
         // 00401d2e: mov eax, ebx
         // 00401d30: call 0x4015d8
         // 00401d35: cmp ss:[esp], 0x0
         // 00401d39: jz 0x401d46
      [-]8bc4e826ffffff84c07504
         // 00401d3b: mov eax, esp
         // 00401d3d: call 0x401c68
         // 00401d42: test b1 al, b1 al
         // 00401d44: jnz 0x401d4a
      [-]33c0eb02
         // 00401d46: xor eax, eax
         // 00401d48: jmp 0x401d4c
      [-]595a5e5bc3
         // 00401d4c: pop ecx
         // 00401d4d: pop edx
         // 00401d4e: pop esi
         // 00401d4f: pop ebx
         // 00401d50: retn 
      [-]33d285c07903
         // 00401d54: xor edx, edx
         // 00401d56: test eax, eax
         // 00401d58: jns 0x401d5d
      [-]c1f8023d????????7f16
         // 00401d5d: sar eax, b1 0x2
         // 00401d60: cmp eax, 0x400
         // 00401d65: jg 0x401d7d
      [-]8b5482f485d27508
         // 00401d6d: mov edx, ds:[edx+eax*0x4]
         // 00401d71: test edx, edx
         // 00401d73: jnz 0x401d7d
      [-]3d????????75ea
         // 00401d76: cmp eax, 0x401
         // 00401d7b: jnz 0x401d67
      [-]535657558bf0bf????????bd????????
         // 00401d80: push ebx
         // 00401d81: push esi
         // 00401d82: push edi
         // 00401d83: push ebp
         // 00401d84: mov esi, eax
         // 00401d86: mov edi, 0x40a600
         // 00401d8b: mov ebp, 0x40a604
      [-]3b73080f8e84000000
         // 00401d96: cmp esi, ds:[ebx+0x8]
         // 00401d99: jle 0x401e23
      [-]8b1f8b43083bf07e7b
         // 00401d9f: mov ebx, ds:[edi]
         // 00401da1: mov eax, ds:[ebx+0x8]
         // 00401da4: cmp esi, eax
         // 00401da6: jle 0x401e23
      [-]8b5b043b73087ff8
         // 00401dab: mov ebx, ds:[ebx+0x4]
         // 00401dae: cmp esi, ds:[ebx+0x8]
         // 00401db1: jg 0x401dab
      [-]8b178942083b1f7404
         // 00401db3: mov edx, ds:[edi]
         // 00401db5: mov ds:[edx+0x8], eax
         // 00401db8: cmp ebx, ds:[edi]
         // 00401dba: jz 0x401dc0
      [-]891feb63
         // 00401dbc: mov ds:[edi], ebx
         // 00401dbe: jmp 0x401e23
      [-]81fe????????7f0d
         // 00401dc0: cmp esi, 0x1000
         // 00401dc6: jg 0x401dd5
      [-]8bc6e885ffffff8bd885db754e
         // 00401dc8: mov eax, esi
         // 00401dca: call 0x401d54
         // 00401dcf: mov ebx, eax
         // 00401dd1: test ebx, ebx
         // 00401dd3: jnz 0x401e23
      [-]8bc6e818ffffff84c07507
         // 00401dd5: mov eax, esi
         // 00401dd7: call 0x401cf4
         // 00401ddc: test b1 al, b1 al
         // 00401dde: jnz 0x401de7
      [-]33c0e988000000
         // 00401de0: xor eax, eax
         // 00401de2: jmp 0x401e6f
      [-]3b75007fa4
         // 00401de7: cmp esi, ss:[ebp+0x0]
         // 00401dea: jg 0x401d90
      [-]297500837d000c7d08
         // 00401dec: sub ss:[ebp+0x0], esi
         // 00401def: cmp ss:[ebp+0x0], 0xc
         // 00401df3: jge 0x401dfd
      [-]03750033c0894500
         // 00401df5: add esi, ss:[ebp+0x0]
         // 00401df8: xor eax, eax
         // 00401dfa: mov ss:[ebp+0x0], eax
      [-]a1????????0135
         // 00401dfd: mov eax, ds:[0x40a608]
         // 00401e02: add ds:[0x40a608], esi
      [-]c004ff05
         // 00401e12: inc ds:[0x40a59c]
      [-]83ee040135
         // 00401e18: sub esi, 0x4
         // 00401e1b: add ds:[0x40a5a0], esi
      [-]8bc3e802fbffff8b53088bc22bc683f80c7c0c
         // 00401e23: mov eax, ebx
         // 00401e25: call 0x40192c
         // 00401e2a: mov edx, ds:[ebx+0x8]
         // 00401e2d: mov eax, edx
         // 00401e2f: sub eax, esi
         // 00401e31: cmp eax, 0xc
         // 00401e34: jl 0x401e42
      [-]8bd303d692e854fdffffeb12
         // 00401e36: mov edx, ebx
         // 00401e38: add edx, esi
         // 00401e3a: xchg eax, edx
         // 00401e3b: call 0x401b94
         // 00401e40: jmp 0x401e54
      [-]8bf23b1f7505
         // 00401e42: mov esi, edx
         // 00401e44: cmp ebx, ds:[edi]
         // 00401e46: jnz 0x401e4d
      [-]8b43048907
         // 00401e48: mov eax, ds:[ebx+0x4]
         // 00401e4b: mov ds:[edi], eax
      [-]8bc303c68320fe
         // 00401e4d: mov eax, ebx
         // 00401e4f: add eax, esi
         // 00401e51: and ds:[eax], 0xfffffffffffffffe
      [-]8bc38bd683ca02891083c004ff05
         // 00401e54: mov eax, ebx
         // 00401e56: mov edx, esi
         // 00401e58: or edx, 0x2
         // 00401e5b: mov ds:[eax], edx
         // 00401e5d: add eax, 0x4
         // 00401e60: inc ds:[0x40a59c]
      [-]83ee040135
         // 00401e66: sub esi, 0x4
         // 00401e69: add ds:[0x40a5a0], esi
      [-]5d5f5e5bc3
         // 00401e6f: pop ebp
         // 00401e70: pop edi
         // 00401e71: pop esi
         // 00401e72: pop ebx
         // 00401e73: retn 
      [-]558bec515356578bd833c0a3????????
         // 140002004: push rbp
         // 140002005: mov b4 ebp, b4 esp
         // 140002007: push rcx
         // 140002008: push rbx
         // 140002009: push rsi
         // 14000200a: push rdi
         // 14000200b: mov b4 ebx, b4 eax
         // 14000200d: xor b4 eax, b4 eax
         // 14000200f: mov b4 ds:[0xa5ac3d800040a5b0], b4 eax
      [-]e866f7ffff84c07516
         // 0040201d: call 0x401788
         // 00402022: test b1 al, b1 al
         // 00402024: jnz 0x40203c
      [-]c745fc????????e961010000
         // 00402030: mov ss:[ebp+0xfffffffffffffffc], 0x8
         // 00402037: jmp 0x40219d
      [-]33c95568
         // 0040203c: xor ecx, ecx
         // 0040203e: push ebp
         // 0040203f: push 0x402196
      [-]64ff31648921803d35a0400000740a
         // 00402044: push fs:[ecx]
         // 00402047: mov fs:[ecx], esp
         // 0040204a: cmp b1 ds:[0x40a035], b1 0x0
         // 00402051: jz 0x40205d
      [-]e887f0ffff
         // 00402058: call EnterCriticalSection
      [-]8bf383ee048b1ef6c302750f
         // 0040205d: mov esi, ebx
         // 0040205f: sub esi, 0x4
         // 00402062: mov ebx, ds:[esi]
         // 00402064: test b1 bl, b1 0x2
         // 00402067: jnz 0x402078
      [-]e9f5000000
         // 00402073: jmp 0x40216d
      [-]8bc325????????83e8042905
         // 0040207e: mov eax, ebx
         // 00402080: and eax, 0x7ffffffc
         // 00402085: sub eax, 0x4
         // 00402088: sub ds:[0x40a5a0], eax
      [-]f6c3017445
         // 0040208e: test b1 bl, b1 0x1
         // 00402091: jz 0x4020d8
      [-]8bc683e80c8b500883fa0c7c08
         // 00402093: mov eax, esi
         // 00402095: sub eax, 0xc
         // 00402098: mov edx, ds:[eax+0x8]
         // 0040209b: cmp edx, 0xc
         // 0040209e: jl 0x4020a8
      [-]f7c2????????740f
         // 004020a0: test edx, 0xffffffff80000003
         // 004020a6: jz 0x4020b7
      [-]e9b6000000
         // 004020b2: jmp 0x40216d
      [-]8bc62bc23b5008740f
         // 004020b7: mov eax, esi
         // 004020b9: sub eax, edx
         // 004020bb: cmp edx, ds:[eax+0x8]
         // 004020be: jz 0x4020cf
      [-]e99e000000
         // 004020ca: jmp 0x40216d
      [-]03da8bf0e854f8ffff
         // 004020cf: add ebx, edx
         // 004020d1: mov esi, eax
         // 004020d3: call 0x40192c
      [-]81e3????????8bc603c38bf83b3d
         // 004020d8: and ebx, 0x7ffffffc
         // 004020de: mov eax, esi
         // 004020e0: add eax, ebx
         // 004020e2: mov edi, eax
         // 004020e4: cmp edi, ds:[0x40a608]
      [-]e813fbffff
         // 00402104: call 0x401c1c
      [-]33c08945fce8d90a0000e985000000
         // 00402109: xor eax, eax
         // 0040210b: mov ss:[ebp+0xfffffffffffffffc], eax
         // 0040210e: call 0x402bec
         // 00402113: jmp 0x40219d
      [-]8b10f6c202741c
         // 00402118: mov edx, ds:[eax]
         // 0040211a: test b1 dl, b1 0x2
         // 0040211d: jz 0x40213b
      [-]81e2????????83fa047d0c
         // 0040211f: and edx, 0x7ffffffc
         // 00402125: cmp edx, 0x4
         // 00402128: jge 0x402136
      [-]830801eb29
         // 00402136: or ds:[eax], 0x1
         // 00402139: jmp 0x402164
      [-]8bc783780400740b
         // 0040213b: mov eax, edi
         // 0040213d: cmp ds:[eax+0x4], 0x0
         // 00402141: jz 0x40214e
      [-]8338007406
         // 00402143: cmp ds:[eax], 0x0
         // 00402146: jz 0x40214e
      [-]8378080c7d0c
         // 00402148: cmp ds:[eax+0x8], 0xc
         // 0040214c: jge 0x40215a
      [-]8b500803dae8c8f7ffff
         // 0040215a: mov edx, ds:[eax+0x8]
         // 0040215d: add ebx, edx
         // 0040215f: call 0x40192c
      [-]8bd38bc6e827faffff
         // 00402164: mov edx, ebx
         // 00402166: mov eax, esi
         // 00402168: call 0x401b94
      [-]a1????????
         // 14000216d: mov b4 eax, b4 ds:[0x33fc45890040a5b0]
      [-]64891068
         // 14000217a: mov b4 fs:[rax], b4 edx
         // 14000217d: push 0x40219d
      [-]803d35a0400000740a
         // 140002182: cmp b1 cs:[0x14040c1be], b1 0x0
         // 140002189: jz 0x140002195
      [-]e857efffff
         // 00402190: call LeaveCriticalSection
      [-]8b45fc5f5e5b595dc3
         // 0040219d: mov eax, ss:[ebp+0xfffffffffffffffc]
         // 004021a0: pop edi
         // 004021a1: pop esi
         // 004021a2: pop ebx
         // 004021a3: pop ecx
         // 004021a4: pop ebp
         // 004021a5: retn 
      [-]5385c07e15
         // 00402448: push ebx
         // 00402449: test eax, eax
         // 0040244b: jle 0x402462
      [-]8bd885db750b
         // 00402453: mov ebx, eax
         // 00402455: test ebx, ebx
         // 00402457: jnz 0x402464
      [-]b001e8d0000000
         // 00402459: mov b1 al, b1 0x1
         // 0040245b: call 0x402530
      [-]8bc35bc3
         // 00402464: mov eax, ebx
         // 00402466: pop ebx
         // 00402467: retn 
      [-]5385c07415
         // 00402468: push ebx
         // 00402469: test eax, eax
         // 0040246b: jz 0x402482
      [-]8bd885db740b
         // 00402473: mov ebx, eax
         // 00402475: test ebx, ebx
         // 00402477: jz 0x402484
      [-]b002e8b0000000
         // 00402479: mov b1 al, b1 0x2
         // 0040247b: call 0x402530
      [-]8bc35bc3
         // 00402484: mov eax, ebx
         // 00402486: pop ebx
         // 00402487: retn 
      [-]8b0885c97432
         // 00402488: mov ecx, ds:[eax]
         // 0040248a: test ecx, ecx
         // 0040248c: jz 0x4024c0
      [-]85d27418
         // 0040248e: test edx, edx
         // 00402490: jz 0x4024aa
      [-]5089c8ff15
         // 00402492: push eax
         // 00402493: mov eax, ecx
         // 00402495: call ds:[0x409038]
      [-]5909c07419
         // 0040249b: pop ecx
         // 0040249c: or eax, eax
         // 0040249e: jz 0x4024b9
      [-]b002e986000000
         // 004024a3: mov b1 al, b1 0x2
         // 004024a5: jmp 0x402530
      [-]891089c8ff15
         // 004024aa: mov ds:[eax], edx
         // 004024ac: mov eax, ecx
         // 004024ae: call ds:[0x409034]
      [-]09c075eb
         // 004024b4: or eax, eax
         // 004024b6: jnz 0x4024a3
      [-]b001e970000000
         // 004024b9: mov b1 al, b1 0x1
         // 004024bb: jmp 0x402530
      [-]85d27410
         // 004024c0: test edx, edx
         // 004024c2: jz 0x4024d4
      [-]5089d0ff15
         // 004024c4: push eax
         // 004024c5: mov eax, edx
         // 004024c7: call ds:[0x409030]
      [-]5909c074e7
         // 004024cd: pop ecx
         // 004024ce: or eax, eax
         // 004024d0: jz 0x4024b9
      [-]e8990b0000
         // 004024de: call 0x40307c
      [-]8bd68bc3ff15
         // 004024f6: mov edx, esi
         // 004024f8: mov eax, ebx
         // 004024fa: call ds:[0x40a008]
      [-]84db750d
         // 00402500: test b1 bl, b1 bl
         // 00402502: jnz 0x402511
      [-]e8bf1900008b98????????eb0f
         // 00402504: call 0x403ec8
         // 00402509: mov ebx, ds:[eax+0x4]
         // 0040250f: jmp 0x402520
      [-]80fb18770a
         // 00402511: cmp b1 bl, b1 0x18
         // 00402514: ja 0x402520
      [-]33c08ac38a983c904000
         // 00402516: xor eax, eax
         // 00402518: mov b1 al, b1 bl
         // 0040251a: mov b1 bl, b1 ds:[eax+0x40903c]
      [-]33c08ac38bd6e8adffffff
         // 00402520: xor eax, eax
         // 00402522: mov b1 al, b1 bl
         // 00402524: mov edx, esi
         // 00402526: call 0x4024d8
      [-]83e07f8b1424e9a9ffffff
         // 00402530: and eax, 0x7f
         // 00402533: mov edx, ss:[esp]
         // 00402536: jmp 0x4024e4
      [-]538bd8e8841900008998????????5bc3
         // 0040253c: push ebx
         // 0040253d: mov ebx, eax
         // 0040253f: call 0x403ec8
         // 00402544: mov ds:[eax+0x4], ebx
         // 0040254a: pop ebx
         // 0040254b: retn 
      [-]565789c689d789c839f77713
         // 0040254c: push esi
         // 0040254d: push edi
         // 0040254e: mov esi, eax
         // 00402550: mov edi, edx
         // 00402552: mov eax, ecx
         // 00402554: cmp edi, esi
         // 00402556: ja 0x40256b
      [-]c1f902782a
         // 0040255a: sar ecx, b1 0x2
         // 0040255d: js 0x402589
      [-]f3a589c183e103f3a45f5ec3
         // 0040255f: rep movsdd 
         // 00402561: mov ecx, eax
         // 00402563: and ecx, 0x3
         // 00402566: rep movsbb 
         // 00402568: pop edi
         // 00402569: pop esi
         // 0040256a: retn 
      [-]8d7431fc8d7c39fcc1f9027811
         // 0040256b: lea esi, ds:[ecx+esi+0xfffffffffffffffc]
         // 0040256f: lea edi, ds:[ecx+edi+0xfffffffffffffffc]
         // 00402573: sar ecx, b1 0x2
         // 00402576: js 0x402589
      [-]fdf3a589c183e10383c60383c703f3a4fc
         // 00402578: std 
         // 00402579: rep movsdd 
         // 0040257b: mov ecx, eax
         // 0040257d: and ecx, 0x3
         // 00402580: add esi, 0x3
         // 00402583: add edi, 0x3
         // 00402586: rep movsbb 
         // 00402588: cld 
      [-]3c617206
         // 0040258c: cmp b1 al, b1 0x61
         // 0040258e: jb 0x402596
      [-]3c7a7702
         // 00402590: cmp b1 al, b1 0x7a
         // 00402592: ja 0x402596
      [-]53568bd833f6668b4304663db1d7722f
         // 00402598: push ebx
         // 00402599: push esi
         // 0040259a: mov ebx, eax
         // 0040259c: xor esi, esi
         // 0040259e: mov b2 ax, b2 ds:[ebx+0x4]
         // 004025a2: cmp b2 ax, b2 0xffffffffffffd7b1
         // 004025a6: jb 0x4025d7
      [-]663db3d77729
         // 004025a8: cmp b2 ax, b2 0xffffffffffffd7b3
         // 004025ac: ja 0x4025d7
      [-]6625b2d7663db2d77507
         // 004025ae: and b2 ax, b2 0xffffffffffffd7b2
         // 004025b2: cmp b2 ax, b2 0xffffffffffffd7b2
         // 004025b6: jnz 0x4025bf
      [-]8bc3ff531c8bf0
         // 004025b8: mov eax, ebx
         // 004025ba: call ds:[ebx+0x1c]
         // 004025bd: mov esi, eax
      [-]85f67507
         // 004025bf: test esi, esi
         // 004025c1: jnz 0x4025ca
      [-]8bc3ff53248bf0
         // 004025c3: mov eax, ebx
         // 004025c5: call ds:[ebx+0x24]
         // 004025c8: mov esi, eax
      [-]85f6741b
         // 004025ca: test esi, esi
         // 004025cc: jz 0x4025e9
      [-]8bc6e867ffffffeb12
         // 004025ce: mov eax, esi
         // 004025d0: call 0x40253c
         // 004025d5: jmp 0x4025e9
      [-]81fb????????740a
         // 004025d7: cmp ebx, 0x40a038
         // 004025dd: jz 0x4025e9
      [-]b8????????e853ffffff
         // 004025df: mov eax, 0x67
         // 004025e4: call 0x40253c
      [-]8bc65e5bc3
         // 004025e9: mov eax, esi
         // 004025eb: pop esi
         // 004025ec: pop ebx
         // 004025ed: retn 
      [-]53565189cec1ee027426
         // 004025f0: push ebx
         // 004025f1: push esi
         // 004025f2: push ecx
         // 004025f3: mov esi, ecx
         // 004025f5: shr esi, b1 0x2
         // 004025f8: jz 0x402620
      [-]8b088b1a39d97545
         // 004025fa: mov ecx, ds:[eax]
         // 004025fc: mov ebx, ds:[edx]
         // 004025fe: cmp ecx, ebx
         // 00402600: jnz 0x402647
      [-]8b48048b5a0439d97538
         // 00402605: mov ecx, ds:[eax+0x4]
         // 00402608: mov ebx, ds:[edx+0x4]
         // 0040260b: cmp ecx, ebx
         // 0040260d: jnz 0x402647
      [-]83c00883c208
         // 0040260f: add eax, 0x8
         // 00402612: add edx, 0x8
      [-]83c00483c204
         // 0040261a: add eax, 0x4
         // 0040261d: add edx, 0x4
      [-]5e83e6037436
         // 00402620: pop esi
         // 00402621: and esi, 0x3
         // 00402624: jz 0x40265c
      [-]8a083a0a7530
         // 00402626: mov b1 cl, b1 ds:[eax]
         // 00402628: cmp b1 cl, b1 ds:[edx]
         // 0040262a: jnz 0x40265c
      [-]8a48013a4a017525
         // 0040262f: mov b1 cl, b1 ds:[eax+0x1]
         // 00402632: cmp b1 cl, b1 ds:[edx+0x1]
         // 00402635: jnz 0x40265c
      [-]8a48023a4a02751a
         // 0040263a: mov b1 cl, b1 ds:[eax+0x2]
         // 0040263d: cmp b1 cl, b1 ds:[edx+0x2]
         // 00402640: jnz 0x40265c
      [-]31c05e5bc3
         // 00402642: xor eax, eax
         // 00402644: pop esi
         // 00402645: pop ebx
         // 00402646: retn 
      [-]5e38d97510
         // 00402647: pop esi
         // 00402648: cmp b1 cl, b1 bl
         // 0040264a: jnz 0x40265c
      [-]38fd750c
         // 0040264c: cmp b1 ch, b1 bh
         // 0040264e: jnz 0x40265c
      [-]c1e910c1eb1038d97502
         // 00402650: shr ecx, b1 0x10
         // 00402653: shr ebx, b1 0x10
         // 00402656: cmp b1 cl, b1 bl
         // 00402658: jnz 0x40265c
      [-]5789c788cd89c8c1e0106689c889d1c1f9027809
         // 00402660: push edi
         // 00402661: mov edi, eax
         // 00402663: mov b1 ch, b1 cl
         // 00402665: mov eax, ecx
         // 00402667: shl eax, b1 0x10
         // 0040266a: mov b2 ax, b2 cx
         // 0040266d: mov ecx, edx
         // 0040266f: sar ecx, b1 0x2
         // 00402672: js 0x40267d
      [-]f3ab89d183e103f3aa
         // 00402674: rep stosdd 
         // 00402676: mov ecx, edx
         // 00402678: and ecx, 0x3
         // 0040267b: rep stosbb 
      [-]5331db6993????????????????
         // 00402680: push ebx
         // 00402681: xor ebx, ebx
         // 00402683: imul edx, ds:[ebx+0x409008], 0x8088405
      [-]8993????????f7e289d05bc3
         // 0040268e: mov ds:[ebx+0x409008], edx
         // 00402694: mul edx
         // 00402696: mov eax, edx
         // 00402698: pop ebx
         // 00402699: retn 
      [-]b9????????e802000000c3
         // 00402770: mov ecx, 0xff
         // 00402775: call 0x40277c
         // 0040277a: retn 
      [-]535081f9????????7605
         // 0040277c: push ebx
         // 0040277d: push eax
         // 0040277e: cmp ecx, 0xff
         // 00402784: jbe 0x40278b
      [-]b9????????
         // 00402786: mov ecx, 0xff
      [-]84db7406
         // 0040278e: test b1 bl, b1 bl
         // 00402790: jz 0x402798
      [-]5a29d088025bc3
         // 00402798: pop edx
         // 00402799: sub eax, edx
         // 0040279b: mov b1 ds:[edx], b1 al
         // 0040279d: pop ebx
         // 0040279e: retn 
      [-]83fa017301
         // 004027a0: cmp edx, 0x1
         // 004027a3: jnb 0x4027a6
      [-]5185c07543
         // 004027a6: push ecx
         // 004027a7: test eax, eax
         // 004027a9: jnz 0x4027ee
      [-]8b42f885c07435
         // 004027ab: mov eax, ds:[edx+0xfffffffffffffff8]
         // 004027ae: test eax, eax
         // 004027b0: jz 0x4027e7
      [-]52e890fcffff5a85c07426
         // 004027b2: push edx
         // 004027b3: call 0x402448
         // 004027b8: pop edx
         // 004027b9: test eax, eax
         // 004027bb: jz 0x4027e3
      [-]31d259c3
         // 004027e3: xor edx, edx
         // 004027e5: pop ecx
         // 004027e6: retn 
      [-]31d283f80159c3
         // 004027e7: xor edx, edx
         // 004027e9: cmp eax, 0x1
         // 004027ec: pop ecx
         // 004027ed: retn 
      [-]8b4afc85c97c03
         // 004027ee: mov ecx, ds:[edx+0xfffffffffffffffc]
         // 004027f1: test ecx, ecx
         // 004027f3: jl 0x4027f8
      [-]31d285c059c3
         // 004027f8: xor edx, edx
         // 004027fa: test eax, eax
         // 004027fc: pop ecx
         // 004027fd: retn 
      [-]dbe39bd92d18904000c3
         // 004028fc: fninit 
         // 004028fe: wait 
         // 004028ff: fldcw b2 ds:[0x409018]
         // 00402905: retn 
      [-]85c07407
         // 00402908: test eax, eax
         // 0040290a: jz 0x402913
      [-]b2018b08ff51fc
         // 0040290c: mov b1 dl, b1 0x1
         // 0040290e: mov ecx, ds:[eax]
         // 00402910: call ds:[ecx+0xfffffffffffffffc]
      [-]85c97419
         // 00402980: test ecx, ecx
         // 00402982: jz 0x40299d
      [-]8b41018039e9740c
         // 00402984: mov eax, ds:[ecx+0x1]
         // 00402987: cmp b1 ds:[ecx], b1 0xe9
         // 0040298a: jz 0x402998
      [-]8039eb750c
         // 0040298c: cmp b1 ds:[ecx], b1 0xeb
         // 0040298f: jnz 0x40299d
      [-]803d1c90400001761d
         // 004029a0: cmp b1 ds:[0x40901c], b1 0x1
         // 004029a7: jbe 0x4029c6
      [-]505251e8cfffffff51546a016a0068
         // 004029a9: push eax
         // 004029aa: push edx
         // 004029ab: push ecx
         // 004029ac: call 0x402980
         // 004029b1: push ecx
         // 004029b2: push esp
         // 004029b3: push 0x1
         // 004029b5: push 0x0
         // 004029b7: push 0xeedfae1
      [-]803d1c904000017612
         // 004029c8: cmp b1 ds:[0x40901c], b1 0x1
         // 004029cf: jbe 0x4029e3
      [-]52546a016a0068
         // 004029d1: push edx
         // 004029d2: push esp
         // 004029d3: push 0x1
         // 004029d5: push 0x0
         // 004029d7: push 0xeedfae2
      [-]31d28b4c24088b44240483c105648902ffd1c20c00
         // 00402bec: xor edx, edx
         // 00402bee: mov ecx, ss:[esp+0x8]
         // 00402bf2: mov eax, ss:[esp+0x4]
         // 00402bf6: add ecx, 0x5
         // 00402bf9: mov fs:[edx], eax
         // 00402bfc: call ecx
         // 00402bfe: retn b2 0xc
      [-]8b1085d2741c
         // 00403094: mov edx, ds:[eax]
         // 00403096: test edx, edx
         // 00403098: jz 0x4030b6
      [-]c700????????8b4af8
         // 0040309a: mov ds:[eax], 0x0
         // 004030a0: mov ecx, ds:[edx+0xfffffffffffffff8]
      [-]f0ff4af8750a
         // 004030a6: lock dec ds:[edx+0xfffffffffffffff8]
         // 004030aa: jnz 0x4030b6
      [-]508d42f8e8b3f3ffff58
         // 004030ac: push eax
         // 004030ad: lea eax, ds:[edx+0xfffffffffffffff8]
         // 004030b0: call 0x402468
         // 004030b5: pop eax
      [-]535689c389d6
         // 004030b8: push ebx
         // 004030b9: push esi
         // 004030ba: mov ebx, eax
         // 004030bc: mov esi, edx
      [-]8b1385d2741a
         // 004030be: mov edx, ds:[ebx]
         // 004030c0: test edx, edx
         // 004030c2: jz 0x4030de
      [-]c703????????8b4af8
         // 004030c4: mov ds:[ebx], 0x0
         // 004030ca: mov ecx, ds:[edx+0xfffffffffffffff8]
      [-]f0ff4af87508
         // 004030d0: lock dec ds:[edx+0xfffffffffffffff8]
         // 004030d4: jnz 0x4030de
      [-]8d42f8e88af3ffff
         // 004030d6: lea eax, ds:[edx+0xfffffffffffffff8]
         // 004030d9: call 0x402468
      [-]85d27424
         // 004030e8: test edx, edx
         // 004030ea: jz 0x403110
      [-]50528b42fce85c00000089c258528b48fce844f4ffff5a58eb04
         // 004030f2: push eax
         // 004030f3: push edx
         // 004030f4: mov eax, ds:[edx+0xfffffffffffffffc]
         // 004030f7: call 0x403158
         // 004030fc: mov edx, eax
         // 004030fe: pop eax
         // 004030ff: push edx
         // 00403100: mov ecx, ds:[eax+0xfffffffffffffffc]
         // 00403103: call 0x40254c
         // 00403108: pop edx
         // 00403109: pop eax
         // 0040310a: jmp 0x403110
      [-]f0ff42f8
         // 0040310c: lock inc ds:[edx+0xfffffffffffffff8]
      [-]871085d27414
         // 00403110: xchg edx, ds:[eax]
         // 00403112: test edx, edx
         // 00403114: jz 0x40312a
      [-]f0ff4af87508
         // 0040311c: lock dec ds:[edx+0xfffffffffffffff8]
         // 00403120: jnz 0x40312a
      [-]8d42f8e83ef3ffff
         // 00403122: lea eax, ds:[edx+0xfffffffffffffff8]
         // 00403125: call 0x402468
      [-]85d2740a
         // 0040312c: test edx, edx
         // 0040312e: jz 0x40313a
      [-]f0ff42f8
         // 00403136: lock inc ds:[edx+0xfffffffffffffff8]
      [-]871085d27414
         // 0040313a: xchg edx, ds:[eax]
         // 0040313c: test edx, edx
         // 0040313e: jz 0x403154
      [-]f0ff4af87508
         // 00403146: lock dec ds:[edx+0xfffffffffffffff8]
         // 0040314a: jnz 0x403154
      [-]8d42f8e814f3ffff
         // 0040314c: lea eax, ds:[edx+0xfffffffffffffff8]
         // 0040314f: call 0x402468
      [-]85c07e24
         // 00403158: test eax, eax
         // 0040315a: jle 0x403180
      [-]5083c00a83e0fe50e8dff2ffff5a66c74402fe000083c0085a8950fcc740f8????????c3
         // 0040315c: push eax
         // 0040315d: add eax, 0xa
         // 00403160: and eax, 0xfffffffffffffffe
         // 00403163: push eax
         // 00403164: call 0x402448
         // 00403169: pop edx
         // 0040316a: mov b2 ds:[edx+eax+0xfffffffffffffffe], b2 0x0
         // 00403171: add eax, 0x8
         // 00403174: pop edx
         // 00403175: mov ds:[eax+0xfffffffffffffffc], edx
         // 00403178: mov ds:[eax+0xfffffffffffffff8], 0x1
         // 0040317f: retn 
      [-]53565789c389d689cf89f8e8c4ffffff89f989c785f67409
         // 00403184: push ebx
         // 00403185: push esi
         // 00403186: push edi
         // 00403187: mov ebx, eax
         // 00403189: mov esi, edx
         // 0040318b: mov edi, ecx
         // 0040318d: mov eax, edi
         // 0040318f: call 0x403158
         // 00403194: mov ecx, edi
         // 00403196: mov edi, eax
         // 00403198: test esi, esi
         // 0040319a: jz 0x4031a5
      [-]89c289f0e8a7f3ffff
         // 0040319c: mov edx, eax
         // 0040319e: mov eax, esi
         // 004031a0: call 0x40254c
      [-]89d8e8e8feffff893b5f5e5bc3
         // 004031a5: mov eax, ebx
         // 004031a7: call 0x403094
         // 004031ac: mov ds:[ebx], edi
         // 004031ae: pop edi
         // 004031af: pop esi
         // 004031b0: pop ebx
         // 004031b1: retn 
      [-]5289e2b9????????e8c3ffffff5ac3
         // 004031b4: push edx
         // 004031b5: mov edx, esp
         // 004031b7: mov ecx, 0x1
         // 004031bc: call 0x403184
         // 004031c1: pop edx
         // 004031c2: retn 
      [-]31c985d27421
         // 004031c4: xor ecx, ecx
         // 004031c6: test edx, edx
         // 004031c8: jz 0x4031eb
      [-]89d15a29d1
         // 004031e6: mov ecx, edx
         // 004031e8: pop edx
         // 004031e9: sub ecx, edx
      [-]e994ffffff
         // 004031eb: jmp 0x403184
      [-]57505189d731c0f2ae7502
         // 004031f4: push edi
         // 004031f5: push eax
         // 004031f6: push ecx
         // 004031f7: mov edi, edx
         // 004031f9: xor eax, eax
         // 004031fb: repne scasbb 
         // 004031fd: jnz 0x403201
      [-]5801c1585fe979ffffff
         // 00403201: pop eax
         // 00403202: add ecx, eax
         // 00403204: pop eax
         // 00403205: pop edi
         // 00403206: jmp 0x403184
      [-]85c07403
         // 0040320c: test eax, eax
         // 0040320e: jz 0x403213
      [-]85d2743f
         // 00403214: test edx, edx
         // 00403216: jz 0x403257
      [-]8b0885c90f84c6feffff
         // 00403218: mov ecx, ds:[eax]
         // 0040321a: test ecx, ecx
         // 0040321c: jz 0x4030e8
      [-]53565789c389d68b79fc8b56fc01fa39ce7417
         // 00403222: push ebx
         // 00403223: push esi
         // 00403224: push edi
         // 00403225: mov ebx, eax
         // 00403227: mov esi, edx
         // 00403229: mov edi, ds:[ecx+0xfffffffffffffffc]
         // 0040322c: mov edx, ds:[esi+0xfffffffffffffffc]
         // 0040322f: add edx, edi
         // 00403231: cmp esi, ecx
         // 00403233: jz 0x40324c
      [-]e8fa02000089f08b4efc
         // 00403235: call 0x403534
         // 0040323a: mov eax, esi
         // 0040323c: mov ecx, ds:[esi+0xfffffffffffffffc]
      [-]8b1301fae804f3ffff5f5e5bc3
         // 0040323f: mov edx, ds:[ebx]
         // 00403241: add edx, edi
         // 00403243: call 0x40254c
         // 00403248: pop edi
         // 00403249: pop esi
         // 0040324a: pop ebx
         // 0040324b: retn 
      [-]e8e30200008b0389f9ebe8
         // 0040324c: call 0x403534
         // 00403251: mov eax, ds:[ebx]
         // 00403253: mov ecx, edi
         // 00403255: jmp 0x40323f
      [-]85d27461
         // 00403258: test edx, edx
         // 0040325a: jz 0x4032bd
      [-]85c90f8484feffff
         // 0040325c: test ecx, ecx
         // 0040325e: jz 0x4030e8
      [-]3b10745c
         // 00403264: cmp edx, ds:[eax]
         // 00403266: jz 0x4032c4
      [-]3b08740e
         // 00403268: cmp ecx, ds:[eax]
         // 0040326a: jz 0x40327a
      [-]5051e875feffff5a58e99affffff
         // 0040326c: push eax
         // 0040326d: push ecx
         // 0040326e: call 0x4030e8
         // 00403273: pop edx
         // 00403274: pop eax
         // 00403275: jmp 0x403214
      [-]53565789d389ce508b43fc0346fce8cbfeffff89c789c289d88b4bfce8b1f2ffff89fa89f08b4efc0353fce8a2f2ffff5889fa85ff7403
         // 0040327a: push ebx
         // 0040327b: push esi
         // 0040327c: push edi
         // 0040327d: mov ebx, edx
         // 0040327f: mov esi, ecx
         // 00403281: push eax
         // 00403282: mov eax, ds:[ebx+0xfffffffffffffffc]
         // 00403285: add eax, ds:[esi+0xfffffffffffffffc]
         // 00403288: call 0x403158
         // 0040328d: mov edi, eax
         // 0040328f: mov edx, eax
         // 00403291: mov eax, ebx
         // 00403293: mov ecx, ds:[ebx+0xfffffffffffffffc]
         // 00403296: call 0x40254c
         // 0040329b: mov edx, edi
         // 0040329d: mov eax, esi
         // 0040329f: mov ecx, ds:[esi+0xfffffffffffffffc]
         // 004032a2: add edx, ds:[ebx+0xfffffffffffffffc]
         // 004032a5: call 0x40254c
         // 004032aa: pop eax
         // 004032ab: mov edx, edi
         // 004032ad: test edi, edi
         // 004032af: jz 0x4032b4
      [-]e82ffeffff5f5e5bc3
         // 004032b4: call 0x4030e8
         // 004032b9: pop edi
         // 004032ba: pop esi
         // 004032bb: pop ebx
         // 004032bc: retn 
      [-]89cae924feffff
         // 004032bd: mov edx, ecx
         // 004032bf: jmp 0x4030e8
      [-]89cae949ffffff
         // 004032c4: mov edx, ecx
         // 004032c6: jmp 0x403214
      [-]535657525089d331ff8b4c941485c9740c
         // 004032cc: push ebx
         // 004032cd: push esi
         // 004032ce: push edi
         // 004032cf: push edx
         // 004032d0: push eax
         // 004032d1: mov ebx, edx
         // 004032d3: xor edi, edi
         // 004032d5: mov ecx, ss:[esp+edx*0x4]
         // 004032d9: test ecx, ecx
         // 004032db: jz 0x4032e9
      [-]39087508
         // 004032dd: cmp ds:[eax], ecx
         // 004032df: jnz 0x4032e9
      [-]89cf8b41fc
         // 004032e1: mov edi, ecx
         // 004032e3: mov eax, ds:[ecx+0xfffffffffffffffc]
      [-]8b4c941485c97409
         // 004032eb: mov ecx, ss:[esp+edx*0x4]
         // 004032ef: test ecx, ecx
         // 004032f1: jz 0x4032fc
      [-]0341fc39cf7502
         // 004032f3: add eax, ds:[ecx+0xfffffffffffffffc]
         // 004032f6: cmp edi, ecx
         // 004032f8: jnz 0x4032fc
      [-]85ff7417
         // 004032ff: test edi, edi
         // 00403301: jz 0x40331a
      [-]89c28b04248b77fce8240200008b3c24ff370337
         // 00403303: mov edx, eax
         // 00403305: mov eax, ss:[esp]
         // 00403308: mov esi, ds:[edi+0xfffffffffffffffc]
         // 0040330b: call 0x403534
         // 00403310: mov edi, ss:[esp]
         // 00403313: push ds:[edi]
         // 00403315: add esi, ds:[edi]
      [-]e839feffff5089c6
         // 0040331a: call 0x403158
         // 0040331f: push eax
         // 00403320: mov esi, eax
      [-]8b449c1889f285c0740a
         // 00403322: mov eax, ss:[esp+ebx*0x4]
         // 00403326: mov edx, esi
         // 00403328: test eax, eax
         // 0040332a: jz 0x403336
      [-]8b48fc01cee816f2ffff
         // 0040332c: mov ecx, ds:[eax+0xfffffffffffffffc]
         // 0040332f: add esi, ecx
         // 00403331: call 0x40254c
      [-]5a5885ff750c
         // 00403339: pop edx
         // 0040333a: pop eax
         // 0040333b: test edi, edi
         // 0040333d: jnz 0x40334b
      [-]85d27403
         // 0040333f: test edx, edx
         // 00403341: jz 0x403346
      [-]e89dfdffff
         // 00403346: call 0x4030e8
      [-]5a5f5e5b588d2494ffe0
         // 0040334b: pop edx
         // 0040334c: pop edi
         // 0040334d: pop esi
         // 0040334e: pop ebx
         // 0040334f: pop eax
         // 00403350: lea esp, ss:[esp+edx*0x4]
         // 00403353: jmp eax
      [-]53565789c689d739d00f848f000000
         // 00403358: push ebx
         // 00403359: push esi
         // 0040335a: push edi
         // 0040335b: mov esi, eax
         // 0040335d: mov edi, edx
         // 0040335f: cmp eax, edx
         // 00403361: jz 0x4033f6
      [-]85f67468
         // 00403367: test esi, esi
         // 00403369: jz 0x4033d3
      [-]85ff746b
         // 0040336b: test edi, edi
         // 0040336d: jz 0x4033da
      [-]8b46fc8b57fc29d07702
         // 0040336f: mov eax, ds:[esi+0xfffffffffffffffc]
         // 00403372: mov edx, ds:[edi+0xfffffffffffffffc]
         // 00403375: sub eax, edx
         // 00403377: ja 0x40337b
      [-]52c1ea027426
         // 0040337b: push edx
         // 0040337c: shr edx, b1 0x2
         // 0040337f: jz 0x4033a7
      [-]8b0e8b1f39d97558
         // 00403381: mov ecx, ds:[esi]
         // 00403383: mov ebx, ds:[edi]
         // 00403385: cmp ecx, ebx
         // 00403387: jnz 0x4033e1
      [-]8b4e048b5f0439d9754b
         // 0040338c: mov ecx, ds:[esi+0x4]
         // 0040338f: mov ebx, ds:[edi+0x4]
         // 00403392: cmp ecx, ebx
         // 00403394: jnz 0x4033e1
      [-]83c60883c708
         // 00403396: add esi, 0x8
         // 00403399: add edi, 0x8
      [-]83c60483c704
         // 004033a1: add esi, 0x4
         // 004033a4: add edi, 0x4
      [-]5a83e2037422
         // 004033a7: pop edx
         // 004033a8: and edx, 0x3
         // 004033ab: jz 0x4033cf
      [-]8b0e8b1f38d97541
         // 004033ad: mov ecx, ds:[esi]
         // 004033af: mov ebx, ds:[edi]
         // 004033b1: cmp b1 cl, b1 bl
         // 004033b3: jnz 0x4033f6
      [-]38fd753a
         // 004033b8: cmp b1 ch, b1 bh
         // 004033ba: jnz 0x4033f6
      [-]81e3????????81e1????????39d97527
         // 004033bf: and ebx, 0xff0000
         // 004033c5: and ecx, 0xff0000
         // 004033cb: cmp ecx, ebx
         // 004033cd: jnz 0x4033f6
      [-]01c0eb23
         // 004033cf: add eax, eax
         // 004033d1: jmp 0x4033f6
      [-]8b57fc29d0eb1c
         // 004033d3: mov edx, ds:[edi+0xfffffffffffffffc]
         // 004033d6: sub eax, edx
         // 004033d8: jmp 0x4033f6
      [-]8b46fc29d0eb15
         // 004033da: mov eax, ds:[esi+0xfffffffffffffffc]
         // 004033dd: sub eax, edx
         // 004033df: jmp 0x4033f6
      [-]5a38d97510
         // 004033e1: pop edx
         // 004033e2: cmp b1 cl, b1 bl
         // 004033e4: jnz 0x4033f6
      [-]38fd750c
         // 004033e6: cmp b1 ch, b1 bh
         // 004033e8: jnz 0x4033f6
      [-]c1e910c1eb1038d97502
         // 004033ea: shr ecx, b1 0x10
         // 004033ed: shr ebx, b1 0x10
         // 004033f0: cmp b1 cl, b1 bl
         // 004033f2: jnz 0x4033f6
      [-]5f5e5bc3
         // 004033f6: pop edi
         // 004033f7: pop esi
         // 004033f8: pop ebx
         // 004033f9: retn 
      [-]85c0740a
         // 004033fc: test eax, eax
         // 004033fe: jz 0x40340a
      [-]f0ff40f8
         // 00403406: lock inc ds:[eax+0xfffffffffffffff8]
      [-]85c07402
         // 0040340c: test eax, eax
         // 0040340e: jz 0x403412
      [-]b8????????c3
         // 00403412: mov eax, 0x403411
         // 00403417: retn 
      [-]8b1085d27438
         // 00403418: mov edx, ds:[eax]
         // 0040341a: test edx, edx
         // 0040341c: jz 0x403456
      [-]5389c38b42fce829fdffff89c28b038913508b48fce80ef1ffff588b48f8
         // 00403424: push ebx
         // 00403425: mov ebx, eax
         // 00403427: mov eax, ds:[edx+0xfffffffffffffffc]
         // 0040342a: call 0x403158
         // 0040342f: mov edx, eax
         // 00403431: mov eax, ds:[ebx]
         // 00403433: mov ds:[ebx], edx
         // 00403435: push eax
         // 00403436: mov ecx, ds:[eax+0xfffffffffffffffc]
         // 00403439: call 0x40254c
         // 0040343e: pop eax
         // 0040343f: mov ecx, ds:[eax+0xfffffffffffffff8]
      [-]f0ff48f87508
         // 00403445: lock dec ds:[eax+0xfffffffffffffff8]
         // 00403449: jnz 0x403453
      [-]8d40f8e815f0ffff
         // 0040344b: lea eax, ds:[eax+0xfffffffffffffff8]
         // 0040344e: call 0x402468
      [-]e9b7ffffff
         // 0040345c: jmp 0x403418
      [-]5385c0742d
         // 00403464: push ebx
         // 00403465: test eax, eax
         // 00403467: jz 0x403496
      [-]8b58fc85db7426
         // 00403469: mov ebx, ds:[eax+0xfffffffffffffffc]
         // 0040346c: test ebx, ebx
         // 0040346e: jz 0x403496
      [-]39da7d1f
         // 00403473: cmp edx, ebx
         // 00403475: jge 0x403496
      [-]29d385c97c19
         // 00403477: sub ebx, edx
         // 00403479: test ecx, ecx
         // 0040347b: jl 0x403496
      [-]39d97f11
         // 0040347d: cmp ecx, ebx
         // 0040347f: jg 0x403492
      [-]01c28b442408e8f8fcffffeb11
         // 00403481: add edx, eax
         // 00403483: mov eax, ss:[esp+0x8]
         // 00403487: call 0x403184
         // 0040348c: jmp 0x40349f
      [-]31d2ebe5
         // 0040348e: xor edx, edx
         // 00403490: jmp 0x403477
      [-]89d9ebeb
         // 00403492: mov ecx, ebx
         // 00403494: jmp 0x403481
      [-]8b442408e8f5fbffff
         // 00403496: mov eax, ss:[esp+0x8]
         // 0040349a: call 0x403094
      [-]5bc20400
         // 0040349f: pop ebx
         // 004034a0: retn b2 0x4
      [-]53565789c389d689cfe8aaffffff8b1385d27430
         // 004034a4: push ebx
         // 004034a5: push esi
         // 004034a6: push edi
         // 004034a7: mov ebx, eax
         // 004034a9: mov esi, edx
         // 004034ab: mov edi, ecx
         // 004034ad: call 0x40345c
         // 004034b2: mov edx, ds:[ebx]
         // 004034b4: test edx, edx
         // 004034b6: jz 0x4034e8
      [-]39ce7d26
         // 004034be: cmp esi, ecx
         // 004034c0: jge 0x4034e8
      [-]85ff7e22
         // 004034c2: test edi, edi
         // 004034c4: jle 0x4034e8
      [-]29f139cf7e02
         // 004034c6: sub ecx, esi
         // 004034c8: cmp edi, ecx
         // 004034ca: jle 0x4034ce
      [-]29f901f28d0417e872f0ffff8b1389d88b52fc29fae84c000000
         // 004034ce: sub ecx, edi
         // 004034d0: add edx, esi
         // 004034d2: lea eax, ds:[edi+edx]
         // 004034d5: call 0x40254c
         // 004034da: mov edx, ds:[ebx]
         // 004034dc: mov eax, ebx
         // 004034de: mov edx, ds:[edx+0xfffffffffffffffc]
         // 004034e1: sub edx, edi
         // 004034e3: call 0x403534
      [-]5f5e5bc3
         // 004034e8: pop edi
         // 004034e9: pop esi
         // 004034ea: pop ebx
         // 004034eb: retn 
      [-]53565789c389d631ff85d27e48
         // 00403534: push ebx
         // 00403535: push esi
         // 00403536: push edi
         // 00403537: mov ebx, eax
         // 00403539: mov esi, edx
         // 0040353b: xor edi, edi
         // 0040353d: test edx, edx
         // 0040353f: jle 0x403589
      [-]8b0385c07423
         // 00403541: mov eax, ds:[ebx]
         // 00403543: test eax, eax
         // 00403545: jz 0x40356a
      [-]8378f801751d
         // 00403547: cmp ds:[eax+0xfffffffffffffff8], 0x1
         // 0040354b: jnz 0x40356a
      [-]83e80883c2095089e0e82defffff5883c00889038970fcc6040600eb28
         // 0040354d: sub eax, 0x8
         // 00403550: add edx, 0x9
         // 00403553: push eax
         // 00403554: mov eax, esp
         // 00403556: call 0x402488
         // 0040355b: pop eax
         // 0040355c: add eax, 0x8
         // 0040355f: mov ds:[ebx], eax
         // 00403561: mov ds:[eax+0xfffffffffffffffc], esi
         // 00403564: mov b1 ds:[esi+eax], b1 0x0
         // 00403568: jmp 0x403592
      [-]89d0e8e7fbffff89c78b0385c07410
         // 0040356a: mov eax, edx
         // 0040356c: call 0x403158
         // 00403571: mov edi, eax
         // 00403573: mov eax, ds:[ebx]
         // 00403575: test eax, eax
         // 00403577: jz 0x403589
      [-]89fa8b48fc39f17c02
         // 00403579: mov edx, edi
         // 0040357b: mov ecx, ds:[eax+0xfffffffffffffffc]
         // 0040357e: cmp ecx, esi
         // 00403580: jl 0x403584
      [-]e8c3efffff
         // 00403584: call 0x40254c
      [-]89d8e804fbffff893b
         // 00403589: mov eax, ebx
         // 0040358b: call 0x403094
         // 00403590: mov ds:[ebx], edi
      [-]5f5e5bc3
         // 00403592: pop edi
         // 00403593: pop esi
         // 00403594: pop ebx
         // 00403595: retn 
      [-]b001e991efffff
         // 00403598: mov b1 al, b1 0x1
         // 0040359a: jmp 0x402530
      [-]8b1085d2740e
         // 004035a0: mov edx, ds:[eax]
         // 004035a2: test edx, edx
         // 004035a4: jz 0x4035b4
      [-]c700????????5052e8cddaffff58
         // 004035a6: mov ds:[eax], 0x0
         // 004035ac: push eax
         // 004035ad: push edx
         // 004035ae: call SysFreeString
         // 004035b3: pop eax
      [-]535689c389d6
         // 004035b8: push ebx
         // 004035b9: push esi
         // 004035ba: mov ebx, eax
         // 004035bc: mov esi, edx
      [-]8b0385c0740c
         // 004035be: mov eax, ds:[ebx]
         // 004035c0: test eax, eax
         // 004035c2: jz 0x4035d0
      [-]c703????????50e8b0daffff
         // 004035c4: mov ds:[ebx], 0x0
         // 004035ca: push eax
         // 004035cb: call SysFreeString
      [-]85d20f84bcffffff
         // 004035dc: test edx, edx
         // 004035de: jz 0x4035a0
      [-]8b4afcd1e90f84b1ffffff
         // 004035e4: mov ecx, ds:[edx+0xfffffffffffffffc]
         // 004035e7: shr ecx, b1 0x1
         // 004035e9: jz 0x4035a0
      [-]515250e881daffff85c00f8499ffffff
         // 004035ef: push ecx
         // 004035f0: push edx
         // 004035f1: push eax
         // 004035f2: call SysReAllocStringLen
         // 004035f7: test eax, eax
         // 004035f9: jz 0x403598
      [-]31c9538a4a01565789c38d74110a8b7c1106
         // 00403600: xor ecx, ecx
         // 00403602: push ebx
         // 00403603: mov b1 cl, b1 ds:[edx+0x1]
         // 00403606: push esi
         // 00403607: push edi
         // 00403608: mov ebx, eax
         // 0040360a: lea esi, ds:[ecx+edx+0xa]
         // 0040360e: mov edi, ds:[ecx+edx+0x6]
      [-]8b168b460401d88b12b9????????e82700000083c608
         // 00403612: mov edx, ds:[esi]
         // 00403614: mov eax, ds:[esi+0x4]
         // 00403617: add eax, ebx
         // 00403619: mov edx, ds:[edx]
         // 0040361b: mov ecx, 0x1
         // 00403620: call 0x40364c
         // 00403625: add esi, 0x8
      [-]89d85f5e5bc3
         // 0040362b: mov eax, ebx
         // 0040362d: pop edi
         // 0040362e: pop esi
         // 0040362f: pop ebx
         // 00403630: retn 
      [-]b010e8e5eeffff
         // 00403644: mov b1 al, b1 0x10
         // 00403646: call 0x402530
      [-]83f9000f84e0000000
         // 0040364c: cmp ecx, 0x0
         // 0040364f: jz 0x403735
      [-]3c110f848b000000
         // 00403682: cmp b1 al, b1 0x11
         // 00403684: jz 0x403715
      [-]e997000000
         // 0040368a: jmp 0x403726
      [-]5f5e5b58b002e9ffedffff
         // 00403726: pop edi
         // 00403727: pop esi
         // 00403728: pop ebx
         // 00403729: pop eax
         // 0040372a: mov b1 al, b1 0x2
         // 0040372c: jmp 0x402530
      [-]5f5e5b58
         // 00403731: pop edi
         // 00403732: pop esi
         // 00403733: pop ebx
         // 00403734: pop eax
      [-]b010e8e1edffff
         // 00403748: mov b1 al, b1 0x10
         // 0040374a: call 0x402530
      [-]5356575589c389d631c08a41018d7c080a8b6ffc31c08b4ff851
         // 00403750: push ebx
         // 00403751: push esi
         // 00403752: push edi
         // 00403753: push ebp
         // 00403754: mov ebx, eax
         // 00403756: mov esi, edx
         // 00403758: xor eax, eax
         // 0040375a: mov b1 al, b1 ds:[ecx+0x1]
         // 0040375d: lea edi, ds:[eax+ecx+0xa]
         // 00403761: mov ebp, ds:[edi+0xfffffffffffffffc]
         // 00403764: xor eax, eax
         // 00403766: mov ecx, ds:[edi+0xfffffffffffffff8]
         // 00403769: push ecx
      [-]8b4f0429c17e0b
         // 0040376a: mov ecx, ds:[edi+0x4]
         // 0040376d: sub ecx, eax
         // 0040376f: jle 0x40377c
      [-]89c201f001dae8d0edffff
         // 00403771: mov edx, eax
         // 00403773: add eax, esi
         // 00403775: add edx, ebx
         // 00403777: call 0x40254c
      [-]8b47048b178b128a0a80f90a7431
         // 0040377c: mov eax, ds:[edi+0x4]
         // 0040377f: mov edx, ds:[edi]
         // 00403781: mov edx, ds:[edx]
         // 00403783: mov b1 cl, b1 ds:[edx]
         // 00403785: cmp b1 cl, b1 0xa
         // 00403788: jz 0x4037bb
      [-]80f90b743d
         // 0040378a: cmp b1 cl, b1 0xb
         // 0040378d: jz 0x4037cc
      [-]80f90c7449
         // 0040378f: cmp b1 cl, b1 0xc
         // 00403792: jz 0x4037dd
      [-]80f90d7455
         // 00403794: cmp b1 cl, b1 0xd
         // 00403797: jz 0x4037ee
      [-]80f90e7470
         // 00403799: cmp b1 cl, b1 0xe
         // 0040379c: jz 0x40380e
      [-]80f90f0f8480000000
         // 0040379e: cmp b1 cl, b1 0xf
         // 004037a1: jz 0x403827
      [-]80f9110f8488000000
         // 004037a7: cmp b1 cl, b1 0x11
         // 004037aa: jz 0x403838
      [-]b0025d5f5e5be975edffff
         // 004037b0: mov b1 al, b1 0x2
         // 004037b2: pop ebp
         // 004037b3: pop edi
         // 004037b4: pop esi
         // 004037b5: pop ebx
         // 004037b6: jmp 0x402530
      [-]8b143001d8e823f9ffffb8????????eb7d
         // 004037bb: mov edx, ds:[eax+esi]
         // 004037be: add eax, ebx
         // 004037c0: call 0x4030e8
         // 004037c5: mov eax, 0x4
         // 004037ca: jmp 0x403849
      [-]8b143001d8e806feffffb8????????eb6c
         // 004037cc: mov edx, ds:[eax+esi]
         // 004037cf: add eax, ebx
         // 004037d1: call 0x4035dc
         // 004037d6: mov eax, 0x4
         // 004037db: jmp 0x403849
      [-]8d143001d8e851ffffffb8????????eb5b
         // 004037dd: lea edx, ds:[eax+esi]
         // 004037e0: add eax, ebx
         // 004037e2: call 0x403738
         // 004037e7: mov eax, 0x10
         // 004037ec: jmp 0x403849
      [-]31c98a4a01ff741102ff7411068b4c110a8b098d143001d8e86100000058eb3b
         // 004037ee: xor ecx, ecx
         // 004037f0: mov b1 cl, b1 ds:[edx+0x1]
         // 004037f3: push ds:[ecx+edx+0x2]
         // 004037f7: push ds:[ecx+edx+0x6]
         // 004037fb: mov ecx, ds:[ecx+edx+0xa]
         // 004037ff: mov ecx, ds:[ecx]
         // 00403801: lea edx, ds:[eax+esi]
         // 00403804: add eax, ebx
         // 00403806: call 0x40386c
         // 0040380b: pop eax
         // 0040380c: jmp 0x403849
      [-]31c98a4a01
         // 0040380e: xor ecx, ecx
         // 00403810: mov b1 cl, b1 ds:[edx+0x1]
      [-]8b143001d8e857040000b8????????eb11
         // 00403827: mov edx, ds:[eax+esi]
         // 0040382a: add eax, ebx
         // 0040382c: call 0x403c88
         // 00403831: mov eax, 0x4
         // 00403836: jmp 0x403849
      [-]89d18b143001d8e828030000b8????????
         // 00403838: mov ecx, edx
         // 0040383a: mov edx, ds:[eax+esi]
         // 0040383d: add eax, ebx
         // 0040383f: call 0x403b6c
         // 00403844: mov eax, 0x4
      [-]03470483c708
         // 00403849: add eax, ds:[edi+0x4]
         // 0040384c: add edi, 0x8
      [-]0f8514ffffff
         // 00403850: jnz 0x40376a
      [-]5929c17e0a
         // 00403856: pop ecx
         // 00403857: sub ecx, eax
         // 00403859: jle 0x403865
      [-]8d141801f0e8e7ecffff
         // 0040385b: lea edx, ds:[eax+ebx]
         // 0040385e: add eax, esi
         // 00403860: call 0x40254c
      [-]5d5f5e5bc3
         // 00403865: pop ebp
         // 00403866: pop edi
         // 00403867: pop esi
         // 00403868: pop ebx
         // 00403869: retn 
      [-]5356575589c389d689cf8b6c24148a0f80f90a7431
         // 0040386c: push ebx
         // 0040386d: push esi
         // 0040386e: push edi
         // 0040386f: push ebp
         // 00403870: mov ebx, eax
         // 00403872: mov esi, edx
         // 00403874: mov edi, ecx
         // 00403876: mov ebp, ss:[esp+0x14]
         // 0040387a: mov b1 cl, b1 ds:[edi]
         // 0040387c: cmp b1 cl, b1 0xa
         // 0040387f: jz 0x4038b2
      [-]80f90b7443
         // 00403881: cmp b1 cl, b1 0xb
         // 00403884: jz 0x4038c9
      [-]80f90c7452
         // 00403886: cmp b1 cl, b1 0xc
         // 00403889: jz 0x4038dd
      [-]80f90d7461
         // 0040388b: cmp b1 cl, b1 0xd
         // 0040388e: jz 0x4038f1
      [-]80f90e747d
         // 00403890: cmp b1 cl, b1 0xe
         // 00403893: jz 0x403912
      [-]80f90f0f8491000000
         // 00403895: cmp b1 cl, b1 0xf
         // 00403898: jz 0x40392f
      [-]80f9110f849c000000
         // 0040389e: cmp b1 cl, b1 0x11
         // 004038a1: jz 0x403943
      [-]b0025d5f5e5be97eecffff
         // 004038a7: mov b1 al, b1 0x2
         // 004038a9: pop ebp
         // 004038aa: pop edi
         // 004038ab: pop esi
         // 004038ac: pop ebx
         // 004038ad: jmp 0x402530
      [-]89d88b16e82df8ffff83c30483c604
         // 004038b2: mov eax, ebx
         // 004038b4: mov edx, ds:[esi]
         // 004038b6: call 0x4030e8
         // 004038bb: add ebx, 0x4
         // 004038be: add esi, 0x4
      [-]e98e000000
         // 004038c4: jmp 0x403957
      [-]89d88b16e80afdffff83c30483c604
         // 004038c9: mov eax, ebx
         // 004038cb: mov edx, ds:[esi]
         // 004038cd: call 0x4035dc
         // 004038d2: add ebx, 0x4
         // 004038d5: add esi, 0x4
      [-]89d889f2e852feffff83c31083c610
         // 004038dd: mov eax, ebx
         // 004038df: mov edx, esi
         // 004038e1: call 0x403738
         // 004038e6: add ebx, 0x10
         // 004038e9: add esi, 0x10
      [-]31c98a4f018d7c3902
         // 004038f1: xor ecx, ecx
         // 004038f3: mov b1 cl, b1 ds:[edi+0x1]
         // 004038f6: lea edi, ds:[ecx+edi+0x2]
      [-]89d889f28b4f08ff7704e863ffffff031f0337
         // 004038fa: mov eax, ebx
         // 004038fc: mov edx, esi
         // 004038fe: mov ecx, ds:[edi+0x8]
         // 00403901: push ds:[edi+0x4]
         // 00403904: call 0x40386c
         // 00403909: add ebx, ds:[edi]
         // 0040390b: add esi, ds:[edi]
      [-]89d889f289f9e833feffff31c08a4701035c380203743802
         // 00403912: mov eax, ebx
         // 00403914: mov edx, esi
         // 00403916: mov ecx, edi
         // 00403918: call 0x403750
         // 0040391d: xor eax, eax
         // 0040391f: mov b1 al, b1 ds:[edi+0x1]
         // 00403922: add ebx, ds:[eax+edi+0x2]
         // 00403926: add esi, ds:[eax+edi+0x2]
      [-]89d88b16e85003000083c30483c604
         // 0040392f: mov eax, ebx
         // 00403931: mov edx, ds:[esi]
         // 00403933: call 0x403c88
         // 00403938: add ebx, 0x4
         // 0040393b: add esi, 0x4
      [-]89d88b1689f9e81e02000083c30483c604
         // 00403943: mov eax, ebx
         // 00403945: mov edx, ds:[esi]
         // 00403947: mov ecx, edi
         // 00403949: call 0x403b6c
         // 0040394e: add ebx, 0x4
         // 00403951: add esi, 0x4
      [-]5d5f5e5bc20400
         // 00403957: pop ebp
         // 00403958: pop edi
         // 00403959: pop esi
         // 0040395a: pop ebx
         // 0040395b: retn b2 0x4
      [-]b011e9c9ebffff
         // 00403960: mov b1 al, b1 0x11
         // 00403962: jmp 0x402530
      [-]85c07403
         // 00403968: test eax, eax
         // 0040396a: jz 0x40396f
      [-]e8f3ffffff
         // 00403970: call 0x403968
      [-]558becff7508e8e9feffff5dc20400
         // 00403978: push ebp
         // 00403979: mov ebp, esp
         // 0040397b: push ss:[ebp+0x8]
         // 0040397e: call 0x40386c
         // 00403983: pop ebp
         // 00403984: retn b2 0x4
      [-]e9bffcffff
         // 00403988: jmp 0x40364c
      [-]e89b010000c3
         // 00403990: call 0x403b30
         // 00403995: retn 
      [-]558bec83c4e0535657894df88bf28945fc8b5dfc8b1b8b45088b3885ff7f1a
         // 00403998: push ebp
         // 00403999: mov ebp, esp
         // 0040399b: add esp, 0xffffffffffffffe0
         // 0040399e: push ebx
         // 0040399f: push esi
         // 004039a0: push edi
         // 004039a1: mov ss:[ebp+0xfffffffffffffff8], ecx
         // 004039a4: mov esi, edx
         // 004039a6: mov ss:[ebp+0xfffffffffffffffc], eax
         // 004039a9: mov ebx, ss:[ebp+0xfffffffffffffffc]
         // 004039ac: mov ebx, ds:[ebx]
         // 004039ae: mov eax, ss:[ebp+0x8]
         // 004039b1: mov edi, ds:[eax]
         // 004039b3: test edi, edi
         // 004039b5: jg 0x4039d1
      [-]85ff7d07
         // 004039b7: test edi, edi
         // 004039b9: jge 0x4039c2
      [-]b004e86eebffff
         // 004039bb: mov b1 al, b1 0x4
         // 004039bd: call 0x402530
      [-]8b45fc8bd6e8c4ffffffe94a010000
         // 004039c2: mov eax, ss:[ebp+0xfffffffffffffffc]
         // 004039c5: mov edx, esi
         // 004039c7: call 0x403990
         // 004039cc: jmp 0x403b1b
      [-]33c08945f085db740b
         // 004039d1: xor eax, eax
         // 004039d3: mov ss:[ebp+0xfffffffffffffff0], eax
         // 004039d6: test ebx, ebx
         // 004039d8: jz 0x4039e5
      [-]83eb048b038945f083eb04
         // 004039da: sub ebx, 0x4
         // 004039dd: mov eax, ds:[ebx]
         // 004039df: mov ss:[ebp+0xfffffffffffffff0], eax
         // 004039e2: sub ebx, 0x4
      [-]33c08a460101c68bc68b50028955e88b500685d27404
         // 004039e5: xor eax, eax
         // 004039e7: mov b1 al, b1 ds:[esi+0x1]
         // 004039ea: add esi, eax
         // 004039ec: mov eax, esi
         // 004039ee: mov edx, ds:[eax+0x2]
         // 004039f1: mov ss:[ebp+0xffffffffffffffe8], edx
         // 004039f4: mov edx, ds:[eax+0x6]
         // 004039f7: test edx, edx
         // 004039f9: jz 0x4039ff
      [-]8b32eb02
         // 004039fb: mov esi, ds:[edx]
         // 004039fd: jmp 0x403a01
      [-]8bc7f76de88945e48b45e499f7ff3b45e87407
         // 00403a01: mov eax, edi
         // 00403a03: imul ss:[ebp+0xffffffffffffffe8]
         // 00403a06: mov ss:[ebp+0xffffffffffffffe4], eax
         // 00403a09: mov eax, ss:[ebp+0xffffffffffffffe4]
         // 00403a0c: cdq 
         // 00403a0d: idiv edi
         // 00403a0f: cmp eax, ss:[ebp+0xffffffffffffffe8]
         // 00403a12: jz 0x403a1b
      [-]b004e815ebffff
         // 00403a14: mov b1 al, b1 0x4
         // 00403a16: call 0x402530
      [-]8345e40885db7405
         // 00403a1b: add ss:[ebp+0xffffffffffffffe4], 0x8
         // 00403a1f: test ebx, ebx
         // 00403a21: jz 0x403a28
      [-]833b017535
         // 00403a23: cmp ds:[ebx], 0x1
         // 00403a26: jnz 0x403a5d
      [-]895de03b7df07d1d
         // 00403a28: mov ss:[ebp+0xffffffffffffffe0], ebx
         // 00403a2b: cmp edi, ss:[ebp+0xfffffffffffffff0]
         // 00403a2e: jge 0x403a4d
      [-]85f67419
         // 00403a30: test esi, esi
         // 00403a32: jz 0x403a4d
      [-]8bc383c0088bd70faf55e803c28b4df02bcf8bd6e83bffffff
         // 00403a34: mov eax, ebx
         // 00403a36: add eax, 0x8
         // 00403a39: mov edx, edi
         // 00403a3b: imul edx, ss:[ebp+0xffffffffffffffe8]
         // 00403a3f: add eax, edx
         // 00403a41: mov ecx, ss:[ebp+0xfffffffffffffff0]
         // 00403a44: sub ecx, edi
         // 00403a46: mov edx, esi
         // 00403a48: call 0x403988
      [-]8d45e08b55e4e830eaffff8b5de0eb5e
         // 00403a4d: lea eax, ss:[ebp+0xffffffffffffffe0]
         // 00403a50: mov edx, ss:[ebp+0xffffffffffffffe4]
         // 00403a53: call 0x402488
         // 00403a58: mov ebx, ss:[ebp+0xffffffffffffffe0]
         // 00403a5b: jmp 0x403abb
      [-]ff0b8b45e4e8e1e9ffff8bd88b45f08945ec3b7dec7d03
         // 00403a5d: dec ds:[ebx]
         // 00403a5f: mov eax, ss:[ebp+0xffffffffffffffe4]
         // 00403a62: call 0x402448
         // 00403a67: mov ebx, eax
         // 00403a69: mov eax, ss:[ebp+0xfffffffffffffff0]
         // 00403a6c: mov ss:[ebp+0xffffffffffffffec], eax
         // 00403a6f: cmp edi, ss:[ebp+0xffffffffffffffec]
         // 00403a72: jge 0x403a77
      [-]85f6742a
         // 00403a77: test esi, esi
         // 00403a79: jz 0x403aa5
      [-]8b55ec0faf55e88bc383c00833c9e8d2ebffff8b45ec508b55fc8b128bc383c0088bcee8d5feffffeb16
         // 00403a7b: mov edx, ss:[ebp+0xffffffffffffffec]
         // 00403a7e: imul edx, ss:[ebp+0xffffffffffffffe8]
         // 00403a82: mov eax, ebx
         // 00403a84: add eax, 0x8
         // 00403a87: xor ecx, ecx
         // 00403a89: call 0x402660
         // 00403a8e: mov eax, ss:[ebp+0xffffffffffffffec]
         // 00403a91: push eax
         // 00403a92: mov edx, ss:[ebp+0xfffffffffffffffc]
         // 00403a95: mov edx, ds:[edx]
         // 00403a97: mov eax, ebx
         // 00403a99: add eax, 0x8
         // 00403a9c: mov ecx, esi
         // 00403a9e: call 0x403978
         // 00403aa3: jmp 0x403abb
      [-]8b4dec0faf4de88bd383c2088b45fc8b00e891eaffff
         // 00403aa5: mov ecx, ss:[ebp+0xffffffffffffffec]
         // 00403aa8: imul ecx, ss:[ebp+0xffffffffffffffe8]
         // 00403aac: mov edx, ebx
         // 00403aae: add edx, 0x8
         // 00403ab1: mov eax, ss:[ebp+0xfffffffffffffffc]
         // 00403ab4: mov eax, ds:[eax]
         // 00403ab6: call 0x40254c
      [-]c703????????83c304893b83c3048bd72b55f00faf55e88b45e80faf45f003c333c9e87eebffff837df8017e2e
         // 00403abb: mov ds:[ebx], 0x1
         // 00403ac1: add ebx, 0x4
         // 00403ac4: mov ds:[ebx], edi
         // 00403ac6: add ebx, 0x4
         // 00403ac9: mov edx, edi
         // 00403acb: sub edx, ss:[ebp+0xfffffffffffffff0]
         // 00403ace: imul edx, ss:[ebp+0xffffffffffffffe8]
         // 00403ad2: mov eax, ss:[ebp+0xffffffffffffffe8]
         // 00403ad5: imul eax, ss:[ebp+0xfffffffffffffff0]
         // 00403ad9: add eax, ebx
         // 00403adb: xor ecx, ecx
         // 00403add: call 0x402660
         // 00403ae2: cmp ss:[ebp+0xfffffffffffffff8], 0x1
         // 00403ae6: jle 0x403b16
      [-]83450804ff4df8
         // 00403ae8: add ss:[ebp+0x8], 0x4
         // 00403aec: dec ss:[ebp+0xfffffffffffffff8]
      [-]85ff7c22
         // 00403af0: test edi, edi
         // 00403af2: jl 0x403b16
      [-]c745f4????????
         // 00403af5: mov ss:[ebp+0xfffffffffffffff4], 0x0
      [-]8b4508508b45f48d04838b4df88bd6e888feffffff45f4
         // 00403afc: mov eax, ss:[ebp+0x8]
         // 00403aff: push eax
         // 00403b00: mov eax, ss:[ebp+0xfffffffffffffff4]
         // 00403b03: lea eax, ds:[ebx+eax*0x4]
         // 00403b06: mov ecx, ss:[ebp+0xfffffffffffffff8]
         // 00403b09: mov edx, esi
         // 00403b0b: call 0x403998
         // 00403b10: inc ss:[ebp+0xfffffffffffffff4]
      [-]8b45fc8918
         // 00403b16: mov eax, ss:[ebp+0xfffffffffffffffc]
         // 00403b19: mov ds:[eax], ebx
      [-]5f5e5b8be55dc20400
         // 00403b1b: pop edi
         // 00403b1c: pop esi
         // 00403b1d: pop ebx
         // 00403b1e: mov esp, ebp
         // 00403b20: pop ebp
         // 00403b21: retn b2 0x4
      [-]8b0885c97433
         // 00403b30: mov ecx, ds:[eax]
         // 00403b32: test ecx, ecx
         // 00403b34: jz 0x403b69
      [-]c700????????f0ff49f87527
         // 00403b36: mov ds:[eax], 0x0
         // 00403b3c: lock dec ds:[ecx+0xfffffffffffffff8]
         // 00403b40: jnz 0x403b69
      [-]5089c831c98a4a018b54110685d2740e
         // 00403b42: push eax
         // 00403b43: mov eax, ecx
         // 00403b45: xor ecx, ecx
         // 00403b47: mov b1 cl, b1 ds:[edx+0x1]
         // 00403b4a: mov edx, ds:[ecx+edx+0x6]
         // 00403b4e: test edx, edx
         // 00403b50: jz 0x403b60
      [-]8b48fc85c97407
         // 00403b52: mov ecx, ds:[eax+0xfffffffffffffffc]
         // 00403b55: test ecx, ecx
         // 00403b57: jz 0x403b60
      [-]8b12e8ecfaffff
         // 00403b59: mov edx, ds:[edx]
         // 00403b5b: call 0x40364c
      [-]83e808e800e9ffff58
         // 00403b60: sub eax, 0x8
         // 00403b63: call 0x402468
         // 00403b68: pop eax
      [-]538b1885d27404
         // 00403b6c: push ebx
         // 00403b6d: mov ebx, ds:[eax]
         // 00403b6f: test edx, edx
         // 00403b71: jz 0x403b77
      [-]f0ff42f8
         // 00403b73: lock inc ds:[edx+0xfffffffffffffff8]
      [-]85db7414
         // 00403b77: test ebx, ebx
         // 00403b79: jz 0x403b8f
      [-]f0ff4bf8750e
         // 00403b7b: lock dec ds:[ebx+0xfffffffffffffff8]
         // 00403b7f: jnz 0x403b8f
      [-]505289caff43f8e8a3ffffff5a58
         // 00403b81: push eax
         // 00403b82: push edx
         // 00403b83: mov edx, ecx
         // 00403b85: inc ds:[ebx+0xfffffffffffffff8]
         // 00403b88: call 0x403b30
         // 00403b8d: pop edx
         // 00403b8e: pop eax
      [-]89105bc3
         // 00403b8f: mov ds:[eax], edx
         // 00403b91: pop ebx
         // 00403b92: retn 
      [-]8b1085d2740e
         // 00403c70: mov edx, ds:[eax]
         // 00403c72: test edx, edx
         // 00403c74: jz 0x403c84
      [-]c700????????50528b02ff500858
         // 00403c76: mov ds:[eax], 0x0
         // 00403c7c: push eax
         // 00403c7d: push edx
         // 00403c7e: mov eax, ds:[edx]
         // 00403c80: call ds:[eax+0x8]
         // 00403c83: pop eax
      [-]85d27419
         // 00403c88: test edx, edx
         // 00403c8a: jz 0x403ca5
      [-]52508b0252ff5004588b088f0085c97501
         // 00403c8c: push edx
         // 00403c8d: push eax
         // 00403c8e: mov eax, ds:[edx]
         // 00403c90: push edx
         // 00403c91: call ds:[eax+0x4]
         // 00403c94: pop eax
         // 00403c95: mov ecx, ds:[eax]
         // 00403c97: pop ds:[eax]
         // 00403c99: test ecx, ecx
         // 00403c9b: jnz 0x403c9e
      [-]8b0151ff5008c3
         // 00403c9e: mov eax, ds:[ecx]
         // 00403ca0: push ecx
         // 00403ca1: call ds:[eax+0x8]
         // 00403ca4: retn 
      [-]8b0885c989107406
         // 00403ca5: mov ecx, ds:[eax]
         // 00403ca7: test ecx, ecx
         // 00403ca9: mov ds:[eax], edx
         // 00403cab: jz 0x403cb3
      [-]8b0151ff5008
         // 00403cad: mov eax, ds:[ecx]
         // 00403caf: push ecx
         // 00403cb0: call ds:[eax+0x8]
      [-]506a40e8e0ffffffc3
         // 00403e70: push eax
         // 00403e71: push 0x40
         // 00403e73: call LocalAlloc_0
         // 00403e78: retn 
      [-]8a0d4ca64000a1
         // 140003ec8: mov b1 cl, b1 cs:[0x14040e51a]
         // 140003ece: mov b4 eax, b4 ds:[0x2675c98400409090]
      [-]33c9e8c1e4ffffc3
         // 00404198: xor ecx, ecx
         // 0040419a: call 0x402660
         // 0040419f: retn 
      [-]85c07505
         // 00404490: test eax, eax
         // 00404492: jnz 0x404499
      [-]b8????????
         // 00404494: mov eax, 0x4090e4
      [-]85d27505
         // 0040449c: test edx, edx
         // 0040449e: jnz 0x4044a5
      [-]ba????????
         // 004044a0: mov edx, 0x4090e4
      [-]588704245089e0e8e0ebffff58c3
         // 004044a8: pop eax
         // 004044a9: xchg eax, ss:[esp]
         // 004044ac: push eax
         // 004044ad: mov eax, esp
         // 004044af: call 0x403094
         // 004044b4: pop eax
         // 004044b5: retn 
      [-]6a00e849fcffff5a505289d8ff533489d8e8861c000050ff742408e868fcffff5a50528b442408c3
         // 004044b8: push 0x0
         // 004044ba: call CreateCompatibleDC
         // 004044bf: pop edx
         // 004044c0: push eax
         // 004044c1: push edx
         // 004044c2: mov eax, ebx
         // 004044c4: call ds:[ebx+0x34]
         // 004044c7: mov eax, ebx
         // 004044c9: call 0x406154
         // 004044ce: push eax
         // 004044cf: push ss:[esp+0x8]
         // 004044d3: call SelectObject
         // 004044d8: pop edx
         // 004044d9: push eax
         // 004044da: push edx
         // 004044db: mov eax, ss:[esp+0x8]
         // 004044df: retn 
      [-]59585a51525052e854fcffffe82ffcffffc3
         // 004044e0: pop ecx
         // 004044e1: pop eax
         // 004044e2: pop edx
         // 004044e3: push ecx
         // 004044e4: push edx
         // 004044e5: push eax
         // 004044e6: push edx
         // 004044e7: call SelectObject
         // 004044ec: call DeleteDC
         // 004044f1: retn 
      [-]e8a3e2ffff7406
         // 004044f8: call 0x4027a0
         // 004044fd: jz 0x404505
      [-]508b10ff1258
         // 004044ff: push eax
         // 00404500: mov edx, ds:[eax]
         // 00404502: call ds:[edx]
         // 00404504: pop eax
      [-]8b5004d1fa7406
         // 00404508: mov edx, ds:[eax+0x4]
         // 0040450b: sar edx, b1 0x1
         // 0040450d: jz 0x404515
      [-]ff4804f9
         // 00404511: dec ds:[eax+0x4]
         // 00404514: stc 
      [-]8b10ff5204
         // 00404517: mov edx, ds:[eax]
         // 00404519: call ds:[edx+0x4]
      [-]85c00f85e0ffffff
         // 00404520: test eax, eax
         // 00404522: jnz 0x404508
      [-]50e80a0000005831d2e82edfffffc3
         // 0040452c: push eax
         // 0040452d: call 0x40453c
         // 00404532: pop eax
         // 00404533: xor edx, edx
         // 00404535: call 0x402468
         // 0040453a: retn 
      [-]31c9874808
         // 0040453c: xor ecx, ecx
         // 0040453e: xchg ecx, ds:[eax+0x8]
      [-]50928b420cffd158
         // 00404543: push eax
         // 00404544: xchg eax, edx
         // 00404545: mov eax, ds:[edx+0xc]
         // 00404548: call ecx
         // 0040454a: pop eax
      [-]31c9874810
         // 0040454b: xor ecx, ecx
         // 0040454d: xchg ecx, ds:[eax+0x10]
      [-]56518b71188b491c
         // 00404552: push esi
         // 00404553: push ecx
         // 00404554: mov esi, ds:[ecx+0x18]
         // 00404557: mov ecx, ds:[ecx+0x1c]
      [-]ad92ad51ffd259
         // 0040455a: lodsdd 
         // 0040455b: xchg eax, edx
         // 0040455c: lodsdd 
         // 0040455d: push ecx
         // 0040455e: call edx
         // 00404560: pop ecx
      [-]58e8b6ffffff5e
         // 00404564: pop eax
         // 00404565: call 0x404520
         // 0040456a: pop esi
      [-]33c0e87fffffffc3
         // 00404572: xor eax, eax
         // 00404574: call 0x4044f8
         // 00404579: retn 
      [-]85c0741d
         // 0040458c: test eax, eax
         // 0040458e: jz 0x4045ad
      [-]8b501850
         // 00404595: mov edx, ds:[eax+0x18]
         // 00404598: push eax
      [-]8b448afc85c07409
         // 00404599: mov eax, ds:[edx+ecx*0x4]
         // 0040459d: test eax, eax
         // 0040459f: jz 0x4045aa
      [-]5251e8c0deffff595a
         // 004045a1: push edx
         // 004045a2: push ecx
         // 004045a3: call 0x402468
         // 004045a8: pop ecx
         // 004045a9: pop edx
      [-]e86effffffc3
         // 004045ad: call 0x404520
         // 004045b2: retn 
      [-]3b501c7d03
         // 004045b4: cmp edx, ds:[eax+0x1c]
         // 004045b7: jge 0x4045bc
      [-]3b5020740e
         // 004045bc: cmp edx, ds:[eax+0x20]
         // 004045bf: jz 0x4045cf
      [-]895020c1e2028d4018e8b9deffff
         // 004045c1: mov ds:[eax+0x20], edx
         // 004045c4: shl edx, b1 0x2
         // 004045c7: lea eax, ds:[eax+0x18]
         // 004045ca: call 0x402488
      [-]ff701831d289501889501c89502058e884deffffc3
         // 004045d0: push ds:[eax+0x18]
         // 004045d3: xor edx, edx
         // 004045d5: mov ds:[eax+0x18], edx
         // 004045d8: mov ds:[eax+0x1c], edx
         // 004045db: mov ds:[eax+0x20], edx
         // 004045de: pop eax
         // 004045df: call 0x402468
         // 004045e4: retn 
      [-]528d481c8b11ff01523b5020507c14
         // 004045e8: push edx
         // 004045e9: lea ecx, ds:[eax+0x1c]
         // 004045ec: mov edx, ds:[ecx]
         // 004045ee: inc ds:[ecx]
         // 004045f0: push edx
         // 004045f1: cmp edx, ds:[eax+0x20]
         // 004045f4: push eax
         // 004045f5: jl 0x40460b
      [-]8b482485c97506
         // 004045f7: mov ecx, ds:[eax+0x24]
         // 004045fa: test ecx, ecx
         // 004045fc: jnz 0x404604
      [-]01cae8a9ffffff
         // 00404604: add edx, ecx
         // 00404606: call 0x4045b4
      [-]59585a8b4918891481c3
         // 0040460b: pop ecx
         // 0040460c: pop eax
         // 0040460d: pop edx
         // 0040460e: mov ecx, ds:[ecx+0x18]
         // 00404611: mov ds:[ecx+eax*0x4], edx
         // 00404614: retn 
      [-]b9????????e802000000c3
         // 00404618: mov ecx, 0x1
         // 0040461d: call 0x404624
         // 00404622: retn 
      [-]85c97e33
         // 00404624: test ecx, ecx
         // 00404626: jle 0x40465b
      [-]3b501c7d2e
         // 00404628: cmp edx, ds:[eax+0x1c]
         // 0040462b: jge 0x40465b
      [-]53938d04113b431c7605
         // 0040462d: push ebx
         // 0040462e: xchg eax, ebx
         // 0040462f: lea eax, ds:[ecx+edx]
         // 00404632: cmp eax, ds:[ebx+0x1c]
         // 00404635: jbe 0x40463c
      [-]8b4b1c29d1
         // 00404637: mov ecx, ds:[ebx+0x1c]
         // 0040463a: sub ecx, edx
      [-]8b4318ff731c294b1c89d38d14908d048a01cb5929d9c1e102e8f2deffff5b
         // 0040463c: mov eax, ds:[ebx+0x18]
         // 0040463f: push ds:[ebx+0x1c]
         // 00404642: sub ds:[ebx+0x1c], ecx
         // 00404645: mov ebx, edx
         // 00404647: lea edx, ds:[eax+edx*0x4]
         // 0040464a: lea eax, ds:[edx+ecx*0x4]
         // 0040464d: add ebx, ecx
         // 0040464f: pop ecx
         // 00404650: sub ecx, ebx
         // 00404652: shl ecx, b1 0x2
         // 00404655: call 0x40254c
         // 0040465a: pop ebx
      [-]33c985d27c0b
         // 0040465c: xor ecx, ecx
         // 0040465e: test edx, edx
         // 00404660: jl 0x40466d
      [-]3b501c7d06
         // 00404662: cmp edx, ds:[eax+0x1c]
         // 00404665: jge 0x40466d
      [-]8b40188b0c90
         // 00404667: mov eax, ds:[eax+0x18]
         // 0040466a: mov ecx, ds:[eax+edx*0x4]
      [-]5150ff701c52e86dffffff5a5829d0c1e00289c1588b40188d04907c0a
         // 00404670: push ecx
         // 00404671: push eax
         // 00404672: push ds:[eax+0x1c]
         // 00404675: push edx
         // 00404676: call 0x4045e8
         // 0040467b: pop edx
         // 0040467c: pop eax
         // 0040467d: sub eax, edx
         // 0040467f: shl eax, b1 0x2
         // 00404682: mov ecx, eax
         // 00404684: pop eax
         // 00404685: mov eax, ds:[eax+0x18]
         // 00404688: lea eax, ds:[eax+edx*0x4]
         // 0040468b: jl 0x404697
      [-]508d5004e8b6deffff58
         // 0040468d: push eax
         // 0040468e: lea edx, ds:[eax+0x4]
         // 00404691: call 0x40254c
         // 00404696: pop eax
      [-]598908c3
         // 00404697: pop ecx
         // 00404698: mov ds:[eax], ecx
         // 0040469a: retn 
      [-]85c07d0b
         // 0040469c: test eax, eax
         // 0040469e: jge 0x4046ab
      [-]25????????50e8ddfaffff
         // 004046a0: and eax, 0xff
         // 004046a5: push eax
         // 004046a6: call GetSysColor
      [-]575089c783c9ff32c0f2aef7d15f92f2ae975f7403
         // 004046c0: push edi
         // 004046c1: push eax
         // 004046c2: mov edi, eax
         // 004046c4: or ecx, 0xffffffffffffffff
         // 004046c7: xor b1 al, b1 al
         // 004046c9: repne scasbb 
         // 004046cb: not ecx
         // 004046cd: pop edi
         // 004046ce: xchg eax, edx
         // 004046cf: repne scasbb 
         // 004046d1: xchg eax, edi
         // 004046d2: pop edi
         // 004046d3: jz 0x4046d8
      [-]5789c7b9????????32c0f2aef7d1fd
         // 004046dc: push edi
         // 004046dd: mov edi, eax
         // 004046df: mov ecx, 0xffffffffffffffff
         // 004046e4: xor b1 al, b1 al
         // 004046e6: repne scasbb 
         // 004046e8: not ecx
         // 004046ea: std 
      [-]88d0f2aeb8????????7503
         // 004046ec: mov b1 al, b1 dl
         // 004046ee: repne scasbb 
         // 004046f0: mov eax, 0x0
         // 004046f5: jnz 0x4046fa
      [-]569250e8e0e9ffff58e84eedffff50e8f8eaffff5e91
         // 00404700: push esi
         // 00404701: xchg eax, edx
         // 00404702: push eax
         // 00404703: call 0x4030e8
         // 00404708: pop eax
         // 00404709: call 0x40345c
         // 0040470e: push eax
         // 0040470f: call 0x40320c
         // 00404714: pop esi
         // 00404715: xchg eax, ecx
      [-]ac2c413c1a7304
         // 00404718: lodsbb 
         // 00404719: sub b1 al, b1 0x41
         // 0040471b: cmp b1 al, b1 0x1a
         // 0040471d: jnb 0x404723
      [-]8046ff20
         // 0040471f: add b1 ds:[esi+0xffffffffffffffff], b1 0x20
      [-]515052e8dceaffff5a85d27f03
         // 00404728: push ecx
         // 00404729: push eax
         // 0040472a: push edx
         // 0040472b: call 0x40320c
         // 00404730: pop edx
         // 00404731: test edx, edx
         // 00404733: jg 0x404738
      [-]29d089c1587d07
         // 00404738: sub eax, edx
         // 0040473a: mov ecx, eax
         // 0040473c: pop eax
         // 0040473d: jge 0x404746
      [-]580f8c4ee9ffff
         // 0040473f: pop eax
         // 00404740: jl 0x403094
      [-]e818edffffc3
         // 00404747: call 0x403464
         // 0040474c: retn 
      [-]e83bfdffff50e865ffffff5a85c07404
         // 00404750: call 0x404490
         // 00404755: push eax
         // 00404756: call 0x4046c0
         // 0040475b: pop edx
         // 0040475c: test eax, eax
         // 0040475e: jz 0x404764
      [-]5650e82dfdffff89d631c9
         // 00404768: push esi
         // 00404769: push eax
         // 0040476a: call 0x40449c
         // 0040476f: mov esi, edx
         // 00404771: xor ecx, ecx
      [-]92585051e8ceffffff5985c07eed
         // 00404779: xchg eax, edx
         // 0040477a: pop eax
         // 0040477b: push eax
         // 0040477c: push ecx
         // 0040477d: call 0x404750
         // 00404782: pop ecx
         // 00404783: test eax, eax
         // 00404785: jle 0x404774
      [-]85c97e04
         // 00404787: test ecx, ecx
         // 00404789: jle 0x40478f
      [-]39c87de5
         // 0040478b: cmp eax, ecx
         // 0040478d: jge 0x404774
      [-]535789c3518b03e8c4ffffff
         // 00404798: push ebx
         // 00404799: push edi
         // 0040479a: mov ebx, eax
         // 0040479c: push ecx
         // 0040479d: mov eax, ds:[ebx]
         // 0040479f: call 0x404768
      [-]89c789c1
         // 004047b1: mov edi, eax
         // 004047b3: mov ecx, eax
      [-]8b03e8a4ecffff8b0389fa
         // 004047b9: mov eax, ds:[ebx]
         // 004047bb: call 0x403464
         // 004047c0: mov eax, ds:[ebx]
         // 004047c2: mov edx, edi
      [-]89d9e85cffffff5f5bc3
         // 004047c5: mov ecx, ebx
         // 004047c7: call 0x404728
         // 004047cc: pop edi
         // 004047cd: pop ebx
         // 004047ce: retn 
      [-]565789c689d789ca31c083e203d1e9d1e9f3a77507
         // 004047d0: push esi
         // 004047d1: push edi
         // 004047d2: mov esi, eax
         // 004047d4: mov edi, edx
         // 004047d6: mov edx, ecx
         // 004047d8: xor eax, eax
         // 004047da: and edx, 0x3
         // 004047dd: shr ecx, b1 0x1
         // 004047df: shr ecx, b1 0x1
         // 004047e1: repe cmpsdd 
         // 004047e3: jnz 0x4047ec
      [-]89d1f3a67501
         // 004047e5: mov ecx, edx
         // 004047e7: repe cmpsbb 
         // 004047e9: jnz 0x4047ec
      [-]85c07410
         // 004047f0: test eax, eax
         // 004047f2: jz 0x404804
      [-]50e84edcffff5a50b100e85ddeffff58
         // 004047f4: push eax
         // 004047f5: call 0x402448
         // 004047fa: pop edx
         // 004047fb: push eax
         // 004047fc: mov b1 cl, b1 0x0
         // 004047fe: call 0x402660
         // 00404803: pop eax
      [-]5356578bfa8bf08bc6e8f6e9ffff8bd88bc6e8edebffff8bd08bc78bcbe85ae9ffff85db7e09
         // 00404808: push ebx
         // 00404809: push esi
         // 0040480a: push edi
         // 0040480b: mov edi, edx
         // 0040480d: mov esi, eax
         // 0040480f: mov eax, esi
         // 00404811: call 0x40320c
         // 00404816: mov ebx, eax
         // 00404818: mov eax, esi
         // 0040481a: call 0x40340c
         // 0040481f: mov edx, eax
         // 00404821: mov eax, edi
         // 00404823: mov ecx, ebx
         // 00404825: call 0x403184
         // 0040482a: test ebx, ebx
         // 0040482c: jle 0x404837
      [-]538b0750e821f9ffff
         // 0040482e: push ebx
         // 0040482f: mov eax, ds:[edi]
         // 00404831: push eax
         // 00404832: call CharLowerBuffA
      [-]5f5e5bc3
         // 00404837: pop edi
         // 00404838: pop esi
         // 00404839: pop ebx
         // 0040483a: retn 
      [-]85c07453
         // 0040483c: test eax, eax
         // 0040483e: jz 0x404893
      [-]9131c0b02a
         // 00404840: xchg eax, ecx
         // 00404841: xor eax, eax
         // 00404843: mov b1 al, b1 0x2a
      [-]8a220a217444
         // 00404847: mov b1 ah, b1 ds:[edx]
         // 00404849: or b1 ah, b1 ds:[ecx]
         // 0040484b: jz 0x404891
      [-]b400663902743d
         // 0040484d: mov b1 ah, b1 0x0
         // 0040484f: cmp b2 ds:[edx], b2 ax
         // 00404852: jz 0x404891
      [-]3821750d
         // 00404854: cmp b1 ds:[ecx], b1 ah
         // 00404856: jnz 0x404865
      [-]38220f94c0eb2c
         // 0040485e: cmp b1 ds:[edx], b1 ah
         // 00404860: setz b1 al
         // 00404863: jmp 0x404891
      [-]38227426
         // 00404865: cmp b1 ds:[edx], b1 ah
         // 00404867: jz 0x40488f
      [-]803a3f7504
         // 00404869: cmp b1 ds:[edx], b1 0x3f
         // 0040486c: jnz 0x404872
      [-]38027513
         // 00404872: cmp b1 ds:[edx], b1 al
         // 00404874: jnz 0x404889
      [-]38217414
         // 00404877: cmp b1 ds:[ecx], b1 ah
         // 00404879: jz 0x40488f
      [-]e8c5ffffff84c0750d
         // 0040487b: call 0x404845
         // 00404880: test b1 al, b1 al
         // 00404882: jnz 0x404891
      [-]8a22322174df
         // 00404889: mov b1 ah, b1 ds:[edx]
         // 0040488b: xor b1 ah, b1 ds:[ecx]
         // 0040488d: jz 0x40486e
      [-]56966a0092e8f2fbffff89e28038007405
         // 00404894: push esi
         // 00404895: xchg eax, esi
         // 00404896: push 0x0
         // 00404898: xchg eax, edx
         // 00404899: call 0x404490
         // 0040489e: mov edx, esp
         // 004048a0: cmp b1 ds:[eax], b1 0x0
         // 004048a3: jz 0x4048aa
      [-]e85effffff
         // 004048a5: call 0x404808
      [-]966a00e8defbffff
         // 004048aa: xchg eax, esi
         // 004048ab: push 0x0
         // 004048ad: call 0x404490
         // 004048b2: mov edx, esp
         // 004048b4: cmp b1 ds:[eax], b1 0x0
         // 004048b7: jz 0x4048be

  }
  condition:
    all of them
}
