rule neshta_10_4 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         833d????????007e40
         // 00401c1c: cmp ds:[0x40a604], 0x0
         // 00401c23: jle 0x401c65
      [-]833d????????0c7d0c
         // 00401c25: cmp ds:[0x40a604], 0xc
         // 00401c2c: jge 0x401c3a
      [-]c705????????????????eb2b
         // 00401c2e: mov ds:[0x40a5b0], 0x7
         // 00401c38: jmp 0x401c65
      [-]a1????????83c8028b15????????8902a1????????83c004e899fdffff33c0a3????????33c0a3????????
         // 00401c3a: mov eax, ds:[0x40a604]
         // 00401c3f: or eax, 0x2
         // 00401c42: mov edx, ds:[0x40a608]
         // 00401c48: mov ds:[edx], eax
         // 00401c4a: mov eax, ds:[0x40a608]
         // 00401c4f: add eax, 0x4
         // 00401c52: call 0x4019f0
         // 00401c57: xor eax, eax
         // 00401c59: mov ds:[0x40a608], eax
         // 00401c5e: xor eax, eax
         // 00401c60: mov ds:[0x40a604], eax
      [-]53565783c4f08bf08d3c24a5a58bfce8a0ffffff8d4c24088bd7b8????????e810f5ffff8b5c2408
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
      [-]8b07a3????????
         // 00401cd9: mov eax, ds:[edi]
         // 00401cdb: mov ds:[0x40a608], eax
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
      [-]8b15????????8b5482f485d27508
         // 00401d67: mov edx, ds:[0x40a60c]
         // 00401d6d: mov edx, ds:[edx+eax*0x4]
         // 00401d71: test edx, edx
         // 00401d73: jnz 0x401d7d
      [-]403d????????75ea
         // 00401d75: inc eax
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
      [-]8b1d????????3b73080f8e84000000
         // 00401d90: mov ebx, ds:[0x40a5f8]
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
      [-]a1????????0135????????8bd683ca02891083c004ff05????????83ee040135????????eb4c
         // 00401dfd: mov eax, ds:[0x40a608]
         // 00401e02: add ds:[0x40a608], esi
         // 00401e08: mov edx, esi
         // 00401e0a: or edx, 0x2
         // 00401e0d: mov ds:[eax], edx
         // 00401e0f: add eax, 0x4
         // 00401e12: inc ds:[0x40a59c]
         // 00401e18: sub esi, 0x4
         // 00401e1b: add ds:[0x40a5a0], esi
         // 00401e21: jmp 0x401e6f
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
      [-]8bc38bd683ca02891083c004ff05????????83ee040135????????
         // 00401e54: mov eax, ebx
         // 00401e56: mov edx, esi
         // 00401e58: or edx, 0x2
         // 00401e5b: mov ds:[eax], edx
         // 00401e5d: add eax, 0x4
         // 00401e60: inc ds:[0x40a59c]
         // 00401e66: sub esi, 0x4
         // 00401e69: add ds:[0x40a5a0], esi
      [-]5d5f5e5bc3
         // 00401e6f: pop ebp
         // 00401e70: pop edi
         // 00401e71: pop esi
         // 00401e72: pop ebx
         // 00401e73: retn 
      [-]558bec83c4f85356578bd8803daca54000007509
         // 00401e74: push ebp
         // 00401e75: mov ebp, esp
         // 00401e77: add esp, 0xfffffffffffffff8
         // 00401e7a: push ebx
         // 00401e7b: push esi
         // 00401e7c: push edi
         // 00401e7d: mov ebx, eax
         // 00401e7f: cmp b1 ds:[0x40a5ac], b1 0x0
         // 00401e86: jnz 0x401e91
      [-]e8fbf8ffff84c07408
         // 00401e88: call 0x401788
         // 00401e8d: test b1 al, b1 al
         // 00401e8f: jz 0x401e99
      [-]81fb????????7e0a
         // 00401e91: cmp ebx, 0x7ffffff8
         // 00401e97: jle 0x401ea3
      [-]33c08945fce954010000
         // 00401e99: xor eax, eax
         // 00401e9b: mov ss:[ebp+0xfffffffffffffffc], eax
         // 00401e9e: jmp 0x401ff7
      [-]33c95568????????64ff31648921803d35a0400000740a
         // 00401ea3: xor ecx, ecx
         // 00401ea5: push ebp
         // 00401ea6: push 0x401ff0
         // 00401eab: push fs:[ecx]
         // 00401eae: mov fs:[ecx], esp
         // 00401eb1: cmp b1 ds:[0x40a035], b1 0x0
         // 00401eb8: jz 0x401ec4
      [-]e820f2ffff
         // 00401ebf: call EnterCriticalSection
      [-]83c30783e3fc83fb0c7d05
         // 00401ec4: add ebx, 0x7
         // 00401ec7: and ebx, 0xfffffffffffffffc
         // 00401eca: cmp ebx, 0xc
         // 00401ecd: jge 0x401ed4
      [-]bb????????
         // 00401ecf: mov ebx, 0xc
      [-]81fb????????0f8f93000000
         // 00401ed4: cmp ebx, 0x1000
         // 00401eda: jg 0x401f73
      [-]8bc385c07903
         // 00401ee0: mov eax, ebx
         // 00401ee2: test eax, eax
         // 00401ee4: jns 0x401ee9
      [-]c1f8028b15????????8b5482f485d27479
         // 00401ee9: sar eax, b1 0x2
         // 00401eec: mov edx, ds:[0x40a60c]
         // 00401ef2: mov edx, ds:[edx+eax*0x4]
         // 00401ef6: test edx, edx
         // 00401ef8: jz 0x401f73
      [-]8bf28bc603c38320fe8b42043bd0751a
         // 00401efa: mov esi, edx
         // 00401efc: mov eax, esi
         // 00401efe: add eax, ebx
         // 00401f00: and ds:[eax], 0xfffffffffffffffe
         // 00401f03: mov eax, ds:[edx+0x4]
         // 00401f06: cmp edx, eax
         // 00401f08: jnz 0x401f24
      [-]8bc385c07903
         // 00401f0a: mov eax, ebx
         // 00401f0c: test eax, eax
         // 00401f0e: jns 0x401f13
      [-]c1f8028b0d????????33ff897c81f4eb26
         // 00401f13: sar eax, b1 0x2
         // 00401f16: mov ecx, ds:[0x40a60c]
         // 00401f1c: xor edi, edi
         // 00401f1e: mov ds:[ecx+eax*0x4], edi
         // 00401f22: jmp 0x401f4a
      [-]8bcb85c97903
         // 00401f24: mov ecx, ebx
         // 00401f26: test ecx, ecx
         // 00401f28: jns 0x401f2d
      [-]c1f9028b3d????????89448ff48b0a894df88b4df88941048b4df88908
         // 00401f2d: sar ecx, b1 0x2
         // 00401f30: mov edi, ds:[0x40a60c]
         // 00401f36: mov ds:[edi+ecx*0x4], eax
         // 00401f3a: mov ecx, ds:[edx]
         // 00401f3c: mov ss:[ebp+0xfffffffffffffff8], ecx
         // 00401f3f: mov ecx, ss:[ebp+0xfffffffffffffff8]
         // 00401f42: mov ds:[ecx+0x4], eax
         // 00401f45: mov ecx, ss:[ebp+0xfffffffffffffff8]
         // 00401f48: mov ds:[eax], ecx
      [-]8bc68b520883ca02891083c0048945fcff05????????83eb04011d????????e87e0c0000e984000000
         // 00401f4a: mov eax, esi
         // 00401f4c: mov edx, ds:[edx+0x8]
         // 00401f4f: or edx, 0x2
         // 00401f52: mov ds:[eax], edx
         // 00401f54: add eax, 0x4
         // 00401f57: mov ss:[ebp+0xfffffffffffffffc], eax
         // 00401f5a: inc ds:[0x40a59c]
         // 00401f60: sub ebx, 0x4
         // 00401f63: add ds:[0x40a5a0], ebx
         // 00401f69: call 0x402bec
         // 00401f6e: jmp 0x401ff7
      [-]3b1d????????7f4a
         // 00401f73: cmp ebx, ds:[0x40a604]
         // 00401f79: jg 0x401fc5
      [-]291d????????833d????????0c7d0d
         // 00401f7b: sub ds:[0x40a604], ebx
         // 00401f81: cmp ds:[0x40a604], 0xc
         // 00401f88: jge 0x401f97
      [-]031d????????33c0a3????????
         // 00401f8a: add ebx, ds:[0x40a604]
         // 00401f90: xor eax, eax
         // 00401f92: mov ds:[0x40a604], eax
      [-]a1????????011d????????8bd383ca02891083c0048945fcff05????????83eb04011d????????e8290c0000eb32
         // 00401f97: mov eax, ds:[0x40a608]
         // 00401f9c: add ds:[0x40a608], ebx
         // 00401fa2: mov edx, ebx
         // 00401fa4: or edx, 0x2
         // 00401fa7: mov ds:[eax], edx
         // 00401fa9: add eax, 0x4
         // 00401fac: mov ss:[ebp+0xfffffffffffffffc], eax
         // 00401faf: inc ds:[0x40a59c]
         // 00401fb5: sub ebx, 0x4
         // 00401fb8: add ds:[0x40a5a0], ebx
         // 00401fbe: call 0x402bec
         // 00401fc3: jmp 0x401ff7
      [-]8bc3e8b4fdffff8945fc33c05a595964891068????????803d35a0400000740a
         // 00401fc5: mov eax, ebx
         // 00401fc7: call 0x401d80
         // 00401fcc: mov ss:[ebp+0xfffffffffffffffc], eax
         // 00401fcf: xor eax, eax
         // 00401fd1: pop edx
         // 00401fd2: pop ecx
         // 00401fd3: pop ecx
         // 00401fd4: mov fs:[eax], edx
         // 00401fd7: push 0x401ff7
         // 00401fdc: cmp b1 ds:[0x40a035], b1 0x0
         // 00401fe3: jz 0x401fef
      [-]e8fdf0ffff
         // 00401fea: call LeaveCriticalSection
      [-]8b45fc5f5e5b59595dc3
         // 00401ff7: mov eax, ss:[ebp+0xfffffffffffffffc]
         // 00401ffa: pop edi
         // 00401ffb: pop esi
         // 00401ffc: pop ebx
         // 00401ffd: pop ecx
         // 00401ffe: pop ecx
         // 00401fff: pop ebp
         // 00402000: retn 
      [-]558bec515356578bd833c0a3????????803daca5400000751f
         // 00402004: push ebp
         // 00402005: mov ebp, esp
         // 00402007: push ecx
         // 00402008: push ebx
         // 00402009: push esi
         // 0040200a: push edi
         // 0040200b: mov ebx, eax
         // 0040200d: xor eax, eax
         // 0040200f: mov ds:[0x40a5b0], eax
         // 00402014: cmp b1 ds:[0x40a5ac], b1 0x0
         // 0040201b: jnz 0x40203c
      [-]e866f7ffff84c07516
         // 0040201d: call 0x401788
         // 00402022: test b1 al, b1 al
         // 00402024: jnz 0x40203c
      [-]c705????????????????c745fc????????e961010000
         // 00402026: mov ds:[0x40a5b0], 0x8
         // 00402030: mov ss:[ebp+0xfffffffffffffffc], 0x8
         // 00402037: jmp 0x40219d
      [-]33c95568????????64ff31648921803d35a0400000740a
         // 0040203c: xor ecx, ecx
         // 0040203e: push ebp
         // 0040203f: push 0x402196
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
      [-]c705????????????????e9f5000000
         // 00402069: mov ds:[0x40a5b0], 0x9
         // 00402073: jmp 0x40216d
      [-]ff0d????????8bc325????????83e8042905????????f6c3017445
         // 00402078: dec ds:[0x40a59c]
         // 0040207e: mov eax, ebx
         // 00402080: and eax, 0x7ffffffc
         // 00402085: sub eax, 0x4
         // 00402088: sub ds:[0x40a5a0], eax
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
      [-]c705????????????????e9b6000000
         // 004020a8: mov ds:[0x40a5b0], 0xa
         // 004020b2: jmp 0x40216d
      [-]8bc62bc23b5008740f
         // 004020b7: mov eax, esi
         // 004020b9: sub eax, edx
         // 004020bb: cmp edx, ds:[eax+0x8]
         // 004020be: jz 0x4020cf
      [-]c705????????????????e99e000000
         // 004020c0: mov ds:[0x40a5b0], 0xa
         // 004020ca: jmp 0x40216d
      [-]03da8bf0e854f8ffff
         // 004020cf: add ebx, edx
         // 004020d1: mov esi, eax
         // 004020d3: call 0x40192c
      [-]81e3????????8bc603c38bf83b3d????????752c
         // 004020d8: and ebx, 0x7ffffffc
         // 004020de: mov eax, esi
         // 004020e0: add eax, ebx
         // 004020e2: mov edi, eax
         // 004020e4: cmp edi, ds:[0x40a608]
         // 004020ea: jnz 0x402118
      [-]291d????????011d????????813d????????????????7e05
         // 004020ec: sub ds:[0x40a608], ebx
         // 004020f2: add ds:[0x40a604], ebx
         // 004020f8: cmp ds:[0x40a604], 0x3c00
         // 00402102: jle 0x402109
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
      [-]c705????????????????eb37
         // 0040212a: mov ds:[0x40a5b0], 0xb
         // 00402134: jmp 0x40216d
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
      [-]c705????????????????eb13
         // 0040214e: mov ds:[0x40a5b0], 0xb
         // 00402158: jmp 0x40216d
      [-]8b500803dae8c8f7ffff
         // 0040215a: mov edx, ds:[eax+0x8]
         // 0040215d: add ebx, edx
         // 0040215f: call 0x40192c
      [-]8bd38bc6e827faffff
         // 00402164: mov edx, ebx
         // 00402166: mov eax, esi
         // 00402168: call 0x401b94
      [-]a1????????8945fc33c05a595964891068????????803d35a0400000740a
         // 0040216d: mov eax, ds:[0x40a5b0]
         // 00402172: mov ss:[ebp+0xfffffffffffffffc], eax
         // 00402175: xor eax, eax
         // 00402177: pop edx
         // 00402178: pop ecx
         // 00402179: pop ecx
         // 0040217a: mov fs:[eax], edx
         // 0040217d: push 0x40219d
         // 00402182: cmp b1 ds:[0x40a035], b1 0x0
         // 00402189: jz 0x402195
      [-]8b45fc5f5e5b595dc3
         // 0040219d: mov eax, ss:[ebp+0xfffffffffffffffc]
         // 004021a0: pop edi
         // 004021a1: pop esi
         // 004021a2: pop ebx
         // 004021a3: pop ecx
         // 004021a4: pop ebp
         // 004021a5: retn 
      [-]5356575583c4f88bf283c60783e6fc83fe0c7d05
         // 004021a8: push ebx
         // 004021a9: push esi
         // 004021aa: push edi
         // 004021ab: push ebp
         // 004021ac: add esp, 0xfffffffffffffff8
         // 004021af: mov esi, edx
         // 004021b1: add esi, 0x7
         // 004021b4: and esi, 0xfffffffffffffffc
         // 004021b7: cmp esi, 0xc
         // 004021ba: jge 0x4021c1
      [-]be????????
         // 004021bc: mov esi, 0xc
      [-]8be883ed048b7d0081e7????????8bc503c78bd83bfe7507
         // 004021c1: mov ebp, eax
         // 004021c3: sub ebp, 0x4
         // 004021c6: mov edi, ss:[ebp+0x0]
         // 004021c9: and edi, 0x7ffffffc
         // 004021cf: mov eax, ebp
         // 004021d1: add eax, edi
         // 004021d3: mov ebx, eax
         // 004021d5: cmp edi, esi
         // 004021d7: jnz 0x4021e0
      [-]b001e99b010000
         // 004021d9: mov b1 al, b1 0x1
         // 004021db: jmp 0x40237b
      [-]3bfe0f8e83000000
         // 004021e0: cmp edi, esi
         // 004021e2: jle 0x40226b
      [-]8bd72bd68914243b1d????????7538
         // 004021e8: mov edx, edi
         // 004021ea: sub edx, esi
         // 004021ec: mov ss:[esp], edx
         // 004021ef: cmp ebx, ds:[0x40a608]
         // 004021f5: jnz 0x40222f
      [-]8b04242905????????8b04240105????????833d????????0c0f8d4c010000
         // 004021f7: mov eax, ss:[esp]
         // 004021fa: sub ds:[0x40a608], eax
         // 00402200: mov eax, ss:[esp]
         // 00402203: add ds:[0x40a604], eax
         // 00402209: cmp ds:[0x40a604], 0xc
         // 00402210: jge 0x402362
      [-]8b04240105????????8b04242905????????8bf7e933010000
         // 00402216: mov eax, ss:[esp]
         // 00402219: add ds:[0x40a608], eax
         // 0040221f: mov eax, ss:[esp]
         // 00402222: sub ds:[0x40a604], eax
         // 00402228: mov esi, edi
         // 0040222a: jmp 0x402362
      [-]8bd8f60302750d
         // 0040222f: mov ebx, eax
         // 00402231: test b1 ds:[ebx], b1 0x2
         // 00402234: jnz 0x402243
      [-]8bc38b5008011424e8e9f6ffff
         // 00402236: mov eax, ebx
         // 00402238: mov edx, ds:[eax+0x8]
         // 0040223b: add ss:[esp], edx
         // 0040223e: call 0x40192c
      [-]833c240c7c1b
         // 00402243: cmp ss:[esp], 0xc
         // 00402247: jl 0x402264
      [-]8bdd03de8b042483c80289038bc383c004e891f7ffffe9fe000000
         // 00402249: mov ebx, ebp
         // 0040224b: add ebx, esi
         // 0040224d: mov eax, ss:[esp]
         // 00402250: or eax, 0x2
         // 00402253: mov ds:[ebx], eax
         // 00402255: mov eax, ebx
         // 00402257: add eax, 0x4
         // 0040225a: call 0x4019f0
         // 0040225f: jmp 0x402362
      [-]8bf7e9f7000000
         // 00402264: mov esi, edi
         // 00402266: jmp 0x402362
      [-]8bc62bc7894424043b1d????????7567
         // 0040226b: mov eax, esi
         // 0040226d: sub eax, edi
         // 0040226f: mov ss:[esp+0x4], eax
         // 00402273: cmp ebx, ds:[0x40a608]
         // 00402279: jnz 0x4022e2
      [-]a1????????3b4424047c53
         // 0040227b: mov eax, ds:[0x40a604]
         // 00402280: cmp eax, ss:[esp+0x4]
         // 00402284: jl 0x4022d9
      [-]8b4424042905????????8b4424040105????????833d????????0c7d18
         // 00402286: mov eax, ss:[esp+0x4]
         // 0040228a: sub ds:[0x40a604], eax
         // 00402290: mov eax, ss:[esp+0x4]
         // 00402294: add ds:[0x40a608], eax
         // 0040229a: cmp ds:[0x40a604], 0xc
         // 004022a1: jge 0x4022bb
      [-]a1????????0105????????0335????????33c0a3????????
         // 004022a3: mov eax, ds:[0x40a604]
         // 004022a8: add ds:[0x40a608], eax
         // 004022ae: add esi, ds:[0x40a604]
         // 004022b4: xor eax, eax
         // 004022b6: mov ds:[0x40a604], eax
      [-]8bc62bc70105????????8b450025????????0bf0897500b001e9a2000000
         // 004022bb: mov eax, esi
         // 004022bd: sub eax, edi
         // 004022bf: add ds:[0x40a5a0], eax
         // 004022c5: mov eax, ss:[ebp+0x0]
         // 004022c8: and eax, 0xffffffff80000003
         // 004022cd: or esi, eax
         // 004022cf: mov ss:[ebp+0x0], esi
         // 004022d2: mov b1 al, b1 0x1
         // 004022d4: jmp 0x40237b
      [-]e83ef9ffff8bdd03df
         // 004022d9: call 0x401c1c
         // 004022de: mov ebx, ebp
         // 004022e0: add ebx, edi
      [-]f60302754d
         // 004022e2: test b1 ds:[ebx], b1 0x2
         // 004022e5: jnz 0x402334
      [-]8bd38bc28b4808890c248b0c243b4c24047d0e
         // 004022e7: mov edx, ebx
         // 004022e9: mov eax, edx
         // 004022eb: mov ecx, ds:[eax+0x8]
         // 004022ee: mov ss:[esp], ecx
         // 004022f1: mov ecx, ss:[esp]
         // 004022f4: cmp ecx, ss:[esp+0x4]
         // 004022f8: jge 0x402308
      [-]0314248bda8b042429442404eb2c
         // 004022fa: add edx, ss:[esp]
         // 004022fd: mov ebx, edx
         // 004022ff: mov eax, ss:[esp]
         // 00402302: sub ss:[esp+0x4], eax
         // 00402306: jmp 0x402334
      [-]e81ff6ffff8b442404290424833c240c7c0e
         // 00402308: call 0x40192c
         // 0040230d: mov eax, ss:[esp+0x4]
         // 00402311: sub ss:[esp], eax
         // 00402314: cmp ss:[esp], 0xc
         // 00402318: jl 0x402328
      [-]8bc503c68b1424e86ef8ffffeb3a
         // 0040231a: mov eax, ebp
         // 0040231c: add eax, esi
         // 0040231e: mov edx, ss:[esp]
         // 00402321: call 0x401b94
         // 00402326: jmp 0x402362
      [-]0334248bdd03de8323feeb2e
         // 00402328: add esi, ss:[esp]
         // 0040232b: mov ebx, ebp
         // 0040232d: add ebx, esi
         // 0040232f: and ds:[ebx], 0xfffffffffffffffe
         // 00402332: jmp 0x402362
      [-]8b03a9????????7421
         // 00402334: mov eax, ds:[ebx]
         // 00402336: test eax, 0xffffffff80000000
         // 0040233b: jz 0x40235e
      [-]25????????03c38bd88b5424048bc3e8cff9ffff84c07409
         // 0040233d: and eax, 0x7ffffffc
         // 00402342: add eax, ebx
         // 00402344: mov ebx, eax
         // 00402346: mov edx, ss:[esp+0x4]
         // 0040234a: mov eax, ebx
         // 0040234c: call 0x401d20
         // 00402351: test b1 al, b1 al
         // 00402353: jz 0x40235e
      [-]8bdd03dfe90dffffff
         // 00402355: mov ebx, ebp
         // 00402357: add ebx, edi
         // 00402359: jmp 0x40226b
      [-]33c0eb19
         // 0040235e: xor eax, eax
         // 00402360: jmp 0x40237b
      [-]8bc62bc70105????????8b450025????????0bf0897500b001
         // 00402362: mov eax, esi
         // 00402364: sub eax, edi
         // 00402366: add ds:[0x40a5a0], eax
         // 0040236c: mov eax, ss:[ebp+0x0]
         // 0040236f: and eax, 0xffffffff80000003
         // 00402374: or esi, eax
         // 00402376: mov ss:[ebp+0x0], esi
         // 00402379: mov b1 al, b1 0x1
      [-]595a5d5f5e5bc3
         // 0040237b: pop ecx
         // 0040237c: pop edx
         // 0040237d: pop ebp
         // 0040237e: pop edi
         // 0040237f: pop esi
         // 00402380: pop ebx
         // 00402381: retn 
      [-]558bec515356578bf28bd8803daca54000007513
         // 00402384: push ebp
         // 00402385: mov ebp, esp
         // 00402387: push ecx
         // 00402388: push ebx
         // 00402389: push esi
         // 0040238a: push edi
         // 0040238b: mov esi, edx
         // 0040238d: mov ebx, eax
         // 0040238f: cmp b1 ds:[0x40a5ac], b1 0x0
         // 00402396: jnz 0x4023ab
      [-]e8ebf3ffff84c0750a
         // 00402398: call 0x401788
         // 0040239d: test b1 al, b1 al
         // 0040239f: jnz 0x4023ab
      [-]33c08945fce991000000
         // 004023a1: xor eax, eax
         // 004023a3: mov ss:[ebp+0xfffffffffffffffc], eax
         // 004023a6: jmp 0x40243c
      [-]33d25568????????64ff32648922803d35a0400000740a
         // 004023ab: xor edx, edx
         // 004023ad: push ebp
         // 004023ae: push 0x402435
         // 004023b3: push fs:[edx]
         // 004023b6: mov fs:[edx], esp
         // 004023b9: cmp b1 ds:[0x40a035], b1 0x0
         // 004023c0: jz 0x4023cc
      [-]e818edffff
         // 004023c7: call EnterCriticalSection
      [-]8bd68bc3e8d3fdffff84c07405
         // 004023cc: mov edx, esi
         // 004023ce: mov eax, ebx
         // 004023d0: call 0x4021a8
         // 004023d5: test b1 al, b1 al
         // 004023d7: jz 0x4023de
      [-]895dfceb36
         // 004023d9: mov ss:[ebp+0xfffffffffffffffc], ebx
         // 004023dc: jmp 0x402414
      [-]8bc6e88ffaffff8bf88bc383e8048b0025????????83e8043bf07d02
         // 004023de: mov eax, esi
         // 004023e0: call 0x401e74
         // 004023e5: mov edi, eax
         // 004023e7: mov eax, ebx
         // 004023e9: sub eax, 0x4
         // 004023ec: mov eax, ds:[eax]
         // 004023ee: and eax, 0x7ffffffc
         // 004023f3: sub eax, 0x4
         // 004023f6: cmp esi, eax
         // 004023f8: jge 0x4023fc
      [-]85ff7411
         // 004023fc: test edi, edi
         // 004023fe: jz 0x402411
      [-]8bd78bcb91e8420100008bc3e8f3fbffff
         // 00402400: mov edx, edi
         // 00402402: mov ecx, ebx
         // 00402404: xchg eax, ecx
         // 00402405: call 0x40254c
         // 0040240a: mov eax, ebx
         // 0040240c: call 0x402004
      [-]33c05a595964891068????????803d35a0400000740a
         // 00402414: xor eax, eax
         // 00402416: pop edx
         // 00402417: pop ecx
         // 00402418: pop ecx
         // 00402419: mov fs:[eax], edx
         // 0040241c: push 0x40243c
         // 00402421: cmp b1 ds:[0x40a035], b1 0x0
         // 00402428: jz 0x402434
      [-]e8b8ecffff
         // 0040242f: call LeaveCriticalSection
      [-]5e5b595dc3
         // 00402440: pop esi
         // 00402441: pop ebx
         // 00402442: pop ecx
         // 00402443: pop ebp
         // 00402444: retn 
      [-]5385c07e15
         // 00402448: push ebx
         // 00402449: test eax, eax
         // 0040244b: jle 0x402462
      [-]5385c07415
         // 00402468: push ebx
         // 00402469: test eax, eax
         // 0040246b: jz 0x402482
      [-]ff15????????8bd885db740b
         // 0040246d: call ds:[0x409034]
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
      [-]5089c8ff15????????5909c07419
         // 00402492: push eax
         // 00402493: mov eax, ecx
         // 00402495: call ds:[0x409038]
         // 0040249b: pop ecx
         // 0040249c: or eax, eax
         // 0040249e: jz 0x4024b9
      [-]b002e986000000
         // 004024a3: mov b1 al, b1 0x2
         // 004024a5: jmp 0x402530
      [-]891089c8ff15????????09c075eb
         // 004024aa: mov ds:[eax], edx
         // 004024ac: mov eax, ecx
         // 004024ae: call ds:[0x409034]
         // 004024b4: or eax, eax
         // 004024b6: jnz 0x4024a3
      [-]b001e970000000
         // 004024b9: mov b1 al, b1 0x1
         // 004024bb: jmp 0x402530
      [-]85d27410
         // 004024c0: test edx, edx
         // 004024c2: jz 0x4024d4
      [-]5089d0ff15????????5909c074e7
         // 004024c4: push eax
         // 004024c5: mov eax, edx
         // 004024c7: call ds:[0x409030]
         // 004024cd: pop ecx
         // 004024ce: or eax, eax
         // 004024d0: jz 0x4024b9
      [-]53568bf28bd880e37f833d????????00740a
         // 004024e4: push ebx
         // 004024e5: push esi
         // 004024e6: mov esi, edx
         // 004024e8: mov ebx, eax
         // 004024ea: and b1 bl, b1 0x7f
         // 004024ed: cmp ds:[0x40a008], 0x0
         // 004024f4: jz 0x402500
      [-]8bd68bc3ff15????????
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
      [-]8bc6e867ffffffeb12
         // 004025ce: mov eax, esi
         // 004025d0: call 0x40253c
         // 004025d5: jmp 0x4025e9
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
      [-]83c00883c2084e75e2
         // 0040260f: add eax, 0x8
         // 00402612: add edx, 0x8
         // 00402615: dec esi
         // 00402616: jnz 0x4025fa
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
      [-]5331db6993????????????????428993????????f7e289d05bc3
         // 00402680: push ebx
         // 00402681: xor ebx, ebx
         // 00402683: imul edx, ds:[ebx+0x409008], 0x8088405
         // 0040268d: inc edx
         // 0040268e: mov ds:[ebx+0x409008], edx
         // 00402694: mul edx
         // 00402696: mov eax, edx
         // 00402698: pop ebx
         // 00402699: retn 
      [-]53565789c65085c0746c
         // 0040269c: push ebx
         // 0040269d: push esi
         // 0040269e: push edi
         // 0040269f: mov esi, eax
         // 004026a1: push eax
         // 004026a2: test eax, eax
         // 004026a4: jz 0x402712
      [-]31c031dbbf????????
         // 004026a6: xor eax, eax
         // 004026a8: xor ebx, ebx
         // 004026aa: mov edi, 0xccccccc
      [-]8a1e4680fb2074f8
         // 004026af: mov b1 bl, b1 ds:[esi]
         // 004026b1: inc esi
         // 004026b2: cmp b1 bl, b1 0x20
         // 004026b5: jz 0x4026af
      [-]b50080fb2d7462
         // 004026b7: mov b1 ch, b1 0x0
         // 004026b9: cmp b1 bl, b1 0x2d
         // 004026bc: jz 0x402720
      [-]80fb2b745f
         // 004026be: cmp b1 bl, b1 0x2b
         // 004026c1: jz 0x402722
      [-]80fb24745f
         // 004026c3: cmp b1 bl, b1 0x24
         // 004026c6: jz 0x402727
      [-]80fb78745a
         // 004026c8: cmp b1 bl, b1 0x78
         // 004026cb: jz 0x402727
      [-]80fb587455
         // 004026cd: cmp b1 bl, b1 0x58
         // 004026d0: jz 0x402727
      [-]80fb307513
         // 004026d2: cmp b1 bl, b1 0x30
         // 004026d5: jnz 0x4026ea
      [-]8a1e4680fb787448
         // 004026d7: mov b1 bl, b1 ds:[esi]
         // 004026d9: inc esi
         // 004026da: cmp b1 bl, b1 0x78
         // 004026dd: jz 0x402727
      [-]80fb587443
         // 004026df: cmp b1 bl, b1 0x58
         // 004026e2: jz 0x402727
      [-]84db7420
         // 004026e4: test b1 bl, b1 bl
         // 004026e6: jz 0x402708
      [-]84db742d
         // 004026ea: test b1 bl, b1 bl
         // 004026ec: jz 0x40271b
      [-]80eb3080fb097725
         // 004026ee: sub b1 bl, b1 0x30
         // 004026f1: cmp b1 bl, b1 0x9
         // 004026f4: ja 0x40271b
      [-]39f87721
         // 004026f6: cmp eax, edi
         // 004026f8: ja 0x40271b
      [-]8d048001c001d88a1e4684db75e6
         // 004026fa: lea eax, ds:[eax+eax*0x4]
         // 004026fd: add eax, eax
         // 004026ff: add eax, ebx
         // 00402701: mov b1 bl, b1 ds:[esi]
         // 00402703: inc esi
         // 00402704: test b1 bl, b1 bl
         // 00402706: jnz 0x4026ee
      [-]fecd7409
         // 00402708: dec b1 ch
         // 0040270a: jz 0x402715
      [-]85c07d54
         // 0040270c: test eax, eax
         // 0040270e: jge 0x402764
      [-]f7d87e4b
         // 00402715: neg eax
         // 00402717: jle 0x402764
      [-]5b29deeb47
         // 0040271b: pop ebx
         // 0040271c: sub esi, ebx
         // 0040271e: jmp 0x402767
      [-]8a1e46eb9c
         // 00402722: mov b1 bl, b1 ds:[esi]
         // 00402724: inc esi
         // 00402725: jmp 0x4026c3
      [-]bf????????8a1e4684db74df
         // 00402727: mov edi, 0xfffffff
         // 0040272c: mov b1 bl, b1 ds:[esi]
         // 0040272e: inc esi
         // 0040272f: test b1 bl, b1 bl
         // 00402731: jz 0x402712
      [-]80fb617203
         // 00402733: cmp b1 bl, b1 0x61
         // 00402736: jb 0x40273b
      [-]80eb3080fb09760b
         // 0040273b: sub b1 bl, b1 0x30
         // 0040273e: cmp b1 bl, b1 0x9
         // 00402741: jbe 0x40274e
      [-]80eb1180fb0577d0
         // 00402743: sub b1 bl, b1 0x11
         // 00402746: cmp b1 bl, b1 0x5
         // 00402749: ja 0x40271b
      [-]39f877c9
         // 0040274e: cmp eax, edi
         // 00402750: ja 0x40271b
      [-]c1e00401d88a1e4684db75d5
         // 00402752: shl eax, b1 0x4
         // 00402755: add eax, ebx
         // 00402757: mov b1 bl, b1 ds:[esi]
         // 00402759: inc esi
         // 0040275a: test b1 bl, b1 bl
         // 0040275c: jnz 0x402733
      [-]fecd7502
         // 0040275e: dec b1 ch
         // 00402760: jnz 0x402764
      [-]89325f5e5bc3
         // 00402767: mov ds:[edx], esi
         // 00402769: pop edi
         // 0040276a: pop esi
         // 0040276b: pop ebx
         // 0040276c: retn 
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
      [-]8a1a4284db7406
         // 0040278b: mov b1 bl, b1 ds:[edx]
         // 0040278d: inc edx
         // 0040278e: test b1 bl, b1 bl
         // 00402790: jz 0x402798
      [-]4088184975f3
         // 00402792: inc eax
         // 00402793: mov b1 ds:[eax], b1 bl
         // 00402795: dec ecx
         // 00402796: jnz 0x40278b
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
      [-]578b4af889c75031c0c1e902f3ab8b4af883e103f3aa585f8b4afc85c97c03
         // 004027bd: push edi
         // 004027be: mov ecx, ds:[edx+0xfffffffffffffff8]
         // 004027c1: mov edi, eax
         // 004027c3: push eax
         // 004027c4: xor eax, eax
         // 004027c6: shr ecx, b1 0x2
         // 004027c9: rep stosdd 
         // 004027cb: mov ecx, ds:[edx+0xfffffffffffffff8]
         // 004027ce: and ecx, 0x3
         // 004027d1: rep stosbb 
         // 004027d3: pop eax
         // 004027d4: pop edi
         // 004027d5: mov ecx, ds:[edx+0xfffffffffffffffc]
         // 004027d8: test ecx, ecx
         // 004027da: jl 0x4027df
      [-]85c059c3
         // 004027df: test eax, eax
         // 004027e1: pop ecx
         // 004027e2: retn 
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
      [-]5333db6a00e8eeffffff83f807751c
         // 00402808: push ebx
         // 00402809: xor ebx, ebx
         // 0040280b: push 0x0
         // 0040280d: call GetKeyboardType
         // 00402812: cmp eax, 0x7
         // 00402815: jnz 0x402833
      [-]6a01e8e2ffffff25????????3d????????7407
         // 00402817: push 0x1
         // 00402819: call GetKeyboardType
         // 0040281e: and eax, 0xff00
         // 00402823: cmp eax, 0xd00
         // 00402828: jz 0x402831
      [-]3d????????7502
         // 0040282a: cmp eax, 0x400
         // 0040282f: jnz 0x402833
      [-]8bc35bc3
         // 00402833: mov eax, ebx
         // 00402835: pop ebx
         // 00402836: retn 
      [-]558bec83c4f40fb705189040008945f88d45fc506a016a0068????????68????????e809e8ffff85c0754d
         // 00402838: push ebp
         // 00402839: mov ebp, esp
         // 0040283b: add esp, 0xfffffffffffffff4
         // 0040283e: movzx eax, b2 ds:[0x409018]
         // 00402845: mov ss:[ebp+0xfffffffffffffff8], eax
         // 00402848: lea eax, ss:[ebp+0xfffffffffffffffc]
         // 0040284b: push eax
         // 0040284c: push 0x1
         // 0040284e: push 0x0
         // 00402850: push 0x4028d0
         // 00402855: push 0xffffffff80000002
         // 0040285a: call RegOpenKeyExA
         // 0040285f: test eax, eax
         // 00402861: jnz 0x4028b0
      [-]33c05568????????64ff30648920c745f4????????8d45f4508d45f8506a006a0068????????8b45fc50e8dee7ffff33c05a595964891068????????8b45fc50e8b8e7ffffc3
         // 00402863: xor eax, eax
         // 00402865: push ebp
         // 00402866: push 0x4028a9
         // 0040286b: push fs:[eax]
         // 0040286e: mov fs:[eax], esp
         // 00402871: mov ss:[ebp+0xfffffffffffffff4], 0x4
         // 00402878: lea eax, ss:[ebp+0xfffffffffffffff4]
         // 0040287b: push eax
         // 0040287c: lea eax, ss:[ebp+0xfffffffffffffff8]
         // 0040287f: push eax
         // 00402880: push 0x0
         // 00402882: push 0x0
         // 00402884: push 0x4028ec
         // 00402889: mov eax, ss:[ebp+0xfffffffffffffffc]
         // 0040288c: push eax
         // 0040288d: call RegQueryValueExA
         // 00402892: xor eax, eax
         // 00402894: pop edx
         // 00402895: pop ecx
         // 00402896: pop ecx
         // 00402897: mov fs:[eax], edx
         // 0040289a: push 0x4028b0
         // 0040289f: mov eax, ss:[ebp+0xfffffffffffffffc]
         // 004028a2: push eax
         // 004028a3: call RegCloseKey
         // 004028a8: retn 
      [-]e982020000
         // 004028a9: jmp 0x402b30
      [-]66a1189040006625c0ff668b55f86683e23f660bc266a3189040008be55dc3
         // 004028b0: mov b2 ax, b2 ds:[0x409018]
         // 004028b6: and b2 ax, b2 0xffffffffffffffc0
         // 004028ba: mov b2 dx, b2 ss:[ebp+0xfffffffffffffff8]
         // 004028be: and b2 dx, b2 0x3f
         // 004028c2: or b2 ax, b2 dx
         // 004028c5: mov b2 ds:[0x409018], b2 ax
         // 004028cb: mov esp, ebp
         // 004028cd: pop ebp
         // 004028ce: retn 
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
      [-]803d1c904000017611
         // 00402914: cmp b1 ds:[0x40901c], b1 0x1
         // 0040291b: jbe 0x40292e
      [-]6a006a006a0068????????ff15????????
         // 0040291d: push 0x0
         // 0040291f: push 0x0
         // 00402921: push 0x0
         // 00402923: push 0xeedfadf
         // 00402928: call ds:[0x40a010]
      [-]803d1c904000017607
         // 0040296c: cmp b1 ds:[0x40901c], b1 0x1
         // 00402973: jbe 0x40297c
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
      [-]0fbec04141eb03
         // 00402991: movsx eax, b1 al
         // 00402994: inc ecx
         // 00402995: inc ecx
         // 00402996: jmp 0x40299b
      [-]803d1c90400001761d
         // 004029a0: cmp b1 ds:[0x40901c], b1 0x1
         // 004029a7: jbe 0x4029c6
      [-]505251e8cfffffff51546a016a0068????????
         // 004029a9: push eax
         // 004029aa: push edx
         // 004029ab: push ecx
         // 004029ac: call 0x402980
         // 004029b1: push ecx
         // 004029b2: push esp
         // 004029b3: push 0x1
         // 004029b5: push 0x0
         // 004029b7: push 0xeedfae1
      [-]5052803d1c904000017610
         // 004029e4: push eax
         // 004029e5: push edx
         // 004029e6: cmp b1 ds:[0x40901c], b1 0x1
         // 004029ed: jbe 0x4029ff
      [-]546a026a0068????????ff15????????
         // 004029ef: push esp
         // 004029f0: push 0x2
         // 004029f2: push 0x0
         // 004029f4: push 0xeedfae3
         // 004029f9: call ds:[0x40a010]
      [-]8b4424048b542408f74004????????741f
         // 00402b30: mov eax, ss:[esp+0x4]
         // 00402b34: mov edx, ss:[esp+0x8]
         // 00402b38: test ds:[eax+0x4], 0x6
         // 00402b3f: jz 0x402b60
      [-]8b4a04c74204????????535657558b6a0883c105e846feffffffd15d5f5e5b
         // 00402b41: mov ecx, ds:[edx+0x4]
         // 00402b44: mov ds:[edx+0x4], 0x402b60
         // 00402b4b: push ebx
         // 00402b4c: push esi
         // 00402b4d: push edi
         // 00402b4e: push ebp
         // 00402b4f: mov ebp, ds:[edx+0x8]
         // 00402b52: add ecx, 0x5
         // 00402b55: call 0x4029a0
         // 00402b5a: call ecx
         // 00402b5c: pop ebp
         // 00402b5d: pop edi
         // 00402b5e: pop esi
         // 00402b5f: pop ebx
      [-]b8????????c3
         // 00402b60: mov eax, 0x1
         // 00402b65: retn 
      [-]31d28b4c24088b44240483c105648902ffd1c20c00
         // 00402bec: xor edx, edx
         // 00402bee: mov ecx, ss:[esp+0x8]
         // 00402bf2: mov eax, ss:[esp+0x4]
         // 00402bf6: add ecx, 0x5
         // 00402bf9: mov fs:[edx], eax
         // 00402bfc: call ecx
         // 00402bfe: retn b2 0xc
      [-]31d28d45f4648b0a6489028908c74004????????896808a3????????c3
         // 00402d44: xor edx, edx
         // 00402d46: lea eax, ss:[ebp+0xfffffffffffffff4]
         // 00402d49: mov ecx, fs:[edx]
         // 00402d4c: mov fs:[edx], eax
         // 00402d4f: mov ds:[eax], ecx
         // 00402d51: mov ds:[eax+0x4], 0x402ca4
         // 00402d58: mov ds:[eax+0x8], ebp
         // 00402d5b: mov ds:[0x40a624], eax
         // 00402d60: retn 
      [-]31d2a1????????85c0741c
         // 00402d64: xor edx, edx
         // 00402d66: mov eax, ds:[0x40a624]
         // 00402d6b: test eax, eax
         // 00402d6d: jz 0x402d8b
      [-]648b0a39c87508
         // 00402d6f: mov ecx, fs:[edx]
         // 00402d72: cmp eax, ecx
         // 00402d74: jnz 0x402d7e
      [-]8b00648902c3
         // 00402d76: mov eax, ds:[eax]
         // 00402d78: mov fs:[edx], eax
         // 00402d7b: retn 
      [-]83f9ff7408
         // 00402d7e: cmp ecx, 0xffffffffffffffff
         // 00402d81: jz 0x402d8b
      [-]390175f5
         // 00402d83: cmp ds:[ecx], eax
         // 00402d85: jnz 0x402d7c
      [-]8b008901
         // 00402d87: mov eax, ds:[eax]
         // 00402d89: mov ds:[ecx], eax
      [-]558bec535657bf????????8b470885c07448
         // 00402d8c: push ebp
         // 00402d8d: mov ebp, esp
         // 00402d8f: push ebx
         // 00402d90: push esi
         // 00402d91: push edi
         // 00402d92: mov edi, 0x40a620
         // 00402d97: mov eax, ds:[edi+0x8]
         // 00402d9a: test eax, eax
         // 00402d9c: jz 0x402de6
      [-]8b5f0c8b700433d25568????????64ff3264892285db7e12
         // 00402d9e: mov ebx, ds:[edi+0xc]
         // 00402da1: mov esi, ds:[eax+0x4]
         // 00402da4: xor edx, edx
         // 00402da6: push ebp
         // 00402da7: push 0x402dd2
         // 00402dac: push fs:[edx]
         // 00402daf: mov fs:[edx], esp
         // 00402db2: test ebx, ebx
         // 00402db4: jle 0x402dc8
      [-]4b895f0c8b44de0485c07402
         // 00402db6: dec ebx
         // 00402db7: mov ds:[edi+0xc], ebx
         // 00402dba: mov eax, ds:[esi+ebx*0x8]
         // 00402dbe: test eax, eax
         // 00402dc0: jz 0x402dc4
      [-]85db7fee
         // 00402dc4: test ebx, ebx
         // 00402dc6: jg 0x402db6
      [-]33c05a5959648910
         // 00402dc8: xor eax, eax
         // 00402dca: pop edx
         // 00402dcb: pop ecx
         // 00402dcc: pop ecx
         // 00402dcd: mov fs:[eax], edx
      [-]5f5e5b5dc3
         // 00402de6: pop edi
         // 00402de7: pop esi
         // 00402de8: pop ebx
         // 00402de9: pop ebp
         // 00402dea: retn 
      [-]558bec535657a1????????85c0744b
         // 00402dec: push ebp
         // 00402ded: mov ebp, esp
         // 00402def: push ebx
         // 00402df0: push esi
         // 00402df1: push edi
         // 00402df2: mov eax, ds:[0x40a628]
         // 00402df7: test eax, eax
         // 00402df9: jz 0x402e46
      [-]8b3033db8b780433d25568????????64ff326489223bf37e14
         // 00402dfb: mov esi, ds:[eax]
         // 00402dfd: xor ebx, ebx
         // 00402dff: mov edi, ds:[eax+0x4]
         // 00402e02: xor edx, edx
         // 00402e04: push ebp
         // 00402e05: push 0x402e32
         // 00402e0a: push fs:[edx]
         // 00402e0d: mov fs:[edx], esp
         // 00402e10: cmp esi, ebx
         // 00402e12: jle 0x402e28
      [-]8b04df43891d????????85c07402
         // 00402e14: mov eax, ds:[edi+ebx*0x8]
         // 00402e17: inc ebx
         // 00402e18: mov ds:[0x40a62c], ebx
         // 00402e1e: test eax, eax
         // 00402e20: jz 0x402e24
      [-]3bf37fec
         // 00402e24: cmp esi, ebx
         // 00402e26: jg 0x402e14
      [-]33c05a5959648910eb14
         // 00402e28: xor eax, eax
         // 00402e2a: pop edx
         // 00402e2b: pop ecx
         // 00402e2c: pop ecx
         // 00402e2d: mov fs:[eax], edx
         // 00402e30: jmp 0x402e46
      [-]5f5e5b5dc3
         // 00402e46: pop edi
         // 00402e47: pop esi
         // 00402e48: pop ebx
         // 00402e49: pop ebp
         // 00402e4a: retn 
      [-]c705????????
         // 00402e4c: mov ds:[0x40a010], RaiseException
      [-]c705????????
         // 00402e56: mov ds:[0x40a014], RtlUnwind
      [-]a3????????33c0a3????????8915????????8b4204a3????????e8c5feffffc60524a0400000e861ffffffc3
         // 00402e60: mov ds:[0x40a628], eax
         // 00402e65: xor eax, eax
         // 00402e67: mov ds:[0x40a62c], eax
         // 00402e6c: mov ds:[0x40a630], edx
         // 00402e72: mov eax, ds:[edx+0x4]
         // 00402e75: mov ds:[0x40a01c], eax
         // 00402e7a: call 0x402d44
         // 00402e7f: mov b1 ds:[0x40a024], b1 0x0
         // 00402e86: call 0x402dec
         // 00402e8b: retn 
      [-]535657be????????b1108b1d????????
         // 00402e8c: push ebx
         // 00402e8d: push esi
         // 00402e8e: push edi
         // 00402e8f: mov esi, 0x409060
         // 00402e94: mov b1 cl, b1 0x10
         // 00402e96: mov ebx, ds:[0x409000]
      [-]8bc3bf????????99f7ff80c23033c08ac18814068bc3bb????????99f7fb8bd84985db75db
         // 00402e9c: mov eax, ebx
         // 00402e9e: mov edi, 0xa
         // 00402ea3: cdq 
         // 00402ea4: idiv edi
         // 00402ea6: add b1 dl, b1 0x30
         // 00402ea9: xor eax, eax
         // 00402eab: mov b1 al, b1 cl
         // 00402ead: mov b1 ds:[esi+eax], b1 dl
         // 00402eb0: mov eax, ebx
         // 00402eb2: mov ebx, 0xa
         // 00402eb7: cdq 
         // 00402eb8: idiv ebx
         // 00402eba: mov ebx, eax
         // 00402ebc: dec ecx
         // 00402ebd: test ebx, ebx
         // 00402ebf: jnz 0x402e9c
      [-]b11ca1????????
         // 00402ec1: mov b1 cl, b1 0x1c
         // 00402ec3: mov eax, ds:[0x409004]
      [-]8bd083e20f8a928090400033db8ad988141ec1e8044985c075e6
         // 00402ec8: mov edx, eax
         // 00402eca: and edx, 0xf
         // 00402ecd: mov b1 dl, b1 ds:[edx+0x409080]
         // 00402ed3: xor ebx, ebx
         // 00402ed5: mov b1 bl, b1 cl
         // 00402ed7: mov b1 ds:[esi+ebx], b1 dl
         // 00402eda: shr eax, b1 0x4
         // 00402edd: dec ecx
         // 00402ede: test eax, eax
         // 00402ee0: jnz 0x402ec8
      [-]5f5e5bc3
         // 00402ee2: pop edi
         // 00402ee3: pop esi
         // 00402ee4: pop ebx
         // 00402ee5: retn 
      [-]31c08705????????f7d819c040bf????????8b5f188b6f14ff771cff77208b37b9????????f3a55f5ec9c20c00
         // 00402ee8: xor eax, eax
         // 00402eea: xchg eax, ds:[0x409000]
         // 00402ef0: neg eax
         // 00402ef2: sbb eax, eax
         // 00402ef4: inc eax
         // 00402ef5: mov edi, 0x40a620
         // 00402efa: mov ebx, ds:[edi+0x18]
         // 00402efd: mov ebp, ds:[edi+0x14]
         // 00402f00: push ds:[edi+0x1c]
         // 00402f03: push ds:[edi+0x20]
         // 00402f06: mov esi, ds:[edi]
         // 00402f08: mov ecx, 0xb
         // 00402f0d: rep movsdd 
         // 00402f0f: pop edi
         // 00402f10: pop esi
         // 00402f11: leave 
         // 00402f12: retn b2 0xc
      [-]51803d34a04000007457
         // 00402f18: push ecx
         // 00402f19: cmp b1 ds:[0x40a034], b1 0x0
         // 00402f20: jz 0x402f79
      [-]66813d08a24000b2d77514
         // 00402f22: cmp b2 ds:[0x40a208], b2 0xffffffffffffd7b2
         // 00402f2b: jnz 0x402f41
      [-]833d????????00760b
         // 00402f2d: cmp ds:[0x40a210], 0x0
         // 00402f34: jbe 0x402f41
      [-]b8????????ff15????????
         // 00402f36: mov eax, 0x40a204
         // 00402f3b: call ds:[0x40a220]
      [-]6a008d442404506a1e68????????6af5e8aae0ffff50e8c4e0ffff6a008d442404506a0268????????6af5e88fe0ffff50e8a9e0ffff5ac3
         // 00402f41: push 0x0
         // 00402f43: lea eax, ss:[esp+0x4]
         // 00402f47: push eax
         // 00402f48: push 0x1e
         // 00402f4a: push 0x409060
         // 00402f4f: push 0xfffffffffffffff5
         // 00402f51: call GetStdHandle
         // 00402f56: push eax
         // 00402f57: call WriteFile
         // 00402f5c: push 0x0
         // 00402f5e: lea eax, ss:[esp+0x4]
         // 00402f62: push eax
         // 00402f63: push 0x2
         // 00402f65: push 0x402fa0
         // 00402f6a: push 0xfffffffffffffff5
         // 00402f6c: call GetStdHandle
         // 00402f71: push eax
         // 00402f72: call WriteFile
         // 00402f77: pop edx
         // 00402f78: retn 
      [-]803d24904000007513
         // 00402f79: cmp b1 ds:[0x409024], b1 0x0
         // 00402f80: jnz 0x402f95
      [-]6a0068????????68????????6a00e89be0ffff
         // 00402f82: push 0x0
         // 00402f84: push 0x409058
         // 00402f89: push 0x409060
         // 00402f8e: push 0x0
         // 00402f90: call MessageBoxA
      [-]53565755bb????????be????????bf????????807b28007516
         // 00402fa4: push ebx
         // 00402fa5: push esi
         // 00402fa6: push edi
         // 00402fa7: push ebp
         // 00402fa8: mov ebx, 0x40a620
         // 00402fad: mov esi, 0x409000
         // 00402fb2: mov edi, 0x40a030
         // 00402fb7: cmp b1 ds:[ebx+0x28], b1 0x0
         // 00402fbb: jnz 0x402fd3
      [-]833f007411
         // 00402fbd: cmp ds:[edi], 0x0
         // 00402fc0: jz 0x402fd3
      [-]8b1789d033d289178be8ffd5833f0075ef
         // 00402fc2: mov edx, ds:[edi]
         // 00402fc4: mov eax, edx
         // 00402fc6: xor edx, edx
         // 00402fc8: mov ds:[edi], edx
         // 00402fca: mov ebp, eax
         // 00402fcc: call ebp
         // 00402fce: cmp ds:[edi], 0x0
         // 00402fd1: jnz 0x402fc2
      [-]833d????????007411
         // 00402fd3: cmp ds:[0x409004], 0x0
         // 00402fda: jz 0x402fed
      [-]e8abfeffffe832ffffff33c0a3????????
         // 00402fdc: call 0x402e8c
         // 00402fe1: call 0x402f18
         // 00402fe6: xor eax, eax
         // 00402fe8: mov ds:[0x409004], eax
      [-]807b2802750a
         // 00402fed: cmp b1 ds:[ebx+0x28], b1 0x2
         // 00402ff1: jnz 0x402ffd
      [-]833e007505
         // 00402ff3: cmp ds:[esi], 0x0
         // 00402ff6: jnz 0x402ffd
      [-]33c089430c
         // 00402ff8: xor eax, eax
         // 00402ffa: mov ds:[ebx+0xc], eax
      [-]e88afdffff807b28017605
         // 00402ffd: call 0x402d8c
         // 00403002: cmp b1 ds:[ebx+0x28], b1 0x1
         // 00403006: jbe 0x40300d
      [-]833e007421
         // 00403008: cmp ds:[esi], 0x0
         // 0040300b: jz 0x40302e
      [-]8b431085c0741a
         // 0040300d: mov eax, ds:[ebx+0x10]
         // 00403010: test eax, eax
         // 00403012: jz 0x40302e
      [-]e8e70b00008b53108b42103b4204740a
         // 00403014: call 0x403c00
         // 00403019: mov edx, ds:[ebx+0x10]
         // 0040301c: mov eax, ds:[edx+0x10]
         // 0040301f: cmp eax, ds:[edx+0x4]
         // 00403022: jz 0x40302e
      [-]85c07406
         // 00403024: test eax, eax
         // 00403026: jz 0x40302e
      [-]50e80ae0ffff
         // 00403028: push eax
         // 00403029: call FreeLibrary
      [-]e831fdffff807b28017503
         // 0040302e: call 0x402d64
         // 00403033: cmp b1 ds:[ebx+0x28], b1 0x1
         // 00403037: jnz 0x40303c
      [-]807b28007405
         // 0040303c: cmp b1 ds:[ebx+0x28], b1 0x0
         // 00403040: jz 0x403047
      [-]e8a1feffff
         // 00403042: call 0x402ee8
      [-]833b007517
         // 00403047: cmp ds:[ebx], 0x0
         // 0040304a: jnz 0x403063
      [-]833d????????007406
         // 0040304c: cmp ds:[0x40a018], 0x0
         // 00403053: jz 0x40305b
      [-]ff15????????
         // 00403055: call ds:[0x40a018]
      [-]8b0650e8c5dfffff
         // 0040305b: mov eax, ds:[esi]
         // 0040305d: push eax
         // 0040305e: call ExitProcess
      [-]8b03568bf08bfbb9????????f3a55ee976ffffff
         // 00403063: mov eax, ds:[ebx]
         // 00403065: push esi
         // 00403066: mov esi, eax
         // 00403068: mov edi, ebx
         // 0040306a: mov ecx, 0xb
         // 0040306f: rep movsdd 
         // 00403071: pop esi
         // 00403072: jmp 0x402fed
      [-]8b1085d2741c
         // 00403094: mov edx, ds:[eax]
         // 00403096: test edx, edx
         // 00403098: jz 0x4030b6
      [-]c700????????8b4af8497c10
         // 0040309a: mov ds:[eax], 0x0
         // 004030a0: mov ecx, ds:[edx+0xfffffffffffffff8]
         // 004030a3: dec ecx
         // 004030a4: jl 0x4030b6
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
      [-]c703????????8b4af8497c0e
         // 004030c4: mov ds:[ebx], 0x0
         // 004030ca: mov ecx, ds:[edx+0xfffffffffffffff8]
         // 004030cd: dec ecx
         // 004030ce: jl 0x4030de
      [-]f0ff4af87508
         // 004030d0: lock dec ds:[edx+0xfffffffffffffff8]
         // 004030d4: jnz 0x4030de
      [-]8d42f8e88af3ffff
         // 004030d6: lea eax, ds:[edx+0xfffffffffffffff8]
         // 004030d9: call 0x402468
      [-]83c3044e75da
         // 004030de: add ebx, 0x4
         // 004030e1: dec esi
         // 004030e2: jnz 0x4030be
      [-]85d27424
         // 004030e8: test edx, edx
         // 004030ea: jz 0x403110
      [-]8b4af8417f1a
         // 004030ec: mov ecx, ds:[edx+0xfffffffffffffff8]
         // 004030ef: inc ecx
         // 004030f0: jg 0x40310c
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
      [-]8b4af8497c0e
         // 00403116: mov ecx, ds:[edx+0xfffffffffffffff8]
         // 00403119: dec ecx
         // 0040311a: jl 0x40312a
      [-]f0ff4af87508
         // 0040311c: lock dec ds:[edx+0xfffffffffffffff8]
         // 00403120: jnz 0x40312a
      [-]8d42f8e83ef3ffff
         // 00403122: lea eax, ds:[edx+0xfffffffffffffff8]
         // 00403125: call 0x402468
      [-]85d2740a
         // 0040312c: test edx, edx
         // 0040312e: jz 0x40313a
      [-]8b4af8417e04
         // 00403130: mov ecx, ds:[edx+0xfffffffffffffff8]
         // 00403133: inc ecx
         // 00403134: jle 0x40313a
      [-]f0ff42f8
         // 00403136: lock inc ds:[edx+0xfffffffffffffff8]
      [-]871085d27414
         // 0040313a: xchg edx, ds:[eax]
         // 0040313c: test edx, edx
         // 0040313e: jz 0x403154
      [-]8b4af8497c0e
         // 00403140: mov ecx, ds:[edx+0xfffffffffffffff8]
         // 00403143: dec ecx
         // 00403144: jl 0x403154
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
      [-]3a0a7417
         // 004031cb: cmp b1 cl, b1 ds:[edx]
         // 004031cd: jz 0x4031e6
      [-]3a4a017411
         // 004031cf: cmp b1 cl, b1 ds:[edx+0x1]
         // 004031d2: jz 0x4031e5
      [-]3a4a02740b
         // 004031d4: cmp b1 cl, b1 ds:[edx+0x2]
         // 004031d7: jz 0x4031e4
      [-]3a4a037405
         // 004031d9: cmp b1 cl, b1 ds:[edx+0x3]
         // 004031dc: jz 0x4031e3
      [-]83c204ebe8
         // 004031de: add edx, 0x4
         // 004031e1: jmp 0x4031cb
      [-]89d15a29d1
         // 004031e6: mov ecx, edx
         // 004031e8: pop edx
         // 004031e9: sub ecx, edx
      [-]e994ffffff
         // 004031eb: jmp 0x403184
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
      [-]83c60883c7084a75e2
         // 00403396: add esi, 0x8
         // 00403399: add edi, 0x8
         // 0040339c: dec edx
         // 0040339d: jnz 0x403381
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
      [-]8b50f8427e04
         // 00403400: mov edx, ds:[eax+0xfffffffffffffff8]
         // 00403403: inc edx
         // 00403404: jle 0x40340a
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
      [-]8b4af8497432
         // 0040341e: mov ecx, ds:[edx+0xfffffffffffffff8]
         // 00403421: dec ecx
         // 00403422: jz 0x403456
      [-]5389c38b42fce829fdffff89c28b038913508b48fce80ef1ffff588b48f8497c0e
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
         // 00403442: dec ecx
         // 00403443: jl 0x403453
      [-]f0ff48f87508
         // 00403445: lock dec ds:[eax+0xfffffffffffffff8]
         // 00403449: jnz 0x403453
      [-]8d40f8e815f0ffff
         // 0040344b: lea eax, ds:[eax+0xfffffffffffffff8]
         // 0040344e: call 0x402468
      [-]e9b7ffffff
         // 0040345c: jmp 0x403418
      [-]53565789c389d689cfe8
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

  }
  condition:
    all of them
}
