rule urelas_20_1 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         6a01e81fffffff59c3
         // 011aedcb: push 0x1
         // 011aedcd: call _flsall
         // 011aedd2: pop ecx
         // 011aedd3: retn 
      [-]85c07402
         // 011b45dd: test eax, eax
         // 011b45df: jz 0x11b45e3
      [-]85c07402
         // 011b4603: test eax, eax
         // 011b4605: jz 0x11b4609
      [-]ffff59c3
         // 0040cc63: pop ecx
         // 0040cc64: retn 
      [-]558bec83ec
         // 00414e6f: push ebp
         // 00414e70: mov ebp, esp
         // 00414e72: sub esp, 0x14
      [-]535657e8
         // 00414e75: push ebx
         // 00414e76: push esi
         // 00414e77: push edi
         // 00414e78: call __encoded_null
      [-]ffffc70424
         // 00429ad3: mov ss:[esp], 0x4316c0
      [-]ffd650e8
         // 00429ae0: call esi
         // 00429ae2: push eax
         // 00429ae3: call __encode_pointer
      [-]ffffc70424
         // 00429ae8: mov ss:[esp], 0x4316ac
      [-]ffd650e8
         // 00429af5: call esi
         // 00429af7: push eax
         // 00429af8: call __encode_pointer
      [-]57ffd650e8
         // 0040ceef: push edi
         // 0040cef0: call esi
         // 0040cef2: push eax
         // 0040cef3: call __encode_pointer
      [-]ffff59a3
         // 0040cef8: pop ecx
         // 0040cef9: mov ds:[0x42d4b4], eax
      [-]5f5e5bc9c3
         // 011b7de3: pop edi
         // 011b7de4: pop esi
         // 011b7de5: pop ebx
         // 011b7de6: leave 
         // 011b7de7: retn 
      [-]558bec83ec28a1
         // 00418cec: push ebp
         // 00418ced: mov ebp, esp
         // 00418cef: sub esp, 0x28
         // 00418cf2: mov eax, ds:[0x422044]
      [-]33c58945fc53568b750857ff75108b7d0c8d4ddce8
         // 00418cf7: xor eax, ebp
         // 00418cf9: mov ss:[ebp+0xfffffffffffffffc], eax
         // 00418cfc: push ebx
         // 00418cfd: push esi
         // 00418cfe: mov esi, ss:[ebp+0x8]
         // 00418d01: push edi
         // 00418d02: push ss:[ebp+0x10]
         // 00418d05: mov edi, ss:[ebp+0xc]
         // 00418d08: lea ecx, ss:[ebp+0xffffffffffffffdc]
         // 00418d0b: call ??0_LocaleUpdate@@QAE@PAUlocaleinfo_struct@@@Z
      [-]8d45dc5033db53535353578d45d8508d45f050e8
         // 00418d10: lea eax, ss:[ebp+0xffffffffffffffdc]
         // 00418d13: push eax
         // 00418d14: xor ebx, ebx
         // 00418d16: push ebx
         // 00418d17: push ebx
         // 00418d18: push ebx
         // 00418d19: push ebx
         // 00418d1a: push edi
         // 00418d1b: lea eax, ss:[ebp+0xffffffffffffffd8]
         // 00418d1e: push eax
         // 00418d1f: lea eax, ss:[ebp+0xfffffffffffffff0]
         // 00418d22: push eax
         // 00418d23: call ___strgtold12_l
      [-]00008945ec8d45f05650e8
         // 00418d28: mov ss:[ebp+0xffffffffffffffec], eax
         // 00418d2b: lea eax, ss:[ebp+0xfffffffffffffff0]
         // 00418d2e: push esi
         // 00418d2f: push eax
         // 00418d30: call 0x4191a9
      [-]000083c428f645ec03752b
         // 00418d35: add esp, 0x28
         // 00418d38: test b1 ss:[ebp+0xffffffffffffffec], b1 0x3
         // 00418d3c: jnz 0x418d69
      [-]83f8017511
         // 011b9159: cmp eax, 0x1
         // 011b915c: jnz 0x11b916f
      [-]385de87407
         // 011b915e: cmp b1 ss:[ebp+0xffffffffffffffe8], b1 bl
         // 011b9161: jz 0x11b916a
      [-]8b45e4836070fd
         // 011b9163: mov eax, ss:[ebp+0xffffffffffffffe4]
         // 011b9166: and ds:[eax+0x70], 0xfffffffffffffffd
      [-]83f802751c
         // 011b916f: cmp eax, 0x2
         // 011b9172: jnz 0x11b9190
      [-]385de87407
         // 011b9174: cmp b1 ss:[ebp+0xffffffffffffffe8], b1 bl
         // 011b9177: jz 0x11b9180
      [-]8b45e4836070fd
         // 011b9179: mov eax, ss:[ebp+0xffffffffffffffe4]
         // 011b917c: and ds:[eax+0x70], 0xfffffffffffffffd
      [-]6a04ebe8
         // 011b9180: push 0x4
         // 011b9182: jmp 0x11b916c
      [-]f645ec0175ea
         // 011b9184: test b1 ss:[ebp+0xffffffffffffffec], b1 0x1
         // 011b9188: jnz 0x11b9174
      [-]f645ec0275ce
         // 011b918a: test b1 ss:[ebp+0xffffffffffffffec], b1 0x2
         // 011b918e: jnz 0x11b915e
      [-]385de87407
         // 011b9190: cmp b1 ss:[ebp+0xffffffffffffffe8], b1 bl
         // 011b9193: jz 0x11b919c
      [-]8b45e4836070fd
         // 011b9195: mov eax, ss:[ebp+0xffffffffffffffe4]
         // 011b9198: and ds:[eax+0x70], 0xfffffffffffffffd
      [-]8b4dfc5f5e33cd5be8
         // 0041cb27: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 0041cb2a: pop edi
         // 0041cb2b: pop esi
         // 0041cb2c: xor ecx, ebp
         // 0041cb2e: pop ebx
         // 0041cb2f: call @__security_check_cookie@4
      [-]558bec83ec28a1
         // 00b191af: push ebp
         // 00b191b0: mov ebp, esp
         // 00b191b2: sub esp, 0x28
         // 00b191b5: mov eax, ds:[0xb27c20]
      [-]33c58945fc53568b750857ff75108b7d0c8d4ddce8
         // 00b191ba: xor eax, ebp
         // 00b191bc: mov ss:[ebp+0xfffffffffffffffc], eax
         // 00b191bf: push ebx
         // 00b191c0: push esi
         // 00b191c1: mov esi, ss:[ebp+0x8]
         // 00b191c4: push edi
         // 00b191c5: push ss:[ebp+0x10]
         // 00b191c8: mov edi, ss:[ebp+0xc]
         // 00b191cb: lea ecx, ss:[ebp+0xffffffffffffffdc]
         // 00b191ce: call ??0_LocaleUpdate@@QAE@PAUlocaleinfo_struct@@@Z
      [-]8d45dc5033db53535353578d45d8508d45f050e8
         // 00b191d3: lea eax, ss:[ebp+0xffffffffffffffdc]
         // 00b191d6: push eax
         // 00b191d7: xor ebx, ebx
         // 00b191d9: push ebx
         // 00b191da: push ebx
         // 00b191db: push ebx
         // 00b191dc: push ebx
         // 00b191dd: push edi
         // 00b191de: lea eax, ss:[ebp+0xffffffffffffffd8]
         // 00b191e1: push eax
         // 00b191e2: lea eax, ss:[ebp+0xfffffffffffffff0]
         // 00b191e5: push eax
         // 00b191e6: call ___strgtold12_l
      [-]00008945ec8d45f05650e8
         // 00b191eb: mov ss:[ebp+0xffffffffffffffec], eax
         // 00b191ee: lea eax, ss:[ebp+0xfffffffffffffff0]
         // 00b191f1: push esi
         // 00b191f2: push eax
         // 00b191f3: call 0xb1a34c
      [-]000083c428f645ec03752b
         // 00b191f8: add esp, 0x28
         // 00b191fb: test b1 ss:[ebp+0xffffffffffffffec], b1 0x3
         // 00b191ff: jnz 0xb1922c
      [-]83f8017511
         // 011b9201: cmp eax, 0x1
         // 011b9204: jnz 0x11b9217
      [-]385de87407
         // 011b9206: cmp b1 ss:[ebp+0xffffffffffffffe8], b1 bl
         // 011b9209: jz 0x11b9212
      [-]8b45e4836070fd
         // 011b920b: mov eax, ss:[ebp+0xffffffffffffffe4]
         // 011b920e: and ds:[eax+0x70], 0xfffffffffffffffd
      [-]83f802751c
         // 011b9217: cmp eax, 0x2
         // 011b921a: jnz 0x11b9238
      [-]385de87407
         // 011b921c: cmp b1 ss:[ebp+0xffffffffffffffe8], b1 bl
         // 011b921f: jz 0x11b9228
      [-]8b45e4836070fd
         // 011b9221: mov eax, ss:[ebp+0xffffffffffffffe4]
         // 011b9224: and ds:[eax+0x70], 0xfffffffffffffffd
      [-]6a04ebe8
         // 011b9228: push 0x4
         // 011b922a: jmp 0x11b9214
      [-]f645ec0175ea
         // 011b922c: test b1 ss:[ebp+0xffffffffffffffec], b1 0x1
         // 011b9230: jnz 0x11b921c
      [-]f645ec0275ce
         // 011b9232: test b1 ss:[ebp+0xffffffffffffffec], b1 0x2
         // 011b9236: jnz 0x11b9206
      [-]385de87407
         // 011b9238: cmp b1 ss:[ebp+0xffffffffffffffe8], b1 bl
         // 011b923b: jz 0x11b9244
      [-]8b45e4836070fd
         // 011b923d: mov eax, ss:[ebp+0xffffffffffffffe4]
         // 011b9240: and ds:[eax+0x70], 0xfffffffffffffffd
      [-]8b4dfc5f5e33cd5be8
         // 0041cbcf: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 0041cbd2: pop edi
         // 0041cbd3: pop esi
         // 0041cbd4: xor ecx, ebp
         // 0041cbd6: pop ebx
         // 0041cbd7: call @__security_check_cookie@4
      [-]558bec83ec2c8b45080fb7480a538bd981e1????????894dec8b4806894de08b48020fb70081e3????????81eb????????c1e01057894de48945e8
         // 004200cf: push ebp
         // 004200d0: mov ebp, esp
         // 004200d2: sub esp, 0x2c
         // 004200d5: mov eax, ss:[ebp+0x8]
         // 004200d8: movzx ecx, b2 ds:[eax+0xa]
         // 004200dc: push ebx
         // 004200dd: mov ebx, ecx
         // 004200df: and ecx, 0x8000
         // 004200e5: mov ss:[ebp+0xffffffffffffffec], ecx
         // 004200e8: mov ecx, ds:[eax+0x6]
         // 004200eb: mov ss:[ebp+0xffffffffffffffe0], ecx
         // 004200ee: mov ecx, ds:[eax+0x2]
         // 004200f1: movzx eax, b2 ds:[eax]
         // 004200f4: and ebx, 0x7fff
         // 004200fa: sub ebx, 0x3fff
         // 00420100: shl eax, b1 0x10
         // 00420109: push edi
         // 0042010a: mov ss:[ebp+0xffffffffffffffe4], ecx
         // 0042010d: mov ss:[ebp+0xffffffffffffffe8], eax
      [-]33db33c0
         // 011b9e4d: xor ebx, ebx
         // 011b9e4f: xor eax, eax
      [-]395c85e0750d
         // 011b9e51: cmp ss:[ebp+eax*0x4], ebx
         // 011b9e55: jnz 0x11b9e64
      [-]4083f8037cf4
         // 011b9e57: inc eax
         // 011b9e58: cmp eax, 0x3
         // 011b9e5b: jl 0x11b9e51
      [-]33c0e9a5040000
         // 011b9e5d: xor eax, eax
         // 011b9e5f: jmp 0x11ba309
      [-]33c08d7de0abab6a02ab58e995040000
         // 011b9e64: xor eax, eax
         // 011b9e66: lea edi, ss:[ebp+0xffffffffffffffe0]
         // 011b9e69: stosdd 
         // 011b9e6a: stosdd 
         // 011b9e6b: push 0x2
         // 011b9e6d: stosdd 
         // 011b9e6e: pop eax
         // 011b9e6f: jmp 0x11ba309
      [-]83650800568d75e08d7dd4a5a5a58b35
         // 00420139: and ss:[ebp+0x8], 0x0
         // 0042013d: push esi
         // 0042013e: lea esi, ss:[ebp+0xffffffffffffffe0]
         // 00420141: lea edi, ss:[ebp+0xffffffffffffffd4]
         // 00420144: movsdd 
         // 00420145: movsdd 
         // 00420146: movsdd 
         // 00420147: mov esi, ds:[0x42c6f8]
      [-]4e8d4e018bc19983e21f03c2c1f8058bd181e2????????895df08945f47905
         // 0042014d: dec esi
         // 0042014e: lea ecx, ds:[esi+0x1]
         // 00420151: mov eax, ecx
         // 00420153: cdq 
         // 00420154: and edx, 0x1f
         // 00420157: add eax, edx
         // 00420159: sar eax, b1 0x5
         // 0042015c: mov edx, ecx
         // 0042015e: and edx, 0xffffffff8000001f
         // 00420164: mov ss:[ebp+0xfffffffffffffff0], ebx
         // 00420167: mov ss:[ebp+0xfffffffffffffff4], eax
         // 0042016a: jns 0x420171
      [-]4a83cae042
         // 011b9ea7: dec edx
         // 011b9ea8: or edx, 0xffffffffffffffe0
         // 011b9eab: inc edx
      [-]8d7c85e06a1f33c0592bca40d3e0894df885070f848d000000
         // 011b9eac: lea edi, ss:[ebp+eax*0x4]
         // 011b9eb0: push 0x1f
         // 011b9eb2: xor eax, eax
         // 011b9eb4: pop ecx
         // 011b9eb5: sub ecx, edx
         // 011b9eb7: inc eax
         // 011b9eb8: shl eax, b1 cl
         // 011b9eba: mov ss:[ebp+0xfffffffffffffff8], ecx
         // 011b9ebd: test ds:[edi], eax
         // 011b9ebf: jz 0x11b9f52
      [-]8b45f483caffd3e2f7d2855485e0eb05
         // 011b9ec5: mov eax, ss:[ebp+0xfffffffffffffff4]
         // 011b9ec8: or edx, 0xffffffffffffffff
         // 011b9ecb: shl edx, b1 cl
         // 011b9ecd: not edx
         // 011b9ecf: test ss:[ebp+eax*0x4], edx
         // 011b9ed3: jmp 0x11b9eda
      [-]837c85e000
         // 011b9ed5: cmp ss:[ebp+eax*0x4], 0x0
      [-]4083f8037cf3
         // 011b9edc: inc eax
         // 011b9edd: cmp eax, 0x3
         // 011b9ee0: jl 0x11b9ed5
      [-]8bc6996a1f5923d103c2c1f80581e6????????7905
         // 011b9ee4: mov eax, esi
         // 011b9ee6: cdq 
         // 011b9ee7: push 0x1f
         // 011b9ee9: pop ecx
         // 011b9eea: and edx, ecx
         // 011b9eec: add eax, edx
         // 011b9eee: sar eax, b1 0x5
         // 011b9ef1: and esi, 0xffffffff8000001f
         // 011b9ef7: jns 0x11b9efe
      [-]4e83cee046
         // 011b9ef9: dec esi
         // 011b9efa: or esi, 0xffffffffffffffe0
         // 011b9efd: inc esi
      [-]8365fc002bce33d242d3e28d4c85e08b3103f28975088b313975087222
         // 011b9efe: and ss:[ebp+0xfffffffffffffffc], 0x0
         // 011b9f02: sub ecx, esi
         // 011b9f04: xor edx, edx
         // 011b9f06: inc edx
         // 011b9f07: shl edx, b1 cl
         // 011b9f09: lea ecx, ss:[ebp+eax*0x4]
         // 011b9f0d: mov esi, ds:[ecx]
         // 011b9f0f: add esi, edx
         // 011b9f11: mov ss:[ebp+0x8], esi
         // 011b9f14: mov esi, ds:[ecx]
         // 011b9f16: cmp ss:[ebp+0x8], esi
         // 011b9f19: jb 0x11b9f3d
      [-]395508eb1b
         // 011b9f1b: cmp ss:[ebp+0x8], edx
         // 011b9f1e: jmp 0x11b9f3b
      [-]85c9742b
         // 011b9f20: test ecx, ecx
         // 011b9f22: jz 0x11b9f4f
      [-]8365fc008d4c85e08b118d7201
         // 004201e9: and ss:[ebp+0xfffffffffffffffc], 0x0
         // 004201ed: lea ecx, ss:[ebp+eax*0x4]
         // 004201f1: mov edx, ds:[ecx]
         // 004201f3: lea esi, ds:[edx+0x1]
      [-]c745fc????????
         // 011b9f3d: mov ss:[ebp+0xfffffffffffffffc], 0x1
      [-]488b550889118b4dfc79d1
         // 011b9f44: dec eax
         // 011b9f45: mov edx, ss:[ebp+0x8]
         // 011b9f48: mov ds:[ecx], edx
         // 011b9f4a: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 011b9f4d: jns 0x11b9f20
      [-]8b4df883c8ffd3e021078b45f44083f8037d0d
         // 011b9f52: mov ecx, ss:[ebp+0xfffffffffffffff8]
         // 011b9f55: or eax, 0xffffffffffffffff
         // 011b9f58: shl eax, b1 cl
         // 011b9f5a: and ds:[edi], eax
         // 011b9f5c: mov eax, ss:[ebp+0xfffffffffffffff4]
         // 011b9f5f: inc eax
         // 011b9f60: cmp eax, 0x3
         // 011b9f63: jge 0x11b9f72
      [-]6a03598d7c85e02bc833c0f3ab
         // 011b9f65: push 0x3
         // 011b9f67: pop ecx
         // 011b9f68: lea edi, ss:[ebp+eax*0x4]
         // 011b9f6c: sub ecx, eax
         // 011b9f6e: xor eax, eax
         // 011b9f70: rep stosdd 
      [-]837d08007401
         // 011b9f72: cmp ss:[ebp+0x8], 0x0
         // 011b9f76: jz 0x11b9f79
      [-]8bc82b0d
         // 00420243: mov ecx, eax
         // 00420245: sub ecx, ds:[0x42c6f8]
      [-]3bd97d0d
         // 0042024b: cmp ebx, ecx
         // 0042024d: jge 0x42025c
      [-]33c08d7de0abababe90d020000
         // 011b9f8a: xor eax, eax
         // 011b9f8c: lea edi, ss:[ebp+0xffffffffffffffe0]
         // 011b9f8f: stosdd 
         // 011b9f90: stosdd 
         // 011b9f91: stosdd 
         // 011b9f92: jmp 0x11ba1a4
      [-]3bd80f8f0f020000
         // 011b9f97: cmp ebx, eax
         // 011b9f99: jg 0x11ba1ae
      [-]2b45f08d75d48bc88d7de0a59983e21f03c2a58bd1c1f80581e2????????a57905
         // 011b9f9f: sub eax, ss:[ebp+0xfffffffffffffff0]
         // 011b9fa2: lea esi, ss:[ebp+0xffffffffffffffd4]
         // 011b9fa5: mov ecx, eax
         // 011b9fa7: lea edi, ss:[ebp+0xffffffffffffffe0]
         // 011b9faa: movsdd 
         // 011b9fab: cdq 
         // 011b9fac: and edx, 0x1f
         // 011b9faf: add eax, edx
         // 011b9fb1: movsdd 
         // 011b9fb2: mov edx, ecx
         // 011b9fb4: sar eax, b1 0x5
         // 011b9fb7: and edx, 0xffffffff8000001f
         // 011b9fbd: movsdd 
         // 011b9fbe: jns 0x11b9fc5
      [-]4a83cae042
         // 011b9fc0: dec edx
         // 011b9fc1: or edx, 0xffffffffffffffe0
         // 011b9fc4: inc edx
      [-]8365f4008365080083cfff8bcad3e7c745fc????????2955fcf7d7
         // 011b9fc5: and ss:[ebp+0xfffffffffffffff4], 0x0
         // 011b9fc9: and ss:[ebp+0x8], 0x0
         // 011b9fcd: or edi, 0xffffffffffffffff
         // 011b9fd0: mov ecx, edx
         // 011b9fd2: shl edi, b1 cl
         // 011b9fd4: mov ss:[ebp+0xfffffffffffffffc], 0x20
         // 011b9fdb: sub ss:[ebp+0xfffffffffffffffc], edx
         // 011b9fde: not edi
      [-]8b5d088d5c9de08b338bce23cf894df08bcad3ee8b4dfc0b75f489338b75f0d3e6ff4508837d08038975f47cd3
         // 011b9fe0: mov ebx, ss:[ebp+0x8]
         // 011b9fe3: lea ebx, ss:[ebp+ebx*0x4]
         // 011b9fe7: mov esi, ds:[ebx]
         // 011b9fe9: mov ecx, esi
         // 011b9feb: and ecx, edi
         // 011b9fed: mov ss:[ebp+0xfffffffffffffff0], ecx
         // 011b9ff0: mov ecx, edx
         // 011b9ff2: shr esi, b1 cl
         // 011b9ff4: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 011b9ff7: or esi, ss:[ebp+0xfffffffffffffff4]
         // 011b9ffa: mov ds:[ebx], esi
         // 011b9ffc: mov esi, ss:[ebp+0xfffffffffffffff0]
         // 011b9fff: shl esi, b1 cl
         // 011ba001: inc ss:[ebp+0x8]
         // 011ba004: cmp ss:[ebp+0x8], 0x3
         // 011ba008: mov ss:[ebp+0xfffffffffffffff4], esi
         // 011ba00b: jl 0x11b9fe0
      [-]8bf06a02c1e6028d4de85a2bce
         // 011ba00d: mov esi, eax
         // 011ba00f: push 0x2
         // 011ba011: shl esi, b1 0x2
         // 011ba014: lea ecx, ss:[ebp+0xffffffffffffffe8]
         // 011ba017: pop edx
         // 011ba018: sub ecx, esi
      [-]3bd07c08
         // 011ba01a: cmp edx, eax
         // 011ba01c: jl 0x11ba026
      [-]8b31897495e0eb05
         // 011ba01e: mov esi, ds:[ecx]
         // 011ba020: mov ss:[ebp+edx*0x4], esi
         // 011ba024: jmp 0x11ba02b
      [-]836495e000
         // 011ba026: and ss:[ebp+edx*0x4], 0x0
      [-]4a83e90485d27de7
         // 011ba02b: dec edx
         // 011ba02c: sub ecx, 0x4
         // 011ba02f: test edx, edx
         // 011ba031: jge 0x11ba01a
      [-]4e8d4e018bc19983e21f03c2c1f8058bd181e2????????8945f47905
         // 004202fe: dec esi
         // 004202ff: lea ecx, ds:[esi+0x1]
         // 00420302: mov eax, ecx
         // 00420304: cdq 
         // 00420305: and edx, 0x1f
         // 00420308: add eax, edx
         // 0042030a: sar eax, b1 0x5
         // 0042030d: mov edx, ecx
         // 0042030f: and edx, 0xffffffff8000001f
         // 00420315: mov ss:[ebp+0xfffffffffffffff4], eax
         // 00420318: jns 0x42031f
      [-]4a83cae042
         // 011ba055: dec edx
         // 011ba056: or edx, 0xffffffffffffffe0
         // 011ba059: inc edx
      [-]6a1f592bca33d242d3e28d5c85e0894df085130f8482000000
         // 011ba05a: push 0x1f
         // 011ba05c: pop ecx
         // 011ba05d: sub ecx, edx
         // 011ba05f: xor edx, edx
         // 011ba061: inc edx
         // 011ba062: shl edx, b1 cl
         // 011ba064: lea ebx, ss:[ebp+eax*0x4]
         // 011ba068: mov ss:[ebp+0xfffffffffffffff0], ecx
         // 011ba06b: test ds:[ebx], edx
         // 011ba06d: jz 0x11ba0f5
      [-]83caffd3e2f7d2855485e0eb05
         // 011ba073: or edx, 0xffffffffffffffff
         // 011ba076: shl edx, b1 cl
         // 011ba078: not edx
         // 011ba07a: test ss:[ebp+eax*0x4], edx
         // 011ba07e: jmp 0x11ba085
      [-]837c85e000
         // 011ba080: cmp ss:[ebp+eax*0x4], 0x0
      [-]4083f8037cf3
         // 011ba087: inc eax
         // 011ba088: cmp eax, 0x3
         // 011ba08b: jl 0x11ba080
      [-]8bc6996a1f5923d103c2c1f80581e6????????7905
         // 011ba08f: mov eax, esi
         // 011ba091: cdq 
         // 011ba092: push 0x1f
         // 011ba094: pop ecx
         // 011ba095: and edx, ecx
         // 011ba097: add eax, edx
         // 011ba099: sar eax, b1 0x5
         // 011ba09c: and esi, 0xffffffff8000001f
         // 011ba0a2: jns 0x11ba0a9
      [-]4e83cee046
         // 011ba0a4: dec esi
         // 011ba0a5: or esi, 0xffffffffffffffe0
         // 011ba0a8: inc esi
      [-]8365080033d22bce42d3e28d4c85e08b318d3c163bfe7204
         // 011ba0a9: and ss:[ebp+0x8], 0x0
         // 011ba0ad: xor edx, edx
         // 011ba0af: sub ecx, esi
         // 011ba0b1: inc edx
         // 011ba0b2: shl edx, b1 cl
         // 011ba0b4: lea ecx, ss:[ebp+eax*0x4]
         // 011ba0b8: mov esi, ds:[ecx]
         // 011ba0ba: lea edi, ds:[esi+edx]
         // 011ba0bd: cmp edi, esi
         // 011ba0bf: jb 0x11ba0c5
      [-]3bfa7307
         // 011ba0c1: cmp edi, edx
         // 011ba0c3: jnb 0x11ba0cc
      [-]c74508????????
         // 011ba0c5: mov ss:[ebp+0x8], 0x1
      [-]89398b4d08eb1f
         // 011ba0cc: mov ds:[ecx], edi
         // 011ba0ce: mov ecx, ss:[ebp+0x8]
         // 011ba0d1: jmp 0x11ba0f2
      [-]85c9741e
         // 011ba0d3: test ecx, ecx
         // 011ba0d5: jz 0x11ba0f5
      [-]8d4c85e08b118d720133ff3bf27205
         // 011ba0d7: lea ecx, ss:[ebp+eax*0x4]
         // 011ba0db: mov edx, ds:[ecx]
         // 011ba0dd: lea esi, ds:[edx+0x1]
         // 011ba0e0: xor edi, edi
         // 011ba0e2: cmp esi, edx
         // 011ba0e4: jb 0x11ba0eb
      [-]83fe017303
         // 011ba0e6: cmp esi, 0x1
         // 011ba0e9: jnb 0x11ba0ee
      [-]89318bcf
         // 011ba0ee: mov ds:[ecx], esi
         // 011ba0f0: mov ecx, edi
      [-]8b4df083c8ffd3e021038b45f44083f8037d0d
         // 011ba0f5: mov ecx, ss:[ebp+0xfffffffffffffff0]
         // 011ba0f8: or eax, 0xffffffffffffffff
         // 011ba0fb: shl eax, b1 cl
         // 011ba0fd: and ds:[ebx], eax
         // 011ba0ff: mov eax, ss:[ebp+0xfffffffffffffff4]
         // 011ba102: inc eax
         // 011ba103: cmp eax, 0x3
         // 011ba106: jge 0x11ba115
      [-]6a03598d7c85e02bc833c0f3ab
         // 011ba108: push 0x3
         // 011ba10a: pop ecx
         // 011ba10b: lea edi, ss:[ebp+eax*0x4]
         // 011ba10f: sub ecx, eax
         // 011ba111: xor eax, eax
         // 011ba113: rep stosdd 
      [-]418bc19983e21f03c28bd1c1f80581e2????????7905
         // 011ba11b: inc ecx
         // 011ba11c: mov eax, ecx
         // 011ba11e: cdq 
         // 011ba11f: and edx, 0x1f
         // 011ba122: add eax, edx
         // 011ba124: mov edx, ecx
         // 011ba126: sar eax, b1 0x5
         // 011ba129: and edx, 0xffffffff8000001f
         // 011ba12f: jns 0x11ba136
      [-]4a83cae042
         // 011ba131: dec edx
         // 011ba132: or edx, 0xffffffffffffffe0
         // 011ba135: inc edx
      [-]8365f4008365080083cfff8bcad3e7c745fc????????2955fcf7d7
         // 011ba136: and ss:[ebp+0xfffffffffffffff4], 0x0
         // 011ba13a: and ss:[ebp+0x8], 0x0
         // 011ba13e: or edi, 0xffffffffffffffff
         // 011ba141: mov ecx, edx
         // 011ba143: shl edi, b1 cl
         // 011ba145: mov ss:[ebp+0xfffffffffffffffc], 0x20
         // 011ba14c: sub ss:[ebp+0xfffffffffffffffc], edx
         // 011ba14f: not edi
      [-]8b5d088d5c9de08b338bce23cf894df08bcad3ee8b4dfc0b75f489338b75f0d3e6ff4508837d08038975f47cd3
         // 011ba151: mov ebx, ss:[ebp+0x8]
         // 011ba154: lea ebx, ss:[ebp+ebx*0x4]
         // 011ba158: mov esi, ds:[ebx]
         // 011ba15a: mov ecx, esi
         // 011ba15c: and ecx, edi
         // 011ba15e: mov ss:[ebp+0xfffffffffffffff0], ecx
         // 011ba161: mov ecx, edx
         // 011ba163: shr esi, b1 cl
         // 011ba165: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 011ba168: or esi, ss:[ebp+0xfffffffffffffff4]
         // 011ba16b: mov ds:[ebx], esi
         // 011ba16d: mov esi, ss:[ebp+0xfffffffffffffff0]
         // 011ba170: shl esi, b1 cl
         // 011ba172: inc ss:[ebp+0x8]
         // 011ba175: cmp ss:[ebp+0x8], 0x3
         // 011ba179: mov ss:[ebp+0xfffffffffffffff4], esi
         // 011ba17c: jl 0x11ba151
      [-]8bf06a02c1e6028d4de85a2bce
         // 011ba17e: mov esi, eax
         // 011ba180: push 0x2
         // 011ba182: shl esi, b1 0x2
         // 011ba185: lea ecx, ss:[ebp+0xffffffffffffffe8]
         // 011ba188: pop edx
         // 011ba189: sub ecx, esi
      [-]3bd07c08
         // 011ba18b: cmp edx, eax
         // 011ba18d: jl 0x11ba197
      [-]8b31897495e0eb05
         // 011ba18f: mov esi, ds:[ecx]
         // 011ba191: mov ss:[ebp+edx*0x4], esi
         // 011ba195: jmp 0x11ba19c
      [-]836495e000
         // 011ba197: and ss:[ebp+edx*0x4], 0x0
      [-]4a83e90485d27de7
         // 011ba19c: dec edx
         // 011ba19d: sub ecx, 0x4
         // 011ba1a0: test edx, edx
         // 011ba1a2: jge 0x11ba18b
      [-]6a0233db58e95a010000
         // 011ba1a4: push 0x2
         // 011ba1a6: xor ebx, ebx
         // 011ba1a8: pop eax
         // 011ba1a9: jmp 0x11ba308
      [-]0f8cad000000
         // 011ba1ba: jl 0x11ba26d
      [-]33c08d7de0ababab814de0????????8bc19983e21f03c28bd1c1f80581e2????????7905
         // 011ba1c0: xor eax, eax
         // 011ba1c2: lea edi, ss:[ebp+0xffffffffffffffe0]
         // 011ba1c5: stosdd 
         // 011ba1c6: stosdd 
         // 011ba1c7: stosdd 
         // 011ba1c8: or ss:[ebp+0xffffffffffffffe0], 0xffffffff80000000
         // 011ba1cf: mov eax, ecx
         // 011ba1d1: cdq 
         // 011ba1d2: and edx, 0x1f
         // 011ba1d5: add eax, edx
         // 011ba1d7: mov edx, ecx
         // 011ba1d9: sar eax, b1 0x5
         // 011ba1dc: and edx, 0xffffffff8000001f
         // 011ba1e2: jns 0x11ba1e9
      [-]4a83cae042
         // 011ba1e4: dec edx
         // 011ba1e5: or edx, 0xffffffffffffffe0
         // 011ba1e8: inc edx
      [-]8365f4008365080083cfff8bcad3e7c745fc????????2955fcf7d7
         // 011ba1e9: and ss:[ebp+0xfffffffffffffff4], 0x0
         // 011ba1ed: and ss:[ebp+0x8], 0x0
         // 011ba1f1: or edi, 0xffffffffffffffff
         // 011ba1f4: mov ecx, edx
         // 011ba1f6: shl edi, b1 cl
         // 011ba1f8: mov ss:[ebp+0xfffffffffffffffc], 0x20
         // 011ba1ff: sub ss:[ebp+0xfffffffffffffffc], edx
         // 011ba202: not edi
      [-]8b5d088d5c9de08b338bce23cf894df08bcad3ee8b4dfc0b75f489338b75f0d3e6ff4508837d08038975f47cd3
         // 011ba204: mov ebx, ss:[ebp+0x8]
         // 011ba207: lea ebx, ss:[ebp+ebx*0x4]
         // 011ba20b: mov esi, ds:[ebx]
         // 011ba20d: mov ecx, esi
         // 011ba20f: and ecx, edi
         // 011ba211: mov ss:[ebp+0xfffffffffffffff0], ecx
         // 011ba214: mov ecx, edx
         // 011ba216: shr esi, b1 cl
         // 011ba218: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 011ba21b: or esi, ss:[ebp+0xfffffffffffffff4]
         // 011ba21e: mov ds:[ebx], esi
         // 011ba220: mov esi, ss:[ebp+0xfffffffffffffff0]
         // 011ba223: shl esi, b1 cl
         // 011ba225: inc ss:[ebp+0x8]
         // 011ba228: cmp ss:[ebp+0x8], 0x3
         // 011ba22c: mov ss:[ebp+0xfffffffffffffff4], esi
         // 011ba22f: jl 0x11ba204
      [-]8bf06a02c1e6028d4de85a2bce
         // 011ba231: mov esi, eax
         // 011ba233: push 0x2
         // 011ba235: shl esi, b1 0x2
         // 011ba238: lea ecx, ss:[ebp+0xffffffffffffffe8]
         // 011ba23b: pop edx
         // 011ba23c: sub ecx, esi
      [-]3bd07c08
         // 011ba23e: cmp edx, eax
         // 011ba240: jl 0x11ba24a
      [-]8b31897495e0eb05
         // 011ba242: mov esi, ds:[ecx]
         // 011ba244: mov ss:[ebp+edx*0x4], esi
         // 011ba248: jmp 0x11ba24f
      [-]836495e000
         // 011ba24a: and ss:[ebp+edx*0x4], 0x0
      [-]4a83e90485d27de7
         // 011ba24f: dec edx
         // 011ba250: sub ecx, 0x4
         // 011ba253: test edx, edx
         // 011ba255: jge 0x11ba23e
      [-]8d1c0133c040e99b000000
         // 00420527: lea ebx, ds:[ecx+eax]
         // 0042052a: xor eax, eax
         // 0042052c: inc eax
         // 0042052d: jmp 0x4205cd
      [-]8165????????7f03d88bc19983e21f03c28bd1c1f80581e2????????7905
         // 00420537: and ss:[ebp+0xffffffffffffffe0], 0x7fffffff
         // 0042053e: add ebx, eax
         // 00420540: mov eax, ecx
         // 00420542: cdq 
         // 00420543: and edx, 0x1f
         // 00420546: add eax, edx
         // 00420548: mov edx, ecx
         // 0042054a: sar eax, b1 0x5
         // 0042054d: and edx, 0xffffffff8000001f
         // 00420553: jns 0x42055a
      [-]4a83cae042
         // 011ba290: dec edx
         // 011ba291: or edx, 0xffffffffffffffe0
         // 011ba294: inc edx
      [-]8365f4008365080083ceff8bcad3e6c745fc????????2955fcf7d6
         // 011ba295: and ss:[ebp+0xfffffffffffffff4], 0x0
         // 011ba299: and ss:[ebp+0x8], 0x0
         // 011ba29d: or esi, 0xffffffffffffffff
         // 011ba2a0: mov ecx, edx
         // 011ba2a2: shl esi, b1 cl
         // 011ba2a4: mov ss:[ebp+0xfffffffffffffffc], 0x20
         // 011ba2ab: sub ss:[ebp+0xfffffffffffffffc], edx
         // 011ba2ae: not esi
      [-]8b4d088b7c8de08bcf23ce894df08bcad3ef8b4d080b7df4897c8de08b7df08b4dfcd3e7ff4508837d0803897df47cd0
         // 011ba2b0: mov ecx, ss:[ebp+0x8]
         // 011ba2b3: mov edi, ss:[ebp+ecx*0x4]
         // 011ba2b7: mov ecx, edi
         // 011ba2b9: and ecx, esi
         // 011ba2bb: mov ss:[ebp+0xfffffffffffffff0], ecx
         // 011ba2be: mov ecx, edx
         // 011ba2c0: shr edi, b1 cl
         // 011ba2c2: mov ecx, ss:[ebp+0x8]
         // 011ba2c5: or edi, ss:[ebp+0xfffffffffffffff4]
         // 011ba2c8: mov ss:[ebp+ecx*0x4], edi
         // 011ba2cc: mov edi, ss:[ebp+0xfffffffffffffff0]
         // 011ba2cf: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 011ba2d2: shl edi, b1 cl
         // 011ba2d4: inc ss:[ebp+0x8]
         // 011ba2d7: cmp ss:[ebp+0x8], 0x3
         // 011ba2db: mov ss:[ebp+0xfffffffffffffff4], edi
         // 011ba2de: jl 0x11ba2b0
      [-]8bf06a02c1e6028d4de85a2bce
         // 011ba2e0: mov esi, eax
         // 011ba2e2: push 0x2
         // 011ba2e4: shl esi, b1 0x2
         // 011ba2e7: lea ecx, ss:[ebp+0xffffffffffffffe8]
         // 011ba2ea: pop edx
         // 011ba2eb: sub ecx, esi
      [-]3bd07c08
         // 011ba2ed: cmp edx, eax
         // 011ba2ef: jl 0x11ba2f9
      [-]8b31897495e0eb05
         // 011ba2f1: mov esi, ds:[ecx]
         // 011ba2f3: mov ss:[ebp+edx*0x4], esi
         // 011ba2f7: jmp 0x11ba2fe
      [-]836495e000
         // 011ba2f9: and ss:[ebp+edx*0x4], 0x0
      [-]4a83e90485d27de7
         // 011ba2fe: dec edx
         // 011ba2ff: sub ecx, 0x4
         // 011ba302: test edx, edx
         // 011ba304: jge 0x11ba2ed
      [-]6a1f592b0d
         // 00426329: push 0x1f
         // 0042632b: pop ecx
         // 0042632c: sub ecx, ds:[0x433c9c]
      [-]d3e38b4decf7d91bc981e1????????0bd98b0d
         // 00426332: shl ebx, b1 cl
         // 00426334: mov ecx, ss:[ebp+0xffffffffffffffec]
         // 00426337: neg ecx
         // 00426339: sbb ecx, ecx
         // 0042633b: and ecx, 0xffffffff80000000
         // 00426341: or ebx, ecx
         // 00426343: mov ecx, ds:[0x433ca0]
      [-]0b5de083f940750d
         // 00426349: or ebx, ss:[ebp+0xffffffffffffffe0]
         // 0042634c: cmp ecx, 0x40
         // 0042634f: jnz 0x42635e
      [-]8b4d0c8b55e48959048911eb0a
         // 011ba331: mov ecx, ss:[ebp+0xc]
         // 011ba334: mov edx, ss:[ebp+0xffffffffffffffe4]
         // 011ba337: mov ds:[ecx+0x4], ebx
         // 011ba33a: mov ds:[ecx], edx
         // 011ba33c: jmp 0x11ba348
      [-]83f9207505
         // 011ba33e: cmp ecx, 0x20
         // 011ba341: jnz 0x11ba348
      [-]8b4d0c8919
         // 011ba343: mov ecx, ss:[ebp+0xc]
         // 011ba346: mov ds:[ecx], ebx
      [-]5f5bc9c3
         // 011ba348: pop edi
         // 011ba349: pop ebx
         // 011ba34a: leave 
         // 011ba34b: retn 
      [-]558bec83ec2c8b45080fb7480a538bd981e1????????894dec8b4806894de08b48020fb70081e3????????81eb????????c1e01057894de48945e8
         // 00420611: push ebp
         // 00420612: mov ebp, esp
         // 00420614: sub esp, 0x2c
         // 00420617: mov eax, ss:[ebp+0x8]
         // 0042061a: movzx ecx, b2 ds:[eax+0xa]
         // 0042061e: push ebx
         // 0042061f: mov ebx, ecx
         // 00420621: and ecx, 0x8000
         // 00420627: mov ss:[ebp+0xffffffffffffffec], ecx
         // 0042062a: mov ecx, ds:[eax+0x6]
         // 0042062d: mov ss:[ebp+0xffffffffffffffe0], ecx
         // 00420630: mov ecx, ds:[eax+0x2]
         // 00420633: movzx eax, b2 ds:[eax]
         // 00420636: and ebx, 0x7fff
         // 0042063c: sub ebx, 0x3fff
         // 00420642: shl eax, b1 0x10
         // 0042064b: push edi
         // 0042064c: mov ss:[ebp+0xffffffffffffffe4], ecx
         // 0042064f: mov ss:[ebp+0xffffffffffffffe8], eax
      [-]33db33c0
         // 011ba391: xor ebx, ebx
         // 011ba393: xor eax, eax
      [-]395c85e0750d
         // 011ba395: cmp ss:[ebp+eax*0x4], ebx
         // 011ba399: jnz 0x11ba3a8
      [-]4083f8037cf4
         // 011ba39b: inc eax
         // 011ba39c: cmp eax, 0x3
         // 011ba39f: jl 0x11ba395
      [-]33c0e9a5040000
         // 011ba3a1: xor eax, eax
         // 011ba3a3: jmp 0x11ba84d
      [-]33c08d7de0abab6a02ab58e995040000
         // 011ba3a8: xor eax, eax
         // 011ba3aa: lea edi, ss:[ebp+0xffffffffffffffe0]
         // 011ba3ad: stosdd 
         // 011ba3ae: stosdd 
         // 011ba3af: push 0x2
         // 011ba3b1: stosdd 
         // 011ba3b2: pop eax
         // 011ba3b3: jmp 0x11ba84d
      [-]83650800568d75e08d7dd4a5a5a58b35
         // 011ba3b8: and ss:[ebp+0x8], 0x0
         // 011ba3bc: push esi
         // 011ba3bd: lea esi, ss:[ebp+0xffffffffffffffe0]
         // 011ba3c0: lea edi, ss:[ebp+0xffffffffffffffd4]
         // 011ba3c3: movsdd 
         // 011ba3c4: movsdd 
         // 011ba3c5: movsdd 
         // 011ba3c6: mov esi, ds:[0x11c8cb0]
      [-]4e8d4e018bc19983e21f03c2c1f8058bd181e2????????895df08945f47905
         // 011ba3cc: dec esi
         // 011ba3cd: lea ecx, ds:[esi+0x1]
         // 011ba3d0: mov eax, ecx
         // 011ba3d2: cdq 
         // 011ba3d3: and edx, 0x1f
         // 011ba3d6: add eax, edx
         // 011ba3d8: sar eax, b1 0x5
         // 011ba3db: mov edx, ecx
         // 011ba3dd: and edx, 0xffffffff8000001f
         // 011ba3e3: mov ss:[ebp+0xfffffffffffffff0], ebx
         // 011ba3e6: mov ss:[ebp+0xfffffffffffffff4], eax
         // 011ba3e9: jns 0x11ba3f0
      [-]4a83cae042
         // 011ba3eb: dec edx
         // 011ba3ec: or edx, 0xffffffffffffffe0
         // 011ba3ef: inc edx
      [-]8d7c85e06a1f33c0592bca40d3e0894df885070f848d000000
         // 011ba3f0: lea edi, ss:[ebp+eax*0x4]
         // 011ba3f4: push 0x1f
         // 011ba3f6: xor eax, eax
         // 011ba3f8: pop ecx
         // 011ba3f9: sub ecx, edx
         // 011ba3fb: inc eax
         // 011ba3fc: shl eax, b1 cl
         // 011ba3fe: mov ss:[ebp+0xfffffffffffffff8], ecx
         // 011ba401: test ds:[edi], eax
         // 011ba403: jz 0x11ba496
      [-]8b45f483caffd3e2f7d2855485e0eb05
         // 011ba409: mov eax, ss:[ebp+0xfffffffffffffff4]
         // 011ba40c: or edx, 0xffffffffffffffff
         // 011ba40f: shl edx, b1 cl
         // 011ba411: not edx
         // 011ba413: test ss:[ebp+eax*0x4], edx
         // 011ba417: jmp 0x11ba41e
      [-]837c85e000
         // 011ba419: cmp ss:[ebp+eax*0x4], 0x0
      [-]4083f8037cf3
         // 011ba420: inc eax
         // 011ba421: cmp eax, 0x3
         // 011ba424: jl 0x11ba419
      [-]8bc6996a1f5923d103c2c1f80581e6????????7905
         // 011ba428: mov eax, esi
         // 011ba42a: cdq 
         // 011ba42b: push 0x1f
         // 011ba42d: pop ecx
         // 011ba42e: and edx, ecx
         // 011ba430: add eax, edx
         // 011ba432: sar eax, b1 0x5
         // 011ba435: and esi, 0xffffffff8000001f
         // 011ba43b: jns 0x11ba442
      [-]4e83cee046
         // 011ba43d: dec esi
         // 011ba43e: or esi, 0xffffffffffffffe0
         // 011ba441: inc esi
      [-]8365fc002bce33d242d3e28d4c85e08b3103f28975088b313975087222
         // 011ba442: and ss:[ebp+0xfffffffffffffffc], 0x0
         // 011ba446: sub ecx, esi
         // 011ba448: xor edx, edx
         // 011ba44a: inc edx
         // 011ba44b: shl edx, b1 cl
         // 011ba44d: lea ecx, ss:[ebp+eax*0x4]
         // 011ba451: mov esi, ds:[ecx]
         // 011ba453: add esi, edx
         // 011ba455: mov ss:[ebp+0x8], esi
         // 011ba458: mov esi, ds:[ecx]
         // 011ba45a: cmp ss:[ebp+0x8], esi
         // 011ba45d: jb 0x11ba481
      [-]395508eb1b
         // 011ba45f: cmp ss:[ebp+0x8], edx
         // 011ba462: jmp 0x11ba47f
      [-]85c9742b
         // 011ba464: test ecx, ecx
         // 011ba466: jz 0x11ba493
      [-]8365fc008d4c85e08b118d7201
         // 0042072b: and ss:[ebp+0xfffffffffffffffc], 0x0
         // 0042072f: lea ecx, ss:[ebp+eax*0x4]
         // 00420733: mov edx, ds:[ecx]
         // 00420735: lea esi, ds:[edx+0x1]
      [-]c745fc????????
         // 011ba481: mov ss:[ebp+0xfffffffffffffffc], 0x1
      [-]488b550889118b4dfc79d1
         // 011ba488: dec eax
         // 011ba489: mov edx, ss:[ebp+0x8]
         // 011ba48c: mov ds:[ecx], edx
         // 011ba48e: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 011ba491: jns 0x11ba464
      [-]8b4df883c8ffd3e021078b45f44083f8037d0d
         // 011ba496: mov ecx, ss:[ebp+0xfffffffffffffff8]
         // 011ba499: or eax, 0xffffffffffffffff
         // 011ba49c: shl eax, b1 cl
         // 011ba49e: and ds:[edi], eax
         // 011ba4a0: mov eax, ss:[ebp+0xfffffffffffffff4]
         // 011ba4a3: inc eax
         // 011ba4a4: cmp eax, 0x3
         // 011ba4a7: jge 0x11ba4b6
      [-]6a03598d7c85e02bc833c0f3ab
         // 011ba4a9: push 0x3
         // 011ba4ab: pop ecx
         // 011ba4ac: lea edi, ss:[ebp+eax*0x4]
         // 011ba4b0: sub ecx, eax
         // 011ba4b2: xor eax, eax
         // 011ba4b4: rep stosdd 
      [-]837d08007401
         // 011ba4b6: cmp ss:[ebp+0x8], 0x0
         // 011ba4ba: jz 0x11ba4bd
      [-]8bc82b0d
         // 00420785: mov ecx, eax
         // 00420787: sub ecx, ds:[0x42c710]
      [-]3bd97d0d
         // 0042078d: cmp ebx, ecx
         // 0042078f: jge 0x42079e
      [-]33c08d7de0abababe90d020000
         // 011ba4ce: xor eax, eax
         // 011ba4d0: lea edi, ss:[ebp+0xffffffffffffffe0]
         // 011ba4d3: stosdd 
         // 011ba4d4: stosdd 
         // 011ba4d5: stosdd 
         // 011ba4d6: jmp 0x11ba6e8
      [-]3bd80f8f0f020000
         // 011ba4db: cmp ebx, eax
         // 011ba4dd: jg 0x11ba6f2
      [-]2b45f08d75d48bc88d7de0a59983e21f03c2a58bd1c1f80581e2????????a57905
         // 011ba4e3: sub eax, ss:[ebp+0xfffffffffffffff0]
         // 011ba4e6: lea esi, ss:[ebp+0xffffffffffffffd4]
         // 011ba4e9: mov ecx, eax
         // 011ba4eb: lea edi, ss:[ebp+0xffffffffffffffe0]
         // 011ba4ee: movsdd 
         // 011ba4ef: cdq 
         // 011ba4f0: and edx, 0x1f
         // 011ba4f3: add eax, edx
         // 011ba4f5: movsdd 
         // 011ba4f6: mov edx, ecx
         // 011ba4f8: sar eax, b1 0x5
         // 011ba4fb: and edx, 0xffffffff8000001f
         // 011ba501: movsdd 
         // 011ba502: jns 0x11ba509
      [-]4a83cae042
         // 011ba504: dec edx
         // 011ba505: or edx, 0xffffffffffffffe0
         // 011ba508: inc edx
      [-]8365f4008365080083cfff8bcad3e7c745fc????????2955fcf7d7
         // 011ba509: and ss:[ebp+0xfffffffffffffff4], 0x0
         // 011ba50d: and ss:[ebp+0x8], 0x0
         // 011ba511: or edi, 0xffffffffffffffff
         // 011ba514: mov ecx, edx
         // 011ba516: shl edi, b1 cl
         // 011ba518: mov ss:[ebp+0xfffffffffffffffc], 0x20
         // 011ba51f: sub ss:[ebp+0xfffffffffffffffc], edx
         // 011ba522: not edi
      [-]8b5d088d5c9de08b338bce23cf894df08bcad3ee8b4dfc0b75f489338b75f0d3e6ff4508837d08038975f47cd3
         // 011ba524: mov ebx, ss:[ebp+0x8]
         // 011ba527: lea ebx, ss:[ebp+ebx*0x4]
         // 011ba52b: mov esi, ds:[ebx]
         // 011ba52d: mov ecx, esi
         // 011ba52f: and ecx, edi
         // 011ba531: mov ss:[ebp+0xfffffffffffffff0], ecx
         // 011ba534: mov ecx, edx
         // 011ba536: shr esi, b1 cl
         // 011ba538: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 011ba53b: or esi, ss:[ebp+0xfffffffffffffff4]
         // 011ba53e: mov ds:[ebx], esi
         // 011ba540: mov esi, ss:[ebp+0xfffffffffffffff0]
         // 011ba543: shl esi, b1 cl
         // 011ba545: inc ss:[ebp+0x8]
         // 011ba548: cmp ss:[ebp+0x8], 0x3
         // 011ba54c: mov ss:[ebp+0xfffffffffffffff4], esi
         // 011ba54f: jl 0x11ba524
      [-]8bf06a02c1e6028d4de85a2bce
         // 011ba551: mov esi, eax
         // 011ba553: push 0x2
         // 011ba555: shl esi, b1 0x2
         // 011ba558: lea ecx, ss:[ebp+0xffffffffffffffe8]
         // 011ba55b: pop edx
         // 011ba55c: sub ecx, esi
      [-]3bd07c08
         // 011ba55e: cmp edx, eax
         // 011ba560: jl 0x11ba56a
      [-]8b31897495e0eb05
         // 011ba562: mov esi, ds:[ecx]
         // 011ba564: mov ss:[ebp+edx*0x4], esi
         // 011ba568: jmp 0x11ba56f
      [-]836495e000
         // 011ba56a: and ss:[ebp+edx*0x4], 0x0
      [-]4a83e90485d27de7
         // 011ba56f: dec edx
         // 011ba570: sub ecx, 0x4
         // 011ba573: test edx, edx
         // 011ba575: jge 0x11ba55e
      [-]4e8d4e018bc19983e21f03c2c1f8058bd181e2????????8945f47905
         // 011ba57d: dec esi
         // 011ba57e: lea ecx, ds:[esi+0x1]
         // 011ba581: mov eax, ecx
         // 011ba583: cdq 
         // 011ba584: and edx, 0x1f
         // 011ba587: add eax, edx
         // 011ba589: sar eax, b1 0x5
         // 011ba58c: mov edx, ecx
         // 011ba58e: and edx, 0xffffffff8000001f
         // 011ba594: mov ss:[ebp+0xfffffffffffffff4], eax
         // 011ba597: jns 0x11ba59e
      [-]4a83cae042
         // 011ba599: dec edx
         // 011ba59a: or edx, 0xffffffffffffffe0
         // 011ba59d: inc edx
      [-]6a1f592bca33d242d3e28d5c85e0894df085130f8482000000
         // 011ba59e: push 0x1f
         // 011ba5a0: pop ecx
         // 011ba5a1: sub ecx, edx
         // 011ba5a3: xor edx, edx
         // 011ba5a5: inc edx
         // 011ba5a6: shl edx, b1 cl
         // 011ba5a8: lea ebx, ss:[ebp+eax*0x4]
         // 011ba5ac: mov ss:[ebp+0xfffffffffffffff0], ecx
         // 011ba5af: test ds:[ebx], edx
         // 011ba5b1: jz 0x11ba639
      [-]83caffd3e2f7d2855485e0eb05
         // 011ba5b7: or edx, 0xffffffffffffffff
         // 011ba5ba: shl edx, b1 cl
         // 011ba5bc: not edx
         // 011ba5be: test ss:[ebp+eax*0x4], edx
         // 011ba5c2: jmp 0x11ba5c9
      [-]837c85e000
         // 011ba5c4: cmp ss:[ebp+eax*0x4], 0x0
      [-]4083f8037cf3
         // 011ba5cb: inc eax
         // 011ba5cc: cmp eax, 0x3
         // 011ba5cf: jl 0x11ba5c4
      [-]8bc6996a1f5923d103c2c1f80581e6????????7905
         // 011ba5d3: mov eax, esi
         // 011ba5d5: cdq 
         // 011ba5d6: push 0x1f
         // 011ba5d8: pop ecx
         // 011ba5d9: and edx, ecx
         // 011ba5db: add eax, edx
         // 011ba5dd: sar eax, b1 0x5
         // 011ba5e0: and esi, 0xffffffff8000001f
         // 011ba5e6: jns 0x11ba5ed
      [-]4e83cee046
         // 011ba5e8: dec esi
         // 011ba5e9: or esi, 0xffffffffffffffe0
         // 011ba5ec: inc esi
      [-]8365080033d22bce42d3e28d4c85e08b318d3c163bfe7204
         // 011ba5ed: and ss:[ebp+0x8], 0x0
         // 011ba5f1: xor edx, edx
         // 011ba5f3: sub ecx, esi
         // 011ba5f5: inc edx
         // 011ba5f6: shl edx, b1 cl
         // 011ba5f8: lea ecx, ss:[ebp+eax*0x4]
         // 011ba5fc: mov esi, ds:[ecx]
         // 011ba5fe: lea edi, ds:[esi+edx]
         // 011ba601: cmp edi, esi
         // 011ba603: jb 0x11ba609
      [-]3bfa7307
         // 011ba605: cmp edi, edx
         // 011ba607: jnb 0x11ba610
      [-]c74508????????
         // 011ba609: mov ss:[ebp+0x8], 0x1
      [-]89398b4d08eb1f
         // 011ba610: mov ds:[ecx], edi
         // 011ba612: mov ecx, ss:[ebp+0x8]
         // 011ba615: jmp 0x11ba636
      [-]85c9741e
         // 011ba617: test ecx, ecx
         // 011ba619: jz 0x11ba639
      [-]8d4c85e08b118d720133ff3bf27205
         // 011ba61b: lea ecx, ss:[ebp+eax*0x4]
         // 011ba61f: mov edx, ds:[ecx]
         // 011ba621: lea esi, ds:[edx+0x1]
         // 011ba624: xor edi, edi
         // 011ba626: cmp esi, edx
         // 011ba628: jb 0x11ba62f
      [-]83fe017303
         // 011ba62a: cmp esi, 0x1
         // 011ba62d: jnb 0x11ba632
      [-]89318bcf
         // 011ba632: mov ds:[ecx], esi
         // 011ba634: mov ecx, edi
      [-]8b4df083c8ffd3e021038b45f44083f8037d0d
         // 011ba639: mov ecx, ss:[ebp+0xfffffffffffffff0]
         // 011ba63c: or eax, 0xffffffffffffffff
         // 011ba63f: shl eax, b1 cl
         // 011ba641: and ds:[ebx], eax
         // 011ba643: mov eax, ss:[ebp+0xfffffffffffffff4]
         // 011ba646: inc eax
         // 011ba647: cmp eax, 0x3
         // 011ba64a: jge 0x11ba659
      [-]6a03598d7c85e02bc833c0f3ab
         // 011ba64c: push 0x3
         // 011ba64e: pop ecx
         // 011ba64f: lea edi, ss:[ebp+eax*0x4]
         // 011ba653: sub ecx, eax
         // 011ba655: xor eax, eax
         // 011ba657: rep stosdd 
      [-]418bc19983e21f03c28bd1c1f80581e2????????7905
         // 00420922: inc ecx
         // 00420923: mov eax, ecx
         // 00420925: cdq 
         // 00420926: and edx, 0x1f
         // 00420929: add eax, edx
         // 0042092b: mov edx, ecx
         // 0042092d: sar eax, b1 0x5
         // 00420930: and edx, 0xffffffff8000001f
         // 00420936: jns 0x42093d
      [-]4a83cae042
         // 011ba675: dec edx
         // 011ba676: or edx, 0xffffffffffffffe0
         // 011ba679: inc edx
      [-]8365f4008365080083cfff8bcad3e7c745fc????????2955fcf7d7
         // 011ba67a: and ss:[ebp+0xfffffffffffffff4], 0x0
         // 011ba67e: and ss:[ebp+0x8], 0x0
         // 011ba682: or edi, 0xffffffffffffffff
         // 011ba685: mov ecx, edx
         // 011ba687: shl edi, b1 cl
         // 011ba689: mov ss:[ebp+0xfffffffffffffffc], 0x20
         // 011ba690: sub ss:[ebp+0xfffffffffffffffc], edx
         // 011ba693: not edi
      [-]8b5d088d5c9de08b338bce23cf894df08bcad3ee8b4dfc0b75f489338b75f0d3e6ff4508837d08038975f47cd3
         // 011ba695: mov ebx, ss:[ebp+0x8]
         // 011ba698: lea ebx, ss:[ebp+ebx*0x4]
         // 011ba69c: mov esi, ds:[ebx]
         // 011ba69e: mov ecx, esi
         // 011ba6a0: and ecx, edi
         // 011ba6a2: mov ss:[ebp+0xfffffffffffffff0], ecx
         // 011ba6a5: mov ecx, edx
         // 011ba6a7: shr esi, b1 cl
         // 011ba6a9: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 011ba6ac: or esi, ss:[ebp+0xfffffffffffffff4]
         // 011ba6af: mov ds:[ebx], esi
         // 011ba6b1: mov esi, ss:[ebp+0xfffffffffffffff0]
         // 011ba6b4: shl esi, b1 cl
         // 011ba6b6: inc ss:[ebp+0x8]
         // 011ba6b9: cmp ss:[ebp+0x8], 0x3
         // 011ba6bd: mov ss:[ebp+0xfffffffffffffff4], esi
         // 011ba6c0: jl 0x11ba695
      [-]8bf06a02c1e6028d4de85a2bce
         // 011ba6c2: mov esi, eax
         // 011ba6c4: push 0x2
         // 011ba6c6: shl esi, b1 0x2
         // 011ba6c9: lea ecx, ss:[ebp+0xffffffffffffffe8]
         // 011ba6cc: pop edx
         // 011ba6cd: sub ecx, esi
      [-]3bd07c08
         // 011ba6cf: cmp edx, eax
         // 011ba6d1: jl 0x11ba6db
      [-]8b31897495e0eb05
         // 011ba6d3: mov esi, ds:[ecx]
         // 011ba6d5: mov ss:[ebp+edx*0x4], esi
         // 011ba6d9: jmp 0x11ba6e0
      [-]836495e000
         // 011ba6db: and ss:[ebp+edx*0x4], 0x0
      [-]4a83e90485d27de7
         // 011ba6e0: dec edx
         // 011ba6e1: sub ecx, 0x4
         // 011ba6e4: test edx, edx
         // 011ba6e6: jge 0x11ba6cf
      [-]6a0233db58e95a010000
         // 011ba6e8: push 0x2
         // 011ba6ea: xor ebx, ebx
         // 011ba6ec: pop eax
         // 011ba6ed: jmp 0x11ba84c
      [-]0f8cad000000
         // 004209c1: jl 0x420a74
      [-]33c08d7de0ababab814de0????????8bc19983e21f03c28bd1c1f80581e2????????7905
         // 011ba704: xor eax, eax
         // 011ba706: lea edi, ss:[ebp+0xffffffffffffffe0]
         // 011ba709: stosdd 
         // 011ba70a: stosdd 
         // 011ba70b: stosdd 
         // 011ba70c: or ss:[ebp+0xffffffffffffffe0], 0xffffffff80000000
         // 011ba713: mov eax, ecx
         // 011ba715: cdq 
         // 011ba716: and edx, 0x1f
         // 011ba719: add eax, edx
         // 011ba71b: mov edx, ecx
         // 011ba71d: sar eax, b1 0x5
         // 011ba720: and edx, 0xffffffff8000001f
         // 011ba726: jns 0x11ba72d
      [-]4a83cae042
         // 011ba728: dec edx
         // 011ba729: or edx, 0xffffffffffffffe0
         // 011ba72c: inc edx
      [-]8365f4008365080083cfff8bcad3e7c745fc????????2955fcf7d7
         // 011ba72d: and ss:[ebp+0xfffffffffffffff4], 0x0
         // 011ba731: and ss:[ebp+0x8], 0x0
         // 011ba735: or edi, 0xffffffffffffffff
         // 011ba738: mov ecx, edx
         // 011ba73a: shl edi, b1 cl
         // 011ba73c: mov ss:[ebp+0xfffffffffffffffc], 0x20
         // 011ba743: sub ss:[ebp+0xfffffffffffffffc], edx
         // 011ba746: not edi
      [-]8b5d088d5c9de08b338bce23cf894df08bcad3ee8b4dfc0b75f489338b75f0d3e6ff4508837d08038975f47cd3
         // 011ba748: mov ebx, ss:[ebp+0x8]
         // 011ba74b: lea ebx, ss:[ebp+ebx*0x4]
         // 011ba74f: mov esi, ds:[ebx]
         // 011ba751: mov ecx, esi
         // 011ba753: and ecx, edi
         // 011ba755: mov ss:[ebp+0xfffffffffffffff0], ecx
         // 011ba758: mov ecx, edx
         // 011ba75a: shr esi, b1 cl
         // 011ba75c: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 011ba75f: or esi, ss:[ebp+0xfffffffffffffff4]
         // 011ba762: mov ds:[ebx], esi
         // 011ba764: mov esi, ss:[ebp+0xfffffffffffffff0]
         // 011ba767: shl esi, b1 cl
         // 011ba769: inc ss:[ebp+0x8]
         // 011ba76c: cmp ss:[ebp+0x8], 0x3
         // 011ba770: mov ss:[ebp+0xfffffffffffffff4], esi
         // 011ba773: jl 0x11ba748
      [-]8bf06a02c1e6028d4de85a2bce
         // 011ba775: mov esi, eax
         // 011ba777: push 0x2
         // 011ba779: shl esi, b1 0x2
         // 011ba77c: lea ecx, ss:[ebp+0xffffffffffffffe8]
         // 011ba77f: pop edx
         // 011ba780: sub ecx, esi
      [-]3bd07c08
         // 011ba782: cmp edx, eax
         // 011ba784: jl 0x11ba78e
      [-]8b31897495e0eb05
         // 011ba786: mov esi, ds:[ecx]
         // 011ba788: mov ss:[ebp+edx*0x4], esi
         // 011ba78c: jmp 0x11ba793
      [-]836495e000
         // 011ba78e: and ss:[ebp+edx*0x4], 0x0
      [-]4a83e90485d27de7
         // 011ba793: dec edx
         // 011ba794: sub ecx, 0x4
         // 011ba797: test edx, edx
         // 011ba799: jge 0x11ba782
      [-]8d1c0133c040e99b000000
         // 00420a69: lea ebx, ds:[ecx+eax]
         // 00420a6c: xor eax, eax
         // 00420a6e: inc eax
         // 00420a6f: jmp 0x420b0f
      [-]8165????????7f03d88bc19983e21f03c28bd1c1f80581e2????????7905
         // 00420a79: and ss:[ebp+0xffffffffffffffe0], 0x7fffffff
         // 00420a80: add ebx, eax
         // 00420a82: mov eax, ecx
         // 00420a84: cdq 
         // 00420a85: and edx, 0x1f
         // 00420a88: add eax, edx
         // 00420a8a: mov edx, ecx
         // 00420a8c: sar eax, b1 0x5
         // 00420a8f: and edx, 0xffffffff8000001f
         // 00420a95: jns 0x420a9c
      [-]4a83cae042
         // 011ba7d4: dec edx
         // 011ba7d5: or edx, 0xffffffffffffffe0
         // 011ba7d8: inc edx
      [-]8365f4008365080083ceff8bcad3e6c745fc????????2955fcf7d6
         // 011ba7d9: and ss:[ebp+0xfffffffffffffff4], 0x0
         // 011ba7dd: and ss:[ebp+0x8], 0x0
         // 011ba7e1: or esi, 0xffffffffffffffff
         // 011ba7e4: mov ecx, edx
         // 011ba7e6: shl esi, b1 cl
         // 011ba7e8: mov ss:[ebp+0xfffffffffffffffc], 0x20
         // 011ba7ef: sub ss:[ebp+0xfffffffffffffffc], edx
         // 011ba7f2: not esi
      [-]8b4d088b7c8de08bcf23ce894df08bcad3ef8b4d080b7df4897c8de08b7df08b4dfcd3e7ff4508837d0803897df47cd0
         // 011ba7f4: mov ecx, ss:[ebp+0x8]
         // 011ba7f7: mov edi, ss:[ebp+ecx*0x4]
         // 011ba7fb: mov ecx, edi
         // 011ba7fd: and ecx, esi
         // 011ba7ff: mov ss:[ebp+0xfffffffffffffff0], ecx
         // 011ba802: mov ecx, edx
         // 011ba804: shr edi, b1 cl
         // 011ba806: mov ecx, ss:[ebp+0x8]
         // 011ba809: or edi, ss:[ebp+0xfffffffffffffff4]
         // 011ba80c: mov ss:[ebp+ecx*0x4], edi
         // 011ba810: mov edi, ss:[ebp+0xfffffffffffffff0]
         // 011ba813: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 011ba816: shl edi, b1 cl
         // 011ba818: inc ss:[ebp+0x8]
         // 011ba81b: cmp ss:[ebp+0x8], 0x3
         // 011ba81f: mov ss:[ebp+0xfffffffffffffff4], edi
         // 011ba822: jl 0x11ba7f4
      [-]8bf06a02c1e6028d4de85a2bce
         // 011ba824: mov esi, eax
         // 011ba826: push 0x2
         // 011ba828: shl esi, b1 0x2
         // 011ba82b: lea ecx, ss:[ebp+0xffffffffffffffe8]
         // 011ba82e: pop edx
         // 011ba82f: sub ecx, esi
      [-]3bd07c08
         // 011ba831: cmp edx, eax
         // 011ba833: jl 0x11ba83d
      [-]8b31897495e0eb05
         // 011ba835: mov esi, ds:[ecx]
         // 011ba837: mov ss:[ebp+edx*0x4], esi
         // 011ba83b: jmp 0x11ba842
      [-]836495e000
         // 011ba83d: and ss:[ebp+edx*0x4], 0x0
      [-]4a83e90485d27de7
         // 011ba842: dec edx
         // 011ba843: sub ecx, 0x4
         // 011ba846: test edx, edx
         // 011ba848: jge 0x11ba831
      [-]6a1f592b0d
         // 00420b10: push 0x1f
         // 00420b12: pop ecx
         // 00420b13: sub ecx, ds:[0x42c714]
      [-]d3e38b4decf7d91bc981e1????????0bd98b0d
         // 00420b19: shl ebx, b1 cl
         // 00420b1b: mov ecx, ss:[ebp+0xffffffffffffffec]
         // 00420b1e: neg ecx
         // 00420b20: sbb ecx, ecx
         // 00420b22: and ecx, 0xffffffff80000000
         // 00420b28: or ebx, ecx
         // 00420b2a: mov ecx, ds:[0x42c718]
      [-]0b5de083f940750d
         // 00420b30: or ebx, ss:[ebp+0xffffffffffffffe0]
         // 00420b33: cmp ecx, 0x40
         // 00420b36: jnz 0x420b45
      [-]8b4d0c8b55e48959048911eb0a
         // 011ba875: mov ecx, ss:[ebp+0xc]
         // 011ba878: mov edx, ss:[ebp+0xffffffffffffffe4]
         // 011ba87b: mov ds:[ecx+0x4], ebx
         // 011ba87e: mov ds:[ecx], edx
         // 011ba880: jmp 0x11ba88c
      [-]83f9207505
         // 011ba882: cmp ecx, 0x20
         // 011ba885: jnz 0x11ba88c
      [-]8b4d0c8919
         // 011ba887: mov ecx, ss:[ebp+0xc]
         // 011ba88a: mov ds:[ecx], ebx
      [-]5f5bc9c3
         // 011ba88c: pop edi
         // 011ba88d: pop ebx
         // 011ba88e: leave 
         // 011ba88f: retn 

  }
  condition:
    all of them
}
