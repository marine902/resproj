rule remcos_10_4 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         83c40cc3
         // 0040508d: add esp, 0xc
         // 00405090: retn 
      [-]83c40cc3
         // 00408d56: add esp, 0xc
         // 00408d59: retn 
      [-]ff742410ff742410ff
         // 00429777: push ss:[esp+0x10]
         // 0042977b: push ss:[esp+0x10]
         // 0042977f: push ss:[esp+0x10]
      [-]ffff33c0
         // 006103f1: xor eax, eax
      [-]000033c0c3
         // 00434bd3: xor eax, eax
         // 00434bd5: retn 
      [-]010059c3
         // 00434be6: pop ecx
         // 00434be7: retn 
      [-]33c03905
         // 00436108: xor eax, eax
         // 0043610a: cmp ds:[0x472020], eax
      [-]0f94c0c3
         // 00436110: setz b1 al
         // 00436113: retn 
      [-]3bf37319
         // 0043534c: cmp esi, ebx
         // 0043534e: jnb 0x435369
      [-]8b3e85ff740a
         // 00436131: mov edi, ds:[esi]
         // 00436133: test edi, edi
         // 00436135: jz 0x436141
      [-]8bcfff15
         // 00435357: mov ecx, edi
         // 00435359: call ds:[___guard_check_icall_fptr]
      [-]83c6043bf372e9
         // 00436141: add esi, 0x4
         // 00436144: cmp esi, ebx
         // 00436146: jb 0x436131
      [-]3bf37319
         // 00435378: cmp esi, ebx
         // 0043537a: jnb 0x435395
      [-]8b3e85ff740a
         // 0043615d: mov edi, ds:[esi]
         // 0043615f: test edi, edi
         // 00436161: jz 0x43616d
      [-]8bcfff15
         // 00435383: mov ecx, edi
         // 00435385: call ds:[___guard_check_icall_fptr]
      [-]83c6043bf372e9
         // 0043616d: add esi, 0x4
         // 00436170: cmp esi, ebx
         // 00436172: jb 0x43615d
      [-]558bec56ff75088bf1e8
         // 004399d4: push ebp
         // 004399d5: mov ebp, esp
         // 004399d7: push esi
         // 004399d8: push ss:[ebp+0x8]
         // 004399db: mov esi, ecx
         // 004399dd: call 0x40daa6
      [-]008bc65e5dc20400
         // 004399e8: mov eax, esi
         // 004399ea: pop esi
         // 004399eb: pop ebp
         // 004399ec: retn b2 0x4
      [-]836104008bc183610800c74104
         // 004399ef: and ds:[ecx+0x4], 0x0
         // 004399f3: mov eax, ecx
         // 004399f5: and ds:[ecx+0x8], 0x0
         // 004399f9: mov ds:[ecx+0x4], 0x45c910
      [-]8bff558bec
         // 0043c5f7: mov edi, edi
         // 0043c5f9: push ebp
         // 0043c5fa: mov ebp, esp
      [-]51518bc4
         // 0043c601: push ecx
         // 0043c602: push ecx
         // 0043c603: mov eax, esp
      [-]ff750850e8
         // 0043c607: push ss:[ebp+0x8]
         // 0043c60a: push eax
         // 0043c60b: call 0x43b933
      [-]ffff83c40c
         // 0043c610: add esp, 0xc
      [-]ffff83c4148b
         // 0043c61a: add esp, 0x14
         // 0043c61d: mov esp, ebp
      [-]00000085c0
         // 004445e6: test eax, eax
      [-]00000085c0
         // 00444615: test eax, eax
      [-]8bff558bec8b45088b003b05
         // 00444a0a: mov edi, edi
         // 00444a0c: push ebp
         // 00444a0d: mov ebp, esp
         // 00444a0f: mov eax, ss:[ebp+0x8]
         // 00444a12: mov eax, ds:[eax]
         // 00444a14: cmp eax, ds:[0x473524]
      [-]feffff59
         // 00444a22: pop ecx
      [-]8bff558bec8b45088b003b05
         // 00444a25: mov edi, edi
         // 00444a27: push ebp
         // 00444a28: mov ebp, esp
         // 00444a2a: mov eax, ss:[ebp+0x8]
         // 00444a2d: mov eax, ds:[eax]
         // 00444a2f: cmp eax, ds:[0x473520]
      [-]feffff59
         // 00444a3d: pop ecx
      [-]e9b2fbffff
         // 00444a45: jmp 0x4445fc
      [-]8bff558becff750868
         // 00444dd9: mov edi, edi
         // 00444ddb: push ebp
         // 00444ddc: mov ebp, esp
         // 00444dde: push ss:[ebp+0x8]
         // 00444de1: push stru_473528._first
      [-]00000059595dc3
         // 00444deb: pop ecx
         // 00444dec: pop ecx
         // 00444ded: pop ebp
         // 00444dee: retn 
      [-]8bff558bec568b750c8b063b05
         // 00448930: mov edi, edi
         // 00448932: push ebp
         // 00448933: mov ebp, esp
         // 00448935: push esi
         // 00448936: mov esi, ss:[ebp+0xc]
         // 00448939: mov eax, ds:[esi]
         // 0044893b: cmp eax, ds:[0x47369c]
      [-]8b4d08a1
         // 00448943: mov ecx, ss:[ebp+0x8]
         // 00448946: mov eax, ds:[0x4729a4]
      [-]8581????????7507
         // 0044894b: test ds:[ecx+0x350], eax
         // 00448951: jnz 0x44895a
      [-]00008906
         // 004483d6: mov ds:[esi], eax
      [-]8bff558bec568b750c8b063b05
         // 0044895d: mov edi, edi
         // 0044895f: push ebp
         // 00448960: mov ebp, esp
         // 00448962: push esi
         // 00448963: mov esi, ss:[ebp+0xc]
         // 00448966: mov eax, ds:[esi]
         // 00448968: cmp eax, ds:[0x4729a0]
      [-]8b4d08a1
         // 00448970: mov ecx, ss:[ebp+0x8]
         // 00448973: mov eax, ds:[0x4729a4]
      [-]8581????????7507
         // 00448978: test ds:[ecx+0x350], eax
         // 0044897e: jnz 0x448987
      [-]00008906
         // 00448403: mov ds:[esi], eax
      [-]8bff558bec8b4d0885c97515
         // 004493a1: mov edi, edi
         // 004493a3: push ebp
         // 004493a4: mov ebp, esp
         // 004493a6: mov ecx, ss:[ebp+0x8]
         // 004493a9: test ecx, ecx
         // 004493ab: jnz 0x4493c2
      [-]c700????????e8
         // 00448e30: mov ds:[eax], 0x16
         // 00448e36: call __invalid_parameter_noinfo
      [-]ffff6a16585dc3
         // 00448e3b: push 0x16
         // 00448e3d: pop eax
         // 00448e3e: pop ebp
         // 00448e3f: retn 
      [-]890133c05dc3
         // 004493c7: mov ds:[ecx], eax
         // 004493c9: xor eax, eax
         // 004493cb: pop ebp
         // 004493cc: retn 
      [-]8bff558bec8b4d0885c97515
         // 004493cd: mov edi, edi
         // 004493cf: push ebp
         // 004493d0: mov ebp, esp
         // 004493d2: mov ecx, ss:[ebp+0x8]
         // 004493d5: test ecx, ecx
         // 004493d7: jnz 0x4493ee
      [-]c700????????e8
         // 00448e5c: mov ds:[eax], 0x16
         // 00448e62: call __invalid_parameter_noinfo
      [-]ffff6a16585dc3
         // 00448e67: push 0x16
         // 00448e69: pop eax
         // 00448e6a: pop ebp
         // 00448e6b: retn 
      [-]890133c05dc3
         // 004493f3: mov ds:[ecx], eax
         // 004493f5: xor eax, eax
         // 004493f7: pop ebp
         // 004493f8: retn 
      [-]8bff558bec8b4d0885c97515
         // 004493f9: mov edi, edi
         // 004493fb: push ebp
         // 004493fc: mov ebp, esp
         // 004493fe: mov ecx, ss:[ebp+0x8]
         // 00449401: test ecx, ecx
         // 00449403: jnz 0x44941a
      [-]c700????????e8
         // 00448e88: mov ds:[eax], 0x16
         // 00448e8e: call __invalid_parameter_noinfo
      [-]ffff6a16585dc3
         // 00448e93: push 0x16
         // 00448e95: pop eax
         // 00448e96: pop ebp
         // 00448e97: retn 
      [-]890133c05dc3
         // 0044941f: mov ds:[ecx], eax
         // 00449421: xor eax, eax
         // 00449423: pop ebp
         // 00449424: retn 

  }
  condition:
    all of them
}
