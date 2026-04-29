rule sality_10_0 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         8b442404
         // 0045b065: mov eax, ss:[esp+0x4]
      [-]5356578b5424108b4424148b4c2418555250515168
         // 004130d0: push ebx
         // 004130d1: push esi
         // 004130d2: push edi
         // 004130d3: mov edx, ss:[esp+0x10]
         // 004130d7: mov eax, ss:[esp+0x14]
         // 004130db: mov ecx, ss:[esp+0x18]
         // 004130df: push ebp
         // 004130e0: push edx
         // 004130e1: push eax
         // 004130e2: push ecx
         // 004130e3: push ecx
         // 004130e4: push 0x413160
      [-]64ff35????????a1
         // 004130e9: push fs:[0x0]
         // 004130f0: mov eax, ds:[___security_cookie]
      [-]0033c489442408648925????????
         // 004130f5: xor eax, esp
         // 004130f7: mov ss:[esp+0x8], eax
         // 004130fb: mov fs:[0x0], esp
      [-]8b4424308b58088b4c242c33198b700c83fefe
         // 0058bbf2: mov eax, ss:[esp+0x30]
         // 0058bbf6: mov ebx, ds:[eax+0x8]
         // 0058bbf9: mov ecx, ss:[esp+0x2c]
         // 0058bbfd: xor ebx, ds:[ecx]
         // 0058bbff: mov esi, ds:[eax+0xc]
         // 0058bc02: cmp esi, 0xfffffffffffffffe
      [-]8b54243483fafe74
         // 0058bc07: mov edx, ss:[esp+0x34]
         // 0058bc0b: cmp edx, 0xfffffffffffffffe
         // 0058bc0e: jz 0x58bc14
      [-]8d34768d5cb3108b0b89480c837b0400
         // 0058bc14: lea esi, ds:[esi+esi*0x2]
         // 0058bc17: lea ebx, ds:[ebx+esi*0x4]
         // 0058bc1b: mov ecx, ds:[ebx]
         // 0058bc1d: mov ds:[eax+0xc], ecx
         // 0058bc20: cmp ds:[ebx+0x4], 0x0
      [-]68????????8b4308e8
         // 0041d576: push 0x101
         // 0041d57b: mov eax, ds:[ebx+0x8]
         // 0041d57e: call 0x420f71
      [-]0000b9????????8b4308e8
         // 0041d583: mov ecx, 0x1
         // 0041d588: mov eax, ds:[ebx+0x8]
         // 0041d58b: call 0x420f90
      [-]648f05????????83c4185f5e5bc3
         // 0058bc42: pop fs:[0x0]
         // 0058bc49: add esp, 0x18
         // 0058bc4c: pop edi
         // 0058bc4d: pop esi
         // 0058bc4e: pop ebx
         // 0058bc4f: retn 
      [-]8b4c2404f74104????????b8????????7433
         // 0058bc50: mov ecx, ss:[esp+0x4]
         // 0058bc54: test ds:[ecx+0x4], 0x6
         // 0058bc5b: mov eax, 0x1
         // 0058bc60: jz 0x58bc95
      [-]8b4424088b480833c8e8
         // 004627e2: mov eax, ss:[esp+0x8]
         // 004627e6: mov ecx, ds:[eax+0x8]
         // 004627e9: xor ecx, eax
         // 004627eb: call @__security_check_cookie@4
      [-]558b6818ff700cff7010ff7014e8
         // 004627f0: push ebp
         // 004627f1: mov ebp, ds:[eax+0x18]
         // 004627f4: push ds:[eax+0xc]
         // 004627f7: push ds:[eax+0x10]
         // 004627fa: push ds:[eax+0x14]
         // 004627fd: call 0x462740
      [-]ffffff83c40c5d8b4424088b5424108902b8????????
         // 00462802: add esp, 0xc
         // 00462805: pop ebp
         // 00462806: mov eax, ss:[esp+0x8]
         // 0046280a: mov edx, ss:[esp+0x10]
         // 0046280e: mov ds:[edx], eax
         // 00462810: mov eax, 0x3
      [-]555657538bea33c033db33d233f633ffffd15b5f5e5dc3
         // 0058bcc0: push ebp
         // 0058bcc1: push esi
         // 0058bcc2: push edi
         // 0058bcc3: push ebx
         // 0058bcc4: mov ebp, edx
         // 0058bcc6: xor eax, eax
         // 0058bcc8: xor ebx, ebx
         // 0058bcca: xor edx, edx
         // 0058bccc: xor esi, esi
         // 0058bcce: xor edi, edi
         // 0058bcd0: call ecx
         // 0058bcd2: pop ebx
         // 0058bcd3: pop edi
         // 0058bcd4: pop esi
         // 0058bcd5: pop ebp
         // 0058bcd6: retn 
      [-]558bec5356576a00
         // 00462862: push ebp
         // 00462863: mov ebp, esp
         // 00462865: push ebx
         // 00462866: push esi
         // 00462867: push edi
         // 00462868: push 0x0
      [-]005f5e5b5dc3
         // 00462871: call RtlUnwind
         // 00462876: pop edi
         // 00462877: pop esi
         // 00462878: pop ebx
         // 00462879: pop ebp
         // 0046287a: retn 
      [-]8b4c240c
         // 0041d7d4: mov ecx, ss:[esp+0xc]
      [-]894b08894304896b0c55515058595d595bc20400
         // 0058c1c7: mov ds:[ebx+0x8], ecx
         // 0058c1ca: mov ds:[ebx+0x4], eax
         // 0058c1cd: mov ds:[ebx+0xc], ebp
         // 0058c1d0: push ebp
         // 0058c1d1: push ecx
         // 0058c1d2: push eax
         // 0058c1d3: pop eax
         // 0058c1d4: pop ecx
         // 0058c1d5: pop ebp
         // 0058c1d6: pop ecx
         // 0058c1d7: pop ebx
         // 0058c1d8: retn b2 0x4

  }
  condition:
    all of them
}
