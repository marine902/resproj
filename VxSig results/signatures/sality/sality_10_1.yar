rule sality_10_1 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         5356578b5424108b4424148b4c2418555250515168
         // 004558e0: push ebx
         // 004558e1: push esi
         // 004558e2: push edi
         // 004558e3: mov edx, ss:[esp+0x10]
         // 004558e7: mov eax, ss:[esp+0x14]
         // 004558eb: mov ecx, ss:[esp+0x18]
         // 004558ef: push ebp
         // 004558f0: push edx
         // 004558f1: push eax
         // 004558f2: push ecx
         // 004558f3: push ecx
         // 004558f4: push 0x455980
      [-]64ff35????????a1
         // 004558f9: push fs:[0x0]
         // 00455900: mov eax, ds:[___security_cookie]
      [-]0033c489442408648925????????
         // 00455905: xor eax, esp
         // 00455907: mov ss:[esp+0x8], eax
         // 0045590b: mov fs:[0x0], esp
      [-]8b4424308b58088b4c242c33198b700c83fefe
         // 0041d202: mov eax, ss:[esp+0x30]
         // 0041d206: mov ebx, ds:[eax+0x8]
         // 0041d209: mov ecx, ss:[esp+0x2c]
         // 0041d20d: xor ebx, ds:[ecx]
         // 0041d20f: mov esi, ds:[eax+0xc]
         // 0041d212: cmp esi, 0xfffffffffffffffe
      [-]8b54243483fafe74
         // 0041d217: mov edx, ss:[esp+0x34]
         // 0041d21b: cmp edx, 0xfffffffffffffffe
         // 0041d21e: jz 0x41d224
      [-]8d34768d5cb3108b0b89480c837b0400
         // 0041d224: lea esi, ds:[esi+esi*0x2]
         // 0041d227: lea ebx, ds:[ebx+esi*0x4]
         // 0041d22b: mov ecx, ds:[ebx]
         // 0041d22d: mov ds:[eax+0xc], ecx
         // 0041d230: cmp ds:[ebx+0x4], 0x0
      [-]68????????8b4308e8
         // 0041d236: push 0x101
         // 0041d23b: mov eax, ds:[ebx+0x8]
         // 0041d23e: call 0x420c45
      [-]b9????????8b4308e8
         // 0041d243: mov ecx, 0x1
         // 0041d248: mov eax, ds:[ebx+0x8]
         // 0041d24b: call 0x420c64
      [-]648f05????????83c4185f5e5bc3
         // 0041d252: pop fs:[0x0]
         // 0041d259: add esp, 0x18
         // 0041d25c: pop edi
         // 0041d25d: pop esi
         // 0041d25e: pop ebx
         // 0041d25f: retn 
      [-]8b4c2404f74104????????b8????????7433
         // 0041d260: mov ecx, ss:[esp+0x4]
         // 0041d264: test ds:[ecx+0x4], 0x6
         // 0041d26b: mov eax, 0x1
         // 0041d270: jz 0x41d2a5
      [-]8b4424088b480833c8e8
         // 0040e81e: mov eax, ss:[esp+0x8]
         // 0040e822: mov ecx, ds:[eax+0x8]
         // 0040e825: xor ecx, eax
         // 0040e827: call @__security_check_cookie@4
      [-]558b6818ff700cff7010ff7014e8
         // 0040e82c: push ebp
         // 0040e82d: mov ebp, ds:[eax+0x18]
         // 0040e830: push ds:[eax+0xc]
         // 0040e833: push ds:[eax+0x10]
         // 0040e836: push ds:[eax+0x14]
         // 0040e839: call 0x40e77c
      [-]ffffff83c40c5d8b4424088b5424108902b8????????
         // 0040e83e: add esp, 0xc
         // 0040e841: pop ebp
         // 0040e842: mov eax, ss:[esp+0x8]
         // 0040e846: mov edx, ss:[esp+0x10]
         // 0040e84a: mov ds:[edx], eax
         // 0040e84c: mov eax, 0x3
      [-]555657538bea33c033db33d233f633ffffd15b5f5e5dc3
         // 0041d2c2: push ebp
         // 0041d2c3: push esi
         // 0041d2c4: push edi
         // 0041d2c5: push ebx
         // 0041d2c6: mov ebp, edx
         // 0041d2c8: xor eax, eax
         // 0041d2ca: xor ebx, ebx
         // 0041d2cc: xor edx, edx
         // 0041d2ce: xor esi, esi
         // 0041d2d0: xor edi, edi
         // 0041d2d2: call ecx
         // 0041d2d4: pop ebx
         // 0041d2d5: pop edi
         // 0041d2d6: pop esi
         // 0041d2d7: pop ebp
         // 0041d2d8: retn 
      [-]558bec5356576a00
         // 00455a10: push ebp
         // 00455a11: mov ebp, esp
         // 00455a13: push ebx
         // 00455a14: push esi
         // 00455a15: push edi
         // 00455a16: push 0x0
      [-]5f5e5b5dc3
         // 00455a25: pop edi
         // 00455a26: pop esi
         // 00455a27: pop ebx
         // 00455a28: pop ebp
         // 00455a29: retn 
      [-]558b6c24085251ff742414e8
         // 004e2e00: push ebp
         // 004e2e01: mov ebp, ss:[esp+0x8]
         // 004e2e05: push edx
         // 004e2e06: push ecx
         // 004e2e07: push ss:[esp+0x14]
         // 004e2e0b: call 0x4e2cb0
      [-]feffff83c40c5dc20800
         // 004e2e10: add esp, 0xc
         // 004e2e13: pop ebp
         // 004e2e14: retn b2 0x8

  }
  condition:
    all of them
}
