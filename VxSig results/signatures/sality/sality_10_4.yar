rule sality_10_4 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         5356578b5424108b4424148b4c2418555250515168
         // 00426480: push ebx
         // 00426481: push esi
         // 00426482: push edi
         // 00426483: mov edx, ss:[esp+0x10]
         // 00426487: mov eax, ss:[esp+0x14]
         // 0042648b: mov ecx, ss:[esp+0x18]
         // 0042648f: push ebp
         // 00426490: push edx
         // 00426491: push eax
         // 00426492: push ecx
         // 00426493: push ecx
         // 00426494: push 0x426510
      [-]64ff35????????a1
         // 00426499: push fs:[0x0]
         // 004264a0: mov eax, ds:[___security_cookie]
      [-]33c489442408648925????????
         // 004264a5: xor eax, esp
         // 004264a7: mov ss:[esp+0x8], eax
         // 004264ab: mov fs:[0x0], esp
      [-]8b4424308b58088b4c242c33198b700c83fefe743b
         // 006c8372: mov eax, ss:[esp+0x30]
         // 006c8376: mov ebx, ds:[eax+0x8]
         // 006c8379: mov ecx, ss:[esp+0x2c]
         // 006c837d: xor ebx, ds:[ecx]
         // 006c837f: mov esi, ds:[eax+0xc]
         // 006c8382: cmp esi, 0xfffffffffffffffe
         // 006c8385: jz 0x6c83c2
      [-]8b54243483fafe7404
         // 006c8387: mov edx, ss:[esp+0x34]
         // 006c838b: cmp edx, 0xfffffffffffffffe
         // 006c838e: jz 0x6c8394
      [-]3bf2762e
         // 006c8390: cmp esi, edx
         // 006c8392: jbe 0x6c83c2
      [-]8d34768d5cb3108b0b89480c837b040075cc
         // 006c8394: lea esi, ds:[esi+esi*0x2]
         // 006c8397: lea ebx, ds:[ebx+esi*0x4]
         // 006c839b: mov ecx, ds:[ebx]
         // 006c839d: mov ds:[eax+0xc], ecx
         // 006c83a0: cmp ds:[ebx+0x4], 0x0
         // 006c83a4: jnz 0x6c8372
      [-]68????????8b4308e8
         // 0040c036: push 0x101
         // 0040c03b: mov eax, ds:[ebx+0x8]
         // 0040c03e: call 0x4101b5
      [-]0000b9????????8b4308e8
         // 0040c043: mov ecx, 0x1
         // 0040c048: mov eax, ds:[ebx+0x8]
         // 0040c04b: call 0x4101d4
      [-]0000ebb0
         // 0040c050: jmp 0x40c002
      [-]648f05????????83c4185f5e5bc3
         // 006c83c2: pop fs:[0x0]
         // 006c83c9: add esp, 0x18
         // 006c83cc: pop edi
         // 006c83cd: pop esi
         // 006c83ce: pop ebx
         // 006c83cf: retn 
      [-]555657538bea33c033db33d233f633ffffd15b5f5e5dc3
         // 006c8432: push ebp
         // 006c8433: push esi
         // 006c8434: push edi
         // 006c8435: push ebx
         // 006c8436: mov ebp, edx
         // 006c8438: xor eax, eax
         // 006c843a: xor ebx, ebx
         // 006c843c: xor edx, edx
         // 006c843e: xor esi, esi
         // 006c8440: xor edi, edi
         // 006c8442: call ecx
         // 006c8444: pop ebx
         // 006c8445: pop edi
         // 006c8446: pop esi
         // 006c8447: pop ebp
         // 006c8448: retn 
      [-]558b6c24085251ff742414e8
         // 00566c57: push ebp
         // 00566c58: mov ebp, ss:[esp+0x8]
         // 00566c5c: push edx
         // 00566c5d: push ecx
         // 00566c5e: push ss:[esp+0x14]
         // 00566c62: call 0x566b10
      [-]feffff83c40c5dc20800
         // 00566c67: add esp, 0xc
         // 00566c6a: pop ebp
         // 00566c6b: retn b2 0x8
      [-]8b4c2404f74104????????b8????????7432
         // 006d1c6c: mov ecx, ss:[esp+0x4]
         // 006d1c70: test ds:[ecx+0x4], 0x6
         // 006d1c77: mov eax, 0x1
         // 006d1c7c: jz 0x6d1cb0
      [-]8b4424148b48fc33c8e8
         // 004100d2: mov eax, ss:[esp+0x14]
         // 004100d6: mov ecx, ds:[eax+0xfffffffffffffffc]
         // 004100d9: xor ecx, eax
         // 004100db: call @__security_check_cookie@4
      [-]ff558b68108b5028528b502452e81400000083c4085d8b4424088b5424108902b8????????
         // 004100e0: push ebp
         // 004100e1: mov ebp, ds:[eax+0x10]
         // 004100e4: mov edx, ds:[eax+0x28]
         // 004100e7: push edx
         // 004100e8: mov edx, ds:[eax+0x24]
         // 004100eb: push edx
         // 004100ec: call 0x410105
         // 004100f1: add esp, 0x8
         // 004100f4: pop ebp
         // 004100f5: mov eax, ss:[esp+0x8]
         // 004100f9: mov edx, ss:[esp+0x10]
         // 004100fd: mov ds:[edx], eax
         // 004100ff: mov eax, 0x3
      [-]5356578b44241055506afe68
         // 00434299: push ebx
         // 0043429a: push esi
         // 0043429b: push edi
         // 0043429c: mov eax, ss:[esp+0x10]
         // 004342a0: push ebp
         // 004342a1: push eax
         // 004342a2: push 0xfffffffffffffffe
         // 004342a4: push 0x434254
      [-]64ff35????????a1
         // 004342a9: push fs:[0x0]
         // 004342b0: mov eax, ds:[___security_cookie]
      [-]33c4508d44240464a3????????
         // 004342b5: xor eax, esp
         // 004342b7: push eax
         // 004342b8: lea eax, ss:[esp+0x4]
         // 004342bc: mov fs:[0x0], eax
      [-]8b4424288b58088b700c83feff743a
         // 006d1cda: mov eax, ss:[esp+0x28]
         // 006d1cde: mov ebx, ds:[eax+0x8]
         // 006d1ce1: mov esi, ds:[eax+0xc]
         // 006d1ce4: cmp esi, 0xffffffffffffffff
         // 006d1ce7: jz 0x6d1d23
      [-]837c242cff7406
         // 006d1ce9: cmp ss:[esp+0x2c], 0xffffffffffffffff
         // 006d1cee: jz 0x6d1cf6
      [-]3b74242c762d
         // 006d1cf0: cmp esi, ss:[esp+0x2c]
         // 006d1cf4: jbe 0x6d1d23
      [-]8d34768b0cb3894c240c89480c837cb304007517
         // 006d1cf6: lea esi, ds:[esi+esi*0x2]
         // 006d1cf9: mov ecx, ds:[ebx+esi*0x4]
         // 006d1cfc: mov ss:[esp+0xc], ecx
         // 006d1d00: mov ds:[eax+0xc], ecx
         // 006d1d03: cmp ds:[ebx+esi*0x4], 0x0
         // 006d1d08: jnz 0x6d1d21
      [-]68????????8b44b308e8
         // 006d1d0a: push 0x101
         // 006d1d0f: mov eax, ds:[ebx+esi*0x4]
         // 006d1d13: call 0x6d1d61
      [-]0000008b44b308e8
         // 006d1d18: mov eax, ds:[ebx+esi*0x4]
         // 006d1d1c: call 0x6d1d80
      [-]8b4c240464890d????????83c4185f5e5bc3
         // 006d1d23: mov ecx, ss:[esp+0x4]
         // 006d1d27: mov fs:[0x0], ecx
         // 006d1d2e: add esp, 0x18
         // 006d1d31: pop edi
         // 006d1d32: pop esi
         // 006d1d33: pop ebx
         // 006d1d34: retn 
      [-]33c0648b0d????????817904
         // 00410189: xor eax, eax
         // 0041018b: mov ecx, fs:[0x0]
         // 00410192: cmp ds:[ecx+0x4], 0x4100c0
      [-]8b510c8b520c3951087505
         // 006d1d47: mov edx, ds:[ecx+0xc]
         // 006d1d4a: mov edx, ds:[edx+0xc]
         // 006d1d4d: cmp ds:[ecx+0x8], edx
         // 006d1d50: jnz 0x6d1d57
      [-]b8????????
         // 006d1d52: mov eax, 0x1
      [-]8b4c240c
         // 004101bc: mov ecx, ss:[esp+0xc]
      [-]894b08894304896b0c55515058595d595bc20400
         // 006d1d6c: mov ds:[ebx+0x8], ecx
         // 006d1d6f: mov ds:[ebx+0x4], eax
         // 006d1d72: mov ds:[ebx+0xc], ebp
         // 006d1d75: push ebp
         // 006d1d76: push ecx
         // 006d1d77: push eax
         // 006d1d78: pop eax
         // 006d1d79: pop ecx
         // 006d1d7a: pop ebp
         // 006d1d7b: pop ecx
         // 006d1d7c: pop ebx
         // 006d1d7d: retn b2 0x4

  }
  condition:
    all of them
}
