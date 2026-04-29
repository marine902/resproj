rule cosmicduke_20_2 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         558bec83ec
         // 00402920: push ebp
         // 00402921: mov ebp, esp
         // 00402923: sub esp, 0x1c
      [-]558bec83ec
         // 00403320: push ebp
         // 00403321: mov ebp, esp
         // 00403331: sub esp, 0x14
      [-]558bec83ec
         // 00405f00: push ebp
         // 00405f01: mov ebp, esp
         // 00405f03: sub esp, 0xc
      [-]64890d????????
         // 00406734: mov fs:[0x0], ecx
      [-]53568bf1
         // 00407123: push ebx
         // 00407127: push esi
         // 00407128: mov esi, ecx
      [-]64a1????????50
         // 0040762a: mov eax, fs:[0x0]
         // 00407630: push eax
      [-]8bff568bf1807e08007409
         // 00408100: mov edi, edi
         // 00408102: push esi
         // 00408103: mov esi, ecx
         // 00408105: cmp b1 ds:[esi+0x8], b1 0x0
         // 00408109: jz 0x408114
      [-]ff7604e8
         // 0040810b: push ds:[esi+0x4]
         // 0040810e: call _free
      [-]83660400c64608005ec3
         // 00408114: and ds:[esi+0x4], 0x0
         // 00408118: mov b1 ds:[esi+0x8], b1 0x0
         // 0040811c: pop esi
         // 0040811d: retn 
      [-]8bff51c701
         // 004086a0: mov edi, edi
         // 004086a2: push ecx
         // 004086a3: mov ds:[ecx], ??_7type_info@@6B@
      [-]000059c3
         // 004086ae: pop ecx
         // 004086af: retn 
      [-]8bff558bec568bf1e8e3fffffff64508017407
         // 004086b0: mov edi, edi
         // 004086b2: push ebp
         // 004086b3: mov ebp, esp
         // 004086b5: push esi
         // 004086b6: mov esi, ecx
         // 004086b8: call 0x4086a0
         // 004086bd: test b1 ss:[ebp+0x8], b1 0x1
         // 004086c1: jz 0x4086ca
      [-]8bc65e5dc20400
         // 004086ca: mov eax, esi
         // 004086cc: pop esi
         // 004086cd: pop ebp
         // 004086ce: retn b2 0x4
      [-]6a0aff15
         // 00408ec8: push 0xa
         // 00408eca: call ds:[__imp_IsProcessorFeaturePresent]
      [-]8bff558bec8b4508a3??
         // 00409422: mov edi, edi
         // 00409424: push ebp
         // 00409425: mov ebp, esp
         // 00409427: mov eax, ss:[ebp+0x8]
         // 0040942a: mov ds:[0x4aba6c], eax
      [-]0033c0c3
         // 0040953f: xor eax, eax
         // 00409541: retn 
      [-]8bff56b8
         // 0040a316: mov edi, edi
         // 0040a318: push esi
         // 0040a319: mov eax, 0x427554
      [-]578bf83bc6730f
         // 0040a323: push edi
         // 0040a324: mov edi, eax
         // 0040a326: cmp eax, esi
         // 0040a328: jnb 0x40a339
      [-]8b0785c07402
         // 0040a32a: mov eax, ds:[edi]
         // 0040a32c: test eax, eax
         // 0040a32e: jz 0x40a332
      [-]83c7043bfe72f1
         // 0040a332: add edi, 0x4
         // 0040a335: cmp edi, esi
         // 0040a337: jb 0x40a32a
      [-]8bff56b8
         // 0040a33c: mov edi, edi
         // 0040a33e: push esi
         // 0040a33f: mov eax, 0x42755c
      [-]578bf83bc6730f
         // 0040a349: push edi
         // 0040a34a: mov edi, eax
         // 0040a34c: cmp eax, esi
         // 0040a34e: jnb 0x40a35f
      [-]8b0785c07402
         // 0040a350: mov eax, ds:[edi]
         // 0040a352: test eax, eax
         // 0040a354: jz 0x40a358
      [-]83c7043bfe72f1
         // 0040a358: add edi, 0x4
         // 0040a35b: cmp edi, esi
         // 0040a35d: jb 0x40a350
      [-]8bff558bec8b4508a3
         // 0040b44a: mov edi, edi
         // 0040b44c: push ebp
         // 0040b44d: mov ebp, esp
         // 0040b44f: mov eax, ss:[ebp+0x8]
         // 0040b452: mov ds:[0x4ac204], eax
      [-]8bff558bec83ec24a1
         // 0041170c: mov edi, edi
         // 0041170e: push ebp
         // 0041170f: mov ebp, esp
         // 00411711: sub esp, 0x24
         // 00411714: mov eax, ds:[___security_cookie]
      [-]420033c58945fc8b4508538945e08b450c56578945e4e8
         // 00411719: xor eax, ebp
         // 0041171b: mov ss:[ebp+0xfffffffffffffffc], eax
         // 0041171e: mov eax, ss:[ebp+0x8]
         // 00411721: push ebx
         // 00411722: mov ss:[ebp+0xffffffffffffffe0], eax
         // 00411725: mov eax, ss:[ebp+0xc]
         // 00411728: push esi
         // 00411729: push edi
         // 0041172a: mov ss:[ebp+0xffffffffffffffe4], eax
         // 0041172d: call __encoded_null
      [-]ffff8365ec00833d
         // 00411732: and ss:[ebp+0xffffffffffffffec], 0x0
         // 00411736: cmp ds:[0x4ac3dc], 0x0
      [-]008945e8757d
         // 0041173d: mov ss:[ebp+0xffffffffffffffe8], eax
         // 00411740: jnz 0x4117bf
      [-]008bd885db0f8410010000
         // 0041174d: mov ebx, eax
         // 0041174f: test ebx, ebx
         // 00411751: jz 0x411867
      [-]53ffd785c00f84fa000000
         // 00411762: push ebx
         // 00411763: call edi
         // 00411765: test eax, eax
         // 00411767: jz 0x411867
      [-]0050ffd668
         // 00411773: push eax
         // 00411774: call esi
         // 00411776: push 0x4248dc
      [-]ffd750ffd668
         // 00411781: call edi
         // 00411783: push eax
         // 00411784: call esi
         // 00411786: push 0x4248c8
      [-]ffd750ffd668
         // 00411791: call edi
         // 00411793: push eax
         // 00411794: call esi
         // 00411796: push 0x4248ac
      [-]ffd750ffd6a3
         // 004117a1: call edi
         // 004117a3: push eax
         // 004117a4: call esi
         // 004117a6: mov ds:[0x4ac3ec], eax
      [-]85c07410
         // 004117ab: test eax, eax
         // 004117ad: jz 0x4117bf
      [-]53ffd750ffd6a3
         // 004117b4: push ebx
         // 004117b5: call edi
         // 004117b7: push eax
         // 004117b8: call esi
         // 004117ba: mov ds:[0x4ac3e8], eax
      [-]8b4de88b35
         // 004117c4: mov ecx, ss:[ebp+0xffffffffffffffe8]
         // 004117c7: mov esi, ds:[__imp_DecodePointer]
      [-]003bc17447
         // 004117cd: cmp eax, ecx
         // 004117cf: jz 0x411818
      [-]50ffd6ff35
         // 004117d9: push eax
         // 004117da: call esi
         // 004117dc: push ds:[0x4ac3ec]
      [-]8bf8ffd68bd885ff742c
         // 004117e2: mov edi, eax
         // 004117e4: call esi
         // 004117e6: mov ebx, eax
         // 004117e8: test edi, edi
         // 004117ea: jz 0x411818
      [-]85db7428
         // 004117ec: test ebx, ebx
         // 004117ee: jz 0x411818
      [-]ffd785c07419
         // 004117f0: call edi
         // 004117f2: test eax, eax
         // 004117f4: jz 0x41180f
      [-]8d4ddc516a0c8d4df0516a0150ffd385c07406
         // 004117f6: lea ecx, ss:[ebp+0xffffffffffffffdc]
         // 004117f9: push ecx
         // 004117fa: push 0xc
         // 004117fc: lea ecx, ss:[ebp+0xfffffffffffffff0]
         // 004117ff: push ecx
         // 00411800: push 0x1
         // 00411802: push eax
         // 00411803: call ebx
         // 00411805: test eax, eax
         // 00411807: jz 0x41180f
      [-]f645f8017509
         // 00411809: test b1 ss:[ebp+0xfffffffffffffff8], b1 0x1
         // 0041180d: jnz 0x411818
      [-]814d10????????eb33
         // 0041180f: or ss:[ebp+0x10], 0x200000
         // 00411816: jmp 0x41184b
      [-]3b45e87429
         // 0041181d: cmp eax, ss:[ebp+0xffffffffffffffe8]
         // 00411820: jz 0x41184b
      [-]50ffd685c07422
         // 00411822: push eax
         // 00411823: call esi
         // 00411825: test eax, eax
         // 00411827: jz 0x41184b
      [-]ffd08945ec85c07419
         // 00411829: call eax
         // 0041182b: mov ss:[ebp+0xffffffffffffffec], eax
         // 0041182e: test eax, eax
         // 00411830: jz 0x41184b
      [-]3b45e8740f
         // 00411837: cmp eax, ss:[ebp+0xffffffffffffffe8]
         // 0041183a: jz 0x41184b
      [-]50ffd685c07408
         // 0041183c: push eax
         // 0041183d: call esi
         // 0041183f: test eax, eax
         // 00411841: jz 0x41184b
      [-]ff75ecffd08945ec
         // 00411843: push ss:[ebp+0xffffffffffffffec]
         // 00411846: call eax
         // 00411848: mov ss:[ebp+0xffffffffffffffec], eax
      [-]ffd685c07410
         // 00411851: call esi
         // 00411853: test eax, eax
         // 00411855: jz 0x411867
      [-]ff7510ff75e4ff75e0ff75ecffd0eb02
         // 00411857: push ss:[ebp+0x10]
         // 0041185a: push ss:[ebp+0xffffffffffffffe4]
         // 0041185d: push ss:[ebp+0xffffffffffffffe0]
         // 00411860: push ss:[ebp+0xffffffffffffffec]
         // 00411863: call eax
         // 00411865: jmp 0x411869
      [-]8b4dfc5f5e33cd5be8
         // 00411869: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 0041186c: pop edi
         // 0041186d: pop esi
         // 0041186e: xor ecx, ebp
         // 00411870: pop ebx
         // 00411871: call @__security_check_cookie@4
      [-]ffffc9c3
         // 00411876: leave 
         // 00411877: retn 
      [-]558bec83ec08535657fc8945fc33c0505050ff75fcff7514ff7510ff750cff7508e8
         // 0041cd47: push ebp
         // 0041cd48: mov ebp, esp
         // 0041cd4a: sub esp, 0x8
         // 0041cd4d: push ebx
         // 0041cd4e: push esi
         // 0041cd4f: push edi
         // 0041cd50: cld 
         // 0041cd51: mov ss:[ebp+0xfffffffffffffffc], eax
         // 0041cd54: xor eax, eax
         // 0041cd56: push eax
         // 0041cd57: push eax
         // 0041cd58: push eax
         // 0041cd59: push ss:[ebp+0xfffffffffffffffc]
         // 0041cd5c: push ss:[ebp+0x14]
         // 0041cd5f: push ss:[ebp+0x10]
         // 0041cd62: push ss:[ebp+0xc]
         // 0041cd65: push ss:[ebp+0x8]
         // 0041cd68: call ___InternalCxxFrameHandler
      [-]000083c4208945f85f5e5b8b45f88be55dc3
         // 0041cd6d: add esp, 0x20
         // 0041cd70: mov ss:[ebp+0xfffffffffffffff8], eax
         // 0041cd73: pop edi
         // 0041cd74: pop esi
         // 0041cd75: pop ebx
         // 0041cd76: mov eax, ss:[ebp+0xfffffffffffffff8]
         // 0041cd79: mov esp, ebp
         // 0041cd7b: pop ebp
         // 0041cd7c: retn 

  }
  condition:
    all of them
}
