rule softcnapp_10_0 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         8b3e85ff74
         // 0042b1d6: mov edi, ds:[esi]
         // 0042b1d8: test edi, edi
         // 0042b1da: jz 0x42b1e6
      [-]83c6043bf372
         // 0042b1e6: add esi, 0x4
         // 0042b1e9: cmp esi, ebx
         // 0042b1eb: jb 0x42b1d6
      [-]558bec83ec08535657fc8945fc33c0505050ff75fcff7514ff7510ff750cff7508e8
         // 00440240: push ebp
         // 00440241: mov ebp, esp
         // 00440243: sub esp, 0x8
         // 00440246: push ebx
         // 00440247: push esi
         // 00440248: push edi
         // 00440249: cld 
         // 0044024a: mov ss:[ebp+0xfffffffffffffffc], eax
         // 0044024d: xor eax, eax
         // 0044024f: push eax
         // 00440250: push eax
         // 00440251: push eax
         // 00440252: push ss:[ebp+0xfffffffffffffffc]
         // 00440255: push ss:[ebp+0x14]
         // 00440258: push ss:[ebp+0x10]
         // 0044025b: push ss:[ebp+0xc]
         // 0044025e: push ss:[ebp+0x8]
         // 00440261: call ___InternalCxxFrameHandler
      [-]83c4208945f85f5e5b8b45f88be55dc3
         // 00440266: add esp, 0x20
         // 00440269: mov ss:[ebp+0xfffffffffffffff8], eax
         // 0044026c: pop edi
         // 0044026d: pop esi
         // 0044026e: pop ebx
         // 0044026f: mov eax, ss:[ebp+0xfffffffffffffff8]
         // 00440272: mov esp, ebp
         // 00440274: pop ebp
         // 00440275: retn 
      [-]8bff558becff7508b9
         // 00442a4e: mov edi, edi
         // 00442a50: push ebp
         // 00442a51: mov ebp, esp
         // 00442a53: push ss:[ebp+0x8]
         // 00442a56: mov ecx, 0x60f078
      [-]8bff558becff7508b9
         // 0050c64b: mov edi, edi
         // 0050c64d: push ebp
         // 0050c64e: mov ebp, esp
         // 0050c650: push ss:[ebp+0x8]
         // 0050c653: mov ecx, 0x6faa8c
      [-]8bff558bec8b45088b003b05??
         // 0044370f: mov edi, edi
         // 00443711: push ebp
         // 00443712: mov ebp, esp
         // 00443714: mov eax, ss:[ebp+0x8]
         // 00443717: mov eax, ds:[eax]
         // 00443719: cmp eax, ds:[0x60f2b0]
      [-]8bff558bec8b45088b003b05
         // 0044372a: mov edi, edi
         // 0044372c: push ebp
         // 0044372d: mov ebp, esp
         // 0044372f: mov eax, ss:[ebp+0x8]
         // 00443732: mov eax, ds:[eax]
         // 00443734: cmp eax, ds:[0x60f2ac]
      [-]8bff558bec83ec0c8b45088d4dff8945f88945f48d45f850ff750c8d45f450e88bffffff8be55dc3
         // 00459412: mov edi, edi
         // 00459414: push ebp
         // 00459415: mov ebp, esp
         // 00459417: sub esp, 0xc
         // 0045941a: mov eax, ss:[ebp+0x8]
         // 0045941d: lea ecx, ss:[ebp+0xffffffffffffffff]
         // 00459420: mov ss:[ebp+0xfffffffffffffff8], eax
         // 00459423: mov ss:[ebp+0xfffffffffffffff4], eax
         // 00459426: lea eax, ss:[ebp+0xfffffffffffffff8]
         // 00459429: push eax
         // 0045942a: push ss:[ebp+0xc]
         // 0045942d: lea eax, ss:[ebp+0xfffffffffffffff4]
         // 00459430: push eax
         // 00459431: call ??$?RV_lambda_0fef6fff2b5e6b53303c9058db11ae1f_@@AAV_lambda_082c17da81b0962e08c0587ee0fac50c_@@V_lambda_fa6e051aed0a38726081083cc7c328e9_@@@?$__crt_seh_guarded_call@PAD@@QAEPAD$$QAV_lambda_0fef6fff2b5e6b53303c9058db11ae1f_@@AAV_lambda_082c17da81b0962e08c0587ee0fac50c_@@$$QAV_lambda_fa6e051aed0a38726081083cc7c328e9_@@@Z_0
         // 00459436: mov esp, ebp
         // 00459438: pop ebp
         // 00459439: retn 
      [-]8bff558bec83ec0c8b45088d4dff8945f88945f48d45f850ff750c8d45f450e812ffffff8be55dc3
         // 0045943a: mov edi, edi
         // 0045943c: push ebp
         // 0045943d: mov ebp, esp
         // 0045943f: sub esp, 0xc
         // 00459442: mov eax, ss:[ebp+0x8]
         // 00459445: lea ecx, ss:[ebp+0xffffffffffffffff]
         // 00459448: mov ss:[ebp+0xfffffffffffffff8], eax
         // 0045944b: mov ss:[ebp+0xfffffffffffffff4], eax
         // 0045944e: lea eax, ss:[ebp+0xfffffffffffffff8]
         // 00459451: push eax
         // 00459452: push ss:[ebp+0xc]
         // 00459455: lea eax, ss:[ebp+0xfffffffffffffff4]
         // 00459458: push eax
         // 00459459: call ??$?RV_lambda_0fef6fff2b5e6b53303c9058db11ae1f_@@AAV_lambda_082c17da81b0962e08c0587ee0fac50c_@@V_lambda_fa6e051aed0a38726081083cc7c328e9_@@@?$__crt_seh_guarded_call@PAD@@QAEPAD$$QAV_lambda_0fef6fff2b5e6b53303c9058db11ae1f_@@AAV_lambda_082c17da81b0962e08c0587ee0fac50c_@@$$QAV_lambda_fa6e051aed0a38726081083cc7c328e9_@@@Z
         // 0045945e: mov esp, ebp
         // 00459460: pop ebp
         // 00459461: retn 
      [-]8bff558becff750868
         // 004440f0: mov edi, edi
         // 004440f2: push ebp
         // 004440f3: mov ebp, esp
         // 004440f5: push ss:[ebp+0x8]
         // 004440f8: push stru_60F2D0._first
      [-]e85e00000059595dc3
         // 004440fd: call __register_onexit_function
         // 00444102: pop ecx
         // 00444103: pop ecx
         // 00444104: pop ebp
         // 00444105: retn 
      [-]8bff558bec83ec0c8b45088d4dff8945f88945f48d45f850ff750c8d45f450e8
         // 0045ba66: mov edi, edi
         // 0045ba68: push ebp
         // 0045ba69: mov ebp, esp
         // 0045ba6b: sub esp, 0xc
         // 0045ba6e: mov eax, ss:[ebp+0x8]
         // 0045ba71: lea ecx, ss:[ebp+0xffffffffffffffff]
         // 0045ba74: mov ss:[ebp+0xfffffffffffffff8], eax
         // 0045ba77: mov ss:[ebp+0xfffffffffffffff4], eax
         // 0045ba7a: lea eax, ss:[ebp+0xfffffffffffffff8]
         // 0045ba7d: push eax
         // 0045ba7e: push ss:[ebp+0xc]
         // 0045ba81: lea eax, ss:[ebp+0xfffffffffffffff4]
         // 0045ba84: push eax
         // 0045ba85: call ??$?RV_lambda_51b6e8b1eb166f2a3faf91f424b38130_@@AAV_lambda_6250bd4b2a391816dd638c3bf72b0bcb_@@V_lambda_0b5a4a3e68152e1d9b943535f5f47bed_@@@?$__crt_seh_guarded_call@X@@QAEX$$QAV_lambda_51b6e8b1eb166f2a3faf91f424b38130_@@AAV_lambda_6250bd4b2a391816dd638c3bf72b0bcb_@@$$QAV_lambda_0b5a4a3e68152e1d9b943535f5f47bed_@@@Z
      [-]8bff558bec83ec0c8b45088d4dff8945f88945f48d45f850ff750c8d45f450e8
         // 0045ba8e: mov edi, edi
         // 0045ba90: push ebp
         // 0045ba91: mov ebp, esp
         // 0045ba93: sub esp, 0xc
         // 0045ba96: mov eax, ss:[ebp+0x8]
         // 0045ba99: lea ecx, ss:[ebp+0xffffffffffffffff]
         // 0045ba9c: mov ss:[ebp+0xfffffffffffffff8], eax
         // 0045ba9f: mov ss:[ebp+0xfffffffffffffff4], eax
         // 0045baa2: lea eax, ss:[ebp+0xfffffffffffffff8]
         // 0045baa5: push eax
         // 0045baa6: push ss:[ebp+0xc]
         // 0045baa9: lea eax, ss:[ebp+0xfffffffffffffff4]
         // 0045baac: push eax
         // 0045baad: call ??$?RV_lambda_3518db117f0e7cdb002338c5d3c47b6c_@@AAV_lambda_b2ea41f6bbb362cd97d94c6828d90b61_@@V_lambda_abdedf541bb04549bc734292b4a045d4_@@@?$__crt_seh_guarded_call@X@@QAEX$$QAV_lambda_3518db117f0e7cdb002338c5d3c47b6c_@@AAV_lambda_b2ea41f6bbb362cd97d94c6828d90b61_@@$$QAV_lambda_abdedf541bb04549bc734292b4a045d4_@@@Z
      [-]feffff8be55dc3
         // 0045bab2: mov esp, ebp
         // 0045bab4: pop ebp
         // 0045bab5: retn 
      [-]558bec8b45088945f4
         // 0045bab8: push ebp
         // 0045bab9: mov ebp, esp
         // 0045babb: sub esp, 0xc
         // 0045babe: mov eax, ss:[ebp+0x8]
         // 0045bac4: mov ss:[ebp+0xfffffffffffffff8], eax
         // 0045bac7: mov ss:[ebp+0xfffffffffffffff4], eax
      [-]feffff8be55dc3
         // 0045bada: mov esp, ebp
         // 0045badc: pop ebp
         // 0045badd: retn 
      [-]558bec568b750c8b063b05
         // 004528ed: push ebp
         // 004528ee: mov ebp, esp
         // 004528f0: push esi
         // 004528f1: mov esi, ss:[ebp+0xc]
         // 004528f4: mov eax, ds:[esi]
         // 004528f6: cmp eax, ds:[0x60f740]
      [-]8b4d08a1
         // 004528fe: mov ecx, ss:[ebp+0x8]
         // 00452901: mov eax, ds:[0x60e900]
      [-]8581????????7507
         // 00452906: test ds:[ecx+0x350], eax
         // 0045290c: jnz 0x452915
      [-]558bec568b750c8b063b05
         // 0045291a: push ebp
         // 0045291b: mov ebp, esp
         // 0045291d: push esi
         // 0045291e: mov esi, ss:[ebp+0xc]
         // 00452921: mov eax, ds:[esi]
         // 00452923: cmp eax, ds:[0x60e7d8]
      [-]8b4d08a1
         // 0045292b: mov ecx, ss:[ebp+0x8]
         // 0045292e: mov eax, ds:[0x60e900]
      [-]8581????????7507
         // 00452933: test ds:[ecx+0x350], eax
         // 00452939: jnz 0x452942
      [-]8bff558bec8d4dff
         // 00456431: mov edi, edi
         // 00456433: push ebp
         // 00456434: mov ebp, esp
         // 00456436: lea ecx, ss:[ebp+0xffffffffffffffff]
      [-]50e844ffffff8be55dc3
         // 0045644f: push eax
         // 00456450: call ??$?RV_lambda_61cee617f5178ae960314fd4d05640a0_@@AAV_lambda_6978c1fb23f02e42e1d9e99668cc68aa_@@V_lambda_9cd88cf8ad10232537feb2133f08c833_@@@?$__crt_seh_guarded_call@H@@QAEH$$QAV_lambda_61cee617f5178ae960314fd4d05640a0_@@AAV_lambda_6978c1fb23f02e42e1d9e99668cc68aa_@@$$QAV_lambda_9cd88cf8ad10232537feb2133f08c833_@@@Z
         // 00456455: mov esp, ebp
         // 00456457: pop ebp
         // 00456458: retn 
      [-]8b5424088d420c8b4a
         // 006a435d: mov edx, ss:[esp+0x8]
         // 006a4361: lea eax, ds:[edx+0xc]
         // 006a4364: mov ecx, ds:[edx+0xffffffffffffffc4]

  }
  condition:
    all of them
}
