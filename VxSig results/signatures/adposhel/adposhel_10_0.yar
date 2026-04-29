rule adposhel_10_0 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         00008365fc00
         // 3d702804: and ss:[ebp+0xfffffffffffffffc], 0x0
      [-]3bf37318
         // 3a3f3c52: cmp esi, ebx
         // 3a3f3c54: jnb 0x3a3f3c6e
      [-]8b3e85ff7409
         // 3d7114ae: mov edi, ds:[esi]
         // 3d7114b0: test edi, edi
         // 3d7114b2: jz 0x3d7114bd
      [-]ffffffd7
         // 3a3f3c64: call edi
      [-]83c6043bf372ea
         // 3d7114bd: add esi, 0x4
         // 3d7114c0: cmp esi, ebx
         // 3d7114c2: jb 0x3d7114ae
      [-]8bff558bec83ec0c8b45088d4dff8945f88945f48d45f850ff750c8d45f450e844ffffff8be55dc3
         // 3d74cdbe: mov edi, edi
         // 3d74cdc0: push ebp
         // 3d74cdc1: mov ebp, esp
         // 3d74cdc3: sub esp, 0xc
         // 3d74cdc6: mov eax, ss:[ebp+0x8]
         // 3d74cdc9: lea ecx, ss:[ebp+0xffffffffffffffff]
         // 3d74cdcc: mov ss:[ebp+0xfffffffffffffff8], eax
         // 3d74cdcf: mov ss:[ebp+0xfffffffffffffff4], eax
         // 3d74cdd2: lea eax, ss:[ebp+0xfffffffffffffff8]
         // 3d74cdd5: push eax
         // 3d74cdd6: push ss:[ebp+0xc]
         // 3d74cdd9: lea eax, ss:[ebp+0xfffffffffffffff4]
         // 3d74cddc: push eax
         // 3d74cddd: call ??$?RV_lambda_61cee617f5178ae960314fd4d05640a0_@@AAV_lambda_6978c1fb23f02e42e1d9e99668cc68aa_@@V_lambda_9cd88cf8ad10232537feb2133f08c833_@@@?$__crt_seh_guarded_call@H@@QAEH$$QAV_lambda_61cee617f5178ae960314fd4d05640a0_@@AAV_lambda_6978c1fb23f02e42e1d9e99668cc68aa_@@$$QAV_lambda_9cd88cf8ad10232537feb2133f08c833_@@@Z
         // 3d74cde2: mov esp, ebp
         // 3d74cde4: pop ebp
         // 3d74cde5: retn 

  }
  condition:
    all of them
}
