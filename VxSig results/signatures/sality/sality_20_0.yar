rule sality_20_0 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         8b4c240c
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
