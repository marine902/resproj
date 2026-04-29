rule pioneer_20_0 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         508b442404
         // 00409751: push eax
         // 00409752: mov eax, ss:[esp+0x4]
      [-]508b44240483c004508b442404c20800
         // 0040977f: push eax
         // 00409780: mov eax, ss:[esp+0x4]
         // 00409784: add eax, 0x4
         // 00409787: push eax
         // 00409788: mov eax, ss:[esp+0x4]
         // 0040978c: retn b2 0x8
      [-]e841deffffc3
         // 0040b917: call 0x40975d
         // 0040b91c: retn 

  }
  condition:
    all of them
}
