rule midie_20_1 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         0033c0c3
         // 0040afd4: xor eax, eax
         // 0040afd6: retn 
      [-]85c07402
         // 00416e1c: test eax, eax
         // 00416e1e: jz 0x416e22
      [-]85c07402
         // 00416e42: test eax, eax
         // 00416e44: jz 0x416e48

  }
  condition:
    all of them
}
