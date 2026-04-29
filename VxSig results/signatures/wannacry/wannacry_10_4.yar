rule wannacry_10_4 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         68????????
         // 00401cf4: push 0xf003f
      [-]5356578b
         // 00402a80: push ebx
         // 00402a81: push esi
         // 00402a82: push edi
         // 00402a83: mov esi, ecx

  }
  condition:
    all of them
}
