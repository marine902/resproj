rule symmi_10_4 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         803bcc0f85
         // 0089d0c2: cmp b1 ds:[ebx], b1 0xcc
         // 0089d0c5: jnz 0x89d167
      [-]85c90f84
         // 008ba22c: test ecx, ecx
         // 008ba22e: jz 0x8ba2bc
      [-]c9c21000
         // 008ba314: leave 
         // 008ba315: retn b2 0x10

  }
  condition:
    all of them
}
