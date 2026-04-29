rule softpulse_10_1 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         5dc20400
         // 0044f6c2: pop ebp
         // 0044f6c3: retn b2 0x4
      [-]85c07402
         // 0046ad93: test eax, eax
         // 0046ad95: jz 0x46ad99

  }
  condition:
    all of them
}
