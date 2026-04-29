rule allaple_30_0 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         c0b004014424
         // 00403350: mov b1 al, b1 0x4
         // 00403352: add ss:[esp+0xffffffffffffffdc], eax
      [-]33c0b004014424
         // 00403c64: xor eax, eax
         // 00403c66: mov b1 al, b1 0x4
         // 00403c68: add ss:[esp+0xffffffffffffffdc], eax
         // 00403c6e: mov eax, ss:[esp+0xffffffffffffffdc]
      [-]33c0b004014424
         // 00403ddf: xor eax, eax
         // 00403de1: mov b1 al, b1 0x4
         // 00403de3: add ss:[esp+0xffffffffffffffdc], eax
      [-]b004014424
         // 00403df9: mov b1 al, b1 0x4
         // 00403dfb: add ss:[esp+0xffffffffffffffdc], eax
      [-]b004014424
         // 00403e2f: mov b1 al, b1 0x4
         // 00403e31: add ss:[esp+0xffffffffffffffdc], eax

  }
  condition:
    all of them
}
