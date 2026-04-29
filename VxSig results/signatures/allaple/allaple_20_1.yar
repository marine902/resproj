rule allaple_20_1 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         c0b004014424
         // 00402b90: mov b1 al, b1 0x4
         // 00402b92: add ss:[esp+0xffffffffffffffdc], eax
      [-]c0b004014424
         // 00403746: mov b1 al, b1 0x4
         // 00403748: add ss:[esp+0xffffffffffffffdc], eax
      [-]c0b004014424
         // 00403a04: mov b1 al, b1 0x4
         // 00403a06: add ss:[esp+0xffffffffffffffdc], eax
      [-]b004014424
         // 00403a53: mov b1 al, b1 0x4
         // 00403a55: add ss:[esp+0xffffffffffffffdc], eax
         // 00403a5c: mov eax, ss:[esp+0xffffffffffffffdc]
      [-]c0b004014424
         // 00403c66: mov b1 al, b1 0x4
         // 00403c68: add ss:[esp+0xffffffffffffffdc], eax
      [-]33c0b004014424
         // 00403d16: xor eax, eax
         // 00403d18: mov b1 al, b1 0x4
         // 00403d1a: add ss:[esp+0xffffffffffffffdc], eax
         // 00403d58: add ss:[esp+0xffffffffffffffdc], ebx
      [-]b004014424
         // 00403de1: mov b1 al, b1 0x4
         // 00403de3: add ss:[esp+0xffffffffffffffdc], eax
      [-]c0b004014424
         // 00403e2f: mov b1 al, b1 0x4
         // 00403e31: add ss:[esp+0xffffffffffffffdc], eax

  }
  condition:
    all of them
}
