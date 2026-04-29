rule allaple_10_1 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         33c0b004014424
         // 00401f8a: xor eax, eax
         // 00401f8c: mov b1 al, b1 0x4
         // 00401f8e: add ss:[esp+0xffffffffffffffdc], eax
      [-]33c0b004014424
         // 00402dd6: xor eax, eax
         // 00402dd8: mov b1 al, b1 0x4
         // 00402dda: add ss:[esp+0xffffffffffffffdc], eax
      [-]c0b004014424
         // 0040307c: mov b1 al, b1 0x4
         // 0040307e: add ss:[esp+0xffffffffffffffdc], eax
      [-]c0b004014424
         // 00403760: mov b1 al, b1 0x4
         // 00403762: add ss:[esp+0xffffffffffffffdc], eax
      [-]33c0b004014424
         // 004037e6: xor eax, eax
         // 004037e8: mov b1 al, b1 0x4
         // 004037ea: add ss:[esp+0xffffffffffffffdc], eax
      [-]33c0b004
         // 0040392b: xor eax, eax
         // 0040392d: mov b1 al, b1 0x4
      [-]8bf4a558
         // 00403a4a: mov esi, esp
         // 00403a4c: movsdd 
         // 00403a4d: pop eax
      [-]33c0b004014424
         // 00403a51: xor eax, eax
         // 00403a53: mov b1 al, b1 0x4
         // 00403a55: add ss:[esp+0xffffffffffffffdc], eax
      [-]33c0b004014424
         // 00403a6e: xor eax, eax
         // 00403a70: mov b1 al, b1 0x4
         // 00403a72: add ss:[esp+0xffffffffffffffdc], eax
      [-]8bf4a558
         // 00403d2a: mov esi, esp
         // 00403d2c: movsdd 
         // 00403d2d: pop eax
      [-]33c0b004014424
         // 00403ddf: xor eax, eax
         // 00403de1: mov b1 al, b1 0x4
         // 00403de3: add ss:[esp+0xffffffffffffffdc], eax
      [-]b004014424
         // 00403e5f: mov b1 al, b1 0x4
         // 00403e61: add ss:[esp+0xffffffffffffffdc], eax
         // 00403e68: mov eax, ss:[esp+0xffffffffffffffdc]
      [-]33c0b004
         // 00403fbf: xor eax, eax
         // 00403fc1: mov b1 al, b1 0x4
         // 00403fe2: mov b1 bl, b1 0x4

  }
  condition:
    all of them
}
