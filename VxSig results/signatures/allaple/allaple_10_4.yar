rule allaple_10_4 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         33c0b004014424
         // 00401aba: xor eax, eax
         // 00401abc: mov b1 al, b1 0x4
         // 00401abe: add ss:[esp+0xffffffffffffffcc], eax
      [-]33c0b004014424
         // 00403515: xor eax, eax
         // 00403517: mov b1 al, b1 0x4
         // 00403519: add ss:[esp+0xffffffffffffffcc], eax
      [-]33c0b004014424
         // 004037be: xor eax, eax
         // 004037c0: mov b1 al, b1 0x4
         // 004037c2: add ss:[esp+0xffffffffffffffcc], eax
      [-]33c0b004
         // 00403861: xor eax, eax
         // 00403863: mov b1 al, b1 0x4
      [-]33c0b004
         // 00403949: xor eax, eax
         // 0040394b: mov b1 al, b1 0x4
      [-]8bf4a558
         // 00403afe: mov esi, esp
         // 00403b00: movsdd 
         // 00403b01: pop eax
      [-]b004014424
         // 00403bb4: mov b1 al, b1 0x4
         // 00403bb6: add ss:[esp+0xffffffffffffffcc], eax
      [-]33c0b004
         // 00403bff: xor eax, eax
         // 00403c01: mov b1 al, b1 0x4
      [-]33c0b004014424
         // 00403c6d: xor eax, eax
         // 00403c6f: mov b1 al, b1 0x4
         // 00403c71: add ss:[esp+0xffffffffffffffcc], eax
         // 00403c78: mov eax, ss:[esp+0xffffffffffffffcc]
      [-]33c0b004014424
         // 00403d2e: xor eax, eax
         // 00403d30: mov b1 al, b1 0x4
         // 00403d32: add ss:[esp+0xffffffffffffffcc], eax
      [-]33c0b004014424
         // 00403e38: xor eax, eax
         // 00403e3a: mov b1 al, b1 0x4
         // 00403e3c: add ss:[esp+0xffffffffffffffcc], eax
      [-]33c0b004014424
         // 00403f0f: xor eax, eax
         // 00403f11: mov b1 al, b1 0x4
         // 00403f13: add ss:[esp+0xffffffffffffffcc], eax
      [-]33c0b004014424
         // 00403f70: xor eax, eax
         // 00403f72: mov b1 al, b1 0x4
         // 00403f74: add ss:[esp+0xffffffffffffffcc], eax

  }
  condition:
    all of them
}
