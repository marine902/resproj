rule allaple_20_0 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         33c0b004014424
         // 00403188: xor eax, eax
         // 0040318a: mov b1 al, b1 0x4
         // 0040318c: add ss:[esp+0xffffffffffffffdc], eax
      [-]c0b004014424
         // 00403760: mov b1 al, b1 0x4
         // 00403762: add ss:[esp+0xffffffffffffffdc], eax
      [-]b004014424
         // 004037e8: mov b1 al, b1 0x4
         // 004037ea: add ss:[esp+0xffffffffffffffdc], eax
      [-]33c0b00401
         // 0040392b: xor eax, eax
         // 0040392d: mov b1 al, b1 0x4
         // 0040394a: add ss:[esp+0xffffffffffffffdc], ecx
      [-]8bf4a558
         // 00403d68: mov esi, esp
         // 00403d6a: movsdd 
         // 00403d6b: pop eax
      [-]33c0b004
         // 00403df7: xor eax, eax
         // 00403df9: mov b1 al, b1 0x4
      [-]04014424
         // 00403f8b: mov b1 al, b1 0x4
         // 00403f8d: add ss:[esp+0xffffffffffffffdc], eax

  }
  condition:
    all of them
}
