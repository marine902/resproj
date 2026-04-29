rule allaple_10_2 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         04014c24
         // 004019af: mov b1 dl, b1 0x4
         // 004019b1: add ss:[esp+0xffffffffffffffc8], edx
         // 004019b8: mov ecx, ss:[esp+0xffffffffffffffc8]
         // 004019ca: add ss:[esp+0xffffffffffffffc8], ebx
      [-]d2b20401
         // 00401df6: mov b1 dl, b1 0x4
         // 00401df8: add ss:[esp+0xffffffffffffffc8], edx
      [-]c0b004014424
         // 00401f45: mov b1 al, b1 0x4
         // 00401f47: add ss:[esp+0xffffffffffffffc8], eax
      [-]dbb304015c24
         // 00401fd2: mov b1 bl, b1 0x4
         // 00401fd4: add ss:[esp+0xffffffffffffffc8], ebx
      [-]b004014424
         // 00402078: mov b1 al, b1 0x4
         // 0040207a: add ss:[esp+0xffffffffffffffc8], eax
      [-]d2b20401
         // 004024f8: mov b1 dl, b1 0x4
         // 00402510: mov b1 al, b1 0x4
         // 00402512: add ss:[esp+0xffffffffffffffc8], eax
      [-]33d2b204015424
         // 0040263a: xor edx, edx
         // 0040263c: mov b1 dl, b1 0x4
         // 0040263e: add ss:[esp+0xffffffffffffffc8], edx
      [-]c0b004014424
         // 00402d1c: mov b1 al, b1 0x4
         // 00402d1e: add ss:[esp+0xffffffffffffffc8], eax
         // 00402d27: mov edx, ss:[esp+0xffffffffffffffc8]
      [-]33dbb30401
         // 00402de3: xor ebx, ebx
         // 00402de5: mov b1 bl, b1 0x4
         // 00402de7: add ss:[esp+0xffffffffffffffc8], ebx
      [-]33c0b004014424
         // 00402f2e: xor eax, eax
         // 00402f30: mov b1 al, b1 0x4
         // 00402f32: add ss:[esp+0xffffffffffffffc8], eax
         // 00402f39: mov eax, ss:[esp+0xffffffffffffffc8]
      [-]c0b004014424
         // 00403058: mov b1 al, b1 0x4
         // 0040305a: add ss:[esp+0xffffffffffffffc8], eax
         // 00403060: mov ebx, ss:[esp+0xffffffffffffffc8]
      [-]33c0b004014424
         // 0040354e: xor eax, eax
         // 00403550: mov b1 al, b1 0x4
         // 00403552: add ss:[esp+0xffffffffffffffc8], eax
      [-]33c9b104014c24
         // 004037d7: xor ecx, ecx
         // 004037d9: mov b1 cl, b1 0x4
         // 004037db: add ss:[esp+0xffffffffffffffc8], ecx
      [-]33c9b104014c24
         // 00403935: xor ecx, ecx
         // 00403937: mov b1 cl, b1 0x4
         // 00403939: add ss:[esp+0xffffffffffffffc8], ecx
      [-]33c0b004
         // 00403be4: xor eax, eax
         // 00403be6: mov b1 al, b1 0x4
      [-]c0b004014424
         // 00403c4e: mov b1 al, b1 0x4
         // 00403c50: add ss:[esp+0xffffffffffffffc8], eax
      [-]04014424
         // 00403dcb: mov b1 dl, b1 0x4
         // 00403dcd: add ss:[esp+0xffffffffffffffc8], edx
         // 00403dd4: mov eax, ss:[esp+0xffffffffffffffc8]
      [-]33c0b004014424
         // 00403e1f: xor eax, eax
         // 00403e21: mov b1 al, b1 0x4
         // 00403e23: add ss:[esp+0xffffffffffffffc8], eax
      [-]b004014424
         // 00403f49: mov b1 al, b1 0x4
         // 00403f4b: add ss:[esp+0xffffffffffffffc8], eax
      [-]33c0b004014424
         // 00403f97: xor eax, eax
         // 00403f99: mov b1 al, b1 0x4
         // 00403f9b: add ss:[esp+0xffffffffffffffc8], eax

  }
  condition:
    all of them
}
