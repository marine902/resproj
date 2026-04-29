rule softpulse_10_3 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         5dc20400
         // 004047b5: pop ebp
         // 004047b6: retn b2 0x4
      [-]68????????e8
         // 0040186b: push 0xffffffff80070057
         // 00401870: call ?AtlThrowImpl@ATL@@YGXJ@Z
      [-]5dc20800
         // 00402b10: pop ebp
         // 00402b11: retn b2 0x8
      [-]000059c3
         // 00406a30: pop ecx
         // 00406a31: retn 
      [-]558bec568bf1e8
         // 00408b39: push ebp
         // 00408b3a: mov ebp, esp
         // 00408b3c: push esi
         // 00408b3d: mov esi, ecx
         // 00408b3f: call 0x408ae9
      [-]fffffff64508017407
         // 00408b44: test b1 ss:[ebp+0x8], b1 0x1
         // 00408b48: jz 0x408b51
      [-]8bc65e5dc20400
         // 00415745: mov eax, esi
         // 00415747: pop esi
         // 00415748: pop ebp
         // 00415749: retn b2 0x4
      [-]85c07402
         // 0041bdb6: test eax, eax
         // 0041bdb8: jz 0x41bdbc
      [-]558bec83ec
         // 00410adc: push ebp
         // 00410add: mov ebp, esp
         // 00410adf: sub esp, 0x44
      [-]4083f8037cf4
         // 00426210: inc eax
         // 00426211: cmp eax, 0x3
         // 00426214: jl 0x42620a
      [-]996a1f5923d103
         // 00410bcc: cdq 
         // 00410bcd: push 0x1f
         // 00410bcf: pop ecx
         // 00410bd0: and edx, ecx
         // 00410bd2: add edx, eax
      [-]2bc833c0f3ab
         // 00410c68: sub ecx, eax
         // 00410c6a: xor eax, eax
         // 00410c6c: rep stosdd 
      [-]33c08d7d
         // 00426343: xor eax, eax
         // 00426345: lea edi, ss:[ebp+0xffffffffffffffe0]
      [-]83e21f03c2
         // 0041274a: and edx, 0x1f
         // 0041274d: add eax, edx
      [-]83cfff8b
         // 00410cd2: or edi, 0xffffffffffffffff
         // 00410cda: mov ecx, edi
      [-]8bc19983e21f03
         // 004263f6: mov eax, ecx
         // 004263f8: cdq 
         // 004263f9: and edx, 0x1f
         // 004263fc: add eax, edx
      [-]5923d103
         // 00412832: pop ecx
         // 00412833: and edx, ecx
         // 00412835: add edx, eax
      [-]33c0f3ab
         // 00410e23: xor eax, eax
         // 00410e25: rep stosdd 
      [-]418bc19983e21f03c2
         // 00412580: inc ecx
         // 00412581: mov eax, ecx
         // 00412583: cdq 
         // 00412584: and edx, 0x1f
         // 00412587: add eax, edx
      [-]9983e21f03c2
         // 00410edf: cdq 
         // 00410ee0: and edx, 0x1f
         // 00410ee3: add eax, edx
      [-]83cfffd3e7
         // 00410ef8: or edi, 0xffffffffffffffff
         // 00410efb: shl edi, b1 cl
      [-]9983e21f
         // 00410f81: cdq 
         // 00410f82: and edx, 0x1f

  }
  condition:
    all of them
}
