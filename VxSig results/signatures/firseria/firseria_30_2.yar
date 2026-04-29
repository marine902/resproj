rule firseria_30_2 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         558bec568bf1c706
         // 0040f988: push ebp
         // 0040f989: mov ebp, esp
         // 0040f98b: push esi
         // 0040f98c: mov esi, ecx
         // 0040f98e: mov ds:[esi], ??_7exception@std@@6B@
      [-]f64508017407
         // 0040f999: test b1 ss:[ebp+0x8], b1 0x1
         // 0040f99d: jz 0x40f9a6
      [-]8bc65e5dc20400
         // 0040c5ce: mov eax, esi
         // 0040c5d0: pop esi
         // 0040c5d1: pop ebp
         // 0040c5d2: retn b2 0x4
      [-]558bec83ec08535657fc8945fc33c0505050ff75fcff7514ff7510ff750cff7508e8
         // 00411fd2: push ebp
         // 00411fd3: mov ebp, esp
         // 00411fd5: sub esp, 0x8
         // 00411fd8: push ebx
         // 00411fd9: push esi
         // 00411fda: push edi
         // 00411fdb: cld 
         // 00411fdc: mov ss:[ebp+0xfffffffffffffffc], eax
         // 00411fdf: xor eax, eax
         // 00411fe1: push eax
         // 00411fe2: push eax
         // 00411fe3: push eax
         // 00411fe4: push ss:[ebp+0xfffffffffffffffc]
         // 00411fe7: push ss:[ebp+0x14]
         // 00411fea: push ss:[ebp+0x10]
         // 00411fed: push ss:[ebp+0xc]
         // 00411ff0: push ss:[ebp+0x8]
         // 00411ff3: call ___InternalCxxFrameHandler
      [-]000083c4208945f85f5e5b8b45f88be55dc3
         // 00411ff8: add esp, 0x20
         // 00411ffb: mov ss:[ebp+0xfffffffffffffff8], eax
         // 00411ffe: pop edi
         // 00411fff: pop esi
         // 00412000: pop ebx
         // 00412001: mov eax, ss:[ebp+0xfffffffffffffff8]
         // 00412004: mov esp, ebp
         // 00412006: pop ebp
         // 00412007: retn 

  }
  condition:
    all of them
}
