rule salgorea_20_3 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         0fb6d0888c15fcfeffff
         // 004010e0: movzx edx, b1 al
         // 004010e3: mov b1 ss:[ebp+edx+0xfffffffffffffefc], b1 cl
      [-]8bff558bec56ff75088bf1e8
         // 00411a83: mov edi, edi
         // 00411a85: push ebp
         // 00411a86: mov ebp, esp
         // 00411a88: push esi
         // 00411a89: push ss:[ebp+0x8]
         // 00411a8c: mov esi, ecx
         // 00411a8e: call ??0exception@std@@QAE@ABV01@@Z
      [-]008bc65e5dc20400
         // 00411a99: mov eax, esi
         // 00411a9b: pop esi
         // 00411a9c: pop ebp
         // 00411a9d: retn b2 0x4
      [-]8b5424088d420c8b4a
         // 00422ee0: mov edx, ss:[esp+0x8]
         // 00422ee4: lea eax, ds:[edx+0xc]
         // 00422ee7: mov ecx, ds:[edx+0xffffffffffffffd4]

  }
  condition:
    all of them
}
