rule firseria_10_0 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         c74614????????6689068b
         // 0040131f: mov ds:[esi+0x14], 0x7
         // 00401327: mov b2 ds:[esi], b2 ax
         // 0040132f: mov eax, esi
      [-]837f1408
         // 0040134a: cmp ds:[edi+0x14], 0x8
      [-]ffff85c074
         // 00401420: test eax, eax
         // 00401422: jz 0x401437
      [-]837f14087202
         // 00401460: cmp ds:[edi+0x14], 0x8
         // 00401464: jb 0x401468
      [-]b001eb02
         // 0040166d: mov b1 al, b1 0x1
         // 0040166f: jmp 0x401673
      [-]00005985
         // 004017cd: pop ecx
         // 004017ce: test eax, eax
      [-]558bec83e4f8b8
         // 00403ff0: push ebp
         // 00403ff1: mov ebp, esp
         // 00403ff3: and esp, 0xfffffffffffffff8
         // 00403ff6: mov eax, 0x812c
      [-]508d8424??
         // 00403dfe: push eax
         // 00403dff: lea eax, ss:[esp+0x400]
      [-]68????????ff
         // 00403871: push 0x104
         // 00403876: call ds:[GetTempPathW]
      [-]8be55dc21000
         // 00403ecb: mov esp, ebp
         // 00403ecd: pop ebp
         // 00403ece: retn b2 0x10
      [-]558bec81ec
         // 00406837: push ebp
         // 00406838: mov ebp, esp
         // 0040683a: sub esp, 0x4c0
      [-]68????????
         // 0040695b: push 0x20019
      [-]6a045839
         // 004068e8: push 0x4
         // 004068ea: pop eax
         // 004068eb: cmp ss:[ebp+0xfffffffffffffb50], eax
      [-]6a4050e8
         // 0040724c: push 0x40
         // 0040724e: push eax
         // 0040724f: call _swprintf
      [-]83c4148d
         // 00407254: add esp, 0x14
         // 00407257: lea eax, ss:[ebp+0xffffffffffffff74]
      [-]42006633
         // 0040727e: xor b2 cx, b2 ds:[0x427578+edx*0x2]
      [-]000083c40c8d
         // 00406a82: add esp, 0xc
         // 00406a85: lea eax, ss:[ebp+0xfffffffffffff6b0]
      [-]ffff6a0e
         // 0040742e: push 0xe
      [-]feffff8b
         // 0040743a: mov ecx, eax
      [-]5356576a07
         // 00406c9c: push ebx
         // 00406c9d: push esi
         // 00406c9e: push edi
         // 00406c9f: push 0x7
      [-]ffff6a07
         // 00407d93: push 0x7
      [-]faffff50
         // 00407df0: push eax
      [-]ffff85c075
         // 00407e08: test eax, eax
         // 00407e0a: jnz 0x407e37
      [-]ffff85c075
         // 00406f73: test eax, eax
         // 00406f75: jnz 0x406f91
      [-]ffff6a07
         // 00406f34: push 0x7
      [-]f8ffff85c075
         // 00406f57: test eax, eax
         // 00406f59: jnz 0x406f93
      [-]ffff85c075
         // 00406fdf: test eax, eax
         // 00406fe1: jnz 0x40700a
      [-]6a025839
         // 00406ffc: push 0x2
         // 00406ffe: pop eax
         // 00406fff: cmp ds:[edi+0x3c], eax
      [-]ffff6a09
         // 00406fb4: push 0x9
      [-]f7ffff85c075
         // 00406fd7: test eax, eax
         // 00406fd9: jnz 0x407016
      [-]ffff85c075
         // 0040705f: test eax, eax
         // 00407061: jnz 0x40708a
      [-]6a025839
         // 0040707c: push 0x2
         // 0040707e: pop eax
         // 0040707f: cmp ds:[edi+0x3c], eax
      [-]00005933c0c3
         // 0040976e: pop ecx
         // 0040976f: xor eax, eax
         // 00409771: retn 
      [-]558bec568bf1c706
         // 0040bc14: push ebp
         // 0040bc15: mov ebp, esp
         // 0040bc17: push esi
         // 0040bc18: mov esi, ecx
         // 0040bc1a: mov ds:[esi], ??_7exception@std@@6B@
      [-]f64508017407
         // 0040bc25: test b1 ss:[ebp+0x8], b1 0x1
         // 0040bc29: jz 0x40bc32
      [-]8bc65e5dc20400
         // 0040b77c: mov eax, esi
         // 0040b77e: pop esi
         // 0040b77f: pop ebp
         // 0040b780: retn b2 0x4
      [-]000059c3
         // 0040c0e0: pop ecx
         // 0040c0e1: retn 
      [-]558bec568bf1e8
         // 0041036c: push ebp
         // 0041036d: mov ebp, esp
         // 0041036f: push esi
         // 00410370: mov esi, ecx
         // 00410372: call 0x410340
      [-]fffffff64508017407
         // 00410377: test b1 ss:[ebp+0x8], b1 0x1
         // 0041037b: jz 0x410384
      [-]ffffff59
         // 0040bc3b: pop ecx
      [-]8bc65e5dc20400
         // 0040bc3c: mov eax, esi
         // 0040bc3e: pop esi
         // 0040bc3f: pop ebp
         // 0040bc40: retn b2 0x4
      [-]85c07402
         // 00414cb9: test eax, eax
         // 00414cbb: jz 0x414cbf
      [-]83f8ff740c
         // 0041def5: cmp eax, 0xffffffffffffffff
         // 0041def8: jz 0x41df06
      [-]83f8fe7407
         // 0041ccda: cmp eax, 0xfffffffffffffffe
         // 0041ccdd: jz 0x41cce6

  }
  condition:
    all of them
}
