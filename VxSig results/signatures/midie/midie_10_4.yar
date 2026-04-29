rule midie_10_4 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         000083c404
         // 0040762c: add esp, 0x4
      [-]000083c404
         // 004077f5: add esp, 0x4
      [-]83c40485
         // 0040f177: add esp, 0x4
         // 0040f17a: test edi, edi
      [-]8b308b4ef08b118b42108b5ef483ee1057ffd08b
         // 0040f718: mov esi, ds:[eax]
         // 0040f71a: mov ecx, ds:[esi+0xfffffffffffffff0]
         // 0040f71d: mov edx, ds:[ecx]
         // 0040f71f: mov eax, ds:[edx+0x10]
         // 0040f722: mov ebx, ds:[esi+0xfffffffffffffff4]
         // 0040f725: sub esi, 0x10
         // 0040f728: push edi
         // 0040f729: call eax
         // 0040f72b: mov ecx, ss:[ebp+0xc]
      [-]8bf885ff7505
         // 0040f739: mov edi, eax
         // 0040f73b: test edi, edi
         // 0040f73d: jnz 0x40f744
      [-]e87c000000
         // 0040f73f: call 0x40f7c0
      [-]000083c410895f048d
         // 0040f760: add esp, 0x10
         // 0040f763: mov ds:[edi+0x4], ebx
         // 0040f766: lea eax, ds:[esi+0xc]
      [-]fff00fc1
         // 0040f76c: lock xadd ds:[eax], ecx
      [-]8b0e8b118b420456ffd0
         // 0040f775: mov ecx, ds:[esi]
         // 0040f777: mov edx, ds:[ecx]
         // 0040f779: mov eax, ds:[edx+0x4]
         // 0040f77c: push esi
         // 0040f77d: call eax
      [-]5dc20800
         // 0040f78a: pop ebp
         // 0040f78b: retn b2 0x8
      [-]8b068b48f083e8103950087d15
         // 0040f790: mov eax, ds:[esi]
         // 0040f792: mov ecx, ds:[eax+0xfffffffffffffff0]
         // 0040f795: sub eax, 0x10
         // 0040f798: cmp ds:[eax+0x8], edx
         // 0040f79b: jge 0x40f7b2
      [-]85d27e11
         // 0040f79d: test edx, edx
         // 0040f79f: jle 0x40f7b2
      [-]578b396a
         // 0040f7a1: push edi
         // 0040f7a2: mov edi, ds:[ecx]
         // 0040f7a4: push 0x1
      [-]52508b4708ffd05f85c07505
         // 0040f7a6: push edx
         // 0040f7a7: push eax
         // 0040f7a8: mov eax, ds:[edi+0x8]
         // 0040f7ab: call eax
         // 0040f7ad: pop edi
         // 0040f7ae: test eax, eax
         // 0040f7b0: jnz 0x40f7b7
      [-]e809000000
         // 0040f7b2: call 0x40f7c0
      [-]83c0108906c3
         // 0040f7b7: add eax, 0x10
         // 0040f7ba: mov ds:[esi], eax
         // 0040f7bc: retn 
      [-]80790800c701
         // 004102f8: cmp b1 ds:[ecx+0x8], b1 0x0
         // 004102fc: mov ds:[ecx], 0x424260
      [-]8b490485c97407
         // 00410304: mov ecx, ds:[ecx+0x4]
         // 00410307: test ecx, ecx
         // 00410309: jz 0x410312
      [-]8bff558becff75086a00ff7104ff15
         // 00410313: mov edi, edi
         // 00410315: push ebp
         // 00410316: mov ebp, esp
         // 00410318: push ss:[ebp+0x8]
         // 0041031b: push 0x0
         // 0041031d: push ds:[ecx+0x4]
         // 00410320: call ds:[HeapAlloc]
      [-]005dc20400
         // 00410326: pop ebp
         // 00410327: retn b2 0x4
      [-]8bff558bec837d0800740e
         // 0041032a: mov edi, edi
         // 0041032c: push ebp
         // 0041032d: mov ebp, esp
         // 0041032f: cmp ss:[ebp+0x8], 0x0
         // 00410333: jz 0x410343
      [-]ff75086a00ff7104ff15
         // 00410335: push ss:[ebp+0x8]
         // 00410338: push 0x0
         // 0041033a: push ds:[ecx+0x4]
         // 0041033d: call ds:[HeapFree]
      [-]5dc20400
         // 00410343: pop ebp
         // 00410344: retn b2 0x4
      [-]8bff558bec33c03945087509
         // 00410347: mov edi, edi
         // 00410349: push ebp
         // 0041034a: mov ebp, esp
         // 0041034c: xor eax, eax
         // 0041034e: cmp ss:[ebp+0x8], eax
         // 00410351: jnz 0x41035c
      [-]ff750c8b01ff10eb21
         // 00410353: push ss:[ebp+0xc]
         // 00410356: mov eax, ds:[ecx]
         // 00410358: call ds:[eax]
         // 0041035a: jmp 0x41037d
      [-]39450c750c
         // 0041035c: cmp ss:[ebp+0xc], eax
         // 0041035f: jnz 0x41036d
      [-]ff75088b01ff500433c0eb10
         // 00410361: push ss:[ebp+0x8]
         // 00410364: mov eax, ds:[ecx]
         // 00410366: call ds:[eax+0x4]
         // 00410369: xor eax, eax
         // 0041036b: jmp 0x41037d
      [-]ff750cff750850ff7104ff15
         // 0041036d: push ss:[ebp+0xc]
         // 00410370: push ss:[ebp+0x8]
         // 00410373: push eax
         // 00410374: push ds:[ecx+0x4]
         // 00410377: call ds:[HeapReAlloc]
      [-]5dc20800
         // 0041037d: pop ebp
         // 0041037e: retn b2 0x8
      [-]8bff558becff75086a00ff7104ff15
         // 00410381: mov edi, edi
         // 00410383: push ebp
         // 00410384: mov ebp, esp
         // 00410386: push ss:[ebp+0x8]
         // 00410389: push 0x0
         // 0041038b: push ds:[ecx+0x4]
         // 0041038e: call ds:[HeapSize]
      [-]005dc20400
         // 00410394: pop ebp
         // 00410395: retn b2 0x4
      [-]8bff558bec568bf1e853fffffff64508017407
         // 00410398: mov edi, edi
         // 0041039a: push ebp
         // 0041039b: mov ebp, esp
         // 0041039d: push esi
         // 0041039e: mov esi, ecx
         // 004103a0: call 0x4102f8
         // 004103a5: test b1 ss:[ebp+0x8], b1 0x1
         // 004103a9: jz 0x4103b2
      [-]8bc65e5dc20400
         // 004103b2: mov eax, esi
         // 004103b4: pop esi
         // 004103b5: pop ebp
         // 004103b6: retn b2 0x4
      [-]8bff558bec8b450cf7651085d2
         // 004103b9: mov edi, edi
         // 004103bb: push ebp
         // 004103bc: mov ebp, esp
         // 004103be: mov eax, ss:[ebp+0xc]
         // 004103c1: mul ss:[ebp+0x10]
         // 004103c4: test edx, edx
      [-]83f8ff7607
         // 004103c8: cmp eax, 0xffffffffffffffff
         // 004103cb: jbe 0x4103d4
      [-]8b4d08890133c05dc3
         // 004103d4: mov ecx, ss:[ebp+0x8]
         // 004103d7: mov ds:[ecx], eax
         // 004103d9: xor eax, eax
         // 004103db: pop ebp
         // 004103dc: retn 
      [-]8bff558bec8b49048b015dff6004
         // 004103dd: mov edi, edi
         // 004103df: push ebp
         // 004103e0: mov ebp, esp
         // 004103e2: mov ecx, ds:[ecx+0x4]
         // 004103e5: mov eax, ds:[ecx]
         // 004103e7: pop ebp
         // 004103e8: jmp ds:[eax+0x4]
      [-]33d28d411442f00fc1108d4108c3
         // 004103eb: xor edx, edx
         // 004103ed: lea eax, ds:[ecx+0x14]
         // 004103f0: inc edx
         // 004103f1: lock xadd ds:[eax], edx
         // 004103f5: lea eax, ds:[ecx+0x8]
         // 004103f8: retn 
      [-]8bff558bec8b450c8b4d1083caff2bd03bd17307
         // 0041041e: mov edi, edi
         // 00410420: push ebp
         // 00410421: mov ebp, esp
         // 00410423: mov eax, ss:[ebp+0xc]
         // 00410426: mov ecx, ss:[ebp+0x10]
         // 00410429: or edx, 0xffffffffffffffff
         // 0041042c: sub edx, eax
         // 0041042e: cmp edx, ecx
         // 00410430: jnb 0x410439
      [-]03c18b4d08890133c05dc3
         // 00410439: add eax, ecx
         // 0041043b: mov ecx, ss:[ebp+0x8]
         // 0041043e: mov ds:[ecx], eax
         // 00410440: xor eax, eax
         // 00410442: pop ebp
         // 00410443: retn 
      [-]8bff558bec568b750857ff750c83c60883e6f88d450856508bf9e856ffffff83c40c85c0
         // 00410444: mov edi, edi
         // 00410446: push ebp
         // 00410447: mov ebp, esp
         // 00410449: push esi
         // 0041044a: mov esi, ss:[ebp+0x8]
         // 0041044d: push edi
         // 0041044e: push ss:[ebp+0xc]
         // 00410451: add esi, 0x8
         // 00410454: and esi, 0xfffffffffffffff8
         // 00410457: lea eax, ss:[ebp+0x8]
         // 0041045a: push esi
         // 0041045b: push eax
         // 0041045c: mov edi, ecx
         // 0041045e: call 0x4103b9
         // 00410463: add esp, 0xc
         // 00410466: test eax, eax
      [-]ff75088d45086a1050e8a6ffffff83c40c85c0
         // 0041046a: push ss:[ebp+0x8]
         // 0041046d: lea eax, ss:[ebp+0x8]
         // 00410470: push 0x10
         // 00410472: push eax
         // 00410473: call 0x41041e
         // 00410478: add esp, 0xc
         // 0041047b: test eax, eax
      [-]8b4f04ff75088b01ff1085c07413
         // 0041047f: mov ecx, ds:[edi+0x4]
         // 00410482: push ss:[ebp+0x8]
         // 00410485: mov eax, ds:[ecx]
         // 00410487: call ds:[eax]
         // 00410489: test eax, eax
         // 0041048b: jz 0x4104a0
      [-]4e836004008938c7400c????????897008eb02
         // 0041048d: dec esi
         // 0041048e: and ds:[eax+0x4], 0x0
         // 00410492: mov ds:[eax], edi
         // 00410494: mov ds:[eax+0xc], 0x1
         // 0041049b: mov ds:[eax+0x8], esi
         // 0041049e: jmp 0x4104a2
      [-]5f5e5dc20800
         // 004104a2: pop edi
         // 004104a3: pop esi
         // 004104a4: pop ebp
         // 004104a5: retn b2 0x8
      [-]8bff558bec568b750c57ff751083c60883e6f88d450c56508bf9e8f2feffff83c40c85c0
         // 004104a8: mov edi, edi
         // 004104aa: push ebp
         // 004104ab: mov ebp, esp
         // 004104ad: push esi
         // 004104ae: mov esi, ss:[ebp+0xc]
         // 004104b1: push edi
         // 004104b2: push ss:[ebp+0x10]
         // 004104b5: add esi, 0x8
         // 004104b8: and esi, 0xfffffffffffffff8
         // 004104bb: lea eax, ss:[ebp+0xc]
         // 004104be: push esi
         // 004104bf: push eax
         // 004104c0: mov edi, ecx
         // 004104c2: call 0x4103b9
         // 004104c7: add esp, 0xc
         // 004104ca: test eax, eax
      [-]ff750c8d450c6a1050e842ffffff83c40c85c0
         // 004104ce: push ss:[ebp+0xc]
         // 004104d1: lea eax, ss:[ebp+0xc]
         // 004104d4: push 0x10
         // 004104d6: push eax
         // 004104d7: call 0x41041e
         // 004104dc: add esp, 0xc
         // 004104df: test eax, eax
      [-]ff750c8b4f04ff75088b01ff500885c07406
         // 004104e3: push ss:[ebp+0xc]
         // 004104e6: mov ecx, ds:[edi+0x4]
         // 004104e9: push ss:[ebp+0x8]
         // 004104ec: mov eax, ds:[ecx]
         // 004104ee: call ds:[eax+0x8]
         // 004104f1: test eax, eax
         // 004104f3: jz 0x4104fb
      [-]4e897008eb02
         // 004104f5: dec esi
         // 004104f6: mov ds:[eax+0x8], esi
         // 004104f9: jmp 0x4104fd
      [-]5f5e5dc20c00
         // 004104fd: pop edi
         // 004104fe: pop esi
         // 004104ff: pop ebp
         // 00410500: retn b2 0xc
      [-]8bff558bec568d4508508bf1e8
         // 00411a19: mov edi, edi
         // 00411a1b: push ebp
         // 00411a1c: mov ebp, esp
         // 00411a1e: push esi
         // 00411a1f: lea eax, ss:[ebp+0x8]
         // 00411a22: push eax
         // 00411a23: mov esi, ecx
         // 00411a25: call ??0exception@std@@QAE@ABQBD@Z
      [-]008bc65e5dc20400
         // 00411a30: mov eax, esi
         // 00411a32: pop esi
         // 00411a33: pop ebp
         // 00411a34: retn b2 0x4
      [-]8bff558bec568bf1c706
         // 0041547e: mov edi, edi
         // 00415480: push ebp
         // 00415481: mov ebp, esp
         // 00415483: push esi
         // 00415484: mov esi, ecx
         // 00415486: mov ds:[esi], ??_7bad_exception@std@@6B@
      [-]fffff64508017407
         // 00415491: test b1 ss:[ebp+0x8], b1 0x1
         // 00415495: jz 0x41549e
      [-]8bc65e5dc20400
         // 0041549e: mov eax, esi
         // 004154a0: pop esi
         // 004154a1: pop ebp
         // 004154a2: retn b2 0x4
      [-]8bff558bec56ff75088bf1e8
         // 00416059: mov edi, edi
         // 0041605b: push ebp
         // 0041605c: mov ebp, esp
         // 0041605e: push esi
         // 0041605f: push ss:[ebp+0x8]
         // 00416062: mov esi, ecx
         // 00416064: call ??0exception@std@@QAE@ABV01@@Z
      [-]ffffc706
         // 00416069: mov ds:[esi], ??_7bad_exception@std@@6B@
      [-]008bc65e5dc20400
         // 0041606f: mov eax, esi
         // 00416071: pop esi
         // 00416072: pop ebp
         // 00416073: retn b2 0x4
      [-]8b5424088d42
         // 00422b30: mov edx, ss:[esp+0x8]
         // 00422b34: lea eax, ds:[edx+0xc]
      [-]8b5424088d42
         // 00422e20: mov edx, ss:[esp+0x8]
         // 00422e24: lea eax, ds:[edx+0xc]
      [-]8b5424088d42
         // 00422ee0: mov edx, ss:[esp+0x8]
         // 00422ee4: lea eax, ds:[edx+0xc]
      [-]ffff59c3
         // 004232e7: pop ecx
         // 004232e8: retn 

  }
  condition:
    all of them
}
