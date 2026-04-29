rule vundo_10_0 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         8b442404538b18568b74241469f6????????85f6578b78047458
         // 00401000: mov eax, ss:[esp+0x4]
         // 00401004: push ebx
         // 00401005: mov ebx, ds:[eax]
         // 00401007: push esi
         // 00401008: mov esi, ss:[esp+0x14]
         // 0040100c: imul esi, 0x61c88647
         // 00401012: test esi, esi
         // 00401014: push edi
         // 00401015: mov edi, ds:[eax+0x4]
         // 00401018: jz 0x401072
      [-]558b6c241890
         // 0040101a: push ebp
         // 0040101b: mov ebp, ss:[esp+0x18]
         // 0040101f: nop 
      [-]8bd68bc3c1e8058bcbc1e10433c1c1ea0b83e2038b4c950003c303ce33c12bf8ff150080400081c6????????8bd7c1ea058bc7c1e00433d08bce83e1038b448d0003d703c633d02bda85f675b3
         // 00401020: mov edx, esi
         // 00401022: mov eax, ebx
         // 00401024: shr eax, b1 0x5
         // 00401027: mov ecx, ebx
         // 00401029: shl ecx, b1 0x4
         // 0040102c: xor eax, ecx
         // 0040102e: shr edx, b1 0xb
         // 00401031: and edx, 0x3
         // 00401034: mov ecx, ss:[ebp+edx*0x4]
         // 00401038: add eax, ebx
         // 0040103a: add ecx, esi
         // 0040103c: xor eax, ecx
         // 0040103e: sub edi, eax
         // 00401040: call ds:[GetTickCount]
         // 00401046: add esi, 0x61c88647
         // 0040104c: mov edx, edi
         // 0040104e: shr edx, b1 0x5
         // 00401051: mov eax, edi
         // 00401053: shl eax, b1 0x4
         // 00401056: xor edx, eax
         // 00401058: mov ecx, esi
         // 0040105a: and ecx, 0x3
         // 0040105d: mov eax, ss:[ebp+ecx*0x4]
         // 00401061: add edx, edi
         // 00401063: add eax, esi
         // 00401065: xor edx, eax
         // 00401067: sub ebx, edx
         // 00401069: test esi, esi
         // 0040106b: jnz 0x401020
      [-]8b4424145d
         // 0040106d: mov eax, ss:[esp+0x14]
         // 00401071: pop ebp
      [-]8978045f5e89185bc3
         // 00401072: mov ds:[eax+0x4], edi
         // 00401075: pop edi
         // 00401076: pop esi
         // 00401077: mov ds:[eax], ebx
         // 00401079: pop ebx
         // 0040107a: retn 
      [-]558bec81ec????????a1????????33c58945fc535657ff150080400050e8b30500008b35088140008b3d0481400083c404
         // 00401080: push ebp
         // 00401081: mov ebp, esp
         // 00401083: sub esp, 0x524
         // 00401089: mov eax, ds:[0x40a010]
         // 0040108e: xor eax, ebp
         // 00401090: mov ss:[ebp+0xfffffffffffffffc], eax
         // 00401093: push ebx
         // 00401094: push esi
         // 00401095: push edi
         // 00401096: call ds:[GetTickCount]
         // 0040109c: push eax
         // 0040109d: call _srand
         // 004010a2: mov esi, ds:[GetDesktopWindow]
         // 004010a8: mov edi, ds:[GetClassNameA]
         // 004010ae: add esp, 0x4
      [-]c68534fbffff00ffd668????????8d8d????????5150a3????????ffd78d85????????8d5001
         // 004010b1: mov b1 ss:[ebp+0xfffffffffffffb34], b1 0x0
         // 004010b8: call esi
         // 004010ba: push 0x400
         // 004010bf: lea ecx, ss:[ebp+0xfffffffffffffb34]
         // 004010c5: push ecx
         // 004010c6: push eax
         // 004010c7: mov ds:[0x40ace0], eax
         // 004010cc: call edi
         // 004010ce: lea eax, ss:[ebp+0xfffffffffffffb34]
         // 004010d4: lea edx, ds:[eax+0x1]
      [-]8a0883c00184c975f7
         // 004010d7: mov b1 cl, b1 ds:[eax]
         // 004010d9: add eax, 0x1
         // 004010dc: test b1 cl, b1 cl
         // 004010de: jnz 0x4010d7
      [-]2bc283f80276ca
         // 004010e0: sub eax, edx
         // 004010e2: cmp eax, 0x2
         // 004010e5: jbe 0x4010b1
      [-]68????????6a00ff15148040008b15????????68????????68????????508985????????8995????????e8da01000083c40c33dbeb03
         // 004010e7: push 0xf6950
         // 004010ec: push 0x0
         // 004010ee: call ds:[GlobalAlloc]
         // 004010f4: mov edx, ds:[0x40a000]
         // 004010fa: push 0x11400
         // 004010ff: push 0x40d410
         // 00401104: push eax
         // 00401105: mov ss:[ebp+0xfffffffffffffb28], eax
         // 0040110b: mov ss:[ebp+0xfffffffffffffb24], edx
         // 00401111: call _memcpy
         // 00401116: add esp, 0xc
         // 00401119: xor ebx, ebx
         // 0040111b: jmp 0x401120
      [-]81fb????????0f8d9e000000
         // 00401120: cmp ebx, 0x15f90
         // 00401126: jge 0x4011ca
      [-]b9????????be????????8dbd????????8d85????????f3a58b3d1080400050ffd750ff150c804000b8????????f7eb03d3c1fa038bc2c1e81f03c28bc8c1e1042bc88bd32bd10fbe8c1534ffffff8db415????????b8????????f7e1c1ea038bc2c1e0042bc22bc88a8c0d34ffffff8d95????????528d85????????880e508d8d????????518d95????????52ffd750ff150880400083c301e956ffffff
         // 0040112c: mov ecx, 0xb
         // 00401131: mov esi, 0x408168
         // 00401136: lea edi, ss:[ebp+0xffffffffffffff34]
         // 0040113c: lea eax, ss:[ebp+0xfffffffffffffadc]
         // 00401142: rep movsdd 
         // 00401144: mov edi, ds:[GetCurrentProcess]
         // 0040114a: push eax
         // 0040114b: call edi
         // 0040114d: push eax
         // 0040114e: call ds:[GetProcessIoCounters]
         // 00401154: mov eax, 0xffffffff88888889
         // 00401159: imul ebx
         // 0040115b: add edx, ebx
         // 0040115d: sar edx, b1 0x3
         // 00401160: mov eax, edx
         // 00401162: shr eax, b1 0x1f
         // 00401165: add eax, edx
         // 00401167: mov ecx, eax
         // 00401169: shl ecx, b1 0x4
         // 0040116c: sub ecx, eax
         // 0040116e: mov edx, ebx
         // 00401170: sub edx, ecx
         // 00401172: movsx ecx, b1 ss:[ebp+edx+0xffffffffffffff34]
         // 0040117a: lea esi, ss:[ebp+edx+0xffffffffffffff34]
         // 00401181: mov eax, 0xffffffff88888889
         // 00401186: mul ecx
         // 00401188: shr edx, b1 0x3
         // 0040118b: mov eax, edx
         // 0040118d: shl eax, b1 0x4
         // 00401190: sub eax, edx
         // 00401192: sub ecx, eax
         // 00401194: mov b1 cl, b1 ss:[ebp+ecx+0xffffffffffffff34]
         // 0040119b: lea edx, ss:[ebp+0xfffffffffffffb2c]
         // 004011a1: push edx
         // 004011a2: lea eax, ss:[ebp+0xfffffffffffffb14]
         // 004011a8: mov b1 ds:[esi], b1 cl
         // 004011aa: push eax
         // 004011ab: lea ecx, ss:[ebp+0xfffffffffffffb1c]
         // 004011b1: push ecx
         // 004011b2: lea edx, ss:[ebp+0xfffffffffffffb0c]
         // 004011b8: push edx
         // 004011b9: call edi
         // 004011bb: push eax
         // 004011bc: call ds:[GetProcessTimes]
         // 004011c2: add ebx, 0x1
         // 004011c5: jmp 0x401120
      [-]8bb5????????83c606bf????????eb06
         // 004011ca: mov esi, ss:[ebp+0xfffffffffffffb28]
         // 004011d0: add esi, 0x6
         // 004011d3: mov edi, 0x1e849
         // 004011d8: jmp 0x4011e0
      [-]0fb64efa0fb646fb0fb656fcc1e10803c10fb64efdc1e00803c20fb656fec1e00803c10fb60ec1e2088985????????0fb646ff03d00fb64601c1e20803d18b8d????????c1e20803d06ae08995????????518d95????????52e8c2fdffff8b85????????0fb6c8c1e1080fb6d40fb6852efbffff03ca0fb6952ffbffffc1e10803c88b85????????c1e10803ca894efa0fb6c8c1e1080fb6d40fb68532fbffff03ca0fb69533fbffffc1e10803c8c1e10803ca894efe83c40c83c60883ef010f853bffffff
         // 004011e0: movzx ecx, b1 ds:[esi+0xfffffffffffffffa]
         // 004011e4: movzx eax, b1 ds:[esi+0xfffffffffffffffb]
         // 004011e8: movzx edx, b1 ds:[esi+0xfffffffffffffffc]
         // 004011ec: shl ecx, b1 0x8
         // 004011ef: add eax, ecx
         // 004011f1: movzx ecx, b1 ds:[esi+0xfffffffffffffffd]
         // 004011f5: shl eax, b1 0x8
         // 004011f8: add eax, edx
         // 004011fa: movzx edx, b1 ds:[esi+0xfffffffffffffffe]
         // 004011fe: shl eax, b1 0x8
         // 00401201: add eax, ecx
         // 00401203: movzx ecx, b1 ds:[esi]
         // 00401206: shl edx, b1 0x8
         // 00401209: mov ss:[ebp+0xfffffffffffffb2c], eax
         // 0040120f: movzx eax, b1 ds:[esi+0xffffffffffffffff]
         // 00401213: add edx, eax
         // 00401215: movzx eax, b1 ds:[esi+0x1]
         // 00401219: shl edx, b1 0x8
         // 0040121c: add edx, ecx
         // 0040121e: mov ecx, ss:[ebp+0xfffffffffffffb24]
         // 00401224: shl edx, b1 0x8
         // 00401227: add edx, eax
         // 00401229: push 0xffffffffffffffe0
         // 0040122b: mov ss:[ebp+0xfffffffffffffb30], edx
         // 00401231: push ecx
         // 00401232: lea edx, ss:[ebp+0xfffffffffffffb2c]
         // 00401238: push edx
         // 00401239: call 0x401000
         // 0040123e: mov eax, ss:[ebp+0xfffffffffffffb2c]
         // 00401244: movzx ecx, b1 al
         // 00401247: shl ecx, b1 0x8
         // 0040124a: movzx edx, b1 ah
         // 0040124d: movzx eax, b1 ss:[ebp+0xfffffffffffffb2e]
         // 00401254: add ecx, edx
         // 00401256: movzx edx, b1 ss:[ebp+0xfffffffffffffb2f]
         // 0040125d: shl ecx, b1 0x8
         // 00401260: add ecx, eax
         // 00401262: mov eax, ss:[ebp+0xfffffffffffffb30]
         // 00401268: shl ecx, b1 0x8
         // 0040126b: add ecx, edx
         // 0040126d: mov ds:[esi+0xfffffffffffffffa], ecx
         // 00401270: movzx ecx, b1 al
         // 00401273: shl ecx, b1 0x8
         // 00401276: movzx edx, b1 ah
         // 00401279: movzx eax, b1 ss:[ebp+0xfffffffffffffb32]
         // 00401280: add ecx, edx
         // 00401282: movzx edx, b1 ss:[ebp+0xfffffffffffffb33]
         // 00401289: shl ecx, b1 0x8
         // 0040128c: add ecx, eax
         // 0040128e: shl ecx, b1 0x8
         // 00401291: add ecx, edx
         // 00401293: mov ds:[esi+0xfffffffffffffffe], ecx
         // 00401296: add esp, 0xc
         // 00401299: add esi, 0x8
         // 0040129c: sub edi, 0x1
         // 0040129f: jnz 0x4011e0
      [-]ff95????????57ff1504804000
         // 004012a5: call ss:[ebp+0xfffffffffffffb28]
         // 004012ab: push edi
         // 004012ac: call ds:[ExitProcess]
      [-]81ec????????a1????????33c4898424????????8d04245068????????ff1518804000e898fdffff
         // 004012c0: sub esp, 0x144
         // 004012c6: mov eax, ds:[0x40a010]
         // 004012cb: xor eax, esp
         // 004012cd: mov ss:[esp+0x140], eax
         // 004012d4: lea eax, ss:[esp]
         // 004012d7: push eax
         // 004012d8: push 0x408194
         // 004012dd: call ds:[FindFirstFileA]
         // 004012e3: call 0x401080
      [-]3b0d????????7502
         // 00401662: cmp ecx, ds:[0x40a010]
         // 00401668: jnz 0x40166c
      [-]e989090000
         // 0040166c: jmp ___report_gsfailure
      [-]558bec81ec????????a3????????890d????????8915????????891d????????8935????????893d????????668c1528ae4000668c0d1cae4000668c1df8ad4000668c05f4ad4000668c25f0ad4000668c2decad40009c8f05????????8b4500a3????????8b4504a3????????8d4508a3????????8b85????????c705????????????????a1????????a3????????c705????????????????c705????????????????a1????????8985????????a1????????8985????????ff156c804000a3????????6a01e800200000596a00ff15688040006804824000ff1564804000833d????????007508
         // 00401ffa: push ebp
         // 00401ffb: mov ebp, esp
         // 00401ffd: sub esp, 0x328
         // 00402003: mov ds:[0x40ae10], eax
         // 00402008: mov ds:[0x40ae0c], ecx
         // 0040200e: mov ds:[0x40ae08], edx
         // 00402014: mov ds:[0x40ae04], ebx
         // 0040201a: mov ds:[0x40ae00], esi
         // 00402020: mov ds:[0x40adfc], edi
         // 00402026: mov b2 ds:[0x40ae28], b2 ss
         // 0040202d: mov b2 ds:[0x40ae1c], b2 cs
         // 00402034: mov b2 ds:[0x40adf8], b2 ds
         // 0040203b: mov b2 ds:[0x40adf4], b2 es
         // 00402042: mov b2 ds:[0x40adf0], b2 fs
         // 00402049: mov b2 ds:[0x40adec], b2 gs
         // 00402050: pushf 
         // 00402051: pop ds:[0x40ae20]
         // 00402057: mov eax, ss:[ebp+0x0]
         // 0040205a: mov ds:[0x40ae14], eax
         // 0040205f: mov eax, ss:[ebp+0x4]
         // 00402062: mov ds:[0x40ae18], eax
         // 00402067: lea eax, ss:[ebp+0x8]
         // 0040206a: mov ds:[0x40ae24], eax
         // 0040206f: mov eax, ss:[ebp+0xfffffffffffffce0]
         // 00402075: mov ds:[0x40ad60], 0x10001
         // 0040207f: mov eax, ds:[0x40ae18]
         // 00402084: mov ds:[0x40ad14], eax
         // 00402089: mov ds:[0x40ad08], 0xffffffffc0000409
         // 00402093: mov ds:[0x40ad0c], 0x1
         // 0040209d: mov eax, ds:[0x40a010]
         // 004020a2: mov ss:[ebp+0xfffffffffffffcd8], eax
         // 004020a8: mov eax, ds:[0x40a014]
         // 004020ad: mov ss:[ebp+0xfffffffffffffcdc], eax
         // 004020b3: call ds:[IsDebuggerPresent]
         // 004020b9: mov ds:[0x40ad58], eax
         // 004020be: push 0x1
         // 004020c0: call 0x4040c5
         // 004020c5: pop ecx
         // 004020c6: push 0x0
         // 004020c8: call ds:[SetUnhandledExceptionFilter]
         // 004020ce: push ExceptionInfo.ExceptionRecord
         // 004020d3: call ds:[UnhandledExceptionFilter]
         // 004020d9: cmp ds:[0x40ad58], 0x0
         // 004020e0: jnz 0x4020ea
      [-]6a01e8dc1f000059
         // 004020e2: push 0x1
         // 004020e4: call 0x4040c5
         // 004020e9: pop ecx
      [-]68????????ff151080400050ff1560804000c9c3
         // 004020ea: push 0xffffffffc0000409
         // 004020ef: call ds:[GetCurrentProcess]
         // 004020f5: push eax
         // 004020f6: call ds:[TerminateProcess]
         // 004020fc: leave 
         // 004020fd: retn 
      [-]68fe204000ff156880400033c0c3
         // 0040213b: push ?__CxxUnhandledExceptionFilter@@YGJPAU_EXCEPTION_POINTERS@@@Z
         // 00402140: call ds:[SetUnhandledExceptionFilter]
         // 00402146: xor eax, eax
         // 00402148: retn 
      [-]8b4c24045633f63bce751d
         // 004021f2: mov ecx, ss:[esp+0x4]
         // 004021f6: push esi
         // 004021f7: xor esi, esi
         // 004021f9: cmp ecx, esi
         // 004021fb: jnz 0x40221a
      [-]e87a2000005656565656c700????????e80b20000083c4146a16585ec3
         // 004021fd: call __errno
         // 00402202: push esi
         // 00402203: push esi
         // 00402204: push esi
         // 00402205: push esi
         // 00402206: push esi
         // 00402207: mov ds:[eax], 0x16
         // 0040220d: call __invalid_parameter
         // 00402212: add esp, 0x14
         // 00402215: push 0x16
         // 00402217: pop eax
         // 00402218: pop esi
         // 00402219: retn 
      [-]a1????????3bc674da
         // 0040221a: mov eax, ds:[0x40b030]
         // 0040221f: cmp eax, esi
         // 00402221: jz 0x4021fd
      [-]890133c05ec3
         // 00402223: mov ds:[ecx], eax
         // 00402225: xor eax, eax
         // 00402227: pop esi
         // 00402228: retn 
      [-]8b4424045633f63bc6751d
         // 00402229: mov eax, ss:[esp+0x4]
         // 0040222d: push esi
         // 0040222e: xor esi, esi
         // 00402230: cmp eax, esi
         // 00402232: jnz 0x402251
      [-]e8432000005656565656c700????????e8d41f000083c4146a16585ec3
         // 00402234: call __errno
         // 00402239: push esi
         // 0040223a: push esi
         // 0040223b: push esi
         // 0040223c: push esi
         // 0040223d: push esi
         // 0040223e: mov ds:[eax], 0x16
         // 00402244: call __invalid_parameter
         // 00402249: add esp, 0x14
         // 0040224c: push 0x16
         // 0040224e: pop eax
         // 0040224f: pop esi
         // 00402250: retn 
      [-]3935????????74db
         // 00402251: cmp ds:[0x40b030], esi
         // 00402257: jz 0x402234
      [-]8b0d????????890833c05ec3
         // 00402259: mov ecx, ds:[0x40b03c]
         // 0040225f: mov ds:[eax], ecx
         // 00402261: xor eax, eax
         // 00402263: pop esi
         // 00402264: retn 
      [-]5657b8????????bf????????3bc78bf0730f
         // 00402e9b: push esi
         // 00402e9c: push edi
         // 00402e9d: mov eax, 0x4092f0
         // 00402ea2: mov edi, 0x4092f0
         // 00402ea7: cmp eax, edi
         // 00402ea9: mov esi, eax
         // 00402eab: jnb 0x402ebc
      [-]8b0685c07402
         // 00402ead: mov eax, ds:[esi]
         // 00402eaf: test eax, eax
         // 00402eb1: jz 0x402eb5
      [-]83c6043bf772f1
         // 00402eb5: add esi, 0x4
         // 00402eb8: cmp esi, edi
         // 00402eba: jb 0x402ead
      [-]5657b8????????bf????????3bc78bf0730f
         // 00402ebf: push esi
         // 00402ec0: push edi
         // 00402ec1: mov eax, 0x4092f8
         // 00402ec6: mov edi, 0x4092f8
         // 00402ecb: cmp eax, edi
         // 00402ecd: mov esi, eax
         // 00402ecf: jnb 0x402ee0
      [-]8b0685c07402
         // 00402ed1: mov eax, ds:[esi]
         // 00402ed3: test eax, eax
         // 00402ed5: jz 0x402ed9
      [-]83c6043bf772f1
         // 00402ed9: add esi, 0x4
         // 00402edc: cmp esi, edi
         // 00402ede: jb 0x402ed1
      [-]e89bffffffa3????????33c0c3
         // 004032da: call __get_sse2_info
         // 004032df: mov ds:[0x40b89c], eax
         // 004032e4: xor eax, eax
         // 004032e6: retn 
      [-]8325????????00c3
         // 004040c5: and ds:[0x40b764], 0x0
         // 004040cc: retn 
      [-]8b442404a3????????c3
         // 00404117: mov eax, ss:[esp+0x4]
         // 0040411b: mov ds:[0x40b638], eax
         // 00404120: retn 
      [-]ff35????????e89ed5ffff59c3
         // 00404578: push ds:[0x40b644]
         // 0040457e: call __decode_pointer
         // 00404583: pop ecx
         // 00404584: retn 
      [-]8b442404a3????????c3
         // 00404735: mov eax, ss:[esp+0x4]
         // 00404739: mov ds:[0x40b650], eax
         // 0040473e: retn 
      [-]8b442404a3????????c3
         // 0040473f: mov eax, ss:[esp+0x4]
         // 00404743: mov ds:[0x40b65c], eax
         // 00404748: retn 
      [-]8b442404a3????????c3
         // 00404749: mov eax, ss:[esp+0x4]
         // 0040474d: mov ds:[0x40b660], eax
         // 00404752: retn 
      [-]8b442404a3????????c3
         // 00404828: mov eax, ss:[esp+0x4]
         // 0040482c: mov ds:[0x40b664], eax
         // 00404831: retn 
      [-]558bec83ec20535657e8b6d2ffff33db391d????????8945f8895dfc895df4895df00f85ae000000
         // 00404854: push ebp
         // 00404855: mov ebp, esp
         // 00404857: sub esp, 0x20
         // 0040485a: push ebx
         // 0040485b: push esi
         // 0040485c: push edi
         // 0040485d: call __encoded_null
         // 00404862: xor ebx, ebx
         // 00404864: cmp ds:[0x40b668], ebx
         // 0040486a: mov ss:[ebp+0xfffffffffffffff8], eax
         // 0040486d: mov ss:[ebp+0xfffffffffffffffc], ebx
         // 00404870: mov ss:[ebp+0xfffffffffffffff4], ebx
         // 00404873: mov ss:[ebp+0xfffffffffffffff0], ebx
         // 00404876: jnz 0x40492a
      [-]68????????ff15d08040008bf83bfb0f8479010000
         // 0040487c: push 0x40890c
         // 00404881: call ds:[LoadLibraryA]
         // 00404887: mov edi, eax
         // 00404889: cmp edi, ebx
         // 0040488b: jz 0x404a0a
      [-]8b353880400068????????57ffd63bc30f8463010000
         // 00404891: mov esi, ds:[GetProcAddress]
         // 00404897: push 0x408900
         // 0040489c: push edi
         // 0040489d: call esi
         // 0040489f: cmp eax, ebx
         // 004048a1: jz 0x404a0a
      [-]50e8fdd1ffffc70424????????57a3????????ffd650e8e8d1ffffc70424????????57a3????????ffd650e8d3d1ffffa3????????8d45f450e80dd9ffff85c05959740d
         // 004048a7: push eax
         // 004048a8: call __encode_pointer
         // 004048ad: mov ss:[esp], 0x4088f0
         // 004048b4: push edi
         // 004048b5: mov ds:[0x40b668], eax
         // 004048ba: call esi
         // 004048bc: push eax
         // 004048bd: call __encode_pointer
         // 004048c2: mov ss:[esp], 0x4088dc
         // 004048c9: push edi
         // 004048ca: mov ds:[0x40b66c], eax
         // 004048cf: call esi
         // 004048d1: push eax
         // 004048d2: call __encode_pointer
         // 004048d7: mov ds:[0x40b670], eax
         // 004048dc: lea eax, ss:[ebp+0xfffffffffffffff4]
         // 004048df: push eax
         // 004048e0: call 0x4021f2
         // 004048e5: test eax, eax
         // 004048e7: pop ecx
         // 004048e8: pop ecx
         // 004048e9: jz 0x4048f8
      [-]5353535353e82cf8ffff
         // 004048eb: push ebx
         // 004048ec: push ebx
         // 004048ed: push ebx
         // 004048ee: push ebx
         // 004048ef: push ebx
         // 004048f0: call __invoke_watson
      [-]837df402752c
         // 004048f8: cmp ss:[ebp+0xfffffffffffffff4], 0x2
         // 004048fc: jnz 0x40492a
      [-]68????????57ffd650e89ed1ffff3bc359a3????????7414
         // 004048fe: push 0x4088c0
         // 00404903: push edi
         // 00404904: call esi
         // 00404906: push eax
         // 00404907: call __encode_pointer
         // 0040490c: cmp eax, ebx
         // 0040490e: pop ecx
         // 0040490f: mov ds:[0x40b678], eax
         // 00404914: jz 0x40492a
      [-]68????????57ffd650e886d1ffff59a3????????
         // 00404916: push 0x4088a8
         // 0040491b: push edi
         // 0040491c: call esi
         // 0040491e: push eax
         // 0040491f: call __encode_pointer
         // 00404924: pop ecx
         // 00404925: mov ds:[0x40b674], eax
      [-]a1????????8b4df83bc17479
         // 0040492a: mov eax, ds:[0x40b674]
         // 0040492f: mov ecx, ss:[ebp+0xfffffffffffffff8]
         // 00404932: cmp eax, ecx
         // 00404934: jz 0x4049af
      [-]390d????????7471
         // 00404936: cmp ds:[0x40b678], ecx
         // 0040493c: jz 0x4049af
      [-]50e8ddd1ffffff35????????8bf0e8d0d1ffff3bf359598bf87456
         // 0040493e: push eax
         // 0040493f: call __decode_pointer
         // 00404944: push ds:[0x40b678]
         // 0040494a: mov esi, eax
         // 0040494c: call __decode_pointer
         // 00404951: cmp esi, ebx
         // 00404953: pop ecx
         // 00404954: pop ecx
         // 00404955: mov edi, eax
         // 00404957: jz 0x4049af
      [-]3bfb7452
         // 00404959: cmp edi, ebx
         // 0040495b: jz 0x4049af
      [-]ffd63bc37419
         // 0040495d: call esi
         // 0040495f: cmp eax, ebx
         // 00404961: jz 0x40497c
      [-]8d4dec516a0c8d4de0516a0150ffd785c07406
         // 00404963: lea ecx, ss:[ebp+0xffffffffffffffec]
         // 00404966: push ecx
         // 00404967: push 0xc
         // 00404969: lea ecx, ss:[ebp+0xffffffffffffffe0]
         // 0040496c: push ecx
         // 0040496d: push 0x1
         // 0040496f: push eax
         // 00404970: call edi
         // 00404972: test eax, eax
         // 00404974: jz 0x40497c
      [-]f645e8017533
         // 00404976: test b1 ss:[ebp+0xffffffffffffffe8], b1 0x1
         // 0040497a: jnz 0x4049af
      [-]8d45f050e8a4d8ffff85c059740d
         // 0040497c: lea eax, ss:[ebp+0xfffffffffffffff0]
         // 0040497f: push eax
         // 00404980: call 0x402229
         // 00404985: test eax, eax
         // 00404987: pop ecx
         // 00404988: jz 0x404997
      [-]5353535353e88df7ffff
         // 0040498a: push ebx
         // 0040498b: push ebx
         // 0040498c: push ebx
         // 0040498d: push ebx
         // 0040498e: push ebx
         // 0040498f: call __invoke_watson
      [-]837df0047209
         // 00404997: cmp ss:[ebp+0xfffffffffffffff0], 0x4
         // 0040499b: jb 0x4049a6
      [-]814d10????????eb44
         // 0040499d: or ss:[ebp+0x10], 0x200000
         // 004049a4: jmp 0x4049ea
      [-]814d10????????eb3b
         // 004049a6: or ss:[ebp+0x10], 0x40000
         // 004049ad: jmp 0x4049ea
      [-]a1????????3b45f87431
         // 004049af: mov eax, ds:[0x40b66c]
         // 004049b4: cmp eax, ss:[ebp+0xfffffffffffffff8]
         // 004049b7: jz 0x4049ea
      [-]50e862d1ffff3bc3597426
         // 004049b9: push eax
         // 004049ba: call __decode_pointer
         // 004049bf: cmp eax, ebx
         // 004049c1: pop ecx
         // 004049c2: jz 0x4049ea
      [-]ffd03bc38945fc741d
         // 004049c4: call eax
         // 004049c6: cmp eax, ebx
         // 004049c8: mov ss:[ebp+0xfffffffffffffffc], eax
         // 004049cb: jz 0x4049ea
      [-]a1????????3b45f87413
         // 004049cd: mov eax, ds:[0x40b670]
         // 004049d2: cmp eax, ss:[ebp+0xfffffffffffffff8]
         // 004049d5: jz 0x4049ea
      [-]50e844d1ffff3bc3597408
         // 004049d7: push eax
         // 004049d8: call __decode_pointer
         // 004049dd: cmp eax, ebx
         // 004049df: pop ecx
         // 004049e0: jz 0x4049ea
      [-]ff75fcffd08945fc
         // 004049e2: push ss:[ebp+0xfffffffffffffffc]
         // 004049e5: call eax
         // 004049e7: mov ss:[ebp+0xfffffffffffffffc], eax
      [-]ff35????????e82cd1ffff3bc3597410
         // 004049ea: push ds:[0x40b668]
         // 004049f0: call __decode_pointer
         // 004049f5: cmp eax, ebx
         // 004049f7: pop ecx
         // 004049f8: jz 0x404a0a
      [-]ff7510ff750cff7508ff75fcffd0eb02
         // 004049fa: push ss:[ebp+0x10]
         // 004049fd: push ss:[ebp+0xc]
         // 00404a00: push ss:[ebp+0x8]
         // 00404a03: push ss:[ebp+0xfffffffffffffffc]
         // 00404a06: call eax
         // 00404a08: jmp 0x404a0c
      [-]5f5e5bc9c3
         // 00404a0c: pop edi
         // 00404a0d: pop esi
         // 00404a0e: pop ebx
         // 00404a0f: leave 
         // 00404a10: retn 

  }
  condition:
    all of them
}
