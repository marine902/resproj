rule stormattack_30_0 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         538b5c2408565785db0f84a3000000
         // 00401000: push ebx
         // 00401001: mov ebx, ss:[esp+0x8]
         // 00401005: push esi
         // 00401006: push edi
         // 00401007: test ebx, ebx
         // 00401009: jz 0x4010b2
      [-]8a44241484c0750e
         // 0040100f: mov b1 al, b1 ss:[esp+0x14]
         // 00401013: test b1 al, b1 al
         // 00401015: jnz 0x401025
      [-]68????????53ff15b8304000eb50
         // 00401017: push 0x104
         // 0040101c: push ebx
         // 0040101d: call ds:[GetSystemWindowsDirectoryA]
         // 00401023: jmp 0x401075
      [-]3c01750e
         // 00401025: cmp b1 al, b1 0x1
         // 00401027: jnz 0x401037
      [-]68????????53ff15bc304000eb3e
         // 00401029: push 0x104
         // 0040102e: push ebx
         // 0040102f: call ds:[GetSystemDirectoryA]
         // 00401035: jmp 0x401075
      [-]3c02753a
         // 00401037: cmp b1 al, b1 0x2
         // 00401039: jnz 0x401075
      [-]68????????53ff15bc304000bf????????83c9ff33c0c6430300f2aef7d12bf98bf78bd18bfb83c9fff2ae8bca4fc1e902f3a58bca83e103f3a4
         // 0040103b: push 0x104
         // 00401040: push ebx
         // 00401041: call ds:[GetSystemDirectoryA]
         // 00401047: mov edi, 0x4042d0
         // 0040104c: or ecx, 0xffffffffffffffff
         // 0040104f: xor eax, eax
         // 00401051: mov b1 ds:[ebx+0x3], b1 0x0
         // 00401055: repne scasbb 
         // 00401057: not ecx
         // 00401059: sub edi, ecx
         // 0040105b: mov esi, edi
         // 0040105d: mov edx, ecx
         // 0040105f: mov edi, ebx
         // 00401061: or ecx, 0xffffffffffffffff
         // 00401064: repne scasbb 
         // 00401066: mov ecx, edx
         // 00401068: dec edi
         // 00401069: shr ecx, b1 0x2
         // 0040106c: rep movsdd 
         // 0040106e: mov ecx, edx
         // 00401070: and ecx, 0x3
         // 00401073: rep movsbb 
      [-]8bfb83c9ff33c0f2aef7d149807c19ff5c742a
         // 00401075: mov edi, ebx
         // 00401077: or ecx, 0xffffffffffffffff
         // 0040107a: xor eax, eax
         // 0040107c: repne scasbb 
         // 0040107e: not ecx
         // 00401080: dec ecx
         // 00401081: cmp b1 ds:[ecx+ebx+0xffffffffffffffff], b1 0x5c
         // 00401086: jz 0x4010b2
      [-]bf????????83c9ff33c0f2aef7d12bf98bf78bd18bfb83c9fff2ae8bca4fc1e902f3a58bca83e103f3a4
         // 00401088: mov edi, 0x4042cc
         // 0040108d: or ecx, 0xffffffffffffffff
         // 00401090: xor eax, eax
         // 00401092: repne scasbb 
         // 00401094: not ecx
         // 00401096: sub edi, ecx
         // 00401098: mov esi, edi
         // 0040109a: mov edx, ecx
         // 0040109c: mov edi, ebx
         // 0040109e: or ecx, 0xffffffffffffffff
         // 004010a1: repne scasbb 
         // 004010a3: mov ecx, edx
         // 004010a5: dec edi
         // 004010a6: shr ecx, b1 0x2
         // 004010a9: rep movsdd 
         // 004010ab: mov ecx, edx
         // 004010ad: and ecx, 0x3
         // 004010b0: rep movsbb 
      [-]5f5e5bc3
         // 004010b2: pop edi
         // 004010b3: pop esi
         // 004010b4: pop ebx
         // 004010b5: retn 
      [-]538b5c2408565785db7475
         // 004010c0: push ebx
         // 004010c1: mov ebx, ss:[esp+0x8]
         // 004010c5: push esi
         // 004010c6: push edi
         // 004010c7: test ebx, ebx
         // 004010c9: jz 0x401140
      [-]b9????????33c08bfbf3aba02541400084c07512
         // 004010cb: mov ecx, 0x41
         // 004010d0: xor eax, eax
         // 004010d2: mov edi, ebx
         // 004010d4: rep stosdd 
         // 004010d6: mov b1 al, b1 ds:[0x404125]
         // 004010db: test b1 al, b1 al
         // 004010dd: jnz 0x4010f1
      [-]6a0253e819ffffff83c408bf????????eb2a
         // 004010df: push 0x2
         // 004010e1: push ebx
         // 004010e2: call 0x401000
         // 004010e7: add esp, 0x8
         // 004010ea: mov edi, 0x404308
         // 004010ef: jmp 0x40111b
      [-]3c017512
         // 004010f1: cmp b1 al, b1 0x1
         // 004010f3: jnz 0x401107
      [-]6a0053e803ffffff83c408bf????????eb14
         // 004010f5: push 0x0
         // 004010f7: push ebx
         // 004010f8: call 0x401000
         // 004010fd: add esp, 0x8
         // 00401100: mov edi, 0x4042fc
         // 00401105: jmp 0x40111b
      [-]3c027535
         // 00401107: cmp b1 al, b1 0x2
         // 00401109: jnz 0x401140
      [-]6a0153e8edfeffff83c408bf????????
         // 0040110b: push 0x1
         // 0040110d: push ebx
         // 0040110e: call 0x401000
         // 00401113: add esp, 0x8
         // 00401116: mov edi, 0x4042f0
      [-]83c9ff33c0f2aef7d12bf98bf78bd18bfb83c9fff2ae8bca4fc1e902f3a58bca83e103f3a4
         // 0040111b: or ecx, 0xffffffffffffffff
         // 0040111e: xor eax, eax
         // 00401120: repne scasbb 
         // 00401122: not ecx
         // 00401124: sub edi, ecx
         // 00401126: mov esi, edi
         // 00401128: mov edx, ecx
         // 0040112a: mov edi, ebx
         // 0040112c: or ecx, 0xffffffffffffffff
         // 0040112f: repne scasbb 
         // 00401131: mov ecx, edx
         // 00401133: dec edi
         // 00401134: shr ecx, b1 0x2
         // 00401137: rep movsdd 
         // 00401139: mov ecx, edx
         // 0040113b: and ecx, 0x3
         // 0040113e: rep movsbb 
      [-]5f5e5bc3
         // 00401140: pop edi
         // 00401141: pop esi
         // 00401142: pop ebx
         // 00401143: retn 
      [-]81ec????????53568d44245c5750e85dffffff83c4048d4c241c51ff15983040008d54240c8d44241c52506a006a006a006a016a008d4c247c6a00516a0066c74424740000c7442470????????ff159c30400085c0750a
         // 00401150: sub esp, 0x158
         // 00401156: push ebx
         // 00401157: push esi
         // 00401158: lea eax, ss:[esp+0x5c]
         // 0040115c: push edi
         // 0040115d: push eax
         // 0040115e: call 0x4010c0
         // 00401163: add esp, 0x4
         // 00401166: lea ecx, ss:[esp+0x1c]
         // 0040116a: push ecx
         // 0040116b: call ds:[GetStartupInfoA]
         // 00401171: lea edx, ss:[esp+0xc]
         // 00401175: lea eax, ss:[esp+0x1c]
         // 00401179: push edx
         // 0040117a: push eax
         // 0040117b: push 0x0
         // 0040117d: push 0x0
         // 0040117f: push 0x0
         // 00401181: push 0x1
         // 00401183: push 0x0
         // 00401185: lea ecx, ss:[esp+0x7c]
         // 00401189: push 0x0
         // 0040118b: push ecx
         // 0040118c: push 0x0
         // 0040118e: mov b2 ss:[esp+0x74], b2 0x0
         // 00401195: mov ss:[esp+0x70], 0x101
         // 0040119d: call ds:[CreateProcessA]
         // 004011a3: test eax, eax
         // 004011a5: jnz 0x4011b1
      [-]5f5e5b81c4????????c3
         // 004011a7: pop edi
         // 004011a8: pop esi
         // 004011a9: pop ebx
         // 004011aa: add esp, 0x158
         // 004011b0: retn 
      [-]8bbc24????????8b1da03040006a0468????????57ffd38b54241440506a0052ff15a43040008bf085f6750a
         // 004011b1: mov edi, ss:[esp+0x168]
         // 004011b8: mov ebx, ds:[lstrlenA]
         // 004011be: push 0x4
         // 004011c0: push 0x1000
         // 004011c5: push edi
         // 004011c6: call ebx
         // 004011c8: mov edx, ss:[esp+0x14]
         // 004011cc: inc eax
         // 004011cd: push eax
         // 004011ce: push 0x0
         // 004011d0: push edx
         // 004011d1: call ds:[VirtualAllocEx]
         // 004011d7: mov esi, eax
         // 004011d9: test esi, esi
         // 004011db: jnz 0x4011e7
      [-]5f5e5b81c4????????c3
         // 004011dd: pop edi
         // 004011de: pop esi
         // 004011df: pop ebx
         // 004011e0: add esp, 0x158
         // 004011e6: retn 
      [-]6a0057ffd340508b442414575650ff15a830400085c0750a
         // 004011e7: push 0x0
         // 004011e9: push edi
         // 004011ea: call ebx
         // 004011ec: inc eax
         // 004011ed: push eax
         // 004011ee: mov eax, ss:[esp+0x14]
         // 004011f2: push edi
         // 004011f3: push esi
         // 004011f4: push eax
         // 004011f5: call ds:[WriteProcessMemory]
         // 004011fb: test eax, eax
         // 004011fd: jnz 0x401209
      [-]5f5e5b81c4????????c3
         // 004011ff: pop edi
         // 00401200: pop esi
         // 00401201: pop ebx
         // 00401202: add esp, 0x158
         // 00401208: retn 
      [-]68????????68????????ff15ac30400050ff15b030400085c0750a
         // 00401209: push 0x404324
         // 0040120e: push 0x404318
         // 00401213: call ds:[GetModuleHandleA]
         // 00401219: push eax
         // 0040121a: call ds:[GetProcAddress]
         // 00401220: test eax, eax
         // 00401222: jnz 0x40122e
      [-]5f5e5b81c4????????c3
         // 00401224: pop edi
         // 00401225: pop esi
         // 00401226: pop ebx
         // 00401227: add esp, 0x158
         // 0040122d: retn 
      [-]8b4c240c6a006a0056506a006a0051ff15b4304000f7d81bc05f5e5bf7d881c4????????c3
         // 0040122e: mov ecx, ss:[esp+0xc]
         // 00401232: push 0x0
         // 00401234: push 0x0
         // 00401236: push esi
         // 00401237: push eax
         // 00401238: push 0x0
         // 0040123a: push 0x0
         // 0040123c: push ecx
         // 0040123d: call ds:[CreateRemoteThread]
         // 00401243: neg eax
         // 00401245: sbb eax, eax
         // 00401247: pop edi
         // 00401248: pop esi
         // 00401249: pop ebx
         // 0040124a: neg eax
         // 0040124c: add esp, 0x158
         // 00401252: retn 
      [-]6aff68????????64a1????????50648925????????81ec????????565768????????8d4c2410e8811300008d44240c68????????8d4c24185051c78424????????????????e85c13000068????????8d5424145052c68424ac00000001e8441300008b0083c9ff8bf833c0f2aef7d12bf98d5424188bc18bf78bfac1e902f3a58bc883e103f3a48d4c2410e8101300008d4c2414c68424a000000000e8ff1200008d4c24085168????????68????????ff151c3040008b54240868????????52ff15203040008b4c24088d44241868????????506a026a0068????????51ff15243040008b54240852ff15283040006a32ff15943040008d4c240cc78424????????????????e8951200008b8c24????????5f5e64890d????????81c4????????c3
         // 00401260: push 0xffffffffffffffff
         // 00401262: push 0x402816
         // 00401267: mov eax, fs:[0x0]
         // 0040126d: push eax
         // 0040126e: mov fs:[0x0], esp
         // 00401275: sub esp, 0x90
         // 0040127b: push esi
         // 0040127c: push edi
         // 0040127d: push 0x40437c
         // 00401282: lea ecx, ss:[esp+0x10]
         // 00401286: call ??0CString@@QAE@PBD@Z
         // 0040128b: lea eax, ss:[esp+0xc]
         // 0040128f: push 0x404020
         // 00401294: lea ecx, ss:[esp+0x18]
         // 00401298: push eax
         // 00401299: push ecx
         // 0040129a: mov ss:[esp+0xac], 0x0
         // 004012a5: call ??H@YG?AVCString@@ABV0@PBD@Z
         // 004012aa: push 0x4044f0
         // 004012af: lea edx, ss:[esp+0x14]
         // 004012b3: push eax
         // 004012b4: push edx
         // 004012b5: mov b1 ss:[esp+0xac], b1 0x1
         // 004012bd: call ??H@YG?AVCString@@ABV0@PBD@Z
         // 004012c2: mov eax, ds:[eax]
         // 004012c4: or ecx, 0xffffffffffffffff
         // 004012c7: mov edi, eax
         // 004012c9: xor eax, eax
         // 004012cb: repne scasbb 
         // 004012cd: not ecx
         // 004012cf: sub edi, ecx
         // 004012d1: lea edx, ss:[esp+0x18]
         // 004012d5: mov eax, ecx
         // 004012d7: mov esi, edi
         // 004012d9: mov edi, edx
         // 004012db: shr ecx, b1 0x2
         // 004012de: rep movsdd 
         // 004012e0: mov ecx, eax
         // 004012e2: and ecx, 0x3
         // 004012e5: rep movsbb 
         // 004012e7: lea ecx, ss:[esp+0x10]
         // 004012eb: call ??1CString@@QAE@XZ
         // 004012f0: lea ecx, ss:[esp+0x14]
         // 004012f4: mov b1 ss:[esp+0xa0], b1 0x0
         // 004012fc: call ??1CString@@QAE@XZ
         // 00401301: lea ecx, ss:[esp+0x8]
         // 00401305: push ecx
         // 00401306: push 0x404340
         // 0040130b: push 0xffffffff80000002
         // 00401310: call ds:[RegOpenKeyA]
         // 00401316: mov edx, ss:[esp+0x8]
         // 0040131a: push 0x404334
         // 0040131f: push edx
         // 00401320: call ds:[RegDeleteValueA]
         // 00401326: mov ecx, ss:[esp+0x8]
         // 0040132a: lea eax, ss:[esp+0x18]
         // 0040132e: push 0x80
         // 00401333: push eax
         // 00401334: push 0x2
         // 00401336: push 0x0
         // 00401338: push 0x404334
         // 0040133d: push ecx
         // 0040133e: call ds:[RegSetValueExA]
         // 00401344: mov edx, ss:[esp+0x8]
         // 00401348: push edx
         // 00401349: call ds:[RegCloseKey]
         // 0040134f: push 0x32
         // 00401351: call ds:[Sleep]
         // 00401357: lea ecx, ss:[esp+0xc]
         // 0040135b: mov ss:[esp+0xa0], 0xffffffffffffffff
         // 00401366: call ??1CString@@QAE@XZ
         // 0040136b: mov ecx, ss:[esp+0x98]
         // 00401372: pop edi
         // 00401373: pop esi
         // 00401374: mov fs:[0x0], ecx
         // 0040137b: add esp, 0x9c
         // 00401381: retn 
      [-]81ec????????8d4424545355565768????????33db5053ff155030400085c00f8448010000
         // 00401390: sub esp, 0x360
         // 00401396: lea eax, ss:[esp+0x54]
         // 0040139a: push ebx
         // 0040139b: push ebp
         // 0040139c: push esi
         // 0040139d: push edi
         // 0040139e: push 0x104
         // 004013a3: xor ebx, ebx
         // 004013a5: push eax
         // 004013a6: push ebx
         // 004013a7: call ds:[GetModuleFileNameA]
         // 004013ad: test eax, eax
         // 004013af: jz 0x4014fd
      [-]8d4c246468????????8d5424685152ff154c30400085c00f842b010000
         // 004013b5: lea ecx, ss:[esp+0x64]
         // 004013b9: push 0x104
         // 004013be: lea edx, ss:[esp+0x68]
         // 004013c2: push ecx
         // 004013c3: push edx
         // 004013c4: call ds:[GetShortPathNameA]
         // 004013ca: test eax, eax
         // 004013cc: jz 0x4014fd
      [-]8d8424????????68????????5068????????ff154830400085c00f840b010000
         // 004013d2: lea eax, ss:[esp+0x26c]
         // 004013d9: push 0x104
         // 004013de: push eax
         // 004013df: push 0x4043a8
         // 004013e4: call ds:[GetEnvironmentVariableA]
         // 004013ea: test eax, eax
         // 004013ec: jz 0x4014fd
      [-]8d8c24????????68????????51ff15443040008b35403040008d5424648d8424????????5250ffd68d8c24????????68????????51ffd68d9424????????8d8424????????5250ffd6b9????????33c08d7c2424895c2410f3ab33c966895c24508b1d64304000894c2414894c241868????????894c2420c7442424????????c7442450????????ffd38b358430400050ffd68b2d883040006a0fffd58b3d8c30400050ffd78d5424108d44242052506a006a006a0c6a006a008d8c24????????6a00516a00ff159c30400085c0742d
         // 004013f2: lea ecx, ss:[esp+0x168]
         // 004013f9: push 0x40439c
         // 004013fe: push ecx
         // 004013ff: call ds:[lstrcpyA]
         // 00401405: mov esi, ds:[lstrcatA]
         // 0040140b: lea edx, ss:[esp+0x64]
         // 0040140f: lea eax, ss:[esp+0x168]
         // 00401416: push edx
         // 00401417: push eax
         // 00401418: call esi
         // 0040141a: lea ecx, ss:[esp+0x168]
         // 00401421: push 0x404394
         // 00401426: push ecx
         // 00401427: call esi
         // 00401429: lea edx, ss:[esp+0x168]
         // 00401430: lea eax, ss:[esp+0x26c]
         // 00401437: push edx
         // 00401438: push eax
         // 00401439: call esi
         // 0040143b: mov ecx, 0x10
         // 00401440: xor eax, eax
         // 00401442: lea edi, ss:[esp+0x24]
         // 00401446: mov ss:[esp+0x10], ebx
         // 0040144a: rep stosdd 
         // 0040144c: xor ecx, ecx
         // 0040144e: mov b2 ss:[esp+0x50], b2 bx
         // 00401453: mov ebx, ds:[GetCurrentProcess]
         // 00401459: mov ss:[esp+0x14], ecx
         // 0040145d: mov ss:[esp+0x18], ecx
         // 00401461: push 0x100
         // 00401466: mov ss:[esp+0x20], ecx
         // 0040146a: mov ss:[esp+0x24], 0x44
         // 00401472: mov ss:[esp+0x50], 0x1
         // 0040147a: call ebx
         // 0040147c: mov esi, ds:[SetPriorityClass]
         // 00401482: push eax
         // 00401483: call esi
         // 00401485: mov ebp, ds:[GetCurrentThread]
         // 0040148b: push 0xf
         // 0040148d: call ebp
         // 0040148f: mov edi, ds:[SetThreadPriority]
         // 00401495: push eax
         // 00401496: call edi
         // 00401498: lea edx, ss:[esp+0x10]
         // 0040149c: lea eax, ss:[esp+0x20]
         // 004014a0: push edx
         // 004014a1: push eax
         // 004014a2: push 0x0
         // 004014a4: push 0x0
         // 004014a6: push 0xc
         // 004014a8: push 0x0
         // 004014aa: push 0x0
         // 004014ac: lea ecx, ss:[esp+0x288]
         // 004014b3: push 0x0
         // 004014b5: push ecx
         // 004014b6: push 0x0
         // 004014b8: call ds:[CreateProcessA]
         // 004014be: test eax, eax
         // 004014c0: jz 0x4014ef
      [-]8b5424106a4052ffd68b4424146af150ffd78b4c241451ff15903040005f5e5db8????????5b81c4????????c3
         // 004014c2: mov edx, ss:[esp+0x10]
         // 004014c6: push 0x40
         // 004014c8: push edx
         // 004014c9: call esi
         // 004014cb: mov eax, ss:[esp+0x14]
         // 004014cf: push 0xfffffffffffffff1
         // 004014d1: push eax
         // 004014d2: call edi
         // 004014d4: mov ecx, ss:[esp+0x14]
         // 004014d8: push ecx
         // 004014d9: call ds:[ResumeThread]
         // 004014df: pop edi
         // 004014e0: pop esi
         // 004014e1: pop ebp
         // 004014e2: mov eax, 0x1
         // 004014e7: pop ebx
         // 004014e8: add esp, 0x360
         // 004014ee: retn 
      [-]6a20ffd350ffd66a00ffd550ffd7
         // 004014ef: push 0x20
         // 004014f1: call ebx
         // 004014f3: push eax
         // 004014f4: call esi
         // 004014f6: push 0x0
         // 004014f8: call ebp
         // 004014fa: push eax
         // 004014fb: call edi
      [-]5f5e5d33c05b81c4????????c3
         // 004014fd: pop edi
         // 004014fe: pop esi
         // 004014ff: pop ebp
         // 00401500: xor eax, eax
         // 00401502: pop ebx
         // 00401503: add esp, 0x360
         // 00401509: retn 
      [-]6aff68????????64a1????????50648925????????81ec????????5355565768????????68????????ff15143040008b2d1830400033db689044400050a3????????c705????????????????c705????????????????891d????????c705????????????????c705????????????????c705????????????????ffd568????????891d????????ff1594304000a1????????689044400050c705????????????????ffd58a0d244140008d54241c5152e83bfaffffbf????????83c9ff33c08d542424f2aef7d12bf983c4048bf78bfa8bd183c9fff2ae8bca4fc1e902f3a58bca8964241c83e103f3a48bcc68????????e8061000006a65518d4424288bcc8964242050899c24????????e8ec0f000083ceff89b424????????e8310e000083c40c3ac30f849a000000
         // 00401510: push 0xffffffffffffffff
         // 00401512: push 0x402836
         // 00401517: mov eax, fs:[0x0]
         // 0040151d: push eax
         // 0040151e: mov fs:[0x0], esp
         // 00401525: sub esp, 0x214
         // 0040152b: push ebx
         // 0040152c: push ebp
         // 0040152d: push esi
         // 0040152e: push edi
         // 0040152f: push 0x4016f0
         // 00401534: push 0x404128
         // 00401539: call ds:[RegisterServiceCtrlHandlerA]
         // 0040153f: mov ebp, ds:[SetServiceStatus]
         // 00401545: xor ebx, ebx
         // 00401547: push ServiceStatus.dwServiceType
         // 0040154c: push eax
         // 0040154d: mov ds:[0x404488], eax
         // 00401552: mov ds:[0x404490], 0x20
         // 0040155c: mov ds:[0x404498], 0x7
         // 00401566: mov ds:[0x40449c], ebx
         // 0040156c: mov ds:[0x4044a8], 0x7d0
         // 00401576: mov ds:[0x4044a4], 0x1
         // 00401580: mov ds:[0x404494], 0x2
         // 0040158a: call ebp
         // 0040158c: push 0x1f4
         // 00401591: mov ds:[0x4044a4], ebx
         // 00401597: call ds:[Sleep]
         // 0040159d: mov eax, ds:[0x404488]
         // 004015a2: push ServiceStatus.dwServiceType
         // 004015a7: push eax
         // 004015a8: mov ds:[0x404494], 0x4
         // 004015b2: call ebp
         // 004015b4: mov b1 cl, b1 ds:[0x404124]
         // 004015ba: lea edx, ss:[esp+0x1c]
         // 004015be: push ecx
         // 004015bf: push edx
         // 004015c0: call 0x401000
         // 004015c5: mov edi, 0x404020
         // 004015ca: or ecx, 0xffffffffffffffff
         // 004015cd: xor eax, eax
         // 004015cf: lea edx, ss:[esp+0x24]
         // 004015d3: repne scasbb 
         // 004015d5: not ecx
         // 004015d7: sub edi, ecx
         // 004015d9: add esp, 0x4
         // 004015dc: mov esi, edi
         // 004015de: mov edi, edx
         // 004015e0: mov edx, ecx
         // 004015e2: or ecx, 0xffffffffffffffff
         // 004015e5: repne scasbb 
         // 004015e7: mov ecx, edx
         // 004015e9: dec edi
         // 004015ea: shr ecx, b1 0x2
         // 004015ed: rep movsdd 
         // 004015ef: mov ecx, edx
         // 004015f1: mov ss:[esp+0x1c], esp
         // 004015f5: and ecx, 0x3
         // 004015f8: rep movsbb 
         // 004015fa: mov ecx, esp
         // 004015fc: push 0x4043b0
         // 00401601: call ??0CString@@QAE@PBD@Z
         // 00401606: push 0x65
         // 00401608: push ecx
         // 00401609: lea eax, ss:[esp+0x28]
         // 0040160d: mov ecx, esp
         // 0040160f: mov ss:[esp+0x20], esp
         // 00401613: push eax
         // 00401614: mov ss:[esp+0x23c], ebx
         // 0040161b: call ??0CString@@QAE@PBD@Z
         // 00401620: or esi, 0xffffffffffffffff
         // 00401623: mov ss:[esp+0x238], esi
         // 0040162a: call 0x402460
         // 0040162f: add esp, 0xc
         // 00401632: cmp b1 al, b1 bl
         // 00401634: jz 0x4016d4
      [-]8a0d244140008d9424????????5152e8b2f9ffff83c4088d8424????????8d4c241050e8aa0f0000bf????????68????????8d4c241489bc24????????e8960f00008b4c241051e8cafaffff83c40485c07437
         // 0040163a: mov b1 cl, b1 ds:[0x404124]
         // 00401640: lea edx, ss:[esp+0x120]
         // 00401647: push ecx
         // 00401648: push edx
         // 00401649: call 0x401000
         // 0040164e: add esp, 0x8
         // 00401651: lea eax, ss:[esp+0x120]
         // 00401658: lea ecx, ss:[esp+0x10]
         // 0040165c: push eax
         // 0040165d: call ??0CString@@QAE@PBD@Z
         // 00401662: mov edi, 0x1
         // 00401667: push 0x404020
         // 0040166c: lea ecx, ss:[esp+0x14]
         // 00401670: mov ss:[esp+0x230], edi
         // 00401677: call ??YCString@@QAEABV0@PBD@Z
         // 0040167c: mov ecx, ss:[esp+0x10]
         // 00401680: push ecx
         // 00401681: call 0x401150
         // 00401686: add esp, 0x4
         // 00401689: test eax, eax
         // 0040168b: jz 0x4016c4
      [-]8b15????????689044400052893d????????c705????????????????ffd5a1????????689044400050891d????????893d????????ffd5
         // 0040168d: mov edx, ds:[0x404488]
         // 00401693: push ServiceStatus.dwServiceType
         // 00401698: push edx
         // 00401699: mov ds:[0x4044a4], edi
         // 0040169f: mov ds:[0x404494], 0x3
         // 004016a9: call ebp
         // 004016ab: mov eax, ds:[0x404488]
         // 004016b0: push ServiceStatus.dwServiceType
         // 004016b5: push eax
         // 004016b6: mov ds:[0x4044a4], ebx
         // 004016bc: mov ds:[0x404494], edi
         // 004016c2: call ebp
      [-]8d4c241089b424????????e82c0f0000
         // 004016c4: lea ecx, ss:[esp+0x10]
         // 004016c8: mov ss:[esp+0x22c], esi
         // 004016cf: call ??1CString@@QAE@XZ
      [-]8b8c24????????5f5e5d64890d????????5b81c4????????c3
         // 004016d4: mov ecx, ss:[esp+0x224]
         // 004016db: pop edi
         // 004016dc: pop esi
         // 004016dd: pop ebp
         // 004016de: mov fs:[0x0], ecx
         // 004016e5: pop ebx
         // 004016e6: add esp, 0x220
         // 004016ec: retn 
      [-]8b442404568b35183040004883f8040f870f010000
         // 004016f0: mov eax, ss:[esp+0x4]
         // 004016f4: push esi
         // 004016f5: mov esi, ds:[SetServiceStatus]
         // 004016fb: dec eax
         // 004016fc: cmp eax, 0x4
         // 004016ff: ja def_401705
      [-]ff248528184000
         // 00401705: jmp ds:[jpt_401705+eax*0x4]
      [-]8b0d????????6890444000c705????????????????c705????????????????51eb20
         // 0040170c: mov ecx, ds:[0x404488]
         // 00401712: push ServiceStatus.dwServiceType
         // 00401717: mov ds:[0x4044a4], 0x1
         // 00401721: mov ds:[0x404494], 0x3
         // 0040172b: push ecx
         // 0040172c: jmp 0x40174e
      [-]8b15????????6890444000c705????????????????c705????????????????52
         // 0040172e: mov edx, ds:[0x404488]
         // 00401734: push ServiceStatus.dwServiceType
         // 00401739: mov ds:[0x4044a4], 0x1
         // 00401743: mov ds:[0x404494], 0x3
         // 0040174d: push edx
      [-]ffd668????????ff15943040008b15????????689044400052c705????????????????c705????????????????ffd65ec20400
         // 0040174e: call esi
         // 00401750: push 0x1f4
         // 00401755: call ds:[Sleep]
         // 0040175b: mov edx, ds:[0x404488]
         // 00401761: push ServiceStatus.dwServiceType
         // 00401766: push edx
         // 00401767: mov ds:[0x4044a4], 0x0
         // 00401771: mov ds:[0x404494], 0x1
         // 0040177b: call esi
         // 0040177d: pop esi
         // 0040177e: retn b2 0x4
      [-]a1????????689044400050c705????????????????c705????????????????ffd668????????ff15943040008b15????????689044400052c705????????????????c705????????????????ffd65ec20400
         // 00401781: mov eax, ds:[0x404488]
         // 00401786: push ServiceStatus.dwServiceType
         // 0040178b: push eax
         // 0040178c: mov ds:[0x4044a4], 0x1
         // 00401796: mov ds:[0x404494], 0x6
         // 004017a0: call esi
         // 004017a2: push 0x1f4
         // 004017a7: call ds:[Sleep]
         // 004017ad: mov edx, ds:[0x404488]
         // 004017b3: push ServiceStatus.dwServiceType
         // 004017b8: push edx
         // 004017b9: mov ds:[0x4044a4], 0x0
         // 004017c3: mov ds:[0x404494], 0x7
         // 004017cd: call esi
         // 004017cf: pop esi
         // 004017d0: retn b2 0x4
      [-]8b0d????????689044400051c705????????????????c705????????????????ffd668????????ff1594304000c705????????????????c705????????????????
         // 004017d3: mov ecx, ds:[0x404488]
         // 004017d9: push ServiceStatus.dwServiceType
         // 004017de: push ecx
         // 004017df: mov ds:[0x4044a4], 0x1
         // 004017e9: mov ds:[0x404494], 0x5
         // 004017f3: call esi
         // 004017f5: push 0x1f4
         // 004017fa: call ds:[Sleep]
         // 00401800: mov ds:[0x4044a4], 0x0
         // 0040180a: mov ds:[0x404494], 0x4
      [-]8b15????????689044400052ffd65ec20400
         // 00401814: mov edx, ds:[0x404488]
         // 0040181a: push ServiceStatus.dwServiceType
         // 0040181f: push edx
         // 00401820: call esi
         // 00401822: pop esi
         // 00401823: retn b2 0x4
      [-]83ec146a00ff157c3140008d44240050ff157831400085c00f8585000000
         // 00401840: sub esp, 0x14
         // 00401843: push 0x0
         // 00401845: call ds:[CoInitialize]
         // 0040184b: lea eax, ss:[esp+0x0]
         // 0040184f: push eax
         // 00401850: call ds:[CoCreateGuid]
         // 00401856: test eax, eax
         // 00401858: jnz 0x4018e3
      [-]8b4c240f8b54240e8b44240d81e1????????518b4c241081e2????????25????????528b54241381e1????????508b442416518b4c241981e2????????25????????528b54241c81e1????????508b44241e518b4c242081e2????????25????????528b54242081e1????????50515268????????6a4068????????ff150031400083c438
         // 0040185e: mov ecx, ss:[esp+0xf]
         // 00401862: mov edx, ss:[esp+0xe]
         // 00401866: mov eax, ss:[esp+0xd]
         // 0040186a: and ecx, 0xff
         // 00401870: push ecx
         // 00401871: mov ecx, ss:[esp+0x10]
         // 00401875: and edx, 0xff
         // 0040187b: and eax, 0xff
         // 00401880: push edx
         // 00401881: mov edx, ss:[esp+0x13]
         // 00401885: and ecx, 0xff
         // 0040188b: push eax
         // 0040188c: mov eax, ss:[esp+0x16]
         // 00401890: push ecx
         // 00401891: mov ecx, ss:[esp+0x19]
         // 00401895: and edx, 0xff
         // 0040189b: and eax, 0xff
         // 004018a0: push edx
         // 004018a1: mov edx, ss:[esp+0x1c]
         // 004018a5: and ecx, 0xff
         // 004018ab: push eax
         // 004018ac: mov eax, ss:[esp+0x1e]
         // 004018b0: push ecx
         // 004018b1: mov ecx, ss:[esp+0x20]
         // 004018b5: and edx, 0xff
         // 004018bb: and eax, 0xffff
         // 004018c0: push edx
         // 004018c1: mov edx, ss:[esp+0x20]
         // 004018c5: and ecx, 0xffff
         // 004018cb: push eax
         // 004018cc: push ecx
         // 004018cd: push edx
         // 004018ce: push 0x4043b4
         // 004018d3: push 0x40
         // 004018d5: push 0x4044b0
         // 004018da: call ds:[_snprintf]
         // 004018e0: add esp, 0x38
      [-]ff1574314000b8????????83c414c3
         // 004018e3: call ds:[CoUninitialize]
         // 004018e9: mov eax, 0x4044b0
         // 004018ee: add esp, 0x14
         // 004018f1: retn 
      [-]81ec????????53555657e831ffffff8bd8b9????????33c08dbc24????????f3abb9????????8d7c246cf3abb9????????8dbc24????????f3aba0244140008d4c246c5051895c2418e8b2f6ffff8bfb83c9ff33c083c408f2aef7d12bf98d54246c8bf78be98bfa83c9fff2ae8bcd4fc1e902f3a58bcd8d54246c83e10368????????f3a4bf????????83c9fff2aef7d12bf98bf78be98bfa83c9fff2ae8bcd4fc1e902f3a58bcd8d8424????????83e10350f3a46a00ff1550304000bf????????83c9ff33c08d9424????????f2aef7d12bf98bc18bf78bfa8d9424????????c1e902f3a58bc883e103f3a48bfb83c9ff33c0f2aef7d12bf98bf78bd98bfa83c9fff2ae8bcb4fc1e902f3a58bcb8d44241483e10350f3a48d8c24????????5168????????ff15103040008d54246c52ff15a03040008b4c2414508d442470506a026a0068????????51ff15243040008b54241452ff15283040008d8424????????68????????50ff15203140008b3d1c3140008bf06a026a0056ffd756ff15183140006a006a00568be8ffd755ff15143140008bcd8bd88bd133c08bfb56c1e902f3ab8bca6a0183e10355f3aa53ff151031400056ff150c3140008b7c244c8d93????????83c9ffc783????????????????8d722033c0f2aef7d12bf98974244c8bc18bf78b7c244c68????????c1e902f3a58bc833c083e103f3a4b9????????8bfaf3ab8d8c24????????c6020451ff152031400083c4448bf0bf????????56575553ff150831400056ff150c31400053ff150431400083c4188d54245c8d4c241833c0525150505050508d9424????????505250c7442440????????89442448894424448944244c897c246c66894424728944247466897c2470ff159c3040005f5e5d5b81c4????????c3
         // 00401900: sub esp, 0x368
         // 00401906: push ebx
         // 00401907: push ebp
         // 00401908: push esi
         // 00401909: push edi
         // 0040190a: call 0x401840
         // 0040190f: mov ebx, eax
         // 00401911: mov ecx, 0x41
         // 00401916: xor eax, eax
         // 00401918: lea edi, ss:[esp+0x170]
         // 0040191f: rep stosdd 
         // 00401921: mov ecx, 0x41
         // 00401926: lea edi, ss:[esp+0x6c]
         // 0040192a: rep stosdd 
         // 0040192c: mov ecx, 0x41
         // 00401931: lea edi, ss:[esp+0x274]
         // 00401938: rep stosdd 
         // 0040193a: mov b1 al, b1 ds:[0x404124]
         // 0040193f: lea ecx, ss:[esp+0x6c]
         // 00401943: push eax
         // 00401944: push ecx
         // 00401945: mov ss:[esp+0x18], ebx
         // 00401949: call 0x401000
         // 0040194e: mov edi, ebx
         // 00401950: or ecx, 0xffffffffffffffff
         // 00401953: xor eax, eax
         // 00401955: add esp, 0x8
         // 00401958: repne scasbb 
         // 0040195a: not ecx
         // 0040195c: sub edi, ecx
         // 0040195e: lea edx, ss:[esp+0x6c]
         // 00401962: mov esi, edi
         // 00401964: mov ebp, ecx
         // 00401966: mov edi, edx
         // 00401968: or ecx, 0xffffffffffffffff
         // 0040196b: repne scasbb 
         // 0040196d: mov ecx, ebp
         // 0040196f: dec edi
         // 00401970: shr ecx, b1 0x2
         // 00401973: rep movsdd 
         // 00401975: mov ecx, ebp
         // 00401977: lea edx, ss:[esp+0x6c]
         // 0040197b: and ecx, 0x3
         // 0040197e: push 0x104
         // 00401983: rep movsbb 
         // 00401985: mov edi, 0x404434
         // 0040198a: or ecx, 0xffffffffffffffff
         // 0040198d: repne scasbb 
         // 0040198f: not ecx
         // 00401991: sub edi, ecx
         // 00401993: mov esi, edi
         // 00401995: mov ebp, ecx
         // 00401997: mov edi, edx
         // 00401999: or ecx, 0xffffffffffffffff
         // 0040199c: repne scasbb 
         // 0040199e: mov ecx, ebp
         // 004019a0: dec edi
         // 004019a1: shr ecx, b1 0x2
         // 004019a4: rep movsdd 
         // 004019a6: mov ecx, ebp
         // 004019a8: lea eax, ss:[esp+0x278]
         // 004019af: and ecx, 0x3
         // 004019b2: push eax
         // 004019b3: rep movsbb 
         // 004019b5: push 0x0
         // 004019b7: call ds:[GetModuleFileNameA]
         // 004019bd: mov edi, 0x4043fc
         // 004019c2: or ecx, 0xffffffffffffffff
         // 004019c5: xor eax, eax
         // 004019c7: lea edx, ss:[esp+0x170]
         // 004019ce: repne scasbb 
         // 004019d0: not ecx
         // 004019d2: sub edi, ecx
         // 004019d4: mov eax, ecx
         // 004019d6: mov esi, edi
         // 004019d8: mov edi, edx
         // 004019da: lea edx, ss:[esp+0x170]
         // 004019e1: shr ecx, b1 0x2
         // 004019e4: rep movsdd 
         // 004019e6: mov ecx, eax
         // 004019e8: and ecx, 0x3
         // 004019eb: rep movsbb 
         // 004019ed: mov edi, ebx
         // 004019ef: or ecx, 0xffffffffffffffff
         // 004019f2: xor eax, eax
         // 004019f4: repne scasbb 
         // 004019f6: not ecx
         // 004019f8: sub edi, ecx
         // 004019fa: mov esi, edi
         // 004019fc: mov ebx, ecx
         // 004019fe: mov edi, edx
         // 00401a00: or ecx, 0xffffffffffffffff
         // 00401a03: repne scasbb 
         // 00401a05: mov ecx, ebx
         // 00401a07: dec edi
         // 00401a08: shr ecx, b1 0x2
         // 00401a0b: rep movsdd 
         // 00401a0d: mov ecx, ebx
         // 00401a0f: lea eax, ss:[esp+0x14]
         // 00401a13: and ecx, 0x3
         // 00401a16: push eax
         // 00401a17: rep movsbb 
         // 00401a19: lea ecx, ss:[esp+0x174]
         // 00401a20: push ecx
         // 00401a21: push 0xffffffff80000002
         // 00401a26: call ds:[RegCreateKeyA]
         // 00401a2c: lea edx, ss:[esp+0x6c]
         // 00401a30: push edx
         // 00401a31: call ds:[lstrlenA]
         // 00401a37: mov ecx, ss:[esp+0x14]
         // 00401a3b: push eax
         // 00401a3c: lea eax, ss:[esp+0x70]
         // 00401a40: push eax
         // 00401a41: push 0x2
         // 00401a43: push 0x0
         // 00401a45: push 0x4043f0
         // 00401a4a: push ecx
         // 00401a4b: call ds:[RegSetValueExA]
         // 00401a51: mov edx, ss:[esp+0x14]
         // 00401a55: push edx
         // 00401a56: call ds:[RegCloseKey]
         // 00401a5c: lea eax, ss:[esp+0x274]
         // 00401a63: push 0x4043ec
         // 00401a68: push eax
         // 00401a69: call ds:[fopen]
         // 00401a6f: mov edi, ds:[fseek]
         // 00401a75: mov esi, eax
         // 00401a77: push 0x2
         // 00401a79: push 0x0
         // 00401a7b: push esi
         // 00401a7c: call edi
         // 00401a7e: push esi
         // 00401a7f: call ds:[ftell]
         // 00401a85: push 0x0
         // 00401a87: push 0x0
         // 00401a89: push esi
         // 00401a8a: mov ebp, eax
         // 00401a8c: call edi
         // 00401a8e: push ebp
         // 00401a8f: call ds:[malloc]
         // 00401a95: mov ecx, ebp
         // 00401a97: mov ebx, eax
         // 00401a99: mov edx, ecx
         // 00401a9b: xor eax, eax
         // 00401a9d: mov edi, ebx
         // 00401a9f: push esi
         // 00401aa0: shr ecx, b1 0x2
         // 00401aa3: rep stosdd 
         // 00401aa5: mov ecx, edx
         // 00401aa7: push 0x1
         // 00401aa9: and ecx, 0x3
         // 00401aac: push ebp
         // 00401aad: rep stosbb 
         // 00401aaf: push ebx
         // 00401ab0: call ds:[fread]
         // 00401ab6: push esi
         // 00401ab7: call ds:[fclose]
         // 00401abd: mov edi, ss:[esp+0x4c]
         // 00401ac1: lea edx, ds:[ebx+0x3058]
         // 00401ac7: or ecx, 0xffffffffffffffff
         // 00401aca: mov ds:[ebx+0x6a0], 0x4
         // 00401ad4: lea esi, ds:[edx+0x20]
         // 00401ad7: xor eax, eax
         // 00401ad9: repne scasbb 
         // 00401adb: not ecx
         // 00401add: sub edi, ecx
         // 00401adf: mov ss:[esp+0x4c], esi
         // 00401ae3: mov eax, ecx
         // 00401ae5: mov esi, edi
         // 00401ae7: mov edi, ss:[esp+0x4c]
         // 00401aeb: push 0x4043e8
         // 00401af0: shr ecx, b1 0x2
         // 00401af3: rep movsdd 
         // 00401af5: mov ecx, eax
         // 00401af7: xor eax, eax
         // 00401af9: and ecx, 0x3
         // 00401afc: rep movsbb 
         // 00401afe: mov ecx, 0x8
         // 00401b03: mov edi, edx
         // 00401b05: rep stosdd 
         // 00401b07: lea ecx, ss:[esp+0xac]
         // 00401b0e: mov b1 ds:[edx], b1 0x4
         // 00401b11: push ecx
         // 00401b12: call ds:[fopen]
         // 00401b18: add esp, 0x44
         // 00401b1b: mov esi, eax
         // 00401b1d: mov edi, 0x1
         // 00401b22: push esi
         // 00401b23: push edi
         // 00401b24: push ebp
         // 00401b25: push ebx
         // 00401b26: call ds:[fwrite]
         // 00401b2c: push esi
         // 00401b2d: call ds:[fclose]
         // 00401b33: push ebx
         // 00401b34: call ds:[free]
         // 00401b3a: add esp, 0x18
         // 00401b3d: lea edx, ss:[esp+0x5c]
         // 00401b41: lea ecx, ss:[esp+0x18]
         // 00401b45: xor eax, eax
         // 00401b47: push edx
         // 00401b48: push ecx
         // 00401b49: push eax
         // 00401b4a: push eax
         // 00401b4b: push eax
         // 00401b4c: push eax
         // 00401b4d: push eax
         // 00401b4e: lea edx, ss:[esp+0x88]
         // 00401b55: push eax
         // 00401b56: push edx
         // 00401b57: push eax
         // 00401b58: mov ss:[esp+0x40], 0x44
         // 00401b60: mov ss:[esp+0x48], eax
         // 00401b64: mov ss:[esp+0x44], eax
         // 00401b68: mov ss:[esp+0x4c], eax
         // 00401b6c: mov ss:[esp+0x6c], edi
         // 00401b70: mov b2 ss:[esp+0x72], b2 ax
         // 00401b75: mov ss:[esp+0x74], eax
         // 00401b79: mov b2 ss:[esp+0x70], b2 di
         // 00401b7e: call ds:[CreateProcessA]
         // 00401b84: pop edi
         // 00401b85: pop esi
         // 00401b86: pop ebp
         // 00401b87: pop ebx
         // 00401b88: add esp, 0x368
         // 00401b8e: retn 
      [-]6aff68????????64a1????????50648925????????81ec????????a0244140005556578d4c24185051e842f4ffffbf????????83c9ff33c08d542420f2aef7d12bf983c4048bf78be98bfa83c9fff2ae8bcd4fc1e902f3a58bcd8964241883e103f3a48bcc68????????e80d0a00006a65518d4424248bcc8964241c50c78424????????????????e8ef090000c78424????????????????e83308000083c40c84c07464
         // 00401b90: push 0xffffffffffffffff
         // 00401b92: push 0x402856
         // 00401b97: mov eax, fs:[0x0]
         // 00401b9d: push eax
         // 00401b9e: mov fs:[0x0], esp
         // 00401ba5: sub esp, 0x214
         // 00401bab: mov b1 al, b1 ds:[0x404124]
         // 00401bb0: push ebp
         // 00401bb1: push esi
         // 00401bb2: push edi
         // 00401bb3: lea ecx, ss:[esp+0x18]
         // 00401bb7: push eax
         // 00401bb8: push ecx
         // 00401bb9: call 0x401000
         // 00401bbe: mov edi, 0x404020
         // 00401bc3: or ecx, 0xffffffffffffffff
         // 00401bc6: xor eax, eax
         // 00401bc8: lea edx, ss:[esp+0x20]
         // 00401bcc: repne scasbb 
         // 00401bce: not ecx
         // 00401bd0: sub edi, ecx
         // 00401bd2: add esp, 0x4
         // 00401bd5: mov esi, edi
         // 00401bd7: mov ebp, ecx
         // 00401bd9: mov edi, edx
         // 00401bdb: or ecx, 0xffffffffffffffff
         // 00401bde: repne scasbb 
         // 00401be0: mov ecx, ebp
         // 00401be2: dec edi
         // 00401be3: shr ecx, b1 0x2
         // 00401be6: rep movsdd 
         // 00401be8: mov ecx, ebp
         // 00401bea: mov ss:[esp+0x18], esp
         // 00401bee: and ecx, 0x3
         // 00401bf1: rep movsbb 
         // 00401bf3: mov ecx, esp
         // 00401bf5: push 0x4043b0
         // 00401bfa: call ??0CString@@QAE@PBD@Z
         // 00401bff: push 0x65
         // 00401c01: push ecx
         // 00401c02: lea eax, ss:[esp+0x24]
         // 00401c06: mov ecx, esp
         // 00401c08: mov ss:[esp+0x1c], esp
         // 00401c0c: push eax
         // 00401c0d: mov ss:[esp+0x238], 0x0
         // 00401c18: call ??0CString@@QAE@PBD@Z
         // 00401c1d: mov ss:[esp+0x234], 0xffffffffffffffff
         // 00401c28: call 0x402460
         // 00401c2d: add esp, 0xc
         // 00401c30: test b1 al, b1 al
         // 00401c32: jz 0x401c98
      [-]8a0d244140008d9424????????5152e8b8f3ffff83c4088d8424????????8d4c240c50e8b009000068????????8d4c2410c78424????????????????e89d0900008b4c240c51e8d1f4ffff83c4048d4c240c85c0c78424????????????????e868090000
         // 00401c34: mov b1 cl, b1 ds:[0x404124]
         // 00401c3a: lea edx, ss:[esp+0x11c]
         // 00401c41: push ecx
         // 00401c42: push edx
         // 00401c43: call 0x401000
         // 00401c48: add esp, 0x8
         // 00401c4b: lea eax, ss:[esp+0x11c]
         // 00401c52: lea ecx, ss:[esp+0xc]
         // 00401c56: push eax
         // 00401c57: call ??0CString@@QAE@PBD@Z
         // 00401c5c: push 0x404020
         // 00401c61: lea ecx, ss:[esp+0x10]
         // 00401c65: mov ss:[esp+0x22c], 0x1
         // 00401c70: call ??YCString@@QAEABV0@PBD@Z
         // 00401c75: mov ecx, ss:[esp+0xc]
         // 00401c79: push ecx
         // 00401c7a: call 0x401150
         // 00401c7f: add esp, 0x4
         // 00401c82: lea ecx, ss:[esp+0xc]
         // 00401c86: test eax, eax
         // 00401c88: mov ss:[esp+0x228], 0xffffffffffffffff
         // 00401c93: call ??1CString@@QAE@XZ
      [-]8b8c24????????5f5e64890d????????5d81c4????????c3
         // 00401c98: mov ecx, ss:[esp+0x220]
         // 00401c9f: pop edi
         // 00401ca0: pop esi
         // 00401ca1: mov fs:[0x0], ecx
         // 00401ca8: pop ebp
         // 00401ca9: add esp, 0x220
         // 00401caf: retn 
      [-]81ec????????55568b3564314000576a0068????????68????????6a00ffd6a1????????83f8010f8521020000
         // 00401cb0: sub esp, 0x330
         // 00401cb6: push ebp
         // 00401cb7: push esi
         // 00401cb8: mov esi, ds:[MessageBoxA]
         // 00401cbe: push edi
         // 00401cbf: push 0x0
         // 00401cc1: push 0x4042c8
         // 00401cc6: push 0x4042c8
         // 00401ccb: push 0x0
         // 00401ccd: call esi
         // 00401ccf: mov eax, ds:[0x404120]
         // 00401cd4: cmp eax, 0x1
         // 00401cd7: jnz 0x401efe
      [-]b9????????33c08d7c2431c644243000f3ab66abaa8d44241c5068????????6a0068????????68????????ff150430400085c07534
         // 00401cdd: mov ecx, 0x40
         // 00401ce2: xor eax, eax
         // 00401ce4: lea edi, ss:[esp+0x31]
         // 00401ce8: mov b1 ss:[esp+0x30], b1 0x0
         // 00401ced: rep stosdd 
         // 00401cef: stosww 
         // 00401cf1: stosbb 
         // 00401cf2: lea eax, ss:[esp+0x1c]
         // 00401cf6: push eax
         // 00401cf7: push 0xf003f
         // 00401cfc: push 0x0
         // 00401cfe: push 0x404340
         // 00401d03: push 0xffffffff80000002
         // 00401d08: call ds:[RegOpenKeyExA]
         // 00401d0e: test eax, eax
         // 00401d10: jnz 0x401d46
      [-]8d4c24148d542430518b4c24208d44241c52506a0068????????51c744242c????????ff15083040008b54241c52ff1528304000
         // 00401d12: lea ecx, ss:[esp+0x14]
         // 00401d16: lea edx, ss:[esp+0x30]
         // 00401d1a: push ecx
         // 00401d1b: mov ecx, ss:[esp+0x20]
         // 00401d1f: lea eax, ss:[esp+0x1c]
         // 00401d23: push edx
         // 00401d24: push eax
         // 00401d25: push 0x0
         // 00401d27: push 0x404334
         // 00401d2c: push ecx
         // 00401d2d: mov ss:[esp+0x2c], 0xc8
         // 00401d35: call ds:[RegQueryValueExA]
         // 00401d3b: mov edx, ss:[esp+0x1c]
         // 00401d3f: push edx
         // 00401d40: call ds:[RegCloseKey]
      [-]68????????8d4c2414e8b80800008d44241068????????8d4c24185051e89e0800008b308d4c2430
         // 00401d46: push 0x40437c
         // 00401d4b: lea ecx, ss:[esp+0x14]
         // 00401d4f: call ??0CString@@QAE@PBD@Z
         // 00401d54: lea eax, ss:[esp+0x10]
         // 00401d58: push 0x404020
         // 00401d5d: lea ecx, ss:[esp+0x18]
         // 00401d61: push eax
         // 00401d62: push ecx
         // 00401d63: call ??H@YG?AVCString@@ABV0@PBD@Z
         // 00401d68: mov esi, ds:[eax]
         // 00401d6a: lea ecx, ss:[esp+0x30]
      [-]8a118ac23a16751c
         // 00401d6e: mov b1 dl, b1 ds:[ecx]
         // 00401d70: mov b1 al, b1 dl
         // 00401d72: cmp b1 dl, b1 ds:[esi]
         // 00401d74: jnz 0x401d92
      [-]84c07414
         // 00401d76: test b1 al, b1 al
         // 00401d78: jz 0x401d8e
      [-]8a51018ac23a5601750e
         // 00401d7a: mov b1 dl, b1 ds:[ecx+0x1]
         // 00401d7d: mov b1 al, b1 dl
         // 00401d7f: cmp b1 dl, b1 ds:[esi+0x1]
         // 00401d82: jnz 0x401d92
      [-]83c10283c60284c075e0
         // 00401d84: add ecx, 0x2
         // 00401d87: add esi, 0x2
         // 00401d8a: test b1 al, b1 al
         // 00401d8c: jnz 0x401d6e
      [-]33f6eb05
         // 00401d8e: xor esi, esi
         // 00401d90: jmp 0x401d97
      [-]1bf683deff
         // 00401d92: sbb esi, esi
         // 00401d94: sbb esi, 0xffffffffffffffff
      [-]8d4c2414e86008000085f67507
         // 00401d97: lea ecx, ss:[esp+0x14]
         // 00401d9b: call ??1CString@@QAE@XZ
         // 00401da0: test esi, esi
         // 00401da2: jnz 0x401dab
      [-]56ff1524314000
         // 00401da4: push esi
         // 00401da5: call ds:[exit]
      [-]8b2dbc3040008d8424????????68????????50ffd5bf????????83c9ff33c08d9424????????f2aef7d12bf98bf78bfa8bd183c9fff2ae8bca4fc1e902f3a58bca8d9424????????83e103f3a4bf????????83c9fff2aef7d12bf98bf78bfa8bd183c9fff2ae8bca4fc1e902f3a58bca83e103f3a4518bcc8964241c68????????e8db0700006a65518d8424????????8bcc8964242450e8c5070000e81406000083c40c84c07517
         // 00401dab: mov ebp, ds:[GetSystemDirectoryA]
         // 00401db1: lea eax, ss:[esp+0x134]
         // 00401db8: push 0x104
         // 00401dbd: push eax
         // 00401dbe: call ebp
         // 00401dc0: mov edi, 0x4042cc
         // 00401dc5: or ecx, 0xffffffffffffffff
         // 00401dc8: xor eax, eax
         // 00401dca: lea edx, ss:[esp+0x134]
         // 00401dd1: repne scasbb 
         // 00401dd3: not ecx
         // 00401dd5: sub edi, ecx
         // 00401dd7: mov esi, edi
         // 00401dd9: mov edi, edx
         // 00401ddb: mov edx, ecx
         // 00401ddd: or ecx, 0xffffffffffffffff
         // 00401de0: repne scasbb 
         // 00401de2: mov ecx, edx
         // 00401de4: dec edi
         // 00401de5: shr ecx, b1 0x2
         // 00401de8: rep movsdd 
         // 00401dea: mov ecx, edx
         // 00401dec: lea edx, ss:[esp+0x134]
         // 00401df3: and ecx, 0x3
         // 00401df6: rep movsbb 
         // 00401df8: mov edi, 0x404020
         // 00401dfd: or ecx, 0xffffffffffffffff
         // 00401e00: repne scasbb 
         // 00401e02: not ecx
         // 00401e04: sub edi, ecx
         // 00401e06: mov esi, edi
         // 00401e08: mov edi, edx
         // 00401e0a: mov edx, ecx
         // 00401e0c: or ecx, 0xffffffffffffffff
         // 00401e0f: repne scasbb 
         // 00401e11: mov ecx, edx
         // 00401e13: dec edi
         // 00401e14: shr ecx, b1 0x2
         // 00401e17: rep movsdd 
         // 00401e19: mov ecx, edx
         // 00401e1b: and ecx, 0x3
         // 00401e1e: rep movsbb 
         // 00401e20: push ecx
         // 00401e21: mov ecx, esp
         // 00401e23: mov ss:[esp+0x1c], esp
         // 00401e27: push 0x4043b0
         // 00401e2c: call ??0CString@@QAE@PBD@Z
         // 00401e31: push 0x65
         // 00401e33: push ecx
         // 00401e34: lea eax, ss:[esp+0x140]
         // 00401e3b: mov ecx, esp
         // 00401e3d: mov ss:[esp+0x24], esp
         // 00401e41: push eax
         // 00401e42: call ??0CString@@QAE@PBD@Z
         // 00401e47: call 0x402460
         // 00401e4c: add esp, 0xc
         // 00401e4f: test b1 al, b1 al
         // 00401e51: jnz 0x401e6a
      [-]8d4c2410e8a407000033c05f5e5d81c4????????c21000
         // 00401e53: lea ecx, ss:[esp+0x10]
         // 00401e57: call ??1CString@@QAE@XZ
         // 00401e5c: xor eax, eax
         // 00401e5e: pop edi
         // 00401e5f: pop esi
         // 00401e60: pop ebp
         // 00401e61: add esp, 0x330
         // 00401e67: retn b2 0x10
      [-]e8f1f3ffff8d8c24????????68????????51ffd58d9424????????8d4c240c52e87d07000068????????8d4c2410e87507000068????????8d4c2410e8670700008b44240c50e89bf2ffff83c40485c07520
         // 00401e6a: call 0x401260
         // 00401e6f: lea ecx, ss:[esp+0x238]
         // 00401e76: push 0x104
         // 00401e7b: push ecx
         // 00401e7c: call ebp
         // 00401e7e: lea edx, ss:[esp+0x238]
         // 00401e85: lea ecx, ss:[esp+0xc]
         // 00401e89: push edx
         // 00401e8a: call ??0CString@@QAE@PBD@Z
         // 00401e8f: push 0x4042cc
         // 00401e94: lea ecx, ss:[esp+0x10]
         // 00401e98: call ??YCString@@QAEABV0@PBD@Z
         // 00401e9d: push 0x404020
         // 00401ea2: lea ecx, ss:[esp+0x10]
         // 00401ea6: call ??YCString@@QAEABV0@PBD@Z
         // 00401eab: mov eax, ss:[esp+0xc]
         // 00401eaf: push eax
         // 00401eb0: call 0x401150
         // 00401eb5: add esp, 0x4
         // 00401eb8: test eax, eax
         // 00401eba: jnz 0x401edc
      [-]8d4c240ce83b0700008d4c2410e83207000033c05f5e5d81c4????????c21000
         // 00401ebc: lea ecx, ss:[esp+0xc]
         // 00401ec0: call ??1CString@@QAE@XZ
         // 00401ec5: lea ecx, ss:[esp+0x10]
         // 00401ec9: call ??1CString@@QAE@XZ
         // 00401ece: xor eax, eax
         // 00401ed0: pop edi
         // 00401ed1: pop esi
         // 00401ed2: pop ebp
         // 00401ed3: add esp, 0x330
         // 00401ed9: retn b2 0x10
      [-]e8aff4ffff8d4c240ce8160700008d4c2410e80d070000a1????????8b3564314000
         // 00401edc: call 0x401390
         // 00401ee1: lea ecx, ss:[esp+0xc]
         // 00401ee5: call ??1CString@@QAE@XZ
         // 00401eea: lea ecx, ss:[esp+0x10]
         // 00401eee: call ??1CString@@QAE@XZ
         // 00401ef3: mov eax, ds:[0x404120]
         // 00401ef8: mov esi, ds:[MessageBoxA]
      [-]83f8027572
         // 00401efe: cmp eax, 0x2
         // 00401f01: jnz 0x401f75
      [-]e81804000085c0743c
         // 00401f03: call 0x402320
         // 00401f08: test eax, eax
         // 00401f0a: jz 0x401f48
      [-]8d4c2420c7442420????????51c7442428????????c74424????????00c74424????????00ff150c304000b8????????5f5e5d81c4????????c21000
         // 00401f0c: lea ecx, ss:[esp+0x20]
         // 00401f10: mov ss:[esp+0x20], 0x404128
         // 00401f18: push ecx
         // 00401f19: mov ss:[esp+0x28], 0x401510
         // 00401f21: mov ss:[esp+0x2c], 0x0
         // 00401f29: mov ss:[esp+0x30], 0x0
         // 00401f31: call ds:[StartServiceCtrlDispatcherA]
         // 00401f37: mov eax, 0x1
         // 00401f3c: pop edi
         // 00401f3d: pop esi
         // 00401f3e: pop ebp
         // 00401f3f: add esp, 0x330
         // 00401f45: retn b2 0x10
      [-]68????????68????????68????????e874000000a1????????83c40c85c07457
         // 00401f48: push 0x4041c8
         // 00401f4d: push 0x404148
         // 00401f52: push 0x404128
         // 00401f57: call 0x401fd0
         // 00401f5c: mov eax, ds:[0x4044ac]
         // 00401f61: add esp, 0xc
         // 00401f64: test eax, eax
         // 00401f66: jz 0x401fbf
      [-]e823f4ffff6a00ff1524314000
         // 00401f68: call 0x401390
         // 00401f6d: push 0x0
         // 00401f6f: call ds:[exit]
      [-]83f803752b
         // 00401f75: cmp eax, 0x3
         // 00401f78: jnz 0x401fa5
      [-]6a0068????????68????????6a00ffd6e871f9ffffe8fcf3ffffb8????????5f5e5d81c4????????c21000
         // 00401f7a: push 0x0
         // 00401f7c: push 0x4044f4
         // 00401f81: push 0x4044f4
         // 00401f86: push 0x0
         // 00401f88: call esi
         // 00401f8a: call 0x401900
         // 00401f8f: call 0x401390
         // 00401f94: mov eax, 0x1
         // 00401f99: pop edi
         // 00401f9a: pop esi
         // 00401f9b: pop ebp
         // 00401f9c: add esp, 0x330
         // 00401fa2: retn b2 0x10
      [-]83f8047515
         // 00401fa5: cmp eax, 0x4
         // 00401fa8: jnz 0x401fbf
      [-]6a0068????????68????????6a00ffd6e8d1fbffff
         // 00401faa: push 0x0
         // 00401fac: push 0x4044f4
         // 00401fb1: push 0x4044f4
         // 00401fb6: push 0x0
         // 00401fb8: call esi
         // 00401fba: call 0x401b90
      [-]5f5eb8????????5d81c4????????c21000
         // 00401fbf: pop edi
         // 00401fc0: pop esi
         // 00401fc1: mov eax, 0x1
         // 00401fc6: pop ebp
         // 00401fc7: add esp, 0x330
         // 00401fcd: retn b2 0x10
      [-]558bec6aff6888314000683026400064a1????????50648925????????81ec????????53565768????????8d85????????5033db53ff15503040008a0d24414000518d95????????52e8e2efffff8dbd????????83c9ff33c0f2aef7d149518d85????????508d8d????????51ff152c31400083c41485c00f842a010000
         // 00401fd0: push ebp
         // 00401fd1: mov ebp, esp
         // 00401fd3: push 0xffffffffffffffff
         // 00401fd5: push stru_403188.EnclosingLevel
         // 00401fda: push _except_handler3
         // 00401fdf: mov eax, fs:[0x0]
         // 00401fe5: push eax
         // 00401fe6: mov fs:[0x0], esp
         // 00401fed: sub esp, 0x370
         // 00401ff3: push ebx
         // 00401ff4: push esi
         // 00401ff5: push edi
         // 00401ff6: push 0x104
         // 00401ffb: lea eax, ss:[ebp+0xfffffffffffffcd8]
         // 00402001: push eax
         // 00402002: xor ebx, ebx
         // 00402004: push ebx
         // 00402005: call ds:[GetModuleFileNameA]
         // 0040200b: mov b1 cl, b1 ds:[0x404124]
         // 00402011: push ecx
         // 00402012: lea edx, ss:[ebp+0xfffffffffffffde0]
         // 00402018: push edx
         // 00402019: call 0x401000
         // 0040201e: lea edi, ss:[ebp+0xfffffffffffffde0]
         // 00402024: or ecx, 0xffffffffffffffff
         // 00402027: xor eax, eax
         // 00402029: repne scasbb 
         // 0040202b: not ecx
         // 0040202d: dec ecx
         // 0040202e: push ecx
         // 0040202f: lea eax, ss:[ebp+0xfffffffffffffcd8]
         // 00402035: push eax
         // 00402036: lea ecx, ss:[ebp+0xfffffffffffffde0]
         // 0040203c: push ecx
         // 0040203d: call ds:[strncmp]
         // 00402043: add esp, 0x14
         // 00402046: test eax, eax
         // 00402048: jz 0x402178
      [-]6a508d95????????528d85????????50ff156c31400068????????8d8d????????518b3528314000ffd683c40885c07543
         // 0040204e: push 0x50
         // 00402050: lea edx, ss:[ebp+0xfffffffffffffc80]
         // 00402056: push edx
         // 00402057: lea eax, ss:[ebp+0xfffffffffffffcd8]
         // 0040205d: push eax
         // 0040205e: call ds:[GetFileTitleA]
         // 00402064: push 0x404434
         // 00402069: lea ecx, ss:[ebp+0xfffffffffffffc80]
         // 0040206f: push ecx
         // 00402070: mov esi, ds:[strstr]
         // 00402076: call esi
         // 00402078: add esp, 0x8
         // 0040207b: test eax, eax
         // 0040207d: jnz 0x4020c2
      [-]68????????8d95????????52ffd683c40885c0752e
         // 0040207f: push 0x40446c
         // 00402084: lea edx, ss:[ebp+0xfffffffffffffc80]
         // 0040208a: push edx
         // 0040208b: call esi
         // 0040208d: add esp, 0x8
         // 00402090: test eax, eax
         // 00402092: jnz 0x4020c2
      [-]8d95????????bf????????83c9fff2aef7d12bf98bf78bd98bfa83c9fff2ae4f8bcbc1e902f3a58bcb83e103f3a4
         // 00402094: lea edx, ss:[ebp+0xfffffffffffffc80]
         // 0040209a: mov edi, 0x404434
         // 0040209f: or ecx, 0xffffffffffffffff
         // 004020a2: repne scasbb 
         // 004020a4: not ecx
         // 004020a6: sub edi, ecx
         // 004020a8: mov esi, edi
         // 004020aa: mov ebx, ecx
         // 004020ac: mov edi, edx
         // 004020ae: or ecx, 0xffffffffffffffff
         // 004020b1: repne scasbb 
         // 004020b3: dec edi
         // 004020b4: mov ecx, ebx
         // 004020b6: shr ecx, b1 0x2
         // 004020b9: rep movsdd 
         // 004020bb: mov ecx, ebx
         // 004020bd: and ecx, 0x3
         // 004020c0: rep movsbb 
      [-]8d95????????bf????????83c9ff33c0f2aef7d12bf98bf78bd98bfa83c9fff2ae4f8bcbc1e902f3a58bcb83e103f3a48dbd????????8d95????????83c9fff2aef7d12bf98bf78bd98bfa83c9fff2ae4f8bcbc1e902f3a58bcb83e103f3a4508d85????????508d8d????????51ff155c304000b9????????33c08dbd????????f3ab8dbd????????8d95????????83c9fff2aef7d12bf98bc18bf78bfac1e902f3a58bc883e103f3a4c705????????????????33db
         // 004020c2: lea edx, ss:[ebp+0xfffffffffffffde0]
         // 004020c8: mov edi, 0x4042cc
         // 004020cd: or ecx, 0xffffffffffffffff
         // 004020d0: xor eax, eax
         // 004020d2: repne scasbb 
         // 004020d4: not ecx
         // 004020d6: sub edi, ecx
         // 004020d8: mov esi, edi
         // 004020da: mov ebx, ecx
         // 004020dc: mov edi, edx
         // 004020de: or ecx, 0xffffffffffffffff
         // 004020e1: repne scasbb 
         // 004020e3: dec edi
         // 004020e4: mov ecx, ebx
         // 004020e6: shr ecx, b1 0x2
         // 004020e9: rep movsdd 
         // 004020eb: mov ecx, ebx
         // 004020ed: and ecx, 0x3
         // 004020f0: rep movsbb 
         // 004020f2: lea edi, ss:[ebp+0xfffffffffffffc80]
         // 004020f8: lea edx, ss:[ebp+0xfffffffffffffde0]
         // 004020fe: or ecx, 0xffffffffffffffff
         // 00402101: repne scasbb 
         // 00402103: not ecx
         // 00402105: sub edi, ecx
         // 00402107: mov esi, edi
         // 00402109: mov ebx, ecx
         // 0040210b: mov edi, edx
         // 0040210d: or ecx, 0xffffffffffffffff
         // 00402110: repne scasbb 
         // 00402112: dec edi
         // 00402113: mov ecx, ebx
         // 00402115: shr ecx, b1 0x2
         // 00402118: rep movsdd 
         // 0040211a: mov ecx, ebx
         // 0040211c: and ecx, 0x3
         // 0040211f: rep movsbb 
         // 00402121: push eax
         // 00402122: lea eax, ss:[ebp+0xfffffffffffffde0]
         // 00402128: push eax
         // 00402129: lea ecx, ss:[ebp+0xfffffffffffffcd8]
         // 0040212f: push ecx
         // 00402130: call ds:[CopyFileA]
         // 00402136: mov ecx, 0x41
         // 0040213b: xor eax, eax
         // 0040213d: lea edi, ss:[ebp+0xfffffffffffffcd8]
         // 00402143: rep stosdd 
         // 00402145: lea edi, ss:[ebp+0xfffffffffffffde0]
         // 0040214b: lea edx, ss:[ebp+0xfffffffffffffcd8]
         // 00402151: or ecx, 0xffffffffffffffff
         // 00402154: repne scasbb 
         // 00402156: not ecx
         // 00402158: sub edi, ecx
         // 0040215a: mov eax, ecx
         // 0040215c: mov esi, edi
         // 0040215e: mov edi, edx
         // 00402160: shr ecx, b1 0x2
         // 00402163: rep movsdd 
         // 00402165: mov ecx, eax
         // 00402167: and ecx, 0x3
         // 0040216a: rep movsbb 
         // 0040216c: mov ds:[0x4044ac], 0x1
         // 00402176: xor ebx, ebx
      [-]6a068d8d????????51ff1558304000899d????????899d????????899d????????895dfc68????????5353ff15343040008bf089b5????????85f60f8416010000
         // 00402178: push 0x6
         // 0040217a: lea ecx, ss:[ebp+0xfffffffffffffcd8]
         // 00402180: push ecx
         // 00402181: call ds:[SetFileAttributesA]
         // 00402187: mov ss:[ebp+0xfffffffffffffddc], ebx
         // 0040218d: mov ss:[ebp+0xfffffffffffffcd0], ebx
         // 00402193: mov ss:[ebp+0xfffffffffffffcd4], ebx
         // 00402199: mov ss:[ebp+0xfffffffffffffffc], ebx
         // 0040219c: push 0xf003f
         // 004021a1: push ebx
         // 004021a2: push ebx
         // 004021a3: call ds:[OpenSCManagerA]
         // 004021a9: mov esi, eax
         // 004021ab: mov ss:[ebp+0xfffffffffffffcd4], esi
         // 004021b1: test esi, esi
         // 004021b3: jz 0x4022cf
      [-]6a006a006a006a006a008d95????????526a006a026a1068????????8b450c508b7d085756ff15303040008bd8899d????????85db7535
         // 004021b9: push 0x0
         // 004021bb: push 0x0
         // 004021bd: push 0x0
         // 004021bf: push 0x0
         // 004021c1: push 0x0
         // 004021c3: lea edx, ss:[ebp+0xfffffffffffffcd8]
         // 004021c9: push edx
         // 004021ca: push 0x0
         // 004021cc: push 0x2
         // 004021ce: push 0x10
         // 004021d0: push 0xf01ff
         // 004021d5: mov eax, ss:[ebp+0xc]
         // 004021d8: push eax
         // 004021d9: mov edi, ss:[ebp+0x8]
         // 004021dc: push edi
         // 004021dd: push esi
         // 004021de: call ds:[CreateServiceA]
         // 004021e4: mov ebx, eax
         // 004021e6: mov ss:[ebp+0xfffffffffffffcd0], ebx
         // 004021ec: test ebx, ebx
         // 004021ee: jnz 0x402225
      [-]ff15543040003d????????7528
         // 004021f0: call ds:[GetLastError]
         // 004021f6: cmp eax, 0x431
         // 004021fb: jnz 0x402225
      [-]68????????5756ff152c3040008bd8899d????????85db0f84b5000000
         // 004021fd: push 0xf01ff
         // 00402202: push edi
         // 00402203: push esi
         // 00402204: call ds:[OpenServiceA]
         // 0040220a: mov ebx, eax
         // 0040220c: mov ss:[ebp+0xfffffffffffffcd0], ebx
         // 00402212: test ebx, ebx
         // 00402214: jz 0x4022cf
      [-]6a006a0053ff1538304000
         // 0040221a: push 0x0
         // 0040221c: push 0x0
         // 0040221e: push ebx
         // 0040221f: call ds:[StartServiceA]
      [-]6a006a0053ff153830400085c00f8497000000
         // 00402225: push 0x0
         // 00402227: push 0x0
         // 00402229: push ebx
         // 0040222a: call ds:[StartServiceA]
         // 00402230: test eax, eax
         // 00402232: jz 0x4022cf
      [-]8d95????????bf????????83c9ff33c0f2aef7d12bf98bc18bf78bfac1e902f3a58bc883e103f3a48d95????????8b7d0883c9ff33c0f2aef7d12bf98bf78bfa8bd183c9fff2ae4f8bcac1e902f3a58bca83e103f3a48d85????????508d8d????????5168????????ff151c3040008b751056ff15a030400050566a016a0068????????8b95????????52ff15243040008bb5????????
         // 00402238: lea edx, ss:[ebp+0xfffffffffffffee4]
         // 0040223e: mov edi, 0x404448
         // 00402243: or ecx, 0xffffffffffffffff
         // 00402246: xor eax, eax
         // 00402248: repne scasbb 
         // 0040224a: not ecx
         // 0040224c: sub edi, ecx
         // 0040224e: mov eax, ecx
         // 00402250: mov esi, edi
         // 00402252: mov edi, edx
         // 00402254: shr ecx, b1 0x2
         // 00402257: rep movsdd 
         // 00402259: mov ecx, eax
         // 0040225b: and ecx, 0x3
         // 0040225e: rep movsbb 
         // 00402260: lea edx, ss:[ebp+0xfffffffffffffee4]
         // 00402266: mov edi, ss:[ebp+0x8]
         // 00402269: or ecx, 0xffffffffffffffff
         // 0040226c: xor eax, eax
         // 0040226e: repne scasbb 
         // 00402270: not ecx
         // 00402272: sub edi, ecx
         // 00402274: mov esi, edi
         // 00402276: mov edi, edx
         // 00402278: mov edx, ecx
         // 0040227a: or ecx, 0xffffffffffffffff
         // 0040227d: repne scasbb 
         // 0040227f: dec edi
         // 00402280: mov ecx, edx
         // 00402282: shr ecx, b1 0x2
         // 00402285: rep movsdd 
         // 00402287: mov ecx, edx
         // 00402289: and ecx, 0x3
         // 0040228c: rep movsbb 
         // 0040228e: lea eax, ss:[ebp+0xfffffffffffffddc]
         // 00402294: push eax
         // 00402295: lea ecx, ss:[ebp+0xfffffffffffffee4]
         // 0040229b: push ecx
         // 0040229c: push 0xffffffff80000002
         // 004022a1: call ds:[RegOpenKeyA]
         // 004022a7: mov esi, ss:[ebp+0x10]
         // 004022aa: push esi
         // 004022ab: call ds:[lstrlenA]
         // 004022b1: push eax
         // 004022b2: push esi
         // 004022b3: push 0x1
         // 004022b5: push 0x0
         // 004022b7: push 0x40443c
         // 004022bc: mov edx, ss:[ebp+0xfffffffffffffddc]
         // 004022c2: push edx
         // 004022c3: call ds:[RegSetValueExA]
         // 004022c9: mov esi, ss:[ebp+0xfffffffffffffcd4]
      [-]c745????????ffe81d000000
         // 004022cf: mov ss:[ebp+0xfffffffffffffffc], 0xffffffffffffffff
         // 004022d6: call 0x4022f8
      [-]85db7407
         // 004022f8: test ebx, ebx
         // 004022fa: jz 0x402303
      [-]53ff1500304000
         // 004022fc: push ebx
         // 004022fd: call ds:[CloseServiceHandle]
      [-]85f67407
         // 00402303: test esi, esi
         // 00402305: jz 0x40230e
      [-]56ff1500304000
         // 00402307: push esi
         // 00402308: call ds:[CloseServiceHandle]
      [-]8b85????????85c07407
         // 0040230e: mov eax, ss:[ebp+0xfffffffffffffddc]
         // 00402314: test eax, eax
         // 00402316: jz 0x40231f
      [-]50ff1528304000
         // 00402318: push eax
         // 00402319: call ds:[RegCloseKey]
      [-]81ec????????535657b9????????33c08d7c2411c6442410008d542410f3ab66abaabf????????83c9ff33c0f2aef7d12bf98bc18bf78bfa8d542410c1e902f3a58bc833c083e103f3a4bf????????83c9fff2aef7d12bf98bf78bd98bfa83c9fff2ae8bcb4fc1e902f3a58bcb8d44240c83e10350f3a468????????8d4c24186a0051
         // 00402320: sub esp, 0x108
         // 00402326: push ebx
         // 00402327: push esi
         // 00402328: push edi
         // 00402329: mov ecx, 0x40
         // 0040232e: xor eax, eax
         // 00402330: lea edi, ss:[esp+0x11]
         // 00402334: mov b1 ss:[esp+0x10], b1 0x0
         // 00402339: lea edx, ss:[esp+0x10]
         // 0040233d: rep stosdd 
         // 0040233f: stosww 
         // 00402341: stosbb 
         // 00402342: mov edi, 0x404448
         // 00402347: or ecx, 0xffffffffffffffff
         // 0040234a: xor eax, eax
         // 0040234c: repne scasbb 
         // 0040234e: not ecx
         // 00402350: sub edi, ecx
         // 00402352: mov eax, ecx
         // 00402354: mov esi, edi
         // 00402356: mov edi, edx
         // 00402358: lea edx, ss:[esp+0x10]
         // 0040235c: shr ecx, b1 0x2
         // 0040235f: rep movsdd 
         // 00402361: mov ecx, eax
         // 00402363: xor eax, eax
         // 00402365: and ecx, 0x3
         // 00402368: rep movsbb 
         // 0040236a: mov edi, 0x404128
         // 0040236f: or ecx, 0xffffffffffffffff
         // 00402372: repne scasbb 
         // 00402374: not ecx
         // 00402376: sub edi, ecx
         // 00402378: mov esi, edi
         // 0040237a: mov ebx, ecx
         // 0040237c: mov edi, edx
         // 0040237e: or ecx, 0xffffffffffffffff
         // 00402381: repne scasbb 
         // 00402383: mov ecx, ebx
         // 00402385: dec edi
         // 00402386: shr ecx, b1 0x2
         // 00402389: rep movsdd 
         // 0040238b: mov ecx, ebx
         // 0040238d: lea eax, ss:[esp+0xc]
         // 00402391: and ecx, 0x3
         // 00402394: push eax
         // 00402395: rep movsbb 
         // 00402397: push 0xf003f
         // 0040239c: lea ecx, ss:[esp+0x18]
         // 004023a0: push 0x0
         // 004023a2: push ecx
         // 004023a3: push 0xffffffff80000002
         // 004023a8: call ds:[RegOpenKeyExA]
         // 004023ae: neg eax
         // 004023b0: sbb eax, eax
         // 004023b2: pop edi
         // 004023b3: pop esi
         // 004023b4: inc eax
         // 004023b5: pop ebx
         // 004023b6: add esp, 0x108
         // 004023bc: retn 

  }
  condition:
    all of them
}
