rule ramsay_10_4 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         558bec83ec188d45f850ff1530e040008b4dfc334df8894df4ff152ce040003345f48945f4ff1528e040003345f48945f4ff1524e040003345f48945f48d55e852ff1520e040008d45e88945f08b4df08b55f08b410433023345f48945f48b45f48be55dc3
         // 00401000: push ebp
         // 00401001: mov ebp, esp
         // 00401003: sub esp, 0x18
         // 00401006: lea eax, ss:[ebp+0xfffffffffffffff8]
         // 00401009: push eax
         // 0040100a: call ds:[GetSystemTimeAsFileTime]
         // 00401010: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 00401013: xor ecx, ss:[ebp+0xfffffffffffffff8]
         // 00401016: mov ss:[ebp+0xfffffffffffffff4], ecx
         // 00401019: call ds:[GetCurrentProcessId]
         // 0040101f: xor eax, ss:[ebp+0xfffffffffffffff4]
         // 00401022: mov ss:[ebp+0xfffffffffffffff4], eax
         // 00401025: call ds:[GetCurrentThreadId]
         // 0040102b: xor eax, ss:[ebp+0xfffffffffffffff4]
         // 0040102e: mov ss:[ebp+0xfffffffffffffff4], eax
         // 00401031: call ds:[GetTickCount]
         // 00401037: xor eax, ss:[ebp+0xfffffffffffffff4]
         // 0040103a: mov ss:[ebp+0xfffffffffffffff4], eax
         // 0040103d: lea edx, ss:[ebp+0xffffffffffffffe8]
         // 00401040: push edx
         // 00401041: call ds:[QueryPerformanceCounter]
         // 00401047: lea eax, ss:[ebp+0xffffffffffffffe8]
         // 0040104a: mov ss:[ebp+0xfffffffffffffff0], eax
         // 0040104d: mov ecx, ss:[ebp+0xfffffffffffffff0]
         // 00401050: mov edx, ss:[ebp+0xfffffffffffffff0]
         // 00401053: mov eax, ds:[ecx+0x4]
         // 00401056: xor eax, ds:[edx]
         // 00401058: xor eax, ss:[ebp+0xfffffffffffffff4]
         // 0040105b: mov ss:[ebp+0xfffffffffffffff4], eax
         // 0040105e: mov eax, ss:[ebp+0xfffffffffffffff4]
         // 00401061: mov esp, ebp
         // 00401063: pop ebp
         // 00401064: retn 
      [-]558bec83ec10c745f8????????33c0668945fc6a0468????????8b4d088d540902526a00ff1538e040008945f88b45088d4c0002516a008b55f852e86040000083c40cc745f0????????eb09
         // 00401070: push ebp
         // 00401071: mov ebp, esp
         // 00401073: sub esp, 0x10
         // 00401076: mov ss:[ebp+0xfffffffffffffff8], 0x0
         // 0040107d: xor eax, eax
         // 0040107f: mov b2 ss:[ebp+0xfffffffffffffffc], b2 ax
         // 00401083: push 0x4
         // 00401085: push 0x1000
         // 0040108a: mov ecx, ss:[ebp+0x8]
         // 0040108d: lea edx, ds:[ecx+ecx+0x2]
         // 00401091: push edx
         // 00401092: push 0x0
         // 00401094: call ds:[VirtualAlloc]
         // 0040109a: mov ss:[ebp+0xfffffffffffffff8], eax
         // 0040109d: mov eax, ss:[ebp+0x8]
         // 004010a0: lea ecx, ds:[eax+eax+0x2]
         // 004010a4: push ecx
         // 004010a5: push 0x0
         // 004010a7: mov edx, ss:[ebp+0xfffffffffffffff8]
         // 004010aa: push edx
         // 004010ab: call _memset
         // 004010b0: add esp, 0xc
         // 004010b3: mov ss:[ebp+0xfffffffffffffff0], 0x0
         // 004010ba: jmp 0x4010c5
      [-]8b4df03b4d087d34
         // 004010c5: mov ecx, ss:[ebp+0xfffffffffffffff0]
         // 004010c8: cmp ecx, ss:[ebp+0x8]
         // 004010cb: jge 0x401101
      [-]8b45f88be55dc3
         // 00401101: mov eax, ss:[ebp+0xfffffffffffffff8]
         // 00401104: mov esp, ebp
         // 00401106: pop ebp
         // 00401107: retn 
      [-]558bec6aff68????????64a1????????5083ec3ca1a020410033c58945dc508d45f464a3????????c745b8????????8b4d0ce8192f00008945f0c745e8????????c745bc????????c745e0????????8d4dc0e8091a0000c745fc????????
         // 00401110: push ebp
         // 00401111: mov ebp, esp
         // 00401113: push 0xffffffffffffffff
         // 00401115: push 0x40d101
         // 0040111a: mov eax, fs:[0x0]
         // 00401120: push eax
         // 00401121: sub esp, 0x3c
         // 00401124: mov eax, ds:[___security_cookie]
         // 00401129: xor eax, ebp
         // 0040112b: mov ss:[ebp+0xffffffffffffffdc], eax
         // 0040112e: push eax
         // 0040112f: lea eax, ss:[ebp+0xfffffffffffffff4]
         // 00401132: mov fs:[0x0], eax
         // 00401138: mov ss:[ebp+0xffffffffffffffb8], 0x0
         // 0040113f: mov ecx, ss:[ebp+0xc]
         // 00401142: call ?_GetToken@_CancellationTokenRegistration@details@Concurrency@@QBEPAV_CancellationTokenState@23@XZ
         // 00401147: mov ss:[ebp+0xfffffffffffffff0], eax
         // 0040114a: mov ss:[ebp+0xffffffffffffffe8], 0x0
         // 00401151: mov ss:[ebp+0xffffffffffffffbc], 0x0
         // 00401158: mov ss:[ebp+0xffffffffffffffe0], 0x0
         // 0040115f: lea ecx, ss:[ebp+0xffffffffffffffc0]
         // 00401162: call 0x402b70
         // 00401167: mov ss:[ebp+0xfffffffffffffffc], 0x1
      [-]8b45f08b4df083e901894df085c00f8419010000
         // 0040116e: mov eax, ss:[ebp+0xfffffffffffffff0]
         // 00401171: mov ecx, ss:[ebp+0xfffffffffffffff0]
         // 00401174: sub ecx, 0x1
         // 00401177: mov ss:[ebp+0xfffffffffffffff0], ecx
         // 0040117a: test eax, eax
         // 0040117c: jz 0x40129b
      [-]8b55e0528b4d0ce8821c00000fbe0083f83d0f8401010000
         // 00401182: mov edx, ss:[ebp+0xffffffffffffffe0]
         // 00401185: push edx
         // 00401186: mov ecx, ss:[ebp+0xc]
         // 00401189: call 0x402e10
         // 0040118e: movsx eax, b1 ds:[eax]
         // 00401191: cmp eax, 0x3d
         // 00401194: jz 0x40129b
      [-]8b4de0518b4d0ce86a1c00000fb61052e8d101000083c4040fb6c085c00f84de000000
         // 0040119a: mov ecx, ss:[ebp+0xffffffffffffffe0]
         // 0040119d: push ecx
         // 0040119e: mov ecx, ss:[ebp+0xc]
         // 004011a1: call 0x402e10
         // 004011a6: movzx edx, b1 ds:[eax]
         // 004011a9: push edx
         // 004011aa: call 0x401380
         // 004011af: add esp, 0x4
         // 004011b2: movzx eax, b1 al
         // 004011b5: test eax, eax
         // 004011b7: jz 0x40129b
      [-]8b4de0518b4d0ce8471c00008b55e88a00884415ec8b4de883c101894de88b55e083c2018955e0837de8040f85a8000000
         // 004011bd: mov ecx, ss:[ebp+0xffffffffffffffe0]
         // 004011c0: push ecx
         // 004011c1: mov ecx, ss:[ebp+0xc]
         // 004011c4: call 0x402e10
         // 004011c9: mov edx, ss:[ebp+0xffffffffffffffe8]
         // 004011cc: mov b1 al, b1 ds:[eax]
         // 004011ce: mov b1 ss:[ebp+edx+0xffffffffffffffec], b1 al
         // 004011d2: mov ecx, ss:[ebp+0xffffffffffffffe8]
         // 004011d5: add ecx, 0x1
         // 004011d8: mov ss:[ebp+0xffffffffffffffe8], ecx
         // 004011db: mov edx, ss:[ebp+0xffffffffffffffe0]
         // 004011de: add edx, 0x1
         // 004011e1: mov ss:[ebp+0xffffffffffffffe0], edx
         // 004011e4: cmp ss:[ebp+0xffffffffffffffe8], 0x4
         // 004011e8: jnz 0x401296
      [-]c745e8????????eb09
         // 004011ee: mov ss:[ebp+0xffffffffffffffe8], 0x0
         // 004011f5: jmp 0x401200
      [-]837de8047d1e
         // 00401200: cmp ss:[ebp+0xffffffffffffffe8], 0x4
         // 00401204: jge 0x401224
      [-]0fb655ec0fb645ed83e030c1f8048d0c90884de40fb655ed83e20fc1e2040fb645ee83e03cc1f80203d08855e50fb64dee83e103c1e1060fb655ef03ca884de6c745e8????????eb09
         // 00401224: movzx edx, b1 ss:[ebp+0xffffffffffffffec]
         // 00401228: movzx eax, b1 ss:[ebp+0xffffffffffffffed]
         // 0040122c: and eax, 0x30
         // 0040122f: sar eax, b1 0x4
         // 00401232: lea ecx, ds:[eax+edx*0x4]
         // 00401235: mov b1 ss:[ebp+0xffffffffffffffe4], b1 cl
         // 00401238: movzx edx, b1 ss:[ebp+0xffffffffffffffed]
         // 0040123c: and edx, 0xf
         // 0040123f: shl edx, b1 0x4
         // 00401242: movzx eax, b1 ss:[ebp+0xffffffffffffffee]
         // 00401246: and eax, 0x3c
         // 00401249: sar eax, b1 0x2
         // 0040124c: add edx, eax
         // 0040124e: mov b1 ss:[ebp+0xffffffffffffffe5], b1 dl
         // 00401251: movzx ecx, b1 ss:[ebp+0xffffffffffffffee]
         // 00401255: and ecx, 0x3
         // 00401258: shl ecx, b1 0x6
         // 0040125b: movzx edx, b1 ss:[ebp+0xffffffffffffffef]
         // 0040125f: add ecx, edx
         // 00401261: mov b1 ss:[ebp+0xffffffffffffffe6], b1 cl
         // 00401264: mov ss:[ebp+0xffffffffffffffe8], 0x0
         // 0040126b: jmp 0x401276
      [-]837de8037d13
         // 00401276: cmp ss:[ebp+0xffffffffffffffe8], 0x3
         // 0040127a: jge 0x40128f
      [-]c745e8????????
         // 0040128f: mov ss:[ebp+0xffffffffffffffe8], 0x0
      [-]e9d3feffff
         // 00401296: jmp 0x40116e
      [-]837de8000f8495000000
         // 0040129b: cmp ss:[ebp+0xffffffffffffffe8], 0x0
         // 0040129f: jz 0x40133a
      [-]c745bc????????eb09
         // 004012a5: mov ss:[ebp+0xffffffffffffffbc], 0x0
         // 004012ac: jmp 0x4012b7
      [-]8b4dbc3b4de87d1e
         // 004012b7: mov ecx, ss:[ebp+0xffffffffffffffbc]
         // 004012ba: cmp ecx, ss:[ebp+0xffffffffffffffe8]
         // 004012bd: jge 0x4012dd
      [-]0fb655ec0fb645ed83e030c1f8048d0c90884de40fb655ed83e20fc1e2040fb645ee83e03cc1f80203d08855e5c745bc????????eb09
         // 004012dd: movzx edx, b1 ss:[ebp+0xffffffffffffffec]
         // 004012e1: movzx eax, b1 ss:[ebp+0xffffffffffffffed]
         // 004012e5: and eax, 0x30
         // 004012e8: sar eax, b1 0x4
         // 004012eb: lea ecx, ds:[eax+edx*0x4]
         // 004012ee: mov b1 ss:[ebp+0xffffffffffffffe4], b1 cl
         // 004012f1: movzx edx, b1 ss:[ebp+0xffffffffffffffed]
         // 004012f5: and edx, 0xf
         // 004012f8: shl edx, b1 0x4
         // 004012fb: movzx eax, b1 ss:[ebp+0xffffffffffffffee]
         // 004012ff: and eax, 0x3c
         // 00401302: sar eax, b1 0x2
         // 00401305: add edx, eax
         // 00401307: mov b1 ss:[ebp+0xffffffffffffffe5], b1 dl
         // 0040130a: mov ss:[ebp+0xffffffffffffffbc], 0x0
         // 00401311: jmp 0x40131c
      [-]8b55e883ea013955bc7d13
         // 0040131c: mov edx, ss:[ebp+0xffffffffffffffe8]
         // 0040131f: sub edx, 0x1
         // 00401322: cmp ss:[ebp+0xffffffffffffffbc], edx
         // 00401325: jge 0x40133a
      [-]8d55c0528b4d08e81a1900008b45b883c8018945b8c645fc008d4dc0e8951900008b45088b4df464890d????????598b4ddc33cde8fb4100008be55dc3
         // 0040133a: lea edx, ss:[ebp+0xffffffffffffffc0]
         // 0040133d: push edx
         // 0040133e: mov ecx, ss:[ebp+0x8]
         // 00401341: call 0x402c60
         // 00401346: mov eax, ss:[ebp+0xffffffffffffffb8]
         // 00401349: or eax, 0x1
         // 0040134c: mov ss:[ebp+0xffffffffffffffb8], eax
         // 0040134f: mov b1 ss:[ebp+0xfffffffffffffffc], b1 0x0
         // 00401353: lea ecx, ss:[ebp+0xffffffffffffffc0]
         // 00401356: call 0x402cf0
         // 0040135b: mov eax, ss:[ebp+0x8]
         // 0040135e: mov ecx, ss:[ebp+0xfffffffffffffff4]
         // 00401361: mov fs:[0x0], ecx
         // 00401368: pop ecx
         // 00401369: mov ecx, ss:[ebp+0xffffffffffffffdc]
         // 0040136c: xor ecx, ebp
         // 0040136e: call @__security_check_cookie@4
         // 00401373: mov esp, ebp
         // 00401375: pop ebp
         // 00401376: retn 
      [-]558bec510fb6450850e8cc42000083c40485c0751b
         // 00401380: push ebp
         // 00401381: mov ebp, esp
         // 00401383: push ecx
         // 00401384: movzx eax, b1 ss:[ebp+0x8]
         // 00401388: push eax
         // 00401389: call _isalnum
         // 0040138e: add esp, 0x4
         // 00401391: test eax, eax
         // 00401393: jnz 0x4013b0
      [-]0fb64d0883f92b7412
         // 00401395: movzx ecx, b1 ss:[ebp+0x8]
         // 00401399: cmp ecx, 0x2b
         // 0040139c: jz 0x4013b0
      [-]0fb6550883fa2f7409
         // 0040139e: movzx edx, b1 ss:[ebp+0x8]
         // 004013a2: cmp edx, 0x2f
         // 004013a5: jz 0x4013b0
      [-]c745fc????????eb07
         // 004013a7: mov ss:[ebp+0xfffffffffffffffc], 0x0
         // 004013ae: jmp 0x4013b7
      [-]c745fc????????
         // 004013b0: mov ss:[ebp+0xfffffffffffffffc], 0x1
      [-]8a45fc8be55dc3
         // 004013b7: mov b1 al, b1 ss:[ebp+0xfffffffffffffffc]
         // 004013ba: mov esp, ebp
         // 004013bc: pop ebp
         // 004013bd: retn 
      [-]558bec6aff68????????64a1????????5083ec50a1a020410033c58945f0508d45f464a3????????c745fc????????68????????8d4dc8e8e4170000c645fc018d4508508d4da851e803fdffff83c408c645fc026a008d4da8e8c21900000fbe108955e48d4da8e8342c000083e801508d4da8e8a81900000fbe008945ec8d4da8e81a2c000083e8028b4d2489016a0468????????8d4da8e8032c000083e802506a00ff1538e040008945c4c745e8????????c745e8????????eb09
         // 004013c0: push ebp
         // 004013c1: mov ebp, esp
         // 004013c3: push 0xffffffffffffffff
         // 004013c5: push 0x40d13e
         // 004013ca: mov eax, fs:[0x0]
         // 004013d0: push eax
         // 004013d1: sub esp, 0x50
         // 004013d4: mov eax, ds:[___security_cookie]
         // 004013d9: xor eax, ebp
         // 004013db: mov ss:[ebp+0xfffffffffffffff0], eax
         // 004013de: push eax
         // 004013df: lea eax, ss:[ebp+0xfffffffffffffff4]
         // 004013e2: mov fs:[0x0], eax
         // 004013e8: mov ss:[ebp+0xfffffffffffffffc], 0x0
         // 004013ef: push 0x40e1e1
         // 004013f4: lea ecx, ss:[ebp+0xffffffffffffffc8]
         // 004013f7: call 0x402be0
         // 004013fc: mov b1 ss:[ebp+0xfffffffffffffffc], b1 0x1
         // 00401400: lea eax, ss:[ebp+0x8]
         // 00401403: push eax
         // 00401404: lea ecx, ss:[ebp+0xffffffffffffffa8]
         // 00401407: push ecx
         // 00401408: call 0x401110
         // 0040140d: add esp, 0x8
         // 00401410: mov b1 ss:[ebp+0xfffffffffffffffc], b1 0x2
         // 00401414: push 0x0
         // 00401416: lea ecx, ss:[ebp+0xffffffffffffffa8]
         // 00401419: call 0x402de0
         // 0040141e: movsx edx, b1 ds:[eax]
         // 00401421: mov ss:[ebp+0xffffffffffffffe4], edx
         // 00401424: lea ecx, ss:[ebp+0xffffffffffffffa8]
         // 00401427: call ?_GetToken@_CancellationTokenRegistration@details@Concurrency@@QBEPAV_CancellationTokenState@23@XZ
         // 0040142c: sub eax, 0x1
         // 0040142f: push eax
         // 00401430: lea ecx, ss:[ebp+0xffffffffffffffa8]
         // 00401433: call 0x402de0
         // 00401438: movsx eax, b1 ds:[eax]
         // 0040143b: mov ss:[ebp+0xffffffffffffffec], eax
         // 0040143e: lea ecx, ss:[ebp+0xffffffffffffffa8]
         // 00401441: call ?_GetToken@_CancellationTokenRegistration@details@Concurrency@@QBEPAV_CancellationTokenState@23@XZ
         // 00401446: sub eax, 0x2
         // 00401449: mov ecx, ss:[ebp+0x24]
         // 0040144c: mov ds:[ecx], eax
         // 0040144e: push 0x4
         // 00401450: push 0x1000
         // 00401455: lea ecx, ss:[ebp+0xffffffffffffffa8]
         // 00401458: call ?_GetToken@_CancellationTokenRegistration@details@Concurrency@@QBEPAV_CancellationTokenState@23@XZ
         // 0040145d: sub eax, 0x2
         // 00401460: push eax
         // 00401461: push 0x0
         // 00401463: call ds:[VirtualAlloc]
         // 00401469: mov ss:[ebp+0xffffffffffffffc4], eax
         // 0040146c: mov ss:[ebp+0xffffffffffffffe8], 0x0
         // 00401473: mov ss:[ebp+0xffffffffffffffe8], 0x0
         // 0040147a: jmp 0x401485
      [-]8d4da8e8d32b000083e8023945e87322
         // 00401485: lea ecx, ss:[ebp+0xffffffffffffffa8]
         // 00401488: call ?_GetToken@_CancellationTokenRegistration@details@Concurrency@@QBEPAV_CancellationTokenState@23@XZ
         // 0040148d: sub eax, 0x2
         // 00401490: cmp ss:[ebp+0xffffffffffffffe8], eax
         // 00401493: jnb 0x4014b7
      [-]8b45c48945a4c645fc018d4da8e827180000c645fc008d4dc8e81b180000c745????????ff8d4d08e80c1800008b45a48b4df464890d????????598b4df033cde8724000008be55dc3
         // 004014b7: mov eax, ss:[ebp+0xffffffffffffffc4]
         // 004014ba: mov ss:[ebp+0xffffffffffffffa4], eax
         // 004014bd: mov b1 ss:[ebp+0xfffffffffffffffc], b1 0x1
         // 004014c1: lea ecx, ss:[ebp+0xffffffffffffffa8]
         // 004014c4: call 0x402cf0
         // 004014c9: mov b1 ss:[ebp+0xfffffffffffffffc], b1 0x0
         // 004014cd: lea ecx, ss:[ebp+0xffffffffffffffc8]
         // 004014d0: call 0x402cf0
         // 004014d5: mov ss:[ebp+0xfffffffffffffffc], 0xffffffffffffffff
         // 004014dc: lea ecx, ss:[ebp+0x8]
         // 004014df: call 0x402cf0
         // 004014e4: mov eax, ss:[ebp+0xffffffffffffffa4]
         // 004014e7: mov ecx, ss:[ebp+0xfffffffffffffff4]
         // 004014ea: mov fs:[0x0], ecx
         // 004014f1: pop ecx
         // 004014f2: mov ecx, ss:[ebp+0xfffffffffffffff0]
         // 004014f5: xor ecx, ebp
         // 004014f7: call @__security_check_cookie@4
         // 004014fc: mov esp, ebp
         // 004014fe: pop ebp
         // 004014ff: retn 
      [-]558bec83ec18568b45088945fcc745f8????????eb09
         // 00401500: push ebp
         // 00401501: mov ebp, esp
         // 00401503: sub esp, 0x18
         // 00401506: push esi
         // 00401507: mov eax, ss:[ebp+0x8]
         // 0040150a: mov ss:[ebp+0xfffffffffffffffc], eax
         // 0040150d: mov ss:[ebp+0xfffffffffffffff8], 0x0
         // 00401514: jmp 0x40151f
      [-]8b45f8998b4d0c2b4d188b75101b751c8945f08955f4894de88975ec8b55f43b55ec7732
         // 0040151f: mov eax, ss:[ebp+0xfffffffffffffff8]
         // 00401522: cdq 
         // 00401523: mov ecx, ss:[ebp+0xc]
         // 00401526: sub ecx, ss:[ebp+0x18]
         // 00401529: mov esi, ss:[ebp+0x10]
         // 0040152c: sbb esi, ss:[ebp+0x1c]
         // 0040152f: mov ss:[ebp+0xfffffffffffffff0], eax
         // 00401532: mov ss:[ebp+0xfffffffffffffff4], edx
         // 00401535: mov ss:[ebp+0xffffffffffffffe8], ecx
         // 00401538: mov ss:[ebp+0xffffffffffffffec], esi
         // 0040153b: mov edx, ss:[ebp+0xfffffffffffffff4]
         // 0040153e: cmp edx, ss:[ebp+0xffffffffffffffec]
         // 00401541: ja 0x401575
      [-]8b45f03b45e87328
         // 00401545: mov eax, ss:[ebp+0xfffffffffffffff0]
         // 00401548: cmp eax, ss:[ebp+0xffffffffffffffe8]
         // 0040154b: jnb 0x401575
      [-]8b4d18518b5514528b45fc50e82c41000083c40c85c07505
         // 0040154d: mov ecx, ss:[ebp+0x18]
         // 00401550: push ecx
         // 00401551: mov edx, ss:[ebp+0x14]
         // 00401554: push edx
         // 00401555: mov eax, ss:[ebp+0xfffffffffffffffc]
         // 00401558: push eax
         // 00401559: call _memcmp
         // 0040155e: add esp, 0xc
         // 00401561: test eax, eax
         // 00401563: jnz 0x40156a
      [-]8b45fceb0d
         // 00401565: mov eax, ss:[ebp+0xfffffffffffffffc]
         // 00401568: jmp 0x401577
      [-]5e8be55dc3
         // 00401577: pop esi
         // 00401578: mov esp, ebp
         // 0040157a: pop ebp
         // 0040157b: retn 
      [-]558bec6aff68????????64a1????????5081ec????????a1a020410033c58945f0508d45f464a3????????c785????????????????c745fc????????8d8d????????e839190000c645fc0233c066898524f0ffff68????????6a008d8d????????51e8293b000083c40cc745ec????????8d55ec5283ec1c8bcc89a5????????8d450c50e8d71400008985????????e8acfdffff83c4208985????????8b8d????????894dc88b55c8528d4dd0e8ae150000c645fc0368????????6a008b45c850ff1540e040006a006a008d4dd0e80d2a0000508d4dd0e8d4170000506a006a00ff153ce040008945cc8b4dcc518d95????????528d4dd0e8e3290000508d4dd0e8aa170000506a006a00ff153ce040008d85????????508d8d????????e83d1a00008d8d????????518b4d08e83e1900008b95????????83ca018995????????c645fc028d4dd0e823160000c645fc018d8d????????e8a4190000c645fc008d4d0ce8081600008b45088b4df464890d????????598b4df033cde86e3e00008be55dc3
         // 00401580: push ebp
         // 00401581: mov ebp, esp
         // 00401583: push 0xffffffffffffffff
         // 00401585: push 0x40d19d
         // 0040158a: mov eax, fs:[0x0]
         // 00401590: push eax
         // 00401591: sub esp, 0xffc
         // 00401597: mov eax, ds:[___security_cookie]
         // 0040159c: xor eax, ebp
         // 0040159e: mov ss:[ebp+0xfffffffffffffff0], eax
         // 004015a1: push eax
         // 004015a2: lea eax, ss:[ebp+0xfffffffffffffff4]
         // 004015a5: mov fs:[0x0], eax
         // 004015ab: mov ss:[ebp+0xfffffffffffff000], 0x0
         // 004015b5: mov ss:[ebp+0xfffffffffffffffc], 0x1
         // 004015bc: lea ecx, ss:[ebp+0xfffffffffffff008]
         // 004015c2: call 0x402f00
         // 004015c7: mov b1 ss:[ebp+0xfffffffffffffffc], b1 0x2
         // 004015cb: xor eax, eax
         // 004015cd: mov b2 ss:[ebp+0xfffffffffffff024], b2 ax
         // 004015d4: push 0xf9e
         // 004015d9: push 0x0
         // 004015db: lea ecx, ss:[ebp+0xfffffffffffff026]
         // 004015e1: push ecx
         // 004015e2: call _memset
         // 004015e7: add esp, 0xc
         // 004015ea: mov ss:[ebp+0xffffffffffffffec], 0x0
         // 004015f1: lea edx, ss:[ebp+0xffffffffffffffec]
         // 004015f4: push edx
         // 004015f5: sub esp, 0x1c
         // 004015f8: mov ecx, esp
         // 004015fa: mov ss:[ebp+0xfffffffffffff004], esp
         // 00401600: lea eax, ss:[ebp+0xc]
         // 00401603: push eax
         // 00401604: call 0x402ae0
         // 00401609: mov ss:[ebp+0xffffffffffffeffc], eax
         // 0040160f: call 0x4013c0
         // 00401614: add esp, 0x20
         // 00401617: mov ss:[ebp+0xffffffffffffeff8], eax
         // 0040161d: mov ecx, ss:[ebp+0xffffffffffffeff8]
         // 00401623: mov ss:[ebp+0xffffffffffffffc8], ecx
         // 00401626: mov edx, ss:[ebp+0xffffffffffffffc8]
         // 00401629: push edx
         // 0040162a: lea ecx, ss:[ebp+0xffffffffffffffd0]
         // 0040162d: call 0x402be0
         // 00401632: mov b1 ss:[ebp+0xfffffffffffffffc], b1 0x3
         // 00401636: push 0x8000
         // 0040163b: push 0x0
         // 0040163d: mov eax, ss:[ebp+0xffffffffffffffc8]
         // 00401640: push eax
         // 00401641: call ds:[VirtualFree]
         // 00401647: push 0x0
         // 00401649: push 0x0
         // 0040164b: lea ecx, ss:[ebp+0xffffffffffffffd0]
         // 0040164e: call ?_GetToken@_CancellationTokenRegistration@details@Concurrency@@QBEPAV_CancellationTokenState@23@XZ
         // 00401653: push eax
         // 00401654: lea ecx, ss:[ebp+0xffffffffffffffd0]
         // 00401657: call 0x402e30
         // 0040165c: push eax
         // 0040165d: push 0x0
         // 0040165f: push 0x0
         // 00401661: call ds:[MultiByteToWideChar]
         // 00401667: mov ss:[ebp+0xffffffffffffffcc], eax
         // 0040166a: mov ecx, ss:[ebp+0xffffffffffffffcc]
         // 0040166d: push ecx
         // 0040166e: lea edx, ss:[ebp+0xfffffffffffff024]
         // 00401674: push edx
         // 00401675: lea ecx, ss:[ebp+0xffffffffffffffd0]
         // 00401678: call ?_GetToken@_CancellationTokenRegistration@details@Concurrency@@QBEPAV_CancellationTokenState@23@XZ
         // 0040167d: push eax
         // 0040167e: lea ecx, ss:[ebp+0xffffffffffffffd0]
         // 00401681: call 0x402e30
         // 00401686: push eax
         // 00401687: push 0x0
         // 00401689: push 0x0
         // 0040168b: call ds:[MultiByteToWideChar]
         // 00401691: lea eax, ss:[ebp+0xfffffffffffff024]
         // 00401697: push eax
         // 00401698: lea ecx, ss:[ebp+0xfffffffffffff008]
         // 0040169e: call 0x4030e0
         // 004016a3: lea ecx, ss:[ebp+0xfffffffffffff008]
         // 004016a9: push ecx
         // 004016aa: mov ecx, ss:[ebp+0x8]
         // 004016ad: call 0x402ff0
         // 004016b2: mov edx, ss:[ebp+0xfffffffffffff000]
         // 004016b8: or edx, 0x1
         // 004016bb: mov ss:[ebp+0xfffffffffffff000], edx
         // 004016c1: mov b1 ss:[ebp+0xfffffffffffffffc], b1 0x2
         // 004016c5: lea ecx, ss:[ebp+0xffffffffffffffd0]
         // 004016c8: call 0x402cf0
         // 004016cd: mov b1 ss:[ebp+0xfffffffffffffffc], b1 0x1
         // 004016d1: lea ecx, ss:[ebp+0xfffffffffffff008]
         // 004016d7: call 0x403080
         // 004016dc: mov b1 ss:[ebp+0xfffffffffffffffc], b1 0x0
         // 004016e0: lea ecx, ss:[ebp+0xc]
         // 004016e3: call 0x402cf0
         // 004016e8: mov eax, ss:[ebp+0x8]
         // 004016eb: mov ecx, ss:[ebp+0xfffffffffffffff4]
         // 004016ee: mov fs:[0x0], ecx
         // 004016f5: pop ecx
         // 004016f6: mov ecx, ss:[ebp+0xfffffffffffffff0]
         // 004016f9: xor ecx, ebp
         // 004016fb: call @__security_check_cookie@4
         // 00401700: mov esp, ebp
         // 00401702: pop ebp
         // 00401703: retn 
      [-]558bec83ec14c745fc????????c745ec????????c745f8????????c745f0????????c745f4????????8d45f8506a08ff154ce0400050ff1504e0400085c07509
         // 00401710: push ebp
         // 00401711: mov ebp, esp
         // 00401713: sub esp, 0x14
         // 00401716: mov ss:[ebp+0xfffffffffffffffc], 0x0
         // 0040171d: mov ss:[ebp+0xffffffffffffffec], 0x0
         // 00401724: mov ss:[ebp+0xfffffffffffffff8], 0x0
         // 0040172b: mov ss:[ebp+0xfffffffffffffff0], 0x0
         // 00401732: mov ss:[ebp+0xfffffffffffffff4], 0x0
         // 00401739: lea eax, ss:[ebp+0xfffffffffffffff8]
         // 0040173c: push eax
         // 0040173d: push 0x8
         // 0040173f: call ds:[GetCurrentProcess]
         // 00401745: push eax
         // 00401746: call ds:[OpenProcessToken]
         // 0040174c: test eax, eax
         // 0040174e: jnz 0x401759
      [-]ff1548e040008945ec
         // 00401750: call ds:[GetLastError]
         // 00401756: mov ss:[ebp+0xffffffffffffffec], eax
      [-]8d4df0516a006a006a198b55f852ff1500e0400085c07514
         // 00401759: lea ecx, ss:[ebp+0xfffffffffffffff0]
         // 0040175c: push ecx
         // 0040175d: push 0x0
         // 0040175f: push 0x0
         // 00401761: push 0x19
         // 00401763: mov edx, ss:[ebp+0xfffffffffffffff8]
         // 00401766: push edx
         // 00401767: call ds:[GetTokenInformation]
         // 0040176d: test eax, eax
         // 0040176f: jnz 0x401785
      [-]ff1548e0400083f87a7409
         // 00401771: call ds:[GetLastError]
         // 00401777: cmp eax, 0x7a
         // 0040177a: jz 0x401785
      [-]ff1548e040008945ec
         // 0040177c: call ds:[GetLastError]
         // 00401782: mov ss:[ebp+0xffffffffffffffec], eax
      [-]8b45f0506a40ff1544e040008945f4837df4007509
         // 00401785: mov eax, ss:[ebp+0xfffffffffffffff0]
         // 00401788: push eax
         // 00401789: push 0x40
         // 0040178b: call ds:[LocalAlloc]
         // 00401791: mov ss:[ebp+0xfffffffffffffff4], eax
         // 00401794: cmp ss:[ebp+0xfffffffffffffff4], 0x0
         // 00401798: jnz 0x4017a3
      [-]ff1548e040008945ec
         // 0040179a: call ds:[GetLastError]
         // 004017a0: mov ss:[ebp+0xffffffffffffffec], eax
      [-]8d4df0518b55f0528b45f4506a198b4df851ff1500e0400085c07509
         // 004017a3: lea ecx, ss:[ebp+0xfffffffffffffff0]
         // 004017a6: push ecx
         // 004017a7: mov edx, ss:[ebp+0xfffffffffffffff0]
         // 004017aa: push edx
         // 004017ab: mov eax, ss:[ebp+0xfffffffffffffff4]
         // 004017ae: push eax
         // 004017af: push 0x19
         // 004017b1: mov ecx, ss:[ebp+0xfffffffffffffff8]
         // 004017b4: push ecx
         // 004017b5: call ds:[GetTokenInformation]
         // 004017bb: test eax, eax
         // 004017bd: jnz 0x4017c8
      [-]ff1548e040008945ec
         // 004017bf: call ds:[GetLastError]
         // 004017c5: mov ss:[ebp+0xffffffffffffffec], eax
      [-]6a008b55f48b0250ff1508e040008b08894dfc8b45fc8be55dc3
         // 004017c8: push 0x0
         // 004017ca: mov edx, ss:[ebp+0xfffffffffffffff4]
         // 004017cd: mov eax, ds:[edx]
         // 004017cf: push eax
         // 004017d0: call ds:[GetSidSubAuthority]
         // 004017d6: mov ecx, ds:[eax]
         // 004017d8: mov ss:[ebp+0xfffffffffffffffc], ecx
         // 004017db: mov eax, ss:[ebp+0xfffffffffffffffc]
         // 004017de: mov esp, ebp
         // 004017e0: pop ebp
         // 004017e1: retn 
      [-]558bec6aff68????????64a1????????5083ec34a1a020410033c5508d45f464a3????????c745fc????????c745d0????????6a0068????????6a036a006a0168????????8d4d08e8a319000050ff155ce040008945e0837de0ff751d
         // 004017f0: push ebp
         // 004017f1: mov ebp, esp
         // 004017f3: push 0xffffffffffffffff
         // 004017f5: push 0x40d1cd
         // 004017fa: mov eax, fs:[0x0]
         // 00401800: push eax
         // 00401801: sub esp, 0x34
         // 00401804: mov eax, ds:[___security_cookie]
         // 00401809: xor eax, ebp
         // 0040180b: push eax
         // 0040180c: lea eax, ss:[ebp+0xfffffffffffffff4]
         // 0040180f: mov fs:[0x0], eax
         // 00401815: mov ss:[ebp+0xfffffffffffffffc], 0x0
         // 0040181c: mov ss:[ebp+0xffffffffffffffd0], 0x0
         // 00401823: push 0x0
         // 00401825: push 0x80
         // 0040182a: push 0x3
         // 0040182c: push 0x0
         // 0040182e: push 0x1
         // 00401830: push 0xffffffff80000000
         // 00401835: lea ecx, ss:[ebp+0x8]
         // 00401838: call 0x4031e0
         // 0040183d: push eax
         // 0040183e: call ds:[CreateFileW]
         // 00401844: mov ss:[ebp+0xffffffffffffffe0], eax
         // 00401847: cmp ss:[ebp+0xffffffffffffffe0], 0xffffffffffffffff
         // 0040184b: jnz 0x40186a
      [-]8b45d08945ccc745????????ff8d4d08e81e1800008b45cce9de000000
         // 0040184d: mov eax, ss:[ebp+0xffffffffffffffd0]
         // 00401850: mov ss:[ebp+0xffffffffffffffcc], eax
         // 00401853: mov ss:[ebp+0xfffffffffffffffc], 0xffffffffffffffff
         // 0040185a: lea ecx, ss:[ebp+0x8]
         // 0040185d: call 0x403080
         // 00401862: mov eax, ss:[ebp+0xffffffffffffffcc]
         // 00401865: jmp 0x401948
      [-]8d4dd4518b55e052ff1558e0400085c07527
         // 0040186a: lea ecx, ss:[ebp+0xffffffffffffffd4]
         // 0040186d: push ecx
         // 0040186e: mov edx, ss:[ebp+0xffffffffffffffe0]
         // 00401871: push edx
         // 00401872: call ds:[GetFileSizeEx]
         // 00401878: test eax, eax
         // 0040187a: jnz 0x4018a3
      [-]8b45e050ff1554e040008b4dd0894dc8c745????????ff8d4d08e8e51700008b45c8e9a5000000
         // 0040187c: mov eax, ss:[ebp+0xffffffffffffffe0]
         // 0040187f: push eax
         // 00401880: call ds:[CloseHandle]
         // 00401886: mov ecx, ss:[ebp+0xffffffffffffffd0]
         // 00401889: mov ss:[ebp+0xffffffffffffffc8], ecx
         // 0040188c: mov ss:[ebp+0xfffffffffffffffc], 0xffffffffffffffff
         // 00401893: lea ecx, ss:[ebp+0x8]
         // 00401896: call 0x403080
         // 0040189b: mov eax, ss:[ebp+0xffffffffffffffc8]
         // 0040189e: jmp 0x401948
      [-]8b55d48955e48b45d88945e88b4d288b55e489118b45e88941046a0468????????8b4d288b11526a00ff1538e040008b4d2489016a008b552c528b45288b08518b55248b02508b4de051ff1550e040008b5524833a007524
         // 004018a3: mov edx, ss:[ebp+0xffffffffffffffd4]
         // 004018a6: mov ss:[ebp+0xffffffffffffffe4], edx
         // 004018a9: mov eax, ss:[ebp+0xffffffffffffffd8]
         // 004018ac: mov ss:[ebp+0xffffffffffffffe8], eax
         // 004018af: mov ecx, ss:[ebp+0x28]
         // 004018b2: mov edx, ss:[ebp+0xffffffffffffffe4]
         // 004018b5: mov ds:[ecx], edx
         // 004018b7: mov eax, ss:[ebp+0xffffffffffffffe8]
         // 004018ba: mov ds:[ecx+0x4], eax
         // 004018bd: push 0x4
         // 004018bf: push 0x1000
         // 004018c4: mov ecx, ss:[ebp+0x28]
         // 004018c7: mov edx, ds:[ecx]
         // 004018c9: push edx
         // 004018ca: push 0x0
         // 004018cc: call ds:[VirtualAlloc]
         // 004018d2: mov ecx, ss:[ebp+0x24]
         // 004018d5: mov ds:[ecx], eax
         // 004018d7: push 0x0
         // 004018d9: mov edx, ss:[ebp+0x2c]
         // 004018dc: push edx
         // 004018dd: mov eax, ss:[ebp+0x28]
         // 004018e0: mov ecx, ds:[eax]
         // 004018e2: push ecx
         // 004018e3: mov edx, ss:[ebp+0x24]
         // 004018e6: mov eax, ds:[edx]
         // 004018e8: push eax
         // 004018e9: mov ecx, ss:[ebp+0xffffffffffffffe0]
         // 004018ec: push ecx
         // 004018ed: call ds:[ReadFile]
         // 004018f3: mov edx, ss:[ebp+0x24]
         // 004018f6: cmp ds:[edx], 0x0
         // 004018f9: jnz 0x40191f
      [-]8b45e050ff1554e040008b4dd0894dc4c745????????ff8d4d08e8661700008b45c4eb29
         // 004018fb: mov eax, ss:[ebp+0xffffffffffffffe0]
         // 004018fe: push eax
         // 004018ff: call ds:[CloseHandle]
         // 00401905: mov ecx, ss:[ebp+0xffffffffffffffd0]
         // 00401908: mov ss:[ebp+0xffffffffffffffc4], ecx
         // 0040190b: mov ss:[ebp+0xfffffffffffffffc], 0xffffffffffffffff
         // 00401912: lea ecx, ss:[ebp+0x8]
         // 00401915: call 0x403080
         // 0040191a: mov eax, ss:[ebp+0xffffffffffffffc4]
         // 0040191d: jmp 0x401948
      [-]8b55e052ff1554e04000c745d0????????8b45d08945c0c745????????ff8d4d08e83b1700008b45c0
         // 0040191f: mov edx, ss:[ebp+0xffffffffffffffe0]
         // 00401922: push edx
         // 00401923: call ds:[CloseHandle]
         // 00401929: mov ss:[ebp+0xffffffffffffffd0], 0x1
         // 00401930: mov eax, ss:[ebp+0xffffffffffffffd0]
         // 00401933: mov ss:[ebp+0xffffffffffffffc0], eax
         // 00401936: mov ss:[ebp+0xfffffffffffffffc], 0xffffffffffffffff
         // 0040193d: lea ecx, ss:[ebp+0x8]
         // 00401940: call 0x403080
         // 00401945: mov eax, ss:[ebp+0xffffffffffffffc0]
      [-]8b4df464890d????????598be55dc3
         // 00401948: mov ecx, ss:[ebp+0xfffffffffffffff4]
         // 0040194b: mov fs:[0x0], ecx
         // 00401952: pop ecx
         // 00401953: mov esp, ebp
         // 00401955: pop ebp
         // 00401956: retn 
      [-]558bec6aff68????????64a1????????5083ec54a1a020410033c58945ec56508d45f464a3????????68????????8d4db4e84a120000c745fc????????68????????8d4db4e8e61300008d4db4e8ae26000033c951508d4db4e872140000508b5510528b450c508b4d0851e830fbffff83c4188945b0837db000752e
         // 00401960: push ebp
         // 00401961: mov ebp, esp
         // 00401963: push 0xffffffffffffffff
         // 00401965: push 0x40d1f8
         // 0040196a: mov eax, fs:[0x0]
         // 00401970: push eax
         // 00401971: sub esp, 0x54
         // 00401974: mov eax, ds:[___security_cookie]
         // 00401979: xor eax, ebp
         // 0040197b: mov ss:[ebp+0xffffffffffffffec], eax
         // 0040197e: push esi
         // 0040197f: push eax
         // 00401980: lea eax, ss:[ebp+0xfffffffffffffff4]
         // 00401983: mov fs:[0x0], eax
         // 00401989: push 0x40e1e4
         // 0040198e: lea ecx, ss:[ebp+0xffffffffffffffb4]
         // 00401991: call 0x402be0
         // 00401996: mov ss:[ebp+0xfffffffffffffffc], 0x0
         // 0040199d: push 0x40e1f4
         // 004019a2: lea ecx, ss:[ebp+0xffffffffffffffb4]
         // 004019a5: call ?append@?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QAEAAV12@PBD@Z
         // 004019aa: lea ecx, ss:[ebp+0xffffffffffffffb4]
         // 004019ad: call ?_GetToken@_CancellationTokenRegistration@details@Concurrency@@QBEPAV_CancellationTokenState@23@XZ
         // 004019b2: xor ecx, ecx
         // 004019b4: push ecx
         // 004019b5: push eax
         // 004019b6: lea ecx, ss:[ebp+0xffffffffffffffb4]
         // 004019b9: call 0x402e30
         // 004019be: push eax
         // 004019bf: mov edx, ss:[ebp+0x10]
         // 004019c2: push edx
         // 004019c3: mov eax, ss:[ebp+0xc]
         // 004019c6: push eax
         // 004019c7: mov ecx, ss:[ebp+0x8]
         // 004019ca: push ecx
         // 004019cb: call 0x401500
         // 004019d0: add esp, 0x18
         // 004019d3: mov ss:[ebp+0xffffffffffffffb0], eax
         // 004019d6: cmp ss:[ebp+0xffffffffffffffb0], 0x0
         // 004019da: jnz 0x401a0a
      [-]8b5514c702????????c742????????00c745a8????????c745????????ff8d4db4e8ee1200008b45a8e920010000
         // 004019dc: mov edx, ss:[ebp+0x14]
         // 004019df: mov ds:[edx], 0x0
         // 004019e5: mov ds:[edx+0x4], 0x0
         // 004019ec: mov ss:[ebp+0xffffffffffffffa8], 0x0
         // 004019f3: mov ss:[ebp+0xfffffffffffffffc], 0xffffffffffffffff
         // 004019fa: lea ecx, ss:[ebp+0xffffffffffffffb4]
         // 004019fd: call 0x402cf0
         // 00401a02: mov eax, ss:[ebp+0xffffffffffffffa8]
         // 00401a05: jmp 0x401b2a
      [-]8d4db4e84e2600000345b08945b068????????8d4dd0e8bb110000c645fc0168????????8d4dd0e85a13000068????????8d4dd0e84d1300008d4dd0e81526000033c951508d4dd0e8d9130000508b5510528b450c508b4d0851e897faffff83c4188945ac837dac007537
         // 00401a0a: lea ecx, ss:[ebp+0xffffffffffffffb4]
         // 00401a0d: call ?_GetToken@_CancellationTokenRegistration@details@Concurrency@@QBEPAV_CancellationTokenState@23@XZ
         // 00401a12: add eax, ss:[ebp+0xffffffffffffffb0]
         // 00401a15: mov ss:[ebp+0xffffffffffffffb0], eax
         // 00401a18: push 0x40e204
         // 00401a1d: lea ecx, ss:[ebp+0xffffffffffffffd0]
         // 00401a20: call 0x402be0
         // 00401a25: mov b1 ss:[ebp+0xfffffffffffffffc], b1 0x1
         // 00401a29: push 0x40e214
         // 00401a2e: lea ecx, ss:[ebp+0xffffffffffffffd0]
         // 00401a31: call ?append@?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QAEAAV12@PBD@Z
         // 00401a36: push 0x40e224
         // 00401a3b: lea ecx, ss:[ebp+0xffffffffffffffd0]
         // 00401a3e: call ?append@?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QAEAAV12@PBD@Z
         // 00401a43: lea ecx, ss:[ebp+0xffffffffffffffd0]
         // 00401a46: call ?_GetToken@_CancellationTokenRegistration@details@Concurrency@@QBEPAV_CancellationTokenState@23@XZ
         // 00401a4b: xor ecx, ecx
         // 00401a4d: push ecx
         // 00401a4e: push eax
         // 00401a4f: lea ecx, ss:[ebp+0xffffffffffffffd0]
         // 00401a52: call 0x402e30
         // 00401a57: push eax
         // 00401a58: mov edx, ss:[ebp+0x10]
         // 00401a5b: push edx
         // 00401a5c: mov eax, ss:[ebp+0xc]
         // 00401a5f: push eax
         // 00401a60: mov ecx, ss:[ebp+0x8]
         // 00401a63: push ecx
         // 00401a64: call 0x401500
         // 00401a69: add esp, 0x18
         // 00401a6c: mov ss:[ebp+0xffffffffffffffac], eax
         // 00401a6f: cmp ss:[ebp+0xffffffffffffffac], 0x0
         // 00401a73: jnz 0x401aac
      [-]8b5514c702????????c742????????00c745a4????????c645fc008d4dd0e858120000c745????????ff8d4db4e8491200008b45a4eb7e
         // 00401a75: mov edx, ss:[ebp+0x14]
         // 00401a78: mov ds:[edx], 0x0
         // 00401a7e: mov ds:[edx+0x4], 0x0
         // 00401a85: mov ss:[ebp+0xffffffffffffffa4], 0x0
         // 00401a8c: mov b1 ss:[ebp+0xfffffffffffffffc], b1 0x0
         // 00401a90: lea ecx, ss:[ebp+0xffffffffffffffd0]
         // 00401a93: call 0x402cf0
         // 00401a98: mov ss:[ebp+0xfffffffffffffffc], 0xffffffffffffffff
         // 00401a9f: lea ecx, ss:[ebp+0xffffffffffffffb4]
         // 00401aa2: call 0x402cf0
         // 00401aa7: mov eax, ss:[ebp+0xffffffffffffffa4]
         // 00401aaa: jmp 0x401b2a
      [-]8b45ac998bc88bf28b45b0992bc81bf28b5514890a8972046a0468????????8b45148b08516a00ff1538e040008945f08b55148b02506a008b4df051e82336000083c40c8b55148b02508b4db0518b55f052e8dd50000083c40c8b45f08945a0c645fc008d4dd0e8d8110000c745????????ff8d4db4e8c91100008b45a0
         // 00401aac: mov eax, ss:[ebp+0xffffffffffffffac]
         // 00401aaf: cdq 
         // 00401ab0: mov ecx, eax
         // 00401ab2: mov esi, edx
         // 00401ab4: mov eax, ss:[ebp+0xffffffffffffffb0]
         // 00401ab7: cdq 
         // 00401ab8: sub ecx, eax
         // 00401aba: sbb esi, edx
         // 00401abc: mov edx, ss:[ebp+0x14]
         // 00401abf: mov ds:[edx], ecx
         // 00401ac1: mov ds:[edx+0x4], esi
         // 00401ac4: push 0x4
         // 00401ac6: push 0x1000
         // 00401acb: mov eax, ss:[ebp+0x14]
         // 00401ace: mov ecx, ds:[eax]
         // 00401ad0: push ecx
         // 00401ad1: push 0x0
         // 00401ad3: call ds:[VirtualAlloc]
         // 00401ad9: mov ss:[ebp+0xfffffffffffffff0], eax
         // 00401adc: mov edx, ss:[ebp+0x14]
         // 00401adf: mov eax, ds:[edx]
         // 00401ae1: push eax
         // 00401ae2: push 0x0
         // 00401ae4: mov ecx, ss:[ebp+0xfffffffffffffff0]
         // 00401ae7: push ecx
         // 00401ae8: call _memset
         // 00401aed: add esp, 0xc
         // 00401af0: mov edx, ss:[ebp+0x14]
         // 00401af3: mov eax, ds:[edx]
         // 00401af5: push eax
         // 00401af6: mov ecx, ss:[ebp+0xffffffffffffffb0]
         // 00401af9: push ecx
         // 00401afa: mov edx, ss:[ebp+0xfffffffffffffff0]
         // 00401afd: push edx
         // 00401afe: call _memcpy
         // 00401b03: add esp, 0xc
         // 00401b06: mov eax, ss:[ebp+0xfffffffffffffff0]
         // 00401b09: mov ss:[ebp+0xffffffffffffffa0], eax
         // 00401b0c: mov b1 ss:[ebp+0xfffffffffffffffc], b1 0x0
         // 00401b10: lea ecx, ss:[ebp+0xffffffffffffffd0]
         // 00401b13: call 0x402cf0
         // 00401b18: mov ss:[ebp+0xfffffffffffffffc], 0xffffffffffffffff
         // 00401b1f: lea ecx, ss:[ebp+0xffffffffffffffb4]
         // 00401b22: call 0x402cf0
         // 00401b27: mov eax, ss:[ebp+0xffffffffffffffa0]
      [-]8b4df464890d????????595e8b4dec33cde82e3a00008be55dc3
         // 00401b2a: mov ecx, ss:[ebp+0xfffffffffffffff4]
         // 00401b2d: mov fs:[0x0], ecx
         // 00401b34: pop ecx
         // 00401b35: pop esi
         // 00401b36: mov ecx, ss:[ebp+0xffffffffffffffec]
         // 00401b39: xor ecx, ebp
         // 00401b3b: call @__security_check_cookie@4
         // 00401b40: mov esp, ebp
         // 00401b42: pop ebp
         // 00401b43: retn 
      [-]558bec6aff68????????64a1????????5083ec38a1a020410033c58945e8508d45f464a3????????68????????8d4dcce85b100000c745fc????????68????????8d4dcce8f71100008d4dcce8bf24000033c951508d4dcce883120000508b5510528b450c508b4d0851e841f9ffff83c4188945c8837dc8007527
         // 00401b50: push ebp
         // 00401b51: mov ebp, esp
         // 00401b53: push 0xffffffffffffffff
         // 00401b55: push 0x40d225
         // 00401b5a: mov eax, fs:[0x0]
         // 00401b60: push eax
         // 00401b61: sub esp, 0x38
         // 00401b64: mov eax, ds:[___security_cookie]
         // 00401b69: xor eax, ebp
         // 00401b6b: mov ss:[ebp+0xffffffffffffffe8], eax
         // 00401b6e: push eax
         // 00401b6f: lea eax, ss:[ebp+0xfffffffffffffff4]
         // 00401b72: mov fs:[0x0], eax
         // 00401b78: push 0x40e228
         // 00401b7d: lea ecx, ss:[ebp+0xffffffffffffffcc]
         // 00401b80: call 0x402be0
         // 00401b85: mov ss:[ebp+0xfffffffffffffffc], 0x0
         // 00401b8c: push 0x40e238
         // 00401b91: lea ecx, ss:[ebp+0xffffffffffffffcc]
         // 00401b94: call ?append@?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QAEAAV12@PBD@Z
         // 00401b99: lea ecx, ss:[ebp+0xffffffffffffffcc]
         // 00401b9c: call ?_GetToken@_CancellationTokenRegistration@details@Concurrency@@QBEPAV_CancellationTokenState@23@XZ
         // 00401ba1: xor ecx, ecx
         // 00401ba3: push ecx
         // 00401ba4: push eax
         // 00401ba5: lea ecx, ss:[ebp+0xffffffffffffffcc]
         // 00401ba8: call 0x402e30
         // 00401bad: push eax
         // 00401bae: mov edx, ss:[ebp+0x10]
         // 00401bb1: push edx
         // 00401bb2: mov eax, ss:[ebp+0xc]
         // 00401bb5: push eax
         // 00401bb6: mov ecx, ss:[ebp+0x8]
         // 00401bb9: push ecx
         // 00401bba: call 0x401500
         // 00401bbf: add esp, 0x18
         // 00401bc2: mov ss:[ebp+0xffffffffffffffc8], eax
         // 00401bc5: cmp ss:[ebp+0xffffffffffffffc8], 0x0
         // 00401bc9: jnz 0x401bf2
      [-]8b5514c702????????c745c4????????c745????????ff8d4dcce8061100008b45c4e9e3000000
         // 00401bcb: mov edx, ss:[ebp+0x14]
         // 00401bce: mov ds:[edx], 0x0
         // 00401bd4: mov ss:[ebp+0xffffffffffffffc4], 0x0
         // 00401bdb: mov ss:[ebp+0xfffffffffffffffc], 0xffffffffffffffff
         // 00401be2: lea ecx, ss:[ebp+0xffffffffffffffcc]
         // 00401be5: call 0x402cf0
         // 00401bea: mov eax, ss:[ebp+0xffffffffffffffc4]
         // 00401bed: jmp 0x401cd5
      [-]8d4dcce8662400000345c88945c868????????8d4dcce84311000068????????8d4dcce8761100008d4dcce83e24000033c951508d4dcce802120000508b5510528b450c508b4d0851e8c0f8ffff83c4188945ec837dec007524
         // 00401bf2: lea ecx, ss:[ebp+0xffffffffffffffcc]
         // 00401bf5: call ?_GetToken@_CancellationTokenRegistration@details@Concurrency@@QBEPAV_CancellationTokenState@23@XZ
         // 00401bfa: add eax, ss:[ebp+0xffffffffffffffc8]
         // 00401bfd: mov ss:[ebp+0xffffffffffffffc8], eax
         // 00401c00: push 0x40e248
         // 00401c05: lea ecx, ss:[ebp+0xffffffffffffffcc]
         // 00401c08: call 0x402d50
         // 00401c0d: push 0x40e258
         // 00401c12: lea ecx, ss:[ebp+0xffffffffffffffcc]
         // 00401c15: call ?append@?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QAEAAV12@PBD@Z
         // 00401c1a: lea ecx, ss:[ebp+0xffffffffffffffcc]
         // 00401c1d: call ?_GetToken@_CancellationTokenRegistration@details@Concurrency@@QBEPAV_CancellationTokenState@23@XZ
         // 00401c22: xor ecx, ecx
         // 00401c24: push ecx
         // 00401c25: push eax
         // 00401c26: lea ecx, ss:[ebp+0xffffffffffffffcc]
         // 00401c29: call 0x402e30
         // 00401c2e: push eax
         // 00401c2f: mov edx, ss:[ebp+0x10]
         // 00401c32: push edx
         // 00401c33: mov eax, ss:[ebp+0xc]
         // 00401c36: push eax
         // 00401c37: mov ecx, ss:[ebp+0x8]
         // 00401c3a: push ecx
         // 00401c3b: call 0x401500
         // 00401c40: add esp, 0x18
         // 00401c43: mov ss:[ebp+0xffffffffffffffec], eax
         // 00401c46: cmp ss:[ebp+0xffffffffffffffec], 0x0
         // 00401c4a: jnz 0x401c70
      [-]8b5514c702????????c745c0????????c745????????ff8d4dcce8851000008b45c0eb65
         // 00401c4c: mov edx, ss:[ebp+0x14]
         // 00401c4f: mov ds:[edx], 0x0
         // 00401c55: mov ss:[ebp+0xffffffffffffffc0], 0x0
         // 00401c5c: mov ss:[ebp+0xfffffffffffffffc], 0xffffffffffffffff
         // 00401c63: lea ecx, ss:[ebp+0xffffffffffffffcc]
         // 00401c66: call 0x402cf0
         // 00401c6b: mov eax, ss:[ebp+0xffffffffffffffc0]
         // 00401c6e: jmp 0x401cd5
      [-]8b45ec2b45c88b4d1489016a0468????????8b55148b02506a00ff1538e040008945f08b4d148b11526a008b45f050e86c34000083c40c8b4d148b11528b45c8508b4df051e8264f000083c40c8b55f08955bcc745????????ff8d4dcce81e1000008b45bc
         // 00401c70: mov eax, ss:[ebp+0xffffffffffffffec]
         // 00401c73: sub eax, ss:[ebp+0xffffffffffffffc8]
         // 00401c76: mov ecx, ss:[ebp+0x14]
         // 00401c79: mov ds:[ecx], eax
         // 00401c7b: push 0x4
         // 00401c7d: push 0x1000
         // 00401c82: mov edx, ss:[ebp+0x14]
         // 00401c85: mov eax, ds:[edx]
         // 00401c87: push eax
         // 00401c88: push 0x0
         // 00401c8a: call ds:[VirtualAlloc]
         // 00401c90: mov ss:[ebp+0xfffffffffffffff0], eax
         // 00401c93: mov ecx, ss:[ebp+0x14]
         // 00401c96: mov edx, ds:[ecx]
         // 00401c98: push edx
         // 00401c99: push 0x0
         // 00401c9b: mov eax, ss:[ebp+0xfffffffffffffff0]
         // 00401c9e: push eax
         // 00401c9f: call _memset
         // 00401ca4: add esp, 0xc
         // 00401ca7: mov ecx, ss:[ebp+0x14]
         // 00401caa: mov edx, ds:[ecx]
         // 00401cac: push edx
         // 00401cad: mov eax, ss:[ebp+0xffffffffffffffc8]
         // 00401cb0: push eax
         // 00401cb1: mov ecx, ss:[ebp+0xfffffffffffffff0]
         // 00401cb4: push ecx
         // 00401cb5: call _memcpy
         // 00401cba: add esp, 0xc
         // 00401cbd: mov edx, ss:[ebp+0xfffffffffffffff0]
         // 00401cc0: mov ss:[ebp+0xffffffffffffffbc], edx
         // 00401cc3: mov ss:[ebp+0xfffffffffffffffc], 0xffffffffffffffff
         // 00401cca: lea ecx, ss:[ebp+0xffffffffffffffcc]
         // 00401ccd: call 0x402cf0
         // 00401cd2: mov eax, ss:[ebp+0xffffffffffffffbc]
      [-]8b4df464890d????????598b4de833cde8843800008be55dc3
         // 00401cd5: mov ecx, ss:[ebp+0xfffffffffffffff4]
         // 00401cd8: mov fs:[0x0], ecx
         // 00401cdf: pop ecx
         // 00401ce0: mov ecx, ss:[ebp+0xffffffffffffffe8]
         // 00401ce3: xor ecx, ebp
         // 00401ce5: call @__security_check_cookie@4
         // 00401cea: mov esp, ebp
         // 00401cec: pop ebp
         // 00401ced: retn 
      [-]558bec6aff68????????64a1????????5083ec38a1a020410033c58945e4508d45f464a3????????68????????8d4dc8e8bb0e0000c745fc????????68????????8d4dc8e8571000008d4dc8e81f23000033c951508d4dc8e8e3100000508b5510528b450c508b4d0851e8a1f7ffff83c4188945f0837df0007527
         // 00401cf0: push ebp
         // 00401cf1: mov ebp, esp
         // 00401cf3: push 0xffffffffffffffff
         // 00401cf5: push 0x40d252
         // 00401cfa: mov eax, fs:[0x0]
         // 00401d00: push eax
         // 00401d01: sub esp, 0x38
         // 00401d04: mov eax, ds:[___security_cookie]
         // 00401d09: xor eax, ebp
         // 00401d0b: mov ss:[ebp+0xffffffffffffffe4], eax
         // 00401d0e: push eax
         // 00401d0f: lea eax, ss:[ebp+0xfffffffffffffff4]
         // 00401d12: mov fs:[0x0], eax
         // 00401d18: push 0x40e268
         // 00401d1d: lea ecx, ss:[ebp+0xffffffffffffffc8]
         // 00401d20: call 0x402be0
         // 00401d25: mov ss:[ebp+0xfffffffffffffffc], 0x0
         // 00401d2c: push 0x40e278
         // 00401d31: lea ecx, ss:[ebp+0xffffffffffffffc8]
         // 00401d34: call ?append@?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QAEAAV12@PBD@Z
         // 00401d39: lea ecx, ss:[ebp+0xffffffffffffffc8]
         // 00401d3c: call ?_GetToken@_CancellationTokenRegistration@details@Concurrency@@QBEPAV_CancellationTokenState@23@XZ
         // 00401d41: xor ecx, ecx
         // 00401d43: push ecx
         // 00401d44: push eax
         // 00401d45: lea ecx, ss:[ebp+0xffffffffffffffc8]
         // 00401d48: call 0x402e30
         // 00401d4d: push eax
         // 00401d4e: mov edx, ss:[ebp+0x10]
         // 00401d51: push edx
         // 00401d52: mov eax, ss:[ebp+0xc]
         // 00401d55: push eax
         // 00401d56: mov ecx, ss:[ebp+0x8]
         // 00401d59: push ecx
         // 00401d5a: call 0x401500
         // 00401d5f: add esp, 0x18
         // 00401d62: mov ss:[ebp+0xfffffffffffffff0], eax
         // 00401d65: cmp ss:[ebp+0xfffffffffffffff0], 0x0
         // 00401d69: jnz 0x401d92
      [-]8b5514c702????????c745c4????????c745????????ff8d4dc8e8660f00008b45c4e9e3000000
         // 00401d6b: mov edx, ss:[ebp+0x14]
         // 00401d6e: mov ds:[edx], 0x0
         // 00401d74: mov ss:[ebp+0xffffffffffffffc4], 0x0
         // 00401d7b: mov ss:[ebp+0xfffffffffffffffc], 0xffffffffffffffff
         // 00401d82: lea ecx, ss:[ebp+0xffffffffffffffc8]
         // 00401d85: call 0x402cf0
         // 00401d8a: mov eax, ss:[ebp+0xffffffffffffffc4]
         // 00401d8d: jmp 0x401e75
      [-]8d4dc8e8c62200000345f08945f068????????8d4dc8e8a30f000068????????8d4dc8e8d60f00008d4dc8e89e22000033c951508d4dc8e862100000508b5510528b450c508b4d0851e820f7ffff83c4188945ec837dec007524
         // 00401d92: lea ecx, ss:[ebp+0xffffffffffffffc8]
         // 00401d95: call ?_GetToken@_CancellationTokenRegistration@details@Concurrency@@QBEPAV_CancellationTokenState@23@XZ
         // 00401d9a: add eax, ss:[ebp+0xfffffffffffffff0]
         // 00401d9d: mov ss:[ebp+0xfffffffffffffff0], eax
         // 00401da0: push 0x40e288
         // 00401da5: lea ecx, ss:[ebp+0xffffffffffffffc8]
         // 00401da8: call 0x402d50
         // 00401dad: push 0x40e298
         // 00401db2: lea ecx, ss:[ebp+0xffffffffffffffc8]
         // 00401db5: call ?append@?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QAEAAV12@PBD@Z
         // 00401dba: lea ecx, ss:[ebp+0xffffffffffffffc8]
         // 00401dbd: call ?_GetToken@_CancellationTokenRegistration@details@Concurrency@@QBEPAV_CancellationTokenState@23@XZ
         // 00401dc2: xor ecx, ecx
         // 00401dc4: push ecx
         // 00401dc5: push eax
         // 00401dc6: lea ecx, ss:[ebp+0xffffffffffffffc8]
         // 00401dc9: call 0x402e30
         // 00401dce: push eax
         // 00401dcf: mov edx, ss:[ebp+0x10]
         // 00401dd2: push edx
         // 00401dd3: mov eax, ss:[ebp+0xc]
         // 00401dd6: push eax
         // 00401dd7: mov ecx, ss:[ebp+0x8]
         // 00401dda: push ecx
         // 00401ddb: call 0x401500
         // 00401de0: add esp, 0x18
         // 00401de3: mov ss:[ebp+0xffffffffffffffec], eax
         // 00401de6: cmp ss:[ebp+0xffffffffffffffec], 0x0
         // 00401dea: jnz 0x401e10
      [-]8b5514c702????????c745c0????????c745????????ff8d4dc8e8e50e00008b45c0eb65
         // 00401dec: mov edx, ss:[ebp+0x14]
         // 00401def: mov ds:[edx], 0x0
         // 00401df5: mov ss:[ebp+0xffffffffffffffc0], 0x0
         // 00401dfc: mov ss:[ebp+0xfffffffffffffffc], 0xffffffffffffffff
         // 00401e03: lea ecx, ss:[ebp+0xffffffffffffffc8]
         // 00401e06: call 0x402cf0
         // 00401e0b: mov eax, ss:[ebp+0xffffffffffffffc0]
         // 00401e0e: jmp 0x401e75
      [-]8b45ec2b45f08b4d1489016a0468????????8b55148b02506a00ff1538e040008945e88b4d148b11526a008b45e850e8cc32000083c40c8b4d148b11528b45f0508b4de851e8864d000083c40c8b55e88955bcc745????????ff8d4dc8e87e0e00008b45bc
         // 00401e10: mov eax, ss:[ebp+0xffffffffffffffec]
         // 00401e13: sub eax, ss:[ebp+0xfffffffffffffff0]
         // 00401e16: mov ecx, ss:[ebp+0x14]
         // 00401e19: mov ds:[ecx], eax
         // 00401e1b: push 0x4
         // 00401e1d: push 0x1000
         // 00401e22: mov edx, ss:[ebp+0x14]
         // 00401e25: mov eax, ds:[edx]
         // 00401e27: push eax
         // 00401e28: push 0x0
         // 00401e2a: call ds:[VirtualAlloc]
         // 00401e30: mov ss:[ebp+0xffffffffffffffe8], eax
         // 00401e33: mov ecx, ss:[ebp+0x14]
         // 00401e36: mov edx, ds:[ecx]
         // 00401e38: push edx
         // 00401e39: push 0x0
         // 00401e3b: mov eax, ss:[ebp+0xffffffffffffffe8]
         // 00401e3e: push eax
         // 00401e3f: call _memset
         // 00401e44: add esp, 0xc
         // 00401e47: mov ecx, ss:[ebp+0x14]
         // 00401e4a: mov edx, ds:[ecx]
         // 00401e4c: push edx
         // 00401e4d: mov eax, ss:[ebp+0xfffffffffffffff0]
         // 00401e50: push eax
         // 00401e51: mov ecx, ss:[ebp+0xffffffffffffffe8]
         // 00401e54: push ecx
         // 00401e55: call _memcpy
         // 00401e5a: add esp, 0xc
         // 00401e5d: mov edx, ss:[ebp+0xffffffffffffffe8]
         // 00401e60: mov ss:[ebp+0xffffffffffffffbc], edx
         // 00401e63: mov ss:[ebp+0xfffffffffffffffc], 0xffffffffffffffff
         // 00401e6a: lea ecx, ss:[ebp+0xffffffffffffffc8]
         // 00401e6d: call 0x402cf0
         // 00401e72: mov eax, ss:[ebp+0xffffffffffffffbc]
      [-]8b4df464890d????????598b4de433cde8e43600008be55dc3
         // 00401e75: mov ecx, ss:[ebp+0xfffffffffffffff4]
         // 00401e78: mov fs:[0x0], ecx
         // 00401e7f: pop ecx
         // 00401e80: mov ecx, ss:[ebp+0xffffffffffffffe4]
         // 00401e83: xor ecx, ebp
         // 00401e85: call @__security_check_cookie@4
         // 00401e8a: mov esp, ebp
         // 00401e8c: pop ebp
         // 00401e8d: retn 
      [-]558bec81ec????????a1a020410033c58945fcc785????????????????6a006a02e818b200008985????????83bd????????ff7507
         // 00401e90: push ebp
         // 00401e91: mov ebp, esp
         // 00401e93: sub esp, 0x240
         // 00401e99: mov eax, ds:[___security_cookie]
         // 00401e9e: xor eax, ebp
         // 00401ea0: mov ss:[ebp+0xfffffffffffffffc], eax
         // 00401ea3: mov ss:[ebp+0xfffffffffffffdc0], 0x0
         // 00401ead: push 0x0
         // 00401eaf: push 0x2
         // 00401eb1: call CreateToolhelp32Snapshot
         // 00401eb6: mov ss:[ebp+0xfffffffffffffdc4], eax
         // 00401ebc: cmp ss:[ebp+0xfffffffffffffdc4], 0xffffffffffffffff
         // 00401ec3: jnz 0x401ecc
      [-]33c0e989000000
         // 00401ec5: xor eax, eax
         // 00401ec7: jmp 0x401f55
      [-]c785????????????????8d85????????508b8d????????51e8dfb1000085c07511
         // 00401ecc: mov ss:[ebp+0xfffffffffffffdc8], 0x22c
         // 00401ed6: lea eax, ss:[ebp+0xfffffffffffffdc8]
         // 00401edc: push eax
         // 00401edd: mov ecx, ss:[ebp+0xfffffffffffffdc4]
         // 00401ee3: push ecx
         // 00401ee4: call Process32FirstW
         // 00401ee9: test eax, eax
         // 00401eeb: jnz 0x401efe
      [-]8b95????????52ff1554e0400033c0eb57
         // 00401eed: mov edx, ss:[ebp+0xfffffffffffffdc4]
         // 00401ef3: push edx
         // 00401ef4: call ds:[CloseHandle]
         // 00401efa: xor eax, eax
         // 00401efc: jmp 0x401f55
      [-]8b4508508d8d????????51ff1554e1400085c0750e
         // 00401efe: mov eax, ss:[ebp+0x8]
         // 00401f01: push eax
         // 00401f02: lea ecx, ss:[ebp+0xfffffffffffffdec]
         // 00401f08: push ecx
         // 00401f09: call ds:[StrCmpIW]
         // 00401f0f: test eax, eax
         // 00401f11: jnz 0x401f21
      [-]8b95????????8995????????eb21
         // 00401f13: mov edx, ss:[ebp+0xfffffffffffffdd0]
         // 00401f19: mov ss:[ebp+0xfffffffffffffdc0], edx
         // 00401f1f: jmp 0x401f42
      [-]c785????????????????8d85????????508b8d????????51e884b1000085c075bc
         // 00401f21: mov ss:[ebp+0xfffffffffffffdc8], 0x22c
         // 00401f2b: lea eax, ss:[ebp+0xfffffffffffffdc8]
         // 00401f31: push eax
         // 00401f32: mov ecx, ss:[ebp+0xfffffffffffffdc4]
         // 00401f38: push ecx
         // 00401f39: call Process32NextW
         // 00401f3e: test eax, eax
         // 00401f40: jnz 0x401efe
      [-]8b95????????52ff1554e040008b85????????
         // 00401f42: mov edx, ss:[ebp+0xfffffffffffffdc4]
         // 00401f48: push edx
         // 00401f49: call ds:[CloseHandle]
         // 00401f4f: mov eax, ss:[ebp+0xfffffffffffffdc0]
      [-]8b4dfc33cde80f3600008be55dc3
         // 00401f55: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 00401f58: xor ecx, ebp
         // 00401f5a: call @__security_check_cookie@4
         // 00401f5f: mov esp, ebp
         // 00401f61: pop ebp
         // 00401f62: retn 
      [-]558bec81ec????????a1a020410033c58945fc33c0668985f0fdffff68????????6a008d8d????????51e87131000083c40c68????????8d95????????52ff156ce0400068????????8d85????????50ff155ce140008d8d????????51ff1558e1400085c07507
         // 00401f70: push ebp
         // 00401f71: mov ebp, esp
         // 00401f73: sub esp, 0x428
         // 00401f79: mov eax, ds:[___security_cookie]
         // 00401f7e: xor eax, ebp
         // 00401f80: mov ss:[ebp+0xfffffffffffffffc], eax
         // 00401f83: xor eax, eax
         // 00401f85: mov b2 ss:[ebp+0xfffffffffffffdf0], b2 ax
         // 00401f8c: push 0x206
         // 00401f91: push 0x0
         // 00401f93: lea ecx, ss:[ebp+0xfffffffffffffdf2]
         // 00401f99: push ecx
         // 00401f9a: call _memset
         // 00401f9f: add esp, 0xc
         // 00401fa2: push 0x104
         // 00401fa7: lea edx, ss:[ebp+0xfffffffffffffdf0]
         // 00401fad: push edx
         // 00401fae: call ds:[GetSystemDirectoryW]
         // 00401fb4: push 0x40e2a8
         // 00401fb9: lea eax, ss:[ebp+0xfffffffffffffdf0]
         // 00401fbf: push eax
         // 00401fc0: call ds:[PathAppendW]
         // 00401fc6: lea ecx, ss:[ebp+0xfffffffffffffdf0]
         // 00401fcc: push ecx
         // 00401fcd: call ds:[PathFileExistsW]
         // 00401fd3: test eax, eax
         // 00401fd5: jnz 0x401fde
      [-]33c0e9bd000000
         // 00401fd7: xor eax, eax
         // 00401fd9: jmp 0x40209b
      [-]68????????e8a8feffff83c40485c07518
         // 00401fde: push 0x40e2bc
         // 00401fe3: call 0x401e90
         // 00401fe8: add esp, 0x4
         // 00401feb: test eax, eax
         // 00401fed: jnz 0x402007
      [-]68????????e897feffff83c40485c07507
         // 00401fef: push 0x40e2e8
         // 00401ff4: call 0x401e90
         // 00401ff9: add esp, 0x4
         // 00401ffc: test eax, eax
         // 00401ffe: jnz 0x402007
      [-]33c0e994000000
         // 00402000: xor eax, eax
         // 00402002: jmp 0x40209b
      [-]33d2668995e0fbffff68????????6a008d85????????50e8ed30000083c40c68????????e8cd4f000083c4045068????????8d8d????????51ff1564e1400083c40cc785????????????????8d95????????528d85????????50e88a28000083c4088985????????8b8d????????51e8dc4e000083c4048985????????8b95????????3b15????????7304
         // 00402007: xor edx, edx
         // 00402009: mov b2 ss:[ebp+0xfffffffffffffbe0], b2 dx
         // 00402010: push 0x206
         // 00402015: push 0x0
         // 00402017: lea eax, ss:[ebp+0xfffffffffffffbe2]
         // 0040201d: push eax
         // 0040201e: call _memset
         // 00402023: add esp, 0xc
         // 00402026: push 0x40e310
         // 0040202b: call __wgetenv
         // 00402030: add esp, 0x4
         // 00402033: push eax
         // 00402034: push 0x40e320
         // 00402039: lea ecx, ss:[ebp+0xfffffffffffffbe0]
         // 0040203f: push ecx
         // 00402040: call ds:[wsprintfW]
         // 00402046: add esp, 0xc
         // 00402049: mov ss:[ebp+0xfffffffffffffbd8], 0x0
         // 00402053: lea edx, ss:[ebp+0xfffffffffffffbd8]
         // 00402059: push edx
         // 0040205a: lea eax, ss:[ebp+0xfffffffffffffbe0]
         // 00402060: push eax
         // 00402061: call 0x4048f0
         // 00402066: add esp, 0x8
         // 00402069: mov ss:[ebp+0xfffffffffffffdec], eax
         // 0040206f: mov ecx, ss:[ebp+0xfffffffffffffdec]
         // 00402075: push ecx
         // 00402076: call _atoi
         // 0040207b: add esp, 0x4
         // 0040207e: mov ss:[ebp+0xfffffffffffffbdc], eax
         // 00402084: mov edx, ss:[ebp+0xfffffffffffffbdc]
         // 0040208a: cmp edx, ds:[0x412000]
         // 00402090: jnb 0x402096
      [-]33c0eb05
         // 00402092: xor eax, eax
         // 00402094: jmp 0x40209b
      [-]b8????????
         // 00402096: mov eax, 0x1
      [-]8b4dfc33cde8c93400008be55dc3
         // 0040209b: mov ecx, ss:[ebp+0xfffffffffffffffc]
         // 0040209e: xor ecx, ebp
         // 004020a0: call @__security_check_cookie@4
         // 004020a5: mov esp, ebp
         // 004020a7: pop ebp
         // 004020a8: retn 
      [-]558bec81ec????????a1a020410033c58945e88b450850ff1558e1400085c0746c
         // 004020b0: push ebp
         // 004020b1: mov ebp, esp
         // 004020b3: sub esp, 0x46c
         // 004020b9: mov eax, ds:[___security_cookie]
         // 004020be: xor eax, ebp
         // 004020c0: mov ss:[ebp+0xffffffffffffffe8], eax
         // 004020c3: mov eax, ss:[ebp+0x8]
         // 004020c6: push eax
         // 004020c7: call ds:[PathFileExistsW]
         // 004020cd: test eax, eax
         // 004020cf: jz 0x40213d
      [-]8b4d0851ff1584e0400085c0755e
         // 004020d1: mov ecx, ss:[ebp+0x8]
         // 004020d4: push ecx
         // 004020d5: call ds:[DeleteFileW]
         // 004020db: test eax, eax
         // 004020dd: jnz 0x40213d
      [-]33d266899598fbffff68????????6a008d85????????50e81530000083c40c6a0ae86befffff83c4045068????????e8ea4e000083c4045068????????8d8d????????51ff1564e1400083c4108d95????????528b450850ff1580e04000
         // 004020df: xor edx, edx
         // 004020e1: mov b2 ss:[ebp+0xfffffffffffffb98], b2 dx
         // 004020e8: push 0x206
         // 004020ed: push 0x0
         // 004020ef: lea eax, ss:[ebp+0xfffffffffffffb9a]
         // 004020f5: push eax
         // 004020f6: call _memset
         // 004020fb: add esp, 0xc
         // 004020fe: push 0xa
         // 00402100: call 0x401070
         // 00402105: add esp, 0x4
         // 00402108: push eax
         // 00402109: push 0x40e380
         // 0040210e: call __wgetenv
         // 00402113: add esp, 0x4
         // 00402116: push eax
         // 00402117: push 0x40e38c
         // 0040211c: lea ecx, ss:[ebp+0xfffffffffffffb98]
         // 00402122: push ecx
         // 00402123: call ds:[wsprintfW]
         // 00402129: add esp, 0x10
         // 0040212c: lea edx, ss:[ebp+0xfffffffffffffb98]
         // 00402132: push edx
         // 00402133: mov eax, ss:[ebp+0x8]
         // 00402136: push eax
         // 00402137: call ds:[MoveFileW]
      [-]c745c8????????c745cc????????8d4dc8518b5514528b4510508b4d0c51e800f8ffff83c4108985????????83bd????????007408
         // 0040213d: mov ss:[ebp+0xffffffffffffffc8], 0x0
         // 00402144: mov ss:[ebp+0xffffffffffffffcc], 0x0
         // 0040214b: lea ecx, ss:[ebp+0xffffffffffffffc8]
         // 0040214e: push ecx
         // 0040214f: mov edx, ss:[ebp+0x14]
         // 00402152: push edx
         // 00402153: mov eax, ss:[ebp+0x10]
         // 00402156: push eax
         // 00402157: mov ecx, ss:[ebp+0xc]
         // 0040215a: push ecx
         // 0040215b: call 0x401960
         // 00402160: add esp, 0x10
         // 00402163: mov ss:[ebp+0xfffffffffffffda4], eax
         // 00402169: cmp ss:[ebp+0xfffffffffffffda4], 0x0
         // 00402170: jz 0x40217a
      [-]8b55c80b55cc7507
         // 00402172: mov edx, ss:[ebp+0xffffffffffffffc8]
         // 00402175: or edx, ss:[ebp+0xffffffffffffffcc]
         // 00402178: jnz 0x402181
      [-]33c0e964010000
         // 0040217a: xor eax, eax
         // 0040217c: jmp 0x4022e5
      [-]8b45c8508b8d????????518b550852e82b28000083c40c85c07507
         // 00402181: mov eax, ss:[ebp+0xffffffffffffffc8]
         // 00402184: push eax
         // 00402185: mov ecx, ss:[ebp+0xfffffffffffffda4]
         // 0040218b: push ecx
         // 0040218c: mov edx, ss:[ebp+0x8]
         // 0040218f: push edx
         // 00402190: call 0x4049c0
         // 00402195: add esp, 0xc
         // 00402198: test eax, eax
         // 0040219a: jnz 0x4021a3
      [-]33c0e942010000
         // 0040219c: xor eax, eax
         // 0040219e: jmp 0x4022e5
      [-]83bd????????007414
         // 004021a3: cmp ss:[ebp+0xfffffffffffffda4], 0x0
         // 004021aa: jz 0x4021c0
      [-]68????????6a008b85????????50ff1540e04000
         // 004021ac: push 0x8000
         // 004021b1: push 0x0
         // 004021b3: mov eax, ss:[ebp+0xfffffffffffffda4]
         // 004021b9: push eax
         // 004021ba: call ds:[VirtualFree]
      [-]c745ec????????33c966898db8fdffff68????????6a008d95????????52e82d2f000083c40c68????????8d85????????506a00ff157ce040006a0068????????6a036a006a0168????????8d8d????????51ff155ce040008945c4837dc4ff7467
         // 004021c0: mov ss:[ebp+0xffffffffffffffec], 0x0
         // 004021c7: xor ecx, ecx
         // 004021c9: mov b2 ss:[ebp+0xfffffffffffffdb8], b2 cx
         // 004021d0: push 0x206
         // 004021d5: push 0x0
         // 004021d7: lea edx, ss:[ebp+0xfffffffffffffdba]
         // 004021dd: push edx
         // 004021de: call _memset
         // 004021e3: add esp, 0xc
         // 004021e6: push 0x104
         // 004021eb: lea eax, ss:[ebp+0xfffffffffffffdb8]
         // 004021f1: push eax
         // 004021f2: push 0x0
         // 004021f4: call ds:[GetModuleFileNameW]
         // 004021fa: push 0x0
         // 004021fc: push 0x80
         // 00402201: push 0x3
         // 00402203: push 0x0
         // 00402205: push 0x1
         // 00402207: push 0xffffffff80000000
         // 0040220c: lea ecx, ss:[ebp+0xfffffffffffffdb8]
         // 00402212: push ecx
         // 00402213: call ds:[CreateFileW]
         // 00402219: mov ss:[ebp+0xffffffffffffffc4], eax
         // 0040221c: cmp ss:[ebp+0xffffffffffffffc4], 0xffffffffffffffff
         // 00402220: jz 0x402289
      [-]8d55f8528d45f0508d4dd0518b55c452ff1578e0400085c07443
         // 00402222: lea edx, ss:[ebp+0xfffffffffffffff8]
         // 00402225: push edx
         // 00402226: lea eax, ss:[ebp+0xfffffffffffffff0]
         // 00402229: push eax
         // 0040222a: lea ecx, ss:[ebp+0xffffffffffffffd0]
         // 0040222d: push ecx
         // 0040222e: mov edx, ss:[ebp+0xffffffffffffffc4]
         // 00402231: push edx
         // 00402232: call ds:[GetFileTime]
         // 00402238: test eax, eax
         // 0040223a: jz 0x40227f
      [-]c745ec????????8d85????????508d4dd051ff1574e040008d95????????528d45f050ff1574e040008d8d????????518d55f852ff1574e040008b45f883c0018945f8
         // 0040223c: mov ss:[ebp+0xffffffffffffffec], 0x1
         // 00402243: lea eax, ss:[ebp+0xfffffffffffffda8]
         // 00402249: push eax
         // 0040224a: lea ecx, ss:[ebp+0xffffffffffffffd0]
         // 0040224d: push ecx
         // 0040224e: call ds:[FileTimeToSystemTime]
         // 00402254: lea edx, ss:[ebp+0xfffffffffffffda8]
         // 0040225a: push edx
         // 0040225b: lea eax, ss:[ebp+0xfffffffffffffff0]
         // 0040225e: push eax
         // 0040225f: call ds:[FileTimeToSystemTime]
         // 00402265: lea ecx, ss:[ebp+0xfffffffffffffda8]
         // 0040226b: push ecx
         // 0040226c: lea edx, ss:[ebp+0xfffffffffffffff8]
         // 0040226f: push edx
         // 00402270: call ds:[FileTimeToSystemTime]
         // 00402276: mov eax, ss:[ebp+0xfffffffffffffff8]
         // 00402279: add eax, 0x1
         // 0040227c: mov ss:[ebp+0xfffffffffffffff8], eax
      [-]8b4dc451ff1554e04000
         // 0040227f: mov ecx, ss:[ebp+0xffffffffffffffc4]
         // 00402282: push ecx
         // 00402283: call ds:[CloseHandle]
      [-]837dec007451
         // 00402289: cmp ss:[ebp+0xffffffffffffffec], 0x0
         // 0040228d: jz 0x4022e0
      [-]6a0068????????6a036a006a0268????????8b550852ff155ce040008985????????83bd????????ff7426
         // 0040228f: push 0x0
         // 00402291: push 0x80
         // 00402296: push 0x3
         // 00402298: push 0x0
         // 0040229a: push 0x2
         // 0040229c: push 0x40000000
         // 004022a1: mov edx, ss:[ebp+0x8]
         // 004022a4: push edx
         // 004022a5: call ds:[CreateFileW]
         // 004022ab: mov ss:[ebp+0xfffffffffffffb94], eax
         // 004022b1: cmp ss:[ebp+0xfffffffffffffb94], 0xffffffffffffffff
         // 004022b8: jz 0x4022e0
      [-]8d45f8508d4df0518d55d0528b85????????50ff1570e040008b8d????????51ff1554e04000
         // 004022ba: lea eax, ss:[ebp+0xfffffffffffffff8]
         // 004022bd: push eax
         // 004022be: lea ecx, ss:[ebp+0xfffffffffffffff0]
         // 004022c1: push ecx
         // 004022c2: lea edx, ss:[ebp+0xffffffffffffffd0]
         // 004022c5: push edx
         // 004022c6: mov eax, ss:[ebp+0xfffffffffffffb94]
         // 004022cc: push eax
         // 004022cd: call ds:[SetFileTime]
         // 004022d3: mov ecx, ss:[ebp+0xfffffffffffffb94]
         // 004022d9: push ecx
         // 004022da: call ds:[CloseHandle]
      [-]b8????????
         // 004022e0: mov eax, 0x1
      [-]8b4de833cde87f3200008be55dc3
         // 004022e5: mov ecx, ss:[ebp+0xffffffffffffffe8]
         // 004022e8: xor ecx, ebp
         // 004022ea: call @__security_check_cookie@4
         // 004022ef: mov esp, ebp
         // 004022f1: pop ebp
         // 004022f2: retn 
      [-]558bec6aff68????????64a1????????5081ec????????a1a020410033c58945f0508d45f464a3????????c745fc????????33c06689855cf9ffff68????????6a008d8d????????51e8c22d000083c40c68????????8d95????????526a00ff157ce040008d85????????508d8d????????e8f90b0000c645fc028d8d????????518d8d????????e8e30a0000c645fc038b15????????5268????????8d8d????????e8580e00008985????????a1????????3b85????????7417
         // 00402300: push ebp
         // 00402301: mov ebp, esp
         // 00402303: push 0xffffffffffffffff
         // 00402305: push 0x40d2a8
         // 0040230a: mov eax, fs:[0x0]
         // 00402310: push eax
         // 00402311: sub esp, 0xb68
         // 00402317: mov eax, ds:[___security_cookie]
         // 0040231c: xor eax, ebp
         // 0040231e: mov ss:[ebp+0xfffffffffffffff0], eax
         // 00402321: push eax
         // 00402322: lea eax, ss:[ebp+0xfffffffffffffff4]
         // 00402325: mov fs:[0x0], eax
         // 0040232b: mov ss:[ebp+0xfffffffffffffffc], 0x1
         // 00402332: xor eax, eax
         // 00402334: mov b2 ss:[ebp+0xfffffffffffff95c], b2 ax
         // 0040233b: push 0x206
         // 00402340: push 0x0
         // 00402342: lea ecx, ss:[ebp+0xfffffffffffff95e]
         // 00402348: push ecx
         // 00402349: call _memset
         // 0040234e: add esp, 0xc
         // 00402351: push 0x104
         // 00402356: lea edx, ss:[ebp+0xfffffffffffff95c]
         // 0040235c: push edx
         // 0040235d: push 0x0
         // 0040235f: call ds:[GetModuleFileNameW]
         // 00402365: lea eax, ss:[ebp+0xfffffffffffff95c]
         // 0040236b: push eax
         // 0040236c: lea ecx, ss:[ebp+0xfffffffffffffb78]
         // 00402372: call 0x402f70
         // 00402377: mov b1 ss:[ebp+0xfffffffffffffffc], b1 0x2
         // 0040237b: lea ecx, ss:[ebp+0xfffffffffffffb78]
         // 00402381: push ecx
         // 00402382: lea ecx, ss:[ebp+0xfffffffffffff8f0]
         // 00402388: call 0x402e70
         // 0040238d: mov b1 ss:[ebp+0xfffffffffffffffc], b1 0x3
         // 00402391: mov edx, ds:[0x40e4a4]
         // 00402397: push edx
         // 00402398: push 0x40e3a0
         // 0040239d: lea ecx, ss:[ebp+0xfffffffffffff8f0]
         // 004023a3: call 0x403200
         // 004023a8: mov ss:[ebp+0xfffffffffffffdb0], eax
         // 004023ae: mov eax, ds:[0x40e4a4]
         // 004023b3: cmp eax, ss:[ebp+0xfffffffffffffdb0]
         // 004023b9: jz 0x4023d2
      [-]8b8d????????83c101516a008d8d????????e82e0d0000
         // 004023bb: mov ecx, ss:[ebp+0xfffffffffffffdb0]
         // 004023c1: add ecx, 0x1
         // 004023c4: push ecx
         // 004023c5: push 0x0
         // 004023c7: lea ecx, ss:[ebp+0xfffffffffffff8f0]
         // 004023cd: call 0x403100
      [-]8d95????????528d8d????????e88c0a0000c645fc04a1????????5068????????8d8d????????e8020e00008985????????8b0d????????3b8d????????7421
         // 004023d2: lea edx, ss:[ebp+0xfffffffffffffb78]
         // 004023d8: push edx
         // 004023d9: lea ecx, ss:[ebp+0xfffffffffffffdc8]
         // 004023df: call 0x402e70
         // 004023e4: mov b1 ss:[ebp+0xfffffffffffffffc], b1 0x4
         // 004023e8: mov eax, ds:[0x40e4a4]
         // 004023ed: push eax
         // 004023ee: push 0x40e3a4
         // 004023f3: lea ecx, ss:[ebp+0xfffffffffffffdc8]
         // 004023f9: call 0x403200
         // 004023fe: mov ss:[ebp+0xfffffffffffff90c], eax
         // 00402404: mov ecx, ds:[0x40e4a4]
         // 0040240a: cmp ecx, ss:[ebp+0xfffffffffffff90c]
         // 00402410: jz 0x402433
      [-]8d8d????????e8431c0000508b95????????83c201528d8d????????e8cd0c0000
         // 00402412: lea ecx, ss:[ebp+0xfffffffffffff8f0]
         // 00402418: call ?_GetToken@_CancellationTokenRegistration@details@Concurrency@@QBEPAV_CancellationTokenState@23@XZ
         // 0040241d: push eax
         // 0040241e: mov edx, ss:[ebp+0xfffffffffffff90c]
         // 00402424: add edx, 0x1
         // 00402427: push edx
         // 00402428: lea ecx, ss:[ebp+0xfffffffffffffdc8]
         // 0040242e: call 0x403100
      [-]c785????????????????c785????????????????c785????????????????c785????????????????c785????????????????c785????????????????8d85????????508d8d????????518d95????????5283ec1c8bcc89a5????????8d85??
         // 00402433: mov ss:[ebp+0xfffffffffffffdb4], 0x0
         // 0040243d: mov ss:[ebp+0xfffffffffffffdb8], 0x0
         // 00402447: mov ss:[ebp+0xfffffffffffffb68], 0x0
         // 00402451: mov ss:[ebp+0xfffffffffffffdbc], 0x0
         // 0040245b: mov ss:[ebp+0xfffffffffffffdc0], 0x0
         // 00402465: mov ss:[ebp+0xfffffffffffffb6c], 0x0
         // 0040246f: lea eax, ss:[ebp+0xfffffffffffffb6c]
         // 00402475: push eax
         // 00402476: lea ecx, ss:[ebp+0xfffffffffffffdb4]
         // 0040247c: push ecx
         // 0040247d: lea edx, ss:[ebp+0xfffffffffffffb68]
         // 00402483: push edx
         // 00402484: sub esp, 0x1c
         // 00402487: mov ecx, esp
         // 00402489: mov ss:[ebp+0xfffffffffffff498], esp
         // 0040248f: lea eax, ss:[ebp+0xfffffffffffffb78]
         // 00402495: push eax
         // 00402496: call 0x402e70
         // 0040249b: mov ss:[ebp+0xfffffffffffff490], eax
         // 004024a1: call 0x4017f0
         // 004024a6: add esp, 0x28
         // 004024a9: mov ss:[ebp+0xfffffffffffff48c], eax
         // 004024af: cmp ss:[ebp+0xfffffffffffff48c], 0x0
         // 004024b6: jnz 0x402512

  }
  condition:
    all of them
}
