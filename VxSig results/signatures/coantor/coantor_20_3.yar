rule coantor_20_3 {
  meta:
    vxsig_build = "redacted"
  strings:
    $ = {
         558bec6afe6810e9420068c004420064a1????????5083ec10535657a1a01043003145f833c5508d45f064a3????????8965e8c745????????ff33ff897dfc57ff1500b042008bd83bdf7457
         // 00401000: push ebp
         // 00401001: mov ebp, esp
         // 00401003: push 0xfffffffffffffffe
         // 00401005: push stru_42E910.GSCookieOffset
         // 0040100a: push __except_handler4
         // 0040100f: mov eax, fs:[0x0]
         // 00401015: push eax
         // 00401016: sub esp, 0x10
         // 00401019: push ebx
         // 0040101a: push esi
         // 0040101b: push edi
         // 0040101c: mov eax, ds:[___security_cookie]
         // 00401021: xor ss:[ebp+0xfffffffffffffff8], eax
         // 00401024: xor eax, ebp
         // 00401026: push eax
         // 00401027: lea eax, ss:[ebp+0xfffffffffffffff0]
         // 0040102a: mov fs:[0x0], eax
         // 00401030: mov ss:[ebp+0xffffffffffffffe8], esp
         // 00401033: mov ss:[ebp+0xffffffffffffffe4], 0xffffffffffffffff
         // 0040103a: xor edi, edi
         // 0040103c: mov ss:[ebp+0xfffffffffffffffc], edi
         // 0040103f: push edi
         // 00401040: call ds:[GetModuleHandleW]
         // 00401046: mov ebx, eax
         // 00401048: cmp ebx, edi
         // 0040104a: jz 0x4010a3
      [-]8b433c03c38138????????754a
         // 0040104c: mov eax, ds:[ebx+0x3c]
         // 0040104f: add eax, ebx
         // 00401051: cmp ds:[eax], 0x4550
         // 00401057: jnz 0x4010a3
      [-]897de00fb748063bf97d3f
         // 00401059: mov ss:[ebp+0xffffffffffffffe0], edi
         // 0040105c: movzx ecx, b2 ds:[eax+0x6]
         // 00401060: cmp edi, ecx
         // 00401062: jge 0x4010a3
      [-]8d14bf8db4d0f80000008b4e0c03cb8b560803d13955087313
         // 00401064: lea edx, ds:[edi+edi*0x4]
         // 00401067: lea esi, ds:[eax+edx*0x8]
         // 0040106e: mov ecx, ds:[esi+0xc]
         // 00401071: add ecx, ebx
         // 00401073: mov edx, ds:[esi+0x8]
         // 00401076: add edx, ecx
         // 00401078: cmp ss:[ebp+0x8], edx
         // 0040107b: jnb 0x401090
      [-]8b55083bd1720c
         // 0040107d: mov edx, ss:[ebp+0x8]
         // 00401080: cmp edx, ecx
         // 00401082: jb 0x401090
      [-]8b76142bf103f28975e4eb13
         // 00401084: mov esi, ds:[esi+0x14]
         // 00401087: sub esi, ecx
         // 00401089: add esi, edx
         // 0040108b: mov ss:[ebp+0xffffffffffffffe4], esi
         // 0040108e: jmp 0x4010a3
      [-]c745fc????????8b45e48b4df064890d????????595f5e5b8be55dc3
         // 004010a3: mov ss:[ebp+0xfffffffffffffffc], 0xfffffffffffffffe
         // 004010aa: mov eax, ss:[ebp+0xffffffffffffffe4]
         // 004010ad: mov ecx, ss:[ebp+0xfffffffffffffff0]
         // 004010b0: mov fs:[0x0], ecx
         // 004010b7: pop ecx
         // 004010b8: pop edi
         // 004010b9: pop esi
         // 004010ba: pop ebx
         // 004010bb: mov esp, ebp
         // 004010bd: pop ebp
         // 004010be: retn 
      [-]c700????????c740????????00c74008????????c7400c????????c74010????????c74014????????c74018????????c7401c????????c74020????????c74024????????c3
         // 004010c0: mov ds:[eax], 0x0
         // 004010c6: mov ds:[eax+0x4], 0x0
         // 004010cd: mov ds:[eax+0x8], 0x6a09e667
         // 004010d4: mov ds:[eax+0xc], 0xffffffffbb67ae85
         // 004010db: mov ds:[eax+0x10], 0x3c6ef372
         // 004010e2: mov ds:[eax+0x14], 0xffffffffa54ff53a
         // 004010e9: mov ds:[eax+0x18], 0x510e527f
         // 004010f0: mov ds:[eax+0x1c], 0xffffffff9b05688c
         // 004010f7: mov ds:[eax+0x20], 0x1f83d9ab
         // 004010fe: mov ds:[eax+0x24], 0x5be0cd19
         // 00401105: retn 
      [-]558bec81ec????????0fb6080fb65001c1e1080bca0fb6500253c1e1080bca0fb65003560fb67005570fb67809c1e1080bca0fb65004c1e2080bd60fb670060fb6580dc1e2080bd60fb67007c1e2080bd60fb67008c1e6080bf70fb6780ac1e6080bf70fb6780bc1e6080bf70fb6780cc1e7080bfb0fb6580ec1e7080bfb0fb6580fc1e7080bfb0fb6581189bd????????0fb67810c1e7080bfb0fb65812c1e7080bfb0fb65813c1e7080bfb0fb6581589bd????????0fb67814c1e7080bfb0fb65816c1e7080bfb0fb65817c1e7080bfb0fb6581989bd????????0fb67818c1e7080bfb0fb6581ac1e7080bfb0fb6581bc1e7080bfb89bd????????0fb6781c898d????????8995????????89b5????????c1e7080fb6581d0bfbc1e7080fb6581e0bfbc1e7080fb6581f0bfb89bd????????0fb67820c1e7080fb658210bfbc1e7080fb658220bfbc1e7080fb658230bfb89bd????????0fb67824c1e7080fb658250bfb0fb65826c1e7080bfb0fb65827c1e7080bfb89bd????????0fb678280fb65829c1e7080bfb0fb6582ac1e7080bfb0fb6582bc1e7080bfb0fb6582d89bd????????0fb6782cc1e7080bfb0fb6582ec1e7080bfb0fb6582fc1e7080bfb0fb6583189bd????????0fb67830c1e7080bfb0fb65832c1e7080bfb0fb65833c1e7080bfb0fb6583589bd????????0fb67834c1e7080bfb0fb65836c1e7080bfb0fb65837c1e7080bfb0fb6583989bd????????0fb67838c1e7080bfbc1e7080fb6583a0bfb0fb6583bc1e7080bfb0fb6583d89bd????????0fb6783cc1e7080bfb0fb6583e0fb6403fc1e7080bfbc1e7080bf88b45088b581c89bd????????8b7808897de08b780c897de88b7810897dec8b78188b40208945dc8bc7c1c80b895de48bdfc1c30733c38b5d08897df8c1cf0633c70343248b7ddc337de4237df8337ddc03f88d8c0f????????8b7de88bc38b401403c1894dfc8b4de08945f08bd9c1cb0d8bc1c1c00a33d88bc1c1c80233d8035dfc8bc70bc12345ec23f98b4df00bc78bf903c38bd9c1cf0bc1c30733fbc1c90633f98b4de4334df8037ddc234df0334de403cf8d9411????????0155ec8955fc8bf8c1cf0d8bd0c1c20a33fa8b55e08bc8c1c90233f9037dfc8bc80bca234de88bd823da8b55ec0bcb03cf8bfac1cf0b8bdac1c30733fbc1ca0633fa037de48b55f83355f08bd82355ec23d93355f803d78b7de88db432????????03fe8975fc8bf1c1ce0d8bd1c1c20a33f28bd1c1ca0233f20375fc8bd00bd12355e0897de80bd303d68bf7c1ce0b8bdfc1c30733f38b5d08c1cf0633f78b7df0337dec037318237de8337df003fe8bb5????????8db437????????0175e08975fc8bfac1cf0d8bf2c1c60a33fe8bf2c1ce0233fe037dfc8bf10bf223f08bd923da0bf303f78975f48b75e08bfec1cf0b8bdec1c30733fbc1ce0633fe037df08b75ec3375e82375e03375ec03f78bbd????????8db43e????????03c68975fc8b75f48bdec1cb0d8bfec1c70a33df8bfec1cf0233df035dfc8bfa0bfe23f9897df88bfa23fe8b75f80bf703f38975f08bf0c1ce0b8bf8c1c70733f78bf8c1cf0633f70375ec8b7de8337de023f8337de803fe8bb5????????8db437????????03ce8975fc8b75f08bdec1cb0d8bfec1c70a33df8bfec1cf0233df8b7df40bfe23fa897df88b7df423fe8b75f8035dfc0bf703f38975ec8bf9c1cf0b8bf1c1c60733fe8bf1c1ce0633fe037de88b75e08bd833de23d933de03df8bb5????????8db433????????03d68975fc8b75ec8bdec1cb0d8bfec1c70a33df8bfec1cf0233df8b7df00bfe237df4035dfc897df88b7df023fe8b75f80bf703f38975e88bf2c1ce0b8bfac1c70733f78bfac1cf0633f70375e08bf833f923fa33f803fe8bb5????????8db437????????0175f48975fc8b75e88bdec1cb0d8bfec1c70a33df8bfec1cf0233df8b7dec035dfc0bfe237df0897df88b7dec23fe8b75f80bf703f38975e08b75f48bfec1cf0b8bdec1c30733fb8bdec1cb0633fb03f88b85????????8bd933da23de8b75e033d903df8b7de88d8403????????0145f08bdec1cb0d8945fc8bc6c1c00a33d88bc6c1c80233d8035dfc8bc723fe0bc62345ec8b75f00bc703c38bfec1cf0b8bdec1c30733fbc1ce0633fe03f98b8d????????8bf23375f48bd82375f033f203f78d8c0e????????014dec8b75e0894dfc8bf8c1cf0d8bc8c1c10a33f98bc8c1c90233f9037dfc23de8bc80bce234de88b75ec0bcb03cf8bfec1cf0b8bdec1c30733fbc1ce0633fe8b75f43375f02375ec03fa3375f48b95????????03f78d9416????????8b75e803f28955fc8bf9c1cf0d8bd1c1c20a33fa8975e88bd1c1ca0233fa037dfc8bd00bd12355e08bd823d90bd303d78bfe8bdec1cf0bc1c30733fbc1ce0633fe037df48b75f03375ec8bd92375e823da3375f003f78bbd????????8db43e????????0175e08975fc8bfac1cf0d8bf2c1c60a33fe8bf2c1ce0233fe037dfc8bf10bf223f00bf303f78975f48b75e08bfe8bdec1cf0bc1c30733fbc1ce0633fe8b75ec3375e8037df02375e03375ec03f78bbd????????8db43e????????03c68975fc8b75f48bdec1cb0d8bfec1c70a33df8bfec1cf0233df035dfc8bfa0bfe23f9897df88bfa23fe8b75f80bf703f38975f08bf0c1ce0b8bf8c1c70733f78bf8c1cf0633f70375ec8b7de8337de023f8337de803fe8bb5????????8db437????????03ce8975fc8b75f08bdec1cb0d8bfec1c70a33df8bfec1cf0233df035dfc8b7df40bfe23fa897df88b7df423fe8b75f80bf703f38975ec8bf9c1cf0b8bf1c1c60733fe8bf1c1ce0633fe8b75e0037de88bd833de23d933de8bb5????????03df8db433????????03d68975fc8b75ec8bdec1cb0d8bfec1c70a33df8bfec1cf0233df035dfc8b7df00bfe237df4897df88b7df023fe8b75f80bf703f38975e88bf2c1ce0b8bfac1c70733f78bfac1cf0633f70375e08bf833f923fa33f803fe8bb5????????8db437????????0175f48975fc8b75e88bdec1cb0d8bfec1c70a33df8bfec1cf0233df035dfc8b7dec0bfe237df0897df88b7dec23fe8b75f80bf703f38975e08bb5????????8bdec1c30f8bfec1c70d33df8bbd????????c1ee0a33de039d????????8bf7c1c60ec1cf0733f78bbd????????c1ef0333f703f303b5????????89b5????????8b75f48bfec1cf0b8bdec1c30733fb8bdec1cb0633fb8bd903bd????????33da23de8b75e033d903df8d8403????????0145f08945fc8b5de823de8bfec1cf0d8bc6c1c00a33f88bc6c1c80233f8037dfc8b45e80bc62345ec0bc303c78945e48b85????????8bd88bf8c1e80ac1c30fc1c70d33df8bbd????????33d8039d????????8bc7c1c00ec1cf0733c78bbd????????c1ef0333c703c30385????????8985????????8b45f08bf88bd8c1cf0bc1c30733fbc1c80633f803bd????????8bc23345f42345f033c203c78b7de48d8c08????????014dec8bdfc1cb0d8bc7c1c00a33d88bc7c1c80233d88bc70bc62345e823fe03d98b8d????????0bc703c38bd9c1c30f8bf9c1c70d33dfc1e90a33d9039d????????8bbd????????8bcfc1c10ec1cf0733cf8bbd????????c1ef0333cf03cb038d????????898d????????8b4dec8bf9c1cf0b8bd9c1c30733fbc1c90633f903bd????????8b4df4334df08bd8234dec334df403cf8d9411????????0155e88b7de4c1cb0d8bc8c1c10a33d98bc8c1c90233d903da8b95????????8bcf23f80bc823ce0bcf03cb8bda8bfac1ea0ac1c30fc1c70d33df8bbd????????33da039d????????8bd7c1c20ec1cf0733d78bbd????????c1ef0333d703d30395????????8995????????8b55e88bfa8bdac1cf0bc1c30733fbc1ca0633fa8b55f03355ec2355e83355f003bd????????8bd803d78b7df48d943a????????03f28955fc23d98bf9c1cf0d8bd1c1c20a33fa8bd1c1ca0233fa037dfc8bd00bd12355e40bd303d78955f48b95????????8bda8bfac1ea0ac1c30fc1c70d33df8bbd????????33da039d????????8bd7c1c20ec1cf0733d78bbd????????c1ef0333d703d30395????????8bfe8995????????8bd6c1ca0bc1c70733d78bfec1cf0633d70395????????8b7dec337de823fe337dec03fa8b55f08d9417????????0155e48955fc8b55f48bdac1cb0d8bfac1c70a33df8bfac1cf0233df035dfc8bf90bfa23f8897df88bf923fa8b55f80bd703d38955f08b95????????8bdac1c30f8bfac1c70d33dfc1ea0a33da039d????????8bbd????????8bd7c1c20ec1cf0733d78bbd????????c1ef0333d703d30395????????8995????????8b55e48bfac1cf0b8bdac1c30733fb8bdac1cb0633fb03bd????????8b5de833de23da335de88b55ec03df8d9413????????03c28955fc8b55f08bdac1cb0d8bfac1c70a33df8bfac1cf0233df8b7df4035dfc0bfa23f9897df88b7df423fa8b55f80bd703d38955ec8b95????????8bda8bfac1c30fc1c70d33df8bbd????????c1ea0a33da039d????????8bd7c1c20ec1cf0733d78bbd????????c1ef0333d703d30395????????8bf88995????????c1cf0b8bd8c1c30733fb8bd8c1cb0633fb03fa8b5de433de8b55e823d833de03df8d9413????????03ca8955fc8b55ec8bdac1cb0d8bfac1c70a33df8bfac1cf0233df035dfc8b7df00bfa237df4897df88b7df023fa8b55f80bd703d38955e88b95????????8bdac1c30f8bfac1c70d33df8bbd????????c1ea0a33da039d????????8bd7c1c20ec1cf0733d78bbd????????c1ef0333d703d30395????????8bf98995????????c1cf0b8bd1c1c20733fa8bd1c1ca0633fa8b55e403bd????????8bda33d823d933da8b55e803df8db433????????0175f48975fc8bfac1cf0d8bf2c1c60a33fe8bf2c1ce0233fe037dfc8b75ec0bf22375f08b5dec23da0bf303f78975e08bb5????????8bdec1c30f8bfec1c70d33df8bbd????????c1ee0a33de039d????????8bf7c1c60ec1cf0733f78bbd????????c1ef0333f703f303b5????????89b5????????8b75f48bfec1cf0b8bdec1c30733fb8bdec1cb0633fb03bd????????8bd833d923de8b75e433d803df8db433????????0175f08975fc8b75e08bdec1cb0d8bfec1c70a33df8bfec1cf0233df035dfc8bfa0bfe237dec897df88bfa23fe8b75f80bf703f38975e48bb5????????8bde8bfec1c30fc1c70d33df8bbd????????c1ee0a33de8bf7c1c60e039d????????c1cf0733f78bbd????????c1ef0333f703f303b5????????89b5????????8b75f08bfec1cf0b8bdec1c30733fbc1ce0633fe03bd????????8bf13375f42375f033f103f78d8406????????0145ec8b75e48945fc8b7de08bdec1cb0d8bc6c1c00a33d88bc6c1c80233d8035dfc8bc60bc723c28945f88bc623c78945e48b45f80b45e403c38945f88b85????????8bd88bf8c1e80ac1c30fc1c70d33df8bbd????????33d8039d????????8bc7c1c00ec1cf0733c78bbd????????c1ef0333c703c30385????????8985????????8b45ec8bf88bd8c1cf0bc1c30733fbc1c80633f88b45f43345f02345ec3345f403bd????????03c78d8c08????????8b45f803d1894dfc8bf8c1cf0d8bc8c1c10a33f98bc8c1c90233f9037dfc8bce0bc8234de08bde23d80bcb03cf894ddc8b8d????????8bd98bf9c1e90ac1c30fc1c70d33df8bbd????????33d9039d????????8bcfc1c10ec1cf0733cf8bbd????????c1ef0333cf03cb038d????????8bfa898d????????8bcac1c90bc1c70733cf8bfac1cf0633cf038d????????8b7df0337dec23fa337df003f98b4df48d8c0f????????014de0894dfc8b4ddc8bd9c1cb0d8bf9c1c70a33df8bf9c1cf0233df035dfc8bf80bf923fe897df88bf823f98b4df80bcf03cb894df48b8d????????8bd9c1c30f8bf9c1c70d33dfc1e90a33d9039d????????8bbd????????8bcfc1c10ec1cf0733cf8bbd????????c1ef0333cf03cb038d????????898d????????8b4de08bf9c1cf0b8bd9c1c30733fb8bd9c1cb0633fb03bd????????8b5dec33da23d9335dec8b4df003df8d8c0b????????03f1894dfc8b4df48bd98bf9c1cb0dc1c70a33df8bf9c1cf0233df8b7ddc035dfc0bf923f8897df88b7ddc23f98b4df80bcf03cb894df08b8d????????8bd98bf9c1c30fc1c70dc1e90a33df8bbd????????33d9039d????????8bcfc1c10ec1cf0733cf8bbd????????c1ef0333cf03cb038d????????8bfe898d????????8bcec1c90bc1c70733cf8bfec1cf0633cf038d????????8bfa337de023fe33fa03f98b4dec8d8c0f????????03c1894dfc8b4df08bd9c1cb0d8bf9c1c70a33df8bf9c1cf0233df035dfc8b7df40bf9237ddc897df88b7df423f98b4df80bcf03cb894dec8b8d????????8bd9c1c30f8bf9c1c70d33df8bbd????????c1e90a33d9039d????????8bcfc1c10ec1cf0733cf8bbd????????c1ef0333cf03cb038d????????8bf8c1cf0b898d????????8bc8c1c10733f98bc8c1c90633f98b4de003bd????????8bde33d923d833d98b4dec03df8d9413????????0155dc8955fc8bf9c1cf0d8bd1c1c20a33fa8bd1c1ca0233fa037dfc8b55f00bd12355f48b5df023d90bd303d78955e88b95????????8bdac1c30f
         // 00401110: push ebp
         // 00401111: mov ebp, esp
         // 00401113: sub esp, 0x124
         // 00401119: movzx ecx, b1 ds:[eax]
         // 0040111c: movzx edx, b1 ds:[eax+0x1]
         // 00401120: shl ecx, b1 0x8
         // 00401123: or ecx, edx
         // 00401125: movzx edx, b1 ds:[eax+0x2]
         // 00401129: push ebx
         // 0040112a: shl ecx, b1 0x8
         // 0040112d: or ecx, edx
         // 0040112f: movzx edx, b1 ds:[eax+0x3]
         // 00401133: push esi
         // 00401134: movzx esi, b1 ds:[eax+0x5]
         // 00401138: push edi
         // 00401139: movzx edi, b1 ds:[eax+0x9]
         // 0040113d: shl ecx, b1 0x8
         // 00401140: or ecx, edx
         // 00401142: movzx edx, b1 ds:[eax+0x4]
         // 00401146: shl edx, b1 0x8
         // 00401149: or edx, esi
         // 0040114b: movzx esi, b1 ds:[eax+0x6]
         // 0040114f: movzx ebx, b1 ds:[eax+0xd]
         // 00401153: shl edx, b1 0x8
         // 00401156: or edx, esi
         // 00401158: movzx esi, b1 ds:[eax+0x7]
         // 0040115c: shl edx, b1 0x8
         // 0040115f: or edx, esi
         // 00401161: movzx esi, b1 ds:[eax+0x8]
         // 00401165: shl esi, b1 0x8
         // 00401168: or esi, edi
         // 0040116a: movzx edi, b1 ds:[eax+0xa]
         // 0040116e: shl esi, b1 0x8
         // 00401171: or esi, edi
         // 00401173: movzx edi, b1 ds:[eax+0xb]
         // 00401177: shl esi, b1 0x8
         // 0040117a: or esi, edi
         // 0040117c: movzx edi, b1 ds:[eax+0xc]
         // 00401180: shl edi, b1 0x8
         // 00401183: or edi, ebx
         // 00401185: movzx ebx, b1 ds:[eax+0xe]
         // 00401189: shl edi, b1 0x8
         // 0040118c: or edi, ebx
         // 0040118e: movzx ebx, b1 ds:[eax+0xf]
         // 00401192: shl edi, b1 0x8
         // 00401195: or edi, ebx
         // 00401197: movzx ebx, b1 ds:[eax+0x11]
         // 0040119b: mov ss:[ebp+0xfffffffffffffee8], edi
         // 004011a1: movzx edi, b1 ds:[eax+0x10]
         // 004011a5: shl edi, b1 0x8
         // 004011a8: or edi, ebx
         // 004011aa: movzx ebx, b1 ds:[eax+0x12]
         // 004011ae: shl edi, b1 0x8
         // 004011b1: or edi, ebx
         // 004011b3: movzx ebx, b1 ds:[eax+0x13]
         // 004011b7: shl edi, b1 0x8
         // 004011ba: or edi, ebx
         // 004011bc: movzx ebx, b1 ds:[eax+0x15]
         // 004011c0: mov ss:[ebp+0xfffffffffffffeec], edi
         // 004011c6: movzx edi, b1 ds:[eax+0x14]
         // 004011ca: shl edi, b1 0x8
         // 004011cd: or edi, ebx
         // 004011cf: movzx ebx, b1 ds:[eax+0x16]
         // 004011d3: shl edi, b1 0x8
         // 004011d6: or edi, ebx
         // 004011d8: movzx ebx, b1 ds:[eax+0x17]
         // 004011dc: shl edi, b1 0x8
         // 004011df: or edi, ebx
         // 004011e1: movzx ebx, b1 ds:[eax+0x19]
         // 004011e5: mov ss:[ebp+0xfffffffffffffef0], edi
         // 004011eb: movzx edi, b1 ds:[eax+0x18]
         // 004011ef: shl edi, b1 0x8
         // 004011f2: or edi, ebx
         // 004011f4: movzx ebx, b1 ds:[eax+0x1a]
         // 004011f8: shl edi, b1 0x8
         // 004011fb: or edi, ebx
         // 004011fd: movzx ebx, b1 ds:[eax+0x1b]
         // 00401201: shl edi, b1 0x8
         // 00401204: or edi, ebx
         // 00401206: mov ss:[ebp+0xfffffffffffffef4], edi
         // 0040120c: movzx edi, b1 ds:[eax+0x1c]
         // 00401210: mov ss:[ebp+0xfffffffffffffedc], ecx
         // 00401216: mov ss:[ebp+0xfffffffffffffee0], edx
         // 0040121c: mov ss:[ebp+0xfffffffffffffee4], esi
         // 00401222: shl edi, b1 0x8
         // 00401225: movzx ebx, b1 ds:[eax+0x1d]
         // 00401229: or edi, ebx
         // 0040122b: shl edi, b1 0x8
         // 0040122e: movzx ebx, b1 ds:[eax+0x1e]
         // 00401232: or edi, ebx
         // 00401234: shl edi, b1 0x8
         // 00401237: movzx ebx, b1 ds:[eax+0x1f]
         // 0040123b: or edi, ebx
         // 0040123d: mov ss:[ebp+0xfffffffffffffef8], edi
         // 00401243: movzx edi, b1 ds:[eax+0x20]
         // 00401247: shl edi, b1 0x8
         // 0040124a: movzx ebx, b1 ds:[eax+0x21]
         // 0040124e: or edi, ebx
         // 00401250: shl edi, b1 0x8
         // 00401253: movzx ebx, b1 ds:[eax+0x22]
         // 00401257: or edi, ebx
         // 00401259: shl edi, b1 0x8
         // 0040125c: movzx ebx, b1 ds:[eax+0x23]
         // 00401260: or edi, ebx
         // 00401262: mov ss:[ebp+0xfffffffffffffefc], edi
         // 00401268: movzx edi, b1 ds:[eax+0x24]
         // 0040126c: shl edi, b1 0x8
         // 0040126f: movzx ebx, b1 ds:[eax+0x25]
         // 00401273: or edi, ebx
         // 00401275: movzx ebx, b1 ds:[eax+0x26]
         // 00401279: shl edi, b1 0x8
         // 0040127c: or edi, ebx
         // 0040127e: movzx ebx, b1 ds:[eax+0x27]
         // 00401282: shl edi, b1 0x8
         // 00401285: or edi, ebx
         // 00401287: mov ss:[ebp+0xffffffffffffff00], edi
         // 0040128d: movzx edi, b1 ds:[eax+0x28]
         // 00401291: movzx ebx, b1 ds:[eax+0x29]
         // 00401295: shl edi, b1 0x8
         // 00401298: or edi, ebx
         // 0040129a: movzx ebx, b1 ds:[eax+0x2a]
         // 0040129e: shl edi, b1 0x8
         // 004012a1: or edi, ebx
         // 004012a3: movzx ebx, b1 ds:[eax+0x2b]
         // 004012a7: shl edi, b1 0x8
         // 004012aa: or edi, ebx
         // 004012ac: movzx ebx, b1 ds:[eax+0x2d]
         // 004012b0: mov ss:[ebp+0xffffffffffffff04], edi
         // 004012b6: movzx edi, b1 ds:[eax+0x2c]
         // 004012ba: shl edi, b1 0x8
         // 004012bd: or edi, ebx
         // 004012bf: movzx ebx, b1 ds:[eax+0x2e]
         // 004012c3: shl edi, b1 0x8
         // 004012c6: or edi, ebx
         // 004012c8: movzx ebx, b1 ds:[eax+0x2f]
         // 004012cc: shl edi, b1 0x8
         // 004012cf: or edi, ebx
         // 004012d1: movzx ebx, b1 ds:[eax+0x31]
         // 004012d5: mov ss:[ebp+0xffffffffffffff08], edi
         // 004012db: movzx edi, b1 ds:[eax+0x30]
         // 004012df: shl edi, b1 0x8
         // 004012e2: or edi, ebx
         // 004012e4: movzx ebx, b1 ds:[eax+0x32]
         // 004012e8: shl edi, b1 0x8
         // 004012eb: or edi, ebx
         // 004012ed: movzx ebx, b1 ds:[eax+0x33]
         // 004012f1: shl edi, b1 0x8
         // 004012f4: or edi, ebx
         // 004012f6: movzx ebx, b1 ds:[eax+0x35]
         // 004012fa: mov ss:[ebp+0xffffffffffffff0c], edi
         // 00401300: movzx edi, b1 ds:[eax+0x34]
         // 00401304: shl edi, b1 0x8
         // 00401307: or edi, ebx
         // 00401309: movzx ebx, b1 ds:[eax+0x36]
         // 0040130d: shl edi, b1 0x8
         // 00401310: or edi, ebx
         // 00401312: movzx ebx, b1 ds:[eax+0x37]
         // 00401316: shl edi, b1 0x8
         // 00401319: or edi, ebx
         // 0040131b: movzx ebx, b1 ds:[eax+0x39]
         // 0040131f: mov ss:[ebp+0xffffffffffffff10], edi
         // 00401325: movzx edi, b1 ds:[eax+0x38]
         // 00401329: shl edi, b1 0x8
         // 0040132c: or edi, ebx
         // 0040132e: shl edi, b1 0x8
         // 00401331: movzx ebx, b1 ds:[eax+0x3a]
         // 00401335: or edi, ebx
         // 00401337: movzx ebx, b1 ds:[eax+0x3b]
         // 0040133b: shl edi, b1 0x8
         // 0040133e: or edi, ebx
         // 00401340: movzx ebx, b1 ds:[eax+0x3d]
         // 00401344: mov ss:[ebp+0xffffffffffffff14], edi
         // 0040134a: movzx edi, b1 ds:[eax+0x3c]
         // 0040134e: shl edi, b1 0x8
         // 00401351: or edi, ebx
         // 00401353: movzx ebx, b1 ds:[eax+0x3e]
         // 00401357: movzx eax, b1 ds:[eax+0x3f]
         // 0040135b: shl edi, b1 0x8
         // 0040135e: or edi, ebx
         // 00401360: shl edi, b1 0x8
         // 00401363: or edi, eax
         // 00401365: mov eax, ss:[ebp+0x8]
         // 00401368: mov ebx, ds:[eax+0x1c]
         // 0040136b: mov ss:[ebp+0xffffffffffffff18], edi
         // 00401371: mov edi, ds:[eax+0x8]
         // 00401374: mov ss:[ebp+0xffffffffffffffe0], edi
         // 00401377: mov edi, ds:[eax+0xc]
         // 0040137a: mov ss:[ebp+0xffffffffffffffe8], edi
         // 0040137d: mov edi, ds:[eax+0x10]
         // 00401380: mov ss:[ebp+0xffffffffffffffec], edi
         // 00401383: mov edi, ds:[eax+0x18]
         // 00401386: mov eax, ds:[eax+0x20]
         // 00401389: mov ss:[ebp+0xffffffffffffffdc], eax
         // 0040138c: mov eax, edi
         // 0040138e: ror eax, b1 0xb
         // 00401391: mov ss:[ebp+0xffffffffffffffe4], ebx
         // 00401394: mov ebx, edi
         // 00401396: rol ebx, b1 0x7
         // 00401399: xor eax, ebx
         // 0040139b: mov ebx, ss:[ebp+0x8]
         // 0040139e: mov ss:[ebp+0xfffffffffffffff8], edi
         // 004013a1: ror edi, b1 0x6
         // 004013a4: xor eax, edi
         // 004013a6: add eax, ds:[ebx+0x24]
         // 004013a9: mov edi, ss:[ebp+0xffffffffffffffdc]
         // 004013ac: xor edi, ss:[ebp+0xffffffffffffffe4]
         // 004013af: and edi, ss:[ebp+0xfffffffffffffff8]
         // 004013b2: xor edi, ss:[ebp+0xffffffffffffffdc]
         // 004013b5: add edi, eax
         // 004013b7: lea ecx, ds:[edi+ecx+0x428a2f98]
         // 004013be: mov edi, ss:[ebp+0xffffffffffffffe8]
         // 004013c1: mov eax, ebx
         // 004013c3: mov eax, ds:[eax+0x14]
         // 004013c6: add eax, ecx
         // 004013c8: mov ss:[ebp+0xfffffffffffffffc], ecx
         // 004013cb: mov ecx, ss:[ebp+0xffffffffffffffe0]
         // 004013ce: mov ss:[ebp+0xfffffffffffffff0], eax
         // 004013d1: mov ebx, ecx
         // 004013d3: ror ebx, b1 0xd
         // 004013d6: mov eax, ecx
         // 004013d8: rol eax, b1 0xa
         // 004013db: xor ebx, eax
         // 004013dd: mov eax, ecx
         // 004013df: ror eax, b1 0x2
         // 004013e2: xor ebx, eax
         // 004013e4: add ebx, ss:[ebp+0xfffffffffffffffc]
         // 004013e7: mov eax, edi
         // 004013e9: or eax, ecx
         // 004013eb: and eax, ss:[ebp+0xffffffffffffffec]
         // 004013ee: and edi, ecx
         // 004013f0: mov ecx, ss:[ebp+0xfffffffffffffff0]
         // 004013f3: or eax, edi
         // 004013f5: mov edi, ecx
         // 004013f7: add eax, ebx
         // 004013f9: mov ebx, ecx
         // 004013fb: ror edi, b1 0xb
         // 004013fe: rol ebx, b1 0x7
         // 00401401: xor edi, ebx
         // 00401403: ror ecx, b1 0x6
         // 00401406: xor edi, ecx
         // 00401408: mov ecx, ss:[ebp+0xffffffffffffffe4]
         // 0040140b: xor ecx, ss:[ebp+0xfffffffffffffff8]
         // 0040140e: add edi, ss:[ebp+0xffffffffffffffdc]
         // 00401411: and ecx, ss:[ebp+0xfffffffffffffff0]
         // 00401414: xor ecx, ss:[ebp+0xffffffffffffffe4]
         // 00401417: add ecx, edi
         // 00401419: lea edx, ds:[ecx+edx+0x71374491]
         // 00401420: add ss:[ebp+0xffffffffffffffec], edx
         // 00401423: mov ss:[ebp+0xfffffffffffffffc], edx
         // 00401426: mov edi, eax
         // 00401428: ror edi, b1 0xd
         // 0040142b: mov edx, eax
         // 0040142d: rol edx, b1 0xa
         // 00401430: xor edi, edx
         // 00401432: mov edx, ss:[ebp+0xffffffffffffffe0]
         // 00401435: mov ecx, eax
         // 00401437: ror ecx, b1 0x2
         // 0040143a: xor edi, ecx
         // 0040143c: add edi, ss:[ebp+0xfffffffffffffffc]
         // 0040143f: mov ecx, eax
         // 00401441: or ecx, edx
         // 00401443: and ecx, ss:[ebp+0xffffffffffffffe8]
         // 00401446: mov ebx, eax
         // 00401448: and ebx, edx
         // 0040144a: mov edx, ss:[ebp+0xffffffffffffffec]
         // 0040144d: or ecx, ebx
         // 0040144f: add ecx, edi
         // 00401451: mov edi, edx
         // 00401453: ror edi, b1 0xb
         // 00401456: mov ebx, edx
         // 00401458: rol ebx, b1 0x7
         // 0040145b: xor edi, ebx
         // 0040145d: ror edx, b1 0x6
         // 00401460: xor edi, edx
         // 00401462: add edi, ss:[ebp+0xffffffffffffffe4]
         // 00401465: mov edx, ss:[ebp+0xfffffffffffffff8]
         // 00401468: xor edx, ss:[ebp+0xfffffffffffffff0]
         // 0040146b: mov ebx, eax
         // 0040146d: and edx, ss:[ebp+0xffffffffffffffec]
         // 00401470: and ebx, ecx
         // 00401472: xor edx, ss:[ebp+0xfffffffffffffff8]
         // 00401475: add edx, edi
         // 00401477: mov edi, ss:[ebp+0xffffffffffffffe8]
         // 0040147a: lea esi, ds:[edx+esi+0xffffffffb5c0fbcf]
         // 00401481: add edi, esi
         // 00401483: mov ss:[ebp+0xfffffffffffffffc], esi
         // 00401486: mov esi, ecx
         // 00401488: ror esi, b1 0xd
         // 0040148b: mov edx, ecx
         // 0040148d: rol edx, b1 0xa
         // 00401490: xor esi, edx
         // 00401492: mov edx, ecx
         // 00401494: ror edx, b1 0x2
         // 00401497: xor esi, edx
         // 00401499: add esi, ss:[ebp+0xfffffffffffffffc]
         // 0040149c: mov edx, eax
         // 0040149e: or edx, ecx
         // 004014a0: and edx, ss:[ebp+0xffffffffffffffe0]
         // 004014a3: mov ss:[ebp+0xffffffffffffffe8], edi
         // 004014a6: or edx, ebx
         // 004014a8: add edx, esi
         // 004014aa: mov esi, edi
         // 004014ac: ror esi, b1 0xb
         // 004014af: mov ebx, edi
         // 004014b1: rol ebx, b1 0x7
         // 004014b4: xor esi, ebx
         // 004014b6: mov ebx, ss:[ebp+0x8]
         // 004014b9: ror edi, b1 0x6
         // 004014bc: xor esi, edi
         // 004014be: mov edi, ss:[ebp+0xfffffffffffffff0]
         // 004014c1: xor edi, ss:[ebp+0xffffffffffffffec]
         // 004014c4: add esi, ds:[ebx+0x18]
         // 004014c7: and edi, ss:[ebp+0xffffffffffffffe8]
         // 004014ca: xor edi, ss:[ebp+0xfffffffffffffff0]
         // 004014cd: add edi, esi
         // 004014cf: mov esi, ss:[ebp+0xfffffffffffffee8]
         // 004014d5: lea esi, ds:[edi+esi+0xffffffffe9b5dba5]
         // 004014dc: add ss:[ebp+0xffffffffffffffe0], esi
         // 004014df: mov ss:[ebp+0xfffffffffffffffc], esi
         // 004014e2: mov edi, edx
         // 004014e4: ror edi, b1 0xd
         // 004014e7: mov esi, edx
         // 004014e9: rol esi, b1 0xa
         // 004014ec: xor edi, esi
         // 004014ee: mov esi, edx
         // 004014f0: ror esi, b1 0x2
         // 004014f3: xor edi, esi
         // 004014f5: add edi, ss:[ebp+0xfffffffffffffffc]
         // 004014f8: mov esi, ecx
         // 004014fa: or esi, edx
         // 004014fc: and esi, eax
         // 004014fe: mov ebx, ecx
         // 00401500: and ebx, edx
         // 00401502: or esi, ebx
         // 00401504: add esi, edi
         // 00401506: mov ss:[ebp+0xfffffffffffffff4], esi
         // 00401509: mov esi, ss:[ebp+0xffffffffffffffe0]
         // 0040150c: mov edi, esi
         // 0040150e: ror edi, b1 0xb
         // 00401511: mov ebx, esi
         // 00401513: rol ebx, b1 0x7
         // 00401516: xor edi, ebx
         // 00401518: ror esi, b1 0x6
         // 0040151b: xor edi, esi
         // 0040151d: add edi, ss:[ebp+0xfffffffffffffff0]
         // 00401520: mov esi, ss:[ebp+0xffffffffffffffec]
         // 00401523: xor esi, ss:[ebp+0xffffffffffffffe8]
         // 00401526: and esi, ss:[ebp+0xffffffffffffffe0]
         // 00401529: xor esi, ss:[ebp+0xffffffffffffffec]
         // 0040152c: add esi, edi
         // 0040152e: mov edi, ss:[ebp+0xfffffffffffffeec]
         // 00401534: lea esi, ds:[esi+edi+0x3956c25b]
         // 0040153b: add eax, esi
         // 0040153d: mov ss:[ebp+0xfffffffffffffffc], esi
         // 00401540: mov esi, ss:[ebp+0xfffffffffffffff4]
         // 00401543: mov ebx, esi
         // 00401545: ror ebx, b1 0xd
         // 00401548: mov edi, esi
         // 0040154a: rol edi, b1 0xa
         // 0040154d: xor ebx, edi
         // 0040154f: mov edi, esi
         // 00401551: ror edi, b1 0x2
         // 00401554: xor ebx, edi
         // 00401556: add ebx, ss:[ebp+0xfffffffffffffffc]
         // 00401559: mov edi, edx
         // 0040155b: or edi, esi
         // 0040155d: and edi, ecx
         // 0040155f: mov ss:[ebp+0xfffffffffffffff8], edi
         // 00401562: mov edi, edx
         // 00401564: and edi, esi
         // 00401566: mov esi, ss:[ebp+0xfffffffffffffff8]
         // 00401569: or esi, edi
         // 0040156b: add esi, ebx
         // 0040156d: mov ss:[ebp+0xfffffffffffffff0], esi
         // 00401570: mov esi, eax
         // 00401572: ror esi, b1 0xb
         // 00401575: mov edi, eax
         // 00401577: rol edi, b1 0x7
         // 0040157a: xor esi, edi
         // 0040157c: mov edi, eax
         // 0040157e: ror edi, b1 0x6
         // 00401581: xor esi, edi
         // 00401583: add esi, ss:[ebp+0xffffffffffffffec]
         // 00401586: mov edi, ss:[ebp+0xffffffffffffffe8]
         // 00401589: xor edi, ss:[ebp+0xffffffffffffffe0]
         // 0040158c: and edi, eax
         // 0040158e: xor edi, ss:[ebp+0xffffffffffffffe8]
         // 00401591: add edi, esi
         // 00401593: mov esi, ss:[ebp+0xfffffffffffffef0]
         // 00401599: lea esi, ds:[edi+esi+0x59f111f1]
         // 004015a0: add ecx, esi
         // 004015a2: mov ss:[ebp+0xfffffffffffffffc], esi
         // 004015a5: mov esi, ss:[ebp+0xfffffffffffffff0]
         // 004015a8: mov ebx, esi
         // 004015aa: ror ebx, b1 0xd
         // 004015ad: mov edi, esi
         // 004015af: rol edi, b1 0xa
         // 004015b2: xor ebx, edi
         // 004015b4: mov edi, esi
         // 004015b6: ror edi, b1 0x2
         // 004015b9: xor ebx, edi
         // 004015bb: mov edi, ss:[ebp+0xfffffffffffffff4]
         // 004015be: or edi, esi
         // 004015c0: and edi, edx
         // 004015c2: mov ss:[ebp+0xfffffffffffffff8], edi
         // 004015c5: mov edi, ss:[ebp+0xfffffffffffffff4]
         // 004015c8: and edi, esi
         // 004015ca: mov esi, ss:[ebp+0xfffffffffffffff8]
         // 004015cd: add ebx, ss:[ebp+0xfffffffffffffffc]
         // 004015d0: or esi, edi
         // 004015d2: add esi, ebx
         // 004015d4: mov ss:[ebp+0xffffffffffffffec], esi
         // 004015d7: mov edi, ecx
         // 004015d9: ror edi, b1 0xb
         // 004015dc: mov esi, ecx
         // 004015de: rol esi, b1 0x7
         // 004015e1: xor edi, esi
         // 004015e3: mov esi, ecx
         // 004015e5: ror esi, b1 0x6
         // 004015e8: xor edi, esi
         // 004015ea: add edi, ss:[ebp+0xffffffffffffffe8]
         // 004015ed: mov esi, ss:[ebp+0xffffffffffffffe0]
         // 004015f0: mov ebx, eax
         // 004015f2: xor ebx, esi
         // 004015f4: and ebx, ecx
         // 004015f6: xor ebx, esi
         // 004015f8: add ebx, edi
         // 004015fa: mov esi, ss:[ebp+0xfffffffffffffef4]
         // 00401600: lea esi, ds:[ebx+esi+0xffffffff923f82a4]
         // 00401607: add edx, esi
         // 00401609: mov ss:[ebp+0xfffffffffffffffc], esi
         // 0040160c: mov esi, ss:[ebp+0xffffffffffffffec]
         // 0040160f: mov ebx, esi
         // 00401611: ror ebx, b1 0xd
         // 00401614: mov edi, esi
         // 00401616: rol edi, b1 0xa
         // 00401619: xor ebx, edi
         // 0040161b: mov edi, esi
         // 0040161d: ror edi, b1 0x2
         // 00401620: xor ebx, edi
         // 00401622: mov edi, ss:[ebp+0xfffffffffffffff0]
         // 00401625: or edi, esi
         // 00401627: and edi, ss:[ebp+0xfffffffffffffff4]
         // 0040162a: add ebx, ss:[ebp+0xfffffffffffffffc]
         // 0040162d: mov ss:[ebp+0xfffffffffffffff8], edi
         // 00401630: mov edi, ss:[ebp+0xfffffffffffffff0]
         // 00401633: and edi, esi
         // 00401635: mov esi, ss:[ebp+0xfffffffffffffff8]
         // 00401638: or esi, edi
         // 0040163a: add esi, ebx
         // 0040163c: mov ss:[ebp+0xffffffffffffffe8], esi
         // 0040163f: mov esi, edx
         // 00401641: ror esi, b1 0xb
         // 00401644: mov edi, edx
         // 00401646: rol edi, b1 0x7
         // 00401649: xor esi, edi
         // 0040164b: mov edi, edx
         // 0040164d: ror edi, b1 0x6
         // 00401650: xor esi, edi
         // 00401652: add esi, ss:[ebp+0xffffffffffffffe0]
         // 00401655: mov edi, eax
         // 00401657: xor edi, ecx
         // 00401659: and edi, edx
         // 0040165b: xor edi, eax
         // 0040165d: add edi, esi
         // 0040165f: mov esi, ss:[ebp+0xfffffffffffffef8]
         // 00401665: lea esi, ds:[edi+esi+0xffffffffab1c5ed5]
         // 0040166c: add ss:[ebp+0xfffffffffffffff4], esi
         // 0040166f: mov ss:[ebp+0xfffffffffffffffc], esi
         // 00401672: mov esi, ss:[ebp+0xffffffffffffffe8]
         // 00401675: mov ebx, esi
         // 00401677: ror ebx, b1 0xd
         // 0040167a: mov edi, esi
         // 0040167c: rol edi, b1 0xa
         // 0040167f: xor ebx, edi
         // 00401681: mov edi, esi
         // 00401683: ror edi, b1 0x2
         // 00401686: xor ebx, edi
         // 00401688: mov edi, ss:[ebp+0xffffffffffffffec]
         // 0040168b: add ebx, ss:[ebp+0xfffffffffffffffc]
         // 0040168e: or edi, esi
         // 00401690: and edi, ss:[ebp+0xfffffffffffffff0]
         // 00401693: mov ss:[ebp+0xfffffffffffffff8], edi
         // 00401696: mov edi, ss:[ebp+0xffffffffffffffec]
         // 00401699: and edi, esi
         // 0040169b: mov esi, ss:[ebp+0xfffffffffffffff8]
         // 0040169e: or esi, edi
         // 004016a0: add esi, ebx
         // 004016a2: mov ss:[ebp+0xffffffffffffffe0], esi
         // 004016a5: mov esi, ss:[ebp+0xfffffffffffffff4]
         // 004016a8: mov edi, esi
         // 004016aa: ror edi, b1 0xb
         // 004016ad: mov ebx, esi
         // 004016af: rol ebx, b1 0x7
         // 004016b2: xor edi, ebx
         // 004016b4: mov ebx, esi
         // 004016b6: ror ebx, b1 0x6
         // 004016b9: xor edi, ebx
         // 004016bb: add edi, eax
         // 004016bd: mov eax, ss:[ebp+0xfffffffffffffefc]
         // 004016c3: mov ebx, ecx
         // 004016c5: xor ebx, edx
         // 004016c7: and ebx, esi
         // 004016c9: mov esi, ss:[ebp+0xffffffffffffffe0]
         // 004016cc: xor ebx, ecx
         // 004016ce: add ebx, edi
         // 004016d0: mov edi, ss:[ebp+0xffffffffffffffe8]
         // 004016d3: lea eax, ds:[ebx+eax+0xffffffffd807aa98]
         // 004016da: add ss:[ebp+0xfffffffffffffff0], eax
         // 004016dd: mov ebx, esi
         // 004016df: ror ebx, b1 0xd
         // 004016e2: mov ss:[ebp+0xfffffffffffffffc], eax
         // 004016e5: mov eax, esi
         // 004016e7: rol eax, b1 0xa
         // 004016ea: xor ebx, eax
         // 004016ec: mov eax, esi
         // 004016ee: ror eax, b1 0x2
         // 004016f1: xor ebx, eax
         // 004016f3: add ebx, ss:[ebp+0xfffffffffffffffc]
         // 004016f6: mov eax, edi
         // 004016f8: and edi, esi
         // 004016fa: or eax, esi
         // 004016fc: and eax, ss:[ebp+0xffffffffffffffec]
         // 004016ff: mov esi, ss:[ebp+0xfffffffffffffff0]
         // 00401702: or eax, edi
         // 00401704: add eax, ebx
         // 00401706: mov edi, esi
         // 00401708: ror edi, b1 0xb
         // 0040170b: mov ebx, esi
         // 0040170d: rol ebx, b1 0x7
         // 00401710: xor edi, ebx
         // 00401712: ror esi, b1 0x6
         // 00401715: xor edi, esi
         // 00401717: add edi, ecx
         // 00401719: mov ecx, ss:[ebp+0xffffffffffffff00]
         // 0040171f: mov esi, edx
         // 00401721: xor esi, ss:[ebp+0xfffffffffffffff4]
         // 00401724: mov ebx, eax
         // 00401726: and esi, ss:[ebp+0xfffffffffffffff0]
         // 00401729: xor esi, edx
         // 0040172b: add esi, edi
         // 0040172d: lea ecx, ds:[esi+ecx+0x12835b01]
         // 00401734: add ss:[ebp+0xffffffffffffffec], ecx
         // 00401737: mov esi, ss:[ebp+0xffffffffffffffe0]
         // 0040173a: mov ss:[ebp+0xfffffffffffffffc], ecx
         // 0040173d: mov edi, eax
         // 0040173f: ror edi, b1 0xd
         // 00401742: mov ecx, eax
         // 00401744: rol ecx, b1 0xa
         // 00401747: xor edi, ecx
         // 00401749: mov ecx, eax
         // 0040174b: ror ecx, b1 0x2
         // 0040174e: xor edi, ecx
         // 00401750: add edi, ss:[ebp+0xfffffffffffffffc]
         // 00401753: and ebx, esi
         // 00401755: mov ecx, eax
         // 00401757: or ecx, esi
         // 00401759: and ecx, ss:[ebp+0xffffffffffffffe8]
         // 0040175c: mov esi, ss:[ebp+0xffffffffffffffec]
         // 0040175f: or ecx, ebx
         // 00401761: add ecx, edi
         // 00401763: mov edi, esi
         // 00401765: ror edi, b1 0xb
         // 00401768: mov ebx, esi
         // 0040176a: rol ebx, b1 0x7
         // 0040176d: xor edi, ebx
         // 0040176f: ror esi, b1 0x6
         // 00401772: xor edi, esi
         // 00401774: mov esi, ss:[ebp+0xfffffffffffffff4]
         // 00401777: xor esi, ss:[ebp+0xfffffffffffffff0]
         // 0040177a: and esi, ss:[ebp+0xffffffffffffffec]
         // 0040177d: add edi, edx
         // 0040177f: xor esi, ss:[ebp+0xfffffffffffffff4]
         // 00401782: mov edx, ss:[ebp+0xffffffffffffff04]
         // 00401788: add esi, edi
         // 0040178a: lea edx, ds:[esi+edx+0x243185be]
         // 00401791: mov esi, ss:[ebp+0xffffffffffffffe8]
         // 00401794: add esi, edx
         // 00401796: mov ss:[ebp+0xfffffffffffffffc], edx
         // 00401799: mov edi, ecx
         // 0040179b: ror edi, b1 0xd
         // 0040179e: mov edx, ecx
         // 004017a0: rol edx, b1 0xa
         // 004017a3: xor edi, edx
         // 004017a5: mov ss:[ebp+0xffffffffffffffe8], esi
         // 004017a8: mov edx, ecx
         // 004017aa: ror edx, b1 0x2
         // 004017ad: xor edi, edx
         // 004017af: add edi, ss:[ebp+0xfffffffffffffffc]
         // 004017b2: mov edx, eax
         // 004017b4: or edx, ecx
         // 004017b6: and edx, ss:[ebp+0xffffffffffffffe0]
         // 004017b9: mov ebx, eax
         // 004017bb: and ebx, ecx
         // 004017bd: or edx, ebx
         // 004017bf: add edx, edi
         // 004017c1: mov edi, esi
         // 004017c3: mov ebx, esi
         // 004017c5: ror edi, b1 0xb
         // 004017c8: rol ebx, b1 0x7
         // 004017cb: xor edi, ebx
         // 004017cd: ror esi, b1 0x6
         // 004017d0: xor edi, esi
         // 004017d2: add edi, ss:[ebp+0xfffffffffffffff4]
         // 004017d5: mov esi, ss:[ebp+0xfffffffffffffff0]
         // 004017d8: xor esi, ss:[ebp+0xffffffffffffffec]
         // 004017db: mov ebx, ecx
         // 004017dd: and esi, ss:[ebp+0xffffffffffffffe8]
         // 004017e0: and ebx, edx
         // 004017e2: xor esi, ss:[ebp+0xfffffffffffffff0]
         // 004017e5: add esi, edi
         // 004017e7: mov edi, ss:[ebp+0xffffffffffffff08]
         // 004017ed: lea esi, ds:[esi+edi+0x550c7dc3]
         // 004017f4: add ss:[ebp+0xffffffffffffffe0], esi
         // 004017f7: mov ss:[ebp+0xfffffffffffffffc], esi
         // 004017fa: mov edi, edx
         // 004017fc: ror edi, b1 0xd
         // 004017ff: mov esi, edx
         // 00401801: rol esi, b1 0xa
         // 00401804: xor edi, esi
         // 00401806: mov esi, edx
         // 00401808: ror esi, b1 0x2
         // 0040180b: xor edi, esi
         // 0040180d: add edi, ss:[ebp+0xfffffffffffffffc]
         // 00401810: mov esi, ecx
         // 00401812: or esi, edx
         // 00401814: and esi, eax
         // 00401816: or esi, ebx
         // 00401818: add esi, edi
         // 0040181a: mov ss:[ebp+0xfffffffffffffff4], esi
         // 0040181d: mov esi, ss:[ebp+0xffffffffffffffe0]
         // 00401820: mov edi, esi
         // 00401822: mov ebx, esi
         // 00401824: ror edi, b1 0xb
         // 00401827: rol ebx, b1 0x7
         // 0040182a: xor edi, ebx
         // 0040182c: ror esi, b1 0x6
         // 0040182f: xor edi, esi
         // 00401831: mov esi, ss:[ebp+0xffffffffffffffec]
         // 00401834: xor esi, ss:[ebp+0xffffffffffffffe8]
         // 00401837: add edi, ss:[ebp+0xfffffffffffffff0]
         // 0040183a: and esi, ss:[ebp+0xffffffffffffffe0]
         // 0040183d: xor esi, ss:[ebp+0xffffffffffffffec]
         // 00401840: add esi, edi
         // 00401842: mov edi, ss:[ebp+0xffffffffffffff0c]
         // 00401848: lea esi, ds:[esi+edi+0x72be5d74]
         // 0040184f: add eax, esi
         // 00401851: mov ss:[ebp+0xfffffffffffffffc], esi
         // 00401854: mov esi, ss:[ebp+0xfffffffffffffff4]
         // 00401857: mov ebx, esi
         // 00401859: ror ebx, b1 0xd
         // 0040185c: mov edi, esi
         // 0040185e: rol edi, b1 0xa
         // 00401861: xor ebx, edi
         // 00401863: mov edi, esi
         // 00401865: ror edi, b1 0x2
         // 00401868: xor ebx, edi
         // 0040186a: add ebx, ss:[ebp+0xfffffffffffffffc]
         // 0040186d: mov edi, edx
         // 0040186f: or edi, esi
         // 00401871: and edi, ecx
         // 00401873: mov ss:[ebp+0xfffffffffffffff8], edi
         // 00401876: mov edi, edx
         // 00401878: and edi, esi
         // 0040187a: mov esi, ss:[ebp+0xfffffffffffffff8]
         // 0040187d: or esi, edi
         // 0040187f: add esi, ebx
         // 00401881: mov ss:[ebp+0xfffffffffffffff0], esi
         // 00401884: mov esi, eax
         // 00401886: ror esi, b1 0xb
         // 00401889: mov edi, eax
         // 0040188b: rol edi, b1 0x7
         // 0040188e: xor esi, edi
         // 00401890: mov edi, eax
         // 00401892: ror edi, b1 0x6
         // 00401895: xor esi, edi
         // 00401897: add esi, ss:[ebp+0xffffffffffffffec]
         // 0040189a: mov edi, ss:[ebp+0xffffffffffffffe8]
         // 0040189d: xor edi, ss:[ebp+0xffffffffffffffe0]
         // 004018a0: and edi, eax
         // 004018a2: xor edi, ss:[ebp+0xffffffffffffffe8]
         // 004018a5: add edi, esi
         // 004018a7: mov esi, ss:[ebp+0xffffffffffffff10]
         // 004018ad: lea esi, ds:[edi+esi+0xffffffff80deb1fe]
         // 004018b4: add ecx, esi
         // 004018b6: mov ss:[ebp+0xfffffffffffffffc], esi
         // 004018b9: mov esi, ss:[ebp+0xfffffffffffffff0]
         // 004018bc: mov ebx, esi
         // 004018be: ror ebx, b1 0xd
         // 004018c1: mov edi, esi
         // 004018c3: rol edi, b1 0xa
         // 004018c6: xor ebx, edi
         // 004018c8: mov edi, esi
         // 004018ca: ror edi, b1 0x2
         // 004018cd: xor ebx, edi
         // 004018cf: add ebx, ss:[ebp+0xfffffffffffffffc]
         // 004018d2: mov edi, ss:[ebp+0xfffffffffffffff4]
         // 004018d5: or edi, esi
         // 004018d7: and edi, edx
         // 004018d9: mov ss:[ebp+0xfffffffffffffff8], edi
         // 004018dc: mov edi, ss:[ebp+0xfffffffffffffff4]
         // 004018df: and edi, esi
         // 004018e1: mov esi, ss:[ebp+0xfffffffffffffff8]
         // 004018e4: or esi, edi
         // 004018e6: add esi, ebx
         // 004018e8: mov ss:[ebp+0xffffffffffffffec], esi
         // 004018eb: mov edi, ecx
         // 004018ed: ror edi, b1 0xb
         // 004018f0: mov esi, ecx
         // 004018f2: rol esi, b1 0x7
         // 004018f5: xor edi, esi
         // 004018f7: mov esi, ecx
         // 004018f9: ror esi, b1 0x6
         // 004018fc: xor edi, esi
         // 004018fe: mov esi, ss:[ebp+0xffffffffffffffe0]
         // 00401901: add edi, ss:[ebp+0xffffffffffffffe8]
         // 00401904: mov ebx, eax
         // 00401906: xor ebx, esi
         // 00401908: and ebx, ecx
         // 0040190a: xor ebx, esi
         // 0040190c: mov esi, ss:[ebp+0xffffffffffffff14]
         // 00401912: add ebx, edi
         // 00401914: lea esi, ds:[ebx+esi+0xffffffff9bdc06a7]
         // 0040191b: add edx, esi
         // 0040191d: mov ss:[ebp+0xfffffffffffffffc], esi
         // 00401920: mov esi, ss:[ebp+0xffffffffffffffec]
         // 00401923: mov ebx, esi
         // 00401925: ror ebx, b1 0xd
         // 00401928: mov edi, esi
         // 0040192a: rol edi, b1 0xa
         // 0040192d: xor ebx, edi
         // 0040192f: mov edi, esi
         // 00401931: ror edi, b1 0x2
         // 00401934: xor ebx, edi
         // 00401936: add ebx, ss:[ebp+0xfffffffffffffffc]
         // 00401939: mov edi, ss:[ebp+0xfffffffffffffff0]
         // 0040193c: or edi, esi
         // 0040193e: and edi, ss:[ebp+0xfffffffffffffff4]
         // 00401941: mov ss:[ebp+0xfffffffffffffff8], edi
         // 00401944: mov edi, ss:[ebp+0xfffffffffffffff0]
         // 00401947: and edi, esi
         // 00401949: mov esi, ss:[ebp+0xfffffffffffffff8]
         // 0040194c: or esi, edi
         // 0040194e: add esi, ebx
         // 00401950: mov ss:[ebp+0xffffffffffffffe8], esi
         // 00401953: mov esi, edx
         // 00401955: ror esi, b1 0xb
         // 00401958: mov edi, edx
         // 0040195a: rol edi, b1 0x7
         // 0040195d: xor esi, edi
         // 0040195f: mov edi, edx
         // 00401961: ror edi, b1 0x6
         // 00401964: xor esi, edi
         // 00401966: add esi, ss:[ebp+0xffffffffffffffe0]
         // 00401969: mov edi, eax
         // 0040196b: xor edi, ecx
         // 0040196d: and edi, edx
         // 0040196f: xor edi, eax
         // 00401971: add edi, esi
         // 00401973: mov esi, ss:[ebp+0xffffffffffffff18]
         // 00401979: lea esi, ds:[edi+esi+0xffffffffc19bf174]
         // 00401980: add ss:[ebp+0xfffffffffffffff4], esi
         // 00401983: mov ss:[ebp+0xfffffffffffffffc], esi
         // 00401986: mov esi, ss:[ebp+0xffffffffffffffe8]
         // 00401989: mov ebx, esi
         // 0040198b: ror ebx, b1 0xd
         // 0040198e: mov edi, esi
         // 00401990: rol edi, b1 0xa
         // 00401993: xor ebx, edi
         // 00401995: mov edi, esi
         // 00401997: ror edi, b1 0x2
         // 0040199a: xor ebx, edi
         // 0040199c: add ebx, ss:[ebp+0xfffffffffffffffc]
         // 0040199f: mov edi, ss:[ebp+0xffffffffffffffec]
         // 004019a2: or edi, esi
         // 004019a4: and edi, ss:[ebp+0xfffffffffffffff0]
         // 004019a7: mov ss:[ebp+0xfffffffffffffff8], edi
         // 004019aa: mov edi, ss:[ebp+0xffffffffffffffec]
         // 004019ad: and edi, esi
         // 004019af: mov esi, ss:[ebp+0xfffffffffffffff8]
         // 004019b2: or esi, edi
         // 004019b4: add esi, ebx
         // 004019b6: mov ss:[ebp+0xffffffffffffffe0], esi
         // 004019b9: mov esi, ss:[ebp+0xffffffffffffff14]
         // 004019bf: mov ebx, esi
         // 004019c1: rol ebx, b1 0xf
         // 004019c4: mov edi, esi
         // 004019c6: rol edi, b1 0xd
         // 004019c9: xor ebx, edi
         // 004019cb: mov edi, ss:[ebp+0xfffffffffffffee0]
         // 004019d1: shr esi, b1 0xa
         // 004019d4: xor ebx, esi
         // 004019d6: add ebx, ss:[ebp+0xffffffffffffff00]
         // 004019dc: mov esi, edi
         // 004019de: rol esi, b1 0xe
         // 004019e1: ror edi, b1 0x7
         // 004019e4: xor esi, edi
         // 004019e6: mov edi, ss:[ebp+0xfffffffffffffee0]
         // 004019ec: shr edi, b1 0x3
         // 004019ef: xor esi, edi
         // 004019f1: add esi, ebx
         // 004019f3: add esi, ss:[ebp+0xfffffffffffffedc]
         // 004019f9: mov ss:[ebp+0xffffffffffffff1c], esi
         // 004019ff: mov esi, ss:[ebp+0xfffffffffffffff4]
         // 00401a02: mov edi, esi
         // 00401a04: ror edi, b1 0xb
         // 00401a07: mov ebx, esi
         // 00401a09: rol ebx, b1 0x7
         // 00401a0c: xor edi, ebx
         // 00401a0e: mov ebx, esi
         // 00401a10: ror ebx, b1 0x6
         // 00401a13: xor edi, ebx
         // 00401a15: mov ebx, ecx
         // 00401a17: add edi, ss:[ebp+0xffffffffffffff1c]
         // 00401a1d: xor ebx, edx
         // 00401a1f: and ebx, esi
         // 00401a21: mov esi, ss:[ebp+0xffffffffffffffe0]
         // 00401a24: xor ebx, ecx
         // 00401a26: add ebx, edi
         // 00401a28: lea eax, ds:[ebx+eax+0xffffffffe49b69c1]
         // 00401a2f: add ss:[ebp+0xfffffffffffffff0], eax
         // 00401a32: mov ss:[ebp+0xfffffffffffffffc], eax
         // 00401a35: mov ebx, ss:[ebp+0xffffffffffffffe8]
         // 00401a38: and ebx, esi
         // 00401a3a: mov edi, esi
         // 00401a3c: ror edi, b1 0xd
         // 00401a3f: mov eax, esi
         // 00401a41: rol eax, b1 0xa
         // 00401a44: xor edi, eax
         // 00401a46: mov eax, esi
         // 00401a48: ror eax, b1 0x2
         // 00401a4b: xor edi, eax
         // 00401a4d: add edi, ss:[ebp+0xfffffffffffffffc]
         // 00401a50: mov eax, ss:[ebp+0xffffffffffffffe8]
         // 00401a53: or eax, esi
         // 00401a55: and eax, ss:[ebp+0xffffffffffffffec]
         // 00401a58: or eax, ebx
         // 00401a5a: add eax, edi
         // 00401a5c: mov ss:[ebp+0xffffffffffffffe4], eax
         // 00401a5f: mov eax, ss:[ebp+0xffffffffffffff18]
         // 00401a65: mov ebx, eax
         // 00401a67: mov edi, eax
         // 00401a69: shr eax, b1 0xa
         // 00401a6c: rol ebx, b1 0xf
         // 00401a6f: rol edi, b1 0xd
         // 00401a72: xor ebx, edi
         // 00401a74: mov edi, ss:[ebp+0xfffffffffffffee4]
         // 00401a7a: xor ebx, eax
         // 00401a7c: add ebx, ss:[ebp+0xffffffffffffff04]
         // 00401a82: mov eax, edi
         // 00401a84: rol eax, b1 0xe
         // 00401a87: ror edi, b1 0x7
         // 00401a8a: xor eax, edi
         // 00401a8c: mov edi, ss:[ebp+0xfffffffffffffee4]
         // 00401a92: shr edi, b1 0x3
         // 00401a95: xor eax, edi
         // 00401a97: add eax, ebx
         // 00401a99: add eax, ss:[ebp+0xfffffffffffffee0]
         // 00401a9f: mov ss:[ebp+0xffffffffffffff20], eax
         // 00401aa5: mov eax, ss:[ebp+0xfffffffffffffff0]
         // 00401aa8: mov edi, eax
         // 00401aaa: mov ebx, eax
         // 00401aac: ror edi, b1 0xb
         // 00401aaf: rol ebx, b1 0x7
         // 00401ab2: xor edi, ebx
         // 00401ab4: ror eax, b1 0x6
         // 00401ab7: xor edi, eax
         // 00401ab9: add edi, ss:[ebp+0xffffffffffffff20]
         // 00401abf: mov eax, edx
         // 00401ac1: xor eax, ss:[ebp+0xfffffffffffffff4]
         // 00401ac4: and eax, ss:[ebp+0xfffffffffffffff0]
         // 00401ac7: xor eax, edx
         // 00401ac9: add eax, edi
         // 00401acb: mov edi, ss:[ebp+0xffffffffffffffe4]
         // 00401ace: lea ecx, ds:[eax+ecx+0xffffffffefbe4786]
         // 00401ad5: add ss:[ebp+0xffffffffffffffec], ecx
         // 00401ad8: mov ebx, edi
         // 00401ada: ror ebx, b1 0xd
         // 00401add: mov eax, edi
         // 00401adf: rol eax, b1 0xa
         // 00401ae2: xor ebx, eax
         // 00401ae4: mov eax, edi
         // 00401ae6: ror eax, b1 0x2
         // 00401ae9: xor ebx, eax
         // 00401aeb: mov eax, edi
         // 00401aed: or eax, esi
         // 00401aef: and eax, ss:[ebp+0xffffffffffffffe8]
         // 00401af2: and edi, esi
         // 00401af4: add ebx, ecx
         // 00401af6: mov ecx, ss:[ebp+0xffffffffffffff1c]
         // 00401afc: or eax, edi
         // 00401afe: add eax, ebx
         // 00401b00: mov ebx, ecx
         // 00401b02: rol ebx, b1 0xf
         // 00401b05: mov edi, ecx
         // 00401b07: rol edi, b1 0xd
         // 00401b0a: xor ebx, edi
         // 00401b0c: shr ecx, b1 0xa
         // 00401b0f: xor ebx, ecx
         // 00401b11: add ebx, ss:[ebp+0xffffffffffffff08]
         // 00401b17: mov edi, ss:[ebp+0xfffffffffffffee8]
         // 00401b1d: mov ecx, edi
         // 00401b1f: rol ecx, b1 0xe
         // 00401b22: ror edi, b1 0x7
         // 00401b25: xor ecx, edi
         // 00401b27: mov edi, ss:[ebp+0xfffffffffffffee8]
         // 00401b2d: shr edi, b1 0x3
         // 00401b30: xor ecx, edi
         // 00401b32: add ecx, ebx
         // 00401b34: add ecx, ss:[ebp+0xfffffffffffffee4]
         // 00401b3a: mov ss:[ebp+0xffffffffffffff24], ecx
         // 00401b40: mov ecx, ss:[ebp+0xffffffffffffffec]
         // 00401b43: mov edi, ecx
         // 00401b45: ror edi, b1 0xb
         // 00401b48: mov ebx, ecx
         // 00401b4a: rol ebx, b1 0x7
         // 00401b4d: xor edi, ebx
         // 00401b4f: ror ecx, b1 0x6
         // 00401b52: xor edi, ecx
         // 00401b54: add edi, ss:[ebp+0xffffffffffffff24]
         // 00401b5a: mov ecx, ss:[ebp+0xfffffffffffffff4]
         // 00401b5d: xor ecx, ss:[ebp+0xfffffffffffffff0]
         // 00401b60: mov ebx, eax
         // 00401b62: and ecx, ss:[ebp+0xffffffffffffffec]
         // 00401b65: xor ecx, ss:[ebp+0xfffffffffffffff4]
         // 00401b68: add ecx, edi
         // 00401b6a: lea edx, ds:[ecx+edx+0xfc19dc6]
         // 00401b71: add ss:[ebp+0xffffffffffffffe8], edx
         // 00401b74: mov edi, ss:[ebp+0xffffffffffffffe4]
         // 00401b77: ror ebx, b1 0xd
         // 00401b7a: mov ecx, eax
         // 00401b7c: rol ecx, b1 0xa
         // 00401b7f: xor ebx, ecx
         // 00401b81: mov ecx, eax
         // 00401b83: ror ecx, b1 0x2
         // 00401b86: xor ebx, ecx
         // 00401b88: add ebx, edx
         // 00401b8a: mov edx, ss:[ebp+0xffffffffffffff20]
         // 00401b90: mov ecx, edi
         // 00401b92: and edi, eax
         // 00401b94: or ecx, eax
         // 00401b96: and ecx, esi
         // 00401b98: or ecx, edi
         // 00401b9a: add ecx, ebx
         // 00401b9c: mov ebx, edx
         // 00401b9e: mov edi, edx
         // 00401ba0: shr edx, b1 0xa
         // 00401ba3: rol ebx, b1 0xf
         // 00401ba6: rol edi, b1 0xd
         // 00401ba9: xor ebx, edi
         // 00401bab: mov edi, ss:[ebp+0xfffffffffffffeec]
         // 00401bb1: xor ebx, edx
         // 00401bb3: add ebx, ss:[ebp+0xffffffffffffff0c]
         // 00401bb9: mov edx, edi
         // 00401bbb: rol edx, b1 0xe
         // 00401bbe: ror edi, b1 0x7
         // 00401bc1: xor edx, edi
         // 00401bc3: mov edi, ss:[ebp+0xfffffffffffffeec]
         // 00401bc9: shr edi, b1 0x3
         // 00401bcc: xor edx, edi
         // 00401bce: add edx, ebx
         // 00401bd0: add edx, ss:[ebp+0xfffffffffffffee8]
         // 00401bd6: mov ss:[ebp+0xffffffffffffff28], edx
         // 00401bdc: mov edx, ss:[ebp+0xffffffffffffffe8]
         // 00401bdf: mov edi, edx
         // 00401be1: mov ebx, edx
         // 00401be3: ror edi, b1 0xb
         // 00401be6: rol ebx, b1 0x7
         // 00401be9: xor edi, ebx
         // 00401beb: ror edx, b1 0x6
         // 00401bee: xor edi, edx
         // 00401bf0: mov edx, ss:[ebp+0xfffffffffffffff0]
         // 00401bf3: xor edx, ss:[ebp+0xffffffffffffffec]
         // 00401bf6: and edx, ss:[ebp+0xffffffffffffffe8]
         // 00401bf9: xor edx, ss:[ebp+0xfffffffffffffff0]
         // 00401bfc: add edi, ss:[ebp+0xffffffffffffff28]
         // 00401c02: mov ebx, eax
         // 00401c04: add edx, edi
         // 00401c06: mov edi, ss:[ebp+0xfffffffffffffff4]
         // 00401c09: lea edx, ds:[edx+edi+0x240ca1cc]
         // 00401c10: add esi, edx
         // 00401c12: mov ss:[ebp+0xfffffffffffffffc], edx
         // 00401c15: and ebx, ecx
         // 00401c17: mov edi, ecx
         // 00401c19: ror edi, b1 0xd
         // 00401c1c: mov edx, ecx
         // 00401c1e: rol edx, b1 0xa
         // 00401c21: xor edi, edx
         // 00401c23: mov edx, ecx
         // 00401c25: ror edx, b1 0x2
         // 00401c28: xor edi, edx
         // 00401c2a: add edi, ss:[ebp+0xfffffffffffffffc]
         // 00401c2d: mov edx, eax
         // 00401c2f: or edx, ecx
         // 00401c31: and edx, ss:[ebp+0xffffffffffffffe4]
         // 00401c34: or edx, ebx
         // 00401c36: add edx, edi
         // 00401c38: mov ss:[ebp+0xfffffffffffffff4], edx
         // 00401c3b: mov edx, ss:[ebp+0xffffffffffffff24]
         // 00401c41: mov ebx, edx
         // 00401c43: mov edi, edx
         // 00401c45: shr edx, b1 0xa
         // 00401c48: rol ebx, b1 0xf
         // 00401c4b: rol edi, b1 0xd
         // 00401c4e: xor ebx, edi
         // 00401c50: mov edi, ss:[ebp+0xfffffffffffffef0]
         // 00401c56: xor ebx, edx
         // 00401c58: add ebx, ss:[ebp+0xffffffffffffff10]
         // 00401c5e: mov edx, edi
         // 00401c60: rol edx, b1 0xe
         // 00401c63: ror edi, b1 0x7
         // 00401c66: xor edx, edi
         // 00401c68: mov edi, ss:[ebp+0xfffffffffffffef0]
         // 00401c6e: shr edi, b1 0x3
         // 00401c71: xor edx, edi
         // 00401c73: add edx, ebx
         // 00401c75: add edx, ss:[ebp+0xfffffffffffffeec]
         // 00401c7b: mov edi, esi
         // 00401c7d: mov ss:[ebp+0xffffffffffffff2c], edx
         // 00401c83: mov edx, esi
         // 00401c85: ror edx, b1 0xb
         // 00401c88: rol edi, b1 0x7
         // 00401c8b: xor edx, edi
         // 00401c8d: mov edi, esi
         // 00401c8f: ror edi, b1 0x6
         // 00401c92: xor edx, edi
         // 00401c94: add edx, ss:[ebp+0xffffffffffffff2c]
         // 00401c9a: mov edi, ss:[ebp+0xffffffffffffffec]
         // 00401c9d: xor edi, ss:[ebp+0xffffffffffffffe8]
         // 00401ca0: and edi, esi
         // 00401ca2: xor edi, ss:[ebp+0xffffffffffffffec]
         // 00401ca5: add edi, edx
         // 00401ca7: mov edx, ss:[ebp+0xfffffffffffffff0]
         // 00401caa: lea edx, ds:[edi+edx+0x2de92c6f]
         // 00401cb1: add ss:[ebp+0xffffffffffffffe4], edx
         // 00401cb4: mov ss:[ebp+0xfffffffffffffffc], edx
         // 00401cb7: mov edx, ss:[ebp+0xfffffffffffffff4]
         // 00401cba: mov ebx, edx
         // 00401cbc: ror ebx, b1 0xd
         // 00401cbf: mov edi, edx
         // 00401cc1: rol edi, b1 0xa
         // 00401cc4: xor ebx, edi
         // 00401cc6: mov edi, edx
         // 00401cc8: ror edi, b1 0x2
         // 00401ccb: xor ebx, edi
         // 00401ccd: add ebx, ss:[ebp+0xfffffffffffffffc]
         // 00401cd0: mov edi, ecx
         // 00401cd2: or edi, edx
         // 00401cd4: and edi, eax
         // 00401cd6: mov ss:[ebp+0xfffffffffffffff8], edi
         // 00401cd9: mov edi, ecx
         // 00401cdb: and edi, edx
         // 00401cdd: mov edx, ss:[ebp+0xfffffffffffffff8]
         // 00401ce0: or edx, edi
         // 00401ce2: add edx, ebx
         // 00401ce4: mov ss:[ebp+0xfffffffffffffff0], edx
         // 00401ce7: mov edx, ss:[ebp+0xffffffffffffff28]
         // 00401ced: mov ebx, edx
         // 00401cef: rol ebx, b1 0xf
         // 00401cf2: mov edi, edx
         // 00401cf4: rol edi, b1 0xd
         // 00401cf7: xor ebx, edi
         // 00401cf9: shr edx, b1 0xa
         // 00401cfc: xor ebx, edx
         // 00401cfe: add ebx, ss:[ebp+0xffffffffffffff14]
         // 00401d04: mov edi, ss:[ebp+0xfffffffffffffef4]
         // 00401d0a: mov edx, edi
         // 00401d0c: rol edx, b1 0xe
         // 00401d0f: ror edi, b1 0x7
         // 00401d12: xor edx, edi
         // 00401d14: mov edi, ss:[ebp+0xfffffffffffffef4]
         // 00401d1a: shr edi, b1 0x3
         // 00401d1d: xor edx, edi
         // 00401d1f: add edx, ebx
         // 00401d21: add edx, ss:[ebp+0xfffffffffffffef0]
         // 00401d27: mov ss:[ebp+0xffffffffffffff30], edx
         // 00401d2d: mov edx, ss:[ebp+0xffffffffffffffe4]
         // 00401d30: mov edi, edx
         // 00401d32: ror edi, b1 0xb
         // 00401d35: mov ebx, edx
         // 00401d37: rol ebx, b1 0x7
         // 00401d3a: xor edi, ebx
         // 00401d3c: mov ebx, edx
         // 00401d3e: ror ebx, b1 0x6
         // 00401d41: xor edi, ebx
         // 00401d43: add edi, ss:[ebp+0xffffffffffffff30]
         // 00401d49: mov ebx, ss:[ebp+0xffffffffffffffe8]
         // 00401d4c: xor ebx, esi
         // 00401d4e: and ebx, edx
         // 00401d50: xor ebx, ss:[ebp+0xffffffffffffffe8]
         // 00401d53: mov edx, ss:[ebp+0xffffffffffffffec]
         // 00401d56: add ebx, edi
         // 00401d58: lea edx, ds:[ebx+edx+0x4a7484aa]
         // 00401d5f: add eax, edx
         // 00401d61: mov ss:[ebp+0xfffffffffffffffc], edx
         // 00401d64: mov edx, ss:[ebp+0xfffffffffffffff0]
         // 00401d67: mov ebx, edx
         // 00401d69: ror ebx, b1 0xd
         // 00401d6c: mov edi, edx
         // 00401d6e: rol edi, b1 0xa
         // 00401d71: xor ebx, edi
         // 00401d73: mov edi, edx
         // 00401d75: ror edi, b1 0x2
         // 00401d78: xor ebx, edi
         // 00401d7a: mov edi, ss:[ebp+0xfffffffffffffff4]
         // 00401d7d: add ebx, ss:[ebp+0xfffffffffffffffc]
         // 00401d80: or edi, edx
         // 00401d82: and edi, ecx
         // 00401d84: mov ss:[ebp+0xfffffffffffffff8], edi
         // 00401d87: mov edi, ss:[ebp+0xfffffffffffffff4]
         // 00401d8a: and edi, edx
         // 00401d8c: mov edx, ss:[ebp+0xfffffffffffffff8]
         // 00401d8f: or edx, edi
         // 00401d91: add edx, ebx
         // 00401d93: mov ss:[ebp+0xffffffffffffffec], edx
         // 00401d96: mov edx, ss:[ebp+0xffffffffffffff2c]
         // 00401d9c: mov ebx, edx
         // 00401d9e: mov edi, edx
         // 00401da0: rol ebx, b1 0xf
         // 00401da3: rol edi, b1 0xd
         // 00401da6: xor ebx, edi
         // 00401da8: mov edi, ss:[ebp+0xfffffffffffffef8]
         // 00401dae: shr edx, b1 0xa
         // 00401db1: xor ebx, edx
         // 00401db3: add ebx, ss:[ebp+0xffffffffffffff18]
         // 00401db9: mov edx, edi
         // 00401dbb: rol edx, b1 0xe
         // 00401dbe: ror edi, b1 0x7
         // 00401dc1: xor edx, edi
         // 00401dc3: mov edi, ss:[ebp+0xfffffffffffffef8]
         // 00401dc9: shr edi, b1 0x3
         // 00401dcc: xor edx, edi
         // 00401dce: add edx, ebx
         // 00401dd0: add edx, ss:[ebp+0xfffffffffffffef4]
         // 00401dd6: mov edi, eax
         // 00401dd8: mov ss:[ebp+0xffffffffffffff34], edx
         // 00401dde: ror edi, b1 0xb
         // 00401de1: mov ebx, eax
         // 00401de3: rol ebx, b1 0x7
         // 00401de6: xor edi, ebx
         // 00401de8: mov ebx, eax
         // 00401dea: ror ebx, b1 0x6
         // 00401ded: xor edi, ebx
         // 00401def: add edi, edx
         // 00401df1: mov ebx, ss:[ebp+0xffffffffffffffe4]
         // 00401df4: xor ebx, esi
         // 00401df6: mov edx, ss:[ebp+0xffffffffffffffe8]
         // 00401df9: and ebx, eax
         // 00401dfb: xor ebx, esi
         // 00401dfd: add ebx, edi
         // 00401dff: lea edx, ds:[ebx+edx+0x5cb0a9dc]
         // 00401e06: add ecx, edx
         // 00401e08: mov ss:[ebp+0xfffffffffffffffc], edx
         // 00401e0b: mov edx, ss:[ebp+0xffffffffffffffec]
         // 00401e0e: mov ebx, edx
         // 00401e10: ror ebx, b1 0xd
         // 00401e13: mov edi, edx
         // 00401e15: rol edi, b1 0xa
         // 00401e18: xor ebx, edi
         // 00401e1a: mov edi, edx
         // 00401e1c: ror edi, b1 0x2
         // 00401e1f: xor ebx, edi
         // 00401e21: add ebx, ss:[ebp+0xfffffffffffffffc]
         // 00401e24: mov edi, ss:[ebp+0xfffffffffffffff0]
         // 00401e27: or edi, edx
         // 00401e29: and edi, ss:[ebp+0xfffffffffffffff4]
         // 00401e2c: mov ss:[ebp+0xfffffffffffffff8], edi
         // 00401e2f: mov edi, ss:[ebp+0xfffffffffffffff0]
         // 00401e32: and edi, edx
         // 00401e34: mov edx, ss:[ebp+0xfffffffffffffff8]
         // 00401e37: or edx, edi
         // 00401e39: add edx, ebx
         // 00401e3b: mov ss:[ebp+0xffffffffffffffe8], edx
         // 00401e3e: mov edx, ss:[ebp+0xffffffffffffff30]
         // 00401e44: mov ebx, edx
         // 00401e46: rol ebx, b1 0xf
         // 00401e49: mov edi, edx
         // 00401e4b: rol edi, b1 0xd
         // 00401e4e: xor ebx, edi
         // 00401e50: mov edi, ss:[ebp+0xfffffffffffffefc]
         // 00401e56: shr edx, b1 0xa
         // 00401e59: xor ebx, edx
         // 00401e5b: add ebx, ss:[ebp+0xffffffffffffff1c]
         // 00401e61: mov edx, edi
         // 00401e63: rol edx, b1 0xe
         // 00401e66: ror edi, b1 0x7
         // 00401e69: xor edx, edi
         // 00401e6b: mov edi, ss:[ebp+0xfffffffffffffefc]
         // 00401e71: shr edi, b1 0x3
         // 00401e74: xor edx, edi
         // 00401e76: add edx, ebx
         // 00401e78: add edx, ss:[ebp+0xfffffffffffffef8]
         // 00401e7e: mov edi, ecx
         // 00401e80: mov ss:[ebp+0xffffffffffffff38], edx
         // 00401e86: ror edi, b1 0xb
         // 00401e89: mov edx, ecx
         // 00401e8b: rol edx, b1 0x7
         // 00401e8e: xor edi, edx
         // 00401e90: mov edx, ecx
         // 00401e92: ror edx, b1 0x6
         // 00401e95: xor edi, edx
         // 00401e97: mov edx, ss:[ebp+0xffffffffffffffe4]
         // 00401e9a: add edi, ss:[ebp+0xffffffffffffff38]
         // 00401ea0: mov ebx, edx
         // 00401ea2: xor ebx, eax
         // 00401ea4: and ebx, ecx
         // 00401ea6: xor ebx, edx
         // 00401ea8: mov edx, ss:[ebp+0xffffffffffffffe8]
         // 00401eab: add ebx, edi
         // 00401ead: lea esi, ds:[ebx+esi+0x76f988da]
         // 00401eb4: add ss:[ebp+0xfffffffffffffff4], esi
         // 00401eb7: mov ss:[ebp+0xfffffffffffffffc], esi
         // 00401eba: mov edi, edx
         // 00401ebc: ror edi, b1 0xd
         // 00401ebf: mov esi, edx
         // 00401ec1: rol esi, b1 0xa
         // 00401ec4: xor edi, esi
         // 00401ec6: mov esi, edx
         // 00401ec8: ror esi, b1 0x2
         // 00401ecb: xor edi, esi
         // 00401ecd: add edi, ss:[ebp+0xfffffffffffffffc]
         // 00401ed0: mov esi, ss:[ebp+0xffffffffffffffec]
         // 00401ed3: or esi, edx
         // 00401ed5: and esi, ss:[ebp+0xfffffffffffffff0]
         // 00401ed8: mov ebx, ss:[ebp+0xffffffffffffffec]
         // 00401edb: and ebx, edx
         // 00401edd: or esi, ebx
         // 00401edf: add esi, edi
         // 00401ee1: mov ss:[ebp+0xffffffffffffffe0], esi
         // 00401ee4: mov esi, ss:[ebp+0xffffffffffffff34]
         // 00401eea: mov ebx, esi
         // 00401eec: rol ebx, b1 0xf
         // 00401eef: mov edi, esi
         // 00401ef1: rol edi, b1 0xd
         // 00401ef4: xor ebx, edi
         // 00401ef6: mov edi, ss:[ebp+0xffffffffffffff00]
         // 00401efc: shr esi, b1 0xa
         // 00401eff: xor ebx, esi
         // 00401f01: add ebx, ss:[ebp+0xffffffffffffff20]
         // 00401f07: mov esi, edi
         // 00401f09: rol esi, b1 0xe
         // 00401f0c: ror edi, b1 0x7
         // 00401f0f: xor esi, edi
         // 00401f11: mov edi, ss:[ebp+0xffffffffffffff00]
         // 00401f17: shr edi, b1 0x3
         // 00401f1a: xor esi, edi
         // 00401f1c: add esi, ebx
         // 00401f1e: add esi, ss:[ebp+0xfffffffffffffefc]
         // 00401f24: mov ss:[ebp+0xffffffffffffff3c], esi
         // 00401f2a: mov esi, ss:[ebp+0xfffffffffffffff4]
         // 00401f2d: mov edi, esi
         // 00401f2f: ror edi, b1 0xb
         // 00401f32: mov ebx, esi
         // 00401f34: rol ebx, b1 0x7
         // 00401f37: xor edi, ebx
         // 00401f39: mov ebx, esi
         // 00401f3b: ror ebx, b1 0x6
         // 00401f3e: xor edi, ebx
         // 00401f40: add edi, ss:[ebp+0xffffffffffffff3c]
         // 00401f46: mov ebx, eax
         // 00401f48: xor ebx, ecx
         // 00401f4a: and ebx, esi
         // 00401f4c: mov esi, ss:[ebp+0xffffffffffffffe4]
         // 00401f4f: xor ebx, eax
         // 00401f51: add ebx, edi
         // 00401f53: lea esi, ds:[ebx+esi+0xffffffff983e5152]
         // 00401f5a: add ss:[ebp+0xfffffffffffffff0], esi
         // 00401f5d: mov ss:[ebp+0xfffffffffffffffc], esi
         // 00401f60: mov esi, ss:[ebp+0xffffffffffffffe0]
         // 00401f63: mov ebx, esi
         // 00401f65: ror ebx, b1 0xd
         // 00401f68: mov edi, esi
         // 00401f6a: rol edi, b1 0xa
         // 00401f6d: xor ebx, edi
         // 00401f6f: mov edi, esi
         // 00401f71: ror edi, b1 0x2
         // 00401f74: xor ebx, edi
         // 00401f76: add ebx, ss:[ebp+0xfffffffffffffffc]
         // 00401f79: mov edi, edx
         // 00401f7b: or edi, esi
         // 00401f7d: and edi, ss:[ebp+0xffffffffffffffec]
         // 00401f80: mov ss:[ebp+0xfffffffffffffff8], edi
         // 00401f83: mov edi, edx
         // 00401f85: and edi, esi
         // 00401f87: mov esi, ss:[ebp+0xfffffffffffffff8]
         // 00401f8a: or esi, edi
         // 00401f8c: add esi, ebx
         // 00401f8e: mov ss:[ebp+0xffffffffffffffe4], esi
         // 00401f91: mov esi, ss:[ebp+0xffffffffffffff38]
         // 00401f97: mov ebx, esi
         // 00401f99: mov edi, esi
         // 00401f9b: rol ebx, b1 0xf
         // 00401f9e: rol edi, b1 0xd
         // 00401fa1: xor ebx, edi
         // 00401fa3: mov edi, ss:[ebp+0xffffffffffffff04]
         // 00401fa9: shr esi, b1 0xa
         // 00401fac: xor ebx, esi
         // 00401fae: mov esi, edi
         // 00401fb0: rol esi, b1 0xe
         // 00401fb3: add ebx, ss:[ebp+0xffffffffffffff24]
         // 00401fb9: ror edi, b1 0x7
         // 00401fbc: xor esi, edi
         // 00401fbe: mov edi, ss:[ebp+0xffffffffffffff04]
         // 00401fc4: shr edi, b1 0x3
         // 00401fc7: xor esi, edi
         // 00401fc9: add esi, ebx
         // 00401fcb: add esi, ss:[ebp+0xffffffffffffff00]
         // 00401fd1: mov ss:[ebp+0xffffffffffffff40], esi
         // 00401fd7: mov esi, ss:[ebp+0xfffffffffffffff0]
         // 00401fda: mov edi, esi
         // 00401fdc: ror edi, b1 0xb
         // 00401fdf: mov ebx, esi
         // 00401fe1: rol ebx, b1 0x7
         // 00401fe4: xor edi, ebx
         // 00401fe6: ror esi, b1 0x6
         // 00401fe9: xor edi, esi
         // 00401feb: add edi, ss:[ebp+0xffffffffffffff40]
         // 00401ff1: mov esi, ecx
         // 00401ff3: xor esi, ss:[ebp+0xfffffffffffffff4]
         // 00401ff6: and esi, ss:[ebp+0xfffffffffffffff0]
         // 00401ff9: xor esi, ecx
         // 00401ffb: add esi, edi
         // 00401ffd: lea eax, ds:[esi+eax+0xffffffffa831c66d]
         // 00402004: add ss:[ebp+0xffffffffffffffec], eax
         // 00402007: mov esi, ss:[ebp+0xffffffffffffffe4]
         // 0040200a: mov ss:[ebp+0xfffffffffffffffc], eax
         // 0040200d: mov edi, ss:[ebp+0xffffffffffffffe0]
         // 00402010: mov ebx, esi
         // 00402012: ror ebx, b1 0xd
         // 00402015: mov eax, esi
         // 00402017: rol eax, b1 0xa
         // 0040201a: xor ebx, eax
         // 0040201c: mov eax, esi
         // 0040201e: ror eax, b1 0x2
         // 00402021: xor ebx, eax
         // 00402023: add ebx, ss:[ebp+0xfffffffffffffffc]
         // 00402026: mov eax, esi
         // 00402028: or eax, edi
         // 0040202a: and eax, edx
         // 0040202c: mov ss:[ebp+0xfffffffffffffff8], eax
         // 0040202f: mov eax, esi
         // 00402031: and eax, edi
         // 00402033: mov ss:[ebp+0xffffffffffffffe4], eax
         // 00402036: mov eax, ss:[ebp+0xfffffffffffffff8]
         // 00402039: or eax, ss:[ebp+0xffffffffffffffe4]
         // 0040203c: add eax, ebx
         // 0040203e: mov ss:[ebp+0xfffffffffffffff8], eax
         // 00402041: mov eax, ss:[ebp+0xffffffffffffff3c]
         // 00402047: mov ebx, eax
         // 00402049: mov edi, eax
         // 0040204b: shr eax, b1 0xa
         // 0040204e: rol ebx, b1 0xf
         // 00402051: rol edi, b1 0xd
         // 00402054: xor ebx, edi
         // 00402056: mov edi, ss:[ebp+0xffffffffffffff08]
         // 0040205c: xor ebx, eax
         // 0040205e: add ebx, ss:[ebp+0xffffffffffffff28]
         // 00402064: mov eax, edi
         // 00402066: rol eax, b1 0xe
         // 00402069: ror edi, b1 0x7
         // 0040206c: xor eax, edi
         // 0040206e: mov edi, ss:[ebp+0xffffffffffffff08]
         // 00402074: shr edi, b1 0x3
         // 00402077: xor eax, edi
         // 00402079: add eax, ebx
         // 0040207b: add eax, ss:[ebp+0xffffffffffffff04]
         // 00402081: mov ss:[ebp+0xffffffffffffff44], eax
         // 00402087: mov eax, ss:[ebp+0xffffffffffffffec]
         // 0040208a: mov edi, eax
         // 0040208c: mov ebx, eax
         // 0040208e: ror edi, b1 0xb
         // 00402091: rol ebx, b1 0x7
         // 00402094: xor edi, ebx
         // 00402096: ror eax, b1 0x6
         // 00402099: xor edi, eax
         // 0040209b: mov eax, ss:[ebp+0xfffffffffffffff4]
         // 0040209e: xor eax, ss:[ebp+0xfffffffffffffff0]
         // 004020a1: and eax, ss:[ebp+0xffffffffffffffec]
         // 004020a4: xor eax, ss:[ebp+0xfffffffffffffff4]
         // 004020a7: add edi, ss:[ebp+0xffffffffffffff44]
         // 004020ad: add eax, edi
         // 004020af: lea ecx, ds:[eax+ecx+0xffffffffb00327c8]
         // 004020b6: mov eax, ss:[ebp+0xfffffffffffffff8]
         // 004020b9: add edx, ecx
         // 004020bb: mov ss:[ebp+0xfffffffffffffffc], ecx
         // 004020be: mov edi, eax
         // 004020c0: ror edi, b1 0xd
         // 004020c3: mov ecx, eax
         // 004020c5: rol ecx, b1 0xa
         // 004020c8: xor edi, ecx
         // 004020ca: mov ecx, eax
         // 004020cc: ror ecx, b1 0x2
         // 004020cf: xor edi, ecx
         // 004020d1: add edi, ss:[ebp+0xfffffffffffffffc]
         // 004020d4: mov ecx, esi
         // 004020d6: or ecx, eax
         // 004020d8: and ecx, ss:[ebp+0xffffffffffffffe0]
         // 004020db: mov ebx, esi
         // 004020dd: and ebx, eax
         // 004020df: or ecx, ebx
         // 004020e1: add ecx, edi
         // 004020e3: mov ss:[ebp+0xffffffffffffffdc], ecx
         // 004020e6: mov ecx, ss:[ebp+0xffffffffffffff40]
         // 004020ec: mov ebx, ecx
         // 004020ee: mov edi, ecx
         // 004020f0: shr ecx, b1 0xa
         // 004020f3: rol ebx, b1 0xf
         // 004020f6: rol edi, b1 0xd
         // 004020f9: xor ebx, edi
         // 004020fb: mov edi, ss:[ebp+0xffffffffffffff0c]
         // 00402101: xor ebx, ecx
         // 00402103: add ebx, ss:[ebp+0xffffffffffffff2c]
         // 00402109: mov ecx, edi
         // 0040210b: rol ecx, b1 0xe
         // 0040210e: ror edi, b1 0x7
         // 00402111: xor ecx, edi
         // 00402113: mov edi, ss:[ebp+0xffffffffffffff0c]
         // 00402119: shr edi, b1 0x3
         // 0040211c: xor ecx, edi
         // 0040211e: add ecx, ebx
         // 00402120: add ecx, ss:[ebp+0xffffffffffffff08]
         // 00402126: mov edi, edx
         // 00402128: mov ss:[ebp+0xffffffffffffff48], ecx
         // 0040212e: mov ecx, edx
         // 00402130: ror ecx, b1 0xb
         // 00402133: rol edi, b1 0x7
         // 00402136: xor ecx, edi
         // 00402138: mov edi, edx
         // 0040213a: ror edi, b1 0x6
         // 0040213d: xor ecx, edi
         // 0040213f: add ecx, ss:[ebp+0xffffffffffffff48]
         // 00402145: mov edi, ss:[ebp+0xfffffffffffffff0]
         // 00402148: xor edi, ss:[ebp+0xffffffffffffffec]
         // 0040214b: and edi, edx
         // 0040214d: xor edi, ss:[ebp+0xfffffffffffffff0]
         // 00402150: add edi, ecx
         // 00402152: mov ecx, ss:[ebp+0xfffffffffffffff4]
         // 00402155: lea ecx, ds:[edi+ecx+0xffffffffbf597fc7]
         // 0040215c: add ss:[ebp+0xffffffffffffffe0], ecx
         // 0040215f: mov ss:[ebp+0xfffffffffffffffc], ecx
         // 00402162: mov ecx, ss:[ebp+0xffffffffffffffdc]
         // 00402165: mov ebx, ecx
         // 00402167: ror ebx, b1 0xd
         // 0040216a: mov edi, ecx
         // 0040216c: rol edi, b1 0xa
         // 0040216f: xor ebx, edi
         // 00402171: mov edi, ecx
         // 00402173: ror edi, b1 0x2
         // 00402176: xor ebx, edi
         // 00402178: add ebx, ss:[ebp+0xfffffffffffffffc]
         // 0040217b: mov edi, eax
         // 0040217d: or edi, ecx
         // 0040217f: and edi, esi
         // 00402181: mov ss:[ebp+0xfffffffffffffff8], edi
         // 00402184: mov edi, eax
         // 00402186: and edi, ecx
         // 00402188: mov ecx, ss:[ebp+0xfffffffffffffff8]
         // 0040218b: or ecx, edi
         // 0040218d: add ecx, ebx
         // 0040218f: mov ss:[ebp+0xfffffffffffffff4], ecx
         // 00402192: mov ecx, ss:[ebp+0xffffffffffffff44]
         // 00402198: mov ebx, ecx
         // 0040219a: rol ebx, b1 0xf
         // 0040219d: mov edi, ecx
         // 0040219f: rol edi, b1 0xd
         // 004021a2: xor ebx, edi
         // 004021a4: shr ecx, b1 0xa
         // 004021a7: xor ebx, ecx
         // 004021a9: add ebx, ss:[ebp+0xffffffffffffff30]
         // 004021af: mov edi, ss:[ebp+0xffffffffffffff10]
         // 004021b5: mov ecx, edi
         // 004021b7: rol ecx, b1 0xe
         // 004021ba: ror edi, b1 0x7
         // 004021bd: xor ecx, edi
         // 004021bf: mov edi, ss:[ebp+0xffffffffffffff10]
         // 004021c5: shr edi, b1 0x3
         // 004021c8: xor ecx, edi
         // 004021ca: add ecx, ebx
         // 004021cc: add ecx, ss:[ebp+0xffffffffffffff0c]
         // 004021d2: mov ss:[ebp+0xffffffffffffff4c], ecx
         // 004021d8: mov ecx, ss:[ebp+0xffffffffffffffe0]
         // 004021db: mov edi, ecx
         // 004021dd: ror edi, b1 0xb
         // 004021e0: mov ebx, ecx
         // 004021e2: rol ebx, b1 0x7
         // 004021e5: xor edi, ebx
         // 004021e7: mov ebx, ecx
         // 004021e9: ror ebx, b1 0x6
         // 004021ec: xor edi, ebx
         // 004021ee: add edi, ss:[ebp+0xffffffffffffff4c]
         // 004021f4: mov ebx, ss:[ebp+0xffffffffffffffec]
         // 004021f7: xor ebx, edx
         // 004021f9: and ebx, ecx
         // 004021fb: xor ebx, ss:[ebp+0xffffffffffffffec]
         // 004021fe: mov ecx, ss:[ebp+0xfffffffffffffff0]
         // 00402201: add ebx, edi
         // 00402203: lea ecx, ds:[ebx+ecx+0xffffffffc6e00bf3]
         // 0040220a: add esi, ecx
         // 0040220c: mov ss:[ebp+0xfffffffffffffffc], ecx
         // 0040220f: mov ecx, ss:[ebp+0xfffffffffffffff4]
         // 00402212: mov ebx, ecx
         // 00402214: mov edi, ecx
         // 00402216: ror ebx, b1 0xd
         // 00402219: rol edi, b1 0xa
         // 0040221c: xor ebx, edi
         // 0040221e: mov edi, ecx
         // 00402220: ror edi, b1 0x2
         // 00402223: xor ebx, edi
         // 00402225: mov edi, ss:[ebp+0xffffffffffffffdc]
         // 00402228: add ebx, ss:[ebp+0xfffffffffffffffc]
         // 0040222b: or edi, ecx
         // 0040222d: and edi, eax
         // 0040222f: mov ss:[ebp+0xfffffffffffffff8], edi
         // 00402232: mov edi, ss:[ebp+0xffffffffffffffdc]
         // 00402235: and edi, ecx
         // 00402237: mov ecx, ss:[ebp+0xfffffffffffffff8]
         // 0040223a: or ecx, edi
         // 0040223c: add ecx, ebx
         // 0040223e: mov ss:[ebp+0xfffffffffffffff0], ecx
         // 00402241: mov ecx, ss:[ebp+0xffffffffffffff48]
         // 00402247: mov ebx, ecx
         // 00402249: mov edi, ecx
         // 0040224b: rol ebx, b1 0xf
         // 0040224e: rol edi, b1 0xd
         // 00402251: shr ecx, b1 0xa
         // 00402254: xor ebx, edi
         // 00402256: mov edi, ss:[ebp+0xffffffffffffff14]
         // 0040225c: xor ebx, ecx
         // 0040225e: add ebx, ss:[ebp+0xffffffffffffff34]
         // 00402264: mov ecx, edi
         // 00402266: rol ecx, b1 0xe
         // 00402269: ror edi, b1 0x7
         // 0040226c: xor ecx, edi
         // 0040226e: mov edi, ss:[ebp+0xffffffffffffff14]
         // 00402274: shr edi, b1 0x3
         // 00402277: xor ecx, edi
         // 00402279: add ecx, ebx
         // 0040227b: add ecx, ss:[ebp+0xffffffffffffff10]
         // 00402281: mov edi, esi
         // 00402283: mov ss:[ebp+0xffffffffffffff50], ecx
         // 00402289: mov ecx, esi
         // 0040228b: ror ecx, b1 0xb
         // 0040228e: rol edi, b1 0x7
         // 00402291: xor ecx, edi
         // 00402293: mov edi, esi
         // 00402295: ror edi, b1 0x6
         // 00402298: xor ecx, edi
         // 0040229a: add ecx, ss:[ebp+0xffffffffffffff50]
         // 004022a0: mov edi, edx
         // 004022a2: xor edi, ss:[ebp+0xffffffffffffffe0]
         // 004022a5: and edi, esi
         // 004022a7: xor edi, edx
         // 004022a9: add edi, ecx
         // 004022ab: mov ecx, ss:[ebp+0xffffffffffffffec]
         // 004022ae: lea ecx, ds:[edi+ecx+0xffffffffd5a79147]
         // 004022b5: add eax, ecx
         // 004022b7: mov ss:[ebp+0xfffffffffffffffc], ecx
         // 004022ba: mov ecx, ss:[ebp+0xfffffffffffffff0]
         // 004022bd: mov ebx, ecx
         // 004022bf: ror ebx, b1 0xd
         // 004022c2: mov edi, ecx
         // 004022c4: rol edi, b1 0xa
         // 004022c7: xor ebx, edi
         // 004022c9: mov edi, ecx
         // 004022cb: ror edi, b1 0x2
         // 004022ce: xor ebx, edi
         // 004022d0: add ebx, ss:[ebp+0xfffffffffffffffc]
         // 004022d3: mov edi, ss:[ebp+0xfffffffffffffff4]
         // 004022d6: or edi, ecx
         // 004022d8: and edi, ss:[ebp+0xffffffffffffffdc]
         // 004022db: mov ss:[ebp+0xfffffffffffffff8], edi
         // 004022de: mov edi, ss:[ebp+0xfffffffffffffff4]
         // 004022e1: and edi, ecx
         // 004022e3: mov ecx, ss:[ebp+0xfffffffffffffff8]
         // 004022e6: or ecx, edi
         // 004022e8: add ecx, ebx
         // 004022ea: mov ss:[ebp+0xffffffffffffffec], ecx
         // 004022ed: mov ecx, ss:[ebp+0xffffffffffffff4c]
         // 004022f3: mov ebx, ecx
         // 004022f5: rol ebx, b1 0xf
         // 004022f8: mov edi, ecx
         // 004022fa: rol edi, b1 0xd
         // 004022fd: xor ebx, edi
         // 004022ff: mov edi, ss:[ebp+0xffffffffffffff18]
         // 00402305: shr ecx, b1 0xa
         // 00402308: xor ebx, ecx
         // 0040230a: add ebx, ss:[ebp+0xffffffffffffff38]
         // 00402310: mov ecx, edi
         // 00402312: rol ecx, b1 0xe
         // 00402315: ror edi, b1 0x7
         // 00402318: xor ecx, edi
         // 0040231a: mov edi, ss:[ebp+0xffffffffffffff18]
         // 00402320: shr edi, b1 0x3
         // 00402323: xor ecx, edi
         // 00402325: add ecx, ebx
         // 00402327: add ecx, ss:[ebp+0xffffffffffffff14]
         // 0040232d: mov edi, eax
         // 0040232f: ror edi, b1 0xb
         // 00402332: mov ss:[ebp+0xffffffffffffff54], ecx
         // 00402338: mov ecx, eax
         // 0040233a: rol ecx, b1 0x7
         // 0040233d: xor edi, ecx
         // 0040233f: mov ecx, eax
         // 00402341: ror ecx, b1 0x6
         // 00402344: xor edi, ecx
         // 00402346: mov ecx, ss:[ebp+0xffffffffffffffe0]
         // 00402349: add edi, ss:[ebp+0xffffffffffffff54]
         // 0040234f: mov ebx, esi
         // 00402351: xor ebx, ecx
         // 00402353: and ebx, eax
         // 00402355: xor ebx, ecx
         // 00402357: mov ecx, ss:[ebp+0xffffffffffffffec]
         // 0040235a: add ebx, edi
         // 0040235c: lea edx, ds:[ebx+edx+0x6ca6351]
         // 00402363: add ss:[ebp+0xffffffffffffffdc], edx
         // 00402366: mov ss:[ebp+0xfffffffffffffffc], edx
         // 00402369: mov edi, ecx
         // 0040236b: ror edi, b1 0xd
         // 0040236e: mov edx, ecx
         // 00402370: rol edx, b1 0xa
         // 00402373: xor edi, edx
         // 00402375: mov edx, ecx
         // 00402377: ror edx, b1 0x2
         // 0040237a: xor edi, edx
         // 0040237c: add edi, ss:[ebp+0xfffffffffffffffc]
         // 0040237f: mov edx, ss:[ebp+0xfffffffffffffff0]
         // 00402382: or edx, ecx
         // 00402384: and edx, ss:[ebp+0xfffffffffffffff4]
         // 00402387: mov ebx, ss:[ebp+0xfffffffffffffff0]
         // 0040238a: and ebx, ecx
         // 0040238c: or edx, ebx
         // 0040238e: add edx, edi
         // 00402390: mov ss:[ebp+0xffffffffffffffe8], edx
         // 00402393: mov edx, ss:[ebp+0xffffffffffffff50]
         // 00402399: mov ebx, edx
         // 0040239b: rol ebx, b1 0xf
         // 0040239e: mov edi, edx
         // 004023a0: rol edi, b1 0xd
         // 004023a3: xor ebx, edi
         // 004023a5: mov edi, ss:[ebp+0xffffffffffffff1c]
         // 004023ab: shr edx, b1 0xa
         // 004023ae: xor ebx, edx
         // 004023b0: add ebx, ss:[ebp+0xffffffffffffff3c]
         // 004023b6: mov edx, edi
         // 004023b8: rol edx, b1 0xe
         // 004023bb: ror edi, b1 0x7
         // 004023be: xor edx, edi
         // 004023c0: mov edi, ss:[ebp+0xffffffffffffff1c]
         // 004023c6: shr edi, b1 0x3
         // 004023c9: xor edx, edi
         // 004023cb: add edx, ebx
         // 004023cd: add edx, ss:[ebp+0xffffffffffffff18]
         // 004023d3: mov ss:[ebp+0xffffffffffffff58], edx
         // 004023d9: mov edx, ss:[ebp+0xffffffffffffffdc]
         // 004023dc: mov edi, edx
         // 004023de: ror edi, b1 0xb
         // 004023e1: mov ebx, edx
         // 004023e3: rol ebx, b1 0x7
         // 004023e6: xor edi, ebx
         // 004023e8: mov ebx, edx
         // 004023ea: ror ebx, b1 0x6
         // 004023ed: xor edi, ebx
         // 004023ef: add edi, ss:[ebp+0xffffffffffffff58]
         // 004023f5: mov ebx, esi
         // 004023f7: xor ebx, eax
         // 004023f9: and ebx, edx
         // 004023fb: mov edx, ss:[ebp+0xffffffffffffffe0]
         // 004023fe: xor ebx, esi
         // 00402400: add ebx, edi
         // 00402402: lea edx, ds:[ebx+edx+0x14292967]
         // 00402409: add ss:[ebp+0xfffffffffffffff4], edx
         // 0040240c: mov ss:[ebp+0xfffffffffffffffc], edx
         // 0040240f: mov edx, ss:[ebp+0xffffffffffffffe8]
         // 00402412: mov ebx, edx
         // 00402414: ror ebx, b1 0xd
         // 00402417: mov edi, edx
         // 00402419: rol edi, b1 0xa
         // 0040241c: xor ebx, edi
         // 0040241e: mov edi, edx
         // 00402420: ror edi, b1 0x2
         // 00402423: xor ebx, edi
         // 00402425: add ebx, ss:[ebp+0xfffffffffffffffc]
         // 00402428: mov edi, ecx
         // 0040242a: or edi, edx
         // 0040242c: and edi, ss:[ebp+0xfffffffffffffff0]
         // 0040242f: mov ss:[ebp+0xfffffffffffffff8], edi
         // 00402432: mov edi, ecx
         // 00402434: and edi, edx
         // 00402436: mov edx, ss:[ebp+0xfffffffffffffff8]
         // 00402439: or edx, edi
         // 0040243b: add edx, ebx
         // 0040243d: mov ss:[ebp+0xffffffffffffffe0], edx
         // 00402440: mov edx, ss:[ebp+0xffffffffffffff54]
         // 00402446: mov ebx, edx
         // 00402448: rol ebx, b1 0xf
         // 0040244b: mov edi, edx
         // 0040244d: rol edi, b1 0xd
         // 00402450: xor ebx, edi
         // 00402452: mov edi, ss:[ebp+0xffffffffffffff20]
         // 00402458: shr edx, b1 0xa
         // 0040245b: xor ebx, edx
         // 0040245d: mov edx, edi
         // 0040245f: rol edx, b1 0xe
         // 00402462: ror edi, b1 0x7
         // 00402465: add ebx, ss:[ebp+0xffffffffffffff40]
         // 0040246b: xor edx, edi
         // 0040246d: mov edi, ss:[ebp+0xffffffffffffff20]
         // 00402473: shr edi, b1 0x3
         // 00402476: xor edx, edi
         // 00402478: add edx, ebx
         // 0040247a: add edx, ss:[ebp+0xffffffffffffff1c]
         // 00402480: mov ss:[ebp+0xffffffffffffff5c], edx
         // 00402486: mov edx, ss:[ebp+0xfffffffffffffff4]
         // 00402489: mov edi, edx
         // 0040248b: ror edi, b1 0xb
         // 0040248e: mov ebx, edx
         // 00402490: rol ebx, b1 0x7
         // 00402493: xor edi, ebx
         // 00402495: ror edx, b1 0x6
         // 00402498: xor edi, edx
         // 0040249a: add edi, ss:[ebp+0xffffffffffffff5c]
         // 004024a0: mov edx, eax
         // 004024a2: xor edx, ss:[ebp+0xffffffffffffffdc]
         // 004024a5: and edx, ss:[ebp+0xfffffffffffffff4]
         // 004024a8: xor edx, eax
         // 004024aa: add edx, edi
         // 004024ac: lea esi, ds:[edx+esi+0x27b70a85]
         // 004024b3: add ss:[ebp+0xfffffffffffffff0], esi
         // 004024b6: mov edx, ss:[ebp+0xffffffffffffffe0]
         // 004024b9: mov ss:[ebp+0xfffffffffffffffc], esi
         // 004024bc: mov edi, ss:[ebp+0xffffffffffffffe8]
         // 004024bf: mov ebx, edx
         // 004024c1: ror ebx, b1 0xd
         // 004024c4: mov esi, edx
         // 004024c6: rol esi, b1 0xa
         // 004024c9: xor ebx, esi
         // 004024cb: mov esi, edx
         // 004024cd: ror esi, b1 0x2
         // 004024d0: xor ebx, esi
         // 004024d2: add ebx, ss:[ebp+0xfffffffffffffffc]
         // 004024d5: mov esi, edi
         // 004024d7: or esi, edx
         // 004024d9: and esi, ecx
         // 004024db: and edi, edx
         // 004024dd: or esi, edi
         // 004024df: add esi, ebx
         // 004024e1: mov ss:[ebp+0xffffffffffffffe4], esi
         // 004024e4: mov esi, ss:[ebp+0xffffffffffffff58]
         // 004024ea: mov ebx, esi
         // 004024ec: mov edi, esi
         // 004024ee: shr esi, b1 0xa
         // 004024f1: rol ebx, b1 0xf
         // 004024f4: rol edi, b1 0xd
         // 004024f7: xor ebx, edi
         // 004024f9: mov edi, ss:[ebp+0xffffffffffffff24]
         // 004024ff: xor ebx, esi
         // 00402501: add ebx, ss:[ebp+0xffffffffffffff44]
         // 00402507: mov esi, edi
         // 00402509: rol esi, b1 0xe
         // 0040250c: ror edi, b1 0x7
         // 0040250f: xor esi, edi
         // 00402511: mov edi, ss:[ebp+0xffffffffffffff24]
         // 00402517: shr edi, b1 0x3
         // 0040251a: xor esi, edi
         // 0040251c: add esi, ebx
         // 0040251e: add esi, ss:[ebp+0xffffffffffffff20]
         // 00402524: mov ss:[ebp+0xffffffffffffff60], esi
         // 0040252a: mov esi, ss:[ebp+0xfffffffffffffff0]
         // 0040252d: mov edi, esi
         // 0040252f: mov ebx, esi
         // 00402531: ror edi, b1 0xb
         // 00402534: rol ebx, b1 0x7
         // 00402537: xor edi, ebx
         // 00402539: ror esi, b1 0x6
         // 0040253c: xor edi, esi
         // 0040253e: mov esi, ss:[ebp+0xffffffffffffffdc]
         // 00402541: xor esi, ss:[ebp+0xfffffffffffffff4]
         // 00402544: add edi, ss:[ebp+0xffffffffffffff60]
         // 0040254a: and esi, ss:[ebp+0xfffffffffffffff0]
         // 0040254d: xor esi, ss:[ebp+0xffffffffffffffdc]
         // 00402550: add esi, edi
         // 00402552: lea eax, ds:[esi+eax+0x2e1b2138]
         // 00402559: mov esi, ss:[ebp+0xffffffffffffffe4]
         // 0040255c: mov ss:[ebp+0xfffffffffffffffc], eax
         // 0040255f: add ecx, eax
         // 00402561: mov edi, esi
         // 00402563: ror edi, b1 0xd
         // 00402566: mov eax, esi
         // 00402568: rol eax, b1 0xa
         // 0040256b: xor edi, eax
         // 0040256d: mov eax, esi
         // 0040256f: ror eax, b1 0x2
         // 00402572: xor edi, eax
         // 00402574: add edi, ss:[ebp+0xfffffffffffffffc]
         // 00402577: mov eax, esi
         // 00402579: or eax, edx
         // 0040257b: and eax, ss:[ebp+0xffffffffffffffe8]
         // 0040257e: mov ebx, esi
         // 00402580: and ebx, edx
         // 00402582: or eax, ebx
         // 00402584: add eax, edi
         // 00402586: mov ss:[ebp+0xfffffffffffffff8], eax
         // 00402589: mov eax, ss:[ebp+0xffffffffffffff5c]
         // 0040258f: mov ebx, eax
         // 00402591: mov edi, eax
         // 00402593: shr eax, b1 0xa
         // 00402596: rol ebx, b1 0xf
         // 00402599: rol edi, b1 0xd
         // 0040259c: xor ebx, edi
         // 0040259e: mov edi, ss:[ebp+0xffffffffffffff28]
         // 004025a4: xor ebx, eax
         // 004025a6: add ebx, ss:[ebp+0xffffffffffffff48]
         // 004025ac: mov eax, edi
         // 004025ae: rol eax, b1 0xe
         // 004025b1: ror edi, b1 0x7
         // 004025b4: xor eax, edi
         // 004025b6: mov edi, ss:[ebp+0xffffffffffffff28]
         // 004025bc: shr edi, b1 0x3
         // 004025bf: xor eax, edi
         // 004025c1: add eax, ebx
         // 004025c3: add eax, ss:[ebp+0xffffffffffffff24]
         // 004025c9: mov edi, ecx
         // 004025cb: mov ss:[ebp+0xffffffffffffff64], eax
         // 004025d1: mov eax, ecx
         // 004025d3: ror eax, b1 0xb
         // 004025d6: rol edi, b1 0x7
         // 004025d9: xor eax, edi
         // 004025db: mov edi, ecx
         // 004025dd: ror edi, b1 0x6
         // 004025e0: xor eax, edi
         // 004025e2: add eax, ss:[ebp+0xffffffffffffff64]
         // 004025e8: mov edi, ss:[ebp+0xfffffffffffffff4]
         // 004025eb: xor edi, ss:[ebp+0xfffffffffffffff0]
         // 004025ee: and edi, ecx
         // 004025f0: xor edi, ss:[ebp+0xfffffffffffffff4]
         // 004025f3: add edi, eax
         // 004025f5: mov eax, ss:[ebp+0xffffffffffffffdc]
         // 004025f8: lea eax, ds:[edi+eax+0x4d2c6dfc]
         // 004025ff: add ss:[ebp+0xffffffffffffffe8], eax
         // 00402602: mov ss:[ebp+0xfffffffffffffffc], eax
         // 00402605: mov eax, ss:[ebp+0xfffffffffffffff8]
         // 00402608: mov ebx, eax
         // 0040260a: ror ebx, b1 0xd
         // 0040260d: mov edi, eax
         // 0040260f: rol edi, b1 0xa
         // 00402612: xor ebx, edi
         // 00402614: mov edi, eax
         // 00402616: ror edi, b1 0x2
         // 00402619: xor ebx, edi
         // 0040261b: add ebx, ss:[ebp+0xfffffffffffffffc]
         // 0040261e: mov edi, esi
         // 00402620: or edi, eax
         // 00402622: and edi, edx
         // 00402624: mov ss:[ebp+0xffffffffffffffe4], edi
         // 00402627: mov edi, esi
         // 00402629: and edi, eax
         // 0040262b: mov eax, ss:[ebp+0xffffffffffffffe4]
         // 0040262e: or eax, edi
         // 00402630: add eax, ebx
         // 00402632: mov ss:[ebp+0xffffffffffffffdc], eax
         // 00402635: mov eax, ss:[ebp+0xffffffffffffff60]
         // 0040263b: mov ebx, eax
         // 0040263d: rol ebx, b1 0xf
         // 00402640: mov edi, eax
         // 00402642: rol edi, b1 0xd
         // 00402645: xor ebx, edi
         // 00402647: shr eax, b1 0xa
         // 0040264a: xor ebx, eax
         // 0040264c: add ebx, ss:[ebp+0xffffffffffffff4c]
         // 00402652: mov edi, ss:[ebp+0xffffffffffffff2c]
         // 00402658: mov eax, edi
         // 0040265a: rol eax, b1 0xe
         // 0040265d: ror edi, b1 0x7
         // 00402660: xor eax, edi
         // 00402662: mov edi, ss:[ebp+0xffffffffffffff2c]
         // 00402668: shr edi, b1 0x3
         // 0040266b: xor eax, edi
         // 0040266d: add eax, ebx
         // 0040266f: add eax, ss:[ebp+0xffffffffffffff28]
         // 00402675: mov ss:[ebp+0xffffffffffffff68], eax
         // 0040267b: mov eax, ss:[ebp+0xffffffffffffffe8]
         // 0040267e: mov edi, eax
         // 00402680: ror edi, b1 0xb
         // 00402683: mov ebx, eax
         // 00402685: rol ebx, b1 0x7
         // 00402688: xor edi, ebx
         // 0040268a: mov ebx, eax
         // 0040268c: ror ebx, b1 0x6
         // 0040268f: xor edi, ebx
         // 00402691: add edi, ss:[ebp+0xffffffffffffff68]
         // 00402697: mov ebx, ss:[ebp+0xfffffffffffffff0]
         // 0040269a: xor ebx, ecx
         // 0040269c: and ebx, eax
         // 0040269e: xor ebx, ss:[ebp+0xfffffffffffffff0]
         // 004026a1: mov eax, ss:[ebp+0xfffffffffffffff4]
         // 004026a4: add ebx, edi
         // 004026a6: lea eax, ds:[ebx+eax+0x53380d13]
         // 004026ad: add edx, eax
         // 004026af: mov ss:[ebp+0xfffffffffffffffc], eax
         // 004026b2: mov eax, ss:[ebp+0xffffffffffffffdc]
         // 004026b5: mov ebx, eax
         // 004026b7: ror ebx, b1 0xd
         // 004026ba: mov edi, eax
         // 004026bc: rol edi, b1 0xa
         // 004026bf: xor ebx, edi
         // 004026c1: mov edi, eax
         // 004026c3: ror edi, b1 0x2
         // 004026c6: xor ebx, edi
         // 004026c8: add ebx, ss:[ebp+0xfffffffffffffffc]
         // 004026cb: mov edi, ss:[ebp+0xfffffffffffffff8]
         // 004026ce: or edi, eax
         // 004026d0: and edi, esi
         // 004026d2: mov ss:[ebp+0xffffffffffffffe4], edi
         // 004026d5: mov edi, ss:[ebp+0xfffffffffffffff8]
         // 004026d8: and edi, eax
         // 004026da: mov eax, ss:[ebp+0xffffffffffffffe4]
         // 004026dd: or eax, edi
         // 004026df: add eax, ebx
         // 004026e1: mov ss:[ebp+0xfffffffffffffff4], eax
         // 004026e4: mov eax, ss:[ebp+0xffffffffffffff64]
         // 004026ea: mov ebx, eax
         // 004026ec: mov edi, eax
         // 004026ee: shr eax, b1 0xa
         // 004026f1: rol ebx, b1 0xf
         // 004026f4: rol edi, b1 0xd
         // 004026f7: xor ebx, edi
         // 004026f9: mov edi, ss:[ebp+0xffffffffffffff30]
         // 004026ff: xor ebx, eax
         // 00402701: add ebx, ss:[ebp+0xffffffffffffff50]
         // 00402707: mov eax, edi
         // 00402709: rol eax, b1 0xe
         // 0040270c: ror edi, b1 0x7
         // 0040270f: xor eax, edi
         // 00402711: mov edi, ss:[ebp+0xffffffffffffff30]
         // 00402717: shr edi, b1 0x3
         // 0040271a: xor eax, edi
         // 0040271c: add eax, ebx
         // 0040271e: add eax, ss:[ebp+0xffffffffffffff2c]
         // 00402724: mov edi, edx
         // 00402726: mov ss:[ebp+0xffffffffffffff6c], eax
         // 0040272c: mov eax, edx
         // 0040272e: ror eax, b1 0xb
         // 00402731: rol edi, b1 0x7
         // 00402734: xor eax, edi
         // 00402736: mov edi, edx
         // 00402738: ror edi, b1 0x6
         // 0040273b: xor eax, edi
         // 0040273d: add eax, ss:[ebp+0xffffffffffffff6c]
         // 00402743: mov edi, ecx
         // 00402745: xor edi, ss:[ebp+0xffffffffffffffe8]
         // 00402748: and edi, edx
         // 0040274a: xor edi, ecx
         // 0040274c: add edi, eax
         // 0040274e: mov eax, ss:[ebp+0xfffffffffffffff0]
         // 00402751: lea eax, ds:[edi+eax+0x650a7354]
         // 00402758: add esi, eax
         // 0040275a: mov ss:[ebp+0xfffffffffffffffc], eax
         // 0040275d: mov eax, ss:[ebp+0xfffffffffffffff4]
         // 00402760: mov ebx, eax
         // 00402762: ror ebx, b1 0xd
         // 00402765: mov edi, eax
         // 00402767: rol edi, b1 0xa
         // 0040276a: xor ebx, edi
         // 0040276c: mov edi, eax
         // 0040276e: ror edi, b1 0x2
         // 00402771: xor ebx, edi
         // 00402773: add ebx, ss:[ebp+0xfffffffffffffffc]
         // 00402776: mov edi, ss:[ebp+0xffffffffffffffdc]
         // 00402779: or edi, eax
         // 0040277b: and edi, ss:[ebp+0xfffffffffffffff8]
         // 0040277e: mov ss:[ebp+0xffffffffffffffe4], edi
         // 00402781: mov edi, ss:[ebp+0xffffffffffffffdc]
         // 00402784: and edi, eax
         // 00402786: mov eax, ss:[ebp+0xffffffffffffffe4]
         // 00402789: or eax, edi
         // 0040278b: add eax, ebx
         // 0040278d: mov ss:[ebp+0xfffffffffffffff0], eax
         // 00402790: mov eax, ss:[ebp+0xffffffffffffff68]
         // 00402796: mov ebx, eax
         // 00402798: rol ebx, b1 0xf
         // 0040279b: mov edi, eax
         // 0040279d: rol edi, b1 0xd
         // 004027a0: xor ebx, edi
         // 004027a2: mov edi, ss:[ebp+0xffffffffffffff34]
         // 004027a8: shr eax, b1 0xa
         // 004027ab: xor ebx, eax
         // 004027ad: add ebx, ss:[ebp+0xffffffffffffff54]
         // 004027b3: mov eax, edi
         // 004027b5: rol eax, b1 0xe
         // 004027b8: ror edi, b1 0x7
         // 004027bb: xor eax, edi
         // 004027bd: mov edi, ss:[ebp+0xffffffffffffff34]
         // 004027c3: shr edi, b1 0x3
         // 004027c6: xor eax, edi
         // 004027c8: add eax, ebx
         // 004027ca: add eax, ss:[ebp+0xffffffffffffff30]
         // 004027d0: mov edi, esi
         // 004027d2: ror edi, b1 0xb
         // 004027d5: mov ss:[ebp+0xffffffffffffff70], eax
         // 004027db: mov eax, esi
         // 004027dd: rol eax, b1 0x7
         // 004027e0: xor edi, eax
         // 004027e2: mov eax, esi
         // 004027e4: ror eax, b1 0x6
         // 004027e7: xor edi, eax
         // 004027e9: mov eax, ss:[ebp+0xffffffffffffffe8]
         // 004027ec: add edi, ss:[ebp+0xffffffffffffff70]
         // 004027f2: mov ebx, eax
         // 004027f4: xor ebx, edx
         // 004027f6: and ebx, esi
         // 004027f8: xor ebx, eax
         // 004027fa: mov eax, ss:[ebp+0xfffffffffffffff0]
         // 004027fd: add ebx, edi
         // 004027ff: lea ecx, ds:[ebx+ecx+0x766a0abb]
         // 00402806: add ss:[ebp+0xfffffffffffffff8], ecx
         // 00402809: mov ebx, ss:[ebp+0xfffffffffffffff4]
         // 0040280c: mov ss:[ebp+0xfffffffffffffffc], ecx
         // 0040280f: mov edi, eax
         // 00402811: ror edi, b1 0xd
         // 00402814: mov ecx, eax
         // 00402816: rol ecx, b1 0xa
         // 00402819: xor edi, ecx
         // 0040281b: mov ecx, eax
         // 0040281d: ror ecx, b1 0x2
         // 00402820: xor edi, ecx
         // 00402822: mov ecx, ss:[ebp+0xfffffffffffffff4]
         // 00402825: or ecx, eax
         // 00402827: and ecx, ss:[ebp+0xffffffffffffffdc]
         // 0040282a: add edi, ss:[ebp+0xfffffffffffffffc]
         // 0040282d: and ebx, eax
         // 0040282f: or ecx, ebx
         // 00402831: add ecx, edi
         // 00402833: mov ss:[ebp+0xffffffffffffffec], ecx
         // 00402836: mov ecx, ss:[ebp+0xffffffffffffff6c]
         // 0040283c: mov ebx, ecx
         // 0040283e: rol ebx, b1 0xf
         // 00402841: mov edi, ecx
         // 00402843: rol edi, b1 0xd
         // 00402846: xor ebx, edi
         // 00402848: mov edi, ss:[ebp+0xffffffffffffff38]
         // 0040284e: shr ecx, b1 0xa
         // 00402851: xor ebx, ecx
         // 00402853: add ebx, ss:[ebp+0xffffffffffffff58]
         // 00402859: mov ecx, edi
         // 0040285b: rol ecx, b1 0xe
         // 0040285e: ror edi, b1 0x7
         // 00402861: xor ecx, edi
         // 00402863: mov edi, ss:[ebp+0xffffffffffffff38]
         // 00402869: shr edi, b1 0x3
         // 0040286c: xor ecx, edi
         // 0040286e: add ecx, ebx
         // 00402870: add ecx, ss:[ebp+0xffffffffffffff34]
         // 00402876: mov ss:[ebp+0xffffffffffffff74], ecx
         // 0040287c: mov ecx, ss:[ebp+0xfffffffffffffff8]
         // 0040287f: mov edi, ecx
         // 00402881: ror edi, b1 0xb
         // 00402884: mov ebx, ecx
         // 00402886: rol ebx, b1 0x7
         // 00402889: xor edi, ebx
         // 0040288b: mov ebx, ecx
         // 0040288d: ror ebx, b1 0x6
         // 00402890: xor edi, ebx
         // 00402892: add edi, ss:[ebp+0xffffffffffffff74]
         // 00402898: mov ebx, esi
         // 0040289a: xor ebx, edx
         // 0040289c: and ebx, ecx
         // 0040289e: mov ecx, ss:[ebp+0xffffffffffffffe8]
         // 004028a1: xor ebx, edx
         // 004028a3: add ebx, edi
         // 004028a5: lea ecx, ds:[ebx+ecx+0xffffffff81c2c92e]
         // 004028ac: add ss:[ebp+0xffffffffffffffdc], ecx
         // 004028af: mov ss:[ebp+0xfffffffffffffffc], ecx
         // 004028b2: mov ecx, ss:[ebp+0xffffffffffffffec]
         // 004028b5: mov ebx, ecx
         // 004028b7: ror ebx, b1 0xd
         // 004028ba: mov edi, ecx
         // 004028bc: rol edi, b1 0xa
         // 004028bf: xor ebx, edi
         // 004028c1: mov edi, ecx
         // 004028c3: ror edi, b1 0x2
         // 004028c6: xor ebx, edi
         // 004028c8: add ebx, ss:[ebp+0xfffffffffffffffc]
         // 004028cb: mov edi, eax
         // 004028cd: or edi, ecx
         // 004028cf: and edi, ss:[ebp+0xfffffffffffffff4]
         // 004028d2: mov ss:[ebp+0xffffffffffffffe4], edi
         // 004028d5: mov edi, eax
         // 004028d7: and edi, ecx
         // 004028d9: mov ecx, ss:[ebp+0xffffffffffffffe4]
         // 004028dc: or ecx, edi
         // 004028de: add ecx, ebx
         // 004028e0: mov ss:[ebp+0xffffffffffffffe8], ecx
         // 004028e3: mov ecx, ss:[ebp+0xffffffffffffff70]
         // 004028e9: mov ebx, ecx
         // 004028eb: mov edi, ecx
         // 004028ed: rol ebx, b1 0xf
         // 004028f0: rol edi, b1 0xd
         // 004028f3: xor ebx, edi
         // 004028f5: mov edi, ss:[ebp+0xffffffffffffff3c]
         // 004028fb: shr ecx, b1 0xa
         // 004028fe: xor ebx, ecx
         // 00402900: mov ecx, edi
         // 00402902: rol ecx, b1 0xe
         // 00402905: ror edi, b1 0x7
         // 00402908: xor ecx, edi
         // 0040290a: mov edi, ss:[ebp+0xffffffffffffff3c]
         // 00402910: shr edi, b1 0x3
         // 00402913: xor ecx, edi
         // 00402915: add ebx, ss:[ebp+0xffffffffffffff5c]
         // 0040291b: add ecx, ebx
         // 0040291d: add ecx, ss:[ebp+0xffffffffffffff38]
         // 00402923: mov ss:[ebp+0xffffffffffffff78], ecx
         // 00402929: mov ecx, ss:[ebp+0xffffffffffffffdc]
         // 0040292c: mov edi, ecx
         // 0040292e: ror edi, b1 0xb
         // 00402931: mov ebx, ecx
         // 00402933: rol ebx, b1 0x7
         // 00402936: xor edi, ebx
         // 00402938: ror ecx, b1 0x6
         // 0040293b: xor edi, ecx
         // 0040293d: add edi, ss:[ebp+0xffffffffffffff78]
         // 00402943: mov ecx, esi
         // 00402945: xor ecx, ss:[ebp+0xfffffffffffffff8]
         // 00402948: and ecx, ss:[ebp+0xffffffffffffffdc]
         // 0040294b: xor ecx, esi
         // 0040294d: add ecx, edi
         // 0040294f: lea edx, ds:[ecx+edx+0xffffffff92722c85]
         // 00402956: add ss:[ebp+0xfffffffffffffff4], edx
         // 00402959: mov ecx, ss:[ebp+0xffffffffffffffe8]
         // 0040295c: mov ss:[ebp+0xfffffffffffffffc], edx
         // 0040295f: mov edi, ss:[ebp+0xffffffffffffffec]
         // 00402962: mov ebx, ecx
         // 00402964: ror ebx, b1 0xd
         // 00402967: mov edx, ecx
         // 00402969: rol edx, b1 0xa
         // 0040296c: xor ebx, edx
         // 0040296e: mov edx, ecx
         // 00402970: ror edx, b1 0x2
         // 00402973: xor ebx, edx
         // 00402975: add ebx, ss:[ebp+0xfffffffffffffffc]
         // 00402978: mov edx, edi
         // 0040297a: or edx, ecx
         // 0040297c: and edx, eax
         // 0040297e: and edi, ecx
         // 00402980: or edx, edi
         // 00402982: add edx, ebx
         // 00402984: mov ss:[ebp+0xffffffffffffffe0], edx
         // 00402987: mov edx, ss:[ebp+0xffffffffffffff74]
         // 0040298d: mov ebx, edx
         // 0040298f: mov edi, edx
         // 00402991: shr edx, b1 0xa
         // 00402994: rol ebx, b1 0xf
         // 00402997: rol edi, b1 0xd
         // 0040299a: xor ebx, edi
         // 0040299c: mov edi, ss:[ebp+0xffffffffffffff40]
         // 004029a2: xor ebx, edx
         // 004029a4: add ebx, ss:[ebp+0xffffffffffffff60]
         // 004029aa: mov edx, edi
         // 004029ac: rol edx, b1 0xe
         // 004029af: ror edi, b1 0x7
         // 004029b2: xor edx, edi
         // 004029b4: mov edi, ss:[ebp+0xffffffffffffff40]
         // 004029ba: shr edi, b1 0x3
         // 004029bd: xor edx, edi
         // 004029bf: add edx, ebx
         // 004029c1: add edx, ss:[ebp+0xffffffffffffff3c]
         // 004029c7: mov ss:[ebp+0xffffffffffffff7c], edx
         // 004029cd: mov edx, ss:[ebp+0xfffffffffffffff4]
         // 004029d0: mov edi, edx
         // 004029d2: ror edi, b1 0xb
         // 004029d5: mov ebx, edx
         // 004029d7: rol ebx, b1 0x7
         // 004029da: xor edi, ebx
         // 004029dc: ror edx, b1 0x6
         // 004029df: xor edi, edx
         // 004029e1: mov edx, ss:[ebp+0xfffffffffffffff8]
         // 004029e4: xor edx, ss:[ebp+0xffffffffffffffdc]
         // 004029e7: add edi, ss:[ebp+0xffffffffffffff7c]
         // 004029ed: and edx, ss:[ebp+0xfffffffffffffff4]
         // 004029f0: xor edx, ss:[ebp+0xfffffffffffffff8]
         // 004029f3: add edx, edi
         // 004029f5: lea esi, ds:[edx+esi+0xffffffffa2bfe8a1]
         // 004029fc: mov edx, ss:[ebp+0xffffffffffffffe0]
         // 004029ff: add eax, esi
         // 00402a01: mov ss:[ebp+0xfffffffffffffffc], esi
         // 00402a04: mov edi, edx
         // 00402a06: ror edi, b1 0xd
         // 00402a09: mov esi, edx
         // 00402a0b: rol esi, b1 0xa
         // 00402a0e: xor edi, esi
         // 00402a10: mov esi, edx
         // 00402a12: ror esi, b1 0x2
         // 00402a15: xor edi, esi
         // 00402a17: add edi, ss:[ebp+0xfffffffffffffffc]
         // 00402a1a: mov esi, ecx
         // 00402a1c: or esi, edx
         // 00402a1e: and esi, ss:[ebp+0xffffffffffffffec]
         // 00402a21: mov ebx, ecx
         // 00402a23: and ebx, edx
         // 00402a25: or esi, ebx
         // 00402a27: add esi, edi
         // 00402a29: mov ss:[ebp+0xffffffffffffffe4], esi
         // 00402a2c: mov esi, ss:[ebp+0xffffffffffffff78]
         // 00402a32: mov ebx, esi
         // 00402a34: mov edi, esi
         // 00402a36: shr esi, b1 0xa
         // 00402a39: rol ebx, b1 0xf
         // 00402a3c: rol edi, b1 0xd
         // 00402a3f: xor ebx, edi
         // 00402a41: xor ebx, esi
         // 00402a43: add ebx, ss:[ebp+0xffffffffffffff64]
         // 00402a49: mov edi, ss:[ebp+0xffffffffffffff44]
         // 00402a4f: mov esi, edi
         // 00402a51: rol esi, b1 0xe
         // 00402a54: ror edi, b1 0x7
         // 00402a57: xor esi, edi
         // 00402a59: mov edi, ss:[ebp+0xffffffffffffff44]
         // 00402a5f: shr edi, b1 0x3
         // 00402a62: xor esi, edi
         // 00402a64: add esi, ebx
         // 00402a66: add esi, ss:[ebp+0xffffffffffffff40]
         // 00402a6c: mov edi, eax
         // 00402a6e: mov ss:[ebp+0xffffffffffffff80], esi
         // 00402a71: mov esi, eax
         // 00402a73: ror esi, b1 0xb
         // 00402a76: rol edi, b1 0x7
         // 00402a79: xor esi, edi
         // 00402a7b: mov edi, eax
         // 00402a7d: ror edi, b1 0x6
         // 00402a80: xor esi, edi
         // 00402a82: add esi, ss:[ebp+0xffffffffffffff80]
         // 00402a85: mov edi, ss:[ebp+0xffffffffffffffdc]
         // 00402a88: xor edi, ss:[ebp+0xfffffffffffffff4]
         // 00402a8b: and edi, eax
         // 00402a8d: xor edi, ss:[ebp+0xffffffffffffffdc]
         // 00402a90: add edi, esi
         // 00402a92: mov esi, ss:[ebp+0xfffffffffffffff8]
         // 00402a95: lea esi, ds:[edi+esi+0xffffffffa81a664b]
         // 00402a9c: add ss:[ebp+0xffffffffffffffec], esi
         // 00402a9f: mov edi, ss:[ebp+0xffffffffffffffe4]
         // 00402aa2: mov ss:[ebp+0xfffffffffffffffc], esi
         // 00402aa5: mov ebx, edi
         // 00402aa7: ror ebx, b1 0xd
         // 00402aaa: mov esi, edi
         // 00402aac: rol esi, b1 0xa
         // 00402aaf: xor ebx, esi
         // 00402ab1: mov esi, edi
         // 00402ab3: ror esi, b1 0x2
         // 00402ab6: xor ebx, esi
         // 00402ab8: add ebx, ss:[ebp+0xfffffffffffffffc]
         // 00402abb: mov esi, edi
         // 00402abd: or esi, edx
         // 00402abf: and esi, ecx
         // 00402ac1: and edi, edx
         // 00402ac3: or esi, edi
         // 00402ac5: add esi, ebx
         // 00402ac7: mov ss:[ebp+0xfffffffffffffff8], esi
         // 00402aca: mov esi, ss:[ebp+0xffffffffffffff7c]
         // 00402ad0: mov ebx, esi
         // 00402ad2: rol ebx, b1 0xf
         // 00402ad5: mov edi, esi
         // 00402ad7: rol edi, b1 0xd
         // 00402ada: xor ebx, edi
         // 00402adc: mov edi, ss:[ebp+0xffffffffffffff48]
         // 00402ae2: shr esi, b1 0xa
         // 00402ae5: xor ebx, esi
         // 00402ae7: mov esi, edi
         // 00402ae9: rol esi, b1 0xe
         // 00402aec: ror edi, b1 0x7
         // 00402aef: xor esi, edi
         // 00402af1: mov edi, ss:[ebp+0xffffffffffffff48]
         // 00402af7: add ebx, ss:[ebp+0xffffffffffffff68]
         // 00402afd: shr edi, b1 0x3
         // 00402b00: xor esi, edi
         // 00402b02: add esi, ebx
         // 00402b04: add esi, ss:[ebp+0xffffffffffffff44]
         // 00402b0a: mov ss:[ebp+0xffffffffffffff84], esi
         // 00402b0d: mov esi, ss:[ebp+0xffffffffffffffec]
         // 00402b10: mov edi, esi
         // 00402b12: ror edi, b1 0xb
         // 00402b15: mov ebx, esi
         // 00402b17: rol ebx, b1 0x7
         // 00402b1a: xor edi, ebx
         // 00402b1c: mov ebx, esi
         // 00402b1e: ror ebx, b1 0x6
         // 00402b21: xor edi, ebx
         // 00402b23: add edi, ss:[ebp+0xffffffffffffff84]
         // 00402b26: mov ebx, ss:[ebp+0xfffffffffffffff4]
         // 00402b29: xor ebx, eax
         // 00402b2b: and ebx, esi
         // 00402b2d: xor ebx, ss:[ebp+0xfffffffffffffff4]
         // 00402b30: mov esi, ss:[ebp+0xffffffffffffffdc]
         // 00402b33: add ebx, edi
         // 00402b35: lea esi, ds:[ebx+esi+0xffffffffc24b8b70]
         // 00402b3c: add ecx, esi
         // 00402b3e: mov ss:[ebp+0xfffffffffffffffc], esi
         // 00402b41: mov esi, ss:[ebp+0xfffffffffffffff8]
         // 00402b44: mov ebx, esi
         // 00402b46: mov edi, esi
         // 00402b48: ror ebx, b1 0xd
         // 00402b4b: rol edi, b1 0xa
         // 00402b4e: xor ebx, edi
         // 00402b50: mov edi, esi
         // 00402b52: ror edi, b1 0x2
         // 00402b55: xor ebx, edi
         // 00402b57: add ebx, ss:[ebp+0xfffffffffffffffc]
         // 00402b5a: mov edi, ss:[ebp+0xffffffffffffffe4]
         // 00402b5d: or edi, esi
         // 00402b5f: and edi, edx
         // 00402b61: mov ss:[ebp+0xffffffffffffffdc], edi
         // 00402b64: mov edi, ss:[ebp+0xffffffffffffffe4]
         // 00402b67: and edi, esi
         // 00402b69: mov esi, ss:[ebp+0xffffffffffffffdc]
         // 00402b6c: or esi, edi
         // 00402b6e: add esi, ebx
         // 00402b70: mov ss:[ebp+0xffffffffffffffdc], esi
         // 00402b73: mov esi, ss:[ebp+0xffffffffffffff80]
         // 00402b76: mov ebx, esi
         // 00402b78: mov edi, esi
         // 00402b7a: shr esi, b1 0xa
         // 00402b7d: rol ebx, b1 0xf
         // 00402b80: rol edi, b1 0xd
         // 00402b83: xor ebx, edi
         // 00402b85: mov edi, ss:[ebp+0xffffffffffffff4c]
         // 00402b8b: xor ebx, esi
         // 00402b8d: add ebx, ss:[ebp+0xffffffffffffff6c]
         // 00402b93: mov esi, edi
         // 00402b95: rol esi, b1 0xe
         // 00402b98: ror edi, b1 0x7
         // 00402b9b: xor esi, edi
         // 00402b9d: mov edi, ss:[ebp+0xffffffffffffff4c]
         // 00402ba3: shr edi, b1 0x3
         // 00402ba6: xor esi, edi
         // 00402ba8: add esi, ebx
         // 00402baa: add esi, ss:[ebp+0xffffffffffffff48]
         // 00402bb0: mov edi, ecx
         // 00402bb2: mov ss:[ebp+0xffffffffffffff88], esi
         // 00402bb5: mov esi, ecx
         // 00402bb7: ror esi, b1 0xb
         // 00402bba: rol edi, b1 0x7
         // 00402bbd: xor esi, edi
         // 00402bbf: mov edi, ecx
         // 00402bc1: ror edi, b1 0x6
         // 00402bc4: xor esi, edi
         // 00402bc6: add esi, ss:[ebp+0xffffffffffffff88]
         // 00402bc9: mov edi, eax
         // 00402bcb: xor edi, ss:[ebp+0xffffffffffffffec]
         // 00402bce: and edi, ecx
         // 00402bd0: xor edi, eax
         // 00402bd2: add edi, esi
         // 00402bd4: mov esi, ss:[ebp+0xfffffffffffffff4]
         // 00402bd7: lea esi, ds:[edi+esi+0xffffffffc76c51a3]
         // 00402bde: add edx, esi
         // 00402be0: mov ss:[ebp+0xfffffffffffffffc], esi
         // 00402be3: mov esi, ss:[ebp+0xffffffffffffffdc]
         // 00402be6: mov ebx, esi
         // 00402be8: ror ebx, b1 0xd
         // 00402beb: mov edi, esi
         // 00402bed: rol edi, b1 0xa
         // 00402bf0: xor ebx, edi
         // 00402bf2: mov edi, esi
         // 00402bf4: ror edi, b1 0x2
         // 00402bf7: xor ebx, edi
         // 00402bf9: add ebx, ss:[ebp+0xfffffffffffffffc]
         // 00402bfc: mov edi, ss:[ebp+0xfffffffffffffff8]
         // 00402bff: or edi, esi
         // 00402c01: and edi, ss:[ebp+0xffffffffffffffe4]
         // 00402c04: mov ss:[ebp+0xffffffffffffffe0], edi
         // 00402c07: mov edi, ss:[ebp+0xfffffffffffffff8]
         // 00402c0a: and edi, esi
         // 00402c0c: mov esi, ss:[ebp+0xffffffffffffffe0]
         // 00402c0f: or esi, edi
         // 00402c11: add esi, ebx
         // 00402c13: mov ss:[ebp+0xfffffffffffffff4], esi
         // 00402c16: mov esi, ss:[ebp+0xffffffffffffff84]
         // 00402c19: mov ebx, esi
         // 00402c1b: rol ebx, b1 0xf
         // 00402c1e: mov edi, esi
         // 00402c20: rol edi, b1 0xd
         // 00402c23: xor ebx, edi
         // 00402c25: mov edi, ss:[ebp+0xffffffffffffff50]
         // 00402c2b: shr esi, b1 0xa
         // 00402c2e: xor ebx, esi
         // 00402c30: add ebx, ss:[ebp+0xffffffffffffff70]
         // 00402c36: mov esi, edi
         // 00402c38: rol esi, b1 0xe
         // 00402c3b: ror edi, b1 0x7
         // 00402c3e: xor esi, edi
         // 00402c40: mov edi, ss:[ebp+0xffffffffffffff50]
         // 00402c46: shr edi, b1 0x3
         // 00402c49: xor esi, edi
         // 00402c4b: add esi, ebx
         // 00402c4d: add esi, ss:[ebp+0xffffffffffffff4c]
         // 00402c53: mov edi, edx
         // 00402c55: ror edi, b1 0xb
         // 00402c58: mov ss:[ebp+0xffffffffffffff8c], esi
         // 00402c5b: mov esi, edx
         // 00402c5d: rol esi, b1 0x7
         // 00402c60: xor edi, esi
         // 00402c62: mov esi, edx
         // 00402c64: ror esi, b1 0x6
         // 00402c67: xor edi, esi
         // 00402c69: mov esi, ss:[ebp+0xffffffffffffffec]
         // 00402c6c: add edi, ss:[ebp+0xffffffffffffff8c]
         // 00402c6f: mov ebx, esi
         // 00402c71: xor ebx, ecx
         // 00402c73: and ebx, edx
         // 00402c75: xor ebx, esi
         // 00402c77: mov esi, ss:[ebp+0xfffffffffffffff4]
         // 00402c7a: add ebx, edi
         // 00402c7c: lea eax, ds:[ebx+eax+0xffffffffd192e819]
         // 00402c83: add ss:[ebp+0xffffffffffffffe4], eax
         // 00402c86: mov ebx, ss:[ebp+0xffffffffffffffdc]
         // 00402c89: mov ss:[ebp+0xfffffffffffffffc], eax
         // 00402c8c: mov edi, esi
         // 00402c8e: ror edi, b1 0xd
         // 00402c91: mov eax, esi
         // 00402c93: rol eax, b1 0xa
         // 00402c96: xor edi, eax
         // 00402c98: mov eax, esi
         // 00402c9a: ror eax, b1 0x2
         // 00402c9d: xor edi, eax
         // 00402c9f: mov eax, ss:[ebp+0xffffffffffffffdc]
         // 00402ca2: add edi, ss:[ebp+0xfffffffffffffffc]
         // 00402ca5: or eax, esi
         // 00402ca7: and eax, ss:[ebp+0xfffffffffffffff8]
         // 00402caa: and ebx, esi
         // 00402cac: or eax, ebx
         // 00402cae: add eax, edi
         // 00402cb0: mov ss:[ebp+0xfffffffffffffff0], eax
         // 00402cb3: mov eax, ss:[ebp+0xffffffffffffff88]
         // 00402cb6: mov ebx, eax
         // 00402cb8: rol ebx, b1 0xf
         // 00402cbb: mov edi, eax
         // 00402cbd: rol edi, b1 0xd
         // 00402cc0: xor ebx, edi
         // 00402cc2: shr eax, b1 0xa
         // 00402cc5: xor ebx, eax
         // 00402cc7: add ebx, ss:[ebp+0xffffffffffffff74]
         // 00402ccd: mov edi, ss:[ebp+0xffffffffffffff54]
         // 00402cd3: mov eax, edi
         // 00402cd5: rol eax, b1 0xe
         // 00402cd8: ror edi, b1 0x7
         // 00402cdb: xor eax, edi
         // 00402cdd: mov edi, ss:[ebp+0xffffffffffffff54]
         // 00402ce3: shr edi, b1 0x3
         // 00402ce6: xor eax, edi
         // 00402ce8: add eax, ebx
         // 00402cea: add eax, ss:[ebp+0xffffffffffffff50]
         // 00402cf0: mov ss:[ebp+0xffffffffffffff90], eax
         // 00402cf3: mov eax, ss:[ebp+0xffffffffffffffe4]
         // 00402cf6: mov edi, eax
         // 00402cf8: ror edi, b1 0xb
         // 00402cfb: mov ebx, eax
         // 00402cfd: rol ebx, b1 0x7
         // 00402d00: xor edi, ebx
         // 00402d02: mov ebx, eax
         // 00402d04: ror ebx, b1 0x6
         // 00402d07: xor edi, ebx
         // 00402d09: add edi, ss:[ebp+0xffffffffffffff90]
         // 00402d0c: mov ebx, ecx
         // 00402d0e: xor ebx, edx
         // 00402d10: and ebx, eax
         // 00402d12: mov eax, ss:[ebp+0xffffffffffffffec]
         // 00402d15: xor ebx, ecx
         // 00402d17: add ebx, edi
         // 00402d19: lea eax, ds:[ebx+eax+0xffffffffd6990624]
         // 00402d20: add ss:[ebp+0xfffffffffffffff8], eax
         // 00402d23: mov ss:[ebp+0xfffffffffffffffc], eax
         // 00402d26: mov eax, ss:[ebp+0xfffffffffffffff0]
         // 00402d29: mov ebx, eax
         // 00402d2b: ror ebx, b1 0xd
         // 00402d2e: mov edi, eax
         // 00402d30: rol edi, b1 0xa
         // 00402d33: xor ebx, edi
         // 00402d35: mov edi, eax
         // 00402d37: ror edi, b1 0x2
         // 00402d3a: xor ebx, edi
         // 00402d3c: add ebx, ss:[ebp+0xfffffffffffffffc]
         // 00402d3f: mov edi, esi
         // 00402d41: or edi, eax
         // 00402d43: and edi, ss:[ebp+0xffffffffffffffdc]
         // 00402d46: mov ss:[ebp+0xffffffffffffffe0], edi
         // 00402d49: mov edi, esi
         // 00402d4b: and edi, eax
         // 00402d4d: mov eax, ss:[ebp+0xffffffffffffffe0]
         // 00402d50: or eax, edi
         // 00402d52: add eax, ebx
         // 00402d54: mov ss:[ebp+0xffffffffffffffec], eax
         // 00402d57: mov eax, ss:[ebp+0xffffffffffffff8c]
         // 00402d5a: mov ebx, eax
         // 00402d5c: mov edi, eax
         // 00402d5e: rol ebx, b1 0xf
         // 00402d61: rol edi, b1 0xd
         // 00402d64: xor ebx, edi
         // 00402d66: mov edi, ss:[ebp+0xffffffffffffff58]
         // 00402d6c: shr eax, b1 0xa
         // 00402d6f: xor ebx, eax
         // 00402d71: add ebx, ss:[ebp+0xffffffffffffff78]
         // 00402d77: mov eax, edi
         // 00402d79: rol eax, b1 0xe
         // 00402d7c: ror edi, b1 0x7
         // 00402d7f: xor eax, edi
         // 00402d81: mov edi, ss:[ebp+0xffffffffffffff58]
         // 00402d87: shr edi, b1 0x3
         // 00402d8a: xor eax, edi
         // 00402d8c: add eax, ebx
         // 00402d8e: add eax, ss:[ebp+0xffffffffffffff54]
         // 00402d94: mov ss:[ebp+0xffffffffffffff94], eax
         // 00402d97: mov eax, ss:[ebp+0xfffffffffffffff8]
         // 00402d9a: mov edi, eax
         // 00402d9c: mov ebx, eax
         // 00402d9e: ror edi, b1 0xb
         // 00402da1: rol ebx, b1 0x7
         // 00402da4: xor edi, ebx
         // 00402da6: mov ebx, eax
         // 00402da8: ror ebx, b1 0x6
         // 00402dab: xor edi, ebx
         // 00402dad: add edi, ss:[ebp+0xffffffffffffff94]
         // 00402db0: mov ebx, ss:[ebp+0xffffffffffffffe4]
         // 00402db3: xor ebx, edx
         // 00402db5: and ebx, eax
         // 00402db7: mov eax, ss:[ebp+0xffffffffffffffec]
         // 00402dba: xor ebx, edx
         // 00402dbc: add ebx, edi
         // 00402dbe: lea ecx, ds:[ebx+ecx+0xfffffffff40e3585]
         // 00402dc5: add ss:[ebp+0xffffffffffffffdc], ecx
         // 00402dc8: mov ss:[ebp+0xfffffffffffffffc], ecx
         // 00402dcb: mov edi, ss:[ebp+0xfffffffffffffff0]
         // 00402dce: mov ebx, eax
         // 00402dd0: ror ebx, b1 0xd
         // 00402dd3: mov ecx, eax
         // 00402dd5: rol ecx, b1 0xa
         // 00402dd8: xor ebx, ecx
         // 00402dda: mov ecx, eax
         // 00402ddc: ror ecx, b1 0x2
         // 00402ddf: xor ebx, ecx
         // 00402de1: add ebx, ss:[ebp+0xfffffffffffffffc]
         // 00402de4: mov ecx, edi
         // 00402de6: or ecx, eax
         // 00402de8: and ecx, esi
         // 00402dea: and edi, eax
         // 00402dec: or ecx, edi
         // 00402dee: add ecx, ebx
         // 00402df0: mov ss:[ebp+0xffffffffffffffe8], ecx
         // 00402df3: mov ecx, ss:[ebp+0xffffffffffffff90]
         // 00402df6: mov ebx, ecx
         // 00402df8: mov edi, ecx
         // 00402dfa: shr ecx, b1 0xa
         // 00402dfd: rol ebx, b1 0xf
         // 00402e00: rol edi, b1 0xd
         // 00402e03: xor ebx, edi
         // 00402e05: mov edi, ss:[ebp+0xffffffffffffff5c]
         // 00402e0b: xor ebx, ecx
         // 00402e0d: add ebx, ss:[ebp+0xffffffffffffff7c]
         // 00402e13: mov ecx, edi
         // 00402e15: rol ecx, b1 0xe
         // 00402e18: ror edi, b1 0x7
         // 00402e1b: xor ecx, edi
         // 00402e1d: mov edi, ss:[ebp+0xffffffffffffff5c]
         // 00402e23: shr edi, b1 0x3
         // 00402e26: xor ecx, edi
         // 00402e28: add ecx, ebx
         // 00402e2a: add ecx, ss:[ebp+0xffffffffffffff58]
         // 00402e30: mov ss:[ebp+0xffffffffffffff98], ecx
         // 00402e33: mov ecx, ss:[ebp+0xffffffffffffffdc]
         // 00402e36: mov edi, ecx
         // 00402e38: ror edi, b1 0xb
         // 00402e3b: mov ebx, ecx
         // 00402e3d: rol ebx, b1 0x7
         // 00402e40: xor edi, ebx
         // 00402e42: ror ecx, b1 0x6
         // 00402e45: xor edi, ecx
         // 00402e47: mov ecx, ss:[ebp+0xffffffffffffffe4]
         // 00402e4a: xor ecx, ss:[ebp+0xfffffffffffffff8]
         // 00402e4d: add edi, ss:[ebp+0xffffffffffffff98]
         // 00402e50: and ecx, ss:[ebp+0xffffffffffffffdc]
         // 00402e53: mov ebx, eax
         // 00402e55: xor ecx, ss:[ebp+0xffffffffffffffe4]
         // 00402e58: add ecx, edi
         // 00402e5a: lea edx, ds:[ecx+edx+0x106aa070]
         // 00402e61: mov ecx, ss:[ebp+0xffffffffffffffe8]
         // 00402e64: add esi, edx
         // 00402e66: mov ss:[ebp+0xfffffffffffffffc], edx
         // 00402e69: mov edi, ecx
         // 00402e6b: ror edi, b1 0xd
         // 00402e6e: mov edx, ecx
         // 00402e70: rol edx, b1 0xa
         // 00402e73: xor edi, edx
         // 00402e75: mov edx, ecx
         // 00402e77: ror edx, b1 0x2
         // 00402e7a: xor edi, edx
         // 00402e7c: mov edx, eax
         // 00402e7e: or edx, ecx
         // 00402e80: and edx, ss:[ebp+0xfffffffffffffff0]
         // 00402e83: add edi, ss:[ebp+0xfffffffffffffffc]
         // 00402e86: and ebx, ecx
         // 00402e88: or edx, ebx
         // 00402e8a: add edx, edi
         // 00402e8c: mov ss:[ebp+0xffffffffffffffe0], edx
         // 00402e8f: mov edx, ss:[ebp+0xffffffffffffff94]
         // 00402e92: mov ebx, edx
         // 00402e94: mov edi, edx
         // 00402e96: shr edx, b1 0xa
         // 00402e99: rol ebx, b1 0xf
         // 00402e9c: rol edi, b1 0xd
         // 00402e9f: xor ebx, edi
         // 00402ea1: xor ebx, edx
         // 00402ea3: add ebx, ss:[ebp+0xffffffffffffff80]
         // 00402ea6: mov edi, ss:[ebp+0xffffffffffffff60]
         // 00402eac: mov edx, edi
         // 00402eae: rol edx, b1 0xe
         // 00402eb1: ror edi, b1 0x7
         // 00402eb4: xor edx, edi
         // 00402eb6: mov edi, ss:[ebp+0xffffffffffffff60]
         // 00402ebc: shr edi, b1 0x3
         // 00402ebf: xor edx, edi
         // 00402ec1: add edx, ebx
         // 00402ec3: add edx, ss:[ebp+0xffffffffffffff5c]
         // 00402ec9: mov edi, esi
         // 00402ecb: mov ss:[ebp+0xffffffffffffff9c], edx
         // 00402ece: mov edx, esi
         // 00402ed0: ror edx, b1 0xb
         // 00402ed3: rol edi, b1 0x7
         // 00402ed6: xor edx, edi
         // 00402ed8: mov edi, esi
         // 00402eda: ror edi, b1 0x6
         // 00402edd: xor edx, edi
         // 00402edf: add edx, ss:[ebp+0xffffffffffffff9c]
         // 00402ee2: mov edi, ss:[ebp+0xfffffffffffffff8]
         // 00402ee5: xor edi, ss:[ebp+0xffffffffffffffdc]
         // 00402ee8: and edi, esi
         // 00402eea: xor edi, ss:[ebp+0xfffffffffffffff8]
         // 00402eed: add edi, edx
         // 00402eef: mov edx, ss:[ebp+0xffffffffffffffe4]
         // 00402ef2: lea edx, ds:[edi+edx+0x19a4c116]
         // 00402ef9: add ss:[ebp+0xfffffffffffffff0], edx
         // 00402efc: mov ss:[ebp+0xfffffffffffffffc], edx
         // 00402eff: mov edx, ss:[ebp+0xffffffffffffffe0]
         // 00402f02: mov ebx, edx
         // 00402f04: ror ebx, b1 0xd
         // 00402f07: mov edi, edx
         // 00402f09: rol edi, b1 0xa
         // 00402f0c: xor ebx, edi
         // 00402f0e: mov edi, edx
         // 00402f10: ror edi, b1 0x2
         // 00402f13: xor ebx, edi
         // 00402f15: add ebx, ss:[ebp+0xfffffffffffffffc]
         // 00402f18: mov edi, ecx
         // 00402f1a: or edi, edx
         // 00402f1c: and edi, eax
         // 00402f1e: mov ss:[ebp+0xffffffffffffffe4], edi
         // 00402f21: mov edi, ecx
         // 00402f23: and edi, edx
         // 00402f25: mov edx, ss:[ebp+0xffffffffffffffe4]
         // 00402f28: or edx, edi
         // 00402f2a: add edx, ebx
         // 00402f2c: mov ss:[ebp+0xffffffffffffffe4], edx
         // 00402f2f: mov edx, ss:[ebp+0xffffffffffffff98]
         // 00402f32: mov ebx, edx
         // 00402f34: mov edi, edx
         // 00402f36: rol ebx, b1 0xf
         // 00402f39: rol edi, b1 0xd
         // 00402f3c: xor ebx, edi
         // 00402f3e: mov edi, ss:[ebp+0xffffffffffffff64]
         // 00402f44: shr edx, b1 0xa
         // 00402f47: xor ebx, edx
         // 00402f49: add ebx, ss:[ebp+0xffffffffffffff84]
         // 00402f4c: mov edx, edi
         // 00402f4e: rol edx, b1 0xe
         // 00402f51: ror edi, b1 0x7
         // 00402f54: xor edx, edi
         // 00402f56: mov edi, ss:[ebp+0xffffffffffffff64]
         // 00402f5c: shr edi, b1 0x3
         // 00402f5f: xor edx, edi
         // 00402f61: add edx, ebx
         // 00402f63: add edx, ss:[ebp+0xffffffffffffff60]
         // 00402f69: mov ss:[ebp+0xffffffffffffffa0], edx
         // 00402f6c: mov edx, ss:[ebp+0xfffffffffffffff0]
         // 00402f6f: mov edi, edx
         // 00402f71: ror edi, b1 0xb
         // 00402f74: mov ebx, edx
         // 00402f76: rol ebx, b1 0x7
         // 00402f79: xor edi, ebx
         // 00402f7b: mov ebx, edx
         // 00402f7d: ror ebx, b1 0x6
         // 00402f80: xor edi, ebx
         // 00402f82: add edi, ss:[ebp+0xffffffffffffffa0]
         // 00402f85: mov ebx, ss:[ebp+0xffffffffffffffdc]
         // 00402f88: xor ebx, esi
         // 00402f8a: and ebx, edx
         // 00402f8c: xor ebx, ss:[ebp+0xffffffffffffffdc]
         // 00402f8f: mov edx, ss:[ebp+0xfffffffffffffff8]
         // 00402f92: add ebx, edi
         // 00402f94: lea edx, ds:[ebx+edx+0x1e376c08]
         // 00402f9b: add eax, edx
         // 00402f9d: mov ss:[ebp+0xfffffffffffffffc], edx
         // 00402fa0: mov edx, ss:[ebp+0xffffffffffffffe4]
         // 00402fa3: mov ebx, edx
         // 00402fa5: mov edi, edx
         // 00402fa7: ror ebx, b1 0xd
         // 00402faa: rol edi, b1 0xa
         // 00402fad: xor ebx, edi
         // 00402faf: mov edi, edx
         // 00402fb1: ror edi, b1 0x2
         // 00402fb4: xor ebx, edi
         // 00402fb6: mov edi, ss:[ebp+0xffffffffffffffe0]
         // 00402fb9: or edx, edi
         // 00402fbb: add ebx, ss:[ebp+0xfffffffffffffffc]
         // 00402fbe: and edx, ecx
         // 00402fc0: mov ss:[ebp+0xfffffffffffffff8], edx
         // 00402fc3: mov edx, ss:[ebp+0xffffffffffffffe4]
         // 00402fc6: and edx, edi
         // 00402fc8: mov ss:[ebp+0xffffffffffffffe8], edx
         // 00402fcb: mov edx, ss:[ebp+0xfffffffffffffff8]
         // 00402fce: or edx, ss:[ebp+0xffffffffffffffe8]
         // 00402fd1: add edx, ebx
         // 00402fd3: mov ss:[ebp+0xfffffffffffffff8], edx
         // 00402fd6: mov edx, ss:[ebp+0xffffffffffffff9c]
         // 00402fd9: mov ebx, edx
         // 00402fdb: mov edi, edx
         // 00402fdd: shr edx, b1 0xa
         // 00402fe0: rol ebx, b1 0xf
         // 00402fe3: rol edi, b1 0xd
         // 00402fe6: xor ebx, edi
         // 00402fe8: mov edi, ss:[ebp+0xffffffffffffff68]
         // 00402fee: xor ebx, edx
         // 00402ff0: add ebx, ss:[ebp+0xffffffffffffff88]
         // 00402ff3: mov edx, edi
         // 00402ff5: rol edx, b1 0xe
         // 00402ff8: ror edi, b1 0x7
         // 00402ffb: xor edx, edi
         // 00402ffd: mov edi, ss:[ebp+0xffffffffffffff68]
         // 00403003: shr edi, b1 0x3
         // 00403006: xor edx, edi
         // 00403008: add edx, ebx
         // 0040300a: add edx, ss:[ebp+0xffffffffffffff64]
         // 00403010: mov edi, eax
         // 00403012: mov ss:[ebp+0xffffffffffffffa4], edx
         // 00403015: mov edx, eax
         // 00403017: ror edx, b1 0xb
         // 0040301a: rol edi, b1 0x7
         // 0040301d: xor edx, edi
         // 0040301f: mov edi, eax
         // 00403021: ror edi, b1 0x6
         // 00403024: xor edx, edi
         // 00403026: add edx, ss:[ebp+0xffffffffffffffa4]
         // 00403029: mov edi, esi
         // 0040302b: xor edi, ss:[ebp+0xfffffffffffffff0]
         // 0040302e: and edi, eax
         // 00403030: xor edi, esi
         // 00403032: add edi, edx
         // 00403034: mov edx, ss:[ebp+0xffffffffffffffdc]
         // 00403037: lea edx, ds:[edi+edx+0x2748774c]
         // 0040303e: mov ss:[ebp+0xfffffffffffffffc], edx
         // 00403041: add ecx, edx
         // 00403043: mov edx, ss:[ebp+0xfffffffffffffff8]
         // 00403046: mov ebx, edx
         // 00403048: ror ebx, b1 0xd
         // 0040304b: mov edi, edx
         // 0040304d: rol edi, b1 0xa
         // 00403050: xor ebx, edi
         // 00403052: mov edi, edx
         // 00403054: ror edi, b1 0x2
         // 00403057: xor ebx, edi
         // 00403059: add ebx, ss:[ebp+0xfffffffffffffffc]
         // 0040305c: mov edi, ss:[ebp+0xffffffffffffffe4]
         // 0040305f: or edi, edx
         // 00403061: and edi, ss:[ebp+0xffffffffffffffe0]
         // 00403064: mov ss:[ebp+0xffffffffffffffdc], edi
         // 00403067: mov edi, ss:[ebp+0xffffffffffffffe4]
         // 0040306a: and edi, edx
         // 0040306c: mov edx, ss:[ebp+0xffffffffffffffdc]
         // 0040306f: or edx, edi
         // 00403071: add edx, ebx
         // 00403073: mov ss:[ebp+0xffffffffffffffdc], edx
         // 00403076: mov edx, ss:[ebp+0xffffffffffffff6c]
         // 0040307c: mov ebx, edx
         // 0040307e: rol ebx, b1 0xe
         // 00403081: mov edi, edx
         // 00403083: ror edi, b1 0x7
         // 00403086: xor ebx, edi
         // 00403088: mov edi, ss:[ebp+0xffffffffffffffa0]
         // 0040308b: shr edx, b1 0x3
         // 0040308e: xor ebx, edx
         // 00403090: add ebx, ss:[ebp+0xffffffffffffff8c]
         // 00403093: mov edx, edi
         // 00403095: rol edx, b1 0xf
         // 00403098: rol edi, b1 0xd
         // 0040309b: xor edx, edi
         // 0040309d: mov edi, ss:[ebp+0xffffffffffffffa0]
         // 004030a0: shr edi, b1 0xa
         // 004030a3: xor edx, edi
         // 004030a5: add edx, ebx
         // 004030a7: add edx, ss:[ebp+0xffffffffffffff68]
         // 004030ad: mov edi, ecx
         // 004030af: ror edi, b1 0xb
         // 004030b2: mov ss:[ebp+0xffffffffffffffa8], edx
         // 004030b5: mov edx, ecx
         // 004030b7: rol edx, b1 0x7
         // 004030ba: xor edi, edx
         // 004030bc: mov edx, ecx
         // 004030be: ror edx, b1 0x6
         // 004030c1: xor edi, edx
         // 004030c3: add edi, ss:[ebp+0xffffffffffffffa8]
         // 004030c6: mov edx, ss:[ebp+0xfffffffffffffff0]
         // 004030c9: mov ebx, edx
         // 004030cb: xor ebx, eax
         // 004030cd: and ebx, ecx
         // 004030cf: xor ebx, edx
         // 004030d1: mov edx, ss:[ebp+0xffffffffffffffdc]
         // 004030d4: add ebx, edi
         // 004030d6: lea esi, ds:[ebx+esi+0x34b0bcb5]
         // 004030dd: add ss:[ebp+0xffffffffffffffe0], esi
         // 004030e0: mov ebx, ss:[ebp+0xfffffffffffffff8]
         // 004030e3: mov ss:[ebp+0xfffffffffffffffc], esi
         // 004030e6: mov edi, edx
         // 004030e8: ror edi, b1 0xd
         // 004030eb: mov esi, edx
         // 004030ed: rol esi, b1 0xa
         // 004030f0: xor edi, esi
         // 004030f2: mov esi, edx
         // 004030f4: ror esi, b1 0x2
         // 004030f7: xor edi, esi
         // 004030f9: mov esi, ss:[ebp+0xfffffffffffffff8]
         // 004030fc: add edi, ss:[ebp+0xfffffffffffffffc]
         // 004030ff: or esi, edx
         // 00403101: and esi, ss:[ebp+0xffffffffffffffe4]
         // 00403104: and ebx, edx
         // 00403106: or esi, ebx
         // 00403108: add esi, edi
         // 0040310a: mov ss:[ebp+0xfffffffffffffff4], esi
         // 0040310d: mov esi, ss:[ebp+0xffffffffffffff70]
         // 00403113: mov ebx, esi
         // 00403115: rol ebx, b1 0xe
         // 00403118: mov edi, esi
         // 0040311a: ror edi, b1 0x7
         // 0040311d: xor ebx, edi
         // 0040311f: shr esi, b1 0x3
         // 00403122: xor ebx, esi
         // 00403124: add ebx, ss:[ebp+0xffffffffffffff90]
         // 00403127: mov edi, ss:[ebp+0xffffffffffffffa4]
         // 0040312a: mov esi, edi
         // 0040312c: rol esi, b1 0xf
         // 0040312f: rol edi, b1 0xd
         // 00403132: xor esi, edi
         // 00403134: mov edi, ss:[ebp+0xffffffffffffffa4]
         // 00403137: shr edi, b1 0xa
         // 0040313a: xor esi, edi
         // 0040313c: add esi, ebx
         // 0040313e: add esi, ss:[ebp+0xffffffffffffff6c]
         // 00403144: mov ss:[ebp+0xffffffffffffffac], esi
         // 00403147: mov esi, ss:[ebp+0xffffffffffffffe0]
         // 0040314a: mov edi, esi
         // 0040314c: ror edi, b1 0xb
         // 0040314f: mov ebx, esi
         // 00403151: rol ebx, b1 0x7
         // 00403154: xor edi, ebx
         // 00403156: mov ebx, esi
         // 00403158: ror ebx, b1 0x6
         // 0040315b: xor edi, ebx
         // 0040315d: add edi, ss:[ebp+0xffffffffffffffac]
         // 00403160: mov ebx, eax
         // 00403162: xor ebx, ecx
         // 00403164: and ebx, esi
         // 00403166: mov esi, ss:[ebp+0xfffffffffffffff0]
         // 00403169: xor ebx, eax
         // 0040316b: add ebx, edi
         // 0040316d: lea esi, ds:[ebx+esi+0x391c0cb3]
         // 00403174: add ss:[ebp+0xffffffffffffffe4], esi
         // 00403177: mov ss:[ebp+0xfffffffffffffffc], esi
         // 0040317a: mov esi, ss:[ebp+0xfffffffffffffff4]
         // 0040317d: mov ebx, esi
         // 0040317f: ror ebx, b1 0xd
         // 00403182: mov edi, esi
         // 00403184: rol edi, b1 0xa
         // 00403187: xor ebx, edi
         // 00403189: mov edi, esi
         // 0040318b: ror edi, b1 0x2
         // 0040318e: xor ebx, edi
         // 00403190: add ebx, ss:[ebp+0xfffffffffffffffc]
         // 00403193: mov edi, edx
         // 00403195: or edi, esi
         // 00403197: and edi, ss:[ebp+0xfffffffffffffff8]
         // 0040319a: mov ss:[ebp+0xffffffffffffffdc], edi
         // 0040319d: mov edi, edx
         // 0040319f: and edi, esi
         // 004031a1: mov esi, ss:[ebp+0xffffffffffffffdc]
         // 004031a4: or esi, edi
         // 004031a6: add esi, ebx
         // 004031a8: mov ss:[ebp+0xfffffffffffffff0], esi
         // 004031ab: mov esi, ss:[ebp+0xffffffffffffff74]
         // 004031b1: mov ebx, esi
         // 004031b3: rol ebx, b1 0xe
         // 004031b6: mov edi, esi
         // 004031b8: ror edi, b1 0x7
         // 004031bb: xor ebx, edi
         // 004031bd: mov edi, ss:[ebp+0xffffffffffffffa8]
         // 004031c0: shr esi, b1 0x3
         // 004031c3: xor ebx, esi
         // 004031c5: add ebx, ss:[ebp+0xffffffffffffff94]
         // 004031c8: mov esi, edi
         // 004031ca: rol esi, b1 0xf
         // 004031cd: rol edi, b1 0xd
         // 004031d0: xor esi, edi
         // 004031d2: mov edi, ss:[ebp+0xffffffffffffffa8]
         // 004031d5: shr edi, b1 0xa
         // 004031d8: xor esi, edi
         // 004031da: add esi, ebx
         // 004031dc: add esi, ss:[ebp+0xffffffffffffff70]
         // 004031e2: mov ss:[ebp+0xffffffffffffffb0], esi
         // 004031e5: mov esi, ss:[ebp+0xffffffffffffffe4]
         // 004031e8: mov edi, esi
         // 004031ea: ror edi, b1 0xb
         // 004031ed: mov ebx, esi
         // 004031ef: rol ebx, b1 0x7
         // 004031f2: xor edi, ebx
         // 004031f4: ror esi, b1 0x6
         // 004031f7: xor edi, esi
         // 004031f9: add edi, ss:[ebp+0xffffffffffffffb0]
         // 004031fc: mov esi, ecx
         // 004031fe: xor esi, ss:[ebp+0xffffffffffffffe0]
         // 00403201: and esi, ss:[ebp+0xffffffffffffffe4]
         // 00403204: xor esi, ecx
         // 00403206: add esi, edi
         // 00403208: lea eax, ds:[esi+eax+0x4ed8aa4a]
         // 0040320f: add ss:[ebp+0xfffffffffffffff8], eax
         // 00403212: mov esi, ss:[ebp+0xfffffffffffffff0]
         // 00403215: mov ss:[ebp+0xfffffffffffffffc], eax
         // 00403218: mov edi, ss:[ebp+0xfffffffffffffff4]
         // 0040321b: mov ebx, esi
         // 0040321d: ror ebx, b1 0xd
         // 00403220: mov eax, esi
         // 00403222: rol eax, b1 0xa
         // 00403225: xor ebx, eax
         // 00403227: mov eax, esi
         // 00403229: ror eax, b1 0x2
         // 0040322c: xor ebx, eax
         // 0040322e: add ebx, ss:[ebp+0xfffffffffffffffc]
         // 00403231: mov eax, edi
         // 00403233: or eax, esi
         // 00403235: and eax, edx
         // 00403237: and edi, esi
         // 00403239: or eax, edi
         // 0040323b: add eax, ebx
         // 0040323d: mov ss:[ebp+0xffffffffffffffec], eax
         // 00403240: mov eax, ss:[ebp+0xffffffffffffff78]
         // 00403246: mov ebx, eax
         // 00403248: mov edi, eax
         // 0040324a: shr eax, b1 0x3
         // 0040324d: rol ebx, b1 0xe
         // 00403250: ror edi, b1 0x7
         // 00403253: xor ebx, edi
         // 00403255: mov edi, ss:[ebp+0xffffffffffffffac]
         // 00403258: xor ebx, eax
         // 0040325a: add ebx, ss:[ebp+0xffffffffffffff98]
         // 0040325d: mov eax, edi
         // 0040325f: rol eax, b1 0xf
         // 00403262: rol edi, b1 0xd
         // 00403265: xor eax, edi
         // 00403267: mov edi, ss:[ebp+0xffffffffffffffac]
         // 0040326a: shr edi, b1 0xa
         // 0040326d: xor eax, edi
         // 0040326f: add eax, ebx
         // 00403271: add eax, ss:[ebp+0xffffffffffffff74]
         // 00403277: mov ss:[ebp+0xffffffffffffffb4], eax
         // 0040327a: mov eax, ss:[ebp+0xfffffffffffffff8]
         // 0040327d: mov edi, eax
         // 0040327f: ror edi, b1 0xb
         // 00403282: mov ebx, eax
         // 00403284: rol ebx, b1 0x7
         // 00403287: xor edi, ebx
         // 00403289: ror eax, b1 0x6
         // 0040328c: xor edi, eax
         // 0040328e: mov eax, ss:[ebp+0xffffffffffffffe4]
         // 00403291: xor eax, ss:[ebp+0xffffffffffffffe0]
         // 00403294: add edi, ss:[ebp+0xffffffffffffffb4]
         // 00403297: and eax, ss:[ebp+0xfffffffffffffff8]
         // 0040329a: mov ebx, esi
         // 0040329c: xor eax, ss:[ebp+0xffffffffffffffe0]
         // 0040329f: add eax, edi
         // 004032a1: lea ecx, ds:[eax+ecx+0x5b9cca4f]
         // 004032a8: mov eax, ss:[ebp+0xffffffffffffffec]
         // 004032ab: mov ss:[ebp+0xfffffffffffffffc], ecx
         // 004032ae: add edx, ecx
         // 004032b0: mov edi, eax
         // 004032b2: ror edi, b1 0xd
         // 004032b5: mov ecx, eax
         // 004032b7: rol ecx, b1 0xa
         // 004032ba: xor edi, ecx
         // 004032bc: mov ecx, eax
         // 004032be: ror ecx, b1 0x2
         // 004032c1: xor edi, ecx
         // 004032c3: add edi, ss:[ebp+0xfffffffffffffffc]
         // 004032c6: mov ecx, esi
         // 004032c8: or ecx, eax
         // 004032ca: and ecx, ss:[ebp+0xfffffffffffffff4]
         // 004032cd: and ebx, eax
         // 004032cf: or ecx, ebx
         // 004032d1: add ecx, edi
         // 004032d3: mov ss:[ebp+0xffffffffffffffe8], ecx
         // 004032d6: mov ecx, ss:[ebp+0xffffffffffffff7c]
         // 004032dc: mov ebx, ecx
         // 004032de: mov edi, ecx
         // 004032e0: shr ecx, b1 0x3
         // 004032e3: rol ebx, b1 0xe
         // 004032e6: ror edi, b1 0x7
         // 004032e9: xor ebx, edi
         // 004032eb: xor ebx, ecx
         // 004032ed: add ebx, ss:[ebp+0xffffffffffffff9c]
         // 004032f0: mov edi, ss:[ebp+0xffffffffffffffb0]
         // 004032f3: mov ecx, edi
         // 004032f5: rol ecx, b1 0xf
         // 004032f8: rol edi, b1 0xd
         // 004032fb: xor ecx, edi
         // 004032fd: mov edi, ss:[ebp+0xffffffffffffffb0]
         // 00403300: shr edi, b1 0xa
         // 00403303: xor ecx, edi
         // 00403305: add ecx, ebx
         // 00403307: add ecx, ss:[ebp+0xffffffffffffff78]
         // 0040330d: mov edi, edx
         // 0040330f: mov ss:[ebp+0xffffffffffffffb8], ecx
         // 00403312: mov ecx, edx
         // 00403314: ror ecx, b1 0xb
         // 00403317: rol edi, b1 0x7
         // 0040331a: xor ecx, edi
         // 0040331c: mov edi, edx
         // 0040331e: ror edi, b1 0x6
         // 00403321: xor ecx, edi
         // 00403323: add ecx, ss:[ebp+0xffffffffffffffb8]
         // 00403326: mov edi, ss:[ebp+0xffffffffffffffe4]
         // 00403329: xor edi, ss:[ebp+0xfffffffffffffff8]
         // 0040332c: and edi, edx
         // 0040332e: xor edi, ss:[ebp+0xffffffffffffffe4]
         // 00403331: add edi, ecx
         // 00403333: mov ecx, ss:[ebp+0xffffffffffffffe0]
         // 00403336: lea ecx, ds:[edi+ecx+0x682e6ff3]
         // 0040333d: add ss:[ebp+0xfffffffffffffff4], ecx
         // 00403340: mov ss:[ebp+0xfffffffffffffffc], ecx
         // 00403343: mov ecx, ss:[ebp+0xffffffffffffffe8]
         // 00403346: mov ebx, ecx
         // 00403348: ror ebx, b1 0xd
         // 0040334b: mov edi, ecx
         // 0040334d: rol edi, b1 0xa
         // 00403350: xor ebx, edi
         // 00403352: mov edi, ecx
         // 00403354: ror edi, b1 0x2
         // 00403357: xor ebx, edi
         // 00403359: add ebx, ss:[ebp+0xfffffffffffffffc]
         // 0040335c: mov edi, eax
         // 0040335e: or edi, ecx
         // 00403360: and edi, esi
         // 00403362: mov ss:[ebp+0xffffffffffffffdc], edi
         // 00403365: mov edi, eax
         // 00403367: and edi, ecx
         // 00403369: mov ecx, ss:[ebp+0xffffffffffffffdc]
         // 0040336c: or ecx, edi
         // 0040336e: add ecx, ebx
         // 00403370: mov ss:[ebp+0xffffffffffffffe0], ecx
         // 00403373: mov ecx, ss:[ebp+0xffffffffffffff80]
         // 00403376: mov ebx, ecx
         // 00403378: mov edi, ecx
         // 0040337a: rol ebx, b1 0xe
         // 0040337d: ror edi, b1 0x7
         // 00403380: xor ebx, edi
         // 00403382: mov edi, ss:[ebp+0xffffffffffffffb4]
         // 00403385: shr ecx, b1 0x3
         // 00403388: xor ebx, ecx
         // 0040338a: add ebx, ss:[ebp+0xffffffffffffffa0]
         // 0040338d: mov ecx, edi
         // 0040338f: rol ecx, b1 0xf
         // 00403392: rol edi, b1 0xd
         // 00403395: xor ecx, edi
         // 00403397: mov edi, ss:[ebp+0xffffffffffffffb4]
         // 0040339a: shr edi, b1 0xa
         // 0040339d: xor ecx, edi
         // 0040339f: add ecx, ebx
         // 004033a1: add ecx, ss:[ebp+0xffffffffffffff7c]
         // 004033a7: mov ss:[ebp+0xffffffffffffffbc], ecx
         // 004033aa: mov ecx, ss:[ebp+0xfffffffffffffff4]
         // 004033ad: mov edi, ecx
         // 004033af: ror edi, b1 0xb
         // 004033b2: mov ebx, ecx
         // 004033b4: rol ebx, b1 0x7
         // 004033b7: xor edi, ebx
         // 004033b9: mov ebx, ecx
         // 004033bb: ror ebx, b1 0x6
         // 004033be: xor edi, ebx
         // 004033c0: add edi, ss:[ebp+0xffffffffffffffbc]
         // 004033c3: mov ebx, ss:[ebp+0xfffffffffffffff8]
         // 004033c6: xor ebx, edx
         // 004033c8: and ebx, ecx
         // 004033ca: xor ebx, ss:[ebp+0xfffffffffffffff8]
         // 004033cd: mov ecx, ss:[ebp+0xffffffffffffffe4]
         // 004033d0: add ebx, edi
         // 004033d2: lea ecx, ds:[ebx+ecx+0x748f82ee]
         // 004033d9: add esi, ecx
         // 004033db: mov ss:[ebp+0xfffffffffffffffc], ecx
         // 004033de: mov ecx, ss:[ebp+0xffffffffffffffe0]
         // 004033e1: mov ebx, ecx
         // 004033e3: mov edi, ecx
         // 004033e5: ror ebx, b1 0xd
         // 004033e8: rol edi, b1 0xa
         // 004033eb: xor ebx, edi
         // 004033ed: mov edi, ecx
         // 004033ef: ror edi, b1 0x2
         // 004033f2: xor ebx, edi
         // 004033f4: add ebx, ss:[ebp+0xfffffffffffffffc]
         // 004033f7: mov edi, ss:[ebp+0xffffffffffffffe8]
         // 004033fa: or edi, ecx
         // 004033fc: and edi, eax
         // 004033fe: mov ss:[ebp+0xffffffffffffffe4], edi
         // 00403401: mov edi, ss:[ebp+0xffffffffffffffe8]
         // 00403404: and edi, ecx
         // 00403406: mov ecx, ss:[ebp+0xffffffffffffffe4]
         // 00403409: or ecx, edi
         // 0040340b: add ecx, ebx
         // 0040340d: mov ss:[ebp+0xffffffffffffffe4], ecx
         // 00403410: mov ecx, ss:[ebp+0xffffffffffffff84]
         // 00403413: mov ebx, ecx
         // 00403415: mov edi, ecx
         // 00403417: shr ecx, b1 0x3
         // 0040341a: rol ebx, b1 0xe
         // 0040341d: ror edi, b1 0x7
         // 00403420: xor ebx, edi
         // 00403422: mov edi, ss:[ebp+0xffffffffffffffb8]
         // 00403425: xor ebx, ecx
         // 00403427: add ebx, ss:[ebp+0xffffffffffffffa4]
         // 0040342a: mov ecx, edi
         // 0040342c: rol ecx, b1 0xf
         // 0040342f: rol edi, b1 0xd
         // 00403432: xor ecx, edi
         // 00403434: mov edi, ss:[ebp+0xffffffffffffffb8]
         // 00403437: shr edi, b1 0xa
         // 0040343a: xor ecx, edi
         // 0040343c: add ecx, ebx
         // 0040343e: add ecx, ss:[ebp+0xffffffffffffff80]
         // 00403441: mov edi, esi
         // 00403443: mov ss:[ebp+0xffffffffffffffc0], ecx
         // 00403446: mov ecx, esi
         // 00403448: ror ecx, b1 0xb
         // 0040344b: rol edi, b1 0x7
         // 0040344e: xor ecx, edi
         // 00403450: mov edi, esi
         // 00403452: ror edi, b1 0x6
         // 00403455: xor ecx, edi
         // 00403457: add ecx, ss:[ebp+0xffffffffffffffc0]
         // 0040345a: mov edi, edx
         // 0040345c: xor edi, ss:[ebp+0xfffffffffffffff4]
         // 0040345f: and edi, esi
         // 00403461: xor edi, edx
         // 00403463: add edi, ecx
         // 00403465: mov ecx, ss:[ebp+0xfffffffffffffff8]
         // 00403468: lea ecx, ds:[edi+ecx+0x78a5636f]
         // 0040346f: add eax, ecx
         // 00403471: mov ss:[ebp+0xfffffffffffffffc], ecx
         // 00403474: mov ecx, ss:[ebp+0xffffffffffffffe4]
         // 00403477: mov edi, ecx
         // 00403479: ror edi, b1 0xd
         // 0040347c: mov ebx, ecx
         // 0040347e: rol ebx, b1 0xa
         // 00403481: xor edi, ebx
         // 00403483: mov ebx, ecx
         // 00403485: or ecx, ss:[ebp+0xffffffffffffffe0]
         // 00403488: ror ebx, b1 0x2
         // 0040348b: and ecx, ss:[ebp+0xffffffffffffffe8]
         // 0040348e: xor edi, ebx
         // 00403490: add edi, ss:[ebp+0xfffffffffffffffc]
         // 00403493: mov ebx, ss:[ebp+0xffffffffffffffe4]
         // 00403496: and ebx, ss:[ebp+0xffffffffffffffe0]
         // 00403499: or ecx, ebx
         // 0040349b: add ecx, edi
         // 0040349d: mov ss:[ebp+0xfffffffffffffff8], ecx
         // 004034a0: mov ecx, ss:[ebp+0xffffffffffffff88]
         // 004034a3: mov ebx, ecx
         // 004034a5: rol ebx, b1 0xe
         // 004034a8: mov edi, ecx
         // 004034aa: ror edi, b1 0x7
         // 004034ad: xor ebx, edi
         // 004034af: mov edi, ss:[ebp+0xffffffffffffffbc]
         // 004034b2: shr ecx, b1 0x3
         // 004034b5: xor ebx, ecx
         // 004034b7: add ebx, ss:[ebp+0xffffffffffffffa8]
         // 004034ba: mov ecx, edi
         // 004034bc: rol ecx, b1 0xf
         // 004034bf: rol edi, b1 0xd
         // 004034c2: xor ecx, edi
         // 004034c4: mov edi, ss:[ebp+0xffffffffffffffbc]
         // 004034c7: shr edi, b1 0xa
         // 004034ca: xor ecx, edi
         // 004034cc: add ecx, ebx
         // 004034ce: add ecx, ss:[ebp+0xffffffffffffff84]
         // 004034d1: mov edi, eax
         // 004034d3: ror edi, b1 0xb
         // 004034d6: mov ss:[ebp+0xffffffffffffffc4], ecx
         // 004034d9: mov ecx, eax
         // 004034db: rol ecx, b1 0x7
         // 004034de: xor edi, ecx
         // 004034e0: mov ecx, eax
         // 004034e2: ror ecx, b1 0x6
         // 004034e5: xor edi, ecx
         // 004034e7: add edi, ss:[ebp+0xffffffffffffffc4]
         // 004034ea: mov ecx, ss:[ebp+0xfffffffffffffff4]
         // 004034ed: mov ebx, ecx
         // 004034ef: xor ebx, esi
         // 004034f1: and ebx, eax
         // 004034f3: xor ebx, ecx
         // 004034f5: mov ecx, ss:[ebp+0xfffffffffffffff8]
         // 004034f8: add ebx, edi
         // 004034fa: lea edx, ds:[ebx+edx+0xffffffff84c87814]
         // 00403501: add ss:[ebp+0xffffffffffffffe8], edx
         // 00403504: mov ebx, ss:[ebp+0xffffffffffffffe4]
         // 00403507: mov ss:[ebp+0xfffffffffffffffc], edx
         // 0040350a: mov edi, ecx
         // 0040350c: ror edi, b1 0xd
         // 0040350f: mov edx, ecx
         // 00403511: rol edx, b1 0xa
         // 00403514: xor edi, edx
         // 00403516: mov edx, ecx
         // 00403518: ror edx, b1 0x2
         // 0040351b: xor edi, edx
         // 0040351d: add edi, ss:[ebp+0xfffffffffffffffc]
         // 00403520: mov edx, ss:[ebp+0xffffffffffffffe4]
         // 00403523: or edx, ecx
         // 00403525: and edx, ss:[ebp+0xffffffffffffffe0]
         // 00403528: and ebx, ecx
         // 0040352a: or edx, ebx
         // 0040352c: add edx, edi
         // 0040352e: mov ss:[ebp+0xffffffffffffffdc], edx
         // 00403531: mov edx, ss:[ebp+0xffffffffffffff8c]
         // 00403534: mov ebx, edx
         // 00403536: rol ebx, b1 0xe
         // 00403539: mov edi, edx
         // 0040353b: ror edi, b1 0x7
         // 0040353e: xor ebx, edi
         // 00403540: mov edi, ss:[ebp+0xffffffffffffffc0]
         // 00403543: shr edx, b1 0x3
         // 00403546: xor ebx, edx
         // 00403548: mov edx, edi
         // 0040354a: rol edx, b1 0xf
         // 0040354d: rol edi, b1 0xd
         // 00403550: xor edx, edi
         // 00403552: mov edi, ss:[ebp+0xffffffffffffffc0]
         // 00403555: add ebx, ss:[ebp+0xffffffffffffffac]
         // 00403558: shr edi, b1 0xa
         // 0040355b: xor edx, edi
         // 0040355d: add edx, ebx
         // 0040355f: add edx, ss:[ebp+0xffffffffffffff88]
         // 00403562: mov ss:[ebp+0xffffffffffffffc8], edx
         // 00403565: mov edx, ss:[ebp+0xffffffffffffffe8]
         // 00403568: mov edi, edx
         // 0040356a: ror edi, b1 0xb
         // 0040356d: mov ebx, edx
         // 0040356f: rol ebx, b1 0x7
         // 00403572: xor edi, ebx
         // 00403574: mov ebx, edx
         // 00403576: ror ebx, b1 0x6
         // 00403579: xor edi, ebx
         // 0040357b: add edi, ss:[ebp+0xffffffffffffffc8]
         // 0040357e: mov ebx, esi
         // 00403580: xor ebx, eax
         // 00403582: and ebx, edx
         // 00403584: mov edx, ss:[ebp+0xfffffffffffffff4]
         // 00403587: xor ebx, esi
         // 00403589: add ebx, edi
         // 0040358b: lea edx, ds:[ebx+edx+0xffffffff8cc70208]
         // 00403592: add ss:[ebp+0xffffffffffffffe0], edx
         // 00403595: mov ss:[ebp+0xfffffffffffffffc], edx
         // 00403598: mov edx, ss:[ebp+0xffffffffffffffdc]
         // 0040359b: mov ebx, edx
         // 0040359d: mov edi, edx
         // 0040359f: ror ebx, b1 0xd
         // 004035a2: rol edi, b1 0xa
         // 004035a5: xor ebx, edi
         // 004035a7: mov edi, edx
         // 004035a9: ror edi, b1 0x2
         // 004035ac: xor ebx, edi
         // 004035ae: add ebx, ss:[ebp+0xfffffffffffffffc]
         // 004035b1: mov edi, ecx
         // 004035b3: or edi, edx
         // 004035b5: and edi, ss:[ebp+0xffffffffffffffe4]
         // 004035b8: mov ss:[ebp+0xfffffffffffffff8], edi
         // 004035bb: mov edi, ecx
         // 004035bd: and edi, edx
         // 004035bf: mov edx, ss:[ebp+0xfffffffffffffff8]
         // 004035c2: or edx, edi
         // 004035c4: add edx, ebx
         // 004035c6: mov ss:[ebp+0xfffffffffffffff4], edx
         // 004035c9: mov edx, ss:[ebp+0xffffffffffffff90]
         // 004035cc: mov ebx, edx
         // 004035ce: mov edi, edx
         // 004035d0: shr edx, b1 0x3
         // 004035d3: rol ebx, b1 0xe
         // 004035d6: ror edi, b1 0x7
         // 004035d9: xor ebx, edi
         // 004035db: mov edi, ss:[ebp+0xffffffffffffffc4]
         // 004035de: xor ebx, edx
         // 004035e0: add ebx, ss:[ebp+0xffffffffffffffb0]
         // 004035e3: mov edx, edi
         // 004035e5: rol edx, b1 0xf
         // 004035e8: rol edi, b1 0xd
         // 004035eb: xor edx, edi
         // 004035ed: mov edi, ss:[ebp+0xffffffffffffffc4]
         // 004035f0: shr edi, b1 0xa
         // 004035f3: xor edx, edi
         // 004035f5: add edx, ebx
         // 004035f7: add edx, ss:[ebp+0xffffffffffffff8c]
         // 004035fa: mov ss:[ebp+0xffffffffffffffcc], edx
         // 004035fd: mov edx, ss:[ebp+0xffffffffffffffe0]
         // 00403600: mov edi, edx
         // 00403602: mov ebx, edx
         // 00403604: ror edi, b1 0xb
         // 00403607: rol ebx, b1 0x7
         // 0040360a: xor edi, ebx
         // 0040360c: ror edx, b1 0x6
         // 0040360f: xor edi, edx
         // 00403611: add edi, ss:[ebp+0xffffffffffffffcc]
         // 00403614: mov edx, eax
         // 00403616: xor edx, ss:[ebp+0xffffffffffffffe8]
         // 00403619: and edx, ss:[ebp+0xffffffffffffffe0]
         // 0040361c: xor edx, eax
         // 0040361e: add edx, edi
         // 00403620: lea esi, ds:[edx+esi+0xffffffff90befffa]
         // 00403627: mov ss:[ebp+0xfffffffffffffffc], esi
         // 0040362a: mov edx, ss:[ebp+0xffffffffffffffe4]
         // 0040362d: add edx, esi
         // 0040362f: mov esi, ss:[ebp+0xfffffffffffffff4]
         // 00403632: mov ebx, esi
         // 00403634: mov edi, esi
         // 00403636: ror ebx, b1 0xd
         // 00403639: rol edi, b1 0xa
         // 0040363c: xor ebx, edi
         // 0040363e: mov edi, esi
         // 00403640: ror edi, b1 0x2
         // 00403643: xor ebx, edi
         // 00403645: add ebx, ss:[ebp+0xfffffffffffffffc]
         // 00403648: mov edi, ss:[ebp+0xffffffffffffffdc]
         // 0040364b: or edi, esi
         // 0040364d: and edi, ecx
         // 0040364f: mov ss:[ebp+0xfffffffffffffff8], edi
         // 00403652: mov edi, ss:[ebp+0xffffffffffffffdc]
         // 00403655: and edi, esi
         // 00403657: mov esi, ss:[ebp+0xfffffffffffffff8]
         // 0040365a: or esi, edi
         // 0040365c: add esi, ebx
         // 0040365e: mov ss:[ebp+0xfffffffffffffff0], esi
         // 00403661: mov esi, ss:[ebp+0xffffffffffffff94]
         // 00403664: mov ebx, esi
         // 00403666: mov edi, esi
         // 00403668: shr esi, b1 0x3
         // 0040366b: rol ebx, b1 0xe
         // 0040366e: ror edi, b1 0x7
         // 00403671: xor ebx, edi
         // 00403673: mov edi, ss:[ebp+0xffffffffffffffc8]
         // 00403676: xor ebx, esi
         // 00403678: add ebx, ss:[ebp+0xffffffffffffffb4]
         // 0040367b: mov esi, edi
         // 0040367d: rol esi, b1 0xf
         // 00403680: rol edi, b1 0xd
         // 00403683: xor esi, edi
         // 00403685: mov edi, ss:[ebp+0xffffffffffffffc8]
         // 00403688: shr edi, b1 0xa
         // 0040368b: xor esi, edi
         // 0040368d: add esi, ebx
         // 0040368f: add esi, ss:[ebp+0xffffffffffffff90]
         // 00403692: mov edi, edx
         // 00403694: mov ss:[ebp+0xffffffffffffffd0], esi
         // 00403697: mov esi, edx
         // 00403699: ror esi, b1 0xb
         // 0040369c: rol edi, b1 0x7
         // 0040369f: xor esi, edi
         // 004036a1: mov edi, edx
         // 004036a3: ror edi, b1 0x6
         // 004036a6: xor esi, edi
         // 004036a8: add esi, ss:[ebp+0xffffffffffffffd0]
         // 004036ab: mov edi, ss:[ebp+0xffffffffffffffe8]
         // 004036ae: xor edi, ss:[ebp+0xffffffffffffffe0]
         // 004036b1: and edi, edx
         // 004036b3: xor edi, ss:[ebp+0xffffffffffffffe8]
         // 004036b6: add edi, esi
         // 004036b8: lea eax, ds:[edi+eax+0xffffffffa4506ceb]
         // 004036bf: mov edi, ss:[ebp+0xfffffffffffffff4]
         // 004036c2: add ecx, eax
         // 004036c4: mov ss:[ebp+0xfffffffffffffffc], eax
         // 004036c7: mov eax, ss:[ebp+0xfffffffffffffff0]
         // 004036ca: mov ebx, eax
         // 004036cc: ror ebx, b1 0xd
         // 004036cf: mov esi, eax
         // 004036d1: rol esi, b1 0xa
         // 004036d4: xor ebx, esi
         // 004036d6: mov esi, eax
         // 004036d8: ror esi, b1 0x2
         // 004036db: xor ebx, esi
         // 004036dd: add ebx, ss:[ebp+0xfffffffffffffffc]
         // 004036e0: mov esi, edi
         // 004036e2: or esi, eax
         // 004036e4: and esi, ss:[ebp+0xffffffffffffffdc]
         // 004036e7: and edi, eax
         // 004036e9: mov eax, ss:[ebp+0xffffffffffffff98]
         // 004036ec: or esi, edi
         // 004036ee: add esi, ebx
         // 004036f0: mov ebx, eax
         // 004036f2: mov ss:[ebp+0xffffffffffffffec], esi
         // 004036f5: rol ebx, b1 0xe
         // 004036f8: mov edi, eax
         // 004036fa: shr eax, b1 0x3
         // 004036fd: ror edi, b1 0x7
         // 00403700: xor ebx, edi
         // 00403702: xor ebx, eax
         // 00403704: add ebx, ss:[ebp+0xffffffffffffffb8]
         // 00403707: mov edi, ss:[ebp+0xffffffffffffffcc]
         // 0040370a: mov eax, edi
         // 0040370c: rol eax, b1 0xf
         // 0040370f: rol edi, b1 0xd
         // 00403712: xor eax, edi
         // 00403714: mov edi, ss:[ebp+0xffffffffffffffcc]
         // 00403717: shr edi, b1 0xa
         // 0040371a: xor eax, edi
         // 0040371c: add eax, ebx
         // 0040371e: add eax, ss:[ebp+0xffffffffffffff94]
         // 00403721: mov edi, ecx
         // 00403723: mov ss:[ebp+0xffffffffffffffd4], eax
         // 00403726: ror edi, b1 0xb
         // 00403729: mov eax, ecx
         // 0040372b: rol eax, b1 0x7
         // 0040372e: xor edi, eax
         // 00403730: mov eax, ecx
         // 00403732: ror eax, b1 0x6
         // 00403735: xor edi, eax
         // 00403737: add edi, ss:[ebp+0xffffffffffffffd4]
         // 0040373a: mov eax, ss:[ebp+0xffffffffffffffe0]
         // 0040373d: mov ebx, edx
         // 0040373f: xor ebx, eax
         // 00403741: and ebx, ecx
         // 00403743: xor ebx, eax
         // 00403745: mov eax, ss:[ebp+0xffffffffffffffe8]
         // 00403748: add ebx, edi
         // 0040374a: lea eax, ds:[ebx+eax+0xffffffffbef9a3f7]
         // 00403751: add ss:[ebp+0xffffffffffffffdc], eax
         // 00403754: mov ss:[ebp+0xfffffffffffffffc], eax
         // 00403757: mov ebx, ss:[ebp+0xfffffffffffffff0]
         // 0040375a: mov edi, esi
         // 0040375c: ror edi, b1 0xd
         // 0040375f: mov eax, esi
         // 00403761: rol eax, b1 0xa
         // 00403764: xor edi, eax
         // 00403766: mov eax, esi
         // 00403768: ror eax, b1 0x2
         // 0040376b: xor edi, eax
         // 0040376d: add edi, ss:[ebp+0xfffffffffffffffc]
         // 00403770: mov eax, ss:[ebp+0xfffffffffffffff0]
         // 00403773: or eax, esi
         // 00403775: and eax, ss:[ebp+0xfffffffffffffff4]
         // 00403778: and ebx, esi
         // 0040377a: or eax, ebx
         // 0040377c: add eax, edi
         // 0040377e: mov ss:[ebp+0xffffffffffffffe8], eax
         // 00403781: mov eax, ss:[ebp+0xffffffffffffffdc]
         // 00403784: mov esi, eax
         // 00403786: ror esi, b1 0xb
         // 00403789: mov edi, eax
         // 0040378b: rol edi, b1 0x7
         // 0040378e: xor esi, edi
         // 00403790: ror eax, b1 0x6
         // 00403793: xor esi, eax
         // 00403795: mov eax, ss:[ebp+0xffffffffffffff9c]
         // 00403798: mov edi, eax
         // 0040379a: rol edi, b1 0xe
         // 0040379d: mov ebx, eax
         // 0040379f: shr eax, b1 0x3
         // 004037a2: ror ebx, b1 0x7
         // 004037a5: xor edi, ebx
         // 004037a7: xor edi, eax
         // 004037a9: mov eax, ss:[ebp+0xffffffffffffffd0]
         // 004037ac: add esi, edi
         // 004037ae: mov edi, eax
         // 004037b0: mov ebx, eax
         // 004037b2: rol edi, b1 0xf
         // 004037b5: rol ebx, b1 0xd
         // 004037b8: shr eax, b1 0xa
         // 004037bb: xor edi, ebx
         // 004037bd: xor edi, eax
         // 004037bf: add edi, ss:[ebp+0xffffffffffffffbc]
         // 004037c2: mov eax, edx
         // 004037c4: xor eax, ecx
         // 004037c6: and eax, ss:[ebp+0xffffffffffffffdc]
         // 004037c9: add edi, esi
         // 004037cb: mov esi, ss:[ebp+0xffffffffffffffe0]
         // 004037ce: xor eax, edx
         // 004037d0: add eax, edi
         // 004037d2: add eax, ss:[ebp+0xffffffffffffff98]
         // 004037d5: lea eax, ds:[eax+esi+0xffffffffc67178f2]
         // 004037dc: mov esi, ss:[ebp+0xffffffffffffffe8]
         // 004037df: mov edi, esi
         // 004037e1: mov ss:[ebp+0xfffffffffffffffc], eax
         // 004037e4: mov eax, esi
         // 004037e6: ror edi, b1 0xd
         // 004037e9: rol eax, b1 0xa
         // 004037ec: xor edi, eax
         // 004037ee: mov eax, esi
         // 004037f0: ror eax, b1 0x2
         // 004037f3: xor edi, eax
         // 004037f5: mov eax, ss:[ebp+0xffffffffffffffec]
         // 004037f8: mov ebx, eax
         // 004037fa: or ebx, esi
         // 004037fc: and ebx, ss:[ebp+0xfffffffffffffff0]
         // 004037ff: and eax, esi
         // 00403801: or ebx, eax
         // 00403803: mov eax, ss:[ebp+0x8]
         // 00403806: add edi, ds:[eax+0x8]
         // 00403809: add ebx, edi
         // 0040380b: mov edi, ss:[ebp+0xfffffffffffffffc]
         // 0040380e: add ebx, edi
         // 00403810: mov ds:[eax+0x8], ebx
         // 00403813: mov ebx, ds:[eax+0xc]
         // 00403816: add ebx, esi
         // 00403818: mov esi, ds:[eax+0x10]
         // 0040381b: add esi, ss:[ebp+0xffffffffffffffec]
         // 0040381e: mov ds:[eax+0xc], ebx
         // 00403821: mov ds:[eax+0x10], esi
         // 00403824: mov esi, ds:[eax+0x14]
         // 00403827: add esi, ss:[ebp+0xfffffffffffffff0]
         // 0040382a: mov ds:[eax+0x14], esi
         // 0040382d: mov esi, ds:[eax+0x18]
         // 00403830: add esi, edi
         // 00403832: add esi, ss:[ebp+0xfffffffffffffff4]
         // 00403835: pop edi
         // 00403836: mov ds:[eax+0x18], esi
         // 00403839: mov esi, ds:[eax+0x1c]
         // 0040383c: add esi, ss:[ebp+0xffffffffffffffdc]
         // 0040383f: mov ds:[eax+0x1c], esi
         // 00403842: mov esi, ds:[eax+0x20]
         // 00403845: add esi, ecx
         // 00403847: mov ecx, ds:[eax+0x24]
         // 0040384a: mov ds:[eax+0x20], esi
         // 0040384d: add ecx, edx
         // 0040384f: pop esi
         // 00403850: mov ds:[eax+0x24], ecx
         // 00403853: pop ebx
         // 00403854: mov esp, ebp
         // 00403856: pop ebp
         // 00403857: retn 

  }
  condition:
    all of them
}
